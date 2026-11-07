// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// tests/lit/verify_server_round4_regressions.goose
// Regression verification suite for server/* Round 4 audit findings (F001..F012).
//
// RUN: goose build --cc gcc -O2 -o %t.exe %s && %t.exe | %FileCheck %s

import std;
import core from "../..";
import wing from "../..";
import lit from "github.com/Lemon4ksan/goose-lit@v0.1.0";

fn build_h2_frame<B>(out: B&, length: u32, frame_type: u8, flags: u8, stream_id: u32) {
    out.push(((length >> 16) & 0xFF) as u8);
    out.push(((length >> 8) & 0xFF) as u8);
    out.push((length & 0xFF) as u8);
    out.push(frame_type);
    out.push(flags);
    out.push(((stream_id >> 24) & 0x7F) as u8);
    out.push(((stream_id >> 16) & 0xFF) as u8);
    out.push(((stream_id >> 8) & 0xFF) as u8);
    out.push((stream_id & 0xFF) as u8);
}

fn test_r1_cache_and_edge_filter(t: lit::T&) {
    t.run("1. Cache URL/query key isolation, SWR is_updating reset & EdgeFilter >512B Pass bypass") { sub =>
        // F001a: Same handler_id across parameterized/query URLs must not serve poisoned cached entry
        var cfg = wing::new_server_pipeline_config("127.0.0.1", wing::new_gcra_quota(1000, core::secs(1), 100));
        let in_cache = wire::STAGE_SRV_IN_DEFAULT_MASK | wire::STAGE_SRV_IN_CACHE_LOOKUP;
        let out_cache = wire::STAGE_SRV_OUT_DEFAULT_MASK | wire::STAGE_SRV_OUT_CACHE_STORE;
        wing::add_route_pso(cfg.router, "GET", "/items/{id}", 201, in_cache, out_cache);

        var req1 = wing::new_request("GET", "/items/alice");
        wing::set_header(req1, "Host", "127.0.0.1");
        var res1 = wing::Response { status_code: 200, .. };
        res1.body.append("payload-alice");
        let v_m1 = wing::stage_server_cache_lookup(cfg.route_cache, req1, 1000, res1, 201);
        sub.assert_true(v_m1 == wire::StageVerdict.Continue, "Initial /items/alice is cache miss");
        let _ = wing::stage_server_cache_store(cfg.route_cache, 1000, res1, 201, req1.url[..]);

        var req2 = wing::new_request("GET", "/items/bob");
        wing::set_header(req2, "Host", "127.0.0.1");
        var res2 = wing::Response { status_code: 200, .. };
        let v_m2 = wing::stage_server_cache_lookup(cfg.route_cache, req2, 1001, res2, 201);
        sub.assert_true(v_m2 == wire::StageVerdict.Continue, "/items/bob sharing handler_id 201 must not hit /items/alice cache entry");

        // F001b: SWR HitStaleNeedsUpdate sets is_updating=true; oversized/failed store must still clear is_updating
        var res_swr = wing::Response { status_code: 200, .. };
        let v_swr = wing::stage_server_cache_lookup(cfg.route_cache, req1, 2500, res_swr, 201);
        sub.assert_true(v_swr == wire::StageVerdict.Continue, "First stale request triggers background update (HitStaleNeedsUpdate)");
        sub.assert_true(cfg.route_cache.is_updating, "is_updating is true during refresh");
        var huge_payload: u8[..16400] = [];
        for i in 16400 {
            huge_payload.push('X');
        }
        let stored_ok = wing::cache_store(cfg.route_cache, 2500, huge_payload[..], 201, "text/plain");
        sub.assert_false(stored_ok, "Oversized payload fails cache_store");
        sub.assert_false(cfg.route_cache.is_updating, "is_updating must be reset even when cache_store fails");

        // F002: EdgeFilter >512B path must not match Pass allowlist rule and bypass BlockForbidden rule
        var ef = wing::EdgeFilter { .. };
        assert(wing::add_edge_filter_rule(ef, wing::make_edge_filter_rule("allow-pub", "/public", wing::EdgeFilterVerdict.Pass)));
        assert(wing::add_edge_filter_rule(ef, wing::make_edge_filter_rule("block-adm", "/admin", wing::EdgeFilterVerdict.BlockForbidden)));
        var long_admin: u8[..600] = [];
        long_admin.append("/admin/");
        for j in 550 {
            long_admin.push('a');
        }
        var dummy_hdrs = wing::HeaderMap { .. };
        let ef_v = wing::evaluate_edge_filter(ef, "GET", long_admin[..], dummy_hdrs);
        sub.assert_true(ef_v == wing::EdgeFilterVerdict.BlockForbidden, ">512B /admin/... path must hit BlockForbidden, not Pass");
    };
}

fn test_r2_pipeline_and_pool(t: lit::T&) {
    t.run("2. Pipeline PSO mask collisions, CORS/405 preflight, compress CL/ETag, Cookie/Forwarded & Timer") { sub =>
        // F003: Enabling only STAGE_EGRESS_COMPRESS_GZIP alongside DEFAULT_ROUTE_PSO_MASK must not enable ZSTD/BR via low-bit collision
        var cfg = wing::new_server_pipeline_config("example.com", wing::new_gcra_quota(1000, core::secs(1), 100));
        var req_c = wing::new_request("GET", "/data");
        wing::set_header(req_c, "Accept-Encoding", "zstd, gzip");
        var res_c = wing::Response { status_code: 200, .. };
        wing::set_header(res_c, "Content-Type", "text/plain");
        wing::set_header(res_c, "Content-Length", "80");
        wing::set_header(res_c, "ETag", "\"v1\"");
        for k in 80 {
            res_c.body.push('A');
        }
        let pso_gzip_only = (wing::DEFAULT_ROUTE_PSO_MASK & ~(wing::STAGE_EGRESS_COMPRESS_BROTLI | wing::STAGE_EGRESS_COMPRESS_ZSTD)) | wing::STAGE_EGRESS_COMPRESS_GZIP;
        wing::dispatch_egress_pipeline(cfg, req_c, res_c, pso_gzip_only, 1000, -1);
        sub.assert_eq(wing::header(res_c, "content-encoding"), "gzip", "Only gzip enabled in egress PSO must not select zstd");

        // F005: Compression must strip stale Content-Length and weaken/qualify strong ETag
        sub.assert_eq(wing::header(res_c, "content-length"), "", "Stale uncompressed Content-Length must be removed after compression");
        sub.assert_true(wing::header(res_c, "etag") != "\"v1\"", "Strong ETag must be modified when Content-Encoding is applied");

        // F004: Unmatched route (404) or MethodNotAllowed (OPTIONS preflight to POST route) must not escalate PSO to require JWT auth
        assert(wing::add_allowed_origin(cfg.cors_policy, "https://app.example.com"));
        assert(wing::add_symmetric_key(cfg.jwks, "k1", wing::JwtAlg.HS256, "0123456789abcdef0123456789abcdef"));
        wing::add_route_pso(cfg.router, "POST", "/api/submit", 301, wing::DEFAULT_ROUTE_PSO_MASK | wing::STAGE_INGRESS_CORS_PREFLIGHT);
        var req_opt = wing::new_request("OPTIONS", "/api/submit");
        wing::set_header(req_opt, "Host", "example.com");
        wing::set_header(req_opt, "Origin", "https://app.example.com");
        wing::set_header(req_opt, "Access-Control-Request-Method", "POST");
        var res_opt = wing::Response { status_code: 200, .. };
        var timer = internal::new_connection_timer(30000000000, 1000000000);
        var fut = internal::InlineHandlerFuture { .. };
        let v_opt = wing::execute_pipeline(cfg, timer, "127.0.0.1", req_opt, 1000000000, res_opt, fut);
        sub.assert_true(v_opt == wing::PipelineOutcome.CorsPreflight, "CORS preflight OPTIONS returns CorsPreflight");
        sub.assert_eq(res_opt.status_code as i64, 204, "CORS preflight returns 204 without 401 JWT escalation");

        // F006a: Cookie tossing (invalid first session= cookie followed by valid session= cookie)
        let key: u8[32] = [
            1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16,
            17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32,
        ];
        assert(wing::add_key(cfg.private_jar.store, core::KeySlot { key_id: 1, master_key: key, .. }));
        var sealed_val: u8[..256] = [];
        assert(wing::private_jar_seal(cfg.private_jar, "session", "uid=42", 1, 999, sealed_val));
        var hdr_cookie: u8[..320] = [];
        hdr_cookie.append("session=invalid_tossed; session=");
        hdr_cookie.append(sealed_val[..]);
        var req_ck = wing::new_request("GET", "/");
        wing::set_header(req_ck, "Cookie", hdr_cookie[..]);
        var ext_ck = internal::RequestExtensions { .. };
        let _ = wing::stage_server_auth_cookie(cfg.private_jar, req_ck, ext_ck, 1000000000);
        sub.assert_eq(ext_ck.session_data[..], "uid=42", "Valid second session cookie accepted after tossed first cookie");

        // F006b: Forwarded multi-element & X-Forwarded-For port stripping + ConnectionTimer activity reset
        var req_ip = wing::new_request("GET", "/");
        wing::set_header(req_ip, "Forwarded", "proto=https, for=\"[2001:db8::1]:8443\"");
        let ip_out = wing::extract_effective_client_ip(true, "127.0.0.1", req_ip);
        sub.assert_eq(ip_out, "2001:db8::1", "Forwarded second element for= extracted and port stripped");

        var ctimer = internal::new_connection_timer(2000, 100);
        internal::notify_request_start(ctimer);
        internal::notify_request_end(ctimer);
        let t_alive1 = internal::advance_connection_tick(ctimer);
        internal::notify_request_start(ctimer);
        internal::notify_request_end(ctimer);
        let t_alive2 = internal::advance_connection_tick(ctimer);
        sub.assert_true(t_alive1 && t_alive2, "Completed requests between ticks must reset missed_ticks and keep connection alive");
    };
}

fn test_r3_h2_and_router(t: lit::T&) {
    t.run("3. H2 rejected HEADERS HPACK sync, 8192 initial window & Router OPTIONS *, >512B path, suffix param") { sub =>
        // F007a: local_initial_window_size must match advertised H2_SERVER_INITIAL_STREAM_WINDOW (8192)
        var sess = internal::new_h2_server_session("goose-wing/1.0", 1000);
        sub.assert_eq(sess.conn.local_initial_window_size as i64, 8192, "H2 session local_initial_window_size matches advertised 8192");

        // F007b: Self-dependent HEADERS (stream 1 depends on stream 1) with PRIORITY (0x20) + END_HEADERS (0x04)
        // must still decode HPACK incremental indexing so subsequent stream 3 referencing that dynamic entry succeeds!
        var pipeline = wing::new_server_pipeline_config("127.0.0.1", wing::new_gcra_quota(1000, core::secs(1), 100));
        var timer = internal::new_connection_timer(30000000000, 1000000000);
        wing::add_route(pipeline.router, "GET", "/ok", 10);

        var wire_in: u8[..1024] = [];
        wire_in.append(rfc::H2_CLIENT_PREFACE);
        build_h2_frame(wire_in, 0, 0x04, 0x00, 0);

        var dt = internal::new_dynamic_table(4096);
        var h1_pri: u8[..512] = [];
        // 5-byte PRIORITY header: dep = stream 1 (self-dependency -> RST_STREAM(PROTOCOL_ERROR)), weight = 15
        h1_pri.push(0x00); h1_pri.push(0x00); h1_pri.push(0x00); h1_pri.push(0x01); h1_pri.push(15);
        internal::encode_hpack_field(dt, h1_pri, ":method", "GET", internal::HpackIndexing.Incremental, false);
        internal::encode_hpack_field(dt, h1_pri, ":scheme", "https", internal::HpackIndexing.Incremental, false);
        internal::encode_hpack_field(dt, h1_pri, ":authority", "127.0.0.1", internal::HpackIndexing.Incremental, false);
        internal::encode_hpack_field(dt, h1_pri, ":path", "/ok", internal::HpackIndexing.Incremental, false);
        internal::encode_hpack_field(dt, h1_pri, "x-shared-dyn", "dyn-value-123", internal::HpackIndexing.Incremental, false);
        build_h2_frame(wire_in, h1_pri.len as u32, 0x01, 0x25, 1); // END_STREAM(0x01) | END_HEADERS(0x04) | PRIORITY(0x20)
        wire_in.append(h1_pri[..]);

        // Stream 3 references the newly indexed dynamic table entry ("x-shared-dyn: dyn-value-123")
        var h3: u8[..512] = [];
        internal::encode_hpack_field(dt, h3, ":method", "GET", internal::HpackIndexing.Incremental, false);
        internal::encode_hpack_field(dt, h3, ":scheme", "https", internal::HpackIndexing.Incremental, false);
        internal::encode_hpack_field(dt, h3, ":authority", "127.0.0.1", internal::HpackIndexing.Incremental, false);
        internal::encode_hpack_field(dt, h3, ":path", "/ok", internal::HpackIndexing.Incremental, false);
        internal::encode_hpack_field(dt, h3, "x-shared-dyn", "dyn-value-123", internal::HpackIndexing.Incremental, false);
        build_h2_frame(wire_in, h3.len as u32, 0x01, 0x05, 3);
        wire_in.append(h3[..]);

        var wire_out: u8[>..] = [];
        let _, ok_h2 = internal::handle_h2_server_ingress(sess, pipeline, timer, "127.0.0.1", wire_in[..], 1000, wire_out);
        sub.assert_true(ok_h2, "H2 connection survives self-dependent stream 1 and decodes stream 3 dynamic HPACK entry");
        sub.assert_true(sess.conn.hpack_dec.entries.len > 0, "HPACK decoder dynamic table updated on rejected stream 1");

        // F009a: Non-terminal catch-all {*rest}/tail must be rejected by insert_route
        var rtr = wing::new_radix_router();
        sub.assert_false(wing::insert_route(rtr.trees[0].tree, "/files/{*rest}/tail", 1), "Non-terminal catch-all route rejected");

        // F009b: OPTIONS * must not match parameterized/wildcard routes in OPTIONS tree
        wing::add_route(rtr, "OPTIONS", "/{*any}", 99);
        wing::add_route(rtr, "GET", "/ping", 2);
        var params_opt = wing::ZeroAllocParams { .. };
        let m_star = wing::match_route(rtr, "OPTIONS", "*", params_opt);
        let m_star_is_405 = match m_star {
            MethodNotAllowed _ => true,
            _ => false,
        };
        sub.assert_true(m_star_is_405, "OPTIONS * returns server-wide Allow via MethodNotAllowed, not matching /{*any}");

        // F009c: Suffix param /archive/{name}.tar.gz with dots inside parameter value ("app.v1.tar.gz")
        wing::add_route(rtr, "GET", "/archive/{name}.tar.gz", 3);
        var p_arc = wing::ZeroAllocParams { .. };
        let m_arc = wing::match_route(rtr, "GET", "/archive/app.v1.tar.gz", p_arc);
        let m_arc_found = match m_arc {
            Found f => f.handler_id == 3,
            _ => false,
        };
        sub.assert_true(m_arc_found, "/archive/app.v1.tar.gz matches /archive/{name}.tar.gz");
        sub.assert_eq(wing::param_val(p_arc, 0, "/archive/app.v1.tar.gz"), "app.v1", "Extracted {name} before .tar.gz is app.v1");
    };
}

var g_stream_last_seen: bool = false;

fn on_stream_chunk(data: const u8[:], is_last: bool) {
    let _ = data;
    if is_last {
        g_stream_last_seen = true;
    }
}

fn test_r4_server_wire(t: lit::T&) {
    t.run("4. Split-TCP chunked EmptyInput, status reason-phrase LF, stream 0-chunk callback, 304 CL & dcz;q=0") { sub =>
        // F011: Split-TCP chunked headers with 0 body bytes yet (ChunkedDecodeError.EmptyInput) must NOT wipe out_req.headers
        var req_split = wing::Request { .. };
        let ok_sp, _ = wing::parse_http1_wire_request("POST /upload HTTP/1.1\r\nHost: example.com\r\nTransfer-Encoding: chunked\r\n\r\n", req_split);
        sub.assert_false(ok_sp, "Incomplete chunked request without terminal chunk returns ok=false");
        sub.assert_true(req_split.headers.entries.len > 0, "Split-TCP chunked headers must remain intact on EmptyInput so server waits for more bytes instead of 400");

        // F012a: Bare LF inside status reason-phrase must be rejected by parse_http1_wire_response
        var res_lf = wing::Response { .. };
        let ok_lf, _ = wing::parse_http1_wire_response("HTTP/1.1 200 OK\nFake-Header: 1\r\nContent-Length: 0\r\n\r\n", res_lf);
        sub.assert_false(ok_lf, "Status line containing bare LF in reason-phrase must be rejected");

        // F012b: feed_http_stream_chunk must invoke Callback("", true) on terminal 0\r\n\r\n chunk arriving in second packet
        g_stream_last_seen = false;
        var consumer = wing::HttpStreamConsumer { content_length: -1, is_chunked: true, is_headers_parsed: true, .. };
        let _, is_last1, ok_sc1 = wing::feed_http_stream_chunk(consumer, "5\r\nhello\r\n", on_stream_chunk);
        sub.assert_true(ok_sc1 && !is_last1, "First chunk packet consumed without terminal chunk");
        let _, is_last2, ok_sc2 = wing::feed_http_stream_chunk(consumer, "0\r\n\r\n", on_stream_chunk);
        sub.assert_true(ok_sc2 && is_last2, "Chunked stream consumer completes on 0\\r\\n\\r\\n");
        sub.assert_true(g_stream_last_seen, "Callback invoked with is_last=true on terminal 0-length chunk");

        // F012c: end_without_body on 304 Not Modified must preserve reported_content_length and not duplicate Server header
        var res_304 = wing::Response { status_code: 304, .. };
        wing::set_header(res_304, "Server", "custom-srv");
        var wire_304: u8[..512] = [];
        wing::end_without_body(res_304, "goose-wing/1.0", wire_304, 128);
        sub.assert_true(core::contains(wire_304[..], "Content-Length: 128\r\n"), "304 response preserves explicit Content-Length from end_without_body");
        sub.assert_false(core::contains(wire_304[..], "Server: goose-wing/1.0\r\n"), "Custom Server header suppresses duplicate default Server header");

        // F012d: accept_encoding_has_token must reject q=0 and response_wire_has_connection_close must detect close in 2nd pipelined response
        sub.assert_false(wing::accept_encoding_has_token("dcz;q=0, gzip", "dcz"), "dcz;q=0 must not match accept_encoding_has_token");
        let pipe_wire = "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\nHTTP/1.1 400 Bad Request\r\nConnection: close\r\nContent-Length: 0\r\n\r\n";
        sub.assert_true(wing::response_wire_has_connection_close(pipe_wire), "Connection: close in 2nd pipelined response detected");
    };
}

fn main() {
    var runner = lit::new_runner("Server Round 4 Audit Regressions Suite", lit::Verbosity.Verbose);
    lit::run_case(runner, "1. Cache & EdgeFilter", test_r1_cache_and_edge_filter);
    lit::run_case(runner, "2. Pipeline & Pool", test_r2_pipeline_and_pool);
    lit::run_case(runner, "3. H2 & Router", test_r3_h2_and_router);
    lit::run_case(runner, "4. Server Wire", test_r4_server_wire);
    let ok = lit::finish(runner);
    assert(ok);
    print("SERVER_ROUND4_REGRESSIONS_VERIFIED");
}

// CHECK: SERVER_ROUND4_REGRESSIONS_VERIFIED
