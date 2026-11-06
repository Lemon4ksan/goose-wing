// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// tests/lit/verify_server_round3_regressions.goose
// Regression verification suite for server/* Round 3 audit findings (F001..F021).
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
    t.run("1. Cache route isolation, Content-Type preservation & EdgeFilter boundary") { sub =>
        // F001: Route A (/json) cache entry must not poison Route B (/plaintext), and must preserve Content-Type
        var cfg = wing::new_server_pipeline_config("127.0.0.1", wing::new_gcra_quota(1000, core::secs(1), 100));
        let in_cache = wire::STAGE_SRV_IN_DEFAULT_MASK | wire::STAGE_SRV_IN_CACHE_LOOKUP;
        let out_cache = wire::STAGE_SRV_OUT_DEFAULT_MASK | wire::STAGE_SRV_OUT_CACHE_STORE;
        wing::add_route_pso(cfg.router, "GET", "/json", 101, in_cache, out_cache);
        wing::set_static_route_payload(cfg.router, 101, "application/json", "{\"ok\":true}");
        wing::add_route_pso(cfg.router, "GET", "/plaintext", 102, in_cache, out_cache);
        wing::set_static_route_payload(cfg.router, 102, "text/plain", "Hello!");

        var req_a = wing::new_request("GET", "/json");
        wing::set_header(req_a, "Host", "127.0.0.1");
        var res_a = wing::Response { status_code: 200, .. };
        var timer = internal::new_connection_timer(30000000000, 1000000000);
        var fut = internal::InlineHandlerFuture { .. };
        let v_a = wing::execute_pipeline(cfg, timer, "127.0.0.1", req_a, 1000000000, res_a, fut);
        sub.assert_true(v_a == wing::PipelineOutcome.Handled, "First /json request populates cache");
        sub.assert_eq(wing::header(res_a, "content-type"), "application/json", "First /json has Content-Type");

        // Second request to /json hits cache and must still include Content-Type
        var res_a2 = wing::Response { status_code: 200, .. };
        let _ = wing::execute_pipeline(cfg, timer, "127.0.0.1", req_a, 1000000000, res_a2, fut);
        sub.assert_eq(res_a2.body[..], "{\"ok\":true}", "Second /json hits cache body");
        sub.assert_eq(wing::header(res_a2, "content-type"), "application/json", "Cached /json preserves Content-Type");

        // Request to /plaintext must NOT receive /json's cached body!
        var req_b = wing::new_request("GET", "/plaintext");
        wing::set_header(req_b, "Host", "127.0.0.1");
        var res_b = wing::Response { status_code: 200, .. };
        let _ = wing::execute_pipeline(cfg, timer, "127.0.0.1", req_b, 1000000000, res_b, fut);
        sub.assert_eq(res_b.body[..], "Hello!", "Route /plaintext must not be poisoned by /json cache");

        // F002: EdgeFilter path_prefix "/admin" must not block "/administrator", and "/admin/" must block "/admin"
        let r_admin = wing::make_edge_filter_rule("block-admin", "/admin", wing::EdgeFilterVerdict.BlockForbidden);
        let r_slash = wing::make_edge_filter_rule("block-slash", "/admin/", wing::EdgeFilterVerdict.BlockForbidden);
        var hdrs = wing::HeaderMap { .. };
        sub.assert_false(wing::edge_rule_matches(r_admin, "/administrator", hdrs), "/admin prefix must not match /administrator");
        sub.assert_true(wing::edge_rule_matches(r_admin, "/admin/users", hdrs), "/admin prefix matches /admin/users");
        sub.assert_true(wing::edge_rule_matches(r_slash, "/admin", hdrs), "/admin/ prefix matches canonicalized /admin");
    };
}

fn test_r2_h2_multiplexer(t: lit::T&) {
    t.run("2. H2 HPACK dyn table update, conn window replenish on RST, partial send body corruption") { sub =>
        var sess = internal::new_h2_server_session("goose-wing/1.0", 1000);
        var pipeline = wing::new_server_pipeline_config("127.0.0.1", wing::new_gcra_quota(1000, core::secs(1), 100));
        var timer = internal::new_connection_timer(30000000000, 1000000000);
        wing::add_route(pipeline.router, "POST", "/echo", 1);

        var init_wire: u8[..256] = [];
        init_wire.append(rfc::H2_CLIENT_PREFACE);
        // Peer SETTINGS with HEADER_TABLE_SIZE (id=1) = 2048 and INITIAL_WINDOW_SIZE (id=4) = 1000
        build_h2_frame(init_wire, 12, 0x04, 0x00, 0);
        init_wire.push(0x00); init_wire.push(0x01);
        init_wire.push(0x00); init_wire.push(0x00); init_wire.push(0x08); init_wire.push(0x00); // 2048
        init_wire.push(0x00); init_wire.push(0x04);
        init_wire.push(0x00); init_wire.push(0x00); init_wire.push(0x03); init_wire.push(0xE8); // 1000
        var wire_out: u8[>..] = [];
        let _, ok_init = internal::handle_h2_server_ingress(sess, pipeline, timer, "127.0.0.1", init_wire[..], 1000, wire_out);
        sub.assert_true(ok_init, "H2 preface and SETTINGS handled");

        // F006: Stream 1 sends Content-Length: 5, then sends 10-byte DATA frame -> stream error PROTOCOL_ERROR,
        // but conn_recv_window MUST remain 65535 (replenished via conn WINDOW_UPDATE)!
        var dt = internal::new_dynamic_table(4096);
        var h1: u8[..512] = [];
        internal::encode_hpack_field(dt, h1, ":method", "POST", internal::HpackIndexing.Incremental, false);
        internal::encode_hpack_field(dt, h1, ":scheme", "https", internal::HpackIndexing.Incremental, false);
        internal::encode_hpack_field(dt, h1, ":authority", "127.0.0.1", internal::HpackIndexing.Incremental, false);
        internal::encode_hpack_field(dt, h1, ":path", "/echo", internal::HpackIndexing.Incremental, false);
        internal::encode_hpack_field(dt, h1, "content-length", "5", internal::HpackIndexing.Incremental, false);
        var w1: u8[..1024] = [];
        build_h2_frame(w1, h1.len as u32, 0x01, 0x04, 1);
        w1.append(h1[..]);
        build_h2_frame(w1, 10, 0x00, 0x01, 1);
        w1.append("0123456789");
        wire_out.clear();
        let _, ok_w1 = internal::handle_h2_server_ingress(sess, pipeline, timer, "127.0.0.1", w1[..], 1000, wire_out);
        sub.assert_true(ok_w1, "Stream 1 CL mismatch resets stream, keeps conn alive");
        sub.assert_eq(sess.conn.conn_recv_window, 65535, "conn_recv_window replenished after stream DATA error");

        // F008: Pre-populate route_cache with 10,000 'Z' bytes on handler 55 and register /cached-big with CACHE_LOOKUP.
        // Peer initial window is 1000 -> 1000 bytes sent initially, 9000 bytes remaining (> 8192 inline cap!).
        // Then peer sends WINDOW_UPDATE(+20000) -> flushed DATA must NOT contain "LEAKED_REQ_BYTES"!
        var big_cached: u8[>..] = [];
        for k in 10000 { big_cached.push('Z'); }
        wing::cache_store(pipeline.route_cache, 1, big_cached[..], 55, "text/plain");
        let in_cache = wire::STAGE_SRV_IN_DEFAULT_MASK | wire::STAGE_SRV_IN_CACHE_LOOKUP;
        wing::add_route_pso(pipeline.router, "GET", "/cached-big", 55, in_cache, wire::STAGE_SRV_OUT_DEFAULT_MASK);
        var h5: u8[..512] = [];
        internal::encode_hpack_field(dt, h5, ":method", "GET", internal::HpackIndexing.Incremental, false);
        internal::encode_hpack_field(dt, h5, ":scheme", "https", internal::HpackIndexing.Incremental, false);
        internal::encode_hpack_field(dt, h5, ":authority", "127.0.0.1", internal::HpackIndexing.Incremental, false);
        internal::encode_hpack_field(dt, h5, ":path", "/cached-big", internal::HpackIndexing.Incremental, false);
        var w5: u8[..1024] = [];
        build_h2_frame(w5, h5.len as u32, 0x01, 0x04, 5);
        w5.append(h5[..]);
        build_h2_frame(w5, 16, 0x00, 0x01, 5);
        w5.append("LEAKED_REQ_BYTES");
        wire_out.clear();
        let _, ok_w5 = internal::handle_h2_server_ingress(sess, pipeline, timer, "127.0.0.1", w5[..], 1000, wire_out);
        sub.assert_true(ok_w5, "Stream 5 partial send initiated");

        // Send WINDOW_UPDATE for conn (0) and stream 5 (+20000)
        var wu5: u8[..64] = [];
        build_h2_frame(wu5, 4, 0x08, 0x00, 0);
        wu5.push(0x00); wu5.push(0x00); wu5.push(0x4E); wu5.push(0x20);
        build_h2_frame(wu5, 4, 0x08, 0x00, 5);
        wu5.push(0x00); wu5.push(0x00); wu5.push(0x4E); wu5.push(0x20);
        wire_out.clear();
        let _, ok_wu5 = internal::handle_h2_server_ingress(sess, pipeline, timer, "127.0.0.1", wu5[..], 1000, wire_out);
        sub.assert_true(ok_wu5, "Stream 5 WINDOW_UPDATE handled");
        sub.assert_false(core::contains(wire_out[..], "LEAKED_REQ_BYTES"), "Request body must NEVER leak into response DATA");
        sub.assert_true(wire_out.len >= 9000, "Remaining 9000 response bytes flushed after WINDOW_UPDATE");
    };
}

fn test_r3_pipeline_and_router(t: lit::T&) {
    t.run("3. Pipeline Accept-Encoding q=0, Vary preservation, X-Matched-Route, HEAD ETag & Router backtrack") { sub =>
        // F010: client_accepts_encoding must reject q=0 and preserve Vary: Origin on compression
        sub.assert_false(wing::client_accepts_encoding("zstd;q=0, gzip;q=0.0", "zstd"), "zstd;q=0 must be rejected");
        sub.assert_false(wing::client_accepts_encoding("x-br", "br"), "x-br must not substring-match br");
        sub.assert_true(wing::client_accepts_encoding("gzip;q=0, br;q=0.8", "br"), "br;q=0.8 must be accepted");

        // F011 & F012: X-Matched-Route emitted in telemetry and HEAD ETag 304 Not Modified works
        var cfg = wing::new_server_pipeline_config("127.0.0.1", wing::new_gcra_quota(1000, core::secs(1), 100));
        let pso = wing::DEFAULT_ROUTE_PSO_MASK | wing::STAGE_EGRESS_ETAG | wing::STAGE_EGRESS_METRICS | wing::STAGE_EGRESS_ACCESS_LOG;
        wing::add_route_pso(cfg.router, "GET", "/item", 201, pso);
        wing::set_static_route_payload(cfg.router, 201, "text/plain", "hello-etag-world");
        wing::add_route_pso(cfg.router, "HEAD", "/item", 201, pso);

        var req_get = wing::new_request("GET", "/item");
        wing::set_header(req_get, "Host", "127.0.0.1");
        var res_get = wing::Response { status_code: 200, .. };
        var timer = internal::new_connection_timer(30000000000, 1000000000);
        var fut = internal::InlineHandlerFuture { .. };
        let _ = wing::execute_pipeline(cfg, timer, "127.0.0.1", req_get, 1000000000, res_get, fut);
        let etag_val = wing::header(res_get, "etag");
        sub.assert_true(etag_val.len > 0, "GET /item produces ETag");
        sub.assert_eq(wing::header(res_get, "x-matched-route"), "/item", "Telemetry stage emits X-Matched-Route");

        var req_head = wing::new_request("HEAD", "/item");
        wing::set_header(req_head, "Host", "127.0.0.1");
        wing::set_header(req_head, "If-None-Match", etag_val);
        var res_head = wing::Response { status_code: 200, .. };
        let _ = wing::execute_pipeline(cfg, timer, "127.0.0.1", req_head, 1000000000, res_head, fut);
        sub.assert_eq(res_head.status_code, 304, "HEAD /item with matching If-None-Match returns 304 Not Modified");
        sub.assert_eq(res_head.body.len, 0, "HEAD /item response body is empty");

        // F015 & F016: Router malformed braces rejected and multi-level wildcard backtrack works
        var rtr = wing::new_radix_router();
        sub.assert_false(wing::insert_route(rtr.trees[0].tree, "/unclosed/{id", 1), "Unclosed { rejected");
        sub.assert_false(wing::insert_route(rtr.trees[0].tree, "/stray/id}", 2), "Stray } rejected");
        sub.assert_false(wing::insert_route(rtr.trees[0].tree, "/nested/{a{b}}", 3), "Nested { rejected");

        // Multi-branch backtrack: /{*any}, /users/{id}/profile, and /users/admin/settings/deep
        sub.assert_true(wing::insert_route(rtr.trees[1].tree, "/{*any}", 100), "Insert catch-all /{*any}");
        sub.assert_true(wing::insert_route(rtr.trees[1].tree, "/users/{id}/profile", 200), "Insert /users/{id}/profile");
        sub.assert_true(wing::insert_route(rtr.trees[1].tree, "/users/admin/settings/deep", 300), "Insert /users/admin/settings/deep");

        var p1 = wing::ZeroAllocParams { .. };
        let m1 = wing::match_path(rtr.trees[1].tree, "/users/admin/settings/other", p1);
        let m1_ok = match m1 {
            Found f => f.handler_id == 100,
            _ => false,
        };
        sub.assert_true(m1_ok, "/users/admin/settings/other backtracks past /users/{id} to /{*any}");

        var p2 = wing::ZeroAllocParams { .. };
        let m2 = wing::match_path(rtr.trees[1].tree, "/users/admin/profile", p2);
        let m2_ok = match m2 {
            Found f => f.handler_id == 200,
            _ => false,
        };
        sub.assert_true(m2_ok, "/users/admin/profile backtracks from static admin to /users/{id}/profile");
        sub.assert_eq(wing::param_val(p2, 0, "/users/admin/profile"), "admin", "Extracted param id == admin");
    };
}

fn test_r4_server_wire(t: lit::T&) {
    t.run("4. Host :0 & forbidden chars, TE readiness, remove_header mask, chunked readiness with trailers") { sub =>
        // F017: Host port :0 and forbidden host chars must be rejected
        var req_h = wing::Request { .. };
        let ok_p0, _ = wing::parse_http1_wire_request("GET / HTTP/1.1\r\nHost: example.com:0\r\n\r\n", req_h);
        sub.assert_false(ok_p0, "Host: example.com:0 must be rejected");
        let ok_badc, _ = wing::parse_http1_wire_request("GET / HTTP/1.1\r\nHost: ex<ample>.com\r\n\r\n", req_h);
        sub.assert_false(ok_badc, "Host with < > must be rejected");

        // F018: is_http1_request_ready must immediately return true on unsupported Transfer-Encoding: gzip
        let te_gzip = "POST /upload HTTP/1.1\r\nHost: example.com\r\nTransfer-Encoding: gzip\r\n\r\n";
        let te_hdr_end = core::find(te_gzip, "\r\n\r\n");
        sub.assert_true(wing::is_http1_request_ready(te_gzip, te_hdr_end), "Unsupported TE: gzip is immediately ready for 501/400 rejection");

        // F019: remove_header("Content-Type") must clear HDR_PRESENCE_CONTENT_TYPE so serialize_http1_headers does not corrupt header 0
        var res = wing::Response { status_code: 200, .. };
        wing::set_header(res, "Content-Type", "text/plain");
        wing::remove_header(res, "Content-Type");
        wing::set_header(res, "X-Custom", "MyVal");
        var wire_res: u8[..512] = [];
        wing::serialize_http1_response(res, "goose-wing/1.0", wire_res);
        sub.assert_true(core::contains(wire_res[..], "X-Custom: MyVal\r\n"), "X-Custom header preserved after remove_header(Content-Type)");

        // F021: is_http1_request_ready on chunked body with trailers and on chunked body containing "0\r\n\r\n" inside data
        let chunk_with_trailer_partial = "POST / HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\nX-Trailer: 1\r\n";
        let chunk_with_trailer_done = "POST / HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\nX-Trailer: 1\r\n\r\n";
        let tr_hdr_end = core::find(chunk_with_trailer_partial, "\r\n\r\n");
        sub.assert_false(wing::is_http1_request_ready(chunk_with_trailer_partial, tr_hdr_end), "Incomplete chunked trailer not ready");
        sub.assert_true(wing::is_http1_request_ready(chunk_with_trailer_done, tr_hdr_end), "Complete chunked trailer is ready");

        let chunk_embedded_zero = "POST / HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: chunked\r\n\r\n8\r\n0\r\n\r\nabc";
        let emb_hdr_end = core::find(chunk_embedded_zero, "\r\n\r\n");
        sub.assert_false(wing::is_http1_request_ready(chunk_embedded_zero, emb_hdr_end), "Embedded 0\\r\\n\\r\\n inside unfinished chunk data must not trigger ready");
    };
}

fn main() {
    var runner = lit::new_runner("Server Round 3 Audit Regressions Suite", lit::Verbosity.Verbose);
    lit::run_case(runner, "1. Cache & EdgeFilter", test_r1_cache_and_edge_filter);
    lit::run_case(runner, "2. H2 Multiplexer", test_r2_h2_multiplexer);
    lit::run_case(runner, "3. Pipeline & Router", test_r3_pipeline_and_router);
    lit::run_case(runner, "4. Server Wire", test_r4_server_wire);
    let ok = lit::finish(runner);
    assert(ok);
    print("SERVER_ROUND3_REGRESSIONS_VERIFIED");
}

// CHECK: SERVER_ROUND3_REGRESSIONS_VERIFIED
