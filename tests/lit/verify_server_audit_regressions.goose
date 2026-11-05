// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// tests/lit/verify_server_audit_regressions.goose
// Regression verification suite for server/* bug audit findings (F001..F055).
//
// RUN: goose build --cc gcc -O2 -o %t.exe %s && %t.exe | %FileCheck %s

import std;
import core from "../..";
import wing from "../..";
import lit from "github.com/Lemon4ksan/goose-lit@v0.1.0";

fn build_h2_test_frame_header<B>(out: B&, length: u32, frame_type: u8, flags: u8, stream_id: u32) {
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

fn test_s1(t: lit::T&) {
    t.run("1. EdgeFilter bounds and duplicate required_header") { sub =>
        // F001: path_prefix > 64 bytes must not silently truncate to a shorter prefix that matches /api/...
        let long_pfx: const u8[:] = "/api/v1/012345678901234567890123456789012345678901234567890123456789/secret";
        let r_long = wing::make_edge_filter_rule("long", long_pfx, wing::EdgeFilterVerdict.BlockForbidden);
        let short_req_path = long_pfx[..64];
        var empty_hdrs: wing::HeaderItem[..4] = [];
        sub.assert_false(wing::edge_rule_matches(r_long, short_req_path, empty_hdrs[..]), "truncated 64B prefix must not match shorter path");

        // F002: whitespace-only required_header must NOT satisfy required_header check
        var r_hdr = wing::make_edge_filter_rule("auth-check", "/secure", wing::EdgeFilterVerdict.BlockForbidden);
        r_hdr.required_header.append("X-API-Key");
        var ws_hdrs: wing::HeaderItem[..4] = [];
        ws_hdrs.push(wing::make_header("X-API-Key", "   \t  "));
        sub.assert_true(wing::edge_rule_matches(r_hdr, "/secure/data", ws_hdrs[..]), "whitespace-only required header must trigger block rule");

        // F002: empty first header followed by non-empty duplicate header must satisfy required_header
        var dup_hdrs: wing::HeaderItem[..4] = [];
        dup_hdrs.push(wing::make_header("X-API-Key", ""));
        dup_hdrs.push(wing::make_header("X-API-Key", "valid-token"));
        sub.assert_false(wing::edge_rule_matches(r_hdr, "/secure/data", dup_hdrs[..]), "valid second duplicate header must satisfy required header");
    };
}

fn test_s2(t: lit::T&) {
    t.run("2. H2ServerSession role, presence_mask, GOAWAY & RST_STREAM") { sub =>
        var sess = internal::new_h2_server_session("goose-wing/1.0", 1000);
        sub.assert_true(sess.conn.is_server, "H2ServerSession must initialize conn.is_server = true");
        sub.assert_false(sess.conn.enable_push, "H2ServerSession must initialize conn.enable_push = false");
        sub.assert_eq(sess.conn.max_concurrent_streams, 16, "H2ServerSession max_concurrent_streams is 16");

        // F012 & F013: copy_stream_headers_and_trailers must populate req.presence_mask so wing::header() works on HTTP/2 requests!
        var pipeline = wing::new_server_pipeline_config("example.com", wing::new_gcra_quota(1000, core::secs(1), 100));
        var timer = internal::new_connection_timer(30000000000, 1000000000);
        wing::add_route(pipeline.router, "QUERY", "/search", 10);

        var init_wire: u8[>..] = [];
        init_wire.append(rfc::H2_CLIENT_PREFACE);
        build_h2_test_frame_header(init_wire, 0, 0x04, 0x00, 0);
        var wire_out: u8[>..] = [];
        let _, ok_init = internal::handle_h2_server_ingress(sess, pipeline, timer, "127.0.0.1", init_wire[..], 1000, wire_out);
        sub.assert_true(ok_init, "H2 preface and SETTINGS handled");

        var dt = internal::new_dynamic_table(4096);
        var h_block: u8[>..] = [];
        internal::encode_hpack_field(dt, h_block, ":method", "QUERY", internal::HpackIndexing.Incremental, false);
        internal::encode_hpack_field(dt, h_block, ":scheme", "https", internal::HpackIndexing.Incremental, false);
        internal::encode_hpack_field(dt, h_block, ":authority", "example.com", internal::HpackIndexing.Incremental, false);
        internal::encode_hpack_field(dt, h_block, ":path", "/search", internal::HpackIndexing.Incremental, false);
        internal::encode_hpack_field(dt, h_block, "content-type", "application/json", internal::HpackIndexing.Incremental, false);
        internal::encode_hpack_field(dt, h_block, "content-length", "2", internal::HpackIndexing.Incremental, false);
        internal::encode_hpack_field(dt, h_block, "sec-fetch-site", "same-origin", internal::HpackIndexing.Incremental, false);

        var req_wire: u8[>..] = [];
        build_h2_test_frame_header(req_wire, h_block.len as u32, 0x01, 0x04, 1);
        req_wire.append(h_block[..]);
        build_h2_test_frame_header(req_wire, 2, 0x00, 0x01, 1);
        req_wire.append("{}");

        // F010: Append a truncated 9-byte RST_STREAM header for stream 1 at the tail of the buffer (missing 4-byte payload).
        build_h2_test_frame_header(req_wire, 4, 0x03, 0x00, 1);

        wire_out.clear();
        let consumed, ok_req = internal::handle_h2_server_ingress(sess, pipeline, timer, "127.0.0.1", req_wire[..], 1000, wire_out);
        sub.assert_true(ok_req, "H2 QUERY request + partial tail RST_STREAM succeeded");
        sub.assert_eq(consumed, (req_wire.len - 9) as i64, "Consumed complete frames, left 9-byte incomplete RST_STREAM");
        sub.assert_gt(wire_out.len, 0, "Stream 1 was NOT falsely cancelled by incomplete tail RST_STREAM");

        if wire_out.len >= 35 {
            var resp_dt = internal::new_dynamic_table(4096);
            var resp_list = internal::DecodedH2HeaderList { .. };
            let h_len = ((wire_out[26] as i64) << 16) | ((wire_out[27] as i64) << 8) | (wire_out[28] as i64);
            let dec_err = internal::decode_hpack_header_block(resp_dt, wire_out[35..(35 + h_len)], resp_list);
            sub.assert_eq(dec_err, rfc::H2_ERR_NO_ERROR, "Response HPACK decoded");
            sub.assert_eq(resp_list.fields[0].name[..], ":status", "First response field is :status");
            sub.assert_eq(resp_list.fields[0].value[..], "200", "HTTP/2 QUERY with Content-Type returned 200 OK (presence_mask populated)");
        }

        // F011: Incoming client GOAWAY frame on stream 0 must mark sess.conn.goaway_received = true
        var goaway_wire: u8[>..] = [];
        build_h2_test_frame_header(goaway_wire, 8, 0x07, 0x00, 0);
        goaway_wire.append([0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
        wire_out.clear();
        let _, ok_go = internal::handle_h2_server_ingress(sess, pipeline, timer, "127.0.0.1", goaway_wire[..], 1000, wire_out);
        sub.assert_true(ok_go, "Client GOAWAY frame accepted");
        sub.assert_true(sess.conn.goaway_received, "sess.conn.goaway_received set to true");
    };
}

fn test_s3a(t: lit::T&) {
    t.run("3a. ExtensionsPool and HEAD Content-Length dedup") { sub =>
        // F020: ExtensionsPool resets conn_id and request_seq
        var ext_pool = internal::ExtensionsPool { .. };
        let e_idx = internal::acquire_extensions(ext_pool);
        ext_pool.slots[e_idx].conn_id = 99;
        ext_pool.slots[e_idx].request_seq = 42;
        internal::release_extensions(ext_pool, e_idx);
        sub.assert_eq(ext_pool.slots[e_idx].conn_id, 0, "conn_id reset on release");
        sub.assert_eq(ext_pool.slots[e_idx].request_seq, 0, "request_seq reset on release");

        // F017: HEAD request must NOT emit duplicate Content-Length: 0 and Content-Length: 13
        var server = wing::new_http_server("127.0.0.1", 8080);
        wing::add_get_route(server, "/head-check", 1001);
        let head_req = "HEAD /head-check HTTP/1.1\r\nHost: 127.0.0.1\r\nSec-Fetch-Site: same-origin\r\n\r\n";
        var head_out: u8[>..] = [];
        let outcome_h, ok_h = wing::handle_connection_wire(server, "127.0.0.1", head_req, 1000000000, head_out);
        sub.assert_true(ok_h && outcome_h == wing::PipelineOutcome.Handled, "HEAD request handled");
        sub.assert_contains(head_out[..], "Content-Length: 13\r\n", "HEAD response preserves GET Content-Length: 13");
        sub.assert_false(core::contains(head_out[..], "Content-Length: 0\r\n"), "HEAD response must NOT also emit Content-Length: 0");
    };
}

fn test_s3b(t: lit::T&) {
    t.run("3b. CORS/CSRF PSO & RFC 7239 Forwarded") { sub =>
        // F015: Rejected CORS preflight must short-circuit and NOT fall through to route handler
        let quota = wing::new_gcra_quota(100, core::secs(1), 10);
        var cfg = wing::new_server_pipeline_config("example.com", quota);
        wing::add_allowed_origin(cfg.cors_policy, "https://trusted.example.com");
        wing::add_route(cfg.router, "OPTIONS", "/cors-resource", 55);
        var timer = internal::new_connection_timer(30000000000, 1000000000);
        var bad_preflight = wing::new_request("OPTIONS", "/cors-resource");
        wing::set_header(bad_preflight, "Origin", "https://evil.attacker.com");
        wing::set_header(bad_preflight, "Access-Control-Request-Method", "POST");
        var res_cors = wing::Response { .. };
        var fut_cors = internal::new_inline_handler_future(0);
        let out_cors = wing::execute_pipeline(cfg, timer, "127.0.0.1", bad_preflight, 1000000000, res_cors, fut_cors);
        sub.assert_true(out_cors == wing::PipelineOutcome.CsrfRejected, "Rejected CORS preflight must be rejected, not routed to handler");
        sub.assert_eq(res_cors.status_code, 403, "Rejected CORS preflight returns 403");

        // F018: RFC 7239 Forwarded with quoted ';for=1.2.3.4' inside extension param
        let fwd_ip = wing::extract_rfc7239_forwarded_for("ext=\"a;for=1.2.3.4,b\";for=203.0.113.77;proto=https");
        sub.assert_eq(fwd_ip, "203.0.113.77", "Quoted ';for=' inside extension parameter ignored in favor of real for= parameter");
    };
}

fn test_s4(t: lit::T&) {
    t.run("4. RadixRouter >64B static, non-dot suffix, backtrack & OPTIONS") { sub =>
        // F021 & F022: Static route > 64 bytes and node splitting without priority underflow
        var router = wing::new_radix_router();
        let long_route: const u8[:] = "/api/v1/organizations/departments/engineering/teams/backend/services/authentication/status";
        sub.assert_true(wing::insert_route(router.trees[0].tree, long_route, 77), "insert >64B static route succeeds");
        var params = wing::ZeroAllocParams { .. };
        let m_long = wing::match_path(router.trees[0].tree, long_route, params);
        let ok_long = match m_long {
            Found f => f.handler_id == 77,
            _ => false,
        };
        sub.assert_true(ok_long, ">64B static route matches accurately");

        // F025a: Non-dot parameter suffix (/items/{id}-summary)
        sub.assert_true(wing::insert_route(router.trees[1].tree, "/items/{id}-summary", 88), "insert hyphen suffix route");
        let m_sfx = wing::match_path(router.trees[1].tree, "/items/abc42-summary", params);
        let ok_sfx = match m_sfx {
            Found f => f.handler_id == 88,
            _ => false,
        };
        sub.assert_true(ok_sfx, "non-dot suffix route /items/{id}-summary matches");
        sub.assert_eq(wing::param_val(params, 0, "/items/abc42-summary"), "abc42", "extracted param 'abc42' before '-summary'");

        // F025b: Static-to-param backtracking (/users/profile/settings + /users/{id} queried with /users/profile)
        wing::insert_route(router.trees[2].tree, "/users/profile/settings", 1);
        wing::insert_route(router.trees[2].tree, "/users/{id}", 2);
        let m_bt = wing::match_path(router.trees[2].tree, "/users/profile", params);
        let ok_bt = match m_bt {
            Found f => f.handler_id == 2,
            _ => false,
        };
        sub.assert_true(ok_bt, "/users/profile backtracks from partial static /users/profile/settings to /users/{id}");
        sub.assert_eq(wing::param_val(params, 0, "/users/profile"), "profile", "backtracked param is 'profile'");

        // F026: resolve_effective_route_path populates out_canon_path even when path is already canonical
        wing::add_route(router, "POST", "/canonical/tier1/route/test", 12);
        var canon_out: u8[..256] = [];
        let m_canon = wing::match_route(router, "POST", "/canonical/tier1/route/test", params, canon_out);
        sub.assert_eq(canon_out[..], "/canonical/tier1/route/test", "out_canon_path populated on already-canonical Tier-1 route");

        // F029: OPTIONS * on router with a single route in a method tree
        let m_star = wing::match_route(router, "OPTIONS", "*", params);
        let ok_star = match m_star {
            MethodNotAllowed mna => core::contains(mna.allow_header[..], "POST"),
            _ => false,
        };
        sub.assert_true(ok_star, "OPTIONS * includes POST when POST tree has a single root route");
    };
}

fn test_s5a(t: lit::T&) {
    t.run("5a. Server Host/CONNECT, serializer & mmap") { sub =>
        // F030: Host header with invalid port must be rejected
        var req_bad_port = wing::Request { .. };
        let ok_bp1, _ = wing::parse_http1_wire_request("GET / HTTP/1.1\r\nHost: example.com:99999\r\n\r\n", req_bad_port);
        sub.assert_false(ok_bp1, "Host port > 65535 must be rejected");
        let ok_bp2, _ = wing::parse_http1_wire_request("GET / HTTP/1.1\r\nHost: example.com:abc\r\n\r\n", req_bad_port);
        sub.assert_false(ok_bp2, "Non-numeric Host port must be rejected");
        let ok_bp3, _ = wing::parse_http1_wire_request("GET / HTTP/1.1\r\nHost: :8080\r\n\r\n", req_bad_port);
        sub.assert_false(ok_bp3, "Empty host before colon must be rejected");

        // F031: CONNECT with valid IPv6 authority [::1]:443 must succeed
        var req_conn = wing::Request { .. };
        let ok_conn, _ = wing::parse_http1_wire_request("CONNECT [::1]:443 HTTP/1.1\r\nHost: [::1]:443\r\n\r\n", req_conn);
        sub.assert_true(ok_conn, "CONNECT [::1]:443 HTTP/1.1 must succeed");

        // F039: serialize_http1_headers with 1 custom header pushed directly (presence_mask == 0) must NOT rewrite it to Content-Type!
        var res_custom = wing::Response { status_code: 200, .. };
        res_custom.headers.push(wing::make_header("X-Custom-Tag", "my-val"));
        var custom_wire: u8[..512] = [];
        wing::serialize_http1_response(res_custom, "goose-wing", custom_wire);
        sub.assert_contains(custom_wire[..], "X-Custom-Tag: my-val\r\n", "Custom header preserved");
        sub.assert_false(core::contains(custom_wire[..], "Content-Type: my-val\r\n"), "Custom header not rewritten to Content-Type");

        // F051: serve_static_mmap_file on a file < 4096 bytes ("version.txt") must include the file body!
        var mmap_wire: u8[>..] = [];
        let ok_mmap = wing::serve_static_mmap_file("version.txt", "text/plain", mmap_wire);
        sub.assert_true(ok_mmap, "serve_static_mmap_file opened version.txt");
        let body_sep = find(mmap_wire[..], "\r\n\r\n");
        sub.assert_gt(body_sep, 0, "Response headers serialized");
        sub.assert_gt(mmap_wire.len - (body_sep + 4), 0, "Small mmap file (<4096B) body must not be empty");
    };
}

fn test_s5b(t: lit::T&) {
    t.run("5b. Pipelined parse failure 400 dedup") { sub =>
        // F048: handle_connection_wire_pipelined on invalid first request must emit exactly ONE HTTP/1.1 400 Bad Request
        var server = wing::new_http_server("127.0.0.1", 8080);
        let bad_req = "GET / HTTP/1.1\r\nHost : bad-colon\r\n\r\n";
        var pipe_out: u8[..1024] = [];
        let _, ok_pipe = wing::handle_connection_wire_pipelined(server, "127.0.0.1", bad_req, 1000000000, pipe_out);
        sub.assert_false(ok_pipe, "Invalid request in pipelined wire rejected");
        let first_400 = find(pipe_out[..], "HTTP/1.1 400 Bad Request");
        sub.assert_ge(first_400, 0, "First 400 Bad Request emitted");
        let second_400 = find(pipe_out[(first_400 + 24)..], "HTTP/1.1 400 Bad Request");
        sub.assert_eq(second_400, -1, "Must NOT emit duplicate 400 Bad Request on parse failure");
    };
}

fn run_round2_part1a(t: lit::T&) {
    t.run("6a. Round 2 Server Audit Regressions (EdgeFilter & H2)") { sub =>
        // R2-F001: add_edge_filter_rule rejects disabled rules (>64B prefix), and edge_rule_matches canonicalizes path
        let long_pfx: const u8[:] = "/api/v1/012345678901234567890123456789012345678901234567890123456789/secret";
        let r_disabled = wing::make_edge_filter_rule("long", long_pfx, wing::EdgeFilterVerdict.BlockForbidden);
        var ef = wing::EdgeFilter { .. };
        sub.assert_false(wing::add_edge_filter_rule(ef, r_disabled), "add_edge_filter_rule must reject disabled overflow rule");
        let r_admin = wing::make_edge_filter_rule("block-admin", "/admin", wing::EdgeFilterVerdict.BlockForbidden);
        sub.assert_true(wing::add_edge_filter_rule(ef, r_admin), "add_edge_filter_rule accepts valid rule");
        var empty_hdrs: wing::HeaderItem[..4] = [];
        sub.assert_true(wing::edge_rule_matches(r_admin, "//admin/panel", empty_hdrs[..]), "edge_rule_matches catches //admin/panel");
        sub.assert_true(wing::edge_rule_matches(r_admin, "/./admin/panel", empty_hdrs[..]), "edge_rule_matches catches /./admin/panel");
        sub.assert_true(wing::edge_rule_matches(r_admin, "/public/../admin/panel", empty_hdrs[..]), "edge_rule_matches catches /public/../admin/panel");

        // R2-F002: reset_h2_server_session_inplace resets urgency_heads and urgency_tails to -1
        var h2_sess = internal::new_h2_server_session("goose-wing/1.0", 1000);
        h2_sess.conn.urgency_heads[3] = 5;
        h2_sess.conn.urgency_tails[3] = 5;
        internal::reset_h2_server_session_inplace(h2_sess, "goose-wing/1.0", 2000);
        sub.assert_eq(h2_sess.conn.urgency_heads[3], -1, "urgency_heads reset to -1");
        sub.assert_eq(h2_sess.conn.urgency_tails[3], -1, "urgency_tails reset to -1");

        // R2-F003: emit_response_trailers when all trailers are disallowed emits 0-length DATA(END_STREAM), not 0-length HEADERS
        var bad_trailers: wing::HeaderItem[..16] = [];
        bad_trailers.push(wing::make_header("content-length", "10"));
        var tr_wire: u8[..128] = [];
        internal::emit_response_trailers(h2_sess, 1, bad_trailers, tr_wire);
        sub.assert_eq(tr_wire.len, 9, "Filtered empty trailer block emits 9-byte frame");
        if tr_wire.len >= 9 {
            sub.assert_eq(tr_wire[3], 0x00, "Filtered empty trailer emits DATA frame (0x00), not HEADERS (0x01)");
            sub.assert_eq(tr_wire[4], 0x01, "Filtered empty trailer sets END_STREAM (0x01)");
        }

        // R2-F004 & R2-F005: 0-length DATA on closed stream does not emit WINDOW_UPDATE(0); self-dependent PRIORITY terminates stream
        var pipeline = wing::new_server_pipeline_config("example.com", wing::new_gcra_quota(1000, core::secs(1), 100));
        var timer = internal::new_connection_timer(30000000000, 1000000000);
        wing::add_route(pipeline.router, "GET", "/test", 10);
        var h2_wire: u8[>..] = [];
        h2_wire.append(rfc::H2_CLIENT_PREFACE);
        build_h2_test_frame_header(h2_wire, 0, 0x04, 0x00, 0);
        var h2_out: u8[>..] = [];
        let _, _ = internal::handle_h2_server_ingress(
            h2_sess, pipeline, timer, "127.0.0.1", h2_wire[..], 1000, h2_out,
        );
        h2_sess.conn.last_peer_stream_id = 1;
        var zero_data_wire: u8[>..] = [];
        build_h2_test_frame_header(zero_data_wire, 0, 0x00, 0x01, 1);
        h2_out.clear();
        let _, ok_zd = internal::handle_h2_server_ingress(
            h2_sess, pipeline, timer, "127.0.0.1", zero_data_wire[..], 1000, h2_out,
        );
        sub.assert_true(ok_zd, "0-length DATA on closed stream handled");
        sub.assert_eq(h2_out.len, 13, "Only 13-byte RST_STREAM emitted, no illegal WINDOW_UPDATE(0)");
    };
}

fn run_round2_part1b(t: lit::T&) {
    t.run("6b. Round 2 Server Audit Regressions (H2 Host, Timer, Router)") { sub =>
        // R2-F006: copy_stream_headers_and_trailers preserves synthesized Host from :authority even with 32 regular headers
        var st_full = internal::H2ServerStream { .. };
        st_full.authority.append("api.example.com");
        for h_i in 32 {
            var hname: u8[..64] = [];
            hname.append("x-custom-");
            core::fast_u64toa(h_i as u64, hname);
            st_full.headers.push(wing::make_header(hname[..], "v"));
        }
        var req_h2_full = wing::new_request("GET", "/test");
        internal::copy_stream_headers_and_trailers(st_full, req_h2_full);
        sub.assert_eq(wing::header(req_h2_full, "host"), "api.example.com", "Synthesized host header preserved when 32 regular headers present");

        // R2-F008: check_connection_tick does not underflow u64 when now_ns < timer.last_tick_mono_ns
        var ctimer = internal::new_connection_timer(30000000000, 1000000000);
        sub.assert_true(internal::check_connection_tick(ctimer, 500), "now_ns < last_tick_mono_ns must not wrap u64");
        sub.assert_eq(ctimer.missed_ticks, 0, "missed_ticks remains 0 when now_ns < last_tick_mono_ns");

        // R2-F013, R2-F014, R2-F015: Router unclosed '{*{}' guard, origin-form '://' preservation, and deep param backtracking
        var rtr = wing::new_radix_router();
        sub.assert_false(wing::insert_route(rtr.trees[0].tree, "/{*{}", 1), "Malformed /{*{} route rejected without slice abort");
        var norm_buf: u8[..256] = [];
        sub.assert_true(wing::canonicalize_route_path("/redirect/http://evil.com/admin", norm_buf), "Origin-form path with :// canonicalized");
        sub.assert_eq(norm_buf[..], "/redirect/http:/evil.com/admin", "Origin-form path must not strip prefix before ://");

        wing::insert_route(rtr.trees[1].tree, "/users/admin/settings", 10);
        wing::insert_route(rtr.trees[1].tree, "/users/{id}/profile", 20);
        var bt_params = wing::ZeroAllocParams { .. };
        let bt_res = wing::match_path(rtr.trees[1].tree, "/users/admin/profile", bt_params);
        let bt_ok = match bt_res {
            Found f => f.handler_id == 20,
            _ => false,
        };
        sub.assert_true(bt_ok, "/users/admin/profile backtracks from static /users/admin/settings to /users/{id}/profile");
        sub.assert_eq(wing::param_val(bt_params, 0, "/users/admin/profile"), "admin", "Extracted {id} == 'admin' after deep backtrack");
    };
}

fn run_round2_part2(t: lit::T&) {
    t.run("7. Round 2 Server Audit Regressions (HTTP/1.1, WS, SNI, MMap, SoA)") { sub =>
        // R2-F016: HTTP/1.1 bare LF in headers and bare LF smuggling before Transfer-Encoding must be rejected
        var req_lf = wing::Request { .. };
        let ok_lf1, _ = wing::parse_http1_wire_request("GET / HTTP/1.1\r\nHost: example.com\nUser-Agent: x\r\n\r\n", req_lf);
        sub.assert_false(ok_lf1, "Bare LF at end of request header line must be rejected");
        let ok_lf2, _ = wing::parse_http1_wire_request("POST / HTTP/1.1\r\nHost: example.com\r\n\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n", req_lf);
        sub.assert_false(ok_lf2, "Embedded bare LF before Transfer-Encoding must be rejected");
        var res_lf = wing::Response { .. };
        let ok_lf3, _ = wing::parse_http1_wire_response("HTTP/1.1 200 OK\r\nServer: gw\r\n\nContent-Length: 5\r\n\r\nhello", res_lf);
        sub.assert_false(ok_lf3, "Embedded bare LF in response headers block must be rejected");

        // R2-F018: feed_http_stream_chunk decodes chunked body framing and marks consumer.is_finished = true
        var stream_req = wing::Request { .. };
        var consumer = wing::HttpStreamConsumer { .. };
        let chunk_wire = "POST /upload HTTP/1.1\r\nHost: example.com\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n";
        let ok_begin, body_off = wing::begin_http_stream_request(chunk_wire, stream_req, consumer);
        sub.assert_true(ok_begin && consumer.is_chunked, "Chunked stream request initialized");
        var streamed_payload: u8[..64] = [];
        var saw_last = false;
        let consumed_ch, is_last_ch, ok_ch = wing::feed_http_stream_chunk(consumer, chunk_wire[body_off..]) { data, last =>
            streamed_payload.append(data);
            if last { saw_last = true; }
        };
        sub.assert_true(ok_ch && is_last_ch && saw_last && consumer.is_finished, "Chunked stream decoded to completion");
        sub.assert_eq(streamed_payload[..], "hello", "Chunked stream callback received decoded payload without chunk size framing");
        sub.assert_eq(consumed_ch, (chunk_wire.len - body_off) as i64, "Consumed exact chunked body bytes");

        // R2-F019 & R2-F020: WebSocket route matching with query string, SNI >4096B guard and trailing dot exact match
        var srv = wing::new_http_server("127.0.0.1", 8080);
        let ws_b = wing::WsBehavior { .. };
        sub.assert_true(wing::add_ws_route(srv, "/ws/live", ws_b), "Registered /ws/live");
        sub.assert_ge(wing::find_ws_route(srv, "/ws/live?token=abc"), 0, "find_ws_route matches request URL with query string");

        var oversize_pem: u8[..4200] = [];
        for k in 4100 { oversize_pem.push('A'); }
        sub.assert_false(wing::add_server_name(srv, "api.example.com", "CERT", oversize_pem[..]), "add_server_name rejects >4096B PEM");
        sub.assert_true(wing::add_server_name(srv, "*.wildcard.org", "CERT_WILD", "KEY_WILD"), "Registered wildcard SNI");
        sub.assert_true(wing::add_server_name(srv, "special.wildcard.org", "CERT_EXACT", "KEY_EXACT"), "Registered exact SNI");
        let sni_cred, ok_sni = wing::resolve_sni_credentials(srv, "special.wildcard.org.");
        sub.assert_true(ok_sni, "Resolved SNI with trailing dot");
        sub.assert_eq(sni_cred.cert_pem, "CERT_EXACT", "Exact SNI match takes priority even with trailing DNS dot");

        // R2-F021 & R2-F022: serve_static_mmap_file truncation guard & oversized chunked pipelined 413 rejection
        var tiny_cork = core::new_cork_buffer();
        tiny_cork.len = core::CORK_BUFFER_CAP - 16;
        sub.assert_false(wing::serve_static_mmap_file("version.txt", "text/plain", tiny_cork), "serve_static_mmap_file rejects truncated output buffer");
    };
}

fn run_round2_part3(t: lit::T&) {
    t.run("8. Round 2 Server Audit Regressions (Oversized Chunk 413 & SoA)") { sub =>
        let chunk_wire = "POST /upload HTTP/1.1\r\nHost: 127.0.0.1\r\nTransfer-Encoding: chunked\r\n\r\n10000000\r\nABCD";
        var req_huge = wing::Request { .. };
        let _, _ = wing::parse_http1_wire_request(chunk_wire, req_huge);
        var keep_huge = true;
        var huge_out: u8[..512] = [];
        let _ = wing::handle_pipelined_parse_failure("goose-wing/1.0", chunk_wire, req_huge, huge_out, keep_huge);
        sub.assert_false(keep_huge, "Oversized chunk size > 10MB in pipelined stream closes connection");
        sub.assert_contains(huge_out[..], "HTTP/1.1 413", "Oversized chunk emits 413 Payload Too Large");

        // R2-F023: soa_table_free shrinks trailing high-water mark
        var soa = wing::SoAConnTable { .. };
        let s0 = wing::soa_table_alloc(soa, 10, 5);
        let s1 = wing::soa_table_alloc(soa, 11, 5);
        sub.assert_eq(soa.count, 2, "SoA high-water mark is 2");
        wing::soa_table_free(soa, s1);
        sub.assert_eq(soa.count, 1, "SoA high-water mark shrinks to 1 when highest slot freed");
        wing::soa_table_free(soa, s0);
        sub.assert_eq(soa.count, 0, "SoA high-water mark shrinks to 0 when all slots freed");
    };
}

fn main() {
    var runner = lit::new_runner("Server Audit Regressions Suite", lit::Verbosity.Verbose);
    lit::run_case(runner, "1. EdgeFilter", test_s1);
    lit::run_case(runner, "2. H2ServerSession", test_s2);
    lit::run_case(runner, "3a. HEAD Dedup", test_s3a);
    lit::run_case(runner, "3b. CORS/CSRF", test_s3b);
    lit::run_case(runner, "4. RadixRouter", test_s4);
    lit::run_case(runner, "5a. Server Wire", test_s5a);
    lit::run_case(runner, "5b. Pipelined 400 Dedup", test_s5b);
    lit::run_case(runner, "6a. Round 2 Part 1a", run_round2_part1a);
    lit::run_case(runner, "6b. Round 2 Part 1b", run_round2_part1b);
    lit::run_case(runner, "7. Round 2 Part 2", run_round2_part2);
    lit::run_case(runner, "8. Round 2 Part 3", run_round2_part3);
    let ok = lit::finish(runner);
    assert(ok);
    print("SERVER_AUDIT_REGRESSIONS_VERIFIED");
}

// CHECK: SERVER_AUDIT_REGRESSIONS_VERIFIED
