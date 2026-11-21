// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Consolidated Verification Suite: Server Router, Pipeline, and Fault Tolerance Verification Suite
//
// RUN: goose build -o %t.exe %s
// RUN: %t.exe
import std;
import wing from "..";
import lit from "github.com/Lemon4ksan/goose-lit@v0.1.0";

// --- Component: server_router ---
// Tests for radix tree routing, buffer pools, and server execution pipeline.

// ----------------------------------------------------------------------------
// 1. Zero-Allocation Parameter Extraction & Byte Spans
// ----------------------------------------------------------------------------
fn test_zero_alloc_params(t: lit::T&) {
    t.run("Span Slicing Without Heap Allocations") { sub =>
        var params = http::ZeroAllocParams { .. };
        let req_path = "/users/alice99/settings";
        let template = "/users/{username}/settings";

        // Record span for username: val is "alice99" at [7..14], key is "{username}" at [7..17]
        sub.assert_true(http::add_param(params, 8, 16, 7, 14), "param added to span storage");
        sub.assert_eq(params.len, 1, "params count is 1");

        let val = http::param_val(params, 0, req_path);
        sub.assert_eq(val, "alice99", "zero-copy value extraction");

        let key = http::param_key(params, 0, template);
        sub.assert_eq(key, "username", "zero-copy key template extraction");

        // Clear params in place
        http::clear(params);
        sub.assert_eq(params.len, 0, "params cleared");

        var sreq = server::ServerRequest { .. };
        sreq.raw_header_arena.append("Authorization: Bearer test");
        server::reset_server_request(sreq);
        sub.assert_eq(sreq.raw_header_arena.len, 0, "arena cleared");
    };
}

// ----------------------------------------------------------------------------
// 2. Radix Trie: Static Precedence, Catch-All & Method Isolation
// ----------------------------------------------------------------------------
fn test_radix_trie_routing(t: lit::T&) {
    t.run("Static Route Priority Over Parameter") { sub =>
        var tree = server::new_radix_tree();
        server::insert_route(tree, "/users/{id}", 101);
        server::insert_route(tree, "/users/profile", 202);

        var params = http::ZeroAllocParams { .. };

        // Exact static route must take precedence
        let match_profile = server::match_path(tree, "/users/profile", params);
        let ok_profile = match match_profile {
            Found f => f.handler_id == 202,
            _ => false,
        };
        sub.assert_true(ok_profile, "static route /users/profile matches handler 202 (not /users/{id})");

        // Dynamic route matches
        let match_dyn = server::match_path(tree, "/users/42", params);
        let ok_dyn = match match_dyn {
            Found f => f.handler_id == 101,
            _ => false,
        };
        sub.assert_true(ok_dyn, "dynamic route /users/42 matches handler 101");
        sub.assert_eq(http::param_val(params, 0, "/users/42"), "42", "extracted id param '42'");
    };

    t.run("Catch-All Route Matching") { sub =>
        var tree = server::new_radix_tree();
        server::insert_route(tree, "/assets/{*filepath}", 303);

        var params = http::ZeroAllocParams { .. };
        let match_res = server::match_path(tree, "/assets/images/icons/logo.png", params);
        let ok = match match_res {
            Found f => f.handler_id == 303,
            _ => false,
        };
        sub.assert_true(ok, "catchall matches multi-segment remainder");
        sub.assert_eq(http::param_val(params, 0, "/assets/images/icons/logo.png"), "images/icons/logo.png", "captured filepath");
    };

    t.run("matchit Issue #83 Monotonic Suffix Preservation") { sub =>
        // Order A: Insert {id}.json first, then {id}/comments.json
        var tree_a = server::new_radix_tree();
        server::insert_route(tree_a, "/posts/{id}.json", 1);
        server::insert_route(tree_a, "/posts/{id}/comments.json", 2);

        var p_a = http::ZeroAllocParams { .. };
        let m1_a = server::match_path(tree_a, "/posts/999.json", p_a);
        let ok1_a = match m1_a {
            Found f => f.handler_id == 1,
            _ => false,
        };
        sub.assert_true(ok1_a, "Order A: /posts/999.json matches handler 1");

        let m2_a = server::match_path(tree_a, "/posts/999/comments.json", p_a);
        let ok2_a = match m2_a {
            Found f => f.handler_id == 2,
            _ => false,
        };
        sub.assert_true(ok2_a, "Order A: /posts/999/comments.json matches handler 2");

        // Order B: Insert {id}/comments.json first, then {id}.json
        // Naive radix trees fail this because splitting overwrites suffix: true with suffix: false!
        var tree_b = server::new_radix_tree();
        server::insert_route(tree_b, "/posts/{id}/comments.json", 2);
        server::insert_route(tree_b, "/posts/{id}.json", 1);

        var p_b = http::ZeroAllocParams { .. };
        let m1_b = server::match_path(tree_b, "/posts/999.json", p_b);
        let ok1_b = match m1_b {
            Found f => f.handler_id == 1,
            _ => false,
        };
        sub.assert_true(ok1_b, "Order B: /posts/999.json matches handler 1 (Issue #83 fixed!)");

        let m2_b = server::match_path(tree_b, "/posts/999/comments.json", p_b);
        let ok2_b = match m2_b {
            Found f => f.handler_id == 2,
            _ => false,
        };
        sub.assert_true(ok2_b, "Order B: /posts/999/comments.json matches handler 2");
    };

    t.run("Multi-Method Isolation & 405 Method Not Allowed") { sub =>
        var router = server::new_radix_router();
        server::add_route(router, "GET", "/api/items", 10);
        server::add_route(router, "POST", "/api/items", 20);

        var params = http::ZeroAllocParams { .. };

        // GET matches
        let m_get = server::match_route(router, "GET", "/api/items", params);
        let ok_get = match m_get {
            Found f => f.handler_id == 10,
            _ => false,
        };
        sub.assert_true(ok_get, "GET /api/items found");

        // POST matches
        let m_post = server::match_route(router, "POST", "/api/items", params);
        let ok_post = match m_post {
            Found f => f.handler_id == 20,
            _ => false,
        };
        sub.assert_true(ok_post, "POST /api/items found");

        // PUT is not allowed -> returns 405 with Allow: GET, POST, HEAD
        let m_put = server::match_route(router, "PUT", "/api/items", params);
        let ok_put = match m_put {
            MethodNotAllowed mna => find(mna.allow_header[..], "GET") >= 0 && find(mna.allow_header[..], "POST") >= 0 && find(mna.allow_header[..], "HEAD") >= 0,
            _ => false,
        };
        sub.assert_true(ok_put, "PUT /api/items returns MethodNotAllowed with Allow header containing GET, POST, and HEAD");

        // RFC 9110 §9.3.2: HEAD automatically routes to GET handler when GET is registered
        let m_head = server::match_route(router, "HEAD", "/api/items", params);
        let ok_head = match m_head {
            Found f => f.handler_id == 10,
            _ => false,
        };
        sub.assert_true(ok_head, "HEAD /api/items automatically matches GET route handler 10");

        // OPTIONS capability probe includes OPTIONS in Allow header
        let m_opt = server::match_route(router, "OPTIONS", "/api/items", params);
        let ok_opt_allow = match m_opt {
            MethodNotAllowed mna => find(mna.allow_header[..], "OPTIONS") >= 0,
            _ => false,
        };
        sub.assert_true(ok_opt_allow, "OPTIONS capability probe contains OPTIONS in Allow header");

        // Route path canonicalization: registering with trailing slash matches without trailing slash
        server::add_route(router, "GET", "/trailing/slash/", 99);
        let m_ts1 = server::match_route(router, "GET", "/trailing/slash", params);
        let ok_ts1 = match m_ts1 {
            Found f => f.handler_id == 99,
            _ => false,
        };
        sub.assert_true(ok_ts1, "GET /trailing/slash matches route registered as /trailing/slash/");

        let m_ts2 = server::match_route(router, "GET", "/trailing/slash/", params);
        let ok_ts2 = match m_ts2 {
            Found f => f.handler_id == 99,
            _ => false,
        };
        sub.assert_true(ok_ts2, "GET /trailing/slash/ matches route registered as /trailing/slash/");

        // Completely unknown route returns NotFound (404)
        let m_none = server::match_route(router, "GET", "/unknown/path", params);
        let ok_none = match m_none {
            NotFound => true,
            _ => false,
        };
        sub.assert_true(ok_none, "unknown path returns NotFound");
    };
}

// ----------------------------------------------------------------------------
// 3. Tako v2 6-Mechanism Server Pool
// ----------------------------------------------------------------------------
fn test_tako_v2_pool_mechanisms(t: lit::T&) {
    t.run("HeaderMapPool Acquisition and Clean Release") { sub =>
        var pool = server_internal::HeaderMapPool { .. };
        let s0 = server_internal::acquire_header_map(pool);
        let s1 = server_internal::acquire_header_map(pool);

        sub.assert_true(s0 >= 0 && s1 >= 0 && s0 != s1, "acquired distinct header map slots");
        sub.assert_true(pool.pool[s0].in_use, "slot marked in_use");

        server_internal::release_header_map(pool, s0);
        sub.assert_false(pool.pool[s0].in_use, "slot released and in_use cleared");

        // Reacquire should reuse slot s0
        let s2 = server_internal::acquire_header_map(pool);
        sub.assert_eq(s2, s0, "reacquired released slot");
    };

    t.run("ExtensionsPool Sanitization (Zero State Leakage)") { sub =>
        var pool = server_internal::ExtensionsPool { .. };
        let idx = server_internal::acquire_extensions(pool);
        sub.assert_true(idx >= 0, "acquired extensions slot");

        // Populate slot with sensitive request state
        pool.slots[idx].peer_ip.append("192.168.1.50");
        pool.slots[idx].matched_route.append("/admin/secrets");
        http::add_param(pool.slots[idx].params, 1, 2, 3, 4);
        pool.slots[idx].populated_entries = 0xFF;

        // Release slot: must wipe all fields
        server_internal::release_extensions(pool, idx);
        sub.assert_false(pool.slots[idx].in_use, "slot released");
        sub.assert_eq(pool.slots[idx].peer_ip.len, 0, "peer_ip sanitized");
        sub.assert_eq(pool.slots[idx].matched_route.len, 0, "matched_route sanitized");
        sub.assert_eq(pool.slots[idx].params.len, 0, "params sanitized");
        sub.assert_eq(pool.slots[idx].populated_entries, 0, "populated_entries sanitized");
    };

    t.run("SyncHeadRelease & ConnectionTimer Slowloris Sweep") { sub =>
        var shr = server_internal::new_sync_head_release();
        sub.assert_false(shr.head_buffer_released, "starts unreleased");
        server_internal::mark_head_released(shr, 4096);
        sub.assert_true(shr.head_buffer_released, "marked released");
        sub.assert_eq(shr.bytes_consumed, 4096, "consumed 4096 bytes");

        // ConnectionTimer: 10s deadline
        let start_ns: u64 = 1000000000;
        var timer = server_internal::new_connection_timer(10000000000, start_ns);

        // Within deadline
        sub.assert_true(server_internal::check_connection_tick(timer, start_ns + 5000000000), "tick ok at 5s");

        // Beyond deadline: Slowloris sweep terminates connection
        sub.assert_false(server_internal::check_connection_tick(timer, start_ns + 11000000000), "tick fails after deadline exceeded");
    };
}

// ----------------------------------------------------------------------------
// 4. Unified Defense-in-Depth Pipeline Integration
// ----------------------------------------------------------------------------
fn test_unified_server_pipeline(t: lit::T&) {
    t.run("End-to-End Handled Request Lifecycle") { sub =>
        let quota = security::new_gcra_quota(100, wing::secs(1), 10);
        var cfg = server::new_server_pipeline_config("example.com", quota);
        server::add_route(cfg.router, "GET", "/api/v1/users/{id}", 42);

        var conn_timer = server_internal::new_connection_timer(30000000000, 1000000000);
        var req = http::new_request("GET", "/api/v1/users/777");
        http::set_header(req, "Host", "example.com");
        http::set_header(req, "Sec-Fetch-Site", "same-origin");
        http::set_header(req, "Sec-Fetch-Mode", "cors");
        http::set_header(req, "Sec-Fetch-Dest", "empty");

        var res = http::Response { .. };
        var fut = server_internal::new_inline_handler_future(0);

        let outcome = server::execute_pipeline(cfg, conn_timer, "127.0.0.1", req, 1000000000, res, fut);
        let ok_handled = match outcome {
            Handled => true,
            _ => false,
        };
        sub.assert_true(ok_handled, "pipeline returned Handled");
        sub.assert_eq(res.status_code, 200, "status code 200 OK");
        sub.assert_eq(fut.vtable_tag, 42, "handler 42 invoked");
    };

    t.run("Pipeline Rate Limiting Defense (Stage 1)") { sub =>
        let quota = security::new_gcra_quota(1, wing::secs(1), 0); // strictly 1 req/s
        var cfg = server::new_server_pipeline_config("example.com", quota);
        server::add_route(cfg.router, "GET", "/health", 1);

        var timer = server_internal::new_connection_timer(30000000000, 1000000000);
        var req = http::new_request("GET", "/health");
        http::set_header(req, "Sec-Fetch-Site", "same-origin");

        var res1 = http::Response { .. };
        var fut1 = server_internal::new_inline_handler_future(0);
        let out1 = server::execute_pipeline(cfg, timer, "10.0.0.1", req, 1000000000, res1, fut1);
        sub.assert_true(out1 == server::PipelineOutcome.Handled, "first request handled");

        // Second request at same nanosecond -> Rate Limited
        var res2 = http::Response { .. };
        var fut2 = server_internal::new_inline_handler_future(0);
        let out2 = server::execute_pipeline(cfg, timer, "10.0.0.1", req, 1000000000, res2, fut2);
        sub.assert_true(out2 == server::PipelineOutcome.RateLimited, "second request rate limited");
        sub.assert_eq(res2.status_code, 429, "status code 429 Too Many Requests");
    };

    t.run("Pipeline CSRF Defense (Stage 2)") { sub =>
        let quota = security::new_gcra_quota(100, wing::secs(1), 10);
        var cfg = server::new_server_pipeline_config("example.com", quota);
        server::add_route(cfg.router, "POST", "/api/transfer", 99);

        var timer = server_internal::new_connection_timer(30000000000, 1000000000);
        var evil_req = http::new_request("POST", "/api/transfer");
        http::set_header(evil_req, "Sec-Fetch-Site", "cross-site");
        http::set_header(evil_req, "Sec-Fetch-Mode", "cors");

        var res = http::Response { .. };
        var fut = server_internal::new_inline_handler_future(0);
        let out = server::execute_pipeline(cfg, timer, "192.168.1.1", evil_req, 1000000000, res, fut);
        sub.assert_true(out == server::PipelineOutcome.CsrfRejected, "cross-site mutation rejected by CSRF guard");
        sub.assert_eq(res.status_code, 403, "status code 403 Forbidden");
    };

    t.run("Pipeline Routing & 405 Method Not Allowed (Stage 3)") { sub =>
        let quota = security::new_gcra_quota(100, wing::secs(1), 10);
        var cfg = server::new_server_pipeline_config("example.com", quota);
        server::add_route(cfg.router, "GET", "/api/data", 10);

        var timer = server_internal::new_connection_timer(30000000000, 1000000000);

        // POST to GET-only route -> 405 Method Not Allowed
        var req_post = http::new_request("POST", "/api/data");
        http::set_header(req_post, "Sec-Fetch-Site", "same-origin");

        var res = http::Response { .. };
        var fut = server_internal::new_inline_handler_future(0);
        let out = server::execute_pipeline(cfg, timer, "127.0.0.1", req_post, 1000000000, res, fut);
        sub.assert_true(out == server::PipelineOutcome.MethodNotAllowed, "method not allowed triggered");
        sub.assert_eq(res.status_code, 405, "status code 405");

        sub.assert_true(res.has_header("Allow"), "Allow header returned");
        sub.assert_contains(res.header("Allow"), "GET", "Allow header indicates GET");
        sub.assert_contains(res.header("Allow"), "HEAD", "Allow header indicates HEAD when GET is supported");

        // Automatic HEAD routing in pipeline: executes GET handler and suppresses body (RFC 9110 §9.3.2)
        var req_head = http::new_request("HEAD", "/api/data");
        http::set_header(req_head, "Sec-Fetch-Site", "same-origin");
        var res_head = http::Response { .. };
        res_head.body.append("Should be suppressed");
        var fut_head = server_internal::new_inline_handler_future(0);
        let out_head = server::execute_pipeline(cfg, timer, "127.0.0.1", req_head, 1000000000, res_head, fut_head);
        sub.assert_true(out_head == server::PipelineOutcome.Handled, "HEAD request handled by GET route in pipeline");
        sub.assert_eq(res_head.status_code, 200, "HEAD status code 200");
        sub.assert_eq(res_head.body.len, 0, "HEAD response body is completely suppressed (len == 0)");
    };

    t.run("Pipeline Expect Header Validation (Stage 0.5) (RFC 9110 Section 10.1.1)") { sub =>
        let quota = security::new_gcra_quota(100, wing::secs(1), 10);
        var cfg = server::new_server_pipeline_config("example.com", quota);
        server::add_route(cfg.router, "POST", "/upload", 42);

        var timer = server_internal::new_connection_timer(30000000000, 1000000000);

        // 1. Valid Expect: 100-continue proceeds to pipeline routing
        var req_100 = http::new_request("POST", "/upload");
        http::set_header(req_100, "Sec-Fetch-Site", "same-origin");
        http::set_header(req_100, "Expect", "100-continue");

        var res1 = http::Response { .. };
        var fut1 = server_internal::new_inline_handler_future(0);
        let out1 = server::execute_pipeline(cfg, timer, "127.0.0.1", req_100, 1000000000, res1, fut1);
        sub.assert_true(out1 == server::PipelineOutcome.Handled, "Expect: 100-continue on valid route handled");

        // 2. Unknown Expect: foo-bar -> 417 Expectation Failed
        var req_unknown = http::new_request("POST", "/upload");
        http::set_header(req_unknown, "Sec-Fetch-Site", "same-origin");
        http::set_header(req_unknown, "Expect", "unknown-feature-flag");

        var res2 = http::Response { .. };
        var fut2 = server_internal::new_inline_handler_future(0);
        let out2 = server::execute_pipeline(cfg, timer, "127.0.0.1", req_unknown, 1000000000, res2, fut2);
        sub.assert_true(out2 == server::PipelineOutcome.ExpectationFailed, "unknown Expect rejected with ExpectationFailed");
        sub.assert_eq(res2.status_code, 417, "RFC 9110 status code 417 Expectation Failed");
    };

    t.run("Pipeline Bitmask PSO Fast-Path Probe & Egress Headers") { sub =>
        let quota = security::new_gcra_quota(1, wing::secs(1), 0); // strictly 1 req/s
        var cfg = server::new_server_pipeline_config("example.com", quota);

        // Fast-path bypass route (pso_mask = 0)
        server::add_route_pso(cfg.router, "GET", "/healthz", 1001, 0);

        // Route with security egress headers
        server::add_route_pso(cfg.router, "GET", "/secure", 1002, server::STAGE_EGRESS_SECURITY_HEADERS);

        var timer = server_internal::new_connection_timer(30000000000, 1000000000);

        // Request 1 to /healthz: even with invalid Expect header, passes via fast-path bypass
        var req1 = http::new_request("GET", "/healthz");
        http::set_header(req1, "Expect", "invalid-expectation");
        var res1 = http::Response { .. };
        var fut1 = server_internal::new_inline_handler_future(0);
        let out1 = server::execute_pipeline(cfg, timer, "10.0.0.1", req1, 1000000000, res1, fut1);
        sub.assert_true(out1 == server::PipelineOutcome.Handled, "fast-path /healthz handled");
        sub.assert_eq(res1.status_code, 200, "status code 200");
        sub.assert_bytes_eq(res1.body[..], "Hello, World!", "fast path body dispatched");

        // Request 2 to /healthz at same nanosecond: not rate limited because rate limiter is bypassed
        var res2 = http::Response { .. };
        var fut2 = server_internal::new_inline_handler_future(0);
        let out2 = server::execute_pipeline(cfg, timer, "10.0.0.1", req1, 1000000000, res2, fut2);
        sub.assert_true(out2 == server::PipelineOutcome.Handled, "second /healthz handled without rate limiting");

        // Request to /secure: gets egress security headers
        var req_sec = http::new_request("GET", "/secure");
        http::set_header(req_sec, "Host", "example.com");
        var res_sec = http::Response { .. };
        var fut_sec = server_internal::new_inline_handler_future(0);
        let out_sec = server::execute_pipeline(cfg, timer, "10.0.0.1", req_sec, 1000000000, res_sec, fut_sec);
        sub.assert_true(out_sec == server::PipelineOutcome.Handled, "secure route handled");
        sub.assert_true(res_sec.has_header("Strict-Transport-Security"), "HSTS header present");
        sub.assert_true(res_sec.has_header("Vary"), "Vary header present");
    };
}

// ----------------------------------------------------------------------------
// 5. Standalone HTTP Server Wire Handling & Protocol Detection
// ----------------------------------------------------------------------------
fn test_standalone_http_server(t: lit::T&) {
    t.run("1. HTTP/1.1 Wire Request Parsing & Response Serializer") { sub =>
        let wire_req = "POST /api/echo HTTP/1.1\r\nHost: localhost:8080\r\nContent-Length: 11\r\nContent-Type: text/plain\r\n\r\nHello World";
        var req = http::new_request("", "");
        let ok_parse, consumed = server::parse_http1_wire_request(wire_req, req);

        sub.assert_true(ok_parse, "Parsed raw HTTP/1.1 wire request");
        sub.assert_eq(consumed, wire_req.len as i64, "Consumed all wire bytes including body");
        sub.assert_bytes_eq(req.method[..], "POST", "Method is POST");
        sub.assert_bytes_eq(req.url[..], "/api/echo", "Path is /api/echo");
        sub.assert_bytes_eq(req.body[..], "Hello World", "Body payload extracted");

        var resp = http::Response { .. };
        resp.status_code = 200;
        http::set_header(resp, "content-type", "application/json");
        resp.body.append("{\"status\":\"ok\"}");

        var out_wire: u8[>..] = [];
        server::serialize_http1_response(resp, "goose-wing-server", out_wire);

        let out_str = out_wire[..];
        sub.assert_true(out_wire.len > 0, "Response wire serialized");
        sub.assert_true(out_str.len >= 15 && out_str[..15] == "HTTP/1.1 200 OK", "Status line HTTP/1.1 200 OK");
        sub.assert_contains(out_str, "Server: goose-wing-server\r\n", "Server header included");
        sub.assert_contains(out_str, "Content-Length: 15\r\n", "Content-Length matches body");
        sub.assert_contains(out_str, "Connection: keep-alive\r\n", "Connection: keep-alive included");
        sub.assert_contains(out_str, "{\"status\":\"ok\"}", "Response body included");
    };

    t.run("2. End-to-End handle_connection_wire Pipeline Dispatch") { sub =>
        var server = server::new_http_server("127.0.0.1", 8080);
        server::add_get_route(server, "/ping", 100);

        let client_req = "GET /ping HTTP/1.1\r\nHost: 127.0.0.1\r\nSec-Fetch-Site: same-origin\r\n\r\n";
        var client_resp_wire: u8[>..] = [];
        let outcome, ok_handled = server::handle_connection_wire(server, "127.0.0.1", client_req, 1000000000, client_resp_wire);

        sub.assert_true(ok_handled, "Wire connection handled");
        sub.assert_eq(outcome, server::PipelineOutcome.Handled, "Pipeline handled route");
        sub.assert_eq(server.requests_processed, 1, "1 request processed");
        sub.assert_contains(client_resp_wire[..], "HTTP/1.1 200 OK", "Response is 200 OK");

        // 404 Route Not Found
        let req_404 = "GET /missing HTTP/1.1\r\nHost: 127.0.0.1\r\nSec-Fetch-Site: same-origin\r\n\r\n";
        var resp_404_wire: u8[>..] = [];
        let outcome_404, _ = server::handle_connection_wire(server, "127.0.0.1", req_404, 1000000000, resp_404_wire);
        sub.assert_eq(outcome_404, server::PipelineOutcome.RouteNotFound, "Route not found");
        sub.assert_contains(resp_404_wire[..], "HTTP/1.1 404 Not Found", "Response is 404 Not Found");
    };

    t.run("3. HTTP/2 Connection Preface Detection & Handshake") { sub =>
        var server = server::new_http_server("127.0.0.1", 8443);

        // Client sends RFC 9113 24-byte preface: "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
        var wire_h2: u8[>..] = [];
        wire_h2.append(rfc::H2_CLIENT_PREFACE[..]);

        var server_h2_resp: u8[>..] = [];
        let outcome_h2, ok_h2 = server::handle_connection_wire(server, "127.0.0.1", wire_h2[..], 1000000000, server_h2_resp);

        sub.assert_true(ok_h2, "HTTP/2 preface detected");
        sub.assert_eq(outcome_h2, server::PipelineOutcome.Handled, "Handled");
        sub.assert_eq(server_h2_resp.len, 33, "Server responded with 33-byte HTTP/2 SETTINGS frame");
        sub.assert_eq(server_h2_resp[3], rfc::H2_FRAME_SETTINGS, "Frame type is SETTINGS (0x04)");
    };

    t.run("4. Incremental PipeBuffer Sans-IO Stream Parsing & Monotonicity") { sub =>
        var server = server::new_http_server("127.0.0.1", 8080);
        server::add_get_route(server, "/greet", 1);

        var pipe = core::new_pipe_buffer();

        // Packet 1: Incomplete request (headers truncated before final CRLF)
        let part1 = "GET /greet HTTP/1.1\r\nHost: 127.0.0.1\r\n";
        core::write(pipe, part1);

        var out_wire1: u8[>..] = [];
        let n1, ok1 = server::handle_connection_pipe(server, "127.0.0.1", pipe, 1000000000, out_wire1);

        sub.assert_true(ok1, "handle_connection_pipe succeeded on incomplete chunk");
        sub.assert_eq(n1, 0, "No complete request processed yet");
        sub.assert_eq(pipe.consumed, 0, "Pipe consumed is 0");
        sub.assert_eq(pipe.examined, part1.len, "Pipe examined advanced to end of chunk");
        sub.assert_eq(out_wire1.len, 0, "No output generated yet");

        // Packet 2: Remainder of request headers arriving
        let part2 = "Sec-Fetch-Site: same-origin\r\n\r\n";
        core::write(pipe, part2);

        var out_wire2: u8[>..] = [];
        let n2, ok2 = server::handle_connection_pipe(server, "127.0.0.1", pipe, 1000000000, out_wire2);

        sub.assert_true(ok2, "handle_connection_pipe succeeded when complete");
        sub.assert_eq(n2, 1, "1 complete request processed");
        sub.assert_eq(pipe.readable_len(), 0, "Pipe drained completely");
        sub.assert_gt(out_wire2.len, 0, "Response generated");
        sub.assert_contains(out_wire2[..], "HTTP/1.1 200 OK", "Status 200 OK");

        // Packet 3: Multiple pipelined requests in one buffer
        let req_a = "GET /greet HTTP/1.1\r\nHost: 127.0.0.1\r\nSec-Fetch-Site: same-origin\r\n\r\n";
        let req_b = "GET /greet HTTP/1.1\r\nHost: 127.0.0.1\r\nSec-Fetch-Site: same-origin\r\n\r\n";
        core::write(pipe, req_a);
        core::write(pipe, req_b);

        var out_wire3: u8[>..] = [];
        let n3, ok3 = server::handle_connection_pipe(server, "127.0.0.1", pipe, 1000000000, out_wire3);

        sub.assert_true(ok3, "handle_connection_pipe handled pipelined requests");
        sub.assert_eq(n3, 2, "2 pipelined requests processed");
        sub.assert_eq(pipe.readable_len(), 0, "Pipe drained completely");

        // Packet 4: Zero-Heap PipeBuffer + CorkBuffer Aggregation
        let req_c = "GET /greet HTTP/1.1\r\nHost: 127.0.0.1\r\nSec-Fetch-Site: same-origin\r\n\r\n";
        core::write(pipe, req_c);
        var cork = core::new_cork_buffer();
        let n4, ok4 = server::handle_connection_pipe(server, "127.0.0.1", pipe, 1000000000, cork);
        sub.assert_true(ok4, "handle_connection_pipe works with CorkBuffer");
        sub.assert_eq(n4, 1, "1 request processed into cork");
        sub.assert_gt(cork.cork_pending(), 0, "Cork buffer contains bytes");
        sub.assert_contains(cork.cork_as_slice(), "HTTP/1.1 200 OK", "Cork contains 200 OK");
        core::cork_consume(cork, cork.cork_pending());
        sub.assert_eq(cork.cork_pending(), 0, "Cork fully consumed");
    };

    t.run("5. HTTP Request Smuggling Defenses (RFC 9112 Section 6.1 & 6.3)") { sub =>
        var server = server::new_http_server("127.0.0.1", 8080);
        server::add_get_route(server, "/safe", 1);
        server::add_post_route(server, "/safe", 2);

        // 5.1 Leading whitespace before method (RFC 9112 §3.1)
        var out1: u8[>..] = [];
        let _, ok1 = server::handle_connection_wire(server, "127.0.0.1", " GET /safe HTTP/1.1\r\n\r\n", 1000000000, out1);
        sub.assert_false(ok1, "Leading space before method rejected");
        sub.assert_contains(out1[..], "400 Bad Request", "Returns 400 Bad Request");

        // 5.2 Single leading empty line (RFC 9112 §2.2) is allowed for robustness
        var out2: u8[>..] = [];
        let _, ok2 = server::handle_connection_wire(server, "127.0.0.1", "\r\nGET /safe HTTP/1.1\r\nHost: localhost\r\nSec-Fetch-Site: same-origin\r\n\r\n", 1000000000, out2);
        sub.assert_true(ok2, "Single leading CRLF allowed per RFC 9112 §2.2");

        // 5.3 Multiple leading empty lines (RFC 9112 §2.2) MUST be rejected
        var out3: u8[>..] = [];
        let _, ok3 = server::handle_connection_wire(server, "127.0.0.1", "\r\n\r\nGET /safe HTTP/1.1\r\nHost: localhost\r\n\r\n", 1000000000, out3);
        sub.assert_false(ok3, "Multiple leading CRLF rejected");

        // 5.4 Whitespace before colon in header (RFC 9112 §5.1, CVE-2019-16276)
        var out4: u8[>..] = [];
        let _, ok4 = server::handle_connection_wire(server, "127.0.0.1", "GET /safe HTTP/1.1\r\nHost : localhost\r\n\r\n", 1000000000, out4);
        sub.assert_false(ok4, "Space before colon rejected");

        // 5.5 Control character in URL path (RFC 9110 §4.1, CVE-2022-22970)
        var out5: u8[>..] = [];
        let bad_url: u8[28] = [
            'G' as u8, 'E' as u8, 'T' as u8, ' ' as u8,
            '/' as u8, 's' as u8, 'a' as u8, 'f' as u8, 'e' as u8, 0x00, // Embedded NUL CTL!
            ' ' as u8, 'H' as u8, 'T' as u8, 'T' as u8, 'P' as u8, '/' as u8, '1' as u8, '.' as u8, '1' as u8,
            '\r' as u8, '\n' as u8, '\r' as u8, '\n' as u8, 0, 0, 0, 0, 0,
        ];
        let _, ok5 = server::handle_connection_wire(server, "127.0.0.1", bad_url[..23], 1000000000, out5);
        sub.assert_false(ok5, "CTL in URL path rejected");

        // 5.6 Non-digit in Content-Length (RFC 9110 §8.6, Go #53188)
        var out6: u8[>..] = [];
        let _, ok6 = server::handle_connection_wire(server, "127.0.0.1", "POST /safe HTTP/1.1\r\nContent-Length: +10\r\n\r\n0123456789", 1000000000, out6);
        sub.assert_false(ok6, "Signed +10 Content-Length rejected");

        // 5.7 Conflict: both Transfer-Encoding and Content-Length present (RFC 9112 §6.1)
        var out7: u8[>..] = [];
        let _, ok7 = server::handle_connection_wire(server, "127.0.0.1", "POST /safe HTTP/1.1\r\nContent-Length: 5\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n", 1000000000, out7);
        sub.assert_false(ok7, "TE and CL conflict rejected");

        // 5.8 Conflicting duplicate Content-Length headers (RFC 9112 §6.3)
        var out8: u8[>..] = [];
        let _, ok8 = server::handle_connection_wire(server, "127.0.0.1", "POST /safe HTTP/1.1\r\nContent-Length: 5\r\nContent-Length: 6\r\n\r\nhello", 1000000000, out8);
        sub.assert_false(ok8, "Conflicting duplicate Content-Length rejected");
    };
}

// --- Component: server_fault_tolerance ---
// Fault Tolerance & Concurrency Verification Suite.
// Verifies:
// 1. Synchronous HttpServer.serve connection capping and clean loop exit.
// 2. Share-nothing HttpServer.serve_reactor connection capping, multiplexing, and teardown.
// 3. TopicTree multi-subscriber live WebSocket broadcast & batched palette drainage.

var g_served_sync:      i64                = 0;
var g_served_reactor:   i64                = 0;
var g_worker_sync_app:  server::HttpServer = server::HttpServer { .. };
var g_worker_react_app: server::HttpServer = server::HttpServer { .. };

thread_fn serve_sync_worker(listener_fd: i64, max_conns: i64, ring_handle: u64) {
    g_worker_sync_app.is_running = true;
    g_worker_sync_app.timer = server_internal::new_connection_timer(30000000000, 1000000000);
    g_worker_sync_app.pipeline.limiter = security::new_sharded_limiter(security::new_gcra_quota(1000, wing::secs(1), 100));
    g_worker_sync_app.pipeline.router = server::new_radix_router();
    let _ = g_worker_sync_app.pipeline.target_host.try_set("127.0.0.1");
    server::add_get_route(g_worker_sync_app, "/ping", 100);
    let served = server::serve(g_worker_sync_app, listener_fd, max_conns);
    g_served_sync = served;
    if ring_handle != 0 {
        core::native_spsc_push(ring_handle, served as u64);
    }
}

thread_fn serve_reactor_worker(listener_fd: i64, max_conns: i64, ring_handle: u64) {
    g_worker_react_app.is_running = true;
    g_worker_react_app.timer = server_internal::new_connection_timer(30000000000, 1000000000);
    g_worker_react_app.pipeline.limiter = security::new_sharded_limiter(security::new_gcra_quota(1000, wing::secs(1), 100));
    g_worker_react_app.pipeline.router = server::new_radix_router();
    let _ = g_worker_react_app.pipeline.target_host.try_set("127.0.0.1");
    server::add_get_route(g_worker_react_app, "/hello", 101);
    let served = server::serve_reactor(g_worker_react_app, listener_fd, max_conns);
    g_served_reactor = served;
    if ring_handle != 0 {
        core::native_spsc_push(ring_handle, served as u64);
    }
}

// ----------------------------------------------------------------------------
// 6. HttpServer.serve Connection Capping
// ----------------------------------------------------------------------------
fn test_serve_connection_capping(t: lit::T&) {
    t.run("Case 1: HttpServer.serve Clean Connection Capping (max_connections = 3)") { sub =>
        let listener = net::tcp_listen("127.0.0.1", 0, 16);
        sub.assert_gt(listener, 0, "Listener created");
        defer net::tcp_close(listener);

        let port = net::tcp_getsockname_port(listener);
        var ring, ok_ring = core::spsc_init(16);
        sub.assert_true(ok_ring, "spsc ring initialized");
        defer core::spsc_close(ring);

        let worker_tid = thread_spawn(serve_sync_worker, listener, 3 as i64, ring.handle);

        for i in 3 {
            let client = net::tcp_connect("127.0.0.1", port, 2000);
            sub.assert_gt(client, 0, "Client connected");

            let req_wire: const u8[:] = "GET /ping HTTP/1.1\r\nHost: 127.0.0.1\r\nSec-Fetch-Site: same-origin\r\nConnection: close\r\n\r\n";
            let s = net::tcp_send(client, req_wire);
            sub.assert_eq(s, req_wire.len as i32, "Client sent request");

            var resp_buf: u8[..512] = [];
            let r = net::tcp_recv(client, resp_buf, 512, 2000);
            sub.assert_gt(r, 0, "Client received response");
            sub.assert_true(find(resp_buf[..], "200 OK") >= 0, "Response is 200 OK");

            net::tcp_close(client);
        }

        let wait_ok = thread_wait(worker_tid);
        sub.assert_true(wait_ok, "serve worker thread terminated cleanly");
        var served_count: u64 = 0;
        let pop_ok = core::spsc_pop(ring, served_count);
        sub.assert_true(pop_ok, "served count received from worker");
        sub.assert_eq(served_count as i64, 3, "HttpServer.serve processed exactly 3 connections");
    };
}

// ----------------------------------------------------------------------------
// 7. HttpServer.serve_reactor Connection Capping
// ----------------------------------------------------------------------------
fn test_serve_reactor_connection_capping(t: lit::T&) {
    t.run("Case 2: HttpServer.serve_reactor Connection Capping & Epoll Shutdown") { sub =>
        let listener = net::tcp_listen("127.0.0.1", 0, 16);
        sub.assert_gt(listener, 0, "Listener created");
        defer net::tcp_close(listener);

        let port = net::tcp_getsockname_port(listener);
        var ring, ok_ring = core::spsc_init(16);
        sub.assert_true(ok_ring, "spsc ring initialized");
        defer core::spsc_close(ring);

        let worker_tid = thread_spawn(serve_reactor_worker, listener, 3 as i64, ring.handle);

        for i in 3 {
            let client = net::tcp_connect("127.0.0.1", port, 2000);
            sub.assert_gt(client, 0, "Client connected");

            let req_wire: const u8[:] = "GET /hello HTTP/1.1\r\nHost: 127.0.0.1\r\nSec-Fetch-Site: same-origin\r\nConnection: close\r\n\r\n";
            let s = net::tcp_send(client, req_wire);
            sub.assert_eq(s, req_wire.len as i32, "Client sent request");

            var resp_buf: u8[..512] = [];
            let r = net::tcp_recv(client, resp_buf, 512, 2000);
            sub.assert_gt(r, 0, "Client received response");
            sub.assert_true(find(resp_buf[..], "200 OK") >= 0, "Response is 200 OK");

            net::tcp_close(client);
        }

        let wait_ok = thread_wait(worker_tid);
        sub.assert_true(wait_ok, "serve_reactor worker thread terminated cleanly");
        var served_count: u64 = 0;
        let pop_ok = core::spsc_pop(ring, served_count);
        sub.assert_true(pop_ok, "served count received from worker");
        sub.assert_eq(served_count as i64, 3, "HttpServer.serve_reactor processed exactly 3 connections");
    };
}

// ----------------------------------------------------------------------------
// 8. TopicTree Live Broadcast & Batch Drainage
// ----------------------------------------------------------------------------
fn test_topic_tree_live_broadcast_and_batch_drain(t: lit::T&) {
    t.run("Case 3: TopicTree Live Socket Broadcast & Batch Drainage") { sub =>
        let listener = net::tcp_listen("127.0.0.1", 0, 16);
        sub.assert_gt(listener, 0, "Listener created");
        defer net::tcp_close(listener);

        let port = net::tcp_getsockname_port(listener);

        let c1 = net::tcp_connect("127.0.0.1", port, 2000);
        let c2 = net::tcp_connect("127.0.0.1", port, 2000);
        let c3 = net::tcp_connect("127.0.0.1", port, 2000);
        sub.assert_gt(c1, 0, "Client 1 connected");
        sub.assert_gt(c2, 0, "Client 2 connected");
        sub.assert_gt(c3, 0, "Client 3 connected");
        defer net::tcp_close(c1);
        defer net::tcp_close(c2);
        defer net::tcp_close(c3);

        let s1 = net::tcp_accept(listener, 2000);
        let s2 = net::tcp_accept(listener, 2000);
        let s3 = net::tcp_accept(listener, 2000);
        sub.assert_gt(s1, 0, "Server accepted 1");
        sub.assert_gt(s2, 0, "Server accepted 2");
        sub.assert_gt(s3, 0, "Server accepted 3");
        defer net::tcp_close(s1);
        defer net::tcp_close(s2);
        defer net::tcp_close(s3);

        var tree = realtime::TopicTree { .. };
        sub.assert_true(realtime::subscribe(tree, s1, "chat/general"), "s1 subscribed to chat/general");
        sub.assert_true(realtime::subscribe(tree, s2, "chat/general"), "s2 subscribed to chat/general");
        sub.assert_true(realtime::subscribe(tree, s3, "alerts/#"), "s3 subscribed to alerts/#");

        let sent_count = realtime::publish_text(tree, "chat/general", "ROOM_MSG");
        sub.assert_eq(sent_count, 2, "Dispatched to both subscribers s1 and s2");

        var buf1: u8[..256] = [];
        let r1 = net::tcp_recv(c1, buf1, 256, 1000);
        sub.assert_gt(r1, 0, "Client 1 received frame");
        sub.assert_true(find(buf1[..], "ROOM_MSG") >= 0, "Frame contains ROOM_MSG");

        var buf2: u8[..256] = [];
        let r2 = net::tcp_recv(c2, buf2, 256, 1000);
        sub.assert_gt(r2, 0, "Client 2 received frame");
        sub.assert_true(find(buf2[..], "ROOM_MSG") >= 0, "Frame contains ROOM_MSG");

        let queued = realtime::publish_batch(tree, "alerts/fire", "EVACUATE");
        sub.assert_eq(queued, 1, "Queued to 1 subscriber matching wildcard alerts/#");
        sub.assert_gt(realtime::drainable_count(tree), 0, "Drainable subscribers pending");

        let drained = realtime::drain(tree);
        sub.assert_eq(drained, 1, "Drained 1 batched message to wire");
        sub.assert_eq(realtime::drainable_count(tree), 0, "Zero drainable subscribers remaining");

        var buf3: u8[..256] = [];
        let r3 = net::tcp_recv(c3, buf3, 256, 1000);
        sub.assert_gt(r3, 0, "Client 3 received drained alert frame");
        sub.assert_true(find(buf3[..], "EVACUATE") >= 0, "Alert frame contains EVACUATE");
    };
}

// --- Component: server_pipeline_invariants ---
// Security invariant tests for Server Request Pipeline & HTTP/1.1 Pipelining:
// 1. HTTP/1.1 Pipelined request buffer parsing.
// 2. RFC 9112 Section 2.2 empty line tolerance & Section 3.1 leading whitespace ban.
// 3. Request target and Host header structural security invariants.

// ----------------------------------------------------------------------------
// 9. HTTP/1.1 Pipelining
// ----------------------------------------------------------------------------
fn test_server_http1_pipelining(t: lit::T&) {
    let wire: const u8[:] = "GET /first HTTP/1.1\r\nHost: example.com\r\n\r\nGET /second HTTP/1.1\r\nHost: example.com\r\n\r\n";

    var req1 = http::Request { .. };
    let ok1, consumed1 = server::parse_http1_wire_request(wire, req1);
    t.assert_true(ok1, "first pipelined request parsed successfully");
    t.assert_true(req1.url[..] == "/first", "first url matches");
    t.assert_true(consumed1 > 0 && consumed1 < wire.len, "consumed bytes valid");

    let rem_wire = wire[consumed1..];
    var req2 = http::Request { .. };
    let ok2, consumed2 = server::parse_http1_wire_request(rem_wire, req2);
    t.assert_true(ok2, "second pipelined request parsed successfully");
    t.assert_true(req2.url[..] == "/second", "second url matches");
    t.assert_eq(consumed1 + consumed2, wire.len, "entire pipelined stream consumed");
}

// ----------------------------------------------------------------------------
// 10. Empty Line & Whitespace Invariants
// ----------------------------------------------------------------------------
fn test_server_empty_line_and_whitespace_invariants(t: lit::T&) {
    // 1. RFC 9112 §2.2: Single empty line (\r\n) before request-line is tolerated
    let single_crlf: const u8[:] = "\r\nGET /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n";
    var req1 = http::Request { .. };
    let ok1, _ = server::parse_http1_wire_request(single_crlf, req1);
    t.assert_true(ok1, "single CRLF before request-line is tolerated");
    t.assert_true(req1.url[..] == "/index.html", "request url matches");

    // 2. RFC 9112 §2.2: Multiple empty lines (\r\n\r\n) before request-line MUST be rejected
    let double_crlf: const u8[:] = "\r\n\r\nGET /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n";
    var req2 = http::Request { .. };
    let ok2, _ = server::parse_http1_wire_request(double_crlf, req2);
    t.assert_false(ok2, "more than one CRLF before request-line must be rejected");

    // 3. RFC 9112 §3.1: Whitespace before method name MUST be rejected
    let ws_method: const u8[:] = " GET /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n";
    var req3 = http::Request { .. };
    let ok3, _ = server::parse_http1_wire_request(ws_method, req3);
    t.assert_false(ok3, "space before method name must be rejected");

    let tab_method: const u8[:] = "\tGET /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n";
    var req4 = http::Request { .. };
    let ok4, _ = server::parse_http1_wire_request(tab_method, req4);
    t.assert_false(ok4, "tab before method name must be rejected");
}

// ----------------------------------------------------------------------------
// 11. Target & Host Invariants
// ----------------------------------------------------------------------------
fn test_server_target_and_host_invariants(t: lit::T&) {
    // 1. Reject CTL character in request target
    let bad_ctl: const u8[:] = "GET /bad\x01path HTTP/1.1\r\nHost: example.com\r\n\r\n";
    var req1 = http::Request { .. };
    let ok1, _ = server::parse_http1_wire_request(bad_ctl, req1);
    t.assert_false(ok1, "CTL in request target must be rejected");

    // 2. Reject Host header with path or query delimiter
    let bad_host1: const u8[:] = "GET / HTTP/1.1\r\nHost: example.com/path\r\n\r\n";
    var req2 = http::Request { .. };
    let ok2, _ = server::parse_http1_wire_request(bad_host1, req2);
    t.assert_false(ok2, "Host header with path separator must be rejected");

    let bad_host2: const u8[:] = "GET / HTTP/1.1\r\nHost: example.com?query\r\n\r\n";
    var req3 = http::Request { .. };
    let ok3, _ = server::parse_http1_wire_request(bad_host2, req3);
    t.assert_false(ok3, "Host header with query delimiter must be rejected");

    // 3. Valid IPv6 literal host
    let ipv6_host: const u8[:] = "GET / HTTP/1.1\r\nHost: [::1]:8080\r\n\r\n";
    var req4 = http::Request { .. };
    let ok4, _ = server::parse_http1_wire_request(ipv6_host, req4);
    t.assert_true(ok4, "valid IPv6 literal host must succeed");
}

// ----------------------------------------------------------------------------
// 12. NGINX Reverse Proxy Harmony (X-Real-IP, Connection Close, SSE)
// ----------------------------------------------------------------------------
fn test_nginx_harmony_invariants(t: lit::T&) {
    t.run("1. X-Real-IP extraction with loopback and trust_proxy_headers") { sub =>
        var server = server::new_http_server("127.0.0.1", 8080);
        server.pipeline.enable_rate_limiter = true;
        server.pipeline.limiter = security::new_sharded_limiter(security::new_gcra_quota(1, wing::secs(1), 0));
        server::add_route(server.pipeline.router, "GET", "/ip-check", 1, 0);

        var req1: u8[..256] = [];
        req1.append("GET /ip-check HTTP/1.1\r\nHost: localhost\r\nX-Real-IP: 203.0.113.195\r\n\r\n");

        var out1: u8[..1024] = [];
        let outcome1, ok1 = server::handle_connection_wire(server, "127.0.0.1", req1[..], 1000000000, out1);
        sub.assert_true(ok1, "first request from 203.0.113.195 succeeds");
        sub.assert_true(outcome1 == server::PipelineOutcome.Handled, "first request handled");

        var req2: u8[..256] = [];
        req2.append("GET /ip-check HTTP/1.1\r\nHost: localhost\r\nX-Real-IP: 198.51.100.5\r\n\r\n");
        var out2: u8[..1024] = [];
        let outcome2, ok2 = server::handle_connection_wire(server, "127.0.0.1", req2[..], 1000000000, out2);
        sub.assert_true(ok2, "request from distinct client IP 198.51.100.5 succeeds despite burst limit on previous IP");
        sub.assert_true(outcome2 == server::PipelineOutcome.Handled, "distinct IP request handled");

        var req3: u8[..256] = [];
        req3.append("GET /ip-check HTTP/1.1\r\nHost: localhost\r\nX-Real-IP: 203.0.113.195\r\n\r\n");
        var out3: u8[..1024] = [];
        let outcome3, _ = server::handle_connection_wire(server, "127.0.0.1", req3[..], 1000000000, out3);
        sub.assert_true(outcome3 == server::PipelineOutcome.RateLimited, "second request from 203.0.113.195 is rate-limited");
        sub.assert_true(core::contains(out3[..], "429 Too Many Requests"), "response contains 429 status line");
    };

    t.run("2. X-Forwarded-For comma-separated list extraction") { sub =>
        var server = server::new_http_server("127.0.0.1", 8080);
        server.pipeline.enable_rate_limiter = true;
        server.pipeline.limiter = security::new_sharded_limiter(security::new_gcra_quota(1, wing::secs(1), 0));
        server::add_route(server.pipeline.router, "GET", "/xff-check", 1, 0);

        var req1: u8[..256] = [];
        req1.append("GET /xff-check HTTP/1.1\r\nHost: localhost\r\nX-Forwarded-For: 203.0.113.50, 10.0.0.1\r\n\r\n");
        var out1: u8[..1024] = [];
        let outcome1, _ = server::handle_connection_wire(server, "127.0.0.1", req1[..], 1000000000, out1);
        sub.assert_true(outcome1 == server::PipelineOutcome.Handled, "first request handled");

        var req2: u8[..256] = [];
        req2.append("GET /xff-check HTTP/1.1\r\nHost: localhost\r\nX-Forwarded-For: 203.0.113.50, 10.0.0.2\r\n\r\n");
        var out2: u8[..1024] = [];
        let outcome2, _ = server::handle_connection_wire(server, "127.0.0.1", req2[..], 1000000000, out2);
        sub.assert_true(outcome2 == server::PipelineOutcome.RateLimited, "same original client IP in XFF is rate limited");
    };

    t.run("2b. RFC 7239 Forwarded header extraction and precedence") { sub =>
        var server = server::new_http_server("127.0.0.1", 8080);
        server.pipeline.enable_rate_limiter = true;
        server.pipeline.limiter = security::new_sharded_limiter(security::new_gcra_quota(1, wing::secs(1), 0));
        server::add_route(server.pipeline.router, "GET", "/fwd-check", 1, 0);

        var req1: u8[..256] = [];
        req1.append("GET /fwd-check HTTP/1.1\r\nHost: localhost\r\nForwarded: for=\"192.0.2.60:4711\";proto=http\r\n\r\n");
        var out1: u8[..1024] = [];
        let outcome1, _ = server::handle_connection_wire(server, "127.0.0.1", req1[..], 1000000000, out1);
        sub.assert_true(outcome1 == server::PipelineOutcome.Handled, "first request handled");

        var req2: u8[..256] = [];
        req2.append("GET /fwd-check HTTP/1.1\r\nHost: localhost\r\nForwarded: for=192.0.2.60\r\nX-Real-IP: 10.0.0.1\r\n\r\n");
        var out2: u8[..1024] = [];
        let outcome2, _ = server::handle_connection_wire(server, "127.0.0.1", req2[..], 1000000000, out2);
        sub.assert_true(outcome2 == server::PipelineOutcome.RateLimited, "Forwarded header takes precedence and triggers rate limit");

        var req3: u8[..256] = [];
        req3.append("GET /fwd-check HTTP/1.1\r\nHost: localhost\r\nForwarded: for=\"[2001:db8:cafe::17]:8080\"\r\n\r\n");
        var out3: u8[..1024] = [];
        let outcome3, _ = server::handle_connection_wire(server, "127.0.0.1", req3[..], 1000000000, out3);
        sub.assert_true(outcome3 == server::PipelineOutcome.Handled, "IPv6 in Forwarded handled");
    };

    t.run("3. Untrusted remote IP ignores proxy headers when trust_proxy_headers is false") { sub =>
        var server = server::new_http_server("127.0.0.1", 8080);
        server.pipeline.enable_rate_limiter = true;
        server.pipeline.trust_proxy_headers = false;
        server.pipeline.limiter = security::new_sharded_limiter(security::new_gcra_quota(1, wing::secs(1), 0));
        server::add_route(server.pipeline.router, "GET", "/untrusted", 1, 0);

        var req1: u8[..256] = [];
        req1.append("GET /untrusted HTTP/1.1\r\nHost: localhost\r\nX-Real-IP: 1.1.1.1\r\n\r\n");
        var out1: u8[..1024] = [];
        let outcome1, _ = server::handle_connection_wire(server, "198.51.100.1", req1[..], 1000000000, out1);
        sub.assert_true(outcome1 == server::PipelineOutcome.Handled, "first request handled");

        var req2: u8[..256] = [];
        req2.append("GET /untrusted HTTP/1.1\r\nHost: localhost\r\nX-Real-IP: 2.2.2.2\r\n\r\n");
        var out2: u8[..1024] = [];
        let outcome2, _ = server::handle_connection_wire(server, "198.51.100.1", req2[..], 1000000000, out2);
        sub.assert_true(outcome2 == server::PipelineOutcome.RateLimited, "second request from same peer is rate limited, spoofed X-Real-IP ignored");
    };

    t.run("4. HTTP/1.1 with Connection: close echoes Connection: close") { sub =>
        var server = server::new_http_server("127.0.0.1", 8080);
        server::add_route(server.pipeline.router, "GET", "/close-test", 1, 0);

        var req: u8[..256] = [];
        req.append("GET /close-test HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n");
        var out: u8[..1024] = [];
        let _, ok = server::handle_connection_wire(server, "127.0.0.1", req[..], 1000000000, out);
        sub.assert_true(ok, "request processed");
        sub.assert_true(core::contains(out[..], "Connection: close\r\n") || core::contains(out[..], "connection: close\r\n"), "response must contain Connection: close");
        sub.assert_false(core::contains(out[..], "Connection: keep-alive\r\n"), "response must NOT contain Connection: keep-alive");
    };

    t.run("5. HTTP/1.0 without keep-alive echoes Connection: close") { sub =>
        var server = server::new_http_server("127.0.0.1", 8080);
        server::add_route(server.pipeline.router, "GET", "/h10-close", 1, 0);

        var req: u8[..256] = [];
        req.append("GET /h10-close HTTP/1.0\r\nHost: localhost\r\n\r\n");
        var out: u8[..1024] = [];
        let _, ok = server::handle_connection_wire(server, "127.0.0.1", req[..], 1000000000, out);
        sub.assert_true(ok, "request processed");
        sub.assert_true(core::contains(out[..], "Connection: close\r\n") || core::contains(out[..], "connection: close\r\n"), "HTTP/1.0 response must contain Connection: close");
        sub.assert_false(core::contains(out[..], "Connection: keep-alive\r\n"), "HTTP/1.0 response must NOT contain Connection: keep-alive");
    };

    t.run("6. HTTP/1.0 with Connection: keep-alive maintains keep-alive") { sub =>
        var server = server::new_http_server("127.0.0.1", 8080);
        server::add_route(server.pipeline.router, "GET", "/h10-keepalive", 1, 0);

        var req: u8[..256] = [];
        req.append("GET /h10-keepalive HTTP/1.0\r\nHost: localhost\r\nConnection: keep-alive\r\n\r\n");
        var out: u8[..1024] = [];
        let _, ok = server::handle_connection_wire(server, "127.0.0.1", req[..], 1000000000, out);
        sub.assert_true(ok, "request processed");
        sub.assert_true(core::contains(out[..], "Connection: keep-alive\r\n"), "explicit keep-alive preserved in HTTP/1.0");
    };

    t.run("7. SSE init_response sets X-Accel-Buffering: no") { sub =>
        var res = http::Response { .. };
        realtime::init_response(res);
        sub.assert_eq(res.status_code, 200, "status code 200");
        sub.assert_eq(http::header(res, "Content-Type"), "text/event-stream", "Content-Type is text/event-stream");
        sub.assert_eq(http::header(res, "X-Accel-Buffering"), "no", "X-Accel-Buffering is no");
    };
}

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

// ----------------------------------------------------------------------------
// 13. Server Audit Regressions
// ----------------------------------------------------------------------------
fn test_server_audit_regressions(t: lit::T&) {
    t.run("1. EdgeFilter bounds and duplicate required_header") { sub =>
        // F001: path_prefix > 64 bytes must not silently truncate to a shorter prefix that matches /api/...
        let long_pfx: const u8[:] = "/api/v1/012345678901234567890123456789012345678901234567890123456789/secret";
        let r_long = server::make_edge_filter_rule("long", long_pfx, server::EdgeFilterVerdict.BlockForbidden);
        let short_req_path = long_pfx[..64];
        var empty_hdrs = http::HeaderMap { .. };
        sub.assert_false(server::edge_rule_matches(r_long, short_req_path, empty_hdrs), "truncated 64B prefix must not match shorter path");

        // F002: whitespace-only required_header must NOT satisfy required_header check
        var r_hdr = server::make_edge_filter_rule("auth-check", "/secure", server::EdgeFilterVerdict.BlockForbidden);
        r_hdr.required_header.append("X-API-Key");
        var ws_hdrs = http::HeaderMap { .. };
        http::append_header(ws_hdrs, "X-API-Key", "   \t  ");
        sub.assert_true(server::edge_rule_matches(r_hdr, "/secure/data", ws_hdrs), "whitespace-only required header must trigger block rule");

        // F002: empty first header followed by non-empty duplicate header must satisfy required_header
        var dup_hdrs = http::HeaderMap { .. };
        http::append_header(dup_hdrs, "X-API-Key", "");
        http::append_header(dup_hdrs, "X-API-Key", "valid-token");
        sub.assert_false(server::edge_rule_matches(r_hdr, "/secure/data", dup_hdrs), "valid second duplicate header must satisfy required header");
    };

    t.run("2. H2ServerSession role, presence_mask, GOAWAY & RST_STREAM") { sub =>
        var sess = server_internal::new_h2_server_session("goose-wing/1.0", 1000);
        sub.assert_true(sess.conn.is_server, "H2ServerSession must initialize conn.is_server = true");
        sub.assert_false(sess.conn.enable_push, "H2ServerSession must initialize conn.enable_push = false");
        sub.assert_eq(sess.conn.max_concurrent_streams, 16, "H2ServerSession max_concurrent_streams is 16");

        // F012 & F013: copy_stream_headers_and_trailers must populate req.presence_mask so http::header() works on HTTP/2 requests!
        // Test with HTTP/2 QUERY request which requires Content-Type in pipeline.goose
        var pipeline = server::new_server_pipeline_config("example.com", security::new_gcra_quota(1000, wing::secs(1), 100));
        var timer = server_internal::new_connection_timer(30000000000, 1000000000);
        server::add_route(pipeline.router, "QUERY", "/search", 10);

        var init_wire: u8[>..] = [];
        init_wire.append(rfc::H2_CLIENT_PREFACE);
        build_h2_test_frame_header(init_wire, 0, 0x04, 0x00, 0);
        var wire_out: u8[>..] = [];
        let _, ok_init = server_internal::handle_h2_server_ingress(sess, pipeline, timer, "127.0.0.1", init_wire[..], 1000, wire_out);
        sub.assert_true(ok_init, "H2 preface and SETTINGS handled");

        var dt = http2::new_dynamic_table(4096);
        var h_block: u8[>..] = [];
        http2::encode_hpack_field(dt, h_block, ":method", "QUERY", http2::HpackIndexing.Incremental, false);
        http2::encode_hpack_field(dt, h_block, ":scheme", "https", http2::HpackIndexing.Incremental, false);
        http2::encode_hpack_field(dt, h_block, ":authority", "example.com", http2::HpackIndexing.Incremental, false);
        http2::encode_hpack_field(dt, h_block, ":path", "/search", http2::HpackIndexing.Incremental, false);
        http2::encode_hpack_field(dt, h_block, "content-type", "application/json", http2::HpackIndexing.Incremental, false);
        http2::encode_hpack_field(dt, h_block, "content-length", "2", http2::HpackIndexing.Incremental, false);
        http2::encode_hpack_field(dt, h_block, "sec-fetch-site", "same-origin", http2::HpackIndexing.Incremental, false);

        var req_wire: u8[>..] = [];
        build_h2_test_frame_header(req_wire, h_block.len as u32, 0x01, 0x04, 1); // HEADERS + END_HEADERS
        req_wire.append(h_block[..]);
        build_h2_test_frame_header(req_wire, 2, 0x00, 0x01, 1); // DATA + END_STREAM "{}"
        req_wire.append("{}");

        // F010: Append a truncated 9-byte RST_STREAM header for stream 1 at the tail of the buffer (missing 4-byte payload).
        // Must NOT cancel stream 1 before the RST_STREAM frame is completely received!
        build_h2_test_frame_header(req_wire, 4, 0x03, 0x00, 1);

        wire_out.clear();
        let consumed, ok_req = server_internal::handle_h2_server_ingress(sess, pipeline, timer, "127.0.0.1", req_wire[..], 1000, wire_out);
        sub.assert_true(ok_req, "H2 QUERY request + partial tail RST_STREAM succeeded");
        sub.assert_eq(consumed, (req_wire.len - 9) as i64, "Consumed complete frames, left 9-byte incomplete RST_STREAM");
        sub.assert_gt(wire_out.len, 0, "Stream 1 was NOT falsely cancelled by incomplete tail RST_STREAM");

        // Decode response HEADERS frame from wire_out (starts at offset 13 after one 13-byte conn WINDOW_UPDATE frame)
        var resp_dt = http2::new_dynamic_table(4096);
        var resp_pseudo = http2::PseudoHeaders { .. };
        var resp_list = http::HeaderMap { .. };
        let h_len = ((wire_out[13] as i64) << 16) | ((wire_out[14] as i64) << 8) | (wire_out[15] as i64);
        let dec_err = http2::decode_hpack_to_map(resp_dt, wire_out[22..(22 + h_len)], resp_pseudo, resp_list);
        sub.assert_eq(dec_err, rfc::H2_ERR_NO_ERROR, "Response HPACK decoded");
        sub.assert_true(resp_pseudo.has_status, "First response field is :status");
        sub.assert_eq(resp_pseudo.status, 200, "HTTP/2 QUERY with Content-Type returned 200 OK (presence_mask populated)");

        // F011: Incoming client GOAWAY frame on stream 0 must mark sess.conn.goaway_received = true
        var goaway_wire: u8[>..] = [];
        build_h2_test_frame_header(goaway_wire, 8, 0x07, 0x00, 0); // GOAWAY len=8, stream=0
        goaway_wire.append([0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
        wire_out.clear();
        let _, ok_go = server_internal::handle_h2_server_ingress(sess, pipeline, timer, "127.0.0.1", goaway_wire[..], 1000, wire_out);
        sub.assert_true(ok_go, "Client GOAWAY frame accepted");
        sub.assert_true(sess.conn.goaway_received, "sess.conn.goaway_received set to true");
    };

    t.run("3. Pipeline HEAD CL dedup, CORS/CSRF PSO & RFC 7239 Forwarded") { sub =>
        // F020: ExtensionsPool resets conn_id and request_seq
        var ext_pool = server_internal::ExtensionsPool { .. };
        let e_idx = server_internal::acquire_extensions(ext_pool);
        ext_pool.slots[e_idx].conn_id = 99;
        ext_pool.slots[e_idx].request_seq = 42;
        server_internal::release_extensions(ext_pool, e_idx);
        sub.assert_eq(ext_pool.slots[e_idx].conn_id, 0, "conn_id reset on release");
        sub.assert_eq(ext_pool.slots[e_idx].request_seq, 0, "request_seq reset on release");

        // F017: HEAD request must NOT emit duplicate Content-Length: 0 and Content-Length: 13
        var server = server::new_http_server("127.0.0.1", 8080);
        server::add_get_route(server, "/head-check", 1001);
        let head_req = "HEAD /head-check HTTP/1.1\r\nHost: 127.0.0.1\r\nSec-Fetch-Site: same-origin\r\n\r\n";
        var head_out: u8[>..] = [];
        let outcome_h, ok_h = server::handle_connection_wire(server, "127.0.0.1", head_req, 1000000000, head_out);
        sub.assert_true(ok_h && outcome_h == server::PipelineOutcome.Handled, "HEAD request handled");
        sub.assert_contains(head_out[..], "Content-Length: 13\r\n", "HEAD response preserves GET Content-Length: 13");
        sub.assert_false(core::contains(head_out[..], "Content-Length: 0\r\n"), "HEAD response must NOT also emit Content-Length: 0");

        // F015: Rejected CORS preflight must short-circuit and NOT fall through to route handler
        let quota = security::new_gcra_quota(100, wing::secs(1), 10);
        var cfg = server::new_server_pipeline_config("example.com", quota);
        security::add_allowed_origin(cfg.cors_policy, "https://trusted.example.com");
        server::add_route(cfg.router, "OPTIONS", "/cors-resource", 55);
        var timer = server_internal::new_connection_timer(30000000000, 1000000000);
        var bad_preflight = http::new_request("OPTIONS", "/cors-resource");
        http::set_header(bad_preflight, "Origin", "https://evil.attacker.com");
        http::set_header(bad_preflight, "Access-Control-Request-Method", "POST");
        var res_cors = http::Response { .. };
        var fut_cors = server_internal::new_inline_handler_future(0);
        let out_cors = server::execute_pipeline(cfg, timer, "127.0.0.1", bad_preflight, 1000000000, res_cors, fut_cors);
        sub.assert_true(out_cors == server::PipelineOutcome.CsrfRejected, "Rejected CORS preflight must be rejected, not routed to handler");
        sub.assert_eq(res_cors.status_code, 403, "Rejected CORS preflight returns 403");

        // F018: RFC 7239 Forwarded with quoted ';for=1.2.3.4' inside extension param
        let fwd_ip = server::extract_rfc7239_forwarded_for("ext=\"a;for=1.2.3.4,b\";for=203.0.113.77;proto=https");
        sub.assert_eq(fwd_ip, "203.0.113.77", "Quoted ';for=' inside extension parameter ignored in favor of real for= parameter");
    };

    t.run("4. RadixRouter >64B static, non-dot suffix, backtrack & OPTIONS") { sub =>
        // F021 & F022: Static route > 64 bytes and node splitting without priority underflow
        var tree = server::new_radix_tree();
        let long_route: const u8[:] = "/api/v1/organizations/departments/engineering/teams/backend/services/authentication/status";
        sub.assert_true(server::insert_route(tree, long_route, 77), "insert >64B static route succeeds");
        var params = http::ZeroAllocParams { .. };
        let m_long = server::match_path(tree, long_route, params);
        let ok_long = match m_long {
            Found f => f.handler_id == 77,
            _ => false,
        };
        sub.assert_true(ok_long, ">64B static route matches accurately");

        // F025a: Non-dot parameter suffix (/items/{id}-summary)
        var tree_sfx = server::new_radix_tree();
        sub.assert_true(server::insert_route(tree_sfx, "/items/{id}-summary", 88), "insert hyphen suffix route");
        let m_sfx = server::match_path(tree_sfx, "/items/abc42-summary", params);
        let ok_sfx = match m_sfx {
            Found f => f.handler_id == 88,
            _ => false,
        };
        sub.assert_true(ok_sfx, "non-dot suffix route /items/{id}-summary matches");
        sub.assert_eq(http::param_val(params, 0, "/items/abc42-summary"), "abc42", "extracted param 'abc42' before '-summary'");

        // F025b: Static-to-param backtracking (/users/profile/settings + /users/{id} queried with /users/profile)
        var tree_bt = server::new_radix_tree();
        server::insert_route(tree_bt, "/users/profile/settings", 1);
        server::insert_route(tree_bt, "/users/{id}", 2);
        let m_bt = server::match_path(tree_bt, "/users/profile", params);
        let ok_bt = match m_bt {
            Found f => f.handler_id == 2,
            _ => false,
        };
        sub.assert_true(ok_bt, "/users/profile backtracks from partial static /users/profile/settings to /users/{id}");
        sub.assert_eq(http::param_val(params, 0, "/users/profile"), "profile", "backtracked param is 'profile'");

        // F026: resolve_effective_route_path populates out_canon_path even when path is already canonical
        var router = server::new_radix_router();
        server::add_route(router, "POST", "/canonical/tier1/route/test", 12);
        var canon_out: u8[..256] = [];
        let m_canon = server::match_route(router, "POST", "/canonical/tier1/route/test", params, canon_out);
        sub.assert_eq(canon_out[..], "/canonical/tier1/route/test", "out_canon_path populated on already-canonical Tier-1 route");

        // F029: OPTIONS * on router with a single route in a method tree
        let m_star = server::match_route(router, "OPTIONS", "*", params);
        let ok_star = match m_star {
            MethodNotAllowed mna => core::contains(mna.allow_header[..], "POST"),
            _ => false,
        };
        sub.assert_true(ok_star, "OPTIONS * includes POST when POST tree has a single root route");
    };

    t.run("5. Server Host/CONNECT, serializer, pipe 400 dedup & mmap") { sub =>
        // F030: Host header with invalid port must be rejected
        var req_bad_port = http::Request { .. };
        let ok_bp1, _ = server::parse_http1_wire_request("GET / HTTP/1.1\r\nHost: example.com:99999\r\n\r\n", req_bad_port);
        sub.assert_false(ok_bp1, "Host port > 65535 must be rejected");
        let ok_bp2, _ = server::parse_http1_wire_request("GET / HTTP/1.1\r\nHost: example.com:abc\r\n\r\n", req_bad_port);
        sub.assert_false(ok_bp2, "Non-numeric Host port must be rejected");
        let ok_bp3, _ = server::parse_http1_wire_request("GET / HTTP/1.1\r\nHost: :8080\r\n\r\n", req_bad_port);
        sub.assert_false(ok_bp3, "Empty host before colon must be rejected");

        // F031: CONNECT with valid IPv6 authority [::1]:443 must succeed
        var req_conn = http::Request { .. };
        let ok_conn, _ = server::parse_http1_wire_request("CONNECT [::1]:443 HTTP/1.1\r\nHost: [::1]:443\r\n\r\n", req_conn);
        sub.assert_true(ok_conn, "CONNECT [::1]:443 HTTP/1.1 must succeed");

        // F039: serialize_http1_headers with 1 custom header pushed directly (presence_mask == 0) must NOT rewrite it to Content-Type!
        var res_custom = http::Response { status_code: 200, .. };
        http::append_header(res_custom.headers, "X-Custom-Tag", "my-val");
        var custom_wire: u8[..512] = [];
        server::serialize_http1_response(res_custom, "goose-wing", custom_wire);
        sub.assert_contains(custom_wire[..], "X-Custom-Tag: my-val\r\n", "Custom header preserved");
        sub.assert_false(core::contains(custom_wire[..], "Content-Type: my-val\r\n"), "Custom header not rewritten to Content-Type");

        // F048: handle_connection_pipe on invalid first request must emit exactly ONE HTTP/1.1 400 Bad Request
        var server = server::new_http_server("127.0.0.1", 8080);
        var pipe = core::new_pipe_buffer();
        core::write(pipe, "GET / HTTP/1.1\r\nHost : bad-colon\r\n\r\n");
        var pipe_out: u8[>..] = [];
        let _, ok_pipe = server::handle_connection_pipe(server, "127.0.0.1", pipe, 1000000000, pipe_out);
        sub.assert_false(ok_pipe, "Invalid request in pipe rejected");
        let first_400 = find(pipe_out[..], "HTTP/1.1 400 Bad Request");
        sub.assert_ge(first_400, 0, "First 400 Bad Request emitted");
        let second_400 = find(pipe_out[(first_400 + 24)..], "HTTP/1.1 400 Bad Request");
        sub.assert_eq(second_400, -1, "Must NOT emit duplicate 400 Bad Request on parse failure");

        // F051: serve_static_mmap_file on a file < 4096 bytes ("version.txt") must include the file body!
        var mmap_wire: u8[>..] = [];
        let ok_mmap = server::serve_static_mmap_file("version.txt", "text/plain", mmap_wire);
        sub.assert_true(ok_mmap, "serve_static_mmap_file opened version.txt");
        let body_sep = find(mmap_wire[..], "\r\n\r\n");
        sub.assert_gt(body_sep, 0, "Response headers serialized");
        sub.assert_gt(mmap_wire.len - (body_sep + 4), 0, "Small mmap file (<4096B) body must not be empty");
    };

    t.run("6. Peer IP extraction, Reactor H2 persistence, TLS reactor & HTTP/3 server") { sub =>
        var peer_ip: u8[..64] = [];
        net::tcp_get_peer_ip(-1, peer_ip);
        sub.assert_eq(peer_ip[..], "127.0.0.1", "tcp_get_peer_ip fallback for invalid fd");

        var server = server::new_http_server("127.0.0.1", 8080);
        server::add_get_route(server, "/h3-check", 2001);

        let h3_settings = fingerprint::H3Settings { .. };
        var h3_cli = http3::new_client_connection(h3_settings);
        let sid, ok_sid = http3::open_request_stream(h3_cli);
        sub.assert_true(ok_sid && sid == 0, "open client H3 stream 0");
        var extra = http::HeaderMap { .. };
        var req_wire: u8[..1024] = [];
        let ok_send = http3::send_request_headers(
            h3_cli, sid, "GET", "https", "127.0.0.1", "/h3-check", extra, true, req_wire,
        );
        sub.assert_true(ok_send, "encode H3 request");

        var h3_srv = http3::new_server_connection(h3_settings);
        var tx_wire: u8[..1024] = [];
        let ok_h3 = server::handle_h3_server_datagram(
            server, h3_srv, sid, "127.0.0.1", req_wire[..], 1000000000, tx_wire,
        );
        sub.assert_true(ok_h3 && tx_wire.len > 0, "handle_h3_server_datagram produced response");

        let rx_err = http3::handle_stream_data(h3_cli, sid, true, tx_wire[..], true);
        sub.assert_eq(rx_err, rfc::H3_ERR_NO_ERROR, "client decoded H3 server response");
        let sc, ok_sc = http3::get_status_code(h3_cli, sid);
        sub.assert_true(ok_sc && sc == 200, "H3 server response status is 200");

        let tls_cfg = tls::ServerHandshakeConfig { .. };
        sub.assert_eq(server::serve_tls(server, -1, tls_cfg, 1), 0, "serve_tls invalid fd");
        sub.assert_eq(server::serve_reactor_tls(server, -1, tls_cfg, 1), 0, "serve_reactor_tls invalid fd");
        sub.assert_eq(server::serve_h3(server, -1, 1), 0, "serve_h3 invalid fd");
    };
}

struct PlodStyleStage {
    seen_route: u8[..64] = [],
}

struct PlodUserDto {
    id:   u8[..32] = [],
    role: u8[..32] = [],
    ip:   u8[..48] = [],
}

fn server::on_server_stage(
    stage: PlodStyleStage&,
    phase: wire::ServerHookPhase,
    cfg:   server::ServerPipelineConfig&,
    req:   const http::Request&,
    ctx:   server::ServerStageCtx&,
    res:   http::Response&,
) -> wire::StageVerdict {
    if phase == wire::ServerHookPhase.RouteHandler {
        if ctx.handler_id == 101 {
            let user_id, ok_id = cfg.route_param(ctx, "id");
            let role_val = cfg.route_param_or(ctx, "role", "member");
            if !ok_id || user_id == "0" {
                res.respond_problem(400, "Invalid User ID", "User ID cannot be zero", "https://example.com/probs/id");
                return wire::StageVerdict.Continue;
            }
            var dto = PlodUserDto { .. };
            let _ = dto.id.try_set(user_id);
            let _ = dto.role.try_set(role_val);
            let _ = dto.ip.try_set(cfg.peer_ip(ctx));
            http::respond_json(res, 200, dto);
        } else if ctx.handler_id == 102 {
            let sub = cfg.auth_subject(ctx);
            let claims = cfg.auth_claims(ctx);
            let tenant = auth::claim_str(claims, "tenant");
            let sess = cfg.session_data(ctx);
            var out_txt: u8[..128] = [];
            out_txt.append(sub);
            out_txt.push(':');
            out_txt.append(tenant);
            out_txt.push(':');
            out_txt.append(sess);
            http::respond_text(res, 200, out_txt[..]);
        } else if ctx.handler_id == 103 {
            http::respond_json_str(res, 201, "{\"created\":true}");
        }
    } else if phase == wire::ServerHookPhase.PreSerialize {
        let idx = ctx.ext_slot_idx;
        if idx >= 0 && idx < cfg.ext_pool.slots.len {
            let _ = stage.seen_route.try_set(cfg.ext_pool.slots[idx].matched_route[..]);
        }
    }
    return wire::StageVerdict.Continue;
}

// ----------------------------------------------------------------------------
// 14. RouteHandler Hook, Context Accessors & Response Builders
// ----------------------------------------------------------------------------
fn test_route_handler_stage_and_ergonomics(t: lit::T&) {
    t.run("1. RouteHandler phase, route_param, respond_json, respond_problem & PreSerialize ext") { sub =>
        var server = server::new_http_server("example.com", 8080);
        server.pipeline.enable_csrf_guard = false;
        server.pipeline.server_pso_capabilities |= server::STAGE_EGRESS_ACCESS_LOG | server::STAGE_EGRESS_METRICS;
        server::add_route(
            server.pipeline.router,
            "GET",
            "/users/:id",
            101,
            server_internal::ENTRY_PARAMS,
            server::DEFAULT_ROUTE_PSO_MASK | server::STAGE_EGRESS_ACCESS_LOG | server::STAGE_EGRESS_METRICS,
        );
        server::add_post_route(server, "/items", 103);

        var stage = PlodStyleStage { .. };
        var wire_out: u8[>..] = [];
        let req_ok = "GET /users/42 HTTP/1.1\r\nHost: example.com\r\n\r\n";
        let outcome, ok_w = server::handle_connection_wire(server, "198.51.100.7", req_ok, 5000000000, wire_out, stage);
        sub.assert_true(ok_w && outcome == server::PipelineOutcome.Handled, "RouteHandler executed via handle_connection_wire");
        sub.assert_contains(wire_out[..], "HTTP/1.1 200 OK\r\n", "200 OK status");
        sub.assert_contains(wire_out[..], "Content-Type: application/json\r\n", "application/json header");
        sub.assert_contains(wire_out[..], "{\"id\":\"42\",\"role\":\"member\",\"ip\":\"198.51.100.7\"}", "serialized DTO");
        sub.assert_contains(wire_out[..], "X-Matched-Route: /users/42\r\n", "X-Matched-Route preserved from real ext");
        sub.assert_eq(stage.seen_route[..], "/users/42", "PreSerialize accessed live RequestExtensions slot");

        // Problem response on id == 0
        var prob_wire: u8[>..] = [];
        let req_bad = "GET /users/0 HTTP/1.1\r\nHost: example.com\r\n\r\n";
        let _, ok_p = server::handle_connection_wire(server, "127.0.0.1", req_bad, 6000000000, prob_wire, stage);
        sub.assert_true(ok_p, "Problem response serialized");
        sub.assert_contains(prob_wire[..], "HTTP/1.1 400 Bad Request\r\n", "400 status from respond_problem");
        sub.assert_contains(prob_wire[..], "Content-Type: application/problem+json\r\n", "problem+json content type");
        sub.assert_contains(prob_wire[..], "\"title\":\"Invalid User ID\"", "problem title");

        // Pipe with stage on POST /items (respond_json_str 201)
        var pipe = core::new_pipe_buffer();
        core::write(pipe, "POST /items HTTP/1.1\r\nHost: example.com\r\nContent-Length: 0\r\n\r\n");
        var pipe_wire: u8[>..] = [];
        let cnt_p, ok_pipe = server::handle_connection_pipe_with_stage(
            server, "127.0.0.1", pipe, 7000000000, pipe_wire, stage,
        );
        sub.assert_true(ok_pipe && cnt_p == 1, "handle_connection_pipe_with_stage handled 1 request");
        sub.assert_contains(pipe_wire[..], "HTTP/1.1 201 Created\r\n", "201 Created preserved without overwrite to 200");
        sub.assert_contains(pipe_wire[..], "{\"created\":true}", "respond_json_str body");

        sub.assert_eq(server::serve_with_stage(server, -1, stage, 1), 0, "serve_with_stage invalid fd");
        sub.assert_eq(server::serve_reactor_with_stage(server, -1, stage, 1), 0, "serve_reactor_with_stage invalid fd");
    };

    t.run("2. CORS reject_non_matching_origin & JWT raw_payload + auth_claims") { sub =>
        var server = server::new_http_server("example.com", 8080);
        server.pipeline.enable_csrf_guard = false;
        server.pipeline.cors_policy.reject_non_matching_origin = true;
        security::add_allowed_origin(server.pipeline.cors_policy, "https://trusted.example.com");
        server::add_get_route(server, "/protected", 102);

        var stage = PlodStyleStage { .. };
        var req_evil = http::new_get("/protected");
        http::set_header(req_evil, "Origin", "https://evil.example.org");
        var res_evil = http::Response { .. };
        let out_evil = server::dispatch_server_request_with_stage(
            server, "127.0.0.1", req_evil, 1000000000, res_evil, stage,
        );
        sub.assert_true(out_evil == server::PipelineOutcome.CsrfRejected, "Disallowed origin rejected on GET");
        sub.assert_eq(res_evil.status_code, 403, "403 Forbidden on disallowed origin");

        // Verify JWT auth_claims and raw_payload preservation
        let secret = "0123456789abcdef0123456789abcdef";
        let _ = auth::add_symmetric_key(server.pipeline.jwks, "k1", auth::JwtAlg.HS256, secret);
        server.pipeline.jwt_options = auth::default_jwt_validation_options(auth::JwtAlg.HS256);
        server.pipeline.server_pso_capabilities |= server::STAGE_INGRESS_AUTH_JWT;
        server::add_route(
            server.pipeline.router,
            "GET",
            "/jwt-info",
            102,
            server_internal::ENTRY_SECURITY,
            server::DEFAULT_ROUTE_PSO_MASK | server::STAGE_INGRESS_AUTH_JWT,
        );

        var hdr = auth::new_jwt_header(auth::JwtAlg.HS256, "k1");
        var claims = auth::JwtClaims { exp: 2000000000, .. };
        let _ = claims.sub.try_set("alice");
        let _ = auth::set_claim(claims, "tenant", "acme");
        var token: u8[..512] = [];
        let ok_sign = auth::sign_jwt_hmac(hdr, claims, secret, token);
        sub.assert_true(ok_sign, "signed HS256 token");

        var req_jwt = http::new_get("/jwt-info");
        req_jwt.bearer(token[..]);
        var res_jwt = http::Response { .. };
        let out_jwt = server::dispatch_server_request_with_stage(
            server, "127.0.0.1", req_jwt, 1000000000, res_jwt, stage,
        );
        sub.assert_true(out_jwt == server::PipelineOutcome.Handled, "JWT route handled");
        sub.assert_eq(res_jwt.status_code, 200, "200 OK from JWT route");
        sub.assert_eq(res_jwt.text(), "alice:acme:", "auth_subject and custom claim 'tenant' extracted");

        var parsed_c = auth::JwtClaims { .. };
        let ok_raw = auth::parse_jwt_claims_json("{\"sub\":\"bob\",\"nested\":{\"a\":1}}", parsed_c);
        sub.assert_true(ok_raw, "parse_jwt_claims_json with nested object succeeds");
        sub.assert_contains(parsed_c.raw_payload[..], "\"nested\":{\"a\":1}", "raw_payload preserved on JwtClaims");
    };
}

// ----------------------------------------------------------------------------
// 15. Router path capacity truncation smuggling (server/router.goose)
// ----------------------------------------------------------------------------
fn test_router_path_capacity_truncation_smuggling(t: lit::T&) {
    t.run("Router MUST NOT truncate oversized path to match parent route") { sub =>
        var router = server::new_radix_router();
        server::add_route(router, "GET", "/admin", 1);

        // Path is /admin/ + 520 'x's (exceeds 512 bytes)
        var long_path: u8[..600] = [];
        long_path.append("/admin/");
        for i in 520 { long_path.push('x'); }

        var params = http::ZeroAllocParams { .. };
        let match_res = server::match_route(router, "GET", long_path[..], params);
        let is_found = match match_res {
            Found _ => true,
            _ => false,
        };
        sub.assert_false(is_found, "Oversized non-matching subpath MUST NOT be truncated to match /admin");
    };
}

// ----------------------------------------------------------------------------
// 16. EdgeFilter
// ----------------------------------------------------------------------------
fn test_srv_reg1_s1(t: lit::T&) {
    t.run("1. EdgeFilter bounds and duplicate required_header") { sub =>
        // F001: path_prefix > 64 bytes must not silently truncate to a shorter prefix that matches /api/...
        let long_pfx: const u8[:] = "/api/v1/012345678901234567890123456789012345678901234567890123456789/secret";
        let r_long = server::make_edge_filter_rule("long", long_pfx, server::EdgeFilterVerdict.BlockForbidden);
        let short_req_path = long_pfx[..64];
        var empty_hdrs = http::HeaderMap { .. };
        sub.assert_false(server::edge_rule_matches(r_long, short_req_path, empty_hdrs), "truncated 64B prefix must not match shorter path");

        // F002: whitespace-only required_header must NOT satisfy required_header check
        var r_hdr = server::make_edge_filter_rule("auth-check", "/secure", server::EdgeFilterVerdict.BlockForbidden);
        r_hdr.required_header.append("X-API-Key");
        var ws_hdrs = http::HeaderMap { .. };
        http::append_header(ws_hdrs, "X-API-Key", "   \t  ");
        sub.assert_true(server::edge_rule_matches(r_hdr, "/secure/data", ws_hdrs), "whitespace-only required header must trigger block rule");

        // F002: empty first header followed by non-empty duplicate header must satisfy required_header
        var dup_hdrs = http::HeaderMap { .. };
        http::append_header(dup_hdrs, "X-API-Key", "");
        http::append_header(dup_hdrs, "X-API-Key", "valid-token");
        sub.assert_false(server::edge_rule_matches(r_hdr, "/secure/data", dup_hdrs), "valid second duplicate header must satisfy required header");
    };
}

// ----------------------------------------------------------------------------
// 17. H2ServerSession
// ----------------------------------------------------------------------------
fn test_srv_reg1_s2(t: lit::T&) {
    t.run("2. H2ServerSession role, presence_mask, GOAWAY & RST_STREAM") { sub =>
        var sess = server_internal::new_h2_server_session("goose-wing/1.0", 1000);
        sub.assert_true(sess.conn.is_server, "H2ServerSession must initialize conn.is_server = true");
        sub.assert_false(sess.conn.enable_push, "H2ServerSession must initialize conn.enable_push = false");
        sub.assert_eq(sess.conn.max_concurrent_streams, 16, "H2ServerSession max_concurrent_streams is 16");

        // F012 & F013: copy_stream_headers_and_trailers must populate req.presence_mask so http::header() works on HTTP/2 requests!
        var pipeline = server::new_server_pipeline_config("example.com", security::new_gcra_quota(1000, wing::secs(1), 100));
        var timer = server_internal::new_connection_timer(30000000000, 1000000000);
        server::add_route(pipeline.router, "QUERY", "/search", 10);

        var init_wire: u8[>..] = [];
        init_wire.append(rfc::H2_CLIENT_PREFACE);
        build_h2_test_frame_header(init_wire, 0, 0x04, 0x00, 0);
        var wire_out: u8[>..] = [];
        let _, ok_init = server_internal::handle_h2_server_ingress(sess, pipeline, timer, "127.0.0.1", init_wire[..], 1000, wire_out);
        sub.assert_true(ok_init, "H2 preface and SETTINGS handled");

        var dt = http2::new_dynamic_table(4096);
        var h_block: u8[>..] = [];
        http2::encode_hpack_field(dt, h_block, ":method", "QUERY", http2::HpackIndexing.Incremental, false);
        http2::encode_hpack_field(dt, h_block, ":scheme", "https", http2::HpackIndexing.Incremental, false);
        http2::encode_hpack_field(dt, h_block, ":authority", "example.com", http2::HpackIndexing.Incremental, false);
        http2::encode_hpack_field(dt, h_block, ":path", "/search", http2::HpackIndexing.Incremental, false);
        http2::encode_hpack_field(dt, h_block, "content-type", "application/json", http2::HpackIndexing.Incremental, false);
        http2::encode_hpack_field(dt, h_block, "content-length", "2", http2::HpackIndexing.Incremental, false);
        http2::encode_hpack_field(dt, h_block, "sec-fetch-site", "same-origin", http2::HpackIndexing.Incremental, false);

        var req_wire: u8[>..] = [];
        build_h2_test_frame_header(req_wire, h_block.len as u32, 0x01, 0x04, 1);
        req_wire.append(h_block[..]);
        build_h2_test_frame_header(req_wire, 2, 0x00, 0x01, 1);
        req_wire.append("{}");

        // F010: Append a truncated 9-byte RST_STREAM header for stream 1 at the tail of the buffer (missing 4-byte payload).
        build_h2_test_frame_header(req_wire, 4, 0x03, 0x00, 1);

        wire_out.clear();
        let consumed, ok_req = server_internal::handle_h2_server_ingress(sess, pipeline, timer, "127.0.0.1", req_wire[..], 1000, wire_out);
        sub.assert_true(ok_req, "H2 QUERY request + partial tail RST_STREAM succeeded");
        sub.assert_eq(consumed, (req_wire.len - 9) as i64, "Consumed complete frames, left 9-byte incomplete RST_STREAM");
        sub.assert_gt(wire_out.len, 0, "Stream 1 was NOT falsely cancelled by incomplete tail RST_STREAM");

        if wire_out.len >= 22 {
            var resp_dt = http2::new_dynamic_table(4096);
            var resp_pseudo = http2::PseudoHeaders { .. };
            var resp_list = http::HeaderMap { .. };
            let h_len = ((wire_out[13] as i64) << 16) | ((wire_out[14] as i64) << 8) | (wire_out[15] as i64);
            let dec_err = http2::decode_hpack_to_map(resp_dt, wire_out[22..(22 + h_len)], resp_pseudo, resp_list);
            sub.assert_eq(dec_err, rfc::H2_ERR_NO_ERROR, "Response HPACK decoded");
            sub.assert_true(resp_pseudo.has_status, "First response field is :status");
            sub.assert_eq(resp_pseudo.status, 200, "HTTP/2 QUERY with Content-Type returned 200 OK (presence_mask populated)");
        }

        // F011: Incoming client GOAWAY frame on stream 0 must mark sess.conn.goaway_received = true
        var goaway_wire: u8[>..] = [];
        build_h2_test_frame_header(goaway_wire, 8, 0x07, 0x00, 0);
        goaway_wire.append([0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
        wire_out.clear();
        let _, ok_go = server_internal::handle_h2_server_ingress(sess, pipeline, timer, "127.0.0.1", goaway_wire[..], 1000, wire_out);
        sub.assert_true(ok_go, "Client GOAWAY frame accepted");
        sub.assert_true(sess.conn.goaway_received, "sess.conn.goaway_received set to true");
    };
}

// ----------------------------------------------------------------------------
// 18. HEAD Dedup
// ----------------------------------------------------------------------------
fn test_srv_reg1_s3a(t: lit::T&) {
    t.run("3a. ExtensionsPool and HEAD Content-Length dedup") { sub =>
        // F020: ExtensionsPool resets conn_id and request_seq
        var ext_pool = server_internal::ExtensionsPool { .. };
        let e_idx = server_internal::acquire_extensions(ext_pool);
        ext_pool.slots[e_idx].conn_id = 99;
        ext_pool.slots[e_idx].request_seq = 42;
        server_internal::release_extensions(ext_pool, e_idx);
        sub.assert_eq(ext_pool.slots[e_idx].conn_id, 0, "conn_id reset on release");
        sub.assert_eq(ext_pool.slots[e_idx].request_seq, 0, "request_seq reset on release");

        // F017: HEAD request must NOT emit duplicate Content-Length: 0 and Content-Length: 13
        var server = server::new_http_server("127.0.0.1", 8080);
        server::add_get_route(server, "/head-check", 1001);
        let head_req = "HEAD /head-check HTTP/1.1\r\nHost: 127.0.0.1\r\nSec-Fetch-Site: same-origin\r\n\r\n";
        var head_out: u8[>..] = [];
        let outcome_h, ok_h = server::handle_connection_wire(server, "127.0.0.1", head_req, 1000000000, head_out);
        sub.assert_true(ok_h && outcome_h == server::PipelineOutcome.Handled, "HEAD request handled");
        sub.assert_contains(head_out[..], "Content-Length: 13\r\n", "HEAD response preserves GET Content-Length: 13");
        sub.assert_false(core::contains(head_out[..], "Content-Length: 0\r\n"), "HEAD response must NOT also emit Content-Length: 0");
    };
}

// ----------------------------------------------------------------------------
// 19. CORS/CSRF
// ----------------------------------------------------------------------------
fn test_srv_reg1_s3b(t: lit::T&) {
    t.run("3b. CORS/CSRF PSO & RFC 7239 Forwarded") { sub =>
        // F015: Rejected CORS preflight must short-circuit and NOT fall through to route handler
        let quota = security::new_gcra_quota(100, wing::secs(1), 10);
        var cfg = server::new_server_pipeline_config("example.com", quota);
        security::add_allowed_origin(cfg.cors_policy, "https://trusted.example.com");
        server::add_route(cfg.router, "OPTIONS", "/cors-resource", 55);
        var timer = server_internal::new_connection_timer(30000000000, 1000000000);
        var bad_preflight = http::new_request("OPTIONS", "/cors-resource");
        http::set_header(bad_preflight, "Origin", "https://evil.attacker.com");
        http::set_header(bad_preflight, "Access-Control-Request-Method", "POST");
        var res_cors = http::Response { .. };
        var fut_cors = server_internal::new_inline_handler_future(0);
        let out_cors = server::execute_pipeline(cfg, timer, "127.0.0.1", bad_preflight, 1000000000, res_cors, fut_cors);
        sub.assert_true(out_cors == server::PipelineOutcome.CsrfRejected, "Rejected CORS preflight must be rejected, not routed to handler");
        sub.assert_eq(res_cors.status_code, 403, "Rejected CORS preflight returns 403");

        // F018: RFC 7239 Forwarded with quoted ';for=1.2.3.4' inside extension param
        let fwd_ip = server::extract_rfc7239_forwarded_for("ext=\"a;for=1.2.3.4,b\";for=203.0.113.77;proto=https");
        sub.assert_eq(fwd_ip, "203.0.113.77", "Quoted ';for=' inside extension parameter ignored in favor of real for= parameter");
    };
}

// ----------------------------------------------------------------------------
// 20. RadixRouter
// ----------------------------------------------------------------------------
fn test_srv_reg1_s4(t: lit::T&) {
    t.run("4. RadixRouter >64B static, non-dot suffix, backtrack & OPTIONS") { sub =>
        // F021 & F022: Static route > 64 bytes and node splitting without priority underflow
        var router = server::new_radix_router();
        let long_route: const u8[:] = "/api/v1/organizations/departments/engineering/teams/backend/services/authentication/status";
        sub.assert_true(server::insert_route(router.trees[0].tree, long_route, 77), "insert >64B static route succeeds");
        var params = http::ZeroAllocParams { .. };
        let m_long = server::match_path(router.trees[0].tree, long_route, params);
        let ok_long = match m_long {
            Found f => f.handler_id == 77,
            _ => false,
        };
        sub.assert_true(ok_long, ">64B static route matches accurately");

        // F025a: Non-dot parameter suffix (/items/{id}-summary)
        sub.assert_true(server::insert_route(router.trees[1].tree, "/items/{id}-summary", 88), "insert hyphen suffix route");
        let m_sfx = server::match_path(router.trees[1].tree, "/items/abc42-summary", params);
        let ok_sfx = match m_sfx {
            Found f => f.handler_id == 88,
            _ => false,
        };
        sub.assert_true(ok_sfx, "non-dot suffix route /items/{id}-summary matches");
        sub.assert_eq(http::param_val(params, 0, "/items/abc42-summary"), "abc42", "extracted param 'abc42' before '-summary'");

        // F025b: Static-to-param backtracking (/users/profile/settings + /users/{id} queried with /users/profile)
        server::insert_route(router.trees[2].tree, "/users/profile/settings", 1);
        server::insert_route(router.trees[2].tree, "/users/{id}", 2);
        let m_bt = server::match_path(router.trees[2].tree, "/users/profile", params);
        let ok_bt = match m_bt {
            Found f => f.handler_id == 2,
            _ => false,
        };
        sub.assert_true(ok_bt, "/users/profile backtracks from partial static /users/profile/settings to /users/{id}");
        sub.assert_eq(http::param_val(params, 0, "/users/profile"), "profile", "backtracked param is 'profile'");

        // F026: resolve_effective_route_path populates out_canon_path even when path is already canonical
        server::add_route(router, "POST", "/canonical/tier1/route/test", 12);
        var canon_out: u8[..256] = [];
        let m_canon = server::match_route(router, "POST", "/canonical/tier1/route/test", params, canon_out);
        sub.assert_eq(canon_out[..], "/canonical/tier1/route/test", "out_canon_path populated on already-canonical Tier-1 route");

        // F029: OPTIONS * on router with a single route in a method tree
        let m_star = server::match_route(router, "OPTIONS", "*", params);
        let ok_star = match m_star {
            MethodNotAllowed mna => core::contains(mna.allow_header[..], "POST"),
            _ => false,
        };
        sub.assert_true(ok_star, "OPTIONS * includes POST when POST tree has a single root route");
    };
}

// ----------------------------------------------------------------------------
// 21. Server Wire
// ----------------------------------------------------------------------------
fn test_srv_reg1_s5a(t: lit::T&) {
    t.run("5a. Server Host/CONNECT, serializer & mmap") { sub =>
        // F030: Host header with invalid port must be rejected
        var req_bad_port = http::Request { .. };
        let ok_bp1, _ = server::parse_http1_wire_request("GET / HTTP/1.1\r\nHost: example.com:99999\r\n\r\n", req_bad_port);
        sub.assert_false(ok_bp1, "Host port > 65535 must be rejected");
        let ok_bp2, _ = server::parse_http1_wire_request("GET / HTTP/1.1\r\nHost: example.com:abc\r\n\r\n", req_bad_port);
        sub.assert_false(ok_bp2, "Non-numeric Host port must be rejected");
        let ok_bp3, _ = server::parse_http1_wire_request("GET / HTTP/1.1\r\nHost: :8080\r\n\r\n", req_bad_port);
        sub.assert_false(ok_bp3, "Empty host before colon must be rejected");

        // F031: CONNECT with valid IPv6 authority [::1]:443 must succeed
        var req_conn = http::Request { .. };
        let ok_conn, _ = server::parse_http1_wire_request("CONNECT [::1]:443 HTTP/1.1\r\nHost: [::1]:443\r\n\r\n", req_conn);
        sub.assert_true(ok_conn, "CONNECT [::1]:443 HTTP/1.1 must succeed");

        // F039: serialize_http1_headers with 1 custom header pushed directly (presence_mask == 0) must NOT rewrite it to Content-Type!
        var res_custom = http::Response { status_code: 200, .. };
        http::append_header(res_custom.headers, "X-Custom-Tag", "my-val");
        var custom_wire: u8[..512] = [];
        server::serialize_http1_response(res_custom, "goose-wing", custom_wire);
        sub.assert_contains(custom_wire[..], "X-Custom-Tag: my-val\r\n", "Custom header preserved");
        sub.assert_false(core::contains(custom_wire[..], "Content-Type: my-val\r\n"), "Custom header not rewritten to Content-Type");

        // F051: serve_static_mmap_file on a file < 4096 bytes ("version.txt") must include the file body!
        var mmap_wire: u8[>..] = [];
        let ok_mmap = server::serve_static_mmap_file("version.txt", "text/plain", mmap_wire);
        sub.assert_true(ok_mmap, "serve_static_mmap_file opened version.txt");
        let body_sep = find(mmap_wire[..], "\r\n\r\n");
        sub.assert_gt(body_sep, 0, "Response headers serialized");
        sub.assert_gt(mmap_wire.len - (body_sep + 4), 0, "Small mmap file (<4096B) body must not be empty");
    };
}

// ----------------------------------------------------------------------------
// 22. Pipelined 400 Dedup
// ----------------------------------------------------------------------------
fn test_srv_reg1_s5b(t: lit::T&) {
    t.run("5b. Pipelined parse failure 400 dedup") { sub =>
        // F048: handle_connection_wire_pipelined on invalid first request must emit exactly ONE HTTP/1.1 400 Bad Request
        var server = server::new_http_server("127.0.0.1", 8080);
        let bad_req = "GET / HTTP/1.1\r\nHost : bad-colon\r\n\r\n";
        var pipe_out: u8[..1024] = [];
        let _, ok_pipe = server::handle_connection_wire_pipelined(server, "127.0.0.1", bad_req, 1000000000, pipe_out);
        sub.assert_false(ok_pipe, "Invalid request in pipelined wire rejected");
        let first_400 = find(pipe_out[..], "HTTP/1.1 400 Bad Request");
        sub.assert_ge(first_400, 0, "First 400 Bad Request emitted");
        let second_400 = find(pipe_out[(first_400 + 24)..], "HTTP/1.1 400 Bad Request");
        sub.assert_eq(second_400, -1, "Must NOT emit duplicate 400 Bad Request on parse failure");
    };
}

// ----------------------------------------------------------------------------
// 23. Round 2 Part 1a
// ----------------------------------------------------------------------------
fn srv_reg1_run_round2_part1a(t: lit::T&) {
    t.run("6a. Round 2 Server Audit Regressions (EdgeFilter & H2)") { sub =>
        // R2-F001: add_edge_filter_rule rejects disabled rules (>64B prefix), and edge_rule_matches canonicalizes path
        let long_pfx: const u8[:] = "/api/v1/012345678901234567890123456789012345678901234567890123456789/secret";
        let r_disabled = server::make_edge_filter_rule("long", long_pfx, server::EdgeFilterVerdict.BlockForbidden);
        var ef = server::EdgeFilter { .. };
        sub.assert_false(server::add_edge_filter_rule(ef, r_disabled), "add_edge_filter_rule must reject disabled overflow rule");
        let r_admin = server::make_edge_filter_rule("block-admin", "/admin", server::EdgeFilterVerdict.BlockForbidden);
        sub.assert_true(server::add_edge_filter_rule(ef, r_admin), "add_edge_filter_rule accepts valid rule");
        var empty_hdrs = http::HeaderMap { .. };
        sub.assert_true(server::edge_rule_matches(r_admin, "//admin/panel", empty_hdrs), "edge_rule_matches catches //admin/panel");
        sub.assert_true(server::edge_rule_matches(r_admin, "/./admin/panel", empty_hdrs), "edge_rule_matches catches /./admin/panel");
        sub.assert_true(server::edge_rule_matches(r_admin, "/public/../admin/panel", empty_hdrs), "edge_rule_matches catches /public/../admin/panel");

        // R2-F002: reset_h2_server_session_inplace resets urgency_heads and urgency_tails to -1
        var h2_sess = server_internal::new_h2_server_session("goose-wing/1.0", 1000);
        h2_sess.conn.urgency_heads[3] = 5;
        h2_sess.conn.urgency_tails[3] = 5;
        server_internal::reset_h2_server_session_inplace(h2_sess, "goose-wing/1.0", 2000);
        sub.assert_eq(h2_sess.conn.urgency_heads[3], -1, "urgency_heads reset to -1");
        sub.assert_eq(h2_sess.conn.urgency_tails[3], -1, "urgency_tails reset to -1");

        // R2-F003: emit_response_trailers when all trailers are disallowed emits 0-length DATA(END_STREAM), not 0-length HEADERS
        var bad_trailers = http::HeaderMap { .. };
        http::append_header(bad_trailers, "content-length", "10");
        var tr_wire: u8[..128] = [];
        server_internal::emit_response_trailers(h2_sess, 1, bad_trailers, tr_wire);
        sub.assert_eq(tr_wire.len, 9, "Filtered empty trailer block emits 9-byte frame");
        if tr_wire.len >= 9 {
            sub.assert_eq(tr_wire[3], 0x00, "Filtered empty trailer emits DATA frame (0x00), not HEADERS (0x01)");
            sub.assert_eq(tr_wire[4], 0x01, "Filtered empty trailer sets END_STREAM (0x01)");
        }

        // R2-F004 & R2-F005: 0-length DATA on closed stream does not emit WINDOW_UPDATE(0); self-dependent PRIORITY terminates stream
        var pipeline = server::new_server_pipeline_config("example.com", security::new_gcra_quota(1000, wing::secs(1), 100));
        var timer = server_internal::new_connection_timer(30000000000, 1000000000);
        server::add_route(pipeline.router, "GET", "/test", 10);
        var h2_wire: u8[>..] = [];
        h2_wire.append(rfc::H2_CLIENT_PREFACE);
        build_h2_test_frame_header(h2_wire, 0, 0x04, 0x00, 0);
        var h2_out: u8[>..] = [];
        let _, _ = server_internal::handle_h2_server_ingress(
            h2_sess, pipeline, timer, "127.0.0.1", h2_wire[..], 1000, h2_out,
        );
        h2_sess.conn.last_peer_stream_id = 1;
        var zero_data_wire: u8[>..] = [];
        build_h2_test_frame_header(zero_data_wire, 0, 0x00, 0x01, 1);
        h2_out.clear();
        let _, ok_zd = server_internal::handle_h2_server_ingress(
            h2_sess, pipeline, timer, "127.0.0.1", zero_data_wire[..], 1000, h2_out,
        );
        sub.assert_true(ok_zd, "0-length DATA on closed stream handled");
        sub.assert_eq(h2_out.len, 13, "Only 13-byte RST_STREAM emitted, no illegal WINDOW_UPDATE(0)");
    };
}

// ----------------------------------------------------------------------------
// 24. Round 2 Part 1b
// ----------------------------------------------------------------------------
fn srv_reg1_run_round2_part1b(t: lit::T&) {
    t.run("6b. Round 2 Server Audit Regressions (H2 Host, Timer, Router)") { sub =>
        // R2-F006: copy_stream_headers_and_trailers preserves synthesized Host from :authority even with 32 regular headers
        var st_full = server_internal::H2ServerStream { .. };
        st_full.authority.append("api.example.com");
        for h_i in 32 {
            var hname: u8[..64] = [];
            hname.append("x-custom-");
            core::fast_u64toa(h_i as u64, hname);
            http::append_header(st_full.headers, hname[..], "v");
        }
        var req_h2_full = http::new_request("GET", "/test");
        server_internal::copy_stream_headers_and_trailers(st_full, req_h2_full);
        sub.assert_eq(http::header(req_h2_full, "host"), "api.example.com", "Synthesized host header preserved when 32 regular headers present");

        // R2-F008: check_connection_tick does not underflow u64 when now_ns < timer.last_tick_mono_ns
        var ctimer = server_internal::new_connection_timer(30000000000, 1000000000);
        sub.assert_true(server_internal::check_connection_tick(ctimer, 500), "now_ns < last_tick_mono_ns must not wrap u64");
        sub.assert_eq(ctimer.missed_ticks, 0, "missed_ticks remains 0 when now_ns < last_tick_mono_ns");

        // R2-F013, R2-F014, R2-F015: Router unclosed '{*{}' guard, origin-form '://' preservation, and deep param backtracking
        var rtr = server::new_radix_router();
        sub.assert_false(server::insert_route(rtr.trees[0].tree, "/{*{}", 1), "Malformed /{*{} route rejected without slice abort");
        var norm_buf: u8[..256] = [];
        sub.assert_true(server::canonicalize_route_path("/redirect/http://evil.com/admin", norm_buf), "Origin-form path with :// canonicalized");
        sub.assert_eq(norm_buf[..], "/redirect/http:/evil.com/admin", "Origin-form path must not strip prefix before ://");

        server::insert_route(rtr.trees[1].tree, "/users/admin/settings", 10);
        server::insert_route(rtr.trees[1].tree, "/users/{id}/profile", 20);
        var bt_params = http::ZeroAllocParams { .. };
        let bt_res = server::match_path(rtr.trees[1].tree, "/users/admin/profile", bt_params);
        let bt_ok = match bt_res {
            Found f => f.handler_id == 20,
            _ => false,
        };
        sub.assert_true(bt_ok, "/users/admin/profile backtracks from static /users/admin/settings to /users/{id}/profile");
        sub.assert_eq(http::param_val(bt_params, 0, "/users/admin/profile"), "admin", "Extracted {id} == 'admin' after deep backtrack");
    };
}

// ----------------------------------------------------------------------------
// 25. Round 2 Part 2
// ----------------------------------------------------------------------------
fn srv_reg1_run_round2_part2(t: lit::T&) {
    t.run("7. Round 2 Server Audit Regressions (HTTP/1.1, WS, SNI, MMap, SoA)") { sub =>
        // R2-F016: HTTP/1.1 bare LF in headers and bare LF smuggling before Transfer-Encoding must be rejected
        var req_lf = http::Request { .. };
        let ok_lf1, _ = server::parse_http1_wire_request("GET / HTTP/1.1\r\nHost: example.com\nUser-Agent: x\r\n\r\n", req_lf);
        sub.assert_false(ok_lf1, "Bare LF at end of request header line must be rejected");
        let ok_lf2, _ = server::parse_http1_wire_request("POST / HTTP/1.1\r\nHost: example.com\r\n\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n", req_lf);
        sub.assert_false(ok_lf2, "Embedded bare LF before Transfer-Encoding must be rejected");
        var res_lf = http::Response { .. };
        let ok_lf3, _ = server::parse_http1_wire_response("HTTP/1.1 200 OK\r\nServer: gw\r\n\nContent-Length: 5\r\n\r\nhello", res_lf);
        sub.assert_false(ok_lf3, "Embedded bare LF in response headers block must be rejected");

        // R2-F018: feed_http_stream_chunk decodes chunked body framing and marks consumer.is_finished = true
        var stream_req = http::Request { .. };
        var consumer = server::HttpStreamConsumer { .. };
        let chunk_wire = "POST /upload HTTP/1.1\r\nHost: example.com\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n";
        let ok_begin, body_off = server::begin_http_stream_request(chunk_wire, stream_req, consumer);
        sub.assert_true(ok_begin && consumer.is_chunked, "Chunked stream request initialized");
        var streamed_payload: u8[..64] = [];
        var saw_last = false;
        let consumed_ch, is_last_ch, ok_ch = server::feed_http_stream_chunk(consumer, chunk_wire[body_off..]) { data, last =>
            streamed_payload.append(data);
            if last { saw_last = true; }
        };
        sub.assert_true(ok_ch && is_last_ch && saw_last && consumer.is_finished, "Chunked stream decoded to completion");
        sub.assert_eq(streamed_payload[..], "hello", "Chunked stream callback received decoded payload without chunk size framing");
        sub.assert_eq(consumed_ch, (chunk_wire.len - body_off) as i64, "Consumed exact chunked body bytes");

        // R2-F019 & R2-F020: WebSocket route matching with query string, SNI >4096B guard and trailing dot exact match
        var srv = server::new_http_server("127.0.0.1", 8080);
        let ws_b = realtime::WsBehavior { .. };
        sub.assert_true(server::add_ws_route(srv, "/ws/live", ws_b), "Registered /ws/live");
        sub.assert_ge(server::find_ws_route(srv, "/ws/live?token=abc"), 0, "find_ws_route matches request URL with query string");

        var oversize_pem: u8[..4200] = [];
        for k in 4100 { oversize_pem.push('A'); }
        sub.assert_false(server::add_server_name(srv, "api.example.com", "CERT", oversize_pem[..]), "add_server_name rejects >4096B PEM");
        sub.assert_true(server::add_server_name(srv, "*.wildcard.org", "CERT_WILD", "KEY_WILD"), "Registered wildcard SNI");
        sub.assert_true(server::add_server_name(srv, "special.wildcard.org", "CERT_EXACT", "KEY_EXACT"), "Registered exact SNI");
        let sni_cred, ok_sni = server::resolve_sni_credentials(srv, "special.wildcard.org.");
        sub.assert_true(ok_sni, "Resolved SNI with trailing dot");
        sub.assert_eq(sni_cred.cert_pem, "CERT_EXACT", "Exact SNI match takes priority even with trailing DNS dot");

        // R2-F021 & R2-F022: serve_static_mmap_file truncation guard & oversized chunked pipelined 413 rejection
        var tiny_cork = core::new_cork_buffer();
        tiny_cork.len = core::CORK_BUFFER_CAP - 16;
        sub.assert_false(server::serve_static_mmap_file("version.txt", "text/plain", tiny_cork), "serve_static_mmap_file rejects truncated output buffer");
    };
}

// ----------------------------------------------------------------------------
// 26. Round 2 Part 3
// ----------------------------------------------------------------------------
fn srv_reg1_run_round2_part3(t: lit::T&) {
    t.run("8. Round 2 Server Audit Regressions (Oversized Chunk 413 & SoA)") { sub =>
        let chunk_wire = "POST /upload HTTP/1.1\r\nHost: 127.0.0.1\r\nTransfer-Encoding: chunked\r\n\r\n10000000\r\nABCD";
        var req_huge = http::Request { .. };
        let _, _ = server::parse_http1_wire_request(chunk_wire, req_huge);
        var keep_huge = true;
        var huge_out: u8[..512] = [];
        let _ = server::handle_pipelined_parse_failure("goose-wing/1.0", chunk_wire, req_huge, huge_out, keep_huge);
        sub.assert_false(keep_huge, "Oversized chunk size > 10MB in pipelined stream closes connection");
        sub.assert_contains(huge_out[..], "HTTP/1.1 413", "Oversized chunk emits 413 Payload Too Large");

        // R2-F023: soa_table_free shrinks trailing high-water mark
        var soa = server::SoAConnTable { .. };
        let s0 = server::soa_table_alloc(soa, 10, 5);
        let s1 = server::soa_table_alloc(soa, 11, 5);
        sub.assert_eq(soa.count, 2, "SoA high-water mark is 2");
        server::soa_table_free(soa, s1);
        sub.assert_eq(soa.count, 1, "SoA high-water mark shrinks to 1 when highest slot freed");
        server::soa_table_free(soa, s0);
        sub.assert_eq(soa.count, 0, "SoA high-water mark shrinks to 0 when all slots freed");
    };
}

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

// ----------------------------------------------------------------------------
// 27. Cache & EdgeFilter
// ----------------------------------------------------------------------------
fn test_srv_reg2_r1_cache_and_edge_filter(t: lit::T&) {
    t.run("1. Cache route isolation, Content-Type preservation & EdgeFilter boundary") { sub =>
        // F001: Route A (/json) cache entry must not poison Route B (/plaintext), and must preserve Content-Type
        var cfg = server::new_server_pipeline_config("127.0.0.1", security::new_gcra_quota(1000, wing::secs(1), 100));
        let in_cache = wire::STAGE_SRV_IN_DEFAULT_MASK | wire::STAGE_SRV_IN_CACHE_LOOKUP;
        let out_cache = wire::STAGE_SRV_OUT_DEFAULT_MASK | wire::STAGE_SRV_OUT_CACHE_STORE;
        server::add_route_pso(cfg.router, "GET", "/json", 101, in_cache, out_cache);
        server::set_static_route_payload(cfg.router, 101, "application/json", "{\"ok\":true}");
        server::add_route_pso(cfg.router, "GET", "/plaintext", 102, in_cache, out_cache);
        server::set_static_route_payload(cfg.router, 102, "text/plain", "Hello!");

        var req_a = http::new_request("GET", "/json");
        http::set_header(req_a, "Host", "127.0.0.1");
        var res_a = http::Response { status_code: 200, .. };
        var timer = server_internal::new_connection_timer(30000000000, 1000000000);
        var fut = server_internal::InlineHandlerFuture { .. };
        let v_a = server::execute_pipeline(cfg, timer, "127.0.0.1", req_a, 1000000000, res_a, fut);
        sub.assert_true(v_a == server::PipelineOutcome.Handled, "First /json request populates cache");
        sub.assert_eq(http::header(res_a, "content-type"), "application/json", "First /json has Content-Type");

        // Second request to /json hits cache and must still include Content-Type
        var res_a2 = http::Response { status_code: 200, .. };
        let _ = server::execute_pipeline(cfg, timer, "127.0.0.1", req_a, 1000000000, res_a2, fut);
        sub.assert_eq(res_a2.body[..], "{\"ok\":true}", "Second /json hits cache body");
        sub.assert_eq(http::header(res_a2, "content-type"), "application/json", "Cached /json preserves Content-Type");

        // Request to /plaintext must NOT receive /json's cached body!
        var req_b = http::new_request("GET", "/plaintext");
        http::set_header(req_b, "Host", "127.0.0.1");
        var res_b = http::Response { status_code: 200, .. };
        let _ = server::execute_pipeline(cfg, timer, "127.0.0.1", req_b, 1000000000, res_b, fut);
        sub.assert_eq(res_b.body[..], "Hello!", "Route /plaintext must not be poisoned by /json cache");

        // F002: EdgeFilter path_prefix "/admin" must not block "/administrator", and "/admin/" must block "/admin"
        let r_admin = server::make_edge_filter_rule("block-admin", "/admin", server::EdgeFilterVerdict.BlockForbidden);
        let r_slash = server::make_edge_filter_rule("block-slash", "/admin/", server::EdgeFilterVerdict.BlockForbidden);
        var hdrs = http::HeaderMap { .. };
        sub.assert_false(server::edge_rule_matches(r_admin, "/administrator", hdrs), "/admin prefix must not match /administrator");
        sub.assert_true(server::edge_rule_matches(r_admin, "/admin/users", hdrs), "/admin prefix matches /admin/users");
        sub.assert_true(server::edge_rule_matches(r_slash, "/admin", hdrs), "/admin/ prefix matches canonicalized /admin");
    };
}

// ----------------------------------------------------------------------------
// 28. H2 Multiplexer
// ----------------------------------------------------------------------------
fn test_srv_reg2_r2_h2_multiplexer(t: lit::T&) {
    t.run("2. H2 HPACK dyn table update, conn window replenish on RST, partial send body corruption") { sub =>
        var sess = server_internal::new_h2_server_session("goose-wing/1.0", 1000);
        var pipeline = server::new_server_pipeline_config("127.0.0.1", security::new_gcra_quota(1000, wing::secs(1), 100));
        var timer = server_internal::new_connection_timer(30000000000, 1000000000);
        server::add_route(pipeline.router, "POST", "/echo", 1);

        var init_wire: u8[..256] = [];
        init_wire.append(rfc::H2_CLIENT_PREFACE);
        // Peer SETTINGS with HEADER_TABLE_SIZE (id=1) = 2048 and INITIAL_WINDOW_SIZE (id=4) = 1000
        build_h2_frame(init_wire, 12, 0x04, 0x00, 0);
        init_wire.push(0x00); init_wire.push(0x01);
        init_wire.push(0x00); init_wire.push(0x00); init_wire.push(0x08); init_wire.push(0x00); // 2048
        init_wire.push(0x00); init_wire.push(0x04);
        init_wire.push(0x00); init_wire.push(0x00); init_wire.push(0x03); init_wire.push(0xE8); // 1000
        var wire_out: u8[>..] = [];
        let _, ok_init = server_internal::handle_h2_server_ingress(sess, pipeline, timer, "127.0.0.1", init_wire[..], 1000, wire_out);
        sub.assert_true(ok_init, "H2 preface and SETTINGS handled");

        // F006: Stream 1 sends Content-Length: 5, then sends 10-byte DATA frame -> stream error PROTOCOL_ERROR,
        // but conn_recv_window MUST remain 65535 (replenished via conn WINDOW_UPDATE)!
        var dt = http2::new_dynamic_table(4096);
        var h1: u8[..512] = [];
        http2::encode_hpack_field(dt, h1, ":method", "POST", http2::HpackIndexing.Incremental, false);
        http2::encode_hpack_field(dt, h1, ":scheme", "https", http2::HpackIndexing.Incremental, false);
        http2::encode_hpack_field(dt, h1, ":authority", "127.0.0.1", http2::HpackIndexing.Incremental, false);
        http2::encode_hpack_field(dt, h1, ":path", "/echo", http2::HpackIndexing.Incremental, false);
        http2::encode_hpack_field(dt, h1, "content-length", "5", http2::HpackIndexing.Incremental, false);
        var w1: u8[..1024] = [];
        build_h2_frame(w1, h1.len as u32, 0x01, 0x04, 1);
        w1.append(h1[..]);
        build_h2_frame(w1, 10, 0x00, 0x01, 1);
        w1.append("0123456789");
        wire_out.clear();
        let _, ok_w1 = server_internal::handle_h2_server_ingress(sess, pipeline, timer, "127.0.0.1", w1[..], 1000, wire_out);
        sub.assert_true(ok_w1, "Stream 1 CL mismatch resets stream, keeps conn alive");
        sub.assert_eq(sess.conn.conn_recv_window, 65535, "conn_recv_window replenished after stream DATA error");

        // F008: Pre-populate route_cache with 10,000 'Z' bytes on handler 55 and register /cached-big with CACHE_LOOKUP.
        // Peer initial window is 1000 -> 1000 bytes sent initially, 9000 bytes remaining (> 8192 inline cap!).
        // Then peer sends WINDOW_UPDATE(+20000) -> flushed DATA must NOT contain "LEAKED_REQ_BYTES"!
        var big_cached: u8[>..] = [];
        for k in 10000 { big_cached.push('Z'); }
        server::cache_store(pipeline.route_cache, 1, big_cached[..], 55, "text/plain");
        let in_cache = wire::STAGE_SRV_IN_DEFAULT_MASK | wire::STAGE_SRV_IN_CACHE_LOOKUP;
        server::add_route_pso(pipeline.router, "GET", "/cached-big", 55, in_cache, wire::STAGE_SRV_OUT_DEFAULT_MASK);
        var h5: u8[..512] = [];
        http2::encode_hpack_field(dt, h5, ":method", "GET", http2::HpackIndexing.Incremental, false);
        http2::encode_hpack_field(dt, h5, ":scheme", "https", http2::HpackIndexing.Incremental, false);
        http2::encode_hpack_field(dt, h5, ":authority", "127.0.0.1", http2::HpackIndexing.Incremental, false);
        http2::encode_hpack_field(dt, h5, ":path", "/cached-big", http2::HpackIndexing.Incremental, false);
        var w5: u8[..1024] = [];
        build_h2_frame(w5, h5.len as u32, 0x01, 0x04, 5);
        w5.append(h5[..]);
        build_h2_frame(w5, 16, 0x00, 0x01, 5);
        w5.append("LEAKED_REQ_BYTES");
        wire_out.clear();
        let _, ok_w5 = server_internal::handle_h2_server_ingress(sess, pipeline, timer, "127.0.0.1", w5[..], 1000, wire_out);
        sub.assert_true(ok_w5, "Stream 5 partial send initiated");

        // Send WINDOW_UPDATE for conn (0) and stream 5 (+20000)
        var wu5: u8[..64] = [];
        build_h2_frame(wu5, 4, 0x08, 0x00, 0);
        wu5.push(0x00); wu5.push(0x00); wu5.push(0x4E); wu5.push(0x20);
        build_h2_frame(wu5, 4, 0x08, 0x00, 5);
        wu5.push(0x00); wu5.push(0x00); wu5.push(0x4E); wu5.push(0x20);
        wire_out.clear();
        let _, ok_wu5 = server_internal::handle_h2_server_ingress(sess, pipeline, timer, "127.0.0.1", wu5[..], 1000, wire_out);
        sub.assert_true(ok_wu5, "Stream 5 WINDOW_UPDATE handled");
        sub.assert_false(core::contains(wire_out[..], "LEAKED_REQ_BYTES"), "Request body must NEVER leak into response DATA");
        sub.assert_true(wire_out.len >= 9000, "Remaining 9000 response bytes flushed after WINDOW_UPDATE");
    };
}

// ----------------------------------------------------------------------------
// 29. Pipeline & Router
// ----------------------------------------------------------------------------
fn test_srv_reg2_r3_pipeline_and_router(t: lit::T&) {
    t.run("3. Pipeline Accept-Encoding q=0, Vary preservation, X-Matched-Route, HEAD ETag & Router backtrack") { sub =>
        // F010: client_accepts_encoding must reject q=0 and preserve Vary: Origin on compression
        sub.assert_false(server::client_accepts_encoding("zstd;q=0, gzip;q=0.0", "zstd"), "zstd;q=0 must be rejected");
        sub.assert_false(server::client_accepts_encoding("x-br", "br"), "x-br must not substring-match br");
        sub.assert_true(server::client_accepts_encoding("gzip;q=0, br;q=0.8", "br"), "br;q=0.8 must be accepted");

        // F011 & F012: X-Matched-Route emitted in telemetry and HEAD ETag 304 Not Modified works
        var cfg = server::new_server_pipeline_config("127.0.0.1", security::new_gcra_quota(1000, wing::secs(1), 100));
        let pso = server::DEFAULT_ROUTE_PSO_MASK | server::STAGE_EGRESS_ETAG | server::STAGE_EGRESS_METRICS | server::STAGE_EGRESS_ACCESS_LOG;
        server::add_route_pso(cfg.router, "GET", "/item", 201, pso);
        server::set_static_route_payload(cfg.router, 201, "text/plain", "hello-etag-world");
        server::add_route_pso(cfg.router, "HEAD", "/item", 201, pso);

        var req_get = http::new_request("GET", "/item");
        http::set_header(req_get, "Host", "127.0.0.1");
        var res_get = http::Response { status_code: 200, .. };
        var timer = server_internal::new_connection_timer(30000000000, 1000000000);
        var fut = server_internal::InlineHandlerFuture { .. };
        let _ = server::execute_pipeline(cfg, timer, "127.0.0.1", req_get, 1000000000, res_get, fut);
        let etag_val = http::header(res_get, "etag");
        sub.assert_true(etag_val.len > 0, "GET /item produces ETag");
        sub.assert_eq(http::header(res_get, "x-matched-route"), "/item", "Telemetry stage emits X-Matched-Route");

        var req_head = http::new_request("HEAD", "/item");
        http::set_header(req_head, "Host", "127.0.0.1");
        http::set_header(req_head, "If-None-Match", etag_val);
        var res_head = http::Response { status_code: 200, .. };
        let _ = server::execute_pipeline(cfg, timer, "127.0.0.1", req_head, 1000000000, res_head, fut);
        sub.assert_eq(res_head.status_code, 304, "HEAD /item with matching If-None-Match returns 304 Not Modified");
        sub.assert_eq(res_head.body.len, 0, "HEAD /item response body is empty");

        // F015 & F016: Router malformed braces rejected and multi-level wildcard backtrack works
        var rtr = server::new_radix_router();
        sub.assert_false(server::insert_route(rtr.trees[0].tree, "/unclosed/{id", 1), "Unclosed { rejected");
        sub.assert_false(server::insert_route(rtr.trees[0].tree, "/stray/id}", 2), "Stray } rejected");
        sub.assert_false(server::insert_route(rtr.trees[0].tree, "/nested/{a{b}}", 3), "Nested { rejected");

        // Multi-branch backtrack: /{*any}, /users/{id}/profile, and /users/admin/settings/deep
        sub.assert_true(server::insert_route(rtr.trees[1].tree, "/{*any}", 100), "Insert catch-all /{*any}");
        sub.assert_true(server::insert_route(rtr.trees[1].tree, "/users/{id}/profile", 200), "Insert /users/{id}/profile");
        sub.assert_true(server::insert_route(rtr.trees[1].tree, "/users/admin/settings/deep", 300), "Insert /users/admin/settings/deep");

        var p1 = http::ZeroAllocParams { .. };
        let m1 = server::match_path(rtr.trees[1].tree, "/users/admin/settings/other", p1);
        let m1_ok = match m1 {
            Found f => f.handler_id == 100,
            _ => false,
        };
        sub.assert_true(m1_ok, "/users/admin/settings/other backtracks past /users/{id} to /{*any}");

        var p2 = http::ZeroAllocParams { .. };
        let m2 = server::match_path(rtr.trees[1].tree, "/users/admin/profile", p2);
        let m2_ok = match m2 {
            Found f => f.handler_id == 200,
            _ => false,
        };
        sub.assert_true(m2_ok, "/users/admin/profile backtracks from static admin to /users/{id}/profile");
        sub.assert_eq(http::param_val(p2, 0, "/users/admin/profile"), "admin", "Extracted param id == admin");
    };
}

// ----------------------------------------------------------------------------
// 30. Server Wire
// ----------------------------------------------------------------------------
fn test_srv_reg2_r4_server_wire(t: lit::T&) {
    t.run("4. Host :0 & forbidden chars, TE readiness, remove_header mask, chunked readiness with trailers") { sub =>
        // F017: Host port :0 and forbidden host chars must be rejected
        var req_h = http::Request { .. };
        let ok_p0, _ = server::parse_http1_wire_request("GET / HTTP/1.1\r\nHost: example.com:0\r\n\r\n", req_h);
        sub.assert_false(ok_p0, "Host: example.com:0 must be rejected");
        let ok_badc, _ = server::parse_http1_wire_request("GET / HTTP/1.1\r\nHost: ex<ample>.com\r\n\r\n", req_h);
        sub.assert_false(ok_badc, "Host with < > must be rejected");

        // F018: is_http1_request_ready must immediately return true on unsupported Transfer-Encoding: gzip
        let te_gzip = "POST /upload HTTP/1.1\r\nHost: example.com\r\nTransfer-Encoding: gzip\r\n\r\n";
        let te_hdr_end = core::find(te_gzip, "\r\n\r\n");
        sub.assert_true(server::is_http1_request_ready(te_gzip, te_hdr_end), "Unsupported TE: gzip is immediately ready for 501/400 rejection");

        // F019: remove_header("Content-Type") must clear HDR_PRESENCE_CONTENT_TYPE so serialize_http1_headers does not corrupt header 0
        var res = http::Response { status_code: 200, .. };
        http::set_header(res, "Content-Type", "text/plain");
        http::remove_header(res, "Content-Type");
        http::set_header(res, "X-Custom", "MyVal");
        var wire_res: u8[..512] = [];
        server::serialize_http1_response(res, "goose-wing/1.0", wire_res);
        sub.assert_true(core::contains(wire_res[..], "X-Custom: MyVal\r\n"), "X-Custom header preserved after remove_header(Content-Type)");

        // F021: is_http1_request_ready on chunked body with trailers and on chunked body containing "0\r\n\r\n" inside data
        let chunk_with_trailer_partial = "POST / HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\nX-Trailer: 1\r\n";
        let chunk_with_trailer_done = "POST / HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\nX-Trailer: 1\r\n\r\n";
        let tr_hdr_end = core::find(chunk_with_trailer_partial, "\r\n\r\n");
        sub.assert_false(server::is_http1_request_ready(chunk_with_trailer_partial, tr_hdr_end), "Incomplete chunked trailer not ready");
        sub.assert_true(server::is_http1_request_ready(chunk_with_trailer_done, tr_hdr_end), "Complete chunked trailer is ready");

        let chunk_embedded_zero = "POST / HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: chunked\r\n\r\n8\r\n0\r\n\r\nabc";
        let emb_hdr_end = core::find(chunk_embedded_zero, "\r\n\r\n");
        sub.assert_false(server::is_http1_request_ready(chunk_embedded_zero, emb_hdr_end), "Embedded 0\\r\\n\\r\\n inside unfinished chunk data must not trigger ready");
    };
}

// ----------------------------------------------------------------------------
// 31. Cache & EdgeFilter
// ----------------------------------------------------------------------------
fn test_srv_reg3_r1_cache_and_edge_filter(t: lit::T&) {
    t.run("1. Cache URL/query key isolation, SWR is_updating reset & EdgeFilter >512B Pass bypass") { sub =>
        // F001a: Same handler_id across parameterized/query URLs must not serve poisoned cached entry
        var cfg = server::new_server_pipeline_config("127.0.0.1", security::new_gcra_quota(1000, wing::secs(1), 100));
        let in_cache = wire::STAGE_SRV_IN_DEFAULT_MASK | wire::STAGE_SRV_IN_CACHE_LOOKUP;
        let out_cache = wire::STAGE_SRV_OUT_DEFAULT_MASK | wire::STAGE_SRV_OUT_CACHE_STORE;
        server::add_route_pso(cfg.router, "GET", "/items/{id}", 201, in_cache, out_cache);

        var req1 = http::new_request("GET", "/items/alice");
        http::set_header(req1, "Host", "127.0.0.1");
        var res1 = http::Response { status_code: 200, .. };
        res1.body.append("payload-alice");
        let v_m1 = server::stage_server_cache_lookup(cfg.route_cache, req1, 1000, res1, 201);
        sub.assert_true(v_m1 == wire::StageVerdict.Continue, "Initial /items/alice is cache miss");
        let _ = server::stage_server_cache_store(cfg.route_cache, 1000, res1, 201, req1.url[..]);

        var req2 = http::new_request("GET", "/items/bob");
        http::set_header(req2, "Host", "127.0.0.1");
        var res2 = http::Response { status_code: 200, .. };
        let v_m2 = server::stage_server_cache_lookup(cfg.route_cache, req2, 1001, res2, 201);
        sub.assert_true(v_m2 == wire::StageVerdict.Continue, "/items/bob sharing handler_id 201 must not hit /items/alice cache entry");

        // F001b: SWR HitStaleNeedsUpdate sets is_updating=true; oversized/failed store must still clear is_updating
        var res_swr = http::Response { status_code: 200, .. };
        let v_swr = server::stage_server_cache_lookup(cfg.route_cache, req1, 2500, res_swr, 201);
        sub.assert_true(v_swr == wire::StageVerdict.Continue, "First stale request triggers background update (HitStaleNeedsUpdate)");
        sub.assert_true(cfg.route_cache.is_updating, "is_updating is true during refresh");
        var huge_payload: u8[..16400] = [];
        for i in 16400 {
            huge_payload.push('X');
        }
        let stored_ok = server::cache_store(cfg.route_cache, 2500, huge_payload[..], 201, "text/plain");
        sub.assert_false(stored_ok, "Oversized payload fails cache_store");
        sub.assert_false(cfg.route_cache.is_updating, "is_updating must be reset even when cache_store fails");

        // F002: EdgeFilter >512B path must not match Pass allowlist rule and bypass BlockForbidden rule
        var ef = server::EdgeFilter { .. };
        assert(server::add_edge_filter_rule(ef, server::make_edge_filter_rule("allow-pub", "/public", server::EdgeFilterVerdict.Pass)));
        assert(server::add_edge_filter_rule(ef, server::make_edge_filter_rule("block-adm", "/admin", server::EdgeFilterVerdict.BlockForbidden)));
        var long_admin: u8[..600] = [];
        long_admin.append("/admin/");
        for j in 550 {
            long_admin.push('a');
        }
        var dummy_hdrs = http::HeaderMap { .. };
        let ef_v = server::evaluate_edge_filter(ef, "GET", long_admin[..], dummy_hdrs);
        sub.assert_true(ef_v == server::EdgeFilterVerdict.BlockForbidden, ">512B /admin/... path must hit BlockForbidden, not Pass");
    };
}

// ----------------------------------------------------------------------------
// 32. Pipeline & Pool
// ----------------------------------------------------------------------------
fn test_srv_reg3_r2_pipeline_and_pool(t: lit::T&) {
    t.run("2. Pipeline PSO mask collisions, CORS/405 preflight, compress CL/ETag, Cookie/Forwarded & Timer") { sub =>
        // F003: Enabling only STAGE_EGRESS_COMPRESS_GZIP alongside DEFAULT_ROUTE_PSO_MASK must not enable ZSTD/BR via low-bit collision
        var cfg = server::new_server_pipeline_config("example.com", security::new_gcra_quota(1000, wing::secs(1), 100));
        var req_c = http::new_request("GET", "/data");
        http::set_header(req_c, "Accept-Encoding", "zstd, gzip");
        var res_c = http::Response { status_code: 200, .. };
        http::set_header(res_c, "Content-Type", "text/plain");
        http::set_header(res_c, "Content-Length", "80");
        http::set_header(res_c, "ETag", "\"v1\"");
        for k in 80 {
            res_c.body.push('A');
        }
        let pso_gzip_only = (server::DEFAULT_ROUTE_PSO_MASK & ~(server::STAGE_EGRESS_COMPRESS_BROTLI | server::STAGE_EGRESS_COMPRESS_ZSTD)) | server::STAGE_EGRESS_COMPRESS_GZIP;
        server::dispatch_egress_pipeline(cfg, req_c, res_c, pso_gzip_only, 1000, -1);
        sub.assert_eq(http::header(res_c, "content-encoding"), "gzip", "Only gzip enabled in egress PSO must not select zstd");

        // F005: Compression must strip stale Content-Length and weaken/qualify strong ETag
        sub.assert_eq(http::header(res_c, "content-length"), "", "Stale uncompressed Content-Length must be removed after compression");
        sub.assert_true(http::header(res_c, "etag") != "\"v1\"", "Strong ETag must be modified when Content-Encoding is applied");

        // F004: Unmatched route (404) or MethodNotAllowed (OPTIONS preflight to POST route) must not escalate PSO to require JWT auth
        assert(security::add_allowed_origin(cfg.cors_policy, "https://app.example.com"));
        assert(auth::add_symmetric_key(cfg.jwks, "k1", auth::JwtAlg.HS256, "0123456789abcdef0123456789abcdef"));
        server::add_route_pso(cfg.router, "POST", "/api/submit", 301, server::DEFAULT_ROUTE_PSO_MASK | server::STAGE_INGRESS_CORS_PREFLIGHT);
        var req_opt = http::new_request("OPTIONS", "/api/submit");
        http::set_header(req_opt, "Host", "example.com");
        http::set_header(req_opt, "Origin", "https://app.example.com");
        http::set_header(req_opt, "Access-Control-Request-Method", "POST");
        var res_opt = http::Response { status_code: 200, .. };
        var timer = server_internal::new_connection_timer(30000000000, 1000000000);
        var fut = server_internal::InlineHandlerFuture { .. };
        let v_opt = server::execute_pipeline(cfg, timer, "127.0.0.1", req_opt, 1000000000, res_opt, fut);
        sub.assert_true(v_opt == server::PipelineOutcome.CorsPreflight, "CORS preflight OPTIONS returns CorsPreflight");
        sub.assert_eq(res_opt.status_code as i64, 204, "CORS preflight returns 204 without 401 JWT escalation");

        // F006a: Cookie tossing (invalid first session= cookie followed by valid session= cookie)
        let key: u8[32] = [
            1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16,
            17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32,
        ];
        assert(security::add_key(cfg.private_jar.store, security::KeySlot { key_id: 1, master_key: key, .. }));
        var sealed_val: u8[..256] = [];
        assert(security::seal(cfg.private_jar, "session", "uid=42", 1, 999, sealed_val));
        var hdr_cookie: u8[..320] = [];
        hdr_cookie.append("session=invalid_tossed; session=");
        hdr_cookie.append(sealed_val[..]);
        var req_ck = http::new_request("GET", "/");
        http::set_header(req_ck, "Cookie", hdr_cookie[..]);
        var ext_ck = server_internal::RequestExtensions { .. };
        let _ = server::stage_server_auth_cookie(cfg.private_jar, req_ck, ext_ck, 1000000000);
        sub.assert_eq(ext_ck.session_data[..], "uid=42", "Valid second session cookie accepted after tossed first cookie");

        // F006b: Forwarded multi-element & X-Forwarded-For port stripping + ConnectionTimer activity reset
        var req_ip = http::new_request("GET", "/");
        http::set_header(req_ip, "Forwarded", "proto=https, for=\"[2001:db8::1]:8443\"");
        let ip_out = server::extract_effective_client_ip(true, "127.0.0.1", req_ip);
        sub.assert_eq(ip_out, "2001:db8::1", "Forwarded second element for= extracted and port stripped");

        var ctimer = server_internal::new_connection_timer(2000, 100);
        server_internal::notify_request_start(ctimer);
        server_internal::notify_request_end(ctimer);
        let t_alive1 = server_internal::advance_connection_tick(ctimer);
        server_internal::notify_request_start(ctimer);
        server_internal::notify_request_end(ctimer);
        let t_alive2 = server_internal::advance_connection_tick(ctimer);
        sub.assert_true(t_alive1 && t_alive2, "Completed requests between ticks must reset missed_ticks and keep connection alive");
    };
}

// ----------------------------------------------------------------------------
// 33. H2 & Router
// ----------------------------------------------------------------------------
fn test_srv_reg3_r3_h2_and_router(t: lit::T&) {
    t.run("3. H2 rejected HEADERS HPACK sync, 8192 initial window & Router OPTIONS *, >512B path, suffix param") { sub =>
        // F007a: local_initial_window_size must match advertised H2_SERVER_INITIAL_STREAM_WINDOW (8192)
        var sess = server_internal::new_h2_server_session("goose-wing/1.0", 1000);
        sub.assert_eq(sess.conn.local_initial_window_size as i64, 8192, "H2 session local_initial_window_size matches advertised 8192");

        // F007b: Self-dependent HEADERS (stream 1 depends on stream 1) with PRIORITY (0x20) + END_HEADERS (0x04)
        // must still decode HPACK incremental indexing so subsequent stream 3 referencing that dynamic entry succeeds!
        var pipeline = server::new_server_pipeline_config("127.0.0.1", security::new_gcra_quota(1000, wing::secs(1), 100));
        var timer = server_internal::new_connection_timer(30000000000, 1000000000);
        server::add_route(pipeline.router, "GET", "/ok", 10);

        var wire_in: u8[..1024] = [];
        wire_in.append(rfc::H2_CLIENT_PREFACE);
        build_h2_frame(wire_in, 0, 0x04, 0x00, 0);

        var dt = http2::new_dynamic_table(4096);
        var h1_pri: u8[..512] = [];
        // 5-byte PRIORITY header: dep = stream 1 (self-dependency -> RST_STREAM(PROTOCOL_ERROR)), weight = 15
        h1_pri.push(0x00); h1_pri.push(0x00); h1_pri.push(0x00); h1_pri.push(0x01); h1_pri.push(15);
        http2::encode_hpack_field(dt, h1_pri, ":method", "GET", http2::HpackIndexing.Incremental, false);
        http2::encode_hpack_field(dt, h1_pri, ":scheme", "https", http2::HpackIndexing.Incremental, false);
        http2::encode_hpack_field(dt, h1_pri, ":authority", "127.0.0.1", http2::HpackIndexing.Incremental, false);
        http2::encode_hpack_field(dt, h1_pri, ":path", "/ok", http2::HpackIndexing.Incremental, false);
        http2::encode_hpack_field(dt, h1_pri, "x-shared-dyn", "dyn-value-123", http2::HpackIndexing.Incremental, false);
        build_h2_frame(wire_in, h1_pri.len as u32, 0x01, 0x25, 1); // END_STREAM(0x01) | END_HEADERS(0x04) | PRIORITY(0x20)
        wire_in.append(h1_pri[..]);

        // Stream 3 references the newly indexed dynamic table entry ("x-shared-dyn: dyn-value-123")
        var h3: u8[..512] = [];
        http2::encode_hpack_field(dt, h3, ":method", "GET", http2::HpackIndexing.Incremental, false);
        http2::encode_hpack_field(dt, h3, ":scheme", "https", http2::HpackIndexing.Incremental, false);
        http2::encode_hpack_field(dt, h3, ":authority", "127.0.0.1", http2::HpackIndexing.Incremental, false);
        http2::encode_hpack_field(dt, h3, ":path", "/ok", http2::HpackIndexing.Incremental, false);
        http2::encode_hpack_field(dt, h3, "x-shared-dyn", "dyn-value-123", http2::HpackIndexing.Incremental, false);
        build_h2_frame(wire_in, h3.len as u32, 0x01, 0x05, 3);
        wire_in.append(h3[..]);

        var wire_out: u8[>..] = [];
        let _, ok_h2 = server_internal::handle_h2_server_ingress(sess, pipeline, timer, "127.0.0.1", wire_in[..], 1000, wire_out);
        sub.assert_true(ok_h2, "H2 connection survives self-dependent stream 1 and decodes stream 3 dynamic HPACK entry");
        sub.assert_true(sess.conn.hpack_dec.entries.len > 0, "HPACK decoder dynamic table updated on rejected stream 1");

        // F009a: Non-terminal catch-all {*rest}/tail must be rejected by insert_route
        var rtr = server::new_radix_router();
        sub.assert_false(server::insert_route(rtr.trees[0].tree, "/files/{*rest}/tail", 1), "Non-terminal catch-all route rejected");

        // F009b: OPTIONS * must not match parameterized/wildcard routes in OPTIONS tree
        server::add_route(rtr, "OPTIONS", "/{*any}", 99);
        server::add_route(rtr, "GET", "/ping", 2);
        var params_opt = http::ZeroAllocParams { .. };
        let m_star = server::match_route(rtr, "OPTIONS", "*", params_opt);
        let m_star_is_405 = match m_star {
            MethodNotAllowed _ => true,
            _ => false,
        };
        sub.assert_true(m_star_is_405, "OPTIONS * returns server-wide Allow via MethodNotAllowed, not matching /{*any}");

        // F009c: Suffix param /archive/{name}.tar.gz with dots inside parameter value ("app.v1.tar.gz")
        server::add_route(rtr, "GET", "/archive/{name}.tar.gz", 3);
        var p_arc = http::ZeroAllocParams { .. };
        let m_arc = server::match_route(rtr, "GET", "/archive/app.v1.tar.gz", p_arc);
        let m_arc_found = match m_arc {
            Found f => f.handler_id == 3,
            _ => false,
        };
        sub.assert_true(m_arc_found, "/archive/app.v1.tar.gz matches /archive/{name}.tar.gz");
        sub.assert_eq(http::param_val(p_arc, 0, "/archive/app.v1.tar.gz"), "app.v1", "Extracted {name} before .tar.gz is app.v1");
    };
}

var g_stream_last_seen: bool = false;

fn srv_reg3_on_stream_chunk(data: const u8[:], is_last: bool) {
    let _ = data;
    if is_last {
        g_stream_last_seen = true;
    }
}

// ----------------------------------------------------------------------------
// 34. Server Wire
// ----------------------------------------------------------------------------
fn test_srv_reg3_r4_server_wire(t: lit::T&) {
    t.run("4. Split-TCP chunked EmptyInput, status reason-phrase LF, stream 0-chunk callback, 304 CL & dcz;q=0") { sub =>
        // F011: Split-TCP chunked headers with 0 body bytes yet (ChunkedDecodeError.EmptyInput) must NOT wipe out_req.headers
        var req_split = http::Request { .. };
        let ok_sp, _ = server::parse_http1_wire_request("POST /upload HTTP/1.1\r\nHost: example.com\r\nTransfer-Encoding: chunked\r\n\r\n", req_split);
        sub.assert_false(ok_sp, "Incomplete chunked request without terminal chunk returns ok=false");
        sub.assert_true(req_split.headers.entries.len > 0, "Split-TCP chunked headers must remain intact on EmptyInput so server waits for more bytes instead of 400");

        // F012a: Bare LF inside status reason-phrase must be rejected by parse_http1_wire_response
        var res_lf = http::Response { .. };
        let ok_lf, _ = server::parse_http1_wire_response("HTTP/1.1 200 OK\nFake-Header: 1\r\nContent-Length: 0\r\n\r\n", res_lf);
        sub.assert_false(ok_lf, "Status line containing bare LF in reason-phrase must be rejected");

        // F012b: feed_http_stream_chunk must invoke Callback("", true) on terminal 0\r\n\r\n chunk arriving in second packet
        g_stream_last_seen = false;
        var consumer = server::HttpStreamConsumer { content_length: -1, is_chunked: true, is_headers_parsed: true, .. };
        let _, is_last1, ok_sc1 = server::feed_http_stream_chunk(consumer, "5\r\nhello\r\n", srv_reg3_on_stream_chunk);
        sub.assert_true(ok_sc1 && !is_last1, "First chunk packet consumed without terminal chunk");
        let _, is_last2, ok_sc2 = server::feed_http_stream_chunk(consumer, "0\r\n\r\n", srv_reg3_on_stream_chunk);
        sub.assert_true(ok_sc2 && is_last2, "Chunked stream consumer completes on 0\\r\\n\\r\\n");
        sub.assert_true(g_stream_last_seen, "Callback invoked with is_last=true on terminal 0-length chunk");

        // F012c: end_without_body on 304 Not Modified must preserve reported_content_length and not duplicate Server header
        var res_304 = http::Response { status_code: 304, .. };
        http::set_header(res_304, "Server", "custom-srv");
        var wire_304: u8[..512] = [];
        server::end_without_body(res_304, "goose-wing/1.0", wire_304, 128);
        sub.assert_true(core::contains(wire_304[..], "Content-Length: 128\r\n"), "304 response preserves explicit Content-Length from end_without_body");
        sub.assert_false(core::contains(wire_304[..], "Server: goose-wing/1.0\r\n"), "Custom Server header suppresses duplicate default Server header");

        // F012d: accept_encoding_has_token must reject q=0 and response_wire_has_connection_close must detect close in 2nd pipelined response
        sub.assert_false(http::accept_encoding_has_token("dcz;q=0, gzip", "dcz"), "dcz;q=0 must not match accept_encoding_has_token");
        let pipe_wire = "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\nHTTP/1.1 400 Bad Request\r\nConnection: close\r\nContent-Length: 0\r\n\r\n";
        sub.assert_true(server::response_wire_has_connection_close(pipe_wire), "Connection: close in 2nd pipelined response detected");
    };

    t.run("5. Integrated Server Pipeline: security.txt, Content-Digest + RFC 9457 ProblemDetails, DPoP & Ed25519 Signatures") { sub =>
        var cfg = server::new_default_server_pipeline_config("example.com");
        cfg.enable_csrf_guard = false;
        cfg.verify_request_digest = true;
        cfg.emit_problem_details = true;
        cfg.security_txt = http::parse_security_txt(
            "Contact: mailto:sec@example.com\nExpires: 2030-01-01T00:00:00Z\n",
            1700000000,
        );
        server::add_route(cfg.router, "POST", "/submit", 1);

        var timer = server_internal::new_connection_timer(30000000000, 1000000000);
        var fut = server_internal::InlineHandlerFuture { .. };

        // 1. /.well-known/security.txt automatic serving
        var req_sec = http::new_request("GET", "/.well-known/security.txt");
        var res_sec = http::Response { .. };
        let out_sec = server::execute_pipeline(cfg, timer, "127.0.0.1", req_sec, 1000000000, res_sec, fut);
        sub.assert_true(out_sec == server::PipelineOutcome.Handled, "security.txt request handled");
        sub.assert_eq(res_sec.status_code, 200, "security.txt returned 200");
        sub.assert_true(core::contains(res_sec.text(), "Contact: mailto:sec@example.com"), "security.txt formatted body");

        // 2. Content-Digest mismatch emits RFC 9457 ProblemDetails 400 response
        var req_bad_dig = http::new_request("POST", "/submit");
        req_bad_dig.body.append("tampered-body");
        http::set_header(req_bad_dig, "Content-Digest", "sha-256=:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=:");
        var res_bad_dig = http::Response { .. };
        let _ = server::execute_pipeline(cfg, timer, "127.0.0.1", req_bad_dig, 2000000000, res_bad_dig, fut);
        sub.assert_eq(res_bad_dig.status_code, 400, "Invalid Content-Digest rejected with 400");
        sub.assert_true(core::contains(res_bad_dig.text(), "Content-Digest verification failed"), "RFC 9457 ProblemDetails body emitted");

        // 3. Route Not Found emits RFC 9457 ProblemDetails 404 response
        var req_404 = http::new_request("GET", "/nonexistent");
        var res_404 = http::Response { .. };
        let _ = server::execute_pipeline(cfg, timer, "127.0.0.1", req_404, 3000000000, res_404, fut);
        sub.assert_eq(res_404.status_code, 404, "Missing route returned 404");
        sub.assert_bytes_eq(res_404.header("Content-Type"), rfc::MIME_PROBLEM_JSON, "404 returned application/problem+json");
    };
}

fn test_goose2rfc_server_audit_regressions(t: lit::T&) {
    t.run("1. SERVER1_C01: H2 GOAWAY 0x7FFFFFFF graceful shutdown & non-increasing last_stream_id (RFC 9113 §6.8)") { sub =>
        var sess = server_internal::H2ServerSession { .. };
        sess.conn.is_server = true;
        var out_wire: u8[..256] = [];
        let ga_hdr = http2::FrameHeader {
            length:     8,
            frame_type: rfc::H2_FRAME_GOAWAY,
            flags:      0,
            stream_id:  0,
        };
        var payload_max: u8[8] = [0x7F, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00];
        let ok_max = server_internal::process_ingress_goaway(sess, ga_hdr, payload_max[..], out_wire);
        sub.assert_true(ok_max, "Client graceful-shutdown GOAWAY with last_stream_id=0x7FFFFFFF accepted");
        sub.assert_eq(sess.conn.goaway_last_stream_id, 0x7FFFFFFF, "goaway_last_stream_id recorded as 0x7FFFFFFF");

        var payload_even: u8[8] = [0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00];
        let ok_even = server_internal::process_ingress_goaway(sess, ga_hdr, payload_even[..], out_wire);
        sub.assert_true(ok_even, "Subsequent GOAWAY with lower even stream ID 2 accepted");
        sub.assert_eq(sess.conn.goaway_last_stream_id, 2, "goaway_last_stream_id decreased to 2");

        var payload_inc: u8[8] = [0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00];
        let ok_inc = server_internal::process_ingress_goaway(sess, ga_hdr, payload_inc[..], out_wire);
        sub.assert_false(ok_inc, "Subsequent GOAWAY increasing last_stream_id from 2 to 4 rejected");
        sub.assert_true(out_wire.len > 0, "PROTOCOL_ERROR GOAWAY emitted on increasing last_stream_id");
    };

    t.run("2. SERVER1_C02..C05: Host empty port (RFC 9110 §7.2) & H1 parser transactional rollback") { sub =>
        sub.assert_true(server::validate_host_header_structure("example.com:"), "Host with empty port after colon is valid per RFC 9110 §7.2");
        sub.assert_true(server::validate_host_header_structure("[::1]:"), "IPv6 Host with empty port after colon is valid per RFC 9110 §7.2");

        var req = http::Request { .. };
        req.method.clear();
        let ok_rl = server::parse_http1_request_line("POST /valid HTTP/9.9", req);
        sub.assert_false(ok_rl, "Unsupported HTTP version rejected");
        sub.assert_eq(req.method.len, 0, "out_req.method untouched on parse_http1_request_line failure");
        sub.assert_eq(req.url.len, 0, "out_req.url untouched on parse_http1_request_line failure");

        var tracker = http::HeaderPresenceTracker { .. };
        let ok_hdrs = server::parse_http1_headers_stream(
            "Host: example.com\r\nBad Header: val\r\n\r\n",
            req,
            tracker,
        );
        sub.assert_false(ok_hdrs, "Invalid second header rejected");
        sub.assert_eq(req.headers.entries.len, 0, "out_req.headers rolled back on parse_http1_headers_stream failure");
        sub.assert_eq(req.presence_mask, 0, "out_req.presence_mask rolled back on failure");
        sub.assert_eq(tracker.mask, 0, "presence_tracker rolled back on failure");

        var res = http::Response { .. };
        let ok_res, consumed_res = server::parse_http1_wire_response(
            "HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\nshort",
            res,
        );
        sub.assert_false(ok_res, "Truncated Content-Length response rejected");
        sub.assert_eq(consumed_res, 0, "Consumed bytes 0 on failed response parse");
        sub.assert_eq(res.status_code, 0, "out_res.status_code rolled back on failure");
        sub.assert_eq(res.headers.entries.len, 0, "out_res.headers rolled back on failure");
    };

    t.run("3. SERVER2_C01, C02, C06..C08: SNI IP literal rejection, H1.0 TE stream guard, Cork 204 & SoA active slot") { sub =>
        var srv = server::HttpServer { .. };
        sub.assert_false(server::add_server_name(srv, "127.0.0.1", "CERT", "KEY"), "IPv4 literal rejected in add_server_name (RFC 6066 §3)");
        sub.assert_false(server::add_server_name(srv, "*", "CERT", "KEY"), "Bare wildcard '*' rejected in add_server_name (RFC 6125 §6.4.3)");
        sub.assert_false(server::sni_pattern_matches("127.0.0.1", "127.0.0.1"), "IPv4 literal rejected in sni_pattern_matches");
        sub.assert_true(server::add_server_name(srv, "*.example.com.", "CERT", "KEY"), "Trailing-dot wildcard DNS pattern accepted");
        let _, ok_ip_resolve = server::resolve_sni_credentials(srv, "127.0.0.1");
        sub.assert_false(ok_ip_resolve, "IPv4 literal rejected in resolve_sni_credentials");

        var req_h10 = http::Request { .. };
        var consumer = server::HttpStreamConsumer { .. };
        let ok_h10, _ = server::begin_http_stream_request(
            "POST /upload HTTP/1.0\r\nTransfer-Encoding: chunked\r\n\r\n",
            req_h10,
            consumer,
        );
        sub.assert_false(ok_h10, "Transfer-Encoding on HTTP/1.0 stream request rejected (RFC 9112 §6.1)");
        sub.assert_eq(consumer.header_end_idx, 0, "consumer.header_end_idx rolled back on failure");
        sub.assert_eq(req_h10.method.len, 0, "req_h10.method rolled back on failure");

        var req_chk = http::Request { .. };
        var consumer2 = server::HttpStreamConsumer { .. };
        let ok_chk, _ = server::begin_http_stream_request(
            "POST /upload HTTP/1.1\r\nHost: example.com\r\nTransfer-Encoding: chunked\r\n\r\n",
            req_chk,
            consumer2,
        );
        sub.assert_true(ok_chk, "Valid HTTP/1.1 chunked stream request started");
        let _, _, ok_bad_frame = server::feed_http_stream_chunk(consumer2, "ZZZ\r\n", srv_reg3_on_stream_chunk);
        sub.assert_false(ok_bad_frame, "Malformed chunk size rejected");
        let _, _, ok_after_err = server::feed_http_stream_chunk(consumer2, "0\r\n\r\n", srv_reg3_on_stream_chunk);
        sub.assert_false(ok_after_err, "Consumer stays in terminal error state after malformed chunk");

        var sc = server::new_server_cork(1);
        var res_204 = http::Response { status_code: 204, .. };
        sub.assert_eq(server::cork_begin_http1_chunked(sc, res_204, "goose"), -1, "cork_begin_http1_chunked rejects 204 No Content (RFC 9112 §6.1)");

        var table = server::SoAConnTable { .. };
        server::soa_table_set_peer_ip(table, 0, "10.0.0.1");
        sub.assert_bytes_eq(server::soa_table_get_peer_ip(table, 0), "", "Inactive SoA slot rejects peer IP mutation");
        server::soa_table_touch(table, 0, 42);
        sub.assert_eq(table.timeout_ticks[0], server::SOA_INVALID_TICK, "Inactive SoA slot rejects timeout tick touch");
    };
}

fn main() {
    var runner = lit::new_runner("Server Router, Pipeline, and Fault Tolerance Verification Suite", lit::Verbosity.Verbose);

    lit::run_case(runner, "1. Zero-Allocation Parameter Extraction & Byte Spans", test_zero_alloc_params);
    lit::run_case(runner, "2. Radix Trie: Static Precedence, Catch-All & Method Isolation", test_radix_trie_routing);
    lit::run_case(runner, "3. Tako v2 6-Mechanism Server Pool", test_tako_v2_pool_mechanisms);
    lit::run_case(runner, "4. Unified Defense-in-Depth Pipeline Integration", test_unified_server_pipeline);
    lit::run_case(runner, "5. Standalone HTTP Server Wire Handling & Protocol Detection", test_standalone_http_server);
    lit::run_case(runner, "6. HttpServer.serve Connection Capping", test_serve_connection_capping);
    lit::run_case(runner, "7. HttpServer.serve_reactor Connection Capping", test_serve_reactor_connection_capping);
    lit::run_case(runner, "8. TopicTree Live Broadcast & Batch Drainage", test_topic_tree_live_broadcast_and_batch_drain);
    lit::run_case(runner, "9. HTTP/1.1 Pipelining", test_server_http1_pipelining);
    lit::run_case(runner, "10. Empty Line & Whitespace Invariants", test_server_empty_line_and_whitespace_invariants);
    lit::run_case(runner, "11. Target & Host Invariants", test_server_target_and_host_invariants);
    lit::run_case(runner, "12. NGINX Reverse Proxy Harmony (X-Real-IP, Connection Close, SSE)", test_nginx_harmony_invariants);
    lit::run_case(runner, "13. Server Audit Regressions", test_server_audit_regressions);
    lit::run_case(runner, "14. RouteHandler Hook, Context Accessors & Response Builders", test_route_handler_stage_and_ergonomics);
    lit::run_case(runner, "15. Router path capacity truncation smuggling (server/router.goose)", test_router_path_capacity_truncation_smuggling);
    lit::run_case(runner, "16. EdgeFilter", test_srv_reg1_s1);
    lit::run_case(runner, "17. H2ServerSession", test_srv_reg1_s2);
    lit::run_case(runner, "18. HEAD Dedup", test_srv_reg1_s3a);
    lit::run_case(runner, "19. CORS/CSRF", test_srv_reg1_s3b);
    lit::run_case(runner, "20. RadixRouter", test_srv_reg1_s4);
    lit::run_case(runner, "21. Server Wire", test_srv_reg1_s5a);
    lit::run_case(runner, "22. Pipelined 400 Dedup", test_srv_reg1_s5b);
    lit::run_case(runner, "23. Round 2 Part 1a", srv_reg1_run_round2_part1a);
    lit::run_case(runner, "24. Round 2 Part 1b", srv_reg1_run_round2_part1b);
    lit::run_case(runner, "25. Round 2 Part 2", srv_reg1_run_round2_part2);
    lit::run_case(runner, "26. Round 2 Part 3", srv_reg1_run_round2_part3);
    lit::run_case(runner, "27. Cache & EdgeFilter", test_srv_reg2_r1_cache_and_edge_filter);
    lit::run_case(runner, "28. H2 Multiplexer", test_srv_reg2_r2_h2_multiplexer);
    lit::run_case(runner, "29. Pipeline & Router", test_srv_reg2_r3_pipeline_and_router);
    lit::run_case(runner, "30. Server Wire", test_srv_reg2_r4_server_wire);
    lit::run_case(runner, "31. Cache & EdgeFilter", test_srv_reg3_r1_cache_and_edge_filter);
    lit::run_case(runner, "32. Pipeline & Pool", test_srv_reg3_r2_pipeline_and_pool);
    lit::run_case(runner, "33. H2 & Router", test_srv_reg3_r3_h2_and_router);
    lit::run_case(runner, "34. Server Wire", test_srv_reg3_r4_server_wire);
    lit::run_case(runner, "35. goose2rfc Server Audit Regressions", test_goose2rfc_server_audit_regressions);

    let ok = lit::finish(runner);
    assert(ok);
}
