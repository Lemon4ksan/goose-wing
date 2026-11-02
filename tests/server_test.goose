// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Consolidated Verification Suite: Server Router, Pipeline, and Fault Tolerance Verification Suite
//
// RUN: goose build -o %t.exe %s
// RUN: %t.exe
import std;
import core from "..";
import wing from "..";
import lit from "github.com/Lemon4ksan/goose-lit@v0.1.0";

// --- Component: server_router ---
// Tests for radix tree routing, buffer pools, and server execution pipeline.

// ----------------------------------------------------------------------------
// 1. Zero-Allocation Parameter Extraction & Byte Spans
// ----------------------------------------------------------------------------
fn test_zero_alloc_params(t: lit::T&) {
    t.run("Span Slicing Without Heap Allocations") { sub =>
        var params = wing::ZeroAllocParams { .. };
        let req_path = "/users/alice99/settings";
        let template = "/users/{username}/settings";

        // Record span for username: val is "alice99" at [7..14], key is "{username}" at [7..17]
        sub.assert_true(wing::add_param(params, 8, 16, 7, 14), "param added to span storage");
        sub.assert_eq(params.len, 1, "params count is 1");

        let val = wing::param_val(params, 0, req_path);
        sub.assert_eq(val, "alice99", "zero-copy value extraction");

        let key = wing::param_key(params, 0, template);
        sub.assert_eq(key, "username", "zero-copy key template extraction");

        // Clear params in place
        wing::clear(params);
        sub.assert_eq(params.len, 0, "params cleared");
    };
}

// ----------------------------------------------------------------------------
// 2. Radix Trie: Static Precedence, Catch-All & Method Isolation
// ----------------------------------------------------------------------------
fn test_radix_trie_routing(t: lit::T&) {
    t.run("Static Route Priority Over Parameter") { sub =>
        var tree = wing::new_radix_tree();
        wing::insert_route(tree, "/users/{id}", 101);
        wing::insert_route(tree, "/users/profile", 202);

        var params = wing::ZeroAllocParams { .. };

        // Exact static route must take precedence
        let match_profile = wing::match_path(tree, "/users/profile", params);
        let ok_profile = match match_profile {
            Found f => f.handler_id == 202,
            _ => false,
        };
        sub.assert_true(ok_profile, "static route /users/profile matches handler 202 (not /users/{id})");

        // Dynamic route matches
        let match_dyn = wing::match_path(tree, "/users/42", params);
        let ok_dyn = match match_dyn {
            Found f => f.handler_id == 101,
            _ => false,
        };
        sub.assert_true(ok_dyn, "dynamic route /users/42 matches handler 101");
        sub.assert_eq(wing::param_val(params, 0, "/users/42"), "42", "extracted id param '42'");
    };

    t.run("Catch-All Route Matching") { sub =>
        var tree = wing::new_radix_tree();
        wing::insert_route(tree, "/assets/{*filepath}", 303);

        var params = wing::ZeroAllocParams { .. };
        let match_res = wing::match_path(tree, "/assets/images/icons/logo.png", params);
        let ok = match match_res {
            Found f => f.handler_id == 303,
            _ => false,
        };
        sub.assert_true(ok, "catchall matches multi-segment remainder");
        sub.assert_eq(wing::param_val(params, 0, "/assets/images/icons/logo.png"), "images/icons/logo.png", "captured filepath");
    };

    t.run("matchit Issue #83 Monotonic Suffix Preservation") { sub =>
        // Order A: Insert {id}.json first, then {id}/comments.json
        var tree_a = wing::new_radix_tree();
        wing::insert_route(tree_a, "/posts/{id}.json", 1);
        wing::insert_route(tree_a, "/posts/{id}/comments.json", 2);

        var p_a = wing::ZeroAllocParams { .. };
        let m1_a = wing::match_path(tree_a, "/posts/999.json", p_a);
        let ok1_a = match m1_a {
            Found f => f.handler_id == 1,
            _ => false,
        };
        sub.assert_true(ok1_a, "Order A: /posts/999.json matches handler 1");

        let m2_a = wing::match_path(tree_a, "/posts/999/comments.json", p_a);
        let ok2_a = match m2_a {
            Found f => f.handler_id == 2,
            _ => false,
        };
        sub.assert_true(ok2_a, "Order A: /posts/999/comments.json matches handler 2");

        // Order B: Insert {id}/comments.json first, then {id}.json
        // Naive radix trees fail this because splitting overwrites suffix: true with suffix: false!
        var tree_b = wing::new_radix_tree();
        wing::insert_route(tree_b, "/posts/{id}/comments.json", 2);
        wing::insert_route(tree_b, "/posts/{id}.json", 1);

        var p_b = wing::ZeroAllocParams { .. };
        let m1_b = wing::match_path(tree_b, "/posts/999.json", p_b);
        let ok1_b = match m1_b {
            Found f => f.handler_id == 1,
            _ => false,
        };
        sub.assert_true(ok1_b, "Order B: /posts/999.json matches handler 1 (Issue #83 fixed!)");

        let m2_b = wing::match_path(tree_b, "/posts/999/comments.json", p_b);
        let ok2_b = match m2_b {
            Found f => f.handler_id == 2,
            _ => false,
        };
        sub.assert_true(ok2_b, "Order B: /posts/999/comments.json matches handler 2");
    };

    t.run("Multi-Method Isolation & 405 Method Not Allowed") { sub =>
        var router = wing::new_radix_router();
        wing::add_route(router, "GET", "/api/items", 10);
        wing::add_route(router, "POST", "/api/items", 20);

        var params = wing::ZeroAllocParams { .. };

        // GET matches
        let m_get = wing::match_route(router, "GET", "/api/items", params);
        let ok_get = match m_get {
            Found f => f.handler_id == 10,
            _ => false,
        };
        sub.assert_true(ok_get, "GET /api/items found");

        // POST matches
        let m_post = wing::match_route(router, "POST", "/api/items", params);
        let ok_post = match m_post {
            Found f => f.handler_id == 20,
            _ => false,
        };
        sub.assert_true(ok_post, "POST /api/items found");

        // PUT is not allowed -> returns 405 with Allow: GET, POST, HEAD
        let m_put = wing::match_route(router, "PUT", "/api/items", params);
        let ok_put = match m_put {
            MethodNotAllowed mna => find(mna.allow_header[..], "GET") >= 0 && find(mna.allow_header[..], "POST") >= 0 && find(mna.allow_header[..], "HEAD") >= 0,
            _ => false,
        };
        sub.assert_true(ok_put, "PUT /api/items returns MethodNotAllowed with Allow header containing GET, POST, and HEAD");

        // RFC 9110 §9.3.2: HEAD automatically routes to GET handler when GET is registered
        let m_head = wing::match_route(router, "HEAD", "/api/items", params);
        let ok_head = match m_head {
            Found f => f.handler_id == 10,
            _ => false,
        };
        sub.assert_true(ok_head, "HEAD /api/items automatically matches GET route handler 10");

        // OPTIONS capability probe includes OPTIONS in Allow header
        let m_opt = wing::match_route(router, "OPTIONS", "/api/items", params);
        let ok_opt_allow = match m_opt {
            MethodNotAllowed mna => find(mna.allow_header[..], "OPTIONS") >= 0,
            _ => false,
        };
        sub.assert_true(ok_opt_allow, "OPTIONS capability probe contains OPTIONS in Allow header");

        // Route path canonicalization: registering with trailing slash matches without trailing slash
        wing::add_route(router, "GET", "/trailing/slash/", 99);
        let m_ts1 = wing::match_route(router, "GET", "/trailing/slash", params);
        let ok_ts1 = match m_ts1 {
            Found f => f.handler_id == 99,
            _ => false,
        };
        sub.assert_true(ok_ts1, "GET /trailing/slash matches route registered as /trailing/slash/");

        let m_ts2 = wing::match_route(router, "GET", "/trailing/slash/", params);
        let ok_ts2 = match m_ts2 {
            Found f => f.handler_id == 99,
            _ => false,
        };
        sub.assert_true(ok_ts2, "GET /trailing/slash/ matches route registered as /trailing/slash/");

        // Completely unknown route returns NotFound (404)
        let m_none = wing::match_route(router, "GET", "/unknown/path", params);
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
        var pool = internal::HeaderMapPool { .. };
        let s0 = internal::acquire_header_map(pool);
        let s1 = internal::acquire_header_map(pool);

        sub.assert_true(s0 >= 0 && s1 >= 0 && s0 != s1, "acquired distinct header map slots");
        sub.assert_true(pool.pool[s0].in_use, "slot marked in_use");

        internal::release_header_map(pool, s0);
        sub.assert_false(pool.pool[s0].in_use, "slot released and in_use cleared");

        // Reacquire should reuse slot s0
        let s2 = internal::acquire_header_map(pool);
        sub.assert_eq(s2, s0, "reacquired released slot");
    };

    t.run("ExtensionsPool Sanitization (Zero State Leakage)") { sub =>
        var pool = internal::ExtensionsPool { .. };
        let idx = internal::acquire_extensions(pool);
        sub.assert_true(idx >= 0, "acquired extensions slot");

        // Populate slot with sensitive request state
        pool.slots[idx].peer_ip.append("192.168.1.50");
        pool.slots[idx].matched_route.append("/admin/secrets");
        wing::add_param(pool.slots[idx].params, 1, 2, 3, 4);
        pool.slots[idx].populated_entries = 0xFF;

        // Release slot: must wipe all fields
        internal::release_extensions(pool, idx);
        sub.assert_false(pool.slots[idx].in_use, "slot released");
        sub.assert_eq(pool.slots[idx].peer_ip.len, 0, "peer_ip sanitized");
        sub.assert_eq(pool.slots[idx].matched_route.len, 0, "matched_route sanitized");
        sub.assert_eq(pool.slots[idx].params.len, 0, "params sanitized");
        sub.assert_eq(pool.slots[idx].populated_entries, 0, "populated_entries sanitized");
    };

    t.run("SyncHeadRelease & ConnectionTimer Slowloris Sweep") { sub =>
        var shr = internal::new_sync_head_release();
        sub.assert_false(shr.head_buffer_released, "starts unreleased");
        internal::mark_head_released(shr, 4096);
        sub.assert_true(shr.head_buffer_released, "marked released");
        sub.assert_eq(shr.bytes_consumed, 4096, "consumed 4096 bytes");

        // ConnectionTimer: 10s deadline
        let start_ns: u64 = 1000000000;
        var timer = internal::new_connection_timer(10000000000, start_ns);

        // Within deadline
        sub.assert_true(internal::check_connection_tick(timer, start_ns + 5000000000), "tick ok at 5s");

        // Beyond deadline: Slowloris sweep terminates connection
        sub.assert_false(internal::check_connection_tick(timer, start_ns + 11000000000), "tick fails after deadline exceeded");
    };
}

// ----------------------------------------------------------------------------
// 4. Unified Defense-in-Depth Pipeline Integration
// ----------------------------------------------------------------------------
fn test_unified_server_pipeline(t: lit::T&) {
    t.run("End-to-End Handled Request Lifecycle") { sub =>
        let quota = wing::new_gcra_quota(100, core::secs(1), 10);
        var cfg = wing::new_server_pipeline_config("example.com", quota);
        wing::add_route(cfg.router, "GET", "/api/v1/users/{id}", 42);

        var conn_timer = internal::new_connection_timer(30000000000, 1000000000);
        var req = wing::new_request("GET", "/api/v1/users/777");
        req.headers.push(wing::make_header("Host", "example.com"));
        req.headers.push(wing::make_header("Sec-Fetch-Site", "same-origin"));
        req.headers.push(wing::make_header("Sec-Fetch-Mode", "cors"));
        req.headers.push(wing::make_header("Sec-Fetch-Dest", "empty"));

        var res = wing::Response { .. };
        var fut = internal::new_inline_handler_future(0);

        let outcome = wing::execute_pipeline(cfg, conn_timer, "127.0.0.1", req, 1000000000, res, fut);
        let ok_handled = match outcome {
            Handled => true,
            _ => false,
        };
        sub.assert_true(ok_handled, "pipeline returned Handled");
        sub.assert_eq(res.status_code, 200, "status code 200 OK");
        sub.assert_eq(fut.vtable_tag, 42, "handler 42 invoked");
    };

    t.run("Pipeline Rate Limiting Defense (Stage 1)") { sub =>
        let quota = wing::new_gcra_quota(1, core::secs(1), 0); // strictly 1 req/s
        var cfg = wing::new_server_pipeline_config("example.com", quota);
        wing::add_route(cfg.router, "GET", "/health", 1);

        var timer = internal::new_connection_timer(30000000000, 1000000000);
        var req = wing::new_request("GET", "/health");
        req.headers.push(wing::make_header("Sec-Fetch-Site", "same-origin"));

        var res1 = wing::Response { .. };
        var fut1 = internal::new_inline_handler_future(0);
        let out1 = wing::execute_pipeline(cfg, timer, "10.0.0.1", req, 1000000000, res1, fut1);
        sub.assert_true(out1 == wing::PipelineOutcome.Handled, "first request handled");

        // Second request at same nanosecond -> Rate Limited
        var res2 = wing::Response { .. };
        var fut2 = internal::new_inline_handler_future(0);
        let out2 = wing::execute_pipeline(cfg, timer, "10.0.0.1", req, 1000000000, res2, fut2);
        sub.assert_true(out2 == wing::PipelineOutcome.RateLimited, "second request rate limited");
        sub.assert_eq(res2.status_code, 429, "status code 429 Too Many Requests");
    };

    t.run("Pipeline CSRF Defense (Stage 2)") { sub =>
        let quota = wing::new_gcra_quota(100, core::secs(1), 10);
        var cfg = wing::new_server_pipeline_config("example.com", quota);
        wing::add_route(cfg.router, "POST", "/api/transfer", 99);

        var timer = internal::new_connection_timer(30000000000, 1000000000);
        var evil_req = wing::new_request("POST", "/api/transfer");
        evil_req.headers.push(wing::make_header("Sec-Fetch-Site", "cross-site"));
        evil_req.headers.push(wing::make_header("Sec-Fetch-Mode", "cors"));

        var res = wing::Response { .. };
        var fut = internal::new_inline_handler_future(0);
        let out = wing::execute_pipeline(cfg, timer, "192.168.1.1", evil_req, 1000000000, res, fut);
        sub.assert_true(out == wing::PipelineOutcome.CsrfRejected, "cross-site mutation rejected by CSRF guard");
        sub.assert_eq(res.status_code, 403, "status code 403 Forbidden");
    };

    t.run("Pipeline Routing & 405 Method Not Allowed (Stage 3)") { sub =>
        let quota = wing::new_gcra_quota(100, core::secs(1), 10);
        var cfg = wing::new_server_pipeline_config("example.com", quota);
        wing::add_route(cfg.router, "GET", "/api/data", 10);

        var timer = internal::new_connection_timer(30000000000, 1000000000);

        // POST to GET-only route -> 405 Method Not Allowed
        var req_post = wing::new_request("POST", "/api/data");
        req_post.headers.push(wing::make_header("Sec-Fetch-Site", "same-origin"));

        var res = wing::Response { .. };
        var fut = internal::new_inline_handler_future(0);
        let out = wing::execute_pipeline(cfg, timer, "127.0.0.1", req_post, 1000000000, res, fut);
        sub.assert_true(out == wing::PipelineOutcome.MethodNotAllowed, "method not allowed triggered");
        sub.assert_eq(res.status_code, 405, "status code 405");

        sub.assert_true(res.has_header("Allow"), "Allow header returned");
        sub.assert_contains(res.header("Allow"), "GET", "Allow header indicates GET");
        sub.assert_contains(res.header("Allow"), "HEAD", "Allow header indicates HEAD when GET is supported");

        // Automatic HEAD routing in pipeline: executes GET handler and suppresses body (RFC 9110 §9.3.2)
        var req_head = wing::new_request("HEAD", "/api/data");
        req_head.headers.push(wing::make_header("Sec-Fetch-Site", "same-origin"));
        var res_head = wing::Response { .. };
        res_head.body.append("Should be suppressed");
        var fut_head = internal::new_inline_handler_future(0);
        let out_head = wing::execute_pipeline(cfg, timer, "127.0.0.1", req_head, 1000000000, res_head, fut_head);
        sub.assert_true(out_head == wing::PipelineOutcome.Handled, "HEAD request handled by GET route in pipeline");
        sub.assert_eq(res_head.status_code, 200, "HEAD status code 200");
        sub.assert_eq(res_head.body.len, 0, "HEAD response body is completely suppressed (len == 0)");
    };

    t.run("Pipeline Expect Header Validation (Stage 0.5) (RFC 9110 Section 10.1.1)") { sub =>
        let quota = wing::new_gcra_quota(100, core::secs(1), 10);
        var cfg = wing::new_server_pipeline_config("example.com", quota);
        wing::add_route(cfg.router, "POST", "/upload", 42);

        var timer = internal::new_connection_timer(30000000000, 1000000000);

        // 1. Valid Expect: 100-continue proceeds to pipeline routing
        var req_100 = wing::new_request("POST", "/upload");
        req_100.headers.push(wing::make_header("Sec-Fetch-Site", "same-origin"));
        req_100.headers.push(wing::make_header("Expect", "100-continue"));

        var res1 = wing::Response { .. };
        var fut1 = internal::new_inline_handler_future(0);
        let out1 = wing::execute_pipeline(cfg, timer, "127.0.0.1", req_100, 1000000000, res1, fut1);
        sub.assert_true(out1 == wing::PipelineOutcome.Handled, "Expect: 100-continue on valid route handled");

        // 2. Unknown Expect: foo-bar -> 417 Expectation Failed
        var req_unknown = wing::new_request("POST", "/upload");
        req_unknown.headers.push(wing::make_header("Sec-Fetch-Site", "same-origin"));
        req_unknown.headers.push(wing::make_header("Expect", "unknown-feature-flag"));

        var res2 = wing::Response { .. };
        var fut2 = internal::new_inline_handler_future(0);
        let out2 = wing::execute_pipeline(cfg, timer, "127.0.0.1", req_unknown, 1000000000, res2, fut2);
        sub.assert_true(out2 == wing::PipelineOutcome.ExpectationFailed, "unknown Expect rejected with ExpectationFailed");
        sub.assert_eq(res2.status_code, 417, "RFC 9110 status code 417 Expectation Failed");
    };

    t.run("Pipeline Bitmask PSO Fast-Path Probe & Egress Headers") { sub =>
        let quota = wing::new_gcra_quota(1, core::secs(1), 0); // strictly 1 req/s
        var cfg = wing::new_server_pipeline_config("example.com", quota);

        // Fast-path bypass route (pso_mask = 0)
        wing::add_route_pso(cfg.router, "GET", "/healthz", 1001, 0);

        // Route with security egress headers
        wing::add_route_pso(cfg.router, "GET", "/secure", 1002, wing::STAGE_EGRESS_SECURITY_HEADERS);

        var timer = internal::new_connection_timer(30000000000, 1000000000);

        // Request 1 to /healthz: even with invalid Expect header, passes via fast-path bypass
        var req1 = wing::new_request("GET", "/healthz");
        req1.headers.push(wing::make_header("Expect", "invalid-expectation"));
        var res1 = wing::Response { .. };
        var fut1 = internal::new_inline_handler_future(0);
        let out1 = wing::execute_pipeline(cfg, timer, "10.0.0.1", req1, 1000000000, res1, fut1);
        sub.assert_true(out1 == wing::PipelineOutcome.Handled, "fast-path /healthz handled");
        sub.assert_eq(res1.status_code, 200, "status code 200");
        sub.assert_bytes_eq(res1.body[..], "Hello, World!", "fast path body dispatched");

        // Request 2 to /healthz at same nanosecond: not rate limited because rate limiter is bypassed
        var res2 = wing::Response { .. };
        var fut2 = internal::new_inline_handler_future(0);
        let out2 = wing::execute_pipeline(cfg, timer, "10.0.0.1", req1, 1000000000, res2, fut2);
        sub.assert_true(out2 == wing::PipelineOutcome.Handled, "second /healthz handled without rate limiting");

        // Request to /secure: gets egress security headers
        var req_sec = wing::new_request("GET", "/secure");
        req_sec.headers.push(wing::make_header("Host", "example.com"));
        var res_sec = wing::Response { .. };
        var fut_sec = internal::new_inline_handler_future(0);
        let out_sec = wing::execute_pipeline(cfg, timer, "10.0.0.1", req_sec, 1000000000, res_sec, fut_sec);
        sub.assert_true(out_sec == wing::PipelineOutcome.Handled, "secure route handled");
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
        var req = wing::new_request("", "");
        let ok_parse, consumed = wing::parse_http1_wire_request(wire_req, req);

        sub.assert_true(ok_parse, "Parsed raw HTTP/1.1 wire request");
        sub.assert_eq(consumed, wire_req.len as i64, "Consumed all wire bytes including body");
        sub.assert_bytes_eq(req.method[..], "POST", "Method is POST");
        sub.assert_bytes_eq(req.url[..], "/api/echo", "Path is /api/echo");
        sub.assert_bytes_eq(req.body[..], "Hello World", "Body payload extracted");

        var resp = wing::Response { .. };
        resp.status_code = 200;
        wing::set_header(resp, "content-type", "application/json");
        resp.body.append("{\"status\":\"ok\"}");

        var out_wire: u8[>..] = [];
        wing::serialize_http1_response(resp, "goose-wing-server", out_wire);

        let out_str = out_wire[..];
        sub.assert_true(out_wire.len > 0, "Response wire serialized");
        sub.assert_true(out_str.len >= 15 && out_str[..15] == "HTTP/1.1 200 OK", "Status line HTTP/1.1 200 OK");
        sub.assert_contains(out_str, "Server: goose-wing-server\r\n", "Server header included");
        sub.assert_contains(out_str, "Content-Length: 15\r\n", "Content-Length matches body");
        sub.assert_contains(out_str, "Connection: keep-alive\r\n", "Connection: keep-alive included");
        sub.assert_contains(out_str, "{\"status\":\"ok\"}", "Response body included");
    };

    t.run("2. End-to-End handle_connection_wire Pipeline Dispatch") { sub =>
        var server = wing::new_http_server("127.0.0.1", 8080);
        wing::add_get_route(server, "/ping", 100);

        let client_req = "GET /ping HTTP/1.1\r\nHost: 127.0.0.1\r\nSec-Fetch-Site: same-origin\r\n\r\n";
        var client_resp_wire: u8[>..] = [];
        let outcome, ok_handled = wing::handle_connection_wire(server, "127.0.0.1", client_req, 1000000000, client_resp_wire);

        sub.assert_true(ok_handled, "Wire connection handled");
        sub.assert_eq(outcome, wing::PipelineOutcome.Handled, "Pipeline handled route");
        sub.assert_eq(server.requests_processed, 1, "1 request processed");
        sub.assert_contains(client_resp_wire[..], "HTTP/1.1 200 OK", "Response is 200 OK");

        // 404 Route Not Found
        let req_404 = "GET /missing HTTP/1.1\r\nHost: 127.0.0.1\r\nSec-Fetch-Site: same-origin\r\n\r\n";
        var resp_404_wire: u8[>..] = [];
        let outcome_404, _ = wing::handle_connection_wire(server, "127.0.0.1", req_404, 1000000000, resp_404_wire);
        sub.assert_eq(outcome_404, wing::PipelineOutcome.RouteNotFound, "Route not found");
        sub.assert_contains(resp_404_wire[..], "HTTP/1.1 404 Not Found", "Response is 404 Not Found");
    };

    t.run("3. HTTP/2 Connection Preface Detection & Handshake") { sub =>
        var server = wing::new_http_server("127.0.0.1", 8443);

        // Client sends RFC 9113 24-byte preface: "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
        var wire_h2: u8[>..] = [];
        wire_h2.append(internal::H2_CLIENT_PREFACE[..]);

        var server_h2_resp: u8[>..] = [];
        let outcome_h2, ok_h2 = wing::handle_connection_wire(server, "127.0.0.1", wire_h2[..], 1000000000, server_h2_resp);

        sub.assert_true(ok_h2, "HTTP/2 preface detected");
        sub.assert_eq(outcome_h2, wing::PipelineOutcome.Handled, "Handled");
        sub.assert_eq(server_h2_resp.len, 33, "Server responded with 33-byte HTTP/2 SETTINGS frame");
        sub.assert_eq(server_h2_resp[3], internal::FRAME_SETTINGS, "Frame type is SETTINGS (0x04)");
    };

    t.run("4. Incremental PipeBuffer Sans-IO Stream Parsing & Monotonicity") { sub =>
        var server = wing::new_http_server("127.0.0.1", 8080);
        wing::add_get_route(server, "/greet", 1);

        var pipe = core::new_pipe_buffer();

        // Packet 1: Incomplete request (headers truncated before final CRLF)
        let part1 = "GET /greet HTTP/1.1\r\nHost: 127.0.0.1\r\n";
        core::write(pipe, part1);

        var out_wire1: u8[>..] = [];
        let n1, ok1 = wing::handle_connection_pipe(server, "127.0.0.1", pipe, 1000000000, out_wire1);

        sub.assert_true(ok1, "handle_connection_pipe succeeded on incomplete chunk");
        sub.assert_eq(n1, 0, "No complete request processed yet");
        sub.assert_eq(pipe.consumed, 0, "Pipe consumed is 0");
        sub.assert_eq(pipe.examined, part1.len, "Pipe examined advanced to end of chunk");
        sub.assert_eq(out_wire1.len, 0, "No output generated yet");

        // Packet 2: Remainder of request headers arriving
        let part2 = "Sec-Fetch-Site: same-origin\r\n\r\n";
        core::write(pipe, part2);

        var out_wire2: u8[>..] = [];
        let n2, ok2 = wing::handle_connection_pipe(server, "127.0.0.1", pipe, 1000000000, out_wire2);

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
        let n3, ok3 = wing::handle_connection_pipe(server, "127.0.0.1", pipe, 1000000000, out_wire3);

        sub.assert_true(ok3, "handle_connection_pipe handled pipelined requests");
        sub.assert_eq(n3, 2, "2 pipelined requests processed");
        sub.assert_eq(pipe.readable_len(), 0, "Pipe drained completely");

        // Packet 4: Zero-Heap PipeBuffer + CorkBuffer Aggregation
        let req_c = "GET /greet HTTP/1.1\r\nHost: 127.0.0.1\r\nSec-Fetch-Site: same-origin\r\n\r\n";
        core::write(pipe, req_c);
        var cork = core::new_cork_buffer();
        let n4, ok4 = wing::handle_connection_pipe(server, "127.0.0.1", pipe, 1000000000, cork);
        sub.assert_true(ok4, "handle_connection_pipe works with CorkBuffer");
        sub.assert_eq(n4, 1, "1 request processed into cork");
        sub.assert_gt(cork.cork_pending(), 0, "Cork buffer contains bytes");
        sub.assert_contains(cork.cork_as_slice(), "HTTP/1.1 200 OK", "Cork contains 200 OK");
        core::cork_consume(cork, cork.cork_pending());
        sub.assert_eq(cork.cork_pending(), 0, "Cork fully consumed");
    };

    t.run("5. HTTP Request Smuggling Defenses (RFC 9112 Section 6.1 & 6.3)") { sub =>
        var server = wing::new_http_server("127.0.0.1", 8080);
        wing::add_get_route(server, "/safe", 1);
        wing::add_post_route(server, "/safe", 2);

        // 5.1 Leading whitespace before method (RFC 9112 §3.1)
        var out1: u8[>..] = [];
        let _, ok1 = wing::handle_connection_wire(server, "127.0.0.1", " GET /safe HTTP/1.1\r\n\r\n", 1000000000, out1);
        sub.assert_false(ok1, "Leading space before method rejected");
        sub.assert_contains(out1[..], "400 Bad Request", "Returns 400 Bad Request");

        // 5.2 Single leading empty line (RFC 9112 §2.2) is allowed for robustness
        var out2: u8[>..] = [];
        let _, ok2 = wing::handle_connection_wire(server, "127.0.0.1", "\r\nGET /safe HTTP/1.1\r\nHost: localhost\r\nSec-Fetch-Site: same-origin\r\n\r\n", 1000000000, out2);
        sub.assert_true(ok2, "Single leading CRLF allowed per RFC 9112 §2.2");

        // 5.3 Multiple leading empty lines (RFC 9112 §2.2) MUST be rejected
        var out3: u8[>..] = [];
        let _, ok3 = wing::handle_connection_wire(server, "127.0.0.1", "\r\n\r\nGET /safe HTTP/1.1\r\nHost: localhost\r\n\r\n", 1000000000, out3);
        sub.assert_false(ok3, "Multiple leading CRLF rejected");

        // 5.4 Whitespace before colon in header (RFC 9112 §5.1, CVE-2019-16276)
        var out4: u8[>..] = [];
        let _, ok4 = wing::handle_connection_wire(server, "127.0.0.1", "GET /safe HTTP/1.1\r\nHost : localhost\r\n\r\n", 1000000000, out4);
        sub.assert_false(ok4, "Space before colon rejected");

        // 5.5 Control character in URL path (RFC 9110 §4.1, CVE-2022-22970)
        var out5: u8[>..] = [];
        let bad_url: u8[28] = [
            'G' as u8, 'E' as u8, 'T' as u8, ' ' as u8,
            '/' as u8, 's' as u8, 'a' as u8, 'f' as u8, 'e' as u8, 0x00, // Embedded NUL CTL!
            ' ' as u8, 'H' as u8, 'T' as u8, 'T' as u8, 'P' as u8, '/' as u8, '1' as u8, '.' as u8, '1' as u8,
            '\r' as u8, '\n' as u8, '\r' as u8, '\n' as u8, 0, 0, 0, 0, 0,
        ];
        let _, ok5 = wing::handle_connection_wire(server, "127.0.0.1", bad_url[..23], 1000000000, out5);
        sub.assert_false(ok5, "CTL in URL path rejected");

        // 5.6 Non-digit in Content-Length (RFC 9110 §8.6, Go #53188)
        var out6: u8[>..] = [];
        let _, ok6 = wing::handle_connection_wire(server, "127.0.0.1", "POST /safe HTTP/1.1\r\nContent-Length: +10\r\n\r\n0123456789", 1000000000, out6);
        sub.assert_false(ok6, "Signed +10 Content-Length rejected");

        // 5.7 Conflict: both Transfer-Encoding and Content-Length present (RFC 9112 §6.1)
        var out7: u8[>..] = [];
        let _, ok7 = wing::handle_connection_wire(server, "127.0.0.1", "POST /safe HTTP/1.1\r\nContent-Length: 5\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n", 1000000000, out7);
        sub.assert_false(ok7, "TE and CL conflict rejected");

        // 5.8 Conflicting duplicate Content-Length headers (RFC 9112 §6.3)
        var out8: u8[>..] = [];
        let _, ok8 = wing::handle_connection_wire(server, "127.0.0.1", "POST /safe HTTP/1.1\r\nContent-Length: 5\r\nContent-Length: 6\r\n\r\nhello", 1000000000, out8);
        sub.assert_false(ok8, "Conflicting duplicate Content-Length rejected");
    };
}

// ----------------------------------------------------------------------------
// Suite Runner
// ----------------------------------------------------------------------------

// --- Component: server_fault_tolerance ---
// Fault Tolerance & Concurrency Verification Suite.
// Verifies:
// 1. Synchronous HttpServer.serve connection capping and clean loop exit.
// 2. Share-nothing HttpServer.serve_reactor connection capping, multiplexing, and teardown.
// 3. TopicTree multi-subscriber live WebSocket broadcast & batched palette drainage.

struct ServerSpawnConfig {
    listener_fd: i64 = -1,
    max_conns:   i64 = 0,
}

thread_fn serve_sync_worker() {
    let cfg = core::recv_msg<ServerSpawnConfig>();
    var app = wing::new_http_server("127.0.0.1", 0);
    wing::add_get_route(app, "/ping", 100);
    let served = wing::serve(app, cfg.listener_fd, cfg.max_conns);
    core::send_msg(served);
}

thread_fn serve_reactor_worker() {
    let cfg = core::recv_msg<ServerSpawnConfig>();
    var app = wing::new_http_server("127.0.0.1", 0);
    wing::add_get_route(app, "/hello", 101);
    let served = wing::serve_reactor(app, cfg.listener_fd, cfg.max_conns);
    core::send_msg(served);
}

fn test_serve_connection_capping(t: lit::T&) {
    t.run("Case 1: HttpServer.serve Clean Connection Capping (max_connections = 3)") { sub =>
        let listener = wing::tcp_listen("127.0.0.1", 0, 16);
        sub.assert_gt(listener, 0, "Listener created");
        defer wing::tcp_close(listener);

        let port = wing::tcp_getsockname_port(listener);
        let worker_tid = thread_spawn(serve_sync_worker);
        core::send_msg(ServerSpawnConfig { listener_fd: listener, max_conns: 3 });

        for i in 3 {
            let client = wing::tcp_connect("127.0.0.1", port, 2000);
            sub.assert_gt(client, 0, "Client connected");

            let req_wire: const u8[:] = "GET /ping HTTP/1.1\r\nHost: 127.0.0.1\r\nSec-Fetch-Site: same-origin\r\nConnection: close\r\n\r\n";
            let s = wing::tcp_send(client, req_wire);
            sub.assert_eq(s, req_wire.len as i32, "Client sent request");

            var resp_buf: u8[..512] = [];
            let r = wing::tcp_recv(client, resp_buf, 512, 2000);
            sub.assert_gt(r, 0, "Client received response");
            sub.assert_true(find(resp_buf[..], "200 OK") >= 0, "Response is 200 OK");

            wing::tcp_close(client);
        }

        let served = core::recv_msg<i64>();
        sub.assert_eq(served, 3, "HttpServer.serve processed exactly 3 connections");

        let wait_ok = thread_wait(worker_tid);
        sub.assert_true(wait_ok, "serve worker thread terminated cleanly");
    };
}

fn test_serve_reactor_connection_capping(t: lit::T&) {
    t.run("Case 2: HttpServer.serve_reactor Connection Capping & Epoll Shutdown") { sub =>
        let listener = wing::tcp_listen("127.0.0.1", 0, 16);
        sub.assert_gt(listener, 0, "Listener created");
        defer wing::tcp_close(listener);

        let port = wing::tcp_getsockname_port(listener);
        let worker_tid = thread_spawn(serve_reactor_worker);
        core::send_msg(ServerSpawnConfig { listener_fd: listener, max_conns: 3 });

        for i in 3 {
            let client = wing::tcp_connect("127.0.0.1", port, 2000);
            sub.assert_gt(client, 0, "Client connected");

            let req_wire: const u8[:] = "GET /hello HTTP/1.1\r\nHost: 127.0.0.1\r\nSec-Fetch-Site: same-origin\r\nConnection: close\r\n\r\n";
            let s = wing::tcp_send(client, req_wire);
            sub.assert_eq(s, req_wire.len as i32, "Client sent request");

            var resp_buf: u8[..512] = [];
            let r = wing::tcp_recv(client, resp_buf, 512, 2000);
            sub.assert_gt(r, 0, "Client received response");
            sub.assert_true(find(resp_buf[..], "200 OK") >= 0, "Response is 200 OK");

            wing::tcp_close(client);
        }

        let served = core::recv_msg<i64>();
        sub.assert_eq(served, 3, "HttpServer.serve_reactor processed exactly 3 connections");

        let wait_ok = thread_wait(worker_tid);
        sub.assert_true(wait_ok, "serve_reactor worker thread terminated cleanly");
    };
}

fn test_topic_tree_live_broadcast_and_batch_drain(t: lit::T&) {
    t.run("Case 3: TopicTree Live Socket Broadcast & Batch Drainage") { sub =>
        let listener = wing::tcp_listen("127.0.0.1", 0, 16);
        sub.assert_gt(listener, 0, "Listener created");
        defer wing::tcp_close(listener);

        let port = wing::tcp_getsockname_port(listener);

        let c1 = wing::tcp_connect("127.0.0.1", port, 2000);
        let c2 = wing::tcp_connect("127.0.0.1", port, 2000);
        let c3 = wing::tcp_connect("127.0.0.1", port, 2000);
        sub.assert_gt(c1, 0, "Client 1 connected");
        sub.assert_gt(c2, 0, "Client 2 connected");
        sub.assert_gt(c3, 0, "Client 3 connected");
        defer wing::tcp_close(c1);
        defer wing::tcp_close(c2);
        defer wing::tcp_close(c3);

        let s1 = wing::tcp_accept(listener, 2000);
        let s2 = wing::tcp_accept(listener, 2000);
        let s3 = wing::tcp_accept(listener, 2000);
        sub.assert_gt(s1, 0, "Server accepted 1");
        sub.assert_gt(s2, 0, "Server accepted 2");
        sub.assert_gt(s3, 0, "Server accepted 3");
        defer wing::tcp_close(s1);
        defer wing::tcp_close(s2);
        defer wing::tcp_close(s3);

        var tree = wing::TopicTree { .. };
        sub.assert_true(wing::subscribe(tree, s1, "chat/general"), "s1 subscribed to chat/general");
        sub.assert_true(wing::subscribe(tree, s2, "chat/general"), "s2 subscribed to chat/general");
        sub.assert_true(wing::subscribe(tree, s3, "alerts/#"), "s3 subscribed to alerts/#");

        let sent_count = wing::publish_text(tree, "chat/general", "ROOM_MSG");
        sub.assert_eq(sent_count, 2, "Dispatched to both subscribers s1 and s2");

        var buf1: u8[..256] = [];
        let r1 = wing::tcp_recv(c1, buf1, 256, 1000);
        sub.assert_gt(r1, 0, "Client 1 received frame");
        sub.assert_true(find(buf1[..], "ROOM_MSG") >= 0, "Frame contains ROOM_MSG");

        var buf2: u8[..256] = [];
        let r2 = wing::tcp_recv(c2, buf2, 256, 1000);
        sub.assert_gt(r2, 0, "Client 2 received frame");
        sub.assert_true(find(buf2[..], "ROOM_MSG") >= 0, "Frame contains ROOM_MSG");

        let queued = wing::publish_batch(tree, "alerts/fire", "EVACUATE");
        sub.assert_eq(queued, 1, "Queued to 1 subscriber matching wildcard alerts/#");
        sub.assert_gt(wing::drainable_count(tree), 0, "Drainable subscribers pending");

        let drained = wing::drain(tree);
        sub.assert_eq(drained, 1, "Drained 1 batched message to wire");
        sub.assert_eq(wing::drainable_count(tree), 0, "Zero drainable subscribers remaining");

        var buf3: u8[..256] = [];
        let r3 = wing::tcp_recv(c3, buf3, 256, 1000);
        sub.assert_gt(r3, 0, "Client 3 received drained alert frame");
        sub.assert_true(find(buf3[..], "EVACUATE") >= 0, "Alert frame contains EVACUATE");
    };
}

// --- Component: server_pipeline_invariants ---
// Security invariant tests for Server Request Pipeline & HTTP/1.1 Pipelining:
// 1. HTTP/1.1 Pipelined request buffer parsing.
// 2. RFC 9112 Section 2.2 empty line tolerance & Section 3.1 leading whitespace ban.
// 3. Request target and Host header structural security invariants.

fn test_server_http1_pipelining(t: lit::T&) {
    let wire: const u8[:] = "GET /first HTTP/1.1\r\nHost: example.com\r\n\r\nGET /second HTTP/1.1\r\nHost: example.com\r\n\r\n";

    var req1 = wing::Request { .. };
    let ok1, consumed1 = wing::parse_http1_wire_request(wire, req1);
    t.assert_true(ok1, "first pipelined request parsed successfully");
    t.assert_true(req1.url[..] == "/first", "first url matches");
    t.assert_true(consumed1 > 0 && consumed1 < wire.len, "consumed bytes valid");

    let rem_wire = wire[consumed1..];
    var req2 = wing::Request { .. };
    let ok2, consumed2 = wing::parse_http1_wire_request(rem_wire, req2);
    t.assert_true(ok2, "second pipelined request parsed successfully");
    t.assert_true(req2.url[..] == "/second", "second url matches");
    t.assert_eq(consumed1 + consumed2, wire.len, "entire pipelined stream consumed");
}

fn test_server_empty_line_and_whitespace_invariants(t: lit::T&) {
    // 1. RFC 9112 §2.2: Single empty line (\r\n) before request-line is tolerated
    let single_crlf: const u8[:] = "\r\nGET /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n";
    var req1 = wing::Request { .. };
    let ok1, _ = wing::parse_http1_wire_request(single_crlf, req1);
    t.assert_true(ok1, "single CRLF before request-line is tolerated");
    t.assert_true(req1.url[..] == "/index.html", "request url matches");

    // 2. RFC 9112 §2.2: Multiple empty lines (\r\n\r\n) before request-line MUST be rejected
    let double_crlf: const u8[:] = "\r\n\r\nGET /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n";
    var req2 = wing::Request { .. };
    let ok2, _ = wing::parse_http1_wire_request(double_crlf, req2);
    t.assert_false(ok2, "more than one CRLF before request-line must be rejected");

    // 3. RFC 9112 §3.1: Whitespace before method name MUST be rejected
    let ws_method: const u8[:] = " GET /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n";
    var req3 = wing::Request { .. };
    let ok3, _ = wing::parse_http1_wire_request(ws_method, req3);
    t.assert_false(ok3, "space before method name must be rejected");

    let tab_method: const u8[:] = "\tGET /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n";
    var req4 = wing::Request { .. };
    let ok4, _ = wing::parse_http1_wire_request(tab_method, req4);
    t.assert_false(ok4, "tab before method name must be rejected");
}

fn test_server_target_and_host_invariants(t: lit::T&) {
    // 1. Reject CTL character in request target
    let bad_ctl: const u8[:] = "GET /bad\x01path HTTP/1.1\r\nHost: example.com\r\n\r\n";
    var req1 = wing::Request { .. };
    let ok1, _ = wing::parse_http1_wire_request(bad_ctl, req1);
    t.assert_false(ok1, "CTL in request target must be rejected");

    // 2. Reject Host header with path or query delimiter
    let bad_host1: const u8[:] = "GET / HTTP/1.1\r\nHost: example.com/path\r\n\r\n";
    var req2 = wing::Request { .. };
    let ok2, _ = wing::parse_http1_wire_request(bad_host1, req2);
    t.assert_false(ok2, "Host header with path separator must be rejected");

    let bad_host2: const u8[:] = "GET / HTTP/1.1\r\nHost: example.com?query\r\n\r\n";
    var req3 = wing::Request { .. };
    let ok3, _ = wing::parse_http1_wire_request(bad_host2, req3);
    t.assert_false(ok3, "Host header with query delimiter must be rejected");

    // 3. Valid IPv6 literal host
    let ipv6_host: const u8[:] = "GET / HTTP/1.1\r\nHost: [::1]:8080\r\n\r\n";
    var req4 = wing::Request { .. };
    let ok4, _ = wing::parse_http1_wire_request(ipv6_host, req4);
    t.assert_true(ok4, "valid IPv6 literal host must succeed");
}

fn test_nginx_harmony_invariants(t: lit::T&) {
    t.run("1. X-Real-IP extraction with loopback and trust_proxy_headers") { sub =>
        var server = wing::new_http_server("127.0.0.1", 8080);
        server.pipeline.enable_rate_limiter = true;
        server.pipeline.limiter = wing::new_sharded_limiter(wing::new_gcra_quota(1, core::secs(1), 0));
        wing::add_route(server.pipeline.router, "GET", "/ip-check", 1, 0);

        var req1: u8[..256] = [];
        req1.append("GET /ip-check HTTP/1.1\r\nHost: localhost\r\nX-Real-IP: 203.0.113.195\r\n\r\n");

        var out1: u8[..1024] = [];
        let outcome1, ok1 = wing::handle_connection_wire(server, "127.0.0.1", req1[..], 1000000000, out1);
        sub.assert_true(ok1, "first request from 203.0.113.195 succeeds");
        sub.assert_true(outcome1 == wing::PipelineOutcome.Handled, "first request handled");

        var req2: u8[..256] = [];
        req2.append("GET /ip-check HTTP/1.1\r\nHost: localhost\r\nX-Real-IP: 198.51.100.5\r\n\r\n");
        var out2: u8[..1024] = [];
        let outcome2, ok2 = wing::handle_connection_wire(server, "127.0.0.1", req2[..], 1000000000, out2);
        sub.assert_true(ok2, "request from distinct client IP 198.51.100.5 succeeds despite burst limit on previous IP");
        sub.assert_true(outcome2 == wing::PipelineOutcome.Handled, "distinct IP request handled");

        var req3: u8[..256] = [];
        req3.append("GET /ip-check HTTP/1.1\r\nHost: localhost\r\nX-Real-IP: 203.0.113.195\r\n\r\n");
        var out3: u8[..1024] = [];
        let outcome3, _ = wing::handle_connection_wire(server, "127.0.0.1", req3[..], 1000000000, out3);
        sub.assert_true(outcome3 == wing::PipelineOutcome.RateLimited, "second request from 203.0.113.195 is rate-limited");
        sub.assert_true(core::contains(out3[..], "429 Too Many Requests"), "response contains 429 status line");
    };

    t.run("2. X-Forwarded-For comma-separated list extraction") { sub =>
        var server = wing::new_http_server("127.0.0.1", 8080);
        server.pipeline.enable_rate_limiter = true;
        server.pipeline.limiter = wing::new_sharded_limiter(wing::new_gcra_quota(1, core::secs(1), 0));
        wing::add_route(server.pipeline.router, "GET", "/xff-check", 1, 0);

        var req1: u8[..256] = [];
        req1.append("GET /xff-check HTTP/1.1\r\nHost: localhost\r\nX-Forwarded-For: 203.0.113.50, 10.0.0.1\r\n\r\n");
        var out1: u8[..1024] = [];
        let outcome1, _ = wing::handle_connection_wire(server, "127.0.0.1", req1[..], 1000000000, out1);
        sub.assert_true(outcome1 == wing::PipelineOutcome.Handled, "first request handled");

        var req2: u8[..256] = [];
        req2.append("GET /xff-check HTTP/1.1\r\nHost: localhost\r\nX-Forwarded-For: 203.0.113.50, 10.0.0.2\r\n\r\n");
        var out2: u8[..1024] = [];
        let outcome2, _ = wing::handle_connection_wire(server, "127.0.0.1", req2[..], 1000000000, out2);
        sub.assert_true(outcome2 == wing::PipelineOutcome.RateLimited, "same original client IP in XFF is rate limited");
    };

    t.run("2b. RFC 7239 Forwarded header extraction and precedence") { sub =>
        var server = wing::new_http_server("127.0.0.1", 8080);
        server.pipeline.enable_rate_limiter = true;
        server.pipeline.limiter = wing::new_sharded_limiter(wing::new_gcra_quota(1, core::secs(1), 0));
        wing::add_route(server.pipeline.router, "GET", "/fwd-check", 1, 0);

        var req1: u8[..256] = [];
        req1.append("GET /fwd-check HTTP/1.1\r\nHost: localhost\r\nForwarded: for=\"192.0.2.60:4711\";proto=http\r\n\r\n");
        var out1: u8[..1024] = [];
        let outcome1, _ = wing::handle_connection_wire(server, "127.0.0.1", req1[..], 1000000000, out1);
        sub.assert_true(outcome1 == wing::PipelineOutcome.Handled, "first request handled");

        var req2: u8[..256] = [];
        req2.append("GET /fwd-check HTTP/1.1\r\nHost: localhost\r\nForwarded: for=192.0.2.60\r\nX-Real-IP: 10.0.0.1\r\n\r\n");
        var out2: u8[..1024] = [];
        let outcome2, _ = wing::handle_connection_wire(server, "127.0.0.1", req2[..], 1000000000, out2);
        sub.assert_true(outcome2 == wing::PipelineOutcome.RateLimited, "Forwarded header takes precedence and triggers rate limit");

        var req3: u8[..256] = [];
        req3.append("GET /fwd-check HTTP/1.1\r\nHost: localhost\r\nForwarded: for=\"[2001:db8:cafe::17]:8080\"\r\n\r\n");
        var out3: u8[..1024] = [];
        let outcome3, _ = wing::handle_connection_wire(server, "127.0.0.1", req3[..], 1000000000, out3);
        sub.assert_true(outcome3 == wing::PipelineOutcome.Handled, "IPv6 in Forwarded handled");
    };

    t.run("3. Untrusted remote IP ignores proxy headers when trust_proxy_headers is false") { sub =>
        var server = wing::new_http_server("127.0.0.1", 8080);
        server.pipeline.enable_rate_limiter = true;
        server.pipeline.trust_proxy_headers = false;
        server.pipeline.limiter = wing::new_sharded_limiter(wing::new_gcra_quota(1, core::secs(1), 0));
        wing::add_route(server.pipeline.router, "GET", "/untrusted", 1, 0);

        var req1: u8[..256] = [];
        req1.append("GET /untrusted HTTP/1.1\r\nHost: localhost\r\nX-Real-IP: 1.1.1.1\r\n\r\n");
        var out1: u8[..1024] = [];
        let outcome1, _ = wing::handle_connection_wire(server, "198.51.100.1", req1[..], 1000000000, out1);
        sub.assert_true(outcome1 == wing::PipelineOutcome.Handled, "first request handled");

        var req2: u8[..256] = [];
        req2.append("GET /untrusted HTTP/1.1\r\nHost: localhost\r\nX-Real-IP: 2.2.2.2\r\n\r\n");
        var out2: u8[..1024] = [];
        let outcome2, _ = wing::handle_connection_wire(server, "198.51.100.1", req2[..], 1000000000, out2);
        sub.assert_true(outcome2 == wing::PipelineOutcome.RateLimited, "second request from same peer is rate limited, spoofed X-Real-IP ignored");
    };

    t.run("4. HTTP/1.1 with Connection: close echoes Connection: close") { sub =>
        var server = wing::new_http_server("127.0.0.1", 8080);
        wing::add_route(server.pipeline.router, "GET", "/close-test", 1, 0);

        var req: u8[..256] = [];
        req.append("GET /close-test HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n");
        var out: u8[..1024] = [];
        let _, ok = wing::handle_connection_wire(server, "127.0.0.1", req[..], 1000000000, out);
        sub.assert_true(ok, "request processed");
        sub.assert_true(core::contains(out[..], "Connection: close\r\n") || core::contains(out[..], "connection: close\r\n"), "response must contain Connection: close");
        sub.assert_false(core::contains(out[..], "Connection: keep-alive\r\n"), "response must NOT contain Connection: keep-alive");
    };

    t.run("5. HTTP/1.0 without keep-alive echoes Connection: close") { sub =>
        var server = wing::new_http_server("127.0.0.1", 8080);
        wing::add_route(server.pipeline.router, "GET", "/h10-close", 1, 0);

        var req: u8[..256] = [];
        req.append("GET /h10-close HTTP/1.0\r\nHost: localhost\r\n\r\n");
        var out: u8[..1024] = [];
        let _, ok = wing::handle_connection_wire(server, "127.0.0.1", req[..], 1000000000, out);
        sub.assert_true(ok, "request processed");
        sub.assert_true(core::contains(out[..], "Connection: close\r\n") || core::contains(out[..], "connection: close\r\n"), "HTTP/1.0 response must contain Connection: close");
        sub.assert_false(core::contains(out[..], "Connection: keep-alive\r\n"), "HTTP/1.0 response must NOT contain Connection: keep-alive");
    };

    t.run("6. HTTP/1.0 with Connection: keep-alive maintains keep-alive") { sub =>
        var server = wing::new_http_server("127.0.0.1", 8080);
        wing::add_route(server.pipeline.router, "GET", "/h10-keepalive", 1, 0);

        var req: u8[..256] = [];
        req.append("GET /h10-keepalive HTTP/1.0\r\nHost: localhost\r\nConnection: keep-alive\r\n\r\n");
        var out: u8[..1024] = [];
        let _, ok = wing::handle_connection_wire(server, "127.0.0.1", req[..], 1000000000, out);
        sub.assert_true(ok, "request processed");
        sub.assert_true(core::contains(out[..], "Connection: keep-alive\r\n"), "explicit keep-alive preserved in HTTP/1.0");
    };

    t.run("7. SSE init_response sets X-Accel-Buffering: no") { sub =>
        var res = wing::Response { .. };
        wing::init_response(res);
        sub.assert_eq(res.status_code, 200, "status code 200");
        sub.assert_eq(wing::header(res, "Content-Type"), "text/event-stream", "Content-Type is text/event-stream");
        sub.assert_eq(wing::header(res, "X-Accel-Buffering"), "no", "X-Accel-Buffering is no");
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

    let ok = lit::finish(runner);
    assert(ok);
}
