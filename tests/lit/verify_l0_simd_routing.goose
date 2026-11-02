// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// tests/lit/verify_l0_simd_routing.goose
// Verification of Flat Register Routing (Tier 0 L0 SIMD/SWAR Register Table).
//
// RUN: goose build --cc gcc -O2 -o %t.exe %s
// RUN: %t.exe | %FileCheck %s

import std;
import core from "../..";
import wing from "../..";

fn test_l0_exact_hits() {
    var router = wing::new_radix_router();

    assert(wing::add_route(router, "GET", "/plaintext", 101));
    assert(wing::add_route(router, "GET", "/json", 102));
    assert(wing::add_route(router, "GET", "/healthz", 103));
    assert(wing::add_route(router, "GET", "/", 104));
    assert(wing::add_route(router, "GET", "/123456789012345", 105)); // exactly 16 bytes

    // Verify L0 count
    assert(router.l0_table.count == 5);

    // Exact matches
    var params = wing::ZeroAllocParams { .. };
    var canon: u8[..512] = [];

    let m1 = wing::match_route(router, "GET", "/plaintext", params, canon);
    match m1 {
        Found f => assert(f.handler_id == 101),
        _ => assert(false),
    };

    let m2 = wing::match_route(router, "GET", "/json", params, canon);
    match m2 {
        Found f => assert(f.handler_id == 102),
        _ => assert(false),
    };

    let m3 = wing::match_route(router, "GET", "/healthz", params, canon);
    match m3 {
        Found f => assert(f.handler_id == 103),
        _ => assert(false),
    };

    let m4 = wing::match_route(router, "GET", "/", params, canon);
    match m4 {
        Found f => assert(f.handler_id == 104),
        _ => assert(false),
    };

    let m5 = wing::match_route(router, "GET", "/123456789012345", params, canon);
    match m5 {
        Found f => assert(f.handler_id == 105),
        _ => assert(false),
    };

    print("L0_EXACT_HITS_OK");
    // CHECK: L0_EXACT_HITS_OK
}

fn test_l0_query_and_uncanonical_fallbacks() {
    var router = wing::new_radix_router();

    assert(wing::add_route(router, "GET", "/plaintext", 101));
    assert(wing::add_route(router, "GET", "/json", 102));

    var params = wing::ZeroAllocParams { .. };
    var canon: u8[..512] = [];

    // Query strings should cleanly miss L0 and fall through to Tier 1
    let q1 = wing::match_route(router, "GET", "/plaintext?format=raw", params, canon);
    match q1 {
        Found f => assert(f.handler_id == 101),
        _ => assert(false),
    };
    assert(canon[..] == "/plaintext");

    let q2 = wing::match_route(router, "GET", "/json?pretty=true", params, canon);
    match q2 {
        Found f => assert(f.handler_id == 102),
        _ => assert(false),
    };
    assert(canon[..] == "/json");

    // Uncanonical paths (double slashes / dot segments) fall through to Tier 1
    let u1 = wing::match_route(router, "GET", "//plaintext", params, canon);
    match u1 {
        Found f => assert(f.handler_id == 101),
        _ => assert(false),
    };
    assert(canon[..] == "/plaintext");

    let u2 = wing::match_route(router, "GET", "/./json", params, canon);
    match u2 {
        Found f => assert(f.handler_id == 102),
        _ => assert(false),
    };
    assert(canon[..] == "/json");

    print("L0_FALLBACKS_OK");
    // CHECK: L0_FALLBACKS_OK
}

fn test_l0_method_segregation() {
    var router = wing::new_radix_router();

    assert(wing::add_route(router, "GET", "/status", 201));
    assert(wing::add_route(router, "POST", "/status", 202));
    assert(wing::add_route(router, "DELETE", "/status", 203));

    var params = wing::ZeroAllocParams { .. };
    var canon: u8[..512] = [];

    let m_get = wing::match_route(router, "GET", "/status", params, canon);
    match m_get {
        Found f => assert(f.handler_id == 201),
        _ => assert(false),
    };

    let m_post = wing::match_route(router, "POST", "/status", params, canon);
    match m_post {
        Found f => assert(f.handler_id == 202),
        _ => assert(false),
    };

    let m_del = wing::match_route(router, "DELETE", "/status", params, canon);
    match m_del {
        Found f => assert(f.handler_id == 203),
        _ => assert(false),
    };

    // Automatic HEAD routing for GET
    let m_head = wing::match_route(router, "HEAD", "/status", params, canon);
    match m_head {
        Found f => assert(f.handler_id == 201),
        _ => assert(false),
    };

    // MethodNotAllowed
    let m_put = wing::match_route(router, "PUT", "/status", params, canon);
    match m_put {
        MethodNotAllowed _ => {},
        _ => assert(false),
    };

    print("L0_METHOD_SEGREGATION_OK");
    // CHECK: L0_METHOD_SEGREGATION_OK
}

fn test_l0_overflow_and_dynamic_routes() {
    var router = wing::new_radix_router();

    // Fill up all 16 slots of L0 table
    let prefixes: const u8[:][16] = [
        "/r00", "/r01", "/r02", "/r03",
        "/r04", "/r05", "/r06", "/r07",
        "/r08", "/r09", "/r10", "/r11",
        "/r12", "/r13", "/r14", "/r15",
    ];

    for i in 16 {
        assert(wing::add_route(router, "GET", prefixes[i], (300 + i) as i32));
    }
    assert(router.l0_table.count == 16);

    // 17th route (> 16 routes) overflows cleanly into Tier 1
    assert(wing::add_route(router, "GET", "/r16_overflow", 316));
    assert(router.l0_table.count == 16); // L0 is full at 16

    // Dynamic parameter route (not in L0)
    assert(wing::add_route(router, "GET", "/users/{id}", 401));

    var params = wing::ZeroAllocParams { .. };
    var canon: u8[..512] = [];

    // Verify all 16 L0 routes hit
    for i in 16 {
        let m = wing::match_route(router, "GET", prefixes[i], params, canon);
        match m {
            Found f => assert(f.handler_id == (300 + i) as i32),
            _ => assert(false),
        };
    }

    // Verify 17th overflow route matches via Tier 1
    let m_over = wing::match_route(router, "GET", "/r16_overflow", params, canon);
    match m_over {
        Found f => assert(f.handler_id == 316),
        _ => assert(false),
    };

    // Verify dynamic parameter route matches and extracts param
    let m_dyn = wing::match_route(router, "GET", "/users/alice", params, canon);
    match m_dyn {
        Found f => {
            assert(f.handler_id == 401);
            assert(params.len == 1);
            let val, ok_p = wing::param_by_name(params, "id", "/users/alice");
            assert(ok_p);
            assert(val == "alice");
        },
        _ => assert(false),
    };

    print("L0_OVERFLOW_AND_DYNAMIC_OK");
    // CHECK: L0_OVERFLOW_AND_DYNAMIC_OK
}

fn test_l0_pipeline_execution() {
    let quota = wing::new_gcra_quota(100, core::secs(1), 10);
    var cfg = wing::new_server_pipeline_config("example.com", quota);

    assert(wing::add_route(cfg.router, "GET", "/healthz", 1001));
    assert(wing::add_route(cfg.router, "GET", "/json", 1002));
    assert(cfg.router.l0_table.count == 2);

    var timer = internal::new_connection_timer(30000000000, 1000000000);

    // Exact L0 hit through pipeline
    var req1 = wing::new_request("GET", "/healthz");
    req1.headers.push(wing::make_header("Host", "example.com"));

    var res1 = wing::Response { .. };
    var fut1 = internal::new_inline_handler_future(0);
    let out1 = wing::execute_pipeline(cfg, timer, "127.0.0.1", req1, 1000000000, res1, fut1);

    assert(out1 == wing::PipelineOutcome.Handled);
    assert(res1.status_code == 200);

    // Query fallback through pipeline
    var req2 = wing::new_request("GET", "/json?pretty=1");
    req2.headers.push(wing::make_header("Host", "example.com"));

    var res2 = wing::Response { .. };
    var fut2 = internal::new_inline_handler_future(0);
    let out2 = wing::execute_pipeline(cfg, timer, "127.0.0.1", req2, 1000000000, res2, fut2);

    assert(out2 == wing::PipelineOutcome.Handled);
    assert(res2.status_code == 200);

    print("L0_PIPELINE_EXECUTION_OK");
    // CHECK: L0_PIPELINE_EXECUTION_OK
}

fn main() {
    test_l0_exact_hits();
    test_l0_query_and_uncanonical_fallbacks();
    test_l0_method_segregation();
    test_l0_overflow_and_dynamic_routes();
    test_l0_pipeline_execution();
    print("ALL_L0_ROUTING_TESTS_PASSED");
    // CHECK: ALL_L0_ROUTING_TESTS_PASSED
}
