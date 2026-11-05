// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// tests/lit/verify_bitmask_pipeline.goose
// Verification of Bitmask Pipeline Dispatch (Pre-Baked Route PSOs & Macro-Fused Bit-Test).
//
// RUN: goose build --cc gcc -O2 -o %t.exe %s
// RUN: %t.exe | %FileCheck %s

import std;
import core from "../..";
import wing from "../..";

fn test_pso_route_matching() {
    var router = wing::new_radix_router();

    // 1. Zero-cost fast-path bypass probe (pso_mask = 0)
    assert(wing::add_route_pso(router, "GET", "/healthz", 1001, 0));

    // 2. Default protected endpoint (default pso_mask)
    assert(wing::add_route(router, "GET", "/api/v1/users/{id}", 1002));

    // 3. Custom security + egress isolation endpoint
    let custom_pso: u64 = wing::STAGE_INGRESS_CORS_PREFLIGHT | wing::STAGE_EGRESS_SECURITY_HEADERS;
    assert(wing::add_route_pso(router, "POST", "/api/v1/secure", 1003, custom_pso));

    // Match /healthz
    var params1 = wing::ZeroAllocParams { .. };
    var canon1: u8[..512] = [];
    let match1 = wing::match_route(router, "GET", "/healthz", params1, canon1);
    match match1 {
        Found f => {
            assert(f.handler_id == 1001);
            assert(f.pso_mask == 0);
        },
        _ => assert(false),
    };

    // Match /api/v1/users/42
    var params2 = wing::ZeroAllocParams { .. };
    var canon2: u8[..512] = [];
    let match2 = wing::match_route(router, "GET", "/api/v1/users/42", params2, canon2);
    match match2 {
        Found f => {
            assert(f.handler_id == 1002);
            assert(f.pso_mask == wing::DEFAULT_ROUTE_PSO_MASK);
        },
        _ => assert(false),
    };

    // Match /api/v1/secure
    var params3 = wing::ZeroAllocParams { .. };
    var canon3: u8[..512] = [];
    let match3 = wing::match_route(router, "POST", "/api/v1/secure", params3, canon3);
    match match3 {
        Found f => {
            assert(f.handler_id == 1003);
            assert(f.pso_mask == custom_pso);
        },
        _ => assert(false),
    };

    print("PSO_ROUTE_MATCH: OK");
}

fn test_pso_fast_path_and_ingress() {
    let quota = wing::new_gcra_quota(100, core::secs(1), 10);
    var cfg = wing::new_server_pipeline_config("example.com", quota);

    // Register /healthz with pso_mask = 0
    assert(wing::add_route_pso(cfg.router, "GET", "/healthz", 1001, 0));

    // Register /protected with default pso_mask
    assert(wing::add_route(cfg.router, "POST", "/protected", 1002));

    var timer = internal::new_connection_timer(30000000000, 1000000000);

    // Case 1: Fast-path probe bypasses invalid Expect header
    var req_probe = wing::new_request("GET", "/healthz");
    wing::append_header(req_probe.headers, "Host", "example.com");
    wing::append_header(req_probe.headers, "Expect", "invalid-unsupported-expectation");

    var res_probe = wing::Response { .. };
    var fut_probe = internal::new_inline_handler_future(0);
    let outcome_probe = wing::execute_pipeline(cfg, timer, "127.0.0.1", req_probe, 1000000000, res_probe, fut_probe);

    assert(outcome_probe == wing::PipelineOutcome.Handled);
    assert(res_probe.status_code == 200);
    assert(res_probe.body == "Hello, World!");
    print("PSO_FAST_PATH_BYPASS: OK");

    // Case 2: Protected route rejects invalid Expect header with 417
    var req_bad_exp = wing::new_request("POST", "/protected");
    wing::append_header(req_bad_exp.headers, "Host", "example.com");
    wing::append_header(req_bad_exp.headers, "Expect", "invalid-unsupported-expectation");

    var res_bad_exp = wing::Response { .. };
    var fut_bad_exp = internal::new_inline_handler_future(0);
    let outcome_bad_exp = wing::execute_pipeline(cfg, timer, "127.0.0.1", req_bad_exp, 1000000000, res_bad_exp, fut_bad_exp);

    assert(outcome_bad_exp == wing::PipelineOutcome.ExpectationFailed);
    assert(res_bad_exp.status_code == 417);

    // Case 3: Protected route accepts valid Expect: 100-continue
    var req_ok_exp = wing::new_request("POST", "/protected");
    wing::append_header(req_ok_exp.headers, "Host", "example.com");
    wing::append_header(req_ok_exp.headers, "Sec-Fetch-Site", "same-origin");
    wing::append_header(req_ok_exp.headers, "Expect", "100-continue");

    var res_ok_exp = wing::Response { .. };
    var fut_ok_exp = internal::new_inline_handler_future(0);
    let outcome_ok_exp = wing::execute_pipeline(cfg, timer, "127.0.0.1", req_ok_exp, 1000000000, res_ok_exp, fut_ok_exp);

    assert(outcome_ok_exp == wing::PipelineOutcome.Handled);
    assert(res_ok_exp.status_code == 200);
    print("PSO_INGRESS_ENFORCEMENT: OK");
}

fn test_pso_egress_security_headers() {
    let quota = wing::new_gcra_quota(100, core::secs(1), 10);
    var cfg = wing::new_server_pipeline_config("example.com", quota);

    let secure_pso: u64 = wing::STAGE_EGRESS_SECURITY_HEADERS;
    assert(wing::add_route_pso(cfg.router, "GET", "/secure-api", 1002, secure_pso));

    var timer = internal::new_connection_timer(30000000000, 1000000000);
    var req = wing::new_request("GET", "/secure-api");
    wing::append_header(req.headers, "Host", "example.com");

    var res = wing::Response { .. };
    var fut = internal::new_inline_handler_future(0);
    let outcome = wing::execute_pipeline(cfg, timer, "127.0.0.1", req, 1000000000, res, fut);

    assert(outcome == wing::PipelineOutcome.Handled);
    assert(res.status_code == 200);
    assert(res.has_header("Strict-Transport-Security"));
    assert(res.has_header("Vary"));
    print("PSO_EGRESS_SECURITY: OK");
}

fn test_client_bitmask_interceptors() {
    var pipeline = wing::InterceptorPipeline { .. };

    // Register interceptors via bitmask setters
    assert(wing::add_bearer_auth(pipeline, "super-secret-token"));
    assert(wing::add_request_id(pipeline, "trace-"));
    assert(wing::add_traceparent(pipeline, "01"));
    assert(wing::add_retry(pipeline, 3, true));

    // Verify bitmask has bits set
    assert((pipeline.active_mask & wing::INTERCEPTOR_APP_AUTH_BEARER) != 0);
    assert((pipeline.active_mask & wing::INTERCEPTOR_APP_REQUEST_ID) != 0);
    assert((pipeline.active_mask & wing::INTERCEPTOR_APP_TRACEPARENT) != 0);
    assert((pipeline.active_mask & wing::INTERCEPTOR_APP_RETRY) != 0);

    // Verify instant retry policy query
    var retries:   i32  = 0;
    var retry_5xx: bool = false;
    assert(wing::find_retry_policy(pipeline, retries, retry_5xx));
    assert(retries == 3);
    assert(retry_5xx);

    // Apply request hook
    var req = wing::new_request("GET", "https://api.internal/data");
    wing::apply_app_interceptors_request(pipeline, req, 1600000000);

    assert(req.has_header("Authorization"));
    assert(req.header("Authorization") == "Bearer super-secret-token");
    assert(req.has_header("X-Request-ID"));
    assert(req.header("X-Request-ID") == "trace-1");
    assert(req.has_header("traceparent"));

    print("CLIENT_BITMASK_INTERCEPTORS: OK");
}

fn main() {
    test_pso_route_matching();
    test_pso_fast_path_and_ingress();
    test_pso_egress_security_headers();
    test_client_bitmask_interceptors();
    print("BITMASK_PIPELINE_COMPLETE: OK");
}

// CHECK: PSO_ROUTE_MATCH: OK
// CHECK: PSO_FAST_PATH_BYPASS: OK
// CHECK: PSO_INGRESS_ENFORCEMENT: OK
// CHECK: PSO_EGRESS_SECURITY: OK
// CHECK: CLIENT_BITMASK_INTERCEPTORS: OK
// CHECK: BITMASK_PIPELINE_COMPLETE: OK
