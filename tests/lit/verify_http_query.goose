// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// tests/lit/verify_http_query.goose
// Verification of RFC 10008 HTTP QUERY Method semantics:
// - Safe & Idempotent request creation with request body & Content-Type
// - Radix router method dispatch & Allow header advertisement
// - Server pipeline rejection of QUERY requests lacking Content-Type (RFC 10008 §2)
// - 0-RTT Early Data anti-replay eligibility (RFC 8470 §5.2 / RFC 10008 §2)
// - CSRF safe-method classification (RFC 9110 §9.2.1 / RFC 10008 §2)
//
// RUN: goose build --cc gcc -O2 -o %t.exe %s
// RUN: %t.exe | %FileCheck %s

import std;
import core from "../..";
import wing from "../..";

fn main() {
    // 1. Verify Request Construction
    let query_req = wing::new_query("/api/v1/search", "{\"filter\":\"status=active\"}", "application/json");
    assert(query_req.method[..] == "QUERY");
    assert(query_req.url[..] == "/api/v1/search");
    assert(query_req.body[..] == "{\"filter\":\"status=active\"}");
    assert(wing::header(query_req, "Content-Type") == "application/json");
    print("QUERY_REQ_OK: ", query_req.method[..]);
    // CHECK: QUERY_REQ_OK: QUERY

    // 2. Verify 0-RTT Early Data Safety (RFC 10008 §2 & RFC 8470 §5.2)
    let is_early_safe = wing::is_safe_for_early_data("QUERY");
    assert(is_early_safe);
    let early_dec = wing::evaluate_early_data_request("QUERY");
    let is_allowed = match early_dec {
        Allow => true,
        _ => false,
    };
    assert(is_allowed);
    print("QUERY_EARLY_DATA_SAFE: 1");
    // CHECK: QUERY_EARLY_DATA_SAFE: 1

    // 3. Verify Router Registration and Matching
    var router = wing::new_radix_router();
    let ok_add = wing::add_route(router, "QUERY", "/items/search", 42);
    assert(ok_add);
    let ok_add_get = wing::add_route(router, "GET", "/items/search", 10);
    assert(ok_add_get);

    var params = wing::ZeroAllocParams { .. };
    var canon_path: u8[..512] = [];
    let match_res = wing::match_route(router, "QUERY", "/items/search", params, canon_path);
    let handler_id = match match_res {
        Found f => f.handler_id,
        _ => -1,
    };
    assert(handler_id == 42);
    print("ROUTER_MATCH_HANDLER: ", handler_id);
    // CHECK: ROUTER_MATCH_HANDLER: 42

    // 4. Verify 405 Method Not Allowed and Allow header advertisement
    var params_bad = wing::ZeroAllocParams { .. };
    var canon_bad: u8[..512] = [];
    let match_delete = wing::match_route(router, "DELETE", "/items/search", params_bad, canon_bad);
    var is_mna = false;
    var allow_val: u8[..64] = [];
    match match_delete {
        MethodNotAllowed mna => {
            is_mna = true;
            allow_val.append(mna.allow_header[..]);
        },
        _ => {},
    };
    assert(is_mna);
    assert(core::contains(allow_val[..], "QUERY"));
    assert(core::contains(allow_val[..], "GET"));
    print("ALLOW_HEADER_CONTAINS_QUERY: 1");
    // CHECK: ALLOW_HEADER_CONTAINS_QUERY: 1

    // 5. Verify Server Pipeline Rejection when Content-Type is missing (RFC 10008 §2)
    let quota = wing::new_gcra_quota(100, core::secs(1), 10);
    var cfg = wing::new_server_pipeline_config("example.com", quota);
    let ok_add_pipeline = wing::add_route(cfg.router, "QUERY", "/items/search", 42);
    assert(ok_add_pipeline);

    var conn_timer1 = internal::new_connection_timer(30000000000, 1000000000);
    var query_no_ct = wing::new_request("QUERY", "/items/search");
    query_no_ct.headers.push(wing::make_header("Host", "example.com"));
    query_no_ct.headers.push(wing::make_header("Sec-Fetch-Site", "same-origin"));
    query_no_ct.body.append("raw filter");

    var res1 = wing::Response { .. };
    var future1 = internal::new_inline_handler_future(0);
    let outcome1 = wing::execute_pipeline(cfg, conn_timer1, "127.0.0.1", query_no_ct, 1000000000, res1, future1);
    assert(res1.status_code == 400);
    print("QUERY_MISSING_CT_STATUS: ", res1.status_code);
    // CHECK: QUERY_MISSING_CT_STATUS: 400

    // 6. Verify Server Pipeline Acceptance when Content-Type is valid
    var conn_timer2 = internal::new_connection_timer(30000000000, 1000000000);
    var query_valid = wing::new_query("/items/search", "raw filter", "text/plain");
    query_valid.headers.push(wing::make_header("Host", "example.com"));
    query_valid.headers.push(wing::make_header("Sec-Fetch-Site", "same-origin"));

    var res2 = wing::Response { .. };
    var future2 = internal::new_inline_handler_future(0);
    let outcome2 = wing::execute_pipeline(cfg, conn_timer2, "127.0.0.1", query_valid, 2000000000, res2, future2);
    assert(res2.status_code == 200);
    print("QUERY_VALID_CT_STATUS: ", res2.status_code);
    // CHECK: QUERY_VALID_CT_STATUS: 200

    // 7. Verify CSRF Fetch Context Classification
    let fetch_ctx = wing::extract_fetch_context(query_valid, "example.com");
    assert(fetch_ctx.method_is_safe);
    print("CSRF_METHOD_SAFE: 1");
    // CHECK: CSRF_METHOD_SAFE: 1

    print("RFC10008_VERIFICATION_COMPLETE");
    // CHECK: RFC10008_VERIFICATION_COMPLETE
}
