// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// tests/lit/rfc_repro_client_round3_invariants.goose
// Protocol regression verification for client round 3 audit remediations.
//
// RUN: goose build -O2 -o %t.exe %s
// RUN: %t.exe | %FileCheck %s

import std;
import core from "../..";
import wing from "../..";

fn test_ssrf_ipv6() {
    assert(wing::is_private_or_reserved_ip("64:ff9b:1::"));
    assert(wing::is_private_or_reserved_ip("64:ff9b:1::1"));
    assert(wing::is_private_or_reserved_ip("64:ff9b:1:abcd::1"));
    assert(wing::is_private_or_reserved_ip("64:ff9b:1::8.8.8.8"));
    assert(!wing::is_private_or_reserved_ip("64:ff9b::8.8.8.8"));

    assert(wing::is_private_or_reserved_ip("2001:20::1"));
    assert(wing::is_private_or_reserved_ip("2001:2f::1"));
    assert(!wing::is_private_or_reserved_ip("2001:30::1"));
    print("CHECK_SSRF_IPV6: OK");
}

fn test_rfc8470_425() {
    var req_post = wing::new_post("https://example.com/api");
    req_post.body.append("payload");
    assert(!wing::should_retry_request(rfc::STATUS_TOO_EARLY, wing::Error { .. }, "POST", req_post, 0, false, 0, false));

    var req_get = wing::new_get("https://example.com/api");
    assert(wing::should_retry_request(rfc::STATUS_TOO_EARLY, wing::Error { .. }, "GET", req_get, 0, false, 0, false));

    var req_idem = wing::new_post("https://example.com/api");
    req_idem.body.append("payload");
    wing::set_header(req_idem, "Idempotency-Key", "uuid-abc");
    assert(wing::should_retry_request(rfc::STATUS_TOO_EARLY, wing::Error { .. }, "POST", req_idem, 0, false, 0, false));

    req_idem.rewindable = false;
    assert(!wing::should_retry_request(rfc::STATUS_TOO_EARLY, wing::Error { .. }, "POST", req_idem, 0, false, 0, false));
    print("CHECK_RFC8470_425: OK");
}

fn test_missing_location() {
    var session = wing::new_session();
    session.enable_cookie_jar = false;
    wing::mock_route(session, "GET", "https://redirect.invalid/missing-loc", rfc::STATUS_FOUND, "302 without location");
    var req_bad_red = wing::new_get("https://redirect.invalid/missing-loc");
    let resp_red, err_red = wing::execute_request(session, req_bad_red);
    assert(!wing::ok(err_red));
    assert(err_red.code == rfc::STATUS_BAD_REQUEST);
    print("CHECK_MISSING_LOCATION: OK");
}

fn test_traceparent_nonzero() {
    var pipe = wing::InterceptorPipeline { .. };
    assert(wing::add_interceptor(
        pipe,
        wing::InterceptorEntry {
            scope:   wing::InterceptorScope.Application,
            kind:    wing::InterceptorKind.Traceparent,
            prefix:  "00",
            counter: 0,
        },
    ));
    var req_trace = wing::new_get("http://example.invalid");
    wing::apply_app_interceptors_request(pipe, req_trace, 1000);
    let tp = wing::header(req_trace, "traceparent");
    assert(tp.len > 0);
    assert(!core::ends_with(tp, "-0000000000000000-00"));
    print("CHECK_TRACEPARENT_NONZERO: OK");
}

fn test_chunked_no_cl() {
    var req_chunked = wing::new_post("http://example.invalid");
    req_chunked.body.append("body");
    wing::set_header(req_chunked, "Transfer-Encoding", "chunked");
    let u = core::new_url("http://example.invalid");
    var hdr_buf: u8[..4096] = [];
    wing::serialize_h1_request(req_chunked, u, hdr_buf);
    assert(!core::contains(hdr_buf[..], "Content-Length:"));
    assert(core::contains(hdr_buf[..], "Transfer-Encoding: chunked"));
    print("CHECK_CHUNKED_NO_CL: OK");
}

fn test_limiter_monotonic() {
    var limiter = wing::new_rate_limiter(10.0, 10);
    let t0 = limiter.last_update_mono_ns;
    assert(wing::allow(limiter, t0 + 1000000));
    assert(!wing::allow(limiter, t0));
    print("CHECK_LIMITER_MONOTONIC: OK");
}

fn test_long_fragment() {
    var url_buf: u8[..2048] = [];
    url_buf.append("https://example.com/item#");
    for i in 600 {
        url_buf.push('z');
    }
    var qitems: wing::QueryItem[..1] = [];
    var qi = wing::QueryItem { .. };
    qi.key.append("p");
    qi.value.append("1");
    qitems.push(qi);
    wing::append_query_params_preserving_fragment(url_buf, qitems[..]);
    assert(core::contains(url_buf[..], "?p=1#"));
    assert(url_buf.len > 600);
    print("CHECK_LONG_FRAGMENT: OK");
}

fn test_ws_subprotocol() {
    assert(wing::header_has_token("chat, binary", "chat"));
    assert(wing::header_has_token("chat, binary", "binary"));
    assert(!wing::header_has_token("chat, binary", "admin"));
    print("CHECK_WS_SUBPROTOCOL: OK");
}

fn main() {
    test_ssrf_ipv6();
    test_rfc8470_425();
    test_missing_location();
    test_traceparent_nonzero();
    test_chunked_no_cl();
    test_limiter_monotonic();
    test_long_fragment();
    test_ws_subprotocol();
}

// CHECK: CHECK_SSRF_IPV6: OK
// CHECK-NEXT: CHECK_RFC8470_425: OK
// CHECK-NEXT: CHECK_MISSING_LOCATION: OK
// CHECK-NEXT: CHECK_TRACEPARENT_NONZERO: OK
// CHECK-NEXT: CHECK_CHUNKED_NO_CL: OK
// CHECK-NEXT: CHECK_LIMITER_MONOTONIC: OK
// CHECK-NEXT: CHECK_LONG_FRAGMENT: OK
// CHECK-NEXT: CHECK_WS_SUBPROTOCOL: OK
