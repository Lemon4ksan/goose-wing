// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// tests/lit/verify_http_problem_and_forwarded.goose
// Verification of:
// - RFC 9457 Problem Details for HTTP APIs (application/problem+json)
// - RFC 7239 Forwarded HTTP Extension (IPv4, IPv6 quoted, proto, host, by)
// - RFC 8470 0-RTT Early-Data & HTTP 425 (Too Early) Recovery
// - RFC 6585, RFC 7725, RFC 9110 Standard Status Code Reason Phrases
//
// RUN: goose build --cc gcc -O2 -o %t.exe %s
// RUN: %t.exe | %FileCheck %s

import std;
import core from "../..";
import wing from "../..";

fn test_rfc9457_problem_details() {
    // 1. Serialization with explicit type URI
    var prob = wing::ProblemDetails {
        status:   403,
        type_uri: "https://example.com/probs/out-of-credit",
        title:    "You do not have enough credit.",
        detail:   "Your current balance is 30, but that costs 50.",
        instance: "/account/12345/msgs/abc",
    };
    var json_out: u8[..1024] = [];
    wing::serialize_problem_details(prob, json_out);
    assert(core::contains(json_out[..], "\"status\":403"));
    assert(core::contains(json_out[..], "\"type\":\"https://example.com/probs/out-of-credit\""));
    assert(core::contains(json_out[..], "\"title\":\"You do not have enough credit.\""));
    assert(core::contains(json_out[..], "\"instance\":\"/account/12345/msgs/abc\""));
    print("PROBLEM_SERIALIZE_OK: 1");
    // CHECK: PROBLEM_SERIALIZE_OK: 1

    // 2. Default type URI "about:blank" (RFC 9457 §4.2.1)
    var blank_prob = wing::ProblemDetails {
        status: 404,
        title:  "Item Not Found",
        ..
    };
    var blank_out: u8[..512] = [];
    wing::serialize_problem_details(blank_prob, blank_out);
    assert(core::contains(blank_out[..], "\"type\":\"about:blank\""));
    print("PROBLEM_DEFAULT_TYPE_OK: 1");
    // CHECK: PROBLEM_DEFAULT_TYPE_OK: 1

    // 3. Problem response constructor
    let res = wing::new_problem_response(prob);
    assert(res.status_code == 403);
    assert(wing::header(res, "Content-Type") == "application/problem+json");
    print("PROBLEM_RESPONSE_OK: 1");
    // CHECK: PROBLEM_RESPONSE_OK: 1

    // 4. Parsing problem details JSON
    var parsed = wing::ProblemDetails { .. };
    let ok_parse = wing::parse_problem_details(json_out[..], parsed);
    assert(ok_parse);
    assert(parsed.status == 403);
    assert(parsed.title[..] == "You do not have enough credit.");
    assert(parsed.instance[..] == "/account/12345/msgs/abc");
    print("PROBLEM_PARSE_OK: 1");
    // CHECK: PROBLEM_PARSE_OK: 1
}

fn test_rfc7239_forwarded() {
    // 1. Format IPv4 Forwarded element
    var elem4 = wing::ForwardedElement {
        for_node: "192.0.2.60",
        proto:    "https",
        host:     "api.example.com",
        ..
    };
    var fwd_buf: u8[..512] = [];
    wing::format_forwarded_element(elem4, fwd_buf);
    assert(core::contains(fwd_buf[..], "for=192.0.2.60"));
    assert(core::contains(fwd_buf[..], "proto=https"));
    assert(core::contains(fwd_buf[..], "host=api.example.com"));
    print("FORWARDED_IPV4_OK: 1");
    // CHECK: FORWARDED_IPV4_OK: 1

    // 2. Format IPv6 Forwarded element with mandatory double quotes (RFC 7239 §4)
    var elem6 = wing::ForwardedElement {
        by:       "203.0.113.43",
        for_node: "[2001:db8:cafe::17]:4711",
        proto:    "http",
        ..
    };
    var fwd_buf6: u8[..512] = [];
    wing::format_forwarded_element(elem6, fwd_buf6);
    assert(core::contains(fwd_buf6[..], "for=\"[2001:db8:cafe::17]:4711\""));
    assert(core::contains(fwd_buf6[..], "by=203.0.113.43"));
    print("FORWARDED_IPV6_QUOTES_OK: 1");
    // CHECK: FORWARDED_IPV6_QUOTES_OK: 1

    // 3. Append to HeaderMap
    var headers = wing::HeaderMap { .. };
    wing::append_forwarded_header(headers, elem4);
    let h_val = wing::get_header(headers, "Forwarded");
    assert(core::contains(h_val, "for=192.0.2.60"));
    print("FORWARDED_HEADER_APPEND_OK: 1");
    // CHECK: FORWARDED_HEADER_APPEND_OK: 1

    // 4. Parse multi-hop Forwarded header
    let raw_multi = "for=192.0.2.60;proto=http, for=\"[2001:db8::1]\";by=203.0.113.43;host=proxy.net";
    var parsed_elems: wing::ForwardedElement[..8] = [];
    let count = wing::parse_forwarded_header(raw_multi, parsed_elems);
    assert(count == 2);
    assert(parsed_elems[0].for_node[..] == "192.0.2.60");
    assert(parsed_elems[0].proto[..] == "http");
    assert(parsed_elems[1].for_node[..] == "[2001:db8::1]");
    assert(parsed_elems[1].by[..] == "203.0.113.43");
    assert(parsed_elems[1].host[..] == "proxy.net");
    print("FORWARDED_PARSE_MULTI_OK: 1");
    // CHECK: FORWARDED_PARSE_MULTI_OK: 1
}

fn test_rfc_status_codes_and_early_data() {
    // 1. RFC 8470 Section 5.2: 425 Too Early
    assert(rfc::status_phrase(425) == "Too Early");
    assert(rfc::HEADER_EARLY_DATA == "Early-Data");
    let dec_retry = wing::evaluate_early_data_response(425, true);
    match dec_retry {
        RetryOn1Rtt => { print("EARLY_DATA_RETRY_OK: 1"); },
        _ => { assert(false); },
    };
    // CHECK: EARLY_DATA_RETRY_OK: 1

    // 2. RFC 9110 Section 15.5.21: 422 Unprocessable Content
    assert(rfc::status_phrase(422) == "Unprocessable Content");

    // 3. RFC 6585: Additional HTTP Status Codes
    assert(rfc::status_phrase(428) == "Precondition Required");
    assert(rfc::status_phrase(431) == "Request Header Fields Too Large");
    assert(rfc::status_phrase(511) == "Network Authentication Required");

    // 4. RFC 7725: 451 Unavailable For Legal Reasons
    assert(rfc::status_phrase(451) == "Unavailable For Legal Reasons");

    // 5. RFC 6266: Content-Disposition
    assert(rfc::HEADER_CONTENT_DISPOSITION == "Content-Disposition");
    print("STATUS_CODES_AND_HEADERS_OK: 1");
    // CHECK: STATUS_CODES_AND_HEADERS_OK: 1
}

fn main() {
    test_rfc9457_problem_details();
    test_rfc7239_forwarded();
    test_rfc_status_codes_and_early_data();
    print("ALL_RFC_VERIFICATIONS_PASSED");
    // CHECK: ALL_RFC_VERIFICATIONS_PASSED
}
