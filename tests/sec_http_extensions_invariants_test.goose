// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Security invariant tests for HTTP Extensions:
// 1. Resumable Upload (draft-ietf-httpbis-resumable-upload-14) Structured Fields & Bounds
// 2. Early Hints (RFC 8297) & RFC 8288 Link header invariants
import std;
import core from "..";
import wing from "..";

fn test_resumable_upload_structured_fields(t: core::T&) {
    // 1. Integer parsing (non-negative integer enforcement)
    let n1, ok1 = wing::parse_upload_int("0");
    t.assert_true(ok1, "0 is valid integer");
    t.assert_eq(n1, 0, "value is 0");

    let n2, ok2 = wing::parse_upload_int("   65536   ");
    t.assert_true(ok2, "trimmed 65536 is valid integer");
    t.assert_eq(n2, 65536, "value is 65536");

    let _, ok_neg = wing::parse_upload_int("-1");
    t.assert_false(ok_neg, "negative integer must be rejected");

    let _, ok_bad = wing::parse_upload_int("abc");
    t.assert_false(ok_bad, "alphanumeric string must be rejected");

    // 2. RFC 8941 Structured Field boolean parsing
    let b1, ok_b1 = wing::parse_upload_boolean("?1");
    t.assert_true(ok_b1, "?1 is valid boolean");
    t.assert_true(b1, "value is true");

    let b2, ok_b2 = wing::parse_upload_boolean("?0");
    t.assert_true(ok_b2, "?0 is valid boolean");
    t.assert_false(b2, "value is false");

    let b3, ok_b3 = wing::parse_upload_boolean("?1; foo=bar");
    t.assert_true(ok_b3, "?1 with parameter is valid");
    t.assert_true(b3, "value is true");

    let _, ok_b4 = wing::parse_upload_boolean("?1bad");
    t.assert_false(ok_b4, "?1bad must be rejected as boolean");

    let _, ok_b5 = wing::parse_upload_boolean("true");
    t.assert_false(ok_b5, "unstructured 'true' must be rejected");
}

fn test_early_hints_link_header_security(t: core::T&) {
    // 1. Standard Link preload
    var links1: wing::EarlyHintLink[..4] = [];
    let ok1 = wing::parse_link_header("<https://cdn.example.com/main.js>; rel=preload; as=script", links1);
    t.assert_true(ok1, "valid link header parse");
    t.assert_eq(links1.len, 1, "parsed 1 link");
    t.assert_true(links1[0].uri[..] == "https://cdn.example.com/main.js", "uri matches");
    t.assert_true(links1[0].rel[..] == "preload", "rel matches");
    t.assert_true(links1[0].as_type[..] == "script", "as matches");

    // 2. Link with commas inside query string (must NOT split entry!)
    var links2: wing::EarlyHintLink[..4] = [];
    let ok2 = wing::parse_link_header("<https://cdn.example.com/bundle.js?v=1,2,3>; rel=preload; as=script", links2);
    t.assert_true(ok2, "uri with comma in query string must not break link parsing");
    t.assert_eq(links2.len, 1, "parsed exactly 1 link");
    t.assert_true(links2[0].uri[..] == "https://cdn.example.com/bundle.js?v=1,2,3", "query string with comma preserved");

    // 3. Case-insensitive parameters (RFC 8288 Section 3.2)
    var links3: wing::EarlyHintLink[..4] = [];
    let ok3 = wing::parse_link_header("<https://cdn.example.com/font.woff2>; REL=preload; AS=font; CrossOrigin", links3);
    t.assert_true(ok3, "case-insensitive param matching");
    t.assert_eq(links3.len, 1, "parsed 1 link");
    t.assert_true(links3[0].rel[..] == "preload", "rel matches");
    t.assert_true(links3[0].as_type[..] == "font", "as matches");
    t.assert_true(links3[0].crossorigin, "crossorigin set");

    // 4. Reject empty URI `<>`
    var links_bad1: wing::EarlyHintLink[..4] = [];
    let ok_bad1 = wing::parse_link_header("<>; rel=preload", links_bad1);
    t.assert_false(ok_bad1, "empty URI <> must be rejected");

    // 5. Reject characters between `>` and `;`
    var links_bad2: wing::EarlyHintLink[..4] = [];
    let ok_bad2 = wing::parse_link_header("<https://example.com>invalid; rel=preload", links_bad2);
    t.assert_false(ok_bad2, "characters between > and ; must be rejected");
}

fn main() {
    var runner = core::new_runner("HTTP Extensions Security Invariants Suite", core::Verbosity.Verbose);
    core::run_case(runner, "1. Resumable Upload Structured Fields", test_resumable_upload_structured_fields);
    core::run_case(runner, "2. Early Hints Link Header Security", test_early_hints_link_header_security);
    let ok = core::finish(runner);
    assert(ok);
}
