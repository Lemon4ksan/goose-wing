// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// tests/lit/cli_bug_hunter_regression.goose
// Regression test suite for CLI package bug-hunter audit findings.
//
// RUN: goose %s | %FileCheck %s

import std;
import core from "../..";
import wing from "../..";
import args from "../../cli";
import rules from "../../cli";

// B1: parse_route_rule_line must preserve modifiers and body when status has flaky fail_spec (503x2).
fn test_b1_flaky_route_modifiers_and_body() {
    var r = RouteRule { .. };
    let ok = parse_route_rule_line("GET /flaky -> 503x2 Location=/other \"hello world\"", r);
    assert(ok);
    assert(r.fail_status == 503);
    assert(r.fail_count == 2);
    assert(r.status_code == 200);
    assert(r.location[..] == "/other");
    assert(r.body[..] == "hello world");
    print("TEST_B1_FLAKY_ROUTE: OK");
}

// B2: extract_remote_filename must return "index.html" when URL ends with trailing slash.
fn test_b2_remote_filename_trailing_slash() {
    let fn1 = extract_remote_filename("http://example.com/");
    assert(fn1 == "index.html");
    let fn2 = extract_remote_filename("http://example.com/path/dir/");
    assert(fn2 == "index.html");
    let fn3 = extract_remote_filename("http://example.com/file.tar.gz?key=val#frag");
    assert(fn3 == "file.tar.gz");
    print("TEST_B2_REMOTE_FILENAME: OK");
}

// B3: append_json_escaped_bytes must preserve UTF-8 bytes (>= 0x80) and not silently strip them.
fn test_b3_json_utf8_preservation() {
    var out: u8[>..] = [];
    append_json_escaped_bytes("Hello, Привет!", out);
    assert(out[..] == "Hello, Привет!");
    print("TEST_B3_JSON_UTF8: OK");
}

// B4: parse_route_rule_line must reject oversized body (>2048) rather than silently truncating to empty.
fn test_b4_oversized_route_body_rejected() {
    var big_line: u8[>..] = [];
    big_line.append("GET /big -> 200 \"");
    for i in 2100 {
        big_line.push('x');
    }
    big_line.push('"');
    var r = RouteRule { .. };
    let ok = parse_route_rule_line(big_line[..], r);
    assert(!ok);
    print("TEST_B4_OVERSIZED_BODY: OK");
}

// B5: httpbin user-agent and cookies reflection must escape quotes in JSON.
fn test_b5_httpbin_reflection_escaping() {
    var stage = ProgrammableServerStage { .. };
    var req = wing::new_request("GET", "/user-agent");
    wing::set_header(req, "User-Agent", "Mozilla/5.0 (\"TestBot\")");
    var res = wing::Response { .. };
    let ok = handle_builtin_httpbin(stage, req, "127.0.0.1", res);
    assert(ok);
    assert(core::contains(res.body[..], "\\\"TestBot\\\""));

    var req2 = wing::new_request("GET", "/cookies");
    wing::set_header(req2, "Cookie", "user=\"alice\"; session=\"xyz\"");
    var res2 = wing::Response { .. };
    let ok2 = handle_builtin_httpbin(stage, req2, "127.0.0.1", res2);
    assert(ok2);
    assert(core::contains(res2.body[..], "\\\"alice\\\""));
    print("TEST_B5_HTTPBIN_ESCAPING: OK");
}

// B6: assign_positional_url must not leave URL partially populated if length exceeds cap.
fn test_b6_assign_positional_url_transactional() {
    var cfg = CliConfig { .. };
    var huge_arg: u8[>..] = [];
    for i in 2050 {
        huge_arg.push('a');
    }
    let ok = assign_positional_url(huge_arg[..], cfg);
    assert(!ok);
    assert(cfg.url.len == 0);
    print("TEST_B6_URL_TRANSACTIONAL: OK");
}

fn main() {
    test_b1_flaky_route_modifiers_and_body();
    test_b2_remote_filename_trailing_slash();
    test_b3_json_utf8_preservation();
    test_b4_oversized_route_body_rejected();
    test_b5_httpbin_reflection_escaping();
    test_b6_assign_positional_url_transactional();
}

// CHECK: TEST_B1_FLAKY_ROUTE: OK
// CHECK-NEXT: TEST_B2_REMOTE_FILENAME: OK
// CHECK-NEXT: TEST_B3_JSON_UTF8: OK
// CHECK-NEXT: TEST_B4_OVERSIZED_BODY: OK
// CHECK-NEXT: TEST_B5_HTTPBIN_ESCAPING: OK
// CHECK-NEXT: TEST_B6_URL_TRANSACTIONAL: OK
