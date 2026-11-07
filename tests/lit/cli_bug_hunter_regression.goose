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

// B7 (F001 & F006): HEAD body suppression in PreRoute ShortCircuit, HEAD matching GET rules, max_reqs Connection: close, and 404 JSON escaping.
fn test_b7_server_stage_head_and_max_reqs() {
    var stage = ProgrammableServerStage { max_reqs: 2, .. };
    var r = RouteRule { .. };
    assert(parse_route_rule_line("GET /hello -> 200 \"world\"", r));
    stage.rules.push(r);

    var req_head = wing::new_request("HEAD", "/hello");
    var res_head = wing::Response { .. };
    var note1: u8[..64] = [];
    let v1 = eval_programmable_server_stage(stage, wire::ServerHookPhase.PreRoute, req_head, res_head, note1);
    match v1 {
        ShortCircuit sc => { assert(sc.status_code == 200); },
        _ => { assert(false); },
    };
    assert(res_head.status_code == 200);
    assert(res_head.header("Content-Length") == "5");
    assert(res_head.body.len == 0);
    assert(res_head.header("Connection") == "");

    var req_404 = wing::new_request("GET", "/bad\"path");
    var res_404 = wing::Response { .. };
    var note2: u8[..64] = [];
    let v2 = eval_programmable_server_stage(stage, wire::ServerHookPhase.PreRoute, req_404, res_404, note2);
    match v2 {
        ShortCircuit sc => { assert(sc.status_code == 404); },
        _ => { assert(false); },
    };
    assert(res_404.status_code == 404);
    assert(res_404.header("Connection") == "close");
    assert(core::contains(res_404.body[..], "/bad\\\"path"));
    print("TEST_B7_SERVER_STAGE_HEAD: OK");
}

// B8 (F002): Unsatisfiable Range on /range/:n and /bytes/:n must return 416 Range Not Satisfiable (RFC 9110 §15.5.17).
fn test_b8_range_416_unsatisfiable() {
    var stage = ProgrammableServerStage { .. };
    var req = wing::new_request("GET", "/range/100");
    wing::set_header(req, "Range", "bytes=100-");
    var res = wing::Response { .. };
    assert(handle_builtin_httpbin(stage, req, "127.0.0.1", res));
    assert(res.status_code == 416);
    assert(res.header("Content-Range") == "bytes */100");
    assert(res.body.len == 0);
    print("TEST_B8_RANGE_416: OK");
}

// B9 (F003): Inline -b cookies seeded into CanonicalCookieJar survive encode_cookie_header_to_map.
fn test_b9_inline_cookies_preserved_in_jar() {
    var jar = wing::CanonicalCookieJar { .. };
    let now_us: i64 = 1750000000000000;
    seed_inline_cookies_to_jar(jar, "http://example.com/api", "sid=abc; theme=dark", now_us);
    var req = wing::new_request("GET", "http://example.com/api");
    wing::set_header(req, "Cookie", "sid=abc; theme=dark");
    let _ = wing::encode_cookie_header_to_map(
        jar,
        "example.com",
        "/api",
        "http",
        80,
        wing::CookieSourceOptions { is_http_api: true, url_is_secure: false },
        "",
        now_us,
        wing::CookieAccessOptions { is_same_site: true, is_top_level_navigation: true, is_safe_method: true, .. },
        req.headers,
    );
    let ck = req.header("Cookie");
    assert(core::contains(ck, "sid=abc"));
    assert(core::contains(ck, "theme=dark"));
    print("TEST_B9_INLINE_COOKIES: OK");
}

// B10 (F004): --form-string literal value and CRLF rejection in -F type=.
fn test_b10_multipart_form_edge_cases() {
    var cfg1 = CliConfig { .. };
    let argv1 = ["wing", "--form-string", "msg=@/nonexistent;type=text/plain", "http://example.com"];
    assert(parse_cli_args(argv1[..], cfg1));
    assert(!cfg1.form_fields[0].is_file);
    assert(cfg1.form_fields[0].value[..] == "@/nonexistent;type=text/plain");

    var cfg2 = CliConfig { .. };
    let argv2 = ["wing", "-F", "f=val;type=text/plain\r\nX-Inj: 1", "http://example.com"];
    assert(!parse_cli_args(argv2[..], cfg2));
    print("TEST_B10_MULTIPART_EDGE: OK");
}

// B11 (F005): Slashless URL extract_remote_filename, local # path in -F, HTTPS:// scheme fold, and -G #fragment / empty -d.
fn test_b11_uri_and_query_mode_edges() {
    assert(extract_remote_filename("http://example.com:8080") == "index.html");
    assert(extract_remote_filename("https://example.com?a=1") == "index.html");
    assert(extract_remote_filename("http://example.com/..") == "index.html");

    var cfg_f = CliConfig { .. };
    assert(parse_form_flag("doc=@dir/#notes.txt", cfg_f));
    assert(cfg_f.form_fields[0].filename[..] == "#notes.txt");

    var cfg_u = CliConfig { .. };
    assert(assign_positional_url("HTTPS://example.com/api", cfg_u));
    assert(cfg_u.url[..] == "HTTPS://example.com/api");

    var cfg_g1 = CliConfig { .. };
    let argv_g1 = ["wing", "-G", "-d", "k=v", "http://example.com/p#sec"];
    assert(parse_cli_args(argv_g1[..], cfg_g1));
    assert(cfg_g1.url[..] == "http://example.com/p?k=v#sec");

    var cfg_g2 = CliConfig { .. };
    let argv_g2 = ["wing", "-G", "-d", "", "http://example.com/p"];
    assert(parse_cli_args(argv_g2[..], cfg_g2));
    assert(!cfg_g2.has_body);
    print("TEST_B11_URI_AND_QUERY_EDGES: OK");
}

// B12 (F006 & F007): /headers JSON escaping, /basic-auth case-insensitive scheme, /bearer OWS trim, header/resolve/noproxy/-C validation.
fn test_b12_httpbin_and_validator_edges() {
    var stage = ProgrammableServerStage { .. };
    var req_h = wing::new_request("GET", "/headers");
    wing::set_header(req_h, "X-Test", "quoted \"val\"");
    var res_h = wing::Response { .. };
    assert(handle_builtin_httpbin(stage, req_h, "127.0.0.1", res_h));
    assert(core::contains(res_h.body[..], "\\\"val\\\""));

    var req_ba = wing::new_request("GET", "/basic-auth/user/pass");
    wing::set_header(req_ba, "Authorization", "basic dXNlcjpwYXNz");
    var res_ba = wing::Response { .. };
    assert(handle_builtin_httpbin(stage, req_ba, "127.0.0.1", res_ba));
    assert(res_ba.status_code == 200);

    var req_br = wing::new_request("GET", "/bearer");
    wing::set_header(req_br, "Authorization", "Bearer   my_tok  ");
    var res_br = wing::Response { .. };
    assert(handle_builtin_httpbin(stage, req_br, "127.0.0.1", res_br));
    assert(res_br.status_code == 200);
    assert(core::contains(res_br.body[..], "\"token\": \"my_tok\""));

    var cfg_v = CliConfig { .. };
    assert(!parse_header_flag("   : value", cfg_v));
    assert(!parse_header_flag("Bad Name: value", cfg_v));
    assert(!parse_resolve_flag("example.com:443:not-an-ip", cfg_v));
    assert(!apply_continue_at_opt("9223372036854775808", cfg_v));
    assert(host_matches_noproxy_token("[::1]", "::1"));
    assert(host_matches_noproxy_token("example.com", "example.com:8080"));
    assert(host_matches_noproxy_token("example.com.", ".example.com"));
    assert(!host_matches_noproxy_token("example.com", "."));
    print("TEST_B12_HTTPBIN_AND_VALIDATORS: OK");
}

fn main() {
    test_b1_flaky_route_modifiers_and_body();
    test_b2_remote_filename_trailing_slash();
    test_b3_json_utf8_preservation();
    test_b4_oversized_route_body_rejected();
    test_b5_httpbin_reflection_escaping();
    test_b6_assign_positional_url_transactional();
    test_b7_server_stage_head_and_max_reqs();
    test_b8_range_416_unsatisfiable();
    test_b9_inline_cookies_preserved_in_jar();
    test_b10_multipart_form_edge_cases();
    test_b11_uri_and_query_mode_edges();
    test_b12_httpbin_and_validator_edges();
}

// CHECK: TEST_B1_FLAKY_ROUTE: OK
// CHECK-NEXT: TEST_B2_REMOTE_FILENAME: OK
// CHECK-NEXT: TEST_B3_JSON_UTF8: OK
// CHECK-NEXT: TEST_B4_OVERSIZED_BODY: OK
// CHECK-NEXT: TEST_B5_HTTPBIN_ESCAPING: OK
// CHECK-NEXT: TEST_B6_URL_TRANSACTIONAL: OK
// CHECK-NEXT: TEST_B7_SERVER_STAGE_HEAD: OK
// CHECK-NEXT: TEST_B8_RANGE_416: OK
// CHECK-NEXT: TEST_B9_INLINE_COOKIES: OK
// CHECK-NEXT: TEST_B10_MULTIPART_EDGE: OK
// CHECK-NEXT: TEST_B11_URI_AND_QUERY_EDGES: OK
// CHECK-NEXT: TEST_B12_HTTPBIN_AND_VALIDATORS: OK
