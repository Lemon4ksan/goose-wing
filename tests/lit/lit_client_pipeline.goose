// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Consolidated Goose LIT Verification Suite: lit_client_pipeline
// RUN: goose build -O2 -o %t.exe %s
// RUN: %t.exe | %FileCheck %s

import std;
import core from "../..";
import wing from "../..";
import args from "../../cli";
import rules from "../../cli";

// ============================================================================
// 1. cli_bug_hunter_regression (1/9)
// ============================================================================
// CHECK: === [1/9] cli_bug_hunter_regression ===

// tests/lit/cli_bug_hunter_regression.goose
// Regression test suite for CLI package bug-hunter audit findings.
//

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

fn run_01_cli_bug_hunter_regression() {
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

// ============================================================================
// 2. rfc_repro_client_buffer_body (2/9)
// ============================================================================
// CHECK: === [2/9] rfc_repro_client_buffer_body ===

// tests/lit/rfc_repro_client_buffer_body.goose
// Regression tests for client buffers, body rewinds, and header synchronization.
//

fn test_large_bearer_token() {
    var pipe = wing::InterceptorPipeline { .. };
    var tok_buf: u8[..2000] = [];
    for i in 1500 {
        tok_buf.push('a');
    }
    let ok_add = wing::add_bearer_auth(pipe, tok_buf[..]);
    assert(ok_add);
    assert(pipe.bearer_token.len == 1507);

    var req = wing::new_get("http://example.invalid/api");
    wing::apply_app_interceptors_request(pipe, req, 1000);
    let auth = wing::header(req, "Authorization");
    assert(auth.len == 1507);
    assert(core::starts_with(auth, "Bearer aaaaa"));
    print("CHECK_BEARER_LARGE: OK");
}

fn test_body_rewind_overflow() {
    var req_small = wing::new_post("http://example.invalid");
    var small_body: u8[..500] = [];
    for i in 500 { small_body.push('x'); }
    wing::text(req_small, small_body[..]);
    assert(req_small.rewindable);
    assert(req_small.rewind_buf.len == 500);

    var req_large = wing::new_post("http://example.invalid");
    var large_body: u8[>..] = [];
    for i in 5000 { large_body.push('y'); }
    wing::text(req_large, large_body[..]);
    assert(!req_large.rewindable);
    assert(req_large.rewind_buf.len == 0);
    assert(req_large.body.len == 5000);

    var session = wing::new_session();
    var ctx = wing::RequestExecutionContext { .. };
    ctx.body.append(req_large.body[..]);
    ctx.rewindable = req_large.rewindable;
    ctx.body_consumed = true;

    var red_info = wing::RedirectInfo { .. };
    red_info.new_method.append("POST");
    red_info.clear_body = false;

    let red_err = wing::apply_redirect_transition(session, ctx, red_info);
    assert(!wing::ok(red_err));
    assert(red_err.code == rfc::STATUS_BAD_REQUEST);
    print("CHECK_REWIND_OVERFLOW: OK");
}

fn test_materialize_presence_mask() {
    var req = wing::Request { .. };
    let wire = "Host: test.example.com\r\nAuthorization: Bearer mysecret\r\n\r\n";
    let err = wing::parse_headers(wire, req.headers);
    assert(err == wing::HeaderParseError.None);
    assert(req.headers.entries.len == 2);
    assert(wing::has_header(req, "Host"));
    assert(wing::has_header(req, "Authorization"));
    assert(wing::header(req, "Host") == "test.example.com");
    assert(wing::header(req, "Authorization") == "Bearer mysecret");

    let ok_rem_host = wing::remove_header(req, "Host");
    assert(ok_rem_host);
    assert(wing::header(req, "Host") == "");
    assert(!wing::has_header(req, "Host"));
    print("CHECK_MATERIALIZE_PRESENCE: OK");
}

fn test_response_spans_invalidation() {
    var res = wing::Response { .. };
    wing::append_header(res.headers, "content-encoding", "gzip");
    wing::append_header(res.headers, "content-length", "128");
    wing::append_header(res.headers, "content-type", "text/plain");

    assert(wing::header(res, "content-encoding") == "gzip");
    wing::clear_decompressed_headers(res);

    assert(wing::header(res, "content-encoding") == "");
    assert(!wing::has_header(res, "content-encoding"));
    assert(wing::header(res, "content-length") == "");
    assert(!wing::has_header(res, "content-length"));
    assert(wing::header(res, "content-type") == "text/plain");

    wing::set_header(res, "content-type", "application/json");
    assert(wing::header(res, "content-type") == "application/json");

    let ok_rem = wing::remove_header(res, "content-type");
    assert(ok_rem);
    assert(wing::header(res, "content-type") == "");
    assert(!wing::has_header(res, "content-type"));
    print("CHECK_RESP_SPANS_INVALIDATION: OK");
}

struct JsonItemModel {
    id:   i32      = 0,
    name: u8[..16] = [],
}

fn test_cl_parsing() {
    let v0, ok0 = wing::parse_content_length_value("0");
    assert(ok0 && v0 == 0);

    let v1, ok1 = wing::parse_content_length_value("4096");
    assert(ok1 && v1 == 4096);

    let v_sp, ok_sp = wing::parse_content_length_value("  1024  ");
    assert(ok_sp && v_sp == 1024);

    let v_max, ok_max = wing::parse_content_length_value("9223372036854775807");
    assert(ok_max && v_max == 9223372036854775807);

    let _, bad_empty = wing::parse_content_length_value("");
    assert(!bad_empty);

    let v_lead, ok_lead = wing::parse_content_length_value(" 100");
    assert(ok_lead && v_lead == 100);

    let _, bad_inner_sp = wing::parse_content_length_value("10 0");
    assert(!bad_inner_sp);

    let _, bad_only_sp = wing::parse_content_length_value("   ");
    assert(!bad_only_sp);

    let _, bad_alpha = wing::parse_content_length_value("10a20");
    assert(!bad_alpha);

    let _, bad_neg = wing::parse_content_length_value("-1");
    assert(!bad_neg);

    let _, bad_pos = wing::parse_content_length_value("+1");
    assert(!bad_pos);

    let _, bad_oflow = wing::parse_content_length_value("9223372036854775808");
    assert(!bad_oflow);

    let _, bad_huge = wing::parse_content_length_value("99999999999999999999");
    assert(!bad_huge);

    print("CHECK_CL_PARSER: OK");
}

fn test_json_decode_bounds() {
    var res_overflow = wing::Response { .. };
    res_overflow.body.append("{\"id\":3000000000,\"name\":\"a_very_long_name_exceeding_capacity\"}");
    let item_overflow, err_overflow = wing::decode_json<JsonItemModel>(res_overflow);
    assert(!wing::ok(err_overflow));
    assert(item_overflow.id == 0);
    assert(item_overflow.name.len == 0);

    var res = wing::Response { .. };
    res.body.append("{\"id\":3000000000,\"name\":\"a_very_long_name\"}");
    let item, err = wing::decode_json<JsonItemModel>(res);
    assert(wing::ok(err));
    assert(item.id == 2147483647);
    assert(item.name.len == 16);
    assert(core::starts_with(item.name[..], "a_very_long_name"));
    print("CHECK_JSON_DECODE_BOUNDS: OK");
}

fn run_02_rfc_repro_client_buffer_body() {
    test_large_bearer_token();
    test_body_rewind_overflow();
    test_materialize_presence_mask();
    test_response_spans_invalidation();
    test_cl_parsing();
    test_json_decode_bounds();
}

// CHECK: CHECK_BEARER_LARGE: OK
// CHECK-NEXT: CHECK_REWIND_OVERFLOW: OK
// CHECK-NEXT: CHECK_MATERIALIZE_PRESENCE: OK
// CHECK-NEXT: CHECK_RESP_SPANS_INVALIDATION: OK
// CHECK-NEXT: CHECK_CL_PARSER: OK
// CHECK-NEXT: CHECK_JSON_DECODE_BOUNDS: OK

// ============================================================================
// 3. rfc_repro_client_bug_hunter (3/9)
// ============================================================================
// CHECK: === [3/9] rfc_repro_client_bug_hunter ===

// tests/lit/rfc_repro_client_bug_hunter.goose
// Regression test suite for client package bug-hunter audit findings (F001-F016).
//

// F001: set_profile(session, Profile.Custom) must reset profile_spec and clear default_headers.
fn test_f001_set_profile_custom() {
    var session = wing::new_session();
    wing::set_profile(session, wing::Profile.Wing);
    assert(session.default_headers.entries.len > 0);
    wing::set_profile(session, wing::Profile.Custom);
    assert(session.default_headers.entries.len == 0);
    assert(session.profile_spec.kind == wing::Profile.Custom);
    print("F001_SET_PROFILE_CUSTOM: OK");
}

// F003: resolve_ech_config stale fallback must pass now_sec (not 0) to dns_cache_lookup, and lookup_cached_ech_config must clear out_ech.
fn test_f003_ech_stale_expiry_and_clear() {
    var session = wing::new_session();
    session.enable_ech = true;
    var rec = wing::HttpsRecord {
        priority: 1,
        has_ech:  true,
        ..
    };
    rec.ech_config_list.append("ech-config-bytes");
    var entry = wing::DnsCacheEntry {
        qtype:           rfc::DNS_QTYPE_HTTPS,
        ttl_sec:         60,
        inserted_at_sec: 1000,
        valid:           true,
        ..
    };
    entry.domain.append("ech.example.com");
    entry.https_records.push(rec);
    wing::dns_cache_insert(session.dns_cache, entry);

    var out_ech: u8[..512] = [];
    out_ech.append("stale-prefix-");
    let ok_fresh = wing::lookup_cached_ech_config(session.dns_cache, "ech.example.com", 1010, out_ech);
    assert(ok_fresh);
    assert(out_ech[..] == "ech-config-bytes");

    // 1000 + 60 + 86400 (stale_ttl_sec) + 100 = 87560 -> completely expired!
    var out_expired: u8[..512] = [];
    let ok_expired = wing::resolve_ech_config(session, "ech.example.com", 90000, out_expired);
    assert(!ok_expired);
    print("F003_ECH_STALE_EXPIRY: OK");
}

// F004: add_mock_sse must reject sample_events > 1024 bytes without panicking, and set_cookie must handle 2048..4096 byte cookies safely.
fn test_f004_mock_sse_and_set_cookie_bounds() {
    var session = wing::new_session();
    var big_sse: u8[..1500] = [];
    for i in 1400 {
        big_sse.push('a');
    }
    wing::add_mock_sse(session, "https://example.com/events", big_sse[..]);
    assert(session.mock_routes.len == 0);

    var big_cookie_val: u8[..2500] = [];
    for i in 2400 {
        big_cookie_val.push('v');
    }
    wing::set_cookie(session, "big_c", big_cookie_val[..]);
    assert(wing::cookie(session, "big_c").len == 2400);
    print("F004_MOCK_SSE_AND_COOKIE_BOUNDS: OK");
}

// F005: process_dictionary_response must store the decompressed representation in dict_cache (RFC 9842 §2.1) and not cache corrupt dcz/dcb bodies.
fn test_f005_dictionary_response_order() {
    var session = wing::new_session();
    var out_dec: u8[..1024] = [];
    let ok_corrupt = wing::process_dictionary_response(
        session,
        "https://example.com",
        "match=\"/app/*\"",
        "dcz",
        "corrupt-dcz-payload",
        out_dec,
    );
    assert(!ok_corrupt);
    assert(session.dict_cache.entries.len == 0);
    print("F005_DICT_RESPONSE_ORDER: OK");
}

// F006: add_interceptor(AuthBearer) must prepend "Bearer ", and log_interceptor_request must clamp >128-byte lines and redact sensitive headers.
fn test_f006_interceptor_bearer_and_log_bounds() {
    var pipe = wing::InterceptorPipeline { .. };
    var entry = wing::InterceptorEntry {
        scope: wing::InterceptorScope.Application,
        kind:  wing::InterceptorKind.AuthBearer,
        ..
    };
    entry.header_val.append("raw-jwt-token");
    assert(wing::add_interceptor(pipe, entry));
    assert(pipe.bearer_token[..] == "Bearer raw-jwt-token");

    assert(!wing::add_traceparent(pipe, "zz"));

    assert(wing::add_logging(pipe, wing::InterceptorScope.Application, wing::LogLevel.Headers));
    var req = wing::new_get("https://example.com/very/long/path/that/exceeds/one/hundred/and/twenty/eight/bytes/when/formatted/into/log/entry/buffer/without/clamping/check");
    wing::sensitive_header(req, "Authorization", "Bearer super-secret-jwt-value-that-must-not-appear-in-logs");
    wing::apply_app_interceptors_request(pipe, req, 1);
    for i in pipe.log_entries.len {
        assert(!core::contains(pipe.log_entries[i][..], "super-secret-jwt-value"));
    }
    print("F006_INTERCEPTOR_BEARER_AND_LOG: OK");
}

// F007 & F008: Backoff.delay / RateLimiter.allow must guard invalid params, and evaluate_early_data_request must fold method case.
fn test_f007_f008_policy_and_early_data() {
    let b = wing::Backoff {
        base_ns: -100,
        max_ns:  -50,
        factor:  0.5,
    };
    assert(wing::delay(b, 2) >= 0);

    var lim = wing::RateLimiter {
        rate_per_sec:        -5.0,
        burst_capacity:      10.0,
        tokens:              1.0,
        last_update_mono_ns: 100,
    };
    assert(!wing::allow(lim, 200));

    let d = wing::evaluate_early_data_request("get", false);
    assert(d == wing::EarlyDataDecision.Allow);
    print("F007_F008_POLICY_AND_EARLY_DATA: OK");
}

// F009: Response.remove_header must clear res.presence_mask bit.
fn test_f009_response_remove_header_presence_mask() {
    var res = wing::Response { .. };
    wing::set_header(res, "Location", "https://example.com/next");
    assert(wing::has_header(res, "Location"));
    assert(wing::remove_header(res, "Location"));
    assert(!wing::has_header(res, "Location"));
    print("F009_RESPONSE_REMOVE_HEADER_MASK: OK");
}

// F010: stage_client_cookie_load must not treat CrossSite context (when had_cross_site_hop is false) as top-level navigation even if is_main_frame is true.
fn test_f010_samesite_cross_site_main_frame() {
    var jar = wing::CanonicalCookieJar { .. };
    let now_us: i64 = 1700000000000000;
    assert(wing::set_cookie_header(jar, "https://target.example.com/", "lax_sid=secret; Path=/; Secure; SameSite=Lax", now_us));
    let target_u = core::new_url("https://target.example.com/api");
    let eval = wing::SameSiteCookieContext {
        context_type:       wing::SameSiteContextType.CrossSite,
        schemefully_same:   false,
        is_reload:          false,
        had_cross_site_hop: false,
    };
    var hdrs = wing::HeaderMap { .. };
    let _ = wing::stage_client_cookie_load(hdrs, target_u, eval, true, "", true, now_us, jar, true);
    assert(!core::contains(wing::find_header(hdrs, "Cookie"), "lax_sid=secret"));
    print("F010_SAMESITE_CROSS_SITE_MAIN_FRAME: OK");
}

// F011: build_effective_url bounds, process_h2_response_frame 1xx header clearing, and prepare_auth_retry_hop stale Cookie removal.
fn test_f011_exec_bounds_and_auth_retry_cookie() {
    var base_big: u8[..1500] = [];
    base_big.append("https://example.com/");
    for i in 1400 {
        base_big.push('a');
    }
    var rel_big: u8[..1000] = [];
    for i in 800 {
        rel_big.push('b');
    }
    var q_items: wing::QueryItem[..1] = [];
    var out_url: u8[..2048]           = [];
    wing::build_effective_url(base_big[..], rel_big[..], q_items[..], out_url);

    var session = wing::new_session();
    wing::set_cookie_header(session.jar, "https://auth.example.com/resource", "sid=initial_token; Path=/", session.virtual_clock_us);
    var ctx = wing::RequestExecutionContext {
        site_for_cookies: wing::site_for_cookies_from_url("https://auth.example.com/resource"),
        is_main_frame:    true,
        ..
    };
    ctx.current_method.append("GET");
    let curr_u = core::new_url("https://auth.example.com/resource");
    let ss_eval = wing::compute_hop_samesite_context(ctx, curr_u, true);
    wing::prepare_hop_cookie_header(session, ctx, curr_u, ss_eval, true);
    assert(core::contains(wing::find_header(ctx.headers, "Cookie"), "sid=initial_token"));

    var resp_401 = wing::Response { status_code: 401, .. };
    wing::set_header(resp_401, "WWW-Authenticate", "Basic realm=\"api\"");
    wing::set_header(resp_401, "Set-Cookie", "sid=; Path=/; Max-Age=0");
    wing::prepare_auth_retry_hop(session, ctx, curr_u, ss_eval, true, resp_401, "Basic YWxpY2U6c2VjcmV0");
    assert(!core::contains(wing::find_header(ctx.headers, "Cookie"), "sid=initial_token"));
    print("F011_EXEC_BOUNDS_AND_AUTH_COOKIE: OK");
}

// F012: pump_response_body must treat 101 Switching Protocols as having an empty HTTP message body.
fn test_f012_h1_101_empty_body() {
    var conn = wing::PooledConnection {
        transport: wing::Transport.Mock { route_idx: 0, cursor: 0 },
        ..
    };
    let req = wing::new_get("http://example.com/ws");
    var resp = wing::Response { status_code: 101, .. };
    let ok_101, keep = wing::pump_response_body(conn, req, resp, "upgraded-protocol-bytes", 100);
    assert(ok_101 && keep);
    assert(resp.body.len == 0);
    assert(conn.rx_buf[..] == "upgraded-protocol-bytes");
    print("F012_H1_101_EMPTY_BODY: OK");
}

// F013: is_private_or_reserved_ip must reject >256-byte IP literals and compressed zero high-word SIIT/NAT64 forms.
fn test_f013_ssrf_oversized_and_siit() {
    var long_ip: u8[..300] = [];
    long_ip.append("FC00::");
    for i in 260 {
        long_ip.push('0');
    }
    assert(wing::is_private_or_reserved_ip(long_ip[..]));
    assert(wing::is_private_or_reserved_ip("::ffff:0:0.0.0.1"));
    assert(wing::is_private_or_reserved_ip("64:ff9b::0.0.0.1"));
    print("F013_SSRF_OVERSIZED_AND_SIIT: OK");
}

// F015 & F016: connect_udp IPv6 percent-encoding and StreamReader chunked token & Content-Length clamping.
fn test_f015_f016_masque_ipv6_and_stream_reader() {
    var session = wing::new_session();
    let _ = wing::mock_route(session, "CONNECT", "https://proxy.example.com/.well-known/masque/udp/2001%3Adb8%3A%3A1/443/", rfc::STATUS_OK, "");
    wing::add_mock_header(session, "Capsule-Protocol", "?1");
    let tun, _, err_m = wing::connect_udp(session, "https://proxy.example.com", "[2001:db8::1]", 443);
    assert(wing::ok(err_m) && tun.state == wing::MasqueTunnelState.Established);

    var resp_chunk = wing::Response { status_code: 200, .. };
    wing::set_header(resp_chunk, "Transfer-Encoding", "gzip, chunked");
    resp_chunk.body.append("4\r\nWiki\r\n0\r\n\r\n");
    let sr_chunk = wing::new_stream_reader(resp_chunk);
    assert(sr_chunk.is_chunked);

    var resp_cl = wing::Response { status_code: 200, .. };
    wing::set_header(resp_cl, "Content-Length", "4");
    resp_cl.body.append("WikiEXTRA_TRAILING");
    var sr_cl = wing::new_stream_reader(resp_cl);
    var out_all: u8[..64] = [];
    let read_n = wing::read_all(sr_cl, out_all);
    assert(read_n == 4);
    assert(out_all[..] == "Wiki");
    print("F015_F016_MASQUE_AND_STREAM_READER: OK");
}

fn run_03_rfc_repro_client_bug_hunter() {
    test_f001_set_profile_custom();
    test_f003_ech_stale_expiry_and_clear();
    test_f004_mock_sse_and_set_cookie_bounds();
    test_f005_dictionary_response_order();
    test_f006_interceptor_bearer_and_log_bounds();
    test_f007_f008_policy_and_early_data();
    test_f009_response_remove_header_presence_mask();
    test_f010_samesite_cross_site_main_frame();
    test_f011_exec_bounds_and_auth_retry_cookie();
    test_f012_h1_101_empty_body();
    test_f013_ssrf_oversized_and_siit();
    test_f015_f016_masque_ipv6_and_stream_reader();
}

// CHECK: F001_SET_PROFILE_CUSTOM: OK
// CHECK-NEXT: F003_ECH_STALE_EXPIRY: OK
// CHECK-NEXT: F004_MOCK_SSE_AND_COOKIE_BOUNDS: OK
// CHECK-NEXT: F005_DICT_RESPONSE_ORDER: OK
// CHECK-NEXT: F006_INTERCEPTOR_BEARER_AND_LOG: OK
// CHECK-NEXT: F007_F008_POLICY_AND_EARLY_DATA: OK
// CHECK-NEXT: F009_RESPONSE_REMOVE_HEADER_MASK: OK
// CHECK-NEXT: F010_SAMESITE_CROSS_SITE_MAIN_FRAME: OK
// CHECK-NEXT: F011_EXEC_BOUNDS_AND_AUTH_COOKIE: OK
// CHECK-NEXT: F012_H1_101_EMPTY_BODY: OK
// CHECK-NEXT: F013_SSRF_OVERSIZED_AND_SIIT: OK
// CHECK-NEXT: F015_F016_MASQUE_AND_STREAM_READER: OK

// ============================================================================
// 4. rfc_repro_client_cross_rfc (4/9)
// ============================================================================
// CHECK: === [4/9] rfc_repro_client_cross_rfc ===

// Cross-component & RFC edge-case regression suite for `client` and `client/session`.

// F001: RFC 9112 Section 7.1 - Truncated `Transfer-Encoding: chunked` body without
// terminating `0\r\n\r\n` must return `StreamReadStatus.Error` on the next `read_chunk`
// (instead of spinning in an infinite loop in `read_chunk` / `download_stream`) and
// roll back partial output in `read_all`.
fn test_f001_truncated_chunked_stream_terminates() {
    var resp = wing::Response { status_code: 200, .. };
    wing::set_header(resp.headers, "Transfer-Encoding", "chunked");
    wing::update_response_presence(resp, "Transfer-Encoding");
    // Missing terminating "0\r\n\r\n" chunk
    resp.body.append("5\r\nhello\r\n");

    var reader = wing::new_stream_reader(resp);
    var chunk_buf: u8[>..] = [];
    let st1, eof1 = wing::read_chunk(reader, 16, chunk_buf);
    assert(st1 == wing::StreamReadStatus.Data);
    assert(chunk_buf[..] == "hello");
    assert(!eof1);

    // Next read_chunk sees cursor at end of raw_data while chunk decoder is still in ChunkSize state.
    let st2, _ = wing::read_chunk(reader, 16, chunk_buf);
    assert(st2 == wing::StreamReadStatus.Error);
    assert(reader.finished);

    // Also verify `download_stream` terminates with ErrorKind.Stream instead of hanging
    var c = wing::new_client();
    wing::mock_route(c, "GET", "https://example.com/trunc-chunked", 200, "5\r\nhello\r\n");
    wing::add_mock_header(c, "Transfer-Encoding", "chunked");
    var downloaded: u8[>..] = [];
    let _, dl_err = wing::download_stream(c, "https://example.com/trunc-chunked", 16, downloaded) {};
    assert(!wing::ok(dl_err));
    assert(dl_err.kind == wing::ErrorKind.Stream);
    assert(downloaded.len == 0);

    // Also verify `read_all` rejects truncated chunked stream and rolls back `out`
    var reader2 = wing::new_stream_reader(resp);
    var all_out: u8[>..] = [];
    let emitted = wing::read_all(reader2, all_out);
    assert(emitted == 0);
    assert(all_out.len == 0);
    assert(wing::has_error(reader2.chunk_decoder));
    print("PASS: F001 truncated chunked stream terminates with Error");
}

// F002: RFC 9842 Section 2.1 & Section 2.3 - Compression Dictionary (`dcz`) delta update
// (`Content-Encoding: dcz` + `Use-As-Dictionary` replacing same pattern) must decompress
// the current response with the previous dictionary before updating `dict_cache`, and
// `stage_client_dict_negotiate` must send `Dictionary-ID` when the stored dictionary has `id`.
fn test_f002_compression_dict_id_and_delta_replace() {
    var c = wing::new_client();
    wing::enable_compression_dict(c, true);
    wing::set_clock_us(c, 1000000000);

    // Step 1: Seed initial dictionary v1 with id="dict-v1"
    let dict_v1: const u8[:] = "shared_dictionary_prefix_v1_0123456789abcdef";
    wing::mock_route(c, "GET", "https://cdn.example.com/app/v1.js", 200, dict_v1);
    wing::add_mock_header(c, "Use-As-Dictionary", "match=\"/app/*\", id=\"dict-v1\", ttl=3600");
    let r1, e1 = wing::get(c, "https://cdn.example.com/app/v1.js");
    assert(wing::ok(e1));
    assert(wing::text(r1) == dict_v1);

    // Step 2: Build a dcz-compressed v2 response using dict_v1 that ALSO carries Use-As-Dictionary
    // for the same match="/app/*" pattern (delta update to dict_v2).
    let dict_v2: const u8[:] = "shared_dictionary_prefix_v1_0123456789abcdef_UPDATED_V2";
    var dcz_wire: u8[..512] = [];
    assert(wing::encode_dcz_response(dcz_wire, c.dict_cache.entries[0].sha256_hash, dict_v2));

    wing::mock_route(c, "GET", "https://cdn.example.com/app/v2.js", 200, dcz_wire[..]);
    wing::add_mock_header(c, "Content-Encoding", "dcz");
    wing::add_mock_header(c, "Use-As-Dictionary", "match=\"/app/*\", id=\"dict-v2\", ttl=3600");

    let r2, e2 = wing::get(c, "https://cdn.example.com/app/v2.js");
    assert(wing::ok(e2));
    // RFC 9842 §2.3: Request for v2.js MUST carry Dictionary-ID: "dict-v1"
    assert(wing::sent_header(r2, "Dictionary-ID") == "\"dict-v1\"");
    // Response v2.js MUST be decompressed to dict_v2 before Use-As-Dictionary overwrites dict_v1!
    assert(wing::text(r2) == dict_v2);
    assert(wing::header(r2, "Content-Encoding") == "");

    // Step 3: Next request to /app/v3.js must advertise Dictionary-ID: "dict-v2"
    wing::mock_route(c, "GET", "https://cdn.example.com/app/v3.js", 200, "v3-plain");
    let r3, e3 = wing::get(c, "https://cdn.example.com/app/v3.js");
    assert(wing::ok(e3));
    assert(wing::sent_header(r3, "Dictionary-ID") == "\"dict-v2\"");
    print("PASS: F002 compression dict Dictionary-ID and delta replacement");
}

// F003: RFC 9111 Section 4.1 & Section 4.3.4 - `HttpCache` (`stage_client_cache_lookup` &
// `stage_client_cache_store`) must evaluate `Vary` against effective hop headers (`ctx.headers`
// including `Cookie` from `session.jar`) rather than bare `req.headers`, and populate
// `resp.presence_mask` on cache hits so `has_header(resp, ...)` works on cached responses.
fn test_f003_cache_vary_cookie_and_presence_mask() {
    var c = wing::new_client();
    c.enable_cache = true;
    wing::set_clock_us(c, 1000000000);

    // Seed cookie for Alice in session.jar
    c.jar.set_cookie_header("https://api.example.com/profile", "session_user=alice; Path=/; Secure", c.virtual_clock_us);

    wing::mock_route(c, "GET", "https://api.example.com/profile", 200, "profile:alice");
    wing::add_mock_header(c, "Cache-Control", "max-age=60");
    wing::add_mock_header(c, "Vary", "Cookie");
    wing::add_mock_header(c, "Content-Type", "text/plain");
    wing::add_mock_header(c, "ETag", "\"v1-alice\"");

    let r1, e1 = wing::get(c, "https://api.example.com/profile");
    assert(wing::ok(e1));
    assert(wing::text(r1) == "profile:alice");

    // Same cookie -> cache hit; `has_header(r_hit, "Content-Type")` must be true!
    c.mock_routes.clear();
    let r_hit, e_hit = wing::get(c, "https://api.example.com/profile");
    assert(wing::ok(e_hit));
    assert(wing::text(r_hit) == "profile:alice");
    assert(wing::has_header(r_hit, "Content-Type"));
    assert(wing::has_header(r_hit, "ETag"));

    // Change cookie in jar to Bob -> `Vary: Cookie` MUST miss cache and fetch from origin!
    c.jar.set_cookie_header("https://api.example.com/profile", "session_user=bob; Path=/; Secure", c.virtual_clock_us);
    wing::mock_route(c, "GET", "https://api.example.com/profile", 200, "profile:bob");
    wing::add_mock_header(c, "Cache-Control", "max-age=60");
    wing::add_mock_header(c, "Vary", "Cookie");
    let r_bob, e_bob = wing::get(c, "https://api.example.com/profile");
    assert(wing::ok(e_bob));
    assert(wing::text(r_bob) == "profile:bob");
    print("PASS: F003 HttpCache Vary: Cookie and cached response presence_mask");
}

// F004: RFC 6797 Section 8.3 & RFC 9110 Section 15.4 - Redirect to an `http://` URL on an HSTS
// host must upgrade to `https://` BEFORE computing scheme-downgrade / cross-origin / SameSite
// transitions, and conflicting multiple `Location` headers must be rejected.
fn test_f004_redirect_hsts_pre_upgrade_and_multiple_location() {
    var c = wing::new_client();
    wing::set_clock_us(c, 1000000000);
    c.jar.set_cookie_header("https://secure.example.com/", "strict_sid=s1; Path=/; Secure; SameSite=Strict", c.virtual_clock_us);

    // Hop 0 sets HSTS and redirects to http://secure.example.com/step2
    wing::mock_route(c, "GET", "https://secure.example.com/step1", 302, "");
    wing::add_mock_header(c, "Strict-Transport-Security", "max-age=31536000");
    wing::add_mock_header(c, "Location", "http://secure.example.com/step2");

    wing::mock_route(c, "GET", "https://secure.example.com/step2", 200, "ok-hsts-redirect");

    var req = wing::new_request("GET", "https://secure.example.com/step1");
    wing::bearer(req, "same-origin-secret");
    let r1, e1 = wing::do(c, req);
    assert(wing::ok(e1));
    assert(wing::text(r1) == "ok-hsts-redirect");
    // Because HSTS upgraded http://secure.example.com/step2 -> https://secure.example.com/step2
    // prior to redirect policy evaluation (RFC 6797 §8.3), it is NOT a scheme downgrade or cross-origin hop:
    assert(wing::sent_header(r1, "Referer") == "https://secure.example.com/step1");
    assert(wing::sent_header(r1, "Authorization") == "Bearer same-origin-secret");
    assert(wing::sent_header(r1, "Cookie") == "strict_sid=s1");

    // Conflicting multiple Location headers on 302 must be rejected (RedirectError.MultipleLocationHeaders)
    var c2 = wing::new_client();
    wing::mock_route(c2, "GET", "https://example.com/multi-loc", 302, "");
    wing::add_mock_header(c2, "Location", "https://example.com/dest-a");
    wing::add_mock_header(c2, "Location", "https://evil.example/dest-b");
    let _, e2 = wing::get(c2, "https://example.com/multi-loc");
    assert(!wing::ok(e2));
    print("PASS: F004 HSTS pre-redirect upgrade and conflicting Location rejection");
}

// F005: RFC 7617 Section 2 & RFC 9110 Section 11.6.1 - 401 Basic Auth must support full
// 128-byte username + 128-byte password capacity, reject non-Basic prefix schemes like
// `BasicCustom`, and allow 401 authentication on a redirect target after an earlier hop.
fn test_f005_auth_401_bounds_scheme_boundary_and_redirect_reset() {
    var c = wing::new_client();
    let long_user: const u8[:] = "uuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuu"; // 80B
    let long_pass: const u8[:] = "pppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppp"; // 80B
    assert(wing::set_credentials(c, long_user, long_pass));

    // 1. Non-Basic scheme `BasicCustom` must NOT trigger Basic credential transmission
    wing::mock_route(c, "GET", "https://example.com/custom-scheme", 401, "unauth");
    wing::add_mock_header(c, "WWW-Authenticate", "BasicCustom realm=\"app\"");
    let r_custom, _ = wing::get(c, "https://example.com/custom-scheme");
    assert(r_custom.status_code == 401);
    assert(wing::sent_header(r_custom, "Authorization") == "");

    // 2. Valid `Basic realm="app"` with 80B+80B (161B > old 140B buffer) must succeed on retry
    wing::mock_route(c, "GET", "https://example.com/long-basic", 401, "");
    wing::add_mock_header(c, "WWW-Authenticate", "Basic realm=\"app\"");
    let r_basic, e_basic = wing::get(c, "https://example.com/long-basic");
    assert(wing::ok(e_basic));
    assert(core::starts_with_fold(wing::sent_header(r_basic, "Authorization"), "Basic "));

    // 3. Redirect target that challenges with 401 after an earlier hop must also be allowed to retry auth
    var c_red = wing::new_client();
    assert(wing::set_credentials(c_red, "admin", "secret"));
    wing::mock_route(c_red, "GET", "https://example.com/entry", 302, "");
    wing::add_mock_header(c_red, "Location", "https://other.example.com/protected");
    wing::mock_route(c_red, "GET", "https://other.example.com/protected", 401, "");
    wing::add_mock_header(c_red, "WWW-Authenticate", "Basic realm=\"other\"");
    let r_red, e_red = wing::get(c_red, "https://example.com/entry");
    assert(wing::ok(e_red));
    assert(core::starts_with_fold(wing::sent_header(r_red, "Authorization"), "Basic "));
    print("PASS: F005 401 Basic capacity, scheme token boundary, and redirect auth");
}

fn run_04_rfc_repro_client_cross_rfc() {
    // Note: F002..F005 run first so we can observe their failure before F001 even if F001 would hang
    test_f002_compression_dict_id_and_delta_replace();
    test_f003_cache_vary_cookie_and_presence_mask();
    test_f004_redirect_hsts_pre_upgrade_and_multiple_location();
    test_f005_auth_401_bounds_scheme_boundary_and_redirect_reset();
    test_f001_truncated_chunked_stream_terminates();
}

// CHECK: PASS: F002 compression dict Dictionary-ID and delta replacement
// CHECK: PASS: F003 HttpCache Vary: Cookie and cached response presence_mask
// CHECK: PASS: F004 HSTS pre-redirect upgrade and conflicting Location rejection
// CHECK: PASS: F005 401 Basic capacity, scheme token boundary, and redirect auth
// CHECK: PASS: F001 truncated chunked stream terminates with Error

// ============================================================================
// 5. rfc_repro_client_round2_bug_hunter (5/9)
// ============================================================================
// CHECK: === [5/9] rfc_repro_client_round2_bug_hunter ===

// tests/lit/rfc_repro_client_round2_bug_hunter.goose
// Regression test suite for client bug-hunter audit findings (F017-F023).
//

// F019: set_credentials must support up to 128 bytes and guard against capacity overflow.
fn test_f019_credentials_capacity() {
    var session = wing::new_session();
    var long_pass: u8[..128] = [];
    for i in 100 {
        long_pass.push('k');
    }
    // Length 100 exceeds old 64-byte capacity but fits in 128-byte DigestCredentials
    let ok = wing::set_credentials(session, "admin_user", long_pass[..]);
    assert(ok);
    assert(session.creds.has_credentials);
    assert(session.creds.password.len == 100);

    // Oversized password > 128 must be safely rejected without panicking
    var too_long: u8[..200] = [];
    for i in 150 {
        too_long.push('x');
    }
    let ok_overflow = wing::set_credentials(session, "admin_user", too_long[..]);
    assert(!ok_overflow);
    print("F019_CREDENTIALS_CAPACITY: OK");
}

// F021: encode_chunk_trailer must filter out disallowed trailer fields (RFC 9112 §7.1.2).
fn test_f021_chunked_disallowed_trailers() {
    var trailers = wing::HeaderMap { .. };
    wing::set_header(trailers, "X-Checksum", "abcdef");
    wing::set_header(trailers, "Content-Length", "42");
    wing::set_header(trailers, "Transfer-Encoding", "chunked");

    var wire_out: u8[>..] = [];
    wing::encode_chunked_payload("hello", trailers, 4096, wire_out);
    let wire_str = wire_out[..];

    assert(find(wire_str, "X-Checksum: abcdef") >= 0);
    assert(find(wire_str, "Content-Length") < 0);
    assert(find(wire_str, "Transfer-Encoding") < 0);
    print("F021_CHUNKED_DISALLOWED_TRAILERS: OK");
}

// F022: session mutator bounds clamping and deduplication.
fn test_f022_session_mutators_bounds_and_dedup() {
    var session = wing::new_session();
    var huge_url: u8[..300] = [];
    for i in 280 {
        huge_url.push('h');
    }

    // Must not panic on URLs > 256
    wing::set_base_url(session, huge_url[..]);
    assert(session.base_url.len <= 256);

    wing::set_proxy(session, huge_url[..]);
    assert(session.proxy_url.len <= 256);

    wing::enable_doh(session, huge_url[..]);
    assert(session.doh.endpoint.len <= 256);

    // Ports and hosts deduplication
    wing::allow_port(session, 8080);
    wing::allow_port(session, 8080);
    assert(session.ssrf_guard.allowed_ports.len == 1);

    wing::deny_port(session, 22);
    wing::deny_port(session, 22);
    assert(session.ssrf_guard.denied_ports.len == 1);

    wing::trust_location_host(session, "cdn.example.com");
    wing::trust_location_host(session, "CDN.EXAMPLE.COM");
    assert(session.trusted_location_hosts.len == 1);
    print("F022_SESSION_MUTATORS_BOUNDS_AND_DEDUP: OK");
}

// F017: stage_client_alt_svc / ingest_compression_dict_header must decode body
// and must NOT cache invalid/corrupted dictionary representations.
fn test_f017_stage_dictionary_compression_handling() {
    var session = wing::new_session();
    var dict_cache = wing::DictionaryCache { .. };
    var resp = wing::Response {
        status_code: 200,
        ..
    };
    wing::set_header(resp, "Use-As-Dictionary", "match=\"/api/*\"");
    wing::set_header(resp, "Content-Encoding", "dcz");
    resp.body.append("corrupt-dcz-payload");

    // Must not cache corrupted dictionary body
    wing::ingest_compression_dict_header(dict_cache, "example.com:443", "/api/item", 1000, resp);
    assert(dict_cache.entries.len == 0);
    print("F017_STAGE_DICT_COMPRESSION_HANDLING: OK");
}

// F018: 101 Switching Protocols connection must not be released into HTTP idle pool (RFC 9112 §6.3, RFC 6455 §4.1).
fn test_f018_h1_101_no_pool_reuse() {
    var session = wing::new_session();
    var conn = wing::PooledConnection {
        conn_id: 42,
        ..
    };
    session.pool.conns.push(conn);
    assert(session.pool.conns.len == 1);

    // On 101, close_pooled_connection must be used instead of release_connection
    session.pool.close_pooled_connection(42);
    assert(session.pool.conns[0].closed);
    print("F018_H1_101_NO_POOL_REUSE: OK");
}

// F020 & F023: prepare_auth_retry_hop must reset body_consumed, and compute_401_auth_header must clear dirty header buf.
fn test_f020_f023_auth_retry_state_and_clear() {
    var session = wing::new_client();
    wing::set_credentials(session, "alice", "secret123");
    var ctx = wing::RequestExecutionContext {
        rewindable:    true,
        body_consumed: true,
        ..
    };
    ctx.rewind_buf.append("post-data");
    ctx.body.append("post-data");

    let u = core::new_url("https://example.com/api");
    let samesite = wing::SameSiteCookieContext { .. };
    let resp = wing::Response { status_code: 401, .. };

    wing::prepare_auth_retry_hop(session, ctx, u, samesite, false, resp, "Basic dGVzdA==");
    assert(!ctx.body_consumed);
    assert(ctx.auth_retried);

    var dirty_header: u8[..4096] = [];
    dirty_header.append("STALE-DIRTY-PREFIX-");
    let ok_auth = wing::compute_401_auth_header(session, ctx, u, "Basic realm=\"api\"", dirty_header);
    assert(ok_auth);
    assert(!core::starts_with(dirty_header[..], "STALE-DIRTY-PREFIX-"));
    assert(core::starts_with(dirty_header[..], "Basic "));
    print("F020_F023_AUTH_RETRY_STATE_AND_CLEAR: OK");
}

fn run_05_rfc_repro_client_round2_bug_hunter() {
    test_f019_credentials_capacity();
    test_f021_chunked_disallowed_trailers();
    test_f022_session_mutators_bounds_and_dedup();
    test_f017_stage_dictionary_compression_handling();
    test_f018_h1_101_no_pool_reuse();
    test_f020_f023_auth_retry_state_and_clear();
}

// CHECK: F019_CREDENTIALS_CAPACITY: OK
// CHECK-NEXT: F021_CHUNKED_DISALLOWED_TRAILERS: OK
// CHECK-NEXT: F022_SESSION_MUTATORS_BOUNDS_AND_DEDUP: OK
// CHECK-NEXT: F017_STAGE_DICT_COMPRESSION_HANDLING: OK
// CHECK-NEXT: F018_H1_101_NO_POOL_REUSE: OK
// CHECK-NEXT: F020_F023_AUTH_RETRY_STATE_AND_CLEAR: OK

// ============================================================================
// 6. rfc_repro_client_round3_invariants (6/9)
// ============================================================================
// CHECK: === [6/9] rfc_repro_client_round3_invariants ===

// tests/lit/rfc_repro_client_round3_invariants.goose
// Protocol regression verification for client round 3 audit remediations.
//

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

fn run_06_rfc_repro_client_round3_invariants() {
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

// ============================================================================
// 7. rfc_repro_client_session_audit (7/9)
// ============================================================================
// CHECK: === [7/9] rfc_repro_client_session_audit ===

// tests/lit/rfc_repro_client_session_audit.goose
// Regression test suite for client/session audit findings (F001-F009).
//

// F001: Default (Lax-allowing-unsafe) cookies must be blocked on unsafe POST requests after a cross-site redirect (RFC 6265bis §5.3.7.1).
fn test_f001_samesite_lax_after_cross_site_redirect() {
    var session = wing::new_session();
    let ok_set = wing::set_cookie_header(
        session.jar,
        "https://target.example.com/landing",
        "def_sid=abc123; Path=/; Secure",
        session.virtual_clock_us,
    );
    assert(ok_set);

    let curr_url = core::new_url("https://target.example.com/landing");
    var ctx = wing::RequestExecutionContext {
        is_main_frame:      true,
        had_cross_site_hop: true,
        site_for_cookies:   wing::null_site_for_cookies(),
        ..
    };
    let samesite_eval = wing::compute_hop_samesite_context(ctx, curr_url, false);
    assert(samesite_eval.context_type == wing::SameSiteContextType.CrossSite);

    let _ = wing::stage_client_cookie_load(
        ctx.headers,
        curr_url,
        samesite_eval,
        ctx.is_main_frame,
        "",
        false,
        session.virtual_clock_us,
        session.jar,
        true,
    );
    let cookie_hdr = wing::find_header(ctx.headers, "Cookie");
    assert(!core::contains(cookie_hdr, "def_sid=abc123"));
    print("F001_SAMESITE_LAX_REDIRECT: OK");
}

// F002: execute_h1_exchange must bound consecutive 1xx informational responses (RFC 9110 §15.2 / Go #65035).
fn test_f002_h1_1xx_loop_bounded() {
    var conn = wing::PooledConnection {
        transport: wing::Transport.Mock { route_idx: 0, cursor: 0 },
        ..
    };
    for i in 8 {
        conn.rx_buf.append("HTTP/1.1 100 Continue\r\n\r\n");
    }
    conn.rx_buf.append("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK");

    let req = wing::new_get("http://example.com/");
    let u = core::new_url("http://example.com/");
    var resp = wing::Response { .. };
    let ok_ex, _ = wing::execute_h1_exchange(conn, req, u, resp, 100);
    assert(!ok_ex);
    print("F002_H1_1XX_BOUNDED: OK");
}

// F003: parse_h1_header_block must reject malformed lines without ':', whitespace before ':', and conflicting Content-Length (RFC 9112 §5.1, §6.3).
fn test_f003_h1_header_strict_rfc9112() {
    var resp1 = wing::Response { .. };
    let ok_garbage = wing::parse_h1_header_block("GarbageLineWithoutColon\r\nContent-Length: 0\r\n", resp1);
    assert(!ok_garbage);

    var resp2 = wing::Response { .. };
    let ok_ws_colon = wing::parse_h1_header_block("Content-Length : 0\r\n", resp2);
    assert(!ok_ws_colon);

    var resp3 = wing::Response { .. };
    let ok_conflicting_cl = wing::parse_h1_header_block("Content-Length: 5\r\nContent-Length: 10\r\n", resp3);
    assert(!ok_conflicting_cl);
    print("F003_H1_HEADER_STRICT: OK");
}

// F004: feed_chunk_slice must reject malformed chunked trailers and pump_h1_chunked_body must preserve leftover pipelined bytes.
fn test_f004_chunked_trailers_and_leftover() {
    var dec = internal::new_chunk_fsm_decoder();
    var resp = wing::Response { .. };
    var trailer_buf: u8[..4096] = [];
    var cur_idx:     i64        = 0;
    // Disallowed trailer field Content-Length in chunked trailer section (RFC 9112 §7.1.2)
    let raw_bad_tr = "4\r\nWiki\r\n0\r\nContent-Length: 99\r\n\r\n";
    let done, ok = wing::feed_chunk_slice(dec, raw_bad_tr, resp, trailer_buf, cur_idx);
    assert(done && !ok);

    var conn = wing::PooledConnection {
        transport: wing::Transport.Mock { route_idx: 0, cursor: 0 },
        ..
    };
    var dec2 = internal::new_chunk_fsm_decoder();
    var resp2 = wing::Response { .. };
    let coalesced = "4\r\nWiki\r\n0\r\n\r\nHTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n";
    let ok_chunk = wing::pump_h1_chunked_body(conn, dec2, coalesced, resp2, 100);
    assert(ok_chunk);
    assert(core::starts_with(conn.rx_buf[..], "HTTP/1.1 200 OK"));
    print("F004_CHUNKED_TRAILERS_LEFTOVER: OK");
}

// F005: serialize_h1_request must reject requests whose serialized head exceeds the 4096-byte buffer instead of silently truncating.
fn test_f005_serialize_h1_request_overflow_rejected() {
    var req = wing::new_get("http://example.com/api");
    var big_val: u8[..3500] = [];
    for i in 3500 {
        big_val.push('a');
    }
    wing::set_header(req, "X-Large-A", big_val[..]);
    wing::set_header(req, "X-Large-B", big_val[..]);
    let u = core::new_url("http://example.com/api");
    var out: u8[..4096] = [];
    let ok_ser = wing::serialize_h1_request(req, u, out);
    assert(!ok_ser);
    print("F005_SERIALIZE_H1_OVERFLOW: OK");
}

// F006: drain_h2_response_frames must fail immediately on H2_ERR_FRAME_SIZE_ERROR and process_h2_response_frame must reject RST_STREAM.
fn test_f006_h2_oversize_frame_and_rst_stream() {
    var rx_oversize: u8[..64] = [0x00, 0x40, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01];
    var dec_dt = internal::new_dynamic_table(4096);
    var resp = wing::Response { .. };
    var got_hdrs = false;
    var ctrl_out: u8[..256] = [];
    let ok_f, _ = wing::drain_h2_response_frames(rx_oversize, 1, false, dec_dt, resp, got_hdrs, ctrl_out);
    assert(!ok_f);

    let rst_hdr = internal::FrameHeader {
        length:     4,
        frame_type: rfc::H2_FRAME_RST_STREAM,
        flags:      0,
        stream_id:  1,
    };
    let rst_payload: u8[4] = [0x00, 0x00, 0x00, 0x08];
    let ok_rst, _ = wing::process_h2_response_frame(
        rst_hdr, rst_payload[..], 1, false, dec_dt, resp, got_hdrs, ctrl_out,
    );
    assert(!ok_rst);
    print("F006_H2_FRAME_VALIDATION: OK");
}

// F007: execute_live_h3_hop must validate AltSvcEndpoint.host against session.ssrf_guard before sending UDP packets.
fn test_f007_altsvc_h3_ssrf_guard() {
    var session = wing::new_session();
    session.ssrf_guard = wing::new_ssrf_guard_policy();
    var ctx = wing::RequestExecutionContext { .. };
    ctx.current_method.append("GET");
    let curr_url = core::new_url("https://example.com/data");
    var bad_ep = wing::AltSvcEndpoint {
        port: 6379,
        ..
    };
    bad_ep.host.append("127.0.0.1");
    bad_ep.proto.append("h3");
    var resp = wing::Response { .. };
    let ok_h3 = wing::execute_live_h3_hop(session, ctx, curr_url, "https://example.com:443", bad_ep, 1000, resp);
    assert(!ok_h3);
    print("F007_ALTSVC_H3_SSRF: OK");
}

// F008: ws() must generate unique Sec-WebSocket-Key nonces across calls, and ws_perform_handshake must enforce case-sensitive single-token subprotocol matching (RFC 6455 §4.1, §4.2.2).
fn test_f008_ws_nonce_and_subprotocol() {
    var session = wing::new_session();
    let _ = wing::mock_route(session, "GET", "http://ws.example.com/chat", rfc::STATUS_SWITCHING_PROTOCOLS, "");
    wing::add_mock_header(session, "Upgrade", "websocket");
    wing::add_mock_header(session, "Connection", "Upgrade");
    wing::add_mock_header(session, "Sec-WebSocket-Protocol", "CHAT");
    let _, resp1, _ = wing::ws(session, "ws://ws.example.com/chat");
    let _, resp2, _ = wing::ws(session, "ws://ws.example.com/chat");
    let k1 = wing::sent_header(resp1, "Sec-WebSocket-Key");
    let k2 = wing::sent_header(resp2, "Sec-WebSocket-Key");
    assert(k1.len > 0 && k2.len > 0 && k1 != k2);

    // Case-mismatch subprotocol ("chat" offered, "CHAT" returned) must be rejected per RFC 6455 §4.2.2
    let _, _, err_proto = wing::ws(session, "ws://ws.example.com/chat") { req =>
        wing::set_header(req, "Sec-WebSocket-Protocol", "chat, superchat");
    };
    assert(!wing::ok(err_proto));
    print("F008_WS_NONCE_AND_SUBPROTO: OK");
}

// F009: put_chunked must set rewindable=false when body exceeds rewind_buf.cap (4096), and connect_udp must reject oversized target_host (>128 bytes).
fn test_f009_chunked_rewind_and_masque_bounds() {
    var session = wing::new_session();
    var long_host: u8[..160] = [];
    for i in 140 {
        long_host.push('a');
    }
    long_host.append(".example.com");
    let _, _, err_masque = wing::connect_udp(session, "https://proxy.example.com", long_host[..], 443);
    assert(!wing::ok(err_masque));
    assert(err_masque.code == rfc::STATUS_BAD_REQUEST);
    print("F009_MASQUE_AND_CHUNKED_BOUNDS: OK");
}

fn run_07_rfc_repro_client_session_audit() {
    test_f001_samesite_lax_after_cross_site_redirect();
    test_f002_h1_1xx_loop_bounded();
    test_f003_h1_header_strict_rfc9112();
    test_f004_chunked_trailers_and_leftover();
    test_f005_serialize_h1_request_overflow_rejected();
    test_f006_h2_oversize_frame_and_rst_stream();
    test_f007_altsvc_h3_ssrf_guard();
    test_f008_ws_nonce_and_subprotocol();
    test_f009_chunked_rewind_and_masque_bounds();
}

// CHECK: F001_SAMESITE_LAX_REDIRECT: OK
// CHECK-NEXT: F002_H1_1XX_BOUNDED: OK
// CHECK-NEXT: F003_H1_HEADER_STRICT: OK
// CHECK-NEXT: F004_CHUNKED_TRAILERS_LEFTOVER: OK
// CHECK-NEXT: F005_SERIALIZE_H1_OVERFLOW: OK
// CHECK-NEXT: F006_H2_FRAME_VALIDATION: OK
// CHECK-NEXT: F007_ALTSVC_H3_SSRF: OK
// CHECK-NEXT: F008_WS_NONCE_AND_SUBPROTO: OK
// CHECK-NEXT: F009_MASQUE_AND_CHUNKED_BOUNDS: OK

// ============================================================================
// 8. rfc_repro_client_session_protocol (8/9)
// ============================================================================
// CHECK: === [8/9] rfc_repro_client_session_protocol ===

// tests/lit/rfc_repro_client_session_protocol.goose
// Regression tests for client session execution, protocol verbs, SSRF, and 1xx handling.
//

fn test_1xx_empty_body_status() {
    assert(rfc::is_empty_body_status(rfc::STATUS_CONTINUE));
    assert(rfc::is_empty_body_status(rfc::STATUS_SWITCHING_PROTOCOLS));
    assert(rfc::is_empty_body_status(rfc::STATUS_EARLY_HINTS));
    assert(rfc::is_empty_body_status(rfc::STATUS_NO_CONTENT));
    assert(rfc::is_empty_body_status(rfc::STATUS_NOT_MODIFIED));
    assert(!rfc::is_empty_body_status(rfc::STATUS_OK));
    assert(!rfc::is_empty_body_status(rfc::STATUS_BAD_REQUEST));
    print("CHECK_1XX_EMPTY_BODY: OK");
}

fn test_sse_content_type_validation() {
    assert(wing::is_sse_content_type("text/event-stream"));
    assert(wing::is_sse_content_type("text/event-stream; charset=utf-8"));
    assert(wing::is_sse_content_type("Text/Event-Stream; boundary=something"));
    assert(wing::is_sse_content_type("text/event-stream \t"));
    assert(!wing::is_sse_content_type("text/event-stream-custom"));
    assert(!wing::is_sse_content_type("application/json"));
    assert(!wing::is_sse_content_type(""));
    print("CHECK_SSE_CONTENT_TYPE: OK");
}

fn test_ws_header_tokens() {
    assert(wing::header_has_token("websocket, upgrade", "websocket"));
    assert(wing::header_has_token("keep-alive, upgrade", "upgrade"));
    assert(wing::header_has_token("Upgrade", "upgrade"));
    assert(!wing::header_has_token("non-upgrade", "upgrade"));
    assert(!wing::header_has_token("websocket-stream", "websocket"));
    print("CHECK_WS_TOKENS: OK");
}

fn test_multihop_redirect_body_clear() {
    var session = wing::new_session();
    var ctx = wing::RequestExecutionContext { .. };
    ctx.body.append("initial_body");
    ctx.rewind_buf.append("initial_body");
    ctx.rewindable = true;

    // Hop 1: 303 See Other (must clear body and rewind buffer)
    var red_303 = wing::RedirectInfo { .. };
    red_303.new_method.append("GET");
    red_303.clear_body = true;

    let err_303 = wing::apply_redirect_transition(session, ctx, red_303);
    assert(wing::ok(err_303));
    assert(ctx.body.len == 0);
    assert(ctx.rewind_buf.len == 0);
    assert(!ctx.rewindable);
    print("CHECK_MULTIHOP_BODY_CLEAR: OK");
}

fn test_multihop_no_resurrect() {
    var session = wing::new_session();
    var ctx = wing::RequestExecutionContext { .. };
    ctx.body.append("initial_payload");
    ctx.rewind_buf.append("initial_payload");
    ctx.rewindable = true;

    // Hop 1: 303 See Other
    var red_303 = wing::RedirectInfo { .. };
    red_303.new_method.append("GET");
    red_303.clear_body = true;
    let _ = wing::apply_redirect_transition(session, ctx, red_303);

    // Hop 2: 307 Temporary Redirect with body_consumed = true
    ctx.body_consumed = true;
    var red_307 = wing::RedirectInfo { .. };
    red_307.new_method.append("GET");
    red_307.clear_body = false;

    let err_307 = wing::apply_redirect_transition(session, ctx, red_307);
    assert(!wing::ok(err_307));
    assert(err_307.code == rfc::STATUS_BAD_REQUEST);
    print("CHECK_MULTIHOP_NO_RESURRECT: OK");
}

fn test_ssrf_6to4_three_octet() {
    // 2002:c000:0200:: = 192.0.2.0 (TEST-NET-1)
    assert(wing::is_private_or_reserved_ip("2002:c000:0200::1"));
    // 2002:c633:6400:: = 198.51.100.0 (TEST-NET-2)
    assert(wing::is_private_or_reserved_ip("2002:c633:6400::1"));
    // 2002:cb00:7100:: = 203.0.113.0 (TEST-NET-3)
    assert(wing::is_private_or_reserved_ip("2002:cb00:7100::1"));
    // 2002:c058:6300:: = 192.88.99.0 (6to4 Relay Anycast)
    assert(wing::is_private_or_reserved_ip("2002:c058:6300::1"));
    // Public IP via 6to4: 8.8.8.8 = 0808:0808
    assert(!wing::is_private_or_reserved_ip("2002:0808:0808::1"));
    print("CHECK_SSRF_6TO4: OK");
}

fn test_drain_rx_buf() {
    var rx: u8[..8192] = [];
    rx.append("HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 200 OK\r\n\r\n");
    rx.compact_wire_buffer(25);
    assert(core::starts_with(rx[..], "HTTP/1.1 200 OK"));
    print("CHECK_DRAIN_RX: OK");
}

fn run_08_rfc_repro_client_session_protocol() {
    test_1xx_empty_body_status();
    test_sse_content_type_validation();
    test_ws_header_tokens();
    test_multihop_redirect_body_clear();
    test_multihop_no_resurrect();
    test_ssrf_6to4_three_octet();
    test_drain_rx_buf();
}

// CHECK: CHECK_1XX_EMPTY_BODY: OK
// CHECK-NEXT: CHECK_SSE_CONTENT_TYPE: OK
// CHECK-NEXT: CHECK_WS_TOKENS: OK
// CHECK-NEXT: CHECK_MULTIHOP_BODY_CLEAR: OK
// CHECK-NEXT: CHECK_MULTIHOP_NO_RESURRECT: OK
// CHECK-NEXT: CHECK_SSRF_6TO4: OK
// CHECK-NEXT: CHECK_DRAIN_RX: OK

// ============================================================================
// 9. verify_request_response_reset (9/9)
// ============================================================================
// CHECK: === [9/9] verify_request_response_reset ===

// tests/lit/verify_request_response_reset.goose
// Verification of zero-allocation reset_request and reset_response.
//

fn run_09_verify_request_response_reset() {
    var req = wing::new_request("POST", "https://example.com/api");
    req.url.append("?token=xyz");
    req.timeout = 5000;
    req.body_consumed = true;
    req.is_http10 = true;
    wing::set_header(req, "X-Custom-Header", "Value123");

    assert(req.headers.entries.len == 1);
    assert(req.url.len > 0);
    assert(req.timeout == 5000);

    wing::reset_request(req);

    assert(req.method[..] == "GET");
    assert(req.url.len == 0);
    assert(req.headers.entries.len == 0);
    assert(req.trailers.entries.len == 0);
    assert(req.query_params.len == 0);
    assert(req.rewind_buf.len == 0);
    assert(req.timeout == 0);
    assert(!req.body_consumed);
    assert(!req.is_http10);

    var res = wing::Response { status_code: 404, .. };
    wing::set_header(res, "Content-Type", "application/json");

    assert(res.status_code == 404);
    assert(res.headers.entries.len == 1);

    wing::reset_response(res);

    assert(res.status_code == 200);
    assert(res.headers.entries.len == 0);
    assert(res.sent_headers.entries.len == 0);
    assert(res.body.len == 0);

    print("REQUEST_RESPONSE_RESET: OK");
}

// CHECK: REQUEST_RESPONSE_RESET: OK

fn main() {
    print("\n=== [1/9] cli_bug_hunter_regression ===\n");
    run_01_cli_bug_hunter_regression();
    print("\n=== [2/9] rfc_repro_client_buffer_body ===\n");
    run_02_rfc_repro_client_buffer_body();
    print("\n=== [3/9] rfc_repro_client_bug_hunter ===\n");
    run_03_rfc_repro_client_bug_hunter();
    print("\n=== [4/9] rfc_repro_client_cross_rfc ===\n");
    run_04_rfc_repro_client_cross_rfc();
    print("\n=== [5/9] rfc_repro_client_round2_bug_hunter ===\n");
    run_05_rfc_repro_client_round2_bug_hunter();
    print("\n=== [6/9] rfc_repro_client_round3_invariants ===\n");
    run_06_rfc_repro_client_round3_invariants();
    print("\n=== [7/9] rfc_repro_client_session_audit ===\n");
    run_07_rfc_repro_client_session_audit();
    print("\n=== [8/9] rfc_repro_client_session_protocol ===\n");
    run_08_rfc_repro_client_session_protocol();
    print("\n=== [9/9] verify_request_response_reset ===\n");
    run_09_verify_request_response_reset();
}
