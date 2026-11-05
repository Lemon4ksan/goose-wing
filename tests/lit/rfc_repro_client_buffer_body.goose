// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// tests/lit/rfc_repro_client_buffer_body.goose
// Regression tests for client buffers, body rewinds, and header synchronization.
//
// RUN: goose build -O2 -o %t.exe %s
// RUN: %t.exe | %FileCheck %s

import std;
import core from "../..";
import wing from "../..";

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
    var res = wing::Response { .. };
    res.body.append("{\"id\":3000000000,\"name\":\"a_very_long_name_exceeding_capacity\"}");
    let item, err = wing::decode_json<JsonItemModel>(res);
    assert(wing::ok(err));
    assert(item.id == 2147483647);
    assert(item.name.len == 16);
    assert(core::starts_with(item.name[..], "a_very_long_name"));
    print("CHECK_JSON_DECODE_BOUNDS: OK");
}

fn main() {
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
