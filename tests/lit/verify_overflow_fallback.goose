// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// tests/lit/verify_overflow_fallback.goose
// Verification of Zero-Allocation Stack Fast Path & Safe Overflow Fallback via Root Struct Arena.
//
// RUN: goose build --cc gcc -O2 -o %t.exe %s
// RUN: %t.exe | %FileCheck %s

import std;
import core from "../..";
import wing from "../..";

fn test_stack_fast_path() {
    var map = wing::HeaderMap { .. };
    var arena = wing::OverflowArena { .. };

    let raw: const u8[:] = "Host: api.example.com\r\nUser-Agent: wing/1.0\r\nAccept: */*\r\n\r\n";
    let err = wing::parse_headers_with_overflow(raw, map, arena);

    assert(wing::is_ok(err));
    assert(map.raw_buf.len > 0);
    assert(arena.spill_raw.len == 0); // Fast path: 0 B in spill arena
    assert(arena.spill_entries.len == 0);

    assert(wing::has_header_spill(map, arena, "Host"));
    let host = wing::get_header_spill(map, arena, "Host");
    assert(host == "api.example.com");

    assert(wing::has_header_spill(map, arena, "User-Agent"));
    let ua = wing::get_header_spill(map, arena, "User-Agent");
    assert(ua == "wing/1.0");

    assert(!wing::has_header_spill(map, arena, "Non-Existent"));

    print("STACK_FAST_PATH: OK");
}

fn test_oversized_header_block() {
    var map = wing::HeaderMap { .. };
    var arena = wing::OverflowArena { .. };

    // Build ~10 KB headers block
    var huge_raw: u8[>..] = [];
    huge_raw.append("Host: api.example.com\r\n");
    for i in 80 {
        huge_raw.append("X-Custom-Data-Padding-");
        // Convert i to 2-digit number
        huge_raw.push('0' + ((i / 10) as u8));
        huge_raw.push('0' + ((i % 10) as u8));
        huge_raw.append(": 0123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789\r\n");
    }
    huge_raw.append("X-Final-Marker: verified_payload\r\n\r\n");

    assert(huge_raw.len > 9000);

    // Standard parse_headers must fail with CapacityExceeded (> 8192 bytes)
    let std_err = wing::parse_headers(huge_raw[..], map);
    assert(std_err == wing::HeaderParseError.CapacityExceeded);

    // parse_headers_with_overflow must succeed using arena
    let of_err = wing::parse_headers_with_overflow(huge_raw[..], map, arena);
    assert(wing::is_ok(of_err));
    assert(arena.spill_raw.len > 9000);

    let host = wing::get_header_spill(map, arena, "Host");
    assert(host == "api.example.com");

    let marker = wing::get_header_spill(map, arena, "X-Final-Marker");
    assert(marker == "verified_payload");

    let pad42 = wing::get_header_spill(map, arena, "X-Custom-Data-Padding-42");
    assert(pad42.len == 100);

    print("OVERSIZED_HEADER_BLOCK: OK");
}

fn test_high_header_count_overflow() {
    var map = wing::HeaderMap { .. };
    var arena = wing::OverflowArena { .. };

    // Build 150 short headers (exceeds 128 entries limit)
    var many_headers: u8[>..] = [];
    many_headers.append("Host: example.org\r\n");
    for i in 148 {
        many_headers.append("H-");
        many_headers.push('0' + (((i / 100) % 10) as u8));
        many_headers.push('0' + (((i / 10) % 10) as u8));
        many_headers.push('0' + ((i % 10) as u8));
        many_headers.append(": v\r\n");
    }
    many_headers.append("X-Overflow-Tail: tail_value\r\n\r\n");

    let std_err = wing::parse_headers(many_headers[..], map);
    assert(std_err == wing::HeaderParseError.CapacityExceeded);

    let of_err = wing::parse_headers_with_overflow(many_headers[..], map, arena);
    assert(wing::is_ok(of_err));

    assert(map.entries.len == 128);       // 128 entries stored in stack map
    assert(arena.spill_entries.len > 20); // Overflow entries stored in arena

    let host = wing::get_header_spill(map, arena, "Host");
    assert(host == "example.org");

    let tail_val = wing::get_header_spill(map, arena, "X-Overflow-Tail");
    assert(tail_val == "tail_value");

    print("HIGH_HEADER_COUNT_OVERFLOW: OK");
}

fn test_oversized_url_overflow() {
    var arena = wing::OverflowArena { .. };

    var huge_url: u8[>..] = [];
    huge_url.append("https://auth.example.com/oauth/authorize?response_type=code&client_id=123456&state=active&huge_jwt=");
    for _ in 3000 {
        huge_url.push('x');
    }

    assert(huge_url.len > 3000);

    // Standard parse_url fails with InputTooLong (> 2048 bytes)
    let std_url, std_url_err = core::parse_url(huge_url[..]);
    assert(std_url_err == core::UrlParseError.InputTooLong);

    // parse_url_with_overflow succeeds without allocation using arena
    let view, of_url_err = wing::parse_url_with_overflow(huge_url[..], arena);
    assert(of_url_err == core::UrlParseError.None);
    assert(view.valid);
    assert(view.host == "auth.example.com");
    assert(view.pathname == "/oauth/authorize");
    assert(view.raw.len > 3000);

    print("OVERSIZED_URL_OVERFLOW: OK");
}

fn test_oversized_response_headers_overflow() {
    var map = wing::HeaderMap { .. };
    var arena = wing::OverflowArena { .. };

    var huge_resp: u8[>..] = [];
    huge_resp.append("HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n");
    for i in 80 {
        huge_resp.append("X-Large-Resp-Header-");
        huge_resp.push('0' + ((i / 10) as u8));
        huge_resp.push('0' + ((i % 10) as u8));
        huge_resp.append(": 0123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789\r\n");
    }
    huge_resp.append("X-Status-Check: verified\r\n\r\n");

    let std_err = wing::parse_response_headers(huge_resp[..], map);
    assert(std_err == wing::HeaderParseError.CapacityExceeded);

    let of_err = wing::parse_response_headers_with_overflow(huge_resp[..], map, arena);
    assert(wing::is_ok(of_err));
    assert(map.status_code == 200);
    assert(map.http_major == 1);
    assert(map.http_minor == 1);

    let check = wing::get_header_spill(map, arena, "X-Status-Check");
    assert(check == "verified");

    print("OVERSIZED_RESPONSE_HEADERS_OVERFLOW: OK");
}

fn test_oversized_request_headers_overflow() {
    var map = wing::HeaderMap { .. };
    var arena = wing::OverflowArena { .. };

    var huge_req: u8[>..] = [];
    huge_req.append("POST /api/v1/submit HTTP/1.1\r\nHost: api.example.com\r\n");
    for i in 80 {
        huge_req.append("X-Large-Req-Header-");
        huge_req.push('0' + ((i / 10) as u8));
        huge_req.push('0' + ((i % 10) as u8));
        huge_req.append(": 0123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789\r\n");
    }
    huge_req.append("X-Req-Check: verified_req\r\n\r\n");

    let std_err = wing::parse_request_headers(huge_req[..], map);
    assert(std_err == wing::HeaderParseError.CapacityExceeded);

    let of_err = wing::parse_request_headers_with_overflow(huge_req[..], map, arena);
    assert(wing::is_ok(of_err));

    let host = wing::get_header_spill(map, arena, "Host");
    assert(host == "api.example.com");

    let check = wing::get_header_spill(map, arena, "X-Req-Check");
    assert(check == "verified_req");

    print("OVERSIZED_REQUEST_HEADERS_OVERFLOW: OK");
}

fn test_spill_accessors_and_serialization() {
    var map = wing::HeaderMap { .. };
    var arena = wing::OverflowArena { .. };

    var raw_input: u8[>..] = [];
    raw_input.append("Host: service.local\r\n");
    for i in 140 {
        raw_input.append("X-Tag: tag-");
        raw_input.push('0' + (((i / 100) % 10) as u8));
        raw_input.push('0' + (((i / 10) % 10) as u8));
        raw_input.push('0' + ((i % 10) as u8));
        raw_input.append("\r\n");
    }
    raw_input.append("\r\n");

    let err = wing::parse_headers_with_overflow(raw_input[..], map, arena);
    assert(wing::is_ok(err));

    var values: u8[..256][>..] = [];
    wing::get_all_values_spill(map, arena, "X-Tag", values);
    assert(values.len == 140);
    assert(values[0] == "tag-000");
    assert(values[139] == "tag-139");

    var raw_out: u8[>..] = [];
    wing::raw_headers_spill(map, arena, raw_out);
    assert(raw_out.len > 0);

    print("SPILL_ACCESSORS_AND_SERIALIZATION: OK");
}

fn main() {
    test_stack_fast_path();
    test_oversized_header_block();
    test_high_header_count_overflow();
    test_oversized_url_overflow();
    test_oversized_response_headers_overflow();
    test_oversized_request_headers_overflow();
    test_spill_accessors_and_serialization();
    print("ALL_OVERFLOW_FALLBACK_TESTS_PASS");
}

// CHECK: STACK_FAST_PATH: OK
// CHECK-NEXT: OVERSIZED_HEADER_BLOCK: OK
// CHECK-NEXT: HIGH_HEADER_COUNT_OVERFLOW: OK
// CHECK-NEXT: OVERSIZED_URL_OVERFLOW: OK
// CHECK-NEXT: OVERSIZED_RESPONSE_HEADERS_OVERFLOW: OK
// CHECK-NEXT: OVERSIZED_REQUEST_HEADERS_OVERFLOW: OK
// CHECK-NEXT: SPILL_ACCESSORS_AND_SERIALIZATION: OK
// CHECK-NEXT: ALL_OVERFLOW_FALLBACK_TESTS_PASS
