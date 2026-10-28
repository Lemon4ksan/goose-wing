// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// RUN: goose %s | %FileCheck %s
import std;
import wire_kit from ".";

fn validate_link_header_wire(buf: const u8[:]) -> i64 {
    let len = buf.len;
    if len < 2 { return -1; }
    if buf[0] != 60 { return -2; } // '<'

    var i: i64 = 1;
    while i < len && buf[i] != 62 { // '>'
        i += 1;
    }
    if i >= len { return -1; }
    let uri_len = i - 1;
    if uri_len <= 0 { return -3; }

    i += 1; // skip '>'
    while i < len && (buf[i] == 32 || buf[i] == 9) { i += 1; }
    if i >= len { return uri_len; }

    if buf[i] != 59 { return -4; } // ';'
    return uri_len;
}

fn validate_upload_boolean_wire(buf: const u8[:]) -> i32 {
    let len = buf.len;
    if len < 2 { return -1; }
    if buf[0] != 63 { return -2; } // '?'
    let val_b = buf[1];
    if val_b != 48 && val_b != 49 { return -2; }

    if len == 2 {
        return if val_b == 49 { 1 } else { 0 };
    }

    let next_b = buf[2];
    if next_b != 59 && next_b != 44 && next_b != 32 && next_b != 9 {
        return -2;
    }

    return if val_b == 49 { 1 } else { 0 };
}

fn main() {
    let link_hdr = "<https://example.com/style.css>";
    assert(wire_kit::verify_split_stream(link_hdr, -1, 29, validate_link_header_wire));
    assert(wire_kit::fuzz_payload(link_hdr, 100, validate_link_header_wire));
    print("HTTP_LINK_SPLIT: OK");

    assert(validate_link_header_wire("<>") == -3);
    assert(validate_link_header_wire("<foo>bar; rel=preload") == -4);
    print("HTTP_LINK_SYNTAX: OK");

    assert(validate_upload_boolean_wire("?1") == 1);
    assert(validate_upload_boolean_wire("?0") == 0);
    assert(validate_upload_boolean_wire("?1; foo") == 1);
    assert(validate_upload_boolean_wire("?1abc") == -2);
    assert(validate_upload_boolean_wire("?2") == -2);
    print("HTTP_UPLOAD_BOOL: OK");
}

// CHECK: HTTP_LINK_SPLIT: OK
// CHECK: HTTP_LINK_SYNTAX: OK
// CHECK: HTTP_UPLOAD_BOOL: OK
