// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// tests/lit/verify_http_extensions_edge.goose
// Verification of RFC 8288 Link header and RFC 8941 Structured Fields upload boolean via wing::http.
//
// RUN: goose build --cc gcc -O2 -o %t.exe %s
// RUN: %t.exe | %FileCheck %s

import std;
import core from "../..";
import wing from "../..";
import wire_kit from ".";

// Wire validator for RFC 8288 Link header using wing::parse_link_header
fn wing_validate_link_header_wire(buf: const u8[:]) -> i64 {
    guard buf.len >= 2 else { return -1; }
    guard buf[0] == '<' else { return -2; }
    var links: wing::EarlyHintLink[..8] = [];
    if wing::parse_link_header(buf, links) {
        guard links.len > 0 && links[0].uri.len > 0 else { return -3; }
        return links[0].uri.len;
    }
    let end_idx = core::index_of_byte(buf, '>');
    guard end_idx >= 0 else { return -1; }
    let uri_len = end_idx - 1;
    guard uri_len > 0 else { return -3; }
    return -4;
}

// RFC 8941 Structured Fields boolean validator for Resumable Uploads
fn validate_upload_boolean_wire(buf: const u8[:]) -> i32 {
    let len = buf.len;
    guard len >= 2 else { return -1; }
    guard buf[0] == '?' else { return -2; }
    let val_b = buf[1];
    guard val_b == '0' || val_b == '1' else { return -2; }

    if len == 2 {
        return if val_b == '1' { 1 } else { 0 };
    }

    let next_b = buf[2];
    guard next_b == ';' || next_b == ',' || next_b == ' ' || next_b == '\t' else {
        return -2;
    }

    return if val_b == '1' { 1 } else { 0 };
}

fn main() {
    let link_hdr = "<https://example.com/style.css>";
    assert(wire_kit::verify_split_stream(link_hdr, -1, 29, wing_validate_link_header_wire));
    assert(wire_kit::fuzz_payload(link_hdr, 100, wing_validate_link_header_wire));
    print("HTTP_LINK_SPLIT: OK");

    assert(wing_validate_link_header_wire("<>") == -3);
    assert(wing_validate_link_header_wire("<foo>bar; rel=preload") == -4);
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
