// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// RUN: goose %s | %FileCheck %s
import std;
import wire_kit from ".";

fn validate_http1_request_wire(buf: const u8[:]) -> i64 {
    let len = buf.len;
    if len < 4 { return -1; }
    let b0 = buf[0];
    if b0 == 32 || b0 == 9 { return -2; }

    var i: i64 = 0;
    var hdr_end: i64 = -1;
    while i + 3 < len {
        if buf[i] == 13 && buf[i + 1] == 10 && buf[i + 2] == 13 && buf[i + 3] == 10 {
            hdr_end = i + 4;
            break;
        }
        i += 1;
    }
    if hdr_end < 0 { return -1; }

    var sp1: i64 = -1;
    var j: i64 = 0;
    while j < hdr_end {
        if buf[j] == 32 {
            sp1 = j;
            break;
        }
        j += 1;
    }
    if sp1 <= 0 { return -3; }

    var sp2: i64 = -1;
    j = sp1 + 1;
    while j < hdr_end {
        if buf[j] == 32 {
            sp2 = j;
            break;
        }
        j += 1;
    }
    if sp2 <= sp1 + 1 { return -3; }

    var k = sp1 + 1;
    while k < sp2 {
        let tb = buf[k];
        if tb < 33 || tb > 126 { return -4; }
        k += 1;
    }

    return hdr_end;
}

fn main() {
    let req = "GET /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n";
    assert(wire_kit::verify_split_stream(req, -1, 47, validate_http1_request_wire));
    assert(wire_kit::fuzz_payload(req, 100, validate_http1_request_wire));
    print("HTTP_REQ_SPLIT: OK");

    var ws_lead: u8[>..] = []; wire_kit::parse_hex("20474554202F20485454502F312E310D0A0D0A", ws_lead);
    assert(validate_http1_request_wire(ws_lead[..]) == -2);

    var ctl_nul: u8[>..] = []; wire_kit::parse_hex("474554202F0020485454502F312E310D0A0D0A", ctl_nul);
    assert(validate_http1_request_wire(ctl_nul[..]) == -4);

    var ctl_ff: u8[>..] = []; wire_kit::parse_hex("474554202FFF20485454502F312E310D0A0D0A", ctl_ff);
    assert(validate_http1_request_wire(ctl_ff[..]) == -4);
    print("HTTP_REQ_SYNTAX: OK");
}

// CHECK: HTTP_REQ_SPLIT: OK
// CHECK: HTTP_REQ_SYNTAX: OK
