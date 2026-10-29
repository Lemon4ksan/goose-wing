// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// tests/lit/verify_server_pipeline_edge.goose
// Verification of HTTP/1.1 request wire parser and RFC 9112 syntax invariants via wing.
//
// RUN: goose build --cc gcc -O2 -o %t.exe %s
// RUN: %t.exe | %FileCheck %s

import std;
import core from "../..";
import wing from "../..";
import wire_kit from ".";

// Wire adapter for verify_split_stream and fuzzing using wing::parse_http1_wire_request
fn wing_validate_http1_request_wire(buf: const u8[:]) -> i64 {
    var req = wing::new_request("GET", "/");
    let ok, consumed = wing::parse_http1_wire_request(buf, req);
    if ok {
        return consumed;
    }
    guard buf.len >= 4 else { return -1; }
    let crlf = core::fast_find_crlfcrlf(buf);
    guard crlf >= 0 else { return -1; }
    return -2;
}

fn main() {
    let req_str = "GET /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n";
    assert(wire_kit::verify_split_stream(req_str, -1, 47, wing_validate_http1_request_wire));
    assert(wire_kit::fuzz_payload(req_str, 100, wing_validate_http1_request_wire));

    var parsed_req = wing::new_request("GET", "/");
    let ok, consumed = wing::parse_http1_wire_request(req_str, parsed_req);
    assert(ok);
    assert(consumed == 47);
    assert(parsed_req.method == "GET");
    assert(parsed_req.url == "/index.html");
    print("HTTP_REQ_SPLIT: OK");

    var ws_lead: u8[>..] = []; wire_kit::parse_hex("20474554202F20485454502F312E310D0A0D0A", ws_lead);
    assert(wing_validate_http1_request_wire(ws_lead[..]) == -2);

    var ctl_nul: u8[>..] = []; wire_kit::parse_hex("474554202F0020485454502F312E310D0A0D0A", ctl_nul);
    assert(wing_validate_http1_request_wire(ctl_nul[..]) == -2);

    var ctl_ff: u8[>..] = []; wire_kit::parse_hex("474554202FFF20485454502F312E310D0A0D0A", ctl_ff);
    assert(wing_validate_http1_request_wire(ctl_ff[..]) == -2);
    print("HTTP_REQ_SYNTAX: OK");
}

// CHECK: HTTP_REQ_SPLIT: OK
// CHECK: HTTP_REQ_SYNTAX: OK
