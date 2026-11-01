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

    // Fast-path request smuggling (CWE-444) & RFC 9112 §3.2 verification
    var srv = wing::new_http_server("127.0.0.1", 8080);
    srv.fast_path = true;
    srv.server_name.clear();
    srv.server_name.append("goose-wing");
    wing::add_static_get_route(srv, "/plaintext", "text/plain", "Hello, World!", 1001);

    var out_wire:       u8[..4096] = [];
    var consumed_bytes: i64        = 0;
    var wants_close = false;

    // 1. Valid fast-path GET request
    let valid_fast = "GET /plaintext HTTP/1.1\r\nHost: localhost\r\n\r\n";
    let ok_fast = wing::try_fast_path_pipeline_step(
        srv, valid_fast, out_wire, consumed_bytes, wants_close, 1700000000,
    );
    assert(ok_fast);
    assert(consumed_bytes == valid_fast.len);

    // 2. Request smuggling attempt: GET with Content-Length (CWE-444) MUST be rejected by fast path
    let smuggle_cl = "GET /plaintext HTTP/1.1\r\nHost: localhost\r\nContent-Length: 5\r\n\r\n12345";
    out_wire.clear();
    let ok_cl = wing::try_fast_path_pipeline_step(
        srv, smuggle_cl, out_wire, consumed_bytes, wants_close, 1700000000,
    );
    assert(!ok_cl);

    // 3. Request smuggling attempt: GET with Transfer-Encoding (CWE-444) MUST be rejected by fast path
    let smuggle_te = "GET /plaintext HTTP/1.1\r\nHost: localhost\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n";
    out_wire.clear();
    let ok_te = wing::try_fast_path_pipeline_step(
        srv, smuggle_te, out_wire, consumed_bytes, wants_close, 1700000000,
    );
    assert(!ok_te);

    // 4. Missing Host header (RFC 9112 §3.2) MUST be rejected by fast path
    let no_host = "GET /plaintext HTTP/1.1\r\nUser-Agent: curl\r\n\r\n";
    out_wire.clear();
    let ok_nohost = wing::try_fast_path_pipeline_step(
        srv, no_host, out_wire, consumed_bytes, wants_close, 1700000000,
    );
    assert(!ok_nohost);

    // 5. Non-HTTP/1.1 version (HTTP/1.0) MUST be rejected by fast path
    let http10 = "GET /plaintext HTTP/1.0\r\nHost: localhost\r\n\r\n";
    out_wire.clear();
    let ok_http10 = wing::try_fast_path_pipeline_step(
        srv, http10, out_wire, consumed_bytes, wants_close, 1700000000,
    );
    assert(!ok_http10);

    print("HTTP_FAST_PATH_SECURITY: OK");
}

// CHECK: HTTP_REQ_SPLIT: OK
// CHECK: HTTP_REQ_SYNTAX: OK
// CHECK: HTTP_FAST_PATH_SECURITY: OK
