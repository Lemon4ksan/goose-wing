// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// tests/lit/verify_ws_h2_rfc8441.goose
// Verification of RFC 8441 Bootstrapping WebSockets with HTTP/2:
// Extended CONNECT request validation, 200 OK upgrade handshake,
// and encapsulated RFC 6455 frame parsing with split-stream verification and fuzzing.
//
// RUN: goose build --cc gcc -O2 -o %t.exe %s
// RUN: %t.exe | %FileCheck %s

import std;
import core from "../..";
import wing from "../..";
import wire_kit from ".";

// Wire bridge to validate RFC 6455 frame encapsulated in H2 DATA stream
fn decode_h2_ws_payload(buf: const u8[:]) -> i64 {
    if buf.len < 2 { return -1; }
    let opcode = buf[0] & 0x0F;
    if !rfc::is_valid_ws_opcode(opcode) { return -2; }
    let masked = (buf[1] & 0x80) != 0;
    let raw_len = buf[1] & 0x7F;
    var min_hdr: i64 = 2;
    if raw_len == 126 { min_hdr += 2; }
    else if raw_len == 127 { min_hdr += 8; }
    if masked { min_hdr += 4; }
    if buf.len < min_hdr { return -1; }

    let hdr, ok = wing::parse_ws_frame_header(buf);
    if !ok { return -2; }
    let total: i64 = hdr.header_len + (hdr.payload_len as! i64);
    if buf.len < total { return -1; }
    return hdr.payload_len as! i64;
}

fn test_rfc8441_handshake() {
    var req = wing::new_request("GET", "/");
    wing::format_h2_websocket_request(req, "/chat", "example.com", "https", "chat.v1");

    assert(wing::is_h2_websocket_request(req));
    assert(wing::validate_h2_websocket_request(req));

    var resp = wing::Response { .. };
    let session, ok = wing::ws_h2_upgrade_request(req, resp, "chat.v1");
    assert(ok);
    assert(resp.status_code == 200);
    assert(wing::is_h2_websocket_response(resp));
    assert(session.subprotocol[..] == "chat.v1");

    // Forbidden headers check: Upgrade or Connection MUST NOT be present
    var bad_req = req;
    wing::set_header(bad_req, "Upgrade", "websocket");
    assert(!wing::validate_h2_websocket_request(bad_req));

    print("H2_WS_HANDSHAKE: OK");
}

fn test_rfc8441_stream_payload() {
    var ws_pkt: u8[>..] = [];
    // RFC 6455 masked text frame: "hello" (payload len 5)
    // 81 (FIN=1, Text=1) 85 (Masked=1, Len=5) 01020304 (Mask) 68656C6C6F (Masked "hello")
    assert(wire_kit::parse_hex("81850102030468656C6C6F", ws_pkt));

    let hdr, ok = wing::parse_ws_frame_header(ws_pkt[..]);
    assert(ok);
    assert(hdr.payload_len == 5);
    assert(hdr.masked);

    assert(wire_kit::verify_split_stream(ws_pkt[..], -1, 5, decode_h2_ws_payload));
    assert(wire_kit::fuzz_payload(ws_pkt[..], 100, decode_h2_ws_payload));

    print("H2_WS_STREAM_PAYLOAD: OK");
}

fn main() {
    test_rfc8441_handshake();
    test_rfc8441_stream_payload();
    print("RFC8441_H2_WEBSOCKET: ALL INVARIANTS PASS");
}

// CHECK: H2_WS_HANDSHAKE: OK
// CHECK: H2_WS_STREAM_PAYLOAD: OK
// CHECK: RFC8441_H2_WEBSOCKET: ALL INVARIANTS PASS
