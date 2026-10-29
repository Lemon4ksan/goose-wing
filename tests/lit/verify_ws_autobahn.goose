// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// tests/lit/verify_ws_autobahn.goose
// Verification of RFC 6455 WebSocket framing, masking, and Autobahn testsuite invariants via wing.
//
// RUN: goose build --cc gcc -O2 -o %t.exe %s
// RUN: %t.exe | %FileCheck %s

import std;
import core from "../..";
import wing from "../..";
import wire_kit from ".";

// Wire validator for RFC 6455 framing rules using wing::parse_ws_frame_header
fn wing_validate_ws_frame(buf: const u8[:], is_client_ingress: bool) -> i32 {
    let hdr, ok = wing::parse_ws_frame_header(buf);
    guard ok else { return 1002; }
    if hdr.rsv1 || hdr.rsv2 || hdr.rsv3 { return 1002; }
    if is_client_ingress && !hdr.masked { return 1002; }
    return 0;
}

fn main() {
    var vOk: u8[>..] = []; wire_kit::parse_hex("818511223344", vOk);
    assert(wing_validate_ws_frame(vOk[..], true) == 0);

    var vRsv1: u8[>..] = []; wire_kit::parse_hex("C18511223344", vRsv1);
    assert(wing_validate_ws_frame(vRsv1[..], true) == 1002);

    var vRsv2: u8[>..] = []; wire_kit::parse_hex("A18511223344", vRsv2);
    assert(wing_validate_ws_frame(vRsv2[..], true) == 1002);

    var vFragPing: u8[>..] = []; wire_kit::parse_hex("098011223344", vFragPing);
    assert(wing_validate_ws_frame(vFragPing[..], true) == 1002);

    var vBigPing: u8[>..] = []; wire_kit::parse_hex("89FE11223344", vBigPing);
    assert(wing_validate_ws_frame(vBigPing[..], true) == 1002);

    var vUnmasked: u8[>..] = []; wire_kit::parse_hex("810568656C6C6F", vUnmasked);
    assert(wing_validate_ws_frame(vUnmasked[..], true) == 1002);
    assert(wing_validate_ws_frame(vUnmasked[..], false) == 0);

    print("WS_AUTOBAHN_FRAMING: ALL OK");
}

// CHECK: WS_AUTOBAHN_FRAMING: ALL OK
