// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// RUN: goose %s | %FileCheck %s
import std;
import wire_kit from ".";

fn validate_ws_frame(buf: const u8[:], is_client_ingress: i32) -> i32 {
    guard buf.len >= 2 else { return 1002; }
    let b0 = buf[0];
    let b1 = buf[1];

    let fin = (b0 >> 7) & 0x1;
    let rsv1 = (b0 >> 6) & 0x1;
    let rsv2 = (b0 >> 5) & 0x1;
    let rsv3 = (b0 >> 4) & 0x1;
    let opcode = b0 & 0x0F;

    let masked = (b1 >> 7) & 0x1;
    let basic_len = b1 & 0x7F;

    if rsv1 != 0 || rsv2 != 0 || rsv3 != 0 {
        return 1002;
    }

    let is_ctrl = (opcode & 0x08) != 0;
    if opcode != 0 && opcode != 1 && opcode != 2 && opcode != 8 && opcode != 9 && opcode != 10 {
        return 1002;
    }

    if is_ctrl && fin == 0 {
        return 1002;
    }

    if is_ctrl && basic_len > 125 {
        return 1002;
    }

    if is_client_ingress == 1 && masked == 0 {
        return 1002;
    }

    return 0;
}

fn main() {
    var vOk: u8[>..] = []; wire_kit::parse_hex("818511223344", vOk);
    assert(validate_ws_frame(vOk[..], 1) == 0);

    var vRsv1: u8[>..] = []; wire_kit::parse_hex("C18511223344", vRsv1);
    assert(validate_ws_frame(vRsv1[..], 1) == 1002);

    var vRsv2: u8[>..] = []; wire_kit::parse_hex("A18511223344", vRsv2);
    assert(validate_ws_frame(vRsv2[..], 1) == 1002);

    var vFragPing: u8[>..] = []; wire_kit::parse_hex("098011223344", vFragPing);
    assert(validate_ws_frame(vFragPing[..], 1) == 1002);

    var vBigPing: u8[>..] = []; wire_kit::parse_hex("89FE11223344", vBigPing);
    assert(validate_ws_frame(vBigPing[..], 1) == 1002);

    var vUnmasked: u8[>..] = []; wire_kit::parse_hex("810568656C6C6F", vUnmasked);
    assert(validate_ws_frame(vUnmasked[..], 1) == 1002);
    assert(validate_ws_frame(vUnmasked[..], 0) == 0);

    print("WS_AUTOBAHN_FRAMING: ALL OK");
}

// CHECK: WS_AUTOBAHN_FRAMING: ALL OK
