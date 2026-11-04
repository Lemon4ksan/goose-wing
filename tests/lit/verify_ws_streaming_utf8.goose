// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// tests/lit/verify_ws_streaming_utf8.goose
// Verification of RFC 6455 close status codes and streaming UTF-8 validation via wing and core.
//
// RUN: goose build --cc gcc -O2 -o %t.exe %s
// RUN: %t.exe | %FileCheck %s

import std;
import core from "../..";
import wing from "../..";
import wire_kit from ".";

// Wire validator for RFC 6455 close status codes using wing::is_valid_ws_close_code
fn wing_validate_ws_close_wire(buf: const u8[:]) -> i64 {
    guard buf.len > 0 else { return 1005; }
    guard buf.len >= 2 else { return -1; }
    let code = core::read_be_u16(buf, 0);
    guard rfc::is_valid_ws_close_code(code) else { return -2; }
    return code as! i64;
}

// Wire validator for streaming UTF-8 using core::validate_utf8_streaming
fn wing_validate_utf8_wire(buf: const u8[:]) -> i32 {
    let valid, ok = core::validate_utf8_streaming(buf, true);
    if ok && valid == buf.len {
        return 1;
    }
    if !ok {
        return -2;
    }
    return -1;
}

fn main() {
    var raw_1000: u8[>..] = []; wire_kit::parse_hex("03E8", raw_1000);
    assert(wire_kit::verify_split_stream(raw_1000[..], -1, 1000, wing_validate_ws_close_wire));
    assert(wire_kit::fuzz_payload(raw_1000[..], 100, wing_validate_ws_close_wire));
    print("WS_CLOSE_SPLIT: OK");

    var c1005: u8[>..] = []; wire_kit::parse_hex("03ED", c1005);
    assert(wing_validate_ws_close_wire(c1005[..]) == -2);

    var c1006: u8[>..] = []; wire_kit::parse_hex("03EE", c1006);
    assert(wing_validate_ws_close_wire(c1006[..]) == -2);

    var c1004: u8[>..] = []; wire_kit::parse_hex("03EC", c1004);
    assert(wing_validate_ws_close_wire(c1004[..]) == -2);

    var c2000: u8[>..] = []; wire_kit::parse_hex("07D0", c2000);
    assert(wing_validate_ws_close_wire(c2000[..]) == -2);

    var c5000: u8[>..] = []; wire_kit::parse_hex("1388", c5000);
    assert(wing_validate_ws_close_wire(c5000[..]) == -2);

    var c1002: u8[>..] = []; wire_kit::parse_hex("03EA", c1002);
    assert(wing_validate_ws_close_wire(c1002[..]) == 1002);
    print("WS_CLOSE_CODES: OK");

    assert(wing_validate_utf8_wire("hello") == 1);

    var uOverlong: u8[>..] = []; wire_kit::parse_hex("C080", uOverlong);
    assert(wing_validate_utf8_wire(uOverlong[..]) == -2);

    var uSurr: u8[>..] = []; wire_kit::parse_hex("EDA080", uSurr);
    assert(wing_validate_utf8_wire(uSurr[..]) == -2);
    print("WS_UTF8_WIRE: OK");
}

// CHECK: WS_CLOSE_SPLIT: OK
// CHECK: WS_CLOSE_CODES: OK
// CHECK: WS_UTF8_WIRE: OK
