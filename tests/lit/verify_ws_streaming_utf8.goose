// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// RUN: goose %s | %FileCheck %s
import std;
import wire_kit from ".";

fn validate_ws_close_wire(buf: const u8[:]) -> i64 {
    let len = buf.len;
    if len == 0 { return 1005; }
    if len == 1 { return -1; }

    let code = ((buf[0] as i64) << 8) | buf[1];

    if code < 1000 || code >= 5000 {
        return -2;
    }
    if code == 1004 || code == 1005 || code == 1006 || code == 1015 {
        return -2;
    }
    if code >= 1016 && code < 3000 {
        return -2;
    }

    return code;
}

fn validate_utf8_wire(buf: const u8[:]) -> i32 {
    let len = buf.len;
    var i: i64 = 0;
    while i < len {
        let b0 = buf[i];
        if b0 < 128 {
            i += 1;
        } else if (b0 & 224) == 192 {
            if i + 1 >= len { return -1; }
            let b1 = buf[i + 1];
            if (b1 & 192) != 128 { return -2; }
            if b0 < 194 { return -2; }
            i += 2;
        } else if (b0 & 240) == 224 {
            if i + 2 >= len { return -1; }
            let b1 = buf[i + 1];
            let b2 = buf[i + 2];
            if (b1 & 192) != 128 || (b2 & 192) != 128 { return -2; }
            if b0 == 224 && b1 < 160 { return -2; }
            if b0 == 237 && b1 >= 160 { return -2; }
            i += 3;
        } else {
            return -2;
        }
    }
    return 1;
}

fn main() {
    var raw_1000: u8[>..] = []; wire_kit::parse_hex("03E8", raw_1000);
    assert(wire_kit::verify_split_stream(raw_1000[..], -1, 1000, validate_ws_close_wire));
    assert(wire_kit::fuzz_payload(raw_1000[..], 100, validate_ws_close_wire));
    print("WS_CLOSE_SPLIT: OK");

    var c1005: u8[>..] = []; wire_kit::parse_hex("03ED", c1005);
    assert(validate_ws_close_wire(c1005[..]) == -2);

    var c1006: u8[>..] = []; wire_kit::parse_hex("03EE", c1006);
    assert(validate_ws_close_wire(c1006[..]) == -2);

    var c1004: u8[>..] = []; wire_kit::parse_hex("03EC", c1004);
    assert(validate_ws_close_wire(c1004[..]) == -2);

    var c2000: u8[>..] = []; wire_kit::parse_hex("07D0", c2000);
    assert(validate_ws_close_wire(c2000[..]) == -2);

    var c5000: u8[>..] = []; wire_kit::parse_hex("1388", c5000);
    assert(validate_ws_close_wire(c5000[..]) == -2);

    var c1002: u8[>..] = []; wire_kit::parse_hex("03EA", c1002);
    assert(validate_ws_close_wire(c1002[..]) == 1002);
    print("WS_CLOSE_CODES: OK");

    assert(validate_utf8_wire("hello") == 1);

    var uOverlong: u8[>..] = []; wire_kit::parse_hex("C080", uOverlong);
    assert(validate_utf8_wire(uOverlong[..]) == -2);

    var uSurr: u8[>..] = []; wire_kit::parse_hex("EDA080", uSurr);
    assert(validate_utf8_wire(uSurr[..]) == -2);
    print("WS_UTF8_WIRE: OK");
}

// CHECK: WS_CLOSE_SPLIT: OK
// CHECK: WS_CLOSE_CODES: OK
// CHECK: WS_UTF8_WIRE: OK
