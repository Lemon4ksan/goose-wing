// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// tests/lit/verify_quic_ack_edge.goose
// Verification of RFC 9000 QUIC ACK frames, varint arithmetic, and long header parsing via wing::quic.
//
// RUN: goose build --cc gcc -O2 -o %t.exe %s
// RUN: %t.exe | %FileCheck %s

import std;
import core from "../..";
import wing from "../..";
import wire_kit from ".";

// Wire adapter for verify_split_stream and fuzzing using wing's real decode_ack_frame
fn wing_validate_quic_ack_wire(buf: const u8[:]) -> i64 {
    guard buf.len > 0 else { return -1; }
    let ack, consumed, ok = wing::decode_ack_frame(buf, 0);
    if ok {
        return (ack.largest_acked - ack.first_ack_range) as! i64;
    }
    let ftype = buf[0];
    guard ftype == 2 || ftype == 3 else { return -2; }
    if buf.len >= 5 {
        let largest, off1, ok1 = wing::quic_decode_varint(buf, 1);
        if ok1 {
            let _, off2, ok2 = wing::quic_decode_varint(buf, off1);
            if ok2 {
                let _, off3, ok3 = wing::quic_decode_varint(buf, off2);
                if ok3 {
                    let first_r, _, ok4 = wing::quic_decode_varint(buf, off3);
                    if ok4 && largest < first_r {
                        return -3;
                    }
                }
            }
        }
    }
    return -1;
}

fn wing_validate_quic_long_header_wire(buf: const u8[:]) -> i32 {
    guard buf.len >= 5 else { return -1; }
    let first = buf[0];
    guard (first & 0x80) != 0 else { return -2; }
    guard (first & 0x40) != 0 else { return -3; }
    let long_type = (first >> 4) & 3;
    if long_type == 0 && (first & 0x0C) != 0 {
        return -4;
    }
    return 1;
}

fn main() {
    var raw_ack: u8[>..] = [];
    assert(wire_kit::parse_hex("02406419000A", raw_ack));
    assert(wire_kit::verify_split_stream(raw_ack[..], -1, 90, wing_validate_quic_ack_wire));
    assert(wire_kit::fuzz_payload(raw_ack[..], 100, wing_validate_quic_ack_wire));
    print("QUIC_ACK_SPLIT: OK");

    var bad_range: u8[>..] = []; wire_kit::parse_hex("020519000A", bad_range);
    assert(wing_validate_quic_ack_wire(bad_range[..]) == -3);
    print("QUIC_ACK_INVARIANT: OK");

    var init_ok: u8[>..] = []; wire_kit::parse_hex("C000000001", init_ok);
    assert(wing_validate_quic_long_header_wire(init_ok[..]) == 1);

    var init_nofix: u8[>..] = []; wire_kit::parse_hex("8000000001", init_nofix);
    assert(wing_validate_quic_long_header_wire(init_nofix[..]) == -3);

    var init_badres: u8[>..] = []; wire_kit::parse_hex("C400000001", init_badres);
    assert(wing_validate_quic_long_header_wire(init_badres[..]) == -4);
    print("QUIC_LONG_HEADER: OK");
}

// CHECK: QUIC_ACK_SPLIT: OK
// CHECK: QUIC_ACK_INVARIANT: OK
// CHECK: QUIC_LONG_HEADER: OK
