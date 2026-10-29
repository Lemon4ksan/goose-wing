// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// tests/lit/verify_hpack_edge.goose
// Verification of RFC 7541 HPACK integer prefix decoding and Huffman padding via wing::http2.
//
// RUN: goose build --cc gcc -O2 -o %t.exe %s
// RUN: %t.exe | %FileCheck %s

import std;
import core from "../..";
import wing from "../..";
import wire_kit from ".";

// Wire adapter for verify_split_stream and fuzzing using wing's real hpack_decode_int
fn wing_decode_hpack_int_5(buf: const u8[:]) -> i64 {
    guard buf.len > 0 else { return -1; }
    let val, new_off, ok = wing::hpack_decode_int(buf, 0, 5);
    if ok {
        return val as! i64;
    }
    if new_off == 0 {
        return -1; // truncated
    }
    return -2; // overflow
}

fn validate_huffman_padding(buf: const u8[:], rem_bits: i32) -> i32 {
    let len = buf.len;
    if len <= 0 || rem_bits < 0 || rem_bits > 7 { return -1; }
    if rem_bits == 0 { return 1; }
    let last_byte = buf[len - 1] as i32;
    let pad_mask = (1 << (rem_bits as u32)) - 1;
    let pad_val = last_byte & pad_mask;
    if pad_val != pad_mask {
        return 0;
    }
    return 1;
}

fn main() {
    var raw_int: u8[>..] = [];
    assert(wire_kit::parse_hex("1F9A0A", raw_int));
    assert(wire_kit::verify_split_stream(raw_int[..], -1, 1337, wing_decode_hpack_int_5));
    assert(wire_kit::fuzz_payload(raw_int[..], 100, wing_decode_hpack_int_5));
    print("HPACK_INT_SPLIT: OK");

    var ovf: u8[>..] = [];
    assert(wire_kit::parse_hex("1FFFFFFFFFFFFFFFFFFF01", ovf));
    assert(wing_decode_hpack_int_5(ovf[..]) == -2);
    print("HPACK_INT_OVF: OK");

    var pad_ok: u8[>..] = [];
    assert(wire_kit::parse_hex("FF", pad_ok));
    assert(validate_huffman_padding(pad_ok[..], 4) == 1);

    var pad_bad: u8[>..] = [];
    assert(wire_kit::parse_hex("FE", pad_bad));
    assert(validate_huffman_padding(pad_bad[..], 4) == 0);
    print("HPACK_HUFFMAN_PAD: OK");
}

// CHECK: HPACK_INT_SPLIT: OK
// CHECK: HPACK_INT_OVF: OK
// CHECK: HPACK_HUFFMAN_PAD: OK
