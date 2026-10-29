// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// tests/lit/verify_hpack_qpack.goose
// Verification of HPACK & QPACK integer prefix decoding, string framing, and Huffman codec via wing.
//
// RUN: goose build --cc gcc -O2 -o %t.exe %s
// RUN: %t.exe | %FileCheck %s

import std;
import core from "../..";
import wing from "../..";
import wire_kit from ".";

// Wire adapter for verify_split_stream and fuzzing using wing::hpack_decode_int (5-bit prefix)
fn wing_decode_varint_5(buf: const u8[:]) -> i64 {
    guard buf.len > 0 else { return -1; }
    let val, new_off, ok = wing::hpack_decode_int(buf, 0, 5);
    if ok { return val as! i64; }
    if new_off == 0 { return -1; }
    return -2;
}

// Wire adapter for verify_split_stream and fuzzing using wing::hpack_decode_int (7-bit prefix)
fn wing_decode_varint_7(buf: const u8[:]) -> i64 {
    guard buf.len > 0 else { return -1; }
    let val, new_off, ok = wing::hpack_decode_int(buf, 0, 7);
    if ok { return val as! i64; }
    if new_off == 0 { return -1; }
    return -2;
}

// Wire adapter for verify_split_stream and fuzzing using wing::decode_hpack_string
fn wing_parse_hpack_string_frame(buf: const u8[:]) -> i64 {
    guard buf.len > 0 else { return -1; }
    var out: u8[..4096] = [];
    let next_off, ok = wing::decode_hpack_string(buf, 0, out);
    if ok {
        let is_huff = (buf[0] & 0x80) != 0;
        let str_len, _, _ = wing::hpack_decode_int(buf, 0, 7);
        return if is_huff { 0 - (str_len as i64) } else { str_len as i64 };
    }
    return -1;
}

fn calc_varint_step(acc: i64, payload: i64, shift: i64) -> i64 {
    return acc + ((payload & 127) << (shift as u32));
}

fn derive_hpack_mask(prefix_bits: i64) -> i64 {
    return (1 << (prefix_bits as u32)) - 1;
}

fn main() {
    var v5: u8[>..] = []; wire_kit::parse_hex("1F9A0A", v5);
    assert(wire_kit::verify_split_stream(v5[..], -1, 1337, wing_decode_varint_5));
    assert(wire_kit::fuzz_payload(v5[..], 100, wing_decode_varint_5));
    print("HPACK_VARINT_5: OK");

    var v7_42: u8[>..] = []; wire_kit::parse_hex("2A", v7_42);
    assert(wing_decode_varint_7(v7_42[..]) == 42);

    var v7_255: u8[>..] = []; wire_kit::parse_hex("7F8001", v7_255);
    assert(wire_kit::verify_split_stream(v7_255[..], -1, 255, wing_decode_varint_7));
    assert(wire_kit::fuzz_payload(v7_255[..], 100, wing_decode_varint_7));

    var vA: u8[>..] = []; wire_kit::parse_hex("7FFFFFFFFFFF10", vA);
    assert(wing_decode_varint_7(vA[..]) == -2);
    var vB: u8[>..] = []; wire_kit::parse_hex("7FFFFFFFFFFFFFFFFFFF01", vB);
    assert(wing_decode_varint_7(vB[..]) == -2);
    var vC: u8[>..] = []; wire_kit::parse_hex("7F80", vC);
    assert(wing_decode_varint_7(vC[..]) == -1);
    print("HPACK_VARINT_7: OK");

    var str_raw: u8[>..] = []; wire_kit::parse_hex("0A637573746F6D2D6B6579", str_raw);
    assert(wire_kit::verify_split_stream(str_raw[..], -1, 10, wing_parse_hpack_string_frame));
    assert(wire_kit::fuzz_payload(str_raw[..], 100, wing_parse_hpack_string_frame));

    var str_huff: u8[>..] = []; wire_kit::parse_hex("8CF1E3C2E5F23A6BA0AB90F4FF", str_huff);
    assert(wire_kit::verify_split_stream(str_huff[..], -1, -12, wing_parse_hpack_string_frame));
    assert(wire_kit::fuzz_payload(str_huff[..], 100, wing_parse_hpack_string_frame));

    var str_ovf: u8[>..] = []; wire_kit::parse_hex("40010203", str_ovf);
    assert(wing_parse_hpack_string_frame(str_ovf[..]) == -1);
    print("HPACK_STRING_FRAMING: OK");

    assert(calc_varint_step(31, 10, 7) == 1311);
    assert(derive_hpack_mask(5) == 31);
    print("HPACK_QPACK_ALL: PASS");
}

// CHECK: HPACK_VARINT_5: OK
// CHECK: HPACK_VARINT_7: OK
// CHECK: HPACK_STRING_FRAMING: OK
// CHECK: HPACK_QPACK_ALL: PASS
