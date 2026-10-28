// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// RUN: goose %s | %FileCheck %s
import std;
import wire_kit from ".";

fn decode_varint_5(buf: const u8[:]) -> i64 {
    let len = buf.len;
    if len < 1 { return -1; }
    let prefix = (buf[0] & 31) as i64;
    if prefix < 31 { return prefix; }

    var val: i64 = 31;
    var shift: u32 = 0;
    var i: i64 = 1;

    while i < len {
        let b = buf[i];
        let payload = (b & 127) as i64;
        if shift >= 28 {
            if shift > 28 || payload > 15 {
                return -2;
            }
        }
        val += payload << shift;
        i += 1;
        if (b & 128) == 0 {
            return val;
        }
        shift += 7;
    }
    return -1;
}

fn decode_varint_7(buf: const u8[:]) -> i64 {
    let len = buf.len;
    if len < 1 { return -1; }
    let prefix = (buf[0] & 127) as i64;
    if prefix < 127 { return prefix; }

    var val: i64 = 127;
    var shift: u32 = 0;
    var i: i64 = 1;

    while i < len {
        let b = buf[i];
        let payload = (b & 127) as i64;
        if shift >= 28 {
            if shift > 28 || payload > 15 {
                return -2;
            }
        }
        val += payload << shift;
        i += 1;
        if (b & 128) == 0 {
            return val;
        }
        shift += 7;
    }
    return -1;
}

fn parse_hpack_string_frame(buf: const u8[:]) -> i64 {
    let len = buf.len;
    if len < 1 { return -1; }
    let b0 = buf[0];
    let is_huffman = (b0 & 128) != 0;
    let raw_len = (b0 & 127) as i64;

    var str_len: i64 = raw_len;
    var hdr_len: i64 = 1;

    if raw_len == 127 {
        var shift: u32 = 0;
        var i: i64 = 1;
        var cont_ok = false;
        while i < len {
            let b = buf[i];
            let payload = (b & 127) as i64;
            if shift >= 28 {
                if shift > 28 || payload > 15 { return -2; }
            }
            str_len += payload << shift;
            i += 1;
            if (b & 128) == 0 {
                cont_ok = true;
                hdr_len = i;
                break;
            }
            shift += 7;
        }
        if !cont_ok { return -1; }
    }

    if len < hdr_len + str_len {
        return -1;
    }

    if is_huffman {
        return 0 - str_len;
    }
    return str_len;
}

fn calc_varint_step(acc: i64, payload: i64, shift: i64) -> i64 {
    return acc + ((payload & 127) << (shift as u32));
}

fn derive_hpack_mask(prefix_bits: i64) -> i64 {
    return (1 << (prefix_bits as u32)) - 1;
}

fn main() {
    var v5: u8[>..] = []; wire_kit::parse_hex("1F9A0A", v5);
    assert(wire_kit::verify_split_stream(v5[..], -1, 1337, decode_varint_5));
    assert(wire_kit::fuzz_payload(v5[..], 100, decode_varint_5));
    print("HPACK_VARINT_5: OK");

    var v7_42: u8[>..] = []; wire_kit::parse_hex("2A", v7_42);
    assert(decode_varint_7(v7_42[..]) == 42);

    var v7_255: u8[>..] = []; wire_kit::parse_hex("7F8001", v7_255);
    assert(wire_kit::verify_split_stream(v7_255[..], -1, 255, decode_varint_7));
    assert(wire_kit::fuzz_payload(v7_255[..], 100, decode_varint_7));

    var vA: u8[>..] = []; wire_kit::parse_hex("7FFFFFFFFFFF10", vA);
    assert(decode_varint_7(vA[..]) == -2);
    var vB: u8[>..] = []; wire_kit::parse_hex("7FFFFFFFFFFFFFFFFFFF01", vB);
    assert(decode_varint_7(vB[..]) == -2);
    var vC: u8[>..] = []; wire_kit::parse_hex("7F80", vC);
    assert(decode_varint_7(vC[..]) == -1);
    print("HPACK_VARINT_7: OK");

    var str_raw: u8[>..] = []; wire_kit::parse_hex("0A637573746F6D2D6B6579", str_raw);
    assert(wire_kit::verify_split_stream(str_raw[..], -1, 10, parse_hpack_string_frame));
    assert(wire_kit::fuzz_payload(str_raw[..], 100, parse_hpack_string_frame));

    var str_huff: u8[>..] = []; wire_kit::parse_hex("8CF1E3C2E5F23A6BA0AB90F4FF", str_huff);
    assert(wire_kit::verify_split_stream(str_huff[..], -1, -12, parse_hpack_string_frame));
    assert(wire_kit::fuzz_payload(str_huff[..], 100, parse_hpack_string_frame));

    var str_ovf: u8[>..] = []; wire_kit::parse_hex("40010203", str_ovf);
    assert(parse_hpack_string_frame(str_ovf[..]) == -1);
    print("HPACK_STRING_FRAMING: OK");

    assert(calc_varint_step(31, 10, 7) == 1311);
    assert(derive_hpack_mask(5) == 31);
    print("HPACK_QPACK_ALL: PASS");
}

// CHECK: HPACK_VARINT_5: OK
// CHECK: HPACK_VARINT_7: OK
// CHECK: HPACK_STRING_FRAMING: OK
// CHECK: HPACK_QPACK_ALL: PASS
