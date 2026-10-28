// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// RUN: goose %s | %FileCheck %s
import std;
import wire_kit from ".";

fn hpack_decode_int_mem(buf: const u8[:]) -> i64 {
    let len = buf.len;
    if len <= 0 { return -1; }
    let mask: i64 = 31;
    let b0 = buf[0] as i64;
    var val = b0 & mask;
    if val < mask {
        return val;
    }
    var shift: u32 = 0;
    var idx: i64 = 1;
    while idx < len {
        let b = buf[idx];
        let payload = (b & 127) as i64;
        if shift >= 28 {
            if shift > 28 || payload > 15 {
                return -2;
            }
        }
        val += payload << shift;
        idx += 1;
        if (b & 128) == 0 {
            return val;
        }
        shift += 7;
    }
    return -1;
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
    assert(wire_kit::verify_split_stream(raw_int[..], -1, 1337, hpack_decode_int_mem));
    assert(wire_kit::fuzz_payload(raw_int[..], 100, hpack_decode_int_mem));
    print("HPACK_INT_SPLIT: OK");

    var ovf: u8[>..] = [];
    assert(wire_kit::parse_hex("1FFFFFFFFFFFFFFFFFFF01", ovf));
    assert(hpack_decode_int_mem(ovf[..]) == -2);
    print("HPACK_INT_OVF: OK");

    var huff_ok: u8[>..] = [];
    assert(wire_kit::parse_hex("A8EB10649CBF", huff_ok));
    assert(validate_huffman_padding(huff_ok[..], 6) == 1);

    var huff_bad: u8[>..] = [];
    assert(wire_kit::parse_hex("A8EB10649CB0", huff_bad));
    assert(validate_huffman_padding(huff_bad[..], 6) == 0);

    assert(validate_huffman_padding(huff_ok[..], 8) == -1);
    print("HPACK_HUFFMAN_PADDING: OK");
}

// CHECK: HPACK_INT_SPLIT: OK
// CHECK: HPACK_INT_OVF: OK
// CHECK: HPACK_HUFFMAN_PADDING: OK
