// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// RUN: goose build --cc gcc -O2 -o %t.exe %s
// RUN: %t.exe | %FileCheck %s

// Verification of HPACK bounds safety and transactional cursor rollback (RFC 7541).
import std;
import core from "../..";
import wing from "../..";

fn main() {
    print("=== VERIFY_WIRE_HPACK_OVERFLOW ===\n");

    var out_str: u8[..64] = [];

    // Case 1: Transactional cursor rollback on premature EOF in hpack_decode_string
    // Encodes length prefix 10, but provides only 3 bytes ("abc")
    let truncated_src: const u8[4] = [10, 'a', 'b', 'c'];
    var offset: u64 = 0;
    let res = wire::hpack_decode_string(truncated_src[..], offset, out_str);
    assert(!res);
    // Offset must roll back to 0 on failure (Rule 5 Transactional cursor contract)
    assert(offset == 0);
    print("HPACK_TRANSACTIONAL_ROLLBACK: OK\n");
    // CHECK: HPACK_TRANSACTIONAL_ROLLBACK: OK

    // Case 2: Huffman flag rejected when raw decoding is requested (BUG-15)
    // 0x84 = 'H' bit set (0x80) with length 4
    let huffman_src: const u8[5] = [0x84, 0x11, 0x22, 0x33, 0x44];
    offset = 0;
    out_str.clear();
    let huff_res = wire::hpack_decode_string(huffman_src[..], offset, out_str);
    assert(!huff_res);
    assert(offset == 0);
    print("HPACK_HUFFMAN_FLAG_SAFEGUARD: OK\n");
    // CHECK: HPACK_HUFFMAN_FLAG_SAFEGUARD: OK

    print("ALL_HPACK_INVARIANTS_VERIFIED: OK\n");
    // CHECK: ALL_HPACK_INVARIANTS_VERIFIED: OK
}
