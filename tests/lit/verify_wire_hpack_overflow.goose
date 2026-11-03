// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// RUN: goose build -O2 -o %t.exe %s
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

    // Case 2: Huffman flag rejected when non-1s padding bits are present (RFC 7541 Section 5.2)
    // 0x81 = 'H' bit set (0x80) with length 1, followed by 0x00 (invalid padding)
    let huffman_src: const u8[2] = [0x81, 0x00];
    offset = 0;
    out_str.clear();
    let huff_res = wire::hpack_decode_string(huffman_src[..], offset, out_str);
    assert(!huff_res);
    assert(offset == 0);
    print("HPACK_HUFFMAN_FLAG_SAFEGUARD: OK\n");

    // Case 3: HPACK wire integer shift overflow (> 56 bits)
    let int_ovf_src: const u8[11] = [0x7F, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x01];
    offset = 0;
    let _, int_ovf_ok = wire::hpack_decode_int(int_ovf_src[..], offset, 7);
    assert(!int_ovf_ok);
    assert(offset == 0);
    print("HPACK_INT_SHIFT_OVERFLOW: OK\n");

    // Case 4: HPACK wire integer truncated continuation
    let int_trunc_src: const u8[3] = [0x7F, 0x80, 0x80];
    offset = 0;
    let _, int_trunc_ok = wire::hpack_decode_int(int_trunc_src[..], offset, 7);
    assert(!int_trunc_ok);
    assert(offset == 0);
    print("HPACK_INT_TRUNCATED: OK\n");

    // Case 5: HPACK decode string with truncated Huffman stream
    let huff_trunc: const u8[3] = [0x85, 0x11, 0x22];
    out_str.clear();
    let huff_next, huff_ok = internal::decode_hpack_string(huff_trunc[..], 0, out_str);
    assert(!huff_ok);
    assert(huff_next == 0);
    print("HPACK_HUFFMAN_TRUNCATED: OK\n");

    // Case 6: HPACK decode string with invalid padding bits (RFC 7541 §5.2)
    let huff_bad_pad: const u8[2] = [0x81, 0x00];
    out_str.clear();
    let pad_next, pad_ok = internal::decode_hpack_string(huff_bad_pad[..], 0, out_str);
    assert(!pad_ok);
    assert(pad_next == 0);
    print("HPACK_HUFFMAN_BAD_PADDING: OK\n");

    // Case 7: QPACK decode int with truncated multibyte continuation
    let qp_trunc: const u8[2] = [0x3F, 0x80];
    let _, qp_off, qp_ok = internal::qpack_decode_int(qp_trunc[..], 0, 6);
    assert(!qp_ok);
    assert(qp_off == 0);
    print("QPACK_INT_TRUNCATED: OK\n");

    // Case 8: QPACK decode string with truncated payload
    let qp_str_trunc: const u8[4] = [0x8A, 0x11, 0x22, 0x33];
    out_str.clear();
    let qp_s_off, qp_s_ok = internal::decode_qpack_string(qp_str_trunc[..], 0, 7, out_str);
    assert(!qp_s_ok);
    assert(qp_s_off == 0);
    print("QPACK_STRING_TRUNCATED: OK\n");

    print("ALL_HPACK_INVARIANTS_VERIFIED: OK\n");
}

// CHECK: HPACK_TRANSACTIONAL_ROLLBACK: OK
// CHECK: HPACK_HUFFMAN_FLAG_SAFEGUARD: OK
// CHECK: HPACK_INT_SHIFT_OVERFLOW: OK
// CHECK: HPACK_INT_TRUNCATED: OK
// CHECK: HPACK_HUFFMAN_TRUNCATED: OK
// CHECK: HPACK_HUFFMAN_BAD_PADDING: OK
// CHECK: QPACK_INT_TRUNCATED: OK
// CHECK: QPACK_STRING_TRUNCATED: OK
// CHECK: ALL_HPACK_INVARIANTS_VERIFIED: OK
