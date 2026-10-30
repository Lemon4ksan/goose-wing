// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Zero-allocation HPACK integer and string wire codecs (RFC 7541).
namespace wire;

import std;
import core from "..";

inline fn hpack_prefix_mask(prefix_bits: u8) -> u64 {
    return match prefix_bits {
        1 => 1,
        2 => 3,
        3 => 7,
        4 => 15,
        5 => 31,
        6 => 63,
        7 => 127,
        8 => 255,
        _ => 0,
    };
}

inline fn calc_hpack_int_rem(val: u64, max_prefix: u64) -> u64 {
    return val - max_prefix;
}

// Encodes an integer with an N-bit prefix into out (RFC 7541 Section 5.1).
fn hpack_encode_int<B>(out: B&, val: u64, prefix_bits: u8, prefix_mask: u8) -> bool {
    guard prefix_bits >= 1 && prefix_bits <= 8 else { return false; }
    let max_prefix = hpack_prefix_mask(prefix_bits);

    if val < max_prefix {
        guard out.try_push(prefix_mask | (val as u8)) else { return false; }
        return true;
    }

    guard out.try_push(prefix_mask | (max_prefix as u8)) else { return false; }
    var rem = calc_hpack_int_rem(val, max_prefix);

    while rem >= 128 {
        guard out.try_push((0x80 | (rem & 0x7F)) as u8) else { return false; }
        rem = rem >> 7;
    }
    guard out.try_push((rem & 0x7F) as u8) else { return false; }
    return true;
}

// Encodes an indexed header field representation (RFC 7541 Section 6.1).
inline fn hpack_encode_indexed<B>(out: B&, index: u64) -> bool {
    return hpack_encode_int(out, index, 7, 0x80);
}

// Encodes an uncompressed octet sequence string with 7-bit prefix length (RFC 7541 Section 5.2).
fn hpack_encode_string<B>(out: B&, str: const u8[:]) -> bool {
    guard hpack_encode_int(out, str.len as u64, 7, 0x00) else { return false; }
    guard out.try_append(str) else { return false; }
    return true;
}

// Encodes a literal header field without indexing (RFC 7541 Section 6.2.2).
fn hpack_encode_literal_without_indexing<B>(out: B&, name: const u8[:], val: const u8[:]) -> bool {
    guard out.try_push(0x00) else { return false; }
    guard hpack_encode_string(out, name) else { return false; }
    guard hpack_encode_string(out, val) else { return false; }
    return true;
}

// Encodes a literal header field never indexed (RFC 7541 Section 6.2.3).
fn hpack_encode_literal_never_indexed<B>(out: B&, name: const u8[:], val: const u8[:]) -> bool {
    guard out.try_push(0x10) else { return false; }
    guard hpack_encode_string(out, name) else { return false; }
    guard hpack_encode_string(out, val) else { return false; }
    return true;
}

inline fn calc_next_u64_offset(cur: u64, delta: u64) -> u64 {
    return cur + delta;
}

inline fn calc_hpack_int_term(nb: u8, m: u64) -> u64 {
    let payload = (nb & 0x7F) as u64;
    return payload << m;
}

inline fn accumulate_hpack_int(val: u64, term: u64) -> u64 {
    return val + term;
}

inline fn advance_hpack_shift(m: u64) -> u64 {
    return m + 7;
}

// Decodes an integer with an N-bit prefix from slice and advances cursor (RFC 7541 Section 5.1).
//
// Example:
//   src = [0x82], offset = 0, prefix_bits = 7
//   returns: val = 2, ok = true, offset = 1
fn hpack_decode_int(src: const u8[:], offset: u64&, prefix_bits: u8) -> u64, bool {
    guard prefix_bits >= 1 && prefix_bits <= 8 else { return 0, false; }
    guard offset < (src.len as u64) else { return 0, false; }

    let max_prefix = hpack_prefix_mask(prefix_bits);
    let mask = max_prefix as u8;
    let b = src[offset];
    offset = calc_next_u64_offset(offset, 1);

    var val = (b & mask) as u64;
    guard val == max_prefix else { return val, true; }

    var m: u64 = 0;
    while offset < (src.len as u64) {
        let nb = src[offset];
        offset = calc_next_u64_offset(offset, 1);
        let term = calc_hpack_int_term(nb, m);
        val = accumulate_hpack_int(val, term);
        m = advance_hpack_shift(m);
        if (nb & 0x80) == 0 {
            return val, true;
        }
        guard m <= 56 else { return 0, false; }
    }
    return 0, false;
}

// Decodes raw HPACK string and advances cursor (RFC 7541 Section 5.2).
//
// Example:
//   src = [0x04, 't', 'e', 's', 't'], offset = 0
//   returns: ok = true, out = "test", offset = 5
fn hpack_decode_string<B>(src: const u8[:], offset: u64&, out: B&) -> bool {
    guard offset < (src.len as u64) else { return false; }
    let str_len, len_ok = hpack_decode_int(src, offset, 7);
    guard len_ok else { return false; }
    let end = calc_next_u64_offset(offset, str_len);
    guard end <= (src.len as u64) else { return false; }
    guard out.try_append(src[offset..end]) else { return false; }
    offset = end;
    return true;
}
