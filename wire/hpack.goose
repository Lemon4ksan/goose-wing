// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Zero-allocation HPACK integer and string wire codecs (RFC 7541).
namespace wire;

import std;
import core from "..";

const HPACK_PREFIX_MASKS: const u64[256] = [
    0, 1, 3, 7, 15, 31, 63, 127, 255, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
];

checkfree inline fn hpack_prefix_mask(prefix_bits: u8) -> u64 {
    return HPACK_PREFIX_MASKS[prefix_bits];
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
    var rem = val - max_prefix;

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

// Decodes a variable-length multi-byte HPACK integer continuation (RFC 7541 Section 5.1).
// Advances `offset` past the multi-byte integer octets.
//
// Example:
//   src = [0x9A, 0x0A], offset = 0, initial_offset = 0, max_prefix = 127
//   returns: val = 1461, ok = true, offset = 2
fn decode_hpack_int_multibyte(src: const u8[:], offset: u64&, initial_offset: u64, max_prefix: u64) -> u64, bool {
    var val: u64 = max_prefix;
    var m:   u64 = 0;
    while offset < (src.len as u64) {
        let nb = src[offset];
        offset += 1;
        let term = ((nb & 0x7F) as u64) << m;
        guard val <= (0xFFFFFFFFFFFFFFFF - term) else {
            offset = initial_offset;
            return 0, false;
        }
        val += term;
        m += 7;
        if (nb & 0x80) == 0 {
            return val, true;
        }
        guard m <= 56 else {
            offset = initial_offset;
            return 0, false;
        }
    }
    offset = initial_offset;
    return 0, false;
}

// Decodes an integer with an N-bit prefix from slice and advances cursor (RFC 7541 Section 5.1).
//
// Example:
//   src = [0x82], offset = 0, prefix_bits = 7
//   returns: val = 2, ok = true, offset = 1
fn hpack_decode_int(src: const u8[:], offset: u64&, prefix_bits: u8) -> u64, bool {
    let initial_offset = offset;
    guard prefix_bits >= 1 && prefix_bits <= 8 else { return 0, false; }
    guard offset < (src.len as u64) else { return 0, false; }

    let max_prefix = hpack_prefix_mask(prefix_bits);
    let mask = max_prefix as u8;
    let b = src[offset];
    offset += 1;

    let val = (b & mask) as u64;
    guard val == max_prefix else { return val, true; }

    return decode_hpack_int_multibyte(src, offset, initial_offset, max_prefix);
}

inline fn copy_hpack_slice<B>(src: const u8[:], offset: u64, end: u64, out: B&) -> bool {
    return out.try_append(src[offset..end]);
}

// Decodes raw HPACK string and advances cursor (RFC 7541 Section 5.2).
//
// Example:
//   src = [0x04, 't', 'e', 's', 't'], offset = 0
//   returns: ok = true, out = "test", offset = 5
fn hpack_decode_string<B>(src: const u8[:], offset: u64&, out: B&) -> bool {
    let initial_offset = offset;
    guard offset < (src.len as u64) && (src[offset] & 0x80) == 0 else { return false; }

    let str_len, len_ok = hpack_decode_int(src, offset, 7);
    let rem = (src.len as u64) - offset;
    guard len_ok && str_len <= rem else {
        offset = initial_offset;
        return false;
    }
    let end = offset + str_len;
    guard copy_hpack_slice(src, offset, end, out) else {
        offset = initial_offset;
        return false;
    }
    offset = end;
    return true;
}
