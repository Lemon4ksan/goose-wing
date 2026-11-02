// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Goose Core Byte String - Fast UTF-8 Validation (RFC 3629 & Unicode Standard).
// Implements zero-allocation, bounds-checked validation verifying:
// - 64-bit unrolled ASCII fast-path (8 bytes per cycle checking high-bit mask 0x80)
// - Valid 2-byte, 3-byte, and 4-byte lead and continuation sequences
// - Rejection of overlong encodings (e.g. 0xC0..0xC1, 0xE0 with b1 < 0xA0, 0xF0 with b1 < 0x90)
// - Rejection of UTF-16 surrogates (U+D800..U+DFFF, 0xED with b1 >= 0xA0)
// - Rejection of codepoints above U+10FFFF (0xF4 with b1 > 0x8F, or byte >= 0xF5)
namespace core;

import std;

extern fn native_simd_is_pure_ascii(data: const u8[:]) -> i32 = "wing_simd_is_pure_ascii";
extern fn native_simd_find_crlf(data: const u8[:]) -> i64 = "wing_simd_find_crlf";

// Returns true if the slice contains only 7-bit ASCII characters (0x00..0x7F).
// Uses 128-bit SSE2 vectorization (16 bytes per cycle) with 64-bit SWAR fallback.
fn is_pure_ascii(data: const u8[:]) -> bool {
    guard data.len > 0 else { return true; }
    return native_simd_is_pure_ascii(data) != 0;
}

// Scans for CRLF (\r\n) delimiter in wire byte streams using 128-bit SSE2 vector comparison.
// Returns offset of '\r' if found, or -1 if not found.
fn find_crlf(data: const u8[:]) -> i64 {
    guard data.len >= 2 else { return -1; }
    return native_simd_find_crlf(data);
}

// Returns true if the slice contains valid RFC 3629 UTF-8.
// Uses a 16-byte SWAR loop to skip ASCII runs before validating multibyte sequences.
fn validate_utf8(data: const u8[:]) -> bool {
    let n = data.len;
    guard n > 0 else { return true; }

    var i: i64 = 0;
    while i < n {
        // 16-byte SWAR fast-path: if both 64-bit words have no high bits set, 16 ASCII bytes are valid
        if i + 16 <= n {
            let w1 = core::read_be_u64(data, i);
            let w2 = core::read_be_u64(data, i + 8);
            if ((w1 & 0x8080808080808080) | (w2 & 0x8080808080808080)) == 0 {
                i += 16;
                continue;
            }
        } else if i + 8 <= n {
            let w = core::read_be_u64(data, i);
            if (w & 0x8080808080808080) == 0 {
                i += 8;
                continue;
            }
        }

        let b0 = data[i];
        if b0 <= 0x7F {
            i++;
        } else if (b0 & 0xE0) == 0xC0 {
            guard i + 1 < n else { return false; }
            let b1 = data[i + 1];
            guard (b1 & 0xC0) == 0x80 else { return false; }
            guard b0 >= 0xC2 else { return false; } // Overlong
            i += 2;
        } else if (b0 & 0xF0) == 0xE0 {
            guard i + 2 < n else { return false; }
            let b1 = data[i + 1];
            let b2 = data[i + 2];
            guard (b1 & 0xC0) == 0x80 && (b2 & 0xC0) == 0x80 else { return false; }
            if b0 == 0xE0 && b1 < 0xA0 { return false; } // Overlong
            if b0 == 0xED && b1 >= 0xA0 { return false; } // UTF-16 surrogates U+D800..U+DFFF
            i += 3;
        } else if (b0 & 0xF8) == 0xF0 {
            guard i + 3 < n else { return false; }
            let b1 = data[i + 1];
            let b2 = data[i + 2];
            let b3 = data[i + 3];
            guard (b1 & 0xC0) == 0x80 && (b2 & 0xC0) == 0x80 && (b3 & 0xC0) == 0x80 else { return false; }
            if b0 == 0xF0 && b1 < 0x90 { return false; } // Overlong
            if b0 == 0xF4 && b1 > 0x8F { return false; } // Above U+10FFFF
            guard b0 <= 0xF4 else { return false; }
            i += 4;
        } else {
            return false;
        }
    }
    return true;
}

inline fn step_utf8_multibyte(
    data:     const u8[:],
    n:        i64,
    i:        i64,
    b0:       u8,
    is_final: bool,
) -> i64, bool {
    if (b0 & 0xE0) == 0xC0 {
        guard b0 >= 0xC2 else { return 0, false; }
        if i + 1 >= n {
            if is_final { return 0, false; }
            return i, true;
        }
        let b1 = data[i + 1];
        guard (b1 & 0xC0) == 0x80 else { return 0, false; }
        return i + 2, true;
    } else if (b0 & 0xF0) == 0xE0 {
        if i + 1 >= n {
            if is_final { return 0, false; }
            return i, true;
        }
        let b1 = data[i + 1];
        guard (b1 & 0xC0) == 0x80 else { return 0, false; }
        if b0 == 0xE0 && b1 < 0xA0 { return 0, false; }
        if b0 == 0xED && b1 >= 0xA0 { return 0, false; }
        if i + 2 >= n {
            if is_final { return 0, false; }
            return i, true;
        }
        let b2 = data[i + 2];
        guard (b2 & 0xC0) == 0x80 else { return 0, false; }
        return i + 3, true;
    } else if (b0 & 0xF8) == 0xF0 {
        guard b0 <= 0xF4 else { return 0, false; }
        if i + 1 >= n {
            if is_final { return 0, false; }
            return i, true;
        }
        let b1 = data[i + 1];
        guard (b1 & 0xC0) == 0x80 else { return 0, false; }
        if b0 == 0xF0 && b1 < 0x90 { return 0, false; }
        if b0 == 0xF4 && b1 > 0x8F { return 0, false; }
        if i + 2 >= n {
            if is_final { return 0, false; }
            return i, true;
        }
        let b2 = data[i + 2];
        guard (b2 & 0xC0) == 0x80 else { return 0, false; }
        if i + 3 >= n {
            if is_final { return 0, false; }
            return i, true;
        }
        let b3 = data[i + 3];
        guard (b3 & 0xC0) == 0x80 else { return 0, false; }
        return i + 4, true;
    }
    return 0, false;
}

// Validates a streaming UTF-8 buffer across fragment boundaries (RFC 3629 & RFC 6455 §8.1).
// When `is_final` is false, allows a valid 1..3 byte prefix of an incomplete multi-byte codepoint
// at the end of `data`, returning the byte offset up to which complete codepoints were verified.
// Immediately rejects invalid lead bytes, overlong prefixes, surrogates, and out-of-range prefixes.
//
// Example:
//   data = "hello world", is_final = true
//   returns: 11, ok = true
fn validate_utf8_streaming(data: const u8[:], is_final: bool) -> i64, bool {
    let n = data.len;
    guard n > 0 else { return 0, true; }

    var i: i64 = 0;
    while i < n {
        if i + 16 <= n {
            let w1 = core::read_be_u64(data, i);
            let w2 = core::read_be_u64(data, i + 8);
            if ((w1 & 0x8080808080808080) | (w2 & 0x8080808080808080)) == 0 {
                i += 16;
                continue;
            }
        } else if i + 8 <= n {
            let w = core::read_be_u64(data, i);
            if (w & 0x8080808080808080) == 0 {
                i += 8;
                continue;
            }
        }

        let b0 = data[i];
        if b0 <= 0x7F {
            i++;
            continue;
        }
        let next_i, ok = step_utf8_multibyte(data, n, i, b0, is_final);
        guard ok else { return 0, false; }
        if next_i == i { return i, true; }
        i = next_i;
    }
    return i, true;
}

// Decode one Unicode scalar, returning (codepoint, consumed bytes, valid).
// Invalid input yields U+FFFD and consumes one maximal subpart (RFC 3629 / Unicode Standard).
// Empty input yields (U+FFFD, 0, false).
//
// Example:
//   s = "café"
//   returns: cp = 99 ('c'), size = 1, valid = true
fn decode_utf8(s: const u8[:]) -> i64, i64, bool {
    guard s.len > 0 else { return 0xFFFD, 0, false; }
    let lead = s[0] as i64;
    if lead < 0x80 { return lead, 1, true; }
    if lead < 0xC2 || lead > 0xF4 { return 0xFFFD, 1, false; }
    let width = if lead < 0xE0 { 2 } else if lead < 0xF0 { 3 } else { 4 };
    var cp = lead & (0x7F >> width);
    for i in 1..width {
        if i == s.len { return 0xFFFD, i, false; }
        let b = s[i] as i64;
        if b < 0x80 || b > 0xBF { return 0xFFFD, i, false; }
        if i == 1 && ((lead == 0xE0 && b < 0xA0) || (lead == 0xED && b > 0x9F)
                  || (lead == 0xF0 && b < 0x90) || (lead == 0xF4 && b > 0x8F)) {
            return 0xFFFD, 1, false;
        }
        cp = (cp << 6) | (b & 0x3F);
    }
    return cp, width, true;
}

// Decode the final Unicode scalar, returning (codepoint, consumed bytes, valid).
// Invalid input yields U+FFFD for the final malformed subpart;
// empty input yields (U+FFFD, 0, false).
//
// Example:
//   s = "!é"
//   returns: cp = 0xE9, size = 2, valid = true
fn decode_last_utf8(s: const u8[:]) -> i64, i64, bool {
    guard s.len > 0 else { return 0xFFFD, 0, false; }
    var start = s.len - 1;
    let limit = if s.len - 4 > 0 { s.len - 4 } else { 0 };
    while start > limit && s[start] >= 0x80 && s[start] <= 0xBF { start -= 1; }
    let cp, size, valid = decode_utf8(s[start..]);
    if start + size != s.len { return 0xFFFD, 1, false; }
    return cp, size, valid;
}

// Return (codepoint, consumed bytes) from the start, replacing a malformed
// maximal subpart with U+FFFD. Empty input returns (U+FFFD, 0).
//
// Example:
//   s = "\xE2\x82!"
//   returns: cp = 0xFFFD, size = 2
fn decode_utf8_lossy(s: const u8[:]) -> i64, i64 {
    let cp, size, _ = decode_utf8(s);
    return cp, size;
}

// Return (codepoint, consumed bytes) from the end, replacing the final
// malformed subpart with U+FFFD. Empty input returns (U+FFFD, 0).
//
// Example:
//   s = "!\xE2\x82"
//   returns: cp = 0xFFFD, size = 2
fn decode_last_utf8_lossy(s: const u8[:]) -> i64, i64 {
    let cp, size, _ = decode_last_utf8(s);
    return cp, size;
}

// Call F(start, end, codepoint) for each decoded scalar or malformed maximal subpart.
fn char_indices<F>(s: const u8[:]) {
    var i: i64 = 0;
    while i < s.len {
        let cp, size, _ = decode_utf8(s[i..]);
        F(i, i + size, cp);
        i += size;
    }
}
