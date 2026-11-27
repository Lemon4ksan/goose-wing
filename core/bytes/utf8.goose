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

// Returns true if the slice contains only 7-bit ASCII characters (0x00..0x7F).
// Uses 16-byte / 8-byte SWAR high-bit checks in pure Goose.
fn is_pure_ascii(data: const u8[:]) -> bool {
    let n = data.len;
    guard n > 0 else { return true; }
    var i: i64 = 0;
    while i + 16 <= n {
        let w1 = core::read_le_u64(data, i);
        let w2 = core::read_le_u64(data, i + 8);
        if ((w1 | w2) & 0x8080808080808080) != 0 {
            return false;
        }
        i += 16;
    }
    if i + 8 <= n {
        if (core::read_le_u64(data, i) & 0x8080808080808080) != 0 {
            return false;
        }
        i += 8;
    }
    while i < n {
        if data[i] >= 0x80 {
            return false;
        }
        i += 1;
    }
    return true;
}

// Scans for CRLF (\r\n) delimiter in wire byte streams using 64-bit SWAR.
// Returns offset of '\r' if found, or -1 if not found.
fn find_crlf(data: const u8[:]) -> i64 {
    let n = data.len;
    guard n >= 2 else { return -1; }
    var i: i64 = 0;
    while i + 8 <= n {
        var hit = core::swar_eq_mask(core::read_le_u64(data, i), '\r');
        while hit != 0 {
            let pos = i + (ctz(hit) >> 3);
            if pos + 1 < n && data[pos + 1] == '\n' {
                return pos;
            }
            hit &= hit - 1;
        }
        i += 8;
    }
    while i + 1 < n {
        if data[i] == '\r' && data[i + 1] == '\n' {
            return i;
        }
        i += 1;
    }
    return -1;
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

// Bjoern Hoehrmann's 364-byte UTF-8 DFA table (UTF8_ACCEPT = 0, UTF8_REJECT = 12).
// First 256 bytes map raw bytes to character classes (0..11).
// Remaining 108 bytes map (state + char_class) to the next automaton state.
const UTF8_DFA_ACCEPT: u8 = 0;
const UTF8_DFA_REJECT: u8 = 12;

let UTF8_DFA_TABLE: const u8[364] = [
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
    9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9,
    7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7,
    7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7,
    8, 8, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
    2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
    10, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 4, 3, 3,
    11, 6, 6, 6, 5, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8,
    0, 12, 24, 36, 60, 96, 84, 12, 12, 12, 48, 72, 12, 12, 12, 12,
    12, 12, 12, 12, 12, 12, 12, 12, 12, 0, 12, 12, 12, 12, 12, 0,
    12, 0, 12, 12, 12, 24, 12, 12, 12, 12, 12, 24, 12, 24, 12, 12,
    12, 12, 12, 12, 12, 12, 12, 24, 12, 12, 12, 12, 12, 24, 12, 12,
    12, 12, 12, 12, 12, 24, 12, 12, 12, 12, 12, 12, 12, 12, 12, 36,
    12, 36, 12, 12, 12, 36, 12, 12, 12, 12, 12, 36, 12, 36, 12, 12,
    12, 36, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12,
];

inline fn skip_utf8_dfa_ascii_run(data: const u8[:], n: i64, start_i: i64) -> i64 {
    var i = start_i;
    while core::add_sat_i64(i, 16) <= n {
        let w1 = core::read_be_u64(data, i);
        let w2 = core::read_be_u64(data, core::add_sat_i64(i, 8));
        if ((w1 | w2) & 0x8080808080808080) != 0 {
            break;
        }
        i = core::add_sat_i64(i, 16);
    }
    if core::add_sat_i64(i, 8) <= n {
        let w = core::read_be_u64(data, i);
        if (w & 0x8080808080808080) == 0 {
            i = core::add_sat_i64(i, 8);
        }
    }
    return i;
}

inline fn step_utf8_dfa_byte(s: u8, b: u8) -> u8 {
    let char_cls = UTF8_DFA_TABLE[b as i64];
    let offset = core::add_sat_i64(s, char_cls);
    let trans_idx = min(core::add_sat_i64(256, offset), 363);
    return UTF8_DFA_TABLE[trans_idx];
}

// Validates a streaming UTF-8 chunk in-place using Bjoern Hoehrmann's 364-byte DFA
// without requiring fragment reassembly across split codepoint boundaries (RFC 3629 & RFC 6455 §8.1).
// Uses a 16-byte SWAR ASCII fast-path whenever `state == 0` (`UTF8_DFA_ACCEPT`).
fn validate_utf8_dfa_chunk(data: const u8[:], state: u8&, is_fin: bool) -> bool {
    let n = data.len;
    var s = state;
    guard s != UTF8_DFA_REJECT else { return false; }

    var i: i64 = 0;
    while i < n {
        if s == UTF8_DFA_ACCEPT {
            i = skip_utf8_dfa_ascii_run(data, n, i);
            if i >= n {
                break;
            }
        }
        s = step_utf8_dfa_byte(s, data[i]);
        guard s != UTF8_DFA_REJECT else {
            state = UTF8_DFA_REJECT;
            return false;
        }
        i = core::add_sat_i64(i, 1);
    }

    state = s;
    return !is_fin || s == UTF8_DFA_ACCEPT;
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
    let limit = max(0, s.len - 4);
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
