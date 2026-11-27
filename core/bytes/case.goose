// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Case-insensitive ASCII folding, character predicates, and ASCII transformations.
namespace core;

import std;

// Checks whether byte is ASCII uppercase letter ('A'..'Z').
fn is_ascii_upper(b: u8) -> bool {
    return b >= 'A' && b <= 'Z';
}

// Checks whether byte is ASCII lowercase letter ('a'..'z').
fn is_ascii_lower(b: u8) -> bool {
    return b >= 'a' && b <= 'z';
}

// Checks whether byte is ASCII alphabetic ('A'..'Z' or 'a'..'z').
fn is_ascii_alpha(b: u8) -> bool {
    return (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z');
}

// Checks whether byte is ASCII decimal digit ('0'..'9').
fn is_ascii_digit(b: u8) -> bool {
    return b >= '0' && b <= '9';
}

// Checks whether byte is ASCII alphanumeric ('0'..'9', 'a'..'z', 'A'..'Z').
fn is_ascii_alphanumeric(b: u8) -> bool {
    return is_ascii_alpha(b) || is_ascii_digit(b);
}

// Checks whether byte is an ASCII hexadecimal digit ('0'..'9', 'a'..'f', 'A'..'F').
checkfree inline fn is_ascii_hexdigit(b: u8) -> bool {
    return (b >= '0' && b <= '9') || (b >= 'a' && b <= 'f') || (b >= 'A' && b <= 'F');
}

// Checks whether byte is visible ASCII (VCHAR, RFC 5234 §B.1: 0x21..0x7E).
inline fn is_ascii_vchar(b: u8) -> bool {
    return b >= 0x21 && b <= 0x7E;
}

// Checks whether byte is printable ASCII (0x20..0x7E).
inline fn is_ascii_printable(b: u8) -> bool {
    return b >= 0x20 && b <= 0x7E;
}

const TCHAR_LUT: const bool[256] = [
    false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false,
    false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false,
    false, true, false, true, true, true, true, true, false, false, true, true, false, true, true, false,
    true, true, true, true, true, true, true, true, true, true, false, false, false, false, false, false,
    false, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true,
    true, true, true, true, true, true, true, true, true, true, true, false, false, false, true, true,
    true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true,
    true, true, true, true, true, true, true, true, true, true, true, false, true, false, true, false,
    false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false,
    false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false,
    false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false,
    false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false,
    false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false,
    false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false,
    false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false,
    false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false,
];

// RFC 9110 Section 5.6.2: Checks whether byte is an HTTP token character (tchar).
checkfree inline fn is_tchar(b: u8) -> bool {
    return TCHAR_LUT[b];
}

const URI_UNRESERVED_LUT: const bool[256] = [
    false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false,
    false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false,
    false, false, false, false, false, false, false, false, false, false, false, false, false, true, true, false,
    true, true, true, true, true, true, true, true, true, true, false, false, false, false, false, false,
    false, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true,
    true, true, true, true, true, true, true, true, true, true, true, false, false, false, false, true,
    false, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true,
    true, true, true, true, true, true, true, true, true, true, true, false, false, false, true, false,
    false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false,
    false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false,
    false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false,
    false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false,
    false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false,
    false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false,
    false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false,
    false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false,
];

// RFC 3986 Section 2.3: Checks whether byte is an unreserved URI character (ALPHA / DIGIT / "-" / "." / "_" / "~").
checkfree inline fn is_uri_unreserved(b: u8) -> bool {
    return URI_UNRESERVED_LUT[b];
}

// Converts an ASCII byte to lowercase if it is uppercase; otherwise returns unchanged.
fn to_lower_ascii_byte(b: u8) -> u8 {
    return if b >= 'A' && b <= 'Z' { b + 32 } else { b };
}

// 64-bit SWAR parallel ASCII lowercase transform (sets bit 5 on 'A'..'Z' in 8 bytes).
inline fn swar_to_lower_64(v: u64) -> u64 {
    let ascii = v & 0x7F7F7F7F7F7F7F7F;
    let not_high = (~v) & 0x8080808080808080;
    let is_upper = (ascii + 0x3F3F3F3F3F3F3F3F) & (~(ascii + 0x2525252525252525)) & not_high;
    return v | (is_upper >> 2);
}

// 64-bit SWAR parallel ASCII uppercase transform (clears bit 5 on 'a'..'z' in 8 bytes).
inline fn swar_to_upper_64(v: u64) -> u64 {
    let ascii = v & 0x7F7F7F7F7F7F7F7F;
    let not_high = (~v) & 0x8080808080808080;
    let is_lower = (ascii + 0x1F1F1F1F1F1F1F1F) & (~(ascii + 0x0505050505050505)) & not_high;
    return v ^ (is_lower >> 2);
}

// Transforms byte slice in-place to ASCII lowercase using 64-bit SWAR.
fn make_ascii_lowercase(buf: u8[:]) {
    guard buf.len > 0 else { return; }
    var i: i64 = 0;
    while i + 8 <= buf.len {
        write_le_u64_at(buf, i, swar_to_lower_64(read_le_u64(buf, i)));
        i += 8;
    }
    while i < buf.len {
        let b = buf[i];
        if b >= 'A' && b <= 'Z' {
            buf[i] = b | 32;
        }
        i += 1;
    }
}

// Transforms byte slice in-place to ASCII uppercase using 64-bit SWAR.
fn make_ascii_uppercase(buf: u8[:]) {
    guard buf.len > 0 else { return; }
    var i: i64 = 0;
    while i + 8 <= buf.len {
        write_le_u64_at(buf, i, swar_to_upper_64(read_le_u64(buf, i)));
        i += 8;
    }
    while i < buf.len {
        let b = buf[i];
        if b >= 'a' && b <= 'z' {
            buf[i] = b - 32;
        }
        i += 1;
    }
}

// RFC 9110 Section 5.6.3: Compares two byte slices for case-insensitive ASCII equality.
// Uses identity fast-path and 64-bit SWAR comparison (8 bytes per cycle).
inline fn eq_ascii_fold(str_a: const u8[:], str_b: const u8[:]) -> bool {
    guard str_a.len == str_b.len else { return false; }
    if str_a.len == 0 || str_a == str_b { return true; }
    var i: i64 = 0;
    while i + 8 <= str_a.len {
        let wa = swar_to_lower_64(read_le_u64(str_a, i));
        let wb = swar_to_lower_64(read_le_u64(str_b, i));
        if wa != wb { return false; }
        i += 8;
    }
    while i < str_a.len {
        if to_lower_ascii_byte(str_a[i]) != to_lower_ascii_byte(str_b[i]) {
            return false;
        }
        i += 1;
    }
    return true;
}

// Checks whether s begins with prefix using case-insensitive ASCII comparison.
fn starts_with_fold(s: const u8[:], prefix: const u8[:]) -> bool {
    guard s.len >= prefix.len else { return false; }
    return eq_ascii_fold(s[..prefix.len], prefix);
}

// Checks whether s ends with suffix using case-insensitive ASCII comparison.
fn ends_with_fold(s: const u8[:], suffix: const u8[:]) -> bool {
    guard s.len >= suffix.len else { return false; }
    return eq_ascii_fold(s[^suffix.len..], suffix);
}

// Searches for needle in haystack using case-insensitive ASCII comparison.
// Returns the 0-based byte index of the first match, or -1 if not found.
fn index_of_fold(haystack: const u8[:], needle: const u8[:]) -> i64 {
    guard needle.len <= haystack.len else { return -1; }
    guard needle.len > 0 else { return 0; }
    let max_pos = haystack.len - needle.len;
    for i in max_pos + 1 {
        if eq_ascii_fold(haystack[i..i + needle.len], needle) {
            return i;
        }
    }
    return -1;
}

// Checks whether haystack contains needle using case-insensitive ASCII comparison.
fn contains_fold(haystack: const u8[:], needle: const u8[:]) -> bool {
    return index_of_fold(haystack, needle) >= 0;
}

// Appends ASCII lowercase transformed bytes from src into out buffer.
fn to_lower_ascii<B>(src: const u8[:], out: B&) {
    for b in src {
        out.push(to_lower_ascii_byte(b));
    }
}

// Appends ASCII uppercase transformed bytes from src into out buffer.
fn to_upper_ascii<B>(src: const u8[:], out: B&) {
    for b in src {
        out.push(to_upper_ascii_byte(b));
    }
}
