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
inline fn is_ascii_hexdigit(b: u8) -> bool {
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

// Converts an ASCII byte to uppercase if it is lowercase; otherwise returns unchanged.
fn to_upper_ascii_byte(b: u8) -> u8 {
    return if b >= 'a' && b <= 'z' { b - 32 } else { b };
}

extern fn native_swar_eq_ascii_fold(a: const u8[:], b: const u8[:]) -> i32 = "wing_swar_eq_ascii_fold";
extern fn native_swar_to_lower(slice: u8[:]) = "wing_swar_to_lower";
extern fn native_swar_to_upper(slice: u8[:]) = "wing_swar_to_upper";

// Transforms byte slice in-place to ASCII lowercase using 64-bit SWAR.
fn make_ascii_lowercase(buf: u8[:]) {
    guard buf.len > 0 else { return; }
    native_swar_to_lower(buf);
}

// Transforms byte slice in-place to ASCII uppercase using 64-bit SWAR.
fn make_ascii_uppercase(buf: u8[:]) {
    guard buf.len > 0 else { return; }
    native_swar_to_upper(buf);
}

// RFC 9110 Section 5.6.3: Compares two byte slices for case-insensitive ASCII equality.
// Fast path uses 64-bit SWAR evaluation (8 bytes per cycle) with vectorized memcmp identity check.
fn eq_ascii_fold(str_a: const u8[:], str_b: const u8[:]) -> bool {
    guard str_a.len == str_b.len else { return false; }
    return native_swar_eq_ascii_fold(str_a, str_b) != 0;
}

// Checks whether s begins with prefix using case-insensitive ASCII comparison.
fn starts_with_fold(s: const u8[:], prefix: const u8[:]) -> bool {
    guard s.len >= prefix.len else { return false; }
    return eq_ascii_fold(s[..prefix.len], prefix);
}

// Checks whether s ends with suffix using case-insensitive ASCII comparison.
fn ends_with_fold(s: const u8[:], suffix: const u8[:]) -> bool {
    guard s.len >= suffix.len else { return false; }
    return eq_ascii_fold(s[s.len - suffix.len..], suffix);
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
