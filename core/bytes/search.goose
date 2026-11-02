// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Byte scanning, index lookups, and predicate search primitives.
namespace core;

import std;

// Checks whether s begins with prefix.
fn starts_with(s: const u8[:], prefix: const u8[:]) -> bool {
    guard s.len >= prefix.len else { return false; }
    return s[..prefix.len] == prefix;
}

// Checks whether s ends with suffix.
fn ends_with(s: const u8[:], suffix: const u8[:]) -> bool {
    guard s.len >= suffix.len else { return false; }
    return s[s.len - suffix.len..] == suffix;
}

// Checks whether haystack contains needle as a contiguous subslice.
fn contains(haystack: const u8[:], needle: const u8[:]) -> bool {
    return find(haystack, needle) >= 0;
}

extern fn native_memchr(s: const u8[:], b: u8) -> i64 = "wing_memchr";
extern fn native_simd_last_index_of_byte(s: const u8[:], b: u8) -> i64 = "wing_simd_last_index_of_byte";
extern fn native_simd_count_byte(s: const u8[:], b: u8) -> i64 = "wing_simd_count_byte";

// Checks whether s contains byte b using vectorized memchr.
fn contains_byte(s: const u8[:], b: u8) -> bool {
    guard s.len > 0 else { return false; }
    return native_memchr(s, b) >= 0;
}

// Returns the 0-based index of the first occurrence of byte b in s, or -1 if not found.
fn index_of_byte(s: const u8[:], b: u8) -> i64 {
    guard s.len > 0 else { return -1; }
    return native_memchr(s, b);
}

// Returns the 0-based index of the last occurrence of byte b in s, or -1 if not found.
fn last_index_of_byte(s: const u8[:], b: u8) -> i64 {
    guard s.len > 0 else { return -1; }
    return native_simd_last_index_of_byte(s, b);
}

// Counts the number of non-overlapping occurrences of byte b in s using SSE2 vector popcount.
fn count_byte(s: const u8[:], b: u8) -> i64 {
    guard s.len > 0 else { return 0; }
    return native_simd_count_byte(s, b);
}

extern fn native_swar_find_ctl(s: const u8[:]) -> i64 = "wing_swar_find_ctl";
extern fn native_fast_find_crlfcrlf(s: const u8[:]) -> i64 = "wing_fast_find_crlfcrlf";

// Scans slice 8 bytes at a time in 1 CPU cycle using SWAR hasLess(word, 32) (uWebSockets HttpParser.h).
// Returns the index of the first control character (< 32, e.g. \r, \n, \t, \0), or s.len if none found.
fn swar_find_ctl(s: const u8[:]) -> i64 {
    return native_swar_find_ctl(s);
}

// High-speed CRLFCRLF (\r\n\r\n) HTTP header delimiter scanner.
// Returns the index of the first '\r' in \r\n\r\n, or -1 if not found.
fn fast_find_crlfcrlf(s: const u8[:]) -> i64 {
    return native_fast_find_crlfcrlf(s);
}

// Places sentinel fence bytes '\r' and 'a' at offset length and length+1 in wire buffer (uWebSockets HttpParser.h).
// Allows SWAR and vectorized parsers to scan safely without bounds checks in the inner loop.
fn fence_wire_slice(buf: u8[:], length: i64) -> bool {
    guard length >= 0 else { return false; }
    guard length + 2 <= buf.len else { return false; }
    buf[length] = '\r';
    buf[length + 1] = 'a';
    return true;
}

extern fn native_prefetch_t0(s: const u8[:]) = "wing_prefetch_t0";
extern fn native_prefetch_nta(s: const u8[:]) = "wing_prefetch_nta";

// Prefetches slice memory into L1 Data Cache.
inline fn prefetch_t0(s: const u8[:]) {
    native_prefetch_t0(s);
}

// Prefetches slice memory using non-temporal streaming hint (minimizes cache pollution).
inline fn prefetch_nta(s: const u8[:]) {
    native_prefetch_nta(s);
}
