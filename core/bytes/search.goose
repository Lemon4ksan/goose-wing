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

// Checks whether s contains byte b.
fn contains_byte(s: const u8[:], b: u8) -> bool {
    for c in s {
        if c == b { return true; }
    }
    return false;
}

// Returns the 0-based index of the first occurrence of byte b in s, or -1 if not found.
fn index_of_byte(s: const u8[:], b: u8) -> i64 {
    for i in s.len {
        if s[i] == b { return i; }
    }
    return -1;
}

// Returns the 0-based index of the last occurrence of byte b in s, or -1 if not found.
fn last_index_of_byte(s: const u8[:], b: u8) -> i64 {
    var idx: i64 = s.len - 1;
    while idx >= 0 {
        if s[idx] == b { return idx; }
        idx--;
    }
    return -1;
}

// Returns the 0-based index of the first occurrence of needle in haystack, or -1 if not found.
fn index_of_slice(haystack: const u8[:], needle: const u8[:]) -> i64 {
    return find(haystack, needle);
}

// Counts the number of non-overlapping occurrences of byte b in s.
fn count_byte(s: const u8[:], b: u8) -> i64 {
    var count: i64 = 0;
    for c in s {
        if c == b { count++; }
    }
    return count;
}

extern fn native_swar_find_ctl(s: const u8[:]) -> i64 = "wing_swar_find_ctl";

// Scans slice 8 bytes at a time in 1 CPU cycle using SWAR hasLess(word, 32) (uWebSockets HttpParser.h).
// Returns the index of the first control character (< 32, e.g. \r, \n, \t, \0), or s.len if none found.
fn swar_find_ctl(s: const u8[:]) -> i64 {
    return native_swar_find_ctl(s);
}

// High-speed CRLFCRLF (\r\n\r\n) HTTP header delimiter scanner.
// Returns the index of the first '\r' in \r\n\r\n, or -1 if not found.
fn fast_find_crlfcrlf(s: const u8[:]) -> i64 {
    guard s.len >= 4 else { return -1; }
    let limit = s.len - 4;
    var i: i64 = 0;
    while i <= limit {
        if s[i] == '\r' && s[i + 1] == '\n' && s[i + 2] == '\r' && s[i + 3] == '\n' {
            return i;
        }
        if s[i + 1] != '\r' {
            i += 2;
        } else {
            i++;
        }
    }
    return -1;
}

// Places sentinel fence bytes '\r' and 'a' at offset length and length+1 in wire buffer (uWebSockets HttpParser.h).
// Allows SWAR and vectorized parsers to scan safely without bounds checks in the inner loop.
fn fence_wire_slice(buf: u8[:], length: i64) -> bool {
    guard length >= 0 && length + 2 <= buf.len else { return false; }
    buf[length] = '\r';
    buf[length + 1] = 'a';
    return true;
}
