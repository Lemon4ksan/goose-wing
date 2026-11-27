// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Zero-heap, zero-copy sub-slicing whitespace and byte trimming operations.
namespace core;

import std;

// Checks whether byte is Linear White Space (SP 0x20 or HTAB 0x09) per RFC 9110 Section 5.6.3.
fn is_lws(b: u8) -> bool {
    return b == ' ' || b == '\t';
}

// Checks whether byte is standard ASCII whitespace (SP, TAB, LF, CR, VT, FF).
fn is_ascii_space(b: u8) -> bool {
    return b == ' ' || b == '\t' || b == '\n' || b == '\r' || b == 0x0B || b == 0x0C;
}

// Trims RFC 9110 Linear White Space (spaces and tabs) from start of val.
fn trim_lws_start(val: const u8[:]) -> const u8[:] {
    var start: i64 = 0;
    while start < val.len && is_lws(val[start]) {
        start++;
    }
    return val[start..];
}

// Trims RFC 9110 Linear White Space (spaces and tabs) from end of val.
fn trim_lws_end(val: const u8[:]) -> const u8[:] {
    var end_pos: i64 = val.len;
    while end_pos > 0 && is_lws(val[end_pos - 1]) {
        end_pos--;
    }
    return val[..end_pos];
}

// Trims RFC 9110 Linear White Space (spaces and tabs) from both ends of val.
fn trim_lws(val: const u8[:]) -> const u8[:] {
    var start: i64 = 0;
    while start < val.len && is_lws(val[start]) {
        start++;
    }
    var end_pos: i64 = val.len;
    while end_pos > start && is_lws(val[end_pos - 1]) {
        end_pos--;
    }
    return val[start..end_pos];
}

// Trims ASCII whitespace from both ends of val.
fn trim_ascii_space(val: const u8[:]) -> const u8[:] {
    var start: i64 = 0;
    while start < val.len && is_ascii_space(val[start]) {
        start++;
    }
    var end_pos: i64 = val.len;
    while end_pos > start && is_ascii_space(val[end_pos - 1]) {
        end_pos--;
    }
    return val[start..end_pos];
}

// Trims matching byte b from start of val.
fn trim_start_byte(val: const u8[:], b: u8) -> const u8[:] {
    var start: i64 = 0;
    while start < val.len && val[start] == b {
        start++;
    }
    return val[start..];
}

// Trims matching byte b from end of val.
fn trim_end_byte(val: const u8[:], b: u8) -> const u8[:] {
    var end_pos: i64 = val.len;
    while end_pos > 0 && val[end_pos - 1] == b {
        end_pos--;
    }
    return val[..end_pos];
}

// Trims matching byte b from both ends of val.
fn trim_byte(val: const u8[:], b: u8) -> const u8[:] {
    var start: i64 = 0;
    while start < val.len && val[start] == b {
        start++;
    }
    var end_pos: i64 = val.len;
    while end_pos > start && val[end_pos - 1] == b {
        end_pos--;
    }
    return val[start..end_pos];
}

// Trims any byte contained in cutset from start of val.
fn trim_start_bytes(val: const u8[:], cutset: const u8[:]) -> const u8[:] {
    let at = find_not_byteset(val, cutset);
    if at < 0 { return ""; }
    return val[at..];
}

// Trims any byte contained in cutset from end of val.
fn trim_end_bytes(val: const u8[:], cutset: const u8[:]) -> const u8[:] {
    let at = rfind_not_byteset(val, cutset);
    if at < 0 { return ""; }
    return val[..at + 1];
}

// Trims any byte contained in cutset from both ends of val.
fn trim_bytes(val: const u8[:], cutset: const u8[:]) -> const u8[:] {
    let start = find_not_byteset(val, cutset);
    if start < 0 { return ""; }
    let end_pos = rfind_not_byteset(val, cutset);
    return val[start..end_pos + 1];
}
