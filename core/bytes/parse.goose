// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Strict bounds-checked decimal and hexadecimal integer parsing.
namespace core;

import std;

// Converts an ASCII hexadecimal character ('0'..'9', 'a'..'f', 'A'..'F') to its numeric value (0..15).
// Returns 0..15 if valid hex digit, or -1 if invalid.
fn hex_digit_to_val(b: u8) -> i32 {
    if b >= '0' && b <= '9' { return b - '0'; }
    if b >= 'a' && b <= 'f' { return b - 'a' + 10; }
    if b >= 'A' && b <= 'F' { return b - 'A' + 10; }
    return -1;
}

// Parses an unsigned 64-bit integer in base 10 from ASCII byte slice s.
// Rejects empty input, non-digit characters, and values exceeding u64::MAX (18446744073709551615).
fn parse_u64_dec(s: const u8[:]) -> u64, bool {
    guard s.len > 0 else { return 0, false; }
    for b in s {
        guard b >= '0' && b <= '9' else { return 0, false; }
    }
    var sig = s;
    while sig.len > 0 && sig[0] == '0' {
        sig = sig[1..];
    }
    guard sig.len > 0 else { return 0, true; }
    guard sig.len <= 20 else { return 0, false; }

    var num: u64 = 0;
    var digits: i64 = 0;
    for b in sig {
        digits++;
        let d = (b - '0') as! u64;
        if digits == 20 {
            // u64::MAX is 18446744073709551615
            // 18446744073709551615 / 10 = 1844674407370955161, remainder 5
            if num > 1844674407370955161 || (num == 1844674407370955161 && d > 5) {
                return 0, false;
            }
        }
        num = num * 10 + d;
    }
    return num, true;
}

// Parses a signed 64-bit integer in base 10 from ASCII byte slice s.
// Supports optional leading '+' or '-' sign.
// Rejects empty input, non-digits, and values outside [-9223372036854775808, 9223372036854775807].
fn parse_i64_dec(s: const u8[:]) -> i64, bool {
    guard s.len > 0 else { return 0, false; }
    var is_neg = false;
    var digits_slice = s;
    if s[0] == '-' {
        is_neg = true;
        digits_slice = s[1..];
    } else if s[0] == '+' {
        digits_slice = s[1..];
    }
    guard digits_slice.len > 0 else { return 0, false; }

    for b in digits_slice {
        guard b >= '0' && b <= '9' else { return 0, false; }
    }

    var sig = digits_slice;
    while sig.len > 0 && sig[0] == '0' {
        sig = sig[1..];
    }
    guard sig.len > 0 else { return 0, true; }
    guard sig.len <= 19 else { return 0, false; }

    var num: u64 = 0;
    var digits: i64 = 0;
    for b in sig {
        digits++;
        let d = (b - '0') as! u64;
        if digits == 19 {
            // i64::MAX is 9223372036854775807
            // |i64::MIN| is 9223372036854775808
            let max_limit_last: u64 = if is_neg { 8 } else { 7 };
            if num > 922337203685477580 || (num == 922337203685477580 && d > max_limit_last) {
                return 0, false;
            }
        }
        num = num * 10 + d;
    }

    if is_neg {
        if num == 9223372036854775808 {
            return -9223372036854775807 - 1, true;
        }
        return -(num as! i64), true;
    }
    return num as! i64, true;
}

// Parses an unsigned 32-bit integer in base 10.
fn parse_u32_dec(s: const u8[:]) -> u32, bool {
    let val, ok = parse_u64_dec(s);
    guard ok && val <= 4294967295 else { return 0, false; }
    return val as! u32, true;
}

// Parses a signed 32-bit integer in base 10.
fn parse_i32_dec(s: const u8[:]) -> i32, bool {
    let val, ok = parse_i64_dec(s);
    guard ok && val >= -2147483648 && val <= 2147483647 else { return 0, false; }
    return val as! i32, true;
}

// Parses an unsigned 64-bit integer from hexadecimal ASCII byte slice s.
// Supports optional leading "0x" or "0X" prefix.
// Rejects empty input, invalid characters, and numbers exceeding 16 hex digits (u64::MAX).
fn parse_u64_hex(s: const u8[:]) -> u64, bool {
    var raw = s;
    if raw.len >= 2 && raw[0] == '0' && (raw[1] == 'x' || raw[1] == 'X') {
        raw = raw[2..];
    }
    guard raw.len > 0 else { return 0, false; }
    guard raw.len <= 16 else { return 0, false; }

    var val: u64 = 0;
    for b in raw {
        let d = hex_digit_to_val(b);
        guard d >= 0 else { return 0, false; }
        val = (val << 4) | (d as! u64);
    }
    return val, true;
}

// Parses an unsigned 32-bit integer from hexadecimal ASCII byte slice s.
fn parse_u32_hex(s: const u8[:]) -> u32, bool {
    let val, ok = parse_u64_hex(s);
    guard ok && val <= 0xFFFFFFFF else { return 0, false; }
    return val as! u32, true;
}

// Parses an unsigned 8-bit integer from hexadecimal ASCII byte slice s (1 or 2 hex digits).
fn parse_u8_hex(s: const u8[:]) -> u8, bool {
    let val, ok = parse_u64_hex(s);
    guard ok && val <= 0xFF else { return 0, false; }
    return val as! u8, true;
}
