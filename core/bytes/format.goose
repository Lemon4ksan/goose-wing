// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Zero-allocation decimal and hexadecimal integer formatting into appendable buffers.
namespace core;

import std;

const DIGITS_LUT: const u8[200] = [
    '0', '0', '0', '1', '0', '2', '0', '3', '0', '4', '0', '5', '0', '6', '0', '7', '0', '8', '0', '9',
    '1', '0', '1', '1', '1', '2', '1', '3', '1', '4', '1', '5', '1', '6', '1', '7', '1', '8', '1', '9',
    '2', '0', '2', '1', '2', '2', '2', '3', '2', '4', '2', '5', '2', '6', '2', '7', '2', '8', '2', '9',
    '3', '0', '3', '1', '3', '2', '3', '3', '3', '4', '3', '5', '3', '6', '3', '7', '3', '8', '3', '9',
    '4', '0', '4', '1', '4', '2', '4', '3', '4', '4', '4', '5', '4', '6', '4', '7', '4', '8', '4', '9',
    '5', '0', '5', '1', '5', '2', '5', '3', '5', '4', '5', '5', '5', '6', '5', '7', '5', '8', '5', '9',
    '6', '0', '6', '1', '6', '2', '6', '3', '6', '4', '6', '5', '6', '6', '6', '7', '6', '8', '6', '9',
    '7', '0', '7', '1', '7', '2', '7', '3', '7', '4', '7', '5', '7', '6', '7', '7', '7', '8', '7', '9',
    '8', '0', '8', '1', '8', '2', '8', '3', '8', '4', '8', '5', '8', '6', '8', '7', '8', '8', '8', '9',
    '9', '0', '9', '1', '9', '2', '9', '3', '9', '4', '9', '5', '9', '6', '9', '7', '9', '8', '9', '9',
];

// Formats an unsigned 64-bit integer in decimal notation into appendable buffer out.
// Accelerates integer formatting via 2-digit lookup table without dynamic allocations.
fn format_u64_dec<B>(val: u64, out: B&) {
    guard val > 0 else {
        out.push('0');
        return;
    }
    var digits: u8[24] = [0; 24];
    var count = 0;
    var v = val;
    while v >= 100 {
        let q = v / 100;
        let r = (v - q * 100) as i64;
        v = q;
        digits[count] = DIGITS_LUT[r * 2 + 1];
        digits[count + 1] = DIGITS_LUT[r * 2];
        count += 2;
    }
    if v < 10 {
        digits[count] = ('0' + (v as u8));
        count += 1;
    } else {
        let r = v as i64;
        digits[count] = DIGITS_LUT[r * 2 + 1];
        digits[count + 1] = DIGITS_LUT[r * 2];
        count += 2;
    }
    var left = 0;
    var right = count - 1;
    while left < right {
        let tmp = digits[left];
        digits[left] = digits[right];
        digits[right] = tmp;
        left++;
        right--;
    }
    out.append(digits[..count]);
}

// Formats a signed 64-bit integer in decimal notation into appendable buffer out.
fn format_i64_dec<B>(val: i64, out: B&) {
    if val < 0 {
        out.push('-');
        if val == -9223372036854775807 - 1 {
            out.append("9223372036854775808");
            return;
        }
        format_u64_dec((-val) as! u64, out);
        return;
    }
    format_u64_dec(val as! u64, out);
}

// Formats an unsigned 32-bit integer in decimal notation into appendable buffer out.
fn format_u32_dec<B>(val: u32, out: B&) {
    format_u64_dec(val as! u64, out);
}

// Formats an unsigned 64-bit integer in hexadecimal notation into appendable buffer out.
// If uppercase is true, uses '0'..'9','A'..'F'; otherwise '0'..'9','a'..'f'.
fn format_u64_hex<B>(val: u64, out: B&, uppercase: bool = false) {
    guard val > 0 else {
        out.push('0');
        return;
    }
    let hex_chars: const u8[16] = if uppercase {
        ['0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F']
    } else {
        ['0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f']
    };
    var digits: u8[16] = [0; 16];
    var count = 0;
    var v = val;
    while v > 0 {
        digits[count] = hex_chars[(v & 0x0F) as! i64];
        v = v >> 4;
        count++;
    }
    for i in count {
        out.push(digits[count - 1 - i]);
    }
}

// Formats an unsigned 32-bit integer in hexadecimal notation into appendable buffer out.
fn format_u32_hex<B>(val: u32, out: B&, uppercase: bool = false) {
    format_u64_hex(val as! u64, out, uppercase);
}

// Formats an unsigned byte as exactly two hexadecimal characters into appendable buffer out.
fn format_u8_hex<B>(val: u8, out: B&, uppercase: bool = false) {
    let hex_chars: const u8[16] = if uppercase {
        ['0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F']
    } else {
        ['0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f']
    };
    out.push(hex_chars[((val >> 4) & 0x0F) as! i64]);
    out.push(hex_chars[(val & 0x0F) as! i64]);
}

// Formats an unsigned 64-bit integer with leading zero padding to fixed width.
fn format_u64_hex_fixed<B>(val: u64, width: i64, out: B&, uppercase: bool = false) {
    guard width > 0 else { return; }
    let hex_chars: const u8[16] = if uppercase {
        ['0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F']
    } else {
        ['0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f']
    };
    var digits: u8[16] = [0; 16];
    var count = 0;
    var v = val;
    while v > 0 && count < 16 {
        digits[count] = hex_chars[(v & 0x0F) as! i64];
        v = v >> 4;
        count++;
    }
    let pad_count = max(0, width - count);
    for _ in pad_count {
        out.push('0');
    }
    let take = min(count, width);
    for i in take {
        out.push(digits[take - 1 - i]);
    }
}

// Fast integer-to-ASCII serialization into a pre-allocated slice without heap allocations.
// Returns number of bytes written, or 0 if `dst` is too small.
fn fast_u64toa(val: u64, dst: u8[:]) -> i64 {
    guard dst.len >= 1 else { return 0; }
    if val == 0 {
        dst[0] = '0';
        return 1;
    }
    var digits: u8[24] = [0; 24];
    var count:  i64    = 0;
    var v = val;
    while v >= 100 {
        let q = v / 100;
        let r = (v - q * 100) as i64;
        v = q;
        digits[count] = DIGITS_LUT[r * 2 + 1];
        digits[count + 1] = DIGITS_LUT[r * 2];
        count += 2;
    }
    if v < 10 {
        digits[count] = '0' + (v as u8);
        count += 1;
    } else {
        let r = v as i64;
        digits[count] = DIGITS_LUT[r * 2 + 1];
        digits[count + 1] = DIGITS_LUT[r * 2];
        count += 2;
    }
    guard count <= dst.len else { return 0; }
    for i in count {
        dst[i] = digits[count - 1 - i];
    }
    return count;
}
