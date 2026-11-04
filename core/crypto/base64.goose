// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Base64 and Base64URL encoding & decoding (RFC 4648).
// Zero-heap allocation when writing into preallocated or bounded buffers.
namespace core;

import std;

// ---- base64url codec (rfc 4648 section 5, unpadded) ------------------------

let BASE64URL_CHARS: const u8[64] = [
    'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M',
    'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z',
    'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm',
    'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z',
    '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '-', '_',
];

fn base64url_encode<B>(data: const u8[:], out: B&) {
    var i = 0;
    while i + 3 <= data.len {
        let s = data[i..i + 3];
        let n = ((s[0] as u32) << 16) | ((s[1] as u32) << 8) | (s[2] as u32);
        let chunk: u8[4] = [
            BASE64URL_CHARS[(n >> 18) & 63],
            BASE64URL_CHARS[(n >> 12) & 63],
            BASE64URL_CHARS[(n >> 6) & 63],
            BASE64URL_CHARS[n & 63],
        ];
        out.append(chunk[..]);
        i += 3;
    }
    let rem = data.len - i;
    if rem == 1 {
        let n = (data[i] as u32) << 16;
        let chunk: u8[2] = [
            BASE64URL_CHARS[(n >> 18) & 63],
            BASE64URL_CHARS[(n >> 12) & 63],
        ];
        out.append(chunk[..]);
    } else if rem == 2 {
        let s = data[i..i + 2];
        let n = ((s[0] as u32) << 16) | ((s[1] as u32) << 8);
        let chunk: u8[3] = [
            BASE64URL_CHARS[(n >> 18) & 63],
            BASE64URL_CHARS[(n >> 12) & 63],
            BASE64URL_CHARS[(n >> 6) & 63],
        ];
        out.append(chunk[..]);
    }
}

const BASE64_URL_DECODE_LUT: const i8[256] = [
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 62, -1, -1,
    52, 53, 54, 55, 56, 57, 58, 59, 60, 61, -1, -1, -1, -1, -1, -1,
    -1, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14,
    15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, -1, -1, -1, -1, 63,
    -1, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40,
    41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
];

checkfree inline fn base64url_val(ch: u8) -> i32 {
    return BASE64_URL_DECODE_LUT[ch];
}

fn base64url_decode<B>(encoded: const u8[:], out: B&) -> bool {
    guard encoded.len > 0 else { return true; }
    var buf:  u32 = 0;
    var bits: i32 = 0;
    var idx:  i64 = 0;

    while idx < encoded.len {
        let ch = encoded[idx];
        if ch == '=' {
            // RFC 4648 §3.5: padding only valid when 2 chars (bits=4) or 3 chars (bits=2) decoded
            guard bits == 4 || bits == 2 else { out.clear(); return false; }
            let pad_mask = (((1 as u32) << bits) - 1);
            guard (buf & pad_mask) == 0 else { out.clear(); return false; }
            let expected_pad = if bits == 4 { 2 } else { 1 };
            guard (encoded.len - idx) == expected_pad else { out.clear(); return false; }
            var p = idx;
            while p < encoded.len {
                guard encoded[p] == '=' else { out.clear(); return false; }
                p++;
            }
            bits = 0;
            break;
        }

        let v = base64url_val(ch);
        guard v >= 0 else { out.clear(); return false; }
        buf = (buf << 6) | (v as u32);
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            let prev_len = out.len;
            out.push(((buf >> bits) & 0xFF) as u8);
            guard out.len > prev_len else { out.clear(); return false; }
        }
        idx++;
    }

    // RFC 4648 §3.5: single lone 6-bit char (len % 4 == 1) is impossible
    guard bits != 6 else { out.clear(); return false; }
    if bits > 0 {
        let pad_mask = (((1 as u32) << bits) - 1);
        guard (buf & pad_mask) == 0 else { out.clear(); return false; }
    }
    return true;
}

// ---- standard base64 codec (rfc 4648 section 4, padded) ---------------------

let BASE64_STD_CHARS: const u8[64] = [
    'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M',
    'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z',
    'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm',
    'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z',
    '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '+', '/',
];

fn base64_encode<B>(data: const u8[:], out: B&) {
    var i = 0;
    while i + 3 <= data.len {
        let s = data[i..i + 3];
        let n = ((s[0] as u32) << 16) | ((s[1] as u32) << 8) | (s[2] as u32);
        let chunk: u8[4] = [
            BASE64_STD_CHARS[(n >> 18) & 63],
            BASE64_STD_CHARS[(n >> 12) & 63],
            BASE64_STD_CHARS[(n >> 6) & 63],
            BASE64_STD_CHARS[n & 63],
        ];
        out.append(chunk[..]);
        i += 3;
    }
    let rem = data.len - i;
    if rem == 1 {
        let n = (data[i] as u32) << 16;
        let chunk: u8[4] = [
            BASE64_STD_CHARS[(n >> 18) & 63],
            BASE64_STD_CHARS[(n >> 12) & 63],
            '=',
            '=',
        ];
        out.append(chunk[..]);
    } else if rem == 2 {
        let s = data[i..i + 2];
        let n = ((s[0] as u32) << 16) | ((s[1] as u32) << 8);
        let chunk: u8[4] = [
            BASE64_STD_CHARS[(n >> 18) & 63],
            BASE64_STD_CHARS[(n >> 12) & 63],
            BASE64_STD_CHARS[(n >> 6) & 63],
            '=',
        ];
        out.append(chunk[..]);
    }
}

const BASE64_STD_DECODE_LUT: const i8[256] = [
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 62, -1, -1, -1, 63,
    52, 53, 54, 55, 56, 57, 58, 59, 60, 61, -1, -1, -1, -1, -1, -1,
    -1, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14,
    15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, -1, -1, -1, -1, -1,
    -1, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40,
    41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
];

checkfree inline fn base64_val(ch: u8) -> i32 {
    return BASE64_STD_DECODE_LUT[ch];
}

fn base64_decode<B>(encoded: const u8[:], out: B&) -> bool {
    guard encoded.len > 0 else { return true; }
    var buf:  u32 = 0;
    var bits: i32 = 0;
    var idx:  i64 = 0;

    while idx < encoded.len {
        let ch = encoded[idx];
        if ch == '=' {
            // RFC 4648 §3.5: padding only valid when 2 chars (bits=4) or 3 chars (bits=2) decoded
            guard bits == 4 || bits == 2 else { out.clear(); return false; }
            let pad_mask = (((1 as u32) << bits) - 1);
            guard (buf & pad_mask) == 0 else { out.clear(); return false; }
            let expected_pad = if bits == 4 { 2 } else { 1 };
            guard (encoded.len - idx) == expected_pad else { out.clear(); return false; }
            var p = idx;
            while p < encoded.len {
                guard encoded[p] == '=' else { out.clear(); return false; }
                p++;
            }
            bits = 0;
            break;
        }

        let v = base64_val(ch);
        guard v >= 0 else { out.clear(); return false; }
        buf = (buf << 6) | (v as u32);
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            let prev_len = out.len;
            out.push(((buf >> bits) & 0xFF) as u8);
            guard out.len > prev_len else { out.clear(); return false; }
        }
        idx++;
    }

    // RFC 4648 §3.5: single lone 6-bit char (len % 4 == 1) is impossible
    guard bits != 6 else { out.clear(); return false; }
    if bits > 0 {
        let pad_mask = (((1 as u32) << bits) - 1);
        guard (buf & pad_mask) == 0 else { out.clear(); return false; }
    }
    return true;
}
