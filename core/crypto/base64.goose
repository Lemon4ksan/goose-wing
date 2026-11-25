// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Base64 and Base64URL encoding & decoding (RFC 4648).
// Zero-heap allocation when writing into preallocated or bounded buffers.
namespace core;

import std;
import core.math;

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

// Constant-time Base64URL character decoder (RFC 4648 Section 5, zero LUT cache side-channel).
checkfree inline fn base64url_val(ch: u8) -> i32 {
    let c: u32 = ch;
    let m_up = 0 - (~((c - 65) | (90 - c)) >> 31);
    let m_lo = 0 - (~((c - 97) | (122 - c)) >> 31);
    let m_num = 0 - (~((c - 48) | (57 - c)) >> 31);
    let m_62 = 0 - (~((c - 45) | (45 - c)) >> 31);
    let m_63 = 0 - (~((c - 95) | (95 - c)) >> 31);
    let valid = m_up | m_lo | m_num | m_62 | m_63;
    let res = (m_up & (c - 65)) |
              (m_lo & (c - 71)) |
              (m_num & (c + 4)) |
              (m_62 & 62) |
              (m_63 & 63);
    return if valid != 0 { res as i32 } else { -1 };
}

inline fn try_push_b64_byte<A>(arr: A&, b: u8) -> bool {
    guard arr.len < arr.cap else { return false; }
    arr.push(b);
    return true;
}

inline fn try_push_b64_byte(arr: u8[>..]&, b: u8) -> bool {
    arr.push(b);
    return true;
}

inline fn b64_fail<B>(out: B&) -> bool {
    if out.len > 0 {
        secure_zeroize_slice(out[..]);
    }
    out.clear();
    return false;
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
            guard bits == 4 || bits == 2 else { return b64_fail(out); }
            let pad_mask = (((1 as u32) << bits) - 1);
            guard (buf & pad_mask) == 0 else { return b64_fail(out); }
            let expected_pad = if bits == 4 { 2 } else { 1 };
            guard (encoded.len - idx) == expected_pad else { return b64_fail(out); }
            var p = idx;
            while p < encoded.len {
                guard encoded[p] == '=' else { return b64_fail(out); }
                p++;
            }
            bits = 0;
            break;
        }

        let v = base64url_val(ch);
        guard v >= 0 else { return b64_fail(out); }
        buf = (buf << 6) | (v as u32);
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            let dec_b = ((buf >> bits) & 0xFF) as u8;
            guard try_push_b64_byte(out, dec_b) else { return b64_fail(out); }
        }
        idx++;
    }

    // RFC 4648 §3.5: single lone 6-bit char (len % 4 == 1) is impossible
    guard bits != 6 else { return b64_fail(out); }
    if bits > 0 {
        let pad_mask = (((1 as u32) << bits) - 1);
        guard (buf & pad_mask) == 0 else { return b64_fail(out); }
    }
    return true;
}

inline fn is_valid_padded_base64url(src: const u8[:]) -> bool {
    if src.len == 0 { return true; }
    guard (src.len & 3) == 0 else { return false; }
    let body_end = core::sub_sat_i64(src.len, 2);
    var idx: i64 = 0;
    while idx < body_end {
        guard base64url_val(src[idx]) >= 0 else { return false; }
        idx = core::add_sat_i64(idx, 1);
    }
    let c1_val = base64url_val(src[core::sub_sat_i64(body_end, 1)]);
    let c2 = src[body_end];
    let c3 = src[core::add_sat_i64(body_end, 1)];
    if c2 == '=' {
        return c3 == '=' && c1_val >= 0 && (c1_val & 0x0F) == 0;
    }
    let c2_val = base64url_val(c2);
    guard c2_val >= 0 else { return false; }
    if c3 == '=' {
        return (c2_val & 0x03) == 0;
    }
    return base64url_val(c3) >= 0;
}

// Validates Base64URL text (RFC 4648 Section 5, padded or unpadded) and canonical zero pad bits
// (RFC 4648 Section 3.5) in a single pass with zero destination buffer allocation.
fn is_valid_base64url(src: const u8[:]) -> bool {
    if src.len == 0 { return true; }
    let last_idx = core::sub_sat_i64(src.len, 1);
    if src[last_idx] == '=' {
        return is_valid_padded_base64url(src);
    }
    let rem = src.len & 3;
    guard rem != 1 else { return false; }
    for b in src {
        guard base64url_val(b) >= 0 else { return false; }
    }
    let last_val = base64url_val(src[last_idx]);
    if rem == 2 { return (last_val & 0x0F) == 0; }
    if rem == 3 { return (last_val & 0x03) == 0; }
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

// Constant-time Standard Base64 character decoder (RFC 4648 Section 4, zero LUT cache side-channel).
checkfree inline fn base64_val(ch: u8) -> i32 {
    let c: u32 = ch;
    let m_up = 0 - (~((c - 65) | (90 - c)) >> 31);
    let m_lo = 0 - (~((c - 97) | (122 - c)) >> 31);
    let m_num = 0 - (~((c - 48) | (57 - c)) >> 31);
    let m_62 = 0 - (~((c - 43) | (43 - c)) >> 31);
    let m_63 = 0 - (~((c - 47) | (47 - c)) >> 31);
    let valid = m_up | m_lo | m_num | m_62 | m_63;
    let res = (m_up & (c - 65)) |
              (m_lo & (c - 71)) |
              (m_num & (c + 4)) |
              (m_62 & 62) |
              (m_63 & 63);
    return if valid != 0 { res as i32 } else { -1 };
}

fn base64_decode<B>(encoded: const u8[:], out: B&) -> bool {
    guard encoded.len > 0 else { return true; }
    guard (encoded.len & 3) == 0 else {
        return b64_fail(out);
    }
    var buf:  u32 = 0;
    var bits: i32 = 0;
    var idx:  i64 = 0;

    while idx < encoded.len {
        let ch = encoded[idx];
        if ch == '=' {
            // RFC 4648 §3.5: padding only valid when 2 chars (bits=4) or 3 chars (bits=2) decoded
            guard bits == 4 || bits == 2 else { return b64_fail(out); }
            let pad_mask = (((1 as u32) << bits) - 1);
            guard (buf & pad_mask) == 0 else { return b64_fail(out); }
            let expected_pad = if bits == 4 { 2 } else { 1 };
            guard (encoded.len - idx) == expected_pad else { return b64_fail(out); }
            var p = idx;
            while p < encoded.len {
                guard encoded[p] == '=' else { return b64_fail(out); }
                p++;
            }
            bits = 0;
            break;
        }

        let v = base64_val(ch);
        guard v >= 0 else { return b64_fail(out); }
        buf = (buf << 6) | (v as u32);
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            let dec_b = ((buf >> bits) & 0xFF) as u8;
            guard try_push_b64_byte(out, dec_b) else { return b64_fail(out); }
        }
        idx++;
    }

    return true;
}

// Validates standard padded Base64 text (RFC 4648 Section 4) and canonical zero pad bits
// (RFC 4648 Section 3.5) in a single pass with zero destination buffer allocation.
fn is_valid_base64(src: const u8[:]) -> bool {
    if src.len == 0 { return true; }
    guard (src.len & 3) == 0 else { return false; }
    let body_end = core::sub_sat_i64(src.len, 2);
    var idx: i64 = 0;
    while idx < body_end {
        guard base64_val(src[idx]) >= 0 else { return false; }
        idx = core::add_sat_i64(idx, 1);
    }

    let c1_val = base64_val(src[core::sub_sat_i64(body_end, 1)]);
    let c2 = src[body_end];
    let c3 = src[core::add_sat_i64(body_end, 1)];
    if c2 == '=' {
        return c3 == '=' && (c1_val & 0x0F) == 0;
    }
    let c2_val = base64_val(c2);
    guard c2_val >= 0 else { return false; }
    if c3 == '=' {
        return (c2_val & 0x03) == 0;
    }
    return base64_val(c3) >= 0;
}
