// core/crypto/base64.goose
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
    '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '-', '_'
];

fn base64url_encode<B>(data: const u8[:], out: B&) {
    var i = 0;
    while i + 3 <= data.len {
        let n = ((data[i] as u32) << 16) | ((data[i + 1] as u32) << 8) | (data[i + 2] as u32);
        out.push(BASE64URL_CHARS[(n >> 18) & 63]);
        out.push(BASE64URL_CHARS[(n >> 12) & 63]);
        out.push(BASE64URL_CHARS[(n >> 6) & 63]);
        out.push(BASE64URL_CHARS[n & 63]);
        i += 3;
    }
    let rem = data.len - i;
    if rem == 1 {
        let n = (data[i] as u32) << 16;
        out.push(BASE64URL_CHARS[(n >> 18) & 63]);
        out.push(BASE64URL_CHARS[(n >> 12) & 63]);
    } else if rem == 2 {
        let n = ((data[i] as u32) << 16) | ((data[i + 1] as u32) << 8);
        out.push(BASE64URL_CHARS[(n >> 18) & 63]);
        out.push(BASE64URL_CHARS[(n >> 12) & 63]);
        out.push(BASE64URL_CHARS[(n >> 6) & 63]);
    }
}

inline fn base64url_val(ch: u8) -> i32 {
    if ch >= 'A' && ch <= 'Z' { return ch - 'A'; }
    if ch >= 'a' && ch <= 'z' { return ch - 'a' + 26; }
    if ch >= '0' && ch <= '9' { return ch - '0' + 52; }
    if ch == '-' { return 62; }
    if ch == '_' { return 63; }
    return -1;
}

fn base64url_decode<B>(encoded: const u8[:], out: B&) -> bool {
    guard encoded.len > 0 else { return true; }
    var buf: u32 = 0;
    var bits = 0;

    for idx in encoded.len {
        let ch = encoded[idx];
        if ch == '=' { break; } // stop on padding if present
        let v = base64url_val(ch);
        guard v >= 0 else { return false; }
        buf = (buf << 6) | (v as u32);
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push(((buf >> bits) & 0xFF) as u8);
        }
    }
    return true;
}

// ---- standard base64 codec (rfc 4648 section 4, padded) ---------------------

let BASE64_STD_CHARS: const u8[64] = [
    'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M',
    'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z',
    'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm',
    'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z',
    '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '+', '/'
];

fn base64_encode<B>(data: const u8[:], out: B&) {
    var i = 0;
    while i + 3 <= data.len {
        let n = ((data[i] as u32) << 16) | ((data[i + 1] as u32) << 8) | (data[i + 2] as u32);
        out.push(BASE64_STD_CHARS[(n >> 18) & 63]);
        out.push(BASE64_STD_CHARS[(n >> 12) & 63]);
        out.push(BASE64_STD_CHARS[(n >> 6) & 63]);
        out.push(BASE64_STD_CHARS[n & 63]);
        i += 3;
    }
    let rem = data.len - i;
    if rem == 1 {
        let n = (data[i] as u32) << 16;
        out.push(BASE64_STD_CHARS[(n >> 18) & 63]);
        out.push(BASE64_STD_CHARS[(n >> 12) & 63]);
        out.push('=');
        out.push('=');
    } else if rem == 2 {
        let n = ((data[i] as u32) << 16) | ((data[i + 1] as u32) << 8);
        out.push(BASE64_STD_CHARS[(n >> 18) & 63]);
        out.push(BASE64_STD_CHARS[(n >> 12) & 63]);
        out.push(BASE64_STD_CHARS[(n >> 6) & 63]);
        out.push('=');
    }
}

inline fn base64_val(ch: u8) -> i32 {
    if ch >= 'A' && ch <= 'Z' { return ch - 'A'; }
    if ch >= 'a' && ch <= 'z' { return ch - 'a' + 26; }
    if ch >= '0' && ch <= '9' { return ch - '0' + 52; }
    if ch == '+' { return 62; }
    if ch == '/' { return 63; }
    return -1;
}

fn base64_decode<B>(encoded: const u8[:], out: B&) -> bool {
    guard encoded.len > 0 else { return true; }
    var buf: u32 = 0;
    var bits = 0;

    for idx in encoded.len {
        let ch = encoded[idx];
        if ch == '=' { break; }
        let v = base64_val(ch);
        guard v >= 0 else { return false; }
        buf = (buf << 6) | (v as u32);
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push(((buf >> bits) & 0xFF) as u8);
        }
    }
    return true;
}
