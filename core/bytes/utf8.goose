// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Goose Core Byte String - Fast UTF-8 Validation (RFC 3629 & Unicode Standard).
// Implements zero-allocation, bounds-checked validation verifying:
// - 64-bit unrolled ASCII fast-path (8 bytes per cycle checking high-bit mask 0x80)
// - Valid 2-byte, 3-byte, and 4-byte lead and continuation sequences
// - Rejection of overlong encodings (e.g. 0xC0..0xC1, 0xE0 with b1 < 0xA0, 0xF0 with b1 < 0x90)
// - Rejection of UTF-16 surrogates (U+D800..U+DFFF, 0xED with b1 >= 0xA0)
// - Rejection of codepoints above U+10FFFF (0xF4 with b1 > 0x8F, or byte >= 0xF5)
namespace core;

import std;

// Returns true if the slice contains only 7-bit ASCII characters (0x00..0x7F).
fn is_pure_ascii(data: const u8[:]) -> bool {
    let n = data.len;
    guard n > 0 else { return true; }

    var i: i64 = 0;
    while i + 8 <= n {
        let w = core::read_be_u64(data, i);
        if (w & 0x8080808080808080) != 0 {
            return false;
        }
        i += 8;
    }

    while i < n {
        if data[i] >= 0x80 {
            return false;
        }
        i++;
    }

    return true;
}

// Scans for CRLF (\r\n) delimiter in wire byte streams.
// Returns offset of '\r' if found, or -1 if not found.
fn find_crlf(data: const u8[:]) -> i64 {
    let n = data.len;
    guard n >= 2 else { return -1; }

    var i: i64 = 0;
    while i + 1 < n {
        if data[i] == '\r' && data[i + 1] == '\n' {
            return i;
        }
        i++;
    }

    return -1;
}

// Returns true if the slice contains valid RFC 3629 UTF-8.
// Employs a 16-byte SWAR ASCII fast-skip loop (Alex Hultman / uWebSockets pattern)
// allowing ultra-fast validation across mixed ASCII / multibyte text payloads.
fn validate_utf8(data: const u8[:]) -> bool {
    let n = data.len;
    guard n > 0 else { return true; }

    var i: i64 = 0;
    while i < n {
        // 16-byte SWAR fast-path: if both 64-bit words have no high bits set, 16 ASCII bytes are valid
        if i + 16 <= n {
            let w1 = core::read_be_u64(data, i);
            let w2 = core::read_be_u64(data, i + 8);
            if ((w1 & 0x8080808080808080) | (w2 & 0x8080808080808080)) == 0 {
                i += 16;
                continue;
            }
        } else if i + 8 <= n {
            let w = core::read_be_u64(data, i);
            if (w & 0x8080808080808080) == 0 {
                i += 8;
                continue;
            }
        }

        let b0 = data[i];
        if b0 <= 0x7F {
            i++;
        } else if (b0 & 0xE0) == 0xC0 {
            guard i + 1 < n else { return false; }
            let b1 = data[i + 1];
            guard (b1 & 0xC0) == 0x80 else { return false; }
            guard b0 >= 0xC2 else { return false; } // Overlong
            i += 2;
        } else if (b0 & 0xF0) == 0xE0 {
            guard i + 2 < n else { return false; }
            let b1 = data[i + 1];
            let b2 = data[i + 2];
            guard (b1 & 0xC0) == 0x80 && (b2 & 0xC0) == 0x80 else { return false; }
            if b0 == 0xE0 && b1 < 0xA0 { return false; } // Overlong
            if b0 == 0xED && b1 >= 0xA0 { return false; } // UTF-16 surrogates U+D800..U+DFFF
            i += 3;
        } else if (b0 & 0xF8) == 0xF0 {
            guard i + 3 < n else { return false; }
            let b1 = data[i + 1];
            let b2 = data[i + 2];
            let b3 = data[i + 3];
            guard (b1 & 0xC0) == 0x80 && (b2 & 0xC0) == 0x80 && (b3 & 0xC0) == 0x80 else { return false; }
            if b0 == 0xF0 && b1 < 0x90 { return false; } // Overlong
            if b0 == 0xF4 && b1 > 0x8F { return false; } // Above U+10FFFF
            guard b0 <= 0xF4 else { return false; }
            i += 4;
        } else {
            return false;
        }
    }
    return true;
}
