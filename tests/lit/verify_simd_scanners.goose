// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// RUN: goose %s | %FileCheck %s
import std;

// Scans first 16 bytes of buffer for delimiter byte and produces a 16-bit bitmask.
fn scan_byte_bitmask(buf: const u8[:], target: u8) -> i32 {
    let limit = if buf.len < 16 { buf.len } else { 16 };
    var mask: i32 = 0;
    for i in limit {
        if buf[i] == target {
            mask |= (1 << (i as u32));
        }
    }
    return mask;
}

// 128-bit WebSocket XOR unmasker
fn apply_mask(dst: u8[:], src: const u8[:], mask: const u8[4]) {
    for i in src.len {
        dst[i] = src[i] ^ mask[i % 4];
    }
}

fn main() {
    let http_req = "GET /api/v2/orders HTTP/1.1\r\nHost: example.com\r\n\r\n";
    let mask = scan_byte_bitmask(http_req, '/');
    // In "GET /api/v2/orde", '/' is at index 4 (16), index 8 (256), and index 11 (2048) -> 2320
    assert(mask == 2320);
    print("SIMD_SLASH_MASK: ", mask);

    let payload = "Hello Goose Wing";
    let key: u8[4] = [0xAA, 0xBB, 0xCC, 0xDD];
    var masked: u8[16] = [0; 16];
    var restored: u8[16] = [0; 16];

    apply_mask(masked[..], payload, key);
    apply_mask(restored[..], masked[..], key);

    assert(restored[0] == 72); // 'H'
    assert(restored[1] == 101); // 'e'
    assert(restored[2] == 108); // 'l'
    assert(restored[3] == 108); // 'l'
    assert(restored[4] == 111); // 'o'
    print("RESTORED: ", restored[0], " ", restored[1], " ", restored[2], " ", restored[3], " ", restored[4]);
}

// CHECK: SIMD_SLASH_MASK: 2320
// CHECK: RESTORED: 72 101 108 108 111
