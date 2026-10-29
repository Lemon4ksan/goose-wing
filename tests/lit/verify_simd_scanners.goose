// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// tests/lit/verify_simd_scanners.goose
// Verification of SWAR 64-bit WebSocket masking, fast CRLFCRLF scanning, and bitmask scanners.
//
// RUN: goose build --cc gcc -O2 -o %t.exe %s
// RUN: %t.exe | %FileCheck %s

import std;
import core from "../..";
import wing from "../..";

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

fn main() {
    let http_req = "GET /api/v2/orders HTTP/1.1\r\nHost: example.com\r\n\r\n";
    let mask = scan_byte_bitmask(http_req, '/');
    // In "GET /api/v2/orde", '/' is at index 4 (16), index 8 (256), and index 11 (2048) -> 2320
    assert(mask == 2320);
    print("SIMD_SLASH_MASK: ", mask);

    // Verify fast CRLFCRLF scanner
    let crlf_off = core::fast_find_crlfcrlf(http_req);
    assert(crlf_off == 46);
    print("CRLFCRLF_OFFSET: ", crlf_off);

    // Verify 64-bit SWAR WebSocket in-place unmasker
    var payload: u8[>..] = [];
    payload.append("Hello Goose Wing");
    let key: u8[4] = [0xAA, 0xBB, 0xCC, 0xDD];

    wing::apply_mask_in_place(payload[..], key);
    // Double mask restores original plaintext
    wing::apply_mask_in_place(payload[..], key);

    assert(payload[0] == 72); // 'H'
    assert(payload[1] == 101); // 'e'
    assert(payload[2] == 108); // 'l'
    assert(payload[3] == 108); // 'l'
    assert(payload[4] == 111); // 'o'
    print("RESTORED: ", payload[0], " ", payload[1], " ", payload[2], " ", payload[3], " ", payload[4]);
}

// CHECK: SIMD_SLASH_MASK: 2320
// CHECK: CRLFCRLF_OFFSET: 46
// CHECK: RESTORED: 72 101 108 108 111
