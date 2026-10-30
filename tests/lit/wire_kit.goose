// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// tests/lit/wire_kit.goose - Zero-allocation wire stream verification and fuzzing kit.
namespace wire_kit;

import std;

// Parses hex string into a byte buffer.
fn parse_hex(hex_str: const u8[:], out: u8[>..]&) -> bool {
    var i: i64 = 0;
    while i < hex_str.len {
        let c = hex_str[i];
        if c == ' ' || c == '\t' || c == '\r' || c == '\n' {
            i += 1;
            continue;
        }
        if i + 1 >= hex_str.len { break; }
        var h0: u8 = 0;
        var h1: u8 = 0;
        let c0 = hex_str[i];
        let c1 = hex_str[i + 1];
        if c0 >= '0' && c0 <= '9' { h0 = c0 - '0'; }
        else if c0 >= 'a' && c0 <= 'f' { h0 = c0 - 'a' + 10; }
        else if c0 >= 'A' && c0 <= 'F' { h0 = c0 - 'A' + 10; }
        else { return false; }

        if c1 >= '0' && c1 <= '9' { h1 = c1 - '0'; }
        else if c1 >= 'a' && c1 <= 'f' { h1 = c1 - 'a' + 10; }
        else if c1 >= 'A' && c1 <= 'F' { h1 = c1 - 'A' + 10; }
        else { return false; }

        out.push((h0 << 4) | h1);
        i += 2;
    }
    return true;
}

// Verifies that a streaming parser handles fragmented prefixes without panics or memory corruption.
// For all prefix lengths 1..(payload.len - 1), prefix_fn must return incomplete_code.
// For the full payload, prefix_fn must return ok_code.
fn verify_split_stream<F: fn(const u8[:]) -> i64>(
    payload:         const u8[:],
    incomplete_code: i64,
    ok_code:         i64,
) -> bool {
    guard payload.len > 0 else { return false; }
    var p: i64 = 1;
    while p < payload.len {
        let code = F(payload[..p]);
        if code != incomplete_code {
            return false;
        }
        p += 1;
    }
    return F(payload) == ok_code;
}

// Deterministic xorshift64 random generator for wire mutation fuzzing
fn xorshift64(state: u64&) -> u64 {
    var x = state;
    x ^= x << 13;
    x ^= x >> 7;
    x ^= x << 17;
    state = x;
    return x;
}

// Fuzzes a wire payload with random single-bit flips, boundary byte injections, and byte deletions.
// Ensures parser never aborts or crashes on corrupted inputs.
fn fuzz_payload<F: fn(const u8[:]) -> i64>(
    seed:       const u8[:],
    iterations: i64,
) -> bool {
    guard seed.len > 0 else { return true; }
    var rng:     u64     = 0x853c49e6748fea9b;
    var mut_buf: u8[>..] = [];

    for _ in iterations {
        mut_buf.clear();
        for b in seed {
            mut_buf.push(b);
        }
        let mode = xorshift64(rng) % 4;
        let pos = (xorshift64(rng) % (mut_buf.len as! u64)) as! i64;
        if mode == 0 {
            // Bit flip
            let bit = (1 << ((xorshift64(rng) % 8) as u32)) as u8;
            mut_buf[pos] ^= bit;
        } else if mode == 1 {
            // Extreme boundary byte
            let choice = xorshift64(rng) % 4;
            mut_buf[pos] = if choice == 0 { 0x00 } else if choice == 1 { 0xFF } else if choice == 2 { 0x7F } else { 0x80 };
        } else if mode == 2 && mut_buf.len >= 2 {
            // Swap adjacent
            let next_pos = (pos + 1) % mut_buf.len;
            let tmp = mut_buf[pos];
            mut_buf[pos] = mut_buf[next_pos];
            mut_buf[next_pos] = tmp;
        } else {
            // 0-byte overwrite
            mut_buf[pos] = 0;
        }

        // Must execute safely without panic
        let _ = F(mut_buf[..]);
    }
    return true;
}
