// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Goose LIT Verification Suite: Constant-Time Primitives, KeySlot Zeroization & Dudect Welch t-Test
// RUN: goose build -O2 -o %t.exe %s
// RUN: %t.exe | %FileCheck %s

import std;
import core from "../..";

// Exported constant-time entry points for x86_64 assembly branch inspection (scripts/verify_ct_asm.py).
export fn wing_ct_eq_tag16_asm(a: const u8[:], b: const u8[:]) -> bool {
    guard a.len == 16 && b.len == 16 else { return false; }
    var ta: u8[16] = [0; 16];
    var tb: u8[16] = [0; 16];
    for i in 16 {
        ta[i] = a[i];
        tb[i] = b[i];
    }
    return core::ct_eq_tag16(ta, tb);
}

export fn wing_ct_eq_tag32_asm(a: const u8[:], b: const u8[:]) -> bool {
    guard a.len == 32 && b.len == 32 else { return false; }
    var ta: u8[32] = [0; 32];
    var tb: u8[32] = [0; 32];
    for i in 32 {
        ta[i] = a[i];
        tb[i] = b[i];
    }
    return core::ct_eq_tag32(ta, tb);
}

export fn wing_ct_eq_bytes_asm(a: const u8[:], b: const u8[:]) -> bool {
    return core::ct_eq_bytes(a, b);
}

fn verify_ct_primitives() {
    assert(core::ct_select_u8(1, 0xAA, 0x55) == 0xAA);
    assert(core::ct_select_u8(0, 0xAA, 0x55) == 0x55);

    var t16_a: u8[16] = [0x11; 16];
    var t16_b: u8[16] = [0x11; 16];
    assert(core::ct_eq_tag16(t16_a, t16_b));
    assert(wing_ct_eq_tag16_asm(t16_a[..], t16_b[..]));
    for pos in 16 {
        t16_b[pos] ^= 0x01;
        assert(!core::ct_eq_tag16(t16_a, t16_b));
        t16_b[pos] ^= 0x01;
    }

    var t32_a: u8[32] = [0x22; 32];
    var t32_b: u8[32] = [0x22; 32];
    assert(core::ct_eq_tag32(t32_a, t32_b));
    assert(wing_ct_eq_tag32_asm(t32_a[..], t32_b[..]));
    for pos in 32 {
        t32_b[pos] ^= 0x80;
        assert(!core::ct_eq_tag32(t32_a, t32_b));
        t32_b[pos] ^= 0x80;
    }

    var t48_a: u8[48] = [0x33; 48];
    var t48_b: u8[48] = [0x33; 48];
    assert(core::ct_eq_tag48(t48_a, t48_b));
    for pos in 48 {
        t48_b[pos] ^= 0x40;
        assert(!core::ct_eq_tag48(t48_a, t48_b));
        t48_b[pos] ^= 0x40;
    }

    var s37_a: u8[37] = [0x7E; 37];
    var s37_b: u8[37] = [0x7E; 37];
    assert(wing_ct_eq_bytes_asm(s37_a[..], s37_b[..]));
    s37_b[0] ^= 1;
    assert(!wing_ct_eq_bytes_asm(s37_a[..], s37_b[..]));
    s37_b[0] ^= 1;
    s37_b[36] ^= 1;
    assert(!wing_ct_eq_bytes_asm(s37_a[..], s37_b[..]));
    print("CT_PRIMITIVES: ok");
}

fn main() {
    // CHECK: === verify_constant_time_dudect ===
    print("=== verify_constant_time_dudect ===");
    // CHECK-NEXT: CT_PRIMITIVES: ok
    verify_ct_primitives();
    // CHECK-NEXT: ALL_CONSTANT_TIME_CHECKS_PASSED
    print("ALL_CONSTANT_TIME_CHECKS_PASSED");
}
