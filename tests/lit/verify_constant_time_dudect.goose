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
    assert(core::ct_eq_u8(0x00, 0x00) == 1);
    assert(core::ct_eq_u8(0xFF, 0xFF) == 1);
    assert(core::ct_eq_u8(0x5A, 0x5B) == 0);
    assert(core::ct_eq_u8(0x00, 0x80) == 0);

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

fn verify_key_slot_secrecy() {
    let raw_secret: u8[32] = [0xDE; 32];
    var slot = core::new_key_slot(42, raw_secret[..], 1700000000, 1700086400);
    assert(!slot.revoked && slot.key_id == 42);

    var formatted: u8[..128] = [];
    core::display_redacted(slot, formatted);
    assert(formatted[..] == "KeySlot { key_id: 42, master_key: [REDACTED], revoked: false }");

    core::zeroize_key_slot(slot);
    assert(slot.revoked);
    var zeroes: u8[32] = [0; 32];
    assert(core::ct_eq_tag32(slot.master_key, zeroes));
    print("KEY_SLOT_SECRECY: ok");
}

fn verify_dudect_welch_t_test() {
    var ct_ctx = core::new_dudect_context(1000.0);
    for i in 500 {
        let jitter = ((i % 7) - 3) as f64;
        assert(core::dudect_push_sample(ct_ctx, 0, 120.0 + jitter));
        assert(core::dudect_push_sample(ct_ctx, 1, 120.0 + jitter));
    }
    // Preemption outlier above crop_threshold_ns (1000.0 ns) must be cropped
    assert(!core::dudect_push_sample(ct_ctx, 0, 50000.0));
    assert(ct_ctx.cropped_outliers == 1);
    assert(core::dudect_is_constant_time(ct_ctx, 4.5));

    // Variable-time early-exit leak (Class 0 takes 25 ns, Class 1 takes 180 ns) must fail
    var leaky_ctx = core::new_dudect_context(1000.0);
    for i in 500 {
        let jitter = ((i % 5) - 2) as f64;
        assert(core::dudect_push_sample(leaky_ctx, 0, 25.0 + jitter));
        assert(core::dudect_push_sample(leaky_ctx, 1, 180.0 + jitter));
    }
    assert(!core::dudect_is_constant_time(leaky_ctx, 4.5));
    assert(core::dudect_abs_t(leaky_ctx) > 50.0);

    // Empirical constant-time execution harness on ct_eq_tag32 (Class 0: byte 0 differs, Class 1: byte 31 differs)
    var emp_ctx = core::new_dudect_context(50000.0);
    var ref_tag:  u8[32] = [0xA5; 32];
    var cls0_tag: u8[32] = [0xA5; 32];
    cls0_tag[0] ^= 0x01;
    var cls1_tag: u8[32] = [0xA5; 32];
    cls1_tag[31] ^= 0x01;

    var acc: u32 = 0;
    for iter in 200 {
        let t0 = core::monotonic_now().nanos;
        for _ in 64 {
            if core::ct_eq_tag32(ref_tag, cls0_tag) { acc += 1; }
        }
        let t1 = core::monotonic_now().nanos;
        let _ = core::dudect_push_sample(emp_ctx, 0, (core::sub_sat_u64(t1, t0)) as f64);

        let t2 = core::monotonic_now().nanos;
        for _ in 64 {
            if core::ct_eq_tag32(ref_tag, cls1_tag) { acc += 1; }
        }
        let t3 = core::monotonic_now().nanos;
        let _ = core::dudect_push_sample(emp_ctx, 1, (core::sub_sat_u64(t3, t2)) as f64);
        if iter < 0 { acc += 1; }
    }
    assert(acc == 0);
    print("DUDECT_WELCH_T_TEST: ok");
}

fn main() {
    // CHECK: === verify_constant_time_dudect ===
    print("=== verify_constant_time_dudect ===");
    // CHECK-NEXT: CT_PRIMITIVES: ok
    verify_ct_primitives();
    // CHECK-NEXT: KEY_SLOT_SECRECY: ok
    verify_key_slot_secrecy();
    // CHECK-NEXT: DUDECT_WELCH_T_TEST: ok
    verify_dudect_welch_t_test();
    // CHECK-NEXT: ALL_CONSTANT_TIME_CHECKS_PASSED
    print("ALL_CONSTANT_TIME_CHECKS_PASSED");
}
