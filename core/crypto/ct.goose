// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Constant-time primitives, key zeroization, KeySlot secrecy pattern, and Dudect Welch t-test verifier.
namespace core;

import std;

// ---- constant-time branchless primitives -----------------------------------

// Returns 1 if a == b, 0 otherwise, using purely branchless bitwise arithmetic.
inline fn ct_eq_u8(a: u8, b: u8) -> u8 {
    let diff = (a ^ b) as u32;
    let non_zero = (diff | (0 - diff)) >> 31;
    return (1 - non_zero) as u8;
}

// Branchless conditional selection: returns if_true when bit == 1, if_false when bit == 0.
inline fn ct_select_u8(bit: u8, if_true: u8, if_false: u8) -> u8 {
    let mask = 0 - (bit & 1);
    return (if_false & (~mask)) | (if_true & mask);
}

// Constant-time slice equality check: only branches on public length before reading secret bytes.
fn ct_eq_bytes(bytes_a: const u8[:], bytes_b: const u8[:]) -> bool {
    guard bytes_a.len == bytes_b.len else { return false; }
    var diff_accum: u64 = 0;
    var idx = 0;
    while idx + 8 <= bytes_a.len {
        diff_accum |= core::read_le_u64(bytes_a, idx) ^ core::read_le_u64(bytes_b, idx);
        idx += 8;
    }
    var tail_accum: u8 = 0;
    while idx < bytes_a.len {
        tail_accum |= bytes_a[idx] ^ bytes_b[idx];
        idx += 1;
    }
    let total_diff = diff_accum | tail_accum;
    let non_zero = (total_diff | (0 - total_diff)) >> 63;
    return non_zero == 0;
}

// Constant-time 16-byte authentication tag comparison (Poly1305 / AES-GCM).
fn ct_eq_tag16(tag_a: const u8[16]&, tag_b: const u8[16]&) -> bool {
    let diff0 = core::read_le_u64(tag_a[..], 0) ^ core::read_le_u64(tag_b[..], 0);
    let diff1 = core::read_le_u64(tag_a[..], 8) ^ core::read_le_u64(tag_b[..], 8);
    let diff = diff0 | diff1;
    let non_zero = (diff | (0 - diff)) >> 63;
    return non_zero == 0;
}

// Constant-time 32-byte MAC comparison (HMAC-SHA256).
fn ct_eq_tag32(tag_a: const u8[32]&, tag_b: const u8[32]&) -> bool {
    let diff0 = core::read_le_u64(tag_a[..], 0) ^ core::read_le_u64(tag_b[..], 0);
    let diff1 = core::read_le_u64(tag_a[..], 8) ^ core::read_le_u64(tag_b[..], 8);
    let diff2 = core::read_le_u64(tag_a[..], 16) ^ core::read_le_u64(tag_b[..], 16);
    let diff3 = core::read_le_u64(tag_a[..], 24) ^ core::read_le_u64(tag_b[..], 24);
    let diff = diff0 | diff1 | diff2 | diff3;
    let non_zero = (diff | (0 - diff)) >> 63;
    return non_zero == 0;
}

// Constant-time 48-byte MAC comparison (HMAC-SHA384).
fn ct_eq_tag48(tag_a: const u8[48]&, tag_b: const u8[48]&) -> bool {
    var diff: u64 = 0;
    for i in 6 {
        let off = i * 8;
        diff |= core::read_le_u64(tag_a[..], off) ^ core::read_le_u64(tag_b[..], off);
    }
    let non_zero = (diff | (0 - diff)) >> 63;
    return non_zero == 0;
}

fn ct_copy_bytes(dst: u8[:], src: const u8[:]) {
    let len = if dst.len < src.len { dst.len } else { src.len };
    for i in len { dst[i] = src[i]; }
}

// ---- secret memory zeroization & KeySlot (secrecy pattern) -----------------

fn secure_zeroize_16(buf: u8[16]&) {
    for idx in 16 { buf[idx] = 0; }
}

fn secure_zeroize_24(buf: u8[24]&) {
    for idx in 24 { buf[idx] = 0; }
}

fn secure_zeroize_32(buf: u8[32]&) {
    for idx in 32 { buf[idx] = 0; }
}

fn secure_zeroize_48(buf: u8[48]&) {
    for idx in 48 { buf[idx] = 0; }
}

fn secure_zeroize_64(buf: u8[64]&) {
    for idx in 64 { buf[idx] = 0; }
}

fn secure_zeroize_slice(buf: u8[:]) {
    for idx in buf.len {
        buf[idx] = 0;
    }
}

fn secure_zeroize_vec(buf: u8[>..]&) {
    for idx in buf.len {
        buf[idx] = 0;
    }
    buf.clear();
}

// KeySlot encapsulates a 256-bit cryptographic master key with rotation metadata.
struct KeySlot {
    key_id:         u32    = 0,
    master_key:     u8[32] = [0; 32],
    created_at_sec: i64    = 0,
    expires_at_sec: i64    = 0,
    revoked:        bool   = false,
}

fn new_key_slot(key_id: u32, raw_key: const u8[:], created_at_sec: i64 = 0, expires_at_sec: i64 = 0) -> KeySlot {
    var slot = KeySlot {
        key_id:         key_id,
        master_key:     [0; 32],
        created_at_sec: created_at_sec,
        expires_at_sec: expires_at_sec,
        revoked:        false,
    };
    let copy_len = if raw_key.len < 32 { raw_key.len } else { 32 };
    for idx in copy_len {
        slot.master_key[idx] = raw_key[idx];
    }
    return slot;
}

fn zeroize_key_slot(slot: KeySlot&) {
    secure_zeroize_32(slot.master_key);
    slot.revoked = true;
}

// Redacted format hook preventing accidental leakage of secret key bytes into logs.
fn format<B>(out: B&, slot: const KeySlot&) {
    out.append("KeySlot { key_id: ");
    format(out, slot.key_id);
    out.append(", master_key: [REDACTED], revoked: ");
    format(out, slot.revoked);
    out.append(" }");
}

fn display_redacted<B>(slot: const KeySlot&, out: B&) {
    format(out, slot);
}

// ---- dudect statistical constant-time verifier (Welch's t-test) ------------

// Online Welford accumulator for two timing classes with OS preemption outlier cropping.
struct DudectContext {
    crop_threshold_ns: f64 = 2000.0,
    n0:                i64 = 0,
    n1:                i64 = 0,
    mean0:             f64 = 0.0,
    mean1:             f64 = 0.0,
    m2_0:              f64 = 0.0,
    m2_1:              f64 = 0.0,
    cropped_outliers:  i64 = 0,
}

fn new_dudect_context(crop_threshold_ns: f64 = 2000.0) -> DudectContext {
    return DudectContext { crop_threshold_ns: crop_threshold_ns, .. };
}

// Records a timing sample (in nanoseconds) for class 0 or class 1.
// Samples exceeding crop_threshold_ns are discarded (cropped), never clamped,
// preserving unbiased sample means per hardware-rust-crypto methodology.
fn dudect_push_sample(ctx: DudectContext&, class_idx: i32, elapsed_ns: f64) -> bool {
    if elapsed_ns < 0.0 || (ctx.crop_threshold_ns > 0.0 && elapsed_ns > ctx.crop_threshold_ns) {
        ctx.cropped_outliers += 1;
        return false;
    }
    if class_idx == 0 {
        ctx.n0 += 1;
        let delta = elapsed_ns - ctx.mean0;
        ctx.mean0 += delta / ctx.n0;
        let delta2 = elapsed_ns - ctx.mean0;
        ctx.m2_0 += delta * delta2;
    } else {
        ctx.n1 += 1;
        let delta = elapsed_ns - ctx.mean1;
        ctx.mean1 += delta / ctx.n1;
        let delta2 = elapsed_ns - ctx.mean1;
        ctx.m2_1 += delta * delta2;
    }
    return true;
}

// Approximate Newton-Raphson square root for Welch's t-statistic denominator.
fn approx_sqrt(val: f64) -> f64 {
    if val <= 0.0 { return 0.0; }
    var x = val;
    for iter in 20 {
        x = 0.5 * (x + val / x);
    }
    return x;
}

// Computes absolute Welch's |t| statistic between Class 0 and Class 1.
fn dudect_abs_t(ctx: const DudectContext&) -> f64 {
    if ctx.n0 < 2 || ctx.n1 < 2 { return 0.0; }
    let var0 = ctx.m2_0 / (ctx.n0 - 1);
    let var1 = ctx.m2_1 / (ctx.n1 - 1);
    let denom_sq = (var0 / ctx.n0) + (var1 / ctx.n1);
    if denom_sq <= 0.000000000001 { return 0.0; }
    let diff = ctx.mean0 - ctx.mean1;
    let abs_diff = if diff < 0.0 { -diff } else { diff };
    return abs_diff / approx_sqrt(denom_sq);
}

// Verifies that |t| is strictly below threshold (default 4.5 for 99.999% confidence, or 1.5 for lockstep).
fn dudect_is_constant_time(ctx: const DudectContext&, max_t: f64 = 4.5) -> bool {
    return dudect_abs_t(ctx) <= max_t;
}
