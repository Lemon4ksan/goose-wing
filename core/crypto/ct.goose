// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Constant-time primitives and key zeroization.
namespace core;

import std;
import core.io.cork;

// ---- constant-time branchless primitives -----------------------------------

extern fn ct_barrier_u8(val: u8) -> u8 = "wing_ct_barrier_u8";
extern fn secure_scrub_stack() = "wing_secure_scrub_stack";

// Branchless conditional selection: returns if_true when bit == 1, if_false when bit == 0.
inline fn ct_select_u8(bit: u8, if_true: u8, if_false: u8) -> u8 {
    let mask = ct_barrier_u8(0 - (bit & 1));
    return (if_false & (~mask)) | (if_true & mask);
}

// Constant-time slice equality check returning 1 if equal, 0 otherwise without branching on bytes.
fn ct_eq_bytes_bit(bytes_a: const u8[:], bytes_b: const u8[:]) -> u8 {
    guard bytes_a.len == bytes_b.len else { return 0; }
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
    return (1 - non_zero) as u8;
}

// Constant-time slice equality check: only branches on public length before reading secret bytes.
fn ct_eq_bytes(bytes_a: const u8[:], bytes_b: const u8[:]) -> bool {
    return ct_eq_bytes_bit(bytes_a, bytes_b) == 1;
}

// Constant-time 16-byte authentication tag comparison returning 1 if equal, 0 otherwise.
inline fn ct_eq_tag16_bit(tag_a: const u8[16]&, tag_b: const u8[16]&) -> u8 {
    let diff0 = core::read_le_u64(tag_a[..], 0) ^ core::read_le_u64(tag_b[..], 0);
    let diff1 = core::read_le_u64(tag_a[..], 8) ^ core::read_le_u64(tag_b[..], 8);
    let diff = diff0 | diff1;
    let non_zero = (diff | (0 - diff)) >> 63;
    return (1 - non_zero) as u8;
}

// Constant-time 16-byte authentication tag comparison (Poly1305 / AES-GCM).
fn ct_eq_tag16(tag_a: const u8[16]&, tag_b: const u8[16]&) -> bool {
    return ct_eq_tag16_bit(tag_a, tag_b) == 1;
}

// Constant-time all-zero check returning 1 if every byte of `data` is 0, 0 otherwise.
inline fn ct_is_zero_bit(data: const u8[:]) -> u8 {
    var acc: u8 = 0;
    for b in data {
        acc |= b;
    }
    let d = acc as u32;
    let non_zero = (d | (0 - d)) >> 31;
    return (1 - non_zero) as u8;
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

extern fn native_secure_zeroize(slice: u8[:]) = "wing_secure_zeroize";
extern fn native_secure_zeroize_u16(slice: u16[:]) = "wing_secure_zeroize_u16";
extern fn native_secure_zeroize_u32(slice: u32[:]) = "wing_secure_zeroize_u32";
extern fn native_secure_zeroize_u64(slice: u64[:]) = "wing_secure_zeroize_u64";
extern fn native_secure_zeroize_i32(slice: i32[:]) = "wing_secure_zeroize_i32";
extern fn native_ct_copy_bytes(dst: u8[:], src: const u8[:]) = "wing_ct_copy_bytes";
extern fn native_ct_declassify(buf: const u8[:]) = "wing_ct_declassify";
extern fn native_ct_declassify_u8(val: u8) -> u8 = "wing_ct_declassify_u8";

fn ct_copy_bytes(dst: u8[:], src: const u8[:]) {
    guard dst.len > 0 && src.len > 0 else { return; }
    native_ct_copy_bytes(dst, src);
}

// Marks a public slice computed from constant-time logic as defined for ctgrind verification.
inline fn ct_declassify_slice(buf: const u8[:]) {
    guard buf.len > 0 else { return; }
    native_ct_declassify(buf);
}

// Marks a public single-byte condition/flag as defined for ctgrind verification.
inline fn ct_declassify_u8(val: u8) -> u8 {
    return native_ct_declassify_u8(val);
}

// ---- secret memory zeroization & KeySlot (secrecy pattern) -----------------

fn secure_zeroize_16(buf: u8[16]&) {
    native_secure_zeroize(buf[..]);
}

fn secure_zeroize_32(buf: u8[32]&) {
    native_secure_zeroize(buf[..]);
}

fn secure_zeroize_48(buf: u8[48]&) {
    native_secure_zeroize(buf[..]);
}

fn secure_zeroize_64(buf: u8[64]&) {
    native_secure_zeroize(buf[..]);
}

fn secure_zeroize_slice(buf: u8[:]) {
    native_secure_zeroize(buf);
}

// Zeroizes a u32 word slice using volatile C stores immune to compiler DSE.
inline fn secure_zeroize_u32_slice(buf: u32[:]) {
    native_secure_zeroize_u32(buf);
}

// Zeroizes a u64 word slice using volatile C stores immune to compiler DSE.
inline fn secure_zeroize_u64_slice(buf: u64[:]) {
    native_secure_zeroize_u64(buf);
}

// Zeroizes a u16 word slice using volatile C stores immune to compiler DSE.
inline fn secure_zeroize_u16_slice(buf: u16[:]) {
    native_secure_zeroize_u16(buf);
}

// Zeroizes an i32 word slice using volatile C stores immune to compiler DSE.
inline fn secure_zeroize_i32_slice(buf: i32[:]) {
    native_secure_zeroize_i32(buf);
}

inline fn crypto_buf_has_room<A>(arr: const A&, needed: i64) -> bool {
    return needed >= 0 && arr.len <= arr.cap && needed <= arr.cap - arr.len;
}

inline fn crypto_buf_has_room(arr: const u8[>..]&, needed: i64) -> bool {
    return needed >= 0;
}

inline fn secure_zeroize_buf_tail<A>(arr: A&, start_len: i64) {
    if start_len >= 0 && start_len < arr.len {
        secure_zeroize_slice(arr[start_len..]);
    }
}

inline fn secure_zeroize_buf_tail(cb: CorkBuffer&, start_len: i64) {
    if start_len >= 0 && start_len < cb.len && cb.len <= CORK_BUFFER_CAP {
        secure_zeroize_slice(cb.storage[start_len..cb.len]);
    }
}
