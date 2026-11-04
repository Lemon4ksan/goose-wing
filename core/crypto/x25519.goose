// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Deterministic zero-allocation Curve25519 Diffie-Hellman Key Exchange (RFC 7748).
// Implements constant-time Montgomery ladder using 10-limb 2^25.5 field representation.
namespace core;

import std;
import core.crypto.fusion;

// ---- Field Element (10 limbs, alternating 26 and 25 bits) ----------------

struct Fe10 {
    v: i64[10] = [0; 10],
}

// crap:ignore
inline fn x25519_load_u32_le(bytes: const u8[:], off: i64) -> u32 {
    return bytes[off] |
           ((bytes[off + 1] as u32) << 8) |
           ((bytes[off + 2] as u32) << 16) |
           ((bytes[off + 3] as u32) << 24);
}

// Expands a 32-byte canonical little-endian integer into 10 limbs.
fn fe_from_bytes(b: const u8[32]&) -> Fe10 {
    var out = Fe10 { .. };
    out.v[0] = ((x25519_load_u32_le(b[..], 0) >> 0) & 0x3FFFFFF);
    out.v[1] = ((x25519_load_u32_le(b[..], 3) >> 2) & 0x1FFFFFF);
    out.v[2] = ((x25519_load_u32_le(b[..], 6) >> 3) & 0x3FFFFFF);
    out.v[3] = ((x25519_load_u32_le(b[..], 9) >> 5) & 0x1FFFFFF);
    out.v[4] = ((x25519_load_u32_le(b[..], 12) >> 6) & 0x3FFFFFF);
    out.v[5] = ((x25519_load_u32_le(b[..], 16) >> 0) & 0x1FFFFFF);
    out.v[6] = ((x25519_load_u32_le(b[..], 19) >> 1) & 0x3FFFFFF);
    out.v[7] = ((x25519_load_u32_le(b[..], 22) >> 3) & 0x1FFFFFF);
    out.v[8] = ((x25519_load_u32_le(b[..], 25) >> 4) & 0x3FFFFFF);
    out.v[9] = ((x25519_load_u32_le(b[..], 28) >> 6) & 0x1FFFFFF);
    return out;
}

// Propagates carries across the 10 limbs modulo 2^255 - 19.
// crap:ignore
fn fe_carry(t: Fe10&) {
    var c0 = t.v[0] >> 26; t.v[0] &= 0x3FFFFFF; t.v[1] += c0;
    var c1 = t.v[1] >> 25; t.v[1] &= 0x1FFFFFF; t.v[2] += c1;
    var c2 = t.v[2] >> 26; t.v[2] &= 0x3FFFFFF; t.v[3] += c2;
    var c3 = t.v[3] >> 25; t.v[3] &= 0x1FFFFFF; t.v[4] += c3;
    var c4 = t.v[4] >> 26; t.v[4] &= 0x3FFFFFF; t.v[5] += c4;
    var c5 = t.v[5] >> 25; t.v[5] &= 0x1FFFFFF; t.v[6] += c5;
    var c6 = t.v[6] >> 26; t.v[6] &= 0x3FFFFFF; t.v[7] += c6;
    var c7 = t.v[7] >> 25; t.v[7] &= 0x1FFFFFF; t.v[8] += c7;
    var c8 = t.v[8] >> 26; t.v[8] &= 0x3FFFFFF; t.v[9] += c8;
    var c9 = t.v[9] >> 25; t.v[9] &= 0x1FFFFFF; t.v[0] += c9 * 19;
}

// Contracts 10 limbs into canonical 32 little-endian bytes in [0, 2^255 - 20].
// crap:ignore
fn fe_to_bytes(fe: Fe10) -> u8[32] {
    var t = fe;
    fe_carry(t);
    fe_carry(t);

    var q = (19 * t.v[9] + t.v[0]) >> 26;
    q = (q + t.v[1]) >> 25;
    q = (q + t.v[2]) >> 26;
    q = (q + t.v[3]) >> 25;
    q = (q + t.v[4]) >> 26;
    q = (q + t.v[5]) >> 25;
    q = (q + t.v[6]) >> 26;
    q = (q + t.v[7]) >> 25;
    q = (q + t.v[8]) >> 26;
    q = (q + t.v[9]) >> 25;

    t.v[0] += 19 * q;
    fe_carry(t);
    t.v[0] -= 19 * q;

    var out: u8[32] = [0; 32];
    out[0] = (t.v[0] >> 0) as u8;
    out[1] = (t.v[0] >> 8) as u8;
    out[2] = (t.v[0] >> 16) as u8;
    out[3] = ((t.v[0] >> 24) | (t.v[1] << 2)) as u8;
    out[4] = (t.v[1] >> 6) as u8;
    out[5] = (t.v[1] >> 14) as u8;
    out[6] = ((t.v[1] >> 22) | (t.v[2] << 3)) as u8;
    out[7] = (t.v[2] >> 5) as u8;
    out[8] = (t.v[2] >> 13) as u8;
    out[9] = ((t.v[2] >> 21) | (t.v[3] << 5)) as u8;
    out[10] = (t.v[3] >> 3) as u8;
    out[11] = (t.v[3] >> 11) as u8;
    out[12] = ((t.v[3] >> 19) | (t.v[4] << 6)) as u8;
    out[13] = (t.v[4] >> 2) as u8;
    out[14] = (t.v[4] >> 10) as u8;
    out[15] = (t.v[4] >> 18) as u8;
    out[16] = (t.v[5] >> 0) as u8;
    out[17] = (t.v[5] >> 8) as u8;
    out[18] = (t.v[5] >> 16) as u8;
    out[19] = ((t.v[5] >> 24) | (t.v[6] << 1)) as u8;
    out[20] = (t.v[6] >> 7) as u8;
    out[21] = (t.v[6] >> 15) as u8;
    out[22] = ((t.v[6] >> 23) | (t.v[7] << 3)) as u8;
    out[23] = (t.v[7] >> 5) as u8;
    out[24] = (t.v[7] >> 13) as u8;
    out[25] = ((t.v[7] >> 21) | (t.v[8] << 4)) as u8;
    out[26] = (t.v[8] >> 4) as u8;
    out[27] = (t.v[8] >> 12) as u8;
    out[28] = ((t.v[8] >> 20) | (t.v[9] << 6)) as u8;
    out[29] = (t.v[9] >> 2) as u8;
    out[30] = (t.v[9] >> 10) as u8;
    out[31] = (t.v[9] >> 18) as u8;
    return out;
}

// Field addition: out = a + b (mod 2^255 - 19).
// crap:ignore
fn fe_add(a: Fe10, b: Fe10) -> Fe10 {
    var out = Fe10 { .. };
    for i in 10 {
        out.v[i] = a.v[i] + b.v[i];
    }
    fe_carry(out);
    return out;
}

// Field subtraction: out = a - b (mod 2^255 - 19).
// Adds 2 * p bias before subtraction to guarantee non-negative limbs.
// crap:ignore
fn fe_sub(a: Fe10, b: Fe10) -> Fe10 {
    var out = Fe10 { .. };
    out.v[0] = (a.v[0] + 0x7FFFFDA) - b.v[0];
    out.v[1] = (a.v[1] + 0x3FFFFFE) - b.v[1];
    out.v[2] = (a.v[2] + 0x7FFFFFE) - b.v[2];
    out.v[3] = (a.v[3] + 0x3FFFFFE) - b.v[3];
    out.v[4] = (a.v[4] + 0x7FFFFFE) - b.v[4];
    out.v[5] = (a.v[5] + 0x3FFFFFE) - b.v[5];
    out.v[6] = (a.v[6] + 0x7FFFFFE) - b.v[6];
    out.v[7] = (a.v[7] + 0x3FFFFFE) - b.v[7];
    out.v[8] = (a.v[8] + 0x7FFFFFE) - b.v[8];
    out.v[9] = (a.v[9] + 0x3FFFFFE) - b.v[9];
    fe_carry(out);
    return out;
}

// Field multiplication: out = f * g (mod 2^255 - 19).
// crap:ignore
fn fe_mul(f: Fe10, g: Fe10) -> Fe10 {
    let f0 = f.v[0]; let f1 = f.v[1]; let f2 = f.v[2]; let f3 = f.v[3]; let f4 = f.v[4];
    let f5 = f.v[5]; let f6 = f.v[6]; let f7 = f.v[7]; let f8 = f.v[8]; let f9 = f.v[9];

    let g0 = g.v[0]; let g1 = g.v[1]; let g2 = g.v[2]; let g3 = g.v[3]; let g4 = g.v[4];
    let g5 = g.v[5]; let g6 = g.v[6]; let g7 = g.v[7]; let g8 = g.v[8]; let g9 = g.v[9];

    let g1_19 = g1 * 19;
    let g2_19 = g2 * 19;
    let g3_19 = g3 * 19;
    let g4_19 = g4 * 19;
    let g5_19 = g5 * 19;
    let g6_19 = g6 * 19;
    let g7_19 = g7 * 19;
    let g8_19 = g8 * 19;
    let g9_19 = g9 * 19;

    var h = Fe10 { .. };

    h.v[0] = f0 * g0 +
             2 * (f1 * g9_19 + f3 * g7_19 + f5 * g5_19 + f7 * g3_19 + f9 * g1_19) +
             (f2 * g8_19 + f4 * g6_19 + f6 * g4_19 + f8 * g2_19);

    h.v[1] = f0 * g1 + f1 * g0 +
             f2 * g9_19 + f3 * g8_19 + f4 * g7_19 + f5 * g6_19 +
             f6 * g5_19 + f7 * g4_19 + f8 * g3_19 + f9 * g2_19;

    h.v[2] = f0 * g2 + 2 * (f1 * g1) + f2 * g0 +
             2 * (f3 * g9_19 + f5 * g7_19 + f7 * g5_19 + f9 * g3_19) +
             (f4 * g8_19 + f6 * g6_19 + f8 * g4_19);

    h.v[3] = f0 * g3 + f1 * g2 + f2 * g1 + f3 * g0 +
             f4 * g9_19 + f5 * g8_19 + f6 * g7_19 + f7 * g6_19 +
             f8 * g5_19 + f9 * g4_19;

    h.v[4] = f0 * g4 + 2 * (f1 * g3) + f2 * g2 + 2 * (f3 * g1) + f4 * g0 +
             2 * (f5 * g9_19 + f7 * g7_19 + f9 * g5_19) +
             (f6 * g8_19 + f8 * g6_19);

    h.v[5] = f0 * g5 + f1 * g4 + f2 * g3 + f3 * g2 + f4 * g1 + f5 * g0 +
             f6 * g9_19 + f7 * g8_19 + f8 * g7_19 + f9 * g6_19;

    h.v[6] = f0 * g6 + 2 * (f1 * g5) + f2 * g4 + 2 * (f3 * g3) + f4 * g2 + 2 * (f5 * g1) + f6 * g0 +
             2 * (f7 * g9_19 + f9 * g7_19) +
             (f8 * g8_19);

    h.v[7] = f0 * g7 + f1 * g6 + f2 * g5 + f3 * g4 + f4 * g3 + f5 * g2 + f6 * g1 + f7 * g0 +
             f8 * g9_19 + f9 * g8_19;

    h.v[8] = f0 * g8 + 2 * (f1 * g7) + f2 * g6 + 2 * (f3 * g5) + f4 * g4 +
             2 * (f5 * g3) + f6 * g2 + 2 * (f7 * g1) + f8 * g0 +
             2 * (f9 * g9_19);

    h.v[9] = f0 * g9 + f1 * g8 + f2 * g7 + f3 * g6 + f4 * g5 + f5 * g4 + f6 * g3 + f7 * g2 + f8 * g1 + f9 * g0;

    fe_carry(h);
    fe_carry(h);
    return h;
}

// Field squaring: out = f^2 (mod 2^255 - 19).
fn fe_sq(f: Fe10) -> Fe10 {
    return fe_mul(f, f);
}

// Multiplication by Curve25519 constant a24 = (486662 - 2) / 4 = 121665.
// crap:ignore
fn fe_mul121665(f: Fe10) -> Fe10 {
    var h = Fe10 { .. };
    for i in 10 {
        h.v[i] = f.v[i] * 121665;
    }
    fe_carry(h);
    fe_carry(h);
    return h;
}

// Field inversion: computes z^(p - 2) mod p via optimal 255-bit addition chain.
fn fe_inv(z: Fe10) -> Fe10 {
    /* 2 */ let a = fe_sq(z);
    /* 4 */ let t0 = fe_sq(a);
    /* 8 */ let t1 = fe_sq(t0);
    /* 9 */ let b = fe_mul(t1, z);
    /* 11 */ let c = fe_mul(b, a);
    /* 22 */ let t2 = fe_sq(c);
    /* 31 */ let d = fe_mul(t2, b);

    var t3 = d;
    for i in 5 { t3 = fe_sq(t3); }
    let e = fe_mul(t3, d);

    var t4 = e;
    for i in 10 { t4 = fe_sq(t4); }
    let f_val = fe_mul(t4, e);

    var t5 = f_val;
    for i in 20 { t5 = fe_sq(t5); }
    let g = fe_mul(t5, f_val);

    var t6 = g;
    for i in 10 { t6 = fe_sq(t6); }
    let h = fe_mul(t6, e);

    var t7 = h;
    for i in 50 { t7 = fe_sq(t7); }
    let i_val = fe_mul(t7, h);

    var t8 = i_val;
    for i in 100 { t8 = fe_sq(t8); }
    let j = fe_mul(t8, i_val);

    var t9 = j;
    for i in 50 { t9 = fe_sq(t9); }
    let k = fe_mul(t9, h);

    var t10 = k;
    for i in 5 { t10 = fe_sq(t10); }
    return fe_mul(t10, c);
}

// Constant-time conditional swap of two field elements using core::ct_mask_u64 and core::ct_select_u64.
// Zero secret-dependent branches are emitted.
inline fn fe_cswap(swap: u8, a: Fe10&, b: Fe10&) {
    let mask = ct_mask_u64(swap & 1);
    for i in 10 {
        let ai = a.v[i] as u64;
        let bi = b.v[i] as u64;
        a.v[i] = ct_select_u64(mask, bi, ai) as i64;
        b.v[i] = ct_select_u64(mask, ai, bi) as i64;
    }
}

// ---- Montgomery Ladder Scalar Multiplication (RFC 7748 Section 5) ---------

fn clamp_scalar_rfc7748(scalar: const u8[32]&) -> u8[32] {
    var clamped: u8[32] = scalar;
    clamped[0] &= 248;
    clamped[31] &= 127;
    clamped[31] |= 64;
    return clamped;
}

// Performs X25519 scalar multiplication: out = scalar * point on Curve25519.
// crap:ignore
fn x25519_scalarmult(scalar: const u8[32]&, point: const u8[32]&) -> u8[32] {
    var clamped = clamp_scalar_rfc7748(scalar);

    let x_1 = fe_from_bytes(point);
    var x_2 = Fe10 { v: [1, 0, 0, 0, 0, 0, 0, 0, 0, 0] };
    var z_2 = Fe10 { .. };
    var x_3 = x_1;
    var z_3 = Fe10 { v: [1, 0, 0, 0, 0, 0, 0, 0, 0, 0] };
    var swap: u8 = 0;

    for i in 255 {
        let bit_pos = 254 - i;
        let byte_idx = bit_pos / 8;
        let bit_idx = (bit_pos % 8) as u8;
        let k_t = (clamped[byte_idx] >> bit_idx) & 1;

        let do_swap = swap ^ k_t;
        swap = k_t;
        fe_cswap(do_swap, x_2, x_3);
        fe_cswap(do_swap, z_2, z_3);

        let a = fe_add(x_2, z_2);
        let aa = fe_sq(a);
        let b = fe_sub(x_2, z_2);
        let bb = fe_sq(b);
        let e = fe_sub(aa, bb);
        let c = fe_add(x_3, z_3);
        let d = fe_sub(x_3, z_3);
        let da = fe_mul(d, a);
        let cb = fe_mul(c, b);

        x_3 = fe_sq(fe_add(da, cb));
        z_3 = fe_mul(x_1, fe_sq(fe_sub(da, cb)));
        x_2 = fe_mul(aa, bb);
        z_2 = fe_mul(e, fe_add(aa, fe_mul121665(e)));
    }

    fe_cswap(swap, x_2, x_3);
    fe_cswap(swap, z_2, z_3);

    let res = fe_mul(x_2, fe_inv(z_2));
    let out = fe_to_bytes(res);
    secure_zeroize_32(clamped);
    return out;
}

// Multiplies scalar by the standard Curve25519 base point u = 9.
fn x25519_base_scalarmult(scalar: const u8[32]&) -> u8[32] {
    let u9: u8[32] = [
        9, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0,
    ];
    return x25519_scalarmult(scalar, u9);
}

// Constant-time check if 32-byte shared secret is all zeros (RFC 7748 §6.1).
fn x25519_is_all_zero(ss: const u8[32]&) -> bool {
    let zero: u8[32] = [0; 32];
    return ct_eq_tag32(ss, zero);
}

// Performs X25519 Diffie-Hellman shared secret calculation (RFC 7748 §6.1).
// Returns (shared_secret, true) on success, or ([0; 32], false) if the result is all-zero (low-order point attack).
fn x25519_shared_secret(scalar: const u8[32]&, point: const u8[32]&) -> u8[32], bool {
    let ss = x25519_scalarmult(scalar, point);
    if x25519_is_all_zero(ss) {
        var zero_ss: u8[32] = [0; 32];
        return zero_ss, false;
    }
    return ss, true;
}
