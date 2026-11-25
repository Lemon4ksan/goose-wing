// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Deterministic zero-allocation ECDSA over NIST P-256 (secp256r1) and P-384 (secp384r1).
// Implements FIPS 186-5 digital signature verification and RFC 6979 deterministic signing.
namespace core;

import std;
import core.math;
import core.crypto.ct;
import core.crypto.sha;

// ---- NIST P-256 (secp256r1) 8-Limb 32-bit Representation -----------------

struct U256 {
    v: u32[8] = [0; 8],
}

// p = 2^256 - 2^224 + 2^192 + 2^96 - 1
const P256_MOD: const u32[8] = [
    0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0x00000000,
    0x00000000, 0x00000000, 0x00000001, 0xFFFFFFFF,
];

// n = FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
const P256_ORDER: const u32[8] = [
    0xFC632551, 0xF3B9CAC2, 0xA7179E84, 0xBCE6FAAD,
    0xFFFFFFFF, 0xFFFFFFFF, 0x00000000, 0xFFFFFFFF,
];

const P256_GX: const u32[8] = [
    0xD898C296, 0xF4A13945, 0x2DEB33A0, 0x77037D81,
    0x63A440F2, 0xF8BCE6E5, 0xE12C4247, 0x6B17D1F2,
];

const P256_GY: const u32[8] = [
    0x37BF51F5, 0xCBB64068, 0x6B315ECE, 0x2BCE3357,
    0x7C0F9E16, 0x8EE7EB4A, 0xFE1A7F9B, 0x4FE342E2,
];

const P256_B: const u32[8] = [
    0x27D2604B, 0x3BCE3C3E, 0xCC53B0F6, 0x651D06B0,
    0x769886BC, 0xB3EBBD55, 0xAA3A93E7, 0x5AC635D8,
];

// crap:ignore
inline fn u256_is_zero(a: U256) -> bool {
    var acc: u32 = 0;
    for i in 8 {
        acc |= a.v[i];
    }
    return acc == 0;
}

// Branchless 256-bit limb subtraction returning `(a - b, borrow)` where `borrow` is 0 or 1.
// crap:ignore
inline fn u256_sub_borrow(a: U256, b: const u32[8]&) -> U256, u64 {
    var diff = U256 { .. };
    var borrow: u64 = 0;
    for i in 8 {
        let d = (a.v[i] as u64) - b[i] - borrow;
        diff.v[i] = (d & 0xFFFFFFFF) as u32;
        borrow = d >> 63;
    }
    return diff, borrow;
}

// Branchless nonzero predicate returning 1 if `a != 0`, else 0.
// crap:ignore
inline fn u256_nonzero_bit(a: U256) -> i32 {
    var acc: u32 = 0;
    for i in 8 { acc |= a.v[i]; }
    return ((acc | (0 - acc)) >> 31) as i32;
}

// Branchless predicate returning 1 if `1 <= a < P256_ORDER`, else 0.
// crap:ignore
inline fn u256_in_order_bit(a: U256) -> u8 {
    let _, borrow = u256_sub_borrow(a, P256_ORDER);
    return ((u256_nonzero_bit(a) as u32) & (borrow as u32)) as u8;
}

// Branchless constant-time 256-bit comparison: returns -1 if a < b, 0 if a == b, 1 if a > b.
// crap:ignore
inline fn u256_cmp(a: U256, b: const u32[8]&) -> i32 {
    let diff, borrow = u256_sub_borrow(a, b);
    let nz = u256_nonzero_bit(diff);
    let lt = borrow as i32;
    let gt = nz & (1 ^ lt);
    return gt - lt;
}

// crap:ignore
inline fn u256_from_be(bytes: const u8[32]&) -> U256 {
    var out = U256 { .. };
    for i in 8 {
        let off = (7 - i) * 4;
        out.v[i] = ((bytes[off] as u32) << 24) |
                   ((bytes[off + 1] as u32) << 16) |
                   ((bytes[off + 2] as u32) << 8) |
                   bytes[off + 3];
    }
    return out;
}

// crap:ignore
inline fn u256_to_be(a: U256) -> u8[32] {
    var out: u8[32] = [0; 32];
    for i in 8 {
        let off = (7 - i) * 4;
        let w = a.v[i];
        out[off] = ((w >> 24) & 0xFF) as u8;
        out[off + 1] = ((w >> 16) & 0xFF) as u8;
        out[off + 2] = ((w >> 8) & 0xFF) as u8;
        out[off + 3] = (w & 0xFF) as u8;
    }
    return out;
}

// Branchless constant-time modular addition: `(a + b) mod m`.
// crap:ignore
fn u256_add_mod(a: U256, b: U256, m: const u32[8]&) -> U256 {
    var sum = U256 { .. };
    var carry: u64 = 0;
    for i in 8 {
        let s = (a.v[i] as u64) + b.v[i] + carry;
        sum.v[i] = (s & 0xFFFFFFFF) as u32;
        carry = s >> 32;
    }
    let diff, borrow = u256_sub_borrow(sum, m);
    let do_sub = ((carry | (1 ^ borrow)) & 1) as u32;
    return u256_select(do_sub, diff, sum);
}

// Branchless constant-time modular subtraction: `(a - b) mod m`.
// crap:ignore
fn u256_sub_mod(a: U256, b: U256, m: const u32[8]&) -> U256 {
    let diff, borrow = u256_sub_borrow(a, b.v);
    var sum = U256 { .. };
    var carry: u64 = 0;
    for i in 8 {
        let s = (diff.v[i] as u64) + m[i] + carry;
        sum.v[i] = (s & 0xFFFFFFFF) as u32;
        carry = s >> 32;
    }
    return u256_select(borrow as u32, sum, diff);
}

// Constant-time 256-bit integer selection.
// crap:ignore
inline fn u256_select(bit: u32, if_true: U256, if_false: U256) -> U256 {
    let mask = ct_barrier_u32(0 - (bit & 1));
    var out = U256 { .. };
    for i in 8 {
        out.v[i] = (if_false.v[i] & (~mask)) | (if_true.v[i] & mask);
    }
    return out;
}

// Zeroizes a 256-bit secret scalar in place.
// crap:ignore
inline fn zeroize_u256(val: U256&) {
    var z_bytes: u8[32] = [0; 32];
    secure_zeroize_32(z_bytes);
    val = u256_from_be(z_bytes);
}

// 32-bit CIOS Montgomery multiplication step on 8-limb U256: `(a * b * R^-1) mod m` where `R = 2^256`.
// crap:ignore
fn u256_monty_mul(a: U256, b: U256, m: const u32[8]&, m0i: u32) -> U256 {
    var t: u32[10] = [0; 10];
    for i in 8 {
        var carry1: u64 = 0;
        let ai = a.v[i] as u64;
        for j in 8 {
            let prod = ai * b.v[j] + t[j] + carry1;
            t[j] = (prod & 0xFFFFFFFF) as u32;
            carry1 = prod >> 32;
        }
        let sum1 = t[8] + carry1;
        t[8] = (sum1 & 0xFFFFFFFF) as u32;
        t[9] = (sum1 >> 32) as u32;

        let q = (t[0] * m0i) as u64;
        var carry2: u64 = (q * m[0] + t[0]) >> 32;
        var j:      i64 = 1;
        while j < 8 {
            let prod = q * m[j] + t[j] + carry2;
            t[j - 1] = (prod & 0xFFFFFFFF) as u32;
            carry2 = prod >> 32;
            j += 1;
        }
        let sum2 = t[8] + carry2;
        t[7] = (sum2 & 0xFFFFFFFF) as u32;
        let top_carry = (sum2 >> 32) + t[9];
        t[8] = (top_carry & 0xFFFFFFFF) as u32;
        t[9] = 0;
    }
    var out = U256 { .. };
    var diff = U256 { .. };
    var borrow: u64 = 0;
    for j in 8 {
        out.v[j] = t[j];
        let d = (t[j] as u64) - m[j] - borrow;
        diff.v[j] = (d & 0xFFFFFFFF) as u32;
        borrow = d >> 63;
    }
    let has_carry = ((t[8] | (0 - t[8])) >> 31) as u64;
    let do_sub = ((has_carry | (1 - borrow)) & 1) as u32;
    return u256_select(do_sub, diff, out);
}

// Fast 8x8 limb Montgomery modular multiplication: `(a * b) mod m`.
// Uses precomputed `R^2 mod m` and `-m[0]^-1 mod 2^32` for P-256 prime and group order.
// crap:ignore
fn u256_mul_mod(a: U256, b: U256, m: const u32[8]&) -> U256 {
    if m[0] == 0xFFFFFFFF {
        let r2_p = U256 {
            v: [
                0x00000003, 0x00000000, 0xFFFFFFFF, 0xFFFFFFFB,
                0xFFFFFFFE, 0xFFFFFFFF, 0xFFFFFFFD, 0x00000004,
            ],
        };
        let a_mont = u256_monty_mul(a, r2_p, m, 1);
        return u256_monty_mul(a_mont, b, m, 1);
    }
    if m[0] == 0xFC632551 {
        let r2_n = U256 {
            v: [
                0xBE79EEA2, 0x83244C95, 0x49BD6FA6, 0x4699799C,
                0x2B6BEC59, 0x2845B239, 0xF3D95620, 0x66E12D94,
            ],
        };
        let a_mont = u256_monty_mul(a, r2_n, m, 0xEE00BC4F);
        return u256_monty_mul(a_mont, b, m, 0xEE00BC4F);
    }
    var res = U256 { .. };
    var cur = a;
    for i in 256 {
        let limb = i >> 5;
        let bit = i & 31;
        let bit_val = (b.v[limb] >> bit) & 1;
        let next_res = u256_add_mod(res, cur, m);
        res = u256_select(bit_val, next_res, res);
        cur = u256_add_mod(cur, cur, m);
    }
    return res;
}

// Modular inversion via Fermat's Little Theorem: a^(m - 2) mod m.
// crap:ignore
fn u256_inv_mod(a: U256, m: const u32[8]&) -> U256 {
    var exp = U256 { .. };
    var borrow: u64 = 2;
    for i in 8 {
        let d = m[i] - borrow;
        exp.v[i] = (d & 0xFFFFFFFF) as u32;
        borrow = d >> 63;
    }
    var res = U256 { .. };
    res.v[0] = 1;
    var base = a;
    defer zeroize_u256(base);
    for i in 256 {
        let limb = i >> 5;
        let bit = i & 31;
        let bit_val = (exp.v[limb] >> bit) & 1;
        let prod = u256_mul_mod(res, base, m);
        res = u256_select(bit_val, prod, res);
        base = u256_mul_mod(base, base, m);
    }
    return res;
}

struct P256Point {
    x:        U256 = U256 { .. },
    y:        U256 = U256 { .. },
    infinity: bool = true,
}

// Homogeneous projective P-256 point `(X : Y : Z)` representing affine `(X/Z, Y/Z)`; infinity is `(0 : 1 : 0)`.
struct P256Projective {
    x: U256 = U256 { .. },
    y: U256 = U256 { v: [1, 0, 0, 0, 0, 0, 0, 0] },
    z: U256 = U256 { .. },
}

// Constant-time P-256 projective point selection.
// crap:ignore
inline fn p256_projective_select(bit: u32, if_true: P256Projective, if_false: P256Projective) -> P256Projective {
    return P256Projective {
        x: u256_select(bit, if_true.x, if_false.x),
        y: u256_select(bit, if_true.y, if_false.y),
        z: u256_select(bit, if_true.z, if_false.z),
    };
}

// Branchless conversion from affine P-256 point to homogeneous projective `(X : Y : Z)`.
// crap:ignore
inline fn p256_to_projective(pt: P256Point) -> P256Projective {
    let inf: u32 = if pt.infinity { 1 } else { 0 };
    let zero = U256 { .. };
    let one = U256 { v: [1, 0, 0, 0, 0, 0, 0, 0] };
    return P256Projective {
        x: u256_select(inf, zero, pt.x),
        y: u256_select(inf, one, pt.y),
        z: u256_select(inf, zero, one),
    };
}

// Complete exception-free doubling for a = -3 prime-order curves (Renes-Costello-Batina 2015, Algorithm 6).
// Zero branches; handles O = (0 : Y : 0) and all finite points uniformly.
// crap:ignore
fn p256_projective_double(pt: P256Projective) -> P256Projective {
    let b_coeff = U256 { v: P256_B };
    var t0 = u256_mul_mod(pt.x, pt.x, P256_MOD);
    let t1 = u256_mul_mod(pt.y, pt.y, P256_MOD);
    var t2 = u256_mul_mod(pt.z, pt.z, P256_MOD);
    var t3 = u256_mul_mod(pt.x, pt.y, P256_MOD);
    t3 = u256_add_mod(t3, t3, P256_MOD);
    var z3 = u256_mul_mod(pt.x, pt.z, P256_MOD);
    z3 = u256_add_mod(z3, z3, P256_MOD);
    var y3 = u256_sub_mod(u256_mul_mod(b_coeff, t2, P256_MOD), z3, P256_MOD);
    var x3 = u256_add_mod(y3, y3, P256_MOD);
    y3 = u256_add_mod(x3, y3, P256_MOD);
    x3 = u256_sub_mod(t1, y3, P256_MOD);
    y3 = u256_mul_mod(x3, u256_add_mod(t1, y3, P256_MOD), P256_MOD);
    x3 = u256_mul_mod(x3, t3, P256_MOD);
    t3 = u256_add_mod(t2, t2, P256_MOD);
    t2 = u256_add_mod(t2, t3, P256_MOD);
    z3 = u256_sub_mod(u256_sub_mod(u256_mul_mod(b_coeff, z3, P256_MOD), t2, P256_MOD), t0, P256_MOD);
    t3 = u256_add_mod(z3, z3, P256_MOD);
    z3 = u256_add_mod(z3, t3, P256_MOD);
    t3 = u256_add_mod(t0, t0, P256_MOD);
    t0 = u256_mul_mod(u256_sub_mod(u256_add_mod(t3, t0, P256_MOD), t2, P256_MOD), z3, P256_MOD);
    y3 = u256_add_mod(y3, t0, P256_MOD);
    t0 = u256_mul_mod(pt.y, pt.z, P256_MOD);
    t0 = u256_add_mod(t0, t0, P256_MOD);
    x3 = u256_sub_mod(x3, u256_mul_mod(t0, z3, P256_MOD), P256_MOD);
    z3 = u256_mul_mod(t0, t1, P256_MOD);
    z3 = u256_add_mod(z3, z3, P256_MOD);
    z3 = u256_add_mod(z3, z3, P256_MOD);
    return P256Projective { x: x3, y: y3, z: z3 };
}

// Complete exception-free addition for a = -3 prime-order curves (Renes-Costello-Batina 2015, Algorithm 4).
// Zero branches; handles O + P, P + O, P + P, and P + (-P) uniformly in constant time.
// crap:ignore
fn p256_projective_add(p1: P256Projective, p2: P256Projective) -> P256Projective {
    let b_coeff = U256 { v: P256_B };
    var t0 = u256_mul_mod(p1.x, p2.x, P256_MOD);
    var t1 = u256_mul_mod(p1.y, p2.y, P256_MOD);
    var t2 = u256_mul_mod(p1.z, p2.z, P256_MOD);
    var t3 = u256_mul_mod(u256_add_mod(p1.x, p1.y, P256_MOD), u256_add_mod(p2.x, p2.y, P256_MOD), P256_MOD);
    t3 = u256_sub_mod(t3, u256_add_mod(t0, t1, P256_MOD), P256_MOD);
    var t4 = u256_mul_mod(u256_add_mod(p1.y, p1.z, P256_MOD), u256_add_mod(p2.y, p2.z, P256_MOD), P256_MOD);
    t4 = u256_sub_mod(t4, u256_add_mod(t1, t2, P256_MOD), P256_MOD);
    var x3 = u256_mul_mod(u256_add_mod(p1.x, p1.z, P256_MOD), u256_add_mod(p2.x, p2.z, P256_MOD), P256_MOD);
    var y3 = u256_sub_mod(x3, u256_add_mod(t0, t2, P256_MOD), P256_MOD);
    var z3 = u256_mul_mod(b_coeff, t2, P256_MOD);
    x3 = u256_sub_mod(y3, z3, P256_MOD);
    z3 = u256_add_mod(x3, x3, P256_MOD);
    x3 = u256_add_mod(x3, z3, P256_MOD);
    z3 = u256_sub_mod(t1, x3, P256_MOD);
    x3 = u256_add_mod(t1, x3, P256_MOD);
    y3 = u256_mul_mod(b_coeff, y3, P256_MOD);
    t1 = u256_add_mod(t2, t2, P256_MOD);
    t2 = u256_add_mod(t1, t2, P256_MOD);
    y3 = u256_sub_mod(u256_sub_mod(y3, t2, P256_MOD), t0, P256_MOD);
    t1 = u256_add_mod(y3, y3, P256_MOD);
    y3 = u256_add_mod(t1, y3, P256_MOD);
    t1 = u256_add_mod(t0, t0, P256_MOD);
    t0 = u256_sub_mod(u256_add_mod(t1, t0, P256_MOD), t2, P256_MOD);
    t1 = u256_mul_mod(t4, y3, P256_MOD);
    t2 = u256_mul_mod(t0, y3, P256_MOD);
    y3 = u256_add_mod(u256_mul_mod(x3, z3, P256_MOD), t2, P256_MOD);
    x3 = u256_sub_mod(u256_mul_mod(t3, x3, P256_MOD), t1, P256_MOD);
    z3 = u256_add_mod(u256_mul_mod(t4, z3, P256_MOD), u256_mul_mod(t3, t0, P256_MOD), P256_MOD);
    return P256Projective { x: x3, y: y3, z: z3 };
}

// Converts a homogeneous projective P-256 point `(X : Y : Z)` to affine `(X / Z, Y / Z)`.
// crap:ignore
fn p256_projective_to_affine(pt: P256Projective) -> P256Point {
    let z_zero_bit = (1 ^ u256_nonzero_bit(pt.z)) as u32;
    let z_inv = u256_inv_mod(pt.z, P256_MOD);
    let x = u256_mul_mod(pt.x, z_inv, P256_MOD);
    let y = u256_mul_mod(pt.y, z_inv, P256_MOD);
    let zero = U256 { .. };
    return P256Point {
        x:        u256_select(z_zero_bit, zero, x),
        y:        u256_select(z_zero_bit, zero, y),
        infinity: z_zero_bit != 0,
    };
}

// crap:ignore
fn p256_point_double(pt: P256Point) -> P256Point {
    return p256_projective_to_affine(p256_projective_double(p256_to_projective(pt)));
}

// crap:ignore
fn p256_point_add(p1: P256Point, p2: P256Point) -> P256Point {
    return p256_projective_to_affine(p256_projective_add(p256_to_projective(p1), p256_to_projective(p2)));
}

// Constant-time scalar multiplication: `[scalar] * pt` using complete projective formulas and branchless selection.
// crap:ignore
fn p256_scalar_mul(pt: P256Point, scalar: U256) -> P256Point {
    var acc = P256Projective { .. };
    var addend = p256_to_projective(pt);
    for i in 256 {
        let limb = i >> 5;
        let bit = i & 31;
        let bit_val = (scalar.v[limb] >> bit) & 1;
        let sum = p256_projective_add(acc, addend);
        acc = p256_projective_select(bit_val, sum, acc);
        addend = p256_projective_double(addend);
    }
    return p256_projective_to_affine(acc);
}

// Computes `u1 * G + u2 * Q` via Shamir's trick in complete projective coordinates with a single final inversion.
// crap:ignore
fn p256_muladd_shamir(g: P256Point, u1: U256, q: P256Point, u2: U256) -> P256Point {
    let g_proj = p256_to_projective(g);
    let q_proj = p256_to_projective(q);
    let gq_proj = p256_projective_add(g_proj, q_proj);

    var acc = P256Projective { .. };
    for i in 256 {
        let bit_idx = 255 - i;
        acc = p256_projective_double(acc);
        let limb = bit_idx >> 5;
        let bit = bit_idx & 31;
        let b1 = (u1.v[limb] >> bit) & 1;
        let b2 = (u2.v[limb] >> bit) & 1;
        if b1 == 1 && b2 == 1 {
            acc = p256_projective_add(acc, gq_proj);
        } else if b1 == 1 {
            acc = p256_projective_add(acc, g_proj);
        } else if b2 == 1 {
            acc = p256_projective_add(acc, q_proj);
        }
    }
    return p256_projective_to_affine(acc);
}

// crap:ignore
fn p256_is_on_curve(pt: P256Point) -> bool {
    guard !pt.infinity else { return false; }
    guard u256_cmp(pt.x, P256_MOD) < 0 && u256_cmp(pt.y, P256_MOD) < 0 else { return false; }
    var three = U256 { .. };
    three.v[0] = 3;
    let b_coeff = U256 { v: P256_B };
    let lhs = u256_mul_mod(pt.y, pt.y, P256_MOD);
    let x2 = u256_mul_mod(pt.x, pt.x, P256_MOD);
    let x3 = u256_mul_mod(x2, pt.x, P256_MOD);
    let three_x = u256_mul_mod(three, pt.x, P256_MOD);
    let rhs = u256_add_mod(u256_sub_mod(x3, three_x, P256_MOD), b_coeff, P256_MOD);
    return u256_cmp(lhs, rhs.v) == 0;
}

// Decodes a P-256 public key from 65-byte uncompressed SEC1 format (`0x04 || X || Y`).
//
// Example:
//   pub_key = [0x04, X(32 bytes), Y(32 bytes)]
//   returns: P256Point { x, y, infinity: false }, ok = true
// crap:ignore
fn decode_p256_public_key(pub_key: const u8[:]) -> P256Point, bool {
    guard pub_key.len == 65 && pub_key[0] == 0x04 else { return P256Point { .. }, false; }
    var x_bytes: u8[32] = [0; 32];
    var y_bytes: u8[32] = [0; 32];
    for i in 32 {
        x_bytes[i] = pub_key[1 + i];
        y_bytes[i] = pub_key[33 + i];
    }
    let pt = P256Point {
        x:        u256_from_be(x_bytes),
        y:        u256_from_be(y_bytes),
        infinity: false,
    };
    guard p256_is_on_curve(pt) else { return P256Point { .. }, false; }
    return pt, true;
}

// Extracts a fixed-width big-endian integer from an ASN.1 DER INTEGER element inside an ECDSA signature.
// Leaves `idx` unchanged on error.
//
// Example:
//   der = [0x02, 0x20, 0x11, ...], idx = 0, out_int = [0; 32]
//   returns: ok = true, idx = 34
// crap:ignore
fn parse_der_ecdsa_int(der: const u8[:], idx: i64&, out_int: u8[:]) -> bool {
    guard idx + 2 <= der.len else { return false; }
    guard der[idx] == 0x02 else { return false; }
    let int_len: i64 = der[idx + 1];
    let val_idx = idx + 2;
    guard int_len > 0 && (int_len & 0x80) == 0 && val_idx + int_len <= der.len else { return false; }
    guard (der[val_idx] & 0x80) == 0 else { return false; }
    if int_len > 1 && der[val_idx] == 0x00 && (der[val_idx + 1] & 0x80) == 0 {
        return false;
    }
    var src_off: i64 = 0;
    var rem_len = int_len;
    if rem_len > 1 && der[val_idx] == 0x00 {
        src_off = 1;
        rem_len -= 1;
    }
    guard rem_len <= out_int.len else { return false; }
    for z in out_int.len {
        out_int[z] = 0;
    }
    let pad_len = out_int.len - rem_len;
    for i in rem_len {
        out_int[pad_len + i] = der[val_idx + src_off + i];
    }
    idx = val_idx + int_len;
    return true;
}

// Decodes an ASN.1 DER-encoded P-256 ECDSA signature into a 64-byte raw `r || s` buffer.
//
// Example:
//   der_sig = [0x30, 0x44, 0x02, 0x20, R..., 0x02, 0x20, S...]
//   returns: ok = true, out_raw = R(32) || S(32)
// crap:ignore
fn ecdsa_p256_decode_der_sig(der_sig: const u8[:], out_raw: u8[64]&) -> bool {
    guard der_sig.len >= 8 && der_sig[0] == 0x30 else { return false; }
    guard (der_sig[1] & 0x80) == 0 else { return false; }
    let seq_len: i64 = der_sig[1];
    var idx: i64 = 2;
    guard idx + seq_len == der_sig.len else { return false; }
    guard parse_der_ecdsa_int(der_sig, idx, out_raw[0..32]) else { return false; }
    guard parse_der_ecdsa_int(der_sig, idx, out_raw[32..64]) else { return false; }
    guard idx == der_sig.len else { return false; }
    var r_bytes: u8[32] = [0; 32];
    var s_bytes: u8[32] = [0; 32];
    for i in 32 {
        r_bytes[i] = out_raw[i];
        s_bytes[i] = out_raw[32 + i];
    }
    let r = u256_from_be(r_bytes);
    let s = u256_from_be(s_bytes);
    return !u256_is_zero(r) && u256_cmp(r, P256_ORDER) < 0 && !u256_is_zero(s) && u256_cmp(s, P256_ORDER) < 0;
}

// Encodes a 64-byte raw `r || s` P-256 signature into ASN.1 DER `SEQUENCE { r, s }` format.
// crap:ignore
fn ecdsa_p256_encode_der_sig(raw_sig: const u8[64]&, out: u8[..72]&) -> bool {
    out.clear();
    var r_start: i64 = 0;
    while r_start < 31 && raw_sig[r_start] == 0 {
        r_start += 1;
    }
    let r_pad = (raw_sig[r_start] & 0x80) != 0;
    let r_len = (32 - r_start) + (if r_pad { 1 } else { 0 });

    var s_start: i64 = 32;
    while s_start < 63 && raw_sig[s_start] == 0 {
        s_start += 1;
    }
    let s_pad = (raw_sig[s_start] & 0x80) != 0;
    let s_len = (64 - s_start) + (if s_pad { 1 } else { 0 });

    let seq_len = 2 + r_len + 2 + s_len;
    out.push(0x30);
    out.push(seq_len as u8);
    out.push(0x02);
    out.push(r_len as u8);
    if r_pad { out.push(0x00); }
    out.append(raw_sig[r_start..32]);
    out.push(0x02);
    out.push(s_len as u8);
    if s_pad { out.push(0x00); }
    out.append(raw_sig[s_start..64]);
    return true;
}

// Derives the 65-byte uncompressed SEC1 public key (`0x04 || X || Y`) from a 32-byte P-256 private scalar.
// crap:ignore
fn ecdsa_p256_public_key(priv_key: const u8[32]&) -> u8[65] {
    var d = u256_add_mod(u256_from_be(priv_key), U256 { .. }, P256_ORDER);
    defer zeroize_u256(d);
    guard !u256_is_zero(d) else { return [0; 65]; }
    let g = P256Point {
        x:        U256 { v: P256_GX },
        y:        U256 { v: P256_GY },
        infinity: false,
    };
    let pub_pt = p256_scalar_mul(g, d);
    let xb = u256_to_be(pub_pt.x);
    let yb = u256_to_be(pub_pt.y);
    var out: u8[65] = [0; 65];
    out[0] = 0x04;
    for i in 32 {
        out[1 + i] = xb[i];
        out[33 + i] = yb[i];
    }
    return out;
}

// Computes an RFC 8446 Section 4.2.8.2 NIST P-256 (secp256r1) ECDH 32-byte shared secret
// (`X` coordinate of `d * peer_pub`). Validates `peer_pub` is on curve and rejects point at infinity.
// crap:ignore
fn p256_ecdh_shared_secret(priv_key: const u8[32]&, peer_pub: const u8[:]) -> u8[32], bool {
    defer secure_scrub_stack();
    var zero: u8[32] = [0; 32];
    let peer_pt, ok_pt = decode_p256_public_key(peer_pub);
    guard ok_pt else { return zero, false; }
    var d = u256_add_mod(u256_from_be(priv_key), U256 { .. }, P256_ORDER);
    defer zeroize_u256(d);
    guard ct_declassify_u8(u256_nonzero_bit(d) as u8) != 0 else { return zero, false; }
    let shared_pt = p256_scalar_mul(peer_pt, d);
    let finite_bit = (u256_nonzero_bit(shared_pt.x) | u256_nonzero_bit(shared_pt.y)) as u8;
    guard ct_declassify_u8(finite_bit) != 0 else { return zero, false; }
    return u256_to_be(shared_pt.x), true;
}

// Initializes the RFC 6979 §3.2 HMAC-SHA256 DRBG state (`K`, `V`) from `int2octets(x)` and `bits2octets(h1)`.
// crap:ignore
fn rfc6979_p256_init(
    x_be:     const u8[32]&,
    z_be:     const u8[32]&,
    k_hmac:   u8[32]&,
    v_hmac:   u8[32]&,
    seed_buf: u8[97]&,
) {
    v_hmac = [0x01; 32];
    k_hmac = [0x00; 32];
    ct_copy_bytes(seed_buf[0..32], v_hmac[..]);
    seed_buf[32] = 0x00;
    ct_copy_bytes(seed_buf[33..65], x_be[..]);
    ct_copy_bytes(seed_buf[65..97], z_be[..]);
    k_hmac = hmac_sha256(k_hmac[..], seed_buf[..]);
    v_hmac = hmac_sha256(k_hmac[..], v_hmac[..]);
    ct_copy_bytes(seed_buf[0..32], v_hmac[..]);
    seed_buf[32] = 0x01;
    k_hmac = hmac_sha256(k_hmac[..], seed_buf[..]);
    v_hmac = hmac_sha256(k_hmac[..], v_hmac[..]);
}

// Draws the next valid RFC 6979 §3.2 candidate scalar `k in [1, n - 1]` from the HMAC-SHA256 DRBG state.
// crap:ignore
fn rfc6979_p256_next_k(k_hmac: u8[32]&, v_hmac: u8[32]&, seed_buf: u8[97]&, retry: bool) -> U256 {
    if retry {
        for i in 32 { seed_buf[i] = v_hmac[i]; }
        seed_buf[32] = 0x00;
        k_hmac = hmac_sha256(k_hmac[..], seed_buf[..33]);
        v_hmac = hmac_sha256(k_hmac[..], v_hmac[..]);
    }
    v_hmac = hmac_sha256(k_hmac[..], v_hmac[..]);
    var k_scalar = u256_from_be(v_hmac);
    while ct_declassify_u8(u256_in_order_bit(k_scalar)) == 0 {
        for i in 32 { seed_buf[i] = v_hmac[i]; }
        seed_buf[32] = 0x00;
        k_hmac = hmac_sha256(k_hmac[..], seed_buf[..33]);
        v_hmac = hmac_sha256(k_hmac[..], v_hmac[..]);
        v_hmac = hmac_sha256(k_hmac[..], v_hmac[..]);
        k_scalar = u256_from_be(v_hmac);
    }
    return k_scalar;
}

// Deterministic RFC 6979 ECDSA P-256 SHA-256 signature generation returning 64-byte `r || s`.
// crap:ignore
fn ecdsa_p256_sign(priv_key: const u8[32]&, message: const u8[:]) -> u8[64] {
    defer secure_scrub_stack();
    var d = u256_add_mod(u256_from_be(priv_key), U256 { .. }, P256_ORDER);
    defer zeroize_u256(d);
    guard ct_declassify_u8(u256_nonzero_bit(d) as u8) != 0 else { return [0; 64]; }
    let msg_hash = sha256(message);
    let z = u256_add_mod(u256_from_be(msg_hash), U256 { .. }, P256_ORDER);
    var x_be = u256_to_be(d);
    defer secure_zeroize_32(x_be);
    let z_be = u256_to_be(z);
    var v_hmac:   u8[32] = [0; 32];
    var k_hmac:   u8[32] = [0; 32];
    var seed_buf: u8[97] = [0; 97];
    defer secure_zeroize_32(v_hmac);
    defer secure_zeroize_32(k_hmac);
    defer secure_zeroize_slice(seed_buf[..]);
    rfc6979_p256_init(x_be, z_be, k_hmac, v_hmac, seed_buf);

    let g = P256Point { x: U256 { v: P256_GX }, y: U256 { v: P256_GY }, infinity: false };
    var r_val = U256 { .. };
    var s_val = U256 { .. };
    var k_scalar = U256 { .. };
    var k_inv = U256 { .. };
    var rd = U256 { .. };
    var z_plus_rd = U256 { .. };
    defer zeroize_u256(k_scalar);
    defer zeroize_u256(k_inv);
    defer zeroize_u256(rd);
    defer zeroize_u256(z_plus_rd);
    var retry = false;
    while ct_declassify_u8((u256_nonzero_bit(r_val) & u256_nonzero_bit(s_val)) as u8) == 0 {
        k_scalar = rfc6979_p256_next_k(k_hmac, v_hmac, seed_buf, retry);
        retry = true;
        let r_pt = p256_scalar_mul(g, k_scalar);
        r_val = u256_add_mod(r_pt.x, U256 { .. }, P256_ORDER);
        k_inv = u256_inv_mod(k_scalar, P256_ORDER);
        rd = u256_mul_mod(r_val, d, P256_ORDER);
        z_plus_rd = u256_add_mod(z, rd, P256_ORDER);
        s_val = u256_mul_mod(k_inv, z_plus_rd, P256_ORDER);
    }

    let r_be = u256_to_be(r_val);
    let s_be = u256_to_be(s_val);
    var sig: u8[64] = [0; 64];
    for i in 32 {
        sig[i] = r_be[i];
        sig[32 + i] = s_be[i];
    }
    return sig;
}

// Verifies a decoded 64-byte `r || s` P-256 signature against affine public point `q_pt` and reduced hash `z`.
// crap:ignore
fn ecdsa_p256_verify_raw_pt(q_pt: P256Point, z: U256, raw_sig: const u8[64]&) -> bool {
    var r_bytes: u8[32] = [0; 32];
    var s_bytes: u8[32] = [0; 32];
    for i in 32 {
        r_bytes[i] = raw_sig[i];
        s_bytes[i] = raw_sig[32 + i];
    }
    let r = u256_from_be(r_bytes);
    let s = u256_from_be(s_bytes);
    guard !u256_is_zero(r) && u256_cmp(r, P256_ORDER) < 0 else { return false; }
    guard !u256_is_zero(s) && u256_cmp(s, P256_ORDER) < 0 else { return false; }

    let w = u256_inv_mod(s, P256_ORDER);
    let u1 = u256_mul_mod(z, w, P256_ORDER);
    let u2 = u256_mul_mod(r, w, P256_ORDER);

    let g = P256Point {
        x:        U256 { v: P256_GX },
        y:        U256 { v: P256_GY },
        infinity: false,
    };
    let pt = p256_muladd_shamir(g, u1, q_pt, u2);
    guard !pt.infinity else { return false; }

    var v = pt.x;
    if u256_cmp(v, P256_ORDER) >= 0 {
        let ord = U256 { v: P256_ORDER };
        v = u256_sub_mod(v, ord, P256_ORDER);
    }
    return u256_cmp(v, r.v) == 0;
}

// Verifies an ASN.1 DER-encoded ECDSA P-256 SHA-256 signature (`SEQUENCE { r, s }`).
// crap:ignore
fn ecdsa_p256_verify_der(pub_key: const u8[:], message: const u8[:], sig: const u8[:]) -> bool {
    guard sig.len >= 8 && sig[0] == 0x30 else { return false; }
    var der_raw: u8[64] = [0; 64];
    guard ecdsa_p256_decode_der_sig(sig, der_raw) else { return false; }
    let q_pt, pub_ok = decode_p256_public_key(pub_key);
    guard pub_ok else { return false; }
    let msg_hash = sha256(message);
    var z = u256_from_be(msg_hash);
    if u256_cmp(z, P256_ORDER) >= 0 {
        let ord = U256 { v: P256_ORDER };
        z = u256_sub_mod(z, ord, P256_ORDER);
    }
    return ecdsa_p256_verify_raw_pt(q_pt, z, der_raw);
}

// Verifies a fixed-width 64-byte IEEE P1363 (`r || s`) ECDSA P-256 SHA-256 signature.
// crap:ignore
fn ecdsa_p256_verify_p1363(pub_key: const u8[:], message: const u8[:], sig: const u8[:]) -> bool {
    guard sig.len == 64 else { return false; }
    let q_pt, pub_ok = decode_p256_public_key(pub_key);
    guard pub_ok else { return false; }
    let msg_hash = sha256(message);
    var z = u256_from_be(msg_hash);
    if u256_cmp(z, P256_ORDER) >= 0 {
        let ord = U256 { v: P256_ORDER };
        z = u256_sub_mod(z, ord, P256_ORDER);
    }
    var p1363_raw: u8[64] = [0; 64];
    for i in 64 {
        p1363_raw[i] = sig[i];
    }
    return ecdsa_p256_verify_raw_pt(q_pt, z, p1363_raw);
}

// Verifies an ECDSA P-256 SHA-256 signature (accepts 64-byte raw `r || s` or ASN.1 DER `SEQUENCE { r, s }`).
// crap:ignore
fn ecdsa_p256_verify(pub_key: const u8[:], message: const u8[:], sig: const u8[:]) -> bool {
    if ecdsa_p256_verify_der(pub_key, message, sig) {
        return true;
    }
    return ecdsa_p256_verify_p1363(pub_key, message, sig);
}

// ---- NIST P-384 (secp384r1) 12-Limb 32-bit Representation ----------------

struct U384 {
    v: u32[12] = [0; 12],
}

// p = 2^384 - 2^128 - 2^96 + 2^32 - 1
const P384_MOD: const u32[12] = [
    0xFFFFFFFF, 0x00000000, 0x00000000, 0xFFFFFFFF,
    0xFFFFFFFE, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF,
    0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF,
];

// n = FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFC7634D81F4372DDF581A0DB248B0A77AECEC196ACCC52973
const P384_ORDER: const u32[12] = [
    0xCCC52973, 0xECEC196A, 0x48B0A77A, 0x581A0DB2,
    0xF4372DDF, 0xC7634D81, 0xFFFFFFFF, 0xFFFFFFFF,
    0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF,
];

const P384_GX: const u32[12] = [
    0x72760AB7, 0x3A545E38, 0xBF55296C, 0x5502F25D,
    0x82542A38, 0x59F741E0, 0x8BA79B98, 0x6E1D3B62,
    0xF320AD74, 0x8EB1C71E, 0xBE8B0537, 0xAA87CA22,
];

const P384_GY: const u32[12] = [
    0x90EA0E5F, 0x7A431D7C, 0x1D7E819D, 0x0A60B1CE,
    0xB5F0B8C0, 0xE9DA3113, 0x289A147C, 0xF8F41DBD,
    0x9292DC29, 0x5D9E98BF, 0x96262C6F, 0x3617DE4A,
];

const P384_B: const u32[12] = [
    0xD3EC2AEF, 0x2A85C8ED, 0x8A2ED19D, 0xC656398D,
    0x5013875A, 0x0314088F, 0xFE814112, 0x181D9C6E,
    0xE3F82D19, 0x988E056B, 0xE23EE7E4, 0xB3312FA7,
];

// crap:ignore
inline fn u384_is_zero(a: U384) -> bool {
    var acc: u32 = 0;
    for i in 12 {
        acc |= a.v[i];
    }
    return acc == 0;
}

// Branchless 384-bit limb subtraction returning `(a - b, borrow)` where `borrow` is 0 or 1.
// crap:ignore
inline fn u384_sub_borrow(a: U384, b: const u32[12]&) -> U384, u64 {
    var diff = U384 { .. };
    var borrow: u64 = 0;
    for i in 12 {
        let d = (a.v[i] as u64) - b[i] - borrow;
        diff.v[i] = (d & 0xFFFFFFFF) as u32;
        borrow = d >> 63;
    }
    return diff, borrow;
}

// Branchless nonzero predicate returning 1 if `a != 0`, else 0.
// crap:ignore
inline fn u384_nonzero_bit(a: U384) -> i32 {
    var acc: u32 = 0;
    for i in 12 { acc |= a.v[i]; }
    return ((acc | (0 - acc)) >> 31) as i32;
}

// Branchless predicate returning 1 if `1 <= a < P384_ORDER`, else 0.
// crap:ignore
inline fn u384_in_order_bit(a: U384) -> u8 {
    let _, borrow = u384_sub_borrow(a, P384_ORDER);
    return ((u384_nonzero_bit(a) as u32) & (borrow as u32)) as u8;
}

// Branchless constant-time 384-bit comparison: returns -1 if a < b, 0 if a == b, 1 if a > b.
// crap:ignore
inline fn u384_cmp(a: U384, b: const u32[12]&) -> i32 {
    let diff, borrow = u384_sub_borrow(a, b);
    let nz = u384_nonzero_bit(diff);
    let lt = borrow as i32;
    let gt = nz & (1 ^ lt);
    return gt - lt;
}

// crap:ignore
inline fn u384_from_be(bytes: const u8[48]&) -> U384 {
    var out = U384 { .. };
    for i in 12 {
        let off = (11 - i) * 4;
        out.v[i] = ((bytes[off] as u32) << 24) |
                   ((bytes[off + 1] as u32) << 16) |
                   ((bytes[off + 2] as u32) << 8) |
                   bytes[off + 3];
    }
    return out;
}

// crap:ignore
inline fn u384_to_be(a: U384) -> u8[48] {
    var out: u8[48] = [0; 48];
    for i in 12 {
        let off = (11 - i) * 4;
        let w = a.v[i];
        out[off] = ((w >> 24) & 0xFF) as u8;
        out[off + 1] = ((w >> 16) & 0xFF) as u8;
        out[off + 2] = ((w >> 8) & 0xFF) as u8;
        out[off + 3] = (w & 0xFF) as u8;
    }
    return out;
}

// Branchless constant-time modular addition: `(a + b) mod m`.
// crap:ignore
fn u384_add_mod(a: U384, b: U384, m: const u32[12]&) -> U384 {
    var sum = U384 { .. };
    var carry: u64 = 0;
    for i in 12 {
        let s = (a.v[i] as u64) + b.v[i] + carry;
        sum.v[i] = (s & 0xFFFFFFFF) as u32;
        carry = s >> 32;
    }
    let diff, borrow = u384_sub_borrow(sum, m);
    let do_sub = ((carry | (1 ^ borrow)) & 1) as u32;
    return u384_select(do_sub, diff, sum);
}

// Branchless constant-time modular subtraction: `(a - b) mod m`.
// crap:ignore
fn u384_sub_mod(a: U384, b: U384, m: const u32[12]&) -> U384 {
    let diff, borrow = u384_sub_borrow(a, b.v);
    var sum = U384 { .. };
    var carry: u64 = 0;
    for i in 12 {
        let s = (diff.v[i] as u64) + m[i] + carry;
        sum.v[i] = (s & 0xFFFFFFFF) as u32;
        carry = s >> 32;
    }
    return u384_select(borrow as u32, sum, diff);
}

// Constant-time 384-bit integer selection.
// crap:ignore
inline fn u384_select(bit: u32, if_true: U384, if_false: U384) -> U384 {
    let mask = ct_barrier_u32(0 - (bit & 1));
    var out = U384 { .. };
    for i in 12 {
        out.v[i] = (if_false.v[i] & (~mask)) | (if_true.v[i] & mask);
    }
    return out;
}

// Zeroizes a 384-bit secret scalar in place.
// crap:ignore
inline fn zeroize_u384(val: U384&) {
    var z_bytes: u8[48] = [0; 48];
    secure_zeroize_48(z_bytes);
    val = u384_from_be(z_bytes);
}

// 32-bit CIOS Montgomery multiplication step on 12-limb U384: `(a * b * R^-1) mod m` where `R = 2^384`.
// crap:ignore
fn u384_monty_mul(a: U384, b: U384, m: const u32[12]&, m0i: u32) -> U384 {
    var t: u32[14] = [0; 14];
    for i in 12 {
        var carry1: u64 = 0;
        let ai = a.v[i] as u64;
        for j in 12 {
            let prod = ai * b.v[j] + t[j] + carry1;
            t[j] = (prod & 0xFFFFFFFF) as u32;
            carry1 = prod >> 32;
        }
        let sum1 = t[12] + carry1;
        t[12] = (sum1 & 0xFFFFFFFF) as u32;
        t[13] = (sum1 >> 32) as u32;

        let q = (t[0] * m0i) as u64;
        var carry2: u64 = (q * m[0] + t[0]) >> 32;
        var j:      i64 = 1;
        while j < 12 {
            let prod = q * m[j] + t[j] + carry2;
            t[j - 1] = (prod & 0xFFFFFFFF) as u32;
            carry2 = prod >> 32;
            j += 1;
        }
        let sum2 = t[12] + carry2;
        t[11] = (sum2 & 0xFFFFFFFF) as u32;
        let top_carry = (sum2 >> 32) + t[13];
        t[12] = (top_carry & 0xFFFFFFFF) as u32;
        t[13] = 0;
    }
    var out = U384 { .. };
    var diff = U384 { .. };
    var borrow: u64 = 0;
    for j in 12 {
        out.v[j] = t[j];
        let d = (t[j] as u64) - m[j] - borrow;
        diff.v[j] = (d & 0xFFFFFFFF) as u32;
        borrow = d >> 63;
    }
    let has_carry = ((t[12] | (0 - t[12])) >> 31) as u64;
    let do_sub = ((has_carry | (1 - borrow)) & 1) as u32;
    return u384_select(do_sub, diff, out);
}

// Fast 12x12 limb Montgomery modular multiplication: `(a * b) mod m`.
// Uses precomputed `R^2 mod m` and `-m[0]^-1 mod 2^32` for P-384 prime and group order.
// crap:ignore
fn u384_mul_mod(a: U384, b: U384, m: const u32[12]&) -> U384 {
    if m[0] == 0xFFFFFFFF {
        let r2_p = U384 {
            v: [
                0x00000001, 0xFFFFFFFE, 0x00000000, 0x00000002,
                0x00000000, 0xFFFFFFFE, 0x00000000, 0x00000002,
                0x00000001, 0x00000000, 0x00000000, 0x00000000,
            ],
        };
        let a_mont = u384_monty_mul(a, r2_p, m, 1);
        return u384_monty_mul(a_mont, b, m, 1);
    }
    if m[0] == 0xCCC52973 {
        let r2_n = U384 {
            v: [
                0x19B409A9, 0x2D319B24, 0xDF1AA419, 0xFF3D81E5,
                0xFCB82947, 0xBC3E483A, 0x4AAB1CC5, 0xD40D4917,
                0x28266895, 0x3FB05B7A, 0x2B39BF21, 0x0C84EE01,
            ],
        };
        let a_mont = u384_monty_mul(a, r2_n, m, 0xE88FDC45);
        return u384_monty_mul(a_mont, b, m, 0xE88FDC45);
    }
    var res = U384 { .. };
    var cur = a;
    for i in 384 {
        let limb = i >> 5;
        let bit = i & 31;
        let bit_val = (b.v[limb] >> bit) & 1;
        let next_res = u384_add_mod(res, cur, m);
        res = u384_select(bit_val, next_res, res);
        cur = u384_add_mod(cur, cur, m);
    }
    return res;
}

// crap:ignore
fn u384_inv_mod(a: U384, m: const u32[12]&) -> U384 {
    var exp = U384 { .. };
    var borrow: u64 = 2;
    for i in 12 {
        let d = m[i] - borrow;
        exp.v[i] = (d & 0xFFFFFFFF) as u32;
        borrow = d >> 63;
    }
    var res = U384 { .. };
    res.v[0] = 1;
    var base = a;
    defer zeroize_u384(base);
    for i in 384 {
        let limb = i >> 5;
        let bit = i & 31;
        let bit_val = (exp.v[limb] >> bit) & 1;
        let prod = u384_mul_mod(res, base, m);
        res = u384_select(bit_val, prod, res);
        base = u384_mul_mod(base, base, m);
    }
    return res;
}

struct P384Point {
    x:        U384 = U384 { .. },
    y:        U384 = U384 { .. },
    infinity: bool = true,
}

// Homogeneous projective P-384 point `(X : Y : Z)` representing affine `(X/Z, Y/Z)`; infinity is `(0 : 1 : 0)`.
struct P384Projective {
    x: U384 = U384 { .. },
    y: U384 = U384 { v: [1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] },
    z: U384 = U384 { .. },
}

// Constant-time P-384 projective point selection.
// crap:ignore
inline fn p384_projective_select(bit: u32, if_true: P384Projective, if_false: P384Projective) -> P384Projective {
    return P384Projective {
        x: u384_select(bit, if_true.x, if_false.x),
        y: u384_select(bit, if_true.y, if_false.y),
        z: u384_select(bit, if_true.z, if_false.z),
    };
}

// Branchless conversion from affine P-384 point to homogeneous projective `(X : Y : Z)`.
// crap:ignore
inline fn p384_to_projective(pt: P384Point) -> P384Projective {
    let inf: u32 = if pt.infinity { 1 } else { 0 };
    let zero = U384 { .. };
    let one = U384 { v: [1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] };
    return P384Projective {
        x: u384_select(inf, zero, pt.x),
        y: u384_select(inf, one, pt.y),
        z: u384_select(inf, zero, one),
    };
}

// Complete exception-free doubling for a = -3 prime-order curves (Renes-Costello-Batina 2015, Algorithm 6).
// Zero branches; handles O = (0 : Y : 0) and all finite points uniformly.
// crap:ignore
fn p384_projective_double(pt: P384Projective) -> P384Projective {
    let b_coeff = U384 { v: P384_B };
    var t0 = u384_mul_mod(pt.x, pt.x, P384_MOD);
    let t1 = u384_mul_mod(pt.y, pt.y, P384_MOD);
    var t2 = u384_mul_mod(pt.z, pt.z, P384_MOD);
    var t3 = u384_mul_mod(pt.x, pt.y, P384_MOD);
    t3 = u384_add_mod(t3, t3, P384_MOD);
    var z3 = u384_mul_mod(pt.x, pt.z, P384_MOD);
    z3 = u384_add_mod(z3, z3, P384_MOD);
    var y3 = u384_sub_mod(u384_mul_mod(b_coeff, t2, P384_MOD), z3, P384_MOD);
    var x3 = u384_add_mod(y3, y3, P384_MOD);
    y3 = u384_add_mod(x3, y3, P384_MOD);
    x3 = u384_sub_mod(t1, y3, P384_MOD);
    y3 = u384_mul_mod(x3, u384_add_mod(t1, y3, P384_MOD), P384_MOD);
    x3 = u384_mul_mod(x3, t3, P384_MOD);
    t3 = u384_add_mod(t2, t2, P384_MOD);
    t2 = u384_add_mod(t2, t3, P384_MOD);
    z3 = u384_sub_mod(u384_sub_mod(u384_mul_mod(b_coeff, z3, P384_MOD), t2, P384_MOD), t0, P384_MOD);
    t3 = u384_add_mod(z3, z3, P384_MOD);
    z3 = u384_add_mod(z3, t3, P384_MOD);
    t3 = u384_add_mod(t0, t0, P384_MOD);
    t0 = u384_mul_mod(u384_sub_mod(u384_add_mod(t3, t0, P384_MOD), t2, P384_MOD), z3, P384_MOD);
    y3 = u384_add_mod(y3, t0, P384_MOD);
    t0 = u384_mul_mod(pt.y, pt.z, P384_MOD);
    t0 = u384_add_mod(t0, t0, P384_MOD);
    x3 = u384_sub_mod(x3, u384_mul_mod(t0, z3, P384_MOD), P384_MOD);
    z3 = u384_mul_mod(t0, t1, P384_MOD);
    z3 = u384_add_mod(z3, z3, P384_MOD);
    z3 = u384_add_mod(z3, z3, P384_MOD);
    return P384Projective { x: x3, y: y3, z: z3 };
}

// Complete exception-free addition for a = -3 prime-order curves (Renes-Costello-Batina 2015, Algorithm 4).
// Zero branches; handles O + P, P + O, P + P, and P + (-P) uniformly in constant time.
// crap:ignore
fn p384_projective_add(p1: P384Projective, p2: P384Projective) -> P384Projective {
    let b_coeff = U384 { v: P384_B };
    var t0 = u384_mul_mod(p1.x, p2.x, P384_MOD);
    var t1 = u384_mul_mod(p1.y, p2.y, P384_MOD);
    var t2 = u384_mul_mod(p1.z, p2.z, P384_MOD);
    var t3 = u384_mul_mod(u384_add_mod(p1.x, p1.y, P384_MOD), u384_add_mod(p2.x, p2.y, P384_MOD), P384_MOD);
    t3 = u384_sub_mod(t3, u384_add_mod(t0, t1, P384_MOD), P384_MOD);
    var t4 = u384_mul_mod(u384_add_mod(p1.y, p1.z, P384_MOD), u384_add_mod(p2.y, p2.z, P384_MOD), P384_MOD);
    t4 = u384_sub_mod(t4, u384_add_mod(t1, t2, P384_MOD), P384_MOD);
    var x3 = u384_mul_mod(u384_add_mod(p1.x, p1.z, P384_MOD), u384_add_mod(p2.x, p2.z, P384_MOD), P384_MOD);
    var y3 = u384_sub_mod(x3, u384_add_mod(t0, t2, P384_MOD), P384_MOD);
    var z3 = u384_mul_mod(b_coeff, t2, P384_MOD);
    x3 = u384_sub_mod(y3, z3, P384_MOD);
    z3 = u384_add_mod(x3, x3, P384_MOD);
    x3 = u384_add_mod(x3, z3, P384_MOD);
    z3 = u384_sub_mod(t1, x3, P384_MOD);
    x3 = u384_add_mod(t1, x3, P384_MOD);
    y3 = u384_mul_mod(b_coeff, y3, P384_MOD);
    t1 = u384_add_mod(t2, t2, P384_MOD);
    t2 = u384_add_mod(t1, t2, P384_MOD);
    y3 = u384_sub_mod(u384_sub_mod(y3, t2, P384_MOD), t0, P384_MOD);
    t1 = u384_add_mod(y3, y3, P384_MOD);
    y3 = u384_add_mod(t1, y3, P384_MOD);
    t1 = u384_add_mod(t0, t0, P384_MOD);
    t0 = u384_sub_mod(u384_add_mod(t1, t0, P384_MOD), t2, P384_MOD);
    t1 = u384_mul_mod(t4, y3, P384_MOD);
    t2 = u384_mul_mod(t0, y3, P384_MOD);
    y3 = u384_add_mod(u384_mul_mod(x3, z3, P384_MOD), t2, P384_MOD);
    x3 = u384_sub_mod(u384_mul_mod(t3, x3, P384_MOD), t1, P384_MOD);
    z3 = u384_add_mod(u384_mul_mod(t4, z3, P384_MOD), u384_mul_mod(t3, t0, P384_MOD), P384_MOD);
    return P384Projective { x: x3, y: y3, z: z3 };
}

// Converts a homogeneous projective P-384 point `(X : Y : Z)` to affine `(X / Z, Y / Z)`.
// crap:ignore
fn p384_projective_to_affine(pt: P384Projective) -> P384Point {
    let z_zero_bit = (1 ^ u384_nonzero_bit(pt.z)) as u32;
    let z_inv = u384_inv_mod(pt.z, P384_MOD);
    let x = u384_mul_mod(pt.x, z_inv, P384_MOD);
    let y = u384_mul_mod(pt.y, z_inv, P384_MOD);
    let zero = U384 { .. };
    return P384Point {
        x:        u384_select(z_zero_bit, zero, x),
        y:        u384_select(z_zero_bit, zero, y),
        infinity: z_zero_bit != 0,
    };
}

// crap:ignore
fn p384_point_double(pt: P384Point) -> P384Point {
    return p384_projective_to_affine(p384_projective_double(p384_to_projective(pt)));
}

// crap:ignore
fn p384_point_add(p1: P384Point, p2: P384Point) -> P384Point {
    return p384_projective_to_affine(p384_projective_add(p384_to_projective(p1), p384_to_projective(p2)));
}

// Constant-time scalar multiplication: `[scalar] * pt` using complete projective formulas and branchless selection.
// crap:ignore
fn p384_scalar_mul(pt: P384Point, scalar: U384) -> P384Point {
    var acc = P384Projective { .. };
    var addend = p384_to_projective(pt);
    for i in 384 {
        let limb = i >> 5;
        let bit = i & 31;
        let bit_val = (scalar.v[limb] >> bit) & 1;
        let sum = p384_projective_add(acc, addend);
        acc = p384_projective_select(bit_val, sum, acc);
        addend = p384_projective_double(addend);
    }
    return p384_projective_to_affine(acc);
}

// Computes `u1 * G + u2 * Q` via Shamir's trick in complete projective coordinates with a single final inversion.
// crap:ignore
fn p384_muladd_shamir(g: P384Point, u1: U384, q: P384Point, u2: U384) -> P384Point {
    let g_proj = p384_to_projective(g);
    let q_proj = p384_to_projective(q);
    let gq_proj = p384_projective_add(g_proj, q_proj);

    var acc = P384Projective { .. };
    for i in 384 {
        let bit_idx = 383 - i;
        acc = p384_projective_double(acc);
        let limb = bit_idx >> 5;
        let bit = bit_idx & 31;
        let b1 = (u1.v[limb] >> bit) & 1;
        let b2 = (u2.v[limb] >> bit) & 1;
        if b1 == 1 && b2 == 1 {
            acc = p384_projective_add(acc, gq_proj);
        } else if b1 == 1 {
            acc = p384_projective_add(acc, g_proj);
        } else if b2 == 1 {
            acc = p384_projective_add(acc, q_proj);
        }
    }
    return p384_projective_to_affine(acc);
}

// crap:ignore
fn p384_is_on_curve(pt: P384Point) -> bool {
    guard !pt.infinity else { return false; }
    guard u384_cmp(pt.x, P384_MOD) < 0 && u384_cmp(pt.y, P384_MOD) < 0 else { return false; }
    var three = U384 { .. };
    three.v[0] = 3;
    let b_coeff = U384 { v: P384_B };
    let lhs = u384_mul_mod(pt.y, pt.y, P384_MOD);
    let x2 = u384_mul_mod(pt.x, pt.x, P384_MOD);
    let x3 = u384_mul_mod(x2, pt.x, P384_MOD);
    let three_x = u384_mul_mod(three, pt.x, P384_MOD);
    let rhs = u384_add_mod(u384_sub_mod(x3, three_x, P384_MOD), b_coeff, P384_MOD);
    return u384_cmp(lhs, rhs.v) == 0;
}

// Decodes a P-384 public key from 97-byte uncompressed SEC1 format (`0x04 || X || Y`).
//
// Example:
//   pub_key = [0x04, X(48 bytes), Y(48 bytes)]
//   returns: P384Point { x, y, infinity: false }, ok = true
// crap:ignore
fn decode_p384_public_key(pub_key: const u8[:]) -> P384Point, bool {
    guard pub_key.len == 97 && pub_key[0] == 0x04 else { return P384Point { .. }, false; }
    var x_bytes: u8[48] = [0; 48];
    var y_bytes: u8[48] = [0; 48];
    for i in 48 {
        x_bytes[i] = pub_key[1 + i];
        y_bytes[i] = pub_key[49 + i];
    }
    let pt = P384Point {
        x:        u384_from_be(x_bytes),
        y:        u384_from_be(y_bytes),
        infinity: false,
    };
    guard p384_is_on_curve(pt) else { return P384Point { .. }, false; }
    return pt, true;
}

// Decodes an ASN.1 DER-encoded P-384 ECDSA signature into a 96-byte raw `r || s` buffer.
//
// Example:
//   der_sig = [0x30, 0x64, 0x02, 0x30, R..., 0x02, 0x30, S...]
//   returns: ok = true, out_raw = R(48) || S(48)
// crap:ignore
fn ecdsa_p384_decode_der_sig(der_sig: const u8[:], out_raw: u8[96]&) -> bool {
    guard der_sig.len >= 8 && der_sig[0] == 0x30 else { return false; }
    guard (der_sig[1] & 0x80) == 0 else { return false; }
    let seq_len: i64 = der_sig[1];
    var idx: i64 = 2;
    guard idx + seq_len == der_sig.len else { return false; }
    guard parse_der_ecdsa_int(der_sig, idx, out_raw[0..48]) else { return false; }
    guard parse_der_ecdsa_int(der_sig, idx, out_raw[48..96]) else { return false; }
    guard idx == der_sig.len else { return false; }
    var r_bytes: u8[48] = [0; 48];
    var s_bytes: u8[48] = [0; 48];
    for i in 48 {
        r_bytes[i] = out_raw[i];
        s_bytes[i] = out_raw[48 + i];
    }
    let r = u384_from_be(r_bytes);
    let s = u384_from_be(s_bytes);
    return !u384_is_zero(r) && u384_cmp(r, P384_ORDER) < 0 && !u384_is_zero(s) && u384_cmp(s, P384_ORDER) < 0;
}

// Derives the 97-byte uncompressed SEC1 public key (`0x04 || X || Y`) from a 48-byte P-384 private scalar.
// crap:ignore
fn ecdsa_p384_public_key(priv_key: const u8[48]&) -> u8[97] {
    var d = u384_add_mod(u384_from_be(priv_key), U384 { .. }, P384_ORDER);
    defer zeroize_u384(d);
    guard !u384_is_zero(d) else { return [0; 97]; }
    let g = P384Point {
        x:        U384 { v: P384_GX },
        y:        U384 { v: P384_GY },
        infinity: false,
    };
    let pub_pt = p384_scalar_mul(g, d);
    let xb = u384_to_be(pub_pt.x);
    let yb = u384_to_be(pub_pt.y);
    var out: u8[97] = [0; 97];
    out[0] = 0x04;
    for i in 48 {
        out[1 + i] = xb[i];
        out[49 + i] = yb[i];
    }
    return out;
}

// Initializes the RFC 6979 §3.2 HMAC-SHA384 DRBG state (`K`, `V`) from `int2octets(x)` and `bits2octets(h1)`.
// crap:ignore
fn rfc6979_p384_init(
    x_be:     const u8[48]&,
    z_be:     const u8[48]&,
    k_hmac:   u8[48]&,
    v_hmac:   u8[48]&,
    seed_buf: u8[145]&,
) {
    v_hmac = [0x01; 48];
    k_hmac = [0x00; 48];
    ct_copy_bytes(seed_buf[0..48], v_hmac[..]);
    seed_buf[48] = 0x00;
    ct_copy_bytes(seed_buf[49..97], x_be[..]);
    ct_copy_bytes(seed_buf[97..145], z_be[..]);
    k_hmac = hmac_sha384(k_hmac[..], seed_buf[..]);
    v_hmac = hmac_sha384(k_hmac[..], v_hmac[..]);
    ct_copy_bytes(seed_buf[0..48], v_hmac[..]);
    seed_buf[48] = 0x01;
    k_hmac = hmac_sha384(k_hmac[..], seed_buf[..]);
    v_hmac = hmac_sha384(k_hmac[..], v_hmac[..]);
}

// Draws the next valid RFC 6979 §3.2 candidate scalar `k in [1, n - 1]` from the HMAC-SHA384 DRBG state.
// crap:ignore
fn rfc6979_p384_next_k(k_hmac: u8[48]&, v_hmac: u8[48]&, seed_buf: u8[145]&, retry: bool) -> U384 {
    if retry {
        for i in 48 { seed_buf[i] = v_hmac[i]; }
        seed_buf[48] = 0x00;
        k_hmac = hmac_sha384(k_hmac[..], seed_buf[..49]);
        v_hmac = hmac_sha384(k_hmac[..], v_hmac[..]);
    }
    v_hmac = hmac_sha384(k_hmac[..], v_hmac[..]);
    var k_scalar = u384_from_be(v_hmac);
    while ct_declassify_u8(u384_in_order_bit(k_scalar)) == 0 {
        for i in 48 { seed_buf[i] = v_hmac[i]; }
        seed_buf[48] = 0x00;
        k_hmac = hmac_sha384(k_hmac[..], seed_buf[..49]);
        v_hmac = hmac_sha384(k_hmac[..], v_hmac[..]);
        v_hmac = hmac_sha384(k_hmac[..], v_hmac[..]);
        k_scalar = u384_from_be(v_hmac);
    }
    return k_scalar;
}

// Deterministic RFC 6979 ECDSA P-384 SHA-384 signature generation returning 96-byte `r || s`.
// crap:ignore
fn ecdsa_p384_sign(priv_key: const u8[48]&, message: const u8[:]) -> u8[96] {
    defer secure_scrub_stack();
    var d = u384_add_mod(u384_from_be(priv_key), U384 { .. }, P384_ORDER);
    defer zeroize_u384(d);
    guard ct_declassify_u8(u384_nonzero_bit(d) as u8) != 0 else { return [0; 96]; }
    let msg_hash = sha384(message);
    let z = u384_add_mod(u384_from_be(msg_hash), U384 { .. }, P384_ORDER);
    var x_be = u384_to_be(d);
    defer secure_zeroize_48(x_be);
    let z_be = u384_to_be(z);
    var v_hmac:   u8[48]  = [0; 48];
    var k_hmac:   u8[48]  = [0; 48];
    var seed_buf: u8[145] = [0; 145];
    defer secure_zeroize_48(v_hmac);
    defer secure_zeroize_48(k_hmac);
    defer secure_zeroize_slice(seed_buf[..]);
    rfc6979_p384_init(x_be, z_be, k_hmac, v_hmac, seed_buf);

    let g = P384Point { x: U384 { v: P384_GX }, y: U384 { v: P384_GY }, infinity: false };
    var r_val = U384 { .. };
    var s_val = U384 { .. };
    var k_scalar = U384 { .. };
    var k_inv = U384 { .. };
    var rd = U384 { .. };
    var z_plus_rd = U384 { .. };
    defer zeroize_u384(k_scalar);
    defer zeroize_u384(k_inv);
    defer zeroize_u384(rd);
    defer zeroize_u384(z_plus_rd);
    var retry = false;
    while ct_declassify_u8((u384_nonzero_bit(r_val) & u384_nonzero_bit(s_val)) as u8) == 0 {
        k_scalar = rfc6979_p384_next_k(k_hmac, v_hmac, seed_buf, retry);
        retry = true;
        let r_pt = p384_scalar_mul(g, k_scalar);
        r_val = u384_add_mod(r_pt.x, U384 { .. }, P384_ORDER);
        k_inv = u384_inv_mod(k_scalar, P384_ORDER);
        rd = u384_mul_mod(r_val, d, P384_ORDER);
        z_plus_rd = u384_add_mod(z, rd, P384_ORDER);
        s_val = u384_mul_mod(k_inv, z_plus_rd, P384_ORDER);
    }

    let r_be = u384_to_be(r_val);
    let s_be = u384_to_be(s_val);
    var sig: u8[96] = [0; 96];
    for i in 48 {
        sig[i] = r_be[i];
        sig[48 + i] = s_be[i];
    }
    return sig;
}

// Derives a 97-byte uncompressed SEC1 NIST P-384 (secp384r1) public key (`0x04 || X || Y`).
// Returns `(zero, false)` when `priv_key == 0 mod n` instead of silently substituting `d = 1`.
// crap:ignore
fn p384_ecdh_public_key(priv_key: const u8[48]&) -> u8[97], bool {
    var out: u8[97] = [0; 97];
    var d = u384_add_mod(u384_from_be(priv_key), U384 { .. }, P384_ORDER);
    defer zeroize_u384(d);
    guard !u384_is_zero(d) else { return out, false; }
    let g = P384Point { x: U384 { v: P384_GX }, y: U384 { v: P384_GY }, infinity: false };
    let pub_pt = p384_scalar_mul(g, d);
    let xb = u384_to_be(pub_pt.x);
    let yb = u384_to_be(pub_pt.y);
    out[0] = 0x04;
    for i in 48 {
        out[1 + i] = xb[i];
        out[49 + i] = yb[i];
    }
    return out, true;
}

// Computes an RFC 8446 Section 4.2.8.2 NIST P-384 (secp384r1) ECDH 48-byte shared secret.
// crap:ignore
fn p384_ecdh_shared_secret(priv_key: const u8[48]&, peer_pub: const u8[:]) -> u8[48], bool {
    defer secure_scrub_stack();
    var zero: u8[48] = [0; 48];
    let peer_pt, ok_pt = decode_p384_public_key(peer_pub);
    guard ok_pt else { return zero, false; }
    var d = u384_add_mod(u384_from_be(priv_key), U384 { .. }, P384_ORDER);
    defer zeroize_u384(d);
    guard ct_declassify_u8(u384_nonzero_bit(d) as u8) != 0 else { return zero, false; }
    let shared_pt = p384_scalar_mul(peer_pt, d);
    let finite_bit = (u384_nonzero_bit(shared_pt.x) | u384_nonzero_bit(shared_pt.y)) as u8;
    guard ct_declassify_u8(finite_bit) != 0 else { return zero, false; }
    return u384_to_be(shared_pt.x), true;
}

// Verifies a decoded 96-byte `r || s` P-384 signature against affine public point `q_pt` and reduced hash `z`.
// crap:ignore
fn ecdsa_p384_verify_raw_pt(q_pt: P384Point, z: U384, raw_sig: const u8[96]&) -> bool {
    var r_bytes: u8[48] = [0; 48];
    var s_bytes: u8[48] = [0; 48];
    for i in 48 {
        r_bytes[i] = raw_sig[i];
        s_bytes[i] = raw_sig[48 + i];
    }
    let r = u384_from_be(r_bytes);
    let s = u384_from_be(s_bytes);
    guard !u384_is_zero(r) && u384_cmp(r, P384_ORDER) < 0 else { return false; }
    guard !u384_is_zero(s) && u384_cmp(s, P384_ORDER) < 0 else { return false; }

    let w = u384_inv_mod(s, P384_ORDER);
    let u1 = u384_mul_mod(z, w, P384_ORDER);
    let u2 = u384_mul_mod(r, w, P384_ORDER);

    let g = P384Point {
        x:        U384 { v: P384_GX },
        y:        U384 { v: P384_GY },
        infinity: false,
    };
    let pt = p384_muladd_shamir(g, u1, q_pt, u2);
    guard !pt.infinity else { return false; }

    var v = pt.x;
    if u384_cmp(v, P384_ORDER) >= 0 {
        let ord = U384 { v: P384_ORDER };
        v = u384_sub_mod(v, ord, P384_ORDER);
    }
    return u384_cmp(v, r.v) == 0;
}

// Verifies an ASN.1 DER-encoded ECDSA P-384 SHA-384 signature (`SEQUENCE { r, s }`).
// crap:ignore
fn ecdsa_p384_verify_der(pub_key: const u8[:], message: const u8[:], sig: const u8[:]) -> bool {
    guard sig.len >= 8 && sig[0] == 0x30 else { return false; }
    var der_raw: u8[96] = [0; 96];
    guard ecdsa_p384_decode_der_sig(sig, der_raw) else { return false; }
    let q_pt, pub_ok = decode_p384_public_key(pub_key);
    guard pub_ok else { return false; }
    let msg_hash = sha384(message);
    var z = u384_from_be(msg_hash);
    if u384_cmp(z, P384_ORDER) >= 0 {
        let ord = U384 { v: P384_ORDER };
        z = u384_sub_mod(z, ord, P384_ORDER);
    }
    return ecdsa_p384_verify_raw_pt(q_pt, z, der_raw);
}

// Verifies a fixed-width 96-byte IEEE P1363 (`r || s`) ECDSA P-384 SHA-384 signature.
// crap:ignore
fn ecdsa_p384_verify_p1363(pub_key: const u8[:], message: const u8[:], sig: const u8[:]) -> bool {
    guard sig.len == 96 else { return false; }
    let q_pt, pub_ok = decode_p384_public_key(pub_key);
    guard pub_ok else { return false; }
    let msg_hash = sha384(message);
    var z = u384_from_be(msg_hash);
    if u384_cmp(z, P384_ORDER) >= 0 {
        let ord = U384 { v: P384_ORDER };
        z = u384_sub_mod(z, ord, P384_ORDER);
    }
    var p1363_raw: u8[96] = [0; 96];
    for i in 96 {
        p1363_raw[i] = sig[i];
    }
    return ecdsa_p384_verify_raw_pt(q_pt, z, p1363_raw);
}

// Verifies an ECDSA P-384 SHA-384 signature (accepts 96-byte raw `r || s` or ASN.1 DER `SEQUENCE { r, s }`).
// crap:ignore
fn ecdsa_p384_verify(pub_key: const u8[:], message: const u8[:], sig: const u8[:]) -> bool {
    if ecdsa_p384_verify_der(pub_key, message, sig) {
        return true;
    }
    return ecdsa_p384_verify_p1363(pub_key, message, sig);
}
