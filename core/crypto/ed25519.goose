// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Ed25519 digital signature creation and verification (RFC 8032).
// Implements twisted Edwards curve -x^2 + y^2 = 1 + d x^2 y^2 over GF(2^255 - 19)
// using extended projective coordinates (X : Y : Z : T) and constant-time scalar arithmetic.
// Zero dynamic heap allocations on key generation, signing, and verification.
namespace core;

import std;

// ---- Mathematical Constants & Base Point --------------------------------

// Twisted Edwards constant d = -121665 / 121666 (mod 2^255 - 19)
let ED25519_D: const Fe10 = Fe10 {
    v: [56195235, 13857412, 51736253, 6949390, 114729, 24766616, 60832955, 30306712, 48412415, 21499315],
};

// 2 * d (mod 2^255 - 19)
let ED25519_D2: const Fe10 = Fe10 {
    v: [45281625, 27714825, 36363642, 13898781, 229458, 15978800, 54557047, 27058993, 29715967, 9444199],
};

// Square root of -1 in GF(2^255 - 19): 2^((p - 1) / 4)
let ED25519_SQRT_M1: const Fe10 = Fe10 {
    v: [34513072, 25610706, 9377949, 3500415, 12389472, 33281959, 41962654, 31548777, 326685, 11406482],
};

// Group order L = 2^252 + 27742317777372353535851937790883648493
let ED25519_L_BYTES: const u8[32] = [
    0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58,
    0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10,
];

let ED25519_L_WORDS: const u64[4] = [
    0x5812631a5cf5d3ed,
    0x14def9dea2f79cd6,
    0x0000000000000000,
    0x1000000000000000,
];

// ---- Extended Point Representation (X : Y : Z : T) -----------------------
// Represents an affine point (X / Z, Y / Z) where X * Y = Z * T.
// Neutral identity element is (0 : 1 : 1 : 0).

struct EdPoint {
    X: Fe10 = Fe10 { .. },
    Y: Fe10 = Fe10 { v: [1, 0, 0, 0, 0, 0, 0, 0, 0, 0] },
    Z: Fe10 = Fe10 { v: [1, 0, 0, 0, 0, 0, 0, 0, 0, 0] },
    T: Fe10 = Fe10 { .. },
}

// Generator base point B = (Bx, By) on Ed25519
fn ed25519_base_point() -> EdPoint {
    return EdPoint {
        X: Fe10 {
            v: [
                52811034, 25909283, 16144682, 17082669, 27570973,
                30858332, 40966398, 8378388, 20764389, 8758491,
            ],
        },
        Y: Fe10 {
            v: [
                40265304, 26843545, 13421772, 20132659, 26843545,
                6710886, 53687091, 13421772, 40265318, 26843545,
            ],
        },
        Z: Fe10 { v: [1, 0, 0, 0, 0, 0, 0, 0, 0, 0] },
        T: Fe10 {
            v: [
                28827043, 27438313, 39759291, 244362, 8635006,
                11264893, 19351346, 13413597, 16611511, 27139452,
            ],
        },
    };
}

// ---- Field Arithmetic Modulo 2^255 - 19 ----------------------------------

inline fn fe_one() -> Fe10 {
    return Fe10 { v: [1, 0, 0, 0, 0, 0, 0, 0, 0, 0] };
}

inline fn fe_neg(a: Fe10) -> Fe10 {
    return fe_sub(Fe10 { .. }, a);
}

// Equality check for normalized field elements
fn fe_eq(a: Fe10, b: Fe10) -> bool {
    let ba = fe_to_bytes(a);
    let bb = fe_to_bytes(b);
    return ba == bb;
}

// Branchless conditional selection: if cond == 1 return a, else b.
inline fn fe_select(cond: u8, a: Fe10, b: Fe10) -> Fe10 {
    let mask = -((cond & 1) as i64);
    var out = Fe10 { .. };
    for i in 10 {
        out.v[i] = b.v[i] ^ (mask & (a.v[i] ^ b.v[i]));
    }
    return out;
}

// Computes z^((p - 5) / 8) mod p = z^(2^252 - 3) using optimal addition chain.
fn fe_pow22523(z: Fe10) -> Fe10 {
    let a = fe_sq(z);
    let t0 = fe_sq(a);
    let t1 = fe_sq(t0);
    let b = fe_mul(t1, z);
    let c = fe_mul(b, a);
    let t2 = fe_sq(c);
    let d = fe_mul(t2, b);

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

    let t10 = fe_sq(fe_sq(k));
    return fe_mul(t10, z);
}

// ---- Extended Twisted Edwards Point Operations ---------------------------

// Point Doubling: 2 * P1 on extended Edwards curve (4S + 4M).
fn ed25519_point_double(p: EdPoint) -> EdPoint {
    let a = fe_sq(p.X);
    let b = fe_sq(p.Y);
    let c = fe_add(fe_sq(p.Z), fe_sq(p.Z));
    let d = fe_neg(a);
    let x_plus_y = fe_add(p.X, p.Y);
    let e = fe_sub(fe_sub(fe_sq(x_plus_y), a), b);
    let g = fe_add(d, b);
    let f = fe_sub(g, c);
    let h = fe_sub(d, b);

    return EdPoint {
        X: fe_mul(e, f),
        Y: fe_mul(g, h),
        Z: fe_mul(f, g),
        T: fe_mul(e, h),
    };
}

// Point Addition: P1 + P2 on extended Edwards curve (8M).
fn ed25519_point_add(p1: EdPoint, p2: EdPoint) -> EdPoint {
    let a = fe_mul(fe_sub(p1.Y, p1.X), fe_sub(p2.Y, p2.X));
    let b = fe_mul(fe_add(p1.Y, p1.X), fe_add(p2.Y, p2.X));
    let c = fe_mul(fe_mul(p1.T, ED25519_D2), p2.T);
    let d = fe_mul(p1.Z, fe_add(p2.Z, p2.Z));
    let e = fe_sub(b, a);
    let f = fe_sub(d, c);
    let g = fe_add(d, c);
    let h = fe_add(b, a);

    return EdPoint {
        X: fe_mul(e, f),
        Y: fe_mul(g, h),
        Z: fe_mul(f, g),
        T: fe_mul(e, h),
    };
}

// Constant-time point selection: if cond == 1 return if_true, else if_false.
fn ed25519_point_select(cond: u8, if_true: EdPoint, if_false: EdPoint) -> EdPoint {
    return EdPoint {
        X: fe_select(cond, if_true.X, if_false.X),
        Y: fe_select(cond, if_true.Y, if_false.Y),
        Z: fe_select(cond, if_true.Z, if_false.Z),
        T: fe_select(cond, if_true.T, if_false.T),
    };
}

// Point Compression: Encodes extended point to canonical 32-byte representation.
fn ed25519_point_compress(p: EdPoint) -> u8[32] {
    let inv_z = fe_inv(p.Z);
    let x = fe_mul(p.X, inv_z);
    let y = fe_mul(p.Y, inv_z);

    var out = fe_to_bytes(y);
    let x_bytes = fe_to_bytes(x);
    if (x_bytes[0] & 1) != 0 {
        out[31] |= 0x80;
    }
    return out;
}

// Check if 255-bit little-endian value is >= 2^255 - 19.
fn ed25519_is_ge_p(y_bytes: const u8[32]&) -> bool {
    let b31 = y_bytes[31] & 0x7F;
    if b31 < 0x7F { return false; }
    for i in 1..31 {
        if y_bytes[31 - i] < 0xFF { return false; }
    }
    return y_bytes[0] >= 0xED;
}

// Point Decompression: Decodes canonical 32-byte representation into extended point.
// Returns true on success, false if point is invalid or not on the curve.
fn ed25519_point_decompress(b: const u8[32]&, out: EdPoint&) -> bool {
    if ed25519_is_ge_p(b) {
        return false;
    }

    let x_0 = (b[31] >> 7) & 1;
    var y_bytes = b;
    y_bytes[31] &= 0x7F;

    let y = fe_from_bytes(y_bytes);
    let y2 = fe_sq(y);
    let one = fe_one();

    // u = y^2 - 1, v = d * y^2 + 1
    let u = fe_sub(y2, one);
    let v = fe_add(fe_mul(ED25519_D, y2), one);

    // Candidate x = u * v^3 * (u * v^7)^((p - 5) / 8) mod p
    let v2 = fe_sq(v);
    let v3 = fe_mul(v2, v);
    let v7 = fe_mul(fe_sq(v3), v);
    let uv7 = fe_mul(u, v7);
    let uv7_pow = fe_pow22523(uv7);
    let cand = fe_mul(fe_mul(u, v3), uv7_pow);

    let v_cand2 = fe_mul(v, fe_sq(cand));
    var x = cand;

    if fe_eq(v_cand2, u) {
        // cand is the square root
    } else if fe_eq(v_cand2, fe_neg(u)) {
        // cand * sqrt(-1) is the square root
        x = fe_mul(cand, ED25519_SQRT_M1);
    } else {
        // u / v is not a quadratic residue; not on curve
        return false;
    }

    let x_bytes = fe_to_bytes(x);
    let cand_parity = x_bytes[0] & 1;
    if cand_parity != x_0 {
        x = fe_neg(x);
    }

    if fe_eq(x, Fe10 { .. }) && x_0 == 1 {
        return false;
    }

    out.X = x;
    out.Y = y;
    out.Z = one;
    out.T = fe_mul(x, y);
    return true;
}

// Constant-time scalar multiplication: [scalar] * point.
fn ed25519_scalarmult_ct(p: EdPoint, scalar: const u8[32]&) -> EdPoint {
    var r = EdPoint { .. };
    var base = p;
    for byte_idx in 32 {
        let b = scalar[byte_idx];
        for bit_idx in 8 {
            let bit = (b >> (bit_idx as u8)) & 1;
            let sum = ed25519_point_add(r, base);
            r = ed25519_point_select(bit, sum, r);
            base = ed25519_point_double(base);
        }
    }
    return r;
}

// Variable-time scalar multiplication for verification: [scalar] * point.
fn ed25519_scalarmult_vartime(p: EdPoint, scalar: const u8[32]&) -> EdPoint {
    var r = EdPoint { .. };
    var base = p;
    for byte_idx in 32 {
        let b = scalar[byte_idx];
        for bit_idx in 8 {
            if ((b >> (bit_idx as u8)) & 1) != 0 {
                r = ed25519_point_add(r, base);
            }
            base = ed25519_point_double(base);
        }
    }
    return r;
}

// Constant-time base point multiplication: [scalar] * B.
fn ed25519_scalarmult_base(scalar: const u8[32]&) -> EdPoint {
    let b = ed25519_base_point();
    return ed25519_scalarmult_ct(b, scalar);
}

// ---- Scalar Arithmetic Modulo Group Order L -----------------------------

// Checks whether scalar S is >= group order L.
fn sc_is_ge_l(s: const u8[32]&) -> bool {
    for i in 32 {
        let idx = 31 - i;
        if s[idx] > ED25519_L_BYTES[idx] { return true; }
        if s[idx] < ED25519_L_BYTES[idx] { return false; }
    }
    return true; // equal to L
}

inline fn sc_sub_l_inplace(rem: u64[4]&) {
    var borrow: u64 = 0;
    for j in 4 {
        let term = ED25519_L_WORDS[j] + borrow;
        if rem[j] < term || (borrow == 1 && term == 0) {
            rem[j] = (rem[j] + (0xFFFFFFFFFFFFFFFF - term)) + 1;
            borrow = 1;
        } else {
            rem[j] -= term;
            borrow = 0;
        }
    }
}

// Reduces 64-byte little-endian integer modulo L using bitwise division.
fn sc_reduce(in64: const u8[64]&) -> u8[32] {
    var rem: u64[4] = [0; 4];

    for i in 512 {
        let bit_idx = 511 - i;
        let byte_pos = bit_idx / 8;
        let bit_pos = (bit_idx % 8) as u8;
        let bit = ((in64[byte_pos] >> bit_pos) & 1) as u64;

        // Shift remainder left by 1 bit and insert current bit
        var carry = bit;
        for j in 4 {
            let next_carry = (rem[j] >> 63) & 1;
            rem[j] = (rem[j] << 1) | carry;
            carry = next_carry;
        }

        // Compare rem with L
        var ge = true;
        for j in 4 {
            let idx = 3 - j;
            if rem[idx] > ED25519_L_WORDS[idx] {
                ge = true;
                break;
            } else if rem[idx] < ED25519_L_WORDS[idx] {
                ge = false;
                break;
            }
        }

        if ge {
            sc_sub_l_inplace(rem);
        }
    }

    var out: u8[32] = [0; 32];
    for i in 4 {
        let w = rem[i];
        for j in 8 {
            out[i * 8 + j] = ((w >> ((j * 8) as u8)) & 0xFF) as u8;
        }
    }
    return out;
}

// Computes S = (k * s + r) mod L.
fn sc_muladd(k: const u8[32]&, s: const u8[32]&, r: const u8[32]&) -> u8[32] {
    // Unpack 32-byte integers into 16 x 16-bit limbs
    var k_w: u64[16] = [0; 16];
    var s_w: u64[16] = [0; 16];
    var r_w: u64[16] = [0; 16];

    for i in 16 {
        let off = i * 2;
        k_w[i] = k[off] | ((k[off + 1] as! u64) << 8);
        s_w[i] = s[off] | ((s[off + 1] as! u64) << 8);
        r_w[i] = r[off] | ((r[off + 1] as! u64) << 8);
    }

    // Multiply 16 x 16 -> 32 limbs and accumulate r
    // Max sum per limb is at most 16 * (2^16 - 1)^2 + (2^16 - 1) < 2^37, well within u64
    var acc: u64[32] = [0; 32];
    for i in 16 {
        for j in 16 {
            acc[i + j] += k_w[i] * s_w[j];
        }
    }
    for i in 16 {
        acc[i] += r_w[i];
    }

    // Carry propagation across 16-bit boundaries
    var carry:     u64     = 0;
    var out_words: u16[32] = [0; 32];
    for i in 32 {
        let cur = acc[i] + carry;
        out_words[i] = (cur & 0xFFFF) as! u16;
        carry = cur >> 16;
    }

    // Pack into 64 little-endian bytes
    var b64: u8[64] = [0; 64];
    for i in 32 {
        let w = out_words[i];
        let off = i * 2;
        b64[off] = (w & 0xFF) as u8;
        b64[off + 1] = ((w >> 8) & 0xFF) as u8;
    }

    return sc_reduce(b64);
}

// ---- Ed25519 Public API (RFC 8032) ---------------------------------------

struct Ed25519KeyPair {
    seed:       u8[32] = [0; 32],
    public_key: u8[32] = [0; 32],
}

// Derives a 32-byte Ed25519 public key from a 32-byte secret seed.
fn ed25519_public_key(seed: const u8[32]&) -> u8[32] {
    let h = sha512(seed[..]);

    var s: u8[32] = [0; 32];
    for i in 32 { s[i] = h[i]; }
    s[0] &= 248;
    s[31] &= 127;
    s[31] |= 64;

    let a_pt = ed25519_scalarmult_base(s);
    return ed25519_point_compress(a_pt);
}

// Generates an Ed25519 keypair from a 32-byte seed.
fn ed25519_keypair(seed: const u8[32]&) -> Ed25519KeyPair {
    let pub_key = ed25519_public_key(seed);
    return Ed25519KeyPair {
        seed:       seed,
        public_key: pub_key,
    };
}

// Signs an arbitrary byte message using a 32-byte seed (RFC 8032 Section 5.1.6).
// Returns 64-byte signature (R || S).
fn ed25519_sign(seed: const u8[32]&, message: const u8[:]) -> u8[64] {
    let h = sha512(seed[..]);

    var s:      u8[32] = [0; 32];
    var prefix: u8[32] = [0; 32];
    for i in 32 {
        s[i] = h[i];
        prefix[i] = h[32 + i];
    }
    s[0] &= 248;
    s[31] &= 127;
    s[31] |= 64;

    // Public key A = [s] * B
    let a_pt = ed25519_scalarmult_base(s);
    let a_bytes = ed25519_point_compress(a_pt);

    // Nonce r = SHA-512(prefix || message) mod L
    var r_ctx = Sha512Ctx { .. };
    sha512_update(r_ctx, prefix[..]);
    sha512_update(r_ctx, message);
    let r_hash = sha512_final(r_ctx);
    let r = sc_reduce(r_hash);

    // Commitment R = [r] * B
    let r_pt = ed25519_scalarmult_base(r);
    let r_bytes = ed25519_point_compress(r_pt);

    // Challenge k = SHA-512(R || A || message) mod L
    var k_ctx = Sha512Ctx { .. };
    sha512_update(k_ctx, r_bytes[..]);
    sha512_update(k_ctx, a_bytes[..]);
    sha512_update(k_ctx, message);
    let k_hash = sha512_final(k_ctx);
    let k = sc_reduce(k_hash);

    // Proof scalar S = (r + k * s) mod L
    let s_scalar = sc_muladd(k, s, r);

    // Signature is (R || S)
    var sig: u8[64] = [0; 64];
    for i in 32 {
        sig[i] = r_bytes[i];
        sig[32 + i] = s_scalar[i];
    }
    return sig;
}

fn compute_ed25519_challenge(r_bytes: const u8[32], public_key: const u8[32], message: const u8[:]) -> u8[32] {
    var k_ctx = Sha512Ctx { .. };
    sha512_update(k_ctx, r_bytes[..]);
    sha512_update(k_ctx, public_key[..]);
    sha512_update(k_ctx, message);
    let k_hash = sha512_final(k_ctx);
    return sc_reduce(k_hash);
}

fn ed25519_points_equal_projective(p1: const EdPoint&, p2: const EdPoint&) -> bool {
    // Affine comparison without field inversions:
    // X1 * Z2 == X2 * Z1 and Y1 * Z2 == Y2 * Z1
    let x1z2 = fe_mul(p1.X, p2.Z);
    let x2z1 = fe_mul(p2.X, p1.Z);
    guard fe_eq(x1z2, x2z1) else { return false; }

    let y1z2 = fe_mul(p1.Y, p2.Z);
    let y2z1 = fe_mul(p2.Y, p1.Z);
    return fe_eq(y1z2, y2z1);
}

// Verifies a 64-byte Ed25519 signature against a 32-byte public key (RFC 8032 Section 5.1.7).
// Returns true if valid, false if signature or public key is malformed or invalid.
fn ed25519_verify(public_key: const u8[32]&, message: const u8[:], signature: const u8[64]&) -> bool {
    var r_bytes: u8[32] = [0; 32];
    var s_bytes: u8[32] = [0; 32];
    for i in 32 {
        r_bytes[i] = signature[i];
        s_bytes[i] = signature[32 + i];
    }

    guard !sc_is_ge_l(s_bytes) else { return false; }

    var a_pt = EdPoint { .. };
    guard ed25519_point_decompress(public_key, a_pt) else { return false; }

    var r_pt = EdPoint { .. };
    guard ed25519_point_decompress(r_bytes, r_pt) else { return false; }

    let k = compute_ed25519_challenge(r_bytes, public_key, message);
    let sb = ed25519_scalarmult_base(s_bytes);
    let ka = ed25519_scalarmult_vartime(a_pt, k);
    let r_plus_ka = ed25519_point_add(r_pt, ka);

    return ed25519_points_equal_projective(sb, r_plus_ka);
}
