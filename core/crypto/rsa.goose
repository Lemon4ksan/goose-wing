// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Deterministic zero-allocation RSA signature verification and generation (RFC 8017).
// Supports RSASSA-PKCS1-v1_5 and RSASSA-PSS with SHA-256, SHA-384, and SHA-512 up to 4096-bit keys.
namespace core;

import std;
import core.crypto.csprng;
import core.crypto.ct;
import core.crypto.sha;

// ---- Big-Endian & 32-Bit Limb Montgomery Modular Arithmetic (up to 4096 bits) -----

// Minimum RSA modulus size in bytes for signature generation/verification and key parsing (2048 bits).
const RSA_MIN_MODULUS_BYTES: i64 = 256;

// Constant-time branchless comparison of two equal-length big-endian byte slices `a` and `b`.
// crap:ignore
inline fn rsa_be_cmp(a: const u8[:], b: const u8[:]) -> i32 {
    var gt: u32 = 0;
    var lt: u32 = 0;
    for i in a.len {
        let ai = a[i] as u32;
        let bi = b[i] as u32;
        let undecided = (gt | lt) ^ 1;
        let bi_gt = ((bi - ai) >> 31) & 1;
        let bi_lt = ((ai - bi) >> 31) & 1;
        gt |= undecided & bi_gt;
        lt |= undecided & bi_lt;
    }
    return core::sub_sat_i64(gt, lt) as i32;
}

// Zeroizes a mutable `u32` limb slice in place using an opaque zeroization barrier.
// crap:ignore
inline fn rsa_zeroize_limbs(limbs: u32[:]) {
    var z_bytes: u8[32] = [0; 32];
    secure_zeroize_32(z_bytes);
    let z_word: u32 = z_bytes[0];
    for i in limbs.len {
        limbs[i] = z_word;
    }
}

// Computes the 32-bit negative modular inverse `-m0^-1 mod 2^32` for an odd limb `m0` via Newton-Raphson.
// crap:ignore
inline fn rsa_ninv32(m0: u32) -> u32 {
    var inv: u32 = 1;
    for _ in 5 {
        inv = inv * (2 - m0 * inv);
    }
    return 0 - inv;
}

// Decodes a big-endian byte slice of length `k <= 512` into `n_limbs = (k + 3) / 4` little-endian u32 limbs.
// crap:ignore
fn rsa_be_to_limbs(src: const u8[:], out: u32[..128]&) {
    out.clear();
    let k = src.len;
    let n_limbs = (k + 3) >> 2;
    for i in n_limbs {
        let end_pos = k - (i << 2);
        var w:     u32 = 0;
        var shift: u32 = 0;
        for b in 4 {
            let pos = end_pos - 1 - b;
            if pos >= 0 {
                w |= (src[pos] as u32) << shift;
            }
            shift += 8;
        }
        out.push(w);
    }
}

// Encodes little-endian `u32` limbs back into a big-endian byte buffer of exact length `k`.
// crap:ignore
fn rsa_limbs_to_be(limbs: const u32[:], k: i64, out: u8[..512]&) {
    out.clear();
    for idx in k {
        let byte_from_lsb = (k - 1) - idx;
        let limb_idx = byte_from_lsb >> 2;
        let shift = ((byte_from_lsb & 3) << 3) as u32;
        let b = if limb_idx < limbs.len {
            ((limbs[limb_idx] >> shift) & 0xFF) as u8
        } else {
            0
        };
        out.push(b);
    }
}

// Branchless limb subtraction `diff = t - m` returning final borrow (0 or 1).
// crap:ignore
inline fn rsa_limbs_sub_borrow(t: const u32[:], m: const u32[:], n_limbs: i64, diff: u32[:]) -> u64 {
    var borrow: u64 = 0;
    for j in n_limbs {
        let d = (t[j] as u64) - m[j] - borrow;
        diff[j] = (d & 0xFFFFFFFF) as u32;
        borrow = d >> 63;
    }
    return borrow;
}

// Builds a 32-bit all-ones mask when `(top_carry != 0) || (borrow == 0)`, else all-zeros.
// crap:ignore
inline fn rsa_monty_sub_mask(top_carry: u64, borrow: u64) -> u32 {
    let has_carry = (top_carry | (0 - top_carry)) >> 63;
    let do_sub = ((has_carry | (1 ^ borrow)) & 1) as u32;
    return 0 - do_sub;
}

// Branchless constant-time conditional subtraction: `t = t - m` when `t >= m` or `top_carry != 0`.
// crap:ignore
fn rsa_monty_cond_sub(t: u32[:], m: const u32[:], n_limbs: i64, top_carry: u64) {
    guard n_limbs <= 128 else { return; }
    var diff: u32[128] = [0; 128];
    defer rsa_zeroize_limbs(diff[0..n_limbs]);
    let borrow = rsa_limbs_sub_borrow(t, m, n_limbs, diff[0..n_limbs]);
    let mask = rsa_monty_sub_mask(top_carry, borrow);
    for j in n_limbs {
        t[j] = (t[j] & (~mask)) | (diff[j] & mask);
    }
}

// Performs 32-bit CIOS Montgomery multiplication: `out = (a * b * R^-1) mod m` where `R = 2^(32 * n_limbs)`.
// crap:ignore
fn rsa_monty_mul(a: const u32[:], b: const u32[:], m: const u32[:], m0i: u32, out: u32[..128]&) {
    let n_limbs = m.len;
    var t: u32[130] = [0; 130];
    defer rsa_zeroize_limbs(t[..]);
    for i in n_limbs {
        var carry1: u64 = 0;
        let ai = a[i] as u64;
        for j in n_limbs {
            let prod = ai * b[j] + t[j] + carry1;
            t[j] = (prod & 0xFFFFFFFF) as u32;
            carry1 = prod >> 32;
        }
        let sum1 = t[n_limbs] + carry1;
        t[n_limbs] = (sum1 & 0xFFFFFFFF) as u32;
        t[n_limbs + 1] = (sum1 >> 32) as u32;

        let q = (t[0] * m0i) as u64;
        var carry2: u64 = (q * m[0] + t[0]) >> 32;
        var j:      i64 = 1;
        while j < n_limbs {
            let prod = q * m[j] + t[j] + carry2;
            t[j - 1] = (prod & 0xFFFFFFFF) as u32;
            carry2 = prod >> 32;
            j += 1;
        }
        let sum2 = t[n_limbs] + carry2;
        t[n_limbs - 1] = (sum2 & 0xFFFFFFFF) as u32;
        let top_carry = t[n_limbs + 1] + (sum2 >> 32);
        t[n_limbs] = (top_carry & 0xFFFFFFFF) as u32;
        t[n_limbs + 1] = 0;
    }
    rsa_monty_cond_sub(t[0..n_limbs], m, n_limbs, t[n_limbs]);
    out.clear();
    out.append(t[0..n_limbs]);
}

// Doubles a little-endian limb integer modulo `m` (`limbs = (2 * limbs) mod m`).
// crap:ignore
fn rsa_limbs_double_mod(limbs: u32[..128]&, m: const u32[:]) {
    let n_limbs = m.len;
    var carry: u64 = 0;
    for i in n_limbs {
        let s = ((limbs[i] as u64) << 1) | carry;
        limbs[i] = (s & 0xFFFFFFFF) as u32;
        carry = s >> 32;
    }
    rsa_monty_cond_sub(limbs[..], m, n_limbs, carry);
}

// Computes `R mod m` (`2^(32 * n_limbs) mod m`) and `R^2 mod m` for Montgomery domain conversion.
// crap:ignore
fn rsa_compute_monty_r2(m: const u32[:], out_r: u32[..128]&, out_r2: u32[..128]&) {
    let n_limbs = m.len;
    out_r.clear();
    for _ in n_limbs {
        out_r.push(0);
    }
    out_r[0] = 1;
    let total_bits = n_limbs << 5;
    for _ in total_bits {
        rsa_limbs_double_mod(out_r, m);
    }
    out_r2.clear();
    out_r2.append(out_r[..]);
    for _ in total_bits {
        rsa_limbs_double_mod(out_r2, m);
    }
}

// Computes `out = (a * b) mod m` on equal-length big-endian buffers (`k <= 512`) via CIOS Montgomery multiplication.
// crap:ignore
fn rsa_be_mul_mod(a: const u8[:], b: const u8[:], m: const u8[:], out: u8[..512]&) {
    let k = m.len;
    guard k > 0 && k <= 512 && a.len == k && b.len == k && (m[k - 1] & 1) == 1 else {
        out.clear();
        return;
    }
    var m_limbs:  u32[..128] = [];
    var a_limbs:  u32[..128] = [];
    var b_limbs:  u32[..128] = [];
    var r_mod:    u32[..128] = [];
    var r2_mod:   u32[..128] = [];
    var a_mont:   u32[..128] = [];
    var prod_raw: u32[..128] = [];
    defer rsa_zeroize_limbs(a_limbs[..]);
    defer rsa_zeroize_limbs(b_limbs[..]);
    defer rsa_zeroize_limbs(a_mont[..]);
    defer rsa_zeroize_limbs(prod_raw[..]);
    rsa_be_to_limbs(m, m_limbs);
    rsa_be_to_limbs(a, a_limbs);
    rsa_be_to_limbs(b, b_limbs);
    let m0i = rsa_ninv32(m_limbs[0]);
    rsa_compute_monty_r2(m_limbs[..], r_mod, r2_mod);
    rsa_monty_mul(a_limbs[..], r2_mod[..], m_limbs[..], m0i, a_mont);
    rsa_monty_mul(a_mont[..], b_limbs[..], m_limbs[..], m0i, prod_raw);
    rsa_limbs_to_be(prod_raw[..], k, out);
}

// Advances one exponent bit during constant-time Montgomery modular exponentiation.
// crap:ignore
fn rsa_monty_exp_step(
    acc:     u32[..128]&,
    base_m:  const u32[:],
    m_limbs: const u32[:],
    m0i:     u32,
    b_val:   u8,
) {
    var sq:   u32[..128] = [];
    var prod: u32[..128] = [];
    defer rsa_zeroize_limbs(sq[..]);
    defer rsa_zeroize_limbs(prod[..]);
    rsa_monty_mul(acc[..], acc[..], m_limbs, m0i, sq);
    rsa_monty_mul(sq[..], base_m, m_limbs, m0i, prod);
    let mask: u32 = 0 - ((b_val & 1) as u32);
    for i in m_limbs.len {
        acc[i] = (sq[i] & (~mask)) | (prod[i] & mask);
    }
}

// Computes `out = base^exp mod m` where `m` is big-endian modulus of length `64 <= k <= 512`.
// Executes constant-time square-and-multiply across all bits of `exp` and wipes intermediate limbs.
// crap:ignore
fn rsa_mod_exp(base: const u8[:], exp: const u8[:], m: const u8[:], out: u8[..512]&) -> bool {
    let k = m.len;
    guard k >= 64 && k <= 512 else { return false; }
    guard base.len == k && exp.len > 0 && exp.len <= 512 else { return false; }
    guard (m[k - 1] & 1) == 1 && m[0] != 0 else { return false; }
    guard rsa_be_cmp(base, m) < 0 else { return false; }
    var exp_nonzero: u8 = 0;
    for i in exp.len {
        exp_nonzero |= exp[i];
    }
    guard exp_nonzero != 0 else { return false; }

    var m_limbs:    u32[..128] = [];
    var base_limbs: u32[..128] = [];
    var r_mod:      u32[..128] = [];
    var r2_mod:     u32[..128] = [];
    var base_mont:  u32[..128] = [];
    var acc_mont:   u32[..128] = [];
    var res_limbs:  u32[..128] = [];
    defer rsa_zeroize_limbs(base_limbs[..]);
    defer rsa_zeroize_limbs(base_mont[..]);
    defer rsa_zeroize_limbs(acc_mont[..]);
    defer rsa_zeroize_limbs(res_limbs[..]);
    rsa_be_to_limbs(m, m_limbs);
    rsa_be_to_limbs(base, base_limbs);
    let m0i = rsa_ninv32(m_limbs[0]);
    rsa_compute_monty_r2(m_limbs[..], r_mod, r2_mod);
    rsa_monty_mul(base_limbs[..], r2_mod[..], m_limbs[..], m0i, base_mont);
    acc_mont.append(r_mod[..]);

    for i in exp.len {
        let eb = exp[i];
        var bit: i32 = 7;
        while bit >= 0 {
            let b_val = (eb >> bit) & 1;
            rsa_monty_exp_step(acc_mont, base_mont[..], m_limbs[..], m0i, b_val);
            bit -= 1;
        }
    }

    var one_limbs: u32[..128] = [];
    one_limbs.push(1);
    var z: i64 = 1;
    while z < m_limbs.len {
        one_limbs.push(0);
        z += 1;
    }
    rsa_monty_mul(acc_mont[..], one_limbs[..], m_limbs[..], m0i, res_limbs);
    rsa_limbs_to_be(res_limbs[..], k, out);
    return true;
}

// Constant-time zero test over a little-endian `u32` limb slice.
// crap:ignore
inline fn rsa_limbs_is_zero(a: const u32[:]) -> bool {
    var acc: u32 = 0;
    for i in a.len { acc |= a[i]; }
    return acc == 0;
}

// Constant-time equality-to-one test over a little-endian `u32` limb slice.
// crap:ignore
inline fn rsa_limbs_is_one(a: const u32[:]) -> bool {
    guard a.len > 0 else { return false; }
    var acc: u32 = a[0] ^ 1;
    var i:   i64 = 1;
    while i < a.len {
        acc |= a[i];
        i += 1;
    }
    return acc == 0;
}

// Shifts a little-endian `u32` limb slice right by 1 bit, injecting `top_carry` into the MSB.
// crap:ignore
inline fn rsa_limbs_shr1(a: u32[:], top_carry: u32) {
    var c = top_carry & 1;
    var idx = a.len - 1;
    while idx >= 0 {
        let next_c = a[idx] & 1;
        a[idx] = (a[idx] >> 1) | (c << 31);
        c = next_c;
        idx -= 1;
    }
}

// Branchless modular halving: `x = (x / 2) mod m` for odd modulus `m`.
// crap:ignore
inline fn rsa_limbs_halve_mod(x: u32[:], m: const u32[:]) {
    let odd_mask: u32 = 0 - (x[0] & 1);
    var carry: u64 = 0;
    for i in m.len {
        let s = (x[i] as u64) + (m[i] & odd_mask) + carry;
        x[i] = (s & 0xFFFFFFFF) as u32;
        carry = s >> 32;
    }
    rsa_limbs_shr1(x, carry as u32);
}

// Branchless modular subtraction in place: `a = (a - b) mod m`.
// crap:ignore
inline fn rsa_limbs_sub_mod(a: u32[:], b: const u32[:], m: const u32[:]) {
    var borrow: u64 = 0;
    for i in m.len {
        let d = (a[i] as u64) - b[i] - borrow;
        a[i] = (d & 0xFFFFFFFF) as u32;
        borrow = d >> 63;
    }
    let add_mask: u32 = 0 - (borrow as u32);
    var carry: u64 = 0;
    for i in m.len {
        let s = (a[i] as u64) + (m[i] & add_mask) + carry;
        a[i] = (s & 0xFFFFFFFF) as u32;
        carry = s >> 32;
    }
}

// Computes `out_inv = r^-1 mod m` via fixed-iteration branchless binary extended GCD for odd `m`.
// Constant-time with respect to `r_limbs`; returns false if `gcd(r, m) != 1`.
// crap:ignore
fn rsa_limbs_mod_inv(r_limbs: const u32[:], m_limbs: const u32[:], out_inv: u32[..128]&) -> bool {
    let n = m_limbs.len;
    guard n > 0 && n <= 128 && r_limbs.len == n && (m_limbs[0] & 1) == 1 else { return false; }
    guard !rsa_limbs_is_zero(r_limbs) else { return false; }
    var a:     u32[128] = [0; 128];
    var b:     u32[128] = [0; 128];
    var u:     u32[128] = [0; 128];
    var v:     u32[128] = [0; 128];
    var u_tmp: u32[128] = [0; 128];
    defer rsa_zeroize_limbs(a[0..n]);
    defer rsa_zeroize_limbs(b[0..n]);
    defer rsa_zeroize_limbs(u[0..n]);
    defer rsa_zeroize_limbs(v[0..n]);
    defer rsa_zeroize_limbs(u_tmp[0..n]);
    for i in n { a[i] = r_limbs[i]; b[i] = m_limbs[i]; }
    u[0] = 1;
    let total_steps = n * 64;
    for _ in total_steps {
        let odd = a[0] & 1;
        var borrow: u64 = 0;
        for i in n {
            let d = (a[i] as u64) - b[i] - borrow;
            borrow = d >> 63;
        }
        let swap_mask: u32 = 0 - (odd & (borrow as u32));
        for i in n {
            let da = (a[i] ^ b[i]) & swap_mask;
            a[i] ^= da;
            b[i] ^= da;
            let du = (u[i] ^ v[i]) & swap_mask;
            u[i] ^= du;
            v[i] ^= du;
        }
        let odd_mask: u32 = 0 - odd;
        var sub_borrow: u64 = 0;
        for i in n {
            let d = (a[i] as u64) - (b[i] & odd_mask) - sub_borrow;
            a[i] = (d & 0xFFFFFFFF) as u32;
            sub_borrow = d >> 63;
            u_tmp[i] = u[i];
        }
        rsa_limbs_sub_mod(u_tmp[0..n], v[0..n], m_limbs);
        for i in n {
            u[i] = (u[i] & (~odd_mask)) | (u_tmp[i] & odd_mask);
        }
        rsa_limbs_shr1(a[0..n], 0);
        rsa_limbs_halve_mod(u[0..n], m_limbs);
    }
    out_inv.clear();
    guard rsa_limbs_is_one(b[0..n]) else { return false; }
    out_inv.append(v[0..n]);
    return true;
}

// Computes Chaum-blinded `out = base^exp mod m` using public exponent `pub_exp`:
// samples random `r in [2, m-1]` with `gcd(r, m) = 1`, evaluates `((base * r^pub_exp)^exp * r^-1) mod m`.
// crap:ignore
fn rsa_mod_exp_blinded(
    base:    const u8[:],
    exp:     const u8[:],
    pub_exp: const u8[:],
    m:       const u8[:],
    out:     u8[..512]&,
) -> bool {
    let k = m.len;
    guard k >= RSA_MIN_MODULUS_BYTES && k <= 512 && base.len == k && exp.len > 0 && exp.len <= 512 else {
        return false;
    }
    guard is_valid_rsa_public_exponent(pub_exp, m) && rsa_be_cmp(base, m) < 0 else { return false; }

    var m_limbs:     u32[..128] = [];
    var r_limbs:     u32[..128] = [];
    var r_inv_limbs: u32[..128] = [];
    var r_be:        u8[512]    = [0; 512];
    var r_inv_be:    u8[..512]  = [];
    var r_e:         u8[..512]  = [];
    var blind_base:  u8[..512]  = [];
    var blind_res:   u8[..512]  = [];
    defer rsa_zeroize_limbs(r_limbs[..]);
    defer rsa_zeroize_limbs(r_inv_limbs[..]);
    defer secure_zeroize_slice(r_be[0..k]);
    defer secure_zeroize_slice(r_inv_be[..]);
    defer secure_zeroize_slice(r_e[..]);
    defer secure_zeroize_slice(blind_base[..]);
    defer secure_zeroize_slice(blind_res[..]);

    rsa_be_to_limbs(m, m_limbs);
    var found = false;
    for _ in 8 {
        guard csprng_fill(r_be[1..k]) else { break; }
        r_be[0] = 0x00;
        r_be[k - 2] |= 0x01;
        r_be[k - 1] |= 0x01;
        rsa_be_to_limbs(r_be[0..k], r_limbs);
        if rsa_limbs_mod_inv(r_limbs[..], m_limbs[..], r_inv_limbs) {
            found = true;
            break;
        }
    }
    guard found else { return false; }

    rsa_limbs_to_be(r_inv_limbs[..], k, r_inv_be);
    guard rsa_mod_exp(r_be[0..k], pub_exp, m, r_e) else { return false; }
    rsa_be_mul_mod(base, r_e[..], m, blind_base);
    guard rsa_mod_exp(blind_base[..], exp, m, blind_res) else { return false; }
    rsa_be_mul_mod(blind_res[..], r_inv_be[..], m, out);
    return out.len == k;
}

// Computes full-width exponent-blinded `out = base^exp mod m` via additive splitting `exp = (exp - r) + r`
// using a `(exp.len - 1)`-byte CSPRNG mask `r`. Fails closed on CSPRNG error or degenerate exponent.
// crap:ignore
fn rsa_mod_exp_exp_blinded(base: const u8[:], exp: const u8[:], m: const u8[:], out: u8[..512]&) -> bool {
    let k = m.len;
    guard k >= RSA_MIN_MODULUS_BYTES && k <= 512 && base.len == k && exp.len > 1 && exp.len <= 512 else {
        return false;
    }
    var r_be:     u8[512]   = [0; 512];
    var d_masked: u8[512]   = [0; 512];
    var part1:    u8[..512] = [];
    var part2:    u8[..512] = [];
    defer secure_zeroize_slice(r_be[0..exp.len]);
    defer secure_zeroize_slice(d_masked[0..exp.len]);
    defer secure_zeroize_slice(part1[..]);
    defer secure_zeroize_slice(part2[..]);

    var split_ok = false;
    for _ in 8 {
        r_be[0] = 0x00;
        guard csprng_fill(r_be[1..exp.len]) else { return false; }
        r_be[exp.len - 1] |= 0x01;
        var borrow:  u32 = 0;
        var nonzero: u8  = 0;
        var idx = exp.len - 1;
        while idx >= 0 {
            let diff = (exp[idx] as u32) - r_be[idx] - borrow;
            let out_b = (diff & 0xFF) as u8;
            d_masked[idx] = out_b;
            nonzero |= out_b;
            borrow = diff >> 31;
            idx -= 1;
        }
        if borrow == 0 && nonzero != 0 {
            split_ok = true;
            break;
        }
    }
    guard split_ok else { return false; }
    guard rsa_mod_exp(base, d_masked[0..exp.len], m, part1) else { return false; }
    guard rsa_mod_exp(base, r_be[0..exp.len], m, part2) else { return false; }
    rsa_be_mul_mod(part1[..], part2[..], m, out);
    return out.len == k;
}

// Validates that an RSA public exponent `e_be` is an odd integer in `3 <= e < n` with odd >=2048-bit modulus `n`.
// crap:ignore
fn is_valid_rsa_public_exponent(e_be: const u8[:], n_be: const u8[:]) -> bool {
    guard e_be.len > 0 && n_be.len >= RSA_MIN_MODULUS_BYTES && (n_be[n_be.len - 1] & 1) == 1 else {
        return false;
    }
    var start: i64 = 0;
    while start < e_be.len && e_be[start] == 0 {
        start += 1;
    }
    let e_trim = e_be[start..e_be.len];
    guard e_trim.len >= 1 && e_trim.len <= n_be.len else { return false; }
    guard (e_trim[e_trim.len - 1] & 1) == 1 else { return false; }
    guard e_trim.len > 1 || e_trim[0] >= 3 else { return false; }
    if e_trim.len == n_be.len {
        guard rsa_be_cmp(e_trim, n_be) < 0 else { return false; }
    }
    return true;
}

// ---- ASN.1 DER RSAPublicKey Parser (RFC 8017 Appendix A.1.1) -------------

// Reads an ASN.1 DER tag and length at `idx`, advancing `idx` to the value payload.
// Leaves `idx` unchanged on error.
//
// Example:
//   der = [0x02, 0x81, 0x80, ...], idx = 0
//   returns: tag = 0x02, len = 128, ok = true, idx = 3
// crap:ignore
fn parse_der_tlv_header(der: const u8[:], idx: i64&) -> u8, i64, bool {
    guard idx + 2 <= der.len else { return 0, 0, false; }
    let tag = der[idx];
    let b1 = der[idx + 1];
    var next_idx = idx + 2;
    if (b1 & 0x80) == 0 {
        let len = b1 as i64;
        guard next_idx + len <= der.len else { return 0, 0, false; }
        idx = next_idx;
        return tag, len, true;
    }
    let num_bytes = (b1 & 0x7F) as i64;
    guard num_bytes >= 1 && num_bytes <= 2 && next_idx + num_bytes <= der.len else { return 0, 0, false; }
    var len: i64 = 0;
    for i in num_bytes {
        len = (len << 8) | der[next_idx + i];
    }
    guard (num_bytes == 1 && len >= 128) || (num_bytes == 2 && len >= 256) else { return 0, 0, false; }
    next_idx += num_bytes;
    guard next_idx + len <= der.len else { return 0, 0, false; }
    idx = next_idx;
    return tag, len, true;
}

// Parses an ASN.1 DER `RSAPublicKey ::= SEQUENCE { modulus INTEGER, publicExponent INTEGER }`.
// Strips a single leading `0x00` sign-padding byte from positive DER integers.
//
// Example:
//   der = [0x30, ..., 0x02, ..., 0x00, N..., 0x02, 0x03, 0x01, 0x00, 0x01]
//   returns: n_be = N, e_be = [0x01, 0x00, 0x01], ok = true
// crap:ignore
fn parse_rsa_public_key_der(der: const u8[:]) -> const u8[:], const u8[:], bool {
    var idx: i64 = 0;
    let seq_tag, seq_len, seq_ok = parse_der_tlv_header(der, idx);
    guard seq_ok && seq_tag == 0x30 && idx + seq_len == der.len else { return "", "", false; }

    let n_tag, n_len, n_ok = parse_der_tlv_header(der, idx);
    guard n_ok && n_tag == 0x02 && n_len >= RSA_MIN_MODULUS_BYTES else { return "", "", false; }
    var n_slice = der[idx..idx + n_len];
    idx += n_len;
    guard (n_slice[0] & 0x80) == 0 else { return "", "", false; }
    if n_slice[0] == 0x00 {
        guard n_slice.len > 1 && (n_slice[1] & 0x80) != 0 else { return "", "", false; }
        n_slice = n_slice[1..n_slice.len];
    }
    guard n_slice.len >= RSA_MIN_MODULUS_BYTES && n_slice[0] != 0 &&
        (n_slice.len > RSA_MIN_MODULUS_BYTES || (n_slice[0] & 0x80) != 0) else {
        return "", "", false;
    }

    let e_tag, e_len, e_ok = parse_der_tlv_header(der, idx);
    guard e_ok && e_tag == 0x02 && e_len >= 1 && idx + e_len == der.len else { return "", "", false; }
    var e_slice = der[idx..idx + e_len];
    guard (e_slice[0] & 0x80) == 0 else { return "", "", false; }
    if e_slice[0] == 0x00 {
        guard e_slice.len > 1 && (e_slice[1] & 0x80) != 0 else { return "", "", false; }
        e_slice = e_slice[1..e_slice.len];
    }
    guard is_valid_rsa_public_exponent(e_slice, n_slice) else { return "", "", false; }
    return n_slice, e_slice, true;
}

// ---- EMSA-PKCS1-v1_5 Encoding & Verification (RFC 8017 Section 9.2) ------

// DigestInfo DER prefix for SHA-256 (19 bytes)
const PKCS1_DIGESTINFO_SHA256: const u8[19] = [
    0x30, 0x31, 0x30, 0x0D, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01,
    0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20,
];

// DigestInfo DER prefix for SHA-384 (19 bytes)
const PKCS1_DIGESTINFO_SHA384: const u8[19] = [
    0x30, 0x41, 0x30, 0x0D, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01,
    0x65, 0x03, 0x04, 0x02, 0x02, 0x05, 0x00, 0x04, 0x30,
];

// Builds an EMSA-PKCS1-v1_5 encoded message block of length `em_len`.
// crap:ignore
fn build_emsa_pkcs1_v15(
    digest_info_prefix: const u8[:],
    hash:               const u8[:],
    em_len:             i64,
    out_em:             u8[..512]&,
) -> bool {
    let t_len = digest_info_prefix.len + hash.len;
    guard em_len >= t_len + 11 && em_len <= 512 else { return false; }
    out_em.clear();
    out_em.push(0x00);
    out_em.push(0x01);
    let ps_len = em_len - t_len - 3;
    for i in ps_len {
        out_em.push(0xFF);
    }
    out_em.push(0x00);
    out_em.append(digest_info_prefix);
    out_em.append(hash);
    return true;
}

// Verifies an RSASSA-PKCS1-v1_5 SHA-256 signature using big-endian modulus `n_be` and exponent `e_be`.
// crap:ignore
fn rsa_pkcs1_sha256_verify(n_be: const u8[:], e_be: const u8[:], message: const u8[:], sig: const u8[:]) -> bool {
    guard sig.len == n_be.len && is_valid_rsa_public_exponent(e_be, n_be) else { return false; }
    var em: u8[..512] = [];
    guard rsa_mod_exp(sig, e_be, n_be, em) else { return false; }
    let digest = sha256(message);
    var expected_em: u8[..512] = [];
    guard build_emsa_pkcs1_v15(PKCS1_DIGESTINFO_SHA256[..], digest[..], n_be.len, expected_em) else { return false; }
    return ct_eq_bytes(em[..], expected_em[..]);
}

// Verifies an RSASSA-PKCS1-v1_5 SHA-384 signature using big-endian modulus `n_be` and exponent `e_be`.
// crap:ignore
fn rsa_pkcs1_sha384_verify(n_be: const u8[:], e_be: const u8[:], message: const u8[:], sig: const u8[:]) -> bool {
    guard sig.len == n_be.len && is_valid_rsa_public_exponent(e_be, n_be) else { return false; }
    var em: u8[..512] = [];
    guard rsa_mod_exp(sig, e_be, n_be, em) else { return false; }
    let digest = sha384(message);
    var expected_em: u8[..512] = [];
    guard build_emsa_pkcs1_v15(PKCS1_DIGESTINFO_SHA384[..], digest[..], n_be.len, expected_em) else { return false; }
    return ct_eq_bytes(em[..], expected_em[..]);
}

// Verifies an RSASSA-PKCS1-v1_5 SHA-256 signature against an ASN.1 DER `RSAPublicKey`.
fn rsa_pkcs1_sha256_verify_der(spki_pubkey_der: const u8[:], message: const u8[:], sig: const u8[:]) -> bool {
    let n_be, e_be, ok = parse_rsa_public_key_der(spki_pubkey_der);
    guard ok else { return false; }
    return rsa_pkcs1_sha256_verify(n_be, e_be, message, sig);
}

// Verifies an RSASSA-PKCS1-v1_5 SHA-384 signature against an ASN.1 DER `RSAPublicKey`.
fn rsa_pkcs1_sha384_verify_der(spki_pubkey_der: const u8[:], message: const u8[:], sig: const u8[:]) -> bool {
    let n_be, e_be, ok = parse_rsa_public_key_der(spki_pubkey_der);
    guard ok else { return false; }
    return rsa_pkcs1_sha384_verify(n_be, e_be, message, sig);
}

// Generates an RSASSA-PKCS1-v1_5 SHA-256 signature using big-endian modulus `n_be` and private exponent `d_be`.
// crap:ignore
fn rsa_pkcs1_sha256_sign(
    n_be:    const u8[:],
    d_be:    const u8[:],
    message: const u8[:],
    out_sig: u8[..512]&,
) -> bool {
    let digest = sha256(message);
    var em: u8[..512] = [];
    defer secure_zeroize_slice(em[..]);
    guard build_emsa_pkcs1_v15(PKCS1_DIGESTINFO_SHA256[..], digest[..], n_be.len, em) else { return false; }
    return rsa_mod_exp_exp_blinded(em[..], d_be, n_be, out_sig);
}

// Generates a Chaum-blinded RSASSA-PKCS1-v1_5 SHA-256 signature using `(n_be, d_be, e_be)`.
// crap:ignore
fn rsa_pkcs1_sha256_sign_blinded(
    n_be:    const u8[:],
    d_be:    const u8[:],
    e_be:    const u8[:],
    message: const u8[:],
    out_sig: u8[..512]&,
) -> bool {
    let digest = sha256(message);
    var em: u8[..512] = [];
    defer secure_zeroize_slice(em[..]);
    guard build_emsa_pkcs1_v15(PKCS1_DIGESTINFO_SHA256[..], digest[..], n_be.len, em) else { return false; }
    return rsa_mod_exp_blinded(em[..], d_be, e_be, n_be, out_sig);
}

// ---- MGF1 & RSASSA-PSS Encoding / Verification (RFC 8017 Section 9.1) ----

// XORs a block of MGF1 mask bytes into `dst` starting at `offset`.
// crap:ignore
fn rsa_mgf1_xor_block(blk: const u8[:], dst: u8[:], offset: i64) {
    let limit = min(blk.len, dst.len - offset);
    for i in limit {
        dst[offset + i] ^= blk[i];
    }
}

// Mask Generation Function MGF1 (RFC 8017 Appendix B.2.1) supporting SHA-256 (32), SHA-384 (48), and SHA-512 (64).
// crap:ignore
fn rsa_mgf1_xor(seed: const u8[:], hash_len: i64, dst: u8[:]) {
    guard seed.len <= 64 && (hash_len == 32 || hash_len == 48 || hash_len == 64) else { return; }
    var counter: u32      = 0;
    var offset:  i64      = 0;
    var hash_in: u8[..68] = [];
    while offset < dst.len {
        hash_in.clear();
        hash_in.append(seed);
        hash_in.push(((counter >> 24) & 0xFF) as u8);
        hash_in.push(((counter >> 16) & 0xFF) as u8);
        hash_in.push(((counter >> 8) & 0xFF) as u8);
        hash_in.push((counter & 0xFF) as u8);
        if hash_len == 32 {
            let blk = sha256(hash_in[..]);
            rsa_mgf1_xor_block(blk[..], dst, offset);
            offset += 32;
        } else if hash_len == 48 {
            let blk = sha384(hash_in[..]);
            rsa_mgf1_xor_block(blk[..], dst, offset);
            offset += 48;
        } else {
            let blk = sha512(hash_in[..]);
            rsa_mgf1_xor_block(blk[..], dst, offset);
            offset += 64;
        }
        counter += 1;
    }
}

// Computes the leftmost-bit mask for EMSA-PSS `EM[0]` from `mod_first_byte` (RFC 8017 Section 9.1.1).
// crap:ignore
inline fn pss_top_mask(mod_first_byte: u8) -> u8 {
    if mod_first_byte <= 1 {
        return 0xFF;
    }
    var top_mask: u8 = 0xFF;
    var b = mod_first_byte;
    while (b & 0x80) == 0 && b != 0 {
        top_mask >>= 1;
        b <<= 1;
    }
    return top_mask >> 1;
}

// Verifies an EMSA-PSS encoded block `em` against `m_hash` with salt length equal to `m_hash.len`.
// crap:ignore
fn verify_emsa_pss(em: const u8[:], m_hash: const u8[:], mod_first_byte: u8) -> bool {
    let h_len = m_hash.len;
    let em_len = em.len;
    guard (h_len == 32 || h_len == 48 || h_len == 64) && mod_first_byte >= 1 else { return false; }
    guard em_len >= h_len + h_len + 2 && em_len <= 512 else { return false; }
    guard em[em_len - 1] == 0xBC else { return false; }

    let top_mask = pss_top_mask(mod_first_byte);
    guard (em[0] & (~top_mask)) == 0 else { return false; }

    let db_len = em_len - h_len - 1;
    var db: u8[512] = [0; 512];
    for i in db_len {
        db[i] = em[i];
    }
    let h_slice = em[db_len..db_len + h_len];
    rsa_mgf1_xor(h_slice, h_len, db[0..db_len]);
    db[0] &= top_mask;

    let zero_pad_len = db_len - h_len - 1;
    for i in zero_pad_len {
        guard db[i] == 0x00 else { return false; }
    }
    guard db[zero_pad_len] == 0x01 else { return false; }

    let salt = db[zero_pad_len + 1..db_len];
    var m_prime: u8[..136] = [];
    for z in 8 {
        m_prime.push(0x00);
    }
    m_prime.append(m_hash);
    m_prime.append(salt);

    if h_len == 32 {
        let h_calc = sha256(m_prime[..]);
        return ct_eq_bytes(h_calc[..], h_slice);
    }
    if h_len == 48 {
        let h_calc = sha384(m_prime[..]);
        return ct_eq_bytes(h_calc[..], h_slice);
    }
    let h_calc = sha512(m_prime[..]);
    return ct_eq_bytes(h_calc[..], h_slice);
}

// Verifies an RSASSA-PSS SHA-256 signature using big-endian modulus `n_be` and exponent `e_be`.
// crap:ignore
fn rsa_pss_sha256_verify(n_be: const u8[:], e_be: const u8[:], message: const u8[:], sig: const u8[:]) -> bool {
    guard sig.len == n_be.len && is_valid_rsa_public_exponent(e_be, n_be) else { return false; }
    var em: u8[..512] = [];
    guard rsa_mod_exp(sig, e_be, n_be, em) else { return false; }
    let m_hash = sha256(message);
    if n_be[0] == 1 {
        guard em.len > 1 && em[0] == 0x00 else { return false; }
        return verify_emsa_pss(em[1..], m_hash[..], 1);
    }
    return verify_emsa_pss(em[..], m_hash[..], n_be[0]);
}

// Verifies an RSASSA-PSS SHA-384 signature using big-endian modulus `n_be` and exponent `e_be`.
// crap:ignore
fn rsa_pss_sha384_verify(n_be: const u8[:], e_be: const u8[:], message: const u8[:], sig: const u8[:]) -> bool {
    guard sig.len == n_be.len && is_valid_rsa_public_exponent(e_be, n_be) else { return false; }
    var em: u8[..512] = [];
    guard rsa_mod_exp(sig, e_be, n_be, em) else { return false; }
    let m_hash = sha384(message);
    if n_be[0] == 1 {
        guard em.len > 1 && em[0] == 0x00 else { return false; }
        return verify_emsa_pss(em[1..], m_hash[..], 1);
    }
    return verify_emsa_pss(em[..], m_hash[..], n_be[0]);
}

// Verifies an RSASSA-PSS SHA-512 signature using big-endian modulus `n_be` and exponent `e_be`.
// crap:ignore
fn rsa_pss_sha512_verify(n_be: const u8[:], e_be: const u8[:], message: const u8[:], sig: const u8[:]) -> bool {
    guard sig.len == n_be.len && is_valid_rsa_public_exponent(e_be, n_be) else { return false; }
    var em: u8[..512] = [];
    guard rsa_mod_exp(sig, e_be, n_be, em) else { return false; }
    let m_hash = sha512(message);
    if n_be[0] == 1 {
        guard em.len > 1 && em[0] == 0x00 else { return false; }
        return verify_emsa_pss(em[1..], m_hash[..], 1);
    }
    return verify_emsa_pss(em[..], m_hash[..], n_be[0]);
}

// Verifies an RSASSA-PSS SHA-256 signature against an ASN.1 DER `RSAPublicKey`.
fn rsa_pss_sha256_verify_der(spki_pubkey_der: const u8[:], message: const u8[:], sig: const u8[:]) -> bool {
    let n_be, e_be, ok = parse_rsa_public_key_der(spki_pubkey_der);
    guard ok else { return false; }
    return rsa_pss_sha256_verify(n_be, e_be, message, sig);
}

// Verifies an RSASSA-PSS SHA-384 signature against an ASN.1 DER `RSAPublicKey`.
fn rsa_pss_sha384_verify_der(spki_pubkey_der: const u8[:], message: const u8[:], sig: const u8[:]) -> bool {
    let n_be, e_be, ok = parse_rsa_public_key_der(spki_pubkey_der);
    guard ok else { return false; }
    return rsa_pss_sha384_verify(n_be, e_be, message, sig);
}

// Verifies an RSASSA-PSS SHA-512 signature against an ASN.1 DER `RSAPublicKey`.
fn rsa_pss_sha512_verify_der(spki_pubkey_der: const u8[:], message: const u8[:], sig: const u8[:]) -> bool {
    let n_be, e_be, ok = parse_rsa_public_key_der(spki_pubkey_der);
    guard ok else { return false; }
    return rsa_pss_sha512_verify(n_be, e_be, message, sig);
}

// Encodes an EMSA-PSS message block of length `em_len` using `m_hash` and `salt`.
// crap:ignore
fn encode_emsa_pss(
    m_hash:         const u8[:],
    salt:           const u8[:],
    em_len:         i64,
    mod_first_byte: u8,
    out_em:         u8[..512]&,
) -> bool {
    let h_len = m_hash.len;
    let s_len = salt.len;
    guard (h_len == 32 || h_len == 48 || h_len == 64) && mod_first_byte >= 1 else { return false; }
    guard s_len == h_len && em_len >= h_len + s_len + 2 && em_len <= 512 else { return false; }

    var m_prime: u8[..136] = [];
    for z in 8 {
        m_prime.push(0x00);
    }
    m_prime.append(m_hash);
    m_prime.append(salt);

    var h_buf: u8[..64] = [];
    if h_len == 32 {
        let d = sha256(m_prime[..]);
        h_buf.append(d[..]);
    } else if h_len == 48 {
        let d = sha384(m_prime[..]);
        h_buf.append(d[..]);
    } else {
        let d = sha512(m_prime[..]);
        h_buf.append(d[..]);
    }

    let db_len = em_len - h_len - 1;
    let zero_pad_len = db_len - s_len - 1;
    var db: u8[512] = [0; 512];
    db[zero_pad_len] = 0x01;
    for i in s_len {
        db[zero_pad_len + 1 + i] = salt[i];
    }
    rsa_mgf1_xor(h_buf[..], h_len, db[0..db_len]);
    db[0] &= pss_top_mask(mod_first_byte);

    out_em.clear();
    out_em.append(db[0..db_len]);
    out_em.append(h_buf[..]);
    out_em.push(0xBC);
    return true;
}

// Encodes an EMSA-PSS message block sized for modulus `n_be` (prepending `0x00` when `n_be[0] == 1`).
// crap:ignore
fn encode_pss_for_modulus(
    m_hash: const u8[:],
    salt:   const u8[:],
    n_be:   const u8[:],
    out_em: u8[..512]&,
) -> bool {
    if n_be[0] == 1 {
        var sub_em: u8[..512] = [];
        guard encode_emsa_pss(m_hash, salt, n_be.len - 1, 1, sub_em) else { return false; }
        out_em.clear();
        out_em.push(0x00);
        out_em.append(sub_em[..]);
        secure_zeroize_slice(sub_em[..]);
        return true;
    }
    return encode_emsa_pss(m_hash, salt, n_be.len, n_be[0], out_em);
}

// Generates an RSASSA-PSS SHA-256 signature using big-endian modulus `n_be`, exponent `d_be`, and 32-byte `salt`.
// crap:ignore
fn rsa_pss_sha256_sign(
    n_be:    const u8[:],
    d_be:    const u8[:],
    salt:    const u8[:],
    message: const u8[:],
    out_sig: u8[..512]&,
) -> bool {
    guard n_be.len >= RSA_MIN_MODULUS_BYTES && salt.len == 32 else { return false; }
    let m_hash = sha256(message);
    var em: u8[..512] = [];
    defer secure_zeroize_slice(em[..]);
    guard encode_pss_for_modulus(m_hash[..], salt, n_be, em) else { return false; }
    return rsa_mod_exp_exp_blinded(em[..], d_be, n_be, out_sig);
}

// Generates a Chaum-blinded RSASSA-PSS SHA-256 signature using `(n_be, d_be, e_be)` and 32-byte `salt`.
// crap:ignore
fn rsa_pss_sha256_sign_blinded(
    n_be:    const u8[:],
    d_be:    const u8[:],
    e_be:    const u8[:],
    salt:    const u8[:],
    message: const u8[:],
    out_sig: u8[..512]&,
) -> bool {
    guard n_be.len >= RSA_MIN_MODULUS_BYTES && salt.len == 32 else { return false; }
    let m_hash = sha256(message);
    var em: u8[..512] = [];
    defer secure_zeroize_slice(em[..]);
    guard encode_pss_for_modulus(m_hash[..], salt, n_be, em) else { return false; }
    return rsa_mod_exp_blinded(em[..], d_be, e_be, n_be, out_sig);
}

// Generates an RSASSA-PSS SHA-512 signature using big-endian modulus `n_be`, exponent `d_be`, and 64-byte `salt`.
// crap:ignore
fn rsa_pss_sha512_sign(
    n_be:    const u8[:],
    d_be:    const u8[:],
    salt:    const u8[:],
    message: const u8[:],
    out_sig: u8[..512]&,
) -> bool {
    guard n_be.len >= RSA_MIN_MODULUS_BYTES && salt.len == 64 else { return false; }
    let m_hash = sha512(message);
    var em: u8[..512] = [];
    defer secure_zeroize_slice(em[..]);
    guard encode_pss_for_modulus(m_hash[..], salt, n_be, em) else { return false; }
    return rsa_mod_exp_exp_blinded(em[..], d_be, n_be, out_sig);
}
