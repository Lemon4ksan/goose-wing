// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Advanced Encryption Standard (AES) FIPS 197 and Galois/Counter Mode (AES-GCM) NIST SP 800-38D.
// Zero dynamic heap allocations on key expansion, block encryption, and AEAD authentication.
namespace core;

import std;

// Hardware-accelerated AES-NI + PCLMULQDQ (with constant-time scalar fallback) AEAD shims.
extern fn native_aes_gcm_seal_aead(
    key:     const u8[:],
    iv:      const u8[:],
    src:     const u8[:],
    aad:     const u8[:],
    dst:     u8[:],
    tag_out: u8[:],
) -> i64 = "wing_aes_gcm_seal_aead";

extern fn native_aes_gcm_open_aead(
    key: const u8[:],
    iv:  const u8[:],
    src: const u8[:],
    aad: const u8[:],
    tag: const u8[:],
    dst: u8[:],
) -> i64 = "wing_aes_gcm_open_aead";

extern fn native_aes_gcm_prepare_key(key: const u8[:], ctx_out: u8[:]) -> i32 = "wing_aes_gcm_prepare_key";

extern fn native_aes_gcm_seal_prepared(
    ctx:     const u8[:],
    iv:      const u8[:],
    src:     const u8[:],
    aad:     const u8[:],
    dst:     u8[:],
    tag_out: u8[:],
) -> i64 = "wing_aes_gcm_seal_prepared";

extern fn native_aes_gcm_open_prepared(
    ctx: const u8[:],
    iv:  const u8[:],
    src: const u8[:],
    aad: const u8[:],
    tag: const u8[:],
    dst: u8[:],
) -> i64 = "wing_aes_gcm_open_prepared";

let AES_RCON: const u32[10] = [
    0x01000000, 0x02000000, 0x04000000, 0x08000000, 0x10000000,
    0x20000000, 0x40000000, 0x80000000, 0x1b000000, 0x36000000,
];

// Bitsliced GF(2^4) multiplicative inversion core for the Boyar-Peralta (2010) AES S-box.
// crap:ignore
inline fn aes_sbox_gf16_inv(t21: u32, t22: u32, t23: u32, t24: u32) -> u32, u32, u32, u32 {
    let t25 = t21 ^ t22;
    let t26 = t21 & t23;
    let t27 = t24 ^ t26;
    let t28 = t25 & t27;
    let t29 = t28 ^ t22;
    let t30 = t23 ^ t24;
    let t31 = t22 ^ t26;
    let t32 = t31 & t30;
    let t33 = t32 ^ t24;
    let t34 = t23 ^ t33;
    let t35 = t27 ^ t33;
    let t36 = t24 & t35;
    let t37 = t36 ^ t34;
    let t38 = t27 ^ t36;
    let t39 = t29 & t38;
    let t40 = t25 ^ t39;
    return t29, t33, t37, t40;
}

// Bitsliced bottom affine transform for the Boyar-Peralta (2010) AES S-box.
// crap:ignore
inline fn aes_sbox_bottom_linear(z: const u32[18]&, bp: u32[8]&) {
    let t46 = z[15] ^ z[16];
    let t47 = z[10] ^ z[11];
    let t48 = z[5] ^ z[13];
    let t49 = z[9] ^ z[10];
    let t50 = z[2] ^ z[12];
    let t51 = z[2] ^ z[5];
    let t52 = z[7] ^ z[8];
    let t53 = z[0] ^ z[3];
    let t54 = z[6] ^ z[7];
    let t55 = z[16] ^ z[17];
    let t56 = z[12] ^ t48;
    let t57 = t50 ^ t53;
    let t58 = z[4] ^ t46;
    let t59 = z[3] ^ t54;
    let t60 = t46 ^ t57;
    let t61 = z[14] ^ t57;
    let t62 = t52 ^ t58;
    let t63 = t49 ^ t58;
    let t64 = z[4] ^ t59;
    let t65 = t61 ^ t62;
    let t66 = z[1] ^ t63;
    let t67 = t64 ^ t65;
    let s3 = t53 ^ t66;
    bp[0] = t59 ^ t63;
    bp[1] = t64 ^ (~s3);
    bp[2] = t55 ^ (~t67);
    bp[3] = s3;
    bp[4] = t51 ^ t66;
    bp[5] = t47 ^ t65;
    bp[6] = t56 ^ (~t62);
    bp[7] = t48 ^ (~t60);
}

// Evaluates the FIPS 197 AES S-box across up to 32 bytes in parallel using Boyar-Peralta (2010)
// bit-sliced boolean gates (bp[0] = MSB bit 7, bp[7] = LSB bit 0; zero table lookups or branches).
// crap:ignore
inline fn aes_sbox_bitslice(bp: u32[8]&) {
    let x0 = bp[0]; let x1 = bp[1]; let x2 = bp[2]; let x3 = bp[3];
    let x4 = bp[4]; let x5 = bp[5]; let x6 = bp[6]; let x7 = bp[7];
    let y14 = x3 ^ x5;
    let y13 = x0 ^ x6;
    let y9 = x0 ^ x3;
    let y8 = x0 ^ x5;
    let t0 = x1 ^ x2;
    let y1 = t0 ^ x7;
    let y4 = y1 ^ x3;
    let y12 = y13 ^ y14;
    let y2 = y1 ^ x0;
    let y5 = y1 ^ x6;
    let y3 = y5 ^ y8;
    let t1 = x4 ^ y12;
    let y15 = t1 ^ x5;
    let y20 = t1 ^ x1;
    let y6 = y15 ^ x7;
    let y10 = y15 ^ t0;
    let y11 = y20 ^ y9;
    let y7 = x7 ^ y11;
    let y17 = y10 ^ y11;
    let y19 = y10 ^ y8;
    let y16 = t0 ^ y11;
    let y21 = y13 ^ y16;
    let y18 = x0 ^ y16;
    let t2 = y12 & y15;
    let t4 = (y3 & y6) ^ t2;
    let t6 = (y4 & x7) ^ t2;
    let t7 = y13 & y16;
    let t9 = (y5 & y1) ^ t7;
    let t11 = (y2 & y7) ^ t7;
    let t12 = y9 & y11;
    let t14 = (y14 & y17) ^ t12;
    let t16 = (y8 & y10) ^ t12;
    let t21 = (t4 ^ t14) ^ y20;
    let t22 = (t6 ^ t16) ^ y19;
    let t23 = (t9 ^ t14) ^ y21;
    let t24 = (t11 ^ t16) ^ y18;
    let t29, t33, t37, t40 = aes_sbox_gf16_inv(t21, t22, t23, t24);
    let t41 = t40 ^ t37;
    let t42 = t29 ^ t33;
    let t43 = t29 ^ t40;
    let t44 = t33 ^ t37;
    let t45 = t42 ^ t41;
    let z: u32[18] = [
        t44 & y15, t37 & y6, t33 & x7, t43 & y16, t40 & y1, t29 & y7,
        t42 & y11, t45 & y17, t41 & y10, t44 & y12, t37 & y3, t33 & y4,
        t43 & y13, t40 & y5, t29 & y2, t42 & y9, t45 & y14, t41 & y8,
    ];
    aes_sbox_bottom_linear(z, bp);
}

// Constant-time bitsliced AES S-box over `buf` (`buf.len <= 16`) in parallel.
// crap:ignore
inline fn aes_sub_slice(buf: u8[:]) {
    var bp: u32[8] = [0; 8];
    for i in buf.len {
        let b = buf[i] as u32;
        let sh = i as u32;
        bp[0] |= ((b >> 7) & 1) << sh;
        bp[1] |= ((b >> 6) & 1) << sh;
        bp[2] |= ((b >> 5) & 1) << sh;
        bp[3] |= ((b >> 4) & 1) << sh;
        bp[4] |= ((b >> 3) & 1) << sh;
        bp[5] |= ((b >> 2) & 1) << sh;
        bp[6] |= ((b >> 1) & 1) << sh;
        bp[7] |= (b & 1) << sh;
    }
    aes_sbox_bitslice(bp);
    for i in buf.len {
        let sh = i as u32;
        let b = (((bp[0] >> sh) & 1) << 7) | (((bp[1] >> sh) & 1) << 6) |
                (((bp[2] >> sh) & 1) << 5) | (((bp[3] >> sh) & 1) << 4) |
                (((bp[4] >> sh) & 1) << 3) | (((bp[5] >> sh) & 1) << 2) |
                (((bp[6] >> sh) & 1) << 1) | ((bp[7] >> sh) & 1);
        buf[i] = b as u8;
    }
}

// Constant-time bitsliced AES SubWord over 4 bytes in parallel.
// crap:ignore
inline fn aes_sub_word(w: u32) -> u32 {
    var bytes: u8[4] = [
        ((w >> 24) & 0xFF) as u8,
        ((w >> 16) & 0xFF) as u8,
        ((w >> 8) & 0xFF) as u8,
        (w & 0xFF) as u8,
    ];
    aes_sub_slice(bytes[..]);
    return ((bytes[0] as u32) << 24) |
           ((bytes[1] as u32) << 16) |
           ((bytes[2] as u32) << 8) |
           bytes[3];
}

inline fn aes_rot_word(w: u32) -> u32 {
    return (w << 8) | (w >> 24);
}

struct Aes256KeySchedule {
    round_keys: u32[60] = [0; 60],
}

// Zeroizes an AES-256 round key schedule in place.
// crap:ignore
inline fn zeroize_aes256_ks(ks: Aes256KeySchedule&) {
    secure_zeroize_u32_slice(ks.round_keys[..]);
}

fn aes256_key_schedule(key: const u8[32]&) -> Aes256KeySchedule {
    var ks = Aes256KeySchedule { .. };
    for i in 8 {
        let off = i * 4;
        ks.round_keys[i] = ((key[off] as u32) << 24) |
            ((key[off + 1] as u32) << 16) |
            ((key[off + 2] as u32) << 8) |
            key[off + 3];
    }
    for i in 8..60 {
        var temp = ks.round_keys[i - 1];
        if (i % 8) == 0 {
            temp = aes_sub_word(aes_rot_word(temp)) ^ AES_RCON[(i / 8) - 1];
        } else if (i % 8) == 4 {
            temp = aes_sub_word(temp);
        }
        ks.round_keys[i] = ks.round_keys[i - 8] ^ temp;
    }
    return ks;
}

inline fn xtime(b: u8) -> u8 {
    let msb = b >> 7;
    let mask = 0 - msb;
    return (b << 1) ^ (mask & 0x1b);
}

fn aes_encrypt_block(ks: const Aes256KeySchedule&, input: const u8[16]&) -> u8[16] {
    var state: u8[16] = [0; 16];
    for i in 16 { state[i] = input[i]; }

    // Initial round key addition
    for i in 4 {
        let rk = ks.round_keys[i];
        state[i * 4] ^= ((rk >> 24) & 0xFF) as u8;
        state[i * 4 + 1] ^= ((rk >> 16) & 0xFF) as u8;
        state[i * 4 + 2] ^= ((rk >> 8) & 0xFF) as u8;
        state[i * 4 + 3] ^= (rk & 0xFF) as u8;
    }

    // 13 main rounds
    for round in 1..14 {
        // SubBytes
        aes_sub_slice(state[..]);
        // ShiftRows
        let t1 = state[1]; state[1] = state[5]; state[5] = state[9]; state[9] = state[13]; state[13] = t1;
        let t2 = state[2]; state[2] = state[10]; state[10] = t2;
        let t6 = state[6]; state[6] = state[14]; state[14] = t6;
        let t3 = state[15]; state[15] = state[11]; state[11] = state[7]; state[7] = state[3]; state[3] = t3;
        // MixColumns
        for c in 4 {
            let col = c * 4;
            let a0 = state[col]; let a1 = state[col + 1];
            let a2 = state[col + 2]; let a3 = state[col + 3];
            state[col] = xtime(a0 ^ a1) ^ a1 ^ a2 ^ a3;
            state[col + 1] = xtime(a1 ^ a2) ^ a2 ^ a3 ^ a0;
            state[col + 2] = xtime(a2 ^ a3) ^ a3 ^ a0 ^ a1;
            state[col + 3] = xtime(a3 ^ a0) ^ a0 ^ a1 ^ a2;
        }
        // AddRoundKey
        let rk_base = round * 4;
        for i in 4 {
            let rk = ks.round_keys[rk_base + i];
            state[i * 4] ^= ((rk >> 24) & 0xFF) as u8;
            state[i * 4 + 1] ^= ((rk >> 16) & 0xFF) as u8;
            state[i * 4 + 2] ^= ((rk >> 8) & 0xFF) as u8;
            state[i * 4 + 3] ^= (rk & 0xFF) as u8;
        }
    }

    // Final round (no MixColumns)
    aes_sub_slice(state[..]);
    let t1 = state[1]; state[1] = state[5]; state[5] = state[9]; state[9] = state[13]; state[13] = t1;
    let t2 = state[2]; state[2] = state[10]; state[10] = t2;
    let t6 = state[6]; state[6] = state[14]; state[14] = t6;
    let t3 = state[15]; state[15] = state[11]; state[11] = state[7]; state[7] = state[3]; state[3] = t3;

    for i in 4 {
        let rk = ks.round_keys[56 + i];
        state[i * 4] ^= ((rk >> 24) & 0xFF) as u8;
        state[i * 4 + 1] ^= ((rk >> 16) & 0xFF) as u8;
        state[i * 4 + 2] ^= ((rk >> 8) & 0xFF) as u8;
        state[i * 4 + 3] ^= (rk & 0xFF) as u8;
    }
    return state;
}

// Constant-time GF(2^8) multiplication modulo x^8 + x^4 + x^3 + x + 1 (FIPS 197 Section 4.2).
// crap:ignore
inline fn aes_gf_mul(a_in: u8, b_in: u8) -> u8 {
    var a = a_in;
    var b = b_in;
    var p: u8 = 0;
    for _ in 8 {
        let mask: u8 = 0 - (b & 1);
        p ^= a & mask;
        a = xtime(a);
        b >>= 1;
    }
    return p;
}

// Constant-time FIPS 197 inverse S-box via inverse affine transform and GF(2^8) inversion (z^254).
// Zero lookup tables or secret-dependent branches (cache-timing safe).
// crap:ignore
inline fn aes_inv_sbox_byte(y: u8) -> u8 {
    let r1 = (y << 1) | (y >> 7);
    let r3 = (y << 3) | (y >> 5);
    let r6 = (y << 6) | (y >> 2);
    let z = r1 ^ r3 ^ r6 ^ 0x05;

    let z2 = aes_gf_mul(z, z);
    let z3 = aes_gf_mul(z2, z);
    let z6 = aes_gf_mul(z3, z3);
    let z12 = aes_gf_mul(z6, z6);
    let z15 = aes_gf_mul(z12, z3);
    let z30 = aes_gf_mul(z15, z15);
    let z60 = aes_gf_mul(z30, z30);
    let z120 = aes_gf_mul(z60, z60);
    let z126 = aes_gf_mul(z120, z6);
    let z252 = aes_gf_mul(z126, z126);
    return aes_gf_mul(z252, z2);
}

inline fn aes_inv_shift_rows(state: u8[16]&) {
    let t1 = state[13]; state[13] = state[9]; state[9] = state[5]; state[5] = state[1]; state[1] = t1;
    let t2 = state[2]; state[2] = state[10]; state[10] = t2;
    let t6 = state[6]; state[6] = state[14]; state[14] = t6;
    let t3 = state[3]; state[3] = state[7]; state[7] = state[11]; state[11] = state[15]; state[15] = t3;
}

// crap:ignore
inline fn aes_inv_mix_columns(state: u8[16]&) {
    for c: u64 in 4 {
        let col = c * 4;
        let s0 = state[col]; let s1 = state[col + 1];
        let s2 = state[col + 2]; let s3 = state[col + 3];
        state[col] = aes_gf_mul(s0, 0x0e) ^ aes_gf_mul(s1, 0x0b) ^
            aes_gf_mul(s2, 0x0d) ^ aes_gf_mul(s3, 0x09);
        state[col + 1] = aes_gf_mul(s0, 0x09) ^ aes_gf_mul(s1, 0x0e) ^
            aes_gf_mul(s2, 0x0b) ^ aes_gf_mul(s3, 0x0d);
        state[col + 2] = aes_gf_mul(s0, 0x0d) ^ aes_gf_mul(s1, 0x09) ^
            aes_gf_mul(s2, 0x0e) ^ aes_gf_mul(s3, 0x0b);
        state[col + 3] = aes_gf_mul(s0, 0x0b) ^ aes_gf_mul(s1, 0x0d) ^
            aes_gf_mul(s2, 0x09) ^ aes_gf_mul(s3, 0x0e);
    }
}

// crap:ignore
inline fn aes_add_round_key_256(ks: const Aes256KeySchedule&, rk_base: u64, state: u8[16]&) {
    for i: u64 in 4 {
        let rk = ks.round_keys[rk_base + i];
        state[i * 4] ^= ((rk >> 24) & 0xFF) as u8;
        state[i * 4 + 1] ^= ((rk >> 16) & 0xFF) as u8;
        state[i * 4 + 2] ^= ((rk >> 8) & 0xFF) as u8;
        state[i * 4 + 3] ^= (rk & 0xFF) as u8;
    }
}

// Decrypts a single 16-byte AES-256 block (FIPS 197 Section 5.3 InvCipher) in constant time.
fn aes256_decrypt_block(ks: const Aes256KeySchedule&, input: const u8[16]&) -> u8[16] {
    var state: u8[16] = [0; 16];
    for i: u64 in 16 { state[i] = input[i]; }

    aes_add_round_key_256(ks, 56, state);

    var rk_base: u64 = 52;
    while rk_base >= 4 {
        aes_inv_shift_rows(state);
        for i: u64 in 16 { state[i] = aes_inv_sbox_byte(state[i]); }
        aes_add_round_key_256(ks, rk_base, state);
        aes_inv_mix_columns(state);
        rk_base = core::sub_sat_u64(rk_base, 4);
    }

    aes_inv_shift_rows(state);
    for i: u64 in 16 { state[i] = aes_inv_sbox_byte(state[i]); }
    aes_add_round_key_256(ks, 0, state);
    return state;
}

struct Aes128KeySchedule {
    round_keys: u32[44] = [0; 44],
}

// Zeroizes an AES-128 round key schedule in place.
// crap:ignore
inline fn zeroize_aes128_ks(ks: Aes128KeySchedule&) {
    secure_zeroize_u32_slice(ks.round_keys[..]);
}

fn aes128_key_schedule(key: const u8[16]&) -> Aes128KeySchedule {
    var ks = Aes128KeySchedule { .. };
    for i in 4 {
        let off = i * 4;
        ks.round_keys[i] = ((key[off] as u32) << 24) |
            ((key[off + 1] as u32) << 16) |
            ((key[off + 2] as u32) << 8) |
            key[off + 3];
    }
    for i in 4..44 {
        var temp = ks.round_keys[i - 1];
        if (i % 4) == 0 {
            temp = aes_sub_word(aes_rot_word(temp)) ^ AES_RCON[(i / 4) - 1];
        }
        ks.round_keys[i] = ks.round_keys[i - 4] ^ temp;
    }
    return ks;
}

fn aes128_encrypt_block(ks: const Aes128KeySchedule&, input: const u8[16]&) -> u8[16] {
    var state: u8[16] = [0; 16];
    for i in 16 { state[i] = input[i]; }

    // Initial round key addition
    for i in 4 {
        let rk = ks.round_keys[i];
        state[i * 4] ^= ((rk >> 24) & 0xFF) as u8;
        state[i * 4 + 1] ^= ((rk >> 16) & 0xFF) as u8;
        state[i * 4 + 2] ^= ((rk >> 8) & 0xFF) as u8;
        state[i * 4 + 3] ^= (rk & 0xFF) as u8;
    }

    // 9 main rounds
    for round in 1..10 {
        aes_sub_slice(state[..]);
        let t1 = state[1]; state[1] = state[5]; state[5] = state[9]; state[9] = state[13]; state[13] = t1;
        let t2 = state[2]; state[2] = state[10]; state[10] = t2;
        let t6 = state[6]; state[6] = state[14]; state[14] = t6;
        let t3 = state[15]; state[15] = state[11]; state[11] = state[7]; state[7] = state[3]; state[3] = t3;

        for c in 4 {
            let col = c * 4;
            let a0 = state[col]; let a1 = state[col + 1];
            let a2 = state[col + 2]; let a3 = state[col + 3];
            state[col] = xtime(a0 ^ a1) ^ a1 ^ a2 ^ a3;
            state[col + 1] = xtime(a1 ^ a2) ^ a2 ^ a3 ^ a0;
            state[col + 2] = xtime(a2 ^ a3) ^ a3 ^ a0 ^ a1;
            state[col + 3] = xtime(a3 ^ a0) ^ a0 ^ a1 ^ a2;
        }

        let rk_base = round * 4;
        for i in 4 {
            let rk = ks.round_keys[rk_base + i];
            state[i * 4] ^= ((rk >> 24) & 0xFF) as u8;
            state[i * 4 + 1] ^= ((rk >> 16) & 0xFF) as u8;
            state[i * 4 + 2] ^= ((rk >> 8) & 0xFF) as u8;
            state[i * 4 + 3] ^= (rk & 0xFF) as u8;
        }
    }

    // Final round (no MixColumns)
    aes_sub_slice(state[..]);
    let t1 = state[1]; state[1] = state[5]; state[5] = state[9]; state[9] = state[13]; state[13] = t1;
    let t2 = state[2]; state[2] = state[10]; state[10] = t2;
    let t6 = state[6]; state[6] = state[14]; state[14] = t6;
    let t3 = state[15]; state[15] = state[11]; state[11] = state[7]; state[7] = state[3]; state[3] = t3;

    for i in 4 {
        let rk = ks.round_keys[40 + i];
        state[i * 4] ^= ((rk >> 24) & 0xFF) as u8;
        state[i * 4 + 1] ^= ((rk >> 16) & 0xFF) as u8;
        state[i * 4 + 2] ^= ((rk >> 8) & 0xFF) as u8;
        state[i * 4 + 3] ^= (rk & 0xFF) as u8;
    }
    return state;
}

// Converts a 1-bit predicate into an all-ones or all-zeros 64-bit constant-time mask.
// crap:ignore
inline fn ghash_bit_mask64(bit: u64) -> u64 {
    return 0 - (bit & 1);
}

// Constant-time GHASH multiplication in GF(2^128).
// crap:ignore
fn ghash_mul(x: const u8[16]&, y: const u8[16]&) -> u8[16] {
    var v_hi = ((y[0] as u64) << 56) | ((y[1] as u64) << 48) | ((y[2] as u64) << 40) | ((y[3] as u64) << 32) |
               ((y[4] as u64) << 24) | ((y[5] as u64) << 16) | ((y[6] as u64) << 8) | y[7];
    var v_lo = ((y[8] as u64) << 56) | ((y[9] as u64) << 48) | ((y[10] as u64) << 40) | ((y[11] as u64) << 32) |
               ((y[12] as u64) << 24) | ((y[13] as u64) << 16) | ((y[14] as u64) << 8) | y[15];

    var z_hi: u64 = 0;
    var z_lo: u64 = 0;

    for i in 16 {
        var bb = x[i];
        for _ in 8 {
            let b_mask = ghash_bit_mask64(bb >> 7);
            z_hi ^= v_hi & b_mask;
            z_lo ^= v_lo & b_mask;
            bb <<= 1;
            let lsb_mask = ghash_bit_mask64(v_lo & 1);
            v_lo = (v_lo >> 1) | ((v_hi & 1) << 63);
            v_hi = (v_hi >> 1) ^ (lsb_mask & 0xe100000000000000);
        }
    }

    var res: u8[16] = [0; 16];
    for i in 8 {
        res[i] = ((z_hi >> ((7 - i) * 8)) & 0xFF) as u8;
        res[8 + i] = ((z_lo >> ((7 - i) * 8)) & 0xFF) as u8;
    }
    return res;
}

fn ghash_update(h: const u8[16]&, y: u8[16]&, data: const u8[:]) {
    var offset = 0;
    while offset < data.len {
        var gblk: u8[16] = [0; 16];
        let rem = data.len - offset;
        let take = min(rem, 16);
        for i in take { gblk[i] = data[offset + i]; }
        for i in 16 { y[i] ^= gblk[i]; }
        y = ghash_mul(y, h);
        offset += take;
    }
}

inline fn inc_ctr32(ctr: u8[16]&) {
    var val = ((ctr[12] as u32) << 24) | ((ctr[13] as u32) << 16) | ((ctr[14] as u32) << 8) | ctr[15];
    val += 1;
    ctr[12] = ((val >> 24) & 0xFF) as u8;
    ctr[13] = ((val >> 16) & 0xFF) as u8;
    ctr[14] = ((val >> 8) & 0xFF) as u8;
    ctr[15] = (val & 0xFF) as u8;
}

inline fn init_j0(nonce12: const u8[12]&) -> u8[16] {
    var j0: u8[16] = [0; 16];
    for i in 12 { j0[i] = nonce12[i]; }
    j0[15] = 1;
    return j0;
}

fn aes_gcm_compute_tag(
    h:      const u8[16]&,
    enc_j0: const u8[16]&,
    aad:    const u8[:],
    ct:     const u8[:],
) -> u8[16] {
    var ghash_acc: u8[16] = [0; 16];
    ghash_update(h, ghash_acc, aad);
    ghash_update(h, ghash_acc, ct);

    var len_block: u8[16] = [0; 16];
    let aad_bits = (aad.len as u64) * 8;
    let ct_bits = (ct.len as u64) * 8;
    for i in 8 {
        len_block[i] = ((aad_bits >> ((7 - i) * 8)) & 0xFF) as u8;
        len_block[8 + i] = ((ct_bits >> ((7 - i) * 8)) & 0xFF) as u8;
    }
    for i in 16 { ghash_acc[i] ^= len_block[i]; }
    ghash_acc = ghash_mul(ghash_acc, h);

    var tag: u8[16] = [0; 16];
    for i in 16 { tag[i] = ghash_acc[i] ^ enc_j0[i]; }
    return tag;
}

const AES_GCM_MAX_BYTES: i64 = 0xFFFFFFFE0;

inline fn zeroize_aes_gcm_blocks(h: u8[16]&, enc_j0: u8[16]&, tag: u8[16]&) {
    secure_zeroize_16(h);
    secure_zeroize_16(enc_j0);
    secure_zeroize_16(tag);
}

inline fn aes_gcm_pure_crypt_block(
    is256: bool,
    ks128: const Aes128KeySchedule&,
    ks256: const Aes256KeySchedule&,
    blk:   const u8[16]&,
) -> u8[16] {
    return if is256 { aes_encrypt_block(ks256, blk) } else { aes128_encrypt_block(ks128, blk) };
}

fn aes_gcm_pure_prepare(
    key:     const u8[:],
    nonce12: const u8[12]&,
    ks128:   Aes128KeySchedule&,
    ks256:   Aes256KeySchedule&,
    h:       u8[16]&,
    enc_j0:  u8[16]&,
) -> bool {
    guard key.len == 16 || key.len == 32 else { return false; }
    let is256 = key.len == 32;
    var k128: u8[16] = [0; 16];
    var k256: u8[32] = [0; 32];
    if is256 {
        for i in 32 { k256[i] = key[i]; }
    } else {
        for i in 16 { k128[i] = key[i]; }
    }
    ks128 = aes128_key_schedule(k128);
    ks256 = aes256_key_schedule(k256);
    secure_zeroize_16(k128);
    secure_zeroize_32(k256);

    var zero_blk: u8[16] = [0; 16];
    var j0 = init_j0(nonce12);
    h = aes_gcm_pure_crypt_block(is256, ks128, ks256, zero_blk);
    enc_j0 = aes_gcm_pure_crypt_block(is256, ks128, ks256, j0);
    secure_zeroize_16(j0);
    return true;
}

fn aes_gcm_pure_apply_ctr(
    is256:   bool,
    ks128:   const Aes128KeySchedule&,
    ks256:   const Aes256KeySchedule&,
    nonce12: const u8[12]&,
    src:     const u8[:],
    dst:     u8[:],
) {
    var ctr = init_j0(nonce12);
    var ks_blk: u8[16] = [0; 16];
    defer secure_zeroize_16(ctr);
    defer secure_zeroize_16(ks_blk);
    var offset: i64 = 0;
    while offset < src.len {
        inc_ctr32(ctr);
        ks_blk = aes_gcm_pure_crypt_block(is256, ks128, ks256, ctr);
        let take = min(src.len - offset, 16);
        for i in take {
            dst[offset + i] = src[offset + i] ^ ks_blk[i];
        }
        offset += take;
    }
}

// Constant-time pure-Goose AES-128/256-GCM AEAD encryption (NIST SP 800-38D).
// Supports both out-of-place and in-place (`plaintext` aliasing `dst`) buffers.
//
// Example:
//   key = [0; 16], nonce12 = [0; 12], plaintext = [0; 16], aad = "", dst = [0; 16]
//   returns: tag16, written = 16, ok = true
fn aes_gcm_seal_pure(
    key:       const u8[:],
    nonce12:   const u8[12]&,
    plaintext: const u8[:],
    aad:       const u8[:],
    dst:       u8[:],
) -> u8[16], i64, bool {
    var zero_tag: u8[16] = [0; 16];
    guard plaintext.len <= AES_GCM_MAX_BYTES && dst.len >= plaintext.len else {
        return zero_tag, 0, false;
    }
    var ks128 = Aes128KeySchedule { .. };
    var ks256 = Aes256KeySchedule { .. };
    var h:      u8[16] = [0; 16];
    var enc_j0: u8[16] = [0; 16];
    defer zeroize_aes128_ks(ks128);
    defer zeroize_aes256_ks(ks256);
    defer secure_zeroize_16(h);
    defer secure_zeroize_16(enc_j0);
    guard aes_gcm_pure_prepare(key, nonce12, ks128, ks256, h, enc_j0) else {
        return zero_tag, 0, false;
    }
    aes_gcm_pure_apply_ctr(key.len == 32, ks128, ks256, nonce12, plaintext, dst);
    let tag = aes_gcm_compute_tag(h, enc_j0, aad, dst[..plaintext.len]);
    return tag, plaintext.len, true;
}

// Constant-time pure-Goose AES-128/256-GCM AEAD decryption (NIST SP 800-38D).
// Verifies the authentication tag before writing plaintext; wipes `dst` on mismatch.
//
// Example:
//   key = [0; 16], nonce12 = [0; 12], ciphertext = [..16], aad = "", tag = tag16, dst = [0; 16]
//   returns: written = 16, ok = true
fn aes_gcm_open_pure(
    key:        const u8[:],
    nonce12:    const u8[12]&,
    ciphertext: const u8[:],
    aad:        const u8[:],
    tag:        const u8[16]&,
    dst:        u8[:],
) -> i64, bool {
    guard ciphertext.len <= AES_GCM_MAX_BYTES && dst.len >= ciphertext.len else {
        return 0, false;
    }
    var ks128 = Aes128KeySchedule { .. };
    var ks256 = Aes256KeySchedule { .. };
    var h:            u8[16] = [0; 16];
    var enc_j0:       u8[16] = [0; 16];
    var computed_tag: u8[16] = [0; 16];
    defer zeroize_aes128_ks(ks128);
    defer zeroize_aes256_ks(ks256);
    defer zeroize_aes_gcm_blocks(h, enc_j0, computed_tag);
    guard aes_gcm_pure_prepare(key, nonce12, ks128, ks256, h, enc_j0) else {
        return 0, false;
    }
    computed_tag = aes_gcm_compute_tag(h, enc_j0, aad, ciphertext);
    guard ct_declassify_u8(ct_eq_tag16_bit(computed_tag, tag)) == 1 else {
        secure_zeroize_slice(dst[..ciphertext.len]);
        return 0, false;
    }
    aes_gcm_pure_apply_ctr(key.len == 32, ks128, ks256, nonce12, ciphertext, dst);
    return ciphertext.len, true;
}

fn aes_gcm_seal_core(
    key:       const u8[:],
    nonce12:   const u8[12]&,
    plaintext: const u8[:],
    aad:       const u8[:],
    dst:       u8[:],
) -> u8[16], i64, bool {
    var tag: u8[16] = [0; 16];
    guard plaintext.len <= AES_GCM_MAX_BYTES && dst.len >= plaintext.len else {
        return tag, 0, false;
    }
    let written = native_aes_gcm_seal_aead(key, nonce12[..], plaintext, aad, dst[..plaintext.len], tag[..]);
    if written == -2 {
        return aes_gcm_seal_pure(key, nonce12, plaintext, aad, dst);
    }
    guard written == plaintext.len else {
        secure_zeroize_slice(tag[..]);
        return tag, 0, false;
    }
    return tag, written, true;
}

fn aes_gcm_open_core_into(
    key:        const u8[:],
    nonce12:    const u8[12]&,
    ciphertext: const u8[:],
    aad:        const u8[:],
    tag:        const u8[16]&,
    dst:        u8[:],
) -> i64, bool {
    guard ciphertext.len <= AES_GCM_MAX_BYTES && dst.len >= ciphertext.len else {
        return 0, false;
    }
    let res = native_aes_gcm_open_aead(key, nonce12[..], ciphertext, aad, tag[..], dst[..ciphertext.len]);
    if res == -2 {
        return aes_gcm_open_pure(key, nonce12, ciphertext, aad, tag, dst[..ciphertext.len]);
    }
    guard res == ciphertext.len else {
        secure_zeroize_slice(dst[..ciphertext.len]);
        return 0, false;
    }
    return res, true;
}

fn aes_gcm_open_small<B>(
    key:           const u8[:],
    nonce12:       const u8[12]&,
    ciphertext:    const u8[:],
    aad:           const u8[:],
    tag:           const u8[16]&,
    out_plaintext: B&,
) -> bool {
    guard ciphertext.len <= 2048 else { return false; }
    var tmp: u8[2048] = [0; 2048];
    let res, ok_open = aes_gcm_open_core_into(key, nonce12, ciphertext, aad, tag, tmp[..ciphertext.len]);
    guard ok_open && res == ciphertext.len else {
        secure_zeroize_slice(tmp[..ciphertext.len]);
        return false;
    }
    guard crypto_buf_has_room(out_plaintext, ciphertext.len) else {
        secure_zeroize_slice(tmp[..ciphertext.len]);
        return false;
    }
    let start_len = out_plaintext.len;
    out_plaintext.append(tmp[..ciphertext.len]);
    secure_zeroize_slice(tmp[..ciphertext.len]);
    let expected_len = add_sat_i64(start_len, ciphertext.len);
    if out_plaintext.len != expected_len {
        if out_plaintext.len > start_len {
            secure_zeroize_buf_tail(out_plaintext, start_len);
            out_plaintext.resize(start_len);
        }
        return false;
    }
    return true;
}

// In-place AES-256-GCM AEAD decryption (NIST SP 800-38D).
// On tag mismatch, executes secure_zeroize_slice(in_out) and returns 0, false.
fn aes256_gcm_open_inplace(
    key:     const u8[32]&,
    nonce12: const u8[12]&,
    in_out:  u8[:],
    aad:     const u8[:],
    tag:     const u8[16]&,
) -> i64, bool {
    guard in_out.len <= AES_GCM_MAX_BYTES else {
        secure_zeroize_slice(in_out);
        return 0, false;
    }
    return aes_gcm_open_core_into(key[..], nonce12, in_out, aad, tag, in_out);
}

// In-place AES-256-GCM AEAD encryption (NIST SP 800-38D).
// Encrypts in_out in-place and returns the 16-byte authentication tag.
fn aes256_gcm_seal_inplace(
    key:     const u8[32]&,
    nonce12: const u8[12]&,
    in_out:  u8[:],
    aad:     const u8[:],
) -> u8[16], bool {
    let tag, _, ok = aes_gcm_seal_core(key[..], nonce12, in_out, aad, in_out);
    return tag, ok;
}

// Out-of-place AES-256-GCM AEAD decryption into caller-provided destination slice (NIST SP 800-38D).
fn aes256_gcm_open_into(
    key:        const u8[32]&,
    nonce12:    const u8[12]&,
    ciphertext: const u8[:],
    aad:        const u8[:],
    tag:        const u8[16]&,
    dst:        u8[:],
) -> i64, bool {
    return aes_gcm_open_core_into(key[..], nonce12, ciphertext, aad, tag, dst);
}

// Out-of-place AES-256-GCM AEAD encryption into caller-provided destination slice (NIST SP 800-38D).
fn aes256_gcm_seal(
    key:       const u8[32]&,
    nonce12:   const u8[12]&,
    plaintext: const u8[:],
    aad:       const u8[:],
    dst:       u8[:],
) -> u8[16], i64, bool {
    return aes_gcm_seal_core(key[..], nonce12, plaintext, aad, dst);
}

fn aes256_gcm_open<B>(
    key:           const u8[32]&,
    nonce12:       const u8[12]&,
    ciphertext:    const u8[:],
    aad:           const u8[:],
    tag:           const u8[16]&,
    out_plaintext: B&,
) -> bool {
    guard ciphertext.len <= AES_GCM_MAX_BYTES else { return false; }
    if ciphertext.len <= 2048 {
        return aes_gcm_open_small(key[..], nonce12, ciphertext, aad, tag, out_plaintext);
    }
    var ks = aes256_key_schedule(key);
    let zero_block: u8[16] = [0; 16];
    var h = aes_encrypt_block(ks, zero_block);
    let j0 = init_j0(nonce12);
    var enc_j0 = aes_encrypt_block(ks, j0);
    var computed_tag = aes_gcm_compute_tag(h, enc_j0, aad, ciphertext);

    guard ct_declassify_u8(ct_eq_tag16_bit(computed_tag, tag)) == 1 else {
        zeroize_aes256_ks(ks);
        zeroize_aes_gcm_blocks(h, enc_j0, computed_tag);
        return false;
    }
    guard crypto_buf_has_room(out_plaintext, ciphertext.len) else {
        zeroize_aes256_ks(ks);
        zeroize_aes_gcm_blocks(h, enc_j0, computed_tag);
        return false;
    }

    let start_len = out_plaintext.len;
    var ctr = j0;
    var enc_ctr: u8[16] = [0; 16];
    var offset = 0;
    while offset < ciphertext.len {
        inc_ctr32(ctr);
        enc_ctr = aes_encrypt_block(ks, ctr);
        let rem = ciphertext.len - offset;
        let take = min(rem, 16);
        for i in take {
            out_plaintext.push(ciphertext[offset + i] ^ enc_ctr[i]);
        }
        offset += take;
    }
    secure_zeroize_16(enc_ctr);
    zeroize_aes_gcm_blocks(h, enc_j0, computed_tag);
    zeroize_aes256_ks(ks);
    if out_plaintext.len - start_len != ciphertext.len {
        if out_plaintext.len > start_len {
            secure_zeroize_buf_tail(out_plaintext, start_len);
            out_plaintext.resize(start_len);
        }
        return false;
    }
    return true;
}

// In-place AES-128-GCM AEAD decryption (NIST SP 800-38D).
// On tag mismatch, executes secure_zeroize_slice(in_out) and returns 0, false.
fn aes128_gcm_open_inplace(
    key:     const u8[16]&,
    nonce12: const u8[12]&,
    in_out:  u8[:],
    aad:     const u8[:],
    tag:     const u8[16]&,
) -> i64, bool {
    guard in_out.len <= AES_GCM_MAX_BYTES else {
        secure_zeroize_slice(in_out);
        return 0, false;
    }
    return aes_gcm_open_core_into(key[..], nonce12, in_out, aad, tag, in_out);
}

// In-place AES-128-GCM AEAD encryption (NIST SP 800-38D).
// Encrypts in_out in-place and returns the 16-byte authentication tag.
fn aes128_gcm_seal_inplace(
    key:     const u8[16]&,
    nonce12: const u8[12]&,
    in_out:  u8[:],
    aad:     const u8[:],
) -> u8[16], bool {
    let tag, _, ok = aes_gcm_seal_core(key[..], nonce12, in_out, aad, in_out);
    return tag, ok;
}

// Out-of-place AES-128-GCM AEAD decryption into caller-provided destination slice (NIST SP 800-38D).
fn aes128_gcm_open_into(
    key:        const u8[16]&,
    nonce12:    const u8[12]&,
    ciphertext: const u8[:],
    aad:        const u8[:],
    tag:        const u8[16]&,
    dst:        u8[:],
) -> i64, bool {
    return aes_gcm_open_core_into(key[..], nonce12, ciphertext, aad, tag, dst);
}

// Out-of-place AES-128-GCM AEAD encryption into caller-provided destination slice (NIST SP 800-38D).
fn aes128_gcm_seal(
    key:       const u8[16]&,
    nonce12:   const u8[12]&,
    plaintext: const u8[:],
    aad:       const u8[:],
    dst:       u8[:],
) -> u8[16], i64, bool {
    return aes_gcm_seal_core(key[..], nonce12, plaintext, aad, dst);
}

fn aes128_gcm_open<B>(
    key:           const u8[16]&,
    nonce12:       const u8[12]&,
    ciphertext:    const u8[:],
    aad:           const u8[:],
    tag:           const u8[16]&,
    out_plaintext: B&,
) -> bool {
    guard ciphertext.len <= AES_GCM_MAX_BYTES else { return false; }
    if ciphertext.len <= 2048 {
        return aes_gcm_open_small(key[..], nonce12, ciphertext, aad, tag, out_plaintext);
    }
    var ks = aes128_key_schedule(key);
    let zero_block: u8[16] = [0; 16];
    var h = aes128_encrypt_block(ks, zero_block);
    let j0 = init_j0(nonce12);
    var enc_j0 = aes128_encrypt_block(ks, j0);
    var computed_tag = aes_gcm_compute_tag(h, enc_j0, aad, ciphertext);

    guard ct_declassify_u8(ct_eq_tag16_bit(computed_tag, tag)) == 1 else {
        zeroize_aes128_ks(ks);
        zeroize_aes_gcm_blocks(h, enc_j0, computed_tag);
        return false;
    }
    guard crypto_buf_has_room(out_plaintext, ciphertext.len) else {
        zeroize_aes128_ks(ks);
        zeroize_aes_gcm_blocks(h, enc_j0, computed_tag);
        return false;
    }

    let start_len = out_plaintext.len;
    var ctr = j0;
    var enc_ctr: u8[16] = [0; 16];
    var offset = 0;
    while offset < ciphertext.len {
        inc_ctr32(ctr);
        enc_ctr = aes128_encrypt_block(ks, ctr);
        let rem = ciphertext.len - offset;
        let take = min(rem, 16);
        for i in take {
            out_plaintext.push(ciphertext[offset + i] ^ enc_ctr[i]);
        }
        offset += take;
    }
    secure_zeroize_16(enc_ctr);
    zeroize_aes_gcm_blocks(h, enc_j0, computed_tag);
    zeroize_aes128_ks(ks);
    if out_plaintext.len - start_len != ciphertext.len {
        if out_plaintext.len > start_len {
            secure_zeroize_buf_tail(out_plaintext, start_len);
            out_plaintext.resize(start_len);
        }
        return false;
    }
    return true;
}

// HKDF-SHA256 + AES-256-GCM scheme (32-byte salt + 12-byte nonce)
fn hkdf_aes256_gcm_seal(
    master_key: const u8[32]&,
    salt32:     const u8[32]&,
    nonce12:    const u8[12]&,
    plaintext:  const u8[:],
    aad:        const u8[:],
    dst:        u8[:],
) -> u8[16], i64, bool {
    var derived_key = hkdf_sha256_32(master_key, salt32[..], "aes-256-gcm-cookie");
    let tag, written_len, ok = aes256_gcm_seal(derived_key, nonce12, plaintext, aad, dst);
    secure_zeroize_32(derived_key);
    return tag, written_len, ok;
}

fn hkdf_aes256_gcm_open_into(
    master_key: const u8[32]&,
    salt32:     const u8[32]&,
    nonce12:    const u8[12]&,
    ciphertext: const u8[:],
    aad:        const u8[:],
    tag:        const u8[16]&,
    dst:        u8[:],
) -> i64, bool {
    var derived_key = hkdf_sha256_32(master_key, salt32[..], "aes-256-gcm-cookie");
    let written_len, ok = aes256_gcm_open_into(derived_key, nonce12, ciphertext, aad, tag, dst);
    secure_zeroize_32(derived_key);
    return written_len, ok;
}

fn hkdf_aes256_gcm_open<B>(
    master_key:    const u8[32]&,
    salt32:        const u8[32]&,
    nonce12:       const u8[12]&,
    ciphertext:    const u8[:],
    aad:           const u8[:],
    tag:           const u8[16]&,
    out_plaintext: B&,
) -> bool {
    var derived_key = hkdf_sha256_32(master_key, salt32[..], "aes-256-gcm-cookie");
    let ok = aes256_gcm_open(derived_key, nonce12, ciphertext, aad, tag, out_plaintext);
    secure_zeroize_32(derived_key);
    return ok;
}

const AES_GCM_STATE_BYTES: i64 = 320;

// Pre-expanded AES-128/256-GCM key schedule and Karatsuba GHASH powers (H, H^2, H^3, H^4).
struct AesGcmKey {
    state:     u8[AES_GCM_STATE_BYTES] = [0; AES_GCM_STATE_BYTES],
    key_len:   u8                      = 0,
    valid:     bool                    = false,
    pure_mode: bool                    = false,
}

// Securely wipes pre-expanded AES-GCM round keys and GHASH subkeys.
fn zeroize_aes_gcm_key(ctx: AesGcmKey&) {
    secure_zeroize_slice(ctx.state[..]);
    ctx.key_len = 0;
    ctx.valid = false;
    ctx.pure_mode = false;
}

// Pre-expands an AES-128 (16-byte) or AES-256 (32-byte) key into `ctx` for repeated AEAD calls.
fn aes_gcm_prepare_key(key: const u8[:], ctx: AesGcmKey&) -> bool {
    guard key.len == 16 || key.len == 32 else {
        zeroize_aes_gcm_key(ctx);
        return false;
    }
    let rc = native_aes_gcm_prepare_key(key, ctx.state[..]);
    if rc == -2 {
        secure_zeroize_slice(ctx.state[..]);
        for i in key.len {
            ctx.state[i] = key[i];
        }
        ctx.key_len = if key.len == 32 { 32 } else { 16 };
        ctx.valid = true;
        ctx.pure_mode = true;
        return true;
    }
    guard rc == 0 else {
        zeroize_aes_gcm_key(ctx);
        return false;
    }
    ctx.key_len = if key.len == 32 { 32 } else { 16 };
    ctx.valid = true;
    ctx.pure_mode = false;
    return true;
}

// Encrypts and authenticates `plaintext` into `dst` using pre-expanded `ctx` (NIST SP 800-38D).
//
// Example:
//   ctx = prepared AES-128 key, iv12 = nonce, plaintext = "hello", aad = "", dst = [0; 5]
//   returns: tag16, written = 5, ok = true
fn aes_gcm_seal_prepared(
    ctx:       const AesGcmKey&,
    iv12:      const u8[12]&,
    plaintext: const u8[:],
    aad:       const u8[:],
    dst:       u8[:],
) -> u8[16], i64, bool {
    var tag: u8[16] = [0; 16];
    guard ctx.valid && plaintext.len <= AES_GCM_MAX_BYTES && dst.len >= plaintext.len else {
        return tag, 0, false;
    }
    if ctx.pure_mode {
        return aes_gcm_seal_pure(ctx.state[..(ctx.key_len as i64)], iv12, plaintext, aad, dst);
    }
    let n = native_aes_gcm_seal_prepared(
        ctx.state[..], iv12[..], plaintext, aad, dst[..plaintext.len], tag[..],
    );
    guard n == plaintext.len else {
        secure_zeroize_slice(tag[..]);
        return tag, 0, false;
    }
    return tag, n, true;
}

// Decrypts and verifies `ciphertext` into `dst` using pre-expanded `ctx` (NIST SP 800-38D).
//
// Example:
//   ctx = prepared AES-128 key, iv12 = nonce, ciphertext = [..5], aad = "", tag = tag16, dst = [0; 5]
//   returns: written = 5, ok = true
fn aes_gcm_open_prepared_into(
    ctx:        const AesGcmKey&,
    iv12:       const u8[12]&,
    ciphertext: const u8[:],
    aad:        const u8[:],
    tag:        const u8[16]&,
    dst:        u8[:],
) -> i64, bool {
    guard ciphertext.len <= AES_GCM_MAX_BYTES && dst.len >= ciphertext.len else {
        return 0, false;
    }
    guard ctx.valid else {
        secure_zeroize_slice(dst[..ciphertext.len]);
        return 0, false;
    }
    if ctx.pure_mode {
        return aes_gcm_open_pure(
            ctx.state[..(ctx.key_len as i64)], iv12, ciphertext, aad, tag, dst[..ciphertext.len],
        );
    }
    let n = native_aes_gcm_open_prepared(
        ctx.state[..], iv12[..], ciphertext, aad, tag[..], dst[..ciphertext.len],
    );
    guard n == ciphertext.len else {
        secure_zeroize_slice(dst[..ciphertext.len]);
        return 0, false;
    }
    return n, true;
}

// Encrypts and authenticates `buf` in-place using pre-expanded `ctx` (NIST SP 800-38D).
//
// Example:
//   ctx = prepared AES-128 key, iv12 = nonce, buf = [1, 2, 3, 4], aad = ""
//   returns: tag16, written = 4, ok = true (with `buf` encrypted in-place)
fn aes_gcm_seal_prepared_inplace(
    ctx:  const AesGcmKey&,
    iv12: const u8[12]&,
    buf:  u8[:],
    aad:  const u8[:],
) -> u8[16], i64, bool {
    var tag: u8[16] = [0; 16];
    guard ctx.valid && buf.len <= AES_GCM_MAX_BYTES else {
        return tag, 0, false;
    }
    if ctx.pure_mode {
        return aes_gcm_seal_pure(ctx.state[..(ctx.key_len as i64)], iv12, buf, aad, buf);
    }
    let n = native_aes_gcm_seal_prepared(ctx.state[..], iv12[..], buf, aad, buf, tag[..]);
    guard n == buf.len else {
        secure_zeroize_slice(tag[..]);
        return tag, 0, false;
    }
    return tag, n, true;
}
