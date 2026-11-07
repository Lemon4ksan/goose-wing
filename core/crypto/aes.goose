// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Advanced Encryption Standard (AES) FIPS 197 and Galois/Counter Mode (AES-GCM) NIST SP 800-38D.
// Zero dynamic heap allocations on key expansion, block encryption, and AEAD authentication.
namespace core;

import std;

let AES_SBOX: const u8[256] = [
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16,
];

let AES_RCON: const u32[10] = [
    0x01000000, 0x02000000, 0x04000000, 0x08000000, 0x10000000,
    0x20000000, 0x40000000, 0x80000000, 0x1b000000, 0x36000000,
];

inline fn aes_sub_word(w: u32) -> u32 {
    return ((AES_SBOX[(w >> 24) & 0xFF] as u32) << 24) |
           ((AES_SBOX[(w >> 16) & 0xFF] as u32) << 16) |
           ((AES_SBOX[(w >> 8) & 0xFF] as u32) << 8) |
           AES_SBOX[w & 0xFF];
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
    var z_bytes: u8[32] = [0; 32];
    secure_zeroize_32(z_bytes);
    let z_word: u32 = z_bytes[0];
    for i in 60 {
        ks.round_keys[i] = z_word;
    }
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
    return if (b & 0x80) != 0 { ((b << 1) ^ 0x1b) } else { (b << 1) };
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
        for i in 16 { state[i] = AES_SBOX[state[i]]; }
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
    for i in 16 { state[i] = AES_SBOX[state[i]]; }
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

struct Aes128KeySchedule {
    round_keys: u32[44] = [0; 44],
}

// Zeroizes an AES-128 round key schedule in place.
// crap:ignore
inline fn zeroize_aes128_ks(ks: Aes128KeySchedule&) {
    var z_bytes: u8[16] = [0; 16];
    secure_zeroize_16(z_bytes);
    let z_word: u32 = z_bytes[0];
    for i in 44 {
        ks.round_keys[i] = z_word;
    }
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
        for i in 16 { state[i] = AES_SBOX[state[i]]; }
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
    for i in 16 { state[i] = AES_SBOX[state[i]]; }
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

// GHASH in GF(2^128)
fn ghash_mul(x: const u8[16]&, y: const u8[16]&) -> u8[16] {
    var v_hi = ((y[0] as u64) << 56) | ((y[1] as u64) << 48) | ((y[2] as u64) << 40) | ((y[3] as u64) << 32) |
               ((y[4] as u64) << 24) | ((y[5] as u64) << 16) | ((y[6] as u64) << 8) | y[7];
    var v_lo = ((y[8] as u64) << 56) | ((y[9] as u64) << 48) | ((y[10] as u64) << 40) | ((y[11] as u64) << 32) |
               ((y[12] as u64) << 24) | ((y[13] as u64) << 16) | ((y[14] as u64) << 8) | y[15];

    var z_hi: u64 = 0;
    var z_lo: u64 = 0;

    for i in 16 {
        let b = x[i];
        for j in 8 {
            if ((b >> (7 - j)) & 1) != 0 {
                z_hi ^= v_hi;
                z_lo ^= v_lo;
            }
            let lsb = v_lo & 1;
            v_lo = (v_lo >> 1) | ((v_hi & 1) << 63);
            v_hi = v_hi >> 1;
            if lsb != 0 {
                v_hi ^= 0xe100000000000000;
            }
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
        let take = if rem < 16 { rem } else { 16 };
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

// In-place AES-256-GCM AEAD decryption (NIST SP 800-38D).
// On tag mismatch, executes secure_zeroize_slice(in_out) and returns 0, false.
fn aes256_gcm_open_inplace(
    key:     const u8[32]&,
    nonce12: const u8[12]&,
    in_out:  u8[:],
    aad:     const u8[:],
    tag:     const u8[16]&,
) -> i64, bool {
    var ks = aes256_key_schedule(key);
    let zero_block: u8[16] = [0; 16];
    let h = aes_encrypt_block(ks, zero_block);
    let j0 = init_j0(nonce12);
    let enc_j0 = aes_encrypt_block(ks, j0);
    let computed_tag = aes_gcm_compute_tag(h, enc_j0, aad, in_out);

    guard ct_eq_tag16(computed_tag, tag) else {
        zeroize_aes256_ks(ks);
        secure_zeroize_slice(in_out);
        return 0, false;
    }

    var ctr = j0;
    var offset = 0;
    while offset < in_out.len {
        inc_ctr32(ctr);
        let enc_ctr = aes_encrypt_block(ks, ctr);
        let rem = in_out.len - offset;
        let take = if rem < 16 { rem } else { 16 };
        for i in take {
            in_out[offset + i] ^= enc_ctr[i];
        }
        offset += take;
    }
    zeroize_aes256_ks(ks);
    return in_out.len, true;
}

// In-place AES-256-GCM AEAD encryption (NIST SP 800-38D).
// Encrypts in_out in-place and returns the 16-byte authentication tag.
fn aes256_gcm_seal_inplace(
    key:     const u8[32]&,
    nonce12: const u8[12]&,
    in_out:  u8[:],
    aad:     const u8[:],
) -> u8[16], bool {
    var ks = aes256_key_schedule(key);
    let zero_block: u8[16] = [0; 16];
    let h = aes_encrypt_block(ks, zero_block);
    let j0 = init_j0(nonce12);

    var ctr = j0;
    var offset = 0;
    while offset < in_out.len {
        inc_ctr32(ctr);
        let enc_ctr = aes_encrypt_block(ks, ctr);
        let rem = in_out.len - offset;
        let take = if rem < 16 { rem } else { 16 };
        for i in take {
            in_out[offset + i] ^= enc_ctr[i];
        }
        offset += take;
    }

    let enc_j0 = aes_encrypt_block(ks, j0);
    let tag = aes_gcm_compute_tag(h, enc_j0, aad, in_out);
    zeroize_aes256_ks(ks);
    return tag, true;
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
    guard dst.len >= ciphertext.len else { return 0, false; }
    var ks = aes256_key_schedule(key);
    let zero_block: u8[16] = [0; 16];
    let h = aes_encrypt_block(ks, zero_block);
    let j0 = init_j0(nonce12);
    let enc_j0 = aes_encrypt_block(ks, j0);
    let computed_tag = aes_gcm_compute_tag(h, enc_j0, aad, ciphertext);

    guard ct_eq_tag16(computed_tag, tag) else {
        zeroize_aes256_ks(ks);
        secure_zeroize_slice(dst[..ciphertext.len]);
        return 0, false;
    }

    var ctr = j0;
    var offset = 0;
    while offset < ciphertext.len {
        inc_ctr32(ctr);
        let enc_ctr = aes_encrypt_block(ks, ctr);
        let rem = ciphertext.len - offset;
        let take = if rem < 16 { rem } else { 16 };
        for i in take {
            dst[offset + i] = ciphertext[offset + i] ^ enc_ctr[i];
        }
        offset += take;
    }
    zeroize_aes256_ks(ks);
    return ciphertext.len, true;
}

// Out-of-place AES-256-GCM AEAD encryption into caller-provided destination slice (NIST SP 800-38D).
fn aes256_gcm_seal(
    key:       const u8[32]&,
    nonce12:   const u8[12]&,
    plaintext: const u8[:],
    aad:       const u8[:],
    dst:       u8[:],
) -> u8[16], i64, bool {
    var empty_tag: u8[16] = [0; 16];
    guard dst.len >= plaintext.len else { return empty_tag, 0, false; }
    var ks = aes256_key_schedule(key);
    let zero_block: u8[16] = [0; 16];
    let h = aes_encrypt_block(ks, zero_block);
    let j0 = init_j0(nonce12);

    var ctr = j0;
    var offset = 0;
    while offset < plaintext.len {
        inc_ctr32(ctr);
        let enc_ctr = aes_encrypt_block(ks, ctr);
        let rem = plaintext.len - offset;
        let take = if rem < 16 { rem } else { 16 };
        for i in take {
            dst[offset + i] = plaintext[offset + i] ^ enc_ctr[i];
        }
        offset += take;
    }

    let enc_j0 = aes_encrypt_block(ks, j0);
    let tag = aes_gcm_compute_tag(h, enc_j0, aad, dst[..plaintext.len]);
    zeroize_aes256_ks(ks);
    return tag, plaintext.len, true;
}

fn aes256_gcm_open<B>(
    key:           const u8[32]&,
    nonce12:       const u8[12]&,
    ciphertext:    const u8[:],
    aad:           const u8[:],
    tag:           const u8[16]&,
    out_plaintext: B&,
) -> bool {
    var ks = aes256_key_schedule(key);
    let zero_block: u8[16] = [0; 16];
    let h = aes_encrypt_block(ks, zero_block);
    let j0 = init_j0(nonce12);
    let enc_j0 = aes_encrypt_block(ks, j0);
    let computed_tag = aes_gcm_compute_tag(h, enc_j0, aad, ciphertext);

    guard ct_eq_tag16(computed_tag, tag) else {
        zeroize_aes256_ks(ks);
        return false;
    }

    let start_len = out_plaintext.len;
    var ctr = j0;
    var offset = 0;
    while offset < ciphertext.len {
        inc_ctr32(ctr);
        let enc_ctr = aes_encrypt_block(ks, ctr);
        let rem = ciphertext.len - offset;
        let take = if rem < 16 { rem } else { 16 };
        for i in take {
            out_plaintext.push(ciphertext[offset + i] ^ enc_ctr[i]);
        }
        offset += take;
    }
    zeroize_aes256_ks(ks);
    if out_plaintext.len - start_len != ciphertext.len {
        out_plaintext.clear();
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
    var ks = aes128_key_schedule(key);
    let zero_block: u8[16] = [0; 16];
    let h = aes128_encrypt_block(ks, zero_block);
    let j0 = init_j0(nonce12);
    let enc_j0 = aes128_encrypt_block(ks, j0);
    let computed_tag = aes_gcm_compute_tag(h, enc_j0, aad, in_out);

    guard ct_eq_tag16(computed_tag, tag) else {
        zeroize_aes128_ks(ks);
        secure_zeroize_slice(in_out);
        return 0, false;
    }

    var ctr = j0;
    var offset = 0;
    while offset < in_out.len {
        inc_ctr32(ctr);
        let enc_ctr = aes128_encrypt_block(ks, ctr);
        let rem = in_out.len - offset;
        let take = if rem < 16 { rem } else { 16 };
        for i in take {
            in_out[offset + i] ^= enc_ctr[i];
        }
        offset += take;
    }
    zeroize_aes128_ks(ks);
    return in_out.len, true;
}

// In-place AES-128-GCM AEAD encryption (NIST SP 800-38D).
// Encrypts in_out in-place and returns the 16-byte authentication tag.
fn aes128_gcm_seal_inplace(
    key:     const u8[16]&,
    nonce12: const u8[12]&,
    in_out:  u8[:],
    aad:     const u8[:],
) -> u8[16], bool {
    var ks = aes128_key_schedule(key);
    let zero_block: u8[16] = [0; 16];
    let h = aes128_encrypt_block(ks, zero_block);
    let j0 = init_j0(nonce12);

    var ctr = j0;
    var offset = 0;
    while offset < in_out.len {
        inc_ctr32(ctr);
        let enc_ctr = aes128_encrypt_block(ks, ctr);
        let rem = in_out.len - offset;
        let take = if rem < 16 { rem } else { 16 };
        for i in take {
            in_out[offset + i] ^= enc_ctr[i];
        }
        offset += take;
    }

    let enc_j0 = aes128_encrypt_block(ks, j0);
    let tag = aes_gcm_compute_tag(h, enc_j0, aad, in_out);
    zeroize_aes128_ks(ks);
    return tag, true;
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
    guard dst.len >= ciphertext.len else { return 0, false; }
    var ks = aes128_key_schedule(key);
    let zero_block: u8[16] = [0; 16];
    let h = aes128_encrypt_block(ks, zero_block);
    let j0 = init_j0(nonce12);
    let enc_j0 = aes128_encrypt_block(ks, j0);
    let computed_tag = aes_gcm_compute_tag(h, enc_j0, aad, ciphertext);

    guard ct_eq_tag16(computed_tag, tag) else {
        zeroize_aes128_ks(ks);
        secure_zeroize_slice(dst[..ciphertext.len]);
        return 0, false;
    }

    var ctr = j0;
    var offset = 0;
    while offset < ciphertext.len {
        inc_ctr32(ctr);
        let enc_ctr = aes128_encrypt_block(ks, ctr);
        let rem = ciphertext.len - offset;
        let take = if rem < 16 { rem } else { 16 };
        for i in take {
            dst[offset + i] = ciphertext[offset + i] ^ enc_ctr[i];
        }
        offset += take;
    }
    zeroize_aes128_ks(ks);
    return ciphertext.len, true;
}

// Out-of-place AES-128-GCM AEAD encryption into caller-provided destination slice (NIST SP 800-38D).
fn aes128_gcm_seal(
    key:       const u8[16]&,
    nonce12:   const u8[12]&,
    plaintext: const u8[:],
    aad:       const u8[:],
    dst:       u8[:],
) -> u8[16], i64, bool {
    var empty_tag: u8[16] = [0; 16];
    guard dst.len >= plaintext.len else { return empty_tag, 0, false; }
    var ks = aes128_key_schedule(key);
    let zero_block: u8[16] = [0; 16];
    let h = aes128_encrypt_block(ks, zero_block);
    let j0 = init_j0(nonce12);

    var ctr = j0;
    var offset = 0;
    while offset < plaintext.len {
        inc_ctr32(ctr);
        let enc_ctr = aes128_encrypt_block(ks, ctr);
        let rem = plaintext.len - offset;
        let take = if rem < 16 { rem } else { 16 };
        for i in take {
            dst[offset + i] = plaintext[offset + i] ^ enc_ctr[i];
        }
        offset += take;
    }

    let enc_j0 = aes128_encrypt_block(ks, j0);
    let tag = aes_gcm_compute_tag(h, enc_j0, aad, dst[..plaintext.len]);
    zeroize_aes128_ks(ks);
    return tag, plaintext.len, true;
}

fn aes128_gcm_open<B>(
    key:           const u8[16]&,
    nonce12:       const u8[12]&,
    ciphertext:    const u8[:],
    aad:           const u8[:],
    tag:           const u8[16]&,
    out_plaintext: B&,
) -> bool {
    var ks = aes128_key_schedule(key);
    let zero_block: u8[16] = [0; 16];
    let h = aes128_encrypt_block(ks, zero_block);
    let j0 = init_j0(nonce12);
    let enc_j0 = aes128_encrypt_block(ks, j0);
    let computed_tag = aes_gcm_compute_tag(h, enc_j0, aad, ciphertext);

    guard ct_eq_tag16(computed_tag, tag) else {
        zeroize_aes128_ks(ks);
        return false;
    }

    let start_len = out_plaintext.len;
    var ctr = j0;
    var offset = 0;
    while offset < ciphertext.len {
        inc_ctr32(ctr);
        let enc_ctr = aes128_encrypt_block(ks, ctr);
        let rem = ciphertext.len - offset;
        let take = if rem < 16 { rem } else { 16 };
        for i in take {
            out_plaintext.push(ciphertext[offset + i] ^ enc_ctr[i]);
        }
        offset += take;
    }
    zeroize_aes128_ks(ks);
    if out_plaintext.len - start_len != ciphertext.len {
        out_plaintext.clear();
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
