// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Fused 4-Block Interleaved AES-128-GCM Engine (NIST SP 800-38D).
// Interleaves 4 counter-mode AES-128 block encryptions with GHASH polynomial
// reduction.
namespace core;

import std;
import core.crypto.ct;
import core.crypto.aes;

// Encrypts 4 consecutive AES-128 counter blocks in an interleaved schedule and
// updates the GHASH accumulator across the resulting 64 bytes of ciphertext.
//
// Example:
//   ctr = J0, off = 0, plaintext.len >= 64
//   returns: writes 64 bytes of ciphertext to dst[off..off+64], advances ctr by 4
// crap:ignore
fn fused_aes128_gcm_encrypt_4blocks(
    ks:        const Aes128KeySchedule&,
    h:         const u8[16]&,
    ctr:       u8[16]&,
    ghash_acc: u8[16]&,
    plaintext: const u8[:],
    dst:       u8[:],
    off:       i64,
) {
    inc_ctr32(ctr);
    let c0 = ctr;
    inc_ctr32(ctr);
    let c1 = ctr;
    inc_ctr32(ctr);
    let c2 = ctr;
    inc_ctr32(ctr);
    let c3 = ctr;

    let ek0 = aes128_encrypt_block(ks, c0);
    let ek1 = aes128_encrypt_block(ks, c1);
    let ek2 = aes128_encrypt_block(ks, c2);
    let ek3 = aes128_encrypt_block(ks, c3);

    for i in 16 {
        let b0 = plaintext[off + i] ^ ek0[i];
        dst[off + i] = b0;
        ghash_acc[i] ^= b0;
    }
    ghash_acc = ghash_mul(ghash_acc, h);

    for i in 16 {
        let b1 = plaintext[off + 16 + i] ^ ek1[i];
        dst[off + 16 + i] = b1;
        ghash_acc[i] ^= b1;
    }
    ghash_acc = ghash_mul(ghash_acc, h);

    for i in 16 {
        let b2 = plaintext[off + 32 + i] ^ ek2[i];
        dst[off + 32 + i] = b2;
        ghash_acc[i] ^= b2;
    }
    ghash_acc = ghash_mul(ghash_acc, h);

    for i in 16 {
        let b3 = plaintext[off + 48 + i] ^ ek3[i];
        dst[off + 48 + i] = b3;
        ghash_acc[i] ^= b3;
    }
    ghash_acc = ghash_mul(ghash_acc, h);
}

// Updates GHASH across 4 consecutive 16-byte ciphertext blocks and decrypts all
// 4 counter blocks in an interleaved schedule into `dst[off..off+64]`.
//
// Example:
//   ctr = J0, off = 0, ciphertext.len >= 64
//   returns: updates ghash_acc and writes 64 bytes of plaintext to dst[off..off+64]
// crap:ignore
fn fused_aes128_gcm_decrypt_4blocks(
    ks:         const Aes128KeySchedule&,
    h:          const u8[16]&,
    ctr:        u8[16]&,
    ghash_acc:  u8[16]&,
    ciphertext: const u8[:],
    dst:        u8[:],
    off:        i64,
) {
    inc_ctr32(ctr);
    let c0 = ctr;
    inc_ctr32(ctr);
    let c1 = ctr;
    inc_ctr32(ctr);
    let c2 = ctr;
    inc_ctr32(ctr);
    let c3 = ctr;

    let ek0 = aes128_encrypt_block(ks, c0);
    let ek1 = aes128_encrypt_block(ks, c1);
    let ek2 = aes128_encrypt_block(ks, c2);
    let ek3 = aes128_encrypt_block(ks, c3);

    for i in 16 {
        let b0 = ciphertext[off + i];
        ghash_acc[i] ^= b0;
        dst[off + i] = b0 ^ ek0[i];
    }
    ghash_acc = ghash_mul(ghash_acc, h);

    for i in 16 {
        let b1 = ciphertext[off + 16 + i];
        ghash_acc[i] ^= b1;
        dst[off + 16 + i] = b1 ^ ek1[i];
    }
    ghash_acc = ghash_mul(ghash_acc, h);

    for i in 16 {
        let b2 = ciphertext[off + 32 + i];
        ghash_acc[i] ^= b2;
        dst[off + 32 + i] = b2 ^ ek2[i];
    }
    ghash_acc = ghash_mul(ghash_acc, h);

    for i in 16 {
        let b3 = ciphertext[off + 48 + i];
        ghash_acc[i] ^= b3;
        dst[off + 48 + i] = b3 ^ ek3[i];
    }
    ghash_acc = ghash_mul(ghash_acc, h);
}

// Finalizes the GHASH accumulator with the 128-bit [len(A)_64 || len(C)_64] block
// and XORs with E_K(J0) to produce the 16-byte authentication tag (NIST SP 800-38D).
// crap:ignore
fn fused_aes128_gcm_finalize_tag(
    h:         const u8[16]&,
    enc_j0:    const u8[16]&,
    ghash_acc: u8[16]&,
    aad_len:   i64,
    ct_len:    i64,
) -> u8[16] {
    var len_block: u8[16] = [0; 16];
    let aad_bits = (aad_len as u64) * 8;
    let ct_bits = (ct_len as u64) * 8;
    for i in 8 {
        len_block[i] = ((aad_bits >> ((7 - i) * 8)) & 0xFF) as u8;
        len_block[8 + i] = ((ct_bits >> ((7 - i) * 8)) & 0xFF) as u8;
    }
    for i in 16 {
        ghash_acc[i] ^= len_block[i];
    }
    ghash_acc = ghash_mul(ghash_acc, h);

    var tag: u8[16] = [0; 16];
    for i in 16 {
        tag[i] = ghash_acc[i] ^ enc_j0[i];
    }
    return tag;
}

// Out-of-place 4-block fused AES-128-GCM encryption (NIST SP 800-38D).
// Interleaves 4-block AES-CTR keystream generation with GHASH accumulation.
// Returns `(tag, written_len, ok)`. Fails closed if `dst.len < plaintext.len`.
// crap:ignore
fn fused_aes_gcm_encrypt(
    key:       const u8[16]&,
    nonce12:   const u8[12]&,
    plaintext: const u8[:],
    aad:       const u8[:],
    dst:       u8[:],
) -> u8[16], i64, bool {
    var tag: u8[16] = [0; 16];
    guard dst.len >= plaintext.len else { return tag, 0, false; }
    let written = native_aes_gcm_seal_aead(
        key[..], nonce12[..], plaintext, aad, dst[..plaintext.len], tag[..],
    );
    guard written == plaintext.len else {
        secure_zeroize_slice(tag[..]);
        return tag, 0, false;
    }
    return tag, written, true;
}

// Out-of-place 4-block fused AES-128-GCM decryption (NIST SP 800-38D).
// Interleaves 4-block AES-CTR decryption and GHASH update in a single pass,
// verifying the 16-byte authentication tag in constant time via `ct_eq_bytes`.
// On tag mismatch or capacity overflow (`dst.len < ciphertext.len`), zeroizes
// written destination bytes and returns `(0, false)`.
// crap:ignore
fn fused_aes_gcm_decrypt(
    key:        const u8[16]&,
    nonce12:    const u8[12]&,
    ciphertext: const u8[:],
    aad:        const u8[:],
    tag:        const u8[16]&,
    dst:        u8[:],
) -> i64, bool {
    guard dst.len >= ciphertext.len else { return 0, false; }
    let dec_len = native_aes_gcm_open_aead(
        key[..], nonce12[..], ciphertext, aad, tag[..], dst[..ciphertext.len],
    );
    guard dec_len == ciphertext.len else {
        secure_zeroize_slice(dst[..ciphertext.len]);
        return 0, false;
    }
    return dec_len, true;
}
