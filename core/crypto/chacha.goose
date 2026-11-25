// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// ChaCha20, HChaCha20, Poly1305, and ChaCha20-Poly1305 / XChaCha20-Poly1305 AEAD (RFC 8439).
// Zero dynamic heap allocations on key derivation, keystream generation, and MAC computation.
namespace core;

import std;
import core.math;
import core.crypto.ct;

extern fn native_chacha_poly_seal_aead(
    key:     const u8[:],
    iv:      const u8[:],
    src:     const u8[:],
    aad:     const u8[:],
    dst:     u8[:],
    tag_out: u8[:],
) -> i64 = "wing_chacha_poly_seal_aead";

extern fn native_chacha_poly_open_aead(
    key: const u8[:],
    iv:  const u8[:],
    src: const u8[:],
    aad: const u8[:],
    tag: const u8[:],
    dst: u8[:],
) -> i64 = "wing_chacha_poly_open_aead";

inline fn chacha_qr(a: u32&, b: u32&, c: u32&, d: u32&) {
    a += b; d ^= a; d = core::rotl32(d, 16);
    c += d; b ^= c; b = core::rotl32(b, 12);
    a += b; d ^= a; d = core::rotl32(d, 8);
    c += d; b ^= c; b = core::rotl32(b, 7);
}

fn load_u32_le(bytes: const u8[:], offset: i64) -> u32 {
    return bytes[offset] |
           ((bytes[offset + 1] as u32) << 8) |
           ((bytes[offset + 2] as u32) << 16) |
           ((bytes[offset + 3] as u32) << 24);
}

fn store_u32_le(bytes: u8[:], offset: i64, val: u32) {
    bytes[offset] = (val & 0xFF) as u8;
    bytes[offset + 1] = ((val >> 8) & 0xFF) as u8;
    bytes[offset + 2] = ((val >> 16) & 0xFF) as u8;
    bytes[offset + 3] = ((val >> 24) & 0xFF) as u8;
}

fn hchacha20(key: const u8[32]&, nonce16: const u8[16]&) -> u8[32] {
    var s: u32[16] = [
        0x61707865, 0x3320646e, 0x79622d32, 0x6b206574,
        load_u32_le(key[..], 0), load_u32_le(key[..], 4),
        load_u32_le(key[..], 8), load_u32_le(key[..], 12),
        load_u32_le(key[..], 16), load_u32_le(key[..], 20),
        load_u32_le(key[..], 24), load_u32_le(key[..], 28),
        load_u32_le(nonce16[..], 0), load_u32_le(nonce16[..], 4),
        load_u32_le(nonce16[..], 8), load_u32_le(nonce16[..], 12),
    ];

    for r in 10 {
        chacha_qr(s[0], s[4], s[8], s[12]);
        chacha_qr(s[1], s[5], s[9], s[13]);
        chacha_qr(s[2], s[6], s[10], s[14]);
        chacha_qr(s[3], s[7], s[11], s[15]);
        chacha_qr(s[0], s[5], s[10], s[15]);
        chacha_qr(s[1], s[6], s[11], s[12]);
        chacha_qr(s[2], s[7], s[8], s[13]);
        chacha_qr(s[3], s[4], s[9], s[14]);
    }

    var out: u8[32] = [0; 32];
    store_u32_le(out[..], 0, s[0]);
    store_u32_le(out[..], 4, s[1]);
    store_u32_le(out[..], 8, s[2]);
    store_u32_le(out[..], 12, s[3]);
    store_u32_le(out[..], 16, s[12]);
    store_u32_le(out[..], 20, s[13]);
    store_u32_le(out[..], 24, s[14]);
    store_u32_le(out[..], 28, s[15]);
    secure_zeroize_u32_slice(s[..]);
    return out;
}

fn chacha20_block(key: const u8[32]&, counter: u32, nonce12: const u8[12]&) -> u8[64] {
    var orig: u32[16] = [
        0x61707865, 0x3320646e, 0x79622d32, 0x6b206574,
        load_u32_le(key[..], 0), load_u32_le(key[..], 4), load_u32_le(key[..], 8), load_u32_le(key[..], 12),
        load_u32_le(key[..], 16), load_u32_le(key[..], 20), load_u32_le(key[..], 24), load_u32_le(key[..], 28),
        counter,
        load_u32_le(nonce12[..], 0), load_u32_le(nonce12[..], 4), load_u32_le(nonce12[..], 8),
    ];
    var s = orig;
    for r in 10 {
        chacha_qr(s[0], s[4], s[8], s[12]);
        chacha_qr(s[1], s[5], s[9], s[13]);
        chacha_qr(s[2], s[6], s[10], s[14]);
        chacha_qr(s[3], s[7], s[11], s[15]);
        chacha_qr(s[0], s[5], s[10], s[15]);
        chacha_qr(s[1], s[6], s[11], s[12]);
        chacha_qr(s[2], s[7], s[8], s[13]);
        chacha_qr(s[3], s[4], s[9], s[14]);
    }

    var blk: u8[64] = [0; 64];
    for i in 16 {
        store_u32_le(blk[..], i * 4, s[i] + orig[i]);
    }
    secure_zeroize_u32_slice(s[..]);
    secure_zeroize_u32_slice(orig[..]);
    return blk;
}

// RFC 8439 Section 2.8: AEAD Construction - max plaintext length is (2^32 - 1) * 64 bytes
// because counter 0 is reserved for the Poly1305 one-time key block.
const CHACHA20_POLY1305_MAX_BYTES: i64 = 0x3FFFFFFFC0;

fn chacha20_xor<B>(
    key:     const u8[32]&,
    counter: u32,
    nonce12: const u8[12]&,
    input:   const u8[:],
    out:     B&,
) -> bool {
    guard input.len > 0 else { return true; }
    let blocks = add_sat_u64((sub_sat_i64(input.len, 1) as u64) >> 6, 1);
    guard add_sat_u64(counter as u64, blocks) <= 0x100000000 else { return false; }
    guard crypto_buf_has_room(out, input.len) else { return false; }
    var cur_ctr = counter;
    var offset = 0;
    var blk: u8[64] = [0; 64];
    defer secure_zeroize_64(blk);
    while offset < input.len {
        blk = chacha20_block(key, cur_ctr, nonce12);
        cur_ctr += 1;
        let rem = input.len - offset;
        let take = min(rem, 64);
        for i in take {
            out.push(input[offset + i] ^ blk[i]);
        }
        offset += take;
    }
    return true;
}

// Poly1305 one-time MAC over GF(2^130 - 5) using 26-bit limbs for pure 64-bit arithmetic.
fn poly1305_process_block(
    m:  const u8[17]&,
    r0: u64, r1: u64, r2: u64, r3: u64, r4: u64,
    s1: u64, s2: u64, s3: u64, s4: u64,
    h0: u64&, h1: u64&, h2: u64&, h3: u64&, h4: u64&,
) {
    let m0: u64 = core::read_le_u32(m[..], 0) & 0x3FFFFFF;
    let m1: u64 = (core::read_le_u32(m[..], 3) >> 2) & 0x3FFFFFF;
    let m2: u64 = (core::read_le_u32(m[..], 6) >> 4) & 0x3FFFFFF;
    let m3: u64 = (core::read_le_u32(m[..], 9) >> 6) & 0x3FFFFFF;
    let m4: u64 = (core::read_le_u32(m[..], 12) >> 8) | ((m[16] as! u64) << 24);

    h0 += m0; h1 += m1; h2 += m2; h3 += m3; h4 += m4;

    let d0 = h0 * r0 + h1 * s4 + h2 * s3 + h3 * s2 + h4 * s1;
    let d1 = h0 * r1 + h1 * r0 + h2 * s4 + h3 * s3 + h4 * s2;
    let d2 = h0 * r2 + h1 * r1 + h2 * r0 + h3 * s4 + h4 * s3;
    let d3 = h0 * r3 + h1 * r2 + h2 * r1 + h3 * r0 + h4 * s4;
    let d4 = h0 * r4 + h1 * r3 + h2 * r2 + h3 * r1 + h4 * r0;

    var c: u64 = d0 >> 26; h0 = d0 & 0x3FFFFFF;
    let td1 = d1 + c; c = td1 >> 26; h1 = td1 & 0x3FFFFFF;
    let td2 = d2 + c; c = td2 >> 26; h2 = td2 & 0x3FFFFFF;
    let td3 = d3 + c; c = td3 >> 26; h3 = td3 & 0x3FFFFFF;
    let td4 = d4 + c; c = td4 >> 26; h4 = td4 & 0x3FFFFFF;
    h0 += c * 5; c = h0 >> 26; h0 &= 0x3FFFFFF; h1 += c;
}

fn poly1305_finalize(
    key32: const u8[32]&,
    h0_in: u64, h1_in: u64, h2_in: u64, h3_in: u64, h4_in: u64,
) -> u8[16] {
    var h0 = h0_in;
    var h1 = h1_in;
    var h2 = h2_in;
    var h3 = h3_in;
    var h4 = h4_in;

    var c: u64 = h0 >> 26; h0 &= 0x3FFFFFF;
    h1 += c; c = h1 >> 26; h1 &= 0x3FFFFFF;
    h2 += c; c = h2 >> 26; h2 &= 0x3FFFFFF;
    h3 += c; c = h3 >> 26; h3 &= 0x3FFFFFF;
    h4 += c; c = h4 >> 26; h4 &= 0x3FFFFFF;
    h0 += c * 5; c = h0 >> 26; h0 &= 0x3FFFFFF;
    h1 += c;

    var g0 = h0 + 5; c = g0 >> 26; g0 &= 0x3FFFFFF;
    var g1 = h1 + c; c = g1 >> 26; g1 &= 0x3FFFFFF;
    var g2 = h2 + c; c = g2 >> 26; g2 &= 0x3FFFFFF;
    var g3 = h3 + c; c = g3 >> 26; g3 &= 0x3FFFFFF;
    var g4 = h4 + c - (1 << 26);

    let mask = ct_barrier_u64((g4 >> 63) - 1);
    let nmask = ~mask;
    h0 = (h0 & nmask) | (g0 & mask);
    h1 = (h1 & nmask) | (g1 & mask);
    h2 = (h2 & nmask) | (g2 & mask);
    h3 = (h3 & nmask) | (g3 & mask);
    h4 = (h4 & nmask) | (g4 & mask);

    let f0 = ((h0 | (h1 << 26)) & 0xFFFFFFFF) + core::read_le_u32(key32[..], 16);
    c = f0 >> 32;
    let f1 = (((h1 >> 6) | (h2 << 20)) & 0xFFFFFFFF) + core::read_le_u32(key32[..], 20) + c;
    c = f1 >> 32;
    let f2 = (((h2 >> 12) | (h3 << 14)) & 0xFFFFFFFF) + core::read_le_u32(key32[..], 24) + c;
    c = f2 >> 32;
    let f3 = (((h3 >> 18) | (h4 << 8)) & 0xFFFFFFFF) + core::read_le_u32(key32[..], 28) + c;

    var out: u8[16] = [0; 16];
    store_u32_le(out[..], 0, (f0 & 0xFFFFFFFF) as u32);
    store_u32_le(out[..], 4, (f1 & 0xFFFFFFFF) as u32);
    store_u32_le(out[..], 8, (f2 & 0xFFFFFFFF) as u32);
    store_u32_le(out[..], 12, (f3 & 0xFFFFFFFF) as u32);
    return out;
}

fn poly1305_mac(key32: const u8[32]&, msg: const u8[:]) -> u8[16] {
    let r0: u64 = (load_u32_le(key32[..], 0) as u64) & 0x3FFFFFF;
    let r1: u64 = ((load_u32_le(key32[..], 3) >> 2) as u64) & 0x3FFFF03;
    let r2: u64 = ((load_u32_le(key32[..], 6) >> 4) as u64) & 0x3FFC0FF;
    let r3: u64 = ((load_u32_le(key32[..], 9) >> 6) as u64) & 0x3F03FFF;
    let r4: u64 = ((load_u32_le(key32[..], 12) >> 8) as u64) & 0x00FFFFF;

    let s1 = r1 * 5;
    let s2 = r2 * 5;
    let s3 = r3 * 5;
    let s4 = r4 * 5;

    var h0: u64 = 0;
    var h1: u64 = 0;
    var h2: u64 = 0;
    var h3: u64 = 0;
    var h4: u64 = 0;

    var offset = 0;
    while offset < msg.len {
        var m: u8[17] = [0; 17];
        let rem = msg.len - offset;
        let take = min(rem, 16);
        for i in take { m[i] = msg[offset + i]; }
        m[take] = 1; // Pad byte 0x01

        poly1305_process_block(m, r0, r1, r2, r3, r4, s1, s2, s3, s4, h0, h1, h2, h3, h4);
        offset += take;
    }

    return poly1305_finalize(key32, h0, h1, h2, h3, h4);
}

// Evaluates Poly1305 AEAD MAC over AAD and ciphertext slices without heap allocations (RFC 8439 §2.8).
fn poly1305_aead_mac(key32: const u8[32]&, aad: const u8[:], ct: const u8[:]) -> u8[16] {
    let r0: u64 = (load_u32_le(key32[..], 0) as u64) & 0x3FFFFFF;
    let r1: u64 = ((load_u32_le(key32[..], 3) >> 2) as u64) & 0x3FFFF03;
    let r2: u64 = ((load_u32_le(key32[..], 6) >> 4) as u64) & 0x3FFC0FF;
    let r3: u64 = ((load_u32_le(key32[..], 9) >> 6) as u64) & 0x3F03FFF;
    let r4: u64 = ((load_u32_le(key32[..], 12) >> 8) as u64) & 0x00FFFFF;

    let s1 = r1 * 5;
    let s2 = r2 * 5;
    let s3 = r3 * 5;
    let s4 = r4 * 5;

    var h0: u64 = 0;
    var h1: u64 = 0;
    var h2: u64 = 0;
    var h3: u64 = 0;
    var h4: u64 = 0;

    var offset = 0;
    while offset + 16 <= aad.len {
        var m: u8[17] = [0; 17];
        for i in 16 { m[i] = aad[offset + i]; }
        m[16] = 1;
        poly1305_process_block(m, r0, r1, r2, r3, r4, s1, s2, s3, s4, h0, h1, h2, h3, h4);
        offset += 16;
    }
    if offset < aad.len {
        var m: u8[17] = [0; 17];
        let rem = aad.len - offset;
        for i in rem { m[i] = aad[offset + i]; }
        m[16] = 1;
        poly1305_process_block(m, r0, r1, r2, r3, r4, s1, s2, s3, s4, h0, h1, h2, h3, h4);
    }

    offset = 0;
    while offset + 16 <= ct.len {
        var m: u8[17] = [0; 17];
        for i in 16 { m[i] = ct[offset + i]; }
        m[16] = 1;
        poly1305_process_block(m, r0, r1, r2, r3, r4, s1, s2, s3, s4, h0, h1, h2, h3, h4);
        offset += 16;
    }
    if offset < ct.len {
        var m: u8[17] = [0; 17];
        let rem = ct.len - offset;
        for i in rem { m[i] = ct[offset + i]; }
        m[16] = 1;
        poly1305_process_block(m, r0, r1, r2, r3, r4, s1, s2, s3, s4, h0, h1, h2, h3, h4);
    }

    var len_m: u8[17] = [0; 17];
    for b in 8 { len_m[b] = (((aad.len as u64) >> (b * 8)) & 0xFF) as u8; }
    for b in 8 { len_m[8 + b] = (((ct.len as u64) >> (b * 8)) & 0xFF) as u8; }
    len_m[16] = 1;
    poly1305_process_block(len_m, r0, r1, r2, r3, r4, s1, s2, s3, s4, h0, h1, h2, h3, h4);

    return poly1305_finalize(key32, h0, h1, h2, h3, h4);
}

// XChaCha20-Poly1305 AEAD (24-byte nonce)
fn xchacha20_poly1305_seal<B>(
    key:            const u8[32]&,
    nonce24:        const u8[24]&,
    plaintext:      const u8[:],
    aad:            const u8[:],
    out_ciphertext: B&,
) -> u8[16], bool {
    var zero_tag: u8[16] = [0; 16];
    guard plaintext.len <= CHACHA20_POLY1305_MAX_BYTES &&
          crypto_buf_has_room(out_ciphertext, plaintext.len) else {
        return zero_tag, false;
    }
    var nonce16: u8[16] = [0; 16];
    for i in 16 { nonce16[i] = nonce24[i]; }
    var subkey = hchacha20(key, nonce16);
    defer secure_zeroize_32(subkey);

    var subnonce: u8[12] = [0; 12];
    for i in 8 { subnonce[4 + i] = nonce24[16 + i]; }

    var ot_block = chacha20_block(subkey, 0, subnonce);
    var otk: u8[32] = [0; 32];
    defer secure_zeroize_32(otk);
    for i in 32 { otk[i] = ot_block[i]; }
    secure_zeroize_64(ot_block);

    let ct_start = out_ciphertext.len;
    let ok_xor = chacha20_xor(subkey, 1, subnonce, plaintext, out_ciphertext);
    guard ok_xor && sub_sat_i64(out_ciphertext.len, ct_start) == plaintext.len else {
        out_ciphertext.resize(ct_start);
        return zero_tag, false;
    }
    let ciphertext_slice = out_ciphertext[ct_start..];

    let tag = poly1305_aead_mac(otk, aad, ciphertext_slice);
    return tag, true;
}

fn xchacha20_poly1305_open<B>(
    key:           const u8[32]&,
    nonce24:       const u8[24]&,
    ciphertext:    const u8[:],
    aad:           const u8[:],
    tag:           const u8[16]&,
    out_plaintext: B&,
) -> bool {
    guard ciphertext.len <= CHACHA20_POLY1305_MAX_BYTES else { return false; }
    var nonce16: u8[16] = [0; 16];
    for i in 16 { nonce16[i] = nonce24[i]; }
    var subkey = hchacha20(key, nonce16);

    var subnonce: u8[12] = [0; 12];
    for i in 8 { subnonce[4 + i] = nonce24[16 + i]; }

    var ot_block = chacha20_block(subkey, 0, subnonce);
    var otk: u8[32] = [0; 32];
    for i in 32 { otk[i] = ot_block[i]; }
    secure_zeroize_64(ot_block);

    let computed_tag = poly1305_aead_mac(otk, aad, ciphertext);
    guard ct_declassify_u8(ct_eq_tag16_bit(computed_tag, tag)) == 1 else {
        secure_zeroize_32(subkey);
        secure_zeroize_32(otk);
        return false;
    }
    guard crypto_buf_has_room(out_plaintext, ciphertext.len) else {
        secure_zeroize_32(subkey);
        secure_zeroize_32(otk);
        return false;
    }

    let start_len = out_plaintext.len;
    let ok_xor = chacha20_xor(subkey, 1, subnonce, ciphertext, out_plaintext);
    secure_zeroize_32(subkey);
    secure_zeroize_32(otk);
    guard ok_xor && core::sub_sat_i64(out_plaintext.len, start_len) == ciphertext.len else {
        out_plaintext.resize(start_len);
        return false;
    }
    return true;
}

// In-place ChaCha20-Poly1305 AEAD decryption (RFC 8439).
// On tag mismatch, executes secure_zeroize_slice(in_out) and returns 0, false.
fn chacha20_poly1305_open_inplace(
    key:     const u8[32]&,
    nonce12: const u8[12]&,
    in_out:  u8[:],
    aad:     const u8[:],
    tag:     const u8[16]&,
) -> i64, bool {
    guard in_out.len <= CHACHA20_POLY1305_MAX_BYTES else {
        secure_zeroize_slice(in_out);
        return 0, false;
    }
    let written = native_chacha_poly_open_aead(key[..], nonce12[..], in_out, aad, tag[..], in_out);
    guard written >= 0 else {
        secure_zeroize_slice(in_out);
        return 0, false;
    }
    return written, true;
}

// In-place ChaCha20-Poly1305 AEAD encryption (RFC 8439).
// Encrypts in_out in-place and returns the 16-byte authentication tag.
fn chacha20_poly1305_seal_inplace(
    key:     const u8[32]&,
    nonce12: const u8[12]&,
    in_out:  u8[:],
    aad:     const u8[:],
) -> u8[16], bool {
    var tag: u8[16] = [0; 16];
    guard in_out.len <= CHACHA20_POLY1305_MAX_BYTES else { return tag, false; }
    let written = native_chacha_poly_seal_aead(key[..], nonce12[..], in_out, aad, in_out, tag[..]);
    guard written >= 0 else {
        secure_zeroize_16(tag);
        return tag, false;
    }
    return tag, true;
}

// Out-of-place ChaCha20-Poly1305 AEAD decryption into caller-provided destination slice (RFC 8439).
fn chacha20_poly1305_open_into(
    key:        const u8[32]&,
    nonce12:    const u8[12]&,
    ciphertext: const u8[:],
    aad:        const u8[:],
    tag:        const u8[16]&,
    dst:        u8[:],
) -> i64, bool {
    guard ciphertext.len <= CHACHA20_POLY1305_MAX_BYTES && dst.len >= ciphertext.len else {
        return 0, false;
    }
    let written = native_chacha_poly_open_aead(
        key[..], nonce12[..], ciphertext, aad, tag[..], dst[..ciphertext.len],
    );
    guard written >= 0 else {
        secure_zeroize_slice(dst[..ciphertext.len]);
        return 0, false;
    }
    return written, true;
}

// Out-of-place ChaCha20-Poly1305 AEAD encryption into caller-provided destination slice (RFC 8439).
fn chacha20_poly1305_seal(
    key:       const u8[32]&,
    nonce12:   const u8[12]&,
    plaintext: const u8[:],
    aad:       const u8[:],
    dst:       u8[:],
) -> u8[16], i64, bool {
    var empty_tag: u8[16] = [0; 16];
    guard plaintext.len <= CHACHA20_POLY1305_MAX_BYTES && dst.len >= plaintext.len else {
        return empty_tag, 0, false;
    }
    let written = native_chacha_poly_seal_aead(
        key[..], nonce12[..], plaintext, aad, dst[..plaintext.len], empty_tag[..],
    );
    guard written >= 0 else {
        secure_zeroize_16(empty_tag);
        return empty_tag, 0, false;
    }
    return empty_tag, written, true;
}

fn chacha20_poly1305_open_small<B>(
    key:           const u8[32]&,
    nonce12:       const u8[12]&,
    ciphertext:    const u8[:],
    aad:           const u8[:],
    tag:           const u8[16]&,
    out_plaintext: B&,
) -> bool {
    guard ciphertext.len <= 2048 else { return false; }
    var pt_buf: u8[2048] = [0; 2048];
    let pt_slice = pt_buf[..ciphertext.len];
    let written = native_chacha_poly_open_aead(key[..], nonce12[..], ciphertext, aad, tag[..], pt_slice);
    guard written >= 0 else {
        secure_zeroize_slice(pt_slice);
        return false;
    }
    guard crypto_buf_has_room(out_plaintext, ciphertext.len) else {
        secure_zeroize_slice(pt_slice);
        return false;
    }
    let start_len = out_plaintext.len;
    out_plaintext.append(pt_slice);
    secure_zeroize_slice(pt_slice);
    guard core::sub_sat_i64(out_plaintext.len, start_len) == ciphertext.len else {
        out_plaintext.resize(start_len);
        return false;
    }
    return true;
}

fn chacha20_poly1305_open<B>(
    key:           const u8[32]&,
    nonce12:       const u8[12]&,
    ciphertext:    const u8[:],
    aad:           const u8[:],
    tag:           const u8[16]&,
    out_plaintext: B&,
) -> bool {
    guard ciphertext.len <= CHACHA20_POLY1305_MAX_BYTES else { return false; }
    if ciphertext.len <= 2048 {
        return chacha20_poly1305_open_small(key, nonce12, ciphertext, aad, tag, out_plaintext);
    }

    var ot_block = chacha20_block(key, 0, nonce12);
    var otk: u8[32] = [0; 32];
    for i in 32 { otk[i] = ot_block[i]; }
    secure_zeroize_64(ot_block);

    let computed_tag = poly1305_aead_mac(otk, aad, ciphertext);
    guard ct_declassify_u8(ct_eq_tag16_bit(computed_tag, tag)) == 1 else {
        secure_zeroize_32(otk);
        return false;
    }
    secure_zeroize_32(otk);
    guard crypto_buf_has_room(out_plaintext, ciphertext.len) else {
        return false;
    }

    let start_len = out_plaintext.len;
    let ok_xor = chacha20_xor(key, 1, nonce12, ciphertext, out_plaintext);
    guard ok_xor && core::sub_sat_i64(out_plaintext.len, start_len) == ciphertext.len else {
        out_plaintext.resize(start_len);
        return false;
    }
    return true;
}
