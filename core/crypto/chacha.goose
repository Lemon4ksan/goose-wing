// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// ChaCha20, HChaCha20, Poly1305, and ChaCha20-Poly1305 / XChaCha20-Poly1305 AEAD (RFC 8439).
// Zero dynamic heap allocations on key derivation, keystream generation, and MAC computation.
namespace core;

import std;

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
    return blk;
}

fn chacha20_xor(
    key:     const u8[32]&,
    counter: u32,
    nonce12: const u8[12]&,
    input:   const u8[:],
    out:     u8[>..]&,
) {
    var cur_ctr = counter;
    var offset = 0;
    while offset < input.len {
        let blk = chacha20_block(key, cur_ctr, nonce12);
        cur_ctr += 1;
        let rem = input.len - offset;
        let take = if rem < 64 { rem } else { 64 };
        for i in take {
            out.push(input[offset + i] ^ blk[i]);
        }
        offset += take;
    }
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

    let mask = (g4 >> 63) - 1;
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
    store_u32_le(out[..], 0, f0 as u32);
    store_u32_le(out[..], 4, f1 as u32);
    store_u32_le(out[..], 8, f2 as u32);
    store_u32_le(out[..], 12, f3 as u32);
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
        let take = if rem < 16 { rem } else { 16 };
        for i in take { m[i] = msg[offset + i]; }
        m[take] = 1; // Pad byte 0x01

        poly1305_process_block(m, r0, r1, r2, r3, r4, s1, s2, s3, s4, h0, h1, h2, h3, h4);
        offset += take;
    }

    return poly1305_finalize(key32, h0, h1, h2, h3, h4);
}

// XChaCha20-Poly1305 AEAD (24-byte nonce)
fn xchacha20_poly1305_seal(
    key:            const u8[32]&,
    nonce24:        const u8[24]&,
    plaintext:      const u8[:],
    aad:            const u8[:],
    out_ciphertext: u8[>..]&,
) -> u8[16] {
    var nonce16: u8[16] = [0; 16];
    for i in 16 { nonce16[i] = nonce24[i]; }
    let subkey = hchacha20(key, nonce16);

    var subnonce: u8[12] = [0; 12];
    for i in 8 { subnonce[4 + i] = nonce24[16 + i]; }

    let ot_block = chacha20_block(subkey, 0, subnonce);
    var otk: u8[32] = [0; 32];
    for i in 32 { otk[i] = ot_block[i]; }

    let ct_start = out_ciphertext.len;
    chacha20_xor(subkey, 1, subnonce, plaintext, out_ciphertext);
    let ciphertext_slice = out_ciphertext[ct_start..];

    var auth_data: u8[>..] = [];
    auth_data.append(aad);
    if (aad.len % 16) != 0 {
        for p in (16 - (aad.len % 16)) { auth_data.push(0); }
    }
    auth_data.append(ciphertext_slice);
    if (ciphertext_slice.len % 16) != 0 {
        for p in (16 - (ciphertext_slice.len % 16)) { auth_data.push(0); }
    }
    for b in 8 { auth_data.push(((aad.len as u64) >> (b * 8)) as u8); }
    for b in 8 { auth_data.push(((ciphertext_slice.len as u64) >> (b * 8)) as u8); }

    return poly1305_mac(otk, auth_data[..]);
}

fn xchacha20_poly1305_open(
    key:           const u8[32]&,
    nonce24:       const u8[24]&,
    ciphertext:    const u8[:],
    aad:           const u8[:],
    tag:           const u8[16]&,
    out_plaintext: u8[>..]&,
) -> bool {
    var nonce16: u8[16] = [0; 16];
    for i in 16 { nonce16[i] = nonce24[i]; }
    let subkey = hchacha20(key, nonce16);

    var subnonce: u8[12] = [0; 12];
    for i in 8 { subnonce[4 + i] = nonce24[16 + i]; }

    let ot_block = chacha20_block(subkey, 0, subnonce);
    var otk: u8[32] = [0; 32];
    for i in 32 { otk[i] = ot_block[i]; }

    var auth_data: u8[>..] = [];
    auth_data.append(aad);
    if (aad.len % 16) != 0 {
        for p in (16 - (aad.len % 16)) { auth_data.push(0); }
    }
    auth_data.append(ciphertext);
    if (ciphertext.len % 16) != 0 {
        for p in (16 - (ciphertext.len % 16)) { auth_data.push(0); }
    }
    for b in 8 { auth_data.push(((aad.len as u64) >> (b * 8)) as u8); }
    for b in 8 { auth_data.push(((ciphertext.len as u64) >> (b * 8)) as u8); }

    let computed_tag = poly1305_mac(otk, auth_data[..]);
    guard ct_eq_tag16(computed_tag, tag) else {
        return false;
    }

    chacha20_xor(subkey, 1, subnonce, ciphertext, out_plaintext);
    return true;
}

// ChaCha20-Poly1305 AEAD (IETF RFC 8439, 12-byte nonce)
fn chacha20_poly1305_seal(
    key:            const u8[32]&,
    nonce12:        const u8[12]&,
    plaintext:      const u8[:],
    aad:            const u8[:],
    out_ciphertext: u8[>..]&,
) -> u8[16] {
    let ot_block = chacha20_block(key, 0, nonce12);
    var otk: u8[32] = [0; 32];
    for i in 32 { otk[i] = ot_block[i]; }

    let ct_start = out_ciphertext.len;
    chacha20_xor(key, 1, nonce12, plaintext, out_ciphertext);
    let ciphertext_slice = out_ciphertext[ct_start..];

    var auth_data: u8[>..] = [];
    auth_data.append(aad);
    if (aad.len % 16) != 0 {
        for p in (16 - (aad.len % 16)) { auth_data.push(0); }
    }
    auth_data.append(ciphertext_slice);
    if (ciphertext_slice.len % 16) != 0 {
        for p in (16 - (ciphertext_slice.len % 16)) { auth_data.push(0); }
    }
    for b in 8 { auth_data.push(((aad.len as u64) >> (b * 8)) as u8); }
    for b in 8 { auth_data.push(((ciphertext_slice.len as u64) >> (b * 8)) as u8); }

    return poly1305_mac(otk, auth_data[..]);
}

fn chacha20_poly1305_open(
    key:           const u8[32]&,
    nonce12:       const u8[12]&,
    ciphertext:    const u8[:],
    aad:           const u8[:],
    tag:           const u8[16]&,
    out_plaintext: u8[>..]&,
) -> bool {
    let ot_block = chacha20_block(key, 0, nonce12);
    var otk: u8[32] = [0; 32];
    for i in 32 { otk[i] = ot_block[i]; }

    var auth_data: u8[>..] = [];
    auth_data.append(aad);
    if (aad.len % 16) != 0 {
        for p in (16 - (aad.len % 16)) { auth_data.push(0); }
    }
    auth_data.append(ciphertext);
    if (ciphertext.len % 16) != 0 {
        for p in (16 - (ciphertext.len % 16)) { auth_data.push(0); }
    }
    for b in 8 { auth_data.push(((aad.len as u64) >> (b * 8)) as u8); }
    for b in 8 { auth_data.push(((ciphertext.len as u64) >> (b * 8)) as u8); }

    let computed_tag = poly1305_mac(otk, auth_data[..]);
    guard ct_eq_tag16(computed_tag, tag) else {
        return false;
    }

    chacha20_xor(key, 1, nonce12, ciphertext, out_plaintext);
    return true;
}
