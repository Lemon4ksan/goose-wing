// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Secure Hash Algorithms: SHA-256, SHA-384, SHA-512 (FIPS 180-4), SHA-1 (RFC 3174),
// HMAC (RFC 2104 / RFC 4231), and HKDF extract/expand (RFC 5869).
namespace core;

import std;
import core.math;
import core.crypto.ct;

// ---- sha-256 (fips 180-4 / rfc 6234) ---------------------------------------

let SHA256_K: const u32[64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

struct Sha256Ctx {
    h: u32[8] = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
        0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
    ],
    buf:       u8[64] = [0; 64],
    buf_len:   i64    = 0,
    total_len: u64    = 0,
}

fn sha256_transform(ctx: Sha256Ctx&, chunk: const u8[:]) {
    var w: u32[64] = [0; 64];
    for i in 16 {
        let off = i * 4;
        w[i] = ((chunk[off] as u32) << 24) |
               ((chunk[off + 1] as u32) << 16) |
               ((chunk[off + 2] as u32) << 8) |
               chunk[off + 3];
    }
    for i in 16..64 {
        let s0 = core::rotr32(w[i - 15], 7) ^ core::rotr32(w[i - 15], 18) ^ (w[i - 15] >> 3);
        let s1 = core::rotr32(w[i - 2], 17) ^ core::rotr32(w[i - 2], 19) ^ (w[i - 2] >> 10);
        w[i] = w[i - 16] + s0 + w[i - 7] + s1;
    }

    var a = ctx.h[0];
    var b = ctx.h[1];
    var c = ctx.h[2];
    var d = ctx.h[3];
    var e = ctx.h[4];
    var f = ctx.h[5];
    var g = ctx.h[6];
    var h = ctx.h[7];

    for i in 64 {
        let s1 = core::rotr32(e, 6) ^ core::rotr32(e, 11) ^ core::rotr32(e, 25);
        let ch = (e & f) ^ ((~e) & g);
        let temp1 = h + s1 + ch + SHA256_K[i] + w[i];
        let s0 = core::rotr32(a, 2) ^ core::rotr32(a, 13) ^ core::rotr32(a, 22);
        let maj = (a & b) ^ (a & c) ^ (b & c);
        let temp2 = s0 + maj;

        h = g;
        g = f;
        f = e;
        e = d + temp1;
        d = c;
        c = b;
        b = a;
        a = temp1 + temp2;
    }

    ctx.h[0] += a;
    ctx.h[1] += b;
    ctx.h[2] += c;
    ctx.h[3] += d;
    ctx.h[4] += e;
    ctx.h[5] += f;
    ctx.h[6] += g;
    ctx.h[7] += h;
}

fn sha256_update(ctx: Sha256Ctx&, data: const u8[:]) {
    guard data.len > 0 else { return; }
    ctx.total_len += (data.len as u64) * 8;
    var offset = 0;
    while offset < data.len {
        let needed = 64 - ctx.buf_len;
        let available = data.len - offset;
        let to_copy = min(available, needed);
        for i in to_copy {
            ctx.buf[ctx.buf_len + i] = data[offset + i];
        }
        ctx.buf_len += to_copy;
        offset += to_copy;

        if ctx.buf_len == 64 {
            sha256_transform(ctx, ctx.buf[..]);
            ctx.buf_len = 0;
        }
    }
}

fn sha256_final(ctx: Sha256Ctx&) -> u8[32] {
    ctx.buf[ctx.buf_len] = 0x80;
    ctx.buf_len += 1;

    if ctx.buf_len > 56 {
        for i in (64 - ctx.buf_len) {
            ctx.buf[ctx.buf_len + i] = 0;
        }
        sha256_transform(ctx, ctx.buf[..]);
        ctx.buf_len = 0;
    }

    for i in (56 - ctx.buf_len) {
        ctx.buf[ctx.buf_len + i] = 0;
    }

    for i in 8 {
        ctx.buf[56 + i] = ((ctx.total_len >> ((7 - i) * 8)) & 0xFF) as u8;
    }
    sha256_transform(ctx, ctx.buf[..]);

    var out: u8[32] = [0; 32];
    for i in 8 {
        out[i * 4] = ((ctx.h[i] >> 24) & 0xFF) as u8;
        out[i * 4 + 1] = ((ctx.h[i] >> 16) & 0xFF) as u8;
        out[i * 4 + 2] = ((ctx.h[i] >> 8) & 0xFF) as u8;
        out[i * 4 + 3] = (ctx.h[i] & 0xFF) as u8;
    }
    return out;
}

fn sha256(data: const u8[:]) -> u8[32] {
    var ctx = Sha256Ctx { .. };
    sha256_update(ctx, data);
    return sha256_final(ctx);
}

fn zeroize_sha256_ctx(ctx: Sha256Ctx&) {
    secure_zeroize_64(ctx.buf);
    for i in 8 { ctx.h[i] = 0; }
    ctx.buf_len = 0;
    ctx.total_len = 0;
}

// ---- hmac-sha256 (rfc 2104 / rfc 4231) -------------------------------------

fn hmac_sha256(key: const u8[:], message: const u8[:]) -> u8[32] {
    var key_block: u8[64] = [0; 64];
    if key.len > 64 {
        var hashed_key = sha256(key);
        for i in 32 { key_block[i] = hashed_key[i]; }
        secure_zeroize_32(hashed_key);
    } else {
        for i in key.len { key_block[i] = key[i]; }
    }

    var ipad: u8[64] = [0; 64];
    var opad: u8[64] = [0; 64];
    for i in 64 {
        ipad[i] = key_block[i] ^ 0x36;
        opad[i] = key_block[i] ^ 0x5c;
    }

    var inner_ctx = Sha256Ctx { .. };
    sha256_update(inner_ctx, ipad[..]);
    sha256_update(inner_ctx, message);
    var inner_hash = sha256_final(inner_ctx);

    var outer_ctx = Sha256Ctx { .. };
    sha256_update(outer_ctx, opad[..]);
    sha256_update(outer_ctx, inner_hash[..]);
    let out = sha256_final(outer_ctx);
    zeroize_sha256_ctx(inner_ctx);
    zeroize_sha256_ctx(outer_ctx);
    secure_zeroize_64(key_block);
    secure_zeroize_64(ipad);
    secure_zeroize_64(opad);
    secure_zeroize_32(inner_hash);
    return out;
}

// Evaluates HMAC-SHA256 across up to three sequential byte slices without intermediate heap allocations.
fn hmac_sha256_parts(key: const u8[:], p1: const u8[:], p2: const u8[:], p3: const u8[:]) -> u8[32] {
    var key_block: u8[64] = [0; 64];
    if key.len > 64 {
        var hashed_key = sha256(key);
        for i in 32 { key_block[i] = hashed_key[i]; }
        secure_zeroize_32(hashed_key);
    } else {
        for i in key.len { key_block[i] = key[i]; }
    }

    var ipad: u8[64] = [0; 64];
    var opad: u8[64] = [0; 64];
    for i in 64 {
        ipad[i] = key_block[i] ^ 0x36;
        opad[i] = key_block[i] ^ 0x5c;
    }

    var inner_ctx = Sha256Ctx { .. };
    sha256_update(inner_ctx, ipad[..]);
    if p1.len > 0 { sha256_update(inner_ctx, p1); }
    if p2.len > 0 { sha256_update(inner_ctx, p2); }
    if p3.len > 0 { sha256_update(inner_ctx, p3); }
    var inner_hash = sha256_final(inner_ctx);

    var outer_ctx = Sha256Ctx { .. };
    sha256_update(outer_ctx, opad[..]);
    sha256_update(outer_ctx, inner_hash[..]);
    let out = sha256_final(outer_ctx);
    zeroize_sha256_ctx(inner_ctx);
    zeroize_sha256_ctx(outer_ctx);
    secure_zeroize_64(key_block);
    secure_zeroize_64(ipad);
    secure_zeroize_64(opad);
    secure_zeroize_32(inner_hash);
    return out;
}

// ---- hkdf-sha256 (rfc 5869) ------------------------------------------------

fn hkdf_extract(salt: const u8[:], ikm: const u8[:]) -> u8[32] {
    let zero_salt: u8[32] = [0; 32];
    let actual_salt = if salt.len == 0 {
        zero_salt[..]
    } else {
        salt
    };
    return hmac_sha256(actual_salt, ikm);
}

fn hkdf_expand_32(prk: const u8[32]&, info: const u8[:]) -> u8[32] {
    let one: u8[1] = [0x01];
    return hmac_sha256_parts(prk[..], info, one[..], "");
}

fn hkdf_sha256_32(ikm: const u8[32]&, salt: const u8[:], info: const u8[:]) -> u8[32] {
    var prk = hkdf_extract(salt, ikm[..]);
    let okm = hkdf_expand_32(prk, info);
    secure_zeroize_32(prk);
    return okm;
}

// ---- sha-384 & sha-512 tables ----------------------------------------------

let SHA512_K: const u64[80] = [
    0x428a2f98d728ae22, 0x7137449123ef65cd, 0xb5c0fbcfec4d3b2f, 0xe9b5dba58189dbbc,
    0x3956c25bf348b538, 0x59f111f1b605d019, 0x923f82a4af194f9b, 0xab1c5ed5da6d8118,
    0xd807aa98a3030242, 0x12835b0145706fbe, 0x243185be4ee4b28c, 0x550c7dc3d5ffb4e2,
    0x72be5d74f27b896f, 0x80deb1fe3b1696b1, 0x9bdc06a725c71235, 0xc19bf174cf692694,
    0xe49b69c19ef14ad2, 0xefbe4786384f25e3, 0x0fc19dc68b8cd5b5, 0x240ca1cc77ac9c65,
    0x2de92c6f592b0275, 0x4a7484aa6ea6e483, 0x5cb0a9dcbd41fbd4, 0x76f988da831153b5,
    0x983e5152ee66dfab, 0xa831c66d2db43210, 0xb00327c898fb213f, 0xbf597fc7beef0ee4,
    0xc6e00bf33da88fc2, 0xd5a79147930aa725, 0x06ca6351e003826f, 0x142929670a0e6e70,
    0x27b70a8546d22ffc, 0x2e1b21385c26c926, 0x4d2c6dfc5ac42aed, 0x53380d139d95b3df,
    0x650a73548baf63de, 0x766a0abb3c77b2a8, 0x81c2c92e47edaee6, 0x92722c851482353b,
    0xa2bfe8a14cf10364, 0xa81a664bbc423001, 0xc24b8b70d0f89791, 0xc76c51a30654be30,
    0xd192e819d6ef5218, 0xd69906245565a910, 0xf40e35855771202a, 0x106aa07032bbd1b8,
    0x19a4c116b8d2d0c8, 0x1e376c085141ab53, 0x2748774cdf8eeb99, 0x34b0bcb5e19b48a8,
    0x391c0cb3c5c95a63, 0x4ed8aa4ae3418acb, 0x5b9cca4f7763e373, 0x682e6ff3d6b2b8a3,
    0x748f82ee5defb2fc, 0x78a5636f43172f60, 0x84c87814a1f0ab72, 0x8cc702081a6439ec,
    0x90befffa23631e28, 0xa4506cebde82bde9, 0xbef9a3f7b2c67915, 0xc67178f2e372532b,
    0xca273eceea26619c, 0xd186b8c721c0c207, 0xeada7dd6cde0eb1e, 0xf57d4f7fee6ed178,
    0x06f067aa72176fba, 0x0a637dc5a2c898a6, 0x113f9804bef90dae, 0x1b710b35131c471b,
    0x28db77f523047d84, 0x32caab7b40c72493, 0x3c9ebe0a15c9bebc, 0x431d67c49c100d4c,
    0x4cc5d4becb3e42b6, 0x597f299cfc657e2a, 0x5fcb6fab3ad6faec, 0x6c44198c4a475817,
];

// Shared transform block for SHA-384 and SHA-512
fn sha512_transform(h_state: u64[8]&, chunk: const u8[:]) {
    var w: u64[80] = [0; 80];
    for i in 16 {
        let off = i * 8;
        w[i] = ((chunk[off] as u64) << 56) |
               ((chunk[off + 1] as u64) << 48) |
               ((chunk[off + 2] as u64) << 40) |
               ((chunk[off + 3] as u64) << 32) |
               ((chunk[off + 4] as u64) << 24) |
               ((chunk[off + 5] as u64) << 16) |
               ((chunk[off + 6] as u64) << 8) |
               chunk[off + 7];
    }
    for i in 16..80 {
        let s0 = core::rotr64(w[i - 15], 1) ^ core::rotr64(w[i - 15], 8) ^ (w[i - 15] >> 7);
        let s1 = core::rotr64(w[i - 2], 19) ^ core::rotr64(w[i - 2], 61) ^ (w[i - 2] >> 6);
        w[i] = w[i - 16] + s0 + w[i - 7] + s1;
    }

    var a = h_state[0];
    var b = h_state[1];
    var c = h_state[2];
    var d = h_state[3];
    var e = h_state[4];
    var f = h_state[5];
    var g = h_state[6];
    var h = h_state[7];

    for i in 80 {
        let s1 = core::rotr64(e, 14) ^ core::rotr64(e, 18) ^ core::rotr64(e, 41);
        let ch = (e & f) ^ ((~e) & g);
        let temp1 = h + s1 + ch + SHA512_K[i] + w[i];
        let s0 = core::rotr64(a, 28) ^ core::rotr64(a, 34) ^ core::rotr64(a, 39);
        let maj = (a & b) ^ (a & c) ^ (b & c);
        let temp2 = s0 + maj;

        h = g;
        g = f;
        f = e;
        e = d + temp1;
        d = c;
        c = b;
        b = a;
        a = temp1 + temp2;
    }

    h_state[0] += a;
    h_state[1] += b;
    h_state[2] += c;
    h_state[3] += d;
    h_state[4] += e;
    h_state[5] += f;
    h_state[6] += g;
    h_state[7] += h;
}

// ---- sha-384 (fips 180-4) --------------------------------------------------

inline fn add_sha512_bit_len(total_lo: u64&, total_hi: u64&, byte_len: i64) {
    let lo, hi = mul_wide_u64(byte_len as u64, 8);
    let chk = add_checked_u64(total_lo, lo);
    total_lo = chk.value;
    let carry: u64 = if chk.overflow { 1 } else { 0 };
    total_hi = add_sat_u64(add_sat_u64(total_hi, hi), carry);
}

struct Sha384Ctx {
    h: u64[8] = [
        0xcbbb9d5dc1059ed8, 0x629a292a367cd507, 0x9159015a3070dd17, 0x152fecd8f70e5939,
        0x67332667ffc00b31, 0x8eb44a8768581511, 0xdb0c2e0d64f98fa7, 0x47b5481dbefa4fa4,
    ],
    buf:          u8[128] = [0; 128],
    buf_len:      i64     = 0,
    total_len:    u64     = 0,
    total_len_hi: u64     = 0,
}

fn zeroize_sha384_ctx(ctx: Sha384Ctx&) {
    secure_zeroize_slice(ctx.buf[..]);
    for i in 8 { ctx.h[i] = 0; }
    ctx.buf_len = 0;
    ctx.total_len = 0;
    ctx.total_len_hi = 0;
}

fn sha384_update(ctx: Sha384Ctx&, data: const u8[:]) {
    guard data.len > 0 else { return; }
    add_sha512_bit_len(ctx.total_len, ctx.total_len_hi, data.len);
    var offset = 0;
    while offset < data.len {
        let needed = 128 - ctx.buf_len;
        let available = data.len - offset;
        let to_copy = min(available, needed);
        for i in to_copy {
            ctx.buf[ctx.buf_len + i] = data[offset + i];
        }
        ctx.buf_len += to_copy;
        offset += to_copy;

        if ctx.buf_len == 128 {
            sha512_transform(ctx.h, ctx.buf[..]);
            ctx.buf_len = 0;
        }
    }
}

fn sha384_final(ctx: Sha384Ctx&) -> u8[48] {
    ctx.buf[ctx.buf_len] = 0x80;
    ctx.buf_len += 1;

    if ctx.buf_len > 112 {
        for i in (128 - ctx.buf_len) {
            ctx.buf[ctx.buf_len + i] = 0;
        }
        sha512_transform(ctx.h, ctx.buf[..]);
        ctx.buf_len = 0;
    }

    for i in (112 - ctx.buf_len) {
        ctx.buf[ctx.buf_len + i] = 0;
    }

    write_be_u64_at(ctx.buf[..], 112, ctx.total_len_hi);
    write_be_u64_at(ctx.buf[..], 120, ctx.total_len);
    sha512_transform(ctx.h, ctx.buf[..]);

    var out: u8[48] = [0; 48];
    for i in 6 {
        for j in 8 {
            out[i * 8 + j] = ((ctx.h[i] >> ((7 - j) * 8)) & 0xFF) as u8;
        }
    }
    return out;
}

fn sha384(data: const u8[:]) -> u8[48] {
    var ctx = Sha384Ctx { .. };
    sha384_update(ctx, data);
    return sha384_final(ctx);
}

// ---- sha-512 (fips 180-4) --------------------------------------------------

struct Sha512Ctx {
    h: u64[8] = [
        0x6a09e667f3bcc908, 0xbb67ae8584caa73b, 0x3c6ef372fe94f82b, 0xa54ff53a5f1d36f1,
        0x510e527fade682d1, 0x9b05688c2b3e6c1f, 0x1f83d9abfb41bd6b, 0x5be0cd19137e2179,
    ],
    buf:          u8[128] = [0; 128],
    buf_len:      i64     = 0,
    total_len:    u64     = 0,
    total_len_hi: u64     = 0,
}

fn zeroize_sha512_ctx(ctx: Sha512Ctx&) {
    secure_zeroize_slice(ctx.buf[..]);
    for i in 8 { ctx.h[i] = 0; }
    ctx.buf_len = 0;
    ctx.total_len = 0;
    ctx.total_len_hi = 0;
}

fn sha512_update(ctx: Sha512Ctx&, data: const u8[:]) {
    guard data.len > 0 else { return; }
    add_sha512_bit_len(ctx.total_len, ctx.total_len_hi, data.len);
    var offset = 0;
    while offset < data.len {
        let needed = 128 - ctx.buf_len;
        let available = data.len - offset;
        let to_copy = min(available, needed);
        for i in to_copy {
            ctx.buf[ctx.buf_len + i] = data[offset + i];
        }
        ctx.buf_len += to_copy;
        offset += to_copy;

        if ctx.buf_len == 128 {
            sha512_transform(ctx.h, ctx.buf[..]);
            ctx.buf_len = 0;
        }
    }
}

fn sha512_final(ctx: Sha512Ctx&) -> u8[64] {
    ctx.buf[ctx.buf_len] = 0x80;
    ctx.buf_len += 1;

    if ctx.buf_len > 112 {
        for i in (128 - ctx.buf_len) {
            ctx.buf[ctx.buf_len + i] = 0;
        }
        sha512_transform(ctx.h, ctx.buf[..]);
        ctx.buf_len = 0;
    }

    for i in (112 - ctx.buf_len) {
        ctx.buf[ctx.buf_len + i] = 0;
    }

    write_be_u64_at(ctx.buf[..], 112, ctx.total_len_hi);
    write_be_u64_at(ctx.buf[..], 120, ctx.total_len);
    sha512_transform(ctx.h, ctx.buf[..]);

    var out: u8[64] = [0; 64];
    for i in 8 {
        for j in 8 {
            out[i * 8 + j] = ((ctx.h[i] >> ((7 - j) * 8)) & 0xFF) as u8;
        }
    }
    return out;
}

fn sha512(data: const u8[:]) -> u8[64] {
    var ctx = Sha512Ctx { .. };
    sha512_update(ctx, data);
    return sha512_final(ctx);
}

// ---- sha-512-256 (fips 180-4) ----------------------------------------------

struct Sha512_256Ctx {
    h: u64[8] = [
        0x22312194fc2bf72c, 0x9f555fa3c84c64c2, 0x2393b86b6f53b151, 0x963877195940eabd,
        0x96283ee2a88effe3, 0xbe5e1e2553863992, 0x2b0199fc2c85b8aa, 0x0eb72ddc81c52ca2,
    ],
    buf:          u8[128] = [0; 128],
    buf_len:      i64     = 0,
    total_len:    u64     = 0,
    total_len_hi: u64     = 0,
}

fn sha512_256_update(ctx: Sha512_256Ctx&, data: const u8[:]) {
    guard data.len > 0 else { return; }
    add_sha512_bit_len(ctx.total_len, ctx.total_len_hi, data.len);
    var offset = 0;
    while offset < data.len {
        let needed = 128 - ctx.buf_len;
        let available = data.len - offset;
        let to_copy = min(available, needed);
        for i in to_copy {
            ctx.buf[ctx.buf_len + i] = data[offset + i];
        }
        ctx.buf_len += to_copy;
        offset += to_copy;

        if ctx.buf_len == 128 {
            sha512_transform(ctx.h, ctx.buf[..]);
            ctx.buf_len = 0;
        }
    }
}

fn sha512_256_final(ctx: Sha512_256Ctx&) -> u8[32] {
    ctx.buf[ctx.buf_len] = 0x80;
    ctx.buf_len += 1;

    if ctx.buf_len > 112 {
        for i in (128 - ctx.buf_len) {
            ctx.buf[ctx.buf_len + i] = 0;
        }
        sha512_transform(ctx.h, ctx.buf[..]);
        ctx.buf_len = 0;
    }

    for i in (112 - ctx.buf_len) {
        ctx.buf[ctx.buf_len + i] = 0;
    }

    write_be_u64_at(ctx.buf[..], 112, ctx.total_len_hi);
    write_be_u64_at(ctx.buf[..], 120, ctx.total_len);
    sha512_transform(ctx.h, ctx.buf[..]);

    var out: u8[32] = [0; 32];
    for i in 4 {
        for j in 8 {
            out[i * 8 + j] = ((ctx.h[i] >> ((7 - j) * 8)) & 0xFF) as u8;
        }
    }
    return out;
}

fn sha512_256(data: const u8[:]) -> u8[32] {
    var ctx = Sha512_256Ctx { .. };
    sha512_256_update(ctx, data);
    return sha512_256_final(ctx);
}

// ---- hmac-sha512 (rfc 2104 / rfc 4231) -------------------------------------

fn hmac_sha512(key: const u8[:], message: const u8[:]) -> u8[64] {
    var key_block: u8[128] = [0; 128];
    if key.len > 128 {
        var hashed_key = sha512(key);
        for i in 64 { key_block[i] = hashed_key[i]; }
        secure_zeroize_64(hashed_key);
    } else {
        for i in key.len { key_block[i] = key[i]; }
    }

    var ipad: u8[128] = [0; 128];
    var opad: u8[128] = [0; 128];
    for i in 128 {
        ipad[i] = key_block[i] ^ 0x36;
        opad[i] = key_block[i] ^ 0x5c;
    }

    var inner_ctx = Sha512Ctx { .. };
    sha512_update(inner_ctx, ipad[..]);
    sha512_update(inner_ctx, message);
    var inner_hash = sha512_final(inner_ctx);

    var outer_ctx = Sha512Ctx { .. };
    sha512_update(outer_ctx, opad[..]);
    sha512_update(outer_ctx, inner_hash[..]);
    let out = sha512_final(outer_ctx);
    zeroize_sha512_ctx(inner_ctx);
    zeroize_sha512_ctx(outer_ctx);
    secure_zeroize_slice(key_block[..]);
    secure_zeroize_slice(ipad[..]);
    secure_zeroize_slice(opad[..]);
    secure_zeroize_64(inner_hash);
    return out;
}

// ---- hmac-sha384 (rfc 2104 / rfc 4231) -------------------------------------

fn hmac_sha384(key: const u8[:], message: const u8[:]) -> u8[48] {
    var key_block: u8[128] = [0; 128];
    if key.len > 128 {
        var hashed_key = sha384(key);
        for i in 48 { key_block[i] = hashed_key[i]; }
        secure_zeroize_48(hashed_key);
    } else {
        for i in key.len { key_block[i] = key[i]; }
    }

    var ipad: u8[128] = [0; 128];
    var opad: u8[128] = [0; 128];
    for i in 128 {
        ipad[i] = key_block[i] ^ 0x36;
        opad[i] = key_block[i] ^ 0x5c;
    }

    var inner_ctx = Sha384Ctx { .. };
    sha384_update(inner_ctx, ipad[..]);
    sha384_update(inner_ctx, message);
    var inner_hash = sha384_final(inner_ctx);

    var outer_ctx = Sha384Ctx { .. };
    sha384_update(outer_ctx, opad[..]);
    sha384_update(outer_ctx, inner_hash[..]);
    let out = sha384_final(outer_ctx);
    zeroize_sha384_ctx(inner_ctx);
    zeroize_sha384_ctx(outer_ctx);
    secure_zeroize_slice(key_block[..]);
    secure_zeroize_slice(ipad[..]);
    secure_zeroize_slice(opad[..]);
    secure_zeroize_48(inner_hash);
    return out;
}

// Evaluates HMAC-SHA384 across up to three sequential byte slices without intermediate heap allocations.
fn hmac_sha384_parts(key: const u8[:], p1: const u8[:], p2: const u8[:], p3: const u8[:]) -> u8[48] {
    var key_block: u8[128] = [0; 128];
    if key.len > 128 {
        var hashed_key = sha384(key);
        for i in 48 { key_block[i] = hashed_key[i]; }
        secure_zeroize_48(hashed_key);
    } else {
        for i in key.len { key_block[i] = key[i]; }
    }

    var ipad: u8[128] = [0; 128];
    var opad: u8[128] = [0; 128];
    for i in 128 {
        ipad[i] = key_block[i] ^ 0x36;
        opad[i] = key_block[i] ^ 0x5c;
    }

    var inner_ctx = Sha384Ctx { .. };
    sha384_update(inner_ctx, ipad[..]);
    if p1.len > 0 { sha384_update(inner_ctx, p1); }
    if p2.len > 0 { sha384_update(inner_ctx, p2); }
    if p3.len > 0 { sha384_update(inner_ctx, p3); }
    var inner_hash = sha384_final(inner_ctx);

    var outer_ctx = Sha384Ctx { .. };
    sha384_update(outer_ctx, opad[..]);
    sha384_update(outer_ctx, inner_hash[..]);
    let out = sha384_final(outer_ctx);
    zeroize_sha384_ctx(inner_ctx);
    zeroize_sha384_ctx(outer_ctx);
    secure_zeroize_slice(key_block[..]);
    secure_zeroize_slice(ipad[..]);
    secure_zeroize_slice(opad[..]);
    secure_zeroize_48(inner_hash);
    return out;
}

// ---- hkdf-sha384 (rfc 5869) ------------------------------------------------

fn hkdf_extract_384(salt: const u8[:], ikm: const u8[:]) -> u8[48] {
    let zero_salt: u8[48] = [0; 48];
    let actual_salt = if salt.len == 0 {
        zero_salt[..]
    } else {
        salt
    };
    return hmac_sha384(actual_salt, ikm);
}

fn hkdf_expand_bytes_256(prk: const u8[:], info: const u8[:], length: u16, out: u8[:]) -> bool {
    let len_i64 = length as i64;
    var n: i64 = (len_i64 + 31) / 32;
    guard prk.len >= 32 && n <= 255 && out.len >= len_i64 else { return false; }
    var t:       u8[32] = [0; 32];
    var out_off: i64    = 0;

    for i in 1..n + 1 {
        let ctr: u8[1] = [i as u8];
        let p1 = if i > 1 { t[..] } else { "" };
        t = hmac_sha256_parts(prk, p1, info, ctr[..]);
        let to_copy = min(len_i64 - out_off, 32);
        for j in to_copy {
            out[out_off + j] = t[j];
        }
        out_off += to_copy;
    }
    secure_zeroize_32(t);
    return true;
}

fn hkdf_expand_bytes_384(prk: const u8[:], info: const u8[:], length: u16, out: u8[:]) -> bool {
    let len_i64 = length as i64;
    var n: i64 = (len_i64 + 47) / 48;
    guard prk.len >= 48 && n <= 255 && out.len >= len_i64 else { return false; }
    var t:       u8[48] = [0; 48];
    var out_off: i64    = 0;

    for i in 1..n + 1 {
        let ctr: u8[1] = [i as u8];
        let p1 = if i > 1 { t[..] } else { "" };
        t = hmac_sha384_parts(prk, p1, info, ctr[..]);
        let to_copy = min(len_i64 - out_off, 48);
        for j in to_copy {
            out[out_off + j] = t[j];
        }
        out_off += to_copy;
    }
    secure_zeroize_48(t);
    return true;
}

// ---- sha-1 (rfc 3174, for rfc 6455 websocket handshakes) --------------------

fn sha1_compress(state: u32[5]&, chunk: const u8[:]) {
    var w: u32[80] = [0; 80];
    for t in 16 {
        let off = t * 4;
        w[t] = ((chunk[off] as u32) << 24) |
               ((chunk[off + 1] as u32) << 16) |
               ((chunk[off + 2] as u32) << 8) |
               chunk[off + 3];
    }
    for t in 16..80 {
        w[t] = core::rotl32(w[t - 3] ^ w[t - 8] ^ w[t - 14] ^ w[t - 16], 1);
    }

    var a = state[0];
    var b = state[1];
    var c = state[2];
    var d = state[3];
    var e = state[4];

    for t in 80 {
        var f: u32 = 0;
        var k: u32 = 0;
        if t < 20 {
            f = (b & c) | ((~b) & d);
            k = 0x5A827999;
        } else if t < 40 {
            f = b ^ c ^ d;
            k = 0x6ED9EBA1;
        } else if t < 60 {
            f = (b & c) | (b & d) | (c & d);
            k = 0x8F1BBCDC;
        } else {
            f = b ^ c ^ d;
            k = 0xCA62C1D6;
        }

        let temp = core::rotl32(a, 5) + f + e + k + w[t];
        e = d;
        d = c;
        c = core::rotl32(b, 30);
        b = a;
        a = temp;
    }

    state[0] += a;
    state[1] += b;
    state[2] += c;
    state[3] += d;
    state[4] += e;
}

fn sha1(data: const u8[:]) -> u8[20] {
    var state: u32[5] = [
        0x67452301,
        0xEFCDAB89,
        0x98BADCFE,
        0x10325476,
        0xC3D2E1F0,
    ];

    let total_len = data.len;
    var offset = 0;
    while offset + 64 <= total_len {
        sha1_compress(state, data[offset..offset + 64]);
        offset += 64;
    }

    let rem = total_len - offset;
    var blk: u8[64] = [0; 64];
    for i in rem { blk[i] = data[offset + i]; }
    blk[rem] = 0x80;

    let bit_len = (total_len as u64) * 8;
    if rem >= 56 {
        sha1_compress(state, blk[..]);
        blk = [0; 64];
        for i in 8 {
            blk[56 + i] = ((bit_len >> ((7 - i) * 8)) & 0xFF) as u8;
        }
        sha1_compress(state, blk[..]);
    } else {
        for i in 8 {
            blk[56 + i] = ((bit_len >> ((7 - i) * 8)) & 0xFF) as u8;
        }
        sha1_compress(state, blk[..]);
    }

    var out: u8[20] = [0; 20];
    for i in 5 {
        let val = state[i];
        out[i * 4] = ((val >> 24) & 0xFF) as u8;
        out[i * 4 + 1] = ((val >> 16) & 0xFF) as u8;
        out[i * 4 + 2] = ((val >> 8) & 0xFF) as u8;
        out[i * 4 + 3] = (val & 0xFF) as u8;
    }
    return out;
}
