// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// RFC 7516 JSON Web Encryption (JWE) Compact Serialization ("dir" + "A256GCM")
// and NIST SP 800-56A / RFC 7518 §4.6.2 ConcatKDF using SHA-256.
namespace wing;

import std;
import core from "..";
import .jwt;

inline fn append_be32_prefixed_slice(buf: u8[..512]&, s: const u8[:]) -> bool {
    let rem = core::sub_sat_i64(buf.cap, buf.len);
    let need = core::add_sat_i64(s.len, 4);
    guard need <= rem && s.len >= 0 && s.len <= 512 else { return false; }
    var len_be: u8[4] = [0; 4];
    core::write_be_u32_at(len_be[..], 0, (s.len & 0xFFFF) as u32);
    buf.append(len_be[..]);
    buf.append(s);
    return true;
}

// Single-pass NIST SP 800-56A / RFC 7518 §4.6.2 ConcatKDF using SHA-256.
// Derives a 256-bit (32-byte) key from shared secret `z` and SuppPubInfo (`alg_id`, `apu`, `apv`, `key_bits`).
fn concat_kdf_sha256(
    z:        const u8[32]&,
    alg_id:   const u8[:],
    apu:      const u8[:],
    apv:      const u8[:],
    key_bits: u32,
) -> u8[32] {
    var kdf_in:   u8[..512] = [];
    var round_be: u8[4]     = [0, 0, 0, 1];
    kdf_in.append(round_be[..]);
    kdf_in.append(z[..]);
    let _ = append_be32_prefixed_slice(kdf_in, alg_id);
    let _ = append_be32_prefixed_slice(kdf_in, apu);
    let _ = append_be32_prefixed_slice(kdf_in, apv);
    var bits_be: u8[4] = [0; 4];
    core::write_be_u32_at(bits_be[..], 0, key_bits);
    if core::sub_sat_i64(kdf_in.cap, kdf_in.len) >= 4 {
        kdf_in.append(bits_be[..]);
    }
    let out = core::sha256(kdf_in[..]);
    core::secure_zeroize_slice(kdf_in[..]);
    return out;
}

// Splits an RFC 7516 JWE Compact Serialization into its 4 dot positions (5 segments).
//
// Example:
//   token = "hdr..iv.ct.tag"
//   returns: ok = true, d1 = 3, d2 = 4, d3 = 7, d4 = 10
fn split_jwe_compact_parts(
    token: const u8[:],
    d1:    i64&,
    d2:    i64&,
    d3:    i64&,
    d4:    i64&,
) -> bool {
    guard token.len > 0 && token.len <= MAX_JWT_TOKEN_LEN else { return false; }
    d1 = -1;
    d2 = -1;
    d3 = -1;
    d4 = -1;
    for i in token.len {
        let ch = token[i];
        if ch == '.' {
            if d1 == -1 {
                d1 = i;
            } else if d2 == -1 {
                d2 = i;
            } else if d3 == -1 {
                d3 = i;
            } else if d4 == -1 {
                d4 = i;
            } else {
                return false;
            }
        }
    }
    return d1 > 0 && d2 > d1 && d3 > d2 && d4 > d3 && d4 < core::sub_sat_i64(token.len, 1);
}

// Encrypts `plaintext` into RFC 7516 JWE Compact Serialization using `"alg":"dir"` and `"enc":"A256GCM"`.
// Produces `protected_b64..base64url(iv).base64url(ciphertext).base64url(tag)`.
fn jwe_seal_dir_a256gcm<B>(
    protected_b64: const u8[:],
    cek:           const u8[32]&,
    iv:            const u8[12]&,
    plaintext:     const u8[:],
    out_compact:   B&,
) -> bool {
    out_compact.clear();
    guard protected_b64.len > 0 && protected_b64.len <= MAX_JWT_HEADER_PART_LEN else { return false; }
    guard core::index_of_byte(protected_b64, '=') == -1 && plaintext.len <= 4096 else { return false; }

    var ct_buf: u8[4096] = [0; 4096];
    let tag, ct_len, ok = core::aes256_gcm_seal(cek, iv, plaintext, protected_b64, ct_buf[..]);
    guard ok else { return false; }

    var token_buf: u8[..8192] = [];
    token_buf.append(protected_b64);
    token_buf.append("..");
    core::base64url_encode(iv[..], token_buf);
    token_buf.push('.');
    core::base64url_encode(ct_buf[..ct_len], token_buf);
    token_buf.push('.');
    core::base64url_encode(tag[..], token_buf);
    return out_compact.try_set(token_buf[..]);
}

// Decrypts and authenticates an RFC 7516 JWE Compact Serialization using `"alg":"dir"` and `"enc":"A256GCM"`.
// Enforces 5 dot-separated parts, empty encrypted key for `dir`, 12-byte IV, 16-byte tag, and AAD = `protected_b64`.
fn jwe_open_dir_a256gcm<B>(
    compact_token: const u8[:],
    cek:           const u8[32]&,
    out_plaintext: B&,
) -> bool {
    out_plaintext.clear();
    guard core::index_of_byte(compact_token, '=') == -1 else { return false; }
    var d1: i64 = 0;
    var d2: i64 = 0;
    var d3: i64 = 0;
    var d4: i64 = 0;
    guard split_jwe_compact_parts(compact_token, d1, d2, d3, d4) else { return false; }
    // RFC 7516 §3.1 / §5.2: For direct encryption ("dir"), the JWE Encrypted Key MUST be empty
    guard core::add_sat_i64(d1, 1) == d2 else { return false; }

    let protected_b64 = compact_token[..d1];
    let iv_start = core::add_sat_i64(d2, 1);
    let ct_start = core::add_sat_i64(d3, 1);
    let tag_start = core::add_sat_i64(d4, 1);

    var iv_dec:  u8[..32]   = [];
    var tag_dec: u8[..32]   = [];
    var ct_dec:  u8[..4096] = [];
    guard core::base64url_decode(compact_token[iv_start..d3], iv_dec) else { return false; }
    guard core::base64url_decode(compact_token[ct_start..d4], ct_dec) else { return false; }
    guard core::base64url_decode(compact_token[tag_start..], tag_dec) else { return false; }
    guard iv_dec.len == 12 && tag_dec.len == 16 else { return false; }

    var iv12: u8[12] = [0; 12];
    for i in 12 { iv12[i] = iv_dec[i]; }
    var tag16: u8[16] = [0; 16];
    for i in 16 { tag16[i] = tag_dec[i]; }

    return core::aes256_gcm_open(cek, iv12, ct_dec[..], protected_b64, tag16, out_plaintext);
}
