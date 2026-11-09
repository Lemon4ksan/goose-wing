// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// RFC 7516 JSON Web Encryption (JWE) Compact Serialization ("dir" + "A256GCM")
// and NIST SP 800-56A / RFC 7518 §4.6.2 ConcatKDF using SHA-256.
namespace wing;

import std;
import json;
import core from "..";
import .jwt;

inline fn append_be32_prefixed_slice<B>(buf: B&, s: const u8[:]) -> bool {
    guard s.len >= 0 && s.len <= 0x7FFFFFFF else { return false; }
    var len_be: u8[4] = [0; 4];
    core::write_be_u32_at(len_be[..], 0, (s.len & 0x7FFFFFFF) as u32);
    return buf.try_append(len_be[..]) && buf.try_append(s);
}

inline fn build_concat_kdf_input<B>(
    buf:      B&,
    z:        const u8[32]&,
    alg_id:   const u8[:],
    apu:      const u8[:],
    apv:      const u8[:],
    key_bits: u32,
) -> bool {
    var round_be: u8[4] = [0, 0, 0, 1];
    var bits_be:  u8[4] = [0; 4];
    core::write_be_u32_at(bits_be[..], 0, key_bits);
    return buf.try_append(round_be[..]) &&
        buf.try_append(z[..]) &&
        append_be32_prefixed_slice(buf, alg_id) &&
        append_be32_prefixed_slice(buf, apu) &&
        append_be32_prefixed_slice(buf, apv) &&
        buf.try_append(bits_be[..]);
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
    var kdf_in: u8[..4096] = [];
    defer core::secure_zeroize_slice(kdf_in[..]);
    if build_concat_kdf_input(kdf_in, z, alg_id, apu, apv, key_bits) {
        return core::sha256(kdf_in[..]);
    }
    var kdf_dyn: u8[>..] = [];
    defer core::secure_zeroize_slice(kdf_dyn[..]);
    let _ = build_concat_kdf_input(kdf_dyn, z, alg_id, apu, apv, key_bits);
    return core::sha256(kdf_dyn[..]);
}

inline fn read_jwe_expected_str_field(
    reader:   json::Reader&,
    expected: const u8[:],
    out_has:  bool&,
    had_err:  bool&,
) {
    var val_buf: u8[..32] = [];
    if json::peek(reader) == '"' && core::read_json_string_into(reader, val_buf) && val_buf[..] == expected {
        out_has = true;
    } else {
        json::skip(reader);
        had_err = true;
    }
}

inline fn read_jwe_protected_member(
    key:       const u8[:],
    reader:    json::Reader&,
    seen_keys: SeenHeaderKey[..16]&,
    has_alg:   bool&,
    has_enc:   bool&,
    had_err:   bool&,
) {
    if key.contains('\\') || is_header_key_present(key, seen_keys[..]) {
        had_err = true;
        json::skip(reader);
        return;
    }
    var seen_item = SeenHeaderKey { .. };
    if !seen_item.name.try_set(key) || !seen_keys.try_push(seen_item) {
        had_err = true;
        json::skip(reader);
        return;
    }
    if key == "alg" {
        read_jwe_expected_str_field(reader, "dir", has_alg, had_err);
        return;
    }
    if key == "enc" {
        read_jwe_expected_str_field(reader, "A256GCM", has_enc, had_err);
        return;
    }
    if key == "crit" || key == "zip" {
        had_err = true;
        json::skip(reader);
        return;
    }
    json::skip(reader);
}

// Validates RFC 7516 §4 / §5.2 JWE Protected Header for direct A256GCM encryption.
fn validate_jwe_dir_a256gcm_header(protected_b64: const u8[:]) -> bool {
    guard protected_b64.len > 0 && protected_b64.len <= MAX_JWT_HEADER_PART_LEN else { return false; }
    guard protected_b64.index_of_byte('=') == -1 else { return false; }
    var hdr_json: u8[..2048] = [];
    guard core::base64url_decode(protected_b64, hdr_json) else { return false; }
    guard hdr_json.len > 0 && hdr_json[..].validate_utf8() else { return false; }

    var reader = json::reader(hdr_json[..]);
    guard json::peek(reader) == '{' else { return false; }
    var seen_keys: SeenHeaderKey[..16] = [];
    var has_alg = false;
    var has_enc = false;
    var had_err = false;
    json::each_member(reader) { key =>
        read_jwe_protected_member(key, reader, seen_keys, has_alg, has_enc, had_err);
    };
    return json::finish(reader) && !had_err && has_alg && has_enc;
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
    guard validate_jwe_dir_a256gcm_header(protected_b64) && plaintext.len <= 4096 else { return false; }

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
    guard compact_token.index_of_byte('=') == -1 else { return false; }
    var d1: i64 = 0;
    var d2: i64 = 0;
    var d3: i64 = 0;
    var d4: i64 = 0;
    guard split_jwe_compact_parts(compact_token, d1, d2, d3, d4) else { return false; }
    // RFC 7516 §3.1 / §5.2: For direct encryption ("dir"), the JWE Encrypted Key MUST be empty
    guard core::add_sat_i64(d1, 1) == d2 else { return false; }

    let protected_b64 = compact_token[..d1];
    guard validate_jwe_dir_a256gcm_header(protected_b64) else { return false; }
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

    guard core::aes256_gcm_open(cek, iv12, ct_dec[..], protected_b64, tag16, out_plaintext) else {
        core::secure_zeroize_slice(out_plaintext[..]);
        out_plaintext.clear();
        return false;
    }
    return true;
}
