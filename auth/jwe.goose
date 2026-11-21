// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// JWE direct A256GCM compact encryption/decryption (RFC 7516) and ConcatKDF SHA-256 (RFC 7518 Section 4.6.2).
namespace auth;

import std;
import core;
import .types;
import .internal;

// RFC 7518 Section 4.6.2: Key Derivation for ECDH Key Agreement - single-round ConcatKDF-SHA256.
fn concat_kdf_sha256(
    z:        const u8[32]&,
    alg_id:   const u8[:],
    apu:      const u8[:],
    apv:      const u8[:],
    key_bits: u32,
) -> u8[32] {
    var input_buf: u8[>..] = [];
    defer core::secure_zeroize_slice(input_buf[..]);
    guard auth_internal::build_concat_kdf_input(input_buf, z, alg_id, apu, apv, key_bits) else {
        return [0; 32];
    }
    return core::sha256(input_buf[..]);
}

// RFC 7516 Section 5.1: Message Encryption - seals plaintext under "dir"+"A256GCM" into compact JWE `out`.
fn jwe_seal_dir_a256gcm<B>(
    protected_b64: const u8[:],
    cek:           const u8[32]&,
    iv:            const u8[12]&,
    plaintext:     const u8[:],
    out:           B&,
) -> bool {
    var committed = false;
    defer if !committed { out.resize(0); };
    guard auth_internal::validate_jwe_dir_a256gcm_header(protected_b64) else { return false; }

    var ct_buf: u8[>..] = [];
    defer core::secure_zeroize_slice(ct_buf[..]);
    ct_buf.resize(plaintext.len, 0);
    let tag, ct_len, ok_seal = core::aes256_gcm_seal(cek, iv, plaintext, protected_b64, ct_buf[..]);
    guard ok_seal else { return false; }

    var iv_b64:  u8[..24] = [];
    var ct_b64:  u8[>..]  = [];
    var tag_b64: u8[..24] = [];
    core::base64url_encode(iv[..], iv_b64);
    core::base64url_encode(ct_buf[..ct_len], ct_b64);
    core::base64url_encode(tag[..], tag_b64);

    out.clear();
    guard out.try_append(protected_b64) && out.try_append("..") else { return false; }
    guard out.try_append(iv_b64[..]) && out.try_push('.' as u8) else { return false; }
    guard out.try_append(ct_b64[..]) && out.try_push('.' as u8) else { return false; }
    guard out.try_append(tag_b64[..]) else { return false; }
    committed = true;
    return true;
}

// RFC 7516 Section 5.2: Message Decryption - verifies header/tag and decrypts compact JWE into `out`.
fn jwe_open_dir_a256gcm<B>(
    compact_token: const u8[:],
    cek:           const u8[32]&,
    out:           B&,
) -> bool {
    var committed = false;
    defer if !committed { out.resize(0); };
    let parts, ok_parts = auth_internal::split_jwe_compact_parts(compact_token);
    guard ok_parts && parts.d2 == parts.d1 + 1 else { return false; }

    let protected_b64 = compact_token[..parts.d1];
    let iv_b64 = compact_token[parts.d2 + 1..parts.d3];
    let ct_b64 = compact_token[parts.d3 + 1..parts.d4];
    let tag_b64 = compact_token[parts.d4 + 1..];
    guard iv_b64.index_of_byte('=') == -1 &&
        ct_b64.index_of_byte('=') == -1 &&
        tag_b64.index_of_byte('=') == -1 else { return false; }
    guard auth_internal::validate_jwe_dir_a256gcm_header(protected_b64) else { return false; }

    var iv_buf:  u8[..16] = [];
    var tag_buf: u8[..24] = [];
    defer core::secure_zeroize_slice(iv_buf[..]);
    defer core::secure_zeroize_slice(tag_buf[..]);
    guard core::base64url_decode(iv_b64, iv_buf) && iv_buf.len == 12 else { return false; }
    guard core::base64url_decode(tag_b64, tag_buf) && tag_buf.len == 16 else { return false; }

    var ct_buf: u8[>..] = [];
    defer core::secure_zeroize_slice(ct_buf[..]);
    guard core::base64url_decode(ct_b64, ct_buf) else { return false; }

    var nonce12: u8[12] = [0; 12];
    var tag16:   u8[16] = [0; 16];
    defer core::secure_zeroize_slice(nonce12[..]);
    defer core::secure_zeroize_slice(tag16[..]);
    for i in 12 { nonce12[i] = iv_buf[i]; }
    for i in 16 { tag16[i] = tag_buf[i]; }

    out.clear();
    guard core::aes256_gcm_open(cek, nonce12, ct_buf[..], protected_b64, tag16, out) else {
        return false;
    }
    committed = true;
    return true;
}
