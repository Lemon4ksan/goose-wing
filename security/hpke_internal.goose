// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Internal helpers for HPKE (RFC 9180) key schedule, DHKEM, and AEAD dispatch.
namespace security_internal;

import std;
import core;
import rfc.http;

// ---- HPKE (RFC 9180) internal helpers --------------------------------------

inline fn build_hpke_suite_id(kem_id: u16, kdf_id: u16, aead_id: u16) -> u8[10] {
    var sid: u8[..10] = "HPKE";
    sid.append_u16_be(kem_id);
    sid.append_u16_be(kdf_id);
    sid.append_u16_be(aead_id);
    var out: u8[10] = [0; 10];
    core::ct_copy_bytes(out[..], sid[..]);
    return out;
}

// Computes LabeledExtract(salt, label, ikm) = HKDF-Extract(salt, "HPKE-v1" || suite_id || label || ikm).
fn hpke_labeled_extract(
    suite_id: const u8[:],
    salt:     const u8[:],
    label:    const u8[:],
    ikm:      const u8[:],
) -> u8[32] {
    var labeled_ikm: u8[..4096] = [];
    let needed = core::add_sat_i64(7, core::add_sat_i64(suite_id.len, core::add_sat_i64(label.len, ikm.len)));
    guard needed <= labeled_ikm.cap else {
        return [0; 32];
    }
    labeled_ikm.append("HPKE-v1");
    labeled_ikm.append(suite_id);
    labeled_ikm.append(label);
    labeled_ikm.append(ikm);

    let prk = core::hkdf_extract(salt, labeled_ikm[..]);
    core::secure_zeroize_slice(labeled_ikm[..]);
    return prk;
}

inline fn is_valid_hpke_aead(aead_id: u16) -> bool {
    return aead_id == rfc::HPKE_AEAD_AES_128_GCM ||
        aead_id == rfc::HPKE_AEAD_AES_256_GCM ||
        aead_id == rfc::HPKE_AEAD_CHACHA20_POLY1305 ||
        aead_id == security::HPKE_AEAD_EXPORT_ONLY;
}

fn derive_kem_shared_secret(
    kem_suite_id:      const u8[:],
    dh:                const u8[32]&,
    enc:               const u8[32]&,
    pkR:               const u8[32]&,
    out_shared_secret: u8[32]&,
) -> bool {
    var kem_context: u8[64] = [0; 64];
    core::ct_copy_bytes(kem_context[..32], enc[..]);
    core::ct_copy_bytes(kem_context[32..], pkR[..]);
    var eae_prk = hpke_labeled_extract(kem_suite_id, [], "eae_prk", dh[..]);
    defer core::secure_zeroize_32(eae_prk);
    return security::hpke_labeled_expand(
        kem_suite_id,
        eae_prk[..],
        "shared_secret",
        kem_context[..],
        32,
        out_shared_secret[..],
    );
}

fn dhkem_x25519_encap(
    pkR:               const u8[32]&,
    ephemeral_sk:      const u8[32]&,
    out_enc:           u8[32]&,
    out_shared_secret: u8[32]&,
) -> bool {
    var dh = core::x25519_scalarmult(ephemeral_sk, pkR);
    defer core::secure_zeroize_32(dh);
    var zero: u8[32] = [0; 32];
    guard !core::ct_eq_bytes(dh[..], zero[..]) else {
        core::secure_zeroize_32(out_enc);
        return false;
    }
    let enc_local = core::x25519_base_scalarmult(ephemeral_sk);
    let kem_suite_id: u8[5] = [0x4B, 0x45, 0x4D, 0x00, 0x20];
    guard derive_kem_shared_secret(kem_suite_id[..], dh, enc_local, pkR, out_shared_secret) else {
        core::secure_zeroize_32(out_enc);
        return false;
    }
    out_enc = enc_local;
    return true;
}

fn dhkem_x25519_decap(
    enc:               const u8[32]&,
    skR:               const u8[32]&,
    pkR:               const u8[32]&,
    out_shared_secret: u8[32]&,
) -> bool {
    var dh = core::x25519_scalarmult(skR, enc);
    defer core::secure_zeroize_32(dh);
    var zero: u8[32] = [0; 32];
    guard !core::ct_eq_bytes(dh[..], zero[..]) else {
        return false;
    }
    let kem_suite_id: u8[5] = [0x4B, 0x45, 0x4D, 0x00, 0x20];
    return derive_kem_shared_secret(kem_suite_id[..], dh, enc, pkR, out_shared_secret);
}

// RFC 9180 Section 5.1: Creating the Encryption Context - Zeroizes derived AEAD and exporter secrets.
inline fn zeroize_hpke_context(ctx: security::HpkeContext&) {
    core::secure_zeroize_32(ctx.key);
    core::secure_zeroize_slice(ctx.base_nonce[..]);
    core::secure_zeroize_32(ctx.exporter_secret);
    ctx.aead_id = 0;
    ctx.kem_id = 0;
    ctx.kdf_id = 0;
    ctx.key_len = 0;
    ctx.nonce_len = 0;
    ctx.seq = 0;
}

// RFC 9180 Section 5.1: Creating the Encryption Context - Derives base-mode HPKE key schedule and exporter secret.
fn hpke_key_schedule_base(
    kem_id:        u16,
    kdf_id:        u16,
    aead_id:       u16,
    shared_secret: const u8[32]&,
    info:          const u8[:],
    out_ctx:       security::HpkeContext&,
) -> bool {
    let hpke_suite_id = build_hpke_suite_id(kem_id, kdf_id, aead_id);
    let psk_id_hash = hpke_labeled_extract(hpke_suite_id[..], [], "psk_id_hash", []);
    let info_hash = hpke_labeled_extract(hpke_suite_id[..], [], "info_hash", info);

    var ks_context: u8[65] = [0; 65];
    ks_context[0] = rfc::HPKE_MODE_BASE;
    core::ct_copy_bytes(ks_context[1..33], psk_id_hash[..]);
    core::ct_copy_bytes(ks_context[33..65], info_hash[..]);

    var secret = hpke_labeled_extract(hpke_suite_id[..], shared_secret[..], "secret", []);
    defer core::secure_zeroize_32(secret);

    var key_len:   u16 = 0;
    var nonce_len: u16 = 0;
    if aead_id != security::HPKE_AEAD_EXPORT_ONLY {
        key_len = if aead_id == rfc::HPKE_AEAD_AES_128_GCM { 16 } else { 32 };
        nonce_len = 12;
        guard security::hpke_labeled_expand(
            hpke_suite_id[..], secret[..], "key", ks_context[..], key_len, out_ctx.key[..key_len],
        ) else {
            return false;
        }
        guard security::hpke_labeled_expand(
            hpke_suite_id[..], secret[..], "base_nonce", ks_context[..], nonce_len, out_ctx.base_nonce[..nonce_len],
        ) else {
            return false;
        }
    }
    guard security::hpke_labeled_expand(
        hpke_suite_id[..], secret[..], "exp", ks_context[..], 32, out_ctx.exporter_secret[..],
    ) else {
        return false;
    }
    out_ctx.aead_id = aead_id;
    out_ctx.kem_id = kem_id;
    out_ctx.kdf_id = kdf_id;
    out_ctx.key_len = key_len;
    out_ctx.nonce_len = nonce_len;
    out_ctx.seq = 0;
    return true;
}

// Computes current AEAD nonce: nonce = base_nonce ^ (0^32 || be64(seq)).
inline fn hpke_compute_nonce(ctx: const security::HpkeContext&) -> u8[12] {
    var nonce = ctx.base_nonce;
    var seq_bytes: u8[8] = [0; 8];
    core::write_be_u64_at(seq_bytes[..], 0, ctx.seq);
    for i in 8 {
        nonce[core::add_sat_i64(4, i)] ^= seq_bytes[i];
    }
    return nonce;
}

fn hpke_dispatch_seal<B>(
    aead_id: u16,
    key:     const u8[32]&,
    nonce:   const u8[12]&,
    pt:      const u8[:],
    aad:     const u8[:],
    out:     B&,
) -> bool {
    // RFC 9180 Section 5.2: Encryption and Decryption - Export-only contexts reject AEAD Seal operations.
    guard aead_id != security::HPKE_AEAD_EXPORT_ONLY && is_valid_hpke_aead(aead_id) else { return false; }
    guard core::add_sat_i64(out.len, core::add_sat_i64(pt.len, 16)) <= out.cap else {
        return false;
    }
    let ct_start = out.len;
    out.resize(core::add_sat_i64(ct_start, pt.len), 0);
    var tag: u8[16] = [0; 16];
    var ok = false;
    if aead_id == rfc::HPKE_AEAD_AES_128_GCM {
        var key16: u8[16] = [0; 16];
        defer core::secure_zeroize_16(key16);
        core::ct_copy_bytes(key16[..], key[..16]);
        let t, _, s = core::aes128_gcm_seal(key16, nonce, pt, aad, out[ct_start..]);
        tag = t;
        ok = s;
    } else if aead_id == rfc::HPKE_AEAD_AES_256_GCM {
        let t, _, s = core::aes256_gcm_seal(key, nonce, pt, aad, out[ct_start..]);
        tag = t;
        ok = s;
    } else if aead_id == rfc::HPKE_AEAD_CHACHA20_POLY1305 {
        let t, _, s = core::chacha20_poly1305_seal(key, nonce, pt, aad, out[ct_start..]);
        tag = t;
        ok = s;
    }
    guard ok else {
        out.resize(ct_start);
        return false;
    }
    out.append(tag[..]);
    return true;
}

inline fn hpke_dispatch_open<B>(
    aead_id: u16,
    key:     const u8[32]&,
    nonce:   const u8[12]&,
    ct:      const u8[:],
    aad:     const u8[:],
    tag:     const u8[16]&,
    out:     B&,
) -> bool {
    if aead_id == rfc::HPKE_AEAD_AES_128_GCM {
        var key16: u8[16] = [0; 16];
        defer core::secure_zeroize_16(key16);
        core::ct_copy_bytes(key16[..], key[..16]);
        return core::aes128_gcm_open(key16, nonce, ct, aad, tag, out);
    }
    if aead_id == rfc::HPKE_AEAD_AES_256_GCM {
        return core::aes256_gcm_open(key, nonce, ct, aad, tag, out);
    }
    if aead_id == rfc::HPKE_AEAD_CHACHA20_POLY1305 {
        return core::chacha20_poly1305_open(key, nonce, ct, aad, tag, out);
    }
    return false;
}
