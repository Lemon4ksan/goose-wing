// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Hybrid Public Key Encryption (RFC 9180) for ECH (RFC 9849) and Secure Messaging.
// Supports DHKEM(X25519, HKDF-SHA256) with AES-128-GCM, AES-256-GCM, and ChaCha20-Poly1305.
namespace wing;

import std;
import core from "..";

// ---- RFC 9180 Identifiers and Code Points --------------------------------

// kem_id/kdf_id are retained so suite_id is recoverable for Secret Export
// (RFC 9180 Section 5.3) after the key schedule completes.
struct HpkeContext {
    key:             u8[32] = [0; 32],
    base_nonce:      u8[12] = [0; 12],
    seq:             u64    = 0,
    exporter_secret: u8[32] = [0; 32],
    aead_id:         u16    = rfc::HPKE_AEAD_AES_128_GCM,
    kem_id:          u16    = rfc::HPKE_KEM_DHKEM_X25519_HKDF_SHA256,
    kdf_id:          u16    = rfc::HPKE_KDF_HKDF_SHA256,
    key_len:         u16    = 16,
    nonce_len:       u16    = 12,
}

// ---- Labeled KDF Primitives (RFC 9180 Section 4) -------------------------

// Computes LabeledExtract(salt, label, ikm) = HKDF-Extract(salt, "HPKE-v1" || suite_id || label || ikm)
fn hpke_labeled_extract(
    suite_id: const u8[:],
    salt:     const u8[:],
    label:    const u8[:],
    ikm:      const u8[:],
) -> u8[32] {
    var labeled_ikm: u8[..1024] = [];
    guard 7 + suite_id.len + label.len + ikm.len <= labeled_ikm.cap else {
        return [0; 32];
    }
    labeled_ikm.append("HPKE-v1");
    labeled_ikm.append(suite_id);
    labeled_ikm.append(label);
    labeled_ikm.append(ikm);

    return core::hkdf_extract(salt, labeled_ikm[..]);
}

// Computes LabeledExpand(prk, label, info, L) =
// HKDF-Expand(prk, I2OSP(L, 2) || "HPKE-v1" || suite_id || label || info, L)
fn hpke_labeled_expand(
    suite_id: const u8[:],
    prk:      const u8[:],
    label:    const u8[:],
    info:     const u8[:],
    length:   u16,
    out:      u8[:],
) -> bool {
    var labeled_info: u8[..1024] = [];
    guard 9 + suite_id.len + label.len + info.len <= labeled_info.cap else {
        return false;
    }
    labeled_info.push(((length >> 8) & 0xFF) as u8);
    labeled_info.push((length & 0xFF) as u8);
    labeled_info.append("HPKE-v1");
    labeled_info.append(suite_id);
    labeled_info.append(label);
    labeled_info.append(info);

    return core::hkdf_expand_bytes_256(prk, labeled_info[..], length, out);
}

// ---- DHKEM(X25519, HKDF-SHA256) (RFC 9180 Section 4.1) ------------------

fn derive_kem_shared_secret(
    kem_suite_id:      const u8[:],
    dh:                const u8[32]&,
    enc:               const u8[32]&,
    pkR:               const u8[32]&,
    out_shared_secret: u8[32]&,
) -> bool {
    var kem_context: u8[64] = [0; 64];
    for i in 32 {
        kem_context[i] = enc[i];
        kem_context[32 + i] = pkR[i];
    }
    var eae_prk = hpke_labeled_extract(kem_suite_id, [], "eae_prk", dh[..]);
    let ok = hpke_labeled_expand(
        kem_suite_id,
        eae_prk[..],
        "shared_secret",
        kem_context[..],
        32,
        out_shared_secret[..],
    );
    core::secure_zeroize_32(eae_prk);
    return ok;
}

// Performs DHKEM Key Encapsulation: computes shared_secret and encapsulated key (enc).
fn dhkem_x25519_encap(
    pkR:               const u8[32]&,
    ephemeral_sk:      const u8[32]&,
    out_enc:           u8[32]&,
    out_shared_secret: u8[32]&,
) -> bool {
    out_enc = core::x25519_base_scalarmult(ephemeral_sk);
    var dh = core::x25519_scalarmult(ephemeral_sk, pkR);
    var zero: u8[32] = [0; 32];
    guard !core::ct_eq_bytes(dh[..], zero[..]) else {
        core::secure_zeroize_32(dh);
        return false;
    }
    let kem_suite_id: u8[5] = [0x4B, 0x45, 0x4D, 0x00, 0x20]; // "KEM" || 0x0020
    let ok = derive_kem_shared_secret(kem_suite_id[..], dh, out_enc, pkR, out_shared_secret);
    core::secure_zeroize_32(dh);
    return ok;
}

// Performs DHKEM Key Decapsulation: reconstructs shared_secret from enc using recipient skR.
fn dhkem_x25519_decap(
    enc:               const u8[32]&,
    skR:               const u8[32]&,
    pkR:               const u8[32]&,
    out_shared_secret: u8[32]&,
) -> bool {
    var dh = core::x25519_scalarmult(skR, enc);
    var zero: u8[32] = [0; 32];
    guard !core::ct_eq_bytes(dh[..], zero[..]) else {
        core::secure_zeroize_32(dh);
        return false;
    }
    let kem_suite_id: u8[5] = [0x4B, 0x45, 0x4D, 0x00, 0x20];
    let ok = derive_kem_shared_secret(kem_suite_id[..], dh, enc, pkR, out_shared_secret);
    core::secure_zeroize_32(dh);
    return ok;
}

// ---- HPKE Key Schedule (RFC 9180 Section 5.1) ----------------------------

// Sets up a base-mode sender context (SetupBaseS).
fn hpke_setup_base_s(
    pkR:          const u8[32]&,
    info:         const u8[:],
    kem_id:       u16,
    kdf_id:       u16,
    aead_id:      u16,
    ephemeral_sk: const u8[32]&,
    out_enc:      u8[32]&,
    out_ctx:      HpkeContext&,
) -> bool {
    guard kem_id == rfc::HPKE_KEM_DHKEM_X25519_HKDF_SHA256 else { return false; }
    guard kdf_id == rfc::HPKE_KDF_HKDF_SHA256 else { return false; }

    var shared_secret: u8[32] = [0; 32];
    guard dhkem_x25519_encap(pkR, ephemeral_sk, out_enc, shared_secret) else { return false; }

    // hpke_suite_id = "HPKE" || I2OSP(kem_id, 2) || I2OSP(kdf_id, 2) || I2OSP(aead_id, 2)
    var hpke_suite_id: u8[10] = [
        0x48, 0x50, 0x4B, 0x45,
        ((kem_id >> 8) & 0xFF) as u8, (kem_id & 0xFF) as u8,
        ((kdf_id >> 8) & 0xFF) as u8, (kdf_id & 0xFF) as u8,
        ((aead_id >> 8) & 0xFF) as u8, (aead_id & 0xFF) as u8,
    ];

    // psk_id_hash = LabeledExtract("", "psk_id_hash", "")
    let psk_id_hash = hpke_labeled_extract(hpke_suite_id[..], [], "psk_id_hash", []);

    // info_hash = LabeledExtract("", "info_hash", info)
    let info_hash = hpke_labeled_extract(hpke_suite_id[..], [], "info_hash", info);

    // key_schedule_context = mode (1B) || psk_id_hash (32B) || info_hash (32B)
    var ks_context: u8[65] = [0; 65];
    ks_context[0] = rfc::HPKE_MODE_BASE;
    core::ct_copy_bytes(ks_context[1..33], psk_id_hash[..]);
    core::ct_copy_bytes(ks_context[33..65], info_hash[..]);

    // secret = LabeledExtract(shared_secret, "secret", "")
    var secret = hpke_labeled_extract(hpke_suite_id[..], shared_secret[..], "secret", []);
    core::secure_zeroize_32(shared_secret);

    // Key and Nonce lengths based on AEAD
    var key_len: u16 = 16;
    if aead_id == rfc::HPKE_AEAD_AES_256_GCM || aead_id == rfc::HPKE_AEAD_CHACHA20_POLY1305 {
        key_len = 32;
    }
    let nonce_len: u16 = 12;

    out_ctx.aead_id = aead_id;
    out_ctx.kem_id = kem_id;
    out_ctx.kdf_id = kdf_id;
    out_ctx.key_len = key_len;
    out_ctx.nonce_len = nonce_len;
    out_ctx.seq = 0;

    guard hpke_labeled_expand(
        hpke_suite_id[..],
        secret[..],
        "key",
        ks_context[..],
        key_len,
        out_ctx.key[..key_len],
    ) else {
        core::secure_zeroize_32(secret);
        return false;
    }
    guard hpke_labeled_expand(
        hpke_suite_id[..],
        secret[..],
        "base_nonce",
        ks_context[..],
        nonce_len,
        out_ctx.base_nonce[..nonce_len],
    ) else {
        core::secure_zeroize_32(secret);
        core::secure_zeroize_32(out_ctx.key);
        return false;
    }
    guard hpke_labeled_expand(
        hpke_suite_id[..],
        secret[..],
        "exp",
        ks_context[..],
        32,
        out_ctx.exporter_secret[..],
    ) else {
        core::secure_zeroize_32(secret);
        core::secure_zeroize_32(out_ctx.key);
        return false;
    }

    core::secure_zeroize_32(secret);
    return true;
}

// Sets up a base-mode recipient context (SetupBaseR).
fn hpke_setup_base_r(
    enc:     const u8[32]&,
    skR:     const u8[32]&,
    info:    const u8[:],
    kem_id:  u16,
    kdf_id:  u16,
    aead_id: u16,
    out_ctx: HpkeContext&,
) -> bool {
    guard kem_id == rfc::HPKE_KEM_DHKEM_X25519_HKDF_SHA256 else { return false; }
    guard kdf_id == rfc::HPKE_KDF_HKDF_SHA256 else { return false; }

    let pkR = core::x25519_base_scalarmult(skR);
    var shared_secret: u8[32] = [0; 32];
    guard dhkem_x25519_decap(enc, skR, pkR, shared_secret) else { return false; }

    var hpke_suite_id: u8[10] = [
        0x48, 0x50, 0x4B, 0x45,
        ((kem_id >> 8) & 0xFF) as u8, (kem_id & 0xFF) as u8,
        ((kdf_id >> 8) & 0xFF) as u8, (kdf_id & 0xFF) as u8,
        ((aead_id >> 8) & 0xFF) as u8, (aead_id & 0xFF) as u8,
    ];

    let psk_id_hash = hpke_labeled_extract(hpke_suite_id[..], [], "psk_id_hash", []);
    let info_hash = hpke_labeled_extract(hpke_suite_id[..], [], "info_hash", info);

    var ks_context: u8[65] = [0; 65];
    ks_context[0] = rfc::HPKE_MODE_BASE;
    core::ct_copy_bytes(ks_context[1..33], psk_id_hash[..]);
    core::ct_copy_bytes(ks_context[33..65], info_hash[..]);

    var secret = hpke_labeled_extract(hpke_suite_id[..], shared_secret[..], "secret", []);
    core::secure_zeroize_32(shared_secret);

    var key_len: u16 = 16;
    if aead_id == rfc::HPKE_AEAD_AES_256_GCM || aead_id == rfc::HPKE_AEAD_CHACHA20_POLY1305 {
        key_len = 32;
    }
    let nonce_len: u16 = 12;

    out_ctx.aead_id = aead_id;
    out_ctx.kem_id = kem_id;
    out_ctx.kdf_id = kdf_id;
    out_ctx.key_len = key_len;
    out_ctx.nonce_len = nonce_len;
    out_ctx.seq = 0;

    guard hpke_labeled_expand(
        hpke_suite_id[..],
        secret[..],
        "key",
        ks_context[..],
        key_len,
        out_ctx.key[..key_len],
    ) else {
        core::secure_zeroize_32(secret);
        return false;
    }
    guard hpke_labeled_expand(
        hpke_suite_id[..],
        secret[..],
        "base_nonce",
        ks_context[..],
        nonce_len,
        out_ctx.base_nonce[..nonce_len],
    ) else {
        core::secure_zeroize_32(secret);
        core::secure_zeroize_32(out_ctx.key);
        return false;
    }
    guard hpke_labeled_expand(
        hpke_suite_id[..],
        secret[..],
        "exp",
        ks_context[..],
        32,
        out_ctx.exporter_secret[..],
    ) else {
        core::secure_zeroize_32(secret);
        core::secure_zeroize_32(out_ctx.key);
        return false;
    }

    core::secure_zeroize_32(secret);
    return true;
}

// Computes current AEAD nonce: nonce = base_nonce ^ (0^32 || be64(seq)).
inline fn hpke_compute_nonce(ctx: const HpkeContext&) -> u8[12] {
    var nonce: u8[12] = [0; 12];
    for i in 12 { nonce[i] = ctx.base_nonce[i]; }
    for i in 8 {
        let b = ((ctx.seq >> ((7 - i) * 8)) & 0xFF) as u8;
        nonce[4 + i] ^= b;
    }
    return nonce;
}

// ---- HPKE Seal and Open (RFC 9180 Section 5.2) ---------------------------

// Encrypts plaintext with current context key/nonce, increments seq, and appends ciphertext + 16B tag.
fn hpke_seal(
    ctx:    HpkeContext&,
    aad:    const u8[:],
    pt:     const u8[:],
    out_ct: u8[>..]&,
) -> bool {
    let nonce = hpke_compute_nonce(ctx);
    ctx.seq += 1;

    let ct_start = out_ct.len;
    for i in pt.len { out_ct.push(0); }

    if ctx.aead_id == rfc::HPKE_AEAD_AES_128_GCM {
        var key16: u8[16] = [0; 16];
        for i in 16 { key16[i] = ctx.key[i]; }
        let tag, _, ok = core::aes128_gcm_seal(key16, nonce, pt, aad, out_ct[ct_start..]);
        core::secure_zeroize_16(key16);
        guard ok else { return false; }
        for i in 16 { out_ct.push(tag[i]); }
        return true;
    } else if ctx.aead_id == rfc::HPKE_AEAD_AES_256_GCM {
        let tag, _, ok = core::aes256_gcm_seal(ctx.key, nonce, pt, aad, out_ct[ct_start..]);
        guard ok else { return false; }
        for i in 16 { out_ct.push(tag[i]); }
        return true;
    } else if ctx.aead_id == rfc::HPKE_AEAD_CHACHA20_POLY1305 {
        let tag, _, ok = core::chacha20_poly1305_seal(ctx.key, nonce, pt, aad, out_ct[ct_start..]);
        guard ok else { return false; }
        for i in 16 { out_ct.push(tag[i]); }
        return true;
    }
    return false;
}

inline fn hpke_dispatch_open(
    aead_id: u16,
    key:     const u8[32]&,
    nonce:   const u8[12]&,
    ct:      const u8[:],
    aad:     const u8[:],
    tag:     const u8[16]&,
    out_pt:  u8[>..]&,
) -> bool {
    if aead_id == rfc::HPKE_AEAD_AES_128_GCM {
        var key16: u8[16] = [0; 16];
        for i in 16 { key16[i] = key[i]; }
        let ok = core::aes128_gcm_open(key16, nonce, ct, aad, tag, out_pt);
        core::secure_zeroize_16(key16);
        return ok;
    }
    if aead_id == rfc::HPKE_AEAD_AES_256_GCM {
        return core::aes256_gcm_open(key, nonce, ct, aad, tag, out_pt);
    }
    if aead_id == rfc::HPKE_AEAD_CHACHA20_POLY1305 {
        return core::chacha20_poly1305_open(key, nonce, ct, aad, tag, out_pt);
    }
    return false;
}

// Decrypts ciphertext + 16B tag with current context key/nonce, increments seq.
fn hpke_open(
    ctx:         HpkeContext&,
    aad:         const u8[:],
    ct_with_tag: const u8[:],
    out_pt:      u8[>..]&,
) -> bool {
    guard ctx.seq < 0xFFFFFFFFFFFFFFFF else { return false; }
    guard ct_with_tag.len >= 16 else { return false; }
    let ct_len = core::sub_sat_i64(ct_with_tag.len, 16);
    let ct = ct_with_tag[..ct_len];

    var tag: u8[16] = [0; 16];
    for i in 16 { tag[i] = ct_with_tag[core::add_sat_i64(ct_len, i)]; }

    let nonce = hpke_compute_nonce(ctx);
    guard hpke_dispatch_open(ctx.aead_id, ctx.key, nonce, ct, aad, tag, out_pt) else {
        return false;
    }
    ctx.seq += 1;
    return true;
}

// ---- Secret Export (RFC 9180 Section 5.3) ----------------------------------

// Exports a secret of length out.len from an established context:
// Context.Export(exporter_context, L) = LabeledExpand(exporter_secret, "sec",
// exporter_context, L). Does not advance seq or consume context state.
fn hpke_export(ctx: const HpkeContext&, exporter_context: const u8[:], out: u8[:]) -> bool {
    guard out.len > 0 && out.len <= 8160 else { return false; } // 255 * Nh for SHA-256
    // labeled_info = I2OSP(L,2) || "HPKE-v1" || suite_id || "sec" || context
    // fits u8[..1024] (22 fixed bytes + exporter_context).
    guard exporter_context.len + 22 <= 1024 else { return false; }
    let suite_id: u8[10] = [
        0x48, 0x50, 0x4B, 0x45,
        ((ctx.kem_id >> 8) & 0xFF) as u8, (ctx.kem_id & 0xFF) as u8,
        ((ctx.kdf_id >> 8) & 0xFF) as u8, (ctx.kdf_id & 0xFF) as u8,
        ((ctx.aead_id >> 8) & 0xFF) as u8, (ctx.aead_id & 0xFF) as u8,
    ];
    return hpke_labeled_expand(
        suite_id[..],
        ctx.exporter_secret[..],
        "sec",
        exporter_context,
        out.len as u16,
        out,
    );
}

// Single-shot seal for ECH: generates ephemeral keys, encapsulates, and seals in one pass.
fn hpke_seal_base(
    pkR:          const u8[32]&,
    info:         const u8[:],
    aad:          const u8[:],
    pt:           const u8[:],
    ephemeral_sk: const u8[32]&,
    aead_id:      u16,
    out_enc:      u8[32]&,
    out_ct:       u8[>..]&,
) -> bool {
    var ctx = HpkeContext { .. };
    guard hpke_setup_base_s(
        pkR,
        info,
        rfc::HPKE_KEM_DHKEM_X25519_HKDF_SHA256,
        rfc::HPKE_KDF_HKDF_SHA256,
        aead_id,
        ephemeral_sk,
        out_enc,
        ctx,
    ) else {
        return false;
    }
    let ok = hpke_seal(ctx, aad, pt, out_ct);
    core::secure_zeroize_32(ctx.key);
    core::secure_zeroize_32(ctx.exporter_secret);
    return ok;
}

// Single-shot open for ECH recipient.
fn hpke_open_base(
    enc:         const u8[32]&,
    skR:         const u8[32]&,
    info:        const u8[:],
    aad:         const u8[:],
    ct_with_tag: const u8[:],
    aead_id:     u16,
    out_pt:      u8[>..]&,
) -> bool {
    var ctx = HpkeContext { .. };
    guard hpke_setup_base_r(
        enc,
        skR,
        info,
        rfc::HPKE_KEM_DHKEM_X25519_HKDF_SHA256,
        rfc::HPKE_KDF_HKDF_SHA256,
        aead_id,
        ctx,
    ) else {
        return false;
    }
    let ok = hpke_open(ctx, aad, ct_with_tag, out_pt);
    core::secure_zeroize_32(ctx.key);
    core::secure_zeroize_32(ctx.exporter_secret);
    return ok;
}
