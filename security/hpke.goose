// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Hybrid Public Key Encryption (RFC 9180) for ECH (RFC 9849) and Secure Messaging.
// Supports DHKEM(X25519, HKDF-SHA256) with AES-128-GCM, AES-256-GCM, and ChaCha20-Poly1305.
namespace security;

import std;
import core;
import .hpke_internal;

// ---- RFC 9180 Identifiers and Code Points --------------------------------

// RFC 9180 Section 7.3: Authenticated Encryption with Associated Data (AEAD) Functions - Export-only AEAD identifier.
const HPKE_AEAD_EXPORT_ONLY: u16 = 0xFFFF;

// RFC 9180 Section 5.2: Role discriminator prevents reusing a context across Seal and Open.
enum HpkeRole {
    Uninitialized,
    Sender,
    Recipient,
}

// kem_id/kdf_id are retained so suite_id is recoverable for Secret Export
// (RFC 9180 Section 5.3) after the key schedule completes.
struct HpkeContext {
    key:             u8[32]   = [0; 32],
    base_nonce:      u8[12]   = [0; 12],
    seq:             u64      = 0,
    exporter_secret: u8[32]   = [0; 32],
    aead_id:         u16      = 0,
    kem_id:          u16      = 0,
    kdf_id:          u16      = 0,
    key_len:         u16      = 0,
    nonce_len:       u16      = 0,
    role:            HpkeRole = HpkeRole.Uninitialized,
}

// RFC 9180 Section 5.1: Zeroizes all derived AEAD/exporter secrets and resets the context role.
fn zeroize_hpke_context(ctx: HpkeContext&) {
    core::secure_zeroize_32(ctx.key);
    core::secure_zeroize_slice(ctx.base_nonce[..]);
    core::secure_zeroize_32(ctx.exporter_secret);
    ctx.aead_id = 0;
    ctx.kem_id = 0;
    ctx.kdf_id = 0;
    ctx.key_len = 0;
    ctx.nonce_len = 0;
    ctx.seq = 0;
    ctx.role = HpkeRole.Uninitialized;
}

// ---- Labeled KDF Expansion (RFC 9180 Section 4) --------------------------

// Computes LabeledExpand(prk, label, info, L) =
// HKDF-Expand(prk, I2OSP(L, 2) || "HPKE-v1" || suite_id || label || info, L).
fn hpke_labeled_expand(
    suite_id: const u8[:],
    prk:      const u8[:],
    label:    const u8[:],
    info:     const u8[:],
    length:   u16,
    out:      u8[:],
) -> bool {
    // RFC 9180 Section 7.2.1: Input Length Restrictions - Support multi-kilobyte ECHConfig and application info buffers.
    var labeled_info: u8[..4096] = [];
    let needed = core::add_sat_i64(9, core::add_sat_i64(suite_id.len, core::add_sat_i64(label.len, info.len)));
    guard needed <= labeled_info.cap && length <= out.len && length <= 8160 else {
        return false;
    }
    labeled_info.append_u16_be(length);
    labeled_info.append("HPKE-v1");
    labeled_info.append(suite_id);
    labeled_info.append(label);
    labeled_info.append(info);

    return core::hkdf_expand_bytes_256(prk, labeled_info[..], length, out);
}

// ---- HPKE Setup (RFC 9180 Section 5.1) -------------------------------------

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
    core::secure_zeroize_32(out_enc);
    zeroize_hpke_context(out_ctx);
    var committed = false;
    defer if !committed {
        core::secure_zeroize_32(out_enc);
        zeroize_hpke_context(out_ctx);
    };

    guard kem_id == rfc::HPKE_KEM_DHKEM_X25519_HKDF_SHA256 else { return false; }
    guard kdf_id == rfc::HPKE_KDF_HKDF_SHA256 else { return false; }
    guard security_internal::is_valid_hpke_aead(aead_id) else { return false; }
    guard info.len <= 4070 else { return false; }

    var shared_secret: u8[32] = [0; 32];
    defer core::secure_zeroize_32(shared_secret);
    guard security_internal::dhkem_x25519_encap(pkR, ephemeral_sk, out_enc, shared_secret) else {
        return false;
    }
    guard security_internal::hpke_key_schedule_base(kem_id, kdf_id, aead_id, shared_secret, info, out_ctx) else {
        return false;
    }

    out_ctx.role = HpkeRole.Sender;
    committed = true;
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
    zeroize_hpke_context(out_ctx);
    var committed = false;
    defer if !committed { zeroize_hpke_context(out_ctx); };

    guard kem_id == rfc::HPKE_KEM_DHKEM_X25519_HKDF_SHA256 else { return false; }
    guard kdf_id == rfc::HPKE_KDF_HKDF_SHA256 else { return false; }
    guard security_internal::is_valid_hpke_aead(aead_id) else { return false; }
    guard info.len <= 4070 else { return false; }

    let pkR = core::x25519_base_scalarmult(skR);
    var shared_secret: u8[32] = [0; 32];
    defer core::secure_zeroize_32(shared_secret);
    guard security_internal::dhkem_x25519_decap(enc, skR, pkR, shared_secret) else { return false; }
    guard security_internal::hpke_key_schedule_base(kem_id, kdf_id, aead_id, shared_secret, info, out_ctx) else {
        return false;
    }

    out_ctx.role = HpkeRole.Recipient;
    committed = true;
    return true;
}

// ---- HPKE Seal and Open (RFC 9180 Section 5.2) ---------------------------

// Encrypts plaintext with current sender context key/nonce, increments seq, and appends ciphertext + 16B tag.
fn hpke_seal<B>(
    ctx: HpkeContext&,
    aad: const u8[:],
    pt:  const u8[:],
    out: B&,
) -> bool {
    guard ctx.role == HpkeRole.Sender && ctx.seq < 0xFFFFFFFFFFFFFFFF else { return false; }
    var nonce = security_internal::hpke_compute_nonce(ctx);
    defer core::secure_zeroize_slice(nonce[..]);
    guard security_internal::hpke_dispatch_seal(ctx.aead_id, ctx.key, nonce, pt, aad, out) else {
        return false;
    }
    ctx.seq = core::add_sat_u64(ctx.seq, 1);
    return true;
}

// Decrypts ciphertext + 16B tag with current recipient context key/nonce, increments seq.
fn hpke_open<B>(
    ctx:         HpkeContext&,
    aad:         const u8[:],
    ct_with_tag: const u8[:],
    out:         B&,
) -> bool {
    guard ctx.role == HpkeRole.Recipient && ctx.seq < 0xFFFFFFFFFFFFFFFF else { return false; }
    guard ct_with_tag.len >= 16 else { return false; }

    let saved_len = out.len;
    var committed = false;
    defer if !committed {
        core::secure_zeroize_slice(out[saved_len..]);
        out.resize(saved_len);
    };

    let ct_len = core::sub_sat_i64(ct_with_tag.len, 16);
    let ct = ct_with_tag[..^16];

    var tag: u8[16] = [0; 16];
    core::ct_copy_bytes(tag[..], ct_with_tag[ct_len..]);

    var nonce = security_internal::hpke_compute_nonce(ctx);
    defer core::secure_zeroize_slice(nonce[..]);
    guard security_internal::hpke_dispatch_open(ctx.aead_id, ctx.key, nonce, ct, aad, tag, out) else {
        return false;
    }
    ctx.seq = core::add_sat_u64(ctx.seq, 1);
    committed = true;
    return true;
}

// ---- Secret Export & Single-Shot Helpers (RFC 9180 Section 5.3 / 6) --------

// Exports a secret of length out.len from an established context:
// Context.Export(exporter_context, L) = LabeledExpand(exporter_secret, "sec", exporter_context, L).
fn hpke_export(ctx: const HpkeContext&, exporter_context: const u8[:], out: u8[:]) -> bool {
    guard ctx.role != HpkeRole.Uninitialized else { return false; }
    guard ctx.kem_id == rfc::HPKE_KEM_DHKEM_X25519_HKDF_SHA256 &&
        ctx.kdf_id == rfc::HPKE_KDF_HKDF_SHA256 &&
        security_internal::is_valid_hpke_aead(ctx.aead_id) else {
        return false;
    }
    // RFC 9180 Section 5.3: Secret Export - Enforce L <= 255 * Nh (8160 bytes for SHA-256).
    guard out.len > 0 && out.len <= 8160 else { return false; }
    guard core::add_sat_i64(exporter_context.len, 22) <= 4096 else { return false; }
    let suite_id = security_internal::build_hpke_suite_id(ctx.kem_id, ctx.kdf_id, ctx.aead_id);
    return hpke_labeled_expand(
        suite_id[..],
        ctx.exporter_secret[..],
        "sec",
        exporter_context,
        out.len as u16,
        out,
    );
}

// Single-shot seal with caller-supplied ephemeral_sk (for deterministic RFC 9180 vectors or pre-generated keys).
fn hpke_seal_base<B>(
    pkR:          const u8[32]&,
    info:         const u8[:],
    aad:          const u8[:],
    pt:           const u8[:],
    ephemeral_sk: const u8[32]&,
    aead_id:      u16,
    out_enc:      u8[32]&,
    out:          B&,
) -> bool {
    var committed = false;
    defer if !committed { core::secure_zeroize_32(out_enc); };
    var ctx = HpkeContext { .. };
    defer zeroize_hpke_context(ctx);
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
    guard hpke_seal(ctx, aad, pt, out) else { return false; }
    committed = true;
    return true;
}

// Single-shot seal generating a fresh CSPRNG ephemeral X25519 key internally.
fn hpke_seal_base_random<B>(
    pkR:     const u8[32]&,
    info:    const u8[:],
    aad:     const u8[:],
    pt:      const u8[:],
    aead_id: u16,
    out_enc: u8[32]&,
    out:     B&,
) -> bool {
    var ephemeral_sk: u8[32] = [0; 32];
    defer core::secure_zeroize_32(ephemeral_sk);
    let got_rng = if core::sim_rng_is_active() {
        core::sim_rng_fill(ephemeral_sk[..])
    } else {
        core::csprng_fill(ephemeral_sk[..])
    };
    guard got_rng else {
        core::secure_zeroize_32(out_enc);
        return false;
    }
    return hpke_seal_base(pkR, info, aad, pt, ephemeral_sk, aead_id, out_enc, out);
}

// Single-shot open for ECH recipient.
fn hpke_open_base<B>(
    enc:         const u8[32]&,
    skR:         const u8[32]&,
    info:        const u8[:],
    aad:         const u8[:],
    ct_with_tag: const u8[:],
    aead_id:     u16,
    out:         B&,
) -> bool {
    var ctx = HpkeContext { .. };
    defer zeroize_hpke_context(ctx);
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
    return hpke_open(ctx, aad, ct_with_tag, out);
}
