// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Internal helpers for cryptographic cookie jars, HPKE (RFC 9180), and Privacy Pass (RFC 9577).
namespace security_internal;

import std;
import core;
import rfc.http;
import .policy_internal;

// ---- Shared buffer capacity predicates -------------------------------------

inline fn can_fit<B>(buf: const B&, needed: i64) -> bool {
    return needed >= 0 && needed <= buf.cap;
}

inline fn can_fit(buf: const u8[>..]&, needed: i64) -> bool {
    return needed >= 0;
}

inline fn can_fit_base64url<B>(buf: const B&, raw_len: i64) -> bool {
    return core::mul_sat_i64(raw_len, 4) <= core::mul_sat_i64(buf.cap, 3);
}

inline fn can_fit_base64url(buf: const u8[>..]&, raw_len: i64) -> bool {
    return true;
}

// ---- CryptoJar internal constants & helpers --------------------------------

extern fn jar_crypto_random_bytes(out: u8[:]) -> i32 = "wing_crypto_random_bytes";

const WIRE_VER_XCHACHA20:    u8 = 0x01;
const WIRE_VER_HKDF_AES_GCM: u8 = 0x02;
const WIRE_VER_HMAC_SHA256:  u8 = 0x03;

const K_OVERHEAD_XCHACHA20:    i64 = 53; // 1 + 4 + 8 + 24 + 16
const K_OVERHEAD_HKDF_AES_GCM: i64 = 65; // 1 + 4 + 32 + 12 + 16
const K_OVERHEAD_HMAC_SHA256:  i64 = 45; // 1 + 4 + 8 + 32
const MAX_COOKIE_NAME_LEN:     i64 = 4096;
const MAX_ENCODED_COOKIE_LEN:  i64 = 16384;

var g_jar_nonce_counter: u64 = 1;

// Additional Authenticated Data (AAD) for context binding:
// ver (1B) || key_id (4B) || timestamp_sec (8B) || cookie_name_len (2B) || cookie_name.
//
// Example:
//   ver = 1, key_id = 1, timestamp_sec = 1700000000, cookie_name = "sid", out = []
//   out becomes [0x01, 0,0,0,1, 0,0,0,0,0x65,0x53,0xF1,0x00, 0,3, 's','i','d']
fn build_cookie_aad<B>(
    ver:           u8,
    key_id:        u32,
    timestamp_sec: u64,
    cookie_name:   const u8[:],
    out:           B&,
) {
    out.push(ver);
    out.append_u32_be(key_id);
    out.append_u64_be(timestamp_sec);
    out.append_u16_be(cookie_name.len as u16);
    out.append(cookie_name);
}

// Framed HMAC input buffer for SignedJar:
// ver (1B) || key_id (4B) || timestamp (8B) || cookie_name_len (2B) || cookie_name || payload_len (4B) || payload.
//
// Example:
//   key_id = 1, cookie_sec = 1700000000, cookie_name = "sid", payload = "ok", out = []
//   out becomes [0x03, 0,0,0,1, 0,0,0,0,0x65,0x53,0xF1,0x00, 0,3, 's','i','d', 0,0,0,2, 'o','k']
fn build_signed_to_sign<B>(
    key_id:      u32,
    cookie_sec:  u64,
    cookie_name: const u8[:],
    payload:     const u8[:],
    out:         B&,
) {
    out.push(WIRE_VER_HMAC_SHA256);
    out.append_u32_be(key_id);
    out.append_u64_be(cookie_sec);
    out.append_u16_be(cookie_name.len as u16);
    out.append(cookie_name);
    out.append_u32_be(payload.len as u32);
    out.append(payload);
}

fn zeroize_jar_key_slot(slot: security::KeySlot&) {
    core::secure_zeroize_32(slot.master_key);
    core::secure_zeroize_32(slot.signing_key);
    core::secure_zeroize_32(slot.encryption_key);
    slot.revoked = true;
}

inline fn is_jar_key_valid_at(slot: const security::KeySlot&, now_sec: i64) -> bool {
    guard !slot.revoked else { return false; }
    if slot.expires_at_sec > 0 && now_sec > 0 && now_sec >= slot.expires_at_sec {
        return false;
    }
    return true;
}

// RFC 8439 Section 4: Security Considerations - Mix OS CSPRNG, counter, clock, and cookie name for AEAD nonce uniqueness.
fn generate_jar_entropy(
    seed:        u64,
    now_sec:     i64,
    cookie_name: const u8[:] = "",
    domain:      u64         = 0,
) -> u8[32] {
    let now_ns = core::sim_now_ns() as u64;
    let name_hash = core::fnv1a_64(cookie_name);
    var entropy_in: u8[64] = [0; 64];
    var seq:        u64    = 0;
    if core::sim_rng_fill(entropy_in[0..32]) {
        seq = core::sim_rng_next_u64();
    } else {
        g_jar_nonce_counter = core::add_sat_u64(g_jar_nonce_counter, 1);
        seq = g_jar_nonce_counter;
        let _ = jar_crypto_random_bytes(entropy_in[0..32]);
    }
    core::write_le_u64_at(entropy_in[..], 32, seed ^ domain ^ name_hash);
    core::write_le_u64_at(entropy_in[..], 40, seq);
    core::write_le_u64_at(entropy_in[..], 48, now_ns);
    core::write_le_u64_at(entropy_in[..], 56, now_sec as u64);
    let out = core::sha256(entropy_in[..]);
    core::secure_zeroize_64(entropy_in);
    return out;
}

inline fn init_hkdf_salt_nonce(
    nonce_seed:  u64,
    now_sec:     i64,
    cookie_name: const u8[:],
    salt:        u8[32]&,
    nonce12:     u8[12]&,
) {
    var entropy1 = generate_jar_entropy(nonce_seed, now_sec, cookie_name, 0x73616c745f686b64);
    var entropy2 = generate_jar_entropy(nonce_seed, now_sec, cookie_name, 0x6e6f6e63655f3132);
    salt = entropy1;
    core::write_le_u64_at(salt[..], 8, now_sec as u64);
    core::ct_copy_bytes(nonce12[..], entropy2[..12]);
    core::secure_zeroize_32(entropy1);
    core::secure_zeroize_32(entropy2);
}

fn seal_binary_hkdf_aes<B>(
    slot:        const security::KeySlot&,
    cookie_name: const u8[:],
    plaintext:   const u8[:],
    now_sec:     i64,
    nonce_seed:  u64,
    out:         B&,
) -> bool {
    guard now_sec > 0 && is_jar_key_valid_at(slot, now_sec) &&
        cookie_name.len > 0 && cookie_name.len <= MAX_COOKIE_NAME_LEN else { return false; }
    guard can_fit(out, core::add_sat_i64(K_OVERHEAD_HKDF_AES_GCM, plaintext.len)) else { return false; }

    let saved_len = out.len;
    var committed = false;
    defer if !committed {
        core::secure_zeroize_slice(out[..]);
        out.resize(saved_len);
    };

    out.clear();
    out.push(WIRE_VER_HKDF_AES_GCM);
    out.append_u32_be(slot.key_id);

    var salt:    u8[32] = [0; 32];
    var nonce12: u8[12] = [0; 12];
    init_hkdf_salt_nonce(nonce_seed, now_sec, cookie_name, salt, nonce12);
    out.append(salt[..]);
    out.append(nonce12[..]);

    var aad_stack: u8[..4128] = [];
    build_cookie_aad(WIRE_VER_HKDF_AES_GCM, slot.key_id, now_sec as u64, cookie_name, aad_stack);
    let ct_start = out.len;
    out.resize(core::add_sat_i64(ct_start, plaintext.len), 0);
    let tag, _, ok_seal = core::hkdf_aes256_gcm_seal(
        slot.encryption_key, salt, nonce12, plaintext, aad_stack[..], out[ct_start..],
    );
    guard ok_seal else { return false; }
    out.append(tag[..]);
    committed = true;
    return true;
}

fn seal_binary_xchacha20<B>(
    slot:        const security::KeySlot&,
    cookie_name: const u8[:],
    plaintext:   const u8[:],
    now_sec:     i64,
    nonce_seed:  u64,
    out:         B&,
) -> bool {
    guard now_sec > 0 && is_jar_key_valid_at(slot, now_sec) &&
        cookie_name.len > 0 && cookie_name.len <= MAX_COOKIE_NAME_LEN else { return false; }
    guard can_fit(out, core::add_sat_i64(K_OVERHEAD_XCHACHA20, plaintext.len)) else { return false; }

    out.clear();
    let now_u = now_sec as u64;
    out.push(WIRE_VER_XCHACHA20);
    out.append_u32_be(slot.key_id);
    out.append_u64_be(now_u);

    var entropy = generate_jar_entropy(nonce_seed, now_sec, cookie_name, 0x7863686163686132);
    var nonce24: u8[24] = [0; 24];
    core::ct_copy_bytes(nonce24[..], entropy[..24]);
    core::secure_zeroize_32(entropy);
    out.append(nonce24[..]);

    var aad_stack: u8[..4128] = [];
    build_cookie_aad(WIRE_VER_XCHACHA20, slot.key_id, now_u, cookie_name, aad_stack);
    let tag = core::xchacha20_poly1305_seal(slot.encryption_key, nonce24, plaintext, aad_stack[..], out);
    out.append(tag[..]);
    return true;
}

// Appends decrypted XChaCha20-Poly1305 cookie payload into `out`, preserving existing contents on failure.
fn open_binary_xchacha20<B>(
    jar:         const security::PrivateJar&,
    slot:        const security::KeySlot&,
    cookie_name: const u8[:],
    raw_wire:    const u8[:],
    now_sec:     i64,
    out:         B&,
) -> bool {
    guard is_jar_key_valid_at(slot, now_sec) &&
        cookie_name.len > 0 && cookie_name.len <= MAX_COOKIE_NAME_LEN &&
        raw_wire.len >= K_OVERHEAD_XCHACHA20 else {
        return false;
    }
    let saved_len = out.len;
    let ct_len = core::sub_sat_i64(raw_wire.len, K_OVERHEAD_XCHACHA20);
    guard can_fit(out, core::add_sat_i64(saved_len, ct_len)) else { return false; }

    let ts = core::read_be_u64(raw_wire, 5);
    guard security::is_cookie_timestamp_valid(jar.store, ts, now_sec) else { return false; }

    var committed = false;
    defer if !committed {
        core::secure_zeroize_slice(out[saved_len..]);
        out.resize(saved_len);
    };

    var nonce24: u8[24] = [0; 24];
    core::ct_copy_bytes(nonce24[..], raw_wire[13..37]);

    let tag_off = core::add_sat_i64(37, ct_len);
    let ct = raw_wire[37..tag_off];

    var tag: u8[16] = [0; 16];
    core::ct_copy_bytes(tag[..], raw_wire[tag_off..core::add_sat_i64(tag_off, 16)]);

    var aad_stack: u8[..4128] = [];
    build_cookie_aad(WIRE_VER_XCHACHA20, slot.key_id, ts, cookie_name, aad_stack);
    guard core::xchacha20_poly1305_open(slot.encryption_key, nonce24, ct, aad_stack[..], tag, out) else {
        return false;
    }
    guard core::sub_sat_i64(out.len, saved_len) == ct_len else { return false; }
    committed = true;
    return true;
}

fn open_binary_hkdf_aes<B>(
    jar:         const security::PrivateJar&,
    slot:        const security::KeySlot&,
    cookie_name: const u8[:],
    raw_wire:    const u8[:],
    now_sec:     i64,
    out:         B&,
) -> bool {
    guard is_jar_key_valid_at(slot, now_sec) &&
        cookie_name.len > 0 && cookie_name.len <= MAX_COOKIE_NAME_LEN &&
        raw_wire.len >= K_OVERHEAD_HKDF_AES_GCM else {
        return false;
    }
    let saved_len = out.len;
    let ct_len = core::sub_sat_i64(raw_wire.len, K_OVERHEAD_HKDF_AES_GCM);
    guard can_fit(out, core::add_sat_i64(saved_len, ct_len)) else { return false; }

    var salt32: u8[32] = [0; 32];
    core::ct_copy_bytes(salt32[..], raw_wire[5..37]);
    let ts = core::read_le_u64(salt32[..], 8);
    guard security::is_cookie_timestamp_valid(jar.store, ts, now_sec) else { return false; }

    var committed = false;
    defer if !committed {
        core::secure_zeroize_slice(out[saved_len..]);
        out.resize(saved_len);
    };

    var nonce12: u8[12] = [0; 12];
    core::ct_copy_bytes(nonce12[..], raw_wire[37..49]);
    let tag_off = core::add_sat_i64(49, ct_len);
    let ct = raw_wire[49..tag_off];

    var tag: u8[16] = [0; 16];
    core::ct_copy_bytes(tag[..], raw_wire[tag_off..core::add_sat_i64(tag_off, 16)]);

    var aad_stack: u8[..4128] = [];
    build_cookie_aad(WIRE_VER_HKDF_AES_GCM, slot.key_id, ts, cookie_name, aad_stack);
    guard core::hkdf_aes256_gcm_open(slot.encryption_key, salt32, nonce12, ct, aad_stack[..], tag, out) else {
        return false;
    }
    guard core::sub_sat_i64(out.len, saved_len) == ct_len else { return false; }
    committed = true;
    return true;
}

fn compute_signed_jar_mac(
    signing_key: const u8[32]&,
    key_id:      u32,
    cookie_u:    u64,
    cookie_name: const u8[:],
    payload:     const u8[:],
) -> u8[32] {
    var to_sign_stack: u8[..8320] = [];
    let sign_len = core::add_sat_i64(19, core::add_sat_i64(cookie_name.len, payload.len));
    if sign_len <= to_sign_stack.cap {
        build_signed_to_sign(key_id, cookie_u, cookie_name, payload, to_sign_stack);
        return core::hmac_sha256(signing_key[..], to_sign_stack[..]);
    }
    var to_sign_dyn: u8[>..] = [];
    build_signed_to_sign(key_id, cookie_u, cookie_name, payload, to_sign_dyn);
    return core::hmac_sha256(signing_key[..], to_sign_dyn[..]);
}

// Decodes base64url cookie into stack_buf (<= 5500 chars) or dyn_buf, returning a view of the decoded wire bytes.
//
// Example:
//   encoded_val = "AQID", stack_buf = [], dyn_buf = []
//   returns: [0x01, 0x02, 0x03], ok = true
fn decode_jar_base64url(
    encoded_val: const u8[:],
    stack_buf:   u8[..4200]&,
    dyn_buf:     u8[>..]&,
) -> const u8[:], bool {
    guard encoded_val.len > 0 && encoded_val.len <= MAX_ENCODED_COOKIE_LEN else {
        return encoded_val[..0], false;
    }
    if encoded_val.len <= 5500 {
        guard core::base64url_decode(encoded_val, stack_buf) else { return encoded_val[..0], false; }
        return stack_buf[..], true;
    }
    guard core::base64url_decode(encoded_val, dyn_buf) else { return encoded_val[..0], false; }
    return dyn_buf[..], true;
}

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

// ---- Privacy Pass (RFC 9577) internal helpers ------------------------------

enum Token68SkipResult {
    NotToken68,
    Skipped,
    Invalid,
}

// RFC 9577 Section 2.1.1.1: Server Name Encoding - Authority host[:port] without userinfo, path, or whitespace.
inline fn is_valid_privacypass_server_name(s: const u8[:]) -> bool {
    guard s.len > 0 && core::find_byteset(s, "@/?#\\ \t,") < 0 && core::swar_find_ctl(s) == s.len else {
        return false;
    }
    var probe: u8[..272] = "https://";
    guard probe.try_append(s) else { return false; }
    return security::extract_hostname_from_origin(probe[..]).len > 0;
}

inline fn is_valid_privacypass_origin_info(orig: const u8[:]) -> bool {
    if orig.len == 0 { return true; }
    var tok = core::make_byte_tokenizer(orig, ',');
    loop {
        let item, ok = core::token_next(tok);
        guard ok else { break; }
        guard is_valid_privacypass_server_name(item) else { return false; }
    }
    return true;
}

inline fn is_valid_quoted_pair_byte(b: u8) -> bool {
    return b == '\t' || b == ' ' || (b >= 0x21 && b <= 0x7E) || b >= 0x80;
}

inline fn is_valid_qdtext_byte(b: u8) -> bool {
    return b == '\t' || b == ' ' || b == 0x21 || (b >= 0x23 && b <= 0x5B) ||
        (b >= 0x5D && b <= 0x7E) || b >= 0x80;
}

// Scans an RFC 9110 Section 5.6.4 quoted-string starting at `quoted[0] == '"'`.
// Writes unescaped payload into `out` and returns consumed byte count including both quotes.
//
// Example:
//   quoted = "\"a\\\"b\", next"
//   returns: consumed = 6, ok = true, out = "a\"b"
inline fn decode_auth_quoted_string<B>(quoted: const u8[:], out: B&) -> i64, bool {
    guard quoted.len >= 2 && quoted[0] == '"' else { return 0, false; }
    let saved_len = out.len;
    var committed = false;
    defer if !committed { out.resize(saved_len); };

    out.clear();
    var pos: i64 = 1;
    while pos < quoted.len {
        let b = quoted[pos];
        if b == '"' {
            committed = true;
            return core::add_sat_i64(pos, 1), true;
        }
        if b == '\\' {
            pos = core::add_sat_i64(pos, 1);
            guard pos < quoted.len && is_valid_quoted_pair_byte(quoted[pos]) else { return 0, false; }
            guard out.try_push(quoted[pos]) else { return 0, false; }
        } else {
            guard is_valid_qdtext_byte(b) && out.try_push(b) else { return 0, false; }
        }
        pos = core::add_sat_i64(pos, 1);
    }
    return 0, false;
}

// Extracts parameter value from key-value parameter string into `out`.
// Leaves `idx` and `out` unchanged on error.
//
// Example:
//   rem = "= \"abc\", def", idx = 0
//   returns: true, idx = 7, out = "abc"
fn parse_param_val<B>(rem: const u8[:], idx: i64&, out: B&) -> bool {
    guard idx >= 0 && idx <= rem.len else { return false; }
    let saved_idx = idx;
    let saved_len = out.len;
    var committed = false;
    defer if !committed {
        idx = saved_idx;
        out.resize(saved_len);
    };

    let after_key = rem[idx..].trim_lws_start();
    guard after_key.len > 0 && after_key[0] == '=' else { return false; }
    let after_eq = after_key[1..].trim_lws_start();
    guard after_eq.len > 0 else { return false; }

    let v_start = core::sub_sat_i64(rem.len, after_eq.len);
    if after_eq[0] == '"' {
        let consumed_q, ok_q = decode_auth_quoted_string(after_eq, out);
        guard ok_q else { return false; }
        let next_idx = core::add_sat_i64(v_start, consumed_q);
        guard next_idx <= rem.len else { return false; }
        let tail = rem[next_idx..];
        guard tail.len == 0 || core::is_lws(tail[0]) || tail[0] == ',' else { return false; }
        idx = next_idx;
        committed = true;
        return true;
    }
    let delim = core::find_byteset(after_eq, ", \t");
    let v_len = if delim >= 0 { delim } else { after_eq.len };
    let val = after_eq[..v_len];
    guard is_valid_cors_token(val) && out.try_set(val) else { return false; }
    idx = core::add_sat_i64(v_start, v_len);
    committed = true;
    return true;
}

// Validates and stores a padded base64url-encoded challenge parameter (RFC 9577 Section 2.1.2).
//
// Example:
//   val = "AQIDBA=="
//   returns: true, challenge_b64 = "AQIDBA=="
fn decode_challenge_b64_param(val: const u8[:], challenge_b64: u8[..512]&) -> bool {
    // RFC 9577 Section 2.1.2: Sending Token Challenges - The challenge base64url value MUST include padding.
    guard val.len > 0 && core::is_valid_padded_base64url(val) else { return false; }
    return challenge_b64.try_set(val);
}

// Decodes padded base64url-encoded token-key parameter into buffer (RFC 9577 Section 2.1.2).
//
// Example:
//   val = "ZXhhbXBsZQ=="
//   returns: ok = true, temp_token_key = "example"
fn decode_token_key_param(val: const u8[:], temp_token_key: u8[..512]&) -> bool {
    // RFC 9577 Section 2.1.2: Sending Token Challenges - The token-key base64url value MUST include padding.
    guard val.len > 0 && core::is_valid_padded_base64url(val) else { return false; }
    var raw_key: u8[..512] = [];
    guard core::base64url_decode(val, raw_key) && raw_key.len > 0 else { return false; }
    return temp_token_key.try_set(raw_key[..]);
}

// Scans an auth-param key token up to `=`, `,`, or whitespace.
//
// Example:
//   rem = "challenge=\"xyz\""
//   returns: "challenge"
fn read_param_key(rem: const u8[:]) -> const u8[:] {
    let delim = core::find_byteset(rem, "=, \t");
    return if delim >= 0 { rem[..delim] } else { rem };
}

inline fn is_next_auth_challenge_start(rem: const u8[:]) -> bool {
    let tok = read_param_key(rem);
    guard is_valid_cors_token(tok) else { return false; }
    let rest = rem[tok.len..];
    if rest.len == 0 || rest[0] == ',' {
        return true;
    }
    guard core::is_lws(rest[0]) else { return false; }
    let after_ws = rest.trim_lws_start();
    return after_ws.len == 0 || after_ws[0] != '=';
}

// Advances `idx` past optional LWS and a required comma separator between auth-params or challenges.
//
// Example:
//   params_str = ", max-age=60", idx = 0
//   returns: true, idx = 1
inline fn consume_challenge_param_delimiter(params_str: const u8[:], idx: i64&) -> bool {
    let after_val = params_str[idx..].trim_lws_start();
    idx = core::sub_sat_i64(params_str.len, after_val.len);
    guard idx < params_str.len else { return true; }
    guard params_str[idx] == ',' else { return false; }
    idx = core::add_sat_i64(idx, 1);
    return params_str[idx..].trim_lws().len > 0;
}

inline fn apply_privacypass_param(
    key:            const u8[:],
    val:            const u8[:],
    seen_mask:      u8&,
    challenge_b64:  u8[..512]&,
    temp_token_key: u8[..512]&,
    temp_max_age:   i64&,
) -> bool {
    if key.eq_ascii_fold("challenge") {
        guard (seen_mask & 1) == 0 && decode_challenge_b64_param(val, challenge_b64) else { return false; }
        seen_mask |= 1;
        return true;
    }
    if key.eq_ascii_fold("token-key") {
        guard (seen_mask & 2) == 0 && decode_token_key_param(val, temp_token_key) else { return false; }
        seen_mask |= 2;
        return true;
    }
    if key.eq_ascii_fold("max-age") {
        guard (seen_mask & 4) == 0 else { return false; }
        let secs, ok_sec = val.parse_i64_dec();
        guard ok_sec && secs >= 0 else { return false; }
        seen_mask |= 4;
        temp_max_age = secs;
        return true;
    }
    return true;
}

// Parses comma-separated PrivateToken challenge parameters starting at `idx`, stopping if a subsequent
// challenge scheme begins after a comma (RFC 9577 Section 2.1.2.1).
//
// Example:
//   raw = "challenge=\"AQIDBA==\", max-age=3600", idx = 0
//   returns: true, idx = 34, challenge_b64 = "AQIDBA=="
fn parse_challenge_params(
    raw:            const u8[:],
    idx:            i64&,
    challenge_b64:  u8[..512]&,
    temp_token_key: u8[..512]&,
    temp_max_age:   i64&,
) -> bool {
    guard idx >= 0 && idx <= raw.len else { return false; }
    let saved_idx = idx;
    var committed = false;
    defer if !committed {
        idx = saved_idx;
        challenge_b64.clear();
        temp_token_key.clear();
        temp_max_age = 0;
    };

    challenge_b64.clear();
    temp_token_key.clear();
    temp_max_age = 0;

    var seen_mask: u8 = 0;
    var first_param = true;
    while idx < raw.len {
        let rem = raw[idx..].trim_lws_start();
        idx = core::sub_sat_i64(raw.len, rem.len);
        guard idx < raw.len else { break; }
        if !first_param && is_next_auth_challenge_start(rem) {
            break;
        }
        first_param = false;

        let key = read_param_key(rem);
        guard is_valid_cors_token(key) else { return false; }
        idx = core::add_sat_i64(idx, key.len);

        var val_buf: u8[..512] = [];
        guard parse_param_val(raw, idx, val_buf) else { return false; }
        guard apply_privacypass_param(
            key, val_buf[..], seen_mask, challenge_b64, temp_token_key, temp_max_age,
        ) else {
            return false;
        }
        guard consume_challenge_param_delimiter(raw, idx) else { return false; }
    }
    guard challenge_b64.len > 0 else { return false; }
    committed = true;
    return true;
}

inline fn is_valid_token68_slice(s: const u8[:]) -> bool {
    guard s.len > 0 else { return false; }
    var seen_eq = false;
    for b in s {
        if b == '=' {
            seen_eq = true;
            continue;
        }
        guard !seen_eq else { return false; }
        let ok = core::is_ascii_alphanumeric(b) || b == '-' || b == '.' || b == '_' ||
            b == '~' || b == '+' || b == '/';
        guard ok else { return false; }
    }
    return true;
}

inline fn try_skip_token68_challenge_param(
    raw:      const u8[:],
    rem_init: const u8[:],
    idx:      i64&,
) -> Token68SkipResult {
    let first_tok = read_param_key(rem_init);
    let after_first = rem_init[first_tok.len..].trim_lws_start();
    let tok68_cand = rem_init[..core::sub_sat_i64(rem_init.len, after_first.len)].trim_lws_end();
    let is_tok68 = after_first.len == 0 || (after_first[0] == ',' && is_valid_token68_slice(tok68_cand));
    guard is_tok68 else { return Token68SkipResult.NotToken68; }
    let tok68_end = core::find_byteset(rem_init, ", \t");
    let tlen = if tok68_end >= 0 { tok68_end } else { rem_init.len };
    guard is_valid_token68_slice(rem_init[..tlen]) else { return Token68SkipResult.Invalid; }
    idx = core::add_sat_i64(idx, tlen);
    return if consume_challenge_param_delimiter(raw, idx) {
        Token68SkipResult.Skipped
    } else {
        Token68SkipResult.Invalid
    };
}

// Skips non-PrivateToken challenge parameters (or token68) up to the next challenge in `WWW-Authenticate`.
//
// Example:
//   raw = "realm=\"grease\", PrivateToken challenge=\"AQID\"", idx = 0
//   returns: true, idx = 16
fn skip_other_auth_challenge_params(raw: const u8[:], idx: i64&) -> bool {
    let rem_init = raw[idx..].trim_lws_start();
    idx = core::sub_sat_i64(raw.len, rem_init.len);
    guard idx < raw.len else { return true; }

    let tok68_res = try_skip_token68_challenge_param(raw, rem_init, idx);
    if tok68_res != Token68SkipResult.NotToken68 {
        return tok68_res == Token68SkipResult.Skipped;
    }

    var first_param = true;
    while idx < raw.len {
        let rem = raw[idx..].trim_lws_start();
        idx = core::sub_sat_i64(raw.len, rem.len);
        guard idx < raw.len else { break; }
        if !first_param && is_next_auth_challenge_start(rem) {
            break;
        }
        first_param = false;
        let key = read_param_key(rem);
        guard is_valid_cors_token(key) else { return false; }
        idx = core::add_sat_i64(idx, key.len);
        var val_buf: u8[..512] = [];
        guard parse_param_val(raw, idx, val_buf) else { return false; }
        guard consume_challenge_param_delimiter(raw, idx) else { return false; }
    }
    return true;
}

fn find_free_token_slot(cache: const security::PrivateTokenCache&, now_sec: i64) -> i64, bool {
    var earliest_idx: i64 = 0;
    var earliest_exp: i64 = 9223372036854775807;
    for &entry, i in cache.entries {
        if entry.used || (entry.expires_at_sec > 0 && now_sec > entry.expires_at_sec) {
            return i, true;
        }
        if entry.expires_at_sec > 0 && entry.expires_at_sec < earliest_exp {
            earliest_exp = entry.expires_at_sec;
            earliest_idx = i;
        }
    }
    if cache.entries.len < cache.entries.cap {
        return 0, false;
    }
    return earliest_idx, true;
}

inline fn entry_matches_challenge(
    entry:   const security::CachedToken&,
    digest:  const u8[32]&,
    now_sec: i64,
) -> bool {
    guard !entry.used else { return false; }
    guard entry.expires_at_sec == 0 || now_sec <= entry.expires_at_sec else { return false; }
    // RFC 9577 Section 2.1.4: Token Caching - Cached tokens can only be redeemed when they match all of the fields in the TokenChallenge.
    return core::ct_eq_bytes(entry.challenge_digest[..], digest[..]);
}

inline fn header_contains_private_token_scheme(raw: const u8[:]) -> bool {
    let clean = raw.trim_lws();
    let scheme_len = rfc::SCHEME_PRIVATE_TOKEN.len;
    if clean.len >= scheme_len && clean[..scheme_len].eq_ascii_fold(rfc::SCHEME_PRIVATE_TOKEN) {
        if clean.len == scheme_len || core::is_lws(clean[scheme_len]) || clean[scheme_len] == ',' {
            return true;
        }
    }
    var key: u8[..512] = [];
    let _, _, ok = security::parse_private_token_challenge(clean, key);
    return ok;
}
