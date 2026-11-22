// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Internal helpers for shared buffer capacity checks and cryptographic cookie jars.
namespace security_internal;

import std;
import core;

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
