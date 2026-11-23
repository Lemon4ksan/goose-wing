// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Cryptographic cookie containers (PrivateJar AEAD and SignedJar HMAC) with key rotation.
namespace security;

import std;
import core;
import .crypto_internal;

// ---- multi-key rotation container (KeyStore) -------------------------------

// Domain-separated key slot holding independent signing and encryption subkeys derived via HKDF-SHA256.
struct KeySlot {
    key_id:         u32    = 0,
    master_key:     u8[32] = [0; 32],
    signing_key:    u8[32] = [0; 32],
    encryption_key: u8[32] = [0; 32],
    created_at_sec: i64    = 0,
    expires_at_sec: i64    = 0,
    revoked:        bool   = false,
}

// Key rotation store supporting an active primary key and retired keys.
struct KeyStore {
    keys:                     KeySlot[..8] = [],
    active_idx:               i64          = 0,
    max_age_sec:              i64          = 2592000, // 30 days default session lifetime
    clock_skew_tolerance_sec: i64          = 300,     // 5 minutes skew tolerance
}

// Appends a KeySlot to the store if capacity permits, master_key is non-zero, and key_id is unique.
// Derives domain-separated signing and encryption subkeys via HKDF-SHA256.
fn add_key(store: KeyStore&, slot: const KeySlot&) -> bool {
    guard !slot.revoked && store.keys.len < store.keys.cap else { return false; }
    guard security_internal::is_nonzero_key_32(slot.master_key) else { return false; }
    for &existing in store.keys {
        if existing.key_id == slot.key_id {
            return false;
        }
    }
    var derived = KeySlot {
        key_id:         slot.key_id,
        master_key:     slot.master_key,
        signing_key:    core::hkdf_sha256_32(slot.master_key, "", "WING-COOKIE-SIGN-HMAC-SHA256"),
        encryption_key: core::hkdf_sha256_32(slot.master_key, "", "WING-COOKIE-ENC-AEAD-256"),
        created_at_sec: slot.created_at_sec,
        expires_at_sec: slot.expires_at_sec,
        revoked:        slot.revoked,
    };
    let ok = store.keys.try_push(derived);
    security_internal::zeroize_jar_key_slot(derived);
    return ok;
}

// Returns the currently active, non-revoked KeySlot.
fn active_key(store: const KeyStore&) -> KeySlot, bool {
    guard store.active_idx >= 0 && store.active_idx < store.keys.len else {
        return KeySlot { .. }, false;
    }
    let slot = store.keys[store.active_idx];
    guard !slot.revoked else { return KeySlot { .. }, false; }
    return slot, true;
}

// Sets the active primary key by key_id if present and not revoked.
fn set_active_key_id(store: KeyStore&, key_id: u32) -> bool {
    for &k, idx in store.keys {
        if k.key_id == key_id && !k.revoked {
            store.active_idx = idx;
            return true;
        }
    }
    return false;
}

// Looks up a non-revoked KeySlot by key_id for decryption or verification.
fn find_key(store: const KeyStore&, key_id: u32) -> KeySlot, bool {
    for &k in store.keys {
        if k.key_id == key_id && !k.revoked {
            return k, true;
        }
    }
    return KeySlot { .. }, false;
}

// Zeroizes and revokes all slots matching key_id in the store.
fn revoke_key(store: KeyStore&, key_id: u32) -> bool {
    var found = false;
    for &k in store.keys {
        if k.key_id == key_id {
            security_internal::zeroize_jar_key_slot(k);
            found = true;
        }
    }
    return found;
}

// Checks if a key needs proactive rotation (revoked or within 24 hours of expiration).
fn needs_rotation(slot: const KeySlot&, now_sec: i64) -> bool {
    guard now_sec >= 0 else { return false; }
    if slot.revoked { return true; }
    guard slot.expires_at_sec > 0 else { return false; }
    if now_sec >= slot.expires_at_sec { return true; }
    return core::sub_sat_i64(slot.expires_at_sec, now_sec) <= 86400;
}

// Validates cookie creation timestamp against clock skew tolerance and max age TTL.
fn is_cookie_timestamp_valid(store: const KeyStore&, cookie_u: u64, now_sec: i64) -> bool {
    // RFC 6265 Section 5.2.2: The Max-Age Attribute - Zero or negative max-age expires immediately.
    guard now_sec > 0 && store.clock_skew_tolerance_sec >= 0 && store.max_age_sec > 0 else {
        return false;
    }
    let now_u = now_sec as u64;
    let skew_u = store.clock_skew_tolerance_sec as u64;
    let max_age_u = store.max_age_sec as u64;
    if cookie_u > core::add_sat_u64(now_u, skew_u) { return false; }
    if now_u > cookie_u && core::sub_sat_u64(now_u, cookie_u) > max_age_u { return false; }
    return true;
}

fn is_cookie_timestamp_valid(store: const KeyStore&, cookie_sec: i64, now_sec: i64) -> bool {
    guard cookie_sec >= 0 else { return false; }
    return is_cookie_timestamp_valid(store, cookie_sec as u64, now_sec);
}

// ---- PrivateJar (authenticated encryption with context binding) ------------

// Encrypted cookie jar using AEAD (XChaCha20-Poly1305 or HKDF-AES-GCM).
// Wire format: version (1B) | key_id (4B) | timestamp/salt | nonce | ciphertext | tag.
struct PrivateJar {
    store:        KeyStore = KeyStore { .. },
    use_hkdf_aes: bool     = false, // false = XChaCha20-Poly1305 (default), true = HKDF + AES-256-GCM
}

fn new_private_jar(store: KeyStore, use_hkdf_aes: bool = false) -> PrivateJar {
    return PrivateJar { store: store, use_hkdf_aes: use_hkdf_aes };
}

// Encrypts and authenticates cookie payload into binary wire format.
fn seal_binary<B>(
    jar:         const PrivateJar&,
    cookie_name: const u8[:],
    plaintext:   const u8[:],
    now_sec:     i64,
    nonce_seed:  u64,
    out:         B&,
) -> bool {
    let idx, ok_key = security_internal::find_active_key_idx(jar.store);
    guard ok_key else { return false; }
    let slot .= jar.store.keys[idx];
    guard security_internal::is_jar_key_valid_at(slot, now_sec) else { return false; }

    if jar.use_hkdf_aes {
        return security_internal::seal_binary_hkdf_aes(slot, cookie_name, plaintext, now_sec, nonce_seed, out);
    }
    return security_internal::seal_binary_xchacha20(slot, cookie_name, plaintext, now_sec, nonce_seed, out);
}

// Verifies authentication tag, context binding, and decrypts payload into `out`.
fn open_binary<B>(
    jar:         const PrivateJar&,
    cookie_name: const u8[:],
    raw_wire:    const u8[:],
    now_sec:     i64,
    out:         B&,
) -> bool {
    guard raw_wire.len >= security_internal::K_OVERHEAD_XCHACHA20 else { return false; }
    let ver = raw_wire[0];
    let expected_ver = if jar.use_hkdf_aes {
        security_internal::WIRE_VER_HKDF_AES_GCM
    } else {
        security_internal::WIRE_VER_XCHACHA20
    };
    guard ver == expected_ver else { return false; }
    let key_id = core::read_be_u32(raw_wire, 1);

    let idx, ok_key = security_internal::find_key_idx(jar.store, key_id);
    guard ok_key else { return false; }
    let slot .= jar.store.keys[idx];
    guard security_internal::is_jar_key_valid_at(slot, now_sec) else { return false; }

    out.clear();
    if ver == security_internal::WIRE_VER_XCHACHA20 {
        return security_internal::open_binary_xchacha20(jar, slot, cookie_name, raw_wire, now_sec, out);
    }
    if ver == security_internal::WIRE_VER_HKDF_AES_GCM {
        return security_internal::open_binary_hkdf_aes(jar, slot, cookie_name, raw_wire, now_sec, out);
    }
    return false;
}

// Encodes encrypted cookie to Base64URL string for HTTP header transmission.
fn seal<B>(
    jar:         const PrivateJar&,
    cookie_name: const u8[:],
    plaintext:   const u8[:],
    now_sec:     i64,
    nonce_seed:  u64,
    out:         B&,
) -> bool {
    var raw_wire: u8[>..] = [];
    defer core::secure_zeroize_slice(raw_wire[..]);
    guard seal_binary(jar, cookie_name, plaintext, now_sec, nonce_seed, raw_wire) else {
        return false;
    }
    guard security_internal::can_fit_base64url(out, raw_wire.len) else { return false; }
    out.clear();
    core::base64url_encode(raw_wire[..], out);
    return true;
}

// Decodes Base64URL cookie value and decrypts with constant-time verification.
fn open<B>(
    jar:         const PrivateJar&,
    cookie_name: const u8[:],
    encoded_val: const u8[:],
    now_sec:     i64,
    out:         B&,
) -> bool {
    var raw_wire_stack: u8[..4200] = [];
    var raw_wire_dyn:   u8[>..]    = [];
    defer core::secure_zeroize_slice(raw_wire_stack[..]);
    defer core::secure_zeroize_slice(raw_wire_dyn[..]);
    let raw_wire, ok_b64 = security_internal::decode_jar_base64url(
        encoded_val,
        raw_wire_stack,
        raw_wire_dyn,
    );
    guard ok_b64 else { return false; }
    return open_binary(jar, cookie_name, raw_wire, now_sec, out);
}

// ---- SignedJar (authenticated integrity with HMAC-SHA256) ------------------

// Authenticated cookie jar using HMAC-SHA256 signatures.
// Wire format: version (1B) | key_id (4B) | timestamp (8B) | payload | mac (32B).
struct SignedJar {
    store: KeyStore = KeyStore { .. },
}

fn new_signed_jar(store: KeyStore) -> SignedJar {
    return SignedJar { store: store };
}

// Formats signed cookie into binary wire:
// ver (0x03) | key_id (4B) | timestamp (8B) | payload (NB) | mac (32B).
fn seal_binary<B>(
    jar:         const SignedJar&,
    cookie_name: const u8[:],
    payload:     const u8[:],
    now_sec:     i64,
    out:         B&,
) -> bool {
    guard now_sec > 0 && cookie_name.len > 0 &&
        cookie_name.len <= security_internal::MAX_COOKIE_NAME_LEN else {
        return false;
    }
    guard payload.len <= 0x7FFFFFFF &&
        security_internal::can_fit(
            out,
            core::add_sat_i64(security_internal::K_OVERHEAD_HMAC_SHA256, payload.len),
        ) else {
            return false;
        }

    let idx, ok_key = security_internal::find_active_key_idx(jar.store);
    guard ok_key else { return false; }
    let slot .= jar.store.keys[idx];
    guard security_internal::is_jar_key_valid_at(slot, now_sec) else { return false; }

    let now_u = now_sec as u64;
    var mac = security_internal::compute_signed_jar_mac(
        slot.signing_key, slot.key_id, now_u, cookie_name, payload,
    );
    defer core::secure_zeroize_32(mac);

    out.clear();
    out.push(security_internal::WIRE_VER_HMAC_SHA256);
    out.append_u32_be(slot.key_id);
    out.append_u64_be(now_u);
    out.append(payload);
    out.append(mac[..]);
    return true;
}

fn open_binary<B>(
    jar:         const SignedJar&,
    cookie_name: const u8[:],
    raw_wire:    const u8[:],
    now_sec:     i64,
    out:         B&,
) -> bool {
    guard cookie_name.len > 0 && cookie_name.len <= security_internal::MAX_COOKIE_NAME_LEN else {
        return false;
    }
    guard raw_wire.len >= security_internal::K_OVERHEAD_HMAC_SHA256 else { return false; }
    guard raw_wire[0] == security_internal::WIRE_VER_HMAC_SHA256 else { return false; }

    let payload_len = core::sub_sat_i64(raw_wire.len, security_internal::K_OVERHEAD_HMAC_SHA256);
    guard payload_len <= 0x7FFFFFFF else { return false; }

    let key_id = core::read_be_u32(raw_wire, 1);
    let idx, ok_key = security_internal::find_key_idx(jar.store, key_id);
    guard ok_key else { return false; }
    let slot .= jar.store.keys[idx];
    guard security_internal::is_jar_key_valid_at(slot, now_sec) else { return false; }

    let cookie_u = core::read_be_u64(raw_wire, 5);
    let tag_off = core::add_sat_i64(13, payload_len);
    let payload = raw_wire[13..tag_off];

    var tag: u8[32] = [0; 32];
    core::ct_copy_bytes(tag[..], raw_wire[tag_off..core::add_sat_i64(tag_off, 32)]);

    var expected_mac = security_internal::compute_signed_jar_mac(
        slot.signing_key, slot.key_id, cookie_u, cookie_name, payload,
    );
    defer core::secure_zeroize_32(expected_mac);
    let mac_ok = core::ct_eq_tag32(expected_mac, tag);
    guard mac_ok && is_cookie_timestamp_valid(jar.store, cookie_u, now_sec) else { return false; }
    guard security_internal::can_fit(out, payload_len) else { return false; }

    out.clear();
    out.append(payload);
    return true;
}

fn seal<B>(
    jar:         const SignedJar&,
    cookie_name: const u8[:],
    payload:     const u8[:],
    now_sec:     i64,
    out:         B&,
) -> bool {
    var raw_wire: u8[>..] = [];
    defer core::secure_zeroize_slice(raw_wire[..]);
    guard seal_binary(jar, cookie_name, payload, now_sec, raw_wire) else { return false; }
    guard security_internal::can_fit_base64url(out, raw_wire.len) else { return false; }
    out.clear();
    core::base64url_encode(raw_wire[..], out);
    return true;
}

fn open<B>(
    jar:         const SignedJar&,
    cookie_name: const u8[:],
    encoded_val: const u8[:],
    now_sec:     i64,
    out:         B&,
) -> bool {
    var raw_wire_stack: u8[..4200] = [];
    var raw_wire_dyn:   u8[>..]    = [];
    let raw_wire, ok_b64 = security_internal::decode_jar_base64url(
        encoded_val,
        raw_wire_stack,
        raw_wire_dyn,
    );
    guard ok_b64 else { return false; }
    return open_binary(jar, cookie_name, raw_wire, now_sec, out);
}
