// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Cryptographic cookie containers (PrivateJar AEAD and SignedJar HMAC) with key rotation.
namespace wing;

import std;
import core from "..";

// ---- protocol wire constants & overhead definitions ------------------------

let WIRE_VER_XCHACHA20: u8 = 0x01;
let WIRE_VER_HKDF_AES_GCM: u8 = 0x02;
let WIRE_VER_HMAC_SHA256: u8 = 0x03;

let K_OVERHEAD_XCHACHA20: i64 = 53;    // 1 + 4 + 8 + 24 + 16
let K_OVERHEAD_HKDF_AES_GCM: i64 = 65; // 1 + 4 + 32 + 12 + 16
let K_OVERHEAD_HMAC_SHA256: i64 = 45;  // 1 + 4 + 8 + 32

// Additional Authenticated Data (AAD) for context binding:
// ver (1B) || key_id (4B) || timestamp_sec (8B) || cookie_name_len (2B) || cookie_name.
// Binds creation timestamp and cookie name to prevent replay and context swapping.
fn build_cookie_aad<B>(ver: u8, key_id: u32, timestamp_sec: i64, cookie_name: const u8[:], out: B&) {
    out.push(ver);
    core::write_be_u32(out, key_id);
    core::write_be_u64(out, timestamp_sec as u64);
    core::write_be_u16(out, cookie_name.len as u16);
    out.append(cookie_name);
}

// Framed HMAC input buffer for SignedJar:
// ver (1B) || key_id (4B) || timestamp (8B) || cookie_name_len (2B) || cookie_name || payload_len (4B) || payload.
// Length prefixes prevent boundary collisions between cookie name and payload.
fn build_signed_to_sign<B>(key_id: u32, cookie_sec: i64, cookie_name: const u8[:], payload: const u8[:], out: B&) {
    out.push(WIRE_VER_HMAC_SHA256);
    core::write_be_u32(out, key_id);
    core::write_be_u64(out, cookie_sec as u64);
    core::write_be_u16(out, cookie_name.len as u16);
    out.append(cookie_name);
    core::write_be_u32(out, payload.len as u32);
    out.append(payload);
}

// ---- multi-key rotation container (KeyStore) -------------------------------

// Key rotation store supporting an active primary key and retired keys.
struct KeyStore {
    keys: core::KeySlot[..8] = [],
    active_idx: i64 = 0,
    max_age_sec: i64 = 2592000,          // 30 days default session lifetime
    clock_skew_tolerance_sec: i64 = 300, // 5 minutes skew tolerance
}

// Creates an empty KeyStore with default session lifetime and skew tolerance.
// Appends a KeySlot to the store if capacity permits.
fn add_key(store: KeyStore&, slot: core::KeySlot) -> bool {
    guard store.keys.len < store.keys.cap else { return false; }
    store.keys.push(slot);
    return true;
}

// Returns the currently active, non-revoked KeySlot.
fn active_key(store: const KeyStore&) -> core::KeySlot, bool {
    guard store.keys.len > 0 else { return core::KeySlot { .. }, false; }
    let slot = store.keys[store.active_idx];
    guard !slot.revoked else { return core::KeySlot { .. }, false; }
    return slot, true;
}

// Sets the active primary key by key_id if present and not revoked.
fn set_active_key_id(store: KeyStore&, key_id: u32) -> bool {
    for idx in store.keys.len {
        if store.keys[idx].key_id == key_id && !store.keys[idx].revoked {
            store.active_idx = idx;
            return true;
        }
    }
    return false;
}

// Looks up a non-revoked KeySlot by key_id for decryption or verification.
fn find_key(store: const KeyStore&, key_id: u32) -> core::KeySlot, bool {
    for idx in store.keys.len {
        if store.keys[idx].key_id == key_id && !store.keys[idx].revoked {
            return store.keys[idx], true;
        }
    }
    return core::KeySlot { .. }, false;
}

// Zeroizes and revokes a key in the store by key_id.
fn revoke_key(store: KeyStore&, key_id: u32) -> bool {
    for idx in store.keys.len {
        if store.keys[idx].key_id == key_id {
            core::zeroize_key_slot(store.keys[idx]);
            return true;
        }
    }
    return false;
}

// Checks if a key needs proactive rotation (starts >= 24 hours before expiration).
fn needs_rotation(slot: const core::KeySlot&, now_sec: i64) -> bool {
    guard slot.expires_at_sec > 0 && !slot.revoked else { return false; }
    return (slot.expires_at_sec - now_sec) <= 86400;
}

// Validates cookie creation timestamp against clock skew tolerance and max age TTL.
fn is_cookie_timestamp_valid(store: const KeyStore&, cookie_sec: i64, now_sec: i64) -> bool {
    guard now_sec > 0 else { return true; }
    if cookie_sec > now_sec + store.clock_skew_tolerance_sec { return false; }
    if now_sec - cookie_sec > store.max_age_sec { return false; }
    return true;
}

// ---- privatejar (authenticated encryption with context binding) -------------

// Encrypted cookie jar using AEAD (XChaCha20-Poly1305 or HKDF-AES-GCM).
// Wire format: version (1B) | key_id (4B) | timestamp/salt | nonce | ciphertext | tag.
struct PrivateJar {
    store: KeyStore = KeyStore { .. },
    use_hkdf_aes: bool = false, // false = XChaCha20-Poly1305 (default), true = HKDF + AES-256-GCM
}

fn new_private_jar(store: KeyStore, use_hkdf_aes: bool = false) -> PrivateJar {
    return PrivateJar { store: store, use_hkdf_aes: use_hkdf_aes };
}

fn seal_binary_hkdf_aes<B>(
    slot: const core::KeySlot&,
    cookie_name: const u8[:],
    plaintext: const u8[:],
    now_sec: i64,
    nonce_seed: u64,
    out: B&,
) -> bool {
    out.push(WIRE_VER_HKDF_AES_GCM);
    core::write_be_u32(out, slot.key_id);

    var salt: u8[32] = [0; 32];
    var nonce12: u8[12] = [0; 12];
    for i in 8 {
        salt[i] = ((nonce_seed >> (i * 8)) & 0xFF) as u8;
        salt[8 + i] = ((now_sec as u64 >> (i * 8)) & 0xFF) as u8;
        nonce12[i] = ((nonce_seed >> (i * 8)) & 0xFF) as u8;
    }
    for i in 32 { out.push(salt[i]); }
    for i in 12 { out.push(nonce12[i]); }

    var aad_stack: u8[..256] = [];
    if (15 + cookie_name.len) <= aad_stack.cap {
        build_cookie_aad(WIRE_VER_HKDF_AES_GCM, slot.key_id, now_sec, cookie_name, aad_stack);
        var ct: u8[>..] = [];
        let tag = core::hkdf_aes256_gcm_seal(slot.master_key, salt, nonce12, plaintext, aad_stack[..], ct);
        out.append(ct[..]);
        for i in 16 { out.push(tag[i]); }
        return true;
    } else {
        var aad_dyn: u8[>..] = [];
        build_cookie_aad(WIRE_VER_HKDF_AES_GCM, slot.key_id, now_sec, cookie_name, aad_dyn);
        var ct: u8[>..] = [];
        let tag = core::hkdf_aes256_gcm_seal(slot.master_key, salt, nonce12, plaintext, aad_dyn[..], ct);
        out.append(ct[..]);
        for i in 16 { out.push(tag[i]); }
        return true;
    }
}

fn seal_binary_xchacha20<B>(
    slot: const core::KeySlot&,
    cookie_name: const u8[:],
    plaintext: const u8[:],
    now_sec: i64,
    nonce_seed: u64,
    out: B&,
) -> bool {
    out.push(WIRE_VER_XCHACHA20);
    core::write_be_u32(out, slot.key_id);
    core::write_be_u64(out, now_sec as u64);

    var nonce24: u8[24] = [0; 24];
    for i in 8 {
        nonce24[i] = ((nonce_seed >> (i * 8)) & 0xFF) as u8;
        nonce24[8 + i] = (((nonce_seed * 6364136223846793005 + 1) >> (i * 8)) & 0xFF) as u8;
        nonce24[16 + i] = ((now_sec as u64 >> (i * 8)) & 0xFF) as u8;
    }
    for i in 24 { out.push(nonce24[i]); }

    var aad_stack: u8[..256] = [];
    if (15 + cookie_name.len) <= aad_stack.cap {
        build_cookie_aad(WIRE_VER_XCHACHA20, slot.key_id, now_sec, cookie_name, aad_stack);
        var ct: u8[>..] = [];
        let tag = core::xchacha20_poly1305_seal(slot.master_key, nonce24, plaintext, aad_stack[..], ct);
        out.append(ct[..]);
        for i in 16 { out.push(tag[i]); }
        return true;
    } else {
        var aad_dyn: u8[>..] = [];
        build_cookie_aad(WIRE_VER_XCHACHA20, slot.key_id, now_sec, cookie_name, aad_dyn);
        var ct: u8[>..] = [];
        let tag = core::xchacha20_poly1305_seal(slot.master_key, nonce24, plaintext, aad_dyn[..], ct);
        out.append(ct[..]);
        for i in 16 { out.push(tag[i]); }
        return true;
    }
}

// Encrypts and authenticates cookie payload into binary wire format:
// For XChaCha20: ver (0x01) | key_id (4B) | timestamp (8B) | nonce (24B) | ciphertext | tag (16B)
fn private_jar_seal_binary<B>(
    jar: const PrivateJar&,
    cookie_name: const u8[:],
    plaintext: const u8[:],
    now_sec: i64,
    nonce_seed: u64,
    out: B&,
) -> bool {
    let slot, ok_key = active_key(jar.store);
    guard ok_key else { return false; }

    if jar.use_hkdf_aes {
        return seal_binary_hkdf_aes(slot, cookie_name, plaintext, now_sec, nonce_seed, out);
    }
    return seal_binary_xchacha20(slot, cookie_name, plaintext, now_sec, nonce_seed, out);
}

fn open_binary_xchacha20(
    jar: const PrivateJar&,
    slot: const core::KeySlot&,
    cookie_name: const u8[:],
    raw_wire: const u8[:],
    now_sec: i64,
    out_plaintext: u8[>..]&,
) -> bool {
    guard raw_wire.len >= K_OVERHEAD_XCHACHA20 else { return false; }

    var ts: u64 = 0;
    for i in 8 { ts = (ts << 8) | raw_wire[5 + i]; }
    let cookie_sec = ts as i64;

    if now_sec > 0 {
        if cookie_sec > now_sec + jar.store.clock_skew_tolerance_sec { return false; }
        if now_sec - cookie_sec > jar.store.max_age_sec { return false; }
    }

    var nonce24: u8[24] = [0; 24];
    for i in 24 { nonce24[i] = raw_wire[13 + i]; }

    let ct_len = raw_wire.len - K_OVERHEAD_XCHACHA20;
    let ct = raw_wire[37..37 + ct_len];

    var tag: u8[16] = [0; 16];
    for i in 16 { tag[i] = raw_wire[37 + ct_len + i]; }

    var aad_stack: u8[..256] = [];
    if (15 + cookie_name.len) <= aad_stack.cap {
        build_cookie_aad(WIRE_VER_XCHACHA20, slot.key_id, cookie_sec, cookie_name, aad_stack);
        return core::xchacha20_poly1305_open(slot.master_key, nonce24, ct, aad_stack[..], tag, out_plaintext);
    } else {
        var aad_dyn: u8[>..] = [];
        build_cookie_aad(WIRE_VER_XCHACHA20, slot.key_id, cookie_sec, cookie_name, aad_dyn);
        return core::xchacha20_poly1305_open(slot.master_key, nonce24, ct, aad_dyn[..], tag, out_plaintext);
    }
}

fn open_binary_hkdf_aes(
    jar: const PrivateJar&,
    slot: const core::KeySlot&,
    cookie_name: const u8[:],
    raw_wire: const u8[:],
    now_sec: i64,
    out_plaintext: u8[>..]&,
) -> bool {
    guard raw_wire.len >= K_OVERHEAD_HKDF_AES_GCM else { return false; }

    var salt32: u8[32] = [0; 32];
    for i in 32 { salt32[i] = raw_wire[5 + i]; }

    var nonce12: u8[12] = [0; 12];
    for i in 12 { nonce12[i] = raw_wire[37 + i]; }

    var ts: u64 = 0;
    for i in 8 { ts |= (salt32[8 + i] as u64) << (i * 8); }
    let cookie_sec = ts as i64;

    if now_sec > 0 && cookie_sec > 0 {
        if cookie_sec > now_sec + jar.store.clock_skew_tolerance_sec { return false; }
        if now_sec - cookie_sec > jar.store.max_age_sec { return false; }
    }

    let ct_len = raw_wire.len - K_OVERHEAD_HKDF_AES_GCM;
    let ct = raw_wire[49..49 + ct_len];

    var tag: u8[16] = [0; 16];
    for i in 16 { tag[i] = raw_wire[49 + ct_len + i]; }

    var aad_stack: u8[..256] = [];
    if (15 + cookie_name.len) <= aad_stack.cap {
        build_cookie_aad(WIRE_VER_HKDF_AES_GCM, slot.key_id, cookie_sec, cookie_name, aad_stack);
        return core::hkdf_aes256_gcm_open(slot.master_key, salt32, nonce12, ct, aad_stack[..], tag, out_plaintext);
    } else {
        var aad_dyn: u8[>..] = [];
        build_cookie_aad(WIRE_VER_HKDF_AES_GCM, slot.key_id, cookie_sec, cookie_name, aad_dyn);
        return core::hkdf_aes256_gcm_open(slot.master_key, salt32, nonce12, ct, aad_dyn[..], tag, out_plaintext);
    }
}

// Verifies authentication tag, context binding, and decrypts payload into out_plaintext.
fn private_jar_open_binary(
    jar: const PrivateJar&,
    cookie_name: const u8[:],
    raw_wire: const u8[:],
    now_sec: i64,
    out_plaintext: u8[>..]&,
) -> bool {
    guard raw_wire.len >= 53 else { return false; }
    let ver = raw_wire[0];
    let key_id = core::read_be_u32(raw_wire, 1);

    let slot, ok_key = find_key(jar.store, key_id);
    guard ok_key else { return false; }

    if ver == WIRE_VER_XCHACHA20 {
        return open_binary_xchacha20(jar, slot, cookie_name, raw_wire, now_sec, out_plaintext);
    }
    if ver == WIRE_VER_HKDF_AES_GCM {
        return open_binary_hkdf_aes(jar, slot, cookie_name, raw_wire, now_sec, out_plaintext);
    }
    return false;
}

// Encodes encrypted cookie to Base64URL string for HTTP header transmission.
fn private_jar_seal<B>(
    jar: const PrivateJar&,
    cookie_name: const u8[:],
    plaintext: const u8[:],
    now_sec: i64,
    nonce_seed: u64,
    out: B&,
) -> bool {
    var raw_wire: u8[>..] = [];
    guard private_jar_seal_binary(jar, cookie_name, plaintext, now_sec, nonce_seed, raw_wire) else {
        return false;
    }
    base64url_encode(raw_wire[..], out);
    return true;
}

// Decodes Base64URL cookie value and decrypts with constant-time verification.
fn private_jar_open(
    jar: const PrivateJar&,
    cookie_name: const u8[:],
    encoded_val: const u8[:],
    now_sec: i64,
    out_plaintext: u8[>..]&,
) -> bool {
    var raw_wire: u8[>..] = [];
    guard core::base64url_decode(encoded_val, raw_wire) else { return false; }
    return private_jar_open_binary(jar, cookie_name, raw_wire[..], now_sec, out_plaintext);
}

// ---- signedjar (authenticated integrity with hmac-sha256) ------------------

// Authenticated cookie jar using HMAC-SHA256 signatures.
// Wire format: version (1B) | key_id (4B) | timestamp (8B) | payload | mac (32B).
struct SignedJar {
    store: KeyStore = KeyStore { .. },
}

fn new_signed_jar(store: KeyStore) -> SignedJar {
    return SignedJar { store: store };
}

// Formats signed cookie into binary wire:
// ver (0x03) | key_id (4B) | timestamp (8B) | payload (NB) | mac (32B)
fn signed_jar_seal_binary<B>(
    jar: const SignedJar&,
    cookie_name: const u8[:],
    payload: const u8[:],
    now_sec: i64,
    out: B&,
) -> bool {
    let slot, ok_key = active_key(jar.store);
    guard ok_key else { return false; }

    out.push(WIRE_VER_HMAC_SHA256);
    core::write_be_u32(out, slot.key_id);
    core::write_be_u64(out, now_sec as u64);
    out.append(payload);

    var to_sign_stack: u8[..4200] = [];
    if (15 + cookie_name.len + 4 + payload.len) <= to_sign_stack.cap {
        build_signed_to_sign(slot.key_id, now_sec, cookie_name, payload, to_sign_stack);
        let mac = core::hmac_sha256(slot.master_key[..], to_sign_stack[..]);
        for i in 32 { out.push(mac[i]); }
        return true;
    } else {
        var to_sign_dyn: u8[>..] = [];
        build_signed_to_sign(slot.key_id, now_sec, cookie_name, payload, to_sign_dyn);
        let mac = core::hmac_sha256(slot.master_key[..], to_sign_dyn[..]);
        for i in 32 { out.push(mac[i]); }
        return true;
    }
}

fn signed_jar_open_binary(
    jar: const SignedJar&,
    cookie_name: const u8[:],
    raw_wire: const u8[:],
    now_sec: i64,
    out_payload: u8[>..]&,
) -> bool {
    guard raw_wire.len >= K_OVERHEAD_HMAC_SHA256 else { return false; }
    let ver = raw_wire[0];
    guard ver == WIRE_VER_HMAC_SHA256 else { return false; }

    let key_id = core::read_be_u32(raw_wire, 1);

    let slot, ok_key = find_key(jar.store, key_id);
    guard ok_key else { return false; }

    let cookie_sec = core::read_be_u64(raw_wire, 5) as! i64;

    if now_sec > 0 {
        if cookie_sec > now_sec + jar.store.clock_skew_tolerance_sec { return false; }
        if now_sec - cookie_sec > jar.store.max_age_sec { return false; }
    }

    let payload_len = raw_wire.len - K_OVERHEAD_HMAC_SHA256;
    let payload = raw_wire[13..13 + payload_len];

    var tag: u8[32] = [0; 32];
    for i in 32 { tag[i] = raw_wire[13 + payload_len + i]; }

    var to_sign_stack: u8[..4200] = [];
    if (15 + cookie_name.len + 4 + payload.len) <= to_sign_stack.cap {
        build_signed_to_sign(slot.key_id, cookie_sec, cookie_name, payload, to_sign_stack);
        let expected_mac = core::hmac_sha256(slot.master_key[..], to_sign_stack[..]);
        guard core::ct_eq_tag32(expected_mac, tag) else { return false; }
        out_payload.append(payload);
        return true;
    } else {
        var to_sign_dyn: u8[>..] = [];
        build_signed_to_sign(slot.key_id, cookie_sec, cookie_name, payload, to_sign_dyn);
        let expected_mac = core::hmac_sha256(slot.master_key[..], to_sign_dyn[..]);
        guard core::ct_eq_tag32(expected_mac, tag) else { return false; }
        out_payload.append(payload);
        return true;
    }
}

fn signed_jar_seal<B>(
    jar: const SignedJar&,
    cookie_name: const u8[:],
    payload: const u8[:],
    now_sec: i64,
    out: B&,
) -> bool {
    var raw_wire: u8[>..] = [];
    guard signed_jar_seal_binary(jar, cookie_name, payload, now_sec, raw_wire) else { return false; }
    base64url_encode(raw_wire[..], out);
    return true;
}

fn signed_jar_open(
    jar: const SignedJar&,
    cookie_name: const u8[:],
    encoded_val: const u8[:],
    now_sec: i64,
    out_payload: u8[>..]&,
) -> bool {
    var raw_wire: u8[>..] = [];
    guard core::base64url_decode(encoded_val, raw_wire) else { return false; }
    return signed_jar_open_binary(jar, cookie_name, raw_wire[..], now_sec, out_payload);
}
