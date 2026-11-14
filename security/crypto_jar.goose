// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Cryptographic cookie containers (PrivateJar AEAD and SignedJar HMAC) with key rotation.
namespace wing;

import std;
import core from "..";

extern fn jar_crypto_random_bytes(out: u8[:]) -> i32 = "wing_crypto_random_bytes";

// ---- protocol wire constants & overhead definitions ------------------------

const WIRE_VER_XCHACHA20:    u8 = 0x01;
const WIRE_VER_HKDF_AES_GCM: u8 = 0x02;
const WIRE_VER_HMAC_SHA256:  u8 = 0x03;

const K_OVERHEAD_XCHACHA20:    i64 = 53; // 1 + 4 + 8 + 24 + 16
const K_OVERHEAD_HKDF_AES_GCM: i64 = 65; // 1 + 4 + 32 + 12 + 16
const K_OVERHEAD_HMAC_SHA256:  i64 = 45; // 1 + 4 + 8 + 32
const MAX_COOKIE_NAME_LEN:     i64 = 4096; // RFC 6265 §6.1
const MAX_ENCODED_COOKIE_LEN:  i64 = 16384;

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

// Additional Authenticated Data (AAD) for context binding:
// ver (1B) || key_id (4B) || timestamp_sec (8B) || cookie_name_len (2B) || cookie_name.
// Binds creation timestamp and cookie name to prevent replay and context swapping.
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
// Length prefixes prevent boundary collisions between cookie name and payload.
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

fn zeroize_jar_key_slot(slot: KeySlot&) {
    core::secure_zeroize_32(slot.master_key);
    core::secure_zeroize_32(slot.signing_key);
    core::secure_zeroize_32(slot.encryption_key);
    slot.revoked = true;
}

// Key rotation store supporting an active primary key and retired keys.
struct KeyStore {
    keys:                     KeySlot[..8] = [],
    active_idx:               i64          = 0,
    max_age_sec:              i64          = 2592000, // 30 days default session lifetime
    clock_skew_tolerance_sec: i64          = 300,     // 5 minutes skew tolerance
}

// Appends a KeySlot to the store if capacity permits and key_id is not already present.
// Derives domain-separated signing and encryption subkeys via HKDF-SHA256.
fn add_key(store: KeyStore&, slot: KeySlot) -> bool {
    defer zeroize_jar_key_slot(slot);
    guard !slot.revoked && store.keys.len < store.keys.cap else { return false; }
    for idx in store.keys.len {
        if store.keys[idx].key_id == slot.key_id {
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
    zeroize_jar_key_slot(derived);
    return ok;
}

inline fn is_jar_key_valid_at(slot: const KeySlot&, now_sec: i64) -> bool {
    guard !slot.revoked else { return false; }
    if slot.expires_at_sec > 0 && now_sec > 0 && now_sec >= slot.expires_at_sec {
        return false;
    }
    return true;
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
    for idx in store.keys.len {
        if store.keys[idx].key_id == key_id && !store.keys[idx].revoked {
            store.active_idx = idx;
            return true;
        }
    }
    return false;
}

// Looks up a non-revoked KeySlot by key_id for decryption or verification.
fn find_key(store: const KeyStore&, key_id: u32) -> KeySlot, bool {
    for idx in store.keys.len {
        if store.keys[idx].key_id == key_id && !store.keys[idx].revoked {
            return store.keys[idx], true;
        }
    }
    return KeySlot { .. }, false;
}

// Zeroizes and revokes all slots matching key_id in the store.
fn revoke_key(store: KeyStore&, key_id: u32) -> bool {
    var found = false;
    for idx in store.keys.len {
        if store.keys[idx].key_id == key_id {
            zeroize_jar_key_slot(store.keys[idx]);
            found = true;
        }
    }
    return found;
}

// Checks if a key needs proactive rotation (revoked or starts >= 24 hours before expiration).
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

// ---- privatejar (authenticated encryption with context binding) -------------

// Encrypted cookie jar using AEAD (XChaCha20-Poly1305 or HKDF-AES-GCM).
// Wire format: version (1B) | key_id (4B) | timestamp/salt | nonce | ciphertext | tag.
struct PrivateJar {
    store:        KeyStore = KeyStore { .. },
    use_hkdf_aes: bool     = false, // false = XChaCha20-Poly1305 (default), true = HKDF + AES-256-GCM
}

fn new_private_jar(store: KeyStore, use_hkdf_aes: bool = false) -> PrivateJar {
    return PrivateJar { store: store, use_hkdf_aes: use_hkdf_aes };
}

var g_jar_nonce_counter: u64 = 1;

// RFC 8439 Section 4: Security Considerations - Mix OS CSPRNG, counter, clock, and cookie name for AEAD nonce uniqueness.
fn generate_jar_entropy(
    seed:        u64,
    now_sec:     i64,
    cookie_name: const u8[:] = "",
    domain:      u64         = 0,
) -> u8[32] {
    g_jar_nonce_counter = g_jar_nonce_counter + 1;
    let now_ns = clock_ns() as u64;
    let name_hash = core::fnv1a_64(cookie_name);
    var entropy_in: u8[64] = [0; 64];
    let _ = jar_crypto_random_bytes(entropy_in[0..32]);
    core::write_le_u64_at(entropy_in[..], 32, seed ^ domain ^ name_hash);
    core::write_le_u64_at(entropy_in[..], 40, g_jar_nonce_counter);
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
    for i in 12 {
        nonce12[i] = entropy2[i];
    }
    core::secure_zeroize_32(entropy1);
    core::secure_zeroize_32(entropy2);
}

fn seal_binary_hkdf_aes<B>(
    slot:        const KeySlot&,
    cookie_name: const u8[:],
    plaintext:   const u8[:],
    now_sec:     i64,
    nonce_seed:  u64,
    out:         B&,
) -> bool {
    out.clear();
    var committed = false;
    defer if !committed { out.clear(); };
    guard now_sec > 0 && is_jar_key_valid_at(slot, now_sec) &&
        cookie_name.len > 0 && cookie_name.len <= MAX_COOKIE_NAME_LEN else { return false; }
    guard can_fit(out, core::add_sat_i64(K_OVERHEAD_HKDF_AES_GCM, plaintext.len)) else { return false; }

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
    guard ok_seal else {
        out.clear();
        return false;
    }
    out.append(tag[..]);
    committed = true;
    return true;
}

fn seal_binary_xchacha20<B>(
    slot:        const KeySlot&,
    cookie_name: const u8[:],
    plaintext:   const u8[:],
    now_sec:     i64,
    nonce_seed:  u64,
    out:         B&,
) -> bool {
    out.clear();
    guard now_sec > 0 && is_jar_key_valid_at(slot, now_sec) &&
        cookie_name.len > 0 && cookie_name.len <= MAX_COOKIE_NAME_LEN else { return false; }
    guard can_fit(out, core::add_sat_i64(K_OVERHEAD_XCHACHA20, plaintext.len)) else { return false; }

    let now_u = now_sec as u64;
    out.push(WIRE_VER_XCHACHA20);
    out.append_u32_be(slot.key_id);
    out.append_u64_be(now_u);

    var entropy = generate_jar_entropy(nonce_seed, now_sec, cookie_name, 0x7863686163686132);
    var nonce24: u8[24] = [0; 24];
    for i in 24 {
        nonce24[i] = entropy[i];
    }
    core::secure_zeroize_32(entropy);
    out.append(nonce24[..]);

    var aad_stack: u8[..4128] = [];
    build_cookie_aad(WIRE_VER_XCHACHA20, slot.key_id, now_u, cookie_name, aad_stack);
    let tag = core::xchacha20_poly1305_seal(slot.encryption_key, nonce24, plaintext, aad_stack[..], out);
    out.append(tag[..]);
    return true;
}

// Encrypts and authenticates cookie payload into binary wire format:
// For XChaCha20: ver (0x01) | key_id (4B) | timestamp (8B) | nonce (24B) | ciphertext | tag (16B)
fn private_jar_seal_binary<B>(
    jar:         const PrivateJar&,
    cookie_name: const u8[:],
    plaintext:   const u8[:],
    now_sec:     i64,
    nonce_seed:  u64,
    out:         B&,
) -> bool {
    out.clear();
    var slot, ok_key = active_key(jar.store);
    guard ok_key && is_jar_key_valid_at(slot, now_sec) else {
        zeroize_jar_key_slot(slot);
        return false;
    }

    let ok = if jar.use_hkdf_aes {
        seal_binary_hkdf_aes(slot, cookie_name, plaintext, now_sec, nonce_seed, out)
    } else {
        seal_binary_xchacha20(slot, cookie_name, plaintext, now_sec, nonce_seed, out)
    };
    zeroize_jar_key_slot(slot);
    return ok;
}

fn open_binary_xchacha20<B>(
    jar:           const PrivateJar&,
    slot:          const KeySlot&,
    cookie_name:   const u8[:],
    raw_wire:      const u8[:],
    now_sec:       i64,
    out_plaintext: B&,
) -> bool {
    let saved_len = out_plaintext.len;
    var committed = false;
    defer if !committed {
        core::secure_zeroize_slice(out_plaintext[saved_len..]);
        out_plaintext.resize(saved_len);
    };
    guard is_jar_key_valid_at(slot, now_sec) &&
        cookie_name.len > 0 && cookie_name.len <= MAX_COOKIE_NAME_LEN &&
        raw_wire.len >= K_OVERHEAD_XCHACHA20 else {
        return false;
    }
    let ct_len = core::sub_sat_i64(raw_wire.len, K_OVERHEAD_XCHACHA20);
    guard can_fit(out_plaintext, core::add_sat_i64(saved_len, ct_len)) else { return false; }

    let ts = core::read_be_u64(raw_wire, 5);
    guard is_cookie_timestamp_valid(jar.store, ts, now_sec) else { return false; }

    var nonce24: u8[24] = [0; 24];
    for i in 24 { nonce24[i] = raw_wire[core::add_sat_i64(13, i)]; }

    let tag_off = core::add_sat_i64(37, ct_len);
    let ct = raw_wire[37..tag_off];

    var tag: u8[16] = [0; 16];
    for i in 16 { tag[i] = raw_wire[core::add_sat_i64(tag_off, i)]; }

    var aad_stack: u8[..4128] = [];
    build_cookie_aad(WIRE_VER_XCHACHA20, slot.key_id, ts, cookie_name, aad_stack);
    guard core::xchacha20_poly1305_open(slot.encryption_key, nonce24, ct, aad_stack[..], tag, out_plaintext) else {
        return false;
    }
    guard core::sub_sat_i64(out_plaintext.len, saved_len) == ct_len else {
        return false;
    }
    committed = true;
    return true;
}

fn open_binary_hkdf_aes<B>(
    jar:           const PrivateJar&,
    slot:          const KeySlot&,
    cookie_name:   const u8[:],
    raw_wire:      const u8[:],
    now_sec:       i64,
    out_plaintext: B&,
) -> bool {
    let saved_len = out_plaintext.len;
    var committed = false;
    defer if !committed {
        core::secure_zeroize_slice(out_plaintext[saved_len..]);
        out_plaintext.resize(saved_len);
    };
    guard is_jar_key_valid_at(slot, now_sec) &&
        cookie_name.len > 0 && cookie_name.len <= MAX_COOKIE_NAME_LEN &&
        raw_wire.len >= K_OVERHEAD_HKDF_AES_GCM else {
        return false;
    }
    let ct_len = core::sub_sat_i64(raw_wire.len, K_OVERHEAD_HKDF_AES_GCM);
    guard can_fit(out_plaintext, core::add_sat_i64(saved_len, ct_len)) else { return false; }

    var salt32: u8[32] = [0; 32];
    for i in 32 { salt32[i] = raw_wire[core::add_sat_i64(5, i)]; }

    var nonce12: u8[12] = [0; 12];
    for i in 12 { nonce12[i] = raw_wire[core::add_sat_i64(37, i)]; }

    let ts = core::read_le_u64(salt32[..], 8);
    guard is_cookie_timestamp_valid(jar.store, ts, now_sec) else { return false; }
    let tag_off = core::add_sat_i64(49, ct_len);
    let ct = raw_wire[49..tag_off];

    var tag: u8[16] = [0; 16];
    for i in 16 { tag[i] = raw_wire[core::add_sat_i64(tag_off, i)]; }

    var aad_stack: u8[..4128] = [];
    build_cookie_aad(WIRE_VER_HKDF_AES_GCM, slot.key_id, ts, cookie_name, aad_stack);
    guard core::hkdf_aes256_gcm_open(slot.encryption_key, salt32, nonce12, ct, aad_stack[..], tag, out_plaintext) else {
        return false;
    }
    guard core::sub_sat_i64(out_plaintext.len, saved_len) == ct_len else {
        return false;
    }
    committed = true;
    return true;
}

// Verifies authentication tag, context binding, and decrypts payload into out_plaintext.
fn private_jar_open_binary<B>(
    jar:           const PrivateJar&,
    cookie_name:   const u8[:],
    raw_wire:      const u8[:],
    now_sec:       i64,
    out_plaintext: B&,
) -> bool {
    out_plaintext.clear();
    guard raw_wire.len >= K_OVERHEAD_XCHACHA20 else { return false; }
    let ver = raw_wire[0];
    let expected_ver = if jar.use_hkdf_aes { WIRE_VER_HKDF_AES_GCM } else { WIRE_VER_XCHACHA20 };
    guard ver == expected_ver else { return false; }
    let key_id = core::read_be_u32(raw_wire, 1);

    var slot, ok_key = find_key(jar.store, key_id);
    guard ok_key && is_jar_key_valid_at(slot, now_sec) else {
        zeroize_jar_key_slot(slot);
        return false;
    }

    var ok = false;
    if ver == WIRE_VER_XCHACHA20 {
        ok = open_binary_xchacha20(jar, slot, cookie_name, raw_wire, now_sec, out_plaintext);
    } else if ver == WIRE_VER_HKDF_AES_GCM {
        ok = open_binary_hkdf_aes(jar, slot, cookie_name, raw_wire, now_sec, out_plaintext);
    }
    zeroize_jar_key_slot(slot);
    return ok;
}

// Encodes encrypted cookie to Base64URL string for HTTP header transmission.
fn private_jar_seal<B>(
    jar:         const PrivateJar&,
    cookie_name: const u8[:],
    plaintext:   const u8[:],
    now_sec:     i64,
    nonce_seed:  u64,
    out:         B&,
) -> bool {
    out.clear();
    var raw_wire: u8[>..] = [];
    guard private_jar_seal_binary(jar, cookie_name, plaintext, now_sec, nonce_seed, raw_wire) else {
        return false;
    }
    guard can_fit_base64url(out, raw_wire.len) else { return false; }
    core::base64url_encode(raw_wire[..], out);
    return true;
}

// Decodes Base64URL cookie value and decrypts with constant-time verification.
fn private_jar_open<B>(
    jar:           const PrivateJar&,
    cookie_name:   const u8[:],
    encoded_val:   const u8[:],
    now_sec:       i64,
    out_plaintext: B&,
) -> bool {
    out_plaintext.clear();
    guard encoded_val.len > 0 && encoded_val.len <= MAX_ENCODED_COOKIE_LEN else { return false; }
    var raw_wire_stack: u8[..4200] = [];
    if encoded_val.len <= 5500 {
        guard core::base64url_decode(encoded_val, raw_wire_stack) else { return false; }
        return private_jar_open_binary(jar, cookie_name, raw_wire_stack[..], now_sec, out_plaintext);
    }
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
    jar:         const SignedJar&,
    cookie_name: const u8[:],
    payload:     const u8[:],
    now_sec:     i64,
    out:         B&,
) -> bool {
    out.clear();
    guard now_sec > 0 && cookie_name.len > 0 && cookie_name.len <= MAX_COOKIE_NAME_LEN else { return false; }
    guard payload.len <= 0x7FFFFFFF && can_fit(out, core::add_sat_i64(K_OVERHEAD_HMAC_SHA256, payload.len)) else {
        return false;
    }

    var slot, ok_key = active_key(jar.store);
    guard ok_key && is_jar_key_valid_at(slot, now_sec) else {
        zeroize_jar_key_slot(slot);
        return false;
    }

    let now_u = now_sec as u64;
    out.push(WIRE_VER_HMAC_SHA256);
    out.append_u32_be(slot.key_id);
    out.append_u64_be(now_u);
    out.append(payload);

    var mac:           u8[32]     = [0; 32];
    var to_sign_stack: u8[..8320] = [];
    let sign_len = core::add_sat_i64(19, core::add_sat_i64(cookie_name.len, payload.len));
    if sign_len <= to_sign_stack.cap {
        build_signed_to_sign(slot.key_id, now_u, cookie_name, payload, to_sign_stack);
        mac = core::hmac_sha256(slot.signing_key[..], to_sign_stack[..]);
    } else {
        var to_sign_dyn: u8[>..] = [];
        build_signed_to_sign(slot.key_id, now_u, cookie_name, payload, to_sign_dyn);
        mac = core::hmac_sha256(slot.signing_key[..], to_sign_dyn[..]);
    }
    zeroize_jar_key_slot(slot);
    out.append(mac[..]);
    core::secure_zeroize_32(mac);
    return true;
}

fn signed_jar_open_binary<B>(
    jar:         const SignedJar&,
    cookie_name: const u8[:],
    raw_wire:    const u8[:],
    now_sec:     i64,
    out_payload: B&,
) -> bool {
    out_payload.clear();
    guard cookie_name.len > 0 && cookie_name.len <= MAX_COOKIE_NAME_LEN else { return false; }
    guard raw_wire.len >= K_OVERHEAD_HMAC_SHA256 else { return false; }
    let ver = raw_wire[0];
    guard ver == WIRE_VER_HMAC_SHA256 else { return false; }

    let payload_len = core::sub_sat_i64(raw_wire.len, K_OVERHEAD_HMAC_SHA256);
    guard payload_len <= 0x7FFFFFFF else { return false; }

    let key_id = core::read_be_u32(raw_wire, 1);

    var slot, ok_key = find_key(jar.store, key_id);
    guard ok_key && is_jar_key_valid_at(slot, now_sec) else {
        zeroize_jar_key_slot(slot);
        return false;
    }

    let cookie_u = core::read_be_u64(raw_wire, 5);
    let tag_off = core::add_sat_i64(13, payload_len);
    let payload = raw_wire[13..tag_off];

    var tag: u8[32] = [0; 32];
    for i in 32 { tag[i] = raw_wire[core::add_sat_i64(tag_off, i)]; }

    var expected_mac:  u8[32]     = [0; 32];
    var to_sign_stack: u8[..8320] = [];
    let sign_len = core::add_sat_i64(19, core::add_sat_i64(cookie_name.len, payload_len));
    if sign_len <= to_sign_stack.cap {
        build_signed_to_sign(slot.key_id, cookie_u, cookie_name, payload, to_sign_stack);
        expected_mac = core::hmac_sha256(slot.signing_key[..], to_sign_stack[..]);
    } else {
        var to_sign_dyn: u8[>..] = [];
        build_signed_to_sign(slot.key_id, cookie_u, cookie_name, payload, to_sign_dyn);
        expected_mac = core::hmac_sha256(slot.signing_key[..], to_sign_dyn[..]);
    }
    zeroize_jar_key_slot(slot);
    let mac_ok = core::ct_eq_tag32(expected_mac, tag);
    core::secure_zeroize_32(expected_mac);
    guard mac_ok && is_cookie_timestamp_valid(jar.store, cookie_u, now_sec) else { return false; }
    guard can_fit(out_payload, payload_len) else { return false; }
    out_payload.append(payload);
    return true;
}

fn signed_jar_seal<B>(
    jar:         const SignedJar&,
    cookie_name: const u8[:],
    payload:     const u8[:],
    now_sec:     i64,
    out:         B&,
) -> bool {
    out.clear();
    var raw_wire: u8[>..] = [];
    guard signed_jar_seal_binary(jar, cookie_name, payload, now_sec, raw_wire) else { return false; }
    guard can_fit_base64url(out, raw_wire.len) else { return false; }
    core::base64url_encode(raw_wire[..], out);
    return true;
}

fn signed_jar_open<B>(
    jar:         const SignedJar&,
    cookie_name: const u8[:],
    encoded_val: const u8[:],
    now_sec:     i64,
    out_payload: B&,
) -> bool {
    out_payload.clear();
    guard encoded_val.len > 0 && encoded_val.len <= MAX_ENCODED_COOKIE_LEN else { return false; }
    var raw_wire_stack: u8[..4200] = [];
    if encoded_val.len <= 5500 {
        guard core::base64url_decode(encoded_val, raw_wire_stack) else { return false; }
        return signed_jar_open_binary(jar, cookie_name, raw_wire_stack[..], now_sec, out_payload);
    }
    var raw_wire: u8[>..] = [];
    guard core::base64url_decode(encoded_val, raw_wire) else { return false; }
    return signed_jar_open_binary(jar, cookie_name, raw_wire[..], now_sec, out_payload);
}
