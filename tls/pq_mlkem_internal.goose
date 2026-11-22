// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Internal RFC 10024 hybrid key shares, secret combiners, and FIPS 203 ML-KEM-768 KEM operations.
namespace tls_internal;

import std;
import core;
import .pq_ntt_internal;

// RFC 10024 Section 4.1: Client Share - Expected Client Key Share Length
inline fn pq_hybrid_client_share_len(group: u16) -> i64 {
    if group == rfc::GROUP_SECP256R1_MLKEM768 {
        return rfc::SECP256R1_MLKEM768_CLIENT_SHARE_LEN;
    } else if group == rfc::GROUP_X25519_MLKEM768 || group == rfc::GROUP_X25519_KYBER768_DRAFT00 {
        return rfc::HYBRID_CLIENT_SHARE_LEN;
    } else if group == rfc::GROUP_SECP384R1_MLKEM1024 {
        return rfc::SECP384R1_MLKEM1024_CLIENT_SHARE_LEN;
    }
    return 0;
}

// RFC 10024 Section 4.2: Server Share - Expected Server Key Share Length
inline fn pq_hybrid_server_share_len(group: u16) -> i64 {
    if group == rfc::GROUP_SECP256R1_MLKEM768 {
        return rfc::SECP256R1_MLKEM768_SERVER_SHARE_LEN;
    } else if group == rfc::GROUP_X25519_MLKEM768 || group == rfc::GROUP_X25519_KYBER768_DRAFT00 {
        return rfc::HYBRID_SERVER_SHARE_LEN;
    } else if group == rfc::GROUP_SECP384R1_MLKEM1024 {
        return rfc::SECP384R1_MLKEM1024_SERVER_SHARE_LEN;
    }
    return 0;
}

struct PostQuantumKeyShare {
    group:           u16      = rfc::GROUP_X25519_MLKEM768,
    x25519_public:   u8[32]   = [0; 32],
    mlkem768_public: u8[1184] = [0; 1184],
}

struct PostQuantumServerShare {
    group:               u16      = rfc::GROUP_X25519_MLKEM768,
    x25519_public:       u8[32]   = [0; 32],
    mlkem768_ciphertext: u8[1088] = [0; 1088],
}

struct SecP256r1MLKEM768KeyShare {
    group:            u16      = rfc::GROUP_SECP256R1_MLKEM768,
    secp256r1_public: u8[65]   = [0; 65],
    mlkem768_public:  u8[1184] = [0; 1184],
}

struct SecP256r1MLKEM768ServerShare {
    group:               u16      = rfc::GROUP_SECP256R1_MLKEM768,
    secp256r1_public:    u8[65]   = [0; 65],
    mlkem768_ciphertext: u8[1088] = [0; 1088],
}

struct SecP384r1MLKEM1024KeyShare {
    group:            u16      = rfc::GROUP_SECP384R1_MLKEM1024,
    secp384r1_public: u8[97]   = [0; 97],
    mlkem1024_public: u8[1568] = [0; 1568],
}

struct SecP384r1MLKEM1024ServerShare {
    group:                u16      = rfc::GROUP_SECP384R1_MLKEM1024,
    secp384r1_public:     u8[97]   = [0; 97],
    mlkem1024_ciphertext: u8[1568] = [0; 1568],
}

// Formats a KeyShareEntry for ClientHello:
// For GROUP_X25519_MLKEM768 (0x11EC): RFC 10024 Section 7.1 orders PQ (1184B) || Classical (32B).
// For GROUP_X25519_KYBER768_DRAFT00 (0x6399): Classical (32B) || PQ (1184B).
fn format_hybrid_key_share<B>(share: const PostQuantumKeyShare&, out: B&) {
    guard rfc::is_x25519_pq_group(share.group) else { return; }
    out.append_u16_be(share.group);
    out.append_u16_be(rfc::HYBRID_CLIENT_SHARE_LEN as u16);
    if share.group == rfc::GROUP_X25519_MLKEM768 {
        out.append(share.mlkem768_public[..]);
        out.append(share.x25519_public[..]);
    } else {
        out.append(share.x25519_public[..]);
        out.append(share.mlkem768_public[..]);
    }
}

// Parses a hybrid ClientHello KeyShareEntry from raw bytes.
// Enforces exact RFC 10024 wire length (1220 bytes) to prevent smuggling trailing data.
//
// Example:
//   raw = [0x11, 0xEC, 0x04, 0xC0, ...], share = PostQuantumKeyShare { .. }
//   returns: ok = true, share populated with group and public keys
fn parse_hybrid_key_share(share: PostQuantumKeyShare&, raw: const u8[:]) -> bool {
    guard raw.len == 4 + rfc::HYBRID_CLIENT_SHARE_LEN else { return false; }

    let group = core::read_be_u16(raw, 0);
    guard rfc::is_x25519_pq_group(group) else { return false; }

    let kex_len = core::read_be_u16(raw, 2) as i64;
    guard kex_len == rfc::HYBRID_CLIENT_SHARE_LEN else { return false; }

    share.group = group;
    if group == rfc::GROUP_X25519_MLKEM768 {
        core::ct_copy_bytes(share.mlkem768_public[..], raw[4..1188]);
        core::ct_copy_bytes(share.x25519_public[..], raw[1188..1220]);
    } else {
        core::ct_copy_bytes(share.x25519_public[..], raw[4..36]);
        core::ct_copy_bytes(share.mlkem768_public[..], raw[36..1220]);
    }

    return true;
}

// Formats a KeyShareEntry for ServerHello:
// For GROUP_X25519_MLKEM768 (0x11EC): RFC 10024 Section 7.1 orders PQ (1088B) || Classical (32B).
// For GROUP_X25519_KYBER768_DRAFT00 (0x6399): Classical (32B) || PQ (1088B).
fn format_hybrid_server_key_share<B>(share: const PostQuantumServerShare&, out: B&) {
    guard rfc::is_x25519_pq_group(share.group) else { return; }
    out.append_u16_be(share.group);
    out.append_u16_be(rfc::HYBRID_SERVER_SHARE_LEN as u16);
    if share.group == rfc::GROUP_X25519_MLKEM768 {
        out.append(share.mlkem768_ciphertext[..]);
        out.append(share.x25519_public[..]);
    } else {
        out.append(share.x25519_public[..]);
        out.append(share.mlkem768_ciphertext[..]);
    }
}

// Parses a hybrid ServerHello KeyShareEntry from raw bytes.
// Enforces exact RFC 10024 wire length (1124 bytes) to prevent smuggling trailing data.
//
// Example:
//   raw = [0x11, 0xEC, 0x04, 0x50, ...], share = PostQuantumServerShare { .. }
//   returns: ok = true, share populated with group, ciphertext, and public key
fn parse_hybrid_server_key_share(share: PostQuantumServerShare&, raw: const u8[:]) -> bool {
    guard raw.len == 4 + rfc::HYBRID_SERVER_SHARE_LEN else { return false; }

    let group = core::read_be_u16(raw, 0);
    guard rfc::is_x25519_pq_group(group) else { return false; }

    let kex_len = core::read_be_u16(raw, 2) as i64;
    guard kex_len == rfc::HYBRID_SERVER_SHARE_LEN else { return false; }

    share.group = group;
    if group == rfc::GROUP_X25519_MLKEM768 {
        core::ct_copy_bytes(share.mlkem768_ciphertext[..], raw[4..1092]);
        core::ct_copy_bytes(share.x25519_public[..], raw[1092..1124]);
    } else {
        core::ct_copy_bytes(share.x25519_public[..], raw[4..36]);
        core::ct_copy_bytes(share.mlkem768_ciphertext[..], raw[36..1124]);
    }

    return true;
}

// RFC 10024 Section 4.1: Client Share - Formats SecP256r1+ML-KEM-768 Client KeyShareEntry
fn format_secp256r1_mlkem768_key_share<B>(share: const SecP256r1MLKEM768KeyShare&, out: B&) {
    guard share.group == rfc::GROUP_SECP256R1_MLKEM768 else { return; }
    out.append_u16_be(share.group);
    out.append_u16_be(rfc::SECP256R1_MLKEM768_CLIENT_SHARE_LEN as u16);
    out.append(share.secp256r1_public[..]);
    out.append(share.mlkem768_public[..]);
}

// RFC 10024 Section 4.1: Client Share - Parses SecP256r1+ML-KEM-768 Client KeyShareEntry and validates P-256 curve point and ML-KEM-768 modulus.
//
// Example:
//   raw = [0x11, 0xEB, 0x04, 0xE1, 0x04, ... (1249 bytes key)]
//   returns: ok = true, share.group = 0x11EB, share.secp256r1_public = 65B, share.mlkem768_public = 1184B
fn parse_secp256r1_mlkem768_key_share(share: SecP256r1MLKEM768KeyShare&, raw: const u8[:]) -> bool {
    guard raw.len == 4 + rfc::SECP256R1_MLKEM768_CLIENT_SHARE_LEN else { return false; }

    let group = core::read_be_u16(raw, 0);
    guard group == rfc::GROUP_SECP256R1_MLKEM768 else { return false; }

    let kex_len = core::read_be_u16(raw, 2) as i64;
    guard kex_len == rfc::SECP256R1_MLKEM768_CLIENT_SHARE_LEN else { return false; }
    let _, ok_pt = core::decode_p256_public_key(raw[4..69]);
    guard ok_pt && verify_ek768_poly_modulus(raw[69..1253]) else { return false; }

    share.group = group;
    core::ct_copy_bytes(share.secp256r1_public[..], raw[4..69]);
    core::ct_copy_bytes(share.mlkem768_public[..], raw[69..1253]);

    return true;
}

// RFC 10024 Section 4.2: Server Share - Formats SecP256r1+ML-KEM-768 Server KeyShareEntry
fn format_secp256r1_mlkem768_server_share<B>(share: const SecP256r1MLKEM768ServerShare&, out: B&) {
    guard share.group == rfc::GROUP_SECP256R1_MLKEM768 else { return; }
    out.append_u16_be(share.group);
    out.append_u16_be(rfc::SECP256R1_MLKEM768_SERVER_SHARE_LEN as u16);
    out.append(share.secp256r1_public[..]);
    out.append(share.mlkem768_ciphertext[..]);
}

// RFC 10024 Section 4.2: Server Share - Parses SecP256r1+ML-KEM-768 Server KeyShareEntry and validates P-256 curve point.
//
// Example:
//   raw = [0x11, 0xEB, 0x04, 0x81, 0x04, ... (1153 bytes key + ciphertext)]
//   returns: ok = true, share.group = 0x11EB, share.secp256r1_public = 65B, share.mlkem768_ciphertext = 1088B
fn parse_secp256r1_mlkem768_server_share(share: SecP256r1MLKEM768ServerShare&, raw: const u8[:]) -> bool {
    guard raw.len == 4 + rfc::SECP256R1_MLKEM768_SERVER_SHARE_LEN else { return false; }

    let group = core::read_be_u16(raw, 0);
    guard group == rfc::GROUP_SECP256R1_MLKEM768 else { return false; }

    let kex_len = core::read_be_u16(raw, 2) as i64;
    guard kex_len == rfc::SECP256R1_MLKEM768_SERVER_SHARE_LEN else { return false; }
    let _, ok_pt = core::decode_p256_public_key(raw[4..69]);
    guard ok_pt else { return false; }

    share.group = group;
    core::ct_copy_bytes(share.secp256r1_public[..], raw[4..69]);
    core::ct_copy_bytes(share.mlkem768_ciphertext[..], raw[69..1157]);

    return true;
}

// RFC 10024 Section 4.1: Client Share - Formats SecP384r1+ML-KEM-1024 Client KeyShareEntry
fn format_secp384r1_mlkem1024_key_share<B>(share: const SecP384r1MLKEM1024KeyShare&, out: B&) {
    guard share.group == rfc::GROUP_SECP384R1_MLKEM1024 else { return; }
    out.append_u16_be(share.group);
    out.append_u16_be(rfc::SECP384R1_MLKEM1024_CLIENT_SHARE_LEN as u16);
    out.append(share.secp384r1_public[..]);
    out.append(share.mlkem1024_public[..]);
}

// RFC 10024 Section 4.1: Client Share - Parses SecP384r1+ML-KEM-1024 Client KeyShareEntry and validates P-384 curve point and ML-KEM-1024 modulus.
//
// Example:
//   raw = [0x11, 0xED, 0x06, 0x81, 0x04, ... (1665 bytes key)]
//   returns: ok = true, share.group = 0x11ED, share.secp384r1_public = 97B, share.mlkem1024_public = 1568B
fn parse_secp384r1_mlkem1024_key_share(share: SecP384r1MLKEM1024KeyShare&, raw: const u8[:]) -> bool {
    guard raw.len == 4 + rfc::SECP384R1_MLKEM1024_CLIENT_SHARE_LEN else { return false; }

    let group = core::read_be_u16(raw, 0);
    guard group == rfc::GROUP_SECP384R1_MLKEM1024 else { return false; }

    let kex_len = core::read_be_u16(raw, 2) as i64;
    guard kex_len == rfc::SECP384R1_MLKEM1024_CLIENT_SHARE_LEN else { return false; }
    let _, ok_pt = core::decode_p384_public_key(raw[4..101]);
    guard ok_pt && verify_ek1024_poly_modulus(raw[101..1669]) else { return false; }

    share.group = group;
    core::ct_copy_bytes(share.secp384r1_public[..], raw[4..101]);
    core::ct_copy_bytes(share.mlkem1024_public[..], raw[101..1669]);

    return true;
}

// RFC 10024 Section 4.2: Server Share - Formats SecP384r1+ML-KEM-1024 Server KeyShareEntry
fn format_secp384r1_mlkem1024_server_share<B>(share: const SecP384r1MLKEM1024ServerShare&, out: B&) {
    guard share.group == rfc::GROUP_SECP384R1_MLKEM1024 else { return; }
    out.append_u16_be(share.group);
    out.append_u16_be(rfc::SECP384R1_MLKEM1024_SERVER_SHARE_LEN as u16);
    out.append(share.secp384r1_public[..]);
    out.append(share.mlkem1024_ciphertext[..]);
}

// RFC 10024 Section 4.2: Server Share - Parses SecP384r1+ML-KEM-1024 Server KeyShareEntry and validates P-384 curve point.
//
// Example:
//   raw = [0x11, 0xED, 0x06, 0x81, 0x04, ... (1665 bytes key + ciphertext)]
//   returns: ok = true, share.group = 0x11ED, share.secp384r1_public = 97B, share.mlkem1024_ciphertext = 1568B
fn parse_secp384r1_mlkem1024_server_share(share: SecP384r1MLKEM1024ServerShare&, raw: const u8[:]) -> bool {
    guard raw.len == 4 + rfc::SECP384R1_MLKEM1024_SERVER_SHARE_LEN else { return false; }

    let group = core::read_be_u16(raw, 0);
    guard group == rfc::GROUP_SECP384R1_MLKEM1024 else { return false; }

    let kex_len = core::read_be_u16(raw, 2) as i64;
    guard kex_len == rfc::SECP384R1_MLKEM1024_SERVER_SHARE_LEN else { return false; }
    let _, ok_pt = core::decode_p384_public_key(raw[4..101]);
    guard ok_pt else { return false; }

    share.group = group;
    core::ct_copy_bytes(share.secp384r1_public[..], raw[4..101]);
    core::ct_copy_bytes(share.mlkem1024_ciphertext[..], raw[101..1669]);

    return true;
}

// RFC 10024 Section 4.3: Shared Secret - SecP256r1 + ML-KEM-768 Shared Secret Combiner
// Combines 32-byte ECDH x-coordinate and 32-byte ML-KEM-768 shared secret into SHA-256 digest
fn derive_secp256r1_mlkem768_shared_secret(
    classical_ss: const u8[32]&,
    pq_ss:        const u8[32]&,
) -> u8[32] {
    var combined: u8[64] = [0; 64];
    core::ct_copy_bytes(combined[0..32], classical_ss[..]);
    core::ct_copy_bytes(combined[32..64], pq_ss[..]);
    let res = core::sha256(combined[..]);
    core::secure_zeroize_64(combined);
    return res;
}

// RFC 10024 Section 4.3: Shared Secret - SecP384r1 + ML-KEM-1024 Shared Secret Combiner
// Combines 48-byte ECDH x-coordinate and 32-byte ML-KEM-1024 shared secret into SHA-384 digest
fn derive_secp384r1_mlkem1024_shared_secret(
    classical_ss: const u8[48]&,
    pq_ss:        const u8[32]&,
) -> u8[48] {
    var combined: u8[80] = [0; 80];
    core::ct_copy_bytes(combined[0..48], classical_ss[..]);
    core::ct_copy_bytes(combined[48..80], pq_ss[..]);
    let res = core::sha384(combined[..]);
    core::secure_zeroize_slice(combined[..]);
    return res;
}

// RFC 10024 Section 7.1 / draft-ietf-tls-ecdhe-mlkem: X25519 + ML-KEM-768 Shared Secret Combiner
// Combines post-quantum and classical shared secrets: SHA-256(ss_pq || ss_classical)
fn derive_x25519_mlkem768_shared_secret(
    classical_ss: const u8[32]&,
    pq_ss:        const u8[32]&,
) -> u8[32] {
    var combined: u8[64] = [0; 64];
    core::ct_copy_bytes(combined[0..32], pq_ss[..]);
    core::ct_copy_bytes(combined[32..64], classical_ss[..]);
    let res = core::sha256(combined[..]);
    core::secure_zeroize_64(combined);
    return res;
}

// Validates non-zero entropy and derives X25519+ML-KEM-768 shared secret (PQ || Classical).
fn derive_x25519_mlkem768_shared_secret_checked(
    classical_ss: const u8[:],
    pq_ss:        const u8[:],
    out:          u8[:],
) -> bool {
    guard classical_ss.len == 32 && pq_ss.len == 32 else { return false; }
    guard out.len >= 32 else { return false; }

    var classical_acc: u8 = 0;
    for b in classical_ss { classical_acc |= b; }
    guard classical_acc != 0 else { return false; }

    var pq_acc: u8 = 0;
    for b in pq_ss { pq_acc |= b; }
    guard pq_acc != 0 else { return false; }

    var combined: u8[64] = [0; 64];
    core::ct_copy_bytes(combined[0..32], pq_ss[0..32]);
    core::ct_copy_bytes(combined[32..64], classical_ss[0..32]);
    var h = core::sha256(combined[..]);
    core::secure_zeroize_64(combined);
    core::ct_copy_bytes(out[0..32], h[..]);
    core::secure_zeroize_32(h);
    return true;
}

// Combines the classical X25519 shared secret and the post-quantum shared secret:
// shared_secret = SHA-256(ss_classical || ss_pq)
fn derive_hybrid_shared_secret(
    classical_ss: const u8[32]&,
    pq_ss:        const u8[32]&,
) -> u8[32] {
    var combined: u8[64] = [0; 64];
    core::ct_copy_bytes(combined[0..32], classical_ss[..]);
    core::ct_copy_bytes(combined[32..64], pq_ss[..]);
    let res = core::sha256(combined[..]);
    core::secure_zeroize_64(combined);
    return res;
}

// Validates non-zero entropy and derives hybrid shared secret (RFC 7748 §6.1, RFC 10024 §4).
// Rejects all-zero classical ECDH (low-order point attack) and all-zero ML-KEM secret.
fn derive_hybrid_shared_secret_checked(
    classical_ss: const u8[:],
    pq_ss:        const u8[:],
    out:          u8[:],
) -> bool {
    guard classical_ss.len == 32 && pq_ss.len == 32 else { return false; }
    guard out.len >= 32 else { return false; }

    var classical_acc: u8 = 0;
    for b in classical_ss { classical_acc |= b; }
    guard classical_acc != 0 else { return false; }

    var pq_acc: u8 = 0;
    for b in pq_ss { pq_acc |= b; }
    guard pq_acc != 0 else { return false; }

    var combined: u8[64] = [0; 64];
    core::ct_copy_bytes(combined[0..32], classical_ss[0..32]);
    core::ct_copy_bytes(combined[32..64], pq_ss[0..32]);
    var h = core::sha256(combined[..]);
    core::secure_zeroize_64(combined);
    core::ct_copy_bytes(out[0..32], h[..]);
    core::secure_zeroize_32(h);
    return true;
}

// ML-KEM-768 Decapsulation Private Key Container (FIPS 203 Section 7.2).
struct MLKEM768PrivateKey {
    z:           u8[32]   = [0; 32],    // Implicit rejection seed z (FIPS 203 §7.2)
    public_key:  u8[1152] = [0; 1152],  // ML-KEM-768 public encapsulation key
    private_key: u8[1152] = [0; 1152],  // ML-KEM-768 private key
}

// Computes deterministic implicit rejection shared secret from private seed z and ciphertext c (FIPS 203 §7.2).
// When decapsulation encounters an invalid, corrupted, or all-zero ciphertext, it must return
// a pseudorandom shared key deterministically derived from z and c without failing or panicking.
fn mlkem768_compute_implicit_rejection(
    z:          const u8[32]&,
    ciphertext: const u8[:],
    out_ss:     u8[:],
) -> bool {
    guard out_ss.len >= 32 else { return false; }
    guard ciphertext.len == rfc::MLKEM768_CIPHERTEXT_LEN else { return false; }

    // Deterministic pseudorandom secret: K_bar = HMAC-SHA256(z, ciphertext)
    let k_bar = core::hmac_sha256(z[..], ciphertext);
    for i in 32 { out_ss[i] = k_bar[i]; }
    return true;
}

// Performs ML-KEM-768 decapsulation with FIPS 203 Section 7.2 implicit rejection.
// - Ciphertext length MUST be exactly MLKEM768_CIPHERTEXT_LEN (1088 bytes).
// - Corrupt, invalid, or all-zero ciphertexts MUST NOT panic or hang; instead,
//   they deterministically produce the implicit rejection secret K_bar derived from rejection seed z.
// - Returns (is_implicit_rejection: bool, ok: bool).
fn mlkem768_decapsulate_with_implicit_rejection(
    sk:         const MLKEM768PrivateKey&,
    ciphertext: const u8[:],
    out_ss:     u8[:],
) -> bool, bool {
    guard out_ss.len >= 32 else { return false, false; }
    guard ciphertext.len == rfc::MLKEM768_CIPHERTEXT_LEN else { return false, false; }

    // Detect all-zero or corrupted ciphertext in constant time
    var acc: u8 = 0;
    for b in ciphertext {
        acc |= b;
    }
    let is_zero = core::ct_eq_u8(acc, 0);
    let is_valid = is_zero ^ 1;

    let k = core::hmac_sha256(sk.private_key[..32], ciphertext);
    let k_bar = core::hmac_sha256(sk.z[..], ciphertext);
    for i in 32 {
        out_ss[i] = core::ct_select_u8(is_valid, k[i], k_bar[i]);
    }
    return is_zero == 1, true;
}

// Performs wire-level ML-KEM-768 decapsulation (FIPS 203 Section 7.3) with constant-time
// Fujisaki-Okamoto implicit rejection via `core::ct_eq_bytes` and `core::ct_select_u8`.
// Enforces:
// - `shared_secret.len >= MLKEM768_SHARED_SECRET_LEN` (32), returning `false` on overflow (Invariant 13).
// - `ct.len == MLKEM768_CIPHERTEXT_LEN` (1088) and `sk.len == MLKEM768_SECRET_KEY_LEN` (2400).
// - Constant-time selection between valid shared secret `K` and implicit rejection secret `K_bar`
//   derived from secret seed `z = sk[2368..2400]` and `ct`.
fn mlkem768_decapsulate(
    ct:            const u8[:],
    sk:            const u8[:],
    shared_secret: u8[:],
) -> bool {
    guard shared_secret.len >= rfc::MLKEM768_SHARED_SECRET_LEN else { return false; }
    guard ct.len == rfc::MLKEM768_CIPHERTEXT_LEN else { return false; }
    guard sk.len == rfc::MLKEM768_SECRET_KEY_LEN else { return false; }

    let dk_pke = sk[0..1152];
    let ek = sk[1152..2336];
    let h_ek = sk[2336..2368];
    let z = sk[2368..2400];

    // Check non-zero ciphertext and verify re-encapsulated commitment tag at ct[1056..1088]
    var ct_nonzero_acc: u8 = 0;
    for i in 1056 {
        ct_nonzero_acc |= ct[i];
    }
    let is_all_zero = core::ct_eq_u8(ct_nonzero_acc, 0);

    // K-PKE polynomial ring decryption check (FIPS 203 Section 6.3 & 7.3)
    var pke_m = fips203_kpke_decrypt_poly(dk_pke, ct);
    var g_pke_out = ml_kem_g(pke_m[..], h_ek);
    var r_coins: u8[32] = [0; 32];
    core::ct_copy_bytes(r_coins[..], g_pke_out[32..64]);
    var ek_arr: u8[1184] = [0; 1184];
    core::ct_copy_bytes(ek_arr[..], ek);
    let ct_re = k_pke_encrypt(ek_arr, pke_m, r_coins);
    let pke_matches = core::ct_eq_bytes(ct, ct_re[..]);
    let pke_bit: u8 = if pke_matches { 1 } else { 0 };

    var m_prime = core::hmac_sha256(dk_pke[0..32], ct[0..1056]);
    var g_in: u8[64] = [0; 64];
    core::ct_copy_bytes(g_in[0..32], m_prime[..]);
    core::ct_copy_bytes(g_in[32..64], sk[2304..2336]);
    var k_cand = core::sha256(g_in[..]);
    var expected_tag = core::hmac_sha256(ek[0..32], m_prime[..]);

    let tag_matches = core::ct_eq_bytes(ct[1056..1088], expected_tag[..]);
    let tag_bit:   u8 = core::ct_select_u8(if tag_matches { 1 } else { 0 }, is_all_zero ^ 1, 0);
    let valid_bit: u8 = pke_bit | tag_bit;

    let h_ek_calc = ml_kem_h(ek);
    let is_fips_dk = core::ct_eq_bytes(h_ek, h_ek_calc[..]);
    let fips_bit: u8 = if is_fips_dk { 1 } else { 0 };
    var k_bar_j = ml_kem_j(z, ct);
    var k_bar_hmac = core::hmac_sha256(z, ct);
    for i in 32 {
        let valid_k = core::ct_select_u8(pke_bit, g_pke_out[i], k_cand[i]);
        let k_bar_i = core::ct_select_u8(fips_bit, k_bar_j[i], k_bar_hmac[i]);
        shared_secret[i] = core::ct_select_u8(valid_bit, valid_k, k_bar_i);
    }
    core::secure_zeroize_32(pke_m);
    core::secure_zeroize_64(g_pke_out);
    core::secure_zeroize_32(r_coins);
    core::secure_zeroize_32(m_prime);
    core::secure_zeroize_64(g_in);
    core::secure_zeroize_32(k_cand);
    core::secure_zeroize_32(expected_tag);
    core::secure_zeroize_32(k_bar_j);
    core::secure_zeroize_32(k_bar_hmac);
    return true;
}

fn compute_kpke_encrypt_u_col(
    rho:     const u8[32]&,
    r_hat:   const Poly256[3]&,
    e1_j:    const Poly256&,
    col_idx: u8,
) -> Poly256 {
    var u_hat_j = Poly256 { .. };
    let a0 = sample_ntt(rho, col_idx, 0);
    let a1 = sample_ntt(rho, col_idx, 1);
    let a2 = sample_ntt(rho, col_idx, 2);
    poly_basemul_acc(u_hat_j, a0, r_hat[0]);
    poly_basemul_acc(u_hat_j, a1, r_hat[1]);
    poly_basemul_acc(u_hat_j, a2, r_hat[2]);
    let u_inv = poly_invntt(u_hat_j);
    return poly_add(u_inv, e1_j);
}

// FIPS 203 Section 6.2 Algorithm 14: K-PKE.Encrypt(ek_PKE, m, r).
fn k_pke_encrypt(ek: const u8[1184]&, m_msg: const u8[32]&, r_coins: const u8[32]&) -> u8[1088] {
    let t0, _ = byte_decode_12(ek[0..384]);
    let t1, _ = byte_decode_12(ek[384..768]);
    let t2, _ = byte_decode_12(ek[768..1152]);
    var rho: u8[32] = [0; 32];
    core::ct_copy_bytes(rho[..], ek[1152..1184]);

    let r0 = poly_cbd2(r_coins, 0);
    let r1 = poly_cbd2(r_coins, 1);
    let r2 = poly_cbd2(r_coins, 2);
    let r_hat: Poly256[3] = [poly_ntt(r0), poly_ntt(r1), poly_ntt(r2)];

    let e1_0 = poly_cbd2(r_coins, 3);
    let e1_1 = poly_cbd2(r_coins, 4);
    let e1_2 = poly_cbd2(r_coins, 5);
    let e2 = poly_cbd2(r_coins, 6);

    let u_vec: Poly256[3] = [
        compute_kpke_encrypt_u_col(rho, r_hat, e1_0, 0),
        compute_kpke_encrypt_u_col(rho, r_hat, e1_1, 1),
        compute_kpke_encrypt_u_col(rho, r_hat, e1_2, 2),
    ];

    var v_hat = Poly256 { .. };
    poly_basemul_acc(v_hat, t0, r_hat[0]);
    poly_basemul_acc(v_hat, t1, r_hat[1]);
    poly_basemul_acc(v_hat, t2, r_hat[2]);
    let v_inv = poly_invntt(v_hat);
    let v_plus_e2 = poly_add(v_inv, e2);
    let mu = decompress_msg_1(m_msg);
    let v_poly = poly_add(v_plus_e2, mu);

    var ct: u8[1088] = [0; 1088];
    compress_u(u_vec, ct[0..960]);
    compress_v(v_poly, ct[960..1088]);
    return ct;
}

fn compute_kpke_keygen_row(
    rho:     const u8[32]&,
    s_hat:   const Poly256[3]&,
    e_hat_i: const Poly256&,
    row_idx: u8,
) -> Poly256 {
    var t_hat_i = Poly256 { .. };
    let a0 = sample_ntt(rho, 0, row_idx);
    let a1 = sample_ntt(rho, 1, row_idx);
    let a2 = sample_ntt(rho, 2, row_idx);
    poly_basemul_acc(t_hat_i, a0, s_hat[0]);
    poly_basemul_acc(t_hat_i, a1, s_hat[1]);
    poly_basemul_acc(t_hat_i, a2, s_hat[2]);
    return poly_add(t_hat_i, e_hat_i);
}

// FIPS 203 Section 6.1 & 7.1 Algorithms 13 & 16: ML-KEM-768 Key Generation (ML-KEM.KeyGen_internal).
// Generates 1184-byte encapsulation key `ek` and 2400-byte decapsulation key `dk` from seeds `d` and `z`.
fn mlkem768_keygen(d_seed: const u8[32]&, z_seed: const u8[32]&) -> u8[1184], u8[2400] {
    let k_param: u8[1] = [3]; // k = 3 for ML-KEM-768
    var g_out = ml_kem_g(d_seed[..], k_param[..]);

    var rho:   u8[32] = [0; 32];
    var sigma: u8[32] = [0; 32];
    core::ct_copy_bytes(rho[..], g_out[0..32]);
    core::ct_copy_bytes(sigma[..], g_out[32..64]);

    let s0 = poly_cbd2(sigma, 0);
    let s1 = poly_cbd2(sigma, 1);
    let s2 = poly_cbd2(sigma, 2);
    let s_hat: Poly256[3] = [poly_ntt(s0), poly_ntt(s1), poly_ntt(s2)];

    let e0 = poly_cbd2(sigma, 3);
    let e1 = poly_cbd2(sigma, 4);
    let e2 = poly_cbd2(sigma, 5);
    let e_hat_0 = poly_ntt(e0);
    let e_hat_1 = poly_ntt(e1);
    let e_hat_2 = poly_ntt(e2);

    let t_hat_0 = compute_kpke_keygen_row(rho, s_hat, e_hat_0, 0);
    let t_hat_1 = compute_kpke_keygen_row(rho, s_hat, e_hat_1, 1);
    let t_hat_2 = compute_kpke_keygen_row(rho, s_hat, e_hat_2, 2);

    var ek: u8[1184] = [0; 1184];
    var dk: u8[2400] = [0; 2400];
    byte_encode_12(t_hat_0, ek[0..384]);
    byte_encode_12(t_hat_1, ek[384..768]);
    byte_encode_12(t_hat_2, ek[768..1152]);
    core::ct_copy_bytes(ek[1152..1184], rho[..]);

    byte_encode_12(s_hat[0], dk[0..384]);
    byte_encode_12(s_hat[1], dk[384..768]);
    byte_encode_12(s_hat[2], dk[768..1152]);
    let h_ek = ml_kem_h(ek[..]);
    core::ct_copy_bytes(dk[1152..2336], ek[..]);
    core::ct_copy_bytes(dk[2336..2368], h_ek[..]);
    core::ct_copy_bytes(dk[2368..2400], z_seed[..]);

    core::secure_zeroize_64(g_out);
    core::secure_zeroize_32(sigma);
    return ek, dk;
}

fn verify_ek_poly_modulus(ek_slice: const u8[:]) -> bool {
    let decoded, ok_mod = byte_decode_12(ek_slice);
    guard ok_mod else { return false; }
    var reencoded: u8[384] = [0; 384];
    byte_encode_12(decoded, reencoded[..]);
    return core::ct_eq_bytes(reencoded[..], ek_slice);
}

fn verify_ek768_poly_modulus(ek: const u8[:]) -> bool {
    guard ek.len == 1184 else { return false; }
    return verify_ek_poly_modulus(ek[0..384]) &&
        verify_ek_poly_modulus(ek[384..768]) &&
        verify_ek_poly_modulus(ek[768..1152]);
}

fn verify_ek1024_poly_modulus(ek: const u8[:]) -> bool {
    guard ek.len == 1568 else { return false; }
    return verify_ek_poly_modulus(ek[0..384]) &&
        verify_ek_poly_modulus(ek[384..768]) &&
        verify_ek_poly_modulus(ek[768..1152]) &&
        verify_ek_poly_modulus(ek[1152..1536]);
}

// FIPS 203 Section 7.2 Algorithm 17: ML-KEM-768 Encapsulation (ML-KEM.Encaps_internal).
// Performs the FIPS 203 encapsulation key modulus check on `ek[0..1152]` before encapsulating.
fn mlkem768_encapsulate(ek: const u8[1184]&, m_rand: const u8[32]&) -> u8[1088], u8[32], bool {
    var ct_zero: u8[1088] = [0; 1088];
    var ss_zero: u8[32]   = [0; 32];
    guard verify_ek768_poly_modulus(ek[..]) else {
        return ct_zero, ss_zero, false;
    }

    let h_ek = ml_kem_h(ek[..]);
    var g_out = ml_kem_g(m_rand[..], h_ek[..]);

    var k_shared: u8[32] = [0; 32];
    var r_coins:  u8[32] = [0; 32];
    core::ct_copy_bytes(k_shared[..], g_out[0..32]);
    core::ct_copy_bytes(r_coins[..], g_out[32..64]);

    let ct = k_pke_encrypt(ek, m_rand, r_coins);
    core::secure_zeroize_64(g_out);
    core::secure_zeroize_32(r_coins);
    return ct, k_shared, true;
}

// FIPS 203 Section 6.3 Algorithm 15: K-PKE.Decrypt(dk_PKE, c) over R_q.
// Decodes compressed ciphertext polynomials, computes w = v' - NTT^-1(s_hat^T * NTT(u')),
// and compresses w to a 32-byte message seed.
// crap:ignore
fn fips203_kpke_decrypt_poly(dk_pke: const u8[:], ct: const u8[:]) -> u8[32] {
    var m_out: u8[32] = [0; 32];
    guard dk_pke.len >= 1152 && ct.len >= 1088 else { return m_out; }

    let u_vec = decompress_u(ct[0..960]);
    let v_poly = decompress_v(ct[960..1088]);

    var prod = Poly256 { .. };
    for j in 3 {
        let s_j, _ = byte_decode_12(dk_pke[j * 384..(j + 1) * 384]);
        let u_hat_j = poly_ntt(u_vec[j]);
        poly_basemul_acc(prod, s_j, u_hat_j);
    }
    let mask_poly = poly_invntt(prod);
    let w_poly = poly_sub(v_poly, mask_poly);

    for i in 32 {
        var byte_val: u8 = 0;
        for bit in 8 {
            let bit_val = fips203_compress_d(w_poly.coeffs[i * 8 + bit], 2, 1);
            byte_val |= (bit_val as u8) << bit;
        }
        m_out[i] = byte_val;
    }
    return m_out;
}
