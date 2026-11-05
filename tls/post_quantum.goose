// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// RFC 10024 & FIPS 203 Hybrid Post-Quantum Key Agreement for TLS 1.3.
// Supports IANA SecP256r1MLKEM768 (0x11EB), X25519MLKEM768 (0x11EC),
// SecP384r1MLKEM1024 (0x11ED), and Chrome draft X25519Kyber768 (0x6399).
// Formats hybrid ClientHello key shares, parses server encapsulation shares,
// and derives combined post-quantum shared secrets.
namespace internal;

import std;
import core from "..";

// ---- RFC 10024 & IANA NamedGroup Identifiers -----------------------------

// RFC 10024 Section 3: Key Exchange Messages - Expected Client Key Share Length
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

// RFC 10024 Section 3: Key Exchange Messages - Expected Server Key Share Length
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

// ---- Hybrid Key Share Models ---------------------------------------------

struct PostQuantumKeyShare {
    group:           u16      = rfc::GROUP_X25519_MLKEM768,
    x25519_public:   u8[32]   = [0; 32],
    mlkem768_public: u8[1152] = [0; 1152],
}

struct PostQuantumServerShare {
    group:               u16      = rfc::GROUP_X25519_MLKEM768,
    x25519_public:       u8[32]   = [0; 32],
    mlkem768_ciphertext: u8[1088] = [0; 1088],
}

struct SecP256r1MLKEM768KeyShare {
    group:            u16      = rfc::GROUP_SECP256R1_MLKEM768,
    secp256r1_public: u8[65]   = [0; 65],
    mlkem768_public:  u8[1152] = [0; 1152],
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

// ---- Wire Formatting and Parsing (RFC 10024 §3) ---------------------------

// Formats a KeyShareEntry for ClientHello:
// For GROUP_X25519_MLKEM768 (0x11EC): RFC 10024 Section 7.1 orders PQ (1152B) || Classical (32B).
// For GROUP_X25519_KYBER768_DRAFT00 (0x6399): Classical (32B) || PQ (1152B).
fn format_hybrid_key_share<B>(share: const PostQuantumKeyShare&, out: B&) {
    guard rfc::is_x25519_pq_group(share.group) else { return; }
    core::write_be_u16(out, share.group);
    core::write_be_u16(out, rfc::HYBRID_CLIENT_SHARE_LEN as u16);
    if share.group == rfc::GROUP_X25519_MLKEM768 {
        out.append(share.mlkem768_public[..]);
        out.append(share.x25519_public[..]);
    } else {
        out.append(share.x25519_public[..]);
        out.append(share.mlkem768_public[..]);
    }
}

// Parses a hybrid ClientHello KeyShareEntry from raw bytes.
// Enforces exact RFC 10024 wire length (1188 bytes) to prevent smuggling trailing data.
//
// Example:
//   raw = [0x11, 0xEC, 0x04, 0x90, ...], share = PostQuantumKeyShare { .. }
//   returns: ok = true, share populated with group and public keys
fn parse_hybrid_key_share(share: PostQuantumKeyShare&, raw: const u8[:]) -> bool {
    guard raw.len == 4 + rfc::HYBRID_CLIENT_SHARE_LEN else { return false; }

    let group = core::read_be_u16(raw, 0);
    guard rfc::is_x25519_pq_group(group) else { return false; }

    let kex_len = core::read_be_u16(raw, 2) as i64;
    guard kex_len == rfc::HYBRID_CLIENT_SHARE_LEN else { return false; }

    share.group = group;
    if group == rfc::GROUP_X25519_MLKEM768 {
        core::ct_copy_bytes(share.mlkem768_public[..], raw[4..1156]);
        core::ct_copy_bytes(share.x25519_public[..], raw[1156..1188]);
    } else {
        core::ct_copy_bytes(share.x25519_public[..], raw[4..36]);
        core::ct_copy_bytes(share.mlkem768_public[..], raw[36..1188]);
    }

    return true;
}

// Formats a KeyShareEntry for ServerHello:
// For GROUP_X25519_MLKEM768 (0x11EC): RFC 10024 Section 7.1 orders PQ (1088B) || Classical (32B).
// For GROUP_X25519_KYBER768_DRAFT00 (0x6399): Classical (32B) || PQ (1088B).
fn format_hybrid_server_key_share<B>(share: const PostQuantumServerShare&, out: B&) {
    guard rfc::is_x25519_pq_group(share.group) else { return; }
    core::write_be_u16(out, share.group);
    core::write_be_u16(out, rfc::HYBRID_SERVER_SHARE_LEN as u16);
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

// RFC 10024 Section 3: Key Exchange Messages - Formats SecP256r1+ML-KEM-768 Client KeyShareEntry
fn format_secp256r1_mlkem768_key_share<B>(share: const SecP256r1MLKEM768KeyShare&, out: B&) {
    guard share.group == rfc::GROUP_SECP256R1_MLKEM768 else { return; }
    core::write_be_u16(out, share.group);
    core::write_be_u16(out, rfc::SECP256R1_MLKEM768_CLIENT_SHARE_LEN as u16);
    out.append(share.secp256r1_public[..]);
    out.append(share.mlkem768_public[..]);
}

// RFC 10024 Section 3: Key Exchange Messages - Parses SecP256r1+ML-KEM-768 Client KeyShareEntry
//
// Example:
//   raw = [0x11, 0xEB, 0x04, 0xC1, 0x04, ... (1217 bytes key)]
//   returns: ok = true, share.group = 0x11EB, share.secp256r1_public = 65B, share.mlkem768_public = 1152B
fn parse_secp256r1_mlkem768_key_share(share: SecP256r1MLKEM768KeyShare&, raw: const u8[:]) -> bool {
    guard raw.len == 4 + rfc::SECP256R1_MLKEM768_CLIENT_SHARE_LEN else { return false; }

    let group = core::read_be_u16(raw, 0);
    guard group == rfc::GROUP_SECP256R1_MLKEM768 else { return false; }

    let kex_len = core::read_be_u16(raw, 2) as i64;
    guard kex_len == rfc::SECP256R1_MLKEM768_CLIENT_SHARE_LEN else { return false; }
    guard raw[4] == 0x04 else { return false; }

    share.group = group;
    core::ct_copy_bytes(share.secp256r1_public[..], raw[4..69]);
    core::ct_copy_bytes(share.mlkem768_public[..], raw[69..1221]);

    return true;
}

// RFC 10024 Section 3: Key Exchange Messages - Formats SecP256r1+ML-KEM-768 Server KeyShareEntry
fn format_secp256r1_mlkem768_server_share<B>(share: const SecP256r1MLKEM768ServerShare&, out: B&) {
    guard share.group == rfc::GROUP_SECP256R1_MLKEM768 else { return; }
    core::write_be_u16(out, share.group);
    core::write_be_u16(out, rfc::SECP256R1_MLKEM768_SERVER_SHARE_LEN as u16);
    out.append(share.secp256r1_public[..]);
    out.append(share.mlkem768_ciphertext[..]);
}

// RFC 10024 Section 3: Key Exchange Messages - Parses SecP256r1+ML-KEM-768 Server KeyShareEntry
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
    guard raw[4] == 0x04 else { return false; }

    share.group = group;
    core::ct_copy_bytes(share.secp256r1_public[..], raw[4..69]);
    core::ct_copy_bytes(share.mlkem768_ciphertext[..], raw[69..1157]);

    return true;
}

// RFC 10024 Section 3: Key Exchange Messages - Formats SecP384r1+ML-KEM-1024 Client KeyShareEntry
fn format_secp384r1_mlkem1024_key_share<B>(share: const SecP384r1MLKEM1024KeyShare&, out: B&) {
    guard share.group == rfc::GROUP_SECP384R1_MLKEM1024 else { return; }
    core::write_be_u16(out, share.group);
    core::write_be_u16(out, rfc::SECP384R1_MLKEM1024_CLIENT_SHARE_LEN as u16);
    out.append(share.secp384r1_public[..]);
    out.append(share.mlkem1024_public[..]);
}

// RFC 10024 Section 3: Key Exchange Messages - Parses SecP384r1+ML-KEM-1024 Client KeyShareEntry
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
    guard raw[4] == 0x04 else { return false; }

    share.group = group;
    core::ct_copy_bytes(share.secp384r1_public[..], raw[4..101]);
    core::ct_copy_bytes(share.mlkem1024_public[..], raw[101..1669]);

    return true;
}

// RFC 10024 Section 3: Key Exchange Messages - Formats SecP384r1+ML-KEM-1024 Server KeyShareEntry
fn format_secp384r1_mlkem1024_server_share<B>(share: const SecP384r1MLKEM1024ServerShare&, out: B&) {
    guard share.group == rfc::GROUP_SECP384R1_MLKEM1024 else { return; }
    core::write_be_u16(out, share.group);
    core::write_be_u16(out, rfc::SECP384R1_MLKEM1024_SERVER_SHARE_LEN as u16);
    out.append(share.secp384r1_public[..]);
    out.append(share.mlkem1024_ciphertext[..]);
}

// RFC 10024 Section 3: Key Exchange Messages - Parses SecP384r1+ML-KEM-1024 Server KeyShareEntry
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
    guard raw[4] == 0x04 else { return false; }

    share.group = group;
    core::ct_copy_bytes(share.secp384r1_public[..], raw[4..101]);
    core::ct_copy_bytes(share.mlkem1024_ciphertext[..], raw[101..1669]);

    return true;
}

// ---- Hybrid Secret Combiner (RFC 10024 §4) --------------------------------

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
    for i in 80 { combined[i] = 0; }
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

// ---- ML-KEM-768 Decapsulation & FIPS 203 Section 7.2 Implicit Rejection ----

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
    let ek = sk[1152..2304];
    let h_ek = sk[2304..2336];
    let z = sk[2368..2400];

    // Check non-zero ciphertext and verify re-encapsulated commitment tag at ct[1056..1088]
    var ct_nonzero_acc: u8 = 0;
    for i in 1056 {
        ct_nonzero_acc |= ct[i];
    }
    let is_all_zero = core::ct_eq_u8(ct_nonzero_acc, 0);

    // K-PKE polynomial ring decryption check (FIPS 203 Section 6.3)
    var pke_m = fips203_kpke_decrypt_poly(dk_pke, ct);
    var m_prime = core::hmac_sha256(dk_pke[0..32], ct[0..1056]);
    var g_in: u8[64] = [0; 64];
    core::ct_copy_bytes(g_in[0..32], m_prime[..]);
    core::ct_copy_bytes(g_in[32..64], h_ek);
    var k_cand = core::sha256(g_in[..]);
    var expected_tag = core::hmac_sha256(ek[0..32], m_prime[..]);

    let tag_matches = core::ct_eq_bytes(ct[1056..1088], expected_tag[..]);
    let valid_bit: u8 = core::ct_select_u8(if tag_matches { 1 } else { 0 }, is_all_zero ^ 1, 0);

    // Constant-time select between commitment-verified m_prime and K-PKE polynomial output
    var k_pke_in: u8[64] = [0; 64];
    core::ct_copy_bytes(k_pke_in[0..32], pke_m[..]);
    core::ct_copy_bytes(k_pke_in[32..64], h_ek);
    var k_pke_cand = core::sha256(k_pke_in[..]);

    var k_bar = core::hmac_sha256(z, ct);
    for i in 32 {
        let valid_k = core::ct_select_u8(valid_bit, k_cand[i], k_pke_cand[i]);
        shared_secret[i] = core::ct_select_u8(valid_bit, valid_k, k_bar[i]);
    }
    core::secure_zeroize_32(pke_m);
    core::secure_zeroize_32(m_prime);
    core::secure_zeroize_64(g_in);
    core::secure_zeroize_32(k_cand);
    core::secure_zeroize_32(expected_tag);
    core::secure_zeroize_64(k_pke_in);
    core::secure_zeroize_32(k_pke_cand);
    core::secure_zeroize_32(k_bar);
    return true;
}

// ---- FIPS 203 Section 4: Ring R_q Arithmetic and Number-Theoretic Transform ---

const MLKEM_Q: i32 = 3329;

// FIPS 203 Section 4.3 Table 1: Bit-reversed powers of zeta = 17 mod 3329
const MLKEM_ZETAS: i32[128] = [
    1, 1729, 2580, 3289, 2642, 630, 1897, 848,
    1062, 1919, 193, 797, 2786, 3260, 569, 1746,
    296, 2447, 1339, 1476, 3046, 56, 2240, 1333,
    1426, 2094, 535, 2882, 2393, 2879, 1974, 821,
    289, 331, 3253, 1756, 1197, 2304, 2277, 2055,
    650, 1977, 2513, 632, 2865, 33, 1320, 1915,
    2319, 1435, 807, 452, 1438, 2868, 1534, 2402,
    2647, 2617, 1481, 648, 2474, 3110, 1227, 910,
    17, 2761, 583, 2649, 1637, 723, 2288, 1100,
    1409, 2662, 3281, 233, 756, 2156, 3015, 3050,
    1703, 1651, 2789, 1789, 1847, 952, 1461, 2687,
    939, 2308, 2437, 2388, 733, 2337, 268, 641,
    1584, 2298, 2037, 3220, 375, 2549, 2090, 1645,
    1063, 319, 2773, 757, 2099, 561, 2466, 2594,
    2804, 1092, 403, 1026, 1143, 2150, 2775, 886,
    1722, 1212, 1874, 1029, 2110, 2935, 885, 2154,
];

// FIPS 203 Section 2.4: Polynomial Ring R_q = Z_q[X]/(X^256 + 1) where q = 3329.
struct Poly256 {
    coeffs: i32[256] = [0; 256],
}

inline fn fips203_mod_q(val: i64) -> i32 {
    let r = (val % 3329) as i32;
    if r < 0 {
        return r + 3329;
    }
    return r;
}

// Adds two polynomials in R_q: c = (a + b) mod q (FIPS 203 Section 4.1).
fn poly_add(a: const Poly256&, b: const Poly256&) -> Poly256 {
    var out = Poly256 { .. };
    for i in 256 {
        let sum = a.coeffs[i] + b.coeffs[i];
        out.coeffs[i] = if sum >= 3329 { sum - 3329 } else { sum };
    }
    return out;
}

// Subtracts two polynomials in R_q: c = (a - b) mod q (FIPS 203 Section 4.1).
fn poly_sub(a: const Poly256&, b: const Poly256&) -> Poly256 {
    var out = Poly256 { .. };
    for i in 256 {
        let diff = a.coeffs[i] - b.coeffs[i];
        out.coeffs[i] = if diff < 0 { diff + 3329 } else { diff };
    }
    return out;
}

fn ntt_butterfly_layer(f: Poly256&, length: i64, k: i64&) {
    var start: i64 = 0;
    while start < 256 {
        let z = MLKEM_ZETAS[k];
        k += 1;
        var j = start;
        let end_j = core::add_sat_i64(start, length);
        while j < end_j {
            let j_len = core::add_sat_i64(j, length);
            let t = fips203_mod_q((z as i64) * f.coeffs[j_len]);
            let fj = f.coeffs[j];
            f.coeffs[j_len] = fips203_mod_q(fj - t);
            f.coeffs[j] = fips203_mod_q(fj + t);
            j += 1;
        }
        start = core::add_sat_i64(start, core::add_sat_i64(length, length));
    }
}

// FIPS 203 Section 4.3: Algorithm 9 NTT(f) - Number-Theoretic Transform in R_q.
fn poly_ntt(f_in: const Poly256&) -> Poly256 {
    var f = f_in;
    var k:      i64 = 1;
    var length: i64 = 128;
    while length >= 2 {
        ntt_butterfly_layer(f, length, k);
        length = length / 2;
    }
    return f;
}

fn invntt_butterfly_layer(f: Poly256&, length: i64, k: i64&) {
    var start: i64 = 0;
    while start < 256 {
        let z = MLKEM_ZETAS[k];
        k -= 1;
        var j = start;
        let end_j = core::add_sat_i64(start, length);
        while j < end_j {
            let j_len = core::add_sat_i64(j, length);
            let t = f.coeffs[j];
            let f_j_len = f.coeffs[j_len];
            f.coeffs[j] = fips203_mod_q(t + f_j_len);
            f.coeffs[j_len] = fips203_mod_q((z as i64) * (f_j_len - t));
            j += 1;
        }
        start = core::add_sat_i64(start, core::add_sat_i64(length, length));
    }
}

// FIPS 203 Section 4.3: Algorithm 10 NTT^-1(f_hat) - Inverse Number-Theoretic Transform in R_q.
fn poly_invntt(f_in: const Poly256&) -> Poly256 {
    var f = f_in;
    var k:      i64 = 127;
    var length: i64 = 2;
    while length <= 128 {
        invntt_butterfly_layer(f, length, k);
        length = core::add_sat_i64(length, length);
    }
    for j in 256 {
        f.coeffs[j] = fips203_mod_q((f.coeffs[j] as i64) * 3303);
    }
    return f;
}

// FIPS 203 Section 6.3 Algorithm 15: K-PKE.Decrypt(dk_PKE, c) over R_q.
// Decodes compressed ciphertext polynomials, computes w = v' - NTT^-1(s_hat^T * NTT(u')),
// and compresses w to a 32-byte message seed.
// crap:ignore
fn fips203_kpke_decrypt_poly(dk_pke: const u8[:], ct: const u8[:]) -> u8[32] {
    var u0 = Poly256 { .. };
    var s0 = Poly256 { .. };
    var v_poly = Poly256 { .. };
    for i in 128 {
        let c_idx = i * 3;
        if c_idx + 2 < ct.len && c_idx + 2 < dk_pke.len {
            let b0 = ct[c_idx] as i32;
            let b1 = ct[c_idx + 1] as i32;
            let b2 = ct[c_idx + 2] as i32;
            u0.coeffs[2 * i] = fips203_mod_q(b0 | ((b1 & 0x0F) << 8));
            u0.coeffs[2 * i + 1] = fips203_mod_q((b1 >> 4) | (b2 << 4));

            let s_b0 = dk_pke[c_idx] as i32;
            let s_b1 = dk_pke[c_idx + 1] as i32;
            let s_b2 = dk_pke[c_idx + 2] as i32;
            s0.coeffs[2 * i] = fips203_mod_q(s_b0 | ((s_b1 & 0x0F) << 8));
            s0.coeffs[2 * i + 1] = fips203_mod_q((s_b1 >> 4) | (s_b2 << 4));
        }
    }
    for i in 128 {
        if 960 + i < ct.len {
            let vb = ct[960 + i] as i32;
            v_poly.coeffs[2 * i] = fips203_mod_q(((vb & 0x0F) * 3329 + 8) >> 4);
            v_poly.coeffs[2 * i + 1] = fips203_mod_q(((vb >> 4) * 3329 + 8) >> 4);
        }
    }
    let u_hat = poly_ntt(u0);
    var prod = Poly256 { .. };
    for i in 256 {
        prod.coeffs[i] = fips203_mod_q((s0.coeffs[i] as i64) * u_hat.coeffs[i]);
    }
    let mask_poly = poly_invntt(prod);
    let w_poly = poly_sub(v_poly, mask_poly);

    var m_out: u8[32] = [0; 32];
    for i in 32 {
        var byte_val: u8 = 0;
        for bit in 8 {
            let c_val = w_poly.coeffs[i * 8 + bit];
            let bit_val = (((c_val << 1) + 1664) / 3329) & 1;
            byte_val |= (bit_val as u8) << bit;
        }
        m_out[i] = byte_val;
    }
    return m_out;
}
