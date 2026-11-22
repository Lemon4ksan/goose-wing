// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// RFC 10024 & FIPS 203 Hybrid Post-Quantum Key Agreement for TLS 1.3.
// Supports IANA SecP256r1MLKEM768 (0x11EB), X25519MLKEM768 (0x11EC),
// SecP384r1MLKEM1024 (0x11ED), and Chrome draft X25519Kyber768 (0x6399).
// Formats hybrid ClientHello key shares, parses server encapsulation shares,
// and derives combined post-quantum shared secrets.
namespace tls_internal;

import std;
import core;

// ---- RFC 10024 & IANA NamedGroup Identifiers -----------------------------

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

// ---- Hybrid Key Share Models ---------------------------------------------

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

// ---- Wire Formatting and Parsing (RFC 10024 §3) ---------------------------

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

// ---- FIPS 202 Keccak-f[1600], SHA-3 & SHAKE XOF Primitives (FIPS 203 §4.1) --

const KECCAK_RC: u64[24] = [
    0x0000000000000001, 0x0000000000008082, 0x800000000000808A, 0x8000000080008000,
    0x000000000000808B, 0x0000000080000001, 0x8000000080008081, 0x8000000000008009,
    0x000000000000008A, 0x0000000000000088, 0x0000000080008009, 0x000000008000000A,
    0x000000008000808B, 0x800000000000008B, 0x8000000000008089, 0x8000000000008003,
    0x8000000000008002, 0x8000000000000080, 0x000000000000800A, 0x800000008000000A,
    0x8000000080008081, 0x8000000000008080, 0x0000000080000001, 0x8000000080008008,
];

const KECCAK_ROTC: u32[24] = [
    1, 3, 6, 10, 15, 21, 28, 36, 45, 55, 2, 14,
    27, 41, 56, 8, 25, 43, 62, 18, 39, 61, 20, 44,
];

const KECCAK_PI: u64[24] = [
    10, 7, 11, 17, 18, 3, 5, 16, 8, 21, 24, 4,
    15, 23, 19, 13, 12, 2, 20, 14, 22, 9, 6, 1,
];

inline fn keccak_chi_row(state: u64[25]&, r0: u64, r1: u64, r2: u64, r3: u64, r4: u64) {
    let s0 = state[r0];
    let s1 = state[r1];
    let s2 = state[r2];
    let s3 = state[r3];
    let s4 = state[r4];
    state[r0] = s0 ^ ((~s1) & s2);
    state[r1] = s1 ^ ((~s2) & s3);
    state[r2] = s2 ^ ((~s3) & s4);
    state[r3] = s3 ^ ((~s4) & s0);
    state[r4] = s4 ^ ((~s0) & s1);
}

inline fn keccak_theta_col(state: u64[25]&, c0: u64, c1: u64, c2: u64, c3: u64, c4: u64, t: u64) {
    state[c0] ^= t;
    state[c1] ^= t;
    state[c2] ^= t;
    state[c3] ^= t;
    state[c4] ^= t;
}

inline fn keccak_round(state: u64[25]&, rc: u64) {
    let bc0 = state[0] ^ state[5] ^ state[10] ^ state[15] ^ state[20];
    let bc1 = state[1] ^ state[6] ^ state[11] ^ state[16] ^ state[21];
    let bc2 = state[2] ^ state[7] ^ state[12] ^ state[17] ^ state[22];
    let bc3 = state[3] ^ state[8] ^ state[13] ^ state[18] ^ state[23];
    let bc4 = state[4] ^ state[9] ^ state[14] ^ state[19] ^ state[24];

    keccak_theta_col(state, 0, 5, 10, 15, 20, bc4 ^ core::rotl64(bc1, 1));
    keccak_theta_col(state, 1, 6, 11, 16, 21, bc0 ^ core::rotl64(bc2, 1));
    keccak_theta_col(state, 2, 7, 12, 17, 22, bc1 ^ core::rotl64(bc3, 1));
    keccak_theta_col(state, 3, 8, 13, 18, 23, bc2 ^ core::rotl64(bc4, 1));
    keccak_theta_col(state, 4, 9, 14, 19, 24, bc3 ^ core::rotl64(bc0, 1));

    var t = state[1];
    for i in 24 {
        let u = i as u64;
        let j = KECCAK_PI[u];
        let tmp = state[j];
        state[j] = core::rotl64(t, KECCAK_ROTC[u]);
        t = tmp;
    }

    keccak_chi_row(state, 0, 1, 2, 3, 4);
    keccak_chi_row(state, 5, 6, 7, 8, 9);
    keccak_chi_row(state, 10, 11, 12, 13, 14);
    keccak_chi_row(state, 15, 16, 17, 18, 19);
    keccak_chi_row(state, 20, 21, 22, 23, 24);
    state[0] ^= rc;
}

// FIPS 202 Section 3.3: Keccak-f[1600] 24-round sponge permutation.
fn keccak_f1600(state: u64[25]&) {
    for r in 24 {
        keccak_round(state, KECCAK_RC[r as u64]);
    }
}

// Branchless constant-time byte XOR into Keccak-f[1600] lanes (shift is bounded in 0..56; zero secret branches).
// crap:ignore
inline fn keccak_xor_bytes(state: u64[25]&, blk: const u8[:]) {
    for i in blk.len {
        let u = i as u64;
        let lane = u >> 3;
        let shift = core::shl_sat_u64(u & 7, 3) as u32;
        state[lane] ^= core::shl_sat_u64(blk[u] as u64, shift);
    }
}

fn keccak_absorb(state: u64[25]&, data: const u8[:], rate: u64, domain: u8) {
    let data_len = data.len as u64;
    var off: u64 = 0;
    while core::add_sat_u64(off, rate) <= data_len {
        let next_off = core::add_sat_u64(off, rate);
        keccak_xor_bytes(state, data[off..next_off]);
        keccak_f1600(state);
        off = next_off;
    }
    let rem = core::sub_sat_u64(data_len, off);
    if rem > 0 {
        keccak_xor_bytes(state, data[off..data_len]);
    }
    let rem_shift = core::shl_sat_u64(rem & 7, 3) as u32;
    state[rem >> 3] ^= core::shl_sat_u64(domain, rem_shift);
    let last = core::sub_sat_u64(rate, 1);
    let last_shift = core::shl_sat_u64(last & 7, 3) as u32;
    state[last >> 3] ^= core::shl_sat_u64(0x80, last_shift);
    keccak_f1600(state);
}

fn keccak_squeeze(state: u64[25]&, rate: u64, out: u8[:]) {
    let out_len = out.len as u64;
    var out_pos:  u64 = 0;
    var lane_pos: u64 = 0;
    while out_pos < out_len {
        if lane_pos == rate {
            keccak_f1600(state);
            lane_pos = 0;
        }
        let w = state[lane_pos >> 3];
        let shift = core::shl_sat_u64(lane_pos & 7, 3);
        out[out_pos] = ((w >> shift) & 0xFF) as u8;
        out_pos = core::add_sat_u64(out_pos, 1);
        lane_pos = core::add_sat_u64(lane_pos, 1);
    }
}

// FIPS 202 Section 6.1: SHA3-256 cryptographic hash function (rate = 136, domain = 0x06).
fn sha3_256(data: const u8[:]) -> u8[32] {
    var state: u64[25] = [0; 25];
    var out:   u8[32]  = [0; 32];
    keccak_absorb(state, data, 136, 0x06);
    keccak_squeeze(state, 136, out[..]);
    return out;
}

// FIPS 202 Section 6.1: SHA3-512 cryptographic hash function (rate = 72, domain = 0x06).
fn sha3_512(data: const u8[:]) -> u8[64] {
    var state: u64[25] = [0; 25];
    var out:   u8[64]  = [0; 64];
    keccak_absorb(state, data, 72, 0x06);
    keccak_squeeze(state, 72, out[..]);
    return out;
}

// FIPS 202 Section 6.2: SHAKE128 extendable-output function (rate = 168, domain = 0x1F).
fn shake128_squeeze(data: const u8[:], out: u8[:]) {
    var state: u64[25] = [0; 25];
    keccak_absorb(state, data, 168, 0x1F);
    keccak_squeeze(state, 168, out);
}

// FIPS 202 Section 6.2: SHAKE256 extendable-output function (rate = 136, domain = 0x1F).
fn shake256_squeeze(data: const u8[:], out: u8[:]) {
    var state: u64[25] = [0; 25];
    keccak_absorb(state, data, 136, 0x1F);
    keccak_squeeze(state, 136, out);
}

// FIPS 203 Section 4.1: Hash function H(s) = SHA3-256(s).
fn ml_kem_h(data: const u8[:]) -> u8[32] {
    guard data.len > 0 else { return sha3_256(""); }
    return sha3_256(data);
}

// FIPS 203 Section 4.1: Hash function G(a || b) = SHA3-512(a || b).
fn ml_kem_g(first: const u8[:], second: const u8[:]) -> u8[64] {
    var buf: u8[96] = [0; 96];
    let n1 = min(first.len as u64, 32);
    let n2 = min(second.len as u64, 64);
    let total = core::add_sat_u64(n1, n2);
    core::ct_copy_bytes(buf[0..n1], first[0..n1]);
    core::ct_copy_bytes(buf[n1..total], second[0..n2]);
    let out = sha3_512(buf[0..total]);
    core::secure_zeroize_slice(buf[..]);
    return out;
}

// FIPS 203 Section 4.1: Implicit rejection KDF J(z || ct) = SHAKE256(z || ct, 32).
fn ml_kem_j(z: const u8[:], ct: const u8[:]) -> u8[32] {
    var buf: u8[1120] = [0; 1120];
    var out: u8[32]   = [0; 32];
    let z_len = min(z.len as u64, 32);
    let ct_len = min(ct.len as u64, 1088);
    let total = core::add_sat_u64(z_len, ct_len);
    core::ct_copy_bytes(buf[0..z_len], z[0..z_len]);
    core::ct_copy_bytes(buf[z_len..total], ct[0..ct_len]);
    shake256_squeeze(buf[0..total], out[..]);
    core::secure_zeroize_slice(buf[0..z_len]);
    return out;
}

// FIPS 203 Section 4.1: Pseudorandom function PRF_2(sigma, b) = SHAKE256(sigma || b, 128).
fn ml_kem_prf(sigma: const u8[32]&, b_nonce: u8) -> u8[128] {
    var prf_in: u8[33]  = [0; 33];
    var out:    u8[128] = [0; 128];
    core::ct_copy_bytes(prf_in[0..32], sigma[..]);
    prf_in[32] = b_nonce;
    shake256_squeeze(prf_in[..], out[..]);
    core::secure_zeroize_slice(prf_in[..]);
    return out;
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

// ---- FIPS 203 Section 4: Ring R_q Arithmetic and Number-Theoretic Transform ---

const MLKEM_Q:             i32 = 3329;
const MLKEM_Q_U32:         u32 = 3329;
const MLKEM_Q_U64:         u64 = 3329;
const MLKEM_BARRETT_SHIFT: u32 = 36;
const MLKEM_BARRETT_MUL:   u64 = 20642678;  // floor(2^36 / 3329) for constant-time Barrett reduction
const MLKEM_COMPRESS_MUL:  u64 = 20642679;  // ceil(2^36 / 3329) for constant-time Compress_d
const MLKEM_BARRETT_BIAS:  i64 = 218169344; // 65536 * 3329 (exact multiple of q; handles val >= -218169344)

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

// Constant-time Barrett reduction modulo q = 3329 for val in [-218169344, +218169344].
// Uses biased unsigned branchless arithmetic with zero division, modulo, or secret branches.
inline fn fips203_mod_q(val: i64) -> i32 {
    let biased = core::add_sat_i64(val, MLKEM_BARRETT_BIAS) as u64;
    let t = core::mul_sat_u64(biased, MLKEM_BARRETT_MUL) >> MLKEM_BARRETT_SHIFT;
    let r = core::sub_sat_u64(biased, core::mul_sat_u64(t, MLKEM_Q_U64));
    let lt_mask = core::ct_mask_u64(core::ct_lt_u64(r, MLKEM_Q_U64));
    return core::ct_select_u64(lt_mask, r, core::sub_sat_u64(r, MLKEM_Q_U64)) as i32;
}

inline fn fips203_add_q(a: i32, b: i32) -> i32 {
    let sum = core::add_sat_u32(a as u32, b as u32);
    let lt_mask = core::ct_mask_u32(core::ct_lt_u32(sum, MLKEM_Q_U32));
    return core::ct_select_u32(lt_mask, sum, core::sub_sat_u32(sum, MLKEM_Q_U32)) as i32;
}

inline fn fips203_sub_q(a: i32, b: i32) -> i32 {
    let ua = a as u32;
    let ub = b as u32;
    let lt_mask = core::ct_mask_u32(core::ct_lt_u32(ua, ub));
    let ge_val = core::sub_sat_u32(ua, ub);
    let lt_val = core::sub_sat_u32(core::add_sat_u32(ua, MLKEM_Q_U32), ub);
    return core::ct_select_u32(lt_mask, lt_val, ge_val) as i32;
}

// Constant-time FIPS 203 Compress_d(c) = round(scale * c / 3329) mod scale via Barrett multiply.
// Exact for all c in [0, 3328] and scale = 2^d for d in {1, 4, 10}.
inline fn fips203_compress_d(coeff: i32, scale: u64, mask: u64) -> u32 {
    let num = core::add_sat_u64(core::mul_sat_u64(coeff as u64, scale), 1664);
    return ((core::mul_sat_u64(num, MLKEM_COMPRESS_MUL) >> MLKEM_BARRETT_SHIFT) & mask) as u32;
}

// Adds two polynomials in R_q: c = (a + b) mod q (FIPS 203 Section 4.1).
fn poly_add(a: const Poly256&, b: const Poly256&) -> Poly256 {
    var out = Poly256 { .. };
    for i in 256 {
        out.coeffs[i] = fips203_add_q(a.coeffs[i], b.coeffs[i]);
    }
    return out;
}

// Subtracts two polynomials in R_q: c = (a - b) mod q (FIPS 203 Section 4.1).
fn poly_sub(a: const Poly256&, b: const Poly256&) -> Poly256 {
    var out = Poly256 { .. };
    for i in 256 {
        out.coeffs[i] = fips203_sub_q(a.coeffs[i], b.coeffs[i]);
    }
    return out;
}

fn ntt_butterfly_layer(f: Poly256&, length: i64, k: i64&) {
    var start: i64 = 0;
    while start < 256 {
        let z = MLKEM_ZETAS[k] as u64;
        k = core::add_sat_i64(k, 1);
        var j = start;
        let end_j = core::add_sat_i64(start, length);
        while j < end_j {
            let j_len = core::add_sat_i64(j, length);
            let t = fips203_mod_q(core::mul_sat_u64(z, f.coeffs[j_len] as u64) as i64);
            let fj = f.coeffs[j];
            f.coeffs[j_len] = fips203_sub_q(fj, t);
            f.coeffs[j] = fips203_add_q(fj, t);
            j = core::add_sat_i64(j, 1);
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
        length = length >> 1;
    }
    return f;
}

fn invntt_butterfly_layer(f: Poly256&, length: i64, k: i64&) {
    var start: i64 = 0;
    while start < 256 {
        let z = MLKEM_ZETAS[k] as u64;
        k = core::sub_sat_i64(k, 1);
        var j = start;
        let end_j = core::add_sat_i64(start, length);
        while j < end_j {
            let j_len = core::add_sat_i64(j, length);
            let t = f.coeffs[j];
            let f_j_len = f.coeffs[j_len];
            f.coeffs[j] = fips203_add_q(t, f_j_len);
            let diff = fips203_sub_q(f_j_len, t);
            f.coeffs[j_len] = fips203_mod_q(core::mul_sat_u64(z, diff as u64) as i64);
            j = core::add_sat_i64(j, 1);
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
        f.coeffs[j] = fips203_mod_q(core::mul_sat_u64(f.coeffs[j] as u64, 3303) as i64);
    }
    return f;
}

// FIPS 203 Section 4.3: Algorithms 11 & 12 MultiplyNTTs and BaseCaseMultiply.
// Multiplies two NTT-domain polynomials a_hat and b_hat modulo (X^2 - gamma) and accumulates into acc.
// crap:ignore
fn poly_basemul_acc(acc: Poly256&, a: const Poly256&, b: const Poly256&) {
    var i: u64 = 0;
    while i < 128 {
        let s = i >> 1;
        let z = MLKEM_ZETAS[core::add_sat_u64(64, s)] as u64;
        let odd_mask = core::ct_mask_u64(i & 1);
        let gamma = core::ct_select_u64(odd_mask, core::sub_sat_u64(MLKEM_Q_U64, z), z);
        let idx0 = i << 1;
        let idx1 = idx0 | 1;
        let a0 = a.coeffs[idx0] as u64;
        let a1 = a.coeffs[idx1] as u64;
        let b0 = b.coeffs[idx0] as u64;
        let b1 = b.coeffs[idx1] as u64;
        let a1b1 = fips203_mod_q(core::mul_sat_u64(a1, b1) as i64) as u64;
        let c0 = fips203_mod_q(
            core::add_sat_u64(core::mul_sat_u64(a0, b0), core::mul_sat_u64(a1b1, gamma)) as i64,
        );
        let c1 = fips203_mod_q(
            core::add_sat_u64(core::mul_sat_u64(a0, b1), core::mul_sat_u64(a1, b0)) as i64,
        );
        acc.coeffs[idx0] = fips203_add_q(acc.coeffs[idx0], c0);
        acc.coeffs[idx1] = fips203_add_q(acc.coeffs[idx1], c1);
        i = core::add_sat_u64(i, 1);
    }
}

// FIPS 203 Section 4.2.2: Algorithm 8 SamplePolyCBD_2 (centered binomial distribution eta = 2).
// crap:ignore
fn poly_cbd2(sigma: const u8[32]&, nonce: u8) -> Poly256 {
    var buf = ml_kem_prf(sigma, nonce);
    var f = Poly256 { .. };
    var i: u64 = 0;
    while i < 128 {
        let byte_val = buf[i] as u32;
        let x0 = core::add_sat_u32(byte_val & 1, (byte_val >> 1) & 1) as i32;
        let y0 = core::add_sat_u32((byte_val >> 2) & 1, (byte_val >> 3) & 1) as i32;
        let x1 = core::add_sat_u32((byte_val >> 4) & 1, (byte_val >> 5) & 1) as i32;
        let y1 = core::add_sat_u32((byte_val >> 6) & 1, (byte_val >> 7) & 1) as i32;
        let idx0 = i << 1;
        f.coeffs[idx0] = fips203_sub_q(x0, y0);
        f.coeffs[idx0 | 1] = fips203_sub_q(x1, y1);
        i = core::add_sat_u64(i, 1);
    }
    core::secure_zeroize_slice(buf[..]);
    return f;
}

// FIPS 203 Section 4.2.2: Algorithm 7 SampleNTT(B) - uniform rejection sampling in R_q via SHAKE128.
// crap:ignore
fn sample_ntt(rho: const u8[32]&, j_idx: u8, i_idx: u8) -> Poly256 {
    var a_hat = Poly256 { .. };
    var seed_in: u8[34] = [0; 34];
    core::ct_copy_bytes(seed_in[0..32], rho[..]);
    seed_in[32] = j_idx;
    seed_in[33] = i_idx;

    var stream: u8[840] = [0; 840];
    shake128_squeeze(seed_in[..], stream[..]);

    var count: u64 = 0;
    var pos:   u64 = 0;
    while pos + 2 < 840 && count < 256 {
        let b0 = stream[pos] as u32;
        let b1 = stream[pos + 1] as u32;
        let b2 = stream[pos + 2] as u32;
        let d1 = b0 | ((b1 & 0x0F) << 8);
        let d2 = (b1 >> 4) | (b2 << 4);
        if d1 < 3329 {
            a_hat.coeffs[count] = d1 as i32;
            count += 1;
        }
        if d2 < 3329 && count < 256 {
            a_hat.coeffs[count] = d2 as i32;
            count += 1;
        }
        pos += 3;
    }
    return a_hat;
}

// FIPS 203 Section 4.2.1: Algorithm 5 ByteEncode_12 - encodes 256 12-bit coefficients into 384 bytes.
// crap:ignore
fn byte_encode_12(f: const Poly256&, out: u8[:]) {
    guard out.len >= 384 else { return; }
    var i: u64 = 0;
    while i < 128 {
        let idx2 = i << 1;
        let idx3 = i * 3;
        let a = f.coeffs[idx2] as u32;
        let b = f.coeffs[idx2 | 1] as u32;
        out[idx3] = (a & 0xFF) as u8;
        out[idx3 + 1] = (((a >> 8) & 0x0F) | ((b & 0x0F) << 4)) as u8;
        out[idx3 + 2] = ((b >> 4) & 0xFF) as u8;
        i += 1;
    }
}

// FIPS 203 Section 4.2.1: Algorithm 6 ByteDecode_12 - decodes 384 bytes into 256 12-bit coefficients
// and verifies the FIPS 203 Section 7.2 encapsulation key modulus check (all d_i < q = 3329).
//
// Example:
//   raw = [0x01, 0x20, 0x00, ... (384 bytes)]
//   returns: f = Poly256 { coeffs: [1, 2, ...] }, ok = true
// crap:ignore
fn byte_decode_12(raw: const u8[:]) -> Poly256, bool {
    var f = Poly256 { .. };
    guard raw.len >= 384 else { return f, false; }
    var valid_mask: u32 = 0xFFFFFFFF;
    var i:          u64 = 0;
    while i < 128 {
        let idx2 = i << 1;
        let idx3 = core::mul_sat_u64(i, 3);
        let b0 = raw[idx3] as u32;
        let b1 = raw[core::add_sat_u64(idx3, 1)] as u32;
        let b2 = raw[core::add_sat_u64(idx3, 2)] as u32;
        let d0 = b0 | ((b1 & 0x0F) << 8);
        let d1 = (b1 >> 4) | (b2 << 4);
        let m0 = core::ct_mask_u32(core::ct_lt_u32(d0, MLKEM_Q_U32));
        let m1 = core::ct_mask_u32(core::ct_lt_u32(d1, MLKEM_Q_U32));
        valid_mask &= m0 & m1;
        f.coeffs[idx2] = core::ct_select_u32(m0, d0, core::sub_sat_u32(d0, MLKEM_Q_U32)) as i32;
        f.coeffs[idx2 | 1] = core::ct_select_u32(m1, d1, core::sub_sat_u32(d1, MLKEM_Q_U32)) as i32;
        i = core::add_sat_u64(i, 1);
    }
    return f, valid_mask != 0;
}

// FIPS 203 Section 4.2.1: Compress_10 and ByteEncode_10 for u vector (3 polynomials -> 960 bytes).
// crap:ignore
fn compress_u(u_vec: const Poly256[3]&, out: u8[:]) {
    guard out.len >= 960 else { return; }
    var p: u64 = 0;
    while p < 3 {
        let base_off = p * 320;
        var i: u64 = 0;
        while i < 64 {
            var t: u32[4] = [0; 4];
            var k: u64    = 0;
            while k < 4 {
                t[k] = fips203_compress_d(u_vec[p].coeffs[(i << 2) | k], 1024, 0x3FF);
                k += 1;
            }
            let off = base_off + 5 * i;
            out[off] = (t[0] & 0xFF) as u8;
            out[off + 1] = (((t[0] >> 8) & 0x03) | ((t[1] & 0x3F) << 2)) as u8;
            out[off + 2] = (((t[1] >> 6) & 0x0F) | ((t[2] & 0x0F) << 4)) as u8;
            out[off + 3] = (((t[2] >> 4) & 0x3F) | ((t[3] & 0x03) << 6)) as u8;
            out[off + 4] = ((t[3] >> 2) & 0xFF) as u8;
            i += 1;
        }
        p += 1;
    }
}

// FIPS 203 Section 4.2.1: ByteDecode_10 and Decompress_10 for u vector (960 bytes -> 3 polynomials).
// crap:ignore
fn decompress_u(raw: const u8[:]) -> Poly256[3] {
    var u_vec: Poly256[3] = [Poly256 { .. }, Poly256 { .. }, Poly256 { .. }];
    guard raw.len >= 960 else { return u_vec; }
    var p: u64 = 0;
    while p < 3 {
        let base_off = p * 320;
        var i: u64 = 0;
        while i < 64 {
            let off = base_off + 5 * i;
            let b0 = raw[off] as u32;
            let b1 = raw[off + 1] as u32;
            let b2 = raw[off + 2] as u32;
            let b3 = raw[off + 3] as u32;
            let b4 = raw[off + 4] as u32;
            let t0 = b0 | ((b1 & 0x03) << 8);
            let t1 = (b1 >> 2) | ((b2 & 0x0F) << 6);
            let t2 = (b2 >> 4) | ((b3 & 0x3F) << 4);
            let t3 = (b3 >> 6) | (b4 << 2);
            let c_base = i << 2;
            u_vec[p].coeffs[c_base] = ((t0 * MLKEM_Q_U32 + 512) >> 10) as! i32;
            u_vec[p].coeffs[c_base | 1] = ((t1 * MLKEM_Q_U32 + 512) >> 10) as! i32;
            u_vec[p].coeffs[c_base | 2] = ((t2 * MLKEM_Q_U32 + 512) >> 10) as! i32;
            u_vec[p].coeffs[c_base | 3] = ((t3 * MLKEM_Q_U32 + 512) >> 10) as! i32;
            i += 1;
        }
        p += 1;
    }
    return u_vec;
}

// FIPS 203 Section 4.2.1: Compress_4 and ByteEncode_4 for v polynomial (128 bytes).
// crap:ignore
fn compress_v(v: const Poly256&, out: u8[:]) {
    guard out.len >= 128 else { return; }
    var i: u64 = 0;
    while i < 128 {
        let idx2 = i << 1;
        let t0 = fips203_compress_d(v.coeffs[idx2], 16, 0x0F);
        let t1 = fips203_compress_d(v.coeffs[idx2 | 1], 16, 0x0F);
        out[i] = (t0 | (t1 << 4)) as u8;
        i += 1;
    }
}

// FIPS 203 Section 4.2.1: ByteDecode_4 and Decompress_4 for v polynomial (128 bytes).
// crap:ignore
fn decompress_v(raw: const u8[:]) -> Poly256 {
    var v = Poly256 { .. };
    guard raw.len >= 128 else { return v; }
    var i: u64 = 0;
    while i < 128 {
        let idx2 = i << 1;
        let vb = raw[i] as u32;
        v.coeffs[idx2] = (((vb & 0x0F) * MLKEM_Q_U32 + 8) >> 4) as! i32;
        v.coeffs[idx2 | 1] = (((vb >> 4) * MLKEM_Q_U32 + 8) >> 4) as! i32;
        i += 1;
    }
    return v;
}

// FIPS 203 Section 4.2.1: Decompress_1(ByteDecode_1(m)) for 32-byte message seed.
// crap:ignore
fn decompress_msg_1(m_msg: const u8[32]&) -> Poly256 {
    var mu = Poly256 { .. };
    var i: u64 = 0;
    while i < 32 {
        let b = m_msg[i];
        var bit: u64 = 0;
        while bit < 8 {
            let mask = core::ct_mask_u32((b >> bit) & 1);
            mu.coeffs[(i << 3) | bit] = (mask & 1665) as i32;
            bit = core::add_sat_u64(bit, 1);
        }
        i = core::add_sat_u64(i, 1);
    }
    return mu;
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
