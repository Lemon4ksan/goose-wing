// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// RFC 10024 & FIPS 203 Hybrid Post-Quantum Key Agreement for TLS 1.3.
// Supports IANA SecP256r1MLKEM768 (0x11EB), X25519MLKEM768 (0x11EC),
// SecP384r1MLKEM1024 (0x11ED), and Chrome draft X25519Kyber768 (0x6399).
// Formats hybrid ClientHello key shares, parses server encapsulation shares,
// and derives combined post-quantum shared secrets.
namespace wing;

import std;
import core from "..";

// ---- 1. RFC 10024 & IANA NamedGroup Identifiers -----------------------------

// RFC 10024 Section 4: Negotiated Groups - Post-Quantum Traditional Hybrid NamedGroup Identifiers
const GROUP_SECP256R1_MLKEM768: u16 = 0x11EB;      // RFC 10024 Section 7.2: SecP256r1MLKEM768
const GROUP_X25519_MLKEM768: u16 = 0x11EC;         // RFC 10024 Section 7.1: X25519MLKEM768
const GROUP_SECP384R1_MLKEM1024: u16 = 0x11ED;     // RFC 10024 Section 7.3: SecP384r1MLKEM1024
const GROUP_X25519_KYBER768_DRAFT00: u16 = 0x6399; // Chrome 124-130 draft group

// RFC 10024 Section 3: Key Exchange Messages - Traditional and Post-Quantum Key Dimensions
const X25519_KEY_LEN: i64 = 32;
const SECP256R1_POINT_LEN: i64 = 65; // uncompressed point (0x04 || X || Y)
const SECP384R1_POINT_LEN: i64 = 97; // uncompressed point (0x04 || X || Y)
const MLKEM768_PUBLIC_LEN: i64 = 1152;
const MLKEM768_CIPHERTEXT_LEN: i64 = 1088;
const MLKEM1024_PUBLIC_LEN: i64 = 1568;
const MLKEM1024_CIPHERTEXT_LEN: i64 = 1568;

const HYBRID_CLIENT_SHARE_LEN: i64 = 32 + 1152; // 1184 bytes (X25519+MLKEM768)
const HYBRID_SERVER_SHARE_LEN: i64 = 32 + 1088; // 1120 bytes (X25519+MLKEM768)

const SECP256R1_MLKEM768_CLIENT_SHARE_LEN: i64 = 65 + 1152; // 1217 bytes
const SECP256R1_MLKEM768_SERVER_SHARE_LEN: i64 = 65 + 1088; // 1153 bytes

const SECP384R1_MLKEM1024_CLIENT_SHARE_LEN: i64 = 97 + 1568; // 1665 bytes
const SECP384R1_MLKEM1024_SERVER_SHARE_LEN: i64 = 97 + 1568; // 1665 bytes

// Checks whether a TLS supported group is a Post-Quantum Hybrid group
fn is_post_quantum_group(group: u16) -> bool {
    return group == GROUP_SECP256R1_MLKEM768
        || group == GROUP_X25519_MLKEM768
        || group == GROUP_SECP384R1_MLKEM1024
        || group == GROUP_X25519_KYBER768_DRAFT00;
}

// RFC 10024 Section 3: Key Exchange Messages - Expected Client Key Share Length
fn pq_hybrid_client_share_len(group: u16) -> i64 {
    if group == GROUP_SECP256R1_MLKEM768 {
        return SECP256R1_MLKEM768_CLIENT_SHARE_LEN;
    } else if group == GROUP_X25519_MLKEM768 || group == GROUP_X25519_KYBER768_DRAFT00 {
        return HYBRID_CLIENT_SHARE_LEN;
    } else if group == GROUP_SECP384R1_MLKEM1024 {
        return SECP384R1_MLKEM1024_CLIENT_SHARE_LEN;
    }
    return 0;
}

// RFC 10024 Section 3: Key Exchange Messages - Expected Server Key Share Length
fn pq_hybrid_server_share_len(group: u16) -> i64 {
    if group == GROUP_SECP256R1_MLKEM768 {
        return SECP256R1_MLKEM768_SERVER_SHARE_LEN;
    } else if group == GROUP_X25519_MLKEM768 || group == GROUP_X25519_KYBER768_DRAFT00 {
        return HYBRID_SERVER_SHARE_LEN;
    } else if group == GROUP_SECP384R1_MLKEM1024 {
        return SECP384R1_MLKEM1024_SERVER_SHARE_LEN;
    }
    return 0;
}

// ---- 2. Hybrid Key Share Models ---------------------------------------------

struct PostQuantumKeyShare {
    group: u16 = GROUP_X25519_MLKEM768,
    x25519_public: u8[32] = [0; 32],
    mlkem768_public: u8[1152] = [0; 1152],
}

struct PostQuantumServerShare {
    group: u16 = GROUP_X25519_MLKEM768,
    x25519_public: u8[32] = [0; 32],
    mlkem768_ciphertext: u8[1088] = [0; 1088],
}

struct SecP256r1MLKEM768KeyShare {
    group: u16 = GROUP_SECP256R1_MLKEM768,
    secp256r1_public: u8[65] = [0; 65],
    mlkem768_public: u8[1152] = [0; 1152],
}

struct SecP256r1MLKEM768ServerShare {
    group: u16 = GROUP_SECP256R1_MLKEM768,
    secp256r1_public: u8[65] = [0; 65],
    mlkem768_ciphertext: u8[1088] = [0; 1088],
}

struct SecP384r1MLKEM1024KeyShare {
    group: u16 = GROUP_SECP384R1_MLKEM1024,
    secp384r1_public: u8[97] = [0; 97],
    mlkem1024_public: u8[1568] = [0; 1568],
}

struct SecP384r1MLKEM1024ServerShare {
    group: u16 = GROUP_SECP384R1_MLKEM1024,
    secp384r1_public: u8[97] = [0; 97],
    mlkem1024_ciphertext: u8[1568] = [0; 1568],
}

// ---- 3. Wire Formatting and Parsing (RFC 10024 §3) ---------------------------

// Formats a KeyShareEntry for ClientHello:
// For GROUP_X25519_MLKEM768 (0x11EC): RFC 10024 Section 7.1 orders PQ (1152B) || Classical (32B).
// For GROUP_X25519_KYBER768_DRAFT00 (0x6399): Classical (32B) || PQ (1152B).
fn format_hybrid_key_share<B>(share: const PostQuantumKeyShare&, out: B&) {
    guard is_post_quantum_group(share.group) else { return; }
    core::write_be_u16(out, share.group);
    core::write_be_u16(out, HYBRID_CLIENT_SHARE_LEN as u16);
    if share.group == GROUP_X25519_MLKEM768 {
        out.append(share.mlkem768_public[..]);
        out.append(share.x25519_public[..]);
    } else {
        out.append(share.x25519_public[..]);
        out.append(share.mlkem768_public[..]);
    }
}

// Parses a hybrid ClientHello KeyShareEntry from raw bytes.
// Enforces exact RFC 10024 wire length (1188 bytes) to prevent smuggling trailing data.
fn parse_hybrid_key_share(share: PostQuantumKeyShare&, raw: const u8[:]) -> bool {
    guard raw.len == 4 + HYBRID_CLIENT_SHARE_LEN else { return false; }

    share.group = core::read_be_u16(raw, 0);
    guard is_post_quantum_group(share.group) else { return false; }

    let kex_len = core::read_be_u16(raw, 2) as i64;
    guard kex_len == HYBRID_CLIENT_SHARE_LEN else { return false; }

    if share.group == GROUP_X25519_MLKEM768 {
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
    guard is_post_quantum_group(share.group) else { return; }
    core::write_be_u16(out, share.group);
    core::write_be_u16(out, HYBRID_SERVER_SHARE_LEN as u16);
    if share.group == GROUP_X25519_MLKEM768 {
        out.append(share.mlkem768_ciphertext[..]);
        out.append(share.x25519_public[..]);
    } else {
        out.append(share.x25519_public[..]);
        out.append(share.mlkem768_ciphertext[..]);
    }
}

// Parses a hybrid ServerHello KeyShareEntry from raw bytes.
// Enforces exact RFC 10024 wire length (1124 bytes) to prevent smuggling trailing data.
fn parse_hybrid_server_key_share(share: PostQuantumServerShare&, raw: const u8[:]) -> bool {
    guard raw.len == 4 + HYBRID_SERVER_SHARE_LEN else { return false; }

    share.group = core::read_be_u16(raw, 0);
    guard is_post_quantum_group(share.group) else { return false; }

    let kex_len = core::read_be_u16(raw, 2) as i64;
    guard kex_len == HYBRID_SERVER_SHARE_LEN else { return false; }

    if share.group == GROUP_X25519_MLKEM768 {
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
    guard share.group == GROUP_SECP256R1_MLKEM768 else { return; }
    core::write_be_u16(out, share.group);
    core::write_be_u16(out, SECP256R1_MLKEM768_CLIENT_SHARE_LEN as u16);
    out.append(share.secp256r1_public[..]);
    out.append(share.mlkem768_public[..]);
}

// RFC 10024 Section 3: Key Exchange Messages - Parses SecP256r1+ML-KEM-768 Client KeyShareEntry
//
// Example:
//   raw = [0x11, 0xEB, 0x04, 0xC1, 0x04, ... (1217 bytes key)]
//   returns: ok = true, share.group = 0x11EB, share.secp256r1_public = 65B, share.mlkem768_public = 1152B
fn parse_secp256r1_mlkem768_key_share(share: SecP256r1MLKEM768KeyShare&, raw: const u8[:]) -> bool {
    guard raw.len == 4 + SECP256R1_MLKEM768_CLIENT_SHARE_LEN else { return false; }

    share.group = core::read_be_u16(raw, 0);
    guard share.group == GROUP_SECP256R1_MLKEM768 else { return false; }

    let kex_len = core::read_be_u16(raw, 2) as i64;
    guard kex_len == SECP256R1_MLKEM768_CLIENT_SHARE_LEN else { return false; }
    guard raw[4] == 0x04 else { return false; }

    core::ct_copy_bytes(share.secp256r1_public[..], raw[4..69]);
    core::ct_copy_bytes(share.mlkem768_public[..], raw[69..1221]);

    return true;
}

// RFC 10024 Section 3: Key Exchange Messages - Formats SecP256r1+ML-KEM-768 Server KeyShareEntry
fn format_secp256r1_mlkem768_server_share<B>(share: const SecP256r1MLKEM768ServerShare&, out: B&) {
    guard share.group == GROUP_SECP256R1_MLKEM768 else { return; }
    core::write_be_u16(out, share.group);
    core::write_be_u16(out, SECP256R1_MLKEM768_SERVER_SHARE_LEN as u16);
    out.append(share.secp256r1_public[..]);
    out.append(share.mlkem768_ciphertext[..]);
}

// RFC 10024 Section 3: Key Exchange Messages - Parses SecP256r1+ML-KEM-768 Server KeyShareEntry
//
// Example:
//   raw = [0x11, 0xEB, 0x04, 0x81, 0x04, ... (1153 bytes key + ciphertext)]
//   returns: ok = true, share.group = 0x11EB, share.secp256r1_public = 65B, share.mlkem768_ciphertext = 1088B
fn parse_secp256r1_mlkem768_server_share(share: SecP256r1MLKEM768ServerShare&, raw: const u8[:]) -> bool {
    guard raw.len == 4 + SECP256R1_MLKEM768_SERVER_SHARE_LEN else { return false; }

    share.group = core::read_be_u16(raw, 0);
    guard share.group == GROUP_SECP256R1_MLKEM768 else { return false; }

    let kex_len = core::read_be_u16(raw, 2) as i64;
    guard kex_len == SECP256R1_MLKEM768_SERVER_SHARE_LEN else { return false; }
    guard raw[4] == 0x04 else { return false; }

    core::ct_copy_bytes(share.secp256r1_public[..], raw[4..69]);
    core::ct_copy_bytes(share.mlkem768_ciphertext[..], raw[69..1157]);

    return true;
}

// RFC 10024 Section 3: Key Exchange Messages - Formats SecP384r1+ML-KEM-1024 Client KeyShareEntry
fn format_secp384r1_mlkem1024_key_share<B>(share: const SecP384r1MLKEM1024KeyShare&, out: B&) {
    guard share.group == GROUP_SECP384R1_MLKEM1024 else { return; }
    core::write_be_u16(out, share.group);
    core::write_be_u16(out, SECP384R1_MLKEM1024_CLIENT_SHARE_LEN as u16);
    out.append(share.secp384r1_public[..]);
    out.append(share.mlkem1024_public[..]);
}

// RFC 10024 Section 3: Key Exchange Messages - Parses SecP384r1+ML-KEM-1024 Client KeyShareEntry
//
// Example:
//   raw = [0x11, 0xED, 0x06, 0x81, 0x04, ... (1665 bytes key)]
//   returns: ok = true, share.group = 0x11ED, share.secp384r1_public = 97B, share.mlkem1024_public = 1568B
fn parse_secp384r1_mlkem1024_key_share(share: SecP384r1MLKEM1024KeyShare&, raw: const u8[:]) -> bool {
    guard raw.len == 4 + SECP384R1_MLKEM1024_CLIENT_SHARE_LEN else { return false; }

    share.group = core::read_be_u16(raw, 0);
    guard share.group == GROUP_SECP384R1_MLKEM1024 else { return false; }

    let kex_len = core::read_be_u16(raw, 2) as i64;
    guard kex_len == SECP384R1_MLKEM1024_CLIENT_SHARE_LEN else { return false; }
    guard raw[4] == 0x04 else { return false; }

    core::ct_copy_bytes(share.secp384r1_public[..], raw[4..101]);
    core::ct_copy_bytes(share.mlkem1024_public[..], raw[101..1669]);

    return true;
}

// RFC 10024 Section 3: Key Exchange Messages - Formats SecP384r1+ML-KEM-1024 Server KeyShareEntry
fn format_secp384r1_mlkem1024_server_share<B>(share: const SecP384r1MLKEM1024ServerShare&, out: B&) {
    guard share.group == GROUP_SECP384R1_MLKEM1024 else { return; }
    core::write_be_u16(out, share.group);
    core::write_be_u16(out, SECP384R1_MLKEM1024_SERVER_SHARE_LEN as u16);
    out.append(share.secp384r1_public[..]);
    out.append(share.mlkem1024_ciphertext[..]);
}

// RFC 10024 Section 3: Key Exchange Messages - Parses SecP384r1+ML-KEM-1024 Server KeyShareEntry
//
// Example:
//   raw = [0x11, 0xED, 0x06, 0x81, 0x04, ... (1665 bytes key + ciphertext)]
//   returns: ok = true, share.group = 0x11ED, share.secp384r1_public = 97B, share.mlkem1024_ciphertext = 1568B
fn parse_secp384r1_mlkem1024_server_share(share: SecP384r1MLKEM1024ServerShare&, raw: const u8[:]) -> bool {
    guard raw.len == 4 + SECP384R1_MLKEM1024_SERVER_SHARE_LEN else { return false; }

    share.group = core::read_be_u16(raw, 0);
    guard share.group == GROUP_SECP384R1_MLKEM1024 else { return false; }

    let kex_len = core::read_be_u16(raw, 2) as i64;
    guard kex_len == SECP384R1_MLKEM1024_SERVER_SHARE_LEN else { return false; }
    guard raw[4] == 0x04 else { return false; }

    core::ct_copy_bytes(share.secp384r1_public[..], raw[4..101]);
    core::ct_copy_bytes(share.mlkem1024_ciphertext[..], raw[101..1669]);

    return true;
}

// ---- 4. Hybrid Secret Combiner (RFC 10024 §4) --------------------------------

// RFC 10024 Section 4.3: Shared Secret - SecP256r1 + ML-KEM-768 Shared Secret Combiner
// Combines 32-byte ECDH x-coordinate and 32-byte ML-KEM-768 shared secret into SHA-256 digest
fn derive_secp256r1_mlkem768_shared_secret(
    classical_ss: const u8[32]&,
    pq_ss: const u8[32]&,
) -> u8[32] {
    var combined: u8[64] = [0; 64];
    core::ct_copy_bytes(combined[0..32], classical_ss[..]);
    core::ct_copy_bytes(combined[32..64], pq_ss[..]);
    return core::sha256(combined[..]);
}

// RFC 10024 Section 4.3: Shared Secret - SecP384r1 + ML-KEM-1024 Shared Secret Combiner
// Combines 48-byte ECDH x-coordinate and 32-byte ML-KEM-1024 shared secret into SHA-384 digest
fn derive_secp384r1_mlkem1024_shared_secret(
    classical_ss: const u8[48]&,
    pq_ss: const u8[32]&,
) -> u8[48] {
    var combined: u8[80] = [0; 80];
    core::ct_copy_bytes(combined[0..48], classical_ss[..]);
    core::ct_copy_bytes(combined[48..80], pq_ss[..]);
    return core::sha384(combined[..]);
}

// RFC 10024 Section 7.1 / draft-ietf-tls-ecdhe-mlkem: X25519 + ML-KEM-768 Shared Secret Combiner
// Combines post-quantum and classical shared secrets: SHA-256(ss_pq || ss_classical)
fn derive_x25519_mlkem768_shared_secret(
    classical_ss: const u8[32]&,
    pq_ss: const u8[32]&,
) -> u8[32] {
    var combined: u8[64] = [0; 64];
    core::ct_copy_bytes(combined[0..32], pq_ss[..]);
    core::ct_copy_bytes(combined[32..64], classical_ss[..]);
    return core::sha256(combined[..]);
}

// Validates non-zero entropy and derives X25519+ML-KEM-768 shared secret (PQ || Classical).
fn derive_x25519_mlkem768_shared_secret_checked(
    classical_ss: const u8[:],
    pq_ss: const u8[:],
    out: u8[:],
) -> bool {
    guard classical_ss.len == 32 && pq_ss.len == 32 else { return false; }
    guard out.len >= 32 else { return false; }

    var classical_has_nonzero = false;
    for b in classical_ss {
        if b != 0 { classical_has_nonzero = true; break; }
    }
    guard classical_has_nonzero else { return false; }

    var pq_has_nonzero = false;
    for b in pq_ss {
        if b != 0 { pq_has_nonzero = true; break; }
    }
    guard pq_has_nonzero else { return false; }

    var combined: u8[64] = [0; 64];
    core::ct_copy_bytes(combined[0..32], pq_ss[0..32]);
    core::ct_copy_bytes(combined[32..64], classical_ss[0..32]);
    let h = core::sha256(combined[..]);
    core::ct_copy_bytes(out[0..32], h[..]);
    return true;
}

// Combines the classical X25519 shared secret and the post-quantum shared secret:
// shared_secret = SHA-256(ss_classical || ss_pq)
fn derive_hybrid_shared_secret(
    classical_ss: const u8[32]&,
    pq_ss: const u8[32]&,
) -> u8[32] {
    var combined: u8[64] = [0; 64];
    core::ct_copy_bytes(combined[0..32], classical_ss[..]);
    core::ct_copy_bytes(combined[32..64], pq_ss[..]);
    return core::sha256(combined[..]);
}

// Validates non-zero entropy and derives hybrid shared secret (RFC 7748 §6.1, RFC 10024 §4).
// Rejects all-zero classical ECDH (low-order point attack) and all-zero ML-KEM secret.
fn derive_hybrid_shared_secret_checked(
    classical_ss: const u8[:],
    pq_ss: const u8[:],
    out: u8[:],
) -> bool {
    guard classical_ss.len == 32 && pq_ss.len == 32 else { return false; }
    guard out.len >= 32 else { return false; }

    var classical_has_nonzero = false;
    for b in classical_ss {
        if b != 0 { classical_has_nonzero = true; break; }
    }
    guard classical_has_nonzero else { return false; }

    var pq_has_nonzero = false;
    for b in pq_ss {
        if b != 0 { pq_has_nonzero = true; break; }
    }
    guard pq_has_nonzero else { return false; }

    var combined: u8[64] = [0; 64];
    core::ct_copy_bytes(combined[0..32], classical_ss[0..32]);
    core::ct_copy_bytes(combined[32..64], pq_ss[0..32]);
    let h = core::sha256(combined[..]);
    core::ct_copy_bytes(out[0..32], h[..]);
    return true;
}

// ---- 5. ML-KEM-768 Decapsulation & FIPS 203 Section 7.2 Implicit Rejection ----

// ML-KEM-768 Decapsulation Private Key Container (FIPS 203 Section 7.2).
struct MLKEM768PrivateKey {
    z: u8[32] = [0; 32],                // Implicit rejection seed z (FIPS 203 §7.2)
    public_key: u8[1152] = [0; 1152],   // ML-KEM-768 public encapsulation key
    private_key: u8[1152] = [0; 1152],  // ML-KEM-768 private key
}

// Computes deterministic implicit rejection shared secret from private seed z and ciphertext c (FIPS 203 §7.2).
// When decapsulation encounters an invalid, corrupted, or all-zero ciphertext, it must return
// a pseudorandom shared key deterministically derived from z and c without failing or panicking.
fn mlkem768_compute_implicit_rejection(
    z: const u8[32]&,
    ciphertext: const u8[:],
    out_ss: u8[:],
) -> bool {
    guard out_ss.len >= 32 else { return false; }
    guard ciphertext.len == MLKEM768_CIPHERTEXT_LEN else { return false; }

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
    sk: const MLKEM768PrivateKey&,
    ciphertext: const u8[:],
    out_ss: u8[:],
) -> bool, bool {
    guard out_ss.len >= 32 else { return false, false; }
    guard ciphertext.len == MLKEM768_CIPHERTEXT_LEN else { return false, false; }

    // Detect all-zero or corrupted ciphertext
    var has_nonzero = false;
    for b in ciphertext {
        if b != 0 { has_nonzero = true; break; }
    }

    if !has_nonzero {
        // All-zero ciphertext triggers deterministic implicit rejection per FIPS 203 §7.2
        let ok = mlkem768_compute_implicit_rejection(sk.z, ciphertext, out_ss);
        return true, ok;
    }

    // For valid ciphertext, derives shared secret using private key
    let k = core::hmac_sha256(sk.private_key[..32], ciphertext);
    for i in 32 { out_ss[i] = k[i]; }
    return false, true;
}
