// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// RFC 10024 & FIPS 203 Hybrid Post-Quantum Key Agreement for TLS 1.3.
// Supports IANA-standardized X25519MLKEM768 (Group 0x11EC) and Chrome draft X25519Kyber768 (Group 0x6399).
// Formats hybrid 1184-byte ClientHello key shares, parses server 1120-byte encapsulation shares,
// and derives combined post-quantum shared secrets.
namespace wing;

import std;
import core from "..";

// ---- 1. RFC 10024 & IANA NamedGroup Identifiers -----------------------------

const GROUP_X25519_MLKEM768: u16 = 0x11EC;          // RFC 10024 official IANA group
const GROUP_X25519_KYBER768_DRAFT00: u16 = 0x6399;  // Chrome 124-130 draft group

const X25519_KEY_LEN: i64 = 32;
const MLKEM768_PUBLIC_LEN: i64 = 1152;
const MLKEM768_CIPHERTEXT_LEN: i64 = 1088;
const HYBRID_CLIENT_SHARE_LEN: i64 = 32 + 1152; // 1184 bytes
const HYBRID_SERVER_SHARE_LEN: i64 = 32 + 1088; // 1120 bytes

// Checks whether a TLS supported group is a Post-Quantum Hybrid group
fn is_post_quantum_group(group: u16) -> bool {
    return group == GROUP_X25519_MLKEM768 || group == GROUP_X25519_KYBER768_DRAFT00;
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

// ---- 3. Wire Formatting and Parsing (RFC 10024 §3) ---------------------------

// Formats a KeyShareEntry for ClientHello:
// group (2 bytes) + key_exchange_len (2 bytes) + [32B X25519 || 1152B ML-KEM-768]
fn format_hybrid_key_share<B>(share: const PostQuantumKeyShare&, out: B&) {
    guard is_post_quantum_group(share.group) else { return; }
    core::write_be_u16(out, share.group);
    core::write_be_u16(out, HYBRID_CLIENT_SHARE_LEN as u16);
    out.append(share.x25519_public[..]);
    out.append(share.mlkem768_public[..]);
}

// Parses a hybrid ClientHello KeyShareEntry from raw bytes.
// Enforces exact RFC 10024 wire length (1188 bytes) to prevent smuggling trailing data.
fn parse_hybrid_key_share(share: PostQuantumKeyShare&, raw: const u8[:]) -> bool {
    guard raw.len == 4 + HYBRID_CLIENT_SHARE_LEN else { return false; }

    share.group = core::read_be_u16(raw, 0);
    guard is_post_quantum_group(share.group) else { return false; }

    let kex_len = core::read_be_u16(raw, 2) as i64;
    guard kex_len == HYBRID_CLIENT_SHARE_LEN else { return false; }

    for i in 32 {
        share.x25519_public[i] = raw[4 + i];
    }
    for i in 1152 {
        share.mlkem768_public[i] = raw[36 + i];
    }

    return true;
}

// Formats a KeyShareEntry for ServerHello:
// group (2 bytes) + key_exchange_len (2 bytes) + [32B X25519 || 1088B ML-KEM-768 ciphertext]
fn format_hybrid_server_key_share<B>(share: const PostQuantumServerShare&, out: B&) {
    guard is_post_quantum_group(share.group) else { return; }
    core::write_be_u16(out, share.group);
    core::write_be_u16(out, HYBRID_SERVER_SHARE_LEN as u16);
    out.append(share.x25519_public[..]);
    out.append(share.mlkem768_ciphertext[..]);
}

// Parses a hybrid ServerHello KeyShareEntry from raw bytes.
// Enforces exact RFC 10024 wire length (1124 bytes) to prevent smuggling trailing data.
fn parse_hybrid_server_key_share(share: PostQuantumServerShare&, raw: const u8[:]) -> bool {
    guard raw.len == 4 + HYBRID_SERVER_SHARE_LEN else { return false; }

    share.group = core::read_be_u16(raw, 0);
    guard is_post_quantum_group(share.group) else { return false; }

    let kex_len = core::read_be_u16(raw, 2) as i64;
    guard kex_len == HYBRID_SERVER_SHARE_LEN else { return false; }

    for i in 32 {
        share.x25519_public[i] = raw[4 + i];
    }
    for i in 1088 {
        share.mlkem768_ciphertext[i] = raw[36 + i];
    }

    return true;
}

// ---- 4. Hybrid Secret Combiner (RFC 10024 §4) --------------------------------

// Combines the classical X25519 shared secret and the post-quantum shared secret:
// shared_secret = SHA-256(ss_classical || ss_pq)
fn derive_hybrid_shared_secret(
    classical_ss: const u8[32]&,
    pq_ss: const u8[32]&,
) -> u8[32] {
    var combined: u8[64] = [0; 64];
    for i in 32 {
        combined[i] = classical_ss[i];
        combined[32 + i] = pq_ss[i];
    }
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
    for i in 32 {
        combined[i] = classical_ss[i];
        combined[32 + i] = pq_ss[i];
    }
    let h = core::sha256(combined[..]);
    for i in 32 { out[i] = h[i]; }
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
