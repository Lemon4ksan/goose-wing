// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Proof Key for Code Exchange by OAuth Public Clients (RFC 7636 / RFC 9700 Security BCP).
// Implements secure S256 code challenge generation and constant-time validation.
namespace wing;

import std;
import core from "..";

// ---- PKCE Constants -------------------------------------------------------

const PKCE_METHOD_S256:  const u8[:] = "S256";
const PKCE_METHOD_PLAIN: const u8[:] = "plain";

const PKCE_MIN_VERIFIER_LEN: i64 = 43;
const PKCE_MAX_VERIFIER_LEN: i64 = 128;

// ---- PKCE Challenge Pair Model -------------------------------------------

struct PkcePair {
    verifier:  u8[..128] = [],
    challenge: u8[..128] = [],
    method:    u8[..16]  = "S256",
}

const PKCE_UNRESERVED_LUT: const bool[256] = [
    false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false,
    false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false,
    false, false, false, false, false, false, false, false, false, false, false, false, false, true, true, false,
    true, true, true, true, true, true, true, true, true, true, false, false, false, false, false, false,
    false, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true,
    true, true, true, true, true, true, true, true, true, true, true, false, false, false, false, true,
    false, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true,
    true, true, true, true, true, true, true, true, true, true, true, false, false, false, true, false,
    false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false,
    false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false,
    false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false,
    false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false,
    false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false,
    false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false,
    false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false,
    false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false,
];

checkfree inline fn is_pkce_unreserved_char(ch: u8) -> bool {
    return PKCE_UNRESERVED_LUT[ch];
}

const BASE64URL_CHAR_LUT: const bool[256] = [
    false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false,
    false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false,
    false, false, false, false, false, false, false, false, false, false, false, false, false, true, false, false,
    true, true, true, true, true, true, true, true, true, true, false, false, false, false, false, false,
    false, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true,
    true, true, true, true, true, true, true, true, true, true, true, false, false, false, false, true,
    false, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true,
    true, true, true, true, true, true, true, true, true, true, true, false, false, false, false, false,
    false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false,
    false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false,
    false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false,
    false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false,
    false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false,
    false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false,
    false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false,
    false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false,
];

checkfree inline fn is_base64url_char(ch: u8) -> bool {
    return BASE64URL_CHAR_LUT[ch];
}

const CANONICAL_S256_FINAL_LUT: const bool[256] = [
    false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false,
    false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false,
    false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false,
    true, false, false, false, true, false, false, false, true, false, false, false, false, false, false, false,
    false, true, false, false, false, true, false, false, false, true, false, false, false, true, false, false,
    false, true, false, false, false, true, false, false, false, true, false, false, false, false, false, false,
    false, false, false, true, false, false, false, true, false, false, false, true, false, false, false, true,
    false, false, false, true, false, false, false, true, false, false, false, false, false, false, false, false,
    false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false,
    false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false,
    false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false,
    false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false,
    false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false,
    false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false,
    false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false,
    false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false,
];

// RFC 7636 §4.2 / RFC 4648 §3.5: Verifies that the 43rd Base64URL character of an S256
// challenge has bits 1..0 set to 00 (canonical padding bits).
checkfree inline fn is_canonical_s256_final_char(ch: u8) -> bool {
    return CANONICAL_S256_FINAL_LUT[ch];
}

// Validates whether verifier conforms to RFC 7636 Section 4.1.
fn is_valid_code_verifier(v: const u8[:]) -> bool {
    guard v.len >= PKCE_MIN_VERIFIER_LEN && v.len <= PKCE_MAX_VERIFIER_LEN else {
        return false;
    }
    for b in v {
        guard is_pkce_unreserved_char(b) else {
            return false;
        }
    }
    return true;
}

var g_pkce_entropy_counter: u64 = 1;

// Validates whether code_challenge conforms to RFC 7636 Section 4.2.
// Defaults to 'plain' when method is omitted per RFC 7636 §4.3.
// S256: exactly 43 unpadded base64url characters with canonical padding bits.
// plain: 43..128 unreserved characters (same as code_verifier).
fn is_valid_code_challenge(challenge: const u8[:], method: const u8[:] = "plain") -> bool {
    let eff_method = if method.len == 0 { PKCE_METHOD_PLAIN } else { method };
    if eff_method == PKCE_METHOD_S256 {
        guard challenge.len == 43 else { return false; }
        for i in 42 {
            guard is_base64url_char(challenge[i]) else { return false; }
        }
        guard is_canonical_s256_final_char(challenge[42]) else { return false; }
        return true;
    } else if eff_method == PKCE_METHOD_PLAIN {
        return is_valid_code_verifier(challenge);
    }
    return false;
}

// Encodes caller-provided entropy bytes into a base64url PKCE verifier (RFC 7636 §4.1).
inline fn encode_external_entropy<B>(entropy: const u8[:], out: B&) -> bool {
    let max_raw = if entropy.len > 96 { 96 } else { entropy.len };
    core::base64url_encode(entropy[..max_raw], out);
    return is_valid_code_verifier(out[..]);
}

inline fn derive_pkce_seed(now_ns: u64, counter: u64) -> u8[32] {
    var seed: u8[32] = [0; 32];
    var w = core::new_slice_writer(seed[..]);
    core::write_u64_le(w, now_ns);
    core::write_u64_le(w, counter);
    core::write_u64_le(w, now_ns ^ 0xa0761d6478bd642f);
    core::write_u64_le(w, counter * 0xe7037ed1a0b428db);
    return seed;
}

inline fn generate_derived_verifier<B>(out: B&) -> bool {
    g_pkce_entropy_counter = g_pkce_entropy_counter + 1;
    let seed = derive_pkce_seed(clock_ns() as u64, g_pkce_entropy_counter);
    let raw_entropy = core::sha256(seed[..]);
    core::base64url_encode(raw_entropy[..], out);
    return is_valid_code_verifier(out[..]);
}

// Generates a valid PKCE code verifier (43..128 characters) into out (RFC 7636 §4.1).
// If entropy bytes (>= 32 bytes) are provided, encodes them into URL-safe characters.
// If empty, derives high-entropy dynamic bytes by mixing monotonic clock (clock_ns),
// global monotonic counter, and multi-round SHA-256 cryptographic expansion (FINDING-R5-SEC-07).
// Returns false if entropy is non-empty but less than 32 bytes (256 bits).
//
// Example:
//   entropy = "", out = []
//   returns: ok = true, out = "..." (43 URL-safe unreserved characters)
fn generate_code_verifier<B>(out: B&, entropy: const u8[:] = "") -> bool {
    out.clear();
    guard entropy.len == 0 || entropy.len >= 32 else {
        return false; // RFC 7636 §4.1: Minimum 256 bits (32 bytes) of entropy required
    }
    if entropy.len >= 32 {
        return encode_external_entropy(entropy, out);
    }
    return generate_derived_verifier(out);
}

// Computes code_challenge from code_verifier using S256 or plain (RFC 7636 Section 4.2).
// S256: BASE64URL-ENCODE(SHA256(ASCII(code_verifier))) without padding.
// Method MUST be case-sensitive ("S256" or "plain", RFC 7636 Section 4.3). Defaults to 'plain'.
fn compute_code_challenge<B>(verifier: const u8[:], method: const u8[:], out: B&) -> bool {
    guard is_valid_code_verifier(verifier) else {
        return false;
    }
    let eff_method = if method.len == 0 { PKCE_METHOD_PLAIN } else { method };
    guard eff_method == PKCE_METHOD_S256 || eff_method == PKCE_METHOD_PLAIN else {
        return false;
    }

    out.clear();
    if eff_method == PKCE_METHOD_S256 {
        let digest = core::sha256(verifier);
        core::base64url_encode(digest[..], out);
    } else {
        out.append(verifier);
    }
    return true;
}

// Constant-time validation of code_verifier against code_challenge (RFC 7636 Section 4.6).
// Defaults to 'plain' when method is omitted per RFC 7636 §4.3.
fn validate_code_challenge(verifier: const u8[:], challenge: const u8[:], method: const u8[:] = "plain") -> bool {
    let eff_method = if method.len == 0 { PKCE_METHOD_PLAIN } else { method };
    guard is_valid_code_verifier(verifier) else {
        return false;
    }
    guard is_valid_code_challenge(challenge, eff_method) else {
        return false;
    }

    var computed: u8[..128] = [];
    guard compute_code_challenge(verifier, eff_method, computed) else {
        return false;
    }

    guard computed.len == challenge.len else {
        return false;
    }

    return core::ct_eq_bytes(computed[..], challenge);
}

// Creates a complete PKCE challenge pair. Returns false if entropy or method is invalid.
fn create_pkce_pair(entropy: const u8[:] = "", method: const u8[:] = "S256") -> PkcePair, bool {
    var pair = PkcePair { .. };
    let eff_method = if method.len == 0 { PKCE_METHOD_PLAIN } else { method };
    guard eff_method.len <= pair.method.cap else { return pair, false; }
    pair.method.clear();
    pair.method.append(eff_method);
    guard generate_code_verifier(pair.verifier, entropy) else { return pair, false; }
    guard compute_code_challenge(pair.verifier[..], eff_method, pair.challenge) else { return pair, false; }
    return pair, true;
}

// ---- OAuth 2.1 & RFC 9700 Security BCP Enforcement -----------------------

// Validates whether code_challenge conforms to OAuth 2.1 Section 7.6.1 and RFC 9700 Section 2.1.1.
// Strictly mandates S256 and forbids the legacy plain transformation.
fn is_valid_code_challenge_strict(challenge: const u8[:], method: const u8[:] = "S256") -> bool {
    guard method == PKCE_METHOD_S256 else { return false; }
    return is_valid_code_challenge(challenge, method);
}

// Validates code_verifier against code_challenge under OAuth 2.1 / RFC 9700 strict rules.
// Rejects method != "S256" immediately.
fn validate_code_challenge_strict(verifier: const u8[:], challenge: const u8[:], method: const u8[:] = "S256") -> bool {
    guard method == PKCE_METHOD_S256 else { return false; }
    return validate_code_challenge(verifier, challenge, method);
}
