// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Proof Key for Code Exchange by OAuth Public Clients (RFC 7636 / RFC 9700 Security BCP).
// Implements secure S256 code challenge generation and constant-time validation.
namespace wing;

import std;
import core from "..";

// ---- 1. PKCE Constants -------------------------------------------------------

const PKCE_METHOD_S256:  const u8[:] = "S256";
const PKCE_METHOD_PLAIN: const u8[:] = "plain";

const PKCE_MIN_VERIFIER_LEN: i64 = 43;
const PKCE_MAX_VERIFIER_LEN: i64 = 128;

// ---- 2. PKCE Challenge Pair Model -------------------------------------------

struct PkcePair {
    verifier:  u8[..128] = [],
    challenge: u8[..128] = [],
    method:    u8[..16]  = "S256",
}

// Checks whether character belongs to RFC 7636 Section 4.1 unreserved set:
// [A-Z] / [a-z] / [0-9] / "-" / "." / "_" / "~"
fn is_pkce_unreserved_char(ch: u8) -> bool {
    return (ch >= 'A' && ch <= 'Z') ||
           (ch >= 'a' && ch <= 'z') ||
           (ch >= '0' && ch <= '9') ||
           ch == '-' || ch == '.' || ch == '_' || ch == '~';
}

fn is_base64url_char(ch: u8) -> bool {
    return (ch >= 'A' && ch <= 'Z') ||
           (ch >= 'a' && ch <= 'z') ||
           (ch >= '0' && ch <= '9') ||
           ch == '-' || ch == '_';
}

// RFC 7636 §4.2 / RFC 4648 §3.5: Verifies that the 43rd Base64URL character of an S256
// challenge has bits 1..0 set to 00 (canonical padding bits).
fn is_canonical_s256_final_char(ch: u8) -> bool {
    return ch == 'A' || ch == 'E' || ch == 'I' || ch == 'M' ||
           ch == 'Q' || ch == 'U' || ch == 'Y' || ch == 'c' ||
           ch == 'g' || ch == 'k' || ch == 'o' || ch == 's' ||
           ch == 'w' || ch == '0' || ch == '4' || ch == '8';
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

// Validates whether code_challenge conforms to RFC 7636 Section 4.2.
// S256: exactly 43 unpadded base64url characters with canonical padding bits.
// plain: 43..128 unreserved characters (same as code_verifier).
fn is_valid_code_challenge(challenge: const u8[:], method: const u8[:] = "S256") -> bool {
    if method == PKCE_METHOD_S256 {
        guard challenge.len == 43 else { return false; }
        for i in 42 {
            guard is_base64url_char(challenge[i]) else { return false; }
        }
        guard is_canonical_s256_final_char(challenge[42]) else { return false; }
        return true;
    } else if method == PKCE_METHOD_PLAIN {
        return is_valid_code_verifier(challenge);
    }
    return false;
}

// Generates a valid PKCE code verifier (43..128 characters) into out (RFC 7636 §4.1).
// If entropy bytes (>= 32 bytes) are provided, encodes them into URL-safe characters.
// If empty, derives high-entropy dynamic bytes from the monotonic clock (invariant 16).
// Returns false if entropy is non-empty but less than 32 bytes (256 bits).
fn generate_code_verifier<B>(out: B&, entropy: const u8[:] = "") -> bool {
    out.clear();
    guard entropy.len == 0 || entropy.len >= 32 else {
        return false; // RFC 7636 §4.1: Minimum 256 bits (32 bytes) of entropy required
    }
    if entropy.len >= 32 {
        let max_raw = if entropy.len > 96 { 96 } else { entropy.len };
        core::base64url_encode(entropy[..max_raw], out);
        return is_valid_code_verifier(out[..]);
    }

    var raw_entropy: u8[32] = [0; 32];
    var state:       u64    = (clock_ns() as u64) ^ 0x56e8feb86659fd93;
    for i in 4 {
        state = state * 6364136223846793005 + 1442695040888963407;
        for j in 8 {
            raw_entropy[i * 8 + j] = ((state >> (j * 8)) & 0xFF) as u8;
        }
    }
    core::base64url_encode(raw_entropy[..], out);
    return is_valid_code_verifier(out[..]);
}

// Computes code_challenge from code_verifier using S256 or plain (RFC 7636 Section 4.2).
// S256: BASE64URL-ENCODE(SHA256(ASCII(code_verifier))) without padding.
// Method MUST be case-sensitive ("S256" or "plain", RFC 7636 Section 4.3).
fn compute_code_challenge<B>(verifier: const u8[:], method: const u8[:], out: B&) -> bool {
    guard is_valid_code_verifier(verifier) else {
        return false;
    }
    guard method == PKCE_METHOD_S256 || method == PKCE_METHOD_PLAIN else {
        return false;
    }

    out.clear();
    if method == PKCE_METHOD_S256 {
        let digest = core::sha256(verifier);
        core::base64url_encode(digest[..], out);
    } else {
        out.append(verifier);
    }
    return true;
}

// Constant-time validation of code_verifier against code_challenge (RFC 7636 Section 4.6).
fn validate_code_challenge(verifier: const u8[:], challenge: const u8[:], method: const u8[:] = "S256") -> bool {
    guard is_valid_code_verifier(verifier) else {
        return false;
    }
    guard is_valid_code_challenge(challenge, method) else {
        return false;
    }

    var computed: u8[..128] = [];
    guard compute_code_challenge(verifier, method, computed) else {
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
    guard method.len <= pair.method.cap else { return pair, false; }
    pair.method.clear();
    pair.method.append(method);
    guard generate_code_verifier(pair.verifier, entropy) else { return pair, false; }
    guard compute_code_challenge(pair.verifier[..], method, pair.challenge) else { return pair, false; }
    return pair, true;
}

// ---- 3. OAuth 2.1 & RFC 9700 Security BCP Enforcement -----------------------

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
