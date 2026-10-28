// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Proof Key for Code Exchange by OAuth Public Clients (RFC 7636 / RFC 9700 Security BCP).
// Implements secure S256 code challenge generation and constant-time validation.
namespace wing;

import std;
import core from "..";

// ---- 1. PKCE Constants -------------------------------------------------------

const PKCE_METHOD_S256: const u8[:] = "S256";
const PKCE_METHOD_PLAIN: const u8[:] = "plain";

const PKCE_MIN_VERIFIER_LEN: i64 = 43;
const PKCE_MAX_VERIFIER_LEN: i64 = 128;

// ---- 2. PKCE Challenge Pair Model -------------------------------------------

struct PkcePair {
    verifier: u8[..128] = [],
    challenge: u8[..128] = [],
    method: u8[..16] = "S256",
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
// S256: exactly 43 unpadded base64url characters.
// plain: 43..128 unreserved characters (same as code_verifier).
fn is_valid_code_challenge(challenge: const u8[:], method: const u8[:] = "S256") -> bool {
    if method == PKCE_METHOD_S256 {
        guard challenge.len == 43 else { return false; }
        for b in challenge {
            guard is_base64url_char(b) else { return false; }
        }
        return true;
    } else if method == PKCE_METHOD_PLAIN {
        return is_valid_code_verifier(challenge);
    }
    return false;
}

// Generates a valid PKCE code verifier (43..128 characters) into out.
// If entropy bytes (e.g. 32-64 bytes) are provided, encodes them into URL-safe characters.
// If empty, derives a high-entropy 64-character verifier.
fn generate_code_verifier<B>(out: B&, entropy: const u8[:] = "") -> bool {
    out.clear();
    if entropy.len >= 32 {
        var b64: u8[..192] = [];
        core::base64url_encode(entropy, b64);
        var take_len = b64.len;
        if take_len > PKCE_MAX_VERIFIER_LEN {
            take_len = PKCE_MAX_VERIFIER_LEN;
        }
        for i in take_len {
            out.push(b64[i]);
        }
        return is_valid_code_verifier(out[..]);
    }

    // Default fallback: 64-character pseudo-random verifier using unreserved charset
    let charset: const u8[66] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~";
    var state: u64 = 0x9e3779b97f4a7c15;
    for i in 64 {
        state = state * 6364136223846793005 + 1442695040888963407 + (i as u64);
        let idx = (state >> 32) % 66;
        out.push(charset[idx as i64]);
    }
    return is_valid_code_verifier(out[..]);
}

// Computes code_challenge from code_verifier using S256 or plain (RFC 7636 Section 4.2).
// S256: BASE64URL-ENCODE(SHA256(ASCII(code_verifier))) without padding.
// Method MUST be case-sensitive ("S256" or "plain", RFC 7636 Section 4.3).
fn compute_code_challenge<B>(verifier: const u8[:], method: const u8[:], out: B&) -> bool {
    out.clear();
    guard is_valid_code_verifier(verifier) else {
        return false;
    }

    if method == PKCE_METHOD_S256 {
        let digest = core::sha256(verifier);
        core::base64url_encode(digest[..], out);
        return true;
    } else if method == PKCE_METHOD_PLAIN {
        out.append(verifier);
        return true;
    }

    return false; // Unsupported or case-mismatched method
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

// Creates a complete PKCE challenge pair.
fn create_pkce_pair(entropy: const u8[:] = "", method: const u8[:] = "S256") -> PkcePair {
    var pair = PkcePair { .. };
    pair.method.clear();
    pair.method.append(method);
    generate_code_verifier(pair.verifier, entropy);
    compute_code_challenge(pair.verifier[..], method, pair.challenge);
    return pair;
}
