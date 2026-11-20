// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// OAuth 2.0 Proof Key for Code Exchange (PKCE) with S256 default (RFC 7636 / RFC 9700 Section 2.1.1).
namespace auth;

import std;
import core from "..";
import rfc.http;
import .types;
import .internal;

// RFC 7636 Section 4.1: Client Creates a Code Verifier - 43..128 unreserved chars.
fn is_valid_code_verifier(v: const u8[:]) -> bool {
    guard v.len >= rfc::PKCE_MIN_VERIFIER_LEN && v.len <= rfc::PKCE_MAX_VERIFIER_LEN else { return false; }
    return auth_internal::is_uri_unreserved_bytes(v);
}

// RFC 7636 Section 4.2: Client Creates the Code Challenge - validates S256 (43 unpadded base64url chars) or plain.
fn is_valid_code_challenge(challenge: const u8[:], method: const u8[:] = "plain") -> bool {
    if method == rfc::PKCE_METHOD_S256 {
        return challenge.len == 43 && challenge.is_valid_base64url();
    }
    if method == rfc::PKCE_METHOD_PLAIN {
        return is_valid_code_verifier(challenge);
    }
    return false;
}

// Encodes caller-provided entropy (>= 32 bytes, clamped to 96) into a base64url PKCE verifier into `out`.
fn encode_external_entropy<B>(entropy: const u8[:], out: B&) -> bool {
    var committed = false;
    defer if !committed { out.resize(0); };
    guard entropy.len >= 32 else { return false; }
    let max_raw = min(entropy.len, 96);
    var encoded: u8[..128] = [];
    defer core::secure_zeroize_slice(encoded[..]);
    core::base64url_encode(entropy[..max_raw], encoded);
    guard is_valid_code_verifier(encoded[..]) else { return false; }
    guard out.try_set(encoded[..]) else { return false; }
    committed = true;
    return true;
}

// RFC 7636 Section 4.1: Client Creates a Code Verifier - generates or encodes >= 256-bit verifier into `out`.
fn generate_code_verifier<B>(out: B&, entropy: const u8[:] = "") -> bool {
    guard entropy.len == 0 || entropy.len >= 32 else { return false; }
    if entropy.len >= 32 {
        return encode_external_entropy(entropy, out);
    }
    return auth_internal::generate_derived_verifier(out);
}

// RFC 7636 Section 4.2: Client Creates the Code Challenge - writes S256 or plain challenge into `out`.
fn compute_code_challenge<B>(verifier: const u8[:], method: const u8[:], out: B&) -> bool {
    var committed = false;
    defer if !committed { out.resize(0); };
    guard is_valid_code_verifier(verifier) else { return false; }
    if method == rfc::PKCE_METHOD_S256 {
        var hash = core::sha256(verifier);
        defer core::secure_zeroize_32(hash);
        var encoded: u8[..64] = [];
        defer core::secure_zeroize_slice(encoded[..]);
        core::base64url_encode(hash[..], encoded);
        guard out.try_set(encoded[..]) else { return false; }
        committed = true;
        return true;
    }
    if method == rfc::PKCE_METHOD_PLAIN {
        guard out.try_set(verifier) else { return false; }
        committed = true;
        return true;
    }
    return false;
}

// RFC 7636 Section 4.6: Server Verifies the Code Verifier - constant-time check against `challenge`.
fn validate_code_challenge(
    verifier:  const u8[:],
    challenge: const u8[:],
    method:    const u8[:] = "plain",
) -> bool {
    guard is_valid_code_verifier(verifier) && is_valid_code_challenge(challenge, method) else { return false; }
    var expected: u8[..128] = [];
    defer core::secure_zeroize_slice(expected[..]);
    guard compute_code_challenge(verifier, method, expected) else { return false; }
    guard expected.len == challenge.len else { return false; }
    return core::ct_eq_bytes(expected[..], challenge);
}

// Creates a verified PKCE verifier/challenge pair using the requested method (defaults to "S256").
fn create_pkce_pair(entropy: const u8[:] = "", method: const u8[:] = "S256") -> PkcePair, bool {
    let empty_pair = PkcePair { method: "", .. };
    let eff_method = if method.len == 0 { rfc::PKCE_METHOD_PLAIN } else { method };
    guard eff_method == rfc::PKCE_METHOD_S256 || eff_method == rfc::PKCE_METHOD_PLAIN else {
        return empty_pair, false;
    }
    var pair = PkcePair { method: "", .. };
    guard pair.method.try_set(eff_method) else { return empty_pair, false; }
    guard generate_code_verifier(pair.verifier, entropy) else { return empty_pair, false; }
    guard compute_code_challenge(pair.verifier[..], eff_method, pair.challenge) else {
        core::secure_zeroize_slice(pair.verifier[..]);
        return empty_pair, false;
    }
    return pair, true;
}

// RFC 9700 Section 2.1.1: Proof Key for Code Exchange - strict validator permitting only S256.
fn is_valid_code_challenge_strict(challenge: const u8[:], method: const u8[:] = "S256") -> bool {
    guard method == rfc::PKCE_METHOD_S256 else { return false; }
    return is_valid_code_challenge(challenge, method);
}

// RFC 9700 Section 2.1.1: Proof Key for Code Exchange - verifies verifier strictly under S256.
fn validate_code_challenge_strict(
    verifier:  const u8[:],
    challenge: const u8[:],
    method:    const u8[:] = "S256",
) -> bool {
    guard method == rfc::PKCE_METHOD_S256 else { return false; }
    return validate_code_challenge(verifier, challenge, method);
}
