// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// ACME HTTP-01 challenge primitives (RFC 8555 §8.1 key authorizations, §8.3 HTTP challenge).
// Zero-heap allocation: inputs are const slices; outputs write to caller-owned bounded buffers.
namespace wing;

import std;
import core from "..";

// RFC 8555 Section 8.3: HTTP Challenge - token must have at least 128 bits of entropy (22 base64url chars)
const ACME_MIN_TOKEN_LEN: i64 = 22;
const ACME_MAX_TOKEN_LEN: i64 = 64;

// RFC 8555 Section 8.1: Key Authorizations - SHA-256 JWK thumbprint is 43 base64url characters
const ACME_THUMBPRINT_LEN: i64 = 43;

// Maximum key-authorization body length (token || '.' || base64url thumbprint).
const ACME_MAX_KEY_AUTH_LEN: i64 = 256;

// HTTP-01 responder table entry: one provisioned challenge per slot.
struct AcmeChallenge {
    token:        u8[..64]  = [],
    key_auth:     u8[..256] = [],
    key_auth_len: i32       = 0,
}

inline fn is_acme_base64url_chars(s: const u8[:]) -> bool {
    for b in s {
        let ok = (b >= 'A' && b <= 'Z') || (b >= 'a' && b <= 'z') ||
                 (b >= '0' && b <= '9') || b == '-' || b == '_';
        guard ok else { return false; }
    }
    return true;
}

inline fn is_valid_acme_thumbprint(thumbprint_b64url: const u8[:]) -> bool {
    return thumbprint_b64url.len == ACME_THUMBPRINT_LEN && is_acme_base64url_chars(thumbprint_b64url);
}

// Validates an ACME challenge token: 22..ACME_MAX_TOKEN_LEN bytes,
// every byte in the URL-safe base64 alphabet [A-Za-z0-9_-] (RFC 8555 §8.1/§8.3).
// Rejects path separators, dots, percent-encoding, and padding so tokens cannot
// traverse or confuse the HTTP-01 path.
fn acme_validate_token(token: const u8[:]) -> bool {
    guard token.len >= ACME_MIN_TOKEN_LEN && token.len <= ACME_MAX_TOKEN_LEN else { return false; }
    return is_acme_base64url_chars(token);
}

// Builds the RFC 8555 §8.1 key authorization body into `out`:
//   keyAuthorization = token || '.' || base64url(Thumbprint(accountKey))
//
// The caller supplies the thumbprint already base64url-encoded via
// compute_jwk_thumbprint + base64url_encode (no re-encoding here).
// Returns bytes written, or -1 when the result would exceed ACME_MAX_KEY_AUTH_LEN.
//
// Example:
//   token = "LoqXcYV8q5ONbJQxbmR7SC", thumbprint_b64url = "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs", out = []
//   returns: 66, out = "LoqXcYV8q5ONbJQxbmR7SC.NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs"
fn acme_key_authorization(
    token:             const u8[:],
    thumbprint_b64url: const u8[:],
    out:               u8[..256]&,
) -> i32 {
    out.clear();
    let token_valid = acme_validate_token(token);
    let thumb_valid = is_valid_acme_thumbprint(thumbprint_b64url);
    let total = core::add_sat_i64(token.len, thumbprint_b64url.len);
    guard token_valid && thumb_valid && total < out.cap else { return -1; }
    out.append(token);
    out.push('.');
    out.append(thumbprint_b64url);
    return out.len as i32;
}

// Builds the RFC 8555 §8.3 HTTP-01 challenge path into `out`:
//   ACME_HTTP01_PREFIX || token
//
// Returns bytes written, or -1 when the path would exceed the caller buffer.
//
// Example:
//   token = "LoqXcYV8q5ONbJQxbmR7SC", out = []
//   returns: 50, out = "/.well-known/acme-challenge/LoqXcYV8q5ONbJQxbmR7SC"
fn acme_http01_path(token: const u8[:], out: u8[..128]&) -> i32 {
    out.clear();
    let token_valid = acme_validate_token(token);
    let total = core::add_sat_i64(rfc::ACME_HTTP01_PREFIX.len, token.len);
    guard token_valid && total <= out.cap else { return -1; }
    out.append(rfc::ACME_HTTP01_PREFIX[..]);
    out.append(token);
    return total as i32;
}

// Matches a request path against the fixed HTTP-01 prefix plus an exact token
// suffix (RFC 8555 §8.3). The token is validated first so traversal and other
// non-base64url tokens are rejected before any path comparison. Length and
// public prefix use early exits; the token suffix is compared with
// core::ct_eq_bytes (constant-time-ish).
fn acme_match_http01(path: const u8[:], token: const u8[:]) -> bool {
    let expected_len = core::add_sat_i64(rfc::ACME_HTTP01_PREFIX.len, token.len);
    guard acme_validate_token(token) else { return false; }
    guard path.len == expected_len else { return false; }
    for i in rfc::ACME_HTTP01_PREFIX.len {
        guard path[i] == rfc::ACME_HTTP01_PREFIX[i] else { return false; }
    }
    return core::ct_eq_bytes(path[rfc::ACME_HTTP01_PREFIX.len..], token);
}

inline fn is_valid_acme_challenge_slot(ch: const AcmeChallenge&) -> bool {
    guard acme_validate_token(ch.token[..]) else { return false; }
    let tok_len = ch.token.len;
    let thumb_idx = core::add_sat_i64(tok_len, 1);
    guard ch.key_auth_len > 0 && ch.key_auth.len == ch.key_auth_len && ch.key_auth.len > thumb_idx else {
        return false;
    }
    guard ch.key_auth[..tok_len] == ch.token[..] && ch.key_auth[tok_len] == '.' else { return false; }
    return is_valid_acme_thumbprint(ch.key_auth[thumb_idx..]);
}

// HTTP-01 responder helper: linear-scans up to 8 challenge slots, matches the
// request path against each stored token, and on a hit copies the stored key
// authorization into out_body. Returns false with out_len untouched on miss.
//
// Example:
//   table = [AcmeChallenge{token:"LoqXcYV8q5ONbJQxbmR7SC",
//            key_auth:"LoqXcYV8q5ONbJQxbmR7SC.NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs", key_auth_len:66}],
//   path = "/.well-known/acme-challenge/LoqXcYV8q5ONbJQxbmR7SC"
//   returns: true, out_len = 66
fn acme_find_challenge(
    table:    const AcmeChallenge[..8]&,
    path:     const u8[:],
    out_body: u8[..256]&,
    out_len:  i32&,
) -> bool {
    for &ch in table {
        let matched = is_valid_acme_challenge_slot(ch) && acme_match_http01(path, ch.token[..]);
        if matched && out_body.try_set(ch.key_auth[..ch.key_auth_len]) {
            out_len = ch.key_auth_len;
            return true;
        }
    }
    out_body.clear();
    return false;
}
