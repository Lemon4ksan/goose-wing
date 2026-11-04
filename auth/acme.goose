// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// ACME HTTP-01 challenge primitives (RFC 8555 §8.1 key authorizations, §8.3 HTTP challenge).
// Zero-heap allocation: inputs are const slices; outputs write to caller-owned bounded buffers.
namespace wing;

import std;
import core from "..";

// RFC 8555 §8.3 fixed path prefix for HTTP-01 challenge resources.
// 64 bytes caps the stack buffer while accepting well-formed base64url tokens).
const ACME_MAX_TOKEN_LEN: i64 = 64;

// Maximum key-authorization body length (token || '.' || base64url thumbprint).
const ACME_MAX_KEY_AUTH_LEN: i64 = 256;

// HTTP-01 responder table entry: one provisioned challenge per slot.
struct AcmeChallenge {
    token:        u8[..64]  = [],
    key_auth:     u8[..256] = [],
    key_auth_len: i32       = 0,
}

// Validates an ACME challenge token: non-empty, at most ACME_MAX_TOKEN_LEN bytes,
// every byte in the URL-safe base64 alphabet [A-Za-z0-9_-] (RFC 8555 §8.1/§8.3).
// Rejects path separators, dots, percent-encoding, and padding so tokens cannot
// traverse or confuse the HTTP-01 path.
fn acme_validate_token(token: const u8[:]) -> bool {
    guard token.len >= 1 && token.len <= ACME_MAX_TOKEN_LEN else { return false; }
    for b in token {
        let ok = (b >= 'A' && b <= 'Z') || (b >= 'a' && b <= 'z') ||
                 (b >= '0' && b <= '9') || b == '-' || b == '_';
        guard ok else { return false; }
    }
    return true;
}

// Builds the RFC 8555 §8.1 key authorization body into `out`:
//   keyAuthorization = token || '.' || base64url(Thumbprint(accountKey))
//
// The caller supplies the thumbprint already base64url-encoded via
// compute_jwk_thumbprint + base64url_encode (no re-encoding here).
// Returns bytes written, or -1 when the result would exceed ACME_MAX_KEY_AUTH_LEN.
//
// Example:
//   token = "tok", thumbprint_b64url = "TP", out = []
//   returns: 6, out = "tok.TP"
fn acme_key_authorization(
    token:             const u8[:],
    thumbprint_b64url: const u8[:],
    out:               u8[..256]&,
) -> i32 {
    let token_valid = acme_validate_token(token);
    let thumb_valid = acme_validate_token(thumbprint_b64url);
    let total = token.len + thumbprint_b64url.len;
    guard token_valid && thumb_valid && total < out.cap else { return -1; }
    out.clear();
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
//   token = "tok", out = []
//   returns: 31, out = "/.well-known/acme-challenge/tok"
fn acme_http01_path(token: const u8[:], out: u8[..128]&) -> i32 {
    let token_valid = acme_validate_token(token);
    let total = rfc::ACME_HTTP01_PREFIX.len + token.len;
    guard token_valid && total <= out.cap else { return -1; }
    out.clear();
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
    let expected_len = rfc::ACME_HTTP01_PREFIX.len + token.len;
    guard acme_validate_token(token) else { return false; }
    guard path.len == expected_len else { return false; }
    for i in rfc::ACME_HTTP01_PREFIX.len {
        guard path[i] == rfc::ACME_HTTP01_PREFIX[i] else { return false; }
    }
    return core::ct_eq_bytes(path[rfc::ACME_HTTP01_PREFIX.len..], token);
}

// HTTP-01 responder helper: linear-scans up to 8 challenge slots, matches the
// request path against each stored token, and on a hit copies the stored key
// authorization into out_body. Returns false with out_len untouched on miss.
//
// Example:
//   table = [AcmeChallenge{token:"tok", key_auth:"tok.TP", key_auth_len:6}],
//   path = "/.well-known/acme-challenge/tok"
//   returns: true, out_body = "tok.TP", out_len = 6
fn acme_find_challenge(
    table:    const AcmeChallenge[..8]&,
    path:     const u8[:],
    out_body: u8[..256]&,
    out_len:  i32&,
) -> bool {
    for &ch in table {
        let matched = ch.key_auth_len > 0 && acme_match_http01(path, ch.token[..]);
        let fits = ch.key_auth_len <= ch.key_auth.len && ch.key_auth_len <= out_body.cap;
        if matched && fits {
            out_body.clear();
            out_body.append(ch.key_auth[..ch.key_auth_len]);
            out_len = ch.key_auth_len;
            return true;
        }
    }
    out_body.clear();
    return false;
}
