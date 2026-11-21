// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// ACME HTTP-01 challenge token validation and responder helpers (RFC 8555 Section 8.3).
namespace auth;

import std;
import core;
import rfc.http;
import .types;
import .internal;

// RFC 8555 Section 8.3: HTTP Challenge - token has 22..64 Base64URL chars (>= 128-bit entropy).
fn validate_acme_token(token: const u8[:]) -> bool {
    return token.len >= auth_internal::ACME_MIN_TOKEN_LEN &&
        token.len <= auth_internal::ACME_MAX_TOKEN_LEN &&
        auth_internal::is_acme_base64url_chars(token);
}

// RFC 8555 Section 8.1: Key Authorizations - builds "<token>.<thumbprint>" into `out`.
//
// Example:
//   token = "LoqXcYV8q5ONbJQxbmR7SC", thumbprint_b64url = "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs"
//   returns: true, out = "LoqXcYV8q5ONbJQxbmR7SC.NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs"
fn build_acme_key_authorization<B>(
    token:             const u8[:],
    thumbprint_b64url: const u8[:],
    out:               B&,
) -> bool {
    var committed = false;
    defer if !committed { out.resize(0); };
    guard validate_acme_token(token) else { return false; }
    guard auth_internal::is_valid_acme_thumbprint(thumbprint_b64url) else { return false; }
    out.clear();
    guard out.try_append(token) else { return false; }
    guard out.try_push('.' as u8) else { return false; }
    guard out.try_append(thumbprint_b64url) else { return false; }
    committed = true;
    return true;
}

// RFC 8555 Section 8.3: HTTP Challenge - formats "/.well-known/acme-challenge/<token>" into `out`.
//
// Example:
//   token = "LoqXcYV8q5ONbJQxbmR7SC"
//   returns: true, out = "/.well-known/acme-challenge/LoqXcYV8q5ONbJQxbmR7SC"
fn build_acme_http01_path<B>(token: const u8[:], out: B&) -> bool {
    var committed = false;
    defer if !committed { out.resize(0); };
    guard validate_acme_token(token) else { return false; }
    out.clear();
    guard out.try_append(rfc::ACME_HTTP01_PREFIX[..]) else { return false; }
    guard out.try_append(token) else { return false; }
    committed = true;
    return true;
}

// RFC 8555 Section 8.3: HTTP Challenge - constant-time token match for an incoming request path.
fn match_acme_http01(path: const u8[:], token: const u8[:]) -> bool {
    guard validate_acme_token(token) else { return false; }
    let req_tok, ok = path.strip_prefix(rfc::ACME_HTTP01_PREFIX[..]);
    guard ok && req_tok.len == token.len else { return false; }
    return core::ct_eq_bytes(req_tok, token);
}

// Looks up a provisioned ACME HTTP-01 challenge matching `path` and writes its key authorization to `out`.
//
// Example:
//   path = "/.well-known/acme-challenge/LoqXcYV8q5ONbJQxbmR7SC"
//   returns: true, out = "<token>.<thumbprint>"
fn find_acme_challenge<B>(
    table: const AcmeChallenge[..8]&,
    path:  const u8[:],
    out:   B&,
) -> bool {
    for &ch in table {
        if auth_internal::is_valid_acme_challenge_slot(ch) && match_acme_http01(path, ch.token[..]) {
            guard out.try_set(ch.key_auth[..]) else {
                out.resize(0);
                return false;
            }
            return true;
        }
    }
    return false;
}
