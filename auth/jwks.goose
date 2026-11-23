// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// JSON Web Key Set (JWKS) key management, parsing, SSRF URL checks, and JWT verification (RFC 7517 / RFC 8725).
namespace auth;

import std;
import json;
import core;
import rfc.http;
import .types;
import .internal;
import .jwk_internal;
import .jwt_core;
import .jwt_internal;
import .jwt;
import .jwk;
import .jwks_internal;

// Appends an Ed25519 verification key to `jwks` (RFC 8037 Section 2).
fn add_ed25519_key(jwks: Jwks&, kid: const u8[:], pub_key: const u8[32]) -> bool {
    guard jwks.keys.len < 16 && kid.len <= 64 && auth_internal::has_nonzero_byte_32(pub_key) else {
        return false;
    }
    var item = JwksKey {
        kty:        JwkKeyType.OKP,
        crv:        "Ed25519",
        alg:        JwtAlg.EdDSA,
        public_key: pub_key,
        valid:      true,
        ..
    };
    if kid.len > 0 { item.kid.append(kid); }
    return jwks.keys.try_push(item);
}

// Appends an ECDSA P-256 verification key to `jwks` (RFC 7518 Section 6.2).
fn add_es256_key(jwks: Jwks&, kid: const u8[:], x: const u8[:], y: const u8[:]) -> bool {
    guard jwks.keys.len < 16 && kid.len <= 64 else { return false; }
    guard auth_internal::is_valid_jwk_ec_p256_coords(x, y) else { return false; }
    var item = JwksKey {
        kty:   JwkKeyType.EC,
        crv:   "P-256",
        alg:   JwtAlg.ES256,
        valid: true,
        ..
    };
    if kid.len > 0 { item.kid.append(kid); }
    item.ec_x.append(x);
    item.ec_y.append(y);
    return jwks.keys.try_push(item);
}

// Appends an RSA public verification key (`RS256`, `PS256`, or `Unspecified`) to `jwks` (RFC 7518 §6.3).
fn add_rsa_key(
    jwks: Jwks&,
    kid:  const u8[:],
    alg:  JwtAlg,
    n_be: const u8[:],
    e_be: const u8[:],
) -> bool {
    guard jwks.keys.len < 16 && kid.len <= 64 else { return false; }
    guard alg == JwtAlg.Unspecified || alg == JwtAlg.RS256 || alg == JwtAlg.PS256 else { return false; }
    guard auth_internal::is_canonical_jwk_rsa_params(n_be, e_be) else { return false; }
    var item = JwksKey { kty: JwkKeyType.RSA, alg: alg, valid: true, .. };
    if kid.len > 0 { item.kid.append(kid); }
    guard item.rsa_n.try_set(n_be) && item.rsa_e.try_set(e_be) else { return false; }
    return jwks.keys.try_push(item);
}

// Appends an HMAC symmetric key (`HS256`/`HS384`/`HS512` or `Unspecified`) to `jwks` (RFC 7518 §3.2).
fn add_symmetric_key(
    jwks:       Jwks&,
    kid:        const u8[:],
    alg:        JwtAlg,
    secret_key: const u8[:],
) -> bool {
    let min_len = if alg == JwtAlg.Unspecified {
        rfc::HMAC_SHA256_MAC_LEN
    } else {
        auth_internal::hmac_min_key_len(alg)
    };
    guard jwks.keys.len < 16 && kid.len <= 64 && min_len > 0 else { return false; }
    guard secret_key.len >= min_len && secret_key.len <= 128 else { return false; }
    var item = JwksKey { kty: JwkKeyType.Oct, alg: alg, valid: true, .. };
    defer core::secure_zeroize_slice(item.symmetric_key[..]);
    if kid.len > 0 { item.kid.append(kid); }
    item.symmetric_key.append(secret_key);
    return jwks.keys.try_push(item);
}

// Finds the index of the first valid JWK in `jwks` matching `kid`.
fn find_key(jwks: const Jwks&, kid: const u8[:]) -> i64, bool {
    for i in jwks.keys.len {
        let k .= jwks.keys[i];
        if k.valid && k.kid[..] == kid {
            return i, true;
        }
    }
    return 0, false;
}

// Serializes `jwks` to RFC 7517 Section 5 JSON format appended to `out`.
fn serialize_jwks<B>(jwks: const Jwks&, out: B&) -> bool {
    let saved_len = out.len;
    var committed = false;
    defer if !committed { out.resize(saved_len); };
    guard out.try_append("{\"keys\":[") else { return false; }
    for i in jwks.keys.len {
        if i > 0 { guard out.try_push(',' as u8) else { return false; } }
        guard auth_internal::serialize_jwk_key(jwks.keys[i], out) else { return false; }
    }
    guard out.try_append("]}") else { return false; }
    committed = true;
    return true;
}

// Parses a JSON Web Key Set (`{"keys":[...]}`) into `out_jwks`, zeroizing on error (RFC 7517 §5).
//
// Example:
//   json_bytes = "{\"keys\":[{\"kty\":\"oct\",\"k\":\"...\"}]}"
//   returns: true, out_jwks.keys populated
fn parse_jwks_json(json_bytes: const u8[:], out_jwks: Jwks&) -> bool {
    zeroize_jwks(out_jwks);
    guard json_bytes.validate_utf8() else { return false; }
    var reader = json::reader(json_bytes);
    guard json::peek(reader) == '{' else { return false; }

    var committed = false;
    defer if !committed { zeroize_jwks(out_jwks); };

    var seen_keys_root = false;
    var seen_root: auth_internal::SeenHeaderKey[..8] = [];
    var had_error = false;
    json::each_member(reader) { root_key =>
        var root_item = auth_internal::SeenHeaderKey { .. };
        let valid_key = !root_key.contains('\\') &&
            !auth_internal::is_header_key_present(root_key, seen_root[..]) &&
            root_item.name.try_set(root_key) &&
            seen_root.try_push(root_item);
        if !valid_key {
            had_error = true;
            json::skip(reader);
        } else if root_key == "keys" {
            auth_internal::parse_jwks_keys_array(reader, out_jwks, seen_keys_root, had_error);
        } else {
            json::skip(reader);
        }
    };
    guard json::finish(reader) && !had_error && seen_keys_root && out_jwks.keys.len > 0 else { return false; }
    committed = true;
    return true;
}

// Resolves a verification key index in `jwks` by `kid`, allowing anonymous lookup only when single keyless JWK exists.
fn resolve_jwks_key_index(jwks: const Jwks&, kid: const u8[:]) -> i64, bool {
    if kid.len > 0 {
        return find_key(jwks, kid);
    }
    if jwks.keys.len == 1 && jwks.keys[0].valid && jwks.keys[0].kid.len == 0 {
        return 0, true;
    }
    return 0, false;
}

// Verifies a compact JWT against `jwks` using `kid` dispatch, clearing `out_claims` on any error.
fn verify_jwt(
    jwks:         const Jwks&,
    token:        const u8[:],
    options:      const JwtValidationOptions&,
    now_unix_sec: i64,
    out_header:   JwtHeader&,
    out_claims:   JwtClaims&,
) -> JwtError {
    var err = JwtError.MalformedToken;
    defer if err != JwtError.None {
        out_claims = JwtClaims { .. };
    };
    var hdr = JwtHeader { .. };
    err = parse_jwt_header_only(token, hdr);
    guard err == JwtError.None else { return err; }

    err = auth_internal::verify_jwt_header_rules(hdr, options);
    guard err == JwtError.None else { return err; }

    let idx, found = resolve_jwks_key_index(jwks, hdr.kid[..]);
    guard found else {
        err = JwtError.KeyNotFound;
        return err;
    }

    err = auth_internal::dispatch_jwks_verification(
        token,
        jwks.keys[idx],
        hdr.alg,
        options,
        now_unix_sec,
        out_header,
        out_claims,
    );
    return err;
}

// Zeroizes all keys inside `jwks` and clears the key array.
fn zeroize_jwks(jwks: Jwks&) {
    for &k in jwks.keys {
        zeroize_jwks_key(k);
    }
    jwks.keys.clear();
}

// RFC 8725 Section 3.12: Validates that a remote JWKS URL uses HTTPS and targets no internal/SSRF host.
fn is_safe_remote_jwks_url(raw_url: const u8[:]) -> bool {
    guard raw_url.len > 0 && raw_url.len <= 2048 else { return false; }
    let view, err = core::parse_url_view(raw_url);
    guard err == core::UrlParseError.None && view.valid && view.host.len > 0 && view.host.len <= 255 else {
        return false;
    }
    guard view.scheme.eq_ascii_fold("https") else { return false; }
    guard view.username.len == 0 && view.password.len == 0 else { return false; }
    guard view.port < 0 || view.port == 443 else { return false; }

    var norm_host: u8[..256] = [];
    view.host.to_lower_ascii(norm_host);
    let trimmed_host = norm_host[..].trim_end_byte('.');
    guard trimmed_host.len > 0 else { return false; }
    return !security::is_forbidden_internal_host(trimmed_host);
}
