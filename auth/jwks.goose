// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// JSON Web Key Set (JWKS / RFC 7517) container, key rotation indexing,
// integrated JWT verification, and RFC 8725 §3.12 SSRF protection for remote JWKS URLs.
namespace wing;

import std;
import json;
import core from "..";
import client.session.ssrf;
import .jwt;
import .jwk;

// ---- JWKS Key Set Container ----------------------------------------------

struct Jwks {
    keys: JwksKey[..16] = [],
}

// Registers an asymmetric Ed25519 public key in the key set
fn add_ed25519_key(
    jwks:    Jwks&,
    kid:     const u8[:],
    pub_key: const u8[32],
) -> bool {
    var key = JwksKey {
        kty:        JwkKeyType.OKP,
        crv:        "Ed25519",
        alg:        JwtAlg.EdDSA,
        use:        "sig",
        public_key: pub_key,
        valid:      true,
        ..
    };
    guard key.kid.try_set(kid) else { return false; }
    return jwks.keys.try_push(key);
}

// Registers an asymmetric ECDSA P-256 public key in the key set (RFC 7518 §6.2).
fn add_es256_key(
    jwks: Jwks&,
    kid:  const u8[:],
    x:    const u8[:],
    y:    const u8[:],
) -> bool {
    guard is_valid_jwk_ec_p256_coords(x, y) else { return false; }
    var key = JwksKey {
        kty:   JwkKeyType.EC,
        crv:   "P-256",
        alg:   JwtAlg.ES256,
        use:   "sig",
        valid: true,
        ..
    };
    guard key.kid.try_set(kid) && key.ec_x.try_set(x) && key.ec_y.try_set(y) else { return false; }
    return jwks.keys.try_push(key);
}

// Registers an asymmetric RSA public key in the key set (RFC 7518 §6.3).
fn add_rsa_key(
    jwks: Jwks&,
    kid:  const u8[:],
    alg:  JwtAlg,
    n_be: const u8[:],
    e_be: const u8[:],
) -> bool {
    guard is_canonical_jwk_rsa_params(n_be, e_be) else { return false; }
    guard alg == JwtAlg.Unspecified || alg == JwtAlg.RS256 || alg == JwtAlg.PS256 else { return false; }
    var key = JwksKey {
        kty:   JwkKeyType.RSA,
        alg:   alg,
        use:   "sig",
        valid: true,
        ..
    };
    guard key.kid.try_set(kid) && key.rsa_n.try_set(n_be) && key.rsa_e.try_set(e_be) else { return false; }
    return jwks.keys.try_push(key);
}

// Registers a symmetric HMAC secret key in the key set
fn add_symmetric_key(
    jwks:       Jwks&,
    kid:        const u8[:],
    alg:        JwtAlg,
    secret_key: const u8[:],
) -> bool {
    guard secret_key.len >= 16 && secret_key.len <= 64 else { return false; }
    guard alg == JwtAlg.Unspecified || alg == JwtAlg.HS256 || alg == JwtAlg.HS384 || alg == JwtAlg.HS512 else {
        return false;
    }
    var key = JwksKey {
        kty:   JwkKeyType.Oct,
        crv:   "",
        alg:   alg,
        use:   "sig",
        valid: true,
        ..
    };
    guard key.kid.try_set(kid) && key.symmetric_key.try_set(secret_key) else { return false; }
    return jwks.keys.try_push(key);
}

// Finds the index of a key by kid (-1 if not found)
fn find_key(jwks: const Jwks&, kid: const u8[:]) -> i32 {
    for i in jwks.keys.len {
        let k = jwks.keys[i];
        if k.valid && k.kid[..] == kid {
            return i as i32;
        }
    }
    return -1;
}

// ---- JWKS Serialization & Parsing (RFC 7517) ------------------------------

// Serializes a JWKS struct into RFC 7517 JSON format: `{"keys": [ {...}, ... ]}`
fn serialize_jwks<B>(jwks: const Jwks&, out: B&) {
    out.append("{\"keys\":[");
    var first = true;
    for &k in jwks.keys {
        if !k.valid { continue; }
        if !first { out.push(','); }
        first = false;
        serialize_jwk_key(k, out);
    }
    out.append("]}");
}

// Parses and validates a single JWK key object from the "keys" JSON array.
//
// Example:
//   reader positioned at {"kty":"OKP", ...}
//   appends validated key to out_jwks, returns: true
fn parse_single_jwk_element(
    reader:   json::Reader&,
    out_jwks: Jwks&,
) -> bool {
    var key_item = JwksKey { .. };
    var mat = JwkRawMaterial { .. };
    defer zeroize_jwks_key(key_item);
    defer core::secure_zeroize_slice(mat.raw_k[..]);

    parse_jwk_key_fields(reader, mat, key_item);
    return finalize_jwk_key(mat, key_item) && out_jwks.keys.try_push(key_item);
}

// Parses an RFC 7517 JWKS JSON document into Jwks struct.
//
// Example:
//   json_bytes = "{\"keys\":[{\"kty\":\"OKP\",\"crv\":\"Ed25519\",\"x\":\"...\"}]}"
//   returns: true, out_jwks.keys.len = 1
fn parse_jwks_json(json_bytes: const u8[:], out_jwks: Jwks&) -> bool {
    out_jwks.keys.clear();
    var reader = json::reader(json_bytes);
    var seen_keys_root = false;
    var had_error = false;

    json::each_member(reader) { root_key =>
        if root_key.contains('\\') {
            had_error = true;
            json::skip(reader);
        } else if root_key == "keys" && !seen_keys_root && json::peek(reader) == '[' {
            seen_keys_root = true;
            json::each_element(reader) {
                let elem_ok = parse_single_jwk_element(reader, out_jwks);
                had_error = had_error || !elem_ok;
            };
        } else {
            if root_key == "keys" { had_error = true; }
            json::skip(reader);
        }
    };

    guard json::finish(reader) && !had_error && seen_keys_root && out_jwks.keys.len > 0 else {
        zeroize_jwks(out_jwks);
        return false;
    }
    return true;
}

// ---- Integrated JWKS JWT Verification -------------------------------------

fn resolve_jwks_key_index(jwks: const Jwks&, kid: const u8[:]) -> i64 {
    if kid.len > 0 {
        return find_key(jwks, kid);
    }
    if jwks.keys.len == 1 && jwks.keys[0].valid && jwks.keys[0].kid.len == 0 {
        return 0;
    }
    return -1;
}

fn is_kty_alg_compatible(kty: JwkKeyType, alg: JwtAlg) -> bool {
    return match kty {
        OKP => alg == JwtAlg.EdDSA,
        Oct => (alg == JwtAlg.HS256 || alg == JwtAlg.HS384 || alg == JwtAlg.HS512),
        EC => alg == JwtAlg.ES256,
        RSA => (alg == JwtAlg.RS256 || alg == JwtAlg.PS256),
        Unknown => false,
    };
}

fn is_valid_key_use(use: const u8[:]) -> bool {
    return use.len == 0 || use == "sig";
}

fn validate_jwks_key_compatibility(
    key:        const JwksKey&,
    header_alg: JwtAlg,
    allow_none: bool,
) -> JwtError {
    guard is_valid_key_use(key.use[..]) else {
        return JwtError.UnsupportedAlgorithm;
    }
    if key.key_ops != 0 && (key.key_ops & JWK_OP_VERIFY) == 0 {
        return JwtError.UnsupportedAlgorithm;
    }
    if header_alg == JwtAlg.Unknown {
        return JwtError.UnsupportedAlgorithm;
    }
    if header_alg == JwtAlg.None && !allow_none {
        return JwtError.UnsupportedAlgorithm;
    }
    // RFC 8725 §3.2: Key Confusion Defense (Asymmetric vs Symmetric)
    guard is_kty_alg_compatible(key.kty, header_alg) else {
        return JwtError.AlgorithmMismatch;
    }
    if key.alg != JwtAlg.Unspecified && key.alg != header_alg {
        return JwtError.AlgorithmMismatch;
    }
    return JwtError.None;
}

fn verify_jwks_ec_key(
    token:        const u8[:],
    key:          const JwksKey&,
    options:      const JwtValidationOptions&,
    now_unix_sec: i64,
    out_header:   JwtHeader&,
    out_claims:   JwtClaims&,
) -> JwtError {
    var pub_pt: u8[..65] = [];
    pub_pt.push(0x04);
    pub_pt.append(key.ec_x[..]);
    pub_pt.append(key.ec_y[..]);
    return verify_jwt_es256(token, pub_pt[..], options, now_unix_sec, out_header, out_claims);
}

fn dispatch_jwks_verification(
    token:        const u8[:],
    key:          const JwksKey&,
    header_alg:   JwtAlg,
    options:      const JwtValidationOptions&,
    now_unix_sec: i64,
    out_header:   JwtHeader&,
    out_claims:   JwtClaims&,
) -> JwtError {
    let compat_err = validate_jwks_key_compatibility(key, header_alg, options.allow_none_alg);
    guard compat_err == JwtError.None else { return compat_err; }

    return match key.kty {
        OKP => verify_jwt_eddsa(token, key.public_key, options, now_unix_sec, out_header, out_claims),
        Oct => verify_jwt_hmac(token, key.symmetric_key[..], options, now_unix_sec, out_header, out_claims),
        EC => verify_jwks_ec_key(token, key, options, now_unix_sec, out_header, out_claims),
        RSA => verify_jwt_rsa(token, key.rsa_n[..], key.rsa_e[..], options, now_unix_sec, out_header, out_claims),
        Unknown => JwtError.KeyNotFound,
    };
}

// Verifies a JWT against a JWKS key set.
// Uses the `kid` in the JWT header to locate the active key and performs signature & claims validation.
fn verify(
    token:        const u8[:],
    jwks:         const Jwks&,
    options:      const JwtValidationOptions&,
    now_unix_sec: i64,
    out_header:   JwtHeader&,
    out_claims:   JwtClaims&,
) -> JwtError {
    var temp_header = JwtHeader { .. };
    let parse_err = parse_jwt_header_only(token, temp_header);
    guard parse_err == JwtError.None else { return parse_err; }

    let key_idx = resolve_jwks_key_index(jwks, temp_header.kid[..]);
    guard key_idx >= 0 && key_idx < jwks.keys.len else {
        return JwtError.KeyNotFound;
    }

    let matched_key = jwks.keys[key_idx];
    guard matched_key.valid else { return JwtError.KeyNotFound; }

    return dispatch_jwks_verification(
        token, matched_key, temp_header.alg, options, now_unix_sec, out_header, out_claims,
    );
}

// Securely wipes all cryptographic keys in the JWKS set.
fn zeroize_jwks(jwks: Jwks&) {
    for i in jwks.keys.len {
        zeroize_jwks_key(jwks.keys[i]);
    }
    jwks.keys.clear();
}

// ---- SSRF Protection for Remote JWKS & OIDC Discovery (RFC 8725 §3.12) --

// Evaluates whether a remote JWKS URL is safe for network retrieval (RFC 8725 §3.12).
// Defends against SSRF, internal network scanning, cloud metadata exfiltration, and credential leaks.
//
// Example:
//   raw_url = "https://auth.example.com/.well-known/jwks.json"
//   returns: true
fn is_safe_remote_jwks_url(raw_url: const u8[:]) -> bool {
    guard raw_url.len > 0 && raw_url.len <= 2048 else { return false; }
    let view, err = core::parse_url_view(raw_url);
    guard err == core::UrlParseError.None && view.valid else { return false; }
    guard view.scheme == "https" else { return false; }
    guard view.username.len == 0 && view.password.len == 0 else { return false; }
    guard view.port < 0 || view.port == 443 else { return false; }
    guard view.host.len > 0 && view.host.len <= 255 else { return false; }

    var norm_host: u8[..256] = [];
    view.host.to_lower_ascii(norm_host);
    let trimmed_host = norm_host[..].trim_end_byte('.');
    guard trimmed_host.len > 0 else { return false; }
    return !is_forbidden_internal_host(trimmed_host);
}
