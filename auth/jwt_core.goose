// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Core JWT types constructors, claim/header accessors, and signature primitives (RFC 7515 / RFC 7518 / RFC 7519).
namespace auth;

import std;
import core from "..";
import rfc.http;
import .types;
import .internal;

// RFC 7518 Section 3: Cryptographic Algorithms for Digital Signatures and MACs.
//
// Example:
//   s = "EdDSA"
//   returns: JwtAlg.EdDSA
fn parse_jwt_alg(s: const u8[:]) -> JwtAlg {
    if s == "none" { return JwtAlg.None; }
    if s == "HS256" { return JwtAlg.HS256; }
    if s == "HS384" { return JwtAlg.HS384; }
    if s == "HS512" { return JwtAlg.HS512; }
    if s == "EdDSA" { return JwtAlg.EdDSA; }
    if s == "ES256" { return JwtAlg.ES256; }
    if s == "RS256" { return JwtAlg.RS256; }
    if s == "PS256" { return JwtAlg.PS256; }
    return JwtAlg.Unknown;
}

// Constructs a default JOSE header with the specified algorithm and optional Key ID (`kid`).
fn new_jwt_header(alg: JwtAlg = JwtAlg.HS256, kid: const u8[:] = "") -> JwtHeader {
    var header = JwtHeader { alg: alg, .. };
    if kid.len > 0 && kid.len <= 64 {
        header.kid.append(kid);
    }
    return header;
}

// Appends a critical header parameter name to `header.crit` (RFC 7515 Section 4.1.11).
fn add_header_crit(header: JwtHeader&, name: const u8[:]) -> bool {
    return auth_internal::append_unique_crit_param(header.crit, name);
}

// Serializes `header` into compact JSON bytes appended to `out` (RFC 7515 Section 4).
fn serialize_jwt_header<B>(header: const JwtHeader&, out: B&) -> bool {
    let saved_len = out.len;
    var committed = false;
    defer if !committed { out.resize(saved_len); };
    guard out.try_append("{\"alg\":") else { return false; }
    core::format_json_string(out, auth_internal::jwt_alg_to_string(header.alg));
    if header.typ.len > 0 {
        guard out.try_append(",\"typ\":") else { return false; }
        core::format_json_string(out, header.typ[..]);
    }
    if header.kid.len > 0 {
        guard out.try_append(",\"kid\":") else { return false; }
        core::format_json_string(out, header.kid[..]);
    }
    if header.cty.len > 0 {
        guard out.try_append(",\"cty\":") else { return false; }
        core::format_json_string(out, header.cty[..]);
    }
    if header.crit.len > 0 {
        guard out.try_append(",\"crit\":[") else { return false; }
        for i in header.crit.len {
            if i > 0 { guard out.try_push(',' as u8) else { return false; } }
            core::format_json_string(out, header.crit[i].name[..]);
        }
        guard out.try_push(']' as u8) else { return false; }
    }
    if header.has_b64 || !header.b64 {
        let b64_lit = if header.b64 { ",\"b64\":true" } else { ",\"b64\":false" };
        guard out.try_append(b64_lit) else { return false; }
    }
    guard out.try_push('}' as u8) else { return false; }
    committed = true;
    return true;
}

// Replaces all audiences on `claims` with a single `aud` value (RFC 7519 Section 4.1.3).
fn set_audience(claims: JwtClaims&, aud: const u8[:]) -> bool {
    guard aud.len > 0 && aud.len <= 128 else { return false; }
    claims.aud.clear();
    claims.aud.append(aud);
    claims.audiences.clear();
    var entry: u8[..128] = [];
    entry.append(aud);
    claims.audiences.push(entry);
    return true;
}

// Appends an audience entry to `claims` (RFC 7519 Section 4.1.3).
fn add_audience(claims: JwtClaims&, aud: const u8[:]) -> bool {
    guard aud.len > 0 && aud.len <= 128 && claims.audiences.len < 8 else { return false; }
    var entry: u8[..128] = [];
    entry.append(aud);
    claims.audiences.push(entry);
    if claims.aud.len == 0 {
        claims.aud.append(aud);
    }
    return true;
}

// Sets a string custom claim on `claims`, replacing any prior value with the same `key`.
fn set_claim(claims: JwtClaims&, key: const u8[:], val: const u8[:]) -> bool {
    guard key.len > 0 && !rfc::is_jwt_standard_claim_name(key) else { return false; }
    guard key.len <= 64 && val.len <= 256 else { return false; }
    for &c in claims.custom_claims {
        if c.key[..] == key {
            c.val_str.clear();
            c.val_str.append(val);
            c.val_num = 0;
            c.val_bool = false;
            c.is_num = false;
            c.is_bool = false;
            return true;
        }
    }
    guard claims.custom_claims.len < 16 else { return false; }
    var item = JwtClaimItem { .. };
    item.key.append(key);
    item.val_str.append(val);
    claims.custom_claims.push(item);
    return true;
}

// Sets an integer custom claim on `claims`, replacing any prior value with the same `key`.
fn set_claim_int(claims: JwtClaims&, key: const u8[:], val: i64) -> bool {
    guard key.len > 0 && !rfc::is_jwt_standard_claim_name(key) && key.len <= 64 else { return false; }
    for &c in claims.custom_claims {
        if c.key[..] == key {
            c.val_str.clear();
            c.val_num = val;
            c.val_bool = false;
            c.is_num = true;
            c.is_bool = false;
            return true;
        }
    }
    guard claims.custom_claims.len < 16 else { return false; }
    var item = JwtClaimItem { val_num: val, is_num: true, .. };
    item.key.append(key);
    claims.custom_claims.push(item);
    return true;
}

// Sets a boolean custom claim on `claims`, replacing any prior value with the same `key`.
fn set_claim_bool(claims: JwtClaims&, key: const u8[:], val: bool) -> bool {
    guard key.len > 0 && !rfc::is_jwt_standard_claim_name(key) && key.len <= 64 else { return false; }
    for &c in claims.custom_claims {
        if c.key[..] == key {
            c.val_str.clear();
            c.val_num = 0;
            c.val_bool = val;
            c.is_num = false;
            c.is_bool = true;
            return true;
        }
    }
    guard claims.custom_claims.len < 16 else { return false; }
    var item = JwtClaimItem { val_bool: val, is_bool: true, .. };
    item.key.append(key);
    claims.custom_claims.push(item);
    return true;
}

// Retrieves a string claim (`iss`, `sub`, `aud`, `jti`, or custom string claim) from `claims`, returning "" if absent.
fn claim_str(claims: const JwtClaims&, key: const u8[:]) -> const u8[:] {
    if key == "iss" {
        let s = claims.iss[..];
        return s;
    }
    if key == "sub" {
        let s = claims.sub[..];
        return s;
    }
    if key == "aud" {
        let s = claims.aud[..];
        return s;
    }
    if key == "jti" {
        let s = claims.jti[..];
        return s;
    }
    for &c in claims.custom_claims {
        if c.key[..] == key && !c.is_num && !c.is_bool {
            return c.val_str[..];
        }
    }
    return "";
}

// Retrieves an integer custom claim from `claims`.
fn claim_int(claims: const JwtClaims&, key: const u8[:]) -> i64, bool {
    for &c in claims.custom_claims {
        if c.key[..] == key && c.is_num {
            return c.val_num, true;
        }
    }
    return 0, false;
}

// Retrieves a boolean custom claim from `claims`.
fn claim_bool(claims: const JwtClaims&, key: const u8[:]) -> bool, bool {
    for &c in claims.custom_claims {
        if c.key[..] == key && c.is_bool {
            return c.val_bool, true;
        }
    }
    return false, false;
}

// Serializes `claims` into compact JSON appended to `out` (RFC 7519 Section 4).
fn serialize_jwt_claims<B>(claims: const JwtClaims&, out: B&) -> bool {
    let saved_len = out.len;
    var committed = false;
    defer if !committed { out.resize(saved_len); };
    guard out.try_push('{' as u8) else { return false; }
    var first = true;
    guard auth_internal::append_json_str_member("iss", claims.iss[..], first, out) else { return false; }
    guard auth_internal::append_json_str_member("sub", claims.sub[..], first, out) else { return false; }
    guard auth_internal::append_json_str_member("jti", claims.jti[..], first, out) else { return false; }
    guard auth_internal::serialize_audiences_member(claims, first, out) else { return false; }
    guard auth_internal::append_json_int_member("exp", claims.exp, first, out) else { return false; }
    guard auth_internal::append_json_int_member("nbf", claims.nbf, first, out) else { return false; }
    guard auth_internal::append_json_int_member("iat", claims.iat, first, out) else { return false; }
    for &c in claims.custom_claims {
        guard auth_internal::serialize_custom_claim(c, first, out) else { return false; }
    }
    guard out.try_push('}' as u8) else { return false; }
    committed = true;
    return true;
}

// Constructs default strict JWT validation options requiring `expected_alg` and `exp`.
fn default_jwt_validation_options(expected_alg: JwtAlg = JwtAlg.HS256) -> JwtValidationOptions {
    return JwtValidationOptions { expected_alg: expected_alg, .. };
}

// Registers a supported critical header parameter name (`crit`) in `opts` (RFC 7515 Section 4.1.11).
fn add_supported_crit(opts: JwtValidationOptions&, name: const u8[:]) -> bool {
    return auth_internal::append_unique_crit_param(opts.supported_crit, name);
}

// Splits compact JWS/JWT "<header>.<claims>.<signature>" into its two dot indices (RFC 7515 Section 7.1).
//
// Example:
//   token = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.sig"
//   returns: dot1 = 20, dot2 = 39, ok = true
fn split_jwt_parts(token: const u8[:]) -> i64, i64, bool {
    guard token.len >= 3 && token.len <= MAX_JWT_TOKEN_LEN else { return 0, 0, false; }
    var d1: i64 = -1;
    var d2: i64 = -1;
    for i in token.len {
        if token[i] == '.' {
            if d1 == -1 {
                d1 = i;
            } else if d2 == -1 {
                d2 = i;
            } else {
                return 0, 0, false;
            }
        }
    }
    guard d1 > 0 && d1 <= MAX_JWT_HEADER_PART_LEN else { return 0, 0, false; }
    guard d2 > d1 + 1 && (d2 - d1 - 1) <= MAX_JWT_CLAIMS_PART_LEN else { return 0, 0, false; }
    return d1, d2, true;
}

// RFC 7519 Section 4.1.4: "exp" (Expiration Time) Claim - checks expiration with bounded leeway.
fn validate_jwt_expiration(exp: i64, require_exp: bool, leeway: i64, now_unix_sec: i64) -> bool {
    if exp == -1 { return !require_exp; }
    if exp < 0 { return false; }
    let safe_leeway = max(leeway, 0);
    return core::sub_sat_i64(now_unix_sec, safe_leeway) <= exp;
}

// RFC 7519 Section 4.1.5: "nbf" (Not Before) Claim - checks activation time with bounded leeway.
fn validate_jwt_not_before(nbf: i64, require_nbf: bool, leeway: i64, now_unix_sec: i64) -> bool {
    if nbf == -1 { return !require_nbf; }
    if nbf < 0 { return false; }
    let safe_leeway = max(leeway, 0);
    return core::add_sat_i64(now_unix_sec, safe_leeway) >= nbf;
}

// RFC 8725 Section 3.1: Verify the Algorithm - prevents alg="none" and algorithm confusion attacks.
fn verify_jwt_algorithm(header_alg: JwtAlg, expected_alg: JwtAlg, allow_none: bool) -> JwtError {
    if header_alg == JwtAlg.Unknown || header_alg == JwtAlg.Unspecified {
        return JwtError.UnsupportedAlgorithm;
    }
    if header_alg == JwtAlg.None {
        return if allow_none { JwtError.None } else { JwtError.UnsupportedAlgorithm };
    }
    if header_alg != expected_alg {
        return JwtError.AlgorithmMismatch;
    }
    return JwtError.None;
}

// RFC 7515 Section 4.1.9: "typ" (Type) Header Parameter - handles optional "application/" prefix per RFC.
fn is_matching_jwt_typ(header_typ: const u8[:], expected_typ: const u8[:]) -> bool {
    guard expected_typ.len > 0 else { return true; }
    guard header_typ.len > 0 else { return false; }
    if header_typ.eq_ascii_fold(expected_typ) { return true; }

    let h_slash = header_typ.index_of_byte('/');
    let e_slash = expected_typ.index_of_byte('/');
    if h_slash >= 0 && e_slash == -1 {
        let h_short, ok = header_typ.strip_prefix_fold("application/");
        return ok && h_short.index_of_byte('/') == -1 && h_short.eq_ascii_fold(expected_typ);
    }
    if e_slash >= 0 && h_slash == -1 {
        let e_short, ok = expected_typ.strip_prefix_fold("application/");
        return ok && e_short.index_of_byte('/') == -1 && header_typ.eq_ascii_fold(e_short);
    }
    return false;
}

// Verifies an HMAC-SHA2 JWS signature bytes slice in constant time (RFC 7518 Section 3.2).
fn verify_jwt_hmac_signature(
    alg:           JwtAlg,
    secret_key:    const u8[:],
    signing_input: const u8[:],
    sig_bytes:     const u8[:],
) -> bool {
    let min_len = auth_internal::hmac_min_key_len(alg);
    guard min_len > 0 && secret_key.len >= min_len else { return false; }
    if alg == JwtAlg.HS256 {
        guard sig_bytes.len == rfc::HMAC_SHA256_MAC_LEN else { return false; }
        var mac = core::hmac_sha256(secret_key, signing_input);
        defer core::secure_zeroize_32(mac);
        return core::ct_eq_bytes(mac[..], sig_bytes);
    }
    if alg == JwtAlg.HS384 {
        guard sig_bytes.len == rfc::HMAC_SHA384_MAC_LEN else { return false; }
        var mac = core::hmac_sha384(secret_key, signing_input);
        defer core::secure_zeroize_48(mac);
        return core::ct_eq_bytes(mac[..], sig_bytes);
    }
    if alg == JwtAlg.HS512 {
        guard sig_bytes.len == rfc::HMAC_SHA512_MAC_LEN else { return false; }
        var mac = core::hmac_sha512(secret_key, signing_input);
        defer core::secure_zeroize_64(mac);
        return core::ct_eq_bytes(mac[..], sig_bytes);
    }
    return false;
}

// Verifies an Ed25519 JWS signature bytes slice (RFC 8037 Section 3.1).
fn verify_jwt_eddsa_signature(
    public_key:    const u8[32],
    signing_input: const u8[:],
    sig_bytes:     const u8[:],
) -> bool {
    guard sig_bytes.len == 64 else { return false; }
    var sig64: u8[64] = [0; 64];
    for i in 64 { sig64[i] = sig_bytes[i]; }
    return core::ed25519_verify(public_key, signing_input, sig64);
}

// Verifies an RSASSA-PKCS1-v1_5 or RSASSA-PSS SHA-256 JWS signature (RFC 7518 Sections 3.3 / 3.5).
fn verify_jwt_rsa_signature(
    alg:           JwtAlg,
    n_be:          const u8[:],
    e_be:          const u8[:],
    signing_input: const u8[:],
    sig_bytes:     const u8[:],
) -> bool {
    if alg == JwtAlg.RS256 {
        return core::rsa_pkcs1_sha256_verify(n_be, e_be, signing_input, sig_bytes);
    }
    if alg == JwtAlg.PS256 {
        return core::rsa_pss_sha256_verify(n_be, e_be, signing_input, sig_bytes);
    }
    return false;
}
