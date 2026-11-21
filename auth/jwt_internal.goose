// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Internal JSON parsing, claim serialization, and signature-input helpers for JWT.
namespace auth_internal;

import std;
import json;
import core;
import rfc.http;
import .types;
import .internal;
import .jwt_core;

// Parses `"crit"` string array into `out_crit`, rejecting duplicates and empty entries (RFC 7515 §4.1.11).
//
// Example:
//   reader at "[\"b64\"]"
//   sets: out_crit[0].name = "b64", had_error = false
inline fn parse_crit_header_elements(
    reader:    json::Reader&,
    out_crit:  auth::CritParam[..8]&,
    had_error: bool&,
) {
    guard json::peek(reader) == '[' else {
        json::skip(reader);
        had_error = true;
        return;
    }
    var count: i64 = 0;
    json::each_element(reader) {
        count = core::add_sat_i64(count, 1);
        var cp_item = auth::CritParam { .. };
        if json::peek(reader) != '"' || !core::read_json_string_into(reader, cp_item.name) || cp_item.name.len == 0 {
            if json::peek(reader) != '"' { json::skip(reader); }
            had_error = true;
        } else {
            for &prev in out_crit {
                if prev.name[..] == cp_item.name[..] { had_error = true; }
            }
            if !out_crit.try_push(cp_item) { had_error = true; }
        }
    };
    if count == 0 { had_error = true; }
}

// Reads a unique non-empty JOSE header string member into `dst`.
//
// Example:
//   reader at "\"JWT\"", seen = false
//   sets: dst = "JWT", seen = true, had_error = false
inline fn parse_jwt_header_str<B>(
    reader:    json::Reader&,
    dst:       B&,
    seen:      bool&,
    had_error: bool&,
) {
    if seen || json::peek(reader) != '"' {
        json::skip(reader);
        had_error = true;
        return;
    }
    seen = true;
    if !core::read_json_string_into(reader, dst) || dst.len == 0 {
        had_error = true;
    }
}

// Parses a single JOSE header JSON object member (RFC 7515 §4 / RFC 7797 §3).
//
// Example:
//   key = "alg", reader at "\"HS256\""
//   sets: header.alg = JwtAlg.HS256, seen_alg = true
fn parse_jwt_header_member(
    key:         const u8[:],
    reader:      json::Reader&,
    header:      auth::JwtHeader&,
    seen_alg:    bool&,
    seen_typ:    bool&,
    seen_kid:    bool&,
    seen_cty:    bool&,
    seen_crit:   bool&,
    seen_b64:    bool&,
    seen_others: SeenHeaderKey[..8]&,
    had_error:   bool&,
) {
    if key.contains('\\') {
        had_error = true;
        json::skip(reader);
        return;
    }
    if key == "alg" {
        var alg_buf: u8[..32] = [];
        parse_jwt_header_str(reader, alg_buf, seen_alg, had_error);
        if !had_error { header.alg = auth::parse_jwt_alg(alg_buf[..]); }
        return;
    }
    if key == "typ" { parse_jwt_header_str(reader, header.typ, seen_typ, had_error); return; }
    if key == "kid" { parse_jwt_header_str(reader, header.kid, seen_kid, had_error); return; }
    if key == "cty" { parse_jwt_header_str(reader, header.cty, seen_cty, had_error); return; }
    if key == "crit" {
        if seen_crit { had_error = true; json::skip(reader); return; }
        seen_crit = true;
        parse_crit_header_elements(reader, header.crit, had_error);
        return;
    }
    if key == "b64" {
        let p = json::peek(reader);
        if seen_b64 || (p != 't' && p != 'f') {
            had_error = true;
            json::skip(reader);
            return;
        }
        seen_b64 = true;
        header.b64 = json::read_bool(reader);
        header.has_b64 = true;
        var b64_item = SeenHeaderKey { .. };
        let _ = b64_item.name.try_set("b64");
        if !seen_others.try_push(b64_item) { had_error = true; }
        return;
    }
    if is_header_key_present(key, seen_others[..]) {
        had_error = true;
    } else {
        var item = SeenHeaderKey { .. };
        if !item.name.try_set(key) || !seen_others.try_push(item) { had_error = true; }
    }
    json::skip(reader);
}

inline fn try_append_audience_element(reader: json::Reader&, claims: auth::JwtClaims&) -> bool {
    guard json::peek(reader) == '"' else {
        json::skip(reader);
        return false;
    }
    var item: u8[..128] = [];
    guard core::read_json_string_into(reader, item) && item.len > 0 else { return false; }
    guard claims.audiences.try_push(item) else { return false; }
    if claims.aud.len == 0 {
        guard claims.aud.try_set(item[..]) else { return false; }
    }
    return true;
}

// Parses `"aud"` claim as a non-empty string or non-empty array of non-empty strings (RFC 7519 §4.1.3).
//
// Example:
//   reader at "\"https://api.example.com\""
//   sets: claims.aud = "https://api.example.com", claims.audiences[0] = "https://api.example.com"
inline fn parse_aud_claim(
    reader:    json::Reader&,
    claims:    auth::JwtClaims&,
    had_error: bool&,
) {
    let p = json::peek(reader);
    if p == '"' {
        var aud_buf: u8[..128] = [];
        if !core::read_json_string_into(reader, aud_buf) || aud_buf.len == 0 ||
            !claims.aud.try_set(aud_buf[..]) || !claims.audiences.try_push(aud_buf) {
            had_error = true;
        }
        return;
    }
    if p == '[' {
        var count: i64 = 0;
        json::each_element(reader) {
            count = core::add_sat_i64(count, 1);
            if !try_append_audience_element(reader, claims) { had_error = true; }
        };
        if count == 0 { had_error = true; }
        return;
    }
    json::skip(reader);
    had_error = true;
}

// Parses a custom JWT claim entry (string, integer, or bool; nested objects/arrays skipped cleanly).
//
// Example:
//   key = "role", reader at "\"admin\""
//   sets: claims custom_claims entry "role" = "admin"
inline fn parse_custom_claim_entry(
    key:       const u8[:],
    reader:    json::Reader&,
    claims:    auth::JwtClaims&,
    had_error: bool&,
) {
    let p = json::peek(reader);
    if p == '"' {
        var val_buf: u8[..256] = [];
        if !core::read_json_string_into(reader, val_buf) || !auth::set_claim(claims, key, val_buf[..]) {
            had_error = true;
        }
        return;
    }
    if p == 't' || p == 'f' {
        let bv = json::read_bool(reader);
        if !auth::set_claim_bool(claims, key, bv) { had_error = true; }
        return;
    }
    if p == '-' || core::is_ascii_digit(p) {
        let num = json::read_number(reader);
        if num >= -9223372036854774784.0 && num <= 9223372036854774784.0 {
            if !auth::set_claim_int(claims, key, num as i64) { had_error = true; }
        } else {
            had_error = true;
        }
        return;
    }
    json::skip(reader);
}

// Parses a NumericDate standard claim (`exp`, `nbf`, or `iat`) with duplicate and range checks (RFC 7519 §2).
//
// Example:
//   reader at "1700000000", seen = false
//   sets: dst = 1700000000, seen = true, had_error = false
inline fn parse_jwt_numeric_date_claim(
    reader:    json::Reader&,
    dst:       i64&,
    seen:      bool&,
    had_error: bool&,
) {
    let p = json::peek(reader);
    if seen || !core::is_ascii_digit(p) {
        json::skip(reader);
        had_error = true;
        return;
    }
    seen = true;
    let num = json::read_number(reader);
    if num >= 0.0 && num <= 9223372036854774784.0 {
        dst = num as i64;
    } else {
        had_error = true;
    }
}

inline fn read_unique_jwt_str<B>(
    reader:    json::Reader&,
    dst:       B&,
    seen:      bool&,
    had_error: bool&,
) {
    if seen || json::peek(reader) != '"' {
        json::skip(reader);
        had_error = true;
        return;
    }
    seen = true;
    if !core::read_json_string_into(reader, dst) { had_error = true; }
}

// Parses registered RFC 7519 §4.1 claims (`iss`, `sub`, `aud`, `jti`, `exp`, `nbf`, `iat`).
//
// Example:
//   key = "iss", reader at "\"https://auth.example.com\""
//   sets: claims.iss = "https://auth.example.com", returns: true
inline fn parse_jwt_standard_claim(
    key:       const u8[:],
    reader:    json::Reader&,
    claims:    auth::JwtClaims&,
    seen_iss:  bool&,
    seen_sub:  bool&,
    seen_aud:  bool&,
    seen_jti:  bool&,
    seen_exp:  bool&,
    seen_nbf:  bool&,
    seen_iat:  bool&,
    had_error: bool&,
) -> bool {
    if key == "iss" { read_unique_jwt_str(reader, claims.iss, seen_iss, had_error); return true; }
    if key == "sub" { read_unique_jwt_str(reader, claims.sub, seen_sub, had_error); return true; }
    if key == "jti" { read_unique_jwt_str(reader, claims.jti, seen_jti, had_error); return true; }
    if key == "aud" {
        if seen_aud { json::skip(reader); had_error = true; return true; }
        seen_aud = true;
        parse_aud_claim(reader, claims, had_error);
        return true;
    }
    if key == "exp" { parse_jwt_numeric_date_claim(reader, claims.exp, seen_exp, had_error); return true; }
    if key == "nbf" { parse_jwt_numeric_date_claim(reader, claims.nbf, seen_nbf, had_error); return true; }
    if key == "iat" { parse_jwt_numeric_date_claim(reader, claims.iat, seen_iat, had_error); return true; }
    return false;
}

inline fn record_custom_claim(
    key:         const u8[:],
    reader:      json::Reader&,
    claims:      auth::JwtClaims&,
    seen_custom: SeenCustomKey[..64]&,
    had_error:   bool&,
) {
    if seen_custom_keys_contains(key, seen_custom[..]) {
        had_error = true;
        json::skip(reader);
        return;
    }
    var sk = SeenCustomKey { .. };
    if !sk.name.try_set(key) || !seen_custom.try_push(sk) {
        had_error = true;
        json::skip(reader);
        return;
    }
    parse_custom_claim_entry(key, reader, claims, had_error);
}

// Encodes JOSE header + claims JSON into "<b64_header>.<b64_claims>" in `out`.
fn build_jwt_signing_input<B>(
    header: const auth::JwtHeader&,
    claims: const auth::JwtClaims&,
    out:    B&,
) -> bool {
    var hdr_json: u8[..2048] = [];
    guard auth::serialize_jwt_header(header, hdr_json) else { return false; }
    var clm_json: u8[>..] = [];
    defer core::secure_zeroize_slice(clm_json[..]);
    guard auth::serialize_jwt_claims(claims, clm_json) else { return false; }

    var b64_hdr: u8[..2800] = [];
    var b64_clm: u8[>..]    = [];
    defer core::secure_zeroize_slice(b64_clm[..]);
    core::base64url_encode(hdr_json[..], b64_hdr);
    core::base64url_encode(clm_json[..], b64_clm);

    return out.try_append(b64_hdr[..]) && out.try_push('.' as u8) && out.try_append(b64_clm[..]);
}

inline fn append_jwt_hmac_signature<B>(
    alg:           auth::JwtAlg,
    secret_key:    const u8[:],
    signing_input: const u8[:],
    out:           B&,
) -> bool {
    var b64_sig: u8[..128] = [];
    defer core::secure_zeroize_slice(b64_sig[..]);
    if alg == auth::JwtAlg.HS256 {
        var mac = core::hmac_sha256(secret_key, signing_input);
        defer core::secure_zeroize_32(mac);
        core::base64url_encode(mac[..], b64_sig);
    } else if alg == auth::JwtAlg.HS384 {
        var mac = core::hmac_sha384(secret_key, signing_input);
        defer core::secure_zeroize_48(mac);
        core::base64url_encode(mac[..], b64_sig);
    } else if alg == auth::JwtAlg.HS512 {
        var mac = core::hmac_sha512(secret_key, signing_input);
        defer core::secure_zeroize_64(mac);
        core::base64url_encode(mac[..], b64_sig);
    } else {
        return false;
    }
    return out.try_push('.' as u8) && out.try_append(b64_sig[..]);
}

inline fn append_jwt_eddsa_signature<B>(
    seed_key:      const u8[32],
    signing_input: const u8[:],
    out:           B&,
) -> bool {
    var sig = core::ed25519_sign(seed_key, signing_input);
    defer core::secure_zeroize_64(sig);
    var b64_sig: u8[..128] = [];
    defer core::secure_zeroize_slice(b64_sig[..]);
    core::base64url_encode(sig[..], b64_sig);
    return out.try_push('.' as u8) && out.try_append(b64_sig[..]);
}

inline fn claims_match_audience(claims: const auth::JwtClaims&, expected: const u8[:]) -> bool {
    if claims.aud[..] == expected { return true; }
    for &a in claims.audiences {
        if a[..] == expected { return true; }
    }
    return false;
}

inline fn claims_match_issuer_allowlist(
    claims:  const auth::JwtClaims&,
    options: const auth::JwtValidationOptions&,
) -> bool {
    for &allowed in options.allowed_issuers {
        if allowed.len > 0 && claims.iss[..] == allowed[..] { return true; }
    }
    return false;
}

inline fn claims_match_audience_allowlist(
    claims:  const auth::JwtClaims&,
    options: const auth::JwtValidationOptions&,
) -> bool {
    for &allowed in options.allowed_audiences {
        if allowed.len > 0 && claims_match_audience(claims, allowed[..]) { return true; }
    }
    return false;
}

inline fn is_crit_param_supported(
    cp_name:   const u8[:],
    supported: const auth::CritParam[..8],
) -> bool {
    for &sp in supported {
        if sp.name[..] == cp_name { return true; }
    }
    return false;
}

inline fn has_crit_param_in_header(header: const auth::JwtHeader&, name: const u8[:]) -> bool {
    for &cp in header.crit {
        if cp.name[..] == name { return true; }
    }
    return false;
}

// Validates compact JWT signature segment syntax for unverified parsing (RFC 7515 §7.1).
//
// Example:
//   alg = JwtAlg.None, sig_part = "sig"
//   returns: JwtError.MalformedToken
fn check_unverified_sig_part(alg: auth::JwtAlg, sig_part: const u8[:]) -> auth::JwtError {
    if alg == auth::JwtAlg.None {
        return if sig_part.len == 0 { auth::JwtError.None } else { auth::JwtError.MalformedToken };
    }
    var sig_buf: u8[..512] = [];
    guard sig_part.len > 0 && core::base64url_decode(sig_part, sig_buf) else {
        return auth::JwtError.InvalidBase64;
    }
    return auth::JwtError.None;
}

// Verifies JOSE header algorithm, type, and critical parameter constraints (RFC 8725 §3).
fn verify_jwt_header_rules(
    header:  const auth::JwtHeader&,
    options: const auth::JwtValidationOptions&,
) -> auth::JwtError {
    let alg_err = auth::verify_jwt_algorithm(header.alg, options.expected_alg, options.allow_none_alg);
    guard alg_err == auth::JwtError.None else { return alg_err; }
    if options.expected_typ.len > 0 && !auth::is_matching_jwt_typ(header.typ[..], options.expected_typ[..]) {
        return auth::JwtError.TypeMismatch;
    }
    // RFC 7797 Section 7: Detachable/unencoded payloads ("b64": false) are prohibited in JWTs.
    if header.has_b64 && !header.b64 {
        return auth::JwtError.CriticalHeaderUnsupported;
    }
    for &cp in header.crit {
        if !is_crit_param_supported(cp.name[..], options.supported_crit) {
            return auth::JwtError.CriticalHeaderUnsupported;
        }
    }
    return auth::JwtError.None;
}
