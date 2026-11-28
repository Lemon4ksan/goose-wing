// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// JSON Web Token (JWT/JWS) signing, parsing, and verification (RFC 7515 / RFC 7519 / RFC 8725).
namespace auth;

import std;
import json;
import core;
import rfc.http;
import .types;
import .internal;
import .jwt_core;
import .jwt_internal;

// Parses a JOSE header JSON object into `out_header`, resetting `out_header` on failure (RFC 7515 §4).
//
// Example:
//   json_bytes = "{\"alg\":\"HS256\",\"typ\":\"JWT\"}"
//   returns: true, out_header.alg = JwtAlg.HS256
fn parse_jwt_header_json(json_bytes: const u8[:], out_header: JwtHeader&) -> bool {
    guard json_bytes.validate_utf8() else {
        out_header = JwtHeader { .. };
        return false;
    }
    var reader = json::reader(json_bytes);
    guard json::peek(reader) == '{' else {
        out_header = JwtHeader { .. };
        return false;
    }

    var hdr = JwtHeader { .. };
    hdr.typ.clear();
    var seen_alg = false;
    var seen_typ = false;
    var seen_kid = false;
    var seen_cty = false;
    var seen_crit = false;
    var seen_b64 = false;
    var seen_others: auth_internal::SeenHeaderKey[..8] = [];
    var had_error = false;
    json::each_member(reader) { key =>
        auth_internal::parse_jwt_header_member(
            key,
            reader,
            hdr,
            seen_alg,
            seen_typ,
            seen_kid,
            seen_cty,
            seen_crit,
            seen_b64,
            seen_others,
            had_error,
        );
    };
    // RFC 7515 Section 4.1.11: Critical Header Parameters - every crit entry must appear as extension header
    // and MUST NOT reference standard JWS header parameter names.
    for &cp in hdr.crit {
        if rfc::is_standard_jws_header_param(cp.name[..])
            || !auth_internal::is_header_key_present(cp.name[..], seen_others[..]) {
            had_error = true;
        }
    }
    guard json::finish(reader) && !had_error && seen_alg else {
        out_header = JwtHeader { .. };
        return false;
    }
    out_header = hdr;
    return true;
}

// Parses JWT claims JSON into `out_claims`, resetting `out_claims` on failure (RFC 7519 §4).
//
// Example:
//   json_bytes = "{\"sub\":\"user1\",\"exp\":1800000000}"
//   returns: true, out_claims.sub = "user1"
fn parse_jwt_claims_json(json_bytes: const u8[:], out_claims: JwtClaims&) -> bool {
    guard json_bytes.validate_utf8() else {
        out_claims = JwtClaims { .. };
        return false;
    }
    var reader = json::reader(json_bytes);
    guard json::peek(reader) == '{' else {
        out_claims = JwtClaims { .. };
        return false;
    }

    var claims = JwtClaims { .. };
    var seen_iss = false;
    var seen_sub = false;
    var seen_aud = false;
    var seen_jti = false;
    var seen_exp = false;
    var seen_nbf = false;
    var seen_iat = false;
    var seen_cnf = false;
    var seen_custom: auth_internal::SeenCustomKey[..64] = [];
    var had_error = false;
    json::each_member(reader) { key =>
        if key.contains('\\') {
            had_error = true;
            json::skip(reader);
        } else if key == "cnf" {
            auth_internal::parse_jwt_cnf_claim(reader, claims, seen_cnf, had_error);
        } else if !auth_internal::parse_jwt_standard_claim(
            key,
            reader,
            claims,
            seen_iss,
            seen_sub,
            seen_aud,
            seen_jti,
            seen_exp,
            seen_nbf,
            seen_iat,
            had_error,
        ) {
            auth_internal::record_custom_claim(key, reader, claims, seen_custom, had_error);
        }
    };
    guard json::finish(reader) && !had_error else {
        out_claims = JwtClaims { .. };
        return false;
    }
    if json_bytes.len <= 2048 {
        claims.raw_payload.append(json_bytes);
    }
    out_claims = claims;
    return true;
}

// Validates issuer, audience, and subject claims against `options` (RFC 7519 Section 4.1).
fn validate_jwt_identity_claims(claims: const JwtClaims&, options: const JwtValidationOptions&) -> JwtError {
    if options.expected_issuer.len > 0 {
        guard claims.iss[..] == options.expected_issuer[..] else { return JwtError.IssuerMismatch; }
    } else if options.allowed_issuers.len > 0 {
        guard auth_internal::claims_match_issuer_allowlist(claims, options) else { return JwtError.IssuerMismatch; }
    }

    if options.expected_audience.len > 0 {
        guard auth_internal::claims_match_audience(claims, options.expected_audience[..]) else {
            return JwtError.AudienceMismatch;
        }
    } else if options.allowed_audiences.len > 0 {
        guard auth_internal::claims_match_audience_allowlist(claims, options) else {
            return JwtError.AudienceMismatch;
        }
    } else if options.validate_aud_when_present && (claims.aud.len > 0 || claims.audiences.len > 0) {
        return JwtError.AudienceMismatch;
    }

    if options.expected_subject.len > 0 {
        guard claims.sub[..] == options.expected_subject[..] else { return JwtError.SubjectMismatch; }
    }
    return JwtError.None;
}

// Validates temporal and identity claims against `options` at `now_unix_sec` (RFC 8725 §3).
fn validate_jwt_claims_rules(
    claims:       const JwtClaims&,
    options:      const JwtValidationOptions&,
    now_unix_sec: i64,
) -> JwtError {
    guard validate_jwt_expiration(claims.exp, options.require_exp, options.leeway_seconds, now_unix_sec) else {
        return JwtError.TokenExpired;
    }
    if options.min_remaining_ttl_seconds > 0 {
        guard claims.exp >= 0 && claims.exp >= core::add_sat_i64(now_unix_sec, options.min_remaining_ttl_seconds) else {
            return JwtError.TokenExpired;
        }
    }
    guard validate_jwt_not_before(claims.nbf, options.require_nbf, options.leeway_seconds, now_unix_sec) else {
        return JwtError.TokenNotYetValid;
    }
    return validate_jwt_identity_claims(claims, options);
}

// Signs a JWT using HMAC-SHA256/384/512 and writes compact JWS to `out` (RFC 7518 §3.2).
fn sign_jwt_hmac<B>(
    header:     const JwtHeader&,
    claims:     const JwtClaims&,
    secret_key: const u8[:],
    out:        B&,
) -> bool {
    let min_len = auth_internal::hmac_min_key_len(header.alg);
    guard min_len > 0 && secret_key.len >= min_len else { return false; }

    if auth_internal::jwt_fits_stack_4096(header, claims) {
        var token_buf: u8[..4096] = [];
        defer core::secure_zeroize_slice(token_buf[..]);
        return auth_internal::finish_sign_jwt_hmac(header, claims, secret_key, token_buf, out);
    }
    var token_buf: u8[>..] = [];
    defer core::secure_zeroize_slice(token_buf[..]);
    return auth_internal::finish_sign_jwt_hmac(header, claims, secret_key, token_buf, out);
}

// Signs a JWT using Ed25519 (RFC 8037 §3.1) and writes compact JWS to `out`.
fn sign_jwt_eddsa<B>(
    header:   const JwtHeader&,
    claims:   const JwtClaims&,
    seed_key: const u8[32]&,
    out:      B&,
) -> bool {
    guard header.alg == JwtAlg.EdDSA else { return false; }

    if auth_internal::jwt_fits_stack_4096(header, claims) {
        var token_buf: u8[..4096] = [];
        defer core::secure_zeroize_slice(token_buf[..]);
        return auth_internal::finish_sign_jwt_eddsa(header, claims, seed_key, token_buf, out);
    }
    var token_buf: u8[>..] = [];
    defer core::secure_zeroize_slice(token_buf[..]);
    return auth_internal::finish_sign_jwt_eddsa(header, claims, seed_key, token_buf, out);
}

// Signs a JWT using ECDSA P-256 + SHA-256 (RFC 7518 §3.4) and writes compact JWS to `out`.
fn sign_jwt_es256<B>(
    header:   const JwtHeader&,
    claims:   const JwtClaims&,
    priv_key: const u8[32]&,
    out:      B&,
) -> bool {
    guard header.alg == JwtAlg.ES256 && core::is_valid_p256_private_key(priv_key) else { return false; }

    if auth_internal::jwt_fits_stack_4096(header, claims) {
        var token_buf: u8[..4096] = [];
        defer core::secure_zeroize_slice(token_buf[..]);
        return auth_internal::finish_sign_jwt_es256(header, claims, priv_key, token_buf, out);
    }
    var token_buf: u8[>..] = [];
    defer core::secure_zeroize_slice(token_buf[..]);
    return auth_internal::finish_sign_jwt_es256(header, claims, priv_key, token_buf, out);
}

// Signs a JWT using RSASSA-PKCS1-v1_5 SHA-256 (RFC 7518 §3.3) and writes compact JWS to `out`.
fn sign_jwt_rs256<B>(
    header: const JwtHeader&,
    claims: const JwtClaims&,
    n_be:   const u8[:],
    d_be:   const u8[:],
    out:    B&,
) -> bool {
    guard header.alg == JwtAlg.RS256 && n_be.len >= 256 && n_be.len <= 512 && (n_be[0] & 0x80) != 0 else {
        return false;
    }

    if auth_internal::jwt_fits_stack_4096(header, claims) {
        var token_buf: u8[..4096] = [];
        defer core::secure_zeroize_slice(token_buf[..]);
        return auth_internal::finish_sign_jwt_rs256(header, claims, n_be, d_be, token_buf, out);
    }
    var token_buf: u8[>..] = [];
    defer core::secure_zeroize_slice(token_buf[..]);
    return auth_internal::finish_sign_jwt_rs256(header, claims, n_be, d_be, token_buf, out);
}

// Signs a JWT using RSASSA-PSS SHA-256 (RFC 7518 §3.5) and writes compact JWS to `out`.
fn sign_jwt_ps256<B>(
    header: const JwtHeader&,
    claims: const JwtClaims&,
    n_be:   const u8[:],
    d_be:   const u8[:],
    salt:   const u8[:],
    out:    B&,
) -> bool {
    guard header.alg == JwtAlg.PS256 && n_be.len >= 256 && n_be.len <= 512 && (n_be[0] & 0x80) != 0 else {
        return false;
    }

    if auth_internal::jwt_fits_stack_4096(header, claims) {
        var token_buf: u8[..4096] = [];
        defer core::secure_zeroize_slice(token_buf[..]);
        return auth_internal::finish_sign_jwt_ps256(header, claims, n_be, d_be, salt, token_buf, out);
    }
    var token_buf: u8[>..] = [];
    defer core::secure_zeroize_slice(token_buf[..]);
    return auth_internal::finish_sign_jwt_ps256(header, claims, n_be, d_be, salt, token_buf, out);
}

// Decodes a Base64URL-encoded JWT header segment into `out_header`.
//
// Example:
//   hdr_b64 = "eyJhbGciOiJIUzI1NiJ9"
//   returns: JwtError.None, out_header.alg = JwtAlg.HS256
fn decode_jwt_header(hdr_b64: const u8[:], out_header: JwtHeader&) -> JwtError {
    guard hdr_b64.len > 0 && hdr_b64.len <= MAX_JWT_HEADER_PART_LEN && hdr_b64.index_of_byte('=') == -1 else {
        out_header = JwtHeader { .. };
        return JwtError.InvalidBase64;
    }
    var json_buf: u8[..2048] = [];
    guard core::base64url_decode(hdr_b64, json_buf) else {
        out_header = JwtHeader { .. };
        return JwtError.InvalidBase64;
    }
    guard parse_jwt_header_json(json_buf[..], out_header) else {
        return JwtError.InvalidHeaderJson;
    }
    return JwtError.None;
}

// Decodes a Base64URL-encoded JWT claims segment into `out_claims`.
//
// Example:
//   clm_b64 = "eyJzdWIiOiJ1MSJ9"
//   returns: JwtError.None, out_claims.sub = "u1"
fn decode_jwt_claims(clm_b64: const u8[:], out_claims: JwtClaims&) -> JwtError {
    guard clm_b64.len > 0 && clm_b64.len <= MAX_JWT_CLAIMS_PART_LEN && clm_b64.index_of_byte('=') == -1 else {
        out_claims = JwtClaims { .. };
        return JwtError.InvalidBase64;
    }
    var json_buf: u8[..2048] = [];
    defer core::secure_zeroize_slice(json_buf[..]);
    guard core::base64url_decode(clm_b64, json_buf) else {
        out_claims = JwtClaims { .. };
        return JwtError.InvalidBase64;
    }
    guard parse_jwt_claims_json(json_buf[..], out_claims) else {
        return JwtError.InvalidClaimsJson;
    }
    return JwtError.None;
}

// Parses only the JOSE header of a compact JWT (for key-id `kid` lookup prior to signature verification).
//
// Example:
//   token = "eyJhbGciOiJIUzI1NiIsImtpZCI6ImsxIn0.eyJzdWIiOiIxIn0.sig"
//   returns: JwtError.None, out_header.kid = "k1"
fn parse_jwt_header_only(token: const u8[:], out_header: JwtHeader&) -> JwtError {
    let dot1, _, ok_parts = split_jwt_parts(token);
    guard ok_parts else {
        out_header = JwtHeader { .. };
        return JwtError.MalformedToken;
    }
    return decode_jwt_header(token[..dot1], out_header);
}

// Parses header and claims of a compact JWT WITHOUT signature verification.
//
// Example:
//   token = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1MSJ9.sig"
//   returns: JwtError.None, out_header.alg = HS256, out_claims.sub = "u1"
fn parse_jwt_unverified(
    token:      const u8[:],
    out_header: JwtHeader&,
    out_claims: JwtClaims&,
) -> JwtError {
    var err = JwtError.MalformedToken;
    var temp_hdr = JwtHeader { .. };
    var temp_clm = JwtClaims { .. };
    defer if err != JwtError.None {
        out_header = JwtHeader { .. };
        out_claims = JwtClaims { .. };
    };
    let dot1, dot2, ok_parts = split_jwt_parts(token);
    guard ok_parts && token.index_of_byte('=') == -1 else { return JwtError.MalformedToken; }

    err = decode_jwt_header(token[..dot1], temp_hdr);
    guard err == JwtError.None else { return err; }
    if temp_hdr.has_b64 && !temp_hdr.b64 {
        err = JwtError.CriticalHeaderUnsupported;
        return err;
    }

    err = auth_internal::check_unverified_sig_part(temp_hdr.alg, token[dot2 + 1..]);
    guard err == JwtError.None else { return err; }

    err = decode_jwt_claims(token[dot1 + 1..dot2], temp_clm);
    guard err == JwtError.None else { return err; }

    out_header = copy(temp_hdr);
    out_claims = copy(temp_clm);
    return JwtError.None;
}

// Verifies an HMAC-SHA2 compact JWT (RFC 7518 §3.2) and populates `out_header` and `out_claims`.
fn verify_jwt_hmac(
    token:        const u8[:],
    secret_key:   const u8[:],
    options:      const JwtValidationOptions&,
    now_unix_sec: i64,
    out_header:   JwtHeader&,
    out_claims:   JwtClaims&,
) -> JwtError {
    var err = JwtError.MalformedToken;
    defer if err != JwtError.None {
        out_header = JwtHeader { .. };
        out_claims = JwtClaims { .. };
    };
    let dot1, dot2, ok_parts = split_jwt_parts(token);
    guard ok_parts && token.index_of_byte('=') == -1 else { return JwtError.MalformedToken; }

    err = decode_jwt_header(token[..dot1], out_header);
    guard err == JwtError.None else { return err; }
    err = auth_internal::verify_jwt_header_rules(out_header, options);
    guard err == JwtError.None else { return err; }

    let min_key_len = auth_internal::hmac_min_key_len(out_header.alg);
    if min_key_len == 0 {
        err = JwtError.AlgorithmMismatch;
        return err;
    }
    guard secret_key.len >= min_key_len else {
        err = JwtError.SignatureInvalid;
        return err;
    }

    let sig_b64 = token[dot2 + 1..];
    guard sig_b64.len > 0 && sig_b64.len <= 172 else {
        err = JwtError.SignatureInvalid;
        return err;
    }
    var sig_bytes: u8[..128] = [];
    guard core::base64url_decode(sig_b64, sig_bytes) else {
        err = JwtError.InvalidBase64;
        return err;
    }
    guard verify_jwt_hmac_signature(out_header.alg, secret_key, token[..dot2], sig_bytes[..]) else {
        err = JwtError.SignatureInvalid;
        return err;
    }

    err = decode_jwt_claims(token[dot1 + 1..dot2], out_claims);
    guard err == JwtError.None else { return err; }
    err = validate_jwt_claims_rules(out_claims, options, now_unix_sec);
    return err;
}

// Verifies an Ed25519 compact JWT (RFC 8037 §3.1) and populates `out_header` and `out_claims`.
fn verify_jwt_eddsa(
    token:        const u8[:],
    public_key:   const u8[32],
    options:      const JwtValidationOptions&,
    now_unix_sec: i64,
    out_header:   JwtHeader&,
    out_claims:   JwtClaims&,
) -> JwtError {
    var err = JwtError.MalformedToken;
    defer if err != JwtError.None {
        out_header = JwtHeader { .. };
        out_claims = JwtClaims { .. };
    };
    let dot1, dot2, ok_parts = split_jwt_parts(token);
    guard ok_parts else { return JwtError.MalformedToken; }

    err = decode_jwt_header(token[..dot1], out_header);
    guard err == JwtError.None else { return err; }
    err = auth_internal::verify_jwt_header_rules(out_header, options);
    guard err == JwtError.None else { return err; }
    guard out_header.alg == JwtAlg.EdDSA else {
        err = JwtError.AlgorithmMismatch;
        return err;
    }

    let sig_b64 = token[dot2 + 1..];
    guard sig_b64.len == 86 && sig_b64.index_of_byte('=') == -1 else {
        err = JwtError.SignatureInvalid;
        return err;
    }
    var sig_bytes: u8[..96] = [];
    guard core::base64url_decode(sig_b64, sig_bytes) else {
        err = JwtError.InvalidBase64;
        return err;
    }
    guard verify_jwt_eddsa_signature(public_key, token[..dot2], sig_bytes[..]) else {
        err = JwtError.SignatureInvalid;
        return err;
    }

    err = decode_jwt_claims(token[dot1 + 1..dot2], out_claims);
    guard err == JwtError.None else { return err; }
    err = validate_jwt_claims_rules(out_claims, options, now_unix_sec);
    return err;
}

// Verifies an ECDSA P-256 SHA-256 compact JWT (RFC 7518 §3.4) and populates `out_header` and `out_claims`.
fn verify_jwt_es256(
    token:        const u8[:],
    public_key:   const u8[:],
    options:      const JwtValidationOptions&,
    now_unix_sec: i64,
    out_header:   JwtHeader&,
    out_claims:   JwtClaims&,
) -> JwtError {
    var err = JwtError.MalformedToken;
    defer if err != JwtError.None {
        out_header = JwtHeader { .. };
        out_claims = JwtClaims { .. };
    };
    let dot1, dot2, ok_parts = split_jwt_parts(token);
    guard ok_parts else { return JwtError.MalformedToken; }

    err = decode_jwt_header(token[..dot1], out_header);
    guard err == JwtError.None else { return err; }
    err = auth_internal::verify_jwt_header_rules(out_header, options);
    guard err == JwtError.None else { return err; }
    guard out_header.alg == JwtAlg.ES256 else {
        err = JwtError.AlgorithmMismatch;
        return err;
    }

    let sig_b64 = token[dot2 + 1..];
    guard sig_b64.len == 86 && sig_b64.index_of_byte('=') == -1 else {
        err = JwtError.SignatureInvalid;
        return err;
    }
    var sig_bytes: u8[..96] = [];
    guard core::base64url_decode(sig_b64, sig_bytes) && sig_bytes.len == 64 else {
        err = JwtError.SignatureInvalid;
        return err;
    }
    guard core::ecdsa_p256_verify_p1363(public_key, token[..dot2], sig_bytes[..]) else {
        err = JwtError.SignatureInvalid;
        return err;
    }

    err = decode_jwt_claims(token[dot1 + 1..dot2], out_claims);
    guard err == JwtError.None else { return err; }
    err = validate_jwt_claims_rules(out_claims, options, now_unix_sec);
    return err;
}

// Verifies an RSA (RS256/PS256) compact JWT (RFC 7518 §§3.3, 3.5) and populates `out_header` and `out_claims`.
fn verify_jwt_rsa(
    token:        const u8[:],
    n_be:         const u8[:],
    e_be:         const u8[:],
    options:      const JwtValidationOptions&,
    now_unix_sec: i64,
    out_header:   JwtHeader&,
    out_claims:   JwtClaims&,
) -> JwtError {
    var err = JwtError.MalformedToken;
    defer if err != JwtError.None {
        out_header = JwtHeader { .. };
        out_claims = JwtClaims { .. };
    };
    let dot1, dot2, ok_parts = split_jwt_parts(token);
    guard ok_parts else { return JwtError.MalformedToken; }

    err = decode_jwt_header(token[..dot1], out_header);
    guard err == JwtError.None else { return err; }
    err = auth_internal::verify_jwt_header_rules(out_header, options);
    guard err == JwtError.None else { return err; }
    guard out_header.alg == JwtAlg.RS256 || out_header.alg == JwtAlg.PS256 else {
        err = JwtError.AlgorithmMismatch;
        return err;
    }

    let sig_b64 = token[dot2 + 1..];
    guard sig_b64.len > 0 && sig_b64.len <= 1024 && sig_b64.index_of_byte('=') == -1 else {
        err = JwtError.SignatureInvalid;
        return err;
    }
    var sig_bytes: u8[..768] = [];
    guard core::base64url_decode(sig_b64, sig_bytes) else {
        err = JwtError.InvalidBase64;
        return err;
    }
    guard verify_jwt_rsa_signature(out_header.alg, n_be, e_be, token[..dot2], sig_bytes[..]) else {
        err = JwtError.SignatureInvalid;
        return err;
    }

    err = decode_jwt_claims(token[dot1 + 1..dot2], out_claims);
    guard err == JwtError.None else { return err; }
    err = validate_jwt_claims_rules(out_claims, options, now_unix_sec);
    return err;
}

// Verifies an RFC 7797 unencoded detached/inline payload JWS using HS256 (`"b64":false` + `"crit":["b64"]`).
fn verify_jws_unencoded_hs256(compact_token: const u8[:], secret: const u8[:]) -> bool {
    guard secret.len >= rfc::HMAC_SHA256_MAC_LEN else { return false; }
    guard compact_token.len >= 3 && compact_token.len <= MAX_JWT_TOKEN_LEN else { return false; }
    let dot1 = compact_token.index_of_byte('.');
    let dot2 = compact_token.last_index_of_byte('.');
    guard dot1 > 0 && dot2 > dot1 + 1 && dot1 <= MAX_JWT_HEADER_PART_LEN else { return false; }
    guard compact_token[dot1 + 1..dot2].index_of_byte('.') == -1 else { return false; }

    var hdr = JwtHeader { .. };
    guard decode_jwt_header(compact_token[..dot1], hdr) == JwtError.None else { return false; }
    guard hdr.alg == JwtAlg.HS256 && hdr.has_b64 && !hdr.b64 else { return false; }
    guard auth_internal::has_only_crit_param_in_header(hdr, "b64") else { return false; }

    let sig_b64 = compact_token[dot2 + 1..];
    guard sig_b64.len == 43 && sig_b64.index_of_byte('=') == -1 else { return false; }
    var sig_bytes: u8[..64] = [];
    guard core::base64url_decode(sig_b64, sig_bytes) else { return false; }
    return verify_jwt_hmac_signature(JwtAlg.HS256, secret, compact_token[..dot2], sig_bytes[..]);
}
