// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// DPoP target URI normalization, JTI generation, header/claims parsing, and key-binding validation (RFC 9449).
namespace auth;

import std;
import json;
import core;
import rfc.http;
import .types;
import .internal;
import .dpop_leaf_internal;

// RFC 9449 Section 4.2: Normalizes HTTP/HTTPS target URI by stripping query/fragment and default ports into `out`.
fn normalize_dpop_target_uri<B>(raw_uri: const u8[:], out: B&) -> bool {
    var committed = false;
    defer if !committed { out.resize(0); };

    for b in raw_uri {
        guard b != '\\' && b != '"' && core::is_ascii_vchar(b) else { return false; }
    }
    let view, err = core::parse_url_view(raw_uri);
    guard err == core::UrlParseError.None && view.valid && view.host.len > 0 else { return false; }
    guard core::normalize_http_target_uri(raw_uri, out) else { return false; }
    committed = true;
    return true;
}

// RFC 9449 Section 4.2: Computes BASE64URL(SHA256(ASCII(access_token))) access-token hash (`ath`) into `out`.
fn compute_dpop_ath<B>(access_token: const u8[:], out: B&) -> bool {
    var committed = false;
    defer if !committed { out.resize(0); };

    guard access_token.len > 0 else { return false; }
    var digest = core::sha256(access_token);
    defer core::secure_zeroize_32(digest);
    var encoded: u8[..64] = [];
    core::base64url_encode(digest[..], encoded);
    guard out.try_set(encoded[..]) else { return false; }
    committed = true;
    return true;
}

// RFC 9449 Section 4.2: Generates a unique Base64URL DPoP `jti` token identifier (22-char default) into `out`.
fn generate_dpop_jti<B>(out: B&, entropy: const u8[:] = "") -> bool {
    var jti_buf: u8[..128] = [];
    defer core::secure_zeroize_slice(jti_buf[..]);
    guard entropy.len == 0 || entropy.len >= 16 else {
        out.resize(0);
        return false;
    }
    if entropy.len >= 16 {
        let max_ent = min(entropy.len, 96);
        core::base64url_encode(entropy[..max_ent], jti_buf);
    } else {
        var rand16: u8[16] = [0; 16];
        defer core::secure_zeroize_16(rand16);
        let got_rng = if core::sim_rng_is_active() {
            core::sim_rng_fill(rand16[..])
        } else {
            core::csprng_fill(rand16[..])
        };
        guard got_rng else {
            out.resize(0);
            return false;
        }
        core::base64url_encode(rand16[..], jti_buf);
    }
    guard out.try_set(jti_buf[..]) else {
        out.resize(0);
        return false;
    }
    return true;
}

// Builds RFC 9449 Section 4.2 DPoP proof payload JSON (`jti`, `htm`, `htu`, `iat`, optional `nonce`/`ath`) into `out`.
fn build_dpop_claims_json<B>(
    method:       const u8[:],
    norm_uri:     const u8[:],
    access_token: const u8[:],
    nonce:        const u8[:],
    now_sec:      i64,
    jti:          const u8[:],
    out:          B&,
) -> bool {
    var committed = false;
    defer if !committed { out.resize(0); };

    guard auth_internal::is_valid_dpop_method(method) && norm_uri.len > 0 && now_sec > 0 else { return false; }
    guard (jti.len == 0 || rfc::is_valid_dpop_nonce(jti)) &&
        (nonce.len == 0 || rfc::is_valid_dpop_nonce(nonce)) else { return false; }
    out.clear();
    guard out.try_append("{\"jti\":") else { return false; }
    if jti.len > 0 {
        guard core::try_format_json_string(out, jti) else { return false; }
    } else {
        var auto_jti: u8[..32] = [];
        guard generate_dpop_jti(auto_jti) && core::try_format_json_string(out, auto_jti[..]) else { return false; }
    }
    guard out.try_append(",\"htm\":") && core::try_format_json_string(out, method) else { return false; }
    guard out.try_append(",\"htu\":") && core::try_format_json_string(out, norm_uri) else { return false; }
    guard out.try_append(",\"iat\":") && core::try_format_i64_dec(now_sec, out) else { return false; }

    if nonce.len > 0 {
        guard rfc::is_valid_dpop_nonce(nonce) else { return false; }
        guard out.try_append(",\"nonce\":") && core::try_format_json_string(out, nonce) else { return false; }
    }
    if access_token.len > 0 {
        var ath: u8[..64] = [];
        guard compute_dpop_ath(access_token, ath) else { return false; }
        guard out.try_append(",\"ath\":") && core::try_format_json_string(out, ath[..]) else { return false; }
    }
    guard out.try_push('}' as u8) else { return false; }
    committed = true;
    return true;
}

// RFC 9449 Section 4.3: Checks DPoP JOSE header `alg` against expected algorithm (empty expects any asymmetric alg).
fn is_matching_dpop_alg(alg_val: const u8[:], expected_alg: const u8[:]) -> bool {
    guard auth_internal::is_asymmetric_dpop_alg(alg_val) else { return false; }
    return expected_alg.len == 0 || alg_val == expected_alg;
}

// Extracts embedded JWK and `alg` metadata from a DPoP proof JOSE header JSON.
//
// Example:
//   header_json = "{\"typ\":\"dpop+jwt\",\"alg\":\"EdDSA\",\"jwk\":{\"kty\":\"OKP\",...}}"
//   returns: true, out_alg = "EdDSA", out_jwk populated
fn parse_dpop_header_jwk_info<B>(
    header_json: const u8[:],
    out_alg:     B&,
    out_jwk:     DPoPJwkInfo&,
) -> bool {
    var committed = false;
    defer if !committed {
        out_alg.resize(0);
        out_jwk = DPoPJwkInfo { valid: false, .. };
    };
    guard header_json.validate_utf8() else { return false; }
    var reader = json::reader(header_json);
    guard json::peek(reader) == '{' else { return false; }

    var st = auth_internal::DPoPHeaderScanState { .. };
    out_alg.clear();
    out_jwk = DPoPJwkInfo { valid: false, .. };
    json::each_member(reader) { key =>
        auth_internal::read_dpop_header_member(reader, key, "", out_alg, out_jwk, st);
    };
    guard json::finish(reader) && !st.had_dup && !st.has_crit else { return false; }
    guard st.valid_typ && st.valid_alg && st.seen_jwk && out_jwk.valid else { return false; }
    guard auth_internal::is_dpop_alg_jwk_compatible(out_alg[..], out_jwk) else { return false; }
    committed = true;
    return true;
}

// RFC 9449 Section 4.3: Verifies a DPoP JOSE header and extracts `out_alg` and validated `out_jwk`.
fn verify_dpop_header<B>(
    header_json:  const u8[:],
    expected_alg: const u8[:],
    out_alg:      B&,
    out_jwk:      DPoPJwkInfo&,
) -> bool {
    var committed = false;
    defer if !committed {
        out_alg.resize(0);
        out_jwk = DPoPJwkInfo { valid: false, .. };
    };
    guard parse_dpop_header_jwk_info(header_json, out_alg, out_jwk) else { return false; }
    guard is_matching_dpop_alg(out_alg[..], expected_alg) else { return false; }
    committed = true;
    return true;
}

// RFC 9449 Section 4.3: Verifies a DPoP JOSE header against `expected_alg` (defaults to "EdDSA").
fn verify_dpop_header(header_json: const u8[:], expected_alg: const u8[:] = "EdDSA") -> bool {
    var alg_buf: u8[..16] = [];
    var jwk_info = DPoPJwkInfo { .. };
    return verify_dpop_header(header_json, expected_alg, alg_buf, jwk_info);
}

// RFC 9449 Section 4.2: Parses DPoP proof claims JSON (`jti`, `htm`, `htu`, `iat`, `nonce`, `ath`, `jkt`) into `out`.
//
// Example:
//   claims_json = "{\"jti\":\"id1\",\"htm\":\"GET\",\"htu\":\"https://ex.com/\",\"iat\":1700000000}"
//   returns: true, out.htm = "GET", out.has_iat = true
fn parse_dpop_claims(claims_json: const u8[:], out: DPoPClaims&) -> bool {
    var committed = false;
    defer if !committed { out = DPoPClaims { .. }; };
    guard claims_json.validate_utf8() else { return false; }
    var reader = json::reader(claims_json);
    guard json::peek(reader) == '{' else { return false; }

    var clm = DPoPClaims { .. };
    var seen_jti = false;
    var seen_htm = false;
    var seen_htu = false;
    var seen_iat = false;
    var seen_nonce = false;
    var seen_ath = false;
    var seen_jkt = false;
    var had_dup = false;
    var had_error = false;
    var seen_extra: auth_internal::SeenHeaderKey[..16] = [];

    json::each_member(reader) { key =>
        if key.contains_byte('\\') {
            had_error = true;
            json::skip(reader);
        } else if key == "jti" {
            auth_internal::parse_dpop_claim_str(reader, clm.jti, seen_jti, had_dup, had_error);
        } else if key == "htm" {
            auth_internal::parse_dpop_claim_str(reader, clm.htm, seen_htm, had_dup, had_error);
        } else if key == "htu" {
            auth_internal::parse_dpop_claim_str(reader, clm.htu, seen_htu, had_dup, had_error);
        } else if key == "nonce" {
            auth_internal::parse_dpop_claim_str(reader, clm.nonce, seen_nonce, had_dup, had_error);
            if !rfc::is_valid_dpop_nonce(clm.nonce[..]) { had_error = true; }
        } else if key == "ath" {
            auth_internal::parse_dpop_claim_str(reader, clm.ath, seen_ath, had_dup, had_error);
        } else if key == "jkt" {
            auth_internal::parse_dpop_claim_str(reader, clm.jkt, seen_jkt, had_dup, had_error);
        } else if key == "iat" {
            if seen_iat { had_dup = true; }
            seen_iat = true;
            auth_internal::parse_dpop_iat_field(reader, clm, had_error);
        } else {
            auth_internal::record_dpop_extra_key(key, seen_extra, had_dup, true);
            json::skip(reader);
        }
    };
    guard json::finish(reader) && !had_dup && !had_error else { return false; }
    out = clm;
    committed = true;
    return true;
}

// RFC 9449 Section 4.3: Verifies mandatory valid DPoP `jti` claim in raw DPoP claims JSON.
fn verify_dpop_jti(claims_json: const u8[:]) -> bool {
    var claims = DPoPClaims { .. };
    return parse_dpop_claims(claims_json, claims) && rfc::is_valid_dpop_nonce(claims.jti[..]);
}

// RFC 9449 Section 4.3: Verifies case-sensitive `htm` claim matches `expected_method`.
fn verify_dpop_method(claims_json: const u8[:], expected_method: const u8[:]) -> bool {
    guard auth_internal::is_valid_dpop_method(expected_method) else { return false; }
    var claims = DPoPClaims { .. };
    return parse_dpop_claims(claims_json, claims) && claims.htm[..] == expected_method;
}

// RFC 9449 Section 4.3: Verifies `htu` has no query/fragment and equals normalized `expected_uri`.
fn verify_dpop_uri(claims_json: const u8[:], expected_uri: const u8[:]) -> bool {
    var claims = DPoPClaims { .. };
    guard parse_dpop_claims(claims_json, claims) && claims.htu.len > 0 else { return false; }
    guard core::find_byteset(claims.htu[..], "?#") == -1 else { return false; }
    var norm_expected: u8[..256] = [];
    guard normalize_dpop_target_uri(expected_uri, norm_expected) else { return false; }
    var norm_htu: u8[..256] = [];
    guard normalize_dpop_target_uri(claims.htu[..], norm_htu) else { return false; }
    return norm_htu[..] == norm_expected[..];
}

// RFC 9449 Section 4.3: Verifies `iat` claim falls within `[now_sec - max_age_sec, now_sec + max_skew_sec]`.
fn verify_dpop_iat(claims_json: const u8[:], now_sec: i64, max_age_sec: i64, max_skew_sec: i64) -> bool {
    guard now_sec > 0 && max_age_sec >= 0 && max_skew_sec >= 0 else { return false; }
    var claims = DPoPClaims { .. };
    guard parse_dpop_claims(claims_json, claims) && claims.has_iat && claims.iat > 0 else { return false; }
    let min_allowed = core::sub_sat_i64(now_sec, max_age_sec);
    let max_allowed = core::add_sat_i64(now_sec, max_skew_sec);
    return claims.iat >= min_allowed && claims.iat <= max_allowed;
}

// Verifies optional `jkt` claim in DPoP claims JSON matches `expected_jkt` in constant time.
fn verify_dpop_jkt(claims_json: const u8[:], expected_jkt: const u8[:]) -> bool {
    guard expected_jkt.len > 0 else { return false; }
    var claims = DPoPClaims { .. };
    guard parse_dpop_claims(claims_json, claims) && claims.jkt.len == expected_jkt.len else { return false; }
    return core::ct_eq_bytes(claims.jkt[..], expected_jkt);
}

// RFC 9449 Section 4.3: Validates parsed DPoP proof claims (`jti`, `htm`, `htu`, `iat`, `ath`, `nonce`, `jkt`).
fn verify_dpop_claims(
    claims:          const DPoPClaims&,
    expected_method: const u8[:],
    expected_uri:    const u8[:],
    access_token:    const u8[:] = "",
    expected_nonce:  const u8[:] = "",
    now_sec:         i64         = 0,
    max_age_sec:     i64         = 300,
    max_skew_sec:    i64         = 60,
    expected_jkt:    const u8[:] = "",
) -> bool {
    guard rfc::is_valid_dpop_nonce(claims.jti[..]) else { return false; }
    guard auth_internal::is_valid_dpop_method(expected_method) &&
        auth_internal::is_valid_dpop_method(claims.htm[..]) else { return false; }
    guard claims.htm[..] == expected_method else { return false; }
    guard claims.htu.len > 0 && core::find_byteset(claims.htu[..], "?#") == -1 else { return false; }

    var norm_expected: u8[..256] = [];
    var norm_htu:      u8[..256] = [];
    guard normalize_dpop_target_uri(expected_uri, norm_expected) else { return false; }
    guard normalize_dpop_target_uri(claims.htu[..], norm_htu) else { return false; }
    guard norm_htu[..] == norm_expected[..] else { return false; }

    if access_token.len > 0 {
        var expected_ath: u8[..64] = [];
        guard compute_dpop_ath(access_token, expected_ath) else { return false; }
        guard claims.ath.len == expected_ath.len &&
            core::ct_eq_bytes(claims.ath[..], expected_ath[..]) else { return false; }
    } else {
        guard claims.ath.len == 0 else { return false; }
    }
    if expected_nonce.len > 0 {
        guard claims.nonce.len == expected_nonce.len &&
            core::ct_eq_bytes(claims.nonce[..], expected_nonce) else { return false; }
    }
    if expected_jkt.len > 0 {
        guard claims.jkt.len == expected_jkt.len &&
            core::ct_eq_bytes(claims.jkt[..], expected_jkt) else { return false; }
    }
    guard now_sec > 0 && max_age_sec >= 0 && max_skew_sec >= 0 else { return false; }
    guard claims.has_iat && claims.iat > 0 else { return false; }
    guard claims.iat <= core::add_sat_i64(now_sec, max_skew_sec) else { return false; }
    return claims.iat >= core::sub_sat_i64(now_sec, max_age_sec);
}

// RFC 7638 / RFC 9449: Verifies an Ed25519 public key against `expected_jkt` (and optional `claims_jkt`).
fn matches_dpop_jkt_thumbprint(
    jwk_pub:      const u8[32]&,
    claims_jkt:   const u8[:],
    expected_jkt: const u8[:],
) -> bool {
    guard expected_jkt.len > 0 else { return false; }
    var x_b64: u8[..64] = [];
    core::base64url_encode(jwk_pub[..], x_b64);
    var canonical: u8[..256] = [];
    canonical.append("{\"crv\":\"Ed25519\",\"kty\":\"OKP\",\"x\":\"");
    canonical.append(x_b64[..]);
    canonical.append("\"}");
    let digest = core::sha256(canonical[..]);
    var computed_jkt: u8[..64] = [];
    core::base64url_encode(digest[..], computed_jkt);
    if claims_jkt.len > 0 {
        guard claims_jkt.len == expected_jkt.len && core::ct_eq_bytes(claims_jkt, expected_jkt) else {
            return false;
        }
    }
    return computed_jkt.len == expected_jkt.len && core::ct_eq_bytes(computed_jkt[..], expected_jkt);
}

// RFC 9449 Section 4.3 / Section 7.1: Verifies embedded DPoP header JWK binds to `key` or `expected_jkt`.
fn verify_dpop_key_binding(
    key:          const u8[:],
    expected_jkt: const u8[:],
    alg:          const u8[:],
    jwk_info:     const DPoPJwkInfo&,
) -> bool {
    if expected_jkt.len > 0 {
        guard auth_internal::matches_dpop_jkt_thumbprint_jwk(jwk_info, "", expected_jkt) else { return false; }
    }
    if key.len == 0 {
        return expected_jkt.len > 0;
    }
    if alg == "EdDSA" {
        return auth_internal::verify_dpop_eddsa_key_binding(key, jwk_info);
    }
    if alg == "ES256" {
        return auth_internal::verify_dpop_es256_key_binding(key, jwk_info);
    }
    if alg == "RS256" || alg == "PS256" {
        guard jwk_info.kty[..] == "RSA" else { return false; }
        let cert_n, cert_e, ok_der = core::parse_rsa_public_key_der(key);
        guard ok_der else { return false; }
        var dec_n: u8[..512] = [];
        var dec_e: u8[..8]   = [];
        guard core::base64url_decode(jwk_info.n[..], dec_n) && core::base64url_decode(jwk_info.e[..], dec_e) else {
            return false;
        }
        return core::ct_eq_bytes(cert_n, dec_n[..]) && core::ct_eq_bytes(cert_e, dec_e[..]);
    }
    return false;
}
