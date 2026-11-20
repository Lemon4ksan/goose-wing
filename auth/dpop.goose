// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// OAuth 2.0 DPoP proof creation, request attachment, and replay protection (RFC 9449).
namespace auth;

import std;
import core from "..";
import rfc.http;
import .types;
import .internal;
import .dpop_leaf_internal;
import .dpop_claims;
import .dpop_internal;

// RFC 9449 Section 4.2: Creates an Ed25519 DPoP proof JWT with embedded JWK into `out`.
fn create_dpop_proof<B>(
    key:          const u8[:],
    method:       const u8[:],
    target_uri:   const u8[:],
    access_token: const u8[:],
    nonce:        const u8[:],
    now_sec:      i64,
    jti:          const u8[:],
    out:          B&,
) -> bool {
    var committed = false;
    defer if !committed { out.resize(0); };

    guard key.len == 32 || key.len == 64 else { return false; }
    var seed: u8[32] = [0; 32];
    defer core::secure_zeroize_32(seed);
    for i in 32 { seed[i] = key[i]; }
    var pub_key = core::ed25519_public_key(seed);
    if key.len == 64 {
        guard core::ct_eq_bytes(pub_key[..], key[32..64]) else { return false; }
    }

    var norm_uri: u8[..256] = [];
    guard normalize_dpop_target_uri(target_uri, norm_uri) else { return false; }

    var x_b64: u8[..64] = [];
    core::base64url_encode(pub_key[..], x_b64);
    var hdr_json: u8[..256] = [];
    hdr_json.append("{\"typ\":\"dpop+jwt\",\"alg\":\"EdDSA\",\"jwk\":{\"kty\":\"OKP\",\"crv\":\"Ed25519\",\"x\":\"");
    hdr_json.append(x_b64[..]);
    hdr_json.append("\"}}");

    var clm_json: u8[..2048] = [];
    defer core::secure_zeroize_slice(clm_json[..]);
    guard build_dpop_claims_json(method, norm_uri[..], access_token, nonce, now_sec, jti, clm_json) else {
        return false;
    }

    var signing_input: u8[..4096] = [];
    defer core::secure_zeroize_slice(signing_input[..]);
    core::base64url_encode(hdr_json[..], signing_input);
    signing_input.push('.');
    core::base64url_encode(clm_json[..], signing_input);

    var sig = core::ed25519_sign(seed, signing_input[..]);
    defer core::secure_zeroize_64(sig);
    var sig_b64: u8[..128] = [];
    defer core::secure_zeroize_slice(sig_b64[..]);
    core::base64url_encode(sig[..], sig_b64);

    out.clear();
    guard out.try_append(signing_input[..]) && out.try_push('.' as u8) && out.try_append(sig_b64[..]) else {
        return false;
    }
    committed = true;
    return true;
}

// RFC 9449 Section 4.2: Creates an ECDSA P-256 (ES256) DPoP proof JWT with embedded JWK into `out`.
fn create_dpop_proof_es256<B>(
    priv_key:     const u8[32],
    method:       const u8[:],
    target_uri:   const u8[:],
    access_token: const u8[:],
    nonce:        const u8[:],
    now_sec:      i64,
    jti:          const u8[:],
    out:          B&,
) -> bool {
    var committed = false;
    defer if !committed { out.resize(0); };

    guard auth_internal::has_nonzero_byte_32(priv_key) else { return false; }
    var norm_uri: u8[..256] = [];
    guard normalize_dpop_target_uri(target_uri, norm_uri) else { return false; }

    let pub_uncomp = core::ecdsa_p256_public_key(priv_key);
    var x_b64: u8[..64] = [];
    var y_b64: u8[..64] = [];
    core::base64url_encode(pub_uncomp[1..33], x_b64);
    core::base64url_encode(pub_uncomp[33..65], y_b64);

    var hdr_json: u8[..512] = [];
    hdr_json.append("{\"typ\":\"dpop+jwt\",\"alg\":\"ES256\",\"jwk\":{\"kty\":\"EC\",\"crv\":\"P-256\",\"x\":\"");
    hdr_json.append(x_b64[..]);
    hdr_json.append("\",\"y\":\"");
    hdr_json.append(y_b64[..]);
    hdr_json.append("\"}}");

    var clm_json: u8[..2048] = [];
    defer core::secure_zeroize_slice(clm_json[..]);
    guard build_dpop_claims_json(method, norm_uri[..], access_token, nonce, now_sec, jti, clm_json) else {
        return false;
    }

    var signing_input: u8[..4096] = [];
    defer core::secure_zeroize_slice(signing_input[..]);
    core::base64url_encode(hdr_json[..], signing_input);
    signing_input.push('.');
    core::base64url_encode(clm_json[..], signing_input);

    var sig = core::ecdsa_p256_sign(priv_key, signing_input[..]);
    defer core::secure_zeroize_64(sig);
    var sig_b64: u8[..128] = [];
    defer core::secure_zeroize_slice(sig_b64[..]);
    core::base64url_encode(sig[..], sig_b64);

    out.clear();
    guard out.try_append(signing_input[..]) && out.try_push('.' as u8) && out.try_append(sig_b64[..]) else {
        return false;
    }
    committed = true;
    return true;
}

// RFC 9449 Section 4.3: Verifies a DPoP proof JWT against key/jkt binding, method, normalized URI, nonce, ath, and iat.
fn verify_dpop_proof(
    jwt:             const u8[:],
    key:             const u8[:],
    expected_method: const u8[:],
    expected_uri:    const u8[:],
    access_token:    const u8[:] = "",
    expected_nonce:  const u8[:] = "",
    now_sec:         i64         = 0,
    max_age_sec:     i64         = 300,
    max_skew_sec:    i64         = 60,
    expected_jkt:    const u8[:] = "",
    expected_alg:    const u8[:] = "EdDSA",
) -> bool {
    var parsed_claims = DPoPClaims { .. };
    return auth_internal::verify_dpop_proof_into_claims(
        jwt,
        key,
        expected_method,
        expected_uri,
        access_token,
        expected_nonce,
        now_sec,
        max_age_sec,
        max_skew_sec,
        expected_jkt,
        expected_alg,
        parsed_claims,
    );
}

// RFC 9449 Section 7.1: Attaches `DPoP: <proof>` and optional `Authorization: DPoP <access_token>` headers to `req`.
fn attach_dpop<R>(req: R&, proof: const u8[:], access_token: const u8[:] = "") {
    guard proof.len > 0 && proof.len <= 4096 else { return; }
    guard core::swar_find_ctl(proof) == proof.len else { return; }
    wing::set_header(req, rfc::DPOP_HEADER, proof);
    if access_token.len > 0 && access_token.len <= 4096 && core::swar_find_ctl(access_token) == access_token.len {
        var auth_val: u8[..4112] = [];
        defer core::secure_zeroize_slice(auth_val[..]);
        auth_val.append("DPoP ");
        auth_val.append(access_token);
        wing::set_header(req, "Authorization", auth_val[..]);
    }
}

// RFC 9449 Section 8.1: Extracts a unique, syntactically valid `DPoP-Nonce` header from `headers`.
//
// Example:
//   headers contains "DPoP-Nonce: server_nonce_retry_456"
//   returns: "server_nonce_retry_456", ok = true
fn extract_dpop_nonce(headers: const wing::HeaderMap&) -> const u8[:], bool {
    var found_idx: i64 = -1;
    var count:     i64 = 0;
    for i in headers.entries.len {
        let e .= headers.entries[i];
        if wing::entry_name(headers, e).eq_ascii_fold(rfc::DPOP_NONCE_HEADER) {
            count = core::add_sat_i64(count, 1);
            found_idx = i;
        }
    }
    guard count == 1 && found_idx >= 0 else { return "", false; }
    let val = wing::entry_value(headers, headers.entries[found_idx]);
    guard rfc::is_valid_dpop_nonce(val) else { return "", false; }
    return val, true;
}

// Extracts a unique `DPoP-Nonce` header value into `out`.
//
// Example:
//   headers contains "DPoP-Nonce: server_nonce_retry_456"
//   returns: true, out = "server_nonce_retry_456"
fn extract_dpop_nonce<B>(headers: const wing::HeaderMap&, out: B&) -> bool {
    let val, ok = extract_dpop_nonce(headers);
    guard ok && out.try_set(val) else {
        out.resize(0);
        return false;
    }
    return true;
}

// RFC 9449 Section 4.3: Checks for JTI replay in `cache`, evicts expired entries, and records fresh JTIs.
fn check_and_record_dpop_jti(
    cache:        DPoPReplayCache&,
    jti:          const u8[:],
    now_sec:      i64,
    ttl_sec:      i64 = 300,
    max_skew_sec: i64 = 60,
) -> bool {
    guard now_sec > 0 && ttl_sec >= 0 && max_skew_sec >= 0 else { return false; }
    guard jti.len > 0 && jti.len <= 512 else { return false; }

    var write_idx: i64 = 0;
    var is_dup = false;
    for i in cache.entries.len {
        let e .= cache.entries[i];
        if e.expires_at_sec >= now_sec {
            if e.jti.len == jti.len && core::ct_eq_bytes(e.jti[..], jti) {
                is_dup = true;
            }
            if write_idx != i {
                cache.entries[write_idx] = e;
            }
            write_idx = core::add_sat_i64(write_idx, 1);
        }
    }
    cache.entries.resize(write_idx);
    guard !is_dup else { return false; }

    if cache.entries.len >= cache.entries.cap {
        var oldest_idx: i64 = 0;
        for i in cache.entries.len {
            if cache.entries[i].expires_at_sec < cache.entries[oldest_idx].expires_at_sec {
                oldest_idx = i;
            }
        }
        cache.entries[oldest_idx] = DPoPJtiEntry {
            expires_at_sec: core::add_sat_i64(now_sec, core::add_sat_i64(ttl_sec, max_skew_sec)),
            ..
        };
        guard cache.entries[oldest_idx].jti.try_set(jti) else { return false; }
        return true;
    }

    var entry = DPoPJtiEntry {
        expires_at_sec: core::add_sat_i64(now_sec, core::add_sat_i64(ttl_sec, max_skew_sec)),
        ..
    };
    guard entry.jti.try_set(jti) && cache.entries.try_push(entry) else { return false; }
    return true;
}

// Verifies a DPoP proof JWT and atomically rejects replayed `jti` values using `cache` (RFC 9449 §4.3 / §11.1).
fn verify_dpop_proof_with_replay_cache(
    cache:           DPoPReplayCache&,
    jwt:             const u8[:],
    key:             const u8[:],
    expected_method: const u8[:],
    expected_uri:    const u8[:],
    now_sec:         i64,
    access_token:    const u8[:] = "",
    expected_nonce:  const u8[:] = "",
    max_age_sec:     i64         = 300,
    max_skew_sec:    i64         = 60,
    expected_jkt:    const u8[:] = "",
    expected_alg:    const u8[:] = "EdDSA",
) -> bool {
    guard now_sec > 0 else { return false; }
    var parsed_claims = DPoPClaims { .. };
    guard auth_internal::verify_dpop_proof_into_claims(
        jwt,
        key,
        expected_method,
        expected_uri,
        access_token,
        expected_nonce,
        now_sec,
        max_age_sec,
        max_skew_sec,
        expected_jkt,
        expected_alg,
        parsed_claims,
    ) else { return false; }
    return check_and_record_dpop_jti(cache, parsed_claims.jti[..], now_sec, max_age_sec, max_skew_sec);
}
