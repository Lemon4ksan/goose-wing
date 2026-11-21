// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Internal end-to-end DPoP proof verifier outputting parsed claims for replay protection.
namespace auth_internal;

import std;
import core;
import rfc.http;
import .types;
import .internal;
import .dpop_leaf_internal;
import .jwt_core;
import .dpop_claims;

fn verify_dpop_proof_into_claims(
    jwt:             const u8[:],
    key:             const u8[:],
    expected_method: const u8[:],
    expected_uri:    const u8[:],
    access_token:    const u8[:],
    expected_nonce:  const u8[:],
    now_sec:         i64,
    max_age_sec:     i64,
    max_skew_sec:    i64,
    expected_jkt:    const u8[:],
    expected_alg:    const u8[:],
    out_claims:      auth::DPoPClaims&,
) -> bool {
    var committed = false;
    defer if !committed { out_claims = auth::DPoPClaims { .. }; };

    guard jwt.len > 0 && jwt.len <= MAX_DPOP_PROOF_LEN && jwt.index_of_byte('=') == -1 else { return false; }
    let dot1, dot2, ok_parts = auth::split_jwt_parts(jwt);
    guard ok_parts && dot2 < core::sub_sat_i64(jwt.len, 1) else { return false; }

    let hdr_b64 = jwt[..dot1];
    let clm_b64 = jwt[dot1 + 1..dot2];
    let sig_b64 = jwt[dot2 + 1..];
    guard hdr_b64.index_of_byte('=') == -1 &&
        clm_b64.index_of_byte('=') == -1 &&
        sig_b64.index_of_byte('=') == -1 else { return false; }

    var header_json: u8[..2048] = [];
    guard core::base64url_decode(hdr_b64, header_json) else { return false; }

    var header_alg: u8[..16] = [];
    var jwk_info = auth::DPoPJwkInfo { .. };
    guard auth::verify_dpop_header(header_json[..], expected_alg, header_alg, jwk_info) else { return false; }
    guard auth::verify_dpop_key_binding(key, expected_jkt, header_alg[..], jwk_info) else { return false; }
    guard verify_dpop_signature_with_jwk(jwt[..dot2], sig_b64, header_alg[..], jwk_info) else { return false; }

    var claims_json: u8[..2048] = [];
    guard core::base64url_decode(clm_b64, claims_json) else { return false; }
    var parsed_claims = auth::DPoPClaims { .. };
    guard auth::parse_dpop_claims(claims_json[..], parsed_claims) else { return false; }
    let target_jkt = if expected_jkt.len > 0 { expected_jkt } else { parsed_claims.jkt[..] };
    if target_jkt.len > 0 {
        guard matches_dpop_jkt_thumbprint_jwk(jwk_info, parsed_claims.jkt[..], target_jkt) else { return false; }
    }
    guard auth::verify_dpop_claims(
        parsed_claims,
        expected_method,
        expected_uri,
        access_token,
        expected_nonce,
        now_sec,
        max_age_sec,
        max_skew_sec,
        "",
    ) else { return false; }

    out_claims = parsed_claims;
    committed = true;
    return true;
}
