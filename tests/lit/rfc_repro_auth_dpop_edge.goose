// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// tests/lit/rfc_repro_auth_dpop_edge.goose
// RFC 9449 DPoP JWK Thumbprint Confirmation & JTI Replay/Entropy Verification.
//
// RUN: goose build --cc gcc -O2 -o %t.exe %s
// RUN: %t.exe | %FileCheck %s

import std;
import core from "../..";
import wing from "../..";

fn main() {
    let key = "super_secret_dpop_key_32_bytes!!";
    let now_sec: i64 = 1714000000;

    // ---- 1. RFC 9449 Section 4.3 & 6.1: JWK Thumbprint Confirmation --------
    // RFC 9449 Section 4.3: Checking DPoP Proofs - confirm that the public key to which the access token is bound matches the public key from the DPoP proof.
    // RFC 9449 Section 6.1: JWK Thumbprint Confirmation Method - The value of the jkt member MUST be the base64url encoding (as defined in [RFC7515]) of the JWK SHA-256 Thumbprint (according to [RFC7638]) of the DPoP public key (in JWK format) to which the access token is bound.
    var proof: u8[>..] = [];
    let ok_gen = wing::create_dpop_proof(
        key,
        "POST",
        "https://api.example.com/token",
        "",
        "",
        now_sec,
        "custom-jti-01",
        proof,
    );
    assert(ok_gen);

    // Compute expected RFC 7638 SHA-256 Thumbprint of key's public key
    var seed: u8[32] = [0; 32];
    for i in 32 { seed[i] = key[i]; }
    let pub_key = core::ed25519_public_key(seed);
    var key_obj = wing::JwksKey { .. };
    key_obj.kty = wing::JwkKeyType.OKP;
    key_obj.crv.append("Ed25519");
    key_obj.public_key = pub_key;
    var expected_jkt: u8[..64] = [];
    assert(wing::compute_jwk_thumbprint(key_obj, expected_jkt));

    // Valid standard DPoP proof (contains NO payload jkt claim) MUST verify against bound token's jkt
    let ok_verify = wing::verify_dpop_proof(
        proof[..],
        key,
        "POST",
        "https://api.example.com/token",
        "",
        "",
        now_sec,
        300,
        60,
        expected_jkt[..],
    );
    assert(ok_verify);
    print("DPOP_JKT_VERIFICATION: OK");

    // ---- 2. RFC 9449 Section 11.1 & 4.2: JTI Replay Cache Limits -----------
    // RFC 9449 Section 11.1: DPoP Proof Replay - As long as the jti value is tracked and duplicates are rejected for the lifetime of the nonce, there is no additional risk of token replay.
    var replay_cache = wing::DPoPReplayCache { .. };
    let long_jti = "jti_rfc9449_long_identifier_0123456789012345678901234567890123456789_enterprise_safe";
    assert(long_jti.len > 64 && long_jti.len <= 128);

    let recorded = wing::check_and_record_dpop_jti(replay_cache, long_jti, now_sec, 300);
    assert(recorded);
    let replayed = wing::check_and_record_dpop_jti(replay_cache, long_jti, now_sec, 300);
    assert(!replayed);
    print("DPOP_JTI_REPLAY_CACHE: OK");

    // ---- 3. RFC 9449 Section 4.2: Stateful JTI Entropy --------------------
    // RFC 9449 Section 4.2: DPoP Proof JWT Syntax - The value MUST be assigned such that there is a negligible probability that the same value will be assigned to any other DPoP proof used in the same context during the time window of validity.
    var jti1: u8[..64] = [];
    var jti2: u8[..64] = [];
    wing::generate_dpop_jti(jti1);
    wing::generate_dpop_jti(jti2);
    assert(jti1[..] != jti2[..]);
    print("DPOP_JTI_ENTROPY: OK");

    // ---- 4. DPoP Proof Length & Header Sensitivity -------------------------
    var proof_at: u8[>..] = [];
    assert(wing::create_dpop_proof(
        key,
        "POST",
        "https://api.example.com/resource/endpoint",
        "access_token_1234567890_abcdef",
        "server-nonce-12345",
        now_sec,
        "custom-jti-01",
        proof_at,
    ));
    assert(proof_at.len >= 392);

    var dpop_req = wing::Request { .. };
    wing::attach_dpop(dpop_req, proof_at[..]);
    assert(dpop_req.headers.len == 1);
    assert(dpop_req.headers[0].name[..] == "DPoP");
    assert(dpop_req.headers[0].value.len == proof_at.len);
    assert(dpop_req.headers[0].is_sensitive);
    print("DPOP_ATTACH_AND_SENSITIVE: OK");

    // ---- 5. RFC 9449 §4.3 Target URI Normalization Edge Cases --------------
    var norm_buf: u8[..256] = [];
    assert(!wing::normalize_dpop_target_uri("https:///api", norm_buf));
    assert(wing::normalize_dpop_target_uri("http://[2001:db8::80]/test", norm_buf));
    assert(norm_buf[..] == "http://[2001:db8::80]/test");
    assert(wing::normalize_dpop_target_uri("http://[2001:db8::1]:80/test", norm_buf));
    assert(norm_buf[..] == "http://[2001:db8::1]/test");
    print("DPOP_URI_NORMALIZATION: OK");

    // ---- 6. RFC 9449 §4.2 Claims JSON Validation ---------------------------
    var cl_buf: u8[..512] = [];
    assert(!wing::build_dpop_claims_json("GET", "https://api.example.com/", "", "", -1, "valid_jti", cl_buf));
    assert(!wing::build_dpop_claims_json("GET", "https://api.example.com/", "", "", 0, "valid_jti", cl_buf));
    assert(!wing::build_dpop_claims_json("GET", "https://api.example.com/", "", "", now_sec, "bad\"jti", cl_buf));
    print("DPOP_CLAIMS_BUILD: OK");

    // ---- 7. RFC 9449 §4.3 Alg & Crit Header Rejection -----------------------
    assert(!wing::is_matching_dpop_alg("dir", ""));
    assert(!wing::is_matching_dpop_alg("A128GCM", ""));
    assert(!wing::is_matching_dpop_alg("HS256", ""));
    assert(wing::is_matching_dpop_alg("EdDSA", ""));
    assert(wing::is_matching_dpop_alg("ES256", ""));
    let crit_hdr = "{\"typ\":\"dpop+jwt\",\"alg\":\"EdDSA\",\"crit\":[\"foo\"],\"jwk\":{\"kty\":\"OKP\",\"crv\":\"Ed25519\",\"x\":\"1234\"}}";
    assert(!wing::verify_dpop_header(crit_hdr));
    print("DPOP_HEADER_REJECTIONS: OK");

    // ---- 8. RFC 9449 §8 Nonce Header Validation ----------------------------
    var hdrs_dup: wing::HeaderItem[..4] = [];
    hdrs_dup.push(wing::make_header("DPoP-Nonce", "nonce1"));
    hdrs_dup.push(wing::make_header("DPoP-Nonce", "nonce2"));
    let _, ok_nonce = wing::extract_dpop_nonce(hdrs_dup);
    assert(!ok_nonce);

    var hdrs_bad: wing::HeaderItem[..4] = [];
    hdrs_bad.push(wing::make_header("DPoP-Nonce", "bad nonce with spaces"));
    let _, ok_bad = wing::extract_dpop_nonce(hdrs_bad);
    assert(!ok_bad);
    print("DPOP_NONCE_VALIDATION: OK");
}

// CHECK: DPOP_JKT_VERIFICATION: OK
// CHECK: DPOP_JTI_REPLAY_CACHE: OK
// CHECK: DPOP_JTI_ENTROPY: OK
// CHECK: DPOP_ATTACH_AND_SENSITIVE: OK
// CHECK: DPOP_URI_NORMALIZATION: OK
// CHECK: DPOP_CLAIMS_BUILD: OK
// CHECK: DPOP_HEADER_REJECTIONS: OK
// CHECK: DPOP_NONCE_VALIDATION: OK
