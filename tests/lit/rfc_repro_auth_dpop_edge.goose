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
}

// CHECK: DPOP_JKT_VERIFICATION: OK
// CHECK: DPOP_JTI_REPLAY_CACHE: OK
// CHECK: DPOP_JTI_ENTROPY: OK
