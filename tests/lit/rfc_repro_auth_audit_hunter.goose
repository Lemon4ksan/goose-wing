// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// tests/lit/rfc_repro_auth_audit_hunter.goose
// RFC Conformance and Bug Hunter Repro for Auth Subsystem:
// 1. RFC 8725 §3.1: verify_jwt_hmac must reject non-HMAC alg with AlgorithmMismatch
// 2. RFC 7518 §6.3.2.7: parse_jwks_json must reject JWKs containing 'oth' private key parameter
// 3. RFC 7616 §3.4: sync_digest_stale_challenge must permit empty password (passwd = *OCTET)
//
// RUN: goose build --cc gcc -O2 -o %t.exe %s
// RUN: %t.exe | %FileCheck %s

import std;
import core from "../..";
import wing from "../..";

fn test_jwt_hmac_alg_confusion() {
    var opts_eddsa = wing::JwtValidationOptions { .. };
    opts_eddsa.expected_alg = wing::JwtAlg.EdDSA;
    var eddsa_h = wing::JwtHeader { .. };
    var eddsa_c = wing::JwtClaims { .. };

    // Header: {"alg":"EdDSA","typ":"JWT"} -> eyJhbGciOiJFZERTQSIsInR5cCI6IkpXVCJ9
    // Claims: {"sub":"alice"}              -> eyJzdWIiOiJhbGljZSJ9
    // Sig:    c2lnbmF0dXJl
    let eddsa_token = "eyJhbGciOiJFZERTQSIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJhbGljZSJ9.c2lnbmF0dXJl";
    let err = wing::verify_jwt_hmac(
        eddsa_token,
        "dummy_key_01234567890123456789!",
        opts_eddsa,
        1714000000,
        eddsa_h,
        eddsa_c,
    );
    assert(err == wing::JwtError.AlgorithmMismatch);
    print("REPRO_JWT_HMAC_ALG_CONFUSION: PASS");
}

fn test_jwks_reject_oth_private_key() {
    let jwk_oth = "{\"keys\":[{\"kty\":\"OKP\",\"crv\":\"Ed25519\",\"x\":\"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo\",\"oth\":[{\"r\":\"dummy\"}],\"kid\":\"key-oth\"}]}";
    var jwks_oth = wing::Jwks { .. };
    let parsed = wing::parse_jwks_json(jwk_oth, jwks_oth);
    assert(!parsed);
    assert(jwks_oth.keys.len == 0);
    print("REPRO_JWKS_REJECT_OTH: PASS");
}

fn test_digest_stale_empty_password() {
    var stored_chal = wing::DigestChallenge { .. };
    stored_chal.valid = true;
    stored_chal.nonce.append("old_nonce_1");
    stored_chal.realm.append("api@example.com");
    stored_chal.algorithm.append("SHA-256");

    var incoming_chal = wing::DigestChallenge { .. };
    incoming_chal.valid = true;
    incoming_chal.stale = true;
    incoming_chal.nonce.append("fresh_nonce_2");
    incoming_chal.realm.append("api@example.com");
    incoming_chal.algorithm.append("SHA-256");

    var empty_pwd_creds = wing::DigestCredentials { .. };
    empty_pwd_creds.username.append("guest_user");
    // password is intentionally empty per RFC 7616 passwd = *OCTET

    var nc: u32 = 5;
    let sync_ok = wing::sync_digest_stale_challenge(stored_chal, incoming_chal, empty_pwd_creds, nc);
    assert(sync_ok);
    assert(stored_chal.nonce == "fresh_nonce_2");
    assert(nc == 1);
    print("REPRO_DIGEST_EMPTY_PASSWORD_STALE: PASS");
}

fn main() {
    test_jwt_hmac_alg_confusion();
    test_jwks_reject_oth_private_key();
    test_digest_stale_empty_password();
}

// CHECK: REPRO_JWT_HMAC_ALG_CONFUSION: PASS
// CHECK: REPRO_JWKS_REJECT_OTH: PASS
// CHECK: REPRO_DIGEST_EMPTY_PASSWORD_STALE: PASS
