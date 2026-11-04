// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// tests/lit/rfc_repro_auth_jwks_edge.goose
// RFC 7517 / RFC 8725 JWKS Edge Cases, SSRF Defense, and Private Key Rejection.
//
// RUN: goose build --cc gcc -O2 -o %t.exe %s
// RUN: %t.exe | %FileCheck %s

import std;
import core from "../..";
import wing from "../..";

fn main() {
    // ---- 1. RFC 8725 §3.12: Remote JWKS URL SSRF Prevention ---------------
    assert(!wing::is_safe_remote_jwks_url("https://localhost........./jwks.json"));
    assert(!wing::is_safe_remote_jwks_url("https://[::1]/jwks.json"));
    assert(!wing::is_safe_remote_jwks_url("https://[0::1]/jwks.json"));
    assert(!wing::is_safe_remote_jwks_url("https://[::ffff:169.254.169.254]/jwks.json"));
    assert(!wing::is_safe_remote_jwks_url("https://[0::ffff:169.254.169.254]/jwks.json"));
    assert(!wing::is_safe_remote_jwks_url("https://[fd01::1]/jwks.json"));
    assert(!wing::is_safe_remote_jwks_url("https://[fe81::1]/jwks.json"));
    assert(!wing::is_safe_remote_jwks_url("https://127.0.0.300/jwks.json"));
    assert(wing::is_safe_remote_jwks_url("https://auth.example.com/.well-known/jwks.json"));
    print("JWKS_SSRF_DEFENSE: OK");

    // ---- 2. RFC 7517 §4: Reject Private Key Parameters in Public JWKS -----
    let jwk_private = "{\"keys\":[{\"kty\":\"OKP\",\"crv\":\"Ed25519\",\"x\":\"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo\",\"d\":\"secret_private_d_param\",\"kid\":\"key-priv\"}]}";
    var jwks_priv = wing::Jwks { .. };
    assert(!wing::parse_jwks_json(jwk_private, jwks_priv));
    assert(jwks_priv.keys.len == 0);
    print("JWKS_REJECT_PRIVATE_KEY: OK");

    // ---- 3. Duplicate Member Rejection in JWK -----------------------------
    let jwk_dup = "{\"keys\":[{\"kty\":\"OKP\",\"kty\":\"oct\",\"crv\":\"Ed25519\",\"x\":\"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo\",\"kid\":\"key-dup\"}]}";
    var jwks_dup = wing::Jwks { .. };
    assert(!wing::parse_jwks_json(jwk_dup, jwks_dup));
    assert(jwks_dup.keys.len == 0);
    print("JWKS_REJECT_DUPLICATES: OK");
}

// CHECK: JWKS_SSRF_DEFENSE: OK
// CHECK: JWKS_REJECT_PRIVATE_KEY: OK
// CHECK: JWKS_REJECT_DUPLICATES: OK
