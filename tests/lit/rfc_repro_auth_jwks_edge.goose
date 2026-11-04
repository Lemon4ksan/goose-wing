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

    // ---- 4. Overflowing Dummy Fields, Duplicate Root Keys, & Bounds --------
    let jwk_many_fields = "{\"keys\":[{\"a1\":1,\"a2\":2,\"a3\":3,\"a4\":4,\"a5\":5,\"a6\":6,\"a7\":7,\"a8\":8,\"a9\":9,\"a10\":10,\"a11\":11,\"a12\":12,\"a13\":13,\"a14\":14,\"a15\":15,\"a16\":16,\"kty\":\"OKP\",\"crv\":\"Ed25519\",\"x\":\"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo\"}]}";
    var jwks_many = wing::Jwks { .. };
    assert(!wing::parse_jwks_json(jwk_many_fields, jwks_many));

    let jwk_dup_root = "{\"keys\":[{\"kty\":\"OKP\",\"crv\":\"Ed25519\",\"x\":\"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo\"}],\"keys\":[]}";
    assert(!wing::parse_jwks_json(jwk_dup_root, jwks_many));
    assert(jwks_many.keys.len == 0);

    var jwks_sym = wing::Jwks { .. };
    assert(!wing::add_symmetric_key(jwks_sym, "k1", wing::JwtAlg.EdDSA, "0123456789abcdef0123456789abcdef"));
    assert(!wing::add_symmetric_key(jwks_sym, "k1", wing::JwtAlg.None, "0123456789abcdef0123456789abcdef"));
    assert(wing::add_symmetric_key(jwks_sym, "k1", wing::JwtAlg.HS256, "0123456789abcdef0123456789abcdef"));
    var tiny_tp: u8[..16] = [];
    assert(!wing::compute_jwk_thumbprint(jwks_sym.keys[0], tiny_tp));
    print("JWKS_BOUNDS_AND_ALG_HARDENING: OK");
}

// CHECK: JWKS_SSRF_DEFENSE: OK
// CHECK: JWKS_REJECT_PRIVATE_KEY: OK
// CHECK: JWKS_REJECT_DUPLICATES: OK
// CHECK: JWKS_BOUNDS_AND_ALG_HARDENING: OK
