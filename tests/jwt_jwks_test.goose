// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// tests/jwt_jwks_test.goose
// Verification suite for Universal JWT (RFC 7519), JWS (RFC 7515), and JWKS (RFC 7517).
// 1. Symmetric HMAC JWS (HS256, HS384, HS512) Signing & Verification
// 2. Asymmetric Ed25519 JWS (EdDSA / RFC 8037) Signing & Verification
// 3. RFC 8725 BCP Security Defenses (Algorithm Confusion, none-alg, Expiry, Leeway, Identity)
// 4. RFC 7517 JWKS Serialization, Parsing, and Key Rotation
// 5. Integrated JWT Verification against JWKS Key Set
import std;
import core from "..";
import wing from "..";

// ----------------------------------------------------------------------------
// 1. Symmetric HMAC JWS (HS256, HS384, HS512) Signing & Verification
// ----------------------------------------------------------------------------
fn test_symmetric_hmac_jwt(t: core::T&) {
    let secret = "super-secret-hmac-key-32byteslong!";
    let now_sec: i64 = 1770000000;

    t.run("HS256 token generation and validation") { sub =>
        var hdr = wing::new_jwt_header(wing::JwtAlg.HS256, "key-hs256");
        var clm = wing::JwtClaims { .. };
        wing::set_issuer(clm, "https://auth.goose-wing.dev");
        wing::set_subject(clm, "user_42");
        wing::set_audience(clm, "api.service.internal");
        wing::set_jwt_id(clm, "jwt-uuid-001");
        wing::set_expiry(clm, now_sec + 3600);
        wing::set_issued_at(clm, now_sec);
        wing::set_claim(clm, "role", "admin");
        wing::set_claim_int(clm, "tier", 5);
        wing::set_claim_bool(clm, "verified", true);

        var token: u8[>..] = [];
        let ok_sign = wing::sign_jwt_hmac(hdr, clm, secret, token);
        sub.assert_true(ok_sign, "HS256 token signed");
        sub.assert_true(token.len > 80, "Token has valid length");

        // Verify token
        var out_hdr = wing::new_jwt_header();
        var out_clm = wing::JwtClaims { .. };
        var opts = wing::default_jwt_validation_options(wing::JwtAlg.HS256);
        opts.expected_issuer.append("https://auth.goose-wing.dev");
        opts.expected_audience.append("api.service.internal");
        opts.expected_subject.append("user_42");

        let err = wing::verify_jwt_hmac(token[..], secret, opts, now_sec, out_hdr, out_clm);
        sub.assert_eq(err, wing::JwtError.None, "Token verified cleanly");
        sub.assert_eq(out_hdr.alg, wing::JwtAlg.HS256, "Alg is HS256");
        sub.assert_bytes_eq(out_hdr.kid[..], "key-hs256", "kid matches");
        sub.assert_bytes_eq(wing::claim_str(out_clm, "sub"), "user_42", "sub matches");
        sub.assert_bytes_eq(wing::claim_str(out_clm, "role"), "admin", "custom role claim");
        let tier, ok_tier = wing::claim_int(out_clm, "tier");
        sub.assert_true(ok_tier, "tier claim present");
        sub.assert_eq(tier, 5, "tier is 5");
        let verified, ok_ver = wing::claim_bool(out_clm, "verified");
        sub.assert_true(ok_ver, "verified claim present");
        sub.assert_true(verified, "verified is true");
    };

    t.run("HS384 and HS512 multi-algorithm verification") { sub =>
        // HS384
        var hdr384 = wing::new_jwt_header(wing::JwtAlg.HS384);
        var clm384 = wing::JwtClaims { .. };
        wing::set_subject(clm384, "agent_384");
        wing::set_expiry(clm384, now_sec + 100);

        var token384: u8[>..] = [];
        sub.assert_true(wing::sign_jwt_hmac(hdr384, clm384, secret, token384), "HS384 signed");

        var out_hdr384 = wing::new_jwt_header();
        var out_clm384 = wing::JwtClaims { .. };
        var opts384 = wing::default_jwt_validation_options(wing::JwtAlg.HS384);
        let err384 = wing::verify_jwt_hmac(token384[..], secret, opts384, now_sec, out_hdr384, out_clm384);
        sub.assert_eq(err384, wing::JwtError.None, "HS384 verified");
        sub.assert_bytes_eq(wing::claim_str(out_clm384, "sub"), "agent_384", "HS384 sub");

        // HS512
        var hdr512 = wing::new_jwt_header(wing::JwtAlg.HS512);
        var clm512 = wing::JwtClaims { .. };
        wing::set_subject(clm512, "agent_512");
        wing::set_expiry(clm512, now_sec + 100);

        var token512: u8[>..] = [];
        sub.assert_true(wing::sign_jwt_hmac(hdr512, clm512, secret, token512), "HS512 signed");

        var out_hdr512 = wing::new_jwt_header();
        var out_clm512 = wing::JwtClaims { .. };
        var opts512 = wing::default_jwt_validation_options(wing::JwtAlg.HS512);
        let err512 = wing::verify_jwt_hmac(token512[..], secret, opts512, now_sec, out_hdr512, out_clm512);
        sub.assert_eq(err512, wing::JwtError.None, "HS512 verified");
        sub.assert_bytes_eq(wing::claim_str(out_clm512, "sub"), "agent_512", "HS512 sub");
    };

    t.run("Tampered payload or signature rejected") { sub =>
        var hdr = wing::new_jwt_header(wing::JwtAlg.HS256);
        var clm = wing::JwtClaims { .. };
        wing::set_subject(clm, "original_user");
        wing::set_expiry(clm, now_sec + 600);

        var token: u8[>..] = [];
        wing::sign_jwt_hmac(hdr, clm, secret, token);

        // Tamper with one byte in signature
        var tampered_sig: u8[>..] = [];
        tampered_sig.append(token[..]);
        tampered_sig[tampered_sig.len - 2] = if tampered_sig[tampered_sig.len - 2] == 'A' { 'B' } else { 'A' };

        var out_h = wing::new_jwt_header();
        var out_c = wing::JwtClaims { .. };
        var opts_sig = wing::default_jwt_validation_options(wing::JwtAlg.HS256);
        let err_sig = wing::verify_jwt_hmac(tampered_sig[..], secret, opts_sig, now_sec, out_h, out_c);
        sub.assert_eq(err_sig, wing::JwtError.SignatureInvalid, "Tampered signature rejected");

        // Wrong secret key
        var opts_key = wing::default_jwt_validation_options(wing::JwtAlg.HS256);
        let err_key = wing::verify_jwt_hmac(token[..], "wrong-secret-key-32byteslong!", opts_key, now_sec, out_h, out_c);
        sub.assert_eq(err_key, wing::JwtError.SignatureInvalid, "Wrong secret rejected");
    };
}

// ----------------------------------------------------------------------------
// 2. Asymmetric Ed25519 JWS (EdDSA / RFC 8037) Signing & Verification
// ----------------------------------------------------------------------------
fn test_asymmetric_eddsa_jwt(t: core::T&) {
    let seed: u8[32] = [
        0x9d, 0x61, 0xb1, 0x9c, 0xfa, 0xd6, 0x47, 0xba,
        0xaa, 0x3e, 0x9d, 0x10, 0xc6, 0x03, 0xac, 0x41,
        0xce, 0xb5, 0xd7, 0x2c, 0x2e, 0x8b, 0x4e, 0x43,
        0xf3, 0x8f, 0x3c, 0xeb, 0x17, 0x1a, 0x8e, 0x1e,
    ];
    let public_key = core::ed25519_public_key(seed);
    let now_sec: i64 = 1770000000;

    t.run("EdDSA token generation and validation") { sub =>
        var hdr = wing::new_jwt_header(wing::JwtAlg.EdDSA, "ed25519-root-key");
        var clm = wing::JwtClaims { .. };
        wing::set_issuer(clm, "https://id.goose.io");
        wing::set_subject(clm, "srv_identity_ed25519");
        wing::set_expiry(clm, now_sec + 1800);
        wing::set_claim(clm, "scope", "cluster:admin");

        var token: u8[>..] = [];
        let ok_sign = wing::sign_jwt_eddsa(hdr, clm, seed, token);
        sub.assert_true(ok_sign, "EdDSA token signed");

        var out_hdr = wing::new_jwt_header();
        var out_clm = wing::JwtClaims { .. };
        var opts = wing::default_jwt_validation_options(wing::JwtAlg.EdDSA);
        opts.expected_issuer.append("https://id.goose.io");

        let err = wing::verify_jwt_eddsa(token[..], public_key, opts, now_sec, out_hdr, out_clm);
        sub.assert_eq(err, wing::JwtError.None, "EdDSA verified with public key");
        sub.assert_eq(out_hdr.alg, wing::JwtAlg.EdDSA, "Alg is EdDSA");
        sub.assert_bytes_eq(out_hdr.kid[..], "ed25519-root-key", "kid is ed25519-root-key");
        sub.assert_bytes_eq(wing::claim_str(out_clm, "scope"), "cluster:admin", "scope claim matches");
    };

    t.run("EdDSA signature tampering and wrong public key") { sub =>
        var hdr = wing::new_jwt_header(wing::JwtAlg.EdDSA);
        var clm = wing::JwtClaims { .. };
        wing::set_subject(clm, "device_007");
        wing::set_expiry(clm, now_sec + 600);

        var token: u8[>..] = [];
        wing::sign_jwt_eddsa(hdr, clm, seed, token);

        // Wrong public key (all zeros)
        let zero_pub: u8[32] = [0; 32];
        var out_h = wing::new_jwt_header();
        var out_c = wing::JwtClaims { .. };
        var opts_bad = wing::default_jwt_validation_options(wing::JwtAlg.EdDSA);
        let err_bad_key = wing::verify_jwt_eddsa(token[..], zero_pub, opts_bad, now_sec, out_h, out_c);
        sub.assert_eq(err_bad_key, wing::JwtError.SignatureInvalid, "Invalid public key rejected");
    };
}

// ----------------------------------------------------------------------------
// 3. RFC 8725 BCP Security Defenses
// ----------------------------------------------------------------------------
fn test_jwt_security_defenses(t: core::T&) {
    let secret = "secret-for-security-tests-123456";
    let now_sec: i64 = 1770000000;

    t.run("Algorithm Confusion Defense (RFC 8725 Section 3.1)") { sub =>
        // Attacker creates HS256 token, but server expects EdDSA
        var hdr = wing::new_jwt_header(wing::JwtAlg.HS256);
        var clm = wing::JwtClaims { .. };
        wing::set_subject(clm, "victim");
        wing::set_expiry(clm, now_sec + 300);

        var token: u8[>..] = [];
        wing::sign_jwt_hmac(hdr, clm, secret, token);

        var out_h = wing::new_jwt_header();
        var out_c = wing::JwtClaims { .. };
        let dummy_pub: u8[32] = [0x55; 32];
        var opts_conf = wing::default_jwt_validation_options(wing::JwtAlg.EdDSA);
        let err = wing::verify_jwt_eddsa(token[..], dummy_pub, opts_conf, now_sec, out_h, out_c);
        sub.assert_eq(err, wing::JwtError.AlgorithmMismatch, "Algorithm confusion rejected");
    };

    t.run("Algorithm Confusion: EdDSA token rejected when HS256 expected (RFC 8725 Section 3.1)") { sub =>
        let seed: u8[32] = [
            0x9d, 0x61, 0xb1, 0x9c, 0xfa, 0xd6, 0x47, 0xba,
            0xaa, 0x3e, 0x9d, 0x10, 0xc6, 0x03, 0xac, 0x41,
            0xce, 0xb5, 0xd7, 0x2c, 0x2e, 0x8b, 0x4e, 0x43,
            0xf3, 0x8f, 0x3c, 0xeb, 0x17, 0x1a, 0x8e, 0x1e,
        ];
        let public_key = core::ed25519_public_key(seed);
        var hdr = wing::new_jwt_header(wing::JwtAlg.EdDSA);
        var clm = wing::JwtClaims { .. };
        wing::set_subject(clm, "victim");
        wing::set_expiry(clm, now_sec + 300);

        var token: u8[>..] = [];
        wing::sign_jwt_eddsa(hdr, clm, seed, token);

        var out_h = wing::new_jwt_header();
        var out_c = wing::JwtClaims { .. };
        var opts_conf = wing::default_jwt_validation_options(wing::JwtAlg.HS256);
        let err = wing::verify_jwt_eddsa(token[..], public_key, opts_conf, now_sec, out_h, out_c);
        sub.assert_eq(err, wing::JwtError.AlgorithmMismatch, "EdDSA token rejected when HS256 expected");
    };

    t.run("none Algorithm Rejection (CVE-2015-9235 Defense)") { sub =>
        // Attacker sends token with alg: "none" and empty signature: "eyJhbGciOiJub25lIn0.eyJzdWIiOiJhZG1pbiJ9."
        let none_token = "eyJhbGciOiJub25lIn0.eyJzdWIiOiJhZG1pbiJ9.";
        var out_h = wing::new_jwt_header();
        var out_c = wing::JwtClaims { .. };
        var opts_none = wing::default_jwt_validation_options(wing::JwtAlg.HS256);
        let err = wing::verify_jwt_hmac(none_token, secret, opts_none, now_sec, out_h, out_c);
        sub.assert_eq(err, wing::JwtError.UnsupportedAlgorithm, "none algorithm rejected by default");
    };

    t.run("Expiration and Clock Skew Leeway (exp)") { sub =>
        var hdr = wing::new_jwt_header(wing::JwtAlg.HS256);
        var clm = wing::JwtClaims { .. };
        wing::set_subject(clm, "time_traveler");
        wing::set_expiry(clm, now_sec - 100); // Expired 100 seconds ago

        var token: u8[>..] = [];
        wing::sign_jwt_hmac(hdr, clm, secret, token);

        var out_h = wing::new_jwt_header();
        var out_c = wing::JwtClaims { .. };

        // 1. With standard 60s leeway -> still expired (100 > 60)
        var opts60 = wing::default_jwt_validation_options(wing::JwtAlg.HS256);
        opts60.leeway_seconds = 60;
        let err_exp = wing::verify_jwt_hmac(token[..], secret, opts60, now_sec, out_h, out_c);
        sub.assert_eq(err_exp, wing::JwtError.TokenExpired, "Expired token rejected");

        // 2. With 120s leeway -> within leeway window -> accepted!
        var opts120 = wing::default_jwt_validation_options(wing::JwtAlg.HS256);
        opts120.leeway_seconds = 120;
        let err_ok = wing::verify_jwt_hmac(token[..], secret, opts120, now_sec, out_h, out_c);
        sub.assert_eq(err_ok, wing::JwtError.None, "Token within leeway window accepted");
    };

    t.run("Not Before check (nbf)") { sub =>
        var hdr = wing::new_jwt_header(wing::JwtAlg.HS256);
        var clm = wing::JwtClaims { .. };
        wing::set_subject(clm, "future_user");
        wing::set_not_before(clm, now_sec + 200); // Valid only in 200 seconds
        wing::set_expiry(clm, now_sec + 1000);

        var token: u8[>..] = [];
        wing::sign_jwt_hmac(hdr, clm, secret, token);

        var out_h = wing::new_jwt_header();
        var out_c = wing::JwtClaims { .. };
        var opts = wing::default_jwt_validation_options(wing::JwtAlg.HS256);
        opts.leeway_seconds = 30;

        let err = wing::verify_jwt_hmac(token[..], secret, opts, now_sec, out_h, out_c);
        sub.assert_eq(err, wing::JwtError.TokenNotYetValid, "Token not yet valid rejected");
    };

    t.run("Issuer, Audience, Subject Mismatch Rejections") { sub =>
        var hdr = wing::new_jwt_header(wing::JwtAlg.HS256);
        var clm = wing::JwtClaims { .. };
        wing::set_issuer(clm, "auth.real.com");
        wing::set_audience(clm, "app.real.com");
        wing::set_subject(clm, "user.real");
        wing::set_expiry(clm, now_sec + 600);

        var token: u8[>..] = [];
        wing::sign_jwt_hmac(hdr, clm, secret, token);

        var out_h = wing::new_jwt_header();
        var out_c = wing::JwtClaims { .. };

        // Mismatched Issuer
        var opts_iss = wing::default_jwt_validation_options(wing::JwtAlg.HS256);
        opts_iss.expected_issuer.append("auth.fake.com");
        sub.assert_eq(wing::verify_jwt_hmac(token[..], secret, opts_iss, now_sec, out_h, out_c), wing::JwtError.IssuerMismatch, "Issuer mismatch");

        // Mismatched Audience
        var opts_aud = wing::default_jwt_validation_options(wing::JwtAlg.HS256);
        opts_aud.expected_audience.append("app.fake.com");
        sub.assert_eq(wing::verify_jwt_hmac(token[..], secret, opts_aud, now_sec, out_h, out_c), wing::JwtError.AudienceMismatch, "Audience mismatch");

        // Mismatched Subject
        var opts_sub = wing::default_jwt_validation_options(wing::JwtAlg.HS256);
        opts_sub.expected_subject.append("user.fake");
        sub.assert_eq(wing::verify_jwt_hmac(token[..], secret, opts_sub, now_sec, out_h, out_c), wing::JwtError.SubjectMismatch, "Subject mismatch");
    };
}

// ----------------------------------------------------------------------------
// 4. RFC 7517 JWKS Serialization, Parsing, and Key Rotation
// ----------------------------------------------------------------------------
fn test_jwks_serialization_and_parsing(t: core::T&) {
    t.run("JWKS serialize and parse roundtrip") { sub =>
        var jwks = wing::Jwks { .. };

        // 1. Add Ed25519 public key
        let ed_pub: u8[32] = [
            0x2f, 0x5a, 0x7b, 0x11, 0x88, 0x99, 0xaa, 0xbb,
            0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11, 0x22, 0x33,
            0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb,
            0xcc, 0xdd, 0xee, 0xff, 0x12, 0x34, 0x56, 0x78,
        ];
        wing::add_ed25519_key(jwks, "ed25519-key-2026", ed_pub);

        // 2. Add Symmetric HMAC key
        let hmac_sec = "secret-sym-key-16b";
        wing::add_symmetric_key(jwks, "hmac-key-2026", wing::JwtAlg.HS256, hmac_sec);

        sub.assert_eq(jwks.keys.len, 2, "2 keys in JWKS");
        sub.assert_eq(wing::find_key(jwks, "ed25519-key-2026"), 0, "Find ed key idx");
        sub.assert_eq(wing::find_key(jwks, "hmac-key-2026"), 1, "Find hmac key idx");
        sub.assert_eq(wing::find_key(jwks, "unknown-key"), -1, "Unknown key returns -1");

        // Serialize to JSON
        var jwks_json: u8[>..] = [];
        wing::serialize_jwks(jwks, jwks_json);

        sub.assert_contains(jwks_json[..], "\"keys\":[", "Contains keys array");
        sub.assert_contains(jwks_json[..], "\"kid\":\"ed25519-key-2026\"", "Contains ed kid");
        sub.assert_contains(jwks_json[..], "\"kty\":\"OKP\"", "Contains OKP kty");
        sub.assert_contains(jwks_json[..], "\"crv\":\"Ed25519\"", "Contains Ed25519 curve");
        sub.assert_contains(jwks_json[..], "\"kid\":\"hmac-key-2026\"", "Contains hmac kid");

        // Parse back from JSON
        var parsed_jwks = wing::Jwks { .. };
        let ok_parse = wing::parse_jwks_json(jwks_json[..], parsed_jwks);
        sub.assert_true(ok_parse, "JWKS parsed from JSON");
        sub.assert_eq(parsed_jwks.keys.len, 2, "2 parsed keys");

        let k0 = parsed_jwks.keys[0];
        sub.assert_eq(k0.kty, wing::JwkKeyType.OKP, "k0 kty OKP");
        sub.assert_bytes_eq(k0.kid[..], "ed25519-key-2026", "k0 kid");
        sub.assert_bytes_eq(k0.public_key[..], ed_pub[..], "k0 public key matches");

        let k1 = parsed_jwks.keys[1];
        sub.assert_eq(k1.kty, wing::JwkKeyType.Oct, "k1 kty Oct");
        sub.assert_bytes_eq(k1.kid[..], "hmac-key-2026", "k1 kid");
        sub.assert_bytes_eq(k1.symmetric_key[..], hmac_sec, "k1 symmetric key matches");
    };

    t.run("JWK Parser Defenses: Missing kty, unknown kty, invalid alg & overflows rejected") { sub =>
        // 1. Missing kty in JWK
        let jwk_no_kty = "{\"keys\":[{\"crv\":\"Ed25519\",\"x\":\"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo\"}]}";
        var jwks1 = wing::Jwks { .. };
        sub.assert_false(wing::parse_jwks_json(jwk_no_kty, jwks1), "Missing kty rejected");

        // 2. Unknown kty in JWK (e.g. RSA or EC)
        let jwk_rsa = "{\"keys\":[{\"kty\":\"RSA\",\"n\":\"...\",\"e\":\"AQAB\"}]}";
        var jwks2 = wing::Jwks { .. };
        sub.assert_false(wing::parse_jwks_json(jwk_rsa, jwks2), "Unknown kty RSA rejected");

        // 3. Unsupported alg in JWK (e.g. RS256 or none)
        let jwk_bad_alg = "{\"keys\":[{\"kty\":\"oct\",\"alg\":\"RS256\",\"k\":\"c2VjcmV0LXN5bS1rZXktMTZieXRlcw\"}]}";
        var jwks3 = wing::Jwks { .. };
        sub.assert_false(wing::parse_jwks_json(jwk_bad_alg, jwks3), "Unsupported alg RS256 rejected");

        let jwk_none_alg = "{\"keys\":[{\"kty\":\"oct\",\"alg\":\"none\",\"k\":\"c2VjcmV0LXN5bS1rZXktMTZieXRlcw\"}]}";
        var jwks4 = wing::Jwks { .. };
        sub.assert_false(wing::parse_jwks_json(jwk_none_alg, jwks4), "Explicit alg:none in JWK rejected");

        // 4. Oversize kid (> 64 bytes)
        let jwk_long_kid = "{\"keys\":[{\"kty\":\"oct\",\"k\":\"c2VjcmV0LXN5bS1rZXktMTZieXRlcw\",\"kid\":\"this-key-identifier-is-intentionally-crafted-to-exceed-the-sixty-four-byte-limit-enforced-by-jwks\"}]}";
        var jwks5 = wing::Jwks { .. };
        sub.assert_false(wing::parse_jwks_json(jwk_long_kid, jwks5), "Oversize kid rejected");

        // 5. add_symmetric_key enforces >= 16 bytes (RFC 8725 §3.6)
        var jwks_api = wing::Jwks { .. };
        sub.assert_false(wing::add_symmetric_key(jwks_api, "short-key", wing::JwtAlg.HS256, "short"), "Key < 16 bytes rejected");
        sub.assert_true(wing::add_symmetric_key(jwks_api, "valid-key", wing::JwtAlg.HS256, "1234567890123456"), "Key == 16 bytes accepted");

        // 6. resolve_jwks_key_index: empty kid token rejected when single JWK has configured non-empty kid
        sub.assert_eq(wing::resolve_jwks_key_index(jwks_api, ""), -1, "Empty kid does not match key with explicit kid");

        var jwks_anon = wing::Jwks { .. };
        sub.assert_true(wing::add_symmetric_key(jwks_anon, "", wing::JwtAlg.HS256, "1234567890123456"), "Add anon key");
        sub.assert_eq(wing::resolve_jwks_key_index(jwks_anon, ""), 0, "Empty kid matches anon single key");
    };
}

// ----------------------------------------------------------------------------
// 5. Integrated JWT Verification against JWKS Key Set
// ----------------------------------------------------------------------------
fn test_jwt_verification_against_jwks(t: core::T&) {
    let now_sec: i64 = 1770000000;
    let ed_seed: u8[32] = [
        0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80,
        0x90, 0xa0, 0xb0, 0xc0, 0xd0, 0xe0, 0xf0, 0x00,
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x11,
    ];
    let ed_pub = core::ed25519_public_key(ed_seed);
    let hmac_sec = "shared-vault-secret-token-key-256";

    // Setup active JWKS with multiple keys
    var jwks = wing::Jwks { .. };
    wing::add_ed25519_key(jwks, "auth-srv-v1", ed_pub);
    wing::add_symmetric_key(jwks, "legacy-sym-v1", wing::JwtAlg.HS256, hmac_sec);

    t.run("Verify EdDSA token using JWKS key lookup") { sub =>
        var hdr = wing::new_jwt_header(wing::JwtAlg.EdDSA, "auth-srv-v1");
        var clm = wing::JwtClaims { .. };
        wing::set_issuer(clm, "auth.corp.com");
        wing::set_subject(clm, "admin_alice");
        wing::set_expiry(clm, now_sec + 600);

        var token: u8[>..] = [];
        wing::sign_jwt_eddsa(hdr, clm, ed_seed, token);

        var out_h = wing::new_jwt_header();
        var out_c = wing::JwtClaims { .. };
        var opts = wing::default_jwt_validation_options(wing::JwtAlg.EdDSA);
        opts.expected_issuer.append("auth.corp.com");

        let err = wing::verify(token[..], jwks, opts, now_sec, out_h, out_c);
        sub.assert_eq(err, wing::JwtError.None, "EdDSA token verified through JWKS");
        sub.assert_bytes_eq(out_h.kid[..], "auth-srv-v1", "kid resolved correctly");
        sub.assert_bytes_eq(wing::claim_str(out_c, "sub"), "admin_alice", "Subject matches");
    };

    t.run("Verify HMAC token using JWKS key lookup") { sub =>
        var hdr = wing::new_jwt_header(wing::JwtAlg.HS256, "legacy-sym-v1");
        var clm = wing::JwtClaims { .. };
        wing::set_subject(clm, "service_worker");
        wing::set_expiry(clm, now_sec + 600);

        var token: u8[>..] = [];
        wing::sign_jwt_hmac(hdr, clm, hmac_sec, token);

        var out_h = wing::new_jwt_header();
        var out_c = wing::JwtClaims { .. };
        let opts = wing::default_jwt_validation_options(wing::JwtAlg.HS256);

        let err = wing::verify(token[..], jwks, opts, now_sec, out_h, out_c);
        sub.assert_eq(err, wing::JwtError.None, "HMAC token verified through JWKS");
        sub.assert_bytes_eq(out_h.kid[..], "legacy-sym-v1", "kid resolved");
        sub.assert_bytes_eq(wing::claim_str(out_c, "sub"), "service_worker", "Subject matches");
    };

    t.run("Unknown kid in token rejected with KeyNotFound") { sub =>
        var hdr = wing::new_jwt_header(wing::JwtAlg.HS256, "unregistered-kid-999");
        var clm = wing::JwtClaims { .. };
        wing::set_subject(clm, "intruder");
        wing::set_expiry(clm, now_sec + 600);

        var token: u8[>..] = [];
        wing::sign_jwt_hmac(hdr, clm, hmac_sec, token);

        var out_h = wing::new_jwt_header();
        var out_c = wing::JwtClaims { .. };
        let opts = wing::default_jwt_validation_options(wing::JwtAlg.HS256);

        let err = wing::verify(token[..], jwks, opts, now_sec, out_h, out_c);
        sub.assert_eq(err, wing::JwtError.KeyNotFound, "Unknown kid returned KeyNotFound");
    };

    t.run("JWKS Algorithm Confusion: EdDSA token rejected when HS256 expected (RFC 8725 §3.1)") { sub =>
        var hdr = wing::new_jwt_header(wing::JwtAlg.EdDSA, "auth-srv-v1");
        var clm = wing::JwtClaims { .. };
        wing::set_subject(clm, "victim");
        wing::set_expiry(clm, now_sec + 300);

        var token: u8[>..] = [];
        wing::sign_jwt_eddsa(hdr, clm, ed_seed, token);

        var out_h = wing::new_jwt_header();
        var out_c = wing::JwtClaims { .. };
        var opts = wing::default_jwt_validation_options(wing::JwtAlg.HS256);
        let err = wing::verify(token[..], jwks, opts, now_sec, out_h, out_c);
        sub.assert_eq(err, wing::JwtError.AlgorithmMismatch, "JWKS verify rejects EdDSA when HS256 expected");
    };

    t.run("JWKS Key Usage Constraint: enc key rejected for verification (RFC 7517 §4.2)") { sub =>
        var jwks_enc = wing::Jwks { .. };
        var key = wing::JwksKey {
            kty: wing::JwkKeyType.OKP,
            crv: "Ed25519",
            alg: wing::JwtAlg.EdDSA,
            use: "enc",
            public_key: ed_pub,
            valid: true,
            ..
        };
        key.kid.append("enc-key-1");
        jwks_enc.keys.push(key);

        var hdr = wing::new_jwt_header(wing::JwtAlg.EdDSA, "enc-key-1");
        var clm = wing::JwtClaims { .. };
        wing::set_subject(clm, "victim");
        wing::set_expiry(clm, now_sec + 300);

        var token: u8[>..] = [];
        wing::sign_jwt_eddsa(hdr, clm, ed_seed, token);

        var out_h = wing::new_jwt_header();
        var out_c = wing::JwtClaims { .. };
        var opts = wing::default_jwt_validation_options(wing::JwtAlg.EdDSA);
        let err = wing::verify(token[..], jwks_enc, opts, now_sec, out_h, out_c);
        sub.assert_eq(err, wing::JwtError.UnsupportedAlgorithm, "enc key rejected for signature verification");
    };

    t.run("JWKS Key Algorithm Constraint: mismatched alg rejected (RFC 7517 §4.4)") { sub =>
        var jwks_alg = wing::Jwks { .. };
        wing::add_symmetric_key(jwks_alg, "hs256-only-key", wing::JwtAlg.HS256, hmac_sec);

        var hdr = wing::new_jwt_header(wing::JwtAlg.HS512, "hs256-only-key");
        var clm = wing::JwtClaims { .. };
        wing::set_subject(clm, "victim");
        wing::set_expiry(clm, now_sec + 300);

        var token: u8[>..] = [];
        wing::sign_jwt_hmac(hdr, clm, hmac_sec, token);

        var out_h = wing::new_jwt_header();
        var out_c = wing::JwtClaims { .. };
        var opts = wing::default_jwt_validation_options(wing::JwtAlg.HS512);
        let err = wing::verify(token[..], jwks_alg, opts, now_sec, out_h, out_c);
        sub.assert_eq(err, wing::JwtError.AlgorithmMismatch, "Mismatched key alg rejected");
    };
}

// ----------------------------------------------------------------------------
// 6. RFC 7519 Claims Parsing, RFC 8725 Defenses & RFC 7638 JWK Thumbprints
// ----------------------------------------------------------------------------
fn craft_raw_jwt<B>(header_json: const u8[:], claims_json: const u8[:], secret: const u8[:], out_token: B&) {
    out_token.clear();
    var h_b64: u8[..256] = [];
    core::base64url_encode(header_json, h_b64);
    var c_b64: u8[..512] = [];
    core::base64url_encode(claims_json, c_b64);
    out_token.append(h_b64[..]);
    out_token.push('.');
    out_token.append(c_b64[..]);
    let sig = core::hmac_sha256(secret, out_token[..]);
    var sig_b64: u8[..64] = [];
    core::base64url_encode(sig[..], sig_b64);
    out_token.push('.');
    out_token.append(sig_b64[..]);
}

fn test_jwt_rfc7519_claims_and_thumbprint(t: core::T&) {
    let secret = "audit-rfc7519-secret-key-32bytes";
    let now_sec: i64 = 1770000000;

    t.run("Duplicate exp claim rejected with InvalidClaimsJson (RFC 7519 §4 / RFC 8725 §2.2)") { sub =>
        let hdr_json = "{\"alg\":\"HS256\",\"typ\":\"JWT\"}";
        // First exp is expired (1000), duplicate exp is future (9999999999)
        let clm_json = "{\"sub\":\"user1\",\"exp\":1000,\"exp\":9999999999}";
        var token: u8[..1024] = [];
        craft_raw_jwt(hdr_json, clm_json, secret, token);

        var out_h = wing::new_jwt_header();
        var out_c = wing::JwtClaims { .. };
        var opts = wing::default_jwt_validation_options(wing::JwtAlg.HS256);
        let err = wing::verify_jwt_hmac(token[..], secret, opts, now_sec, out_h, out_c);
        sub.assert_eq(err, wing::JwtError.InvalidClaimsJson, "Token with duplicate exp claim MUST be rejected");
    };

    t.run("Duplicate sub claim rejected with InvalidClaimsJson (RFC 7519 §4)") { sub =>
        let hdr_json = "{\"alg\":\"HS256\",\"typ\":\"JWT\"}";
        let clm_json = "{\"sub\":\"alice\",\"sub\":\"bob\",\"exp\":2000000000}";
        var token: u8[..1024] = [];
        craft_raw_jwt(hdr_json, clm_json, secret, token);

        var out_h = wing::new_jwt_header();
        var out_c = wing::JwtClaims { .. };
        var opts = wing::default_jwt_validation_options(wing::JwtAlg.HS256);
        let err = wing::verify_jwt_hmac(token[..], secret, opts, now_sec, out_h, out_c);
        sub.assert_eq(err, wing::JwtError.InvalidClaimsJson, "Token with duplicate sub claim MUST be rejected");
    };

    t.run("Duplicate custom claim rejected with InvalidClaimsJson (RFC 7519 §4)") { sub =>
        let hdr_json = "{\"alg\":\"HS256\",\"typ\":\"JWT\"}";
        let clm_json = "{\"sub\":\"alice\",\"role\":\"user\",\"role\":\"admin\",\"exp\":2000000000}";
        var token: u8[..1024] = [];
        craft_raw_jwt(hdr_json, clm_json, secret, token);

        var out_h = wing::new_jwt_header();
        var out_c = wing::JwtClaims { .. };
        var opts = wing::default_jwt_validation_options(wing::JwtAlg.HS256);
        let err = wing::verify_jwt_hmac(token[..], secret, opts, now_sec, out_h, out_c);
        sub.assert_eq(err, wing::JwtError.InvalidClaimsJson, "Token with duplicate custom claim MUST be rejected");
    };

    t.run("Duplicate header alg rejected with InvalidHeaderJson (RFC 7515 §4 / RFC 8725 §2.2)") { sub =>
        let hdr_json = "{\"alg\":\"HS256\",\"alg\":\"HS512\"}";
        let clm_json = "{\"sub\":\"alice\",\"exp\":2000000000}";
        var token: u8[..1024] = [];
        craft_raw_jwt(hdr_json, clm_json, secret, token);

        var out_h = wing::new_jwt_header();
        var out_c = wing::JwtClaims { .. };
        var opts = wing::default_jwt_validation_options(wing::JwtAlg.HS256);
        let err = wing::verify_jwt_hmac(token[..], secret, opts, now_sec, out_h, out_c);
        sub.assert_eq(err, wing::JwtError.InvalidHeaderJson, "Header with duplicate alg MUST be rejected");
    };

    t.run("Negative timestamp in exp rejected with InvalidClaimsJson (RFC 7519 §2 NumericDate)") { sub =>
        let hdr_json = "{\"alg\":\"HS256\",\"typ\":\"JWT\"}";
        let clm_json = "{\"sub\":\"alice\",\"exp\":-10}";
        var token: u8[..1024] = [];
        craft_raw_jwt(hdr_json, clm_json, secret, token);

        var out_h = wing::new_jwt_header();
        var out_c = wing::JwtClaims { .. };
        var opts = wing::default_jwt_validation_options(wing::JwtAlg.HS256);
        opts.require_exp = false; // Even if exp not required, invalid negative timestamp must be rejected
        let err = wing::verify_jwt_hmac(token[..], secret, opts, now_sec, out_h, out_c);
        sub.assert_eq(err, wing::JwtError.InvalidClaimsJson, "Negative timestamp MUST be rejected during claims parsing");
    };

    t.run("Negative leeway rejected in expiration validation (RFC 8725 §2.5)") { sub =>
        var hdr = wing::new_jwt_header(wing::JwtAlg.HS256);
        var clm = wing::JwtClaims { .. };
        wing::set_subject(clm, "alice");
        wing::set_expiry(clm, 1000);

        var token: u8[..1024] = [];
        wing::sign_jwt_hmac(hdr, clm, secret, token);

        var out_h = wing::new_jwt_header();
        var out_c = wing::JwtClaims { .. };
        var opts = wing::default_jwt_validation_options(wing::JwtAlg.HS256);
        opts.leeway_seconds = -1; // Negative leeway must not trigger signed overflow
        let err = wing::verify_jwt_hmac(token[..], secret, opts, 1005, out_h, out_c);
        sub.assert_eq(err, wing::JwtError.TokenExpired, "Negative leeway triggers TokenExpired, preventing signed overflow bypass");
    };

    t.run("RFC 7638 JWK Thumbprint calculation canonical JSON ordering (OKP / Ed25519 & Oct)") { sub =>
        // OKP Key (RFC 8037 §4): canonical order "crv", "kty", "x"
        var okp_key = wing::JwksKey {
            kty: wing::JwkKeyType.OKP,
            crv: "Ed25519",
            alg: wing::JwtAlg.EdDSA, // optional member - must be excluded from canonical JSON
            use: "sig",             // optional member - must be excluded from canonical JSON
            valid: true,
            ..
        };
        okp_key.kid.append("test-key-id-ignored");
        for i in 32 {
            okp_key.public_key[i] = (i + 1) as u8;
        }

        var okp_canonical: u8[..256] = [];
        let ok1 = wing::compute_canonical_jwk(okp_key, okp_canonical);
        sub.assert_true(ok1, "OKP canonical JSON computed");
        // Lexicographical ordering: "crv", then "kty", then "x"
        sub.assert_true(core::starts_with(okp_canonical[..], "{\"crv\":\"Ed25519\",\"kty\":\"OKP\",\"x\":\""), "OKP canonical members ordered crv, kty, x");
        sub.assert_false(core::contains(okp_canonical[..], "alg"), "Canonical JSON excludes alg");
        sub.assert_false(core::contains(okp_canonical[..], "use"), "Canonical JSON excludes use");
        sub.assert_false(core::contains(okp_canonical[..], "kid"), "Canonical JSON excludes kid");

        var okp_thumbprint: u8[..64] = [];
        let ok_tp1 = wing::compute_jwk_thumbprint(okp_key, okp_thumbprint);
        sub.assert_true(ok_tp1, "OKP thumbprint computed");
        sub.assert_eq(okp_thumbprint.len, 43, "Thumbprint is 43 chars (unpadded base64url of SHA-256)");

        // Oct Key (RFC 7638 §3.2): canonical order "k", "kty"
        var oct_key = wing::JwksKey {
            kty: wing::JwkKeyType.Oct,
            alg: wing::JwtAlg.HS256,
            valid: true,
            ..
        };
        oct_key.symmetric_key.append("test-secret-oct-32bytes-padding!");

        var oct_canonical: u8[..256] = [];
        let ok2 = wing::compute_canonical_jwk(oct_key, oct_canonical);
        sub.assert_true(ok2, "Oct canonical JSON computed");
        // Lexicographical ordering: "k" before "kty"
        sub.assert_true(core::starts_with(oct_canonical[..], "{\"k\":\""), "Oct canonical members start with k");
        sub.assert_true(core::ends_with(oct_canonical[..], "\",\"kty\":\"oct\"}"), "Oct canonical members end with kty");
        sub.assert_false(core::contains(oct_canonical[..], "alg"), "Oct canonical JSON excludes alg");

        var oct_thumbprint: u8[..64] = [];
        let ok_tp2 = wing::compute_jwk_thumbprint(oct_key, oct_thumbprint);
        sub.assert_true(ok_tp2, "Oct thumbprint computed");
        sub.assert_eq(oct_thumbprint.len, 43, "Oct thumbprint is 43 chars");
    };
}

// ----------------------------------------------------------------------------
// 7. RFC 7515 §4.1.11 / RFC 8725 §3.8 Critical Headers & RFC 8725 §3.11 Explicit Typ
// ----------------------------------------------------------------------------
fn test_jwt_crit_and_typ_validation(t: core::T&) {
    let secret = "audit-crit-typ-secret-key-32byte";
    let now_sec: i64 = 1770000000;

    t.run("Critical Header (crit) rejected when unsupported (RFC 7515 §4.1.11 / RFC 8725 §3.8)") { sub =>
        let hdr_json = "{\"alg\":\"HS256\",\"typ\":\"JWT\",\"crit\":[\"custom_ext\"],\"custom_ext\":\"confidential\"}";
        let clm_json = "{\"sub\":\"alice\",\"exp\":2000000000}";
        var token: u8[..1024] = [];
        craft_raw_jwt(hdr_json, clm_json, secret, token);

        var out_h = wing::new_jwt_header();
        var out_c = wing::JwtClaims { .. };
        var opts = wing::default_jwt_validation_options(wing::JwtAlg.HS256);
        let err = wing::verify_jwt_hmac(token[..], secret, opts, now_sec, out_h, out_c);
        sub.assert_eq(err, wing::JwtError.CriticalHeaderUnsupported, "Unsupported crit parameter MUST fail verification");
    };

    t.run("Critical Header (crit) accepted when explicitly supported (RFC 7515 §4.1.11)") { sub =>
        let hdr_json = "{\"alg\":\"HS256\",\"typ\":\"JWT\",\"crit\":[\"custom_ext\"],\"custom_ext\":\"confidential\"}";
        let clm_json = "{\"sub\":\"alice\",\"exp\":2000000000}";
        var token: u8[..1024] = [];
        craft_raw_jwt(hdr_json, clm_json, secret, token);

        var out_h = wing::new_jwt_header();
        var out_c = wing::JwtClaims { .. };
        var opts = wing::default_jwt_validation_options(wing::JwtAlg.HS256);
        sub.assert_true(wing::add_supported_crit(opts, "custom_ext"), "Added supported crit parameter");
        let err = wing::verify_jwt_hmac(token[..], secret, opts, now_sec, out_h, out_c);
        sub.assert_eq(err, wing::JwtError.None, "Supported crit parameter passes verification");
        sub.assert_eq(out_h.crit.len, 1, "Parsed crit header length is 1");
        sub.assert_bytes_eq(out_h.crit[0].name[..], "custom_ext", "Parsed crit name matches");
    };

    t.run("Standard header parameter in crit rejected with InvalidHeaderJson (RFC 7515 §4.1.11)") { sub =>
        // RFC 7515 §4.1.11 forbids 'alg', 'typ', 'kid', 'crit', etc. inside 'crit'
        let hdr_json = "{\"alg\":\"HS256\",\"typ\":\"JWT\",\"crit\":[\"alg\"]}";
        let clm_json = "{\"sub\":\"alice\",\"exp\":2000000000}";
        var token: u8[..1024] = [];
        craft_raw_jwt(hdr_json, clm_json, secret, token);

        var out_h = wing::new_jwt_header();
        var out_c = wing::JwtClaims { .. };
        var opts = wing::default_jwt_validation_options(wing::JwtAlg.HS256);
        let err = wing::verify_jwt_hmac(token[..], secret, opts, now_sec, out_h, out_c);
        sub.assert_eq(err, wing::JwtError.InvalidHeaderJson, "Standard parameter 'alg' in crit array MUST be rejected");
    };

    t.run("Parameter listed in crit but missing from header rejected with InvalidHeaderJson (RFC 7515 §4.1.11)") { sub =>
        // 'ext_missing' is listed in crit, but not present as a member in the header
        let hdr_json = "{\"alg\":\"HS256\",\"typ\":\"JWT\",\"crit\":[\"ext_missing\"]}";
        let clm_json = "{\"sub\":\"alice\",\"exp\":2000000000}";
        var token: u8[..1024] = [];
        craft_raw_jwt(hdr_json, clm_json, secret, token);

        var out_h = wing::new_jwt_header();
        var out_c = wing::JwtClaims { .. };
        var opts = wing::default_jwt_validation_options(wing::JwtAlg.HS256);
        let err = wing::verify_jwt_hmac(token[..], secret, opts, now_sec, out_h, out_c);
        sub.assert_eq(err, wing::JwtError.InvalidHeaderJson, "Missing crit member in header MUST be rejected");
    };

    t.run("Empty crit array rejected with InvalidHeaderJson (RFC 7515 §4.1.11)") { sub =>
        let hdr_json = "{\"alg\":\"HS256\",\"typ\":\"JWT\",\"crit\":[]}";
        let clm_json = "{\"sub\":\"alice\",\"exp\":2000000000}";
        var token: u8[..1024] = [];
        craft_raw_jwt(hdr_json, clm_json, secret, token);

        var out_h = wing::new_jwt_header();
        var out_c = wing::JwtClaims { .. };
        var opts = wing::default_jwt_validation_options(wing::JwtAlg.HS256);
        let err = wing::verify_jwt_hmac(token[..], secret, opts, now_sec, out_h, out_c);
        sub.assert_eq(err, wing::JwtError.InvalidHeaderJson, "Empty crit array MUST be rejected");
    };

    t.run("Explicit JWT typ verification succeeds on exact match (RFC 8725 §3.11 & RFC 9068)") { sub =>
        let hdr_json = "{\"alg\":\"HS256\",\"typ\":\"at+jwt\"}";
        let clm_json = "{\"sub\":\"alice\",\"exp\":2000000000}";
        var token: u8[..1024] = [];
        craft_raw_jwt(hdr_json, clm_json, secret, token);

        var out_h = wing::new_jwt_header();
        var out_c = wing::JwtClaims { .. };
        var opts = wing::default_jwt_validation_options(wing::JwtAlg.HS256);
        wing::set_expected_type(opts, "at+jwt");
        let err = wing::verify_jwt_hmac(token[..], secret, opts, now_sec, out_h, out_c);
        sub.assert_eq(err, wing::JwtError.None, "Expected typ 'at+jwt' matches token typ");
        sub.assert_bytes_eq(out_h.typ[..], "at+jwt", "Parsed typ matches");
    };

    t.run("Explicit JWT typ verification succeeds with application/ prefix equivalence (RFC 8725 §3.11)") { sub =>
        let hdr_json = "{\"alg\":\"HS256\",\"typ\":\"application/at+jwt\"}";
        let clm_json = "{\"sub\":\"alice\",\"exp\":2000000000}";
        var token: u8[..1024] = [];
        craft_raw_jwt(hdr_json, clm_json, secret, token);

        var out_h = wing::new_jwt_header();
        var out_c = wing::JwtClaims { .. };
        var opts = wing::default_jwt_validation_options(wing::JwtAlg.HS256);
        wing::set_expected_type(opts, "at+jwt"); // expected without prefix, header has prefix
        let err = wing::verify_jwt_hmac(token[..], secret, opts, now_sec, out_h, out_c);
        sub.assert_eq(err, wing::JwtError.None, "'application/at+jwt' equivalent to 'at+jwt'");

        // Inverse: expected with prefix, header without prefix
        var opts2 = wing::default_jwt_validation_options(wing::JwtAlg.HS256);
        wing::set_expected_type(opts2, "application/at+jwt");
        let hdr_json2 = "{\"alg\":\"HS256\",\"typ\":\"at+jwt\"}";
        var token2: u8[..1024] = [];
        craft_raw_jwt(hdr_json2, clm_json, secret, token2);
        let err2 = wing::verify_jwt_hmac(token2[..], secret, opts2, now_sec, out_h, out_c);
        sub.assert_eq(err2, wing::JwtError.None, "'at+jwt' equivalent to 'application/at+jwt'");
    };

    t.run("Token type confusion attack rejected (RFC 8725 §3.11)") { sub =>
        // ID token presented to an endpoint expecting an access token (at+jwt)
        let hdr_json = "{\"alg\":\"HS256\",\"typ\":\"id+jwt\"}";
        let clm_json = "{\"sub\":\"alice\",\"exp\":2000000000}";
        var token: u8[..1024] = [];
        craft_raw_jwt(hdr_json, clm_json, secret, token);

        var out_h = wing::new_jwt_header();
        var out_c = wing::JwtClaims { .. };
        var opts = wing::default_jwt_validation_options(wing::JwtAlg.HS256);
        wing::set_expected_type(opts, "at+jwt"); // expecting access token
        let err = wing::verify_jwt_hmac(token[..], secret, opts, now_sec, out_h, out_c);
        sub.assert_eq(err, wing::JwtError.TypeMismatch, "Type confusion between id+jwt and at+jwt rejected");
    };

    t.run("Case-insensitive typ verification (RFC 8725 §3.11)") { sub =>
        let hdr_json = "{\"alg\":\"HS256\",\"typ\":\"AT+JWT\"}";
        let clm_json = "{\"sub\":\"alice\",\"exp\":2000000000}";
        var token: u8[..1024] = [];
        craft_raw_jwt(hdr_json, clm_json, secret, token);

        var out_h = wing::new_jwt_header();
        var out_c = wing::JwtClaims { .. };
        var opts = wing::default_jwt_validation_options(wing::JwtAlg.HS256);
        wing::set_expected_type(opts, "at+jwt");
        let err = wing::verify_jwt_hmac(token[..], secret, opts, now_sec, out_h, out_c);
        sub.assert_eq(err, wing::JwtError.None, "Case-insensitive typ comparison succeeds");
    };

    t.run("Multi-audience array claims parsing & verification (RFC 7519 §4.1.3)") { sub =>
        let hdr_json = "{\"alg\":\"HS256\",\"typ\":\"JWT\"}";
        let clm_json = "{\"sub\":\"alice\",\"aud\":[\"https://api.one.com\",\"https://api.two.com\"],\"exp\":2000000000}";
        var token: u8[..1024] = [];
        craft_raw_jwt(hdr_json, clm_json, secret, token);

        var out_h = wing::new_jwt_header();
        var out_c = wing::JwtClaims { .. };
        var opts = wing::default_jwt_validation_options(wing::JwtAlg.HS256);
        opts.expected_audience.append("https://api.two.com");
        let err = wing::verify_jwt_hmac(token[..], secret, opts, now_sec, out_h, out_c);
        sub.assert_eq(err, wing::JwtError.None, "Multi-audience array matches second audience");

        // Fails when requesting unlisted audience
        var opts_bad = wing::default_jwt_validation_options(wing::JwtAlg.HS256);
        opts_bad.expected_audience.append("https://api.three.com");
        let err_bad = wing::verify_jwt_hmac(token[..], secret, opts_bad, now_sec, out_h, out_c);
        sub.assert_eq(err_bad, wing::JwtError.AudienceMismatch, "Unlisted audience fails validation");
    };

    t.run("JWKS oct key without alg rejects alg:none attack") { sub =>
        var jwks = wing::Jwks { .. };
        let key_json = "{\"keys\":[{\"kty\":\"oct\",\"k\":\"c3VwZXJfc2VjcmV0X2tleV8zMl9ieXRlcyEh\",\"kid\":\"k-sym-01\"}]}";
        let ok_parse = wing::parse_jwks_json(key_json, jwks);
        sub.assert_true(ok_parse, "JWKS parsed");

        let hdr_none = "eyJhbGciOiJub25lIiwia2lkIjoiay1zeW0tMDEiLCJ0eXAiOiJKV1QifQ";
        let clm_none = "eyJzdWIiOiJhbGljZSIsImV4cCI6MjAwMDAwMDAwMH0";
        var token_none: u8[..256] = [];
        token_none.append(hdr_none);
        token_none.push('.' as u8);
        token_none.append(clm_none);
        token_none.push('.' as u8);

        var out_h = wing::new_jwt_header();
        var out_c = wing::JwtClaims { .. };
        var opts = wing::default_jwt_validation_options(wing::JwtAlg.None);
        opts.allow_none_alg = false;
        let err = wing::verify(token_none[..], jwks, opts, now_sec, out_h, out_c);
        sub.assert_true(err == wing::JwtError.UnsupportedAlgorithm || err == wing::JwtError.KeyNotFound, "alg:none against JWKS oct key rejected");
    };

    t.run("Hardened RFC 7515/7519 edge cases and defenses") { sub =>
        // 1. audiences.clear() contract on repeated parsing
        let clm_json_auds = "{\"sub\":\"alice\",\"aud\":[\"aud-1\",\"aud-2\",\"aud-3\"],\"exp\":2000000000}";
        var clm_repeated = wing::JwtClaims { .. };
        sub.assert_true(wing::parse_jwt_claims_json(clm_json_auds, clm_repeated), "Claims parsed first time");
        sub.assert_eq(clm_repeated.audiences.len, 3, "Exactly 3 audiences first time");
        sub.assert_true(wing::parse_jwt_claims_json(clm_json_auds, clm_repeated), "Claims parsed second time (reused struct)");
        sub.assert_eq(clm_repeated.audiences.len, 3, "audiences cleared on re-parsing (not 6!)");

        // 2. parse_aud_claim: empty array [] rejected per RFC 7519 §4.1.3
        var clm_empty_aud = wing::JwtClaims { .. };
        sub.assert_false(wing::parse_jwt_claims_json("{\"aud\":[]}", clm_empty_aud), "Empty aud array rejected");

        // 2b. parse_aud_claim: non-string element in aud array rejected
        var clm_num_aud = wing::JwtClaims { .. };
        sub.assert_false(wing::parse_jwt_claims_json("{\"aud\":[123]}", clm_num_aud), "Non-string aud element rejected");

        // 3. parse_jwt_alg: unknown alg parses as Unknown and rejects even with allow_none_alg = true
        let alg_rs = wing::parse_jwt_alg("RS256");
        sub.assert_eq(alg_rs, wing::JwtAlg.Unknown, "RS256 parses as Unknown");
        var opts_allow_none = wing::default_jwt_validation_options(wing::JwtAlg.None);
        opts_allow_none.allow_none_alg = true;
        let err_unknown = wing::verify_jwt_algorithm(alg_rs, wing::JwtAlg.None, opts_allow_none.allow_none_alg);
        sub.assert_eq(err_unknown, wing::JwtError.UnsupportedAlgorithm, "Unknown alg cannot bypass as none");

        // 4. claim_str ignores numeric/boolean claims, and set_claim_int clears val_str
        var clm_types = wing::JwtClaims { .. };
        wing::set_claim(clm_types, "tier", "gold");
        sub.assert_bytes_eq(wing::claim_str(clm_types, "tier"), "gold", "tier is string 'gold'");
        wing::set_claim_int(clm_types, "tier", 42);
        sub.assert_bytes_eq(wing::claim_str(clm_types, "tier"), "", "claim_str returns empty for numeric claim");
        let tier_val, ok_tier = wing::claim_int(clm_types, "tier");
        sub.assert_true(ok_tier, "tier is present as int");
        sub.assert_eq(tier_val, 42, "tier value is 42");

        // 5. Duplicate custom claim detection when initial value is skipped (array/object)
        var clm_dup = wing::JwtClaims { .. };
        let clm_dup_json = "{\"sub\":\"alice\",\"roles\":[\"admin\"],\"roles\":\"admin\"}";
        sub.assert_false(wing::parse_jwt_claims_json(clm_dup_json, clm_dup), "Duplicate custom claim key with mixed types rejected");

        // 6. Duplicate crit parameter rejected per RFC 7515 §4.1.11
        var hdr_crit_dup = wing::new_jwt_header();
        let hdr_crit_dup_json = "{\"alg\":\"HS256\",\"crit\":[\"custom\",\"custom\"],\"custom\":\"value\"}";
        sub.assert_false(wing::parse_jwt_header_json(hdr_crit_dup_json, hdr_crit_dup), "Duplicate parameter inside crit list rejected");

        // 7. NumericDate: non-integer float timestamp support (RFC 7519 §2)
        var clm_float = wing::JwtClaims { .. };
        let clm_float_json = "{\"sub\":\"alice\",\"iat\":1770000000.456,\"exp\":1770003600.789}";
        sub.assert_true(wing::parse_jwt_claims_json(clm_float_json, clm_float), "Float NumericDate claims parsed successfully");
        sub.assert_eq(clm_float.iat, 1770000000, "iat parsed and truncated to whole seconds");
        sub.assert_eq(clm_float.exp, 1770003600, "exp parsed and truncated to whole seconds");

        // 8. SSRF Protection on Remote JWKS URLs (RFC 8725 §3.12)
        sub.assert_true(
            wing::is_safe_remote_jwks_url("https://auth.example.com/.well-known/jwks.json"),
            "Valid public HTTPS JWKS URL accepted",
        );
        sub.assert_false(
            wing::is_safe_remote_jwks_url("http://auth.example.com/jwks.json"),
            "Insecure HTTP scheme rejected",
        );
        sub.assert_false(
            wing::is_safe_remote_jwks_url("https://127.0.0.1/jwks.json"),
            "Loopback 127.0.0.1 rejected",
        );
        sub.assert_false(
            wing::is_safe_remote_jwks_url("https://localhost/jwks.json"),
            "Localhost rejected",
        );
        sub.assert_false(
            wing::is_safe_remote_jwks_url("https://169.254.169.254/latest/meta-data/"),
            "Cloud metadata IP 169.254.169.254 rejected",
        );
        sub.assert_false(
            wing::is_safe_remote_jwks_url("https://metadata.google.internal/computeMetadata/v1/"),
            "Cloud metadata hostname rejected",
        );
        sub.assert_false(
            wing::is_safe_remote_jwks_url("https://10.0.0.1/jwks.json"),
            "RFC 1918 10.0.0.0/8 rejected",
        );
        sub.assert_false(
            wing::is_safe_remote_jwks_url("https://192.168.1.1/jwks.json"),
            "RFC 1918 192.168.0.0/16 rejected",
        );
        sub.assert_false(
            wing::is_safe_remote_jwks_url("https://user:pass@example.com/jwks.json"),
            "Embedded credentials in URL rejected",
        );
        sub.assert_false(
            wing::is_safe_remote_jwks_url("https://example.com:8080/jwks.json"),
            "Non-standard port 8080 rejected",
        );

        // 9. Oversized token DoS bounds
        var huge_token: u8[>..] = [];
        for i in 8200 { huge_token.push('a' as u8); }
        var dot1: i64 = 0;
        var dot2: i64 = 0;
        sub.assert_false(
            wing::split_jwt_parts(huge_token[..], dot1, dot2),
            "Token exceeding MAX_JWT_TOKEN_LEN (8192) rejected immediately",
        );

        // 10. Zeroization of secret keys in JWKS
        var test_jwks = wing::Jwks { .. };
        let sym_sec = "test_zeroize_secret_32bytes_long";
        wing::add_symmetric_key(test_jwks, "zero-key", wing::JwtAlg.HS256, sym_sec);
        sub.assert_eq(test_jwks.keys.len, 1, "Key added to JWKS");
        sub.assert_true(test_jwks.keys[0].valid, "Key is initially valid");
        sub.assert_eq(test_jwks.keys[0].symmetric_key.len, 32, "Symmetric key has 32 bytes");

        wing::zeroize_jwks(test_jwks);
        sub.assert_eq(test_jwks.keys.len, 0, "Keys cleared from JWKS after zeroize");
    };
}

// ----------------------------------------------------------------------------
// Suite Runner
// ----------------------------------------------------------------------------
fn main() {
    var runner = core::new_runner("RFC 7519 / RFC 7515 / RFC 7517 JWT & JWKS Suite", core::Verbosity.Verbose);

    core::run_case(runner, "1. Symmetric HMAC JWS (HS256, HS384, HS512)", test_symmetric_hmac_jwt);
    core::run_case(runner, "2. Asymmetric Ed25519 JWS (EdDSA / RFC 8037)", test_asymmetric_eddsa_jwt);
    core::run_case(runner, "3. RFC 8725 BCP Security Defenses", test_jwt_security_defenses);
    core::run_case(runner, "4. RFC 7517 JWKS Serialization, Parsing & Key Rotation", test_jwks_serialization_and_parsing);
    core::run_case(runner, "5. Integrated JWT Verification against JWKS Key Set", test_jwt_verification_against_jwks);
    core::run_case(runner, "6. RFC 7519 Claims Parsing, RFC 8725 Defenses & RFC 7638 JWK Thumbprints", test_jwt_rfc7519_claims_and_thumbprint);
    core::run_case(runner, "7. RFC 7515 Crit Headers & RFC 8725 Explicit Typ Verification", test_jwt_crit_and_typ_validation);

    let ok = core::finish(runner);
    assert(ok);
}
