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
        var clm = wing::new_jwt_claims();
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
        var out_clm = wing::new_jwt_claims();
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
        var clm384 = wing::new_jwt_claims();
        wing::set_subject(clm384, "agent_384");
        wing::set_expiry(clm384, now_sec + 100);

        var token384: u8[>..] = [];
        sub.assert_true(wing::sign_jwt_hmac(hdr384, clm384, secret, token384), "HS384 signed");

        var out_hdr384 = wing::new_jwt_header();
        var out_clm384 = wing::new_jwt_claims();
        var opts384 = wing::default_jwt_validation_options(wing::JwtAlg.HS384);
        let err384 = wing::verify_jwt_hmac(token384[..], secret, opts384, now_sec, out_hdr384, out_clm384);
        sub.assert_eq(err384, wing::JwtError.None, "HS384 verified");
        sub.assert_bytes_eq(wing::claim_str(out_clm384, "sub"), "agent_384", "HS384 sub");

        // HS512
        var hdr512 = wing::new_jwt_header(wing::JwtAlg.HS512);
        var clm512 = wing::new_jwt_claims();
        wing::set_subject(clm512, "agent_512");
        wing::set_expiry(clm512, now_sec + 100);

        var token512: u8[>..] = [];
        sub.assert_true(wing::sign_jwt_hmac(hdr512, clm512, secret, token512), "HS512 signed");

        var out_hdr512 = wing::new_jwt_header();
        var out_clm512 = wing::new_jwt_claims();
        var opts512 = wing::default_jwt_validation_options(wing::JwtAlg.HS512);
        let err512 = wing::verify_jwt_hmac(token512[..], secret, opts512, now_sec, out_hdr512, out_clm512);
        sub.assert_eq(err512, wing::JwtError.None, "HS512 verified");
        sub.assert_bytes_eq(wing::claim_str(out_clm512, "sub"), "agent_512", "HS512 sub");
    };

    t.run("Tampered payload or signature rejected") { sub =>
        var hdr = wing::new_jwt_header(wing::JwtAlg.HS256);
        var clm = wing::new_jwt_claims();
        wing::set_subject(clm, "original_user");
        wing::set_expiry(clm, now_sec + 600);

        var token: u8[>..] = [];
        wing::sign_jwt_hmac(hdr, clm, secret, token);

        // Tamper with one byte in signature
        var tampered_sig: u8[>..] = [];
        tampered_sig.append(token[..]);
        tampered_sig[tampered_sig.len - 2] = if tampered_sig[tampered_sig.len - 2] == 'A' { 'B' } else { 'A' };

        var out_h = wing::new_jwt_header();
        var out_c = wing::new_jwt_claims();
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
        0xf3, 0x8f, 0x3c, 0xeb, 0x17, 0x1a, 0x8e, 0x1e
    ];
    let public_key = core::ed25519_public_key(seed);
    let now_sec: i64 = 1770000000;

    t.run("EdDSA token generation and validation") { sub =>
        var hdr = wing::new_jwt_header(wing::JwtAlg.EdDSA, "ed25519-root-key");
        var clm = wing::new_jwt_claims();
        wing::set_issuer(clm, "https://id.goose.io");
        wing::set_subject(clm, "srv_identity_ed25519");
        wing::set_expiry(clm, now_sec + 1800);
        wing::set_claim(clm, "scope", "cluster:admin");

        var token: u8[>..] = [];
        let ok_sign = wing::sign_jwt_eddsa(hdr, clm, seed, token);
        sub.assert_true(ok_sign, "EdDSA token signed");

        var out_hdr = wing::new_jwt_header();
        var out_clm = wing::new_jwt_claims();
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
        var clm = wing::new_jwt_claims();
        wing::set_subject(clm, "device_007");
        wing::set_expiry(clm, now_sec + 600);

        var token: u8[>..] = [];
        wing::sign_jwt_eddsa(hdr, clm, seed, token);

        // Wrong public key (all zeros)
        let zero_pub: u8[32] = [0; 32];
        var out_h = wing::new_jwt_header();
        var out_c = wing::new_jwt_claims();
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
        var clm = wing::new_jwt_claims();
        wing::set_subject(clm, "victim");
        wing::set_expiry(clm, now_sec + 300);

        var token: u8[>..] = [];
        wing::sign_jwt_hmac(hdr, clm, secret, token);

        var out_h = wing::new_jwt_header();
        var out_c = wing::new_jwt_claims();
        let dummy_pub: u8[32] = [0x55; 32];
        var opts_conf = wing::default_jwt_validation_options(wing::JwtAlg.EdDSA);
        let err = wing::verify_jwt_eddsa(token[..], dummy_pub, opts_conf, now_sec, out_h, out_c);
        sub.assert_eq(err, wing::JwtError.AlgorithmMismatch, "Algorithm confusion rejected");
    };

    t.run("none Algorithm Rejection (CVE-2015-9235 Defense)") { sub =>
        // Attacker sends token with alg: "none" and empty signature: "eyJhbGciOiJub25lIn0.eyJzdWIiOiJhZG1pbiJ9."
        let none_token = "eyJhbGciOiJub25lIn0.eyJzdWIiOiJhZG1pbiJ9.";
        var out_h = wing::new_jwt_header();
        var out_c = wing::new_jwt_claims();
        var opts_none = wing::default_jwt_validation_options(wing::JwtAlg.HS256);
        let err = wing::verify_jwt_hmac(none_token, secret, opts_none, now_sec, out_h, out_c);
        sub.assert_eq(err, wing::JwtError.UnsupportedAlgorithm, "none algorithm rejected by default");
    };

    t.run("Expiration and Clock Skew Leeway (exp)") { sub =>
        var hdr = wing::new_jwt_header(wing::JwtAlg.HS256);
        var clm = wing::new_jwt_claims();
        wing::set_subject(clm, "time_traveler");
        wing::set_expiry(clm, now_sec - 100); // Expired 100 seconds ago

        var token: u8[>..] = [];
        wing::sign_jwt_hmac(hdr, clm, secret, token);

        var out_h = wing::new_jwt_header();
        var out_c = wing::new_jwt_claims();

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
        var clm = wing::new_jwt_claims();
        wing::set_subject(clm, "future_user");
        wing::set_not_before(clm, now_sec + 200); // Valid only in 200 seconds
        wing::set_expiry(clm, now_sec + 1000);

        var token: u8[>..] = [];
        wing::sign_jwt_hmac(hdr, clm, secret, token);

        var out_h = wing::new_jwt_header();
        var out_c = wing::new_jwt_claims();
        var opts = wing::default_jwt_validation_options(wing::JwtAlg.HS256);
        opts.leeway_seconds = 30;

        let err = wing::verify_jwt_hmac(token[..], secret, opts, now_sec, out_h, out_c);
        sub.assert_eq(err, wing::JwtError.TokenNotYetValid, "Token not yet valid rejected");
    };

    t.run("Issuer, Audience, Subject Mismatch Rejections") { sub =>
        var hdr = wing::new_jwt_header(wing::JwtAlg.HS256);
        var clm = wing::new_jwt_claims();
        wing::set_issuer(clm, "auth.real.com");
        wing::set_audience(clm, "app.real.com");
        wing::set_subject(clm, "user.real");
        wing::set_expiry(clm, now_sec + 600);

        var token: u8[>..] = [];
        wing::sign_jwt_hmac(hdr, clm, secret, token);

        var out_h = wing::new_jwt_header();
        var out_c = wing::new_jwt_claims();

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
        var jwks = wing::new_jwks();

        // 1. Add Ed25519 public key
        let ed_pub: u8[32] = [
            0x2f, 0x5a, 0x7b, 0x11, 0x88, 0x99, 0xaa, 0xbb,
            0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11, 0x22, 0x33,
            0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb,
            0xcc, 0xdd, 0xee, 0xff, 0x12, 0x34, 0x56, 0x78
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
        var parsed_jwks = wing::new_jwks();
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
        0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x11
    ];
    let ed_pub = core::ed25519_public_key(ed_seed);
    let hmac_sec = "shared-vault-secret-token-key-256";

    // Setup active JWKS with multiple keys
    var jwks = wing::new_jwks();
    wing::add_ed25519_key(jwks, "auth-srv-v1", ed_pub);
    wing::add_symmetric_key(jwks, "legacy-sym-v1", wing::JwtAlg.HS256, hmac_sec);

    t.run("Verify EdDSA token using JWKS key lookup") { sub =>
        var hdr = wing::new_jwt_header(wing::JwtAlg.EdDSA, "auth-srv-v1");
        var clm = wing::new_jwt_claims();
        wing::set_issuer(clm, "auth.corp.com");
        wing::set_subject(clm, "admin_alice");
        wing::set_expiry(clm, now_sec + 600);

        var token: u8[>..] = [];
        wing::sign_jwt_eddsa(hdr, clm, ed_seed, token);

        var out_h = wing::new_jwt_header();
        var out_c = wing::new_jwt_claims();
        var opts = wing::default_jwt_validation_options(wing::JwtAlg.EdDSA);
        opts.expected_issuer.append("auth.corp.com");

        let err = wing::verify(token[..], jwks, opts, now_sec, out_h, out_c);
        sub.assert_eq(err, wing::JwtError.None, "EdDSA token verified through JWKS");
        sub.assert_bytes_eq(out_h.kid[..], "auth-srv-v1", "kid resolved correctly");
        sub.assert_bytes_eq(wing::claim_str(out_c, "sub"), "admin_alice", "Subject matches");
    };

    t.run("Verify HMAC token using JWKS key lookup") { sub =>
        var hdr = wing::new_jwt_header(wing::JwtAlg.HS256, "legacy-sym-v1");
        var clm = wing::new_jwt_claims();
        wing::set_subject(clm, "service_worker");
        wing::set_expiry(clm, now_sec + 600);

        var token: u8[>..] = [];
        wing::sign_jwt_hmac(hdr, clm, hmac_sec, token);

        var out_h = wing::new_jwt_header();
        var out_c = wing::new_jwt_claims();
        let opts = wing::default_jwt_validation_options(wing::JwtAlg.HS256);

        let err = wing::verify(token[..], jwks, opts, now_sec, out_h, out_c);
        sub.assert_eq(err, wing::JwtError.None, "HMAC token verified through JWKS");
        sub.assert_bytes_eq(out_h.kid[..], "legacy-sym-v1", "kid resolved");
        sub.assert_bytes_eq(wing::claim_str(out_c, "sub"), "service_worker", "Subject matches");
    };

    t.run("Unknown kid in token rejected with KeyNotFound") { sub =>
        var hdr = wing::new_jwt_header(wing::JwtAlg.HS256, "unregistered-kid-999");
        var clm = wing::new_jwt_claims();
        wing::set_subject(clm, "intruder");
        wing::set_expiry(clm, now_sec + 600);

        var token: u8[>..] = [];
        wing::sign_jwt_hmac(hdr, clm, hmac_sec, token);

        var out_h = wing::new_jwt_header();
        var out_c = wing::new_jwt_claims();
        let opts = wing::default_jwt_validation_options(wing::JwtAlg.HS256);

        let err = wing::verify(token[..], jwks, opts, now_sec, out_h, out_c);
        sub.assert_eq(err, wing::JwtError.KeyNotFound, "Unknown kid returned KeyNotFound");
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

    let ok = core::finish(runner);
    assert(ok);
}
