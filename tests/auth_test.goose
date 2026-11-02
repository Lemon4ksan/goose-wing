// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Consolidated Verification Suite: Authentication, Cryptographic Tokens, and Invariants Suite
//
// RUN: goose build -o %t.exe %s
// RUN: %t.exe
import std;
import core from "..";
import wing from "..";
import lit from "github.com/Lemon4ksan/goose-lit@v0.1.0";

// --- Component: auth ---
// Verification suite for RFC 7616 Digest Access Authentication, RFC 7617 Basic Authentication,
// and 401 Authenticator Replay Loop.

fn test_rfc7616_official_ietf_vector(t: lit::T&) {
    t.run("RFC 7616 Section 3.9.1 Official SHA-256 Test Vector") { sub =>
        let raw_challenge = "Digest realm=\"http-auth@example.org\", qop=\"auth, auth-int\", algorithm=SHA-256, nonce=\"7ypf/xlj9XXwfDPEoM4URrv/xwf94BcCAzFZH4GiTo0v\", opaque=\"FQhe/qaU925kual Rocco\"";
        let chal, ok_c = wing::parse_digest_challenge(raw_challenge);
        sub.assert_true(ok_c, "parsed RFC 7616 challenge");
        sub.assert_bytes_eq(chal.realm[..], "http-auth@example.org", "realm matched");
        sub.assert_bytes_eq(chal.nonce[..], "7ypf/xlj9XXwfDPEoM4URrv/xwf94BcCAzFZH4GiTo0v", "nonce matched");
        sub.assert_bytes_eq(chal.algorithm[..], "SHA-256", "algorithm is SHA-256");

        var creds = wing::DigestCredentials { .. };
        creds.username.append("Mufasa");
        creds.password.append("Circle of Life");

        let cnonce = "f2/wE4q74E6zIJEtWaHKaf5wv/H5QzzpXusqGemxURZJ";
        let nc: u32 = 1;
        let method = "GET";
        let uri = "/dir/index.html";

        var auth_header: u8[..512] = [];
        let ok_d = wing::compute_digest_response(chal, creds, method, uri, nc, cnonce, "", auth_header);
        sub.assert_true(ok_d, "digest response computed");

        // The expected response hash from RFC 7616 Section 3.9.1:
        let expected_hash = "753927fa0e85d155564e2e272a28d1802ca10daf4496794697cf8db5856cb6c1";
        var found_hash = false;
        if auth_header.len >= expected_hash.len {
            for i in auth_header.len - expected_hash.len + 1 {
                if auth_header[i..i + expected_hash.len] == expected_hash {
                    found_hash = true;
                    break;
                }
            }
        }
        sub.assert_true(found_hash, "Calculated response hash matches official RFC 7616 Section 3.9.1 test vector!");
    };

    t.run("Official RFC 7616 Section 3.9.1 MD5 Vector") { sub =>
        let raw_chal = "Digest realm=\"http-auth@example.org\", nonce=\"7ypf/xlj9XXwfDPEoM4URrv/xwf94BcCAzFZH4GiTo0v\", algorithm=MD5, qop=\"auth\"";
        let chal, ok_c = wing::parse_digest_challenge(raw_chal);
        sub.assert_true(ok_c, "parsed MD5 challenge");
        sub.assert_bytes_eq(chal.algorithm[..], "MD5", "algorithm is MD5");

        var creds = wing::DigestCredentials { .. };
        creds.username.append("Mufasa");
        creds.password.append("Circle of Life");

        let cnonce = "f2/wE4q74E6zIJEtWaHKaf5wv/H5QzzpXusqGemxURZJ";
        var auth_header: u8[..512] = [];
        let ok_d = wing::compute_digest_response(chal, creds, "GET", "/dir/index.html", 1, cnonce, "", auth_header);
        sub.assert_true(ok_d, "MD5 digest computed");

        let expected_md5 = "8ca523f5e9506fed4657c9700eebdbec";
        var found_md5 = false;
        if auth_header.len >= expected_md5.len {
            for i in auth_header.len - expected_md5.len + 1 {
                if auth_header[i..i + expected_md5.len] == expected_md5 {
                    found_md5 = true;
                    break;
                }
            }
        }
        sub.assert_true(found_md5, "MD5 response matches official RFC 7616 Section 3.9.1 MD5 vector (8ca523f5e9...)");
    };
}

fn test_401_authenticator_loop(t: lit::T&) {
    t.run("Client Automatically Resolves 401 Challenge with RFC 7616 Digest") { sub =>
        var client = wing::new_client();
        wing::set_credentials(client, "Mufasa", "Circle of Life");

        // First attempt (no Authorization header sent yet) returns 401 with Digest challenge
        wing::mock_route(client, "GET", "https://api.corp.com/protected/doc", 401, "{\"error\":\"unauthorized\"}");
        wing::add_mock_header(client, "WWW-Authenticate", "Digest realm=\"http-auth@example.org\", qop=\"auth\", algorithm=SHA-256, nonce=\"7ypf/xlj9xxbKfUIDFtdaQ==\"");

        // Route with Authorization header returns 200 OK
        // In our mock engine, when client adds Authorization header, it executes hop
        let resp, err = wing::get(client, "https://api.corp.com/protected/doc");
        sub.assert_true(wing::ok(err), "request completed");

        // Verify sent Authorization header on replay
        let sent_auth = wing::sent_header(resp, "Authorization");
        sub.assert_true(sent_auth.len > 0, "Client generated and sent Authorization header");
        sub.assert_bytes_eq(sent_auth[..7], "Digest ", "Scheme is Digest");

        var has_mufasa = false;
        if sent_auth.len >= 6 {
            for i in sent_auth.len - 5 {
                if sent_auth[i..i + 6] == "Mufasa" { has_mufasa = true; break; }
            }
        }
        sub.assert_true(has_mufasa, "Sent header contains username Mufasa");
    };

    t.run("Client Automatically Resolves 401 Challenge with RFC 7617 Basic Auth") { sub =>
        var client = wing::new_client();
        wing::set_credentials(client, "admin", "secret123");

        wing::mock_route(client, "GET", "https://api.corp.com/admin", 401, "unauthorized");
        wing::add_mock_header(client, "WWW-Authenticate", "Basic realm=\"admin-area\"");

        let resp, err = wing::get(client, "https://api.corp.com/admin");
        sub.assert_true(wing::ok(err), "request completed");

        let sent_auth = wing::sent_header(resp, "Authorization");
        sub.assert_true(sent_auth.len > 0, "Basic Authorization header sent");
        // "admin:secret123" in base64 is "YWRtaW46c2VjcmV0MTIz"
        sub.assert_bytes_eq(sent_auth, "Basic YWRtaW46c2VjcmV0MTIz", "Correct Base64 Basic auth sent");
    };

    t.run("Loop Prevention: Persistent 401 Returns to Caller Without Infinite Loop") { sub =>
        var client = wing::new_client();
        wing::set_credentials(client, "wrong_user", "wrong_pass");

        wing::mock_route(client, "GET", "https://api.corp.com/secure", 401, "invalid credentials");
        wing::add_mock_header(client, "WWW-Authenticate", "Basic realm=\"test\"");

        // If credentials fail, client retries once with Auth header, server still returns 401, and client stops cleanly!
        let resp, err = wing::get(client, "https://api.corp.com/secure");
        sub.assert_true(wing::ok(err), "no hang or crash");
        sub.assert_eq(wing::status(resp), 401, "401 status returned to caller");
    };
}

fn test_rfc7616_userhash_options(t: lit::T&) {
    t.run("RFC 7616 Section 3.4.4 userhash=true") { sub =>
        let raw_chal = "Digest realm=\"secure@example.com\", nonce=\"dcd98b7102dd2f0e8b11d0f600bfb0c093\", qop=\"auth\", userhash=true";
        let chal, ok_chal = wing::parse_digest_challenge(raw_chal);
        sub.assert_true(ok_chal, "Challenge with userhash parsed");
        sub.assert_true(chal.userhash, "Challenge userhash flag set");

        var creds = wing::DigestCredentials { .. };
        creds.username.append("alice");
        creds.password.append("Secret123");

        var out_hdr: u8[..512] = [];
        let ok_resp = wing::compute_digest_response(chal, creds, "GET", "/api/data", 1, "0a4f113b", "", out_hdr);
        sub.assert_true(ok_resp, "Digest response computed with userhash");
        sub.assert_true(core::contains(out_hdr[..], "userhash=true"), "Authorization contains userhash=true");

        // Verify username is hex hash, not plain "alice"
        sub.assert_false(core::contains(out_hdr[..], "username=\"alice\""), "Plain username is hidden by userhash");
    };

    t.run("Official RFC 7616 Section 3.9.2 SHA-512-256 Vector") { sub =>
        let raw_chal = "Digest realm=\"api@example.org\", qop=\"auth, auth-int\", algorithm=SHA-512-256, nonce=\"5TsQWLVdgBdmrQ0XsxbDODV+57QdFR34I9HAbC/RVvkK\", opaque=\"HRPCssKJSGjCrkzDg8OhwpzCiGPChXYjwrI2QmXDnsOS\", charset=UTF-8, userhash=true";
        let chal, ok_chal = wing::parse_digest_challenge(raw_chal);
        sub.assert_true(ok_chal, "Parsed SHA-512-256 challenge");
        sub.assert_bytes_eq(chal.algorithm[..], "SHA-512-256", "Algorithm is SHA-512-256");

        var creds = wing::DigestCredentials { .. };
        creds.username.append("J\xc3\xa4s\xc3\xb8n Doe");
        creds.password.append("Secret, or not?");

        let cnonce = "NTg6RKcb9boFIAS3KrFK9BGeh+iDa/sm6jUMp2wds69v";
        let method = "GET";
        let uri = "/doe.json";

        var out_hdr: u8[..1024] = [];
        let ok_resp = wing::compute_digest_response(chal, creds, method, uri, 1, cnonce, "", out_hdr);
        sub.assert_true(ok_resp, "Digest response computed for SHA-512-256");

        let expected_userhash = "793263caabb707a56211940d90411ea4a575adeccb7e360aeb624ed06ece9b0b";
        let expected_response = "3798d4131c277846293534c3edc11bd8a5e4cdcbff78b05db9d95eeb1cec68a5";

        sub.assert_true(core::contains(out_hdr[..], expected_userhash), "Hashed username matches official RFC 7616 Section 3.9.2 vector");
        sub.assert_true(core::contains(out_hdr[..], expected_response), "Response hash matches official RFC 7616 Section 3.9.2 vector");
    };
}

// --- Component: auth_jwt_jwks ---
// tests/jwt_jwks_test.goose
// Verification suite for Universal JWT (RFC 7519), JWS (RFC 7515), and JWKS (RFC 7517).
// 1. Symmetric HMAC JWS (HS256, HS384, HS512) Signing & Verification
// 2. Asymmetric Ed25519 JWS (EdDSA / RFC 8037) Signing & Verification
// 3. RFC 8725 BCP Security Defenses (Algorithm Confusion, none-alg, Expiry, Leeway, Identity)
// 4. RFC 7517 JWKS Serialization, Parsing, and Key Rotation
// 5. Integrated JWT Verification against JWKS Key Set

// ----------------------------------------------------------------------------
// 1. Symmetric HMAC JWS (HS256, HS384, HS512) Signing & Verification
// ----------------------------------------------------------------------------
fn test_symmetric_hmac_jwt(t: lit::T&) {
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
fn test_asymmetric_eddsa_jwt(t: lit::T&) {
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
fn test_jwt_security_defenses(t: lit::T&) {
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
fn test_jwks_serialization_and_parsing(t: lit::T&) {
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
fn test_jwt_verification_against_jwks(t: lit::T&) {
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
            kty:        wing::JwkKeyType.OKP,
            crv:        "Ed25519",
            alg:        wing::JwtAlg.EdDSA,
            use:        "enc",
            public_key: ed_pub,
            valid:      true,
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

fn test_jwt_rfc7519_claims_and_thumbprint(t: lit::T&) {
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
            kty:   wing::JwkKeyType.OKP,
            crv:   "Ed25519",
            alg:   wing::JwtAlg.EdDSA, // optional member - must be excluded from canonical JSON
            use:   "sig",           // optional member - must be excluded from canonical JSON
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
            kty:   wing::JwkKeyType.Oct,
            alg:   wing::JwtAlg.HS256,
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
fn test_jwt_crit_and_typ_validation(t: lit::T&) {
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

// --- Component: auth_dpop_pkce ---
// Verification suite for OAuth 2.0 PKCE (RFC 7636) and DPoP (RFC 9449):
// - PKCE code verifier charset and length invariants (43..128 chars)
// - PKCE S256 and plain code challenge computation and constant-time validation
// - DPoP target URI normalization (strips query/fragments, lowercases scheme/host)
// - DPoP ATH (Access Token Hash) SHA-256 base64url generation
// - DPoP Proof JWT creation (JOSE header framing, claims payload, HMAC-SHA256 signature)
// - DPoP Proof verification against expected method, URI, access token, and nonce
// - Request header attachment and response DPoP-Nonce extraction

fn test_pkce_rfc7636(t: lit::T&) {
    t.run("PKCE Verifier Generation & Invariants") { sub =>
        var verifier: u8[..128] = [];
        let ok = wing::generate_code_verifier(verifier);
        sub.assert_true(ok, "Verifier generated");
        sub.assert_ge(verifier.len, 43, "Verifier length >= 43");
        sub.assert_le(verifier.len, 128, "Verifier length <= 128");
        sub.assert_true(wing::is_valid_code_verifier(verifier[..]), "Verifier contains only unreserved chars");

        // Edge case: too short / too long verifiers
        sub.assert_false(wing::is_valid_code_verifier("short_verifier"), "Rejects length < 43");
        var huge_str: u8[..150] = [];
        for i in 140 { huge_str.push('a' as u8); }
        sub.assert_false(wing::is_valid_code_verifier(huge_str[..]), "Rejects length > 128");

        // Edge case: illegal characters (+ and / not allowed in PKCE verifiers)
        let invalid_chars = "dBjftJeZ4CVP+mB92K27uhbUJU1p1r/wW1gFWFOEjXk123";
        sub.assert_false(wing::is_valid_code_verifier(invalid_chars), "Rejects + and / in verifier");
    };

    t.run("PKCE Challenge Computation (S256 & Plain)") { sub =>
        // RFC 7636 Appendix B test vector
        let rfc_verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
        var challenge_s256: u8[..128] = [];
        let ok_s256 = wing::compute_code_challenge(rfc_verifier, "S256", challenge_s256);
        sub.assert_true(ok_s256, "S256 challenge computed");
        sub.assert_bytes_eq(challenge_s256[..], "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM", "RFC 7636 Appendix B S256 vector matches exactly");

        // Plain method (RFC 7636 §4.2)
        var challenge_plain: u8[..128] = [];
        let ok_plain = wing::compute_code_challenge(rfc_verifier, "plain", challenge_plain);
        sub.assert_true(ok_plain, "Plain challenge computed");
        sub.assert_bytes_eq(challenge_plain[..], rfc_verifier, "Plain challenge matches verifier verbatim");

        // Validate API
        sub.assert_true(wing::validate_code_challenge(rfc_verifier, challenge_s256[..], "S256"), "Validation succeeds for valid S256");
        sub.assert_false(wing::validate_code_challenge(rfc_verifier, "invalid_challenge_hash_123456789012345678901", "S256"), "Validation fails for wrong challenge");

        // RFC 7636 §4.3: code_challenge_method defaults to 'plain' when omitted
        sub.assert_true(wing::validate_code_challenge(rfc_verifier, challenge_plain[..]), "Validation defaults to plain when method omitted");
        sub.assert_true(wing::is_valid_code_challenge(challenge_plain[..]), "is_valid_code_challenge defaults to plain when method omitted");

        // RFC 7636 §4.2: S256 challenge MUST be unpadded base64url (no '=' padding)
        let padded_challenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM=";
        sub.assert_false(wing::is_valid_code_challenge(padded_challenge, "S256"), "Padded S256 challenge rejected by is_valid_code_challenge");
        sub.assert_false(wing::validate_code_challenge(rfc_verifier, padded_challenge, "S256"), "Padded S256 challenge rejected by validate_code_challenge");

        // RFC 7636 §4.3: code_challenge_method is case-sensitive
        sub.assert_false(wing::compute_code_challenge(rfc_verifier, "s256", challenge_s256), "Lowercase method s256 rejected");
        sub.assert_false(wing::validate_code_challenge(rfc_verifier, challenge_s256[..], "s256"), "Validation rejects lowercase s256 method");
        sub.assert_false(wing::validate_code_challenge(rfc_verifier, challenge_plain[..], "Plain"), "Validation rejects capitalized Plain method");

        // Invalid challenge length and charset
        sub.assert_false(wing::is_valid_code_challenge("too_short", "S256"), "Short S256 challenge rejected");
        let illegal_char_challenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw+cM"; // '+' instead of '-'
        sub.assert_false(wing::is_valid_code_challenge(illegal_char_challenge, "S256"), "Illegal char in S256 challenge rejected");

        // RFC 7636 §4.2 / RFC 4648 §3.5: 43rd character MUST have zero padding bits (bits 1..0 == 00)
        // 'M' (001100) has bits 1..0 == 00 (valid). 'B' (000001) has bits 1..0 == 01 (invalid non-zero padding bits)
        let non_canonical_challenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cB";
        sub.assert_false(wing::is_valid_code_challenge(non_canonical_challenge, "S256"), "Non-zero padding bits in 43rd char rejected");
    };

    t.run("PKCE Create Challenge Pair Helper & Security Invariants") { sub =>
        // 1. Valid pair generation with default dynamic entropy
        let pair, ok_pair = wing::create_pkce_pair("", "S256");
        sub.assert_true(ok_pair, "PKCE pair created successfully");
        sub.assert_ge(pair.verifier.len, 43, "Pair verifier length >= 43");
        sub.assert_le(pair.verifier.len, 128, "Pair verifier length <= 128");
        sub.assert_true(wing::validate_code_challenge(pair.verifier[..], pair.challenge[..], "S256"), "Pair challenge matches verifier");

        // 2. Dynamic entropy prevents static replay when entropy is omitted (invariant 16)
        var v1: u8[..128] = [];
        var v2: u8[..128] = [];
        sub.assert_true(wing::generate_code_verifier(v1), "Verifier 1 generated");
        sub.assert_true(wing::generate_code_verifier(v2), "Verifier 2 generated");
        sub.assert_false(core::ct_eq_bytes(v1[..], v2[..]), "Consecutive verifiers with omitted entropy are distinct");

        // 3. Insufficient entropy (< 32 bytes) returns false (RFC 7636 §4.1)
        var v_short: u8[..128] = [];
        sub.assert_false(wing::generate_code_verifier(v_short, "short_entropy_16b"), "Entropy < 32 bytes rejected");
        let pair_bad_ent, ok_ent = wing::create_pkce_pair("short_entropy_16b", "S256");
        sub.assert_false(ok_ent, "create_pkce_pair rejects entropy < 32 bytes");

        // 4. Large entropy (> 96 bytes) properly caps at 128 chars without buffer overflow
        var large_entropy: u8[..150] = [];
        for i in 120 { large_entropy.push((i & 0xFF) as u8); }
        var v_large: u8[..128] = [];
        sub.assert_true(wing::generate_code_verifier(v_large, large_entropy[..]), "Large entropy accepted");
        sub.assert_eq(v_large.len, 128, "Large entropy capped to exactly 128 characters");

        // 5. Invalid method returns false in create_pkce_pair
        let pair_bad_m, ok_m = wing::create_pkce_pair("", "invalid_method");
        sub.assert_false(ok_m, "create_pkce_pair rejects invalid method");
    };
}

// Helper to construct a signed EdDSA DPoP proof token with RFC 9449 compliant JWK header.
fn make_test_dpop_token<B>(
    key:           const u8[:],
    claims_json:   const u8[:],
    out:           B&,
    custom_header: const u8[:] = "",
) {
    out.clear();
    var seed: u8[32] = [0; 32];
    for i in 32 {
        if i < key.len {
            seed[i] = key[i];
        }
    }
    let pub_key = core::ed25519_public_key(seed);
    var x_b64: u8[..64] = [];
    core::base64url_encode(pub_key[..], x_b64);

    var h_b64: u8[..384] = [];
    if custom_header.len > 0 {
        core::base64url_encode(custom_header, h_b64);
    } else {
        var header_json: u8[..256] = [];
        header_json.append("{\"typ\":\"dpop+jwt\",\"alg\":\"EdDSA\",\"jwk\":{\"kty\":\"OKP\",\"crv\":\"Ed25519\",\"x\":\"");
        header_json.append(x_b64[..]);
        header_json.append("\"}}");
        core::base64url_encode(header_json[..], h_b64);
    }

    var c_b64: u8[..768] = [];
    core::base64url_encode(claims_json, c_b64);

    var signing_input: u8[..1152] = [];
    signing_input.append(h_b64[..]);
    signing_input.push('.' as u8);
    signing_input.append(c_b64[..]);

    let sig = core::ed25519_sign(seed, signing_input[..]);
    var sig_b64: u8[..128] = [];
    core::base64url_encode(sig[..], sig_b64);

    out.append(signing_input[..]);
    out.push('.' as u8);
    out.append(sig_b64[..]);
}

fn test_dpop_rfc9449(t: lit::T&) {
    t.run("DPoP URI Normalization") { sub =>
        var norm: u8[..256] = [];
        let ok1 = wing::normalize_dpop_target_uri("https://API.Example.COM/resource/items?page=1&limit=10#section", norm);
        sub.assert_true(ok1, "URI normalized");
        sub.assert_bytes_eq(norm[..], "https://api.example.com/resource/items", "Strips query and fragment, lowercases host");

        var norm2: u8[..256] = [];
        wing::normalize_dpop_target_uri("http://myhost:8080/data", norm2);
        sub.assert_bytes_eq(norm2[..], "http://myhost:8080/data", "Preserves port in authority");

        var norm3: u8[..256] = [];
        wing::normalize_dpop_target_uri("https://api.example.com:443/resource", norm3);
        sub.assert_bytes_eq(norm3[..], "https://api.example.com/resource", "Removes default HTTPS port 443 per RFC 3986 §6.2.3");

        var norm4: u8[..256] = [];
        wing::normalize_dpop_target_uri("http://api.example.com:80/resource", norm4);
        sub.assert_bytes_eq(norm4[..], "http://api.example.com/resource", "Removes default HTTP port 80 per RFC 3986 §6.2.3");
    };

    t.run("DPoP ATH Access Token Hash") { sub =>
        let token = "K50_K72qJ101BgsoCIeQ21cmP5CQ3L80mgW85GLp16U";
        var ath: u8[..64] = [];
        wing::compute_dpop_ath(token, ath);
        sub.assert_true(ath.len > 0, "ATH generated");
        // Base64url encoded SHA-256 of token
        let expected_sha = core::sha256(token);
        var expected_b64: u8[..64] = [];
        core::base64url_encode(expected_sha[..], expected_b64);
        sub.assert_bytes_eq(ath[..], expected_b64[..], "ATH matches SHA-256 base64url");
    };

    t.run("DPoP Proof JWT Generation and Verification") { sub =>
        let key = "super_secret_dpop_key_32_bytes!!";
        let method = "POST";
        let uri = "https://resource.example.org/protected/resource?query=1";
        let token = "access_token_xyz_987";
        let nonce = "server_nonce_abc123";
        let now_sec: i64 = 1714000000;
        let jti = "custom-unique-jti-001";

        var proof_jwt: u8[>..] = [];
        let ok_gen = wing::create_dpop_proof(key, method, uri, token, nonce, now_sec, jti, proof_jwt);
        sub.assert_true(ok_gen, "DPoP proof generated");
        sub.assert_true(proof_jwt.len > 50, "JWT has substantial length");

        // Verify valid proof
        let ok_ver = wing::verify_dpop_proof(
            proof_jwt[..],
            key,
            "POST",
            "https://resource.example.org/protected/resource",
            token,
            nonce,
            now_sec,
        );
        sub.assert_true(ok_ver, "DPoP proof successfully verified");

        // Verify failure on mismatched method
        let fail_method = wing::verify_dpop_proof(
            proof_jwt[..],
            key,
            "GET", // Expected GET but proof was for POST
            "https://resource.example.org/protected/resource",
            token,
            nonce,
            now_sec,
        );
        sub.assert_false(fail_method, "Verification fails on method mismatch");

        // Verify failure on wrong access token
        let fail_token = wing::verify_dpop_proof(
            proof_jwt[..],
            key,
            "POST",
            "https://resource.example.org/protected/resource",
            "different_token",
            nonce,
            now_sec,
        );
        sub.assert_false(fail_token, "Verification fails on ATH mismatch");

        // Verify failure on wrong nonce
        let fail_nonce = wing::verify_dpop_proof(
            proof_jwt[..],
            key,
            "POST",
            "https://resource.example.org/protected/resource",
            token,
            "stale_nonce",
            now_sec,
        );
        sub.assert_false(fail_nonce, "Verification fails on nonce mismatch");

        // Verify failure on tampered signature / wrong key
        let fail_key = wing::verify_dpop_proof(
            proof_jwt[..],
            "wrong_key_that_does_not_match!",
            "POST",
            "https://resource.example.org/protected/resource",
            token,
            nonce,
            now_sec,
        );
        sub.assert_false(fail_key, "Verification fails on bad signature");
    };

    t.run("DPoP Request Header Attachment & Nonce Extraction") { sub =>
        var req = wing::Request { .. };
        wing::attach_dpop(req, "eyJhbGciOi...", "token_xyz");

        sub.assert_true(req.has_header("DPoP"), "Request contains DPoP header");
        sub.assert_bytes_eq(req.header("DPoP"), "eyJhbGciOi...", "DPoP header value matches");
        sub.assert_true(req.has_header("Authorization"), "Request contains Authorization header");
        sub.assert_bytes_eq(req.header("Authorization"), "DPoP token_xyz", "Authorization header has DPoP scheme");

        // Nonce extraction from response headers
        var resp_headers: wing::HeaderItem[..4] = [];
        resp_headers.push(wing::make_header("Content-Type", "application/json"));
        resp_headers.push(wing::make_header("DPoP-Nonce", "server_nonce_retry_456"));

        var extracted_nonce: u8[..128] = [];
        let ok_nonce = wing::extract_dpop_nonce(resp_headers[..], extracted_nonce);
        sub.assert_true(ok_nonce, "DPoP-Nonce extracted");
        sub.assert_bytes_eq(extracted_nonce[..], "server_nonce_retry_456", "Extracted nonce matches header");
    };

    t.run("DPoP Proof Replay: missing iat claim must be rejected (RFC 9449 §4.2)") { sub =>
        let key = "super_secret_dpop_key_32_bytes!!";
        let c_json = "{\"jti\":\"jti-no-iat-01\",\"htm\":\"GET\",\"htu\":\"https://api.example.com/data\"}";
        var token: u8[..1024] = [];
        make_test_dpop_token(key, c_json, token);

        let ok = wing::verify_dpop_proof(token[..], key, "GET", "https://api.example.com/data", "", "", 1714000000);
        sub.assert_false(ok, "Proof without iat MUST be rejected when now_sec > 0");
    };

    t.run("DPoP Nonce Substring Injection: expected nonce in jti must not bypass missing nonce claim (RFC 9449 §4.3)") { sub =>
        let key = "super_secret_dpop_key_32_bytes!!";
        let c_json = "{\"jti\":\"expected_srv_nonce_999\",\"htm\":\"GET\",\"htu\":\"https://api.example.com/data\",\"iat\":1714000000}";
        var token: u8[..1024] = [];
        make_test_dpop_token(key, c_json, token);

        let ok = wing::verify_dpop_proof(token[..], key, "GET", "https://api.example.com/data", "", "expected_srv_nonce_999", 1714000000);
        sub.assert_false(ok, "Proof with nonce in jti instead of nonce claim MUST be rejected");
    };

    t.run("DPoP ATH Substring Injection: expected ATH in jti must not bypass missing ath claim (RFC 9449 §4.3)") { sub =>
        let key = "super_secret_dpop_key_32_bytes!!";
        let access_tok = "tok_victim_12345";
        var exp_ath: u8[..64] = [];
        wing::compute_dpop_ath(access_tok, exp_ath);

        var c_json: u8[..512] = [];
        c_json.append("{\"jti\":\"");
        c_json.append(exp_ath[..]);
        c_json.append("\",\"htm\":\"GET\",\"htu\":\"https://api.example.com/data\",\"iat\":1714000000}");

        var token: u8[..1024] = [];
        make_test_dpop_token(key, c_json[..], token);

        let ok = wing::verify_dpop_proof(token[..], key, "GET", "https://api.example.com/data", access_tok, "", 1714000000);
        sub.assert_false(ok, "Proof with ath in jti instead of ath claim MUST be rejected");
    };

    t.run("DPoP Proof JWK Thumbprint Confirmation (jkt / RFC 9449 §6.1)") { sub =>
        let key = "super_secret_dpop_key_32_bytes!!";
        let expected_jkt = "0ZcOCORZTXDEZytrEBBlSz2bTHTNVrQSnXDtfSTXvt8";

        var c_json: u8[..512] = [];
        c_json.append("{\"jti\":\"jti-jkt-01\",\"htm\":\"POST\",\"htu\":\"https://api.example.com/token\",\"iat\":1714000000,\"jkt\":\"");
        c_json.append(expected_jkt);
        c_json.append("\"}");

        var token: u8[..1024] = [];
        make_test_dpop_token(key, c_json[..], token);

        // Direct claim verification
        sub.assert_true(wing::verify_dpop_jkt(c_json[..], expected_jkt), "verify_dpop_jkt succeeds on matching thumbprint");
        sub.assert_false(wing::verify_dpop_jkt(c_json[..], "wrong_thumbprint_value_12345678901234567890"), "verify_dpop_jkt fails on wrong thumbprint");

        // Proof verification with expected_jkt
        let ok_proof = wing::verify_dpop_proof(token[..], key, "POST", "https://api.example.com/token", "", "", 1714000000, 300, 60, expected_jkt);
        sub.assert_true(ok_proof, "verify_dpop_proof succeeds when jkt matches");

        let fail_proof = wing::verify_dpop_proof(token[..], key, "POST", "https://api.example.com/token", "", "", 1714000000, 300, 60, "wrong_thumbprint_value_12345678901234567890");
        sub.assert_false(fail_proof, "verify_dpop_proof fails when jkt does not match");
    };

    t.run("DPoP Method Validation: exact uppercase String required (RFC 9449 §4.2 & §4.3)") { sub =>
        let key = "super_secret_dpop_key_32_bytes!!";

        // Direct claims json method checks
        sub.assert_false(wing::verify_dpop_method("{\"htm\":\"post\"}", "POST"), "Lowercase htm in proof rejected");
        sub.assert_false(wing::verify_dpop_method("{\"htm\":\"POST\"}", "post"), "Lowercase expected method rejected");
        sub.assert_false(wing::verify_dpop_method("{\"htm\":\"GET\"}", "POST"), "Method mismatch rejected");
        sub.assert_true(wing::verify_dpop_method("{\"htm\":\"POST\"}", "POST"), "Uppercase matching method accepted");

        // Proof with lowercase method MUST be rejected
        var token: u8[..1024] = [];
        make_test_dpop_token(key, "{\"jti\":\"jti-lc-method\",\"htm\":\"post\",\"htu\":\"https://api.example.com/data\",\"iat\":1714000000}", token);

        let fail_lc = wing::verify_dpop_proof(token[..], key, "POST", "https://api.example.com/data", "", "", 1714000000);
        sub.assert_false(fail_lc, "Proof with lowercase htm MUST be rejected");

        // Header with alg:none or fake typ must be rejected (RFC 9449 §4.2)
        var tok_bad: u8[..1024] = [];
        make_test_dpop_token(key, "{\"jti\":\"jti-fake-typ\",\"htm\":\"POST\",\"htu\":\"https://api.example.com/data\",\"iat\":1714000000}", tok_bad, "{\"typ\":\"jwt\",\"alg\":\"EdDSA\",\"p\":\"dpop+jwt\"}");
        let ok_fake_typ = wing::verify_dpop_proof(tok_bad[..], key, "POST", "https://api.example.com/data", "", "", 1714000000);
        sub.assert_false(ok_fake_typ, "Proof with fake typ must be rejected even if dpop+jwt is in extra property");
    };

    t.run("DPoP JTI dynamic entropy fallback (RFC 9449 §4.2)") { sub =>
        var jti1: u8[..64] = [];
        var jti2: u8[..64] = [];
        wing::generate_dpop_jti(jti1);
        for i in 100000 {
            // spin loop to advance nanosecond clock
        }
        wing::generate_dpop_jti(jti2);
        sub.assert_eq(jti1.len, 22, "Fallback JTI length is 22");
        sub.assert_eq(jti2.len, 22, "Fallback JTI length is 22");
        let are_equal = (jti1[..] == jti2[..]);
        sub.assert_false(are_equal, "Successive JTI generations must produce distinct values");
    };

    t.run("DPoP Nonce NQCHAR syntax & injection rejection (RFC 9449 §8)") { sub =>
        sub.assert_true(wing::is_valid_dpop_nonce("valid-server-nonce_123.456"), "Valid nonce accepted");
        sub.assert_false(wing::is_valid_dpop_nonce(""), "Empty nonce rejected");
        sub.assert_false(wing::is_valid_dpop_nonce("nonce\"with_quote"), "Quote in nonce rejected");
        sub.assert_false(wing::is_valid_dpop_nonce("nonce\\with_backslash"), "Backslash in nonce rejected");
        sub.assert_false(wing::is_valid_dpop_nonce("nonce with space"), "Space in nonce rejected");
        sub.assert_false(wing::is_valid_dpop_nonce("nonce\r\ninjection"), "CRLF in nonce rejected");
    };

    t.run("DPoP URI normalization rejects quotes and control characters") { sub =>
        var norm: u8[..256] = [];
        sub.assert_false(wing::normalize_dpop_target_uri("https://example.com/api\"evil", norm), "Quote in URI rejected");
        sub.assert_false(wing::normalize_dpop_target_uri("https://example.com/api space", norm), "Space in URI rejected");
    };

    t.run("DPoP Claims JSON Parser defends against duplicate keys & claim smuggling") { sub =>
        let key = "super_secret_dpop_key_32_bytes!!";

        // Duplicate htm claim
        let c_dup_htm = "{\"jti\":\"jti-dup\",\"htm\":\"POST\",\"htm\":\"GET\",\"htu\":\"https://api.example.com/data\",\"iat\":1714000000}";
        var tok_dup: u8[..1024] = [];
        make_test_dpop_token(key, c_dup_htm, tok_dup);

        let ok_dup = wing::verify_dpop_proof(tok_dup[..], key, "POST", "https://api.example.com/data", "", "", 1714000000);
        sub.assert_false(ok_dup, "Proof with duplicate htm claim MUST be rejected (JSON smuggling defense)");

        // Substring spoofing in custom claim value
        let c_spoof = "{\"jti\":\"jti-spoof\",\"custom\":\"hello \\\"htm\\\":\\\"GET\\\"\",\"htm\":\"POST\",\"htu\":\"https://api.example.com/data\",\"iat\":1714000000}";
        var tok_spoof: u8[..1024] = [];
        make_test_dpop_token(key, c_spoof, tok_spoof);

        let ok_spoof_get = wing::verify_dpop_proof(tok_spoof[..], key, "GET", "https://api.example.com/data", "", "", 1714000000);
        sub.assert_false(ok_spoof_get, "Fake htm inside custom string value MUST NOT fool method verification");

        let ok_spoof_post = wing::verify_dpop_proof(tok_spoof[..], key, "POST", "https://api.example.com/data", "", "", 1714000000);
        sub.assert_true(ok_spoof_post, "Real htm claim matches correctly despite custom field noise");
    };

    t.run("DPoP Attach access token into Authorization header") { sub =>
        var req = wing::Request { .. };
        var token_bytes: u8[..350] = [];
        for i in 300 {
            token_bytes.push(('a' as u8) + ((i % 26) as u8));
        }
        wing::attach_dpop(req, "proof_signature_sample", token_bytes[..]);
        sub.assert_true(req.has_header("Authorization"), "Authorization header attached with access token");
        sub.assert_ge(req.header("Authorization").len, 300, "Access token preserved without truncation");
    };

    t.run("DPoP Replay Cache & DoS Bounds (RFC 9449 §4.3 Rule 4)") { sub =>
        let key = "super_secret_dpop_key_32_bytes!!";
        let now_sec: i64 = 1714000000;
        var cache = wing::DPoPReplayCache { .. };

        var proof_valid: u8[..1024] = [];
        let ok_create = wing::create_dpop_proof(
            key,
            "POST",
            "https://api.example.com/data",
            "",
            "",
            now_sec,
            "jti_test_1",
            proof_valid,
        );
        sub.assert_true(ok_create, "DPoP proof generated");

        // First verification with replay cache succeeds and records jti
        let ok_first = wing::verify_dpop_proof_with_replay_cache(
            proof_valid[..],
            key,
            "POST",
            "https://api.example.com/data",
            now_sec,
            cache,
        );
        sub.assert_true(ok_first, "First verification succeeds and registers JTI");

        // Replay of the identical proof MUST be rejected
        let ok_replay = wing::verify_dpop_proof_with_replay_cache(
            proof_valid[..],
            key,
            "POST",
            "https://api.example.com/data",
            now_sec + 5,
            cache,
        );
        sub.assert_false(ok_replay, "Replayed DPoP proof MUST be rejected by replay cache");

        // Different JTI succeeds
        var proof_diff: u8[..1024] = [];
        wing::create_dpop_proof(key, "POST", "https://api.example.com/data", "", "", now_sec, "jti_test_2", proof_diff);
        let ok_diff = wing::verify_dpop_proof_with_replay_cache(
            proof_diff[..],
            key,
            "POST",
            "https://api.example.com/data",
            now_sec + 6,
            cache,
        );
        sub.assert_true(ok_diff, "Distinct JTI succeeds cleanly");

        // Oversized proof (> 4096 bytes) rejected immediately before decoding
        var huge_proof: u8[>..] = [];
        for i in 4100 { huge_proof.push('A' as u8); }
        sub.assert_false(
            wing::verify_dpop_proof(huge_proof[..], key, "POST", "https://api.example.com/data"),
            "Oversized DPoP proof (> 4096) rejected without decoding",
        );
    };
}

// --- Component: auth_privacypass ---
// Verification suite for RFC 9576 Privacy Pass Architecture,
// RFC 9577 PrivateToken HTTP Authentication Scheme, and RFC 9578 Blind RSA Tokens:
// - TokenChallenge binary wire serialization and deserialization (RFC 9577 §2.1.1)
// - Token binary wire serialization and deserialization (RFC 9577 §2.2.1)
// - Challenge digest SHA-256 computation (RFC 9577 §2.2.1)
// - WWW-Authenticate: PrivateToken header parsing (challenge, token-key, max-age)
// - Authorization: PrivateToken token="..." header formatting (RFC 9577 §2.2.2)
// - Sec-Private-State-Token W3C header formatting
// - PrivateTokenCache storage, expiration, and single-use redemption enforcement
// - Request header attachment and response 401 PrivateToken challenge detection
// - RFC 9577 §6.2.1 GREASE token type verification

fn test_token_challenge_roundtrip(t: lit::T&) {
    t.run("TokenChallenge with 32-byte Redemption Context") { sub =>
        var ch = wing::TokenChallenge {
            token_type: wing::TOKEN_TYPE_BLIND_RSA,
            ..
        };
        ch.issuer_name.append("issuer.example.com");
        for i in 32 { ch.redemption_context.push(0x42); }
        ch.origin_info.append("origin.example.com");

        var wire: u8[>..] = [];
        wing::marshal_token_challenge(ch, wire);
        sub.assert_gt(wire.len, 7, "Wire length > 7");

        var parsed = wing::TokenChallenge { .. };
        let ok = wing::unmarshal_token_challenge(wire[..], parsed);
        sub.assert_true(ok, "Unmarshal succeeded");
        sub.assert_eq(parsed.token_type, wing::TOKEN_TYPE_BLIND_RSA, "Token type matches");
        sub.assert_bytes_eq(parsed.issuer_name[..], "issuer.example.com", "Issuer name matches");
        sub.assert_eq(parsed.redemption_context.len, 32, "Redemption context is 32 bytes");
        sub.assert_bytes_eq(parsed.origin_info[..], "origin.example.com", "Origin info matches");

        // Challenge digest
        let digest = wing::compute_challenge_digest(ch);
        var zero_cnt = 0;
        for b in digest {
            if b == 0 { zero_cnt += 1; }
        }
        sub.assert_true(zero_cnt < 32, "Challenge digest is non-zero SHA-256");
    };

    t.run("TokenChallenge with Empty Context and Multiple Origins") { sub =>
        var ch = wing::TokenChallenge {
            token_type: wing::TOKEN_TYPE_PUBLICLY_VERIFIABLE,
            ..
        };
        ch.issuer_name.append("turnstile.cloudflare.com");
        ch.origin_info.append("site1.com,site2.com,site3.com");

        var wire: u8[>..] = [];
        wing::marshal_token_challenge(ch, wire);

        var parsed = wing::TokenChallenge { .. };
        let ok = wing::unmarshal_token_challenge(wire[..], parsed);
        sub.assert_true(ok, "Unmarshal succeeded");
        sub.assert_eq(parsed.token_type, wing::TOKEN_TYPE_PUBLICLY_VERIFIABLE, "Token type matches");
        sub.assert_eq(parsed.redemption_context.len, 0, "Redemption context is empty");
        sub.assert_bytes_eq(parsed.origin_info[..], "site1.com,site2.com,site3.com", "Origins preserved");
    };
}

fn test_token_wire_roundtrip(t: lit::T&) {
    t.run("Token Binary Wire Codec (RFC 9577 §2.2.1)") { sub =>
        var tok = wing::Token {
            token_type: wing::TOKEN_TYPE_BLIND_RSA,
            ..
        };
        for i in 32 { tok.nonce[i] = (i + 1) as u8; }
        for i in 32 { tok.challenge_digest[i] = (i + 50) as u8; }
        for i in 32 { tok.token_key_id.push(0x01); }
        for i in 64 { tok.authenticator.push(0x99); }

        var wire: u8[>..] = [];
        wing::marshal_token(tok, wire);
        // 2 + 32 + 32 + 32 + 64 = 162 bytes
        sub.assert_eq(wire.len, 162, "Token wire is exactly 162 bytes");

        var parsed = wing::Token { .. };
        let ok = wing::unmarshal_token(wire[..], 32, 64, parsed);
        sub.assert_true(ok, "Token unmarshaled");
        sub.assert_eq(parsed.token_type, wing::TOKEN_TYPE_BLIND_RSA, "Token type matches");
        sub.assert_bytes_eq(parsed.nonce[..], tok.nonce[..], "Nonce matches");
        sub.assert_bytes_eq(parsed.challenge_digest[..], tok.challenge_digest[..], "Challenge digest matches");
        sub.assert_bytes_eq(parsed.token_key_id[..], tok.token_key_id[..], "Token key id matches");
        sub.assert_bytes_eq(parsed.authenticator[..], tok.authenticator[..], "Authenticator matches");
    };
}

fn test_privacypass_headers_and_cache(t: lit::T&) {
    t.run("WWW-Authenticate PrivateToken Challenge Parsing") { sub =>
        // Construct challenge wire and base64url
        var ch = wing::TokenChallenge {
            token_type: wing::TOKEN_TYPE_BLIND_RSA,
            ..
        };
        ch.issuer_name.append("issuer.example.com");
        ch.origin_info.append("origin.example.com");

        var ch_wire: u8[>..] = [];
        wing::marshal_token_challenge(ch, ch_wire);

        var ch_b64: u8[..512] = [];
        core::base64url_encode(ch_wire[..], ch_b64);

        var header_val: u8[..1024] = [];
        header_val.append("PrivateToken challenge=\"");
        header_val.append(ch_b64[..]);
        header_val.append("\", token-key=\"AQIDBA==\", max-age=3600");

        var parsed_ch = wing::TokenChallenge { .. };
        var token_key: u8[..128] = [];
        var max_age:   i64       = 0;
        let ok = wing::parse_private_token_challenge(header_val[..], parsed_ch, token_key, max_age);
        sub.assert_true(ok, "PrivateToken challenge header parsed");
        sub.assert_bytes_eq(parsed_ch.issuer_name[..], "issuer.example.com", "Issuer name parsed");
        sub.assert_bytes_eq(parsed_ch.origin_info[..], "origin.example.com", "Origin info parsed");
        sub.assert_eq(max_age, 3600, "max-age parsed as 3600 seconds");
    };

    t.run("Authorization Header Formatting") { sub =>
        let raw_token = "mock_privacy_token_bytes_xyz_12345";
        var auth_hdr: u8[..512] = [];
        wing::format_private_token_authorization(raw_token, auth_hdr);
        sub.assert_true(core::eq_ascii_fold(auth_hdr[..19], "PrivateToken token="), "Starts with PrivateToken token=");

        var sec_hdr: u8[..512] = [];
        wing::format_sec_private_state_token(raw_token, sec_hdr);
        sub.assert_gt(sec_hdr.len, 0, "Sec-Private-State-Token formatted");
    };

    t.run("PrivateTokenCache Storage and Single-Use Enforcement") { sub =>
        var cache = wing::PrivateTokenCache { .. };
        var ch = wing::TokenChallenge { .. };
        ch.issuer_name.append("issuer.example.com");
        ch.origin_info.append("example.com");

        var tok = wing::Token { .. };
        tok.token_key_id.append("key1");
        let raw = "raw_token_data_stream";

        let now_sec: i64 = 1714000000;
        let put_ok = wing::put_private_token(cache, ch, tok, raw, 3600, now_sec);
        sub.assert_true(put_ok, "Token cached");

        // Spend token 1st time (should succeed)
        var got_tok = wing::Token { .. };
        var got_raw: u8[..512] = [];
        let get1_ok = wing::get_private_token(cache, ch, now_sec + 10, got_tok, got_raw);
        sub.assert_true(get1_ok, "1st spend succeeds");
        sub.assert_bytes_eq(got_raw[..], raw, "Got matching raw token");

        // Spend token 2nd time (should FAIL - RFC 9577 single-use spend)
        var got_tok2 = wing::Token { .. };
        var got_raw2: u8[..512] = [];
        let get2_ok = wing::get_private_token(cache, ch, now_sec + 20, got_tok2, got_raw2);
        sub.assert_false(get2_ok, "2nd spend fails (token already redeemed)");
    };

    t.run("Client Response Challenge Detection and GREASE Types") { sub =>
        var resp = wing::Response { status_code: 401, .. };
        resp.headers.push(wing::make_header("WWW-Authenticate", "PrivateToken challenge=\"abc\""));
        sub.assert_true(wing::has_private_token_challenge(resp), "Detects 401 PrivateToken challenge");

        var resp_200 = wing::Response { status_code: 200, .. };
        sub.assert_false(wing::has_private_token_challenge(resp_200), "Rejects non-401 response");

        // GREASE verification (RFC 9577 §6.2.1)
        sub.assert_true(wing::is_grease_token_type(0x02AA), "0x02AA is GREASE");
        sub.assert_true(wing::is_grease_token_type(0xF057), "0xF057 is GREASE");
        sub.assert_false(wing::is_grease_token_type(0x0001), "0x0001 is NOT GREASE (Blind RSA)");
        sub.assert_false(wing::is_grease_token_type(0x0002), "0x0002 is NOT GREASE (Publicly Verifiable)");
    };
}

// --- Component: auth_ed25519 ---
// tests/ed25519_test.goose
// Verification test suite for Ed25519 (RFC 8032) and SHA-512 (FIPS 180-4).

fn test_sha512_fips(t: lit::T&) {
    t.run("SHA512-01: Empty string NIST vector") { sub =>
        let empty: u8[0] = [];
        let hash = core::sha512(empty[..]);
        let expected: u8[64] = [
            0xcf, 0x83, 0xe1, 0x35, 0x7e, 0xef, 0xb8, 0xbd,
            0xf1, 0x54, 0x28, 0x50, 0xd6, 0x6d, 0x80, 0x07,
            0xd6, 0x20, 0xe4, 0x05, 0x0b, 0x57, 0x15, 0xdc,
            0x83, 0xf4, 0xa9, 0x21, 0xd3, 0x6c, 0xe9, 0xce,
            0x47, 0xd0, 0xd1, 0x3c, 0x5d, 0x85, 0xf2, 0xb0,
            0xff, 0x83, 0x18, 0xd2, 0x87, 0x7e, 0xec, 0x2f,
            0x63, 0xb9, 0x31, 0xbd, 0x47, 0x41, 0x7a, 0x81,
            0xa5, 0x38, 0x32, 0x7a, 0xf9, 0x27, 0xda, 0x3e,
        ];
        for i in 64 {
            sub.assert_eq(hash[i], expected[i], "SHA-512 empty string hash byte matches NIST");
        }
    };

    t.run("SHA512-02: String 'abc' NIST vector") { sub =>
        let abc: u8[3] = [0x61, 0x62, 0x63];
        let hash = core::sha512(abc[..]);
        let expected: u8[64] = [
            0xdd, 0xaf, 0x35, 0xa1, 0x93, 0x61, 0x7a, 0xba,
            0xcc, 0x41, 0x73, 0x49, 0xae, 0x20, 0x41, 0x31,
            0x12, 0xe6, 0xfa, 0x4e, 0x89, 0xa9, 0x7e, 0xa2,
            0x0a, 0x9e, 0xee, 0xe6, 0x4b, 0x55, 0xd3, 0x9a,
            0x21, 0x92, 0x99, 0x2a, 0x27, 0x4f, 0xc1, 0xa8,
            0x36, 0xba, 0x3c, 0x23, 0xa3, 0xfe, 0xeb, 0xbd,
            0x45, 0x4d, 0x44, 0x23, 0x64, 0x3c, 0xe8, 0x0e,
            0x2a, 0x9a, 0xc9, 0x4f, 0xa5, 0x4c, 0xa4, 0x9f,
        ];
        for i in 64 {
            sub.assert_eq(hash[i], expected[i], "SHA-512 'abc' hash byte matches NIST");
        }
    };
}

fn test_ed25519_rfc8032(t: lit::T&) {
    t.run("ED25519-01: RFC 8032 Section 7.1 Test Vector 1 (Empty Message)") { sub =>
        let seed: u8[32] = [
            0x9d, 0x61, 0xb1, 0x9d, 0xef, 0xfd, 0x5a, 0x60,
            0xba, 0x84, 0x4a, 0xf4, 0x92, 0xec, 0x2c, 0xc4,
            0x44, 0x49, 0xc5, 0x69, 0x7b, 0x32, 0x69, 0x19,
            0x70, 0x3b, 0xac, 0x03, 0x1c, 0xae, 0x7f, 0x60,
        ];
        let expected_pub: u8[32] = [
            0xd7, 0x5a, 0x98, 0x01, 0x82, 0xb1, 0x0a, 0xb7,
            0xd5, 0x4b, 0xfe, 0xd3, 0xc9, 0x64, 0x07, 0x3a,
            0x0e, 0xe1, 0x72, 0xf3, 0xda, 0xa6, 0x23, 0x25,
            0xaf, 0x02, 0x1a, 0x68, 0xf7, 0x07, 0x51, 0x1a,
        ];
        let expected_sig: u8[64] = [
            0xe5, 0x56, 0x43, 0x00, 0xc3, 0x60, 0xac, 0x72,
            0x90, 0x86, 0xe2, 0xcc, 0x80, 0x6e, 0x82, 0x8a,
            0x84, 0x87, 0x7f, 0x1e, 0xb8, 0xe5, 0xd9, 0x74,
            0xd8, 0x73, 0xe0, 0x65, 0x22, 0x49, 0x01, 0x55,
            0x5f, 0xb8, 0x82, 0x15, 0x90, 0xa3, 0x3b, 0xac,
            0xc6, 0x1e, 0x39, 0x70, 0x1c, 0xf9, 0xb4, 0x6b,
            0xd2, 0x5b, 0xf5, 0xf0, 0x59, 0x5b, 0xbe, 0x24,
            0x65, 0x51, 0x41, 0x43, 0x8e, 0x7a, 0x10, 0x0b,
        ];

        // 1. Check public key derivation
        let pub_key = core::ed25519_public_key(seed);
        for i in 32 {
            sub.assert_eq(pub_key[i], expected_pub[i], "Vector 1 public key matches RFC 8032");
        }

        // 2. Check signature generation
        let empty_msg: u8[0] = [];
        let sig = core::ed25519_sign(seed, empty_msg[..]);
        for i in 64 {
            sub.assert_eq(sig[i], expected_sig[i], "Vector 1 signature matches RFC 8032");
        }

        // 3. Check signature verification
        let ok = core::ed25519_verify(pub_key, empty_msg[..], sig);
        sub.assert_true(ok, "Vector 1 signature verification succeeds");
    };

    t.run("ED25519-02: RFC 8032 Section 7.1 Test Vector 2 (1-byte Message)") { sub =>
        let seed: u8[32] = [
            0x4c, 0xcd, 0x08, 0x9b, 0x28, 0xff, 0x96, 0xda,
            0x9d, 0xb6, 0xc3, 0x46, 0xec, 0x11, 0x4e, 0x0f,
            0x5b, 0x8a, 0x31, 0x9f, 0x35, 0xab, 0xa6, 0x24,
            0xda, 0x8c, 0xf6, 0xed, 0x4f, 0xb8, 0xa6, 0xfb,
        ];
        let expected_pub: u8[32] = [
            0x3d, 0x40, 0x17, 0xc3, 0xe8, 0x43, 0x89, 0x5a,
            0x92, 0xb7, 0x0a, 0xa7, 0x4d, 0x1b, 0x7e, 0xbc,
            0x9c, 0x98, 0x2c, 0xcf, 0x2e, 0xc4, 0x96, 0x8c,
            0xc0, 0xcd, 0x55, 0xf1, 0x2a, 0xf4, 0x66, 0x0c,
        ];
        let expected_sig: u8[64] = [
            0x92, 0xa0, 0x09, 0xa9, 0xf0, 0xd4, 0xca, 0xb8,
            0x72, 0x0e, 0x82, 0x0b, 0x5f, 0x64, 0x25, 0x40,
            0xa2, 0xb2, 0x7b, 0x54, 0x16, 0x50, 0x3f, 0x8f,
            0xb3, 0x76, 0x22, 0x23, 0xeb, 0xdb, 0x69, 0xda,
            0x08, 0x5a, 0xc1, 0xe4, 0x3e, 0x15, 0x99, 0x6e,
            0x45, 0x8f, 0x36, 0x13, 0xd0, 0xf1, 0x1d, 0x8c,
            0x38, 0x7b, 0x2e, 0xae, 0xb4, 0x30, 0x2a, 0xee,
            0xb0, 0x0d, 0x29, 0x16, 0x12, 0xbb, 0x0c, 0x00,
        ];
        let msg: u8[1] = [0x72];

        // 1. Check public key derivation
        let pub_key = core::ed25519_public_key(seed);
        for i in 32 {
            sub.assert_eq(pub_key[i], expected_pub[i], "Vector 2 public key matches RFC 8032");
        }

        // 2. Check signature generation
        let sig = core::ed25519_sign(seed, msg[..]);
        for i in 64 {
            sub.assert_eq(sig[i], expected_sig[i], "Vector 2 signature matches RFC 8032");
        }

        // 3. Check signature verification
        let ok = core::ed25519_verify(pub_key, msg[..], sig);
        sub.assert_true(ok, "Vector 2 signature verification succeeds");
    };

    t.run("ED25519-03: RFC 8032 Section 7.1 Test Vector 3 (2-byte Message)") { sub =>
        let seed: u8[32] = [
            0xc5, 0xaa, 0x8d, 0xf4, 0x3f, 0x9f, 0x83, 0x7b,
            0xed, 0xb7, 0x44, 0x2f, 0x31, 0xdc, 0xb7, 0xb1,
            0x66, 0xd3, 0x85, 0x35, 0x07, 0x6f, 0x09, 0x4b,
            0x85, 0xce, 0x3a, 0x2e, 0x0b, 0x44, 0x58, 0xf7,
        ];
        let expected_pub: u8[32] = [
            0xfc, 0x51, 0xcd, 0x8e, 0x62, 0x18, 0xa1, 0xa3,
            0x8d, 0xa4, 0x7e, 0xd0, 0x02, 0x30, 0xf0, 0x58,
            0x08, 0x16, 0xed, 0x13, 0xba, 0x33, 0x03, 0xac,
            0x5d, 0xeb, 0x91, 0x15, 0x48, 0x90, 0x80, 0x25,
        ];
        let expected_sig: u8[64] = [
            0x62, 0x91, 0xd6, 0x57, 0xde, 0xec, 0x24, 0x02,
            0x48, 0x27, 0xe6, 0x9c, 0x3a, 0xbe, 0x01, 0xa3,
            0x0c, 0xe5, 0x48, 0xa2, 0x84, 0x74, 0x3a, 0x44,
            0x5e, 0x36, 0x80, 0xd7, 0xdb, 0x5a, 0xc3, 0xac,
            0x18, 0xff, 0x9b, 0x53, 0x8d, 0x16, 0xf2, 0x90,
            0xae, 0x67, 0xf7, 0x60, 0x98, 0x4d, 0xc6, 0x59,
            0x4a, 0x7c, 0x15, 0xe9, 0x71, 0x6e, 0xd2, 0x8d,
            0xc0, 0x27, 0xbe, 0xce, 0xea, 0x1e, 0xc4, 0x0a,
        ];
        let msg: u8[2] = [0xaf, 0x82];

        // 1. Check public key derivation
        let pub_key = core::ed25519_public_key(seed);
        for i in 32 {
            sub.assert_eq(pub_key[i], expected_pub[i], "Vector 3 public key matches RFC 8032");
        }

        // 2. Check signature generation
        let sig = core::ed25519_sign(seed, msg[..]);
        for i in 64 {
            sub.assert_eq(sig[i], expected_sig[i], "Vector 3 signature matches RFC 8032");
        }

        // 3. Check signature verification
        let ok = core::ed25519_verify(pub_key, msg[..], sig);
        sub.assert_true(ok, "Vector 3 signature verification succeeds");
    };

    t.run("ED25519-04: Tamper Resistance & Malleability Checks") { sub =>
        let seed: u8[32] = [
            0x9d, 0x61, 0xb1, 0x9d, 0xef, 0xfd, 0x5a, 0x60,
            0xba, 0x84, 0x4a, 0xf4, 0x92, 0xec, 0x2c, 0xc4,
            0x44, 0x49, 0xc5, 0x69, 0x7b, 0x32, 0x69, 0x19,
            0x70, 0x3b, 0xac, 0x03, 0x1c, 0xae, 0x7f, 0x60,
        ];
        let pub_key = core::ed25519_public_key(seed);
        let msg: u8[4] = [0x74, 0x65, 0x73, 0x74]; // "test"
        let sig = core::ed25519_sign(seed, msg[..]);

        // Valid signature verifies
        sub.assert_true(core::ed25519_verify(pub_key, msg[..], sig), "Original signature verifies");

        // 1. Tampered message
        let tampered_msg: u8[4] = [0x74, 0x65, 0x73, 0x75];
        sub.assert_false(core::ed25519_verify(pub_key, tampered_msg[..], sig), "Tampered message rejected");

        // 2. Tampered R in signature
        var tampered_sig = sig;
        tampered_sig[0] ^= 0x01;
        sub.assert_false(core::ed25519_verify(pub_key, msg[..], tampered_sig), "Tampered R rejected");

        // 3. Tampered S in signature
        tampered_sig = sig;
        tampered_sig[32] ^= 0x01;
        sub.assert_false(core::ed25519_verify(pub_key, msg[..], tampered_sig), "Tampered S rejected");

        // 4. Tampered public key
        var tampered_pub = pub_key;
        tampered_pub[0] ^= 0x01;
        sub.assert_false(core::ed25519_verify(tampered_pub, msg[..], sig), "Tampered public key rejected");

        // 5. Non-canonical S >= L (malleability rejection)
        var non_canonical_sig = sig;
        for i in 32 {
            non_canonical_sig[32 + i] = core::ED25519_L_BYTES[i];
        }
        sub.assert_false(core::ed25519_verify(pub_key, msg[..], non_canonical_sig), "S >= L rejected");
    };

    t.run("ED25519-05: Keypair Helper & 1KB Message Signing") { sub =>
        let seed: u8[32] = [
            0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0,
            0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10,
            0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
            0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00,
        ];
        let kp = core::ed25519_keypair(seed);
        let direct_pub = core::ed25519_public_key(seed);
        for i in 32 {
            sub.assert_eq(kp.public_key[i], direct_pub[i], "Keypair helper matches direct derivation");
            sub.assert_eq(kp.seed[i], seed[i], "Keypair seed preserved");
        }

        // Construct 1024-byte payload
        var large_msg: u8[1024] = [0; 1024];
        for i in 1024 {
            large_msg[i] = ((i * 37 + 13) & 0xFF) as u8;
        }

        let large_sig = core::ed25519_sign(seed, large_msg[..]);
        let large_ok = core::ed25519_verify(kp.public_key, large_msg[..], large_sig);
        sub.assert_true(large_ok, "1024-byte payload sign and verify succeeds");
    };
}

// --- Component: auth_hpke ---
// tests/hpke_test.goose
// Verification test suite for Curve25519 (RFC 7748) and HPKE (RFC 9180).

fn test_x25519_rfc7748(t: lit::T&) {
    t.run("X25519-01: RFC 7748 Alice/Bob Key Agreement & Test Vectors") { sub =>
        let alice_sk: u8[32] = [
            0x77, 0x07, 0x6d, 0x0a, 0x73, 0x18, 0xa5, 0x7d,
            0x3c, 0x16, 0xc1, 0x72, 0x51, 0xb2, 0x66, 0x45,
            0xdf, 0x4c, 0x2f, 0x87, 0xeb, 0xc0, 0x99, 0x2a,
            0xb1, 0x77, 0xfb, 0xa5, 0x1d, 0xb9, 0x2c, 0x2a,
        ];
        let bob_sk: u8[32] = [
            0x5d, 0xab, 0x08, 0x7e, 0x62, 0x4a, 0x8a, 0x4b,
            0x79, 0xe1, 0x7f, 0x8b, 0x83, 0x80, 0x0e, 0xe6,
            0x6f, 0x3b, 0xb1, 0x29, 0x26, 0x18, 0xb6, 0xfd,
            0x1c, 0x2f, 0x8b, 0x27, 0xff, 0x88, 0xe0, 0xeb,
        ];

        let alice_pk = core::x25519_base_scalarmult(alice_sk);
        let expected_alice_pk: u8[32] = [
            0x85, 0x20, 0xf0, 0x09, 0x89, 0x30, 0xa7, 0x54,
            0x74, 0x8b, 0x7d, 0xdc, 0xb4, 0x3e, 0xf7, 0x5a,
            0x0d, 0xbf, 0x3a, 0x0d, 0x26, 0x38, 0x1a, 0xf4,
            0xeb, 0xa4, 0xa9, 0x8e, 0xaa, 0x9b, 0x4e, 0x6a,
        ];
        for i in 32 {
            sub.assert_eq(alice_pk[i], expected_alice_pk[i], "Alice PK matches RFC 7748");
        }

        let bob_pk = core::x25519_base_scalarmult(bob_sk);
        let expected_bob_pk: u8[32] = [
            0xde, 0x9e, 0xdb, 0x7d, 0x7b, 0x7d, 0xc1, 0xb4,
            0xd3, 0x5b, 0x61, 0xc2, 0xec, 0xe4, 0x35, 0x37,
            0x3f, 0x83, 0x43, 0xc8, 0x5b, 0x78, 0x67, 0x4d,
            0xad, 0xfc, 0x7e, 0x14, 0x6f, 0x88, 0x2b, 0x4f,
        ];
        for i in 32 {
            sub.assert_eq(bob_pk[i], expected_bob_pk[i], "Bob PK matches RFC 7748");
        }

        let shared_alice = core::x25519_scalarmult(alice_sk, bob_pk);
        let shared_bob = core::x25519_scalarmult(bob_sk, alice_pk);
        let expected_shared: u8[32] = [
            0x4a, 0x5d, 0x9d, 0x5b, 0xa4, 0xce, 0x2d, 0xe1,
            0x72, 0x8e, 0x3b, 0xf4, 0x80, 0x35, 0x0f, 0x25,
            0xe0, 0x7e, 0x21, 0xc9, 0x47, 0xd1, 0x9e, 0x33,
            0x76, 0xf0, 0x9b, 0x3c, 0x1e, 0x16, 0x17, 0x42,
        ];
        for i in 32 {
            sub.assert_eq(shared_alice[i], expected_shared[i], "Alice shared secret matches RFC 7748");
            sub.assert_eq(shared_bob[i], expected_shared[i], "Bob shared secret matches RFC 7748");
        }
    };
}

fn test_hpke_rfc9180(t: lit::T&) {
    t.run("HPKE-01: RFC 9180 Section A.1.1 DHKEM(X25519, HKDF-SHA256) + AES-128-GCM") { sub =>
        let skEm: u8[32] = [
            0x52, 0xc4, 0xa7, 0x58, 0xa8, 0x02, 0xcd, 0x8b,
            0x93, 0x6e, 0xce, 0xea, 0x31, 0x44, 0x32, 0x79,
            0x8d, 0x5b, 0xaf, 0x2d, 0x7e, 0x92, 0x35, 0xdc,
            0x08, 0x4a, 0xb1, 0xb9, 0xcf, 0xa2, 0xf7, 0x36,
        ];
        let pkRm: u8[32] = [
            0x39, 0x48, 0xcf, 0xe0, 0xad, 0x1d, 0xdb, 0x69,
            0x5d, 0x78, 0x0e, 0x59, 0x07, 0x71, 0x95, 0xda,
            0x6c, 0x56, 0x50, 0x6b, 0x02, 0x73, 0x29, 0x79,
            0x4a, 0xb0, 0x2b, 0xca, 0x80, 0x81, 0x5c, 0x4d,
        ];
        let skRm: u8[32] = [
            0x46, 0x12, 0xc5, 0x50, 0x26, 0x3f, 0xc8, 0xad,
            0x58, 0x37, 0x5d, 0xf3, 0xf5, 0x57, 0xaa, 0xc5,
            0x31, 0xd2, 0x68, 0x50, 0x90, 0x3e, 0x55, 0xa9,
            0xf2, 0x3f, 0x21, 0xd8, 0x53, 0x4e, 0x8a, 0xc8,
        ];

        let info: const u8[:] = "Ode on a Grecian Urn";
        let pt:   const u8[:] = "Beauty is truth, truth beauty";
        let aad:  const u8[:] = "Count-0";

        var enc: u8[32]  = [0; 32];
        var ct:  u8[>..] = [];

        let ok_seal = wing::hpke_seal_base(
            pkRm,
            info,
            aad,
            pt,
            skEm,
            wing::HPKE_AEAD_AES_128_GCM,
            enc,
            ct,
        );
        sub.assert_true(ok_seal, "hpke_seal_base succeeds");

        let expected_enc: u8[32] = [
            0x37, 0xfd, 0xa3, 0x56, 0x7b, 0xdb, 0xd6, 0x28,
            0xe8, 0x86, 0x68, 0xc3, 0xc8, 0xd7, 0xe9, 0x7d,
            0x1d, 0x12, 0x53, 0xb6, 0xd4, 0xea, 0x6d, 0x44,
            0xc1, 0x50, 0xf7, 0x41, 0xf1, 0xbf, 0x44, 0x31,
        ];
        for i in 32 {
            sub.assert_eq(enc[i], expected_enc[i], "enc matches RFC 9180 A.1.1");
        }

        let expected_ct: u8[45] = [
            0xf9, 0x38, 0x55, 0x8b, 0x5d, 0x72, 0xf1, 0xa2,
            0x38, 0x10, 0xb4, 0xbe, 0x2a, 0xb4, 0xf8, 0x43,
            0x31, 0xac, 0xc0, 0x2f, 0xc9, 0x7b, 0xab, 0xc5,
            0x3a, 0x52, 0xae, 0x82, 0x18, 0xa3, 0x55, 0xa9,
            0x6d, 0x87, 0x70, 0xac, 0x83, 0xd0, 0x7b, 0xea,
            0x87, 0xe1, 0x3c, 0x51, 0x2a,
        ];
        sub.assert_eq(ct.len, 45, "ct length is 45");
        for i in 45 {
            sub.assert_eq(ct[i], expected_ct[i], "ct matches RFC 9180 A.1.1");
        }

        // Test decryption roundtrip
        var decrypted: u8[>..] = [];
        let ok_open = wing::hpke_open_base(
            enc,
            skRm,
            info,
            aad,
            ct[..],
            wing::HPKE_AEAD_AES_128_GCM,
            decrypted,
        );
        sub.assert_true(ok_open, "hpke_open_base succeeds");
        sub.assert_eq(decrypted.len, pt.len, "decrypted length matches plaintext");
        for i in pt.len {
            sub.assert_eq(decrypted[i], pt[i], "decrypted byte matches");
        }

        // Test tamper resistance
        ct[5] ^= 0x40;
        var dec_tampered: u8[>..] = [];
        let ok_tamper = wing::hpke_open_base(
            enc,
            skRm,
            info,
            aad,
            ct[..],
            wing::HPKE_AEAD_AES_128_GCM,
            dec_tampered,
        );
        sub.assert_false(ok_tamper, "tampered ciphertext fails decryption");
    };

    t.run("HPKE-02: DHKEM(X25519) + ChaCha20-Poly1305 Roundtrip") { sub =>
        let alice_sk: u8[32] = [
            0x77, 0x07, 0x6d, 0x0a, 0x73, 0x18, 0xa5, 0x7d,
            0x3c, 0x16, 0xc1, 0x72, 0x51, 0xb2, 0x66, 0x45,
            0xdf, 0x4c, 0x2f, 0x87, 0xeb, 0xc0, 0x99, 0x2a,
            0xb1, 0x77, 0xfb, 0xa5, 0x1d, 0xb9, 0x2c, 0x2a,
        ];
        let bob_sk: u8[32] = [
            0x5d, 0xab, 0x08, 0x7e, 0x62, 0x4a, 0x8a, 0x4b,
            0x79, 0xe1, 0x7f, 0x8b, 0x83, 0x80, 0x0e, 0xe6,
            0x6f, 0x3b, 0xb1, 0x29, 0x26, 0x18, 0xb6, 0xfd,
            0x1c, 0x2f, 0x8b, 0x27, 0xff, 0x88, 0xe0, 0xeb,
        ];
        let bob_pk = core::x25519_base_scalarmult(bob_sk);

        let info: const u8[:] = "Wing Systems Zero-Heap ECH";
        let pt:   const u8[:] = "EncryptedClientHelloInner message payload";
        let aad:  const u8[:] = "ClientHelloOuterAAD";

        var enc: u8[32]  = [0; 32];
        var ct:  u8[>..] = [];

        let ok_seal = wing::hpke_seal_base(
            bob_pk,
            info,
            aad,
            pt,
            alice_sk,
            wing::HPKE_AEAD_CHACHA20_POLY1305,
            enc,
            ct,
        );
        sub.assert_true(ok_seal, "ChaCha20Poly1305 seal succeeds");

        var decrypted: u8[>..] = [];
        let ok_open = wing::hpke_open_base(
            enc,
            bob_sk,
            info,
            aad,
            ct[..],
            wing::HPKE_AEAD_CHACHA20_POLY1305,
            decrypted,
        );
        sub.assert_true(ok_open, "ChaCha20Poly1305 open succeeds");
        sub.assert_eq(decrypted.len, pt.len, "decrypted length matches");
        for i in pt.len {
            sub.assert_eq(decrypted[i], pt[i], "decrypted payload matches");
        }
    };
}

// --- Component: auth_digest_invariants ---
// Hardening & Security Invariants Suite for HTTP Digest Authentication (RFC 7616):
// 1. Buffer overflow protection on algorithm and qop (> 32 bytes).
// 2. Missing '=' separator and malformed parameter syntax rejection.
// 3. Parameter injection prevention in Authorization header serialization.
// 4. CRLF injection prevention in Digest header parameters.

fn test_digest_challenge_buffer_bounds(t: lit::T&) {
    t.run("DIGEST-SEC-01: Algorithm Name Exceeding 32 Bytes Must Not Panic") { sub =>
        // 40-character algorithm string
        let long_algo = "Digest realm=\"api\", nonce=\"12345\", algorithm=SHA-256-SUPER-LONG-ALGORITHM-NAME-OVERFLOW";
        let chal, ok = wing::parse_digest_challenge(long_algo);
        // Must either fail or safely reject the oversize algorithm without panicking
        sub.assert_true(true, "oversize algorithm handled without capacity panic");
        if ok {
            sub.assert_true(chal.algorithm.len <= 32, "algorithm capacity not exceeded");
        }
    };

    t.run("DIGEST-SEC-02: QOP String Exceeding 32 Bytes Must Not Panic") { sub =>
        // 50-character qop string
        let long_qop = "Digest realm=\"api\", nonce=\"12345\", qop=\"auth,auth-int,super-long-unsupported-qop-value-overflow\"";
        let chal, ok = wing::parse_digest_challenge(long_qop);
        sub.assert_true(true, "oversize qop handled without capacity panic");
        if ok {
            sub.assert_true(chal.qop.len <= 32, "qop capacity not exceeded");
        }
    };

    t.run("DIGEST-SEC-03: Missing '=' Separator Must Be Rejected") { sub =>
        let missing_eq = "Digest realm \"test\", nonce=\"12345\"";
        let _, ok = wing::parse_digest_challenge(missing_eq);
        sub.assert_false(ok, "missing '=' separator between parameter key and value must be rejected");
    };

    t.run("DIGEST-SEC-04: Unclosed Quoted Parameter Must Be Rejected") { sub =>
        let unclosed = "Digest realm=\"unclosed_realm, nonce=\"12345\"";
        let _, ok = wing::parse_digest_challenge(unclosed);
        sub.assert_false(ok, "unclosed quoted string in challenge must be rejected");
    };
}

fn test_has_substr(haystack: const u8[:], needle: const u8[:]) -> bool {
    guard haystack.len >= needle.len else { return false; }
    for i in 0..(haystack.len - needle.len + 1) {
        if haystack[i..i + needle.len] == needle {
            return true;
        }
    }
    return false;
}

fn test_digest_auth_serialization_security(t: lit::T&) {
    t.run("DIGEST-SEC-05: Injected Quotes in Nonce Must Be Escaped") { sub =>
        var out_hdr: u8[..512] = [];
        let ok = wing::serialize_digest_auth(
            "user", "realm", "nonce\"with\"quotes", "/api",
            "SHA-256", "0123456789abcdef", "auth",
            "00000001", "cnonce", "opaque", false,
            out_hdr,
        );
        sub.assert_true(ok, "serialization succeeds with escaped quotes");

        // Verify that quotes inside nonce were escaped as \"
        sub.assert_true(test_has_substr(out_hdr[..], "nonce=\"nonce\\\"with\\\"quotes\""), "quotes inside nonce must be escaped with backslash");
    };

    t.run("DIGEST-SEC-06: CRLF Injection in Realm or Nonce Must Be Rejected") { sub =>
        var out_hdr: u8[..512] = [];
        let ok = wing::serialize_digest_auth(
            "user", "realm\r\nEvil: true", "nonce", "/api",
            "SHA-256", "0123456789abcdef", "auth",
            "00000001", "cnonce", "opaque", false,
            out_hdr,
        );
        sub.assert_false(ok, "CRLF inside realm must cause serialization failure (header injection prevention)");
    };
}

// Invariant 13: Zero silent buffer drops - JWT header unknown keys capacity overflow
fn test_jwt_header_capacity_rejection(t: lit::T&) {
    t.run("JWT header unknown key overflow triggers parsing error") { sub =>
        var bad_jwt: u8[>..] = "{\"alg\":\"none\",\"k1\":1,\"k2\":2,\"k3\":3,\"k4\":4,\"k5\":5,\"k6\":6,\"k7\":7,\"k8\":8,\"k9\":9}";
        var hdr = wing::JwtHeader { .. };
        let err = wing::decode_jwt_header(bad_jwt[..], hdr);
        sub.assert_true(err != wing::JwtError.None, "JWT header exceeding seen_others capacity MUST fail");
    };
}

fn test_acme_http01(t: lit::T&) {
    t.run("RFC 8555 §8.3 HTTP-01 token validation") { sub =>
        sub.assert_true(wing::acme_validate_token("LoqXcYV8vQa8jxAjEuX0"), "RFC 8555 example token accepted");
        sub.assert_false(wing::acme_validate_token("../etc/passwd"), "path traversal rejected");
        sub.assert_false(wing::acme_validate_token("a/b"), "slash rejected");
        sub.assert_false(wing::acme_validate_token(""), "empty token rejected");
    };

    t.run("RFC 8555 §8.1 key authorization concatenation") { sub =>
        var out: u8[..256] = [];
        let n = wing::acme_key_authorization("tok", "TP", out);
        sub.assert_eq(n, 6, "key authorization length");
        sub.assert_bytes_eq(out[..], "tok.TP", "token || '.' || thumbprint");
    };

    t.run("RFC 8555 §8.3 HTTP-01 path construction") { sub =>
        var out: u8[..128] = [];
        let n = wing::acme_http01_path("tok", out);
        sub.assert_eq(n, 31, "path length");
        sub.assert_bytes_eq(out[..], "/.well-known/acme-challenge/tok", "well-known acme-challenge path");
    };

    t.run("RFC 8555 §8.3 HTTP-01 path matching rejects traversal") { sub =>
        sub.assert_true(wing::acme_match_http01("/.well-known/acme-challenge/tok", "tok"), "exact match");
        sub.assert_false(wing::acme_match_http01("/.well-known/acme-challenge/other", "tok"), "different token");
        sub.assert_false(wing::acme_match_http01("/.well-known/acme-challenge/../tok", "tok"), "dot-dot traversal");
    };

    t.run("HTTP-01 challenge responder table lookup") { sub =>
        var table: wing::AcmeChallenge[..8] = [];
        var ch = wing::AcmeChallenge {
            token:        "tok",
            key_auth:     "tok.TP",
            key_auth_len: 6,
        };
        table.push(ch);

        var body:     u8[..256] = [];
        var body_len: i32       = 0;
        sub.assert_true(
            wing::acme_find_challenge(table, "/.well-known/acme-challenge/tok", body, body_len),
            "challenge found",
        );
        sub.assert_eq(body_len, 6, "body length");
        sub.assert_bytes_eq(body[..], "tok.TP", "key authorization body");
        sub.assert_false(
            wing::acme_find_challenge(table, "/.well-known/acme-challenge/nope", body, body_len),
            "unknown path rejected",
        );
    };
}

fn main() {
    var runner = lit::new_runner("Authentication, Cryptographic Tokens, and Invariants Suite", lit::Verbosity.Verbose);

    lit::run_case(runner, "1. RFC 7616 Official IETF Test Vector & MD5 Fallback", test_rfc7616_official_ietf_vector);
    lit::run_case(runner, "2. 401 Authenticator Replay Loop (Digest & Basic)", test_401_authenticator_loop);
    lit::run_case(runner, "3. RFC 7616 Userhash Options", test_rfc7616_userhash_options);
    lit::run_case(runner, "4. Symmetric HMAC JWS (HS256, HS384, HS512)", test_symmetric_hmac_jwt);
    lit::run_case(runner, "5. Asymmetric Ed25519 JWS (EdDSA / RFC 8037)", test_asymmetric_eddsa_jwt);
    lit::run_case(runner, "6. RFC 8725 BCP Security Defenses", test_jwt_security_defenses);
    lit::run_case(runner, "7. RFC 7517 JWKS Serialization, Parsing & Key Rotation", test_jwks_serialization_and_parsing);
    lit::run_case(runner, "8. Integrated JWT Verification against JWKS Key Set", test_jwt_verification_against_jwks);
    lit::run_case(runner, "9. RFC 7519 Claims Parsing, RFC 8725 Defenses & RFC 7638 JWK Thumbprints", test_jwt_rfc7519_claims_and_thumbprint);
    lit::run_case(runner, "10. RFC 7515 Crit Headers & RFC 8725 Explicit Typ Verification", test_jwt_crit_and_typ_validation);
    lit::run_case(runner, "11. OAuth 2.0 PKCE (RFC 7636)", test_pkce_rfc7636);
    lit::run_case(runner, "12. OAuth 2.0 DPoP (RFC 9449)", test_dpop_rfc9449);
    lit::run_case(runner, "13. TokenChallenge Wire Codec", test_token_challenge_roundtrip);
    lit::run_case(runner, "14. Token Binary Wire Codec", test_token_wire_roundtrip);
    lit::run_case(runner, "15. Privacy Pass Headers & Cache", test_privacypass_headers_and_cache);
    lit::run_case(runner, "16. SHA-512 (FIPS 180-4) Cryptographic Hash Vectors", test_sha512_fips);
    lit::run_case(runner, "17. Ed25519 (RFC 8032) Digital Signatures & Attacks", test_ed25519_rfc8032);
    lit::run_case(runner, "18. Curve25519 (RFC 7748) Test Vectors", test_x25519_rfc7748);
    lit::run_case(runner, "19. HPKE (RFC 9180) SetupBase, Seal & Open Vectors", test_hpke_rfc9180);
    lit::run_case(runner, "20. Digest Challenge Buffer Bounds & Syntax", test_digest_challenge_buffer_bounds);
    lit::run_case(runner, "21. Digest Authorization Serialization Defenses", test_digest_auth_serialization_security);
    lit::run_case(runner, "22. Invariant 13 JWT Header Capacity Rejection", test_jwt_header_capacity_rejection);
    lit::run_case(runner, "23. RFC 8555 ACME HTTP-01", test_acme_http01);

    let ok = lit::finish(runner);
    assert(ok);
}
