// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Verification suite for OAuth 2.0 PKCE (RFC 7636) and DPoP (RFC 9449):
// - PKCE code verifier charset and length invariants (43..128 chars)
// - PKCE S256 and plain code challenge computation and constant-time validation
// - DPoP target URI normalization (strips query/fragments, lowercases scheme/host)
// - DPoP ATH (Access Token Hash) SHA-256 base64url generation
// - DPoP Proof JWT creation (JOSE header framing, claims payload, HMAC-SHA256 signature)
// - DPoP Proof verification against expected method, URI, access token, and nonce
// - Request header attachment and response DPoP-Nonce extraction
import std;
import core from "..";
import wing from "..";

fn test_pkce_rfc7636(t: core::T&) {
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
    };

    t.run("PKCE Create Challenge Pair Helper") { sub =>
        let pair = wing::create_pkce_pair("", "S256");
        sub.assert_ge(pair.verifier.len, 43, "Pair verifier length >= 43");
        sub.assert_true(wing::validate_code_challenge(pair.verifier[..], pair.challenge[..], "S256"), "Pair challenge matches verifier");
    };
}

fn test_dpop_rfc9449(t: core::T&) {
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
        let h_b64 = "eyJ0eXAiOiJkcG9wK2p3dCIsImFsZyI6IkhTMjU2In0";
        let c_json = "{\"jti\":\"jti-no-iat-01\",\"htm\":\"GET\",\"htu\":\"https://api.example.com/data\"}";
        var c_b64: u8[..256] = [];
        core::base64url_encode(c_json, c_b64);
        var signing_input: u8[..512] = [];
        signing_input.append(h_b64);
        signing_input.push('.' as u8);
        signing_input.append(c_b64[..]);
        let sig = core::hmac_sha256(key, signing_input[..]);
        var sig_b64: u8[..64] = [];
        core::base64url_encode(sig[..], sig_b64);
        var token: u8[..1024] = [];
        token.append(signing_input[..]);
        token.push('.' as u8);
        token.append(sig_b64[..]);

        let ok = wing::verify_dpop_proof(token[..], key, "GET", "https://api.example.com/data", "", "", 1714000000);
        sub.assert_false(ok, "Proof without iat MUST be rejected when now_sec > 0");
    };

    t.run("DPoP Nonce Substring Injection: expected nonce in jti must not bypass missing nonce claim (RFC 9449 §4.3)") { sub =>
        let key = "super_secret_dpop_key_32_bytes!!";
        let h_b64 = "eyJ0eXAiOiJkcG9wK2p3dCIsImFsZyI6IkhTMjU2In0";
        let c_json = "{\"jti\":\"expected_srv_nonce_999\",\"htm\":\"GET\",\"htu\":\"https://api.example.com/data\",\"iat\":1714000000}";
        var c_b64: u8[..256] = [];
        core::base64url_encode(c_json, c_b64);
        var signing_input: u8[..512] = [];
        signing_input.append(h_b64);
        signing_input.push('.' as u8);
        signing_input.append(c_b64[..]);
        let sig = core::hmac_sha256(key, signing_input[..]);
        var sig_b64: u8[..64] = [];
        core::base64url_encode(sig[..], sig_b64);
        var token: u8[..1024] = [];
        token.append(signing_input[..]);
        token.push('.' as u8);
        token.append(sig_b64[..]);

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

        let h_b64 = "eyJ0eXAiOiJkcG9wK2p3dCIsImFsZyI6IkhTMjU2In0";
        var c_b64: u8[..256] = [];
        core::base64url_encode(c_json[..], c_b64);
        var signing_input: u8[..512] = [];
        signing_input.append(h_b64);
        signing_input.push('.' as u8);
        signing_input.append(c_b64[..]);
        let sig = core::hmac_sha256(key, signing_input[..]);
        var sig_b64: u8[..64] = [];
        core::base64url_encode(sig[..], sig_b64);
        var token: u8[..1024] = [];
        token.append(signing_input[..]);
        token.push('.' as u8);
        token.append(sig_b64[..]);

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

        let h_b64 = "eyJ0eXAiOiJkcG9wK2p3dCIsImFsZyI6IkhTMjU2In0";
        var c_b64: u8[..256] = [];
        core::base64url_encode(c_json[..], c_b64);
        var signing_input: u8[..512] = [];
        signing_input.append(h_b64);
        signing_input.push('.' as u8);
        signing_input.append(c_b64[..]);
        let sig = core::hmac_sha256(key, signing_input[..]);
        var sig_b64: u8[..64] = [];
        core::base64url_encode(sig[..], sig_b64);
        var token: u8[..1024] = [];
        token.append(signing_input[..]);
        token.push('.' as u8);
        token.append(sig_b64[..]);

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
        let h_b64 = "eyJ0eXAiOiJkcG9wK2p3dCIsImFsZyI6IkhTMjU2In0";
        let c_json = "{\"jti\":\"jti-lc-method\",\"htm\":\"post\",\"htu\":\"https://api.example.com/data\",\"iat\":1714000000}";
        var c_b64: u8[..256] = [];
        core::base64url_encode(c_json, c_b64);
        var signing_input: u8[..512] = [];
        signing_input.append(h_b64);
        signing_input.push('.' as u8);
        signing_input.append(c_b64[..]);
        let sig = core::hmac_sha256(key, signing_input[..]);
        var sig_b64: u8[..64] = [];
        core::base64url_encode(sig[..], sig_b64);
        var token: u8[..1024] = [];
        token.append(signing_input[..]);
        token.push('.' as u8);
        token.append(sig_b64[..]);

        let fail_lc = wing::verify_dpop_proof(token[..], key, "POST", "https://api.example.com/data", "", "", 1714000000);
        sub.assert_false(fail_lc, "Proof with lowercase htm MUST be rejected");

        // Header with alg:none or fake typ must be rejected (RFC 9449 §4.2)
        let h_bad = "{\"typ\":\"jwt\",\"alg\":\"HS256\",\"p\":\"dpop+jwt\"}";
        var h_bad_b64: u8[..256] = [];
        core::base64url_encode(h_bad, h_bad_b64);
        var signing_bad: u8[..512] = [];
        signing_bad.append(h_bad_b64[..]);
        signing_bad.push('.' as u8);
        signing_bad.append(c_b64[..]);
        let sig_bad = core::hmac_sha256(key, signing_bad[..]);
        var sig_bad_b64: u8[..64] = [];
        core::base64url_encode(sig_bad[..], sig_bad_b64);
        var tok_bad: u8[..1024] = [];
        tok_bad.append(signing_bad[..]);
        tok_bad.push('.' as u8);
        tok_bad.append(sig_bad_b64[..]);
        let ok_fake_typ = wing::verify_dpop_proof(tok_bad[..], key, "POST", "https://api.example.com/data", "", "", 1714000000);
        sub.assert_false(ok_fake_typ, "Proof with fake typ must be rejected even if dpop+jwt is in extra property");
    };
}

fn main() {
    var runner = core::new_runner("OAuth 2.0 PKCE & DPoP Suite (RFC 7636 / RFC 9449)", core::Verbosity.Verbose);
    core::run_case(runner, "1. OAuth 2.0 PKCE (RFC 7636)", test_pkce_rfc7636);
    core::run_case(runner, "2. OAuth 2.0 DPoP (RFC 9449)", test_dpop_rfc9449);
    let ok = core::finish(runner);
    assert(ok);
}
