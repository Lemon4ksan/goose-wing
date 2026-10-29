// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Verification suite for RFC 9530 Digest Fields for HTTP (obsoleting RFC 3230)
// and OAuth 2.1 / RFC 9700 strict PKCE validation:
// - Content-Digest and Repr-Digest generation using RFC 8941 Structured Fields
// - sha-256 and sha-512 binary byte sequence verification (:base64:)
// - Cryptographic binding with RFC 9421 HTTP Message Signatures
// - Tampered payload rejection
// - Strict PKCE plain transformation rejection
import std;
import core from "..";
import wing from "..";

fn test_rfc9530_content_digest(t: core::T&) {
    t.run("Content-Digest sha-256 Generation & Verification") { sub =>
        var req = wing::Request {
            method: "POST",
            url: "https://api.gateway.org/items",
            ..
        };
        req.body.clear();
        req.body.append("{\"item_id\":42,\"action\":\"checkout\"}");

        let ok_set = wing::set_content_digest(req, "sha-256");
        sub.assert_true(ok_set, "Content-Digest set on request");

        let digest_val = req.header("Content-Digest");
        sub.assert_gt(digest_val.len, 0, "Content-Digest header exists");
        sub.assert_contains(digest_val, "sha-256=:", "Has sha-256 prefix with SF byte sequence delimiter");
        sub.assert_true(digest_val[digest_val.len - 1] == ':' as u8, "Ends with SF byte sequence delimiter");

        let ok_verify = wing::verify_request_content_digest(req);
        sub.assert_true(ok_verify, "Content-Digest verifies successfully against body");

        // Tamper payload
        var tampered_req = req;
        tampered_req.body.clear();
        tampered_req.body.append("{\"item_id\":42,\"action\":\"tampered\"}");
        let tamper_verify = wing::verify_request_content_digest(tampered_req);
        sub.assert_false(tamper_verify, "Tampered body fails Content-Digest verification");
    };

    t.run("Content-Digest sha-512 on Response") { sub =>
        var res = wing::Response {
            status_code: 200,
            ..
        };
        res.body.clear();
        res.body.append("{\"status\":\"shipped\",\"tracking\":\"TRK123456\"}");

        let ok_set = wing::set_response_content_digest(res, "sha-512");
        sub.assert_true(ok_set, "Content-Digest sha-512 set on response");

        let digest_val = res.header("Content-Digest");
        sub.assert_contains(digest_val, "sha-512=:", "Has sha-512 SF prefix");

        let ok_verify = wing::verify_response_content_digest(res);
        sub.assert_true(ok_verify, "Response Content-Digest verifies against body");
    };

    t.run("Repr-Digest Generation & Verification") { sub =>
        var req = wing::Request {
            method: "PUT",
            url: "https://api.gateway.org/data",
            ..
        };
        req.body.clear();
        req.body.append("raw representation payload");

        let ok_set = wing::set_repr_digest(req, "sha-256");
        sub.assert_true(ok_set, "Repr-Digest set on request");

        let repr_val = req.header("Repr-Digest");
        sub.assert_contains(repr_val, "sha-256=:", "Has Repr-Digest header");

        let ok_verify = wing::verify_request_repr_digest(req);
        sub.assert_true(ok_verify, "Repr-Digest verifies against body");
    };
}

fn test_rfc9530_with_rfc9421_signatures(t: core::T&) {
    t.run("RFC 9421 Signature covering Content-Digest") { sub =>
        let seed: u8[32] = [
            0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80,
            0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
            0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00,
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        ];
        let pubkey = core::ed25519_public_key(seed);

        var req = wing::Request {
            method: "POST",
            url: "https://payment.bank.org/transfers",
            ..
        };
        req.body.clear();
        req.body.append("{\"amount\":1000,\"recipient\":\"alice\"}");
        wing::set_header(req, "content-type", "application/json");

        // 1. Add RFC 9530 Content-Digest
        wing::set_content_digest(req, "sha-256");

        // 2. Sign message including content-digest
        var params = wing::HttpSignatureParams {
            label: "sig1",
            key_id: "bank-key-1",
            alg: "ed25519",
            ..
        };
        params.components.push("@method");
        params.components.push("@authority");
        params.components.push("@path");
        params.components.push("content-type");
        params.components.push("content-digest");

        let ok_sign = wing::sign_http_request(req, params, seed[..]);
        sub.assert_true(ok_sign, "Request signed with RFC 9421 including Content-Digest");

        // 3. Verify digest and signature
        sub.assert_true(wing::verify_request_content_digest(req), "Content-Digest valid");
        sub.assert_true(wing::verify_http_signature(req, "sig1", params, pubkey[..]), "HTTP signature valid");

        // 4. Tampering body breaks Content-Digest
        req.body.clear();
        req.body.append("{\"amount\":999999,\"recipient\":\"mallory\"}");
        sub.assert_false(wing::verify_request_content_digest(req), "Tampered body breaks Content-Digest");
    };
}

fn test_oauth21_strict_pkce(t: core::T&) {
    t.run("OAuth 2.1 & RFC 9700 Strict PKCE Enforcement") { sub =>
        let verifier: const u8[:] = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";

        // S256 is accepted
        var s256_challenge: u8[..128] = [];
        let ok_s256 = wing::compute_code_challenge(verifier, "S256", s256_challenge);
        sub.assert_true(ok_s256, "S256 challenge computed");
        sub.assert_true(wing::is_valid_code_challenge_strict(s256_challenge[..], "S256"), "S256 valid under strict rules");
        sub.assert_true(wing::validate_code_challenge_strict(verifier, s256_challenge[..], "S256"), "S256 validates under strict rules");

        // plain is strictly rejected under OAuth 2.1 rules
        var plain_challenge: u8[..128] = [];
        wing::compute_code_challenge(verifier, "plain", plain_challenge);
        sub.assert_false(wing::is_valid_code_challenge_strict(plain_challenge[..], "plain"), "plain method rejected by strict challenge check");
        sub.assert_false(wing::validate_code_challenge_strict(verifier, plain_challenge[..], "plain"), "plain method rejected by strict validation");
    };
}

fn main() {
    var runner = core::new_runner("RFC 9530 Digest Fields & OAuth 2.1 PKCE Suite", core::Verbosity.Verbose);
    core::run_case(runner, "1. RFC 9530 Content-Digest & Repr-Digest", test_rfc9530_content_digest);
    core::run_case(runner, "2. RFC 9530 Binding to RFC 9421 Signatures", test_rfc9530_with_rfc9421_signatures);
    core::run_case(runner, "3. OAuth 2.1 Strict PKCE", test_oauth21_strict_pkce);
    let ok = core::finish(runner);
    assert(ok);
}
