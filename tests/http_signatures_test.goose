// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Verification suite for RFC 9421 HTTP Message Signatures:
// - Component extraction (@method, @target-uri, @authority, @path, custom headers)
// - Canonical Signature Base string construction
// - Signature-Input RFC 8941 Structured Fields serialization
// - Signature header formatting with sf-binary :<base64>:
// - End-to-end request signing and cryptographic verification (HMAC-SHA256)
// - Rejection on tampered headers, modified method, or expired signatures
import std;
import core from "..";
import wing from "..";

fn test_http_signatures(t: core::T&) {
    t.run("Canonical Signature Base Construction (RFC 9421 §2.5)") { sub =>
        var req = wing::Request {
            method: "POST",
            url: "https://example.com/api/orders?status=active",
            ..
        };
        wing::set_header(req, "Content-Type", "application/json");
        wing::set_header(req, "Digest", "SHA-256=X48E9qOokqqrvdts8nOJRJN3OWDUoyWxBf7kbu9DBPE=");

        var params = wing::HttpSignatureParams {
            label: "sig1",
            key_id: "test-key-rsa-pss",
            alg: "hmac-sha256",
            created: 1618884475,
            ..
        };
        params.components.push("@method");
        params.components.push("@authority");
        params.components.push("@path");
        params.components.push("content-type");

        var sig_base: u8[>..] = [];
        let ok = wing::build_signature_base(req, params, sig_base);
        sub.assert_true(ok, "Signature base constructed");

        // Verify canonical elements
        sub.assert_contains(sig_base[..], "\"@method\": POST\n", "Contains @method");
        sub.assert_contains(sig_base[..], "\"@authority\": example.com\n", "Contains @authority");
        sub.assert_contains(sig_base[..], "\"@path\": /api/orders\n", "Contains @path");
        sub.assert_contains(sig_base[..], "\"content-type\": application/json\n", "Contains content-type");
        sub.assert_contains(sig_base[..], "\"@signature-params\": (\"@method\" \"@authority\" \"@path\" \"content-type\");created=1618884475;keyid=\"test-key-rsa-pss\";alg=\"hmac-sha256\"", "Contains @signature-params trailer");
    };

    t.run("End-to-End Signing and Verification") { sub =>
        var req = wing::Request {
            method: "GET",
            url: "https://api.bank.com/v1/accounts/12345",
            ..
        };
        wing::set_header(req, "Host", "api.bank.com");
        wing::set_header(req, "Accept", "application/json");

        var params = wing::HttpSignatureParams {
            label: "sig-bank",
            key_id: "k-prod-01",
            created: 1700000000,
            expires: 1700000300,
            ..
        };
        params.components.push("@method");
        params.components.push("@target-uri");
        params.components.push("accept");

        let key = "shared_secret_hmac_key_32_bytes!";

        let sign_ok = wing::sign_http_request(req, params, key);
        sub.assert_true(sign_ok, "Request signed successfully");

        // Verify headers attached
        sub.assert_true(req.has_header("Signature-Input"), "Signature-Input present");
        sub.assert_contains(req.header("Signature-Input"), "sig-bank=(\"@method\" \"@target-uri\" \"accept\")", "Signature-Input formatted");
        sub.assert_true(req.has_header("Signature"), "Signature present");
        sub.assert_contains(req.header("Signature"), "sig-bank=:", "Signature has sf-binary framing");

        // Verify signature valid
        let ver_ok = wing::verify_http_signature(req, "sig-bank", params, key, 1700000100);
        sub.assert_true(ver_ok, "Signature verification passed");

        // Verification fails if expired
        let ver_expired = wing::verify_http_signature(req, "sig-bank", params, key, 1700000500);
        sub.assert_false(ver_expired, "Expired signature rejected");

        // Verification fails if key is wrong
        let ver_wrong_key = wing::verify_http_signature(req, "sig-bank", params, "wrong_key_123456789012345678901", 1700000100);
        sub.assert_false(ver_wrong_key, "Tampered key rejected");

        // Verification fails if header was tampered
        req.headers[1].value.clear();
        req.headers[1].value.append("application/xml"); // changed accept
        let ver_tampered = wing::verify_http_signature(req, "sig-bank", params, key, 1700000100);
        sub.assert_false(ver_tampered, "Tampered header rejected");
    };

    t.run("RFC 9421 Timing Defense, Created/Expires Bounds & @query") { sub =>
        var req = wing::Request {
            method: "GET",
            url: "https://api.example.com/items?filter=active&sort=desc",
            ..
        };
        wing::set_header(req, "X-Custom", "  spaced   value  ");

        var params = wing::HttpSignatureParams {
            label: "sig1",
            created: 1700000000,
            expires: 1700000300,
            ..
        };
        params.components.push("@query");
        params.components.push("x-custom");

        var sig_base: u8[>..] = [];
        let ok_base = wing::build_signature_base(req, params, sig_base);
        sub.assert_true(ok_base, "Signature base with @query built");
        sub.assert_contains(sig_base[..], "\"@query\": ?filter=active&sort=desc\n", "Contains @query");
        sub.assert_contains(sig_base[..], "\"x-custom\": spaced value\n", "Whitespace trimmed and collapsed");

        let key = "hmac_key_test_secret_32_bytes!!";
        let sign_ok = wing::sign_http_request(req, params, key);
        sub.assert_true(sign_ok, "Request signed");

        // 1. Valid signature verifies
        let v_ok = wing::verify_http_signature(req, "sig1", params, key, 1700000100);
        sub.assert_true(v_ok, "Signature verified");

        // 2. Reject if created in future beyond clock skew
        let v_future = wing::verify_http_signature(req, "sig1", params, key, 1699999000);
        sub.assert_false(v_future, "Future creation rejected");

        // 3. Reject if created >= expires
        var bad_params = params;
        bad_params.created = 1700000500;
        bad_params.expires = 1700000400;
        let v_bad_exp = wing::verify_http_signature(req, "sig1", bad_params, key, 1700000450);
        sub.assert_false(v_bad_exp, "created >= expires rejected");

        // 4. Multiple signatures in dictionary & prefix isolation
        var multi_req = req;
        var multi_sig: u8[..512] = "sig1_prefix=:aW52YWxpZA==:, ";
        multi_sig.append(req.header("Signature"));
        wing::set_header(multi_req, "Signature", multi_sig[..]);

        let v_multi = wing::verify_http_signature(multi_req, "sig1", params, key, 1700000100);
        sub.assert_true(v_multi, "Dictionary member sig1 isolated from sig1_prefix");

        let v_prefix = wing::verify_http_signature(multi_req, "sig1_prefix", params, key, 1700000100);
        sub.assert_false(v_prefix, "Fake prefix signature rejected");
    };
}

fn test_ed25519_signatures(t: core::T&) {
    t.run("Ed25519 Asymmetric HTTP Signatures (RFC 9421 §3.2.2)") { sub =>
        var seed: u8[32] = [0; 32];
        for i in 32 { seed[i] = (i + 17) as u8; }
        let pub_key = core::ed25519_public_key(seed);

        var req = wing::Request {
            method: "POST",
            url: "https://api.gateway.org/transfers",
            ..
        };
        wing::set_header(req, "Content-Type", "application/json");
        wing::set_header(req, "Digest", "SHA-256=abcdef1234567890");

        var params = wing::HttpSignatureParams {
            label: "sig-ed",
            key_id: "ed25519-key-1",
            alg: "ed25519",
            created: 1700000000,
            ..
        };
        params.components.push("@method");
        params.components.push("@authority");
        params.components.push("content-type");

        let sign_ok = wing::sign_http_request(req, params, seed[..]);
        sub.assert_true(sign_ok, "Signed request with Ed25519");
        sub.assert_true(req.has_header("Signature-Input"), "Has Signature-Input");
        sub.assert_true(req.has_header("Signature"), "Has Signature");

        // Verification with public key
        let v_ok = wing::verify_http_signature(req, "sig-ed", params, pub_key[..], 1700000050);
        sub.assert_true(v_ok, "Ed25519 signature verified successfully");

        // Rejection on wrong public key
        var wrong_pub: u8[32] = [0xFF; 32];
        let v_wrong = wing::verify_http_signature(req, "sig-ed", params, wrong_pub[..], 1700000050);
        sub.assert_false(v_wrong, "Wrong public key rejected");

        // Rejection on tampered method
        var tampered_req = req;
        tampered_req.method.clear();
        tampered_req.method.append("PUT");
        let v_tampered = wing::verify_http_signature(tampered_req, "sig-ed", params, pub_key[..], 1700000050);
        sub.assert_false(v_tampered, "Tampered method rejected");
    };
}

fn test_response_signatures(t: core::T&) {
    t.run("HTTP Response Signatures with @status & ;req component chaining") { sub =>
        var req = wing::Request {
            method: "GET",
            url: "https://shop.com/orders/42",
            ..
        };
        wing::set_header(req, "X-Client-Id", "client-999");

        var res = wing::new_response();
        res.status_code = 200;
        res.set_header("Content-Type", "application/json");
        res.set_header("ETag", "\"v42-alpha\"");

        var params = wing::HttpSignatureParams {
            label: "res-sig",
            key_id: "res-key-01",
            alg: "hmac-sha256",
            created: 1700000100,
            ..
        };
        params.components.push("@status");
        params.components.push("etag");
        params.components.push("@method;req");

        let secret = "response_hmac_secret_32_bytes_!!";
        let sign_ok = wing::sign_http_response(res, req, params, secret);
        sub.assert_true(sign_ok, "Response signed");
        sub.assert_true(res.has_header("Signature-Input"), "Response has Signature-Input");
        sub.assert_true(res.has_header("Signature"), "Response has Signature");

        // Verify valid response signature
        let v_ok = wing::verify_http_response_signature(res, req, "res-sig", params, secret, 1700000110);
        sub.assert_true(v_ok, "Response signature verified");

        // Tamper status code (200 -> 404)
        var tampered_res = res;
        tampered_res.status_code = 404;
        let v_status_tampered = wing::verify_http_response_signature(tampered_res, req, "res-sig", params, secret, 1700000110);
        sub.assert_false(v_status_tampered, "Tampered response status code rejected");
    };
}

fn main() {
    var runner = core::new_runner("RFC 9421 HTTP Message Signatures Suite", core::Verbosity.Verbose);
    core::run_case(runner, "1. HTTP Message Signatures", test_http_signatures);
    core::run_case(runner, "2. Ed25519 Signatures", test_ed25519_signatures);
    core::run_case(runner, "3. Response Signatures", test_response_signatures);
    let ok = core::finish(runner);
    assert(ok);
}
