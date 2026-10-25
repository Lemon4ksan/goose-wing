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
        wing::header(req, "Content-Type", "application/json");
        wing::header(req, "Digest", "SHA-256=X48E9qOokqqrvdts8nOJRJN3OWDUoyWxBf7kbu9DBPE=");

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
        wing::header(req, "Host", "api.bank.com");
        wing::header(req, "Accept", "application/json");

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
        var has_input = false;
        var has_sig = false;
        for &h in req.headers {
            if core::eq_ascii_fold(h.name[..], "Signature-Input") {
                has_input = true;
                sub.assert_contains(h.value[..], "sig-bank=(\"@method\" \"@target-uri\" \"accept\")", "Signature-Input formatted");
            }
            if core::eq_ascii_fold(h.name[..], "Signature") {
                has_sig = true;
                sub.assert_contains(h.value[..], "sig-bank=:", "Signature has sf-binary framing");
            }
        }
        sub.assert_true(has_input, "Signature-Input present");
        sub.assert_true(has_sig, "Signature present");

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
}

fn main() {
    var runner = core::new_runner("RFC 9421 HTTP Message Signatures Suite", core::Verbosity.Verbose);
    core::run_case(runner, "1. HTTP Message Signatures", test_http_signatures);
    let ok = core::finish(runner);
    assert(ok);
}
