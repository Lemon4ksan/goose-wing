// Verification suite for RFC 7616 Digest Access Authentication, RFC 7617 Basic Authentication,
// 401 Authenticator Replay Loop, and AWS SigV4 Request Signing.
import std;
import core from "..";
import wing from "..";

fn test_rfc7616_official_ietf_vector(t: core::T&) {
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

fn test_401_authenticator_loop(t: core::T&) {
    t.run("Client Automatically Resolves 401 Challenge with RFC 7616 Digest") { sub =>
        var client = wing::new_client();
        wing::set_digest_credentials(client, "Mufasa", "Circle of Life");

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
        wing::set_basic_credentials(client, "admin", "secret123");

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
        wing::set_basic_credentials(client, "wrong_user", "wrong_pass");

        wing::mock_route(client, "GET", "https://api.corp.com/secure", 401, "invalid credentials");
        wing::add_mock_header(client, "WWW-Authenticate", "Basic realm=\"test\"");

        // If credentials fail, client retries once with Auth header, server still returns 401, and client stops cleanly!
        let resp, err = wing::get(client, "https://api.corp.com/secure");
        sub.assert_true(wing::ok(err), "no hang or crash");
        sub.assert_eq(wing::status(resp), 401, "401 status returned to caller");
    };
}

fn test_aws_sigv4_signing(t: core::T&) {
    t.run("AWS SigV4 Request Signing & Canonical Header Derivation") { sub =>
        let creds = wing::new_aws_credentials(
            "AKIAIOSFODNN7EXAMPLE",
            "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
            "us-east-1",
            "s3"
        );

        var req = wing::new_get("https://examplebucket.s3.amazonaws.com/test.txt");
        let dt = "20130524T000000Z";

        let signed = wing::sign_aws_sigv4(req, creds, dt);
        sub.assert_true(signed, "AWS SigV4 signed successfully");

        // Verify injected headers
        let amz_date = wing::header(req, "x-amz-date");
        sub.assert_bytes_eq(amz_date, dt, "x-amz-date header set");

        let amz_sha = wing::header(req, "x-amz-content-sha256");
        // Empty payload SHA-256
        sub.assert_bytes_eq(amz_sha, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", "Empty payload sha256 correct");

        let auth = wing::header(req, "Authorization");
        sub.assert_true(auth.len > 0, "Authorization header present");
        sub.assert_bytes_eq(auth[..17], "AWS4-HMAC-SHA256 ", "Algorithm identifier is AWS4-HMAC-SHA256");

        var has_cred = false;
        if auth.len >= 20 {
            for i in auth.len - 19 {
                if auth[i..i + 20] == "AKIAIOSFODNN7EXAMPLE" { has_cred = true; break; }
            }
        }
        sub.assert_true(has_cred, "Credential contains AccessKey");
    };
}

fn main() {
    var runner = core::new_runner("RFC 7616 Digest Access Authentication & AWS SigV4 Suite", core::Verbosity.Verbose);
    core::run_case(runner, "1. RFC 7616 Official IETF Test Vector & MD5 Fallback", test_rfc7616_official_ietf_vector);
    core::run_case(runner, "2. 401 Authenticator Replay Loop (Digest & Basic)", test_401_authenticator_loop);
    core::run_case(runner, "3. AWS SigV4 Request Signing", test_aws_sigv4_signing);
    let ok = core::finish(runner);
    assert(ok);
}
