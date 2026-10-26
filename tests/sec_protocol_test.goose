// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Tests for SSRF guard filtering, scheme downgrade sanitization, and URL resolution.
import std;
import core from "..";
import wing from "..";

// ----------------------------------------------------------------------------
// Round 1: IPv4-Mapped IPv6 SSRF Defense
// ----------------------------------------------------------------------------
fn test_ipv4_mapped_ipv6_ssrf(t: core::T&) {
    t.run("IPv4-Mapped IPv6 Loopback and Private Address SSRF Blocking") { sub =>
        var session = wing::new_session();
        wing::enable_ssrf_guard(session, true);

        // 1. IPv4-mapped loopback (127.0.0.1)
        var req_loop = wing::new_get("http://[::ffff:127.0.0.1]/admin");
        let res_loop, err_loop = wing::execute_request(session, req_loop);
        sub.assert_false(wing::ok(err_loop), "[::ffff:127.0.0.1] loopback must be blocked by SSRF guard");

        // 2. IPv4-mapped cloud metadata (169.254.169.254)
        var req_meta = wing::new_get("http://[::ffff:169.254.169.254]/latest/meta-data/");
        let res_meta, err_meta = wing::execute_request(session, req_meta);
        sub.assert_false(wing::ok(err_meta), "[::ffff:169.254.169.254] cloud metadata must be blocked by SSRF guard");

        // 3. IPv4-mapped RFC 1918 private subnet (10.0.0.1)
        var req_priv10 = wing::new_get("http://[::ffff:10.0.0.1]/internal");
        let res_priv10, err_priv10 = wing::execute_request(session, req_priv10);
        sub.assert_false(wing::ok(err_priv10), "[::ffff:10.0.0.1] private 10.x must be blocked by SSRF guard");

        // 4. IPv4-mapped RFC 1918 private subnet (192.168.1.1)
        var req_priv192 = wing::new_get("http://[::ffff:192.168.1.1]/router");
        let res_priv192, err_priv192 = wing::execute_request(session, req_priv192);
        sub.assert_false(wing::ok(err_priv192), "[::ffff:192.168.1.1] private 192.168.x must be blocked by SSRF guard");

        // 5. IPv4-mapped RFC 1918 private subnet (172.16.0.1)
        var req_priv172 = wing::new_get("http://[::ffff:172.16.0.1]/backend");
        let res_priv172, err_priv172 = wing::execute_request(session, req_priv172);
        sub.assert_false(wing::ok(err_priv172), "[::ffff:172.16.0.1] private 172.16.x must be blocked by SSRF guard");

        // 6. Direct hex-format IPv4-mapped loopback [::ffff:7f00:1]
        var req_hex_loop = wing::new_get("http://[::ffff:7f00:1]/status");
        let res_hex_loop, err_hex_loop = wing::execute_request(session, req_hex_loop);
        sub.assert_false(wing::ok(err_hex_loop), "[::ffff:7f00:1] hex loopback must be blocked by SSRF guard");

        // 7. Direct hex-format IPv4-mapped cloud metadata [::ffff:a9fe:a9fe]
        var req_hex_meta = wing::new_get("http://[::ffff:a9fe:a9fe]/meta");
        let res_hex_meta, err_hex_meta = wing::execute_request(session, req_hex_meta);
        sub.assert_false(wing::ok(err_hex_meta), "[::ffff:a9fe:a9fe] hex metadata must be blocked by SSRF guard");
    };

    t.run("DNS Rebinding with IPv4-Mapped IPv6 Resolved Address") { sub =>
        var session = wing::new_session();
        wing::enable_ssrf_guard(session, true);

        // Hostname resolves to IPv4-mapped loopback address
        wing::mock_route(session, "GET", "http://rebind.target.com/api", 200, "ok");
        wing::add_mock_resolved_ip(session, "::ffff:127.0.0.1");

        var req = wing::new_get("http://rebind.target.com/api");
        let res, err = wing::execute_request(session, req);
        sub.assert_false(wing::ok(err), "DNS rebinding with ::ffff:127.0.0.1 must be blocked");

        // Hostname resolves to hex IPv4-mapped loopback address ::ffff:7f00:1
        wing::mock_route(session, "GET", "http://rebind2.target.com/api", 200, "ok");
        wing::add_mock_resolved_ip(session, "::ffff:7f00:1");

        var req2 = wing::new_get("http://rebind2.target.com/api");
        let res2, err2 = wing::execute_request(session, req2);
        sub.assert_false(wing::ok(err2), "DNS rebinding with ::ffff:7f00:1 must be blocked");
    };
}

// ----------------------------------------------------------------------------
// Round 2: Scheme Downgrade Header Sanitization
// ----------------------------------------------------------------------------
fn test_scheme_downgrade_with_trusted_hosts(t: core::T&) {
    t.run("sanitize_headers_on_redirect: Scheme Downgrade to Trusted Host Strips Sensitive Headers") { sub =>
        var req = wing::new_get("https://example.com/secure");
        wing::header(req, "Authorization", "Basic YWxhZGRpbjpvcGVuc2VzYW1l");
        wing::header(req, "X-API-Key", "super-secret-token");
        wing::header(req, "Custom-Key", "public-data");

        let redirect_info = wing::compute_redirect_info(
            "GET", 302, "https://example.com/secure", "http://example.com/insecure",
            wing::ReferrerPolicy.NoReferrerWhenDowngrade, "https://example.com/secure",
            false, false
        );
        sub.assert_true(redirect_info.is_scheme_downgrade, "scheme downgrade detected");

        // When trusted_location_forwarding is true, scheme downgrade MUST STILL strip sensitive headers per RFC 9110
        wing::sanitize_headers_on_redirect(req.headers, redirect_info, false, false, true, true);

        var has_auth = false;
        var has_api_key = false;
        var has_custom = false;
        for hdr in req.headers {
            if core::eq_ascii_fold(hdr.name[..], "Authorization") { has_auth = true; }
            if core::eq_ascii_fold(hdr.name[..], "X-API-Key") { has_api_key = true; }
            if core::eq_ascii_fold(hdr.name[..], "Custom-Key") { has_custom = true; }
        }

        sub.assert_false(has_auth, "Authorization must be stripped on scheme downgrade even if host is trusted");
        sub.assert_false(has_api_key, "X-API-Key must be stripped on scheme downgrade even if host is trusted");
        sub.assert_true(has_custom, "Non-sensitive header Custom-Key is preserved");
    };

    t.run("ClientSession End-to-End: Scheme Downgrade to Trusted Host Strips Credentials") { sub =>
        var session = wing::new_session();
        wing::trust_location_host(session, "example.com");

        // Route 1: HTTPS endpoint redirects to HTTP on trusted host example.com
        wing::mock_route(session, "GET", "https://example.com/login", 302, "");
        wing::add_mock_header(session, "Location", "http://example.com/cleartext_api");

        // Route 2: Destination cleartext HTTP endpoint
        wing::mock_route(session, "GET", "http://example.com/cleartext_api", 200, "{\"ok\":true}");

        var req = wing::new_get("https://example.com/login");
        wing::header(req, "Authorization", "Bearer top_secret_credential");

        let res, err = wing::execute_request(session, req);
        sub.assert_true(wing::ok(err), "request succeeded");
        sub.assert_eq(res.status_code, 200, "final status 200");

        var sent_auth = false;
        for sent_hdr in res.sent_headers {
            if core::eq_ascii_fold(sent_hdr.name[..], "Authorization") {
                sent_auth = true;
            }
        }
        sub.assert_false(sent_auth, "Authorization header must not be sent over cleartext HTTP on scheme downgrade");
    };

    t.run("Cross-Origin HTTPS -> HTTPS to Trusted Host Preserves Credentials") { sub =>
        var req = wing::new_get("https://app.client.com/data");
        wing::header(req, "Authorization", "Bearer shared_token");

        // Cross-origin redirect, but both ends are secure HTTPS
        let redirect_info = wing::compute_redirect_info(
            "GET", 302, "https://app.client.com/data", "https://api.trusted.com/data",
            wing::ReferrerPolicy.StrictOriginWhenCrossOrigin, "https://app.client.com/data",
            false, false
        );
        sub.assert_true(redirect_info.is_cross_origin, "cross origin redirect");
        sub.assert_false(redirect_info.is_scheme_downgrade, "no scheme downgrade");

        // With trusted_location_forwarding = true on HTTPS -> HTTPS, credentials are preserved
        wing::sanitize_headers_on_redirect(req.headers, redirect_info, false, false, true, true);

        var has_auth = false;
        for hdr in req.headers {
            if core::eq_ascii_fold(hdr.name[..], "Authorization") { has_auth = true; }
        }
        sub.assert_true(has_auth, "Authorization is preserved for trusted cross-origin HTTPS -> HTTPS");
    };
}

// ----------------------------------------------------------------------------
// Round 3: File URL Windows Drive Compliance
// ----------------------------------------------------------------------------
fn test_file_url_windows_drive_compliance(t: core::T&) {
    t.run("WHATWG URL Section 4.4: Windows Drive Letter Pipe Normalization (| to :)") { sub =>
        // 1. file:///C|/... must normalize to file:///C:/...
        let u_pipe, err_pipe = core::parse_url("file:///C|/Users/admin/report.pdf");
        sub.assert_true(u_pipe.valid, "file:///C|/... is valid file url");
        sub.assert_bytes_eq(core::pathname(u_pipe), "/C:/Users/admin/report.pdf", "pathname normalized pipe to colon /C:/");
        sub.assert_bytes_eq(core::href(u_pipe), "file:///C:/Users/admin/report.pdf", "href normalized pipe to colon");

        // 2. Native file_path extraction succeeds on normalized drive letter
        var os_path: u8[..256] = [];
        let ok_path = core::file_path(u_pipe, os_path);
        sub.assert_true(ok_path, "file_path succeeded on pipe-normalized drive URL");
        sub.assert_bytes_eq(os_path[..], "C:\\Users\\admin\\report.pdf", "extracted native Windows backslash path");

        // 3. new_file_url with pipe notation C|\... normalizes to file:///C:/...
        let u_pipe_native = core::new_file_url("C|\\Projects\\app\\main.goose");
        sub.assert_true(u_pipe_native.valid, "new_file_url accepts C|\\ path");
        sub.assert_bytes_eq(core::pathname(u_pipe_native), "/C:/Projects/app/main.goose", "new_file_url normalized C| to /C:/");
    };

    t.run("WHATWG URL Section 4.4: Root-Relative Path Preserves Base Windows Drive Letter") { sub =>
        let base_file = core::new_url("file:///C:/Users/admin/app/index.html");
        sub.assert_true(base_file.valid, "base file URL is valid");

        // 1. Root-relative forward slash /assets/logo.png resolves to file:///C:/assets/logo.png
        let rel_slash = core::new_url("/assets/logo.png", base_file);
        sub.assert_true(rel_slash.valid, "resolved root-relative URL is valid");
        sub.assert_bytes_eq(core::href(rel_slash), "file:///C:/assets/logo.png", "drive letter C: preserved on root-relative /assets/logo.png");

        var path_slash: u8[..256] = [];
        let ok_slash = core::file_path(rel_slash, path_slash);
        sub.assert_true(ok_slash, "file_path succeeded on resolved root-relative URL");
        sub.assert_bytes_eq(path_slash[..], "C:\\assets\\logo.png", "extracted Windows path retains drive letter");

        // 2. Root-relative backslash \styles\app.css resolves to file:///C:/styles/app.css
        let rel_bs = core::new_url("\\styles\\app.css", base_file);
        sub.assert_true(rel_bs.valid, "resolved root-relative backslash URL is valid");
        sub.assert_bytes_eq(core::href(rel_bs), "file:///C:/styles/app.css", "drive letter C: preserved on root-relative \\styles\\app.css");

        var path_bs: u8[..256] = [];
        let ok_bs = core::file_path(rel_bs, path_bs);
        sub.assert_true(ok_bs, "file_path succeeded on backslash resolved URL");
        sub.assert_bytes_eq(path_bs[..], "C:\\styles\\app.css", "extracted Windows path from backslash retains drive letter");

        // 3. Explicit alternative drive letter in reference overrides base drive letter
        let rel_other = core::new_url("/D:/data/store.db", base_file);
        sub.assert_bytes_eq(core::href(rel_other), "file:///D:/data/store.db", "explicit drive D: overrides base drive C:");
    };
}

// ----------------------------------------------------------------------------
// Consolidated Suite Entry Point
// ----------------------------------------------------------------------------
fn main() {
    var runner = core::new_runner("Protocol Security Suite", core::Verbosity.Verbose);

    core::run_case(runner, "1. IPv4-Mapped IPv6 SSRF Defense", test_ipv4_mapped_ipv6_ssrf);
    core::run_case(runner, "2. Scheme Downgrade Header Sanitization", test_scheme_downgrade_with_trusted_hosts);
    core::run_case(runner, "3. File URL Windows Drive Compliance", test_file_url_windows_drive_compliance);

    let ok = core::finish(runner);
    assert(ok);
}
