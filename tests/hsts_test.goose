// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Verification suite for RFC 6797 HTTP Strict Transport Security (HSTS):
// 1. Header parsing (max-age, includeSubDomains, preload)
// 2. Static Preload List matcher (.dev, .app TLDs & major secure domains)
// 3. Dynamic HSTS Cache learning & pre-flight URL auto-upgrade (http:// -> https://)
// 4. Subdomain inheritance with `includeSubDomains`
// 5. Deletion of Known HSTS Host (`max-age=0`)
// 6. RFC 6797 Section 8.1 Security Invariant: Rejection of HSTS over insecure HTTP
import std;
import core from "..";
import wing from "..";

fn test_hsts_header_parsing(t: core::T&) {
    t.run("Parse max-age, includeSubDomains, and preload") { sub =>
        let raw = "max-age=31536000; includeSubDomains; preload";
        let d, ok = wing::parse_hsts_header(raw);
        sub.assert_true(ok, "hsts parsed successfully");
        sub.assert_eq(d.max_age_sec, 31536000, "max-age is 1 year in seconds");
        sub.assert_true(d.include_subdomains, "includeSubDomains is true");
        sub.assert_true(d.preload, "preload is true");

        // Case-insensitive and whitespace-tolerant
        let raw2 = "  includeSubDomains ;  MAX-AGE = 86400  ";
        let d2, ok2 = wing::parse_hsts_header(raw2);
        sub.assert_true(ok2, "case-insensitive hsts parsed");
        sub.assert_eq(d2.max_age_sec, 86400, "max-age 86400");
        sub.assert_true(d2.include_subdomains, "includeSubDomains matched");
        sub.assert_false(d2.preload, "preload not present");
    };
}

fn test_hsts_preload_list_auto_upgrade(t: core::T&) {
    t.run("Chromium Preload List: Google, GitHub & .dev/.app TLDs Auto-Upgraded to HTTPS") { sub =>
        var client = wing::new_client();

        // 1. Static preloaded domain (github.com)
        sub.assert_true(wing::is_hsts(client, "github.com"), "github.com is preloaded HSTS");
        sub.assert_true(wing::is_hsts(client, "api.github.com"), "api.github.com inherits HSTS");

        // 2. HSTS TLD (.dev and .app)
        sub.assert_true(wing::is_hsts(client, "myproject.dev"), ".dev TLD is always HSTS");
        sub.assert_true(wing::is_hsts(client, "coolservice.app"), ".app TLD is always HSTS");

        // 3. Regular non-HSTS domain
        sub.assert_false(wing::is_hsts(client, "example.com"), "example.com is not HSTS");

        // 4. Test pre-flight URL rewrite
        // Mock the HTTPS route
        wing::mock_route(client, "GET", "https://github.com/trending", 200, "{\"repos\":[]}");

        // Client initiates GET with http://github.com/trending
        let resp, err = wing::get(client, "http://github.com/trending");
        sub.assert_true(wing::ok(err), "request succeeded");
        sub.assert_eq(wing::status(resp), 200, "status 200");
        // Effective URL must be https://, not cleartext http://!
        sub.assert_bytes_eq(resp.effective_url[..8], "https://", "URL was transparently upgraded to https:// before dispatch");
    };
}

fn test_dynamic_hsts_cache_lifecycle(t: core::T&) {
    t.run("Dynamic Learning: Response Header Upgrades Subsequent Cleartext Requests") { sub =>
        var client = wing::new_client();
        wing::set_clock_us(client, 1700000000000000); // t0

        sub.assert_false(wing::is_hsts(client, "mycorp.internal"), "not HSTS initially");

        // 1. Visit HTTPS site which serves Strict-Transport-Security header
        wing::mock_route(client, "GET", "https://mycorp.internal/login", 200, "login-page");
        wing::add_mock_header(client, "Strict-Transport-Security", "max-age=3600; includeSubDomains");

        let resp1, err1 = wing::get(client, "https://mycorp.internal/login");
        sub.assert_true(wing::ok(err1), "initial https login ok");

        // Client has now recorded HSTS for mycorp.internal and its subdomains
        sub.assert_true(wing::is_hsts(client, "mycorp.internal"), "now known HSTS host");
        sub.assert_true(wing::is_hsts(client, "api.mycorp.internal"), "subdomain also protected");

        // 2. Next request: user enters plain http://mycorp.internal/dashboard
        wing::mock_route(client, "GET", "https://mycorp.internal/dashboard", 200, "dashboard-secure-content");

        let resp2, err2 = wing::get(client, "http://mycorp.internal/dashboard");
        sub.assert_true(wing::ok(err2), "dashboard request ok");
        sub.assert_bytes_eq(resp2.effective_url[..8], "https://", "http:// upgraded to https:// preventing SSL stripping");
        sub.assert_bytes_eq(resp2.body[..], "dashboard-secure-content", "secure content returned");
    };

    t.run("HSTS Deletion Directive (max-age=0)") { sub =>
        var client = wing::new_client();
        wing::set_clock_us(client, 1700000000000000);

        // Learn HSTS
        wing::mock_route(client, "GET", "https://service.org/start", 200, "ok");
        wing::add_mock_header(client, "Strict-Transport-Security", "max-age=7200");
        let _, _ = wing::get(client, "https://service.org/start");
        sub.assert_true(wing::is_hsts(client, "service.org"), "hsts active");

        // Server sends max-age=0 to revoke HSTS
        wing::mock_route(client, "GET", "https://service.org/revoke", 200, "revoked");
        wing::add_mock_header(client, "Strict-Transport-Security", "max-age=0");
        let _, _ = wing::get(client, "https://service.org/revoke");

        // Host must now be deleted from known HSTS hosts
        sub.assert_false(wing::is_hsts(client, "service.org"), "hsts revoked via max-age=0");
    };

    t.run("RFC 6797 Section 8.1 Security Invariant: Rejection Over Insecure HTTP") { sub =>
        var client = wing::new_client();
        wing::set_clock_us(client, 1700000000000000);

        // Insecure plain HTTP server tries to assert HSTS
        wing::mock_route(client, "GET", "http://insecure.test/page", 200, "insecure-page");
        wing::add_mock_header(client, "Strict-Transport-Security", "max-age=31536000");

        let _, _ = wing::get(client, "http://insecure.test/page");

        // RFC 6797 Section 8.1: Must be rejected and ignored!
        sub.assert_false(wing::is_hsts(client, "insecure.test"), "HSTS header ignored over plain HTTP");
    };
}

fn main() {
    var runner = core::new_runner("RFC 6797 HSTS & Automated Protocol Upgrade Suite", core::Verbosity.Verbose);
    core::run_case(runner, "1. HSTS Header Directive Parsing", test_hsts_header_parsing);
    core::run_case(runner, "2. Chromium Static Preload List & .dev/.app Auto-Upgrade", test_hsts_preload_list_auto_upgrade);
    core::run_case(runner, "3. Dynamic HSTS Cache Lifecycle, Subdomains & Security Invariants", test_dynamic_hsts_cache_lifecycle);
    let ok = core::finish(runner);
    assert(ok);
}
