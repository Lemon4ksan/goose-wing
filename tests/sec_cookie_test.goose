// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Tests for cookie security prefix enforcement and Max-Age bounds.
import std;
import core from "..";
import wing from "..";

// ----------------------------------------------------------------------------
// Round 1: RFC 6265bis Section 5.6 Insecure Cookie Protection
// ----------------------------------------------------------------------------
fn test_rfc6265bis_sec56_shadowing_protection(t: core::T&) {
    var clock = core::new_mock_clock();

    t.run("SEC-01: Insecure subpath must not shadow root secure cookie") { sub =>
        var j = wing::new_canonical_cookie_jar();
        // Set Secure cookie on HTTPS at root path "/"
        sub.require_true(wing::set_cookie_header(j, "https://example.com/", "session=secure_val; Secure; Path=/", clock.now_us));
        sub.assert_eq(j.cookies.len, 1);

        // Insecure HTTP request attempting to set cookie with same name on subpath "/login"
        let accepted = wing::set_cookie_header(j, "http://example.com/login", "session=insecure_val; Path=/login", clock.now_us);
        sub.assert_false(accepted, "Insecure HTTP Set-Cookie on subpath must be rejected when Secure cookie exists on root path");
        sub.assert_eq(j.cookies.len, 1, "Cookie store must retain only the Secure root cookie");
        sub.assert_gt(j.rejected_security_count, 0, "Security rejection counter must increment");
    };

    t.run("SEC-02: Insecure subdomain must not shadow parent domain secure cookie") { sub =>
        var j = wing::new_canonical_cookie_jar();
        // Set Secure domain cookie at parent domain "example.com"
        sub.require_true(wing::set_cookie_header(j, "https://example.com/", "auth=secure_val; Domain=example.com; Secure; Path=/", clock.now_us));
        sub.assert_eq(j.cookies.len, 1);

        // Insecure HTTP request from subdomain attempting to set cookie with same name
        let accepted = wing::set_cookie_header(j, "http://sub.example.com/", "auth=insecure_val; Domain=sub.example.com; Path=/", clock.now_us);
        sub.assert_false(accepted, "Insecure HTTP subdomain Set-Cookie must be rejected when parent domain has Secure cookie");
        sub.assert_eq(j.cookies.len, 1, "Cookie store must retain only the parent domain Secure cookie");
        sub.assert_gt(j.rejected_security_count, 0, "Security rejection counter must increment");
    };
}

// ----------------------------------------------------------------------------
// Round 2: Case-Insensitive Prefix Enforcement
// ----------------------------------------------------------------------------
fn test_case_insensitive_prefix_enforcement(t: core::T&) {
    var clock = core::new_mock_clock();

    t.run("PREFIX-01: Lowercase __secure- without Secure flag must be rejected") { sub =>
        var jar = wing::new_canonical_cookie_jar();
        let ok = wing::set_cookie_header(jar, "https://example.com/", "__secure-token=abc", clock.now_us);
        sub.assert_false(ok, "__secure- without Secure flag must be rejected");
        sub.assert_eq(jar.cookies.len, 0);
    };

    t.run("PREFIX-02: Lowercase __secure- on insecure HTTP channel must be rejected") { sub =>
        var jar = wing::new_canonical_cookie_jar();
        let ok = wing::set_cookie_header(jar, "http://example.com/", "__secure-token=abc; Secure", clock.now_us);
        sub.assert_false(ok, "__secure- on insecure HTTP must be rejected");
        sub.assert_eq(jar.cookies.len, 0);
    };

    t.run("PREFIX-03: Lowercase __host- with Domain attribute must be rejected") { sub =>
        var jar = wing::new_canonical_cookie_jar();
        let ok = wing::set_cookie_header(jar, "https://example.com/", "__host-token=abc; Secure; Path=/; Domain=example.com", clock.now_us);
        sub.assert_false(ok, "__host- with Domain attribute must be rejected");
        sub.assert_eq(jar.cookies.len, 0);
    };

    t.run("PREFIX-04: Lowercase __host- with non-root Path must be rejected") { sub =>
        var jar = wing::new_canonical_cookie_jar();
        let ok = wing::set_cookie_header(jar, "https://example.com/sub", "__host-token=abc; Secure; Path=/sub", clock.now_us);
        sub.assert_false(ok, "__host- with non-root path must be rejected");
        sub.assert_eq(jar.cookies.len, 0);
    };

    t.run("PREFIX-05: Lowercase __http- without HttpOnly must be rejected") { sub =>
        var jar = wing::new_canonical_cookie_jar();
        let ok = wing::set_cookie_header(jar, "https://example.com/", "__http-token=abc; Secure", clock.now_us);
        sub.assert_false(ok, "__http- without HttpOnly must be rejected");
        sub.assert_eq(jar.cookies.len, 0);
    };

    t.run("PREFIX-06: Nameless cookie with lowercase prefix value must be rejected") { sub =>
        var jar = wing::new_canonical_cookie_jar();
        var cookie = wing::new_canonical_cookie("", "__secure-val");
        let ok = wing::set_canonical_cookie(jar, cookie, true, true, clock.now_us);
        sub.assert_false(ok, "Nameless cookie starting with lowercase security prefix must be rejected");
        sub.assert_eq(jar.cookies.len, 0);
    };
}

// ----------------------------------------------------------------------------
// Round 3: Max-Age Capping and Overflow Protection
// ----------------------------------------------------------------------------
fn test_max_age_overflow_and_capping(t: core::T&) {
    var clock = core::new_mock_clock();
    let expected_cap_us = clock.now_us + internal::K_MAX_COOKIE_AGE_US;

    t.run("MAXAGE-01: Large Max-Age (10000000000000) must clamp to 400 days in jar") { sub =>
        var jar = wing::new_canonical_cookie_jar();
        let ok = wing::set_cookie_header(jar, "https://example.com/", "session=tok1; Max-Age=10000000000000", clock.now_us);
        sub.assert_true(ok, "Large Max-Age must be accepted into jar");
        sub.assert_eq(jar.cookies.len, 1, "Cookie with large Max-Age must be stored in jar");
        if jar.cookies.len > 0 {
            sub.assert_eq(jar.cookies[0].expires_utc, expected_cap_us, "Cookie expiration must be capped at 400 days");
            sub.assert_eq(jar.cookies[0].value[..], "tok1");
        }
    };

    t.run("MAXAGE-02: Direct parse_canonical_set_cookie with excessive Max-Age clamps to 400 days") { sub =>
        let cookie, cause, ok = wing::parse_canonical_set_cookie("token=val; Max-Age=10000000000000", "example.com", "/", clock.now_us);
        sub.assert_true(ok, "parse_canonical_set_cookie should succeed");
        sub.assert_true(cookie.persistent, "Cookie must be persistent");
        sub.assert_eq(cookie.expires_utc, expected_cap_us, "Excessive Max-Age must clamp to 400 days");
    };

    t.run("MAXAGE-03: Max-Age exceeding i64 max microseconds boundary") { sub =>
        var jar = wing::new_canonical_cookie_jar();
        let ok = wing::set_cookie_header(jar, "https://example.com/", "boundary=1; Max-Age=9223372036855", clock.now_us);
        sub.assert_true(ok, "Boundary Max-Age must be accepted");
        sub.assert_eq(jar.cookies.len, 1, "Boundary Max-Age cookie must be retained");
        if jar.cookies.len > 0 {
            sub.assert_eq(jar.cookies[0].expires_utc, expected_cap_us, "Boundary Max-Age must clamp to 400 days");
        }
    };

    t.run("MAXAGE-04: Reasonable Max-Age below 400 days remains unchanged") { sub =>
        var jar = wing::new_canonical_cookie_jar();
        let ok = wing::set_cookie_header(jar, "https://example.com/", "short=1; Max-Age=3600", clock.now_us);
        sub.assert_true(ok, "3600s Max-Age must be accepted");
        sub.assert_eq(jar.cookies.len, 1);
        if jar.cookies.len > 0 {
            sub.assert_eq(jar.cookies[0].expires_utc, clock.now_us + 3600000000, "1h Max-Age must be exactly 3600 seconds");
        }
    };

    t.run("MAXAGE-05: Non-positive Max-Age properly expires cookie") { sub =>
        let cookie, cause, ok = wing::parse_canonical_set_cookie("exp=0; Max-Age=0", "example.com", "/", clock.now_us);
        sub.assert_true(ok);
        sub.assert_true(cookie.persistent);
        sub.assert_eq(cookie.expires_utc, clock.now_us - 1000000, "Max-Age=0 expires immediately in the past");
    };
}

// ----------------------------------------------------------------------------
// Round 4: RFC 6265 Section 5.3 Step 11.2 HttpOnly Overwrite Protection
// ----------------------------------------------------------------------------
fn test_httponly_script_overwrite_protection(t: core::T&) {
    var clock = core::new_mock_clock();

    t.run("HTTPONLY-01: Non-HTTP script API must not overwrite existing HttpOnly cookie (RFC 6265 Sec 5.3 Step 11.2)") { sub =>
        var jar = wing::new_canonical_cookie_jar();
        // 1. HTTP API sets a sensitive HttpOnly session cookie
        sub.require_true(
            wing::set_cookie_header(jar, "https://example.com/", "session=super_secret_token; HttpOnly; Secure; Path=/", clock.now_us, true),
            "HTTP API must successfully store HttpOnly cookie",
        );
        sub.assert_eq(jar.cookies.len, 1);
        sub.assert_true(jar.cookies[0].httponly);
        sub.assert_bytes_eq(jar.cookies[0].value[..], "super_secret_token");

        // 2. Non-HTTP script API attempts to overwrite the HttpOnly cookie (e.g. via document.cookie)
        var script_cookie = wing::new_canonical_cookie("session", "attacker_controlled_value");
        script_cookie.with_domain("example.com", true).with_path("/").with_secure(true);
        let accepted = wing::set_canonical_cookie(jar, script_cookie, false, true, clock.now_us);

        sub.assert_false(accepted, "Non-HTTP API must NOT be allowed to overwrite an existing HttpOnly cookie");
        sub.assert_eq(jar.cookies.len, 1, "Cookie store must retain exactly 1 cookie");
        sub.assert_true(jar.cookies[0].httponly, "Existing cookie must retain HttpOnly flag");
        sub.assert_bytes_eq(jar.cookies[0].value[..], "super_secret_token", "HttpOnly cookie value must NOT be modified by script");
        sub.assert_gt(jar.rejected_security_count, 0, "rejected_security_count must be incremented");
    };

    t.run("HTTPONLY-02: Non-HTTP script API must not delete HttpOnly cookie via Max-Age=0 (RFC 6265 Sec 5.3 Step 11.2)") { sub =>
        var jar = wing::new_canonical_cookie_jar();
        sub.require_true(
            wing::set_cookie_header(jar, "https://example.com/", "auth=token123; HttpOnly; Secure; Path=/", clock.now_us, true),
        );
        sub.assert_eq(jar.cookies.len, 1);

        // Script attempts to purge the HttpOnly cookie using Max-Age=0
        var purge_cookie = wing::new_canonical_cookie("auth", "deleted");
        purge_cookie.with_domain("example.com", true).with_path("/").with_secure(true).with_max_age_seconds(0, clock.now_us);
        let accepted = wing::set_canonical_cookie(jar, purge_cookie, false, true, clock.now_us);

        sub.assert_false(accepted, "Non-HTTP API must NOT be allowed to delete an HttpOnly cookie via expired overwrite");
        sub.assert_eq(jar.cookies.len, 1, "HttpOnly cookie must not be deleted by script API");
        sub.assert_bytes_eq(jar.cookies[0].value[..], "token123");
    };
}

// ----------------------------------------------------------------------------
// Round 5: RFC 6265bis §5.5.7 SameSite=None and §5.1.3 Domain IP Invariants
// ----------------------------------------------------------------------------
fn test_rfc6265bis_samesite_and_domain_ip_rules(t: core::T&) {
    var clock = core::new_mock_clock();

    t.run("SAMESITE-01: parse_canonical_set_cookie rejects SameSite=None without Secure (RFC 6265bis §5.5.7)") { sub =>
        let cookie, cause, ok = wing::parse_canonical_set_cookie(
            "session=abc12345; SameSite=None; Path=/",
            "example.com",
            "/",
            clock.now_us,
        );
        sub.assert_false(ok, "SameSite=None without Secure must be rejected by parse_canonical_set_cookie");
    };

    t.run("SAMESITE-02: parse_canonical_set_cookie accepts SameSite=None with Secure (RFC 6265bis §5.5.7)") { sub =>
        let cookie, cause, ok = wing::parse_canonical_set_cookie(
            "session=abc12345; SameSite=None; Secure; Path=/",
            "example.com",
            "/",
            clock.now_us,
        );
        sub.assert_true(ok, "SameSite=None with Secure must be accepted");
        sub.assert_eq(cookie.same_site, wing::CookieSameSite.None);
        sub.assert_true(cookie.secure);
    };

    t.run("DOMAIN-IP-01: Domain matching cannot match subdomains against IP literal (RFC 6265 §5.1.3)") { sub =>
        var c = wing::new_canonical_cookie("test_ip", "val1");
        c.with_domain("192.168.1.1", false); // non-host-only domain cookie
        sub.assert_false(c.matches_domain("sub.192.168.1.1"), "Subdomain must not match IP address domain per RFC 6265 §5.1.3");
        sub.assert_true(c.matches_domain("192.168.1.1"), "Exact IP match must succeed");
    };

    t.run("DOMAIN-IP-02: IPv6 host with brackets matches unbracketed cookie domain") { sub =>
        var c = wing::new_canonical_cookie("test_ipv6", "val2");
        c.with_domain("2001:db8::1", true);
        sub.assert_true(c.matches_domain("[2001:db8::1]"), "IPv6 with brackets must match unbracketed cookie domain");
    };

    t.run("DOMAIN-DOT-01: FQDN multiple trailing dots normalize correctly") { sub =>
        var c = wing::new_canonical_cookie("test_dot", "val3");
        c.with_domain("example.com", false);
        sub.assert_true(c.matches_domain("example.com.."), "Host with multiple trailing dots must match");
    };
}

// ----------------------------------------------------------------------------
// Consolidated Suite Entry Point
// ----------------------------------------------------------------------------
fn main() {
    var runner = core::new_runner("Cookie Invariants Suite", core::Verbosity.Verbose);

    core::run_case(runner, "1. RFC 6265bis Section 5.6 Insecure Cookie Protection", test_rfc6265bis_sec56_shadowing_protection);
    core::run_case(runner, "2. Case-Insensitive Prefix Enforcement", test_case_insensitive_prefix_enforcement);
    core::run_case(runner, "3. Max-Age Capping and Overflow Protection", test_max_age_overflow_and_capping);
    core::run_case(runner, "4. RFC 6265 Section 5.3 Step 11.2 HttpOnly Overwrite Protection", test_httponly_script_overwrite_protection);
    core::run_case(runner, "5. RFC 6265bis SameSite=None and §5.1.3 Domain IP Invariants", test_rfc6265bis_samesite_and_domain_ip_rules);

    let ok = core::finish(runner);
    assert(ok);
}
