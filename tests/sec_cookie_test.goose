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
// Round 6: RFC 6265 §5.3 Step 11.3 Creation-Time Preservation & §5.1.1 Date Lexer
// ----------------------------------------------------------------------------
fn test_rfc6265_creation_time_and_date_lexing(t: core::T&) {
    var clock = core::new_mock_clock();
    let t1 = clock.now_us;
    let t2 = clock.now_us + 10000000; // 10s later

    t.run("CREATION-01: Updating cookie with unset source_port preserves original creation_utc (RFC 6265 §5.3 Step 11.3)") { sub =>
        var jar = wing::new_canonical_cookie_jar();
        // 1. Initial cookie set via HTTP at t1 (source_port = 443)
        let ok1 = wing::set_cookie_header(jar, "https://example.com/", "session=initial_val; Secure; Path=/", t1);
        sub.require_true(ok1, "Initial cookie set must succeed");
        sub.assert_eq(jar.cookies.len, 1);
        sub.assert_eq(jar.cookies[0].creation_utc, t1);

        // 2. Cookie updated at t2 with new value and unset port (source_port = -1)
        var update_cookie = wing::new_canonical_cookie("session", "updated_val");
        update_cookie.with_domain("example.com", true).with_path("/").with_secure(true);
        let ok2 = wing::set_canonical_cookie(jar, update_cookie, true, true, t2);

        sub.assert_true(ok2, "Update must succeed");
        sub.assert_eq(jar.cookies.len, 1, "Cookie store must contain exactly 1 cookie after update");
        if jar.cookies.len > 0 {
            sub.assert_bytes_eq(jar.cookies[0].value[..], "updated_val", "Cookie value must be updated");
            sub.assert_eq(jar.cookies[0].creation_utc, t1, "RFC 6265 §5.3 Step 11.3: creation_utc MUST be preserved across updates");
            sub.assert_eq(jar.cookies[0].last_access_utc, t2, "last_access_utc must be updated to current time");
        }
    };

    t.run("CREATION-02: Updating cookie with case-different domain preserves creation_utc (RFC 6265 §5.3 Step 11.3)") { sub =>
        var jar = wing::new_canonical_cookie_jar();
        let ok1 = wing::set_cookie_header(jar, "https://example.com/", "auth=val1; Secure; Path=/", t1);
        sub.require_true(ok1);
        sub.assert_eq(jar.cookies[0].creation_utc, t1);

        var update_cookie = wing::new_canonical_cookie("auth", "val2");
        update_cookie.with_domain("EXAMPLE.COM", true).with_path("/").with_secure(true);
        let ok2 = wing::set_canonical_cookie(jar, update_cookie, true, true, t2);

        sub.assert_true(ok2);
        sub.assert_eq(jar.cookies.len, 1, "Must recognize collision across case-different domain");
        if jar.cookies.len > 0 {
            sub.assert_bytes_eq(jar.cookies[0].value[..], "val2");
            sub.assert_eq(jar.cookies[0].creation_utc, t1, "creation_utc must be preserved");
        }
    };

    t.run("LEX-MONTH-01: Date lexer rejects invalid month tokens like 'junk' or 'decay' (RFC 6265bis §5.1.1)") { sub =>
        let cookie1, cause1, ok1 = wing::parse_canonical_set_cookie(
            "test=1; Expires=Wed, 09 junk 2021 10:18:14 GMT",
            "example.com",
            "/",
            t1,
        );
        sub.assert_true(ok1);
        // Invalid month token causes Expires parsing to fail, so cookie remains non-persistent (session)
        sub.assert_false(cookie1.persistent, "Cookie with invalid month token must not be persistent");

        let cookie2, cause2, ok2 = wing::parse_canonical_set_cookie(
            "test=2; Expires=Wed, 09 decay 2021 10:18:14 GMT",
            "example.com",
            "/",
            t1,
        );
        sub.assert_true(ok2);
        sub.assert_false(cookie2.persistent, "Cookie with 'decay' month token must not be persistent");
    };

    t.run("LEX-MONTH-02: Date lexer accepts valid 3-letter and full month names (RFC 6265bis §5.1.1)") { sub =>
        let cookie_jun, _, ok_jun = wing::parse_canonical_set_cookie(
            "test=1; Expires=Wed, 09 Jun 2021 10:18:14 GMT",
            "example.com",
            "/",
            t1,
        );
        sub.assert_true(ok_jun);
        sub.assert_true(cookie_jun.persistent);

        let cookie_dec, _, ok_dec = wing::parse_canonical_set_cookie(
            "test=2; Expires=Wed, 09 December 2021 10:18:14 GMT",
            "example.com",
            "/",
            t1,
        );
        sub.assert_true(ok_dec);
        sub.assert_true(cookie_dec.persistent);
    };

    t.run("LEX-YEAR-01: 2-digit years map correctly: 70..99 -> 1970..1999, 00..69 -> 2000..2069 (RFC 6265 §5.1.1)") { sub =>
        let exp_94, ok_94 = wing::parse_cookie_date_us("Sunday, 06-Nov-94 08:49:37 GMT");
        sub.assert_true(ok_94);
        sub.assert_eq(exp_94, 784111777000000, "Year 94 must map to 1994");

        let exp_25, ok_25 = wing::parse_cookie_date_us("Sunday, 06-Nov-25 08:49:37 GMT");
        sub.assert_true(ok_25);
        sub.assert_eq(exp_25, 1762418977000000, "Year 25 must map to 2025");

        let exp_00, ok_00 = wing::parse_cookie_date_us("Sunday, 06-Nov-00 08:49:37 GMT");
        sub.assert_true(ok_00);
        sub.assert_eq(exp_00, 973500577000000, "Year 00 must map to 2000");

        let exp_69, ok_69 = wing::parse_cookie_date_us("Sunday, 06-Nov-69 08:49:37 GMT");
        sub.assert_true(ok_69);
        sub.assert_eq(exp_69, 3150953377000000, "Year 69 must map to 2069");

        let exp_70, ok_70 = wing::parse_cookie_date_us("Sunday, 06-Nov-70 08:49:37 GMT");
        sub.assert_true(ok_70);
        sub.assert_eq(exp_70, 26729377000000, "Year 70 must map to 1970");
    };

    t.run("PREFIX-PARSER: RFC 6265bis §5.6 Direct parser enforcement of __Secure-, __Host-, and nameless prefixes") { sub =>
        let now_us: i64 = 1700000000000000;

        // 1. __Secure- without Secure rejected
        let c1, _, ok1 = wing::parse_canonical_set_cookie("__Secure-id=123", "example.com", "/", now_us);
        sub.assert_false(ok1, "__Secure- without Secure rejected");

        // 2. __Secure- with Secure accepted
        let c2, _, ok2 = wing::parse_canonical_set_cookie("__Secure-id=123; Secure", "example.com", "/", now_us);
        sub.assert_true(ok2, "__Secure- with Secure accepted");

        // 3. __Host- without Secure rejected
        let c3, _, ok3 = wing::parse_canonical_set_cookie("__Host-id=123; Path=/", "example.com", "/", now_us);
        sub.assert_false(ok3, "__Host- without Secure rejected");

        // 4. __Host- with non-root Path rejected
        let c4, _, ok4 = wing::parse_canonical_set_cookie("__Host-id=123; Secure; Path=/sub", "example.com", "/sub", now_us);
        sub.assert_false(ok4, "__Host- with non-root Path rejected");

        // 5. Nameless cookie with __Host- value rejected
        let c5, _, ok5 = wing::parse_canonical_set_cookie("=__Host-bad", "example.com", "/", now_us);
        sub.assert_false(ok5, "Nameless cookie with __Host- value rejected");
    };
}

// ----------------------------------------------------------------------------
// Round 7: Cookie Hardening & Cross-Origin Single-Label Protection
// ----------------------------------------------------------------------------
fn test_cookie_hardening_invariants(t: core::T&) {
    let now_us: i64 = 1700000000000000;

    t.run("SEC-07: Single-label cross-origin domain injection must be rejected") { sub =>
        // evil.com attempting to set cookie for localhost
        let _, _, ok_lh = wing::parse_canonical_set_cookie("sid=hacked; Domain=localhost", "evil.com", "/", now_us);
        sub.assert_false(ok_lh, "evil.com must NOT set Domain=localhost cookie");

        // evil.com attempting to set cookie for intranet
        let _, _, ok_intra = wing::parse_canonical_set_cookie("sid=hacked; Domain=intranet", "evil.com", "/", now_us);
        sub.assert_false(ok_intra, "evil.com must NOT set Domain=intranet cookie");

        // localhost setting cookie on localhost itself is valid (converted to host-only)
        let c_lh, _, ok_lh_self = wing::parse_canonical_set_cookie("sid=ok; Domain=localhost", "localhost", "/", now_us);
        sub.assert_true(ok_lh_self, "localhost setting Domain=localhost must be accepted");
        sub.assert_true(c_lh.host_only, "localhost cookie must be forced host-only");
    };

    t.run("PSL-01: PSL Wildcard base domains must be recognized as public suffixes") { sub =>
        var db = wing::new_psl_database();
        wing::init_default_psl_rules(db);

        // kawasaki.jp is a wildcard rule pattern (*.kawasaki.jp) -> base domain is a public suffix
        sub.assert_true(wing::is_public_suffix(db, "kawasaki.jp"), "kawasaki.jp base domain must be public suffix");
        // compute.amazonaws.com is a wildcard rule (*.compute.amazonaws.com) -> base domain is a public suffix
        sub.assert_true(wing::is_public_suffix(db, "compute.amazonaws.com"), "compute.amazonaws.com base domain must be public suffix");
    };

    t.run("PREFIX-07: __Http- prefix requires Secure and HttpOnly in parser") { sub =>
        // __Http- without HttpOnly rejected
        let _, _, ok_no_http = wing::parse_canonical_set_cookie("__Http-tok=1; Secure", "example.com", "/", now_us);
        sub.assert_false(ok_no_http, "__Http- without HttpOnly must be rejected");

        // __Http- without Secure rejected
        let _, _, ok_no_sec = wing::parse_canonical_set_cookie("__Http-tok=1; HttpOnly", "example.com", "/", now_us);
        sub.assert_false(ok_no_sec, "__Http- without Secure must be rejected");

        // __Http- with both Secure and HttpOnly accepted
        let _, _, ok_valid = wing::parse_canonical_set_cookie("__Http-tok=1; Secure; HttpOnly", "example.com", "/", now_us);
        sub.assert_true(ok_valid, "__Http- with Secure and HttpOnly must be accepted");
    };

    t.run("BUILDER-01: with_domain and with_host lowercase domain") { sub =>
        var c1 = wing::new_canonical_cookie("a", "1");
        wing::with_domain(c1, "Example.COM");
        sub.assert_bytes_eq(c1.domain[..], "example.com");

        var c2 = wing::new_canonical_cookie("b", "2");
        wing::with_host(c2, "HOST.Local");
        sub.assert_bytes_eq(c2.domain[..], "host.local");
    };

    t.run("FILTER-01: Deletion filter strips leading dot in domain") { sub =>
        var jar = wing::new_canonical_cookie_jar();
        sub.require_true(wing::set_cookie_header(jar, "https://example.com/", "a=1; Domain=example.com", now_us));
        sub.assert_eq(jar.cookies.len, 1);

        var filter = wing::CookieDeletionInfo { .. };
        filter.domain.append(".example.com");
        let deleted = wing::delete_matching(jar, filter);
        sub.assert_eq(deleted, 1, "delete_matching must match despite leading dot in filter.domain");
        sub.assert_eq(jar.cookies.len, 0);
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
    core::run_case(runner, "6. RFC 6265 §5.3 Step 11.3 Creation-Time & §5.1.1 Date Lexer", test_rfc6265_creation_time_and_date_lexing);
    core::run_case(runner, "7. Cookie Hardening & Cross-Origin Single-Label Protection", test_cookie_hardening_invariants);

    let ok = core::finish(runner);
    assert(ok);
}
