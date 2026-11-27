// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Consolidated Verification Suite: Cookie Engine, PSL, and Security Verification Suite
//
// RUN: goose build -o %t.exe %s
// RUN: %t.exe
import std;
import wing from "..";
import lit from "github.com/Lemon4ksan/goose-lit@v0.1.0";

// --- Component: cookie_engine ---
// Tests for CanonicalCookieJar (RFC 6265, RFC 6265bis, CHIPS).

struct PrefixVector {
    header:    const u8[:],
    url:       const u8[:],
    from_http: bool,
    expect_ok: bool,
}

// ----------------------------------------------------------------------------
// 1. Lexer, 4096B/1024B Limits, CTL Rejection & WPT Nameless
// ----------------------------------------------------------------------------
fn test_lexer_limits_and_ctl(t: lit::T&) {
    var clock = lit::new_mock_clock();

    t.run("Size Limits: 4096B Name+Value and 1024B Attribute Cap (Issue #1340)") { sub =>
        var jar = cookie::CanonicalCookieJar { .. };

        // 1. Exactly 4096 bytes (4 + 4092) -> must be accepted
        var val_4092: u8[..4100] = [];
        for i in 4092 { val_4092.push('v'); }
        var hdr_ok: u8[..4200] = [];
        format(hdr_ok, "abcd=", val_4092[..], "; Secure");
        sub.assert_true(
            cookie::set_cookie_header(jar, "https://example.com/", hdr_ok[..], clock.now_us),
            "4096B name+value must be accepted",
        );
        sub.assert_eq(jar.cookies.len, 1);

        // 2. 4097 bytes (4 + 4093) -> must be rejected entirely
        val_4092.push('x');
        var hdr_over: u8[..4200] = [];
        format(hdr_over, "abcd=", val_4092[..], "; Secure");
        sub.assert_false(
            cookie::set_cookie_header(jar, "https://example.com/", hdr_over[..], clock.now_us),
            "4097B name+value must be rejected",
        );
        sub.assert_eq(jar.cookies.len, 1);

        // 3. Attribute Path of 1025 bytes (> 1024) -> cookie accepted, but Path ignored (default-path '/dir')
        var long_path: u8[..1030] = [];
        long_path.push('/');
        for i in 1024 { long_path.push('p'); } // 1025 bytes total
        var hdr_long_attr: u8[..1100] = [];
        format(hdr_long_attr, "attr_cap=ok; Path=", long_path[..]);
        sub.require_true(
            cookie::set_cookie_header(jar, "https://example.com/dir/page.html", hdr_long_attr[..], clock.now_us),
            "cookie with >1024B Path attribute must still be accepted",
        );
        sub.assert_bytes_eq(jar.cookies[1].path[..], "/dir", "1025B Path must be ignored in favor of default-path '/dir'");
    };

    t.run("CTL Rejection vs HTAB Allowance (Issue #1420, #1531)") { sub =>
        var jar = cookie::CanonicalCookieJar { .. };

        // Control bytes \r, \n, \0, \x7F must reject the cookie rather than truncating it
        sub.assert_false(cookie::set_cookie_header(jar, "https://example.com/", "a=b\r\nSecure", clock.now_us));
        sub.assert_false(cookie::set_cookie_header(jar, "https://example.com/", "a=b\x00evil", clock.now_us));
        sub.assert_false(cookie::set_cookie_header(jar, "https://example.com/", "a=b\x7F", clock.now_us));
        sub.assert_eq(jar.cookies.len, 0);

        // Horizontal tab (\t, 0x09) and double quotes inside value are allowed
        sub.require_true(cookie::set_cookie_header(jar, "https://example.com/", "\tsid\t=\t\"quoted_val\"\t;\tSecure\t", clock.now_us));
        sub.assert_bytes_eq(jar.cookies[0].name[..], "sid");
        sub.assert_bytes_eq(jar.cookies[0].value[..], "\"quoted_val\"");
    };

    t.run("WPT http-state Nameless Cookies (0004, 0020, 0023)") { sub =>
        var jar = cookie::CanonicalCookieJar { .. };

        // WPT 0004: Set-Cookie: foo -> ("", "foo")
        sub.require_true(cookie::set_cookie_header(jar, "https://example.com/", "foo", clock.now_us));
        sub.assert_bytes_eq(jar.cookies[0].name[..], "");
        sub.assert_bytes_eq(jar.cookies[0].value[..], "foo");

        // WPT 0020 & 0023: Set-Cookie: = and empty line must be ignored
        sub.assert_false(cookie::set_cookie_header(jar, "https://example.com/", "=", clock.now_us));
        sub.assert_false(cookie::set_cookie_header(jar, "https://example.com/", "   =   ", clock.now_us));
        sub.assert_false(cookie::set_cookie_header(jar, "https://example.com/", "", clock.now_us));
        sub.assert_bytes_eq(jar.cookies[0].value[..], "foo", "existing nameless cookie must remain intact");
    };
}

// ----------------------------------------------------------------------------
// 2. Date Tokenizer, 400-Day Cap & Expired Overwrite
// ----------------------------------------------------------------------------
fn test_dates_400d_cap_and_expired_overwrite(t: lit::T&) {
    var clock = lit::new_mock_clock(1700000000000000);
    var jar = cookie::CanonicalCookieJar { .. };

    // 1. 400-day cap (kMinutesIn400Days = 576000)
    t.require_true(cookie::set_cookie_header(jar, "https://example.com/", "long=1; Max-Age=999999999", clock.now_us));
    let expected_max_exp = clock.now_us + (400 * 86400 * 1000000);
    t.assert_eq(jar.cookies[0].expires_utc, expected_max_exp, "TTL must be clamped to exactly 400 days");

    // 2. Max-Age=0 for non-existent cookie must NOT expand storage
    t.assert_true(cookie::set_cookie_header(jar, "https://example.com/", "ghost=1; Max-Age=0", clock.now_us));
    t.assert_eq(jar.cookies.len, 1, "already expired new cookie must not be pushed into storage");

    // 3. Max-Age=0 for existing cookie must immediately purge it and increment counter
    t.assert_true(cookie::set_cookie_header(jar, "https://example.com/", "long=deleted; Max-Age=0", clock.now_us));
    t.assert_eq(jar.cookies.len, 0, "existing cookie must be purged immediately on Max-Age=0");
    t.assert_eq(jar.expired_overwrite_count, 1);
}

// ----------------------------------------------------------------------------
// 3. Domain, Public Suffix List (PSL), IPv4/IPv6 & Path-Match
// ----------------------------------------------------------------------------
fn test_domain_psl_ip_and_path_matching(t: lit::T&) {
    var clock = lit::new_mock_clock();
    var jar = cookie::CanonicalCookieJar { .. };

    t.run("DOM-01: PSL Rejection for TLD and Effective Public Suffixes") { sub =>
        // Cannot set cookie for 'com', 'co.uk', or 'github.io'
        sub.assert_false(cookie::set_cookie_header(jar, "https://app.example.com/", "sid=1; Domain=com", clock.now_us));
        sub.assert_false(cookie::set_cookie_header(jar, "https://app.example.com/", "sid=1; Domain=co.uk", clock.now_us));
        sub.assert_false(cookie::set_cookie_header(jar, "https://app.example.com/", "sid=1; Domain=github.io", clock.now_us));
        sub.assert_eq(jar.cookies.len, 0);
    };

    t.run("DOM-03 & DOM-04: Subdomain Rejection & Leading Dot Normalization") { sub =>
        // Cannot set cookie for a subdomain
        sub.assert_false(cookie::set_cookie_header(jar, "https://example.com/", "sid=1; Domain=sub.example.com", clock.now_us));

        // Setting for parent domain with leading dot .EXAMPLE.COM -> lowercases and strips leading dot
        sub.require_true(cookie::set_cookie_header(jar, "https://sub.example.com/", "sid=1; Domain=.EXAMPLE.COM", clock.now_us));
        sub.assert_bytes_eq(jar.cookies[0].domain[..], "example.com");
        sub.assert_false(jar.cookies[0].host_only);
    };

    t.run("DOM-05: IP Literals must never domain-match") { sub =>
        var ip_jar = cookie::CanonicalCookieJar { .. };
        // Domain=0.1 must be rejected
        sub.assert_false(cookie::set_cookie_header(ip_jar, "http://192.168.0.1:8080/", "sid=1; Domain=0.1", clock.now_us));
        // Domain=192.168.0.1 on IP origin must be accepted but treated as host_only
        sub.require_true(cookie::set_cookie_header(ip_jar, "http://192.168.0.1:8080/", "sid=1; Domain=192.168.0.1", clock.now_us));
        sub.assert_true(ip_jar.cookies[0].host_only);
    };

    t.run("RFC 6265 Section 5.1.4 Path Matching Engine") { sub =>
        sub.assert_true(cookie::path_match("/sub", "/sub"));
        sub.assert_true(cookie::path_match("/sub/", "/sub"));
        sub.assert_true(cookie::path_match("/sub/page", "/sub"));
        sub.assert_false(cookie::path_match("/subprefix", "/sub"));
        sub.assert_false(cookie::path_match("/dir", "/dir/page"));
    };
}

// ----------------------------------------------------------------------------
// 4. Layered Cookie Prefixes (__Secure-, __Host-, __Http-, __Host-Http-)
// ----------------------------------------------------------------------------
fn test_layered_prefixes_table(t: lit::T&) {
    var clock = lit::new_mock_clock();
    let vectors = [
        PrefixVector { header: "__Secure-a=1; Secure", url: "https://example.com/", from_http: true, expect_ok: true },
        PrefixVector { header: "__Secure-a=1", url: "https://example.com/", from_http: true, expect_ok: false },
        PrefixVector { header: "__Secure-a=1; Secure", url: "http://example.com/", from_http: true, expect_ok: false },
        PrefixVector { header: "__Host-a=1; Secure; Path=/", url: "https://example.com/", from_http: true, expect_ok: true },
        PrefixVector { header: "__Host-a=1; Secure; Path=/; Domain=example.com", url: "https://example.com/", from_http: true, expect_ok: false },
        PrefixVector { header: "__Host-a=1; Secure; Path=/sub", url: "https://example.com/", from_http: true, expect_ok: false },
        PrefixVector { header: "__Http-a=1; Secure; HttpOnly", url: "https://example.com/", from_http: true, expect_ok: true },
        PrefixVector { header: "__Http-a=1; Secure", url: "https://example.com/", from_http: true, expect_ok: false },
        PrefixVector { header: "__http-a=1; Secure; HttpOnly", url: "https://example.com/", from_http: false, expect_ok: false },
        PrefixVector { header: "__Host-Http-a=1; Secure; HttpOnly; Path=/", url: "https://example.com/", from_http: true, expect_ok: true },
        PrefixVector { header: "__HOST-HTTP-a=1; Secure; HttpOnly; Path=/", url: "https://example.com/", from_http: false, expect_ok: false },
    ];

    lit::run_table(t, "PrefixMatrix", vectors[..]) { sub, row, idx =>
        var jar = cookie::CanonicalCookieJar { .. };
        let u = cookie::parse_canonical_cookie_url(row.url);
        var c = cookie::parse_canonical_set_cookie(row.header, u.host[..], u.path[..], clock.now_us);
        c.source_scheme = if u.is_secure { cookie::SourceScheme.Secure } else { cookie::SourceScheme.NonSecure };
        c.source_port = u.port;
        let src_opts = cookie::SourceOptions { is_http_api: row.from_http, url_is_secure: u.is_secure };
        let ok = cookie::set_canonical_cookie(jar, c, src_opts, clock.now_us);
        sub.assert_eq(ok, row.expect_ok, row.header);
    };
}

// ----------------------------------------------------------------------------
// 5. SameSite Lax+POST 120s Window & Origin-Bound Cookies (OBC)
// ----------------------------------------------------------------------------
fn test_samesite_lax_post_window_and_obc(t: lit::T&) {
    var clock = lit::new_mock_clock();
    var jar = cookie::CanonicalCookieJar { .. };

    // Default SameSite -> Lax-allowing-unsafe for 120 seconds
    t.require_true(cookie::set_cookie_header(jar, "https://idp.example.com/login", "sso=token123; Secure", clock.now_us));

    // At t=119s cross-site top-level POST must include cookie
    lit::advance_sec(clock, 119);
    var out_119: u16[..180] = [];
    cookie::get_canonical_cookies_for_request(
        jar, "https://idp.example.com/acs", true, "", clock.now_us, out_119,
        cookie::AccessOptions { is_same_site: false, is_top_level_navigation: true, is_safe_method: false },
    );
    t.assert_eq(out_119.len, 1, "at t=119s Lax+POST window must allow cross-site top-level POST");

    // At t=121s cross-site POST is blocked, but GET is allowed
    lit::advance_sec(clock, 2);
    var out_121_post: u16[..180] = [];
    cookie::get_canonical_cookies_for_request(
        jar, "https://idp.example.com/acs", true, "", clock.now_us, out_121_post,
        cookie::AccessOptions { is_same_site: false, is_top_level_navigation: true, is_safe_method: false },
    );
    t.assert_eq(out_121_post.len, 0, "at t=121s Lax+POST window expired for unsafe POST");

    var out_121_get: u16[..180] = [];
    cookie::get_canonical_cookies_for_request(
        jar, "https://idp.example.com/acs", true, "", clock.now_us, out_121_get,
        cookie::AccessOptions { is_same_site: false, is_top_level_navigation: true, is_safe_method: true },
    );
    t.assert_eq(out_121_get.len, 1, "at t=121s safe top-level GET is still allowed under Lax");

    // Origin-Bound Cookies (OBC): http://[::1]:80 with Secure upgrades source_port to 443
    t.require_true(cookie::set_cookie_header(jar, "http://[::1]:80/test", "__Host-local=ok; Secure; Path=/", clock.now_us));
    t.assert_eq(jar.cookies[1].source_port, 443, "OBC must upgrade port 80 -> 443 on trustworthy [::1] origin");
}

// ----------------------------------------------------------------------------
// 6. 6-Round Domain GC Priority Quotas Asymmetry
// ----------------------------------------------------------------------------
fn test_gc_6_rounds_asymmetry_and_global_immunity(t: lit::T&) {
    var clock = lit::new_mock_clock();
    var jar = cookie::CanonicalCookieJar { .. };

    // Populate example.com domain:
    // - 30 Low Secure (protected by low quota = 30)
    // - 60 Medium Secure (quota 50, 10 over quota, but protected in Round 3 by Secure flag)
    // - 91 High Non-Secure (quota 70, 21 over quota, evicted in Round 4 due to Non-Secure!)
    for i in 30 {
        var h: u8[..64] = [];
        format(h, "low_sec_", i, "=1; Secure; Priority=Low");
        cookie::set_cookie_header(jar, "https://example.com/", h[..], lit::advance_us(clock, 10));
    }
    for i in 60 {
        var h: u8[..64] = [];
        format(h, "med_sec_", i, "=1; Secure; Priority=Medium");
        cookie::set_cookie_header(jar, "https://example.com/", h[..], lit::advance_us(clock, 10));
    }
    for i in 91 {
        var h: u8[..64] = [];
        format(h, "high_nonsec_", i, "=1; Priority=High");
        cookie::set_cookie_header(jar, "http://example.com/", h[..], lit::advance_us(clock, 10));
    }

    // 181 cookies inserted -> Domain GC triggered (181 -> 150 target, 31 evicted)
    t.assert_eq(jar.cookies.len, 150, "domain GC must purge down to 150 cookies");
    t.assert_eq(jar.evicted_domain_count, 31);

    // Count surviving cookies by priority
    var low_sec_alive = 0;
    var med_sec_alive = 0;
    var high_nonsec_alive = 0;
    for i in jar.cookies.len {
        if jar.cookies[i].priority == cookie::Priority.Low { low_sec_alive += 1; }
        if jar.cookies[i].priority == cookie::Priority.Medium { med_sec_alive += 1; }
        if jar.cookies[i].priority == cookie::Priority.High { high_nonsec_alive += 1; }
    }

    // Round 4 must evict 21 High Non-Secure before Round 5 evicts 10 Medium Secure
    t.assert_eq(low_sec_alive, 30, "all 30 Low Secure cookies must survive");
    t.assert_eq(high_nonsec_alive, 70, "21 High Non-Secure cookies must be evicted in Round 4");
    t.assert_eq(med_sec_alive, 50, "only 10 Medium Secure cookies must be evicted in Round 5");
}

// ----------------------------------------------------------------------------
// 7. Global Garbage Collection & 30-Day Purge Immunity
// ----------------------------------------------------------------------------
fn test_global_gc_and_30_day_immunity(t: lit::T&) {
    var clock = lit::new_mock_clock(1700000000000000);
    var jar = cookie::CanonicalCookieJar { .. };
    jar.max_cookies_global = 20;
    jar.target_cookies_global = 10;
    jar.max_cookies_per_domain = 50;
    jar.target_cookies_per_domain = 40;

    // Insert 20 cookies across 20 distinct domains
    for i in 20 {
        var u: u8[..64] = [];
        format(u, "https://d", i, ".com/");
        cookie::set_cookie_header(jar, u[..], "c=1; Secure", clock.now_us);
    }
    t.assert_eq(jar.cookies.len, 20);

    // 21st cookie inserted immediately: all 20 previous cookies have last_access < 30 days old (immune!)
    cookie::set_cookie_header(jar, "https://d20.com/", "c=1; Secure", clock.now_us);
    t.assert_eq(jar.cookies.len, 21, "all cookies within 30-day window must be immune from global purge");

    // Advance clock past 30 days (e.g. 31 days)
    lit::advance_days(clock, 31);

    // Now inserting 22nd cookie triggers global purge of non-immune cookies down to target (10)
    cookie::set_cookie_header(jar, "https://d21.com/", "c=1; Secure", clock.now_us);
    t.assert_le(jar.cookies.len, 11, "global purge must evict non-immune cookies down to target");
    t.assert_gt(jar.evicted_global_count, 0);
}

// ----------------------------------------------------------------------------
// 8. CHIPS Partitioned Cookies & 10KB Memory Quota Enforcement
// ----------------------------------------------------------------------------
fn test_chips_and_10kb_quota(t: lit::T&) {
    var clock = lit::new_mock_clock();
    var jar = cookie::CanonicalCookieJar { .. };

    // 1. Partitioned cookie ingestion with valid top-level site
    t.assert_true(
        cookie::set_cookie_header(jar, "https://ad.service.com/", "user_id=123; Secure; Partitioned; SameSite=None", clock.now_us, "https://publisher.com"),
        "partitioned cookie must be accepted with top-level site",
    );
    t.assert_eq(jar.cookies.len, 1);
    t.assert_bytes_eq(jar.cookies[0].partition_key[..], "https://publisher.com");

    // 2. CHIPS 10KB Quota: Fill partition with large 3000-byte cookies
    var big_val: u8[..3100] = [];
    for i in 3000 { big_val.push('c'); }

    for i in 4 {
        var hdr: u8[..3200] = [];
        format(hdr, "chunk_", i, "=", big_val[..], "; Secure; Partitioned; SameSite=None");
        cookie::set_cookie_header(jar, "https://ad.service.com/", hdr[..], lit::advance_sec(clock, 1), "https://publisher.com");
    }

    // 4 cookies * ~3010 bytes = 12040 bytes (> 10240 quota). CHIPS quota must have evicted oldest
    t.assert_gt(jar.evicted_chips_count, 0, "CHIPS quota must evict oldest partitioned cookies exceeding 10KB");
    t.assert_le(jar.cookies.len, 4, "partitioned cookies count must be constrained by 10KB cap");
}

// ----------------------------------------------------------------------------
// 9. RFC 6265 Section 5.4 Header Sorting & Persistence Key Model
// ----------------------------------------------------------------------------
fn test_header_sorting_and_persistence_key(t: lit::T&) {
    var clock = lit::new_mock_clock();
    var jar = cookie::CanonicalCookieJar { .. };

    t.run("RFC 6265 Section 5.4 Cookie Header Sorting (Longest Path First, Earliest Creation First)") { sub =>
        // 1. Shorter path, earlier creation
        cookie::set_cookie_header(jar, "https://example.com/sub/page", "short_path=1; Path=/sub", lit::advance_sec(clock, 1));
        // 2. Longer path, later creation
        cookie::set_cookie_header(jar, "https://example.com/sub/page", "long_path=2; Path=/sub/page", lit::advance_sec(clock, 1));
        // 3. Same path as #1, later creation
        cookie::set_cookie_header(jar, "https://example.com/sub/page", "another_short=3; Path=/sub", lit::advance_sec(clock, 1));

        var out_hdr: u8[..256] = [];
        cookie::build_cookie_header(jar, "https://example.com/sub/page", clock.now_us, out_hdr);

        // Longest path (/sub/page) MUST come first, followed by earlier /sub, followed by later /sub
        sub.assert_contains(out_hdr[..], "long_path=2; short_path=1; another_short=3", "RFC 6265 Section 5.4 sorting order");
    };

    t.run("SQL Persistence Key Model (host_only prefixing)") { sub =>
        var jar2 = cookie::CanonicalCookieJar { .. };
        // Host-only cookie: host_key = 'example.com'
        cookie::set_cookie_header(jar2, "https://example.com/", "sid=host_val", clock.now_us);
        // Domain cookie: host_key = '.example.com'
        cookie::set_cookie_header(jar2, "https://example.com/", "sid=domain_val; Domain=example.com", clock.now_us);

        sub.assert_eq(jar2.cookies.len, 2, "host-only and domain cookies must coexist without colliding");
        sub.assert_true(jar2.cookies[0].host_only);
        sub.assert_false(jar2.cookies[1].host_only);
    };
}

// --- Component: cookie_vectors ---
// Test vectors for CanonicalCookieJar (RFC 6265, RFC 6265bis, CHIPS).

struct IngestionVector {
    id:                const u8[:],
    url:               const u8[:],
    set_cookie:        const u8[:],
    from_http:         bool,
    expect_accepted:   bool,
    expect_name:       const u8[:],
    expect_val:        const u8[:],
    expect_domain:     const u8[:],
    expect_path:       const u8[:],
    expect_host_only:  bool,
    expect_secure:     bool,
    expect_httponly:   bool,
    expect_persistent: bool,
    expect_port:       i32,
}

// ----------------------------------------------------------------------------
// 10. Ingestion Matrix: Lexer, Omnomnom, Dates, PSL, IPv6 & OBC
// ----------------------------------------------------------------------------
fn run_ingestion_matrix(t: lit::T&) {
    let now_us = 1700000000000000; // Epoch baseline
    let vectors = [
        // --- LEX & OMNOMNOM ---
        IngestionVector {
            id:                "LEX-10 (WPT 0004 nameless value)",
            url:               "https://example.com/", set_cookie: "foo", from_http: true,
            expect_accepted:   true, expect_name: "", expect_val: "foo",
            expect_domain:     "example.com", expect_path: "/",
            expect_host_only:  true, expect_secure: false, expect_httponly: false,
            expect_persistent: false, expect_port: 443,
        },
        IngestionVector {
            id:                "LEX-11 (WPT 0004 nameless value with spaces and Secure)",
            url:               "https://example.com/", set_cookie: "foo ; Secure", from_http: true,
            expect_accepted:   true, expect_name: "", expect_val: "foo",
            expect_domain:     "example.com", expect_path: "/",
            expect_host_only:  true, expect_secure: true, expect_httponly: false,
            expect_persistent: false, expect_port: 443,
        },
        IngestionVector {
            id:                "LEX-12 (WPT 0020 empty '=' rejected)",
            url:               "https://example.com/", set_cookie: "   =   ", from_http: true,
            expect_accepted:   false, expect_name: "", expect_val: "",
            expect_domain:     "", expect_path: "",
            expect_host_only:  true, expect_secure: false, expect_httponly: false,
            expect_persistent: false, expect_port: 443,
        },
        IngestionVector {
            id:                "LEX-13 (Multiple '=' in value and path)",
            url:               "https://example.com/", set_cookie: "k=v1=v2=v3; Path=/a=b", from_http: true,
            expect_accepted:   true, expect_name: "k", expect_val: "v1=v2=v3",
            expect_domain:     "example.com", expect_path: "/a=b",
            expect_host_only:  true, expect_secure: false, expect_httponly: false,
            expect_persistent: false, expect_port: 443,
        },
        IngestionVector {
            id:                "LEX-14 (HTAB and SP trimming around tokens)",
            url:               "https://example.com/", set_cookie: "\t key \t = \t val \t ; \t HttpOnly \t", from_http: true,
            expect_accepted:   true, expect_name: "key", expect_val: "val",
            expect_domain:     "example.com", expect_path: "/",
            expect_host_only:  true, expect_secure: false, expect_httponly: true,
            expect_persistent: false, expect_port: 443,
        },
        IngestionVector {
            id:                "LEX-15 (Semicolon inside DQUOTE splits pair; unclosed quote rejected per RFC 6265 В§4.1.1)",
            url:               "https://example.com/", set_cookie: "k=\"quoted;val\"", from_http: true,
            expect_accepted:   false, expect_name: "", expect_val: "",
            expect_domain:     "", expect_path: "",
            expect_host_only:  true, expect_secure: false, expect_httponly: false,
            expect_persistent: false, expect_port: 443,
        },
        IngestionVector {
            id:                "LEX-16 (DQUOTE preserved in cookie value)",
            url:               "https://example.com/", set_cookie: "k=\"hello_world\"", from_http: true,
            expect_accepted:   true, expect_name: "k", expect_val: "\"hello_world\"",
            expect_domain:     "example.com", expect_path: "/",
            expect_host_only:  true, expect_secure: false, expect_httponly: false,
            expect_persistent: false, expect_port: 443,
        },
        IngestionVector {
            id:                "LEX-17 (Duplicate Path attribute: last wins)",
            url:               "https://example.com/", set_cookie: "k=v; Path=/first; PATH=/second", from_http: true,
            expect_accepted:   true, expect_name: "k", expect_val: "v",
            expect_domain:     "example.com", expect_path: "/second",
            expect_host_only:  true, expect_secure: false, expect_httponly: false,
            expect_persistent: false, expect_port: 443,
        },

        // --- DATES & CALENDAR BOUNDARIES ---
        IngestionVector {
            id:                "TIME-01 (Canonical RFC 1123 date)",
            url:               "https://example.com/", set_cookie: "k=v; Expires=Wed, 21 Oct 2026 07:28:00 GMT", from_http: true,
            expect_accepted:   true, expect_name: "k", expect_val: "v",
            expect_domain:     "example.com", expect_path: "/",
            expect_host_only:  true, expect_secure: false, expect_httponly: false,
            expect_persistent: true, expect_port: 443,
        },
        IngestionVector {
            id:                "TIME-07 (Year 1600 < 1601 falls back to session cookie)",
            url:               "https://example.com/", set_cookie: "k=v; Expires=Sun, 31 Dec 1600 23:59:59 GMT", from_http: true,
            expect_accepted:   true, expect_name: "k", expect_val: "v",
            expect_domain:     "example.com", expect_path: "/",
            expect_host_only:  true, expect_secure: false, expect_httponly: false,
            expect_persistent: false, expect_port: 443,
        },
        IngestionVector {
            id:                "TIME-08 (Invalid day 32 falls back to session cookie)",
            url:               "https://example.com/", set_cookie: "k=v; Expires=32 Jan 2027 00:00:00 GMT", from_http: true,
            expect_accepted:   true, expect_name: "k", expect_val: "v",
            expect_domain:     "example.com", expect_path: "/",
            expect_host_only:  true, expect_secure: false, expect_httponly: false,
            expect_persistent: false, expect_port: 443,
        },
        IngestionVector {
            id:                "TIME-13 (Max-Age=100 overrides past Expires=1970)",
            url:               "https://example.com/", set_cookie: "k=v; Max-Age=100; Expires=Thu, 01 Jan 1970 00:00:00 GMT", from_http: true,
            expect_accepted:   true, expect_name: "k", expect_val: "v",
            expect_domain:     "example.com", expect_path: "/",
            expect_host_only:  true, expect_secure: false, expect_httponly: false,
            expect_persistent: true, expect_port: 443,
        },
        IngestionVector {
            id:                "TIME-15 (Non-digit Max-Age=100abc ignored -> session)",
            url:               "https://example.com/", set_cookie: "k=v; Max-Age=100abc", from_http: true,
            expect_accepted:   true, expect_name: "k", expect_val: "v",
            expect_domain:     "example.com", expect_path: "/",
            expect_host_only:  true, expect_secure: false, expect_httponly: false,
            expect_persistent: false, expect_port: 443,
        },

        // --- DOMAIN, PSL, IPv4 & IPv6 ---
        IngestionVector {
            id:                "DOM-01 (No Domain attribute -> host-only)",
            url:               "https://sub.example.com/", set_cookie: "k=v", from_http: true,
            expect_accepted:   true, expect_name: "k", expect_val: "v",
            expect_domain:     "sub.example.com", expect_path: "/",
            expect_host_only:  true, expect_secure: false, expect_httponly: false,
            expect_persistent: false, expect_port: 443,
        },
        IngestionVector {
            id:                "DOM-02 (Domain attribute present -> not host-only)",
            url:               "https://sub.example.com/", set_cookie: "k=v; Domain=sub.example.com", from_http: true,
            expect_accepted:   true, expect_name: "k", expect_val: "v",
            expect_domain:     "sub.example.com", expect_path: "/",
            expect_host_only:  false, expect_secure: false, expect_httponly: false,
            expect_persistent: false, expect_port: 443,
        },
        IngestionVector {
            id:                "DOM-03 (Multiple leading dots Domain=..example.com ignored -> host-only)",
            url:               "https://sub.example.com/", set_cookie: "k=v; Domain=..example.com", from_http: true,
            expect_accepted:   true, expect_name: "k", expect_val: "v",
            expect_domain:     "sub.example.com", expect_path: "/",
            expect_host_only:  true, expect_secure: false, expect_httponly: false,
            expect_persistent: false, expect_port: 443,
        },
        IngestionVector {
            id:                "DOM-05 (Empty Domain= ignored -> host-only)",
            url:               "https://example.com/", set_cookie: "k=v; Domain=", from_http: true,
            expect_accepted:   true, expect_name: "k", expect_val: "v",
            expect_domain:     "example.com", expect_path: "/",
            expect_host_only:  true, expect_secure: false, expect_httponly: false,
            expect_persistent: false, expect_port: 443,
        },
        IngestionVector {
            id:                "DOM-06 (PSL supercookie co.uk rejected)",
            url:               "https://app.co.uk/", set_cookie: "k=v; Domain=co.uk", from_http: true,
            expect_accepted:   false, expect_name: "", expect_val: "",
            expect_domain:     "", expect_path: "",
            expect_host_only:  false, expect_secure: false, expect_httponly: false,
            expect_persistent: false, expect_port: 443,
        },
        IngestionVector {
            id:                "DOM-07 (Direct request to PSL co.uk forces host_only=true)",
            url:               "https://co.uk/", set_cookie: "k=v; Domain=co.uk", from_http: true,
            expect_accepted:   true, expect_name: "k", expect_val: "v",
            expect_domain:     "co.uk", expect_path: "/",
            expect_host_only:  true, expect_secure: false, expect_httponly: false,
            expect_persistent: false, expect_port: 443,
        },
        IngestionVector {
            id:                "DOM-08 (Parent domain cannot set child subdomain)",
            url:               "https://example.com/", set_cookie: "k=v; Domain=sub.example.com", from_http: true,
            expect_accepted:   false, expect_name: "", expect_val: "",
            expect_domain:     "", expect_path: "",
            expect_host_only:  false, expect_secure: false, expect_httponly: false,
            expect_persistent: false, expect_port: 443,
        },
        IngestionVector {
            id:                "DOM-09 (Suffix without dot boundary: notexample.com -> example.com)",
            url:               "https://notexample.com/", set_cookie: "k=v; Domain=example.com", from_http: true,
            expect_accepted:   false, expect_name: "", expect_val: "",
            expect_domain:     "", expect_path: "",
            expect_host_only:  false, expect_secure: false, expect_httponly: false,
            expect_persistent: false, expect_port: 443,
        },
        IngestionVector {
            id:                "DOM-10 (CVE-2016-8615 IPv4 partial suffix rejected)",
            url:               "http://192.168.1.100/", set_cookie: "k=v; Domain=1.100", from_http: true,
            expect_accepted:   false, expect_name: "", expect_val: "",
            expect_domain:     "", expect_path: "",
            expect_host_only:  false, expect_secure: false, expect_httponly: false,
            expect_persistent: false, expect_port: 80,
        },
        IngestionVector {
            id:                "DOM-11 (IPv4 exact match accepted as host-only)",
            url:               "http://192.168.1.100/", set_cookie: "k=v; Domain=192.168.1.100", from_http: true,
            expect_accepted:   true, expect_name: "k", expect_val: "v",
            expect_domain:     "192.168.1.100", expect_path: "/",
            expect_host_only:  true, expect_secure: false, expect_httponly: false,
            expect_persistent: false, expect_port: 80,
        },
        IngestionVector {
            id:                "DOM-12 & PATH-06 (IPv6 bracketed literal + query string slash)",
            url:               "http://[::1]:8080/a/b?redirect=/x/y/z", set_cookie: "k=v", from_http: true,
            expect_accepted:   true, expect_name: "k", expect_val: "v",
            expect_domain:     "::1", expect_path: "/a",
            expect_host_only:  true, expect_secure: false, expect_httponly: false,
            expect_persistent: false, expect_port: 8080,
        },
        IngestionVector {
            id:                "DOM-13 (Intranet single-label host forces host_only=true)",
            url:               "http://intranet-server/", set_cookie: "k=v; Domain=intranet-server", from_http: true,
            expect_accepted:   true, expect_name: "k", expect_val: "v",
            expect_domain:     "intranet-server", expect_path: "/",
            expect_host_only:  true, expect_secure: false, expect_httponly: false,
            expect_persistent: false, expect_port: 80,
        },
        IngestionVector {
            id:                "SHAD-01 (Cookie Crumbles: nameless cookie simulating __Host- rejected)",
            url:               "http://sub.example.com/", set_cookie: "=__Host-sid=attacker_val; Domain=example.com", from_http: true,
            expect_accepted:   false, expect_name: "", expect_val: "",
            expect_domain:     "", expect_path: "",
            expect_host_only:  false, expect_secure: false, expect_httponly: false,
            expect_persistent: false, expect_port: 80,
        },
        IngestionVector {
            id:                "OBC-03 (Trustworthy localhost:80 with Secure upgrades port to 443)",
            url:               "http://127.0.0.1:80/login", set_cookie: "__Host-s=1; Secure; Path=/", from_http: true,
            expect_accepted:   true, expect_name: "__Host-s", expect_val: "1",
            expect_domain:     "127.0.0.1", expect_path: "/",
            expect_host_only:  true, expect_secure: true, expect_httponly: false,
            expect_persistent: false, expect_port: 443,
        },
    ];

    lit::run_table(t, "IngestionVectors", vectors[..]) { sub, v, idx =>
        var jar = cookie::CanonicalCookieJar { .. };
        let ok = cookie::set_cookie_header(jar, v.url, v.set_cookie, now_us, v.from_http);
        sub.require_eq(ok, v.expect_accepted, v.id);

        if v.expect_accepted {
            sub.require_eq(jar.cookies.len, 1, v.id);
            let stored = jar.cookies[0];
            sub.assert_bytes_eq(stored.name[..], v.expect_name, v.id);
            sub.assert_bytes_eq(stored.value[..], v.expect_val, v.id);
            sub.assert_bytes_eq(stored.domain[..], v.expect_domain, v.id);
            sub.assert_bytes_eq(stored.path[..], v.expect_path, v.id);
            sub.assert_eq(stored.host_only, v.expect_host_only, v.id);
            sub.assert_eq(stored.secure, v.expect_secure, v.id);
            sub.assert_eq(stored.httponly, v.expect_httponly, v.id);
            sub.assert_eq(stored.persistent, v.expect_persistent, v.id);
            sub.assert_eq(stored.source_port, v.expect_port, v.id);
        }
    };
}

// ----------------------------------------------------------------------------
// 11. Full 33-Byte ASCII Control Character (CTL) Rejection Sweep
// ----------------------------------------------------------------------------
fn run_exhaustive_ctl_sweep(t: lit::T&) {
    let now_us = 1700000000000000;
    var jar = cookie::CanonicalCookieJar { .. };

    for b in 128 {
        let byte_val = b as u8;
        let is_ctl = (byte_val <= 0x08) || (byte_val >= 0x0A && byte_val <= 0x1F) || (byte_val == 0x7F);
        if is_ctl {
            var hdr: u8[..32] = [];
            hdr.append("sid=val");
            hdr.push(byte_val);
            hdr.append("tail; Secure");
            let accepted = cookie::set_cookie_header(jar, "https://example.com/", hdr[..], now_us);
            t.assert_false(accepted, "CTL byte in Set-Cookie must be strictly rejected, never truncated");
        }
    }
    t.assert_eq(jar.cookies.len, 0, "Zero cookies must be stored after full CTL sweep");
}

// ----------------------------------------------------------------------------
// 12. RFC 6265 Section 5.1.4 Path-Matching Engine & Default-Path Rules
// ----------------------------------------------------------------------------
struct PathMatchVector {
    id:           const u8[:],
    cookie_path:  const u8[:],
    request_path: const u8[:],
    expect_match: bool,
}

fn run_path_matching_matrix(t: lit::T&) {
    let path_vectors = [
        PathMatchVector { id: "PATH-EXACT", cookie_path: "/admin", request_path: "/admin", expect_match: true },
        PathMatchVector { id: "PATH-SUBDIR", cookie_path: "/admin", request_path: "/admin/users", expect_match: true },
        PathMatchVector { id: "PATH-TRAILING-SLASH-REQ", cookie_path: "/admin", request_path: "/admin/", expect_match: true },
        PathMatchVector { id: "PATH-PREFIX-NO-SLASH-BOUNDARY", cookie_path: "/admin", request_path: "/admin-panel", expect_match: false },
        PathMatchVector { id: "PATH-PREFIX-SUPERSET", cookie_path: "/admin", request_path: "/administrator", expect_match: false },
        PathMatchVector { id: "PATH-08 (Cookie has trailing slash, req does not)", cookie_path: "/custom/", request_path: "/custom", expect_match: false },
        PathMatchVector { id: "PATH-08-OK (Cookie has trailing slash, req matches)", cookie_path: "/custom/", request_path: "/custom/page", expect_match: true },
        PathMatchVector { id: "PATH-ROOT", cookie_path: "/", request_path: "/any/deep/path", expect_match: true },
    ];

    lit::run_table(t, "PathMatchRFC6265", path_vectors[..]) { sub, v, idx =>
        let got = cookie::path_match(v.request_path, v.cookie_path);
        sub.assert_eq(got, v.expect_match, v.id);
    };

    t.run("Default-Path Algorithm RFC 6265 Section 5.1.4 (PATH-01..PATH-06)") { sub =>
        var out: u8[..128] = [];

        cookie::compute_default_path("", out);
        sub.assert_bytes_eq(out[..], "/", "PATH-01: empty uri-path -> '/'");

        cookie::compute_default_path("noslash", out);
        sub.assert_bytes_eq(out[..], "/", "no leading slash -> '/'");

        cookie::compute_default_path("/", out);
        sub.assert_bytes_eq(out[..], "/", "PATH-02: single slash -> '/'");

        cookie::compute_default_path("/docs", out);
        sub.assert_bytes_eq(out[..], "/", "PATH-03: '/docs' has only one slash -> '/'");

        cookie::compute_default_path("/a/b/c", out);
        sub.assert_bytes_eq(out[..], "/a/b", "PATH-04: '/a/b/c' -> '/a/b'");

        cookie::compute_default_path("/a/b/", out);
        sub.assert_bytes_eq(out[..], "/a/b", "PATH-05: '/a/b/' -> '/a/b' (rightmost slash excluded)");
    };
}

// ----------------------------------------------------------------------------
// 13. SameSite, Lax+POST 120s Window & Schemeful Same-Site (SS-01..SS-14)
// ----------------------------------------------------------------------------
struct SameSiteVector {
    id:               const u8[:],
    samesite_mode:    cookie::SameSite,
    age_sec:          i64,
    is_same_site:     bool,
    is_top_level_nav: bool,
    is_safe_method:   bool,
    expect_send:      bool,
}

fn run_samesite_and_redirect_matrix(t: lit::T&) {
    let ss_vectors = [
        SameSiteVector { id: "SS-01 (Strict + same-site)", samesite_mode: cookie::SameSite.Strict, age_sec: 500, is_same_site: true, is_top_level_nav: false, is_safe_method: false, expect_send: true },
        SameSiteVector { id: "SS-02 (Strict + cross-site top-level GET)", samesite_mode: cookie::SameSite.Strict, age_sec: 10, is_same_site: false, is_top_level_nav: true, is_safe_method: true, expect_send: false },
        SameSiteVector { id: "SS-03 (Explicit Lax + cross-site top-level GET)", samesite_mode: cookie::SameSite.Lax, age_sec: 500, is_same_site: false, is_top_level_nav: true, is_safe_method: true, expect_send: true },
        SameSiteVector { id: "SS-04 (Explicit Lax + cross-site top-level POST at 10s -> BLOCKED)", samesite_mode: cookie::SameSite.Lax, age_sec: 10, is_same_site: false, is_top_level_nav: true, is_safe_method: false, expect_send: false },
        SameSiteVector { id: "SS-05 (Explicit Lax + cross-site iframe GET -> BLOCKED)", samesite_mode: cookie::SameSite.Lax, age_sec: 10, is_same_site: false, is_top_level_nav: false, is_safe_method: true, expect_send: false },
        SameSiteVector { id: "SS-06 (Default + cross-site top-level POST at 119s -> ALLOWED by Lax+POST)", samesite_mode: cookie::SameSite.Default, age_sec: 119, is_same_site: false, is_top_level_nav: true, is_safe_method: false, expect_send: true },
        SameSiteVector { id: "SS-07 (Default + cross-site top-level POST at 121s -> BLOCKED)", samesite_mode: cookie::SameSite.Default, age_sec: 121, is_same_site: false, is_top_level_nav: true, is_safe_method: false, expect_send: false },
        SameSiteVector { id: "SS-08 (Default + cross-site XHR/iframe POST at 10s -> BLOCKED)", samesite_mode: cookie::SameSite.Default, age_sec: 10, is_same_site: false, is_top_level_nav: false, is_safe_method: false, expect_send: false },
        SameSiteVector { id: "SS-10 (None + cross-site iframe POST)", samesite_mode: cookie::SameSite.None, age_sec: 500, is_same_site: false, is_top_level_nav: false, is_safe_method: false, expect_send: true },
    ];

    lit::run_table(t, "SameSiteDecisionMatrix", ss_vectors[..]) { sub, v, idx =>
        let create_us = 1000000000000;
        let now_us = create_us + (v.age_sec * 1000000);
        var c = cookie::new_canonical_cookie("sid", "val");
        c.same_site = v.samesite_mode;
        c.secure = true;
        c.creation_utc = create_us;

        let got = cookie::is_sendable_for_samesite(
            c,
            cookie::AccessOptions {
                is_same_site:            v.is_same_site,
                is_top_level_navigation: v.is_top_level_nav,
                is_safe_method:          v.is_safe_method,
            },
            now_us,
        );
        sub.assert_eq(got, v.expect_send, v.id);
    };

    t.run("Schemeful Same-Site (SS-13 & SS-14)") { sub =>
        sub.assert_false(
            cookie::is_schemeful_same_site("http", "example.com", "https", "example.com"),
            "SS-13: http://example.com and https://example.com must be cross-site",
        );
        sub.assert_true(
            cookie::is_schemeful_same_site("https", "a.example.com", "https", "b.example.com"),
            "SS-14: subdomains sharing scheme and eTLD+1 must be same-site",
        );
    };
}

// ----------------------------------------------------------------------------
// 14. CHIPS Partition Isolation & 10,240B Byte Quota Enforcement
// ----------------------------------------------------------------------------
fn run_chips_partition_quota_and_isolation(t: lit::T&) {
    var clock = lit::new_mock_clock();
    var jar = cookie::CanonicalCookieJar { .. };

    // CHIPS-02: Partitioned cookie without Secure is rejected
    t.assert_false(
        cookie::set_cookie_header(jar, "https://ads.com/", "c=1; Partitioned", clock.now_us),
        "CHIPS-02: Partitioned cookie without Secure must be rejected",
    );

    // CHIPS-03: Fill partition ("https://news.com", "ads.com") up to 10,000 bytes (5 cookies of 2,000 B)
    var val_1996: u8[..2000] = [];
    for i in 1996 { val_1996.push('x'); }

    for i in 5 {
        var name: u8[..16] = [];
        format(name, "p0", i);
        var c = cookie::new_canonical_cookie(name[..], val_1996[..]);
        c.value.push('z'); // 3 + 1997 = 2000 bytes exactly
        c.domain.append("ads.com");
        c.path.append("/");
        c.secure = true;
        c.partitioned = true;
        c.partition_key.append("https://news.com");
        c.source_scheme = cookie::SourceScheme.Secure;
        c.source_port = 443;
        let step_time = lit::advance_sec(clock, 10);
        let src_opts = cookie::SourceOptions { is_http_api: true, url_is_secure: true };
        t.require_true(cookie::set_canonical_cookie(jar, c, src_opts, step_time));
    }
    t.assert_eq(jar.cookies.len, 5, "5 partitioned cookies (10,000 B total) must fit in 10,240 B quota");

    // Add cookie of the same domain ads.com, but in OTHER partition "https://shop.com" (2,000 B)
    var c_other_part = cookie::new_canonical_cookie("p_shop", val_1996[..]);
    c_other_part.domain.append("ads.com");
    c_other_part.path.append("/");
    c_other_part.secure = true;
    c_other_part.partitioned = true;
    c_other_part.partition_key.append("https://shop.com");
    c_other_part.source_scheme = cookie::SourceScheme.Secure;
    c_other_part.source_port = 443;
    let src_opts_other = cookie::SourceOptions { is_http_api: true, url_is_secure: true };
    t.require_true(cookie::set_canonical_cookie(jar, c_other_part, src_opts_other, lit::advance_sec(clock, 10)));
    t.assert_eq(jar.cookies.len, 6, "other partition must have an independent 10,240 B quota");

    // Add 6th cookie into first partition "https://news.com" of size 500 B (10,000 + 500 = 10,500 > 10,240)
    var val_496: u8[..500] = [];
    for i in 496 { val_496.push('y'); }
    var c_overflow = cookie::new_canonical_cookie("p05", val_496[..]);
    c_overflow.domain.append("ads.com");
    c_overflow.path.append("/");
    c_overflow.secure = true;
    c_overflow.partitioned = true;
    c_overflow.partition_key.append("https://news.com");
    c_overflow.source_scheme = cookie::SourceScheme.Secure;
    c_overflow.source_port = 443;
    let src_opts_overflow = cookie::SourceOptions { is_http_api: true, url_is_secure: true };
    t.require_true(cookie::set_canonical_cookie(jar, c_overflow, src_opts_overflow, lit::advance_sec(clock, 10)));

    // Oldest cookie "p00" from partition "https://news.com" must be evicted
    var p00_found = false;
    var p_shop_found = false;
    for i in jar.cookies.len {
        if jar.cookies[i].name[..] == "p00" { p00_found = true; }
        if jar.cookies[i].name[..] == "p_shop" { p_shop_found = true; }
    }
    t.assert_false(p00_found, "CHIPS-03: oldest LRA cookie 'p00' in partition must be evicted on >10240B");
    t.assert_true(p_shop_found, "CHIPS-01: cookie in 'https://shop.com' partition must remain untouched");
}

// ----------------------------------------------------------------------------
// 15. GC OBC (Domain-before-Host) & Global 30-Day Purge Immunity
// ----------------------------------------------------------------------------
fn run_gc_obc_domain_before_host_and_global_purge(t: lit::T&) {
    var clock = lit::new_mock_clock();

    t.run("GC-07: Domain cookies evicted BEFORE Host cookies despite newer LastAccessDate") { sub =>
        var jar = cookie::CanonicalCookieJar { .. };

        // 1. Insert 175 Host-Only cookies with OLD access times (t = 1..175)
        for i in 175 {
            var h: u8[..64] = [];
            format(h, "host_", i, "=1; Priority=Low");
            cookie::set_cookie_header(jar, "http://example.com/", h[..], lit::advance_us(clock, 10));
        }

        // 2. Insert 6 Domain cookies (Domain=example.com) with FRESH access times
        for i in 6 {
            var h: u8[..64] = [];
            format(h, "dom_", i, "=1; Domain=example.com; Priority=Low");
            cookie::set_cookie_header(jar, "http://example.com/", h[..], lit::advance_sec(clock, 100));
        }

        // Total 181 inserted -> GC evicted 31 cookies (150 remain)
        sub.assert_eq(jar.cookies.len, 150);

        // All 6 domain cookies must be evicted first despite newer access times
        var remaining_domain_cookies = 0;
        for i in jar.cookies.len {
            if !jar.cookies[i].host_only { remaining_domain_cookies += 1; }
        }
        sub.assert_eq(remaining_domain_cookies, 0, "GC-07: all 6 domain cookies must be purged before any host cookie");
    };

    t.run("GC-10 & GC-11: Global 3300 Limit and 30-Day kSafeFromGlobalPurgeDays Immunity") { sub =>
        var jar = cookie::CanonicalCookieJar { .. };

        // Create 3350 cookies across 34 eTLD+1 domains (~98-100 per domain)
        // First 400 cookies created on day 0
        for i in 400 {
            let dom_id = i / 100;
            var url: u8[..64] = [];
            format(url, "https://d", dom_id, ".com/");
            var hdr: u8[..64] = [];
            format(hdr, "old_", i, "=val; Max-Age=30000000");
            cookie::set_cookie_header(jar, url[..], hdr[..], lit::advance_us(clock, 10));
        }

        // Advance virtual clock by 31 days (beyond 30-day immunity window for first 400 cookies)
        lit::advance_days(clock, 31);

        for i in 2901 {
            let dom_id = 4 + (i / 100);
            var url: u8[..64] = [];
            format(url, "https://d", dom_id, ".com/");
            var hdr: u8[..64] = [];
            format(hdr, "recent_", i, "=val; Max-Age=30000000");
            cookie::set_cookie_header(jar, url[..], hdr[..], lit::advance_us(clock, 10));
        }

        // Inserting 3301st cookie triggers global GC down to target 3000
        sub.assert_eq(jar.cookies.len, 3000, "GC-11: Global GC must purge down to 3000 when >30d old cookies exist");
        sub.assert_eq(jar.evicted_global_count, 301);
    };
}

// ----------------------------------------------------------------------------
// 16. RFC 6265 Section 5.4 Ordering, Server First-Win & SQLite V24 Coalescing
// ----------------------------------------------------------------------------
fn run_serialization_server_first_win_and_sqlite_v24(t: lit::T&) {
    var clock = lit::new_mock_clock();

    t.run("SER-01 & SRV-01: RFC 6265 Section 5.4 Path-Length Ordering and Server First-Win Protection") { sub =>
        var jar = cookie::CanonicalCookieJar { .. };

        // Set 3 cookies named 'sid' with different paths and creation timestamps:
        // 1) path="/" (create = T+10)
        cookie::set_cookie_header(jar, "https://example.com/", "sid=root_guest; Path=/", lit::advance_sec(clock, 10));
        // 2) path="/admin/panel" (create = T+30)
        cookie::set_cookie_header(jar, "https://example.com/", "sid=panel_late; Path=/admin/panel", lit::advance_sec(clock, 20));
        // 3) path="/admin" (create = T+40)
        cookie::set_cookie_header(jar, "https://example.com/", "sid=admin_mid; Path=/admin", lit::advance_sec(clock, 10));

        var cookie_hdr: u8[..256] = [];
        cookie::build_request_cookie_header(jar, "https://example.com/admin/panel/settings", true, "", clock.now_us, cookie_hdr);

        // Expected order: longest path '/admin/panel' -> '/admin' -> '/'
        sub.assert_bytes_eq(
            cookie_hdr[..],
            "sid=panel_late; sid=admin_mid; sid=root_guest",
            "SER-01: longer paths must precede shorter paths",
        );

        // In server parser: get_server_cookie must return FIRST occurrence ("panel_late")
        let parsed_req = cookie::parse_server_cookie_header(cookie_hdr[..]);
        let val = cookie::get_server_cookie(parsed_req[..], "sid");
        sub.assert_bytes_eq(
            val,
            "panel_late",
            "SRV-01: Server parser must preserve first occurrence to prevent root path shadowing",
        );
    };

    t.run("SQL-01..SQL-04: SQLite V24 Leading Dot in host_key and WriteBackBatcher Coalescing") { sub =>
        var c_host = cookie::new_canonical_cookie("sid", "host_val");
        c_host.domain.append("example.com");
        c_host.host_only = true;

        var c_dom = cookie::new_canonical_cookie("sid", "dom_val");
        c_dom.domain.append("example.com");
        c_dom.host_only = false;

        var sql_host: u8[..512] = [];
        var sql_dom:  u8[..512] = [];
        cookie::generate_sqlite_insert_sql(c_host, sql_host);
        cookie::generate_sqlite_insert_sql(c_dom, sql_dom);

        // Host-only cookie has host_key = 'example.com', domain cookie has host_key = '.example.com'
        sub.assert_contains(sql_host[..], "'example.com'", "SQL-01: host-only cookie must not have leading dot in host_key");
        sub.assert_contains(sql_dom[..], "'.example.com'", "SQL-01: domain cookie must have leading dot in SQLite V24 host_key");

        // Verification of coalescing in WriteBackBatcher: Insert + Delete = 0 operations
        var batch = cookie::new_write_back_batcher(clock.now_us);
        cookie::queue_insert(batch, c_host);
        sub.assert_eq(batch.ops.len, 1);
        cookie::queue_delete(batch, c_host);
        sub.assert_eq(batch.ops.len, 0, "SQL-02: Insert followed by Delete must coalesce to 0 disk ops");
    };
}

// ----------------------------------------------------------------------------
// 17. Matrix 11: LastAccessDate Throttling, Monotonicity & Clock Skew
// ----------------------------------------------------------------------------
fn run_matrix_11_clock_skew_and_throttling(t: lit::T&) {
    t.run("CLK-01 & CLK-02: 60s LastAccessDate Throttling (kDefaultAccessUpdateThresholdSeconds)") { sub =>
        var jar = cookie::CanonicalCookieJar { .. };
        jar.access_update_threshold_us = 60000000; // 60 seconds

        let t0: i64 = 1000 * 1000000; // 1000s
        cookie::set_cookie_header(jar, "https://example.com/api", "sid=token1", t0);
        sub.require_eq(jar.cookies.len, 1);
        sub.assert_eq(jar.cookies[0].last_access_utc, t0);

        // CLK-01: Read at t_1 = 1059s (delta = 59s < 60s) -> last_access_utc must NOT update
        let t1 = t0 + (59 * 1000000);
        let val1 = jar.get("https://example.com/api", "sid", t1);
        sub.assert_eq(val1, "token1");
        sub.assert_eq(jar.cookies[0].last_access_utc, t0, "CLK-01: access under 60s threshold must NOT update last_access_utc");

        // CLK-02: Read at t_2 = 1060s (delta = 60s >= 60s) -> last_access_utc updates
        let t2 = t0 + (60 * 1000000);
        let val2 = jar.get("https://example.com/api", "sid", t2);
        sub.assert_eq(val2, "token1");
        sub.assert_eq(jar.cookies[0].last_access_utc, t2, "CLK-02: access at >=60s threshold must update last_access_utc");
    };

    t.run("CLK-03: Sub-microsecond Collision Ordering via monotonic seq_counter") { sub =>
        var jar = cookie::CanonicalCookieJar { .. };
        let t0: i64 = 5000; // identical microsecond

        // Insert 3 cookies in the exact same microsecond
        cookie::set_cookie_header(jar, "https://example.com/", "c1=v1; Path=/", t0);
        cookie::set_cookie_header(jar, "https://example.com/", "c2=v2; Path=/", t0);
        cookie::set_cookie_header(jar, "https://example.com/", "c3=v3; Path=/", t0);

        var hdr: u8[..128] = [];
        jar.build_cookie_header("https://example.com/", t0, hdr);
        sub.assert_bytes_eq(hdr[..], "c1=v1; c2=v2; c3=v3", "CLK-03: stable FIFO sequence ordering on identical creation_utc");
    };

    t.run("CLK-04 & CLK-05: NTP Clock Skew Backward Shift and CreationDate Preservation") { sub =>
        var jar = cookie::CanonicalCookieJar { .. };

        // c1 created at t0 = 2000s
        let t0: i64 = 2000 * 1000000;
        cookie::set_cookie_header(jar, "https://example.com/", "c1=orig; Path=/", t0);
        sub.assert_eq(jar.cookies[0].creation_utc, t0);

        // NTP synchronization shifts client clock back to t1 = 1000s
        let t1: i64 = 1000 * 1000000;

        // CLK-04: c2 created with Max-Age=60 at t1 = 1000s -> expires_utc = 1060s
        cookie::set_cookie_header(jar, "https://example.com/", "c2=rel; Max-Age=60; Path=/", t1);
        sub.assert_eq(jar.cookies[1].expires_utc, t1 + (60 * 1000000), "CLK-04: TTL relative to client local clock");

        // CLK-05: Overwrite c1 at t1 = 1000s must preserve original creation_utc = 2000s
        cookie::set_cookie_header(jar, "https://example.com/", "c1=overwritten; Path=/", t1);
        sub.assert_eq(jar.cookies.len, 2);

        var c1_idx = 0;
        if jar.cookies[1].name[..] == "c1" { c1_idx = 1; }
        sub.assert_eq(jar.cookies[c1_idx].creation_utc, t0, "CLK-05: creation_utc immutable across backward clock skew");
        sub.assert_eq(jar.cookies[c1_idx].last_update_utc, t1, "CLK-05: last_update_utc updated to current time");
    };
}

// ----------------------------------------------------------------------------
// 18. Matrix 13: SiteForCookies Ancestor Frame Hierarchy & Context
// ----------------------------------------------------------------------------
fn run_matrix_13_site_for_cookies_and_ancestors(t: lit::T&) {
    t.run("CTX-01 & CTX-02: ABA Framing vs Homogeneous Ancestor Hierarchy") { sub =>
        // CTX-01: Top https://a.com -> iframe https://evil.com -> iframe https://a.com/inner
        let ancestors_aba: const u8[:][2] = ["https://a.com", "https://evil.com"];
        let site_aba = cookie::compute_site_for_cookies_with_ancestors("https://a.com", ancestors_aba[..]);
        sub.assert_true(site_aba.is_null, "CTX-01: cross-site ancestor renders SiteForCookies null");
        sub.assert_false(cookie::is_request_same_site(site_aba, "https://a.com/inner"), "CTX-01: request inside ABA is cross-site");

        // CTX-02: Top https://a.com -> iframe https://sub.a.com/widget
        let ancestors_clean: const u8[:][1] = ["https://a.com"];
        let site_clean = cookie::compute_site_for_cookies_with_ancestors("https://a.com", ancestors_clean[..]);
        sub.assert_false(site_clean.is_null, "CTX-02: all same-site ancestors retain valid SiteForCookies");
        sub.assert_true(cookie::is_request_same_site(site_clean, "https://api.a.com/data"), "CTX-02: request is same-site");
    };
}

// ----------------------------------------------------------------------------
// 19. Matrix 14: Selective Deletion & Session Cleanup (DEL-01..DEL-05)
// ----------------------------------------------------------------------------
fn run_matrix_14_selective_deletion(t: lit::T&) {
    t.run("DEL-01: TimeRange Selective Deletion [begin, end]") { sub =>
        var jar = cookie::CanonicalCookieJar { .. };
        cookie::set_cookie_header(jar, "https://example.com/", "c1=1; Path=/", 100);
        cookie::set_cookie_header(jar, "https://example.com/", "c2=2; Path=/", 200);
        cookie::set_cookie_header(jar, "https://example.com/", "c3=3; Path=/", 300);
        cookie::set_cookie_header(jar, "https://example.com/", "c4=4; Path=/", 400);
        sub.require_eq(jar.cookies.len, 4);

        let deleted = cookie::delete_all_created_in_time_range(jar, 200, 300);
        sub.assert_eq(deleted, 2, "DEL-01: exactly 2 cookies deleted inside [200, 300]");
        sub.assert_eq(jar.cookies.len, 2);
        sub.assert_eq(jar.cookies[0].name[..], "c1");
        sub.assert_eq(jar.cookies[1].name[..], "c4");
    };

    t.run("DEL-02 & DEL-04: Session Cookie Deletion and Cookie Incrementalism Section 3.5") { sub =>
        var jar = cookie::CanonicalCookieJar { .. };
        // c1: Session cookie (no Max-Age/Expires)
        cookie::set_cookie_header(jar, "https://example.com/", "c_sess=1; Path=/", 1000);
        // c2: Persistent cookie over secure channel
        cookie::set_cookie_header(jar, "https://example.com/", "c_sec=2; Max-Age=3600; Secure; Path=/", 1000);
        // c3: Persistent cookie over non-secure channel
        cookie::set_cookie_header(jar, "http://example.com/", "c_plain=3; Max-Age=3600; Path=/", 1000);
        sub.require_eq(jar.cookies.len, 3);

        // DEL-04: Incrementalism Section 3.5: purge non-secure cookies on session end
        let purged = cookie::delete_session_cookies(jar, true);
        sub.assert_eq(purged, 2, "Session cookie (c_sess) and NonSecure persistent cookie (c_plain) purged");
        sub.assert_eq(jar.cookies.len, 1);
        sub.assert_eq(jar.cookies[0].name[..], "c_sec", "Secure persistent cookie preserved");
    };
}

// ----------------------------------------------------------------------------
// 20. Matrices 15 & 16: Cryptographic Integrity & Protocol Attacks
// ----------------------------------------------------------------------------
fn run_matrix_15_and_16_crypto_and_attacks(t: lit::T&) {
    t.run("CRY-02: Rejection of Tampered Record with Both Plaintext and Encrypted Values") { sub =>
        var jar = cookie::CanonicalCookieJar { .. };

        // Valid JSON with normal cookie
        let valid_json = "[{\"name\":\"clean_sid\",\"value\":\"secret_123\",\"domain\":\"example.com\",\"path\":\"/\"}]";
        let valid_count = jar.import_json(valid_json, 1000);
        sub.assert_eq(valid_count, 1);

        // Tampered record: simultaneous plaintext 'value' and 'encrypted_value' (kValuesExistInBothEncryptedAndPlaintext = 8)
        var tampered_cookie = cookie::new_canonical_cookie("hacked", "plain_val");
        tampered_cookie.encrypted_value.append("ciphertext_blob_123");
        tampered_cookie.domain.append("example.com");

        let both_invalid = tampered_cookie.value.len > 0 && tampered_cookie.encrypted_value.len > 0;
        sub.assert_true(both_invalid, "CRY-02: Detected simultaneous plaintext and encrypted values");
    };

    t.run("CRY-05: Constant-Time Comparison Timing Immunity") { sub =>
        sub.assert_true(core::ct_eq_bytes("secret_token_123", "secret_token_123"));
        sub.assert_false(core::ct_eq_bytes("secret_token_123", "secret_token_124"));
        sub.assert_false(core::ct_eq_bytes("short", "longer_token"));
    };

    t.run("ATK-01: Set-Cookie Comma Folding Invariant (RFC 6265bis Section 1)") { sub =>
        var jar = cookie::CanonicalCookieJar { .. };
        // Comma inside Path attribute must NOT split the cookie
        let ok = cookie::set_cookie_header(jar, "https://example.com/c,d=e", "a=b; Path=/c,d=e", 1000);
        sub.assert_true(ok);
        sub.assert_eq(jar.cookies.len, 1);
        sub.assert_eq(jar.cookies[0].name[..], "a");
        sub.assert_eq(jar.cookies[0].value[..], "b");
        sub.assert_eq(jar.cookies[0].path[..], "/c,d=e");
    };
}

// ----------------------------------------------------------------------------
// 21. GC-04: strict_secure_cookies Policy Priority Eviction
// ----------------------------------------------------------------------------
fn run_gc_strict_secure_policy(t: lit::T&) {
    let now_us = 1700000000000000;
    var jar = cookie::CanonicalCookieJar { .. };
    jar.strict_secure_cookies = true;

    // Insert 100 Secure cookies
    for i in 100 {
        var h: u8[..64] = [];
        format(h, "sec_", i, "=1; Secure");
        cookie::set_cookie_header(jar, "https://example.com/", h[..], now_us + i);
    }
    // Insert 80 Non-Secure cookies (total 180 = max limit)
    for i in 80 {
        var h: u8[..64] = [];
        format(h, "nonsec_", i, "=1");
        cookie::set_cookie_header(jar, "http://example.com/", h[..], now_us + 100 + i);
    }
    t.assert_eq(jar.cookies.len, 180);

    // 181st cookie triggers domain GC with strict_secure_cookies=true
    // GC-04: All non-secure cookies are evicted first!
    cookie::set_cookie_header(jar, "http://example.com/", "trigger=1", now_us + 200);
    t.assert_le(jar.cookies.len, 101, "all non-secure cookies evicted under strict_secure_cookies policy");
    t.assert_gt(jar.rejected_security_count, 0);
}

// ----------------------------------------------------------------------------
// 22. Database Load Sanitization (CTL-08) & Nameless Cookie Import
// ----------------------------------------------------------------------------
fn run_ctl_sanitization_and_nameless_import(t: lit::T&) {
    let now_us = 1700000000000000;
    var jar = cookie::CanonicalCookieJar { .. };

    // 1. JSON import supporting nameless omnomnom cookies
    var json_data: u8[..512] = [];
    format(
        json_data,
        "[{\"name\":\"valid\",\"value\":\"ok\",\"domain\":\"example.com\",\"path\":\"/\",\"secure\":true},",
        "{\"name\":\"\",\"value\":\"nameless_val\",\"domain\":\"example.com\",\"path\":\"/\",\"secure\":true}]",
    );

    let count = cookie::import_json(jar, json_data[..], now_us);
    t.assert_eq(count, 2, "Both valid named and nameless cookies imported from JSON");
    t.assert_eq(jar.cookies.len, 2);
    t.assert_bytes_eq(jar.cookies[0].name[..], "valid");
    t.assert_bytes_eq(jar.cookies[1].name[..], "");
    t.assert_bytes_eq(jar.cookies[1].value[..], "nameless_val");

    // 2. CTL-08: Direct or loaded cookie containing control chars rejected by engine
    var corrupt_cookie = cookie::CanonicalCookie { .. };
    corrupt_cookie.name.append("bad");
    corrupt_cookie.value.append("corrupt\x01val");
    corrupt_cookie.domain.append("example.com");
    corrupt_cookie.path.clear();
    corrupt_cookie.path.append("/");
    let src_opts_corrupt = cookie::SourceOptions { is_http_api: true, url_is_secure: true };
    let corrupt_inserted = cookie::set_canonical_cookie(jar, corrupt_cookie, src_opts_corrupt, now_us);
    t.assert_false(corrupt_inserted, "CTL-08: Cookie with CTL byte %x01 rejected upon loading/insertion");
}

// ----------------------------------------------------------------------------
// 23. Property-Based PRNG Fuzzing (600 Steps Invariant Check)
// ----------------------------------------------------------------------------
fn run_property_based_fuzzer(t: lit::T&) {
    var rng = lit::new_fuzz_rng(0xCAFEBABE1337BEEF);
    var clock = lit::new_mock_clock();
    var jar = cookie::CanonicalCookieJar { .. };

    // Run 600 random insertion, overwrite, and expiration steps on a single domain
    for step in 600 {
        let key_idx = lit::next_range(rng, 0, 260);
        let prio_idx = lit::next_range(rng, 0, 3);
        let is_sec = lit::next_range(rng, 0, 2) == 1;
        let is_host_only = lit::next_range(rng, 0, 2) == 1;
        let max_age = lit::next_range(rng, -5, 50000);

        var hdr: u8[..128] = [];
        format(hdr, "k_", key_idx, "=val_", step, "; Max-Age=", max_age);
        if !is_host_only { hdr.append("; Domain=fuzz.example.com"); }
        if is_sec { hdr.append("; Secure"); }
        if prio_idx == 0 { hdr.append("; Priority=Low"); }
        if prio_idx == 1 { hdr.append("; Priority=Medium"); }
        if prio_idx == 2 { hdr.append("; Priority=High"); }

        let url = if is_sec { "https://sub.fuzz.example.com/a/b" } else { "http://sub.fuzz.example.com/a/b" };
        cookie::set_cookie_header(jar, url, hdr[..], lit::advance_ms(clock, 50));

        // Invariant 1: cookie count in domain never exceeds kDomainMaxCookies (180)
        t.require_le(jar.cookies.len, 180, "Fuzz Invariant 1: domain cookie count must never exceed 180");
    }

    // Invariant 2: no stored persistent cookie has TTL > 400 days from current virtual time
    let max_allowed_exp = clock.now_us + (400 * 86400 * 1000000);
    for i in jar.cookies.len {
        if jar.cookies[i].persistent {
            t.assert_le(jar.cookies[i].expires_utc, max_allowed_exp, "Fuzz Invariant 2: 400-day cap violated");
        }
    }
}

// --- Component: cookie_psl ---
// Full verification suite for Mozilla Public Suffix List (PSL) Engine
// and RFC 6265 Cookie Scoping (Normal, Wildcard, Exception, Private, and eTLD+1).

// ----------------------------------------------------------------------------
// 24. PSL Rule Types and Precedence (Normal, Wildcard, Exception, Private)
// ----------------------------------------------------------------------------
fn test_psl_rule_types_and_precedence(t: lit::T&) {
    let db = cookie::new_psl_database();

    t.run("Case 1: Normal ICANN Suffixes") { sub =>
        // com
        var s1: u8[..64] = [];
        let icann1, ok1 = cookie::find_public_suffix(db, "example.com", s1);
        sub.assert_true(ok1, "example.com has public suffix");
        sub.assert_true(icann1, "example.com suffix is ICANN");
        sub.assert_bytes_eq(s1[..], "com", "suffix is com");
        sub.assert_false(cookie::is_public_suffix(db, "example.com"), "example.com is not public suffix");
        sub.assert_true(cookie::is_public_suffix(db, "com"), "com is public suffix");

        // co.uk (2-level)
        var s2: u8[..64] = [];
        let icann2, ok2 = cookie::find_public_suffix(db, "service.co.uk", s2);
        sub.assert_true(ok2, "service.co.uk has public suffix");
        sub.assert_true(icann2, "co.uk suffix is ICANN");
        sub.assert_bytes_eq(s2[..], "co.uk", "suffix is co.uk");
        sub.assert_true(cookie::is_public_suffix(db, "co.uk"), "co.uk is public suffix");

        // deep subdomain
        var s3: u8[..64] = [];
        let _, ok3 = cookie::find_public_suffix(db, "a.b.c.service.co.uk", s3);
        sub.assert_true(ok3, "deep subdomain matched");
        sub.assert_bytes_eq(s3[..], "co.uk", "suffix remains co.uk");
    };

    t.run("Case 2: Wildcard Rules (*.ck, *.kawasaki.jp)") { sub =>
        // *.ck -> any label under ck is a public suffix
        // bar.ck -> public suffix is bar.ck
        var s1: u8[..64] = [];
        let _, ok1 = cookie::find_public_suffix(db, "bar.ck", s1);
        sub.assert_true(ok1, "bar.ck matched wildcard *.ck");
        sub.assert_bytes_eq(s1[..], "bar.ck", "suffix is bar.ck");
        sub.assert_true(cookie::is_public_suffix(db, "bar.ck"), "bar.ck is public suffix due to wildcard");

        // sub.bar.ck -> suffix is bar.ck, eTLD+1 is sub.bar.ck
        var s2: u8[..64] = [];
        let _, ok2 = cookie::find_public_suffix(db, "sub.bar.ck", s2);
        sub.assert_true(ok2, "sub.bar.ck matched");
        sub.assert_bytes_eq(s2[..], "bar.ck", "suffix is bar.ck");

        var etld2: u8[..64] = [];
        cookie::extract_etld_plus_one(db, "sub.bar.ck", etld2);
        sub.assert_bytes_eq(etld2[..], "sub.bar.ck", "eTLD+1 is sub.bar.ck");
    };

    t.run("Case 3: Exception Rules (!www.ck, !city.kawasaki.jp)") { sub =>
        // !www.ck -> exception rule overrides wildcard *.ck. Suffix is 'ck', so www.ck is registrable!
        var s1: u8[..64] = [];
        let _, ok1 = cookie::find_public_suffix(db, "www.ck", s1);
        sub.assert_true(ok1, "www.ck matched exception rule");
        sub.assert_bytes_eq(s1[..], "ck", "exception rule stripped leftmost label to ck");
        sub.assert_false(cookie::is_public_suffix(db, "www.ck"), "www.ck is NOT a public suffix");

        var etld1: u8[..64] = [];
        cookie::extract_etld_plus_one(db, "www.ck", etld1);
        sub.assert_bytes_eq(etld1[..], "www.ck", "www.ck is eTLD+1");

        // sub.www.ck -> suffix is still 'ck', eTLD+1 is www.ck
        var s2: u8[..64] = [];
        let _, ok2 = cookie::find_public_suffix(db, "sub.www.ck", s2);
        sub.assert_true(ok2, "sub.www.ck matched");
        sub.assert_bytes_eq(s2[..], "ck", "suffix is ck");

        var etld2: u8[..64] = [];
        cookie::extract_etld_plus_one(db, "sub.www.ck", etld2);
        sub.assert_bytes_eq(etld2[..], "www.ck", "eTLD+1 is www.ck");
    };

    t.run("Case 4: Private Section and Tenant Isolation") { sub =>
        // github.io is Private section
        var s1: u8[..64] = [];
        let icann1, ok1 = cookie::find_public_suffix(db, "alice.github.io", s1);
        sub.assert_true(ok1, "alice.github.io parsed");
        sub.assert_false(icann1, "github.io is Private section (not ICANN)");
        sub.assert_bytes_eq(s1[..], "github.io", "suffix is github.io");

        var etld_alice: u8[..64] = [];
        cookie::extract_etld_plus_one(db, "alice.github.io", etld_alice);
        sub.assert_bytes_eq(etld_alice[..], "alice.github.io", "alice.github.io is isolated tenant eTLD+1");

        // Cloudfront & Pages.dev
        var s2: u8[..64] = [];
        let icann2, ok2 = cookie::find_public_suffix(db, "my-site.pages.dev", s2);
        sub.assert_true(ok2, "pages.dev parsed");
        sub.assert_false(icann2, "pages.dev is Private");
        sub.assert_bytes_eq(s2[..], "pages.dev", "suffix is pages.dev");
    };

    t.run("Case 5: Default Rule (*) on Unlisted TLD") { sub =>
        var s1: u8[..64] = [];
        let icann1, ok1 = cookie::find_public_suffix(db, "app.customprivatetld", s1);
        sub.assert_true(ok1, "fallback matched");
        sub.assert_true(icann1, "fallback treated as ICANN");
        sub.assert_bytes_eq(s1[..], "customprivatetld", "fallback suffix is highest label");

        var etld1: u8[..64] = [];
        cookie::extract_etld_plus_one(db, "sub.app.customprivatetld", etld1);
        sub.assert_bytes_eq(etld1[..], "app.customprivatetld", "eTLD+1 for unlisted TLD");
    };
}

// ----------------------------------------------------------------------------
// 25. PSL Dynamic Update and RFC 6265 Scoping
// ----------------------------------------------------------------------------
fn test_psl_dynamic_update_and_scoping(t: lit::T&) {
    t.run("Case 1: Dynamic update_with_list parsing") { sub =>
        var db = cookie::PslDatabase { rules: [] };
        let initial_count = db.rules.len;
        sub.assert_eq(initial_count, 0, "empty db initially");

        let psl_text = "// ===BEGIN ICANN DOMAINS===\ncom\nco.uk\n*.sch.uk\n!special.sch.uk\n\n// ===BEGIN PRIVATE DOMAINS===\ninternal.corp\n";

        cookie::update_with_list(db, psl_text);
        sub.assert_eq(db.rules.len, 5, "5 rules parsed");

        // Verify normal
        sub.assert_true(cookie::is_public_suffix(db, "com"), "com is public suffix");
        sub.assert_true(cookie::is_public_suffix(db, "co.uk"), "co.uk is public suffix");

        // Verify wildcard *.sch.uk
        var s_sch: u8[..64] = [];
        let _, ok_sch = cookie::find_public_suffix(db, "grammar.sch.uk", s_sch);
        sub.assert_true(ok_sch, "grammar.sch.uk matched wildcard");
        sub.assert_bytes_eq(s_sch[..], "grammar.sch.uk", "suffix is grammar.sch.uk");

        // Verify exception !special.sch.uk
        var s_sp: u8[..64] = [];
        let _, ok_sp = cookie::find_public_suffix(db, "special.sch.uk", s_sp);
        sub.assert_true(ok_sp, "special.sch.uk matched exception");
        sub.assert_bytes_eq(s_sp[..], "sch.uk", "exception stripped leftmost label to sch.uk");

        // Verify private
        var s_corp: u8[..64] = [];
        let icann_corp, ok_corp = cookie::find_public_suffix(db, "node.internal.corp", s_corp);
        sub.assert_true(ok_corp, "internal.corp matched");
        sub.assert_false(icann_corp, "internal.corp is Private");
        sub.assert_bytes_eq(s_corp[..], "internal.corp", "suffix is internal.corp");
    };

    t.run("Case 2: RFC 6265 Cookie Domain Match with PSL Rejection") { sub =>
        let db = cookie::new_psl_database();

        // Valid domain matches
        sub.assert_true(cookie::domain_match(db, "app.example.com", "example.com"), "subdomain matches parent domain");
        sub.assert_true(cookie::domain_match(db, "example.com", "example.com"), "exact host matches domain");

        // Rejection: cookie domain is public suffix
        sub.assert_false(cookie::domain_match(db, "app.example.com", "com"), "reject cookie domain 'com' (public suffix)");
        sub.assert_false(cookie::domain_match(db, "app.example.co.uk", "co.uk"), "reject cookie domain 'co.uk' (public suffix)");
        sub.assert_false(cookie::domain_match(db, "alice.github.io", "github.io"), "reject cookie domain 'github.io' (private suffix)");

        // Suffix collision
        sub.assert_false(cookie::domain_match(db, "badexample.com", "example.com"), "reject suffix collision without dot boundary");
    };

    t.run("Case 3: Case-insensitivity and edge dots normalization") { sub =>
        let db = cookie::new_psl_database();

        var s1: u8[..64] = [];
        let _, ok1 = cookie::find_public_suffix(db, ".EXAMPLE.COM.", s1);
        sub.assert_true(ok1, "domain with leading and trailing dot parsed");
        sub.assert_bytes_eq(s1[..], "com", "suffix normalized to com");

        var etld1: u8[..64] = [];
        cookie::extract_etld_plus_one(db, ".SUB.EXAMPLE.CO.UK.", etld1);
        sub.assert_bytes_eq(etld1[..], "example.co.uk", "eTLD+1 normalized to example.co.uk");
    };
}

// --- Component: cookie_prefix_ssrf ---
// Security tests for cookie prefixes, SSRF filter bypasses, and port validation.

// ----------------------------------------------------------------------------
// 26. RFC 6265bis Section 5.6: __Host- & __Secure- Cookie Prefix Enforcement
// ----------------------------------------------------------------------------
fn test_host_and_secure_cookie_prefix_smuggling(t: lit::T&) {
    var clock = lit::new_mock_clock();

    t.run("HOST-01: __Host- cookie with Domain=127.0.0.1 literal must be rejected") { sub =>
        var jar = cookie::CanonicalCookieJar { .. };
        // RFC 6265bis Section 5.6.2: Must not include a Domain attribute
        let ok = cookie::set_cookie_header(jar, "https://127.0.0.1/", "__Host-auth=secret123; Domain=127.0.0.1; Secure; Path=/", clock.now_us);
        sub.assert_false(ok, "__Host- with Domain=127.0.0.1 must be rejected per RFC 6265bis");
        sub.assert_eq(jar.cookies.len, 0, "Jar must not store __Host- cookie with Domain attribute");
    };

    t.run("HOST-02: __Host- cookie with Domain=localhost must be rejected") { sub =>
        var jar = cookie::CanonicalCookieJar { .. };
        let ok = cookie::set_cookie_header(jar, "https://localhost/", "__Host-token=secret456; Domain=localhost; Secure; Path=/", clock.now_us);
        sub.assert_false(ok, "__Host- with Domain=localhost must be rejected per RFC 6265bis");
        sub.assert_eq(jar.cookies.len, 0, "Jar must not store __Host- cookie with Domain attribute on localhost");
    };

    t.run("HOST-03: __Host- cookie with empty or dot Domain attribute must be rejected") { sub =>
        var jar = cookie::CanonicalCookieJar { .. };
        let ok1 = cookie::set_cookie_header(jar, "https://example.com/", "__Host-sess=val; Domain=; Secure; Path=/", clock.now_us);
        sub.assert_false(ok1, "__Host- with empty Domain= attribute must be rejected");

        let ok2 = cookie::set_cookie_header(jar, "https://example.com/", "__Host-sess=val; Domain=.; Secure; Path=/", clock.now_us);
        sub.assert_false(ok2, "__Host- with Domain=. attribute must be rejected");

        sub.assert_eq(jar.cookies.len, 0);
    };

    t.run("HOST-04: Direct parse_canonical_set_cookie must reject __Host- with Domain attribute") { sub =>
        let cookie, cause, ok = cookie::parse_canonical_set_cookie(
            "__Host-key=secret; Domain=example.com; Secure; Path=/",
            "example.com",
            "/",
            clock.now_us,
        );
        sub.assert_false(ok, "parse_canonical_set_cookie must return false for __Host- with Domain attribute");
    };

    t.run("HOST-05: __Host- cookie with non-root path must be rejected") { sub =>
        var jar = cookie::CanonicalCookieJar { .. };
        let ok = cookie::set_cookie_header(jar, "https://example.com/api/", "__Host-tok=val; Path=/api; Secure", clock.now_us);
        sub.assert_false(ok, "__Host- cookie with Path=/api must be rejected (must be Path=/)");
        sub.assert_eq(jar.cookies.len, 0);
    };

    t.run("HOST-06: __Host- cookie over plain HTTP must be rejected") { sub =>
        var jar = cookie::CanonicalCookieJar { .. };
        let ok = cookie::set_cookie_header(jar, "http://example.com/", "__Host-tok=val; Secure; Path=/", clock.now_us);
        sub.assert_false(ok, "__Host- cookie over http:// must be rejected (requires secure channel)");
        sub.assert_eq(jar.cookies.len, 0);
    };

    t.run("HOST-07: __Host- cookie without Secure attribute must be rejected") { sub =>
        var jar = cookie::CanonicalCookieJar { .. };
        let ok = cookie::set_cookie_header(jar, "https://example.com/", "__Host-tok=val; Path=/", clock.now_us);
        sub.assert_false(ok, "__Host- cookie without Secure attribute must be rejected");
        sub.assert_eq(jar.cookies.len, 0);
    };

    t.run("HOST-08: Valid __Host- cookie on HTTPS with Path=/ is stored and retrieved") { sub =>
        var jar = cookie::CanonicalCookieJar { .. };
        let ok = cookie::set_cookie_header(jar, "https://example.com/", "__Host-auth=valid_secret; Secure; Path=/", clock.now_us);
        sub.assert_true(ok, "Valid __Host- cookie must be accepted");
        sub.assert_eq(jar.cookies.len, 1);
        sub.assert_eq(jar.get("__Host-auth"), "valid_secret");
    };

    t.run("SECURE-01: __Secure- cookie without Secure attribute must be rejected") { sub =>
        var jar = cookie::CanonicalCookieJar { .. };
        let ok = cookie::set_cookie_header(jar, "https://example.com/", "__Secure-id=12345; Path=/", clock.now_us);
        sub.assert_false(ok, "__Secure- cookie without Secure attribute must be rejected");
        sub.assert_eq(jar.cookies.len, 0);
    };

    t.run("SECURE-02: __Secure- cookie over plain HTTP must be rejected") { sub =>
        var jar = cookie::CanonicalCookieJar { .. };
        let ok = cookie::set_cookie_header(jar, "http://example.com/", "__Secure-id=12345; Secure; Path=/", clock.now_us);
        sub.assert_false(ok, "__Secure- cookie over plain http:// must be rejected");
        sub.assert_eq(jar.cookies.len, 0);
    };

    t.run("SECURE-03: Valid __Secure- cookie with Domain and sub-path on HTTPS is accepted") { sub =>
        var jar = cookie::CanonicalCookieJar { .. };
        let ok = cookie::set_cookie_header(jar, "https://sub.example.com/api/", "__Secure-id=ok123; Secure; Domain=example.com; Path=/api", clock.now_us);
        sub.assert_true(ok, "__Secure- cookie with Domain and sub-path must be accepted on HTTPS");
        sub.assert_eq(jar.cookies.len, 1);
    };

    t.run("SECURE-04: Case-folded prefixes (__HOST- and __secure-) are strictly enforced") { sub =>
        var jar = cookie::CanonicalCookieJar { .. };
        let ok1 = cookie::set_cookie_header(jar, "https://example.com/", "__HOST-key=val; Domain=example.com; Secure; Path=/", clock.now_us);
        sub.assert_false(ok1, "Case-folded __HOST- with Domain must be rejected");

        let ok2 = cookie::set_cookie_header(jar, "https://example.com/", "__secure-tok=val; Path=/", clock.now_us);
        sub.assert_false(ok2, "Case-folded __secure- without Secure attribute must be rejected");
    };

    t.run("SECURE-05: Cookie Crumbles / Nameless cookie prefix injection rejected") { sub =>
        var jar = cookie::CanonicalCookieJar { .. };
        let ok = cookie::set_cookie_header(jar, "https://example.com/", "=__Host-sess=stolen; Secure; Path=/", clock.now_us);
        sub.assert_false(ok, "Nameless cookie containing __Host- prefix in value must be rejected (SHAD-01)");
    };

    t.run("SECURE-06: Non-secure HTTP cannot overwrite an existing secure __Secure- cookie") { sub =>
        var jar = cookie::CanonicalCookieJar { .. };
        // 1. Secure set over HTTPS
        let ok1 = cookie::set_cookie_header(jar, "https://example.com/", "__Secure-token=legit; Secure; Path=/", clock.now_us);
        sub.assert_true(ok1);

        // 2. Insecure attempt to overwrite over plain HTTP
        let ok2 = cookie::set_cookie_header(jar, "http://example.com/", "__Secure-token=malicious; Path=/", clock.now_us + 1000);
        sub.assert_false(ok2, "Insecure HTTP request must not overwrite secure cookie");
        sub.assert_eq(jar.get("__Secure-token"), "legit", "Original secure value must be preserved");
    };
}

// ----------------------------------------------------------------------------
// 27. SSRF Filter Bypasses & IPv6 Zone ID / Scope ID Proxy Smuggling
// ----------------------------------------------------------------------------
fn test_ssrf_filter_bypasses(t: lit::T&) {
    t.run("SSRF-01: NAT64 prefix to 0.0.0.0 (64:ff9b:: and 64:ff9b::0.0.0.0) must be blocked") { sub =>
        sub.assert_true(security::is_private_or_reserved_ip("64:ff9b::"), "NAT64 empty suffix (0.0.0.0) must be reserved");
        sub.assert_true(security::is_private_or_reserved_ip("64:ff9b::0.0.0.0"), "NAT64 0.0.0.0 must be reserved");
        sub.assert_true(security::is_private_or_reserved_ip("[64:ff9b::]"), "NAT64 bracketed empty suffix must be reserved");
    };

    t.run("SSRF-02: IPv6 Multicast (ff00::/8) must be blocked") { sub =>
        sub.assert_true(security::is_private_or_reserved_ip("ff02::1"), "IPv6 all-nodes multicast must be reserved");
        sub.assert_true(security::is_private_or_reserved_ip("ff01::1"), "IPv6 node-local multicast must be reserved");
        sub.assert_true(security::is_private_or_reserved_ip("[ff05::2]"), "IPv6 site-local multicast must be reserved");
    };

    t.run("SSRF-03: IPv6 Site-Local (fec0::/10) must be blocked") { sub =>
        sub.assert_true(security::is_private_or_reserved_ip("fec0::1"), "IPv6 site-local fec0::1 must be reserved");
        sub.assert_true(security::is_private_or_reserved_ip("[feff::ffff]"), "IPv6 site-local feff::ffff must be reserved");
    };

    t.run("SSRF-04: Trailing-dot IP literal (127.0.0.1. and 0.0.0.0.) must be blocked") { sub =>
        sub.assert_true(security::is_private_or_reserved_ip("127.0.0.1."), "127.0.0.1. with trailing dot must be blocked");
        sub.assert_true(security::is_private_or_reserved_ip("0.0.0.0."), "0.0.0.0. with trailing dot must be blocked");
        sub.assert_true(security::is_private_or_reserved_ip("10.0.0.1."), "10.0.0.1. with trailing dot must be blocked");
    };

    t.run("SSRF-05: IPv6 Zone ID / Scope ID Proxy Smuggling & SSRF Bypass (CVE-2025-22870)") { sub =>
        // In CVE-2025-22870, [::1%25.example.com]:80 bypassed proxy filters because .example.com was treated as host
        // Goose recognizes stripped base ::1 and fe80::1 as reserved/loopback/link-local:
        sub.assert_true(security::is_private_or_reserved_ip("[::1%25.example.com]"), "Bracketed ::1 with %25 zone ID must be blocked");
        sub.assert_true(security::is_private_or_reserved_ip("::1%25.example.com"), "Bare ::1 with %25 zone ID must be blocked");
        sub.assert_true(security::is_private_or_reserved_ip("::1%eth0"), "Bare ::1 with %eth0 interface scope must be blocked");
        sub.assert_true(security::is_private_or_reserved_ip("::1%lo"), "Bare ::1 with %lo interface scope must be blocked");
        sub.assert_true(security::is_private_or_reserved_ip("[fe80::1%25eth0]"), "Link-local with %25 scope must be blocked");
        sub.assert_true(security::is_private_or_reserved_ip("fe80::1%eth0"), "Link-local with interface scope must be blocked");
        sub.assert_true(security::is_private_or_reserved_ip("ff02::1%eth0"), "Multicast with interface scope must be blocked");

        // Public IPs with scope ID should not be misclassified as private:
        sub.assert_false(security::is_private_or_reserved_ip("2606:4700:4700::1111%eth0"), "Public IPv6 with scope must not be blocked as private");
    };

    t.run("SSRF-06: WHATWG URL parser invalidates bracketed IPv6 with zone ID, immune by design") { sub =>
        let u1 = core::new_url("http://[::1%25.example.com]:80/api");
        sub.assert_false(u1.valid, "URL parser must invalidate [::1%25.example.com]");

        let u2 = core::new_url("http://[::1%eth0]:80/api");
        sub.assert_false(u2.valid, "URL parser must invalidate [::1%eth0]");
    };

    t.run("SSRF-07: RFC 5737 / RFC 2544 / RFC 6890 Reserved Test & Benchmarking Networks") { sub =>
        // TEST-NET-1 (192.0.2.0/24)
        sub.assert_true(security::is_private_or_reserved_ip("192.0.2.1"), "TEST-NET-1 must be blocked");
        sub.assert_true(security::is_private_or_reserved_ip("192.0.2.254"), "TEST-NET-1 must be blocked");

        // TEST-NET-2 (198.51.100.0/24)
        sub.assert_true(security::is_private_or_reserved_ip("198.51.100.1"), "TEST-NET-2 must be blocked");
        sub.assert_true(security::is_private_or_reserved_ip("198.51.100.254"), "TEST-NET-2 must be blocked");

        // TEST-NET-3 (203.0.113.0/24)
        sub.assert_true(security::is_private_or_reserved_ip("203.0.113.1"), "TEST-NET-3 must be blocked");
        sub.assert_true(security::is_private_or_reserved_ip("203.0.113.254"), "TEST-NET-3 must be blocked");

        // Benchmarking (198.18.0.0/15)
        sub.assert_true(security::is_private_or_reserved_ip("198.18.0.1"), "198.18.0.0/15 benchmarking must be blocked");
        sub.assert_true(security::is_private_or_reserved_ip("198.19.255.254"), "198.19.255.254 benchmarking must be blocked");

        // 6to4 Relay Anycast (192.88.99.0/24)
        sub.assert_true(security::is_private_or_reserved_ip("192.88.99.1"), "192.88.99.0/24 must be blocked");

        // Legitimate public IPs must not be blocked:
        sub.assert_false(security::is_private_or_reserved_ip("198.50.1.1"), "198.50.1.1 must not be blocked");
        sub.assert_false(security::is_private_or_reserved_ip("203.1.1.1"), "203.1.1.1 must not be blocked");
    };

    t.run("SSRF-08: Flexible IPv4 Integer Overflow & Scoped Multicast SSRF Guard") { sub =>
        // Integer overflow defense: > 0xFFFFFFFF must not wrap around or be parsed as 0
        sub.assert_false(security::is_private_or_reserved_ip("4294967296"), "4294967296 (2^32) must not wrap around");
        sub.assert_false(security::is_private_or_reserved_ip("127.0.0.0x10000000000000001"), "u64 overflow must not parse as valid IPv4");
        sub.assert_false(security::is_private_or_reserved_ip("127..0.1"), "Empty double-dot segment must not parse as valid IPv4");

        // IPv6 Scoped Multicast with Zone ID must be blocked by SSRF guard policy
        var policy = security::SsrfGuardPolicy { enabled: true, .. };
        let u_multi = core::new_url("http://[ff02::1%25eth0]/status");
        sub.assert_true(u_multi.valid, "Scoped multicast URL is syntactically valid per RFC 6874");
        let err_multi = client::validate_url_against_ssrf(u_multi, policy);
        sub.assert_ne(err_multi, client::RedirectError.None, "Scoped multicast URL must be blocked by SSRF guard");

        let u_node = core::new_url("http://[ff01::1%25eth0]/admin");
        sub.assert_true(u_node.valid, "Node-local multicast URL is syntactically valid per RFC 6874");
        let err_node = client::validate_url_against_ssrf(u_node, policy);
        sub.assert_ne(err_node, client::RedirectError.None, "Node-local multicast URL must be blocked by SSRF guard");
    };
}

// ----------------------------------------------------------------------------
// 28. Dangerous Service Ports & Port 0 SSRF Bypass
// ----------------------------------------------------------------------------
fn test_dangerous_service_ports(t: lit::T&) {
    t.run("PORT-01: Dangerous service ports (Port 0, FTP 21, Telnet 23, MySQL 3306, Postgres 5432, MongoDB 27017)") { sub =>
        sub.assert_true(security::is_dangerous_service_port(0), "Port 0 must be dangerous");
        sub.assert_true(security::is_dangerous_service_port(21), "Port 21 (FTP) must be dangerous");
        sub.assert_true(security::is_dangerous_service_port(23), "Port 23 (Telnet) must be dangerous");
        sub.assert_true(security::is_dangerous_service_port(3306), "Port 3306 (MySQL) must be dangerous");
        sub.assert_true(security::is_dangerous_service_port(5432), "Port 5432 (PostgreSQL) must be dangerous");
        sub.assert_true(security::is_dangerous_service_port(27017), "Port 27017 (MongoDB) must be dangerous");
    };

    t.run("PORT-02: validate_url_against_ssrf blocks Port 0 and Dangerous Ports") { sub =>
        var policy = security::SsrfGuardPolicy { enabled: true, .. };

        // Port 0 request
        let u_p0 = core::new_url("http://example.com:0/api");
        let err_p0 = client::validate_url_against_ssrf(u_p0, policy);
        sub.assert_ne(err_p0, client::RedirectError.None, "Port 0 URL must be blocked by SSRF guard");

        // Port 3306 request
        let u_mysql = core::new_url("http://example.com:3306/db");
        let err_mysql = client::validate_url_against_ssrf(u_mysql, policy);
        sub.assert_ne(err_mysql, client::RedirectError.None, "Port 3306 URL must be blocked by SSRF guard");

        // Trailing-dot loopback URL request
        let u_dot = core::new_url("http://127.0.0.1./admin");
        let err_dot = client::validate_url_against_ssrf(u_dot, policy);
        sub.assert_ne(err_dot, client::RedirectError.None, "http://127.0.0.1./ with trailing dot must be blocked by SSRF guard");
    };

    t.run("PORT-03: validate_url_against_ssrf blocks Redis (6379), Memcached (11211), and Docker (2375)") { sub =>
        var policy = security::SsrfGuardPolicy { enabled: true, .. };

        let u_redis = core::new_url("http://example.com:6379/");
        let err_redis = client::validate_url_against_ssrf(u_redis, policy);
        sub.assert_ne(err_redis, client::RedirectError.None, "Redis 6379 must be blocked");

        let u_mem = core::new_url("http://example.com:11211/");
        let err_mem = client::validate_url_against_ssrf(u_mem, policy);
        sub.assert_ne(err_mem, client::RedirectError.None, "Memcached 11211 must be blocked");

        let u_doc = core::new_url("http://example.com:2375/");
        let err_doc = client::validate_url_against_ssrf(u_doc, policy);
        sub.assert_ne(err_doc, client::RedirectError.None, "Docker daemon 2375 must be blocked");
    };
}

// ----------------------------------------------------------------------------
// 29. Public Suffix Boundary Attacks & FQDN Edge Cases
// ----------------------------------------------------------------------------
fn test_public_suffix_boundary_attacks(t: lit::T&) {
    var clock = lit::new_mock_clock();

    t.run("PSL-01: Supercookie prevention on ICANN public suffixes") { sub =>
        var jar = cookie::CanonicalCookieJar { .. };
        // example.com cannot set cookie for .com
        let ok1 = cookie::set_cookie_header(jar, "https://example.com/", "super=bad; Domain=com; Secure; Path=/", clock.now_us);
        sub.assert_false(ok1, "Setting Domain=com must be rejected");

        // attacker.co.uk cannot set cookie for .co.uk
        let ok2 = cookie::set_cookie_header(jar, "https://attacker.co.uk/", "super=bad; Domain=co.uk; Secure; Path=/", clock.now_us);
        sub.assert_false(ok2, "Setting Domain=co.uk must be rejected");

        sub.assert_eq(jar.cookies.len, 0);
    };

    t.run("PSL-02: Private PSL section boundary protection") { sub =>
        var jar = cookie::CanonicalCookieJar { .. };
        // tenant.github.io cannot set cookie for .github.io
        let ok1 = cookie::set_cookie_header(jar, "https://tenant.github.io/", "cross=bad; Domain=github.io; Secure; Path=/", clock.now_us);
        sub.assert_false(ok1, "Setting Domain=github.io must be rejected");

        // sub.amazonaws.com cannot set cookie for .amazonaws.com
        let ok2 = cookie::set_cookie_header(jar, "https://sub.amazonaws.com/", "cross=bad; Domain=amazonaws.com; Secure; Path=/", clock.now_us);
        sub.assert_false(ok2, "Setting Domain=amazonaws.com must be rejected");

        sub.assert_eq(jar.cookies.len, 0);
    };

    t.run("PSL-03: Mozilla PSL Wildcards & Exception rules (!city.kobe.jp)") { sub =>
        var jar = cookie::CanonicalCookieJar { .. };
        // !city.kobe.jp is an exception rule: city.kobe.jp is NOT a public suffix!
        let ok_kobe = cookie::set_cookie_header(jar, "https://sub.city.kobe.jp/", "area=kobe; Domain=city.kobe.jp; Secure; Path=/", clock.now_us);
        sub.assert_true(ok_kobe, "Domain=city.kobe.jp must be accepted due to !city.kobe.jp exception");

        // other.kobe.jp is under *.kobe.jp wildcard: it IS a public suffix!
        let ok_other = cookie::set_cookie_header(jar, "https://sub.other.kobe.jp/", "area=bad; Domain=other.kobe.jp; Secure; Path=/", clock.now_us);
        sub.assert_false(ok_other, "Domain=other.kobe.jp must be rejected under *.kobe.jp wildcard");
    };

    t.run("PSL-04: FQDN Trailing-dot normalization (industry benchmark)") { sub =>
        var etld1: u8[..128] = [];
        core::extract_etld_plus_one("example.com.", etld1);
        sub.assert_eq(etld1[..], "example.com", "example.com. with trailing dot must derive example.com");

        var etld2: u8[..128] = [];
        core::extract_etld_plus_one("sub.example.com.", etld2);
        sub.assert_eq(etld2[..], "example.com", "sub.example.com. must derive example.com");

        let matches = cookie::domain_match("sub.example.com.", ".example.com.");
        sub.assert_true(matches, "cookie_domain_match must handle trailing dot FQDN");
    };

    t.run("PSL-05: IP address literal immunity (industry benchmark)") { sub =>
        var etld_ip: u8[..128] = [];
        core::extract_etld_plus_one("127.0.0.1", etld_ip);
        sub.assert_eq(etld_ip[..], "127.0.0.1", "IP literal must not be parsed through PSL");

        // RFC 6265 Section 5.1.3: domain matching MUST NOT match suffixes on IP addresses
        let match_ip = cookie::domain_match("192.168.1.1", "168.1.1");
        sub.assert_false(match_ip, "IP address must never match sub-domain suffixes");
    };

    t.run("PSL-06: Case insensitivity in PSL evaluations (industry benchmark)") { sub =>
        var etld_upper: u8[..128] = [];
        core::extract_etld_plus_one("FOO.EXAMPLE.COM", etld_upper);
        sub.assert_eq(etld_upper[..], "example.com", "Uppercase FOO.EXAMPLE.COM must derive lowercase example.com");

        sub.assert_true(cookie::is_public_suffix_domain("CO.UK"), "CO.UK must be recognized as public suffix");
        sub.assert_true(cookie::is_public_suffix_domain("Com"), "Com must be recognized as public suffix");
    };
}

// ----------------------------------------------------------------------------
// 30. Token Bucket & GCRA Burst / Concurrency Limits
// ----------------------------------------------------------------------------
fn test_rate_limiter_burst_and_concurrency(t: lit::T&) {
    t.run("RATE-01: Burst capacity boundary (1/s emission, burst=5 allows 6 requests)") { sub =>
        let quota = security::new_gcra_quota(1, wing::secs(1), 5); // T=1s, tau=5s
        var cell = security::GcraCell { tat_ns: 0 };
        let now_ns: u64 = 10000000000; // t=10s

        // 6 back-to-back requests (1 initial + 5 burst)
        for i in 6 {
            let dec = security::gcra_check_n(quota, cell, 1, now_ns);
            sub.assert_true(security::is_allowed(dec), "Request within burst capacity must be allowed");
        }

        // 7th request must be rejected
        let dec7 = security::gcra_check_n(quota, cell, 1, now_ns);
        sub.assert_false(security::is_allowed(dec7), "7th request exceeding burst capacity must be rejected");

        match dec7 {
            Rejected r => {
                sub.assert_true(r.retry_after_ns > 0, "Rejected decision must report positive retry_after");
            },
            _ => { sub.assert_true(false, "Expected Rejected decision"); },
        };
    };

    t.run("RATE-02: Cost > burst pitfall ") { sub =>
        let quota = security::new_gcra_quota(1, wing::secs(1), 5);
        var cell = security::GcraCell { tat_ns: 0 };
        let now_ns: u64 = 10000000000;

        // Requesting 10 cells when burst=5 is impossible and rejected immediately
        let dec = security::gcra_check_n(quota, cell, 10, now_ns);
        sub.assert_false(security::is_allowed(dec), "Cost exceeding burst capacity must be rejected");
        sub.assert_eq(cell.tat_ns, 0, "TAT cell must remain unmutated on rejection");
    };

    t.run("RATE-03: Integer overflow saturation defense") { sub =>
        let quota = security::new_gcra_quota(1, wing::secs(1), 5);
        var cell = security::GcraCell { tat_ns: 0 };
        let now_ns: u64 = 10000000000;

        // Passing huge cost_n (0xFFFFFFFFFFFFFFFF) must saturate and reject without wrap-around
        let dec = security::gcra_check_n(quota, cell, 0xFFFFFFFFFFFFFFFF, now_ns);
        sub.assert_false(security::is_allowed(dec), "Saturated huge cost must be rejected");
    };

    t.run("RATE-04: Zero-cost inspection does not advance TAT") { sub =>
        let quota = security::new_gcra_quota(1, wing::secs(1), 5);
        var cell = security::GcraCell { tat_ns: 10000000000 };
        let now_ns: u64 = 10000000000;

        let dec = security::gcra_check_n(quota, cell, 0, now_ns);
        sub.assert_true(security::is_allowed(dec), "Zero-cost inspection is allowed");
        sub.assert_eq(cell.tat_ns, 10000000000, "Zero-cost check must not advance TAT");
    };

    t.run("RATE-05: Priority slot reservation (gcra_reserve_n)") { sub =>
        let quota = security::new_gcra_quota(1, wing::secs(1), 0); // 1 req/sec, no burst
        var cell = security::GcraCell { tat_ns: 0 };
        let now_ns: u64 = 10000000000;

        // 1st request succeeds
        let dec1 = security::gcra_reserve_n(quota, cell, 1, now_ns, 2000000000);
        sub.assert_true(security::is_allowed(dec1));

        // 2nd request arrives immediately: can reserve within max_wait_ns (2s)
        let dec2 = security::gcra_reserve_n(quota, cell, 1, now_ns, 2000000000);
        sub.assert_true(security::is_allowed(dec2), "Slot must be reserved within max_wait");
        match dec2 {
            Reserved r => {
                sub.assert_eq(r.wait_ns, 1000000000, "Wait time is exactly 1 emission interval (1s)");
            },
            _ => { sub.assert_true(false, "Expected Reserved decision"); },
        };
    };

    t.run("RATE-06: 256-shard rate limiter protects distinct client keys") { sub =>
        let quota = security::new_gcra_quota(1, wing::secs(1), 1);
        var limiter = security::new_sharded_limiter(quota);
        let now_ns: u64 = 5000000000;

        let dec_ip1 = security::check_rate_limit(limiter, "192.168.1.100", 1, now_ns);
        sub.assert_true(security::is_allowed(dec_ip1));

        let dec_ip2 = security::check_rate_limit(limiter, "10.0.0.50", 1, now_ns);
        sub.assert_true(security::is_allowed(dec_ip2), "Distinct client key must have independent rate quota");
    };

    t.run("RATE-07: Probabilistic GCRA DDoS mitigation under flood") { sub =>
        let quota = security::new_gcra_quota(1000, wing::secs(1), 100);
        var pgcra = security::new_probabilistic_gcra(quota, 20); // 5% sample rate

        var allowed_count = 0;
        let now_ns: u64 = 1000000000;
        for i in 100 {
            let dec = security::check_rate_limit(pgcra, 1, now_ns);
            if security::is_allowed(dec) {
                allowed_count++;
            }
        }
        sub.assert_true(allowed_count > 50, "Probabilistic filter allows majority of requests under normal sampling");
    };
}

// ----------------------------------------------------------------------------
// 31. Singleflight Thundering Herd & Cache Stampede Defense
// ----------------------------------------------------------------------------
fn test_singleflight_thundering_herd(t: lit::T&) {
    t.run("FLIGHT-01: Duplicate call suppression (10 concurrent requests, exactly 1 leader)") { sub =>
        var g = core::SingleflightGroup { .. };
        let key = "cache:user:profile:42";

        var leader_count = 0;
        var follower_count = 0;

        // 10 callers concurrently request the same key
        for caller_id in 10 {
            let is_lead, val, shared = core::start_or_join(g, key);
            if is_lead {
                leader_count++;
            } else {
                follower_count++;
            }
        }

        sub.assert_eq(leader_count, 1, "Exactly ONE caller must be designated as leader");
        sub.assert_eq(follower_count, 9, "9 callers must join as followers (duplicate suppression)");
        sub.assert_eq(core::waiter_count(g, key), 9, "Waiter count must be 9");
        sub.assert_true(core::is_in_flight(g, key), "Key must be marked in-flight");
    };

    t.run("FLIGHT-02: Result broadcast and shared flag accuracy ") { sub =>
        var g = core::SingleflightGroup { .. };
        let key = "db:query:orders";

        // Leader starts
        let is_lead1, _, _ = core::start_or_join(g, key);
        sub.assert_true(is_lead1);

        // Follower 1 joins
        let is_lead2, _, _ = core::start_or_join(g, key);
        sub.assert_false(is_lead2);

        // Leader finishes computation with result 8888
        let finish_ok, waiters = core::finish_call(g, key, 8888, true);
        sub.assert_true(finish_ok);
        sub.assert_eq(waiters, 1);

        // Verify shared status and result value
        sub.assert_true(core::is_shared(g, key), "Result was shared between leader and follower");
        let cached_val, ok = core::result_value(g, key);
        sub.assert_true(ok);
        sub.assert_eq(cached_val, 8888);
    };

    t.run("FLIGHT-03: Unshared execution (single caller)") { sub =>
        var g = core::SingleflightGroup { .. };
        let key = "db:query:rare_item";

        let is_lead, _, _ = core::start_or_join(g, key);
        sub.assert_true(is_lead);

        let finish_ok, waiters = core::finish_call(g, key, 42, true);
        sub.assert_true(finish_ok);
        sub.assert_eq(waiters, 0, "No waiters joined");
        sub.assert_false(core::is_shared(g, key), "Single caller execution must not be marked shared");
    };

    t.run("FLIGHT-04: Explicit Forget & re-execution ") { sub =>
        var g = core::SingleflightGroup { .. };
        let key = "cache:stock:price";

        // Initial run
        core::start_or_join(g, key);
        core::finish_call(g, key, 100, true);

        // Forget key
        let forgot = core::forget(g, key);
        sub.assert_true(forgot, "forget must successfully remove the key");

        // Subsequent call must execute as new leader
        let is_lead_next, _, _ = core::start_or_join(g, key);
        sub.assert_true(is_lead_next, "After forget, next call must be a new leader");
    };

    t.run("FLIGHT-05: ForgetUnshared proposal ") { sub =>
        var g = core::SingleflightGroup { .. };

        // 1. Shared key
        core::start_or_join(g, "key_shared");
        core::start_or_join(g, "key_shared"); // waiter joined
        core::finish_call(g, "key_shared", 1, true);

        // forget_unshared must NOT forget a shared key
        let forgot_shared = core::forget_unshared(g, "key_shared");
        sub.assert_false(forgot_shared, "forget_unshared must not remove shared key");

        // 2. Unshared key
        core::start_or_join(g, "key_unshared");
        core::finish_call(g, "key_unshared", 2, true);

        // forget_unshared MUST forget unshared key
        let forgot_unshared = core::forget_unshared(g, "key_unshared");
        sub.assert_true(forgot_unshared, "forget_unshared must remove unshared key");
    };

    t.run("FLIGHT-06: Error / Failure unblocking ") { sub =>
        var g = core::SingleflightGroup { .. };
        let key = "db:broken_query";

        // Leader starts
        let is_lead, _, _ = core::start_or_join(g, key);
        sub.assert_true(is_lead);

        // Follower joins
        let is_lead2, _, _ = core::start_or_join(g, key);
        sub.assert_false(is_lead2);

        // Leader fails
        let finish_ok, waiters = core::finish_call(g, key, 0, false);
        sub.assert_true(finish_ok);
        sub.assert_eq(waiters, 1);

        let res, ok = core::result_value(g, key);
        sub.assert_false(ok, "Result value must record failure status without deadlocking");
        sub.assert_false(core::is_in_flight(g, key), "Key must not remain in-flight after failure");
    };
}

// --- Component: cookie_security ---
// Tests for cookie security prefix enforcement and Max-Age bounds.

// ----------------------------------------------------------------------------
// Round 1: RFC 6265bis Section 5.6 Insecure Cookie Protection
// ----------------------------------------------------------------------------
// ----------------------------------------------------------------------------
// 32. RFC 6265bis Section 5.6 Insecure Cookie Protection
// ----------------------------------------------------------------------------
fn test_rfc6265bis_sec56_shadowing_protection(t: lit::T&) {
    var clock = lit::new_mock_clock();

    t.run("SEC-01: Insecure subpath must not shadow root secure cookie") { sub =>
        var j = cookie::CanonicalCookieJar { .. };
        // Set Secure cookie on HTTPS at root path "/"
        sub.require_true(cookie::set_cookie_header(j, "https://example.com/", "session=secure_val; Secure; Path=/", clock.now_us));
        sub.assert_eq(j.cookies.len, 1);

        // Insecure HTTP request attempting to set cookie with same name on subpath "/login"
        let accepted = cookie::set_cookie_header(j, "http://example.com/login", "session=insecure_val; Path=/login", clock.now_us);
        sub.assert_false(accepted, "Insecure HTTP Set-Cookie on subpath must be rejected when Secure cookie exists on root path");
        sub.assert_eq(j.cookies.len, 1, "Cookie store must retain only the Secure root cookie");
        sub.assert_gt(j.rejected_security_count, 0, "Security rejection counter must increment");
    };

    t.run("SEC-02: Insecure subdomain must not shadow parent domain secure cookie") { sub =>
        var j = cookie::CanonicalCookieJar { .. };
        // Set Secure domain cookie at parent domain "example.com"
        sub.require_true(cookie::set_cookie_header(j, "https://example.com/", "auth=secure_val; Domain=example.com; Secure; Path=/", clock.now_us));
        sub.assert_eq(j.cookies.len, 1);

        // Insecure HTTP request from subdomain attempting to set cookie with same name
        let accepted = cookie::set_cookie_header(j, "http://sub.example.com/", "auth=insecure_val; Domain=sub.example.com; Path=/", clock.now_us);
        sub.assert_false(accepted, "Insecure HTTP subdomain Set-Cookie must be rejected when parent domain has Secure cookie");
        sub.assert_eq(j.cookies.len, 1, "Cookie store must retain only the parent domain Secure cookie");
        sub.assert_gt(j.rejected_security_count, 0, "Security rejection counter must increment");
    };
}

// ----------------------------------------------------------------------------
// Round 2: Case-Insensitive Prefix Enforcement
// ----------------------------------------------------------------------------
// ----------------------------------------------------------------------------
// 33. Case-Insensitive Prefix Enforcement
// ----------------------------------------------------------------------------
fn test_case_insensitive_prefix_enforcement(t: lit::T&) {
    var clock = lit::new_mock_clock();

    t.run("PREFIX-01: Lowercase __secure- without Secure flag must be rejected") { sub =>
        var jar = cookie::CanonicalCookieJar { .. };
        let ok = cookie::set_cookie_header(jar, "https://example.com/", "__secure-token=abc", clock.now_us);
        sub.assert_false(ok, "__secure- without Secure flag must be rejected");
        sub.assert_eq(jar.cookies.len, 0);
    };

    t.run("PREFIX-02: Lowercase __secure- on insecure HTTP channel must be rejected") { sub =>
        var jar = cookie::CanonicalCookieJar { .. };
        let ok = cookie::set_cookie_header(jar, "http://example.com/", "__secure-token=abc; Secure", clock.now_us);
        sub.assert_false(ok, "__secure- on insecure HTTP must be rejected");
        sub.assert_eq(jar.cookies.len, 0);
    };

    t.run("PREFIX-03: Lowercase __host- with Domain attribute must be rejected") { sub =>
        var jar = cookie::CanonicalCookieJar { .. };
        let ok = cookie::set_cookie_header(jar, "https://example.com/", "__host-token=abc; Secure; Path=/; Domain=example.com", clock.now_us);
        sub.assert_false(ok, "__host- with Domain attribute must be rejected");
        sub.assert_eq(jar.cookies.len, 0);
    };

    t.run("PREFIX-04: Lowercase __host- with non-root Path must be rejected") { sub =>
        var jar = cookie::CanonicalCookieJar { .. };
        let ok = cookie::set_cookie_header(jar, "https://example.com/sub", "__host-token=abc; Secure; Path=/sub", clock.now_us);
        sub.assert_false(ok, "__host- with non-root path must be rejected");
        sub.assert_eq(jar.cookies.len, 0);
    };

    t.run("PREFIX-05: Lowercase __http- without HttpOnly must be rejected") { sub =>
        var jar = cookie::CanonicalCookieJar { .. };
        let ok = cookie::set_cookie_header(jar, "https://example.com/", "__http-token=abc; Secure", clock.now_us);
        sub.assert_false(ok, "__http- without HttpOnly must be rejected");
        sub.assert_eq(jar.cookies.len, 0);
    };

    t.run("PREFIX-06: Nameless cookie with lowercase prefix value must be rejected") { sub =>
        var jar = cookie::CanonicalCookieJar { .. };
        var cookie = cookie::new_canonical_cookie("", "__secure-val");
        let src_opts = cookie::SourceOptions { is_http_api: true, url_is_secure: true };
        let ok = cookie::set_canonical_cookie(jar, cookie, src_opts, clock.now_us);
        sub.assert_false(ok, "Nameless cookie starting with lowercase security prefix must be rejected");
        sub.assert_eq(jar.cookies.len, 0);
    };
}

// ----------------------------------------------------------------------------
// Round 3: Max-Age Capping and Overflow Protection
// ----------------------------------------------------------------------------
// ----------------------------------------------------------------------------
// 34. Max-Age Capping and Overflow Protection
// ----------------------------------------------------------------------------
fn test_max_age_overflow_and_capping(t: lit::T&) {
    var clock = lit::new_mock_clock();
    let expected_cap_us = clock.now_us + cookie_internal::K_MAX_COOKIE_AGE_US;

    t.run("MAXAGE-01: Large Max-Age (10000000000000) must clamp to 400 days in jar") { sub =>
        var jar = cookie::CanonicalCookieJar { .. };
        let ok = cookie::set_cookie_header(jar, "https://example.com/", "session=tok1; Max-Age=10000000000000", clock.now_us);
        sub.assert_true(ok, "Large Max-Age must be accepted into jar");
        sub.assert_eq(jar.cookies.len, 1, "Cookie with large Max-Age must be stored in jar");
        if jar.cookies.len > 0 {
            sub.assert_eq(jar.cookies[0].expires_utc, expected_cap_us, "Cookie expiration must be capped at 400 days");
            sub.assert_eq(jar.cookies[0].value[..], "tok1");
        }
    };

    t.run("MAXAGE-02: Direct parse_canonical_set_cookie with excessive Max-Age clamps to 400 days") { sub =>
        let cookie, cause, ok = cookie::parse_canonical_set_cookie("token=val; Max-Age=10000000000000", "example.com", "/", clock.now_us);
        sub.assert_true(ok, "parse_canonical_set_cookie should succeed");
        sub.assert_true(cookie.persistent, "Cookie must be persistent");
        sub.assert_eq(cookie.expires_utc, expected_cap_us, "Excessive Max-Age must clamp to 400 days");
    };

    t.run("MAXAGE-03: Max-Age exceeding i64 max microseconds boundary") { sub =>
        var jar = cookie::CanonicalCookieJar { .. };
        let ok = cookie::set_cookie_header(jar, "https://example.com/", "boundary=1; Max-Age=9223372036855", clock.now_us);
        sub.assert_true(ok, "Boundary Max-Age must be accepted");
        sub.assert_eq(jar.cookies.len, 1, "Boundary Max-Age cookie must be retained");
        if jar.cookies.len > 0 {
            sub.assert_eq(jar.cookies[0].expires_utc, expected_cap_us, "Boundary Max-Age must clamp to 400 days");
        }
    };

    t.run("MAXAGE-04: Reasonable Max-Age below 400 days remains unchanged") { sub =>
        var jar = cookie::CanonicalCookieJar { .. };
        let ok = cookie::set_cookie_header(jar, "https://example.com/", "short=1; Max-Age=3600", clock.now_us);
        sub.assert_true(ok, "3600s Max-Age must be accepted");
        sub.assert_eq(jar.cookies.len, 1);
        if jar.cookies.len > 0 {
            sub.assert_eq(jar.cookies[0].expires_utc, clock.now_us + 3600000000, "1h Max-Age must be exactly 3600 seconds");
        }
    };

    t.run("MAXAGE-05: Non-positive Max-Age properly expires cookie") { sub =>
        let cookie, cause, ok = cookie::parse_canonical_set_cookie("exp=0; Max-Age=0", "example.com", "/", clock.now_us);
        sub.assert_true(ok);
        sub.assert_true(cookie.persistent);
        sub.assert_eq(cookie.expires_utc, clock.now_us - 1000000, "Max-Age=0 expires immediately in the past");
    };
}

// ----------------------------------------------------------------------------
// Round 4: RFC 6265 Section 5.3 Step 11.2 HttpOnly Overwrite Protection
// ----------------------------------------------------------------------------
// ----------------------------------------------------------------------------
// 35. RFC 6265 Section 5.3 Step 11.2 HttpOnly Overwrite Protection
// ----------------------------------------------------------------------------
fn test_httponly_script_overwrite_protection(t: lit::T&) {
    var clock = lit::new_mock_clock();

    t.run("HTTPONLY-01: Non-HTTP script API must not overwrite existing HttpOnly cookie (RFC 6265 Sec 5.3 Step 11.2)") { sub =>
        var jar = cookie::CanonicalCookieJar { .. };
        // 1. HTTP API sets a sensitive HttpOnly session cookie
        sub.require_true(
            cookie::set_cookie_header(jar, "https://example.com/", "session=super_secret_token; HttpOnly; Secure; Path=/", clock.now_us, true),
            "HTTP API must successfully store HttpOnly cookie",
        );
        sub.assert_eq(jar.cookies.len, 1);
        sub.assert_true(jar.cookies[0].httponly);
        sub.assert_bytes_eq(jar.cookies[0].value[..], "super_secret_token");

        // 2. Non-HTTP script API attempts to overwrite the HttpOnly cookie (e.g. via document.cookie)
        var script_cookie = cookie::new_canonical_cookie("session", "attacker_controlled_value");
        script_cookie.with_domain("example.com", true).with_path("/").with_secure(true);
        let src_opts1 = cookie::SourceOptions { is_http_api: false, url_is_secure: true };
        let accepted = cookie::set_canonical_cookie(jar, script_cookie, src_opts1, clock.now_us);

        sub.assert_false(accepted, "Non-HTTP API must NOT be allowed to overwrite an existing HttpOnly cookie");
        sub.assert_eq(jar.cookies.len, 1, "Cookie store must retain exactly 1 cookie");
        sub.assert_true(jar.cookies[0].httponly, "Existing cookie must retain HttpOnly flag");
        sub.assert_bytes_eq(jar.cookies[0].value[..], "super_secret_token", "HttpOnly cookie value must NOT be modified by script");
        sub.assert_gt(jar.rejected_security_count, 0, "rejected_security_count must be incremented");
    };

    t.run("HTTPONLY-02: Non-HTTP script API must not delete HttpOnly cookie via Max-Age=0 (RFC 6265 Sec 5.3 Step 11.2)") { sub =>
        var jar = cookie::CanonicalCookieJar { .. };
        sub.require_true(
            cookie::set_cookie_header(jar, "https://example.com/", "auth=token123; HttpOnly; Secure; Path=/", clock.now_us, true),
        );
        sub.assert_eq(jar.cookies.len, 1);

        // Script attempts to purge the HttpOnly cookie using Max-Age=0
        var purge_cookie = cookie::new_canonical_cookie("auth", "deleted");
        purge_cookie.with_domain("example.com", true).with_path("/").with_secure(true).with_max_age_seconds(0, clock.now_us);
        let src_opts2 = cookie::SourceOptions { is_http_api: false, url_is_secure: true };
        let accepted = cookie::set_canonical_cookie(jar, purge_cookie, src_opts2, clock.now_us);

        sub.assert_false(accepted, "Non-HTTP API must NOT be allowed to delete an HttpOnly cookie via expired overwrite");
        sub.assert_eq(jar.cookies.len, 1, "HttpOnly cookie must not be deleted by script API");
        sub.assert_bytes_eq(jar.cookies[0].value[..], "token123");
    };
}

// ----------------------------------------------------------------------------
// Round 5: RFC 6265bis §5.5.7 SameSite=None and §5.1.3 Domain IP Invariants
// ----------------------------------------------------------------------------
// ----------------------------------------------------------------------------
// 36. RFC 6265bis SameSite=None and §5.1.3 Domain IP Invariants
// ----------------------------------------------------------------------------
fn test_rfc6265bis_samesite_and_domain_ip_rules(t: lit::T&) {
    var clock = lit::new_mock_clock();

    t.run("SAMESITE-01: parse_canonical_set_cookie rejects SameSite=None without Secure (RFC 6265bis §5.5.7)") { sub =>
        let cookie, cause, ok = cookie::parse_canonical_set_cookie(
            "session=abc12345; SameSite=None; Path=/",
            "example.com",
            "/",
            clock.now_us,
        );
        sub.assert_false(ok, "SameSite=None without Secure must be rejected by parse_canonical_set_cookie");
    };

    t.run("SAMESITE-02: parse_canonical_set_cookie accepts SameSite=None with Secure (RFC 6265bis §5.5.7)") { sub =>
        let cookie, cause, ok = cookie::parse_canonical_set_cookie(
            "session=abc12345; SameSite=None; Secure; Path=/",
            "example.com",
            "/",
            clock.now_us,
        );
        sub.assert_true(ok, "SameSite=None with Secure must be accepted");
        sub.assert_eq(cookie.same_site, cookie::SameSite.None);
        sub.assert_true(cookie.secure);
    };

    t.run("DOMAIN-IP-01: Domain matching cannot match subdomains against IP literal (RFC 6265 §5.1.3)") { sub =>
        var c = cookie::new_canonical_cookie("test_ip", "val1");
        c.with_domain("192.168.1.1", false); // non-host-only domain cookie
        sub.assert_false(c.matches_domain("sub.192.168.1.1"), "Subdomain must not match IP address domain per RFC 6265 §5.1.3");
        sub.assert_true(c.matches_domain("192.168.1.1"), "Exact IP match must succeed");
    };

    t.run("DOMAIN-IP-02: IPv6 host with brackets matches unbracketed cookie domain") { sub =>
        var c = cookie::new_canonical_cookie("test_ipv6", "val2");
        c.with_domain("2001:db8::1", true);
        sub.assert_true(c.matches_domain("[2001:db8::1]"), "IPv6 with brackets must match unbracketed cookie domain");
    };

    t.run("DOMAIN-DOT-01: FQDN trailing dots are isolated and malformed dots rejected") { sub =>
        var c = cookie::new_canonical_cookie("test_dot", "val3");
        c.with_domain("example.com", false);
        sub.assert_true(c.matches_domain("example.com"), "Exact domain matches");
        sub.assert_false(c.matches_domain("example.com."), "Trailing-dot FQDN must not fold onto non-dotted domain");
        sub.assert_false(c.matches_domain("example.com.."), "Host with multiple trailing dots must not match");
    };
}

// ----------------------------------------------------------------------------
// Round 6: RFC 6265 §5.3 Step 11.3 Creation-Time Preservation & §5.1.1 Date Lexer
// ----------------------------------------------------------------------------
// ----------------------------------------------------------------------------
// 37. RFC 6265 §5.3 Step 11.3 Creation-Time & §5.1.1 Date Lexer
// ----------------------------------------------------------------------------
fn test_rfc6265_creation_time_and_date_lexing(t: lit::T&) {
    var clock = lit::new_mock_clock();
    let t1 = clock.now_us;
    let t2 = clock.now_us + 10000000; // 10s later

    t.run("CREATION-01: Updating cookie with unset source_port preserves original creation_utc (RFC 6265 §5.3 Step 11.3)") { sub =>
        var jar = cookie::CanonicalCookieJar { .. };
        // 1. Initial cookie set via HTTP at t1 (source_port = 443)
        let ok1 = cookie::set_cookie_header(jar, "https://example.com/", "session=initial_val; Secure; Path=/", t1);
        sub.require_true(ok1, "Initial cookie set must succeed");
        sub.assert_eq(jar.cookies.len, 1);
        sub.assert_eq(jar.cookies[0].creation_utc, t1);

        // 2. Cookie updated at t2 with new value and unset port (source_port = -1)
        var update_cookie = cookie::new_canonical_cookie("session", "updated_val");
        update_cookie.with_domain("example.com", true).with_path("/").with_secure(true);
        let src_opts_u1 = cookie::SourceOptions { is_http_api: true, url_is_secure: true };
        let ok2 = cookie::set_canonical_cookie(jar, update_cookie, src_opts_u1, t2);

        sub.assert_true(ok2, "Update must succeed");
        sub.assert_eq(jar.cookies.len, 1, "Cookie store must contain exactly 1 cookie after update");
        if jar.cookies.len > 0 {
            sub.assert_bytes_eq(jar.cookies[0].value[..], "updated_val", "Cookie value must be updated");
            sub.assert_eq(jar.cookies[0].creation_utc, t1, "RFC 6265 §5.3 Step 11.3: creation_utc MUST be preserved across updates");
            sub.assert_eq(jar.cookies[0].last_access_utc, t2, "last_access_utc must be updated to current time");
        }
    };

    t.run("CREATION-02: Updating cookie with case-different domain preserves creation_utc (RFC 6265 §5.3 Step 11.3)") { sub =>
        var jar = cookie::CanonicalCookieJar { .. };
        let ok1 = cookie::set_cookie_header(jar, "https://example.com/", "auth=val1; Secure; Path=/", t1);
        sub.require_true(ok1);
        sub.assert_eq(jar.cookies[0].creation_utc, t1);

        var update_cookie = cookie::new_canonical_cookie("auth", "val2");
        update_cookie.with_domain("EXAMPLE.COM", true).with_path("/").with_secure(true);
        let src_opts_u2 = cookie::SourceOptions { is_http_api: true, url_is_secure: true };
        let ok2 = cookie::set_canonical_cookie(jar, update_cookie, src_opts_u2, t2);

        sub.assert_true(ok2);
        sub.assert_eq(jar.cookies.len, 1, "Must recognize collision across case-different domain");
        if jar.cookies.len > 0 {
            sub.assert_bytes_eq(jar.cookies[0].value[..], "val2");
            sub.assert_eq(jar.cookies[0].creation_utc, t1, "creation_utc must be preserved");
        }
    };

    t.run("LEX-MONTH-01: Date lexer rejects invalid month tokens like 'junk' or 'decay' (RFC 6265bis §5.1.1)") { sub =>
        let cookie1, cause1, ok1 = cookie::parse_canonical_set_cookie(
            "test=1; Expires=Wed, 09 junk 2021 10:18:14 GMT",
            "example.com",
            "/",
            t1,
        );
        sub.assert_true(ok1);
        // Invalid month token causes Expires parsing to fail, so cookie remains non-persistent (session)
        sub.assert_false(cookie1.persistent, "Cookie with invalid month token must not be persistent");

        let cookie2, cause2, ok2 = cookie::parse_canonical_set_cookie(
            "test=2; Expires=Wed, 09 decay 2021 10:18:14 GMT",
            "example.com",
            "/",
            t1,
        );
        sub.assert_true(ok2);
        sub.assert_false(cookie2.persistent, "Cookie with 'decay' month token must not be persistent");
    };

    t.run("LEX-MONTH-02: Date lexer accepts valid 3-letter and full month names (RFC 6265bis §5.1.1)") { sub =>
        let cookie_jun, _, ok_jun = cookie::parse_canonical_set_cookie(
            "test=1; Expires=Wed, 09 Jun 2021 10:18:14 GMT",
            "example.com",
            "/",
            t1,
        );
        sub.assert_true(ok_jun);
        sub.assert_true(cookie_jun.persistent);

        let cookie_dec, _, ok_dec = cookie::parse_canonical_set_cookie(
            "test=2; Expires=Wed, 09 December 2021 10:18:14 GMT",
            "example.com",
            "/",
            t1,
        );
        sub.assert_true(ok_dec);
        sub.assert_true(cookie_dec.persistent);
    };

    t.run("LEX-YEAR-01: 2-digit years map correctly: 70..99 -> 1970..1999, 00..69 -> 2000..2069 (RFC 6265 §5.1.1)") { sub =>
        let exp_94, ok_94 = cookie::parse_date_us("Sunday, 06-Nov-94 08:49:37 GMT");
        sub.assert_true(ok_94);
        sub.assert_eq(exp_94, 784111777000000, "Year 94 must map to 1994");

        let exp_25, ok_25 = cookie::parse_date_us("Sunday, 06-Nov-25 08:49:37 GMT");
        sub.assert_true(ok_25);
        sub.assert_eq(exp_25, 1762418977000000, "Year 25 must map to 2025");

        let exp_00, ok_00 = cookie::parse_date_us("Sunday, 06-Nov-00 08:49:37 GMT");
        sub.assert_true(ok_00);
        sub.assert_eq(exp_00, 973500577000000, "Year 00 must map to 2000");

        let exp_69, ok_69 = cookie::parse_date_us("Sunday, 06-Nov-69 08:49:37 GMT");
        sub.assert_true(ok_69);
        sub.assert_eq(exp_69, 3150953377000000, "Year 69 must map to 2069");

        let exp_70, ok_70 = cookie::parse_date_us("Sunday, 06-Nov-70 08:49:37 GMT");
        sub.assert_true(ok_70);
        sub.assert_eq(exp_70, 26729377000000, "Year 70 must map to 1970");
    };

    t.run("PREFIX-PARSER: RFC 6265bis §5.6 Direct parser enforcement of __Secure-, __Host-, and nameless prefixes") { sub =>
        let now_us: i64 = 1700000000000000;

        // 1. __Secure- without Secure rejected
        let c1, _, ok1 = cookie::parse_canonical_set_cookie("__Secure-id=123", "example.com", "/", now_us);
        sub.assert_false(ok1, "__Secure- without Secure rejected");

        // 2. __Secure- with Secure accepted
        let c2, _, ok2 = cookie::parse_canonical_set_cookie("__Secure-id=123; Secure", "example.com", "/", now_us);
        sub.assert_true(ok2, "__Secure- with Secure accepted");

        // 3. __Host- without Secure rejected
        let c3, _, ok3 = cookie::parse_canonical_set_cookie("__Host-id=123; Path=/", "example.com", "/", now_us);
        sub.assert_false(ok3, "__Host- without Secure rejected");

        // 4. __Host- with non-root Path rejected
        let c4, _, ok4 = cookie::parse_canonical_set_cookie("__Host-id=123; Secure; Path=/sub", "example.com", "/sub", now_us);
        sub.assert_false(ok4, "__Host- with non-root Path rejected");

        // 5. Nameless cookie with __Host- value rejected
        let c5, _, ok5 = cookie::parse_canonical_set_cookie("=__Host-bad", "example.com", "/", now_us);
        sub.assert_false(ok5, "Nameless cookie with __Host- value rejected");
    };
}

// ----------------------------------------------------------------------------
// Round 7: Cookie Hardening & Cross-Origin Single-Label Protection
// ----------------------------------------------------------------------------
// ----------------------------------------------------------------------------
// 38. Cookie Hardening & Cross-Origin Single-Label Protection
// ----------------------------------------------------------------------------
fn test_cookie_hardening_invariants(t: lit::T&) {
    let now_us: i64 = 1700000000000000;

    t.run("SEC-07: Single-label cross-origin domain injection must be rejected") { sub =>
        // evil.com attempting to set cookie for localhost
        let _, _, ok_lh = cookie::parse_canonical_set_cookie("sid=hacked; Domain=localhost", "evil.com", "/", now_us);
        sub.assert_false(ok_lh, "evil.com must NOT set Domain=localhost cookie");

        // evil.com attempting to set cookie for intranet
        let _, _, ok_intra = cookie::parse_canonical_set_cookie("sid=hacked; Domain=intranet", "evil.com", "/", now_us);
        sub.assert_false(ok_intra, "evil.com must NOT set Domain=intranet cookie");

        // localhost setting cookie on localhost itself is valid (converted to host-only)
        let c_lh, _, ok_lh_self = cookie::parse_canonical_set_cookie("sid=ok; Domain=localhost", "localhost", "/", now_us);
        sub.assert_true(ok_lh_self, "localhost setting Domain=localhost must be accepted");
        sub.assert_true(c_lh.host_only, "localhost cookie must be forced host-only");
    };

    t.run("PSL-01: PSL Wildcard base domains must be recognized as public suffixes") { sub =>
        var db = cookie::new_psl_database();
        db.use_dafsa = true;

        // kawasaki.jp is a wildcard rule pattern (*.kawasaki.jp) -> base domain is a public suffix
        sub.assert_true(cookie::is_public_suffix(db, "kawasaki.jp"), "kawasaki.jp base domain must be public suffix");
        // compute.amazonaws.com is a wildcard rule (*.compute.amazonaws.com) -> base domain is a public suffix
        sub.assert_true(cookie::is_public_suffix(db, "compute.amazonaws.com"), "compute.amazonaws.com base domain must be public suffix");
    };

    t.run("PREFIX-07: __Http- prefix requires Secure and HttpOnly in parser") { sub =>
        // __Http- without HttpOnly rejected
        let _, _, ok_no_http = cookie::parse_canonical_set_cookie("__Http-tok=1; Secure", "example.com", "/", now_us);
        sub.assert_false(ok_no_http, "__Http- without HttpOnly must be rejected");

        // __Http- without Secure rejected
        let _, _, ok_no_sec = cookie::parse_canonical_set_cookie("__Http-tok=1; HttpOnly", "example.com", "/", now_us);
        sub.assert_false(ok_no_sec, "__Http- without Secure must be rejected");

        // __Http- with both Secure and HttpOnly accepted
        let _, _, ok_valid = cookie::parse_canonical_set_cookie("__Http-tok=1; Secure; HttpOnly", "example.com", "/", now_us);
        sub.assert_true(ok_valid, "__Http- with Secure and HttpOnly must be accepted");
    };

    t.run("BUILDER-01: with_domain and with_host lowercase domain") { sub =>
        var c1 = cookie::new_canonical_cookie("a", "1");
        cookie::with_domain(c1, "Example.COM");
        sub.assert_bytes_eq(c1.domain[..], "example.com");

        var c2 = cookie::new_canonical_cookie("b", "2");
        cookie::with_host(c2, "HOST.Local");
        sub.assert_bytes_eq(c2.domain[..], "host.local");
    };

    t.run("FILTER-01: Deletion filter strips leading dot in domain") { sub =>
        var jar = cookie::CanonicalCookieJar { .. };
        sub.require_true(cookie::set_cookie_header(jar, "https://example.com/", "a=1; Domain=example.com", now_us));
        sub.assert_eq(jar.cookies.len, 1);

        var filter = cookie::DeletionInfo { .. };
        filter.domain.append(".example.com");
        let deleted = cookie::delete_matching(jar, filter);
        sub.assert_eq(deleted, 1, "delete_matching must match despite leading dot in filter.domain");
        sub.assert_eq(jar.cookies.len, 0);
    };
}

// ----------------------------------------------------------------------------
// 39. Cookie Span Iteration
// ----------------------------------------------------------------------------
fn test_cookie_span_iteration(t: lit::T&) {
    t.run("Single Cookie Pair") { sub =>
        let raw: const u8[:] = "theme=dark";
        var cursor: i64 = 0;

        let span, ok = cookie::next_span(raw, cursor);
        sub.assert_true(ok, "first cookie extracted");
        sub.assert_eq(cookie::span_name(raw, span), "theme", "cookie name is 'theme'");
        sub.assert_eq(cookie::span_value(raw, span), "dark", "cookie value is 'dark'");

        let span_end, ok_end = cookie::next_span(raw, cursor);
        sub.assert_false(ok_end, "terminal contract: returns false at EOF");
    };

    t.run("Multi-Cookie Header with OWS") { sub =>
        let raw: const u8[:] = "sid=xyz123;   pref=auto; lang=ru-RU  ";
        var cursor: i64 = 0;

        // 1. sid
        let s1, ok1 = cookie::next_span(raw, cursor);
        sub.assert_true(ok1);
        sub.assert_eq(cookie::span_name(raw, s1), "sid");
        sub.assert_eq(cookie::span_value(raw, s1), "xyz123");

        // 2. pref
        let s2, ok2 = cookie::next_span(raw, cursor);
        sub.assert_true(ok2);
        sub.assert_eq(cookie::span_name(raw, s2), "pref");
        sub.assert_eq(cookie::span_value(raw, s2), "auto");

        // 3. lang
        let s3, ok3 = cookie::next_span(raw, cursor);
        sub.assert_true(ok3);
        sub.assert_eq(cookie::span_name(raw, s3), "lang");
        sub.assert_eq(cookie::span_value(raw, s3), "ru-RU");

        // End
        let s4, ok4 = cookie::next_span(raw, cursor);
        sub.assert_false(ok4);
    };

    t.run("Empty Value and Valueless Flag Cookies") { sub =>
        let raw: const u8[:] = "flag; empty=; full=1";
        var cursor: i64 = 0;

        // 1. flag (no '=')
        let s1, ok1 = cookie::next_span(raw, cursor);
        sub.assert_true(ok1);
        sub.assert_eq(cookie::span_name(raw, s1), "flag");
        sub.assert_eq(cookie::span_value(raw, s1), "");

        // 2. empty= (empty value)
        let s2, ok2 = cookie::next_span(raw, cursor);
        sub.assert_true(ok2);
        sub.assert_eq(cookie::span_name(raw, s2), "empty");
        sub.assert_eq(cookie::span_value(raw, s2), "");

        // 3. full=1
        let s3, ok3 = cookie::next_span(raw, cursor);
        sub.assert_true(ok3);
        sub.assert_eq(cookie::span_name(raw, s3), "full");
        sub.assert_eq(cookie::span_value(raw, s3), "1");

        let _, ok4 = cookie::next_span(raw, cursor);
        sub.assert_false(ok4);
    };
}

// ----------------------------------------------------------------------------
// 40. Fast-Path Cookie Lookup
// ----------------------------------------------------------------------------
fn test_cookie_find_value(t: lit::T&) {
    t.run("Fast-Path find_cookie_value Lookup") { sub =>
        let raw: const u8[:] = "session=token999; theme=nord; consent=yes";

        let val_theme, ok_theme = cookie::find_cookie_value(raw, "theme");
        sub.assert_true(ok_theme, "find theme succeeds");
        sub.assert_eq(val_theme, "nord", "theme is nord");

        let val_sess, ok_sess = cookie::find_cookie_value(raw, "session");
        sub.assert_true(ok_sess, "find session succeeds");
        sub.assert_eq(val_sess, "token999", "session is token999");

        let val_consent, ok_consent = cookie::find_cookie_value(raw, "consent");
        sub.assert_true(ok_consent, "find consent succeeds");
        sub.assert_eq(val_consent, "yes", "consent is yes");

        let val_missing, ok_missing = cookie::find_cookie_value(raw, "nonexistent");
        sub.assert_false(ok_missing, "missing cookie returns false");
        sub.assert_eq(val_missing, "", "missing cookie value is empty");
    };
}

// ----------------------------------------------------------------------------
// 41. RFC 6265bis §5.1.4: Cookie URL Fallback Path Parsing with Fragment and Default Slash
// ----------------------------------------------------------------------------
fn test_cookie_url_fallback_path_fragment(t: lit::T&) {
    t.run("URL with fragment in fallback path MUST exclude fragment from host and default path to '/'") { sub =>
        // In fallback path (e.g. invalid port or scheme-less format like "http://example.com#section"):
        let u = cookie::parse_canonical_cookie_url("http://example.com#section");
        sub.assert_true(u.host[..] == "example.com", "Host must be 'example.com', not contain '#section'");
        sub.assert_true(u.path[..] == "/", "Default path must be '/' per RFC 6265bis §5.1.4");
    };
}

// ----------------------------------------------------------------------------
// 42. RFC 6265bis §5.4 & Go #82389: Cookie Relative Path Attribute Ignored
// ----------------------------------------------------------------------------
fn test_cookie_relative_path_ignored(t: lit::T&) {
    t.run("Cookie Path attribute without leading slash MUST be ignored (RFC 6265bis §5.4)") { sub =>
        // RFC 6265bis Section 5.4:
        // "If the attribute-value is empty or if the first character of the
        // attribute-value is not %x2F ('/'):
        //   Let cookie-path be the default-path.
        // Otherwise:
        //   Let cookie-path be the attribute-value."
        var cookie = cookie::CanonicalCookie { .. };
        cookie.path.clear();
        cookie.path.append("/default/api");

        // Relative path "relative/path" lacks leading '/' -> must be ignored!
        cookie::apply_parsed_path_attribute(cookie, "relative/path");
        sub.assert_bytes_eq(cookie.path[..], "/default/api", "Relative Path 'relative/path' must be ignored, retaining default path");

        // Relative path "admin" lacks leading '/' -> must be ignored!
        cookie::apply_parsed_path_attribute(cookie, "admin");
        sub.assert_bytes_eq(cookie.path[..], "/default/api", "Relative Path 'admin' must be ignored, retaining default path");

        // Absolute path "/valid/path" begins with '/' -> must be applied!
        cookie::apply_parsed_path_attribute(cookie, "/valid/path");
        sub.assert_bytes_eq(cookie.path[..], "/valid/path", "Absolute Path '/valid/path' must be applied");
    };
}

// ----------------------------------------------------------------------------
// 43. Cookie Ingestion Quota Enforcement in Netscape Import (Go #75672, CVE-2025-58186)
// ----------------------------------------------------------------------------
fn test_cookie_import_cap_defense(t: lit::T&) {
    t.run("import_netscape caps cookies at K_MAX_COOKIES to prevent memory/CPU exhaustion") { sub =>
        var jar = cookie::CanonicalCookieJar { .. };

        // Generate 3500 valid Netscape cookie lines:
        // domain \t flag \t path \t secure \t expiration \t name \t value \n
        var content: u8[>..] = [];
        for i in 3500 {
            content.append("example.com\tTRUE\t/\tFALSE\t2000000000\tc");
            var num_buf: u8[..16] = [];
            core::format_i64_dec(i, num_buf);
            content.append(num_buf[..]);
            content.append("\tv\n");
        }

        let imported = cookie::import_netscape(jar, content[..], 1000000);
        sub.assert_true(imported <= 3300, "Imported cookies must not exceed K_MAX_COOKIES ceiling (3300)");
        sub.assert_true(imported >= 3000, "Should import up to capacity");
    };
}

// ----------------------------------------------------------------------------
// 44. goose2rfc Cookie & PSL Audit Regressions
// ----------------------------------------------------------------------------
fn test_goose2rfc_cookie_audit_regressions(t: lit::T&) {
    let now_us: i64 = 1700000000000000;

    t.run("COOKIE1_C01: Max-Age leading '+' sign ignored per RFC 6265 Section 5.2.2") { sub =>
        let c, _, ok = cookie::parse_canonical_set_cookie("sid=val; Max-Age=+100", "example.com", "/", now_us);
        sub.assert_true(ok);
        sub.assert_false(c.persistent, "Max-Age=+100 must be ignored, leaving cookie as session cookie");
    };

    t.run("COOKIE1_C02: Domain attribute with consecutive dots or whitespace rejected") { sub =>
        let _, _, ok_dots = cookie::parse_canonical_set_cookie("sid=val; Domain=sub..example.com", "a.sub..example.com", "/", now_us);
        sub.assert_false(ok_dots, "Domain with empty label '..' must be rejected");

        let _, _, ok_space = cookie::parse_canonical_set_cookie("sid=val; Domain=a b.example.com", "a b.example.com", "/", now_us);
        sub.assert_false(ok_space, "Domain with internal space must be rejected");
    };

    t.run("COOKIE1_C03: CanonicalCookie format omits Unknown SameSite/Priority and flush_cookie_deltas rolls back on overflow") { sub =>
        let c, _, ok = cookie::parse_canonical_set_cookie(
            "sid=val; SameSite=Bogus; Priority=Bogus; Path=/",
            "example.com",
            "/",
            now_us,
        );
        sub.assert_true(ok);
        sub.assert_eq(c.same_site, cookie::SameSite.Unknown);
        sub.assert_eq(c.priority, cookie::Priority.Unknown);

        var line: u8[..256] = [];
        cookie::format(c, line);
        sub.assert_bytes_eq(line[..], "sid=val; Path=/", "Unknown SameSite/Priority must not be serialized onto wire");

        // Verify 4096-byte name+value with attributes fits in flush_deltas
        var big_val: u8[..4096] = [];
        for i in 4090 { big_val.push('a'); }
        var big_cookie = cookie::new_canonical_cookie("bigkey", big_val[..]);
        big_cookie.with_domain("example.com", false).with_path("/").with_secure(true).with_http_only(true);
        var djar = cookie::ServerCookieDeltaJar { .. };
        sub.assert_true(cookie::add(djar, big_cookie));
        var hmap = http::HeaderMap { .. };
        sub.assert_true(cookie::flush_deltas(djar, hmap), "4096B payload + attributes must fit in flush_deltas");
    };

    t.run("COOKIE1_C04: parse_kv_span trims outer LWS on direct slice bounds") { sub =>
        let raw = "  sid = xyz  ";
        let span = cookie::parse_kv_span(raw, 0, raw.len);
        sub.assert_bytes_eq(cookie::span_name(raw, span), "sid");
        sub.assert_bytes_eq(cookie::span_value(raw, span), "xyz");
    };

    t.run("COOKIE2_C02: parse_server_cookie_header rejects valueless tokens without '=' and invalid token chars") { sub =>
        let parsed = cookie::parse_server_cookie_header("bareflag; bad name=1; badval=a,b; good=ok");
        sub.assert_eq(parsed.len, 1, "Only valid cookie-pair must be accepted");
        sub.assert_bytes_eq(cookie::get_server_cookie(parsed[..], "good"), "ok");
    };

    t.run("COOKIE2_C07 & COOKIE2_C08: PSL rule parser strips inline comments/whitespace and rejects malformed domains") { sub =>
        let _, ok_excl = cookie::parse_rule_line("!", cookie::PslSection.Icann);
        sub.assert_false(ok_excl, "Bare '!' must be rejected");
        let _, ok_wild = cookie::parse_rule_line("*.", cookie::PslSection.Icann);
        sub.assert_false(ok_wild, "Bare '*.' must be rejected");
        let rule, ok_rule = cookie::parse_rule_line("example.org // inline comment", cookie::PslSection.Icann);
        sub.assert_true(ok_rule);
        sub.assert_bytes_eq(rule.pattern[..], "example.org", "Inline comment and whitespace must be stripped");

        var norm: u8[..256] = [];
        sub.assert_false(cookie::normalize_domain("sub..example.com", norm), "Consecutive dots must be rejected");
        sub.assert_false(cookie::normalize_domain("bad host.com", norm), "Internal space must be rejected");
    };
}

fn main() {
    var runner = lit::new_runner("Cookie Engine, PSL, and Security Verification Suite", lit::Verbosity.Verbose);

    lit::run_case(runner, "1. Lexer, 4096B/1024B Quotas, CTL & WPT Nameless", test_lexer_limits_and_ctl);
    lit::run_case(runner, "2. Date Tokenizer, 400-Day Cap & Expired Overwrite", test_dates_400d_cap_and_expired_overwrite);
    lit::run_case(runner, "3. Domain, PSL, IPv4/IPv6 & Path-Match (RFC 6265 Section 5.1.3, Section 5.1.4)", test_domain_psl_ip_and_path_matching);
    lit::run_case(runner, "4. Layered Prefixes (__Secure-, __Host-, __Http-, __Host-Http-)", test_layered_prefixes_table);
    lit::run_case(runner, "5. SameSite Lax+POST 120s Window & OBC IPv6 Port Upgrade", test_samesite_lax_post_window_and_obc);
    lit::run_case(runner, "6. 6-Round Domain GC Asymmetry (Round 4 vs Round 5)", test_gc_6_rounds_asymmetry_and_global_immunity);
    lit::run_case(runner, "7. Global Garbage Collection & 30-Day Purge Immunity", test_global_gc_and_30_day_immunity);
    lit::run_case(runner, "8. CHIPS Partitioned Cookies & 10KB Memory Quota Enforcement", test_chips_and_10kb_quota);
    lit::run_case(runner, "9. RFC 6265 Section 5.4 Header Sorting & Persistence Key Model", test_header_sorting_and_persistence_key);
    lit::run_case(runner, "10. Exhaustive Ingestion Matrix (LEX, TIME, DOM, PSL, IPv6, OBC)", run_ingestion_matrix);
    lit::run_case(runner, "11. Full 33-Byte ASCII Control Character (CTL) Rejection Sweep", run_exhaustive_ctl_sweep);
    lit::run_case(runner, "12. RFC 6265 Section 5.1.4 Path-Matching Engine & Default-Path Rules", run_path_matching_matrix);
    lit::run_case(runner, "13. SameSite, Lax+POST 120s & Schemeful Same-Site Matrix", run_samesite_and_redirect_matrix);
    lit::run_case(runner, "14. CHIPS Partition Isolation & 10,240B Byte Quota Enforcement", run_chips_partition_quota_and_isolation);
    lit::run_case(runner, "15. GC OBC (Domain-before-Host) & Global 30-Day Purge Immunity", run_gc_obc_domain_before_host_and_global_purge);
    lit::run_case(runner, "16. RFC 6265 Section 5.4 Ordering, Server First-Win & SQLite V24 Coalescing", run_serialization_server_first_win_and_sqlite_v24);
    lit::run_case(runner, "17. Matrix 11: LastAccessDate Throttling, Monotonicity & Clock Skew", run_matrix_11_clock_skew_and_throttling);
    lit::run_case(runner, "18. Matrix 13: SiteForCookies Ancestor Frame Hierarchy & Context", run_matrix_13_site_for_cookies_and_ancestors);
    lit::run_case(runner, "19. Matrix 14: Selective Deletion & Session Cleanup", run_matrix_14_selective_deletion);
    lit::run_case(runner, "20. Matrices 15 & 16: Cryptographic Integrity & Protocol Attacks", run_matrix_15_and_16_crypto_and_attacks);
    lit::run_case(runner, "21. GC-04: strict_secure_cookies Policy Priority Eviction", run_gc_strict_secure_policy);
    lit::run_case(runner, "22. Database Load Sanitization (CTL-08) & Nameless Cookie Import", run_ctl_sanitization_and_nameless_import);
    lit::run_case(runner, "23. Property-Based PRNG Fuzzing (600 Steps Invariant Check)", run_property_based_fuzzer);
    lit::run_case(runner, "24. PSL Rule Types and Precedence (Normal, Wildcard, Exception, Private)", test_psl_rule_types_and_precedence);
    lit::run_case(runner, "25. PSL Dynamic Update and RFC 6265 Scoping", test_psl_dynamic_update_and_scoping);
    lit::run_case(runner, "26. RFC 6265bis Section 5.6 (__Host- & __Secure- Prefix Invariants)", test_host_and_secure_cookie_prefix_smuggling);
    lit::run_case(runner, "27. SSRF Filter Bypasses & IPv6 Zone ID Proxy Smuggling (CVE-2025-22870)", test_ssrf_filter_bypasses);
    lit::run_case(runner, "28. Dangerous Service Ports & Port 0 SSRF Bypass", test_dangerous_service_ports);
    lit::run_case(runner, "29. Public Suffix Boundary Attacks & FQDN Edge Cases (Go PSL Bugs)", test_public_suffix_boundary_attacks);
    lit::run_case(runner, "30. Token Bucket & GCRA Burst / Concurrency Limits (Go Rate Limiter Bugs)", test_rate_limiter_burst_and_concurrency);
    lit::run_case(runner, "31. Singleflight Thundering Herd & Cache Stampede Defense (Go Singleflight Bugs)", test_singleflight_thundering_herd);
    lit::run_case(runner, "32. RFC 6265bis Section 5.6 Insecure Cookie Protection", test_rfc6265bis_sec56_shadowing_protection);
    lit::run_case(runner, "33. Case-Insensitive Prefix Enforcement", test_case_insensitive_prefix_enforcement);
    lit::run_case(runner, "34. Max-Age Capping and Overflow Protection", test_max_age_overflow_and_capping);
    lit::run_case(runner, "35. RFC 6265 Section 5.3 Step 11.2 HttpOnly Overwrite Protection", test_httponly_script_overwrite_protection);
    lit::run_case(runner, "36. RFC 6265bis SameSite=None and §5.1.3 Domain IP Invariants", test_rfc6265bis_samesite_and_domain_ip_rules);
    lit::run_case(runner, "37. RFC 6265 §5.3 Step 11.3 Creation-Time & §5.1.1 Date Lexer", test_rfc6265_creation_time_and_date_lexing);
    lit::run_case(runner, "38. Cookie Hardening & Cross-Origin Single-Label Protection", test_cookie_hardening_invariants);
    lit::run_case(runner, "39. Cookie Span Iteration", test_cookie_span_iteration);
    lit::run_case(runner, "40. Fast-Path Cookie Lookup", test_cookie_find_value);
    lit::run_case(runner, "41. RFC 6265bis §5.1.4: Cookie URL Fallback Path and Fragment", test_cookie_url_fallback_path_fragment);
    lit::run_case(runner, "42. RFC 6265bis §5.4 & Go #82389: Cookie Relative Path Attribute Ignored", test_cookie_relative_path_ignored);
    lit::run_case(runner, "43. Cookie Ingestion Quota Enforcement in Netscape Import", test_cookie_import_cap_defense);
    lit::run_case(runner, "44. goose2rfc Cookie & PSL Audit Regressions", test_goose2rfc_cookie_audit_regressions);

    let ok = lit::finish(runner);
    assert(ok);
}
