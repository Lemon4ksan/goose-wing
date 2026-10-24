// Tests for CanonicalCookieJar (RFC 6265, RFC 6265bis, CHIPS).
import std;
import core from "..";
import wing from "..";

struct PrefixVector {
    header: const u8[:],
    url: const u8[:],
    from_http: bool,
    expect_ok: bool,
}

// ----------------------------------------------------------------------------
// 1. Lexer, 4096B/1024B Limits, CTL Rejection & WPT Nameless
// ----------------------------------------------------------------------------
fn test_lexer_limits_and_ctl(t: core::T&) {
    var clock = core::new_mock_clock();

    t.run("Size Limits: 4096B Name+Value and 1024B Attribute Cap (Issue #1340)") { sub =>
        var jar = wing::new_canonical_cookie_jar();

        // 1. Exactly 4096 bytes (4 + 4092) -> must be accepted
        var val_4092: u8[..4100] = [];
        for i in 4092 { val_4092.push('v'); }
        var hdr_ok: u8[..4200] = [];
        format(hdr_ok, "abcd=", val_4092[..], "; Secure");
        sub.assert_true(
            wing::set_cookie_header(jar, "https://example.com/", hdr_ok[..], clock.now_us),
            "4096B name+value must be accepted"
        );
        sub.assert_eq(jar.cookies.len, 1);

        // 2. 4097 bytes (4 + 4093) -> must be rejected entirely
        val_4092.push('x');
        var hdr_over: u8[..4200] = [];
        format(hdr_over, "abcd=", val_4092[..], "; Secure");
        sub.assert_false(
            wing::set_cookie_header(jar, "https://example.com/", hdr_over[..], clock.now_us),
            "4097B name+value must be rejected"
        );
        sub.assert_eq(jar.cookies.len, 1);

        // 3. Attribute Path of 1025 bytes (> 1024) -> cookie accepted, but Path ignored (default-path '/dir')
        var long_path: u8[..1030] = [];
        long_path.push('/');
        for i in 1024 { long_path.push('p'); } // 1025 bytes total
        var hdr_long_attr: u8[..1100] = [];
        format(hdr_long_attr, "attr_cap=ok; Path=", long_path[..]);
        sub.require_true(
            wing::set_cookie_header(jar, "https://example.com/dir/page.html", hdr_long_attr[..], clock.now_us),
            "cookie with >1024B Path attribute must still be accepted"
        );
        sub.assert_bytes_eq(jar.cookies[1].path[..], "/dir", "1025B Path must be ignored in favor of default-path '/dir'");
    };

    t.run("CTL Rejection vs HTAB Allowance (Issue #1420, #1531)") { sub =>
        var jar = wing::new_canonical_cookie_jar();

        // Control bytes \r, \n, \0, \x7F must reject the cookie rather than truncating it
        sub.assert_false(wing::set_cookie_header(jar, "https://example.com/", "a=b\r\nSecure", clock.now_us));
        sub.assert_false(wing::set_cookie_header(jar, "https://example.com/", "a=b\x00evil", clock.now_us));
        sub.assert_false(wing::set_cookie_header(jar, "https://example.com/", "a=b\x7F", clock.now_us));
        sub.assert_eq(jar.cookies.len, 0);

        // Horizontal tab (\t, 0x09) and double quotes inside value are allowed
        sub.require_true(wing::set_cookie_header(jar, "https://example.com/", "\tsid\t=\t\"quoted_val\"\t;\tSecure\t", clock.now_us));
        sub.assert_bytes_eq(jar.cookies[0].name[..], "sid");
        sub.assert_bytes_eq(jar.cookies[0].value[..], "\"quoted_val\"");
    };

    t.run("WPT http-state Nameless Cookies (0004, 0020, 0023)") { sub =>
        var jar = wing::new_canonical_cookie_jar();

        // WPT 0004: Set-Cookie: foo -> ("", "foo")
        sub.require_true(wing::set_cookie_header(jar, "https://example.com/", "foo", clock.now_us));
        sub.assert_bytes_eq(jar.cookies[0].name[..], "");
        sub.assert_bytes_eq(jar.cookies[0].value[..], "foo");

        // WPT 0020 & 0023: Set-Cookie: = and empty line must be ignored
        sub.assert_false(wing::set_cookie_header(jar, "https://example.com/", "=", clock.now_us));
        sub.assert_false(wing::set_cookie_header(jar, "https://example.com/", "   =   ", clock.now_us));
        sub.assert_false(wing::set_cookie_header(jar, "https://example.com/", "", clock.now_us));
        sub.assert_bytes_eq(jar.cookies[0].value[..], "foo", "existing nameless cookie must remain intact");
    };
}

// ----------------------------------------------------------------------------
// 2. Date Tokenizer, 400-Day Cap & Expired Overwrite
// ----------------------------------------------------------------------------
fn test_dates_400d_cap_and_expired_overwrite(t: core::T&) {
    var clock = core::new_mock_clock(1700000000000000);
    var jar = wing::new_canonical_cookie_jar();

    // 1. 400-day cap (kMinutesIn400Days = 576000)
    t.require_true(wing::set_cookie_header(jar, "https://example.com/", "long=1; Max-Age=999999999", clock.now_us));
    let expected_max_exp = clock.now_us + (400 * 86400 * 1000000);
    t.assert_eq(jar.cookies[0].expires_utc, expected_max_exp, "TTL must be clamped to exactly 400 days");

    // 2. Max-Age=0 for non-existent cookie must NOT expand storage
    t.assert_true(wing::set_cookie_header(jar, "https://example.com/", "ghost=1; Max-Age=0", clock.now_us));
    t.assert_eq(jar.cookies.len, 1, "already expired new cookie must not be pushed into storage");

    // 3. Max-Age=0 for existing cookie must immediately purge it and increment counter
    t.assert_true(wing::set_cookie_header(jar, "https://example.com/", "long=deleted; Max-Age=0", clock.now_us));
    t.assert_eq(jar.cookies.len, 0, "existing cookie must be purged immediately on Max-Age=0");
    t.assert_eq(jar.expired_overwrite_count, 1);
}

// ----------------------------------------------------------------------------
// 3. Domain, Public Suffix List (PSL), IPv4/IPv6 & Path-Match
// ----------------------------------------------------------------------------
fn test_domain_psl_ip_and_path_matching(t: core::T&) {
    var clock = core::new_mock_clock();
    var jar = wing::new_canonical_cookie_jar();

    t.run("DOM-01: PSL Rejection for TLD and Effective Public Suffixes") { sub =>
        // Cannot set cookie for 'com', 'co.uk', or 'github.io'
        sub.assert_false(wing::set_cookie_header(jar, "https://app.example.com/", "sid=1; Domain=com", clock.now_us));
        sub.assert_false(wing::set_cookie_header(jar, "https://app.example.com/", "sid=1; Domain=co.uk", clock.now_us));
        sub.assert_false(wing::set_cookie_header(jar, "https://app.example.com/", "sid=1; Domain=github.io", clock.now_us));
        sub.assert_eq(jar.cookies.len, 0);
    };

    t.run("DOM-03 & DOM-04: Subdomain Rejection & Leading Dot Normalization") { sub =>
        // Cannot set cookie for a subdomain
        sub.assert_false(wing::set_cookie_header(jar, "https://example.com/", "sid=1; Domain=sub.example.com", clock.now_us));

        // Setting for parent domain with leading dot .EXAMPLE.COM -> lowercases and strips leading dot
        sub.require_true(wing::set_cookie_header(jar, "https://sub.example.com/", "sid=1; Domain=.EXAMPLE.COM", clock.now_us));
        sub.assert_bytes_eq(jar.cookies[0].domain[..], "example.com");
        sub.assert_false(jar.cookies[0].host_only);
    };

    t.run("DOM-05: IP Literals must never domain-match") { sub =>
        var ip_jar = wing::new_canonical_cookie_jar();
        // Domain=0.1 must be rejected
        sub.assert_false(wing::set_cookie_header(ip_jar, "http://192.168.0.1:8080/", "sid=1; Domain=0.1", clock.now_us));
        // Domain=192.168.0.1 on IP origin must be accepted but treated as host_only
        sub.require_true(wing::set_cookie_header(ip_jar, "http://192.168.0.1:8080/", "sid=1; Domain=192.168.0.1", clock.now_us));
        sub.assert_true(ip_jar.cookies[0].host_only);
    };

    t.run("RFC 6265 Section 5.1.4 Path Matching Engine") { sub =>
        sub.assert_true(wing::cookie_path_match("/sub", "/sub"));
        sub.assert_true(wing::cookie_path_match("/sub/", "/sub"));
        sub.assert_true(wing::cookie_path_match("/sub/page", "/sub"));
        sub.assert_false(wing::cookie_path_match("/subprefix", "/sub"));
        sub.assert_false(wing::cookie_path_match("/dir", "/dir/page"));
    };
}

// ----------------------------------------------------------------------------
// 4. Layered Cookie Prefixes (__Secure-, __Host-, __Http-, __Host-Http-)
// ----------------------------------------------------------------------------
fn test_layered_prefixes_table(t: core::T&) {
    var clock = core::new_mock_clock();
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

    core::run_table(t, "PrefixMatrix", vectors[..]) { sub, row, idx =>
        var jar = wing::new_canonical_cookie_jar();
        let u = wing::parse_canonical_cookie_url(row.url);
        var c = wing::parse_canonical_set_cookie(row.header, u.host[..], u.path[..], clock.now_us);
        c.source_scheme = if u.is_secure { wing::CookieSourceScheme.Secure } else { wing::CookieSourceScheme.NonSecure };
        c.source_port = u.port;
        let ok = wing::set_canonical_cookie(jar, c, row.from_http, u.is_secure, clock.now_us);
        sub.assert_eq(ok, row.expect_ok, row.header);
    };
}

// ----------------------------------------------------------------------------
// 5. SameSite Lax+POST 120s Window & Origin-Bound Cookies (OBC)
// ----------------------------------------------------------------------------
fn test_samesite_lax_post_window_and_obc(t: core::T&) {
    var clock = core::new_mock_clock();
    var jar = wing::new_canonical_cookie_jar();

    // Default SameSite -> Lax-allowing-unsafe for 120 seconds
    t.require_true(wing::set_cookie_header(jar, "https://idp.example.com/login", "sso=token123; Secure", clock.now_us));

    // At t=119s cross-site top-level POST must include cookie
    core::advance_sec(clock, 119);
    var out_119: wing::CanonicalCookie[>..] = [];
    wing::get_canonical_cookies_for_request(
        jar, "https://idp.example.com/acs", true, "", clock.now_us, out_119,
        false, // is_same_site = false (cross-site)
        true,  // is_top_level_nav = true
        false  // is_safe_method = false (POST)
    );
    t.assert_eq(out_119.len, 1, "at t=119s Lax+POST window must allow cross-site top-level POST");

    // At t=121s cross-site POST is blocked, but GET is allowed
    core::advance_sec(clock, 2);
    var out_121_post: wing::CanonicalCookie[>..] = [];
    wing::get_canonical_cookies_for_request(
        jar, "https://idp.example.com/acs", true, "", clock.now_us, out_121_post,
        false, true, false
    );
    t.assert_eq(out_121_post.len, 0, "at t=121s Lax+POST window expired for unsafe POST");

    var out_121_get: wing::CanonicalCookie[>..] = [];
    wing::get_canonical_cookies_for_request(
        jar, "https://idp.example.com/acs", true, "", clock.now_us, out_121_get,
        false, true, true
    );
    t.assert_eq(out_121_get.len, 1, "at t=121s safe top-level GET is still allowed under Lax");

    // Origin-Bound Cookies (OBC): http://[::1]:80 with Secure upgrades source_port to 443
    t.require_true(wing::set_cookie_header(jar, "http://[::1]:80/test", "__Host-local=ok; Secure; Path=/", clock.now_us));
    t.assert_eq(jar.cookies[1].source_port, 443, "OBC must upgrade port 80 -> 443 on trustworthy [::1] origin");
}

// ----------------------------------------------------------------------------
// 6. 6-Round Domain GC Priority Quotas Asymmetry
// ----------------------------------------------------------------------------
fn test_gc_6_rounds_asymmetry_and_global_immunity(t: core::T&) {
    var clock = core::new_mock_clock();
    var jar = wing::new_canonical_cookie_jar();

    // Populate example.com domain:
    // - 30 Low Secure (protected by low quota = 30)
    // - 60 Medium Secure (quota 50, 10 over quota, but protected in Round 3 by Secure flag)
    // - 91 High Non-Secure (quota 70, 21 over quota, evicted in Round 4 due to Non-Secure!)
    for i in 30 {
        var h: u8[..64] = [];
        format(h, "low_sec_", i, "=1; Secure; Priority=Low");
        wing::set_cookie_header(jar, "https://example.com/", h[..], core::advance_us(clock, 10));
    }
    for i in 60 {
        var h: u8[..64] = [];
        format(h, "med_sec_", i, "=1; Secure; Priority=Medium");
        wing::set_cookie_header(jar, "https://example.com/", h[..], core::advance_us(clock, 10));
    }
    for i in 91 {
        var h: u8[..64] = [];
        format(h, "high_nonsec_", i, "=1; Priority=High");
        wing::set_cookie_header(jar, "http://example.com/", h[..], core::advance_us(clock, 10));
    }

    // 181 cookies inserted -> Domain GC triggered (181 -> 150 target, 31 evicted)
    t.assert_eq(jar.cookies.len, 150, "domain GC must purge down to 150 cookies");
    t.assert_eq(jar.evicted_domain_count, 31);

    // Count surviving cookies by priority
    var low_sec_alive = 0;
    var med_sec_alive = 0;
    var high_nonsec_alive = 0;
    for i in jar.cookies.len {
        if jar.cookies[i].priority == wing::CookiePriority.Low { low_sec_alive += 1; }
        if jar.cookies[i].priority == wing::CookiePriority.Medium { med_sec_alive += 1; }
        if jar.cookies[i].priority == wing::CookiePriority.High { high_nonsec_alive += 1; }
    }

    // Round 4 must evict 21 High Non-Secure before Round 5 evicts 10 Medium Secure
    t.assert_eq(low_sec_alive, 30, "all 30 Low Secure cookies must survive");
    t.assert_eq(high_nonsec_alive, 70, "21 High Non-Secure cookies must be evicted in Round 4");
    t.assert_eq(med_sec_alive, 50, "only 10 Medium Secure cookies must be evicted in Round 5");
}

// ----------------------------------------------------------------------------
// 7. Global Garbage Collection & 30-Day Purge Immunity
// ----------------------------------------------------------------------------
fn test_global_gc_and_30_day_immunity(t: core::T&) {
    var clock = core::new_mock_clock(1700000000000000);
    var jar = wing::new_canonical_cookie_jar();
    jar.max_cookies_global = 20;
    jar.target_cookies_global = 10;
    jar.max_cookies_per_domain = 50;
    jar.target_cookies_per_domain = 40;

    // Insert 20 cookies across 20 distinct domains
    for i in 20 {
        var u: u8[..64] = [];
        format(u, "https://d", i, ".com/");
        wing::set_cookie_header(jar, u[..], "c=1; Secure", clock.now_us);
    }
    t.assert_eq(jar.cookies.len, 20);

    // 21st cookie inserted immediately: all 20 previous cookies have last_access < 30 days old (immune!)
    wing::set_cookie_header(jar, "https://d20.com/", "c=1; Secure", clock.now_us);
    t.assert_eq(jar.cookies.len, 21, "all cookies within 30-day window must be immune from global purge");

    // Advance clock past 30 days (e.g. 31 days)
    core::advance_days(clock, 31);

    // Now inserting 22nd cookie triggers global purge of non-immune cookies down to target (10)
    wing::set_cookie_header(jar, "https://d21.com/", "c=1; Secure", clock.now_us);
    t.assert_le(jar.cookies.len, 11, "global purge must evict non-immune cookies down to target");
    t.assert_gt(jar.evicted_global_count, 0);
}

// ----------------------------------------------------------------------------
// 8. CHIPS Partitioned Cookies & 10KB Memory Quota Enforcement
// ----------------------------------------------------------------------------
fn test_chips_and_10kb_quota(t: core::T&) {
    var clock = core::new_mock_clock();
    var jar = wing::new_canonical_cookie_jar();

    // 1. Partitioned cookie ingestion with valid top-level site
    t.assert_true(
        wing::set_cookie_header(jar, "https://ad.service.com/", "user_id=123; Secure; Partitioned; SameSite=None", clock.now_us, "https://publisher.com"),
        "partitioned cookie must be accepted with top-level site"
    );
    t.assert_eq(jar.cookies.len, 1);
    t.assert_bytes_eq(jar.cookies[0].partition_key[..], "https://publisher.com");

    // 2. CHIPS 10KB Quota: Fill partition with large 3000-byte cookies
    var big_val: u8[..3100] = [];
    for i in 3000 { big_val.push('c'); }

    for i in 4 {
        var hdr: u8[..3200] = [];
        format(hdr, "chunk_", i, "=", big_val[..], "; Secure; Partitioned; SameSite=None");
        wing::set_cookie_header(jar, "https://ad.service.com/", hdr[..], core::advance_sec(clock, 1), "https://publisher.com");
    }

    // 4 cookies * ~3010 bytes = 12040 bytes (> 10240 quota). CHIPS quota must have evicted oldest
    t.assert_gt(jar.evicted_chips_count, 0, "CHIPS quota must evict oldest partitioned cookies exceeding 10KB");
    t.assert_le(jar.cookies.len, 4, "partitioned cookies count must be constrained by 10KB cap");
}

// ----------------------------------------------------------------------------
// 9. RFC 6265 Section 5.4 Header Sorting & Persistence Key Model
// ----------------------------------------------------------------------------
fn test_header_sorting_and_persistence_key(t: core::T&) {
    var clock = core::new_mock_clock();
    var jar = wing::new_canonical_cookie_jar();

    t.run("RFC 6265 Section 5.4 Cookie Header Sorting (Longest Path First, Earliest Creation First)") { sub =>
        // 1. Shorter path, earlier creation
        wing::set_cookie_header(jar, "https://example.com/sub/page", "short_path=1; Path=/sub", core::advance_sec(clock, 1));
        // 2. Longer path, later creation
        wing::set_cookie_header(jar, "https://example.com/sub/page", "long_path=2; Path=/sub/page", core::advance_sec(clock, 1));
        // 3. Same path as #1, later creation
        wing::set_cookie_header(jar, "https://example.com/sub/page", "another_short=3; Path=/sub", core::advance_sec(clock, 1));

        var out_hdr: u8[..256] = [];
        wing::build_cookie_header(jar, "https://example.com/sub/page", out_hdr, clock.now_us);

        // Longest path (/sub/page) MUST come first, followed by earlier /sub, followed by later /sub
        sub.assert_contains(out_hdr[..], "long_path=2; short_path=1; another_short=3", "RFC 6265 Section 5.4 sorting order");
    };

    t.run("SQL Persistence Key Model (host_only prefixing)") { sub =>
        var jar2 = wing::new_canonical_cookie_jar();
        // Host-only cookie: host_key = 'example.com'
        wing::set_cookie_header(jar2, "https://example.com/", "sid=host_val", clock.now_us);
        // Domain cookie: host_key = '.example.com'
        wing::set_cookie_header(jar2, "https://example.com/", "sid=domain_val; Domain=example.com", clock.now_us);

        sub.assert_eq(jar2.cookies.len, 2, "host-only and domain cookies must coexist without colliding");
        sub.assert_true(jar2.cookies[0].host_only);
        sub.assert_false(jar2.cookies[1].host_only);
    };
}

// ----------------------------------------------------------------------------
// Suite Entry Point
// ----------------------------------------------------------------------------
fn main() {
    var runner = core::new_runner("CanonicalCookieJar Suite", core::Verbosity.Verbose);

    core::run_case(runner, "1. Lexer, 4096B/1024B Quotas, CTL & WPT Nameless", test_lexer_limits_and_ctl);
    core::run_case(runner, "2. Date Tokenizer, 400-Day Cap & Expired Overwrite", test_dates_400d_cap_and_expired_overwrite);
    core::run_case(runner, "3. Domain, PSL, IPv4/IPv6 & Path-Match (RFC 6265 Section 5.1.3, Section 5.1.4)", test_domain_psl_ip_and_path_matching);
    core::run_case(runner, "4. Layered Prefixes (__Secure-, __Host-, __Http-, __Host-Http-)", test_layered_prefixes_table);
    core::run_case(runner, "5. SameSite Lax+POST 120s Window & OBC IPv6 Port Upgrade", test_samesite_lax_post_window_and_obc);
    core::run_case(runner, "6. 6-Round Domain GC Asymmetry (Round 4 vs Round 5)", test_gc_6_rounds_asymmetry_and_global_immunity);
    core::run_case(runner, "7. Global Garbage Collection & 30-Day Purge Immunity", test_global_gc_and_30_day_immunity);
    core::run_case(runner, "8. CHIPS Partitioned Cookies & 10KB Memory Quota Enforcement", test_chips_and_10kb_quota);
    core::run_case(runner, "9. RFC 6265 Section 5.4 Header Sorting & Persistence Key Model", test_header_sorting_and_persistence_key);

    let ok = core::finish(runner);
    assert(ok);
}

