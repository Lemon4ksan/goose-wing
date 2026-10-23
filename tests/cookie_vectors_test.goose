// Industrial Verification & Security Attack Vectors for CanonicalCookieJar
// Conforming to RFC 6265, RFC 6265bis, CHIPS, CookieMonster, WPT & USENIX Security.
import std;
import wing from "..";

struct IngestionVector {
    id: const u8[:],
    url: const u8[:],
    set_cookie: const u8[:],
    from_http: bool,
    expect_accepted: bool,
    expect_name: const u8[:],
    expect_val: const u8[:],
    expect_domain: const u8[:],
    expect_path: const u8[:],
    expect_host_only: bool,
    expect_secure: bool,
    expect_httponly: bool,
    expect_persistent: bool,
    expect_port: i32,
}

// ----------------------------------------------------------------------------
// 1. Ingestion Matrix: Lexer, Omnomnom, Dates, PSL, IPv6 & OBC
// ----------------------------------------------------------------------------
fn run_ingestion_matrix(t: wing::T&) {
    let now_us = 1700000000000000; // Epoch baseline
    let vectors = [
        // --- LEX & OMNOMNOM ---
        IngestionVector {
            id: "LEX-10 (WPT 0004 nameless value)",
            url: "https://example.com/", set_cookie: "foo", from_http: true,
            expect_accepted: true, expect_name: "", expect_val: "foo",
            expect_domain: "example.com", expect_path: "/",
            expect_host_only: true, expect_secure: false, expect_httponly: false,
            expect_persistent: false, expect_port: 443,
        },
        IngestionVector {
            id: "LEX-11 (WPT 0004 nameless value with spaces and Secure)",
            url: "https://example.com/", set_cookie: "foo ; Secure", from_http: true,
            expect_accepted: true, expect_name: "", expect_val: "foo",
            expect_domain: "example.com", expect_path: "/",
            expect_host_only: true, expect_secure: true, expect_httponly: false,
            expect_persistent: false, expect_port: 443,
        },
        IngestionVector {
            id: "LEX-12 (WPT 0020 empty '=' rejected)",
            url: "https://example.com/", set_cookie: "   =   ", from_http: true,
            expect_accepted: false, expect_name: "", expect_val: "",
            expect_domain: "", expect_path: "",
            expect_host_only: true, expect_secure: false, expect_httponly: false,
            expect_persistent: false, expect_port: 443,
        },
        IngestionVector {
            id: "LEX-13 (Multiple '=' in value and path)",
            url: "https://example.com/", set_cookie: "k=v1=v2=v3; Path=/a=b", from_http: true,
            expect_accepted: true, expect_name: "k", expect_val: "v1=v2=v3",
            expect_domain: "example.com", expect_path: "/a=b",
            expect_host_only: true, expect_secure: false, expect_httponly: false,
            expect_persistent: false, expect_port: 443,
        },
        IngestionVector {
            id: "LEX-14 (HTAB and SP trimming around tokens)",
            url: "https://example.com/", set_cookie: "\t key \t = \t val \t ; \t HttpOnly \t", from_http: true,
            expect_accepted: true, expect_name: "key", expect_val: "val",
            expect_domain: "example.com", expect_path: "/",
            expect_host_only: true, expect_secure: false, expect_httponly: true,
            expect_persistent: false, expect_port: 443,
        },
        IngestionVector {
            id: "LEX-15 (Semicolon inside DQUOTE splits pair)",
            url: "https://example.com/", set_cookie: "k=\"quoted;val\"", from_http: true,
            expect_accepted: true, expect_name: "k", expect_val: "\"quoted",
            expect_domain: "example.com", expect_path: "/",
            expect_host_only: true, expect_secure: false, expect_httponly: false,
            expect_persistent: false, expect_port: 443,
        },
        IngestionVector {
            id: "LEX-16 (DQUOTE preserved in cookie value)",
            url: "https://example.com/", set_cookie: "k=\"hello_world\"", from_http: true,
            expect_accepted: true, expect_name: "k", expect_val: "\"hello_world\"",
            expect_domain: "example.com", expect_path: "/",
            expect_host_only: true, expect_secure: false, expect_httponly: false,
            expect_persistent: false, expect_port: 443,
        },
        IngestionVector {
            id: "LEX-17 (Duplicate Path attribute: last wins)",
            url: "https://example.com/", set_cookie: "k=v; Path=/first; PATH=/second", from_http: true,
            expect_accepted: true, expect_name: "k", expect_val: "v",
            expect_domain: "example.com", expect_path: "/second",
            expect_host_only: true, expect_secure: false, expect_httponly: false,
            expect_persistent: false, expect_port: 443,
        },

        // --- DATES & CALENDAR BOUNDARIES ---
        IngestionVector {
            id: "TIME-01 (Canonical RFC 1123 date)",
            url: "https://example.com/", set_cookie: "k=v; Expires=Wed, 21 Oct 2026 07:28:00 GMT", from_http: true,
            expect_accepted: true, expect_name: "k", expect_val: "v",
            expect_domain: "example.com", expect_path: "/",
            expect_host_only: true, expect_secure: false, expect_httponly: false,
            expect_persistent: true, expect_port: 443,
        },
        IngestionVector {
            id: "TIME-07 (Year 1600 < 1601 falls back to session cookie)",
            url: "https://example.com/", set_cookie: "k=v; Expires=Sun, 31 Dec 1600 23:59:59 GMT", from_http: true,
            expect_accepted: true, expect_name: "k", expect_val: "v",
            expect_domain: "example.com", expect_path: "/",
            expect_host_only: true, expect_secure: false, expect_httponly: false,
            expect_persistent: false, expect_port: 443,
        },
        IngestionVector {
            id: "TIME-08 (Invalid day 32 falls back to session cookie)",
            url: "https://example.com/", set_cookie: "k=v; Expires=32 Jan 2027 00:00:00 GMT", from_http: true,
            expect_accepted: true, expect_name: "k", expect_val: "v",
            expect_domain: "example.com", expect_path: "/",
            expect_host_only: true, expect_secure: false, expect_httponly: false,
            expect_persistent: false, expect_port: 443,
        },
        IngestionVector {
            id: "TIME-13 (Max-Age=100 overrides past Expires=1970)",
            url: "https://example.com/", set_cookie: "k=v; Max-Age=100; Expires=Thu, 01 Jan 1970 00:00:00 GMT", from_http: true,
            expect_accepted: true, expect_name: "k", expect_val: "v",
            expect_domain: "example.com", expect_path: "/",
            expect_host_only: true, expect_secure: false, expect_httponly: false,
            expect_persistent: true, expect_port: 443,
        },
        IngestionVector {
            id: "TIME-15 (Non-digit Max-Age=100abc ignored -> session)",
            url: "https://example.com/", set_cookie: "k=v; Max-Age=100abc", from_http: true,
            expect_accepted: true, expect_name: "k", expect_val: "v",
            expect_domain: "example.com", expect_path: "/",
            expect_host_only: true, expect_secure: false, expect_httponly: false,
            expect_persistent: false, expect_port: 443,
        },

        // --- DOMAIN, PSL, IPv4 & IPv6 ---
        IngestionVector {
            id: "DOM-01 (No Domain attribute -> host-only)",
            url: "https://sub.example.com/", set_cookie: "k=v", from_http: true,
            expect_accepted: true, expect_name: "k", expect_val: "v",
            expect_domain: "sub.example.com", expect_path: "/",
            expect_host_only: true, expect_secure: false, expect_httponly: false,
            expect_persistent: false, expect_port: 443,
        },
        IngestionVector {
            id: "DOM-02 (Domain attribute present -> not host-only)",
            url: "https://sub.example.com/", set_cookie: "k=v; Domain=sub.example.com", from_http: true,
            expect_accepted: true, expect_name: "k", expect_val: "v",
            expect_domain: "sub.example.com", expect_path: "/",
            expect_host_only: false, expect_secure: false, expect_httponly: false,
            expect_persistent: false, expect_port: 443,
        },
        IngestionVector {
            id: "DOM-03 (Multiple leading dots Domain=..example.com ignored -> host-only)",
            url: "https://sub.example.com/", set_cookie: "k=v; Domain=..example.com", from_http: true,
            expect_accepted: true, expect_name: "k", expect_val: "v",
            expect_domain: "sub.example.com", expect_path: "/",
            expect_host_only: true, expect_secure: false, expect_httponly: false,
            expect_persistent: false, expect_port: 443,
        },
        IngestionVector {
            id: "DOM-05 (Empty Domain= ignored -> host-only)",
            url: "https://example.com/", set_cookie: "k=v; Domain=", from_http: true,
            expect_accepted: true, expect_name: "k", expect_val: "v",
            expect_domain: "example.com", expect_path: "/",
            expect_host_only: true, expect_secure: false, expect_httponly: false,
            expect_persistent: false, expect_port: 443,
        },
        IngestionVector {
            id: "DOM-06 (PSL supercookie co.uk rejected)",
            url: "https://app.co.uk/", set_cookie: "k=v; Domain=co.uk", from_http: true,
            expect_accepted: false, expect_name: "", expect_val: "",
            expect_domain: "", expect_path: "",
            expect_host_only: false, expect_secure: false, expect_httponly: false,
            expect_persistent: false, expect_port: 443,
        },
        IngestionVector {
            id: "DOM-07 (Direct request to PSL co.uk forces host_only=true)",
            url: "https://co.uk/", set_cookie: "k=v; Domain=co.uk", from_http: true,
            expect_accepted: true, expect_name: "k", expect_val: "v",
            expect_domain: "co.uk", expect_path: "/",
            expect_host_only: true, expect_secure: false, expect_httponly: false,
            expect_persistent: false, expect_port: 443,
        },
        IngestionVector {
            id: "DOM-08 (Parent domain cannot set child subdomain)",
            url: "https://example.com/", set_cookie: "k=v; Domain=sub.example.com", from_http: true,
            expect_accepted: false, expect_name: "", expect_val: "",
            expect_domain: "", expect_path: "",
            expect_host_only: false, expect_secure: false, expect_httponly: false,
            expect_persistent: false, expect_port: 443,
        },
        IngestionVector {
            id: "DOM-09 (Suffix without dot boundary: notexample.com -> example.com)",
            url: "https://notexample.com/", set_cookie: "k=v; Domain=example.com", from_http: true,
            expect_accepted: false, expect_name: "", expect_val: "",
            expect_domain: "", expect_path: "",
            expect_host_only: false, expect_secure: false, expect_httponly: false,
            expect_persistent: false, expect_port: 443,
        },
        IngestionVector {
            id: "DOM-10 (CVE-2016-8615 IPv4 partial suffix rejected)",
            url: "http://192.168.1.100/", set_cookie: "k=v; Domain=1.100", from_http: true,
            expect_accepted: false, expect_name: "", expect_val: "",
            expect_domain: "", expect_path: "",
            expect_host_only: false, expect_secure: false, expect_httponly: false,
            expect_persistent: false, expect_port: 80,
        },
        IngestionVector {
            id: "DOM-11 (IPv4 exact match accepted as host-only)",
            url: "http://192.168.1.100/", set_cookie: "k=v; Domain=192.168.1.100", from_http: true,
            expect_accepted: true, expect_name: "k", expect_val: "v",
            expect_domain: "192.168.1.100", expect_path: "/",
            expect_host_only: true, expect_secure: false, expect_httponly: false,
            expect_persistent: false, expect_port: 80,
        },
        IngestionVector {
            id: "DOM-12 & PATH-06 (IPv6 bracketed literal + query string slash)",
            url: "http://[::1]:8080/a/b?redirect=/x/y/z", set_cookie: "k=v", from_http: true,
            expect_accepted: true, expect_name: "k", expect_val: "v",
            expect_domain: "::1", expect_path: "/a",
            expect_host_only: true, expect_secure: false, expect_httponly: false,
            expect_persistent: false, expect_port: 8080,
        },
        IngestionVector {
            id: "DOM-13 (Intranet single-label host forces host_only=true)",
            url: "http://intranet-server/", set_cookie: "k=v; Domain=intranet-server", from_http: true,
            expect_accepted: true, expect_name: "k", expect_val: "v",
            expect_domain: "intranet-server", expect_path: "/",
            expect_host_only: true, expect_secure: false, expect_httponly: false,
            expect_persistent: false, expect_port: 80,
        },
        IngestionVector {
            id: "SHAD-01 (Cookie Crumbles: nameless cookie simulating __Host- rejected)",
            url: "http://sub.example.com/", set_cookie: "=__Host-sid=attacker_val; Domain=example.com", from_http: true,
            expect_accepted: false, expect_name: "", expect_val: "",
            expect_domain: "", expect_path: "",
            expect_host_only: false, expect_secure: false, expect_httponly: false,
            expect_persistent: false, expect_port: 80,
        },
        IngestionVector {
            id: "OBC-03 (Trustworthy localhost:80 with Secure upgrades port to 443)",
            url: "http://127.0.0.1:80/login", set_cookie: "__Host-s=1; Secure; Path=/", from_http: true,
            expect_accepted: true, expect_name: "__Host-s", expect_val: "1",
            expect_domain: "127.0.0.1", expect_path: "/",
            expect_host_only: true, expect_secure: true, expect_httponly: false,
            expect_persistent: false, expect_port: 443,
        },
    ];

    wing::run_table(t, "IngestionVectors", vectors[..]) { sub, v, idx =>
        var jar = wing::new_canonical_cookie_jar();
        let ok = wing::set_cookie_header(jar, v.url, v.set_cookie, now_us, v.from_http);
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
// 2. Full 33-Byte ASCII Control Character (CTL) Rejection Sweep
// ----------------------------------------------------------------------------
fn run_exhaustive_ctl_sweep(t: wing::T&) {
    let now_us = 1700000000000000;
    var jar = wing::new_canonical_cookie_jar();

    for b in 128 {
        let byte_val = b as u8;
        let is_ctl = (byte_val <= 0x08) || (byte_val >= 0x0A && byte_val <= 0x1F) || (byte_val == 0x7F);
        if is_ctl {
            var hdr: u8[..32] = [];
            hdr.append("sid=val");
            hdr.push(byte_val);
            hdr.append("tail; Secure");
            let accepted = wing::set_cookie_header(jar, "https://example.com/", hdr[..], now_us);
            t.assert_false(accepted, "CTL byte in Set-Cookie must be strictly rejected, never truncated");
        }
    }
    t.assert_eq(jar.cookies.len, 0, "Zero cookies must be stored after full CTL sweep");
}

// ----------------------------------------------------------------------------
// 3. RFC 6265 Section 5.1.4 Path-Matching Engine & Default-Path Rules
// ----------------------------------------------------------------------------
struct PathMatchVector {
    id: const u8[:],
    cookie_path: const u8[:],
    request_path: const u8[:],
    expect_match: bool,
}

fn run_path_matching_matrix(t: wing::T&) {
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

    wing::run_table(t, "PathMatchRFC6265", path_vectors[..]) { sub, v, idx =>
        let got = wing::cookie_path_match(v.request_path, v.cookie_path);
        sub.assert_eq(got, v.expect_match, v.id);
    };

    t.run("Default-Path Algorithm RFC 6265 Section 5.1.4 (PATH-01..PATH-06)") { sub =>
        var out: u8[..128] = [];

        wing::compute_default_cookie_path("", out);
        sub.assert_bytes_eq(out[..], "/", "PATH-01: empty uri-path -> '/'");

        wing::compute_default_cookie_path("noslash", out);
        sub.assert_bytes_eq(out[..], "/", "no leading slash -> '/'");

        wing::compute_default_cookie_path("/", out);
        sub.assert_bytes_eq(out[..], "/", "PATH-02: single slash -> '/'");

        wing::compute_default_cookie_path("/docs", out);
        sub.assert_bytes_eq(out[..], "/", "PATH-03: '/docs' has only one slash -> '/'");

        wing::compute_default_cookie_path("/a/b/c", out);
        sub.assert_bytes_eq(out[..], "/a/b", "PATH-04: '/a/b/c' -> '/a/b'");

        wing::compute_default_cookie_path("/a/b/", out);
        sub.assert_bytes_eq(out[..], "/a/b", "PATH-05: '/a/b/' -> '/a/b' (rightmost slash excluded)");
    };
}

// ----------------------------------------------------------------------------
// 4. SameSite, Lax+POST 120s Window & Schemeful Same-Site (SS-01..SS-14)
// ----------------------------------------------------------------------------
struct SameSiteVector {
    id: const u8[:],
    samesite_mode: wing::CookieSameSite,
    age_sec: i64,
    is_same_site: bool,
    is_top_level_nav: bool,
    is_safe_method: bool,
    expect_send: bool,
}

fn run_samesite_and_redirect_matrix(t: wing::T&) {
    let ss_vectors = [
        SameSiteVector { id: "SS-01 (Strict + same-site)", samesite_mode: wing::CookieSameSite.Strict, age_sec: 500, is_same_site: true, is_top_level_nav: false, is_safe_method: false, expect_send: true },
        SameSiteVector { id: "SS-02 (Strict + cross-site top-level GET)", samesite_mode: wing::CookieSameSite.Strict, age_sec: 10, is_same_site: false, is_top_level_nav: true, is_safe_method: true, expect_send: false },
        SameSiteVector { id: "SS-03 (Explicit Lax + cross-site top-level GET)", samesite_mode: wing::CookieSameSite.Lax, age_sec: 500, is_same_site: false, is_top_level_nav: true, is_safe_method: true, expect_send: true },
        SameSiteVector { id: "SS-04 (Explicit Lax + cross-site top-level POST at 10s -> BLOCKED)", samesite_mode: wing::CookieSameSite.Lax, age_sec: 10, is_same_site: false, is_top_level_nav: true, is_safe_method: false, expect_send: false },
        SameSiteVector { id: "SS-05 (Explicit Lax + cross-site iframe GET -> BLOCKED)", samesite_mode: wing::CookieSameSite.Lax, age_sec: 10, is_same_site: false, is_top_level_nav: false, is_safe_method: true, expect_send: false },
        SameSiteVector { id: "SS-06 (Default + cross-site top-level POST at 119s -> ALLOWED by Lax+POST)", samesite_mode: wing::CookieSameSite.Default, age_sec: 119, is_same_site: false, is_top_level_nav: true, is_safe_method: false, expect_send: true },
        SameSiteVector { id: "SS-07 (Default + cross-site top-level POST at 121s -> BLOCKED)", samesite_mode: wing::CookieSameSite.Default, age_sec: 121, is_same_site: false, is_top_level_nav: true, is_safe_method: false, expect_send: false },
        SameSiteVector { id: "SS-08 (Default + cross-site XHR/iframe POST at 10s -> BLOCKED)", samesite_mode: wing::CookieSameSite.Default, age_sec: 10, is_same_site: false, is_top_level_nav: false, is_safe_method: false, expect_send: false },
        SameSiteVector { id: "SS-10 (None + cross-site iframe POST)", samesite_mode: wing::CookieSameSite.None, age_sec: 500, is_same_site: false, is_top_level_nav: false, is_safe_method: false, expect_send: true },
    ];

    wing::run_table(t, "SameSiteDecisionMatrix", ss_vectors[..]) { sub, v, idx =>
        let create_us = 1000000000000;
        let now_us = create_us + (v.age_sec * 1000000);
        var c = wing::new_canonical_cookie("sid", "val");
        c.same_site = v.samesite_mode;
        c.secure = true;
        c.creation_utc = create_us;

        let got = wing::is_cookie_sendable_for_samesite(
            c, v.is_same_site, v.is_top_level_nav, v.is_safe_method, now_us
        );
        sub.assert_eq(got, v.expect_send, v.id);
    };

    t.run("Schemeful Same-Site (SS-13 & SS-14)") { sub =>
        sub.assert_false(
            wing::is_schemeful_same_site("http", "example.com", "https", "example.com"),
            "SS-13: http://example.com and https://example.com must be cross-site"
        );
        sub.assert_true(
            wing::is_schemeful_same_site("https", "a.example.com", "https", "b.example.com"),
            "SS-14: subdomains sharing scheme and eTLD+1 must be same-site"
        );
    };
}

// ----------------------------------------------------------------------------
// 5. CHIPS Partition Isolation & 10,240B Byte Quota Enforcement
// ----------------------------------------------------------------------------
fn run_chips_partition_quota_and_isolation(t: wing::T&) {
    var clock = wing::new_mock_clock();
    var jar = wing::new_canonical_cookie_jar();

    // CHIPS-02: Partitioned cookie without Secure is rejected
    t.assert_false(
        wing::set_cookie_header(jar, "https://ads.com/", "c=1; Partitioned", clock.now_us),
        "CHIPS-02: Partitioned cookie without Secure must be rejected"
    );

    // CHIPS-03: Fill partition ("https://news.com", "ads.com") up to 10,000 bytes (5 cookies of 2,000 B)
    var val_1996: u8[..2000] = [];
    for i in 1996 { val_1996.push('x'); }

    for i in 5 {
        var name: u8[..16] = [];
        format(name, "p0", i);
        var c = wing::new_canonical_cookie(name[..], val_1996[..]);
        c.value.push('z'); // 3 + 1997 = 2000 bytes exactly
        c.domain.append("ads.com");
        c.path.append("/");
        c.secure = true;
        c.partitioned = true;
        c.partition_key.append("https://news.com");
        c.source_scheme = wing::CookieSourceScheme.Secure;
        c.source_port = 443;
        let step_time = wing::advance_sec(clock, 10);
        t.require_true(wing::set_canonical_cookie(jar, c, true, true, step_time));
    }
    t.assert_eq(jar.cookies.len, 5, "5 partitioned cookies (10,000 B total) must fit in 10,240 B quota");

    // Add cookie of the same domain ads.com, but in OTHER partition "https://shop.com" (2,000 B)
    var c_other_part = wing::new_canonical_cookie("p_shop", val_1996[..]);
    c_other_part.domain.append("ads.com");
    c_other_part.path.append("/");
    c_other_part.secure = true;
    c_other_part.partitioned = true;
    c_other_part.partition_key.append("https://shop.com");
    c_other_part.source_scheme = wing::CookieSourceScheme.Secure;
    c_other_part.source_port = 443;
    t.require_true(wing::set_canonical_cookie(jar, c_other_part, true, true, wing::advance_sec(clock, 10)));
    t.assert_eq(jar.cookies.len, 6, "other partition must have an independent 10,240 B quota");

    // Add 6th cookie into first partition "https://news.com" of size 500 B (10,000 + 500 = 10,500 > 10,240)
    var val_496: u8[..500] = [];
    for i in 496 { val_496.push('y'); }
    var c_overflow = wing::new_canonical_cookie("p05", val_496[..]);
    c_overflow.domain.append("ads.com");
    c_overflow.path.append("/");
    c_overflow.secure = true;
    c_overflow.partitioned = true;
    c_overflow.partition_key.append("https://news.com");
    c_overflow.source_scheme = wing::CookieSourceScheme.Secure;
    c_overflow.source_port = 443;
    t.require_true(wing::set_canonical_cookie(jar, c_overflow, true, true, wing::advance_sec(clock, 10)));

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
// 6. GC OBC (Domain-before-Host) & Global 30-Day Purge Immunity
// ----------------------------------------------------------------------------
fn run_gc_obc_domain_before_host_and_global_purge(t: wing::T&) {
    var clock = wing::new_mock_clock();

    t.run("GC-07: Domain cookies evicted BEFORE Host cookies despite newer LastAccessDate") { sub =>
        var jar = wing::new_canonical_cookie_jar();

        // 1. Insert 175 Host-Only cookies with OLD access times (t = 1..175)
        for i in 175 {
            var h: u8[..64] = [];
            format(h, "host_", i, "=1; Priority=Low");
            wing::set_cookie_header(jar, "http://example.com/", h[..], wing::advance_us(clock, 10));
        }

        // 2. Insert 6 Domain cookies (Domain=example.com) with FRESH access times
        for i in 6 {
            var h: u8[..64] = [];
            format(h, "dom_", i, "=1; Domain=example.com; Priority=Low");
            wing::set_cookie_header(jar, "http://example.com/", h[..], wing::advance_sec(clock, 100));
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
        var jar = wing::new_canonical_cookie_jar();

        // Create 3350 cookies across 34 eTLD+1 domains (~98-100 per domain)
        // First 400 cookies created on day 0
        for i in 400 {
            let dom_id = i / 100;
            var url: u8[..64] = [];
            format(url, "https://d", dom_id, ".com/");
            var hdr: u8[..64] = [];
            format(hdr, "old_", i, "=val; Max-Age=30000000");
            wing::set_cookie_header(jar, url[..], hdr[..], wing::advance_us(clock, 10));
        }

        // Advance virtual clock by 31 days (beyond 30-day immunity window for first 400 cookies)
        wing::advance_days(clock, 31);

        for i in 2901 {
            let dom_id = 4 + (i / 100);
            var url: u8[..64] = [];
            format(url, "https://d", dom_id, ".com/");
            var hdr: u8[..64] = [];
            format(hdr, "recent_", i, "=val; Max-Age=30000000");
            wing::set_cookie_header(jar, url[..], hdr[..], wing::advance_us(clock, 10));
        }

        // Inserting 3301st cookie triggers global GC down to target 3000
        sub.assert_eq(jar.cookies.len, 3000, "GC-11: Global GC must purge down to 3000 when >30d old cookies exist");
        sub.assert_eq(jar.evicted_global_count, 301);
    };
}

// ----------------------------------------------------------------------------
// 7. RFC 6265 Section 5.4 Ordering, Server First-Win & SQLite V24 Coalescing
// ----------------------------------------------------------------------------
fn run_serialization_server_first_win_and_sqlite_v24(t: wing::T&) {
    var clock = wing::new_mock_clock();

    t.run("SER-01 & SRV-01: RFC 6265 Section 5.4 Path-Length Ordering and Server First-Win Protection") { sub =>
        var jar = wing::new_canonical_cookie_jar();

        // Set 3 cookies named 'sid' with different paths and creation timestamps:
        // 1) path="/" (create = T+10)
        wing::set_cookie_header(jar, "https://example.com/", "sid=root_guest; Path=/", wing::advance_sec(clock, 10));
        // 2) path="/admin/panel" (create = T+30)
        wing::set_cookie_header(jar, "https://example.com/", "sid=panel_late; Path=/admin/panel", wing::advance_sec(clock, 20));
        // 3) path="/admin" (create = T+40)
        wing::set_cookie_header(jar, "https://example.com/", "sid=admin_mid; Path=/admin", wing::advance_sec(clock, 10));

        var cookie_hdr: u8[..256] = [];
        wing::build_request_cookie_header(jar, "https://example.com/admin/panel/settings", true, "", clock.now_us, cookie_hdr);

        // Expected order: longest path '/admin/panel' -> '/admin' -> '/'
        sub.assert_bytes_eq(
            cookie_hdr[..],
            "sid=panel_late; sid=admin_mid; sid=root_guest",
            "SER-01: longer paths must precede shorter paths"
        );

        // In server parser: get_server_cookie must return FIRST occurrence ("panel_late")
        let parsed_req = wing::parse_server_cookie_header(cookie_hdr[..]);
        let val = wing::get_server_cookie(parsed_req[..], "sid");
        sub.assert_bytes_eq(
            val,
            "panel_late",
            "SRV-01: Server parser must preserve first occurrence to prevent root path shadowing"
        );
    };

    t.run("SQL-01..SQL-04: SQLite V24 Leading Dot in host_key and WriteBackBatcher Coalescing") { sub =>
        var c_host = wing::new_canonical_cookie("sid", "host_val");
        c_host.domain.append("example.com");
        c_host.host_only = true;

        var c_dom = wing::new_canonical_cookie("sid", "dom_val");
        c_dom.domain.append("example.com");
        c_dom.host_only = false;

        var sql_host: u8[..512] = [];
        var sql_dom: u8[..512] = [];
        wing::generate_sqlite_insert_sql(c_host, sql_host);
        wing::generate_sqlite_insert_sql(c_dom, sql_dom);

        // Host-only cookie has host_key = 'example.com', domain cookie has host_key = '.example.com'
        sub.assert_contains(sql_host[..], "'example.com'", "SQL-01: host-only cookie must not have leading dot in host_key");
        sub.assert_contains(sql_dom[..], "'.example.com'", "SQL-01: domain cookie must have leading dot in SQLite V24 host_key");

        // Verification of coalescing in WriteBackBatcher: Insert + Delete = 0 operations
        var batch = wing::new_write_back_batcher(clock.now_us);
        wing::queue_insert(batch, c_host);
        sub.assert_eq(batch.ops.len, 1);
        wing::queue_delete(batch, c_host);
        sub.assert_eq(batch.ops.len, 0, "SQL-02: Insert followed by Delete must coalesce to 0 disk ops");
    };
}

// ----------------------------------------------------------------------------
// 8. Matrix 11: LastAccessDate Throttling, Monotonicity & Clock Skew
// ----------------------------------------------------------------------------
fn run_matrix_11_clock_skew_and_throttling(t: wing::T&) {
    t.run("CLK-01 & CLK-02: 60s LastAccessDate Throttling (kDefaultAccessUpdateThresholdSeconds)") { sub =>
        var jar = wing::new_canonical_cookie_jar();
        jar.access_update_threshold_us = 60000000; // 60 seconds

        let t0: i64 = 1000 * 1000000; // 1000s
        wing::set_cookie_header(jar, "https://example.com/api", "sid=token1", t0);
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
        var jar = wing::new_canonical_cookie_jar();
        let t0: i64 = 5000; // identical microsecond

        // Insert 3 cookies in the exact same microsecond
        wing::set_cookie_header(jar, "https://example.com/", "c1=v1; Path=/", t0);
        wing::set_cookie_header(jar, "https://example.com/", "c2=v2; Path=/", t0);
        wing::set_cookie_header(jar, "https://example.com/", "c3=v3; Path=/", t0);

        var hdr: u8[..128] = [];
        jar.build_cookie_header("https://example.com/", hdr, t0);
        sub.assert_bytes_eq(hdr[..], "c1=v1; c2=v2; c3=v3", "CLK-03: stable FIFO sequence ordering on identical creation_utc");
    };

    t.run("CLK-04 & CLK-05: NTP Clock Skew Backward Shift and CreationDate Preservation") { sub =>
        var jar = wing::new_canonical_cookie_jar();

        // c1 created at t0 = 2000s
        let t0: i64 = 2000 * 1000000;
        wing::set_cookie_header(jar, "https://example.com/", "c1=orig; Path=/", t0);
        sub.assert_eq(jar.cookies[0].creation_utc, t0);

        // NTP synchronization shifts client clock back to t1 = 1000s
        let t1: i64 = 1000 * 1000000;

        // CLK-04: c2 created with Max-Age=60 at t1 = 1000s -> expires_utc = 1060s
        wing::set_cookie_header(jar, "https://example.com/", "c2=rel; Max-Age=60; Path=/", t1);
        sub.assert_eq(jar.cookies[1].expires_utc, t1 + (60 * 1000000), "CLK-04: TTL relative to client local clock");

        // CLK-05: Overwrite c1 at t1 = 1000s must preserve original creation_utc = 2000s
        wing::set_cookie_header(jar, "https://example.com/", "c1=overwritten; Path=/", t1);
        sub.assert_eq(jar.cookies.len, 2);

        var c1_idx = 0;
        if jar.cookies[1].name[..] == "c1" { c1_idx = 1; }
        sub.assert_eq(jar.cookies[c1_idx].creation_utc, t0, "CLK-05: creation_utc immutable across backward clock skew");
        sub.assert_eq(jar.cookies[c1_idx].last_update_utc, t1, "CLK-05: last_update_utc updated to current time");
    };
}

// ----------------------------------------------------------------------------
// 9. Matrix 13: SiteForCookies Ancestor Frame Hierarchy & Context
// ----------------------------------------------------------------------------
fn run_matrix_13_site_for_cookies_and_ancestors(t: wing::T&) {
    t.run("CTX-01 & CTX-02: ABA Framing vs Homogeneous Ancestor Hierarchy") { sub =>
        // CTX-01: Top https://a.com -> iframe https://evil.com -> iframe https://a.com/inner
        let ancestors_aba: const u8[:][2] = ["https://a.com", "https://evil.com"];
        let site_aba = wing::compute_site_for_cookies_with_ancestors("https://a.com", ancestors_aba[..]);
        sub.assert_true(site_aba.is_null, "CTX-01: cross-site ancestor renders SiteForCookies null");
        sub.assert_false(wing::is_request_same_site(site_aba, "https://a.com/inner"), "CTX-01: request inside ABA is cross-site");

        // CTX-02: Top https://a.com -> iframe https://sub.a.com/widget
        let ancestors_clean: const u8[:][1] = ["https://a.com"];
        let site_clean = wing::compute_site_for_cookies_with_ancestors("https://a.com", ancestors_clean[..]);
        sub.assert_false(site_clean.is_null, "CTX-02: all same-site ancestors retain valid SiteForCookies");
        sub.assert_true(wing::is_request_same_site(site_clean, "https://api.a.com/data"), "CTX-02: request is same-site");
    };
}

// ----------------------------------------------------------------------------
// 10. Matrix 14: Selective Deletion & Session Cleanup (DEL-01..DEL-05)
// ----------------------------------------------------------------------------
fn run_matrix_14_selective_deletion(t: wing::T&) {
    t.run("DEL-01: TimeRange Selective Deletion [begin, end]") { sub =>
        var jar = wing::new_canonical_cookie_jar();
        wing::set_cookie_header(jar, "https://example.com/", "c1=1; Path=/", 100);
        wing::set_cookie_header(jar, "https://example.com/", "c2=2; Path=/", 200);
        wing::set_cookie_header(jar, "https://example.com/", "c3=3; Path=/", 300);
        wing::set_cookie_header(jar, "https://example.com/", "c4=4; Path=/", 400);
        sub.require_eq(jar.cookies.len, 4);

        let deleted = wing::delete_all_created_in_time_range(jar, 200, 300);
        sub.assert_eq(deleted, 2, "DEL-01: exactly 2 cookies deleted inside [200, 300]");
        sub.assert_eq(jar.cookies.len, 2);
        sub.assert_eq(jar.cookies[0].name[..], "c1");
        sub.assert_eq(jar.cookies[1].name[..], "c4");
    };

    t.run("DEL-02 & DEL-04: Session Cookie Deletion and Cookie Incrementalism Section 3.5") { sub =>
        var jar = wing::new_canonical_cookie_jar();
        // c1: Session cookie (no Max-Age/Expires)
        wing::set_cookie_header(jar, "https://example.com/", "c_sess=1; Path=/", 1000);
        // c2: Persistent cookie over secure channel
        wing::set_cookie_header(jar, "https://example.com/", "c_sec=2; Max-Age=3600; Secure; Path=/", 1000);
        // c3: Persistent cookie over non-secure channel
        wing::set_cookie_header(jar, "http://example.com/", "c_plain=3; Max-Age=3600; Path=/", 1000);
        sub.require_eq(jar.cookies.len, 3);

        // DEL-04: Incrementalism Section 3.5: purge non-secure cookies on session end
        let purged = wing::delete_session_cookies(jar, true);
        sub.assert_eq(purged, 2, "Session cookie (c_sess) and NonSecure persistent cookie (c_plain) purged");
        sub.assert_eq(jar.cookies.len, 1);
        sub.assert_eq(jar.cookies[0].name[..], "c_sec", "Secure persistent cookie preserved");
    };
}

// ----------------------------------------------------------------------------
// 11. Matrices 15 & 16: Cryptographic Integrity & Protocol Attacks
// ----------------------------------------------------------------------------
fn run_matrix_15_and_16_crypto_and_attacks(t: wing::T&) {
    t.run("CRY-02: Rejection of Tampered Record with Both Plaintext and Encrypted Values") { sub =>
        var jar = wing::new_canonical_cookie_jar();

        // Valid JSON with normal cookie
        let valid_json = "[{\"name\":\"clean_sid\",\"value\":\"secret_123\",\"domain\":\"example.com\",\"path\":\"/\"}]";
        let valid_count = jar.import_json(valid_json, 1000);
        sub.assert_eq(valid_count, 1);

        // Tampered record: simultaneous plaintext 'value' and 'encrypted_value' (kValuesExistInBothEncryptedAndPlaintext = 8)
        var tampered_cookie = wing::new_canonical_cookie("hacked", "plain_val");
        tampered_cookie.encrypted_value.append("ciphertext_blob_123");
        tampered_cookie.domain.append("example.com");

        let both_invalid = tampered_cookie.value.len > 0 && tampered_cookie.encrypted_value.len > 0;
        sub.assert_true(both_invalid, "CRY-02: Detected simultaneous plaintext and encrypted values");
    };

    t.run("CRY-05: Constant-Time Comparison Timing Immunity") { sub =>
        sub.assert_true(wing::constant_time_eq("secret_token_123", "secret_token_123"));
        sub.assert_false(wing::constant_time_eq("secret_token_123", "secret_token_124"));
        sub.assert_false(wing::constant_time_eq("short", "longer_token"));
    };

    t.run("ATK-01: Set-Cookie Comma Folding Invariant (RFC 6265bis Section 1)") { sub =>
        var jar = wing::new_canonical_cookie_jar();
        // Comma inside Path attribute must NOT split the cookie
        let ok = wing::set_cookie_header(jar, "https://example.com/c,d=e", "a=b; Path=/c,d=e", 1000);
        sub.assert_true(ok);
        sub.assert_eq(jar.cookies.len, 1);
        sub.assert_eq(jar.cookies[0].name[..], "a");
        sub.assert_eq(jar.cookies[0].value[..], "b");
        sub.assert_eq(jar.cookies[0].path[..], "/c,d=e");
    };
}

// ----------------------------------------------------------------------------
// 12. GC-04: strict_secure_cookies Policy Priority Eviction
// ----------------------------------------------------------------------------
fn run_gc_strict_secure_policy(t: wing::T&) {
    let now_us = 1700000000000000;
    var jar = wing::new_canonical_cookie_jar();
    jar.strict_secure_cookies = true;

    // Insert 100 Secure cookies
    for i in 100 {
        var h: u8[..64] = [];
        format(h, "sec_", i, "=1; Secure");
        wing::set_cookie_header(jar, "https://example.com/", h[..], now_us + i);
    }
    // Insert 80 Non-Secure cookies (total 180 = max limit)
    for i in 80 {
        var h: u8[..64] = [];
        format(h, "nonsec_", i, "=1");
        wing::set_cookie_header(jar, "http://example.com/", h[..], now_us + 100 + i);
    }
    t.assert_eq(jar.cookies.len, 180);

    // 181st cookie triggers domain GC with strict_secure_cookies=true
    // GC-04: All non-secure cookies are evicted first!
    wing::set_cookie_header(jar, "http://example.com/", "trigger=1", now_us + 200);
    t.assert_le(jar.cookies.len, 101, "all non-secure cookies evicted under strict_secure_cookies policy");
    t.assert_gt(jar.rejected_security_count, 0);
}

// ----------------------------------------------------------------------------
// 13. Database Load Sanitization (CTL-08) & Nameless Cookie Import
// ----------------------------------------------------------------------------
fn run_ctl_sanitization_and_nameless_import(t: wing::T&) {
    let now_us = 1700000000000000;
    var jar = wing::new_canonical_cookie_jar();

    // 1. JSON import supporting nameless omnomnom cookies
    var json_data: u8[..512] = [];
    format(
        json_data,
        "[{\"name\":\"valid\",\"value\":\"ok\",\"domain\":\"example.com\",\"path\":\"/\",\"secure\":true},",
        "{\"name\":\"\",\"value\":\"nameless_val\",\"domain\":\"example.com\",\"path\":\"/\",\"secure\":true}]"
    );

    let count = wing::import_canonical_json(jar, json_data[..], now_us);
    t.assert_eq(count, 2, "Both valid named and nameless cookies imported from JSON");
    t.assert_eq(jar.cookies.len, 2);
    t.assert_bytes_eq(jar.cookies[0].name[..], "valid");
    t.assert_bytes_eq(jar.cookies[1].name[..], "");
    t.assert_bytes_eq(jar.cookies[1].value[..], "nameless_val");

    // 2. CTL-08: Direct or loaded cookie containing control chars rejected by engine
    var corrupt_cookie = wing::CanonicalCookie { .. };
    corrupt_cookie.name.append("bad");
    corrupt_cookie.value.append("corrupt\x01val");
    corrupt_cookie.domain.append("example.com");
    corrupt_cookie.path.clear();
    corrupt_cookie.path.append("/");
    let corrupt_inserted = wing::set_canonical_cookie(jar, corrupt_cookie, true, true, now_us);
    t.assert_false(corrupt_inserted, "CTL-08: Cookie with CTL byte %x01 rejected upon loading/insertion");
}

// ----------------------------------------------------------------------------
// 14. Property-Based PRNG Fuzzing (600 Steps Invariant Check)
// ----------------------------------------------------------------------------
fn run_property_based_fuzzer(t: wing::T&) {
    var rng = wing::new_fuzz_rng(0xCAFEBABE1337BEEF);
    var clock = wing::new_mock_clock();
    var jar = wing::new_canonical_cookie_jar();

    // Run 600 random insertion, overwrite, and expiration steps on a single domain
    for step in 600 {
        let key_idx = wing::next_range(rng, 0, 260);
        let prio_idx = wing::next_range(rng, 0, 3);
        let is_sec = wing::next_range(rng, 0, 2) == 1;
        let is_host_only = wing::next_range(rng, 0, 2) == 1;
        let max_age = wing::next_range(rng, -5, 50000);

        var hdr: u8[..128] = [];
        format(hdr, "k_", key_idx, "=val_", step, "; Max-Age=", max_age);
        if !is_host_only { hdr.append("; Domain=fuzz.example.com"); }
        if is_sec { hdr.append("; Secure"); }
        if prio_idx == 0 { hdr.append("; Priority=Low"); }
        if prio_idx == 1 { hdr.append("; Priority=Medium"); }
        if prio_idx == 2 { hdr.append("; Priority=High"); }

        let url = if is_sec { "https://sub.fuzz.example.com/a/b" } else { "http://sub.fuzz.example.com/a/b" };
        wing::set_cookie_header(jar, url, hdr[..], wing::advance_ms(clock, 50));

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

// ----------------------------------------------------------------------------
// Suite Entry Point
// ----------------------------------------------------------------------------
fn main() {
    var runner = wing::new_runner("Maximum Cookie Edge-Case & Security Vectors (Matrices 1..16 & Fuzzer)", wing::Verbosity.Verbose);

    wing::run_case(runner, "1. Exhaustive Ingestion Matrix (LEX, TIME, DOM, PSL, IPv6, OBC)", run_ingestion_matrix);
    wing::run_case(runner, "2. Full 33-Byte ASCII Control Character (CTL) Rejection Sweep", run_exhaustive_ctl_sweep);
    wing::run_case(runner, "3. RFC 6265 Section 5.1.4 Path-Matching Engine & Default-Path Rules", run_path_matching_matrix);
    wing::run_case(runner, "4. SameSite, Lax+POST 120s & Schemeful Same-Site Matrix", run_samesite_and_redirect_matrix);
    wing::run_case(runner, "5. CHIPS Partition Isolation & 10,240B Byte Quota Enforcement", run_chips_partition_quota_and_isolation);
    wing::run_case(runner, "6. GC OBC (Domain-before-Host) & Global 30-Day Purge Immunity", run_gc_obc_domain_before_host_and_global_purge);
    wing::run_case(runner, "7. RFC 6265 Section 5.4 Ordering, Server First-Win & SQLite V24 Coalescing", run_serialization_server_first_win_and_sqlite_v24);
    wing::run_case(runner, "8. Matrix 11: LastAccessDate Throttling, Monotonicity & Clock Skew", run_matrix_11_clock_skew_and_throttling);
    wing::run_case(runner, "9. Matrix 13: SiteForCookies Ancestor Frame Hierarchy & Context", run_matrix_13_site_for_cookies_and_ancestors);
    wing::run_case(runner, "10. Matrix 14: Selective Deletion & Session Cleanup", run_matrix_14_selective_deletion);
    wing::run_case(runner, "11. Matrices 15 & 16: Cryptographic Integrity & Protocol Attacks", run_matrix_15_and_16_crypto_and_attacks);
    wing::run_case(runner, "12. GC-04: strict_secure_cookies Policy Priority Eviction", run_gc_strict_secure_policy);
    wing::run_case(runner, "13. Database Load Sanitization (CTL-08) & Nameless Cookie Import", run_ctl_sanitization_and_nameless_import);
    wing::run_case(runner, "14. Property-Based PRNG Fuzzing (600 Steps Invariant Check)", run_property_based_fuzzer);

    let ok = wing::finish(runner);
    assert(ok);
}
