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
// 3. RFC 6265 §5.1.4 Path-Matching Engine & Default-Path Rules
// ----------------------------------------------------------------------------
fn run_path_matching_matrix(t: wing::T&) {
    // PATH-01: https://example.com (empty uri-path) -> default-path "/"
    var p1: u8[..32] = [];
    wing::default_cookie_path_calc("", p1);
    t.assert_bytes_eq(p1[..], "/", "PATH-01 empty uri-path");

    // PATH-02: https://example.com/ -> default-path "/"
    var p2: u8[..32] = [];
    wing::default_cookie_path_calc("/", p2);
    t.assert_bytes_eq(p2[..], "/", "PATH-02 single / uri-path");

    // PATH-03: https://example.com/docs (single leading slash) -> default-path "/"
    var p3: u8[..32] = [];
    wing::default_cookie_path_calc("/docs", p3);
    t.assert_bytes_eq(p3[..], "/", "PATH-03 single leading / without sub-dirs");

    // PATH-04: https://example.com/a/b/c -> default-path "/a/b"
    var p4: u8[..32] = [];
    wing::default_cookie_path_calc("/a/b/c", p4);
    t.assert_bytes_eq(p4[..], "/a/b", "PATH-04 directory prefix");

    // PATH-05: https://example.com/a/b/ (trailing slash) -> default-path "/a/b"
    var p5: u8[..32] = [];
    wing::default_cookie_path_calc("/a/b/", p5);
    t.assert_bytes_eq(p5[..], "/a/b", "PATH-05 trailing slash stripped");

    // Cookie-path matching rules:
    t.assert_true(wing::cookie_path_match("/a/b", "/a/b"), "exact match");
    t.assert_true(wing::cookie_path_match("/a/b/", "/a/b"), "slash boundary");
    t.assert_true(wing::cookie_path_match("/a/b/page", "/a/b"), "subpath match");
    t.assert_false(wing::cookie_path_match("/a/bc", "/a/b"), "prefix without slash boundary must fail");

    // PATH-08: cookie-path ends with '/'
    t.assert_true(wing::cookie_path_match("/custom/", "/custom/"), "exact slash match");
    t.assert_true(wing::cookie_path_match("/custom/page", "/custom/"), "subpath match");
    t.assert_false(wing::cookie_path_match("/custom", "/custom/"), "request shorter than cookie path must fail");
}

// ----------------------------------------------------------------------------
// 4. Server-Side Ingoing Cookie Header Parser (§5.4 First-Win Invariant)
// ----------------------------------------------------------------------------
fn run_server_header_first_win(t: wing::T&) {
    // SRV-01: Specific Path=/admin cookie comes first, general Path=/ cookie comes second
    let raw_header = "sid=admin_token; user=alice; sid=guest_token; theme=dark; user=mallory";
    var parsed_cookies: wing::CanonicalCookie[>..] = [];
    wing::parse_server_cookie_header(raw_header, 1000000, parsed_cookies);

    t.assert_eq(parsed_cookies.len, 3, "Exactly 3 distinct cookies parsed");
    t.assert_bytes_eq(parsed_cookies[0].name[..], "sid");
    t.assert_bytes_eq(parsed_cookies[0].value[..], "admin_token", "First occurrence of sid preserved");
    t.assert_bytes_eq(parsed_cookies[1].name[..], "user");
    t.assert_bytes_eq(parsed_cookies[1].value[..], "alice", "First occurrence of user preserved");
    t.assert_bytes_eq(parsed_cookies[2].name[..], "theme");
    t.assert_bytes_eq(parsed_cookies[2].value[..], "dark", "Theme parsed");
}

// ----------------------------------------------------------------------------
// Suite Entry Point
// ----------------------------------------------------------------------------
fn main() {
    var runner = wing::new_runner("Maximum Cookie Edge-Case & Security Vectors", wing::Verbosity.Verbose);
    wing::run_case(runner, "1. Exhaustive Ingestion Matrix (LEX, TIME, DOM, PSL, IPv6, OBC)", run_ingestion_matrix);
    wing::run_case(runner, "2. Full 33-Byte ASCII Control Character (CTL) Rejection Sweep", run_exhaustive_ctl_sweep);
    wing::run_case(runner, "3. RFC 6265 §5.1.4 Path-Matching Engine & Default-Path Rules", run_path_matching_matrix);
    wing::run_case(runner, "4. Server-Side Ingoing Cookie Header Parser (First-Win Invariant)", run_server_header_first_win);
    let ok = wing::finish(runner);
    assert(ok);
}
