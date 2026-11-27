// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Consolidated Verification Suite: Core URL Parser, Normalizer, and Security Verification Suite
//
// RUN: goose build -o %t.exe %s
// RUN: %t.exe
import std;
import wing from "..";
import lit from "github.com/Lemon4ksan/goose-lit@v0.1.0";

// --- Component: core_url ---
// Tests for URL parsing, IPv6 formatting, and path resolution.

// ----------------------------------------------------------------------------
// 1. WHATWG URL Parser, IPv6 RFC 5952 Compression, and Origin
// ----------------------------------------------------------------------------
fn test_url_parser_and_origin(t: lit::T&) {
    t.run("Absolute URL Normalization & Default Port Stripping") { sub =>
        // Default port 80 for HTTP is stripped from authority
        let url_http = core::new_url("HTTP://Example.COM:80/path/to/resource?query=1#frag");
        sub.assert_true(url_http.valid, "valid HTTP url");
        sub.assert_bytes_eq(core::scheme(url_http), "http", "scheme normalized to lowercase");
        sub.assert_bytes_eq(core::host(url_http), "example.com", "host normalized to lowercase");
        sub.assert_eq(core::effective_port(url_http), 80, "effective port is 80");
        sub.assert_bytes_eq(core::port_str(url_http), "", "default port stripped from port string");
        sub.assert_bytes_eq(core::pathname(url_http), "/path/to/resource", "pathname preserved");
        sub.assert_bytes_eq(core::search(url_http), "?query=1", "search query parsed");
        sub.assert_bytes_eq(core::hash(url_http), "#frag", "fragment parsed");
        sub.assert_true(core::is_special(url_http), "http is a special scheme");

        // Non-default port 8080 for HTTP is preserved
        let url_custom_port = core::new_url("https://secure.example.com:8443/api");
        sub.assert_true(url_custom_port.valid, "valid custom port url");
        sub.assert_bytes_eq(core::scheme(url_custom_port), "https", "https scheme");
        sub.assert_bytes_eq(core::hostname(url_custom_port), "secure.example.com", "hostname without port");
        sub.assert_bytes_eq(core::host(url_custom_port), "secure.example.com:8443", "host includes port");
        sub.assert_eq(core::effective_port(url_custom_port), 8443, "effective port 8443");
        sub.assert_bytes_eq(core::port_str(url_custom_port), "8443", "port string is 8443");
        sub.assert_bytes_eq(core::pathname(url_custom_port), "/api", "pathname is /api");
    };

    t.run("IPv6 Zero-Run Compression (RFC 5952)") { sub =>
        // Full 8-group IPv6 with zero runs compressed to ::
        let url_ipv6 = core::new_url("http://[2001:0db8:0000:0000:0000:ff00:0042:8329]/");
        sub.assert_true(url_ipv6.valid, "valid IPv6 url");
        sub.assert_bytes_eq(core::host(url_ipv6), "[2001:db8::ff00:42:8329]", "zero run compressed per RFC 5952");

        // Loopback IPv6 ::1
        let url_loopback = core::new_url("http://[0000:0000:0000:0000:0000:0000:0000:0001]:8080/");
        sub.assert_true(url_loopback.valid, "valid loopback IPv6");
        sub.assert_bytes_eq(core::hostname(url_loopback), "[::1]", "loopback hostname compressed to [::1]");
        sub.assert_bytes_eq(core::host(url_loopback), "[::1]:8080", "host includes port 8080");
        sub.assert_eq(core::effective_port(url_loopback), 8080, "port 8080 preserved");

        // IPv4-mapped IPv6 [::ffff:192.168.1.1]
        let url_mapped = core::new_url("http://[::ffff:192.168.1.1]/");
        sub.assert_true(url_mapped.valid, "valid IPv4-mapped IPv6");
        sub.assert_bytes_eq(core::host(url_mapped), "[::ffff:c0a8:101]", "IPv4-mapped hex normalized");
    };

    t.run("Dot-Segment Normalization & Relative Resolution") { sub =>
        // Path dot-segment collapsing
        let url_dots = core::new_url("https://example.com/a/b/../c/./d");
        sub.assert_bytes_eq(core::pathname(url_dots), "/a/c/d", "dot segments collapsed");

        // Relative resolution against base URL
        let base_url = core::new_url("https://example.com/v1/auth/login.html");
        sub.assert_true(base_url.valid, "base url valid");

        // Relative path navigation ../dashboard
        let rel_url = core::new_url("../dashboard", base_url);
        sub.assert_true(rel_url.valid, "relative url valid");
        sub.assert_bytes_eq(core::href(rel_url), "https://example.com/v1/dashboard", "resolved ../ relative to base");

        // Root-relative path /logout
        let root_rel = core::new_url("/logout", base_url);
        sub.assert_true(root_rel.valid, "root-relative url valid");
        sub.assert_bytes_eq(core::href(root_rel), "https://example.com/logout", "resolved root-relative to base");
    };

    t.run("Origin Model: Tuple vs Opaque and Serialization") { sub =>
        let url1 = core::new_url("https://example.com/path");
        let url2 = core::new_url("https://example.com:443/other");
        let url3 = core::new_url("http://example.com/path");
        let url4 = core::new_url("https://example.com:8443/path");

        let orig1 = core::origin_from_url(url1);
        let orig2 = core::origin_from_url(url2);
        let orig3 = core::origin_from_url(url3);
        let orig4 = core::origin_from_url(url4);

        // Same origin: https://example.com == https://example.com:443
        sub.assert_true(core::is_same_origin(orig1, orig2), "same origin matches");

        // Cross-origin: scheme mismatch (https vs http)
        sub.assert_false(core::is_same_origin(orig1, orig3), "scheme mismatch is cross-origin");

        // Cross-origin: port mismatch (443 vs 8443)
        sub.assert_false(core::is_same_origin(orig1, orig4), "port mismatch is cross-origin");

        // Origin serialization
        var orig_str: u8[..64] = [];
        core::serialize_origin(orig1, orig_str);
        sub.assert_bytes_eq(orig_str[..], "https://example.com", "origin serialized without default port");

        // Opaque origin
        let opaque_a = core::new_opaque_origin();
        let opaque_b = core::new_opaque_origin();
        sub.assert_true(opaque_a.kind == core::OriginKind.Opaque, "opaque kind");
        sub.assert_false(core::is_same_origin(opaque_a, opaque_b), "two opaque origins never match");

        var opaque_str: u8[..32] = [];
        core::serialize_origin(opaque_a, opaque_str);
        sub.assert_bytes_eq(opaque_str[..], "null", "opaque origin serializes to 'null'");
    };

    t.run("Origin Model: RFC 6454 / WHATWG §7.1 Standards Conformance") { sub =>
        // 1. Port 0 Serialization (RFC 6454 §6.2: port 0 is NOT default port 80/443 and MUST be serialized)
        let url_p0_http = core::new_url("http://example.com:0/path");
        let orig_p0_http = core::origin_from_url(url_p0_http);
        var str_p0_http: u8[..64] = [];
        core::serialize_origin(orig_p0_http, str_p0_http);
        sub.assert_bytes_eq(str_p0_http[..], "http://example.com:0", "port 0 is preserved in http origin serialization");

        let url_p0_https = core::new_url("https://example.com:0/path");
        let orig_p0_https = core::origin_from_url(url_p0_https);
        var str_p0_https: u8[..64] = [];
        core::serialize_origin(orig_p0_https, str_p0_https);
        sub.assert_bytes_eq(str_p0_https[..], "https://example.com:0", "port 0 is preserved in https origin serialization");

        let tuple_p0 = core::new_origin_tuple("http", "example.com", 0);
        var str_tuple_p0: u8[..64] = [];
        core::serialize_origin(tuple_p0, str_tuple_p0);
        sub.assert_bytes_eq(str_tuple_p0[..], "http://example.com:0", "tuple with explicit port 0 serializes :0");

        // 2. Default Port Equivalence (RFC 6454 §4 & §5: omitted port -1 equals default port 80/443)
        let orig_http_80 = core::new_origin_tuple("http", "example.com", 80);
        let orig_http_omit = core::new_origin_tuple("http", "example.com", -1);
        sub.assert_true(core::is_same_origin(orig_http_80, orig_http_omit), "http port 80 and omitted port -1 are same origin");

        let orig_https_443 = core::new_origin_tuple("https", "example.com", 443);
        let orig_https_omit = core::new_origin_tuple("https", "example.com", -1);
        sub.assert_true(core::is_same_origin(orig_https_443, orig_https_omit), "https port 443 and omitted port -1 are same origin");

        let url_http_std = core::new_url("http://example.com/");
        let orig_http_std = core::origin_from_url(url_http_std);
        sub.assert_true(core::is_same_origin(orig_http_std, orig_http_omit), "URL origin matches omitted-port origin tuple");
        sub.assert_false(core::is_same_origin(orig_http_std, orig_p0_http), "port 0 is cross-origin to default port 80");

        // 3. IPv6 Host Bracket Normalization and Serialization (RFC 6454 §6.2 step 3 & RFC 3986 §3.2.2)
        let orig_ipv6_raw = core::new_origin_tuple("http", "::1", 80);
        let orig_ipv6_bracket = core::new_origin_tuple("http", "[::1]", -1);
        sub.assert_true(core::is_same_origin(orig_ipv6_raw, orig_ipv6_bracket), "IPv6 raw and bracketed hosts normalize to same origin");

        var str_ipv6: u8[..64] = [];
        core::serialize_origin(orig_ipv6_raw, str_ipv6);
        sub.assert_bytes_eq(str_ipv6[..], "http://[::1]", "IPv6 origin serialization encloses host in square brackets");

        let orig_ipv6_port = core::new_origin_tuple("https", "2001:db8::1", 8443);
        var str_ipv6_port: u8[..64] = [];
        core::serialize_origin(orig_ipv6_port, str_ipv6_port);
        sub.assert_bytes_eq(str_ipv6_port[..], "https://[2001:db8::1]:8443", "IPv6 custom port origin serialized with brackets");

        // 4. WHATWG §7.1 Blob URL Origin Inheritance across schemes
        let blob_ws = core::new_url("blob:ws://example.com:8080/uuid-ws");
        let orig_blob_ws = core::origin_from_url(blob_ws);
        var str_blob_ws: u8[..64] = [];
        core::serialize_origin(orig_blob_ws, str_blob_ws);
        sub.assert_bytes_eq(str_blob_ws[..], "ws://example.com:8080", "blob URL inherits ws: origin");

        let blob_ftp = core::new_url("blob:ftp://ftp.example.org/uuid-ftp");
        let orig_blob_ftp = core::origin_from_url(blob_ftp);
        var str_blob_ftp: u8[..64] = [];
        core::serialize_origin(orig_blob_ftp, str_blob_ftp);
        sub.assert_bytes_eq(str_blob_ftp[..], "ftp://ftp.example.org", "blob URL inherits ftp: origin");

        // 5. UrlView RFC 3986 §3.2.2 & WHATWG §4.4 Edge Cases: IPv6 Brackets and Empty Port
        let view_ipv6, err_v1 = core::parse_url_view("http://[::1]:8080/path");
        sub.assert_true(view_ipv6.valid, "UrlView parses IPv6 with port");
        sub.assert_bytes_eq(core::host(view_ipv6), "[::1]", "UrlView host includes square brackets");
        sub.assert_bytes_eq(core::hostname(view_ipv6), "[::1]", "UrlView hostname includes square brackets");

        let view_empty_port, err_v2 = core::parse_url_view("http://example.com:/path");
        sub.assert_true(view_empty_port.valid, "UrlView accepts trailing colon with empty port");
        sub.assert_eq(core::port(view_empty_port) as i64, -1, "UrlView empty port normalizes to -1");

        let view_ipv6_empty_port, err_v3 = core::parse_url_view("http://[::1]:/path");
        sub.assert_true(view_ipv6_empty_port.valid, "UrlView accepts IPv6 with empty port");
        sub.assert_bytes_eq(core::hostname(view_ipv6_empty_port), "[::1]", "UrlView IPv6 hostname intact with empty port");
        sub.assert_eq(core::port(view_ipv6_empty_port) as i64, -1, "UrlView IPv6 empty port normalizes to -1");
    };
}

// ----------------------------------------------------------------------------
// 3. WHATWG URL Standard & Security Audit Verification
// ----------------------------------------------------------------------------
fn test_whatwg_audit_fixes(t: lit::T&) {
    t.run("1.2: Origin Inheritance for blob: URLs") { sub =>
        // 1.2: blob: URLs inherit tuple origin from embedded URL in pathname
        let blob_url = core::new_url("blob:https://example.com/550e8400-e29b-41d4-a716-446655440000");
        let blob_orig = core::origin_from_url(blob_url);
        sub.assert_true(blob_orig.kind == core::OriginKind.Tuple, "blob: inherits tuple origin");
        var blob_orig_str: u8[..64] = [];
        core::serialize_origin(blob_orig, blob_orig_str);
        sub.assert_bytes_eq(blob_orig_str[..], "https://example.com", "blob origin matches embedded origin");

        let blob_custom_port = core::new_url("blob:http://example.com:8080/uuid");
        let blob_cp_orig = core::origin_from_url(blob_custom_port);
        var blob_cp_str: u8[..64] = [];
        core::serialize_origin(blob_cp_orig, blob_cp_str);
        sub.assert_bytes_eq(blob_cp_str[..], "http://example.com:8080", "blob origin preserves custom port");
    };

    t.run("1.3: C0 Control Code Points & Host Sanitization") { sub =>
        // Control character injection in host
        let bad_host_c0, err_c0 = core::parse_url("http://exam\x01ple.com/");
        sub.assert_true(err_c0 == core::UrlParseError.ForbiddenHostCodePoint, "C0 control byte 0x01 in host rejected");

        let bad_host_pct, err_pct = core::parse_url("http://example%.com/");
        sub.assert_true(err_pct == core::UrlParseError.ForbiddenHostCodePoint, "percent in host rejected");

        let bad_host_caret, err_caret = core::parse_url("http://exam^ple.com/");
        sub.assert_true(err_caret == core::UrlParseError.ForbiddenHostCodePoint, "caret in host rejected");
    };

    t.run("1.4 & 5.2: Scheme Integrity in Relative Resolution & Non-Special Schemes") { sub =>
        // 1.4: Different scheme from base does NOT silently downgrade to base scheme
        let base_http = core::new_url("http://example.com/dir/page");
        let res_https, err_https = core::parse_url_with_base("https:/secure/login", base_http);
        sub.assert_true(res_https.valid, "parsed https:/secure/login");
        sub.assert_bytes_eq(core::scheme(res_https), "https", "scheme remains https (no downgrade to http)");
        sub.assert_bytes_eq(core::host(res_https), "secure", "secure parsed as authority");
        sub.assert_bytes_eq(core::pathname(res_https), "/login", "login parsed as pathname");

        // Same scheme as base resolves path against base authority
        let res_same_scheme = core::new_url("http:/api/v1", base_http);
        sub.assert_bytes_eq(core::href(res_same_scheme), "http://example.com/api/v1", "same-scheme single slash resolves against base");

        // 5.2: Non-special scheme with single slash path
        let custom_url, custom_err = core::parse_url("custom:/a/b/c");
        sub.assert_true(custom_url.valid, "non-special scheme with single slash path is valid");
        sub.assert_bytes_eq(core::scheme(custom_url), "custom", "scheme is custom");
        sub.assert_bytes_eq(core::pathname(custom_url), "/a/b/c", "pathname is /a/b/c");

        // 5.2: Non-special scheme with empty host
        let git_url, git_err = core::parse_url("git:///repo");
        sub.assert_true(git_url.valid, "non-special scheme allows empty host");
        sub.assert_bytes_eq(core::pathname(git_url), "/repo", "git pathname is /repo");
    };

    t.run("2.1..2.3: Trailing Slash on Dot Segments, Empty Paths & 64B+ Segments") { sub =>
        // 2.1: Trailing slash preserved when path ends in .. or .
        let url_dots_parent = core::new_url("https://example.com/a/b/..");
        sub.assert_bytes_eq(core::pathname(url_dots_parent), "/a/", "trailing slash preserved on /..");

        let url_dots_cur = core::new_url("https://example.com/a/b/.");
        sub.assert_bytes_eq(core::pathname(url_dots_cur), "/a/b/", "trailing slash preserved on /.");

        let url_encoded_dots = core::new_url("https://example.com/a/b/%2e%2e");
        sub.assert_bytes_eq(core::pathname(url_encoded_dots), "/a/", "trailing slash preserved on /%2e%2e");

        // 2.2: Preserving empty path segments (// inside pathname)
        let url_empty_segs = core::new_url("https://example.com/api//v1///users");
        sub.assert_bytes_eq(core::pathname(url_empty_segs), "/api//v1///users", "empty path segments preserved");

        // 2.3: Segment longer than 64 bytes (JWT / hash)
        let long_token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIn0.abcdefghijklmnopqrstuvwxyz0123456789";
        var long_path: u8[..256] = [];
        long_path.append("https://example.com/auth/verify/");
        long_path.append(long_token);
        let url_long = core::new_url(long_path[..]);
        sub.assert_true(url_long.valid, "long segment url valid");
        sub.assert_contains(core::pathname(url_long), long_token, "long segment > 64B preserved without truncation");

        // Deep path (> 16 segments)
        let url_deep = core::new_url("https://example.com/1/2/3/4/5/6/7/8/9/10/11/12/13/14/15/16/17/18/19/20");
        sub.assert_true(url_deep.valid, "deep path > 16 segments valid");
        sub.assert_true(core::ends_with(core::pathname(url_deep), "/19/20"), "20th segment preserved");
    };

    t.run("3.1..3.4: Strict IPv6 Boundary Validation, Leading Zeros & Port 0") { sub =>
        // 3.1: Single leading colon is invalid
        let bad_ipv6_lead, err_lead = core::parse_url("http://[:1:2:3:4:5:6:7]/");
        sub.assert_false(bad_ipv6_lead.valid, "single leading colon in IPv6 rejected");
        sub.assert_true(err_lead == core::UrlParseError.InvalidIpv6, "InvalidIpv6 error on single leading colon");

        // 3.2: Trailing single colon is invalid
        let bad_ipv6_trail, err_trail = core::parse_url("http://[fe80::1:]/");
        sub.assert_false(bad_ipv6_trail.valid, "trailing single colon in IPv6 rejected");

        let bad_ipv6_full_trail, err_ft = core::parse_url("http://[1:2:3:4:5:6:7:8:]/");
        sub.assert_false(bad_ipv6_full_trail.valid, "trailing single colon on 8-piece IPv6 rejected");

        // 3.3: Leading zeros in IPv4 octet within IPv6 forbidden
        let bad_ipv4_zero, err_zero = core::parse_url("http://[::ffff:192.168.001.1]/");
        sub.assert_false(bad_ipv4_zero.valid, "leading zero in IPv4-in-IPv6 octet rejected");

        // 3.4: Port 0 is valid in WHATWG URL
        let url_port_zero, err_zero_port = core::parse_url("http://example.com:0/path");
        sub.assert_true(url_port_zero.valid, "port 0 is valid");
        sub.assert_eq(core::effective_port(url_port_zero), 0, "effective port is 0");
        sub.assert_bytes_eq(core::port_str(url_port_zero), "0", "port_str is 0");

        // Empty port after IPv6 is valid (defaults to scheme default)
        let url_ipv6_empty_port, err_ep = core::parse_url("http://[::1]:/path");
        sub.assert_true(url_ipv6_empty_port.valid, "empty port after IPv6 is valid");
        sub.assert_eq(core::effective_port(url_ipv6_empty_port), 80, "empty port defaults to 80");

        // Empty host with port in HTTP is rejected
        let url_empty_host, err_eh = core::parse_url("http://:80/path");
        sub.assert_false(url_empty_host.valid, "empty host in http rejected");
        sub.assert_true(err_eh == core::UrlParseError.MissingHost, "MissingHost on empty host");
    };

    t.run("4.2: Windows Drive Root Protection") { sub =>
        // 4.2: Windows drive letter C: protected on ..
        let url_drive_up = core::new_url("file:///C:/Users/..");
        sub.assert_bytes_eq(core::pathname(url_drive_up), "/C:/", "popping above Users leaves drive root /C:/");

        let url_drive_root_up = core::new_url("file:///C:/..");
        sub.assert_bytes_eq(core::pathname(url_drive_root_up), "/C:/", "popping above drive root stays at /C:/");
    };

    t.run("5.1 & 5.3: Base URL Without Authority & InvalidScheme Rejection") { sub =>
        // 5.1: Base URL without authority (custom:/root) resolves relative path safely
        let base_no_auth, err_base = core::parse_url("custom:/root");
        sub.assert_true(base_no_auth.valid, "base without authority valid");
        let rel_resolved, err_rel = core::parse_url_with_base("leaf", base_no_auth);
        sub.assert_true(rel_resolved.valid, "relative resolution against authority-less base succeeded");
        sub.assert_bytes_eq(core::href(rel_resolved), "custom:/leaf", "resolved relative path against authority-less base");

        // 5.3: InvalidScheme error returned when leading character is non-alpha
        let bad_scheme, err_scheme = core::parse_url("123://example.com");
        sub.assert_false(bad_scheme.valid, "123:// rejected");
        sub.assert_true(err_scheme == core::UrlParseError.InvalidScheme, "InvalidScheme returned on 123://");
    };
}

// ----------------------------------------------------------------------------
// 4. Canonical WPT & Edge Case Test Vectors (Categories 2 through 8)
// ----------------------------------------------------------------------------
fn test_canonical_wpt_and_edge_vectors(t: lit::T&) {
    t.run("Category 2: Lexer, C0 Controls, Spaces & Scheme Parsing (LEX-01..09)") { sub =>
        // LEX-01: Trim C0 control characters and spaces (<= 0x20) around edges
        let url_lex01, err_lex01 = core::parse_url("\x00\x01\x1F https://example.com/path \x20\x09\x0A");
        sub.assert_true(url_lex01.valid, "LEX-01: valid after edge trimming");
        sub.assert_bytes_eq(core::href(url_lex01), "https://example.com/path", "LEX-01: trimmed href matches");

        // LEX-02: Strip internal ASCII tab (0x09), LF (0x0A), CR (0x0D) across all parts
        let url_lex02, err_lex02 = core::parse_url("ht\ttp\n://ex\rample.com/a\tb\nc?q=1\t2#h\nash");
        sub.assert_true(url_lex02.valid, "LEX-02: valid after internal tab/newline stripping");
        sub.assert_bytes_eq(core::href(url_lex02), "http://example.com/abc?q=12#hash", "LEX-02: internal tabs/newlines removed");

        // LEX-03: Lowercase scheme and host, preserve pathname casing
        let url_lex03, err_lex03 = core::parse_url("HTTP://ExAmPlE.CoM/Path");
        sub.assert_true(url_lex03.valid, "LEX-03: valid mixed case URL");
        sub.assert_bytes_eq(core::href(url_lex03), "http://example.com/Path", "LEX-03: scheme/host lowercased, pathname preserved");

        // LEX-04: Forbidden C0 byte 0x01 in host rejected
        let url_lex04, err_lex04 = core::parse_url("http://exam\x01ple.com/");
        sub.assert_false(url_lex04.valid, "LEX-04: C0 in host rejected");
        sub.assert_true(err_lex04 == core::UrlParseError.ForbiddenHostCodePoint, "LEX-04: ForbiddenHostCodePoint on 0x01");

        // LEX-05: Forbidden byte 0x7F in host rejected
        let url_lex05, err_lex05 = core::parse_url("http://exam\x7Fple.com/");
        sub.assert_false(url_lex05.valid, "LEX-05: 0x7F DEL in host rejected");
        sub.assert_true(err_lex05 == core::UrlParseError.ForbiddenHostCodePoint, "LEX-05: ForbiddenHostCodePoint on 0x7F");

        // LEX-06: Raw percent '%' in special scheme host rejected
        let url_lex06, err_lex06 = core::parse_url("http://example%2ecom/");
        sub.assert_false(url_lex06.valid, "LEX-06: percent in host rejected");
        sub.assert_true(err_lex06 == core::UrlParseError.ForbiddenHostCodePoint, "LEX-06: ForbiddenHostCodePoint on %");

        // LEX-07: Scheme starting with digit rejected
        let url_lex07, err_lex07 = core::parse_url("123://example.com");
        sub.assert_false(url_lex07.valid, "LEX-07: scheme starting with digit rejected");
        sub.assert_true(err_lex07 == core::UrlParseError.InvalidScheme, "LEX-07: InvalidScheme on leading digit");

        // LEX-08: Scheme containing +, -, ., and digits from second char accepted
        let url_lex08, err_lex08 = core::parse_url("a+b-c.1://example.com/test");
        sub.assert_true(url_lex08.valid, "LEX-08: valid scheme with +, -, ., digits");
        sub.assert_bytes_eq(core::scheme(url_lex08), "a+b-c.1", "LEX-08: scheme matches");
        sub.assert_bytes_eq(core::href(url_lex08), "a+b-c.1://example.com/test", "LEX-08: href matches");

        // LEX-09: Empty input or whitespace-only input rejected
        let url_lex09_empty, err_lex09_empty = core::parse_url("");
        sub.assert_false(url_lex09_empty.valid, "LEX-09: empty input rejected");
        sub.assert_true(err_lex09_empty == core::UrlParseError.EmptyInput, "LEX-09: EmptyInput error on empty string");

        let url_lex09_ws, err_lex09_ws = core::parse_url(" \t\r\n ");
        sub.assert_false(url_lex09_ws.valid, "LEX-09: whitespace-only rejected");
        sub.assert_true(err_lex09_ws == core::UrlParseError.EmptyInput, "LEX-09: EmptyInput on whitespace");
    };

    t.run("Category 3: Authority, Userinfo & Interop Collisions (AUTH-01..08)") { sub =>
        // AUTH-01: Backslashes equivalent to slashes in special schemes
        let url_auth01 = core::new_url("http:\\\\example.com\\a\\b");
        sub.assert_true(url_auth01.valid, "AUTH-01: valid backslashes url");
        sub.assert_bytes_eq(core::href(url_auth01), "http://example.com/a/b", "AUTH-01: backslashes normalized to slashes");

        // AUTH-02: Special schemes absorb leading slashes
        let url_auth02 = core::new_url("https://///example.com/test");
        sub.assert_true(url_auth02.valid, "AUTH-02: valid multi-slash url");
        sub.assert_bytes_eq(core::href(url_auth02), "https://example.com/test", "AUTH-02: excess leading slashes absorbed");

        // AUTH-03: Single slash with different special scheme from base does not downgrade
        let base_auth03 = core::new_url("http://old.com/dir/p");
        let url_auth03 = core::new_url("https:/example.com/login", base_auth03);
        sub.assert_true(url_auth03.valid, "AUTH-03: valid https URL");
        sub.assert_bytes_eq(core::href(url_auth03), "https://example.com/login", "AUTH-03: scheme remains https and host is example.com");

        // AUTH-04: Single slash with same scheme as base resolves from base root
        let base_auth04 = core::new_url("http://example.com/dir/p");
        let url_auth04 = core::new_url("http:/secure/login", base_auth04);
        sub.assert_true(url_auth04.valid, "AUTH-04: valid relative resolution");
        sub.assert_bytes_eq(core::href(url_auth04), "http://example.com/secure/login", "AUTH-04: single slash resolves from root of base");

        // AUTH-05: Last @ in authority delimits userinfo per WHATWG URL
        let url_auth05 = core::new_url("http://user@evil.com:pass@good.com/");
        sub.assert_true(url_auth05.valid, "AUTH-05: valid userinfo with multiple @");
        sub.assert_bytes_eq(core::hostname(url_auth05), "good.com", "AUTH-05: host after last @ is good.com");
        sub.assert_bytes_eq(core::username(url_auth05), "user%40evil.com", "AUTH-05: username has @ encoded as %40");
        sub.assert_bytes_eq(core::password(url_auth05), "pass", "AUTH-05: password is pass");

        // AUTH-06: Empty username and empty password (:@) omitted in serialization
        let url_auth06 = core::new_url("https://:@example.com/path");
        sub.assert_true(url_auth06.valid, "AUTH-06: valid empty credentials url");
        sub.assert_bytes_eq(core::href(url_auth06), "https://example.com/path", "AUTH-06: :@ omitted from href");
        sub.assert_false(core::has_credentials(url_auth06), "AUTH-06: has_credentials is false");

        // AUTH-07: Empty password after colon (user:@) omits colon before @
        let url_auth07 = core::new_url("https://user:@example.com/");
        sub.assert_true(url_auth07.valid, "AUTH-07: valid user without password");
        sub.assert_bytes_eq(core::href(url_auth07), "https://user@example.com/", "AUTH-07: empty password omits colon");
        sub.assert_bytes_eq(core::username(url_auth07), "user", "AUTH-07: username is user");
        sub.assert_bytes_eq(core::password(url_auth07), "", "AUTH-07: password is empty");

        // AUTH-08: Empty username with password (:pass@) retains leading colon
        let url_auth08 = core::new_url("https://:pass@example.com/");
        sub.assert_true(url_auth08.valid, "AUTH-08: valid password without user");
        sub.assert_bytes_eq(core::href(url_auth08), "https://:pass@example.com/", "AUTH-08: retains leading colon");
        sub.assert_bytes_eq(core::username(url_auth08), "", "AUTH-08: username is empty");
        sub.assert_bytes_eq(core::password(url_auth08), "pass", "AUTH-08: password is pass");
    };

    t.run("Category 4: IPv6 RFC 5952 Canonical Compression & Ports (IPV6-01..10, PORT-01..07)") { sub =>
        // IPV6-01: Zero run compressed to :: and leading zeros stripped
        let url_ip01 = core::new_url("http://[2001:0db8:0000:0000:0000:0000:1428:57ab]/");
        sub.assert_bytes_eq(core::href(url_ip01), "http://[2001:db8::1428:57ab]/", "IPV6-01: zero run compressed to ::");

        // IPV6-02: Single zero block is not compressed to ::
        let url_ip02 = core::new_url("http://[2001:db8:0:1:1:1:1:1]/");
        sub.assert_bytes_eq(core::href(url_ip02), "http://[2001:db8:0:1:1:1:1:1]/", "IPV6-02: single zero block not compressed");

        // IPV6-03: Two equal zero runs compress the first run
        let url_ip03 = core::new_url("http://[2001:db8:0:0:1:0:0:1]/");
        sub.assert_bytes_eq(core::href(url_ip03), "http://[2001:db8::1:0:0:1]/", "IPV6-03: first equal zero run compressed");

        // IPV6-04: Loopback address compressed and port separation
        let url_ip04 = core::new_url("http://[0:0:0:0:0:0:0:1]:8080/");
        sub.assert_bytes_eq(core::hostname(url_ip04), "[::1]", "IPV6-04: hostname is [::1]");
        sub.assert_bytes_eq(core::host(url_ip04), "[::1]:8080", "IPV6-04: host is [::1]:8080");

        // IPV6-05: All eight zero groups compressed to [::]
        let url_ip05 = core::new_url("http://[0:0:0:0:0:0:0:0]/");
        sub.assert_bytes_eq(core::href(url_ip05), "http://[::]/", "IPV6-05: all zeros compressed to [::]");

        // IPV6-06: IPv4-mapped IPv6 suffix parsed into 2 hex blocks
        let url_ip06 = core::new_url("http://[::ffff:192.0.2.128]/");
        sub.assert_bytes_eq(core::href(url_ip06), "http://[::ffff:c000:280]/", "IPV6-06: mapped IPv4 hex converted");

        // IPV6-07: Single leading colon rejected
        let url_ip07, err_ip07 = core::parse_url("http://[:1:2:3:4:5:6:7]/");
        sub.assert_false(url_ip07.valid, "IPV6-07: single leading colon rejected");
        sub.assert_true(err_ip07 == core::UrlParseError.InvalidIpv6, "IPV6-07: InvalidIpv6");

        // IPV6-08: Trailing colon rejected
        let url_ip08, err_ip08 = core::parse_url("http://[fe80::1:]/");
        sub.assert_false(url_ip08.valid, "IPV6-08: trailing colon rejected");
        sub.assert_true(err_ip08 == core::UrlParseError.InvalidIpv6, "IPV6-08: InvalidIpv6");

        // IPV6-09: Multiple :: compressions rejected
        let url_ip09, err_ip09 = core::parse_url("http://[2001::db8::1]/");
        sub.assert_false(url_ip09.valid, "IPV6-09: double :: rejected");
        sub.assert_true(err_ip09 == core::UrlParseError.InvalidIpv6, "IPV6-09: InvalidIpv6");

        // IPV6-10: Leading zeros in IPv4 octets within IPv6 rejected
        let url_ip10, err_ip10 = core::parse_url("http://[::ffff:192.168.001.1]/");
        sub.assert_false(url_ip10.valid, "IPV6-10: leading zero in IPv4 octet rejected");
        sub.assert_true(err_ip10 == core::UrlParseError.InvalidIpv6, "IPV6-10: InvalidIpv6");

        // PORT-01: Default ports stripped in special schemes
        let u_p1_1 = core::new_url("http://example.com:80/");
        let u_p1_2 = core::new_url("https://example.com:443/");
        let u_p1_3 = core::new_url("ws://example.com:80/");
        let u_p1_4 = core::new_url("wss://example.com:443/");
        sub.assert_bytes_eq(core::href(u_p1_1), "http://example.com/", "PORT-01: http:80 stripped");
        sub.assert_bytes_eq(core::href(u_p1_2), "https://example.com/", "PORT-01: https:443 stripped");
        sub.assert_bytes_eq(core::href(u_p1_3), "ws://example.com/", "PORT-01: ws:80 stripped");
        sub.assert_bytes_eq(core::href(u_p1_4), "wss://example.com/", "PORT-01: wss:443 stripped");

        // PORT-02: Non-default ports preserved
        let u_p2_1 = core::new_url("http://example.com:443/");
        let u_p2_2 = core::new_url("https://example.com:80/");
        sub.assert_bytes_eq(core::href(u_p2_1), "http://example.com:443/", "PORT-02: http:443 preserved");
        sub.assert_bytes_eq(core::href(u_p2_2), "https://example.com:80/", "PORT-02: https:80 preserved");

        // PORT-03: Leading zeros stripped from port and default port eliminated
        let url_port03 = core::new_url("http://example.com:00000000000080/");
        sub.assert_bytes_eq(core::href(url_port03), "http://example.com/", "PORT-03: leading zeros stripped and port 80 omitted");

        // PORT-04: Port 0 is valid
        let url_port04 = core::new_url("http://example.com:0/");
        sub.assert_bytes_eq(core::href(url_port04), "http://example.com:0/", "PORT-04: port 0 serialized");
        sub.assert_bytes_eq(core::port_str(url_port04), "0", "PORT-04: port_str is 0");
        sub.assert_eq(core::effective_port(url_port04), 0, "PORT-04: effective port is 0");

        // PORT-05: Empty port after colon ignored
        let u_p5_1 = core::new_url("http://example.com:/");
        let u_p5_2 = core::new_url("http://[::1]:/");
        sub.assert_bytes_eq(core::href(u_p5_1), "http://example.com/", "PORT-05: empty port on host ignored");
        sub.assert_bytes_eq(core::href(u_p5_2), "http://[::1]/", "PORT-05: empty port on IPv6 ignored");

        // PORT-06: Port out of range (> 65535) or double port rejected
        let url_p6_high, err_p6_high = core::parse_url("http://example.com:65536/");
        sub.assert_false(url_p6_high.valid, "PORT-06: 65536 rejected");
        sub.assert_true(err_p6_high == core::UrlParseError.InvalidPort, "PORT-06: InvalidPort on 65536");

        let url_p6_double, err_p6_double = core::parse_url("http://127.0.0.1:11211:80/");
        sub.assert_false(url_p6_double.valid, "PORT-06: double port rejected");
        sub.assert_true(err_p6_double == core::UrlParseError.InvalidPort, "PORT-06: InvalidPort on double port");

        // PORT-07: Missing host in special scheme rejected
        let url_p7_mh1, err_p7_mh1 = core::parse_url("http://:80/path");
        sub.assert_false(url_p7_mh1.valid, "PORT-07: empty host in http rejected");
        sub.assert_true(err_p7_mh1 == core::UrlParseError.MissingHost, "PORT-07: MissingHost on http://:80");

        let url_p7_mh2, err_p7_mh2 = core::parse_url("https:///path");
        sub.assert_false(url_p7_mh2.valid, "PORT-07: empty host in https rejected");
        sub.assert_true(err_p7_mh2 == core::UrlParseError.MissingHost, "PORT-07: MissingHost on https:///path");
    };

    t.run("Category 5: Path Collapsing, Dot-Segments & Relative Resolution (PATH-01..07, REL-01..07)") { sub =>
        // PATH-01: Trailing slash preserved after ..
        let u_path01 = core::new_url("https://example.com/a/b/..");
        sub.assert_bytes_eq(core::pathname(u_path01), "/a/", "PATH-01: trailing slash after ..");

        // PATH-02: Trailing slash preserved after .
        let u_path02 = core::new_url("https://example.com/a/b/.");
        sub.assert_bytes_eq(core::pathname(u_path02), "/a/b/", "PATH-02: trailing slash after .");

        // PATH-03: Percent-encoded dot segments recognized case-insensitively
        let u_path03_1 = core::new_url("https://example.com/a/b/%2e");
        let u_path03_2 = core::new_url("https://example.com/a/b/%2E%2e");
        sub.assert_bytes_eq(core::pathname(u_path03_1), "/a/b/", "PATH-03: %2e preserved as dot");
        sub.assert_bytes_eq(core::pathname(u_path03_2), "/a/", "PATH-03: %2E%2e popped like ..");

        // PATH-04: Popping above root is absorbed
        let u_path04 = core::new_url("https://example.com/../../../a/b");
        sub.assert_bytes_eq(core::pathname(u_path04), "/a/b", "PATH-04: above root absorbed");

        // PATH-05: Empty path segments (//) preserved
        let u_path05 = core::new_url("https://example.com/api//v1///users");
        sub.assert_bytes_eq(core::pathname(u_path05), "/api//v1///users", "PATH-05: // preserved");

        // PATH-06: Long 120-byte segment preserved without truncation
        var long_a: u8[..256] = [];
        long_a.append("https://example.com/v1/");
        for idx in 120 {
            long_a.push('a');
        }
        long_a.append("/profile");
        let url_p6 = core::new_url(long_a[..]);
        sub.assert_true(url_p6.valid, "PATH-06: 120B segment url valid");
        sub.assert_bytes_eq(core::pathname(url_p6), long_a[19..], "PATH-06: 120B segment not truncated");

        // PATH-07: Deep path with 25 segments preserved
        var deep_path: u8[..256] = [];
        deep_path.append("https://example.com");
        for seg_idx in 25 {
            deep_path.append("/s");
            format(deep_path, (seg_idx + 1) as i64);
        }
        let url_p7 = core::new_url(deep_path[..]);
        sub.assert_true(url_p7.valid, "PATH-07: 25 segments valid");
        sub.assert_true(core::ends_with(core::pathname(url_p7), "/s24/s25"), "PATH-07: 25th segment preserved");

        // REL-01: Empty relative URL strips fragment from base
        let base_rel = core::new_url("https://example.com/a/b?q=1#old");
        let url_rel01 = core::new_url("", base_rel);
        sub.assert_bytes_eq(core::href(url_rel01), "https://example.com/a/b?q=1", "REL-01: empty rel strips hash");

        // REL-02: Hash-only relative replaces hash
        let url_rel02 = core::new_url("#new-frag", base_rel);
        sub.assert_bytes_eq(core::href(url_rel02), "https://example.com/a/b?q=1#new-frag", "REL-02: replaces hash");

        // REL-03: Query and hash relative replaces search and hash
        let base_rel_q = core::new_url("https://example.com/a/b?old=1#old");
        let url_rel03 = core::new_url("?new-query#frag", base_rel_q);
        sub.assert_bytes_eq(core::href(url_rel03), "https://example.com/a/b?new-query#frag", "REL-03: replaces search and hash");

        // REL-04: Relative without trailing slash drops last component of base
        let base_no_slash = core::new_url("https://example.com/a/b");
        let url_rel04 = core::new_url("c/d.html", base_no_slash);
        sub.assert_bytes_eq(core::href(url_rel04), "https://example.com/a/c/d.html", "REL-04: drops b and appends c/d.html");

        // REL-05: Relative with trailing slash appends inside directory
        let base_with_slash = core::new_url("https://example.com/a/b/");
        let url_rel05 = core::new_url("c/d.html", base_with_slash);
        sub.assert_bytes_eq(core::href(url_rel05), "https://example.com/a/b/c/d.html", "REL-05: appends inside directory b/");

        // REL-06: Network-path (//...) inherits scheme from base
        let url_rel06 = core::new_url("//cdn.example.org/app.js", base_no_slash);
        sub.assert_bytes_eq(core::href(url_rel06), "https://cdn.example.org/app.js", "REL-06: inherits https from base");

        // REL-07: Empty query and hash boundary (?#)
        let url_rel07 = core::new_url("https://example.com?#");
        sub.assert_bytes_eq(core::href(url_rel07), "https://example.com/?#", "REL-07: href includes ?#");
        sub.assert_bytes_eq(core::search(url_rel07), "?", "REL-07: search is ?");
        sub.assert_bytes_eq(core::hash(url_rel07), "#", "REL-07: hash is #");
    };

    t.run("Category 6: Non-Special URLs & Opaque Paths (NSPEC-01..07)") { sub =>
        // NSPEC-01: Non-special scheme with opaque path
        let url_ns01 = core::new_url("mailto:user@example.com?subject=Test#top");
        sub.assert_true(url_ns01.has_opaque_path, "NSPEC-01: opaque path true");
        sub.assert_bytes_eq(core::pathname(url_ns01), "user@example.com", "NSPEC-01: pathname is user@example.com");
        sub.assert_bytes_eq(core::search(url_ns01), "?subject=Test", "NSPEC-01: search parsed");
        sub.assert_bytes_eq(core::hash(url_ns01), "#top", "NSPEC-01: hash parsed");

        // NSPEC-02: Relative path cannot resolve against opaque base
        let base_ns02 = core::new_url("mailto:user@example.com");
        let url_ns02, err_ns02 = core::parse_url_with_base("subpage.html", base_ns02);
        sub.assert_false(url_ns02.valid, "NSPEC-02: relative against opaque base rejected");
        sub.assert_true(err_ns02 == core::UrlParseError.OpaqueBaseCannotResolveRelative, "NSPEC-02: OpaqueBaseCannotResolveRelative");

        // NSPEC-03: Fragment-only replacement allowed against opaque base
        let base_ns03 = core::new_url("data:text/html,<h1>Hi</h1>#section1");
        let url_ns03 = core::new_url("#section2", base_ns03);
        sub.assert_true(url_ns03.valid, "NSPEC-03: fragment replacement on opaque base succeeded");
        sub.assert_bytes_eq(core::href(url_ns03), "data:text/html,<h1>Hi</h1>#section2", "NSPEC-03: hash replaced on opaque base");

        // NSPEC-04: Non-special scheme does not convert backslash to slash
        let url_ns04 = core::new_url("git://github.com/a\\b/c");
        sub.assert_bytes_eq(core::href(url_ns04), "git://github.com/a\\b/c", "NSPEC-04: backslash preserved in non-special scheme");

        // NSPEC-05: Non-special scheme allows empty host
        let url_ns05 = core::new_url("git:///repo/path");
        sub.assert_true(url_ns05.valid, "NSPEC-05: valid non-special empty host");
        sub.assert_bytes_eq(core::hostname(url_ns05), "", "NSPEC-05: hostname is empty");
        sub.assert_bytes_eq(core::pathname(url_ns05), "/repo/path", "NSPEC-05: pathname is /repo/path");

        // NSPEC-06: Non-special scheme with single slash has hierarchical path with dot collapsing
        let url_ns06 = core::new_url("custom:/a/b/../c");
        sub.assert_true(url_ns06.valid, "NSPEC-06: valid hierarchical non-special");
        sub.assert_false(url_ns06.has_opaque_path, "NSPEC-06: has_opaque_path is false");
        sub.assert_bytes_eq(core::href(url_ns06), "custom:/a/c", "NSPEC-06: collapsed path to custom:/a/c");

        // NSPEC-07: Relative resolution against non-special base with slash
        let base_ns07 = core::new_url("git://host/");
        let url_ns07 = core::new_url("path", base_ns07);
        sub.assert_bytes_eq(core::href(url_ns07), "git://host/path", "NSPEC-07: resolved against non-special base");
    };

    t.run("Category 7: File URLs (FILE-01, FILE-05)") { sub =>
        // FILE-01: localhost host on file: URL is normalized to empty host
        let url_f01 = core::new_url("file://localhost/etc/hosts");
        sub.assert_bytes_eq(core::href(url_f01), "file:///etc/hosts", "FILE-01: localhost normalized to empty host");
        sub.assert_bytes_eq(core::hostname(url_f01), "", "FILE-01: hostname is empty");

        // FILE-05: Windows drive root cannot be popped by ..
        let url_f05 = core::new_url("file:///C:/Users/../..");
        sub.assert_bytes_eq(core::href(url_f05), "file:///C:/", "FILE-05: popping above drive root stays at file:///C:/");
    };

    t.run("Category 8: Origin Isolation (SEC-01..04)") { sub =>
        // SEC-01: Tuple origin omits default port 443
        let url_sec01 = core::new_url("https://Example.COM:443/a");
        var orig_str01: u8[..64] = [];
        core::serialize_origin(core::origin_from_url(url_sec01), orig_str01);
        sub.assert_bytes_eq(orig_str01[..], "https://example.com", "SEC-01: default port omitted");

        // SEC-02: Non-default port serialized in origin
        let url_sec02 = core::new_url("https://example.com:8443/a");
        var orig_str02: u8[..64] = [];
        core::serialize_origin(core::origin_from_url(url_sec02), orig_str02);
        sub.assert_bytes_eq(orig_str02[..], "https://example.com:8443", "SEC-02: non-default port serialized");

        // SEC-03: blob: inherits nested origin tuple
        let url_sec03 = core::new_url("blob:https://example.com:8443/550e8400-e29b");
        let orig_blob = core::origin_from_url(url_sec03);
        sub.assert_true(orig_blob.kind == core::OriginKind.Tuple, "SEC-03: blob origin is Tuple");
        sub.assert_bytes_eq(orig_blob.scheme[..], "https", "SEC-03: blob inherited scheme");
        sub.assert_bytes_eq(orig_blob.host[..], "example.com", "SEC-03: blob inherited host");
        sub.assert_eq(orig_blob.port, 8443, "SEC-03: blob inherited port 8443");

        // SEC-04: file: and data: origins are opaque with distinct nonces
        let url_sec04_file = core::new_url("file:///path");
        let url_sec04_data = core::new_url("data:text/plain,hi");
        let orig_file = core::origin_from_url(url_sec04_file);
        let orig_data = core::origin_from_url(url_sec04_data);
        var ser_file: u8[..64] = [];
        var ser_data: u8[..64] = [];
        core::serialize_origin(orig_file, ser_file);
        core::serialize_origin(orig_data, ser_data);
        sub.assert_bytes_eq(ser_file[..], "null", "SEC-04: file origin serialized to null");
        sub.assert_bytes_eq(ser_data[..], "null", "SEC-04: data origin serialized to null");
        sub.assert_false(core::is_same_origin(orig_file, orig_data), "SEC-04: distinct opaque origins are not same-origin");
    };

    t.run("Exhaustive Non-Happy Path Matrix: Errors, Bounds & Injection Rejection") { sub =>
        // 1. RelativeWithoutBase error when no base is provided
        let u_nobase_1, err_nobase_1 = core::parse_url("../path");
        sub.assert_false(u_nobase_1.valid, "NEG: ../path rejected without base");
        sub.assert_true(err_nobase_1 == core::UrlParseError.RelativeWithoutBase, "NEG: RelativeWithoutBase on ../path");

        let u_nobase_2, err_nobase_2 = core::parse_url("/absolute/path");
        sub.assert_false(u_nobase_2.valid, "NEG: /path rejected without base");
        sub.assert_true(err_nobase_2 == core::UrlParseError.RelativeWithoutBase, "NEG: RelativeWithoutBase on /path");

        let u_nobase_3, err_nobase_3 = core::parse_url("?search");
        sub.assert_false(u_nobase_3.valid, "NEG: ?search rejected without base");
        sub.assert_true(err_nobase_3 == core::UrlParseError.RelativeWithoutBase, "NEG: RelativeWithoutBase on ?search");

        let u_nobase_4, err_nobase_4 = core::parse_url("#fragment");
        sub.assert_false(u_nobase_4.valid, "NEG: #frag rejected without base");
        sub.assert_true(err_nobase_4 == core::UrlParseError.RelativeWithoutBase, "NEG: RelativeWithoutBase on #frag");

        let u_nobase_5, err_nobase_5 = core::parse_url("rel/leaf");
        sub.assert_false(u_nobase_5.valid, "NEG: rel/leaf rejected without base");
        sub.assert_true(err_nobase_5 == core::UrlParseError.RelativeWithoutBase, "NEG: RelativeWithoutBase on rel/leaf");

        // 2. Strict IPv6 syntax rejections
        let u_ipv6_too_many, err_ipv6_tm = core::parse_url("http://[1:2:3:4:5:6:7:8:9]/");
        sub.assert_false(u_ipv6_too_many.valid, "NEG: 9-piece IPv6 rejected");
        sub.assert_true(err_ipv6_tm == core::UrlParseError.InvalidIpv6, "NEG: InvalidIpv6 on 9 pieces");

        let u_ipv6_too_few, err_ipv6_tf = core::parse_url("http://[1:2:3]/");
        sub.assert_false(u_ipv6_too_few.valid, "NEG: 3-piece IPv6 without :: rejected");
        sub.assert_true(err_ipv6_tf == core::UrlParseError.InvalidIpv6, "NEG: InvalidIpv6 on 3 pieces");

        let u_ipv6_triple, err_ipv6_triple = core::parse_url("http://[fe80:::1]/");
        sub.assert_false(u_ipv6_triple.valid, "NEG: triple colon IPv6 rejected");
        sub.assert_true(err_ipv6_triple == core::UrlParseError.InvalidIpv6, "NEG: InvalidIpv6 on :::");

        let u_ipv6_nonhex, err_ipv6_nonhex = core::parse_url("http://[zz::1]/");
        sub.assert_false(u_ipv6_nonhex.valid, "NEG: non-hex IPv6 rejected");
        sub.assert_true(err_ipv6_nonhex == core::UrlParseError.InvalidIpv6, "NEG: InvalidIpv6 on zz");

        let u_ipv6_v4_high, err_ipv6_v4_high = core::parse_url("http://[::192.168.1.300]/");
        sub.assert_false(u_ipv6_v4_high.valid, "NEG: IPv4 mapped octet > 255 rejected");
        sub.assert_true(err_ipv6_v4_high == core::UrlParseError.InvalidIpv6, "NEG: InvalidIpv6 on octet 300");

        let u_ipv6_v4_short, err_ipv6_v4_short = core::parse_url("http://[::192.168.1]/");
        sub.assert_false(u_ipv6_v4_short.valid, "NEG: IPv4 mapped incomplete octets rejected");
        sub.assert_true(err_ipv6_v4_short == core::UrlParseError.InvalidIpv6, "NEG: InvalidIpv6 on 3 octets");

        let u_ipv6_v4_long, err_ipv6_v4_long = core::parse_url("http://[::192.168.1.1.1]/");
        sub.assert_false(u_ipv6_v4_long.valid, "NEG: IPv4 mapped 5 octets rejected");
        sub.assert_true(err_ipv6_v4_long == core::UrlParseError.InvalidIpv6, "NEG: InvalidIpv6 on 5 octets");

        // 3. Port parsing rejections
        let u_port_huge, err_port_huge = core::parse_url("http://example.com:999999/");
        sub.assert_false(u_port_huge.valid, "NEG: port 999999 rejected");
        sub.assert_true(err_port_huge == core::UrlParseError.InvalidPort, "NEG: InvalidPort on 999999");

        let u_port_alpha, err_port_alpha = core::parse_url("http://example.com:abc/");
        sub.assert_false(u_port_alpha.valid, "NEG: port abc rejected");
        sub.assert_true(err_port_alpha == core::UrlParseError.InvalidPort, "NEG: InvalidPort on abc");

        let u_port_neg, err_port_neg = core::parse_url("http://example.com:-1/");
        sub.assert_false(u_port_neg.valid, "NEG: port -1 rejected");
        sub.assert_true(err_port_neg == core::UrlParseError.InvalidPort, "NEG: InvalidPort on -1");

        let u_port_space, err_port_space = core::parse_url("http://example.com: 80/");
        sub.assert_false(u_port_space.valid, "NEG: space in port rejected");
        sub.assert_true(err_port_space == core::UrlParseError.InvalidPort, "NEG: InvalidPort on space in port");

        // 4. Host forbidden character rejections
        let u_host_space, err_host_space = core::parse_url("http://exam ple.com/");
        sub.assert_false(u_host_space.valid, "NEG: space in host rejected");
        sub.assert_true(err_host_space == core::UrlParseError.ForbiddenHostCodePoint, "NEG: ForbiddenHostCodePoint on space");

        let u_host_lt, err_host_lt = core::parse_url("http://exam<ple.com/");
        sub.assert_false(u_host_lt.valid, "NEG: < in host rejected");
        sub.assert_true(err_host_lt == core::UrlParseError.ForbiddenHostCodePoint, "NEG: ForbiddenHostCodePoint on <");

        let u_host_gt, err_host_gt = core::parse_url("http://exam>ple.com/");
        sub.assert_false(u_host_gt.valid, "NEG: > in host rejected");
        sub.assert_true(err_host_gt == core::UrlParseError.ForbiddenHostCodePoint, "NEG: ForbiddenHostCodePoint on >");

        let u_host_pipe, err_host_pipe = core::parse_url("http://exam|ple.com/");
        sub.assert_false(u_host_pipe.valid, "NEG: | in host rejected");
        sub.assert_true(err_host_pipe == core::UrlParseError.ForbiddenHostCodePoint, "NEG: ForbiddenHostCodePoint on |");

        // 5. Invalid scheme initial character rejections
        let u_scheme_excl, err_scheme_excl = core::parse_url("!https://example.com/");
        sub.assert_false(u_scheme_excl.valid, "NEG: !scheme rejected");
        sub.assert_true(err_scheme_excl == core::UrlParseError.InvalidScheme, "NEG: InvalidScheme on !");

        let u_scheme_dash, err_scheme_dash = core::parse_url("-http://example.com/");
        sub.assert_false(u_scheme_dash.valid, "NEG: -scheme rejected");
        sub.assert_true(err_scheme_dash == core::UrlParseError.InvalidScheme, "NEG: InvalidScheme on -");

        let u_scheme_plus, err_scheme_plus = core::parse_url("+ftp://example.com/");
        sub.assert_false(u_scheme_plus.valid, "NEG: +scheme rejected");
        sub.assert_true(err_scheme_plus == core::UrlParseError.InvalidScheme, "NEG: InvalidScheme on +");
    };
}

// ----------------------------------------------------------------------------
// 5. Dual-Mode URL Resolution: RFC 3986 Reference vs Backend Endpoint Joining
// ----------------------------------------------------------------------------
fn test_dual_mode_resolution_rfc_vs_endpoint(t: lit::T&) {
    t.run("Mode 2: Backend API / Service Endpoint Joining (resolve_endpoint)") { sub =>
        // Base without trailing slash: "/api" is preserved as a permanent prefix
        let base_no_slash = core::new_url("http://example.com/api");

        // Leading slash does NOT wipe out /api prefix
        let ep_slash = core::resolve_endpoint(base_no_slash, "/v1");
        sub.assert_bytes_eq(core::pathname(ep_slash), "/api/v1", "Backend: /api prefix preserved on /v1");
        sub.assert_bytes_eq(core::href(ep_slash), "http://example.com/api/v1", "Backend: href is http://example.com/api/v1");

        // Without leading slash gives identical result
        let ep_noslash = core::resolve_endpoint(base_no_slash, "v1");
        sub.assert_bytes_eq(core::pathname(ep_noslash), "/api/v1", "Backend: /api prefix preserved on v1");
        sub.assert_bytes_eq(core::href(ep_noslash), "http://example.com/api/v1", "Backend: href matches");

        // Deep subpaths with query and fragment
        let ep_deep = core::resolve_endpoint(base_no_slash, "/v1/users?limit=20#top");
        sub.assert_bytes_eq(core::pathname(ep_deep), "/api/v1/users", "Backend: deep path preserved");
        sub.assert_bytes_eq(core::search(ep_deep), "?limit=20", "Backend: query preserved");
        sub.assert_bytes_eq(core::hash(ep_deep), "#top", "Backend: hash preserved");
        sub.assert_bytes_eq(core::href(ep_deep), "http://example.com/api/v1/users?limit=20#top", "Backend: full href matches");

        // Base with trailing slash: "http://example.com/api/" does not produce double slash
        let base_with_slash = core::new_url("http://example.com/api/");
        let ep_ws_slash = core::resolve_endpoint(base_with_slash, "/v1");
        sub.assert_bytes_eq(core::pathname(ep_ws_slash), "/api/v1", "Backend: no double slash on /api/ + /v1");

        let ep_ws_noslash = core::resolve_endpoint(base_with_slash, "v1");
        sub.assert_bytes_eq(core::pathname(ep_ws_noslash), "/api/v1", "Backend: no double slash on /api/ + v1");

        // Multi-level service prefix
        let base_service = core::new_url("https://gateway.internal/service/v1");
        let ep_service = core::resolve_endpoint(base_service, "/items/42");
        sub.assert_bytes_eq(core::pathname(ep_service), "/service/v1/items/42", "Backend: multi-level prefix preserved");

        // Root base without path
        let base_root = core::new_url("http://example.com");
        let ep_root = core::resolve_endpoint(base_root, "/v1");
        sub.assert_bytes_eq(core::pathname(ep_root), "/v1", "Backend: root base gets /v1");

        // Dot-segment collapsing within endpoint
        let ep_dots = core::resolve_endpoint(base_service, "../v2/items");
        sub.assert_bytes_eq(core::pathname(ep_dots), "/service/v2/items", "Backend: dot segments collapsed");

        // Absolute URL in endpoint overrides base URL
        let ep_abs = core::resolve_endpoint(base_no_slash, "https://auth.company.com/oauth/token");
        sub.assert_bytes_eq(core::href(ep_abs), "https://auth.company.com/oauth/token", "Backend: absolute URL overrides base");

        // Protocol-relative endpoint
        let ep_proto = core::resolve_endpoint(base_no_slash, "//cdn.other.com/assets/logo.png");
        sub.assert_bytes_eq(core::href(ep_proto), "http://cdn.other.com/assets/logo.png", "Backend: protocol-relative inherits scheme");

        // UFCS syntax verification
        let ufcs_ep = base_no_slash.resolve_endpoint("/v1");
        sub.assert_bytes_eq(core::href(ufcs_ep), "http://example.com/api/v1", "UFCS: base.resolve_endpoint");

        let ufcs_join = base_no_slash.resolve_endpoint("/v1");
        sub.assert_bytes_eq(core::href(ufcs_join), "http://example.com/api/v1", "UFCS: base.resolve_endpoint");
    };
}

// ----------------------------------------------------------------------------
// Case 6: Large & Dynamic URLs (UrlView and 2048-Byte Buffer)
// ----------------------------------------------------------------------------
// ----------------------------------------------------------------------------
// 6. Large & Dynamic URLs (UrlView and 2048-Byte Buffer)
// ----------------------------------------------------------------------------
fn test_dynamic_and_large_urls(t: lit::T&) {
    t.run("Case 6.1: 2048-Byte Buffer for Large URLs with JWT Query") { sub =>
        // Construct a 1200-byte URL with a large query token
        var large_input: u8[>..] = [];
        large_input.append("https://auth.company.internal/oauth/callback?code=abc&state=");
        for i in 1000 {
            large_input.push('x');
        }
        large_input.append("&session_id=12345#auth_success");

        sub.assert_true(large_input.len > 1050, "Input is over 1050 bytes");

        // Parses cleanly into Url (exceeding previous 512B cap)
        let parsed_url = core::new_url(large_input[..]);
        sub.assert_true(parsed_url.valid, "Parsed large URL is valid");
        sub.assert_bytes_eq(core::scheme(parsed_url), "https", "Scheme is https");
        sub.assert_bytes_eq(core::hostname(parsed_url), "auth.company.internal", "Host matches");
        sub.assert_bytes_eq(core::pathname(parsed_url), "/oauth/callback", "Path matches");
        sub.assert_bytes_eq(core::hash(parsed_url), "#auth_success", "Hash matches");
        sub.assert_true(core::search(parsed_url).len > 1000, "Search query is over 1000 bytes");
        sub.assert_bytes_eq(core::href(parsed_url), large_input[..], "href reproduces full large URL");
    };

    t.run("Case 6.2: UrlView Zero-Copy Arbitrary-Length Streaming Inspection") { sub =>
        // Construct an arbitrary 5000-byte URL
        var huge_input: u8[>..] = [];
        huge_input.append("https://user:pass@streaming.cdn.org:8443/blob/stream/data?payload=");
        for i in 4000 {
            huge_input.push('A');
        }
        huge_input.append("#playback_pos_42");

        let view, view_err = core::parse_url_view(huge_input[..]);
        sub.assert_true(view.valid, "UrlView is valid for 5000-byte URL");
        sub.assert_true(view_err == core::UrlParseError.None, "UrlView has no error");
        sub.assert_bytes_eq(core::scheme(view), "https", "UrlView scheme is https");
        sub.assert_bytes_eq(core::host(view), "streaming.cdn.org", "UrlView host matches");
        sub.assert_eq(core::port(view) as i64, 8443, "UrlView port is 8443");
        sub.assert_bytes_eq(core::pathname(view), "/blob/stream/data", "UrlView pathname matches");
        sub.assert_bytes_eq(core::hash(view), "#playback_pos_42", "UrlView hash matches");
        sub.assert_true(core::search(view).len > 4000, "UrlView search query is over 4000 bytes");
    };
}

// ----------------------------------------------------------------------------
// Case 7: RFC 3986 §5.2.4 & WHATWG §4.4 Standards Verification (Trailing Dots, Slashes, Windows Drives, Multicast Zone IDs)
// ----------------------------------------------------------------------------
// ----------------------------------------------------------------------------
// 7. RFC 3986 & WHATWG Standards Edge Cases
// ----------------------------------------------------------------------------
fn test_rfc3986_whatwg_standards_edge_cases(t: lit::T&) {
    t.run("Case 7.1: WHATWG §4.4 Bare Windows Drive Trailing Slash & Boundary Normalization") { sub =>
        // Bare drive letters on file: URL MUST normalize with trailing slash
        let u_c = core::new_url("file:///C:");
        sub.assert_true(u_c.valid, "file:///C: is valid");
        sub.assert_bytes_eq(core::href(u_c), "file:///C:/", "file:///C: serializes with trailing slash");
        sub.assert_bytes_eq(core::pathname(u_c), "/C:/", "pathname has trailing slash");

        let u_pipe = core::new_url("file:///C|");
        sub.assert_true(u_pipe.valid, "file:///C| is valid");
        sub.assert_bytes_eq(core::href(u_pipe), "file:///C:/", "file:///C| normalizes pipe to colon and appends trailing slash");
        sub.assert_bytes_eq(core::pathname(u_pipe), "/C:/", "pathname has trailing slash");

        let u_lower = core::new_url("file:///c:");
        sub.assert_true(u_lower.valid, "file:///c: is valid");
        sub.assert_bytes_eq(core::href(u_lower), "file:///c:/", "file:///c: serializes with trailing slash");

        let u_dpipe = core::new_url("file:///d|");
        sub.assert_true(u_dpipe.valid, "file:///d| is valid");
        sub.assert_bytes_eq(core::href(u_dpipe), "file:///d:/", "file:///d| normalizes to d:/");

        // Windows drive segment cannot be popped by ..
        let u_dotdot = core::new_url("file:///C:/..");
        sub.assert_true(u_dotdot.valid, "file:///C:/.. is valid");
        sub.assert_bytes_eq(core::href(u_dotdot), "file:///C:/", "file:///C:/.. preserves drive letter and trailing slash");

        let u_pipedotdot = core::new_url("file:///C|/..");
        sub.assert_true(u_pipedotdot.valid, "file:///C|/.. is valid");
        sub.assert_bytes_eq(core::href(u_pipedotdot), "file:///C:/", "file:///C|/.. preserves drive letter and trailing slash");

        let u_subdotdot = core::new_url("file:///C:/foo/..");
        sub.assert_true(u_subdotdot.valid, "file:///C:/foo/.. is valid");
        sub.assert_bytes_eq(core::href(u_subdotdot), "file:///C:/", "file:///C:/foo/.. pops foo to C:/");

        let u_deepdotdot = core::new_url("file:///C:/foo/../..");
        sub.assert_true(u_deepdotdot.valid, "file:///C:/foo/../.. is valid");
        sub.assert_bytes_eq(core::href(u_deepdotdot), "file:///C:/", "file:///C:/foo/../.. pops only to C:/");

        // Non-file special scheme does not force trailing slash on drive-like path
        let u_http = core::new_url("http://example.com/C:");
        sub.assert_true(u_http.valid, "http URL is valid");
        sub.assert_bytes_eq(core::href(u_http), "http://example.com/C:", "HTTP URL does not append slash to C:");
    };

    t.run("Case 7.2: RFC 3986 §5.2.4 Dot Segments, Slashes, and Encoded Dots") { sub =>
        // Trailing single and double dots
        let u1 = core::new_url("http://example.com/a/b/.");
        sub.assert_bytes_eq(core::pathname(u1), "/a/b/", "Trailing . leaves trailing slash");

        let u2 = core::new_url("http://example.com/a/b/..");
        sub.assert_bytes_eq(core::pathname(u2), "/a/", "Trailing .. pops segment and leaves trailing slash");

        let u3 = core::new_url("http://example.com/..");
        sub.assert_bytes_eq(core::pathname(u3), "/", "Double dot at root normalizes to /");

        // Consecutive slashes with dot segment
        let u4 = core::new_url("http://example.com/a///..");
        sub.assert_bytes_eq(core::pathname(u4), "/a/", "Trailing .. after consecutive slashes pops empty segment to /a/");

        // Encoded dot segment variations (%2e and %2E)
        let u5 = core::new_url("http://example.com/a/%2e");
        sub.assert_bytes_eq(core::pathname(u5), "/a/", "%2e treated as . segment");

        let u6 = core::new_url("http://example.com/a/%2E");
        sub.assert_bytes_eq(core::pathname(u6), "/a/", "%2E treated as . segment");

        let u7 = core::new_url("http://example.com/a/%2e%2e");
        sub.assert_bytes_eq(core::pathname(u7), "/", "%2e%2e treated as .. segment");

        let u_dot8 = core::new_url("http://example.com/a/.%2e");
        sub.assert_bytes_eq(core::pathname(u_dot8), "/", ".%2e treated as .. segment");

        let u_dot9 = core::new_url("http://example.com/a/%2e.");
        sub.assert_bytes_eq(core::pathname(u_dot9), "/", "%2e. treated as .. segment");
    };

    t.run("Case 7.3: RFC 6874 §2 & RFC 4007 §5 Scoped Multicast & Zone ID Conformance") { sub =>
        // Node-Local multicast (ff01::/16) with Zone ID
        let u_ff01 = core::new_url("http://[ff01::1%25eth0]/status");
        sub.assert_true(u_ff01.valid, "ff01::/16 node-local multicast allows Zone ID");
        sub.assert_bytes_eq(core::hostname(u_ff01), "[ff01::1%25eth0]", "Host includes compressed IPv6 and zone ID");

        // Link-Local multicast (ff02::/16) with Zone ID
        let u_ff02 = core::new_url("http://[ff02::1%25eth0]:8080/data");
        sub.assert_true(u_ff02.valid, "ff02::/16 link-local multicast allows Zone ID");
        sub.assert_bytes_eq(core::hostname(u_ff02), "[ff02::1%25eth0]", "Host includes compressed IPv6 and zone ID");
        sub.assert_eq(core::effective_port(u_ff02), 8080, "Port parsed correctly");

        // Site-Local multicast (ff05::/16) with Zone ID
        let u_ff05 = core::new_url("http://[ff05::1%25eth0]/");
        sub.assert_true(u_ff05.valid, "ff05::/16 site-local multicast allows Zone ID");

        // Link-Local unicast (fe80::/10) with Zone ID
        let u_fe80 = core::new_url("http://[fe80::1%25eth0]/");
        sub.assert_true(u_fe80.valid, "fe80::/10 link-local unicast allows Zone ID");

        // Global multicast (ff0e::/16) MUST NOT allow Zone ID (RFC 6874 §2)
        let u_ff0e = core::new_url("http://[ff0e::1%25eth0]/");
        sub.assert_false(u_ff0e.valid, "ff0e::/16 global multicast MUST NOT allow Zone ID");

        // Global unicast (2001:db8::) MUST NOT allow Zone ID (RFC 6874 §2)
        let u_2001 = core::new_url("http://[2001:db8::1%25eth0]/");
        sub.assert_false(u_2001.valid, "Global unicast MUST NOT allow Zone ID");

        // UrlView zero-copy verification
        let v_good, _ = core::parse_url_view("http://[ff02::1%25eth0]:9000/metrics");
        sub.assert_true(v_good.valid, "UrlView parses scoped multicast with Zone ID");
        sub.assert_bytes_eq(core::host(v_good), "[ff02::1%25eth0]", "UrlView host matches");
        sub.assert_eq(core::port(v_good) as i64, 9000, "UrlView port is 9000");

        let v_bad, _ = core::parse_url_view("http://[ff0e::1%25eth0]:9000/metrics");
        sub.assert_false(v_bad.valid, "UrlView rejects global multicast with Zone ID");

        // RFC 6874 §2: Zone ID grammar permits unreserved (including . and ~) and pct-encoded
        let u_dot = core::new_url("http://[fe80::1%25eth0.1]/");
        sub.assert_true(u_dot.valid, "Zone ID with dot allowed");
        let u_tilde = core::new_url("http://[fe80::1%25eth~1]/");
        sub.assert_true(u_tilde.valid, "Zone ID with tilde allowed");
        let u_pct = core::new_url("http://[fe80::1%25eth%201]/");
        sub.assert_true(u_pct.valid, "Zone ID with pct-encoded character allowed");

        // RFC 6874 §4: Outgoing Host and Origin serialization MUST strip Zone ID
        var out_host: u8[..128] = [];
        core::format_outgoing_host(u_fe80, out_host);
        sub.assert_bytes_eq(out_host[..], "[fe80::1]", "format_outgoing_host strips Zone ID");

        let u_fe80_port = core::new_url("http://[fe80::1%25eth0]:8080/data");
        var out_host_p: u8[..128] = [];
        core::format_outgoing_host(u_fe80_port, out_host_p);
        sub.assert_bytes_eq(out_host_p[..], "[fe80::1]:8080", "format_outgoing_host with port strips Zone ID");

        let orig = core::origin_from_url(u_fe80_port);
        var orig_str: u8[..128] = [];
        core::serialize_origin(orig, orig_str);
        sub.assert_bytes_eq(orig_str[..], "http://[fe80::1]:8080", "serialize_origin strips Zone ID");
    };
}

// --- Component: core_url_security ---
// Tests for URL and query string parsing edge cases.

// ----------------------------------------------------------------------------
// 8. Semicolon Query Splitting Defense (CVE-2021-31525)
// ----------------------------------------------------------------------------
fn test_semicolon_query_splitting_defense(t: lit::T&) {
    t.run("QUERY-01: Semicolon is treated as literal content, NOT parameter separator (CVE-2021-31525)") { sub =>
        // Under WHATWG URL, only '&' is a delimiter; ';' is literal data.
        let raw = "?a=1;b=2";
        var out_a: u8[..64] = [];
        sub.assert_true(core::get_query_param_fast(raw, "a", out_a) == core::QueryParamMatch.Value);
        sub.assert_bytes_eq(out_a[..], "1;b=2", "Value of 'a' must be '1;b=2' verbatim");
        sub.assert_false(core::has_query_param_fast(raw, "b"), "Parameter 'b' must NOT exist (no parameter splitting on semicolon)");
    };

    t.run("QUERY-02: Canonical ampersand '&' parameter splitting") { sub =>
        let raw = "?foo=bar&baz=qux&num=42";
        var v1: u8[..64] = [];
        var v2: u8[..64] = [];
        var v3: u8[..64] = [];
        sub.assert_true(core::get_query_param_fast(raw, "foo", v1) == core::QueryParamMatch.Value);
        sub.assert_bytes_eq(v1[..], "bar");
        sub.assert_true(core::get_query_param_fast(raw, "baz", v2) == core::QueryParamMatch.Value);
        sub.assert_bytes_eq(v2[..], "qux");
        sub.assert_true(core::get_query_param_fast(raw, "num", v3) == core::QueryParamMatch.Value);
        sub.assert_bytes_eq(v3[..], "42");
    };

    t.run("QUERY-03: Verbatim query parameter extraction (RFC 3986 §3.4)") { sub =>
        let raw = "?search=hello+world%21&user_id=alice%40example.com";
        var out_search: u8[..64] = [];
        sub.assert_true(core::get_query_param_fast(raw, "search", out_search) == core::QueryParamMatch.Value);
        sub.assert_bytes_eq(out_search[..], "hello+world%21", "+ preserved verbatim");

        var dec_user: u8[..64] = [];
        sub.assert_true(core::get_query_param_fast(raw, "user_id", dec_user) == core::QueryParamMatch.Value);
        sub.assert_bytes_eq(dec_user[..], "alice%40example.com");
    };

    t.run("QUERY-04: Empty parameters and flag-only parameters") { sub =>
        let raw = "?active&filter=&category=tech";
        var out_active: u8[..64] = [];
        var out_filter: u8[..64] = [];
        var out_cat:    u8[..64] = [];
        sub.assert_true(core::has_query_param_fast(raw, "active"));
        sub.assert_true(core::get_query_param_fast(raw, "active", out_active) == core::QueryParamMatch.Valueless);
        sub.assert_bytes_eq(out_active[..], "", "Flag-only parameter has empty value");
        sub.assert_true(core::has_query_param_fast(raw, "filter"));
        sub.assert_true(core::get_query_param_fast(raw, "filter", out_filter) == core::QueryParamMatch.Value);
        sub.assert_bytes_eq(out_filter[..], "", "Empty value parameter has empty value");
        sub.assert_true(core::get_query_param_fast(raw, "category", out_cat) == core::QueryParamMatch.Value);
        sub.assert_bytes_eq(out_cat[..], "tech");
    };
}

// ----------------------------------------------------------------------------
// 9. IPv6 Host Security Bypasses (CVE-2026-25679 & CVE-2025-47912)
// ----------------------------------------------------------------------------
fn test_ipv6_host_security_bypasses(t: lit::T&) {
    t.run("IPV6-01: Bracketed IPv6 not at start of host rejection (CVE-2026-25679)") { sub =>
        // Host with prefix before bracket: bad[::1]
        let u1 = core::new_url("http://bad[::1]/");
        sub.assert_false(u1.valid, "Host with prefix before [ must be rejected");

        // Host with suffix after bracket: [::1]bad
        let u2 = core::new_url("http://[::1]bad/");
        sub.assert_false(u2.valid, "Host with suffix after ] must be rejected");

        // Host with domain and bracket: evil.com[::1]
        let u3 = core::new_url("http://evil.com[::1]/");
        sub.assert_false(u3.valid, "evil.com[::1] must be rejected");
    };

    t.run("IPV6-02: Insufficient validation of bracketed IPv6 hostnames (CVE-2025-47912)") { sub =>
        // Missing closing bracket
        let u1 = core::new_url("http://[::1/path");
        sub.assert_false(u1.valid, "Unclosed [ must be rejected");

        // Empty bracket
        let u2 = core::new_url("http://[]/");
        sub.assert_false(u2.valid, "Empty [] host must be rejected");

        // Triple colons in IPv6
        let u3 = core::new_url("http://[:::1]/");
        sub.assert_false(u3.valid, "Triple colon [:::1] must be rejected");

        // Invalid hex characters in IPv6
        let u4 = core::new_url("http://[2001:db8::zzzz]/");
        sub.assert_false(u4.valid, "Non-hex characters in IPv6 must be rejected");
    };
}

// ----------------------------------------------------------------------------
// 10. Port Number Boundaries & Overflow Defense
// ----------------------------------------------------------------------------
fn test_port_number_boundaries_and_overflow(t: lit::T&) {
    t.run("PORT-01: Port > 65535 rejection ") { sub =>
        // Boundary: 65536
        let u1 = core::new_url("http://example.com:65536/");
        sub.assert_false(u1.valid, "Port 65536 must be rejected as invalid port");

        // 70000
        let u2 = core::new_url("http://example.com:70000/");
        sub.assert_false(u2.valid, "Port 70000 must be rejected");

        // 999999
        let u3 = core::new_url("http://example.com:999999/");
        sub.assert_false(u3.valid, "Port 999999 must be rejected");

        // Max valid port 65535
        let u4 = core::new_url("http://example.com:65535/");
        sub.assert_true(u4.valid, "Port 65535 must be accepted");
        sub.assert_eq(core::effective_port(u4), 65535);
    };

    t.run("PORT-02: Non-numeric and malformed port rejection ") { sub =>
        // Non-numeric port
        let u1 = core::new_url("http://example.com:foo/");
        sub.assert_false(u1.valid, "Non-numeric port :foo must be rejected");

        // Alphanumeric port
        let u2 = core::new_url("http://example.com:80a/");
        sub.assert_false(u2.valid, "Alphanumeric port :80a must be rejected");

        // Multiple colons in non-IPv6 host
        let u3 = core::new_url("http://example.com:80:90/");
        sub.assert_false(u3.valid, "Multiple colons in host authority must be rejected");
    };
}

// ----------------------------------------------------------------------------
// 11. Path Traversal & Userinfo Isolation
// ----------------------------------------------------------------------------
fn test_path_traversal_and_userinfo(t: lit::T&) {
    t.run("TRAV-01: Mixed percent-encoded dot segments sanitization ") { sub =>
        // .%2e ("..")
        let u1 = core::new_url("https://example.com/api/.%2e/admin");
        sub.assert_true(u1.valid);
        sub.assert_bytes_eq(core::pathname(u1), "/admin", ".%2e collapsed as ..");

        // %2e. ("..")
        let u2 = core::new_url("https://example.com/api/%2e./admin");
        sub.assert_true(u2.valid);
        sub.assert_bytes_eq(core::pathname(u2), "/admin", "%2e. collapsed as ..");

        // %2e%2e ("..")
        let u3 = core::new_url("https://example.com/api/%2e%2e/admin");
        sub.assert_true(u3.valid);
        sub.assert_bytes_eq(core::pathname(u3), "/admin", "%2e%2e collapsed as ..");
    };

    t.run("USER-01: Userinfo credentials with special characters ") { sub =>
        // User with @ escaped in username
        let u1 = core::new_url("https://alice%40example.com:secret@api.service.com/");
        sub.assert_true(u1.valid);
        sub.assert_bytes_eq(core::username(u1), "alice%40example.com");
        sub.assert_bytes_eq(core::password(u1), "secret");
        sub.assert_bytes_eq(core::host(u1), "api.service.com", "Host correctly isolated from userinfo @");

        // Raw @ in password properly escaped to %40
        let u2 = core::new_url("https://bob:p@ss@service.com/");
        sub.assert_true(u2.valid);
        sub.assert_bytes_eq(core::username(u2), "bob");
        sub.assert_bytes_eq(core::host(u2), "service.com");
    };
}

// ----------------------------------------------------------------------------
// 12. Go #78948 / CVE-2026-39825: Query Parameter Truncation & Smuggling
// ----------------------------------------------------------------------------
fn test_query_param_truncation_smuggling(t: lit::T&) {
    t.run("Parameters exceeding 32 must not be silently dropped without indication") { sub =>
        // Ensure wing native symbols are linked
        var dummy: u8[..4] = "test";
        core::make_ascii_lowercase(dummy[..]);

        // Construct a query string with 35 parameters where the 33rd parameter is a security-sensitive flag.
        // In fixed-capacity parsers (capacity = 32), parameters beyond 32 are silently ignored.
        // Downstream backends parsing up to 1024 parameters see admin=true, but the proxy/WAF does not!
        var raw_query: u8[..1024] = "?";
        for i in 32 {
            raw_query.append("p");
            var num_buf: u8[..8] = [];
            format(num_buf, i);
            raw_query.append(num_buf[..]);
            raw_query.append("=val&");
        }
        raw_query.append("admin=true&role=superuser&access=full");

        sub.assert_true(core::has_query_param_fast(raw_query[..], "admin"), "Critical parameter 'admin' after 32nd item must NOT be silently lost");
        var out_admin: u8[..32] = [];
        sub.assert_true(core::get_query_param_fast(raw_query[..], "admin", out_admin) == core::QueryParamMatch.Value);
        sub.assert_bytes_eq(out_admin[..], "true", "Parameter 'admin' must have value 'true'");
    };
}

// ----------------------------------------------------------------------------
// 13. Go #78760 / CVE-2026-39821: Pure ASCII Punycode URL Host Rejection
// ----------------------------------------------------------------------------
fn test_pure_ascii_punycode_url_host_rejection(t: lit::T&) {
    t.run("URL with pure ASCII Punycode host xn--test-.com must be rejected (Go #78760)") { sub =>
        // Punycode label "xn--test-" contains no non-ASCII delta.
        // Per UTS 46 Revision 33 & Go #78760, accepting pure ASCII Punycode allows domain validation bypasses.
        let u = core::new_url("http://xn--test-.com/api");
        sub.assert_false(u.valid, "URL with pure ASCII Punycode host xn--test-.com MUST be marked invalid");
    };
}

// ----------------------------------------------------------------------------
// 15. Go #78172 & RFC 3986 §3.2.2 / RFC 9112 §3.2: Malformed IP-Literal Host
// ----------------------------------------------------------------------------
fn test_malformed_ip_literal_host_rejection(t: lit::T&) {
    t.run("Empty IP-literal Host '[]' must be rejected with 400 Bad Request") { sub =>
        // RFC 9112 §3.2 & RFC 3986 §3.2.2: Host header with empty brackets "[]"
        // is structurally invalid and must be rejected by the server parser.
        var req = http::new_request("GET", "/");
        let wire: const u8[:] = "GET / HTTP/1.1\r\nHost: []\r\n\r\n";
        let ok, _ = server::parse_http1_wire_request(wire, req);
        sub.assert_false(ok, "Host: [] must be rejected per RFC 3986 §3.2.2 and Go #78172");
    };

    t.run("Unclosed bracket IP-literal Host '[::1' must be rejected") { sub =>
        var req = http::new_request("GET", "/");
        let wire: const u8[:] = "GET / HTTP/1.1\r\nHost: [::1\r\n\r\n";
        let ok, _ = server::parse_http1_wire_request(wire, req);
        sub.assert_false(ok, "Host: [::1 must be rejected per RFC 3986 §3.2.2 and Go #78172");
    };

    t.run("Invalid IP-literal characters '[invalid_host]' must be rejected") { sub =>
        var req = http::new_request("GET", "/");
        let wire: const u8[:] = "GET / HTTP/1.1\r\nHost: [invalid_host]\r\n\r\n";
        let ok, _ = server::parse_http1_wire_request(wire, req);
        sub.assert_false(ok, "Host: [invalid_host] must be rejected per RFC 3986 §3.2.2 and Go #78172");
    };
}

// ----------------------------------------------------------------------------
// 16. Go #80282 & RFC 3986 §5.2.4: Deep Path Dot-Segment Collapse Truncation
// ----------------------------------------------------------------------------
fn test_deep_path_dot_segment_collapse(t: lit::T&) {
    t.run("Paths deeper than 64 segments must correctly pop with '..'") { sub =>
        // In core/url/parser.goose:925, seg_starts has fixed capacity 64:
        //   var seg_starts: i32[..64] = [];
        // When normalizing a path with 65 segments followed by '/leaf/..',
        // segment 65 cannot be pushed to seg_starts. A subsequent '..' pops
        // to seg_starts[63], obliterating segments 64 and 65 entirely!
        var raw_url: u8[..2000] = "http://example.com";
        for i in 65 {
            raw_url.append("/d");
        }
        raw_url.append("/leaf/..");

        let u = core::new_url(raw_url[..]);
        let p = core::pathname(u);

        // Per RFC 3986 §5.2.4, /leaf/.. must pop only /leaf, preserving all 65 /d segments.
        // It must end with "/d/" (dot-segment pop retains directory context) and retain all 65 segments.
        sub.assert_true(core::ends_with(p, "/d/"), "Deep path with >64 segments must preserve segment 65 after '..' pop");
        sub.assert_eq(p.len, 131, "Path must retain all 65 segments (131 bytes)");
    };
}

// ----------------------------------------------------------------------------
// 17. Go #62235 & RFC 6874 §2: Scoped IPv6 Link-Local URL Zone ID %25 Acceptance
// ----------------------------------------------------------------------------
fn test_scoped_ipv6_link_local_url_acceptance(t: lit::T&) {
    t.run("URL with RFC 6874 percent-encoded Zone ID [fe80::1%25eth0] must be valid") { sub =>
        // RFC 6874 Section 2:
        //   IP-literal = "[" IPv6address "%25" ZoneID "]"
        // A link-local scoped IPv6 literal with percent-encoded '%25' zone ID is standard
        // per RFC 6874 and WHATWG URL standard.
        // In core/url/parser.goose, parse_and_compress_ipv6 rejects any '%' token,
        // causing valid scoped link-local URLs to be marked invalid!
        let u = core::new_url("http://[fe80::1%25eth0]:8080/api");
        sub.assert_true(u.valid, "Scoped IPv6 URL with %25 Zone ID must be valid per RFC 6874 §2 and Go #62235");
    };
}

// ----------------------------------------------------------------------------
// 18. Go #78569 & CVE-2026-25679 follow-up: parse_url_view Trailing Garbage on IPv6 Brackets
// ----------------------------------------------------------------------------
fn test_parse_url_view_ipv6_bracket_trailing_garbage(t: lit::T&) {
    t.run("parse_url_view must reject trailing host garbage after closing bracket [::1]evil.com") { sub =>
        let view, err = core::parse_url_view("http://[::1]evil.com/api");
        sub.assert_false(view.valid, "parse_url_view MUST reject host with trailing garbage after bracket [::1]evil.com (Go #78569)");
        sub.assert_true(err != core::UrlParseError.None, "Must return parse error for malformed IPv6 host");
    };
}

// ----------------------------------------------------------------------------
// 19. RFC 3986 §3.2.2 & Go #75678 (CVE-2025-47912): parse_url_view Non-IPv6 Bracket Rejection
// ----------------------------------------------------------------------------
fn test_parse_url_view_non_ipv6_bracketed_host(t: lit::T&) {
    t.run("parse_url_view must reject bracketed domain name [google.com]") { sub =>
        // RFC 3986 Section 3.2.2:
        // IP-literal = "[" ( IPv6address / IPvFuture ) "]"
        // Hostnames and IPv4 addresses MUST NOT be enclosed in square brackets.
        // Currently, parse_url_view accepts 'http://[google.com]/path' with view.valid == true!
        let view, err = core::parse_url_view("http://[google.com]/path");
        sub.assert_false(view.valid, "parse_url_view MUST reject hostname in square brackets [google.com] (Go #75678 / CVE-2025-47912)");
        sub.assert_true(err != core::UrlParseError.None, "Must return parse error for bracketed hostname");
    };

    t.run("parse_url_view must reject bracketed IPv4 address [127.0.0.1]") { sub =>
        let view_ip, err_ip = core::parse_url_view("http://[127.0.0.1]/path");
        sub.assert_false(view_ip.valid, "parse_url_view MUST reject IPv4 address in square brackets [127.0.0.1]");
        sub.assert_true(err_ip != core::UrlParseError.None, "Must return parse error for bracketed IPv4 address");
    };
}

// ----------------------------------------------------------------------------
// 20. RFC 3986 §2 / RFC 9112 §3.2 & CVE-2023-26159: CRLF in URL View Host and Path
// ----------------------------------------------------------------------------
fn test_parse_url_view_crlf_rejection(t: lit::T&) {
    t.run("parse_url_view must reject unencoded CRLF in host") { sub =>
        // Unencoded CRLF in URL host enables HTTP request smuggling and host header injection.
        let view, err = core::parse_url_view("http://evil\r\n.com/path");
        sub.assert_false(view.valid, "parse_url_view MUST reject CRLF in host (CVE-2023-26159)");
        sub.assert_true(err != core::UrlParseError.None, "Must return parse error for CRLF in host");
    };

    t.run("parse_url_view must reject unencoded CRLF in path") { sub =>
        // Unencoded CRLF in URL path enables HTTP request line splitting and header injection.
        let view, err = core::parse_url_view("http://example.com/path\r\nInjected-Header: 1");
        sub.assert_false(view.valid, "parse_url_view MUST reject CRLF in path (CVE-2023-26159)");
        sub.assert_true(err != core::UrlParseError.None, "Must return parse error for CRLF in path");
    };
}

// ----------------------------------------------------------------------------
// 21. CVE-2025-61726 & CVE-2026-39825: Query Parameter Key Overflow Defense
// ----------------------------------------------------------------------------
fn test_query_param_key_overflow_defense(t: lit::T&) {
    t.run("percent_decode_query with 80-byte input into 64-byte buffer MUST NOT overflow") { sub =>
        var input: u8[..128] = [];
        for i in 80 { input.push('k' as u8); }
        var out_buf: u8[..64] = [];
        core::percent_decode_query(input[..], out_buf);
        sub.assert_true(out_buf.len <= 64, "Decoded buffer must not exceed capacity 64");
    };
}

// ----------------------------------------------------------------------------
// 22. RFC 3986 §4.2 & Go #81292: Relative URL Double-Slash Path Authority Protection
// ----------------------------------------------------------------------------
fn test_relative_url_double_slash_path_protection(t: lit::T&) {
    t.run("Relative path starting with encoded slashes MUST NOT be converted to authority (Go #81292)") { sub =>
        // Go #81292 / RFC 3986 Section 4.2:
        // Percent-encoded slashes in relative paths must not promote a path to a host.
        let base = core::new_url("https://example.com/api/");
        let parsed = core::new_url("/relative/path", base);
        let smuggled = core::new_url("/%2fevil.com/path", base);
        sub.assert_true(smuggled.valid, "Parsed percent-encoded slash relative URL is valid");
        sub.assert_bytes_eq(core::hostname(smuggled), "example.com", "Hostname MUST remain example.com, not promote evil.com to authority");
        sub.assert_true(parsed.valid, "Parsed relative URL is valid");
        sub.assert_bytes_eq(core::hostname(parsed), "example.com", "Hostname retained as example.com");
        sub.assert_bytes_eq(core::pathname(parsed), "/relative/path", "Pathname matches /relative/path");
    };
}

// ----------------------------------------------------------------------------
// 23. RFC 3986 §3.2.2 & Go #77578 / CVE-2025-47912: URL Bracketed Host Validation
// ----------------------------------------------------------------------------
fn test_url_bracketed_host_validation(t: lit::T&) {
    t.run("IPv4 and non-IP hostnames in brackets MUST be rejected (CVE-2025-47912)") { sub =>
        let u1 = core::new_url("http://[127.0.0.1]/");
        sub.assert_false(u1.valid, "http://[127.0.0.1]/ MUST NOT be accepted as valid URL");

        let u2 = core::new_url("http://[example.com]/");
        sub.assert_false(u2.valid, "http://[example.com]/ MUST NOT be accepted as valid URL");

        let u_valid = core::new_url("http://[::1]/");
        sub.assert_true(u_valid.valid, "http://[::1]/ is a valid IPv6 URL");
    };

    t.run("IPv6 brackets not at start of host MUST be rejected (Go #77578 / CVE-2026-25679)") { sub =>
        let u_bad_pre = core::new_url("http://foo[::1]/");
        sub.assert_false(u_bad_pre.valid, "http://foo[::1]/ MUST be rejected");

        let u_bad_mid = core::new_url("http://example.com[::1]:80/");
        sub.assert_false(u_bad_mid.valid, "http://example.com[::1]:80/ MUST be rejected");
    };
}

// --- Component: regress_issues_batch10 ---
// Phase 10 RED test suite: Heapless Fixed-Capacity Buffer Safety & RFC Invariants
// Tests capacity truncation smuggling, bounds aborts, and RFC protocol non-conformances:
//
// 1. Path dot-segment desync when segments exceed buffer capacity (core/url/parser.goose)
// 2. URL oversized input & scheme handling without runtime abort (core/url/parser.goose)
// 3. Query parameter smuggling & key truncation false match (core/url/query.goose)
// 4. MediaType parameter truncation smuggling & duplicate boundary (http/mime.goose)
// 5. Multipart oversized Content-Type header on part without abort (http/multipart.goose)
// 6. HPACK literal header with indexed name value > 16B abort (http2/hpack.goose)
// 7. HTTP/2 :authority whitespace and comma rejection (http2/hpack.goose)
// 8. HTTP/3 unknown pseudo-header (:custom) & CTL character rejection (http3/connection.goose)
// 9. Router path capacity truncation smuggling (server/router.goose)
// 10. Alt-Svc oversized proto/host/endpoint capacity safety (http/altsvc.goose)

// ----------------------------------------------------------------------------
// 24. Path dot-segment desync on segment capacity overflow (core/url/parser.goose)
// ----------------------------------------------------------------------------
fn test_path_dot_segment_capacity_desync(t: lit::T&) {
    t.run("Path dot-segment normalization MUST NOT desync when segments exceed 256") { sub =>
        // Construct a URL with 256 's' segments, followed by 'target' and '/..'
        // E.g.: http://example.com/s/s/.../s/target/..
        // Total segments before '..': 257.
        // If segment 257 ('target') is omitted from seg_starts, '/..' pops segment 256 ('s'),
        // leaving 'target' in the path and deleting an innocent earlier segment!
        var raw_url: u8[..2048] = [];
        raw_url.append("http://example.com");
        for i in 256 {
            raw_url.append("/s");
        }
        raw_url.append("/target/..");

        let parsed = core::new_url(raw_url[..]);
        sub.assert_true(parsed.valid, "URL with 257 segments should parse or fail safely");

        let path = core::pathname(parsed);
        // 'target' should have been canceled out by '..'
        let has_target = find(path, "target") >= 0;
        sub.assert_false(has_target, "Path segment 'target' MUST be canceled by '/..' and not leak into normalized path");

        // Count how many '/s' segments remain: must be exactly 256!
        var s_count = 0;
        var cur: i64 = 0;
        while cur < path.len {
            let idx = find(path[cur..], "/s");
            if idx >= 0 {
                s_count++;
                cur += idx + 2;
            } else {
                break;
            }
        }
        sub.assert_eq(s_count, 256, "Exactly 256 '/s' segments must remain; segment 256 MUST NOT be popped by target/..");
    };

    t.run("Fixed-capacity try_push and try_append return false on capacity boundary") { sub =>
        var arr: i32[..4] = [];
        sub.assert_true(arr.try_push(10), "try_push 1 should succeed");
        sub.assert_true(arr.try_push(20), "try_push 2 should succeed");
        sub.assert_true(arr.try_push(30), "try_push 3 should succeed");
        sub.assert_true(arr.try_push(40), "try_push 4 should succeed");
        sub.assert_false(arr.try_push(50), "try_push 5 MUST fail on full buffer");
        sub.assert_eq(arr.len, 4, "arr.len must remain 4 without truncation corruption");

        var str: u8[..6] = [];
        sub.assert_true(str.try_append("abc"), "try_append abc should succeed");
        sub.assert_false(str.try_append("defg"), "try_append defg MUST fail because 3 + 4 > 6");
        sub.assert_eq(str.len, 3, "str.len must remain 3 after failed try_append");
        sub.assert_true(str.try_append("def"), "try_append def should succeed exactly filling capacity");
        sub.assert_eq(str.len, 6, "str.len must be 6");
    };

    t.run("URL path depth exceeding 1024 segments returns UrlParseError.PathTooDeep") { sub =>
        var deep_path: u8[..2048] = [];
        deep_path.append("http://example.com");
        for i in 1025 {
            deep_path.push('/');
        }

        let parsed, err = core::parse_url(deep_path[..]);
        sub.assert_false(parsed.valid, "URL with > 1024 segments must be invalid");
        sub.assert_true(err == core::UrlParseError.PathTooDeep, "Error code MUST be UrlParseError.PathTooDeep");
    };
}

// ----------------------------------------------------------------------------
// 25. URL oversized input & scheme handling without runtime abort (core/url/parser.goose)
// ----------------------------------------------------------------------------
fn test_url_oversized_input_no_abort(t: lit::T&) {
    t.run("URL with scheme > 64 bytes MUST be rejected gracefully without abort") { sub =>
        var long_scheme: u8[..128] = [];
        for i in 70 { long_scheme.push('a'); }
        long_scheme.append("://example.com/");

        let parsed = core::new_url(long_scheme[..]);
        sub.assert_false(parsed.valid, "Scheme > 64 bytes MUST be marked invalid without abort");
    };

    t.run("URL input > 2048 bytes MUST be rejected gracefully without abort") { sub =>
        var giant_url: u8[>..] = [];
        giant_url.append("http://example.com/");
        for i in 2100 { giant_url.push('x'); }

        let parsed = core::new_url(giant_url[..]);
        sub.assert_false(parsed.valid, "URL input > 2048 bytes MUST be rejected without bounds abort");
    };
}

// ----------------------------------------------------------------------------
// 26. Query parameter smuggling & key truncation false match (core/url/query.goose)
// ----------------------------------------------------------------------------
fn test_query_parameter_smuggling_and_truncation(t: lit::T&) {
    t.run("Fast query param lookup MUST NOT falsely match when key exceeds 64 bytes") { sub =>
        // Construct query: ?aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa_evil=1
        // (64 'a's followed by '_evil')
        var raw_query: u8[..256] = [];
        raw_query.append("?");
        for i in 64 { raw_query.push('a'); }
        raw_query.append("_evil=1");

        // Search for 64 'a's: it MUST NOT match!
        var search_key: u8[..64] = [];
        for i in 64 { search_key.push('a'); }

        var out_val: u8[..64] = [];
        let m = core::get_query_param_fast(raw_query[..], search_key[..], out_val);
        sub.assert_true(m == core::QueryParamMatch.Missing, "Fast query param lookup MUST NOT falsely match truncated 64-byte key");
    };
}

// ----------------------------------------------------------------------------
// 27. URL & Origin (core/url/*)
// ----------------------------------------------------------------------------
fn test_url_origin_punycode_and_view_validation(t: lit::T&) {
    t.run("DNS label > 63 bytes in URL must return InvalidHost (CVE-2026-97044)") { sub =>
        var long_url: u8[..256] = [];
        long_url.append("http://");
        for i in 64 { long_url.push('a'); }
        long_url.append(".com/");

        let parsed, err = core::parse_url(long_url[..]);
        sub.assert_false(parsed.valid, "URL with host label > 63B MUST be rejected");
        sub.assert_true(err == core::UrlParseError.InvalidHost, "Error must be InvalidHost");
    };

    t.run("parse_url_view rejects empty host on special http scheme") { sub =>
        let view, err = core::parse_url_view("http:///path");
        sub.assert_false(view.valid, "Empty host for http scheme MUST return valid == false");
    };

    t.run("parse_url_view rejects forbidden space in host") { sub =>
        let view, err = core::parse_url_view("http://exa mple.com/path");
        sub.assert_false(view.valid, "Space in host MUST return valid == false");
    };

    t.run("extract_etld_plus_one with 180B domain must not abort") { sub =>
        var long_domain: u8[..256] = [];
        for i in 10 {
            long_domain.append("subdomain.");
        }
        long_domain.append("example.co.uk");

        var etld: u8[..256] = [];
        core::extract_etld_plus_one(long_domain[..], etld);
        sub.assert_eq(etld[..], "example.co.uk", "eTLD+1 correctly extracted for 180B host");
    };

    t.run("parse_endpoint returns InputTooLong on path overflow without abort") { sub =>
        var base_url_str: u8[>..] = [];
        base_url_str.append("http://example.com/");
        for i in 1500 { base_url_str.push('a'); }

        let base_url, _ = core::parse_url(base_url_str[..]);
        sub.assert_true(base_url.valid, "Base URL valid");

        var ep: u8[>..] = [];
        for i in 700 { ep.push('b'); }

        let res_url, err = core::parse_endpoint(base_url, ep[..]);
        sub.assert_false(res_url.valid, "Oversized combined path must return valid == false");
        sub.assert_true(err == core::UrlParseError.InputTooLong, "Error must be InputTooLong");
    };
}

fn main() {
    var runner = lit::new_runner("Core URL Parser, Normalizer, and Security Verification Suite", lit::Verbosity.Verbose);

    lit::run_case(runner, "1. WHATWG URL Parser, IPv6 RFC 5952 Compression & Origin", test_url_parser_and_origin);
    lit::run_case(runner, "3. WHATWG URL Standard & Security Audit Verification", test_whatwg_audit_fixes);
    lit::run_case(runner, "4. Canonical WPT & Edge Case Vectors (Categories 2..8)", test_canonical_wpt_and_edge_vectors);
    lit::run_case(runner, "5. Dual-Mode Resolution: RFC 3986 Reference vs Backend Endpoint", test_dual_mode_resolution_rfc_vs_endpoint);
    lit::run_case(runner, "6. Large & Dynamic URLs (UrlView and 2048-Byte Buffer)", test_dynamic_and_large_urls);
    lit::run_case(runner, "7. RFC 3986 & WHATWG Standards Edge Cases", test_rfc3986_whatwg_standards_edge_cases);
    lit::run_case(runner, "8. Semicolon Query Splitting Defense (CVE-2021-31525)", test_semicolon_query_splitting_defense);
    lit::run_case(runner, "9. IPv6 Host Security Bypasses (CVE-2026-25679 & CVE-2025-47912)", test_ipv6_host_security_bypasses);
    lit::run_case(runner, "10. Port Number Boundaries & Overflow Defense", test_port_number_boundaries_and_overflow);
    lit::run_case(runner, "11. Path Traversal & Userinfo Isolation", test_path_traversal_and_userinfo);
    lit::run_case(runner, "12. Go #78948 (CVE-2026-39825) Query Parameter Truncation & Smuggling", test_query_param_truncation_smuggling);
    lit::run_case(runner, "13. Go #78760 (CVE-2026-39821) Pure ASCII Punycode URL Host Rejection", test_pure_ascii_punycode_url_host_rejection);
    lit::run_case(runner, "15. Go #78172 & RFC 3986 §3.2.2 / RFC 9112 §3.2: Malformed Host", test_malformed_ip_literal_host_rejection);
    lit::run_case(runner, "16. Go #80282 & RFC 3986 §5.2.4: Deep Path Collapse Truncation", test_deep_path_dot_segment_collapse);
    lit::run_case(runner, "17. Go #62235 & RFC 6874 §2: Scoped IPv6 Link-Local URL Zone ID", test_scoped_ipv6_link_local_url_acceptance);
    lit::run_case(runner, "18. Go #78569 & CVE-2026-25679 follow-up: parse_url_view [::1]evil.com Rejection", test_parse_url_view_ipv6_bracket_trailing_garbage);
    lit::run_case(runner, "19. RFC 3986 §3.2.2 & Go #75678: parse_url_view Non-IPv6 Bracket Rejection", test_parse_url_view_non_ipv6_bracketed_host);
    lit::run_case(runner, "20. RFC 3986 §2 / RFC 9112 §3.2 & CVE-2023-26159: CRLF in URL View Host and Path", test_parse_url_view_crlf_rejection);
    lit::run_case(runner, "21. CVE-2025-61726 & CVE-2026-39825: Query Parameter Bounds Guard", test_query_param_key_overflow_defense);
    lit::run_case(runner, "22. RFC 3986 §4.2 & Go #81292: Relative URL Double-Slash Path Authority Protection", test_relative_url_double_slash_path_protection);
    lit::run_case(runner, "23. RFC 3986 §3.2.2 & Go #77578 / CVE-2025-47912: URL Bracketed Host Validation", test_url_bracketed_host_validation);
    lit::run_case(runner, "24. Path dot-segment capacity desync (core/url/parser.goose)", test_path_dot_segment_capacity_desync);
    lit::run_case(runner, "25. URL oversized input handling without abort (core/url/parser.goose)", test_url_oversized_input_no_abort);
    lit::run_case(runner, "26. Query parameter smuggling & key truncation (core/url/query.goose)", test_query_parameter_smuggling_and_truncation);
    lit::run_case(runner, "27. URL & Origin validation & bounds (core/url/*)", test_url_origin_punycode_and_view_validation);

    let ok = lit::finish(runner);
    assert(ok);
}
