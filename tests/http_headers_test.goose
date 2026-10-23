// Tests for HeaderMap, header parsing, validation, and iteration.
import std;
import wing from "..";

fn test_headermap_zero_heap_and_inline_slots(t: wing::T&) {
    t.run("Basic HeaderMap Operations and O(1) WellKnown Slots") { sub =>
        var map = wing::new_header_map();
        sub.assert_true(map.valid, "Newly created map is valid");

        // Set well-known inline headers
        let ok_host = wing::set_inline(map, wing::WellKnownHeader.Host, "api.service.internal");
        sub.assert_true(ok_host, "Set inline host succeeded");
        let ok_ct = wing::set_inline(map, wing::WellKnownHeader.ContentType, "application/json; charset=utf-8");
        sub.assert_true(ok_ct, "Set inline content-type succeeded");
        let ok_cl = wing::set_inline(map, wing::WellKnownHeader.ContentLength, "1024");
        sub.assert_true(ok_cl, "Set inline content-length succeeded");

        // O(1) retrieval
        sub.assert_bytes_eq(wing::get_inline(map, wing::WellKnownHeader.Host), "api.service.internal", "Inline Host match");
        sub.assert_bytes_eq(wing::get_inline(map, wing::WellKnownHeader.ContentType), "application/json; charset=utf-8", "Inline Content-Type match");
        sub.assert_bytes_eq(wing::get_inline(map, wing::WellKnownHeader.ContentLength), "1024", "Inline Content-Length match");

        // Case-insensitive retrieval via general accessor
        sub.assert_bytes_eq(wing::get_header(map, "HOST"), "api.service.internal", "Case-insensitive HOST lookup");
        sub.assert_bytes_eq(wing::get_header(map, "content-TYPE"), "application/json; charset=utf-8", "Case-insensitive content-TYPE lookup");
        sub.assert_true(wing::has_header(map, "content-length"), "has_header content-length true");
        sub.assert_false(wing::has_header(map, "authorization"), "has_header authorization false");
    };

    t.run("Custom Headers & Overwrite Behavior") { sub =>
        var map = wing::new_header_map();
        wing::append_header(map, "X-Custom-Engine", "GooseWing/1.0");
        wing::append_header(map, "X-Trace-ID", "trace-abc-123");

        sub.assert_bytes_eq(wing::get_header(map, "x-custom-engine"), "GooseWing/1.0", "Custom header found");
        sub.assert_bytes_eq(wing::get_header(map, "x-trace-id"), "trace-abc-123", "Trace ID found");

        // Overwrite via insert_header
        wing::insert_header(map, "x-trace-id", "trace-xyz-999");
        sub.assert_bytes_eq(wing::get_header(map, "x-trace-id"), "trace-xyz-999", "Trace ID overwritten");

        // Removal
        let removed = wing::remove_header(map, "X-Custom-Engine");
        sub.assert_true(removed, "Header successfully removed");
        sub.assert_false(wing::has_header(map, "X-Custom-Engine"), "Removed header no longer present");
    };

    t.run("Connection Reuse (reset_for_keep_alive)") { sub =>
        var map = wing::new_header_map();
        wing::set_inline(map, wing::WellKnownHeader.Host, "example.com");
        wing::append_header(map, "X-Req", "1");
        sub.assert_eq(map.entries.len, 2, "2 entries before reset");

        wing::reset_for_keep_alive(map);
        sub.assert_eq(map.entries.len, 0, "0 entries after reset");
        sub.assert_eq(map.raw_buf.len, 0, "raw_buf cleared after reset");
        sub.assert_bytes_eq(wing::get_inline(map, wing::WellKnownHeader.Host), "", "Inline slot cleared");

        // Re-use for next request
        wing::set_inline(map, wing::WellKnownHeader.Host, "reused.com");
        sub.assert_bytes_eq(wing::get_inline(map, wing::WellKnownHeader.Host), "reused.com", "Inline slot reused cleanly");
    };
}

fn test_rfc9110_and_cookie_fold_isolation(t: wing::T&) {
    t.run("List-Based Header Comma Folding (Vary, Accept)") { sub =>
        var map = wing::new_header_map();
        wing::append_header(map, "Vary", "Accept-Encoding");
        wing::append_header(map, "Vary", "User-Agent");
        wing::append_header(map, "Vary", "Origin");

        var combined: u8[>..] = [];
        let ok = wing::get_combined(map, "Vary", combined);
        sub.assert_true(ok, "Vary is comma-foldable per RFC 9110 Section 5.3");
        sub.assert_bytes_eq(combined[..], "Accept-Encoding, User-Agent, Origin", "Vary folded correctly");
    };

    t.run("Absolute Prohibition of Set-Cookie Folding (RFC 6265bis & RFC 9110 Section 5.3)") { sub =>
        var map = wing::new_header_map();
        wing::append_header(map, "Set-Cookie", "session_id=abc; Secure; HttpOnly; SameSite=Strict");
        wing::append_header(map, "Set-Cookie", "theme=dark; Path=/; Max-Age=86400");
        wing::append_header(map, "Set-Cookie", "cart=item1,item2; Path=/cart");

        // get_combined MUST fail on Set-Cookie!
        var combined: u8[>..] = [];
        let ok = wing::get_combined(map, "Set-Cookie", combined);
        sub.assert_false(ok, "get_combined MUST reject Set-Cookie to prevent session ambiguity");

        // get_set_cookie zero-allocation extraction
        var cookies: u8[..1024][>..] = [];
        wing::get_set_cookie(map, cookies);
        sub.assert_eq(cookies.len, 3, "Exactly 3 distinct Set-Cookie entries returned");
        sub.assert_bytes_eq(cookies[0][..], "session_id=abc; Secure; HttpOnly; SameSite=Strict", "Cookie 1 exact");
        sub.assert_bytes_eq(cookies[1][..], "theme=dark; Path=/; Max-Age=86400", "Cookie 2 exact");
        sub.assert_bytes_eq(cookies[2][..], "cart=item1,item2; Path=/cart", "Cookie 3 exact");

        // Serialization must emit multiple Set-Cookie lines without comma folding
        var serialized: u8[>..] = [];
        wing::serialize_headers(map, serialized);
        sub.assert_contains(serialized[..], "Set-Cookie: session_id=abc", "Contains line 1");
        sub.assert_contains(serialized[..], "Set-Cookie: theme=dark", "Contains line 2");
        sub.assert_contains(serialized[..], "Set-Cookie: cart=item1,item2", "Contains line 3");
    };

    t.run("Authentication Challenge Fold Isolation (WWW-Authenticate)") { sub =>
        var map = wing::new_header_map();
        wing::append_header(map, "WWW-Authenticate", "Basic realm=\"Access to staging\"");
        wing::append_header(map, "WWW-Authenticate", "Bearer error=\"invalid_token\"");

        var combined: u8[>..] = [];
        let ok = wing::get_combined(map, "WWW-Authenticate", combined);
        sub.assert_false(ok, "get_combined MUST reject WWW-Authenticate folding");
    };
}

fn test_lexical_validation_and_swar(t: wing::T&) {
    t.run("Valid tchar and Invalid Header Name Checks") { sub =>
        sub.assert_true(wing::is_valid_header_name("Content-Type"), "Content-Type is valid");
        sub.assert_true(wing::is_valid_header_name("x-api-key_2.0"), "x-api-key_2.0 is valid");
        sub.assert_true(wing::is_valid_header_name("!#$%&'*+-.^_`|~"), "All RFC 9110 tchars are valid");

        sub.assert_false(wing::is_valid_header_name(""), "Empty header name is invalid");
        sub.assert_false(wing::is_valid_header_name("Content Type"), "Header name with space is invalid");
        sub.assert_false(wing::is_valid_header_name("Header:Name"), "Colon in name is invalid");
        sub.assert_false(wing::is_valid_header_name("Header\tTab"), "Tab in name is invalid");
    };

    t.run("RFC 9113 Section 8.2.1: HTTP/2 Wire Lowercase ASCII Validation") { sub =>
        sub.assert_true(wing::is_valid_header_name_h2("content-type"), "Lowercase is valid in HTTP/2");
        sub.assert_true(wing::is_valid_header_name_h2(":path"), "Pseudo-header is valid");
        sub.assert_false(wing::is_valid_header_name_h2("Content-Type"), "Uppercase is FORBIDDEN on wire in HTTP/2");
        sub.assert_false(wing::is_valid_header_name_h2("HOST"), "Uppercase HOST is FORBIDDEN in HTTP/2");
    };

    t.run("Control Character and Embedded NUL Injection Hard Rejection") { sub =>
        // Embedded NUL
        var map = wing::new_header_map();
        let nul_raw: u8[28] = ['H','o','s','t',':',' ','a',0,'b','c','.','c','o','m','\r','\n','\r','\n', 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        let err_nul = wing::parse_headers(nul_raw[..18], map);
        sub.assert_eq(err_nul, wing::HeaderParseError.EmbeddedNull, "Embedded NUL causes immediate parse failure");

        // CRLF in value
        sub.assert_false(wing::is_valid_header_value("valid\r\ninjected: true"), "CRLF in value rejected");
        sub.assert_false(wing::is_valid_header_value("bad\x01control"), "CTL rejected in value");
        sub.assert_true(wing::is_valid_header_value("normal value with \t tab"), "HTAB accepted in value");
    };

    t.run("Whitespace before Colon Rejection (RFC 9110 Section 5.1)") { sub =>
        var map = wing::new_header_map();
        let raw = "Host : example.com\r\n\r\n";
        let err = wing::parse_headers(raw, map);
        sub.assert_eq(err, wing::HeaderParseError.InvalidHeaderName, "Space before colon rejected");
    };
}

fn test_httparse_regression_and_obs_fold(t: wing::T&) {
    t.run("httparse PR #223 / Issue #222: Whitespace-Only Line Hard Syntax Error") { sub =>
        var map = wing::new_header_map();
        // A line containing only spaces between valid headers MUST NOT silently truncate headers!
        let raw = "Host: example.com\r\n   \r\nX-Secret: leak\r\n\r\n";
        let err = wing::parse_headers(raw, map);
        sub.assert_eq(err, wing::HeaderParseError.WhitespaceOnlyLine, "Whitespace-only line produces hard syntax error");
        sub.assert_false(map.valid, "Map marked invalid on whitespace-only line");
    };

    t.run("obs-fold Request Smuggling Defense") { sub =>
        var map = wing::new_header_map();
        let raw_fold = "Header: initial\r\n continuation\r\n\r\n";

        // Default: obs-fold rejected
        let err_forbidden = wing::parse_headers(raw_fold, map, false);
        sub.assert_eq(err_forbidden, wing::HeaderParseError.ObsFoldForbidden, "obs-fold forbidden by default");

        // Archival compatibility mode: obs-fold permitted and folded
        let err_ok = wing::parse_headers(raw_fold, map, true);
        sub.assert_eq(err_ok, wing::HeaderParseError.None, "obs-fold accepted in compatibility mode");
        sub.assert_bytes_eq(wing::get_header(map, "header"), "initial continuation", "Folded with single space");

        // Leading whitespace on very first line fails even in compatibility mode
        let raw_bad_first = "  first-line-ws: bad\r\n\r\n";
        let err_bad_first = wing::parse_headers(raw_bad_first, map, true);
        sub.assert_eq(err_bad_first, wing::HeaderParseError.LeadingWhitespaceOnFirstHeader, "Leading whitespace on first header rejected");
    };
}

fn test_chromium_net_parity(t: wing::T&) {
    t.run("Chromium raw_headers_ \\0\\0 Format") { sub =>
        var map = wing::new_header_map();
        wing::append_header(map, "Host", "chromium.org");
        wing::append_header(map, "Accept", "*/*");

        var raw_out: u8[>..] = [];
        wing::raw_headers(map, raw_out);

        // Lines terminated with \0, whole block with double \0
        sub.assert_true(raw_out.len > 0, "raw_out non-empty");
        sub.assert_eq(raw_out[raw_out.len - 1], 0, "Terminated with \0");
        sub.assert_eq(raw_out[raw_out.len - 2], 0, "Terminated with double \0\0");
    };

    t.run("Chromium 304 Not Modified Merge (Shielding Cookies and Challenges)") { sub =>
        var cached = wing::new_header_map();
        wing::append_header(cached, "ETag", "\"etag-123\"");
        wing::append_header(cached, "Cache-Control", "max-age=3600");
        wing::append_header(cached, "Set-Cookie", "session=original; Secure");
        wing::append_header(cached, "Strict-Transport-Security", "max-age=31536000");

        var resp_304 = wing::new_header_map();
        wing::append_header(resp_304, "Cache-Control", "max-age=7200");
        wing::append_header(resp_304, "Set-Cookie", "session=hijacked");
        wing::append_header(resp_304, "Strict-Transport-Security", "max-age=0");
        wing::append_header(resp_304, "X-Fresh-Header", "injected");

        wing::merge_with_headers_304(cached, resp_304);

        // Cache-Control updated to 7200
        sub.assert_bytes_eq(wing::get_header(cached, "Cache-Control"), "max-age=7200", "Cache-Control updated");
        // Fresh custom header merged
        sub.assert_bytes_eq(wing::get_header(cached, "X-Fresh-Header"), "injected", "Fresh header merged");
        // Set-Cookie MUST NOT be overwritten or injected by 304!
        sub.assert_bytes_eq(wing::get_header(cached, "Set-Cookie"), "session=original; Secure", "Set-Cookie preserved from cache");
        // Strict-Transport-Security MUST NOT be downgraded by 304!
        sub.assert_bytes_eq(wing::get_header(cached, "Strict-Transport-Security"), "max-age=31536000", "HSTS preserved from cache");
    };

    t.run("Chromium Cache Persistence Filtering") { sub =>
        var src = wing::new_header_map();
        wing::append_header(src, "Content-Type", "text/html");
        wing::append_header(src, "Set-Cookie", "user=alice");
        wing::append_header(src, "WWW-Authenticate", "Basic realm=\"admin\"");
        wing::append_header(src, "Connection", "keep-alive");

        var dst = wing::new_header_map();
        wing::persist_headers(src, dst, wing::PERSIST_SANS_COOKIES | wing::PERSIST_SANS_CHALLENGES | wing::PERSIST_SANS_NON_CACHEABLE);

        sub.assert_true(wing::has_header(dst, "Content-Type"), "Content-Type persisted");
        sub.assert_false(wing::has_header(dst, "Set-Cookie"), "Set-Cookie stripped");
        sub.assert_false(wing::has_header(dst, "WWW-Authenticate"), "WWW-Authenticate stripped");
        sub.assert_false(wing::has_header(dst, "Connection"), "Connection stripped");
    };
}

// ---- consolidated suite entry point ---------------------------------------

fn main() {
    var runner = wing::new_runner("HTTP Headers & Lexical Verification Suite", wing::Verbosity.Verbose);

    wing::run_case(runner, "1. Zero-Heap HeaderMap & Inline Slots", test_headermap_zero_heap_and_inline_slots);
    wing::run_case(runner, "2. RFC 9110 & Set-Cookie Fold Isolation", test_rfc9110_and_cookie_fold_isolation);
    wing::run_case(runner, "3. Lexical Validation & SWAR", test_lexical_validation_and_swar);
    wing::run_case(runner, "4. httparse PR #223 Regression & obs-fold", test_httparse_regression_and_obs_fold);
    wing::run_case(runner, "5. Chromium Net Parity (raw_headers, 304 Merge, Persistence)", test_chromium_net_parity);

    let ok = wing::finish(runner);
    assert(ok);
}
