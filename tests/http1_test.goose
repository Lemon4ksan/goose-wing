// RUN: goose build -o %t.exe %s
// RUN: %t.exe
// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Consolidated Verification Suite: HTTP/1.1 Framing, Chunked Transfer, and Smuggling Defense Suite
import std;
import core from "..";
import wing from "..";
import lit from "github.com/Lemon4ksan/goose-lit@v0.1.0";

// --- Component: http_headers ---
// Tests for HeaderMap, header parsing, validation, and iteration.

fn test_headermap_zero_heap_and_inline_slots(t: lit::T&) {
    t.run("Basic HeaderMap Operations and O(1) WellKnown Slots") { sub =>
        var map = wing::HeaderMap { .. };
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
        var map = wing::HeaderMap { .. };
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
        var map = wing::HeaderMap { .. };
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

fn test_rfc9110_and_cookie_fold_isolation(t: lit::T&) {
    t.run("List-Based Header Comma Folding (Vary, Accept)") { sub =>
        var map = wing::HeaderMap { .. };
        wing::append_header(map, "Vary", "Accept-Encoding");
        wing::append_header(map, "Vary", "User-Agent");
        wing::append_header(map, "Vary", "Origin");

        var combined: u8[>..] = [];
        let ok = wing::get_combined(map, "Vary", combined);
        sub.assert_true(ok, "Vary is comma-foldable per RFC 9110 Section 5.3");
        sub.assert_bytes_eq(combined[..], "Accept-Encoding, User-Agent, Origin", "Vary folded correctly");
    };

    t.run("Absolute Prohibition of Set-Cookie Folding (RFC 6265bis & RFC 9110 Section 5.3)") { sub =>
        var map = wing::HeaderMap { .. };
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
        var map = wing::HeaderMap { .. };
        wing::append_header(map, "WWW-Authenticate", "Basic realm=\"Access to staging\"");
        wing::append_header(map, "WWW-Authenticate", "Bearer error=\"invalid_token\"");

        var combined: u8[>..] = [];
        let ok = wing::get_combined(map, "WWW-Authenticate", combined);
        sub.assert_false(ok, "get_combined MUST reject WWW-Authenticate folding");
    };
}

fn test_lexical_validation_and_swar(t: lit::T&) {
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
        var map = wing::HeaderMap { .. };
        let nul_raw: u8[28] = ['H', 'o', 's', 't', ':', ' ', 'a', 0, 'b', 'c', '.', 'c', 'o', 'm', '\r', '\n', '\r', '\n', 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        let err_nul = wing::parse_headers(nul_raw[..18], map);
        sub.assert_eq(err_nul, wing::HeaderParseError.EmbeddedNull, "Embedded NUL causes immediate parse failure");

        // CRLF in value
        sub.assert_false(wing::is_valid_header_value("valid\r\ninjected: true"), "CRLF in value rejected");
        sub.assert_false(wing::is_valid_header_value("bad\x01control"), "CTL rejected in value");
        sub.assert_true(wing::is_valid_header_value("normal value with \t tab"), "HTAB accepted in value");
    };

    t.run("Whitespace before Colon Rejection (RFC 9110 Section 5.1)") { sub =>
        var map = wing::HeaderMap { .. };
        let raw = "Host : example.com\r\n\r\n";
        let err = wing::parse_headers(raw, map);
        sub.assert_eq(err, wing::HeaderParseError.InvalidHeaderName, "Space before colon rejected");
    };

    t.run("parse_response_headers status line and headers") { sub =>
        var map = wing::HeaderMap { .. };
        let raw = "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n";
        let err = wing::parse_response_headers(raw, map);
        sub.assert_eq(err, wing::HeaderParseError.None, "Response headers parsed");
        sub.assert_eq(map.status_code, 200, "Status code is 200");
    };

    t.run("HeaderPresenceTracker Duplicate Transfer-Encoding Smuggling Rejection") { sub =>
        var tracker = wing::HeaderPresenceTracker { .. };
        sub.assert_true(wing::track_header_presence(tracker, "Transfer-Encoding", "chunked", 0), "First TE accepted");
        sub.assert_false(wing::track_header_presence(tracker, "Transfer-Encoding", "identity", 1), "Duplicate TE rejected");
        sub.assert_true(tracker.has_duplicate_te, "has_duplicate_te flag set");
    };

    t.run("advance_crlf Strict Line Ending Validation") { sub =>
        let valid_crlf = "header: value\r\nnext";
        var c1: i64 = 0;
        sub.assert_true(wing::advance_crlf(valid_crlf, c1, 13), "CRLF advanced");
        sub.assert_eq(c1, 15, "Cursor advanced by 2");

        let valid_lf = "header: value\nnext";
        var c2: i64 = 0;
        sub.assert_true(wing::advance_crlf(valid_lf, c2, 13), "LF advanced");
        sub.assert_eq(c2, 14, "Cursor advanced by 1");

        let invalid_end = "header: valuenext";
        var c3: i64 = 0;
        sub.assert_false(wing::advance_crlf(invalid_end, c3, 13), "Non-CRLF/LF rejected");
        sub.assert_eq(c3, 13, "Cursor stops at line_end");
    };
}

fn test_httparse_regression_and_obs_fold(t: lit::T&) {
    t.run("httparse PR #223 / Issue #222: Whitespace-Only Line Hard Syntax Error") { sub =>
        var map = wing::HeaderMap { .. };
        // A line containing only spaces between valid headers MUST NOT silently truncate headers!
        let raw = "Host: example.com\r\n   \r\nX-Secret: leak\r\n\r\n";
        let err = wing::parse_headers(raw, map);
        sub.assert_eq(err, wing::HeaderParseError.WhitespaceOnlyLine, "Whitespace-only line produces hard syntax error");
        sub.assert_false(map.valid, "Map marked invalid on whitespace-only line");
    };

    t.run("obs-fold Request Smuggling Defense") { sub =>
        var map = wing::HeaderMap { .. };
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

fn test_chromium_net_parity(t: lit::T&) {
    t.run("Chromium raw_headers_ \\0\\0 Format") { sub =>
        var map = wing::HeaderMap { .. };
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
        var cached = wing::HeaderMap { .. };
        wing::append_header(cached, "ETag", "\"etag-123\"");
        wing::append_header(cached, "Cache-Control", "max-age=3600");
        wing::append_header(cached, "Set-Cookie", "session=original; Secure");
        wing::append_header(cached, "Strict-Transport-Security", "max-age=31536000");

        var resp_304 = wing::HeaderMap { .. };
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
        var src = wing::HeaderMap { .. };
        wing::append_header(src, "Content-Type", "text/html");
        wing::append_header(src, "Set-Cookie", "user=alice");
        wing::append_header(src, "WWW-Authenticate", "Basic realm=\"admin\"");
        wing::append_header(src, "Connection", "keep-alive");

        var dst = wing::HeaderMap { .. };
        wing::persist_headers(src, dst, wing::PERSIST_SANS_COOKIES | wing::PERSIST_SANS_CHALLENGES | wing::PERSIST_SANS_NON_CACHEABLE);

        sub.assert_true(wing::has_header(dst, "Content-Type"), "Content-Type persisted");
        sub.assert_false(wing::has_header(dst, "Set-Cookie"), "Set-Cookie stripped");
        sub.assert_false(wing::has_header(dst, "WWW-Authenticate"), "WWW-Authenticate stripped");
        sub.assert_false(wing::has_header(dst, "Connection"), "Connection stripped");
    };
}

// ---- consolidated suite entry point ---------------------------------------

// --- Component: http1_chunked ---
// Verification suite for RFC 9112 Section 7 (Chunked Transfer Coding & Trailers)
// 1. One-Shot Chunked Decoding with Trailer Extraction
// 2. RFC 9112 Smuggling & Desynchronization Defenses (Bare LF, Bounds, Disallowed Trailers)
// 3. Incremental Chunked Stream Decoder (Fragmented & Torture Stream Feeding)
// 4. HttpServer Ingress with Chunked Framing & Smuggling Guards (TE/CL Conflict)
// 5. Server Chunked Response Serialization & Symmetrical Response Wire Parser

// ----------------------------------------------------------------------------
// 1. One-Shot Chunked Decoding with Trailer Extraction
// ----------------------------------------------------------------------------
fn test_oneshot_chunked_trailers(t: lit::T&) {
    t.run("Single and multi-chunk decoding with byte count accuracy") { sub =>
        let raw = "4\r\nWiki\r\n6\r\n pedia\r\n0\r\n\r\n";
        var out_body:     u8[>..]                = [];
        var out_trailers: wing::HeaderItem[..16] = [];

        let err, consumed = wing::decode_chunked_body_with_trailers(raw, out_body, out_trailers);
        sub.assert_eq(err, wing::ChunkedDecodeError.None, "Decoded successfully");
        sub.assert_bytes_eq(out_body[..], "Wiki pedia", "Body reassembled");
        sub.assert_eq(consumed, raw.len, "All raw bytes consumed");
        sub.assert_eq(out_trailers.len, 0, "No trailers in simple message");
    };

    t.run("Chunk extension ignored and parsed cleanly") { sub =>
        let raw = "5;ext_name=ext_value;flag\r\nHello\r\n0;last=1\r\n\r\n";
        var out_body:     u8[>..]                = [];
        var out_trailers: wing::HeaderItem[..16] = [];

        let err, consumed = wing::decode_chunked_body_with_trailers(raw, out_body, out_trailers);
        sub.assert_eq(err, wing::ChunkedDecodeError.None, "Decoded successfully with extensions");
        sub.assert_bytes_eq(out_body[..], "Hello", "Body matches");
        sub.assert_eq(consumed, raw.len, "Exact length consumed");
    };

    t.run("Extraction of multiple custom trailers") { sub =>
        let raw = "5\r\nHello\r\n0\r\nExpires: Wed, 21 Oct 2026 07:28:00 GMT\r\nX-Checksum: sha256-abc123xyz\r\nX-Timing: dur=15.4\r\n\r\n";
        var out_body:     u8[>..]                = [];
        var out_trailers: wing::HeaderItem[..16] = [];

        let err, consumed = wing::decode_chunked_body_with_trailers(raw, out_body, out_trailers);
        sub.assert_eq(err, wing::ChunkedDecodeError.None, "Decoded cleanly with trailers");
        sub.assert_bytes_eq(out_body[..], "Hello", "Payload correct");
        sub.assert_eq(consumed, raw.len, "Consumed exact stream length");
        sub.assert_eq(out_trailers.len, 3, "3 trailers extracted");

        var req = wing::new_request("POST", "/data");
        req.trailers = copy(out_trailers);
        sub.assert_true(wing::has_trailer(req, "x-checksum"), "Has x-checksum");
        sub.assert_bytes_eq(wing::trailer(req, "x-checksum"), "sha256-abc123xyz", "Trailer x-checksum value");
        sub.assert_bytes_eq(wing::trailer(req, "expires"), "Wed, 21 Oct 2026 07:28:00 GMT", "Trailer expires value");
        sub.assert_bytes_eq(wing::trailer(req, "x-timing"), "dur=15.4", "Trailer x-timing value");
        sub.assert_bytes_eq(wing::trailer(req, "missing"), "", "Empty string for missing trailer");
    };

    t.run("Pipelined keep-alive requests separation") { sub =>
        let raw = "4\r\nBody\r\n0\r\n\r\nGET /next HTTP/1.1\r\nHost: example.com\r\n\r\n";
        var out_body:     u8[>..]                = [];
        var out_trailers: wing::HeaderItem[..16] = [];

        let err, consumed = wing::decode_chunked_body_with_trailers(raw, out_body, out_trailers);
        sub.assert_eq(err, wing::ChunkedDecodeError.None, "Decoded chunked segment");
        sub.assert_bytes_eq(out_body[..], "Body", "Payload extracted");
        sub.assert_eq(consumed, 14, "Exact 14 bytes consumed for chunked stream");
        sub.assert_bytes_eq(raw[consumed..(consumed + 18)], "GET /next HTTP/1.1", "Remaining stream untouched");
    };
}

// ----------------------------------------------------------------------------
// 2. RFC 9112 Smuggling & Desynchronization Defenses
// ----------------------------------------------------------------------------
fn test_chunked_smuggling_defenses(t: lit::T&) {
    t.run("Bare LF in chunk size rejection (CVE-2025-22871)") { sub =>
        var out_body:     u8[>..]                = [];
        var out_trailers: wing::HeaderItem[..16] = [];

        let raw = "4\nWiki\r\n0\r\n\r\n";
        let err, _ = wing::decode_chunked_body_with_trailers(raw, out_body, out_trailers);
        sub.assert_eq(err, wing::ChunkedDecodeError.BareLfInChunkSize, "Bare LF in chunk size rejected");
    };

    t.run("Bare LF in chunk data terminator rejection") { sub =>
        var out_body:     u8[>..]                = [];
        var out_trailers: wing::HeaderItem[..16] = [];

        let raw = "4\r\nWiki\n0\r\n\r\n";
        let err, _ = wing::decode_chunked_body_with_trailers(raw, out_body, out_trailers);
        sub.assert_eq(err, wing::ChunkedDecodeError.BareLfInChunkData, "Bare LF after chunk data rejected");
    };

    t.run("Bare LF in chunk data terminator at exact buffer end") { sub =>
        var out_body:     u8[>..]                = [];
        var out_trailers: wing::HeaderItem[..16] = [];

        let raw = "4\r\nWiki\n";
        let err, _ = wing::decode_chunked_body_with_trailers(raw, out_body, out_trailers);
        sub.assert_eq(err, wing::ChunkedDecodeError.BareLfInChunkData, "Bare LF at buffer boundary rejected");
    };

    t.run("Bare LF in trailer line rejection") { sub =>
        var out_body:     u8[>..]                = [];
        var out_trailers: wing::HeaderItem[..16] = [];

        let raw = "4\r\nWiki\r\n0\r\nX-Check: val\n\r\n";
        let err, _ = wing::decode_chunked_body_with_trailers(raw, out_body, out_trailers);
        sub.assert_eq(err, wing::ChunkedDecodeError.BareLfInTrailer, "Bare LF in trailer header rejected");
    };

    t.run("Bare LF terminating trailer section rejection") { sub =>
        var out_body:     u8[>..]                = [];
        var out_trailers: wing::HeaderItem[..16] = [];

        let raw = "0\r\n\n";
        let err, _ = wing::decode_chunked_body_with_trailers(raw, out_body, out_trailers);
        sub.assert_eq(err, wing::ChunkedDecodeError.BareLfInTrailer, "Bare LF ending trailers rejected");
    };

    t.run("RFC 9110 Section 6.5.1: Full Forbidden Trailer Fields Enforcement") { sub =>
        var out_body:     u8[>..]                = [];
        var out_trailers: wing::HeaderItem[..16] = [];

        let disallowed_cases: const u8[:][20] = [
            "Transfer-Encoding: chunked",
            "Content-Length: 42",
            "Trailer: X-Foo",
            "Host: evil.com",
            "Authorization: Bearer secret",
            "Proxy-Authorization: Basic abc",
            "Set-Cookie: session=hijack",
            "Cookie: secret=leak",
            "Content-Range: bytes 0-10/100",
            "Content-Type: text/plain",
            "Content-Encoding: gzip",
            "Connection: close",
            "Keep-Alive: timeout=5",
            "Upgrade: websocket",
            "Proxy-Connection: keep-alive",
            "TE: trailers",
            "If-Match: \"xyz\"",
            "If-None-Match: \"xyz\"",
            "If-Modified-Since: Wed, 21 Oct 2026 07:28:00 GMT",
            "Range: bytes=0-10",
        ];

        for dc in disallowed_cases {
            var raw: u8[..256] = "0\r\n";
            raw.append(dc);
            raw.append("\r\n\r\n");
            out_body.clear();
            out_trailers.clear();
            let err, _ = wing::decode_chunked_body_with_trailers(raw[..], out_body, out_trailers);
            sub.assert_eq(err, wing::ChunkedDecodeError.DisallowedTrailer, "Disallowed header in trailer rejected");
        }

        // Direct is_disallowed_trailer_field verification including pseudo-headers and whitespace
        sub.assert_true(wing::is_disallowed_trailer_field("connection"), "connection is forbidden");
        sub.assert_true(wing::is_disallowed_trailer_field("Connection"), "Connection (cased) is forbidden");
        sub.assert_true(wing::is_disallowed_trailer_field("  connection  "), "whitespace padded connection is forbidden");
        sub.assert_true(wing::is_disallowed_trailer_field("keep-alive"), "keep-alive is forbidden");
        sub.assert_true(wing::is_disallowed_trailer_field("upgrade"), "upgrade is forbidden");
        sub.assert_true(wing::is_disallowed_trailer_field("proxy-connection"), "proxy-connection is forbidden");
        sub.assert_true(wing::is_disallowed_trailer_field("if-match"), "if-match is forbidden");
        sub.assert_true(wing::is_disallowed_trailer_field("if-none-match"), "if-none-match is forbidden");
        sub.assert_true(wing::is_disallowed_trailer_field("if-modified-since"), "if-modified-since is forbidden");
        sub.assert_true(wing::is_disallowed_trailer_field("if-unmodified-since"), "if-unmodified-since is forbidden");
        sub.assert_true(wing::is_disallowed_trailer_field("if-range"), "if-range is forbidden");
        sub.assert_true(wing::is_disallowed_trailer_field("range"), "range is forbidden");
        sub.assert_true(wing::is_disallowed_trailer_field(":method"), "pseudo-header :method is forbidden");
        sub.assert_true(wing::is_disallowed_trailer_field(":path"), "pseudo-header :path is forbidden");
        sub.assert_true(wing::is_disallowed_trailer_field(":status"), "pseudo-header :status is forbidden");
        sub.assert_true(wing::is_disallowed_trailer_field(":authority"), "pseudo-header :authority is forbidden");

        // Allowed custom trailers
        sub.assert_false(wing::is_disallowed_trailer_field("x-checksum"), "x-checksum is allowed");
        sub.assert_false(wing::is_disallowed_trailer_field("expires"), "expires is allowed");
    };

    t.run("RFC 9112 Section 7.1.2: Chunked FSM trailer syntax & colon enforcement") { sub =>
        // Missing colon in trailer line MUST be rejected by FSM
        var dec1 = internal::new_chunk_fsm_decoder();
        let st1, _, _ = internal::chunk_fsm_feed(dec1, "0\r\nTrailerWithoutColon\r\n\r\n");
        sub.assert_eq(st1, internal::ChunkFsmStatus.Error, "Trailer line without colon must return Error");

        // Whitespace before colon in trailer line MUST be rejected (RFC 9112 §5.1 / CVE-2019-16276)
        var dec2 = internal::new_chunk_fsm_decoder();
        let st2, _, _ = internal::chunk_fsm_feed(dec2, "0\r\nX-Trailer : val\r\n\r\n");
        sub.assert_eq(st2, internal::ChunkFsmStatus.Error, "Whitespace before colon in trailer must return Error");
    };

    t.run("Trailer flood protection (> 16 fields or > 4096 bytes)") { sub =>
        var out_body:     u8[>..]                = [];
        var out_trailers: wing::HeaderItem[..16] = [];

        // 17 trailer headers
        var flood: u8[..2048] = "0\r\n";
        for i in 17 {
            flood.append("X-Field-");
            format(flood, i as i64);
            flood.append(": val\r\n");
        }
        flood.append("\r\n");

        let err_flood, _ = wing::decode_chunked_body_with_trailers(flood[..], out_body, out_trailers);
        sub.assert_eq(err_flood, wing::ChunkedDecodeError.DisallowedTrailer, "17 trailers rejected (exceeds cap of 16)");

        // Massive trailer line > 4096 bytes
        var huge: u8[>..] = [];
        huge.append("0\r\nX-Big: ");
        for i in 4096 {
            huge.push('A');
        }
        huge.append("\r\n\r\n");
        let err_huge, _ = wing::decode_chunked_body_with_trailers(huge[..], out_body, out_trailers);
        sub.assert_eq(err_huge, wing::ChunkedDecodeError.DisallowedTrailer, "Trailer > 4096 bytes rejected");
    };

    t.run("RFC 9112 Section 7.1: Chunk size 64-bit integer overflow rejection") { sub =>
        var out_body:     u8[>..]                = [];
        var out_trailers: wing::HeaderItem[..16] = [];

        // 1. 0xffffffffffffffff (16 hex digits: 2^64 - 1, signed overflow)
        let raw_max = "FFFFFFFFFFFFFFFF\r\nWiki\r\n0\r\n\r\n";
        let err_max, _ = wing::decode_chunked_body_with_trailers(raw_max, out_body, out_trailers);
        sub.assert_eq(err_max, wing::ChunkedDecodeError.ChunkSizeOverflow, "0xffffffffffffffff rejected as ChunkSizeOverflow");

        // 2. 0x10000000000000000 (17 hex digits: 2^64 overflow)
        let raw_17 = "10000000000000000\r\nWiki\r\n0\r\n\r\n";
        let err_17, _ = wing::decode_chunked_body_with_trailers(raw_17, out_body, out_trailers);
        sub.assert_eq(err_17, wing::ChunkedDecodeError.ChunkSizeOverflow, "0x10000000000000000 rejected as ChunkSizeOverflow");

        // 3. 7fffffffffffffff + 1 = 8000000000000000 (16 hex digits: signed i64 overflow)
        let raw_signed = "8000000000000000\r\nWiki\r\n0\r\n\r\n";
        let err_signed, _ = wing::decode_chunked_body_with_trailers(raw_signed, out_body, out_trailers);
        sub.assert_eq(err_signed, wing::ChunkedDecodeError.ChunkSizeOverflow, "7fffffffffffffff + 1 rejected as ChunkSizeOverflow");

        // Direct parse_chunk_size_hex unit tests
        var sz: u64 = 0;
        let err_p1 = wing::parse_chunk_size_hex("FFFFFFFFFFFFFFFF", sz);
        sub.assert_eq(err_p1, wing::ChunkedDecodeError.ChunkSizeOverflow, "parse_chunk_size_hex overflows on FFFFFFFFFFFFFFFF");

        let err_p2 = wing::parse_chunk_size_hex("10000000000000000", sz);
        sub.assert_eq(err_p2, wing::ChunkedDecodeError.ChunkSizeOverflow, "parse_chunk_size_hex overflows on 17 hex digits");

        let err_p3 = wing::parse_chunk_size_hex("8000000000000000", sz);
        sub.assert_eq(err_p3, wing::ChunkedDecodeError.ChunkSizeOverflow, "parse_chunk_size_hex overflows on 8000000000000000");
    };

    t.run("RFC 9112 Section 7.1: Leading zeros in chunk size accepted") { sub =>
        var out_body:     u8[>..]                = [];
        var out_trailers: wing::HeaderItem[..16] = [];

        // Chunk size with leading zeros > 16 characters total, but small value
        let raw_zeros = "00000000000000000004\r\nWiki\r\n00000000000000000000\r\n\r\n";
        let err_zeros, consumed = wing::decode_chunked_body_with_trailers(raw_zeros, out_body, out_trailers);
        sub.assert_eq(err_zeros, wing::ChunkedDecodeError.None, "Leading zeros in chunk size decoded successfully");
        sub.assert_bytes_eq(out_body[..], "Wiki", "Payload reassembled correctly with leading zeros");
        sub.assert_eq(consumed, raw_zeros.len, "All raw bytes consumed");

        var sz: u64 = 0;
        let err_p = wing::parse_chunk_size_hex("00000000000000000005", sz);
        sub.assert_eq(err_p, wing::ChunkedDecodeError.None, "parse_chunk_size_hex accepts leading zeros");
        sub.assert_eq(sz, 5, "Size parsed as 5");

        let err_p0 = wing::parse_chunk_size_hex("00000000000000000000", sz);
        sub.assert_eq(err_p0, wing::ChunkedDecodeError.None, "parse_chunk_size_hex accepts leading zeros for zero");
        sub.assert_eq(sz, 0, "Size parsed as 0");
    };

    t.run("RFC 9112 Section 7.1.1: Chunked FSM rejects trailing whitespace without extension") { sub =>
        var dec = internal::new_chunk_fsm_decoder();
        // Space between chunk-size and CRLF without ';'
        let st_sp, _, _ = internal::chunk_fsm_feed(dec, "5 \r\nhello\r\n0\r\n\r\n");
        sub.assert_eq(st_sp, internal::ChunkFsmStatus.Error, "Trailing space after chunk-size without extension rejected");

        var dec_tab = internal::new_chunk_fsm_decoder();
        // Tab between chunk-size and CRLF without ';'
        let st_tab, _, _ = internal::chunk_fsm_feed(dec_tab, "5\t\r\nhello\r\n0\r\n\r\n");
        sub.assert_eq(st_tab, internal::ChunkFsmStatus.Error, "Trailing tab after chunk-size without extension rejected");

        // Valid extension with leading space (BWS preceding ';') must still succeed
        var dec_ok = internal::new_chunk_fsm_decoder();
        let st_ok, _, slice = internal::chunk_fsm_feed(dec_ok, "5 ;ext=1\r\nhello\r\n0\r\n\r\n");
        sub.assert_eq(st_ok, internal::ChunkFsmStatus.YieldChunk, "Space before semicolon in valid extension accepted");
        sub.assert_bytes_eq(slice, "hello", "Payload correctly yielded");
    };

    t.run("RFC 9112 Section 7.1.1: Chunked FSM rejects unseparated tokens and post-quote tokens in extensions") { sub =>
        var dec1 = internal::new_chunk_fsm_decoder();
        let st1, _, _ = internal::chunk_fsm_feed(dec1, "5;ext=val1 val2\r\nhello\r\n0\r\n\r\n");
        sub.assert_eq(st1, internal::ChunkFsmStatus.Error, "Unseparated tokens after value must return Error");

        var dec2 = internal::new_chunk_fsm_decoder();
        let st2, _, _ = internal::chunk_fsm_feed(dec2, "5;ext=\"quoted\"junk\r\nhello\r\n0\r\n\r\n");
        sub.assert_eq(st2, internal::ChunkFsmStatus.Error, "Trailing junk after closing quote must return Error");
    };
}

// ----------------------------------------------------------------------------
// 3. Incremental Chunked Stream Decoder (Fragmented & Torture Stream Feeding)
// ----------------------------------------------------------------------------
fn test_incremental_chunked_stream_decoder(t: lit::T&) {
    t.run("Torture 1-byte incremental feeding") { sub =>
        let wire = "5\r\nHello\r\n6\r\n World\r\n0\r\nX-Checksum: c89a\r\n\r\n";
        var dec = wing::ChunkedStreamDecoder { .. };
        var stream_out: u8[>..] = [];

        for i in wire.len {
            let one_byte = wire[i..(i + 1)];
            let ok_step, consumed = wing::feed_chunked_stream(dec, one_byte, stream_out);
            sub.assert_true(ok_step, "Step ok");
            sub.assert_eq(consumed, 1, "Consumed 1 byte");
        }

        sub.assert_true(wing::is_complete(dec), "Decoder reached Complete state");
        sub.assert_false(wing::has_error(dec), "No error in decoder");
        sub.assert_bytes_eq(stream_out[..], "Hello World", "Reassembled stream payload");
        sub.assert_eq(dec.trailers.len, 1, "1 trailer extracted");
        sub.assert_bytes_eq(dec.trailers[0].name[..], "X-Checksum", "Trailer name");
        sub.assert_bytes_eq(dec.trailers[0].value[..], "c89a", "Trailer value");
    };

    t.run("Arbitrary 7-byte chunk slice feeding") { sub =>
        let wire = "A\r\n0123456789\r\n5\r\nABCDE\r\n0\r\n\r\n";
        var dec = wing::ChunkedStreamDecoder { .. };
        var stream_out: u8[>..] = [];

        var offset: i64 = 0;
        while offset < wire.len {
            let slice_end = if offset + 7 < wire.len { offset + 7 } else { wire.len };
            let chunk_slice = wire[offset..slice_end];
            let ok_step, consumed = wing::feed_chunked_stream(dec, chunk_slice, stream_out);
            sub.assert_true(ok_step, "Feeding slice succeeded");
            sub.assert_eq(consumed, chunk_slice.len, "Full slice consumed");
            offset = slice_end;
        }

        sub.assert_true(wing::is_complete(dec), "Decoding completed");
        sub.assert_bytes_eq(stream_out[..], "0123456789ABCDE", "Accurate multi-chunk assembly");
    };

    t.run("Incremental decoder stops on bare LF error") { sub =>
        let wire = "4\nWiki\r\n0\r\n\r\n";
        var dec = wing::ChunkedStreamDecoder { .. };
        var stream_out: u8[>..] = [];

        let ok, consumed = wing::feed_chunked_stream(dec, wire, stream_out);
        sub.assert_false(ok, "Decoder detected error");
        sub.assert_true(wing::has_error(dec), "Has error state");
        sub.assert_eq(dec.error_code, wing::ChunkedDecodeError.BareLfInChunkSize, "Bare LF caught incrementally");
    };
}

// ----------------------------------------------------------------------------
// 4. HttpServer Ingress with Chunked Framing & Smuggling Guards
// ----------------------------------------------------------------------------
fn test_httpserver_chunked_ingress(t: lit::T&) {
    t.run("HttpServer handles incoming chunked POST with trailers") { sub =>
        var server = wing::new_http_server("127.0.0.1", 8080);
        wing::add_post_route(server, "/upload/chunked", 101);

        let wire_req = "POST /upload/chunked HTTP/1.1\r\nHost: localhost\r\nTransfer-Encoding: chunked\r\nTrailer: X-Audit-Id\r\n\r\n5\r\nchunk\r\n0\r\nX-Audit-Id: audit-9988\r\n\r\n";

        var wire_resp: u8[>..] = [];
        let outcome, ok_handled = wing::handle_connection_wire(server, "127.0.0.1", wire_req, 1000000000, wire_resp);
        sub.assert_true(ok_handled, "Chunked request handled cleanly");
        sub.assert_eq(outcome, wing::PipelineOutcome.Handled, "Pipeline outcome Handled");
        sub.assert_contains(wire_resp[..], "HTTP/1.1 200 OK", "Server returned 200 OK");
    };

    t.run("Smuggling Guard: Dual Transfer-Encoding AND Content-Length rejected") { sub =>
        var server = wing::new_http_server("127.0.0.1", 8080);
        wing::add_post_route(server, "/api", 102);

        // Smuggling vector: both TE and CL specified
        let smuggled_req = "POST /api HTTP/1.1\r\nHost: localhost\r\nTransfer-Encoding: chunked\r\nContent-Length: 5\r\n\r\n5\r\nhello\r\n0\r\n\r\n";

        var wire_resp: u8[>..] = [];
        let outcome, ok_handled = wing::handle_connection_wire(server, "127.0.0.1", smuggled_req, 1000000000, wire_resp);
        sub.assert_false(ok_handled, "Dual TE+CL rejected by server");
        sub.assert_contains(wire_resp[..], "HTTP/1.1 400 Bad Request", "400 Bad Request returned");
    };

    t.run("Smuggling Guard: Conflicting duplicate Content-Length rejected") { sub =>
        var req = wing::new_request("POST", "/data");
        let wire = "POST /data HTTP/1.1\r\nHost: localhost\r\nContent-Length: 10\r\nContent-Length: 20\r\n\r\n0123456789";
        let ok, _ = wing::parse_http1_wire_request(wire, req);
        sub.assert_false(ok, "Conflicting Content-Length rejected");
    };

    t.run("Smuggling Guard: Invalid Transfer-Encoding coding rejected") { sub =>
        var req = wing::new_request("POST", "/data");
        // Unknown transfer coding "compress" as final encoding without chunked
        let wire = "POST /data HTTP/1.1\r\nHost: localhost\r\nTransfer-Encoding: compress\r\n\r\n";
        let ok, _ = wing::parse_http1_wire_request(wire, req);
        sub.assert_false(ok, "Non-chunked transfer encoding rejected");
    };

    t.run("Smuggling Guard: RFC 9112 Section 6.1 Unrecognized transfer coding rejected") { sub =>
        var req1 = wing::new_request("POST", "/data");
        // Unknown transfer coding preceding chunked
        let wire1 = "POST /data HTTP/1.1\r\nHost: localhost\r\nTransfer-Encoding: bogus, chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n";
        let ok1, _ = wing::parse_http1_wire_request(wire1, req1);
        sub.assert_false(ok1, "Transfer-Encoding with unrecognized coding 'bogus' must be rejected");

        // Chunked not final: chunked followed by identity or gzip
        var req2 = wing::new_request("POST", "/data");
        let wire2 = "POST /data HTTP/1.1\r\nHost: localhost\r\nTransfer-Encoding: chunked, identity\r\n\r\n";
        let ok2, _ = wing::parse_http1_wire_request(wire2, req2);
        sub.assert_false(ok2, "Transfer-Encoding: chunked, identity must be rejected");

        var req3 = wing::new_request("POST", "/data");
        let wire3 = "POST /data HTTP/1.1\r\nHost: localhost\r\nTransfer-Encoding: chunked, gzip\r\n\r\n";
        let ok3, _ = wing::parse_http1_wire_request(wire3, req3);
        sub.assert_false(ok3, "Transfer-Encoding: chunked, gzip must be rejected");
    };
}

// ----------------------------------------------------------------------------
// 5. Server Chunked Response Serialization & Symmetrical Response Wire Parser
// ----------------------------------------------------------------------------
fn test_chunked_response_and_wire_parser(t: lit::T&) {
    t.run("Server response serialization automatically chunks when trailers present") { sub =>
        var res = wing::Response { .. };
        res.status_code = 200;
        res.body.append("Streaming payload message");
        wing::add_trailer(res, "X-Checksum", "sha256-res-hash");
        wing::add_trailer(res, "X-Duration", "12ms");

        var wire_out: u8[>..] = [];
        wing::serialize_http1_response(res, "goose-wing/1.0", wire_out);

        sub.assert_contains(wire_out[..], "HTTP/1.1 200 OK\r\n", "Status line");
        sub.assert_contains(wire_out[..], "Transfer-Encoding: chunked\r\n", "Transfer-Encoding: chunked present");
        sub.assert_contains(wire_out[..], "Trailer: X-Checksum, X-Duration\r\n", "Trailer advertisement present");
        sub.assert_contains(wire_out[..], "X-Checksum: sha256-res-hash\r\n", "Trailer emitted in trailer section");
        sub.assert_contains(wire_out[..], "X-Duration: 12ms\r\n", "Second trailer emitted");

        // Parse serialized response with symmetrical parse_http1_wire_response
        var parsed_res = wing::Response { .. };
        let ok_parse, consumed = wing::parse_http1_wire_response(wire_out[..], parsed_res);
        sub.assert_true(ok_parse, "Wire response parsed cleanly");
        sub.assert_eq(consumed, wire_out.len, "Entire wire stream consumed");
        sub.assert_eq(parsed_res.status_code, 200, "Status is 200");
        sub.assert_bytes_eq(parsed_res.body[..], "Streaming payload message", "Decoded response body");
        sub.assert_true(wing::has_trailer(parsed_res, "x-checksum"), "Has x-checksum trailer");
        sub.assert_bytes_eq(wing::trailer(parsed_res, "x-checksum"), "sha256-res-hash", "Trailer matches");
        sub.assert_bytes_eq(wing::trailer(parsed_res, "x-duration"), "12ms", "Second trailer matches");
    };

    t.run("Fixed-size chunk serialization with encode_chunked_payload") { sub =>
        var body_data: u8[..64]               = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
        var trs:       wing::HeaderItem[..16] = [];
        var item = wing::HeaderItem { .. };
        item.name.append("X-Complete");
        item.value.append("true");
        trs.push(item);

        var encoded_wire: u8[>..] = [];
        wing::encode_chunked_payload(body_data[..], trs, 10, encoded_wire);

        var parsed_body: u8[>..]                = [];
        var parsed_trs:  wing::HeaderItem[..16] = [];
        let err, consumed = wing::decode_chunked_body_with_trailers(encoded_wire[..], parsed_body, parsed_trs);
        sub.assert_eq(err, wing::ChunkedDecodeError.None, "Decoded segmented chunks");
        sub.assert_eq(consumed, encoded_wire.len, "Exact bytes consumed");
        sub.assert_bytes_eq(parsed_body[..], "ABCDEFGHIJKLMNOPQRSTUVWXYZ", "Payload fully reconstructed");
        sub.assert_eq(parsed_trs.len, 1, "1 trailer reconstructed");
        sub.assert_bytes_eq(parsed_trs[0].name[..], "X-Complete", "Trailer name correct");
        sub.assert_bytes_eq(parsed_trs[0].value[..], "true", "Trailer value correct");
    };

    t.run("RFC 9112 Section 6.1: Response wire parser strips Content-Length when chunked present") { sub =>
        let wire_dual = "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nContent-Length: 42\r\n\r\n5\r\nhello\r\n0\r\n\r\n";
        var res = wing::Response { .. };
        let ok_parse, consumed = wing::parse_http1_wire_response(wire_dual, res);
        sub.assert_true(ok_parse, "Dual TE+CL in response parsed cleanly (TE overrides CL)");
        sub.assert_bytes_eq(res.body[..], "hello", "Body decoded from chunked");
        sub.assert_false(wing::has_header(res, "content-length"), "Content-Length header MUST be stripped per RFC 9112 Section 6.1");
    };
}

// ----------------------------------------------------------------------------
// Suite Runner
// ----------------------------------------------------------------------------

// --- Component: http_request_smuggling ---
// Tests for request smuggling defenses and chunked transfer decoding (RFC 9112).

fn test_te_cl_request_smuggling_defense(t: lit::T&) {
    t.run("SMUGGLE-01: Conflicting Transfer-Encoding and Content-Length (TE.CL / CL.TE) Rejection") { sub =>
        // TE then CL
        var map1 = wing::HeaderMap { .. };
        let raw_te_cl = "Transfer-Encoding: chunked\r\nContent-Length: 42\r\n\r\n";
        let err1 = wing::parse_headers(raw_te_cl, map1);
        sub.assert_eq(err1, wing::HeaderParseError.InvalidContentLength, "TE followed by CL must fail with InvalidContentLength per RFC 9112 Section 6.3");
        sub.assert_false(map1.valid, "Map must be marked invalid on TE/CL conflict");

        // CL then TE
        var map2 = wing::HeaderMap { .. };
        let raw_cl_te = "Content-Length: 42\r\nTransfer-Encoding: chunked\r\n\r\n";
        let err2 = wing::parse_headers(raw_cl_te, map2);
        sub.assert_eq(err2, wing::HeaderParseError.InvalidContentLength, "CL followed by TE must fail with InvalidContentLength per RFC 9112 Section 6.3");
        sub.assert_false(map2.valid, "Map must be marked invalid on CL/TE conflict");
    };

    t.run("SMUGGLE-02: Duplicate Differing Content-Length Rejection (CL.CL)") { sub =>
        var map = wing::HeaderMap { .. };
        let raw_diff_cl = "Content-Length: 10\r\nContent-Length: 20\r\n\r\n";
        let err = wing::parse_headers(raw_diff_cl, map);
        sub.assert_eq(err, wing::HeaderParseError.InvalidContentLength, "Duplicate differing Content-Length must be rejected");
        sub.assert_false(map.valid, "Map must be marked invalid on duplicate differing Content-Length");
    };

    t.run("SMUGGLE-03: Negative Content-Length Rejection") { sub =>
        var map = wing::HeaderMap { .. };
        let raw_neg = "Content-Length: -5\r\n\r\n";
        let err = wing::parse_headers(raw_neg, map);
        sub.assert_eq(err, wing::HeaderParseError.InvalidContentLength, "Negative Content-Length must be rejected");
        sub.assert_false(map.valid, "Map must be marked invalid on negative Content-Length");
    };

    t.run("SMUGGLE-04: Non-Digit Characters in Content-Length Rejection") { sub =>
        // Suffix alphanumeric
        var map1 = wing::HeaderMap { .. };
        let raw_alpha = "Content-Length: 12abc\r\n\r\n";
        let err1 = wing::parse_headers(raw_alpha, map1);
        sub.assert_eq(err1, wing::HeaderParseError.InvalidContentLength, "Alpha characters in Content-Length must be rejected");

        // Explicit positive sign '+'
        var map2 = wing::HeaderMap { .. };
        let raw_plus = "Content-Length: +10\r\n\r\n";
        let err2 = wing::parse_headers(raw_plus, map2);
        sub.assert_eq(err2, wing::HeaderParseError.InvalidContentLength, "Plus sign in Content-Length must be rejected");

        // Decimal dot
        var map3 = wing::HeaderMap { .. };
        let raw_dot = "Content-Length: 10.5\r\n\r\n";
        let err3 = wing::parse_headers(raw_dot, map3);
        sub.assert_eq(err3, wing::HeaderParseError.InvalidContentLength, "Decimal dot in Content-Length must be rejected");

        // Empty value
        var map4 = wing::HeaderMap { .. };
        let raw_empty = "Content-Length:\r\n\r\n";
        let err4 = wing::parse_headers(raw_empty, map4);
        sub.assert_eq(err4, wing::HeaderParseError.InvalidContentLength, "Empty Content-Length must be rejected");
    };

    t.run("SMUGGLE-05: Content-Length 64-bit Overflow Rejection") { sub =>
        var map = wing::HeaderMap { .. };
        // 30-digit integer overflow
        let raw_ovf = "Content-Length: 999999999999999999999999999999\r\n\r\n";
        let err = wing::parse_headers(raw_ovf, map);
        sub.assert_eq(err, wing::HeaderParseError.InvalidContentLength, "Overflowing Content-Length must be rejected");
        sub.assert_false(map.valid, "Map must be marked invalid on overflowing Content-Length");
    };

    t.run("SMUGGLE-06: Comma-Separated Differing Content-Length Rejection") { sub =>
        var map = wing::HeaderMap { .. };
        let raw_comma = "Content-Length: 15, 30\r\n\r\n";
        let err = wing::parse_headers(raw_comma, map);
        sub.assert_eq(err, wing::HeaderParseError.InvalidContentLength, "Differing comma-separated Content-Length must be rejected");
    };

    t.run("SMUGGLE-07: Duplicate Transfer-Encoding Headers Rejection") { sub =>
        var map = wing::HeaderMap { .. };
        let raw_dup_te = "Transfer-Encoding: chunked\r\nTransfer-Encoding: gzip\r\n\r\n";
        let err = wing::parse_headers(raw_dup_te, map);
        sub.assert_eq(err, wing::HeaderParseError.InvalidContentLength, "Duplicate Transfer-Encoding headers must be rejected");
    };

    t.run("SMUGGLE-08: Valid Content-Length Acceptance & Identical Duplicate Folding") { sub =>
        // Valid Content-Length: 0
        var map1 = wing::HeaderMap { .. };
        let raw_zero = "Content-Length: 0\r\n\r\n";
        let err1 = wing::parse_headers(raw_zero, map1);
        sub.assert_eq(err1, wing::HeaderParseError.None, "Content-Length: 0 is valid");
        sub.assert_true(map1.valid, "Map must be valid");

        // Valid Content-Length: 1024
        var map2 = wing::HeaderMap { .. };
        let raw_valid = "Content-Length: 1024\r\n\r\n";
        let err2 = wing::parse_headers(raw_valid, map2);
        sub.assert_eq(err2, wing::HeaderParseError.None, "Content-Length: 1024 is valid");
        sub.assert_bytes_eq(wing::get_header(map2, "content-length"), "1024", "Header retrieved correctly");

        // Duplicate IDENTICAL Content-Length per RFC 9112 Section 6.3
        var map3 = wing::HeaderMap { .. };
        let raw_dup_same = "Content-Length: 42\r\nContent-Length: 42\r\n\r\n";
        let err3 = wing::parse_headers(raw_dup_same, map3);
        sub.assert_eq(err3, wing::HeaderParseError.None, "Duplicate identical Content-Length must be accepted per RFC 9112 Section 6.3");
        sub.assert_bytes_eq(wing::get_header(map3, "content-length"), "42", "Single unified value retrieved");
    };

    t.run("SMUGGLE-09: obs-fold on Content-Length Rejection") { sub =>
        var map = wing::HeaderMap { .. };
        // Even in allow_obs_fold=true compatibility mode, obs-fold on Content-Length must be rejected
        let raw_fold_cl = "Content-Length: 10\r\n 20\r\n\r\n";
        let err = wing::parse_headers(raw_fold_cl, map, true);
        sub.assert_eq(err, wing::HeaderParseError.InvalidContentLength, "obs-fold on Content-Length must be rejected");
        sub.assert_false(map.valid, "Map must be invalid");
    };

    t.run("SMUGGLE-10: Space Before Colon in Header Name Rejection ") { sub =>
        var map1 = wing::HeaderMap { .. };
        let raw1 = "Content-Length : 10\r\n\r\n";
        let err1 = wing::parse_headers(raw1, map1);
        sub.assert_eq(err1, wing::HeaderParseError.InvalidHeaderName, "Space before colon in Content-Length must be rejected per RFC 7230 Section 3.2.4");

        var map2 = wing::HeaderMap { .. };
        let raw2 = "Transfer-Encoding : chunked\r\n\r\n";
        let err2 = wing::parse_headers(raw2, map2);
        sub.assert_eq(err2, wing::HeaderParseError.InvalidHeaderName, "Space before colon in Transfer-Encoding must be rejected");

        var map3 = wing::HeaderMap { .. };
        let raw3 = "X-Foo : bar\r\n\r\n";
        let err3 = wing::parse_headers(raw3, map3);
        sub.assert_eq(err3, wing::HeaderParseError.InvalidHeaderName, "Space before colon in general header must be rejected");
    };

    t.run("SMUGGLE-11: Tab Before Colon in Header Name Rejection") { sub =>
        var map = wing::HeaderMap { .. };
        let raw = "Content-Length\t: 10\r\n\r\n";
        let err = wing::parse_headers(raw, map);
        sub.assert_eq(err, wing::HeaderParseError.InvalidHeaderName, "Tab before colon must be rejected as InvalidHeaderName");
    };

    t.run("SMUGGLE-12: CR or CTL Injection in Transfer-Encoding ") { sub =>
        var map1 = wing::HeaderMap { .. };
        let raw1 = "Transfer-Encoding: \rchunked\r\n\r\n";
        let err1 = wing::parse_headers(raw1, map1);
        sub.assert_ne(err1, wing::HeaderParseError.None, "Bare CR in header splits line into invalid header line without colon");
        sub.assert_false(map1.valid, "Map must be invalid on bare CR injection");

        var map2 = wing::HeaderMap { .. };
        let raw2 = "Transfer-Encoding: chunked\x01\r\n\r\n";
        let err2 = wing::parse_headers(raw2, map2);
        sub.assert_eq(err2, wing::HeaderParseError.InvalidHeaderValue, "CTL character in Transfer-Encoding must be rejected");
        sub.assert_false(map2.valid, "Map must be invalid on CTL injection");
    };

    t.run("SMUGGLE-13: Multiple Identical Content-Length Folded ") { sub =>
        var map = wing::HeaderMap { .. };
        let raw = "Content-Length: 128\r\nContent-Length: 128\r\nContent-Length: 128\r\n\r\n";
        let err = wing::parse_headers(raw, map);
        sub.assert_eq(err, wing::HeaderParseError.None, "Triple identical Content-Length must be accepted per RFC 9112 Section 6.3");
        sub.assert_bytes_eq(wing::get_header(map, "content-length"), "128", "Single folded value retrieved");
    };

    t.run("SMUGGLE-14: HTTP/2 Malformed Framing Protection Against Smuggling into HTTP/1 (CVE-2026-78660)") { sub =>
        // Differing comma-separated values
        var map1 = wing::HeaderMap { .. };
        let raw1 = "Content-Length: 10, 20\r\n\r\n";
        let err1 = wing::parse_headers(raw1, map1);
        sub.assert_eq(err1, wing::HeaderParseError.InvalidContentLength, "Differing comma-delimited Content-Length rejected");

        // Duplicate differing values
        var map2 = wing::HeaderMap { .. };
        let raw2 = "Content-Length: 0\r\nContent-Length: 5\r\n\r\n";
        let err2 = wing::parse_headers(raw2, map2);
        sub.assert_eq(err2, wing::HeaderParseError.InvalidContentLength, "Duplicate differing Content-Length rejected");
    };

    t.run("SMUGGLE-15: Content-Length Validation When Transfer-Encoding Present ") { sub =>
        var map1 = wing::HeaderMap { .. };
        let raw1 = "Transfer-Encoding: chunked\r\nContent-Length: invalid_num\r\n\r\n";
        let err1 = wing::parse_headers(raw1, map1);
        sub.assert_eq(err1, wing::HeaderParseError.InvalidContentLength, "TE with invalid CL rejected");

        var map2 = wing::HeaderMap { .. };
        let raw2 = "Transfer-Encoding: chunked\r\nContent-Length: 0\r\n\r\n";
        let err2 = wing::parse_headers(raw2, map2);
        sub.assert_eq(err2, wing::HeaderParseError.InvalidContentLength, "TE with CL:0 rejected");
    };
}

fn test_chunked_encoding_bare_lf_defense(t: lit::T&) {
    t.run("CHUNK-01: Bare LF in Chunk-Size Line Rejection (CVE-2025-22871)") { sub =>
        var out_body: u8[>..] = [];

        // Bare LF after hex chunk size
        let raw1 = "4\nwiki\r\n0\r\n\r\n";
        let err1 = wing::decode_chunked_body(raw1, out_body);
        sub.assert_eq(err1, wing::ChunkedDecodeError.BareLfInChunkSize, "Bare LF in chunk size must be rejected per RFC 9112 Section 7.1");
        sub.assert_eq(out_body.len, 0, "No data decoded on bare LF");

        // Bare LF with multi-digit hex
        let raw2 = "1a\nhello_world_test_data\r\n0\r\n\r\n";
        let err2 = wing::decode_chunked_body(raw2, out_body);
        sub.assert_eq(err2, wing::ChunkedDecodeError.BareLfInChunkSize, "Bare LF in 2-digit hex chunk size must be rejected");

        // Bare LF with chunk extension
        let raw3 = "5;ext=foo\nhello\r\n0\r\n\r\n";
        let err3 = wing::decode_chunked_body(raw3, out_body);
        sub.assert_eq(err3, wing::ChunkedDecodeError.BareLfInChunkSize, "Bare LF after chunk extension must be rejected");
    };

    t.run("CHUNK-02: Bare LF Ending Chunk-Data Rejection (RFC 9112 Section 7.1)") { sub =>
        var out_body: u8[>..] = [];

        // Valid chunk-size CRLF, but chunk-data terminated by bare LF
        let raw1 = "4\r\nwiki\n0\r\n\r\n";
        let err1 = wing::decode_chunked_body(raw1, out_body);
        sub.assert_eq(err1, wing::ChunkedDecodeError.BareLfInChunkData, "Bare LF after chunk data must be rejected");

        let raw2 = "5\r\nhello\n0\r\n\r\n";
        let err2 = wing::decode_chunked_body(raw2, out_body);
        sub.assert_eq(err2, wing::ChunkedDecodeError.BareLfInChunkData, "Bare LF after chunk data must fail with BareLfInChunkData");
    };

    t.run("CHUNK-03: Bare LF in Trailer Lines Rejection ") { sub =>
        var out_body: u8[>..] = [];

        // Last chunk followed by bare LF instead of CRLF
        let raw1 = "0\r\n\n";
        let err1 = wing::decode_chunked_body(raw1, out_body);
        sub.assert_eq(err1, wing::ChunkedDecodeError.BareLfInTrailer, "Bare LF terminating trailer section must be rejected");

        // Trailer header terminated by bare LF
        let raw2 = "0\r\nX-Checksum: abc\n\r\n";
        let err2 = wing::decode_chunked_body(raw2, out_body);
        sub.assert_eq(err2, wing::ChunkedDecodeError.BareLfInTrailer, "Bare LF ending trailer header must be rejected");
    };

    t.run("CHUNK-04: Chunk Extensions with CR or CTL Rejection ") { sub =>
        var out_body: u8[>..] = [];

        // Bare CR inside extension
        let raw1 = "4;ext=val\rfoo\r\nwiki\r\n0\r\n\r\n";
        let err1 = wing::decode_chunked_body(raw1, out_body);
        sub.assert_eq(err1, wing::ChunkedDecodeError.InvalidChunkExtension, "Bare CR in extension must be rejected");

        // Control char inside extension
        let raw2 = "4;ext=\x01\r\nwiki\r\n0\r\n\r\n";
        let err2 = wing::decode_chunked_body(raw2, out_body);
        sub.assert_eq(err2, wing::ChunkedDecodeError.InvalidChunkExtension, "Control char in extension must be rejected");
    };

    t.run("CHUNK-05: 64-Bit Chunk Size Overflow & Hex Validation") { sub =>
        var out_body: u8[>..] = [];

        // 17-digit hex overflow
        let raw1 = "10000000000000000\r\nfoo\r\n0\r\n\r\n";
        let err1 = wing::decode_chunked_body(raw1, out_body);
        sub.assert_true(err1 == wing::ChunkedDecodeError.InvalidChunkSizeHex || err1 == wing::ChunkedDecodeError.ChunkSizeOverflow, "17-digit chunk size must be rejected");

        // Non-hex characters
        let raw3 = "+5\r\nhello\r\n0\r\n\r\n";
        let err3 = wing::decode_chunked_body(raw3, out_body);
        sub.assert_eq(err3, wing::ChunkedDecodeError.InvalidChunkSizeHex, "Plus sign in chunk size must be rejected");

        let raw4 = "0x10\r\nhello\r\n0\r\n\r\n";
        let err4 = wing::decode_chunked_body(raw4, out_body);
        sub.assert_eq(err4, wing::ChunkedDecodeError.InvalidChunkSizeHex, "0x prefix in chunk size must be rejected");

        let raw5 = "xyz\r\nhello\r\n0\r\n\r\n";
        let err5 = wing::decode_chunked_body(raw5, out_body);
        sub.assert_eq(err5, wing::ChunkedDecodeError.InvalidChunkSizeHex, "Non-hex characters in chunk size must be rejected");
    };

    t.run("CHUNK-06: Disallowed Trailer Smuggling Defenses (RFC 9112 Section 7.1.2)") { sub =>
        var out_body: u8[>..] = [];

        // Content-Length in trailer (framing conflict smuggling)
        let raw1 = "4\r\ntest\r\n0\r\nContent-Length: 10\r\n\r\n";
        let err1 = wing::decode_chunked_body(raw1, out_body);
        sub.assert_eq(err1, wing::ChunkedDecodeError.DisallowedTrailer, "Content-Length in trailer must be rejected");

        // Transfer-Encoding in trailer
        let raw2 = "4\r\ntest\r\n0\r\nTransfer-Encoding: chunked\r\n\r\n";
        let err2 = wing::decode_chunked_body(raw2, out_body);
        sub.assert_eq(err2, wing::ChunkedDecodeError.DisallowedTrailer, "Transfer-Encoding in trailer must be rejected");

        // Trailer header in trailer
        let raw3 = "4\r\ntest\r\n0\r\nTrailer: foo\r\n\r\n";
        let err3 = wing::decode_chunked_body(raw3, out_body);
        sub.assert_eq(err3, wing::ChunkedDecodeError.DisallowedTrailer, "Trailer header in trailer must be rejected");

        // Authorization in trailer (security bypass)
        let raw4 = "4\r\ntest\r\n0\r\nAuthorization: Bearer evil\r\n\r\n";
        let err4 = wing::decode_chunked_body(raw4, out_body);
        sub.assert_eq(err4, wing::ChunkedDecodeError.DisallowedTrailer, "Authorization in trailer must be rejected");

        // Set-Cookie in trailer
        let raw5 = "4\r\ntest\r\n0\r\nSet-Cookie: session=smuggled\r\n\r\n";
        let err5 = wing::decode_chunked_body(raw5, out_body);
        sub.assert_eq(err5, wing::ChunkedDecodeError.DisallowedTrailer, "Set-Cookie in trailer must be rejected");

        // Content-Range in trailer
        let raw6 = "4\r\ntest\r\n0\r\nContent-Range: bytes 0-10/100\r\n\r\n";
        let err6 = wing::decode_chunked_body(raw6, out_body);
        sub.assert_eq(err6, wing::ChunkedDecodeError.DisallowedTrailer, "Content-Range in trailer must be rejected");
    };

    t.run("CHUNK-08: Trailer Flooding Attack Defense ") { sub =>
        var out_body:  u8[>..]    = [];
        var flood_buf: u8[..4096] = [];
        flood_buf.append("4\r\ntest\r\n0\r\n");
        // Inject 20 valid non-disallowed trailer lines (exceeding max_trailers = 16)
        for i in 20 {
            flood_buf.append("X-Custom-Trailer-");
            format(flood_buf, i as i64);
            flood_buf.append(": value\r\n");
        }
        flood_buf.append("\r\n");

        let err = wing::decode_chunked_body(flood_buf[..], out_body);
        sub.assert_eq(err, wing::ChunkedDecodeError.DisallowedTrailer, "More than 16 trailer fields must be rejected");
    };

    t.run("CHUNK-09: Trailer Total Byte Length Bomb Defense") { sub =>
        var out_body: u8[>..] = [];
        var huge_tr:  u8[>..] = [];
        huge_tr.append("4\r\ntest\r\n0\r\nX-Giant-Trailer: ");
        for _ in 4500 {
            huge_tr.push('A');
        }
        huge_tr.append("\r\n\r\n");

        let err = wing::decode_chunked_body(huge_tr[..], out_body);
        sub.assert_eq(err, wing::ChunkedDecodeError.DisallowedTrailer, "Trailer exceeding 4096 bytes must be rejected");
    };

    t.run("CHUNK-07: Valid Chunked Body Decoding & Multi-Chunk Reassembly") { sub =>
        // Standard single chunk
        var body1: u8[>..] = [];
        let raw1 = "4\r\nwiki\r\n0\r\n\r\n";
        let err1 = wing::decode_chunked_body(raw1, body1);
        sub.assert_eq(err1, wing::ChunkedDecodeError.None, "Standard chunk decoded cleanly");
        sub.assert_bytes_eq(body1[..], "wiki", "Decoded data matches expected");

        // Multi-chunk sequence
        var body2: u8[>..] = [];
        let raw2 = "5\r\nHello\r\n1\r\n \r\n5\r\nWorld\r\n0\r\n\r\n";
        let err2 = wing::decode_chunked_body(raw2, body2);
        sub.assert_eq(err2, wing::ChunkedDecodeError.None, "Multi-chunk decoded cleanly");
        sub.assert_bytes_eq(body2[..], "Hello World", "Reassembled message matches expected");

        // Chunk with valid extension
        var body3: u8[>..] = [];
        let raw3 = "4;token=123\r\ntest\r\n0\r\n\r\n";
        let err3 = wing::decode_chunked_body(raw3, body3);
        sub.assert_eq(err3, wing::ChunkedDecodeError.None, "Chunk with extension decoded cleanly");
        sub.assert_bytes_eq(body3[..], "test", "Data after extension parsed accurately");

        // Chunk with allowed trailer
        var body4: u8[>..] = [];
        let raw4 = "4\r\ndata\r\n0\r\nX-Checksum: 12345\r\n\r\n";
        let err4 = wing::decode_chunked_body(raw4, body4);
        sub.assert_eq(err4, wing::ChunkedDecodeError.None, "Chunk with custom trailer decoded cleanly");
        sub.assert_bytes_eq(body4[..], "data", "Payload decoded cleanly");
    };
}

fn test_hop_by_hop_stripping_defense(t: lit::T&) {
    t.run("HOP-01: Standard Hop-by-Hop Headers Stripped (RFC 9110 Section 7.6.1)") { sub =>
        var src = wing::HeaderMap { .. };
        let raw = "Host: example.com\r\nConnection: close\r\nKeep-Alive: timeout=5, max=100\r\nProxy-Authenticate: Basic\r\nProxy-Authorization: Basic abc\r\nTE: gzip\r\nTrailer: X-Checksum\r\nTransfer-Encoding: chunked\r\nUpgrade: websocket\r\nProxy-Connection: keep-alive\r\nContent-Type: application/json\r\nAuthorization: Bearer token123\r\n\r\n";
        let p_err = wing::parse_headers(raw, src);
        sub.assert_eq(p_err, wing::HeaderParseError.None, "Source headers parsed ok");

        var dst = wing::HeaderMap { .. };
        wing::strip_hop_by_hop_headers(src, dst);

        // Verify hop-by-hop headers are completely absent
        sub.assert_false(wing::has_header(dst, "connection"), "Connection must be stripped");
        sub.assert_false(wing::has_header(dst, "keep-alive"), "Keep-Alive must be stripped");
        sub.assert_false(wing::has_header(dst, "proxy-authenticate"), "Proxy-Authenticate must be stripped");
        sub.assert_false(wing::has_header(dst, "proxy-authorization"), "Proxy-Authorization must be stripped");
        sub.assert_false(wing::has_header(dst, "te"), "TE must be stripped");
        sub.assert_false(wing::has_header(dst, "trailer"), "Trailer must be stripped");
        sub.assert_false(wing::has_header(dst, "transfer-encoding"), "Transfer-Encoding must be stripped");
        sub.assert_false(wing::has_header(dst, "upgrade"), "Upgrade must be stripped");
        sub.assert_false(wing::has_header(dst, "proxy-connection"), "Proxy-Connection must be stripped");

        // Verify end-to-end headers are preserved
        sub.assert_true(wing::has_header(dst, "host"), "Host must be preserved");
        sub.assert_true(wing::has_header(dst, "content-type"), "Content-Type must be preserved");
        sub.assert_true(wing::has_header(dst, "authorization"), "Authorization must be preserved");
        sub.assert_bytes_eq(wing::get_header(dst, "authorization"), "Bearer token123", "Authorization value intact");
    };

    t.run("HOP-02: Dynamic Custom Tokens in Connection Header (RFC 9110 Section 7.6.1)") { sub =>
        var src = wing::HeaderMap { .. };
        let raw = "Host: api.internal\r\nConnection: close, X-Custom-Hop, X-Internal-Token\r\nX-Custom-Hop: sensitive_gateway_data\r\nX-Internal-Token: secret999\r\nX-Preserve-Me: public_data\r\n\r\n";
        wing::parse_headers(raw, src);

        var dst = wing::HeaderMap { .. };
        wing::strip_hop_by_hop_headers(src, dst);

        sub.assert_false(wing::has_header(dst, "connection"), "Connection header stripped");
        sub.assert_false(wing::has_header(dst, "x-custom-hop"), "X-Custom-Hop dynamically stripped");
        sub.assert_false(wing::has_header(dst, "x-internal-token"), "X-Internal-Token dynamically stripped");
        sub.assert_true(wing::has_header(dst, "x-preserve-me"), "X-Preserve-Me preserved");
        sub.assert_bytes_eq(wing::get_header(dst, "x-preserve-me"), "public_data", "Value intact");
    };

    t.run("HOP-03: Empty Connection Header Does Not Block Subsequent Stripping ") { sub =>
        var src = wing::HeaderMap { .. };
        // First Connection header is empty, second specifies sensitive custom header
        let raw = "Host: example.com\r\nConnection:\r\nConnection: close, X-Secret-Hop\r\nX-Secret-Hop: leaked_token\r\nContent-Type: text/plain\r\n\r\n";
        wing::parse_headers(raw, src);

        var dst = wing::HeaderMap { .. };
        wing::strip_hop_by_hop_headers(src, dst);

        sub.assert_false(wing::has_header(dst, "connection"), "Connection headers stripped");
        sub.assert_false(wing::has_header(dst, "x-secret-hop"), "X-Secret-Hop stripped despite empty first Connection header");
        sub.assert_true(wing::has_header(dst, "content-type"), "Content-Type preserved");
    };

    t.run("HOP-04: Multiple Comma-Separated Connection Headers ") { sub =>
        var src = wing::HeaderMap { .. };
        // Multiple Connection headers with multiple tokens
        let raw = "Host: example.com\r\nConnection: keep-alive, X-Hop-One\r\nConnection: X-Hop-Two, X-Hop-Three\r\nX-Hop-One: v1\r\nX-Hop-Two: v2\r\nX-Hop-Three: v3\r\nX-Retained: keep_this\r\n\r\n";
        wing::parse_headers(raw, src);

        var dst = wing::HeaderMap { .. };
        wing::strip_hop_by_hop_headers(src, dst);

        sub.assert_false(wing::has_header(dst, "x-hop-one"), "X-Hop-One stripped");
        sub.assert_false(wing::has_header(dst, "x-hop-two"), "X-Hop-Two stripped");
        sub.assert_false(wing::has_header(dst, "x-hop-three"), "X-Hop-Three stripped");
        sub.assert_true(wing::has_header(dst, "x-retained"), "X-Retained preserved");
    };

    t.run("HOP-05: Case-Insensitive & Whitespace-Tolerant Token Stripping") { sub =>
        var src = wing::HeaderMap { .. };
        let raw = "Host: example.com\r\nConnection: \t  x-foo  ,\t X-BAR \t\r\nX-FOO: val1\r\nx-bar: val2\r\nX-Normal: val3\r\n\r\n";
        wing::parse_headers(raw, src);

        var dst = wing::HeaderMap { .. };
        wing::strip_hop_by_hop_headers(src, dst);

        sub.assert_false(wing::has_header(dst, "x-foo"), "X-FOO stripped case-insensitively");
        sub.assert_false(wing::has_header(dst, "x-bar"), "x-bar stripped case-insensitively");
        sub.assert_true(wing::has_header(dst, "x-normal"), "X-Normal retained");
    };

    t.run("HOP-06: Hop-by-Hop Stripping on 1xx Informational Responses (CVE-2021-33197)") { sub =>
        var src_1xx = wing::HeaderMap { .. };
        let raw_1xx = "Link: </style.css>; rel=preload\r\nConnection: close, X-Early-Hop\r\nX-Early-Hop: forbidden_hint\r\nKeep-Alive: timeout=10\r\n\r\n";
        wing::parse_headers(raw_1xx, src_1xx);

        var dst_1xx = wing::HeaderMap { .. };
        wing::strip_hop_by_hop_headers(src_1xx, dst_1xx);

        sub.assert_true(wing::has_header(dst_1xx, "link"), "Link header retained on 1xx");
        sub.assert_false(wing::has_header(dst_1xx, "connection"), "Connection stripped on 1xx");
        sub.assert_false(wing::has_header(dst_1xx, "keep-alive"), "Keep-Alive stripped on 1xx");
        sub.assert_false(wing::has_header(dst_1xx, "x-early-hop"), "Custom hop token stripped on 1xx");
    };
}

fn test_url_quadratic_backtrack_defense(t: lit::T&) {
    t.run("BACKTRACK-01: Linear O(N) Execution on 100 Alternating Backtrack Segments (CVE-2026-56860)") { sub =>
        var path_buf: u8[..1024] = [];
        path_buf.append("https://example.com");
        for _ in 100 {
            path_buf.append("/a/..");
        }
        path_buf.append("/target");

        let sw = core::stopwatch();
        let u = core::new_url(path_buf[..]);
        let dur = core::elapsed(sw);
        let elapsed_us = dur.nanos / 1000;

        sub.assert_true(u.valid, "URL with 100 backtrack segments must parse successfully");
        sub.assert_bytes_eq(core::pathname(u), "/target", "Collapsed path must equal /target");
        sub.assert_true(elapsed_us < 1000, "100 backtrack segments must execute in under 1ms (linear O(N))");
    };

    t.run("BACKTRACK-02: 50 Nested Segments Collapsed by 50 Parent References") { sub =>
        var path_buf: u8[..1024] = [];
        path_buf.append("https://example.com");
        for _ in 50 {
            path_buf.append("/dir");
        }
        for _ in 50 {
            path_buf.append("/..");
        }
        path_buf.append("/root_target");

        let sw = core::stopwatch();
        let u = core::new_url(path_buf[..]);
        let dur = core::elapsed(sw);
        let elapsed_us = dur.nanos / 1000;

        sub.assert_true(u.valid, "Nested 50 dir / 50 .. must parse successfully");
        sub.assert_bytes_eq(core::pathname(u), "/root_target", "50 dirs collapsed back to root_target");
        sub.assert_true(elapsed_us < 1000, "50 nested + 50 backtrack must execute in under 1ms");
    };

    t.run("BACKTRACK-03: Root Directory Traversal Containment (Cannot Escape Root)") { sub =>
        let u1 = core::new_url("https://example.com/../../../../../../../../");
        sub.assert_true(u1.valid, "Excessive root .. is valid");
        sub.assert_bytes_eq(core::pathname(u1), "/", "Excessive .. contained at root /");

        let u2 = core::new_url("https://example.com/../../../../etc/passwd");
        sub.assert_true(u2.valid, "Traversal path parsed");
        sub.assert_bytes_eq(core::pathname(u2), "/etc/passwd", "Path traversal contained at root");
    };

    t.run("BACKTRACK-04: Percent-Encoded Dot Segments Normalization (%2e, %2E)") { sub =>
        let u1 = core::new_url("https://example.com/a/%2e%2e/b/%2E%2E/c/%2e/d");
        sub.assert_true(u1.valid, "Percent-encoded dot segments parsed");
        sub.assert_bytes_eq(core::pathname(u1), "/c/d", "%2e%2e collapsed identically to ..");

        let u2 = core::new_url("https://example.com/admin/%2e%2e/%2e%2e/public");
        sub.assert_bytes_eq(core::pathname(u2), "/public", "Double percent-encoded dots collapsed to root");
    };

    t.run("BACKTRACK-05: Path Backtrack via Relative Reference Resolution") { sub =>
        let base = core::new_url("https://api.example.com/v1/users/profiles/");
        let resolved = core::resolve_endpoint(base, "../../v2/billing");
        sub.assert_true(resolved.valid, "Relative endpoint resolved");
        sub.assert_bytes_eq(core::pathname(resolved), "/v1/v2/billing", "Relative backtrack collapsed properly");
    };
}

fn test_sfv_integer_overflow_guard(t: lit::T&) {
    t.run("SFV-01: RFC 8941 Section 3.3.1 19+ Digit Integer Accumulation Overflow Guard") { sub =>
        var item = wing::SfvItem { .. };

        // 19-digit number exceeding signed 64-bit int max (9223372036854775808)
        let ok1 = wing::parse_sfv_item("9223372036854775808", item);
        sub.assert_false(ok1, "19-digit number exceeding i64 max must be rejected");

        // 20-digit number
        let ok2 = wing::parse_sfv_item("10000000000000000000", item);
        sub.assert_false(ok2, "20-digit number must be rejected immediately without overflow");

        // 35-digit giant number
        let ok3 = wing::parse_sfv_item("99999999999999999999999999999999999", item);
        sub.assert_false(ok3, "Giant digit string must be rejected cleanly");

        // Negative 20-digit number
        let ok4 = wing::parse_sfv_item("-10000000000000000000", item);
        sub.assert_false(ok4, "Negative 20-digit number must be rejected cleanly");
    };

    t.run("SFV-02: RFC 8941 Section 3.3.2 19+ Digit Decimal Accumulation Overflow Guard") { sub =>
        var item = wing::SfvItem { .. };

        // 20 integer digits before decimal dot
        let ok1 = wing::parse_sfv_item("10000000000000000000.5", item);
        sub.assert_false(ok1, "20-digit integer part in decimal must be rejected without overflow");

        // 30 integer digits before decimal dot
        let ok2 = wing::parse_sfv_item("999999999999999999999999999999.123", item);
        sub.assert_false(ok2, "Giant decimal integer part must be rejected cleanly");
    };
}

// --- Component: http_status_diagnostics ---
// Verification suite for RFC 9211 (Cache-Status) and RFC 9209 (Proxy-Status):
// - RFC 9211 Cache-Status header parsing (hit, stored, collapsed, ttl, fwd, key, detail)
// - RFC 9211 formatting and roundtrip verification
// - RFC 9209 Proxy-Status header parsing (error, next-hop, details, received-status)
// - RFC 9209 formatting and multi-proxy hop chains

fn test_cache_status_rfc9211(t: lit::T&) {
    t.run("Parse Single & Multi-Cache Status") { sub =>
        let raw = "OriginCache; hit; ttl=120; key=\"asset-hash-123\"; detail=\"memory\", EdgeCache; stored; fwd=stale; fwd-status=200";
        var entries: wing::CacheStatusEntry[..8] = [];
        let count = wing::parse_cache_status_header(raw, entries);
        sub.assert_eq(count, 2, "Parsed 2 cache status entries");

        // Entry 1: OriginCache
        sub.assert_bytes_eq(entries[0].cache_name[..], "OriginCache", "Entry 1 name matches");
        sub.assert_true(entries[0].hit, "Entry 1 is a hit");
        sub.assert_eq(entries[0].ttl, 120, "Entry 1 TTL is 120");
        sub.assert_bytes_eq(entries[0].key[..], "asset-hash-123", "Entry 1 key matches");
        sub.assert_bytes_eq(entries[0].detail[..], "memory", "Entry 1 detail matches");

        // Entry 2: EdgeCache
        sub.assert_bytes_eq(entries[1].cache_name[..], "EdgeCache", "Entry 2 name matches");
        sub.assert_false(entries[1].hit, "Entry 2 is NOT hit");
        sub.assert_true(entries[1].stored, "Entry 2 is stored");
        sub.assert_bytes_eq(entries[1].fwd[..], "stale", "Entry 2 fwd reason is stale");
        sub.assert_eq(entries[1].fwd_status, 200, "Entry 2 fwd-status is 200");
    };

    t.run("Format Cache Status") { sub =>
        var entry = wing::CacheStatusEntry {
            hit: true,
            ttl: 300,
            ..
        };
        entry.cache_name.append("CDN-Fastly");
        entry.key.append("page-v2");

        var out: u8[..256] = [];
        wing::format_cache_status(entry, out);
        sub.assert_contains(out[..], "CDN-Fastly; hit; ttl=300; key=\"page-v2\"", "Formatted matches RFC 9211");
    };
}

fn test_proxy_status_rfc9209(t: lit::T&) {
    t.run("Parse Proxy Error Status") { sub =>
        let raw = "edge-us-east; error=connection_refused; next-hop=\"10.0.1.5\"; details=\"TCP SYN reset by peer\"; received-status=502";
        var entries: wing::ProxyStatusEntry[..8] = [];
        let count = wing::parse_proxy_status_header(raw, entries);
        sub.assert_eq(count, 1, "Parsed 1 proxy status");

        sub.assert_bytes_eq(entries[0].proxy_name[..], "edge-us-east", "Proxy name matches");
        sub.assert_bytes_eq(entries[0].error_type[..], "connection_refused", "Error type is connection_refused");
        sub.assert_bytes_eq(entries[0].next_hop[..], "10.0.1.5", "Next hop matches");
        sub.assert_bytes_eq(entries[0].details[..], "TCP SYN reset by peer", "Details match");
        sub.assert_eq(entries[0].received_status, 502, "Received status is 502");
    };

    t.run("Format Proxy Status") { sub =>
        var entry = wing::ProxyStatusEntry {
            received_status: 504,
            ..
        };
        entry.proxy_name.append("gateway-ingress");
        entry.error_type.append("connection_timeout");
        entry.next_hop.append("origin.internal");

        var out: u8[..256] = [];
        wing::format_proxy_status(entry, out);
        sub.assert_contains(out[..], "gateway-ingress; error=connection_timeout", "Formatted error");
        sub.assert_contains(out[..], "next-hop=\"origin.internal\"", "Formatted next-hop");
        sub.assert_contains(out[..], "received-status=504", "Formatted received-status");
    };
}

// --- Component: http_extensions_invariants ---
// Security invariant tests for HTTP Extensions:
// 1. Resumable Upload (draft-ietf-httpbis-resumable-upload-14) Structured Fields & Bounds
// 2. Early Hints (RFC 8297) & RFC 8288 Link header invariants

fn test_resumable_upload_structured_fields(t: lit::T&) {
    // 1. Integer parsing (non-negative integer enforcement)
    let n1, ok1 = wing::parse_upload_int("0");
    t.assert_true(ok1, "0 is valid integer");
    t.assert_eq(n1, 0, "value is 0");

    let n2, ok2 = wing::parse_upload_int("   65536   ");
    t.assert_true(ok2, "trimmed 65536 is valid integer");
    t.assert_eq(n2, 65536, "value is 65536");

    let _, ok_neg = wing::parse_upload_int("-1");
    t.assert_false(ok_neg, "negative integer must be rejected");

    let _, ok_bad = wing::parse_upload_int("abc");
    t.assert_false(ok_bad, "alphanumeric string must be rejected");

    // 2. RFC 8941 Structured Field boolean parsing
    let b1, ok_b1 = wing::parse_upload_boolean("?1");
    t.assert_true(ok_b1, "?1 is valid boolean");
    t.assert_true(b1, "value is true");

    let b2, ok_b2 = wing::parse_upload_boolean("?0");
    t.assert_true(ok_b2, "?0 is valid boolean");
    t.assert_false(b2, "value is false");

    let b3, ok_b3 = wing::parse_upload_boolean("?1; foo=bar");
    t.assert_true(ok_b3, "?1 with parameter is valid");
    t.assert_true(b3, "value is true");

    let _, ok_b4 = wing::parse_upload_boolean("?1bad");
    t.assert_false(ok_b4, "?1bad must be rejected as boolean");

    let _, ok_b5 = wing::parse_upload_boolean("true");
    t.assert_false(ok_b5, "unstructured 'true' must be rejected");
}

fn test_early_hints_link_header_security(t: lit::T&) {
    // 1. Standard Link preload
    var links1: wing::EarlyHintLink[..4] = [];
    let ok1 = wing::parse_link_header("<https://cdn.example.com/main.js>; rel=preload; as=script", links1);
    t.assert_true(ok1, "valid link header parse");
    t.assert_eq(links1.len, 1, "parsed 1 link");
    t.assert_true(links1[0].uri[..] == "https://cdn.example.com/main.js", "uri matches");
    t.assert_true(links1[0].rel[..] == "preload", "rel matches");
    t.assert_true(links1[0].as_type[..] == "script", "as matches");

    // 2. Link with commas inside query string (must NOT split entry!)
    var links2: wing::EarlyHintLink[..4] = [];
    let ok2 = wing::parse_link_header("<https://cdn.example.com/bundle.js?v=1,2,3>; rel=preload; as=script", links2);
    t.assert_true(ok2, "uri with comma in query string must not break link parsing");
    t.assert_eq(links2.len, 1, "parsed exactly 1 link");
    t.assert_true(links2[0].uri[..] == "https://cdn.example.com/bundle.js?v=1,2,3", "query string with comma preserved");

    // 3. Case-insensitive parameters (RFC 8288 Section 3.2)
    var links3: wing::EarlyHintLink[..4] = [];
    let ok3 = wing::parse_link_header("<https://cdn.example.com/font.woff2>; REL=preload; AS=font; CrossOrigin", links3);
    t.assert_true(ok3, "case-insensitive param matching");
    t.assert_eq(links3.len, 1, "parsed 1 link");
    t.assert_true(links3[0].rel[..] == "preload", "rel matches");
    t.assert_true(links3[0].as_type[..] == "font", "as matches");
    t.assert_true(links3[0].crossorigin, "crossorigin set");

    // 4. Reject empty URI `<>`
    var links_bad1: wing::EarlyHintLink[..4] = [];
    let ok_bad1 = wing::parse_link_header("<>; rel=preload", links_bad1);
    t.assert_false(ok_bad1, "empty URI <> must be rejected");

    // 5. Reject characters between `>` and `;`
    var links_bad2: wing::EarlyHintLink[..4] = [];
    let ok_bad2 = wing::parse_link_header("<https://example.com>invalid; rel=preload", links_bad2);
    t.assert_false(ok_bad2, "characters between > and ; must be rejected");
}

fn main() {
    var runner = lit::new_runner("HTTP/1.1 Framing, Chunked Transfer, and Smuggling Defense Suite", lit::Verbosity.Verbose);

    lit::run_case(runner, "1. Zero-Heap HeaderMap & Inline Slots", test_headermap_zero_heap_and_inline_slots);
    lit::run_case(runner, "2. RFC 9110 & Set-Cookie Fold Isolation", test_rfc9110_and_cookie_fold_isolation);
    lit::run_case(runner, "3. Lexical Validation & SWAR", test_lexical_validation_and_swar);
    lit::run_case(runner, "4. httparse PR #223 Regression & obs-fold", test_httparse_regression_and_obs_fold);
    lit::run_case(runner, "5. Chromium Net Parity (raw_headers, 304 Merge, Persistence)", test_chromium_net_parity);
    lit::run_case(runner, "6. One-Shot Chunked Decoding with Trailer Extraction", test_oneshot_chunked_trailers);
    lit::run_case(runner, "7. RFC 9112 Smuggling & Desynchronization Defenses", test_chunked_smuggling_defenses);
    lit::run_case(runner, "8. Incremental Chunked Stream Decoder", test_incremental_chunked_stream_decoder);
    lit::run_case(runner, "9. HttpServer Ingress with Chunked Framing & Smuggling Guards", test_httpserver_chunked_ingress);
    lit::run_case(runner, "10. Server Chunked Response Serialization & Symmetrical Response Wire Parser", test_chunked_response_and_wire_parser);
    lit::run_case(runner, "11. TE/CL Request Smuggling & Content-Length Poisoning Defense", test_te_cl_request_smuggling_defense);
    lit::run_case(runner, "12. Chunked Encoding & Bare LF Smuggling Defense (CVE-2025-22871)", test_chunked_encoding_bare_lf_defense);
    lit::run_case(runner, "13. Hop-by-Hop Header Stripping & Gateway Isolation (RFC 9110 Section 7.6.1)", test_hop_by_hop_stripping_defense);
    lit::run_case(runner, "14. URL Path Backtrack Quadratic Complexity Defense (CVE-2026-56860)", test_url_quadratic_backtrack_defense);
    lit::run_case(runner, "15. SFV Integer & Decimal 64-Bit Overflow Protection", test_sfv_integer_overflow_guard);
    lit::run_case(runner, "16. RFC 9211 Cache-Status", test_cache_status_rfc9211);
    lit::run_case(runner, "17. RFC 9209 Proxy-Status", test_proxy_status_rfc9209);
    lit::run_case(runner, "18. Resumable Upload Structured Fields", test_resumable_upload_structured_fields);
    lit::run_case(runner, "19. Early Hints Link Header Security", test_early_hints_link_header_security);

    let ok = lit::finish(runner);
    assert(ok);
}
