// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Consolidated Verification Suite: HTTP/1.1 Framing, Chunked Transfer, and Smuggling Defense Suite
//
// RUN: goose build -o %t.exe %s
// RUN: %t.exe
import std;
import wing from "..";
import lit from "github.com/Lemon4ksan/goose-lit@v0.1.0";

// --- Component: http_headers ---
// Tests for HeaderMap, header parsing, validation, and iteration.

// ----------------------------------------------------------------------------
// 1. Zero-Heap HeaderMap & Inline Slots
// ----------------------------------------------------------------------------
fn test_headermap_zero_heap_and_inline_slots(t: lit::T&) {
    t.run("Basic HeaderMap Operations and O(1) WellKnown Slots") { sub =>
        var map = http::HeaderMap { .. };
        sub.assert_true(map.valid, "Newly created map is valid");

        // Set well-known inline headers
        let ok_host = http::set_inline(map, http::WellKnownHeader.Host, "api.service.internal");
        sub.assert_true(ok_host, "Set inline host succeeded");
        let ok_ct = http::set_inline(map, http::WellKnownHeader.ContentType, "application/json; charset=utf-8");
        sub.assert_true(ok_ct, "Set inline content-type succeeded");
        let ok_cl = http::set_inline(map, http::WellKnownHeader.ContentLength, "1024");
        sub.assert_true(ok_cl, "Set inline content-length succeeded");

        // O(1) retrieval
        sub.assert_bytes_eq(http::get_inline(map, http::WellKnownHeader.Host), "api.service.internal", "Inline Host match");
        sub.assert_bytes_eq(http::get_inline(map, http::WellKnownHeader.ContentType), "application/json; charset=utf-8", "Inline Content-Type match");
        sub.assert_bytes_eq(http::get_inline(map, http::WellKnownHeader.ContentLength), "1024", "Inline Content-Length match");

        // Case-insensitive retrieval via general accessor
        sub.assert_bytes_eq(http::get_header(map, "HOST"), "api.service.internal", "Case-insensitive HOST lookup");
        sub.assert_bytes_eq(http::get_header(map, "content-TYPE"), "application/json; charset=utf-8", "Case-insensitive content-TYPE lookup");
        sub.assert_true(http::has_header(map, "content-length"), "has_header content-length true");
        sub.assert_false(http::has_header(map, "authorization"), "has_header authorization false");
    };

    t.run("Custom Headers & Overwrite Behavior") { sub =>
        var map = http::HeaderMap { .. };
        http::append_header(map, "X-Custom-Engine", "GooseWing/1.0");
        http::append_header(map, "X-Trace-ID", "trace-abc-123");

        sub.assert_bytes_eq(http::get_header(map, "x-custom-engine"), "GooseWing/1.0", "Custom header found");
        sub.assert_bytes_eq(http::get_header(map, "x-trace-id"), "trace-abc-123", "Trace ID found");

        // Overwrite via insert_header
        http::insert_header(map, "x-trace-id", "trace-xyz-999");
        sub.assert_bytes_eq(http::get_header(map, "x-trace-id"), "trace-xyz-999", "Trace ID overwritten");

        // Removal
        let removed = http::remove_header(map, "X-Custom-Engine");
        sub.assert_true(removed, "Header successfully removed");
        sub.assert_false(http::has_header(map, "X-Custom-Engine"), "Removed header no longer present");
    };

    t.run("200-Iteration In-Place Overwrite and Shrink Compaction Without raw_buf Exhaustion") { sub =>
        var map = http::HeaderMap { .. };
        http::append_header(map, "Host", "api.example.com");
        http::append_header(map, "User-Agent", "goose-wing/1.0");
        http::append_header(map, "Authorization", "Bearer initial-token-000000000000000000000000");

        for iter in 200 {
            var token_val: u8[..64] = [];
            format(token_val, "Bearer rotated-jwt-token-iteration-", iter);
            sub.assert_true(
                http::insert_header(map, "Authorization", token_val[..]),
                "insert_header succeeded across 200 iterations without raw_buf exhaustion",
            );
            sub.assert_bytes_eq(http::get_header(map, "Authorization"), token_val[..], "Authorization matches current iteration");

            var trace_val: u8[..32] = [];
            format(trace_val, "hop-", iter);
            sub.assert_true(http::insert_header(map, "X-Hop-Trace", trace_val[..]), "insert X-Hop-Trace succeeded");
            sub.assert_true(http::remove_header(map, "X-Hop-Trace"), "remove X-Hop-Trace compacted raw_buf");
        }
        sub.assert_bytes_eq(http::get_header(map, "Host"), "api.example.com", "Host intact after 200 compactions");
        sub.assert_bytes_eq(http::get_header(map, "User-Agent"), "goose-wing/1.0", "User-Agent intact after 200 compactions");
        sub.assert_lt(map.raw_buf.len, 256, "raw_buf remained compact (< 256 bytes) after 200 overwrite/remove cycles");
    };

    t.run("Connection Reuse (reset_for_keep_alive)") { sub =>
        var map = http::HeaderMap { .. };
        http::set_inline(map, http::WellKnownHeader.Host, "example.com");
        http::append_header(map, "X-Req", "1");
        sub.assert_eq(map.entries.len, 2, "2 entries before reset");

        http::reset_for_keep_alive(map);
        sub.assert_eq(map.entries.len, 0, "0 entries after reset");
        sub.assert_eq(map.raw_buf.len, 0, "raw_buf cleared after reset");
        sub.assert_bytes_eq(http::get_inline(map, http::WellKnownHeader.Host), "", "Inline slot cleared");

        // Re-use for next request
        http::set_inline(map, http::WellKnownHeader.Host, "reused.com");
        sub.assert_bytes_eq(http::get_inline(map, http::WellKnownHeader.Host), "reused.com", "Inline slot reused cleanly");
    };
}

// ----------------------------------------------------------------------------
// 2. RFC 9110 & Set-Cookie Fold Isolation
// ----------------------------------------------------------------------------
fn test_rfc9110_and_cookie_fold_isolation(t: lit::T&) {
    t.run("List-Based Header Comma Folding (Vary, Accept)") { sub =>
        var map = http::HeaderMap { .. };
        http::append_header(map, "Vary", "Accept-Encoding");
        http::append_header(map, "Vary", "User-Agent");
        http::append_header(map, "Vary", "Origin");

        var combined: u8[>..] = [];
        let ok = http::get_combined(map, "Vary", combined);
        sub.assert_true(ok, "Vary is comma-foldable per RFC 9110 Section 5.3");
        sub.assert_bytes_eq(combined[..], "Accept-Encoding, User-Agent, Origin", "Vary folded correctly");
    };

    t.run("Absolute Prohibition of Set-Cookie Folding (RFC 6265bis & RFC 9110 Section 5.3)") { sub =>
        var map = http::HeaderMap { .. };
        http::append_header(map, "Set-Cookie", "session_id=abc; Secure; HttpOnly; SameSite=Strict");
        http::append_header(map, "Set-Cookie", "theme=dark; Path=/; Max-Age=86400");
        http::append_header(map, "Set-Cookie", "cart=item1,item2; Path=/cart");

        // get_combined MUST fail on Set-Cookie!
        var combined: u8[>..] = [];
        let ok = http::get_combined(map, "Set-Cookie", combined);
        sub.assert_false(ok, "get_combined MUST reject Set-Cookie to prevent session ambiguity");

        // get_set_cookie zero-allocation extraction
        var cookies: u8[..1024][>..] = [];
        http::get_set_cookie(map, cookies);
        sub.assert_eq(cookies.len, 3, "Exactly 3 distinct Set-Cookie entries returned");
        sub.assert_bytes_eq(cookies[0][..], "session_id=abc; Secure; HttpOnly; SameSite=Strict", "Cookie 1 exact");
        sub.assert_bytes_eq(cookies[1][..], "theme=dark; Path=/; Max-Age=86400", "Cookie 2 exact");
        sub.assert_bytes_eq(cookies[2][..], "cart=item1,item2; Path=/cart", "Cookie 3 exact");

        // Serialization must emit multiple Set-Cookie lines without comma folding
        var serialized: u8[>..] = [];
        http::serialize_headers(map, serialized);
        sub.assert_contains(serialized[..], "Set-Cookie: session_id=abc", "Contains line 1");
        sub.assert_contains(serialized[..], "Set-Cookie: theme=dark", "Contains line 2");
        sub.assert_contains(serialized[..], "Set-Cookie: cart=item1,item2", "Contains line 3");
    };

    t.run("Authentication Challenge Fold Isolation (WWW-Authenticate)") { sub =>
        var map = http::HeaderMap { .. };
        http::append_header(map, "WWW-Authenticate", "Basic realm=\"Access to staging\"");
        http::append_header(map, "WWW-Authenticate", "Bearer error=\"invalid_token\"");

        var combined: u8[>..] = [];
        let ok = http::get_combined(map, "WWW-Authenticate", combined);
        sub.assert_false(ok, "get_combined MUST reject WWW-Authenticate folding");
    };
}

// ----------------------------------------------------------------------------
// 3. Lexical Validation & SWAR
// ----------------------------------------------------------------------------
fn test_lexical_validation_and_swar(t: lit::T&) {
    t.run("Valid tchar and Invalid Header Name Checks") { sub =>
        sub.assert_true(http::is_valid_header_name("Content-Type"), "Content-Type is valid");
        sub.assert_true(http::is_valid_header_name("x-api-key_2.0"), "x-api-key_2.0 is valid");
        sub.assert_true(http::is_valid_header_name("!#$%&'*+-.^_`|~"), "All RFC 9110 tchars are valid");

        sub.assert_false(http::is_valid_header_name(""), "Empty header name is invalid");
        sub.assert_false(http::is_valid_header_name("Content Type"), "Header name with space is invalid");
        sub.assert_false(http::is_valid_header_name("Header:Name"), "Colon in name is invalid");
        sub.assert_false(http::is_valid_header_name("Header\tTab"), "Tab in name is invalid");
    };

    t.run("RFC 9113 Section 8.2.1: HTTP/2 Wire Lowercase ASCII Validation") { sub =>
        sub.assert_true(http::is_valid_header_name_h2("content-type"), "Lowercase is valid in HTTP/2");
        sub.assert_true(http::is_valid_header_name_h2(":path"), "Pseudo-header is valid");
        sub.assert_false(http::is_valid_header_name_h2("Content-Type"), "Uppercase is FORBIDDEN on wire in HTTP/2");
        sub.assert_false(http::is_valid_header_name_h2("HOST"), "Uppercase HOST is FORBIDDEN in HTTP/2");
    };

    t.run("Control Character and Embedded NUL Injection Hard Rejection") { sub =>
        // Embedded NUL
        var map = http::HeaderMap { .. };
        let nul_raw: u8[28] = ['H', 'o', 's', 't', ':', ' ', 'a', 0, 'b', 'c', '.', 'c', 'o', 'm', '\r', '\n', '\r', '\n', 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        let err_nul = http::parse_headers(nul_raw[..18], map);
        sub.assert_eq(err_nul, http::HeaderParseError.EmbeddedNull, "Embedded NUL causes immediate parse failure");

        // CRLF in value
        sub.assert_false(http::is_valid_header_value("valid\r\ninjected: true"), "CRLF in value rejected");
        sub.assert_false(http::is_valid_header_value("bad\x01control"), "CTL rejected in value");
        sub.assert_true(http::is_valid_header_value("normal value with \t tab"), "HTAB accepted in value");
    };

    t.run("Whitespace before Colon Rejection (RFC 9110 Section 5.1)") { sub =>
        var map = http::HeaderMap { .. };
        let raw = "Host : example.com\r\n\r\n";
        let err = http::parse_headers(raw, map);
        sub.assert_eq(err, http::HeaderParseError.InvalidHeaderName, "Space before colon rejected");
    };

    t.run("parse_response_headers status line and headers") { sub =>
        var map = http::HeaderMap { .. };
        let raw = "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n";
        let err = http::parse_response_headers(raw, map);
        sub.assert_eq(err, http::HeaderParseError.None, "Response headers parsed");
        sub.assert_eq(map.status_code, 200, "Status code is 200");
    };

    t.run("HeaderPresenceTracker Duplicate Transfer-Encoding Smuggling Rejection") { sub =>
        var tracker = http::HeaderPresenceTracker { .. };
        sub.assert_true(http::track_header_presence(tracker, "Transfer-Encoding", "chunked", 0), "First TE accepted");
        sub.assert_false(http::track_header_presence(tracker, "Transfer-Encoding", "identity", 1), "Duplicate TE rejected");
        sub.assert_true(tracker.has_duplicate_te, "has_duplicate_te flag set");
    };

    t.run("advance_crlf Strict Line Ending Validation") { sub =>
        let valid_crlf = "header: value\r\nnext";
        var c1: i64 = 0;
        sub.assert_true(http::advance_crlf(valid_crlf, c1, 13), "CRLF advanced");
        sub.assert_eq(c1, 15, "Cursor advanced by 2");

        let valid_lf = "header: value\nnext";
        var c2: i64 = 0;
        sub.assert_true(http::advance_crlf(valid_lf, c2, 13), "LF advanced");
        sub.assert_eq(c2, 14, "Cursor advanced by 1");

        let invalid_end = "header: valuenext";
        var c3: i64 = 0;
        sub.assert_false(http::advance_crlf(invalid_end, c3, 13), "Non-CRLF/LF rejected");
        sub.assert_eq(c3, 13, "Cursor stops at line_end");
    };
}

// ----------------------------------------------------------------------------
// 4. httparse PR #223 Regression & obs-fold
// ----------------------------------------------------------------------------
fn test_httparse_regression_and_obs_fold(t: lit::T&) {
    t.run("httparse PR #223 / Issue #222: Whitespace-Only Line Hard Syntax Error") { sub =>
        var map = http::HeaderMap { .. };
        // A line containing only spaces between valid headers MUST NOT silently truncate headers!
        let raw = "Host: example.com\r\n   \r\nX-Secret: leak\r\n\r\n";
        let err = http::parse_headers(raw, map);
        sub.assert_eq(err, http::HeaderParseError.WhitespaceOnlyLine, "Whitespace-only line produces hard syntax error");
        sub.assert_false(map.valid, "Map marked invalid on whitespace-only line");
    };

    t.run("obs-fold Request Smuggling Defense") { sub =>
        var map = http::HeaderMap { .. };
        let raw_fold = "Header: initial\r\n continuation\r\n\r\n";

        // Default: obs-fold rejected
        let err_forbidden = http::parse_headers(raw_fold, map, false);
        sub.assert_eq(err_forbidden, http::HeaderParseError.ObsFoldForbidden, "obs-fold forbidden by default");

        // Archival compatibility mode: obs-fold permitted and folded
        let err_ok = http::parse_headers(raw_fold, map, true);
        sub.assert_eq(err_ok, http::HeaderParseError.None, "obs-fold accepted in compatibility mode");
        sub.assert_bytes_eq(http::get_header(map, "header"), "initial continuation", "Folded with single space");

        // Leading whitespace on very first line fails even in compatibility mode
        let raw_bad_first = "  first-line-ws: bad\r\n\r\n";
        let err_bad_first = http::parse_headers(raw_bad_first, map, true);
        sub.assert_eq(err_bad_first, http::HeaderParseError.LeadingWhitespaceOnFirstHeader, "Leading whitespace on first header rejected");
    };
}

// ----------------------------------------------------------------------------
// 5. Chromium Net Parity (raw_headers, 304 Merge, Persistence)
// ----------------------------------------------------------------------------
fn test_chromium_net_parity(t: lit::T&) {
    t.run("Chromium raw_headers_ \\0\\0 Format") { sub =>
        var map = http::HeaderMap { .. };
        http::append_header(map, "Host", "chromium.org");
        http::append_header(map, "Accept", "*/*");

        var raw_out: u8[>..] = [];
        http::raw_headers(map, raw_out);

        // Lines terminated with \0, whole block with double \0
        sub.assert_true(raw_out.len > 0, "raw_out non-empty");
        sub.assert_eq(raw_out[raw_out.len - 1], 0, "Terminated with \0");
        sub.assert_eq(raw_out[raw_out.len - 2], 0, "Terminated with double \0\0");
    };

    t.run("Chromium 304 Not Modified Merge (Shielding Cookies and Challenges)") { sub =>
        var cached = http::HeaderMap { .. };
        http::append_header(cached, "ETag", "\"etag-123\"");
        http::append_header(cached, "Cache-Control", "max-age=3600");
        http::append_header(cached, "Set-Cookie", "session=original; Secure");
        http::append_header(cached, "Strict-Transport-Security", "max-age=31536000");

        var resp_304 = http::HeaderMap { .. };
        http::append_header(resp_304, "Cache-Control", "max-age=7200");
        http::append_header(resp_304, "Set-Cookie", "session=hijacked");
        http::append_header(resp_304, "Strict-Transport-Security", "max-age=0");
        http::append_header(resp_304, "X-Fresh-Header", "injected");

        http::merge_with_headers_304(cached, resp_304);

        // Cache-Control updated to 7200
        sub.assert_bytes_eq(http::get_header(cached, "Cache-Control"), "max-age=7200", "Cache-Control updated");
        // Fresh custom header merged
        sub.assert_bytes_eq(http::get_header(cached, "X-Fresh-Header"), "injected", "Fresh header merged");
        // Set-Cookie MUST NOT be overwritten or injected by 304!
        sub.assert_bytes_eq(http::get_header(cached, "Set-Cookie"), "session=original; Secure", "Set-Cookie preserved from cache");
        // Strict-Transport-Security MUST NOT be downgraded by 304!
        sub.assert_bytes_eq(http::get_header(cached, "Strict-Transport-Security"), "max-age=31536000", "HSTS preserved from cache");
    };

    t.run("Chromium Cache Persistence Filtering") { sub =>
        var src = http::HeaderMap { .. };
        http::append_header(src, "Content-Type", "text/html");
        http::append_header(src, "Set-Cookie", "user=alice");
        http::append_header(src, "WWW-Authenticate", "Basic realm=\"admin\"");
        http::append_header(src, "Connection", "keep-alive");

        var dst = http::HeaderMap { .. };
        http::persist_headers(src, dst, http::PERSIST_SANS_COOKIES | http::PERSIST_SANS_CHALLENGES | http::PERSIST_SANS_NON_CACHEABLE);

        sub.assert_true(http::has_header(dst, "Content-Type"), "Content-Type persisted");
        sub.assert_false(http::has_header(dst, "Set-Cookie"), "Set-Cookie stripped");
        sub.assert_false(http::has_header(dst, "WWW-Authenticate"), "WWW-Authenticate stripped");
        sub.assert_false(http::has_header(dst, "Connection"), "Connection stripped");
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
// 6. One-Shot Chunked Decoding with Trailer Extraction
// ----------------------------------------------------------------------------
fn test_oneshot_chunked_trailers(t: lit::T&) {
    t.run("Single and multi-chunk decoding with byte count accuracy") { sub =>
        let raw = "4\r\nWiki\r\n6\r\n pedia\r\n0\r\n\r\n";
        var out_body: u8[>..] = [];
        var out_trailers = http::HeaderMap { .. };

        let err, consumed = http::decode_chunked_body_with_trailers(raw, out_body, out_trailers);
        sub.assert_eq(err, http::ChunkedDecodeError.None, "Decoded successfully");
        sub.assert_bytes_eq(out_body[..], "Wiki pedia", "Body reassembled");
        sub.assert_eq(consumed, raw.len, "All raw bytes consumed");
        sub.assert_eq(out_trailers.entries.len, 0, "No trailers in simple message");
    };

    t.run("Chunk extension ignored and parsed cleanly") { sub =>
        let raw = "5;ext_name=ext_value;flag\r\nHello\r\n0;last=1\r\n\r\n";
        var out_body: u8[>..] = [];
        var out_trailers = http::HeaderMap { .. };

        let err, consumed = http::decode_chunked_body_with_trailers(raw, out_body, out_trailers);
        sub.assert_eq(err, http::ChunkedDecodeError.None, "Decoded successfully with extensions");
        sub.assert_bytes_eq(out_body[..], "Hello", "Body matches");
        sub.assert_eq(consumed, raw.len, "Exact length consumed");
    };

    t.run("Extraction of multiple custom trailers") { sub =>
        let raw = "5\r\nHello\r\n0\r\nETag: \"v1-abc\"\r\nX-Checksum: sha256-abc123xyz\r\nX-Timing: dur=15.4\r\n\r\n";
        var out_body: u8[>..] = [];
        var out_trailers = http::HeaderMap { .. };

        let err, consumed = http::decode_chunked_body_with_trailers(raw, out_body, out_trailers);
        sub.assert_eq(err, http::ChunkedDecodeError.None, "Decoded cleanly with trailers");
        sub.assert_bytes_eq(out_body[..], "Hello", "Payload correct");
        sub.assert_eq(consumed, raw.len, "Consumed exact stream length");
        sub.assert_eq(out_trailers.entries.len, 3, "3 trailers extracted");

        var req = http::new_request("POST", "/data");
        req.trailers = copy(out_trailers);
        sub.assert_true(http::has_trailer(req, "x-checksum"), "Has x-checksum");
        sub.assert_bytes_eq(http::trailer(req, "x-checksum"), "sha256-abc123xyz", "Trailer x-checksum value");
        sub.assert_bytes_eq(http::trailer(req, "etag"), "\"v1-abc\"", "Trailer etag value");
        sub.assert_bytes_eq(http::trailer(req, "x-timing"), "dur=15.4", "Trailer x-timing value");
        sub.assert_bytes_eq(http::trailer(req, "missing"), "", "Empty string for missing trailer");
    };

    t.run("Pipelined keep-alive requests separation") { sub =>
        let raw = "4\r\nBody\r\n0\r\n\r\nGET /next HTTP/1.1\r\nHost: example.com\r\n\r\n";
        var out_body: u8[>..] = [];
        var out_trailers = http::HeaderMap { .. };

        let err, consumed = http::decode_chunked_body_with_trailers(raw, out_body, out_trailers);
        sub.assert_eq(err, http::ChunkedDecodeError.None, "Decoded chunked segment");
        sub.assert_bytes_eq(out_body[..], "Body", "Payload extracted");
        sub.assert_eq(consumed, 14, "Exact 14 bytes consumed for chunked stream");
        sub.assert_bytes_eq(raw[consumed..(consumed + 18)], "GET /next HTTP/1.1", "Remaining stream untouched");
    };
}

// ----------------------------------------------------------------------------
// 7. RFC 9112 Smuggling & Desynchronization Defenses
// ----------------------------------------------------------------------------
fn test_chunked_smuggling_defenses(t: lit::T&) {
    t.run("Bare LF in chunk size rejection (CVE-2025-22871)") { sub =>
        var out_body: u8[>..] = [];
        var out_trailers = http::HeaderMap { .. };

        let raw = "4\nWiki\r\n0\r\n\r\n";
        let err, _ = http::decode_chunked_body_with_trailers(raw, out_body, out_trailers);
        sub.assert_eq(err, http::ChunkedDecodeError.BareLfInChunkSize, "Bare LF in chunk size rejected");
    };

    t.run("Bare LF in chunk data terminator rejection") { sub =>
        var out_body: u8[>..] = [];
        var out_trailers = http::HeaderMap { .. };

        let raw = "4\r\nWiki\n0\r\n\r\n";
        let err, _ = http::decode_chunked_body_with_trailers(raw, out_body, out_trailers);
        sub.assert_eq(err, http::ChunkedDecodeError.BareLfInChunkData, "Bare LF after chunk data rejected");
    };

    t.run("Bare LF in chunk data terminator at exact buffer end") { sub =>
        var out_body: u8[>..] = [];
        var out_trailers = http::HeaderMap { .. };

        let raw = "4\r\nWiki\n";
        let err, _ = http::decode_chunked_body_with_trailers(raw, out_body, out_trailers);
        sub.assert_eq(err, http::ChunkedDecodeError.BareLfInChunkData, "Bare LF at buffer boundary rejected");
    };

    t.run("Bare LF in trailer line rejection") { sub =>
        var out_body: u8[>..] = [];
        var out_trailers = http::HeaderMap { .. };

        let raw = "4\r\nWiki\r\n0\r\nX-Check: val\n\r\n";
        let err, _ = http::decode_chunked_body_with_trailers(raw, out_body, out_trailers);
        sub.assert_eq(err, http::ChunkedDecodeError.BareLfInTrailer, "Bare LF in trailer header rejected");
    };

    t.run("Bare LF terminating trailer section rejection") { sub =>
        var out_body: u8[>..] = [];
        var out_trailers = http::HeaderMap { .. };

        let raw = "0\r\n\n";
        let err, _ = http::decode_chunked_body_with_trailers(raw, out_body, out_trailers);
        sub.assert_eq(err, http::ChunkedDecodeError.BareLfInTrailer, "Bare LF ending trailers rejected");
    };

    t.run("RFC 9110 Section 6.5.1: Full Forbidden Trailer Fields Enforcement") { sub =>
        var out_body: u8[>..] = [];
        var out_trailers = http::HeaderMap { .. };

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
            let err, _ = http::decode_chunked_body_with_trailers(raw[..], out_body, out_trailers);
            sub.assert_eq(err, http::ChunkedDecodeError.DisallowedTrailer, "Disallowed header in trailer rejected");
        }

        // Direct is_disallowed_trailer_field verification including pseudo-headers and whitespace
        sub.assert_true(rfc::is_disallowed_trailer_field("connection"), "connection is forbidden");
        sub.assert_true(rfc::is_disallowed_trailer_field("Connection"), "Connection (cased) is forbidden");
        sub.assert_true(rfc::is_disallowed_trailer_field("  connection  "), "whitespace padded connection is forbidden");
        sub.assert_true(rfc::is_disallowed_trailer_field("keep-alive"), "keep-alive is forbidden");
        sub.assert_true(rfc::is_disallowed_trailer_field("upgrade"), "upgrade is forbidden");
        sub.assert_true(rfc::is_disallowed_trailer_field("proxy-connection"), "proxy-connection is forbidden");
        sub.assert_true(rfc::is_disallowed_trailer_field("if-match"), "if-match is forbidden");
        sub.assert_true(rfc::is_disallowed_trailer_field("if-none-match"), "if-none-match is forbidden");
        sub.assert_true(rfc::is_disallowed_trailer_field("if-modified-since"), "if-modified-since is forbidden");
        sub.assert_true(rfc::is_disallowed_trailer_field("if-unmodified-since"), "if-unmodified-since is forbidden");
        sub.assert_true(rfc::is_disallowed_trailer_field("if-range"), "if-range is forbidden");
        sub.assert_true(rfc::is_disallowed_trailer_field("range"), "range is forbidden");
        sub.assert_true(rfc::is_disallowed_trailer_field(":method"), "pseudo-header :method is forbidden");
        sub.assert_true(rfc::is_disallowed_trailer_field(":path"), "pseudo-header :path is forbidden");
        sub.assert_true(rfc::is_disallowed_trailer_field(":status"), "pseudo-header :status is forbidden");
        sub.assert_true(rfc::is_disallowed_trailer_field(":authority"), "pseudo-header :authority is forbidden");
        sub.assert_true(rfc::is_disallowed_trailer_field("expires"), "expires is forbidden per RFC 9110 §6.5.1");
        sub.assert_true(rfc::is_disallowed_trailer_field("vary"), "vary is forbidden per RFC 9110 §6.5.1");
        sub.assert_true(rfc::is_disallowed_trailer_field("date"), "date is forbidden per RFC 9110 §6.5.1");
        sub.assert_true(rfc::is_disallowed_trailer_field("pragma"), "pragma is forbidden per RFC 9110 §6.5.1");

        // Allowed custom and metadata trailers
        sub.assert_false(rfc::is_disallowed_trailer_field("x-checksum"), "x-checksum is allowed");
        sub.assert_false(rfc::is_disallowed_trailer_field("etag"), "etag is allowed");
        sub.assert_false(rfc::is_disallowed_trailer_field("server-timing"), "server-timing is allowed");
    };

    t.run("RFC 9112 Section 7.1.2: Chunked FSM trailer syntax & colon enforcement") { sub =>
        // Missing colon in trailer line MUST be rejected by FSM
        var dec1 = http_internal::new_chunk_fsm_decoder();
        let st1, _, _ = http_internal::chunk_fsm_feed(dec1, "0\r\nTrailerWithoutColon\r\n\r\n");
        sub.assert_eq(st1, http_internal::ChunkFsmStatus.Error, "Trailer line without colon must return Error");

        // Whitespace before colon in trailer line MUST be rejected (RFC 9112 §5.1 / CVE-2019-16276)
        var dec2 = http_internal::new_chunk_fsm_decoder();
        let st2, _, _ = http_internal::chunk_fsm_feed(dec2, "0\r\nX-Trailer : val\r\n\r\n");
        sub.assert_eq(st2, http_internal::ChunkFsmStatus.Error, "Whitespace before colon in trailer must return Error");
    };

    t.run("Trailer flood protection (> 16 fields or > 4096 bytes)") { sub =>
        var out_body: u8[>..] = [];
        var out_trailers = http::HeaderMap { .. };

        // 17 trailer headers
        var flood: u8[..2048] = "0\r\n";
        for i in 17 {
            flood.append("X-Field-");
            format(flood, i as i64);
            flood.append(": val\r\n");
        }
        flood.append("\r\n");

        let err_flood, _ = http::decode_chunked_body_with_trailers(flood[..], out_body, out_trailers);
        sub.assert_eq(err_flood, http::ChunkedDecodeError.DisallowedTrailer, "17 trailers rejected (exceeds cap of 16)");

        // Massive trailer line > 4096 bytes
        var huge: u8[>..] = [];
        huge.append("0\r\nX-Big: ");
        for i in 4096 {
            huge.push('A');
        }
        huge.append("\r\n\r\n");
        let err_huge, _ = http::decode_chunked_body_with_trailers(huge[..], out_body, out_trailers);
        sub.assert_eq(err_huge, http::ChunkedDecodeError.DisallowedTrailer, "Trailer > 4096 bytes rejected");
    };

    t.run("RFC 9112 Section 7.1: Chunk size 64-bit integer overflow rejection") { sub =>
        var out_body: u8[>..] = [];
        var out_trailers = http::HeaderMap { .. };

        // 1. 0xffffffffffffffff (16 hex digits: 2^64 - 1, signed overflow)
        let raw_max = "FFFFFFFFFFFFFFFF\r\nWiki\r\n0\r\n\r\n";
        let err_max, _ = http::decode_chunked_body_with_trailers(raw_max, out_body, out_trailers);
        sub.assert_eq(err_max, http::ChunkedDecodeError.ChunkSizeOverflow, "0xffffffffffffffff rejected as ChunkSizeOverflow");

        // 2. 0x10000000000000000 (17 hex digits: 2^64 overflow)
        let raw_17 = "10000000000000000\r\nWiki\r\n0\r\n\r\n";
        let err_17, _ = http::decode_chunked_body_with_trailers(raw_17, out_body, out_trailers);
        sub.assert_eq(err_17, http::ChunkedDecodeError.ChunkSizeOverflow, "0x10000000000000000 rejected as ChunkSizeOverflow");

        // 3. 7fffffffffffffff + 1 = 8000000000000000 (16 hex digits: signed i64 overflow)
        let raw_signed = "8000000000000000\r\nWiki\r\n0\r\n\r\n";
        let err_signed, _ = http::decode_chunked_body_with_trailers(raw_signed, out_body, out_trailers);
        sub.assert_eq(err_signed, http::ChunkedDecodeError.ChunkSizeOverflow, "7fffffffffffffff + 1 rejected as ChunkSizeOverflow");

        // Direct parse_chunk_size_hex unit tests
        let _, err_p1 = http::parse_chunk_size_hex("FFFFFFFFFFFFFFFF");
        sub.assert_eq(err_p1, http::ChunkedDecodeError.ChunkSizeOverflow, "parse_chunk_size_hex overflows on FFFFFFFFFFFFFFFF");

        let _, err_p2 = http::parse_chunk_size_hex("10000000000000000");
        sub.assert_eq(err_p2, http::ChunkedDecodeError.ChunkSizeOverflow, "parse_chunk_size_hex overflows on 17 hex digits");

        let _, err_p3 = http::parse_chunk_size_hex("8000000000000000");
        sub.assert_eq(err_p3, http::ChunkedDecodeError.ChunkSizeOverflow, "parse_chunk_size_hex overflows on 8000000000000000");
    };

    t.run("RFC 9112 Section 7.1: Leading zeros in chunk size accepted") { sub =>
        var out_body: u8[>..] = [];
        var out_trailers = http::HeaderMap { .. };

        // Chunk size with leading zeros > 16 characters total, but small value
        let raw_zeros = "00000000000000000004\r\nWiki\r\n00000000000000000000\r\n\r\n";
        let err_zeros, consumed = http::decode_chunked_body_with_trailers(raw_zeros, out_body, out_trailers);
        sub.assert_eq(err_zeros, http::ChunkedDecodeError.None, "Leading zeros in chunk size decoded successfully");
        sub.assert_bytes_eq(out_body[..], "Wiki", "Payload reassembled correctly with leading zeros");
        sub.assert_eq(consumed, raw_zeros.len, "All raw bytes consumed");

        let sz, err_p = http::parse_chunk_size_hex("00000000000000000005");
        sub.assert_eq(err_p, http::ChunkedDecodeError.None, "parse_chunk_size_hex accepts leading zeros");
        sub.assert_eq(sz, 5, "Size parsed as 5");

        let sz0, err_p0 = http::parse_chunk_size_hex("00000000000000000000");
        sub.assert_eq(err_p0, http::ChunkedDecodeError.None, "parse_chunk_size_hex accepts leading zeros for zero");
        sub.assert_eq(sz0, 0, "Size parsed as 0");
    };

    t.run("RFC 9112 Section 7.1.1: Chunked FSM rejects trailing whitespace without extension") { sub =>
        var dec = http_internal::new_chunk_fsm_decoder();
        // Space between chunk-size and CRLF without ';'
        let st_sp, _, _ = http_internal::chunk_fsm_feed(dec, "5 \r\nhello\r\n0\r\n\r\n");
        sub.assert_eq(st_sp, http_internal::ChunkFsmStatus.Error, "Trailing space after chunk-size without extension rejected");

        var dec_tab = http_internal::new_chunk_fsm_decoder();
        // Tab between chunk-size and CRLF without ';'
        let st_tab, _, _ = http_internal::chunk_fsm_feed(dec_tab, "5\t\r\nhello\r\n0\r\n\r\n");
        sub.assert_eq(st_tab, http_internal::ChunkFsmStatus.Error, "Trailing tab after chunk-size without extension rejected");

        // Valid extension with leading space (BWS preceding ';') must still succeed
        var dec_ok = http_internal::new_chunk_fsm_decoder();
        let st_ok, _, slice = http_internal::chunk_fsm_feed(dec_ok, "5 ;ext=1\r\nhello\r\n0\r\n\r\n");
        sub.assert_eq(st_ok, http_internal::ChunkFsmStatus.YieldChunk, "Space before semicolon in valid extension accepted");
        sub.assert_bytes_eq(slice, "hello", "Payload correctly yielded");
    };

    t.run("RFC 9112 Section 7.1.1: Chunked FSM rejects unseparated tokens and post-quote tokens in extensions") { sub =>
        var dec1 = http_internal::new_chunk_fsm_decoder();
        let st1, _, _ = http_internal::chunk_fsm_feed(dec1, "5;ext=val1 val2\r\nhello\r\n0\r\n\r\n");
        sub.assert_eq(st1, http_internal::ChunkFsmStatus.Error, "Unseparated tokens after value must return Error");

        var dec2 = http_internal::new_chunk_fsm_decoder();
        let st2, _, _ = http_internal::chunk_fsm_feed(dec2, "5;ext=\"quoted\"junk\r\nhello\r\n0\r\n\r\n");
        sub.assert_eq(st2, http_internal::ChunkFsmStatus.Error, "Trailing junk after closing quote must return Error");
    };
}

// ----------------------------------------------------------------------------
// 8. Incremental Chunked Stream Decoder (Fragmented & Torture Stream Feeding)
// ----------------------------------------------------------------------------
fn test_incremental_chunked_stream_decoder(t: lit::T&) {
    t.run("Torture 1-byte incremental feeding") { sub =>
        let wire = "5\r\nHello\r\n6\r\n World\r\n0\r\nX-Checksum: c89a\r\n\r\n";
        var dec = client::ChunkedStreamDecoder { .. };
        var stream_out: u8[>..] = [];

        for i in wire.len {
            let one_byte = wire[i..(i + 1)];
            let consumed, ok_step = client::feed_chunked_stream(dec, one_byte, stream_out);
            sub.assert_true(ok_step, "Step ok");
            sub.assert_eq(consumed, 1, "Consumed 1 byte");
        }

        sub.assert_true(client::is_complete(dec), "Decoder reached Complete state");
        sub.assert_false(client::has_error(dec), "No error in decoder");
        sub.assert_bytes_eq(stream_out[..], "Hello World", "Reassembled stream payload");
        sub.assert_eq(dec.trailers.entries.len, 1, "1 trailer extracted");
        sub.assert_bytes_eq(http::entry_name(dec.trailers, dec.trailers.entries[0]), "X-Checksum", "Trailer name");
        sub.assert_bytes_eq(http::entry_value(dec.trailers, dec.trailers.entries[0]), "c89a", "Trailer value");
    };

    t.run("Arbitrary 7-byte chunk slice feeding") { sub =>
        let wire = "A\r\n0123456789\r\n5\r\nABCDE\r\n0\r\n\r\n";
        var dec = client::ChunkedStreamDecoder { .. };
        var stream_out: u8[>..] = [];

        var offset: i64 = 0;
        while offset < wire.len {
            let slice_end = if offset + 7 < wire.len { offset + 7 } else { wire.len };
            let chunk_slice = wire[offset..slice_end];
            let consumed, ok_step = client::feed_chunked_stream(dec, chunk_slice, stream_out);
            sub.assert_true(ok_step, "Feeding slice succeeded");
            sub.assert_eq(consumed, chunk_slice.len, "Full slice consumed");
            offset = slice_end;
        }

        sub.assert_true(client::is_complete(dec), "Decoding completed");
        sub.assert_bytes_eq(stream_out[..], "0123456789ABCDE", "Accurate multi-chunk assembly");
    };

    t.run("Incremental decoder stops on bare LF error") { sub =>
        let wire = "4\nWiki\r\n0\r\n\r\n";
        var dec = client::ChunkedStreamDecoder { .. };
        var stream_out: u8[>..] = [];

        let consumed, ok = client::feed_chunked_stream(dec, wire, stream_out);
        sub.assert_false(ok, "Decoder detected error");
        sub.assert_true(client::has_error(dec), "Has error state");
        sub.assert_eq(dec.error_code, http::ChunkedDecodeError.BareLfInChunkSize, "Bare LF caught incrementally");
    };
}

// ----------------------------------------------------------------------------
// 9. HttpServer Ingress with Chunked Framing & Smuggling Guards
// ----------------------------------------------------------------------------
fn test_httpserver_chunked_ingress(t: lit::T&) {
    t.run("HttpServer handles incoming chunked POST with trailers") { sub =>
        var server = server::new_http_server("127.0.0.1", 8080);
        server::add_post_route(server, "/upload/chunked", 101);

        let wire_req = "POST /upload/chunked HTTP/1.1\r\nHost: localhost\r\nTransfer-Encoding: chunked\r\nTrailer: X-Audit-Id\r\n\r\n5\r\nchunk\r\n0\r\nX-Audit-Id: audit-9988\r\n\r\n";

        var wire_resp: u8[>..] = [];
        let outcome, ok_handled = server::handle_connection_wire(server, "127.0.0.1", wire_req, 1000000000, wire_resp);
        sub.assert_true(ok_handled, "Chunked request handled cleanly");
        sub.assert_eq(outcome, server::PipelineOutcome.Handled, "Pipeline outcome Handled");
        sub.assert_contains(wire_resp[..], "HTTP/1.1 200 OK", "Server returned 200 OK");
    };

    t.run("Smuggling Guard: Dual Transfer-Encoding AND Content-Length rejected") { sub =>
        var server = server::new_http_server("127.0.0.1", 8080);
        server::add_post_route(server, "/api", 102);

        // Smuggling vector: both TE and CL specified
        let smuggled_req = "POST /api HTTP/1.1\r\nHost: localhost\r\nTransfer-Encoding: chunked\r\nContent-Length: 5\r\n\r\n5\r\nhello\r\n0\r\n\r\n";

        var wire_resp: u8[>..] = [];
        let outcome, ok_handled = server::handle_connection_wire(server, "127.0.0.1", smuggled_req, 1000000000, wire_resp);
        sub.assert_false(ok_handled, "Dual TE+CL rejected by server");
        sub.assert_contains(wire_resp[..], "HTTP/1.1 400 Bad Request", "400 Bad Request returned");
    };

    t.run("Smuggling Guard: Conflicting duplicate Content-Length rejected") { sub =>
        var req = http::new_request("POST", "/data");
        let wire = "POST /data HTTP/1.1\r\nHost: localhost\r\nContent-Length: 10\r\nContent-Length: 20\r\n\r\n0123456789";
        let ok, _ = server::parse_http1_wire_request(wire, req);
        sub.assert_false(ok, "Conflicting Content-Length rejected");
    };

    t.run("Smuggling Guard: Invalid Transfer-Encoding coding rejected") { sub =>
        var req = http::new_request("POST", "/data");
        // Unknown transfer coding "compress" as final encoding without chunked
        let wire = "POST /data HTTP/1.1\r\nHost: localhost\r\nTransfer-Encoding: compress\r\n\r\n";
        let ok, _ = server::parse_http1_wire_request(wire, req);
        sub.assert_false(ok, "Non-chunked transfer encoding rejected");
    };

    t.run("Smuggling Guard: RFC 9112 Section 6.1 Unrecognized transfer coding rejected") { sub =>
        var req1 = http::new_request("POST", "/data");
        // Unknown transfer coding preceding chunked
        let wire1 = "POST /data HTTP/1.1\r\nHost: localhost\r\nTransfer-Encoding: bogus, chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n";
        let ok1, _ = server::parse_http1_wire_request(wire1, req1);
        sub.assert_false(ok1, "Transfer-Encoding with unrecognized coding 'bogus' must be rejected");

        // Chunked not final: chunked followed by identity or gzip
        var req2 = http::new_request("POST", "/data");
        let wire2 = "POST /data HTTP/1.1\r\nHost: localhost\r\nTransfer-Encoding: chunked, identity\r\n\r\n";
        let ok2, _ = server::parse_http1_wire_request(wire2, req2);
        sub.assert_false(ok2, "Transfer-Encoding: chunked, identity must be rejected");

        var req3 = http::new_request("POST", "/data");
        let wire3 = "POST /data HTTP/1.1\r\nHost: localhost\r\nTransfer-Encoding: chunked, gzip\r\n\r\n";
        let ok3, _ = server::parse_http1_wire_request(wire3, req3);
        sub.assert_false(ok3, "Transfer-Encoding: chunked, gzip must be rejected");
    };

    t.run("Zero-Copy Header Spans and Wire Extraction") { sub =>
        let wire = "GET /api/v1/resource HTTP/1.1\r\nHost: api.example.com\r\nAuthorization: Bearer test_secret_token_12345\r\nX-Custom-Tag: wing-fast\r\n\r\n";
        var req = http::new_request("", "");
        let ok_parse, consumed = server::parse_http1_wire_request(wire, req);
        sub.assert_true(ok_parse, "Parse succeeded");
        sub.assert_eq(consumed, wire.len, "Consumed entire header block");
        sub.assert_eq(req.headers.entries.len, 3, "Captured 3 headers in HeaderMap");

        sub.assert_bytes_eq(http::header(req, "Host"), "api.example.com", "Extracted Host from HeaderMap");
        sub.assert_bytes_eq(http::header(req, "Authorization"), "Bearer test_secret_token_12345", "Extracted Authorization from HeaderMap");
        sub.assert_bytes_eq(http::header(req, "X-Custom-Tag"), "wing-fast", "Extracted custom header from HeaderMap");
    };
}

// ----------------------------------------------------------------------------
// 10. Server Chunked Response Serialization & Symmetrical Response Wire Parser
// ----------------------------------------------------------------------------
fn test_chunked_response_and_wire_parser(t: lit::T&) {
    t.run("Server response serialization automatically chunks when trailers present") { sub =>
        var res = http::Response { .. };
        res.status_code = 200;
        res.body.append("Streaming payload message");
        http::add_trailer(res, "X-Checksum", "sha256-res-hash");
        http::add_trailer(res, "X-Duration", "12ms");

        var wire_out: u8[>..] = [];
        server::serialize_http1_response(res, "goose-wing/1.0", wire_out);

        sub.assert_contains(wire_out[..], "HTTP/1.1 200 OK\r\n", "Status line");
        sub.assert_contains(wire_out[..], "Transfer-Encoding: chunked\r\n", "Transfer-Encoding: chunked present");
        sub.assert_contains(wire_out[..], "Trailer: X-Checksum, X-Duration\r\n", "Trailer advertisement present");
        sub.assert_contains(wire_out[..], "X-Checksum: sha256-res-hash\r\n", "Trailer emitted in trailer section");
        sub.assert_contains(wire_out[..], "X-Duration: 12ms\r\n", "Second trailer emitted");

        // Parse serialized response with symmetrical parse_http1_wire_response
        var parsed_res = http::Response { .. };
        let ok_parse, consumed = server::parse_http1_wire_response(wire_out[..], parsed_res);
        sub.assert_true(ok_parse, "Wire response parsed cleanly");
        sub.assert_eq(consumed, wire_out.len, "Entire wire stream consumed");
        sub.assert_eq(parsed_res.status_code, 200, "Status is 200");
        sub.assert_bytes_eq(parsed_res.body[..], "Streaming payload message", "Decoded response body");
        sub.assert_true(http::has_trailer(parsed_res, "x-checksum"), "Has x-checksum trailer");
        sub.assert_bytes_eq(http::trailer(parsed_res, "x-checksum"), "sha256-res-hash", "Trailer matches");
        sub.assert_bytes_eq(http::trailer(parsed_res, "x-duration"), "12ms", "Second trailer matches");
    };

    t.run("Fixed-size chunk serialization with encode_chunked_payload") { sub =>
        var body_data: u8[..64] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
        var trs = http::HeaderMap { .. };
        http::append_header(trs, "X-Complete", "true");

        var encoded_wire: u8[>..] = [];
        client::encode_chunked_payload(body_data[..], trs, 10, encoded_wire);

        var parsed_body: u8[>..] = [];
        var parsed_trs = http::HeaderMap { .. };
        let err, consumed = http::decode_chunked_body_with_trailers(encoded_wire[..], parsed_body, parsed_trs);
        sub.assert_eq(err, http::ChunkedDecodeError.None, "Decoded segmented chunks");
        sub.assert_eq(consumed, encoded_wire.len, "Exact bytes consumed");
        sub.assert_bytes_eq(parsed_body[..], "ABCDEFGHIJKLMNOPQRSTUVWXYZ", "Payload fully reconstructed");
        sub.assert_eq(parsed_trs.entries.len, 1, "1 trailer reconstructed");
        sub.assert_bytes_eq(http::entry_name(parsed_trs, parsed_trs.entries[0]), "X-Complete", "Trailer name correct");
        sub.assert_bytes_eq(http::entry_value(parsed_trs, parsed_trs.entries[0]), "true", "Trailer value correct");
    };

    t.run("RFC 9112 Section 6.1: Response wire parser strips Content-Length when chunked present") { sub =>
        let wire_dual = "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nContent-Length: 42\r\n\r\n5\r\nhello\r\n0\r\n\r\n";
        var res = http::Response { .. };
        let ok_parse, consumed = server::parse_http1_wire_response(wire_dual, res);
        sub.assert_true(ok_parse, "Dual TE+CL in response parsed cleanly (TE overrides CL)");
        sub.assert_eq(consumed, wire_dual.len, "Consumed entire dual TE+CL response");
        sub.assert_bytes_eq(res.body[..], "hello", "Body decoded from chunked");
        sub.assert_false(http::has_header(res, "content-length"), "Content-Length header MUST be stripped per RFC 9112 Section 6.1");
        sub.assert_bytes_eq(http::header(res, "Transfer-Encoding"), "chunked", "HeaderMap Transfer-Encoding on Response");
    };
}

// --- Component: http_request_smuggling ---
// Tests for request smuggling defenses and chunked transfer decoding (RFC 9112).

// ----------------------------------------------------------------------------
// 11. TE/CL Request Smuggling & Content-Length Poisoning Defense
// ----------------------------------------------------------------------------
fn test_te_cl_request_smuggling_defense(t: lit::T&) {
    t.run("SMUGGLE-01: Conflicting Transfer-Encoding and Content-Length (TE.CL / CL.TE) Rejection") { sub =>
        // TE then CL
        var map1 = http::HeaderMap { .. };
        let raw_te_cl = "Transfer-Encoding: chunked\r\nContent-Length: 42\r\n\r\n";
        let err1 = http::parse_headers(raw_te_cl, map1);
        sub.assert_eq(err1, http::HeaderParseError.InvalidContentLength, "TE followed by CL must fail with InvalidContentLength per RFC 9112 Section 6.3");
        sub.assert_false(map1.valid, "Map must be marked invalid on TE/CL conflict");

        // CL then TE
        var map2 = http::HeaderMap { .. };
        let raw_cl_te = "Content-Length: 42\r\nTransfer-Encoding: chunked\r\n\r\n";
        let err2 = http::parse_headers(raw_cl_te, map2);
        sub.assert_eq(err2, http::HeaderParseError.InvalidContentLength, "CL followed by TE must fail with InvalidContentLength per RFC 9112 Section 6.3");
        sub.assert_false(map2.valid, "Map must be marked invalid on CL/TE conflict");
    };

    t.run("SMUGGLE-02: Duplicate Differing Content-Length Rejection (CL.CL)") { sub =>
        var map = http::HeaderMap { .. };
        let raw_diff_cl = "Content-Length: 10\r\nContent-Length: 20\r\n\r\n";
        let err = http::parse_headers(raw_diff_cl, map);
        sub.assert_eq(err, http::HeaderParseError.InvalidContentLength, "Duplicate differing Content-Length must be rejected");
        sub.assert_false(map.valid, "Map must be marked invalid on duplicate differing Content-Length");
    };

    t.run("SMUGGLE-03: Negative Content-Length Rejection") { sub =>
        var map = http::HeaderMap { .. };
        let raw_neg = "Content-Length: -5\r\n\r\n";
        let err = http::parse_headers(raw_neg, map);
        sub.assert_eq(err, http::HeaderParseError.InvalidContentLength, "Negative Content-Length must be rejected");
        sub.assert_false(map.valid, "Map must be marked invalid on negative Content-Length");
    };

    t.run("SMUGGLE-04: Non-Digit Characters in Content-Length Rejection") { sub =>
        // Suffix alphanumeric
        var map1 = http::HeaderMap { .. };
        let raw_alpha = "Content-Length: 12abc\r\n\r\n";
        let err1 = http::parse_headers(raw_alpha, map1);
        sub.assert_eq(err1, http::HeaderParseError.InvalidContentLength, "Alpha characters in Content-Length must be rejected");

        // Explicit positive sign '+'
        var map2 = http::HeaderMap { .. };
        let raw_plus = "Content-Length: +10\r\n\r\n";
        let err2 = http::parse_headers(raw_plus, map2);
        sub.assert_eq(err2, http::HeaderParseError.InvalidContentLength, "Plus sign in Content-Length must be rejected");

        // Decimal dot
        var map3 = http::HeaderMap { .. };
        let raw_dot = "Content-Length: 10.5\r\n\r\n";
        let err3 = http::parse_headers(raw_dot, map3);
        sub.assert_eq(err3, http::HeaderParseError.InvalidContentLength, "Decimal dot in Content-Length must be rejected");

        // Empty value
        var map4 = http::HeaderMap { .. };
        let raw_empty = "Content-Length:\r\n\r\n";
        let err4 = http::parse_headers(raw_empty, map4);
        sub.assert_eq(err4, http::HeaderParseError.InvalidContentLength, "Empty Content-Length must be rejected");
    };

    t.run("SMUGGLE-05: Content-Length 64-bit Overflow Rejection") { sub =>
        var map = http::HeaderMap { .. };
        // 30-digit integer overflow
        let raw_ovf = "Content-Length: 999999999999999999999999999999\r\n\r\n";
        let err = http::parse_headers(raw_ovf, map);
        sub.assert_eq(err, http::HeaderParseError.InvalidContentLength, "Overflowing Content-Length must be rejected");
        sub.assert_false(map.valid, "Map must be marked invalid on overflowing Content-Length");
    };

    t.run("SMUGGLE-06: Comma-Separated Differing Content-Length Rejection") { sub =>
        var map = http::HeaderMap { .. };
        let raw_comma = "Content-Length: 15, 30\r\n\r\n";
        let err = http::parse_headers(raw_comma, map);
        sub.assert_eq(err, http::HeaderParseError.InvalidContentLength, "Differing comma-separated Content-Length must be rejected");
    };

    t.run("SMUGGLE-07: Duplicate Transfer-Encoding Headers Rejection") { sub =>
        var map = http::HeaderMap { .. };
        let raw_dup_te = "Transfer-Encoding: chunked\r\nTransfer-Encoding: gzip\r\n\r\n";
        let err = http::parse_headers(raw_dup_te, map);
        sub.assert_eq(err, http::HeaderParseError.InvalidContentLength, "Duplicate Transfer-Encoding headers must be rejected");
    };

    t.run("SMUGGLE-08: Valid Content-Length Acceptance & Identical Duplicate Folding") { sub =>
        // Valid Content-Length: 0
        var map1 = http::HeaderMap { .. };
        let raw_zero = "Content-Length: 0\r\n\r\n";
        let err1 = http::parse_headers(raw_zero, map1);
        sub.assert_eq(err1, http::HeaderParseError.None, "Content-Length: 0 is valid");
        sub.assert_true(map1.valid, "Map must be valid");

        // Valid Content-Length: 1024
        var map2 = http::HeaderMap { .. };
        let raw_valid = "Content-Length: 1024\r\n\r\n";
        let err2 = http::parse_headers(raw_valid, map2);
        sub.assert_eq(err2, http::HeaderParseError.None, "Content-Length: 1024 is valid");
        sub.assert_bytes_eq(http::get_header(map2, "content-length"), "1024", "Header retrieved correctly");

        // Duplicate IDENTICAL Content-Length per RFC 9112 Section 6.3
        var map3 = http::HeaderMap { .. };
        let raw_dup_same = "Content-Length: 42\r\nContent-Length: 42\r\n\r\n";
        let err3 = http::parse_headers(raw_dup_same, map3);
        sub.assert_eq(err3, http::HeaderParseError.None, "Duplicate identical Content-Length must be accepted per RFC 9112 Section 6.3");
        sub.assert_bytes_eq(http::get_header(map3, "content-length"), "42", "Single unified value retrieved");
    };

    t.run("SMUGGLE-09: obs-fold on Content-Length Rejection") { sub =>
        var map = http::HeaderMap { .. };
        // Even in allow_obs_fold=true compatibility mode, obs-fold on Content-Length must be rejected
        let raw_fold_cl = "Content-Length: 10\r\n 20\r\n\r\n";
        let err = http::parse_headers(raw_fold_cl, map, true);
        sub.assert_eq(err, http::HeaderParseError.InvalidContentLength, "obs-fold on Content-Length must be rejected");
        sub.assert_false(map.valid, "Map must be invalid");
    };

    t.run("SMUGGLE-10: Space Before Colon in Header Name Rejection ") { sub =>
        var map1 = http::HeaderMap { .. };
        let raw1 = "Content-Length : 10\r\n\r\n";
        let err1 = http::parse_headers(raw1, map1);
        sub.assert_eq(err1, http::HeaderParseError.InvalidHeaderName, "Space before colon in Content-Length must be rejected per RFC 7230 Section 3.2.4");

        var map2 = http::HeaderMap { .. };
        let raw2 = "Transfer-Encoding : chunked\r\n\r\n";
        let err2 = http::parse_headers(raw2, map2);
        sub.assert_eq(err2, http::HeaderParseError.InvalidHeaderName, "Space before colon in Transfer-Encoding must be rejected");

        var map3 = http::HeaderMap { .. };
        let raw3 = "X-Foo : bar\r\n\r\n";
        let err3 = http::parse_headers(raw3, map3);
        sub.assert_eq(err3, http::HeaderParseError.InvalidHeaderName, "Space before colon in general header must be rejected");
    };

    t.run("SMUGGLE-11: Tab Before Colon in Header Name Rejection") { sub =>
        var map = http::HeaderMap { .. };
        let raw = "Content-Length\t: 10\r\n\r\n";
        let err = http::parse_headers(raw, map);
        sub.assert_eq(err, http::HeaderParseError.InvalidHeaderName, "Tab before colon must be rejected as InvalidHeaderName");
    };

    t.run("SMUGGLE-12: CR or CTL Injection in Transfer-Encoding ") { sub =>
        var map1 = http::HeaderMap { .. };
        let raw1 = "Transfer-Encoding: \rchunked\r\n\r\n";
        let err1 = http::parse_headers(raw1, map1);
        sub.assert_ne(err1, http::HeaderParseError.None, "Bare CR in header splits line into invalid header line without colon");
        sub.assert_false(map1.valid, "Map must be invalid on bare CR injection");

        var map2 = http::HeaderMap { .. };
        let raw2 = "Transfer-Encoding: chunked\x01\r\n\r\n";
        let err2 = http::parse_headers(raw2, map2);
        sub.assert_eq(err2, http::HeaderParseError.InvalidHeaderValue, "CTL character in Transfer-Encoding must be rejected");
        sub.assert_false(map2.valid, "Map must be invalid on CTL injection");
    };

    t.run("SMUGGLE-13: Multiple Identical Content-Length Folded ") { sub =>
        var map = http::HeaderMap { .. };
        let raw = "Content-Length: 128\r\nContent-Length: 128\r\nContent-Length: 128\r\n\r\n";
        let err = http::parse_headers(raw, map);
        sub.assert_eq(err, http::HeaderParseError.None, "Triple identical Content-Length must be accepted per RFC 9112 Section 6.3");
        sub.assert_bytes_eq(http::get_header(map, "content-length"), "128", "Single folded value retrieved");
    };

    t.run("SMUGGLE-14: HTTP/2 Malformed Framing Protection Against Smuggling into HTTP/1 (CVE-2026-78660)") { sub =>
        // Differing comma-separated values
        var map1 = http::HeaderMap { .. };
        let raw1 = "Content-Length: 10, 20\r\n\r\n";
        let err1 = http::parse_headers(raw1, map1);
        sub.assert_eq(err1, http::HeaderParseError.InvalidContentLength, "Differing comma-delimited Content-Length rejected");

        // Duplicate differing values
        var map2 = http::HeaderMap { .. };
        let raw2 = "Content-Length: 0\r\nContent-Length: 5\r\n\r\n";
        let err2 = http::parse_headers(raw2, map2);
        sub.assert_eq(err2, http::HeaderParseError.InvalidContentLength, "Duplicate differing Content-Length rejected");
    };

    t.run("SMUGGLE-15: Content-Length Validation When Transfer-Encoding Present ") { sub =>
        var map1 = http::HeaderMap { .. };
        let raw1 = "Transfer-Encoding: chunked\r\nContent-Length: invalid_num\r\n\r\n";
        let err1 = http::parse_headers(raw1, map1);
        sub.assert_eq(err1, http::HeaderParseError.InvalidContentLength, "TE with invalid CL rejected");

        var map2 = http::HeaderMap { .. };
        let raw2 = "Transfer-Encoding: chunked\r\nContent-Length: 0\r\n\r\n";
        let err2 = http::parse_headers(raw2, map2);
        sub.assert_eq(err2, http::HeaderParseError.InvalidContentLength, "TE with CL:0 rejected");
    };
}

// ----------------------------------------------------------------------------
// 12. Chunked Encoding & Bare LF Smuggling Defense (CVE-2025-22871)
// ----------------------------------------------------------------------------
fn test_chunked_encoding_bare_lf_defense(t: lit::T&) {
    t.run("CHUNK-01: Bare LF in Chunk-Size Line Rejection (CVE-2025-22871)") { sub =>
        var out_body: u8[>..] = [];

        // Bare LF after hex chunk size
        let raw1 = "4\nwiki\r\n0\r\n\r\n";
        let err1 = http::decode_chunked_body(raw1, out_body);
        sub.assert_eq(err1, http::ChunkedDecodeError.BareLfInChunkSize, "Bare LF in chunk size must be rejected per RFC 9112 Section 7.1");
        sub.assert_eq(out_body.len, 0, "No data decoded on bare LF");

        // Bare LF with multi-digit hex
        let raw2 = "1a\nhello_world_test_data\r\n0\r\n\r\n";
        let err2 = http::decode_chunked_body(raw2, out_body);
        sub.assert_eq(err2, http::ChunkedDecodeError.BareLfInChunkSize, "Bare LF in 2-digit hex chunk size must be rejected");

        // Bare LF with chunk extension
        let raw3 = "5;ext=foo\nhello\r\n0\r\n\r\n";
        let err3 = http::decode_chunked_body(raw3, out_body);
        sub.assert_eq(err3, http::ChunkedDecodeError.BareLfInChunkSize, "Bare LF after chunk extension must be rejected");
    };

    t.run("CHUNK-02: Bare LF Ending Chunk-Data Rejection (RFC 9112 Section 7.1)") { sub =>
        var out_body: u8[>..] = [];

        // Valid chunk-size CRLF, but chunk-data terminated by bare LF
        let raw1 = "4\r\nwiki\n0\r\n\r\n";
        let err1 = http::decode_chunked_body(raw1, out_body);
        sub.assert_eq(err1, http::ChunkedDecodeError.BareLfInChunkData, "Bare LF after chunk data must be rejected");

        let raw2 = "5\r\nhello\n0\r\n\r\n";
        let err2 = http::decode_chunked_body(raw2, out_body);
        sub.assert_eq(err2, http::ChunkedDecodeError.BareLfInChunkData, "Bare LF after chunk data must fail with BareLfInChunkData");
    };

    t.run("CHUNK-03: Bare LF in Trailer Lines Rejection ") { sub =>
        var out_body: u8[>..] = [];

        // Last chunk followed by bare LF instead of CRLF
        let raw1 = "0\r\n\n";
        let err1 = http::decode_chunked_body(raw1, out_body);
        sub.assert_eq(err1, http::ChunkedDecodeError.BareLfInTrailer, "Bare LF terminating trailer section must be rejected");

        // Trailer header terminated by bare LF
        let raw2 = "0\r\nX-Checksum: abc\n\r\n";
        let err2 = http::decode_chunked_body(raw2, out_body);
        sub.assert_eq(err2, http::ChunkedDecodeError.BareLfInTrailer, "Bare LF ending trailer header must be rejected");
    };

    t.run("CHUNK-04: Chunk Extensions with CR or CTL Rejection ") { sub =>
        var out_body: u8[>..] = [];

        // Bare CR inside extension
        let raw1 = "4;ext=val\rfoo\r\nwiki\r\n0\r\n\r\n";
        let err1 = http::decode_chunked_body(raw1, out_body);
        sub.assert_eq(err1, http::ChunkedDecodeError.InvalidChunkExtension, "Bare CR in extension must be rejected");

        // Control char inside extension
        let raw2 = "4;ext=\x01\r\nwiki\r\n0\r\n\r\n";
        let err2 = http::decode_chunked_body(raw2, out_body);
        sub.assert_eq(err2, http::ChunkedDecodeError.InvalidChunkExtension, "Control char in extension must be rejected");
    };

    t.run("CHUNK-05: 64-Bit Chunk Size Overflow & Hex Validation") { sub =>
        var out_body: u8[>..] = [];

        // 17-digit hex overflow
        let raw1 = "10000000000000000\r\nfoo\r\n0\r\n\r\n";
        let err1 = http::decode_chunked_body(raw1, out_body);
        sub.assert_true(err1 == http::ChunkedDecodeError.InvalidChunkSizeHex || err1 == http::ChunkedDecodeError.ChunkSizeOverflow, "17-digit chunk size must be rejected");

        // Non-hex characters
        let raw3 = "+5\r\nhello\r\n0\r\n\r\n";
        let err3 = http::decode_chunked_body(raw3, out_body);
        sub.assert_eq(err3, http::ChunkedDecodeError.InvalidChunkSizeHex, "Plus sign in chunk size must be rejected");

        let raw4 = "0x10\r\nhello\r\n0\r\n\r\n";
        let err4 = http::decode_chunked_body(raw4, out_body);
        sub.assert_eq(err4, http::ChunkedDecodeError.InvalidChunkSizeHex, "0x prefix in chunk size must be rejected");

        let raw5 = "xyz\r\nhello\r\n0\r\n\r\n";
        let err5 = http::decode_chunked_body(raw5, out_body);
        sub.assert_eq(err5, http::ChunkedDecodeError.InvalidChunkSizeHex, "Non-hex characters in chunk size must be rejected");
    };

    t.run("CHUNK-06: Disallowed Trailer Smuggling Defenses (RFC 9112 Section 7.1.2)") { sub =>
        var out_body: u8[>..] = [];

        // Content-Length in trailer (framing conflict smuggling)
        let raw1 = "4\r\ntest\r\n0\r\nContent-Length: 10\r\n\r\n";
        let err1 = http::decode_chunked_body(raw1, out_body);
        sub.assert_eq(err1, http::ChunkedDecodeError.DisallowedTrailer, "Content-Length in trailer must be rejected");

        // Transfer-Encoding in trailer
        let raw2 = "4\r\ntest\r\n0\r\nTransfer-Encoding: chunked\r\n\r\n";
        let err2 = http::decode_chunked_body(raw2, out_body);
        sub.assert_eq(err2, http::ChunkedDecodeError.DisallowedTrailer, "Transfer-Encoding in trailer must be rejected");

        // Trailer header in trailer
        let raw3 = "4\r\ntest\r\n0\r\nTrailer: foo\r\n\r\n";
        let err3 = http::decode_chunked_body(raw3, out_body);
        sub.assert_eq(err3, http::ChunkedDecodeError.DisallowedTrailer, "Trailer header in trailer must be rejected");

        // Authorization in trailer (security bypass)
        let raw4 = "4\r\ntest\r\n0\r\nAuthorization: Bearer evil\r\n\r\n";
        let err4 = http::decode_chunked_body(raw4, out_body);
        sub.assert_eq(err4, http::ChunkedDecodeError.DisallowedTrailer, "Authorization in trailer must be rejected");

        // Set-Cookie in trailer
        let raw5 = "4\r\ntest\r\n0\r\nSet-Cookie: session=smuggled\r\n\r\n";
        let err5 = http::decode_chunked_body(raw5, out_body);
        sub.assert_eq(err5, http::ChunkedDecodeError.DisallowedTrailer, "Set-Cookie in trailer must be rejected");

        // Content-Range in trailer
        let raw6 = "4\r\ntest\r\n0\r\nContent-Range: bytes 0-10/100\r\n\r\n";
        let err6 = http::decode_chunked_body(raw6, out_body);
        sub.assert_eq(err6, http::ChunkedDecodeError.DisallowedTrailer, "Content-Range in trailer must be rejected");
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

        let err = http::decode_chunked_body(flood_buf[..], out_body);
        sub.assert_eq(err, http::ChunkedDecodeError.DisallowedTrailer, "More than 16 trailer fields must be rejected");
    };

    t.run("CHUNK-09: Trailer Total Byte Length Bomb Defense") { sub =>
        var out_body: u8[>..] = [];
        var huge_tr:  u8[>..] = [];
        huge_tr.append("4\r\ntest\r\n0\r\nX-Giant-Trailer: ");
        for _ in 4500 {
            huge_tr.push('A');
        }
        huge_tr.append("\r\n\r\n");

        let err = http::decode_chunked_body(huge_tr[..], out_body);
        sub.assert_eq(err, http::ChunkedDecodeError.DisallowedTrailer, "Trailer exceeding 4096 bytes must be rejected");
    };

    t.run("CHUNK-07: Valid Chunked Body Decoding & Multi-Chunk Reassembly") { sub =>
        // Standard single chunk
        var body1: u8[>..] = [];
        let raw1 = "4\r\nwiki\r\n0\r\n\r\n";
        let err1 = http::decode_chunked_body(raw1, body1);
        sub.assert_eq(err1, http::ChunkedDecodeError.None, "Standard chunk decoded cleanly");
        sub.assert_bytes_eq(body1[..], "wiki", "Decoded data matches expected");

        // Multi-chunk sequence
        var body2: u8[>..] = [];
        let raw2 = "5\r\nHello\r\n1\r\n \r\n5\r\nWorld\r\n0\r\n\r\n";
        let err2 = http::decode_chunked_body(raw2, body2);
        sub.assert_eq(err2, http::ChunkedDecodeError.None, "Multi-chunk decoded cleanly");
        sub.assert_bytes_eq(body2[..], "Hello World", "Reassembled message matches expected");

        // Chunk with valid extension
        var body3: u8[>..] = [];
        let raw3 = "4;token=123\r\ntest\r\n0\r\n\r\n";
        let err3 = http::decode_chunked_body(raw3, body3);
        sub.assert_eq(err3, http::ChunkedDecodeError.None, "Chunk with extension decoded cleanly");
        sub.assert_bytes_eq(body3[..], "test", "Data after extension parsed accurately");

        // Chunk with allowed trailer
        var body4: u8[>..] = [];
        let raw4 = "4\r\ndata\r\n0\r\nX-Checksum: 12345\r\n\r\n";
        let err4 = http::decode_chunked_body(raw4, body4);
        sub.assert_eq(err4, http::ChunkedDecodeError.None, "Chunk with custom trailer decoded cleanly");
        sub.assert_bytes_eq(body4[..], "data", "Payload decoded cleanly");
    };
}

// ----------------------------------------------------------------------------
// 13. Hop-by-Hop Header Stripping & Gateway Isolation (RFC 9110 Section 7.6.1)
// ----------------------------------------------------------------------------
fn test_hop_by_hop_stripping_defense(t: lit::T&) {
    t.run("HOP-01: Standard Hop-by-Hop Headers Stripped (RFC 9110 Section 7.6.1)") { sub =>
        var src = http::HeaderMap { .. };
        let raw = "Host: example.com\r\nConnection: close\r\nKeep-Alive: timeout=5, max=100\r\nProxy-Authenticate: Basic\r\nProxy-Authorization: Basic abc\r\nTE: gzip\r\nTrailer: X-Checksum\r\nTransfer-Encoding: chunked\r\nUpgrade: websocket\r\nProxy-Connection: keep-alive\r\nContent-Type: application/json\r\nAuthorization: Bearer token123\r\n\r\n";
        let p_err = http::parse_headers(raw, src);
        sub.assert_eq(p_err, http::HeaderParseError.None, "Source headers parsed ok");

        var dst = http::HeaderMap { .. };
        http::strip_hop_by_hop_headers(src, dst);

        // Verify hop-by-hop headers are completely absent
        sub.assert_false(http::has_header(dst, "connection"), "Connection must be stripped");
        sub.assert_false(http::has_header(dst, "keep-alive"), "Keep-Alive must be stripped");
        sub.assert_false(http::has_header(dst, "proxy-authenticate"), "Proxy-Authenticate must be stripped");
        sub.assert_false(http::has_header(dst, "proxy-authorization"), "Proxy-Authorization must be stripped");
        sub.assert_false(http::has_header(dst, "te"), "TE must be stripped");
        sub.assert_false(http::has_header(dst, "trailer"), "Trailer must be stripped");
        sub.assert_false(http::has_header(dst, "transfer-encoding"), "Transfer-Encoding must be stripped");
        sub.assert_false(http::has_header(dst, "upgrade"), "Upgrade must be stripped");
        sub.assert_false(http::has_header(dst, "proxy-connection"), "Proxy-Connection must be stripped");

        // Verify end-to-end headers are preserved
        sub.assert_true(http::has_header(dst, "host"), "Host must be preserved");
        sub.assert_true(http::has_header(dst, "content-type"), "Content-Type must be preserved");
        sub.assert_true(http::has_header(dst, "authorization"), "Authorization must be preserved");
        sub.assert_bytes_eq(http::get_header(dst, "authorization"), "Bearer token123", "Authorization value intact");
    };

    t.run("HOP-02: Dynamic Custom Tokens in Connection Header (RFC 9110 Section 7.6.1)") { sub =>
        var src = http::HeaderMap { .. };
        let raw = "Host: api.internal\r\nConnection: close, X-Custom-Hop, X-Internal-Token\r\nX-Custom-Hop: sensitive_gateway_data\r\nX-Internal-Token: secret999\r\nX-Preserve-Me: public_data\r\n\r\n";
        http::parse_headers(raw, src);

        var dst = http::HeaderMap { .. };
        http::strip_hop_by_hop_headers(src, dst);

        sub.assert_false(http::has_header(dst, "connection"), "Connection header stripped");
        sub.assert_false(http::has_header(dst, "x-custom-hop"), "X-Custom-Hop dynamically stripped");
        sub.assert_false(http::has_header(dst, "x-internal-token"), "X-Internal-Token dynamically stripped");
        sub.assert_true(http::has_header(dst, "x-preserve-me"), "X-Preserve-Me preserved");
        sub.assert_bytes_eq(http::get_header(dst, "x-preserve-me"), "public_data", "Value intact");
    };

    t.run("HOP-03: Empty Connection Header Does Not Block Subsequent Stripping ") { sub =>
        var src = http::HeaderMap { .. };
        // First Connection header is empty, second specifies sensitive custom header
        let raw = "Host: example.com\r\nConnection:\r\nConnection: close, X-Secret-Hop\r\nX-Secret-Hop: leaked_token\r\nContent-Type: text/plain\r\n\r\n";
        http::parse_headers(raw, src);

        var dst = http::HeaderMap { .. };
        http::strip_hop_by_hop_headers(src, dst);

        sub.assert_false(http::has_header(dst, "connection"), "Connection headers stripped");
        sub.assert_false(http::has_header(dst, "x-secret-hop"), "X-Secret-Hop stripped despite empty first Connection header");
        sub.assert_true(http::has_header(dst, "content-type"), "Content-Type preserved");
    };

    t.run("HOP-04: Multiple Comma-Separated Connection Headers ") { sub =>
        var src = http::HeaderMap { .. };
        // Multiple Connection headers with multiple tokens
        let raw = "Host: example.com\r\nConnection: keep-alive, X-Hop-One\r\nConnection: X-Hop-Two, X-Hop-Three\r\nX-Hop-One: v1\r\nX-Hop-Two: v2\r\nX-Hop-Three: v3\r\nX-Retained: keep_this\r\n\r\n";
        http::parse_headers(raw, src);

        var dst = http::HeaderMap { .. };
        http::strip_hop_by_hop_headers(src, dst);

        sub.assert_false(http::has_header(dst, "x-hop-one"), "X-Hop-One stripped");
        sub.assert_false(http::has_header(dst, "x-hop-two"), "X-Hop-Two stripped");
        sub.assert_false(http::has_header(dst, "x-hop-three"), "X-Hop-Three stripped");
        sub.assert_true(http::has_header(dst, "x-retained"), "X-Retained preserved");
    };

    t.run("HOP-05: Case-Insensitive & Whitespace-Tolerant Token Stripping") { sub =>
        var src = http::HeaderMap { .. };
        let raw = "Host: example.com\r\nConnection: \t  x-foo  ,\t X-BAR \t\r\nX-FOO: val1\r\nx-bar: val2\r\nX-Normal: val3\r\n\r\n";
        http::parse_headers(raw, src);

        var dst = http::HeaderMap { .. };
        http::strip_hop_by_hop_headers(src, dst);

        sub.assert_false(http::has_header(dst, "x-foo"), "X-FOO stripped case-insensitively");
        sub.assert_false(http::has_header(dst, "x-bar"), "x-bar stripped case-insensitively");
        sub.assert_true(http::has_header(dst, "x-normal"), "X-Normal retained");
    };

    t.run("HOP-06: Hop-by-Hop Stripping on 1xx Informational Responses (CVE-2021-33197)") { sub =>
        var src_1xx = http::HeaderMap { .. };
        let raw_1xx = "Link: </style.css>; rel=preload\r\nConnection: close, X-Early-Hop\r\nX-Early-Hop: forbidden_hint\r\nKeep-Alive: timeout=10\r\n\r\n";
        http::parse_headers(raw_1xx, src_1xx);

        var dst_1xx = http::HeaderMap { .. };
        http::strip_hop_by_hop_headers(src_1xx, dst_1xx);

        sub.assert_true(http::has_header(dst_1xx, "link"), "Link header retained on 1xx");
        sub.assert_false(http::has_header(dst_1xx, "connection"), "Connection stripped on 1xx");
        sub.assert_false(http::has_header(dst_1xx, "keep-alive"), "Keep-Alive stripped on 1xx");
        sub.assert_false(http::has_header(dst_1xx, "x-early-hop"), "Custom hop token stripped on 1xx");
    };
}

// ----------------------------------------------------------------------------
// 14. URL Path Backtrack Quadratic Complexity Defense (CVE-2026-56860)
// ----------------------------------------------------------------------------
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

// ----------------------------------------------------------------------------
// 15. SFV Integer & Decimal 64-Bit Overflow Protection
// ----------------------------------------------------------------------------
fn test_sfv_integer_overflow_guard(t: lit::T&) {
    t.run("SFV-01: RFC 8941 Section 3.3.1 19+ Digit Integer Accumulation Overflow Guard") { sub =>
        var item = http::SfvItem { .. };

        // 19-digit number exceeding signed 64-bit int max (9223372036854775808)
        let ok1 = http::parse_sfv_item("9223372036854775808", item);
        sub.assert_false(ok1, "19-digit number exceeding i64 max must be rejected");

        // 20-digit number
        let ok2 = http::parse_sfv_item("10000000000000000000", item);
        sub.assert_false(ok2, "20-digit number must be rejected immediately without overflow");

        // 35-digit giant number
        let ok3 = http::parse_sfv_item("99999999999999999999999999999999999", item);
        sub.assert_false(ok3, "Giant digit string must be rejected cleanly");

        // Negative 20-digit number
        let ok4 = http::parse_sfv_item("-10000000000000000000", item);
        sub.assert_false(ok4, "Negative 20-digit number must be rejected cleanly");
    };

    t.run("SFV-02: RFC 8941 Section 3.3.2 19+ Digit Decimal Accumulation Overflow Guard") { sub =>
        var item = http::SfvItem { .. };

        // 20 integer digits before decimal dot
        let ok1 = http::parse_sfv_item("10000000000000000000.5", item);
        sub.assert_false(ok1, "20-digit integer part in decimal must be rejected without overflow");

        // 30 integer digits before decimal dot
        let ok2 = http::parse_sfv_item("999999999999999999999999999999.123", item);
        sub.assert_false(ok2, "Giant decimal integer part must be rejected cleanly");
    };
}

// --- Component: http_status_diagnostics ---
// Verification suite for RFC 9211 (Cache-Status) and RFC 9209 (Proxy-Status):
// - RFC 9211 Cache-Status header parsing (hit, stored, collapsed, ttl, fwd, key, detail)
// - RFC 9211 formatting and roundtrip verification
// - RFC 9209 Proxy-Status header parsing (error, next-hop, details, received-status)
// - RFC 9209 formatting and multi-proxy hop chains

// ----------------------------------------------------------------------------
// 16. RFC 9211 Cache-Status
// ----------------------------------------------------------------------------
fn test_cache_status_rfc9211(t: lit::T&) {
    t.run("Parse Single & Multi-Cache Status") { sub =>
        let raw = "OriginCache; hit; ttl=120; key=\"asset-hash-123\"; detail=\"memory\", EdgeCache; stored; fwd=stale; fwd-status=200";
        var entries: http::CacheStatusEntry[..8] = [];
        let count = http::parse_cache_status_header(raw, entries);
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
        var entry = http::CacheStatusEntry {
            hit: true,
            ttl: 300,
            ..
        };
        entry.cache_name.append("CDN-Fastly");
        entry.key.append("page-v2");

        var out: u8[..256] = [];
        http::format_cache_status(entry, out);
        sub.assert_contains(out[..], "CDN-Fastly; hit; ttl=300; key=\"page-v2\"", "Formatted matches RFC 9211");
    };
}

// ----------------------------------------------------------------------------
// 17. RFC 9209 Proxy-Status
// ----------------------------------------------------------------------------
fn test_proxy_status_rfc9209(t: lit::T&) {
    t.run("Parse Proxy Error Status") { sub =>
        let raw = "edge-us-east; error=connection_refused; next-hop=\"10.0.1.5\"; details=\"TCP SYN reset by peer\"; received-status=502";
        var entries: http::ProxyStatusEntry[..8] = [];
        let count = http::parse_proxy_status_header(raw, entries);
        sub.assert_eq(count, 1, "Parsed 1 proxy status");

        sub.assert_bytes_eq(entries[0].proxy_name[..], "edge-us-east", "Proxy name matches");
        sub.assert_bytes_eq(entries[0].error_type[..], "connection_refused", "Error type is connection_refused");
        sub.assert_bytes_eq(entries[0].next_hop[..], "10.0.1.5", "Next hop matches");
        sub.assert_bytes_eq(entries[0].details[..], "TCP SYN reset by peer", "Details match");
        sub.assert_eq(entries[0].received_status, 502, "Received status is 502");
    };

    t.run("Format Proxy Status") { sub =>
        var entry = http::ProxyStatusEntry {
            received_status: 504,
            ..
        };
        entry.proxy_name.append("gateway-ingress");
        entry.error_type.append("connection_timeout");
        entry.next_hop.append("origin.internal");

        var out: u8[..256] = [];
        http::format_proxy_status(entry, out);
        sub.assert_contains(out[..], "gateway-ingress; error=connection_timeout", "Formatted error");
        sub.assert_contains(out[..], "next-hop=\"origin.internal\"", "Formatted next-hop");
        sub.assert_contains(out[..], "received-status=504", "Formatted received-status");
    };
}

// --- Component: http_extensions_invariants ---
// Security invariant tests for HTTP Extensions:
// 1. Resumable Upload (draft-ietf-httpbis-resumable-upload-14) Structured Fields & Bounds
// 2. Early Hints (RFC 8297) & RFC 8288 Link header invariants

// ----------------------------------------------------------------------------
// 18. Resumable Upload Structured Fields
// ----------------------------------------------------------------------------
fn test_resumable_upload_structured_fields(t: lit::T&) {
    // 1. Integer parsing (non-negative integer enforcement)
    let n1, ok1 = http::parse_upload_int("0");
    t.assert_true(ok1, "0 is valid integer");
    t.assert_eq(n1, 0, "value is 0");

    let n2, ok2 = http::parse_upload_int("   65536   ");
    t.assert_true(ok2, "trimmed 65536 is valid integer");
    t.assert_eq(n2, 65536, "value is 65536");

    let _, ok_neg = http::parse_upload_int("-1");
    t.assert_false(ok_neg, "negative integer must be rejected");

    let _, ok_bad = http::parse_upload_int("abc");
    t.assert_false(ok_bad, "alphanumeric string must be rejected");

    // 2. RFC 8941 Structured Field boolean parsing
    let b1, ok_b1 = http::parse_upload_boolean("?1");
    t.assert_true(ok_b1, "?1 is valid boolean");
    t.assert_true(b1, "value is true");

    let b2, ok_b2 = http::parse_upload_boolean("?0");
    t.assert_true(ok_b2, "?0 is valid boolean");
    t.assert_false(b2, "value is false");

    let b3, ok_b3 = http::parse_upload_boolean("?1; foo=bar");
    t.assert_true(ok_b3, "?1 with parameter is valid");
    t.assert_true(b3, "value is true");

    let _, ok_b4 = http::parse_upload_boolean("?1bad");
    t.assert_false(ok_b4, "?1bad must be rejected as boolean");

    let _, ok_b5 = http::parse_upload_boolean("true");
    t.assert_false(ok_b5, "unstructured 'true' must be rejected");
}

// ----------------------------------------------------------------------------
// 19. Early Hints Link Header Security
// ----------------------------------------------------------------------------
fn test_early_hints_link_header_security(t: lit::T&) {
    // 1. Standard Link preload
    var links1: http::EarlyHintLink[..4] = [];
    let ok1 = http::parse_link_header("<https://cdn.example.com/main.js>; rel=preload; as=script", links1);
    t.assert_true(ok1, "valid link header parse");
    t.assert_eq(links1.len, 1, "parsed 1 link");
    t.assert_true(links1[0].uri[..] == "https://cdn.example.com/main.js", "uri matches");
    t.assert_true(links1[0].rel[..] == "preload", "rel matches");
    t.assert_true(links1[0].as_type[..] == "script", "as matches");

    // 2. Link with commas inside query string (must NOT split entry!)
    var links2: http::EarlyHintLink[..4] = [];
    let ok2 = http::parse_link_header("<https://cdn.example.com/bundle.js?v=1,2,3>; rel=preload; as=script", links2);
    t.assert_true(ok2, "uri with comma in query string must not break link parsing");
    t.assert_eq(links2.len, 1, "parsed exactly 1 link");
    t.assert_true(links2[0].uri[..] == "https://cdn.example.com/bundle.js?v=1,2,3", "query string with comma preserved");

    // 3. Case-insensitive parameters (RFC 8288 Section 3.2)
    var links3: http::EarlyHintLink[..4] = [];
    let ok3 = http::parse_link_header("<https://cdn.example.com/font.woff2>; REL=preload; AS=font; CrossOrigin", links3);
    t.assert_true(ok3, "case-insensitive param matching");
    t.assert_eq(links3.len, 1, "parsed 1 link");
    t.assert_true(links3[0].rel[..] == "preload", "rel matches");
    t.assert_true(links3[0].as_type[..] == "font", "as matches");
    t.assert_true(links3[0].crossorigin, "crossorigin set");

    // 4. Reject empty URI `<>`
    var links_bad1: http::EarlyHintLink[..4] = [];
    let ok_bad1 = http::parse_link_header("<>; rel=preload", links_bad1);
    t.assert_false(ok_bad1, "empty URI <> must be rejected");

    // 5. Reject characters between `>` and `;`
    var links_bad2: http::EarlyHintLink[..4] = [];
    let ok_bad2 = http::parse_link_header("<https://example.com>invalid; rel=preload", links_bad2);
    t.assert_false(ok_bad2, "characters between > and ; must be rejected");
}

// ----------------------------------------------------------------------------
// 20. HeaderMap In-Place Compaction & Overwrite
// ----------------------------------------------------------------------------
fn test_headermap_inplace_compaction_and_overwrite(t: lit::T&) {
    var map = http::HeaderMap { .. };
    t.require_true(http::insert_header(map, "Host", "example.com"));
    t.require_true(http::insert_header(map, "Authorization", "Bearer initial_long_secret_token_value_1234567890"));
    t.require_true(http::insert_header(map, "X-Custom", "after-auth"));
    let initial_len = map.raw_buf.len;

    // 1. Shorter in-place overwrite shifts tail immediately without slack bytes
    t.require_true(http::insert_header(map, "Authorization", "Bearer short"));
    t.assert_lt(map.raw_buf.len, initial_len, "raw_buf shrinks immediately on shorter overwrite");
    t.assert_bytes_eq(http::get_header(map, "Authorization"), "Bearer short", "Overwritten value matches");
    t.assert_bytes_eq(http::get_header(map, "X-Custom"), "after-auth", "Tail entry shifted cleanly");

    // 2. Repeated remove + insert cycles never exhaust raw_buf
    for i in 0..500 {
        t.require_true(http::remove_header(map, "Authorization"));
        t.require_true(http::insert_header(map, "Authorization", "Bearer rotating_hop_token_value_abcdef_0123456789"));
        t.require_true(http::set_or_replace(map, "X-Custom", "updated-val"));
    }
    t.assert_lt(map.raw_buf.len, 256, "raw_buf remains compact after 500 mutation cycles");
    t.assert_bytes_eq(http::get_header(map, "Host"), "example.com", "Host preserved");
    t.assert_bytes_eq(http::get_header(map, "X-Custom"), "updated-val", "X-Custom preserved");
}

// ----------------------------------------------------------------------------
// 21. Single Header Cursor
// ----------------------------------------------------------------------------
fn test_single_header_cursor(t: lit::T&) {
    t.run("Single Well-Known Header") { sub =>
        var map = http::HeaderMap {};
        let ok1 = map.append_header("Host", "example.com");
        sub.assert_true(ok1, "append Host succeeds");

        var cursor: i64 = 0;
        let val, ok = http::next_header_value(map, "", "Host", cursor);
        sub.assert_true(ok, "first Host found");
        sub.assert_eq(val, "example.com", "value matches");
        sub.assert_eq(cursor, -1, "cursor terminates at -1 for single entry");

        let val_end, ok_end = http::next_header_value(map, "", "Host", cursor);
        sub.assert_false(ok_end, "terminal call returns false");
        sub.assert_eq(val_end, "", "exhausted value is empty");
        sub.assert_eq(cursor, -1, "cursor remains -1");
    };

    t.run("Single Custom Header") { sub =>
        var map = http::HeaderMap {};
        let ok1 = map.append_header("X-Request-Id", "req-12345");
        sub.assert_true(ok1, "append custom succeeds");

        var cursor: i64 = 0;
        let val, ok = http::next_header_value(map, "", "X-Request-Id", cursor);
        sub.assert_true(ok, "custom header found");
        sub.assert_eq(val, "req-12345", "value matches");
        sub.assert_eq(cursor, -1, "cursor terminates at -1");
    };

    t.run("Non-Existent Header") { sub =>
        var map = http::HeaderMap {};
        map.append_header("Host", "example.com");

        var cursor: i64 = 0;
        let val, ok = http::next_header_value(map, "", "Authorization", cursor);
        sub.assert_false(ok, "non-existent header returns false");
        sub.assert_eq(val, "", "empty return");
        sub.assert_eq(cursor, -1, "cursor set to -1");

        // Custom non-existent
        var cursor2: i64 = 0;
        let val2, ok2 = http::next_header_value(map, "", "X-Missing", cursor2);
        sub.assert_false(ok2, "non-existent custom returns false");
        sub.assert_eq(val2, "", "empty return");
        sub.assert_eq(cursor2, -1, "cursor set to -1");
    };
}

// ----------------------------------------------------------------------------
// 22. Multi-Value Header Cursor
// ----------------------------------------------------------------------------
fn test_multi_value_header_cursor(t: lit::T&) {
    t.run("Multi-Value Well-Known Set-Cookie Chain") { sub =>
        var map = http::HeaderMap {};
        map.append_header("Host", "example.com");
        map.append_header("Set-Cookie", "session=abc; Path=/; Secure");
        map.append_header("Content-Type", "text/html");
        map.append_header("Set-Cookie", "theme=dark; Path=/");
        map.append_header("Set-Cookie", "experiment=variant_b; Path=/");

        var cursor: i64 = 0;

        // 1st Set-Cookie
        let val1, ok1 = http::next_header_value(map, "", "Set-Cookie", cursor);
        sub.assert_true(ok1, "1st Set-Cookie found");
        sub.assert_eq(val1, "session=abc; Path=/; Secure");
        sub.assert_true(cursor >= 0, "cursor advances to next index");

        // 2nd Set-Cookie
        let val2, ok2 = http::next_header_value(map, "", "Set-Cookie", cursor);
        sub.assert_true(ok2, "2nd Set-Cookie found");
        sub.assert_eq(val2, "theme=dark; Path=/");
        sub.assert_true(cursor >= 0, "cursor advances to 3rd index");

        // 3rd Set-Cookie
        let val3, ok3 = http::next_header_value(map, "", "Set-Cookie", cursor);
        sub.assert_true(ok3, "3rd Set-Cookie found");
        sub.assert_eq(val3, "experiment=variant_b; Path=/");
        sub.assert_eq(cursor, -1, "cursor terminates at -1");

        // Terminal
        let val4, ok4 = http::next_header_value(map, "", "Set-Cookie", cursor);
        sub.assert_false(ok4, "terminal return is false");
        sub.assert_eq(cursor, -1, "cursor remains -1");
    };

    t.run("Multi-Value Custom Header Chain") { sub =>
        var map = http::HeaderMap {};
        map.append_header("X-Forwarded-For", "192.168.1.1");
        map.append_header("Server", "goose-wing");
        map.append_header("X-Forwarded-For", "10.0.0.1");
        map.append_header("X-Forwarded-For", "172.16.0.1");

        var cursor: i64 = 0;

        let val1, ok1 = http::next_header_value(map, "", "x-forwarded-for", cursor);
        sub.assert_true(ok1, "case-insensitive 1st found");
        sub.assert_eq(val1, "192.168.1.1");

        let val2, ok2 = http::next_header_value(map, "", "X-FORWARDED-FOR", cursor);
        sub.assert_true(ok2, "case-insensitive 2nd found");
        sub.assert_eq(val2, "10.0.0.1");

        let val3, ok3 = http::next_header_value(map, "", "X-Forwarded-For", cursor);
        sub.assert_true(ok3, "case-insensitive 3rd found");
        sub.assert_eq(val3, "172.16.0.1");
        sub.assert_eq(cursor, -1, "terminal cursor -1");

        let _, ok4 = http::next_header_value(map, "", "X-Forwarded-For", cursor);
        sub.assert_false(ok4, "terminal exhausted");
    };

    t.run("Empty Header Value") { sub =>
        var map = http::HeaderMap {};
        map.append_header("X-Empty-Flag", "");

        var cursor: i64 = 0;
        let val, ok = http::next_header_value(map, "", "X-Empty-Flag", cursor);
        sub.assert_true(ok, "empty header value is found with ok=true");
        sub.assert_eq(val, "", "value slice is empty string");
        sub.assert_eq(cursor, -1, "cursor terminates at -1");
    };
}

// ----------------------------------------------------------------------------
// F002: Status Diagnostics Bounds and Safety
// ----------------------------------------------------------------------------
// ----------------------------------------------------------------------------
// 23. F002 Status Diagnostics Bounds & Safety
// ----------------------------------------------------------------------------
fn test_f002_status_diagnostics_bounds_and_safety(t: lit::T&) {
    t.run("parse_cache_status_header rejects unclosed quoted string") { sub =>
        var entries: http::CacheStatusEntry[..8] = [];
        let count = http::parse_cache_status_header("OriginCache; key=\"unclosed", entries);
        sub.assert_eq(count, 0, "Unclosed quote in Cache-Status MUST fail parsing rather than consuming to EOF");
    };

    t.run("parse_cache_status_header rejects fwd > 32 bytes without abort") { sub =>
        var raw: u8[..128] = [];
        raw.append("OriginCache; fwd=");
        for i in 50 { raw.push('x'); }

        var entries: http::CacheStatusEntry[..8] = [];
        let count = http::parse_cache_status_header(raw[..], entries);
        sub.assert_eq(count, 0, "fwd > 32B MUST be rejected and not abort on entry.fwd.append");
    };

    t.run("parse_cache_status_header rejects non-numeric fwd-status without wrapping") { sub =>
        var entries: http::CacheStatusEntry[..8] = [];
        let count = http::parse_cache_status_header("OriginCache; fwd-status=invalid", entries);
        sub.assert_eq(count, 0, "Invalid fwd-status MUST fail rather than setting fwd_status=0 via discarded tuple error");
    };

    t.run("parse_proxy_status_header rejects error > 64 bytes without abort") { sub =>
        var raw: u8[..128] = [];
        raw.append("edge1; error=");
        for i in 80 { raw.push('e'); }

        var entries: http::ProxyStatusEntry[..8] = [];
        let count = http::parse_proxy_status_header(raw[..], entries);
        sub.assert_eq(count, 0, "error > 64B MUST be rejected and not abort on entry.error_type.append");
    };
}

// ----------------------------------------------------------------------------
// F005: SFV Zero Silent Drops (Invariant 13)
// ----------------------------------------------------------------------------
// ----------------------------------------------------------------------------
// 24. F005 SFV Zero Silent Drops (Invariant 13)
// ----------------------------------------------------------------------------
fn test_f005_sfv_no_silent_dropping(t: lit::T&) {
    t.run("parse_sf_dict rejects dictionaries with > 16 entries") { sub =>
        var raw: u8[..512] = [];
        for i in 17 {
            if i > 0 { raw.append(", "); }
            raw.append("k");
            format(raw, i);
            raw.append("=1");
        }

        var entries: http::SfDictEntry[..16] = [];
        let ok = http::parse_sf_dict(raw[..], entries);
        sub.assert_false(ok, "parse_sf_dict MUST return false on > 16 entries rather than silently dropping 17th");
    };

    t.run("parse_sf_list rejects lists with > 16 items") { sub =>
        var raw: u8[..512] = [];
        for i in 17 {
            if i > 0 { raw.append(", "); }
            raw.append("item");
            format(raw, i);
        }

        var items: http::SfParameterizedItem[..16] = [];
        let ok = http::parse_sf_list(raw[..], items);
        sub.assert_false(ok, "parse_sf_list MUST return false on > 16 items rather than silently dropping 17th");
    };

    t.run("sf_parse_inner_list rejects inner lists with > 8 items") { sub =>
        var raw: u8[..512] = "endpoints=(";
        for i in 9 {
            if i > 0 { raw.push(' '); }
            raw.append("srv");
            format(raw, i);
        }
        raw.push(')');

        var entries: http::SfDictEntry[..16] = [];
        let ok = http::parse_sf_dict(raw[..], entries);
        sub.assert_false(ok, "Inner list > 8 items MUST return false rather than silently dropping 9th");
    };
}

// ----------------------------------------------------------------------------
// F010: HeaderMap Overflow Spill Smuggling, Obs-Fold & get_combined Bounds
// ----------------------------------------------------------------------------
// ----------------------------------------------------------------------------
// 25. F010 HeaderMap Overflow Spill Smuggling & Bounds
// ----------------------------------------------------------------------------
fn test_f010_headermap_overflow_and_bounds(t: lit::T&) {
    t.run("parse_headers_with_overflow detects conflicting Content-Length after 128 headers") { sub =>
        var raw: u8[>..] = [];
        raw.append("Host: example.com\r\n");
        for i in 128 {
            raw.append("X-Pad: 1\r\n");
        }
        raw.append("Transfer-Encoding: chunked\r\n");
        raw.append("Content-Length: 50\r\n\r\n");

        var map = http::HeaderMap { .. };
        var arena = http::OverflowArena { .. };
        let err = http::parse_headers_with_overflow(raw[..], map, arena, false);
        sub.assert_false(http::is_ok(err), "Conflicting TE + CL past 128th header MUST be rejected");
    };

    t.run("parse_headers_with_overflow handles duplicate Content-Length when raw > 8192B without OOB") { sub =>
        var raw: u8[>..] = [];
        raw.append("Host: example.com\r\n");
        raw.append("Content-Length: 10\r\n");
        raw.append("Content-Length: 10\r\n");
        for i in 100 {
            raw.append("X-Large-Padding-Header: 012345678901234567890123456789012345678901234567890123456789\r\n");
        }
        raw.append("\r\n");

        var map = http::HeaderMap { .. };
        var arena = http::OverflowArena { .. };
        let err = http::parse_headers_with_overflow(raw[..], map, arena, false);
        sub.assert_true(http::is_ok(err), "Identical duplicate Content-Length in >8KB arena buffer must succeed without OOB");
    };

    t.run("parse_headers_with_overflow handles obs-fold on 129th header when raw <= 8192B") { sub =>
        var raw: u8[>..] = [];
        for i in 129 {
            raw.append("X-H: v\r\n");
        }
        raw.append(" folded\r\n\r\n");

        var map = http::HeaderMap { .. };
        var arena = http::OverflowArena { .. };
        let err = http::parse_headers_with_overflow(raw[..], map, arena, true);
        sub.assert_true(http::is_ok(err), "Obs-fold on 129th header with stack raw_buf must not slice empty spill_raw");
    };

    t.run("get_combined rejects overflow when combined header value exceeds out buffer capacity") { sub =>
        var map = http::HeaderMap { .. };
        var v1: u8[..400] = [];
        for i in 300 { v1.push('a'); }
        var v2: u8[..400] = [];
        for i in 300 { v2.push('b'); }
        http::append_header(map, "Vary", v1[..]);
        http::append_header(map, "Vary", v2[..]);

        var small_out: u8[..512] = [];
        let ok = http::get_combined(map, "Vary", small_out, 512);
        sub.assert_false(ok, "get_combined MUST return false and clear out when combined length > max_out_len");
        sub.assert_eq(small_out.len, 0, "small_out must be cleared on capacity failure");
    };

    t.run("merge_with_headers_304 preserves multiple headers of same name in 304 response") { sub =>
        var cached = http::HeaderMap { .. };
        http::append_header(cached, "Cache-Control", "max-age=10");

        var resp_304 = http::HeaderMap { .. };
        http::append_header(resp_304, "Cache-Control", "public");
        http::append_header(resp_304, "Cache-Control", "max-age=3600");

        http::merge_with_headers_304(cached, resp_304);
        var combined: u8[..256] = [];
        let ok = http::get_combined(cached, "Cache-Control", combined);
        sub.assert_true(ok, "Combined Cache-Control exists");
        sub.assert_bytes_eq(combined[..], "public, max-age=3600", "Both 304 Cache-Control lines must be preserved");
    };
}

// ----------------------------------------------------------------------------
// F011: Perfect Hash Non-Alpha Collision & Chunked Trailer Validation
// ----------------------------------------------------------------------------
// ----------------------------------------------------------------------------
// 26. F011 Perfect Hash Collision & Chunked Trailers
// ----------------------------------------------------------------------------
fn test_f011_perfect_hash_and_chunked_trailers(t: lit::T&) {
    t.run("identify_known_header rejects non-alpha control char collision on user\\ragent") { sub =>
        let id = http::identify_known_header("user\ragent");
        sub.assert_true(id == http::KnownHeaderId.Unknown, "user\\ragent MUST NOT match KnownHeaderId.UserAgent");
    };

    t.run("chunk_fsm_feed rejects forbidden framing trailer Content-Length") { sub =>
        var dec = http_internal::ChunkFsmDecoder { .. };
        let wire = "0\r\nContent-Length: 100\r\n\r\n";
        let st, consumed, chunk = http_internal::chunk_fsm_feed(dec, wire);
        sub.assert_true(st == http_internal::ChunkFsmStatus.Error, "Forbidden Content-Length trailer in ChunkFsmDecoder MUST be rejected");
    };

    t.run("decode_chunked_body_with_trailers clears out_body and out_trailers on mid-stream error") { sub =>
        let wire = "4\r\nWiki\r\n4\r\nBad!\r\n0\r\nContent-Length: 5\r\n\r\n";
        var out_body: u8[>..] = [];
        var out_trailers = http::HeaderMap { .. };
        let err, consumed = http::decode_chunked_body_with_trailers(wire, out_body, out_trailers);
        sub.assert_false(err == http::ChunkedDecodeError.None, "Disallowed trailer fails chunked decode");
        sub.assert_eq(out_body.len, 0, "out_body MUST be cleared on chunked decode failure");
    };
}

// ----------------------------------------------------------------------------
// F017-F023: HeaderMap Overflow Obs-Fold, Empty Host Smuggling, Shift & Chunked
// ----------------------------------------------------------------------------
// ----------------------------------------------------------------------------
// 27. F017-F023 HeaderMap Arena Obs-Fold, Host Smuggling & Chunked
// ----------------------------------------------------------------------------
fn test_f017_f023_headers_chunked_forwarded(t: lit::T&) {
    t.run("F017: handle_obs_fold_arena migrates name to spill_raw so resolve_entry_name does not panic") { sub =>
        var raw: u8[>..] = [];
        for i in 128 {
            raw.append("X-P: 1\r\n");
        }
        raw.append("X-Fold: val1\r\n val2\r\nHost: example.com\r\n\r\n");

        var map = http::HeaderMap { .. };
        var arena = http::OverflowArena { .. };
        let err = http::parse_headers_with_overflow(raw[..], map, arena, true);
        sub.assert_true(http::is_ok(err), "Obs-fold on 129th header followed by Host must succeed without OOB");
        sub.assert_bytes_eq(http::get_header_spill(map, arena, "X-Fold"), "val1 val2", "Folded 129th header value resolved");
    };

    t.run("F018: duplicate Host header rejected even when first Host value is empty") { sub =>
        var map = http::HeaderMap { .. };
        let err = http::parse_headers("Host: \r\nHost: evil.com\r\n\r\n", map, false);
        sub.assert_false(http::is_ok(err), "Duplicate Host after empty Host MUST be rejected per RFC 9112 §3.2");
    };

    t.run("F019: shift_raw_buf_left updates obs-folded values_begin when earlier header folded at tail") { sub =>
        var map = http::HeaderMap { .. };
        let err = http::parse_headers("X-Fold: a\r\n b\r\nX-Next: longvalue\r\n\r\n", map, true);
        sub.assert_true(http::is_ok(err), "Initial obs-fold parse succeeds");
        http::set_header(map, "X-Next", "v");
        sub.assert_bytes_eq(http::get_header(map, "X-Fold"), "a b", "Obs-folded header value remains valid after in-place shrink");
    };

    t.run("F020: remove_sensitive_headers does not panic on HEADER_SRC_ARENA entries when raw > 8KB") { sub =>
        var raw: u8[>..] = [];
        raw.append("Authorization: Bearer secret\r\nX-Custom: 1\r\nX-Custom: 2\r\n");
        for i in 100 {
            raw.append("X-Pad: 01234567890123456789012345678901234567890123456789012345678901234567890123456789\r\n");
        }
        raw.append("\r\n");
        var map = http::HeaderMap { .. };
        var arena = http::OverflowArena { .. };
        let err = http::parse_headers_with_overflow(raw[..], map, arena, false);
        sub.assert_true(http::is_ok(err), "Large >8KB header block parsed");
        http::remove_sensitive_headers(map);
        sub.assert_false(http::has_header_spill(map, arena, "Authorization"), "Sensitive Authorization removed without OOB");
    };

    t.run("F021: Host obs-fold smuggling, status-line SP/range, Proxy-Authenticate non-cacheable & 304 capacity") { sub =>
        var map1 = http::HeaderMap { .. };
        let err1 = http::parse_headers("Host: example.com\r\n , evil.com\r\n\r\n", map1, true);
        sub.assert_false(http::is_ok(err1), "Obs-fold injecting space/comma into Host MUST be rejected");

        var map2 = http::HeaderMap { .. };
        sub.assert_false(http::is_ok(http::parse_response_headers("HTTP/1.1200 OK\r\n\r\n", map2)), "Missing SP after HTTP/1.1 must fail");
        sub.assert_false(http::is_ok(http::parse_response_headers("HTTP/1.1 2000 OK\r\n\r\n", map2)), "4-digit status code must fail");
        sub.assert_false(http::is_ok(http::parse_response_headers("HTTP/1.1 000 OK\r\n\r\n", map2)), "Status code < 100 must fail");

        var src = http::HeaderMap { .. };
        http::append_header(src, "Proxy-Authenticate", "Basic realm=\"p\"");
        var dst = http::HeaderMap { .. };
        http::persist_headers(src, dst, http::PERSIST_SANS_NON_CACHEABLE);
        sub.assert_false(http::has_header(dst, "Proxy-Authenticate"), "Proxy-Authenticate MUST be stripped as non-cacheable");
    };

    t.run("F022-F023: Forwarded duplicate param & malformed element rejection, ChunkFsm BWS before = & TE params") { sub =>
        var elems: http::ForwardedElement[..8] = [];
        sub.assert_eq(http::parse_forwarded_header("for=1.2.3.4;for=5.6.7.8", elems), 0, "Duplicate for= in Forwarded element MUST fail per RFC 7239 §4");
        sub.assert_eq(http::parse_forwarded_header("bad_elem, for=1.2.3.4", elems), 0, "Malformed Forwarded element MUST reject header");

        var dec = http_internal::ChunkFsmDecoder { .. };
        let st, consumed, chunk = http_internal::chunk_fsm_feed(dec, "4;ext =val\r\nWiki\r\n0\r\n\r\n");
        sub.assert_false(st == http_internal::ChunkFsmStatus.Error, "BWS before '=' in chunk-ext MUST be accepted per RFC 9112 §7.1.1");

        sub.assert_false(http::validate_transfer_encoding_value("gzip;===, chunked"), "Malformed transfer-parameter gzip;=== MUST be rejected");
    };
}

// ----------------------------------------------------------------------------
// 28. uWebSockets #1949 / RFC 9112 §3.2: Host Header Query or Fragment Rejection in HTTP/1.0
// ----------------------------------------------------------------------------
fn test_host_header_query_fragment_rejection(t: lit::T&) {
    t.run("HTTP/1.0 request with query in Host header must be rejected") { sub =>
        // RFC 9112 §3.2 & uWebSockets #1949: If a Host header is provided, the authority
        // MUST NOT contain query '?' or fragment '#', even if protocol is HTTP/1.0.
        // Currently, server/server.goose:169 guards Host character checks with:
        //   if proto_slice == "HTTP/1.1" { ... }
        // which leaves HTTP/1.0 vulnerable to host authority injection!
        var req = http::new_request("GET", "/api");
        let wire: const u8[:] = "GET /api HTTP/1.0\r\nHost: example.com?foo=bar\r\n\r\n";
        let ok, _ = server::parse_http1_wire_request(wire, req);
        sub.assert_false(ok, "Host header with query '?' in HTTP/1.0 must be rejected per RFC 9112 §3.2 and uWS #1949");
    };

    t.run("HTTP/1.0 request with fragment in Host header must be rejected") { sub =>
        var req = http::new_request("GET", "/api");
        let wire: const u8[:] = "GET /api HTTP/1.0\r\nHost: example.com#fragment\r\n\r\n";
        let ok, _ = server::parse_http1_wire_request(wire, req);
        sub.assert_false(ok, "Host header with fragment '#' in HTTP/1.0 must be rejected per RFC 9112 §3.2 and uWS #1949");
    };
}

// --- Component: regress_issues_batch02 ---
// Phase 2 RED test suite based on security audit reports and Go / uWebSockets issue trackers.
// Verifies protocol flaws, RFC non-conformances, and security bypasses that are CURRENTLY UNFIXED in goose-wing.
//
// Issues covered:
// 1. RFC 9110 §8.6 & Go #81642 / uWS #1370: Status 204 No Content Body Leakage (HTTP Smuggling)
// 2. Go #78172 & RFC 3986 §3.2.2 / RFC 9112 §3.2: Malformed IP-Literal Host Header Acceptance
// 3. Go #80282 & RFC 3986 §5.2.4: Deep Path Dot-Segment Collapse Truncation Bug
// 4. RFC 9110 §7.6.1 & Go #82065: Connection Header Hop-by-Hop 16-Token Truncation Leak
// 5. RFC 9449 §4.3: DPoP Proof URI Substring Prefix Collision Bypass
// 6. Go #62235 & RFC 6874 §2: Scoped IPv6 Link-Local URL Zone ID %25 Acceptance

// ----------------------------------------------------------------------------
// 29. RFC 9110 §8.6 / uWS #1370 / Go #81642: Status 204/304 Body Leakage on Wire
// ----------------------------------------------------------------------------
fn test_status_204_body_suppression_on_wire(t: lit::T&) {
    t.run("Status 204 No Content must not serialize message body to wire") { sub =>
        // RFC 9110 Section 8.6 & Section 6.4.1:
        // A 204 (No Content) response MUST NOT include a message body.
        // In server/server.goose:540, serialize_http1_response appends res.body[..]
        // directly to the wire when body.len > 0, despite status 204 omitting Content-Length.
        // This causes HTTP response splitting / smuggling on persistent connections!
        var res = http::Response { .. };
        res.status_code = 204;
        res.body.append("LEAKED_PAYLOAD_SMUGGLING");

        var wire_out: u8[..1024] = [];
        server::serialize_http1_response(res, "GooseWing", wire_out);

        let has_body = find(wire_out[..], "LEAKED_PAYLOAD_SMUGGLING") >= 0;
        sub.assert_false(has_body, "Status 204 response MUST NOT emit message body to wire per RFC 9110 §8.6");
    };
}

// ----------------------------------------------------------------------------
// 30. RFC 9110 §7.6.1 & Go #82065: Connection Header 16-Token Truncation Leak
// ----------------------------------------------------------------------------
fn test_connection_header_hop_by_hop_token_capacity(t: lit::T&) {
    t.run("Custom hop-by-hop headers past index 16 must not leak across intermediary") { sub =>
        // In http/headers.goose:1455 (collect_connection_tokens), out_tokens has cap 16:
        //   out_tokens: u8[..64][..16]&
        // If a Connection header specifies > 16 tokens (e.g. h1..h17), the 17th token
        // is silently dropped, causing strip_hop_by_hop_headers to retain 'h17'!
        var src = http::HeaderMap { .. };
        http::append_header(src, "Connection", "h1, h2, h3, h4, h5, h6, h7, h8, h9, h10, h11, h12, h13, h14, h15, h16, h17");
        http::append_header(src, "h17", "confidential-token");

        var dst = http::HeaderMap { .. };
        http::strip_hop_by_hop_headers(src, dst);

        sub.assert_false(http::has_header(dst, "h17"), "Hop-by-hop header h17 must be stripped per RFC 9110 §7.6.1");
    };
}

// --- Component: regress_issues_batch03 ---
// Phase 3 regression test suite based on security audit reports and Go / uWebSockets issue trackers.
//
// Issues covered:
// 1. Go #81508 & RFC 9110 §14.1.2: Unsupported Range Unit Must Return 200 OK (Not 416)
// 2. Go #21096 & RFC 9110 §7.6.1 / RFC 9113: Forwarding 'TE: trailers' for gRPC (Not Stripped)
// 3. RFC 6455 §8.1 / §7.4.1 / Autobahn 6.4.1: Close Frame with Invalid UTF-8 Must Fail with 1007 (Not 1002)
// 4. RFC 7692 §5.1 / uWS #1164: RSV1 Set on WebSocket Continuation Frame Must Fail with 1002
// 5. Go #76635 & RFC 6455 §4.1: Empty Path in WebSocket Handshake Must Default to '/'
// 6. Go #78569 & CVE-2026-25679 follow-up: parse_url_view Trailing Garbage on IPv6 Brackets [::1]evil.com
// 7. RFC 9112 Section 4: Status Line - HTTP Wire Response Status Line Whitespace & 4-Digit Smuggling (uWS #1949)

// ----------------------------------------------------------------------------
// 31. Go #81508 & RFC 9110 §14.1.2: Unsupported Range Unit Must Return 200 OK
// ----------------------------------------------------------------------------
fn test_unsupported_range_unit_ignored(t: lit::T&) {
    t.run("Unrecognized Range unit (e.g. items=0-10) must be ignored and return 200 OK") { sub =>
        var out_status: i32 = 0;
        var out_headers = http::HeaderMap { .. };
        var out_body: u8[>..] = [];

        let payload: const u8[:] = "Hello World Range Test";
        let mod_sec: i64         = 1700000000;

        http::serve_range_request(
            "items=0-10",
            "",
            "\"etag123\"",
            mod_sec,
            payload.len as i64,
            "text/plain",
            out_status,
            out_headers,
            out_body,
        ) { start, len, buf =>
            buf.append(payload[start..(start + len)]);
        };

        sub.assert_eq(out_status, 200, "Unrecognized Range unit must be ignored and return 200 OK (Go #81508 / RFC 9110 §14.1.2)");
        sub.assert_bytes_eq(out_body[..], payload, "Must return complete representation when Range unit is ignored");
    };
}

// ----------------------------------------------------------------------------
// 32. RFC 9112 Section 4: Status Line - HTTP Wire Response Status Line Whitespace & 4-Digit Smuggling (uWS #1949)
// ----------------------------------------------------------------------------
fn test_http1_wire_response_status_line_validation(t: lit::T&) {
    t.run("parse_http1_wire_response must reject 4-digit status code 'HTTP/1.1 2000 OK'") { sub =>
        var res = http::Response { .. };
        let wire: const u8[:] = "HTTP/1.1 2000 OK\r\nContent-Length: 0\r\n\r\n";
        let ok, _ = server::parse_http1_wire_response(wire, res);
        sub.assert_false(ok, "parse_http1_wire_response MUST reject 4-digit status codes like '2000'");
    };

    t.run("parse_http1_wire_response must reject non-SP whitespace 'HTTP/1.1\\t200 OK'") { sub =>
        var res = http::Response { .. };
        let wire_tab: const u8[:] = "HTTP/1.1\t200 OK\r\nContent-Length: 0\r\n\r\n";
        let ok_tab, _ = server::parse_http1_wire_response(wire_tab, res);
        sub.assert_false(ok_tab, "parse_http1_wire_response MUST reject Tab (\\t) between HTTP-version and status code");
    };
}

// --- Component: regress_issues_batch04 ---
// Phase 4 RED test suite based on security audit reports and Go / uWebSockets issue trackers.
// Verifies protocol flaws, RFC non-conformances, and security vulnerabilities that are CURRENTLY UNFIXED in goose-wing.
//
// Issues covered:
// 1. RFC 9110 §6.5.1 & Go #81143: Disallow Content-Type and Content-Encoding in Chunked Trailers
// 2. RFC 9110 §14.1.2 & Go #81858 (CVE-2026-78667): Range Requests Exceeding Max Ranges Must Return 200 OK (Not 416)
// 3. RFC 9112 §6.1 & RFC 7230 §3.3.3: Invalid Response Transfer-Encoding Must Reject (Not Fall Through to Content-Length)
// 4. RFC 3986 §3.2.2 & Go #75678 (CVE-2025-47912): parse_url_view Must Reject Non-IPv6 Bracketed Hosts ([google.com], [127.0.0.1])
// 5. RFC 3986 §2 / RFC 9112 §3.2 & CVE-2023-26159: parse_url_view Must Reject Unencoded CRLF in Host and Path
// 6. RFC 6455 §5.5 & uWS #1407: WebSocket Control Frame Encoding with Payload > 125 Must Never Emit Extended Length (126/127)

// ----------------------------------------------------------------------------
// 33. RFC 9110 §6.5.1 & Go #81143: Disallow Content-Type and Content-Encoding in Trailers
// ----------------------------------------------------------------------------
fn test_forbidden_trailer_fields(t: lit::T&) {
    t.run("Content-Type in chunked trailer must be rejected as DisallowedTrailer") { sub =>
        // RFC 9110 Section 6.5.1:
        // "A sender MUST NOT generate a trailer that contains any of the following fields:
        // ... Content-Encoding, Content-Type, Content-Range."
        // A recipient MUST NOT process forbidden fields as metadata of the payload.
        var out_body: u8[>..] = [];
        var out_trailers = http::HeaderMap { .. };
        let chunk_wire: const u8[:] = "5\r\nHello\r\n0\r\nContent-Type: text/html\r\n\r\n";

        let err, _ = http::decode_chunked_body_with_trailers(chunk_wire, out_body, out_trailers);
        sub.assert_eq(err, http::ChunkedDecodeError.DisallowedTrailer, "Content-Type trailer must be rejected with DisallowedTrailer (RFC 9110 §6.5.1)");
    };

    t.run("Content-Encoding in chunked trailer must be rejected as DisallowedTrailer") { sub =>
        var out_body: u8[>..] = [];
        var out_trailers = http::HeaderMap { .. };
        let chunk_wire: const u8[:] = "5\r\nHello\r\n0\r\nContent-Encoding: gzip\r\n\r\n";

        let err, _ = http::decode_chunked_body_with_trailers(chunk_wire, out_body, out_trailers);
        sub.assert_eq(err, http::ChunkedDecodeError.DisallowedTrailer, "Content-Encoding trailer must be rejected with DisallowedTrailer (RFC 9110 §6.5.1)");
    };
}

// ----------------------------------------------------------------------------
// 34. RFC 9110 §14.1.2 & Go #81858 (CVE-2026-78667): Exceeded Ranges Must Return 200 OK
// ----------------------------------------------------------------------------
fn test_exceeded_max_ranges_returns_200(t: lit::T&) {
    t.run("Range request with > 16 ranges must be ignored and served with 200 OK") { sub =>
        // RFC 9110 Section 14.1.2 & Go #81858 (CVE-2026-78667):
        // "An origin server MAY ignore a Range header field containing more than one range,
        // or containing ranges with excessive overhead... and return the entire selected
        // representation with a 200 (OK) status code."
        // In http/multipart.goose:668, serve_range_request returns 416 for ExceededMaxRanges!
        var out_status: i32 = 0;
        var out_headers = http::HeaderMap { .. };
        var out_body: u8[>..] = [];

        let payload: const u8[:] = "0123456789abcdefghijklmnopqrstuvwxyz";
        let mod_sec: i64         = 1700000000;

        // 17 small ranges exceeds max_ranges=16
        let excessive_range = "bytes=0-1,2-3,4-5,6-7,8-9,10-11,12-13,14-15,16-17,18-19,20-21,22-23,24-25,26-27,28-29,30-31,32-33";

        http::serve_range_request(
            excessive_range,
            "",
            "\"etag123\"",
            mod_sec,
            payload.len,
            "text/plain",
            out_status,
            out_headers,
            out_body,
        ) { start, len, buf =>
            buf.append(payload[start..(start + len)]);
        };

        sub.assert_eq(out_status, 200, "Excessive range count must be ignored and return 200 OK (Go #81858 / CVE-2026-78667)");
        sub.assert_bytes_eq(out_body[..], payload, "Must return complete representation when excessive ranges are ignored");
    };
}

// ----------------------------------------------------------------------------
// 35. RFC 9112 §6.1 & RFC 7230 §3.3.3: Invalid Response Transfer-Encoding Rejection
// ----------------------------------------------------------------------------
fn test_response_invalid_transfer_encoding_rejected(t: lit::T&) {
    t.run("Response with invalid Transfer-Encoding and Content-Length must NOT fall through") { sub =>
        // RFC 9112 Section 6.1:
        // "If a Transfer-Encoding header field is present in a response and the chunked transfer
        // coding is not the final transfer coding, the recipient MUST treat the response as an
        // error or close the connection without reading the body."
        // Currently, parse_http1_wire_response falls through to Content-Length!
        var res = http::Response { .. };
        let wire: const u8[:] = "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked, identity\r\nContent-Length: 5\r\n\r\nhello";
        let ok, _ = server::parse_http1_wire_response(wire, res);

        sub.assert_false(ok, "parse_http1_wire_response MUST reject response with invalid Transfer-Encoding (RFC 9112 §6.1)");
    };

    t.run("Response with unknown Transfer-Encoding must be rejected") { sub =>
        var res = http::Response { .. };
        let wire_unknown: const u8[:] = "HTTP/1.1 200 OK\r\nTransfer-Encoding: bogus\r\nContent-Length: 4\r\n\r\ntest";
        let ok_unk, _ = server::parse_http1_wire_response(wire_unknown, res);

        sub.assert_false(ok_unk, "parse_http1_wire_response MUST reject response with unknown Transfer-Encoding 'bogus'");
    };
}

// --- Component: regress_issues_batch05 ---
// Phase 5 RED test suite based on security audit reports and Go / uWebSockets issue trackers.
// Verifies protocol flaws, RFC non-conformances, and security vulnerabilities that are CURRENTLY UNFIXED in goose-wing.
//
// Issues covered:
// 1. RFC 9112 §3.2.3 & §9.3.6: CONNECT Request-Target Authority-Form Enforcement (Reject origin-form for CONNECT, reject authority-form for non-CONNECT)
// 2. RFC 9112 §7.2, §9.5 & RFC 7230 §5.4: Multiple / Comma-Separated Values in Host Header Must Reject with 400
// 3. RFC 1035 §2.3.4 & §4.1.4 (CVE-2026-97044): DNS Wire Decoding Must Reject Label Length > 63 and Reserved Label Flags
// 4. HAProxy PROXY Protocol v2 §2.2 & uWS #1927 / #1948: PROXY v2 Header Must Reject Truncated TLVs and Trailing Bytes
// 5. RFC 6455 §5.5, §5.5.1 & uWS #1407: WebSocket Close Frame Reason Payload Must Be Clamped to <= 123 Bytes
// 6. CVE-2025-61726 & CVE-2026-39825: Query Parameter Key Overflow Defense Against Bounded Capacity
// 7. RFC 6265bis §5.1.4: Cookie URL Fallback Path Parsing Must Discard Fragment and Default to '/'

// ----------------------------------------------------------------------------
// 36. RFC 9112 §3.2.3 & §9.3.6: CONNECT Request-Target Authority-Form Enforcement
// ----------------------------------------------------------------------------
fn test_connect_authority_form_enforcement(t: lit::T&) {
    t.run("CONNECT with valid authority-form host:port MUST be accepted") { sub =>
        // RFC 9112 Section 3.2.3: "The authority-form of request-target is only used for CONNECT requests"
        // E.g.: CONNECT example.com:443 HTTP/1.1
        let wire = "CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n";
        var req = http::new_request("GET", "");
        let ok_parse, consumed = server::parse_http1_wire_request(wire, req);
        sub.assert_true(ok_parse, "Valid CONNECT with authority-form (example.com:443) must be accepted");
        sub.assert_true(req.method[..] == "CONNECT", "Method must be CONNECT");
        sub.assert_true(req.url[..] == "example.com:443", "URL must be example.com:443");
    };

    t.run("CONNECT with origin-form (/path) MUST be rejected") { sub =>
        // RFC 9112 Section 9.3.6: "Any request-target other than authority-form is invalid for CONNECT"
        let wire = "CONNECT /api/tunnel HTTP/1.1\r\nHost: example.com\r\n\r\n";
        var req = http::new_request("GET", "");
        let ok_parse, _ = server::parse_http1_wire_request(wire, req);
        sub.assert_false(ok_parse, "CONNECT with origin-form (/api/tunnel) MUST be rejected per RFC 9112 §9.3.6");
    };

    t.run("GET with authority-form (host:port) MUST be rejected") { sub =>
        // RFC 9112 Section 3.2.3: Authority-form is ONLY valid for CONNECT!
        let wire = "GET example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n";
        var req = http::new_request("GET", "");
        let ok_parse, _ = server::parse_http1_wire_request(wire, req);
        sub.assert_false(ok_parse, "GET with authority-form (example.com:443) MUST be rejected");
    };
}

// ----------------------------------------------------------------------------
// 37. RFC 9112 §7.2, §9.5 & RFC 7230 §5.4: Multiple / Comma-Separated Values in Host Header
// ----------------------------------------------------------------------------
fn test_host_header_comma_separated_values_rejected(t: lit::T&) {
    t.run("Host header with comma-separated hosts (folded duplicate) MUST be rejected") { sub =>
        // RFC 9112 Section 9.5: "A server MUST respond with a 400 (Bad Request) status code to any
        // HTTP/1.1 request message that contains more than one Host header field or a Host header field
        // with multiple field values."
        let wire = "GET / HTTP/1.1\r\nHost: example.com,evil.com\r\n\r\n";
        var req = http::new_request("GET", "");
        let ok_parse, _ = server::parse_http1_wire_request(wire, req);
        sub.assert_false(ok_parse, "Host header with comma-separated values (example.com,evil.com) MUST be rejected");
    };

    t.run("Host header with comma and space MUST be rejected") { sub =>
        let wire = "GET / HTTP/1.1\r\nHost: primary.com, secondary.com\r\n\r\n";
        var req = http::new_request("GET", "");
        let ok_parse, _ = server::parse_http1_wire_request(wire, req);
        sub.assert_false(ok_parse, "Host header with comma and space MUST be rejected");
    };
}

// ----------------------------------------------------------------------------
// 38. RFC 9112 §7.1 & CVE-2023-45287 (Go #71988): Chunked FSM Bare LF in Chunk Size Rejection
// ----------------------------------------------------------------------------
fn test_chunked_fsm_bare_lf_rejection(t: lit::T&) {
    t.run("Chunk size terminated with bare LF MUST return Error") { sub =>
        // RFC 9112 Section 7.1 & Section 2.2: Bare LF on chunk size line is forbidden (HTTP Smuggling)
        var dec = http_internal::new_chunk_fsm_decoder();
        let raw = "5\nhello\r\n0\r\n\r\n";
        let st, consumed, _ = http_internal::chunk_fsm_feed(dec, raw);
        sub.assert_eq(st, http_internal::ChunkFsmStatus.Error, "Bare LF without preceding CR MUST return ChunkFsmStatus.Error");
    };

    t.run("Chunk extension terminated with bare LF MUST return Error") { sub =>
        var dec = http_internal::new_chunk_fsm_decoder();
        let raw = "5;ext=val\nhello\r\n0\r\n\r\n";
        let st, consumed, _ = http_internal::chunk_fsm_feed(dec, raw);
        sub.assert_eq(st, http_internal::ChunkFsmStatus.Error, "Bare LF in chunk extension MUST return ChunkFsmStatus.Error");
    };
}

// ----------------------------------------------------------------------------
// 39. RFC 9112 §7.1.1 & Go #82257: Chunked FSM BWS (Spaces/Tabs) Preceding Semicolon Acceptance
// ----------------------------------------------------------------------------
fn test_chunked_fsm_bws_preceding_semicolon(t: lit::T&) {
    t.run("Space preceding semicolon in chunk extension MUST be accepted") { sub =>
        // RFC 9112 Section 7.1.1: chunk-ext = *( BWS ";" BWS chunk-ext-name [ BWS "=" BWS chunk-ext-val ] )
        // BWS = *( SP / HTAB )
        var dec = http_internal::new_chunk_fsm_decoder();
        let raw = "5 ;ext=foo\r\nhello\r\n0\r\n\r\n";
        var total_body: u8[..64] = [];
        var cursor:     i64      = 0;

        while cursor < raw.len {
            let st, consumed, chunk = http_internal::chunk_fsm_feed(dec, raw[cursor..]);
            cursor += consumed;
            if st == http_internal::ChunkFsmStatus.YieldChunk {
                total_body.append(chunk);
            } else if st == http_internal::ChunkFsmStatus.Complete {
                break;
            } else if st == http_internal::ChunkFsmStatus.Error {
                sub.assert_true(false, "Chunked decoder must not error on BWS before semicolon");
                break;
            }
        }

        sub.assert_bytes_eq(total_body[..], "hello", "Decoded payload must match");
    };

    t.run("HTAB preceding semicolon in chunk extension MUST be accepted") { sub =>
        var dec = http_internal::new_chunk_fsm_decoder();
        let raw = "5\t;ext=foo\r\nworld\r\n0\r\n\r\n";
        var total_body: u8[..64] = [];
        var cursor:     i64      = 0;

        while cursor < raw.len {
            let st, consumed, chunk = http_internal::chunk_fsm_feed(dec, raw[cursor..]);
            cursor += consumed;
            if st == http_internal::ChunkFsmStatus.YieldChunk {
                total_body.append(chunk);
            } else if st == http_internal::ChunkFsmStatus.Complete {
                break;
            } else if st == http_internal::ChunkFsmStatus.Error {
                sub.assert_true(false, "Chunked decoder must not error on HTAB before semicolon");
                break;
            }
        }

        sub.assert_bytes_eq(total_body[..], "world", "Decoded payload must match");
    };
}

// ----------------------------------------------------------------------------
// 40. CVE-2026-42507 & Go #79346: Control Character Sanitization in Diagnostic Error Messages
// ----------------------------------------------------------------------------
fn test_diagnostic_control_character_sanitization(t: lit::T&) {
    t.run("Control characters in untrusted tokens MUST be escaped for safe logging") { sub =>
        // CVE-2026-42507 & Go #79346:
        // Untrusted header tokens containing CRLF or control bytes (< 0x20, > 0x7E)
        // must be escaped to prevent log injection and HTTP response splitting.
        var out_clean: u8[..128] = [];
        http::escape_diagnostic_control_chars("malformed\r\nInjected-Header: evil", out_clean);

        // Result must NOT contain raw \r or \n
        var has_raw_cr = false;
        var has_raw_lf = false;
        for b in out_clean {
            if b == '\r' { has_raw_cr = true; }
            if b == '\n' { has_raw_lf = true; }
        }
        sub.assert_false(has_raw_cr, "Sanitized string MUST NOT contain raw CR");
        sub.assert_false(has_raw_lf, "Sanitized string MUST NOT contain raw LF");
        sub.assert_bytes_eq(out_clean[..], "malformed\\r\\nInjected-Header: evil", "CRLF correctly escaped to \\r\\n");
    };
}

// ----------------------------------------------------------------------------
// 41. RFC 9110 §15.2 & Go #65035: Excessive 1xx Informational Response Limit Defense
// ----------------------------------------------------------------------------
fn test_informational_1xx_response_limit(t: lit::T&) {
    t.run("Consecutive 1xx responses exceeding limit MUST be rejected") { sub =>
        // RFC 9110 Section 15.2 & Go #65035:
        // Bound consecutive 1xx informational responses (default limit: 5) to prevent infinite loops.
        sub.assert_true(http::validate_informational_response_count(1, 5), "1st 1xx response is valid");
        sub.assert_true(http::validate_informational_response_count(5, 5), "5th 1xx response is valid (at limit)");
        sub.assert_false(http::validate_informational_response_count(6, 5), "6th 1xx response MUST be rejected (> limit)");
        sub.assert_false(http::validate_informational_response_count(100, 5), "100th 1xx response MUST be rejected");
    };
}

// ----------------------------------------------------------------------------
// 42. RFC 9112 §7.1.1 & Go #82257: Chunk Extension with Bad Whitespace Before Semicolon
// ----------------------------------------------------------------------------
fn test_chunked_bws_before_semicolon(t: lit::T&) {
    t.run("Chunk extension with space before semicolon parses cleanly (RFC 9112 §7.1.1)") { sub =>
        let wire = "5 ; ext=val\r\nhello\r\n0\r\n\r\n";
        var body: u8[>..] = [];
        let err = http::decode_chunked_body(wire, body);
        sub.assert_eq(err, http::ChunkedDecodeError.None, "Chunk extension with BWS before ';' decoded successfully");
        sub.assert_bytes_eq(body[..], "hello", "Decoded chunk data matches expected payload");
    };

    t.run("Chunk extension with tab before semicolon parses cleanly (RFC 9112 §7.1.1)") { sub =>
        let wire = "4\t; ext=token\r\nwing\r\n0\r\n\r\n";
        var body: u8[>..] = [];
        let err = http::decode_chunked_body(wire, body);
        sub.assert_eq(err, http::ChunkedDecodeError.None, "Chunk extension with HTAB before ';' decoded successfully");
        sub.assert_bytes_eq(body[..], "wing", "Decoded chunk data matches expected payload");
    };
}

// --- Component: regress_issues_batch09 ---
// Phase 9 RED test suite based on security issue trackers and RFC specifications.
// Verifies protocol flaws, RFC non-conformances, and security edge cases:
//
// 1. RFC 9112 §7.2 / RFC 3986 §3.2.2 & uWebSockets #1949: HTTP/1.1 Host Header Character Validation & Duplicate Rejection
// 2. RFC 9113 §8.3.1 & uWebSockets #1949: HTTP/2 :authority Pseudo-Header Forbidden Characters
// 3. RFC 9113 §8.1.2: HTTP/2 Trailer Section Disallowed Header Fields
// 4. RFC 9114 §4.3: HTTP/3 / QPACK Duplicate Pseudo-Headers & Order Invariants
// 5. RFC 9113 §6.5.2: HTTP/2 Client SETTINGS Frame Rejection of SETTINGS_ENABLE_PUSH != 0
// 6. RFC 3986 §3.2.2 & Go #77578 (CVE-2026-25679) / CVE-2025-47912: URL Bracketed Host Validation
// 7. RFC 9110 §15.4 & Go #73816 (CVE-2025-4673): Cross-Origin Redirect Sensitive Header Stripping

// ----------------------------------------------------------------------------
// 43. RFC 9112 §7.2 / RFC 3986 §3.2.2 & uWebSockets #1949: HTTP/1.1 Host Validation
// ----------------------------------------------------------------------------
fn test_h1_host_header_validation_and_duplicates(t: lit::T&) {
    t.run("Host header with path, query, fragment or userinfo MUST be rejected (uWS #1949)") { sub =>
        // RFC 9112 Section 7.2:
        // Host = uri-host [ ":" port ]
        // Must not contain path (/), query (?), fragment (#), or userinfo (@)
        var map1 = http::HeaderMap { .. };
        let err_path = http::parse_headers("Host: example.com/path\r\n\r\n", map1);
        sub.assert_false(http::is_ok(err_path), "Host with path '/' MUST be rejected");

        var map2 = http::HeaderMap { .. };
        let err_query = http::parse_headers("Host: example.com?q=1\r\n\r\n", map2);
        sub.assert_false(http::is_ok(err_query), "Host with query '?' MUST be rejected");

        var map3 = http::HeaderMap { .. };
        let err_hash = http::parse_headers("Host: example.com#frag\r\n\r\n", map3);
        sub.assert_false(http::is_ok(err_hash), "Host with fragment '#' MUST be rejected");

        var map4 = http::HeaderMap { .. };
        let err_at = http::parse_headers("Host: user@example.com\r\n\r\n", map4);
        sub.assert_false(http::is_ok(err_at), "Host with userinfo '@' MUST be rejected");

        var map_ok = http::HeaderMap { .. };
        let err_ok = http::parse_headers("Host: example.com:8080\r\n\r\n", map_ok);
        sub.assert_true(http::is_ok(err_ok), "Clean Host 'example.com:8080' is valid");
    };

    t.run("Duplicate Host headers in HTTP/1.1 MUST be rejected (RFC 9112 §7.2)") { sub =>
        var map_dup = http::HeaderMap { .. };
        let err_dup = http::parse_headers("Host: example.com\r\nHost: evil.com\r\n\r\n", map_dup);
        sub.assert_false(http::is_ok(err_dup), "Duplicate Host headers MUST be rejected (smuggling protection)");
    };
}

// ----------------------------------------------------------------------------
// 44. SFV string & display string overflow rejection (http/mime.goose)
// ----------------------------------------------------------------------------
fn test_sfv_string_overflow_rejection(t: lit::T&) {
    t.run("SFV string > 1088 bytes must be rejected as syntax error") { sub =>
        var raw_str: u8[>..] = [];
        raw_str.push('"');
        for i in 1090 {
            raw_str.push('a');
        }
        raw_str.push('"');

        var item = http::SfvItem { .. };
        let ok = http::parse_sfv_item(raw_str[..], item);
        sub.assert_false(ok, "SFV string > 1088 bytes MUST return false and not silently truncate");
    };

    t.run("SFV display string > 1088 bytes must be rejected as syntax error") { sub =>
        var raw_dstr: u8[>..] = [];
        raw_dstr.append("%\"");
        for i in 1090 {
            raw_dstr.push('b');
        }
        raw_dstr.push('"');

        var item = http::SfvItem { .. };
        let ok = http::parse_sfv_item(raw_dstr[..], item);
        sub.assert_false(ok, "SFV display string > 1088 bytes MUST return false and not silently truncate");
    };
}

// ----------------------------------------------------------------------------
// 45. SFV parameter & list/dict capacity smuggling (http/mime.goose)
// ----------------------------------------------------------------------------
fn test_sfv_capacity_smuggling_rejection(t: lit::T&) {
    t.run("SFV item with > 16 parameters must be rejected rather than dropping 17th") { sub =>
        var raw_params: u8[..1024] = [];
        raw_params.append("token");
        for i in 17 {
            raw_params.append(";p");
            format(raw_params, i);
            raw_params.append("=1");
        }

        var item = http::SfvItem { .. };
        let ok = http::parse_sfv_item(raw_params[..], item);
        sub.assert_false(ok, "SFV parameters > 16 MUST be rejected rather than dropping security parameters");
    };

    t.run("SFV dictionary with > 64 keys must be rejected") { sub =>
        var raw_dict: u8[>..] = [];
        for i in 65 {
            if i > 0 { raw_dict.append(", "); }
            raw_dict.append("k");
            format(raw_dict, i);
            raw_dict.append("=1");
        }

        var dict = http::SfvDict { .. };
        let ok = http::parse_sfv_dict(raw_dict[..], dict);
        sub.assert_false(ok, "SFV dict > 64 entries MUST return false and not drop keys");
    };
}

// ----------------------------------------------------------------------------
// 46. HTTP/1.x obs-fold buffer capacity overflow safety (http/headers.goose)
// ----------------------------------------------------------------------------
fn test_http_headers_obs_fold_capacity_safety(t: lit::T&) {
    t.run("Oversized obs-fold continuation MUST return CapacityExceeded without abort") { sub =>
        var headers_raw: u8[>..] = [];
        headers_raw.append("Host: example.com\r\nX-Fold: start\r\n");
        // Pad with continuations exceeding 8192 bytes
        for i in 100 {
            headers_raw.append(" ");
            for j in 90 { headers_raw.push('z'); }
            headers_raw.append("\r\n");
        }
        headers_raw.append("\r\n");

        var map = http::HeaderMap { .. };
        let err = http::parse_headers(headers_raw[..], map, true);
        sub.assert_true(err == http::HeaderParseError.CapacityExceeded, "Oversized obs-fold MUST return CapacityExceeded");
    };
}

// ----------------------------------------------------------------------------
// 47. Chunked FSM & Extensions (http/headers/chunked_fsm.goose, chunked.goose)
// ----------------------------------------------------------------------------
fn test_chunked_fsm_and_extensions_rfc9112(t: lit::T&) {
    t.run("Chunk extension with empty value (ext=) must return Error") { sub =>
        var dec = http_internal::new_chunk_fsm_decoder();
        let status, _, _ = http_internal::chunk_fsm_feed(dec, "5;ext=\r\nhello\r\n0\r\n\r\n");
        sub.assert_true(status == http_internal::ChunkFsmStatus.Error, "ext= with empty value MUST return Error");
    };

    t.run("Chunk extension with unclosed quote must return Error") { sub =>
        var dec = http_internal::new_chunk_fsm_decoder();
        let status, _, _ = http_internal::chunk_fsm_feed(dec, "5;ext=\"unclosed\r\nhello\r\n0\r\n\r\n");
        sub.assert_true(status == http_internal::ChunkFsmStatus.Error, "Unclosed quote in chunk extension MUST return Error");
    };

    t.run("parse_chunk_size_hex rejects DEL (0x7F)") { sub =>
        let _, err = http::parse_chunk_size_hex("5;ext=foo\x7F");
        sub.assert_true(err == http::ChunkedDecodeError.InvalidChunkExtension, "DEL in chunk extension must be rejected");
    };

    t.run("parse_chunk_size_hex rejects invalid quoted-pair control escape") { sub =>
        let _, err = http::parse_chunk_size_hex("5;ext=\"a\\\x01b\"");
        sub.assert_true(err == http::ChunkedDecodeError.InvalidChunkExtension, "Control char escape in quoted-pair must be rejected");
    };

    t.run("Chunk FSM handles split trailing CRLF without infinite loop") { sub =>
        var dec = http_internal::new_chunk_fsm_decoder();
        // Feed chunk body + '\r'
        let st1, off1, slice1 = http_internal::chunk_fsm_feed(dec, "5\r\nhello\r");
        sub.assert_true(st1 == http_internal::ChunkFsmStatus.YieldChunk, "First feed yields chunk slice");
        sub.assert_eq(slice1, "hello", "Body payload emitted");

        // Feed remaining '\n'
        let st2, off2, slice2 = http_internal::chunk_fsm_feed(dec, "\n");
        sub.assert_true(st2 == http_internal::ChunkFsmStatus.NeedMore, "Second feed consumes trailing LF and expects next chunk");

        // Feed final chunk
        let st3, off3, _ = http_internal::chunk_fsm_feed(dec, "0\r\n\r\n");
        sub.assert_true(st3 == http_internal::ChunkFsmStatus.Complete, "Zero chunk terminates stream");
    };
}

// ----------------------------------------------------------------------------
// 48. HTTP/1.x Headers & Smuggling (http/headers/lexical.goose, headers.goose)
// ----------------------------------------------------------------------------
fn test_http1_headers_cl_host_and_cookie_bounds(t: lit::T&) {
    t.run("track_header_presence MUST reject invalid first Content-Length value") { sub =>
        var tracker = http::HeaderPresenceTracker { .. };
        let ok = http::track_header_presence(tracker, "Content-Length", "invalid", 0);
        sub.assert_false(ok, "Invalid first Content-Length MUST return false immediately");
    };

    t.run("validate_header_framing_conflicts rejects Host with interior comma") { sub =>
        var map = http::HeaderMap { .. };
        let err = http::parse_headers("Host: a.com, b.com\r\n\r\n", map);
        sub.assert_true(err == http::HeaderParseError.InvalidHeaderValue, "Host with comma MUST be rejected");
    };

    t.run("validate_header_framing_conflicts rejects Host with interior space") { sub =>
        var map = http::HeaderMap { .. };
        let err = http::parse_headers("Host: a .com\r\n\r\n", map);
        sub.assert_true(err == http::HeaderParseError.InvalidHeaderValue, "Host with space MUST be rejected");
    };

    t.run("get_set_cookie with Set-Cookie > 1024B must not abort") { sub =>
        var raw_hdr: u8[>..] = [];
        raw_hdr.append("Host: example.com\r\nSet-Cookie: session=");
        for i in 1500 { raw_hdr.push('x'); }
        raw_hdr.append("\r\n\r\n");

        var map = http::HeaderMap { .. };
        let err = http::parse_headers(raw_hdr[..], map);
        sub.assert_true(err == http::HeaderParseError.None, "Headers parsed successfully");

        var cookies: u8[..1024][>..] = [];
        http::get_set_cookie(map, cookies);
        sub.assert_eq(cookies.len, 1, "Exactly one Set-Cookie retrieved without abort");
    };

    t.run("classify_well_known_header recognises CORS access-control headers") { sub =>
        var map = http::HeaderMap { .. };
        let raw = "Access-Control-Max-Age: 600\r\nAccess-Control-Request-Method: POST\r\nAccess-Control-Request-Headers: X-Custom, Authorization\r\n\r\n";
        let err = http::parse_headers(raw, map);
        sub.assert_true(err == http::HeaderParseError.None, "Headers parsed successfully");
        sub.assert_bytes_eq(http::get_inline(map, http::WellKnownHeader.AccessControlMaxAge), "600", "AccessControlMaxAge inline match");
        sub.assert_bytes_eq(http::get_inline(map, http::WellKnownHeader.AccessControlRequestMethod), "POST", "AccessControlRequestMethod inline match");
        sub.assert_bytes_eq(http::get_inline(map, http::WellKnownHeader.AccessControlRequestHeaders), "X-Custom, Authorization", "AccessControlRequestHeaders inline match");
    };
}

// ----------------------------------------------------------------------------
// 49. HTTP Chunked 64-bit FSM Error Stickiness, Bare CR & Trailer Invariants
// ----------------------------------------------------------------------------
fn test_chunked_fsm_invariants(t: lit::T&) {
    t.run("chunk_fsm_feed error state is sticky and idempotent") { sub =>
        var dec = http_internal::new_chunk_fsm_decoder();
        // Malformed chunk size: '1', '2' consumed, 'Z' triggers Error
        let st1, cons1, _ = http_internal::chunk_fsm_feed(dec, "12Z\r\n");
        sub.assert_eq(st1, http_internal::ChunkFsmStatus.Error, "First feed returns Error");
        sub.assert_eq(cons1, 2, "2 valid hex bytes consumed before error at byte 2");

        // Subsequent feed on poisoned decoder MUST immediately return Error with 0 bytes consumed
        let st2, cons2, _ = http_internal::chunk_fsm_feed(dec, "4\r\nWiki\r\n0\r\n\r\n");
        sub.assert_eq(st2, http_internal::ChunkFsmStatus.Error, "Poisoned decoder remains in Error");
        sub.assert_eq(cons2, 0, "Poisoned decoder consumes 0 bytes");

        // Reset restores usability
        http_internal::chunk_fsm_reset(dec);
        let st3, _, _ = http_internal::chunk_fsm_feed(dec, "4\r\nWiki\r\n0\r\n\r\n");
        sub.assert_eq(st3, http_internal::ChunkFsmStatus.YieldChunk, "Reset decoder functions again");
    };

    t.run("chunk_fsm_feed rejects bare CR in trailer lines (RFC 9112 §2.2)") { sub =>
        var dec = http_internal::new_chunk_fsm_decoder();
        // Trailer line has \r followed by 'X' instead of \n
        let raw = "0\r\nX-Trailer: val\rX-Next: 1\r\n\r\n";
        let st, _, _ = http_internal::chunk_fsm_feed(dec, raw);
        sub.assert_eq(st, http_internal::ChunkFsmStatus.Error, "Bare CR in trailer line rejected");
    };

    t.run("chunk_fsm_feed rejects bare LF and obs-fold in trailer mode") { sub =>
        var dec1 = http_internal::new_chunk_fsm_decoder();
        let st1, _, _ = http_internal::chunk_fsm_feed(dec1, "0\r\n\n");
        sub.assert_eq(st1, http_internal::ChunkFsmStatus.Error, "Bare LF in trailer mode rejected");

        var dec2 = http_internal::new_chunk_fsm_decoder();
        // obs-fold (space at start of trailer line)
        let st2, _, _ = http_internal::chunk_fsm_feed(dec2, "0\r\n X-Fold: bad\r\n\r\n");
        sub.assert_eq(st2, http_internal::ChunkFsmStatus.Error, "Obs-fold at start of trailer line rejected");
    };

    t.run("chunk_fsm_feed rejects NUL and CTL bytes in trailer line") { sub =>
        var dec = http_internal::new_chunk_fsm_decoder();
        var raw: u8[..32] = "0\r\nX-Bad: \0val\r\n\r\n";
        let st, _, _ = http_internal::chunk_fsm_feed(dec, raw[..]);
        sub.assert_eq(st, http_internal::ChunkFsmStatus.Error, "NUL byte in trailer rejected");
    };
}

// ----------------------------------------------------------------------------
// 50. HTTP/1.1 Wire Response Parser 204/304/1xx Chunked Desync & Header Block Cap
// ----------------------------------------------------------------------------
fn test_http1_wire_response_204_304_1xx_framing(t: lit::T&) {
    t.run("parse_http1_wire_response: 204/304/1xx with Transfer-Encoding chunked must succeed without body") { sub =>
        // RFC 9112 §6.3 rule 1: 1xx, 204, and 304 responses NEVER have a message body,
        // even if Transfer-Encoding: chunked is sent by a broken/malicious upstream.
        let wire_204 = "HTTP/1.1 204 No Content\r\nTransfer-Encoding: chunked\r\n\r\n";
        var res_204 = http::Response { .. };
        let ok_204, consumed_204 = server::parse_http1_wire_response(wire_204, res_204);
        sub.assert_true(ok_204, "204 with Transfer-Encoding: chunked MUST succeed");
        sub.assert_eq(consumed_204, wire_204.len, "consumed exact header bytes");
        sub.assert_eq(res_204.status_code, 204, "status code is 204");
        sub.assert_eq(res_204.body.len, 0, "body must be empty for 204");

        let wire_304 = "HTTP/1.1 304 Not Modified\r\nTransfer-Encoding: chunked\r\n\r\n";
        var res_304 = http::Response { .. };
        let ok_304, consumed_304 = server::parse_http1_wire_response(wire_304, res_304);
        sub.assert_true(ok_304, "304 with Transfer-Encoding: chunked MUST succeed");
        sub.assert_eq(consumed_304, wire_304.len, "consumed exact header bytes");
        sub.assert_eq(res_304.status_code, 304, "status code is 304");
        sub.assert_eq(res_304.body.len, 0, "body must be empty for 304");

        let wire_100 = "HTTP/1.1 100 Continue\r\nTransfer-Encoding: chunked\r\n\r\n";
        var res_100 = http::Response { .. };
        let ok_100, consumed_100 = server::parse_http1_wire_response(wire_100, res_100);
        sub.assert_true(ok_100, "100 Continue with Transfer-Encoding: chunked MUST succeed");
        sub.assert_eq(consumed_100, wire_100.len, "consumed exact header bytes");
        sub.assert_eq(res_100.status_code, 100, "status code is 100");
        sub.assert_eq(res_100.body.len, 0, "body must be empty for 100");
    };

    t.run("parse_http1_wire_response: enforce 8192 byte header block ceiling") { sub =>
        // A response header block exceeding 8192 bytes MUST be rejected
        var huge_resp: u8[>..] = [];
        huge_resp.append("HTTP/1.1 200 OK\r\n");
        while huge_resp.len < 8200 {
            huge_resp.append("X-Padding: 0123456789012345678901234567890123456789\r\n");
        }
        huge_resp.append("\r\n");

        var res = http::Response { .. };
        let ok, _ = server::parse_http1_wire_response(huge_resp[..], res);
        sub.assert_false(ok, "response header block > 8192 bytes MUST be rejected");
    };
}

// ----------------------------------------------------------------------------
// 51. HTTP/1.1 Response Serializer Empty-Status Chunked Bodyless Enforcement
// ----------------------------------------------------------------------------
fn test_http1_response_serialization_empty_status(t: lit::T&) {
    t.run("serialize_http1_response: 204/304 suppresses Transfer-Encoding and chunked body") { sub =>
        // 204 No Content with Transfer-Encoding or trailers requested
        var res_204 = http::Response { .. };
        res_204.status_code = 204;
        http::set_header(res_204, "Transfer-Encoding", "chunked");
        http::add_trailer(res_204, "X-Checksum", "abc");
        res_204.body.append("illegal body data");

        var wire_204: u8[>..] = [];
        server::serialize_http1_response(res_204, "goose-wing/1.0", wire_204);

        sub.assert_contains(wire_204[..], "HTTP/1.1 204 No Content\r\n", "Status line is 204");
        sub.assert_not_contains(wire_204[..], "Transfer-Encoding", "Transfer-Encoding MUST NOT be emitted on 204");
        sub.assert_not_contains(wire_204[..], "Content-Length", "Content-Length MUST NOT be emitted on 204");
        sub.assert_not_contains(wire_204[..], "0\r\n\r\n", "0\\r\\n\\r\\n chunked body MUST NOT be emitted on 204");
        sub.assert_not_contains(wire_204[..], "illegal body data", "body data MUST NOT be emitted on 204");

        // 304 Not Modified
        var res_304 = http::Response { .. };
        res_304.status_code = 304;
        http::set_header(res_304, "Transfer-Encoding", "chunked");
        http::add_trailer(res_304, "X-Checksum", "abc");

        var wire_304: u8[>..] = [];
        server::serialize_http1_response(res_304, "goose-wing/1.0", wire_304);

        sub.assert_contains(wire_304[..], "HTTP/1.1 304 Not Modified\r\n", "Status line is 304");
        sub.assert_not_contains(wire_304[..], "Transfer-Encoding", "Transfer-Encoding MUST NOT be emitted on 304");
        sub.assert_not_contains(wire_304[..], "Content-Length", "Content-Length MUST NOT be emitted on 304");
        sub.assert_not_contains(wire_304[..], "0\r\n\r\n", "chunked body MUST NOT be emitted on 304");
    };

    t.run("serialize_http1_response: 1xx suppresses automatic Content-Length: 0") { sub =>
        var res_100 = http::Response { .. };
        res_100.status_code = 100;

        var wire_100: u8[>..] = [];
        server::serialize_http1_response(res_100, "goose-wing/1.0", wire_100);

        sub.assert_contains(wire_100[..], "HTTP/1.1 100 Continue\r\n", "Status line is 100");
        sub.assert_not_contains(wire_100[..], "Content-Length", "1xx MUST NOT emit Content-Length: 0");
    };
}

// --- Component: regress_issues_batch19 ---
// Phase 19 RED test suite: Reducing Load, DoS Mitigation, RFC Conformance,
// and Protocol Invariants.
//
// 1. Chunk Extension Length Overhead Defense in ChunkFsmDecoder (CVE-2023-39326, Go #64433, RFC 9112 §7.1.1)
// 2. Chunk Trailer Length & Memory Flood Defense in ChunkFsmDecoder (CVE-2023-39326, RFC 9112 §7.1.2)
// 3. TLS 1.3 Cookie Extension Length Validation (RFC 8446 §4.2.2, OpenSSL #30868)
// 4. TLS 1.3 CertificateRequest certificate_authorities Extension Vector Validation (RFC 8446 §4.2.4, OpenSSL #32211)
// 5. Cookie Ingestion Quota Enforcement in Netscape Import (Go #75672, CVE-2025-58186)

// ----------------------------------------------------------------------------
// 52. Chunk Extension Length Overhead Defense (CVE-2023-39326, Go #64433)
// ----------------------------------------------------------------------------
fn test_chunk_fsm_extension_length_defense(t: lit::T&) {
    t.run("ChunkFsmDecoder rejects chunk extension exceeding 1024 bytes") { sub =>
        var dec = http_internal::new_chunk_fsm_decoder();

        // Build chunk header with extension > 1024 bytes: "5;ext=" + 1025 'a's + "\r\nhello\r\n0\r\n\r\n"
        var raw: u8[>..] = [];
        raw.append("5;ext=");
        for _ in 1025 {
            raw.push('a');
        }
        raw.append("\r\nhello\r\n0\r\n\r\n");

        let st, consumed, _ = http_internal::chunk_fsm_feed(dec, raw[..]);
        sub.assert_eq(st, http_internal::ChunkFsmStatus.Error, "Oversized chunk extension must trigger Error");
        sub.assert_eq(dec.state, http_internal::CHUNK_STATE_IS_ERROR, "FSM state must transition to sticky Error");
    };

    t.run("ChunkFsmDecoder accepts valid chunk extension <= 1024 bytes") { sub =>
        var dec = http_internal::new_chunk_fsm_decoder();
        let raw = "5;ext=valid\r\nhello\r\n0\r\n\r\n";
        let st, consumed, chunk = http_internal::chunk_fsm_feed(dec, raw);
        sub.assert_eq(st, http_internal::ChunkFsmStatus.YieldChunk, "Valid chunk extension accepted");
        sub.assert_bytes_eq(chunk, "hello", "Chunk payload yielded correctly");
    };
}

// ----------------------------------------------------------------------------
// 53. Chunk Trailer Length & Memory Flood Defense (CVE-2023-39326, RFC 9112 §7.1.2)
// ----------------------------------------------------------------------------
fn test_chunk_fsm_trailer_flood_defense(t: lit::T&) {
    t.run("ChunkFsmDecoder rejects total trailer bytes exceeding 4096 bytes") { sub =>
        var dec = http_internal::new_chunk_fsm_decoder();

        // Stream final chunk "0\r\n", followed by oversized trailer line > 4096 bytes
        var raw: u8[>..] = [];
        raw.append("0\r\nX-Trailer: ");
        for _ in 4100 {
            raw.push('b');
        }
        raw.append("\r\n\r\n");

        let st, consumed, _ = http_internal::chunk_fsm_feed(dec, raw[..]);
        sub.assert_eq(st, http_internal::ChunkFsmStatus.Error, "Oversized trailers > 4096 bytes must trigger Error");
        sub.assert_eq(dec.state, http_internal::CHUNK_STATE_IS_ERROR, "FSM state must transition to sticky Error");
    };

    t.run("ChunkFsmDecoder accepts legitimate trailers <= 4096 bytes") { sub =>
        var dec = http_internal::new_chunk_fsm_decoder();
        let raw = "0\r\nX-Checksum: deadbeef\r\n\r\n";
        let st, consumed, _ = http_internal::chunk_fsm_feed(dec, raw);
        sub.assert_eq(st, http_internal::ChunkFsmStatus.Complete, "Legitimate trailers succeed with Complete");
    };
}

// ----------------------------------------------------------------------------
// 54. goose2rfc HTTP/1.1, Forwarded, Early Hints & Status Diagnostics Regressions
// ----------------------------------------------------------------------------
fn test_goose2rfc_http1_audit_regressions(t: lit::T&) {
    t.run("RFC 9112 §2.3 & §5.1: Case-sensitive HTTP-name and clean HeaderMap rollback on error") { sub =>
        var map = http::HeaderMap { .. };
        let err_case = http::parse_response_headers("http/1.1 200 OK\r\nContent-Length: 0\r\n\r\n", map);
        sub.assert_eq(err_case, http::HeaderParseError.MalformedStatusLine, "Lowercase http/1.1 MUST be rejected per RFC 9112 §2.3");

        let err_partial = http::parse_response_headers("HTTP/1.1 201 Created\r\nX-Valid: 1\r\nBad Header: 2\r\n\r\n", map);
        sub.assert_eq(err_partial, http::HeaderParseError.InvalidHeaderName, "Invalid second header rejected");
        sub.assert_eq(map.entries.len, 0, "HeaderMap entries MUST be cleared on parse failure");
        sub.assert_eq(map.status_code, 200, "HeaderMap status_code MUST not retain uncommitted status on failure");
        sub.assert_false(map.valid, "HeaderMap valid flag is false on failure");
    };

    t.run("Invariant 5: parse_chunk_ext_quoted_val rolls back cursor on unclosed quote") { sub =>
        var cur: i64 = 4;
        let ok = http::parse_chunk_ext_quoted_val("ext=\"unclosed", cur);
        sub.assert_false(ok, "Unclosed quoted chunk-ext value rejected");
        sub.assert_eq(cur, 4, "Cursor rolled back to initial offset 4 on error");
    };

    t.run("RFC 7239 §4 & RFC 8288 §3: Forwarded and Link parameter grammar & quote balance") { sub =>
        var elem = http::ForwardedElement { .. };
        sub.assert_false(http::parse_forwarded_element("for = 192.0.2.60", elem), "Whitespace around '=' in Forwarded MUST be rejected");
        sub.assert_false(http::parse_forwarded_element("for=\"192.0.2.60", elem), "Unbalanced quote in Forwarded MUST be rejected");
        sub.assert_false(http::parse_forwarded_element("for=[2001:db8::1]", elem), "Unquoted IPv6 brackets in Forwarded MUST be rejected");
        sub.assert_true(http::parse_forwarded_element("for=\"[2001:db8::1]\"", elem), "Quoted IPv6 in Forwarded accepted");

        var links: http::EarlyHintLink[..8] = [];
        sub.assert_false(http::parse_link_header("</a.css>; rel=\"preload", links), "Unbalanced quote in Link rel MUST be rejected");
        sub.assert_eq(links.len, 0, "out_links cleared on Link parse failure");
    };

    t.run("RFC 9211 & RFC 9209: Cache-Status and Proxy-Status single entry cursor/entry rollback") { sub =>
        var idx: i64 = 0;
        var cs = http::CacheStatusEntry { .. };
        sub.assert_false(http::parse_single_cache_status_entry("OriginCache; ttl=bad", idx, cs), "Invalid ttl fails CacheStatusEntry");
        sub.assert_eq(idx, 0, "Cache-Status cursor rolled back to 0");
        sub.assert_eq(cs.cache_name.len, 0, "CacheStatusEntry rolled back on error");

        var p_idx: i64 = 0;
        var ps = http::ProxyStatusEntry { .. };
        sub.assert_false(http::parse_single_proxy_status_entry("edge1; received-status=bad", p_idx, ps), "Invalid received-status fails ProxyStatusEntry");
        sub.assert_eq(p_idx, 0, "Proxy-Status cursor rolled back to 0");
        sub.assert_eq(ps.proxy_name.len, 0, "ProxyStatusEntry rolled back on error");

        var hm = http::HeaderMap { .. };
        sub.assert_true(http::append_header(hm, "www-authenticate", "Bearer realm=\"api\""), "WWW-Authenticate added");
        sub.assert_true(http::is_challenge(hm.entries[0]), "WWW-Authenticate tagged with challenge flag");
    };
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
    lit::run_case(runner, "20. HeaderMap In-Place Compaction & Overwrite", test_headermap_inplace_compaction_and_overwrite);
    lit::run_case(runner, "21. Single Header Cursor", test_single_header_cursor);
    lit::run_case(runner, "22. Multi-Value Header Cursor", test_multi_value_header_cursor);
    lit::run_case(runner, "23. F002 Status Diagnostics Bounds & Safety", test_f002_status_diagnostics_bounds_and_safety);
    lit::run_case(runner, "24. F005 SFV Zero Silent Drops (Invariant 13)", test_f005_sfv_no_silent_dropping);
    lit::run_case(runner, "25. F010 HeaderMap Overflow Spill Smuggling & Bounds", test_f010_headermap_overflow_and_bounds);
    lit::run_case(runner, "26. F011 Perfect Hash Collision & Chunked Trailers", test_f011_perfect_hash_and_chunked_trailers);
    lit::run_case(runner, "27. F017-F023 HeaderMap Arena Obs-Fold, Host Smuggling & Chunked", test_f017_f023_headers_chunked_forwarded);
    lit::run_case(runner, "28. uWebSockets #1949 / RFC 9112 §3.2 Host Header Query & Fragment Rejection", test_host_header_query_fragment_rejection);
    lit::run_case(runner, "29. RFC 9110 §8.6 / uWS #1370 / Go #81642: Status 204 Body Leakage", test_status_204_body_suppression_on_wire);
    lit::run_case(runner, "30. RFC 9110 §7.6.1 & Go #82065: Connection Hop-by-Hop Truncation", test_connection_header_hop_by_hop_token_capacity);
    lit::run_case(runner, "31. Go #81508 & RFC 9110 §14.1.2: Unsupported Range Unit Must Return 200 OK", test_unsupported_range_unit_ignored);
    lit::run_case(runner, "32. RFC 9112 Section 4: Status Line - HTTP Wire Response Status Line Validation (uWS #1949)", test_http1_wire_response_status_line_validation);
    lit::run_case(runner, "33. RFC 9110 §6.5.1 & Go #81143: Disallow Content-Type and Content-Encoding in Trailers", test_forbidden_trailer_fields);
    lit::run_case(runner, "34. RFC 9110 §14.1.2 & Go #81858: Range Requests Exceeding Max Ranges Return 200 OK", test_exceeded_max_ranges_returns_200);
    lit::run_case(runner, "35. RFC 9112 §6.1 & RFC 7230 §3.3.3: Invalid Response Transfer-Encoding Rejection", test_response_invalid_transfer_encoding_rejected);
    lit::run_case(runner, "36. RFC 9112 §3.2.3 & §9.3.6: CONNECT Authority-Form Enforcement", test_connect_authority_form_enforcement);
    lit::run_case(runner, "37. RFC 9112 §7.2 & §9.5: Host Header Multiple Values Rejection", test_host_header_comma_separated_values_rejected);
    lit::run_case(runner, "38. RFC 9112 §7.1: Chunked FSM Bare LF Rejection", test_chunked_fsm_bare_lf_rejection);
    lit::run_case(runner, "39. RFC 9112 §7.1.1: Chunked FSM BWS Before Semicolon", test_chunked_fsm_bws_preceding_semicolon);
    lit::run_case(runner, "40. CVE-2026-42507 & Go #79346: Control Character Sanitization in Diagnostic Error Messages", test_diagnostic_control_character_sanitization);
    lit::run_case(runner, "41. RFC 9110 §15.2 & Go #65035: Excessive 1xx Informational Response Limit Defense", test_informational_1xx_response_limit);
    lit::run_case(runner, "42. RFC 9112 §7.1.1 & Go #82257: Chunk Extension with Bad Whitespace Before Semicolon", test_chunked_bws_before_semicolon);
    lit::run_case(runner, "43. RFC 9112 §7.2 / RFC 3986 §3.2.2 & uWS #1949: HTTP/1.1 Host Header Validation", test_h1_host_header_validation_and_duplicates);
    lit::run_case(runner, "44. SFV string overflow rejection (http/mime.goose)", test_sfv_string_overflow_rejection);
    lit::run_case(runner, "45. SFV capacity smuggling rejection (http/mime.goose)", test_sfv_capacity_smuggling_rejection);
    lit::run_case(runner, "46. HTTP/1.x obs-fold capacity safety (http/headers.goose)", test_http_headers_obs_fold_capacity_safety);
    lit::run_case(runner, "47. Chunked FSM & extensions RFC 9112 (http/headers/*)", test_chunked_fsm_and_extensions_rfc9112);
    lit::run_case(runner, "48. HTTP/1.x headers CL, host, cookie bounds (http/headers/*)", test_http1_headers_cl_host_and_cookie_bounds);
    lit::run_case(runner, "49. HTTP Chunked FSM invariants (http/headers/chunked_fsm.goose)", test_chunked_fsm_invariants);
    lit::run_case(runner, "50. HTTP/1.1 Wire Response Parser 204/304/1xx Chunked Desync & Header Block Cap", test_http1_wire_response_204_304_1xx_framing);
    lit::run_case(runner, "51. HTTP/1.1 Response Serializer Empty-Status Chunked Bodyless Enforcement", test_http1_response_serialization_empty_status);
    lit::run_case(runner, "52. Chunk Extension Length Overhead Defense", test_chunk_fsm_extension_length_defense);
    lit::run_case(runner, "53. Chunk Trailer Length Flood Defense", test_chunk_fsm_trailer_flood_defense);
    lit::run_case(runner, "54. goose2rfc HTTP/1.1, Forwarded, Early Hints & Status Diagnostics Regressions", test_goose2rfc_http1_audit_regressions);

    let ok = lit::finish(runner);
    assert(ok);
}
