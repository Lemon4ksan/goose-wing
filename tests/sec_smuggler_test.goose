// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Tests for request smuggling defenses and chunked transfer decoding (RFC 9112).
import std;
import core from "..";
import wing from "..";

fn test_te_cl_request_smuggling_defense(t: core::T&) {
    t.run("SMUGGLE-01: Conflicting Transfer-Encoding and Content-Length (TE.CL / CL.TE) Rejection") { sub =>
        // TE then CL
        var map1 = wing::new_header_map();
        let raw_te_cl = "Transfer-Encoding: chunked\r\nContent-Length: 42\r\n\r\n";
        let err1 = wing::parse_headers(raw_te_cl, map1);
        sub.assert_eq(err1, wing::HeaderParseError.InvalidContentLength, "TE followed by CL must fail with InvalidContentLength per RFC 9112 Section 6.3");
        sub.assert_false(map1.valid, "Map must be marked invalid on TE/CL conflict");

        // CL then TE
        var map2 = wing::new_header_map();
        let raw_cl_te = "Content-Length: 42\r\nTransfer-Encoding: chunked\r\n\r\n";
        let err2 = wing::parse_headers(raw_cl_te, map2);
        sub.assert_eq(err2, wing::HeaderParseError.InvalidContentLength, "CL followed by TE must fail with InvalidContentLength per RFC 9112 Section 6.3");
        sub.assert_false(map2.valid, "Map must be marked invalid on CL/TE conflict");
    };

    t.run("SMUGGLE-02: Duplicate Differing Content-Length Rejection (CL.CL)") { sub =>
        var map = wing::new_header_map();
        let raw_diff_cl = "Content-Length: 10\r\nContent-Length: 20\r\n\r\n";
        let err = wing::parse_headers(raw_diff_cl, map);
        sub.assert_eq(err, wing::HeaderParseError.InvalidContentLength, "Duplicate differing Content-Length must be rejected");
        sub.assert_false(map.valid, "Map must be marked invalid on duplicate differing Content-Length");
    };

    t.run("SMUGGLE-03: Negative Content-Length Rejection") { sub =>
        var map = wing::new_header_map();
        let raw_neg = "Content-Length: -5\r\n\r\n";
        let err = wing::parse_headers(raw_neg, map);
        sub.assert_eq(err, wing::HeaderParseError.InvalidContentLength, "Negative Content-Length must be rejected");
        sub.assert_false(map.valid, "Map must be marked invalid on negative Content-Length");
    };

    t.run("SMUGGLE-04: Non-Digit Characters in Content-Length Rejection") { sub =>
        // Suffix alphanumeric
        var map1 = wing::new_header_map();
        let raw_alpha = "Content-Length: 12abc\r\n\r\n";
        let err1 = wing::parse_headers(raw_alpha, map1);
        sub.assert_eq(err1, wing::HeaderParseError.InvalidContentLength, "Alpha characters in Content-Length must be rejected");

        // Explicit positive sign '+'
        var map2 = wing::new_header_map();
        let raw_plus = "Content-Length: +10\r\n\r\n";
        let err2 = wing::parse_headers(raw_plus, map2);
        sub.assert_eq(err2, wing::HeaderParseError.InvalidContentLength, "Plus sign in Content-Length must be rejected");

        // Decimal dot
        var map3 = wing::new_header_map();
        let raw_dot = "Content-Length: 10.5\r\n\r\n";
        let err3 = wing::parse_headers(raw_dot, map3);
        sub.assert_eq(err3, wing::HeaderParseError.InvalidContentLength, "Decimal dot in Content-Length must be rejected");

        // Empty value
        var map4 = wing::new_header_map();
        let raw_empty = "Content-Length:\r\n\r\n";
        let err4 = wing::parse_headers(raw_empty, map4);
        sub.assert_eq(err4, wing::HeaderParseError.InvalidContentLength, "Empty Content-Length must be rejected");
    };

    t.run("SMUGGLE-05: Content-Length 64-bit Overflow Rejection") { sub =>
        var map = wing::new_header_map();
        // 30-digit integer overflow
        let raw_ovf = "Content-Length: 999999999999999999999999999999\r\n\r\n";
        let err = wing::parse_headers(raw_ovf, map);
        sub.assert_eq(err, wing::HeaderParseError.InvalidContentLength, "Overflowing Content-Length must be rejected");
        sub.assert_false(map.valid, "Map must be marked invalid on overflowing Content-Length");
    };

    t.run("SMUGGLE-06: Comma-Separated Differing Content-Length Rejection") { sub =>
        var map = wing::new_header_map();
        let raw_comma = "Content-Length: 15, 30\r\n\r\n";
        let err = wing::parse_headers(raw_comma, map);
        sub.assert_eq(err, wing::HeaderParseError.InvalidContentLength, "Differing comma-separated Content-Length must be rejected");
    };

    t.run("SMUGGLE-07: Duplicate Transfer-Encoding Headers Rejection") { sub =>
        var map = wing::new_header_map();
        let raw_dup_te = "Transfer-Encoding: chunked\r\nTransfer-Encoding: gzip\r\n\r\n";
        let err = wing::parse_headers(raw_dup_te, map);
        sub.assert_eq(err, wing::HeaderParseError.InvalidContentLength, "Duplicate Transfer-Encoding headers must be rejected");
    };

    t.run("SMUGGLE-08: Valid Content-Length Acceptance & Identical Duplicate Folding") { sub =>
        // Valid Content-Length: 0
        var map1 = wing::new_header_map();
        let raw_zero = "Content-Length: 0\r\n\r\n";
        let err1 = wing::parse_headers(raw_zero, map1);
        sub.assert_eq(err1, wing::HeaderParseError.None, "Content-Length: 0 is valid");
        sub.assert_true(map1.valid, "Map must be valid");

        // Valid Content-Length: 1024
        var map2 = wing::new_header_map();
        let raw_valid = "Content-Length: 1024\r\n\r\n";
        let err2 = wing::parse_headers(raw_valid, map2);
        sub.assert_eq(err2, wing::HeaderParseError.None, "Content-Length: 1024 is valid");
        sub.assert_bytes_eq(wing::get_header(map2, "content-length"), "1024", "Header retrieved correctly");

        // Duplicate IDENTICAL Content-Length per RFC 9112 Section 6.3
        var map3 = wing::new_header_map();
        let raw_dup_same = "Content-Length: 42\r\nContent-Length: 42\r\n\r\n";
        let err3 = wing::parse_headers(raw_dup_same, map3);
        sub.assert_eq(err3, wing::HeaderParseError.None, "Duplicate identical Content-Length must be accepted per RFC 9112 Section 6.3");
        sub.assert_bytes_eq(wing::get_header(map3, "content-length"), "42", "Single unified value retrieved");
    };

    t.run("SMUGGLE-09: obs-fold on Content-Length Rejection") { sub =>
        var map = wing::new_header_map();
        // Even in allow_obs_fold=true compatibility mode, obs-fold on Content-Length must be rejected
        let raw_fold_cl = "Content-Length: 10\r\n 20\r\n\r\n";
        let err = wing::parse_headers(raw_fold_cl, map, true);
        sub.assert_eq(err, wing::HeaderParseError.InvalidContentLength, "obs-fold on Content-Length must be rejected");
        sub.assert_false(map.valid, "Map must be invalid");
    };

    t.run("SMUGGLE-10: Space Before Colon in Header Name Rejection ") { sub =>
        var map1 = wing::new_header_map();
        let raw1 = "Content-Length : 10\r\n\r\n";
        let err1 = wing::parse_headers(raw1, map1);
        sub.assert_eq(err1, wing::HeaderParseError.InvalidHeaderName, "Space before colon in Content-Length must be rejected per RFC 7230 Section 3.2.4");

        var map2 = wing::new_header_map();
        let raw2 = "Transfer-Encoding : chunked\r\n\r\n";
        let err2 = wing::parse_headers(raw2, map2);
        sub.assert_eq(err2, wing::HeaderParseError.InvalidHeaderName, "Space before colon in Transfer-Encoding must be rejected");

        var map3 = wing::new_header_map();
        let raw3 = "X-Foo : bar\r\n\r\n";
        let err3 = wing::parse_headers(raw3, map3);
        sub.assert_eq(err3, wing::HeaderParseError.InvalidHeaderName, "Space before colon in general header must be rejected");
    };

    t.run("SMUGGLE-11: Tab Before Colon in Header Name Rejection") { sub =>
        var map = wing::new_header_map();
        let raw = "Content-Length\t: 10\r\n\r\n";
        let err = wing::parse_headers(raw, map);
        sub.assert_eq(err, wing::HeaderParseError.InvalidHeaderName, "Tab before colon must be rejected as InvalidHeaderName");
    };

    t.run("SMUGGLE-12: CR or CTL Injection in Transfer-Encoding ") { sub =>
        var map1 = wing::new_header_map();
        let raw1 = "Transfer-Encoding: \rchunked\r\n\r\n";
        let err1 = wing::parse_headers(raw1, map1);
        sub.assert_ne(err1, wing::HeaderParseError.None, "Bare CR in header splits line into invalid header line without colon");
        sub.assert_false(map1.valid, "Map must be invalid on bare CR injection");

        var map2 = wing::new_header_map();
        let raw2 = "Transfer-Encoding: chunked\x01\r\n\r\n";
        let err2 = wing::parse_headers(raw2, map2);
        sub.assert_eq(err2, wing::HeaderParseError.InvalidHeaderValue, "CTL character in Transfer-Encoding must be rejected");
        sub.assert_false(map2.valid, "Map must be invalid on CTL injection");
    };

    t.run("SMUGGLE-13: Multiple Identical Content-Length Folded ") { sub =>
        var map = wing::new_header_map();
        let raw = "Content-Length: 128\r\nContent-Length: 128\r\nContent-Length: 128\r\n\r\n";
        let err = wing::parse_headers(raw, map);
        sub.assert_eq(err, wing::HeaderParseError.None, "Triple identical Content-Length must be accepted per RFC 9112 Section 6.3");
        sub.assert_bytes_eq(wing::get_header(map, "content-length"), "128", "Single folded value retrieved");
    };

    t.run("SMUGGLE-14: HTTP/2 Malformed Framing Protection Against Smuggling into HTTP/1 (CVE-2026-78660)") { sub =>
        // Differing comma-separated values
        var map1 = wing::new_header_map();
        let raw1 = "Content-Length: 10, 20\r\n\r\n";
        let err1 = wing::parse_headers(raw1, map1);
        sub.assert_eq(err1, wing::HeaderParseError.InvalidContentLength, "Differing comma-delimited Content-Length rejected");

        // Duplicate differing values
        var map2 = wing::new_header_map();
        let raw2 = "Content-Length: 0\r\nContent-Length: 5\r\n\r\n";
        let err2 = wing::parse_headers(raw2, map2);
        sub.assert_eq(err2, wing::HeaderParseError.InvalidContentLength, "Duplicate differing Content-Length rejected");
    };

    t.run("SMUGGLE-15: Content-Length Validation When Transfer-Encoding Present ") { sub =>
        var map1 = wing::new_header_map();
        let raw1 = "Transfer-Encoding: chunked\r\nContent-Length: invalid_num\r\n\r\n";
        let err1 = wing::parse_headers(raw1, map1);
        sub.assert_eq(err1, wing::HeaderParseError.InvalidContentLength, "TE with invalid CL rejected");

        var map2 = wing::new_header_map();
        let raw2 = "Transfer-Encoding: chunked\r\nContent-Length: 0\r\n\r\n";
        let err2 = wing::parse_headers(raw2, map2);
        sub.assert_eq(err2, wing::HeaderParseError.InvalidContentLength, "TE with CL:0 rejected");
    };
}

fn test_chunked_encoding_bare_lf_defense(t: core::T&) {
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
        sub.assert_eq(err1, wing::ChunkedDecodeError.InvalidChunkSizeHex, "17-digit chunk size must be rejected");

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
        var out_body: u8[>..] = [];
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
        var huge_tr: u8[>..] = [];
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

fn test_hop_by_hop_stripping_defense(t: core::T&) {
    t.run("HOP-01: Standard Hop-by-Hop Headers Stripped (RFC 9110 Section 7.6.1)") { sub =>
        var src = wing::new_header_map();
        let raw = "Host: example.com\r\nConnection: close\r\nKeep-Alive: timeout=5, max=100\r\nProxy-Authenticate: Basic\r\nProxy-Authorization: Basic abc\r\nTE: trailers\r\nTrailer: X-Checksum\r\nTransfer-Encoding: chunked\r\nUpgrade: websocket\r\nProxy-Connection: keep-alive\r\nContent-Type: application/json\r\nAuthorization: Bearer token123\r\n\r\n";
        let p_err = wing::parse_headers(raw, src);
        sub.assert_eq(p_err, wing::HeaderParseError.None, "Source headers parsed ok");

        var dst = wing::new_header_map();
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
        var src = wing::new_header_map();
        let raw = "Host: api.internal\r\nConnection: close, X-Custom-Hop, X-Internal-Token\r\nX-Custom-Hop: sensitive_gateway_data\r\nX-Internal-Token: secret999\r\nX-Preserve-Me: public_data\r\n\r\n";
        wing::parse_headers(raw, src);

        var dst = wing::new_header_map();
        wing::strip_hop_by_hop_headers(src, dst);

        sub.assert_false(wing::has_header(dst, "connection"), "Connection header stripped");
        sub.assert_false(wing::has_header(dst, "x-custom-hop"), "X-Custom-Hop dynamically stripped");
        sub.assert_false(wing::has_header(dst, "x-internal-token"), "X-Internal-Token dynamically stripped");
        sub.assert_true(wing::has_header(dst, "x-preserve-me"), "X-Preserve-Me preserved");
        sub.assert_bytes_eq(wing::get_header(dst, "x-preserve-me"), "public_data", "Value intact");
    };

    t.run("HOP-03: Empty Connection Header Does Not Block Subsequent Stripping ") { sub =>
        var src = wing::new_header_map();
        // First Connection header is empty, second specifies sensitive custom header
        let raw = "Host: example.com\r\nConnection:\r\nConnection: close, X-Secret-Hop\r\nX-Secret-Hop: leaked_token\r\nContent-Type: text/plain\r\n\r\n";
        wing::parse_headers(raw, src);

        var dst = wing::new_header_map();
        wing::strip_hop_by_hop_headers(src, dst);

        sub.assert_false(wing::has_header(dst, "connection"), "Connection headers stripped");
        sub.assert_false(wing::has_header(dst, "x-secret-hop"), "X-Secret-Hop stripped despite empty first Connection header");
        sub.assert_true(wing::has_header(dst, "content-type"), "Content-Type preserved");
    };

    t.run("HOP-04: Multiple Comma-Separated Connection Headers ") { sub =>
        var src = wing::new_header_map();
        // Multiple Connection headers with multiple tokens
        let raw = "Host: example.com\r\nConnection: keep-alive, X-Hop-One\r\nConnection: X-Hop-Two, X-Hop-Three\r\nX-Hop-One: v1\r\nX-Hop-Two: v2\r\nX-Hop-Three: v3\r\nX-Retained: keep_this\r\n\r\n";
        wing::parse_headers(raw, src);

        var dst = wing::new_header_map();
        wing::strip_hop_by_hop_headers(src, dst);

        sub.assert_false(wing::has_header(dst, "x-hop-one"), "X-Hop-One stripped");
        sub.assert_false(wing::has_header(dst, "x-hop-two"), "X-Hop-Two stripped");
        sub.assert_false(wing::has_header(dst, "x-hop-three"), "X-Hop-Three stripped");
        sub.assert_true(wing::has_header(dst, "x-retained"), "X-Retained preserved");
    };

    t.run("HOP-05: Case-Insensitive & Whitespace-Tolerant Token Stripping") { sub =>
        var src = wing::new_header_map();
        let raw = "Host: example.com\r\nConnection: \t  x-foo  ,\t X-BAR \t\r\nX-FOO: val1\r\nx-bar: val2\r\nX-Normal: val3\r\n\r\n";
        wing::parse_headers(raw, src);

        var dst = wing::new_header_map();
        wing::strip_hop_by_hop_headers(src, dst);

        sub.assert_false(wing::has_header(dst, "x-foo"), "X-FOO stripped case-insensitively");
        sub.assert_false(wing::has_header(dst, "x-bar"), "x-bar stripped case-insensitively");
        sub.assert_true(wing::has_header(dst, "x-normal"), "X-Normal retained");
    };

    t.run("HOP-06: Hop-by-Hop Stripping on 1xx Informational Responses (CVE-2021-33197)") { sub =>
        var src_1xx = wing::new_header_map();
        let raw_1xx = "Link: </style.css>; rel=preload\r\nConnection: close, X-Early-Hop\r\nX-Early-Hop: forbidden_hint\r\nKeep-Alive: timeout=10\r\n\r\n";
        wing::parse_headers(raw_1xx, src_1xx);

        var dst_1xx = wing::new_header_map();
        wing::strip_hop_by_hop_headers(src_1xx, dst_1xx);

        sub.assert_true(wing::has_header(dst_1xx, "link"), "Link header retained on 1xx");
        sub.assert_false(wing::has_header(dst_1xx, "connection"), "Connection stripped on 1xx");
        sub.assert_false(wing::has_header(dst_1xx, "keep-alive"), "Keep-Alive stripped on 1xx");
        sub.assert_false(wing::has_header(dst_1xx, "x-early-hop"), "Custom hop token stripped on 1xx");
    };
}

fn test_url_quadratic_backtrack_defense(t: core::T&) {
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

fn test_sfv_integer_overflow_guard(t: core::T&) {
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

fn main() {
    var runner = core::new_runner("Request Smuggling Defenses Suite", core::Verbosity.Verbose);

    core::run_case(runner, "1. TE/CL Request Smuggling & Content-Length Poisoning Defense", test_te_cl_request_smuggling_defense);
    core::run_case(runner, "2. Chunked Encoding & Bare LF Smuggling Defense (CVE-2025-22871)", test_chunked_encoding_bare_lf_defense);
    core::run_case(runner, "3. Hop-by-Hop Header Stripping & Gateway Isolation (RFC 9110 Section 7.6.1)", test_hop_by_hop_stripping_defense);
    core::run_case(runner, "4. URL Path Backtrack Quadratic Complexity Defense (CVE-2026-56860)", test_url_quadratic_backtrack_defense);
    core::run_case(runner, "5. SFV Integer & Decimal 64-Bit Overflow Protection", test_sfv_integer_overflow_guard);

    let ok = core::finish(runner);
    assert(ok);
}
