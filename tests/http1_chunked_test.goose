// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Verification suite for RFC 9112 Section 7 (Chunked Transfer Coding & Trailers)
// 1. One-Shot Chunked Decoding with Trailer Extraction
// 2. RFC 9112 Smuggling & Desynchronization Defenses (Bare LF, Bounds, Disallowed Trailers)
// 3. Incremental Chunked Stream Decoder (Fragmented & Torture Stream Feeding)
// 4. HttpServer Ingress with Chunked Framing & Smuggling Guards (TE/CL Conflict)
// 5. Server Chunked Response Serialization & Symmetrical Response Wire Parser
import std;
import core from "..";
import wing from "..";

// ----------------------------------------------------------------------------
// 1. One-Shot Chunked Decoding with Trailer Extraction
// ----------------------------------------------------------------------------
fn test_oneshot_chunked_trailers(t: core::T&) {
    t.run("Single and multi-chunk decoding with byte count accuracy") { sub =>
        let raw = "4\r\nWiki\r\n6\r\n pedia\r\n0\r\n\r\n";
        var out_body: u8[>..] = [];
        var out_trailers: wing::HeaderItem[..16] = [];

        let err, consumed = wing::decode_chunked_body_with_trailers(raw, out_body, out_trailers);
        sub.assert_eq(err, wing::ChunkedDecodeError.None, "Decoded successfully");
        sub.assert_bytes_eq(out_body[..], "Wiki pedia", "Body reassembled");
        sub.assert_eq(consumed, raw.len, "All raw bytes consumed");
        sub.assert_eq(out_trailers.len, 0, "No trailers in simple message");
    };

    t.run("Chunk extension ignored and parsed cleanly") { sub =>
        let raw = "5;ext_name=ext_value;flag\r\nHello\r\n0;last=1\r\n\r\n";
        var out_body: u8[>..] = [];
        var out_trailers: wing::HeaderItem[..16] = [];

        let err, consumed = wing::decode_chunked_body_with_trailers(raw, out_body, out_trailers);
        sub.assert_eq(err, wing::ChunkedDecodeError.None, "Decoded successfully with extensions");
        sub.assert_bytes_eq(out_body[..], "Hello", "Body matches");
        sub.assert_eq(consumed, raw.len, "Exact length consumed");
    };

    t.run("Extraction of multiple custom trailers") { sub =>
        let raw = "5\r\nHello\r\n0\r\nExpires: Wed, 21 Oct 2026 07:28:00 GMT\r\nX-Checksum: sha256-abc123xyz\r\nX-Timing: dur=15.4\r\n\r\n";
        var out_body: u8[>..] = [];
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
        var out_body: u8[>..] = [];
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
fn test_chunked_smuggling_defenses(t: core::T&) {
    t.run("Bare LF in chunk size rejection (CVE-2025-22871)") { sub =>
        var out_body: u8[>..] = [];
        var out_trailers: wing::HeaderItem[..16] = [];

        let raw = "4\nWiki\r\n0\r\n\r\n";
        let err, _ = wing::decode_chunked_body_with_trailers(raw, out_body, out_trailers);
        sub.assert_eq(err, wing::ChunkedDecodeError.BareLfInChunkSize, "Bare LF in chunk size rejected");
    };

    t.run("Bare LF in chunk data terminator rejection") { sub =>
        var out_body: u8[>..] = [];
        var out_trailers: wing::HeaderItem[..16] = [];

        let raw = "4\r\nWiki\n0\r\n\r\n";
        let err, _ = wing::decode_chunked_body_with_trailers(raw, out_body, out_trailers);
        sub.assert_eq(err, wing::ChunkedDecodeError.BareLfInChunkData, "Bare LF after chunk data rejected");
    };

    t.run("Bare LF in chunk data terminator at exact buffer end") { sub =>
        var out_body: u8[>..] = [];
        var out_trailers: wing::HeaderItem[..16] = [];

        let raw = "4\r\nWiki\n";
        let err, _ = wing::decode_chunked_body_with_trailers(raw, out_body, out_trailers);
        sub.assert_eq(err, wing::ChunkedDecodeError.BareLfInChunkData, "Bare LF at buffer boundary rejected");
    };

    t.run("Bare LF in trailer line rejection") { sub =>
        var out_body: u8[>..] = [];
        var out_trailers: wing::HeaderItem[..16] = [];

        let raw = "4\r\nWiki\r\n0\r\nX-Check: val\n\r\n";
        let err, _ = wing::decode_chunked_body_with_trailers(raw, out_body, out_trailers);
        sub.assert_eq(err, wing::ChunkedDecodeError.BareLfInTrailer, "Bare LF in trailer header rejected");
    };

    t.run("Bare LF terminating trailer section rejection") { sub =>
        var out_body: u8[>..] = [];
        var out_trailers: wing::HeaderItem[..16] = [];

        let raw = "0\r\n\n";
        let err, _ = wing::decode_chunked_body_with_trailers(raw, out_body, out_trailers);
        sub.assert_eq(err, wing::ChunkedDecodeError.BareLfInTrailer, "Bare LF ending trailers rejected");
    };

    t.run("RFC 9110 Section 6.5.1: Comprehensive Forbidden Trailer Fields Enforcement") { sub =>
        var out_body: u8[>..] = [];
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
        var out_body: u8[>..] = [];
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
        var out_body: u8[>..] = [];
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
        var out_body: u8[>..] = [];
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
fn test_incremental_chunked_stream_decoder(t: core::T&) {
    t.run("Torture 1-byte incremental feeding") { sub =>
        let wire = "5\r\nHello\r\n6\r\n World\r\n0\r\nX-Checksum: c89a\r\n\r\n";
        var dec = wing::new_chunked_stream_decoder();
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
        var dec = wing::new_chunked_stream_decoder();
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
        var dec = wing::new_chunked_stream_decoder();
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
fn test_httpserver_chunked_ingress(t: core::T&) {
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
fn test_chunked_response_and_wire_parser(t: core::T&) {
    t.run("Server response serialization automatically chunks when trailers present") { sub =>
        var res = wing::new_response();
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
        var parsed_res = wing::new_response();
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
        var body_data: u8[..64] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
        var trs: wing::HeaderItem[..16] = [];
        var item = wing::HeaderItem { .. };
        item.name.append("X-Complete");
        item.value.append("true");
        trs.push(item);

        var encoded_wire: u8[>..] = [];
        wing::encode_chunked_payload(body_data[..], trs, 10, encoded_wire);

        var parsed_body: u8[>..] = [];
        var parsed_trs: wing::HeaderItem[..16] = [];
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
        var res = wing::new_response();
        let ok_parse, consumed = wing::parse_http1_wire_response(wire_dual, res);
        sub.assert_true(ok_parse, "Dual TE+CL in response parsed cleanly (TE overrides CL)");
        sub.assert_bytes_eq(res.body[..], "hello", "Body decoded from chunked");
        sub.assert_false(wing::has_header(res, "content-length"), "Content-Length header MUST be stripped per RFC 9112 Section 6.1");
    };
}

// ----------------------------------------------------------------------------
// Suite Runner
// ----------------------------------------------------------------------------
fn main() {
    let _ = wing::tcp_init();
    var runner = core::new_runner("RFC 9112 Chunked Transfer & Trailers Suite", core::Verbosity.Verbose);

    core::run_case(runner, "1. One-Shot Chunked Decoding with Trailer Extraction", test_oneshot_chunked_trailers);
    core::run_case(runner, "2. RFC 9112 Smuggling & Desynchronization Defenses", test_chunked_smuggling_defenses);
    core::run_case(runner, "3. Incremental Chunked Stream Decoder", test_incremental_chunked_stream_decoder);
    core::run_case(runner, "4. HttpServer Ingress with Chunked Framing & Smuggling Guards", test_httpserver_chunked_ingress);
    core::run_case(runner, "5. Server Chunked Response Serialization & Symmetrical Response Wire Parser", test_chunked_response_and_wire_parser);

    let ok = core::finish(runner);
    assert(ok);
}
