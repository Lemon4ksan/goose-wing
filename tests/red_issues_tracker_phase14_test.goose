// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Phase 14 RED test suite: RFC Protocol Invariants, Trailer Filtering,
// UTF-8 Truncation Boundaries, Sticky FSM Error States, and Codec Quota Guards.
//
// 1. HTTP/2 Response Trailers Filtering & HPACK Encoding (server/h2_multiplexer.goose)
// 2. WebSocket Close UTF-8 Boundary Truncation & Subprotocol Lists (realtime/websocket.goose)
// 3. HTTP Chunked 64-bit FSM Error Stickiness, Bare CR & Trailer Invariants (http/headers/chunked_fsm.goose)
// 4. Zstandard RFC 8878 RLE Block, SizeMismatch & 0-Sequence Bomb Guards (core/compress/zstd.goose)
// 5. Deflate RFC 1951 Dynamic Huffman Missing EOB 256 Rejection (core/compress/deflate.goose)

import std;
import core from "..";
import wing from "..";

// ----------------------------------------------------------------------------
// 1. HTTP/2 Response Trailers Filtering & HPACK Encoding
// ----------------------------------------------------------------------------
fn test_h2_multiplexer_trailers(t: core::T&) {
    t.run("emit_response_trailers filters pseudo-headers, hop-by-hop, and disallowed fields") { sub =>
        var sess = wing::new_h2_server_session("goose-wing/1.0", 1000);
        var trailers: wing::HeaderItem[..16] = [];

        // Valid trailers
        trailers.push(wing::make_header("x-checksum", "sha256-abc"));
        trailers.push(wing::make_header("x-duration", "15ms"));

        // Forbidden pseudo-headers and connection headers per RFC 9113 §8.1 / §8.2.2
        trailers.push(wing::make_header(":status", "200"));
        trailers.push(wing::make_header("connection", "close"));
        trailers.push(wing::make_header("transfer-encoding", "chunked"));
        trailers.push(wing::make_header("content-length", "42"));
        trailers.push(wing::make_header("host", "example.com"));

        var out_wire: u8[>..] = [];
        wing::emit_response_trailers(sess, 1, trailers, out_wire);

        sub.assert_gt(out_wire.len, 9, "Trailers frame emitted");

        // Parse frame header
        let hdr, ok_hdr = wing::parse_frame_header(out_wire[..9], 16384);
        sub.assert_eq(ok_hdr, wing::ERR_NO_ERROR, "Frame header valid");
        sub.assert_eq(hdr.frame_type, wing::FRAME_HEADERS, "Type is HEADERS");
        sub.assert_eq(hdr.stream_id, 1, "Stream ID is 1");
        sub.assert_true((hdr.flags & wing::FLAG_END_HEADERS) != 0, "FLAG_END_HEADERS set");
        sub.assert_true((hdr.flags & wing::FLAG_END_STREAM) != 0, "FLAG_END_STREAM set");

        // Decode HPACK payload
        var dec_list = wing::DecodedH2HeaderList { .. };
        let dec_err = wing::decode_hpack_header_block(sess.conn.hpack_dec, out_wire[9..9 + (hdr.length as i64)], dec_list);
        sub.assert_eq(dec_err, wing::ERR_NO_ERROR, "HPACK block decoded");

        // Exactly 2 valid trailer headers should survive
        sub.assert_eq(dec_list.fields.len, 2, "Only 2 valid trailers encoded");
        sub.assert_bytes_eq(dec_list.fields[0].name[..], "x-checksum", "First trailer name");
        sub.assert_bytes_eq(dec_list.fields[0].value[..], "sha256-abc", "First trailer value");
        sub.assert_bytes_eq(dec_list.fields[1].name[..], "x-duration", "Second trailer name");
        sub.assert_bytes_eq(dec_list.fields[1].value[..], "15ms", "Second trailer value");
    };

    t.run("handle_h2_server_ingress emits response with body and trailers") { sub =>
        var sess = wing::new_h2_server_session("goose-wing/1.0", 1000);
        var pipeline = wing::new_server_pipeline_config("127.0.0.1", wing::new_gcra_quota(1000, core::secs(1), 100));
        var timer = internal::new_connection_timer(30000000000, 1000000000);

        var wire_in: u8[>..] = [];
        wire_in.append(wing::H2_CLIENT_PREFACE[..]);

        // Client request on stream 1
        var hpack_block: u8[>..] = [];
        var dt = wing::new_dynamic_table(4096);
        wing::encode_hpack_field(dt, hpack_block, ":method", "GET", true, false);
        wing::encode_hpack_field(dt, hpack_block, ":scheme", "https", true, false);
        wing::encode_hpack_field(dt, hpack_block, ":path", "/test", true, false);

        let req_hdr = wing::FrameHeader {
            length: hpack_block.len as u32,
            frame_type: wing::FRAME_HEADERS,
            flags: wing::FLAG_END_HEADERS | wing::FLAG_END_STREAM,
            stream_id: 1,
        };
        wing::encode_frame_header_to(req_hdr, wire_in);
        wire_in.append(hpack_block[..]);

        var out_wire: u8[>..] = [];
        let consumed, ok = wing::handle_h2_server_ingress(sess, pipeline, timer, "127.0.0.1", wire_in[..], 1000, out_wire);
        sub.assert_true(ok, "Ingress handled cleanly");
        sub.assert_gt(consumed, 0, "Ingress bytes consumed");
        sub.assert_gt(out_wire.len, 0, "Server produced response");
    };
}

// ----------------------------------------------------------------------------
// 2. WebSocket Close UTF-8 Boundary Truncation & Subprotocol Lists
// ----------------------------------------------------------------------------
fn test_websocket_close_and_subprotocol(t: core::T&) {
    t.run("encode_close_payload preserves UTF-8 integrity on 123-byte boundary") { sub =>
        // Build reason string of 122 ASCII 'A's + 3-byte Euro sign '€' (0xE2, 0x82, 0xAC)
        var reason: u8[>..] = [];
        for i in 122 {
            reason.push('A');
        }
        reason.push(0xE2);
        reason.push(0x82);
        reason.push(0xAC); // Total 125 bytes

        var out: u8[>..] = [];
        wing::encode_close_payload(out, wing::WS_STATUS_NORMAL, reason[..]);

        sub.assert_eq(out.len, 2 + 122, "Status code (2B) + truncated reason (122B)");
        let code, reason_slice, ok_parse = wing::parse_close_payload(out[..]);
        sub.assert_true(ok_parse, "Parse close payload succeeds");
        sub.assert_eq(code, wing::WS_STATUS_NORMAL, "Code matches 1000");
        sub.assert_true(core::validate_utf8(reason_slice), "Truncated reason must be strictly valid UTF-8");
        sub.assert_eq(reason_slice.len, 122, "Euro symbol split across 123B was peeled back cleanly");
    };

    t.run("encode_close_payload keeps 3-byte UTF-8 char when ending exactly at 123") { sub =>
        // 120 ASCII + 3-byte '€' at indices 120..122 -> fits exactly in 123 bytes!
        var reason: u8[>..] = [];
        for i in 120 {
            reason.push('A');
        }
        reason.push(0xE2);
        reason.push(0x82);
        reason.push(0xAC);
        reason.push('Z'); // byte 123 (would be 124th byte)

        var out: u8[>..] = [];
        wing::encode_close_payload(out, wing::WS_STATUS_NORMAL, reason[..]);

        sub.assert_eq(out.len, 2 + 123, "Status code (2B) + 123B reason");
        let _, reason_slice, ok_parse = wing::parse_close_payload(out[..]);
        sub.assert_true(ok_parse, "Parse succeeds");
        sub.assert_true(core::validate_utf8(reason_slice), "Valid UTF-8");
        sub.assert_eq(reason_slice[120], 0xE2, "Euro byte 0");
        sub.assert_eq(reason_slice[121], 0x82, "Euro byte 1");
        sub.assert_eq(reason_slice[122], 0xAC, "Euro byte 2");
    };

    t.run("has_subprotocol_token parses comma-separated lists with whitespace") { sub =>
        let list = "graphql-ws,  chat.v2 , json-rpc";
        sub.assert_true(wing::has_subprotocol_token(list, "graphql-ws"), "Matches first token");
        sub.assert_true(wing::has_subprotocol_token(list, "chat.v2"), "Matches trimmed token");
        sub.assert_true(wing::has_subprotocol_token(list, "json-rpc"), "Matches last token");
        sub.assert_false(wing::has_subprotocol_token(list, "chat"), "Rejects partial prefix");
        sub.assert_false(wing::has_subprotocol_token(list, "graphql"), "Rejects partial prefix");
    };

    t.run("ws_upgrade_request checks multiple Sec-WebSocket-Protocol headers") { sub =>
        var req = wing::new_request("GET", "https://example.com/ws");
        req.set_header("Host", "example.com");
        req.set_header("Upgrade", "websocket");
        req.set_header("Connection", "Upgrade");
        req.set_header("Sec-WebSocket-Version", "13");
        req.set_header("Sec-WebSocket-Key", "dGhlIHNhbXBsZSBub25jZQ==");
        req.headers.push(wing::make_header("Sec-WebSocket-Protocol", "wamp.2.json"));
        req.headers.push(wing::make_header("Sec-WebSocket-Protocol", "chat.v1"));

        var resp = wing::new_response();
        let ws_sess, ok = wing::ws_upgrade_request(req, resp, "chat.v1");
        sub.assert_true(ok, "Upgrade accepted with subprotocol from second header");
        sub.assert_eq(resp.status_code, 101, "Switching Protocols 101");
        sub.assert_bytes_eq(resp.header("sec-websocket-protocol"), "chat.v1", "Subprotocol header set");
        sub.assert_bytes_eq(ws_sess.subprotocol[..], "chat.v1", "Session subprotocol populated");
    };

    t.run("is_websocket_upgrade_request handles comma-separated Connection tokens") { sub =>
        var req = wing::new_request("GET", "https://example.com/ws");
        req.set_header("Host", "example.com");
        req.set_header("Upgrade", "websocket");
        req.set_header("Connection", "keep-alive, Upgrade");
        req.set_header("Sec-WebSocket-Version", "13");
        req.set_header("Sec-WebSocket-Key", "dGhlIHNhbXBsZSBub25jZQ==");

        sub.assert_true(wing::is_websocket_upgrade_request(req), "Recognized as WebSocket upgrade request");
    };

    t.run("SharedWsCompressor deflate and inflate round-trip with RFC 7692 tail stripping") { sub =>
        var comp = wing::new_shared_ws_compressor();
        let original = "Hello, WebSocket PerMessageDeflate with zero-heap shared reactor context!";

        var wire: u8[>..] = [];
        let ok_c = wing::ws_deflate_message(comp, original, wire, true);
        sub.assert_true(ok_c, "Deflate succeeds");
        sub.assert_gt(wire.len, 0, "Compressed bytes produced");

        var restored: u8[>..] = [];
        let ok_d = wing::ws_inflate_message(comp, wire[..], restored, 65536, true);
        sub.assert_true(ok_d, "Inflate succeeds");
        sub.assert_bytes_eq(restored[..], original, "Restored text matches verbatim");
    };
}

// ----------------------------------------------------------------------------
// 3. HTTP Chunked 64-bit FSM Error Stickiness, Bare CR & Trailer Invariants
// ----------------------------------------------------------------------------
fn test_chunked_fsm_invariants(t: core::T&) {
    t.run("chunk_fsm_feed error state is sticky and idempotent") { sub =>
        var dec = internal::new_chunk_fsm_decoder();
        // Malformed chunk size: '1', '2' consumed, 'Z' triggers Error
        let st1, cons1, _ = internal::chunk_fsm_feed(dec, "12Z\r\n");
        sub.assert_eq(st1, internal::ChunkFsmStatus.Error, "First feed returns Error");
        sub.assert_eq(cons1, 2, "2 valid hex bytes consumed before error at byte 2");

        // Subsequent feed on poisoned decoder MUST immediately return Error with 0 bytes consumed
        let st2, cons2, _ = internal::chunk_fsm_feed(dec, "4\r\nWiki\r\n0\r\n\r\n");
        sub.assert_eq(st2, internal::ChunkFsmStatus.Error, "Poisoned decoder remains in Error");
        sub.assert_eq(cons2, 0, "Poisoned decoder consumes 0 bytes");

        // Reset restores usability
        internal::chunk_fsm_reset(dec);
        let st3, _, _ = internal::chunk_fsm_feed(dec, "4\r\nWiki\r\n0\r\n\r\n");
        sub.assert_eq(st3, internal::ChunkFsmStatus.YieldChunk, "Reset decoder functions again");
    };

    t.run("chunk_fsm_feed rejects bare CR in trailer lines (RFC 9112 §2.2)") { sub =>
        var dec = internal::new_chunk_fsm_decoder();
        // Trailer line has \r followed by 'X' instead of \n
        let raw = "0\r\nX-Trailer: val\rX-Next: 1\r\n\r\n";
        let st, _, _ = internal::chunk_fsm_feed(dec, raw);
        sub.assert_eq(st, internal::ChunkFsmStatus.Error, "Bare CR in trailer line rejected");
    };

    t.run("chunk_fsm_feed rejects bare LF and obs-fold in trailer mode") { sub =>
        var dec1 = internal::new_chunk_fsm_decoder();
        let st1, _, _ = internal::chunk_fsm_feed(dec1, "0\r\n\n");
        sub.assert_eq(st1, internal::ChunkFsmStatus.Error, "Bare LF in trailer mode rejected");

        var dec2 = internal::new_chunk_fsm_decoder();
        // obs-fold (space at start of trailer line)
        let st2, _, _ = internal::chunk_fsm_feed(dec2, "0\r\n X-Fold: bad\r\n\r\n");
        sub.assert_eq(st2, internal::ChunkFsmStatus.Error, "Obs-fold at start of trailer line rejected");
    };

    t.run("chunk_fsm_feed rejects NUL and CTL bytes in trailer line") { sub =>
        var dec = internal::new_chunk_fsm_decoder();
        var raw: u8[..32] = "0\r\nX-Bad: \0val\r\n\r\n";
        let st, _, _ = internal::chunk_fsm_feed(dec, raw[..]);
        sub.assert_eq(st, internal::ChunkFsmStatus.Error, "NUL byte in trailer rejected");
    };
}

// ----------------------------------------------------------------------------
// 4. Zstandard RFC 8878 RLE Block, SizeMismatch & 0-Sequence Bomb Guards
// ----------------------------------------------------------------------------
fn test_zstandard_rfc8878_invariants(t: core::T&) {
    t.run("Zstandard RLE_Block decompression repeats 1 byte block_size times") { sub =>
        // Construct valid Zstandard frame containing an RLE_Block (Block_Type = 1)
        var frame: u8[>..] = [];
        // Magic
        frame.push(0x28); frame.push(0xB5); frame.push(0x2F); frame.push(0xFD);
        // Frame Header Descriptor: single segment, no checksum, FCS = 2B
        frame.push(0x20 | 0x40);
        // Frame_Content_Size = 256 + 100 = 356 bytes
        core::write_le_u16(frame, 100);

        // Block Header: last_block=1, block_type=RLE(1), block_size=356
        let last_bit: u32 = 1;
        let btype: u32 = 1; // RLE
        let bsize: u32 = 356;
        let b_hdr = last_bit | (btype << 1) | (bsize << 3);
        frame.push((b_hdr & 0xFF) as u8);
        frame.push(((b_hdr >> 8) & 0xFF) as u8);
        frame.push(((b_hdr >> 16) & 0xFF) as u8);
        // RLE content: exactly 1 byte 'Z' (0x5A)
        frame.push(0x5A);

        var decomp: u8[>..] = [];
        let ok, err = core::zstd_decompress(frame[..], decomp);
        sub.assert_true(ok, "RLE block decompression succeeds");
        sub.assert_eq(err, core::CompressError.None, "Error is None");
        sub.assert_eq(decomp.len, 356, "Decompressed size is exactly 356 bytes");
        var all_z = true;
        for b in decomp {
            if b != 0x5A { all_z = false; }
        }
        sub.assert_true(all_z, "All 356 bytes are 'Z'");
    };

    t.run("Zstandard Frame_Content_Size mismatch triggers SizeMismatch") { sub =>
        // Construct frame with declared Frame_Content_Size = 20, but block only decompresses 10 bytes
        var frame: u8[>..] = [];
        frame.push(0x28); frame.push(0xB5); frame.push(0x2F); frame.push(0xFD);
        frame.push(0x20); // single segment, FCS = 1B (flag 0)
        frame.push(20);   // Declared FCS = 20

        // Raw block with 10 bytes
        let b_hdr = 1 | (0 << 1) | (10 << 3);
        frame.push((b_hdr & 0xFF) as u8);
        frame.push(((b_hdr >> 8) & 0xFF) as u8);
        frame.push(((b_hdr >> 16) & 0xFF) as u8);
        for i in 10 { frame.push('A'); }

        var decomp: u8[>..] = [];
        let ok, err = core::zstd_decompress(frame[..], decomp);
        sub.assert_false(ok, "FCS mismatch must fail");
        sub.assert_eq(err, core::CompressError.SizeMismatch, "Error is SizeMismatch");
    };

    t.run("Zstandard 0-sequences block respects max_output_bytes quota") { sub =>
        // Frame with raw block of 50 bytes tested against quota of 20 bytes
        var frame: u8[>..] = [];
        frame.push(0x28); frame.push(0xB5); frame.push(0x2F); frame.push(0xFD);
        frame.push(0x20);
        frame.push(50);

        let b_hdr = 1 | (0 << 1) | (50 << 3);
        frame.push((b_hdr & 0xFF) as u8);
        frame.push(((b_hdr >> 8) & 0xFF) as u8);
        frame.push(((b_hdr >> 16) & 0xFF) as u8);
        for i in 50 { frame.push('B'); }

        var decomp: u8[>..] = [];
        let ok, err = core::zstd_decompress_with_limit(frame[..], decomp, 20);
        sub.assert_false(ok, "Exceeding quota fails");
        sub.assert_eq(err, core::CompressError.OutputBufferOverflow, "Error is OutputBufferOverflow");
    };
}

// ----------------------------------------------------------------------------
// 5. Deflate RFC 1951 Dynamic Huffman Missing EOB 256 Rejection
// ----------------------------------------------------------------------------
fn test_deflate_rfc1951_invariants(t: core::T&) {
    t.run("inflate rejects Dynamic Huffman block missing EOB symbol 256 (RFC 1951 §3.2.7)") { sub =>
        // Construct minimal corrupt Dynamic Huffman bitstream where symbol 256 has code length 0.
        // Bit 0: BFINAL=1, Bits 1-2: BTYPE=10 (Dynamic)
        // HLIT = 0 (257 codes: 0..256), HDIST = 0 (1 dist code), HCLEN = 1 (5 code length codes: 16,17,18,0,8)
        var w = core::BitWriter { bit_buf: 0, bit_count: 0 };
        var wire: u8[>..] = [];

        core::write_bits(w, 1 | (2 << 1), 3, wire); // BFINAL=1, BTYPE=10
        core::write_bits(w, 0, 5, wire);             // HLIT: 257 codes (0..256)
        core::write_bits(w, 0, 5, wire);             // HDIST: 1 code
        core::write_bits(w, 1, 4, wire);             // HCLEN: 4+1 = 5 code length codes (16, 17, 18, 0, 8)

        // Code length code lengths: for 16, 17, 18, 0, 8
        // Let code 18 (repeat 11..138 zeros) have length 1 (code 0)
        core::write_bits(w, 0, 3, wire); // 16: len 0
        core::write_bits(w, 0, 3, wire); // 17: len 0
        core::write_bits(w, 1, 3, wire); // 18: len 1 (code 0)
        core::write_bits(w, 0, 3, wire); // 0: len 0
        core::write_bits(w, 0, 3, wire); // 8: len 0

        // Now encode HLIT+HDIST = 257 + 1 = 258 code lengths.
        // Use code 18 twice with 7 extra bits each (repeat zeros):
        // 1st: code 0 (1 bit) + 127 extra bits -> 138 zeros (codes 0..137)
        core::write_bits(w, 0, 1, wire);
        core::write_bits(w, 127, 7, wire);
        // 2nd: code 0 (1 bit) + 109 extra bits -> 120 zeros (codes 138..257)
        // Thus ALL symbols 0..256 have length 0, including EOB 256!
        core::write_bits(w, 0, 1, wire);
        core::write_bits(w, 109, 7, wire);

        core::flush_bits(w, wire);

        var decomp: u8[>..] = [];
        let ok, err = core::inflate(wire[..], decomp);
        sub.assert_false(ok, "Dynamic Huffman missing EOB 256 MUST fail");
        sub.assert_eq(err, core::CompressError.CodeLengthsIncomplete, "Error is CodeLengthsIncomplete");
    };

    t.run("get_deflate_config returns valid tuning across all levels 0..9") { sub =>
        for lvl in 10 {
            let cfg = core::get_deflate_config(lvl as i32);
            sub.assert_gt(cfg.max_chain, 0, "max_chain positive");
            sub.assert_gt(cfg.good_len, 0, "good_len positive");
            sub.assert_gt(cfg.nice_len, 0, "nice_len positive");
        }
    };
}

// ----------------------------------------------------------------------------
// Main Runner
// ----------------------------------------------------------------------------
fn main() {
    var runner = core::new_runner("RED Suite Phase 14: G-CRAP Risk Targets & RFC Invariants", core::Verbosity.Verbose);

    core::run_case(runner, "1. H2 multiplexer trailer encoding (server/h2_multiplexer.goose)", test_h2_multiplexer_trailers);
    core::run_case(runner, "2. WebSocket Close UTF-8 & Subprotocols (realtime/websocket.goose)", test_websocket_close_and_subprotocol);
    core::run_case(runner, "3. HTTP Chunked FSM invariants (http/headers/chunked_fsm.goose)", test_chunked_fsm_invariants);
    core::run_case(runner, "4. Zstandard RFC 8878 invariants (core/compress/zstd.goose)", test_zstandard_rfc8878_invariants);
    core::run_case(runner, "5. Deflate RFC 1951 invariants (core/compress/deflate.goose)", test_deflate_rfc1951_invariants);

    let ok = core::finish(runner);
    assert(ok);
}
