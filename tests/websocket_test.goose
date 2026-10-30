// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Consolidated Verification Suite: WebSocket & Server-Sent Events Verification Suite
import std;
import core from "..";
import wing from "..";

// --- Component: websocket_framing_handshake ---
// Team FrameForge Protocol Audit Suite - Round 1
// Focus: RFC 6455 & RFC 7692 WebSocket Framing, Deflate Compression, RSV Spoofing, Masking, and Close Codes.

fn test_frameforge_r1_websocket(t: core::T&) {
    // ------------------------------------------------------------------------
    // Bug 1: RFC 7692 Section 6.1: Compression - Premature UTF-8 validation on raw compressed text wire bytes
    // ------------------------------------------------------------------------
    t.run("1. RFC 7692 Section 6.1 Compressed Text Frame UTF-8 Validation Boundary") { sub =>
        var ws = wing::new_websocket_session(true); // client session
        wing::enable_permessage_deflate(ws, wing::WS_COMPRESS_SHARED_COMPRESSOR);

        var comp = wing::SharedWsCompressor { .. };
        let original_text = "The quick brown fox jumps over the lazy dog. Repetition for deflate efficiency: The quick brown fox jumps over the lazy dog!";
        var comp_wire: u8[..1024] = [];
        let ok_c = wing::ws_deflate_message(comp, original_text, comp_wire, true);
        sub.assert_true(ok_c, "Deflate message succeeded");

        // Encode as unfragmented compressed text frame (RSV1=1, FIN=1, Opcode=TEXT)
        var frame_wire: u8[..2048] = [];
        let no_mask: u8[4] = [0, 0, 0, 0];
        wing::encode_ws_frame_compressed(frame_wire, wing::WS_OPCODE_TEXT, comp_wire[..], false, no_mask, true);

        var view = wing::WsMessageView { .. };
        var reply: u8[..256] = [];
        let ok_recv = wing::receive_view(ws, frame_wire[..], view, reply);

        sub.assert_true(ok_recv, "receive_view must successfully handle valid compressed text frame");
        sub.assert_false(ws.is_closed, "Connection must NOT be closed on compressed text frame");
        sub.assert_true(view.is_valid, "Message view must be valid");
        sub.assert_true(view.is_compressed, "Message view must indicate payload is compressed");
        sub.assert_eq(view.opcode, wing::WS_OPCODE_TEXT, "Opcode is TEXT");

        // Verify decompressed payload is valid UTF-8 and matches original
        var decomp_text: u8[..2048] = [];
        let ok_d = wing::ws_inflate_message(comp, view.payload, decomp_text, 65536, true);
        sub.assert_true(ok_d, "Inflate succeeds on received compressed payload");
        sub.assert_true(core::validate_utf8(decomp_text[..]), "Decompressed payload is valid UTF-8 per RFC 7692 Section 6.1: Compression");
        sub.assert_bytes_eq(decomp_text[..], original_text, "Decompressed payload matches original plaintext");
    };

    // ------------------------------------------------------------------------
    // Bug 2: RFC 7692 §5.1 & RFC 6455 §5.4: Fragmented Compressed Message Assembly
    // ------------------------------------------------------------------------
    t.run("2. RFC 7692 §5.1 Fragmented Compressed Message Assembly and RSV1 State Retention") { sub =>
        var ws = wing::new_websocket_session(true);
        wing::enable_permessage_deflate(ws, wing::WS_COMPRESS_SHARED_COMPRESSOR);

        var comp = wing::SharedWsCompressor { .. };
        let msg_text = "Fragmented compressed WebSocket stream testing per RFC 7692 §5.1 and RFC 6455 §5.4.";
        var comp_wire: u8[..1024] = [];
        let ok_c = wing::ws_deflate_message(comp, msg_text, comp_wire, true);
        sub.assert_true(ok_c, "Deflate succeeded");
        sub.assert_gt(comp_wire.len, 10, "Compressed output non-trivial");

        // Split compressed stream into two fragments
        let mid = comp_wire.len / 2;
        let part1 = comp_wire[..mid];
        let part2 = comp_wire[mid..];

        let no_mask: u8[4] = [0, 0, 0, 0];

        // Fragment 1: RSV1=1, FIN=0, Opcode=TEXT
        var f1_wire: u8[..1024] = [];
        wing::encode_ws_frame_compressed(f1_wire, wing::WS_OPCODE_TEXT, part1, false, no_mask, false);

        var view1 = wing::WsMessageView { .. };
        var reply1: u8[..256] = [];
        let ok1 = wing::receive_view(ws, f1_wire[..], view1, reply1);
        sub.assert_true(ok1, "First fragment accepted");
        sub.assert_false(view1.is_valid, "Message not complete on first fragment");
        sub.assert_false(ws.is_closed, "Connection remains open");

        // Fragment 2: RSV1=0, FIN=1, Opcode=CONTINUATION
        var f2_wire: u8[..1024] = [];
        wing::encode_ws_frame(f2_wire, wing::WS_OPCODE_CONTINUATION, part2, false, no_mask, true);

        var view2 = wing::WsMessageView { .. };
        var reply2: u8[..256] = [];
        let ok2 = wing::receive_view(ws, f2_wire[..], view2, reply2);
        sub.assert_true(ok2, "Terminal continuation fragment accepted");
        sub.assert_false(ws.is_closed, "Connection must NOT be closed on compressed fragmented text message");
        sub.assert_true(view2.is_valid, "Reassembled message is valid");
        sub.assert_eq(view2.opcode, wing::WS_OPCODE_TEXT, "Preserved initial opcode TEXT");
        sub.assert_true(view2.is_compressed, "Reassembled view must have is_compressed set to true");

        // Verify decompressed reassembled payload
        var decomp_text: u8[..2048] = [];
        let ok_d = wing::ws_inflate_message(comp, view2.payload, decomp_text, 65536, true);
        sub.assert_true(ok_d, "Inflate succeeds on reassembled payload");
        sub.assert_bytes_eq(decomp_text[..], msg_text, "Decompressed text matches original plaintext");
    };

    // ------------------------------------------------------------------------
    // Bug 3: RFC 6455 §5.1: Immediate Protocol Error (1002) on Unmasked Client Frame Header
    // ------------------------------------------------------------------------
    t.run("3. RFC 6455 §5.1 Early Masking Enforcement on Partial / Streaming Frame") { sub =>
        var ws = wing::new_websocket_session(false); // SERVER session: client-to-server frames MUST be masked
        var view = wing::WsMessageView { .. };
        var reply: u8[..256] = [];

        // Ingress wire: Unmasked frame header (masked=false) claiming large payload (e.g. 5000 bytes),
        // but only the 4-byte header is supplied to receive_view.
        // Server MUST reject immediately with 1002 without waiting for 5000 bytes.
        let unmasked_hdr: u8[4] = [
            0x81, // FIN=1, Opcode=TEXT
            126,  // Masked=0, raw_len=126
            0x13, 0x88, // 5000 bytes extended length
        ];

        let handled = wing::receive_view(ws, unmasked_hdr[..], view, reply);
        sub.assert_true(handled, "receive_view must process fatal unmasked header error");
        sub.assert_true(ws.is_closed, "Server must immediately close connection on unmasked client frame");
        sub.assert_eq(ws.close_code, wing::WS_STATUS_PROTOCOL_ERROR, "Close code MUST be 1002 (PROTOCOL_ERROR)");
    };

    // ------------------------------------------------------------------------
    // Bug 4: RFC 6455 §5.2: Immediate Protocol Error (1002) on RSV Spoofing Header
    // ------------------------------------------------------------------------
    t.run("4. RFC 6455 §5.2 Early RSV Bit Spoofing Rejection on Partial Wire Header") { sub =>
        var ws = wing::new_websocket_session(false); // server session
        var view = wing::WsMessageView { .. };
        var reply: u8[..256] = [];

        // RSV2 bit set (0x20) with mask bit set, claiming 5000 bytes payload. Only 8 header bytes supplied.
        let rsv2_hdr: u8[8] = [
            0xA1, // FIN=1, RSV2=1, Opcode=TEXT
            0xFE, // Masked=1, raw_len=126
            0x13, 0x88, // 5000 bytes
            0x01, 0x02, 0x03, 0x04, // Mask key
        ];

        let handled = wing::receive_view(ws, rsv2_hdr[..], view, reply);
        sub.assert_true(handled, "receive_view must immediately handle RSV violation");
        sub.assert_true(ws.is_closed, "Server must immediately close connection on invalid RSV bits");
        sub.assert_eq(ws.close_code, wing::WS_STATUS_PROTOCOL_ERROR, "Close code MUST be 1002 (PROTOCOL_ERROR)");
    };

    // ------------------------------------------------------------------------
    // Bug 5: RFC 6455 §7.4.1 & §7.4.2: Forbidden and Out-of-Range Close Codes
    // ------------------------------------------------------------------------
    t.run("5. RFC 6455 §7.4 Close Status Code Validation and Omission on Wire") { sub =>
        // Validation function check
        sub.assert_true(wing::is_valid_ws_close_code(wing::WS_STATUS_NORMAL), "1000 is valid");
        sub.assert_true(wing::is_valid_ws_close_code(wing::WS_STATUS_GOING_AWAY), "1001 is valid");
        sub.assert_true(wing::is_valid_ws_close_code(wing::WS_STATUS_PROTOCOL_ERROR), "1002 is valid");
        sub.assert_true(wing::is_valid_ws_close_code(wing::WS_STATUS_INVALID_PAYLOAD), "1007 is valid");
        sub.assert_true(wing::is_valid_ws_close_code(3000), "3000 app range is valid");
        sub.assert_true(wing::is_valid_ws_close_code(4999), "4999 private range is valid");

        // Forbidden codes MUST NOT be valid on the wire
        sub.assert_false(wing::is_valid_ws_close_code(1004), "1004 is forbidden on wire");
        sub.assert_false(wing::is_valid_ws_close_code(1005), "1005 is forbidden on wire");
        sub.assert_false(wing::is_valid_ws_close_code(1006), "1006 is forbidden on wire");
        sub.assert_false(wing::is_valid_ws_close_code(1015), "1015 is forbidden on wire");

        // Invalid ranges
        sub.assert_false(wing::is_valid_ws_close_code(0), "0 is forbidden on wire");
        sub.assert_false(wing::is_valid_ws_close_code(999), "999 is forbidden (< 1000)");
        sub.assert_false(wing::is_valid_ws_close_code(1016), "1016 is reserved unassigned");
        sub.assert_false(wing::is_valid_ws_close_code(2999), "2999 is reserved unassigned");
        sub.assert_false(wing::is_valid_ws_close_code(5000), "5000 is forbidden (>= 5000)");

        // Outbound close() call with internal code 1006 (WS_STATUS_ABNORMAL_CLOSURE) MUST emit 0-byte payload
        var ws1 = wing::new_websocket_session(false);
        var wire1: u8[..128] = [];
        wing::close(ws1, wing::WS_STATUS_ABNORMAL_CLOSURE, "abnormal", wire1);
        let hdr1, ok1 = wing::parse_ws_frame_header(wire1[..]);
        sub.assert_true(ok1, "Close frame must parse");
        sub.assert_eq(hdr1.payload_len, 0, "1006 abnormal close MUST NOT write status code to wire (0 payload length)");

        // Outbound close() call with forbidden code 1015 MUST NOT put 1015 on wire
        var ws2 = wing::new_websocket_session(false);
        var wire2: u8[..128] = [];
        wing::close(ws2, 1015, "tls", wire2);
        let hdr2, ok2 = wing::parse_ws_frame_header(wire2[..]);
        sub.assert_true(ok2, "Close frame must parse");
        sub.assert_eq(hdr2.payload_len, 0, "1015 TLS close MUST NOT write status code to wire");

        // Outbound close() with non-UTF-8 reason MUST NOT serialize invalid UTF-8 onto wire
        var ws3 = wing::new_websocket_session(false);
        var wire3: u8[..128] = [];
        let bad_utf8: u8[3] = [0xFF, 0xFE, 0xFD];
        wing::close(ws3, wing::WS_STATUS_NORMAL, bad_utf8[..], wire3);
        let hdr3, ok3 = wing::parse_ws_frame_header(wire3[..]);
        sub.assert_true(ok3, "Close frame must parse");
        sub.assert_eq(hdr3.payload_len, 2, "Only 2-byte status code written; non-UTF-8 reason omitted");
    };

    // ------------------------------------------------------------------------
    // Bug 6: RFC 6455 §7.1.5: Echoing Empty Close Frame on Receiving Empty Close
    // ------------------------------------------------------------------------
    t.run("6. RFC 6455 §7.1.5 Empty Close Frame Response Contains No Body") { sub =>
        var ws = wing::new_websocket_session(false);
        var view = wing::WsMessageView { .. };
        var reply: u8[..256] = [];

        // Ingress wire: Client sends masked Close frame with NO body (payload length 0)
        let empty_close_frame: u8[6] = [
            0x88, // FIN=1, Opcode=CLOSE
            0x80, // Masked=1, payload_len=0
            0x11, 0x22, 0x33, 0x44, // Mask key
        ];

        let handled = wing::receive_view(ws, empty_close_frame[..], view, reply);
        sub.assert_true(handled, "receive_view handles empty close frame");
        sub.assert_true(view.is_valid, "Close message is valid");
        sub.assert_eq(view.close_code, wing::WS_STATUS_NO_STATUS, "Close code parsed as 1005 (No Status)");
        sub.assert_gt(reply.len, 0, "Server generated reply close frame");

        let rep_hdr, ok_rep = wing::parse_ws_frame_header(reply[..]);
        sub.assert_true(ok_rep, "Reply close frame parsed");
        sub.assert_eq(rep_hdr.opcode, wing::WS_OPCODE_CLOSE, "Reply opcode is Close");
        sub.assert_eq(rep_hdr.payload_len, 0, "RFC 6455 §7.1.5: Response close frame to body-less close MUST contain no body (0-byte payload)");
    };

    // ------------------------------------------------------------------------
    // Bug 7: RFC 6455 §5.5: Immediate Rejection of Control Frame Extended Length in Header Parser
    // ------------------------------------------------------------------------
    t.run("7. RFC 6455 §5.5 Control Frame Extended Length Rejection in parse_ws_frame_header") { sub =>
        // 2 bytes: Opcode Ping, raw_len = 126 (claims 16-bit extended length)
        let ping_ext16: u8[2] = [0x89, 126];
        let _, ok1 = wing::parse_ws_frame_header(ping_ext16[..]);
        sub.assert_false(ok1, "parse_ws_frame_header MUST immediately reject raw_len=126 on control frame");

        // 2 bytes: Opcode Close, raw_len = 127 (claims 64-bit extended length)
        let close_ext64: u8[2] = [0x88, 127];
        let _, ok2 = wing::parse_ws_frame_header(close_ext64[..]);
        sub.assert_false(ok2, "parse_ws_frame_header MUST immediately reject raw_len=127 on control frame");
    };

    // ------------------------------------------------------------------------
    // Bug 8: RFC 7692 §5.1: encode_ws_frame_compressed RSV1 Invariant Enforcement
    // ------------------------------------------------------------------------
    t.run("8. RFC 7692 §5.1 encode_ws_frame_compressed Never Sets RSV1 on Control or Continuation") { sub =>
        var out_ping: u8[..64] = [];
        let mask: u8[4] = [0, 0, 0, 0];
        wing::encode_ws_frame_compressed(out_ping, wing::WS_OPCODE_PING, "", false, mask, true);
        let hdr_p, ok_p = wing::parse_ws_frame_header(out_ping[..]);
        sub.assert_true(ok_p, "Ping parsed");
        sub.assert_false(hdr_p.rsv1, "RSV1 MUST NOT be set on control frame per RFC 7692 §5.1");

        var out_cont: u8[..64] = [];
        wing::encode_ws_frame_compressed(out_cont, wing::WS_OPCODE_CONTINUATION, "chunk", false, mask, true);
        let hdr_c, ok_c = wing::parse_ws_frame_header(out_cont[..]);
        sub.assert_true(ok_c, "Continuation parsed");
        sub.assert_false(hdr_c.rsv1, "RSV1 MUST NOT be set on continuation frame per RFC 7692 §5.1");
    };
}

// --- Component: websocket_framing_control ---
// Team FrameForge Protocol Audit Suite - Round 2
// Focus: RFC 6455 & RFC 7692 Decompression Bomb Defense, Payload Bounds Fast-Fail (1009),
// Interleaved Control Frames in Compressed Streams, and Close Handshake Idempotence.

fn test_frameforge_r2_websocket(t: core::T&) {
    // ------------------------------------------------------------------------
    // Bug 8: RFC 7692 §7.2 & RFC 6455 §7.4.1 (1009): Decompression Bomb Abort
    // ------------------------------------------------------------------------
    t.run("1. RFC 7692 Decompression Bomb Defense and Buffer Sanitization") { sub =>
        var comp = wing::SharedWsCompressor { .. };
        // Construct highly compressible payload that expands significantly
        var raw_payload: u8[..4096] = [];
        for i in 2048 {
            raw_payload.push('A');
        }
        var comp_wire: u8[..512] = [];
        let ok_c = wing::ws_deflate_message(comp, raw_payload[..], comp_wire, true);
        sub.assert_true(ok_c, "Deflate succeeded");
        sub.assert_lt(comp_wire.len, 100, "Compressed output is small (< 100 bytes)");

        // 1a: Attempt inflate with max_payload limit smaller than uncompressed size
        var decomp_buf: u8[..512] = [];
        let ok_d1 = wing::ws_inflate_message(comp, comp_wire[..], decomp_buf, 256, true);
        sub.assert_false(ok_d1, "ws_inflate_message MUST fail immediately on OutputBufferOverflow");
        sub.assert_eq(comp.decompress_buf.len, 0, "Decompression buffer wiped on limit violation");
        sub.assert_eq(comp.compress_buf.len, 0, "Compression buffer wiped on limit violation");

        // 1b: Verify successful inflate when max_payload is adequate
        var ok_buf: u8[..4096] = [];
        let ok_d2 = wing::ws_inflate_message(comp, comp_wire[..], ok_buf, 4096, true);
        sub.assert_true(ok_d2, "ws_inflate_message succeeds when max_payload is adequate");
        sub.assert_eq(ok_buf.len, 2048, "Decompressed length matches original");

        // 1c: Test DedicatedWsCompressor decompression bomb defense
        var ded = wing::new_dedicated_ws_compressor(32);
        var ded_wire: u8[..512] = [];
        let ok_ded_c = wing::deflate_message_dedicated(ded, raw_payload[..], ded_wire);
        sub.assert_true(ok_ded_c, "Dedicated deflate succeeded");

        var ded_out: u8[..512] = [];
        let ok_ded_d = wing::inflate_message_dedicated(ded, ded_wire[..], ded_out, 128);
        sub.assert_false(ok_ded_d, "inflate_message_dedicated MUST fail on OutputBufferOverflow");
        sub.assert_eq(ded.decompress_buf.len, 0, "Dedicated decompress buffer wiped on limit violation");
    };

    // ------------------------------------------------------------------------
    // Bug 9: RFC 6455 §7.4.1 (1009) & §5.2: Early Payload Length Fast-Fail
    // ------------------------------------------------------------------------
    t.run("2. RFC 6455 §7.4.1 Early Fast-Fail on Oversized Declared Frame Header") { sub =>
        var ws = wing::new_websocket_session(true);
        wing::set_max_payload_length(ws, 512);
        sub.assert_eq(ws.max_payload_length, 512, "Max payload length configured to 512 bytes");

        // Create a frame claiming 2048 bytes payload (16-bit extended length: 0x0800),
        // but providing only 4 header bytes on the wire.
        let oversized_hdr: u8[4] = [0x81, 126, 0x08, 0x00]; // FIN=1, Text, unmasked, len=2048
        var view = wing::WsMessageView { .. };
        var reply: u8[..256] = [];

        let handled = wing::receive_view(ws, oversized_hdr[..], view, reply);
        sub.assert_true(handled, "receive_view MUST immediately process oversized header");
        sub.assert_true(ws.is_closed, "Session MUST be transitioned to closed state");
        sub.assert_eq(ws.close_code, wing::WS_STATUS_MESSAGE_TOO_BIG, "Close code MUST be 1009 (Message Too Big)");
        sub.assert_gt(reply.len, 0, "Close frame MUST be emitted on wire in reply");

        // Verify emitted close frame contains status code 1009
        let hdr_rep, ok_rep = wing::parse_ws_frame_header(reply[..]);
        sub.assert_true(ok_rep, "Parsed emitted reply frame header");
        sub.assert_eq(hdr_rep.opcode, wing::WS_OPCODE_CLOSE, "Emitted frame opcode is CLOSE");
        let p_start = hdr_rep.header_len as i64;
        let p_len = hdr_rep.payload_len as i64;
        var p = reply[p_start..(p_start + p_len)];
        if hdr_rep.masked {
            wing::mask_websocket_payload(p, hdr_rep.mask_key);
        }
        let code, _, ok_p = wing::parse_close_payload(p);
        sub.assert_true(ok_p, "Parsed emitted close payload");
        sub.assert_eq(code, wing::WS_STATUS_MESSAGE_TOO_BIG, "Wire Close frame carries status 1009");
    };

    // ------------------------------------------------------------------------
    // Bug 10: RFC 6455 §5.4 & §7.4.1: Fragmented Message Size Limit Enforcement
    // ------------------------------------------------------------------------
    t.run("3. RFC 6455 §5.4 Cumulative Multi-Frame Assembly Payload Limit Enforcement") { sub =>
        var ws = wing::new_websocket_session(true);
        wing::set_max_payload_length(ws, 120);

        let no_mask: u8[4] = [0, 0, 0, 0];
        // Fragment 1: 70 bytes Text frame (FIN=0)
        var chunk1: u8[..128] = [];
        for i in 70 { chunk1.push('X'); }
        var f1_wire: u8[..256] = [];
        wing::encode_ws_frame(f1_wire, wing::WS_OPCODE_TEXT, chunk1[..], false, no_mask, false);

        var view1 = wing::WsMessageView { .. };
        var reply1: u8[..256] = [];
        let ok1 = wing::receive_view(ws, f1_wire[..], view1, reply1);
        sub.assert_true(ok1, "Initial 70-byte fragment accepted");
        sub.assert_false(ws.is_closed, "Session still open");
        sub.assert_eq(ws.frag_opcode, wing::WS_OPCODE_TEXT, "Frag opcode recorded as TEXT");

        // Fragment 2: 70 bytes Continuation frame (FIN=1) -> cumulative 140 bytes > 120 limit
        var chunk2: u8[..128] = [];
        for i in 70 { chunk2.push('Y'); }
        var f2_wire: u8[..256] = [];
        wing::encode_ws_frame(f2_wire, wing::WS_OPCODE_CONTINUATION, chunk2[..], false, no_mask, true);

        var view2 = wing::WsMessageView { .. };
        var reply2: u8[..256] = [];
        let ok2 = wing::receive_view(ws, f2_wire[..], view2, reply2);
        sub.assert_true(ok2, "receive_view handled terminal continuation violation");
        sub.assert_true(ws.is_closed, "Connection closed on cumulative fragment limit violation");
        sub.assert_eq(ws.close_code, wing::WS_STATUS_MESSAGE_TOO_BIG, "Close status is 1009");
        sub.assert_eq(ws.frag_opcode, 0, "frag_opcode reset on limit breach");
        sub.assert_eq(ws.frag_buffer.len, 0, "frag_buffer cleared on limit breach");
    };

    // ------------------------------------------------------------------------
    // Bug 11: RFC 6455 §5.4: Interleaved Control Frames in Compressed Streams
    // ------------------------------------------------------------------------
    t.run("4. RFC 6455 §5.4 Interleaved Ping/Pong During Fragmented Compressed Stream") { sub =>
        var ws = wing::new_websocket_session(true);
        wing::enable_permessage_deflate(ws, wing::WS_COMPRESS_SHARED_COMPRESSOR);

        var comp = wing::SharedWsCompressor { .. };
        let stream_msg = "Realtime telemetry payload fragmented across WebSocket frames with interleaved control heartbeats.";
        var comp_wire: u8[..1024] = [];
        let ok_c = wing::ws_deflate_message(comp, stream_msg, comp_wire, true);
        sub.assert_true(ok_c, "Deflate succeeded");

        let half = comp_wire.len / 2;
        let part1 = comp_wire[..half];
        let part2 = comp_wire[half..];

        let no_mask: u8[4] = [0, 0, 0, 0];

        // Frame 1: Compressed initial fragment (TEXT, RSV1=1, FIN=0)
        var f1_wire: u8[..1024] = [];
        wing::encode_ws_frame_compressed(f1_wire, wing::WS_OPCODE_TEXT, part1, false, no_mask, false);

        var v1 = wing::WsMessageView { .. };
        var r1: u8[..256] = [];
        let ok1 = wing::receive_view(ws, f1_wire[..], v1, r1);
        sub.assert_true(ok1, "Frame 1 accepted");
        sub.assert_eq(ws.frag_opcode, wing::WS_OPCODE_TEXT, "Frag opcode TEXT");
        sub.assert_true(ws.frag_compressed, "Frag compressed state is true");

        // Interleaved Frame 2: Ping heartbeat (PING, FIN=1)
        var ping_wire: u8[..128] = [];
        wing::encode_ws_frame(ping_wire, wing::WS_OPCODE_PING, "beat", false, no_mask, true);

        var v_ping = wing::WsMessageView { .. };
        var r_ping: u8[..256] = [];
        let ok_ping = wing::receive_view(ws, ping_wire[..], v_ping, r_ping);
        sub.assert_true(ok_ping, "Interleaved Ping accepted");
        sub.assert_true(v_ping.is_valid, "Ping view is valid");
        sub.assert_eq(v_ping.opcode, wing::WS_OPCODE_PING, "Ping opcode delivered");
        sub.assert_gt(r_ping.len, 0, "Pong response generated");
        // State retention check
        sub.assert_eq(ws.frag_opcode, wing::WS_OPCODE_TEXT, "Frag opcode TEXT preserved across Ping");
        sub.assert_true(ws.frag_compressed, "Frag compressed preserved across Ping");

        // Interleaved Frame 3: Pong heartbeat (PONG, FIN=1)
        var pong_wire: u8[..128] = [];
        wing::encode_ws_frame(pong_wire, wing::WS_OPCODE_PONG, "beat", false, no_mask, true);

        var v_pong = wing::WsMessageView { .. };
        var r_pong: u8[..256] = [];
        let ok_pong = wing::receive_view(ws, pong_wire[..], v_pong, r_pong);
        sub.assert_true(ok_pong, "Interleaved Pong accepted");
        sub.assert_eq(ws.pongs_received, 1, "Pongs received counter incremented");
        sub.assert_eq(ws.frag_opcode, wing::WS_OPCODE_TEXT, "Frag opcode TEXT preserved across Pong");
        sub.assert_true(ws.frag_compressed, "Frag compressed preserved across Pong");

        // Frame 4: Continuation terminal fragment (CONTINUATION, FIN=1)
        var f2_wire: u8[..1024] = [];
        wing::encode_ws_frame(f2_wire, wing::WS_OPCODE_CONTINUATION, part2, false, no_mask, true);

        var v2 = wing::WsMessageView { .. };
        var r2: u8[..256] = [];
        let ok2 = wing::receive_view(ws, f2_wire[..], v2, r2);
        sub.assert_true(ok2, "Terminal continuation accepted");
        sub.assert_true(v2.is_valid, "Reassembled view is valid");
        sub.assert_eq(v2.opcode, wing::WS_OPCODE_TEXT, "Reassembled opcode is TEXT");
        sub.assert_true(v2.is_compressed, "Reassembled message correctly tagged as compressed");

        // Decompress and verify
        var decomp_out: u8[..2048] = [];
        let ok_dec = wing::ws_inflate_message(comp, v2.payload, decomp_out, 65536, true);
        sub.assert_true(ok_dec, "Decompression of reassembled stream succeeded");
        sub.assert_bytes_eq(decomp_out[..], stream_msg, "Decompressed text matches stream original");
    };

    // ------------------------------------------------------------------------
    // Bug 12: RFC 6455 §5.5.1 & §7.1.5: Close Handshake Idempotence & Teardown
    // ------------------------------------------------------------------------
    t.run("5. RFC 6455 §5.5.1 Close Handshake Idempotence, Teardown and Ingress Discard") { sub =>
        // 5a: Outbound Close idempotence
        var ws = wing::new_websocket_session(true);
        var reply1: u8[..256] = [];
        wing::close(ws, wing::WS_STATUS_NORMAL, "clean shutdown", reply1);
        sub.assert_true(ws.is_closed, "Session is_closed is true");
        sub.assert_eq(ws.close_code, wing::WS_STATUS_NORMAL, "Close code 1000");
        sub.assert_gt(reply1.len, 0, "First close call emits Close frame on wire");

        var reply2: u8[..256] = [];
        wing::close(ws, wing::WS_STATUS_NORMAL, "clean shutdown again", reply2);
        sub.assert_eq(reply2.len, 0, "Second close call MUST NOT emit duplicate Close frame");

        // 5b: Outbound data frame writes blocked post-close
        var out_text: u8[..256] = [];
        wing::send_text(ws, "should not be sent", out_text);
        sub.assert_eq(out_text.len, 0, "send_text drops writes once closed");

        let status = wing::send_text_with_status(ws, "should not be sent", out_text);
        sub.assert_eq(status, wing::WsSendStatus.Closed, "send_text_with_status returns Closed");

        var out_bin: u8[..256] = [];
        wing::send_binary(ws, "binary", out_bin);
        sub.assert_eq(out_bin.len, 0, "send_binary drops writes once closed");

        var out_ping: u8[..256] = [];
        wing::send_ping(ws, "ping", out_ping);
        sub.assert_eq(out_ping.len, 0, "send_ping drops writes once closed");

        // 5c: Inbound data frames discarded post-close (RFC 6455 §5.5.1)
        let no_mask: u8[4] = [0, 0, 0, 0];
        var incoming_text_frame: u8[..256] = [];
        wing::encode_ws_frame(incoming_text_frame, wing::WS_OPCODE_TEXT, "hello", false, no_mask, true);

        var view_disc = wing::WsMessageView { .. };
        var rep_disc: u8[..256] = [];
        let ok_disc = wing::receive_view(ws, incoming_text_frame[..], view_disc, rep_disc);
        sub.assert_false(ok_disc, "receive_view MUST discard incoming data frames once connection is closed");
        sub.assert_false(view_disc.is_valid, "Message view must be invalid on discarded post-close frame");

        // 5d: Inbound Close handshake and duplicate Close frame rejection
        var ws_srv = wing::new_websocket_session(false); // Server session expecting masked frames
        var client_close_frame: u8[..256] = [];
        var close_body:         u8[..64]  = [];
        wing::encode_close_payload(close_body, wing::WS_STATUS_NORMAL, "client close");
        let mask_k: u8[4] = [0x12, 0x34, 0x56, 0x78];
        wing::encode_ws_frame(client_close_frame, wing::WS_OPCODE_CLOSE, close_body[..], true, mask_k, true);

        var v_close = wing::WsMessageView { .. };
        var r_close: u8[..256] = [];
        let ok_c1 = wing::receive_view(ws_srv, client_close_frame[..], v_close, r_close);
        sub.assert_true(ok_c1, "Initial peer Close frame accepted");
        sub.assert_true(v_close.is_valid, "Close view is valid");
        sub.assert_eq(v_close.opcode, wing::WS_OPCODE_CLOSE, "Opcode is CLOSE");
        sub.assert_eq(v_close.close_code, wing::WS_STATUS_NORMAL, "Close code 1000");
        sub.assert_true(ws_srv.is_closed, "Server session closed");
        sub.assert_true(ws_srv.close_received, "close_received flag is true");
        sub.assert_gt(r_close.len, 0, "Server generated Close response frame");

        // Duplicate peer Close frame reception
        var v_close2 = wing::WsMessageView { .. };
        var r_close2: u8[..256] = [];
        let ok_c2 = wing::receive_view(ws_srv, client_close_frame[..], v_close2, r_close2);
        sub.assert_false(ok_c2, "Duplicate peer Close frame MUST be ignored/discarded");
        sub.assert_false(v_close2.is_valid, "Duplicate close view is invalid");
        sub.assert_eq(r_close2.len, 0, "No duplicate reply emitted on second peer close frame");
    };

    // ------------------------------------------------------------------------
    // Bug 13: RFC 6455 §5.4: Immediate Protocol Error on Interleaved Data or Orphan Continuation
    // ------------------------------------------------------------------------
    t.run("6. RFC 6455 §5.4 Immediate Header Rejection on Framing Violations") { sub =>
        let no_mask: u8[4] = [0, 0, 0, 0];

        // 6a: Orphaned Continuation frame (without starting fragment)
        var ws1 = wing::new_websocket_session(true);
        var cont_frame: u8[..64] = [];
        wing::encode_ws_frame(cont_frame, wing::WS_OPCODE_CONTINUATION, "chunk", false, no_mask, true);

        var v1 = wing::WsMessageView { .. };
        var r1: u8[..256] = [];
        let ok1 = wing::receive_view(ws1, cont_frame[..], v1, r1);
        sub.assert_true(ok1, "Orphaned continuation rejected at header check");
        sub.assert_true(ws1.is_closed, "Connection closed");
        sub.assert_eq(ws1.close_code, wing::WS_STATUS_PROTOCOL_ERROR, "Protocol Error 1002 on orphaned continuation");

        // 6b: Interleaved new data frame while fragmented message in progress
        var ws2 = wing::new_websocket_session(true);
        var f1_wire: u8[..64] = [];
        wing::encode_ws_frame(f1_wire, wing::WS_OPCODE_TEXT, "start", false, no_mask, false);
        var v_init = wing::WsMessageView { .. };
        var r_init: u8[..256] = [];
        wing::receive_view(ws2, f1_wire[..], v_init, r_init);
        sub.assert_eq(ws2.frag_opcode, wing::WS_OPCODE_TEXT, "Frag opcode TEXT set");

        // Send unexpected new Binary data frame before continuation
        var bin_frame: u8[..64] = [];
        wing::encode_ws_frame(bin_frame, wing::WS_OPCODE_BINARY, "interleaved", false, no_mask, true);
        var v2 = wing::WsMessageView { .. };
        var r2: u8[..256] = [];
        let ok2 = wing::receive_view(ws2, bin_frame[..], v2, r2);
        sub.assert_true(ok2, "Interleaved data frame rejected at header check");
        sub.assert_true(ws2.is_closed, "Connection closed");
        sub.assert_eq(ws2.close_code, wing::WS_STATUS_PROTOCOL_ERROR, "Protocol Error 1002 on interleaved data frame");
        sub.assert_eq(ws2.frag_opcode, 0, "frag_opcode wiped");
        sub.assert_eq(ws2.frag_buffer.len, 0, "frag_buffer wiped");
    };
}

// --- Component: websocket_framing_compression ---
// Team FrameForge Protocol Audit Suite - Round 3 (Championship Round)
// Focus: RFC 6455 §5.4 Multibyte UTF-8 Boundary Splits Across Continuation Frames,
// RFC 7692 §7.1.1 Permessage-Deflate Sliding Window Context Takeover & Dictionary Retention,
// and Zero-Allocation SWAR 64-bit/32-bit XOR Payload Masking Loop Boundary Safety.

fn test_frameforge_r3_websocket(t: core::T&) {
    // ------------------------------------------------------------------------
    // Item 1: RFC 6455 §5.4 & §8.1: Multibyte UTF-8 Split Across Continuation Frames
    // ------------------------------------------------------------------------
    t.run("1. RFC 6455 Multibyte UTF-8 Code Point Split Across Fragment Boundaries") { sub =>
        let no_mask: u8[4] = [0, 0, 0, 0];

        // 1a: 2-byte UTF-8 codepoint ('ß' = 0xC3 0x9F) split across 2 fragments:
        // Fragment 1: "Grü" + 0xC3 (FIN=0, TEXT)
        // Fragment 2: 0x9F + "e" (FIN=1, CONTINUATION) -> assembled "Grüße"
        var ws1 = wing::new_websocket_session(true);
        let f1_part: u8[4] = ['G', 'r', 0xC3, 0xBC]; // "Grü" is 4 bytes: G, r, 0xC3, 0xBC
        // Add split 2-byte character 'ß' (0xC3 0x9F): put 0xC3 in frag 1, 0x9F in frag 2
        var frag1_body: u8[..16] = [];
        frag1_body.append(f1_part[..]);
        frag1_body.push(0xC3); // Leading byte of 'ß'

        var f1_wire: u8[..64] = [];
        wing::encode_ws_frame(f1_wire, wing::WS_OPCODE_TEXT, frag1_body[..], false, no_mask, false);

        var v1 = wing::WsMessageView { .. };
        var r1: u8[..256] = [];
        let ok1 = wing::receive_view(ws1, f1_wire[..], v1, r1);
        sub.assert_true(ok1, "Fragment 1 with trailing incomplete 2-byte lead byte accepted");
        sub.assert_false(v1.is_valid, "Message not complete on Fragment 1");
        sub.assert_false(ws1.is_closed, "Connection MUST NOT fail with premature 1007 on split UTF-8 fragment");
        sub.assert_eq(ws1.frag_opcode, wing::WS_OPCODE_TEXT, "Frag opcode TEXT recorded");

        var frag2_body: u8[..16] = [];
        frag2_body.push(0x9F); // Continuation byte of 'ß'
        frag2_body.push('e');

        var f2_wire: u8[..64] = [];
        wing::encode_ws_frame(f2_wire, wing::WS_OPCODE_CONTINUATION, frag2_body[..], false, no_mask, true);

        var v2 = wing::WsMessageView { .. };
        var r2: u8[..256] = [];
        let ok2 = wing::receive_view(ws1, f2_wire[..], v2, r2);
        sub.assert_true(ok2, "Terminal fragment accepted");
        sub.assert_true(v2.is_valid, "Reassembled message is valid");
        sub.assert_false(ws1.is_closed, "Connection remains open and clean");
        sub.assert_eq(v2.opcode, wing::WS_OPCODE_TEXT, "Opcode is TEXT");
        let expected_gruesse: u8[7] = ['G', 'r', 0xC3, 0xBC, 0xC3, 0x9F, 'e'];
        sub.assert_bytes_eq(v2.payload, expected_gruesse[..], "Assembled payload matches valid UTF-8 'Grüße'");

        // 1b: 3-byte UTF-8 codepoint ('€' = 0xE2 0x82 0xAC) split across 2 fragments:
        // Frag 1 has "100" + 0xE2 (FIN=0, TEXT)
        // Frag 2 has 0x82, 0xAC (FIN=1, CONTINUATION)
        var ws2 = wing::new_websocket_session(true);
        var f3_body: u8[..16] = ['1', '0', '0', 0xE2];
        var f3_wire: u8[..64] = [];
        wing::encode_ws_frame(f3_wire, wing::WS_OPCODE_TEXT, f3_body[..], false, no_mask, false);

        var v3 = wing::WsMessageView { .. };
        var r3: u8[..256] = [];
        let ok3 = wing::receive_view(ws2, f3_wire[..], v3, r3);
        sub.assert_true(ok3, "Fragment with split 3-byte lead accepted");
        sub.assert_false(ws2.is_closed, "No premature UTF-8 error on 3-byte split");

        var f4_body: u8[..16] = [0x82, 0xAC];
        var f4_wire: u8[..64] = [];
        wing::encode_ws_frame(f4_wire, wing::WS_OPCODE_CONTINUATION, f4_body[..], false, no_mask, true);

        var v4 = wing::WsMessageView { .. };
        var r4: u8[..256] = [];
        let ok4 = wing::receive_view(ws2, f4_wire[..], v4, r4);
        sub.assert_true(ok4, "Terminal continuation fragment accepted");
        sub.assert_true(v4.is_valid, "Reassembled message is valid");
        let expected_euro: u8[6] = ['1', '0', '0', 0xE2, 0x82, 0xAC];
        sub.assert_bytes_eq(v4.payload, expected_euro[..], "Assembled payload matches valid UTF-8 '100€'");

        // 1c: 4-byte UTF-8 codepoint ('🦀' = 0xF0 0x9F 0xA6 0x80) split across 3 fragments:
        // Frag 1: 0xF0, 0x9F (FIN=0, TEXT)
        // Frag 2: 0xA6 (FIN=0, CONTINUATION)
        // Frag 3: 0x80 (FIN=1, CONTINUATION)
        var ws3 = wing::new_websocket_session(true);
        var c1_body: u8[..8]  = [0xF0, 0x9F];
        var c1_wire: u8[..64] = [];
        wing::encode_ws_frame(c1_wire, wing::WS_OPCODE_TEXT, c1_body[..], false, no_mask, false);
        var vc1 = wing::WsMessageView { .. };
        var rc1: u8[..256] = [];
        wing::receive_view(ws3, c1_wire[..], vc1, rc1);
        sub.assert_false(ws3.is_closed, "Frag 1 of 4-byte codepoint accepted");

        var c2_body: u8[..8]  = [0xA6];
        var c2_wire: u8[..64] = [];
        wing::encode_ws_frame(c2_wire, wing::WS_OPCODE_CONTINUATION, c2_body[..], false, no_mask, false);
        var vc2 = wing::WsMessageView { .. };
        var rc2: u8[..256] = [];
        wing::receive_view(ws3, c2_wire[..], vc2, rc2);
        sub.assert_false(ws3.is_closed, "Frag 2 of 4-byte codepoint accepted");

        var c3_body: u8[..8]  = [0x80];
        var c3_wire: u8[..64] = [];
        wing::encode_ws_frame(c3_wire, wing::WS_OPCODE_CONTINUATION, c3_body[..], false, no_mask, true);
        var vc3 = wing::WsMessageView { .. };
        var rc3: u8[..256] = [];
        wing::receive_view(ws3, c3_wire[..], vc3, rc3);
        sub.assert_true(vc3.is_valid, "Reassembled 4-byte emoji message valid");
        sub.assert_false(ws3.is_closed, "Session remains open");
        let expected_crab: u8[4] = [0xF0, 0x9F, 0xA6, 0x80];
        sub.assert_bytes_eq(vc3.payload, expected_crab[..], "Payload matches 4-byte UTF-8 crab");

        // 1d: Malformed split sequence: Fragment 1 has 0xC3, Fragment 2 has invalid continuation 0x20 (ASCII space)
        var ws4 = wing::new_websocket_session(true);
        var bad1_body: u8[..8]  = ['h', 'i', 0xC3];
        var bad1_wire: u8[..64] = [];
        wing::encode_ws_frame(bad1_wire, wing::WS_OPCODE_TEXT, bad1_body[..], false, no_mask, false);
        var vb1 = wing::WsMessageView { .. };
        var rb1: u8[..256] = [];
        wing::receive_view(ws4, bad1_wire[..], vb1, rb1);

        var bad2_body: u8[..8]  = [' ', 'x']; // 0x20 is not a valid UTF-8 continuation byte
        var bad2_wire: u8[..64] = [];
        wing::encode_ws_frame(bad2_wire, wing::WS_OPCODE_CONTINUATION, bad2_body[..], false, no_mask, true);
        var vb2 = wing::WsMessageView { .. };
        var rb2: u8[..256] = [];
        let ok_bad = wing::receive_view(ws4, bad2_wire[..], vb2, rb2);
        sub.assert_true(ok_bad, "Terminal fragment processed");
        sub.assert_true(ws4.is_closed, "Session MUST close on invalid assembled UTF-8");
        sub.assert_eq(ws4.close_code, wing::WS_STATUS_INVALID_PAYLOAD, "Close code 1007 on malformed UTF-8 assembly");
    };

    // ------------------------------------------------------------------------
    // Item 2: RFC 7692 §7.1.1: Context Takeover & Dictionary Reset Boundaries
    // ------------------------------------------------------------------------
    t.run("2. RFC 7692 Permessage-Deflate Sliding Window Context Takeover Boundaries") { sub =>
        // 2a: Session context takeover negotiation configuration
        var ws_c = wing::new_websocket_session(true); // client
        wing::enable_permessage_deflate(
            ws_c,
            wing::WS_COMPRESS_SHARED_COMPRESSOR,
            wing::WsContextTakeoverOptions { server_no_context: true, client_no_context: true },
        );
        sub.assert_true(wing::ws_should_reset_compressor(ws_c), "Client with client_no_context_takeover resets compressor");
        sub.assert_true(wing::ws_should_reset_decompressor(ws_c), "Client with server_no_context_takeover resets decompressor");

        // Allow context takeover on client compressor (persistent sliding dictionary)
        wing::set_context_takeover(
            ws_c,
            wing::WsContextTakeoverOptions { server_no_context: false, client_no_context: false },
        );
        sub.assert_false(wing::ws_should_reset_compressor(ws_c), "Compressor retains sliding window when client takeover allowed");
        sub.assert_false(wing::ws_should_reset_decompressor(ws_c), "Decompressor retains sliding window when server takeover allowed");

        // Server session configuration
        var ws_s = wing::new_websocket_session(false); // server
        wing::set_context_takeover(
            ws_s,
            wing::WsContextTakeoverOptions { server_no_context: false, client_no_context: true },
        ); // server retains, client resets
        sub.assert_false(wing::ws_should_reset_compressor(ws_s), "Server compressor retains window when server_no_context=false");
        sub.assert_true(wing::ws_should_reset_decompressor(ws_s), "Server decompressor resets window when client_no_context=true");

        // 2b: DedicatedWsCompressor with reset_window=false (context takeover retained)
        var ded_comp = wing::new_dedicated_ws_compressor(32);
        var ded_decomp = wing::new_dedicated_ws_compressor(32);

        let msg1 = "WebSocket realtime protocol audit stream message 1 with repeated terms and patterns";
        var out_wire1: u8[..512] = [];
        let ok_c1 = wing::deflate_message_dedicated(ded_comp, msg1, out_wire1, false);
        sub.assert_true(ok_c1, "Dedicated deflate message 1 succeeded");
        sub.assert_gt(ded_comp.history.len, 0, "Sliding window dictionary retained in history");

        var out_plain1: u8[..512] = [];
        let ok_d1 = wing::inflate_message_dedicated(ded_decomp, out_wire1[..], out_plain1, 65536, false);
        sub.assert_true(ok_d1, "Dedicated inflate message 1 succeeded");
        sub.assert_bytes_eq(out_plain1[..], msg1, "Decompressed message 1 matches plaintext");

        // 2c: DedicatedWsCompressor with reset_window=true (dictionary wiped)
        var ded_comp_reset = wing::new_dedicated_ws_compressor(32);
        var out_wire_reset: u8[..512] = [];
        let ok_cr = wing::deflate_message_dedicated(ded_comp_reset, msg1, out_wire_reset, true);
        sub.assert_true(ok_cr, "Dedicated deflate with reset succeeded");
        sub.assert_eq(ded_comp_reset.history.len, 0, "Sliding window history wiped when reset_window=true");
    };

    // ------------------------------------------------------------------------
    // Item 3: Zero-Allocation SWAR 64-bit/32-bit XOR Masking Loop Boundary Safety
    // ------------------------------------------------------------------------
    t.run("3. Zero-Allocation SWAR 64-bit/32-bit Masking Loop Boundary Safety") { sub =>
        let mask_key: u8[4] = [0xDE, 0xAD, 0xBE, 0xEF];

        // 3a: Length 0 (Empty slice)
        var empty_buf: u8[..16] = [];
        wing::apply_mask_in_place(empty_buf[..], mask_key);
        sub.assert_eq(empty_buf.len, 0, "Length 0 handled safely");

        // 3b: Length 1 (Scalar tail only)
        var b1: u8[..1] = [0x55];
        wing::apply_mask_in_place(b1[..], mask_key);
        sub.assert_eq(b1[0], (0x55 ^ 0xDE) as u8, "Length 1 masked correctly");
        wing::apply_mask_in_place(b1[..], mask_key);
        sub.assert_eq(b1[0], 0x55, "Length 1 unmasked to original value");

        // 3c: Length 3 (Scalar tail only, 3 bytes)
        var b3: u8[..3] = [0x10, 0x20, 0x30];
        wing::apply_mask_in_place(b3[..], mask_key);
        sub.assert_eq(b3[0], (0x10 ^ 0xDE) as u8, "Length 3 byte 0 masked");
        sub.assert_eq(b3[1], (0x20 ^ 0xAD) as u8, "Length 3 byte 1 masked");
        sub.assert_eq(b3[2], (0x30 ^ 0xBE) as u8, "Length 3 byte 2 masked");
        wing::apply_mask_in_place(b3[..], mask_key);
        sub.assert_eq(b3[0], 0x10, "Length 3 restored");
        sub.assert_eq(b3[1], 0x20, "Length 3 restored");
        sub.assert_eq(b3[2], 0x30, "Length 3 restored");

        // 3d: Length 4 (32-bit SWAR tail only, exactly 4 bytes)
        var b4: u8[..4] = [0x11, 0x22, 0x33, 0x44];
        wing::apply_mask_in_place(b4[..], mask_key);
        sub.assert_eq(b4[0], (0x11 ^ 0xDE) as u8, "Length 4 byte 0");
        sub.assert_eq(b4[1], (0x22 ^ 0xAD) as u8, "Length 4 byte 1");
        sub.assert_eq(b4[2], (0x33 ^ 0xBE) as u8, "Length 4 byte 2");
        sub.assert_eq(b4[3], (0x44 ^ 0xEF) as u8, "Length 4 byte 3");
        wing::apply_mask_in_place(b4[..], mask_key);
        sub.assert_eq(b4[0], 0x11, "Length 4 byte 0 restored");
        sub.assert_eq(b4[3], 0x44, "Length 4 byte 3 restored");

        // 3e: Length 7 (32-bit SWAR + 3 scalar bytes)
        var b7: u8[..7] = [1, 2, 3, 4, 5, 6, 7];
        wing::apply_mask_in_place(b7[..], mask_key);
        wing::apply_mask_in_place(b7[..], mask_key);
        for i in 7 {
            sub.assert_eq(b7[i], (i + 1) as u8, "Length 7 restored");
        }

        // 3f: Length 8 (Exactly one 64-bit SWAR iteration, 0 tail bytes)
        var b8: u8[..8] = [10, 20, 30, 40, 50, 60, 70, 80];
        wing::apply_mask_in_place(b8[..], mask_key);
        sub.assert_eq(b8[0], (10 ^ 0xDE) as u8, "b8[0] masked");
        sub.assert_eq(b8[4], (50 ^ 0xDE) as u8, "b8[4] masked with key[0]");
        sub.assert_eq(b8[7], (80 ^ 0xEF) as u8, "b8[7] masked with key[3]");
        wing::apply_mask_in_place(b8[..], mask_key);
        sub.assert_eq(b8[0], 10, "b8[0] restored");
        sub.assert_eq(b8[7], 80, "b8[7] restored");

        // 3g: Length 15 (64-bit SWAR + 32-bit SWAR + 3 scalar bytes)
        var b15: u8[..15] = [];
        for i in 15 { b15.push((i * 7 + 3) as u8); }
        var orig15: u8[..15] = [];
        orig15.append(b15[..]);

        wing::apply_mask_in_place(b15[..], mask_key);
        // Verify byte 0..14 match manual XOR
        for i in 15 {
            sub.assert_eq(b15[i], (orig15[i] ^ mask_key[i % 4]) as u8, "b15 matches reference XOR");
        }
        wing::apply_mask_in_place(b15[..], mask_key);
        sub.assert_bytes_eq(b15[..], orig15[..], "b15 restored to original");

        // 3h: Length 64 (Large payload across multiple 64-bit iterations)
        var b64: u8[..64] = [];
        for i in 64 { b64.push((i ^ 0x5A) as u8); }
        var orig64: u8[..64] = [];
        orig64.append(b64[..]);

        wing::apply_mask_in_place(b64[..], mask_key);
        for i in 64 {
            sub.assert_eq(b64[i], (orig64[i] ^ mask_key[i % 4]) as u8, "b64 matches reference XOR");
        }
        wing::apply_mask_in_place(b64[..], mask_key);
        sub.assert_bytes_eq(b64[..], orig64[..], "b64 restored cleanly");

        // 3i: Verify mask_websocket_payload parity with apply_mask_in_place
        var p1: u8[..32] = [];
        var p2: u8[..32] = [];
        for i in 32 {
            p1.push((i * 13 + 1) as u8);
            p2.push((i * 13 + 1) as u8);
        }
        wing::apply_mask_in_place(p1[..], mask_key);
        wing::mask_websocket_payload(p2[..], mask_key);
        sub.assert_bytes_eq(p1[..], p2[..], "mask_websocket_payload parity with apply_mask_in_place");
    };
}

// --- Component: websocket_streaming_invariants ---
// Hardening & Security Invariants Suite for WebSocket Streaming & Close Framing (RFC 6455):
// 1. Close status code validation & 1-byte close payload bans (§5.5.1 / §7.4).
// 2. Control frame length limits (<= 125 bytes) and fragmentation bans (§5.5).
// 3. Streaming UTF-8 validation across multi-byte character splits, overlong encodings, and surrogates.

fn test_ws_close_payload_rfc6455_invariants(t: core::T&) {
    t.run("WS-SEC-01: Empty Close Payload and 1-Byte Payload Bans (RFC 6455 §5.5.1)") { sub =>
        // Empty payload (0 bytes) is valid: defaults to WS_STATUS_NO_STATUS (1005)
        let empty_payload: u8[0] = [];
        let code_0, reason_0, ok_0 = wing::parse_close_payload(empty_payload[..]);
        sub.assert_true(ok_0, "empty close payload is valid");
        sub.assert_eq(code_0, wing::WS_STATUS_NO_STATUS, "status code defaults to 1005");
        sub.assert_eq(reason_0.len, 0, "reason is empty");

        // 1-byte payload is strictly FORBIDDEN on the wire
        let one_byte: u8[1] = [0x03];
        let _, _, ok_1 = wing::parse_close_payload(one_byte[..]);
        sub.assert_false(ok_1, "1-byte close payload must be rejected per RFC 6455 §5.5.1");
    };

    t.run("WS-SEC-02: Forbidden Close Codes on Wire (RFC 6455 §7.4.1 & §7.4.2)") { sub =>
        // Reserved / internal codes that MUST NOT be sent on the wire
        sub.assert_false(wing::is_valid_ws_close_code(1004), "1004 (reserved) forbidden on wire");
        sub.assert_false(wing::is_valid_ws_close_code(1005), "1005 (no status) forbidden on wire");
        sub.assert_false(wing::is_valid_ws_close_code(1006), "1006 (abnormal) forbidden on wire");
        sub.assert_false(wing::is_valid_ws_close_code(1015), "1015 (TLS failure) forbidden on wire");

        // Reserved unassigned range 1016..2999
        sub.assert_false(wing::is_valid_ws_close_code(1016), "1016 (reserved) forbidden");
        sub.assert_false(wing::is_valid_ws_close_code(2000), "2000 (unassigned) forbidden");
        sub.assert_false(wing::is_valid_ws_close_code(2999), "2999 (unassigned) forbidden");

        // Out of range (< 1000 or >= 5000)
        sub.assert_false(wing::is_valid_ws_close_code(999), "code 999 out of range");
        sub.assert_false(wing::is_valid_ws_close_code(5000), "code 5000 out of range");
    };

    t.run("WS-SEC-03: Valid Standard and Application-Defined Close Codes") { sub =>
        sub.assert_true(wing::is_valid_ws_close_code(1000), "1000 Normal Closure valid");
        sub.assert_true(wing::is_valid_ws_close_code(1001), "1001 Going Away valid");
        sub.assert_true(wing::is_valid_ws_close_code(1002), "1002 Protocol Error valid");
        sub.assert_true(wing::is_valid_ws_close_code(1003), "1003 Unsupported Data valid");
        sub.assert_true(wing::is_valid_ws_close_code(1007), "1007 Invalid Payload valid");
        sub.assert_true(wing::is_valid_ws_close_code(1008), "1008 Policy Violation valid");
        sub.assert_true(wing::is_valid_ws_close_code(1009), "1009 Message Too Big valid");
        sub.assert_true(wing::is_valid_ws_close_code(1010), "1010 Mandatory Extension valid");
        sub.assert_true(wing::is_valid_ws_close_code(1011), "1011 Internal Error valid");

        // Valid registered/private ranges 3000..4999
        sub.assert_true(wing::is_valid_ws_close_code(3000), "3000 (registered) valid");
        sub.assert_true(wing::is_valid_ws_close_code(4000), "4000 (private use) valid");
        sub.assert_true(wing::is_valid_ws_close_code(4999), "4999 (private use) valid");
    };
}

fn test_ws_control_frame_invariants(t: core::T&) {
    t.run("WS-SEC-04: Control Frame Payload > 125 Bytes Forbidden (RFC 6455 §5.5)") { sub =>
        // PING frame with payload length 126 (0x7E) encoded with extended 16-bit length
        let bad_ping: u8[4] = [
            0x89, // FIN=1, Opcode=9 (Ping)
            0x7E, // Mask=0, Len=126
            0x00, 0x7E, // Extended 16-bit length 126
        ];
        let _, ok = wing::parse_ws_frame_header(bad_ping[..]);
        sub.assert_false(ok, "Control frame with payload length > 125 must be rejected");
    };

    t.run("WS-SEC-05: Fragmented Control Frame Forbidden (RFC 6455 §5.5)") { sub =>
        // PING frame with FIN=0 (fragmented)
        let frag_ping: u8[2] = [
            0x09, // FIN=0 (bit 7=0), Opcode=9 (Ping)
            0x00, // Mask=0, Len=0
        ];
        let _, ok = wing::parse_ws_frame_header(frag_ping[..]);
        sub.assert_false(ok, "Fragmented control frame (FIN=0) must be rejected");
    };

    t.run("WS-SEC-06: Undefined Opcodes Rejected (RFC 6455 §5.2)") { sub =>
        // Opcode 3 (reserved non-control)
        let unk_op3: u8[2] = [0x83, 0x00];
        let _, ok3 = wing::parse_ws_frame_header(unk_op3[..]);
        sub.assert_false(ok3, "Unknown opcode 0x3 must be rejected");

        // Opcode 0xB (reserved control)
        let unk_opB: u8[2] = [0x8B, 0x00];
        let _, okB = wing::parse_ws_frame_header(unk_opB[..]);
        sub.assert_false(okB, "Unknown control opcode 0xB must be rejected");
    };
}

fn test_ws_streaming_utf8_invariants(t: core::T&) {
    t.run("WS-SEC-07: Overlong Encodings and UTF-16 Surrogates Rejected") { sub =>
        // Overlong 2-byte NUL: 0xC0 0x80
        let overlong_nul: u8[2] = [0xC0, 0x80];
        sub.assert_false(core::validate_utf8(overlong_nul[..]), "overlong NUL 0xC0 0x80 must be rejected");

        // Overlong 3-byte: 0xE0 0x80 0xAF
        let overlong_3: u8[3] = [0xE0, 0x80, 0xAF];
        sub.assert_false(core::validate_utf8(overlong_3[..]), "overlong 3-byte sequence must be rejected");

        // High surrogate half: 0xED 0xA0 0x80 (U+D800)
        let surrogate_hi: u8[3] = [0xED, 0xA0, 0x80];
        sub.assert_false(core::validate_utf8(surrogate_hi[..]), "UTF-16 high surrogate must be rejected");

        // Low surrogate half: 0xED 0xBF 0xBF (U+DFFF)
        let surrogate_lo: u8[3] = [0xED, 0xBF, 0xBF];
        sub.assert_false(core::validate_utf8(surrogate_lo[..]), "UTF-16 low surrogate must be rejected");
    };

    t.run("WS-SEC-08: Streaming UTF-8 across Split Multi-Byte Characters") { sub =>
        // Euro sign € is 3 bytes: 0xE2 0x82 0xAC
        // Chunk 1: "a" + [0xE2, 0x82] (incomplete 3-byte sequence, is_final=false)
        let chunk1: u8[3] = ['a', 0xE2, 0x82];
        let valid_len1, ok1 = core::validate_utf8_streaming(chunk1[..], false);
        sub.assert_true(ok1, "partial UTF-8 sequence accepted when is_final=false");
        sub.assert_eq(valid_len1, 1, "valid prefix length is 1 ('a')");

        // When is_final=true, partial UTF-8 sequence at end must fail
        let _, ok1_final = core::validate_utf8_streaming(chunk1[..], true);
        sub.assert_false(ok1_final, "partial UTF-8 sequence rejected when is_final=true");

        // Chunk 2: [0xAC] + "b" (completes Euro sign: 0xE2 0x82 0xAC + 'b')
        let full_msg: u8[5] = ['a', 0xE2, 0x82, 0xAC, 'b'];
        let valid_full, ok_full = core::validate_utf8_streaming(full_msg[..], true);
        sub.assert_true(ok_full, "assembled message is fully valid UTF-8");
        sub.assert_eq(valid_full, 5, "entire 5-byte message validated");
    };
}

// --- Component: websocket_h2_extended_connect ---
// tests/websocket_h2_test.goose
// Verification Suite for RFC 8441: Bootstrapping WebSockets with HTTP/2.

fn test_rfc8441_client_formatting(t: core::T&) {
    t.run("1. Client Request Formatting & Pseudo-Headers") { sub =>
        var req = wing::new_request("GET", "/");
        wing::format_h2_websocket_request(req, "/v1/chat", "api.example.com", "https", "graphql-transport-ws");

        sub.assert_bytes_eq(req.method[..], "CONNECT", "Method is CONNECT");
        sub.assert_bytes_eq(req.url[..], "/v1/chat", "URL path matches");

        sub.assert_bytes_eq(req.header(":method"), "CONNECT", ":method pseudo-header is CONNECT");
        sub.assert_bytes_eq(req.header(":protocol"), "websocket", ":protocol pseudo-header is websocket");
        sub.assert_bytes_eq(req.header(":scheme"), "https", ":scheme pseudo-header is https");
        sub.assert_bytes_eq(req.header(":authority"), "api.example.com", ":authority pseudo-header is api.example.com");
        sub.assert_bytes_eq(req.header(":path"), "/v1/chat", ":path pseudo-header is /v1/chat");
        sub.assert_bytes_eq(req.header("sec-websocket-version"), "13", "sec-websocket-version is 13");
        sub.assert_bytes_eq(req.header("sec-websocket-protocol"), "graphql-transport-ws", "subprotocol matches");

        sub.assert_true(wing::is_h2_websocket_request(req), "is_h2_websocket_request is true");
        sub.assert_true(wing::validate_h2_websocket_request(req), "validate_h2_websocket_request succeeds");
    };
}

fn test_rfc8441_validation_invariants(t: core::T&) {
    t.run("1. Strict RFC 8441 Rejections (Forbidden Headers & Missing Fields)") { sub =>
        // 1. Forbidden Upgrade header
        var req1 = wing::new_request("GET", "/");
        wing::format_h2_websocket_request(req1, "/chat", "example.com");
        wing::set_header(req1, "Upgrade", "websocket");
        sub.assert_false(wing::validate_h2_websocket_request(req1), "Reject request with Upgrade header");

        // 2. Forbidden Connection header
        var req2 = wing::new_request("GET", "/");
        wing::format_h2_websocket_request(req2, "/chat", "example.com");
        wing::set_header(req2, "Connection", "Upgrade");
        sub.assert_false(wing::validate_h2_websocket_request(req2), "Reject request with Connection header");

        // 3. Forbidden Sec-WebSocket-Key header (RFC 8441 §4: Sec-WebSocket-Key MUST NOT be used)
        var req3 = wing::new_request("GET", "/");
        wing::format_h2_websocket_request(req3, "/chat", "example.com");
        wing::set_header(req3, "Sec-WebSocket-Key", "dGhlIHNhbXBsZSBub25jZQ==");
        sub.assert_false(wing::validate_h2_websocket_request(req3), "Reject request with Sec-WebSocket-Key header");

        // 4. Missing :protocol
        var req4 = wing::new_request("GET", "/");
        wing::format_h2_websocket_request(req4, "/chat", "example.com");
        wing::set_header(req4, ":protocol", "");
        sub.assert_false(wing::validate_h2_websocket_request(req4), "Reject request with empty :protocol");

        // 5. Wrong :protocol value (e.g. webtransport instead of websocket)
        var req5 = wing::new_request("GET", "/");
        wing::format_h2_websocket_request(req5, "/chat", "example.com");
        wing::set_header(req5, ":protocol", "webtransport");
        sub.assert_false(wing::validate_h2_websocket_request(req5), "Reject request with wrong :protocol");

        // 6. Wrong sec-websocket-version
        var req6 = wing::new_request("GET", "/");
        wing::format_h2_websocket_request(req6, "/chat", "example.com");
        wing::set_header(req6, "sec-websocket-version", "8");
        sub.assert_false(wing::validate_h2_websocket_request(req6), "Reject request with version != 13");
    };
}

fn test_rfc8441_server_upgrade(t: core::T&) {
    t.run("1. 200 OK Response & Subprotocol Negotiation") { sub =>
        var req = wing::new_request("GET", "/");
        wing::format_h2_websocket_request(req, "/live", "stream.example.com", "https", "wamp.2.json, mqtt");

        var resp = wing::Response { .. };
        let session, ok = wing::ws_h2_upgrade_request(req, resp, "mqtt");
        sub.assert_true(ok, "ws_h2_upgrade_request succeeds");
        sub.assert_eq(resp.status_code, 200, "RFC 8441 §5: Status code MUST be 200 (NOT 101)");
        sub.assert_bytes_eq(resp.header("sec-websocket-protocol"), "mqtt", "Negotiated subprotocol is mqtt");
        sub.assert_bytes_eq(session.subprotocol[..], "mqtt", "Session subprotocol matches");
        sub.assert_true(wing::is_h2_websocket_response(resp), "is_h2_websocket_response returns true");

        // Negative: Upgrade invalid request fails with 400
        var bad_req = wing::new_request("GET", "/");
        wing::format_h2_websocket_request(bad_req, "/live", "stream.example.com");
        wing::set_header(bad_req, "Connection", "keep-alive");
        var bad_resp = wing::Response { .. };
        let _, bad_ok = wing::ws_h2_upgrade_request(bad_req, bad_resp);
        sub.assert_false(bad_ok, "Upgrade invalid request fails");
        sub.assert_eq(bad_resp.status_code, 400, "Bad request produces 400");
    };
}

fn test_rfc8441_data_frame_payload(t: core::T&) {
    t.run("1. RFC 6455 Frame Encapsulation inside HTTP/2 Stream") { sub =>
        // Once connection is 200 OK, payload of HTTP/2 DATA frames contains RFC 6455 frames
        var ws_wire: u8[>..] = [];
        let mask_key: const u8[4] = [0x12, 0x34, 0x56, 0x78];
        let payload = "Ping from H2 WebSocket";
        wing::encode_ws_frame(ws_wire, wing::WS_OPCODE_TEXT, payload, true, mask_key);

        let hdr, ok = wing::parse_ws_frame_header(ws_wire[..]);
        sub.assert_true(ok, "Parse WS frame from H2 stream data");
        sub.assert_eq(hdr.opcode, wing::WS_OPCODE_TEXT, "Opcode is TEXT");
        sub.assert_eq(hdr.payload_len as i64, payload.len, "Payload length matches");
        sub.assert_true(hdr.masked, "Mask bit set");
    };
}

// --- Component: websocket_sse ---
// Verification Suite for WebSocket (RFC 6455 / RFC 8441), HTTP/3 PRIORITY_UPDATE (RFC 9218)
// and Server-Sent Events (W3C EventSource).

fn test_websocket_framing_and_handshake(t: core::T&) {
    t.run("1. RFC 6455 Section 1.3 Handshake Vector Verification") { sub =>
        let client_key = "dGhlIHNhbXBsZSBub25jZQ==";
        var accept_key: u8[>..] = [];
        wing::compute_websocket_accept(client_key, accept_key);

        sub.assert_bytes_eq(
            accept_key[..],
            "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=",
            "RFC 6455 Section 1.3 Sec-WebSocket-Accept key derivation matches standard vector",
        );
        sub.assert_true(wing::validate_websocket_accept(client_key, "s3pPLMBiTxaQ9kYGzzhZRbK+xOo="), "Validation succeeds");
        sub.assert_false(wing::validate_websocket_accept(client_key, "invalid_accept_key="), "Tampered accept key rejected");

        // Nonce generator
        let test_nonce: u8[16] = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];
        var out_key: u8[>..] = [];
        wing::generate_websocket_key(test_nonce, out_key);
        sub.assert_eq(out_key.len, 24, "Client key is 24 base64 characters");
    };

    t.run("2. RFC 6455 In-Place 64-Bit Unrolled Masking") { sub =>
        let mask_key: u8[4] = [0x37, 0xfa, 0x21, 0x3d];
        var payload: u8[>..] = [];
        payload.append("Hello, WebSocket Zero-Allocation World! This is a longer string to test 64-bit unrolling.");

        var original: u8[>..] = [];
        original.append(payload[..]);

        // Mask
        wing::mask_websocket_payload(payload[..], mask_key);
        sub.assert_false(payload[..] == original[..], "Masked payload differs from original plaintext");

        // Unmask (symmetric XOR)
        wing::mask_websocket_payload(payload[..], mask_key);
        sub.assert_bytes_eq(payload[..], original[..], "Unmasking perfectly restores original plaintext");
    };

    t.run("3. Small, Medium (16-bit) and Large (64-bit) Frame Headers") { sub =>
        // Small frame (<= 125 bytes)
        let hdr_small = wing::WsFrameHeader {
            fin:         true,
            opcode:      wing::WS_OPCODE_TEXT,
            masked:      true,
            mask_key:    [0x12, 0x34, 0x56, 0x78],
            payload_len: 42,
            ..
        };
        var buf_small: u8[>..] = [];
        hdr_small.encode(buf_small);
        sub.assert_eq(buf_small.len, 6, "Small frame header length is 2 + 4 = 6 bytes (UFCS)");

        let parsed_small, ok_s = wing::parse_ws_frame_header(buf_small[..]);
        sub.assert_true(ok_s, "Small frame header parsed");
        sub.assert_eq(parsed_small.payload_len, 42, "Small payload length 42");
        sub.assert_true(parsed_small.masked, "Masked bit set");
        sub.assert_eq(parsed_small.opcode, wing::WS_OPCODE_TEXT, "Opcode is TEXT");

        // Medium frame (126..65535 bytes)
        let hdr_med = wing::WsFrameHeader {
            fin:         true,
            opcode:      wing::WS_OPCODE_BINARY,
            masked:      false,
            payload_len: 1000,
            ..
        };
        var buf_med: u8[>..] = [];
        hdr_med.encode(buf_med);
        sub.assert_eq(buf_med.len, 4, "Medium unmasked frame header length is 2 + 2 = 4 bytes");

        let parsed_med, ok_m = wing::parse_ws_frame_header(buf_med[..]);
        sub.assert_true(ok_m, "Medium frame header parsed");
        sub.assert_eq(parsed_med.payload_len, 1000, "Medium payload length 1000");

        // Large frame (> 65535 bytes)
        let hdr_lg = wing::WsFrameHeader {
            fin:         true,
            opcode:      wing::WS_OPCODE_BINARY,
            masked:      false,
            payload_len: 100000,
            ..
        };
        var buf_lg: u8[>..] = [];
        hdr_lg.encode(buf_lg);
        sub.assert_eq(buf_lg.len, 10, "Large frame header length is 2 + 8 = 10 bytes");

        let parsed_lg, ok_l = wing::parse_ws_frame_header(buf_lg[..]);
        sub.assert_true(ok_l, "Large frame header parsed");
        sub.assert_eq(parsed_lg.payload_len, 100000, "Large payload length 100000");
    };

    t.run("4. Control Frame Invariants & Close Payload") { sub =>
        // Control frames MUST NOT be fragmented (RFC 6455 Section 5.5)
        let frag_ping: u8[2] = [0x09, 0x00]; // FIN = 0, Opcode = 9 (Ping)
        let _, ok_frag = wing::parse_ws_frame_header(frag_ping[..]);
        sub.assert_false(ok_frag, "Fragmented control frame (FIN=0) must be rejected");

        // Control frames MUST NOT have payload > 125
        let large_ping: u8[4] = [0x89, 126, 0x00, 0x80]; // Ping with 128 bytes
        let _, ok_lg_ping = wing::parse_ws_frame_header(large_ping[..]);
        sub.assert_false(ok_lg_ping, "Control frame with payload > 125 must be rejected");

        // Close payload codec
        var close_buf: u8[>..] = [];
        wing::encode_close_payload(close_buf, wing::WS_STATUS_NORMAL, "goodbye");
        sub.assert_eq(close_buf.len, 2 + 7, "2 status bytes + 7 reason bytes");

        let code, reason, ok_close = wing::parse_close_payload(close_buf[..]);
        sub.assert_true(ok_close, "Close payload parsed successfully");
        sub.assert_eq(code, wing::WS_STATUS_NORMAL, "Status is 1000 Normal");
        sub.assert_bytes_eq(reason, "goodbye", "Reason matches");
    };

    t.run("5. Full Frame Serialization & RFC 6455 Roundtrip") { sub =>
        let mask: u8[4] = [0xaa, 0xbb, 0xcc, 0xdd];
        var wire: u8[>..] = [];
        wing::encode_ws_frame(wire, wing::WS_OPCODE_TEXT, "Wing Engine WebSocket", true, mask, true);

        let hdr, ok = wing::parse_ws_frame_header(wire[..]);
        sub.assert_true(ok, "Parse frame header from serialized wire bytes");
        sub.assert_eq(hdr.opcode, wing::WS_OPCODE_TEXT, "Text opcode");
        sub.assert_true(hdr.masked, "Client frame masked");

        var payload_copy: u8[>..] = [];
        let p_start = hdr.header_len as i64;
        payload_copy.append(wire[p_start..]);
        wing::mask_websocket_payload(payload_copy[..], hdr.mask_key);
        sub.assert_bytes_eq(payload_copy[..], "Wing Engine WebSocket", "De-masked payload matches original");
    };

    t.run("6. WebSocketSession High-Level Lifecycle") { sub =>
        var session = wing::new_websocket_session(true);
        session.subprotocol.append("chat.v1");

        var req: u8[>..] = [];
        session.build_handshake_request("example.com", "/chat", "dGhlIHNhbXBsZSBub25jZQ==", req);
        sub.assert_true(req.len > 0, "Handshake request created via UFCS");

        var text_frame: u8[>..] = [];
        wing::send_text(session, "hello server", text_frame);
        sub.assert_true(text_frame.len > 0, "Text frame generated");

        var ping_frame: u8[>..] = [];
        wing::send_ping(session, "heartbeat", ping_frame);
        sub.assert_true(ping_frame.len > 0, "Ping frame generated");

        var close_frame: u8[>..] = [];
        wing::close(session, wing::WS_STATUS_NORMAL, "goodbye", close_frame);
        sub.assert_true(session.is_closed, "Session marked closed");
        sub.assert_eq(session.close_code, wing::WS_STATUS_NORMAL, "Close code set");
    };

    t.run("7. Aoni-Style Automated Client WebSocket Upgrade & receive Engine") { sub =>
        var client = wing::new_client();
        wing::add_mock_websocket(client, "https://stream.example.com/ws", "chat.v1");

        var ws_sess, resp, err = client.ws("wss://stream.example.com/ws") { req =>
            req.bearer("token123");
            req.set_header("Sec-WebSocket-Protocol", "chat.v1");
        };

        sub.assert_true(err.ok(), "Client ws upgrade succeeded");
        sub.assert_eq(resp.status_code, 101, "Response status 101 Switching Protocols");
        sub.assert_bytes_eq(ws_sess.subprotocol[..], "chat.v1", "Subprotocol negotiated");

        // Test automatic receive on incoming Ping
        var incoming_ping: u8[>..] = [];
        let no_mask: u8[4] = [0, 0, 0, 0];
        wing::encode_ws_frame(incoming_ping, wing::WS_OPCODE_PING, "ping-payload", false, no_mask, true);

        var msg = wing::WsMessage { .. };
        var pong_reply: u8[>..] = [];
        let handled_ping = ws_sess.receive(incoming_ping[..], msg, pong_reply);
        sub.assert_true(handled_ping, "receive processed ping frame");
        sub.assert_eq(msg.opcode, wing::WS_OPCODE_PING, "Message opcode is PING");
        sub.assert_true(pong_reply.len > 0, "Automatic Pong response generated into reply buffer");

        // Verify that the reply is a valid Pong frame
        let pong_hdr, ok_pong = wing::parse_ws_frame_header(pong_reply[..]);
        sub.assert_true(ok_pong, "Parsed auto-pong frame header");
        sub.assert_eq(pong_hdr.opcode, wing::WS_OPCODE_PONG, "Opcode in auto-reply is PONG");

        // Server-side upgrade test with complex Connection header
        var server_req = wing::new_request("GET", "https://example.com/ws");
        server_req.set_header("Upgrade", "websocket");
        server_req.set_header("Connection", "keep-alive, Upgrade");
        server_req.set_header("Sec-WebSocket-Version", "13");
        server_req.set_header("Sec-WebSocket-Key", "dGhlIHNhbXBsZSBub25jZQ==");

        var server_resp = wing::Response { .. };
        let s_ws, ok_s = wing::ws_upgrade_request(server_req, server_resp, "chat.v1");
        sub.assert_true(ok_s, "Server upgrade succeeded");
        sub.assert_eq(server_resp.status_code, 101, "Server status 101");
        sub.assert_bytes_eq(server_resp.header("Sec-WebSocket-Accept"), "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=", "Server accept matches RFC 6455");
        sub.assert_false(s_ws.is_client, "Server session is_client is false");

        // Negative tests: wrong method
        var bad_meth_req = wing::new_request("POST", "https://example.com/ws");
        var bad_resp = wing::Response { .. };
        let _, ok_bad_m = wing::ws_upgrade_request(bad_meth_req, bad_resp);
        sub.assert_false(ok_bad_m, "POST upgrade rejected");
        sub.assert_eq(bad_resp.status_code, 405, "Status 405 Method Not Allowed");

        // Negative tests: wrong version
        var bad_ver_req = wing::new_request("GET", "https://example.com/ws");
        bad_ver_req.set_header("Upgrade", "websocket");
        bad_ver_req.set_header("Connection", "Upgrade");
        bad_ver_req.set_header("Sec-WebSocket-Version", "12");
        bad_ver_req.set_header("Sec-WebSocket-Key", "dGhlIHNhbXBsZSBub25jZQ==");
        bad_resp = wing::Response { .. };
        let _, ok_bad_v = wing::ws_upgrade_request(bad_ver_req, bad_resp);
        sub.assert_false(ok_bad_v, "WebSocket Version 12 rejected");
        sub.assert_eq(bad_resp.status_code, 426, "Status 426 Upgrade Required");
        sub.assert_bytes_eq(bad_resp.header("Sec-WebSocket-Version"), "13", "Required version 13 returned");
    };

    t.run("8. Multi-Frame Fragmented Message Assembly & Interleaved Control Frames") { sub =>
        var ws = wing::new_websocket_session(true); // client session
        let no_mask: u8[4] = [0, 0, 0, 0];

        // Fragment 1: TEXT with FIN=0
        var f1_wire: u8[..128] = [];
        wing::encode_ws_frame(f1_wire, wing::WS_OPCODE_TEXT, "Hello, ", false, no_mask, false);

        var msg1 = wing::WsMessage { .. };
        var reply1: u8[..128] = [];
        let ok1 = wing::receive(ws, f1_wire[..], msg1, reply1);
        sub.assert_true(ok1, "receive accepted initial fragment");
        sub.assert_false(msg1.is_valid, "Message not complete on initial fragment");

        // Interleaved Control Frame: PING with FIN=1 during fragmentation (RFC 6455 §5.4)
        var ping_wire: u8[..128] = [];
        wing::encode_ws_frame(ping_wire, wing::WS_OPCODE_PING, "mid-stream", false, no_mask, true);

        var ping_msg = wing::WsMessage { .. };
        var ping_reply: u8[..128] = [];
        let ok_p = wing::receive(ws, ping_wire[..], ping_msg, ping_reply);
        sub.assert_true(ok_p, "receive accepted interleaved PING");
        sub.assert_true(ping_msg.is_valid, "Ping message was delivered");
        sub.assert_eq(ping_msg.opcode, wing::WS_OPCODE_PING, "Ping opcode delivered");
        sub.assert_gt(ping_reply.len, 0, "Pong response generated for interleaved ping");

        // Fragment 2: CONTINUATION with FIN=1
        var f2_wire: u8[..128] = [];
        wing::encode_ws_frame(f2_wire, wing::WS_OPCODE_CONTINUATION, "World!", false, no_mask, true);

        var msg2 = wing::WsMessage { .. };
        var reply2: u8[..128] = [];
        let ok2 = wing::receive(ws, f2_wire[..], msg2, reply2);
        sub.assert_true(ok2, "receive accepted terminal CONTINUATION fragment");
        sub.assert_true(msg2.is_valid, "Message is valid upon terminal fragment");
        sub.assert_eq(msg2.opcode, wing::WS_OPCODE_TEXT, "Assembled message preserved original opcode (TEXT)");
        sub.assert_bytes_eq(msg2.data[..], "Hello, World!", "Assembled payload matches combined fragments");
    };

    t.run("9. Autobahn UTF-8 Strict Validation & Anomaly Rejection") { sub =>
        // 9.1 Invalid UTF-8 sequence in text frame (RFC 6455 §5.6, Autobahn Case 6.x)
        var ws1 = wing::new_websocket_session(true);
        let no_mask: u8[4] = [0, 0, 0, 0];

        var bad_text_wire: u8[..128] = [];
        let invalid_utf8: u8[4] = [0xCE, 0xBA, 0xE1, 0x00]; // 0xE1 followed by 0x00 is invalid UTF-8
        wing::encode_ws_frame(bad_text_wire, wing::WS_OPCODE_TEXT, invalid_utf8[..], false, no_mask, true);

        var msg1 = wing::WsMessage { .. };
        var reply1: u8[..128] = [];
        wing::receive(ws1, bad_text_wire[..], msg1, reply1);

        sub.assert_false(msg1.is_valid, "Invalid UTF-8 text rejected");
        sub.assert_true(ws1.is_closed, "Connection closed on invalid UTF-8");
        sub.assert_eq(ws1.close_code, wing::WS_STATUS_INVALID_PAYLOAD, "Close code 1007 Invalid Payload");

        // 9.2 Unexpected CONTINUATION without initial fragment
        var ws2 = wing::new_websocket_session(true);
        var unexpected_cont: u8[..128] = [];
        wing::encode_ws_frame(unexpected_cont, wing::WS_OPCODE_CONTINUATION, "orphan", false, no_mask, true);

        var msg2 = wing::WsMessage { .. };
        var reply2: u8[..128] = [];
        wing::receive(ws2, unexpected_cont[..], msg2, reply2);

        sub.assert_false(msg2.is_valid, "Orphan continuation rejected");
        sub.assert_true(ws2.is_closed, "Connection closed on protocol error");
        sub.assert_eq(ws2.close_code, wing::WS_STATUS_PROTOCOL_ERROR, "Close code 1002 Protocol Error");

        // 9.3 Interleaved data frame during fragmentation
        var ws3 = wing::new_websocket_session(true);
        var frag_start: u8[..128] = [];
        wing::encode_ws_frame(frag_start, wing::WS_OPCODE_TEXT, "part1", false, no_mask, false);
        var msg3 = wing::WsMessage { .. };
        var reply3: u8[..128] = [];
        wing::receive(ws3, frag_start[..], msg3, reply3);

        // Next frame is another TEXT frame instead of CONTINUATION
        var bad_interleave: u8[..128] = [];
        wing::encode_ws_frame(bad_interleave, wing::WS_OPCODE_BINARY, "binary-data", false, no_mask, true);
        wing::receive(ws3, bad_interleave[..], msg3, reply3);

        sub.assert_false(msg3.is_valid, "Interleaved data frame rejected");
        sub.assert_true(ws3.is_closed, "Connection closed on interleaving error");
        sub.assert_eq(ws3.close_code, wing::WS_STATUS_PROTOCOL_ERROR, "Close code 1002 Protocol Error");
    };

    t.run("10. Streaming consume_frame_view, >16KB Zero-Copy & Multi-Token Upgrade") { sub =>
        // 10.1 Unfragmented > 16 KB message via receive_view / consume_frame_view
        var ws_large = wing::new_websocket_session(false);
        let mask: u8[4] = [0x12, 0x34, 0x56, 0x78];
        var big_payload: u8[>..] = [];
        for i in 20000 {
            big_payload.push('A');
        }
        var big_wire: u8[>..] = [];
        wing::encode_ws_frame(big_wire, wing::WS_OPCODE_TEXT, big_payload[..], true, mask, true);

        // Partial slice: should return (0, false) without closing
        var view = wing::WsMessageView { .. };
        var reply: u8[..256] = [];
        let c_part, h_part = wing::consume_frame_view(ws_large, big_wire[..100], view, reply);
        sub.assert_eq(c_part, 0, "Partial valid frame consumes 0 bytes");
        sub.assert_false(h_part, "Partial valid frame returns handled=false");
        sub.assert_false(ws_large.is_closed, "Session stays open while waiting for frame bytes");

        // Full slice: should consume entire 20008-byte frame zero-copy
        let c_full, h_full = wing::consume_frame_view(ws_large, big_wire[..], view, reply);
        sub.assert_true(h_full, "Full 20KB frame handled");
        sub.assert_eq(c_full, big_wire.len, "Consumed exact frame length");
        sub.assert_false(ws_large.is_closed, "Session stays open on 20KB frame within 64KB max_payload_length");
        sub.assert_true(view.is_valid, "Zero-copy view is valid");
        sub.assert_eq(view.payload.len, 20000, "Zero-copy payload length is 20000");

        // 10.2 Multi-token Upgrade header in ws_upgrade_request and is_websocket_upgrade_request
        var upg_req = wing::new_request("GET", "https://example.com/ws");
        upg_req.set_header("Host", "example.com");
        upg_req.set_header("Upgrade", "h2c, WebSocket");
        upg_req.set_header("Connection", "keep-alive, Upgrade");
        upg_req.set_header("Sec-WebSocket-Version", "13");
        upg_req.set_header("Sec-WebSocket-Key", "dGhlIHNhbXBsZSBub25jZQ==");

        sub.assert_true(wing::is_websocket_upgrade_request(upg_req), "is_websocket_upgrade_request accepts multi-token Upgrade");
        var upg_resp = wing::Response { .. };
        let _, ok_upg = wing::ws_upgrade_request(upg_req, upg_resp);
        sub.assert_true(ok_upg, "ws_upgrade_request accepts multi-token Upgrade");
        sub.assert_eq(upg_resp.status_code, 101, "Status 101 Switching Protocols");
    };
}

fn test_http3_priority_update(t: core::T&) {
    t.run("1. HTTP/3 PRIORITY_UPDATE Frame Codec (RFC 9218 Section 7.2)") { sub =>
        let prio = wing::PriorityParam { urgency: 1, incremental: true };
        var wire: u8[>..] = [];
        sub.assert_true(internal::encode_h3_priority_update_request(wire, 8, prio), "encode H3 priority update request");

        let hdr, ok_hdr = internal::parse_h3_frame_header(wire[..], 0);
        sub.assert_true(ok_hdr, "parse H3 frame header");
        sub.assert_eq(hdr.frame_type, internal::H3_FRAME_PRIORITY_UPDATE_REQUEST, "Frame type is 0xF0700");

        let h3_payload_start = hdr.header_len as i64;
        let payload = wire[h3_payload_start..];
        let stream_id, parsed_prio, ok_prio = internal::parse_h3_priority_update_request(payload);
        sub.assert_true(ok_prio, "parse H3 priority update payload");
        sub.assert_eq(stream_id, 8, "Prioritized stream ID is 8");
        sub.assert_eq(parsed_prio.urgency as i64, 1, "Urgency is 1");
        sub.assert_true(parsed_prio.incremental, "Incremental is true");

        // Push stream priority update
        var push_wire: u8[>..] = [];
        sub.assert_true(internal::encode_h3_priority_update_push(push_wire, 42, prio), "encode H3 priority update push");
        let push_hdr, ok_push_hdr = internal::parse_h3_frame_header(push_wire[..], 0);
        sub.assert_true(ok_push_hdr, "parse push header");
        sub.assert_eq(push_hdr.frame_type, internal::H3_FRAME_PRIORITY_UPDATE_PUSH, "Frame type is 0xF0701");

        let push_start = push_hdr.header_len as i64;
        let push_id, parsed_push_prio, ok_push = internal::parse_h3_priority_update_push(push_wire[push_start..]);
        sub.assert_true(ok_push, "parse push payload");
        sub.assert_eq(push_id, 42, "Push ID is 42");
        sub.assert_eq(parsed_push_prio.urgency as i64, 1, "Push urgency is 1");
    };
}

fn test_server_sent_events(t: core::T&) {
    t.run("1. W3C EventSource Standard Streaming Parsing") { sub =>
        let stream_data = "data: first event\n\nevent: custom\ndata: second event line 1\ndata: second event line 2\nid: 42\nretry: 5000\n\n";

        var parser = wing::SseParser { .. };
        var events: wing::SseEvent[..10] = [];

        wing::sse_feed(parser, stream_data, events);

        sub.assert_eq(events.len, 2, "2 events dispatched from stream");

        // Event 1
        sub.assert_bytes_eq(events[0].event[..], "message", "Default event type is 'message'");
        sub.assert_bytes_eq(events[0].data[..], "first event", "Event 1 data");
        sub.assert_bytes_eq(events[0].id[..], "", "Event 1 has no id");

        // Event 2 (multi-line data, named event, id, retry)
        sub.assert_bytes_eq(events[1].event[..], "custom", "Event 2 type is 'custom'");
        sub.assert_bytes_eq(events[1].data[..], "second event line 1\nsecond event line 2", "Multi-line data joined by newline");
        sub.assert_bytes_eq(events[1].id[..], "42", "Event 2 id is 42");
        sub.assert_eq(events[1].retry_ms as i64, 5000, "Retry ms is 5000");
    };

    t.run("2. SSE Comment Lines and Keepalive Filtering") { sub =>
        let stream = ": this is a comment\n: keepalive ping\ndata: real data\n\n: another comment\n";
        var parser = wing::SseParser { .. };
        var events: wing::SseEvent[..10] = [];

        wing::sse_feed(parser, stream, events);
        sub.assert_eq(events.len, 1, "Only 1 event dispatched, comments ignored");
        sub.assert_bytes_eq(events[0].data[..], "real data", "Data content");
    };

    t.run("3. CRLF and CR Line Ending Normalization") { sub =>
        let stream_crlf = "data: hello\r\n\r\ndata: world\r\r";
        var parser = wing::SseParser { .. };
        var events: wing::SseEvent[..10] = [];

        wing::sse_feed(parser, stream_crlf, events);
        sub.assert_eq(events.len, 2, "2 events parsed across CRLF and CR boundaries");
        sub.assert_bytes_eq(events[0].data[..], "hello", "Event 0 data");
        sub.assert_bytes_eq(events[1].data[..], "world", "Event 1 data");
    };

    t.run("4. SSE Serializer and Wire Formatting") { sub =>
        var out: u8[>..] = [];
        wing::sse_format_event(out, "update", "line1\nline2", "id-99", 2500);

        let expected = "retry: 2500\nid: id-99\nevent: update\ndata: line1\ndata: line2\n\n";
        sub.assert_bytes_eq(out[..], expected, "SSE serialized event matches expected format");

        // Parse back through parser
        var parser = wing::SseParser { .. };
        var events: wing::SseEvent[..10] = [];
        wing::sse_feed(parser, out[..], events);
        sub.assert_eq(events.len, 1, "Roundtrip parsed 1 event");
        sub.assert_bytes_eq(events[0].event[..], "update", "Event type roundtrip");
        sub.assert_bytes_eq(events[0].data[..], "line1\nline2", "Multi-line data roundtrip");
        sub.assert_bytes_eq(events[0].id[..], "id-99", "Event ID roundtrip");
        sub.assert_eq(events[0].retry_ms as i64, 2500, "Retry ms roundtrip");
    };

    t.run("5. SseSubscription Ergonomics and Header Generation") { sub =>
        var subscr = wing::new_sse_subscription("https://api.example.com/stream");
        subscr.parser.last_event_id.append("evt-1234");

        var req: u8[>..] = [];
        wing::sse_build_request_headers(subscr, "api.example.com", "/stream", req);

        sub.assert_true(req.len > 0, "SSE request headers created");

        var events: wing::SseEvent[..5] = [];
        subscr.consume("data: chunked message\n\n", events);
        sub.assert_eq(events.len, 1, "Consumed 1 event via SseSubscription");
        sub.assert_bytes_eq(events[0].data[..], "chunked message", "Event content matches");
    };

    t.run("6. Aoni-Style Automated Client SSE Subscription") { sub =>
        var client = wing::new_client();
        wing::add_mock_sse(client, "https://api.example.com/events", "event: tick\nid: 1\ndata: {\"val\":100}\n\n");

        var sse_sub, resp, err = client.sse("https://api.example.com/events") { req =>
            req.bearer("token123");
        };

        sub.assert_true(err.ok(), "Client SSE connect succeeded");
        sub.assert_eq(resp.status_code, 200, "Response status 200 OK");
        sub.assert_true(sse_sub.connected, "Subscription marked connected");

        var events: wing::SseEvent[..5] = [];
        sse_sub.consume(resp.body[..], events);
        sub.assert_eq(events.len, 1, "Consumed 1 event from mock SSE stream");
        sub.assert_bytes_eq(events[0].event[..], "tick", "Event name is tick");
        sub.assert_bytes_eq(events[0].data[..], "{\"val\":100}", "Data payload matches");
        sub.assert_bytes_eq(events[0].id[..], "1", "Event ID matches");

        // Server-side response initialization
        var s_resp = wing::Response { .. };
        wing::init_response(s_resp);
        sub.assert_eq(s_resp.status_code, 200, "Server SSE status 200");
        sub.assert_bytes_eq(wing::header(s_resp, "Content-Type"), "text/event-stream", "Content-Type text/event-stream");
    };

    t.run("7. W3C EventSource Empty Data Dispatch, Leading BOM, and CR Sanitization") { sub =>
        // Empty data field ("data:\n\n") must dispatch an event with empty data,
        // and "data:\ndata: hello\n\n" must preserve the leading newline ("\nhello").
        let stream_empty = "\xEF\xBB\xBFdata:\n\ndata:\ndata: hello\n\n";
        var parser = wing::SseParser { .. };
        var events: wing::SseEvent[..10] = [];
        wing::sse_feed(parser, stream_empty, events);

        sub.assert_eq(events.len, 2, "Both empty-data and leading-empty-line events dispatched after BOM strip");
        sub.assert_bytes_eq(events[0].data[..], "", "Event 0 has empty string data");
        sub.assert_bytes_eq(events[1].data[..], "\nhello", "Event 1 preserves leading newline before second data line");

        // Serializer splits CRLF and bare CR in data
        var formatted: u8[>..] = [];
        wing::sse_format_event(formatted, "msg", "a\r\nb\rc\nd");
        sub.assert_bytes_eq(formatted[..], "event: msg\ndata: a\ndata: b\ndata: c\ndata: d\n\n", "CRLF and bare CR split into separate data lines");

        // Empty path defaults to "/"
        var sub_empty_path = wing::new_sse_subscription("https://example.com");
        var hdr_out: u8[..256] = [];
        wing::sse_build_request_headers(sub_empty_path, "example.com", "", hdr_out);
        sub.assert_true(core::starts_with(hdr_out[..], "GET / HTTP/1.1\r\n"), "Empty SSE path defaults to '/'");
    };
}

fn main() {
    var runner = core::new_runner("WebSocket & Server-Sent Events Verification Suite", core::Verbosity.Verbose);

    core::run_case(runner, "1. WebSocket Invariants & Compression Audit", test_frameforge_r1_websocket);
    core::run_case(runner, "2. WebSocket Frame Protocol Conformance", test_frameforge_r2_websocket);
    core::run_case(runner, "3. WebSocket Exhaustive Framing Invariants", test_frameforge_r3_websocket);
    core::run_case(runner, "4. Close Payload & Wire Status Code Invariants (§5.5.1 / §7.4)", test_ws_close_payload_rfc6455_invariants);
    core::run_case(runner, "5. Control Frame Limits & Fragmentation Bans (§5.5)", test_ws_control_frame_invariants);
    core::run_case(runner, "6. Streaming UTF-8 Invariants & Surrogate Rejection", test_ws_streaming_utf8_invariants);
    core::run_case(runner, "7. RFC 8441 Client Formatting", test_rfc8441_client_formatting);
    core::run_case(runner, "8. RFC 8441 Validation Invariants", test_rfc8441_validation_invariants);
    core::run_case(runner, "9. RFC 8441 Server Upgrade", test_rfc8441_server_upgrade);
    core::run_case(runner, "10. RFC 8441 Stream Data Framing", test_rfc8441_data_frame_payload);
    core::run_case(runner, "11. WebSocket (RFC 6455 & RFC 8441) Framing and Handshake", test_websocket_framing_and_handshake);
    core::run_case(runner, "12. HTTP/3 PRIORITY_UPDATE (RFC 9218) Frame Codec", test_http3_priority_update);
    core::run_case(runner, "13. Server-Sent Events (SSE / W3C EventSource) Engine", test_server_sent_events);

    let ok = core::finish(runner);
    assert(ok);
}
