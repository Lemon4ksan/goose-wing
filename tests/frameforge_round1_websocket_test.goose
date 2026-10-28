// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Team FrameForge Protocol Audit Suite - Round 1
// Focus: RFC 6455 & RFC 7692 WebSocket Framing, Deflate Compression, RSV Spoofing, Masking, and Close Codes.
import std;
import core from "..";
import wing from "..";

fn test_frameforge_r1_websocket(t: core::T&) {
    // ------------------------------------------------------------------------
    // Bug 1: RFC 7692 §8.1: Premature UTF-8 validation on raw compressed text wire bytes
    // ------------------------------------------------------------------------
    t.run("1. RFC 7692 §8.1 Compressed Text Frame UTF-8 Validation Boundary") { sub =>
        var ws = wing::new_websocket_session(true); // client session
        wing::enable_permessage_deflate(ws, wing::WS_COMPRESS_SHARED_COMPRESSOR);

        var comp = wing::new_shared_ws_compressor();
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
        sub.assert_true(core::validate_utf8(decomp_text[..]), "Decompressed payload is valid UTF-8 per RFC 7692 §8.1");
        sub.assert_bytes_eq(decomp_text[..], original_text, "Decompressed payload matches original plaintext");
    };

    // ------------------------------------------------------------------------
    // Bug 2: RFC 7692 §5.1 & RFC 6455 §5.4: Fragmented Compressed Message Assembly
    // ------------------------------------------------------------------------
    t.run("2. RFC 7692 §5.1 Fragmented Compressed Message Assembly and RSV1 State Retention") { sub =>
        var ws = wing::new_websocket_session(true);
        wing::enable_permessage_deflate(ws, wing::WS_COMPRESS_SHARED_COMPRESSOR);

        var comp = wing::new_shared_ws_compressor();
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

fn main() {
    var runner = core::new_runner("Team FrameForge Protocol Audit Suite - Round 1", core::Verbosity.Verbose);
    core::run_case(runner, "Team FrameForge RFC 6455 & RFC 7692 Invariant Audit", test_frameforge_r1_websocket);
    let ok = core::finish(runner);
    assert(ok);
}
