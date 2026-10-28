// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Team FrameForge Protocol Audit Suite - Round 2
// Focus: RFC 6455 & RFC 7692 Decompression Bomb Defense, Payload Bounds Fast-Fail (1009),
// Interleaved Control Frames in Compressed Streams, and Close Handshake Idempotence.
import std;
import core from "..";
import wing from "..";

fn test_frameforge_r2_websocket(t: core::T&) {
    // ------------------------------------------------------------------------
    // Bug 8: RFC 7692 §7.2 & RFC 6455 §7.4.1 (1009): Decompression Bomb Abort
    // ------------------------------------------------------------------------
    t.run("1. RFC 7692 Decompression Bomb Defense and Buffer Sanitization") { sub =>
        var comp = wing::new_shared_ws_compressor();
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
        sub.assert_eq(wing::get_max_payload_length(ws), 512, "Max payload length configured to 512 bytes");

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

        var comp = wing::new_shared_ws_compressor();
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
        var close_body: u8[..64] = [];
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
        sub.assert_true(wing::is_close_received(ws_srv), "close_received flag is true");
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

fn main() {
    var runner = core::new_runner("Team FrameForge Protocol Audit Suite - Round 2", core::Verbosity.Verbose);
    core::run_case(runner, "Team FrameForge RFC 6455 & RFC 7692 Round 2 Audit", test_frameforge_r2_websocket);
    let ok = core::finish(runner);
    assert(ok);
}
