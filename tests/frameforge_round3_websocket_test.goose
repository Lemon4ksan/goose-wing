// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Team FrameForge Protocol Audit Suite - Round 3 (Championship Round)
// Focus: RFC 6455 §5.4 Multibyte UTF-8 Boundary Splits Across Continuation Frames,
// RFC 7692 §7.1.1 Permessage-Deflate Sliding Window Context Takeover & Dictionary Retention,
// and Zero-Allocation SWAR 64-bit/32-bit XOR Payload Masking Loop Boundary Safety.
import std;
import core from "..";
import wing from "..";

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
        var c1_body: u8[..8] = [0xF0, 0x9F];
        var c1_wire: u8[..64] = [];
        wing::encode_ws_frame(c1_wire, wing::WS_OPCODE_TEXT, c1_body[..], false, no_mask, false);
        var vc1 = wing::WsMessageView { .. };
        var rc1: u8[..256] = [];
        wing::receive_view(ws3, c1_wire[..], vc1, rc1);
        sub.assert_false(ws3.is_closed, "Frag 1 of 4-byte codepoint accepted");

        var c2_body: u8[..8] = [0xA6];
        var c2_wire: u8[..64] = [];
        wing::encode_ws_frame(c2_wire, wing::WS_OPCODE_CONTINUATION, c2_body[..], false, no_mask, false);
        var vc2 = wing::WsMessageView { .. };
        var rc2: u8[..256] = [];
        wing::receive_view(ws3, c2_wire[..], vc2, rc2);
        sub.assert_false(ws3.is_closed, "Frag 2 of 4-byte codepoint accepted");

        var c3_body: u8[..8] = [0x80];
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
        var bad1_body: u8[..8] = ['h', 'i', 0xC3];
        var bad1_wire: u8[..64] = [];
        wing::encode_ws_frame(bad1_wire, wing::WS_OPCODE_TEXT, bad1_body[..], false, no_mask, false);
        var vb1 = wing::WsMessageView { .. };
        var rb1: u8[..256] = [];
        wing::receive_view(ws4, bad1_wire[..], vb1, rb1);

        var bad2_body: u8[..8] = [' ', 'x']; // 0x20 is not a valid UTF-8 continuation byte
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
        wing::enable_permessage_deflate(ws_c, wing::WS_COMPRESS_SHARED_COMPRESSOR, true, true);
        sub.assert_true(wing::ws_should_reset_compressor(ws_c), "Client with client_no_context_takeover resets compressor");
        sub.assert_true(wing::ws_should_reset_decompressor(ws_c), "Client with server_no_context_takeover resets decompressor");

        // Allow context takeover on client compressor (persistent sliding dictionary)
        wing::set_context_takeover(ws_c, false, false);
        sub.assert_false(wing::ws_should_reset_compressor(ws_c), "Compressor retains sliding window when client takeover allowed");
        sub.assert_false(wing::ws_should_reset_decompressor(ws_c), "Decompressor retains sliding window when server takeover allowed");

        // Server session configuration
        var ws_s = wing::new_websocket_session(false); // server
        wing::set_context_takeover(ws_s, false, true); // server retains, client resets
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

fn main() {
    var runner = core::new_runner("Team FrameForge Protocol Audit Suite - Round 3", core::Verbosity.Verbose);
    core::run_case(runner, "Team FrameForge RFC 6455 & RFC 7692 Round 3 Championship Audit", test_frameforge_r3_websocket);
    let ok = core::finish(runner);
    assert(ok);
}
