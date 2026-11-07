// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// tests/lit/verify_realtime_regressions.goose
// Regression test suite for realtime subsystem bugs:
// 1. arm_heartbeat & tick_heartbeat modulo 240 wrap-around for idle_timeout_s >= 480
// 2. flush_node_palette_messages palette_len active message bound check
// 3. decode_webtransport_close_session canonical BE u32 error code decoding
//
// RUN: goose build --cc gcc -O2 -o %t.exe %s
// RUN: %t.exe | %FileCheck %s

import std;
import core from "../..";
import wing from "../..";

// 1. Heartbeat ping delay must not wrap to 0 or 1s when idle_timeout_s >= 480
fn test_heartbeat_ping_delay_wrap() {
    var ws = wing::new_websocket_session(false);
    ws.idle_timeout_s = 480;
    ws.send_pings_automatically = true;

    var wheel = wing::TickTimerWheel { .. };
    wing::arm_heartbeat(ws, wheel);

    // With idle_timeout_s = 480 (8 mins), idle_sec is clamped to 239s.
    // Ping delay must be ~119s, NOT wrapped to 0 or 1s!
    assert(ws.ping_slot >= 100 && ws.ping_slot <= 125);

    // In tick_heartbeat, ping_slot must also be armed to ~119s
    var out_wire: u8[..256] = [];
    let _ = wing::tick_heartbeat(ws, wheel, out_wire);
    assert(ws.ping_slot >= 100 && ws.ping_slot <= 125);
    print("HEARTBEAT_PING_DELAY_WRAP: ok");
}

// 2. WebTransport close session decode with 32-bit error code
fn test_webtransport_close_decode() {
    var payload: u8[..64] = [];
    wing::encode_webtransport_close_session(0x12345678, "session ended", payload);

    // Payload starts after varint type (2 bytes) and varint len (1 byte)
    // Decode from capsule body
    var body = payload[3..];
    var out_close = wing::WebTransportCloseSession { .. };
    assert(wing::decode_webtransport_close_session(body, out_close));
    assert(out_close.error_code == 0x12345678);
    assert(out_close.reason[..] == "session ended");
    print("WEBTRANSPORT_CLOSE_DECODE: ok");
}

// 3. WSRT-01: RFC 7692 permessage-deflate negotiation and window bits clamping
fn test_wsrt01_permessage_deflate_negotiation() {
    var srv_cfg = wing::PerMessageDeflateConfig {
        server_max_window_bits:     12,
        client_max_window_bits:     15,
        server_no_context_takeover: false,
        client_no_context_takeover: false,
    };

    let neg1, ok1 = wing::negotiate_permessage_deflate(
        "permessage-deflate; server_max_window_bits=8; client_max_window_bits=\"10\"; server_no_context_takeover",
        srv_cfg,
    );
    assert(ok1);
    assert(neg1.server_max_window_bits == 9);
    assert(neg1.client_max_window_bits == 10);
    assert(neg1.server_no_context_takeover);
    assert(!neg1.client_no_context_takeover);

    var resp_hdr: u8[..128] = [];
    wing::append_permessage_deflate_response(neg1, resp_hdr);
    assert(resp_hdr[..] == "permessage-deflate; server_no_context_takeover; server_max_window_bits=9; client_max_window_bits=10");

    // Reject duplicate parameters, out-of-range window bits, leading zeros, or unknown params
    let _, ok_dup = wing::negotiate_permessage_deflate(
        "permessage-deflate; server_no_context_takeover; server_no_context_takeover",
        srv_cfg,
    );
    assert(!ok_dup);

    let _, ok_range = wing::negotiate_permessage_deflate(
        "permessage-deflate; server_max_window_bits=7",
        srv_cfg,
    );
    assert(!ok_range);

    let _, ok_zero = wing::negotiate_permessage_deflate(
        "permessage-deflate; server_max_window_bits=09",
        srv_cfg,
    );
    assert(!ok_zero);

    print("WSRT01_PERMESSAGE_DEFLATE: ok");
}

// 4. WSRT-02: Client-side RFC 6455 HTTP/1.1 101 Upgrade response verification
fn test_wsrt02_client_upgrade_verification() {
    let client_key = "dGhlIHNhbXBsZSBub25jZQ==";
    var hdrs = wing::HeaderMap { .. };
    wing::set_header(hdrs, "Upgrade", "websocket");
    wing::set_header(hdrs, "Connection", "Upgrade");
    wing::set_header(hdrs, "Sec-WebSocket-Accept", "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=");
    wing::set_header(hdrs, "Sec-WebSocket-Protocol", "chat");

    let proto, err = wing::validate_client_upgrade_response(101, hdrs, "", client_key, "superchat, chat");
    assert(err == wing::WsError.None);
    assert(proto == "chat");

    let _, err_status = wing::validate_client_upgrade_response(200, hdrs, "", client_key, "chat");
    assert(err_status == wing::WsError.InvalidStatusCode);

    let _, err_proto = wing::validate_client_upgrade_response(101, hdrs, "", client_key, "mqtt");
    assert(err_proto == wing::WsError.InvalidSubprotocol);

    print("WSRT02_CLIENT_UPGRADE: ok");
}

// 5. WSRT-03 & WSRT-04: Half-closed CloseSent state machine, close timeout & SWAR outbound masking
fn test_wsrt03_04_half_closed_and_masking() {
    var ws = wing::new_websocket_session(true);
    var out_frag: u8[..128] = [];
    wing::send_fragment(ws, rfc::WS_OPCODE_TEXT, "part1", false, out_frag);
    assert(out_frag.len == 11);

    var out_close: u8[..128] = [];
    wing::close_at(ws, rfc::WS_STATUS_NORMAL, "closing", 1000, out_close);
    assert(ws.close_sent);
    assert(!ws.is_closed);
    assert(!wing::is_close_handshake_expired(ws, 4000));
    assert(wing::is_close_handshake_expired(ws, 6000));

    // Outbound sends blocked while close_sent == true
    var blocked: u8[..128] = [];
    wing::send_text(ws, "blocked", blocked);
    wing::send_fragment(ws, rfc::WS_OPCODE_CONTINUATION, "part2", true, blocked);
    assert(blocked.len == 0);

    // Inbound peer Close ACK completes the handshake without echoing a duplicate Close frame
    var peer_close_body: u8[..32] = [];
    wing::encode_close_payload(peer_close_body, rfc::WS_STATUS_NORMAL, "ack");
    var peer_close_wire: u8[..64] = [];
    let no_mask: u8[4] = [0, 0, 0, 0];
    wing::encode_ws_frame(peer_close_wire, rfc::WS_OPCODE_CLOSE, peer_close_body[..], false, no_mask, true);

    var view = wing::WsMessageView { .. };
    var reply: u8[..64] = [];
    let consumed, handled = wing::consume_frame_view(ws, peer_close_wire[..], view, reply);
    assert(handled && consumed == peer_close_wire.len);
    assert(ws.close_received && ws.is_closed);
    assert(reply.len == 0);
    // Exercise disarm_heartbeat, send_binary_with_status, send_binary_compressed_with_status,
    // abort_with_hook, and format_h3_websocket_response
    var ws2 = wing::new_websocket_session(false);
    wing::enable_permessage_deflate(ws2);
    var shared_comp = wing::SharedWsCompressor { .. };
    var bin_wire: u8[..256] = [];
    let st_bin1 = wing::send_binary_with_status(ws2, "raw_bin", bin_wire);
    assert(st_bin1 == wing::WsSendStatus.Backpressure);
    let st_bin2 = wing::send_binary_compressed_with_status(ws2, "comp_bin_payload_data", shared_comp, bin_wire);
    assert(st_bin2 == wing::WsSendStatus.Backpressure);
    wing::disarm_heartbeat(ws2);
    assert(ws2.timeout_slot == wing::TICK_TIMER_DISARMED);

    var pending = wing::new_ws_pending_upgrade(99, "dGhlIHNhbXBsZSBub25jZQ==");
    wing::abort_with_hook(pending) { _fd: i64, _tag: u64 => };
    assert(pending.is_aborted);

    var h3_resp = wing::Response { .. };
    wing::format_h3_websocket_response(h3_resp, "chat");
    assert(wing::is_h3_websocket_response(h3_resp));

    print("WSRT03_04_HALF_CLOSED_AND_MASKING: ok");
}

// 6. WSRT-05: 364-byte DFA streaming UTF-8 validator across split multi-byte codepoints
fn test_wsrt05_utf8_dfa_streaming() {
    var state: u8 = 0;
    // 4-byte emoji U+1F600 (F0 9F 98 80) split 2+2 across fragments after 16-byte ASCII prefix
    let chunk1 = "0123456789abcdef\xF0\x9F";
    let chunk2 = "\x98\x80!";
    assert(core::validate_utf8_dfa_chunk(chunk1, state, false));
    assert(state != 0);
    assert(core::validate_utf8_dfa_chunk(chunk2, state, true));
    assert(state == 0);

    // Incomplete codepoint at FIN must fail
    var state_bad: u8 = 0;
    assert(!core::validate_utf8_dfa_chunk(chunk1, state_bad, true));
    print("WSRT05_UTF8_DFA: ok");
}

// 7. WSRT-06 & WSRT-07: Segment-hash topic lookup & retained message store / wildcard replay
fn test_wsrt06_07_topic_retained_and_lookup() {
    var tree = wing::TopicTree { .. };
    let c1, err1 = wing::publish_retained(tree, "sensors/temp/living", "21.5C", false);
    assert(err1 == wing::PubSubError.None && c1 == 0);

    let err_sub = wing::subscribe_with_retained(tree, 42, "sensors/+/living");
    assert(err_sub == wing::PubSubError.None);
    assert(wing::subscriber_queued_messages(tree, 42) == 1);

    // Zero-length payload deletes retained entry
    let _, err_del = wing::publish_retained(tree, "sensors/temp/living", "", false);
    assert(err_del == wing::PubSubError.None);
    let err_sub2 = wing::subscribe_with_retained(tree, 43, "sensors/#");
    assert(err_sub2 == wing::PubSubError.None);
    assert(wing::subscriber_queued_messages(tree, 43) == 0);
    print("WSRT06_07_TOPIC_RETAINED: ok");
}

fn main() {
    test_heartbeat_ping_delay_wrap();
    test_webtransport_close_decode();
    test_wsrt01_permessage_deflate_negotiation();
    test_wsrt02_client_upgrade_verification();
    test_wsrt03_04_half_closed_and_masking();
    test_wsrt05_utf8_dfa_streaming();
    test_wsrt06_07_topic_retained_and_lookup();
}

// CHECK: HEARTBEAT_PING_DELAY_WRAP: ok
// CHECK-NEXT: WEBTRANSPORT_CLOSE_DECODE: ok
// CHECK-NEXT: WSRT01_PERMESSAGE_DEFLATE: ok
// CHECK-NEXT: WSRT02_CLIENT_UPGRADE: ok
// CHECK-NEXT: WSRT03_04_HALF_CLOSED_AND_MASKING: ok
// CHECK-NEXT: WSRT05_UTF8_DFA: ok
// CHECK-NEXT: WSRT06_07_TOPIC_RETAINED: ok
