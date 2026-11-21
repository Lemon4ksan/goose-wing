// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Consolidated Goose LIT Verification Suite: lit_websocket_and_sse
// RUN: goose build -O2 -o %t.exe %s
// RUN: %t.exe | %FileCheck %s

import std;
import core from "../..";
import wing from "../..";
import wire_kit from ".";

// ============================================================================
// 1. verify_realtime_regressions (1/8)
// ============================================================================
// CHECK: === [1/8] verify_realtime_regressions ===

// tests/lit/verify_realtime_regressions.goose
// Regression test suite for realtime subsystem bugs:
// 1. arm_heartbeat & tick_heartbeat modulo 240 wrap-around for idle_timeout_s >= 480
// 2. flush_node_palette_messages palette_len active message bound check
// 3. decode_webtransport_close_session canonical BE u32 error code decoding
//

// 1. Heartbeat ping delay must not wrap to 0 or 1s when idle_timeout_s >= 480
fn test_heartbeat_ping_delay_wrap() {
    var ws = realtime::new_websocket_session(false);
    ws.idle_timeout_s = 480;
    ws.send_pings_automatically = true;

    var wheel = core::TickTimerWheel { .. };
    realtime::arm_heartbeat(ws, wheel);

    // With idle_timeout_s = 480 (8 mins), idle_sec is clamped to 239s.
    // Ping delay must be ~119s, NOT wrapped to 0 or 1s!
    assert(ws.ping_slot >= 100 && ws.ping_slot <= 125);

    // In tick_heartbeat, ping_slot must also be armed to ~119s
    var out_wire: u8[..256] = [];
    let _ = realtime::tick_heartbeat(ws, wheel, out_wire);
    assert(ws.ping_slot >= 100 && ws.ping_slot <= 125);
    print("HEARTBEAT_PING_DELAY_WRAP: ok");
}

// 2. WebTransport close session decode with 32-bit error code
fn test_webtransport_close_decode() {
    var payload: u8[..64] = [];
    realtime::encode_webtransport_close_session(0x12345678, "session ended", payload);

    // Payload starts after varint type (2 bytes) and varint len (1 byte)
    // Decode from capsule body
    var body = payload[3..];
    var out_close = realtime::WebTransportCloseSession { .. };
    assert(realtime::decode_webtransport_close_session(body, out_close));
    assert(out_close.error_code == 0x12345678);
    assert(out_close.reason[..] == "session ended");
    print("WEBTRANSPORT_CLOSE_DECODE: ok");
}

// 3. WSRT-01: RFC 7692 permessage-deflate negotiation and window bits clamping
fn test_wsrt01_permessage_deflate_negotiation() {
    var srv_cfg = realtime::PerMessageDeflateConfig {
        server_max_window_bits:     12,
        client_max_window_bits:     15,
        server_no_context_takeover: false,
        client_no_context_takeover: false,
    };

    let neg1, ok1 = realtime::negotiate_permessage_deflate(
        "permessage-deflate; server_max_window_bits=8; client_max_window_bits=\"10\"; server_no_context_takeover",
        srv_cfg,
    );
    assert(ok1);
    assert(neg1.server_max_window_bits == 9);
    assert(neg1.client_max_window_bits == 10);
    assert(neg1.server_no_context_takeover);
    assert(!neg1.client_no_context_takeover);

    var resp_hdr: u8[..128] = [];
    realtime::append_permessage_deflate_response(neg1, resp_hdr);
    assert(resp_hdr[..] == "permessage-deflate; server_no_context_takeover; server_max_window_bits=9; client_max_window_bits=10");

    // Reject duplicate parameters, out-of-range window bits, leading zeros, or unknown params
    let _, ok_dup = realtime::negotiate_permessage_deflate(
        "permessage-deflate; server_no_context_takeover; server_no_context_takeover",
        srv_cfg,
    );
    assert(!ok_dup);

    let _, ok_range = realtime::negotiate_permessage_deflate(
        "permessage-deflate; server_max_window_bits=7",
        srv_cfg,
    );
    assert(!ok_range);

    let _, ok_zero = realtime::negotiate_permessage_deflate(
        "permessage-deflate; server_max_window_bits=09",
        srv_cfg,
    );
    assert(!ok_zero);

    print("WSRT01_PERMESSAGE_DEFLATE: ok");
}

// 4. WSRT-02: Client-side RFC 6455 HTTP/1.1 101 Upgrade response verification
fn test_wsrt02_client_upgrade_verification() {
    let client_key = "dGhlIHNhbXBsZSBub25jZQ==";
    var hdrs = http::HeaderMap { .. };
    http::set_header(hdrs, "Upgrade", "websocket");
    http::set_header(hdrs, "Connection", "Upgrade");
    http::set_header(hdrs, "Sec-WebSocket-Accept", "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=");
    http::set_header(hdrs, "Sec-WebSocket-Protocol", "chat");

    let proto, err = realtime::validate_client_upgrade_response(101, hdrs, "", client_key, "superchat, chat");
    assert(err == realtime::WsError.None);
    assert(proto == "chat");

    let _, err_status = realtime::validate_client_upgrade_response(200, hdrs, "", client_key, "chat");
    assert(err_status == realtime::WsError.InvalidStatusCode);

    let _, err_proto = realtime::validate_client_upgrade_response(101, hdrs, "", client_key, "mqtt");
    assert(err_proto == realtime::WsError.InvalidSubprotocol);

    print("WSRT02_CLIENT_UPGRADE: ok");
}

// 5. WSRT-03 & WSRT-04: Half-closed CloseSent state machine, close timeout & SWAR outbound masking
fn test_wsrt03_04_half_closed_and_masking() {
    var ws = realtime::new_websocket_session(true);
    var out_frag: u8[..128] = [];
    realtime::send_fragment(ws, rfc::WS_OPCODE_TEXT, "part1", false, out_frag);
    assert(out_frag.len == 11);

    var out_close: u8[..128] = [];
    realtime::close_at(ws, rfc::WS_STATUS_NORMAL, "closing", 1000, out_close);
    assert(ws.close_sent);
    assert(!ws.is_closed);
    assert(!realtime::is_close_handshake_expired(ws, 4000));
    assert(realtime::is_close_handshake_expired(ws, 6000));

    // Outbound sends blocked while close_sent == true
    var blocked: u8[..128] = [];
    realtime::send_text(ws, "blocked", blocked);
    realtime::send_fragment(ws, rfc::WS_OPCODE_CONTINUATION, "part2", true, blocked);
    assert(blocked.len == 0);

    // Inbound peer Close ACK completes the handshake without echoing a duplicate Close frame
    var peer_close_body: u8[..32] = [];
    realtime::encode_close_payload(peer_close_body, rfc::WS_STATUS_NORMAL, "ack");
    var peer_close_wire: u8[..64] = [];
    let no_mask: u8[4] = [0, 0, 0, 0];
    realtime::encode_ws_frame(peer_close_wire, rfc::WS_OPCODE_CLOSE, peer_close_body[..], false, no_mask, true);

    var view = realtime::WsMessageView { .. };
    var reply: u8[..64] = [];
    let consumed, handled = realtime::consume_frame_view(ws, peer_close_wire[..], view, reply);
    assert(handled && consumed == peer_close_wire.len);
    assert(ws.close_received && ws.is_closed);
    assert(reply.len == 0);
    // Exercise disarm_heartbeat, send_binary_with_status, send_binary_compressed_with_status,
    // abort_with_hook, and format_h3_websocket_response
    var ws2 = realtime::new_websocket_session(false);
    realtime::enable_permessage_deflate(ws2);
    var shared_comp = realtime::SharedWsCompressor { .. };
    var bin_wire: u8[..256] = [];
    let st_bin1 = realtime::send_binary_with_status(ws2, "raw_bin", bin_wire);
    assert(st_bin1 == realtime::WsSendStatus.Backpressure);
    let st_bin2 = realtime::send_binary_compressed_with_status(ws2, "comp_bin_payload_data", shared_comp, bin_wire);
    assert(st_bin2 == realtime::WsSendStatus.Backpressure);
    realtime::disarm_heartbeat(ws2);
    assert(ws2.timeout_slot == core::TICK_TIMER_DISARMED);

    var pending = realtime::new_ws_pending_upgrade(99, "dGhlIHNhbXBsZSBub25jZQ==");
    realtime::abort_with_hook(pending) { _fd: i64, _tag: u64 => };
    assert(pending.is_aborted);

    var h3_resp = http::Response { .. };
    realtime::format_h3_websocket_response(h3_resp, "chat");
    assert(realtime::is_h3_websocket_response(h3_resp));

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
    var tree = realtime::TopicTree { .. };
    let c1, err1 = realtime::publish_retained(tree, "sensors/temp/living", "21.5C", false);
    assert(err1 == realtime::PubSubError.None && c1 == 0);

    let err_sub = realtime::subscribe_with_retained(tree, 42, "sensors/+/living");
    assert(err_sub == realtime::PubSubError.None);
    assert(realtime::subscriber_queued_messages(tree, 42) == 1);

    // Zero-length payload deletes retained entry
    let _, err_del = realtime::publish_retained(tree, "sensors/temp/living", "", false);
    assert(err_del == realtime::PubSubError.None);
    let err_sub2 = realtime::subscribe_with_retained(tree, 43, "sensors/#");
    assert(err_sub2 == realtime::PubSubError.None);
    assert(realtime::subscriber_queued_messages(tree, 43) == 0);
    print("WSRT06_07_TOPIC_RETAINED: ok");
}

fn run_01_verify_realtime_regressions() {
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

// ============================================================================
// 2. verify_realtime_spec_invariants (2/8)
// ============================================================================
// CHECK: === [2/8] verify_realtime_spec_invariants ===

// tests/lit/verify_realtime_spec_invariants.goose
// Rigorous protocol specification verification for:
// 1. WebSocket Control Frames (RFC 6455 В§5.5) - length <= 125, non-fragmented (FIN=1)
// 2. WebSocket RSV Bits (RFC 6455 В§5.2, RFC 7692 В§5.1) - zero unless negotiated
// 3. WebSocket Close Codes (RFC 6455 В§7.4.1, В§7.4.2) - invalid/reserved code rejection
// 4. Cookie Syntax & Prefixes (RFC 6265bis В§4.1.3, RFC 6265 В§4.1.1) - __Secure-, __Host-, token & cookie-octet
//

// ---- WebSocket Control Frames (RFC 6455 В§5.5) ---------------------------

fn test_ws_control_frame_invariants() {
    print("--- 1. WS Control Frames (RFC 6455 Section 5.5) ---\n");

    // Case 1.1: Ping with payload > 125 bytes MUST fail with PROTOCOL_ERROR (1002)
    var ws1 = realtime::new_websocket_session(false);
    var reply1: u8[>..] = [];
    var msg1 = realtime::WsMessage { .. };
    var big_ping: u8[>..] = [];
    // 0x89 = FIN=1, opcode=9 (Ping); 0xFE = Masked=1, len=126; extended length 0x007E (126 bytes)
    wire_kit::parse_hex("89FE007E11223344", big_ping);
    for _ in 126 { big_ping.push(0xAA); }
    let _ = realtime::receive(ws1, big_ping[..], msg1, reply1);
    print("PING_OVERSIZE_126: closed=", ws1.is_closed, " code=", ws1.close_code, "\n");
    // CHECK: PING_OVERSIZE_126: closed=true code=1002

    // Case 1.2: Fragmented Ping (FIN=0) MUST fail with PROTOCOL_ERROR (1002)
    var ws2 = realtime::new_websocket_session(false);
    var reply2: u8[>..] = [];
    var msg2 = realtime::WsMessage { .. };
    var frag_ping: u8[>..] = [];
    // 0x09 = FIN=0, opcode=9 (Ping); 0x84 = Masked=1, len=4
    wire_kit::parse_hex("09841122334468656C6C", frag_ping);
    let _ = realtime::receive(ws2, frag_ping[..], msg2, reply2);
    print("PING_FRAGMENTED: closed=", ws2.is_closed, " code=", ws2.close_code, "\n");
    // CHECK: PING_FRAGMENTED: closed=true code=1002

    // Case 1.3: Fragmented Close (FIN=0) MUST fail with PROTOCOL_ERROR (1002)
    var ws3 = realtime::new_websocket_session(false);
    var reply3: u8[>..] = [];
    var msg3 = realtime::WsMessage { .. };
    var frag_close: u8[>..] = [];
    // 0x08 = FIN=0, opcode=8 (Close); 0x82 = Masked=1, len=2; payload code 1000 (0x03E8)
    wire_kit::parse_hex("08821122334412CA", frag_close);
    let _ = realtime::receive(ws3, frag_close[..], msg3, reply3);
    print("CLOSE_FRAGMENTED: closed=", ws3.is_closed, " code=", ws3.close_code, "\n");
    // CHECK: CLOSE_FRAGMENTED: closed=true code=1002

    // Case 1.4: Standalone parse_close_payload with payload > 125 bytes MUST fail
    var over_close_payload: u8[>..] = [];
    over_close_payload.push(0x03);
    over_close_payload.push(0xE8); // code 1000
    for _ in 124 { over_close_payload.push('x'); } // total 126 bytes
    let _, _, ok_over = realtime::parse_close_payload(over_close_payload[..]);
    print("PARSE_CLOSE_OVER_125: ok=", ok_over, "\n");
    // CHECK: PARSE_CLOSE_OVER_125: ok=false
}

// ---- WebSocket RSV Bits (RFC 6455 В§5.2) ---------------------------------

fn test_ws_rsv_bit_invariants() {
    print("--- 2. WS RSV Bits (RFC 6455 Section 5.2) ---\n");

    // Case 2.1: RSV1=1 without negotiated extension MUST fail with PROTOCOL_ERROR (1002)
    var ws1 = realtime::new_websocket_session(false);
    var reply1: u8[>..] = [];
    var msg1 = realtime::WsMessage { .. };
    var rsv1_frame: u8[>..] = [];
    // 0xC1 = FIN=1, RSV1=1, opcode=1 (Text); Masked=1, len=5
    wire_kit::parse_hex("C1851122334468656C6C6F", rsv1_frame);
    let _ = realtime::receive(ws1, rsv1_frame[..], msg1, reply1);
    print("RSV1_NO_EXT: closed=", ws1.is_closed, " code=", ws1.close_code, "\n");
    // CHECK: RSV1_NO_EXT: closed=true code=1002

    // Case 2.2: RSV2=1 MUST fail with PROTOCOL_ERROR (1002)
    var ws2 = realtime::new_websocket_session(false);
    var reply2: u8[>..] = [];
    var msg2 = realtime::WsMessage { .. };
    var rsv2_frame: u8[>..] = [];
    // 0xA1 = FIN=1, RSV2=1, opcode=1 (Text); Masked=1, len=5
    wire_kit::parse_hex("A1851122334468656C6C6F", rsv2_frame);
    let _ = realtime::receive(ws2, rsv2_frame[..], msg2, reply2);
    print("RSV2_NONZERO: closed=", ws2.is_closed, " code=", ws2.close_code, "\n");
    // CHECK: RSV2_NONZERO: closed=true code=1002

    // Case 2.3: RSV3=1 MUST fail with PROTOCOL_ERROR (1002)
    var ws3 = realtime::new_websocket_session(false);
    var reply3: u8[>..] = [];
    var msg3 = realtime::WsMessage { .. };
    var rsv3_frame: u8[>..] = [];
    // 0x91 = FIN=1, RSV3=1, opcode=1 (Text); Masked=1, len=5
    wire_kit::parse_hex("91851122334468656C6C6F", rsv3_frame);
    let _ = realtime::receive(ws3, rsv3_frame[..], msg3, reply3);
    print("RSV3_NONZERO: closed=", ws3.is_closed, " code=", ws3.close_code, "\n");
    // CHECK: RSV3_NONZERO: closed=true code=1002

    // Case 2.4: RSV1=1 on control frame (Ping) MUST fail even if compression enabled
    var ws4 = realtime::new_websocket_session(false);
    realtime::enable_permessage_deflate(ws4);
    var reply4: u8[>..] = [];
    var msg4 = realtime::WsMessage { .. };
    var rsv1_ping: u8[>..] = [];
    // 0xC9 = FIN=1, RSV1=1, opcode=9 (Ping); Masked=1, len=4
    wire_kit::parse_hex("C9841122334468656C6C", rsv1_ping);
    let _ = realtime::receive(ws4, rsv1_ping[..], msg4, reply4);
    print("RSV1_ON_PING: closed=", ws4.is_closed, " code=", ws4.close_code, "\n");
    // CHECK: RSV1_ON_PING: closed=true code=1002
}

// ---- WebSocket Close Code Validation (RFC 6455 В§7.4) --------------------

fn test_ws_close_code_invariants() {
    print("--- 3. WS Close Codes (RFC 6455 Section 7.4) ---\n");

    // Permitted codes
    print("CODE_1000_OK: ", rfc::is_valid_ws_close_code(1000), "\n");
    print("CODE_3000_OK: ", rfc::is_valid_ws_close_code(3000), "\n");
    print("CODE_4999_OK: ", rfc::is_valid_ws_close_code(4999), "\n");
    // CHECK: CODE_1000_OK: true
    // CHECK: CODE_3000_OK: true
    // CHECK: CODE_4999_OK: true

    // Forbidden codes on the wire
    print("CODE_0_FORBIDDEN: ", !rfc::is_valid_ws_close_code(0), "\n");
    print("CODE_999_FORBIDDEN: ", !rfc::is_valid_ws_close_code(999), "\n");
    print("CODE_1004_FORBIDDEN: ", !rfc::is_valid_ws_close_code(1004), "\n");
    print("CODE_1005_FORBIDDEN: ", !rfc::is_valid_ws_close_code(1005), "\n");
    print("CODE_1006_FORBIDDEN: ", !rfc::is_valid_ws_close_code(1006), "\n");
    print("CODE_1015_FORBIDDEN: ", !rfc::is_valid_ws_close_code(1015), "\n");
    print("CODE_1016_FORBIDDEN: ", !rfc::is_valid_ws_close_code(1016), "\n");
    print("CODE_2999_FORBIDDEN: ", !rfc::is_valid_ws_close_code(2999), "\n");
    print("CODE_5000_FORBIDDEN: ", !rfc::is_valid_ws_close_code(5000), "\n");
    // CHECK: CODE_0_FORBIDDEN: true
    // CHECK: CODE_999_FORBIDDEN: true
    // CHECK: CODE_1004_FORBIDDEN: true
    // CHECK: CODE_1005_FORBIDDEN: true
    // CHECK: CODE_1006_FORBIDDEN: true
    // CHECK: CODE_1015_FORBIDDEN: true
    // CHECK: CODE_1016_FORBIDDEN: true
    // CHECK: CODE_2999_FORBIDDEN: true
    // CHECK: CODE_5000_FORBIDDEN: true

    // Wire Close frame with code 1005 received -> MUST fail with 1002
    var ws1 = realtime::new_websocket_session(false);
    var reply1: u8[>..] = [];
    var msg1 = realtime::WsMessage { .. };
    var close_1005: u8[>..] = [];
    wire_kit::parse_hex("88820000000003ED", close_1005); // 0x03ED = 1005
    let _ = realtime::receive(ws1, close_1005[..], msg1, reply1);
    print("RECV_CLOSE_1005: closed=", ws1.is_closed, " code=", ws1.close_code, "\n");
    // CHECK: RECV_CLOSE_1005: closed=true code=1002

    // Wire Close frame with code 5000 received -> MUST fail with 1002
    var ws2 = realtime::new_websocket_session(false);
    var reply2: u8[>..] = [];
    var msg2 = realtime::WsMessage { .. };
    var close_5000: u8[>..] = [];
    wire_kit::parse_hex("8882000000001388", close_5000); // 0x1388 = 5000
    let _ = realtime::receive(ws2, close_5000[..], msg2, reply2);
    print("RECV_CLOSE_5000: closed=", ws2.is_closed, " code=", ws2.close_code, "\n");
    // CHECK: RECV_CLOSE_5000: closed=true code=1002
}

// ---- Cookie Syntax and Prefixes (RFC 6265bis В§4.1.3 & RFC 6265 В§4.1.1) --

fn test_cookie_syntax_and_prefix_invariants() {
    print("--- 4. Cookie Syntax and Prefixes (RFC 6265bis / RFC 6265) ---\n");
    let now_us: i64 = 1700000000000000;

    // 4.1 __Secure- requires Secure attribute
    let _, _, ok_sec_no_sec = cookie::parse_canonical_set_cookie("__Secure-id=123", "example.com", "/", now_us);
    let _, _, ok_sec_with_sec = cookie::parse_canonical_set_cookie("__Secure-id=123; Secure", "example.com", "/", now_us);
    print("SECURE_PREFIX: no_sec=", ok_sec_no_sec, " with_sec=", ok_sec_with_sec, "\n");
    // CHECK: SECURE_PREFIX: no_sec=false with_sec=true

    // 4.2 __Host- requires Secure attribute
    let _, _, ok_host_no_sec = cookie::parse_canonical_set_cookie("__Host-id=123; Path=/", "example.com", "/", now_us);
    print("HOST_NO_SEC: ok=", ok_host_no_sec, "\n");
    // CHECK: HOST_NO_SEC: ok=false

    // 4.3 __Host- MUST NOT have Domain attribute
    let _, _, ok_host_dom = cookie::parse_canonical_set_cookie("__Host-id=123; Secure; Path=/; Domain=example.com", "example.com", "/", now_us);
    print("HOST_WITH_DOMAIN: ok=", ok_host_dom, "\n");
    // CHECK: HOST_WITH_DOMAIN: ok=false

    // 4.4 __Host- MUST have Path attribute equal to '/'
    // Must fail when Path attribute is missing entirely, EVEN IF default_path is "/"
    let _, _, ok_host_missing_path = cookie::parse_canonical_set_cookie("__Host-id=123; Secure", "example.com", "/", now_us);
    print("HOST_MISSING_PATH_ATTR: ok=", ok_host_missing_path, "\n");
    // CHECK: HOST_MISSING_PATH_ATTR: ok=false

    // Must fail when Path attribute is not '/'
    let _, _, ok_host_sub_path = cookie::parse_canonical_set_cookie("__Host-id=123; Secure; Path=/sub", "example.com", "/sub", now_us);
    print("HOST_NON_ROOT_PATH: ok=", ok_host_sub_path, "\n");
    // CHECK: HOST_NON_ROOT_PATH: ok=false

    // Must succeed when Secure, no Domain, and Path=/
    let _, _, ok_host_valid = cookie::parse_canonical_set_cookie("__Host-id=123; Secure; Path=/", "example.com", "/", now_us);
    print("HOST_VALID: ok=", ok_host_valid, "\n");
    // CHECK: HOST_VALID: ok=true

    // 4.5 Cookie Name Syntax Validation (RFC 6265 §4.1.1: cookie-name = token)
    let _, _, ok_name_space = cookie::parse_canonical_set_cookie("bad name=123", "example.com", "/", now_us);
    let _, _, ok_name_at = cookie::parse_canonical_set_cookie("bad@name=123", "example.com", "/", now_us);
    let _, _, ok_name_comma = cookie::parse_canonical_set_cookie("bad,name=123", "example.com", "/", now_us);
    let _, _, ok_name_bracket = cookie::parse_canonical_set_cookie("[bad]=123", "example.com", "/", now_us);
    let _, _, ok_name_slash = cookie::parse_canonical_set_cookie("bad/name=123", "example.com", "/", now_us);
    let _, _, ok_name_paren = cookie::parse_canonical_set_cookie("bad(name)=123", "example.com", "/", now_us);
    print("NAME_SYNTAX: sp=", ok_name_space, " at=", ok_name_at, " comma=", ok_name_comma, " brk=", ok_name_bracket, " slash=", ok_name_slash, " par=", ok_name_paren, "\n");
    // CHECK: NAME_SYNTAX: sp=false at=false comma=false brk=false slash=false par=false

    // 4.6 Cookie Value Syntax Validation (RFC 6265 §4.1.1: cookie-value = *cookie-octet / (DQUOTE *cookie-octet DQUOTE))
    let _, _, ok_val_space = cookie::parse_canonical_set_cookie("id=val ue", "example.com", "/", now_us);
    let _, _, ok_val_comma = cookie::parse_canonical_set_cookie("id=val,ue", "example.com", "/", now_us);
    let _, _, ok_val_backslash = cookie::parse_canonical_set_cookie("id=val\\ue", "example.com", "/", now_us);
    let _, _, ok_val_unclosed = cookie::parse_canonical_set_cookie("id=\"val", "example.com", "/", now_us);
    let _, _, ok_val_unmatched = cookie::parse_canonical_set_cookie("id=val\"", "example.com", "/", now_us);
    let _, _, ok_val_good = cookie::parse_canonical_set_cookie("id=valid_value", "example.com", "/", now_us);
    let _, _, ok_val_good_quoted = cookie::parse_canonical_set_cookie("id=\"valid_quoted_value\"", "example.com", "/", now_us);
    print("VAL_SYNTAX: sp=", ok_val_space, " comma=", ok_val_comma, " bslash=", ok_val_backslash, " unclosed=", ok_val_unclosed, " unmatched=", ok_val_unmatched, " good=", ok_val_good, " quoted=", ok_val_good_quoted, "\n");
    // CHECK: VAL_SYNTAX: sp=false comma=false bslash=false unclosed=false unmatched=false good=true quoted=true
}

// ---- 5. SSE Regression Invariants (W3C EventSource §9.2.6) ----------------

fn test_sse_regressions() {
    print("--- 5. SSE Regressions ---\n");

    // 5.1 sse_process_line MUST reset cur_data/cur_event/has_data even when out_events is at capacity
    var p_cap = realtime::SseParser { .. };
    var ev_1: realtime::SseEvent[..1] = [];
    realtime::sse_feed(p_cap, "event: ev1\ndata: first\n\nevent: ev2\ndata: second\n\n", ev_1);
    var ev_next: realtime::SseEvent[..2] = [];
    realtime::sse_feed(p_cap, "data: third\n\n", ev_next);
    print("SSE_CAP_RESET: len=", ev_next.len, " event=", ev_next[0].event[..], " data=", ev_next[0].data[..], "\n");
    // CHECK: SSE_CAP_RESET: len=1 event=message data=third

    // 5.2 sse_flush MUST discard incomplete events lacking trailing blank line per W3C EventSource §9.2.6
    var p_eof = realtime::SseParser { .. };
    var ev_eof: realtime::SseEvent[..4] = [];
    realtime::sse_feed(p_eof, "data: complete\n\ndata: incomplete_no_blank_line\n", ev_eof);
    p_eof.sse_flush();
    print("SSE_FLUSH_EOF: count=", ev_eof.len, " has_data=", p_eof.has_data, " bom_checked=", p_eof.bom_checked, "\n");
    // CHECK: SSE_FLUSH_EOF: count=1 has_data=false bom_checked=false

    // 5.3 sse_clean_token_len MUST stop at NUL byte (0x00) as well as CR/LF
    var id_with_nul: u8[..16]  = ['i', 'd', '1', 0, 'x', 'y'];
    var fmt_out:     u8[..128] = [];
    realtime::sse_format_event(fmt_out, "ev", "hello", id_with_nul[..], 0);
    var p_rt = realtime::SseParser { .. };
    var ev_rt: realtime::SseEvent[..2] = [];
    realtime::sse_feed(p_rt, fmt_out[..], ev_rt);
    print("SSE_NUL_ID_CLEAN: id=", ev_rt[0].id[..], "\n");
    // CHECK: SSE_NUL_ID_CLEAN: id=id1

    // 5.4 SseSubscription.url MUST support URLs > 256 bytes (up to 2048 bytes)
    var long_url: u8[..512] = [];
    long_url.append("https://api.example.com/events?");
    for _ in 300 { long_url.push('a'); }
    let sub_long = realtime::new_sse_subscription(long_url[..]);
    print("SSE_LONG_URL: len=", sub_long.url.len, " expected=", long_url.len, "\n");
    // CHECK: SSE_LONG_URL: len=331 expected=331

    // 5.5 sse_build_request_headers MUST strip CR/LF/NUL from host, path, and last_event_id
    var sub_inj = realtime::new_sse_subscription("https://example.com/sse");
    sub_inj.parser.last_event_id.append("42\r\nX-Injected: pwn");
    var hdr_buf: u8[..512] = [];
    realtime::sse_build_request_headers(sub_inj, "example.com\r\nX-Host: bad", "/sse\r\nX-Path: bad", hdr_buf);
    let has_injected = core::find(hdr_buf[..], "X-Injected") >= 0 ||
                       core::find(hdr_buf[..], "X-Host") >= 0 ||
                       core::find(hdr_buf[..], "X-Path") >= 0;
    print("SSE_HDR_INJECTION_BLOCKED: blocked=", !has_injected, "\n");
    // CHECK: SSE_HDR_INJECTION_BLOCKED: blocked=true
}

// ---- 6. TopicTree Regression Invariants -----------------------------------

fn test_topic_tree_regressions() {
    print("--- 6. TopicTree Regressions ---\n");

    // 6.1 match_topic MUST reject invalid mid-pattern '#' and wildcard publish topics
    let m_mid_hash = realtime::match_topic("sport/#/tennis", "sport/a/b");
    let m_wild_pub = realtime::match_topic("sport/+", "sport/+");
    print("TOPIC_MATCH_STRICT: mid_hash=", m_mid_hash, " wild_pub=", m_wild_pub, "\n");
    // CHECK: TOPIC_MATCH_STRICT: mid_hash=false wild_pub=false

    // 6.2 get_socket_topics MUST clear out_topics even when sock_fd <= 0
    var tree = realtime::TopicTree { .. };
    var stale_topics: u8[..64][..32] = [];
    var dummy_pat:    u8[..64]       = [];
    dummy_pat.append("stale/topic");
    stale_topics.push(dummy_pat);
    let cnt_bad = realtime::get_socket_topics(tree, -1, stale_topics);
    print("TOPIC_GET_CLEAR: ret=", cnt_bad, " len=", stale_topics.len, "\n");
    // CHECK: TOPIC_GET_CLEAR: ret=0 len=0

    // 6.3 subscribe_ex MUST reclaim newly created bucket when 4096 subscription nodes are full
    var full_tree = realtime::TopicTree { .. };
    for i in 4096 {
        full_tree.nodes[i].in_use = true;
    }
    let old_c, new_c, ok_sub_full = full_tree.subscribe_ex(10, "new/bucket/pattern");
    print("TOPIC_BUCKET_RECLAIM: ok=", ok_sub_full, " active_buckets=", full_tree.active_buckets, " old=", old_c, " new=", new_c, "\n");
    // CHECK: TOPIC_BUCKET_RECLAIM: ok=false active_buckets=0 old=0 new=0

    // 6.4 prepare_message_compressed MUST succeed with has_compressed=false when deflate expands near-16KB incompressible payload
    var prep_msg = realtime::PreparedMessage { .. };
    var shared_c = realtime::SharedWsCompressor { .. };
    var incomp: u8[..16368] = [];
    var rng_s:  u32         = 0x12345678;
    for _ in 16368 {
        rng_s = rng_s ^ (rng_s << 13);
        rng_s = rng_s ^ (rng_s >> 17);
        rng_s = rng_s ^ (rng_s << 5);
        incomp.push((rng_s & 0xFF) as u8);
    }
    let ok_prep = realtime::prepare_message_compressed(prep_msg, incomp[..], shared_c);
    print("TOPIC_PREP_INCOMP_16K: ok=", ok_prep, " has_comp=", prep_msg.has_compressed, " wire_gt_0=", prep_msg.wire.len > 0, "\n");
    // CHECK: TOPIC_PREP_INCOMP_16K: ok=true has_comp=false wire_gt_0=true

    // 6.5 publish_batch called 65 times with 0 subscribers MUST NOT panic with OOB at palette[64]
    var batch_tree = realtime::TopicTree { .. };
    for _ in 65 {
        let _ = realtime::publish_batch(batch_tree, "unsubscribed/topic", "hello");
    }
    print("TOPIC_BATCH_65_NO_SUBS: publishes=", batch_tree.total_publishes, " palette_len=", batch_tree.palette_len, "\n");
    // CHECK: TOPIC_BATCH_65_NO_SUBS: publishes=65 palette_len=0
}

// ---- 7. WebSocket Regression Invariants -----------------------------------

fn test_websocket_regressions() {
    print("--- 7. WebSocket Regressions ---\n");

    // 7.1 unmask_websocket_shifted MUST guard against signed i64 addition overflow
    var small_frame: u8[..16] = [1, 2, 3, 4, 5, 6, 7, 8];
    let mask_k: u8[4] = [0x11, 0x22, 0x33, 0x44];
    let unm = realtime::unmask_websocket_shifted(small_frame[..], 4, 0x7FFFFFFFFFFFFFFE, mask_k);
    print("WS_UNMASK_OVERFLOW_GUARD: len=", unm.len, "\n");
    // CHECK: WS_UNMASK_OVERFLOW_GUARD: len=0

    // 7.2 DedicatedWsCompressor cross-message sliding dictionary compression & decompression
    // Construct message 1 with a high-entropy 64-byte token, and message 2 repeating that token once.
    // Without cross-message dictionary, message 2 cannot compress the single occurrence of the 64-byte token!
    // With cross-message dictionary (deflate_with_dict), message 2 references message 1's history and compresses smaller!
    var ded_c = realtime::new_dedicated_ws_compressor(32);
    var ded_d = realtime::new_dedicated_ws_compressor(32);
    let dict_msg1 = "UNIQUE_PREFIX_TOKEN_9876543210_ZYXWVUTSRQPONMLKJIHGFEDCBA_0123456789_END";
    var w1: u8[..256] = [];
    var w2: u8[..256] = [];
    let _ = realtime::deflate_message_dedicated(ded_c, dict_msg1, w1, false);
    let _ = realtime::deflate_message_dedicated(ded_c, dict_msg1, w2, false);
    var p1: u8[..256] = [];
    var p2: u8[..256] = [];
    let ok_p1 = realtime::inflate_message_dedicated(ded_d, w1[..], p1, 65536, false);
    let ok_p2 = realtime::inflate_message_dedicated(ded_d, w2[..], p2, 65536, false);
    print("WS_DEDICATED_DICT: w2_smaller=", w2.len < w1.len, " ok_p1=", ok_p1, " ok_p2=", ok_p2, " match=", p2[..] == dict_msg1, "\n");
    // CHECK: WS_DEDICATED_DICT: w2_smaller=true ok_p1=true ok_p2=true match=true

    // 7.3 ws_inflate_message and inflate_message_dedicated MUST clear out_plain on OutputBufferOverflow
    var dirty_plain: u8[..512] = [];
    dirty_plain.append("stale_prefix");
    let ok_ovf = realtime::inflate_message_dedicated(ded_d, w1[..], dirty_plain, 10, false);
    print("WS_INFLATE_CLEAN_ON_OVF: ok=", ok_ovf, " plain_len=", dirty_plain.len, "\n");
    // CHECK: WS_INFLATE_CLEAN_ON_OVF: ok=false plain_len=0

    // 7.4 encode_ws_frame_compressed MUST clamp control frame payload to 125 bytes
    var big_ctrl_payload: u8[..200] = [];
    for _ in 150 { big_ctrl_payload.push('P'); }
    var ctrl_wire: u8[..256] = [];
    realtime::encode_ws_frame_compressed(ctrl_wire, rfc::WS_OPCODE_PING, big_ctrl_payload[..], false, mask_k, true);
    print("WS_COMP_CTRL_CLAMP: wire_len=", ctrl_wire.len, "\n");
    // CHECK: WS_COMP_CTRL_CLAMP: wire_len=127

    // 7.5 is_valid_websocket_key MUST reject non-zero padding bits in 22nd char ('B' has low 4 bits 0001 != 0)
    let bad_pad_key = realtime::is_valid_websocket_key("AAAAAAAAAAAAAAAAAAAAAAB==");
    let good_pad_key = realtime::is_valid_websocket_key("dGhlIHNhbXBsZSBub25jZQ==");
    print("WS_KEY_PADDING_BITS: bad=", bad_pad_key, " good=", good_pad_key, "\n");
    // CHECK: WS_KEY_PADDING_BITS: bad=false good=true

    // 7.6 validate_websocket_accept MUST reject oversized client_key with empty server_accept
    var long_key: u8[..128] = [];
    for _ in 100 { long_key.push('A'); }
    let bypass_accept = realtime::validate_websocket_accept(long_key[..], "");
    print("WS_ACCEPT_EMPTY_BYPASS: ok=", bypass_accept, "\n");
    // CHECK: WS_ACCEPT_EMPTY_BYPASS: ok=false

    // 7.7 ws_has_broken_compression MUST not wrap u32 on minor version overflow
    let ua_overflow = realtime::ws_has_broken_compression("Mozilla/5.0 Version/15.4294967296 Safari/605.1.15");
    let ua_affected = realtime::ws_has_broken_compression("Mozilla/5.0 Version/15.3 Safari/605.1.15");
    print("WS_SAFARI_OVERFLOW: ovf=", ua_overflow, " affected=", ua_affected, "\n");
    // CHECK: WS_SAFARI_OVERFLOW: ovf=false affected=true

    // 7.8 notify_buffered MUST guard against u64 addition overflow
    var ws_bp = realtime::new_websocket_session(false);
    ws_bp.buffered_amount = 100;
    var bp_close: u8[..128] = [];
    let bp_status = realtime::notify_buffered(ws_bp, 0xFFFFFFFFFFFFFFFF, bp_close);
    print("WS_BACKPRESSURE_U64_OVF: dropped=", bp_status == realtime::WsSendStatus.Dropped, "\n");
    // CHECK: WS_BACKPRESSURE_U64_OVF: dropped=true

    // 7.9 consume_frame_view_into on already-closed session with incomplete frame MUST return (0, false)
    var ws_closed = realtime::new_websocket_session(false);
    ws_closed.is_closed = true;
    var partial_wire: u8[..8] = [0x81, 0x85, 0x11, 0x22]; // incomplete masked frame (needs 6 hdr + 5 payload = 11 bytes)
    var c_view = realtime::WsMessageView { .. };
    var c_reply: u8[..64] = [];
    let consumed_closed, handled_closed = realtime::consume_frame_view(ws_closed, partial_wire[..], c_view, c_reply);
    print("WS_CLOSED_PARTIAL: consumed=", consumed_closed, " handled=", handled_closed, "\n");
    // CHECK: WS_CLOSED_PARTIAL: consumed=0 handled=false

    // 7.10 ws_upgrade_request MUST NOT leave 101 headers in out_resp when subprotocol > 64 bytes, and validate_h2_websocket_request MUST enforce http/https :scheme
    var upg_req = http::new_request("GET", "http://example.com/ws");
    upg_req.set_header("Host", "example.com");
    upg_req.set_header("Upgrade", "websocket");
    upg_req.set_header("Connection", "Upgrade");
    upg_req.set_header("Sec-WebSocket-Version", "13");
    upg_req.set_header("Sec-WebSocket-Key", "dGhlIHNhbXBsZSBub25jZQ==");
    var big_subproto: u8[..128] = [];
    for _ in 70 { big_subproto.push('p'); }
    var upg_resp = http::Response { .. };
    let _, ok_upg_big = realtime::ws_upgrade_request(upg_req, upg_resp, big_subproto[..]);
    let leaked_accept = http::header(upg_resp, "Sec-WebSocket-Accept").len > 0;

    var h2_req = http::Request { .. };
    realtime::format_h2_websocket_request(h2_req, "/ws", "example.com", "ftp");
    let ok_h2_ftp = realtime::validate_h2_websocket_request(h2_req);
    print("WS_UPGRADE_CLEAN: ok_big=", ok_upg_big, " leaked_accept=", leaked_accept, " h2_ftp=", ok_h2_ftp, "\n");
    // CHECK: WS_UPGRADE_CLEAN: ok_big=false leaked_accept=false h2_ftp=false
}

// ---- 8. WebTransport Regression Invariants --------------------------------

fn test_webtransport_regressions() {
    print("--- 8. WebTransport Regressions ---\n");

    // 8.1 read_varint MUST NOT mutate idx on truncated multi-byte varint
    var trunc_varint: u8[1] = [0x40]; // 2-byte prefix (01), missing 2nd byte
    var v_idx:        i64   = 0;
    let _, ok_vi = realtime::read_varint(trunc_varint[..], v_idx);
    print("WT_READ_VARINT_ATOMIC: ok=", ok_vi, " idx=", v_idx, "\n");
    // CHECK: WT_READ_VARINT_ATOMIC: ok=false idx=0

    // 8.2 decode_webtransport_datagram MUST reject quarter_id > 0x0FFFFFFFFFFFFFFF (u64 * 4 overflow)
    // 0xFF followed by 7 0xFF bytes encodes varint 0x3FFFFFFFFFFFFFFF
    let ovf_dgram_wire: u8[10] = [0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x00, 'A'];
    var dgram_out = realtime::WebTransportDatagram { .. };
    let ok_dgram_ovf = realtime::decode_webtransport_datagram(ovf_dgram_wire[..], dgram_out);
    print("WT_DGRAM_QID_OVF: ok=", ok_dgram_ovf, "\n");
    // CHECK: WT_DGRAM_QID_OVF: ok=false

    // 8.3 decode_webtransport_close_session MUST validate UTF-8 and not mutate out on >1024 reason
    var bad_utf8_close: u8[6] = [0x00, 0x00, 0x00, 0x01, 0xFF, 0xFE];
    var close_out = realtime::WebTransportCloseSession { error_code: 777, .. };
    let ok_bad_u8 = realtime::decode_webtransport_close_session(bad_utf8_close[..], close_out);
    print("WT_CLOSE_UTF8: ok=", ok_bad_u8, " preserved_code=", close_out.error_code, "\n");
    // CHECK: WT_CLOSE_UTF8: ok=false preserved_code=777

    // 8.4 WebTransportDemuxer MUST reuse closed stream slots across > 64 sequential streams
    var demuxer = realtime::WebTransportDemuxer { .. };
    let _ = realtime::register_webtransport_session(demuxer, 4);
    var all_routed = true;
    for s in 70 {
        let stream_id = (s as u64) * 4; // bidi stream IDs: 0, 4, 8, ...
        let open_pkt: u8[4] = [0x40, 0x41, 0x04, 'A'];
        var p_out = realtime::WebTransportStreamPayload { .. };
        // Open with fin=false, then close with fin=true
        let ok1 = realtime::demux_webtransport_stream(demuxer, stream_id, open_pkt[..], false, p_out);
        let ok2 = realtime::demux_webtransport_stream(demuxer, stream_id, "B", true, p_out);
        if !ok1 || !ok2 || p_out.payload != "B" {
            all_routed = false;
        }
    }
    print("WT_DEMUX_REUSE_70_STREAMS: all_routed=", all_routed, "\n");
    // CHECK: WT_DEMUX_REUSE_70_STREAMS: all_routed=true
}

// ---- 9. Cross-Component & RFC Edge-Case Regressions -----------------------

fn test_cross_component_and_rfc_edge_regressions() {
    print("--- 9. Cross-Component & RFC Edge-Case Regressions ---\n");

    // 9.1 (F001) RFC 7692 §7.2.3 BFINAL=0 sync-flush vectors & bounded buffer capacity
    var shared_c = realtime::SharedWsCompressor { .. };
    var ded_c = realtime::new_dedicated_ws_compressor(32);
    let rfc7692_hello: u8[7] = [0xf2, 0x48, 0xcd, 0xc9, 0xc9, 0x07, 0x00]; // §7.2.3.1
    let rfc7692_win:   u8[5] = [0xf2, 0x00, 0x11, 0x00, 0x00];             // §7.2.3.2
    let rfc7692_empty: u8[1] = [0x00];                                     // §7.2.3.6
    var plain1:  u8[..64] = [];
    var plain2:  u8[..64] = [];
    var plain_e: u8[..16] = [];
    let ok_s1 = realtime::ws_inflate_message(shared_c, rfc7692_hello[..], plain1);
    let ok_d1 = realtime::inflate_message_dedicated(ded_c, rfc7692_hello[..], plain1);
    let ok_d2 = realtime::inflate_message_dedicated(ded_c, rfc7692_win[..], plain2);
    let ok_se = realtime::ws_inflate_message(shared_c, rfc7692_empty[..], plain_e);
    var tiny_plain: u8[..3] = [];
    let ok_tiny = realtime::ws_inflate_message(shared_c, rfc7692_hello[..], tiny_plain, 65536);
    var tiny_wire: u8[..2] = [];
    let ok_tiny_def = realtime::deflate_message_dedicated(ded_c, "HelloHelloHello", tiny_wire);
    print(
        "F001_RFC7692_DEFLATE: s1=", ok_s1 && plain1[..] == "Hello",
        " d12=", ok_d1 && ok_d2 && plain2[..] == "Hello",
        " empty=", ok_se && plain_e.len == 0,
        " tiny_inf=", ok_tiny, " tiny_def=", ok_tiny_def, "\n",
    );
    // CHECK: F001_RFC7692_DEFLATE: s1=true d12=true empty=true tiny_inf=false tiny_def=false

    // 9.2 (F002) RFC 6455 §4.1 & §4.2.1 HTTP/1.0 rejection, duplicate key/version, subprotocol tchar
    var req_h10 = http::new_request("GET", "/ws");
    req_h10.is_http10 = true;
    http::set_header(req_h10, "Host", "example.com");
    http::set_header(req_h10, "Upgrade", "websocket");
    http::set_header(req_h10, "Connection", "Upgrade");
    http::set_header(req_h10, "Sec-WebSocket-Version", "13");
    http::set_header(req_h10, "Sec-WebSocket-Key", "dGhlIHNhbXBsZSBub25jZQ==");
    var resp_h10 = http::Response { .. };
    let _, ok_h10 = realtime::ws_upgrade_request(req_h10, resp_h10);

    var req_dup = http::new_request("GET", "/ws");
    http::set_header(req_dup, "Host", "example.com");
    http::set_header(req_dup, "Upgrade", "websocket");
    http::set_header(req_dup, "Connection", "Upgrade");
    http::set_header(req_dup, "Sec-WebSocket-Version", "13");
    http::set_header(req_dup, "Sec-WebSocket-Key", "dGhlIHNhbXBsZSBub25jZQ==");
    let _ = http::append_header(req_dup.headers, "Sec-WebSocket-Key", "AQIDBAUGBwgJCgsMDQ4PEA==");
    var resp_dup = http::Response { .. };
    let _, ok_dup = realtime::ws_upgrade_request(req_dup, resp_dup);
    let bad_sub = realtime::has_subprotocol_token("chat, bad proto", "bad proto");
    print("F002_WS_HANDSHAKE: h10=", ok_h10, " dup_key=", ok_dup, " bad_sub=", bad_sub, "\n");
    // CHECK: F002_WS_HANDSHAKE: h10=false dup_key=false bad_sub=false

    // 9.3 (F003) TopicTree batch FIFO order across overlapping wildcard buckets & unsubscribe migration
    var tt = realtime::TopicTree { .. };
    let _ = realtime::subscribe(tt, 55, "sport/tennis/+");
    let _ = realtime::subscribe(tt, 55, "sport/#");
    let _ = realtime::publish_batch(tt, "sport/tennis/p1", "first");
    let _ = realtime::publish_batch(tt, "sport/swim", "second");
    let head_idx = tt.drainable_head as i64;
    let fifo_ok = head_idx >= 0 &&
        tt.nodes[head_idx].num_message_indices == 2 &&
        tt.nodes[head_idx].message_indices[0] == 0 &&
        tt.nodes[head_idx].message_indices[1] == 1;
    let _ = realtime::unsubscribe(tt, 55, "sport/tennis/+");
    let retained_after_unsub = realtime::subscriber_queued_messages(tt, 55);
    print("F003_TOPIC_BATCH: fifo=", fifo_ok, " retained=", retained_after_unsub, "\n");
    // CHECK: F003_TOPIC_BATCH: fifo=true retained=2

    // 9.4 (F004) W3C EventSource §9.2.6 uncommitted id: discarded on sse_flush & prepare_request sanitize
    var sse_p = realtime::SseParser { .. };
    var sse_evs: realtime::SseEvent[..4] = [];
    realtime::sse_feed(sse_p, "id: committed-1\ndata: ok\n\nid: uncommitted-2\ndata: partial", sse_evs);
    sse_p.sse_flush();
    let id_preserved = sse_p.last_event_id[..] == "committed-1";

    // 9.5 (F005) WebTransport QUIC datagram bounded cap, session re-register clean & response reopen
    let dgram_big: u8[7] = [0x31, 0x05, 'A', 'B', 'C', 'D', 'E'];
    var small_dgram_out: u8[..3] = [];
    let ok_small_dg = realtime::decode_quic_datagram_frame(dgram_big[..], small_dgram_out);
    var wt_sess = realtime::WebTransportSession { is_active: false, is_draining: true, close_code: 99, .. };
    var wt_res = http::Response { .. };
    wt_res.status_code = 200;
    let _ = wt_sess.handle_webtransport_response(wt_res);
    let wt_reopened = realtime::is_webtransport_session_open(wt_sess) && wt_sess.close_code == 0;
    print("F004_F005_SSE_WT: id_ok=", id_preserved, " small_dg=", ok_small_dg, " wt_open=", wt_reopened, "\n");
    // CHECK: F004_F005_SSE_WT: id_ok=true small_dg=false wt_open=true
}

fn run_02_verify_realtime_spec_invariants() {
    test_ws_control_frame_invariants();
    test_ws_rsv_bit_invariants();
    test_ws_close_code_invariants();
    test_cookie_syntax_and_prefix_invariants();
    test_sse_regressions();
    test_topic_tree_regressions();
    test_websocket_regressions();
    test_webtransport_regressions();
    test_cross_component_and_rfc_edge_regressions();
    print("ALL REALTIME SPEC INVARIANTS VERIFIED\n");
}

// CHECK: ALL REALTIME SPEC INVARIANTS VERIFIED

// ============================================================================
// 3. verify_sse_wire (3/8)
// ============================================================================
// CHECK: === [3/8] verify_sse_wire ===

// tests/lit/verify_sse_wire.goose
// Verification of W3C EventSource Server-Sent Events (SSE) wire protocol:
// multi-line data concatenation, keepalive comments, retry delays,
// BOM stripping, and split-stream event dispatch.
//

// Wire bridge to SSE streaming parser for split stream and fuzz verification
fn decode_sse_frame_wire(buf: const u8[:]) -> i64 {
    var p = realtime::SseParser { .. };
    var events: realtime::SseEvent[..4] = [];
    realtime::sse_feed(p, buf, events);
    if events.len == 0 { return -1; }
    return events[0].data.len;
}

fn test_sse_event_formatting_and_feed() {
    var wire_out: u8[>..] = [];
    realtime::sse_format_event(wire_out, "update", "first line\nsecond line", "101", 5000);

    var p = realtime::SseParser { .. };
    var events: realtime::SseEvent[..4] = [];
    realtime::sse_feed(p, wire_out[..], events);

    assert(events.len == 1);
    assert(events[0].event == "update");
    assert(events[0].id == "101");
    assert(events[0].data == "first line\nsecond line");
    assert(p.retry_ms == 5000);
    print("SSE_FORMAT_AND_FEED: OK");
}

fn test_sse_split_stream_and_fuzz() {
    let wire_data = "event: msg\ndata: hello\n\n";
    assert(wire_kit::verify_split_stream(wire_data, -1, 5, decode_sse_frame_wire));
    assert(wire_kit::fuzz_payload(wire_data, 100, decode_sse_frame_wire));
    print("SSE_SPLIT_AND_FUZZ: OK");
}

fn test_sse_comments_and_bom() {
    // 1. Keep-alive comment line + retry directive
    let comment_wire = ": keepalive ping\nretry: 4500\n\n";
    var p = realtime::SseParser { .. };
    var events: realtime::SseEvent[..4] = [];
    realtime::sse_feed(p, comment_wire, events);
    assert(events.len == 0); // Comments do not generate events
    assert(p.retry_ms == 4500);

    // 2. UTF-8 BOM stripping (\xEF\xBB\xBF)
    var bom_wire: u8[>..] = [];
    bom_wire.push(0xEF);
    bom_wire.push(0xBB);
    bom_wire.push(0xBF);
    bom_wire.append("data: payload-with-bom\n\n");

    var p_bom = realtime::SseParser { .. };
    var bom_events: realtime::SseEvent[..4] = [];
    realtime::sse_feed(p_bom, bom_wire[..], bom_events);
    assert(bom_events.len == 1);
    assert(bom_events[0].data == "payload-with-bom");

    print("SSE_COMMENTS_AND_BOM: OK");
}

fn test_sse_4096_byte_payload() {
    var big_wire: u8[>..] = [];
    big_wire.append("data: ");
    for i in 4096 {
        big_wire.push('A');
    }
    big_wire.append("\n\n");

    var p = realtime::SseParser { .. };
    var events: realtime::SseEvent[..4] = [];
    realtime::sse_feed(p, big_wire[..], events);
    assert(events.len == 1);
    assert(events[0].data.len == 4096);
    print("SSE_4096_PAYLOAD: OK");
}

fn run_03_verify_sse_wire() {
    test_sse_event_formatting_and_feed();
    test_sse_split_stream_and_fuzz();
    test_sse_comments_and_bom();
    test_sse_4096_byte_payload();
    print("SSE_WIRE: ALL INVARIANTS PASS");
}

// CHECK: SSE_FORMAT_AND_FEED: OK
// CHECK: SSE_SPLIT_AND_FUZZ: OK
// CHECK: SSE_COMMENTS_AND_BOM: OK
// CHECK: SSE_4096_PAYLOAD: OK
// CHECK: SSE_WIRE: ALL INVARIANTS PASS

// ============================================================================
// 4. verify_ws_autobahn (4/8)
// ============================================================================
// CHECK: === [4/8] verify_ws_autobahn ===

// tests/lit/verify_ws_autobahn.goose
// Verification of RFC 6455 WebSocket framing, masking, and Autobahn testsuite invariants via wing.
//

// Wire validator for RFC 6455 framing rules using realtime::parse_ws_frame_header
fn wing_validate_ws_frame(buf: const u8[:], is_client_ingress: bool) -> i32 {
    let hdr, ok = realtime::parse_ws_frame_header(buf);
    guard ok else { return 1002; }
    if hdr.rsv1 || hdr.rsv2 || hdr.rsv3 { return 1002; }
    if is_client_ingress && !hdr.masked { return 1002; }
    return 0;
}

fn run_04_verify_ws_autobahn() {
    var vOk: u8[>..] = []; wire_kit::parse_hex("818511223344", vOk);
    assert(wing_validate_ws_frame(vOk[..], true) == 0);

    var vRsv1: u8[>..] = []; wire_kit::parse_hex("C18511223344", vRsv1);
    assert(wing_validate_ws_frame(vRsv1[..], true) == 1002);

    var vRsv2: u8[>..] = []; wire_kit::parse_hex("A18511223344", vRsv2);
    assert(wing_validate_ws_frame(vRsv2[..], true) == 1002);

    var vFragPing: u8[>..] = []; wire_kit::parse_hex("098011223344", vFragPing);
    assert(wing_validate_ws_frame(vFragPing[..], true) == 1002);

    var vBigPing: u8[>..] = []; wire_kit::parse_hex("89FE11223344", vBigPing);
    assert(wing_validate_ws_frame(vBigPing[..], true) == 1002);

    var vUnmasked: u8[>..] = []; wire_kit::parse_hex("810568656C6C6F", vUnmasked);
    assert(wing_validate_ws_frame(vUnmasked[..], true) == 1002);
    assert(wing_validate_ws_frame(vUnmasked[..], false) == 0);

    print("WS_AUTOBAHN_FRAMING: ALL OK");
}

// CHECK: WS_AUTOBAHN_FRAMING: ALL OK

// ============================================================================
// 5. verify_ws_autobahn_exhaustive (5/8)
// ============================================================================
// CHECK: === [5/8] verify_ws_autobahn_exhaustive ===

// RFC 6455 / Autobahn WebSocket Testsuite Exhaustive Verification
// Verifies protocol invariants across Categories 1-7 without Docker requirement.

fn test_autobahn_cat2_control_frames() {
    var ws = realtime::new_websocket_session(false);
    var reply: u8[>..] = [];
    var msg = realtime::WsMessage { .. };

    // Case 2.1: Ping with payload > 125 bytes MUST trigger protocol error (1002)
    var big_ping: u8[>..] = [];
    wire_kit::parse_hex("89FE007E11223344", big_ping); // 126 bytes declared
    for _ in 126 { big_ping.push(0xAA); }

    let _ = realtime::receive(ws, big_ping[..], msg, reply);
    print("CAT2_BIG_PING: closed=", ws.is_closed, " code=", ws.close_code, "\n");
    // CHECK: CAT2_BIG_PING: closed=true code=1002

    // Case 2.2: Fragmented Ping (FIN=0, opcode=9) MUST trigger protocol error (1002)
    var ws2 = realtime::new_websocket_session(false);
    var frag_ping: u8[>..] = [];
    wire_kit::parse_hex("09841122334468656C6C", frag_ping); // FIN=0, Opcode=9
    reply.clear();
    let _ = realtime::receive(ws2, frag_ping[..], msg, reply);
    print("CAT2_FRAG_PING: closed=", ws2.is_closed, " code=", ws2.close_code, "\n");
    // CHECK: CAT2_FRAG_PING: closed=true code=1002
}

fn test_autobahn_cat3_reserved_bits() {
    var ws = realtime::new_websocket_session(false);
    var reply: u8[>..] = [];
    var msg = realtime::WsMessage { .. };

    // Case 3.1: RSV1=1 without permessage-deflate MUST trigger 1002
    var rsv1_frame: u8[>..] = [];
    wire_kit::parse_hex("C1851122334468656C6C6F", rsv1_frame);
    let _ = realtime::receive(ws, rsv1_frame[..], msg, reply);
    print("CAT3_RSV1: closed=", ws.is_closed, " code=", ws.close_code, "\n");
    // CHECK: CAT3_RSV1: closed=true code=1002

    // Case 3.2: RSV2=1 MUST trigger 1002
    var ws2 = realtime::new_websocket_session(false);
    var rsv2_frame: u8[>..] = [];
    wire_kit::parse_hex("A1851122334468656C6C6F", rsv2_frame);
    let _ = realtime::receive(ws2, rsv2_frame[..], msg, reply);
    print("CAT3_RSV2: closed=", ws2.is_closed, " code=", ws2.close_code, "\n");
    // CHECK: CAT3_RSV2: closed=true code=1002
}

fn test_autobahn_cat4_opcodes() {
    var ws = realtime::new_websocket_session(false);
    var reply: u8[>..] = [];
    var msg = realtime::WsMessage { .. };

    // Case 4.1: Undefined data opcode 3 MUST trigger 1002
    var op3_frame: u8[>..] = [];
    wire_kit::parse_hex("83841122334468656C6C", op3_frame);
    let _ = realtime::receive(ws, op3_frame[..], msg, reply);
    print("CAT4_OP3: closed=", ws.is_closed, " code=", ws.close_code, "\n");
    // CHECK: CAT4_OP3: closed=true code=1002

    // Case 4.2: Undefined control opcode 11 MUST trigger 1002
    var ws2 = realtime::new_websocket_session(false);
    var op11_frame: u8[>..] = [];
    wire_kit::parse_hex("8B841122334468656C6C", op11_frame);
    let _ = realtime::receive(ws2, op11_frame[..], msg, reply);
    print("CAT4_OP11: closed=", ws2.is_closed, " code=", ws2.close_code, "\n");
    // CHECK: CAT4_OP11: closed=true code=1002
}

fn test_autobahn_cat5_fragmentation_fsm() {
    var ws = realtime::new_websocket_session(false);
    var reply: u8[>..] = [];
    var msg = realtime::WsMessage { .. };

    // Case 5.1: Continuation frame without starting fragment MUST trigger 1002
    var orphan_cont: u8[>..] = [];
    wire_kit::parse_hex("80841122334468656C6C", orphan_cont);
    let _ = realtime::receive(ws, orphan_cont[..], msg, reply);
    print("CAT5_ORPHAN_CONT: closed=", ws.is_closed, " code=", ws.close_code, "\n");
    // CHECK: CAT5_ORPHAN_CONT: closed=true code=1002

    // Case 5.2: Interleaved text frame during fragmented binary message MUST trigger 1002
    var ws2 = realtime::new_websocket_session(false);
    var frag_start: u8[>..] = [];
    wire_kit::parse_hex("028411223344AABBCCDD", frag_start); // Binary, FIN=0
    let _ = realtime::receive(ws2, frag_start[..], msg, reply);

    var interleaved_text: u8[>..] = [];
    wire_kit::parse_hex("81841122334468656C6C", interleaved_text); // Text, FIN=1
    let _ = realtime::receive(ws2, interleaved_text[..], msg, reply);
    print("CAT5_INTERLEAVED: closed=", ws2.is_closed, " code=", ws2.close_code, "\n");
    // CHECK: CAT5_INTERLEAVED: closed=true code=1002
}

fn test_autobahn_cat6_utf8_validation() {
    var ws = realtime::new_websocket_session(false);
    var reply: u8[>..] = [];
    var msg = realtime::WsMessage { .. };

    // Case 6.1: Text frame containing invalid UTF-8 byte 0xFF MUST trigger 1007
    var bad_utf8: u8[>..] = [];
    // Mask key = 00000000, payload = FF 65 6C 6C
    wire_kit::parse_hex("818400000000FF656C6C", bad_utf8);
    let _ = realtime::receive(ws, bad_utf8[..], msg, reply);
    print("CAT6_BAD_UTF8: closed=", ws.is_closed, " code=", ws.close_code, "\n");
    // CHECK: CAT6_BAD_UTF8: closed=true code=1007
}

fn test_autobahn_cat7_close_handling() {
    var ws = realtime::new_websocket_session(false);
    var reply: u8[>..] = [];
    var msg = realtime::WsMessage { .. };

    // Case 7.1: Close frame with 1-byte payload MUST trigger protocol error (1002)
    var close_1byte: u8[>..] = [];
    wire_kit::parse_hex("888100000000AA", close_1byte); // payload len = 1
    let _ = realtime::receive(ws, close_1byte[..], msg, reply);
    print("CAT7_1BYTE_CLOSE: closed=", ws.is_closed, " code=", ws.close_code, "\n");
    // CHECK: CAT7_1BYTE_CLOSE: closed=true code=1002

    // Case 7.2: Close frame with forbidden wire code 1005 MUST trigger protocol error (1002)
    var ws2 = realtime::new_websocket_session(false);
    var close_1005: u8[>..] = [];
    wire_kit::parse_hex("88820000000003ED", close_1005); // 0x03ED = 1005
    let _ = realtime::receive(ws2, close_1005[..], msg, reply);
    print("CAT7_CODE_1005: closed=", ws2.is_closed, " code=", ws2.close_code, "\n");
    // CHECK: CAT7_CODE_1005: closed=true code=1002

    // Case 7.3: Close frame with valid code 1000 (Normal) MUST succeed and echo close
    var ws3 = realtime::new_websocket_session(false);
    var close_1000: u8[>..] = [];
    wire_kit::parse_hex("88820000000003E8", close_1000); // 0x03E8 = 1000
    let _ = realtime::receive(ws3, close_1000[..], msg, reply);
    print("CAT7_CODE_1000: closed=", ws3.is_closed, " code=", ws3.close_code, "\n");
    // CHECK: CAT7_CODE_1000: closed=true code=1000
}

fn run_05_verify_ws_autobahn_exhaustive() {
    print("=== LIT Autobahn WebSocket Exhaustive Verification ===\n");
    test_autobahn_cat2_control_frames();
    test_autobahn_cat3_reserved_bits();
    test_autobahn_cat4_opcodes();
    test_autobahn_cat5_fragmentation_fsm();
    test_autobahn_cat6_utf8_validation();
    test_autobahn_cat7_close_handling();
}

// ============================================================================
// 6. verify_ws_h2_rfc8441 (6/8)
// ============================================================================
// CHECK: === [6/8] verify_ws_h2_rfc8441 ===

// tests/lit/verify_ws_h2_rfc8441.goose
// Verification of RFC 8441 Bootstrapping WebSockets with HTTP/2:
// Extended CONNECT request validation, 200 OK upgrade handshake,
// and encapsulated RFC 6455 frame parsing with split-stream verification and fuzzing.
//

// Wire bridge to validate RFC 6455 frame encapsulated in H2 DATA stream
fn decode_h2_ws_payload(buf: const u8[:]) -> i64 {
    if buf.len < 2 { return -1; }
    let opcode = buf[0] & 0x0F;
    if !rfc::is_valid_ws_opcode(opcode) { return -2; }
    let masked = (buf[1] & 0x80) != 0;
    let raw_len = buf[1] & 0x7F;
    var min_hdr: i64 = 2;
    if raw_len == 126 { min_hdr += 2; }
    else if raw_len == 127 { min_hdr += 8; }
    if masked { min_hdr += 4; }
    if buf.len < min_hdr { return -1; }

    let hdr, ok = realtime::parse_ws_frame_header(buf);
    if !ok { return -2; }
    let total: i64 = hdr.header_len + (hdr.payload_len as! i64);
    if buf.len < total { return -1; }
    return hdr.payload_len as! i64;
}

fn test_rfc8441_handshake() {
    var req = http::new_request("GET", "/");
    realtime::format_h2_websocket_request(req, "/chat", "example.com", "https", "chat.v1");

    assert(realtime::is_h2_websocket_request(req));
    assert(realtime::validate_h2_websocket_request(req));

    var resp = http::Response { .. };
    let session, ok = realtime::ws_h2_upgrade_request(req, resp, "chat.v1");
    assert(ok);
    assert(resp.status_code == 200);
    assert(realtime::is_h2_websocket_response(resp));
    assert(session.subprotocol[..] == "chat.v1");

    // Forbidden headers check: Upgrade or Connection MUST NOT be present
    var bad_req = req;
    http::set_header(bad_req, "Upgrade", "websocket");
    assert(!realtime::validate_h2_websocket_request(bad_req));

    print("H2_WS_HANDSHAKE: OK");
}

fn test_rfc8441_stream_payload() {
    var ws_pkt: u8[>..] = [];
    // RFC 6455 masked text frame: "hello" (payload len 5)
    // 81 (FIN=1, Text=1) 85 (Masked=1, Len=5) 01020304 (Mask) 68656C6C6F (Masked "hello")
    assert(wire_kit::parse_hex("81850102030468656C6C6F", ws_pkt));

    let hdr, ok = realtime::parse_ws_frame_header(ws_pkt[..]);
    assert(ok);
    assert(hdr.payload_len == 5);
    assert(hdr.masked);

    assert(wire_kit::verify_split_stream(ws_pkt[..], -1, 5, decode_h2_ws_payload));
    assert(wire_kit::fuzz_payload(ws_pkt[..], 100, decode_h2_ws_payload));

    print("H2_WS_STREAM_PAYLOAD: OK");
}

fn run_06_verify_ws_h2_rfc8441() {
    test_rfc8441_handshake();
    test_rfc8441_stream_payload();
    print("RFC8441_H2_WEBSOCKET: ALL INVARIANTS PASS");
}

// CHECK: H2_WS_HANDSHAKE: OK
// CHECK: H2_WS_STREAM_PAYLOAD: OK
// CHECK: RFC8441_H2_WEBSOCKET: ALL INVARIANTS PASS

// ============================================================================
// 7. verify_ws_masking_simd (7/8)
// ============================================================================
// CHECK: === [7/8] verify_ws_masking_simd ===

// tests/lit/verify_ws_masking_simd.goose
// Verification of WebSocket Payload XOR Masking (RFC 6455 §5.3) & Invariants (§5.1).
// Tests SWAR 64-bit vectorization, scalar unaligned offsets (1..63 bytes),
// roundtrip mask/unmask symmetry, and client/server mask validation.
//

fn verify_single_size_mask(sz: i64, mask: const u8[4]&) {
    var buf: u8[>..] = [];
    for i in sz {
        let val: u8 = ((i * 7 + 13) & 0xFF) as u8;
        buf.push(val);
    }

    var original: u8[>..] = [];
    for b in buf { original.push(b); }

    // Mask in place
    realtime::mask_websocket_payload(buf[..], mask);

    // Unmask with identical key
    realtime::mask_websocket_payload(buf[..], mask);

    for i in sz {
        assert(buf[i] == original[i]);
    }
}

fn test_masking_roundtrip_across_sizes() {
    let mask: u8[4] = [0x37, 0xFA, 0x21, 0x3D];
    // Sample across scalar tails, SWAR, and SIMD boundary
    let sizes: i64[10] = [1, 3, 7, 8, 15, 31, 32, 63, 64, 129];
    for s in sizes {
        verify_single_size_mask(s, mask);
    }
    print("WS_MASK_ROUNDTRIP_ALL_SIZES: OK");
}

fn verify_single_swar_equivalence(sz: i64, mask: const u8[4]&) {
    var buf_swar:   u8[>..] = [];
    var buf_scalar: u8[>..] = [];

    for i in sz {
        let val: u8 = ((i * 31 + 4) & 0xFF) as u8;
        buf_swar.push(val);
        buf_scalar.push(val);
    }

    realtime::apply_mask_in_place(buf_swar[..], mask);

    for i in sz {
        let m = mask[i % 4];
        buf_scalar[i] = buf_scalar[i] ^ m;
    }

    for i in sz {
        assert(buf_swar[i] == buf_scalar[i]);
    }
}

fn test_swar_vs_scalar_equivalence() {
    let mask:       u8[4]  = [0xA5, 0x5A, 0xF0, 0x0F];
    let test_sizes: i64[6] = [1, 7, 8, 15, 33, 63];
    for s in test_sizes {
        verify_single_swar_equivalence(s, mask);
    }
    print("WS_SWAR_EQUIVALENCE: OK");
}

fn test_masking_enforcement_invariants() {
    let client_recv_masked = realtime::is_ws_masking_valid(realtime::WsRole.Client, true);
    assert(!client_recv_masked);
    print("CLIENT_RECV_MASKED_INVALID: OK");

    let client_recv_unmasked = realtime::is_ws_masking_valid(realtime::WsRole.Client, false);
    assert(client_recv_unmasked);
    print("CLIENT_RECV_UNMASKED_VALID: OK");

    let server_recv_unmasked = realtime::is_ws_masking_valid(realtime::WsRole.Server, false);
    assert(!server_recv_unmasked);
    print("SERVER_RECV_UNMASKED_INVALID: OK");

    let server_recv_masked = realtime::is_ws_masking_valid(realtime::WsRole.Server, true);
    assert(server_recv_masked);
    print("SERVER_RECV_MASKED_VALID: OK");
}

fn parse_ws_frame_step(buf: const u8[:]) -> i64 {
    guard buf.len >= 2 else { return -1; }
    let hdr, ok = realtime::parse_ws_frame_header(buf);
    guard ok else { return -1; }
    let hlen: i64 = hdr.header_len;
    let plen: i64 = hdr.payload_len as i64;
    guard buf.len - hlen >= plen else { return -1; }
    return hdr.opcode;
}

fn test_ws_split_stream() {
    var frame_out: u8[>..] = [];
    let payload = "Antigravity";
    let mask: u8[4] = [0x12, 0x34, 0x56, 0x78];
    realtime::encode_ws_frame(frame_out, rfc::WS_OPCODE_TEXT, payload, true, mask, true);

    let ok = wire_kit::verify_split_stream(frame_out[..], -1, rfc::WS_OPCODE_TEXT, parse_ws_frame_step);
    assert(ok);
    assert(wire_kit::fuzz_payload(frame_out[..], 100, parse_ws_frame_step));
    print("WS_SPLIT_STREAM_VERIFIED: OK");
}

fn run_07_verify_ws_masking_simd() {
    print("=== RUNNING WS MASKING AND INVARIANTS SUITE ===");
    test_masking_roundtrip_across_sizes();
    test_swar_vs_scalar_equivalence();
    test_masking_enforcement_invariants();
    test_ws_split_stream();
    print("WS MASKING COMPLETE: ALL INVARIANTS PASSED");
}

// CHECK: === RUNNING WS MASKING AND INVARIANTS SUITE ===
// CHECK: WS_MASK_ROUNDTRIP_ALL_SIZES: OK
// CHECK: WS_SWAR_EQUIVALENCE: OK
// CHECK: CLIENT_RECV_MASKED_INVALID: OK
// CHECK: CLIENT_RECV_UNMASKED_VALID: OK
// CHECK: SERVER_RECV_UNMASKED_INVALID: OK
// CHECK: SERVER_RECV_MASKED_VALID: OK
// CHECK: WS_SPLIT_STREAM_VERIFIED: OK
// CHECK: WS MASKING COMPLETE: ALL INVARIANTS PASSED

// ============================================================================
// 8. verify_ws_streaming_utf8 (8/8)
// ============================================================================
// CHECK: === [8/8] verify_ws_streaming_utf8 ===

// tests/lit/verify_ws_streaming_utf8.goose
// Verification of RFC 6455 close status codes and streaming UTF-8 validation via wing and core.
//

// Wire validator for RFC 6455 close status codes using wing::is_valid_ws_close_code
fn wing_validate_ws_close_wire(buf: const u8[:]) -> i64 {
    guard buf.len > 0 else { return 1005; }
    guard buf.len >= 2 else { return -1; }
    let code = core::read_be_u16(buf, 0);
    guard rfc::is_valid_ws_close_code(code) else { return -2; }
    return code;
}

// Wire validator for streaming UTF-8 using core::validate_utf8_streaming
fn wing_validate_utf8_wire(buf: const u8[:]) -> i32 {
    let valid, ok = core::validate_utf8_streaming(buf, true);
    if ok && valid == buf.len {
        return 1;
    }
    if !ok {
        return -2;
    }
    return -1;
}

fn run_08_verify_ws_streaming_utf8() {
    var raw_1000: u8[>..] = []; wire_kit::parse_hex("03E8", raw_1000);
    assert(wire_kit::verify_split_stream(raw_1000[..], -1, 1000, wing_validate_ws_close_wire));
    assert(wire_kit::fuzz_payload(raw_1000[..], 100, wing_validate_ws_close_wire));
    print("WS_CLOSE_SPLIT: OK");

    var c1005: u8[>..] = []; wire_kit::parse_hex("03ED", c1005);
    assert(wing_validate_ws_close_wire(c1005[..]) == -2);

    var c1006: u8[>..] = []; wire_kit::parse_hex("03EE", c1006);
    assert(wing_validate_ws_close_wire(c1006[..]) == -2);

    var c1004: u8[>..] = []; wire_kit::parse_hex("03EC", c1004);
    assert(wing_validate_ws_close_wire(c1004[..]) == -2);

    var c2000: u8[>..] = []; wire_kit::parse_hex("07D0", c2000);
    assert(wing_validate_ws_close_wire(c2000[..]) == -2);

    var c5000: u8[>..] = []; wire_kit::parse_hex("1388", c5000);
    assert(wing_validate_ws_close_wire(c5000[..]) == -2);

    var c1002: u8[>..] = []; wire_kit::parse_hex("03EA", c1002);
    assert(wing_validate_ws_close_wire(c1002[..]) == 1002);
    print("WS_CLOSE_CODES: OK");

    assert(wing_validate_utf8_wire("hello") == 1);

    var uOverlong: u8[>..] = []; wire_kit::parse_hex("C080", uOverlong);
    assert(wing_validate_utf8_wire(uOverlong[..]) == -2);

    var uSurr: u8[>..] = []; wire_kit::parse_hex("EDA080", uSurr);
    assert(wing_validate_utf8_wire(uSurr[..]) == -2);
    print("WS_UTF8_WIRE: OK");
}

// CHECK: WS_CLOSE_SPLIT: OK
// CHECK: WS_CLOSE_CODES: OK
// CHECK: WS_UTF8_WIRE: OK

fn main() {
    print("\n=== [1/8] verify_realtime_regressions ===\n");
    run_01_verify_realtime_regressions();
    print("\n=== [2/8] verify_realtime_spec_invariants ===\n");
    run_02_verify_realtime_spec_invariants();
    print("\n=== [3/8] verify_sse_wire ===\n");
    run_03_verify_sse_wire();
    print("\n=== [4/8] verify_ws_autobahn ===\n");
    run_04_verify_ws_autobahn();
    print("\n=== [5/8] verify_ws_autobahn_exhaustive ===\n");
    run_05_verify_ws_autobahn_exhaustive();
    print("\n=== [6/8] verify_ws_h2_rfc8441 ===\n");
    run_06_verify_ws_h2_rfc8441();
    print("\n=== [7/8] verify_ws_masking_simd ===\n");
    run_07_verify_ws_masking_simd();
    print("\n=== [8/8] verify_ws_streaming_utf8 ===\n");
    run_08_verify_ws_streaming_utf8();
}
