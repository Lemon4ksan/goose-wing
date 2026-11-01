// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// tests/lit/verify_realtime_spec_invariants.goose
// Rigorous protocol specification verification for:
// 1. WebSocket Control Frames (RFC 6455 В§5.5) - length <= 125, non-fragmented (FIN=1)
// 2. WebSocket RSV Bits (RFC 6455 В§5.2, RFC 7692 В§5.1) - zero unless negotiated
// 3. WebSocket Close Codes (RFC 6455 В§7.4.1, В§7.4.2) - invalid/reserved code rejection
// 4. Cookie Syntax & Prefixes (RFC 6265bis В§4.1.3, RFC 6265 В§4.1.1) - __Secure-, __Host-, token & cookie-octet
//
// RUN: goose build --cc gcc -O2 -o %t.exe %s
// RUN: %t.exe | %FileCheck %s

import std;
import core from "../..";
import wing from "../..";
import wire_kit from ".";

// ---- WebSocket Control Frames (RFC 6455 В§5.5) ---------------------------

fn test_ws_control_frame_invariants() {
    print("--- 1. WS Control Frames (RFC 6455 Section 5.5) ---\n");

    // Case 1.1: Ping with payload > 125 bytes MUST fail with PROTOCOL_ERROR (1002)
    var ws1 = wing::new_websocket_session(false);
    var reply1: u8[>..] = [];
    var msg1 = wing::WsMessage { .. };
    var big_ping: u8[>..] = [];
    // 0x89 = FIN=1, opcode=9 (Ping); 0xFE = Masked=1, len=126; extended length 0x007E (126 bytes)
    wire_kit::parse_hex("89FE007E11223344", big_ping);
    for _ in 126 { big_ping.push(0xAA); }
    let _ = wing::receive(ws1, big_ping[..], msg1, reply1);
    print("PING_OVERSIZE_126: closed=", ws1.is_closed, " code=", ws1.close_code, "\n");
    // CHECK: PING_OVERSIZE_126: closed=true code=1002

    // Case 1.2: Fragmented Ping (FIN=0) MUST fail with PROTOCOL_ERROR (1002)
    var ws2 = wing::new_websocket_session(false);
    var reply2: u8[>..] = [];
    var msg2 = wing::WsMessage { .. };
    var frag_ping: u8[>..] = [];
    // 0x09 = FIN=0, opcode=9 (Ping); 0x84 = Masked=1, len=4
    wire_kit::parse_hex("09841122334468656C6C", frag_ping);
    let _ = wing::receive(ws2, frag_ping[..], msg2, reply2);
    print("PING_FRAGMENTED: closed=", ws2.is_closed, " code=", ws2.close_code, "\n");
    // CHECK: PING_FRAGMENTED: closed=true code=1002

    // Case 1.3: Fragmented Close (FIN=0) MUST fail with PROTOCOL_ERROR (1002)
    var ws3 = wing::new_websocket_session(false);
    var reply3: u8[>..] = [];
    var msg3 = wing::WsMessage { .. };
    var frag_close: u8[>..] = [];
    // 0x08 = FIN=0, opcode=8 (Close); 0x82 = Masked=1, len=2; payload code 1000 (0x03E8)
    wire_kit::parse_hex("08821122334412CA", frag_close);
    let _ = wing::receive(ws3, frag_close[..], msg3, reply3);
    print("CLOSE_FRAGMENTED: closed=", ws3.is_closed, " code=", ws3.close_code, "\n");
    // CHECK: CLOSE_FRAGMENTED: closed=true code=1002

    // Case 1.4: Standalone parse_close_payload with payload > 125 bytes MUST fail
    var over_close_payload: u8[>..] = [];
    over_close_payload.push(0x03);
    over_close_payload.push(0xE8); // code 1000
    for _ in 124 { over_close_payload.push('x'); } // total 126 bytes
    let _, _, ok_over = wing::parse_close_payload(over_close_payload[..]);
    print("PARSE_CLOSE_OVER_125: ok=", ok_over, "\n");
    // CHECK: PARSE_CLOSE_OVER_125: ok=false
}

// ---- WebSocket RSV Bits (RFC 6455 В§5.2) ---------------------------------

fn test_ws_rsv_bit_invariants() {
    print("--- 2. WS RSV Bits (RFC 6455 Section 5.2) ---\n");

    // Case 2.1: RSV1=1 without negotiated extension MUST fail with PROTOCOL_ERROR (1002)
    var ws1 = wing::new_websocket_session(false);
    var reply1: u8[>..] = [];
    var msg1 = wing::WsMessage { .. };
    var rsv1_frame: u8[>..] = [];
    // 0xC1 = FIN=1, RSV1=1, opcode=1 (Text); Masked=1, len=5
    wire_kit::parse_hex("C1851122334468656C6C6F", rsv1_frame);
    let _ = wing::receive(ws1, rsv1_frame[..], msg1, reply1);
    print("RSV1_NO_EXT: closed=", ws1.is_closed, " code=", ws1.close_code, "\n");
    // CHECK: RSV1_NO_EXT: closed=true code=1002

    // Case 2.2: RSV2=1 MUST fail with PROTOCOL_ERROR (1002)
    var ws2 = wing::new_websocket_session(false);
    var reply2: u8[>..] = [];
    var msg2 = wing::WsMessage { .. };
    var rsv2_frame: u8[>..] = [];
    // 0xA1 = FIN=1, RSV2=1, opcode=1 (Text); Masked=1, len=5
    wire_kit::parse_hex("A1851122334468656C6C6F", rsv2_frame);
    let _ = wing::receive(ws2, rsv2_frame[..], msg2, reply2);
    print("RSV2_NONZERO: closed=", ws2.is_closed, " code=", ws2.close_code, "\n");
    // CHECK: RSV2_NONZERO: closed=true code=1002

    // Case 2.3: RSV3=1 MUST fail with PROTOCOL_ERROR (1002)
    var ws3 = wing::new_websocket_session(false);
    var reply3: u8[>..] = [];
    var msg3 = wing::WsMessage { .. };
    var rsv3_frame: u8[>..] = [];
    // 0x91 = FIN=1, RSV3=1, opcode=1 (Text); Masked=1, len=5
    wire_kit::parse_hex("91851122334468656C6C6F", rsv3_frame);
    let _ = wing::receive(ws3, rsv3_frame[..], msg3, reply3);
    print("RSV3_NONZERO: closed=", ws3.is_closed, " code=", ws3.close_code, "\n");
    // CHECK: RSV3_NONZERO: closed=true code=1002

    // Case 2.4: RSV1=1 on control frame (Ping) MUST fail even if compression enabled
    var ws4 = wing::new_websocket_session(false);
    wing::enable_permessage_deflate(ws4);
    var reply4: u8[>..] = [];
    var msg4 = wing::WsMessage { .. };
    var rsv1_ping: u8[>..] = [];
    // 0xC9 = FIN=1, RSV1=1, opcode=9 (Ping); Masked=1, len=4
    wire_kit::parse_hex("C9841122334468656C6C", rsv1_ping);
    let _ = wing::receive(ws4, rsv1_ping[..], msg4, reply4);
    print("RSV1_ON_PING: closed=", ws4.is_closed, " code=", ws4.close_code, "\n");
    // CHECK: RSV1_ON_PING: closed=true code=1002
}

// ---- WebSocket Close Code Validation (RFC 6455 В§7.4) --------------------

fn test_ws_close_code_invariants() {
    print("--- 3. WS Close Codes (RFC 6455 Section 7.4) ---\n");

    // Permitted codes
    print("CODE_1000_OK: ", wing::is_valid_ws_close_code(1000), "\n");
    print("CODE_3000_OK: ", wing::is_valid_ws_close_code(3000), "\n");
    print("CODE_4999_OK: ", wing::is_valid_ws_close_code(4999), "\n");
    // CHECK: CODE_1000_OK: true
    // CHECK: CODE_3000_OK: true
    // CHECK: CODE_4999_OK: true

    // Forbidden codes on the wire
    print("CODE_0_FORBIDDEN: ", !wing::is_valid_ws_close_code(0), "\n");
    print("CODE_999_FORBIDDEN: ", !wing::is_valid_ws_close_code(999), "\n");
    print("CODE_1004_FORBIDDEN: ", !wing::is_valid_ws_close_code(1004), "\n");
    print("CODE_1005_FORBIDDEN: ", !wing::is_valid_ws_close_code(1005), "\n");
    print("CODE_1006_FORBIDDEN: ", !wing::is_valid_ws_close_code(1006), "\n");
    print("CODE_1015_FORBIDDEN: ", !wing::is_valid_ws_close_code(1015), "\n");
    print("CODE_1016_FORBIDDEN: ", !wing::is_valid_ws_close_code(1016), "\n");
    print("CODE_2999_FORBIDDEN: ", !wing::is_valid_ws_close_code(2999), "\n");
    print("CODE_5000_FORBIDDEN: ", !wing::is_valid_ws_close_code(5000), "\n");
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
    var ws1 = wing::new_websocket_session(false);
    var reply1: u8[>..] = [];
    var msg1 = wing::WsMessage { .. };
    var close_1005: u8[>..] = [];
    wire_kit::parse_hex("88820000000003ED", close_1005); // 0x03ED = 1005
    let _ = wing::receive(ws1, close_1005[..], msg1, reply1);
    print("RECV_CLOSE_1005: closed=", ws1.is_closed, " code=", ws1.close_code, "\n");
    // CHECK: RECV_CLOSE_1005: closed=true code=1002

    // Wire Close frame with code 5000 received -> MUST fail with 1002
    var ws2 = wing::new_websocket_session(false);
    var reply2: u8[>..] = [];
    var msg2 = wing::WsMessage { .. };
    var close_5000: u8[>..] = [];
    wire_kit::parse_hex("8882000000001388", close_5000); // 0x1388 = 5000
    let _ = wing::receive(ws2, close_5000[..], msg2, reply2);
    print("RECV_CLOSE_5000: closed=", ws2.is_closed, " code=", ws2.close_code, "\n");
    // CHECK: RECV_CLOSE_5000: closed=true code=1002
}

// ---- Cookie Syntax and Prefixes (RFC 6265bis В§4.1.3 & RFC 6265 В§4.1.1) --

fn test_cookie_syntax_and_prefix_invariants() {
    print("--- 4. Cookie Syntax and Prefixes (RFC 6265bis / RFC 6265) ---\n");
    let now_us: i64 = 1700000000000000;

    // 4.1 __Secure- requires Secure attribute
    let _, _, ok_sec_no_sec = wing::parse_canonical_set_cookie("__Secure-id=123", "example.com", "/", now_us);
    let _, _, ok_sec_with_sec = wing::parse_canonical_set_cookie("__Secure-id=123; Secure", "example.com", "/", now_us);
    print("SECURE_PREFIX: no_sec=", ok_sec_no_sec, " with_sec=", ok_sec_with_sec, "\n");
    // CHECK: SECURE_PREFIX: no_sec=false with_sec=true

    // 4.2 __Host- requires Secure attribute
    let _, _, ok_host_no_sec = wing::parse_canonical_set_cookie("__Host-id=123; Path=/", "example.com", "/", now_us);
    print("HOST_NO_SEC: ok=", ok_host_no_sec, "\n");
    // CHECK: HOST_NO_SEC: ok=false

    // 4.3 __Host- MUST NOT have Domain attribute
    let _, _, ok_host_dom = wing::parse_canonical_set_cookie("__Host-id=123; Secure; Path=/; Domain=example.com", "example.com", "/", now_us);
    print("HOST_WITH_DOMAIN: ok=", ok_host_dom, "\n");
    // CHECK: HOST_WITH_DOMAIN: ok=false

    // 4.4 __Host- MUST have Path attribute equal to '/'
    // Must fail when Path attribute is missing entirely, EVEN IF default_path is "/"
    let _, _, ok_host_missing_path = wing::parse_canonical_set_cookie("__Host-id=123; Secure", "example.com", "/", now_us);
    print("HOST_MISSING_PATH_ATTR: ok=", ok_host_missing_path, "\n");
    // CHECK: HOST_MISSING_PATH_ATTR: ok=false

    // Must fail when Path attribute is not '/'
    let _, _, ok_host_sub_path = wing::parse_canonical_set_cookie("__Host-id=123; Secure; Path=/sub", "example.com", "/sub", now_us);
    print("HOST_NON_ROOT_PATH: ok=", ok_host_sub_path, "\n");
    // CHECK: HOST_NON_ROOT_PATH: ok=false

    // Must succeed when Secure, no Domain, and Path=/
    let _, _, ok_host_valid = wing::parse_canonical_set_cookie("__Host-id=123; Secure; Path=/", "example.com", "/", now_us);
    print("HOST_VALID: ok=", ok_host_valid, "\n");
    // CHECK: HOST_VALID: ok=true

    // 4.5 Cookie Name Syntax Validation (RFC 6265 В§4.1.1: cookie-name = token)
    let _, _, ok_name_space = wing::parse_canonical_set_cookie("bad name=123", "example.com", "/", now_us);
    let _, _, ok_name_at = wing::parse_canonical_set_cookie("bad@name=123", "example.com", "/", now_us);
    let _, _, ok_name_comma = wing::parse_canonical_set_cookie("bad,name=123", "example.com", "/", now_us);
    let _, _, ok_name_bracket = wing::parse_canonical_set_cookie("[bad]=123", "example.com", "/", now_us);
    let _, _, ok_name_slash = wing::parse_canonical_set_cookie("bad/name=123", "example.com", "/", now_us);
    let _, _, ok_name_paren = wing::parse_canonical_set_cookie("bad(name)=123", "example.com", "/", now_us);
    print("NAME_SYNTAX: sp=", ok_name_space, " at=", ok_name_at, " comma=", ok_name_comma, " brk=", ok_name_bracket, " slash=", ok_name_slash, " par=", ok_name_paren, "\n");
    // CHECK: NAME_SYNTAX: sp=false at=false comma=false brk=false slash=false par=false

    // 4.6 Cookie Value Syntax Validation (RFC 6265 В§4.1.1: cookie-value = *cookie-octet / (DQUOTE *cookie-octet DQUOTE))
    let _, _, ok_val_space = wing::parse_canonical_set_cookie("id=val ue", "example.com", "/", now_us);
    let _, _, ok_val_comma = wing::parse_canonical_set_cookie("id=val,ue", "example.com", "/", now_us);
    let _, _, ok_val_backslash = wing::parse_canonical_set_cookie("id=val\\ue", "example.com", "/", now_us);
    let _, _, ok_val_unclosed = wing::parse_canonical_set_cookie("id=\"val", "example.com", "/", now_us);
    let _, _, ok_val_unmatched = wing::parse_canonical_set_cookie("id=val\"", "example.com", "/", now_us);
    let _, _, ok_val_good = wing::parse_canonical_set_cookie("id=valid_value", "example.com", "/", now_us);
    let _, _, ok_val_good_quoted = wing::parse_canonical_set_cookie("id=\"valid_quoted_value\"", "example.com", "/", now_us);
    print("VAL_SYNTAX: sp=", ok_val_space, " comma=", ok_val_comma, " bslash=", ok_val_backslash, " unclosed=", ok_val_unclosed, " unmatched=", ok_val_unmatched, " good=", ok_val_good, " quoted=", ok_val_good_quoted, "\n");
    // CHECK: VAL_SYNTAX: sp=false comma=false bslash=false unclosed=false unmatched=false good=true quoted=true
}

fn main() {
    test_ws_control_frame_invariants();
    test_ws_rsv_bit_invariants();
    test_ws_close_code_invariants();
    test_cookie_syntax_and_prefix_invariants();
    print("ALL REALTIME SPEC INVARIANTS VERIFIED\n");
}

// CHECK: ALL REALTIME SPEC INVARIANTS VERIFIED
