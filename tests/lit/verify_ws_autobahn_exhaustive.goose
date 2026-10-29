// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// RUN: goose build --cc gcc -O2 -o %t.exe %s
// RUN: %t.exe | %FileCheck %s

// RFC 6455 / Autobahn WebSocket Testsuite Exhaustive Verification
// Verifies protocol invariants across Categories 1-7 without Docker requirement.
import std;
import core from "../..";
import wing from "../..";
import wire_kit from ".";

fn test_autobahn_cat2_control_frames() {
    var ws = wing::new_websocket_session(false);
    var reply: u8[>..] = [];
    var msg = wing::WsMessage { .. };

    // Case 2.1: Ping with payload > 125 bytes MUST trigger protocol error (1002)
    var big_ping: u8[>..] = [];
    wire_kit::parse_hex("89FE007E11223344", big_ping); // 126 bytes declared
    for _ in 126 { big_ping.push(0xAA); }

    let _ = wing::receive(ws, big_ping[..], msg, reply);
    print("CAT2_BIG_PING: closed=", ws.is_closed, " code=", ws.close_code, "\n");
    // CHECK: CAT2_BIG_PING: closed=true code=1002

    // Case 2.2: Fragmented Ping (FIN=0, opcode=9) MUST trigger protocol error (1002)
    var ws2 = wing::new_websocket_session(false);
    var frag_ping: u8[>..] = [];
    wire_kit::parse_hex("09841122334468656C6C", frag_ping); // FIN=0, Opcode=9
    reply.clear();
    let _ = wing::receive(ws2, frag_ping[..], msg, reply);
    print("CAT2_FRAG_PING: closed=", ws2.is_closed, " code=", ws2.close_code, "\n");
    // CHECK: CAT2_FRAG_PING: closed=true code=1002
}

fn test_autobahn_cat3_reserved_bits() {
    var ws = wing::new_websocket_session(false);
    var reply: u8[>..] = [];
    var msg = wing::WsMessage { .. };

    // Case 3.1: RSV1=1 without permessage-deflate MUST trigger 1002
    var rsv1_frame: u8[>..] = [];
    wire_kit::parse_hex("C1851122334468656C6C6F", rsv1_frame);
    let _ = wing::receive(ws, rsv1_frame[..], msg, reply);
    print("CAT3_RSV1: closed=", ws.is_closed, " code=", ws.close_code, "\n");
    // CHECK: CAT3_RSV1: closed=true code=1002

    // Case 3.2: RSV2=1 MUST trigger 1002
    var ws2 = wing::new_websocket_session(false);
    var rsv2_frame: u8[>..] = [];
    wire_kit::parse_hex("A1851122334468656C6C6F", rsv2_frame);
    let _ = wing::receive(ws2, rsv2_frame[..], msg, reply);
    print("CAT3_RSV2: closed=", ws2.is_closed, " code=", ws2.close_code, "\n");
    // CHECK: CAT3_RSV2: closed=true code=1002
}

fn test_autobahn_cat4_opcodes() {
    var ws = wing::new_websocket_session(false);
    var reply: u8[>..] = [];
    var msg = wing::WsMessage { .. };

    // Case 4.1: Undefined data opcode 3 MUST trigger 1002
    var op3_frame: u8[>..] = [];
    wire_kit::parse_hex("83841122334468656C6C", op3_frame);
    let _ = wing::receive(ws, op3_frame[..], msg, reply);
    print("CAT4_OP3: closed=", ws.is_closed, " code=", ws.close_code, "\n");
    // CHECK: CAT4_OP3: closed=true code=1002

    // Case 4.2: Undefined control opcode 11 MUST trigger 1002
    var ws2 = wing::new_websocket_session(false);
    var op11_frame: u8[>..] = [];
    wire_kit::parse_hex("8B841122334468656C6C", op11_frame);
    let _ = wing::receive(ws2, op11_frame[..], msg, reply);
    print("CAT4_OP11: closed=", ws2.is_closed, " code=", ws2.close_code, "\n");
    // CHECK: CAT4_OP11: closed=true code=1002
}

fn test_autobahn_cat5_fragmentation_fsm() {
    var ws = wing::new_websocket_session(false);
    var reply: u8[>..] = [];
    var msg = wing::WsMessage { .. };

    // Case 5.1: Continuation frame without starting fragment MUST trigger 1002
    var orphan_cont: u8[>..] = [];
    wire_kit::parse_hex("80841122334468656C6C", orphan_cont);
    let _ = wing::receive(ws, orphan_cont[..], msg, reply);
    print("CAT5_ORPHAN_CONT: closed=", ws.is_closed, " code=", ws.close_code, "\n");
    // CHECK: CAT5_ORPHAN_CONT: closed=true code=1002

    // Case 5.2: Interleaved text frame during fragmented binary message MUST trigger 1002
    var ws2 = wing::new_websocket_session(false);
    var frag_start: u8[>..] = [];
    wire_kit::parse_hex("028411223344AABBCCDD", frag_start); // Binary, FIN=0
    let _ = wing::receive(ws2, frag_start[..], msg, reply);

    var interleaved_text: u8[>..] = [];
    wire_kit::parse_hex("81841122334468656C6C", interleaved_text); // Text, FIN=1
    let _ = wing::receive(ws2, interleaved_text[..], msg, reply);
    print("CAT5_INTERLEAVED: closed=", ws2.is_closed, " code=", ws2.close_code, "\n");
    // CHECK: CAT5_INTERLEAVED: closed=true code=1002
}

fn test_autobahn_cat6_utf8_validation() {
    var ws = wing::new_websocket_session(false);
    var reply: u8[>..] = [];
    var msg = wing::WsMessage { .. };

    // Case 6.1: Text frame containing invalid UTF-8 byte 0xFF MUST trigger 1007
    var bad_utf8: u8[>..] = [];
    // Mask key = 00000000, payload = FF 65 6C 6C
    wire_kit::parse_hex("818400000000FF656C6C", bad_utf8);
    let _ = wing::receive(ws, bad_utf8[..], msg, reply);
    print("CAT6_BAD_UTF8: closed=", ws.is_closed, " code=", ws.close_code, "\n");
    // CHECK: CAT6_BAD_UTF8: closed=true code=1007
}

fn test_autobahn_cat7_close_handling() {
    var ws = wing::new_websocket_session(false);
    var reply: u8[>..] = [];
    var msg = wing::WsMessage { .. };

    // Case 7.1: Close frame with 1-byte payload MUST trigger protocol error (1002)
    var close_1byte: u8[>..] = [];
    wire_kit::parse_hex("888100000000AA", close_1byte); // payload len = 1
    let _ = wing::receive(ws, close_1byte[..], msg, reply);
    print("CAT7_1BYTE_CLOSE: closed=", ws.is_closed, " code=", ws.close_code, "\n");
    // CHECK: CAT7_1BYTE_CLOSE: closed=true code=1002

    // Case 7.2: Close frame with forbidden wire code 1005 MUST trigger protocol error (1002)
    var ws2 = wing::new_websocket_session(false);
    var close_1005: u8[>..] = [];
    wire_kit::parse_hex("88820000000003ED", close_1005); // 0x03ED = 1005
    let _ = wing::receive(ws2, close_1005[..], msg, reply);
    print("CAT7_CODE_1005: closed=", ws2.is_closed, " code=", ws2.close_code, "\n");
    // CHECK: CAT7_CODE_1005: closed=true code=1002

    // Case 7.3: Close frame with valid code 1000 (Normal) MUST succeed and echo close
    var ws3 = wing::new_websocket_session(false);
    var close_1000: u8[>..] = [];
    wire_kit::parse_hex("88820000000003E8", close_1000); // 0x03E8 = 1000
    let _ = wing::receive(ws3, close_1000[..], msg, reply);
    print("CAT7_CODE_1000: closed=", ws3.is_closed, " code=", ws3.close_code, "\n");
    // CHECK: CAT7_CODE_1000: closed=true code=1000
}

fn main() {
    print("=== LIT Autobahn WebSocket Exhaustive Verification ===\n");
    test_autobahn_cat2_control_frames();
    test_autobahn_cat3_reserved_bits();
    test_autobahn_cat4_opcodes();
    test_autobahn_cat5_fragmentation_fsm();
    test_autobahn_cat6_utf8_validation();
    test_autobahn_cat7_close_handling();
}
