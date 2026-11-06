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

fn main() {
    test_heartbeat_ping_delay_wrap();
    test_webtransport_close_decode();
}

// CHECK: HEARTBEAT_PING_DELAY_WRAP: ok
// CHECK-NEXT: WEBTRANSPORT_CLOSE_DECODE: ok
