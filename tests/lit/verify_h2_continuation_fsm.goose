// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// tests/lit/verify_h2_continuation_fsm.goose
// Verification of HTTP/2 CONTINUATION flood defenses, interleaving bans, and window arithmetic.
//
// RUN: goose build --cc gcc -O2 -o %t.exe %s
// RUN: %t.exe | %FileCheck %s

import std;
import core from "../..";
import wing from "../..";
import wire_kit from ".";

fn parse_h2_hdr_step(buf: const u8[:]) -> i64 {
    guard buf.len >= 9 else { return -1; }
    let hdr, err = internal::parse_frame_header(buf);
    guard err == internal::ERR_NO_ERROR else { return err as! i64; }
    let val_err = internal::validate_frame_header_rules(hdr);
    guard val_err == internal::ERR_NO_ERROR else { return val_err as! i64; }
    guard buf.len >= 9 + (hdr.length as i64) else { return -1; }
    return hdr.stream_id as! i64;
}

fn main() {
    print("=== H2_CONTINUATION_AND_FSM_VERIFICATION ===");

    // 1. Initial HEADERS frame without END_HEADERS (flags = 0x00)
    var conn = internal::new_h2_connection(0);
    let h_hdr = internal::FrameHeader {
        length: 120,
        frame_type: internal::FRAME_HEADERS,
        flags: 0, // No END_HEADERS
        stream_id: 1,
    };
    let err_h = internal::on_ingress_frame_header(conn, h_hdr, 0);
    assert(err_h == internal::ERR_NO_ERROR);
    assert(conn.continuation_stream_id == 1);
    print("STATE: IngressHeaders -> ExpectContinuation(stream=1)");

    // 2. Interleaved PING frame on stream 0 during continuation sequence -> PROTOCOL_ERROR
    let ping_hdr = internal::FrameHeader {
        length: 8,
        frame_type: internal::FRAME_PING,
        flags: 0,
        stream_id: 0,
    };
    let err_ping = internal::on_ingress_frame_header(conn, ping_hdr, 0);
    assert(err_ping == internal::ERR_PROTOCOL_ERROR);
    print("INTERLEAVED_PING_BAN: PROTOCOL_ERROR");

    // 3. Interleaved DATA frame during continuation sequence -> PROTOCOL_ERROR
    let data_hdr = internal::FrameHeader {
        length: 50,
        frame_type: internal::FRAME_DATA,
        flags: 0,
        stream_id: 1,
    };
    let err_data = internal::on_ingress_frame_header(conn, data_hdr, 0);
    assert(err_data == internal::ERR_PROTOCOL_ERROR);
    print("INTERLEAVED_DATA_BAN: PROTOCOL_ERROR");

    // 4. CONTINUATION frame on wrong stream ID (stream 3 instead of 1) -> PROTOCOL_ERROR
    let cont_bad_sid = internal::FrameHeader {
        length: 64,
        frame_type: internal::FRAME_CONTINUATION,
        flags: internal::FLAG_END_HEADERS,
        stream_id: 3,
    };
    let err_cont_bad = internal::on_ingress_frame_header(conn, cont_bad_sid, 0);
    assert(err_cont_bad == internal::ERR_PROTOCOL_ERROR);
    print("MISMATCHED_STREAM_CONTINUATION: PROTOCOL_ERROR");

    // 5. Valid CONTINUATION frame on stream 1 with END_HEADERS
    let cont_ok = internal::FrameHeader {
        length: 64,
        frame_type: internal::FRAME_CONTINUATION,
        flags: internal::FLAG_END_HEADERS,
        stream_id: 1,
    };
    let err_cont_ok = internal::on_ingress_frame_header(conn, cont_ok, 0);
    assert(err_cont_ok == internal::ERR_NO_ERROR);
    assert(conn.continuation_stream_id == 0);
    print("STATE: ContinuationEnd -> Normal");

    // 6. Flow control: WINDOW_UPDATE increment 0 is illegal
    let err_zero_win = internal::apply_window_update(conn, 0, 0);
    assert(err_zero_win == internal::ERR_PROTOCOL_ERROR);
    print("ZERO_WINDOW_UPDATE: PROTOCOL_ERROR");

    // 7. Flow control: Window overflow beyond 2^31 - 1
    let err_ovf_win = internal::apply_window_update(conn, 0, 0x7FFFFFFF);
    assert(err_ovf_win == internal::ERR_FLOW_CONTROL_ERROR);
    print("WINDOW_OVERFLOW: FLOW_CONTROL_ERROR");

    // 8. Wire framing split stream & mutation fuzzing
    var raw_cont_wire: u8[>..] = [];
    assert(wire_kit::parse_hex("00000409040000000101020304", raw_cont_wire));
    assert(wire_kit::verify_split_stream(raw_cont_wire[..], -1, 1, parse_h2_hdr_step));
    assert(wire_kit::fuzz_payload(raw_cont_wire[..], 200, parse_h2_hdr_step));
    print("WIRE_CONTINUATION_FUZZ: PASS");
}

// CHECK-LABEL: === H2_CONTINUATION_AND_FSM_VERIFICATION ===
// CHECK-NEXT: STATE: IngressHeaders -> ExpectContinuation(stream=1)
// CHECK-NEXT: INTERLEAVED_PING_BAN: PROTOCOL_ERROR
// CHECK-NEXT: INTERLEAVED_DATA_BAN: PROTOCOL_ERROR
// CHECK-NEXT: MISMATCHED_STREAM_CONTINUATION: PROTOCOL_ERROR
// CHECK-NEXT: STATE: ContinuationEnd -> Normal
// CHECK-NEXT: ZERO_WINDOW_UPDATE: PROTOCOL_ERROR
// CHECK-NEXT: WINDOW_OVERFLOW: FLOW_CONTROL_ERROR
// CHECK-NEXT: WIRE_CONTINUATION_FUZZ: PASS
