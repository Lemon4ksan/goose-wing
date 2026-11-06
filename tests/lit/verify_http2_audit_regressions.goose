// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// tests/lit/verify_http2_audit_regressions.goose
// Regression verification for HTTP/2 audit findings:
// 1. RFC 9218 §7.1: PRIORITY_UPDATE zero-length Priority Field Value resets to default.
// 2. RFC 8441 §3: SETTINGS_ENABLE_CONNECT_PROTOCOL received by server is PROTOCOL_ERROR.
// 3. RFC 9113 §5.1: HEADERS on closed stream with recycled slot returns STREAM_CLOSED.
// 4. RFC 9113 §6.8: GOAWAY with invalid stream parity returns PROTOCOL_ERROR.
//
// RUN: goose build --cc gcc -O2 -o %t.exe %s
// RUN: %t.exe | %FileCheck %s

import std;
import core from "../..";
import wing from "../..";

fn test_priority_update_empty_field() {
    // 4-byte payload: prioritized_stream_id = 3, empty field value
    let payload4: u8[4] = [0x00, 0x00, 0x00, 0x03];
    let stream_id, prio, err = internal::parse_priority_update_payload(payload4[..], false);
    assert(stream_id == 3);
    assert(err == rfc::H2_ERR_NO_ERROR);
    assert(prio.urgency == 3);
    assert(!prio.incremental);
    print("TEST_PRIO_EMPTY: OK\n");
}

fn test_settings_enable_connect_proto_server() {
    // Server receives SETTINGS_ENABLE_CONNECT_PROTOCOL from client: MUST reject with PROTOCOL_ERROR
    let err_srv = internal::validate_settings_parameter(rfc::H2_SETTING_ENABLE_CONNECT_PROTO, 1, false);
    assert(err_srv == rfc::H2_ERR_PROTOCOL_ERROR);

    // Client receives SETTINGS_ENABLE_CONNECT_PROTOCOL=1 from server: valid
    let err_cli = internal::validate_settings_parameter(rfc::H2_SETTING_ENABLE_CONNECT_PROTO, 1, true);
    assert(err_cli == rfc::H2_ERR_NO_ERROR);
    print("TEST_SETTINGS_CONNECT: OK\n");
}

fn test_headers_closed_stream_recycled_slot() {
    var conn = internal::new_h2_connection(0);
    // 1. Open stream 1 with END_STREAM so it transitions to HalfClosedRemote
    let hdr1 = internal::FrameHeader {
        length:     10,
        frame_type: rfc::H2_FRAME_HEADERS,
        flags:      rfc::H2_FLAG_END_HEADERS | rfc::H2_FLAG_END_STREAM,
        stream_id:  1,
    };
    let r1 = internal::handle_h2_headers_frame_header(conn, hdr1, 0);
    assert(r1 == rfc::H2_ERR_NO_ERROR);

    // Close local half so stream 1 is fully Closed and inactive
    internal::close_local_stream(conn, 1);

    // 2. Open stream 3 (which reuses slot 0 previously used by stream 1)
    let hdr3 = internal::FrameHeader {
        length:     10,
        frame_type: rfc::H2_FRAME_HEADERS,
        flags:      rfc::H2_FLAG_END_HEADERS | rfc::H2_FLAG_END_STREAM,
        stream_id:  3,
    };
    let r3 = internal::handle_h2_headers_frame_header(conn, hdr3, 0);
    assert(r3 == rfc::H2_ERR_NO_ERROR);

    // 3. Client sends another HEADERS frame on stream 1.
    // Must return STREAM_CLOSED, NOT PROTOCOL_ERROR!
    let hdr1_late = internal::FrameHeader {
        length:     10,
        frame_type: rfc::H2_FRAME_HEADERS,
        flags:      rfc::H2_FLAG_END_HEADERS,
        stream_id:  1,
    };
    let r_late = internal::handle_h2_headers_frame_header(conn, hdr1_late, 0);
    assert(r_late == rfc::H2_ERR_STREAM_CLOSED);
    print("TEST_RECYCLED_SLOT_CLOSED: OK\n");
}

fn test_goaway_invalid_parity() {
    var srv_conn = internal::new_h2_connection(0);
    srv_conn.is_server = true;
    // Client sending GOAWAY with odd stream ID 1 (acknowledging client's own stream) is invalid
    let err_ga = internal::apply_goaway(srv_conn, 1, rfc::H2_ERR_NO_ERROR);
    assert(err_ga == rfc::H2_ERR_PROTOCOL_ERROR);
    print("TEST_GOAWAY_PARITY: OK\n");
}

fn main() {
    test_priority_update_empty_field();
    test_settings_enable_connect_proto_server();
    test_headers_closed_stream_recycled_slot();
    test_goaway_invalid_parity();
    print("ALL_HTTP2_REGRESSIONS: OK\n");
}

// CHECK: TEST_PRIO_EMPTY: OK
// CHECK: TEST_SETTINGS_CONNECT: OK
// CHECK: TEST_RECYCLED_SLOT_CLOSED: OK
// CHECK: TEST_GOAWAY_PARITY: OK
// CHECK: ALL_HTTP2_REGRESSIONS: OK
