// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// tests/lit/verify_role_polarity.goose
// Verifies RFC Role-Polarity and Protocol State Transition Matrix across QUIC, HTTP/3, and HTTP/2.
// Strict compliance with RFC 9000, RFC 9114, RFC 9218, and RFC 9113.
//
// RUN: goose build --cc gcc -O2 -o %t.exe %s
// RUN: %t.exe | %FileCheck %s

import std;
import core from "../..";
import wing from "../..";

// 1. QUIC Role Polarity (RFC 9000 Section 19.20)
// Server MUST NOT receive HANDSHAKE_DONE frame -> PROTOCOL_VIOLATION.
// Client MUST accept HANDSHAKE_DONE frame -> Transitions to Established.
fn test_quic_role_polarity() {
    let scid: u8[4] = [0x10, 0x11, 0x12, 0x13];

    // Case A: Server receives HANDSHAKE_DONE
    var server_conn = internal::new_quic_server_connection(scid[..]);
    var dgram_serv: u8[..64] = [];
    dgram_serv.push(0x40); // 1-RTT Short Header
    dgram_serv.append(scid[..]);
    dgram_serv.push(0x01); // Packet number = 1
    assert(internal::encode_handshake_done_frame(dgram_serv));

    var ack_out = internal::AckFrame { .. };
    let handled_s, _ = internal::quic_conn_process_datagram(server_conn, dgram_serv[..], 1000, ack_out);
    assert(!handled_s);
    assert(server_conn.state == internal::QuicConnState.Closing);
    assert(server_conn.close_code == rfc::QUIC_ERR_PROTOCOL_VIOLATION);

    // Case B: Client receives HANDSHAKE_DONE
    var client_conn = internal::new_quic_client_connection(scid[..], scid[..]);
    var dgram_cli: u8[..64] = [];
    dgram_cli.push(0x40); // 1-RTT Short Header
    dgram_cli.append(scid[..]);
    dgram_cli.push(0x01); // Packet number = 1
    assert(internal::encode_handshake_done_frame(dgram_cli));

    let handled_c, _ = internal::quic_conn_process_datagram(client_conn, dgram_cli[..], 1000, ack_out);
    assert(handled_c);
    assert(client_conn.state == internal::QuicConnState.Established);

    print("QUIC_ROLE_POLARITY: OK");
}

// 2. HTTP/3 Role Polarity (RFC 9114 Section 7.2.7 & RFC 9218 Section 7)
// Client MUST NOT receive MAX_PUSH_ID or PRIORITY_UPDATE -> H3_FRAME_UNEXPECTED.
// Server MUST NOT receive PUSH_PROMISE -> H3_FRAME_UNEXPECTED.

// Case A: Client receives PRIORITY_UPDATE_REQUEST on Control Stream (RFC 9218 §7)
fn test_h3_role_polarity_case_a(settings: wing::H3Settings) {
    var client_conn = internal::new_h3_client_connection(settings);
    // First, establish control stream with valid SETTINGS frame
    var ctrl_init: u8[..64] = [];
    internal::quic_encode_varint(ctrl_init, rfc::H3_STREAM_CONTROL);
    internal::encode_h3_settings_frame(ctrl_init, settings);
    let err_init = client_conn.handle_stream_data(3, false, ctrl_init[..], false);
    assert(err_init == rfc::H3_ERR_NO_ERROR);

    // Then client receives forbidden PRIORITY_UPDATE_REQUEST
    var prio_frame: u8[..64] = [];
    let prio = wing::PriorityParam { urgency: 1, incremental: false };
    assert(internal::encode_h3_priority_update_request(prio_frame, 0, prio));

    let err_prio = client_conn.handle_stream_data(3, false, prio_frame[..], false);
    assert(err_prio == rfc::H3_ERR_FRAME_UNEXPECTED);
    assert(client_conn.state == internal::H3ConnState.Closed);
}

// Case B: Client receives MAX_PUSH_ID on Control Stream (RFC 9114 §7.2.7)
fn test_h3_role_polarity_case_b(settings: wing::H3Settings) {
    var client_conn2 = internal::new_h3_client_connection(settings);
    // First, establish control stream with valid SETTINGS frame
    var ctrl_init2: u8[..64] = [];
    internal::quic_encode_varint(ctrl_init2, rfc::H3_STREAM_CONTROL);
    internal::encode_h3_settings_frame(ctrl_init2, settings);
    let err_init2 = client_conn2.handle_stream_data(3, false, ctrl_init2[..], false);
    assert(err_init2 == rfc::H3_ERR_NO_ERROR);

    // Then client receives forbidden MAX_PUSH_ID
    var max_push_frame: u8[..32] = [];
    assert(internal::encode_h3_max_push_id(max_push_frame, 10));

    let err_push = client_conn2.handle_stream_data(3, false, max_push_frame[..], false);
    assert(err_push == rfc::H3_ERR_FRAME_UNEXPECTED);
    assert(client_conn2.state == internal::H3ConnState.Closed);
}

// Case C: Server receives PUSH_PROMISE on Request Stream (RFC 9114 §7.2.5)
fn test_h3_role_polarity_case_c(settings: wing::H3Settings) {
    var server_conn = internal::new_h3_server_connection(settings);
    var push_promise_frame: u8[..32] = [];
    assert(internal::encode_h3_frame_header(push_promise_frame, rfc::H3_FRAME_PUSH_PROMISE, 3));
    internal::quic_encode_varint(push_promise_frame, 1); // Push ID = 1 (1 byte)
    push_promise_frame.push(0x00); // QPACK header block (2 bytes)
    push_promise_frame.push(0x00);

    let err_pp = server_conn.handle_stream_data(0, true, push_promise_frame[..], false);
    assert(err_pp == rfc::H3_ERR_FRAME_UNEXPECTED);
    assert(server_conn.state == internal::H3ConnState.Closed);
}

fn test_h3_role_polarity() {
    let settings = wing::H3Settings {
        qpack_max_table_capacity: 4096,
        max_field_section_size:   65536,
        qpack_blocked_streams:    16,
        enable_connect_protocol:  1,
    };

    test_h3_role_polarity_case_a(settings);
    test_h3_role_polarity_case_b(settings);
    test_h3_role_polarity_case_c(settings);

    print("H3_ROLE_POLARITY: OK");
}

// 3. HTTP/2 State Transition & Role Rules (RFC 9113)
fn test_h2_state_matrix() {
    // Case A: Stream 0 DATA Frame (RFC 9113 Section 5.1.1 & 6.1)
    let data_hdr = internal::FrameHeader {
        length:     5,
        frame_type: rfc::H2_FRAME_DATA,
        flags:      0,
        stream_id:  0, // Forbidden!
    };
    let err_data = internal::validate_frame_header_rules(data_hdr, 16384);
    assert(err_data == rfc::H2_ERR_PROTOCOL_ERROR);

    // Case B: SETTINGS with ACK and length != 0 (RFC 9113 Section 6.5)
    let set_ack_hdr = internal::FrameHeader {
        length:     6, // Forbidden: ACK must be 0 length
        frame_type: rfc::H2_FRAME_SETTINGS,
        flags:      rfc::H2_FLAG_ACK,
        stream_id:  0,
    };
    let err_set = internal::validate_frame_header_rules(set_ack_hdr, 16384);
    assert(err_set == rfc::H2_ERR_FRAME_SIZE_ERROR);

    // Case C: Server receives PUSH_PROMISE (RFC 9113 Section 6.6)
    var sess = internal::new_h2_server_session("localhost");
    var pipeline = wing::ServerPipelineConfig { .. };
    var timer = internal::ConnectionTimer { .. };
    var handshake_wire: u8[..64] = [];
    handshake_wire.append(rfc::H2_CLIENT_PREFACE[..]);
    let set_hdr = internal::FrameHeader { length: 0, frame_type: rfc::H2_FRAME_SETTINGS, flags: 0, stream_id: 0 };
    internal::encode_frame_header_to(set_hdr, handshake_wire);
    var server_out: u8[..1024] = [];
    let _, ok_init = internal::handle_h2_server_ingress(sess, pipeline, timer, "127.0.0.1", handshake_wire[..], 1000, server_out);
    assert(ok_init);

    var pp_wire: u8[..64] = [];
    let pp_hdr = internal::FrameHeader { length: 4, frame_type: rfc::H2_FRAME_PUSH_PROMISE, flags: 0, stream_id: 1 };
    internal::encode_frame_header_to(pp_hdr, pp_wire);
    pp_wire.push(0x00);
    pp_wire.push(0x00);
    pp_wire.push(0x00);
    pp_wire.push(0x02); // Promised stream 2
    server_out.clear();
    let _, ok_pp = internal::handle_h2_server_ingress(sess, pipeline, timer, "127.0.0.1", pp_wire[..], 1001, server_out);
    assert(!ok_pp); // Rejected with GOAWAY

    // Verify GOAWAY emitted
    let goaway_hdr, err_go = internal::parse_frame_header(server_out[..9]);
    assert(err_go == rfc::H2_ERR_NO_ERROR);
    assert(goaway_hdr.frame_type == rfc::H2_FRAME_GOAWAY);

    print("H2_STATE_MATRIX: OK");
}

fn main() {
    test_quic_role_polarity();
    test_h3_role_polarity();
    test_h2_state_matrix();
}

// CHECK: QUIC_ROLE_POLARITY: OK
// CHECK-NEXT: H3_ROLE_POLARITY: OK
// CHECK-NEXT: H2_STATE_MATRIX: OK
