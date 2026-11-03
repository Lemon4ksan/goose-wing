// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// tests/lit/rfc_repro_framer_quic_invariants.goose
// Verification of RFC 9000 transport wire framing and connection ID invariants:
// - RFC 9000 Section 12.4: Frames and Frame Types - An endpoint MUST treat receipt of a packet containing no frames as a connection error of type PROTOCOL_VIOLATION.
// - RFC 9000 Section 19.16: RETIRE_CONNECTION_ID Frames - An endpoint that provides a zero-length connection ID MUST treat receipt of a RETIRE_CONNECTION_ID frame as a connection error of type PROTOCOL_VIOLATION.
// - RFC 9000 Section 19.15: NEW_CONNECTION_ID Frames - An endpoint that is sending packets with a zero-length Destination Connection ID MUST treat receipt of a NEW_CONNECTION_ID frame as a connection error of type PROTOCOL_VIOLATION.
//
// RUN: goose build --cc gcc -O2 -o %t.exe %s
// RUN: %t.exe | %FileCheck %s

import std;
import core from "../..";
import wing from "../..";

fn test_empty_payload_packet_rejected() {
    let scid: u8[8] = [1, 2, 3, 4, 5, 6, 7, 8];
    var srv = internal::new_quic_server_connection(scid[..]);
    srv.state = internal::QuicConnState.Established;

    // RFC 9000 Section 12.4: Frames and Frame Types - An endpoint MUST treat receipt of a packet containing no frames as a connection error of type PROTOCOL_VIOLATION.
    let empty_payload: const u8[:] = "";
    let handled, _ = internal::quic_conn_process_payload(srv, empty_payload, internal::QuicHeaderType.OneRtt);
    assert(!handled);
    assert(srv.close_code == internal::QUIC_ERR_PROTOCOL_VIOLATION);
    assert(srv.state == internal::QuicConnState.Closing);

    print("QUIC_EMPTY_PAYLOAD_REJECTED: OK");
}

fn test_retire_conn_id_on_zero_length_scid_rejected() {
    // Server provides zero-length Connection ID to peer (scid is empty)
    var srv = internal::new_quic_server_connection("");
    srv.state = internal::QuicConnState.Established;

    var rcid_payload: u8[>..] = [];
    assert(internal::encode_retire_conn_id_frame(rcid_payload, 1));

    // RFC 9000 Section 19.16: RETIRE_CONNECTION_ID Frames - An endpoint that provides a zero-length connection ID MUST treat receipt of a RETIRE_CONNECTION_ID frame as a connection error of type PROTOCOL_VIOLATION.
    let handled, _ = internal::quic_conn_process_payload(srv, rcid_payload[..], internal::QuicHeaderType.OneRtt);
    assert(!handled);
    assert(srv.close_code == internal::QUIC_ERR_PROTOCOL_VIOLATION);
    assert(srv.state == internal::QuicConnState.Closing);

    print("QUIC_RETIRE_CONN_ID_ZERO_SCID_REJECTED: OK");
}

fn test_new_conn_id_on_zero_length_dcid_rejected() {
    // Client sends packets with zero-length Destination Connection ID (dcid is empty)
    let scid: u8[8] = [1, 2, 3, 4, 5, 6, 7, 8];
    var client = internal::new_quic_client_connection("", scid[..]);
    client.state = internal::QuicConnState.Established;

    var ncid_payload: u8[>..] = [];
    let reset_tok: u8[16] = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];
    let new_cid:   u8[4]  = [0xAA, 0xBB, 0xCC, 0xDD];
    assert(internal::encode_new_conn_id_frame(ncid_payload, 1, 0, new_cid[..], reset_tok));

    // RFC 9000 Section 19.15: NEW_CONNECTION_ID Frames - An endpoint that is sending packets with a zero-length Destination Connection ID MUST treat receipt of a NEW_CONNECTION_ID frame as a connection error of type PROTOCOL_VIOLATION.
    let handled, _ = internal::quic_conn_process_payload(client, ncid_payload[..], internal::QuicHeaderType.OneRtt);
    assert(!handled);
    assert(client.close_code == internal::QUIC_ERR_PROTOCOL_VIOLATION);
    assert(client.state == internal::QuicConnState.Closing);

    print("QUIC_NEW_CONN_ID_ZERO_DCID_REJECTED: OK");
}

fn main() {
    test_empty_payload_packet_rejected();
    test_retire_conn_id_on_zero_length_scid_rejected();
    test_new_conn_id_on_zero_length_dcid_rejected();
    print("ALL_QUIC_FRAMER_INVARIANTS: OK");
}

// CHECK: QUIC_EMPTY_PAYLOAD_REJECTED: OK
// CHECK: QUIC_RETIRE_CONN_ID_ZERO_SCID_REJECTED: OK
// CHECK: QUIC_NEW_CONN_ID_ZERO_DCID_REJECTED: OK
// CHECK: ALL_QUIC_FRAMER_INVARIANTS: OK
