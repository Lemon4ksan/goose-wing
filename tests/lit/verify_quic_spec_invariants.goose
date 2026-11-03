// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// tests/lit/verify_quic_spec_invariants.goose
// Verification of RFC 9000 strict specification invariants:
// - RFC 9000 §19.7: NEW_TOKEN token field MUST NOT be empty (FRAME_ENCODING_ERROR).
// - RFC 9000 §19.7: Clients MUST NOT send NEW_TOKEN; server receipt is PROTOCOL_VIOLATION.
// - RFC 9000 §19.11 & §4.6: MAX_STREAMS cannot exceed 2^60 (FRAME_ENCODING_ERROR).
// - RFC 9000 §19.14: STREAMS_BLOCKED cannot exceed 2^60 (FRAME_ENCODING_ERROR).
// - RFC 9000 §12.4 & §12.5: Prohibited frames in packet number spaces (PROTOCOL_VIOLATION).
// - RFC 9000 §19.13: STREAM_DATA_BLOCKED on send-only stream is STREAM_STATE_ERROR.
//
// RUN: goose build --cc gcc -O2 -o %t.exe %s
// RUN: %t.exe | %FileCheck %s

import std;
import core from "../..";
import wing from "../..";
import wire_kit from ".";

fn test_new_token_empty_rejected() {
    var vEmptyToken: u8[>..] = [];
    assert(wire_kit::parse_hex("0700", vEmptyToken)); // Type 0x07 (NEW_TOKEN), Length 0
    let _, _, ok = internal::decode_quic_frame(vEmptyToken[..], 0);
    assert(!ok); // RFC 9000 §19.7: Token MUST NOT be empty -> FRAME_ENCODING_ERROR

    var vValidToken: u8[>..] = [];
    assert(wire_kit::parse_hex("070474657374", vValidToken)); // Type 0x07, Length 4, "test"
    let frame, next_off, ok_val = internal::decode_quic_frame(vValidToken[..], 0);
    assert(ok_val);
    assert(next_off == 6);
    assert(frame.frame_type == internal::QuicFrameType.NewToken);
    assert(frame.payload == "test");
    print("QUIC_NEW_TOKEN_INVARIANTS: OK");
}

fn test_max_streams_boundary_2_60() {
    // 2^60 is 0x1000000000000000. Encoded as 8-byte varint: 0xD0 0x00 0x00 0x00 0x00 0x00 0x00 0x00
    var vMaxStreamsValid: u8[>..] = [];
    assert(wire_kit::parse_hex("12D000000000000000", vMaxStreamsValid));
    let frame_val, _, ok_val = internal::decode_quic_frame(vMaxStreamsValid[..], 0);
    assert(ok_val);
    assert(frame_val.max_data == (1 as u64) << 60);

    // 2^60 + 1: 0xD0 0x00 0x00 0x00 0x00 0x00 0x00 0x01 -> MUST be rejected (RFC 9000 §19.11)
    var vMaxStreamsOvf: u8[>..] = [];
    assert(wire_kit::parse_hex("12D000000000000001", vMaxStreamsOvf));
    let _, _, ok_ovf = internal::decode_quic_frame(vMaxStreamsOvf[..], 0);
    assert(!ok_ovf);

    // Test uni variant (0x13)
    var vMaxStreamsUniOvf: u8[>..] = [];
    assert(wire_kit::parse_hex("13D000000000000001", vMaxStreamsUniOvf));
    let _, _, ok_uni_ovf = internal::decode_quic_frame(vMaxStreamsUniOvf[..], 0);
    assert(!ok_uni_ovf);

    print("QUIC_MAX_STREAMS_2_60_CEILING: OK");
}

fn test_streams_blocked_boundary_2_60() {
    // 2^60 is valid: 0xD0 0x00 0x00 0x00 0x00 0x00 0x00 0x00
    var vSbValid: u8[>..] = [];
    assert(wire_kit::parse_hex("16D000000000000000", vSbValid));
    let frame_val, _, ok_val = internal::decode_quic_frame(vSbValid[..], 0);
    assert(ok_val);
    assert(frame_val.max_data == (1 as u64) << 60);

    // 2^60 + 1 MUST be rejected (RFC 9000 §19.14)
    var vSbOvf: u8[>..] = [];
    assert(wire_kit::parse_hex("16D000000000000001", vSbOvf));
    let _, _, ok_ovf = internal::decode_quic_frame(vSbOvf[..], 0);
    assert(!ok_ovf);

    // Test uni variant (0x17)
    var vSbUniOvf: u8[>..] = [];
    assert(wire_kit::parse_hex("17D000000000000001", vSbUniOvf));
    let _, _, ok_uni_ovf = internal::decode_quic_frame(vSbUniOvf[..], 0);
    assert(!ok_uni_ovf);

    print("QUIC_STREAMS_BLOCKED_2_60_CEILING: OK");
}

fn test_packet_number_space_frame_matrix() {
    let scid: u8[8] = [1, 2, 3, 4, 5, 6, 7, 8];
    var srv = internal::new_quic_server_connection(scid[..]);

    // Initial packet containing STREAM frame (0x08) -> MUST trigger PROTOCOL_VIOLATION (RFC 9000 §12.5)
    var stream_payload: u8[>..] = [];
    assert(wire_kit::parse_hex("0804026869", stream_payload)); // STREAM id=4 len=2 "hi"

    let handled, _ = internal::quic_conn_process_payload(srv, stream_payload[..], internal::QuicHeaderType.Initial);
    assert(!handled);
    assert(srv.close_code == rfc::QUIC_ERR_PROTOCOL_VIOLATION);

    // Reset connection
    var srv2 = internal::new_quic_server_connection(scid[..]);
    // Initial packet containing HANDSHAKE_DONE (0x1E) -> MUST trigger PROTOCOL_VIOLATION
    var hd_payload: u8[>..] = [];
    hd_payload.push(0x1E);
    let handled2, _ = internal::quic_conn_process_payload(srv2, hd_payload[..], internal::QuicHeaderType.Initial);
    assert(!handled2);
    assert(srv2.close_code == rfc::QUIC_ERR_PROTOCOL_VIOLATION);

    // Initial packet containing CONNECTION_CLOSE_APP (0x1D) -> MUST trigger PROTOCOL_VIOLATION
    var srv3 = internal::new_quic_server_connection(scid[..]);
    var cc_app_payload: u8[>..] = [];
    assert(wire_kit::parse_hex("1D0000", cc_app_payload)); // CONNECTION_CLOSE_APP code=0 len=0
    let handled3, _ = internal::quic_conn_process_payload(srv3, cc_app_payload[..], internal::QuicHeaderType.Initial);
    assert(!handled3);
    assert(srv3.close_code == rfc::QUIC_ERR_PROTOCOL_VIOLATION);

    // 1-RTT packet containing legitimate STREAM frame -> MUST succeed
    var srv4 = internal::new_quic_server_connection(scid[..]);
    srv4.state = internal::QuicConnState.Established;
    let handled4, _ = internal::quic_conn_process_payload(srv4, stream_payload[..], internal::QuicHeaderType.OneRtt);
    assert(handled4);
    assert(srv4.close_code == 0);

    print("QUIC_SPACE_FRAME_MATRIX: OK");
}

fn test_server_receiving_new_token() {
    let scid: u8[8] = [1, 2, 3, 4, 5, 6, 7, 8];
    var srv = internal::new_quic_server_connection(scid[..]);
    srv.state = internal::QuicConnState.Established;

    // Server receiving NEW_TOKEN (0x07) in 1-RTT packet -> MUST trigger PROTOCOL_VIOLATION (RFC 9000 §19.7)
    var tok_payload: u8[>..] = [];
    assert(wire_kit::parse_hex("070474657374", tok_payload));
    let handled, _ = internal::quic_conn_process_payload(srv, tok_payload[..], internal::QuicHeaderType.OneRtt);
    assert(!handled);
    assert(srv.close_code == rfc::QUIC_ERR_PROTOCOL_VIOLATION);

    print("QUIC_SERVER_NEW_TOKEN_REJECTED: OK");
}

fn test_stream_data_blocked_send_only() {
    let scid: u8[8] = [1, 2, 3, 4, 5, 6, 7, 8];
    var srv = internal::new_quic_server_connection(scid[..]);
    srv.state = internal::QuicConnState.Established;

    // Server receives STREAM_DATA_BLOCKED on stream 3 (ServerUni: client can only receive, cannot send).
    // Stream 3 for Server is send-only. Peer (client) is receive-only.
    // RFC 9000 §19.13: "An endpoint that receives a STREAM_DATA_BLOCKED frame for a send-only stream
    // MUST terminate the connection with error STREAM_STATE_ERROR."
    var sdb_payload: u8[>..] = [];
    assert(wire_kit::parse_hex("15034000", sdb_payload)); // STREAM_DATA_BLOCKED stream=3 limit=0
    let handled, _ = internal::quic_conn_process_payload(srv, sdb_payload[..], internal::QuicHeaderType.OneRtt);
    assert(!handled);
    assert(srv.close_code == rfc::QUIC_ERR_STREAM_STATE);

    print("QUIC_STREAM_DATA_BLOCKED_INVARIANTS: OK");
}

fn test_frame_encoders() {
    var out_tok: u8[>..] = [];
    assert(!internal::encode_new_token_frame(out_tok, "")); // empty token rejected
    assert(internal::encode_new_token_frame(out_tok, "valid_token"));
    let f_tok, _, ok_tok = internal::decode_quic_frame(out_tok[..], 0);
    assert(ok_tok);
    assert(f_tok.frame_type == internal::QuicFrameType.NewToken);
    assert(f_tok.payload == "valid_token");

    var out_ncid: u8[>..] = [];
    let reset_tok: u8[16] = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];
    let cid:       u8[4]  = [0xAA, 0xBB, 0xCC, 0xDD];
    assert(internal::encode_new_conn_id_frame(out_ncid, 1, 0, cid[..], reset_tok));
    let f_ncid, _, ok_ncid = internal::decode_quic_frame(out_ncid[..], 0);
    assert(ok_ncid);
    assert(f_ncid.frame_type == internal::QuicFrameType.NewConnectionId);
    assert(f_ncid.stream_id == 1);
    assert(f_ncid.offset == 0);

    var out_rcid: u8[>..] = [];
    assert(internal::encode_retire_conn_id_frame(out_rcid, 2));
    let f_rcid, _, ok_rcid = internal::decode_quic_frame(out_rcid[..], 0);
    assert(ok_rcid);
    assert(f_rcid.frame_type == internal::QuicFrameType.RetireConnectionId);
    assert(f_rcid.stream_id == 2);

    print("QUIC_FRAME_ENCODERS: OK");
}

fn main() {
    test_new_token_empty_rejected();
    test_max_streams_boundary_2_60();
    test_streams_blocked_boundary_2_60();
    test_packet_number_space_frame_matrix();
    test_server_receiving_new_token();
    test_stream_data_blocked_send_only();
    test_frame_encoders();
    print("ALL_QUIC_SPEC_INVARIANTS: OK");
}

// CHECK: QUIC_NEW_TOKEN_INVARIANTS: OK
// CHECK: QUIC_MAX_STREAMS_2_60_CEILING: OK
// CHECK: QUIC_STREAMS_BLOCKED_2_60_CEILING: OK
// CHECK: QUIC_SPACE_FRAME_MATRIX: OK
// CHECK: QUIC_SERVER_NEW_TOKEN_REJECTED: OK
// CHECK: QUIC_STREAM_DATA_BLOCKED_INVARIANTS: OK
// CHECK: QUIC_FRAME_ENCODERS: OK
// CHECK: ALL_QUIC_SPEC_INVARIANTS: OK
