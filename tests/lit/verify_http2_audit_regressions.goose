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
import headers from "../../http";
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

fn test_hpack_huffman_and_indexing_policy() {
    // H2HPACK-01 & H2HPACK-02: Zero-stack-zeroing Huffman decode rollback & single-pass short Huffman encode
    var dec_out: u8[..64] = [];
    dec_out.append("prefix:");
    let bad_huff: u8[2] = [0xFF, 0xFF]; // Invalid EOS padding (> 7 bits)
    assert(!internal::huff_decode_bytes(bad_huff[..], dec_out));
    assert(dec_out[..] == "prefix:");

    var enc_out: u8[..128] = [];
    assert(internal::encode_hpack_string_literal(enc_out, "www.example.com", true));
    assert((enc_out[0] & 0x80) != 0); // Huffman flag set
    var rt_out: u8[..128] = [];
    let next_off, ok_str = internal::decode_hpack_string(enc_out[..], 0, rt_out);
    assert(ok_str && next_off == (enc_out.len as u64) && rt_out[..] == "www.example.com");

    // Incompressible short string falls back to raw octets
    var raw_out: u8[..64] = [];
    assert(internal::encode_hpack_string_literal(raw_out, "\x00\x01", true));
    assert((raw_out[0] & 0x80) == 0 && raw_out[0] == 2);

    // H2HPACK-03: Adaptive Header Indexing Policy
    assert(internal::select_hpack_indexing("authorization", "Bearer secret-token-value", 4096) == internal::HpackIndexing.NeverIndexed);
    assert(internal::select_hpack_indexing("cookie", "sid=123", 4096) == internal::HpackIndexing.NeverIndexed);
    assert(internal::select_hpack_indexing("cookie", "session_id=0123456789abcdef0123456789", 4096) == internal::HpackIndexing.Incremental);
    assert(internal::select_hpack_indexing("content-length", "42", 4096) == internal::HpackIndexing.None);
    assert(internal::select_hpack_indexing("etag", "\"v1\"", 4096) == internal::HpackIndexing.None);
    assert(internal::select_hpack_indexing("x-large", "012345678901234567890123456789", 48) == internal::HpackIndexing.None);
    assert(internal::select_hpack_indexing("x-custom", "ok", 4096) == internal::HpackIndexing.Incremental);
    print("TEST_HPACK_HUFF_AND_POLICY: OK\n");
}

fn test_graceful_shutdown_and_protocol_guards() {
    // H2HPACK-05: Two-Phase Graceful GOAWAY Shutdown
    var sess = internal::new_h2_server_session("goose-wing/1.0", 1000);
    var out_wire: u8[>..] = [];
    internal::initiate_graceful_shutdown(sess, out_wire);
    assert(sess.conn.shutdown_notice_sent && !sess.conn.goaway_sent);
    assert(out_wire.len == 34); // 17-byte GOAWAY(2^31-1) + 17-byte PING

    // Client echoes PING ACK with matching shutdown_ping_opaque
    let ping_ack_hdr = internal::FrameHeader {
        length:     8,
        frame_type: rfc::H2_FRAME_PING,
        flags:      rfc::H2_FLAG_ACK,
        stream_id:  0,
    };
    var ping_payload: u8[..8] = [];
    core::append_u64_be(ping_payload, sess.conn.shutdown_ping_opaque);
    var out_phase2: u8[>..] = [];
    internal::process_ingress_ping(sess, ping_ack_hdr, ping_payload[..], out_phase2);
    assert(sess.conn.goaway_sent && out_phase2.len == 17);

    // H2HPACK-06: Explicit PRIORITY_UPDATE prevents Priority request header override
    var sess2 = internal::new_h2_server_session("goose-wing/1.0", 1000);
    let hdr_s1 = internal::FrameHeader {
        length:     10,
        frame_type: rfc::H2_FRAME_HEADERS,
        flags:      rfc::H2_FLAG_END_HEADERS,
        stream_id:  1,
    };
    assert(internal::handle_h2_headers_frame_header(sess2.conn, hdr_s1, 0) == rfc::H2_ERR_NO_ERROR);
    let _, p_exp, _ = internal::parse_priority_update_payload("\x00\x00\x00\x01u=1, i", false);
    assert(internal::apply_priority_update(sess2.conn, 1, p_exp) == rfc::H2_ERR_NO_ERROR);
    assert(sess2.conn.streams[0].has_explicit_priority_update);
    var hdr_map = wing::HeaderMap { .. };
    wing::set_header(hdr_map, "priority", "u=6");
    internal::apply_request_priority_header(sess2.conn, 1, hdr_map);
    assert(sess2.conn.streams[0].priority.urgency == 1);

    // H2HPACK-08: Extended CONNECT :protocol rejected when enable_connect_protocol == 0
    sess.conn.enable_connect_protocol = 0;
    var p_ext = internal::H2PseudoHeaders {
        has_method:    true,
        has_scheme:    true,
        has_path:      true,
        has_authority: true,
        has_protocol:  true,
        ..
    };
    p_ext.method.append("CONNECT");
    p_ext.scheme.append("https");
    p_ext.path.append("/chat");
    p_ext.authority.append("example.com");
    p_ext.protocol.append("websocket");
    assert(!internal::validate_request_pseudo_headers(p_ext, false, sess.conn.enable_connect_protocol));
    sess.conn.enable_connect_protocol = 1;
    assert(internal::validate_request_pseudo_headers(p_ext, false, sess.conn.enable_connect_protocol));

    // H2HPACK-04: Coalesced receive flow-control WINDOW_UPDATE threshold
    sess2.conn.coalesce_window_updates = true;
    let s_slot, _ = internal::find_or_alloc_stream(sess2, 1);
    var wu_wire: u8[>..] = [];
    internal::replenish_ingress_data_windows(sess2, s_slot, 1, 1024, false, wu_wire);
    assert(wu_wire.len == 0 && sess2.conn.unclaimed_recv_window == 1024);
    internal::replenish_ingress_data_windows(sess2, s_slot, 1, 32768, false, wu_wire);
    assert(wu_wire.len == 26 && sess2.conn.unclaimed_recv_window == 0 && sess2.streams[s_slot].unclaimed_local_window == 0);

    // Exercise HuffContext / huff_decode_step & has_lower_urgency_ready
    var hctx = internal::new_huff_context();
    var hdst: u8[8] = [0; 8];
    let hsrc: u8[2] = [0x9C, 0xC5];
    let hlen, hok = internal::huff_decode_step(hctx, hdst[..], 0, hsrc[..], true);
    assert(hok && hlen == 3);
    assert(!internal::has_lower_urgency_ready(sess2.conn));
    print("TEST_SHUTDOWN_AND_GUARDS: OK\n");
}

fn main() {
    test_priority_update_empty_field();
    test_settings_enable_connect_proto_server();
    test_headers_closed_stream_recycled_slot();
    test_goaway_invalid_parity();
    test_hpack_huffman_and_indexing_policy();
    test_graceful_shutdown_and_protocol_guards();
    print("ALL_HTTP2_REGRESSIONS: OK\n");
}

// CHECK: TEST_PRIO_EMPTY: OK
// CHECK: TEST_SETTINGS_CONNECT: OK
// CHECK: TEST_RECYCLED_SLOT_CLOSED: OK
// CHECK: TEST_GOAWAY_PARITY: OK
// CHECK: TEST_HPACK_HUFF_AND_POLICY: OK
// CHECK: TEST_SHUTDOWN_AND_GUARDS: OK
// CHECK: ALL_HTTP2_REGRESSIONS: OK
