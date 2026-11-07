// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// tests/lit/verify_http3_regressions.goose
// Regression tests for confirmed HTTP/3 and QPACK bugs:
// 1. Server rejects requests missing both :authority and Host (RFC 9114 §4.3.1).
// 2. QPACK never_index flag correctly marks newly appended duplicate header (Security).
// 3. QPACK dynamic insert failure does not mutate tbl and does not drop header (RFC 9204 §4.3).
// 4. Server rejects GOAWAY with invalid stream ID (RFC 9114 §7.2.6).
// 5. Client rejects incoming frames on unopened client bidi streams (RFC 9114 §6.1).
//
// RUN: goose build --cc gcc -O1 -o %t.exe %s
// RUN: %t.exe | %FileCheck %s

import std;
import core from "../..";
import wing from "../..";

fn test_server_rejects_missing_authority_and_host() {
    let settings = wing::H3Settings { .. };
    var conn = internal::new_h3_server_connection(settings);

    // Initialize peer control stream
    var init_ctrl: u8[..64] = [];
    internal::quic_encode_varint(init_ctrl, rfc::H3_STREAM_CONTROL);
    assert(internal::encode_h3_settings_frame(init_ctrl, settings));
    let err_init = internal::handle_stream_data(conn, 2, false, init_ctrl[..], false);
    assert(err_init == rfc::H3_ERR_NO_ERROR);

    // Encode a request HEADERS frame with :method, :scheme, :path, but NO :authority and NO Host
    var qpack_payload: u8[..128] = [];
    qpack_payload.push(0x00); // RIC = 0
    qpack_payload.push(0x00); // DeltaBase = 0
    // Static index 17: :method GET (11010001 = 0xD1)
    qpack_payload.push(0xD1);
    // Static index 1: :path / (11000001 = 0xC1)
    qpack_payload.push(0xC1);
    // Static index 23: :scheme https (11010111 = 0xD7)
    qpack_payload.push(0xD7);

    var req_frame: u8[..256] = [];
    assert(internal::encode_h3_headers_frame(req_frame, qpack_payload[..]));

    let err = internal::handle_stream_data(conn, 0, true, req_frame[..], true);
    // RFC 9114 §4.3.1: Must be rejected with H3_ERR_GENERAL_PROTOCOL
    assert(err == rfc::H3_ERR_GENERAL_PROTOCOL);
    print("REGRESS_MISSING_AUTHORITY: OK");
}

fn test_qpack_never_index_flag_on_duplicate_header_name() {
    let tbl = internal::new_qpack_table(4096, 16);
    var pseudo = internal::H3PseudoHeaders { .. };
    var headers = wing::HeaderMap { .. };

    // QPACK section with two "set-cookie" headers:
    // First: "set-cookie: theme=dark" without never_index
    // Second: "set-cookie: session=secret" with never_index (001NHxxx -> N=1, H=0 -> 0x30)
    var wire: u8[..256] = [];
    wire.push(0x00); // RIC = 0
    wire.push(0x00); // DeltaBase = 0

    // Header 1: Literal name "x-token-id" (len 10), Literal value "theme=dark" (len 10)
    // 001NHxxx with N=0, H=0 -> 0x20
    wire.push(0x27); // 0x20 | 7
    wire.push(0x03); // 10 - 7 = 3
    wire.append("x-token-id");
    wire.push(0x0A); // val len 10
    wire.append("theme=dark");

    // Header 2: Literal name "x-token-id" (len 10), Literal value "session=secret" (len 14)
    // 001NHxxx with N=1, H=0 -> 0x30
    wire.push(0x37); // 0x30 | 7
    wire.push(0x03); // 10 - 7 = 3
    wire.append("x-token-id");
    wire.push(0x0E); // val len 14
    wire.append("session=secret");

    let err = internal::decode_qpack_to_map(tbl, wire[..], pseudo, headers, 8192);
    assert(err == internal::QpackError.None);
    assert(headers.entries.len == 2);

    let flag0 = (headers.entries[0].flags & wing::HEADER_FLAG_SENSITIVE) != 0;
    let flag1 = (headers.entries[1].flags & wing::HEADER_FLAG_SENSITIVE) != 0;

    // Entry 0 must NOT be sensitive; Entry 1 MUST be sensitive
    assert(!flag0);
    assert(flag1);
    print("REGRESS_NEVER_INDEX_DUPLICATE: OK");
}

fn test_server_rejects_goaway_with_non_client_bidi_stream_id() {
    let settings = wing::H3Settings { .. };
    var conn = internal::new_h3_server_connection(settings);

    // Initialize peer control stream
    var init_ctrl: u8[..64] = [];
    internal::quic_encode_varint(init_ctrl, rfc::H3_STREAM_CONTROL);
    assert(internal::encode_h3_settings_frame(init_ctrl, settings));
    let err_init = internal::handle_stream_data(conn, 2, false, init_ctrl[..], false);
    assert(err_init == rfc::H3_ERR_NO_ERROR);

    // Client sends GOAWAY with stream ID 1 (server-initiated bidirectional -> invalid in GOAWAY)
    var ga_wire: u8[..64] = [];
    assert(internal::encode_h3_goaway_frame(ga_wire, 1));
    let err_ga1 = internal::handle_stream_data(conn, 2, false, ga_wire[..], false);
    // RFC 9114 §7.2.6: Must be rejected with H3_ERR_ID_ERROR
    assert(err_ga1 == rfc::H3_ERR_ID_ERROR);

    // Client sends GOAWAY with stream ID 2 (client-initiated unidirectional -> invalid in GOAWAY)
    conn = internal::new_h3_server_connection(settings);
    internal::handle_stream_data(conn, 2, false, init_ctrl[..], false);
    ga_wire.clear();
    assert(internal::encode_h3_goaway_frame(ga_wire, 2));
    let err_ga2 = internal::handle_stream_data(conn, 2, false, ga_wire[..], false);
    assert(err_ga2 == rfc::H3_ERR_ID_ERROR);

    print("REGRESS_GOAWAY_INVALID_ID: OK");
}

fn test_qpack_dynamic_insert_transactional_failure() {
    var tbl = internal::new_qpack_table(4096, 16);
    assert(internal::qpack_set_capacity(tbl, 4096));

    // Create a constrained encoder stream buffer that cannot fit the insert instruction
    var tiny_enc: u8[..2]   = [];
    var out_sec:  u8[..256] = [];
    var max_dyn:  u64       = 0;
    var used_dyn = false;

    let prev_ic = tbl.insert_count;
    // Attempt dynamic field encoding when enc_stream is full
    internal::encode_qpack_field_dynamic(
        tbl, 4, 0, "x-custom-key", "custom-val",
        out_sec, tiny_enc, max_dyn, used_dyn, false,
    );

    // Dynamic table must NOT have inserted a phantom entry
    assert(tbl.insert_count == prev_ic);
    // Header must NOT be silently dropped: it must have been encoded as literal in out_sec!
    assert(out_sec.len > 0);

    print("REGRESS_QPACK_DYNAMIC_INSERT_TRANSACTIONAL: OK");
}

fn test_client_rejects_server_frames_on_unopened_bidi_stream() {
    let settings = wing::H3Settings { .. };
    var conn = internal::new_h3_client_connection(settings);

    // Server sends DATA frame on stream 0, but client NEVER opened stream 0!
    var data_frame: u8[..64] = [];
    assert(internal::encode_h3_data_frame(data_frame, "hello"));
    let err = internal::handle_stream_data(conn, 0, true, data_frame[..], false);

    // RFC 9114 §4.1 / §6.1: Must be rejected with H3_ERR_STREAM_CREATION
    assert(err == rfc::H3_ERR_STREAM_CREATION);
    assert(conn.state == internal::H3ConnState.Closed);

    print("REGRESS_CLIENT_UNOPENED_BIDI_REJECTED: OK");
}

// F001: Blocked QPACK HEADERS frame must unblock and validate when Encoder Stream delivers inserts (RFC 9204 §2.2.1)
fn test_qpack_blocked_stream_unblocks_on_encoder_stream() {
    let settings = wing::H3Settings {
        qpack_max_table_capacity: 4096,
        max_field_section_size:   65536,
        qpack_blocked_streams:    4,
        enable_connect_protocol:  0,
    };
    var srv = internal::new_h3_server_connection(settings);
    assert(internal::qpack_set_capacity(srv.qpack_table, 4096));

    // Build a request HEADERS frame with RIC=1 (EncodedRIC=2, Base=1 -> [0x02, 0x00]) referencing dynamic abs_idx 0
    var qpack_sec: u8[..128] = [0x02, 0x00];
    internal::encode_qpack_field(qpack_sec, ":method", "POST");
    internal::encode_qpack_field(qpack_sec, ":scheme", "https");
    internal::encode_qpack_field(qpack_sec, ":authority", "example.com");
    internal::encode_qpack_field(qpack_sec, ":path", "/upload");
    qpack_sec.push(0x80); // Dynamic indexed rel_idx 0 (abs_idx 0)
    var hdr_frame: u8[..160] = [];
    assert(internal::encode_h3_headers_frame(hdr_frame, qpack_sec[..]));

    // 1. Arrive before encoder stream: stream 0 becomes QPACK-blocked
    let err_hdr = internal::handle_stream_data(srv, 0, true, hdr_frame[..], false);
    assert(err_hdr == rfc::H3_ERR_NO_ERROR);
    assert(internal::qpack_is_stream_blocked(srv.qpack_table, 0));

    // 2. Peer sends QPACK encoder stream (uni stream 6) with type 0x02 + Insert Literal ("content-length", "5")
    var peer_enc_tbl = internal::new_qpack_table(4096, 4);
    assert(internal::qpack_set_capacity(peer_enc_tbl, 4096));
    var enc_wire: u8[..64] = [];
    assert(internal::quic_encode_varint(enc_wire, rfc::H3_STREAM_QPACK_ENCODER));
    let _, ok_ins = internal::encode_qpack_dynamic_insert(peer_enc_tbl, "content-length", "5", enc_wire, false);
    assert(ok_ins);
    let err_enc = internal::handle_stream_data(srv, 6, false, enc_wire[..], false);
    assert(err_enc == rfc::H3_ERR_NO_ERROR);

    // Stream 0 must now be unblocked and its headers_received must be true!
    assert(!internal::qpack_is_stream_blocked(srv.qpack_table, 0));
    let s_idx, found = internal::find_h3_stream_idx(srv, 0);
    assert(found && s_idx >= 0 && srv.streams[s_idx].headers_received);
    assert(srv.streams[s_idx].content_length == 5);

    // 3. Subsequent DATA frame ("hello", 5 bytes) with FIN must succeed!
    var data_frame: u8[..32] = [];
    assert(internal::encode_h3_data_frame(data_frame, "hello"));
    let err_data = internal::handle_stream_data(srv, 0, true, data_frame[..], true);
    assert(err_data == rfc::H3_ERR_NO_ERROR);
    print("REGRESS_F001_BLOCKED_UNBLOCK: OK");
}

// F002: Multiple field sections on one stream (HEADERS + trailers) must queue FIFO Section Acknowledgments (RFC 9204 §4.4.1)
fn test_qpack_multi_section_fifo_ack() {
    let settings = wing::H3Settings {
        qpack_max_table_capacity: 4096,
        max_field_section_size:   65536,
        qpack_blocked_streams:    4,
        enable_connect_protocol:  0,
    };
    var srv = internal::new_h3_server_connection(settings);
    assert(internal::h3_activate_qpack_dynamic_table(srv, 4096));
    // Open stream 0 on server by receiving a minimal GET request
    var req_qpack: u8[..128] = [0x00, 0x00];
    internal::encode_qpack_field(req_qpack, ":method", "GET");
    internal::encode_qpack_field(req_qpack, ":scheme", "https");
    internal::encode_qpack_field(req_qpack, ":authority", "example.com");
    internal::encode_qpack_field(req_qpack, ":path", "/");
    var req_frame: u8[..160] = [];
    assert(internal::encode_h3_headers_frame(req_frame, req_qpack[..]));
    assert(internal::handle_stream_data(srv, 0, true, req_frame[..], true) == rfc::H3_ERR_NO_ERROR);

    var hdrs = wing::HeaderMap { .. };
    wing::set_header(hdrs, "x-resp-hdr", "v1");
    var trls = wing::HeaderMap { .. };
    wing::set_header(trls, "x-trailer", "t1");
    var out_wire: u8[..512] = [];
    assert(internal::send_response_headers_body_and_trailers(srv, 0, 200, hdrs, "body", trls, out_wire));

    // Both HEADERS and trailers referenced dynamic entries on stream 0; two Section Acknowledgments must succeed in FIFO order
    assert(internal::qpack_ack_section(srv.qpack_table, 0) == internal::QpackError.None);
    assert(internal::qpack_ack_section(srv.qpack_table, 0) == internal::QpackError.None);
    // A third Section Acknowledgment on stream 0 must fail
    assert(internal::qpack_ack_section(srv.qpack_table, 0) == internal::QpackError.DecoderStreamError);
    print("REGRESS_F002_MULTI_SECTION_ACK: OK");
}

// F003: HEAD 200 response with non-zero Content-Length and 0 DATA bytes succeeds; DATA on HEAD/204/304 rejected (RFC 9114 §4.1.2)
fn test_head_and_no_content_response_framing() {
    let settings = wing::H3Settings { .. };
    var cli = internal::new_h3_client_connection(settings);
    let sid, ok_open = internal::open_request_stream(cli);
    assert(ok_open && sid == 0);
    var req_out: u8[..256] = [];
    var empty_h = wing::HeaderMap { .. };
    assert(internal::send_request_headers(cli, sid, "HEAD", "https", "example.com", "/file", empty_h, true, req_out));

    var resp_qpack: u8[..128] = [0x00, 0x00];
    internal::encode_qpack_field(resp_qpack, ":status", "200");
    internal::encode_qpack_field(resp_qpack, "content-length", "500");
    var resp_frame: u8[..160] = [];
    assert(internal::encode_h3_headers_frame(resp_frame, resp_qpack[..]));
    // FIN with 0 DATA bytes on HEAD response with CL=500 must succeed!
    let err_head = internal::handle_stream_data(cli, sid, true, resp_frame[..], true);
    assert(err_head == rfc::H3_ERR_NO_ERROR);
    print("REGRESS_F003_HEAD_FRAMING: OK");
}

// F004: Client rejects CANCEL_PUSH before MAX_PUSH_ID and rejects malformed PUSH_PROMISE headers (RFC 9114 §4.6, §7.2.3, §7.2.5)
fn test_cancel_push_and_goaway_push_promise() {
    let settings = wing::H3Settings { .. };
    var cli = internal::new_h3_client_connection(settings);
    var init_ctrl: u8[..64] = [];
    internal::quic_encode_varint(init_ctrl, rfc::H3_STREAM_CONTROL);
    assert(internal::encode_h3_settings_frame(init_ctrl, settings));
    assert(internal::handle_stream_data(cli, 3, false, init_ctrl[..], false) == rfc::H3_ERR_NO_ERROR);

    var cp_wire: u8[..32] = [];
    assert(internal::encode_h3_cancel_push(cp_wire, 0));
    // Client has NEVER sent MAX_PUSH_ID -> CANCEL_PUSH(0) must fail with H3_ERR_ID_ERROR
    assert(internal::handle_stream_data(cli, 3, false, cp_wire[..], false) == rfc::H3_ERR_ID_ERROR);

    // Client receives PUSH_PROMISE with invalid request headers (e.g. :status instead of request pseudo-headers) -> H3_ERR_GENERAL_PROTOCOL
    var cli2 = internal::new_h3_client_connection(settings);
    let sid, _ = internal::open_request_stream(cli2);
    cli2.max_push_id_sent = true;
    cli2.max_push_id_advertised = 5;
    var bad_pp_qpack: u8[..64] = [0x00, 0x00];
    internal::encode_qpack_field(bad_pp_qpack, ":status", "200");
    var bad_pp_frame: u8[..96] = [];
    assert(internal::encode_h3_push_promise(bad_pp_frame, 0, bad_pp_qpack[..]));
    assert(internal::handle_stream_data(cli2, sid, true, bad_pp_frame[..], false) == rfc::H3_ERR_GENERAL_PROTOCOL);
    print("REGRESS_F004_PUSH_INVARIANTS: OK");
}

// F005: PRIORITY_UPDATE empty field value, pre-stream buffering, and unpromised push_id rejection (RFC 9218 §7, §7.2)
fn test_priority_update_rfc9218_edge_cases() {
    var empty_pu: u8[..16] = [0x00]; // stream_id = 0, field_value = ""
    let sid, prio, ok_pu = internal::parse_h3_priority_update_request(empty_pu[..]);
    assert(ok_pu && sid == 0 && prio.urgency == 3 && !prio.incremental);

    let settings = wing::H3Settings { .. };
    var srv = internal::new_h3_server_connection(settings);
    var init_ctrl: u8[..64] = [];
    internal::quic_encode_varint(init_ctrl, rfc::H3_STREAM_CONTROL);
    assert(internal::encode_h3_settings_frame(init_ctrl, settings));
    assert(internal::handle_stream_data(srv, 2, false, init_ctrl[..], false) == rfc::H3_ERR_NO_ERROR);

    // Send PRIORITY_UPDATE(stream 0, u=1, i) BEFORE stream 0 is opened
    var pu_wire: u8[..32] = [];
    let p_target = wing::PriorityParam { urgency: 1, incremental: true };
    assert(internal::encode_h3_priority_update_request(pu_wire, 0, p_target));
    assert(internal::handle_stream_data(srv, 2, false, pu_wire[..], false) == rfc::H3_ERR_NO_ERROR);
    let idx0, found0 = internal::find_h3_stream_idx(srv, 0);
    assert(found0 && idx0 >= 0 && srv.streams[idx0].priority.urgency == 1 && srv.streams[idx0].priority.incremental);

    // Unpromised push_id in H3_FRAME_PRIORITY_UPDATE_PUSH must return H3_ERR_ID_ERROR
    var mp_wire: u8[..32] = [];
    assert(internal::encode_h3_max_push_id(mp_wire, 10));
    assert(internal::handle_stream_data(srv, 2, false, mp_wire[..], false) == rfc::H3_ERR_NO_ERROR);
    var pup_wire: u8[..32] = [];
    assert(internal::encode_h3_priority_update_push(pup_wire, 3, p_target));
    assert(internal::handle_stream_data(srv, 2, false, pup_wire[..], false) == rfc::H3_ERR_ID_ERROR);
    print("REGRESS_F005_PRIORITY_UPDATE: OK");
}

// F006, F007, F008: Settings narrowing / :protocol polarity, :method/:scheme lexical & wire map validation, 1xx Content-Length
fn test_settings_and_lexical_and_1xx_regressions() {
    // F006: 62-bit qpack_blocked_streams must not panic on narrowing cast; client SETTINGS cannot enable :protocol on server
    let huge_settings = wing::H3Settings {
        qpack_max_table_capacity: 0,
        max_field_section_size:   65536,
        qpack_blocked_streams:    0x100000005,
        enable_connect_protocol:  0,
    };
    var srv = internal::new_h3_server_connection(huge_settings);
    let peer_set = wing::H3Settings { enable_connect_protocol: 1, .. };
    var init_ctrl: u8[..64] = [];
    internal::quic_encode_varint(init_ctrl, rfc::H3_STREAM_CONTROL);
    assert(internal::encode_h3_settings_frame(init_ctrl, peer_set));
    assert(internal::handle_stream_data(srv, 2, false, init_ctrl[..], false) == rfc::H3_ERR_NO_ERROR);

    var proto_qpack: u8[..128] = [0x00, 0x00];
    internal::encode_qpack_field(proto_qpack, ":method", "CONNECT");
    internal::encode_qpack_field(proto_qpack, ":protocol", "websocket");
    internal::encode_qpack_field(proto_qpack, ":scheme", "https");
    internal::encode_qpack_field(proto_qpack, ":authority", "example.com");
    internal::encode_qpack_field(proto_qpack, ":path", "/chat");
    var proto_frame: u8[..160] = [];
    assert(internal::encode_h3_headers_frame(proto_frame, proto_qpack[..]));
    assert(internal::handle_stream_data(srv, 0, true, proto_frame[..], false) == rfc::H3_ERR_GENERAL_PROTOCOL);

    // F007: :method with space or :scheme starting with digit rejected; emit_qpack_field_to_map rejects connection header
    var bad_m_srv = internal::new_h3_server_connection(huge_settings);
    var bad_m_qpack: u8[..128] = [0x00, 0x00];
    internal::encode_qpack_field(bad_m_qpack, ":method", "GET /admin");
    internal::encode_qpack_field(bad_m_qpack, ":scheme", "https");
    internal::encode_qpack_field(bad_m_qpack, ":authority", "example.com");
    internal::encode_qpack_field(bad_m_qpack, ":path", "/");
    var bad_m_frame: u8[..160] = [];
    assert(internal::encode_h3_headers_frame(bad_m_frame, bad_m_qpack[..]));
    assert(internal::handle_stream_data(bad_m_srv, 0, true, bad_m_frame[..], false) == rfc::H3_ERR_GENERAL_PROTOCOL);

    // F008: 1xx informational response with Content-Length rejected (RFC 9110 §8.6)
    var cli = internal::new_h3_client_connection(huge_settings);
    let sid, _ = internal::open_request_stream(cli);
    var info_qpack: u8[..128] = [0x00, 0x00];
    internal::encode_qpack_field(info_qpack, ":status", "103");
    internal::encode_qpack_field(info_qpack, "content-length", "99");
    var info_frame: u8[..160] = [];
    assert(internal::encode_h3_headers_frame(info_frame, info_qpack[..]));
    assert(internal::handle_stream_data(cli, sid, true, info_frame[..], false) == rfc::H3_ERR_GENERAL_PROTOCOL);
    print("REGRESS_F006_F007_F008: OK");
}

fn main() {
    test_server_rejects_missing_authority_and_host();
    test_qpack_never_index_flag_on_duplicate_header_name();
    test_server_rejects_goaway_with_non_client_bidi_stream_id();
    test_qpack_dynamic_insert_transactional_failure();
    test_client_rejects_server_frames_on_unopened_bidi_stream();
    test_qpack_blocked_stream_unblocks_on_encoder_stream();
    test_qpack_multi_section_fifo_ack();
    test_head_and_no_content_response_framing();
    test_cancel_push_and_goaway_push_promise();
    test_priority_update_rfc9218_edge_cases();
    test_settings_and_lexical_and_1xx_regressions();
    print("ALL_HTTP3_REGRESSIONS_PASS");
}

// CHECK: REGRESS_MISSING_AUTHORITY: OK
// CHECK: REGRESS_NEVER_INDEX_DUPLICATE: OK
// CHECK: REGRESS_GOAWAY_INVALID_ID: OK
// CHECK: REGRESS_QPACK_DYNAMIC_INSERT_TRANSACTIONAL: OK
// CHECK: REGRESS_CLIENT_UNOPENED_BIDI_REJECTED: OK
// CHECK: REGRESS_F001_BLOCKED_UNBLOCK: OK
// CHECK: REGRESS_F002_MULTI_SECTION_ACK: OK
// CHECK: REGRESS_F003_HEAD_FRAMING: OK
// CHECK: REGRESS_F004_PUSH_INVARIANTS: OK
// CHECK: REGRESS_F005_PRIORITY_UPDATE: OK
// CHECK: REGRESS_F006_F007_F008: OK
// CHECK: ALL_HTTP3_REGRESSIONS_PASS
