// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Protocol Smuggler Cycle 1 Regression Suite (HTTP/2, HTTP/3, QPACK, HPACK, Connect/gRPC)
// RUN: goose %s | %FileCheck %s

import std;
import core from "../..";
import wing from "../..";

// Bug 1: HTTP/3 PUSH_PROMISE QPACK stream-ID confusion, response smuggling on unblock,
// missing promised push ID tracking, and non-transactional QPACK table/buffer operations.
fn test_bug1_h3_push_promise_and_qpack() {
    let settings = fingerprint::H3Settings {
        qpack_max_table_capacity: 4096,
        max_field_section_size:   65536,
        qpack_blocked_streams:    4,
        enable_connect_protocol:  0,
    };
    var cli = h3_internal::new_h3_client_connection(settings);
    assert(h3_internal::qpack_set_capacity(cli.qpack_table, 4096));
    let sid0, ok0 = h3_internal::open_request_stream(cli);
    let sid4, ok4 = h3_internal::open_request_stream(cli);
    assert(ok0 && sid0 == 0 && ok4 && sid4 == 4);
    cli.max_push_id_sent = true;
    cli.max_push_id_advertised = 5;

    // 1A. Server sends QPACK-blocked PUSH_PROMISE on stream 4 with push_id = 0 containing
    // forbidden `:status: 200` + dynamic ref 0. Must block stream 4 (NOT stream 0), and
    // when unblocked must reject `:status` rather than smuggling it into stream 0's response!
    var smuggled_qpack: u8[..128] = [0x02, 0x00];
    h3_internal::encode_qpack_field(smuggled_qpack, ":status", "200");
    smuggled_qpack.push(0x80);
    var bad_pp_wire: u8[..160] = [];
    assert(h3_internal::encode_h3_push_promise(bad_pp_wire, 0, smuggled_qpack[..]));

    let err_pp = h3_internal::handle_stream_data(cli, sid4, true, bad_pp_wire[..], false);
    assert(err_pp == rfc::H3_ERR_NO_ERROR);
    assert(!h3_internal::qpack_is_stream_blocked(cli.qpack_table, sid0));
    assert(h3_internal::qpack_is_stream_blocked(cli.qpack_table, sid4));

    var peer_enc_tbl = h3_internal::new_qpack_table(4096, 4);
    assert(h3_internal::qpack_set_capacity(peer_enc_tbl, 4096));
    var enc_wire: u8[..64] = [];
    assert(quic_internal::quic_encode_varint(enc_wire, rfc::H3_STREAM_QPACK_ENCODER));
    let _, ok_ins = h3_internal::encode_qpack_dynamic_insert(peer_enc_tbl, "x-smuggled", "1", enc_wire, false);
    assert(ok_ins);

    let err_unblock = h3_internal::handle_stream_data(cli, 7, false, enc_wire[..], false);
    assert(err_unblock == rfc::H3_ERR_GENERAL_PROTOCOL);
    assert(cli.streams[0].status_code == 0);

    // 1B. Valid QPACK-blocked PUSH_PROMISE updates max_promised_push_id and unblocks cleanly.
    var cli_ok = h3_internal::new_h3_client_connection(settings);
    assert(h3_internal::qpack_set_capacity(cli_ok.qpack_table, 4096));
    let _, ok_s0 = h3_internal::open_request_stream(cli_ok);
    let sid_req, ok_s4 = h3_internal::open_request_stream(cli_ok);
    assert(ok_s0 && ok_s4 && sid_req == 4);
    cli_ok.max_push_id_sent = true;
    cli_ok.max_push_id_advertised = 5;

    var good_pp_qpack: u8[..128] = [0x02, 0x00];
    h3_internal::encode_qpack_field(good_pp_qpack, ":method", "GET");
    h3_internal::encode_qpack_field(good_pp_qpack, ":scheme", "https");
    h3_internal::encode_qpack_field(good_pp_qpack, ":authority", "example.com");
    h3_internal::encode_qpack_field(good_pp_qpack, ":path", "/app.js");
    good_pp_qpack.push(0x80);
    var good_pp_wire: u8[..160] = [];
    assert(h3_internal::encode_h3_push_promise(good_pp_wire, 2, good_pp_qpack[..]));

    assert(h3_internal::handle_stream_data(cli_ok, sid_req, true, good_pp_wire[..], false) == rfc::H3_ERR_NO_ERROR);
    assert(cli_ok.has_promised_push_id && cli_ok.max_promised_push_id == 2);
    assert(h3_internal::handle_stream_data(cli_ok, 7, false, enc_wire[..], false) == rfc::H3_ERR_NO_ERROR);

    // 1C. Transactional encode_qpack_set_capacity, decode_qpack_section, and qpack_decode_int.
    var tbl = h3_internal::new_qpack_table(4096, 4);
    assert(h3_internal::qpack_set_capacity(tbl, 4096));
    assert(h3_internal::qpack_insert_literal(tbl, "x-keep", "value"));
    var tiny_enc: u8[..2] = [0xAA];
    assert(!h3_internal::encode_qpack_set_capacity(tbl, 1024, tiny_enc));
    assert(tiny_enc.len == 1);
    assert(tbl.capacity_bytes == 4096 && tbl.entries.len == 1);

    var partial_sec: u8[..32]                      = [0x00, 0x00, 0xD1, 0x27, 0x05];
    var out_fields:  h3_internal::HeaderField[..8] = [];
    let q_err = h3_internal::decode_qpack_section(tbl, partial_sec[..], out_fields, 16384);
    assert(q_err != h3_internal::QpackError.None);
    assert(out_fields.len == 0);

    var q_pseudo = h3_internal::H3PseudoHeaders {};
    var q_headers = wing::HeaderMap {};
    let q_map_err = h3_internal::decode_qpack_to_map(tbl, partial_sec[..], q_pseudo, q_headers, 16384);
    assert(q_map_err != h3_internal::QpackError.None);
    assert(!q_pseudo.has_method && q_headers.entries.len == 0);

    print("BUG1_H3_PUSH_PROMISE_AND_QPACK: OK");
}

// Bug 2: HTTP/2 GOAWAY last_stream_id ratchet bypass (RFC 9113 Section 6.8),
// non-transactional SETTINGS_INITIAL_WINDOW_SIZE delta, and ORIGIN/ALTSVC framing bounds.
fn test_bug2_h2_goaway_and_transactional_frames() {
    // 2A. GOAWAY last_stream_id ratchet: peer MUST NOT increase last_stream_id on subsequent GOAWAY.
    var conn = h2_internal::new_h2_connection(0);
    conn.is_server = false;
    assert(h2_internal::apply_goaway(conn, 5, rfc::H2_ERR_NO_ERROR) == rfc::H2_ERR_NO_ERROR);
    assert(conn.goaway_last_stream_id == 5);
    assert(h2_internal::apply_goaway(conn, 9, rfc::H2_ERR_NO_ERROR) == rfc::H2_ERR_PROTOCOL_ERROR);
    assert(conn.goaway_last_stream_id == 5);
    assert(h2_internal::apply_goaway(conn, 3, rfc::H2_ERR_NO_ERROR) == rfc::H2_ERR_NO_ERROR);
    assert(conn.goaway_last_stream_id == 3);

    // 2B. Transactional apply_peer_initial_window_size_delta on stream overflow.
    var fc_conn = h2_internal::new_h2_connection(0);
    h2_internal::open_new_session_stream(fc_conn, 1, false);
    h2_internal::open_new_session_stream(fc_conn, 3, false);
    fc_conn.streams[1].send_window = rfc::H2_MAX_WINDOW_SIZE - 10;
    let err_delta = h2_internal::apply_peer_initial_window_size_delta(fc_conn, 65635);
    assert(err_delta == rfc::H2_ERR_FLOW_CONTROL_ERROR);
    assert(fc_conn.peer_initial_window_size == 65535);
    assert(fc_conn.streams[0].send_window == 65535);

    // 2C. Transactional parse_origin_frame & bounded encode_origin_frame / encode_altsvc_frame.
    let bad_origin_payload: u8[11] = [0x00, 0x06, 'e', 'x', '.', 'c', 'o', 'm', 0x00, 0x10, 'x'];
    var origins: const u8[:][..16] = [];
    let count, o_err = h2_internal::parse_origin_frame(bad_origin_payload[..], 0, origins);
    assert(o_err == rfc::H2_ERR_FRAME_SIZE_ERROR && count == 0 && origins.len == 0);

    var valid_origins:  const u8[:][..16] = ["https://example.com"];
    var tiny_frame_buf: u8[..8]           = [0x01];
    assert(!h2_internal::encode_origin_frame(tiny_frame_buf, valid_origins));
    assert(tiny_frame_buf.len == 1);
    assert(!h2_internal::encode_altsvc_frame(tiny_frame_buf, "https://example.com", "h3=\":443\"", 0));
    assert(tiny_frame_buf.len == 1);

    print("BUG2_H2_GOAWAY_AND_FRAMES: OK");
}

// Bug 3: Connect Protocol EndStream error smuggling via metadata-first JSON key order
// and dirty out_trailers / out_payload on parse failure.
fn test_bug3_connect_end_stream_smuggling() {
    // 3A. JSON EndStream with "metadata" preceding "error" must not skip "error".
    let reordered_json = "{\"metadata\":{\"x-trace\":[\"req-99\"]},\"error\":{\"code\":\"permission_denied\",\"message\":\"blocked\"}}";
    var st = wing::GrpcStatusCode.Ok;
    var msg: u8[..256] = [];
    var tr = wing::HeaderMap { .. };
    assert(wing::parse_connect_end_stream(reordered_json, st, msg, tr));
    assert(st == wing::GrpcStatusCode.PermissionDenied);
    assert(msg[..] == "blocked");
    assert(wing::get_header(tr, "x-trace") == "req-99");

    // 3B. Malformed EndStream after metadata entry must roll back out_trailers and reject unclosed brackets.
    var tr_bad = wing::HeaderMap { .. };
    let truncated_meta = "{\"metadata\":{\"x-leak\":[\"1\"],\"x-broken\":[\"unclosed}}";
    assert(!wing::parse_connect_end_stream(truncated_meta, st, msg, tr_bad));
    assert(tr_bad.entries.len == 0);

    // 3C. Unary GET query with unsupported compression clears out_payload on failure.
    var get_params = wing::ConnectUnaryGetParams { .. };
    var get_payload: u8[>..] = [];
    let get_code = wing::parse_connect_get_query(
        "connect=v1&encoding=proto&base64=1&compression=br&message=cGluZw",
        get_params,
        get_payload,
    );
    assert(get_code == wing::GrpcStatusCode.Unimplemented);
    assert(get_payload.len == 0);

    print("BUG3_CONNECT_END_STREAM_SMUGGLING: OK");
}

// Bug 4: HPACK non-transactional out-buffer writes on bounded overflow & hpack_decode_int cursor rollback.
fn test_bug4_hpack_transactional_bounds() {
    var tiny_int_buf: u8[..2] = [0xAA];
    assert(!h2_internal::hpack_encode_int(tiny_int_buf, 300, 5, 0x00));
    assert(tiny_int_buf.len == 1);

    var tiny_huff_buf: u8[..4] = [0xBB];
    assert(!h2_internal::huff_encode_bytes("www.example.com", tiny_huff_buf));
    assert(tiny_huff_buf.len == 1);

    var tiny_str_buf: u8[..6] = [0xCC];
    assert(!h2_internal::encode_hpack_string_literal(tiny_str_buf, "www.example.com", true));
    assert(tiny_str_buf.len == 1);

    var tiny_raw_buf: u8[..4] = [0xDD];
    assert(!h2_internal::encode_hpack_string_literal(tiny_raw_buf, "abcdef", false));
    assert(tiny_raw_buf.len == 1);

    var dt = h2_internal::new_dynamic_table(4096);
    var bad_h2_blk: u8[..16] = [0x82, 0x86, 0x84, 0x00, 0x05, 'x', '-', 'b'];
    var h2_pseudo = h2_internal::H2PseudoHeaders {};
    var h2_headers = wing::HeaderMap {};
    let h2_dec_err = h2_internal::decode_hpack_to_map(dt, bad_h2_blk[..], h2_pseudo, h2_headers, 8192, true);
    assert(h2_dec_err == rfc::H2_ERR_COMPRESSION_ERROR);
    assert(!h2_pseudo.has_method && !h2_pseudo.has_scheme && !h2_pseudo.has_path && h2_headers.entries.len == 0);

    print("BUG4_HPACK_TRANSACTIONAL_BOUNDS: OK");
}

fn main() {
    test_bug1_h3_push_promise_and_qpack();
    test_bug2_h2_goaway_and_transactional_frames();
    test_bug3_connect_end_stream_smuggling();
    test_bug4_hpack_transactional_bounds();
}

// CHECK: BUG1_H3_PUSH_PROMISE_AND_QPACK: OK
// CHECK: BUG2_H2_GOAWAY_AND_FRAMES: OK
// CHECK: BUG3_CONNECT_END_STREAM_SMUGGLING: OK
// CHECK: BUG4_HPACK_TRANSACTIONAL_BOUNDS: OK
