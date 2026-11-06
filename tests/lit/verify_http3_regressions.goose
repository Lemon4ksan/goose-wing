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

fn main() {
    test_server_rejects_missing_authority_and_host();
    test_qpack_never_index_flag_on_duplicate_header_name();
    test_server_rejects_goaway_with_non_client_bidi_stream_id();
    test_qpack_dynamic_insert_transactional_failure();
    test_client_rejects_server_frames_on_unopened_bidi_stream();
    print("ALL_HTTP3_REGRESSIONS_PASS");
}

// CHECK: REGRESS_MISSING_AUTHORITY: OK
// CHECK: REGRESS_NEVER_INDEX_DUPLICATE: OK
// CHECK: REGRESS_GOAWAY_INVALID_ID: OK
// CHECK: REGRESS_QPACK_DYNAMIC_INSERT_TRANSACTIONAL: OK
// CHECK: REGRESS_CLIENT_UNOPENED_BIDI_REJECTED: OK
// CHECK: ALL_HTTP3_REGRESSIONS_PASS
