// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// tests/lit/verify_h3_spec_invariants.goose
// Verification of RFC 9114 and RFC 9204 spec invariants:
// 1. Control stream forbidden frames precedence (RFC 9114 §7.2.1, §7.2.2, §7.2.8).
// 2. Duplicate setting identifier rejection (RFC 9114 §7.2.4).
// 3. Unidirectional push stream validation (RFC 9114 §6.2.2, §4.6).
// 4. Server-initiated bidirectional stream rejection (RFC 9114 §6.1).
// 5. Initial dynamic table capacity is zero (RFC 9204 §3.2.3).
// 6. Prefixed integer 62-bit boundary overflow on 9th byte (RFC 9204 §4.1.1).
// 7. Dynamic table index boundary against RIC in Case A and C (RFC 9204 §4.5.2, §4.5.4).
//
// RUN: goose build --cc gcc -O2 -o %t.exe %s
// RUN: %t.exe | %FileCheck %s

import std;
import core from "../..";
import wing from "../..";

fn test_control_stream_forbidden_frames_precedence(conn: internal::H3Connection&, settings: const wing::H3Settings&) {
    conn = internal::new_h3_server_connection(settings);

    // A. DATA frame sent on peer control stream before SETTINGS (RFC 9114 §6.2.1)
    // If the first frame is any other frame type, connection error H3_MISSING_SETTINGS (0x010A)
    var data_wire: u8[..64] = [];
    internal::quic_encode_varint(data_wire, internal::H3_STREAM_CONTROL);
    assert(internal::encode_h3_data_frame(data_wire, "test"));
    let err_data = internal::handle_stream_data(conn, 2, false, data_wire[..], false);
    assert(err_data == internal::H3_ERR_MISSING_SETTINGS);

    // B. HEADERS frame sent on peer control stream before SETTINGS (RFC 9114 §6.2.1)
    conn = internal::new_h3_server_connection(settings);
    var headers_wire: u8[..64] = [];
    internal::quic_encode_varint(headers_wire, internal::H3_STREAM_CONTROL);
    assert(internal::encode_h3_headers_frame(headers_wire, "head"));
    let err_hdr = internal::handle_stream_data(conn, 2, false, headers_wire[..], false);
    assert(err_hdr == internal::H3_ERR_MISSING_SETTINGS);

    // C. HTTP/2 reserved frame (0x02 PRIORITY) sent on control stream before SETTINGS (RFC 9114 §6.2.1)
    conn = internal::new_h3_server_connection(settings);
    var h2_wire: u8[..64] = [];
    internal::quic_encode_varint(h2_wire, internal::H3_STREAM_CONTROL);
    assert(internal::encode_h3_frame_header(h2_wire, 0x02, 0));
    let err_h2 = internal::handle_stream_data(conn, 2, false, h2_wire[..], false);
    assert(err_h2 == internal::H3_ERR_MISSING_SETTINGS);

    // D. GOAWAY frame (allowed on control stream) sent before SETTINGS -> H3_ERR_MISSING_SETTINGS (RFC 9114 §6.2.1)
    conn = internal::new_h3_server_connection(settings);
    var ga_wire: u8[..64] = [];
    internal::quic_encode_varint(ga_wire, internal::H3_STREAM_CONTROL);
    assert(internal::encode_h3_goaway_frame(ga_wire, 0));
    let err_ga = internal::handle_stream_data(conn, 2, false, ga_wire[..], false);
    assert(err_ga == internal::H3_ERR_MISSING_SETTINGS);

    // E. DATA frame sent on peer control stream after SETTINGS -> H3_ERR_FRAME_UNEXPECTED (RFC 9114 §7.2.1)
    conn = internal::new_h3_server_connection(settings);
    var init_wire: u8[..64] = [];
    internal::quic_encode_varint(init_wire, internal::H3_STREAM_CONTROL);
    assert(internal::encode_h3_settings_frame(init_wire, settings));
    let err_init = internal::handle_stream_data(conn, 2, false, init_wire[..], false);
    assert(err_init == internal::H3_ERR_NO_ERROR);

    var post_data: u8[..64] = [];
    assert(internal::encode_h3_data_frame(post_data, "bad"));
    let err_post = internal::handle_stream_data(conn, 2, false, post_data[..], false);
    assert(err_post == internal::H3_ERR_FRAME_UNEXPECTED);

    print("CONTROL_STREAM_FORBIDDEN_PRECEDENCE: OK");
}

fn test_duplicate_settings_rejection() {
    var out_settings = wing::H3Settings { .. };

    // Duplicate unknown/GREASE setting ID (e.g. 0x21 sent twice)
    var wire_grease: u8[..64] = [];
    internal::quic_encode_varint(wire_grease, 0x21);
    internal::quic_encode_varint(wire_grease, 100);
    internal::quic_encode_varint(wire_grease, 0x21); // Duplicate!
    internal::quic_encode_varint(wire_grease, 200);
    let err_grease = internal::parse_h3_settings_frame(wire_grease[..], out_settings);
    assert(err_grease == internal::H3_ERR_SETTINGS_ERROR);

    // Duplicate unknown setting ID (e.g. 0x1F sent twice)
    var wire_unknown: u8[..64] = [];
    internal::quic_encode_varint(wire_unknown, 0x1F);
    internal::quic_encode_varint(wire_unknown, 1);
    internal::quic_encode_varint(wire_unknown, 0x1F); // Duplicate!
    internal::quic_encode_varint(wire_unknown, 2);
    let err_unknown = internal::parse_h3_settings_frame(wire_unknown[..], out_settings);
    assert(err_unknown == internal::H3_ERR_SETTINGS_ERROR);

    // Valid distinct settings pass
    var wire_valid: u8[..64] = [];
    internal::quic_encode_varint(wire_valid, 0x21);
    internal::quic_encode_varint(wire_valid, 100);
    internal::quic_encode_varint(wire_valid, 0x40);
    internal::quic_encode_varint(wire_valid, 200);
    let err_valid = internal::parse_h3_settings_frame(wire_valid[..], out_settings);
    assert(err_valid == internal::H3_ERR_NO_ERROR);

    print("DUPLICATE_SETTINGS_REJECTION: OK");
}

fn test_push_stream_validation(conn: internal::H3Connection&, settings: const wing::H3Settings&) {
    // 1. Server receives push stream from client -> H3_ERR_STREAM_CREATION (RFC 9114 §6.2.2)
    conn = internal::new_h3_server_connection(settings);
    var push_wire: u8[..64] = [];
    internal::quic_encode_varint(push_wire, internal::H3_STREAM_PUSH);
    internal::quic_encode_varint(push_wire, 0);
    let s_err = internal::handle_stream_data(conn, 2, false, push_wire[..], false);
    assert(s_err == internal::H3_ERR_STREAM_CREATION);
    assert(conn.state == internal::H3ConnState.Closed);

    // 2. Client receives push stream without having sent MAX_PUSH_ID -> H3_ERR_ID_ERROR (RFC 9114 §4.6)
    conn = internal::new_h3_client_connection(settings);
    push_wire.clear();
    internal::quic_encode_varint(push_wire, internal::H3_STREAM_PUSH);
    internal::quic_encode_varint(push_wire, 0);
    let c_err = internal::handle_stream_data(conn, 3, false, push_wire[..], false);
    assert(c_err == internal::H3_ERR_ID_ERROR);
    assert(conn.state == internal::H3ConnState.Closed);

    // 3. Client receives push stream with push_id > max_push_id_advertised -> H3_ERR_ID_ERROR
    conn = internal::new_h3_client_connection(settings);
    var dummy_out: u8[..64] = [];
    assert(internal::send_max_push_id(conn, 5, dummy_out));
    push_wire.clear();
    internal::quic_encode_varint(push_wire, internal::H3_STREAM_PUSH);
    internal::quic_encode_varint(push_wire, 6);
    let c_err_excess = internal::handle_stream_data(conn, 3, false, push_wire[..], false);
    assert(c_err_excess == internal::H3_ERR_ID_ERROR);

    // 4. Client receives push stream with push_id <= max_push_id_advertised -> H3_ERR_NO_ERROR
    conn = internal::new_h3_client_connection(settings);
    dummy_out.clear();
    assert(internal::send_max_push_id(conn, 5, dummy_out));
    push_wire.clear();
    internal::quic_encode_varint(push_wire, internal::H3_STREAM_PUSH);
    internal::quic_encode_varint(push_wire, 4);
    let c_err_ok = internal::handle_stream_data(conn, 3, false, push_wire[..], false);
    assert(c_err_ok == internal::H3_ERR_NO_ERROR);

    print("PUSH_STREAM_VALIDATION: OK");
}

fn test_server_initiated_bidi_stream_rejection(conn: internal::H3Connection&, settings: const wing::H3Settings&) {
    conn = internal::new_h3_client_connection(settings);
    let err_bidi = internal::handle_stream_data(conn, 1, true, "test", false);
    assert(err_bidi == internal::H3_ERR_STREAM_CREATION);
    assert(conn.state == internal::H3ConnState.Closed);

    print("SERVER_INITIATED_BIDI_REJECTION: OK");
}

fn test_initial_dynamic_table_capacity_zero(conn: internal::H3Connection&) {
    let settings = wing::H3Settings { qpack_max_table_capacity: 4096, .. };
    conn = internal::new_h3_client_connection(settings);
    assert(conn.qpack_table.capacity_bytes == 0);

    var enc_stream_data: u8[..64] = [];
    internal::quic_encode_varint(enc_stream_data, internal::H3_STREAM_QPACK_ENCODER);
    enc_stream_data.push(0x44); // 0100 0100 (Insert literal name len 4)
    enc_stream_data.append("test");
    enc_stream_data.push(0x03); // Val len 3
    enc_stream_data.append("val");

    let err = internal::handle_stream_data(conn, 3, false, enc_stream_data[..], false);
    assert(err == internal::H3_ERR_QPACK_ENCODER_STREAM_ERROR);
    assert(conn.state == internal::H3ConnState.Closed);

    // Now test with Set Dynamic Table Capacity instruction first
    conn = internal::new_h3_client_connection(settings);
    var enc_stream_valid: u8[..64] = [];
    internal::quic_encode_varint(enc_stream_valid, internal::H3_STREAM_QPACK_ENCODER);
    enc_stream_valid.push(0x3F); // 0x20 | 0x1F
    enc_stream_valid.push(0xE1); // Capacity 4096
    enc_stream_valid.push(0x1F);
    enc_stream_valid.push(0x44); // Insert literal name len 4
    enc_stream_valid.append("test");
    enc_stream_valid.push(0x03); // Val len 3
    enc_stream_valid.append("val");

    let err2 = internal::handle_stream_data(conn, 3, false, enc_stream_valid[..], false);
    assert(err2 == internal::H3_ERR_NO_ERROR);
    assert(conn.qpack_table.insert_count == 1);

    print("INITIAL_DYNAMIC_TABLE_CAPACITY_ZERO: OK");
}

fn test_qpack_int_62bit_boundary() {
    // 9 continuation bytes where 9th continuation byte has continuation bit set (0x80)
    var buf_overflow: u8[..16] = [
        0xFF,
        0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80,
        0x80, // shift 56 with continuation bit set -> indicates byte 10 (> 62 bits)
        0x01,
    ];
    let val, next_off, ok = internal::qpack_decode_int(buf_overflow[..], 0, 8);
    assert(!ok);

    // Shift 56 with payload > 0x3F (e.g. 0x40)
    var buf_overflow2: u8[..16] = [
        0xFF,
        0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80,
        0x40,
    ];
    let val2, next_off2, ok2 = internal::qpack_decode_int(buf_overflow2[..], 0, 8);
    assert(!ok2);

    print("QPACK_INT_62BIT_BOUNDARY: OK");
}

fn test_qpack_ric_boundary_cases_a_and_c() {
    var tbl = internal::new_qpack_table(4096, 16);
    assert(internal::qpack_insert_literal(tbl, "x-key-0", "val-0")); // Abs idx 0
    assert(internal::qpack_insert_literal(tbl, "x-key-1", "val-1")); // Abs idx 1

    // Encoded section with:
    // Encoded RIC = 2 (decoded ric = 1)
    // Sign = 0, DeltaBase = 1 (Base = 1 + 1 = 2)
    // Case A: Index = 0 -> abs_idx = 2 - 0 - 1 = 1 == ric!
    // Must be rejected with DecompressionFailed (RFC 9204 §4.5.2)
    var wire_case_a: u8[..16] = [
        0x02, // Encoded RIC = 2 -> ric = 1
        0x01, // Sign=0, DeltaBase=1 -> Base = 2
        0x80, // Case A: 10xxxxxx, Index = 0 -> abs_idx = 1 == ric
    ];
    var fields_a: internal::HeaderField[>..] = [];
    let err_a = internal::decode_qpack_section(tbl, wire_case_a[..], fields_a, 8192);
    assert(err_a == internal::QpackError.DecompressionFailed);

    // Case C: Literal with dynamic name reference
    // Name Index = 0 -> abs_idx = 2 - 0 - 1 = 1 == ric!
    // Must be rejected with DecompressionFailed (RFC 9204 §4.5.4)
    var wire_case_c: u8[..16] = [
        0x02, // Encoded RIC = 2 -> ric = 1
        0x01, // Sign=0, DeltaBase=1 -> Base = 2
        0x40, // Case C: 01000000, name_idx = 0 -> abs_idx = 1 == ric
        0x03, // Value len 3
        'v', 'a', 'l',
    ];
    var fields_c: internal::HeaderField[>..] = [];
    let err_c = internal::decode_qpack_section(tbl, wire_case_c[..], fields_c, 8192);
    assert(err_c == internal::QpackError.DecompressionFailed);

    print("QPACK_RIC_BOUNDARY_CASES_A_AND_C: OK");
}

fn main() {
    let settings = wing::H3Settings { .. };
    var conn = internal::new_h3_server_connection(settings);

    test_control_stream_forbidden_frames_precedence(conn, settings);
    test_duplicate_settings_rejection();
    test_push_stream_validation(conn, settings);
    test_server_initiated_bidi_stream_rejection(conn, settings);
    test_initial_dynamic_table_capacity_zero(conn);
    test_qpack_int_62bit_boundary();
    test_qpack_ric_boundary_cases_a_and_c();
    print("ALL_H3_SPEC_INVARIANTS: PASS");
}

// CHECK: CONTROL_STREAM_FORBIDDEN_PRECEDENCE: OK
// CHECK: DUPLICATE_SETTINGS_REJECTION: OK
// CHECK: PUSH_STREAM_VALIDATION: OK
// CHECK: SERVER_INITIATED_BIDI_REJECTION: OK
// CHECK: INITIAL_DYNAMIC_TABLE_CAPACITY_ZERO: OK
// CHECK: QPACK_INT_62BIT_BOUNDARY: OK
// CHECK: QPACK_RIC_BOUNDARY_CASES_A_AND_C: OK
// CHECK: ALL_H3_SPEC_INVARIANTS: PASS
