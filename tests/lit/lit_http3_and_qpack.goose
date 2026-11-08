// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Consolidated Goose LIT Verification Suite: lit_http3_and_qpack
// RUN: goose build -O2 -o %t.exe %s
// RUN: %t.exe | %FileCheck %s

import std;
import core from "../..";
import wing from "../..";
import wire_kit from ".";

// ============================================================================
// 1. rfc_repro_semantic_h3_connect_pseudo (1/6)
// ============================================================================
// CHECK: === [1/6] rfc_repro_semantic_h3_connect_pseudo ===

// tests/lit/rfc_repro_semantic_h3_connect_pseudo.goose
// Verification of RFC 9114 Section 4.3.1 and Section 4.4 CONNECT pseudo-header validation.
// RFC 9114 Section 4.3.1: Request Pseudo-Header Fields - All HTTP/3 requests MUST include exactly one value for the :method, :scheme, and :path pseudo-header fields, unless the request is a CONNECT request; see Section 4.4.
// RFC 9114 Section 4.4: The CONNECT Method - A CONNECT request MUST be constructed as follows: The :method pseudo-header field is set to "CONNECT", the :scheme and :path pseudo-header fields are omitted, the :authority pseudo-header field contains the host and port to connect to. A CONNECT request that does not conform to these restrictions is malformed.
//

fn run_01_rfc_repro_semantic_h3_connect_pseudo() {
    var settings = wing::H3Settings { .. };
    var conn = internal::new_h3_server_connection(settings);
    let s_idx, err_s = internal::get_or_create_bidi_stream(conn, 0);
    assert(err_s == rfc::H3_ERR_NO_ERROR);

    // 1. Valid RFC 9114 CONNECT: :method = CONNECT, :authority = host:port (omitted :scheme and :path)
    var valid_connect_fields: internal::HeaderField[>..] = [];
    var f1 = internal::HeaderField { .. };
    f1.name.append(":method");
    f1.value.append("CONNECT");
    valid_connect_fields.push(f1);

    var f2 = internal::HeaderField { .. };
    f2.name.append(":authority");
    f2.value.append("example.com:443");
    valid_connect_fields.push(f2);

    let err_valid = internal::validate_h3_headers(conn, s_idx, valid_connect_fields);
    print("VALID_CONNECT: ", err_valid == rfc::H3_ERR_NO_ERROR, "\n");

    // 2. Malformed RFC 9114 CONNECT: :scheme and :path must be omitted for CONNECT
    conn = internal::new_h3_server_connection(settings);
    let s_idx2, err_s2 = internal::get_or_create_bidi_stream(conn, 0);
    assert(err_s2 == rfc::H3_ERR_NO_ERROR);

    var malformed_connect_fields: internal::HeaderField[>..] = [];
    var m1 = internal::HeaderField { .. };
    m1.name.append(":method");
    m1.value.append("CONNECT");
    malformed_connect_fields.push(m1);

    var m2 = internal::HeaderField { .. };
    m2.name.append(":scheme");
    m2.value.append("https");
    malformed_connect_fields.push(m2);

    var m3 = internal::HeaderField { .. };
    m3.name.append(":path");
    m3.value.append("/");
    malformed_connect_fields.push(m3);

    var m4 = internal::HeaderField { .. };
    m4.name.append(":authority");
    m4.value.append("example.com:443");
    malformed_connect_fields.push(m4);

    let err_malformed = internal::validate_h3_headers(conn, s_idx2, malformed_connect_fields);
    print("MALFORMED_CONNECT_SCHEME_PATH: ", err_malformed == rfc::H3_ERR_GENERAL_PROTOCOL, "\n");

    // 3. Malformed RFC 9114 CONNECT: missing :authority
    conn = internal::new_h3_server_connection(settings);
    let s_idx3, err_s3 = internal::get_or_create_bidi_stream(conn, 0);
    assert(err_s3 == rfc::H3_ERR_NO_ERROR);

    var no_auth_fields: internal::HeaderField[>..] = [];
    var a1 = internal::HeaderField { .. };
    a1.name.append(":method");
    a1.value.append("CONNECT");
    no_auth_fields.push(a1);

    let err_no_auth = internal::validate_h3_headers(conn, s_idx3, no_auth_fields);
    print("MALFORMED_CONNECT_NO_AUTH: ", err_no_auth == rfc::H3_ERR_GENERAL_PROTOCOL, "\n");

    // 4. Standard valid GET request
    conn = internal::new_h3_server_connection(settings);
    let s_idx4, err_s4 = internal::get_or_create_bidi_stream(conn, 0);
    assert(err_s4 == rfc::H3_ERR_NO_ERROR);

    var get_fields: internal::HeaderField[>..] = [];
    var g1 = internal::HeaderField { .. };
    g1.name.append(":method");
    g1.value.append("GET");
    get_fields.push(g1);

    var g2 = internal::HeaderField { .. };
    g2.name.append(":scheme");
    g2.value.append("https");
    get_fields.push(g2);

    var g3 = internal::HeaderField { .. };
    g3.name.append(":path");
    g3.value.append("/");
    get_fields.push(g3);

    var g4 = internal::HeaderField { .. };
    g4.name.append(":authority");
    g4.value.append("example.com");
    get_fields.push(g4);

    let err_get = internal::validate_h3_headers(conn, s_idx4, get_fields);
    print("VALID_GET: ", err_get == rfc::H3_ERR_NO_ERROR, "\n");
}

// CHECK: VALID_CONNECT: true
// CHECK: MALFORMED_CONNECT_SCHEME_PATH: true
// CHECK: MALFORMED_CONNECT_NO_AUTH: true
// CHECK: VALID_GET: true

// ============================================================================
// 2. verify_h3_spec_invariants (2/6)
// ============================================================================
// CHECK: === [2/6] verify_h3_spec_invariants ===

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

fn test_control_stream_forbidden_frames_precedence(conn: internal::H3Connection&, settings: const wing::H3Settings&) {
    conn = internal::new_h3_server_connection(settings);

    // A. DATA frame sent on peer control stream before SETTINGS (RFC 9114 §6.2.1)
    // If the first frame is any other frame type, connection error H3_MISSING_SETTINGS (0x010A)
    var data_wire: u8[..64] = [];
    internal::quic_encode_varint(data_wire, rfc::H3_STREAM_CONTROL);
    assert(internal::encode_h3_data_frame(data_wire, "test"));
    let err_data = internal::handle_stream_data(conn, 2, false, data_wire[..], false);
    assert(err_data == rfc::H3_ERR_MISSING_SETTINGS);

    // B. HEADERS frame sent on peer control stream before SETTINGS (RFC 9114 §6.2.1)
    conn = internal::new_h3_server_connection(settings);
    var headers_wire: u8[..64] = [];
    internal::quic_encode_varint(headers_wire, rfc::H3_STREAM_CONTROL);
    assert(internal::encode_h3_headers_frame(headers_wire, "head"));
    let err_hdr = internal::handle_stream_data(conn, 2, false, headers_wire[..], false);
    assert(err_hdr == rfc::H3_ERR_MISSING_SETTINGS);

    // C. HTTP/2 reserved frame (0x02 PRIORITY) sent on control stream before SETTINGS (RFC 9114 §6.2.1)
    conn = internal::new_h3_server_connection(settings);
    var h2_wire: u8[..64] = [];
    internal::quic_encode_varint(h2_wire, rfc::H3_STREAM_CONTROL);
    assert(internal::encode_h3_frame_header(h2_wire, 0x02, 0));
    let err_h2 = internal::handle_stream_data(conn, 2, false, h2_wire[..], false);
    assert(err_h2 == rfc::H3_ERR_MISSING_SETTINGS);

    // D. GOAWAY frame (allowed on control stream) sent before SETTINGS -> H3_ERR_MISSING_SETTINGS (RFC 9114 §6.2.1)
    conn = internal::new_h3_server_connection(settings);
    var ga_wire: u8[..64] = [];
    internal::quic_encode_varint(ga_wire, rfc::H3_STREAM_CONTROL);
    assert(internal::encode_h3_goaway_frame(ga_wire, 0));
    let err_ga = internal::handle_stream_data(conn, 2, false, ga_wire[..], false);
    assert(err_ga == rfc::H3_ERR_MISSING_SETTINGS);

    // E. DATA frame sent on peer control stream after SETTINGS -> H3_ERR_FRAME_UNEXPECTED (RFC 9114 §7.2.1)
    conn = internal::new_h3_server_connection(settings);
    var init_wire: u8[..64] = [];
    internal::quic_encode_varint(init_wire, rfc::H3_STREAM_CONTROL);
    assert(internal::encode_h3_settings_frame(init_wire, settings));
    let err_init = internal::handle_stream_data(conn, 2, false, init_wire[..], false);
    assert(err_init == rfc::H3_ERR_NO_ERROR);

    var post_data: u8[..64] = [];
    assert(internal::encode_h3_data_frame(post_data, "bad"));
    let err_post = internal::handle_stream_data(conn, 2, false, post_data[..], false);
    assert(err_post == rfc::H3_ERR_FRAME_UNEXPECTED);

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
    assert(err_grease == rfc::H3_ERR_SETTINGS_ERROR);

    // Duplicate unknown setting ID (e.g. 0x1F sent twice)
    var wire_unknown: u8[..64] = [];
    internal::quic_encode_varint(wire_unknown, 0x1F);
    internal::quic_encode_varint(wire_unknown, 1);
    internal::quic_encode_varint(wire_unknown, 0x1F); // Duplicate!
    internal::quic_encode_varint(wire_unknown, 2);
    let err_unknown = internal::parse_h3_settings_frame(wire_unknown[..], out_settings);
    assert(err_unknown == rfc::H3_ERR_SETTINGS_ERROR);

    // Valid distinct settings pass
    var wire_valid: u8[..64] = [];
    internal::quic_encode_varint(wire_valid, 0x21);
    internal::quic_encode_varint(wire_valid, 100);
    internal::quic_encode_varint(wire_valid, 0x40);
    internal::quic_encode_varint(wire_valid, 200);
    let err_valid = internal::parse_h3_settings_frame(wire_valid[..], out_settings);
    assert(err_valid == rfc::H3_ERR_NO_ERROR);

    print("DUPLICATE_SETTINGS_REJECTION: OK");
}

fn test_push_stream_validation(conn: internal::H3Connection&, settings: const wing::H3Settings&) {
    // 1. Server receives push stream from client -> H3_ERR_STREAM_CREATION (RFC 9114 §6.2.2)
    conn = internal::new_h3_server_connection(settings);
    var push_wire: u8[..64] = [];
    internal::quic_encode_varint(push_wire, rfc::H3_STREAM_PUSH);
    internal::quic_encode_varint(push_wire, 0);
    let s_err = internal::handle_stream_data(conn, 2, false, push_wire[..], false);
    assert(s_err == rfc::H3_ERR_STREAM_CREATION);
    assert(conn.state == internal::H3ConnState.Closed);

    // 2. Client receives push stream without having sent MAX_PUSH_ID -> H3_ERR_ID_ERROR (RFC 9114 §4.6)
    conn = internal::new_h3_client_connection(settings);
    push_wire.clear();
    internal::quic_encode_varint(push_wire, rfc::H3_STREAM_PUSH);
    internal::quic_encode_varint(push_wire, 0);
    let c_err = internal::handle_stream_data(conn, 3, false, push_wire[..], false);
    assert(c_err == rfc::H3_ERR_ID_ERROR);
    assert(conn.state == internal::H3ConnState.Closed);

    // 3. Client receives push stream with push_id > max_push_id_advertised -> H3_ERR_ID_ERROR
    conn = internal::new_h3_client_connection(settings);
    var dummy_out: u8[..64] = [];
    assert(internal::send_max_push_id(conn, 5, dummy_out));
    push_wire.clear();
    internal::quic_encode_varint(push_wire, rfc::H3_STREAM_PUSH);
    internal::quic_encode_varint(push_wire, 6);
    let c_err_excess = internal::handle_stream_data(conn, 3, false, push_wire[..], false);
    assert(c_err_excess == rfc::H3_ERR_ID_ERROR);

    // 4. Client receives push stream with push_id <= max_push_id_advertised -> H3_ERR_NO_ERROR
    conn = internal::new_h3_client_connection(settings);
    dummy_out.clear();
    assert(internal::send_max_push_id(conn, 5, dummy_out));
    push_wire.clear();
    internal::quic_encode_varint(push_wire, rfc::H3_STREAM_PUSH);
    internal::quic_encode_varint(push_wire, 4);
    let c_err_ok = internal::handle_stream_data(conn, 3, false, push_wire[..], false);
    assert(c_err_ok == rfc::H3_ERR_NO_ERROR);

    print("PUSH_STREAM_VALIDATION: OK");
}

fn test_server_initiated_bidi_stream_rejection(conn: internal::H3Connection&, settings: const wing::H3Settings&) {
    conn = internal::new_h3_client_connection(settings);
    let err_bidi = internal::handle_stream_data(conn, 1, true, "test", false);
    assert(err_bidi == rfc::H3_ERR_STREAM_CREATION);
    assert(conn.state == internal::H3ConnState.Closed);

    print("SERVER_INITIATED_BIDI_REJECTION: OK");
}

fn test_initial_dynamic_table_capacity_zero(conn: internal::H3Connection&) {
    let settings = wing::H3Settings { qpack_max_table_capacity: 4096, .. };
    conn = internal::new_h3_client_connection(settings);
    assert(conn.qpack_table.capacity_bytes == 0);

    var enc_stream_data: u8[..64] = [];
    internal::quic_encode_varint(enc_stream_data, rfc::H3_STREAM_QPACK_ENCODER);
    enc_stream_data.push(0x44); // 0100 0100 (Insert literal name len 4)
    enc_stream_data.append("test");
    enc_stream_data.push(0x03); // Val len 3
    enc_stream_data.append("val");

    let err = internal::handle_stream_data(conn, 3, false, enc_stream_data[..], false);
    assert(err == rfc::H3_ERR_QPACK_ENCODER_STREAM_ERROR);
    assert(conn.state == internal::H3ConnState.Closed);

    // Now test with Set Dynamic Table Capacity instruction first
    conn = internal::new_h3_client_connection(settings);
    var enc_stream_valid: u8[..64] = [];
    internal::quic_encode_varint(enc_stream_valid, rfc::H3_STREAM_QPACK_ENCODER);
    enc_stream_valid.push(0x3F); // 0x20 | 0x1F
    enc_stream_valid.push(0xE1); // Capacity 4096
    enc_stream_valid.push(0x1F);
    enc_stream_valid.push(0x44); // Insert literal name len 4
    enc_stream_valid.append("test");
    enc_stream_valid.push(0x03); // Val len 3
    enc_stream_valid.append("val");

    let err2 = internal::handle_stream_data(conn, 3, false, enc_stream_valid[..], false);
    assert(err2 == rfc::H3_ERR_NO_ERROR);
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

fn run_02_verify_h3_spec_invariants() {
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

// ============================================================================
// 3. verify_http3_framing (3/6)
// ============================================================================
// CHECK: === [3/6] verify_http3_framing ===

// tests/lit/verify_http3_framing.goose
// Verification of RFC 9114 HTTP/3 frame header encoding/decoding,
// GREASE identification, HTTP/2 reserved frame prohibitions,
// control vs request stream rules, and SETTINGS frame invariants.
//

// Wire bridge to HTTP/3 frame decoder
fn decode_h3_frame_wire(buf: const u8[:]) -> i64 {
    let hdr, ok = internal::parse_h3_frame_header(buf, 0);
    if !ok { return -1; }
    let total = (hdr.header_len as! i64) + (hdr.payload_len as! i64);
    if buf.len < total { return -1; }
    return hdr.payload_len as! i64;
}

fn test_h3_frame_headers() {
    var data_pkt: u8[>..] = [];
    // DATA frame (0x00) with 8 bytes payload: "HELLO123"
    // VarInt type 0 = 0x00, VarInt len 8 = 0x08, Payload = "HELLO123"
    assert(wire_kit::parse_hex("000848454C4C4F313233", data_pkt));

    let hdr, ok = internal::parse_h3_frame_header(data_pkt[..], 0);
    assert(ok);
    assert(hdr.frame_type == rfc::H3_FRAME_DATA);
    assert(hdr.payload_len == 8);
    assert(hdr.header_len == 2);

    assert(wire_kit::verify_split_stream(data_pkt[..], -1, 8, decode_h3_frame_wire));
    assert(wire_kit::fuzz_payload(data_pkt[..], 100, decode_h3_frame_wire));
    print("H3_FRAME_HEADER: OK");
}

fn test_h3_grease_and_h2_reserved() {
    // RFC 9114 Section 7.2.8: 0x1f * N + 0x21 are GREASE frames
    assert(rfc::is_h3_grease_frame(0x21));
    assert(rfc::is_h3_grease_frame(0x40));
    assert(rfc::is_h3_grease_frame(0x5F));
    assert(!rfc::is_h3_grease_frame(0x00));
    assert(!rfc::is_h3_grease_frame(0x04));

    // RFC 9114 Section 7.2.8: Reserved HTTP/2 frames trigger H3_FRAME_UNEXPECTED
    assert(rfc::is_h2_reserved_frame_in_h3(0x02)); // PRIORITY
    assert(rfc::is_h2_reserved_frame_in_h3(0x06)); // PING
    assert(rfc::is_h2_reserved_frame_in_h3(0x08)); // WINDOW_UPDATE
    assert(rfc::is_h2_reserved_frame_in_h3(0x09)); // CONTINUATION
    assert(!rfc::is_h2_reserved_frame_in_h3(0x00)); // DATA is H3
    assert(!rfc::is_h2_reserved_frame_in_h3(0x01)); // HEADERS is H3

    // Stream allowed rules
    assert(rfc::is_allowed_on_control_stream(rfc::H3_FRAME_SETTINGS));
    assert(rfc::is_allowed_on_control_stream(rfc::H3_FRAME_GOAWAY));
    assert(rfc::is_allowed_on_control_stream(0x21)); // GREASE allowed on control
    assert(!rfc::is_allowed_on_control_stream(rfc::H3_FRAME_DATA));
    assert(!rfc::is_allowed_on_control_stream(rfc::H3_FRAME_HEADERS));

    assert(rfc::is_allowed_on_request_stream(rfc::H3_FRAME_DATA));
    assert(rfc::is_allowed_on_request_stream(rfc::H3_FRAME_HEADERS));
    assert(!rfc::is_allowed_on_request_stream(rfc::H3_FRAME_SETTINGS));
    assert(!rfc::is_allowed_on_request_stream(rfc::H3_FRAME_GOAWAY));
    print("H3_RULES_AND_GREASE: OK");
}

fn test_h3_settings_frame() {
    var settings = wing::H3Settings {
        qpack_max_table_capacity: 4096,
        max_field_section_size:   16384,
        qpack_blocked_streams:    16,
        enable_connect_protocol:  1,
    };
    var wire_out: u8[..128] = [];
    assert(internal::encode_h3_settings_frame(wire_out, settings));

    // First decode frame header
    let hdr, ok_hdr = internal::parse_h3_frame_header(wire_out[..], 0);
    assert(ok_hdr);
    assert(hdr.frame_type == rfc::H3_FRAME_SETTINGS);

    // Parse settings payload
    let payload = wire_out[hdr.header_len..];
    var parsed_settings = wing::H3Settings { .. };
    let err = internal::parse_h3_settings_frame(payload, parsed_settings);
    assert(err == rfc::H3_ERR_NO_ERROR);
    assert(parsed_settings.qpack_max_table_capacity == 4096);
    assert(parsed_settings.max_field_section_size == 16384);
    assert(parsed_settings.qpack_blocked_streams == 16);
    assert(parsed_settings.enable_connect_protocol == 1);

    // Test rejection of forbidden HTTP/2 settings (e.g. 0x02 = SETTINGS_ENABLE_PUSH)
    var bad_h2_setting: u8[..32] = [];
    internal::quic_encode_varint(bad_h2_setting, 0x02);
    internal::quic_encode_varint(bad_h2_setting, 0);
    var bad_settings = wing::H3Settings { .. };
    let err_h2 = internal::parse_h3_settings_frame(bad_h2_setting[..], bad_settings);
    assert(err_h2 == rfc::H3_ERR_SETTINGS_ERROR);

    // Test rejection of duplicate settings
    var dup_setting: u8[..32] = [];
    internal::quic_encode_varint(dup_setting, rfc::H3_SETTING_QPACK_MAX_TABLE_CAPACITY);
    internal::quic_encode_varint(dup_setting, 1024);
    internal::quic_encode_varint(dup_setting, rfc::H3_SETTING_QPACK_MAX_TABLE_CAPACITY);
    internal::quic_encode_varint(dup_setting, 2048);
    let err_dup = internal::parse_h3_settings_frame(dup_setting[..], bad_settings);
    assert(err_dup == rfc::H3_ERR_SETTINGS_ERROR);

    print("H3_SETTINGS_CONFORMANCE: OK");
}

fn test_h3_control_frames_roundtrip() {
    // 1. GOAWAY
    var goaway_buf: u8[..32] = [];
    assert(internal::encode_h3_goaway_frame(goaway_buf, 42));
    let gw_hdr, gw_ok = internal::parse_h3_frame_header(goaway_buf[..], 0);
    assert(gw_ok);
    assert(gw_hdr.frame_type == rfc::H3_FRAME_GOAWAY);
    let gw_id, gw_parsed = internal::parse_h3_goaway_frame(goaway_buf[gw_hdr.header_len..]);
    assert(gw_parsed);
    assert(gw_id == 42);

    // 2. CANCEL_PUSH
    var cancel_buf: u8[..32] = [];
    assert(internal::encode_h3_cancel_push(cancel_buf, 7));
    let cp_hdr, cp_ok = internal::parse_h3_frame_header(cancel_buf[..], 0);
    assert(cp_ok);
    assert(cp_hdr.frame_type == rfc::H3_FRAME_CANCEL_PUSH);
    let cp_id, cp_parsed = internal::parse_h3_cancel_push(cancel_buf[cp_hdr.header_len..]);
    assert(cp_parsed);
    assert(cp_id == 7);

    // 3. MAX_PUSH_ID
    var max_buf: u8[..32] = [];
    assert(internal::encode_h3_max_push_id(max_buf, 99));
    let mp_hdr, mp_ok = internal::parse_h3_frame_header(max_buf[..], 0);
    assert(mp_ok);
    assert(mp_hdr.frame_type == rfc::H3_FRAME_MAX_PUSH_ID);
    let mp_id, mp_parsed = internal::parse_h3_max_push_id(max_buf[mp_hdr.header_len..]);
    assert(mp_parsed);
    assert(mp_id == 99);

    print("H3_CONTROL_FRAMES: OK");
}

fn test_quich3_origin_frame_and_coalescing() {
    let origins: (const u8[:])[2] = ["https://example.com", "https://api.example.com:8443"];
    var wire: u8[..128] = [];
    assert(internal::encode_h3_origin_frame(wire, origins[..]));

    let hdr, ok_hdr = internal::parse_h3_frame_header(wire[..], 0);
    assert(ok_hdr);
    assert(hdr.frame_type == internal::H3_FRAME_ORIGIN);

    var parsed: u8[..128][..16] = [];
    assert(internal::parse_h3_origin_frame(wire[hdr.header_len..], parsed));
    assert(parsed.len == 2);
    assert(parsed[0][..] == "https://example.com");
    assert(parsed[1][..] == "https://api.example.com:8443");

    // Reject zero-length origin entry and truncated length
    let zero_entry: u8[2] = [0x00, 0x00];
    var bad_out: u8[..128][..16] = [];
    assert(!internal::parse_h3_origin_frame(zero_entry[..], bad_out));
    let trunc_entry: u8[3] = [0x00, 0x05, 'a'];
    assert(!internal::parse_h3_origin_frame(trunc_entry[..], bad_out));

    // Client control stream stores peer_origins; Server ignores ORIGIN frame
    let settings = wing::H3Settings { .. };
    var cli_conn = internal::new_h3_client_connection(settings);
    var ctrl_wire: u8[..256] = [];
    internal::quic_encode_varint(ctrl_wire, rfc::H3_STREAM_CONTROL);
    internal::encode_h3_settings_frame(ctrl_wire, settings);
    ctrl_wire.append(wire[..]);
    assert(internal::handle_stream_data(cli_conn, 3, false, ctrl_wire[..], false) == rfc::H3_ERR_NO_ERROR);
    assert(cli_conn.peer_origins.len == 2);
    assert(cli_conn.peer_origins[0][..] == "https://example.com");

    var srv_conn = internal::new_h3_server_connection(settings);
    assert(internal::handle_stream_data(srv_conn, 2, false, ctrl_wire[..], false) == rfc::H3_ERR_NO_ERROR);
    assert(srv_conn.peer_origins.len == 0);
    print("H3_ORIGIN_FRAME: OK");
}

fn test_quich3_priority_scheduler() {
    let settings = wing::H3Settings { .. };
    var conn = internal::new_h3_client_connection(settings);
    let sid0, _ = internal::open_request_stream(conn);
    let sid4, _ = internal::open_request_stream(conn);
    let sid8, _ = internal::open_request_stream(conn);

    conn.streams[0].tx_pending_bytes = 512;
    conn.streams[0].priority = wing::PriorityParam { urgency: 4, incremental: false };
    conn.streams[1].tx_pending_bytes = 512;
    conn.streams[1].priority = wing::PriorityParam { urgency: 1, incremental: true };
    conn.streams[2].tx_pending_bytes = 512;
    conn.streams[2].priority = wing::PriorityParam { urgency: 1, incremental: true };

    let next1, ok1 = internal::select_next_h3_tx_stream(conn);
    assert(ok1 && next1 == sid4);
    let next2, ok2 = internal::select_next_h3_tx_stream(conn);
    assert(ok2 && next2 == sid8);
    let next3, ok3 = internal::select_next_h3_tx_stream(conn);
    assert(ok3 && next3 == sid4);

    conn.streams[1].tx_pending_bytes = 0;
    conn.streams[2].tx_pending_bytes = 0;
    let next4, ok4 = internal::select_next_h3_tx_stream(conn);
    assert(ok4 && next4 == sid0);
    print("H3_PRIORITY_SCHEDULER: OK");
}

fn test_quich3_webtransport_settings_and_glitch() {
    let wt_set = wing::H3Settings {
        qpack_max_table_capacity:  4096,
        max_field_section_size:    16384,
        qpack_blocked_streams:     16,
        enable_connect_protocol:   1,
        h3_datagram:               1,
        enable_webtransport:       1,
        webtransport_max_sessions: 8,
    };
    var out_buf: u8[..128] = [];
    assert(internal::encode_h3_settings_frame(out_buf, wt_set));
    let hdr, ok_hdr = internal::parse_h3_frame_header(out_buf[..], 0);
    assert(ok_hdr);
    var parsed = wing::H3Settings { .. };
    assert(internal::parse_h3_settings_frame(out_buf[hdr.header_len..], parsed) == rfc::H3_ERR_NO_ERROR);
    assert(parsed.h3_datagram == 1 && parsed.enable_webtransport == 1 && parsed.webtransport_max_sessions == 8);

    // Reject boolean setting > 1 and oversized SETTINGS > 256B
    var bad_bool: u8[..16] = [];
    internal::quic_encode_varint(bad_bool, internal::H3_SETTINGS_H3_DATAGRAM);
    internal::quic_encode_varint(bad_bool, 2);
    assert(internal::parse_h3_settings_frame(bad_bool[..], parsed) == rfc::H3_ERR_SETTINGS_ERROR);

    var huge_set: u8[300] = [0; 300];
    assert(internal::parse_h3_settings_frame(huge_set[..], parsed) == rfc::H3_ERR_EXCESSIVE_LOAD);

    // WebTransport connect request validation & control glitch limiter
    var wt_req = wing::Request { .. };
    wing::format_webtransport_connect_request(wt_req, "https://wt.example.com/session");
    assert(wing::is_webtransport_connect_request(wt_req));
    wing::format_webtransport_connect_request(wt_req, "http://wt.example.com/session");
    assert(!wing::is_webtransport_connect_request(wt_req));

    var conn = internal::new_h3_client_connection(wt_set);
    conn.max_control_glitches = 2;
    var ctrl: u8[..128] = [];
    internal::quic_encode_varint(ctrl, rfc::H3_STREAM_CONTROL);
    internal::encode_h3_settings_frame(ctrl, wt_set);
    for _ in 3 {
        internal::encode_h3_frame_header(ctrl, 0x21, 0);
    }
    assert(internal::handle_stream_data(conn, 3, false, ctrl[..], false) == rfc::H3_ERR_EXCESSIVE_LOAD);
    print("H3_WT_SETTINGS_AND_GLITCH: OK");
}

fn run_03_verify_http3_framing() {
    test_h3_frame_headers();
    test_h3_grease_and_h2_reserved();
    test_h3_settings_frame();
    test_h3_control_frames_roundtrip();
    test_quich3_origin_frame_and_coalescing();
    test_quich3_priority_scheduler();
    test_quich3_webtransport_settings_and_glitch();
    print("HTTP3_FRAMING: ALL INVARIANTS PASS");
}

// CHECK: H3_FRAME_HEADER: OK
// CHECK: H3_RULES_AND_GREASE: OK
// CHECK: H3_SETTINGS_CONFORMANCE: OK
// CHECK: H3_CONTROL_FRAMES: OK
// CHECK: H3_ORIGIN_FRAME: OK
// CHECK: H3_PRIORITY_SCHEDULER: OK
// CHECK: H3_WT_SETTINGS_AND_GLITCH: OK
// CHECK: HTTP3_FRAMING: ALL INVARIANTS PASS

// ============================================================================
// 4. verify_http3_regressions (4/6)
// ============================================================================
// CHECK: === [4/6] verify_http3_regressions ===

// tests/lit/verify_http3_regressions.goose
// Regression tests for confirmed HTTP/3 and QPACK bugs:
// 1. Server rejects requests missing both :authority and Host (RFC 9114 §4.3.1).
// 2. QPACK never_index flag correctly marks newly appended duplicate header (Security).
// 3. QPACK dynamic insert failure does not mutate tbl and does not drop header (RFC 9204 §4.3).
// 4. Server rejects GOAWAY with invalid stream ID (RFC 9114 §7.2.6).
// 5. Client rejects incoming frames on unopened client bidi streams (RFC 9114 §6.1).
//

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

fn run_04_verify_http3_regressions() {
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

// ============================================================================
// 5. verify_qpack_blocked_streams (5/6)
// ============================================================================
// CHECK: === [5/6] verify_qpack_blocked_streams ===

// tests/lit/verify_qpack_blocked_streams.goose
// Verification of QPACK Blocked Streams and Dynamic Table Synchronization (RFC 9204 §2.1.2).
// Tests SETTINGS_QPACK_BLOCKED_STREAMS bounds enforcement, stream queueing,
// required insert count (RIC) resolution, and stream unblocking.
//

fn test_qpack_blocking_limit() {
    // Create QpackTable with max_capacity = 4096 and max_blocked = 2
    var tbl = internal::new_qpack_table(4096, 2);
    assert(internal::qpack_can_block_stream(tbl));
    print("CAN_BLOCK_INIT: true");

    // Block stream 4 waiting for RIC 5
    let payload4: const u8[:] = "req4_wire";
    let ok1 = internal::qpack_block_stream(tbl, 4, 5, payload4);
    assert(ok1);
    assert(internal::qpack_is_stream_blocked(tbl, 4));
    print("STREAM_4_BLOCKED: true");

    // Block stream 8 waiting for RIC 6
    let payload8: const u8[:] = "req8_wire";
    let ok2 = internal::qpack_block_stream(tbl, 8, 6, payload8);
    assert(ok2);
    assert(internal::qpack_is_stream_blocked(tbl, 8));
    print("STREAM_8_BLOCKED: true");

    // Table now has 2 blocked streams == max_blocked (2)
    // Next attempt to block stream 12 MUST be rejected per RFC 9204 §2.1.2
    assert(!internal::qpack_can_block_stream(tbl));
    let payload12: const u8[:] = "req12_wire";
    let ok3 = internal::qpack_block_stream(tbl, 12, 7, payload12);
    assert(!ok3);
    print("STREAM_12_EXHAUSTED_REJECTED: true");
}

fn test_qpack_unblocking_progression() {
    var tbl = internal::new_qpack_table(4096, 4);

    let payload: const u8[:] = "data";
    assert(internal::qpack_block_stream(tbl, 100, 1, payload));
    assert(internal::qpack_block_stream(tbl, 101, 2, payload));
    assert(tbl.blocked_streams.len == 2);
    print("BLOCKED_COUNT_INIT: 2");

    // Unblock stream 100
    let unblocked100 = internal::qpack_unblock_stream(tbl, 100);
    assert(unblocked100);
    assert(!internal::qpack_is_stream_blocked(tbl, 100));
    assert(internal::qpack_is_stream_blocked(tbl, 101));
    assert(tbl.blocked_streams.len == 1);
    print("STREAM_100_UNBLOCKED: true");

    // Unblocking an unblocked or unknown stream returns false
    let unblocked_again = internal::qpack_unblock_stream(tbl, 100);
    assert(!unblocked_again);
    print("STREAM_100_DOUBLE_UNBLOCK_REJECTED: true");

    // Unblock stream 101
    let unblocked101 = internal::qpack_unblock_stream(tbl, 101);
    assert(unblocked101);
    assert(tbl.blocked_streams.len == 0);
    print("ALL_STREAMS_UNBLOCKED: true");
}

fn run_05_verify_qpack_blocked_streams() {
    print("=== RUNNING QPACK BLOCKED STREAMS SUITE ===");
    test_qpack_blocking_limit();
    test_qpack_unblocking_progression();
    print("QPACK BLOCKED STREAMS COMPLETE: ALL INVARIANTS PASSED");
}

// CHECK: === RUNNING QPACK BLOCKED STREAMS SUITE ===
// CHECK: CAN_BLOCK_INIT: true
// CHECK: STREAM_4_BLOCKED: true
// CHECK: STREAM_8_BLOCKED: true
// CHECK: STREAM_12_EXHAUSTED_REJECTED: true
// CHECK: BLOCKED_COUNT_INIT: 2
// CHECK: STREAM_100_UNBLOCKED: true
// CHECK: STREAM_100_DOUBLE_UNBLOCK_REJECTED: true
// CHECK: ALL_STREAMS_UNBLOCKED: true
// CHECK: QPACK BLOCKED STREAMS COMPLETE: ALL INVARIANTS PASSED

// ============================================================================
// 6. verify_zstd_and_quic_edge (6/6)
// ============================================================================
// CHECK: === [6/6] verify_zstd_and_quic_edge ===

// tests/lit/verify_zstd_and_quic_edge.goose
// Verification of RFC 8878 Zstandard 4-stream literals partition invariants,
// RFC 9000 §17.2.1 Version Negotiation payload boundaries, and QUIC ACK frame offset chaining.
//

fn test_zstd_4stream_partition() {
    // RFC 8878 §3.1.1.3.1.2: 4 Streams Regenerated Size Partition Invariant
    // Stream 1: (N + 3) / 4
    // Stream 2: (N + 2) / 4
    // Stream 3: (N + 1) / 4
    // Stream 4: N / 4
    // Sum MUST equal N for all N >= 6.
    let test_sizes: const i64[10] = [6, 7, 8, 9, 10, 11, 12, 100, 1023, 65536];
    var all_sums_match = true;

    for n in test_sizes {
        let sz1 = (n + 3) / 4;
        let sz2 = (n + 2) / 4;
        let sz3 = (n + 1) / 4;
        let sz4 = n / 4;
        let sum = sz1 + sz2 + sz3 + sz4;
        if sum != n {
            all_sums_match = false;
        }
    }
    print("ZSTD_4STREAM_PARTITION_SUM: ", if all_sums_match { "OK" } else { "FAIL" });

    // Specific boundary checks for N = 6 (minimum 4-stream regenerated size)
    let n6 = 6;
    let n6_s1 = (n6 + 3) / 4; // 2
    let n6_s2 = (n6 + 2) / 4; // 2
    let n6_s3 = (n6 + 1) / 4; // 1
    let n6_s4 = n6 / 4;       // 1
    assert(n6_s1 == 2 && n6_s2 == 2 && n6_s3 == 1 && n6_s4 == 1);
    print("ZSTD_4STREAM_N6_SIZES: s1=", n6_s1, " s2=", n6_s2, " s3=", n6_s3, " s4=", n6_s4);

    // Specific boundary checks for N = 10
    let n10 = 10;
    let n10_s1 = (n10 + 3) / 4; // 3
    let n10_s2 = (n10 + 2) / 4; // 3
    let n10_s3 = (n10 + 1) / 4; // 2
    let n10_s4 = n10 / 4;       // 2
    assert(n10_s1 == 3 && n10_s2 == 3 && n10_s3 == 2 && n10_s4 == 2);
    print("ZSTD_4STREAM_N10_SIZES: s1=", n10_s1, " s2=", n10_s2, " s3=", n10_s3, " s4=", n10_s4);

    // Verify round-trip zstd compress/decompress with declared frame content size
    var raw_input: u8[>..] = [];
    raw_input.append("The quick brown fox jumps over the lazy dog. Zstandard RFC 8878 high-throughput framing verification.");
    var compressed: u8[>..] = [];
    let ok_comp = core::zstd_compress(raw_input[..], compressed);
    assert(ok_comp);

    var decompressed: u8[>..] = [];
    let ok_decomp, decomp_err = core::zstd_decompress(compressed[..], decompressed);
    assert(ok_decomp);
    assert(decomp_err == core::CompressError.None);
    assert(decompressed.len == raw_input.len);
    print("ZSTD_ROUNDTRIP_DECOMPRESS: OK, len=", decompressed.len);
}

fn test_quic_vn_boundaries() {
    // 1. Valid Version Negotiation with 1 version (4 bytes)
    var vn_1: u8[>..] = [];
    vn_1.push(0x80); // Long header (bit 7 = 1)
    core::append_u32_be(vn_1, rfc::QUIC_VERSION_NEGOTIATION); // Version 0x00000000
    vn_1.push(4); // DCID len
    vn_1.append("DCID");
    vn_1.push(4); // SCID len
    vn_1.append("SCID");
    core::append_u32_be(vn_1, rfc::QUIC_VERSION_1); // 1 Supported Version (4 bytes)

    let hdr_1, ok_vn_1 = internal::parse_quic_header(vn_1[..], 0);
    let type_str_1 = if hdr_1.header_type == internal::QuicHeaderType.VersionNegotiation { "VN" } else { "OTHER" };
    print("QUIC_VN_1_VER: ", if ok_vn_1 { "OK" } else { "FAIL" }, " type=", type_str_1);

    // 2. Valid Version Negotiation with 2 versions (8 bytes)
    var vn_2: u8[>..] = [];
    vn_2.push(0x80);
    core::append_u32_be(vn_2, rfc::QUIC_VERSION_NEGOTIATION);
    vn_2.push(4);
    vn_2.append("DCID");
    vn_2.push(4);
    vn_2.append("SCID");
    core::append_u32_be(vn_2, rfc::QUIC_VERSION_1);
    core::append_u32_be(vn_2, 0xFACEB00C); // Second version

    let hdr_2, ok_vn_2 = internal::parse_quic_header(vn_2[..], 0);
    let type_str_2 = if hdr_2.header_type == internal::QuicHeaderType.VersionNegotiation { "VN" } else { "OTHER" };
    print("QUIC_VN_2_VER: ", if ok_vn_2 { "OK" } else { "FAIL" }, " type=", type_str_2);

    // 3. Malformed Version Negotiation with 0 versions (RFC 9000 §17.2.1: MUST have >= 1 version)
    var vn_empty: u8[>..] = [];
    vn_empty.push(0x80);
    core::append_u32_be(vn_empty, rfc::QUIC_VERSION_NEGOTIATION);
    vn_empty.push(4);
    vn_empty.append("DCID");
    vn_empty.push(4);
    vn_empty.append("SCID");
    // No versions follow!

    let _, ok_vn_empty = internal::parse_quic_header(vn_empty[..], 0);
    print("QUIC_VN_EMPTY: ", if !ok_vn_empty { "REJECTED" } else { "ACCEPTED" });

    // 4. Malformed Version Negotiation with truncated 3-byte version
    var vn_trunc: u8[>..] = [];
    vn_trunc.push(0x80);
    core::append_u32_be(vn_trunc, rfc::QUIC_VERSION_NEGOTIATION);
    vn_trunc.push(4);
    vn_trunc.append("DCID");
    vn_trunc.push(4);
    vn_trunc.append("SCID");
    vn_trunc.append([0x00, 0x00, 0x01]); // 3 bytes (not a multiple of 4!)

    let _, ok_vn_trunc = internal::parse_quic_header(vn_trunc[..], 0);
    print("QUIC_VN_TRUNC: ", if !ok_vn_trunc { "REJECTED" } else { "ACCEPTED" });

    // 5. Malformed Version Negotiation with 5 bytes (1 version + 1 dangling byte)
    var vn_dangling: u8[>..] = [];
    vn_dangling.push(0x80);
    core::append_u32_be(vn_dangling, rfc::QUIC_VERSION_NEGOTIATION);
    vn_dangling.push(4);
    vn_dangling.append("DCID");
    vn_dangling.push(4);
    vn_dangling.append("SCID");
    core::append_u32_be(vn_dangling, rfc::QUIC_VERSION_1);
    vn_dangling.push(0xFF); // 1 extra byte

    let _, ok_vn_dangling = internal::parse_quic_header(vn_dangling[..], 0);
    print("QUIC_VN_DANGLING: ", if !ok_vn_dangling { "REJECTED" } else { "ACCEPTED" });
}

fn test_quic_ack_offset_chaining() {
    var ack1 = internal::AckFrame {
        is_ecn:          false,
        largest_acked:   200,
        ack_delay:       15,
        first_ack_range: 5,
        ..
    };
    var wire: u8[..64] = [];
    // Prefix wire with 3 padding bytes (PING or PADDING frames)
    wire.append([0x00, 0x00, 0x01]);

    let ok_enc = internal::encode_ack_frame(wire, ack1);
    assert(ok_enc);

    let prefix_off: u64 = 3;
    let dec_ack, next_off, ok_dec = internal::decode_ack_frame(wire[..], prefix_off);
    print("QUIC_ACK_CHAIN_DECODE: ", if ok_dec { "OK" } else { "FAIL" });
    assert(ok_dec);
    assert(dec_ack.largest_acked == 200);
    assert(dec_ack.first_ack_range == 5);
    assert(next_off == (wire.len as u64));
    print("QUIC_ACK_CHAIN_OFFSET: start=", prefix_off, " next=", next_off, " total=", wire.len);

    // Decoding beyond wire boundary returns original offset and false
    let _, err_off, ok_bad = internal::decode_ack_frame(wire[..], next_off + 1);
    print("QUIC_ACK_CHAIN_EOF: ", if !ok_bad && err_off == next_off + 1 { "OK" } else { "FAIL" });
}

fn run_06_verify_zstd_and_quic_edge() {
    test_zstd_4stream_partition();
    test_quic_vn_boundaries();
    test_quic_ack_offset_chaining();
}

// CHECK-DAG: ZSTD_4STREAM_PARTITION_SUM: OK
// CHECK-DAG: ZSTD_4STREAM_N6_SIZES: s1=2 s2=2 s3=1 s4=1
// CHECK-DAG: ZSTD_4STREAM_N10_SIZES: s1=3 s2=3 s3=2 s4=2
// CHECK-DAG: ZSTD_ROUNDTRIP_DECOMPRESS: OK, len=[[REG_SZ:[0-9]+]]
// CHECK-DAG: QUIC_VN_1_VER: OK type=VN
// CHECK-DAG: QUIC_VN_2_VER: OK type=VN
// CHECK-DAG: QUIC_VN_EMPTY: REJECTED
// CHECK-DAG: QUIC_VN_TRUNC: REJECTED
// CHECK-DAG: QUIC_VN_DANGLING: REJECTED
// CHECK-DAG: QUIC_ACK_CHAIN_DECODE: OK
// CHECK-DAG: QUIC_ACK_CHAIN_OFFSET: start=3 next=[[END_OFF:[0-9]+]] total=[[END_OFF]]
// CHECK-DAG: QUIC_ACK_CHAIN_EOF: OK

fn main() {
    print("\n=== [1/6] rfc_repro_semantic_h3_connect_pseudo ===\n");
    run_01_rfc_repro_semantic_h3_connect_pseudo();
    print("\n=== [2/6] verify_h3_spec_invariants ===\n");
    run_02_verify_h3_spec_invariants();
    print("\n=== [3/6] verify_http3_framing ===\n");
    run_03_verify_http3_framing();
    print("\n=== [4/6] verify_http3_regressions ===\n");
    run_04_verify_http3_regressions();
    print("\n=== [5/6] verify_qpack_blocked_streams ===\n");
    run_05_verify_qpack_blocked_streams();
    print("\n=== [6/6] verify_zstd_and_quic_edge ===\n");
    run_06_verify_zstd_and_quic_edge();
}
