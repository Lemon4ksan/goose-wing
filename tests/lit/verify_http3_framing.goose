// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// tests/lit/verify_http3_framing.goose
// Verification of RFC 9114 HTTP/3 frame header encoding/decoding,
// GREASE identification, HTTP/2 reserved frame prohibitions,
// control vs request stream rules, and SETTINGS frame invariants.
//
// RUN: goose build --cc gcc -O2 -o %t.exe %s
// RUN: %t.exe | %FileCheck %s

import std;
import core from "../..";
import wing from "../..";
import wire_kit from ".";

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

fn main() {
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
