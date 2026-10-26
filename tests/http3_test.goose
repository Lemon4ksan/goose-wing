// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// tests/http3_test.goose
// Conformance and Security Defense Suite for HTTP/3 (RFC 9114) and QPACK (RFC 9204).
import std;
import core from "..";
import wing from "..";

// ============================================================================
// 1. Frame Header Encoding, Decoding & GREASE Conformance
// ============================================================================
fn test_h3_framing_and_grease(t: core::T&) {
    t.run("H3-01: Frame Header VarInt Encoding & Decoding") { sub =>
        var buf: u8[..64] = [];

        // DATA frame (0x00, len 100)
        sub.assert_true(wing::encode_h3_frame_header(buf, wing::H3_FRAME_DATA, 100), "encode DATA frame header");
        sub.assert_eq(buf.len, 3, "1-byte type + 2-byte len (100 <= 16383 takes 2 bytes)");

        let hdr, ok = wing::parse_h3_frame_header(buf[..], 0);
        sub.assert_true(ok, "parse DATA frame header");
        sub.assert_eq(hdr.frame_type, wing::H3_FRAME_DATA, "type is DATA");
        sub.assert_eq(hdr.payload_len, 100, "length is 100");
        sub.assert_eq(hdr.header_len, 3, "header length is 3 bytes");

        // Large frame (len 1000000)
        buf.clear();
        sub.assert_true(wing::encode_h3_frame_header(buf, wing::H3_FRAME_HEADERS, 1000000), "encode HEADERS frame header");
        let hdr_lg, ok_lg = wing::parse_h3_frame_header(buf[..], 0);
        sub.assert_true(ok_lg, "parse large HEADERS header");
        sub.assert_eq(hdr_lg.frame_type, wing::H3_FRAME_HEADERS, "type is HEADERS");
        sub.assert_eq(hdr_lg.payload_len, 1000000, "length is 1000000");
    };

    t.run("H3-02: GREASE Frame Identification & Stream Allowed Rules") { sub =>
        // RFC 9114 Section 7.2.8: 0x1f * N + 0x21
        // N=0: 0x21 (33)
        // N=1: 0x40 (64)
        // N=2: 0x5F (95)
        sub.assert_true(wing::is_h3_grease_frame(0x21), "0x21 is GREASE");
        sub.assert_true(wing::is_h3_grease_frame(0x40), "0x40 is GREASE");
        sub.assert_true(wing::is_h3_grease_frame(0x5F), "0x5F is GREASE");
        sub.assert_false(wing::is_h3_grease_frame(0x00), "DATA is not GREASE");
        sub.assert_false(wing::is_h3_grease_frame(0x04), "SETTINGS is not GREASE");

        // Control stream rules
        sub.assert_true(wing::is_allowed_on_control_stream(wing::H3_FRAME_SETTINGS), "SETTINGS allowed on Control");
        sub.assert_true(wing::is_allowed_on_control_stream(wing::H3_FRAME_GOAWAY), "GOAWAY allowed on Control");
        sub.assert_true(wing::is_allowed_on_control_stream(0x21), "GREASE allowed on Control");
        sub.assert_false(wing::is_allowed_on_control_stream(wing::H3_FRAME_DATA), "DATA strictly forbidden on Control");
        sub.assert_false(wing::is_allowed_on_control_stream(wing::H3_FRAME_HEADERS), "HEADERS strictly forbidden on Control");

        // Request stream rules
        sub.assert_true(wing::is_allowed_on_request_stream(wing::H3_FRAME_DATA), "DATA allowed on Request");
        sub.assert_true(wing::is_allowed_on_request_stream(wing::H3_FRAME_HEADERS), "HEADERS allowed on Request");
        sub.assert_false(wing::is_allowed_on_request_stream(wing::H3_FRAME_SETTINGS), "SETTINGS strictly forbidden on Request");
        sub.assert_false(wing::is_allowed_on_request_stream(wing::H3_FRAME_GOAWAY), "GOAWAY strictly forbidden on Request");
    };
}

// ============================================================================
// 2. SETTINGS Frame Conformance & Protocol Defenses
// ============================================================================
fn test_h3_settings_conformance(t: core::T&) {
    t.run("H3-03: SETTINGS Frame Encoding & Parsing") { sub =>
        var set_out = wing::H3Settings {
            qpack_max_table_capacity: 4096,
            max_field_section_size: 32768,
            qpack_blocked_streams: 16,
            enable_connect_protocol: 1,
        };

        var frame_buf: u8[..128] = [];
        sub.assert_true(wing::encode_h3_settings_frame(frame_buf, set_out), "encode SETTINGS frame");

        let hdr, ok_hdr = wing::parse_h3_frame_header(frame_buf[..], 0);
        sub.assert_true(ok_hdr, "parse SETTINGS header");
        sub.assert_eq(hdr.frame_type, wing::H3_FRAME_SETTINGS, "frame type is SETTINGS");

        let p_start = hdr.header_len as i64;
        let p_end = (hdr.header_len + hdr.payload_len) as i64;
        let payload = frame_buf[p_start..p_end];
        var set_in = wing::H3Settings { .. };
        let err = wing::parse_h3_settings_frame(payload, set_in);
        sub.assert_eq(err, wing::H3_ERR_NO_ERROR, "settings parsed with NO_ERROR");
        sub.assert_eq(set_in.qpack_max_table_capacity, 4096, "table capacity 4096");
        sub.assert_eq(set_in.max_field_section_size, 32768, "max section size 32768");
        sub.assert_eq(set_in.qpack_blocked_streams, 16, "blocked streams 16");
        sub.assert_eq(set_in.enable_connect_protocol, 1, "enable connect protocol 1");
    };

    t.run("H3-04: Rejection of Forbidden HTTP/2 Settings Identifiers") { sub =>
        // Construct payload with HTTP/2 setting 0x02 (SETTINGS_ENABLE_PUSH)
        var bad_payload: u8[..16] = [];
        wing::quic_encode_varint(bad_payload, 0x02); // Forbidden H2 setting
        wing::quic_encode_varint(bad_payload, 1);

        var set_in = wing::H3Settings { .. };
        let err = wing::parse_h3_settings_frame(bad_payload[..], set_in);
        sub.assert_eq(err, wing::H3_ERR_SETTINGS_ERROR, "forbidden H2 setting triggers H3_SETTINGS_ERROR (0x0109)");

        // Forbidden H2 setting 0x04 (SETTINGS_INITIAL_WINDOW_SIZE)
        bad_payload.clear();
        wing::quic_encode_varint(bad_payload, 0x04);
        wing::quic_encode_varint(bad_payload, 65535);
        let err_win = wing::parse_h3_settings_frame(bad_payload[..], set_in);
        sub.assert_eq(err_win, wing::H3_ERR_SETTINGS_ERROR, "H2 initial window size setting triggers H3_SETTINGS_ERROR");
    };

    t.run("H3-05: Rejection of Duplicate Setting Identifiers") { sub =>
        // Construct payload with duplicate QPACK_MAX_TABLE_CAPACITY (0x01)
        var dup_payload: u8[..16] = [];
        wing::quic_encode_varint(dup_payload, wing::H3_SETTING_QPACK_MAX_TABLE_CAPACITY);
        wing::quic_encode_varint(dup_payload, 1024);
        wing::quic_encode_varint(dup_payload, wing::H3_SETTING_QPACK_MAX_TABLE_CAPACITY);
        wing::quic_encode_varint(dup_payload, 2048);

        var set_in = wing::H3Settings { .. };
        let err = wing::parse_h3_settings_frame(dup_payload[..], set_in);
        sub.assert_eq(err, wing::H3_ERR_SETTINGS_ERROR, "duplicate setting triggers H3_SETTINGS_ERROR (0x0109)");
    };
}

// ============================================================================
// 3. Unidirectional Control and QPACK Streams
// ============================================================================
fn test_h3_unidirectional_streams(t: core::T&) {
    t.run("H3-06: Client Preambles for Control and QPACK Streams") { sub =>
        let settings = wing::H3Settings {
            qpack_max_table_capacity: 4096,
            max_field_section_size: 65536,
            qpack_blocked_streams: 16,
            enable_connect_protocol: 1,
        };
        var conn = wing::new_h3_client_connection(settings);

        var ctrl_buf: u8[..128] = [];
        var qenc_buf: u8[..16] = [];
        var qdec_buf: u8[..16] = [];

        sub.assert_true(
            wing::h3_encode_client_preambles(conn, ctrl_buf, qenc_buf, qdec_buf),
            "encode client preambles"
        );

        // Control stream starts with VarInt 0x00 followed by SETTINGS frame
        let ctrl_type, off_ctrl, ok_c = wing::quic_decode_varint(ctrl_buf[..], 0);
        sub.assert_true(ok_c, "decode control stream type");
        sub.assert_eq(ctrl_type, wing::H3_STREAM_CONTROL, "control stream type is 0x00");

        let set_hdr, ok_s = wing::parse_h3_frame_header(ctrl_buf[..], off_ctrl);
        sub.assert_true(ok_s, "parse settings header on control stream");
        sub.assert_eq(set_hdr.frame_type, wing::H3_FRAME_SETTINGS, "first frame is SETTINGS");

        // QPACK Encoder starts with VarInt 0x02
        let qenc_type, _, ok_e = wing::quic_decode_varint(qenc_buf[..], 0);
        sub.assert_true(ok_e, "decode qpack encoder type");
        sub.assert_eq(qenc_type, wing::H3_STREAM_QPACK_ENCODER, "qpack encoder type is 0x02");

        // QPACK Decoder starts with VarInt 0x03
        let qdec_type, _, ok_d = wing::quic_decode_varint(qdec_buf[..], 0);
        sub.assert_true(ok_d, "decode qpack decoder type");
        sub.assert_eq(qdec_type, wing::H3_STREAM_QPACK_DECODER, "qpack decoder type is 0x03");
    };

    t.run("H3-07: Inbound Control Stream Invariants & SETTINGS Rules") { sub =>
        let settings = wing::H3Settings { .. };
        var conn = wing::new_h3_client_connection(settings);

        // Server control stream payload: Stream Type 0x00 || GOAWAY frame (NOT SETTINGS!)
        var bad_ctrl: u8[..32] = [];
        wing::quic_encode_varint(bad_ctrl, wing::H3_STREAM_CONTROL);
        wing::encode_h3_goaway_frame(bad_ctrl, 0);

        let err_no_set = wing::h3_handle_stream_data(conn, 3, false, bad_ctrl[..], false);
        sub.assert_eq(
            err_no_set,
            wing::H3_ERR_MISSING_SETTINGS,
            "first frame not SETTINGS triggers H3_MISSING_SETTINGS (0x010A)"
        );

        // Valid server control stream: Stream Type 0x00 || SETTINGS frame
        var conn2 = wing::new_h3_client_connection(settings);
        var good_ctrl: u8[..64] = [];
        wing::quic_encode_varint(good_ctrl, wing::H3_STREAM_CONTROL);
        wing::encode_h3_settings_frame(good_ctrl, settings);

        let err_ok = wing::h3_handle_stream_data(conn2, 3, false, good_ctrl[..], false);
        sub.assert_eq(err_ok, wing::H3_ERR_NO_ERROR, "valid control stream processed ok");
        sub.assert_true(conn2.peer_settings_received, "peer settings recorded");

        // Second SETTINGS frame received later on control stream
        var second_settings: u8[..64] = [];
        wing::encode_h3_settings_frame(second_settings, settings);
        let err_second = wing::h3_handle_stream_data(conn2, 3, false, second_settings[..], false);
        sub.assert_eq(
            err_second,
            wing::H3_ERR_FRAME_UNEXPECTED,
            "second SETTINGS frame triggers H3_FRAME_UNEXPECTED (0x0105)"
        );
    };

    t.run("H3-08: Critical Stream Closure Defense") { sub =>
        let settings = wing::H3Settings { .. };
        var conn = wing::new_h3_client_connection(settings);

        var good_ctrl: u8[..64] = [];
        wing::quic_encode_varint(good_ctrl, wing::H3_STREAM_CONTROL);
        wing::encode_h3_settings_frame(good_ctrl, settings);

        // Process valid control stream on sid 3
        conn.handle_stream_data(3, false, good_ctrl[..], false);

        // Register QPACK encoder stream on sid 7
        var qpack_enc: u8[..64] = [];
        wing::quic_encode_varint(qpack_enc, wing::H3_STREAM_QPACK_ENCODER);
        conn.handle_stream_data(7, false, qpack_enc[..], false);

        // Unknown unidirectional stream on sid 11: closing with FIN must NOT trigger critical error
        var unknown_uni: u8[..64] = [];
        wing::quic_encode_varint(unknown_uni, 0x21); // GREASE stream type
        let err_unknown = conn.handle_stream_data(11, false, unknown_uni[..], true);
        sub.assert_eq(err_unknown, wing::H3_ERR_NO_ERROR, "closing non-critical uni stream is permitted");

        // Peer closes QPACK encoder stream with FIN -> critical error
        let err_qpack = conn.handle_stream_data(7, false, [], true);
        sub.assert_eq(
            err_qpack,
            wing::H3_ERR_CLOSED_CRITICAL_STREAM,
            "closing QPACK encoder stream triggers H3_CLOSED_CRITICAL_STREAM (0x0104)"
        );

        // Reset conn to test control stream closure
        var conn_ctrl = wing::new_h3_client_connection(settings);
        conn_ctrl.handle_stream_data(3, false, good_ctrl[..], false);
        let err_crit = conn_ctrl.handle_stream_data(3, false, [], true);
        sub.assert_eq(
            err_crit,
            wing::H3_ERR_CLOSED_CRITICAL_STREAM,
            "closing control stream triggers H3_CLOSED_CRITICAL_STREAM (0x0104)"
        );
    };
}

// ============================================================================
// 4. Request Stream Lifecycle & Full Request-Response Multiplexing
// ============================================================================
fn test_h3_request_streams(t: core::T&) {
    t.run("H3-09: Client Request Header & Data Frame Generation") { sub =>
        let settings = wing::H3Settings { .. };
        var conn = wing::new_h3_client_connection(settings);

        // Open request stream 0
        let sid, ok_sid = conn.open_request_stream();
        sub.assert_true(ok_sid, "open request stream succeeds");
        sub.assert_eq(sid, 0, "first client stream id is 0");

        var extra_hdrs = wing::new_header_map();
        wing::append_header(extra_hdrs, "user-agent", "GooseWing/1.0");

        var req_buf: u8[..512] = [];
        let ok_send = conn.send_request_headers(
            sid,
            "POST",
            "https",
            "api.example.com",
            "/v1/submit",
            extra_hdrs,
            false, // not end of stream
            req_buf
        );
        sub.assert_true(ok_send, "send request headers succeeds");

        // Parse generated frame
        let hdr, ok_hdr = wing::parse_h3_frame_header(req_buf[..], 0);
        sub.assert_true(ok_hdr, "parse generated request frame");
        sub.assert_eq(hdr.frame_type, wing::H3_FRAME_HEADERS, "frame type is HEADERS");

        // Send request body
        var data_buf: u8[..64] = [];
        let body = "{\"status\":\"ready\"}";
        let ok_data = conn.send_request_data(sid, body, true, data_buf);
        sub.assert_true(ok_data, "send request body succeeds");

        let d_hdr, ok_d_hdr = wing::parse_h3_frame_header(data_buf[..], 0);
        sub.assert_true(ok_d_hdr, "parse generated data frame");
        sub.assert_eq(d_hdr.frame_type, wing::H3_FRAME_DATA, "frame type is DATA");
        sub.assert_eq(d_hdr.payload_len, body.len as u64, "data payload matches body length");
    };

    t.run("H3-10: Inbound Server Response Processing (Status 200 & Body)") { sub =>
        let settings = wing::H3Settings { .. };
        var conn = wing::new_h3_client_connection(settings);

        let sid, _ = conn.open_request_stream();

        // Construct server response HEADERS frame (:status = 200)
        var qpack_resp: u8[..128] = [];
        qpack_resp.push(0x00); // RIC = 0
        qpack_resp.push(0x00); // Base = 0
        // :status 200 is index 25 in QPACK static table
        // Static indexed field: 11xxxxxx (0xC0 | 25 = 0xD9)
        qpack_resp.push(0xD9);

        var srv_wire: u8[..256] = [];
        wing::encode_h3_headers_frame(srv_wire, qpack_resp[..]);

        // Append server DATA frame: "Hello, HTTP/3 World!"
        let resp_body = "Hello, HTTP/3 World!";
        wing::encode_h3_data_frame(srv_wire, resp_body);

        // Ingest response on bidi stream 0 with FIN
        let err = conn.handle_stream_data(sid, true, srv_wire[..], true);
        sub.assert_eq(err, wing::H3_ERR_NO_ERROR, "response ingested without error");

        // Inspect response state via UFCS
        let sc, ok_sc = conn.get_status_code(sid);
        sub.assert_true(ok_sc, "status code extracted");
        sub.assert_eq(sc, 200, "status code is 200");

        let rec_body, ok_body = conn.get_response_body(sid);
        sub.assert_true(ok_body, "response body extracted");
        sub.assert_eq(rec_body, resp_body, "response body matches exactly");

        sub.assert_true(conn.is_stream_finished(sid), "stream is finished with FIN");
    };

    t.run("H3-11: Protocol Error: DATA Before HEADERS on Request Stream") { sub =>
        let settings = wing::H3Settings { .. };
        var conn = wing::new_h3_client_connection(settings);

        let sid, _ = conn.open_request_stream();

        // Server sends DATA frame before HEADERS frame
        var bad_resp: u8[..64] = [];
        wing::encode_h3_data_frame(bad_resp, "illegal early body");

        let err = conn.handle_stream_data(sid, true, bad_resp[..], false);
        sub.assert_eq(
            err,
            wing::H3_ERR_FRAME_UNEXPECTED,
            "DATA before HEADERS triggers H3_FRAME_UNEXPECTED (0x0105)"
        );
    };

    t.run("H3-12: GOAWAY Frame Handling & Stream Demultiplexing") { sub =>
        let settings = wing::H3Settings { .. };
        var conn = wing::new_h3_client_connection(settings);

        // Open streams 0 and 4
        let s0, _ = conn.open_request_stream();
        let s4, _ = conn.open_request_stream();
        sub.assert_eq(s0, 0, "s0 is 0");
        sub.assert_eq(s4, 4, "s4 is 4");

        // Ingest GOAWAY with max_stream_id = 4 on control stream
        var ctrl_goaway: u8[..64] = [];
        wing::quic_encode_varint(ctrl_goaway, wing::H3_STREAM_CONTROL);
        wing::encode_h3_settings_frame(ctrl_goaway, settings);
        wing::encode_h3_goaway_frame(ctrl_goaway, 4);

        conn.handle_stream_data(3, false, ctrl_goaway[..], false);
        sub.assert_true(conn.goaway_received, "goaway received");
        sub.assert_eq(conn.goaway_max_stream_id, 4, "goaway max stream id is 4");

        // Attempting to open next stream (id 8 >= 4) must fail
        let s8, ok_s8 = conn.open_request_stream();
        sub.assert_false(ok_s8, "cannot open stream beyond GOAWAY limit");
    };
}

// ============================================================================
// Main HTTP/3 Conformance Runner
// ============================================================================
fn main() {
    var runner = core::new_runner("HTTP/3 (RFC 9114) Zero-Allocation Conformance Suite", core::Verbosity.Verbose);

    core::run_case(runner, "1. Frame Header Encoding, Decoding & GREASE Conformance", test_h3_framing_and_grease);
    core::run_case(runner, "2. SETTINGS Frame Conformance & Protocol Defenses", test_h3_settings_conformance);
    core::run_case(runner, "3. Unidirectional Control and QPACK Streams", test_h3_unidirectional_streams);
    core::run_case(runner, "4. Request Stream Lifecycle & Full Request-Response Multiplexing", test_h3_request_streams);

    let ok = core::finish(runner);
    assert(ok);
}
