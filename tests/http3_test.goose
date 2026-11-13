// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Consolidated Verification Suite: HTTP/3 Framing, QPACK, and WebTransport Verification Suite
//
// RUN: goose build -o %t.exe %s
// RUN: %t.exe
import std;
import core from "..";
import wing from "..";
import lit from "github.com/Lemon4ksan/goose-lit@v0.1.0";

// --- Component: http3 ---
// tests/http3_test.goose
// Conformance and Security Defense Suite for HTTP/3 (RFC 9114) and QPACK (RFC 9204).

// 1. Frame Header Encoding, Decoding & GREASE Conformance
fn test_h3_framing_and_grease(t: lit::T&) {
    t.run("H3-01: Frame Header VarInt Encoding & Decoding") { sub =>
        var buf: u8[..64] = [];

        // DATA frame (0x00, len 100)
        sub.assert_true(internal::encode_h3_frame_header(buf, rfc::H3_FRAME_DATA, 100), "encode DATA frame header");
        sub.assert_eq(buf.len, 3, "1-byte type + 2-byte len (100 <= 16383 takes 2 bytes)");

        let hdr, ok = internal::parse_h3_frame_header(buf[..], 0);
        sub.assert_true(ok, "parse DATA frame header");
        sub.assert_eq(hdr.frame_type, rfc::H3_FRAME_DATA, "type is DATA");
        sub.assert_eq(hdr.payload_len, 100, "length is 100");
        sub.assert_eq(hdr.header_len, 3, "header length is 3 bytes");

        // Large frame (len 1000000)
        buf.clear();
        sub.assert_true(internal::encode_h3_frame_header(buf, rfc::H3_FRAME_HEADERS, 1000000), "encode HEADERS frame header");
        let hdr_lg, ok_lg = internal::parse_h3_frame_header(buf[..], 0);
        sub.assert_true(ok_lg, "parse large HEADERS header");
        sub.assert_eq(hdr_lg.frame_type, rfc::H3_FRAME_HEADERS, "type is HEADERS");
        sub.assert_eq(hdr_lg.payload_len, 1000000, "length is 1000000");
    };

    t.run("H3-02: GREASE Frame Identification & Stream Allowed Rules") { sub =>
        // RFC 9114 Section 7.2.8: 0x1f * N + 0x21
        // N=0: 0x21 (33)
        // N=1: 0x40 (64)
        // N=2: 0x5F (95)
        sub.assert_true(rfc::is_h3_grease_frame(0x21), "0x21 is GREASE");
        sub.assert_true(rfc::is_h3_grease_frame(0x40), "0x40 is GREASE");
        sub.assert_true(rfc::is_h3_grease_frame(0x5F), "0x5F is GREASE");
        sub.assert_false(rfc::is_h3_grease_frame(0x00), "DATA is not GREASE");
        sub.assert_false(rfc::is_h3_grease_frame(0x04), "SETTINGS is not GREASE");

        // Control stream rules
        sub.assert_true(rfc::is_allowed_on_control_stream(rfc::H3_FRAME_SETTINGS), "SETTINGS allowed on Control");
        sub.assert_true(rfc::is_allowed_on_control_stream(rfc::H3_FRAME_GOAWAY), "GOAWAY allowed on Control");
        sub.assert_true(rfc::is_allowed_on_control_stream(0x21), "GREASE allowed on Control");
        sub.assert_false(rfc::is_allowed_on_control_stream(rfc::H3_FRAME_DATA), "DATA strictly forbidden on Control");
        sub.assert_false(rfc::is_allowed_on_control_stream(rfc::H3_FRAME_HEADERS), "HEADERS strictly forbidden on Control");

        // Request stream rules
        sub.assert_true(rfc::is_allowed_on_request_stream(rfc::H3_FRAME_DATA), "DATA allowed on Request");
        sub.assert_true(rfc::is_allowed_on_request_stream(rfc::H3_FRAME_HEADERS), "HEADERS allowed on Request");
        sub.assert_false(rfc::is_allowed_on_request_stream(rfc::H3_FRAME_SETTINGS), "SETTINGS strictly forbidden on Request");
        sub.assert_false(rfc::is_allowed_on_request_stream(rfc::H3_FRAME_GOAWAY), "GOAWAY strictly forbidden on Request");
    };
}

// 2. SETTINGS Frame Conformance & Protocol Defenses
fn test_h3_settings_conformance(t: lit::T&) {
    t.run("H3-03: SETTINGS Frame Encoding & Parsing") { sub =>
        var set_out = wing::H3Settings {
            qpack_max_table_capacity: 4096,
            max_field_section_size:   32768,
            qpack_blocked_streams:    16,
            enable_connect_protocol:  1,
        };

        var frame_buf: u8[..128] = [];
        sub.assert_true(internal::encode_h3_settings_frame(frame_buf, set_out), "encode SETTINGS frame");

        let hdr, ok_hdr = internal::parse_h3_frame_header(frame_buf[..], 0);
        sub.assert_true(ok_hdr, "parse SETTINGS header");
        sub.assert_eq(hdr.frame_type, rfc::H3_FRAME_SETTINGS, "frame type is SETTINGS");

        let p_start = hdr.header_len as i64;
        let p_end = (hdr.header_len + hdr.payload_len) as i64;
        let payload = frame_buf[p_start..p_end];
        var set_in = wing::H3Settings { .. };
        let err = internal::parse_h3_settings_frame(payload, set_in);
        sub.assert_eq(err, rfc::H3_ERR_NO_ERROR, "settings parsed with NO_ERROR");
        sub.assert_eq(set_in.qpack_max_table_capacity, 4096, "table capacity 4096");
        sub.assert_eq(set_in.max_field_section_size, 32768, "max section size 32768");
        sub.assert_eq(set_in.qpack_blocked_streams, 16, "blocked streams 16");
        sub.assert_eq(set_in.enable_connect_protocol, 1, "enable connect protocol 1");
    };

    t.run("H3-04: Rejection of Forbidden HTTP/2 Settings Identifiers") { sub =>
        // Construct payload with HTTP/2 setting 0x02 (SETTINGS_ENABLE_PUSH)
        var bad_payload: u8[..16] = [];
        internal::quic_encode_varint(bad_payload, 0x02); // Forbidden H2 setting
        internal::quic_encode_varint(bad_payload, 1);

        var set_in = wing::H3Settings { .. };
        let err = internal::parse_h3_settings_frame(bad_payload[..], set_in);
        sub.assert_eq(err, rfc::H3_ERR_SETTINGS_ERROR, "forbidden H2 setting triggers H3_SETTINGS_ERROR (0x0109)");

        // Forbidden H2 setting 0x04 (SETTINGS_INITIAL_WINDOW_SIZE)
        bad_payload.clear();
        internal::quic_encode_varint(bad_payload, 0x04);
        internal::quic_encode_varint(bad_payload, 65535);
        let err_win = internal::parse_h3_settings_frame(bad_payload[..], set_in);
        sub.assert_eq(err_win, rfc::H3_ERR_SETTINGS_ERROR, "H2 initial window size setting triggers H3_SETTINGS_ERROR");
    };

    t.run("H3-05: Rejection of Duplicate Setting Identifiers") { sub =>
        // Construct payload with duplicate QPACK_MAX_TABLE_CAPACITY (0x01)
        var dup_payload: u8[..16] = [];
        internal::quic_encode_varint(dup_payload, rfc::H3_SETTING_QPACK_MAX_TABLE_CAPACITY);
        internal::quic_encode_varint(dup_payload, 1024);
        internal::quic_encode_varint(dup_payload, rfc::H3_SETTING_QPACK_MAX_TABLE_CAPACITY);
        internal::quic_encode_varint(dup_payload, 2048);

        var set_in = wing::H3Settings { .. };
        let err = internal::parse_h3_settings_frame(dup_payload[..], set_in);
        sub.assert_eq(err, rfc::H3_ERR_SETTINGS_ERROR, "duplicate setting triggers H3_SETTINGS_ERROR (0x0109)");
    };
}

// 3. Unidirectional Control and QPACK Streams
fn test_h3_unidirectional_streams(t: lit::T&) {
    t.run("H3-06: Client Preambles for Control and QPACK Streams") { sub =>
        let settings = wing::H3Settings {
            qpack_max_table_capacity: 4096,
            max_field_section_size:   65536,
            qpack_blocked_streams:    16,
            enable_connect_protocol:  1,
        };
        var conn = internal::new_h3_client_connection(settings);

        var ctrl_buf: u8[..128] = [];
        var qenc_buf: u8[..16]  = [];
        var qdec_buf: u8[..16]  = [];

        sub.assert_true(
            internal::encode_client_preambles(conn, ctrl_buf, qenc_buf, qdec_buf),
            "encode client preambles",
        );

        // Control stream starts with VarInt 0x00 followed by SETTINGS frame
        let ctrl_type, off_ctrl, ok_c = internal::quic_decode_varint(ctrl_buf[..], 0);
        sub.assert_true(ok_c, "decode control stream type");
        sub.assert_eq(ctrl_type, rfc::H3_STREAM_CONTROL, "control stream type is 0x00");

        let set_hdr, ok_s = internal::parse_h3_frame_header(ctrl_buf[..], off_ctrl);
        sub.assert_true(ok_s, "parse settings header on control stream");
        sub.assert_eq(set_hdr.frame_type, rfc::H3_FRAME_SETTINGS, "first frame is SETTINGS");

        // QPACK Encoder starts with VarInt 0x02
        let qenc_type, _, ok_e = internal::quic_decode_varint(qenc_buf[..], 0);
        sub.assert_true(ok_e, "decode qpack encoder type");
        sub.assert_eq(qenc_type, rfc::H3_STREAM_QPACK_ENCODER, "qpack encoder type is 0x02");

        // QPACK Decoder starts with VarInt 0x03
        let qdec_type, _, ok_d = internal::quic_decode_varint(qdec_buf[..], 0);
        sub.assert_true(ok_d, "decode qpack decoder type");
        sub.assert_eq(qdec_type, rfc::H3_STREAM_QPACK_DECODER, "qpack decoder type is 0x03");
    };

    t.run("H3-07: Inbound Control Stream Invariants & SETTINGS Rules") { sub =>
        let settings = wing::H3Settings { .. };
        var conn = internal::new_h3_client_connection(settings);

        // Server control stream payload: Stream Type 0x00 || GOAWAY frame (NOT SETTINGS!)
        var bad_ctrl: u8[..32] = [];
        internal::quic_encode_varint(bad_ctrl, rfc::H3_STREAM_CONTROL);
        internal::encode_h3_goaway_frame(bad_ctrl, 0);

        let err_no_set = internal::handle_stream_data(conn, 3, false, bad_ctrl[..], false);
        sub.assert_eq(
            err_no_set,
            rfc::H3_ERR_MISSING_SETTINGS,
            "first frame not SETTINGS triggers H3_MISSING_SETTINGS (0x010A)",
        );

        // Valid server control stream: Stream Type 0x00 || SETTINGS frame
        var conn2 = internal::new_h3_client_connection(settings);
        var good_ctrl: u8[..64] = [];
        internal::quic_encode_varint(good_ctrl, rfc::H3_STREAM_CONTROL);
        internal::encode_h3_settings_frame(good_ctrl, settings);

        let err_ok = internal::handle_stream_data(conn2, 3, false, good_ctrl[..], false);
        sub.assert_eq(err_ok, rfc::H3_ERR_NO_ERROR, "valid control stream processed ok");
        sub.assert_true(conn2.peer_settings_received, "peer settings recorded");

        // Second SETTINGS frame received later on control stream
        var second_settings: u8[..64] = [];
        internal::encode_h3_settings_frame(second_settings, settings);
        let err_second = internal::handle_stream_data(conn2, 3, false, second_settings[..], false);
        sub.assert_eq(
            err_second,
            rfc::H3_ERR_FRAME_UNEXPECTED,
            "second SETTINGS frame triggers H3_FRAME_UNEXPECTED (0x0105)",
        );
    };

    t.run("H3-08: Critical Stream Closure Defense") { sub =>
        let settings = wing::H3Settings { .. };
        var conn = internal::new_h3_client_connection(settings);

        var good_ctrl: u8[..64] = [];
        internal::quic_encode_varint(good_ctrl, rfc::H3_STREAM_CONTROL);
        internal::encode_h3_settings_frame(good_ctrl, settings);

        // Process valid control stream on sid 3
        conn.handle_stream_data(3, false, good_ctrl[..], false);

        // Register QPACK encoder stream on sid 7
        var qpack_enc: u8[..64] = [];
        internal::quic_encode_varint(qpack_enc, rfc::H3_STREAM_QPACK_ENCODER);
        conn.handle_stream_data(7, false, qpack_enc[..], false);

        // Unknown unidirectional stream on sid 11: closing with FIN must NOT trigger critical error
        var unknown_uni: u8[..64] = [];
        internal::quic_encode_varint(unknown_uni, 0x21); // GREASE stream type
        let err_unknown = conn.handle_stream_data(11, false, unknown_uni[..], true);
        sub.assert_eq(err_unknown, rfc::H3_ERR_NO_ERROR, "closing non-critical uni stream is permitted");

        // Peer closes QPACK encoder stream with FIN -> critical error
        let err_qpack = conn.handle_stream_data(7, false, [], true);
        sub.assert_eq(
            err_qpack,
            rfc::H3_ERR_CLOSED_CRITICAL_STREAM,
            "closing QPACK encoder stream triggers H3_CLOSED_CRITICAL_STREAM (0x0104)",
        );

        // Reset conn to test control stream closure
        var conn_ctrl = internal::new_h3_client_connection(settings);
        conn_ctrl.handle_stream_data(3, false, good_ctrl[..], false);
        let err_crit = conn_ctrl.handle_stream_data(3, false, [], true);
        sub.assert_eq(
            err_crit,
            rfc::H3_ERR_CLOSED_CRITICAL_STREAM,
            "closing control stream triggers H3_CLOSED_CRITICAL_STREAM (0x0104)",
        );
    };
}

// 4. Request Stream Lifecycle & Full Request-Response Multiplexing
fn test_h3_request_streams(t: lit::T&) {
    t.run("H3-09: Client Request Header & Data Frame Generation") { sub =>
        let settings = wing::H3Settings { .. };
        var conn = internal::new_h3_client_connection(settings);

        // Open request stream 0
        let sid, ok_sid = conn.open_request_stream();
        sub.assert_true(ok_sid, "open request stream succeeds");
        sub.assert_eq(sid, 0, "first client stream id is 0");

        var extra_hdrs = wing::HeaderMap { .. };
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
            req_buf,
        );
        sub.assert_true(ok_send, "send request headers succeeds");

        // Parse generated frame
        let hdr, ok_hdr = internal::parse_h3_frame_header(req_buf[..], 0);
        sub.assert_true(ok_hdr, "parse generated request frame");
        sub.assert_eq(hdr.frame_type, rfc::H3_FRAME_HEADERS, "frame type is HEADERS");

        // Send request body
        var data_buf: u8[..64] = [];
        let body = "{\"status\":\"ready\"}";
        let ok_data = conn.send_request_data(sid, body, true, data_buf);
        sub.assert_true(ok_data, "send request body succeeds");

        let d_hdr, ok_d_hdr = internal::parse_h3_frame_header(data_buf[..], 0);
        sub.assert_true(ok_d_hdr, "parse generated data frame");
        sub.assert_eq(d_hdr.frame_type, rfc::H3_FRAME_DATA, "frame type is DATA");
        sub.assert_eq(d_hdr.payload_len, body.len as u64, "data payload matches body length");
    };

    t.run("H3-10: Inbound Server Response Processing (Status 200 & Body)") { sub =>
        let settings = wing::H3Settings { .. };
        var conn = internal::new_h3_client_connection(settings);

        let sid, _ = conn.open_request_stream();

        // Construct server response HEADERS frame (:status = 200)
        var qpack_resp: u8[..128] = [];
        qpack_resp.push(0x00); // RIC = 0
        qpack_resp.push(0x00); // Base = 0
        // :status 200 is index 25 in QPACK static table
        // Static indexed field: 11xxxxxx (0xC0 | 25 = 0xD9)
        qpack_resp.push(0xD9);

        var srv_wire: u8[..256] = [];
        internal::encode_h3_headers_frame(srv_wire, qpack_resp[..]);

        // Append server DATA frame: "Hello, HTTP/3 World!"
        let resp_body = "Hello, HTTP/3 World!";
        internal::encode_h3_data_frame(srv_wire, resp_body);

        // Ingest response on bidi stream 0 with FIN
        let err = conn.handle_stream_data(sid, true, srv_wire[..], true);
        sub.assert_eq(err, rfc::H3_ERR_NO_ERROR, "response ingested without error");

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
        var conn = internal::new_h3_client_connection(settings);

        let sid, _ = conn.open_request_stream();

        // Server sends DATA frame before HEADERS frame
        var bad_resp: u8[..64] = [];
        internal::encode_h3_data_frame(bad_resp, "illegal early body");

        let err = conn.handle_stream_data(sid, true, bad_resp[..], false);
        sub.assert_eq(
            err,
            rfc::H3_ERR_FRAME_UNEXPECTED,
            "DATA before HEADERS triggers H3_FRAME_UNEXPECTED (0x0105)",
        );
    };

    t.run("H3-12: GOAWAY Frame Handling & Stream Demultiplexing") { sub =>
        let settings = wing::H3Settings { .. };
        var conn = internal::new_h3_client_connection(settings);

        // Open streams 0 and 4
        let s0, _ = conn.open_request_stream();
        let s4, _ = conn.open_request_stream();
        sub.assert_eq(s0, 0, "s0 is 0");
        sub.assert_eq(s4, 4, "s4 is 4");

        // Ingest GOAWAY with max_stream_id = 4 on control stream
        var ctrl_goaway: u8[..64] = [];
        internal::quic_encode_varint(ctrl_goaway, rfc::H3_STREAM_CONTROL);
        internal::encode_h3_settings_frame(ctrl_goaway, settings);
        internal::encode_h3_goaway_frame(ctrl_goaway, 4);

        conn.handle_stream_data(3, false, ctrl_goaway[..], false);
        sub.assert_true(conn.goaway_received, "goaway received");
        sub.assert_eq(conn.goaway_max_stream_id, 4, "goaway max stream id is 4");

        // Attempting to open next stream (id 8 >= 4) must fail
        let s8, ok_s8 = conn.open_request_stream();
        sub.assert_false(ok_s8, "cannot open stream beyond GOAWAY limit");
    };

    t.run("H3-13: QPACK Dynamic Table Encoding & Encoder Stream Roundtrip") { sub =>
        let settings = wing::H3Settings {
            qpack_max_table_capacity: 4096,
            max_field_section_size:   16384,
            qpack_blocked_streams:    16,
            ..
        };
        var client_conn = internal::new_h3_client_connection(settings);
        var server_conn = internal::new_h3_server_connection(settings);

        sub.assert_true(internal::h3_activate_qpack_dynamic_table(client_conn, 4096), "activate dynamic table on client");
        sub.assert_true(client_conn.encoder_stream_buf.len > 0, "Set Dynamic Table Capacity emitted");

        let sid0, ok0 = client_conn.open_request_stream();
        sub.assert_true(ok0, "open stream 0");

        var extra = wing::HeaderMap { .. };
        wing::append_header(extra, "x-custom-token", "secret-val-123");

        var req_frame0: u8[..512] = [];
        sub.assert_true(
            client_conn.send_request_headers(sid0, "GET", "https", "dyn.example.com", "/items", extra, true, req_frame0),
            "send request 0 with dynamic table insertion",
        );
        sub.assert_true(client_conn.qpack_table.insert_count >= 1, "entries inserted into client dynamic table");

        // Feed QPACK encoder stream preamble + client encoder instructions to server_conn
        var enc_wire: u8[..512] = [];
        internal::quic_encode_varint(enc_wire, rfc::H3_STREAM_QPACK_ENCODER);
        enc_wire.append(client_conn.encoder_stream_buf[..]);
        let err_enc = server_conn.handle_stream_data(6, false, enc_wire[..], false);
        sub.assert_eq(err_enc, rfc::H3_ERR_NO_ERROR, "server processed client encoder stream");
        sub.assert_eq(server_conn.qpack_table.insert_count, client_conn.qpack_table.insert_count, "server dynamic table synced");

        // Feed request 0 HEADERS frame to server_conn
        let err_req0 = server_conn.handle_stream_data(sid0, true, req_frame0[..], true);
        sub.assert_eq(err_req0, rfc::H3_ERR_NO_ERROR, "server decoded dynamic QPACK request 0");

        // Send a second request reusing the dynamic table entries without new insertions
        let prev_inserts = client_conn.qpack_table.insert_count;
        let sid4, ok4 = client_conn.open_request_stream();
        sub.assert_true(ok4, "open stream 4");
        var req_frame4: u8[..512] = [];
        sub.assert_true(
            client_conn.send_request_headers(sid4, "GET", "https", "dyn.example.com", "/items", extra, true, req_frame4),
            "send request 4 reusing dynamic table entries",
        );
        sub.assert_eq(client_conn.qpack_table.insert_count, prev_inserts, "no new insertions needed on repeat headers");
        let err_req4 = server_conn.handle_stream_data(sid4, true, req_frame4[..], true);
        sub.assert_eq(err_req4, rfc::H3_ERR_NO_ERROR, "server decoded dynamic QPACK request 4");
    };
}

// 5. QPACK Table Lifecycle, String Decoding & Stream Instructions (RFC 9204)
fn test_qpack_table_and_codec(t: lit::T&) {
    t.run("QPACK-01: Table Capacity and Entry Management") { sub =>
        var tbl = internal::new_qpack_table(4096, 16);
        sub.assert_eq(tbl.capacity_bytes, 4096, "capacity is 4096");
        sub.assert_eq(tbl.insert_count, 0, "initial insert count is 0");

        // Literal insertion
        sub.assert_true(internal::qpack_insert_literal(tbl, "custom-key", "custom-val"), "insert literal");
        sub.assert_eq(tbl.insert_count, 1, "insert count incremented to 1");

        // Lookup absolute
        var name_buf: u8[..256]  = [];
        var val_buf:  u8[..4096] = [];
        let ok_lookup = internal::qpack_lookup_absolute(tbl, 0, name_buf, val_buf);
        sub.assert_true(ok_lookup, "lookup absolute 0");
        sub.assert_eq(name_buf[..], "custom-key", "key matches");
        sub.assert_eq(val_buf[..], "custom-val", "val matches");

        // Static name reference insertion (index 17 is ":status")
        sub.assert_true(internal::qpack_insert_named_static(tbl, 17, "200"), "insert named static");
        sub.assert_eq(tbl.insert_count, 2, "insert count is 2");

        // Dynamic name reference insertion (relative 0 is latest entry: ":status")
        sub.assert_true(internal::qpack_insert_named_dynamic(tbl, 0, "404"), "insert named dynamic");
        sub.assert_eq(tbl.insert_count, 3, "insert count is 3");

        // Duplicate entry (relative 0 is latest entry)
        sub.assert_true(internal::qpack_duplicate(tbl, 0), "duplicate latest entry");
        sub.assert_eq(tbl.insert_count, 4, "insert count is 4");

        // Capacity shrink causing eviction
        sub.assert_true(internal::qpack_set_capacity(tbl, 100), "shrink capacity");
        sub.assert_eq(tbl.capacity_bytes, 100, "capacity updated");

        // Section ACK and cancellation
        internal::qpack_ack_section(tbl, 4, 1);
        internal::qpack_cancel_stream(tbl, 4);
        internal::qpack_increment_received(tbl, 2);
    };

    t.run("QPACK-02: String Decoding (Plain and Huffman)") { sub =>
        // Plain string: "custom-value"
        var plain_encoded: u8[..32] = [];
        plain_encoded.push(12); // length 12, H=0
        plain_encoded.append("custom-value");

        var plain_out: u8[..64] = [];
        let next_p, ok_p = internal::decode_qpack_string(plain_encoded[..], 0, 7, plain_out);
        sub.assert_true(ok_p, "decode plain string");
        sub.assert_eq(plain_out[..], "custom-value", "plain string matches");
        sub.assert_eq(next_p, 13, "next offset is 13");

        // Out-of-bounds offset test
        var err_out: u8[..16] = [];
        let _, ok_err = internal::decode_qpack_string(plain_encoded[..], 50, 7, err_out);
        sub.assert_false(ok_err, "decode out-of-bounds string fails safely");
    };

    t.run("QPACK-03: Encoder Stream Instruction Parsing") { sub =>
        var tbl = internal::new_qpack_table(4096, 16);

        // 1. Set Dynamic Table Capacity instruction: 0x3F 0xE1 0x1F (capacity 4096)
        var enc_cap: u8[..16] = [];
        enc_cap.push(0x3F);
        enc_cap.push(0xE1);
        enc_cap.push(0x1F);
        let _, err1 = internal::qpack_process_encoder_instruction(tbl, enc_cap[..], 0);
        sub.assert_eq(err1, internal::QpackError.None, "set capacity instruction succeeds");

        // 2. Insert with literal name and value: 0100 0110 "custom" 0000 0101 "value"
        var enc_lit: u8[..32] = [];
        enc_lit.push(0x46); // 0100 0110 (N=0, H=0, name_len=6)
        enc_lit.append("custom");
        enc_lit.push(0x05); // H=0, val_len=5
        enc_lit.append("value");
        let _, err2 = internal::qpack_process_encoder_instruction(tbl, enc_lit[..], 0);
        sub.assert_eq(err2, internal::QpackError.None, "insert literal instruction succeeds");
        sub.assert_eq(tbl.insert_count, 1, "table has 1 entry");

        // 3. Duplicate instruction: 000xxxxx (duplicate relative index 0)
        var enc_dup: u8[..4] = [];
        enc_dup.push(0x00); // 0000 0000: duplicate rel 0
        let _, err3 = internal::qpack_process_encoder_instruction(tbl, enc_dup[..], 0);
        sub.assert_eq(err3, internal::QpackError.None, "duplicate instruction succeeds");
        sub.assert_eq(tbl.insert_count, 2, "table has 2 entries");
    };

    t.run("QPACK-04: Decoder Stream Instruction Parsing") { sub =>
        var tbl = internal::new_qpack_table(4096, 16);

        // Track unacknowledged section for stream 4 with RIC=1 (RFC 9204 §4.4.1)
        sub.assert_true(internal::qpack_track_unacked_stream(tbl, 4, 1), "track unacked stream 4");

        // 1. Section Acknowledgment (1xxxxxxx) for stream 4
        var dec_ack: u8[..8] = [];
        dec_ack.push(0x84); // 1000 0100 -> stream 4
        let _, err_d1 = internal::qpack_process_decoder_instruction(tbl, dec_ack[..], 0);
        sub.assert_eq(err_d1, internal::QpackError.None, "section ack succeeds");
        sub.assert_eq(tbl.known_rcvd_count, 1, "known_rcvd_count updated to 1");

        // Duplicate Section Acknowledgment for already-acknowledged stream MUST fail (RFC 9204 §4.4.1)
        let _, err_dup = internal::qpack_process_decoder_instruction(tbl, dec_ack[..], 0);
        sub.assert_eq(err_dup, internal::QpackError.DecoderStreamError, "duplicate section ack triggers DecoderStreamError");

        // 2. Stream Cancellation (01xxxxxx) for stream 4
        var dec_canc: u8[..8] = [];
        dec_canc.push(0x44); // 0100 0100 -> stream 4
        let _, err_d2 = internal::qpack_process_decoder_instruction(tbl, dec_canc[..], 0);
        sub.assert_eq(err_d2, internal::QpackError.None, "stream cancellation succeeds");

        // 3. Insert Count Increment (00xxxxxx) with increment 3 (RFC 9204 Section 4.4.3)
        tbl.known_rcvd_count = 0;
        tbl.insert_count = 3;
        var dec_inc: u8[..8] = [];
        dec_inc.push(0x03); // 0000 0011 -> inc 3
        let _, err_d3 = internal::qpack_process_decoder_instruction(tbl, dec_inc[..], 0);
        sub.assert_eq(err_d3, internal::QpackError.None, "insert count increment succeeds");
        sub.assert_eq(tbl.known_rcvd_count, 3, "known received count updated to 3");

        // 4. Excess Insert Count Increment beyond insert_count must fail with DecoderStreamError
        dec_inc.clear();
        dec_inc.push(0x01); // inc 1 -> 3 + 1 = 4 > insert_count (3)
        let _, err_d4 = internal::qpack_process_decoder_instruction(tbl, dec_inc[..], 0);
        sub.assert_eq(err_d4, internal::QpackError.DecoderStreamError, "excess increment rejected per RFC 9204 Section 4.4.3");
    };

    t.run("QPACK-05: Section Decoding (Static, Dynamic, and Literal Fields)") { sub =>
        var tbl = internal::new_qpack_table(4096, 16);
        // Insert entry: "x-api-version" -> "v2"
        internal::qpack_insert_literal(tbl, "x-api-version", "v2");

        // Build section:
        var sec: u8[..128] = [];
        // Encoded RIC: RIC=1, max_cap=4096 => encoded = 2 (RFC 9204 Section 4.5.1)
        let enc_ric = internal::encode_ric(1, tbl.capacity_bytes);
        sec.push(enc_ric as u8);
        // Sign=0, DeltaBase=0 => 0x00
        sec.push(0x00);

        // 1. Static Indexed Field: :status 200 (index 25 -> 0xC0 | 25 = 0xD9)
        sec.push(0xD9);

        // 2. Dynamic Indexed Field: relative index 0 -> 0x80 | 0 = 0x80
        sec.push(0x80);

        // 3. Literal Field Line with Static Name Reference:
        // index 0 (:authority), literal value "test.com"
        // 0101 0000 (0x50 with T=1, static, index 0): 0x50
        sec.push(0x50);
        sec.push(8); // val len 8, H=0
        sec.append("test.com");

        // 4. Literal Field Line with Literal Name:
        // 0010 0000 (0x20: N=0, H=0): name "foo", val "bar"
        sec.push(0x23); // name_len 3
        sec.append("foo");
        sec.push(0x03); // val len 3
        sec.append("bar");

        var out_fields: internal::HeaderField[>..] = [];
        let err = internal::decode_qpack_section(tbl, sec[..], out_fields, 16384);
        sub.assert_eq(err, internal::QpackError.None, "decode section succeeds");
        sub.assert_eq(out_fields.len, 4, "4 fields decoded");

        sub.assert_eq(out_fields[0].name[..], ":status", "field 0 name is :status");
        sub.assert_eq(out_fields[0].value[..], "200", "field 0 val is 200");

        sub.assert_eq(out_fields[1].name[..], "x-api-version", "field 1 name is x-api-version");
        sub.assert_eq(out_fields[1].value[..], "v2", "field 1 val is v2");

        sub.assert_eq(out_fields[2].name[..], ":authority", "field 2 name is :authority");
        sub.assert_eq(out_fields[2].value[..], "test.com", "field 2 val is test.com");

        sub.assert_eq(out_fields[3].name[..], "foo", "field 3 name is foo");
        sub.assert_eq(out_fields[3].value[..], "bar", "field 3 val is bar");
    };
}

// 6. HTTP/3 Extended Frames & Stream Edge-Cases
fn test_h3_extended_frames(t: lit::T&) {
    t.run("H3-13: Extended Frame Encoding & Inbound Ingestion") { sub =>
        let settings = wing::H3Settings { .. };
        var conn = internal::new_h3_server_connection(settings);

        // Encode and parse CANCEL_PUSH frame
        var cp_buf: u8[..32] = [];
        sub.assert_true(internal::encode_h3_cancel_push(cp_buf, 42), "encode CANCEL_PUSH");
        let cp_hdr, ok_cp_hdr = internal::parse_h3_frame_header(cp_buf[..], 0);
        sub.assert_true(ok_cp_hdr, "parse CANCEL_PUSH frame header");
        let cp_id, ok_cp = internal::parse_h3_cancel_push(cp_buf[cp_hdr.header_len..cp_hdr.header_len + cp_hdr.payload_len]);
        sub.assert_true(ok_cp, "parse CANCEL_PUSH");
        sub.assert_eq(cp_id, 42, "push id matches");

        // Encode and parse MAX_PUSH_ID frame
        var mp_buf: u8[..32] = [];
        sub.assert_true(internal::encode_h3_max_push_id(mp_buf, 100), "encode MAX_PUSH_ID");
        let mp_hdr, ok_mp_hdr = internal::parse_h3_frame_header(mp_buf[..], 0);
        sub.assert_true(ok_mp_hdr, "parse MAX_PUSH_ID frame header");
        let mp_id, ok_mp = internal::parse_h3_max_push_id(mp_buf[mp_hdr.header_len..mp_hdr.header_len + mp_hdr.payload_len]);
        sub.assert_true(ok_mp, "parse MAX_PUSH_ID");
        sub.assert_eq(mp_id, 100, "max push id matches");

        // Encode and parse PRIORITY_UPDATE frame for Request Stream
        var pu_buf: u8[..64] = [];
        let p_req = wing::PriorityParam { urgency: 3, incremental: true };
        sub.assert_true(internal::encode_h3_priority_update_request(pu_buf, 0, p_req), "encode PRIORITY_UPDATE req");
        let pu_hdr, ok_pu_hdr = internal::parse_h3_frame_header(pu_buf[..], 0);
        sub.assert_true(ok_pu_hdr, "parse PRIORITY_UPDATE req header");
        let pr_elem, pr_prio, ok_pr = internal::parse_h3_priority_update_request(pu_buf[pu_hdr.header_len..pu_hdr.header_len + pu_hdr.payload_len]);
        sub.assert_true(ok_pr, "parse PRIORITY_UPDATE req");
        sub.assert_eq(pr_elem, 0, "elem id is 0");
        sub.assert_eq(pr_prio.urgency, 3, "urgency is 3");
        sub.assert_true(pr_prio.incremental, "incremental is true");

        // Encode and parse PRIORITY_UPDATE frame for Push Stream
        var pp_buf: u8[..64] = [];
        let p_push = wing::PriorityParam { urgency: 5, incremental: false };
        sub.assert_true(internal::encode_h3_priority_update_push(pp_buf, 1, p_push), "encode PRIORITY_UPDATE push");
        let pp_hdr, ok_pp_hdr = internal::parse_h3_frame_header(pp_buf[..], 0);
        sub.assert_true(ok_pp_hdr, "parse PRIORITY_UPDATE push header");
        let pp_elem, pp_prio, ok_pp = internal::parse_h3_priority_update_push(pp_buf[pp_hdr.header_len..pp_hdr.header_len + pp_hdr.payload_len]);
        sub.assert_true(ok_pp, "parse PRIORITY_UPDATE push");
        sub.assert_eq(pp_elem, 1, "elem id is 1");
        sub.assert_eq(pp_prio.urgency, 5, "urgency is 5");
        sub.assert_false(pp_prio.incremental, "incremental is false");

        // Ingest control stream with extended frames (CANCEL_PUSH, MAX_PUSH_ID, PRIORITY_UPDATE)
        var ctrl_wire: u8[..256] = [];
        internal::quic_encode_varint(ctrl_wire, rfc::H3_STREAM_CONTROL);
        internal::encode_h3_settings_frame(ctrl_wire, settings);
        internal::encode_h3_cancel_push(ctrl_wire, 1);
        internal::encode_h3_max_push_id(ctrl_wire, 10);
        internal::encode_h3_priority_update_request(ctrl_wire, 0, p_req);

        let err_ctrl = conn.handle_stream_data(3, false, ctrl_wire[..], false);
        sub.assert_eq(err_ctrl, rfc::H3_ERR_NO_ERROR, "ingest extended frames on control stream");
    };

    t.run("H3-14: Send Request Data Edge Cases") { sub =>
        let settings = wing::H3Settings { .. };
        var conn = internal::new_h3_client_connection(settings);

        let sid, _ = conn.open_request_stream();

        // Send headers
        var req_buf: u8[..256] = [];
        var hdrs = wing::HeaderMap { .. };
        conn.send_request_headers(sid, "GET", "https", "example.com", "/", hdrs, false, req_buf);

        // Send data without end_stream
        var data_chunk: u8[..64] = [];
        sub.assert_true(conn.send_request_data(sid, "part1", false, data_chunk), "send data chunk 1");

        // Send data with end_stream
        data_chunk.clear();
        sub.assert_true(conn.send_request_data(sid, "part2", true, data_chunk), "send data chunk 2 with FIN");

        // Send on non-existent stream fails
        data_chunk.clear();
        sub.assert_false(conn.send_request_data(999, "bad", false, data_chunk), "send on unknown stream fails");
    };
}

// 7. Team QPackStrike Protocol Hardening Suite (RFC 9114, RFC 9204, RFC 9000)
fn test_round1_qpackstrike_suite(t: lit::T&) {
    t.run("QPACK-R1-01: 62-bit Integer Decoding and Overflow Rejection (RFC 9204 Section 4.1.1)") { sub =>
        // 62-bit integer: 0x3FFFFFFFFFFFFFFF
        // With 7-bit prefix: prefix byte 0x7F, followed by 9 continuation octets
        var buf62: u8[..16] = [0x7F, 0x80, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x3F];
        let val62, next_off62, ok62 = internal::qpack_decode_int(buf62[..], 0, 7);
        sub.assert_true(ok62, "decode max 62-bit integer 0x3FFFFFFFFFFFFFFF succeeds");
        sub.assert_eq(val62, rfc::QUIC_VARINT_MAX, "decoded value matches 0x3FFFFFFFFFFFFFFF");
        sub.assert_eq(next_off62, 10, "consumed 10 bytes");

        // 63-bit integer overflow: payload > 0x3F at 9th continuation byte (0x40)
        var buf_overflow: u8[..16] = [0x7F, 0x80, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x40];
        let _, _, ok_ovf = internal::qpack_decode_int(buf_overflow[..], 0, 7);
        sub.assert_false(ok_ovf, "63-bit integer overflow rejected");

        // Overflow on encoder stream returns EncoderStreamError
        var tbl = internal::new_qpack_table(4096, 16);
        var enc_ovf: u8[..16] = [0x3F, 0x80, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x40];
        let _, err_enc = internal::qpack_process_encoder_instruction(tbl, enc_ovf[..], 0);
        sub.assert_eq(err_enc, internal::QpackError.EncoderStreamError, "overflow on encoder stream yields EncoderStreamError");

        // Overflow on decoder stream returns DecoderStreamError
        var dec_ovf: u8[..16] = [0xFF, 0x80, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x40];
        let _, err_dec = internal::qpack_process_decoder_instruction(tbl, dec_ovf[..], 0);
        sub.assert_eq(err_dec, internal::QpackError.DecoderStreamError, "overflow on decoder stream yields DecoderStreamError");
    };

    t.run("QPACK-R1-02: Zero Capacity Rejects Dynamic Table Insertion (RFC 9204 Section 3.2.3, 3.2.4)") { sub =>
        var tbl = internal::new_qpack_table(4096, 16);
        tbl.capacity_bytes = 0; // Explicitly capacity 0

        // Attempt Insert with Literal Name when capacity is 0
        var enc_lit: u8[..32] = [];
        enc_lit.push(0x46);
        enc_lit.append("custom");
        enc_lit.push(0x05);
        enc_lit.append("value");
        let _, err_ins = internal::qpack_process_encoder_instruction(tbl, enc_lit[..], 0);
        sub.assert_eq(err_ins, internal::QpackError.EncoderStreamError, "insert when capacity=0 rejected with EncoderStreamError");

        // Attempt Duplicate when capacity is 0
        var enc_dup: u8[..4] = [0x00];
        let _, err_dup = internal::qpack_process_encoder_instruction(tbl, enc_dup[..], 0);
        sub.assert_eq(err_dup, internal::QpackError.EncoderStreamError, "duplicate when capacity=0 rejected with EncoderStreamError");
    };

    t.run("H3-R1-01: Frame Payload Length Integer Overflow Protection (RFC 9114 Section 7.1)") { sub =>
        let settings = wing::H3Settings { .. };
        var conn = internal::new_h3_client_connection(settings);

        // Control stream: valid SETTINGS frame first
        var ctrl_wire: u8[..128] = [];
        internal::quic_encode_varint(ctrl_wire, rfc::H3_STREAM_CONTROL);
        internal::encode_h3_settings_frame(ctrl_wire, settings);
        conn.handle_stream_data(3, false, ctrl_wire[..], false);
        sub.assert_true(conn.peer_settings_received, "peer settings received");

        // Now send frame header with maliciously crafted 62-bit payload length (0x3FFFFFFFFFFFFFF0)
        // that would overflow 'offset + hdr.payload_len'
        var mal_frame: u8[..32] = [];
        internal::quic_encode_varint(mal_frame, rfc::H3_FRAME_CANCEL_PUSH);
        internal::quic_encode_varint(mal_frame, 0x3FFFFFFFFFFFFFF0);
        mal_frame.push(0x00);

        let err = conn.handle_stream_data(3, false, mal_frame[..], false);
        sub.assert_eq(err, rfc::H3_ERR_FRAME_ERROR, "huge payload_len triggers H3_FRAME_ERROR without overflow");
        sub.assert_eq(conn.state, internal::H3ConnState.Closed, "connection closed on frame error");
    };

    t.run("H3-R1-02: HTTP/2 Reserved Frame 0x0A (ALTSVC) Rejection (RFC 9114 Section 7.2.8)") { sub =>
        sub.assert_true(rfc::is_h2_reserved_frame_in_h3(0x0A), "0x0A is reserved from H2");
        sub.assert_false(rfc::is_allowed_on_control_stream(0x0A), "0x0A forbidden on control stream");
        sub.assert_false(rfc::is_allowed_on_request_stream(0x0A), "0x0A forbidden on request stream");

        let settings = wing::H3Settings { .. };
        var conn = internal::new_h3_client_connection(settings);

        // Control stream with valid SETTINGS followed by frame type 0x0A
        var ctrl_wire: u8[..64] = [];
        internal::quic_encode_varint(ctrl_wire, rfc::H3_STREAM_CONTROL);
        internal::encode_h3_settings_frame(ctrl_wire, settings);
        internal::quic_encode_varint(ctrl_wire, 0x0A);
        internal::quic_encode_varint(ctrl_wire, 0);

        let err = conn.handle_stream_data(3, false, ctrl_wire[..], false);
        sub.assert_eq(err, rfc::H3_ERR_FRAME_UNEXPECTED, "frame 0x0A rejected with H3_FRAME_UNEXPECTED");
    };

    t.run("H3-R1-03: Unknown Unidirectional Stream Persistence (RFC 9114 Section 6.2)") { sub =>
        let settings = wing::H3Settings { .. };
        var conn = internal::new_h3_client_connection(settings);

        var ctrl: u8[..64] = [];
        internal::quic_encode_varint(ctrl, rfc::H3_STREAM_CONTROL);
        internal::encode_h3_settings_frame(ctrl, settings);
        conn.handle_stream_data(3, false, ctrl[..], false);

        // Open unknown unidirectional stream 15 (type 0x21 GREASE)
        var chunk1: u8[..16] = [];
        internal::quic_encode_varint(chunk1, 0x21);
        let err1 = conn.handle_stream_data(15, false, chunk1[..], false);
        sub.assert_eq(err1, rfc::H3_ERR_NO_ERROR, "unknown uni stream chunk 1 accepted");

        // Send second chunk with leading byte 0x00
        var chunk2: u8[..16] = [0x00, 0x01, 0x02, 0x03];
        let err2 = conn.handle_stream_data(15, false, chunk2[..], false);
        sub.assert_eq(err2, rfc::H3_ERR_NO_ERROR, "unknown uni stream chunk 2 ignored safely");
        sub.assert_eq(conn.error_code, rfc::H3_ERR_NO_ERROR, "connection still valid");
    };

    t.run("QUIC-R1-01: Datagram Frame Length Integer Overflow Protection (RFC 9221 Section 3)") { sub =>
        var wire: u8[..16] = [];
        internal::quic_encode_varint(wire, rfc::QUIC_FRAME_DATAGRAM_LEN);
        internal::quic_encode_varint(wire, 0x3FFFFFFFFFFFFFF0);

        let payload, _, ok = internal::decode_quic_datagram_frame(wire[..], 0, wire.len as u64);
        sub.assert_false(ok, "overflowing datagram frame length safely rejected");
        sub.assert_eq(payload.len, 0, "no slice produced");
    };
}

// 8. Team QPackStrike Round 2 Protocol Audit Suite (RFC 9114, RFC 9204, RFC 9000)
fn test_round2_qpackstrike_suite(t: lit::T&) {
    t.run("H3-R2-01: Control Stream Frame Sequence & Missing SETTINGS Precedence (RFC 9114 §6.2.1, §7.2.4)") { sub =>
        let settings = wing::H3Settings { .. };

        // Test A: DATA frame (0x00) sent as first frame on control stream MUST trigger H3_ERR_MISSING_SETTINGS (0x010A)
        var conn1 = internal::new_h3_client_connection(settings);
        var bad_ctrl1: u8[..64] = [];
        internal::quic_encode_varint(bad_ctrl1, rfc::H3_STREAM_CONTROL);
        internal::encode_h3_frame_header(bad_ctrl1, rfc::H3_FRAME_DATA, 4);
        bad_ctrl1.append([1, 2, 3, 4]);

        let err1 = conn1.handle_stream_data(3, false, bad_ctrl1[..], false);
        sub.assert_eq(err1, rfc::H3_ERR_MISSING_SETTINGS, "initial DATA frame on control stream MUST return H3_MISSING_SETTINGS (0x010A)");
        sub.assert_eq(conn1.state, internal::H3ConnState.Closed, "connection closed");
        sub.assert_eq(conn1.error_code, rfc::H3_ERR_MISSING_SETTINGS, "error code is H3_MISSING_SETTINGS");

        // Test B: HEADERS frame (0x01) sent as first frame on control stream MUST trigger H3_ERR_MISSING_SETTINGS (0x010A)
        var conn2 = internal::new_h3_client_connection(settings);
        var bad_ctrl2: u8[..64] = [];
        internal::quic_encode_varint(bad_ctrl2, rfc::H3_STREAM_CONTROL);
        internal::encode_h3_frame_header(bad_ctrl2, rfc::H3_FRAME_HEADERS, 2);
        bad_ctrl2.append([0x00, 0x00]);

        let err2 = conn2.handle_stream_data(3, false, bad_ctrl2[..], false);
        sub.assert_eq(err2, rfc::H3_ERR_MISSING_SETTINGS, "initial HEADERS frame on control stream MUST return H3_MISSING_SETTINGS (0x010A)");
        sub.assert_eq(conn2.state, internal::H3ConnState.Closed, "connection closed");

        // Test C: Valid SETTINGS as first frame succeeds
        var conn3 = internal::new_h3_client_connection(settings);
        var good_ctrl: u8[..64] = [];
        internal::quic_encode_varint(good_ctrl, rfc::H3_STREAM_CONTROL);
        internal::encode_h3_settings_frame(good_ctrl, settings);
        let err3 = conn3.handle_stream_data(3, false, good_ctrl[..], false);
        sub.assert_eq(err3, rfc::H3_ERR_NO_ERROR, "initial SETTINGS succeeds");
        sub.assert_eq(conn3.state, internal::H3ConnState.Active, "connection active");

        // Test D: Subsequent DATA frame after SETTINGS triggers H3_FRAME_UNEXPECTED (0x0105)
        var bad_post_settings: u8[..64] = [];
        internal::encode_h3_frame_header(bad_post_settings, rfc::H3_FRAME_DATA, 4);
        bad_post_settings.append([1, 2, 3, 4]);
        let err4 = conn3.handle_stream_data(3, false, bad_post_settings[..], false);
        sub.assert_eq(err4, rfc::H3_ERR_FRAME_UNEXPECTED, "subsequent DATA frame triggers H3_FRAME_UNEXPECTED (0x0105)");
        sub.assert_eq(conn3.state, internal::H3ConnState.Closed, "connection closed");
    };

    t.run("H3-R2-02: GOAWAY Stream ID Monotonicity and Client-Bidi Validation (RFC 9114 §5.2, §7.2.6)") { sub =>
        let settings = wing::H3Settings { .. };

        // Test A: Initial GOAWAY with non-client-bidi stream ID triggers H3_ERR_ID_ERROR (0x0108)
        // Stream ID 1: server-initiated bidirectional ((1 & 0x03) == 1)
        var conn1 = internal::new_h3_client_connection(settings);
        var init_ctrl: u8[..64] = [];
        internal::quic_encode_varint(init_ctrl, rfc::H3_STREAM_CONTROL);
        internal::encode_h3_settings_frame(init_ctrl, settings);
        conn1.handle_stream_data(3, false, init_ctrl[..], false);

        var bad_ga1: u8[..32] = [];
        internal::encode_h3_goaway_frame(bad_ga1, 1); // Server-bidi ID 1
        let err1 = conn1.handle_stream_data(3, false, bad_ga1[..], false);
        sub.assert_eq(err1, rfc::H3_ERR_ID_ERROR, "GOAWAY with server-bidi stream ID MUST trigger H3_ERR_ID_ERROR");
        sub.assert_eq(conn1.state, internal::H3ConnState.Closed, "connection closed");

        // Test B: Initial GOAWAY with client-uni stream ID triggers H3_ERR_ID_ERROR
        // Stream ID 2: client-initiated unidirectional ((2 & 0x03) == 2)
        var conn2 = internal::new_h3_client_connection(settings);
        conn2.handle_stream_data(3, false, init_ctrl[..], false);
        var bad_ga2: u8[..32] = [];
        internal::encode_h3_goaway_frame(bad_ga2, 2); // Client-uni ID 2
        let err2 = conn2.handle_stream_data(3, false, bad_ga2[..], false);
        sub.assert_eq(err2, rfc::H3_ERR_ID_ERROR, "GOAWAY with client-uni stream ID MUST trigger H3_ERR_ID_ERROR");

        // Test C: Valid GOAWAY with client-bidi stream ID 8 succeeds
        var conn3 = internal::new_h3_client_connection(settings);
        conn3.handle_stream_data(3, false, init_ctrl[..], false);
        var good_ga: u8[..32] = [];
        internal::encode_h3_goaway_frame(good_ga, 8); // Client-bidi ID 8 ((8 & 0x03) == 0)
        let err3 = conn3.handle_stream_data(3, false, good_ga[..], false);
        sub.assert_eq(err3, rfc::H3_ERR_NO_ERROR, "valid GOAWAY accepted");
        sub.assert_eq(conn3.state, internal::H3ConnState.Draining, "connection state is Draining");
        sub.assert_eq(conn3.goaway_max_stream_id, 8, "max stream id is 8");

        // Test D: Subsequent GOAWAY with increased stream ID triggers H3_ERR_ID_ERROR
        var bad_seq_ga: u8[..32] = [];
        internal::encode_h3_goaway_frame(bad_seq_ga, 12); // 12 > 8: non-monotonic increase!
        let err4 = conn3.handle_stream_data(3, false, bad_seq_ga[..], false);
        sub.assert_eq(err4, rfc::H3_ERR_ID_ERROR, "increasing GOAWAY stream ID MUST trigger H3_ERR_ID_ERROR");
        sub.assert_eq(conn3.state, internal::H3ConnState.Closed, "connection closed");

        // Test E: Subsequent GOAWAY with decreased stream ID succeeds
        var conn4 = internal::new_h3_client_connection(settings);
        conn4.handle_stream_data(3, false, init_ctrl[..], false);
        conn4.handle_stream_data(3, false, good_ga[..], false); // first GOAWAY with 8
        var good_seq_ga: u8[..32] = [];
        internal::encode_h3_goaway_frame(good_seq_ga, 4); // 4 <= 8: monotonic decrease
        let err5 = conn4.handle_stream_data(3, false, good_seq_ga[..], false);
        sub.assert_eq(err5, rfc::H3_ERR_NO_ERROR, "decreasing GOAWAY accepted");
        sub.assert_eq(conn4.goaway_max_stream_id, 4, "max stream id updated to 4");

        // Test F: GOAWAY with malformed payload (extra trailing bytes) triggers H3_ERR_FRAME_ERROR (RFC 9114 §7.2.6)
        var conn5 = internal::new_h3_client_connection(settings);
        conn5.handle_stream_data(3, false, init_ctrl[..], false);
        var bad_pl_ga: u8[..32] = [];
        internal::encode_h3_frame_header(bad_pl_ga, rfc::H3_FRAME_GOAWAY, 2);
        bad_pl_ga.push(0x00); // stream ID 0
        bad_pl_ga.push(0xFF); // trailing extra garbage byte
        let err6 = conn5.handle_stream_data(3, false, bad_pl_ga[..], false);
        sub.assert_eq(err6, rfc::H3_ERR_FRAME_ERROR, "malformed GOAWAY payload MUST return H3_ERR_FRAME_ERROR");
    };

    t.run("QPACK-R2-01: Eviction Barrier and Blocked Streams Constraints (RFC 9204 §2.1.1, §2.1.2)") { sub =>
        // Test A: Pinned entry prevents eviction flooding
        var tbl = internal::new_qpack_table(128, 4);
        internal::qpack_insert_literal(tbl, "x-pinned", "val1"); // ~46 bytes, abs_idx 0
        internal::qpack_pin_entry(tbl, 0); // Pin entry 0

        internal::qpack_insert_literal(tbl, "x-second", "val2"); // ~46 bytes, abs_idx 1 (total ~92 <= 128)
        // Inserting 3rd entry (~46 bytes, total 138 > 128) requires evicting entry 0
        // Because entry 0 is pinned, eviction MUST fail and insertion returns false
        let ok_blocked = internal::qpack_insert_literal(tbl, "x-third", "val3");
        sub.assert_false(ok_blocked, "insertion requiring eviction of pinned entry fails");

        // After unpinning, eviction succeeds
        internal::qpack_unpin_entry(tbl, 0);
        let ok_unpinned = internal::qpack_insert_literal(tbl, "x-third", "val3");
        sub.assert_true(ok_unpinned, "insertion succeeds after unpinning");

        // Test A2: Stream Cancellation releases dynamic entry references and allows eviction (RFC 9204 §2.2.2.2)
        var tbl_canc = internal::new_qpack_table(100, 4);
        internal::qpack_insert_literal(tbl_canc, "x-first", "v1");
        sub.assert_true(internal::qpack_track_stream_ref(tbl_canc, 10, 0), "stream 10 pins entry 0");
        internal::qpack_insert_literal(tbl_canc, "x-second", "v2");
        let ok_blocked2 = internal::qpack_insert_literal(tbl_canc, "x-third", "v3");
        sub.assert_false(ok_blocked2, "eviction blocked while stream 10 holds reference");
        internal::qpack_cancel_stream(tbl_canc, 10);
        let ok_canc = internal::qpack_insert_literal(tbl_canc, "x-third", "v3");
        sub.assert_true(ok_canc, "eviction succeeds after stream cancellation releases reference");

        // Test B: Blocked streams manager helpers
        var tbl_b = internal::new_qpack_table(512, 2);
        sub.assert_true(internal::qpack_can_block_stream(tbl_b), "can block stream when under max_blocked");
        sub.assert_true(internal::qpack_block_stream(tbl_b, 0, 5, "payload0"), "block stream 0");
        sub.assert_true(internal::qpack_is_stream_blocked(tbl_b, 0), "stream 0 is blocked");
        sub.assert_true(internal::qpack_block_stream(tbl_b, 4, 6, "payload4"), "block stream 4");
        sub.assert_false(internal::qpack_can_block_stream(tbl_b), "cannot block stream when at max_blocked (2)");
        sub.assert_false(internal::qpack_block_stream(tbl_b, 8, 7, "payload8"), "blocking stream 8 fails when max_blocked exceeded");

        sub.assert_true(internal::qpack_unblock_stream(tbl_b, 0), "unblock stream 0");
        sub.assert_false(internal::qpack_is_stream_blocked(tbl_b, 0), "stream 0 no longer blocked");
        sub.assert_true(internal::qpack_can_block_stream(tbl_b), "can block stream again after unblocking");

        // Test C: decode_qpack_section with ric > tbl.insert_count triggers BlockedStreamsExhausted
        var tbl_c = internal::new_qpack_table(4096, 0); // max_blocked = 0
        // Header block requesting RIC = 1 (encoded as enc_ric = 2) when insert_count = 0
        var qpack_block: u8[..32]                   = [0x02, 0x00, 0xD1];
        var out_fields:  internal::HeaderField[>..] = [];
        let dec_err = internal::decode_qpack_section(tbl_c, qpack_block[..], out_fields);
        sub.assert_eq(dec_err, internal::QpackError.BlockedStreamsExhausted, "ric > insert_count with max_blocked 0 returns BlockedStreamsExhausted");
    };

    t.run("QUIC-R2-01: Header Reserved Bits Zeroing Validation (RFC 9000 §17.2, §17.3)") { sub =>
        // Test A: Long Header Initial packet with non-zero reserved bits (0x0C mask) MUST fail
        var bad_init: u8[..64] = [];
        bad_init.push(0xC8); // Long header Initial (0xC0), but bit 3 is set (0x08)! Reserved bits = 0x08 != 0
        core::append_u32_be(bad_init, rfc::QUIC_VERSION_1);
        bad_init.push(0); // DCID len
        bad_init.push(0); // SCID len
        internal::quic_encode_varint(bad_init, 0); // token len 0
        internal::quic_encode_varint(bad_init, 4); // plen
        bad_init.append([0x00, 0x01, 0x02, 0x03]); // PN + payload
        let _, ok_bad_init = internal::parse_quic_header(bad_init[..], 0);
        sub.assert_false(ok_bad_init, "Initial packet with non-zero reserved bits rejected per RFC 9000 §17.2");

        // Test B: Long Header Handshake packet with non-zero reserved bits (bit 2 is set, 0x04)
        var bad_hs: u8[..64] = [];
        bad_hs.push(0xE4); // Handshake (0xE0) with bit 2 set (0x04)
        core::append_u32_be(bad_hs, rfc::QUIC_VERSION_1);
        bad_hs.push(0); // DCID len
        bad_hs.push(0); // SCID len
        internal::quic_encode_varint(bad_hs, 4); // plen
        bad_hs.append([0x00, 0x01, 0x02, 0x03]);
        let _, ok_bad_hs = internal::parse_quic_header(bad_hs[..], 0);
        sub.assert_false(ok_bad_hs, "Handshake packet with non-zero reserved bits rejected per RFC 9000 §17.2");

        // Test C: Valid Long Header Initial packet with reserved bits == 0 succeeds
        var good_init: u8[..64] = [];
        good_init.push(0xC0); // Long header Initial, reserved bits = 0
        core::append_u32_be(good_init, rfc::QUIC_VERSION_1);
        good_init.push(0);
        good_init.push(0);
        internal::quic_encode_varint(good_init, 0);
        internal::quic_encode_varint(good_init, 4);
        good_init.append([0x00, 0x01, 0x02, 0x03]);
        let _, ok_good_init = internal::parse_quic_header(good_init[..], 0);
        sub.assert_true(ok_good_init, "Initial packet with zero reserved bits accepted");

        // Test D: Short Header (1-RTT) packet with non-zero reserved bits (0x18 mask) MUST fail
        let bad_short1: u8[16] = [
            0x50, // Short header (0x40) with bit 4 set (0x10)! Reserved bits != 0
            0x01, 0x02, 0x03, 0x04,
            0x2A, // PN
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];
        let _, ok_bs1 = internal::parse_quic_header(bad_short1[..], 4);
        sub.assert_false(ok_bs1, "Short header with reserved bit 4 set rejected per RFC 9000 §17.3");

        let bad_short2: u8[16] = [
            0x48, // Short header (0x40) with bit 3 set (0x08)! Reserved bits != 0
            0x01, 0x02, 0x03, 0x04,
            0x2A, // PN
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];
        let _, ok_bs2 = internal::parse_quic_header(bad_short2[..], 4);
        sub.assert_false(ok_bs2, "Short header with reserved bit 3 set rejected per RFC 9000 §17.3");

        // Test E: Valid Short Header with reserved bits == 0 succeeds
        let good_short: u8[16] = [
            0x40, // Short header, reserved bits 0
            0x01, 0x02, 0x03, 0x04,
            0x2A, // PN
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];
        let _, ok_good_short = internal::parse_quic_header(good_short[..], 4);
        sub.assert_true(ok_good_short, "Short header with zero reserved bits accepted");
    };
}

// 9. Team QPackStrike Round 3 Championship Audit Suite (RFC 9204, RFC 9000, RFC 9114)
fn test_round3_qpackstrike_suite(t: lit::T&) {
    t.run("QPACK-R3-01: Huffman Padding Bounds and All-1s Validation (RFC 9204 §4.1.2, RFC 7541 §5.2)") { sub =>
        // Test A: Non-empty input with only padding (0xFF) MUST fail (8 bits of padding > 7 bits)
        var bad_huff1: u8[..4]  = [0xFF];
        var out1:      u8[..64] = [];
        let ok1 = internal::huff_decode_bytes(bad_huff1[..], out1);
        sub.assert_false(ok1, "Huffman string of pure 0xFF (8 bits padding) MUST fail per RFC 9204 §4.1.2");

        // Test B: 16 bits of pure padding (0xFF, 0xFF) MUST fail
        var bad_huff2: u8[..4]  = [0xFF, 0xFF];
        var out2:      u8[..64] = [];
        let ok2 = internal::huff_decode_bytes(bad_huff2[..], out2);
        sub.assert_false(ok2, "Huffman string of 0xFFFF (16 bits padding) MUST fail");

        // Test C: Valid Huffman string ("custom-key") with extra trailing 0xFF (8 bits padding) MUST fail
        var valid_encoded: u8[..64] = [];
        sub.assert_true(internal::huff_encode_bytes("custom-key", valid_encoded), "encode custom-key");
        valid_encoded.push(0xFF); // Append extra 8 bits of padding
        var out3: u8[..64] = [];
        let ok3 = internal::huff_decode_bytes(valid_encoded[..], out3);
        sub.assert_false(ok3, "Huffman string with trailing full byte padding MUST fail per RFC 9204 §4.1.2");

        // Test D: Valid Huffman string ("custom-key") decodes cleanly
        var valid_clean: u8[..64] = [];
        sub.assert_true(internal::huff_encode_bytes("custom-key", valid_clean), "encode custom-key clean");
        var out4: u8[..64] = [];
        let ok4 = internal::huff_decode_bytes(valid_clean[..], out4);
        sub.assert_true(ok4, "Valid Huffman string decodes cleanly");
        sub.assert_eq(out4[..], "custom-key", "decoded content matches");

        // Test E: decode_qpack_string rejects string literal with invalid Huffman padding
        var raw_str_wire: u8[..64] = [];
        // Length 2, Huffman bit set (0x80 | 2 = 0x82), followed by [0xFF, 0xFF]
        raw_str_wire.push(0x82);
        raw_str_wire.push(0xFF);
        raw_str_wire.push(0xFF);
        var q_out: u8[..64] = [];
        let _, ok_str = internal::decode_qpack_string(raw_str_wire[..], 0, 7, q_out);
        sub.assert_false(ok_str, "decode_qpack_string rejects Huffman with padding > 7 bits");
    };

    t.run("QUIC-R3-01: Packet Number Reconstruction 62-Bit Arithmetic Safety (RFC 9000 §17.1, Appendix A.3)") { sub =>
        // Test A: Standard packet number reconstruction
        let pn1, ok_pn1 = internal::decode_packet_number_checked(0, 1, 1);
        sub.assert_true(ok_pn1, "decode standard pn 1 ok");
        sub.assert_eq(pn1, 1, "reconstructed pn is 1");

        let pn256, ok_pn256 = internal::decode_packet_number_checked(255, 0, 1);
        sub.assert_true(ok_pn256, "decode wrap-around pn ok");
        sub.assert_eq(pn256, 256, "reconstructed pn is 256");

        // Test B: Invalid pn_len (0 or > 4) MUST fail
        let _, ok_bad_len0 = internal::decode_packet_number_checked(100, 42, 0);
        sub.assert_false(ok_bad_len0, "pn_len 0 rejected");
        let _, ok_bad_len5 = internal::decode_packet_number_checked(100, 42, 5);
        sub.assert_false(ok_bad_len5, "pn_len 5 rejected");

        // Test C: Packet number exceeding 2^62 - 1 MUST fail per RFC 9000 §17.1
        let _, ok_exceed = internal::decode_packet_number_checked(0x3FFFFFFFFFFFFFFF, 1, 1);
        // Largest acked is already at 2^62 - 1, candidate next pn would exceed 2^62 - 1
        sub.assert_false(ok_exceed, "reconstructed PN exceeding 2^62 - 1 rejected");

        // Test D: Input truncated_pn exceeding 2^62 - 1 MUST fail
        let _, ok_bad_trunc = internal::decode_packet_number_checked(100, 0x4000000000000000, 4);
        sub.assert_false(ok_bad_trunc, "truncated_pn >= 2^62 rejected");

        // Test E: Boundary at 2^62 - 2 reconstructed cleanly
        let near_max: u64 = 0x3FFFFFFFFFFFFFFE;
        let pn_near, ok_near = internal::decode_packet_number_checked(near_max - 1, (near_max & 0xFF), 1);
        sub.assert_true(ok_near, "reconstructed PN near 2^62 - 1 accepted");
        sub.assert_eq(pn_near, near_max, "reconstructed value matches");
    };

    t.run("H3-R3-01: PUSH_PROMISE, CANCEL_PUSH, and MAX_PUSH_ID Invariants (RFC 9114 §7.2.5, §7.2.7)") { sub =>
        let settings = wing::H3Settings { .. };

        // Test A: Server receiving PUSH_PROMISE frame on request stream MUST fail with H3_FRAME_UNEXPECTED
        var srv_conn = internal::H3Connection {
            role:  internal::H3ConnRole.Server,
            state: internal::H3ConnState.Active,
            ..
        };
        // Add open request stream 0
        srv_conn.streams.push(internal::H3StreamEntry {
            stream_id: 0,
            kind:      internal::H3StreamKind.Request,
            state:     internal::H3StreamState.Open,
            is_bidi:   true,
            ..
        });

        var push_wire: u8[..64] = [];
        sub.assert_true(internal::encode_h3_push_promise(push_wire, 1, [0x00, 0x00]), "encode PUSH_PROMISE");
        let err_srv = srv_conn.handle_stream_data(0, true, push_wire[..], false);
        sub.assert_eq(err_srv, rfc::H3_ERR_FRAME_UNEXPECTED, "Server receiving PUSH_PROMISE MUST return H3_FRAME_UNEXPECTED");
        sub.assert_eq(srv_conn.state, internal::H3ConnState.Closed, "server connection closed");

        // Test B: Client receiving PUSH_PROMISE when client never sent MAX_PUSH_ID MUST fail with H3_ERR_ID_ERROR
        var cli_conn = internal::new_h3_client_connection(settings);
        let sid, _ = cli_conn.open_request_stream();
        let err_no_max = cli_conn.handle_stream_data(sid, true, push_wire[..], false);
        sub.assert_eq(err_no_max, rfc::H3_ERR_ID_ERROR, "PUSH_PROMISE without MAX_PUSH_ID MUST return H3_ERR_ID_ERROR");

        // Test C: Client receiving PUSH_PROMISE with Push ID > max_push_id_advertised MUST fail with H3_ERR_ID_ERROR
        var cli_conn2 = internal::new_h3_client_connection(settings);
        let sid2, _ = cli_conn2.open_request_stream();
        var max_p_buf: u8[..32] = [];
        sub.assert_true(internal::send_max_push_id(cli_conn2, 5, max_p_buf), "client advertises MAX_PUSH_ID = 5");

        var bad_push_wire: u8[..64] = [];
        sub.assert_true(internal::encode_h3_push_promise(bad_push_wire, 10, [0x00, 0x00]), "encode PUSH_PROMISE with push_id 10 > 5");
        let err_exceed = cli_conn2.handle_stream_data(sid2, true, bad_push_wire[..], false);
        sub.assert_eq(err_exceed, rfc::H3_ERR_ID_ERROR, "PUSH_PROMISE with push_id > advertised limit MUST return H3_ERR_ID_ERROR");

        // Test D: Client receiving PUSH_PROMISE with push_id <= max_push_id_advertised succeeds
        var good_push_wire: u8[..64] = [];
        sub.assert_true(internal::encode_h3_push_promise(good_push_wire, 3, [0x00, 0x00]), "encode PUSH_PROMISE with push_id 3 <= 5");
        let err_good_push = cli_conn2.handle_stream_data(sid2, true, good_push_wire[..], false);
        sub.assert_eq(err_good_push, rfc::H3_ERR_NO_ERROR, "PUSH_PROMISE with valid push_id accepted");

        // Test E: CANCEL_PUSH with Push ID > advertised max limit on control stream returns H3_ERR_ID_ERROR
        var init_ctrl: u8[..64] = [];
        internal::quic_encode_varint(init_ctrl, rfc::H3_STREAM_CONTROL);
        internal::encode_h3_settings_frame(init_ctrl, settings);
        cli_conn2.handle_stream_data(3, false, init_ctrl[..], false);

        var bad_cp_wire: u8[..32] = [];
        sub.assert_true(internal::encode_h3_cancel_push(bad_cp_wire, 20), "encode CANCEL_PUSH with push_id 20 > 5");
        let err_cp_exceed = cli_conn2.handle_stream_data(3, false, bad_cp_wire[..], false);
        sub.assert_eq(err_cp_exceed, rfc::H3_ERR_ID_ERROR, "CANCEL_PUSH with push_id > advertised limit returns H3_ERR_ID_ERROR");

        // Test F: MAX_PUSH_ID monotonicity violation (decreasing max_push_id) returns H3_ERR_ID_ERROR
        var srv_ctrl_conn = internal::H3Connection {
            role:  internal::H3ConnRole.Server,
            state: internal::H3ConnState.Active,
            ..
        };
        var srv_init_ctrl: u8[..64] = [];
        internal::quic_encode_varint(srv_init_ctrl, rfc::H3_STREAM_CONTROL);
        internal::encode_h3_settings_frame(srv_init_ctrl, settings);
        srv_ctrl_conn.handle_stream_data(2, false, srv_init_ctrl[..], false);

        var mp1_wire: u8[..32] = [];
        sub.assert_true(internal::encode_h3_max_push_id(mp1_wire, 50), "first MAX_PUSH_ID = 50");
        let err_mp1 = srv_ctrl_conn.handle_stream_data(2, false, mp1_wire[..], false);
        sub.assert_eq(err_mp1, rfc::H3_ERR_NO_ERROR, "first MAX_PUSH_ID accepted");

        var mp2_wire: u8[..32] = [];
        sub.assert_true(internal::encode_h3_max_push_id(mp2_wire, 30), "decreasing MAX_PUSH_ID = 30 < 50");
        let err_mp2 = srv_ctrl_conn.handle_stream_data(2, false, mp2_wire[..], false);
        sub.assert_eq(err_mp2, rfc::H3_ERR_ID_ERROR, "decreasing MAX_PUSH_ID MUST return H3_ERR_ID_ERROR");
    };

    t.run("H3-R3-02: RFC 9114 & RFC 9204 Hardening (RIC, Stream Recycling, Role Checks, Pseudo-Headers)") { sub =>
        let settings = wing::H3Settings { .. };

        // Test A: qpack_insert_literal rejects entry larger than table capacity (RFC 9204 §3.2.2)
        var tbl_small = internal::new_qpack_table(40, 0); // capacity 40 bytes
        // Entry overhead is 32. Name len 5 + Val len 5 = 10, total cost 42 > 40
        let ok_oversize = internal::qpack_insert_literal(tbl_small, "hello", "world");
        sub.assert_false(ok_oversize, "entry larger than capacity MUST return false per RFC 9204 §3.2.2");

        // Test B: decode_qpack_section rejects RIC > insert_count (RFC 9204 §4.5.1)
        var tbl_ric = internal::new_qpack_table(4096, 16);
        internal::qpack_insert_literal(tbl_ric, "x-header", "v1"); // abs_idx 0
        // Encoded block declaring RIC=2 (encoded as 3) when table only has insert_count=1
        // Per RFC 9204 §4.5.1, RIC > insert_count MUST fail decompression
        var sec_bad_ric: u8[..16]                   = [0x03, 0x00, 0xD9];
        var out_f:       internal::HeaderField[>..] = [];
        let err_bad_ric = internal::decode_qpack_section(tbl_ric, sec_bad_ric[..], out_f);
        sub.assert_eq(err_bad_ric, internal::QpackError.DecompressionFailed, "RIC > insert_count MUST fail decompression");

        // Test C: Stream slot reuse allows > 8 requests on same connection
        var cli_reuse = internal::new_h3_client_connection(settings);
        let empty_headers = wing::HeaderMap { .. };
        for i in 12 {
            let sid, ok_open = cli_reuse.open_request_stream();
            sub.assert_true(ok_open, "open request stream in loop");
            sub.assert_eq(sid, (i * 4) as u64, "stream ID increments by 4");

            // Server sends 200 response with FIN
            var resp_wire: u8[..64] = [];
            internal::encode_h3_headers_frame(resp_wire, [0x00, 0x00, 0xD9]);
            let err_resp = cli_reuse.handle_stream_data(sid, true, resp_wire[..], true);
            sub.assert_eq(err_resp, rfc::H3_ERR_NO_ERROR, "response ingested");
            // Client sends FIN to close stream locally and remotely
            var req_data: u8[..256] = [];
            cli_reuse.send_request_headers(sid, "GET", "https", "example.com", "/", empty_headers, true, req_data);
        }

        // Test D: Server sending MAX_PUSH_ID to client triggers H3_FRAME_UNEXPECTED (RFC 9114 §7.2.7)
        var cli_mp = internal::new_h3_client_connection(settings);
        var init_ctrl_d: u8[..64] = [];
        internal::quic_encode_varint(init_ctrl_d, rfc::H3_STREAM_CONTROL);
        internal::encode_h3_settings_frame(init_ctrl_d, settings);
        cli_mp.handle_stream_data(3, false, init_ctrl_d[..], false);

        var bad_mp_wire: u8[..32] = [];
        internal::encode_h3_max_push_id(bad_mp_wire, 10);
        let err_cli_mp = cli_mp.handle_stream_data(3, false, bad_mp_wire[..], false);
        sub.assert_eq(err_cli_mp, rfc::H3_ERR_FRAME_UNEXPECTED, "Server sending MAX_PUSH_ID to client rejected");

        // Test E: Server sending PRIORITY_UPDATE to client triggers H3_FRAME_UNEXPECTED (RFC 9218 §7.2)
        var cli_prio = internal::new_h3_client_connection(settings);
        cli_prio.handle_stream_data(3, false, init_ctrl_d[..], false);

        var bad_prio_wire: u8[..64] = [];
        let bad_prio = wing::PriorityParam { urgency: 2, incremental: false };
        internal::encode_h3_priority_update_request(bad_prio_wire, 0, bad_prio);
        let err_cli_prio = cli_prio.handle_stream_data(3, false, bad_prio_wire[..], false);
        sub.assert_eq(err_cli_prio, rfc::H3_ERR_FRAME_UNEXPECTED, "Server sending PRIORITY_UPDATE to client rejected");

        // Test F: Response missing :status triggers H3_ERR_GENERAL_PROTOCOL (RFC 9114 §4.3.2)
        var cli_no_status = internal::new_h3_client_connection(settings);
        let sid_ns, _ = cli_no_status.open_request_stream();
        var no_status_wire: u8[..64] = [];
        // Section with only custom header: "x-foo: bar" (RIC=0, Base=0, Literal Name)
        var qpack_no_st: u8[..64] = [0x00, 0x00];
        internal::encode_qpack_field(qpack_no_st, "x-foo", "bar", true);
        internal::encode_h3_headers_frame(no_status_wire, qpack_no_st[..]);
        let err_no_status = cli_no_status.handle_stream_data(sid_ns, true, no_status_wire[..], false);
        sub.assert_eq(err_no_status, rfc::H3_ERR_GENERAL_PROTOCOL, "Response missing :status rejected");

        // Test G: Response with client pseudo-header :method triggers H3_ERR_GENERAL_PROTOCOL (RFC 9114 §4.3.2)
        var cli_with_meth = internal::new_h3_client_connection(settings);
        let sid_wm, _ = cli_with_meth.open_request_stream();
        var with_meth_wire: u8[..64] = [];
        var qpack_wm:       u8[..64] = [0x00, 0x00, 0xD9]; // :status 200
        internal::encode_qpack_field(qpack_wm, ":method", "GET", true);
        internal::encode_h3_headers_frame(with_meth_wire, qpack_wm[..]);
        let err_with_meth = cli_with_meth.handle_stream_data(sid_wm, true, with_meth_wire[..], false);
        sub.assert_eq(err_with_meth, rfc::H3_ERR_GENERAL_PROTOCOL, "Response containing :method rejected");
    };
}

// Main HTTP/3 Conformance Runner

// --- Component: http3_webtransport ---
// Verification suite for W3C / IETF draft-ietf-webtrans-http3-16 and RFC 9221:
// - Extended CONNECT request formatting & validation (:protocol = webtransport)
// - WebTransport session state transitions & lifecycle (open, drain, close)
// - WebTransport unidirectional (0x54) and bidirectional (0x41) stream framing
// - WebTransport datagram wire encoding & decoding (Session ID varint + payload)
// - RFC 9221 QUIC DATAGRAM frame encoding & decoding
// - HTTP/3 error code translation with GREASE skipping
// - WebTransport capsule codecs (close, drain, reset_stream, stop_sending)

// ----------------------------------------------------------------------------
// 10. WebTransport Session & Datagrams
// ----------------------------------------------------------------------------
fn test_webtransport_session_and_datagrams(t: lit::T&) {
    t.run("Extended CONNECT Initiation (draft-16)") { sub =>
        var req = wing::Request { .. };
        wing::format_webtransport_connect_request(req, "https://chat.example.com/wt-feed");

        sub.assert_bytes_eq(req.method[..], "CONNECT", "Method is CONNECT");
        sub.assert_bytes_eq(req.url[..], "https://chat.example.com/wt-feed", "URL matches target");

        sub.assert_true(req.has_header(":protocol"), "Has :protocol header");
        sub.assert_bytes_eq(req.header(":protocol"), "webtransport", ":protocol is webtransport");
        sub.assert_true(req.has_header("sec-webtransport-http3-draft"), "Has draft header");
        sub.assert_bytes_eq(req.header("sec-webtransport-http3-draft"), "draft16", "Draft is draft16");

        sub.assert_true(wing::is_webtransport_connect_request(req), "is_webtransport_connect_request returns true");

        var bad_req = wing::Request { .. };
        sub.assert_false(wing::is_webtransport_connect_request(bad_req), "Non-CONNECT request is rejected");

        var session = wing::WebTransportSession { session_id: 104, .. };
        var resp_200 = wing::Response { status_code: 200, .. };
        wing::format_webtransport_connect_response(resp_200);
        sub.assert_bytes_eq(resp_200.header("sec-webtransport-http3-draft"), "draft16", "Response draft header is draft16");

        let ok = wing::handle_webtransport_response(resp_200, session);
        sub.assert_true(ok, "Session activated on 200 OK");
        sub.assert_true(session.is_active, "Session is active");

        var resp_500 = wing::Response { status_code: 500, .. };
        let fail = wing::handle_webtransport_response(resp_500, session);
        sub.assert_false(fail, "Session rejected on 500 Error");
        sub.assert_false(session.is_active, "Session deactivated");
    };

    t.run("WebTransport Datagram Framing") { sub =>
        let payload = "RAW_UNRELIABLE_TELEMETRY_SAMPLE";
        let session_id: u64 = 40;

        var wire: u8[>..] = [];
        wing::encode_webtransport_datagram(session_id, payload, wire);
        sub.assert_gt(wire.len, payload.len, "Framing includes varint session id");

        var decoded = wing::WebTransportDatagram { .. };
        let ok_dec = wing::decode_webtransport_datagram(wire[..], decoded);
        sub.assert_true(ok_dec, "Datagram decoded");
        sub.assert_eq(decoded.session_id, 40, "Session ID is 40");
        sub.assert_bytes_eq(decoded.payload[..], payload, "Payload matches original bytes");
    };

    t.run("RFC 9221 QUIC DATAGRAM Frame Codec") { sub =>
        let datagram_msg = "LOW_LATENCY_POSITION_UPDATE_X100_Y200";
        var frame_wire: u8[>..] = [];
        wing::encode_quic_datagram_frame(datagram_msg, frame_wire);

        sub.assert_gt(frame_wire.len, datagram_msg.len, "Frame wire includes type and length varints");

        var extracted_msg: u8[>..] = [];
        let ok_frame = wing::decode_quic_datagram_frame(frame_wire[..], extracted_msg);
        sub.assert_true(ok_frame, "QUIC DATAGRAM frame decoded");
        sub.assert_bytes_eq(extracted_msg[..], datagram_msg, "Extracted payload matches verbatim");

        // Oversized datagram (> 1500B) rejection without panic
        var huge_dgram: u8[>..] = [];
        huge_dgram.push(0x01); // quarter_stream_id = 1 (session_id = 4)
        huge_dgram.push(0x00); // context_id = 0
        for i in 1600 { huge_dgram.push('X'); }
        var dec_huge = wing::WebTransportDatagram { .. };
        sub.assert_false(wing::decode_webtransport_datagram(huge_dgram[..], dec_huge), "Oversized >1500B datagram rejected safely");

        // Truncated QUIC DATAGRAM frame with huge 62-bit varint length rejected without overflow
        let trunc_quic: u8[9] = [0x31, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF];
        var out_trunc: u8[>..] = [];
        sub.assert_false(wing::decode_quic_datagram_frame(trunc_quic[..], out_trunc), "Huge 62-bit varint length rejected safely");
    };
}

// ----------------------------------------------------------------------------
// 11. WebTransport Stream Framing
// ----------------------------------------------------------------------------
fn test_webtransport_stream_framing(t: lit::T&) {
    t.run("Unidirectional Stream Framing (Type 0x54)") { sub =>
        let session_id: u64 = 256;
        var wire: u8[..32] = [];
        wing::encode_webtransport_uni_stream_header(session_id, wire);

        // 0x54 (84) > 63, so RFC 9000 varint encodes it as 2 bytes [0x40, 0x54]
        sub.assert_eq(wire[0], 0x40, "Varint 2-byte prefix 0x40");
        sub.assert_eq(wire[1], 0x54, "Stream type is 0x54");

        var decoded = wing::WebTransportUniStreamHeader { .. };
        let ok = wing::decode_webtransport_uni_stream_header(wire[..], decoded);
        sub.assert_true(ok, "Uni stream header decoded successfully");
        sub.assert_eq(decoded.session_id, 256, "Decoded session ID matches");
        sub.assert_eq(decoded.header_len, wire.len, "Header length matches encoded bytes");

        // Invalid stream type
        var invalid_wire: u8[..32] = [];
        invalid_wire.push(0x40);
        invalid_wire.push(0x55);
        invalid_wire.push(0x01);
        var bad_decoded = wing::WebTransportUniStreamHeader { .. };
        sub.assert_false(wing::decode_webtransport_uni_stream_header(invalid_wire[..], bad_decoded), "Rejected non-0x54 stream type");
    };

    t.run("Bidirectional Stream Opening Framing (Signal 0x41)") { sub =>
        let session_id: u64 = 1024;
        var wire: u8[..32] = [];
        wing::encode_webtransport_bidi_stream_header(session_id, wire);

        // 0x41 (65) > 63, so RFC 9000 varint encodes it as 2 bytes [0x40, 0x41]
        sub.assert_eq(wire[0], 0x40, "Varint 2-byte prefix 0x40");
        sub.assert_eq(wire[1], 0x41, "Stream signal is 0x41");

        var decoded = wing::WebTransportBidiStreamHeader { .. };
        let ok = wing::decode_webtransport_bidi_stream_header(wire[..], decoded);
        sub.assert_true(ok, "Bidi stream header decoded successfully");
        sub.assert_eq(decoded.session_id, 1024, "Decoded session ID matches");
        sub.assert_eq(decoded.header_len, wire.len, "Header length matches encoded bytes");

        // Invalid signal
        var invalid_wire: u8[..32] = [];
        invalid_wire.push(0x40);
        invalid_wire.push(0x42);
        invalid_wire.push(0x02);
        var bad_decoded = wing::WebTransportBidiStreamHeader { .. };
        sub.assert_false(wing::decode_webtransport_bidi_stream_header(invalid_wire[..], bad_decoded), "Rejected non-0x41 signal");
    };
}

// ----------------------------------------------------------------------------
// 12. WebTransport Error Code Mapping
// ----------------------------------------------------------------------------
fn test_webtransport_error_mapping(t: lit::T&) {
    t.run("Application Error Translation to HTTP/3 and Back") { sub =>
        let test_codes: u32[7] = [0, 1, 29, 30, 31, 1000, 0xFFFFFFFF];
        for i in 7 {
            let app_err = test_codes[i];
            let h3_err = wing::webtransport_code_to_http_code(app_err);

            sub.assert_ge(h3_err, rfc::WEBTRANSPORT_ERROR_FIRST, "H3 error >= lower bound");
            sub.assert_le(h3_err, rfc::WEBTRANSPORT_ERROR_LAST, "H3 error <= upper bound");

            // Verify no GREASE collision: (h3_err - 0x21) % 0x1F != 0
            let is_grease = ((h3_err - 0x21) % 0x1F) == 0;
            sub.assert_false(is_grease, "Mapped H3 error is not a GREASE point");

            let recovered, ok = wing::http_code_to_webtransport_code(h3_err);
            sub.assert_true(ok, "HTTP error translated back to WebTransport error");
            sub.assert_eq(recovered, app_err, "Recovered application error matches original");
        }

        // Out of bound checks
        let _, bad1 = wing::http_code_to_webtransport_code(rfc::WEBTRANSPORT_ERROR_FIRST - 1);
        sub.assert_false(bad1, "Underflow H3 error rejected");

        let _, bad2 = wing::http_code_to_webtransport_code(rfc::WEBTRANSPORT_ERROR_LAST + 1);
        sub.assert_false(bad2, "Overflow H3 error rejected");
    };
}

// ----------------------------------------------------------------------------
// 13. WebTransport Capsule Codecs
// ----------------------------------------------------------------------------
fn test_webtransport_capsules(t: lit::T&) {
    t.run("CLOSE_WEBTRANSPORT_SESSION Capsule") { sub =>
        let err_code: u32 = 404;
        let reason = "RESOURCE_NOT_FOUND_ON_STREAM";
        var wire: u8[..256] = [];
        wing::encode_webtransport_close_session(err_code, reason, wire);

        var c, ok_c = wing::parse_http_capsule(wire[..]);
        sub.assert_true(ok_c, "HTTP Capsule parsed from wire");
        sub.assert_eq(c.capsule_type, rfc::CAPSULE_CLOSE_WEBTRANSPORT, "Capsule type is CLOSE_WEBTRANSPORT");

        var decoded = wing::WebTransportCloseSession { .. };
        let ok_dec = wing::decode_webtransport_close_session(c.payload, decoded);
        sub.assert_true(ok_dec, "Close session payload decoded");
        sub.assert_eq(decoded.error_code, 404, "Error code matches 404");
        sub.assert_bytes_eq(decoded.reason[..], reason, "Reason matches original message");
    };

    t.run("DRAIN_WEBTRANSPORT_SESSION Capsule") { sub =>
        var wire: u8[..64] = [];
        wing::encode_webtransport_drain_session(wire);

        var c, ok_c = wing::parse_http_capsule(wire[..]);
        sub.assert_true(ok_c, "Drain capsule parsed");
        sub.assert_eq(c.capsule_type, rfc::CAPSULE_DRAIN_WEBTRANSPORT, "Capsule type is DRAIN_WEBTRANSPORT");
        sub.assert_true(wing::decode_webtransport_drain_session(c.payload), "Drain payload is valid (0-length)");

        var bad_payload: u8[2] = [1, 2];
        sub.assert_false(wing::decode_webtransport_drain_session(bad_payload[..]), "Non-empty drain payload is invalid");
    };

    t.run("Stream Reset and Stop Sending Capsules") { sub =>
        // WT_RESET_STREAM
        var r_wire: u8[..64] = [];
        wing::encode_webtransport_reset_stream(12, 503, r_wire);
        var c_r, ok_cr = wing::parse_http_capsule(r_wire[..]);
        sub.assert_true(ok_cr, "Reset stream capsule parsed");
        sub.assert_eq(c_r.capsule_type, rfc::CAPSULE_WT_RESET_STREAM, "Capsule type is WT_RESET_STREAM");

        var reset_dec = wing::WebTransportStreamReset { .. };
        sub.assert_true(wing::decode_webtransport_reset_stream(c_r.payload, reset_dec), "Reset payload decoded");
        sub.assert_eq(reset_dec.stream_id, 12, "Reset stream ID is 12");
        sub.assert_eq(reset_dec.error_code, 503, "Reset error code is 503");

        // WT_STOP_SENDING
        var s_wire: u8[..64] = [];
        wing::encode_webtransport_stop_sending(18, 499, s_wire);
        var c_s, ok_cs = wing::parse_http_capsule(s_wire[..]);
        sub.assert_true(ok_cs, "Stop sending capsule parsed");
        sub.assert_eq(c_s.capsule_type, rfc::CAPSULE_WT_STOP_SENDING, "Capsule type is WT_STOP_SENDING");

        var stop_dec = wing::WebTransportStreamStopSending { .. };
        sub.assert_true(wing::decode_webtransport_stop_sending(c_s.payload, stop_dec), "Stop sending payload decoded");
        sub.assert_eq(stop_dec.stream_id, 18, "Stop sending stream ID is 18");
        sub.assert_eq(stop_dec.error_code, 499, "Stop sending error code is 499");
    };
}

// ----------------------------------------------------------------------------
// 14. WebTransport Session Lifecycle
// ----------------------------------------------------------------------------
fn test_webtransport_session_lifecycle(t: lit::T&) {
    t.run("Session Transitions: Active -> Draining -> Closed") { sub =>
        var session = wing::WebTransportSession { session_id: 88, is_active: true, .. };
        sub.assert_true(wing::is_webtransport_session_open(session), "Session is initially open");

        wing::drain_webtransport_session(session);
        sub.assert_true(session.is_draining, "Session is draining");
        sub.assert_true(session.is_active, "Session is still active while draining");
        sub.assert_false(wing::is_webtransport_session_open(session), "is_webtransport_session_open is false while draining");

        wing::close_webtransport_session(session, 200, "CLEAN_DISCONNECT");
        sub.assert_false(session.is_active, "Session is closed");
        sub.assert_eq(session.close_code, 200, "Close code matches");
        sub.assert_bytes_eq(session.close_reason[..], "CLEAN_DISCONNECT", "Close reason matches");
        sub.assert_false(wing::is_webtransport_session_open(session), "Closed session is not open");
    };
}

// ----------------------------------------------------------------------------
// 15. WebTransport Stream Demuxing & Session Routing
// ----------------------------------------------------------------------------
fn test_webtransport_stream_demuxing(t: lit::T&) {
    t.run("1. Bidirectional Stream Wire Demuxing (Signal 0x41 & Direct Session ID)") { sub =>
        // Case A: draft-ietf-webtrans-http3 Section 4.2 with 0x41 signal
        // Wire: 0x40, 0x41 (signal 65) || 0x1A (session ID 26) || payload "TELEMETRY"
        let bidi_wire_sig: u8[12] = [
            0x40, 0x41, 0x1A,
            'T', 'E', 'L', 'E', 'M', 'E', 'T', 'R', 'Y',
        ];
        let sid_a, payload_a, ok_a = wing::demux_webtransport_bidi_stream(bidi_wire_sig[..]);
        sub.assert_true(ok_a, "Demuxed bidi stream with 0x41 signal");
        sub.assert_eq(sid_a, 26, "Session ID is 26");
        sub.assert_bytes_eq(payload_a, "TELEMETRY", "Extracted payload matches");

        // Case B: draft-ietf-webtrans-http3 Section 4.2 requires 0x41 signal; streams lacking it are rejected
        // Wire: 0x1A (session ID 26) without 0x41 signal || payload "DIRECT_DATA"
        let bidi_wire_direct: u8[12] = [
            0x1A,
            'D', 'I', 'R', 'E', 'C', 'T', '_', 'D', 'A', 'T', 'A',
        ];
        let _, _, ok_b = wing::demux_webtransport_bidi_stream(bidi_wire_direct[..]);
        sub.assert_false(ok_b, "Demuxing bidi stream lacking 0x41 signal is rejected");

        // Negative check: empty wire
        let empty_wire: u8[0] = [];
        let _, _, ok_c_empty = wing::demux_webtransport_bidi_stream(empty_wire[..]);
        sub.assert_false(ok_c_empty, "Empty wire fails");
    };

    t.run("2. Unidirectional Stream Wire Demuxing (Type 0x54 + Session ID)") { sub =>
        // Wire: 0x40, 0x54 (type 84) || 0x2A (session ID 42) || payload "UNI_PAYLOAD"
        let uni_wire: u8[14] = [
            0x40, 0x54, 0x2A,
            'U', 'N', 'I', '_', 'P', 'A', 'Y', 'L', 'O', 'A', 'D',
        ];
        let sid, payload, ok = wing::demux_webtransport_uni_stream(uni_wire[..]);
        sub.assert_true(ok, "Demuxed uni stream with type 0x54");
        sub.assert_eq(sid, 42, "Session ID is 42");
        sub.assert_bytes_eq(payload, "UNI_PAYLOAD", "Payload matches");

        // Wrong stream type (0x55 instead of 0x54)
        let bad_uni_wire: u8[4] = [0x40, 0x55, 0x2A, 'X'];
        let _, _, bad_ok = wing::demux_webtransport_uni_stream(bad_uni_wire[..]);
        sub.assert_false(bad_ok, "Wrong stream type rejected");
    };

    t.run("3. WebTransportDemuxer Session Lifecycle and Routing State Machine") { sub =>
        var demuxer = wing::WebTransportDemuxer { .. };

        // 1. Register Session 100
        sub.assert_true(wing::register_webtransport_session(demuxer, 100), "Registered session 100");
        let st1, ok_st1 = wing::get_webtransport_session_state(demuxer, 100);
        sub.assert_true(ok_st1, "Queried session 100 state");
        sub.assert_eq(st1, wing::WebTransportSessionState.Active, "Session 100 is Active");

        // 2. Dispatch bidirectional initial stream on QUIC Stream 4 (client bidi: stream_id & 0x02 == 0)
        // Wire: 0x40, 0x41 (signal 65) || 0x40, 0x64 (session 100) || payload "FRAME_1"
        var bidi_pkt1: u8[11] = [
            0x40, 0x41,
            0x40, 0x64,
            'F', 'R', 'A', 'M', 'E', '_', '1',
        ];
        var out_p1 = wing::WebTransportStreamPayload { .. };
        let ok_d1 = wing::demux_webtransport_stream(demuxer, 4, bidi_pkt1[..], false, out_p1);
        sub.assert_true(ok_d1, "Dispatched initial bidi frame on stream 4");
        sub.assert_eq(out_p1.session_id, 100, "Session ID is 100");
        sub.assert_bytes_eq(out_p1.payload, "FRAME_1", "Payload is FRAME_1");
        sub.assert_eq(out_p1.kind, wing::WebTransportStreamKind.Bidirectional, "Kind is Bidirectional");
        sub.assert_false(out_p1.fin, "FIN is false");

        // 3. Dispatch continuation chunk on the same open stream 4 (no header!)
        let chunk2: const u8[:] = "_CONT";
        var out_p2 = wing::WebTransportStreamPayload { .. };
        let ok_d2 = wing::demux_webtransport_stream(demuxer, 4, chunk2, true, out_p2);
        sub.assert_true(ok_d2, "Dispatched continuation chunk on stream 4");
        sub.assert_eq(out_p2.session_id, 100, "Session ID is 100");
        sub.assert_bytes_eq(out_p2.payload, "_CONT", "Payload is _CONT");
        sub.assert_true(out_p2.fin, "FIN is true (stream closed)");

        // 4. Dispatch unidirectional stream on QUIC Stream 3 (client uni: stream_id & 0x02 != 0)
        // Wire: 0x40, 0x54 (type 0x54) || 0x40, 0x64 (session 100) || payload "UNI_STREAM"
        var uni_pkt: u8[14] = [
            0x40, 0x54, 0x40, 0x64,
            'U', 'N', 'I', '_', 'S', 'T', 'R', 'E', 'A', 'M',
        ];
        var out_p3 = wing::WebTransportStreamPayload { .. };
        let ok_d3 = wing::demux_webtransport_stream(demuxer, 3, uni_pkt[..], true, out_p3);
        sub.assert_true(ok_d3, "Dispatched unidirectional stream 3");
        sub.assert_eq(out_p3.session_id, 100, "Session ID is 100");
        sub.assert_bytes_eq(out_p3.payload, "UNI_STREAM", "Payload is UNI_STREAM");
        sub.assert_eq(out_p3.kind, wing::WebTransportStreamKind.Unidirectional, "Kind is Unidirectional");

        // Verify session accounting
        sub.assert_eq(demuxer.total_dispatched, 3, "Total dispatched frames is 3");
        sub.assert_eq(demuxer.sessions[0].streams_count, 2, "2 streams initiated for session 100");
        sub.assert_eq(demuxer.sessions[0].frames_received, 3, "3 frames received for session 100");
        sub.assert_eq(demuxer.sessions[0].bytes_received, 22, "22 bytes received for session 100 (7 + 5 + 10)");

        // 5. Drain session 100 (draft Section 8.2: new streams rejected)
        sub.assert_true(wing::drain_webtransport_demuxer_session(demuxer, 100), "Drained session 100");
        let st2, _ = wing::get_webtransport_session_state(demuxer, 100);
        sub.assert_eq(st2, wing::WebTransportSessionState.Draining, "Session 100 is Draining");

        // Attempting to open a NEW stream on draining session MUST be rejected
        // Wire: 0x40, 0x41 (signal 65) || 0x40, 0x64 (session 100) || payload "NEW!!!"
        var new_bidi: u8[10] = [
            0x40, 0x41,
            0x40, 0x64,
            'N', 'E', 'W', '!', '!', '!',
        ];
        var out_reject = wing::WebTransportStreamPayload { .. };
        let ok_reject = wing::demux_webtransport_stream(demuxer, 8, new_bidi[..], false, out_reject);
        sub.assert_false(ok_reject, "New stream rejected on draining session");
        sub.assert_gt(demuxer.dropped_frames, 0, "Dropped frames incremented");

        // 6. Close session 100
        sub.assert_true(wing::close_webtransport_demuxer_session(demuxer, 100, 200, "NORMAL_CLOSURE"), "Closed session 100");
        let st3, _ = wing::get_webtransport_session_state(demuxer, 100);
        sub.assert_eq(st3, wing::WebTransportSessionState.Closed, "Session 100 is Closed");
        sub.assert_eq(demuxer.sessions[0].close_code, 200, "Close code 200");
        sub.assert_bytes_eq(demuxer.sessions[0].close_reason[..], "NORMAL_CLOSURE", "Close reason recorded");
    };
}

// 16. HTTP/3 Bug Hunter Audit Regressions (F001-F006)
fn test_h3_audit_regressions(t: lit::T&) {
    t.run("F001: Reject signed Content-Length (+5, -0) per RFC 9110 §8.6") { sub =>
        let settings = wing::H3Settings { .. };
        var conn = internal::new_h3_server_connection(settings);
        var qpack1: u8[..128] = [0x00, 0x00];
        internal::encode_qpack_field(qpack1, ":method", "POST");
        internal::encode_qpack_field(qpack1, ":scheme", "https");
        internal::encode_qpack_field(qpack1, ":path", "/upload");
        internal::encode_qpack_field(qpack1, "content-length", "+5");
        var frame1: u8[..160] = [];
        let _ = internal::encode_h3_headers_frame(frame1, qpack1[..]);
        let err = conn.handle_stream_data(0, true, frame1[..], false);
        sub.assert_eq(err, rfc::H3_ERR_GENERAL_PROTOCOL, "+5 Content-Length rejected");

        var conn2 = internal::new_h3_server_connection(settings);
        var qpack2: u8[..128] = [0x00, 0x00];
        internal::encode_qpack_field(qpack2, ":method", "POST");
        internal::encode_qpack_field(qpack2, ":scheme", "https");
        internal::encode_qpack_field(qpack2, ":path", "/upload");
        internal::encode_qpack_field(qpack2, "content-length", "-0");
        var frame2: u8[..160] = [];
        let _ = internal::encode_h3_headers_frame(frame2, qpack2[..]);
        let err2 = conn2.handle_stream_data(0, true, frame2[..], false);
        sub.assert_eq(err2, rfc::H3_ERR_GENERAL_PROTOCOL, "-0 Content-Length rejected");
    };

    t.run("F002: 204/304 with non-zero Content-Length and 0 DATA bytes + FIN before headers") { sub =>
        let settings = wing::H3Settings { .. };
        var c_conn = internal::new_h3_client_connection(settings);
        let sid, _ = c_conn.open_request_stream();
        var out_hdr: u8[..256] = [];
        var extra = wing::HeaderMap { .. };
        let _ = c_conn.send_request_headers(sid, "GET", "https", "example.com", "/res", extra, true, out_hdr);

        var resp_qpack: u8[..128] = [0x00, 0x00];
        internal::encode_qpack_field(resp_qpack, ":status", "204");
        internal::encode_qpack_field(resp_qpack, "content-length", "42");
        var resp_frame: u8[..160] = [];
        let _ = internal::encode_h3_headers_frame(resp_frame, resp_qpack[..]);
        let err_204 = c_conn.handle_stream_data(sid, true, resp_frame[..], true);
        sub.assert_eq(err_204, rfc::H3_ERR_NO_ERROR, "204 with CL=42 and 0 DATA bytes succeeds per RFC 9114 §4.1.2");

        var s_conn = internal::new_h3_server_connection(settings);
        let empty_payload: u8[0] = [];
        let err_fin = s_conn.handle_stream_data(0, true, empty_payload[..], true);
        sub.assert_ne(err_fin, rfc::H3_ERR_NO_ERROR, "FIN on bidi stream before final headers must fail");
    };

    t.run("F003: Reject oversized :method and bounded frame encoding overflow") { sub =>
        let settings = wing::H3Settings { .. };
        var conn = internal::new_h3_server_connection(settings);
        var qpack_m: u8[..128] = [0x00, 0x00];
        internal::encode_qpack_field(qpack_m, ":method", "OVERSIZEDMETHOD17");
        internal::encode_qpack_field(qpack_m, ":scheme", "https");
        internal::encode_qpack_field(qpack_m, ":path", "/");
        var frame_m: u8[..160] = [];
        let _ = internal::encode_h3_headers_frame(frame_m, qpack_m[..]);
        let err = conn.handle_stream_data(0, true, frame_m[..], false);
        sub.assert_eq(err, rfc::H3_ERR_GENERAL_PROTOCOL, "Oversized :method (>16 bytes) rejected instead of silent drop");

        var tiny_out: u8[..4] = [];
        let ok_data = internal::encode_h3_data_frame(tiny_out, "12345");
        sub.assert_false(ok_data, "encode_h3_data_frame returns false when payload exceeds buffer cap");
        sub.assert_eq(tiny_out.len, 0, "tiny_out remains clean on failed encode_h3_data_frame");
    };

    t.run("F004/F005: PUSH_PROMISE H3_ERR_ID_ERROR closes connection and Server GOAWAY Push ID check") { sub =>
        let settings = wing::H3Settings { .. };
        var c_conn = internal::new_h3_client_connection(settings);
        let sid, _ = c_conn.open_request_stream();
        var out_hdr: u8[..256] = [];
        var extra = wing::HeaderMap { .. };
        let _ = c_conn.send_request_headers(sid, "GET", "https", "example.com", "/", extra, false, out_hdr);
        var pp_frame: u8[..64] = [];
        let _ = internal::encode_h3_push_promise(pp_frame, 0, [0x00, 0x00]);
        let err_pp = c_conn.handle_stream_data(sid, true, pp_frame[..], false);
        sub.assert_eq(err_pp, rfc::H3_ERR_ID_ERROR, "PUSH_PROMISE without MAX_PUSH_ID returns H3_ERR_ID_ERROR");
        sub.assert_eq(c_conn.state, internal::H3ConnState.Closed, "Connection state transitions to Closed on H3_ERR_ID_ERROR");
        sub.assert_eq(c_conn.error_code, rfc::H3_ERR_ID_ERROR, "Connection error_code recorded");
    };

    t.run("F006: QPACK stream referencing >8 dynamic entries does not leak ref_count") { sub =>
        var tbl = internal::new_qpack_table(4096, 4);
        for i in 12 {
            var name: u8[..16] = [];
            name.append("x-dyn-");
            name.push(('a' + (i as u8)));
            sub.assert_true(internal::qpack_insert_literal(tbl, name[..], "val"), "inserted dyn entry");
            sub.assert_true(internal::qpack_track_stream_ref(tbl, 4, (i as u64)), "tracked stream ref");
        }
        internal::qpack_cancel_stream(tbl, 4);
        for i in tbl.entries.len {
            sub.assert_eq(tbl.entries[i].ref_count, 0, "all 12 entries unpinned after stream cancel");
        }
    };
}

// --- Component: nghttp3_vendor_conformance ---
// Ported test vectors from vendor/nghttp3 (tests/nghttp3_qpack_test.c,
// tests/nghttp3_http_test.c, tests/nghttp3_conn_test.c):
// - Required Insert Count (RIC) wrap-around reconstruction (test_nghttp3_qpack_decoder_reconstruct_ricnt)
// - Huffman all-ones 4-byte [0xFF, 0xFF, 0xFF, 0xFF] rejection (test_nghttp3_qpack_huffman_decode_fail_state)
// - Header value SWAR boundary checks at 31B, 32B, 64B (test_nghttp3_check_header_value)
// - Post-Base Dynamic Indexed Field & Literal Field with Post-Base Name Reference (RFC 9204 §4.5.3, §4.5.5)
// - Out-of-order stream decoding and stream cancellation instruction (0x40 | stream_id)
// ----------------------------------------------------------------------------
// 17. nghttp3 Vendor Conformance Vectors
// ----------------------------------------------------------------------------
fn test_nghttp3_vendor_conformance(t: lit::T&) {
    t.run("NGHTTP3-QPACK-01: Required Insert Count (RIC) Modulo Wrap-Around Reconstruction") { sub =>
        // test_nghttp3_qpack_decoder_reconstruct_ricnt (RFC 9204 §4.5.1.1):
        // max_entries = 4096 / 32 = 128; full_range = 2 * 128 = 256
        let cap:       u64    = 4096;
        let ric_cases: u64[6] = [1, 127, 128, 255, 256, 300];
        for i in 6 {
            let orig_ric = ric_cases[i];
            let enc_ric = internal::encode_ric(orig_ric, cap);
            let dec_ric, err = internal::decode_ric(enc_ric, orig_ric + 10, cap);
            sub.assert_eq(err, internal::QpackError.None, "RIC reconstructed cleanly across modulo boundary");
            sub.assert_eq(dec_ric, orig_ric, "reconstructed RIC equals original RIC");
        }

        // Invalid encoded_ric != 0 when max_table_capacity == 0 MUST fail
        let _, err_zero_cap = internal::decode_ric(1, 0, 0);
        sub.assert_eq(
            err_zero_cap,
            internal::QpackError.DecompressionFailed,
            "non-zero encoded RIC with 0 table capacity rejected",
        );
    };

    t.run("NGHTTP3-QPACK-02: 4-Byte All-Ones Huffman Failure & Post-Base Dynamic Indexing") { sub =>
        // test_nghttp3_qpack_huffman_decode_fail_state: 4 bytes of 0xFF
        let all_ones: u8[4] = [0xFF, 0xFF, 0xFF, 0xFF];
        var huff_out: u8[..32] = [];
        sub.assert_false(internal::huff_decode_bytes(all_ones[..], huff_out), "4-byte 0xFFFFFFFF Huffman rejected");

        // Post-Base Dynamic Indexed Field (0001xxxx = 0x10 | post_base_idx)
        // Insert 2 entries: abs 0 ("x-k0": "v0"), abs 1 ("x-k1": "v1").
        // Set RIC = 2, Base = 1 (Sign=1, DeltaBase = RIC - Base - 1 = 0 -> byte1 = 0x80).
        // Post-base index 0 resolves to Base + 0 = abs_idx 1 ("x-k1": "v1")!
        var tbl = internal::new_qpack_table(4096, 16);
        sub.assert_true(internal::qpack_insert_literal(tbl, "x-k0", "v0"), "insert abs 0");
        sub.assert_true(internal::qpack_insert_literal(tbl, "x-k1", "v1"), "insert abs 1");

        var sec: u8[..64] = [];
        let enc_ric = internal::encode_ric(2, tbl.capacity_bytes);
        sec.push(enc_ric as u8);
        sec.push(0x80); // Sign=1 (negative delta), DeltaBase=0 -> Base = 2 - 0 - 1 = 1
        sec.push(0xD9); // Static :status 200
        sec.push(0x80); // Relative index 0 -> Base - 1 - 0 = 0 ("x-k0": "v0")
        sec.push(0x10); // Post-base index 0 -> Base + 0 = 1 ("x-k1": "v1")

        var out_fields: internal::HeaderField[>..] = [];
        let err = internal::decode_qpack_section(tbl, sec[..], out_fields, 16384);
        sub.assert_eq(err, internal::QpackError.None, "post-base dynamic indexed section decoded");
        sub.assert_eq(out_fields.len, 3, "3 fields decoded");
        sub.assert_eq(out_fields[1].name[..], "x-k0", "relative index 0 resolved to abs 0");
        sub.assert_eq(out_fields[1].value[..], "v0", "relative index 0 value matches");
        sub.assert_eq(out_fields[2].name[..], "x-k1", "post-base index 0 resolved to abs 1");
        sub.assert_eq(out_fields[2].value[..], "v1", "post-base index 0 value matches");
    };

    t.run("NGHTTP3-HTTP-01: Header Value & Name SWAR Boundary Checks (test_nghttp3_check_header_value)") { sub =>
        // Valid 32B and 64B header values (exercising 8-byte SWAR / 16-byte SIMD boundaries)
        let good31 = "0123456789abcdef0123456789abcde";
        let good32 = "0123456789abcdef0123456789abcdef";
        let good64 = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        sub.assert_true(wing::is_valid_header_value(good31), "31-byte printable value valid");
        sub.assert_true(wing::is_valid_header_value(good32), "32-byte printable value valid");
        sub.assert_true(wing::is_valid_header_value(good64), "64-byte printable value valid");
        sub.assert_true(wing::is_valid_header_value(""), "empty header value valid");

        // Control chars (0x00..0x08, 0x0A..0x1F, 0x7F) at index 31 (end of 32-byte block) MUST fail
        let bad_ctl_bytes: u8[6] = [0x00, 0x07, 0x0A, 0x0D, 0x1F, 0x7F];
        for k in 6 {
            var buf32: u8[32] = ['a'; 32];
            buf32[31] = bad_ctl_bytes[k];
            sub.assert_false(wing::is_valid_header_value(buf32[..]), "control char at byte 31 rejected");
        }

        // Horizontal tab (0x09) and space (0x20) inside header value are valid
        var tab_mid: u8[32] = ['a'; 32];
        tab_mid[15] = '\t';
        tab_mid[16] = ' ';
        sub.assert_true(wing::is_valid_header_value(tab_mid[..]), "interior HTAB and SP valid in header value");
    };

    t.run("NGHTTP3-CONN-01: Decoder Stream Cancellation & Encoder Dynamic Table Sync") { sub =>
        var enc_tbl = internal::new_qpack_table(4096, 16);
        var dec_tbl = internal::new_qpack_table(4096, 16);

        // Stream 8 pins dynamic entry 0, Stream 12 pins dynamic entry 1
        sub.assert_true(internal::qpack_insert_literal(enc_tbl, "x-stream-8", "alpha"), "insert entry 0");
        sub.assert_true(internal::qpack_insert_literal(enc_tbl, "x-stream-12", "bravo"), "insert entry 1");
        sub.assert_true(internal::qpack_track_stream_ref(enc_tbl, 8, 0), "stream 8 pins entry 0");
        sub.assert_true(internal::qpack_track_stream_ref(enc_tbl, 12, 1), "stream 12 pins entry 1");
        sub.assert_true(internal::qpack_track_unacked_stream(enc_tbl, 12, 2), "stream 12 tracks RIC=2");

        // Decoder emits Stream Cancellation for stream 8 (01xxxxxx = 0x48)
        // followed by Section Acknowledgment for stream 12 (1xxxxxxx = 0x8C)
        let dec_wire: u8[2] = [0x48, 0x8C];
        let next1, err1 = internal::qpack_process_decoder_instruction(enc_tbl, dec_wire[..], 0);
        sub.assert_eq(err1, internal::QpackError.None, "stream 8 cancellation processed");
        sub.assert_eq(next1, 1, "consumed 1 byte for stream cancellation");
        sub.assert_eq(enc_tbl.entries[0].ref_count, 0, "entry 0 unpinned after stream 8 cancellation");

        let next2, err2 = internal::qpack_process_decoder_instruction(enc_tbl, dec_wire[..], next1);
        sub.assert_eq(err2, internal::QpackError.None, "stream 12 section ack processed");
        sub.assert_eq(next2, 2, "consumed 2nd byte for section ack");
        sub.assert_eq(enc_tbl.known_rcvd_count, 2, "known_rcvd_count advanced to 2");

        // Encoder instruction stream synced into dec_tbl
        var inst_wire: u8[..64] = [];
        inst_wire.push(0x4A); // Insert literal name (len 10)
        inst_wire.append("x-stream-8");
        inst_wire.push(0x05); // val len 5
        inst_wire.append("alpha");
        let _, err_inst = internal::qpack_process_encoder_instruction(dec_tbl, inst_wire[..], 0);
        sub.assert_eq(err_inst, internal::QpackError.None, "decoder processed encoder literal insert");
        sub.assert_eq(dec_tbl.insert_count, 1, "decoder insert_count is 1");
    };
}

// 18. Ported Control Stream, SETTINGS, GOAWAY & Request Framing Semantics (vendor/nghttp3/tests/nghttp3_conn_test.c)
fn test_nghttp3_conn_and_http_semantics(t: lit::T&) {
    t.run("NGHTTP3-CONN-02: Control Stream First-Frame SETTINGS & Reserved H2 Settings/Frames Rejection (test_nghttp3_conn_read_control)") { sub =>
        let settings = wing::H3Settings { .. };

        // 1. Control stream starting with GOAWAY, CANCEL_PUSH, DATA, or HEADERS before SETTINGS -> H3_ERR_MISSING_SETTINGS
        let non_settings_first: u64[4] = [
            rfc::H3_FRAME_GOAWAY,
            rfc::H3_FRAME_CANCEL_PUSH,
            rfc::H3_FRAME_DATA,
            rfc::H3_FRAME_HEADERS,
        ];
        for ftype in non_settings_first {
            var conn = internal::new_h3_client_connection(settings);
            var wire: u8[..32] = [];
            internal::quic_encode_varint(wire, rfc::H3_STREAM_CONTROL);
            internal::encode_h3_frame_header(wire, ftype, 1);
            wire.push(0x00);
            let err = conn.handle_stream_data(3, false, wire[..], false);
            sub.assert_eq(err, rfc::H3_ERR_MISSING_SETTINGS, "non-SETTINGS first frame on control stream returns H3_ERR_MISSING_SETTINGS");
        }

        // 2. Duplicate SETTINGS frame on control stream -> H3_ERR_FRAME_UNEXPECTED
        var conn_dup = internal::new_h3_client_connection(settings);
        var wire_dup: u8[..64] = [];
        internal::quic_encode_varint(wire_dup, rfc::H3_STREAM_CONTROL);
        internal::encode_h3_settings_frame(wire_dup, settings);
        internal::encode_h3_settings_frame(wire_dup, settings);
        let err_dup = conn_dup.handle_stream_data(3, false, wire_dup[..], false);
        sub.assert_eq(err_dup, rfc::H3_ERR_FRAME_UNEXPECTED, "second SETTINGS frame on control stream rejected");

        // 3. Reserved HTTP/2 Setting IDs (0x00, 0x02, 0x03, 0x04, 0x05) -> H3_ERR_SETTINGS_ERROR (RFC 9114 §7.2.4.1)
        let reserved_setting_ids: u64[5] = [0x00, 0x02, 0x03, 0x04, 0x05];
        for rsid in reserved_setting_ids {
            var raw_set: u8[..16] = [];
            internal::quic_encode_varint(raw_set, rsid);
            internal::quic_encode_varint(raw_set, 1);
            var parsed_s = wing::H3Settings { .. };
            let err_rs = internal::parse_h3_settings_frame(raw_set[..], parsed_s);
            sub.assert_eq(err_rs, rfc::H3_ERR_SETTINGS_ERROR, "reserved HTTP/2 setting ID rejected with H3_ERR_SETTINGS_ERROR");
        }

        // 4. Forbidden HTTP/2 frame types (0x02 PRIORITY, 0x06 PING, 0x08 WINDOW_UPDATE, 0x09 CONTINUATION) -> H3_ERR_FRAME_UNEXPECTED
        let forbidden_h2_frames: u64[4] = [0x02, 0x06, 0x08, 0x09];
        for h2f in forbidden_h2_frames {
            var conn_f = internal::new_h3_client_connection(settings);
            var wire_f: u8[..64] = [];
            internal::quic_encode_varint(wire_f, rfc::H3_STREAM_CONTROL);
            internal::encode_h3_settings_frame(wire_f, settings);
            internal::encode_h3_frame_header(wire_f, h2f, 0);
            let err_f = conn_f.handle_stream_data(3, false, wire_f[..], false);
            sub.assert_eq(err_f, rfc::H3_ERR_FRAME_UNEXPECTED, "forbidden HTTP/2 frame type on H3 control stream rejected");
        }
    };

    t.run("NGHTTP3-CONN-03: GOAWAY Monotonicity & Request Stream Frame Ordering (test_nghttp3_conn_recv_goaway)") { sub =>
        let settings = wing::H3Settings { .. };
        var conn = internal::new_h3_client_connection(settings);

        var init_ctrl: u8[..64] = [];
        internal::quic_encode_varint(init_ctrl, rfc::H3_STREAM_CONTROL);
        internal::encode_h3_settings_frame(init_ctrl, settings);
        sub.assert_eq(conn.handle_stream_data(3, false, init_ctrl[..], false), rfc::H3_ERR_NO_ERROR, "control stream initialized");

        // 1. First GOAWAY with stream ID 16 -> accepted
        var ga1: u8[..16] = [];
        internal::encode_h3_goaway_frame(ga1, 16);
        sub.assert_eq(conn.handle_stream_data(3, false, ga1[..], false), rfc::H3_ERR_NO_ERROR, "GOAWAY(16) accepted");

        // 2. Second GOAWAY with lower stream ID 8 -> accepted
        var ga2: u8[..16] = [];
        internal::encode_h3_goaway_frame(ga2, 8);
        sub.assert_eq(conn.handle_stream_data(3, false, ga2[..], false), rfc::H3_ERR_NO_ERROR, "decreasing GOAWAY(8) accepted");

        // 3. Third GOAWAY with higher stream ID 12 > 8 -> H3_ERR_ID_ERROR (RFC 9114 §5.2)
        var ga3: u8[..16] = [];
        internal::encode_h3_goaway_frame(ga3, 12);
        sub.assert_eq(conn.handle_stream_data(3, false, ga3[..], false), rfc::H3_ERR_ID_ERROR, "increasing GOAWAY(12 > 8) rejected with H3_ERR_ID_ERROR");

        // 4. Request stream receiving DATA frame before initial HEADERS frame -> H3_ERR_FRAME_UNEXPECTED (RFC 9114 §4.1)
        var req_conn = internal::new_h3_client_connection(settings);
        let sid, _ = req_conn.open_request_stream();
        var data_first: u8[..16] = [];
        internal::encode_h3_data_frame(data_first, "hello");
        sub.assert_eq(
            req_conn.handle_stream_data(sid, true, data_first[..], false),
            rfc::H3_ERR_FRAME_UNEXPECTED,
            "DATA frame before initial HEADERS rejected with H3_ERR_FRAME_UNEXPECTED",
        );
    };

    t.run("NGHTTP3-HTTP-02: Header Name/Value Lexical Matrix & Server OPTIONS * Validation (nghttp3_http_test.c)") { sub =>
        // 1. test_nghttp3_check_header_value (nghttp3_http_test.c:354-409):
        // All control chars 0x00..0x08, 0x0A..0x1F, and 0x7F (DEL) MUST be rejected
        var ctl: u8 = 0;
        while ctl <= 0x1F {
            if ctl != '\t' {
                let bad_v: u8[3] = ['a', ctl, 'b'];
                sub.assert_false(internal::validate_qpack_field_val(bad_v[..]), "control char 0x00..0x1F (except HTAB) rejected in QPACK value");
            }
            ctl += 1;
        }
        let del_v: u8[3] = ['a', 0x7F, 'b'];
        sub.assert_false(internal::validate_qpack_field_val(del_v[..]), "DEL (0x7F) rejected in QPACK value");

        // Leading or trailing SP (' ') or HTAB ('\t') rejected; internal HTAB and 0x80..0xFE accepted
        sub.assert_false(internal::validate_qpack_field_val(" alpha"), "leading SP rejected");
        sub.assert_false(internal::validate_qpack_field_val("alpha "), "trailing SP rejected");
        sub.assert_false(internal::validate_qpack_field_val("\talpha"), "leading HTAB rejected");
        sub.assert_false(internal::validate_qpack_field_val("alpha\t"), "trailing HTAB rejected");
        sub.assert_true(internal::validate_qpack_field_val("alpha\tbravo"), "internal HTAB accepted");
        sub.assert_true(internal::validate_qpack_field_val(""), "empty header value accepted");
        let obs_text: u8[4] = ['a', 0x80, 0xFE, 'b'];
        sub.assert_true(internal::validate_qpack_field_val(obs_text[..]), "obs-text 0x80..0xFE accepted");

        // 2. test_nghttp3_check_header_name (nghttp3_http_test.c:411-424)
        sub.assert_false(internal::validate_qpack_field_name(""), "empty header name rejected");
        sub.assert_false(internal::validate_qpack_field_name(":"), "bare ':' header name rejected");
        sub.assert_true(internal::validate_qpack_field_name("a"), "single lowercase char 'a' accepted");
        sub.assert_true(internal::validate_qpack_field_name(":a"), "pseudo-header ':a' syntax accepted");
        sub.assert_false(internal::validate_qpack_field_name("foO"), "uppercase 'foO' rejected");
        sub.assert_false(internal::validate_qpack_field_name(":Foo"), "uppercase ':Foo' rejected");
        let bad_name_utf: u8[4] = ['0', '0', '0', 0xFC];
        sub.assert_false(internal::validate_qpack_field_name(bad_name_utf[..]), "non-ASCII 0xFC in header name rejected");

        // 3. Server pseudo-header validation: OPTIONS * accepted vs GET * rejected (RFC 9114 §4.3.1)
        let settings = wing::H3Settings { .. };
        var cli_conn = internal::new_h3_client_connection(settings);
        let sid_opt, _ = cli_conn.open_request_stream();
        let sid_bad, _ = cli_conn.open_request_stream();
        let empty_extra = wing::HeaderMap { .. };

        var opt_frame: u8[..128] = [];
        sub.assert_true(
            cli_conn.send_request_headers(sid_opt, "OPTIONS", "https", "example.com", "*", empty_extra, true, opt_frame),
            "encode OPTIONS * request headers",
        );
        var srv_opt = internal::new_h3_server_connection(settings);
        sub.assert_eq(srv_opt.handle_stream_data(0, true, opt_frame[..], true), rfc::H3_ERR_NO_ERROR, "OPTIONS * accepted by H3 server");

        var bad_frame: u8[..128] = [];
        sub.assert_true(
            cli_conn.send_request_headers(sid_bad, "GET", "https", "example.com", "*", empty_extra, true, bad_frame),
            "encode GET * request headers",
        );
        var srv_get_star = internal::new_h3_server_connection(settings);
        sub.assert_eq(
            srv_get_star.handle_stream_data(0, true, bad_frame[..], true),
            rfc::H3_ERR_GENERAL_PROTOCOL,
            "GET * rejected by H3 server with H3_ERR_GENERAL_PROTOCOL",
        );
    };
}

// ----------------------------------------------------------------------------
// F009: Alt-Svc Slot Prioritization for h3 & failed_attempts Saturation
// ----------------------------------------------------------------------------
// ----------------------------------------------------------------------------
// 19. F009 Alt-Svc Slot Prioritization & Backoff Saturation
// ----------------------------------------------------------------------------
fn test_f009_altsvc_slot_prioritization_and_backoff_saturation(t: lit::T&) {
    t.run("parse_altsvc_header retains h3 when preceded by 4 draft/legacy protocols") { sub =>
        var cache = wing::AltSvcCache { .. };
        let origin = "example.com:443";
        let raw = "h3-Q050=\":443\", h3-Q046=\":443\", h3-27=\":443\", h3-29=\":443\", h3=\":8443\"; ma=3600";
        wing::update(cache, origin, raw, 1000);

        var ep = wing::AltSvcEndpoint { .. };
        let found = wing::lookup_h3(cache, origin, 1050, ep);
        sub.assert_true(found, "5th h3 endpoint MUST NOT be dropped by 4 preceding draft protocols");
        sub.assert_eq(ep.port as i64, 8443, "Promoted h3 port must be 8443");
    };

    t.run("record_failure saturates failed_attempts without wrapping u8 to 0") { sub =>
        var cache = wing::AltSvcCache { .. };
        let origin = "backoff.example.com:443";
        wing::update(cache, origin, "h3=\":443\"; ma=86400", 1000);

        for i in 256 {
            wing::record_failure(cache, origin, 1000);
        }
        let attempts = wing::failed_attempts(cache, origin);
        sub.assert_true(attempts > 0, "failed_attempts MUST saturate (> 0) after 256 failures instead of wrapping to 0");
        sub.assert_true(wing::is_broken(cache, origin, 1150), "Origin must remain in 160s max backoff at t=1150");
    };

    t.run("lookup_h3 rejects negative elapsed time on backward clock jump") { sub =>
        var cache = wing::AltSvcCache { .. };
        let origin = "clock.example.com:443";
        wing::update(cache, origin, "h3=\":443\"; ma=60", 1000);

        var ep = wing::AltSvcEndpoint { .. };
        let found = wing::lookup_h3(cache, origin, 900, ep);
        sub.assert_false(found, "Negative elapsed time (now_sec < inserted_at_sec) MUST NOT match as fresh");
    };
}

// ----------------------------------------------------------------------------
// 20. RFC 9114 §4.2 & RFC 9204 §4.1: HTTP/3 QPACK Uppercase Literal Field Names
// ----------------------------------------------------------------------------
fn test_qpack_uppercase_literal_field_name_rejection(t: lit::T&) {
    t.run("Lowercase literal field name is decoded successfully") { sub =>
        var tbl = internal::QpackTable { .. };
        var out_fields: internal::HeaderField[>..] = [];

        // Literal Field Line With Literal Name (001NHxxx):
        // Byte 0: 0x24 (0010 0100: name len 4)
        // Name: "host"
        // Byte: 0x07 (val len 7)
        // Value: "foo.bar"
        let wire: const u8[15] = [
            0x00, 0x00, // RIC=0, Base=0
            0x24, 'h', 'o', 's', 't',
            0x07, 'f', 'o', 'o', '.', 'b', 'a', 'r',
        ];

        let err = internal::decode_qpack_section(tbl, wire[..], out_fields);
        sub.assert_eq(err, internal::QpackError.None, "Valid lowercase QPACK field accepted");
        sub.assert_eq(out_fields.len, 1, "1 field decoded");
        sub.assert_bytes_eq(out_fields[0].name[..], "host", "Field name matches");
    };

    t.run("Uppercase literal field name MUST be rejected with DecompressionFailed") { sub =>
        // RFC 9114 Section 4.2: Characters in field names MUST be converted to lowercase prior to encoding.
        // A request containing uppercase characters in field names MUST be treated as malformed.
        var tbl = internal::QpackTable { .. };
        var out_fields: internal::HeaderField[>..] = [];

        let wire: const u8[15] = [
            0x00, 0x00, // RIC=0, Base=0
            0x24, 'H', 'o', 's', 't', // "Host" has uppercase 'H'
            0x07, 'f', 'o', 'o', '.', 'b', 'a', 'r',
        ];

        let err = internal::decode_qpack_section(tbl, wire[..], out_fields);
        sub.assert_eq(err, internal::QpackError.DecompressionFailed, "Uppercase field name MUST be rejected per RFC 9114 §4.2");
    };
}

// ----------------------------------------------------------------------------
// 21. RFC 9114 §6.2.1 & Go #78102: Duplicate HTTP/3 Control Stream Rejection
// ----------------------------------------------------------------------------
fn test_h3_duplicate_control_stream_rejection(t: lit::T&) {
    t.run("Second H3_STREAM_CONTROL stream MUST be rejected with H3_ERR_STREAM_CREATION (0x0103)") { sub =>
        let settings = wing::H3Settings { .. };
        var conn = internal::new_h3_client_connection(settings);
        // First control stream: Stream ID 3 (unidirectional), Type 0x00 (H3_STREAM_CONTROL)
        var ctrl1_wire: u8[..16] = [];
        internal::quic_encode_varint(ctrl1_wire, rfc::H3_STREAM_CONTROL);
        let err1 = conn.handle_stream_data(3, false, ctrl1_wire[..], false);
        sub.assert_eq(err1, rfc::H3_ERR_NO_ERROR, "First control stream accepted");
        sub.assert_true(conn.peer_control_opened, "Peer control opened flag set");

        // Second control stream: Stream ID 7 (unidirectional), Type 0x00
        var ctrl2_wire: u8[..16] = [];
        internal::quic_encode_varint(ctrl2_wire, rfc::H3_STREAM_CONTROL);
        let err2 = conn.handle_stream_data(7, false, ctrl2_wire[..], false);
        sub.assert_eq(err2, rfc::H3_ERR_STREAM_CREATION, "Duplicate control stream MUST return H3_ERR_STREAM_CREATION (0x0103)");
        sub.assert_eq(conn.state, internal::H3ConnState.Closed, "Connection state transitioned to Closed");
    };
}

// ----------------------------------------------------------------------------
// 22. RFC 9114 §4.3: HTTP/3 / QPACK Duplicate Pseudo-Headers & Order Invariants
// ----------------------------------------------------------------------------
fn test_h3_pseudo_header_invariants(t: lit::T&) {
    t.run("Duplicate :status or pseudo-headers after regular headers MUST be rejected (RFC 9114 §4.3)") { sub =>
        let settings = wing::H3Settings { .. };
        var conn = internal::new_h3_client_connection(settings);

        // Open request stream
        let s_id, ok_open = conn.open_request_stream();
        sub.assert_true(ok_open, "Stream opened");

        // Encode QPACK headers with duplicate :status
        var qpack_dup: u8[>..] = [0x00, 0x00];
        internal::encode_qpack_field(qpack_dup, ":status", "200");
        internal::encode_qpack_field(qpack_dup, ":status", "500");

        var wire_dup: u8[>..] = [];
        internal::encode_h3_headers_frame(wire_dup, qpack_dup[..]);

        let res_dup = conn.handle_stream_data(s_id, true, wire_dup[..], false);
        sub.assert_eq(res_dup, rfc::H3_ERR_GENERAL_PROTOCOL, "Duplicate :status MUST return H3_ERR_GENERAL_PROTOCOL");

        // Test pseudo-header after regular header
        var conn2 = internal::new_h3_client_connection(settings);
        let s_id2, ok_open2 = conn2.open_request_stream();
        sub.assert_true(ok_open2, "Stream opened");

        var qpack_order: u8[>..] = [0x00, 0x00];
        internal::encode_qpack_field(qpack_order, "content-type", "text/plain");
        internal::encode_qpack_field(qpack_order, ":status", "200");

        var wire_order: u8[>..] = [];
        internal::encode_h3_headers_frame(wire_order, qpack_order[..]);

        let res_order = conn2.handle_stream_data(s_id2, true, wire_order[..], false);
        sub.assert_eq(res_order, rfc::H3_ERR_GENERAL_PROTOCOL, "Pseudo-header after regular header MUST return H3_ERR_GENERAL_PROTOCOL");
    };
}

// ----------------------------------------------------------------------------
// 23. HTTP/3 unknown pseudo-header (:custom) & CTL character rejection (http3/connection.goose)
// ----------------------------------------------------------------------------
fn test_h3_pseudo_header_unknown_and_ctl(t: lit::T&) {
    t.run("HTTP/3 request with unknown pseudo-header :custom MUST return error") { sub =>
        let settings = wing::H3Settings { .. };
        var conn = internal::new_h3_client_connection(settings);

        let s_id, ok_open = conn.open_request_stream();
        sub.assert_true(ok_open, "Stream opened");

        // Encode QPACK headers with unknown pseudo-header :custom
        var qpack_buf: u8[>..] = [0x00, 0x00];
        internal::encode_qpack_field(qpack_buf, ":method", "GET");
        internal::encode_qpack_field(qpack_buf, ":scheme", "https");
        internal::encode_qpack_field(qpack_buf, ":path", "/");
        internal::encode_qpack_field(qpack_buf, ":custom", "invalid");

        var wire_buf: u8[>..] = [];
        internal::encode_h3_headers_frame(wire_buf, qpack_buf[..]);

        let res = conn.handle_stream_data(s_id, true, wire_buf[..], false);
        sub.assert_true(res != rfc::H3_ERR_NO_ERROR, "HTTP/3 unknown pseudo-header :custom MUST be rejected with error (RFC 9114 §4.3)");
    };

    t.run("HTTP/3 header with CTL character MUST return error") { sub =>
        let settings = wing::H3Settings { .. };
        var conn = internal::new_h3_client_connection(settings);

        let s_id, ok_open = conn.open_request_stream();
        sub.assert_true(ok_open, "Stream opened");

        // Encode QPACK headers with CTL char 0x01 in header value
        var qpack_buf: u8[>..] = [0x00, 0x00];
        internal::encode_qpack_field(qpack_buf, ":method", "GET");
        internal::encode_qpack_field(qpack_buf, ":scheme", "https");
        internal::encode_qpack_field(qpack_buf, ":path", "/");
        internal::encode_qpack_field(qpack_buf, "custom", "bad\x01value");

        var wire_buf: u8[>..] = [];
        internal::encode_h3_headers_frame(wire_buf, qpack_buf[..]);

        let res = conn.handle_stream_data(s_id, true, wire_buf[..], false);
        sub.assert_true(res != rfc::H3_ERR_NO_ERROR, "HTTP/3 header value with CTL MUST be rejected with error (RFC 9114 §4.2)");
    };
}

// ----------------------------------------------------------------------------
// 24. Alt-Svc oversized proto/host/endpoint capacity safety (http/altsvc.goose)
// ----------------------------------------------------------------------------
fn test_altsvc_oversized_capacity_safety(t: lit::T&) {
    t.run("Alt-Svc with > 4 endpoints MUST NOT abort on fixed array overflow") { sub =>
        var endpoints: wing::AltSvcEndpoint[..4] = [];
        // Header with 5 endpoints
        let raw = "h3=\":443\", h2=\":443\", h3-29=\":443\", h3-Q050=\":443\", h3-Q046=\":443\"";
        let ok, is_clear = wing::parse_altsvc_header(raw, endpoints);
        sub.assert_true(ok, "Alt-Svc with 5 endpoints parsed without aborting");
        sub.assert_eq(endpoints.len, 4, "Capacity clamped cleanly at 4 without crash");
    };

    t.run("Alt-Svc with proto > 16 bytes MUST NOT abort") { sub =>
        var endpoints: wing::AltSvcEndpoint[..4] = [];
        let raw = "superlongprotonamethatexceeds16bytes=\":443\"";
        let ok, is_clear = wing::parse_altsvc_header(raw, endpoints);
        sub.assert_true(ok, "Alt-Svc with long proto parsed without aborting");
    };
}

// ----------------------------------------------------------------------------
// 25. HTTP/3 & QPACK (http3/*)
// ----------------------------------------------------------------------------
fn test_h3_and_qpack_rfc9114_rfc9204(t: lit::T&) {
    t.run("H3 request stream accepts 103 Early Hints followed by 200 final response (Go #80687)") { sub =>
        let settings = wing::H3Settings { .. };
        var conn = internal::new_h3_client_connection(settings);
        let sid, _ = internal::open_request_stream(conn);

        // 1. Ingest 103 Early Hints HEADERS frame
        var qpack_103: u8[..64] = [];
        qpack_103.push(0x00); qpack_103.push(0x00);
        internal::encode_qpack_field(qpack_103, ":status", "103", true);

        var frame_103: u8[..128] = [];
        internal::encode_h3_headers_frame(frame_103, qpack_103[..]);
        let err1 = internal::handle_stream_data(conn, sid, true, frame_103[..], false);
        sub.assert_eq(err1, rfc::H3_ERR_NO_ERROR, "103 Early Hints HEADERS accepted");

        // 2. Ingest 200 OK final response HEADERS frame
        var qpack_200: u8[..64] = [];
        qpack_200.push(0x00); qpack_200.push(0x00);
        internal::encode_qpack_field(qpack_200, ":status", "200", true);

        var frame_200: u8[..128] = [];
        internal::encode_h3_headers_frame(frame_200, qpack_200[..]);
        let err2 = internal::handle_stream_data(conn, sid, true, frame_200[..], true);
        sub.assert_eq(err2, rfc::H3_ERR_NO_ERROR, "200 OK HEADERS after 103 Early Hints accepted");

        let status, ok_s = internal::get_status_code(conn, sid);
        sub.assert_true(ok_s, "Status code available");
        sub.assert_eq(status, 200, "Final status code is 200");
    };

    t.run("H3 rejects :status 101 Switching Protocols (RFC 9114 §4.3.2)") { sub =>
        let settings = wing::H3Settings { .. };
        var conn = internal::new_h3_client_connection(settings);
        let sid, _ = internal::open_request_stream(conn);

        var qpack_101: u8[..64] = [];
        qpack_101.push(0x00); qpack_101.push(0x00);
        internal::encode_qpack_field(qpack_101, ":status", "101", true);

        var frame_101: u8[..128] = [];
        internal::encode_h3_headers_frame(frame_101, qpack_101[..]);
        let err = internal::handle_stream_data(conn, sid, true, frame_101[..], false);
        sub.assert_eq(err, rfc::H3_ERR_GENERAL_PROTOCOL, ":status 101 MUST return H3_ERR_GENERAL_PROTOCOL");
    };

    t.run("QPACK emit_field_checked rejects field names with invalid token chars") { sub =>
        var fields: internal::HeaderField[>..] = [];
        var budget: u64                        = 4096;
        let err = internal::emit_field_checked(fields, budget, "bad name", "value", false);
        sub.assert_true(err == internal::QpackError.DecompressionFailed, "QPACK field name with space MUST fail");
    };
}

// ----------------------------------------------------------------------------
// 26. QPACK Modular RIC, Post-Base Bounds & Bare-Colon Token Sanitization
// ----------------------------------------------------------------------------
fn test_qpack_invariants_and_token_defenses(t: lit::T&) {
    t.run("decode_base integer overflow and underflow protection") { sub =>
        // Sign bit 0: Base = ric + delta_base. Test overflow on ric + delta_base
        let _, err_ov = internal::decode_base(0, 10, 0xFFFFFFFFFFFFFFFF);
        sub.assert_eq(err_ov, internal::QpackError.DecompressionFailed, "overflow in base addition rejected");

        // Sign bit 1: Base = ric - delta_base - 1. Test underflow when ric <= delta_base
        let _, err_un = internal::decode_base(1, 5, 5);
        sub.assert_eq(err_un, internal::QpackError.DecompressionFailed, "underflow in base subtraction rejected");

        let base_ok, err_ok = internal::decode_base(0, 5, 10);
        sub.assert_eq(err_ok, internal::QpackError.None, "valid base decoded");
        sub.assert_eq(base_ok, 15, "base is 15");
    };

    t.run("emit_field_checked rejects bare colon and non-token characters") { sub =>
        var fields: internal::HeaderField[>..] = [];
        var budget: u64                        = 4096;

        // Bare colon ":" must be rejected
        let err_colon = internal::emit_field_checked(fields, budget, ":", "val", false);
        sub.assert_eq(err_colon, internal::QpackError.DecompressionFailed, "bare colon rejected");

        // Empty field name
        let err_empty = internal::emit_field_checked(fields, budget, "", "val", false);
        sub.assert_eq(err_empty, internal::QpackError.DecompressionFailed, "empty name rejected");

        // Disallowed control char in name
        let err_ctl = internal::emit_field_checked(fields, budget, "bad\nheader", "val", false);
        sub.assert_eq(err_ctl, internal::QpackError.DecompressionFailed, "newline in name rejected");

        // Valid pseudo header
        let err_valid = internal::emit_field_checked(fields, budget, ":status", "200", false);
        sub.assert_eq(err_valid, internal::QpackError.None, "valid :status accepted");
        sub.assert_eq(fields.len, 1, "field emitted");
    };

    t.run("decode_qpack_section enforces RFC 9204 Post-Base index bounds abs_idx < ric") { sub =>
        var tbl = internal::new_qpack_table(4096, 16);
        // Insert one dynamic entry: "x-foo" = "bar" -> abs_idx = 0
        internal::qpack_insert_literal(tbl, "x-foo", "bar");
        sub.assert_eq(tbl.insert_count, 1, "dynamic table insert_count is 1");

        // Construct section with RIC = 1, Base = 0 (S=1, DeltaBase=0 -> Base = 1 - 0 - 1 = 0)
        // Then attempt Post-Base index 1 -> abs_idx = Base + 1 = 1 >= RIC (1)
        // Per RFC 9204 §4.5.3, abs_idx >= ric MUST be treated as decompression error!
        var sec: u8[..32] = [];
        // 1. EncodedInsertCount = 1 (enc_ric for ric=1 is 2 when max_entries = 4096/32 = 128)
        let enc_ric = internal::encode_ric(1, 4096);
        internal::hpack_encode_int(sec, enc_ric, 8, 0x00);
        // 2. Sign=1, DeltaBase=0 -> 0x80 | 0 = 0x80
        sec.push(0x80);
        // 3. Post-Base Indexed Field Line: 0001xxxx with post_idx = 1 -> 0x11
        sec.push(0x11);

        var out_fields: internal::HeaderField[>..] = [];
        let err = internal::decode_qpack_section(tbl, sec[..], out_fields, 4096);
        sub.assert_eq(err, internal::QpackError.DecompressionFailed, "post_idx resulting in abs_idx >= ric rejected");
    };

    t.run("decode_qpack_section accepts valid RIC >= max_dyn_abs_used + 1 per RFC 9204 §4.5.1") { sub =>
        var tbl = internal::new_qpack_table(4096, 16);
        // Insert two entries: abs_idx 0 ("x-first"), abs_idx 1 ("x-second")
        internal::qpack_insert_literal(tbl, "x-first", "v1");
        internal::qpack_insert_literal(tbl, "x-second", "v2");
        sub.assert_eq(tbl.insert_count, 2, "dynamic table insert_count is 2");

        // Section references ONLY static :status 200 (index 0)
        // Encoder signals RIC = 2 (TotalNumberOfInserts), Base = 2 (S=0, DeltaBase=0)
        // Per RFC 9204 §4.5.1, encoder MAY set RIC > 0 even if no dynamic entries referenced
        var sec: u8[..32] = [];
        let enc_ric = internal::encode_ric(2, 4096);
        internal::hpack_encode_int(sec, enc_ric, 8, 0x00);
        sec.push(0x00); // S=0, DeltaBase=0 -> Base = 2
        sec.push(0xD9); // Static index 25 (:status 200)

        var out_fields: internal::HeaderField[>..] = [];
        let err = internal::decode_qpack_section(tbl, sec[..], out_fields, 4096);
        sub.assert_eq(err, internal::QpackError.None, "RIC > 0 with static-only fields accepted per RFC 9204 §4.5.1");
        sub.assert_eq(out_fields.len, 1, "1 field decoded");
        sub.assert_bytes_eq(out_fields[0].name[..], ":status", "name is :status");
        sub.assert_bytes_eq(out_fields[0].value[..], "200", "value is 200");
    };
}

// ----------------------------------------------------------------------------
// 27. HTTP/3 Framing, Reserved 0x00 Setting & Malformed Payloads
// ----------------------------------------------------------------------------
fn test_h3_framing_and_settings_invariants(t: lit::T&) {
    t.run("parse_h3_settings_frame rejects reserved setting 0x00 and duplicates") { sub =>
        // 1. Reserved setting 0x00 (from HTTP/2) MUST cause H3_SETTINGS_ERROR (RFC 9114 §7.2.4.1)
        var payload_00: u8[..16] = [];
        internal::quic_encode_varint(payload_00, 0x00); // Reserved identifier 0x00
        internal::quic_encode_varint(payload_00, 100);

        var st1 = wing::H3Settings { .. };
        let err_00 = internal::parse_h3_settings_frame(payload_00[..], st1);
        sub.assert_eq(err_00, rfc::H3_ERR_SETTINGS_ERROR, "Reserved setting 0x00 rejected with H3_SETTINGS_ERROR");

        // 2. Duplicate QPACK_MAX_TABLE_CAPACITY setting MUST cause H3_SETTINGS_ERROR
        var payload_dup: u8[..32] = [];
        internal::quic_encode_varint(payload_dup, rfc::H3_SETTING_QPACK_MAX_TABLE_CAPACITY);
        internal::quic_encode_varint(payload_dup, 4096);
        internal::quic_encode_varint(payload_dup, rfc::H3_SETTING_QPACK_MAX_TABLE_CAPACITY);
        internal::quic_encode_varint(payload_dup, 8192);

        var st2 = wing::H3Settings { .. };
        let err_dup = internal::parse_h3_settings_frame(payload_dup[..], st2);
        sub.assert_eq(err_dup, rfc::H3_ERR_SETTINGS_ERROR, "Duplicate setting rejected with H3_SETTINGS_ERROR");

        // 3. Invalid ENABLE_CONNECT_PROTOCOL value (must be 0 or 1)
        var payload_conn: u8[..16] = [];
        internal::quic_encode_varint(payload_conn, rfc::H3_SETTING_ENABLE_CONNECT_PROTOCOL);
        internal::quic_encode_varint(payload_conn, 2); // Invalid: only 0 or 1 allowed

        var st3 = wing::H3Settings { .. };
        let err_conn = internal::parse_h3_settings_frame(payload_conn[..], st3);
        sub.assert_eq(err_conn, rfc::H3_ERR_SETTINGS_ERROR, "Invalid connect protocol val rejected with H3_SETTINGS_ERROR");
    };
}

// ----------------------------------------------------------------------------
// 28. HTTP/3 Multiplexer, Unidirectional Dispatch & Trailer Defenses
// ----------------------------------------------------------------------------
fn test_h3_multiplexer_and_stream_defenses(t: lit::T&) {
    t.run("handle_stream_data dispatches QPACK encoder stream instructions and catches errors") { sub =>
        let settings = wing::H3Settings { qpack_max_table_capacity: 4096, .. };
        var conn = internal::new_h3_client_connection(settings);

        // 1. Establish control stream first (Stream 2)
        var ctrl_wire: u8[..64] = [];
        internal::quic_encode_varint(ctrl_wire, rfc::H3_STREAM_CONTROL);
        internal::encode_h3_settings_frame(ctrl_wire, settings);
        let err_c = conn.handle_stream_data(2, false, ctrl_wire[..], false);
        sub.assert_eq(err_c, rfc::H3_ERR_NO_ERROR, "control stream established");

        // 2. Open QPACK encoder stream (Stream 6) with valid Set Dynamic Table Capacity instruction (0x20 | 5-bit cap)
        var enc_wire: u8[..64] = [];
        internal::quic_encode_varint(enc_wire, rfc::H3_STREAM_QPACK_ENCODER);
        internal::hpack_encode_int(enc_wire, 2048, 5, 0x20); // Capacity 2048
        let err_enc = conn.handle_stream_data(6, false, enc_wire[..], false);
        sub.assert_eq(err_enc, rfc::H3_ERR_NO_ERROR, "encoder stream capacity instruction processed");
        sub.assert_eq(conn.qpack_table.capacity_bytes, 2048, "dynamic table capacity updated to 2048");

        // 3. Send malformed instruction on encoder stream -> returns H3_ERR_QPACK_ENCODER_STREAM_ERROR
        var bad_enc_wire: u8[..16] = [];
        // Capacity larger than max_capacity_bytes (4096)
        internal::hpack_encode_int(bad_enc_wire, 999999, 5, 0x20);
        let err_bad_enc = conn.handle_stream_data(6, false, bad_enc_wire[..], false);
        sub.assert_eq(err_bad_enc, rfc::H3_ERR_QPACK_ENCODER_STREAM_ERROR, "invalid encoder instruction closed connection");
        sub.assert_eq(conn.state, internal::H3ConnState.Closed, "conn state is Closed");
    };

    t.run("handle_stream_data rejects second trailer section and DATA after trailers") { sub =>
        let settings = wing::H3Settings { .. };
        var conn = internal::new_h3_client_connection(settings);
        let _s0, _ = conn.open_request_stream();

        // Setup control stream
        var ctrl_wire: u8[..64] = [];
        internal::quic_encode_varint(ctrl_wire, rfc::H3_STREAM_CONTROL);
        internal::encode_h3_settings_frame(ctrl_wire, settings);
        conn.handle_stream_data(2, false, ctrl_wire[..], false);

        // Stream 0: Initial response headers (200 OK)
        var resp_hdrs: u8[..64] = [];
        var sec1:      u8[..16] = [0x00, 0x00, 0xD9]; // RIC 0, Base 0, :status 200
        internal::encode_h3_headers_frame(resp_hdrs, sec1[..]);
        let err_h1 = conn.handle_stream_data(0, true, resp_hdrs[..], false);
        sub.assert_eq(err_h1, rfc::H3_ERR_NO_ERROR, "initial 200 OK headers accepted");

        // Stream 0: DATA frame
        var data_frame: u8[..32] = [];
        internal::encode_h3_data_frame(data_frame, "hello");
        let err_d1 = conn.handle_stream_data(0, true, data_frame[..], false);
        sub.assert_eq(err_d1, rfc::H3_ERR_NO_ERROR, "data frame accepted");

        // Stream 0: First trailer section (x-checksum: abc)
        var trailer1_frame: u8[..64] = [];
        var sec_tr1:        u8[..32] = [0x00, 0x00];
        // Literal with literal name: name "x-chk", val "1"
        sec_tr1.push(0x25);
        sec_tr1.append("x-chk");
        sec_tr1.push(0x01);
        sec_tr1.append("1");
        internal::encode_h3_headers_frame(trailer1_frame, sec_tr1[..]);
        let err_tr1 = conn.handle_stream_data(0, true, trailer1_frame[..], false);
        sub.assert_eq(err_tr1, rfc::H3_ERR_NO_ERROR, "first trailer section accepted");

        // 1. DATA frame AFTER trailers MUST cause H3_FRAME_UNEXPECTED (RFC 9114 §4.1)
        var post_tr_data: u8[..32] = [];
        internal::encode_h3_data_frame(post_tr_data, "illegal");
        let err_post_d = conn.handle_stream_data(0, true, post_tr_data[..], false);
        sub.assert_eq(err_post_d, rfc::H3_ERR_FRAME_UNEXPECTED, "DATA after trailers rejected with H3_FRAME_UNEXPECTED");

        // Reset and test second trailer section rejection
        var conn2 = internal::new_h3_client_connection(settings);
        let _s2, _ = conn2.open_request_stream();
        conn2.handle_stream_data(2, false, ctrl_wire[..], false);
        conn2.handle_stream_data(0, true, resp_hdrs[..], false);
        conn2.handle_stream_data(0, true, data_frame[..], false);
        conn2.handle_stream_data(0, true, trailer1_frame[..], false);

        // 2. Second trailer section MUST cause H3_FRAME_UNEXPECTED (RFC 9114 §4.1)
        let err_tr2 = conn2.handle_stream_data(0, true, trailer1_frame[..], false);
        sub.assert_eq(err_tr2, rfc::H3_ERR_FRAME_UNEXPECTED, "second trailer section rejected with H3_FRAME_UNEXPECTED");
    };

    t.run("handle_stream_data validates 3-digit status code and trailer disallowed headers") { sub =>
        let settings = wing::H3Settings { .. };
        var conn = internal::new_h3_client_connection(settings);
        let _s0, _ = conn.open_request_stream();

        // Setup control stream
        var ctrl_wire: u8[..64] = [];
        internal::quic_encode_varint(ctrl_wire, rfc::H3_STREAM_CONTROL);
        internal::encode_h3_settings_frame(ctrl_wire, settings);
        conn.handle_stream_data(2, false, ctrl_wire[..], false);

        // 1. Status code with 4 digits e.g. "0200" MUST fail
        var sec_bad_st: u8[..32] = [0x00, 0x00];
        // Literal with static name index 24 (:status) encoded with 4-bit prefix
        internal::hpack_encode_int(sec_bad_st, 24, 4, 0x50);
        sec_bad_st.push(4); // len 4
        sec_bad_st.append("0200");

        var bad_st_frame: u8[..64] = [];
        internal::encode_h3_headers_frame(bad_st_frame, sec_bad_st[..]);
        let err_st = conn.handle_stream_data(0, true, bad_st_frame[..], false);
        sub.assert_eq(err_st, rfc::H3_ERR_GENERAL_PROTOCOL, "4-digit status code rejected");

        // 2. Disallowed content-length in trailer section MUST fail
        var conn3 = internal::new_h3_client_connection(settings);
        let _s3, _ = conn3.open_request_stream();
        conn3.handle_stream_data(2, false, ctrl_wire[..], false);
        var sec_ok:  u8[..16] = [0x00, 0x00, 0xD9]; // :status 200
        var ok_hdrs: u8[..32] = [];
        internal::encode_h3_headers_frame(ok_hdrs, sec_ok[..]);
        conn3.handle_stream_data(0, true, ok_hdrs[..], false);

        var sec_cl_tr: u8[..32] = [0x00, 0x00];
        // Literal with static name index 4 (content-length)
        sec_cl_tr.push(0x50 | 4);
        sec_cl_tr.push(2);
        sec_cl_tr.append("10");

        var cl_tr_frame: u8[..64] = [];
        internal::encode_h3_headers_frame(cl_tr_frame, sec_cl_tr[..]);
        let err_cl_tr = conn3.handle_stream_data(0, true, cl_tr_frame[..], false);
        sub.assert_eq(err_cl_tr, rfc::H3_ERR_GENERAL_PROTOCOL, "content-length in trailer rejected");
    };
}

// ----------------------------------------------------------------------------
// 29. HTTP/3 Stream Data Host vs :authority Conflict & Host Syntax
// ----------------------------------------------------------------------------
fn test_h3_host_authority_conflict_and_syntax(t: lit::T&) {
    t.run("H3 request: reject conflicting :authority and host headers") { sub =>
        let settings = wing::H3Settings { .. };
        var conn = internal::new_h3_server_connection(settings);

        // Establish control stream (Stream 2)
        var ctrl_wire: u8[..64] = [];
        internal::quic_encode_varint(ctrl_wire, rfc::H3_STREAM_CONTROL);
        internal::encode_h3_settings_frame(ctrl_wire, settings);
        conn.handle_stream_data(2, false, ctrl_wire[..], false);

        // Stream 0: Request headers with :authority: "example.com" and host: "evil.com"
        var sec: u8[..256] = [0x00, 0x00]; // RIC 0, Base 0
        internal::encode_qpack_field(sec, ":method", "GET", false);
        internal::encode_qpack_field(sec, ":scheme", "https", false);
        internal::encode_qpack_field(sec, ":path", "/", false);
        internal::encode_qpack_field(sec, ":authority", "example.com", false);
        internal::encode_qpack_field(sec, "host", "evil.com", false);

        var req_frame: u8[..256] = [];
        internal::encode_h3_headers_frame(req_frame, sec[..]);

        let err = conn.handle_stream_data(0, true, req_frame[..], false);
        sub.assert_eq(err, rfc::H3_ERR_GENERAL_PROTOCOL, "conflicting :authority and host MUST return H3_ERR_GENERAL_PROTOCOL");
    };

    t.run("H3 request: reject duplicate host headers and invalid host syntax") { sub =>
        let settings = wing::H3Settings { .. };
        var conn = internal::new_h3_server_connection(settings);

        var ctrl_wire: u8[..64] = [];
        internal::quic_encode_varint(ctrl_wire, rfc::H3_STREAM_CONTROL);
        internal::encode_h3_settings_frame(ctrl_wire, settings);
        conn.handle_stream_data(2, false, ctrl_wire[..], false);

        // Duplicate host headers
        var sec_dup: u8[..256] = [0x00, 0x00];
        internal::encode_qpack_field(sec_dup, ":method", "GET", false);
        internal::encode_qpack_field(sec_dup, ":scheme", "https", false);
        internal::encode_qpack_field(sec_dup, ":path", "/", false);
        internal::encode_qpack_field(sec_dup, "host", "example.com", false);
        internal::encode_qpack_field(sec_dup, "host", "example.com", false);

        var dup_frame: u8[..256] = [];
        internal::encode_h3_headers_frame(dup_frame, sec_dup[..]);

        let err_dup = conn.handle_stream_data(0, true, dup_frame[..], false);
        sub.assert_eq(err_dup, rfc::H3_ERR_GENERAL_PROTOCOL, "duplicate host headers MUST return H3_ERR_GENERAL_PROTOCOL");

        // Invalid host syntax (containing '/')
        var conn2 = internal::new_h3_server_connection(settings);
        conn2.handle_stream_data(2, false, ctrl_wire[..], false);

        var sec_bad: u8[..256] = [0x00, 0x00];
        internal::encode_qpack_field(sec_bad, ":method", "GET", false);
        internal::encode_qpack_field(sec_bad, ":scheme", "https", false);
        internal::encode_qpack_field(sec_bad, ":path", "/", false);
        internal::encode_qpack_field(sec_bad, "host", "example.com/evil", false);

        var bad_frame: u8[..256] = [];
        internal::encode_h3_headers_frame(bad_frame, sec_bad[..]);

        let err_bad = conn2.handle_stream_data(0, true, bad_frame[..], false);
        sub.assert_eq(err_bad, rfc::H3_ERR_GENERAL_PROTOCOL, "host with slash MUST return H3_ERR_GENERAL_PROTOCOL");

        // Empty :authority
        var conn3 = internal::new_h3_server_connection(settings);
        conn3.handle_stream_data(2, false, ctrl_wire[..], false);

        var sec_empty: u8[..256] = [0x00, 0x00];
        internal::encode_qpack_field(sec_empty, ":method", "GET", false);
        internal::encode_qpack_field(sec_empty, ":scheme", "https", false);
        internal::encode_qpack_field(sec_empty, ":path", "/", false);
        internal::encode_qpack_field(sec_empty, ":authority", "", false);

        var empty_frame: u8[..256] = [];
        internal::encode_h3_headers_frame(empty_frame, sec_empty[..]);

        let err_empty = conn3.handle_stream_data(0, true, empty_frame[..], false);
        sub.assert_eq(err_empty, rfc::H3_ERR_GENERAL_PROTOCOL, "empty :authority MUST return H3_ERR_GENERAL_PROTOCOL");
    };

    t.run("H3 request: matching case-insensitive :authority and host succeed") { sub =>
        let settings = wing::H3Settings { .. };
        var conn = internal::new_h3_server_connection(settings);

        var ctrl_wire: u8[..64] = [];
        internal::quic_encode_varint(ctrl_wire, rfc::H3_STREAM_CONTROL);
        internal::encode_h3_settings_frame(ctrl_wire, settings);
        conn.handle_stream_data(2, false, ctrl_wire[..], false);

        var sec_ok: u8[..256] = [0x00, 0x00];
        internal::encode_qpack_field(sec_ok, ":method", "GET", false);
        internal::encode_qpack_field(sec_ok, ":scheme", "https", false);
        internal::encode_qpack_field(sec_ok, ":path", "/", false);
        internal::encode_qpack_field(sec_ok, ":authority", "Example.COM", false);
        internal::encode_qpack_field(sec_ok, "host", "example.com", false);

        var ok_frame: u8[..256] = [];
        internal::encode_h3_headers_frame(ok_frame, sec_ok[..]);

        let err_ok = conn.handle_stream_data(0, true, ok_frame[..], false);
        sub.assert_eq(err_ok, rfc::H3_ERR_NO_ERROR, "case-insensitive matching authority and host accepted");
    };
}

// Main Runner

// --- Component: regress_issues_batch17 ---
// Phase 17 RED test suite: Reducing Load, DoS Mitigation, RFC Conformance,
// and Protocol Invariants.
//
// 1. HTTP/3 DATA Frame Rejection on Bodyless Status Codes (204, 304, 1xx) (RFC 9114 §4.1, Go #81642)
// 2. HTTP/3 Prohibited Trailer Framing Headers & QPACK NUL/CR/LF Injection (RFC 9114 §4.2, §4.3, Go #80683)
// 3. HTTP/2 :status Pseudo-Header Validation & 101 Prohibition (RFC 9113 §8.3.2, §8.8)
// 4. HTTP/2 DATA Frame Rejection on Streams with Trailers Received (RFC 9113 §8.1)
// 5. X.509 DNS Name Constraints Wildcard & Empty/Leading Dot Validation (RFC 5280 §4.2.1.10)
// 6. X.509 ASN.1 Time Parsing Bounds & Overflow Defense (RFC 5280 §4.1.2.5, OpenSSL #31686)

// ----------------------------------------------------------------------------
// 30. HTTP/3 DATA Frame Rejection on Bodyless Status Codes (204, 304, 1xx)
// ----------------------------------------------------------------------------
fn test_h3_bodyless_status_data_rejection(t: lit::T&) {
    t.run("H3: reject DATA frame on stream with 204 No Content") { sub =>
        let settings = wing::H3Settings { .. };
        var conn = internal::new_h3_client_connection(settings);
        let _s0, _ = conn.open_request_stream();

        // Control stream setup
        var ctrl_wire: u8[..64] = [];
        internal::quic_encode_varint(ctrl_wire, rfc::H3_STREAM_CONTROL);
        internal::encode_h3_settings_frame(ctrl_wire, settings);
        conn.handle_stream_data(2, false, ctrl_wire[..], false);

        // 1. Send HEADERS frame with :status = 204
        var qpack_204: u8[..32] = [];
        qpack_204.push(0x00); // Required Insert Count = 0
        qpack_204.push(0x00); // Delta Base = 0
        internal::encode_qpack_field(qpack_204, ":status", "204", false);

        var wire_h: u8[..64] = [];
        internal::encode_h3_headers_frame(wire_h, qpack_204[..]);

        let err_h = conn.handle_stream_data(0, true, wire_h[..], false);
        sub.assert_eq(err_h, rfc::H3_ERR_NO_ERROR, "headers frame accepted");
        sub.assert_eq(conn.streams[0].status_code, 204, "stream status 204 recorded");

        // 2. Peer attempts to send DATA frame on 204 response
        var wire_d: u8[..32] = [];
        internal::encode_h3_data_frame(wire_d, "unexpected body");

        let err_d = conn.handle_stream_data(0, true, wire_d[..], true);
        sub.assert_eq(err_d, rfc::H3_ERR_FRAME_UNEXPECTED, "DATA frame on 204 status MUST return H3_ERR_FRAME_UNEXPECTED");
    };

    t.run("H3: reject DATA frame on stream with 304 Not Modified") { sub =>
        let settings = wing::H3Settings { .. };
        var conn = internal::new_h3_client_connection(settings);
        let _s0, _ = conn.open_request_stream();
        let _s4, _ = conn.open_request_stream();

        var ctrl_wire: u8[..64] = [];
        internal::quic_encode_varint(ctrl_wire, rfc::H3_STREAM_CONTROL);
        internal::encode_h3_settings_frame(ctrl_wire, settings);
        conn.handle_stream_data(2, false, ctrl_wire[..], false);

        var qpack_304: u8[..32] = [];
        qpack_304.push(0x00);
        qpack_304.push(0x00);
        internal::encode_qpack_field(qpack_304, ":status", "304", false);

        var wire_h: u8[..64] = [];
        internal::encode_h3_headers_frame(wire_h, qpack_304[..]);

        conn.handle_stream_data(4, true, wire_h[..], false);

        var wire_d: u8[..32] = [];
        internal::encode_h3_data_frame(wire_d, "unexpected body");

        let err_d = conn.handle_stream_data(4, true, wire_d[..], true);
        sub.assert_eq(err_d, rfc::H3_ERR_FRAME_UNEXPECTED, "DATA frame on 304 status MUST return H3_ERR_FRAME_UNEXPECTED");
    };

    t.run("H3: reject DATA frame on stream with 103 Early Hints") { sub =>
        let settings = wing::H3Settings { .. };
        var conn = internal::new_h3_client_connection(settings);
        let _s0, _ = conn.open_request_stream();
        let _s4, _ = conn.open_request_stream();
        let _s8, _ = conn.open_request_stream();

        var ctrl_wire: u8[..64] = [];
        internal::quic_encode_varint(ctrl_wire, rfc::H3_STREAM_CONTROL);
        internal::encode_h3_settings_frame(ctrl_wire, settings);
        conn.handle_stream_data(2, false, ctrl_wire[..], false);

        var qpack_103: u8[..32] = [];
        qpack_103.push(0x00);
        qpack_103.push(0x00);
        internal::encode_qpack_field(qpack_103, ":status", "103", false);

        var wire_h: u8[..64] = [];
        internal::encode_h3_headers_frame(wire_h, qpack_103[..]);

        conn.handle_stream_data(8, true, wire_h[..], false);

        var wire_d: u8[..32] = [];
        internal::encode_h3_data_frame(wire_d, "unexpected body");

        let err_d = conn.handle_stream_data(8, true, wire_d[..], true);
        sub.assert_eq(err_d, rfc::H3_ERR_FRAME_UNEXPECTED, "DATA frame on 1xx status MUST return H3_ERR_FRAME_UNEXPECTED");
    };
}

// ----------------------------------------------------------------------------
// 31. HTTP/3 Prohibited Trailer Framing Headers & QPACK NUL/CR/LF Injection
// ----------------------------------------------------------------------------
fn test_h3_prohibited_trailers_and_qpack_nul_rejection(t: lit::T&) {
    t.run("H3: reject prohibited framing headers in trailers") { sub =>
        let settings = wing::H3Settings { .. };
        var conn = internal::new_h3_client_connection(settings);
        let _s0, _ = conn.open_request_stream();

        var ctrl_wire: u8[..64] = [];
        internal::quic_encode_varint(ctrl_wire, rfc::H3_STREAM_CONTROL);
        internal::encode_h3_settings_frame(ctrl_wire, settings);
        conn.handle_stream_data(2, false, ctrl_wire[..], false);

        // 1. Initial 200 response headers
        var qpack_init: u8[..32] = [];
        qpack_init.push(0x00);
        qpack_init.push(0x00);
        internal::encode_qpack_field(qpack_init, ":status", "200", false);

        var wire_h: u8[..64] = [];
        internal::encode_h3_headers_frame(wire_h, qpack_init[..]);
        conn.handle_stream_data(0, true, wire_h[..], false);

        // 2. Trailer with prohibited transfer-encoding
        var qpack_te: u8[..32] = [];
        qpack_te.push(0x00);
        qpack_te.push(0x00);
        internal::encode_qpack_field(qpack_te, "transfer-encoding", "chunked", false);

        var wire_te: u8[..64] = [];
        internal::encode_h3_headers_frame(wire_te, qpack_te[..]);

        let err_te = conn.handle_stream_data(0, true, wire_te[..], true);
        sub.assert_eq(err_te, rfc::H3_ERR_GENERAL_PROTOCOL, "trailer with transfer-encoding MUST return H3_ERR_GENERAL_PROTOCOL");

        // 3. New connection: trailer with prohibited connection: close
        var conn2 = internal::new_h3_client_connection(settings);
        let _s2, _ = conn2.open_request_stream();
        conn2.handle_stream_data(2, false, ctrl_wire[..], false);
        conn2.handle_stream_data(0, true, wire_h[..], false);

        var qpack_conn: u8[..32] = [];
        qpack_conn.push(0x00);
        qpack_conn.push(0x00);
        internal::encode_qpack_field(qpack_conn, "connection", "close", false);

        var wire_conn: u8[..64] = [];
        internal::encode_h3_headers_frame(wire_conn, qpack_conn[..]);

        let err_conn = conn2.handle_stream_data(0, true, wire_conn[..], true);
        sub.assert_eq(err_conn, rfc::H3_ERR_GENERAL_PROTOCOL, "trailer with connection MUST return H3_ERR_GENERAL_PROTOCOL");

        // 4. New connection: trailer with prohibited upgrade
        var conn3 = internal::new_h3_client_connection(settings);
        let _s3, _ = conn3.open_request_stream();
        conn3.handle_stream_data(2, false, ctrl_wire[..], false);
        conn3.handle_stream_data(0, true, wire_h[..], false);

        var qpack_upg: u8[..32] = [];
        qpack_upg.push(0x00);
        qpack_upg.push(0x00);
        internal::encode_qpack_field(qpack_upg, "upgrade", "websocket", false);

        var wire_upg: u8[..64] = [];
        internal::encode_h3_headers_frame(wire_upg, qpack_upg[..]);

        let err_upg = conn3.handle_stream_data(0, true, wire_upg[..], true);
        sub.assert_eq(err_upg, rfc::H3_ERR_GENERAL_PROTOCOL, "trailer with upgrade MUST return H3_ERR_GENERAL_PROTOCOL");
    };

    t.run("QPACK: reject field values with NUL, CR, or LF") { sub =>
        let tbl = internal::new_qpack_table(0, 0);
        var fields: internal::HeaderField[>..] = [];

        // Literal with NUL byte in value: "hello\0world"
        var nul_val_wire: u8[..32] = [];
        nul_val_wire.push(0x00); // ric 0
        nul_val_wire.push(0x00); // delta base 0
        internal::encode_qpack_field(nul_val_wire, "x-custom", "hello\0world", false);

        let err_nul = internal::decode_qpack_section(tbl, nul_val_wire[..], fields);
        sub.assert_eq(err_nul, internal::QpackError.DecompressionFailed, "field value with NUL MUST return DecompressionFailed");

        // Literal with CR in value: "hello\rworld"
        var cr_val_wire: u8[..32] = [];
        cr_val_wire.push(0x00);
        cr_val_wire.push(0x00);
        internal::encode_qpack_field(cr_val_wire, "x-custom", "hello\rworld", false);

        let err_cr = internal::decode_qpack_section(tbl, cr_val_wire[..], fields);
        sub.assert_eq(err_cr, internal::QpackError.DecompressionFailed, "field value with CR MUST return DecompressionFailed");

        // Literal with LF in value: "hello\nworld"
        var lf_val_wire: u8[..32] = [];
        lf_val_wire.push(0x00);
        lf_val_wire.push(0x00);
        internal::encode_qpack_field(lf_val_wire, "x-custom", "hello\nworld", false);

        let err_lf = internal::decode_qpack_section(tbl, lf_val_wire[..], fields);
        sub.assert_eq(err_lf, internal::QpackError.DecompressionFailed, "field value with LF MUST return DecompressionFailed");
    };
}

// --- Component: regress_issues_batch18 ---
// Phase 18 RED test suite: Reducing Load, DoS Mitigation, RFC Conformance,
// and Protocol Invariants.
//
// 1. HTTP/3 Server Request Trailers Invariants (RFC 9114 §4.3)
// 2. HTTP/3 Empty DATA Frame Flooding Defense (CVE-2019-9518, RFC 9114 §10.5)
// 3. X.509 Basic Constraints Negative or Non-CA PathLen Defense (RFC 5280 §4.2.1.9, OpenSSL #32374)
// 4. X.509 Name Constraints Subtree Base dNSName Validation (RFC 5280 §4.2.1.10, OpenSSL #31686)

// ----------------------------------------------------------------------------
// 32. HTTP/3 Server Request Trailers Invariants (RFC 9114 §4.3)
// ----------------------------------------------------------------------------
fn test_h3_server_request_trailers_invariants(t: lit::T&) {
    t.run("H3 Server: reject pseudo-headers in request trailers") { sub =>
        let settings = wing::H3Settings { .. };
        var conn = internal::new_h3_server_connection(settings);

        // Client control stream setup on stream 3 (unidirectional client stream)
        var ctrl_wire: u8[..64] = [];
        internal::quic_encode_varint(ctrl_wire, rfc::H3_STREAM_CONTROL);
        internal::encode_h3_settings_frame(ctrl_wire, settings);
        conn.handle_stream_data(3, false, ctrl_wire[..], false);

        // 1. Client sends initial request HEADERS on stream 0
        var qpack_req: u8[..128] = [];
        qpack_req.push(0x00); // ric 0
        qpack_req.push(0x00); // delta base 0
        internal::encode_qpack_field(qpack_req, ":method", "POST", false);
        internal::encode_qpack_field(qpack_req, ":scheme", "https", false);
        internal::encode_qpack_field(qpack_req, ":authority", "example.com", false);
        internal::encode_qpack_field(qpack_req, ":path", "/upload", false);

        var wire_req: u8[..128] = [];
        internal::encode_h3_headers_frame(wire_req, qpack_req[..]);
        let err_req = conn.handle_stream_data(0, true, wire_req[..], false);
        sub.assert_eq(err_req, rfc::H3_ERR_NO_ERROR, "initial request headers accepted");

        // 2. Client sends DATA frame on stream 0
        var wire_d: u8[..32] = [];
        internal::encode_h3_data_frame(wire_d, "payload-data");
        let err_d = conn.handle_stream_data(0, true, wire_d[..], false);
        sub.assert_eq(err_d, rfc::H3_ERR_NO_ERROR, "data frame accepted");

        // 3. Client sends trailers containing forbidden pseudo-header :path
        var qpack_tr: u8[..64] = [];
        qpack_tr.push(0x00);
        qpack_tr.push(0x00);
        internal::encode_qpack_field(qpack_tr, ":path", "/forbidden", false);

        var wire_tr: u8[..64] = [];
        internal::encode_h3_headers_frame(wire_tr, qpack_tr[..]);
        let err_tr = conn.handle_stream_data(0, true, wire_tr[..], true);
        sub.assert_eq(err_tr, rfc::H3_ERR_GENERAL_PROTOCOL, "request trailers with pseudo-header MUST return H3_ERR_GENERAL_PROTOCOL");
    };

    t.run("H3 Server: reject prohibited framing headers in request trailers") { sub =>
        let settings = wing::H3Settings { .. };
        var conn = internal::new_h3_server_connection(settings);

        var ctrl_wire: u8[..64] = [];
        internal::quic_encode_varint(ctrl_wire, rfc::H3_STREAM_CONTROL);
        internal::encode_h3_settings_frame(ctrl_wire, settings);
        conn.handle_stream_data(3, false, ctrl_wire[..], false);

        var qpack_req: u8[..128] = [];
        qpack_req.push(0x00);
        qpack_req.push(0x00);
        internal::encode_qpack_field(qpack_req, ":method", "POST", false);
        internal::encode_qpack_field(qpack_req, ":scheme", "https", false);
        internal::encode_qpack_field(qpack_req, ":authority", "example.com", false);
        internal::encode_qpack_field(qpack_req, ":path", "/upload", false);

        var wire_req: u8[..128] = [];
        internal::encode_h3_headers_frame(wire_req, qpack_req[..]);
        conn.handle_stream_data(0, true, wire_req[..], false);

        // Client sends trailers with prohibited transfer-encoding
        var qpack_te: u8[..64] = [];
        qpack_te.push(0x00);
        qpack_te.push(0x00);
        internal::encode_qpack_field(qpack_te, "transfer-encoding", "chunked", false);

        var wire_te: u8[..64] = [];
        internal::encode_h3_headers_frame(wire_te, qpack_te[..]);
        let err_te = conn.handle_stream_data(0, true, wire_te[..], true);
        sub.assert_eq(err_te, rfc::H3_ERR_GENERAL_PROTOCOL, "request trailers with transfer-encoding MUST return H3_ERR_GENERAL_PROTOCOL");
    };

    t.run("H3 Server: reject DATA frame or extra HEADERS after request trailers") { sub =>
        let settings = wing::H3Settings { .. };
        var conn = internal::new_h3_server_connection(settings);

        var ctrl_wire: u8[..64] = [];
        internal::quic_encode_varint(ctrl_wire, rfc::H3_STREAM_CONTROL);
        internal::encode_h3_settings_frame(ctrl_wire, settings);
        conn.handle_stream_data(3, false, ctrl_wire[..], false);

        var qpack_req: u8[..128] = [];
        qpack_req.push(0x00);
        qpack_req.push(0x00);
        internal::encode_qpack_field(qpack_req, ":method", "POST", false);
        internal::encode_qpack_field(qpack_req, ":scheme", "https", false);
        internal::encode_qpack_field(qpack_req, ":authority", "example.com", false);
        internal::encode_qpack_field(qpack_req, ":path", "/upload", false);

        var wire_req: u8[..128] = [];
        internal::encode_h3_headers_frame(wire_req, qpack_req[..]);
        conn.handle_stream_data(0, true, wire_req[..], false);

        // Valid trailer: x-checksum
        var qpack_tr: u8[..64] = [];
        qpack_tr.push(0x00);
        qpack_tr.push(0x00);
        internal::encode_qpack_field(qpack_tr, "x-checksum", "deadbeef", false);

        var wire_tr: u8[..64] = [];
        internal::encode_h3_headers_frame(wire_tr, qpack_tr[..]);
        let err_tr = conn.handle_stream_data(0, true, wire_tr[..], false);
        sub.assert_eq(err_tr, rfc::H3_ERR_NO_ERROR, "valid request trailers accepted");

        // Attempt 1: Peer sends DATA frame after trailers
        var wire_d: u8[..32] = [];
        internal::encode_h3_data_frame(wire_d, "extra data");
        let err_data = conn.handle_stream_data(0, true, wire_d[..], false);
        sub.assert_eq(err_data, rfc::H3_ERR_FRAME_UNEXPECTED, "DATA after request trailers MUST return H3_ERR_FRAME_UNEXPECTED");

        // Attempt 2 (new connection): Peer sends a 3rd HEADERS frame after trailers
        var conn2 = internal::new_h3_server_connection(settings);
        conn2.handle_stream_data(3, false, ctrl_wire[..], false);
        conn2.handle_stream_data(0, true, wire_req[..], false);
        conn2.handle_stream_data(0, true, wire_tr[..], false);

        var wire_extra_h: u8[..64] = [];
        internal::encode_h3_headers_frame(wire_extra_h, qpack_tr[..]);
        let err_extra_h = conn2.handle_stream_data(0, true, wire_extra_h[..], true);
        sub.assert_eq(err_extra_h, rfc::H3_ERR_FRAME_UNEXPECTED, "HEADERS after request trailers MUST return H3_ERR_FRAME_UNEXPECTED");
    };
}

// ----------------------------------------------------------------------------
// 33. HTTP/3 Empty DATA Frame Flooding Defense (CVE-2019-9518, RFC 9114 §10.5)
// ----------------------------------------------------------------------------
fn test_h3_empty_frame_flooding(t: lit::T&) {
    t.run("H3: reject flood of empty DATA frames (> 32 streak)") { sub =>
        let settings = wing::H3Settings { .. };
        var conn = internal::new_h3_client_connection(settings);
        let _s0, _ = conn.open_request_stream();

        var ctrl_wire: u8[..64] = [];
        internal::quic_encode_varint(ctrl_wire, rfc::H3_STREAM_CONTROL);
        internal::encode_h3_settings_frame(ctrl_wire, settings);
        conn.handle_stream_data(2, false, ctrl_wire[..], false);

        // Initial 200 response headers
        var qpack_resp: u8[..32] = [];
        qpack_resp.push(0x00);
        qpack_resp.push(0x00);
        internal::encode_qpack_field(qpack_resp, ":status", "200", false);

        var wire_h: u8[..64] = [];
        internal::encode_h3_headers_frame(wire_h, qpack_resp[..]);
        conn.handle_stream_data(0, true, wire_h[..], false);

        // Prepare empty DATA frame
        var wire_empty: u8[..16] = [];
        internal::encode_h3_data_frame(wire_empty, "");

        var err: u64 = rfc::H3_ERR_NO_ERROR;
        for i in 32 {
            err = conn.handle_stream_data(0, true, wire_empty[..], false);
            sub.assert_eq(err, rfc::H3_ERR_NO_ERROR, "empty data frame within budget accepted");
        }

        // The 33rd consecutive empty DATA frame triggers flood defense
        err = conn.handle_stream_data(0, true, wire_empty[..], false);
        sub.assert_eq(err, rfc::H3_ERR_EXCESSIVE_LOAD, "empty data frame exceeding streak MUST return H3_ERR_EXCESSIVE_LOAD");
    };
}

fn main() {
    var runner = lit::new_runner("HTTP/3 Framing, QPACK, and WebTransport Verification Suite", lit::Verbosity.Verbose);

    lit::run_case(runner, "1. Frame Header Encoding, Decoding & GREASE Conformance", test_h3_framing_and_grease);
    lit::run_case(runner, "2. SETTINGS Frame Conformance & Protocol Defenses", test_h3_settings_conformance);
    lit::run_case(runner, "3. Unidirectional Control and QPACK Streams", test_h3_unidirectional_streams);
    lit::run_case(runner, "4. Request Stream Lifecycle & Full Request-Response Multiplexing", test_h3_request_streams);
    lit::run_case(runner, "5. QPACK Table Lifecycle, String Decoding & Stream Instructions", test_qpack_table_and_codec);
    lit::run_case(runner, "6. HTTP/3 Extended Frames & Stream Edge-Cases", test_h3_extended_frames);
    lit::run_case(runner, "7. Team QPackStrike Protocol Hardening Suite", test_round1_qpackstrike_suite);
    lit::run_case(runner, "8. Team QPackStrike Round 2 Hardening Suite", test_round2_qpackstrike_suite);
    lit::run_case(runner, "9. Team QPackStrike Round 3 Championship Suite", test_round3_qpackstrike_suite);
    lit::run_case(runner, "10. WebTransport Session & Datagrams", test_webtransport_session_and_datagrams);
    lit::run_case(runner, "11. WebTransport Stream Framing", test_webtransport_stream_framing);
    lit::run_case(runner, "12. WebTransport Error Code Mapping", test_webtransport_error_mapping);
    lit::run_case(runner, "13. WebTransport Capsule Codecs", test_webtransport_capsules);
    lit::run_case(runner, "14. WebTransport Session Lifecycle", test_webtransport_session_lifecycle);
    lit::run_case(runner, "15. WebTransport Stream Demuxing & Session Routing", test_webtransport_stream_demuxing);
    lit::run_case(runner, "16. HTTP/3 Bug Hunter Audit Regressions (F001-F006)", test_h3_audit_regressions);
    lit::run_case(runner, "17. nghttp3 Vendor Conformance Vectors", test_nghttp3_vendor_conformance);
    lit::run_case(runner, "18. nghttp3 Control Stream, SETTINGS, GOAWAY & Request Ordering", test_nghttp3_conn_and_http_semantics);
    lit::run_case(runner, "19. F009 Alt-Svc Slot Prioritization & Backoff Saturation", test_f009_altsvc_slot_prioritization_and_backoff_saturation);
    lit::run_case(runner, "20. RFC 9114 §4.2: QPACK Uppercase Literal Field Names", test_qpack_uppercase_literal_field_name_rejection);
    lit::run_case(runner, "21. RFC 9114 §6.2.1 & Go #78102: Duplicate HTTP/3 Control Stream Rejection", test_h3_duplicate_control_stream_rejection);
    lit::run_case(runner, "22. RFC 9114 §4.3: HTTP/3 / QPACK Duplicate Pseudo-Headers & Order Invariants", test_h3_pseudo_header_invariants);
    lit::run_case(runner, "23. HTTP/3 unknown pseudo-header & CTL character rejection (http3/connection.goose)", test_h3_pseudo_header_unknown_and_ctl);
    lit::run_case(runner, "24. Alt-Svc oversized proto/host/endpoints capacity safety (http/altsvc.goose)", test_altsvc_oversized_capacity_safety);
    lit::run_case(runner, "25. HTTP/3 & QPACK RFC 9114 / RFC 9204 (http3/*)", test_h3_and_qpack_rfc9114_rfc9204);
    lit::run_case(runner, "26. QPACK Modular RIC, Post-Base Bounds & Bare-Colon Token Sanitization", test_qpack_invariants_and_token_defenses);
    lit::run_case(runner, "27. HTTP/3 Framing, Reserved 0x00 Setting & Malformed Payloads", test_h3_framing_and_settings_invariants);
    lit::run_case(runner, "28. HTTP/3 Multiplexer, Unidirectional Dispatch & Trailer Defenses", test_h3_multiplexer_and_stream_defenses);
    lit::run_case(runner, "29. HTTP/3 Stream Data Host vs :authority Conflict & Host Syntax", test_h3_host_authority_conflict_and_syntax);
    lit::run_case(runner, "30. HTTP/3 DATA Frame Rejection on Bodyless Status Codes (204, 304, 1xx)", test_h3_bodyless_status_data_rejection);
    lit::run_case(runner, "31. HTTP/3 Prohibited Trailer Framing Headers & QPACK NUL/CR/LF Injection", test_h3_prohibited_trailers_and_qpack_nul_rejection);
    lit::run_case(runner, "32. HTTP/3 Server Request Trailers Invariants", test_h3_server_request_trailers_invariants);
    lit::run_case(runner, "33. HTTP/3 Empty DATA Frame Flooding Defense", test_h3_empty_frame_flooding);

    let ok = lit::finish(runner);
    assert(ok);
}
