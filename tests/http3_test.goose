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
            wing::encode_client_preambles(conn, ctrl_buf, qenc_buf, qdec_buf),
            "encode client preambles",
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

        let err_no_set = wing::handle_stream_data(conn, 3, false, bad_ctrl[..], false);
        sub.assert_eq(
            err_no_set,
            wing::H3_ERR_MISSING_SETTINGS,
            "first frame not SETTINGS triggers H3_MISSING_SETTINGS (0x010A)",
        );

        // Valid server control stream: Stream Type 0x00 || SETTINGS frame
        var conn2 = wing::new_h3_client_connection(settings);
        var good_ctrl: u8[..64] = [];
        wing::quic_encode_varint(good_ctrl, wing::H3_STREAM_CONTROL);
        wing::encode_h3_settings_frame(good_ctrl, settings);

        let err_ok = wing::handle_stream_data(conn2, 3, false, good_ctrl[..], false);
        sub.assert_eq(err_ok, wing::H3_ERR_NO_ERROR, "valid control stream processed ok");
        sub.assert_true(conn2.peer_settings_received, "peer settings recorded");

        // Second SETTINGS frame received later on control stream
        var second_settings: u8[..64] = [];
        wing::encode_h3_settings_frame(second_settings, settings);
        let err_second = wing::handle_stream_data(conn2, 3, false, second_settings[..], false);
        sub.assert_eq(
            err_second,
            wing::H3_ERR_FRAME_UNEXPECTED,
            "second SETTINGS frame triggers H3_FRAME_UNEXPECTED (0x0105)",
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
            "closing QPACK encoder stream triggers H3_CLOSED_CRITICAL_STREAM (0x0104)",
        );

        // Reset conn to test control stream closure
        var conn_ctrl = wing::new_h3_client_connection(settings);
        conn_ctrl.handle_stream_data(3, false, good_ctrl[..], false);
        let err_crit = conn_ctrl.handle_stream_data(3, false, [], true);
        sub.assert_eq(
            err_crit,
            wing::H3_ERR_CLOSED_CRITICAL_STREAM,
            "closing control stream triggers H3_CLOSED_CRITICAL_STREAM (0x0104)",
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
            req_buf,
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
            "DATA before HEADERS triggers H3_FRAME_UNEXPECTED (0x0105)",
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
// 5. QPACK Table Lifecycle, String Decoding & Stream Instructions (RFC 9204)
// ============================================================================
fn test_qpack_table_and_codec(t: core::T&) {
    t.run("QPACK-01: Table Capacity and Entry Management") { sub =>
        var tbl = wing::new_qpack_table(4096, 16);
        sub.assert_eq(tbl.capacity_bytes, 4096, "capacity is 4096");
        sub.assert_eq(tbl.insert_count, 0, "initial insert count is 0");

        // Literal insertion
        sub.assert_true(wing::qpack_insert_literal(tbl, "custom-key", "custom-val"), "insert literal");
        sub.assert_eq(tbl.insert_count, 1, "insert count incremented to 1");

        // Lookup absolute
        var name_buf: u8[..256] = [];
        var val_buf: u8[..4096] = [];
        let ok_lookup = wing::qpack_lookup_absolute(tbl, 0, name_buf, val_buf);
        sub.assert_true(ok_lookup, "lookup absolute 0");
        sub.assert_eq(name_buf[..], "custom-key", "key matches");
        sub.assert_eq(val_buf[..], "custom-val", "val matches");

        // Static name reference insertion (index 17 is ":status")
        sub.assert_true(wing::qpack_insert_named_static(tbl, 17, "200"), "insert named static");
        sub.assert_eq(tbl.insert_count, 2, "insert count is 2");

        // Dynamic name reference insertion (relative 0 is latest entry: ":status")
        sub.assert_true(wing::qpack_insert_named_dynamic(tbl, 0, "404"), "insert named dynamic");
        sub.assert_eq(tbl.insert_count, 3, "insert count is 3");

        // Duplicate entry (relative 0 is latest entry)
        sub.assert_true(wing::qpack_duplicate(tbl, 0), "duplicate latest entry");
        sub.assert_eq(tbl.insert_count, 4, "insert count is 4");

        // Capacity shrink causing eviction
        sub.assert_true(wing::qpack_set_capacity(tbl, 100), "shrink capacity");
        sub.assert_eq(tbl.capacity_bytes, 100, "capacity updated");

        // Section ACK and cancellation
        wing::qpack_ack_section(tbl, 4, 1);
        wing::qpack_cancel_stream(tbl, 4);
        wing::qpack_increment_received(tbl, 2);
    };

    t.run("QPACK-02: String Decoding (Plain and Huffman)") { sub =>
        // Plain string: "custom-value"
        var plain_encoded: u8[..32] = [];
        plain_encoded.push(12); // length 12, H=0
        plain_encoded.append("custom-value");

        var plain_out: u8[..64] = [];
        let next_p, ok_p = wing::decode_qpack_string(plain_encoded[..], 0, 7, plain_out);
        sub.assert_true(ok_p, "decode plain string");
        sub.assert_eq(plain_out[..], "custom-value", "plain string matches");
        sub.assert_eq(next_p, 13, "next offset is 13");

        // Out-of-bounds offset test
        var err_out: u8[..16] = [];
        let _, ok_err = wing::decode_qpack_string(plain_encoded[..], 50, 7, err_out);
        sub.assert_false(ok_err, "decode out-of-bounds string fails safely");
    };

    t.run("QPACK-03: Encoder Stream Instruction Parsing") { sub =>
        var tbl = wing::new_qpack_table(4096, 16);

        // 1. Set Dynamic Table Capacity instruction: 0x3F 0xE1 0x1F (capacity 4096)
        var enc_cap: u8[..16] = [];
        enc_cap.push(0x3F);
        enc_cap.push(0xE1);
        enc_cap.push(0x1F);
        let _, err1 = wing::qpack_process_encoder_instruction(tbl, enc_cap[..], 0);
        sub.assert_eq(err1, wing::QpackError.None, "set capacity instruction succeeds");

        // 2. Insert with literal name and value: 0100 0110 "custom" 0000 0101 "value"
        var enc_lit: u8[..32] = [];
        enc_lit.push(0x46); // 0100 0110 (N=0, H=0, name_len=6)
        enc_lit.append("custom");
        enc_lit.push(0x05); // H=0, val_len=5
        enc_lit.append("value");
        let _, err2 = wing::qpack_process_encoder_instruction(tbl, enc_lit[..], 0);
        sub.assert_eq(err2, wing::QpackError.None, "insert literal instruction succeeds");
        sub.assert_eq(tbl.insert_count, 1, "table has 1 entry");

        // 3. Duplicate instruction: 000xxxxx (duplicate relative index 0)
        var enc_dup: u8[..4] = [];
        enc_dup.push(0x00); // 0000 0000: duplicate rel 0
        let _, err3 = wing::qpack_process_encoder_instruction(tbl, enc_dup[..], 0);
        sub.assert_eq(err3, wing::QpackError.None, "duplicate instruction succeeds");
        sub.assert_eq(tbl.insert_count, 2, "table has 2 entries");
    };

    t.run("QPACK-04: Decoder Stream Instruction Parsing") { sub =>
        var tbl = wing::new_qpack_table(4096, 16);

        // 1. Section Acknowledgment (1xxxxxxx) for stream 4
        var dec_ack: u8[..8] = [];
        dec_ack.push(0x84); // 1000 0100 -> stream 4
        let _, err_d1 = wing::qpack_process_decoder_instruction(tbl, dec_ack[..], 0);
        sub.assert_eq(err_d1, wing::QpackError.None, "section ack succeeds");

        // 2. Stream Cancellation (01xxxxxx) for stream 4
        var dec_canc: u8[..8] = [];
        dec_canc.push(0x44); // 0100 0100 -> stream 4
        let _, err_d2 = wing::qpack_process_decoder_instruction(tbl, dec_canc[..], 0);
        sub.assert_eq(err_d2, wing::QpackError.None, "stream cancellation succeeds");

        // 3. Insert Count Increment (00xxxxxx) with increment 3 (RFC 9204 Section 4.4.3)
        tbl.insert_count = 3;
        var dec_inc: u8[..8] = [];
        dec_inc.push(0x03); // 0000 0011 -> inc 3
        let _, err_d3 = wing::qpack_process_decoder_instruction(tbl, dec_inc[..], 0);
        sub.assert_eq(err_d3, wing::QpackError.None, "insert count increment succeeds");
        sub.assert_eq(tbl.known_rcvd_count, 3, "known received count updated to 3");

        // 4. Excess Insert Count Increment beyond insert_count must fail with DecoderStreamError
        dec_inc.clear();
        dec_inc.push(0x01); // inc 1 -> 3 + 1 = 4 > insert_count (3)
        let _, err_d4 = wing::qpack_process_decoder_instruction(tbl, dec_inc[..], 0);
        sub.assert_eq(err_d4, wing::QpackError.DecoderStreamError, "excess increment rejected per RFC 9204 Section 4.4.3");
    };

    t.run("QPACK-05: Section Decoding (Static, Dynamic, and Literal Fields)") { sub =>
        var tbl = wing::new_qpack_table(4096, 16);
        // Insert entry: "x-api-version" -> "v2"
        wing::qpack_insert_literal(tbl, "x-api-version", "v2");

        // Build section:
        var sec: u8[..128] = [];
        // Encoded RIC: RIC=1, max_cap=4096 => encoded = 2 (RFC 9204 Section 4.5.1)
        let enc_ric = wing::encode_ric(1, tbl.capacity_bytes);
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

        var out_fields: wing::HeaderField[>..] = [];
        let err = wing::decode_qpack_section(tbl, sec[..], out_fields, 16384);
        sub.assert_eq(err, wing::QpackError.None, "decode section succeeds");
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

// ============================================================================
// 6. HTTP/3 Extended Frames & Stream Edge-Cases
// ============================================================================
fn test_h3_extended_frames(t: core::T&) {
    t.run("H3-13: Extended Frame Encoding & Inbound Ingestion") { sub =>
        let settings = wing::H3Settings { .. };
        var conn = wing::new_h3_client_connection(settings);

        // Encode and parse CANCEL_PUSH frame
        var cp_buf: u8[..32] = [];
        sub.assert_true(wing::encode_h3_cancel_push(cp_buf, 42), "encode CANCEL_PUSH");
        let cp_hdr, ok_cp_hdr = wing::parse_h3_frame_header(cp_buf[..], 0);
        sub.assert_true(ok_cp_hdr, "parse CANCEL_PUSH frame header");
        let cp_id, ok_cp = wing::parse_h3_cancel_push(cp_buf[cp_hdr.header_len..cp_hdr.header_len + cp_hdr.payload_len]);
        sub.assert_true(ok_cp, "parse CANCEL_PUSH");
        sub.assert_eq(cp_id, 42, "push id matches");

        // Encode and parse MAX_PUSH_ID frame
        var mp_buf: u8[..32] = [];
        sub.assert_true(wing::encode_h3_max_push_id(mp_buf, 100), "encode MAX_PUSH_ID");
        let mp_hdr, ok_mp_hdr = wing::parse_h3_frame_header(mp_buf[..], 0);
        sub.assert_true(ok_mp_hdr, "parse MAX_PUSH_ID frame header");
        let mp_id, ok_mp = wing::parse_h3_max_push_id(mp_buf[mp_hdr.header_len..mp_hdr.header_len + mp_hdr.payload_len]);
        sub.assert_true(ok_mp, "parse MAX_PUSH_ID");
        sub.assert_eq(mp_id, 100, "max push id matches");

        // Encode and parse PRIORITY_UPDATE frame for Request Stream
        var pu_buf: u8[..64] = [];
        let p_req = wing::PriorityParam { urgency: 3, incremental: true };
        sub.assert_true(wing::encode_h3_priority_update_request(pu_buf, 0, p_req), "encode PRIORITY_UPDATE req");
        let pu_hdr, ok_pu_hdr = wing::parse_h3_frame_header(pu_buf[..], 0);
        sub.assert_true(ok_pu_hdr, "parse PRIORITY_UPDATE req header");
        let pr_elem, pr_prio, ok_pr = wing::parse_h3_priority_update_request(pu_buf[pu_hdr.header_len..pu_hdr.header_len + pu_hdr.payload_len]);
        sub.assert_true(ok_pr, "parse PRIORITY_UPDATE req");
        sub.assert_eq(pr_elem, 0, "elem id is 0");
        sub.assert_eq(pr_prio.urgency, 3, "urgency is 3");
        sub.assert_true(pr_prio.incremental, "incremental is true");

        // Encode and parse PRIORITY_UPDATE frame for Push Stream
        var pp_buf: u8[..64] = [];
        let p_push = wing::PriorityParam { urgency: 5, incremental: false };
        sub.assert_true(wing::encode_h3_priority_update_push(pp_buf, 1, p_push), "encode PRIORITY_UPDATE push");
        let pp_hdr, ok_pp_hdr = wing::parse_h3_frame_header(pp_buf[..], 0);
        sub.assert_true(ok_pp_hdr, "parse PRIORITY_UPDATE push header");
        let pp_elem, pp_prio, ok_pp = wing::parse_h3_priority_update_push(pp_buf[pp_hdr.header_len..pp_hdr.header_len + pp_hdr.payload_len]);
        sub.assert_true(ok_pp, "parse PRIORITY_UPDATE push");
        sub.assert_eq(pp_elem, 1, "elem id is 1");
        sub.assert_eq(pp_prio.urgency, 5, "urgency is 5");
        sub.assert_false(pp_prio.incremental, "incremental is false");

        // Ingest control stream with extended frames (CANCEL_PUSH, MAX_PUSH_ID, PRIORITY_UPDATE)
        var ctrl_wire: u8[..256] = [];
        wing::quic_encode_varint(ctrl_wire, wing::H3_STREAM_CONTROL);
        wing::encode_h3_settings_frame(ctrl_wire, settings);
        wing::encode_h3_cancel_push(ctrl_wire, 1);
        wing::encode_h3_max_push_id(ctrl_wire, 10);
        wing::encode_h3_priority_update_request(ctrl_wire, 0, p_req);

        let err_ctrl = conn.handle_stream_data(3, false, ctrl_wire[..], false);
        sub.assert_eq(err_ctrl, wing::H3_ERR_NO_ERROR, "ingest extended frames on control stream");
    };

    t.run("H3-14: Send Request Data Edge Cases") { sub =>
        let settings = wing::H3Settings { .. };
        var conn = wing::new_h3_client_connection(settings);

        let sid, _ = conn.open_request_stream();

        // Send headers
        var req_buf: u8[..256] = [];
        var hdrs = wing::new_header_map();
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

// ============================================================================
// 7. Team QPackStrike Protocol Hardening Suite (RFC 9114, RFC 9204, RFC 9000)
// ============================================================================
fn test_round1_qpackstrike_suite(t: core::T&) {
    t.run("QPACK-R1-01: 62-bit Integer Decoding and Overflow Rejection (RFC 9204 Section 4.1.1)") { sub =>
        // 62-bit integer: 0x3FFFFFFFFFFFFFFF
        // With 7-bit prefix: prefix byte 0x7F, followed by 9 continuation octets
        var buf62: u8[..16] = [0x7F, 0x80, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x3F];
        let val62, next_off62, ok62 = wing::qpack_decode_int(buf62[..], 0, 7);
        sub.assert_true(ok62, "decode max 62-bit integer 0x3FFFFFFFFFFFFFFF succeeds");
        sub.assert_eq(val62, wing::QPACK_MAX_INT_VAL, "decoded value matches 0x3FFFFFFFFFFFFFFF");
        sub.assert_eq(next_off62, 10, "consumed 10 bytes");

        // 63-bit integer overflow: payload > 0x3F at 9th continuation byte (0x40)
        var buf_overflow: u8[..16] = [0x7F, 0x80, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x40];
        let _, _, ok_ovf = wing::qpack_decode_int(buf_overflow[..], 0, 7);
        sub.assert_false(ok_ovf, "63-bit integer overflow rejected");

        // Overflow on encoder stream returns EncoderStreamError
        var tbl = wing::new_qpack_table(4096, 16);
        var enc_ovf: u8[..16] = [0x3F, 0x80, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x40];
        let _, err_enc = wing::qpack_process_encoder_instruction(tbl, enc_ovf[..], 0);
        sub.assert_eq(err_enc, wing::QpackError.EncoderStreamError, "overflow on encoder stream yields EncoderStreamError");

        // Overflow on decoder stream returns DecoderStreamError
        var dec_ovf: u8[..16] = [0xFF, 0x80, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x40];
        let _, err_dec = wing::qpack_process_decoder_instruction(tbl, dec_ovf[..], 0);
        sub.assert_eq(err_dec, wing::QpackError.DecoderStreamError, "overflow on decoder stream yields DecoderStreamError");
    };

    t.run("QPACK-R1-02: Zero Capacity Rejects Dynamic Table Insertion (RFC 9204 Section 3.2.3, 3.2.4)") { sub =>
        var tbl = wing::new_qpack_table(4096, 16);
        tbl.capacity_bytes = 0; // Explicitly capacity 0

        // Attempt Insert with Literal Name when capacity is 0
        var enc_lit: u8[..32] = [];
        enc_lit.push(0x46);
        enc_lit.append("custom");
        enc_lit.push(0x05);
        enc_lit.append("value");
        let _, err_ins = wing::qpack_process_encoder_instruction(tbl, enc_lit[..], 0);
        sub.assert_eq(err_ins, wing::QpackError.EncoderStreamError, "insert when capacity=0 rejected with EncoderStreamError");

        // Attempt Duplicate when capacity is 0
        var enc_dup: u8[..4] = [0x00];
        let _, err_dup = wing::qpack_process_encoder_instruction(tbl, enc_dup[..], 0);
        sub.assert_eq(err_dup, wing::QpackError.EncoderStreamError, "duplicate when capacity=0 rejected with EncoderStreamError");
    };

    t.run("H3-R1-01: Frame Payload Length Integer Overflow Protection (RFC 9114 Section 7.1)") { sub =>
        let settings = wing::H3Settings { .. };
        var conn = wing::new_h3_client_connection(settings);

        // Control stream: valid SETTINGS frame first
        var ctrl_wire: u8[..128] = [];
        wing::quic_encode_varint(ctrl_wire, wing::H3_STREAM_CONTROL);
        wing::encode_h3_settings_frame(ctrl_wire, settings);
        conn.handle_stream_data(3, false, ctrl_wire[..], false);
        sub.assert_true(conn.peer_settings_received, "peer settings received");

        // Now send frame header with maliciously crafted 62-bit payload length (0x3FFFFFFFFFFFFFF0)
        // that would overflow 'offset + hdr.payload_len'
        var mal_frame: u8[..32] = [];
        wing::quic_encode_varint(mal_frame, wing::H3_FRAME_CANCEL_PUSH);
        wing::quic_encode_varint(mal_frame, 0x3FFFFFFFFFFFFFF0);
        mal_frame.push(0x00);

        let err = conn.handle_stream_data(3, false, mal_frame[..], false);
        sub.assert_eq(err, wing::H3_ERR_FRAME_ERROR, "huge payload_len triggers H3_FRAME_ERROR without overflow");
        sub.assert_eq(conn.state, wing::H3ConnState.Closed, "connection closed on frame error");
    };

    t.run("H3-R1-02: HTTP/2 Reserved Frame 0x0A (ALTSVC) Rejection (RFC 9114 Section 7.2.8)") { sub =>
        sub.assert_true(wing::is_h2_reserved_frame_in_h3(0x0A), "0x0A is reserved from H2");
        sub.assert_false(wing::is_allowed_on_control_stream(0x0A), "0x0A forbidden on control stream");
        sub.assert_false(wing::is_allowed_on_request_stream(0x0A), "0x0A forbidden on request stream");

        let settings = wing::H3Settings { .. };
        var conn = wing::new_h3_client_connection(settings);

        // Control stream with valid SETTINGS followed by frame type 0x0A
        var ctrl_wire: u8[..64] = [];
        wing::quic_encode_varint(ctrl_wire, wing::H3_STREAM_CONTROL);
        wing::encode_h3_settings_frame(ctrl_wire, settings);
        wing::quic_encode_varint(ctrl_wire, 0x0A);
        wing::quic_encode_varint(ctrl_wire, 0);

        let err = conn.handle_stream_data(3, false, ctrl_wire[..], false);
        sub.assert_eq(err, wing::H3_ERR_FRAME_UNEXPECTED, "frame 0x0A rejected with H3_FRAME_UNEXPECTED");
    };

    t.run("H3-R1-03: Unknown Unidirectional Stream Persistence (RFC 9114 Section 6.2)") { sub =>
        let settings = wing::H3Settings { .. };
        var conn = wing::new_h3_client_connection(settings);

        var ctrl: u8[..64] = [];
        wing::quic_encode_varint(ctrl, wing::H3_STREAM_CONTROL);
        wing::encode_h3_settings_frame(ctrl, settings);
        conn.handle_stream_data(3, false, ctrl[..], false);

        // Open unknown unidirectional stream 15 (type 0x21 GREASE)
        var chunk1: u8[..16] = [];
        wing::quic_encode_varint(chunk1, 0x21);
        let err1 = conn.handle_stream_data(15, false, chunk1[..], false);
        sub.assert_eq(err1, wing::H3_ERR_NO_ERROR, "unknown uni stream chunk 1 accepted");

        // Send second chunk with leading byte 0x00
        var chunk2: u8[..16] = [0x00, 0x01, 0x02, 0x03];
        let err2 = conn.handle_stream_data(15, false, chunk2[..], false);
        sub.assert_eq(err2, wing::H3_ERR_NO_ERROR, "unknown uni stream chunk 2 ignored safely");
        sub.assert_eq(conn.error_code, wing::H3_ERR_NO_ERROR, "connection still valid");
    };

    t.run("QUIC-R1-01: Datagram Frame Length Integer Overflow Protection (RFC 9221 Section 3)") { sub =>
        var wire: u8[..16] = [];
        wing::quic_encode_varint(wire, wing::QUIC_FRAME_DATAGRAM_LEN);
        wing::quic_encode_varint(wire, 0x3FFFFFFFFFFFFFF0);

        let payload, _, ok = wing::decode_quic_datagram_frame(wire[..], 0, wire.len as u64);
        sub.assert_false(ok, "overflowing datagram frame length safely rejected");
        sub.assert_eq(payload.len, 0, "no slice produced");
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
    core::run_case(runner, "5. QPACK Table Lifecycle, String Decoding & Stream Instructions", test_qpack_table_and_codec);
    core::run_case(runner, "6. HTTP/3 Extended Frames & Stream Edge-Cases", test_h3_extended_frames);
    core::run_case(runner, "7. Team QPackStrike Protocol Hardening Suite", test_round1_qpackstrike_suite);

    let ok = core::finish(runner);
    assert(ok);
}
