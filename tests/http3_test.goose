// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// tests/http3_test.goose
// Conformance and Security Defense Suite for HTTP/3 (RFC 9114) and QPACK (RFC 9204).
import std;
import core from "..";
import wing from "..";

// 1. Frame Header Encoding, Decoding & GREASE Conformance
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

// 2. SETTINGS Frame Conformance & Protocol Defenses
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

// 3. Unidirectional Control and QPACK Streams
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

// 4. Request Stream Lifecycle & Full Request-Response Multiplexing
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

// 5. QPACK Table Lifecycle, String Decoding & Stream Instructions (RFC 9204)
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

// 6. HTTP/3 Extended Frames & Stream Edge-Cases
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

// 7. Team QPackStrike Protocol Hardening Suite (RFC 9114, RFC 9204, RFC 9000)
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

// 8. Team QPackStrike Round 2 Protocol Audit Suite (RFC 9114, RFC 9204, RFC 9000)
fn test_round2_qpackstrike_suite(t: core::T&) {
    t.run("H3-R2-01: Control Stream Frame Sequence & Missing SETTINGS Precedence (RFC 9114 §6.2.1, §7.2.4)") { sub =>
        let settings = wing::H3Settings { .. };

        // Test A: DATA frame (0x00) sent as first frame on control stream MUST trigger H3_ERR_MISSING_SETTINGS (0x010A)
        var conn1 = wing::new_h3_client_connection(settings);
        var bad_ctrl1: u8[..64] = [];
        wing::quic_encode_varint(bad_ctrl1, wing::H3_STREAM_CONTROL);
        wing::encode_h3_frame_header(bad_ctrl1, wing::H3_FRAME_DATA, 4);
        bad_ctrl1.append([1, 2, 3, 4]);

        let err1 = conn1.handle_stream_data(3, false, bad_ctrl1[..], false);
        sub.assert_eq(err1, wing::H3_ERR_MISSING_SETTINGS, "initial DATA frame on control stream MUST return H3_MISSING_SETTINGS (0x010A)");
        sub.assert_eq(conn1.state, wing::H3ConnState.Closed, "connection closed");
        sub.assert_eq(conn1.error_code, wing::H3_ERR_MISSING_SETTINGS, "error code is H3_MISSING_SETTINGS");

        // Test B: HEADERS frame (0x01) sent as first frame on control stream MUST trigger H3_ERR_MISSING_SETTINGS (0x010A)
        var conn2 = wing::new_h3_client_connection(settings);
        var bad_ctrl2: u8[..64] = [];
        wing::quic_encode_varint(bad_ctrl2, wing::H3_STREAM_CONTROL);
        wing::encode_h3_frame_header(bad_ctrl2, wing::H3_FRAME_HEADERS, 2);
        bad_ctrl2.append([0x00, 0x00]);

        let err2 = conn2.handle_stream_data(3, false, bad_ctrl2[..], false);
        sub.assert_eq(err2, wing::H3_ERR_MISSING_SETTINGS, "initial HEADERS frame on control stream MUST return H3_MISSING_SETTINGS (0x010A)");
        sub.assert_eq(conn2.state, wing::H3ConnState.Closed, "connection closed");

        // Test C: Valid SETTINGS as first frame succeeds
        var conn3 = wing::new_h3_client_connection(settings);
        var good_ctrl: u8[..64] = [];
        wing::quic_encode_varint(good_ctrl, wing::H3_STREAM_CONTROL);
        wing::encode_h3_settings_frame(good_ctrl, settings);
        let err3 = conn3.handle_stream_data(3, false, good_ctrl[..], false);
        sub.assert_eq(err3, wing::H3_ERR_NO_ERROR, "initial SETTINGS succeeds");
        sub.assert_eq(conn3.state, wing::H3ConnState.Active, "connection active");

        // Test D: Subsequent DATA frame after SETTINGS triggers H3_FRAME_UNEXPECTED (0x0105)
        var bad_post_settings: u8[..64] = [];
        wing::encode_h3_frame_header(bad_post_settings, wing::H3_FRAME_DATA, 4);
        bad_post_settings.append([1, 2, 3, 4]);
        let err4 = conn3.handle_stream_data(3, false, bad_post_settings[..], false);
        sub.assert_eq(err4, wing::H3_ERR_FRAME_UNEXPECTED, "subsequent DATA frame triggers H3_FRAME_UNEXPECTED (0x0105)");
        sub.assert_eq(conn3.state, wing::H3ConnState.Closed, "connection closed");
    };

    t.run("H3-R2-02: GOAWAY Stream ID Monotonicity and Client-Bidi Validation (RFC 9114 §5.2, §7.2.6)") { sub =>
        let settings = wing::H3Settings { .. };

        // Test A: Initial GOAWAY with non-client-bidi stream ID triggers H3_ERR_ID_ERROR (0x0108)
        // Stream ID 1: server-initiated bidirectional ((1 & 0x03) == 1)
        var conn1 = wing::new_h3_client_connection(settings);
        var init_ctrl: u8[..64] = [];
        wing::quic_encode_varint(init_ctrl, wing::H3_STREAM_CONTROL);
        wing::encode_h3_settings_frame(init_ctrl, settings);
        conn1.handle_stream_data(3, false, init_ctrl[..], false);

        var bad_ga1: u8[..32] = [];
        wing::encode_h3_goaway_frame(bad_ga1, 1); // Server-bidi ID 1
        let err1 = conn1.handle_stream_data(3, false, bad_ga1[..], false);
        sub.assert_eq(err1, wing::H3_ERR_ID_ERROR, "GOAWAY with server-bidi stream ID MUST trigger H3_ERR_ID_ERROR");
        sub.assert_eq(conn1.state, wing::H3ConnState.Closed, "connection closed");

        // Test B: Initial GOAWAY with client-uni stream ID triggers H3_ERR_ID_ERROR
        // Stream ID 2: client-initiated unidirectional ((2 & 0x03) == 2)
        var conn2 = wing::new_h3_client_connection(settings);
        conn2.handle_stream_data(3, false, init_ctrl[..], false);
        var bad_ga2: u8[..32] = [];
        wing::encode_h3_goaway_frame(bad_ga2, 2); // Client-uni ID 2
        let err2 = conn2.handle_stream_data(3, false, bad_ga2[..], false);
        sub.assert_eq(err2, wing::H3_ERR_ID_ERROR, "GOAWAY with client-uni stream ID MUST trigger H3_ERR_ID_ERROR");

        // Test C: Valid GOAWAY with client-bidi stream ID 8 succeeds
        var conn3 = wing::new_h3_client_connection(settings);
        conn3.handle_stream_data(3, false, init_ctrl[..], false);
        var good_ga: u8[..32] = [];
        wing::encode_h3_goaway_frame(good_ga, 8); // Client-bidi ID 8 ((8 & 0x03) == 0)
        let err3 = conn3.handle_stream_data(3, false, good_ga[..], false);
        sub.assert_eq(err3, wing::H3_ERR_NO_ERROR, "valid GOAWAY accepted");
        sub.assert_eq(conn3.state, wing::H3ConnState.Draining, "connection state is Draining");
        sub.assert_eq(conn3.goaway_max_stream_id, 8, "max stream id is 8");

        // Test D: Subsequent GOAWAY with increased stream ID triggers H3_ERR_ID_ERROR
        var bad_seq_ga: u8[..32] = [];
        wing::encode_h3_goaway_frame(bad_seq_ga, 12); // 12 > 8: non-monotonic increase!
        let err4 = conn3.handle_stream_data(3, false, bad_seq_ga[..], false);
        sub.assert_eq(err4, wing::H3_ERR_ID_ERROR, "increasing GOAWAY stream ID MUST trigger H3_ERR_ID_ERROR");
        sub.assert_eq(conn3.state, wing::H3ConnState.Closed, "connection closed");

        // Test E: Subsequent GOAWAY with decreased stream ID succeeds
        var conn4 = wing::new_h3_client_connection(settings);
        conn4.handle_stream_data(3, false, init_ctrl[..], false);
        conn4.handle_stream_data(3, false, good_ga[..], false); // first GOAWAY with 8
        var good_seq_ga: u8[..32] = [];
        wing::encode_h3_goaway_frame(good_seq_ga, 4); // 4 <= 8: monotonic decrease
        let err5 = conn4.handle_stream_data(3, false, good_seq_ga[..], false);
        sub.assert_eq(err5, wing::H3_ERR_NO_ERROR, "decreasing GOAWAY accepted");
        sub.assert_eq(conn4.goaway_max_stream_id, 4, "max stream id updated to 4");

        // Test F: GOAWAY with malformed payload (extra trailing bytes) triggers H3_ERR_FRAME_ERROR (RFC 9114 §7.2.6)
        var conn5 = wing::new_h3_client_connection(settings);
        conn5.handle_stream_data(3, false, init_ctrl[..], false);
        var bad_pl_ga: u8[..32] = [];
        wing::encode_h3_frame_header(bad_pl_ga, wing::H3_FRAME_GOAWAY, 2);
        bad_pl_ga.push(0x00); // stream ID 0
        bad_pl_ga.push(0xFF); // trailing extra garbage byte
        let err6 = conn5.handle_stream_data(3, false, bad_pl_ga[..], false);
        sub.assert_eq(err6, wing::H3_ERR_FRAME_ERROR, "malformed GOAWAY payload MUST return H3_ERR_FRAME_ERROR");
    };

    t.run("QPACK-R2-01: Eviction Barrier and Blocked Streams Constraints (RFC 9204 §2.1.1, §2.1.2)") { sub =>
        // Test A: Pinned entry prevents eviction flooding
        var tbl = wing::new_qpack_table(128, 4);
        wing::qpack_insert_literal(tbl, "x-pinned", "val1"); // ~46 bytes, abs_idx 0
        wing::qpack_pin_entry(tbl, 0); // Pin entry 0

        wing::qpack_insert_literal(tbl, "x-second", "val2"); // ~46 bytes, abs_idx 1 (total ~92 <= 128)
        // Inserting 3rd entry (~46 bytes, total 138 > 128) requires evicting entry 0
        // Because entry 0 is pinned, eviction MUST fail and insertion returns false
        let ok_blocked = wing::qpack_insert_literal(tbl, "x-third", "val3");
        sub.assert_false(ok_blocked, "insertion requiring eviction of pinned entry fails");

        // After unpinning, eviction succeeds
        wing::qpack_unpin_entry(tbl, 0);
        let ok_unpinned = wing::qpack_insert_literal(tbl, "x-third", "val3");
        sub.assert_true(ok_unpinned, "insertion succeeds after unpinning");

        // Test B: Blocked streams manager helpers
        var tbl_b = wing::new_qpack_table(512, 2);
        sub.assert_true(wing::qpack_can_block_stream(tbl_b), "can block stream when under max_blocked");
        sub.assert_true(wing::qpack_block_stream(tbl_b, 0, 5, "payload0"), "block stream 0");
        sub.assert_true(wing::qpack_is_stream_blocked(tbl_b, 0), "stream 0 is blocked");
        sub.assert_true(wing::qpack_block_stream(tbl_b, 4, 6, "payload4"), "block stream 4");
        sub.assert_false(wing::qpack_can_block_stream(tbl_b), "cannot block stream when at max_blocked (2)");
        sub.assert_false(wing::qpack_block_stream(tbl_b, 8, 7, "payload8"), "blocking stream 8 fails when max_blocked exceeded");

        sub.assert_true(wing::qpack_unblock_stream(tbl_b, 0), "unblock stream 0");
        sub.assert_false(wing::qpack_is_stream_blocked(tbl_b, 0), "stream 0 no longer blocked");
        sub.assert_true(wing::qpack_can_block_stream(tbl_b), "can block stream again after unblocking");

        // Test C: decode_qpack_section with ric > tbl.insert_count triggers BlockedStreamsExhausted
        var tbl_c = wing::new_qpack_table(4096, 0); // max_blocked = 0
        // Header block requesting RIC = 1 (encoded as enc_ric = 2) when insert_count = 0
        var qpack_block: u8[..32] = [0x02, 0x00, 0xD1];
        var out_fields: wing::HeaderField[>..] = [];
        let dec_err = wing::decode_qpack_section(tbl_c, qpack_block[..], out_fields);
        sub.assert_eq(dec_err, wing::QpackError.BlockedStreamsExhausted, "ric > insert_count with max_blocked 0 returns BlockedStreamsExhausted");
    };

    t.run("QUIC-R2-01: Header Reserved Bits Zeroing Validation (RFC 9000 §17.2, §17.3)") { sub =>
        // Test A: Long Header Initial packet with non-zero reserved bits (0x0C mask) MUST fail
        var bad_init: u8[..64] = [];
        bad_init.push(0xC8); // Long header Initial (0xC0), but bit 3 is set (0x08)! Reserved bits = 0x08 != 0
        core::append_u32_be(bad_init, wing::QUIC_VERSION_1);
        bad_init.push(0); // DCID len
        bad_init.push(0); // SCID len
        wing::quic_encode_varint(bad_init, 0); // token len 0
        wing::quic_encode_varint(bad_init, 4); // plen
        bad_init.append([0x00, 0x01, 0x02, 0x03]); // PN + payload
        let _, ok_bad_init = wing::parse_quic_header(bad_init[..], 0);
        sub.assert_false(ok_bad_init, "Initial packet with non-zero reserved bits rejected per RFC 9000 §17.2");

        // Test B: Long Header Handshake packet with non-zero reserved bits (bit 2 is set, 0x04)
        var bad_hs: u8[..64] = [];
        bad_hs.push(0xE4); // Handshake (0xE0) with bit 2 set (0x04)
        core::append_u32_be(bad_hs, wing::QUIC_VERSION_1);
        bad_hs.push(0); // DCID len
        bad_hs.push(0); // SCID len
        wing::quic_encode_varint(bad_hs, 4); // plen
        bad_hs.append([0x00, 0x01, 0x02, 0x03]);
        let _, ok_bad_hs = wing::parse_quic_header(bad_hs[..], 0);
        sub.assert_false(ok_bad_hs, "Handshake packet with non-zero reserved bits rejected per RFC 9000 §17.2");

        // Test C: Valid Long Header Initial packet with reserved bits == 0 succeeds
        var good_init: u8[..64] = [];
        good_init.push(0xC0); // Long header Initial, reserved bits = 0
        core::append_u32_be(good_init, wing::QUIC_VERSION_1);
        good_init.push(0);
        good_init.push(0);
        wing::quic_encode_varint(good_init, 0);
        wing::quic_encode_varint(good_init, 4);
        good_init.append([0x00, 0x01, 0x02, 0x03]);
        let _, ok_good_init = wing::parse_quic_header(good_init[..], 0);
        sub.assert_true(ok_good_init, "Initial packet with zero reserved bits accepted");

        // Test D: Short Header (1-RTT) packet with non-zero reserved bits (0x18 mask) MUST fail
        let bad_short1: u8[16] = [
            0x50, // Short header (0x40) with bit 4 set (0x10)! Reserved bits != 0
            0x01, 0x02, 0x03, 0x04,
            0x2A, // PN
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];
        let _, ok_bs1 = wing::parse_quic_header(bad_short1[..], 4);
        sub.assert_false(ok_bs1, "Short header with reserved bit 4 set rejected per RFC 9000 §17.3");

        let bad_short2: u8[16] = [
            0x48, // Short header (0x40) with bit 3 set (0x08)! Reserved bits != 0
            0x01, 0x02, 0x03, 0x04,
            0x2A, // PN
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];
        let _, ok_bs2 = wing::parse_quic_header(bad_short2[..], 4);
        sub.assert_false(ok_bs2, "Short header with reserved bit 3 set rejected per RFC 9000 §17.3");

        // Test E: Valid Short Header with reserved bits == 0 succeeds
        let good_short: u8[16] = [
            0x40, // Short header, reserved bits 0
            0x01, 0x02, 0x03, 0x04,
            0x2A, // PN
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];
        let _, ok_good_short = wing::parse_quic_header(good_short[..], 4);
        sub.assert_true(ok_good_short, "Short header with zero reserved bits accepted");
    };
}

// 9. Team QPackStrike Round 3 Championship Audit Suite (RFC 9204, RFC 9000, RFC 9114)
fn test_round3_qpackstrike_suite(t: core::T&) {
    t.run("QPACK-R3-01: Huffman Padding Bounds and All-1s Validation (RFC 9204 §4.1.2, RFC 7541 §5.2)") { sub =>
        // Test A: Non-empty input with only padding (0xFF) MUST fail (8 bits of padding > 7 bits)
        var bad_huff1: u8[..4] = [0xFF];
        var out1: u8[..64] = [];
        let ok1 = wing::huff_decode_bytes(bad_huff1[..], out1);
        sub.assert_false(ok1, "Huffman string of pure 0xFF (8 bits padding) MUST fail per RFC 9204 §4.1.2");

        // Test B: 16 bits of pure padding (0xFF, 0xFF) MUST fail
        var bad_huff2: u8[..4] = [0xFF, 0xFF];
        var out2: u8[..64] = [];
        let ok2 = wing::huff_decode_bytes(bad_huff2[..], out2);
        sub.assert_false(ok2, "Huffman string of 0xFFFF (16 bits padding) MUST fail");

        // Test C: Valid Huffman string ("custom-key") with extra trailing 0xFF (8 bits padding) MUST fail
        var valid_encoded: u8[..64] = [];
        sub.assert_true(wing::huff_encode_bytes("custom-key", valid_encoded), "encode custom-key");
        valid_encoded.push(0xFF); // Append extra 8 bits of padding
        var out3: u8[..64] = [];
        let ok3 = wing::huff_decode_bytes(valid_encoded[..], out3);
        sub.assert_false(ok3, "Huffman string with trailing full byte padding MUST fail per RFC 9204 §4.1.2");

        // Test D: Valid Huffman string ("custom-key") decodes cleanly
        var valid_clean: u8[..64] = [];
        sub.assert_true(wing::huff_encode_bytes("custom-key", valid_clean), "encode custom-key clean");
        var out4: u8[..64] = [];
        let ok4 = wing::huff_decode_bytes(valid_clean[..], out4);
        sub.assert_true(ok4, "Valid Huffman string decodes cleanly");
        sub.assert_eq(out4[..], "custom-key", "decoded content matches");

        // Test E: decode_qpack_string rejects string literal with invalid Huffman padding
        var raw_str_wire: u8[..64] = [];
        // Length 2, Huffman bit set (0x80 | 2 = 0x82), followed by [0xFF, 0xFF]
        raw_str_wire.push(0x82);
        raw_str_wire.push(0xFF);
        raw_str_wire.push(0xFF);
        var q_out: u8[..64] = [];
        let _, ok_str = wing::decode_qpack_string(raw_str_wire[..], 0, 7, q_out);
        sub.assert_false(ok_str, "decode_qpack_string rejects Huffman with padding > 7 bits");
    };

    t.run("QUIC-R3-01: Packet Number Reconstruction 62-Bit Arithmetic Safety (RFC 9000 §17.1, Appendix A.3)") { sub =>
        // Test A: Standard packet number reconstruction
        let pn1, ok_pn1 = wing::decode_packet_number_checked(0, 1, 1);
        sub.assert_true(ok_pn1, "decode standard pn 1 ok");
        sub.assert_eq(pn1, 1, "reconstructed pn is 1");

        let pn256, ok_pn256 = wing::decode_packet_number_checked(255, 0, 1);
        sub.assert_true(ok_pn256, "decode wrap-around pn ok");
        sub.assert_eq(pn256, 256, "reconstructed pn is 256");

        // Test B: Invalid pn_len (0 or > 4) MUST fail
        let _, ok_bad_len0 = wing::decode_packet_number_checked(100, 42, 0);
        sub.assert_false(ok_bad_len0, "pn_len 0 rejected");
        let _, ok_bad_len5 = wing::decode_packet_number_checked(100, 42, 5);
        sub.assert_false(ok_bad_len5, "pn_len 5 rejected");

        // Test C: Packet number exceeding 2^62 - 1 MUST fail per RFC 9000 §17.1
        let _, ok_exceed = wing::decode_packet_number_checked(0x3FFFFFFFFFFFFFFF, 1, 1);
        // Largest acked is already at 2^62 - 1, candidate next pn would exceed 2^62 - 1
        sub.assert_false(ok_exceed, "reconstructed PN exceeding 2^62 - 1 rejected");

        // Test D: Input truncated_pn exceeding 2^62 - 1 MUST fail
        let _, ok_bad_trunc = wing::decode_packet_number_checked(100, 0x4000000000000000, 4);
        sub.assert_false(ok_bad_trunc, "truncated_pn >= 2^62 rejected");

        // Test E: Boundary at 2^62 - 2 reconstructed cleanly
        let near_max: u64 = 0x3FFFFFFFFFFFFFFE;
        let pn_near, ok_near = wing::decode_packet_number_checked(near_max - 1, (near_max & 0xFF), 1);
        sub.assert_true(ok_near, "reconstructed PN near 2^62 - 1 accepted");
        sub.assert_eq(pn_near, near_max, "reconstructed value matches");
    };

    t.run("H3-R3-01: PUSH_PROMISE, CANCEL_PUSH, and MAX_PUSH_ID Invariants (RFC 9114 §7.2.5, §7.2.7)") { sub =>
        let settings = wing::H3Settings { .. };

        // Test A: Server receiving PUSH_PROMISE frame on request stream MUST fail with H3_FRAME_UNEXPECTED
        var srv_conn = wing::H3Connection {
            role: wing::H3ConnRole.Server,
            state: wing::H3ConnState.Active,
            ..
        };
        // Add open request stream 0
        srv_conn.streams.push(wing::H3StreamEntry {
            stream_id: 0,
            kind: wing::H3StreamKind.Request,
            state: wing::H3StreamState.Open,
            is_bidi: true,
            ..
        });

        var push_wire: u8[..64] = [];
        sub.assert_true(wing::encode_h3_push_promise(push_wire, 1, [0x00, 0x00]), "encode PUSH_PROMISE");
        let err_srv = srv_conn.handle_stream_data(0, true, push_wire[..], false);
        sub.assert_eq(err_srv, wing::H3_ERR_FRAME_UNEXPECTED, "Server receiving PUSH_PROMISE MUST return H3_FRAME_UNEXPECTED");
        sub.assert_eq(srv_conn.state, wing::H3ConnState.Closed, "server connection closed");

        // Test B: Client receiving PUSH_PROMISE when client never sent MAX_PUSH_ID MUST fail with H3_ERR_ID_ERROR
        var cli_conn = wing::new_h3_client_connection(settings);
        let sid, _ = cli_conn.open_request_stream();
        let err_no_max = cli_conn.handle_stream_data(sid, true, push_wire[..], false);
        sub.assert_eq(err_no_max, wing::H3_ERR_ID_ERROR, "PUSH_PROMISE without MAX_PUSH_ID MUST return H3_ERR_ID_ERROR");

        // Test C: Client receiving PUSH_PROMISE with Push ID > max_push_id_advertised MUST fail with H3_ERR_ID_ERROR
        var cli_conn2 = wing::new_h3_client_connection(settings);
        let sid2, _ = cli_conn2.open_request_stream();
        var max_p_buf: u8[..32] = [];
        sub.assert_true(wing::send_max_push_id(cli_conn2, 5, max_p_buf), "client advertises MAX_PUSH_ID = 5");

        var bad_push_wire: u8[..64] = [];
        sub.assert_true(wing::encode_h3_push_promise(bad_push_wire, 10, [0x00, 0x00]), "encode PUSH_PROMISE with push_id 10 > 5");
        let err_exceed = cli_conn2.handle_stream_data(sid2, true, bad_push_wire[..], false);
        sub.assert_eq(err_exceed, wing::H3_ERR_ID_ERROR, "PUSH_PROMISE with push_id > advertised limit MUST return H3_ERR_ID_ERROR");

        // Test D: Client receiving PUSH_PROMISE with push_id <= max_push_id_advertised succeeds
        var good_push_wire: u8[..64] = [];
        sub.assert_true(wing::encode_h3_push_promise(good_push_wire, 3, [0x00, 0x00]), "encode PUSH_PROMISE with push_id 3 <= 5");
        let err_good_push = cli_conn2.handle_stream_data(sid2, true, good_push_wire[..], false);
        sub.assert_eq(err_good_push, wing::H3_ERR_NO_ERROR, "PUSH_PROMISE with valid push_id accepted");

        // Test E: CANCEL_PUSH with Push ID > advertised max limit on control stream returns H3_ERR_ID_ERROR
        var init_ctrl: u8[..64] = [];
        wing::quic_encode_varint(init_ctrl, wing::H3_STREAM_CONTROL);
        wing::encode_h3_settings_frame(init_ctrl, settings);
        cli_conn2.handle_stream_data(3, false, init_ctrl[..], false);

        var bad_cp_wire: u8[..32] = [];
        sub.assert_true(wing::encode_h3_cancel_push(bad_cp_wire, 20), "encode CANCEL_PUSH with push_id 20 > 5");
        let err_cp_exceed = cli_conn2.handle_stream_data(3, false, bad_cp_wire[..], false);
        sub.assert_eq(err_cp_exceed, wing::H3_ERR_ID_ERROR, "CANCEL_PUSH with push_id > advertised limit returns H3_ERR_ID_ERROR");

        // Test F: MAX_PUSH_ID monotonicity violation (decreasing max_push_id) returns H3_ERR_ID_ERROR
        var srv_ctrl_conn = wing::H3Connection {
            role: wing::H3ConnRole.Server,
            state: wing::H3ConnState.Active,
            ..
        };
        var srv_init_ctrl: u8[..64] = [];
        wing::quic_encode_varint(srv_init_ctrl, wing::H3_STREAM_CONTROL);
        wing::encode_h3_settings_frame(srv_init_ctrl, settings);
        srv_ctrl_conn.handle_stream_data(2, false, srv_init_ctrl[..], false);

        var mp1_wire: u8[..32] = [];
        sub.assert_true(wing::encode_h3_max_push_id(mp1_wire, 50), "first MAX_PUSH_ID = 50");
        let err_mp1 = srv_ctrl_conn.handle_stream_data(2, false, mp1_wire[..], false);
        sub.assert_eq(err_mp1, wing::H3_ERR_NO_ERROR, "first MAX_PUSH_ID accepted");

        var mp2_wire: u8[..32] = [];
        sub.assert_true(wing::encode_h3_max_push_id(mp2_wire, 30), "decreasing MAX_PUSH_ID = 30 < 50");
        let err_mp2 = srv_ctrl_conn.handle_stream_data(2, false, mp2_wire[..], false);
        sub.assert_eq(err_mp2, wing::H3_ERR_ID_ERROR, "decreasing MAX_PUSH_ID MUST return H3_ERR_ID_ERROR");
    };
}

// Main HTTP/3 Conformance Runner
fn main() {
    var runner = core::new_runner("HTTP/3 (RFC 9114) Zero-Allocation Conformance Suite", core::Verbosity.Verbose);

    core::run_case(runner, "1. Frame Header Encoding, Decoding & GREASE Conformance", test_h3_framing_and_grease);
    core::run_case(runner, "2. SETTINGS Frame Conformance & Protocol Defenses", test_h3_settings_conformance);
    core::run_case(runner, "3. Unidirectional Control and QPACK Streams", test_h3_unidirectional_streams);
    core::run_case(runner, "4. Request Stream Lifecycle & Full Request-Response Multiplexing", test_h3_request_streams);
    core::run_case(runner, "5. QPACK Table Lifecycle, String Decoding & Stream Instructions", test_qpack_table_and_codec);
    core::run_case(runner, "6. HTTP/3 Extended Frames & Stream Edge-Cases", test_h3_extended_frames);
    core::run_case(runner, "7. Team QPackStrike Protocol Hardening Suite", test_round1_qpackstrike_suite);
    core::run_case(runner, "8. Team QPackStrike Round 2 Hardening Suite", test_round2_qpackstrike_suite);
    core::run_case(runner, "9. Team QPackStrike Round 3 Championship Suite", test_round3_qpackstrike_suite);

    let ok = core::finish(runner);
    assert(ok);
}
