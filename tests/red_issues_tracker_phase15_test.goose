// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Phase 15 RED test suite: HTTP/3 & QUIC Transport Engine RFC Invariants,
// QPACK Dynamic Table Ring Decoders, Header Protection & Stream Multiplexer Defenses.
//
// 1. QUIC Packet Headers, Header Protection & Interval Reassembly (quic/packet.goose)
// 2. QPACK Modular RIC, Post-Base Bounds & Bare-Colon Token Sanitization (http3/qpack.goose)
// 3. HTTP/3 Framing, Reserved 0x00 Setting & Malformed Payloads (http3/framing.goose)
// 4. HTTP/3 Multiplexer, Unidirectional Encoder/Decoder Dispatch & Trailer Defenses (http3/connection.goose)

import std;
import core from "..";
import wing from "..";

// ----------------------------------------------------------------------------
// 1. QUIC Packet Headers, Header Protection & Interval Reassembly
// ----------------------------------------------------------------------------
fn test_quic_packet_and_reassembly(t: core::T&) {
    t.run("parse_quic_header enforces fixed bit, CID lengths, and plen >= pn_len") { sub =>
        // 1. Short header with fixed bit cleared (bit 6 = 0) MUST fail per RFC 9000 §17.3
        let bad_short: u8[16] = [
            0x00, // Fixed bit (0x40) is not set!
            0x01, 0x02, 0x03, 0x04,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];
        let _, ok_s = wing::parse_quic_header(bad_short[..], 4);
        sub.assert_false(ok_s, "Short header with fixed bit 0 rejected");

        // 2. Short header with dcid_len_short > 20 MUST fail
        let valid_short: u8[16] = [
            0x40, // Short header, fixed bit 1, pn_len 1
            0x01, 0x02, 0x03, 0x04,
            0x2A, // packet number
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];
        let _, ok_dcid_lg = wing::parse_quic_header(valid_short[..], 21);
        sub.assert_false(ok_dcid_lg, "Short header with dcid > 20 rejected");

        let hdr_s, ok_s_valid = wing::parse_quic_header(valid_short[..], 4);
        sub.assert_true(ok_s_valid, "Valid short header accepted");
        sub.assert_eq(hdr_s.header_type, wing::QuicHeaderType.OneRtt, "Header type is OneRtt");
        sub.assert_eq(hdr_s.pn_length, 1, "PN length is 1");

        // 3. Long header with fixed bit cleared MUST fail per RFC 9000 §17.2
        var bad_long: u8[..64] = [];
        bad_long.push(0x80); // Long header, but fixed bit 0x40 NOT set!
        core::append_u32_be(bad_long, wing::QUIC_VERSION_1);
        bad_long.push(4); // DCID len
        bad_long.append([1, 2, 3, 4]);
        bad_long.push(4); // SCID len
        bad_long.append([5, 6, 7, 8]);
        wing::quic_encode_varint(bad_long, 10); // plen
        bad_long.push(1); // pn
        let _, ok_l_fix = wing::parse_quic_header(bad_long[..], 0);
        sub.assert_false(ok_l_fix, "Long header with fixed bit 0 rejected");

        // 4. Long header with plen < pn_len MUST fail per RFC 9000 §17.2
        var bad_plen: u8[..64] = [];
        bad_plen.push(0xC1); // Long header, Initial, pn_len = 2 (bits 0..1 = 1)
        core::append_u32_be(bad_plen, wing::QUIC_VERSION_1);
        bad_plen.push(0); // DCID len 0
        bad_plen.push(0); // SCID len 0
        wing::quic_encode_varint(bad_plen, 0); // token len 0
        wing::quic_encode_varint(bad_plen, 1); // plen = 1, but pn_len = 2!
        bad_plen.append([0x00, 0x2A]); // 2 bytes PN
        let _, ok_plen = wing::parse_quic_header(bad_plen[..], 0);
        sub.assert_false(ok_plen, "Long header with plen < pn_len rejected");
    };

    t.run("encode_quic_header enforces pn_len bounds and 20-byte CID") { sub =>
        var hdr = wing::QuicHeader {
            header_type: wing::QuicHeaderType.Initial,
            version: wing::QUIC_VERSION_1,
            payload_length: 64,
            packet_number: 1,
            ..
        };
        // Valid 20-byte DCID (matches QUIC_MAX_CID_LEN = 20)
        for i in 20 { hdr.dcid.push(i as u8); }

        var out: u8[..128] = [];
        let ok_valid = wing::encode_quic_header(out, hdr, 1);
        sub.assert_true(ok_valid, "encode with DCID == 20 accepted");

        // Invalid pn_len 0 or 5
        out.clear();
        sub.assert_false(wing::encode_quic_header(out, hdr, 0), "pn_len 0 rejected");
        sub.assert_false(wing::encode_quic_header(out, hdr, 5), "pn_len 5 rejected");
    };

    t.run("apply and remove header protection with truncated buffers") { sub =>
        let hp_mask: u8[5] = [0x5A, 0x11, 0x22, 0x33, 0x44];

        // Empty buffer
        var empty_buf: u8[..4] = [];
        wing::apply_header_protection(empty_buf[..], 0, 1, hp_mask);
        let pn_len_e, pn_e = wing::remove_header_protection(empty_buf[..], 0, hp_mask);
        sub.assert_eq(pn_len_e, 0, "remove on empty returns 0");
        sub.assert_eq(pn_e, 0, "pn on empty returns 0");

        // Truncated buffer where pn_offset + pn_len > pkt.len
        var trunc_buf: u8[4] = [0xC0, 0x00, 0x00, 0x00];
        wing::apply_header_protection(trunc_buf[..], 10, 2, hp_mask); // offset 10 > len 4: safe no-op
        sub.assert_eq(trunc_buf[0], 0xC0, "first byte untouched when out of bounds");

        let pn_len_tr, _ = wing::remove_header_protection(trunc_buf[..], 10, hp_mask);
        sub.assert_eq(pn_len_tr, 0, "remove out of bounds returns 0");
        sub.assert_eq(trunc_buf[0], 0xC0, "first byte restored on out-of-bounds");

        // Valid round-trip
        var valid_pkt: u8[8] = [0xC0, 0x01, 0x02, 0x03, 0x12, 0x34, 0xAA, 0xBB];
        let orig_first = valid_pkt[0];
        let orig_pn0 = valid_pkt[4];
        let orig_pn1 = valid_pkt[5];

        wing::apply_header_protection(valid_pkt[..], 4, 2, hp_mask);
        sub.assert_ne(valid_pkt[0], orig_first, "first byte masked");

        let dec_pn_len, dec_pn = wing::remove_header_protection(valid_pkt[..], 4, hp_mask);
        sub.assert_eq(dec_pn_len, 1, "pn_len unmasked is (first & 3) + 1");
        sub.assert_eq(valid_pkt[0], orig_first, "first byte restored");
    };

    t.run("decode_packet_number bounds checking and epoch shifts") { sub =>
        // Out of bounds pn_len
        let pn_raw = wing::decode_packet_number(100, 42, 0);
        sub.assert_eq(pn_raw, 42, "pn_len 0 returns truncated");
        let pn_lg = wing::decode_packet_number(100, 42, 5);
        sub.assert_eq(pn_lg, 42, "pn_len 5 returns truncated");

        // 1-byte PN decoding near wrap-around
        let pn1 = wing::decode_packet_number(0xA8252, 0x9B, 1);
        sub.assert_eq(pn1, 0xA829B, "RFC 9000 Appendix A.3 1-byte decode vector");

        // 2-byte PN decoding
        let pn2 = wing::decode_packet_number(0xA8252, 0x9B3F, 2);
        sub.assert_eq(pn2, 0xA9B3F, "RFC 9000 Appendix A.3 2-byte decode vector");
    };

    t.run("can_send_on_path anti-amplification overflow protection") { sub =>
        let ip: u8[16] = [0; 16];
        var path = wing::new_path_state(ip, 443, false);

        // Path received 1000 bytes -> can send up to 3000 bytes
        wing::on_path_bytes_received(path, 1000);
        sub.assert_true(wing::can_send_on_path(path, 3000), "3000 <= 3 * 1000 allowed");
        sub.assert_false(wing::can_send_on_path(path, 3001), "3001 > 3 * 1000 blocked");

        // Test with massive numbers that would overflow 3 * received or sent + packet
        var path_huge = wing::new_path_state(ip, 443, false);
        path_huge.bytes_received = 0x7FFFFFFFFFFFFFFF; // 3 * bytes_received overflows u64
        path_huge.bytes_sent = 0xFFFFFFFFFFFFFFF0;
        sub.assert_false(wing::can_send_on_path(path_huge, 32), "sent + packet overflow safely blocked");

        // Validated path ignores limit
        wing::validate_path(path);
        sub.assert_true(wing::can_send_on_path(path, 1000000), "validated path allows send");
    };

    t.run("decode_quic_datagram_frame respects packet_end boundary") { sub =>
        var wire: u8[..32] = [];
        // DATAGRAM with Length (0x31)
        sub.assert_true(wing::encode_quic_datagram_frame(wire, "hello", true), "encode datagram len");

        // Normal decode without packet_end
        let payload1, end1, ok1 = wing::decode_quic_datagram_frame(wire[..], 0, 0);
        sub.assert_true(ok1, "decode ok without packet_end");
        sub.assert_bytes_eq(payload1, "hello", "payload matches");

        // Decode with packet_end cutting into datagram length
        let _, _, ok_trunc = wing::decode_quic_datagram_frame(wire[..], 0, end1 - 1);
        sub.assert_false(ok_trunc, "datagram exceeding packet_end rejected");
    };

    t.run("merge_reassembly_interval enforces 64 intervals capacity") { sub =>
        var r_buf = wing::new_reassembly_buffer(65536);

        // Insert 64 disjunct intervals [0, 1), [2, 3), [4, 5), ...
        for i in 64 {
            let s = (i as u64) * 2;
            let ok = wing::insert_fragment(r_buf, s, "X", false);
            sub.assert_true(ok, "insert interval");
        }
        sub.assert_eq(r_buf.intervals.len, 64, "intervals array full at cap 64");

        // 65th disjunct interval cannot be added
        let ok_65 = wing::insert_fragment(r_buf, 200, "Y", false);
        sub.assert_false(ok_65, "65th disjunct interval safely rejected on capacity exhaustion");
    };
}

// ----------------------------------------------------------------------------
// 2. QPACK Modular RIC, Post-Base Bounds & Bare-Colon Token Sanitization
// ----------------------------------------------------------------------------
fn test_qpack_invariants_and_token_defenses(t: core::T&) {
    t.run("decode_base integer overflow and underflow protection") { sub =>
        // Sign bit 0: Base = ric + delta_base. Test overflow on ric + delta_base
        let _, err_ov = wing::decode_base(0, 10, 0xFFFFFFFFFFFFFFFF);
        sub.assert_eq(err_ov, wing::QpackError.DecompressionFailed, "overflow in base addition rejected");

        // Sign bit 1: Base = ric - delta_base - 1. Test underflow when ric <= delta_base
        let _, err_un = wing::decode_base(1, 5, 5);
        sub.assert_eq(err_un, wing::QpackError.DecompressionFailed, "underflow in base subtraction rejected");

        let base_ok, err_ok = wing::decode_base(0, 5, 10);
        sub.assert_eq(err_ok, wing::QpackError.None, "valid base decoded");
        sub.assert_eq(base_ok, 15, "base is 15");
    };

    t.run("emit_field_checked rejects bare colon and non-token characters") { sub =>
        var fields: wing::HeaderField[>..] = [];
        var budget: u64 = 4096;

        // Bare colon ":" must be rejected
        let err_colon = wing::emit_field_checked(fields, budget, ":", "val", false);
        sub.assert_eq(err_colon, wing::QpackError.DecompressionFailed, "bare colon rejected");

        // Empty field name
        let err_empty = wing::emit_field_checked(fields, budget, "", "val", false);
        sub.assert_eq(err_empty, wing::QpackError.DecompressionFailed, "empty name rejected");

        // Disallowed control char in name
        let err_ctl = wing::emit_field_checked(fields, budget, "bad\nheader", "val", false);
        sub.assert_eq(err_ctl, wing::QpackError.DecompressionFailed, "newline in name rejected");

        // Valid pseudo header
        let err_valid = wing::emit_field_checked(fields, budget, ":status", "200", false);
        sub.assert_eq(err_valid, wing::QpackError.None, "valid :status accepted");
        sub.assert_eq(fields.len, 1, "field emitted");
    };

    t.run("decode_qpack_section enforces RFC 9204 Post-Base index bounds abs_idx < ric") { sub =>
        var tbl = wing::new_qpack_table(4096, 16);
        // Insert one dynamic entry: "x-foo" = "bar" -> abs_idx = 0
        wing::qpack_insert_literal(tbl, "x-foo", "bar");
        sub.assert_eq(tbl.insert_count, 1, "dynamic table insert_count is 1");

        // Construct section with RIC = 1, Base = 0 (S=1, DeltaBase=0 -> Base = 1 - 0 - 1 = 0)
        // Then attempt Post-Base index 1 -> abs_idx = Base + 1 = 1 >= RIC (1)
        // Per RFC 9204 §4.5.3, abs_idx >= ric MUST be treated as decompression error!
        var sec: u8[..32] = [];
        // 1. EncodedInsertCount = 1 (enc_ric for ric=1 is 2 when max_entries = 4096/32 = 128)
        let enc_ric = wing::encode_ric(1, 4096);
        wing::hpack_encode_int(sec, enc_ric, 8, 0x00);
        // 2. Sign=1, DeltaBase=0 -> 0x80 | 0 = 0x80
        sec.push(0x80);
        // 3. Post-Base Indexed Field Line: 0001xxxx with post_idx = 1 -> 0x11
        sec.push(0x11);

        var out_fields: wing::HeaderField[>..] = [];
        let err = wing::decode_qpack_section(tbl, sec[..], out_fields, 4096);
        sub.assert_eq(err, wing::QpackError.DecompressionFailed, "post_idx resulting in abs_idx >= ric rejected");
    };

    t.run("decode_qpack_section accepts valid RIC >= max_dyn_abs_used + 1 per RFC 9204 §4.5.1") { sub =>
        var tbl = wing::new_qpack_table(4096, 16);
        // Insert two entries: abs_idx 0 ("x-first"), abs_idx 1 ("x-second")
        wing::qpack_insert_literal(tbl, "x-first", "v1");
        wing::qpack_insert_literal(tbl, "x-second", "v2");
        sub.assert_eq(tbl.insert_count, 2, "dynamic table insert_count is 2");

        // Section references ONLY static :status 200 (index 0)
        // Encoder signals RIC = 2 (TotalNumberOfInserts), Base = 2 (S=0, DeltaBase=0)
        // Per RFC 9204 §4.5.1, encoder MAY set RIC > 0 even if no dynamic entries referenced
        var sec: u8[..32] = [];
        let enc_ric = wing::encode_ric(2, 4096);
        wing::hpack_encode_int(sec, enc_ric, 8, 0x00);
        sec.push(0x00); // S=0, DeltaBase=0 -> Base = 2
        sec.push(0xD9); // Static index 25 (:status 200)

        var out_fields: wing::HeaderField[>..] = [];
        let err = wing::decode_qpack_section(tbl, sec[..], out_fields, 4096);
        sub.assert_eq(err, wing::QpackError.None, "RIC > 0 with static-only fields accepted per RFC 9204 §4.5.1");
        sub.assert_eq(out_fields.len, 1, "1 field decoded");
        sub.assert_bytes_eq(out_fields[0].name[..], ":status", "name is :status");
        sub.assert_bytes_eq(out_fields[0].value[..], "200", "value is 200");
    };
}

// ----------------------------------------------------------------------------
// 3. HTTP/3 Framing, Reserved 0x00 Setting & Malformed Payloads
// ----------------------------------------------------------------------------
fn test_h3_framing_and_settings_invariants(t: core::T&) {
    t.run("parse_h3_settings_frame rejects reserved setting 0x00 and duplicates") { sub =>
        // 1. Reserved setting 0x00 (from HTTP/2) MUST cause H3_SETTINGS_ERROR (RFC 9114 §7.2.4.1)
        var payload_00: u8[..16] = [];
        wing::quic_encode_varint(payload_00, 0x00); // Reserved identifier 0x00
        wing::quic_encode_varint(payload_00, 100);

        var st1 = wing::H3Settings { .. };
        let err_00 = wing::parse_h3_settings_frame(payload_00[..], st1);
        sub.assert_eq(err_00, wing::H3_ERR_SETTINGS_ERROR, "Reserved setting 0x00 rejected with H3_SETTINGS_ERROR");

        // 2. Duplicate QPACK_MAX_TABLE_CAPACITY setting MUST cause H3_SETTINGS_ERROR
        var payload_dup: u8[..32] = [];
        wing::quic_encode_varint(payload_dup, wing::H3_SETTING_QPACK_MAX_TABLE_CAPACITY);
        wing::quic_encode_varint(payload_dup, 4096);
        wing::quic_encode_varint(payload_dup, wing::H3_SETTING_QPACK_MAX_TABLE_CAPACITY);
        wing::quic_encode_varint(payload_dup, 8192);

        var st2 = wing::H3Settings { .. };
        let err_dup = wing::parse_h3_settings_frame(payload_dup[..], st2);
        sub.assert_eq(err_dup, wing::H3_ERR_SETTINGS_ERROR, "Duplicate setting rejected with H3_SETTINGS_ERROR");

        // 3. Invalid ENABLE_CONNECT_PROTOCOL value (must be 0 or 1)
        var payload_conn: u8[..16] = [];
        wing::quic_encode_varint(payload_conn, wing::H3_SETTING_ENABLE_CONNECT_PROTOCOL);
        wing::quic_encode_varint(payload_conn, 2); // Invalid: only 0 or 1 allowed

        var st3 = wing::H3Settings { .. };
        let err_conn = wing::parse_h3_settings_frame(payload_conn[..], st3);
        sub.assert_eq(err_conn, wing::H3_ERR_SETTINGS_ERROR, "Invalid connect protocol val rejected with H3_SETTINGS_ERROR");
    };
}

// ----------------------------------------------------------------------------
// 4. HTTP/3 Multiplexer, Unidirectional Dispatch & Trailer Defenses
// ----------------------------------------------------------------------------
fn test_h3_multiplexer_and_stream_defenses(t: core::T&) {
    t.run("handle_stream_data dispatches QPACK encoder stream instructions and catches errors") { sub =>
        let settings = wing::H3Settings { qpack_max_table_capacity: 4096, .. };
        var conn = wing::new_h3_client_connection(settings);

        // 1. Establish control stream first (Stream 2)
        var ctrl_wire: u8[..64] = [];
        wing::quic_encode_varint(ctrl_wire, wing::H3_STREAM_CONTROL);
        wing::encode_h3_settings_frame(ctrl_wire, settings);
        let err_c = conn.handle_stream_data(2, false, ctrl_wire[..], false);
        sub.assert_eq(err_c, wing::H3_ERR_NO_ERROR, "control stream established");

        // 2. Open QPACK encoder stream (Stream 6) with valid Set Dynamic Table Capacity instruction (0x20 | 5-bit cap)
        var enc_wire: u8[..64] = [];
        wing::quic_encode_varint(enc_wire, wing::H3_STREAM_QPACK_ENCODER);
        wing::hpack_encode_int(enc_wire, 2048, 5, 0x20); // Capacity 2048
        let err_enc = conn.handle_stream_data(6, false, enc_wire[..], false);
        sub.assert_eq(err_enc, wing::H3_ERR_NO_ERROR, "encoder stream capacity instruction processed");
        sub.assert_eq(conn.qpack_table.capacity_bytes, 2048, "dynamic table capacity updated to 2048");

        // 3. Send malformed instruction on encoder stream -> returns H3_ERR_QPACK_ENCODER_STREAM_ERROR
        var bad_enc_wire: u8[..16] = [];
        // Capacity larger than max_capacity_bytes (4096)
        wing::hpack_encode_int(bad_enc_wire, 999999, 5, 0x20);
        let err_bad_enc = conn.handle_stream_data(6, false, bad_enc_wire[..], false);
        sub.assert_eq(err_bad_enc, wing::H3_ERR_QPACK_ENCODER_STREAM_ERROR, "invalid encoder instruction closed connection");
        sub.assert_eq(conn.state, wing::H3ConnState.Closed, "conn state is Closed");
    };

    t.run("handle_stream_data rejects second trailer section and DATA after trailers") { sub =>
        let settings = wing::H3Settings { .. };
        var conn = wing::new_h3_client_connection(settings);

        // Setup control stream
        var ctrl_wire: u8[..64] = [];
        wing::quic_encode_varint(ctrl_wire, wing::H3_STREAM_CONTROL);
        wing::encode_h3_settings_frame(ctrl_wire, settings);
        conn.handle_stream_data(2, false, ctrl_wire[..], false);

        // Stream 0: Initial response headers (200 OK)
        var resp_hdrs: u8[..64] = [];
        var sec1: u8[..16] = [0x00, 0x00, 0xD9]; // RIC 0, Base 0, :status 200
        wing::encode_h3_headers_frame(resp_hdrs, sec1[..]);
        let err_h1 = conn.handle_stream_data(0, true, resp_hdrs[..], false);
        sub.assert_eq(err_h1, wing::H3_ERR_NO_ERROR, "initial 200 OK headers accepted");

        // Stream 0: DATA frame
        var data_frame: u8[..32] = [];
        wing::encode_h3_data_frame(data_frame, "hello");
        let err_d1 = conn.handle_stream_data(0, true, data_frame[..], false);
        sub.assert_eq(err_d1, wing::H3_ERR_NO_ERROR, "data frame accepted");

        // Stream 0: First trailer section (x-checksum: abc)
        var trailer1_frame: u8[..64] = [];
        var sec_tr1: u8[..32] = [0x00, 0x00];
        // Literal with literal name: name "x-chk", val "1"
        sec_tr1.push(0x25);
        sec_tr1.append("x-chk");
        sec_tr1.push(0x01);
        sec_tr1.append("1");
        wing::encode_h3_headers_frame(trailer1_frame, sec_tr1[..]);
        let err_tr1 = conn.handle_stream_data(0, true, trailer1_frame[..], false);
        sub.assert_eq(err_tr1, wing::H3_ERR_NO_ERROR, "first trailer section accepted");

        // 1. DATA frame AFTER trailers MUST cause H3_FRAME_UNEXPECTED (RFC 9114 §4.1)
        var post_tr_data: u8[..32] = [];
        wing::encode_h3_data_frame(post_tr_data, "illegal");
        let err_post_d = conn.handle_stream_data(0, true, post_tr_data[..], false);
        sub.assert_eq(err_post_d, wing::H3_ERR_FRAME_UNEXPECTED, "DATA after trailers rejected with H3_FRAME_UNEXPECTED");

        // Reset and test second trailer section rejection
        var conn2 = wing::new_h3_client_connection(settings);
        conn2.handle_stream_data(2, false, ctrl_wire[..], false);
        conn2.handle_stream_data(0, true, resp_hdrs[..], false);
        conn2.handle_stream_data(0, true, data_frame[..], false);
        conn2.handle_stream_data(0, true, trailer1_frame[..], false);

        // 2. Second trailer section MUST cause H3_FRAME_UNEXPECTED (RFC 9114 §4.1)
        let err_tr2 = conn2.handle_stream_data(0, true, trailer1_frame[..], false);
        sub.assert_eq(err_tr2, wing::H3_ERR_FRAME_UNEXPECTED, "second trailer section rejected with H3_FRAME_UNEXPECTED");
    };

    t.run("handle_stream_data validates 3-digit status code and trailer disallowed headers") { sub =>
        let settings = wing::H3Settings { .. };
        var conn = wing::new_h3_client_connection(settings);

        // Setup control stream
        var ctrl_wire: u8[..64] = [];
        wing::quic_encode_varint(ctrl_wire, wing::H3_STREAM_CONTROL);
        wing::encode_h3_settings_frame(ctrl_wire, settings);
        conn.handle_stream_data(2, false, ctrl_wire[..], false);

        // 1. Status code with 4 digits e.g. "0200" MUST fail
        var sec_bad_st: u8[..32] = [0x00, 0x00];
        // Literal with static name index 24 (:status) encoded with 4-bit prefix
        wing::hpack_encode_int(sec_bad_st, 24, 4, 0x50);
        sec_bad_st.push(4); // len 4
        sec_bad_st.append("0200");

        var bad_st_frame: u8[..64] = [];
        wing::encode_h3_headers_frame(bad_st_frame, sec_bad_st[..]);
        let err_st = conn.handle_stream_data(0, true, bad_st_frame[..], false);
        sub.assert_eq(err_st, wing::H3_ERR_GENERAL_PROTOCOL, "4-digit status code rejected");

        // 2. Disallowed content-length in trailer section MUST fail
        var conn3 = wing::new_h3_client_connection(settings);
        conn3.handle_stream_data(2, false, ctrl_wire[..], false);
        var sec_ok: u8[..16] = [0x00, 0x00, 0xD9]; // :status 200
        var ok_hdrs: u8[..32] = [];
        wing::encode_h3_headers_frame(ok_hdrs, sec_ok[..]);
        conn3.handle_stream_data(0, true, ok_hdrs[..], false);

        var sec_cl_tr: u8[..32] = [0x00, 0x00];
        // Literal with static name index 4 (content-length)
        sec_cl_tr.push(0x50 | 4);
        sec_cl_tr.push(2);
        sec_cl_tr.append("10");

        var cl_tr_frame: u8[..64] = [];
        wing::encode_h3_headers_frame(cl_tr_frame, sec_cl_tr[..]);
        let err_cl_tr = conn3.handle_stream_data(0, true, cl_tr_frame[..], false);
        sub.assert_eq(err_cl_tr, wing::H3_ERR_GENERAL_PROTOCOL, "content-length in trailer rejected");
    };
}

// ============================================================================
// Main Runner
// ============================================================================
fn main() {
    var runner = core::new_runner("Phase 15: HTTP/3 & QUIC RFC Invariants & Defenses Suite", core::Verbosity.Verbose);

    core::run_case(runner, "1. QUIC Packet Headers, Header Protection & Interval Reassembly", test_quic_packet_and_reassembly);
    core::run_case(runner, "2. QPACK Modular RIC, Post-Base Bounds & Bare-Colon Token Sanitization", test_qpack_invariants_and_token_defenses);
    core::run_case(runner, "3. HTTP/3 Framing, Reserved 0x00 Setting & Malformed Payloads", test_h3_framing_and_settings_invariants);
    core::run_case(runner, "4. HTTP/3 Multiplexer, Unidirectional Dispatch & Trailer Defenses", test_h3_multiplexer_and_stream_defenses);

    let ok = core::finish(runner);
    assert(ok);
}
