// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Phase 17 RED test suite: Reducing Load, DoS Mitigation, RFC Conformance,
// and Protocol Invariants.
//
// 1. HTTP/3 DATA Frame Rejection on Bodyless Status Codes (204, 304, 1xx) (RFC 9114 §4.1, Go #81642)
// 2. HTTP/3 Prohibited Trailer Framing Headers & QPACK NUL/CR/LF Injection (RFC 9114 §4.2, §4.3, Go #80683)
// 3. HTTP/2 :status Pseudo-Header Validation & 101 Prohibition (RFC 9113 §8.3.2, §8.8)
// 4. HTTP/2 DATA Frame Rejection on Streams with Trailers Received (RFC 9113 §8.1)
// 5. X.509 DNS Name Constraints Wildcard & Empty/Leading Dot Validation (RFC 5280 §4.2.1.10)
// 6. X.509 ASN.1 Time Parsing Bounds & Overflow Defense (RFC 5280 §4.1.2.5, OpenSSL #31686)

import std;
import core from "..";
import wing from "..";

// ----------------------------------------------------------------------------
// 1. HTTP/3 DATA Frame Rejection on Bodyless Status Codes (204, 304, 1xx)
// ----------------------------------------------------------------------------
fn test_h3_bodyless_status_data_rejection(t: core::T&) {
    t.run("H3: reject DATA frame on stream with 204 No Content") { sub =>
        let settings = wing::H3Settings { .. };
        var conn = wing::new_h3_client_connection(settings);

        // Control stream setup
        var ctrl_wire: u8[..64] = [];
        wing::quic_encode_varint(ctrl_wire, wing::H3_STREAM_CONTROL);
        wing::encode_h3_settings_frame(ctrl_wire, settings);
        conn.handle_stream_data(2, false, ctrl_wire[..], false);

        // 1. Send HEADERS frame with :status = 204
        var qpack_204: u8[..32] = [];
        qpack_204.push(0x00); // Required Insert Count = 0
        qpack_204.push(0x00); // Delta Base = 0
        wing::encode_qpack_field(qpack_204, ":status", "204", false);

        var wire_h: u8[..64] = [];
        wing::encode_h3_headers_frame(wire_h, qpack_204[..]);

        let err_h = conn.handle_stream_data(0, true, wire_h[..], false);
        sub.assert_eq(err_h, wing::H3_ERR_NO_ERROR, "headers frame accepted");
        sub.assert_eq(conn.streams[0].status_code, 204, "stream status 204 recorded");

        // 2. Peer attempts to send DATA frame on 204 response
        var wire_d: u8[..32] = [];
        wing::encode_h3_data_frame(wire_d, "unexpected body");

        let err_d = conn.handle_stream_data(0, true, wire_d[..], true);
        sub.assert_eq(err_d, wing::H3_ERR_FRAME_UNEXPECTED, "DATA frame on 204 status MUST return H3_ERR_FRAME_UNEXPECTED");
    };

    t.run("H3: reject DATA frame on stream with 304 Not Modified") { sub =>
        let settings = wing::H3Settings { .. };
        var conn = wing::new_h3_client_connection(settings);

        var ctrl_wire: u8[..64] = [];
        wing::quic_encode_varint(ctrl_wire, wing::H3_STREAM_CONTROL);
        wing::encode_h3_settings_frame(ctrl_wire, settings);
        conn.handle_stream_data(2, false, ctrl_wire[..], false);

        var qpack_304: u8[..32] = [];
        qpack_304.push(0x00);
        qpack_304.push(0x00);
        wing::encode_qpack_field(qpack_304, ":status", "304", false);

        var wire_h: u8[..64] = [];
        wing::encode_h3_headers_frame(wire_h, qpack_304[..]);

        conn.handle_stream_data(4, true, wire_h[..], false);

        var wire_d: u8[..32] = [];
        wing::encode_h3_data_frame(wire_d, "unexpected body");

        let err_d = conn.handle_stream_data(4, true, wire_d[..], true);
        sub.assert_eq(err_d, wing::H3_ERR_FRAME_UNEXPECTED, "DATA frame on 304 status MUST return H3_ERR_FRAME_UNEXPECTED");
    };

    t.run("H3: reject DATA frame on stream with 103 Early Hints") { sub =>
        let settings = wing::H3Settings { .. };
        var conn = wing::new_h3_client_connection(settings);

        var ctrl_wire: u8[..64] = [];
        wing::quic_encode_varint(ctrl_wire, wing::H3_STREAM_CONTROL);
        wing::encode_h3_settings_frame(ctrl_wire, settings);
        conn.handle_stream_data(2, false, ctrl_wire[..], false);

        var qpack_103: u8[..32] = [];
        qpack_103.push(0x00);
        qpack_103.push(0x00);
        wing::encode_qpack_field(qpack_103, ":status", "103", false);

        var wire_h: u8[..64] = [];
        wing::encode_h3_headers_frame(wire_h, qpack_103[..]);

        conn.handle_stream_data(8, true, wire_h[..], false);

        var wire_d: u8[..32] = [];
        wing::encode_h3_data_frame(wire_d, "unexpected body");

        let err_d = conn.handle_stream_data(8, true, wire_d[..], true);
        sub.assert_eq(err_d, wing::H3_ERR_FRAME_UNEXPECTED, "DATA frame on 1xx status MUST return H3_ERR_FRAME_UNEXPECTED");
    };
}

// ----------------------------------------------------------------------------
// 2. HTTP/3 Prohibited Trailer Framing Headers & QPACK NUL/CR/LF Injection
// ----------------------------------------------------------------------------
fn test_h3_prohibited_trailers_and_qpack_nul_rejection(t: core::T&) {
    t.run("H3: reject prohibited framing headers in trailers") { sub =>
        let settings = wing::H3Settings { .. };
        var conn = wing::new_h3_client_connection(settings);

        var ctrl_wire: u8[..64] = [];
        wing::quic_encode_varint(ctrl_wire, wing::H3_STREAM_CONTROL);
        wing::encode_h3_settings_frame(ctrl_wire, settings);
        conn.handle_stream_data(2, false, ctrl_wire[..], false);

        // 1. Initial 200 response headers
        var qpack_init: u8[..32] = [];
        qpack_init.push(0x00);
        qpack_init.push(0x00);
        wing::encode_qpack_field(qpack_init, ":status", "200", false);

        var wire_h: u8[..64] = [];
        wing::encode_h3_headers_frame(wire_h, qpack_init[..]);
        conn.handle_stream_data(0, true, wire_h[..], false);

        // 2. Trailer with prohibited transfer-encoding
        var qpack_te: u8[..32] = [];
        qpack_te.push(0x00);
        qpack_te.push(0x00);
        wing::encode_qpack_field(qpack_te, "transfer-encoding", "chunked", false);

        var wire_te: u8[..64] = [];
        wing::encode_h3_headers_frame(wire_te, qpack_te[..]);

        let err_te = conn.handle_stream_data(0, true, wire_te[..], true);
        sub.assert_eq(err_te, wing::H3_ERR_GENERAL_PROTOCOL, "trailer with transfer-encoding MUST return H3_ERR_GENERAL_PROTOCOL");

        // 3. New connection: trailer with prohibited connection: close
        var conn2 = wing::new_h3_client_connection(settings);
        conn2.handle_stream_data(2, false, ctrl_wire[..], false);
        conn2.handle_stream_data(0, true, wire_h[..], false);

        var qpack_conn: u8[..32] = [];
        qpack_conn.push(0x00);
        qpack_conn.push(0x00);
        wing::encode_qpack_field(qpack_conn, "connection", "close", false);

        var wire_conn: u8[..64] = [];
        wing::encode_h3_headers_frame(wire_conn, qpack_conn[..]);

        let err_conn = conn2.handle_stream_data(0, true, wire_conn[..], true);
        sub.assert_eq(err_conn, wing::H3_ERR_GENERAL_PROTOCOL, "trailer with connection MUST return H3_ERR_GENERAL_PROTOCOL");

        // 4. New connection: trailer with prohibited upgrade
        var conn3 = wing::new_h3_client_connection(settings);
        conn3.handle_stream_data(2, false, ctrl_wire[..], false);
        conn3.handle_stream_data(0, true, wire_h[..], false);

        var qpack_upg: u8[..32] = [];
        qpack_upg.push(0x00);
        qpack_upg.push(0x00);
        wing::encode_qpack_field(qpack_upg, "upgrade", "websocket", false);

        var wire_upg: u8[..64] = [];
        wing::encode_h3_headers_frame(wire_upg, qpack_upg[..]);

        let err_upg = conn3.handle_stream_data(0, true, wire_upg[..], true);
        sub.assert_eq(err_upg, wing::H3_ERR_GENERAL_PROTOCOL, "trailer with upgrade MUST return H3_ERR_GENERAL_PROTOCOL");
    };

    t.run("QPACK: reject field values with NUL, CR, or LF") { sub =>
        let tbl = wing::new_qpack_table(0, 0);
        var fields: wing::HeaderField[>..] = [];

        // Literal with NUL byte in value: "hello\0world"
        var nul_val_wire: u8[..32] = [];
        nul_val_wire.push(0x00); // ric 0
        nul_val_wire.push(0x00); // delta base 0
        wing::encode_qpack_field(nul_val_wire, "x-custom", "hello\0world", false);

        let err_nul = wing::decode_qpack_section(tbl, nul_val_wire[..], fields);
        sub.assert_eq(err_nul, wing::QpackError.DecompressionFailed, "field value with NUL MUST return DecompressionFailed");

        // Literal with CR in value: "hello\rworld"
        var cr_val_wire: u8[..32] = [];
        cr_val_wire.push(0x00);
        cr_val_wire.push(0x00);
        wing::encode_qpack_field(cr_val_wire, "x-custom", "hello\rworld", false);

        let err_cr = wing::decode_qpack_section(tbl, cr_val_wire[..], fields);
        sub.assert_eq(err_cr, wing::QpackError.DecompressionFailed, "field value with CR MUST return DecompressionFailed");

        // Literal with LF in value: "hello\nworld"
        var lf_val_wire: u8[..32] = [];
        lf_val_wire.push(0x00);
        lf_val_wire.push(0x00);
        wing::encode_qpack_field(lf_val_wire, "x-custom", "hello\nworld", false);

        let err_lf = wing::decode_qpack_section(tbl, lf_val_wire[..], fields);
        sub.assert_eq(err_lf, wing::QpackError.DecompressionFailed, "field value with LF MUST return DecompressionFailed");
    };
}

// ----------------------------------------------------------------------------
// 3. HTTP/2 :status Pseudo-Header Validation & 101 Prohibition
// ----------------------------------------------------------------------------
fn test_h2_status_pseudo_header_validation(t: core::T&) {
    t.run("HPACK: reject invalid :status values (out of range, non-3-digit, or 101)") { sub =>
        var dt = wing::new_dynamic_table(4096);
        var out_list = wing::DecodedH2HeaderList { .. };

        // 1. :status = "999" (out of 100..599 range)
        var block_999: u8[..32] = [];
        block_999.push(0x00); // literal with new name
        block_999.push(7);
        block_999.append(":status");
        block_999.push(3);
        block_999.append("999");

        let err_999 = wing::decode_hpack_header_block(dt, block_999[..], out_list);
        sub.assert_eq(err_999, wing::ERR_PROTOCOL_ERROR, ":status 999 MUST return PROTOCOL_ERROR");

        // 2. :status = "042" (out of 100..599 range)
        var block_042: u8[..32] = [];
        block_042.push(0x00);
        block_042.push(7);
        block_042.append(":status");
        block_042.push(3);
        block_042.append("042");

        var out_list2 = wing::DecodedH2HeaderList { .. };
        let err_042 = wing::decode_hpack_header_block(dt, block_042[..], out_list2);
        sub.assert_eq(err_042, wing::ERR_PROTOCOL_ERROR, ":status 042 MUST return PROTOCOL_ERROR");

        // 3. :status = "101" (RFC 9113 §8.8: 101 Switching Protocols forbidden in HTTP/2)
        var block_101: u8[..32] = [];
        block_101.push(0x00);
        block_101.push(7);
        block_101.append(":status");
        block_101.push(3);
        block_101.append("101");

        var out_list3 = wing::DecodedH2HeaderList { .. };
        let err_101 = wing::decode_hpack_header_block(dt, block_101[..], out_list3);
        sub.assert_eq(err_101, wing::ERR_PROTOCOL_ERROR, ":status 101 MUST return PROTOCOL_ERROR");

        // 4. :status = "20" (less than 3 digits)
        var block_short: u8[..32] = [];
        block_short.push(0x00);
        block_short.push(7);
        block_short.append(":status");
        block_short.push(2);
        block_short.append("20");

        var out_list4 = wing::DecodedH2HeaderList { .. };
        let err_short = wing::decode_hpack_header_block(dt, block_short[..], out_list4);
        sub.assert_eq(err_short, wing::ERR_PROTOCOL_ERROR, ":status 20 MUST return PROTOCOL_ERROR");

        // 5. :status = "2000" (more than 3 digits)
        var block_long: u8[..32] = [];
        block_long.push(0x00);
        block_long.push(7);
        block_long.append(":status");
        block_long.push(4);
        block_long.append("2000");

        var out_list5 = wing::DecodedH2HeaderList { .. };
        let err_long = wing::decode_hpack_header_block(dt, block_long[..], out_list5);
        sub.assert_eq(err_long, wing::ERR_PROTOCOL_ERROR, ":status 2000 MUST return PROTOCOL_ERROR");
    };

    t.run("HPACK: accept valid 3-digit :status values") { sub =>
        var dt = wing::new_dynamic_table(4096);

        // :status = "200"
        var block_200: u8[..16] = [];
        block_200.push(0x88); // static entry 8 (:status: 200)

        var out_list = wing::DecodedH2HeaderList { .. };
        let err_200 = wing::decode_hpack_header_block(dt, block_200[..], out_list);
        sub.assert_eq(err_200, wing::ERR_NO_ERROR, ":status 200 accepted");

        // :status = "204"
        var block_204: u8[..16] = [];
        block_204.push(0x89); // static entry 9 (:status: 204)

        var out_list2 = wing::DecodedH2HeaderList { .. };
        let err_204 = wing::decode_hpack_header_block(dt, block_204[..], out_list2);
        sub.assert_eq(err_204, wing::ERR_NO_ERROR, ":status 204 accepted");
    };
}

// ----------------------------------------------------------------------------
// 4. HTTP/2 DATA Frame Rejection on Streams with Trailers Received
// ----------------------------------------------------------------------------
fn test_h2_data_frame_after_trailers_rejection(t: core::T&) {
    t.run("H2: reject DATA frame on stream where trailers were received") { sub =>
        var conn = wing::new_h2_connection(0);

        // Open stream 1
        let h_initial = wing::FrameHeader {
            length: 16,
            frame_type: wing::FRAME_HEADERS,
            flags: wing::FLAG_END_HEADERS,
            stream_id: 1,
        };
        wing::on_ingress_frame_header(conn, h_initial, 0);

        // Receive trailers with END_STREAM
        let h_trailers = wing::FrameHeader {
            length: 8,
            frame_type: wing::FRAME_HEADERS,
            flags: wing::FLAG_END_HEADERS | wing::FLAG_END_STREAM,
            stream_id: 1,
        };
        let err_tr = wing::on_ingress_frame_header(conn, h_trailers, 0);
        sub.assert_eq(err_tr, wing::ERR_NO_ERROR, "trailers accepted");

        // Now attempt to feed a DATA frame on stream 1
        let h_data = wing::FrameHeader {
            length: 10,
            frame_type: wing::FRAME_DATA,
            flags: 0,
            stream_id: 1,
        };
        let err_data = wing::on_data_frame_received(conn, h_data, 10);
        sub.assert_eq(err_data, wing::ERR_STREAM_CLOSED, "DATA frame after trailers MUST return ERR_STREAM_CLOSED");
    };
}

// ----------------------------------------------------------------------------
// 5. X.509 DNS Name Constraints Wildcard & Empty/Leading Dot Validation
// ----------------------------------------------------------------------------
fn test_x509_dns_name_constraint_wildcard_and_empty_labels(t: core::T&) {
    t.run("DNS name constraints: reject empty labels and leading dots in candidate") { sub =>
        // Candidate with empty label: "..example.com"
        let res_empty = wing::match_dns_name_constraint("..example.com", ".example.com");
        sub.assert_false(res_empty, "candidate with .. MUST NOT match constraint");

        // Candidate with leading dot: ".example.com"
        let res_lead = wing::match_dns_name_constraint(".example.com", ".example.com");
        sub.assert_false(res_lead, "candidate with leading dot MUST NOT match constraint");

        // Candidate with interior empty label: "sub..example.com"
        let res_inner = wing::match_dns_name_constraint("sub..example.com", "example.com");
        sub.assert_false(res_inner, "candidate with interior .. MUST NOT match constraint");
    };

    t.run("DNS name constraints: wildcard matching rules") { sub =>
        // *.example.com matches constraint .example.com
        let res_wc = wing::match_dns_name_constraint("*.example.com", ".example.com");
        sub.assert_true(res_wc, "*.example.com MUST match .example.com");

        // *.example.com matches constraint example.com
        let res_wc2 = wing::match_dns_name_constraint("*.example.com", "example.com");
        sub.assert_true(res_wc2, "*.example.com MUST match example.com");

        // *.other.com does not match example.com
        let res_diff = wing::match_dns_name_constraint("*.other.com", "example.com");
        sub.assert_false(res_diff, "*.other.com MUST NOT match example.com");
    };

    t.run("DNS name constraints: apex and subdomain distinction") { sub =>
        // Constraint .example.com MUST NOT match example.com itself
        let res_apex = wing::match_dns_name_constraint("example.com", ".example.com");
        sub.assert_false(res_apex, "example.com MUST NOT match .example.com");

        // Constraint example.com MUST match example.com itself
        let res_apex2 = wing::match_dns_name_constraint("example.com", "example.com");
        sub.assert_true(res_apex2, "example.com MUST match example.com");

        // Suffix collision: badexample.com MUST NOT match example.com
        let res_bad = wing::match_dns_name_constraint("badexample.com", "example.com");
        sub.assert_false(res_bad, "badexample.com MUST NOT match example.com");
    };
}

// ----------------------------------------------------------------------------
// 6. X.509 ASN.1 Time Parsing Bounds & Overflow Defense
// ----------------------------------------------------------------------------
fn test_x509_asn1_time_parsing_bounds(t: core::T&) {
    t.run("parse_utc_time: reject out-of-bound calendar fields") { sub =>
        // Valid: "260101120000Z" (2026-01-01 12:00:00 UTC)
        let _, ok_valid = wing::parse_utc_time("260101120000Z");
        sub.assert_true(ok_valid, "valid UTC time parsed");

        // Month 00
        let _, ok_m0 = wing::parse_utc_time("260001120000Z");
        sub.assert_false(ok_m0, "Month 00 rejected");

        // Month 13
        let _, ok_m13 = wing::parse_utc_time("261301120000Z");
        sub.assert_false(ok_m13, "Month 13 rejected");

        // Day 00
        let _, ok_d0 = wing::parse_utc_time("260100120000Z");
        sub.assert_false(ok_d0, "Day 00 rejected");

        // Day 32
        let _, ok_d32 = wing::parse_utc_time("260132120000Z");
        sub.assert_false(ok_d32, "Day 32 rejected");

        // Hour 24
        let _, ok_h24 = wing::parse_utc_time("260101240000Z");
        sub.assert_false(ok_h24, "Hour 24 rejected");

        // Minute 60
        let _, ok_min60 = wing::parse_utc_time("260101126000Z");
        sub.assert_false(ok_min60, "Minute 60 rejected");

        // Second 61
        let _, ok_s61 = wing::parse_utc_time("260101120061Z");
        sub.assert_false(ok_s61, "Second 61 rejected");
    };

    t.run("parse_generalized_time: reject out-of-bound calendar fields") { sub =>
        // Valid: "20260101120000Z"
        let _, ok_valid = wing::parse_generalized_time("20260101120000Z");
        sub.assert_true(ok_valid, "valid Generalized time parsed");

        // Month 00
        let _, ok_m0 = wing::parse_generalized_time("20260001120000Z");
        sub.assert_false(ok_m0, "Month 00 rejected");

        // Month 13
        let _, ok_m13 = wing::parse_generalized_time("20261301120000Z");
        sub.assert_false(ok_m13, "Month 13 rejected");

        // Day 00
        let _, ok_d0 = wing::parse_generalized_time("20260100120000Z");
        sub.assert_false(ok_d0, "Day 00 rejected");

        // Day 32
        let _, ok_d32 = wing::parse_generalized_time("20260132120000Z");
        sub.assert_false(ok_d32, "Day 32 rejected");

        // Hour 24
        let _, ok_h24 = wing::parse_generalized_time("20260101240000Z");
        sub.assert_false(ok_h24, "Hour 24 rejected");

        // Minute 60
        let _, ok_min60 = wing::parse_generalized_time("20260101126000Z");
        sub.assert_false(ok_min60, "Minute 60 rejected");

        // Second 61
        let _, ok_s61 = wing::parse_generalized_time("20260101120061Z");
        sub.assert_false(ok_s61, "Second 61 rejected");
    };
}

// ----------------------------------------------------------------------------
// Main test runner
// ----------------------------------------------------------------------------
fn main() {
    let runner = core::new_runner("red_issues_tracker_phase17_test");

    core::run_case(runner, "1. HTTP/3 DATA Frame Rejection on Bodyless Status Codes (204, 304, 1xx)", test_h3_bodyless_status_data_rejection);
    core::run_case(runner, "2. HTTP/3 Prohibited Trailer Framing Headers & QPACK NUL/CR/LF Injection", test_h3_prohibited_trailers_and_qpack_nul_rejection);
    core::run_case(runner, "3. HTTP/2 :status Pseudo-Header Validation & 101 Prohibition", test_h2_status_pseudo_header_validation);
    core::run_case(runner, "4. HTTP/2 DATA Frame Rejection on Streams with Trailers Received", test_h2_data_frame_after_trailers_rejection);
    core::run_case(runner, "5. X.509 DNS Name Constraints Wildcard & Empty/Leading Dot Validation", test_x509_dns_name_constraint_wildcard_and_empty_labels);
    core::run_case(runner, "6. X.509 ASN.1 Time Parsing Bounds & Overflow Defense", test_x509_asn1_time_parsing_bounds);

    let ok = core::finish(runner);
    assert(ok);
}
