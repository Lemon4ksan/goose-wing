// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Phase 18 RED test suite: Reducing Load, DoS Mitigation, RFC Conformance,
// and Protocol Invariants.
//
// 1. HTTP/3 Server Request Trailers Invariants (RFC 9114 §4.3)
// 2. HTTP/3 Empty DATA Frame Flooding Defense (CVE-2019-9518, RFC 9114 §10.5)
// 3. X.509 Basic Constraints Negative or Non-CA PathLen Defense (RFC 5280 §4.2.1.9, OpenSSL #32374)
// 4. X.509 Name Constraints Subtree Base dNSName Validation (RFC 5280 §4.2.1.10, OpenSSL #31686)

import std;
import core from "..";
import wing from "..";

// ----------------------------------------------------------------------------
// 1. HTTP/3 Server Request Trailers Invariants (RFC 9114 §4.3)
// ----------------------------------------------------------------------------
fn test_h3_server_request_trailers_invariants(t: core::T&) {
    t.run("H3 Server: reject pseudo-headers in request trailers") { sub =>
        let settings = wing::H3Settings { .. };
        var conn = wing::new_h3_server_connection(settings);

        // Client control stream setup on stream 3 (unidirectional client stream)
        var ctrl_wire: u8[..64] = [];
        wing::quic_encode_varint(ctrl_wire, wing::H3_STREAM_CONTROL);
        wing::encode_h3_settings_frame(ctrl_wire, settings);
        conn.handle_stream_data(3, false, ctrl_wire[..], false);

        // 1. Client sends initial request HEADERS on stream 0
        var qpack_req: u8[..128] = [];
        qpack_req.push(0x00); // ric 0
        qpack_req.push(0x00); // delta base 0
        wing::encode_qpack_field(qpack_req, ":method", "POST", false);
        wing::encode_qpack_field(qpack_req, ":scheme", "https", false);
        wing::encode_qpack_field(qpack_req, ":authority", "example.com", false);
        wing::encode_qpack_field(qpack_req, ":path", "/upload", false);

        var wire_req: u8[..128] = [];
        wing::encode_h3_headers_frame(wire_req, qpack_req[..]);
        let err_req = conn.handle_stream_data(0, true, wire_req[..], false);
        sub.assert_eq(err_req, wing::H3_ERR_NO_ERROR, "initial request headers accepted");

        // 2. Client sends DATA frame on stream 0
        var wire_d: u8[..32] = [];
        wing::encode_h3_data_frame(wire_d, "payload-data");
        let err_d = conn.handle_stream_data(0, true, wire_d[..], false);
        sub.assert_eq(err_d, wing::H3_ERR_NO_ERROR, "data frame accepted");

        // 3. Client sends trailers containing forbidden pseudo-header :path
        var qpack_tr: u8[..64] = [];
        qpack_tr.push(0x00);
        qpack_tr.push(0x00);
        wing::encode_qpack_field(qpack_tr, ":path", "/forbidden", false);

        var wire_tr: u8[..64] = [];
        wing::encode_h3_headers_frame(wire_tr, qpack_tr[..]);
        let err_tr = conn.handle_stream_data(0, true, wire_tr[..], true);
        sub.assert_eq(err_tr, wing::H3_ERR_GENERAL_PROTOCOL, "request trailers with pseudo-header MUST return H3_ERR_GENERAL_PROTOCOL");
    };

    t.run("H3 Server: reject prohibited framing headers in request trailers") { sub =>
        let settings = wing::H3Settings { .. };
        var conn = wing::new_h3_server_connection(settings);

        var ctrl_wire: u8[..64] = [];
        wing::quic_encode_varint(ctrl_wire, wing::H3_STREAM_CONTROL);
        wing::encode_h3_settings_frame(ctrl_wire, settings);
        conn.handle_stream_data(3, false, ctrl_wire[..], false);

        var qpack_req: u8[..128] = [];
        qpack_req.push(0x00);
        qpack_req.push(0x00);
        wing::encode_qpack_field(qpack_req, ":method", "POST", false);
        wing::encode_qpack_field(qpack_req, ":scheme", "https", false);
        wing::encode_qpack_field(qpack_req, ":authority", "example.com", false);
        wing::encode_qpack_field(qpack_req, ":path", "/upload", false);

        var wire_req: u8[..128] = [];
        wing::encode_h3_headers_frame(wire_req, qpack_req[..]);
        conn.handle_stream_data(0, true, wire_req[..], false);

        // Client sends trailers with prohibited transfer-encoding
        var qpack_te: u8[..64] = [];
        qpack_te.push(0x00);
        qpack_te.push(0x00);
        wing::encode_qpack_field(qpack_te, "transfer-encoding", "chunked", false);

        var wire_te: u8[..64] = [];
        wing::encode_h3_headers_frame(wire_te, qpack_te[..]);
        let err_te = conn.handle_stream_data(0, true, wire_te[..], true);
        sub.assert_eq(err_te, wing::H3_ERR_GENERAL_PROTOCOL, "request trailers with transfer-encoding MUST return H3_ERR_GENERAL_PROTOCOL");
    };

    t.run("H3 Server: reject DATA frame or extra HEADERS after request trailers") { sub =>
        let settings = wing::H3Settings { .. };
        var conn = wing::new_h3_server_connection(settings);

        var ctrl_wire: u8[..64] = [];
        wing::quic_encode_varint(ctrl_wire, wing::H3_STREAM_CONTROL);
        wing::encode_h3_settings_frame(ctrl_wire, settings);
        conn.handle_stream_data(3, false, ctrl_wire[..], false);

        var qpack_req: u8[..128] = [];
        qpack_req.push(0x00);
        qpack_req.push(0x00);
        wing::encode_qpack_field(qpack_req, ":method", "POST", false);
        wing::encode_qpack_field(qpack_req, ":scheme", "https", false);
        wing::encode_qpack_field(qpack_req, ":authority", "example.com", false);
        wing::encode_qpack_field(qpack_req, ":path", "/upload", false);

        var wire_req: u8[..128] = [];
        wing::encode_h3_headers_frame(wire_req, qpack_req[..]);
        conn.handle_stream_data(0, true, wire_req[..], false);

        // Valid trailer: x-checksum
        var qpack_tr: u8[..64] = [];
        qpack_tr.push(0x00);
        qpack_tr.push(0x00);
        wing::encode_qpack_field(qpack_tr, "x-checksum", "deadbeef", false);

        var wire_tr: u8[..64] = [];
        wing::encode_h3_headers_frame(wire_tr, qpack_tr[..]);
        let err_tr = conn.handle_stream_data(0, true, wire_tr[..], false);
        sub.assert_eq(err_tr, wing::H3_ERR_NO_ERROR, "valid request trailers accepted");

        // Attempt 1: Peer sends DATA frame after trailers
        var wire_d: u8[..32] = [];
        wing::encode_h3_data_frame(wire_d, "extra data");
        let err_data = conn.handle_stream_data(0, true, wire_d[..], false);
        sub.assert_eq(err_data, wing::H3_ERR_FRAME_UNEXPECTED, "DATA after request trailers MUST return H3_ERR_FRAME_UNEXPECTED");

        // Attempt 2 (new connection): Peer sends a 3rd HEADERS frame after trailers
        var conn2 = wing::new_h3_server_connection(settings);
        conn2.handle_stream_data(3, false, ctrl_wire[..], false);
        conn2.handle_stream_data(0, true, wire_req[..], false);
        conn2.handle_stream_data(0, true, wire_tr[..], false);

        var wire_extra_h: u8[..64] = [];
        wing::encode_h3_headers_frame(wire_extra_h, qpack_tr[..]);
        let err_extra_h = conn2.handle_stream_data(0, true, wire_extra_h[..], true);
        sub.assert_eq(err_extra_h, wing::H3_ERR_FRAME_UNEXPECTED, "HEADERS after request trailers MUST return H3_ERR_FRAME_UNEXPECTED");
    };
}

// ----------------------------------------------------------------------------
// 2. HTTP/3 Empty DATA Frame Flooding Defense (CVE-2019-9518, RFC 9114 §10.5)
// ----------------------------------------------------------------------------
fn test_h3_empty_frame_flooding(t: core::T&) {
    t.run("H3: reject flood of empty DATA frames (> 32 streak)") { sub =>
        let settings = wing::H3Settings { .. };
        var conn = wing::new_h3_client_connection(settings);

        var ctrl_wire: u8[..64] = [];
        wing::quic_encode_varint(ctrl_wire, wing::H3_STREAM_CONTROL);
        wing::encode_h3_settings_frame(ctrl_wire, settings);
        conn.handle_stream_data(2, false, ctrl_wire[..], false);

        // Initial 200 response headers
        var qpack_resp: u8[..32] = [];
        qpack_resp.push(0x00);
        qpack_resp.push(0x00);
        wing::encode_qpack_field(qpack_resp, ":status", "200", false);

        var wire_h: u8[..64] = [];
        wing::encode_h3_headers_frame(wire_h, qpack_resp[..]);
        conn.handle_stream_data(0, true, wire_h[..], false);

        // Prepare empty DATA frame
        var wire_empty: u8[..16] = [];
        wing::encode_h3_data_frame(wire_empty, "");

        var err: u64 = wing::H3_ERR_NO_ERROR;
        for i in 32 {
            err = conn.handle_stream_data(0, true, wire_empty[..], false);
            sub.assert_eq(err, wing::H3_ERR_NO_ERROR, "empty data frame within budget accepted");
        }

        // The 33rd consecutive empty DATA frame triggers flood defense
        err = conn.handle_stream_data(0, true, wire_empty[..], false);
        sub.assert_eq(err, wing::H3_ERR_EXCESSIVE_LOAD, "empty data frame exceeding streak MUST return H3_ERR_EXCESSIVE_LOAD");
    };
}

// ----------------------------------------------------------------------------
// 3. X.509 Basic Constraints Negative or Non-CA PathLen Defense (RFC 5280 §4.2.1.9)
// ----------------------------------------------------------------------------
fn test_x509_basic_constraints_negative_or_non_ca_pathlen(t: core::T&) {
    t.run("BasicConstraints: reject negative pathLenConstraint in CA cert") { sub =>
        // DER sequence: [BOOLEAN TRUE, INTEGER -1]
        // 30 06:
        //   01 01 FF (cA: TRUE)
        //   02 01 FF (pathLen: -1)
        var bc_der: u8[..8] = [0x30, 0x06, 0x01, 0x01, 0xFF, 0x02, 0x01, 0xFF];
        var cert = wing::ParsedCert { .. };
        var c = wing::cursor_from(bc_der[..]);
        wing::x509_parse_basic_constraints_ext(c, cert);

        sub.assert_true(cert.has_unsupported_critical, "negative pathLenConstraint MUST mark cert unsupported/malformed");
    };

    t.run("BasicConstraints: reject pathLenConstraint when cA is false") { sub =>
        // DER sequence: [BOOLEAN FALSE, INTEGER 3]
        // 30 06:
        //   01 01 00 (cA: FALSE)
        //   02 01 03 (pathLen: 3)
        var bc_der: u8[..8] = [0x30, 0x06, 0x01, 0x01, 0x00, 0x02, 0x01, 0x03];
        var cert = wing::ParsedCert { .. };
        var c = wing::cursor_from(bc_der[..]);
        wing::x509_parse_basic_constraints_ext(c, cert);

        sub.assert_true(cert.has_unsupported_critical, "pathLenConstraint on non-CA cert MUST mark cert unsupported/malformed");
    };
}

// ----------------------------------------------------------------------------
// 4. X.509 Name Constraints Subtree Base dNSName Validation (RFC 5280 §4.2.1.10)
// ----------------------------------------------------------------------------
fn test_x509_name_constraints_subtree_dns_nul(t: core::T&) {
    t.run("NameConstraints: reject subtree base dNSName with embedded NUL") { sub =>
        var subtree_buf: u8[..32] = [];
        // [2] dNSName tag 0x82, length 12: "example\0.com"
        subtree_buf.push(0x82);
        subtree_buf.push(12);
        subtree_buf.append("example\0.com");

        var c = wing::cursor_from(subtree_buf[..]);
        var out_type = wing::SanType.Other;
        var out_val = wing::cursor_from(subtree_buf[..0]);
        let ok = wing::x509_parse_general_subtree_base(c, out_type, out_val);
        sub.assert_false(ok, "subtree base dNSName with embedded NUL MUST be rejected");
    };
}

// ----------------------------------------------------------------------------
// Main test runner
// ----------------------------------------------------------------------------
fn main() {
    let runner = core::new_runner("red_issues_tracker_phase18_test");

    core::run_case(runner, "1. HTTP/3 Server Request Trailers Invariants", test_h3_server_request_trailers_invariants);
    core::run_case(runner, "2. HTTP/3 Empty DATA Frame Flooding Defense", test_h3_empty_frame_flooding);
    core::run_case(runner, "3. X.509 Basic Constraints Negative or Non-CA PathLen Defense", test_x509_basic_constraints_negative_or_non_ca_pathlen);
    core::run_case(runner, "4. X.509 Name Constraints Subtree Base dNSName Validation", test_x509_name_constraints_subtree_dns_nul);

    let ok = core::finish(runner);
    assert(ok);
}
