// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Consolidated Verification Suite: Issue Regression Suite Batch 4 (Phases 16-19 & Stress)
import std;
import core from "..";
import wing from "..";

// --- Component: regress_issues_batch16 ---
// Phase 16 RED test suite: RFC Protocol Invariants, Authority/Host Smuggling Defenses,
// Name Constraint Bounds, Frame State Sequences, and Empty-Status Bodyless Wire Formats.
//
// 1. X.509 URI Name Constraints Evasion via @ in Path/Query & ?/# Suffix (tls/x509.goose)
// 2. HTTP/1.1 Wire Response Parser 204/304/1xx Chunked Desync & Header Block Cap (server/server.goose)
// 3. HTTP/1.1 Response Serializer Empty-Status Chunked Bodyless Enforcement (server/server.goose)
// 4. HTTP/3 Stream Data Host vs :authority Conflict & Host Syntax (http3/connection.goose)
// 5. HTTP/2 HPACK Host Syntax & Case-Insensitive Authority Equivalence (http2/hpack.goose)
// 6. HTTP/2 Connection Frame Coordinator Trailer END_STREAM Enforcement (http2/connection.goose)
// 7. CORS Wildcard Origin Authority Smuggling & CSRF Userinfo Spoofing (security/cors.goose, security/csrf.goose)

// ----------------------------------------------------------------------------
// 1. X.509 URI Name Constraints Evasion via @ in Path/Query & ?/# Suffix
// ----------------------------------------------------------------------------
fn test_x509_uri_name_constraints_evasion(t: core::T&) {
    t.run("URI name constraints: reject @ in path/query smuggling permitted host") { sub =>
        // Attacker attempts to bypass name constraints by putting @ in the path:
        // Host is "evil.com", path contains "@permitted.example.com"
        let candidate = "https://evil.com/path@permitted.example.com";
        let res = wing::match_uri_name_constraint(candidate, "permitted.example.com");
        sub.assert_false(res, "evil.com with @permitted in path MUST NOT match constraint permitted.example.com");

        let candidate_q = "https://evil.com/resource?foo=bar@permitted.example.com";
        let res_q = wing::match_uri_name_constraint(candidate_q, "permitted.example.com");
        sub.assert_false(res_q, "evil.com with @permitted in query MUST NOT match constraint permitted.example.com");
    };

    t.run("URI name constraints: reject ? or # suffix confusion after host") { sub =>
        // Attacker attempts to smuggle suffix match by ending host with ? or #
        let candidate_q = "https://evil.com?.permitted.example.com";
        let res_q = wing::match_uri_name_constraint(candidate_q, "permitted.example.com");
        sub.assert_false(res_q, "evil.com?.permitted.example.com MUST NOT match permitted.example.com");

        let candidate_h = "https://evil.com#.permitted.example.com";
        let res_h = wing::match_uri_name_constraint(candidate_h, "permitted.example.com");
        sub.assert_false(res_h, "evil.com#.permitted.example.com MUST NOT match permitted.example.com");
    };

    t.run("URI name constraints: reject userinfo in authority and IPv4 literals for dNSName") { sub =>
        // RFC 5280 §4.2.1.10: URI SAN with userinfo cannot satisfy a DNS name constraint
        let cand_user = "https://user:pass@permitted.example.com/path";
        let res_u = wing::match_uri_name_constraint(cand_user, "permitted.example.com");
        sub.assert_false(res_u, "userinfo in URI authority MUST NOT satisfy DNS constraint");

        // IPv4 address literal cannot satisfy a dNSName constraint
        let cand_ip = "https://192.168.1.1/path";
        let res_ip = wing::match_uri_name_constraint(cand_ip, "192.168.1.1");
        sub.assert_false(res_ip, "IPv4 literal MUST NOT satisfy dNSName constraint");
    };

    t.run("URI name constraints: valid DNS matches succeed") { sub =>
        let cand_valid = "https://sub.permitted.example.com/path";
        let res_v = wing::match_uri_name_constraint(cand_valid, "permitted.example.com");
        sub.assert_true(res_v, "valid subdomain matches constraint");

        let cand_exact = "https://permitted.example.com/path";
        let res_e = wing::match_uri_name_constraint(cand_exact, "permitted.example.com");
        sub.assert_true(res_e, "exact domain matches constraint");
    };
}

// ----------------------------------------------------------------------------
// 2. HTTP/1.1 Wire Response Parser 204/304/1xx Chunked Desync & Header Block Cap
// ----------------------------------------------------------------------------
fn test_http1_wire_response_204_304_1xx_framing(t: core::T&) {
    t.run("parse_http1_wire_response: 204/304/1xx with Transfer-Encoding chunked must succeed without body") { sub =>
        // RFC 9112 §6.3 rule 1: 1xx, 204, and 304 responses NEVER have a message body,
        // even if Transfer-Encoding: chunked is sent by a broken/malicious upstream.
        let wire_204 = "HTTP/1.1 204 No Content\r\nTransfer-Encoding: chunked\r\n\r\n";
        var res_204 = wing::Response { .. };
        let ok_204, consumed_204 = wing::parse_http1_wire_response(wire_204, res_204);
        sub.assert_true(ok_204, "204 with Transfer-Encoding: chunked MUST succeed");
        sub.assert_eq(consumed_204, wire_204.len, "consumed exact header bytes");
        sub.assert_eq(res_204.status_code, 204, "status code is 204");
        sub.assert_eq(res_204.body.len, 0, "body must be empty for 204");

        let wire_304 = "HTTP/1.1 304 Not Modified\r\nTransfer-Encoding: chunked\r\n\r\n";
        var res_304 = wing::Response { .. };
        let ok_304, consumed_304 = wing::parse_http1_wire_response(wire_304, res_304);
        sub.assert_true(ok_304, "304 with Transfer-Encoding: chunked MUST succeed");
        sub.assert_eq(consumed_304, wire_304.len, "consumed exact header bytes");
        sub.assert_eq(res_304.status_code, 304, "status code is 304");
        sub.assert_eq(res_304.body.len, 0, "body must be empty for 304");

        let wire_100 = "HTTP/1.1 100 Continue\r\nTransfer-Encoding: chunked\r\n\r\n";
        var res_100 = wing::Response { .. };
        let ok_100, consumed_100 = wing::parse_http1_wire_response(wire_100, res_100);
        sub.assert_true(ok_100, "100 Continue with Transfer-Encoding: chunked MUST succeed");
        sub.assert_eq(consumed_100, wire_100.len, "consumed exact header bytes");
        sub.assert_eq(res_100.status_code, 100, "status code is 100");
        sub.assert_eq(res_100.body.len, 0, "body must be empty for 100");
    };

    t.run("parse_http1_wire_response: enforce 8192 byte header block ceiling") { sub =>
        // A response header block exceeding 8192 bytes MUST be rejected
        var huge_resp: u8[>..] = [];
        huge_resp.append("HTTP/1.1 200 OK\r\n");
        while huge_resp.len < 8200 {
            huge_resp.append("X-Padding: 0123456789012345678901234567890123456789\r\n");
        }
        huge_resp.append("\r\n");

        var res = wing::Response { .. };
        let ok, _ = wing::parse_http1_wire_response(huge_resp[..], res);
        sub.assert_false(ok, "response header block > 8192 bytes MUST be rejected");
    };
}

// ----------------------------------------------------------------------------
// 3. HTTP/1.1 Response Serializer Empty-Status Chunked Bodyless Enforcement
// ----------------------------------------------------------------------------
fn test_http1_response_serialization_empty_status(t: core::T&) {
    t.run("serialize_http1_response: 204/304 suppresses Transfer-Encoding and chunked body") { sub =>
        // 204 No Content with Transfer-Encoding or trailers requested
        var res_204 = wing::Response { .. };
        res_204.status_code = 204;
        res_204.headers.push(wing::make_header("Transfer-Encoding", "chunked"));
        wing::add_trailer(res_204, "X-Checksum", "abc");
        res_204.body.append("illegal body data");

        var wire_204: u8[>..] = [];
        wing::serialize_http1_response(res_204, "goose-wing/1.0", wire_204);

        sub.assert_contains(wire_204[..], "HTTP/1.1 204 No Content\r\n", "Status line is 204");
        sub.assert_not_contains(wire_204[..], "Transfer-Encoding", "Transfer-Encoding MUST NOT be emitted on 204");
        sub.assert_not_contains(wire_204[..], "Content-Length", "Content-Length MUST NOT be emitted on 204");
        sub.assert_not_contains(wire_204[..], "0\r\n\r\n", "0\\r\\n\\r\\n chunked body MUST NOT be emitted on 204");
        sub.assert_not_contains(wire_204[..], "illegal body data", "body data MUST NOT be emitted on 204");

        // 304 Not Modified
        var res_304 = wing::Response { .. };
        res_304.status_code = 304;
        res_304.headers.push(wing::make_header("Transfer-Encoding", "chunked"));
        wing::add_trailer(res_304, "X-Checksum", "abc");

        var wire_304: u8[>..] = [];
        wing::serialize_http1_response(res_304, "goose-wing/1.0", wire_304);

        sub.assert_contains(wire_304[..], "HTTP/1.1 304 Not Modified\r\n", "Status line is 304");
        sub.assert_not_contains(wire_304[..], "Transfer-Encoding", "Transfer-Encoding MUST NOT be emitted on 304");
        sub.assert_not_contains(wire_304[..], "Content-Length", "Content-Length MUST NOT be emitted on 304");
        sub.assert_not_contains(wire_304[..], "0\r\n\r\n", "chunked body MUST NOT be emitted on 304");
    };

    t.run("serialize_http1_response: 1xx suppresses automatic Content-Length: 0") { sub =>
        var res_100 = wing::Response { .. };
        res_100.status_code = 100;

        var wire_100: u8[>..] = [];
        wing::serialize_http1_response(res_100, "goose-wing/1.0", wire_100);

        sub.assert_contains(wire_100[..], "HTTP/1.1 100 Continue\r\n", "Status line is 100");
        sub.assert_not_contains(wire_100[..], "Content-Length", "1xx MUST NOT emit Content-Length: 0");
    };
}

// ----------------------------------------------------------------------------
// 4. HTTP/3 Stream Data Host vs :authority Conflict & Host Syntax
// ----------------------------------------------------------------------------
fn test_h3_host_authority_conflict_and_syntax(t: core::T&) {
    t.run("H3 request: reject conflicting :authority and host headers") { sub =>
        let settings = wing::H3Settings { .. };
        var conn = wing::new_h3_client_connection(settings);

        // Establish control stream (Stream 2)
        var ctrl_wire: u8[..64] = [];
        wing::quic_encode_varint(ctrl_wire, wing::H3_STREAM_CONTROL);
        wing::encode_h3_settings_frame(ctrl_wire, settings);
        conn.handle_stream_data(2, false, ctrl_wire[..], false);

        // Stream 0: Request headers with :authority: "example.com" and host: "evil.com"
        var sec: u8[..256] = [0x00, 0x00]; // RIC 0, Base 0
        wing::encode_qpack_field(sec, ":method", "GET", false);
        wing::encode_qpack_field(sec, ":scheme", "https", false);
        wing::encode_qpack_field(sec, ":path", "/", false);
        wing::encode_qpack_field(sec, ":authority", "example.com", false);
        wing::encode_qpack_field(sec, "host", "evil.com", false);

        var req_frame: u8[..256] = [];
        wing::encode_h3_headers_frame(req_frame, sec[..]);

        let err = conn.handle_stream_data(0, true, req_frame[..], false);
        sub.assert_eq(err, wing::H3_ERR_GENERAL_PROTOCOL, "conflicting :authority and host MUST return H3_ERR_GENERAL_PROTOCOL");
    };

    t.run("H3 request: reject duplicate host headers and invalid host syntax") { sub =>
        let settings = wing::H3Settings { .. };
        var conn = wing::new_h3_client_connection(settings);

        var ctrl_wire: u8[..64] = [];
        wing::quic_encode_varint(ctrl_wire, wing::H3_STREAM_CONTROL);
        wing::encode_h3_settings_frame(ctrl_wire, settings);
        conn.handle_stream_data(2, false, ctrl_wire[..], false);

        // Duplicate host headers
        var sec_dup: u8[..256] = [0x00, 0x00];
        wing::encode_qpack_field(sec_dup, ":method", "GET", false);
        wing::encode_qpack_field(sec_dup, ":scheme", "https", false);
        wing::encode_qpack_field(sec_dup, ":path", "/", false);
        wing::encode_qpack_field(sec_dup, "host", "example.com", false);
        wing::encode_qpack_field(sec_dup, "host", "example.com", false);

        var dup_frame: u8[..256] = [];
        wing::encode_h3_headers_frame(dup_frame, sec_dup[..]);

        let err_dup = conn.handle_stream_data(0, true, dup_frame[..], false);
        sub.assert_eq(err_dup, wing::H3_ERR_GENERAL_PROTOCOL, "duplicate host headers MUST return H3_ERR_GENERAL_PROTOCOL");

        // Invalid host syntax (containing '/')
        var conn2 = wing::new_h3_client_connection(settings);
        conn2.handle_stream_data(2, false, ctrl_wire[..], false);

        var sec_bad: u8[..256] = [0x00, 0x00];
        wing::encode_qpack_field(sec_bad, ":method", "GET", false);
        wing::encode_qpack_field(sec_bad, ":scheme", "https", false);
        wing::encode_qpack_field(sec_bad, ":path", "/", false);
        wing::encode_qpack_field(sec_bad, "host", "example.com/evil", false);

        var bad_frame: u8[..256] = [];
        wing::encode_h3_headers_frame(bad_frame, sec_bad[..]);

        let err_bad = conn2.handle_stream_data(0, true, bad_frame[..], false);
        sub.assert_eq(err_bad, wing::H3_ERR_GENERAL_PROTOCOL, "host with slash MUST return H3_ERR_GENERAL_PROTOCOL");

        // Empty :authority
        var conn3 = wing::new_h3_client_connection(settings);
        conn3.handle_stream_data(2, false, ctrl_wire[..], false);

        var sec_empty: u8[..256] = [0x00, 0x00];
        wing::encode_qpack_field(sec_empty, ":method", "GET", false);
        wing::encode_qpack_field(sec_empty, ":scheme", "https", false);
        wing::encode_qpack_field(sec_empty, ":path", "/", false);
        wing::encode_qpack_field(sec_empty, ":authority", "", false);

        var empty_frame: u8[..256] = [];
        wing::encode_h3_headers_frame(empty_frame, sec_empty[..]);

        let err_empty = conn3.handle_stream_data(0, true, empty_frame[..], false);
        sub.assert_eq(err_empty, wing::H3_ERR_GENERAL_PROTOCOL, "empty :authority MUST return H3_ERR_GENERAL_PROTOCOL");
    };

    t.run("H3 request: matching case-insensitive :authority and host succeed") { sub =>
        let settings = wing::H3Settings { .. };
        var conn = wing::new_h3_client_connection(settings);

        var ctrl_wire: u8[..64] = [];
        wing::quic_encode_varint(ctrl_wire, wing::H3_STREAM_CONTROL);
        wing::encode_h3_settings_frame(ctrl_wire, settings);
        conn.handle_stream_data(2, false, ctrl_wire[..], false);

        var sec_ok: u8[..256] = [0x00, 0x00];
        wing::encode_qpack_field(sec_ok, ":method", "GET", false);
        wing::encode_qpack_field(sec_ok, ":scheme", "https", false);
        wing::encode_qpack_field(sec_ok, ":path", "/", false);
        wing::encode_qpack_field(sec_ok, ":authority", "Example.COM", false);
        wing::encode_qpack_field(sec_ok, "host", "example.com", false);

        var ok_frame: u8[..256] = [];
        wing::encode_h3_headers_frame(ok_frame, sec_ok[..]);

        let err_ok = conn.handle_stream_data(0, true, ok_frame[..], false);
        sub.assert_eq(err_ok, wing::H3_ERR_NO_ERROR, "case-insensitive matching authority and host accepted");
    };
}

// ----------------------------------------------------------------------------
// 5. HTTP/2 HPACK Host Syntax & Case-Insensitive Authority Equivalence
// ----------------------------------------------------------------------------
fn test_h2_hpack_host_authority_validation(t: core::T&) {
    t.run("HPACK: reject empty :authority and empty host") { sub =>
        var dt = wing::new_dynamic_table(4096);
        var out_list = wing::DecodedH2HeaderList { .. };

        // 1. Empty :authority (0x01 is static index for :authority with literal value len 0)
        var empty_auth_block: u8[..32] = [];
        empty_auth_block.push(0x82); // :method: GET
        empty_auth_block.push(0x87); // :scheme: https
        empty_auth_block.push(0x84); // :path: /
        empty_auth_block.push(0x01); // literal with static name 1 (:authority)
        empty_auth_block.push(0x00); // value len 0

        let err_auth = wing::decode_hpack_header_block(dt, empty_auth_block[..], out_list);
        sub.assert_eq(err_auth, wing::ERR_PROTOCOL_ERROR, "empty :authority MUST return PROTOCOL_ERROR");

        // 2. Empty host
        var empty_host_block: u8[..32] = [];
        empty_host_block.push(0x82); // :method: GET
        empty_host_block.push(0x87); // :scheme: https
        empty_host_block.push(0x84); // :path: /
        empty_host_block.push(0x00); // literal with new name
        empty_host_block.push(4);    // name len 4
        empty_host_block.append("host");
        empty_host_block.push(0);    // value len 0

        var out_list2 = wing::DecodedH2HeaderList { .. };
        let err_host = wing::decode_hpack_header_block(dt, empty_host_block[..], out_list2);
        sub.assert_eq(err_host, wing::ERR_PROTOCOL_ERROR, "empty host header MUST return PROTOCOL_ERROR");
    };

    t.run("HPACK: reject host with invalid authority characters") { sub =>
        var dt = wing::new_dynamic_table(4096);
        var out_list = wing::DecodedH2HeaderList { .. };

        // Host containing slash (host: evil.com/path)
        var slash_host_block: u8[..32] = [];
        slash_host_block.push(0x82); // :method: GET
        slash_host_block.push(0x87); // :scheme: https
        slash_host_block.push(0x84); // :path: /
        slash_host_block.push(0x00); // literal with new name
        slash_host_block.push(4);    // name len 4
        slash_host_block.append("host");
        slash_host_block.push(13);   // value len 13
        slash_host_block.append("evil.com/path");

        let err_slash = wing::decode_hpack_header_block(dt, slash_host_block[..], out_list);
        sub.assert_eq(err_slash, wing::ERR_PROTOCOL_ERROR, "host with slash MUST return PROTOCOL_ERROR");

        // Host containing userinfo @ (host: user@evil.com)
        var user_host_block: u8[..32] = [];
        user_host_block.push(0x82);
        user_host_block.push(0x87);
        user_host_block.push(0x84);
        user_host_block.push(0x00);
        user_host_block.push(4);
        user_host_block.append("host");
        user_host_block.push(13);
        user_host_block.append("user@evil.com");

        var out_list2 = wing::DecodedH2HeaderList { .. };
        let err_user = wing::decode_hpack_header_block(dt, user_host_block[..], out_list2);
        sub.assert_eq(err_user, wing::ERR_PROTOCOL_ERROR, "host with @ MUST return PROTOCOL_ERROR");
    };

    t.run("HPACK: accept case-insensitive matching :authority and host") { sub =>
        var dt = wing::new_dynamic_table(4096);
        var out_list = wing::DecodedH2HeaderList { .. };

        // :authority: Example.COM and host: example.com
        var hpack_block: u8[..64] = [];
        hpack_block.push(0x82); // :method: GET
        hpack_block.push(0x87); // :scheme: https
        hpack_block.push(0x84); // :path: /
        hpack_block.push(0x01); // :authority
        hpack_block.push(11);
        hpack_block.append("Example.COM");
        hpack_block.push(0x00); // host
        hpack_block.push(4);
        hpack_block.append("host");
        hpack_block.push(11);
        hpack_block.append("example.com");

        let err = wing::decode_hpack_header_block(dt, hpack_block[..], out_list);
        sub.assert_eq(err, wing::ERR_NO_ERROR, "case-insensitive matching authority and host MUST succeed");
    };
}

// ----------------------------------------------------------------------------
// 6. HTTP/2 Connection Frame Coordinator Trailer END_STREAM Enforcement
// ----------------------------------------------------------------------------
fn test_h2_connection_trailers_end_stream_requirement(t: core::T&) {
    t.run("H2 ingress: second HEADERS frame on stream MUST have FLAG_END_STREAM") { sub =>
        var conn = wing::new_h2_connection(0);

        // 1. Initial HEADERS frame on stream 1 (without END_STREAM) -> opens stream
        let h_initial = wing::FrameHeader {
            length: 16,
            frame_type: wing::FRAME_HEADERS,
            flags: wing::FLAG_END_HEADERS, // no END_STREAM
            stream_id: 1,
        };
        let err1 = wing::on_ingress_frame_header(conn, h_initial, 0);
        sub.assert_eq(err1, wing::ERR_NO_ERROR, "initial HEADERS frame accepted");

        // 2. Second HEADERS frame on stream 1 WITHOUT FLAG_END_STREAM (non-final trailers)
        // Per RFC 9113 §8.1: A HEADERS frame for trailers MUST carry FLAG_END_STREAM.
        let h_second_bad = wing::FrameHeader {
            length: 8,
            frame_type: wing::FRAME_HEADERS,
            flags: wing::FLAG_END_HEADERS, // no END_STREAM!
            stream_id: 1,
        };
        let err2 = wing::on_ingress_frame_header(conn, h_second_bad, 0);
        sub.assert_eq(err2, wing::ERR_PROTOCOL_ERROR, "second HEADERS without END_STREAM MUST trigger PROTOCOL_ERROR");
    };

    t.run("H2 ingress: valid trailers accepted, third HEADERS rejected") { sub =>
        var conn = wing::new_h2_connection(0);

        let h_initial = wing::FrameHeader {
            length: 16,
            frame_type: wing::FRAME_HEADERS,
            flags: wing::FLAG_END_HEADERS,
            stream_id: 1,
        };
        wing::on_ingress_frame_header(conn, h_initial, 0);

        // Valid trailer frame with END_STREAM
        let h_trailers = wing::FrameHeader {
            length: 8,
            frame_type: wing::FRAME_HEADERS,
            flags: wing::FLAG_END_HEADERS | wing::FLAG_END_STREAM,
            stream_id: 1,
        };
        let err_tr = wing::on_ingress_frame_header(conn, h_trailers, 0);
        sub.assert_eq(err_tr, wing::ERR_NO_ERROR, "valid trailers with END_STREAM accepted");

        // Third HEADERS frame after trailers received MUST be rejected
        let h_third = wing::FrameHeader {
            length: 8,
            frame_type: wing::FRAME_HEADERS,
            flags: wing::FLAG_END_HEADERS | wing::FLAG_END_STREAM,
            stream_id: 1,
        };
        let err3 = wing::on_ingress_frame_header(conn, h_third, 0);
        sub.assert_true(err3 == wing::ERR_STREAM_CLOSED || err3 == wing::ERR_PROTOCOL_ERROR, "third HEADERS after trailers rejected");
    };
}

// ----------------------------------------------------------------------------
// 7. CORS Wildcard Origin Authority Smuggling & CSRF Userinfo Spoofing
// ----------------------------------------------------------------------------
fn test_cors_wildcard_origin_smuggling_and_csrf_userinfo(t: core::T&) {
    t.run("match_cors_origin_pattern: reject path/query/userinfo suffix confusion") { sub =>
        let pattern = "https://*.example.com";

        // Path suffix confusion: evil.com/.example.com
        let res_path = wing::match_cors_origin_pattern("https://evil.com/.example.com", pattern);
        sub.assert_false(res_path, "evil.com/.example.com MUST NOT match *.example.com");

        // Query suffix confusion: evil.com?.example.com
        let res_query = wing::match_cors_origin_pattern("https://evil.com?.example.com", pattern);
        sub.assert_false(res_query, "evil.com?.example.com MUST NOT match *.example.com");

        // Hash suffix confusion: evil.com#.example.com
        let res_hash = wing::match_cors_origin_pattern("https://evil.com#.example.com", pattern);
        sub.assert_false(res_hash, "evil.com#.example.com MUST NOT match *.example.com");

        // Userinfo suffix confusion: evil.com@.example.com
        let res_user = wing::match_cors_origin_pattern("https://evil.com@.example.com", pattern);
        sub.assert_false(res_user, "evil.com@.example.com MUST NOT match *.example.com");

        // Empty subdomain: .example.com
        let res_dot = wing::match_cors_origin_pattern("https://.example.com", pattern);
        sub.assert_false(res_dot, ".example.com MUST NOT match *.example.com");

        // Consecutive dots: sub..example.com
        let res_ddot = wing::match_cors_origin_pattern("https://sub..example.com", pattern);
        sub.assert_false(res_ddot, "sub..example.com MUST NOT match *.example.com");

        // Valid subdomain match
        let res_valid = wing::match_cors_origin_pattern("https://api.example.com", pattern);
        sub.assert_true(res_valid, "valid subdomain api.example.com matches *.example.com");
    };

    t.run("extract_host_from_url: reject userinfo spoofing in Origin/Referer") { sub =>
        // Attacker sends Origin/Referer with target host in userinfo:
        // https://example.com@evil.com/path
        // If userinfo is not stripped or rejected, host comparison might be confused
        let spoofed = "https://example.com@evil.com/path";
        let host = wing::extract_host_from_url(spoofed);
        sub.assert_eq(host.len, 0, "URL with userinfo @ MUST return empty host to reject spoofing");

        let valid_url = "https://valid.example.com:8080/path";
        let valid_host = wing::extract_host_from_url(valid_url);
        sub.assert_bytes_eq(valid_host, "valid.example.com:8080", "valid host extracted");
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

// --- Component: regress_issues_batch18 ---
// Phase 18 RED test suite: Reducing Load, DoS Mitigation, RFC Conformance,
// and Protocol Invariants.
//
// 1. HTTP/3 Server Request Trailers Invariants (RFC 9114 §4.3)
// 2. HTTP/3 Empty DATA Frame Flooding Defense (CVE-2019-9518, RFC 9114 §10.5)
// 3. X.509 Basic Constraints Negative or Non-CA PathLen Defense (RFC 5280 §4.2.1.9, OpenSSL #32374)
// 4. X.509 Name Constraints Subtree Base dNSName Validation (RFC 5280 §4.2.1.10, OpenSSL #31686)

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

// --- Component: regress_issues_batch19 ---
// Phase 19 RED test suite: Reducing Load, DoS Mitigation, RFC Conformance,
// and Protocol Invariants.
//
// 1. Chunk Extension Length Overhead Defense in ChunkFsmDecoder (CVE-2023-39326, Go #64433, RFC 9112 §7.1.1)
// 2. Chunk Trailer Length & Memory Flood Defense in ChunkFsmDecoder (CVE-2023-39326, RFC 9112 §7.1.2)
// 3. TLS 1.3 Cookie Extension Length Validation (RFC 8446 §4.2.2, OpenSSL #30868)
// 4. TLS 1.3 CertificateRequest certificate_authorities Extension Vector Validation (RFC 8446 §4.2.4, OpenSSL #32211)
// 5. Cookie Ingestion Quota Enforcement in Netscape Import (Go #75672, CVE-2025-58186)

// ----------------------------------------------------------------------------
// 1. Chunk Extension Length Overhead Defense (CVE-2023-39326, Go #64433)
// ----------------------------------------------------------------------------
fn test_chunk_fsm_extension_length_defense(t: core::T&) {
    t.run("ChunkFsmDecoder rejects chunk extension exceeding 1024 bytes") { sub =>
        var dec = internal::new_chunk_fsm_decoder();

        // Build chunk header with extension > 1024 bytes: "5;ext=" + 1025 'a's + "\r\nhello\r\n0\r\n\r\n"
        var raw: u8[>..] = [];
        raw.append("5;ext=");
        for _ in 1025 {
            raw.push('a');
        }
        raw.append("\r\nhello\r\n0\r\n\r\n");

        let st, consumed, _ = internal::chunk_fsm_feed(dec, raw[..]);
        sub.assert_eq(st, internal::ChunkFsmStatus.Error, "Oversized chunk extension must trigger Error");
        sub.assert_eq(dec.state, internal::CHUNK_STATE_IS_ERROR, "FSM state must transition to sticky Error");
    };

    t.run("ChunkFsmDecoder accepts valid chunk extension <= 1024 bytes") { sub =>
        var dec = internal::new_chunk_fsm_decoder();
        let raw = "5;ext=valid\r\nhello\r\n0\r\n\r\n";
        let st, consumed, chunk = internal::chunk_fsm_feed(dec, raw);
        sub.assert_eq(st, internal::ChunkFsmStatus.YieldChunk, "Valid chunk extension accepted");
        sub.assert_bytes_eq(chunk, "hello", "Chunk payload yielded correctly");
    };
}

// ----------------------------------------------------------------------------
// 2. Chunk Trailer Length & Memory Flood Defense (CVE-2023-39326, RFC 9112 §7.1.2)
// ----------------------------------------------------------------------------
fn test_chunk_fsm_trailer_flood_defense(t: core::T&) {
    t.run("ChunkFsmDecoder rejects total trailer bytes exceeding 4096 bytes") { sub =>
        var dec = internal::new_chunk_fsm_decoder();

        // Stream final chunk "0\r\n", followed by oversized trailer line > 4096 bytes
        var raw: u8[>..] = [];
        raw.append("0\r\nX-Trailer: ");
        for _ in 4100 {
            raw.push('b');
        }
        raw.append("\r\n\r\n");

        let st, consumed, _ = internal::chunk_fsm_feed(dec, raw[..]);
        sub.assert_eq(st, internal::ChunkFsmStatus.Error, "Oversized trailers > 4096 bytes must trigger Error");
        sub.assert_eq(dec.state, internal::CHUNK_STATE_IS_ERROR, "FSM state must transition to sticky Error");
    };

    t.run("ChunkFsmDecoder accepts legitimate trailers <= 4096 bytes") { sub =>
        var dec = internal::new_chunk_fsm_decoder();
        let raw = "0\r\nX-Checksum: deadbeef\r\n\r\n";
        let st, consumed, _ = internal::chunk_fsm_feed(dec, raw);
        sub.assert_eq(st, internal::ChunkFsmStatus.Complete, "Legitimate trailers succeed with Complete");
    };
}

// ----------------------------------------------------------------------------
// 3. TLS 1.3 Cookie Extension Length Validation (RFC 8446 §4.2.2, OpenSSL #30868)
// ----------------------------------------------------------------------------
fn test_tls13_cookie_extension_validation(t: core::T&) {
    t.run("Cookie extension with zero-length vector (empty) MUST be rejected") { sub =>
        // cookie<1..2^16-1>: vector length 0 is strictly forbidden by RFC 8446 Section 4.2.2
        let empty_cookie: u8[2] = [0x00, 0x00];
        var out: u8[..64] = [];
        let ok = wing::parse_tls_cookie_extension(empty_cookie[..], out);
        sub.assert_false(ok, "Zero-length cookie vector must be rejected");
    };

    t.run("Cookie extension with truncated payload MUST be rejected") { sub =>
        // Advertises 4 bytes but only 2 present
        let trunc_cookie: u8[4] = [0x00, 0x04, 0xAA, 0xBB];
        var out: u8[..64] = [];
        let ok = wing::parse_tls_cookie_extension(trunc_cookie[..], out);
        sub.assert_false(ok, "Truncated cookie payload must be rejected");
    };

    t.run("Cookie extension with trailing bytes MUST be rejected") { sub =>
        // Advertises 2 bytes but 3 bytes present in extension
        let trailing_cookie: u8[5] = [0x00, 0x02, 0xAA, 0xBB, 0xFF];
        var out: u8[..64] = [];
        let ok = wing::parse_tls_cookie_extension(trailing_cookie[..], out);
        sub.assert_false(ok, "Trailing bytes after cookie vector must be rejected");
    };

    t.run("Valid Cookie extension succeeds") { sub =>
        let valid_cookie: u8[6] = [0x00, 0x04, 0x01, 0x02, 0x03, 0x04];
        var out: u8[..64] = [];
        let ok = wing::parse_tls_cookie_extension(valid_cookie[..], out);
        sub.assert_true(ok, "Valid cookie extension parsed successfully");
        sub.assert_eq(out.len, 4, "Extracted 4-byte cookie");
        let expected: u8[4] = [0x01, 0x02, 0x03, 0x04];
        sub.assert_bytes_eq(out[..], expected[..], "Cookie contents match");
    };
}

// ----------------------------------------------------------------------------
// 4. TLS 1.3 CertificateRequest certificate_authorities Extension (RFC 8446 §4.2.4, OpenSSL #32211)
// ----------------------------------------------------------------------------
fn test_tls13_cert_authorities_extension_validation(t: core::T&) {
    t.run("certificate_authorities extension with empty vector (< 3 bytes) MUST be rejected") { sub =>
        // authorities<3..2^16-1>: length 0 is strictly forbidden by RFC 8446 Section 4.2.4
        let empty_ca: u8[2] = [0x00, 0x00];
        let ok = wing::validate_certificate_authorities_extension(empty_ca[..]);
        sub.assert_false(ok, "Empty authorities vector must be rejected");
    };

    t.run("certificate_authorities extension with vector length < 3 MUST be rejected") { sub =>
        // authorities vector length 2 (less than lower bound 3)
        let short_ca: u8[4] = [0x00, 0x02, 0x00, 0x00];
        let ok = wing::validate_certificate_authorities_extension(short_ca[..]);
        sub.assert_false(ok, "Authorities vector length < 3 must be rejected");
    };

    t.run("certificate_authorities extension with valid DN succeeds") { sub =>
        // authorities vector length = 5: one DN with length = 3 ("ABC")
        let valid_ca: u8[7] = [0x00, 0x05, 0x00, 0x03, 'A', 'B', 'C'];
        let ok = wing::validate_certificate_authorities_extension(valid_ca[..]);
        sub.assert_true(ok, "Valid authorities vector accepted");
    };

    t.run("CertificateRequest message with empty certificate_authorities MUST be rejected") { sub =>
        // Build CertificateRequest:
        // context_length: 0 (1B)
        // extensions_length: 6 (2B)
        // [ext 47 (2B: 0x00, 0x2F), ext_len 2 (2B: 0x00, 0x02), authorities_len 0 (2B: 0x00, 0x00)]
        // + signature_algorithms (type 13, len 4: list_len 2, ecdsa_secp256r1_sha256 0x0403)
        var msg: u8[..64] = [];
        msg.push(0x00); // context len 0
        // extensions length: 6 (CA) + 8 (sig_algs) = 14 (0x00, 0x0E)
        msg.push(0x00); msg.push(0x0E);
        // EXT_CERTIFICATE_AUTHORITIES (47 = 0x002F), ext_data_len 2, authorities_len 0
        msg.push(0x00); msg.push(0x2F);
        msg.push(0x00); msg.push(0x02);
        msg.push(0x00); msg.push(0x00); // EMPTY authorities vector!
        // EXT_SIGNATURE_ALGORITHMS (13 = 0x000D), ext_data_len 4, list_len 2, 0x0403
        msg.push(0x00); msg.push(0x0D);
        msg.push(0x00); msg.push(0x04);
        msg.push(0x00); msg.push(0x02);
        msg.push(0x04); msg.push(0x03);

        var parsed = wing::CertificateRequestMsg { .. };
        let ok = wing::parse_certificate_request(msg[..], false, parsed);
        sub.assert_false(ok, "CertificateRequest with empty certificate_authorities MUST be rejected");
    };
}

// ----------------------------------------------------------------------------
// 5. Cookie Ingestion Quota Enforcement in Netscape Import (Go #75672, CVE-2025-58186)
// ----------------------------------------------------------------------------
fn test_cookie_import_cap_defense(t: core::T&) {
    t.run("import_netscape caps cookies at K_MAX_COOKIES to prevent memory/CPU exhaustion") { sub =>
        var jar = wing::CanonicalCookieJar { .. };

        // Generate 3500 valid Netscape cookie lines:
        // domain \t flag \t path \t secure \t expiration \t name \t value \n
        var content: u8[>..] = [];
        for i in 3500 {
            content.append("example.com\tTRUE\t/\tFALSE\t2000000000\tc");
            var num_buf: u8[..16] = [];
            core::format_i64_dec(i, num_buf);
            content.append(num_buf[..]);
            content.append("\tv\n");
        }

        let imported = wing::import_netscape(jar, content[..], 1000000);
        sub.assert_true(imported <= 3300, "Imported cookies must not exceed K_MAX_COOKIES ceiling (3300)");
        sub.assert_true(imported >= 3000, "Should import up to capacity");
    };
}

// ----------------------------------------------------------------------------
// Test Runner
// ----------------------------------------------------------------------------

// --- Component: regress_go_stress ---
// Regression and stress tests for Go issue tracker / CVE vulnerabilities

fn test_chunked_cve_2019_16276(t: core::T&) {
    // Space before colon in trailers must be rejected
    var wire: u8[..64] = [];
    wire.append("Content-Length : 100\r\n\r\n");
    var out_trailers: wing::HeaderItem[..16] = [];
    var cursor: i64 = 0;
    let err = wing::parse_chunked_trailers_with_out(wire[..], cursor, out_trailers);
    t.assert_true(err != wing::ChunkedDecodeError.None, "Space before colon in trailer must fail per CVE-2019-16276");

    // Negative / overflow chunk size
    var bad_chunk: u8[..64] = [];
    bad_chunk.append("FFFFFFFFFFFFFFFF\r\n");
    var out_body: u8[>..] = [];
    var trailers: wing::HeaderItem[..16] = [];
    let b_err, b_consumed = wing::decode_chunked_body_with_trailers(bad_chunk[..], out_body, trailers);
    t.assert_true(b_err != wing::ChunkedDecodeError.None, "Overflow chunk size FFFFFFFFFFFFFFFF must be rejected");
}

fn test_dns_name_length_overflow(t: core::T&) {
    // Malformed pointer chain pointing beyond end of packet
    let bad_dns: u8[12] = [
        0x00, 0x01, 0x81, 0x80,
        0x00, 0x01, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
    ];
    var resp = wing::DnsResponse {};
    let ok = wing::parse_dns_response(bad_dns[..], resp);
    t.assert_false(ok, "Truncated DNS packet must return false without panic");
}

fn test_websocket_length_overflow(t: core::T&) {
    // Header with extended payload length 0x7FFFFFFFFFFFFFFF
    let bad_ws_hdr: u8[10] = [
        0x81, 0x7F,
        0x7F, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    ];
    var session = wing::new_websocket_session(true);
    session.max_payload_length = 0;
    var msg = wing::WsMessage {};
    var reply: u8[..64] = [];
    let ok = wing::receive(session, bad_ws_hdr[..], msg, reply);
    t.assert_false(ok, "Huge 64-bit length frame without wire bytes must return false without overflow");

    // Close frame with illegal 1-byte payload must close with PROTOCOL_ERROR
    let bad_close: u8[3] = [0x88, 0x01, 0x00];
    var session2 = wing::new_websocket_session(false);
    var msg2 = wing::WsMessage {};
    var reply2: u8[..64] = [];
    let ok2 = wing::receive(session2, bad_close[..], msg2, reply2);
    t.assert_true(ok2 && session2.is_closed && session2.close_code == wing::WS_STATUS_PROTOCOL_ERROR, "Close frame with 1-byte payload must trigger WS_STATUS_PROTOCOL_ERROR");
}

fn test_proxy_protocol_overflow(t: core::T&) {
    // PROXY v1 with >8 space-separated tokens
    let bad_line: const u8[:] = "PROXY TCP4 1.1.1.1 2.2.2.2 80 80 EXTRA1 EXTRA2 EXTRA3 EXTRA4\r\n";
    let hdr, consumed, ok = wing::parse_proxy_v1(bad_line);
    t.assert_false(ok, "PROXY v1 with >8 tokens must fail safely without buffer overflow");
}

fn test_masque_address_capsule_bounds(t: core::T&) {
    // Address capsule with oversized IP bytes (>16 bytes)
    var payload: u8[..32] = [];
    payload.push(1);  // request_id = 1
    payload.push(4);  // ip_version = 4
    payload.push(32); // prefix_len = 32
    for i in 20 { payload.push(0xAA); } // 20 bytes (> 16 cap)

    let req, ok = wing::decode_address_request_capsule(payload[..]);
    t.assert_false(ok, "Address request capsule with >16 IP bytes must fail without panic");
}

fn test_jwt_exp_overflow(t: core::T&) {
    var claims = wing::JwtClaims { .. };
    // Expiry near i64::MAX
    wing::set_expiry(claims, 9223372036854775800);
    var opts = wing::JwtValidationOptions {};
    opts.leeway_seconds = 60;
    // Current time 1000 should NOT consider this expired despite addition overflow
    let err = wing::validate_jwt_claims_rules(claims, opts, 1000);
    t.assert_eq(err, wing::JwtError.None, "Far future exp must not overflow to expired");
}

fn test_quic_ack_underflow(t: core::T&) {
    var ack = wing::AckFrame {};
    ack.largest_acked = 10;
    ack.first_ack_range = 10;
    // Malicious huge gap that would wrap around in gap + 2
    ack.ranges.push(wing::AckRange { gap: 0xFFFFFFFFFFFFFFFF, ack_range: 0 });

    var space = wing::PnSpaceState {};
    space.has_sent_packets = true;
    space.largest_sent_pn = 100;
    var out_intervals: wing::AckInterval[..64] = [];

    let ok = wing::parse_and_validate_ack(space, ack, out_intervals);
    t.assert_false(ok, "Huge gap wrapping in gap + 2 must be safely rejected");
}

fn test_x509_san_tld_wildcard(t: core::T&) {
    // TLD wildcard *.com must NOT match evil.com (RFC 6125 §6.4.3)
    t.assert_false(wing::match_dns_san("*.com", "evil.com"), "*.com must not match evil.com");
    // Valid wildcard *.example.com must match sub.example.com
    t.assert_true(wing::match_dns_san("*.example.com", "sub.example.com"), "*.example.com matches sub.example.com");
    // Wildcard must not match IPv4
    t.assert_false(wing::match_dns_san("*.168.1.1", "192.168.1.1"), "Wildcard must not match IPv4 literal");
}

fn test_ipv6_mapped_ipv4_ssrf_cve_2024_24790(t: core::T&) {
    // CVE-2024-24790: IPv4-mapped IPv6 loopback & private addresses must be detected
    t.assert_true(wing::is_private_or_reserved_ip("::ffff:127.0.0.1"), "::ffff:127.0.0.1 must be private");
    t.assert_true(wing::is_private_or_reserved_ip("0:0:0:0:0:ffff:10.0.0.1"), "0:0:0:0:0:ffff:10.0.0.1 must be private");
    t.assert_true(wing::is_private_or_reserved_ip("::ffff:192.168.1.1"), "::ffff:192.168.1.1 must be private");
    t.assert_true(wing::is_private_or_reserved_ip("::ffff:169.254.169.254"), "::ffff:169.254.169.254 must be private");
    // Public IP must not be flagged
    t.assert_false(wing::is_private_or_reserved_ip("::ffff:8.8.8.8"), "::ffff:8.8.8.8 is public");
}

fn test_connect_tunnel_rejection_cve_2026_56866(t: core::T&) {
    // CVE-2026-56866: Failed or rejected CONNECT responses must poison/close connection
    t.assert_true(wing::should_close_connection_on_connect_error(wing::ConnectTunnelError.ProxyAuthRequired), "407 must close");
    t.assert_true(wing::should_close_connection_on_connect_error(wing::ConnectTunnelError.ConnectFailed), "Failed connect must close");
    t.assert_false(wing::should_close_connection_on_connect_error(wing::ConnectTunnelError.None), "Success connect must not close");
}

fn test_http2_initial_window_flood_cve_2026_78669(t: core::T&) {
    // CVE-2026-78669: Excessive SETTINGS INITIAL_WINDOW_SIZE changes must be throttled
    var conn = wing::new_h2_connection(1000);
    for i in 16 {
        let err = wing::apply_peer_initial_window_size_delta(conn, (65535 + (i % 2)) as u32);
        t.assert_eq(err, wing::ERR_NO_ERROR, "Initial updates <= 16 must succeed");
    }
    let flood_err = wing::apply_peer_initial_window_size_delta(conn, 65536);
    t.assert_eq(flood_err, wing::ERR_ENHANCE_YOUR_CALM, "17th window change must return ERR_ENHANCE_YOUR_CALM");
}

fn test_query_param_limit_cve_2026_39825(t: core::T&) {
    // CVE-2026-39825: Query parameter count limiter
    let normal_query: const u8[:] = "user=alice&action=login&lang=en";
    t.assert_true(core::validate_query_param_count(normal_query, 5), "Normal query <= 5 passes");

    var flood_query: u8[..128] = [];
    for i in 10 {
        flood_query.append("p=1&");
    }
    t.assert_false(core::validate_query_param_count(flood_query[..], 5), "Flooded query > 5 must fail");
}

fn test_punycode_validation_cve_2026_39821_and_97044(t: core::T&) {
    // CVE-2026-39821: Pure ASCII Punycode label (e.g. xn--test-) must be rejected
    t.assert_false(wing::validate_punycode_label("xn--test-"), "Pure ASCII xn--test- must be rejected");
    t.assert_true(wing::validate_punycode_label("xn--fsqu00a"), "Valid Punycode label must pass");

    // CVE-2026-97044: IDNA domain bounds validation
    t.assert_true(wing::validate_idna_domain_bounds("example.com"), "Standard domain passes");
    t.assert_false(wing::validate_idna_domain_bounds("xn--test-.com"), "Domain with pure ASCII Punycode rejected");
}

fn test_x509_uri_zone_id_cve_2024_45341(t: core::T&) {
    // CVE-2024-45341: IPv6 zone IDs in URI SAN must not bypass name constraints
    t.assert_true(wing::match_uri_san("example.com", "example.com"), "Identical URI SAN matches");
    t.assert_false(wing::match_uri_san("fe80::1%eth0", "fe80::1%eth0"), "Zone ID in URI SAN must be rejected");
}

fn test_error_sanitization_cve_2026_42507(t: core::T&) {
    // CVE-2026-42507: Unescaped inputs in errors must be sanitized against CRLF injection
    let untrusted: const u8[:] = "Bad\r\nSet-Cookie: evil\x00";
    var clean_buf: u8[..64] = [];
    wing::sanitize_untrusted_for_error(untrusted, clean_buf);
    t.assert_false(core::contains_byte(clean_buf[..], '\r'), "CR must be removed/replaced");
    t.assert_false(core::contains_byte(clean_buf[..], '\n'), "LF must be removed/replaced");
    t.assert_false(core::contains_byte(clean_buf[..], 0), "NUL must be removed/replaced");
}

fn main() {
    var runner = core::new_runner("Issue Regression Suite Batch 4 (Phases 16-19 & Stress)", core::Verbosity.Verbose);

    core::run_case(runner, "1. X.509 URI Name Constraints Evasion via @ in Path/Query & ?/# Suffix", test_x509_uri_name_constraints_evasion);
    core::run_case(runner, "2. HTTP/1.1 Wire Response Parser 204/304/1xx Chunked Desync & Header Block Cap", test_http1_wire_response_204_304_1xx_framing);
    core::run_case(runner, "3. HTTP/1.1 Response Serializer Empty-Status Chunked Bodyless Enforcement", test_http1_response_serialization_empty_status);
    core::run_case(runner, "4. HTTP/3 Stream Data Host vs :authority Conflict & Host Syntax", test_h3_host_authority_conflict_and_syntax);
    core::run_case(runner, "5. HTTP/2 HPACK Host Syntax & Case-Insensitive Authority Equivalence", test_h2_hpack_host_authority_validation);
    core::run_case(runner, "6. HTTP/2 Connection Frame Coordinator Trailer END_STREAM Enforcement", test_h2_connection_trailers_end_stream_requirement);
    core::run_case(runner, "7. CORS Wildcard Origin Authority Smuggling & CSRF Userinfo Spoofing", test_cors_wildcard_origin_smuggling_and_csrf_userinfo);
    core::run_case(runner, "8. HTTP/3 DATA Frame Rejection on Bodyless Status Codes (204, 304, 1xx)", test_h3_bodyless_status_data_rejection);
    core::run_case(runner, "9. HTTP/3 Prohibited Trailer Framing Headers & QPACK NUL/CR/LF Injection", test_h3_prohibited_trailers_and_qpack_nul_rejection);
    core::run_case(runner, "10. HTTP/2 :status Pseudo-Header Validation & 101 Prohibition", test_h2_status_pseudo_header_validation);
    core::run_case(runner, "11. HTTP/2 DATA Frame Rejection on Streams with Trailers Received", test_h2_data_frame_after_trailers_rejection);
    core::run_case(runner, "12. X.509 DNS Name Constraints Wildcard & Empty/Leading Dot Validation", test_x509_dns_name_constraint_wildcard_and_empty_labels);
    core::run_case(runner, "13. X.509 ASN.1 Time Parsing Bounds & Overflow Defense", test_x509_asn1_time_parsing_bounds);
    core::run_case(runner, "14. HTTP/3 Server Request Trailers Invariants", test_h3_server_request_trailers_invariants);
    core::run_case(runner, "15. HTTP/3 Empty DATA Frame Flooding Defense", test_h3_empty_frame_flooding);
    core::run_case(runner, "16. X.509 Basic Constraints Negative or Non-CA PathLen Defense", test_x509_basic_constraints_negative_or_non_ca_pathlen);
    core::run_case(runner, "17. X.509 Name Constraints Subtree Base dNSName Validation", test_x509_name_constraints_subtree_dns_nul);
    core::run_case(runner, "18. Chunk Extension Length Overhead Defense", test_chunk_fsm_extension_length_defense);
    core::run_case(runner, "19. Chunk Trailer Length Flood Defense", test_chunk_fsm_trailer_flood_defense);
    core::run_case(runner, "20. TLS 1.3 Cookie Extension Length Validation", test_tls13_cookie_extension_validation);
    core::run_case(runner, "21. TLS 1.3 CertificateRequest certificate_authorities Extension", test_tls13_cert_authorities_extension_validation);
    core::run_case(runner, "22. Cookie Ingestion Quota Enforcement in Netscape Import", test_cookie_import_cap_defense);
    core::run_case(runner, "23. CVE-2019-16276 Space-before-colon & Chunk Size Overflow", test_chunked_cve_2019_16276);
    core::run_case(runner, "24. DNS Name Decoding Length Overflow", test_dns_name_length_overflow);
    core::run_case(runner, "25. WebSocket Extended Length & Close Frame Invariants", test_websocket_length_overflow);
    core::run_case(runner, "26. PROXY Protocol v1 Token Capacity Guard", test_proxy_protocol_overflow);
    core::run_case(runner, "27. MASQUE Address Request Capsule Bounds", test_masque_address_capsule_bounds);
    core::run_case(runner, "28. JWT Expiry Integer Overflow Defense", test_jwt_exp_overflow);
    core::run_case(runner, "29. QUIC ACK Frame Gap Addition Overflow Defense", test_quic_ack_underflow);
    core::run_case(runner, "30. X.509 DNS SAN TLD Wildcard & IP Literal Defense", test_x509_san_tld_wildcard);
    core::run_case(runner, "31. CVE-2024-24790 IPv4-Mapped IPv6 SSRF Filter Defense", test_ipv6_mapped_ipv4_ssrf_cve_2024_24790);
    core::run_case(runner, "32. CVE-2026-56866 Client CONNECT Tunnel Rejection Poisoning", test_connect_tunnel_rejection_cve_2026_56866);
    core::run_case(runner, "33. CVE-2026-78669 HTTP/2 Initial Window Size Flood Defense", test_http2_initial_window_flood_cve_2026_78669);
    core::run_case(runner, "34. CVE-2026-39825 URL Query Parameter Flooding Limit", test_query_param_limit_cve_2026_39825);
    core::run_case(runner, "35. CVE-2026-39821 & CVE-2026-97044 Punycode & IDNA Bounds", test_punycode_validation_cve_2026_39821_and_97044);
    core::run_case(runner, "36. CVE-2024-45341 X.509 URI SAN Zone ID Rejection", test_x509_uri_zone_id_cve_2024_45341);
    core::run_case(runner, "37. CVE-2026-42507 Error Message Untrusted Input Sanitization", test_error_sanitization_cve_2026_42507);

    let ok = core::finish(runner);
    assert(ok);
}
