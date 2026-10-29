// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

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

import std;
import core from "..";
import wing from "..";

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
        var res_204 = wing::new_response();
        let ok_204, consumed_204 = wing::parse_http1_wire_response(wire_204, res_204);
        sub.assert_true(ok_204, "204 with Transfer-Encoding: chunked MUST succeed");
        sub.assert_eq(consumed_204, wire_204.len, "consumed exact header bytes");
        sub.assert_eq(res_204.status_code, 204, "status code is 204");
        sub.assert_eq(res_204.body.len, 0, "body must be empty for 204");

        let wire_304 = "HTTP/1.1 304 Not Modified\r\nTransfer-Encoding: chunked\r\n\r\n";
        var res_304 = wing::new_response();
        let ok_304, consumed_304 = wing::parse_http1_wire_response(wire_304, res_304);
        sub.assert_true(ok_304, "304 with Transfer-Encoding: chunked MUST succeed");
        sub.assert_eq(consumed_304, wire_304.len, "consumed exact header bytes");
        sub.assert_eq(res_304.status_code, 304, "status code is 304");
        sub.assert_eq(res_304.body.len, 0, "body must be empty for 304");

        let wire_100 = "HTTP/1.1 100 Continue\r\nTransfer-Encoding: chunked\r\n\r\n";
        var res_100 = wing::new_response();
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

        var res = wing::new_response();
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
        var res_204 = wing::new_response();
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
        var res_304 = wing::new_response();
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
        var res_100 = wing::new_response();
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
fn main() {
    var runner = core::new_runner("Phase 16: RFC Invariants & Smuggling Defenses Suite", core::Verbosity.Verbose);

    core::run_case(runner, "1. X.509 URI Name Constraints Evasion via @ in Path/Query & ?/# Suffix", test_x509_uri_name_constraints_evasion);
    core::run_case(runner, "2. HTTP/1.1 Wire Response Parser 204/304/1xx Chunked Desync & Header Block Cap", test_http1_wire_response_204_304_1xx_framing);
    core::run_case(runner, "3. HTTP/1.1 Response Serializer Empty-Status Chunked Bodyless Enforcement", test_http1_response_serialization_empty_status);
    core::run_case(runner, "4. HTTP/3 Stream Data Host vs :authority Conflict & Host Syntax", test_h3_host_authority_conflict_and_syntax);
    core::run_case(runner, "5. HTTP/2 HPACK Host Syntax & Case-Insensitive Authority Equivalence", test_h2_hpack_host_authority_validation);
    core::run_case(runner, "6. HTTP/2 Connection Frame Coordinator Trailer END_STREAM Enforcement", test_h2_connection_trailers_end_stream_requirement);
    core::run_case(runner, "7. CORS Wildcard Origin Authority Smuggling & CSRF Userinfo Spoofing", test_cors_wildcard_origin_smuggling_and_csrf_userinfo);

    let ok = core::finish(runner);
    assert(ok);
}
