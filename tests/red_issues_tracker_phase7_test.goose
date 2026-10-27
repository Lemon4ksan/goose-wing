// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Phase 7 RED test suite based on .gemini issue trackers and RFC specifications.
// Verifies protocol flaws, RFC non-conformances, and edge cases that are CURRENTLY UNFIXED in goose-wing.
//
// Issues covered:
// 1. RFC 9113 §6.8 & Go #80759: HTTP/2 GOAWAY Frame Stream ID Invariant (Stream ID MUST Be 0)
// 2. RFC 6265bis §5.4 & Go #82389: Cookie Relative Path Attribute Without Leading Slash Must Not Override Default Path
// 3. RFC 9110 §13.2.1: Cache-Control max-age Arithmetic Overflow Clamping (Saturates to MAX_DELTA_SECONDS)
// 4. RFC 9113 §8.5 & RFC 8441: HTTP/2 Standard CONNECT Request Rejection if :scheme or :path Present
// 5. RFC 6455 §5.5 & Go #7825: WebSocket Control Frame Standalone Empty Ping / Pong Roundtrip
// 6. CVE-2026-42507 & Go #79346: Control Character Sanitization in Diagnostic Error Messages
// 7. RFC 9110 §15.2 & Go #65035: Excessive 1xx Informational Response Limit Defense
// 8. RFC 9113 §8.3.1 & RFC 9110 §7.1: HTTP/2 Asterisk-form :path = '*' ONLY for OPTIONS Method
// 9. RFC 9113 §8.3: HTTP/2 Request and Response Pseudo-Header Segregation (:status vs :method)
// 10. RFC 9113 §8.3.1 & Go #78762: HTTP/2 :authority vs Host Consistency and Duplicate Host Header Rejection
// 11. CVE-2026-94441 & Go #81656: Scheme Isolation in Connection Pool Keys (H2c vs Https)
// 12. RFC 9114 §6.2.1 & Go #78102: Duplicate HTTP/3 Control Stream Rejection (H3_ERR_STREAM_CREATION)
// 13. RFC 9112 §7.1.1 & Go #82257: Chunk Extension with Bad Whitespace Before Semicolon

import std;
import core from "..";
import wing from "..";

// ----------------------------------------------------------------------------
// 1. RFC 9113 §6.8 & Go #80759: HTTP/2 GOAWAY Frame Stream ID Invariant
// ----------------------------------------------------------------------------
fn test_h2_goaway_stream_id_zero(t: core::T&) {
    t.run("GOAWAY frame on stream_id > 0 must return ERR_PROTOCOL_ERROR (RFC 9113 §6.8)") { sub =>
        // RFC 9113 Section 6.8:
        // "GOAWAY frames apply to the connection, not a specific stream, so the stream identifier
        // for a GOAWAY frame MUST be zero (0x00)."
        // "An endpoint MUST treat a GOAWAY frame with a stream identifier other than 0x00
        // as a connection error (Section 5.4.1) of type PROTOCOL_ERROR."
        let bad_hdr = wing::FrameHeader {
            length: 8,
            frame_type: wing::FRAME_GOAWAY,
            flags: 0,
            stream_id: 1, // Invalid: GOAWAY MUST be on stream 0
        };
        let err = wing::validate_frame_header_rules(bad_hdr);
        sub.assert_eq(err, wing::ERR_PROTOCOL_ERROR, "GOAWAY on stream 1 MUST be rejected with PROTOCOL_ERROR (RFC 9113 §6.8)");

        let bad_hdr3 = wing::FrameHeader {
            length: 8,
            frame_type: wing::FRAME_GOAWAY,
            flags: 0,
            stream_id: 3,
        };
        let err3 = wing::validate_frame_header_rules(bad_hdr3);
        sub.assert_eq(err3, wing::ERR_PROTOCOL_ERROR, "GOAWAY on stream 3 MUST be rejected with PROTOCOL_ERROR (RFC 9113 §6.8)");

        let good_hdr = wing::FrameHeader {
            length: 8,
            frame_type: wing::FRAME_GOAWAY,
            flags: 0,
            stream_id: 0,
        };
        let ok_err = wing::validate_frame_header_rules(good_hdr);
        sub.assert_eq(ok_err, wing::ERR_NO_ERROR, "GOAWAY on stream 0 is valid");
    };
}

// ----------------------------------------------------------------------------
// 2. RFC 6265bis §5.4 & Go #82389: Cookie Relative Path Attribute Ignored
// ----------------------------------------------------------------------------
fn test_cookie_relative_path_ignored(t: core::T&) {
    t.run("Cookie Path attribute without leading slash MUST be ignored (RFC 6265bis §5.4)") { sub =>
        // RFC 6265bis Section 5.4:
        // "If the attribute-value is empty or if the first character of the
        // attribute-value is not %x2F ('/'):
        //   Let cookie-path be the default-path.
        // Otherwise:
        //   Let cookie-path be the attribute-value."
        var cookie = wing::CanonicalCookie { .. };
        cookie.path.clear();
        cookie.path.append("/default/api");

        // Relative path "relative/path" lacks leading '/' -> must be ignored!
        wing::apply_parsed_path_attribute(cookie, "relative/path");
        sub.assert_bytes_eq(cookie.path[..], "/default/api", "Relative Path 'relative/path' must be ignored, retaining default path");

        // Relative path "admin" lacks leading '/' -> must be ignored!
        wing::apply_parsed_path_attribute(cookie, "admin");
        sub.assert_bytes_eq(cookie.path[..], "/default/api", "Relative Path 'admin' must be ignored, retaining default path");

        // Absolute path "/valid/path" begins with '/' -> must be applied!
        wing::apply_parsed_path_attribute(cookie, "/valid/path");
        sub.assert_bytes_eq(cookie.path[..], "/valid/path", "Absolute Path '/valid/path' must be applied");
    };
}

// ----------------------------------------------------------------------------
// 3. RFC 9110 §13.2.1: Cache-Control max-age Arithmetic Overflow Clamping
// ----------------------------------------------------------------------------
fn test_cache_control_max_age_overflow_clamping(t: core::T&) {
    t.run("Huge max-age delta-seconds (20+ digits) must saturate to MAX_DELTA_SECONDS without wrapping") { sub =>
        // RFC 9110 Section 13.2.1 & RFC 8941:
        // Delta-seconds directives with huge number of digits must saturate/clamp to MAX_DELTA_SECONDS
        // without 64-bit integer overflow wrap to negative numbers.
        let secs, ok = wing::parse_delta_seconds("99999999999999999999");
        sub.assert_true(ok, "Huge delta-seconds must parse successfully");
        sub.assert_gt(secs, 0, "Huge delta-seconds must be positive (no arithmetic wrap)");
        sub.assert_eq(secs, wing::MAX_DELTA_SECONDS as i32, "Huge delta-seconds must saturate to MAX_DELTA_SECONDS (2147483647)");
    };
}

// ----------------------------------------------------------------------------
// 4. RFC 9113 §8.5 & RFC 8441: HTTP/2 Standard CONNECT Request Rejection if :scheme or :path Present
// ----------------------------------------------------------------------------
fn test_h2_connect_scheme_path_rejection(t: core::T&) {
    t.run("Standard CONNECT with :path present MUST return ERR_PROTOCOL_ERROR (RFC 9113 §8.5)") { sub =>
        // RFC 9113 Section 8.5:
        // "For CONNECT requests, the ':path' and ':scheme' pseudo-header fields MUST be omitted."
        // "A request that includes ':path' or ':scheme' in a CONNECT request (unless using
        // the Extended CONNECT protocol defined in RFC 8441) MUST be treated as malformed."
        var headers = wing::DecodedH2HeaderList { .. };
        let ok_meth = wing::validate_header_ordering_and_rules(headers, ":method", "CONNECT");
        sub.assert_eq(ok_meth, wing::ERR_NO_ERROR, ":method CONNECT accepted");
        headers.fields.push(wing::DecodedH2Header { name: ":method", value: "CONNECT", .. });

        let ok_auth = wing::validate_header_ordering_and_rules(headers, ":authority", "proxy.example.com:443");
        sub.assert_eq(ok_auth, wing::ERR_NO_ERROR, ":authority accepted");
        headers.fields.push(wing::DecodedH2Header { name: ":authority", value: "proxy.example.com:443", .. });

        // Standard CONNECT with :path must be rejected as PROTOCOL_ERROR!
        let err_path = wing::validate_header_ordering_and_rules(headers, ":path", "/");
        sub.assert_eq(err_path, wing::ERR_PROTOCOL_ERROR, "Standard CONNECT with :path MUST return ERR_PROTOCOL_ERROR (RFC 9113 §8.5)");
    };

    t.run("Standard CONNECT with :scheme present MUST return ERR_PROTOCOL_ERROR (RFC 9113 §8.5)") { sub =>
        var headers = wing::DecodedH2HeaderList { .. };
        let ok_meth = wing::validate_header_ordering_and_rules(headers, ":method", "CONNECT");
        sub.assert_eq(ok_meth, wing::ERR_NO_ERROR, ":method CONNECT accepted");
        headers.fields.push(wing::DecodedH2Header { name: ":method", value: "CONNECT", .. });

        let ok_auth = wing::validate_header_ordering_and_rules(headers, ":authority", "proxy.example.com:443");
        sub.assert_eq(ok_auth, wing::ERR_NO_ERROR, ":authority accepted");
        headers.fields.push(wing::DecodedH2Header { name: ":authority", value: "proxy.example.com:443", .. });

        // Standard CONNECT with :scheme must be rejected as PROTOCOL_ERROR!
        let err_scheme = wing::validate_header_ordering_and_rules(headers, ":scheme", "https");
        sub.assert_eq(err_scheme, wing::ERR_PROTOCOL_ERROR, "Standard CONNECT with :scheme MUST return ERR_PROTOCOL_ERROR (RFC 9113 §8.5)");
    };
}

// ----------------------------------------------------------------------------
// 5. RFC 6455 §5.5 & Go #7825: WebSocket Empty Payload Ping / Pong Roundtrip
// ----------------------------------------------------------------------------
fn test_ws_empty_payload_ping_pong(t: core::T&) {
    t.run("WebSocket Ping with 0 payload is accepted and answered with 0-payload Pong") { sub =>
        // RFC 6455 §5.5.2 & §5.5.3 / Go #7825:
        // A Ping frame MAY carry an empty application data payload (0 bytes).
        // The receiver MUST emit a Pong frame with identical 0-byte payload.
        var ws_sess = wing::new_websocket_session(true); // client
        var ping_wire: u8[>..] = [];
        let no_mask: u8[4] = [0, 0, 0, 0];
        wing::encode_ws_frame(ping_wire, wing::WS_OPCODE_PING, "", false, no_mask, true);

        // Frame header must have payload_len = 0
        let hdr, ok_hdr = wing::parse_ws_frame_header(ping_wire[..]);
        sub.assert_true(ok_hdr, "Empty Ping header parsed");
        sub.assert_eq(hdr.opcode, wing::WS_OPCODE_PING, "Opcode is PING");
        sub.assert_eq(hdr.payload_len, 0, "Payload length is 0");

        var msg = wing::WsMessage { .. };
        var pong_reply: u8[>..] = [];
        let handled = ws_sess.receive(ping_wire[..], msg, pong_reply);
        sub.assert_true(handled, "receive processed empty Ping frame");
        sub.assert_eq(msg.opcode, wing::WS_OPCODE_PING, "Message opcode is PING");
        sub.assert_eq(msg.data.len, 0, "Ping message payload is 0 bytes");

        // Outbound Pong response must also be empty payload
        sub.assert_ge(pong_reply.len, 2, "Outbound Pong reply frame emitted");
        let pong_hdr, ok_pong = wing::parse_ws_frame_header(pong_reply[..]);
        sub.assert_true(ok_pong, "Parsed auto-pong frame header");
        sub.assert_eq(pong_hdr.opcode, wing::WS_OPCODE_PONG, "Opcode in auto-reply is PONG");
        sub.assert_eq(pong_hdr.payload_len, 0, "Pong payload length is 0 bytes");
    };
}

// ----------------------------------------------------------------------------
// 6. CVE-2026-42507 & Go #79346: Control Character Sanitization in Diagnostic Error Messages
// ----------------------------------------------------------------------------
fn test_diagnostic_control_character_sanitization(t: core::T&) {
    t.run("Control characters in untrusted tokens MUST be escaped for safe logging") { sub =>
        // CVE-2026-42507 & Go #79346:
        // Untrusted header tokens containing CRLF or control bytes (< 0x20, > 0x7E)
        // must be escaped to prevent log injection and HTTP response splitting.
        var out_clean: u8[..128] = [];
        wing::escape_diagnostic_control_chars("malformed\r\nInjected-Header: evil", out_clean);

        // Result must NOT contain raw \r or \n
        var has_raw_cr = false;
        var has_raw_lf = false;
        for b in out_clean {
            if b == '\r' { has_raw_cr = true; }
            if b == '\n' { has_raw_lf = true; }
        }
        sub.assert_false(has_raw_cr, "Sanitized string MUST NOT contain raw CR");
        sub.assert_false(has_raw_lf, "Sanitized string MUST NOT contain raw LF");
        sub.assert_bytes_eq(out_clean[..], "malformed\\r\\nInjected-Header: evil", "CRLF correctly escaped to \\r\\n");
    };
}

// ----------------------------------------------------------------------------
// 7. RFC 9110 §15.2 & Go #65035: Excessive 1xx Informational Response Limit Defense
// ----------------------------------------------------------------------------
fn test_informational_1xx_response_limit(t: core::T&) {
    t.run("Consecutive 1xx responses exceeding limit MUST be rejected") { sub =>
        // RFC 9110 Section 15.2 & Go #65035:
        // Bound consecutive 1xx informational responses (default limit: 5) to prevent infinite loops.
        sub.assert_true(wing::validate_informational_response_count(1, 5), "1st 1xx response is valid");
        sub.assert_true(wing::validate_informational_response_count(5, 5), "5th 1xx response is valid (at limit)");
        sub.assert_false(wing::validate_informational_response_count(6, 5), "6th 1xx response MUST be rejected (> limit)");
        sub.assert_false(wing::validate_informational_response_count(100, 5), "100th 1xx response MUST be rejected");
    };
}

// ----------------------------------------------------------------------------
// 8. RFC 9113 §8.3.1 & RFC 9110 §7.1: HTTP/2 Asterisk-form :path = "*" ONLY for OPTIONS
// ----------------------------------------------------------------------------
fn test_h2_asterisk_path_only_for_options(t: core::T&) {
    t.run("Asterisk-form :path '*' is valid for OPTIONS method") { sub =>
        var headers = wing::DecodedH2HeaderList { .. };
        let ok_meth = wing::validate_header_ordering_and_rules(headers, ":method", "OPTIONS");
        sub.assert_eq(ok_meth, wing::ERR_NO_ERROR, ":method OPTIONS accepted");
        headers.fields.push(wing::DecodedH2Header { name: ":method", value: "OPTIONS", .. });

        let ok_path = wing::validate_header_ordering_and_rules(headers, ":path", "*");
        sub.assert_eq(ok_path, wing::ERR_NO_ERROR, ":path '*' accepted for OPTIONS");
    };

    t.run("Asterisk-form :path '*' on GET method MUST return ERR_PROTOCOL_ERROR (RFC 9113 §8.3.1)") { sub =>
        var headers = wing::DecodedH2HeaderList { .. };
        let ok_meth = wing::validate_header_ordering_and_rules(headers, ":method", "GET");
        sub.assert_eq(ok_meth, wing::ERR_NO_ERROR, ":method GET accepted");
        headers.fields.push(wing::DecodedH2Header { name: ":method", value: "GET", .. });

        let err_path = wing::validate_header_ordering_and_rules(headers, ":path", "*");
        sub.assert_eq(err_path, wing::ERR_PROTOCOL_ERROR, "GET with :path '*' MUST be rejected with PROTOCOL_ERROR (RFC 9113 §8.3.1)");
    };
}

// ----------------------------------------------------------------------------
// 9. RFC 9113 §8.3: Request and Response Pseudo-Header Segregation
// ----------------------------------------------------------------------------
fn test_h2_pseudo_header_request_response_segregation(t: core::T&) {
    t.run("Response pseudo-header :status in Request header block MUST return ERR_PROTOCOL_ERROR") { sub =>
        var headers = wing::DecodedH2HeaderList { .. };
        let ok_meth = wing::validate_header_ordering_and_rules(headers, ":method", "GET");
        sub.assert_eq(ok_meth, wing::ERR_NO_ERROR, ":method GET accepted");
        headers.fields.push(wing::DecodedH2Header { name: ":method", value: "GET", .. });

        let err_status = wing::validate_header_ordering_and_rules(headers, ":status", "200");
        sub.assert_eq(err_status, wing::ERR_PROTOCOL_ERROR, ":status in request header block MUST return PROTOCOL_ERROR (RFC 9113 §8.3)");
    };

    t.run("Request pseudo-header :method in Response header block MUST return ERR_PROTOCOL_ERROR") { sub =>
        var headers = wing::DecodedH2HeaderList { .. };
        let ok_status = wing::validate_header_ordering_and_rules(headers, ":status", "200");
        sub.assert_eq(ok_status, wing::ERR_NO_ERROR, ":status 200 accepted");
        headers.fields.push(wing::DecodedH2Header { name: ":status", value: "200", .. });

        let err_meth = wing::validate_header_ordering_and_rules(headers, ":method", "GET");
        sub.assert_eq(err_meth, wing::ERR_PROTOCOL_ERROR, ":method in response header block MUST return PROTOCOL_ERROR (RFC 9113 §8.3)");
    };
}

// ----------------------------------------------------------------------------
// 10. RFC 9113 §8.3.1 & Go #78762: HTTP/2 :authority vs Host Consistency and Duplicates
// ----------------------------------------------------------------------------
fn test_h2_authority_host_consistency_and_duplicates(t: core::T&) {
    t.run("Matching :authority and Host headers are accepted") { sub =>
        var headers = wing::DecodedH2HeaderList { .. };
        let ok_auth = wing::validate_header_ordering_and_rules(headers, ":authority", "example.com");
        sub.assert_eq(ok_auth, wing::ERR_NO_ERROR, ":authority accepted");
        headers.fields.push(wing::DecodedH2Header { name: ":authority", value: "example.com", .. });

        let ok_host = wing::validate_header_ordering_and_rules(headers, "host", "example.com");
        sub.assert_eq(ok_host, wing::ERR_NO_ERROR, "Matching Host header accepted");
    };

    t.run("Conflicting :authority and Host headers MUST return ERR_PROTOCOL_ERROR (RFC 9113 §8.3.1)") { sub =>
        var headers = wing::DecodedH2HeaderList { .. };
        let ok_auth = wing::validate_header_ordering_and_rules(headers, ":authority", "example.com");
        sub.assert_eq(ok_auth, wing::ERR_NO_ERROR, ":authority accepted");
        headers.fields.push(wing::DecodedH2Header { name: ":authority", value: "example.com", .. });

        let err_host = wing::validate_header_ordering_and_rules(headers, "host", "attacker.com");
        sub.assert_eq(err_host, wing::ERR_PROTOCOL_ERROR, "Conflicting Host 'attacker.com' MUST return ERR_PROTOCOL_ERROR (RFC 9113 §8.3.1)");
    };

    t.run("Multiple Host headers in HTTP/2 MUST return ERR_PROTOCOL_ERROR (RFC 9113 §8.2.1)") { sub =>
        var headers = wing::DecodedH2HeaderList { .. };
        let ok_host1 = wing::validate_header_ordering_and_rules(headers, "host", "example.com");
        sub.assert_eq(ok_host1, wing::ERR_NO_ERROR, "First Host accepted");
        headers.fields.push(wing::DecodedH2Header { name: "host", value: "example.com", .. });

        let err_host2 = wing::validate_header_ordering_and_rules(headers, "host", "example.com");
        sub.assert_eq(err_host2, wing::ERR_PROTOCOL_ERROR, "Duplicate Host header MUST return ERR_PROTOCOL_ERROR (RFC 9113 §8.2.1)");
    };
}

// ----------------------------------------------------------------------------
// 11. CVE-2026-94441 & Go #81656: Scheme Isolation in Connection Pool Keys
// ----------------------------------------------------------------------------
fn test_h2c_vs_https_connection_pool_isolation(t: core::T&) {
    t.run("Connection pool key for H2c vs Https to same host:port MUST NOT match") { sub =>
        let dummy_proxy = wing::ProxyChain { .. };
        let dummy_part = wing::NetworkAnonymizationKey { .. };
        let dummy_policy = wing::TlsAndDnsPolicy { .. };

        let h2c_key = wing::new_pool_key(
            wing::PoolScheme.H2c,
            "api.internal",
            80,
            dummy_proxy,
            dummy_part,
            dummy_policy,
        );

        let https_key = wing::new_pool_key(
            wing::PoolScheme.Https,
            "api.internal",
            80,
            dummy_proxy,
            dummy_part,
            dummy_policy,
        );

        sub.assert_false(wing::pool_key_equals(h2c_key, https_key), "H2c and Https pool keys MUST NOT be equal");
        sub.assert_ne(wing::pool_key_hash(h2c_key), wing::pool_key_hash(https_key), "H2c and Https pool keys MUST produce different hashes");
    };
}

// ----------------------------------------------------------------------------
// 12. RFC 9114 §6.2.1 & Go #78102: Duplicate HTTP/3 Control Stream Rejection
// ----------------------------------------------------------------------------
fn test_h3_duplicate_control_stream_rejection(t: core::T&) {
    t.run("Second H3_STREAM_CONTROL stream MUST be rejected with H3_ERR_STREAM_CREATION (0x0103)") { sub =>
        let settings = wing::H3Settings { .. };
        var conn = wing::new_h3_client_connection(settings);
        // First control stream: Stream ID 3 (unidirectional), Type 0x00 (H3_STREAM_CONTROL)
        var ctrl1_wire: u8[>..] = [];
        wing::quic_encode_varint(ctrl1_wire, wing::H3_STREAM_CONTROL);
        let err1 = conn.handle_stream_data(3, false, ctrl1_wire[..], false);
        sub.assert_eq(err1, wing::H3_ERR_NO_ERROR, "First control stream accepted");
        sub.assert_true(conn.peer_control_opened, "Peer control opened flag set");

        // Second control stream: Stream ID 7 (unidirectional), Type 0x00
        var ctrl2_wire: u8[>..] = [];
        wing::quic_encode_varint(ctrl2_wire, wing::H3_STREAM_CONTROL);
        let err2 = conn.handle_stream_data(7, false, ctrl2_wire[..], false);
        sub.assert_eq(err2, wing::H3_ERR_STREAM_CREATION, "Duplicate control stream MUST return H3_ERR_STREAM_CREATION (0x0103)");
        sub.assert_eq(conn.state, wing::H3ConnState.Closed, "Connection state transitioned to Closed");
    };
}

// ----------------------------------------------------------------------------
// 13. RFC 9112 §7.1.1 & Go #82257: Chunk Extension with Bad Whitespace Before Semicolon
// ----------------------------------------------------------------------------
fn test_chunked_bws_before_semicolon(t: core::T&) {
    t.run("Chunk extension with space before semicolon parses cleanly (RFC 9112 §7.1.1)") { sub =>
        let wire = "5 ; ext=val\r\nhello\r\n0\r\n\r\n";
        var body: u8[>..] = [];
        let err = wing::decode_chunked_body(wire, body);
        sub.assert_eq(err, wing::ChunkedDecodeError.None, "Chunk extension with BWS before ';' decoded successfully");
        sub.assert_bytes_eq(body[..], "hello", "Decoded chunk data matches expected payload");
    };

    t.run("Chunk extension with tab before semicolon parses cleanly (RFC 9112 §7.1.1)") { sub =>
        let wire = "4\t; ext=token\r\nwing\r\n0\r\n\r\n";
        var body: u8[>..] = [];
        let err = wing::decode_chunked_body(wire, body);
        sub.assert_eq(err, wing::ChunkedDecodeError.None, "Chunk extension with HTAB before ';' decoded successfully");
        sub.assert_bytes_eq(body[..], "wing", "Decoded chunk data matches expected payload");
    };
}

fn main() {
    var runner = core::new_runner("RED Suite Phase 7: Issues Tracker & RFC Invariants", core::Verbosity.Verbose);
    core::run_case(runner, "1. RFC 9113 §6.8 & Go #80759: HTTP/2 GOAWAY Stream ID Invariant", test_h2_goaway_stream_id_zero);
    core::run_case(runner, "2. RFC 6265bis §5.4 & Go #82389: Cookie Relative Path Attribute Ignored", test_cookie_relative_path_ignored);
    core::run_case(runner, "3. RFC 9110 §13.2.1: Cache-Control max-age Arithmetic Overflow Clamping", test_cache_control_max_age_overflow_clamping);
    core::run_case(runner, "4. RFC 9113 §8.5 & RFC 8441: HTTP/2 Standard CONNECT Request Rejection if :scheme or :path Present", test_h2_connect_scheme_path_rejection);
    core::run_case(runner, "5. RFC 6455 §5.5 & Go #7825: WebSocket Empty Payload Ping / Pong Roundtrip", test_ws_empty_payload_ping_pong);
    core::run_case(runner, "6. CVE-2026-42507 & Go #79346: Control Character Sanitization in Diagnostic Error Messages", test_diagnostic_control_character_sanitization);
    core::run_case(runner, "7. RFC 9110 §15.2 & Go #65035: Excessive 1xx Informational Response Limit Defense", test_informational_1xx_response_limit);
    core::run_case(runner, "8. RFC 9113 §8.3.1 & RFC 9110 §7.1: HTTP/2 Asterisk-form :path = '*' ONLY for OPTIONS", test_h2_asterisk_path_only_for_options);
    core::run_case(runner, "9. RFC 9113 §8.3: Request and Response Pseudo-Header Segregation", test_h2_pseudo_header_request_response_segregation);
    core::run_case(runner, "10. RFC 9113 §8.3.1 & Go #78762: HTTP/2 :authority vs Host Consistency and Duplicates", test_h2_authority_host_consistency_and_duplicates);
    core::run_case(runner, "11. CVE-2026-94441 & Go #81656: Scheme Isolation in Connection Pool Keys", test_h2c_vs_https_connection_pool_isolation);
    core::run_case(runner, "12. RFC 9114 §6.2.1 & Go #78102: Duplicate HTTP/3 Control Stream Rejection", test_h3_duplicate_control_stream_rejection);
    core::run_case(runner, "13. RFC 9112 §7.1.1 & Go #82257: Chunk Extension with Bad Whitespace Before Semicolon", test_chunked_bws_before_semicolon);
    let ok = core::finish(runner);
    assert(ok);
}
