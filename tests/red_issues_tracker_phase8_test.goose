// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Phase 8 RED test suite based on .gemini issue trackers and RFC specifications.
// Verifies protocol flaws, RFC non-conformances, and edge cases:
//
// 1. RFC 9113 §6.8 & Go #80759: HTTP/2 GOAWAY Last-Stream-ID Peer Role Invariant
// 2. RFC 9113 §6.8 & Go #82365: HTTP/2 Inbound Stream Rejection After GOAWAY
// 3. RFC 9113 §8.3.1 & Go #77843: HTTP/2 :path Pseudo-Header RFC 3986 Character Validation
// 4. RFC 9113 §8.3 & Go #78775: HTTP/2 Trailer Section Forbidden Pseudo-Headers
// 5. RFC 6455 §4.2.1: WebSocket Upgrade Handshake Missing Host Header Rejection
// 6. RFC 6455 §4.2.2: WebSocket Subprotocol Agreement Verification
// 7. RFC 3986 §4.2 & Go #81292: Relative URL Double-Slash Path Authority Protection

import std;
import core from "..";
import wing from "..";

// ----------------------------------------------------------------------------
// 1. RFC 9113 §6.8 & Go #80759: HTTP/2 GOAWAY Last-Stream-ID Peer Role Invariant
// ----------------------------------------------------------------------------
fn test_h2_goaway_last_stream_id_peer_role(t: core::T&) {
    t.run("Client GOAWAY with odd stream ID sent to Server MUST be rejected with PROTOCOL_ERROR") { sub =>
        // RFC 9113 Section 6.8 & Go #80759:
        // "Since streams initiated by a client have odd stream identifiers and streams initiated
        // by a server have even stream identifiers, the Last-Stream-ID sent by a client MUST be
        // an even stream identifier or zero (streams initiated by the peer)."
        // Client sent stream 1 or 3 -> invalid!
        let valid_client_0 = wing::validate_goaway_last_stream_id(0, true);
        sub.assert_true(valid_client_0, "Client GOAWAY with last_stream_id=0 is valid");

        let valid_client_even = wing::validate_goaway_last_stream_id(2, true);
        sub.assert_true(valid_client_even, "Client GOAWAY with last_stream_id=2 (server stream) is valid");

        let invalid_client_odd1 = wing::validate_goaway_last_stream_id(1, true);
        sub.assert_false(invalid_client_odd1, "Client GOAWAY with last_stream_id=1 MUST be rejected (Go #80759)");

        let invalid_client_odd3 = wing::validate_goaway_last_stream_id(3, true);
        sub.assert_false(invalid_client_odd3, "Client GOAWAY with last_stream_id=3 MUST be rejected (Go #80759)");
    };

    t.run("Server GOAWAY with even stream ID > 0 sent to Client MUST be rejected with PROTOCOL_ERROR") { sub =>
        // Server sent stream 2 or 4 -> invalid! Server can only acknowledge client streams (odd) or 0.
        let valid_server_0 = wing::validate_goaway_last_stream_id(0, false);
        sub.assert_true(valid_server_0, "Server GOAWAY with last_stream_id=0 is valid");

        let valid_server_odd = wing::validate_goaway_last_stream_id(1, false);
        sub.assert_true(valid_server_odd, "Server GOAWAY with last_stream_id=1 (client stream) is valid");

        let valid_server_max = wing::validate_goaway_last_stream_id(0x7FFFFFFF, false);
        sub.assert_true(valid_server_max, "Server GOAWAY with 2^31-1 (graceful shutdown) is valid");

        let invalid_server_even2 = wing::validate_goaway_last_stream_id(2, false);
        sub.assert_false(invalid_server_even2, "Server GOAWAY with even stream 2 MUST be rejected (RFC 9113 §6.8)");

        let invalid_server_even4 = wing::validate_goaway_last_stream_id(4, false);
        sub.assert_false(invalid_server_even4, "Server GOAWAY with even stream 4 MUST be rejected (RFC 9113 §6.8)");
    };
}

// ----------------------------------------------------------------------------
// 2. RFC 9113 §6.8 & Go #82365: HTTP/2 Stream Ingestion Blocked After GOAWAY
// ----------------------------------------------------------------------------
fn test_h2_stream_blocked_after_goaway(t: core::T&) {
    t.run("New stream headers frame on stream > last_stream_id after GOAWAY MUST return ERR_REFUSED_STREAM") { sub =>
        // RFC 9113 Section 6.8 & Go #82365:
        // After receiving a GOAWAY frame with Last-Stream-ID = N, any new stream with ID > N
        // must be rejected.
        var conn = wing::new_h2_connection(0, 8192, false);
        let ok_ga = wing::apply_goaway(conn, 3, wing::ERR_NO_ERROR);
        sub.assert_eq(ok_ga, wing::ERR_NO_ERROR, "apply_goaway accepted");
        sub.assert_true(conn.goaway_received, "goaway_received flag is set");
        sub.assert_eq(conn.goaway_last_stream_id, 3, "goaway_last_stream_id is 3");

        // Attempting to open stream 5 (> 3) after GOAWAY must be refused
        let hdr_st5 = wing::FrameHeader {
            length: 10,
            frame_type: wing::FRAME_HEADERS,
            flags: wing::FLAG_END_HEADERS,
            stream_id: 5,
        };
        let res_st5 = wing::handle_h2_headers_frame_header(conn, hdr_st5, 0);
        sub.assert_eq(res_st5, wing::ERR_REFUSED_STREAM, "Stream 5 > last_stream_id 3 MUST return REFUSED_STREAM");

        // Stream 1 (<= 3) was processed before GOAWAY, so it is not rejected as refused
        let hdr_st1 = wing::FrameHeader {
            length: 10,
            frame_type: wing::FRAME_HEADERS,
            flags: wing::FLAG_END_HEADERS,
            stream_id: 1,
        };
        let res_st1 = wing::handle_h2_headers_frame_header(conn, hdr_st1, 0);
        sub.assert_eq(res_st1, wing::ERR_NO_ERROR, "Stream 1 <= last_stream_id 3 is accepted");
    };
}

// ----------------------------------------------------------------------------
// 3. RFC 9113 §8.3.1 & Go #77843: HTTP/2 :path Pseudo-Header Character Validation
// ----------------------------------------------------------------------------
fn test_h2_path_character_validation(t: core::T&) {
    t.run("Path containing unescaped angle brackets (<>) MUST return ERR_PROTOCOL_ERROR (Go #77843)") { sub =>
        var headers = wing::DecodedH2HeaderList { .. };
        let ok_meth = wing::validate_header_ordering_and_rules(headers, ":method", "GET");
        sub.assert_eq(ok_meth, wing::ERR_NO_ERROR, ":method GET accepted");
        headers.fields.push(wing::DecodedH2Header { name: ":method", value: "GET", .. });

        // Unescaped '>' is forbidden in RFC 3986 pchar and query
        let err_gt = wing::validate_header_ordering_and_rules(headers, ":path", "/api/search?q=test>123");
        sub.assert_eq(err_gt, wing::ERR_PROTOCOL_ERROR, "Path with raw '>' MUST return ERR_PROTOCOL_ERROR (Go #77843)");

        // Unescaped '<' is forbidden
        let err_lt = wing::validate_header_ordering_and_rules(headers, ":path", "/api/search<test");
        sub.assert_eq(err_lt, wing::ERR_PROTOCOL_ERROR, "Path with raw '<' MUST return ERR_PROTOCOL_ERROR (Go #77843)");

        // Space inside path is forbidden
        let err_sp = wing::validate_header_ordering_and_rules(headers, ":path", "/api/my test");
        sub.assert_eq(err_sp, wing::ERR_PROTOCOL_ERROR, "Path with interior space MUST return ERR_PROTOCOL_ERROR");

        // Properly percent-encoded path is valid
        let ok_encoded = wing::validate_header_ordering_and_rules(headers, ":path", "/api/search?q=test%3E123");
        sub.assert_eq(ok_encoded, wing::ERR_NO_ERROR, "Percent-encoded path '/api/search?q=test%3E123' is valid");
    };
}

// ----------------------------------------------------------------------------
// 4. RFC 9113 §8.3 & Go #78775: HTTP/2 Trailer Section Forbidden Pseudo-Headers
// ----------------------------------------------------------------------------
fn test_h2_trailer_forbidden_pseudo_headers(t: core::T&) {
    t.run("Pseudo-headers in HTTP/2 trailer block MUST return ERR_PROTOCOL_ERROR (RFC 9113 §8.3)") { sub =>
        // RFC 9113 Section 8.3:
        // "Pseudo-header fields MUST NOT appear in trailer sections."
        var trailers = wing::DecodedH2HeaderList { is_trailer: true, .. };

        let err_status = wing::validate_header_ordering_and_rules(trailers, ":status", "200");
        sub.assert_eq(err_status, wing::ERR_PROTOCOL_ERROR, "Pseudo-header :status in trailers MUST return PROTOCOL_ERROR");

        let err_path = wing::validate_header_ordering_and_rules(trailers, ":path", "/index");
        sub.assert_eq(err_path, wing::ERR_PROTOCOL_ERROR, "Pseudo-header :path in trailers MUST return PROTOCOL_ERROR");

        // Regular trailer field is valid
        let ok_trailer = wing::validate_header_ordering_and_rules(trailers, "grpc-status", "0");
        sub.assert_eq(ok_trailer, wing::ERR_NO_ERROR, "Regular trailer field 'grpc-status' is valid");
    };
}

// ----------------------------------------------------------------------------
// 5. RFC 6455 §4.2.1: WebSocket Upgrade Handshake Missing Host Header Rejection
// ----------------------------------------------------------------------------
fn test_ws_handshake_missing_host_rejection(t: core::T&) {
    t.run("WebSocket Upgrade handshake without Host header MUST be rejected with HTTP 400") { sub =>
        // RFC 6455 Section 4.2.1 item 2:
        // "The request MUST contain a |Host| header field."
        // "If the handshake lacks a Host header, the server MUST respond with 400 Bad Request."
        var req = wing::new_request("GET", "/ws");
        wing::set_header(req, "Upgrade", "websocket");
        wing::set_header(req, "Connection", "Upgrade");
        wing::set_header(req, "Sec-WebSocket-Version", "13");
        wing::set_header(req, "Sec-WebSocket-Key", "dGhlIHNhbXBsZSBub25jZQ==");
        // Omit Host header!

        var resp = wing::new_response();
        let _, ok = wing::ws_upgrade_request(req, resp);
        sub.assert_false(ok, "Upgrade handshake MUST fail when Host header is missing (RFC 6455 §4.2.1)");
        sub.assert_eq(resp.status_code, 400, "Response status code MUST be 400 Bad Request");

        sub.assert_false(wing::is_websocket_upgrade_request(req), "is_websocket_upgrade_request MUST return false without Host");

        // With valid Host header, handshake succeeds
        wing::set_header(req, "Host", "example.com");
        var resp_ok = wing::new_response();
        let _, ok_with_host = wing::ws_upgrade_request(req, resp_ok);
        sub.assert_true(ok_with_host, "Upgrade handshake succeeds with Host header present");
        sub.assert_eq(resp_ok.status_code, 101, "Response status code is 101 Switching Protocols");
    };
}

// ----------------------------------------------------------------------------
// 6. RFC 6455 §4.2.2: WebSocket Subprotocol Agreement Verification
// ----------------------------------------------------------------------------
fn test_ws_subprotocol_agreement_verification(t: core::T&) {
    t.run("Server selecting subprotocol NOT offered by client MUST NOT negotiate it (RFC 6455 §4.2.2)") { sub =>
        // RFC 6455 Section 4.2.2 item 5:
        // "If the server does include a |Sec-WebSocket-Protocol| header field in its response,
        // the value of that field MUST be one of the subprotocols requested by the client."
        var req = wing::new_request("GET", "/ws");
        wing::set_header(req, "Host", "example.com");
        wing::set_header(req, "Upgrade", "websocket");
        wing::set_header(req, "Connection", "Upgrade");
        wing::set_header(req, "Sec-WebSocket-Version", "13");
        wing::set_header(req, "Sec-WebSocket-Key", "dGhlIHNhbXBsZSBub25jZQ==");
        wing::set_header(req, "Sec-WebSocket-Protocol", "chat, superchat");

        // Server attempts to negotiate "unsupported_protocol" not offered by client
        var resp_unmatched = wing::new_response();
        let sess_unmatched, ok1 = wing::ws_upgrade_request(req, resp_unmatched, "unsupported_protocol");
        sub.assert_true(ok1, "Handshake succeeds");
        sub.assert_eq(sess_unmatched.subprotocol.len, 0, "Unmatched subprotocol MUST NOT be accepted in session");
        sub.assert_false(wing::has_header(resp_unmatched, "Sec-WebSocket-Protocol"), "Sec-WebSocket-Protocol header MUST NOT be sent for unoffered protocol");

        // Server selects "chat" which WAS offered by client
        var resp_matched = wing::new_response();
        let sess_matched, ok2 = wing::ws_upgrade_request(req, resp_matched, "chat");
        sub.assert_true(ok2, "Handshake succeeds");
        sub.assert_bytes_eq(sess_matched.subprotocol[..], "chat", "Matched subprotocol 'chat' is negotiated");
        sub.assert_bytes_eq(wing::header(resp_matched, "Sec-WebSocket-Protocol"), "chat", "Sec-WebSocket-Protocol header contains 'chat'");
    };
}

// ----------------------------------------------------------------------------
// 7. RFC 3986 §4.2 & Go #81292: Relative URL Double-Slash Path Authority Protection
// ----------------------------------------------------------------------------
fn test_relative_url_double_slash_path_protection(t: core::T&) {
    t.run("Relative path starting with encoded slashes MUST NOT be converted to authority (Go #81292)") { sub =>
        // Go #81292 / RFC 3986 Section 4.2:
        // Percent-encoded slashes in relative paths must not promote a path to a host.
        let base = core::new_url("https://example.com/api/");
        let parsed = core::new_url("/relative/path", base);
        let smuggled = core::new_url("/%2fevil.com/path", base);
        sub.assert_true(smuggled.valid, "Parsed percent-encoded slash relative URL is valid");
        sub.assert_bytes_eq(core::hostname(smuggled), "example.com", "Hostname MUST remain example.com, not promote evil.com to authority");
        sub.assert_true(parsed.valid, "Parsed relative URL is valid");
        sub.assert_bytes_eq(core::hostname(parsed), "example.com", "Hostname retained as example.com");
        sub.assert_bytes_eq(core::pathname(parsed), "/relative/path", "Pathname matches /relative/path");
    };
}

fn main() {
    var runner = core::new_runner("RED Suite Phase 8: Tracker Issues & RFC Invariants", core::Verbosity.Verbose);
    core::run_case(runner, "1. RFC 9113 §6.8 & Go #80759: HTTP/2 GOAWAY Last-Stream-ID Peer Role Invariant", test_h2_goaway_last_stream_id_peer_role);
    core::run_case(runner, "2. RFC 9113 §6.8 & Go #82365: HTTP/2 Inbound Stream Rejection After GOAWAY", test_h2_stream_blocked_after_goaway);
    core::run_case(runner, "3. RFC 9113 §8.3.1 & Go #77843: HTTP/2 :path Pseudo-Header Character Validation", test_h2_path_character_validation);
    core::run_case(runner, "4. RFC 9113 §8.3 & Go #78775: HTTP/2 Trailer Section Forbidden Pseudo-Headers", test_h2_trailer_forbidden_pseudo_headers);
    core::run_case(runner, "5. RFC 6455 §4.2.1: WebSocket Upgrade Handshake Missing Host Header Rejection", test_ws_handshake_missing_host_rejection);
    core::run_case(runner, "6. RFC 6455 §4.2.2: WebSocket Subprotocol Agreement Verification", test_ws_subprotocol_agreement_verification);
    core::run_case(runner, "7. RFC 3986 §4.2 & Go #81292: Relative URL Double-Slash Path Authority Protection", test_relative_url_double_slash_path_protection);
    let ok = core::finish(runner);
    assert(ok);
}
