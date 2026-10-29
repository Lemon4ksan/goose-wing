// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Verification suite for RFC 8441 & RFC 9220: Extended CONNECT (WebSockets over H2 and H3):
// - Detection of Extended CONNECT vs classic TCP tunnel CONNECT
// - HTTP/3 client request formatting (:protocol = websocket)
// - Strict protocol invariance: rejection of Upgrade/Connection/Sec-WebSocket-Key
// - Server-side upgrade producing 200 OK and subprotocol negotiation
// - Zero-allocation stream encapsulation of masked (client) and unmasked (server) WS frames
import std;
import core from "..";
import wing from "..";

fn test_extended_connect_detection(t: core::T&) {
    t.run("Extended CONNECT vs Classic Tunnel Detection") { sub =>
        // 1. Classic TCP tunnel CONNECT (RFC 9114 §4.4)
        var tunnel_req = wing::new_request("CONNECT", "example.com:443");
        wing::set_header(tunnel_req, ":method", "CONNECT");
        wing::set_header(tunnel_req, ":authority", "example.com:443");
        sub.assert_false(wing::is_extended_connect_request(tunnel_req), "Classic tunnel is not extended connect");

        // 2. Extended CONNECT (RFC 8441 / RFC 9220)
        var ext_req = wing::new_request("CONNECT", "/chat");
        wing::set_header(ext_req, ":method", "CONNECT");
        wing::set_header(ext_req, ":protocol", "websocket");
        wing::set_header(ext_req, ":scheme", "https");
        wing::set_header(ext_req, ":authority", "example.com");
        wing::set_header(ext_req, ":path", "/chat");
        sub.assert_true(wing::is_extended_connect_request(ext_req), "Detected extended connect via :protocol");

        // 3. Regular GET request
        var get_req = wing::new_request("GET", "/index.html");
        sub.assert_false(wing::is_extended_connect_request(get_req), "GET is not extended connect");
    };
}

fn test_h3_websocket_formatting(t: core::T&) {
    t.run("HTTP/3 Request Formatting & Protocol Validation (RFC 9220 §3)") { sub =>
        var req = wing::new_request("GET", "/");
        wing::format_h3_websocket_request(req, "/v2/feed", "h3.example.com", "https", "json-stream");

        sub.assert_bytes_eq(req.method[..], "CONNECT", "Method is CONNECT");
        sub.assert_bytes_eq(req.url[..], "/v2/feed", "URL matches");

        sub.assert_bytes_eq(req.header(":method"), "CONNECT", ":method pseudo-header is CONNECT");
        sub.assert_bytes_eq(req.header(":protocol"), "websocket", ":protocol pseudo-header is websocket");
        sub.assert_bytes_eq(req.header(":scheme"), "https", ":scheme pseudo-header is https");
        sub.assert_bytes_eq(req.header(":authority"), "h3.example.com", ":authority matches");
        sub.assert_bytes_eq(req.header(":path"), "/v2/feed", ":path matches");
        sub.assert_bytes_eq(req.header("sec-websocket-version"), "13", "Version is 13");
        sub.assert_bytes_eq(req.header("sec-websocket-protocol"), "json-stream", "Subprotocol matches");

        sub.assert_true(wing::validate_h3_websocket_request(req), "Valid RFC 9220 request passes");

        // Strict rejection of forbidden headers (RFC 9220 §3)
        var bad_req = req;
        wing::set_header(bad_req, "Upgrade", "websocket");
        sub.assert_false(wing::validate_h3_websocket_request(bad_req), "Upgrade header rejected");

        var bad_req2 = req;
        wing::set_header(bad_req2, "Sec-WebSocket-Key", "abc123==");
        sub.assert_false(wing::validate_h3_websocket_request(bad_req2), "Sec-WebSocket-Key rejected");
    };
}

fn test_h3_server_upgrade(t: core::T&) {
    t.run("Server-Side HTTP/3 WebSocket Upgrade (200 OK)") { sub =>
        var req = wing::new_request("GET", "/");
        wing::format_h3_websocket_request(req, "/ws", "h3.example.com", "https", "v1.proto, v2.proto");

        var resp = wing::new_response();
        let session, ok = wing::ws_h3_upgrade_request(req, resp, "v2.proto");
        sub.assert_true(ok, "Upgrade accepted");
        sub.assert_eq(resp.status_code, 200, "RFC 9220 §3: Status code MUST be 200 (NOT 101)");
        sub.assert_bytes_eq(resp.header("sec-websocket-protocol"), "v2.proto", "Negotiated subprotocol matches");
        sub.assert_bytes_eq(session.subprotocol[..], "v2.proto", "Session records negotiated subprotocol");
        sub.assert_true(wing::is_h3_websocket_response(resp), "Response identified as H3 WebSocket acceptance");
    };
}

fn test_stream_frame_encapsulation(t: core::T&) {
    t.run("Stream Encapsulation of Masked and Unmasked Frames") { sub =>
        // 1. Client frame (MUST be masked)
        var client_data: u8[>..] = [];
        let mask: const u8[4] = [0xAA, 0xBB, 0xCC, 0xDD];
        wing::ws_encapsulate_stream_data(client_data, wing::WS_OPCODE_TEXT, "Hello H3 WebSocket", true, mask);

        let hdr_c, ok_c = wing::parse_ws_frame_header(client_data[..]);
        sub.assert_true(ok_c, "Client frame header parsed");
        sub.assert_true(hdr_c.masked, "Client frame has mask bit set");
        sub.assert_eq(hdr_c.opcode, wing::WS_OPCODE_TEXT, "Opcode is TEXT");

        // 2. Server frame (MUST NOT be masked per RFC 6455 §5.1 / RFC 8441 / RFC 9220)
        var server_data: u8[>..] = [];
        wing::ws_encapsulate_stream_data(server_data, wing::WS_OPCODE_TEXT, "Server response payload", false);

        let hdr_s, ok_s = wing::parse_ws_frame_header(server_data[..]);
        sub.assert_true(ok_s, "Server frame header parsed");
        sub.assert_false(hdr_s.masked, "Server frame MUST NOT be masked");
        sub.assert_eq(hdr_s.payload_len as i64, ("Server response payload").len, "Payload length matches");
    };
}

fn main() {
    var runner = core::new_runner("RFC 8441 & RFC 9220 Extended CONNECT Suite", core::Verbosity.Verbose);
    core::run_case(runner, "1. Extended CONNECT Detection", test_extended_connect_detection);
    core::run_case(runner, "2. H3 WebSocket Formatting & Validation", test_h3_websocket_formatting);
    core::run_case(runner, "3. H3 Server Upgrade (200 OK)", test_h3_server_upgrade);
    core::run_case(runner, "4. Stream Frame Encapsulation", test_stream_frame_encapsulation);
    let ok = core::finish(runner);
    assert(ok);
}
