// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// tests/websocket_h2_test.goose
// Verification Suite for RFC 8441: Bootstrapping WebSockets with HTTP/2.
import std;
import core from "..";
import wing from "..";

fn test_rfc8441_client_formatting(t: core::T&) {
    t.run("1. Client Request Formatting & Pseudo-Headers") { sub =>
        var req = wing::new_request("GET", "/");
        wing::format_h2_websocket_request(req, "/v1/chat", "api.example.com", "https", "graphql-transport-ws");

        sub.assert_bytes_eq(req.method[..], "CONNECT", "Method is CONNECT");
        sub.assert_bytes_eq(req.url[..], "/v1/chat", "URL path matches");

        sub.assert_bytes_eq(req.header(":method"), "CONNECT", ":method pseudo-header is CONNECT");
        sub.assert_bytes_eq(req.header(":protocol"), "websocket", ":protocol pseudo-header is websocket");
        sub.assert_bytes_eq(req.header(":scheme"), "https", ":scheme pseudo-header is https");
        sub.assert_bytes_eq(req.header(":authority"), "api.example.com", ":authority pseudo-header is api.example.com");
        sub.assert_bytes_eq(req.header(":path"), "/v1/chat", ":path pseudo-header is /v1/chat");
        sub.assert_bytes_eq(req.header("sec-websocket-version"), "13", "sec-websocket-version is 13");
        sub.assert_bytes_eq(req.header("sec-websocket-protocol"), "graphql-transport-ws", "subprotocol matches");

        sub.assert_true(wing::is_h2_websocket_request(req), "is_h2_websocket_request is true");
        sub.assert_true(wing::validate_h2_websocket_request(req), "validate_h2_websocket_request succeeds");
    };
}

fn test_rfc8441_validation_invariants(t: core::T&) {
    t.run("1. Strict RFC 8441 Rejections (Forbidden Headers & Missing Fields)") { sub =>
        // 1. Forbidden Upgrade header
        var req1 = wing::new_request("GET", "/");
        wing::format_h2_websocket_request(req1, "/chat", "example.com");
        wing::set_header(req1, "Upgrade", "websocket");
        sub.assert_false(wing::validate_h2_websocket_request(req1), "Reject request with Upgrade header");

        // 2. Forbidden Connection header
        var req2 = wing::new_request("GET", "/");
        wing::format_h2_websocket_request(req2, "/chat", "example.com");
        wing::set_header(req2, "Connection", "Upgrade");
        sub.assert_false(wing::validate_h2_websocket_request(req2), "Reject request with Connection header");

        // 3. Forbidden Sec-WebSocket-Key header (RFC 8441 §4: Sec-WebSocket-Key MUST NOT be used)
        var req3 = wing::new_request("GET", "/");
        wing::format_h2_websocket_request(req3, "/chat", "example.com");
        wing::set_header(req3, "Sec-WebSocket-Key", "dGhlIHNhbXBsZSBub25jZQ==");
        sub.assert_false(wing::validate_h2_websocket_request(req3), "Reject request with Sec-WebSocket-Key header");

        // 4. Missing :protocol
        var req4 = wing::new_request("GET", "/");
        wing::format_h2_websocket_request(req4, "/chat", "example.com");
        wing::set_header(req4, ":protocol", "");
        sub.assert_false(wing::validate_h2_websocket_request(req4), "Reject request with empty :protocol");

        // 5. Wrong :protocol value (e.g. webtransport instead of websocket)
        var req5 = wing::new_request("GET", "/");
        wing::format_h2_websocket_request(req5, "/chat", "example.com");
        wing::set_header(req5, ":protocol", "webtransport");
        sub.assert_false(wing::validate_h2_websocket_request(req5), "Reject request with wrong :protocol");

        // 6. Wrong sec-websocket-version
        var req6 = wing::new_request("GET", "/");
        wing::format_h2_websocket_request(req6, "/chat", "example.com");
        wing::set_header(req6, "sec-websocket-version", "8");
        sub.assert_false(wing::validate_h2_websocket_request(req6), "Reject request with version != 13");
    };
}

fn test_rfc8441_server_upgrade(t: core::T&) {
    t.run("1. 200 OK Response & Subprotocol Negotiation") { sub =>
        var req = wing::new_request("GET", "/");
        wing::format_h2_websocket_request(req, "/live", "stream.example.com", "https", "wamp.2.json, mqtt");

        var resp = wing::new_response();
        let session, ok = wing::ws_h2_upgrade_request(req, resp, "mqtt");
        sub.assert_true(ok, "ws_h2_upgrade_request succeeds");
        sub.assert_eq(resp.status_code, 200, "RFC 8441 §5: Status code MUST be 200 (NOT 101)");
        sub.assert_bytes_eq(resp.header("sec-websocket-protocol"), "mqtt", "Negotiated subprotocol is mqtt");
        sub.assert_bytes_eq(session.subprotocol[..], "mqtt", "Session subprotocol matches");
        sub.assert_true(wing::is_h2_websocket_response(resp), "is_h2_websocket_response returns true");

        // Negative: Upgrade invalid request fails with 400
        var bad_req = wing::new_request("GET", "/");
        wing::format_h2_websocket_request(bad_req, "/live", "stream.example.com");
        wing::set_header(bad_req, "Connection", "keep-alive");
        var bad_resp = wing::new_response();
        let _, bad_ok = wing::ws_h2_upgrade_request(bad_req, bad_resp);
        sub.assert_false(bad_ok, "Upgrade invalid request fails");
        sub.assert_eq(bad_resp.status_code, 400, "Bad request produces 400");
    };
}

fn test_rfc8441_data_frame_payload(t: core::T&) {
    t.run("1. RFC 6455 Frame Encapsulation inside HTTP/2 Stream") { sub =>
        // Once connection is 200 OK, payload of HTTP/2 DATA frames contains RFC 6455 frames
        var ws_wire: u8[>..] = [];
        let mask_key: const u8[4] = [0x12, 0x34, 0x56, 0x78];
        let payload = "Ping from H2 WebSocket";
        wing::encode_ws_frame(ws_wire, wing::WS_OPCODE_TEXT, payload, true, mask_key);

        let hdr, ok = wing::parse_ws_frame_header(ws_wire[..]);
        sub.assert_true(ok, "Parse WS frame from H2 stream data");
        sub.assert_eq(hdr.opcode, wing::WS_OPCODE_TEXT, "Opcode is TEXT");
        sub.assert_eq(hdr.payload_len as i64, payload.len, "Payload length matches");
        sub.assert_true(hdr.masked, "Mask bit set");
    };
}

fn main() {
    var runner = core::new_runner("RFC 8441: WebSockets over HTTP/2 Suite", core::Verbosity.Verbose);
    core::run_case(runner, "1. RFC 8441 Client Formatting", test_rfc8441_client_formatting);
    core::run_case(runner, "2. RFC 8441 Validation Invariants", test_rfc8441_validation_invariants);
    core::run_case(runner, "3. RFC 8441 Server Upgrade", test_rfc8441_server_upgrade);
    core::run_case(runner, "4. RFC 8441 Stream Data Framing", test_rfc8441_data_frame_payload);
    let ok = core::finish(runner);
    assert(ok);
}
