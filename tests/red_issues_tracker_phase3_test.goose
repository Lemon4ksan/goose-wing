// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Phase 3 regression test suite based on .gemini audit reports and Go / uWebSockets issue trackers.
//
// Issues covered:
// 1. Go #81508 & RFC 9110 §14.1.2: Unsupported Range Unit Must Return 200 OK (Not 416)
// 2. Go #21096 & RFC 9110 §7.6.1 / RFC 9113: Forwarding 'TE: trailers' for gRPC (Not Stripped)
// 3. RFC 6455 §8.1 / §7.4.1 / Autobahn 6.4.1: Close Frame with Invalid UTF-8 Must Fail with 1007 (Not 1002)
// 4. RFC 7692 §5.1 / uWS #1164: RSV1 Set on WebSocket Continuation Frame Must Fail with 1002
// 5. Go #76635 & RFC 6455 §4.1: Empty Path in WebSocket Handshake Must Default to '/'
// 6. Go #78569 & CVE-2026-25679 follow-up: parse_url_view Trailing Garbage on IPv6 Brackets [::1]evil.com
// 7. RFC 9112 §3.1.2 & uWS #1949: HTTP Wire Response Status Line Whitespace & 4-Digit Smuggling

import std;
import core from "..";
import wing from "..";

// ----------------------------------------------------------------------------
// 1. Go #81508 & RFC 9110 §14.1.2: Unsupported Range Unit Must Return 200 OK
// ----------------------------------------------------------------------------
fn test_unsupported_range_unit_ignored(t: core::T&) {
    t.run("Unrecognized Range unit (e.g. items=0-10) must be ignored and return 200 OK") { sub =>
        var out_status: i32 = 0;
        var out_headers = wing::new_header_map();
        var out_body: u8[>..] = [];

        let payload: const u8[:] = "Hello World Range Test";
        let mod_time = core::unix(1700000000);

        wing::serve_range_request(
            "items=0-10",
            "",
            "\"etag123\"",
            mod_time,
            payload.len as i64,
            "text/plain",
            out_status,
            out_headers,
            out_body,
        ) { start, len, buf =>
            buf.append(payload[start..(start + len)]);
        };

        sub.assert_eq(out_status, 200, "Unrecognized Range unit must be ignored and return 200 OK (Go #81508 / RFC 9110 §14.1.2)");
        sub.assert_bytes_eq(out_body[..], payload, "Must return complete representation when Range unit is ignored");
    };
}

// ----------------------------------------------------------------------------
// 2. Go #21096 & RFC 9110 §7.6.1 / RFC 9113: Forwarding 'TE: trailers' for gRPC
// ----------------------------------------------------------------------------
fn test_grpc_te_trailers_preserved(t: core::T&) {
    t.run("TE: trailers header must NOT be stripped by strip_hop_by_hop_headers") { sub =>
        var src = wing::new_header_map();
        wing::append_header(src, "TE", "trailers");
        wing::append_header(src, "Connection", "keep-alive");
        wing::append_header(src, "X-Custom", "preserve-me");

        var dst = wing::new_header_map();
        wing::strip_hop_by_hop_headers(src, dst);

        sub.assert_true(wing::has_header(dst, "TE"), "TE: trailers must be preserved across proxies for gRPC (Go #21096)");
        let te_val = wing::get_header(dst, "TE");
        sub.assert_bytes_eq(te_val, "trailers", "TE value must remain 'trailers'");
        sub.assert_false(wing::has_header(dst, "Connection"), "Connection header must be stripped");
        sub.assert_true(wing::has_header(dst, "X-Custom"), "Regular headers must be retained");
    };

    t.run("TE with non-trailers (e.g. TE: gzip, deflate) must be stripped") { sub =>
        var src = wing::new_header_map();
        wing::append_header(src, "TE", "gzip, deflate");
        wing::append_header(src, "X-Custom", "keep");

        var dst = wing::new_header_map();
        wing::strip_hop_by_hop_headers(src, dst);

        sub.assert_false(wing::has_header(dst, "TE"), "TE without 'trailers' must be stripped as hop-by-hop");
    };
}

// ----------------------------------------------------------------------------
// 3. RFC 6455 §8.1 / §7.4.1 / Autobahn 6.4.1: Close Frame Invalid UTF-8 (1007)
// ----------------------------------------------------------------------------
fn test_close_frame_invalid_utf8_status_1007(t: core::T&) {
    t.run("Close frame with invalid UTF-8 payload must fail with 1007 (not 1002)") { sub =>
        var ws = wing::new_websocket_session(false);

        var wire: u8[..64] = [];
        wire.push(0x88); // FIN=1, Opcode=8 (Close)
        wire.push(0x84); // Masked=1, Len=4
        wire.push(0x00); wire.push(0x00); wire.push(0x00); wire.push(0x00);
        wire.push(0x03); wire.push(0xE8); // Status code 1000
        wire.push(0xFF); wire.push(0xFF); // Invalid UTF-8 bytes

        var out_view = wing::WsMessageView { .. };
        var out_reply: u8[..256] = [];

        let handled = wing::receive_view(ws, wire[..], out_view, out_reply);
        sub.assert_true(handled, "Receive handled incoming invalid UTF-8 close frame");
        sub.assert_true(ws.is_closed, "Connection closed on invalid UTF-8");
        sub.assert_eq(ws.close_code, wing::WS_STATUS_INVALID_PAYLOAD, "Close status code MUST be 1007 (Invalid Payload), NOT 1002");
    };
}

// ----------------------------------------------------------------------------
// 4. RFC 7692 §5.1 / uWS #1164: RSV1 Set on Continuation Frame Must Fail (1002)
// ----------------------------------------------------------------------------
fn test_continuation_rsv1_rejected(t: core::T&) {
    t.run("Continuation frame with RSV1 set must be rejected with protocol error 1002") { sub =>
        var ws = wing::new_websocket_session(false);
        wing::enable_permessage_deflate(ws);

        var f1: u8[..64] = [];
        f1.push(0x41); // FIN=0, RSV1=1, Opcode=1 (Text)
        f1.push(0x84); // Masked=1, Len=4
        f1.push(0x00); f1.push(0x00); f1.push(0x00); f1.push(0x00);
        f1.append("test");

        var out_view = wing::WsMessageView { .. };
        var out_reply: u8[..256] = [];
        let ok1 = wing::receive_view(ws, f1[..], out_view, out_reply);
        sub.assert_true(ok1, "First fragment accepted");
        sub.assert_false(ws.is_closed, "WS still open after fragment 1");

        var f2: u8[..64] = [];
        f2.push(0xC0); // FIN=1, RSV1=1, Opcode=0 (Continuation with RSV1!)
        f2.push(0x84); // Masked=1, Len=4
        f2.push(0x00); f2.push(0x00); f2.push(0x00); f2.push(0x00);
        f2.append("data");

        let ok2 = wing::receive_view(ws, f2[..], out_view, out_reply);
        sub.assert_true(ok2, "Frame 2 processed");
        sub.assert_true(ws.is_closed, "WebSocket connection MUST be closed on continuation frame with RSV1 set");
        sub.assert_eq(ws.close_code, wing::WS_STATUS_PROTOCOL_ERROR, "Close code MUST be 1002 (Protocol Error)");
    };
}

// ----------------------------------------------------------------------------
// 5. Go #76635 & RFC 6455 §4.1: Empty Path in WebSocket Handshake Must Default to '/'
// ----------------------------------------------------------------------------
fn test_ws_handshake_empty_path_defaults_to_slash(t: core::T&) {
    t.run("build_handshake_request with empty path must serialize 'GET / HTTP/1.1'") { sub =>
        var ws = wing::new_websocket_session(true);
        var wire_out: u8[..512] = [];

        wing::build_handshake_request(ws, "example.com", "", "dGhlIHNhbXBsZSBub25jZQ==", wire_out);

        let has_double_space = core::index_of_slice(wire_out[..], "GET  HTTP/1.1") >= 0;
        sub.assert_false(has_double_space, "Must NOT format malformed 'GET  HTTP/1.1' with double space");

        let starts_with_get_slash = core::starts_with(wire_out[..], "GET / HTTP/1.1\r\n");
        sub.assert_true(starts_with_get_slash, "Empty path MUST serialize as 'GET / HTTP/1.1\r\n' (Go #76635 / RFC 6455 §4.1)");
    };
}

// ----------------------------------------------------------------------------
// 6. Go #78569 & CVE-2026-25679 follow-up: parse_url_view Trailing Garbage on IPv6 Brackets
// ----------------------------------------------------------------------------
fn test_parse_url_view_ipv6_bracket_trailing_garbage(t: core::T&) {
    t.run("parse_url_view must reject trailing host garbage after closing bracket [::1]evil.com") { sub =>
        let view, err = core::parse_url_view("http://[::1]evil.com/api");
        sub.assert_false(view.valid, "parse_url_view MUST reject host with trailing garbage after bracket [::1]evil.com (Go #78569)");
        sub.assert_true(err != core::UrlParseError.None, "Must return parse error for malformed IPv6 host");
    };
}

// ----------------------------------------------------------------------------
// 7. RFC 9112 §3.1.2 & uWS #1949: HTTP Wire Response Status Line Whitespace & 4-Digit Smuggling
// ----------------------------------------------------------------------------
fn test_http1_wire_response_status_line_validation(t: core::T&) {
    t.run("parse_http1_wire_response must reject 4-digit status code 'HTTP/1.1 2000 OK'") { sub =>
        var res = wing::new_response();
        let wire: const u8[:] = "HTTP/1.1 2000 OK\r\nContent-Length: 0\r\n\r\n";
        let ok, _ = wing::parse_http1_wire_response(wire, res);
        sub.assert_false(ok, "parse_http1_wire_response MUST reject 4-digit status codes like '2000'");
    };

    t.run("parse_http1_wire_response must reject non-SP whitespace 'HTTP/1.1\\t200 OK'") { sub =>
        var res = wing::new_response();
        let wire_tab: const u8[:] = "HTTP/1.1\t200 OK\r\nContent-Length: 0\r\n\r\n";
        let ok_tab, _ = wing::parse_http1_wire_response(wire_tab, res);
        sub.assert_false(ok_tab, "parse_http1_wire_response MUST reject Tab (\\t) between HTTP-version and status code");
    };
}

fn main() {
    let _ = wing::tcp_init();
    var dummy: u8[4] = [0, 0, 0, 0];
    wing::swar_to_lower(dummy[..]);

    var runner = core::new_runner("RED Suite Phase 3: CVE & Issue Tracker Flaws", core::Verbosity.Verbose);

    core::run_case(runner, "1. Go #81508 & RFC 9110 §14.1.2: Unsupported Range Unit Must Return 200 OK", test_unsupported_range_unit_ignored);
    core::run_case(runner, "2. Go #21096 & RFC 9110 §7.6.1: Forwarding TE: trailers for gRPC", test_grpc_te_trailers_preserved);
    core::run_case(runner, "3. RFC 6455 §8.1 / §7.4.1 / Autobahn 6.4.1: Close Invalid UTF-8 Status 1007", test_close_frame_invalid_utf8_status_1007);
    core::run_case(runner, "4. RFC 7692 §5.1 / uWS #1164: RSV1 on Continuation Frame Rejection", test_continuation_rsv1_rejected);
    core::run_case(runner, "5. Go #76635 & RFC 6455 §4.1: Empty Path in WS Handshake Defaults to '/'", test_ws_handshake_empty_path_defaults_to_slash);
    core::run_case(runner, "6. Go #78569 & CVE-2026-25679 follow-up: parse_url_view [::1]evil.com Rejection", test_parse_url_view_ipv6_bracket_trailing_garbage);
    core::run_case(runner, "7. RFC 9112 §3.1.2 & uWS #1949: HTTP Wire Response Status Line Validation", test_http1_wire_response_status_line_validation);

    let ok = core::finish(runner);
    print("\n[PHASE 3 TEST SUITE STATUS] Finished execution. Result ok=", ok);
}
