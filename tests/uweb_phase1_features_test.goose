// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Verification suite for uWebSockets Phase 1 features in goose-wing:
// 1. Declarative WebSocket Route Registration in HttpServer (app.ws pattern)
// 2. Per-Socket Typed UserData / Inline State (getUserData pattern)
// 3. Dynamic Backpressure Control & Drainage Notifications (drain pattern)
// 4. Selective Per-Message Compression (compress flag)
import std;
import core from "..";
import wing from "..";

fn test_declarative_ws_routing(t: core::T&) {
    t.run("1. Declarative add_ws_route & 101 Switching Protocols Handshake") { sub =>
        var server = wing::new_http_server("127.0.0.1", 8080);

        var ws_cfg = wing::new_ws_behavior(101);
        ws_cfg.subprotocol.append("chat.v2");
        ws_cfg.compression = wing::WS_COMPRESS_SHARED_COMPRESSOR;
        ws_cfg.max_backpressure = 1048576;

        let ok_add = server.add_ws_route("/ws/live", ws_cfg);
        sub.assert_true(ok_add, "add_ws_route registered successfully");

        let route_idx = server.find_ws_route("/ws/live");
        sub.assert_ge(route_idx, 0, "Route found in registry");

        // Client sends valid RFC 6455 upgrade request
        let req_wire: const u8[:] = "GET /ws/live HTTP/1.1\r\nHost: 127.0.0.1:8080\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Protocol: chat.v2\r\nSec-WebSocket-Extensions: permessage-deflate; client_max_window_bits\r\n\r\n";

        var wire_out: u8[..2048] = [];
        let outcome, ok_handle = wing::handle_connection_wire(server, "127.0.0.1", req_wire, 1000, wire_out);

        sub.assert_true(ok_handle, "handle_connection_wire succeeded");
        sub.assert_true(outcome == wing::PipelineOutcome.Handled, "Outcome is Handled");

        let wire_str = wire_out[..];
        sub.assert_true(core::index_of_slice(wire_str, "HTTP/1.1 101 Switching Protocols\r\n") == 0, "Status 101");
        sub.assert_true(core::index_of_slice(wire_str, "Upgrade: websocket\r\n") >= 0, "Upgrade header");
        sub.assert_true(core::index_of_slice(wire_str, "Connection: Upgrade\r\n") >= 0, "Connection header");
        sub.assert_true(core::index_of_slice(wire_str, "Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n") >= 0, "Accept key derived");
        sub.assert_true(core::index_of_slice(wire_str, "Sec-WebSocket-Protocol: chat.v2\r\n") >= 0, "Negotiated subprotocol");
        sub.assert_true(core::index_of_slice(wire_str, "Sec-WebSocket-Extensions: permessage-deflate") >= 0, "Negotiated compression");
    };

    t.run("2. WS Request to Unregistered Route Falls Back to 404") { sub =>
        var server = wing::new_http_server("127.0.0.1", 8080);
        let ws_cfg = wing::new_ws_behavior(101);
        server.add_ws_route("/ws/valid", ws_cfg);

        let unreg_wire: const u8[:] = "GET /ws/unknown HTTP/1.1\r\nHost: 127.0.0.1:8080\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n";

        var wire_out: u8[..1024] = [];
        let outcome, ok_handle = wing::handle_connection_wire(server, "127.0.0.1", unreg_wire, 1000, wire_out);
        sub.assert_true(ok_handle, "Handled gracefully");
        sub.assert_true(core::index_of_slice(wire_out[..], "404 Not Found") >= 0, "Returns 404 for unknown WS route");
    };

    t.run("3. Fast-Path and Pipelined Stream WS Upgrade") { sub =>
        var server = wing::new_http_server("127.0.0.1", 8080);
        server.fast_path = true;
        let ws_cfg = wing::new_ws_behavior(200);
        server.add_ws_route("/ws/fast", ws_cfg);

        let fast_wire: const u8[:] = "GET /ws/fast HTTP/1.1\r\nHost: 127.0.0.1:8080\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n";

        var wire_out: u8[..1024] = [];
        let outcome, ok_handle = wing::handle_connection_wire(server, "127.0.0.1", fast_wire, 1000, wire_out);
        sub.assert_true(ok_handle, "Fast-path handled WS upgrade");
        sub.assert_true(core::index_of_slice(wire_out[..], "HTTP/1.1 101 Switching Protocols") == 0, "Fast-path returns 101");
    };
}

fn test_per_socket_user_data(t: core::T&) {
    t.run("1. Zero-Alloc Inline UserData & UserTag") { sub =>
        var ws = wing::new_websocket_session(false);

        // User tag (64-bit integer handle)
        ws.set_user_tag(0xFEEDFACEDEADBEEF);
        sub.assert_eq(ws.get_user_tag(), 0xFEEDFACEDEADBEEF, "User tag set and retrieved");

        // User data slice
        let udata_sample = "session_token=usr_998124_admin;room=crypto_traders";
        let ok_set = ws.set_user_data(udata_sample);
        sub.assert_true(ok_set, "User data stored in inline buffer");
        sub.assert_bytes_eq(ws.get_user_data(), udata_sample, "Retrieved user data matches");

        // Update user data
        let udata_update = "room=lobby";
        ws.set_user_data(udata_update);
        sub.assert_bytes_eq(ws.get_user_data(), udata_update, "Updated user data retrieved");
    };
}

fn test_backpressure_and_drain(t: core::T&) {
    t.run("1. Backpressure Watermark Tracking & Drain Event") { sub =>
        var ws = wing::new_websocket_session(false);
        ws.set_max_backpressure(500, false);
        sub.assert_eq(ws.get_buffered_amount(), 0, "Initial buffered amount is 0");
        sub.assert_false(ws.is_backpressured, "Initially not backpressured");

        var out: u8[..1024] = [];
        // Send small message (40 bytes payload + 10 bytes overhead = 50 bytes)
        let st1 = ws.send_text_with_status("1234567890123456789012345678901234567890", out);
        sub.assert_true(st1 == wing::WsSendStatus.Backpressure, "Status is Backpressure when queued bytes > 0");
        sub.assert_eq(ws.get_buffered_amount(), 50, "50 bytes buffered");
        sub.assert_true(ws.is_backpressured, "Marked as backpressured");

        // Partial drain
        let drained_part = ws.notify_drained(20);
        sub.assert_false(drained_part, "Partial drain does not trigger drain event");
        sub.assert_eq(ws.get_buffered_amount(), 30, "30 bytes remaining");
        sub.assert_true(ws.is_backpressured, "Still backpressured");

        // Full drain
        let drained_full = ws.notify_drained(30);
        sub.assert_true(drained_full, "Full drain to 0 triggers drain event!");
        sub.assert_eq(ws.get_buffered_amount(), 0, "Buffered amount is 0");
        sub.assert_false(ws.is_backpressured, "No longer backpressured");

        // Subsequent drain when already 0
        let drained_redundant = ws.notify_drained(10);
        sub.assert_false(drained_redundant, "Redundant drain does not re-trigger event");
    };

    t.run("2. Backpressure Drop Policy When max_backpressure Exceeded") { sub =>
        var ws = wing::new_websocket_session(false);
        ws.set_max_backpressure(60, false); // Limit 60 bytes, close_on_limit = false

        var out: u8[..1024] = [];
        // 1st message: 40 + 10 = 50 bytes <= 60
        let st1 = ws.send_text_with_status("1234567890123456789012345678901234567890", out);
        sub.assert_true(st1 == wing::WsSendStatus.Backpressure, "First send accepted");
        sub.assert_eq(ws.get_buffered_amount(), 50, "50 bytes buffered");
        let initial_out_len = out.len;

        // 2nd message: 50 + 50 = 100 > 60 -> Must be DROPPED
        let st2 = ws.send_text_with_status("1234567890123456789012345678901234567890", out);
        sub.assert_true(st2 == wing::WsSendStatus.Dropped, "Status is Dropped when limit exceeded");
        sub.assert_eq(ws.dropped_messages_count, 1, "Dropped message counter incremented");
        sub.assert_eq(out.len, initial_out_len, "Dropped message was NOT serialized to wire buffer");
        sub.assert_false(ws.is_closed, "Socket remains open when close_on_limit is false");
    };

    t.run("3. Backpressure Close Policy (Slowloris Defense)") { sub =>
        var ws = wing::new_websocket_session(false);
        ws.set_max_backpressure(60, true); // Limit 60 bytes, close_on_limit = true

        var out: u8[..1024] = [];
        let st1 = ws.send_text_with_status("1234567890123456789012345678901234567890", out);
        sub.assert_true(st1 == wing::WsSendStatus.Backpressure, "First send accepted");

        // 2nd send exceeds limit -> connection closed with 1008 Policy Violation
        let st2 = ws.send_text_with_status("1234567890123456789012345678901234567890", out);
        sub.assert_true(st2 == wing::WsSendStatus.Closed, "Status is Closed when limit exceeded and close_on_limit=true");
        sub.assert_true(ws.is_closed, "WebSocket is marked closed");
        sub.assert_eq(ws.close_code, wing::WS_STATUS_POLICY_VIOLATION, "Close code 1008 Policy Violation");

        // Subsequent sends on closed socket return Closed
        let st3 = ws.send_text_with_status("after close", out);
        sub.assert_true(st3 == wing::WsSendStatus.Closed, "Send on closed socket returns Closed");
    };
}

fn test_selective_compression(t: core::T&) {
    t.run("1. Selective Compression Flag Toggle") { sub =>
        var ws = wing::new_websocket_session(false);
        wing::enable_permessage_deflate(ws, wing::WS_COMPRESS_SHARED_COMPRESSOR);
        var comp = wing::new_shared_ws_compressor();

        let repetitive_text = "{\"event\":\"trade\",\"ticker\":\"BTC-USDT\",\"price\":65432.10,\"volume\":1.54321,\"timestamp\":1700000000}";

        // 1. Send with compress = true
        var out_comp: u8[..1024] = [];
        let st_c = ws.send_text_compressed_with_status(repetitive_text, comp, out_comp, true);
        sub.assert_true(st_c == wing::WsSendStatus.Backpressure, "Compressed send succeeded");

        let hdr_comp, ok_c = wing::parse_ws_frame_header(out_comp[..]);
        sub.assert_true(ok_c, "Parsed compressed frame header");
        sub.assert_true(hdr_comp.rsv1, "RSV1 bit set (frame is compressed)");

        // 2. Send with compress = false (selective uncompressed bypass)
        var ws2 = wing::new_websocket_session(false);
        wing::enable_permessage_deflate(ws2, wing::WS_COMPRESS_SHARED_COMPRESSOR);

        var out_plain: u8[..1024] = [];
        let st_p = ws2.send_text_compressed_with_status(repetitive_text, comp, out_plain, false);
        sub.assert_true(st_p == wing::WsSendStatus.Backpressure, "Uncompressed send succeeded");

        let hdr_plain, ok_p = wing::parse_ws_frame_header(out_plain[..]);
        sub.assert_true(ok_p, "Parsed uncompressed frame header");
        sub.assert_false(hdr_plain.rsv1, "RSV1 bit cleared (frame sent raw uncompressed)");
        sub.assert_eq(hdr_plain.payload_len as i64, repetitive_text.len, "Payload length matches uncompressed raw length");
    };
}

fn main() {
    var runner = core::new_runner("uWebSockets Phase 1 Features Verification Suite", core::Verbosity.Verbose);

    core::run_case(runner, "1. Declarative WebSocket Route Registration", test_declarative_ws_routing);
    core::run_case(runner, "2. Per-Socket Typed UserData / Inline State", test_per_socket_user_data);
    core::run_case(runner, "3. Dynamic Backpressure Control & Drainage Notifications", test_backpressure_and_drain);
    core::run_case(runner, "4. Selective Per-Message Compression", test_selective_compression);

    let ok = core::finish(runner);
    assert(ok);
}
