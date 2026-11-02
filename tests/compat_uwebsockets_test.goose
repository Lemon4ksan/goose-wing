// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Consolidated Verification Suite: Behavioral Compatibility Suite
//
// RUN: goose build -o %t.exe %s
// RUN: %t.exe
import std;
import core from "..";
import wing from "..";
import lit from "github.com/Lemon4ksan/goose-lit@v0.1.0";

// --- Component: compat_uweb_features_phase1 ---
// Verification suite for Phase 1 features in goose-wing:
// 1. Declarative WebSocket Route Registration in HttpServer (app.ws pattern)
// 2. Per-Socket Typed UserData / Inline State (getUserData pattern)
// 3. Dynamic Backpressure Control & Drainage Notifications (drain pattern)
// 4. Selective Per-Message Compression (compress flag)

fn test_declarative_ws_routing(t: lit::T&) {
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
        sub.assert_true(find(wire_str, "HTTP/1.1 101 Switching Protocols\r\n") == 0, "Status 101");
        sub.assert_true(find(wire_str, "Upgrade: websocket\r\n") >= 0, "Upgrade header");
        sub.assert_true(find(wire_str, "Connection: Upgrade\r\n") >= 0, "Connection header");
        sub.assert_true(find(wire_str, "Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n") >= 0, "Accept key derived");
        sub.assert_true(find(wire_str, "Sec-WebSocket-Protocol: chat.v2\r\n") >= 0, "Negotiated subprotocol");
        sub.assert_true(find(wire_str, "Sec-WebSocket-Extensions: permessage-deflate") >= 0, "Negotiated compression");
    };

    t.run("2. WS Request to Unregistered Route Falls Back to 404") { sub =>
        var server = wing::new_http_server("127.0.0.1", 8080);
        let ws_cfg = wing::new_ws_behavior(101);
        server.add_ws_route("/ws/valid", ws_cfg);

        let unreg_wire: const u8[:] = "GET /ws/unknown HTTP/1.1\r\nHost: 127.0.0.1:8080\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n";

        var wire_out: u8[..1024] = [];
        let outcome, ok_handle = wing::handle_connection_wire(server, "127.0.0.1", unreg_wire, 1000, wire_out);
        sub.assert_true(ok_handle, "Handled gracefully");
        sub.assert_true(find(wire_out[..], "404 Not Found") >= 0, "Returns 404 for unknown WS route");
    };

    t.run("3. Connection Wire WS Upgrade") { sub =>
        var server = wing::new_http_server("127.0.0.1", 8080);
        let ws_cfg = wing::new_ws_behavior(200);
        server.add_ws_route("/ws/fast", ws_cfg);

        let fast_wire: const u8[:] = "GET /ws/fast HTTP/1.1\r\nHost: 127.0.0.1:8080\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n";

        var wire_out: u8[..1024] = [];
        let outcome, ok_handle = wing::handle_connection_wire(server, "127.0.0.1", fast_wire, 1000, wire_out);
        sub.assert_true(ok_handle, "Handled WS upgrade");
        sub.assert_true(find(wire_out[..], "HTTP/1.1 101 Switching Protocols") == 0, "Returns 101");
    };
}

fn test_per_socket_user_data(t: lit::T&) {
    t.run("1. Zero-Alloc Inline UserData & UserTag") { sub =>
        var ws = wing::new_websocket_session(false);

        // User tag (64-bit integer handle)
        ws.set_user_tag(0xFEEDFACEDEADBEEF);
        sub.assert_eq(ws.user_tag, 0xFEEDFACEDEADBEEF, "User tag set and retrieved");

        // User data slice
        let udata_sample = "session_token=usr_998124_admin;room=crypto_traders";
        let ok_set = ws.set_user_data(udata_sample);
        sub.assert_true(ok_set, "User data stored in inline buffer");
        sub.assert_bytes_eq(ws.user_data[..], udata_sample, "Retrieved user data matches");

        // Update user data
        let udata_update = "room=lobby";
        ws.set_user_data(udata_update);
        sub.assert_bytes_eq(ws.user_data[..], udata_update, "Updated user data retrieved");
    };
}

fn test_backpressure_and_drain(t: lit::T&) {
    t.run("1. Backpressure Watermark Tracking & Drain Event") { sub =>
        var ws = wing::new_websocket_session(false);
        ws.set_max_backpressure(500, false);
        sub.assert_eq(ws.buffered_amount, 0, "Initial buffered amount is 0");
        sub.assert_false(ws.is_backpressured, "Initially not backpressured");

        var out: u8[..1024] = [];
        // Send small message (40 bytes payload + 2 bytes server frame header = 42 bytes)
        let st1 = ws.send_text_with_status("1234567890123456789012345678901234567890", out);
        sub.assert_true(st1 == wing::WsSendStatus.Backpressure, "Status is Backpressure when queued bytes > 0");
        sub.assert_eq(ws.buffered_amount, 42, "42 bytes buffered");
        sub.assert_true(ws.is_backpressured, "Marked as backpressured");

        // Partial drain
        let drained_part = ws.notify_drained(20);
        sub.assert_false(drained_part, "Partial drain does not trigger drain event");
        sub.assert_eq(ws.buffered_amount, 22, "22 bytes remaining");
        sub.assert_true(ws.is_backpressured, "Still backpressured");

        // Full drain
        let drained_full = ws.notify_drained(22);
        sub.assert_true(drained_full, "Full drain to 0 triggers drain event!");
        sub.assert_eq(ws.buffered_amount, 0, "Buffered amount is 0");
        sub.assert_false(ws.is_backpressured, "No longer backpressured");

        // Subsequent drain when already 0
        let drained_redundant = ws.notify_drained(10);
        sub.assert_false(drained_redundant, "Redundant drain does not re-trigger event");
    };

    t.run("2. Backpressure Drop Policy When max_backpressure Exceeded") { sub =>
        var ws = wing::new_websocket_session(false);
        ws.set_max_backpressure(60, false); // Limit 60 bytes, close_on_limit = false

        var out: u8[..1024] = [];
        // 1st message: 40 + 2 = 42 bytes <= 60
        let st1 = ws.send_text_with_status("1234567890123456789012345678901234567890", out);
        sub.assert_true(st1 == wing::WsSendStatus.Backpressure, "First send accepted");
        sub.assert_eq(ws.buffered_amount, 42, "42 bytes buffered");
        let initial_out_len = out.len;

        // 2nd message: 42 + 42 = 84 > 60 -> Must be DROPPED
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

fn test_selective_compression(t: lit::T&) {
    t.run("1. Selective Compression Flag Toggle") { sub =>
        var ws = wing::new_websocket_session(false);
        wing::enable_permessage_deflate(ws, wing::WS_COMPRESS_SHARED_COMPRESSOR);
        var comp = wing::SharedWsCompressor { .. };

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

// --- Component: compat_uweb_features_phase2 ---
// Verification suite for Phase 2 & Phase 3 features in goose-wing:
// 1. Heartbeat Daemon & 1-Byte Modular Tick Sweeper (sendPingsAutomatically & idleTimeout)
// 2. Pub/Sub Subscription Count Hook & Room Lifecycle (subscription pattern)
// 3. Per-Socket Topic Enumeration (iterateTopics pattern)
// 4. Asynchronous WebSocket Upgrade & Abort Safety (res->onAborted & res->upgrade pattern)
// 5. Cross-Thread EventLoop Task Dispatch (loop->defer pattern)
// 6. Dedicated Sliding-Window Compression (DedicatedWsCompressor pattern)

fn test_heartbeat_and_idle_sweeper(t: lit::T&) {
    t.run("1. Auto-Ping Generation & Idle Timeout Reaper") { sub =>
        var wheel = wing::new_tick_timer_wheel(10);
        var ws = wing::new_websocket_session(false);
        ws.idle_timeout_s = 10;
        ws.send_pings_automatically = true;
        ws.arm_heartbeat(wheel);

        sub.assert_false(ws.is_closed, "Session initially open");
        sub.assert_true(ws.check_heartbeat(wheel) == wing::WsHeartbeatAction.None, "No action at tick 0");

        // Advance 5 seconds: half of idle timeout triggers ping
        wing::tick_timer_advance(wheel, 5);
        sub.assert_true(ws.check_heartbeat(wheel) == wing::WsHeartbeatAction.SendPing, "Ping action triggered at 5s");

        var wire_ping: u8[..256] = [];
        let act = ws.tick_heartbeat(wheel, wire_ping);
        sub.assert_true(act == wing::WsHeartbeatAction.SendPing, "tick_heartbeat executed SendPing");
        sub.assert_gt(wire_ping.len, 0, "Ping frame serialized to wire");
        sub.assert_eq(ws.pings_sent, 1, "pings_sent incremented");

        let hdr, ok_h = wing::parse_ws_frame_header(wire_ping[..]);
        sub.assert_true(ok_h, "Parsed generated ping header");
        sub.assert_eq(hdr.opcode, wing::WS_OPCODE_PING, "Frame opcode is Ping (0x9)");

        // Advance another 5 seconds without touching: idle timeout (10s) expires
        wing::tick_timer_advance(wheel, 5);
        sub.assert_true(ws.check_heartbeat(wheel) == wing::WsHeartbeatAction.CloseIdle, "CloseIdle action triggered at 10s");

        var wire_close: u8[..256] = [];
        let act_close = ws.tick_heartbeat(wheel, wire_close);
        sub.assert_true(act_close == wing::WsHeartbeatAction.CloseIdle, "tick_heartbeat executed CloseIdle");
        sub.assert_true(ws.is_closed, "Session marked closed");
        sub.assert_eq(ws.close_code, wing::WS_STATUS_NORMAL, "Close status is 1000");

        let hdr_c, ok_c = wing::parse_ws_frame_header(wire_close[..]);
        sub.assert_true(ok_c, "Parsed generated close header");
        sub.assert_eq(hdr_c.opcode, wing::WS_OPCODE_CLOSE, "Frame opcode is Close (0x8)");
    };

    t.run("2. Touch Resets Idle Timeout") { sub =>
        var wheel = wing::new_tick_timer_wheel(10);
        var ws = wing::new_websocket_session(false);
        ws.idle_timeout_s = 10;
        ws.arm_heartbeat(wheel);

        wing::tick_timer_advance(wheel, 8);
        // Client activity touches session
        ws.touch(wheel);

        // Advance 2 more seconds: total 10 ticks, but touched at tick 8 so not expired yet
        wing::tick_timer_advance(wheel, 2);
        sub.assert_true(ws.check_heartbeat(wheel) == wing::WsHeartbeatAction.None, "Idle timer was reset by touch");
        sub.assert_false(ws.is_closed, "Session remains open");
    };
}

fn test_subscription_counts_and_topics(t: lit::T&) {
    t.run("1. Subscription Count Lifecycle (Room Creation / Destruction)") { sub =>
        var server = wing::new_http_server("127.0.0.1", 8080);
        var old_cnt: i32 = -1;
        var new_cnt: i32 = -1;

        // Socket 10 joins room
        let ok1 = server.subscribe_ex(10, "chat/gaming", old_cnt, new_cnt);
        sub.assert_true(ok1, "Socket 10 subscribed");
        sub.assert_eq(old_cnt, 0, "Old count 0: Room created");
        sub.assert_eq(new_cnt, 1, "New count 1");

        // Socket 20 joins room
        let ok2 = server.subscribe_ex(20, "chat/gaming", old_cnt, new_cnt);
        sub.assert_true(ok2, "Socket 20 subscribed");
        sub.assert_eq(old_cnt, 1, "Old count 1");
        sub.assert_eq(new_cnt, 2, "New count 2");

        // Socket 10 leaves room
        let ok3 = server.unsubscribe_ex(10, "chat/gaming", old_cnt, new_cnt);
        sub.assert_true(ok3, "Socket 10 unsubscribed");
        sub.assert_eq(old_cnt, 2, "Old count 2");
        sub.assert_eq(new_cnt, 1, "New count 1");

        // Socket 20 leaves room
        let ok4 = server.unsubscribe_ex(20, "chat/gaming", old_cnt, new_cnt);
        sub.assert_true(ok4, "Socket 20 unsubscribed");
        sub.assert_eq(old_cnt, 1, "Old count 1");
        sub.assert_eq(new_cnt, 0, "New count 0: Room destroyed/empty");
    };

    t.run("2. Per-Socket Topic Enumeration") { sub =>
        var server = wing::new_http_server("127.0.0.1", 8080);
        server.subscribe(42, "feed/crypto");
        server.subscribe(42, "feed/stocks");
        server.subscribe(42, "news/#");

        let cnt = server.get_socket_topic_count(42);
        sub.assert_eq(cnt, 3, "Socket 42 has 3 subscriptions");

        var topics: u8[..64][..32] = [];
        let fetched = server.get_socket_topics(42, topics);
        sub.assert_eq(fetched, 3, "Fetched 3 topics");
        sub.assert_eq(topics[0][..], "feed/crypto", "First topic matches");
        sub.assert_eq(topics[1][..], "feed/stocks", "Second topic matches");
        sub.assert_eq(topics[2][..], "news/#", "Third topic matches");

        server.unsubscribe(42, "feed/stocks");
        sub.assert_eq(server.get_socket_topic_count(42), 2, "Count decremented to 2 after unsub");
    };
}

fn test_async_upgrade_and_aborted(t: lit::T&) {
    t.run("1. Asynchronous Upgrade with UserData & UserTag") { sub =>
        var server = wing::new_http_server("127.0.0.1", 8080);
        var ws_cfg = wing::new_ws_behavior(50);
        ws_cfg.subprotocol.append("v1.stream");
        server.add_ws_route("/ws/stream", ws_cfg);

        var req = wing::new_request("GET", "/ws/stream");
        req.set_header("Upgrade", "websocket");
        req.set_header("Connection", "Upgrade");
        req.set_header("Sec-WebSocket-Key", "dGhlIHNhbXBsZSBub25jZQ==");
        req.set_header("Sec-WebSocket-Version", "13");
        req.set_header("Sec-WebSocket-Protocol", "v1.stream");

        // Defer upgrade while performing async auth / DB lookup
        var pending, ok_defer = server.defer_ws_upgrade(req, 99);
        sub.assert_true(ok_defer, "defer_ws_upgrade succeeded");
        sub.assert_eq(pending.sock_fd, 99, "Pending sock_fd preserved");
        sub.assert_false(pending.is_aborted, "Pending not aborted");

        pending.set_user_tag(123456789);
        pending.set_user_data("auth:user_jwt_token");

        // Async task completes: finalize upgrade
        var wire_out: u8[..2048] = [];
        var sess, ok_comp = server.complete_ws_upgrade(pending, wire_out);
        sub.assert_true(ok_comp, "complete_ws_upgrade succeeded");
        sub.assert_eq(sess.user_tag, 123456789, "UserTag passed to session");
        sub.assert_eq(sess.user_data[..], "auth:user_jwt_token", "UserData passed to session");

        let wire_str = wire_out[..];
        sub.assert_true(core::contains(wire_str, "HTTP/1.1 101 Switching Protocols\r\n"), "Status 101");
        sub.assert_true(core::contains(wire_str, "Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n"), "Accept key");
        sub.assert_true(core::contains(wire_str, "Sec-WebSocket-Protocol: v1.stream\r\n"), "Protocol echoed");
    };

    t.run("2. Asynchronous Upgrade Aborted by Client Disconnect") { sub =>
        var server = wing::new_http_server("127.0.0.1", 8080);
        var ws_cfg = wing::new_ws_behavior(50);
        server.add_ws_route("/ws/abortable", ws_cfg);

        var req = wing::new_request("GET", "/ws/abortable");
        req.set_header("Upgrade", "websocket");
        req.set_header("Connection", "Upgrade");
        req.set_header("Sec-WebSocket-Key", "dGhlIHNhbXBsZSBub25jZQ==");
        req.set_header("Sec-WebSocket-Version", "13");

        var pending, _ = server.defer_ws_upgrade(req, 100);
        // Client disconnects before async auth resolves
        pending.abort();
        sub.assert_true(pending.is_aborted, "Pending marked aborted");

        var wire_out: u8[..2048] = [];
        var sess, ok_comp = server.complete_ws_upgrade(pending, wire_out);
        sub.assert_false(ok_comp, "Aborted upgrade returns false and does not write 101");
        sub.assert_eq(wire_out.len, 0, "No wire bytes written");
    };
}

fn test_loop_defer_and_dedicated_compressor(t: lit::T&) {
    t.run("1. EventLoop Task Deferral (loop.defer)") { sub =>
        var cfg = internal::auto_transport_driver_config();
        cfg.active_kind = internal::TransportDriverKind.Standard;

        var el = wing::new_event_loop(cfg);
        sub.assert_false(el.has_deferred_tasks(), "No deferred tasks initially");

        // External thread schedules work on event loop
        let ok1 = el.defer_task(1001, 42, 1);
        let ok2 = el.defer_task(1002, 84, 2);
        sub.assert_true(ok1, "First task deferred");
        sub.assert_true(ok2, "Second task deferred");
        sub.assert_true(el.has_deferred_tasks(), "Has deferred tasks");
        sub.assert_eq(el.deferred_count, 2, "Count is 2");

        var count_dispatched: u32 = 0;
        let drained = wing::drain_deferred_tasks(el) { tag, udata, tid, loop_ref =>
            count_dispatched += 1;
        };
        sub.assert_eq(drained, 2, "Drained 2 tasks");
        sub.assert_eq(count_dispatched, 2, "Dispatched 2 tasks");
        sub.assert_false(el.has_deferred_tasks(), "Queue empty after drain");

        wing::close_event_loop(el);
    };

    t.run("2. Dedicated Sliding-Window Compressor") { sub =>
        var ded = wing::new_dedicated_ws_compressor(32);
        let sample = "Dedicated compressor stream message with repetitive patterns pattern pattern pattern";

        var wire_comp: u8[..1024] = [];
        let ok_c = ded.deflate_message_dedicated(sample, wire_comp);
        sub.assert_true(ok_c, "Dedicated deflate succeeded");
        sub.assert_gt(wire_comp.len, 0, "Compressed output non-empty");

        var plain: u8[..1024] = [];
        let ok_d = ded.inflate_message_dedicated(wire_comp[..], plain);
        sub.assert_true(ok_d, "Dedicated inflate succeeded");
        sub.assert_eq(plain[..], sample, "Inflated content matches original input");
    };
}

// --- Component: compat_uweb_optimizations ---
// Verification suite for optimizations in goose-wing:
// 1. 256-bit Header BloomFilter and fast case-insensitive rejection
// 2. Fast HTTP/1.1 response serialization with pre-formatted status lines
// 3. Zero-Copy WebSocket frame ingress (WsMessageView)
// 4. Shared receive buffer and direct slice streaming

fn test_header_bloom_filter(t: lit::T&) {
    t.run("1. 256-bit Header BloomFilter Bitwise Rejection") { sub =>
        var bf = wing::HeaderBloomFilter { .. };
        wing::add_header(bf, "Content-Type");
        wing::add_header(bf, "Host");
        wing::add_header(bf, "Connection");
        wing::add_header(bf, "X-Custom-Auth");

        // Case-insensitive positive checks
        sub.assert_true(wing::might_have_header(bf, "content-type"), "Matches lowercase content-type");
        sub.assert_true(wing::might_have_header(bf, "CONTENT-TYPE"), "Matches uppercase CONTENT-TYPE");
        sub.assert_true(wing::might_have_header(bf, "Content-Type"), "Matches mixed-case Content-Type");
        sub.assert_true(wing::might_have_header(bf, "host"), "Matches host");
        sub.assert_true(wing::might_have_header(bf, "connection"), "Matches connection");
        sub.assert_true(wing::might_have_header(bf, "x-custom-auth"), "Matches x-custom-auth");

        // Negative checks: must be rejected with 0 string comparisons
        sub.assert_false(wing::might_have_header(bf, "sec-websocket-key"), "Rejects missing sec-websocket-key in 3 cycles");
        sub.assert_false(wing::might_have_header(bf, "authorization"), "Rejects missing authorization in 3 cycles");
        sub.assert_false(wing::might_have_header(bf, "upgrade"), "Rejects missing upgrade in 3 cycles");
        sub.assert_false(wing::might_have_header(bf, "transfer-encoding"), "Rejects missing transfer-encoding in 3 cycles");
    };

    t.run("2. Request Struct with Integrated BloomFilter") { sub =>
        var req = wing::new_request("GET", "/api/v1/status");
        req.set_header("Host", "api.example.com");
        req.set_header("Accept", "application/json");

        sub.assert_true(req.has_header("host"), "Request has host");
        sub.assert_true(req.has_header("ACCEPT"), "Request has ACCEPT (case-insensitive)");
        sub.assert_eq(req.header("accept"), "application/json", "Header value retrieved");

        // Missing headers return false / empty without iterating all headers
        sub.assert_false(req.has_header("cookie"), "Cookie fast-rejected");
        sub.assert_eq(req.header("cookie"), "", "Empty string for missing cookie");
    };
}

fn test_fast_serialization(t: lit::T&) {
    t.run("1. Pre-formatted 200 OK Status Line & Content-Length 0") { sub =>
        var res = wing::Response { .. };
        res.status_code = 200;

        var wire: u8[>..] = [];
        wing::serialize_http1_response(res, "goose-wing", wire);

        let wire_str = wire[..];
        sub.assert_true(find(wire_str, "HTTP/1.1 200 OK\r\n") == 0, "Status line uses pre-formatted 200 OK");
        sub.assert_true(find(wire_str, "Content-Length: 0\r\n") >= 0, "Zero-length body emits Content-Length: 0 without decimal format loop");
        sub.assert_true(find(wire_str, "Connection: keep-alive\r\n") >= 0, "Default keep-alive emitted");
    };
}

fn test_zero_copy_websocket_view(t: lit::T&) {
    t.run("1. Zero-Copy Ingress via WsMessageView") { sub =>
        var ws = wing::new_websocket_session(false); // server session
        let mask: u8[4] = [0x11, 0x22, 0x33, 0x44];

        var wire_frame: u8[>..] = [];
        wing::encode_ws_frame(wire_frame, wing::WS_OPCODE_TEXT, "Zero-Copy Ingress Payload", true, mask, true);

        var view = wing::WsMessageView { .. };
        var reply: u8[>..] = [];

        // Receive directly into non-owning view
        let ok = ws.receive_view(wire_frame[..], view, reply);
        sub.assert_true(ok, "ws.receive_view succeeds");
        sub.assert_true(view.is_valid, "Message marked valid");
        sub.assert_eq(view.opcode, wing::WS_OPCODE_TEXT, "Opcode is TEXT");
        sub.assert_bytes_eq(view.payload, "Zero-Copy Ingress Payload", "Payload matches wire data without copying into heap or local buffer");

        // Ping auto-reply via view
        var ping_wire: u8[>..] = [];
        wing::encode_ws_frame(ping_wire, wing::WS_OPCODE_PING, "heartbeat", true, mask, true);

        var ping_view = wing::WsMessageView { .. };
        var pong_out: u8[>..] = [];
        let ok_ping = ws.receive_view(ping_wire[..], ping_view, pong_out);
        sub.assert_true(ok_ping, "Ping processed");
        sub.assert_eq(ping_view.opcode, wing::WS_OPCODE_PING, "Ping opcode");
        sub.assert_bytes_eq(ping_view.payload, "heartbeat", "Ping payload matched");
        sub.assert_true(pong_out.len > 0, "Pong reply generated automatically");
    };
}

fn test_shared_tcp_buffer(t: lit::T&) {
    t.run("1. Live TCP Direct Slice Recv") { sub =>
        let listener = wing::tcp_listen("127.0.0.1", 0, 16);
        sub.assert_gt(listener, 0, "Listener created");
        let port = wing::tcp_getsockname_port(listener);

        let client = wing::tcp_connect("127.0.0.1", port, 2000);
        sub.assert_gt(client, 0, "Client connected");

        let srv_sock = wing::tcp_accept(listener, 2000);
        sub.assert_gt(srv_sock, 0, "Server accepted");

        // Client sends payload
        let payload = "ZERO_COPY_TCP_PAYLOAD_TEST";
        wing::tcp_send(client, payload);

        // Server receives directly into preallocated slice without stack memset
        var srv_storage: u8[256] = [0; 256];
        let recvd = wing::tcp_recv_slice(srv_sock, srv_storage[..], 2000);
        sub.assert_eq(recvd, payload.len as i32, "Direct slice received all bytes");
        sub.assert_bytes_eq(srv_storage[..recvd], payload, "Storage content matches sent payload");

        wing::tcp_close(client);
        wing::tcp_close(srv_sock);
        wing::tcp_close(listener);
    };
}

fn test_topic_tree_pubsub(t: lit::T&) {
    t.run("1. Exact and Wildcard MQTT Pattern Matching") { sub =>
        var tree = wing::TopicTree { .. };

        // Register subscribers with distinct socket descriptors
        sub.assert_true(tree.subscribe(101, "chat/general"), "Sub 101 to exact chat/general");
        sub.assert_true(tree.subscribe(102, "chat/+"), "Sub 102 to single-level wildcard chat/+");
        sub.assert_true(tree.subscribe(103, "sensors/#"), "Sub 103 to multi-level wildcard sensors/#");
        sub.assert_true(tree.subscribe(104, "#"), "Sub 104 to global root wildcard #");

        sub.assert_eq(tree.active_subscriptions, 4, "4 active subscriptions in pool");
        sub.assert_true(tree.is_subscribed(101, "chat/general"), "101 is subscribed to chat/general");
        sub.assert_false(tree.is_subscribed(101, "chat/random"), "101 is not subscribed to chat/random");

        // Query subscribers for "chat/general":
        // Should match: 101 (exact), 102 (chat/+), 104 (#). Total: 3
        var subs_gen: i64[..512] = [];
        let count_gen = tree.find_subscribers("chat/general", subs_gen);
        sub.assert_eq(count_gen, 3, "chat/general matches 3 subscribers");
        sub.assert_true(subs_gen.contains(101), "Contains 101");
        sub.assert_true(subs_gen.contains(102), "Contains 102");
        sub.assert_true(subs_gen.contains(104), "Contains 104");
        sub.assert_false(subs_gen.contains(103), "Does not contain 103");

        // Query subscribers for "sensors/room1/temp":
        // Should match: 103 (sensors/#), 104 (#). Total: 2
        var subs_temp: i64[..512] = [];
        let count_temp = tree.find_subscribers("sensors/room1/temp", subs_temp);
        sub.assert_eq(count_temp, 2, "sensors/room1/temp matches 2 subscribers");
        sub.assert_true(subs_temp.contains(103), "Contains 103");
        sub.assert_true(subs_temp.contains(104), "Contains 104");
    };

    t.run("2. Subscriber Deduplication across Overlapping Patterns") { sub =>
        var tree = wing::TopicTree { .. };

        // Socket 200 subscribes to multiple overlapping wildcard topics
        tree.subscribe(200, "market/#");
        tree.subscribe(200, "market/+");
        tree.subscribe(200, "market/btc");

        var matched: i64[..512] = [];
        let count = tree.find_subscribers("market/btc", matched);
        sub.assert_eq(count, 1, "Socket 200 delivered exactly once despite 3 overlapping matches");
        sub.assert_eq(matched[0], 200, "Matched socket is 200");
    };

    t.run("3. Unsubscribe and Complete Connection Teardown") { sub =>
        var tree = wing::TopicTree { .. };

        tree.subscribe(301, "news/sport");
        tree.subscribe(301, "news/weather");
        tree.subscribe(302, "news/sport");

        sub.assert_eq(tree.active_subscriptions, 3, "3 subscriptions registered");

        // Unsubscribe 301 from one topic
        let ok_unsub = tree.unsubscribe(301, "news/sport");
        sub.assert_true(ok_unsub, "Unsubscribed 301 from news/sport");
        sub.assert_eq(tree.subscriber_count("news/sport"), 1, "1 remaining subscriber on news/sport");

        // Connection disconnect: unsubscribe_all removes all remaining topics for 301
        let unsubs_all = tree.unsubscribe_all(301);
        sub.assert_eq(unsubs_all, 1, "Removed 1 remaining topic on unsubscribe_all");
        sub.assert_false(tree.is_subscribed(301, "news/weather"), "301 no longer subscribed to weather");

        // Clean up 302
        tree.unsubscribe_all(302);
        sub.assert_eq(tree.active_subscriptions, 0, "All subscriptions cleanly freed");
        sub.assert_eq(tree.active_buckets, 0, "All empty buckets reclaimed");
    };
}

fn test_vectored_io(t: lit::T&) {
    t.run("1. Zero-Copy HTTP Response via Vectored I/O (tcp_send2)") { sub =>
        let listener = wing::tcp_listen("127.0.0.1", 0, 16);
        sub.assert_gt(listener, 0, "Listener created");
        let port = wing::tcp_getsockname_port(listener);

        let client = wing::tcp_connect("127.0.0.1", port, 2000);
        sub.assert_gt(client, 0, "Client connected");

        let srv_sock = wing::tcp_accept(listener, 2000);
        sub.assert_gt(srv_sock, 0, "Server accepted");

        // 1. Direct tcp_send2 with separate header and payload slices
        let hdr_part = "HDR_PART;";
        let body_part = "BODY_PART_VECTORED_IO";
        let sent2 = wing::tcp_send2(srv_sock, hdr_part, body_part);
        sub.assert_eq(sent2, (hdr_part.len + body_part.len) as i32, "tcp_send2 sent both slices in 1 call");

        var client_buf: u8[256] = [0; 256];
        let recvd = wing::tcp_recv_slice(client, client_buf[..], 2000);
        sub.assert_eq(recvd, (hdr_part.len + body_part.len) as i32, "Client received combined slices");
        sub.assert_bytes_eq(client_buf[..recvd], "HDR_PART;BODY_PART_VECTORED_IO", "Data matches concatenation without memory copy");

        // 2. Full HTTP response via send_http1_response (zero-copy body)
        var res = wing::Response { .. };
        res.status_code = 200;
        res.set_header("Content-Type", "text/plain");
        res.body.append("HELLO_VECTORED_WORLD");

        var wire_headers: u8[..1024] = [];
        let sent_res = wing::send_http1_response(srv_sock, res, "goose-wing", wire_headers);
        sub.assert_gt(sent_res, 0, "send_http1_response transmitted bytes");

        var resp_buf: u8[1024] = [0; 1024];
        let recvd_resp = wing::tcp_recv_slice(client, resp_buf[..], 2000);
        sub.assert_gt(recvd_resp, 0, "Client received response");
        let resp_slice = resp_buf[..recvd_resp];
        sub.assert_true(find(resp_slice, "HTTP/1.1 200 OK\r\n") == 0, "Starts with 200 OK");
        sub.assert_true(find(resp_slice, "HELLO_VECTORED_WORLD") >= 0, "Body received intact");

        wing::tcp_close(client);
        wing::tcp_close(srv_sock);
        wing::tcp_close(listener);
    };
}

fn test_server_cork_buffer(t: lit::T&) {
    t.run("1. 16 KB CorkBuffer Syscall Coalescing") { sub =>
        let listener = wing::tcp_listen("127.0.0.1", 0, 16);
        sub.assert_gt(listener, 0, "Listener created");
        let port = wing::tcp_getsockname_port(listener);

        let client = wing::tcp_connect("127.0.0.1", port, 2000);
        sub.assert_gt(client, 0, "Client connected");

        let srv_sock = wing::tcp_accept(listener, 2000);
        sub.assert_gt(srv_sock, 0, "Server accepted");

        var cork = wing::new_server_cork(srv_sock);
        wing::server_cork_write(cork, "alpha;");
        wing::server_cork_write(cork, "beta;");
        wing::server_cork_write(cork, "gamma;");
        wing::server_cork_write2(cork, "delta;", "epsilon;");

        // 4 writes (5 items) are coalesced into the 16 KB buffer without network transmission
        sub.assert_eq(core::cork_pending(cork.buffer), 31, "31 bytes buffered in cork");

        // Flush cork buffer in 1 syscall
        let flushed = wing::server_cork_flush(cork);
        sub.assert_eq(flushed, 31, "31 bytes flushed to socket in 1 syscall");
        sub.assert_eq(core::cork_pending(cork.buffer), 0, "Cork buffer is empty after flush");

        var recv_storage: u8[128] = [0; 128];
        let recvd = wing::tcp_recv_slice(client, recv_storage[..], 2000);
        sub.assert_eq(recvd, 31, "Client received all coalesced bytes at once");
        sub.assert_bytes_eq(recv_storage[..recvd], "alpha;beta;gamma;delta;epsilon;", "Coalesced data verified");

        // Test server_cork_write_response (zero-copy headers + body)
        var res = wing::Response { .. };
        res.status_code = 200;
        res.body.append("cork body test");
        let wr_res = wing::server_cork_write_response(cork, res, "goose-wing");
        sub.assert_gt(wr_res, 0, "Response written to cork");
        wing::server_cork_flush(cork);
        var resp_buf: u8[512] = [0; 512];
        let recvd_res = wing::tcp_recv_slice(client, resp_buf[..], 2000);
        sub.assert_gt(recvd_res, 0, "Client received response");
        sub.assert_true(find(resp_buf[..recvd_res], "HTTP/1.1 200 OK") >= 0, "Status line 200 present");
        sub.assert_true(find(resp_buf[..recvd_res], "cork body test") >= 0, "Body present");

        wing::tcp_close(client);
        wing::tcp_close(srv_sock);
        wing::tcp_close(listener);
    };
}

fn test_handshake_and_date_and_swar_utf8(t: lit::T&) {
    t.run("1. Unrolled 2-Block WebSocket Handshake Accept Key") { sub =>
        let test_key = "dGhlIHNhbXBsZSBub25jZQ==";
        var accept_key: u8[..64] = [];
        wing::compute_websocket_accept(test_key, accept_key);
        sub.assert_eq(accept_key[..], "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=", "Exact RFC 6455 accept key generated via 2-block SHA-1");

        // Validate acceptance helper
        sub.assert_true(wing::validate_websocket_accept(test_key, "s3pPLMBiTxaQ9kYGzzhZRbK+xOo="), "Validation succeeds");
        sub.assert_false(wing::validate_websocket_accept(test_key, "invalid_accept_key"), "Validation rejects mismatch");
    };

    t.run("2. Cached RFC 7231 Date Header Generation") { sub =>
        let date_hdr = wing::get_cached_http_date_header(1700000000); // Fixed epoch 2023-11-14 22:13:20 GMT
        sub.assert_true(find(date_hdr, "Date: ") == 0, "Header starts with Date: ");
        sub.assert_true(find(date_hdr, "GMT\r\n") > 0, "Header ends with GMT CRLF");

        // Check response serialization automatically includes Date
        var res = wing::Response { .. };
        res.status_code = 200;
        var wire: u8[..512] = [];
        wing::serialize_http1_headers(res, "goose-wing", wire);
        sub.assert_true(find(wire[..], "Date: ") >= 0, "HTTP/1.1 response includes Date header");
    };

    t.run("3. 16-byte SWAR ASCII Skip UTF-8 Validator") { sub =>
        // Pure 7-bit ASCII (should fast-skip in 16-byte words)
        let ascii_text = "This is a 64-byte purely ASCII test payload for SWAR verification!";
        sub.assert_true(core::validate_utf8(ascii_text), "ASCII text validated");

        // Mixed ASCII and multi-byte UTF-8 (Russian, CJK, Emoji)
        let mixed_text = "{\"user\": \"Иван\", \"status\": \"🚀 success\", \"code\": 200}";
        sub.assert_true(core::validate_utf8(mixed_text), "Mixed ASCII and UTF-8 validated");

        // Invalid UTF-8 sequence (truncated byte)
        let invalid_utf8: u8[4] = [0xD0, 0x98, 0xD0, 0x00]; // 0xD0 followed by 0x00 is invalid
        sub.assert_false(core::validate_utf8(invalid_utf8[..]), "Invalid multi-byte rejected");
    };
}

fn test_fast_query_parser(t: lit::T&) {
    t.run("1. Zero-Allocation Targeted Query Parameter Lookup") { sub =>
        let query_str = "?filter=active&search=hello+world%21&debug&empty=&limit=50";

        // 1. Direct targeted retrieval with percent decoding
        var search_val: u8[..64] = [];
        let found_search, is_valueless_search = core::get_query_param_fast(query_str, "search", search_val);
        sub.assert_true(found_search, "Found 'search'");
        sub.assert_false(is_valueless_search, "'search' has a value");
        sub.assert_bytes_eq(search_val[..], "hello+world!", "+ preserved verbatim per RFC 3986 and %21 to !");

        // 2. Valueless query parameter ("?debug") vs empty value ("?empty=")
        var debug_val: u8[..64] = [];
        let found_debug, is_valueless_debug = core::get_query_param_fast(query_str, "debug", debug_val);
        sub.assert_true(found_debug, "Found 'debug'");
        sub.assert_true(is_valueless_debug, "'debug' correctly recognized as valueless parameter");

        var empty_val: u8[..64] = [];
        let found_empty, is_valueless_empty = core::get_query_param_fast(query_str, "empty", empty_val);
        sub.assert_true(found_empty, "Found 'empty'");
        sub.assert_false(is_valueless_empty, "'empty' has an empty value (not valueless)");
        sub.assert_eq(empty_val.len, 0, "empty value length is 0");

        // 3. Fast existence checks
        sub.assert_true(core::has_query_param_fast(query_str, "filter"), "Has filter");
        sub.assert_true(core::has_query_param_fast(query_str, "limit"), "Has limit");
        sub.assert_false(core::has_query_param_fast(query_str, "missing"), "Missing param returns false");
    };
}

fn test_epoll_reactor_multiplexer(t: lit::T&) {
    t.run("1. Non-blocking Epoll Reactor Multiplexing Across Multiple Sockets") { sub =>
        let listener = wing::tcp_listen("127.0.0.1", 0, 16);
        sub.assert_gt(listener, 0, "Listener created");
        let port = wing::tcp_getsockname_port(listener);
        sub.assert_true(wing::tcp_set_nonblocking(listener, true), "Listener configured non-blocking");

        let epfd = wing::epoll_create();
        sub.assert_gt(epfd, 0, "Epoll reactor created");

        let ok_add_l = wing::epoll_add(epfd, listener, wing::EPOLL_READ, wing::EPOLL_LISTENER_TAG);
        sub.assert_true(ok_add_l, "Listener added to epoll");

        // Connect 2 clients concurrently
        let c1 = wing::tcp_connect("127.0.0.1", port, 2000);
        let c2 = wing::tcp_connect("127.0.0.1", port, 2000);
        sub.assert_gt(c1, 0, "Client 1 connected");
        sub.assert_gt(c2, 0, "Client 2 connected");

        // Harvest accept readiness
        var ready_fds:   i64[..16] = [];
        var ready_udata: u64[..16] = [];
        let n_accept = wing::epoll_wait(epfd, ready_fds, ready_udata, 2000);
        sub.assert_gt(n_accept, 0, "Accept readiness harvested by epoll_wait");

        var accepted_socks: i64[..8] = [];
        while true {
            let s = wing::tcp_accept_nonblocking(listener);
            if s <= 0 { break; }
            wing::tcp_set_nonblocking(s, true);
            accepted_socks.push(s);
        }
        sub.assert_eq(accepted_socks.len, 2, "Both client sockets accepted non-blocking");

        // Register accepted sockets in epoll with unique udata tags
        wing::epoll_add(epfd, accepted_socks[0], wing::EPOLL_READ, 101);
        wing::epoll_add(epfd, accepted_socks[1], wing::EPOLL_READ, 102);

        // Clients send messages
        wing::tcp_send(c1, "PING_ONE");
        wing::tcp_send(c2, "PING_TWO");

        // Reactor harvests read readiness for both sockets in 1 single epoll_wait call
        ready_fds.clear();
        ready_udata.clear();
        let n_data = wing::epoll_wait(epfd, ready_fds, ready_udata, 2000);
        sub.assert_gt(n_data, 0, "Data readiness events harvested");

        var recvd_1 = false;
        var recvd_2 = false;

        for i in ready_udata.len {
            let tag = ready_udata[i];
            if tag == 101 {
                var buf: u8[..128] = [];
                let r = wing::tcp_recv_nonblocking(accepted_socks[0], buf);
                sub.assert_eq(r, 8, "8 bytes read from sock 0");
                sub.assert_bytes_eq(buf[..], "PING_ONE", "Matches PING_ONE");
                recvd_1 = true;
            } else if tag == 102 {
                var buf: u8[..128] = [];
                let r = wing::tcp_recv_nonblocking(accepted_socks[1], buf);
                sub.assert_eq(r, 8, "8 bytes read from sock 1");
                sub.assert_bytes_eq(buf[..], "PING_TWO", "Matches PING_TWO");
                recvd_2 = true;
            }
        }

        sub.assert_true(recvd_1, "Socket 0 processed non-blocking in reactor");
        sub.assert_true(recvd_2, "Socket 1 processed non-blocking in reactor");

        // Clean up
        wing::epoll_del(epfd, accepted_socks[0]);
        wing::epoll_del(epfd, accepted_socks[1]);
        wing::epoll_del(epfd, listener);
        wing::epoll_close(epfd);

        wing::tcp_close(c1);
        wing::tcp_close(c2);
        wing::tcp_close(accepted_socks[0]);
        wing::tcp_close(accepted_socks[1]);
        wing::tcp_close(listener);
    };
}

fn test_swar_ctl_scanner(t: lit::T&) {
    t.run("1. SWAR hasLess 64-bit Parallel Control Character Scanning") { sub =>
        // Pure printable ASCII
        let clean = "Host: api.example.com:8080";
        let offset_clean = core::swar_find_ctl(clean);
        sub.assert_eq(offset_clean, clean.len, "No CTL found in clean string");

        // CRLF at offset 16 (on an 8-byte boundary)
        let crlf_16 = "1234567812345678\r\nRestOfHeader";
        let offset_16 = core::swar_find_ctl(crlf_16);
        sub.assert_eq(offset_16, 16, "CRLF found at boundary offset 16");

        // CRLF at odd offset 7
        let crlf_7 = "1234567\r\nRestOfHeader";
        let offset_7 = core::swar_find_ctl(crlf_7);
        sub.assert_eq(offset_7, 7, "CRLF found at offset 7");

        // Embedded NUL at offset 3
        var with_nul: u8[..16] = [];
        with_nul.append("abc");
        with_nul.push(0);
        with_nul.append("defgh");
        let offset_nul = core::swar_find_ctl(with_nul[..]);
        sub.assert_eq(offset_nul, 3, "NUL byte detected at offset 3");

        // Long string (40 bytes) with CR at byte 33
        var long_str: u8[..48] = [];
        for _ in 33 { long_str.push('a'); }
        long_str.push('\r');
        long_str.push('\n');
        let offset_long = core::swar_find_ctl(long_str[..]);
        sub.assert_eq(offset_long, 33, "Long string scanned across 5 64-bit words finds CR at 33");
    };
}

fn test_fast_integer_ascii_serializers(t: lit::T&) {
    t.run("1. Fast u64toa and u32toa_hex") { sub =>
        var buf: u8[32] = [0; 32];

        // u64toa zero
        let n0 = core::fast_u64toa(0, buf[..]);
        sub.assert_eq(n0, 1, "0 length is 1");
        sub.assert_bytes_eq(buf[..n0], "0", "0 formatted");

        // u64toa small
        let n42 = core::fast_u64toa(42, buf[..]);
        sub.assert_eq(n42, 2, "42 length is 2");
        sub.assert_bytes_eq(buf[..n42], "42", "42 formatted");

        // u64toa HTTP Content-Length typical (8192)
        let n_cl = core::fast_u64toa(8192, buf[..]);
        sub.assert_eq(n_cl, 4, "8192 length is 4");
        sub.assert_bytes_eq(buf[..n_cl], "8192", "8192 formatted");

        // u64toa large
        let n_large = core::fast_u64toa(1234567890123456789, buf[..]);
        sub.assert_eq(n_large, 19, "Large int length is 19");
        sub.assert_bytes_eq(buf[..n_large], "1234567890123456789", "Large int matches");

        // u32toa_hex zero
        let h0 = core::fast_u32toa_hex(0, buf[..]);
        sub.assert_eq(h0, 1, "hex 0 length is 1");
        sub.assert_bytes_eq(buf[..h0], "0", "hex 0 matches");

        // u32toa_hex 15 ("f")
        let h15 = core::fast_u32toa_hex(15, buf[..]);
        sub.assert_eq(h15, 1, "hex 15 length is 1");
        sub.assert_bytes_eq(buf[..h15], "f", "hex 15 is 'f'");

        // u32toa_hex 16 ("10")
        let h16 = core::fast_u32toa_hex(16, buf[..]);
        sub.assert_eq(h16, 2, "hex 16 length is 2");
        sub.assert_bytes_eq(buf[..h16], "10", "hex 16 is '10'");

        // u32toa_hex 0xDEADBEEF ("deadbeef")
        let h_dead = core::fast_u32toa_hex(0xDEADBEEF, buf[..]);
        sub.assert_eq(h_dead, 8, "0xDEADBEEF length is 8");
        sub.assert_bytes_eq(buf[..h_dead], "deadbeef", "0xDEADBEEF is 'deadbeef'");
    };
}

fn test_ws_unmask_shifted_header_overwrite(t: lit::T&) {
    t.run("1. In-Place Zero-Copy Unmasking with Header Overwrite") { sub =>
        let mask: u8[4] = [0xAA, 0xBB, 0xCC, 0xDD];
        let original_msg = "Hello, zero-copy WebSocket world with shifted header overwrite!";

        // Build a masked client frame: 6-byte header + payload
        var frame: u8[..256] = [];
        wing::encode_ws_frame(frame, wing::WS_OPCODE_TEXT, original_msg, true, mask, true);

        let hdr, ok_hdr = wing::parse_ws_frame_header(frame[..]);
        sub.assert_true(ok_hdr, "Frame header parsed");
        sub.assert_eq(hdr.header_len, 6, "Header length is 6 bytes");
        sub.assert_eq(hdr.payload_len as i64, original_msg.len, "Payload length matches");

        // Shift unmask directly over frame header
        let unmasked = wing::unmask_websocket_shifted(
            frame[..],
            hdr.header_len as i64,
            hdr.payload_len as i64,
            hdr.mask_key,
        );

        sub.assert_eq(unmasked.len, original_msg.len, "Unmasked length matches");
        sub.assert_bytes_eq(unmasked, original_msg, "Unmasked payload matches original plaintext");

        // Verify unmasked data starts at frame[0]
        sub.assert_bytes_eq(frame[..original_msg.len], original_msg, "Header was cleanly overwritten in-place at index 0");
    };
}

fn test_chunked_fsm_decoder(t: lit::T&) {
    t.run("1. 64-bit Register FSM Chunked Stream Decoding") { sub =>
        var dec = internal::new_chunk_fsm_decoder();

        let raw = "4\r\nWiki\r\n7\r\npedia  \r\nE\r\nin \r\n\r\nchunks.\r\n0\r\n\r\n";
        var total_body: u8[..128] = [];
        var cursor:     i64       = 0;

        while cursor < raw.len {
            let st, consumed, chunk = internal::chunk_fsm_feed(dec, raw[cursor..]);
            cursor += consumed;

            if st == internal::ChunkFsmStatus.YieldChunk {
                total_body.append(chunk);
            } else if st == internal::ChunkFsmStatus.Complete {
                break;
            } else if st == internal::ChunkFsmStatus.Error {
                sub.assert_true(false, "FSM decoder encountered unexpected error");
                break;
            }
        }

        sub.assert_bytes_eq(total_body[..], "Wikipedia  in \r\n\r\nchunks.", "Assembled chunked stream matches");

        // Chunk extensions
        var dec_ext = internal::new_chunk_fsm_decoder();
        let raw_ext = "5;token=val;foo=\"quoted;val\"\r\nHello\r\n0\r\n\r\n";
        var ext_body:   u8[..64] = [];
        var ext_cursor: i64      = 0;

        while ext_cursor < raw_ext.len {
            let st, consumed, chunk = internal::chunk_fsm_feed(dec_ext, raw_ext[ext_cursor..]);
            ext_cursor += consumed;
            if st == internal::ChunkFsmStatus.YieldChunk {
                ext_body.append(chunk);
            } else if st == internal::ChunkFsmStatus.Complete {
                break;
            }
        }
        sub.assert_bytes_eq(ext_body[..], "Hello", "Chunk extension decoded properly");

        // Invalid hex chunk size
        var dec_err = internal::new_chunk_fsm_decoder();
        let st_err, _, _ = internal::chunk_fsm_feed(dec_err, "Z\r\n");
        sub.assert_eq(st_err, internal::ChunkFsmStatus.Error, "Invalid hex digit returns Error");
    };
}

fn test_http_route_cache(t: lit::T&) {
    t.run("1. Dual-Expiry Coalescing HTTP Route Cache") { sub =>
        var cache = wing::new_http_route_cache(1000, 5000);

        // Initially empty
        let initial = wing::cache_lookup(cache, 100);
        sub.assert_eq(initial, wing::CacheLookup.Miss, "Empty cache returns Miss");

        // Store rendered response
        let wire_sample = "HTTP/1.1 200 OK\r\nContent-Length: 13\r\n\r\nCached Hello!";
        let ok_store = wing::cache_store(cache, 1000, wire_sample);
        sub.assert_true(ok_store, "Response cached successfully");

        // Fresh hit (within lower_expiry 1000ms: at t=1500)
        let hit_fresh = wing::cache_lookup(cache, 1500);
        sub.assert_eq(hit_fresh, wing::CacheLookup.HitFresh, "Lookup at t=1500 is Fresh Hit");
        sub.assert_bytes_eq(cache.wire[..], wire_sample, "Cached wire matches");

        // Stale hit (between 1000ms and 5000ms: at t=3000)
        let hit_stale = wing::cache_lookup(cache, 3000);
        sub.assert_eq(hit_stale, wing::CacheLookup.HitStaleNeedsUpdate, "Lookup at t=3000 is Stale Hit");
        sub.assert_bytes_eq(cache.wire[..], wire_sample, "Stale cached response still served");

        // Expired miss (after upper_expiry 5000ms: at t=7000)
        let hit_expired = wing::cache_lookup(cache, 7000);
        sub.assert_eq(hit_expired, wing::CacheLookup.Miss, "Lookup at t=7000 is Miss");

        // Invalidation
        wing::cache_invalidate(cache);
        sub.assert_eq(wing::cache_lookup(cache, 1500), wing::CacheLookup.Miss, "Invalidated cache is Miss");
    };
}

fn test_tick_timer_wheel(t: lit::T&) {
    t.run("1. 1-Byte Tick Wheel Low-Overhead Timeout Sweeper") { sub =>
        var wheel = wing::new_tick_timer_wheel(10); // 10s default
        sub.assert_eq(wheel.current_tick, 0, "Initial tick is 0");

        // Arm two slots
        let slot1 = wing::tick_timer_arm(wheel, 10);
        let slot2 = wing::tick_timer_arm(wheel, 5);
        sub.assert_eq(slot1, 10, "Slot 1 timeout tick is 10");
        sub.assert_eq(slot2, 5, "Slot 2 timeout tick is 5");

        sub.assert_false(wing::tick_timer_is_expired(wheel, slot1), "Slot 1 not expired at t=0");
        sub.assert_false(wing::tick_timer_is_expired(wheel, slot2), "Slot 2 not expired at t=0");

        // Advance 5 ticks
        wing::tick_timer_advance(wheel, 5);
        sub.assert_eq(wheel.current_tick, 5, "Wheel at tick 5");
        sub.assert_true(wing::tick_timer_is_expired(wheel, slot2), "Slot 2 expired at t=5");
        sub.assert_false(wing::tick_timer_is_expired(wheel, slot1), "Slot 1 still active at t=5");

        // Advance 5 more ticks
        wing::tick_timer_advance(wheel, 5);
        sub.assert_eq(wheel.current_tick, 10, "Wheel at tick 10");
        sub.assert_true(wing::tick_timer_is_expired(wheel, slot1), "Slot 1 expired at t=10");

        // Disarmed slot
        let slot_disarmed = wing::tick_timer_disarm();
        sub.assert_eq(slot_disarmed, wing::TICK_TIMER_DISARMED, "Disarmed is 255");
        sub.assert_false(wing::tick_timer_is_expired(wheel, slot_disarmed), "Disarmed slot never expires");

        // Modular wraparound (modulo 240)
        wheel.current_tick = 235;
        let slot_wrap = wing::tick_timer_arm(wheel, 10); // (235 + 10) % 240 = 5
        sub.assert_eq(slot_wrap, 5, "Wraps modulo 240 cleanly to 5");
        sub.assert_false(wing::tick_timer_is_expired(wheel, slot_wrap), "Not expired before wrap");
        wing::tick_timer_advance(wheel, 10); // 235 + 10 = 5 mod 240
        sub.assert_eq(wheel.current_tick, 5, "Advanced across 240 boundary to 5");
        sub.assert_true(wing::tick_timer_is_expired(wheel, slot_wrap), "Expires at wrapped tick 5");
    };
}

fn test_buffer_fencing_margin(t: lit::T&) {
    t.run("1. Wire Buffer Sentinel Fencing") { sub =>
        var wire_buf: u8[64] = [0; 64];
        let req_text = "GET /status HTTP/1.1";
        for i in req_text.len {
            wire_buf[i] = req_text[i];
        }

        let ok_fence = core::fence_wire_slice(wire_buf[..], req_text.len);
        sub.assert_true(ok_fence, "Buffer fenced successfully");
        sub.assert_eq(wire_buf[req_text.len], '\r', "Byte at len is sentinel CR");
        sub.assert_eq(wire_buf[req_text.len + 1], 'a', "Byte at len+1 is sentinel 'a' (non-LF)");

        // Out of bounds fence check
        let bad_fence = core::fence_wire_slice(wire_buf[..], 63);
        sub.assert_false(bad_fence, "Cannot fence without at least 2 spare bytes margin");
    };
}

fn test_tcp_quickack_and_cork(t: lit::T&) {
    t.run("1. TCP QuickACK and Cork Control") { sub =>
        let listener = wing::tcp_listen("127.0.0.1", 0, 16);
        sub.assert_gt(listener, 0, "Listener created");
        let port = wing::tcp_getsockname_port(listener);

        let client = wing::tcp_connect("127.0.0.1", port, 2000);
        sub.assert_gt(client, 0, "Client connected");

        let accepted = wing::tcp_accept(listener, 2000);
        sub.assert_gt(accepted, 0, "Accepted incoming connection");

        // Set TCP_QUICKACK
        let ok_qack = wing::tcp_set_quickack(accepted, true);
        sub.assert_true(ok_qack, "TCP_QUICKACK configured successfully");

        // Set TCP_CORK enable
        let ok_cork_on = wing::tcp_set_cork(accepted, true);
        sub.assert_true(ok_cork_on, "TCP_CORK enabled successfully");

        // Send under cork
        let sent = wing::tcp_send(accepted, "CORKED_PAYLOAD");
        sub.assert_gt(sent, 0, "Bytes sent under cork");

        // Uncork
        let ok_cork_off = wing::tcp_set_cork(accepted, false);
        sub.assert_true(ok_cork_off, "TCP_CORK disabled successfully (flushed)");

        wing::tcp_close(client);
        wing::tcp_close(accepted);
        wing::tcp_close(listener);
    };
}

// --- Component: compat_uweb_bugs_regression ---
// Red regression test suite based on & issue tracker.
// Tracks verified fixes for vulnerabilities, RFC non-conformances, and edge cases.

fn test_uweb_1951_non_ascii_url_rejection(t: lit::T&) {
    // Issue #1951 / RFC 9112 Section 3.2:
    // Request target must only consist of visible ASCII characters (0x21..0x7E).
    // Raw UTF-8 bytes (e.g. 0xD1, 0x82) or raw binary bytes (>= 0x80) MUST be rejected with HTTP 400.

    var req = wing::new_request("GET", "");
    let bad_utf8: const u8[:] = "GET /тест HTTP/1.1\r\nHost: example.com\r\n\r\n";
    let ok1, _ = wing::parse_http1_wire_request(bad_utf8, req);
    t.assert_false(ok1, "Raw UTF-8 in request target must be rejected per #1951 / RFC 9112 §3.2");

    let bad_bin: const u8[:] = "GET /\xFF\xFE/resource HTTP/1.1\r\nHost: example.com\r\n\r\n";
    let ok2, _ = wing::parse_http1_wire_request(bad_bin, req);
    t.assert_false(ok2, "High-bit raw binary bytes in request target must be rejected");

    let valid_ascii: const u8[:] = "GET /test/path?foo=bar%20baz HTTP/1.1\r\nHost: example.com\r\n\r\n";
    let ok3, _ = wing::parse_http1_wire_request(valid_ascii, req);
    t.assert_true(ok3, "Valid visible ASCII path must be accepted");
}

fn test_uweb_1855_head_content_length_duplicate(t: lit::T&) {
    // Issue #1855 / RFC 9110 Section 8.6:
    // When responding to HEAD or providing a manual Content-Length on empty body,
    // the server MUST NOT serialize two conflicting Content-Length headers (e.g. 0 and 1024).

    var res = wing::Response { .. };
    res.status_code = 200;
    wing::set_header(res, "Content-Length", "1024");
    // Body is intentionally empty (HEAD response)

    var wire_out: u8[..1024] = [];
    wing::serialize_http1_response(res, "GooseWing", wire_out);
    let wire_str = wire_out[..];

    t.assert_true(find(wire_str, "Content-Length: 1024\r\n") >= 0, "Must contain Content-Length: 1024");
    t.assert_false(find(wire_str, "Content-Length: 0\r\n") >= 0, "Must NOT contain conflicting Content-Length: 0");

    // Count occurrences of 'Content-Length:'
    var count:  i64 = 0;
    var cursor: i64 = 0;
    while cursor < wire_str.len {
        let idx = find(wire_str[cursor..], "Content-Length:");
        if idx < 0 { break; }
        count++;
        cursor += idx + 15;
    }
    t.assert_eq(count, 1, "Exactly one Content-Length header must be emitted");
}

fn test_uweb_1927_proxy_enforcement_and_no_fallthrough(t: lit::T&) {
    // Issue #1927 & #1948 / HAProxy PROXY Protocol Specification:
    // When accept_proxy_protocol is enabled, the connection MUST begin with a valid PROXY header.
    // If a client sends plain HTTP without PROXY, it MUST be rejected immediately (NO fallthrough!).

    var srv = wing::new_http_server("127.0.0.1", 8080);
    srv.accept_proxy_protocol = true;

    var wire_out: u8[..1024] = [];
    let plain_http: const u8[:] = "GET /admin HTTP/1.1\r\nHost: example.com\r\n\r\n";
    let outcome, ok = wing::handle_connection_wire(srv, "192.168.1.50", plain_http, 123456789, wire_out);

    t.assert_false(ok, "Direct plain HTTP connection when PROXY is enforced must be rejected");
    t.assert_true(find(wire_out[..], "400 Bad Request") >= 0, "Must return 400 Bad Request on missing PROXY header");
}

fn test_uweb_1407_control_frame_protocol_error(t: lit::T&) {
    // Issue #1407 / RFC 6455 Section 5.5:
    // Malformed control frames (payload > 125, fragmented control frame with FIN=0)
    // MUST trigger WS_STATUS_PROTOCOL_ERROR (1002) and close the WebSocket connection.

    var ws = wing::new_websocket_session(false); // Server-side session
    var msg = wing::WsMessage {};
    var reply: u8[..256] = [];

    // 1. Fragmented Ping frame (FIN = 0, opcode = 0x09) with 4-byte mask
    let frag_ping: u8[6] = [
        0x09, // FIN=0, opcode=Ping
        0x80, // Masked, len=0
        0x01, 0x02, 0x03, 0x04, // Mask key
    ];
    let ok1 = wing::receive(ws, frag_ping[..], msg, reply);
    t.assert_true(ok1, "receive must handle protocol error");
    t.assert_true(ws.is_closed, "WebSocket must be marked closed on fragmented control frame");
    t.assert_eq(ws.close_code, wing::WS_STATUS_PROTOCOL_ERROR, "Must close with WS_STATUS_PROTOCOL_ERROR (1002)");

    // 2. Control frame with payload length > 125 (len = 126)
    var ws2 = wing::new_websocket_session(false);
    var reply2: u8[..256] = [];
    let oversize_ping: u8[8] = [
        0x89, // FIN=1, opcode=Ping
        0xFE, // Masked, len=126 (0x7E)
        0x00, 0x7E, // 126 bytes extended length
        0x01, 0x02, 0x03, 0x04, // Mask key
    ];
    let ok2 = wing::receive(ws2, oversize_ping[..], msg, reply2);
    t.assert_true(ok2, "receive must handle protocol error");
    t.assert_true(ws2.is_closed, "WebSocket must be closed on oversized control frame");
    t.assert_eq(ws2.close_code, wing::WS_STATUS_PROTOCOL_ERROR, "Must close with WS_STATUS_PROTOCOL_ERROR (1002)");
}

fn test_uweb_1933_topictree_trailing_wildcard(t: lit::T&) {
    // Issue #1933 & OASIS MQTT v5.0 §4.7.1.3:
    // 'sport/+' MUST match 'sport/' (trailing slash level), but 'sport' MUST NOT match 'sport/'.
    t.assert_true(wing::match_topic("sport/+", "sport/"), "'sport/+' must match 'sport/' with trailing slash");
    t.assert_false(wing::match_topic("sport/+", "sport/a/"), "'sport/+' must NOT match 'sport/a/' (two trailing levels)");
    t.assert_false(wing::match_topic("sport", "sport/"), "'sport' must NOT match 'sport/'");
    t.assert_false(wing::match_topic("sport/", "sport"), "'sport/' must NOT match 'sport'");
    t.assert_true(wing::match_topic("sport/#", "sport/"), "'sport/#' must match 'sport/'");
    t.assert_true(wing::match_topic("sport/#", "sport"), "'sport/#' must match 'sport'");

    // OASIS MQTT v5.0 §4.7.2: Topics starting with '$' must not match root '+' or '#'
    t.assert_false(wing::match_topic("#", "$SYS/stats"), "'#' must NOT match '$SYS/stats'");
    t.assert_false(wing::match_topic("+/stats", "$SYS/stats"), "'+/stats' must NOT match '$SYS/stats'");
    t.assert_true(wing::match_topic("$SYS/#", "$SYS/stats"), "'$SYS/#' must match '$SYS/stats'");

    // Issue #1924 / #1933:
    // Publishing to empty TopicTree or querying non-existent topic must return 0 without panicking.
    var tree = wing::TopicTree { .. };
    t.assert_eq(wing::subscriber_count(tree, "non/existent"), 0, "Subscriber count on non-existent topic must be 0");
    var out_fds: i64[..512] = [];
    let count = wing::find_subscribers(tree, "test/topic", out_fds);
    t.assert_eq(count, 0, "Finding subscribers in empty tree must return 0");

    // Batch publish deduplication across overlapping wildcard buckets
    t.assert_true(wing::subscribe(tree, 77, "chat/+"), "Sub 77 to chat/+");
    t.assert_true(wing::subscribe(tree, 77, "chat/#"), "Sub 77 to chat/#");
    let queued = wing::publish_batch(tree, "chat/room1", "hello");
    t.assert_eq(queued, 1, "publish_batch must queue message once per distinct socket across overlapping buckets");
    t.assert_true(wing::subscriber_needs_drain(tree, 77), "Socket 77 needs drain");
    t.assert_eq(wing::subscriber_queued_messages(tree, 77), 1, "Socket 77 has exactly 1 queued message");

    // Queue up to 32 messages without resetting palette_len mid-broadcast
    for i in 31 {
        wing::publish_batch(tree, "chat/room1", "msg");
    }
    t.assert_eq(wing::subscriber_queued_messages(tree, 77), 32, "Socket 77 has 32 queued messages");
    t.assert_eq(tree.palette_len, 32, "Palette length is 32");

    // 33rd message triggers drain_subscriber inside publish_batch
    wing::publish_batch(tree, "chat/room1", "msg33");
    t.assert_eq(tree.palette_len, 33, "Palette length must NOT be wiped by drain_subscriber mid-broadcast");
}

fn test_usock_263_socket_lifecycle_and_non_blocking_clean(t: lit::T&) {
    let listener = wing::tcp_listen("127.0.0.1", 0, 16);
    t.assert_true(listener > 0, "Listener created with non-inheritable handle");
    let port = wing::tcp_getsockname_port(listener);
    t.assert_true(port > 0, "Port allocated");

    let client = wing::tcp_connect("127.0.0.1", port, 2000);
    t.assert_true(client > 0, "Client connected without handle inheritance");

    let server_sock = wing::tcp_accept(listener, 2000);
    t.assert_true(server_sock > 0, "Server accepted connection");

    let msg = "PING_uWS_263";
    let sent = wing::tcp_send(client, msg);
    t.assert_eq(sent, msg.len as i32, "Sent test payload");

    var buf: u8[128] = [0; 128];
    let recvd = wing::tcp_recv_slice(server_sock, buf[..], 2000);
    t.assert_eq(recvd, msg.len as i32, "Received payload on accepted socket");

    wing::tcp_close(client);
    wing::tcp_close(server_sock);
    wing::tcp_close(listener);
}

fn test_uweb_1949_host_header_validation(t: lit::T&) {
    // Issue #1949 / RFC 9112 Section 3.2:
    // 1. Missing Host header in HTTP/1.1 must be rejected with 400.
    // 2. Multiple Host headers must be rejected with 400.
    // 3. Host containing path ('/'), query ('?'), fragment ('#'), or userinfo ('@') must be rejected with 400.
    var req = wing::new_request("GET", "");

    // 1. Missing Host in HTTP/1.1
    let no_host: const u8[:] = "GET / HTTP/1.1\r\nConnection: close\r\n\r\n";
    let ok1, _ = wing::parse_http1_wire_request(no_host, req);
    t.assert_false(ok1, "HTTP/1.1 request without Host header must be rejected");

    // 2. Host with path slash '/'
    let slash_host: const u8[:] = "GET / HTTP/1.1\r\nHost: localhost:8080/path\r\n\r\n";
    let ok2, _ = wing::parse_http1_wire_request(slash_host, req);
    t.assert_false(ok2, "Host header with slash '/path' must be rejected");

    // 3. Host with query '?'
    let query_host: const u8[:] = "GET / HTTP/1.1\r\nHost: localhost?query=1\r\n\r\n";
    let ok3, _ = wing::parse_http1_wire_request(query_host, req);
    t.assert_false(ok3, "Host header with query '?' must be rejected");

    // 4. Host with userinfo '@'
    let user_host: const u8[:] = "GET / HTTP/1.1\r\nHost: admin@localhost\r\n\r\n";
    let ok4, _ = wing::parse_http1_wire_request(user_host, req);
    t.assert_false(ok4, "Host header with userinfo '@' must be rejected");

    // 5. Multiple conflicting Host headers
    let multi_host: const u8[:] = "GET / HTTP/1.1\r\nHost: alpha.com\r\nHost: beta.com\r\n\r\n";
    let ok5, _ = wing::parse_http1_wire_request(multi_host, req);
    t.assert_false(ok5, "Multiple Host headers must be rejected");

    // 6. Valid Host header
    let valid_host: const u8[:] = "GET / HTTP/1.1\r\nHost: localhost:8080\r\n\r\n";
    let ok6, _ = wing::parse_http1_wire_request(valid_host, req);
    t.assert_true(ok6, "Valid Host header must be accepted");
}

fn test_uweb_1370_204_no_content_length(t: lit::T&) {
    // Issue #1370 / RFC 9110 Section 8.6:
    // A server MUST NOT send a Content-Length header field in any response
    // with status code 204 (No Content).
    var res = wing::Response { .. };
    res.status_code = 204;
    wing::set_header(res, "Content-Length", "0"); // User handler mistakenly sets Content-Length

    var wire_out: u8[..1024] = [];
    wing::serialize_http1_response(res, "GooseWing", wire_out);
    let wire_str = wire_out[..];

    t.assert_false(find(wire_str, "Content-Length") >= 0, "204 No Content response must NOT contain Content-Length header");
}

fn test_rfc_6455_1005_empty_close_payload(t: lit::T&) {
    // RFC 6455 Section 7.4.1 / Autobahn 7.1.x:
    // Status code 1005 (No Status Received) is designated for internal use
    // and MUST NOT be serialized onto the wire in a Close frame!
    // A close with WS_STATUS_NO_STATUS must produce an empty 0-byte payload.

    var ws = wing::new_websocket_session(false);
    var wire_out: u8[..256] = [];
    wing::close(ws, wing::WS_STATUS_NO_STATUS, "", wire_out);

    let hdr, ok = wing::parse_ws_frame_header(wire_out[..]);
    t.assert_true(ok, "Close frame must parse");
    t.assert_eq(hdr.opcode, wing::WS_OPCODE_CLOSE, "Opcode is Close");
    t.assert_eq(hdr.payload_len, 0, "1005 close frame payload length must be 0 bytes on wire");
}

fn test_uweb_1952_options_asterisk_and_get_asterisk_rejection(t: lit::T&) {
    // Issue #1952 / RFC 9112 Section 3.2.4:
    // Asterisk-form ('*') request target is ONLY valid for OPTIONS.
    // GET *, POST *, or any non-OPTIONS method with '*' MUST be rejected with 400.
    // Normal origin-form targets for GET/POST must begin with '/'.
    var req = wing::new_request("GET", "");

    let opt_star: const u8[:] = "OPTIONS * HTTP/1.1\r\nHost: example.com\r\n\r\n";
    let ok1, _ = wing::parse_http1_wire_request(opt_star, req);
    t.assert_true(ok1, "OPTIONS * HTTP/1.1 must be accepted per RFC 9112 §3.2.4");

    let get_star: const u8[:] = "GET * HTTP/1.1\r\nHost: example.com\r\n\r\n";
    let ok2, _ = wing::parse_http1_wire_request(get_star, req);
    t.assert_false(ok2, "GET * HTTP/1.1 must be rejected per #1952 / RFC 9112 §3.2.4");

    let post_star: const u8[:] = "POST * HTTP/1.1\r\nHost: example.com\r\n\r\n";
    let ok3, _ = wing::parse_http1_wire_request(post_star, req);
    t.assert_false(ok3, "POST * HTTP/1.1 must be rejected");
}

fn test_uweb_1932_ws_send_blocked_when_closed(t: lit::T&) {
    // Issue #1932 / RFC 6455 Section 5.5.1:
    // Once a WebSocket session is closed (or closing after backpressure/close frame),
    // all subsequent sends (text, binary, ping) MUST be dropped without writing frames.
    var ws = wing::new_websocket_session(false);
    var close_wire: u8[..128] = [];
    wing::close(ws, wing::WS_STATUS_NORMAL, "bye", close_wire);
    t.assert_true(ws.is_closed, "Session is closed");

    var wire_out: u8[..256] = [];
    wing::send_text(ws, "should be dropped", wire_out);
    t.assert_eq(wire_out.len, 0, "send_text must emit 0 bytes after session is closed");

    wing::send_binary(ws, "binary drop", wire_out);
    t.assert_eq(wire_out.len, 0, "send_binary must emit 0 bytes after session is closed");

    wing::send_ping(ws, "ping drop", wire_out);
    t.assert_eq(wire_out.len, 0, "send_ping must emit 0 bytes after session is closed");
}

fn test_mqtt_invalid_multilevel_wildcard_rejection(t: lit::T&) {
    // OASIS MQTT v5.0 §4.7.1.2 & TopicTree Validation:
    // Multi-level wildcard '#' MUST be the last character in the topic pattern,
    // and MUST be either alone ("#") or preceded by '/' ("sport/#").
    // Patterns like "sport/#/tennis" or "sport#" or "sport+foo" are syntactically illegal!
    var tree = wing::TopicTree { .. };

    t.assert_false(wing::subscribe(tree, 10, "sport/#/tennis"), "'#' in middle of topic pattern must be rejected");
    t.assert_false(wing::subscribe(tree, 10, "sport#"), "'#' not preceded by '/' must be rejected");
    t.assert_false(wing::subscribe(tree, 10, "sport+"), "'+' not occupying entire segment must be rejected");
    t.assert_true(wing::subscribe(tree, 10, "sport/#"), "Valid 'sport/#' must be accepted");
    t.assert_true(wing::subscribe(tree, 10, "#"), "Valid '#' must be accepted");
    t.assert_true(wing::subscribe(tree, 10, "sport/+/tennis"), "Valid 'sport/+/tennis' must be accepted");
}

fn test_uweb_1090_mqtt_wildcard_publish_rejection(t: lit::T&) {
    // Issue #1090 / OASIS MQTT v5.0 §3.3.2.1:
    // "The Topic Name in the PUBLISH packet MUST NOT contain wildcard characters [MQTT-3.3.2-1]."
    // Publishing to wildcard topics ("sport/+", "sport/#", "+", "#") is illegal and MUST be rejected.
    var tree = wing::TopicTree { .. };
    t.assert_true(wing::subscribe(tree, 10, "sport/+"), "Subscribe to 'sport/+'");
    t.assert_true(wing::subscribe(tree, 20, "sport/#"), "Subscribe to 'sport/#'");

    var fds: i64[..512] = [];
    // Legitimate publish to concrete topic: matches both
    let count1 = wing::find_subscribers(tree, "sport/tennis", fds);
    t.assert_eq(count1, 2, "Concrete topic 'sport/tennis' matches 2 subscribers");

    // Illegal publish containing '+' wildcard: must return 0
    let count2 = wing::find_subscribers(tree, "sport/+", fds);
    t.assert_eq(count2, 0, "Publish to wildcard topic 'sport/+' MUST be rejected (0 subscribers)");

    // Illegal publish containing '#' wildcard: must return 0
    let count3 = wing::find_subscribers(tree, "sport/#", fds);
    t.assert_eq(count3, 0, "Publish to wildcard topic 'sport/#' MUST be rejected (0 subscribers)");

    // Standalone wildcard publish: must return 0
    let count4 = wing::find_subscribers(tree, "#", fds);
    t.assert_eq(count4, 0, "Publish to wildcard topic '#' MUST be rejected (0 subscribers)");
}

fn test_uweb_1944_query_lookup_encoded_and_valueless(t: lit::T&) {
    // Issue #1944 / WHATWG URL:
    // Query parameter fast lookup must handle percent-encoded keys and valueless parameters.
    let query_str: const u8[:] = "?user%20id=42&flag&category%2Ftag=news";

    t.assert_true(core::has_query_param_fast(query_str, "user id"), "Must find percent-encoded key 'user id'");

    var user_id_val: u8[..64] = [];
    let found1, is_valueless1 = core::get_query_param_fast(query_str, "user id", user_id_val);
    t.assert_true(found1, "Found 'user id'");
    t.assert_false(is_valueless1, "'user id' has value");
    t.assert_eq(user_id_val[..], "42", "Decoded value of 'user id' is '42'");

    var flag_val: u8[..64] = [];
    let found2, is_valueless2 = core::get_query_param_fast(query_str, "flag", flag_val);
    t.assert_true(found2, "Found valueless 'flag'");
    t.assert_true(is_valueless2, "'flag' is valueless");

    var cat_val: u8[..64] = [];
    let found3, is_valueless3 = core::get_query_param_fast(query_str, "category/tag", cat_val);
    t.assert_true(found3, "Found 'category/tag'");
    t.assert_false(is_valueless3, "'category/tag' has value");
    t.assert_eq(cat_val[..], "news", "Decoded value of 'category/tag' is 'news'");
}

fn test_uweb_1898_extra_bytes_connection_poisoning(t: lit::T&) {
    // Issue #1898 / RFC 9112 Section 9.3:
    // Extra bytes sent beyond Content-Length must not be ignored or allowed to poison keep-alive.
    // If a request stream contains unparseable trailing junk after a request, the connection handler
    // must reject it with 400 Bad Request and fail the stream (return ok = false), rather than silently breaking.
    var server = wing::new_http_server();
    wing::add_route(server.pipeline.router, "POST", "/submit", 1);

    let poisoned_stream: const u8[:] =
        "POST /submit HTTP/1.1\r\nHost: example.com\r\nContent-Length: 5\r\n\r\nHELLOPOISON_EXTRA_BYTES_LINGERING";

    var wire_out: u8[..4096] = [];
    let handled, ok = wing::handle_connection_wire_pipelined(server, "127.0.0.1", poisoned_stream, 0, wire_out);
    t.assert_false(ok, "Trailing unparseable bytes after Content-Length must invalidate the stream (ok = false)");
    t.assert_true(find(wire_out[..], "400 Bad Request") >= 0, "Must serialize 400 Bad Request for poisoned connection");
}

fn test_rfc_6455_non_minimal_length_protocol_error(t: lit::T&) {
    // RFC 6455 §5.2 & Autobahn Cases 3.1, 3.2, 3.3, 3.4 / #1407:
    // Non-minimal length encodings (e.g. 16-bit length < 126 or 64-bit length <= 65535)
    // and high-bit violations in 64-bit length MUST fail the connection with Protocol Error (1002).
    var ws = wing::new_websocket_session(false); // server session
    var reply: u8[..256] = [];
    var view = wing::WsMessageView { .. };

    // 1. Non-minimal 16-bit encoding: raw_len = 126, but length is 10 (< 126).
    // Wire: 0x81 (FIN+text), 0xFE (Masked + 126), 0x00, 0x0A (len=10), mask: 4 bytes, payload: 10 bytes
    var wire_non_minimal_16: u8[..32] = [
        0x81, 0xFE, 0x00, 0x0A,
        0x11, 0x22, 0x33, 0x44,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ];
    let handled1 = wing::receive_view(ws, wire_non_minimal_16[..], view, reply);
    t.assert_true(handled1, "Handled non-minimal 16-bit length frame");
    t.assert_true(ws.is_closed, "Session must be closed on non-minimal length");
    t.assert_eq(ws.close_code, wing::WS_STATUS_PROTOCOL_ERROR, "Must close with 1002 (PROTOCOL_ERROR)");

    // 2. High-bit set in 64-bit length: byte 2 has 0x80 set
    var ws2 = wing::new_websocket_session(false);
    var wire_high_bit_64: u8[..32] = [
        0x81, 0xFF, 0x80, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00,
        0x11, 0x22, 0x33, 0x44,
    ];
    let handled2 = wing::receive_view(ws2, wire_high_bit_64[..], view, reply);
    t.assert_true(handled2, "Handled high-bit 64-bit length frame");
    t.assert_true(ws2.is_closed, "Session must be closed on high-bit in 64-bit length");
    t.assert_eq(ws2.close_code, wing::WS_STATUS_PROTOCOL_ERROR, "Must close with 1002 (PROTOCOL_ERROR)");
}

fn test_uweb_1658_max_header_size_rejection(t: lit::T&) {
    // #1658 / RFC 9112 §2.1:
    // Total header block size must be bounded (e.g. 8192 bytes).
    // Incoming requests exceeding 8192 bytes of headers must be rejected.
    var req = wing::new_request("GET", "");
    var huge_wire: u8[>..] = [];
    huge_wire.append("GET /large-headers HTTP/1.1\r\nHost: example.com\r\n");
    for i in 26 {
        huge_wire.append("X-Large-Header-Padding: 01234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789\r\n");
    }
    huge_wire.append("\r\n");
    t.assert_true(huge_wire.len > 8192, "Total wire headers exceed 8192 bytes");

    let ok, _ = wing::parse_http1_wire_request(huge_wire[..], req);
    t.assert_false(ok, "Headers exceeding 8KB must be rejected per #1658 / RFC 9112 §2.1");
}

fn test_usock_101_windows_exclusive_port_defense(t: lit::T&) {
    // Issue #101 / #167:
    // On Windows, listening sockets MUST set SO_EXCLUSIVEADDRUSE rather than SO_REUSEADDR.
    // SO_REUSEADDR on Windows permits rogue processes to forcibly bind to the same port and steal connections (port hijacking).
    // With SO_EXCLUSIVEADDRUSE, a second bind to the same local IP and port MUST fail.
    let s1 = wing::native_tcp_listen("127.0.0.1", 0, 128);
    t.assert_true(s1 > 0, "First listener created successfully");
    let port = wing::native_tcp_getsockname_port(s1);
    t.assert_true(port > 0, "Listener bound to dynamic port");

    // Second bind attempt on the same address & port: MUST be rejected
    let s2 = wing::native_tcp_listen("127.0.0.1", port, 128);
    t.assert_eq(s2, -1, "Second listener on exact same port MUST fail (-1)");

    wing::native_tcp_close(s1);
    if s2 > 0 {
        wing::native_tcp_close(s2);
    }
}

fn test_rfc_6455_sec_websocket_key_validation(t: lit::T&) {
    // RFC 6455 Section 4.2.1:
    // "The |Sec-WebSocket-Key| MUST be a base64-encoded value that, when decoded, is 16 bytes in length."
    // Handshake request with malformed, short, or non-base64 key MUST be rejected with HTTP 400.
    var req_bad = wing::new_request("GET", "/ws");
    wing::set_header(req_bad, "Host", "example.com");
    wing::set_header(req_bad, "Upgrade", "websocket");
    wing::set_header(req_bad, "Connection", "Upgrade");
    wing::set_header(req_bad, "Sec-WebSocket-Version", "13");
    wing::set_header(req_bad, "Sec-WebSocket-Key", "short_invalid_key");

    var res_bad = wing::Response { .. };
    let sess_bad, ok_bad = wing::ws_upgrade_request(req_bad, res_bad);
    t.assert_false(ok_bad, "Upgrade with non-16-byte key must fail");
    t.assert_eq(res_bad.status_code, 400, "Must return HTTP 400 Bad Request for malformed Sec-WebSocket-Key");

    // Valid 16-byte nonce base64-encoded (RFC 6455 example)
    var req_good = wing::new_request("GET", "/ws");
    wing::set_header(req_good, "Host", "example.com");
    wing::set_header(req_good, "Upgrade", "websocket");
    wing::set_header(req_good, "Connection", "Upgrade");
    wing::set_header(req_good, "Sec-WebSocket-Version", "13");
    wing::set_header(req_good, "Sec-WebSocket-Key", "dGhlIHNhbXBsZSBub25jZQ==");

    var res_good = wing::Response { .. };
    let sess_good, ok_good = wing::ws_upgrade_request(req_good, res_good);
    t.assert_true(ok_good, "Upgrade with valid Sec-WebSocket-Key must succeed");
    t.assert_eq(res_good.status_code, 101, "Must return HTTP 101 Switching Protocols");
    let accept_val = wing::header(res_good, "Sec-WebSocket-Accept");
    t.assert_eq(accept_val, "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=", "Correct RFC 6455 Sec-WebSocket-Accept header");
}

fn test_uweb_1948_proxy_v2_command_and_family_validation(t: lit::T&) {
    // Issue #1948 / HAProxy PROXY Protocol v2 Specification §2.2:
    // 1. Only exact family/transport combinations 0x00, 0x11, 0x12, 0x21, 0x22, 0x31, 0x32 are valid.
    //    Unspecified combinations like 0x01 (UNSPEC+STREAM) or 0x10 (INET4+UNSPEC) MUST be rejected.
    // 2. Command LOCAL (0x20) MUST NOT expose proxied addresses; native endpoint address MUST be preserved.

    let preamble: const u8[12] = [
        0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51, 0x55, 0x49, 0x54, 0x0A,
    ];

    // Case 1: fam_trans = 0x01 (UNSPEC + STREAM) - MUST FAIL
    var bad_wire1: u8[..16] = [];
    bad_wire1.append(preamble[..]);
    bad_wire1.push(0x21); // PROXY command
    bad_wire1.push(0x01); // Invalid UNSPEC+STREAM
    bad_wire1.push(0x00); // len hi
    bad_wire1.push(0x00); // len lo
    let hdr1, c1, ok1 = wing::parse_proxy_v2(bad_wire1[..]);
    t.assert_false(ok1, "PROXY v2 with invalid fam_trans 0x01 (UNSPEC+STREAM) MUST be rejected");

    // Case 2: fam_trans = 0x10 (INET4 + UNSPEC) - MUST FAIL
    var bad_wire2: u8[..16] = [];
    bad_wire2.append(preamble[..]);
    bad_wire2.push(0x21); // PROXY command
    bad_wire2.push(0x10); // Invalid INET4+UNSPEC
    bad_wire2.push(0x00); // len hi
    bad_wire2.push(0x00); // len lo
    let hdr2, c2, ok2 = wing::parse_proxy_v2(bad_wire2[..]);
    t.assert_false(ok2, "PROXY v2 with invalid fam_trans 0x10 (INET4+UNSPEC) MUST be rejected");

    // Case 3: Command LOCAL (0x20) with IPv4 address payload - MUST NOT expose proxied address
    var local_wire: u8[..32] = [];
    local_wire.append(preamble[..]);
    local_wire.push(0x20); // LOCAL command
    local_wire.push(0x11); // INET4 + STREAM
    local_wire.push(0x00); // len hi
    local_wire.push(0x0C); // len = 12
    // 12 bytes address block: src 10.0.0.1, dst 10.0.0.2, sport 1234, dport 80
    let addr_bytes: u8[12] = [10, 0, 0, 1, 10, 0, 0, 2, 0x04, 0xD2, 0x00, 0x50];
    local_wire.append(addr_bytes[..]);

    let hdr3, c3, ok3 = wing::parse_proxy_v2(local_wire[..]);
    t.assert_true(ok3, "LOCAL command header syntax is valid");
    t.assert_eq(hdr3.src_ip_str.len, 0, "LOCAL command MUST NOT expose proxied client IP");
}

fn test_usock_258_windows_connect_rst_immediate_failure(t: lit::T&) {
    // Issue #258 / #259 & Winsock2 Specification:
    // On Windows, when a non-blocking connect fails (RST / ECONNREFUSED), Winsock2
    // signals the socket via exceptfds or writefds with SO_ERROR set.
    // In #258, libuv/WSAPoll reported writable, and because uWS
    // omitted getsockopt(SO_ERROR), it incorrectly treated connection failure as success (calling on_open).
    // In wing, native_tcp_connect guards via exceptfds, SO_ERROR inspection, and bounded timeout:
    // 1) Connection to unlistening port with 50ms timeout MUST return -1 (never treated as open).
    // 2) Elapsed time MUST be bounded (< 300ms) without hanging.

    let sw = core::stopwatch();
    let s = wing::native_tcp_connect("127.0.0.1", 59999, 50);
    let dur_ms = sw.elapsed().as_millis();

    t.assert_eq(s, -1, "Connect to closed port MUST return -1 (never call on_open)");
    t.assert_true(dur_ms < 300, "Connect with 50ms timeout must return within bounded time");
}

fn test_uweb_1941_transfer_encoding_list_and_final_chunked(t: lit::T&) {
    // Issue #1941 / PR #1943 & RFC 9112 Section 6.1 & 7:
    // Transfer-Encoding can be a comma-separated list of transfer codings (e.g. gzip, identity, br, deflate),
    // but MUST end with 'chunked' (case-insensitive) as the final transfer coding.
    // In #1941, compared whole string against exact literal "chunked", causing 400 Bad Request
    // on valid list forms like "gzip, chunked", "identity, chunked", "CHUNKED".
    // goose-wing must accept any valid coding sequence ending in chunked, and reject:
    // 1) non-chunked endings (e.g. "chunked, gzip" or "identity")
    // 2) multiple chunked encodings (e.g. "chunked, chunked")

    // 1. Valid list forms ending in chunked
    t.assert_true(wing::validate_transfer_encoding_value("chunked"), "Single chunked is valid");
    t.assert_true(wing::validate_transfer_encoding_value("CHUNKED"), "Case-insensitive CHUNKED is valid");
    t.assert_true(wing::validate_transfer_encoding_value("gzip, chunked"), "gzip, chunked list is valid");
    t.assert_true(wing::validate_transfer_encoding_value("identity, chunked"), "identity, chunked list is valid");
    t.assert_true(wing::validate_transfer_encoding_value("deflate, gzip, chunked"), "deflate, gzip, chunked list is valid");
    t.assert_true(wing::validate_transfer_encoding_value("br, chunked"), "br, chunked list is valid");
    t.assert_true(wing::validate_transfer_encoding_value("gzip;q=1.0, chunked"), "parameterized coding is valid");

    // 2. Invalid forms (chunked not final or duplicate chunked)
    t.assert_false(wing::validate_transfer_encoding_value("chunked, gzip"), "chunked before gzip must be rejected");
    t.assert_false(wing::validate_transfer_encoding_value("chunked, identity"), "chunked before identity must be rejected");
    t.assert_false(wing::validate_transfer_encoding_value("identity"), "Missing chunked must be rejected");
    t.assert_false(wing::validate_transfer_encoding_value("chunked, chunked"), "Duplicate chunked must be rejected");

    // 3. End-to-end server wire handling with identity, chunked
    var server = wing::new_http_server("test-server");
    wing::add_post_route(server, "/upload", 1);
    var wire_out: u8[..512] = [];
    let raw_req: const u8[:] = "POST /upload HTTP/1.1\r\nHost: localhost\r\nTransfer-Encoding: identity, chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n";
    let _, ok = wing::handle_connection_wire(server, "127.0.0.1", raw_req, 1000000000, wire_out);
    t.assert_true(ok, "Server must accept and process request with Transfer-Encoding: identity, chunked");
    t.assert_contains(wire_out[..], "200 OK", "Server responds 200 OK to valid chunked list form");
}

fn test_uweb_1936_chunk_extension_and_size_whitespace_validation(t: lit::T&) {
    // Issue #1936 / Http11Probe & RFC 9112 Section 7.1.1:
    // chunk = chunk-size [ chunk-ext ] CRLF
    // chunk-size = 1*HEXDIG
    // chunk-ext = *( BWS ";" BWS chunk-ext-name [ BWS "=" BWS chunk-ext-val ] )
    // chunk-ext-name = token
    // chunk-ext-val = token / quoted-string
    //
    // In #1936 / Http11Probe, failed 5+ compliance and smuggling checks:
    // 1) Whitespace before chunk-size (" 5\r\n") MUST be rejected.
    // 2) Whitespace after chunk-size without extension ("5 \r\n") MUST be rejected.
    // 3) Empty extension name after semicolon ("5;\r\n" or "5;;foo\r\n" or "5;=val\r\n") MUST be rejected.
    // 4) Unclosed quoted string in extension value ("5;foo=\"bar\r\n") MUST be rejected.
    // 5) Non-token characters in extension name ("5;foo@bar=1\r\n") MUST be rejected.
    // 6) Legitimate extensions ("5;name=value;flag\r\n" and "5;name=\"quoted val\"\r\n") MUST succeed.

    var body:     u8[>..]                = [];
    var trailers: wing::HeaderItem[..16] = [];

    // 1. Valid extensions
    body.clear(); trailers.clear();
    let err1, _ = wing::decode_chunked_body_with_trailers("5;name=value;flag\r\nHello\r\n0\r\n\r\n", body, trailers);
    t.assert_eq(err1, wing::ChunkedDecodeError.None, "Valid chunk extension accepted");

    body.clear(); trailers.clear();
    let err2, _ = wing::decode_chunked_body_with_trailers("5;name=\"quoted val\"\r\nHello\r\n0\r\n\r\n", body, trailers);
    t.assert_eq(err2, wing::ChunkedDecodeError.None, "Valid quoted extension accepted");

    // 2. Illegal whitespace around chunk-size (smuggling vector)
    body.clear(); trailers.clear();
    let err_ws1, _ = wing::decode_chunked_body_with_trailers(" 5\r\nHello\r\n0\r\n\r\n", body, trailers);
    t.assert_ne(err_ws1, wing::ChunkedDecodeError.None, "Leading whitespace before chunk size MUST be rejected");

    body.clear(); trailers.clear();
    let err_ws2, _ = wing::decode_chunked_body_with_trailers("5 \r\nHello\r\n0\r\n\r\n", body, trailers);
    t.assert_ne(err_ws2, wing::ChunkedDecodeError.None, "Trailing whitespace after chunk size without ';' MUST be rejected");

    // 3. Illegal empty extension names
    body.clear(); trailers.clear();
    let err_ext1, _ = wing::decode_chunked_body_with_trailers("5;\r\nHello\r\n0\r\n\r\n", body, trailers);
    t.assert_ne(err_ext1, wing::ChunkedDecodeError.None, "Empty extension name after ';' MUST be rejected");

    body.clear(); trailers.clear();
    let err_ext2, _ = wing::decode_chunked_body_with_trailers("5;=val\r\nHello\r\n0\r\n\r\n", body, trailers);
    t.assert_ne(err_ext2, wing::ChunkedDecodeError.None, "Extension with missing name before '=' MUST be rejected");

    body.clear(); trailers.clear();
    let err_ext3, _ = wing::decode_chunked_body_with_trailers("5;;foo=bar\r\nHello\r\n0\r\n\r\n", body, trailers);
    t.assert_ne(err_ext3, wing::ChunkedDecodeError.None, "Double semicolon in extension MUST be rejected");

    // 4. Unclosed quoted-string in extension value
    body.clear(); trailers.clear();
    let err_quote, _ = wing::decode_chunked_body_with_trailers("5;foo=\"unclosed\r\nHello\r\n0\r\n\r\n", body, trailers);
    t.assert_ne(err_quote, wing::ChunkedDecodeError.None, "Unclosed quoted string in extension MUST be rejected");

    // 5. Invalid token character in extension name
    body.clear(); trailers.clear();
    let err_tok, _ = wing::decode_chunked_body_with_trailers("5;foo@bar=1\r\nHello\r\n0\r\n\r\n", body, trailers);
    t.assert_ne(err_tok, wing::ChunkedDecodeError.None, "Invalid token character '@' in extension name MUST be rejected");
}

// --- Test 50: PreparedMessage & publishPrepared ---
fn test_uweb_prepared_message(t: lit::T&) {
    var tree = wing::TopicTree { .. };
    wing::subscribe(tree, 101, "broadcast/tickers");
    wing::subscribe(tree, 102, "broadcast/+");

    var msg = wing::PreparedMessage { .. };
    let ok_prep = wing::prepare_message(msg, "{\"ticker\":\"BTC\",\"price\":92500}", wing::WS_OPCODE_TEXT);
    t.assert_true(ok_prep, "prepare_message succeeded");
    t.assert_gt(msg.wire.len, 0, "Wire frame encoded");
    t.assert_false(msg.has_compressed, "Raw prepared message has_compressed is false");

    // Header validation
    let hdr, ok_h = wing::parse_ws_frame_header(msg.wire[..]);
    t.assert_true(ok_h, "Parsed prepared frame header");
    t.assert_eq(hdr.opcode, wing::WS_OPCODE_TEXT, "Opcode is TEXT");
    t.assert_true(hdr.fin, "FIN bit set");
    t.assert_false(hdr.masked, "Server frame unmasked per RFC 6455");

    // Prepared message with compression
    var comp_msg = wing::PreparedMessage { .. };
    var shared_comp = wing::SharedWsCompressor { .. };
    let long_payload = "REPEAT_KEY_DATA_FIELD_VALUE_12345_REPEAT_KEY_DATA_FIELD_VALUE_12345_REPEAT_KEY_DATA_FIELD_VALUE_12345";
    let ok_c = wing::prepare_message_compressed(comp_msg, long_payload, shared_comp, wing::WS_OPCODE_TEXT);
    t.assert_true(ok_c, "prepare_message_compressed succeeded");
    t.assert_true(comp_msg.has_compressed, "Compressible payload marked has_compressed");
    t.assert_lt(comp_msg.compressed_wire.len, comp_msg.wire.len, "Compressed wire smaller than uncompressed");

    // Verify compressed header has RSV1
    let c_hdr, ok_ch = wing::parse_ws_frame_header(comp_msg.compressed_wire[..]);
    t.assert_true(ok_ch, "Parsed compressed frame header");
    t.assert_true(c_hdr.rsv1, "RSV1 bit set on compressed frame per RFC 7692");

    // Verify find_subscribers matches subscribers
    var matched: i64[..512] = [];
    let count = tree.find_subscribers("broadcast/tickers", matched);
    t.assert_eq(count, 2, "2 subscribers match broadcast/tickers");

    // Dispatches pre-encoded message to topic subscribers
    let pub_count = wing::publish_prepared(tree, "broadcast/tickers", msg);
    t.assert_eq(pub_count, 0, "No bytes sent to offline test fds");
    t.assert_eq(tree.total_publishes, 1, "TopicTree total_publishes tracked");
}

// --- Test 51: WebSocket maxLifetime Session Timeout ---
fn test_uweb_max_lifetime_sweeper(t: lit::T&) {
    var wheel = wing::new_tick_timer_wheel(10);
    var ws = wing::new_websocket_session(false);
    ws.idle_timeout_s = 10;
    ws.max_lifetime_s = 20; // 20 seconds maximum lifetime
    ws.arm_heartbeat(wheel);

    // Advance 8s, then touch (client active)
    wing::tick_timer_advance(wheel, 8);
    wing::ws_advance_lifetime(ws, 8);
    ws.touch(wheel);

    t.assert_true(ws.check_heartbeat(wheel) == wing::WsHeartbeatAction.None, "No expiry after touch at 8s");

    // Advance another 8s, touch again (total 16s lifetime, idle was reset)
    wing::tick_timer_advance(wheel, 8);
    wing::ws_advance_lifetime(ws, 8);
    ws.touch(wheel);

    t.assert_true(ws.check_heartbeat(wheel) == wing::WsHeartbeatAction.None, "No expiry after touch at 16s");
    t.assert_false(ws.is_closed, "Session still open at 16s");

    // Advance another 5s (total 21s, exceeds max_lifetime_s = 20)
    wing::tick_timer_advance(wheel, 5);
    wing::ws_advance_lifetime(ws, 5);

    // Despite being touched at 16s (idle would not expire until 26s), maxLifetime forces CloseMaxLifetime
    let act = ws.check_heartbeat(wheel);
    t.assert_true(act == wing::WsHeartbeatAction.CloseMaxLifetime, "CloseMaxLifetime action triggered");

    var wire_close: u8[..256] = [];
    let act_tick = ws.tick_heartbeat(wheel, wire_close);
    t.assert_true(act_tick == wing::WsHeartbeatAction.CloseMaxLifetime, "tick_heartbeat executed CloseMaxLifetime");
    t.assert_true(ws.is_closed, "Session closed by maxLifetime");
    t.assert_eq(ws.close_code, wing::WS_STATUS_NORMAL, "Close status code 1000");
}

// --- Test 52: #1347 Safari 15.0-15.3 Broken Compression Workaround ---
fn test_uweb_safari_15_broken_compression(t: lit::T&) {
    // Safari 15.0..15.3 should return true
    let ua_15_0 = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/15.0 Safari/605.1.15";
    t.assert_true(wing::ws_has_broken_compression(ua_15_0), "Safari 15.0 detected as broken");

    let ua_15_1 = "Mozilla/5.0 (iPhone; CPU iPhone OS 15_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/15.1 Mobile/15E148 Safari/604.1";
    t.assert_true(wing::ws_has_broken_compression(ua_15_1), "Safari 15.1 detected as broken");

    let ua_15_2 = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/15.2 Safari/605.1.15";
    t.assert_true(wing::ws_has_broken_compression(ua_15_2), "Safari 15.2 detected as broken");

    let ua_15_3 = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/15.3 Safari/605.1.15";
    t.assert_true(wing::ws_has_broken_compression(ua_15_3), "Safari 15.3 detected as broken");

    // Safari 15.4+ fixed the bug
    let ua_15_4 = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/15.4 Safari/605.1.15";
    t.assert_false(wing::ws_has_broken_compression(ua_15_4), "Safari 15.4 NOT broken");

    let ua_16_0 = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.0 Safari/605.1.15";
    t.assert_false(wing::ws_has_broken_compression(ua_16_0), "Safari 16.0 NOT broken");

    // Chrome and Firefox
    let ua_chrome = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36";
    t.assert_false(wing::ws_has_broken_compression(ua_chrome), "Chrome NOT broken");

    let ua_firefox = "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/119.0";
    t.assert_false(wing::ws_has_broken_compression(ua_firefox), "Firefox NOT broken");

    // Edge cases / empty
    t.assert_false(wing::ws_has_broken_compression(""), "Empty UA NOT broken");
    t.assert_false(wing::ws_has_broken_compression("curl/7.88.1"), "curl NOT broken");
}

// Global test state for streaming chunk capture
var g_stream_received_bytes:      i64  = 0;
var g_stream_chunk_count:         i32  = 0;
var g_stream_last_chunk_is_final: bool = false;

fn stream_chunk_collector(chunk: const u8[:], is_last: bool) {
    g_stream_received_bytes += chunk.len;
    g_stream_chunk_count += 1;
    g_stream_last_chunk_is_final = is_last;
}

// Global test state for async abort / writable callbacks
var g_async_aborted_fd:      i64  = -1;
var g_async_aborted_tag:     u64  = 0;
var g_async_writable_called: bool = false;

fn on_test_client_aborted(fd: i64, tag: u64) {
    g_async_aborted_fd = fd;
    g_async_aborted_tag = tag;
}

fn on_test_socket_writable(fd: i64, total_written: u64, tag: u64) -> bool {
    g_async_writable_called = true;
    return true;
}

fn test_missing_sni_fallback(hostname: const u8[:]) -> wing::SniCredentials {
    if core::contains(hostname, "fallback") {
        return wing::SniCredentials {
            cert_pem: "FALLBACK_CERT_PEM",
            key_pem:  "FALLBACK_KEY_PEM",
        };
    }
    return wing::SniCredentials { .. };
}

// --- Test 53: endWithoutBody & HEAD/304 Content-Length Spoofing ---
fn test_uweb_end_without_body(t: lit::T&) {
    var res = wing::Response { status_code: 200, .. };
    var wire: u8[..1024] = [];

    // 1. Standard end_without_body with reported Content-Length (HEAD request)
    wing::end_without_body(res, "goose-wing", wire, 1048576, false);
    t.assert_gt(wire.len, 0, "Wire headers serialized");
    t.assert_true(core::contains(wire[..], "Content-Length: 1048576\r\n"), "Content-Length present in header block");
    t.assert_true(core::contains(wire[..], "\r\n\r\n"), "Double CRLF terminator present");

    let sent_bytes = wing::send_http1_end_without_body(0, res, "goose-wing", wire, 1048576, false);
    t.assert_eq(sent_bytes, 0, "send_http1_end_without_body returns 0 on non-positive fd");

    // Verify wire has exactly 0 body bytes after \r\n\r\n
    let pos_end = find(wire[..], "\r\n\r\n");
    t.assert_eq(pos_end + 4, wire.len, "Zero body bytes emitted on wire after header end");

    // 2. end_without_body with close_connection = true
    wire.clear();
    var res2 = wing::Response { status_code: 304, .. };
    wing::end_without_body(res2, "goose-wing", wire, -1, true);
    t.assert_true(core::contains(wire[..], "Connection: close\r\n"), "Connection: close added");
    t.assert_false(core::contains(wire[..], "Content-Length"), "Content-Length omitted when negative");
}

// --- Test 54: Streaming Ingress onData / onDataV2 ---
fn test_uweb_streaming_on_data(t: lit::T&) {
    var req = wing::new_request("POST", "/upload/stream");
    var consumer = wing::HttpStreamConsumer { .. };

    let wire_headers = "POST /upload/stream HTTP/1.1\r\nHost: example.com\r\nContent-Length: 100\r\n\r\n";
    let ok_beg, hdr_len = wing::begin_http_stream_request(wire_headers, req, consumer);
    t.assert_true(ok_beg, "begin_http_stream_request succeeded");
    t.assert_eq(consumer.content_length, 100, "Content-Length parsed as 100");
    t.assert_true(consumer.is_headers_parsed, "Headers marked parsed");
    t.assert_false(consumer.is_finished, "Consumer not finished yet");
    t.assert_eq(hdr_len, wire_headers.len, "Header length points past headers");

    g_stream_received_bytes = 0;
    g_stream_chunk_count = 0;
    g_stream_last_chunk_is_final = false;

    // Chunk 1: 40 bytes
    let chunk1 = "1234567890123456789012345678901234567890";
    let c1, is_last1, ok1 = wing::feed_http_stream_chunk(consumer, chunk1, stream_chunk_collector);
    t.assert_true(ok1, "Chunk 1 fed successfully");
    t.assert_eq(c1, 40, "Consumed 40 bytes");
    t.assert_false(is_last1, "Chunk 1 is not last");
    t.assert_false(consumer.is_finished, "Consumer not finished");
    t.assert_eq(g_stream_received_bytes, 40, "40 bytes received by callback");

    // Chunk 2: 60 bytes (completes the 100 bytes)
    let chunk2 = "123456789012345678901234567890123456789012345678901234567890";
    let c2, is_last2, ok2 = wing::feed_http_stream_chunk(consumer, chunk2, stream_chunk_collector);
    t.assert_true(ok2, "Chunk 2 fed successfully");
    t.assert_eq(c2, 60, "Consumed 60 bytes");
    t.assert_true(is_last2, "Chunk 2 is last");
    t.assert_true(consumer.is_finished, "Consumer is finished");
    t.assert_eq(g_stream_received_bytes, 100, "100 total bytes received");
    t.assert_eq(g_stream_chunk_count, 2, "2 chunks delivered");
    t.assert_true(g_stream_last_chunk_is_final, "Last chunk marked final in collector");
}

// --- Test 55: Async Backpressure (onWritable) & Abort (onAborted) ---
fn test_uweb_async_backpressure_and_aborted(t: lit::T&) {
    var ctx = wing::HttpAsyncContext {
        sock_fd:          42,
        user_tag:         999,
        is_backpressured: true,
        in_use:           true,
        ..
    };

    g_async_writable_called = false;
    g_async_aborted_fd = -1;
    g_async_aborted_tag = 0;

    // 1. Socket drains: triggers onWritable
    let drained = wing::notify_socket_writable(ctx, on_test_socket_writable);
    t.assert_true(drained, "notify_socket_writable returned true");
    t.assert_true(g_async_writable_called, "onWritable callback executed");
    t.assert_false(ctx.is_backpressured, "Backpressured state cleared on drain");

    // 2. Client terminates prematurely: triggers onAborted
    wing::notify_client_aborted(ctx, on_test_client_aborted);
    t.assert_true(ctx.is_aborted, "Context marked is_aborted");
    t.assert_eq(g_async_aborted_fd, 42, "onAborted received correct fd");
    t.assert_eq(g_async_aborted_tag, 999, "onAborted received correct user tag");

    // Further writable notifications MUST be ignored after abort
    g_async_writable_called = false;
    let blocked = wing::notify_socket_writable(ctx, on_test_socket_writable);
    t.assert_false(blocked, "Writable notification rejected when connection aborted");
    t.assert_false(g_async_writable_called, "onWritable not called when connection aborted");
}

// --- Test 56: Dynamic Runtime SNI Multi-Certificate Registry ---
fn test_uweb_dynamic_sni_registry(t: lit::T&) {
    var server = wing::new_http_server("test-sni");

    let cert_main: const u8[:] = "-----BEGIN CERTIFICATE-----\nMAIN\n-----END CERTIFICATE-----";
    let key_main:  const u8[:] = "-----BEGIN PRIVATE KEY-----\nMAIN_KEY\n-----END PRIVATE KEY-----";

    let cert_wildcard: const u8[:] = "-----BEGIN CERTIFICATE-----\nWILDCARD\n-----END CERTIFICATE-----";
    let key_wildcard:  const u8[:] = "-----BEGIN PRIVATE KEY-----\nWILDCARD_KEY\n-----END PRIVATE KEY-----";

    let cert_special: const u8[:] = "-----BEGIN CERTIFICATE-----\nSPECIAL\n-----END CERTIFICATE-----";
    let key_special:  const u8[:] = "-----BEGIN PRIVATE KEY-----\nSPECIAL_KEY\n-----END PRIVATE KEY-----";

    // 1. Direct SNI pattern matcher compliance (RFC 6125 §6.4.3)
    t.assert_true(wing::sni_pattern_matches("example.com", "example.com"), "Exact domain matches");
    t.assert_true(wing::sni_pattern_matches("example.com", "EXAMPLE.COM"), "Exact domain case-insensitive");
    t.assert_true(wing::sni_pattern_matches("*.example.com", "api.example.com"), "Wildcard matches subdomain");
    t.assert_true(wing::sni_pattern_matches("*.example.com", "API.EXAMPLE.COM"), "Wildcard case-insensitive");
    t.assert_false(wing::sni_pattern_matches("*.example.com", "example.com"), "Wildcard does NOT match apex domain");
    t.assert_false(wing::sni_pattern_matches("*.example.com", "deep.sub.example.com"), "Wildcard does NOT match multi-level subdomain");
    t.assert_false(wing::sni_pattern_matches("*.example.com", "other.org"), "Wildcard does NOT match different domain");

    // 2. Register domains (app.addServerName)
    let ok_add1 = wing::add_server_name(server, "api.example.com", cert_main, key_main);
    t.assert_true(ok_add1, "Added exact domain api.example.com");

    let ok_add2 = wing::add_server_name(server, "*.wildcard.org", cert_wildcard, key_wildcard);
    t.assert_true(ok_add2, "Added wildcard domain *.wildcard.org");

    let ok_add3 = wing::add_server_name(server, "special.wildcard.org", cert_special, key_special);
    t.assert_true(ok_add3, "Added special override domain special.wildcard.org");

    t.assert_eq(server.sni_registry.count, 3, "3 SNI domain entries registered");

    // 3. Resolve exact match
    let cred1, ok1 = wing::resolve_sni_credentials(server, "api.example.com");
    t.assert_true(ok1, "Resolved api.example.com");
    t.assert_eq(cred1.cert_pem, cert_main, "Exact match returned correct cert");
    t.assert_eq(cred1.key_pem, key_main, "Exact match returned correct key");

    // 4. Resolve exact match case-insensitive
    let cred1_case, ok1_case = wing::resolve_sni_credentials(server, "API.EXAMPLE.COM");
    t.assert_true(ok1_case, "Resolved API.EXAMPLE.COM case-insensitive");
    t.assert_eq(cred1_case.cert_pem, cert_main, "Case-insensitive matched correct cert");

    // 5. Resolve wildcard match
    let cred2, ok2 = wing::resolve_sni_credentials(server, "sub.wildcard.org");
    t.assert_true(ok2, "Resolved sub.wildcard.org via wildcard");
    t.assert_eq(cred2.cert_pem, cert_wildcard, "Wildcard returned wildcard cert");

    // 6. Exact match priority over wildcard
    let cred3, ok3 = wing::resolve_sni_credentials(server, "special.wildcard.org");
    t.assert_true(ok3, "Resolved special.wildcard.org");
    t.assert_eq(cred3.cert_pem, cert_special, "Exact priority returned special cert, not wildcard cert");

    // 7. Non-matching queries
    let _, ok_apex = wing::resolve_sni_credentials(server, "wildcard.org");
    t.assert_false(ok_apex, "Apex domain rejected by wildcard SNI");

    let _, ok_multi = wing::resolve_sni_credentials(server, "deep.sub.wildcard.org");
    t.assert_false(ok_multi, "Multi-level subdomain rejected by wildcard SNI");

    let _, ok_unreg = wing::resolve_sni_credentials(server, "unregistered.net");
    t.assert_false(ok_unreg, "Unregistered domain returns false");

    // 8. Fallback for missing server name (app.missingServerName)
    let cred_fb, ok_fb = wing::resolve_sni_credentials_with_fallback(server, "dynamic.fallback.io", test_missing_sni_fallback);
    t.assert_true(ok_fb, "Fallback handler resolved missing server name");
    t.assert_eq(cred_fb.cert_pem, "FALLBACK_CERT_PEM", "Fallback cert returned");

    // 9. Remove server name (app.removeServerName)
    let ok_rem = wing::remove_server_name(server, "api.example.com");
    t.assert_true(ok_rem, "remove_server_name succeeded");
    t.assert_eq(server.sni_registry.count, 2, "SNI registry count decremented to 2");

    let _, ok_post_rem = wing::resolve_sni_credentials(server, "api.example.com");
    t.assert_false(ok_post_rem, "api.example.com no longer resolves after removal");
}

// --- Test 57: Unix Domain Sockets (AF_UNIX) & Socket Adoption ---
fn test_uweb_unix_domain_sockets_and_adopt_socket(t: lit::T&) {
    var server = wing::new_http_server("test-uds");

    // 1. Socket Adoption (us_adopt_accepted_socket)
    let raw_sock = wing::tcp_listen("127.0.0.1", 0, 16);
    t.assert_gt(raw_sock, 0, "Created raw listener socket");

    let adopted = wing::adopt_socket(server, raw_sock);
    t.assert_eq(adopted, raw_sock, "Socket adopted successfully and matches descriptor");

    let bad_adopted = wing::adopt_socket(server, -1);
    t.assert_eq(bad_adopted, -1, "Invalid descriptor adoption rejected with -1");

    wing::tcp_close(raw_sock);

    // 2. Unix Domain Sockets (AF_UNIX) Listen & Connect
    let uds_path: const u8[:] = "./test_uweb_uds.sock";
    let uds_listener = wing::listen_unix(server, uds_path, 16);
    t.assert_gt(uds_listener, 0, "listen_unix created AF_UNIX listener");

    let uds_client = wing::tcp_connect_unix(uds_path);
    t.assert_gt(uds_client, 0, "tcp_connect_unix connected to AF_UNIX socket");

    let uds_conn = wing::tcp_accept(uds_listener, 2000);
    t.assert_gt(uds_conn, 0, "Accepted AF_UNIX client connection");

    // Full duplex data transfer over AF_UNIX socket
    let sent = wing::tcp_send(uds_client, "PING_UDS");
    t.assert_eq(sent, 8, "Sent 8 bytes over AF_UNIX client");

    var srv_buf: u8[..64] = [];
    let recvd = wing::tcp_recv(uds_conn, srv_buf, 2000);
    t.assert_eq(recvd, 8, "Server received 8 bytes over AF_UNIX");
    t.assert_eq(srv_buf[..8], "PING_UDS", "Server received authentic payload");

    let replied = wing::tcp_send(uds_conn, "PONG_UDS");
    t.assert_eq(replied, 8, "Server replied 8 bytes over AF_UNIX");

    var client_buf: u8[..64] = [];
    let recvd_cli = wing::tcp_recv(uds_client, client_buf, 2000);
    t.assert_eq(recvd_cli, 8, "Client received 8 bytes over AF_UNIX");
    t.assert_eq(client_buf[..8], "PONG_UDS", "Client received authentic reply");

    // Clean up
    wing::tcp_close(uds_client);
    wing::tcp_close(uds_conn);
    wing::tcp_close(uds_listener);
}

fn main() {
    var runner = lit::new_runner("uWS Behavioral Compatibility Suite", lit::Verbosity.Verbose);

    lit::run_case(runner, "1. Declarative WebSocket Route Registration", test_declarative_ws_routing);
    lit::run_case(runner, "2. Per-Socket Typed UserData / Inline State", test_per_socket_user_data);
    lit::run_case(runner, "3. Dynamic Backpressure Control & Drainage Notifications", test_backpressure_and_drain);
    lit::run_case(runner, "4. Selective Per-Message Compression", test_selective_compression);
    lit::run_case(runner, "5. Heartbeat Daemon & Idle Timeout Sweeper", test_heartbeat_and_idle_sweeper);
    lit::run_case(runner, "6. Pub/Sub Subscription Counts & Socket Topics", test_subscription_counts_and_topics);
    lit::run_case(runner, "7. Asynchronous WebSocket Upgrade & Abort Safety", test_async_upgrade_and_aborted);
    lit::run_case(runner, "8. EventLoop Defer & Dedicated Compressor", test_loop_defer_and_dedicated_compressor);
    lit::run_case(runner, "9. 256-bit Header BloomFilter", test_header_bloom_filter);
    lit::run_case(runner, "10. Fast HTTP/1.1 Response Serialization", test_fast_serialization);
    lit::run_case(runner, "11. Zero-Copy WebSocket Ingress View", test_zero_copy_websocket_view);
    lit::run_case(runner, "12. Shared TCP Buffer & Direct Slice Recv", test_shared_tcp_buffer);
    lit::run_case(runner, "13. Native Pub/Sub TopicTree Engine", test_topic_tree_pubsub);
    lit::run_case(runner, "14. Vectored I/O (tcp_send2 / WSASend)", test_vectored_io);
    lit::run_case(runner, "15. 16 KB CorkBuffer Syscall Coalescing", test_server_cork_buffer);
    lit::run_case(runner, "16. Unrolled Handshake, Cached Date & SWAR UTF-8", test_handshake_and_date_and_swar_utf8);
    lit::run_case(runner, "17. Fast In-Place Query Parser", test_fast_query_parser);
    lit::run_case(runner, "18. Share-Nothing Epoll Reactor & Non-blocking Multiplexing", test_epoll_reactor_multiplexer);
    lit::run_case(runner, "19. SWAR 64-bit Parallel Control Character Scanning", test_swar_ctl_scanner);
    lit::run_case(runner, "20. Fast Integer & Hex to ASCII Serializers", test_fast_integer_ascii_serializers);
    lit::run_case(runner, "21. In-Place WebSocket Unmasking with Header Overwrite", test_ws_unmask_shifted_header_overwrite);
    lit::run_case(runner, "22. 64-bit Register FSM Chunked Stream Decoder", test_chunked_fsm_decoder);
    lit::run_case(runner, "23. Dual-Expiry Coalescing HTTP Route Cache", test_http_route_cache);
    lit::run_case(runner, "24. 1-Byte Modular Tick Timer Wheel", test_tick_timer_wheel);
    lit::run_case(runner, "25. Wire Buffer Sentinel Fencing", test_buffer_fencing_margin);
    lit::run_case(runner, "26. TCP QuickACK and Cork Control", test_tcp_quickack_and_cork);
    lit::run_case(runner, "27. #1951 Non-ASCII / UTF-8 Request Target Rejection", test_uweb_1951_non_ascii_url_rejection);
    lit::run_case(runner, "28. #1855 Duplicate Content-Length in HEAD Responses", test_uweb_1855_head_content_length_duplicate);
    lit::run_case(runner, "29. #1927 PROXY Protocol Enforcement Without Fallthrough", test_uweb_1927_proxy_enforcement_and_no_fallthrough);
    lit::run_case(runner, "30. #1407 WebSocket Control Frame Protocol Error (1002)", test_uweb_1407_control_frame_protocol_error);
    lit::run_case(runner, "31. #1933 TopicTree Trailing Wildcard & Safe Zero Publish", test_uweb_1933_topictree_trailing_wildcard);
    lit::run_case(runner, "32. #263 Socket Handle Lifecycle & Inheritance Defense", test_usock_263_socket_lifecycle_and_non_blocking_clean);
    lit::run_case(runner, "33. #1949 Host Header Invariant Enforcement (RFC 9112 §3.2)", test_uweb_1949_host_header_validation);
    lit::run_case(runner, "34. #1370 Status 204 No Content Strip Content-Length", test_uweb_1370_204_no_content_length);
    lit::run_case(runner, "35. RFC 6455 §7.4.1 Omit 1005 on Wire in Empty Close Frames", test_rfc_6455_1005_empty_close_payload);
    lit::run_case(runner, "36. #1952 OPTIONS * Acceptance & GET/POST * Rejection", test_uweb_1952_options_asterisk_and_get_asterisk_rejection);
    lit::run_case(runner, "37. #1932 Block Outbound WebSocket Sends After Close", test_uweb_1932_ws_send_blocked_when_closed);
    lit::run_case(runner, "38. MQTT §4.7.1.2 TopicTree Wildcard Syntax Validation", test_mqtt_invalid_multilevel_wildcard_rejection);
    lit::run_case(runner, "39. #1090 TopicTree Wildcard Publish Rejection", test_uweb_1090_mqtt_wildcard_publish_rejection);
    lit::run_case(runner, "40. #1944 Query Lookup with Encoded Keys & Valueless", test_uweb_1944_query_lookup_encoded_and_valueless);
    lit::run_case(runner, "41. #1898 Extra Trailing Bytes Connection Poisoning Defense", test_uweb_1898_extra_bytes_connection_poisoning);
    lit::run_case(runner, "42. RFC 6455 §5.2 Non-Minimal WebSocket Length Protocol Error", test_rfc_6455_non_minimal_length_protocol_error);
    lit::run_case(runner, "43. #1658 HTTP Header Block 8KB Limit Enforcement", test_uweb_1658_max_header_size_rejection);
    lit::run_case(runner, "44. #101 Windows SO_EXCLUSIVEADDRUSE Port Hijack Defense", test_usock_101_windows_exclusive_port_defense);
    lit::run_case(runner, "45. RFC 6455 §4.2.1 Sec-WebSocket-Key Nonce Validation", test_rfc_6455_sec_websocket_key_validation);
    lit::run_case(runner, "46. #1948 PROXY v2 Family & LOCAL Command Address Validation", test_uweb_1948_proxy_v2_command_and_family_validation);
    lit::run_case(runner, "47. #258 Windows Connect RST Immediate Failure via exceptfds", test_usock_258_windows_connect_rst_immediate_failure);
    lit::run_case(runner, "48. #1941 Transfer-Encoding List & Final Chunked Requirement", test_uweb_1941_transfer_encoding_list_and_final_chunked);
    lit::run_case(runner, "49. #1936 Chunk Extension & Size Whitespace Validation (RFC 9112 §7.1.1)", test_uweb_1936_chunk_extension_and_size_whitespace_validation);
    lit::run_case(runner, "50. PreparedMessage & publishPrepared", test_uweb_prepared_message);
    lit::run_case(runner, "51. WebSocket maxLifetime Session Timeout", test_uweb_max_lifetime_sweeper);
    lit::run_case(runner, "52. #1347 Safari 15.0-15.3 Broken Compression Workaround", test_uweb_safari_15_broken_compression);
    lit::run_case(runner, "53. endWithoutBody & HEAD/304 Content-Length Spoofing", test_uweb_end_without_body);
    lit::run_case(runner, "54. Streaming Ingress onData / onDataV2", test_uweb_streaming_on_data);
    lit::run_case(runner, "55. Async Backpressure (onWritable) & Abort (onAborted)", test_uweb_async_backpressure_and_aborted);
    lit::run_case(runner, "56. Dynamic Runtime SNI Multi-Certificate Registry", test_uweb_dynamic_sni_registry);
    lit::run_case(runner, "57. Unix Domain Sockets (AF_UNIX) & Socket Adoption", test_uweb_unix_domain_sockets_and_adopt_socket);

    let ok = lit::finish(runner);
    assert(ok);
}
