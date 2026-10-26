// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Verification suite for uWebSockets Phase 2 & Phase 3 features in goose-wing:
// 1. Heartbeat Daemon & 1-Byte Modular Tick Sweeper (sendPingsAutomatically & idleTimeout)
// 2. Pub/Sub Subscription Count Hook & Room Lifecycle (subscription pattern)
// 3. Per-Socket Topic Enumeration (iterateTopics pattern)
// 4. Asynchronous WebSocket Upgrade & Abort Safety (res->onAborted & res->upgrade pattern)
// 5. Cross-Thread EventLoop Task Dispatch (loop->defer pattern)
// 6. Dedicated Sliding-Window Compression (DedicatedWsCompressor pattern)
import std;
import core from "..";
import wing from "..";

fn test_heartbeat_and_idle_sweeper(t: core::T&) {
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

fn test_subscription_counts_and_topics(t: core::T&) {
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

fn test_async_upgrade_and_aborted(t: core::T&) {
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
        sub.assert_eq(sess.get_user_data(), "auth:user_jwt_token", "UserData passed to session");

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

fn test_loop_defer_and_dedicated_compressor(t: core::T&) {
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
        sub.assert_eq(el.deferred_task_count(), 2, "Count is 2");

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

fn main() {
    var runner = core::new_runner("uWebSockets Phase 2 & 3 Features Verification Suite", core::Verbosity.Verbose);

    core::run_case(runner, "1. Heartbeat Daemon & Idle Timeout Sweeper", test_heartbeat_and_idle_sweeper);
    core::run_case(runner, "2. Pub/Sub Subscription Counts & Socket Topics", test_subscription_counts_and_topics);
    core::run_case(runner, "3. Asynchronous WebSocket Upgrade & Abort Safety", test_async_upgrade_and_aborted);
    core::run_case(runner, "4. EventLoop Defer & Dedicated Compressor", test_loop_defer_and_dedicated_compressor);

    let ok = core::finish(runner);
    assert(ok);
}
