// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Fault Tolerance & Concurrency Verification Suite.
// Verifies:
// 1. Synchronous HttpServer.serve connection capping and clean loop exit.
// 2. Share-nothing HttpServer.serve_reactor connection capping, multiplexing, and teardown.
// 3. TopicTree multi-subscriber live WebSocket broadcast & batched palette drainage.
import std;
import core from "..";
import wing from "..";

struct ServerSpawnConfig {
    listener_fd: i64 = -1,
    max_conns: i64 = 0,
}

thread_fn serve_sync_worker() {
    let cfg = core::recv_msg<ServerSpawnConfig>();
    var app = wing::new_http_server("127.0.0.1", 0);
    wing::add_get_route(app, "/ping", 100);
    let served = wing::serve(app, cfg.listener_fd, cfg.max_conns);
    core::send_msg(served);
}

thread_fn serve_reactor_worker() {
    let cfg = core::recv_msg<ServerSpawnConfig>();
    var app = wing::new_http_server("127.0.0.1", 0);
    wing::add_get_route(app, "/hello", 101);
    let served = wing::serve_reactor(app, cfg.listener_fd, cfg.max_conns);
    core::send_msg(served);
}

fn test_serve_connection_capping(t: core::T&) {
    t.run("Case 1: HttpServer.serve Clean Connection Capping (max_connections = 3)") { sub =>
        let listener = wing::tcp_listen("127.0.0.1", 0, 16);
        sub.assert_gt(listener, 0, "Listener created");
        defer wing::tcp_close(listener);

        let port = wing::tcp_getsockname_port(listener);
        let worker_tid = thread_spawn(serve_sync_worker);
        core::send_msg(ServerSpawnConfig { listener_fd: listener, max_conns: 3 });

        for i in 3 {
            let client = wing::tcp_connect("127.0.0.1", port, 2000);
            sub.assert_gt(client, 0, "Client connected");

            let req_wire: const u8[:] = "GET /ping HTTP/1.1\r\nHost: 127.0.0.1\r\nSec-Fetch-Site: same-origin\r\nConnection: close\r\n\r\n";
            let s = wing::tcp_send(client, req_wire);
            sub.assert_eq(s, req_wire.len as i32, "Client sent request");

            var resp_buf: u8[..512] = [];
            let r = wing::tcp_recv(client, resp_buf, 512, 2000);
            sub.assert_gt(r, 0, "Client received response");
            sub.assert_true(core::index_of_slice(resp_buf[..], "200 OK") >= 0, "Response is 200 OK");

            wing::tcp_close(client);
        }

        let served = core::recv_msg<i64>();
        sub.assert_eq(served, 3, "HttpServer.serve processed exactly 3 connections");

        let wait_ok = thread_wait(worker_tid);
        sub.assert_true(wait_ok, "serve worker thread terminated cleanly");
    };
}

fn test_serve_reactor_connection_capping(t: core::T&) {
    t.run("Case 2: HttpServer.serve_reactor Connection Capping & Epoll Shutdown") { sub =>
        let listener = wing::tcp_listen("127.0.0.1", 0, 16);
        sub.assert_gt(listener, 0, "Listener created");
        defer wing::tcp_close(listener);

        let port = wing::tcp_getsockname_port(listener);
        let worker_tid = thread_spawn(serve_reactor_worker);
        core::send_msg(ServerSpawnConfig { listener_fd: listener, max_conns: 3 });

        for i in 3 {
            let client = wing::tcp_connect("127.0.0.1", port, 2000);
            sub.assert_gt(client, 0, "Client connected");

            let req_wire: const u8[:] = "GET /hello HTTP/1.1\r\nHost: 127.0.0.1\r\nSec-Fetch-Site: same-origin\r\nConnection: close\r\n\r\n";
            let s = wing::tcp_send(client, req_wire);
            sub.assert_eq(s, req_wire.len as i32, "Client sent request");

            var resp_buf: u8[..512] = [];
            let r = wing::tcp_recv(client, resp_buf, 512, 2000);
            sub.assert_gt(r, 0, "Client received response");
            sub.assert_true(core::index_of_slice(resp_buf[..], "200 OK") >= 0, "Response is 200 OK");

            wing::tcp_close(client);
        }

        let served = core::recv_msg<i64>();
        sub.assert_eq(served, 3, "HttpServer.serve_reactor processed exactly 3 connections");

        let wait_ok = thread_wait(worker_tid);
        sub.assert_true(wait_ok, "serve_reactor worker thread terminated cleanly");
    };
}

fn test_topic_tree_live_broadcast_and_batch_drain(t: core::T&) {
    t.run("Case 3: TopicTree Live Socket Broadcast & Batch Drainage") { sub =>
        let listener = wing::tcp_listen("127.0.0.1", 0, 16);
        sub.assert_gt(listener, 0, "Listener created");
        defer wing::tcp_close(listener);

        let port = wing::tcp_getsockname_port(listener);

        let c1 = wing::tcp_connect("127.0.0.1", port, 2000);
        let c2 = wing::tcp_connect("127.0.0.1", port, 2000);
        let c3 = wing::tcp_connect("127.0.0.1", port, 2000);
        sub.assert_gt(c1, 0, "Client 1 connected");
        sub.assert_gt(c2, 0, "Client 2 connected");
        sub.assert_gt(c3, 0, "Client 3 connected");
        defer wing::tcp_close(c1);
        defer wing::tcp_close(c2);
        defer wing::tcp_close(c3);

        let s1 = wing::tcp_accept(listener, 2000);
        let s2 = wing::tcp_accept(listener, 2000);
        let s3 = wing::tcp_accept(listener, 2000);
        sub.assert_gt(s1, 0, "Server accepted 1");
        sub.assert_gt(s2, 0, "Server accepted 2");
        sub.assert_gt(s3, 0, "Server accepted 3");
        defer wing::tcp_close(s1);
        defer wing::tcp_close(s2);
        defer wing::tcp_close(s3);

        var tree = wing::new_topic_tree();
        sub.assert_true(wing::subscribe(tree, s1, "chat/general"), "s1 subscribed to chat/general");
        sub.assert_true(wing::subscribe(tree, s2, "chat/general"), "s2 subscribed to chat/general");
        sub.assert_true(wing::subscribe(tree, s3, "alerts/#"), "s3 subscribed to alerts/#");

        let sent_count = wing::publish_text(tree, "chat/general", "ROOM_MSG");
        sub.assert_eq(sent_count, 2, "Dispatched to both subscribers s1 and s2");

        var buf1: u8[..256] = [];
        let r1 = wing::tcp_recv(c1, buf1, 256, 1000);
        sub.assert_gt(r1, 0, "Client 1 received frame");
        sub.assert_true(core::index_of_slice(buf1[..], "ROOM_MSG") >= 0, "Frame contains ROOM_MSG");

        var buf2: u8[..256] = [];
        let r2 = wing::tcp_recv(c2, buf2, 256, 1000);
        sub.assert_gt(r2, 0, "Client 2 received frame");
        sub.assert_true(core::index_of_slice(buf2[..], "ROOM_MSG") >= 0, "Frame contains ROOM_MSG");

        let queued = wing::publish_batch(tree, "alerts/fire", "EVACUATE");
        sub.assert_eq(queued, 1, "Queued to 1 subscriber matching wildcard alerts/#");
        sub.assert_gt(wing::drainable_count(tree), 0, "Drainable subscribers pending");

        let drained = wing::drain(tree);
        sub.assert_eq(drained, 1, "Drained 1 batched message to wire");
        sub.assert_eq(wing::drainable_count(tree), 0, "Zero drainable subscribers remaining");

        var buf3: u8[..256] = [];
        let r3 = wing::tcp_recv(c3, buf3, 256, 1000);
        sub.assert_gt(r3, 0, "Client 3 received drained alert frame");
        sub.assert_true(core::index_of_slice(buf3[..], "EVACUATE") >= 0, "Alert frame contains EVACUATE");
    };
}

fn main() {
    var runner = core::new_runner("Server Fault Tolerance & Concurrency Suite", core::Verbosity.Verbose);
    core::run_case(runner, "1. HttpServer.serve Connection Capping", test_serve_connection_capping);
    core::run_case(runner, "2. HttpServer.serve_reactor Connection Capping", test_serve_reactor_connection_capping);
    core::run_case(runner, "3. TopicTree Live Broadcast & Batch Drainage", test_topic_tree_live_broadcast_and_batch_drain);
    let ok = core::finish(runner);
    assert(ok);
}
