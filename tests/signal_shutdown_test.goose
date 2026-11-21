// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Verification Suite: OS Shutdown Signals (SIGINT/SIGTERM), Programmatic Shutdown,
// HTTP/1.1 Connection: close Drain, and Reactor Graceful Exit.
//
// RUN: goose build -o %t.exe %s
// RUN: %t.exe
import std;
import os;
import wing from "..";
import lit from "github.com/Lemon4ksan/goose-lit@v0.1.0";

extern fn c_raise(sig: i32) -> i32 = "raise";

const TEST_SIGINT:  i32 = 2;
const TEST_SIGTERM: i32 = 15;

thread_fn delayed_shutdown_worker(delay_ms: i64) {
    sleep_ms(delay_ms);
    net::request_shutdown();
}

fn test_signal_flag_lifecycle(t: lit::T&) {
    net::reset_shutdown_signals();
    defer net::reset_shutdown_signals();

    t.assert_true(net::install_shutdown_signals(), "install_shutdown_signals returns true");
    t.assert_false(net::shutdown_requested(), "shutdown_requested starts false after reset");
    t.assert_false(net::consume_reload_signal(), "consume_reload_signal starts false");

    net::request_shutdown();
    t.assert_true(net::shutdown_requested(), "request_shutdown sets shutdown_requested to true");

    net::reset_shutdown_signals();
    t.assert_false(net::shutdown_requested(), "reset_shutdown_signals clears flag");
}

fn test_sigint_and_sigterm_raise(t: lit::T&) {
    net::reset_shutdown_signals();
    defer net::reset_shutdown_signals();

    t.assert_true(net::install_shutdown_signals(), "signal handlers installed");
    t.assert_eq(c_raise(TEST_SIGINT), 0, "raise(SIGINT) succeeds");
    t.assert_true(net::shutdown_requested(), "SIGINT sets shutdown_requested");

    net::reset_shutdown_signals();
    t.assert_false(net::shutdown_requested(), "reset clears SIGINT");

    t.assert_eq(c_raise(TEST_SIGTERM), 0, "raise(SIGTERM) succeeds");
    t.assert_true(net::shutdown_requested(), "SIGTERM sets shutdown_requested");
}

fn test_dispatch_honor_shutdown_flag_control(t: lit::T&) {
    net::reset_shutdown_signals();
    defer net::reset_shutdown_signals();

    var server = server::new_http_server("127.0.0.1", 0);
    t.assert_false(server.handle_os_signals, "handle_os_signals defaults to false (opt-in)");
    t.assert_true(server.honor_shutdown_flag, "honor_shutdown_flag defaults to true");
    t.assert_eq(server.shutdown_grace_ns, 2000000000, "shutdown_grace_ns defaults to 2s");

    server.pipeline.enable_csrf_guard = false;
    server.pipeline.enable_rate_limiter = false;
    server.honor_shutdown_flag = false;
    server::init_run_state(server);
    server.add_static_get_route("/ping", "text/plain", "pong", 1);

    net::request_shutdown();
    t.assert_false(server::should_stop(server), "server ignores global flag when honor_shutdown_flag=false");

    let wire_req = "GET /ping HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: keep-alive\r\n\r\n";
    var out_wire: u8[..4096] = [];
    let _, ok_keep = server::handle_connection_wire(
        server, "127.0.0.1", wire_req, 1000000000, out_wire,
    );
    t.assert_true(ok_keep, "keep-alive request succeeded while flag ignored");
    t.assert_true(server.is_running, "server.is_running remains true when honor_shutdown_flag=false");
    t.assert_true(
        out_wire[..].contains_fold("connection: keep-alive"),
        "response keeps keep-alive when honor_shutdown_flag=false",
    );

    server.honor_shutdown_flag = true;
    t.assert_true(server::should_stop(server), "server observes global flag once honor_shutdown_flag=true");

    out_wire.clear();
    let outcome, ok_close = server::handle_connection_wire(
        server, "127.0.0.1", wire_req, 1000000000, out_wire,
    );
    t.assert_true(ok_close, "handle_connection_wire succeeded during shutdown");
    t.assert_true(outcome == server::PipelineOutcome.Handled, "request was handled");
    t.assert_false(server.is_running, "server.is_running cleared during shutdown");
    t.assert_true(
        out_wire[..].contains_fold("connection: close"),
        "response carries Connection: close during shutdown",
    );
}

fn test_serve_http_listener_exits_on_worker_shutdown(t: lit::T&) {
    net::reset_shutdown_signals();
    defer net::reset_shutdown_signals();

    let listener = net::tcp_listen("127.0.0.1", 0, 8);
    t.assert_true(listener > 0, "ephemeral listener bound");
    defer net::tcp_close(listener);

    var server = server::new_http_server("127.0.0.1", 0);
    let tid = thread_spawn(delayed_shutdown_worker, 60);
    server::serve_http_listener(listener, server, 100);
    let joined = thread_wait(tid);

    t.assert_true(joined, "worker thread exited cleanly");
    t.assert_true(net::shutdown_requested(), "shutdown_requested observed");
    t.assert_false(server.is_running, "serve_http_listener cleared is_running");
}

fn test_serve_reactor_graceful_exit_and_live_client(t: lit::T&) {
    net::reset_shutdown_signals();
    defer net::reset_shutdown_signals();

    let listener = net::tcp_listen("127.0.0.1", 0, 16);
    t.assert_true(listener > 0, "ephemeral reactor listener bound");
    defer net::tcp_close(listener);

    let port = net::tcp_getsockname_port(listener);
    t.assert_true(port > 0, "bound port is valid");

    var server = server::new_http_server("127.0.0.1", port);
    server.pipeline.enable_csrf_guard = false;
    server.pipeline.enable_rate_limiter = false;
    server.shutdown_grace_ns = 100000000;
    server.add_static_get_route("/health", "text/plain", "OK", 1);

    let client = net::tcp_connect("127.0.0.1", port, 1000);
    t.assert_true(client > 0, "client connected before shutdown");
    defer net::tcp_close(client);

    let sent = net::tcp_send(client, "GET /health HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n");
    t.assert_true(sent > 0, "client sent request");

    let tid = thread_spawn(delayed_shutdown_worker, 120);
    let served = server::serve_reactor(server, listener, 0);
    let joined = thread_wait(tid);

    var buf: u8[..1024] = [];
    let recvd = net::tcp_recv(client, buf, 1024, 1000);
    t.assert_true(recvd > 0, "client received HTTP response before reactor exited");
    t.assert_true(buf[..recvd].contains_fold("200 OK"), "response status is 200 OK");
    t.assert_true(joined, "shutdown worker joined");
    t.assert_true(served >= 0, "reactor returned valid served count");
    t.assert_false(server.is_running, "reactor stopped cleanly on shutdown signal");
}

fn main() {
    var runner = lit::new_runner("Shutdown Signals & Graceful Server Exit Suite", lit::Verbosity.Verbose);

    lit::run_case(runner, "1. Signal Flag Lifecycle", test_signal_flag_lifecycle);
    lit::run_case(runner, "2. SIGINT and SIGTERM Handling", test_sigint_and_sigterm_raise);
    lit::run_case(runner, "3. Dispatch Caller Shutdown Control & Connection: close", test_dispatch_honor_shutdown_flag_control);
    lit::run_case(runner, "4. serve_http_listener Exits on Worker Shutdown", test_serve_http_listener_exits_on_worker_shutdown);
    lit::run_case(runner, "5. serve_reactor Serves Live Client & Exits on Shutdown", test_serve_reactor_graceful_exit_and_live_client);

    let ok = lit::finish(runner);
    assert(ok);
}
