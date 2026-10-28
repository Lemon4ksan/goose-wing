// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Red Test Vector for TCP Abrupt Teardown, RST vs FIN Invariant & Keepalive Boundary Validation (WING-BUG-ND-03).
// Upstream references:
// - RFC 1122 §4.2.2.13 (TCP Close & Abort Invariant: closing socket with unread receive data MUST issue RST).
// - RFC 1122 §4.2.3.6 (TCP Keepalive Timing Boundaries & Minimum Period).
// - Go net #40738 (TCP connection reset vs clean shutdown semantics on unread buffered data).
// - POSIX.1-2008 & Berkeley Sockets SO_LINGER zero-abort specification.
import std;
import core from "..";
import wing from "..";

fn test_abrupt_rst_on_unread_receive_data(t: core::T&) {
    t.run("Case 1: RFC 1122 §4.2.2.13 Abortive RST on Unread Receive Data") { sub =>
        let listener = wing::tcp_listen("127.0.0.1", 0, 16);
        sub.assert_gt(listener, 0, "Listener created");
        defer wing::tcp_close(listener);

        let port = wing::tcp_getsockname_port(listener);
        let client = wing::tcp_connect("127.0.0.1", port, 2000);
        sub.assert_gt(client, 0, "Client connected");
        defer wing::tcp_close(client);

        let server_conn = wing::tcp_accept(listener, 2000);
        sub.assert_gt(server_conn, 0, "Server accepted");

        // 1. Client sends data to server
        let wire_msg: const u8[:] = "UNREAD_TRANSACTION_PAYLOAD_MUST_TRIGGER_RST";
        let sent = wing::tcp_send(client, wire_msg);
        sub.assert_eq(sent, wire_msg.len as i32, "Client sent payload");

        // Give the OS kernel time to buffer incoming data in server socket receive queue
        core::sleep(core::millis(50));

        // Verify unread data is present in server receive queue
        let readable = wing::tcp_get_readable_bytes(server_conn);
        sub.assert_gt(readable, 0, "Server socket has unread bytes in receive buffer");

        // 2. Server closes socket via async_socket_close while unread data is still pending:
        // RFC 1122 §4.2.2.13 mandates that closing with unread data MUST issue an abortive RST,
        // never a graceful FIN!
        var srv_bp = wing::new_backpressure();
        let close_ok = wing::async_socket_close(server_conn, srv_bp);
        sub.assert_true(close_ok, "async_socket_close executed");

        // Give OS time to deliver RST packet
        core::sleep(core::millis(50));

        // 3. Client attempts to read or write on the connection:
        // Because server issued RST (not FIN), client MUST receive an error (-1 / WSAECONNRESET / ECONNRESET),
        // NOT a clean EOF (0)!
        var probe_buf: u8[..64] = [];
        let r = wing::tcp_recv(client, probe_buf, 64, 1000);
        sub.assert_eq(r, -1, "Client must observe connection reset (-1) from abortive RST, not clean EOF (0)");
    };
}

fn test_explicit_socket_abort(t: core::T&) {
    t.run("Case 2: Explicit tcp_abort and async_socket_abort RST Teardown") { sub =>
        let listener = wing::tcp_listen("127.0.0.1", 0, 16);
        let port = wing::tcp_getsockname_port(listener);
        let client = wing::tcp_connect("127.0.0.1", port, 2000);
        let server_conn = wing::tcp_accept(listener, 2000);
        defer wing::tcp_close(listener);
        defer wing::tcp_close(client);

        var srv_bp = wing::new_backpressure();
        wing::backpressure_append(srv_bp, "PENDING_DIRTY_DATA_TO_BE_DISCARDED");
        sub.assert_gt(wing::backpressure_len(srv_bp), 0, "Server backpressure holds pending data");

        // Explicit abort: discard backpressure and send immediate RST
        let abort_ok = wing::async_socket_abort(server_conn, srv_bp);
        sub.assert_true(abort_ok, "async_socket_abort returned true");
        sub.assert_eq(wing::backpressure_len(srv_bp), 0, "Backpressure cleared on abort");
        sub.assert_true(srv_bp.write_shut, "write_shut is true");

        core::sleep(core::millis(50));

        // Client observes connection reset (-1)
        var probe_buf: u8[..64] = [];
        let r = wing::tcp_recv(client, probe_buf, 64, 1000);
        sub.assert_eq(r, -1, "Client observes connection reset (-1) from explicit abort");
    };
}

fn test_keepalive_boundary_validation(t: core::T&) {
    t.run("Case 3: TCP Keepalive Boundary Validation (RFC 1122 §4.2.3.6)") { sub =>
        let listener = wing::tcp_listen("127.0.0.1", 0, 16);
        sub.assert_gt(listener, 0, "Listener created");
        defer wing::tcp_close(listener);

        // Valid configurations
        sub.assert_true(wing::tcp_set_keepalive(listener, 1, 11, 3), "Valid keepalive (1, 11, 3) accepted");
        sub.assert_true(wing::tcp_set_keepalive(listener, 60, 10, 5), "Valid keepalive (60, 10, 5) accepted");
        sub.assert_true(wing::tcp_set_keepalive(listener, 7200, 75, 9), "RFC 1122 standard 2-hour keepalive accepted");

        // Invalid configurations must be rejected with false
        sub.assert_false(wing::tcp_set_keepalive(listener, 0, 10, 5), "idle_sec=0 must be rejected");
        sub.assert_false(wing::tcp_set_keepalive(listener, -1, 10, 5), "negative idle_sec must be rejected");
        sub.assert_false(wing::tcp_set_keepalive(listener, 60, 0, 5), "intvl_sec=0 must be rejected");
        sub.assert_false(wing::tcp_set_keepalive(listener, 60, -5, 5), "negative intvl_sec must be rejected");
        sub.assert_false(wing::tcp_set_keepalive(listener, 60, 10, 0), "cnt=0 must be rejected");
        sub.assert_false(wing::tcp_set_keepalive(listener, 60, 10, -2), "negative cnt must be rejected");
        sub.assert_false(wing::tcp_set_keepalive(listener, 60, 10, 200), "excessive cnt (> 127) must be rejected");
        sub.assert_false(wing::tcp_set_keepalive(listener, 86400, 10, 5), "idle_sec > 7200 must be rejected");
    };
}

fn test_flow_control_state_tracking(t: core::T&) {
    t.run("Case 4: Backpressure Flow Control State Tracking") { sub =>
        var bp = wing::new_backpressure();
        sub.assert_false(wing::tcp_is_flow_controlled(bp), "Empty backpressure is not flow controlled");

        wing::backpressure_append(bp, "FLOW_CONTROLLED_PAYLOAD");
        sub.assert_true(wing::tcp_is_flow_controlled(bp), "Backpressure with pending data is flow controlled");

        wing::backpressure_clear(bp);
        sub.assert_false(wing::tcp_is_flow_controlled(bp), "Cleared backpressure is not flow controlled");
    };
}

fn main() {
    var runner = core::new_runner("TCP Abrupt Teardown, RST vs FIN & Keepalive Suite", core::Verbosity.Verbose);
    core::run_case(runner, "1. RFC 1122 §4.2.2.13 Abortive RST on Unread Receive Data", test_abrupt_rst_on_unread_receive_data);
    core::run_case(runner, "2. Explicit Socket Abort RST Teardown", test_explicit_socket_abort);
    core::run_case(runner, "3. TCP Keepalive Boundary Validation", test_keepalive_boundary_validation);
    core::run_case(runner, "4. Backpressure Flow Control State Tracking", test_flow_control_state_tracking);
    let ok = core::finish(runner);
    assert(ok);
}
