// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Red Test Vector for TCP Half-Close & Graceful Shutdown State Transitions (WING-BUG-ND-02).
// Upstream references:
// - uWebSockets/uSockets #148: closeOnBackpressureLimit / deferred shutdown handling.
// - uWebSockets #1932: Block all socket sends after closing/shutdown is initiated.
// - Go net/http #82375: Server truncates response with RST on shutdown when slow reader leaves data in write queue.
// - Go net/http #18527: Half-closed connection triggers request cancellation (server must support peer FIN while writing).
// - RFC 9293 Section 3.5: TCP Close sequence & full-duplex half-closed states (CLOSE_WAIT / FIN_WAIT_2).
// - RFC 1122 Section 4.2.2.13: TCP close and lingering options (SO_LINGER).
import std;
import core from "..";
import wing from "..";

fn test_half_close_deferred_shutdown(t: core::T&) {
    t.run("Case 1: Deferred Shutdown on Active Backpressure & Re-entrant Send Block") { sub =>
        let listener = wing::tcp_listen("127.0.0.1", 0, 16);
        sub.assert_gt(listener, 0, "Listener created");
        defer wing::tcp_close(listener);

        let port = wing::tcp_getsockname_port(listener);
        let client = wing::tcp_connect("127.0.0.1", port, 2000);
        sub.assert_gt(client, 0, "Client connected");
        defer wing::tcp_close(client);

        let server_conn = wing::tcp_accept(listener, 2000);
        sub.assert_gt(server_conn, 0, "Server accepted");
        defer wing::tcp_close(server_conn);

        var cork = core::new_cork_buffer();
        var bp = wing::new_backpressure();

        // 1. Simulate active backpressure: data is buffered in BackPressure queue
        let payload: const u8[:] = "CRITICAL_TRANSACTION_PAYLOAD_BEFORE_SHUTDOWN";
        let append_ok = wing::backpressure_append(bp, payload);
        sub.assert_true(append_ok, "Backpressure contains payload");
        sub.assert_gt(wing::backpressure_len(bp), 0, "Backpressure length > 0");

        // 2. Initiate graceful shutdown while backpressure is active:
        // Must NOT shut down wire immediately (which drops unsent data or causes RST),
        // but must DEFER shutdown until backpressure drains completely.
        let did_shut, is_deferred = wing::async_socket_shutdown(client, bp, cork);
        sub.assert_false(did_shut, "Immediate shutdown must NOT execute while backpressure is pending");
        sub.assert_true(is_deferred, "Shutdown must be marked deferred");
        sub.assert_true(bp.shutdown_pending, "bp.shutdown_pending must be true");
        sub.assert_false(bp.write_shut, "bp.write_shut must be false while deferred");

        // 3. uWebSockets #1932: Block subsequent writes once shutdown is pending
        let extra_data: const u8[:] = "SHOULD_BE_DROPPED_AFTER_SHUTDOWN";
        let wr_sent, wr_poll = wing::async_socket_write(client, cork, bp, extra_data);
        sub.assert_eq(wr_sent, 0, "Writes must be rejected after shutdown initiated");
        sub.assert_false(wr_poll, "No writable poll needed for rejected write");

        // 4. Drain backpressure: on final drain, deferred shutdown must trigger automatically
        var total_drained: i32 = 0;
        while wing::backpressure_len(bp) > 0 {
            let drained, empty = wing::async_socket_drain(client, bp);
            if drained > 0 {
                total_drained += drained;
            }
            if empty {
                break;
            }
        }

        sub.assert_eq(total_drained, payload.len as i32, "All queued payload drained to wire");
        sub.assert_eq(wing::backpressure_len(bp), 0, "Backpressure is completely empty");
        sub.assert_false(bp.shutdown_pending, "Deferred shutdown is no longer pending");
        sub.assert_true(bp.write_shut, "Write side is now cleanly shut down");

        // 5. Server reads the full payload and then receives EOF (FIN from client)
        var srv_buf: u8[..1024] = [];
        let recvd = wing::tcp_recv(server_conn, srv_buf, 1024, 2000);
        sub.assert_eq(recvd, payload.len as i32, "Server received complete queued payload");
        sub.assert_eq(srv_buf[..recvd], payload, "Payload content matches wire byte-for-byte");

        // Server receives EOF (clean FIN from SHUT_WR)
        var eof_buf: u8[..64] = [];
        let eof = wing::tcp_recv(server_conn, eof_buf, 64, 1000);
        sub.assert_eq(eof, 0, "Server observed EOF (FIN) after payload drained");
    };
}

fn test_peer_fin_half_closed_response(t: core::T&) {
    t.run("Case 2: Peer FIN Handling & Server Response in CLOSE_WAIT State") { sub =>
        let listener = wing::tcp_listen("127.0.0.1", 0, 16);
        let port = wing::tcp_getsockname_port(listener);
        let client = wing::tcp_connect("127.0.0.1", port, 2000);
        let server_conn = wing::tcp_accept(listener, 2000);
        defer wing::tcp_close(listener);
        defer wing::tcp_close(client);
        defer wing::tcp_close(server_conn);

        // 1. Client sends request
        let req_data: const u8[:] = "GET /fast-close HTTP/1.1\r\n\r\n";
        wing::tcp_send(client, req_data);

        // Client immediately shuts down its writing side (half-close / FIN, Go #18527)
        let shut_ok = wing::tcp_shutdown(client, wing::SHUT_WR);
        sub.assert_true(shut_ok, "Client tcp_shutdown(SHUT_WR) succeeded");

        // 2. Server reads request followed by EOF (peer FIN)
        var srv_req: u8[..1024] = [];
        let r1 = wing::tcp_recv(server_conn, srv_req, 1024, 2000);
        sub.assert_eq(r1, req_data.len as i32, "Server read request");

        var eof_probe: u8[..16] = [];
        let eof = wing::tcp_recv(server_conn, eof_probe, 16, 500);
        sub.assert_eq(eof, 0, "Server detected peer FIN (EOF on read)");

        // 3. Server marks peer FIN
        var server_bp = wing::new_backpressure();
        wing::async_socket_on_peer_fin(server_conn, server_bp);
        sub.assert_true(server_bp.peer_fin_received, "Server registered peer FIN in backpressure state");

        // 4. Server can STILL write response back to client (RFC 9293 full-duplex half-close)
        var server_cork = core::new_cork_buffer();
        let resp_data: const u8[:] = "HTTP/1.1 200 OK\r\nContent-Length: 12\r\n\r\nHALF_CLOSE_OK";
        let wr_bytes, _ = wing::async_socket_write(server_conn, server_cork, server_bp, resp_data);
        sub.assert_gt(wr_bytes, 0, "Server successfully wrote response despite peer half-close");

        // Uncork server response
        wing::async_socket_uncork(server_conn, server_cork, server_bp);

        // 5. Client can still read the entire server response even after having shut down its write side!
        var cli_resp: u8[..1024] = [];
        let r2 = wing::tcp_recv(client, cli_resp, 1024, 2000);
        sub.assert_eq(r2, resp_data.len as i32, "Client received full response from half-closed peer");
        sub.assert_eq(cli_resp[..r2], resp_data, "Response matches wire bytes");
    };
}

fn test_socket_options_tuning(t: core::T&) {
    t.run("Case 3: Live OS Socket Options (SO_LINGER, TCP_NODELAY, SO_REUSEADDR)") { sub =>
        let listener = wing::tcp_listen("127.0.0.1", 0, 16);
        sub.assert_gt(listener, 0, "Listener created");
        defer wing::tcp_close(listener);

        let port = wing::tcp_getsockname_port(listener);
        let client = wing::tcp_connect("127.0.0.1", port, 2000);
        sub.assert_gt(client, 0, "Client connected");
        defer wing::tcp_close(client);

        // 1. TCP_NODELAY toggle
        let nd_on = wing::tcp_set_nodelay(client, true);
        sub.assert_true(nd_on, "tcp_set_nodelay(true) succeeded");
        let nd_off = wing::tcp_set_nodelay(client, false);
        sub.assert_true(nd_off, "tcp_set_nodelay(false) succeeded");

        // 2. SO_LINGER tuning (RFC 1122 Section 4.2.2.13)
        // Reset linger: onoff=true, timeout_sec=0 -> RST on close (used in RST abort toxics)
        let linger_rst = wing::tcp_set_linger(client, true, 0);
        sub.assert_true(linger_rst, "tcp_set_linger(true, 0) succeeded");

        // Graceful linger: onoff=true, timeout_sec=5
        let linger_graceful = wing::tcp_set_linger(client, true, 5);
        sub.assert_true(linger_graceful, "tcp_set_linger(true, 5) succeeded");

        // Disable linger: onoff=false
        let linger_off = wing::tcp_set_linger(client, false, 0);
        sub.assert_true(linger_off, "tcp_set_linger(false, 0) succeeded");

        // 3. SO_REUSEADDR tuning
        let reuse_ok = wing::tcp_set_reuseaddr(listener, true);
        sub.assert_true(reuse_ok, "tcp_set_reuseaddr(true) succeeded");
    };
}

fn main() {
    var runner = core::new_runner("TCP Half-Close & Graceful Shutdown Suite", core::Verbosity.Verbose);
    core::run_case(runner, "1. Deferred Shutdown on Active Backpressure", test_half_close_deferred_shutdown);
    core::run_case(runner, "2. Peer FIN Half-Close Full-Duplex Ordering", test_peer_fin_half_closed_response);
    core::run_case(runner, "3. Live Socket Options Tuning", test_socket_options_tuning);
    let ok = core::finish(runner);
    assert(ok);
}
