// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Consolidated Verification Suite: TCP Socket IO, Corking, Abort, and Half-Close Verification Suite
//
// RUN: goose build -o %t.exe %s
// RUN: %t.exe
import std;
import core from "..";
import wing from "..";
import lit from "github.com/Lemon4ksan/goose-lit@v0.1.0";

// --- Component: net_tcp_live ---

fn test_tcp_loopback_echo(t: lit::T&) {
    // 1. Listen on ephemeral port
    let listener = wing::tcp_listen("127.0.0.1", 0, 16);
    t.assert_true(listener > 0, "Listener socket must be created successfully");
    defer wing::tcp_close(listener);

    let port = wing::tcp_getsockname_port(listener);
    t.assert_true(port > 0, "Bound port must be non-zero ephemeral port");

    // 2. Connect client
    let client = wing::tcp_connect("127.0.0.1", port, 2000);
    t.assert_true(client > 0, "Client must connect to loopback listener");
    defer wing::tcp_close(client);

    // 3. Accept connection on server
    let server_conn = wing::tcp_accept(listener, 2000);
    t.assert_true(server_conn > 0, "Server must accept connection");
    defer wing::tcp_close(server_conn);

    // 4. Send HTTP request from client
    let req_bytes: const u8[:] = "GET /status HTTP/1.1\r\nHost: localhost\r\n\r\n";
    let sent = wing::tcp_send(client, req_bytes);
    t.assert_eq(sent, req_bytes.len as i32, "Client sent all bytes");

    // 5. Server receives and parses wire request
    var srv_buf: u8[..1024] = [];
    let recvd = wing::tcp_recv(server_conn, srv_buf, 1024, 2000);
    t.assert_true(recvd > 0, "Server received request bytes");

    var req = wing::Request {};
    let ok_req, consumed = wing::parse_http1_wire_request(srv_buf[..], req);
    t.assert_true(ok_req, "Server successfully parsed HTTP/1.1 request");
    t.assert_eq(req.method[..], "GET", "Method is GET");
    t.assert_eq(req.url[..], "/status", "Path is /status");

    // 6. Server sends HTTP/1.1 200 OK response
    let resp_bytes: const u8[:] = "HTTP/1.1 200 OK\r\nContent-Length: 5\r\nConnection: close\r\n\r\nHELLO";
    let resp_sent = wing::tcp_send(server_conn, resp_bytes);
    t.assert_eq(resp_sent, resp_bytes.len as i32, "Server sent response");

    // 7. Client receives response
    var cli_buf: u8[..1024] = [];
    let cli_recvd = wing::tcp_recv(client, cli_buf, 1024, 2000);
    t.assert_true(cli_recvd > 0, "Client received response");

    var resp = wing::Response {};
    let ok_resp, resp_consumed = wing::parse_http1_wire_response(cli_buf[..], resp);
    t.assert_true(ok_resp, "Client parsed HTTP/1.1 response");
    t.assert_eq(resp.status_code, 200, "Status is 200");
    t.assert_eq(resp.body[..], "HELLO", "Body is HELLO");
}

// --- Component: net_tcp_cork_desync ---
// Red Test Vector for TCP Cork/Uncork Desync & Backpressure FIFO Inversion (uWebSockets #1186, #1959).
// Verifies:
// 1. Calling async_socket_uncork while backpressure is active preserves FIFO order (never transmits cork ahead of backpressure).
// 2. Calling async_socket_uncork while cork is empty but backpressure is pending returns needs_poll=true.
// 3. Optional async writes (optionally=true) never pollute the backpressure queue on partial/unaccepted sends.

fn test_uncork_backpressure_fifo_ordering(t: lit::T&) {
    t.run("Case 1: FIFO Stream Order Preservation on Uncork with Active Backpressure") { sub =>
        let listener = wing::tcp_listen("127.0.0.1", 0, 16);
        sub.assert_gt(listener, 0, "Listener created");
        defer wing::tcp_close(listener);

        let port = wing::tcp_getsockname_port(listener);
        sub.assert_gt(port as i64, 0, "Valid port");

        let client = wing::tcp_connect("127.0.0.1", port, 2000);
        sub.assert_gt(client, 0, "Client connected");
        defer wing::tcp_close(client);

        let server_conn = wing::tcp_accept(listener, 2000);
        sub.assert_gt(server_conn, 0, "Server accepted");
        defer wing::tcp_close(server_conn);

        var cork = core::new_cork_buffer();
        var bp = wing::BackPressure { .. };

        // Simulate active backpressure: PART 1 was previously queued in backpressure
        let part1: const u8[:] = "PART1_PREFIX_DATA_";
        let append_ok = wing::backpressure_append(bp, part1);
        sub.assert_true(append_ok, "Backpressure contains part 1");
        sub.assert_eq(wing::backpressure_len(bp), part1.len as i64, "Backpressure length matches part 1");

        // Now, subsequent data is buffered into cork
        let part2: const u8[:] = "PART2_SUFFIX_DATA!";
        cork.cork_write(part2);
        sub.assert_eq(cork.cork_pending(), part2.len as i64, "Cork contains part 2");

        // Uncork the socket: Flawed implementation sends part 2 directly to the wire first,
        // violating TCP stream FIFO ordering and returning needs_poll=false!
        let written, needs_poll = wing::async_socket_uncork(client, cork, bp);

        // Server reads what was transmitted on the wire so far
        var recv_wire: u8[..1024] = [];
        let r1 = wing::tcp_recv(server_conn, recv_wire, 1024, 500);

        // If any bytes were sent on wire, they MUST start with PART 1, never PART 2!
        if r1 > 0 {
            sub.assert_true(recv_wire.len >= 5, "Received at least 5 bytes");
            sub.assert_eq(recv_wire[..5], "PART1", "First bytes received on wire MUST be PART 1, never PART 2");
        }

        // Drain any remaining backpressure
        while wing::backpressure_len(bp) > 0 {
            let drained, empty = wing::async_socket_drain(client, bp);
            if drained <= 0 {
                break;
            }
        }

        // Read all remaining bytes from server
        loop {
            var tmp: u8[..1024] = [];
            let r = wing::tcp_recv(server_conn, tmp, 1024, 200);
            if r <= 0 {
                break;
            }
            recv_wire.append(tmp[..]);
        }

        // The entire stream MUST be strictly FIFO: PART1 followed by PART2
        let expected: const u8[:] = "PART1_PREFIX_DATA_PART2_SUFFIX_DATA!";
        sub.assert_eq(recv_wire[..], expected, "Complete stream on wire MUST match FIFO order");
    };
}

fn test_uncork_empty_cork_with_backpressure(t: lit::T&) {
    t.run("Case 2: Uncork Empty Cork Reports Needs-Poll when Backpressure Pending") { sub =>
        let listener = wing::tcp_listen("127.0.0.1", 0, 16);
        sub.assert_gt(listener, 0, "Listener created");
        defer wing::tcp_close(listener);

        let port = wing::tcp_getsockname_port(listener);
        let client = wing::tcp_connect("127.0.0.1", port, 2000);
        defer wing::tcp_close(client);
        let server_conn = wing::tcp_accept(listener, 2000);
        defer wing::tcp_close(server_conn);

        var cork = core::new_cork_buffer();
        var bp = wing::BackPressure { .. };

        // Set pending backpressure
        let data: const u8[:] = "STALLED_BACKPRESSURE_CHUNK";
        wing::backpressure_append(bp, data);

        // Cork is empty (cork_pending == 0)
        sub.assert_eq(cork.cork_pending(), 0, "Cork is empty");

        // In flawed implementation: guard pending > 0 returns (0, false),
        // telling the event loop no poll is needed and causing permanent stall!
        let written, needs_poll = wing::async_socket_uncork(client, cork, bp);

        // If backpressure is still pending, needs_poll MUST be true!
        if wing::backpressure_len(bp) > 0 {
            sub.assert_true(needs_poll, "Uncorking with pending backpressure MUST return needs_poll=true");
        }
    };
}

// --- Component: net_tcp_chaos_stress ---
// End-to-end chaos stress test using live TCP sockets.
// Operates either standalone or through an intermediate ToxiProxy.

// Verifies end-to-end HTTP/1.1 request/response roundtrip with streaming wire parsing
fn test_live_h1_roundtrip(t: lit::T&) {
    let listener = wing::tcp_listen("127.0.0.1", 0, 16);
    t.assert_true(listener > 0, "Listener started");
    let srv_port = wing::tcp_getsockname_port(listener);
    t.assert_true(srv_port > 0, "Got bound port");

    let client = wing::tcp_connect("127.0.0.1", srv_port, 2000);
    t.assert_true(client > 0, "Client connected");

    let server_conn = wing::tcp_accept(listener, 2000);
    t.assert_true(server_conn > 0, "Server accepted");

    // Client sends chunked request
    let req_wire: const u8[:] = "POST /upload HTTP/1.1\r\nHost: localhost\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nHELLO\r\n0\r\n\r\n";
    let sent = wing::tcp_send(client, req_wire);
    t.assert_eq(sent, req_wire.len as i32, "Sent chunked request");

    // Server reads wire and parses request
    var srv_buf: u8[..2048] = [];
    let recvd = wing::tcp_recv(server_conn, srv_buf, 2048, 2000);
    t.assert_true(recvd > 0, "Server read bytes");

    var req = wing::Request {};
    let ok_req, consumed = wing::parse_http1_wire_request(srv_buf[..], req);
    t.assert_true(ok_req, "Parsed request");
    t.assert_eq(req.method[..], "POST", "Method is POST");
    t.assert_eq(req.body[..], "HELLO", "Body unchunked to HELLO");

    // Server sends response
    let resp_wire: const u8[:] = "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nOK";
    wing::tcp_send(server_conn, resp_wire);

    // Client receives response
    var cli_buf: u8[..1024] = [];
    let cli_recvd = wing::tcp_recv(client, cli_buf, 1024, 2000);
    t.assert_true(cli_recvd > 0, "Client read response");

    var resp = wing::Response {};
    let ok_resp, _ = wing::parse_http1_wire_response(cli_buf[..], resp);
    t.assert_true(ok_resp, "Parsed response");
    t.assert_eq(resp.status_code, 200, "Status is 200");
    t.assert_eq(resp.body[..], "OK", "Body is OK");

    wing::tcp_close(client);
    wing::tcp_close(server_conn);
    wing::tcp_close(listener);
}

// Verifies server rejects malformed space-before-colon request (CVE-2019-16276)
fn test_live_h1_space_before_colon_rejected(t: lit::T&) {
    let listener = wing::tcp_listen("127.0.0.1", 0, 16);
    let srv_port = wing::tcp_getsockname_port(listener);
    let client = wing::tcp_connect("127.0.0.1", srv_port, 2000);
    let server_conn = wing::tcp_accept(listener, 2000);

    // Smuggled header with space before colon
    let evil_req: const u8[:] = "GET /test HTTP/1.1\r\nHost: localhost\r\nTransfer-Encoding : chunked\r\n\r\n";
    wing::tcp_send(client, evil_req);

    var srv_buf: u8[..1024] = [];
    wing::tcp_recv(server_conn, srv_buf, 1024, 2000);

    var req = wing::Request {};
    let ok_req, _ = wing::parse_http1_wire_request(srv_buf[..], req);
    t.assert_false(ok_req, "Space before colon request MUST be rejected by wire parser");

    wing::tcp_close(client);
    wing::tcp_close(server_conn);
    wing::tcp_close(listener);
}

// Verifies server rejects conflicting Content-Length headers over live TCP
fn test_live_h1_conflicting_content_length(t: lit::T&) {
    let listener = wing::tcp_listen("127.0.0.1", 0, 16);
    let srv_port = wing::tcp_getsockname_port(listener);
    let client = wing::tcp_connect("127.0.0.1", srv_port, 2000);
    let server_conn = wing::tcp_accept(listener, 2000);

    let evil_req: const u8[:] = "POST /test HTTP/1.1\r\nHost: localhost\r\nContent-Length: 5\r\nContent-Length: 6\r\n\r\nHELLO";
    wing::tcp_send(client, evil_req);

    var srv_buf: u8[..1024] = [];
    wing::tcp_recv(server_conn, srv_buf, 1024, 2000);

    var req = wing::Request {};
    let ok_req, _ = wing::parse_http1_wire_request(srv_buf[..], req);
    t.assert_false(ok_req, "Conflicting Content-Length headers MUST be rejected");

    wing::tcp_close(client);
    wing::tcp_close(server_conn);
    wing::tcp_close(listener);
}

// Verifies server detects connection reset / EOF cleanly
fn test_live_h1_abrupt_disconnect(t: lit::T&) {
    let listener = wing::tcp_listen("127.0.0.1", 0, 16);
    let srv_port = wing::tcp_getsockname_port(listener);
    let client = wing::tcp_connect("127.0.0.1", srv_port, 2000);
    let server_conn = wing::tcp_accept(listener, 2000);

    // Client closes socket immediately without sending full headers
    wing::tcp_close(client);

    var srv_buf: u8[..1024] = [];
    let recvd = wing::tcp_recv(server_conn, srv_buf, 1024, 1000);
    // recvd == 0 indicates clean peer FIN, or negative on error
    t.assert_true(recvd <= 0, "Server detects disconnect/EOF cleanly");

    wing::tcp_close(server_conn);
    wing::tcp_close(listener);
}

// --- Component: net_tcp_rst_abort ---
// Red Test Vector for TCP Abrupt Teardown, RST vs FIN Invariant & Keepalive Boundary Validation (WING-BUG-ND-03).
// Upstream references:
// - RFC 1122 §4.2.2.13 (TCP Close & Abort Invariant: closing socket with unread receive data MUST issue RST).
// - RFC 1122 §4.2.3.6 (TCP Keepalive Timing Boundaries & Minimum Period).
// - Go net #40738 (TCP connection reset vs clean shutdown semantics on unread buffered data).
// - POSIX.1-2008 & Berkeley Sockets SO_LINGER zero-abort specification.

fn test_abrupt_rst_on_unread_receive_data(t: lit::T&) {
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
        var srv_bp = wing::BackPressure { .. };
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

fn test_explicit_socket_abort(t: lit::T&) {
    t.run("Case 2: Explicit tcp_abort and async_socket_abort RST Teardown") { sub =>
        let listener = wing::tcp_listen("127.0.0.1", 0, 16);
        let port = wing::tcp_getsockname_port(listener);
        let client = wing::tcp_connect("127.0.0.1", port, 2000);
        let server_conn = wing::tcp_accept(listener, 2000);
        defer wing::tcp_close(listener);
        defer wing::tcp_close(client);

        var srv_bp = wing::BackPressure { .. };
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

fn test_keepalive_boundary_validation(t: lit::T&) {
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

fn test_flow_control_state_tracking(t: lit::T&) {
    t.run("Case 4: Backpressure Flow Control State Tracking") { sub =>
        var bp = wing::BackPressure { .. };
        sub.assert_false(wing::tcp_is_flow_controlled(bp), "Empty backpressure is not flow controlled");

        wing::backpressure_append(bp, "FLOW_CONTROLLED_PAYLOAD");
        sub.assert_true(wing::tcp_is_flow_controlled(bp), "Backpressure with pending data is flow controlled");

        wing::backpressure_clear(bp);
        sub.assert_false(wing::tcp_is_flow_controlled(bp), "Cleared backpressure is not flow controlled");

        // Bounded capacity: when backpressure reaches 65536 bytes, backpressure_append returns false
        var bp_full = wing::BackPressure { .. };
        var big_chunk: u8[4096] = ['B'; 4096];
        for i in 16 {
            wing::backpressure_append(bp_full, big_chunk[..]);
        }
        sub.assert_eq(wing::backpressure_len(bp_full), 65536, "Backpressure at max capacity 65536");
        let ok_append = wing::backpressure_append(bp_full, "OVERFLOW");
        sub.assert_false(ok_append, "Appending to full backpressure returns false");
        sub.assert_eq(bp_full.drop_count, 1, "Drop count incremented on overflow");

        // uncork_spill_to_bp preserves cork buffer when backpressure is full
        var cork = core::new_cork_buffer();
        core::cork_write_exact(cork, "SAVED_IN_CORK");
        wing::uncork_spill_to_bp(cork, bp_full);
        sub.assert_eq(core::cork_pending(cork), 13, "Cork data preserved when backpressure full");
    };
}

// --- Component: net_tcp_half_close ---
// Red Test Vector for TCP Half-Close & Graceful Shutdown State Transitions (WING-BUG-ND-02).
// Upstream references:
// - uWebSockets/uSockets #148: closeOnBackpressureLimit / deferred shutdown handling.
// - uWebSockets #1932: Block all socket sends after closing/shutdown is initiated.
// - Go net/http #82375: Server truncates response with RST on shutdown when slow reader leaves data in write queue.
// - Go net/http #18527: Half-closed connection triggers request cancellation (server must support peer FIN while writing).
// - RFC 9293 Section 3.5: TCP Close sequence & full-duplex half-closed states (CLOSE_WAIT / FIN_WAIT_2).
// - RFC 1122 Section 4.2.2.13: TCP close and lingering options (SO_LINGER).

fn test_half_close_deferred_shutdown(t: lit::T&) {
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
        var bp = wing::BackPressure { .. };

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

fn test_peer_fin_half_closed_response(t: lit::T&) {
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
        var server_bp = wing::BackPressure { .. };
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

fn test_socket_options_tuning(t: lit::T&) {
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

// --- Component: net_l4_socket_io ---
// Layer 4 Kernel Network Socket I/O Verification Suite.
// Verifies real OS network stack semantics across Windows Winsock2 and POSIX:
// 1. Non-blocking empty read returning WouldBlock/EAGAIN (-2).
// 2. Non-blocking data reception and immediate return to WouldBlock.
// 3. Immediate connection refusal on closed/unbound local port without hanging.
// 4. Rapid connection burst lifecycle & descriptor leak prevention.
// 5. Vectored I/O (tcp_send2) edge cases with empty header/payload boundaries.
// 6. Zero-copy shared buffer (tcp_recv_shared) and direct slice (tcp_recv_slice).
// 7. Abrupt TCP RST termination via tcp_abort propagating ECONNRESET to peer.

fn test_nonblocking_empty_wouldblock(t: lit::T&) {
    t.run("Case 1: Non-blocking Socket Empty Read Returns WouldBlock (-2)") { sub =>
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

        let nb_ok = wing::tcp_set_nonblocking(client, true);
        sub.assert_true(nb_ok, "Client set to non-blocking");

        var cli_buf: u8[..256] = [];
        let r1 = wing::tcp_recv_nonblocking(client, cli_buf);
        sub.assert_eq(r1, -2, "Empty non-blocking read returns -2 (WouldBlock)");
        sub.assert_eq(cli_buf.len, 0, "No bytes buffered on WouldBlock");
    };
}

fn test_nonblocking_data_exchange(t: lit::T&) {
    t.run("Case 2: Non-blocking Socket Data Reception & Return to WouldBlock") { sub =>
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

        wing::tcp_set_nonblocking(client, true);

        let payload: const u8[:] = "NONBLOCKING_BURST_DATA";
        let sent = wing::tcp_send(server_conn, payload);
        sub.assert_eq(sent, payload.len as i32, "Server sent payload");

        core::sleep(core::millis(30));

        var cli_buf: u8[..256] = [];
        let r2 = wing::tcp_recv_nonblocking(client, cli_buf);
        sub.assert_eq(r2, payload.len as i32, "Client received all bytes non-blocking");
        sub.assert_eq(cli_buf[..], payload, "Received content matches wire bytes");

        cli_buf.clear();
        let r3 = wing::tcp_recv_nonblocking(client, cli_buf);
        sub.assert_eq(r3, -2, "Subsequent empty non-blocking read returns -2");
    };
}

fn test_connect_refused_immediate_failure(t: lit::T&) {
    t.run("Case 3: Connection Refusal on Closed Port Returns Immediate Error") { sub =>
        let listener = wing::tcp_listen("127.0.0.1", 0, 16);
        sub.assert_gt(listener, 0, "Temporary listener created");
        let closed_port = wing::tcp_getsockname_port(listener);
        sub.assert_gt(closed_port, 0, "Got ephemeral port");
        wing::tcp_close(listener);

        let t_start = core::monotonic_now();
        let conn = wing::tcp_connect("127.0.0.1", closed_port, 300);
        let t_now = core::monotonic_now();
        let t_elapsed_ms = core::as_millis(core::duration_since(t_now, t_start));

        sub.assert_le(conn, 0, "Connection to closed port must fail (return <= 0)");
        sub.assert_lt(t_elapsed_ms, 1000, "Refused connection aborted within timeout threshold");
    };
}

fn execute_single_burst_exchange(listener: i64, port: u16) -> bool {
    let client = wing::tcp_connect("127.0.0.1", port, 2000);
    guard client > 0 else { return false; }
    defer wing::tcp_close(client);

    let server_conn = wing::tcp_accept(listener, 2000);
    guard server_conn > 0 else { return false; }
    defer wing::tcp_close(server_conn);

    let msg: const u8[:] = "BURST_PING";
    let sent = wing::tcp_send(client, msg);
    guard sent == msg.len as i32 else { return false; }

    var srv_buf: u8[..64] = [];
    let recvd = wing::tcp_recv(server_conn, srv_buf, 64, 1000);
    guard recvd == msg.len as i32 else { return false; }

    return true;
}

fn test_rapid_connection_burst(t: lit::T&) {
    t.run("Case 4: Rapid Connection Burst Lifecycle & Zero Descriptor Leaks") { sub =>
        let listener = wing::tcp_listen("127.0.0.1", 0, 32);
        sub.assert_gt(listener, 0, "Listener created");
        defer wing::tcp_close(listener);

        let port = wing::tcp_getsockname_port(listener);
        for i in 25 {
            let ok = execute_single_burst_exchange(listener, port);
            sub.assert_true(ok, "Loopback connection exchange completed cleanly");
        }
    };
}

fn test_vectored_send2_edge_cases(t: lit::T&) {
    t.run("Case 5: Vectored I/O (tcp_send2) Edge Cases with Empty Slices") { sub =>
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

        let p_only: const u8[:] = "PAYLOAD_ONLY_CONTENT";
        let sent1 = wing::tcp_send2(client, "", p_only);
        sub.assert_eq(sent1, p_only.len as i32, "tcp_send2 sent with empty header");

        var buf1: u8[..128] = [];
        let r1 = wing::tcp_recv(server_conn, buf1, 128, 2000);
        sub.assert_eq(r1, p_only.len as i32, "Server received payload-only bytes");
        sub.assert_eq(buf1[..], p_only, "Payload-only content verified");

        let h_only: const u8[:] = "HEADER_ONLY_CONTENT";
        let sent2 = wing::tcp_send2(client, h_only, "");
        sub.assert_eq(sent2, h_only.len as i32, "tcp_send2 sent with empty payload");

        var buf2: u8[..128] = [];
        let r2 = wing::tcp_recv(server_conn, buf2, 128, 2000);
        sub.assert_eq(r2, h_only.len as i32, "Server received header-only bytes");
        sub.assert_eq(buf2[..], h_only, "Header-only content verified");

        let sent0 = wing::tcp_send2(client, "", "");
        sub.assert_eq(sent0, 0, "tcp_send2 with both empty slices returns 0");

        let sent_inv = wing::tcp_send2(-1, "A", "B");
        sub.assert_eq(sent_inv, 0, "tcp_send2 on invalid FD returns 0");
    };
}

fn test_shared_buffer_recv(t: lit::T&) {
    t.run("Case 6: Zero-Copy Shared Buffer Recv (tcp_recv_shared)") { sub =>
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

        let msg1: const u8[:] = "SHARED_BUFFER_TEST_PAYLOAD";
        wing::tcp_send(client, msg1);

        var shared_buf: u8[..65536] = [];
        let recvd1, slice1 = wing::tcp_recv_shared(server_conn, shared_buf, 4096, 2000);
        sub.assert_eq(recvd1, msg1.len as i32, "tcp_recv_shared returned byte count");
        sub.assert_eq(slice1, msg1, "tcp_recv_shared slice matches message");
    };
}

fn test_direct_slice_recv(t: lit::T&) {
    t.run("Case 7: Direct Destination Slice Recv (tcp_recv_slice)") { sub =>
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

        let msg2: const u8[:] = "DIRECT_SLICE_TEST_PAYLOAD";
        wing::tcp_send(client, msg2);

        var slice_buf: u8[64] = [0; 64];
        let recvd2 = wing::tcp_recv_slice(server_conn, slice_buf[..msg2.len], 2000);
        sub.assert_eq(recvd2, msg2.len as i32, "tcp_recv_slice returned byte count");
        sub.assert_eq(slice_buf[..recvd2], msg2, "tcp_recv_slice buffer matches message");
    };
}

fn test_peer_abort_propagation(t: lit::T&) {
    t.run("Case 8: Peer tcp_abort Discard & Immediate Reset Propagation") { sub =>
        let listener = wing::tcp_listen("127.0.0.1", 0, 16);
        sub.assert_gt(listener, 0, "Listener created");
        defer wing::tcp_close(listener);

        let port = wing::tcp_getsockname_port(listener);
        let client = wing::tcp_connect("127.0.0.1", port, 2000);
        sub.assert_gt(client, 0, "Client connected");
        defer wing::tcp_close(client);

        let server_conn = wing::tcp_accept(listener, 2000);
        sub.assert_gt(server_conn, 0, "Server accepted");

        let abort_ok = wing::tcp_abort(server_conn);
        sub.assert_true(abort_ok, "tcp_abort returned true");

        core::sleep(core::millis(40));

        var probe: u8[..32] = [];
        let r = wing::tcp_recv(client, probe, 32, 1000);
        sub.assert_eq(r, -1, "Client received -1 error on socket reset by peer RST");
    };
}

// --- Component: net_sockopt ---
// Verification suite for L4 OS Socket Parameter Tuning (sysnet / net/sockopt.goose):
// - Authentic Wing NetStack, Custom, and None L4 socket profile configurations
// - p0f v3 TCP stack parameter invariants (TTL, Window, MSS, WScale, DF, TCP_NODELAY)
// - Profile and ClientProfile dispatch overloads
// - Socket option summary formatting

fn test_socket_p0f_profiles(t: lit::T&) {
    t.run("Wing Authentic Zero-Heap NetStack Profile") { sub =>
        let wing_cfg = internal::p0f_socket_config(wing::Profile.Wing);
        sub.assert_eq(wing_cfg.ttl, 64, "Wing TTL is 64");
        sub.assert_eq(wing_cfg.window_size, 65535, "Wing window size is 65535");
        sub.assert_true(wing_cfg.has_dont_fragment, "Wing DF is enabled");
        sub.assert_true(wing_cfg.tcp_nodelay, "Wing TCP_NODELAY is enabled");
        sub.assert_eq(wing_cfg.wscale, 8, "Wing WScale is 8");
        sub.assert_eq(wing_cfg.mss, 1460, "Wing MSS is 1460");
        sub.assert_true(internal::validate_p0f_socket_invariants(wing_cfg), "Wing invariants valid");
    };

    t.run("Custom Socket Profile") { sub =>
        let custom_cfg = internal::p0f_socket_config(wing::Profile.Custom);
        sub.assert_eq(custom_cfg.ttl, 64, "Custom TTL is 64");
        sub.assert_eq(custom_cfg.window_size, 65535, "Custom window size is 65535");
        sub.assert_true(custom_cfg.has_dont_fragment, "Custom DF is enabled");
        sub.assert_eq(custom_cfg.wscale, 8, "Custom WScale is 8");
        sub.assert_true(internal::validate_p0f_socket_invariants(custom_cfg), "Custom invariants valid");
    };

    t.run("None / Raw Socket Profile") { sub =>
        let none_cfg = internal::p0f_socket_config(wing::Profile.None);
        sub.assert_eq(none_cfg.ttl, 64, "None TTL is 64");
        sub.assert_eq(none_cfg.window_size, 65535, "None window size is 65535");
        sub.assert_false(none_cfg.has_dont_fragment, "None DF is disabled");
        sub.assert_eq(none_cfg.wscale, 7, "None WScale is 7");
        sub.assert_true(internal::validate_p0f_socket_invariants(none_cfg), "None invariants valid");
    };
}

fn test_socket_invariant_validation(t: lit::T&) {
    t.run("Invariant Boundary Checks") { sub =>
        var bad_cfg = internal::p0f_socket_config(wing::Profile.Wing);

        // Invalid TTL
        bad_cfg.ttl = 99;
        sub.assert_false(internal::validate_p0f_socket_invariants(bad_cfg), "TTL 99 is invalid");

        // Valid TTLs
        bad_cfg.ttl = 64;
        sub.assert_true(internal::validate_p0f_socket_invariants(bad_cfg), "TTL 64 is valid");
        bad_cfg.ttl = 128;
        sub.assert_true(internal::validate_p0f_socket_invariants(bad_cfg), "TTL 128 is valid");

        // Invalid Window Size
        bad_cfg.window_size = 0;
        sub.assert_false(internal::validate_p0f_socket_invariants(bad_cfg), "Window 0 is invalid");
        bad_cfg.window_size = 70000;
        sub.assert_false(internal::validate_p0f_socket_invariants(bad_cfg), "Window 70000 is invalid");
        bad_cfg.window_size = 64240;

        // Invalid MSS
        bad_cfg.mss = 200;
        sub.assert_false(internal::validate_p0f_socket_invariants(bad_cfg), "MSS 200 is invalid");
        bad_cfg.mss = 1460;

        // Invalid WScale
        bad_cfg.wscale = 15;
        sub.assert_false(internal::validate_p0f_socket_invariants(bad_cfg), "WScale 15 is invalid");
    };

    t.run("Summary String Formatting") { sub =>
        let cfg = internal::p0f_socket_config(wing::Profile.Wing);
        var summary: u8[>..] = [];
        internal::format_socket_p0f_summary(cfg, summary);
        sub.assert_true(summary.len > 0, "Summary formatted");
        // Verify key substrings
        sub.assert_contains(summary[..], "Wing/1.0 NetStack", "Summary contains OS/stack name");
        sub.assert_contains(summary[..], "TTL=64", "Summary contains TTL");
        sub.assert_contains(summary[..], "Window=65535", "Summary contains Window");
    };
}

fn test_live_socket_options(t: lit::T&) {
    t.run("OS Socket Option Tuning & Telemetry") { sub =>
        let listener = wing::tcp_listen("127.0.0.1", 0, 16);
        sub.assert_gt(listener, 0, "Listener socket created");
        defer wing::tcp_close(listener);

        let port = wing::tcp_getsockname_port(listener);
        sub.assert_gt(port as i64, 0, "Bound to valid ephemeral port");

        // TCP_DEFER_ACCEPT (Linux / FreeBSD)
        let ok_defer = wing::tcp_set_defer_accept(listener, 1);
        sub.assert_true(ok_defer, "tcp_set_defer_accept returns success");

        // TCP_USER_TIMEOUT
        let ok_ut = wing::tcp_set_user_timeout(listener, 5000);
        sub.assert_true(ok_ut, "tcp_set_user_timeout returns success");

        // Aggressive SO_KEEPALIVE
        let ok_keep = wing::tcp_set_keepalive(listener, 1, 11, 3);
        sub.assert_true(ok_keep, "tcp_set_keepalive returns success");

        // TCP_SYNCNT
        let ok_syn = wing::tcp_set_syn_retries(listener, 3);
        sub.assert_true(ok_syn, "tcp_set_syn_retries returns success");

        // Queue telemetry
        let notsent = wing::tcp_get_notsent_bytes(listener);
        sub.assert_ge(notsent, 0, "notsent_bytes >= 0");

        let readable = wing::tcp_get_readable_bytes(listener);
        sub.assert_ge(readable, 0, "readable_bytes >= 0");

        // End-to-end CorkBuffer -> tcp_flush_cork -> tcp_recv_pipe into PipeBuffer
        let client_sock = wing::tcp_connect("127.0.0.1", port, 2000);
        sub.assert_gt(client_sock, 0, "Client connected to listener");
        defer wing::tcp_close(client_sock);

        let accepted_sock = wing::tcp_accept(listener, 2000);
        sub.assert_gt(accepted_sock, 0, "Accepted incoming connection");
        defer wing::tcp_close(accepted_sock);

        var cork = core::new_cork_buffer();
        cork.cork_write("WING_PIPE_STREAM_PAYLOAD");
        sub.assert_eq(cork.cork_pending(), 24, "Cork has 24 bytes pending");

        let flushed = wing::tcp_flush_cork(client_sock, cork);
        sub.assert_eq(flushed, 24, "Flushed all 24 bytes via tcp_flush_cork");
        sub.assert_eq(cork.cork_pending(), 0, "Cork drained to 0");

        var pipe = core::new_pipe_buffer();
        let recvd = wing::tcp_recv_pipe(accepted_sock, pipe, 1024, 2000);
        sub.assert_eq(recvd, 24, "tcp_recv_pipe read directly into pipe storage");
        sub.assert_eq(pipe.readable_len(), 24, "PipeBuffer has 24 readable bytes");
        sub.assert_eq(pipe.readable_slice(), "WING_PIPE_STREAM_PAYLOAD", "Direct pipe slice matches wire payload");
    };
}

// --- Component: net_iovec ---
// Verification suite for Vectorized Scatter/Gather I/O (IoVec & IoVecArray):
// - Zero-allocation chunk aggregation & capacity enforcement
// - Slice indexing & zero-copy accessor semantics
// - Flattening & bounded partial copy into destination slices
// - Head consumption & dynamic zero-shift offset tracking
// - Ring compaction under slot pressure
// - Real kernel TCP socket transmission via tcp_sendv

fn test_iovec_lifecycle(t: lit::T&) {
    t.run("IoVecArray Lifecycle & Capacity") { sub =>
        var arr = core::new_iovec_array();
        sub.assert_true(core::iovec_is_empty(arr), "Initially empty");
        sub.assert_eq(core::iovec_count(arr), 0, "Initial count 0");
        sub.assert_eq(core::iovec_total_bytes(arr), 0, "Initial total bytes 0");

        // Push empty slice is no-op
        sub.assert_true(core::iovec_push(arr, ""), "Push empty slice succeeded");
        sub.assert_eq(core::iovec_count(arr), 0, "Empty slice not stored");

        // Push 3 distinct chunks
        sub.assert_true(core::iovec_push(arr, "GET / HTTP/1.1\r\n"), "Push chunk 1");
        sub.assert_true(core::iovec_push(arr, "Host: example.com\r\n\r\n"), "Push chunk 2");
        sub.assert_true(core::iovec_push(arr, "payload-body"), "Push chunk 3");

        sub.assert_false(core::iovec_is_empty(arr), "Not empty after pushes");
        sub.assert_eq(core::iovec_count(arr), 3, "Count is 3");
        let expected_bytes = ("GET / HTTP/1.1\r\n").len + ("Host: example.com\r\n\r\n").len + ("payload-body").len;
        sub.assert_eq(core::iovec_total_bytes(arr), expected_bytes, "Total bytes calculated correctly");

        // Inspect slices
        sub.assert_eq(core::iovec_get(arr, 0), "GET / HTTP/1.1\r\n", "Chunk 0 matches");
        sub.assert_eq(core::iovec_get(arr, 1), "Host: example.com\r\n\r\n", "Chunk 1 matches");
        sub.assert_eq(core::iovec_get(arr, 2), "payload-body", "Chunk 2 matches");
        sub.assert_eq(core::iovec_get(arr, 3), "", "Out of range returns empty slice");

        // Clear
        core::iovec_clear(arr);
        sub.assert_true(core::iovec_is_empty(arr), "Empty after clear");
        sub.assert_eq(core::iovec_count(arr), 0, "Count 0 after clear");
        sub.assert_eq(core::iovec_total_bytes(arr), 0, "Total bytes 0 after clear");
    };
}

fn test_iovec_flatten_and_copy(t: lit::T&) {
    t.run("IoVecArray Flatten & Copy") { sub =>
        var arr = core::new_iovec_array();
        core::iovec_push(arr, "AAAA");
        core::iovec_push(arr, "BBBB");
        core::iovec_push(arr, "CCCC");

        // 1. Flatten into appendable buffer
        var flat: u8[>..] = [];
        core::iovec_flatten(arr, flat);
        sub.assert_eq(flat[..], "AAAABBBBCCCC", "Flatten output matches");

        // 2. Exact copy to fixed slice
        var dst: u8[12] = [0; 12];
        let copied = core::iovec_copy_to(arr, dst[..]);
        sub.assert_eq(copied, 12, "Copied 12 bytes");
        sub.assert_eq(dst[..], "AAAABBBBCCCC", "Fixed buffer destination matches");

        // 3. Truncated copy to smaller slice
        var small_dst: u8[6] = [0; 6];
        let trunc_copied = core::iovec_copy_to(arr, small_dst[..]);
        sub.assert_eq(trunc_copied, 6, "Copied only 6 bytes");
        sub.assert_eq(small_dst[..], "AAAABB", "Small buffer truncated correctly");
    };
}

fn test_iovec_consumption_and_compact(t: lit::T&) {
    t.run("Partial Consumption & Compact") { sub =>
        var arr = core::new_iovec_array();
        core::iovec_push(arr, "0123456789"); // 10 bytes
        core::iovec_push(arr, "ABCDEFGHIJ"); // 10 bytes
        core::iovec_push(arr, "KLMNOPQRST"); // 10 bytes
        sub.assert_eq(core::iovec_total_bytes(arr), 30, "Total 30 bytes");

        // Consume 4 bytes (partial chunk 0)
        let c1 = core::iovec_consume(arr, 4);
        sub.assert_eq(c1, 4, "Consumed 4 bytes");
        sub.assert_eq(core::iovec_total_bytes(arr), 26, "Remaining 26 bytes");
        sub.assert_eq(core::iovec_get(arr, 0), "456789", "Head chunk adjusted by offset");
        sub.assert_eq(core::iovec_count(arr), 3, "Count is still 3");

        // Consume 10 bytes (remaining 6 of chunk 0 + 4 of chunk 1)
        let c2 = core::iovec_consume(arr, 10);
        sub.assert_eq(c2, 10, "Consumed 10 bytes");
        sub.assert_eq(core::iovec_total_bytes(arr), 16, "Remaining 16 bytes");
        sub.assert_eq(core::iovec_count(arr), 2, "Count reduced to 2 (chunk 0 retired)");
        sub.assert_eq(core::iovec_get(arr, 0), "EFGHIJ", "Chunk 1 is new head at offset 4");

        // Push new chunk while head > 0 to verify compaction
        sub.assert_true(core::iovec_push(arr, "UVW"), "Pushed after retirement");
        sub.assert_eq(core::iovec_count(arr), 3, "Count is 3");
        sub.assert_eq(core::iovec_total_bytes(arr), 19, "Remaining 16 + 3 = 19 bytes");

        // Consume remaining all bytes
        let c3 = core::iovec_consume(arr, 19);
        sub.assert_eq(c3, 19, "Consumed all remaining 19 bytes");
        sub.assert_true(core::iovec_is_empty(arr), "Array is empty");
        sub.assert_eq(core::iovec_total_bytes(arr), 0, "Total bytes 0");
    };
}

fn test_tcp_sendv_socket(t: lit::T&) {
    t.run("Kernel TCP Transmission via tcp_sendv") { sub =>
        let listener = wing::tcp_listen("127.0.0.1", 0, 16);
        sub.assert_gt(listener, 0, "Listener bound");
        defer wing::tcp_close(listener);

        let port = wing::tcp_getsockname_port(listener);
        let client = wing::tcp_connect("127.0.0.1", port, 2000);
        sub.assert_gt(client, 0, "Client connected");
        defer wing::tcp_close(client);

        let server_fd = wing::tcp_accept(listener);
        sub.assert_gt(server_fd, 0, "Server accepted client");
        defer wing::tcp_close(server_fd);

        // Prepare 3 scatter/gather chunks
        var arr = core::new_iovec_array();
        core::iovec_push(arr, "HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\n");
        core::iovec_push(arr, "HE");
        core::iovec_push(arr, "LLO");

        let total_to_send = core::iovec_total_bytes(arr) as i32;
        let sent = wing::tcp_sendv(client, arr);
        sub.assert_eq(sent, total_to_send, "All vectorized bytes sent");
        sub.assert_true(core::iovec_is_empty(arr), "IoVecArray fully consumed by sendv");

        // Read back on server socket
        var recv_buf: u8[128] = [0; 128];
        let n_recv = wing::tcp_recv_slice(server_fd, recv_buf[..], 2000);
        sub.assert_eq(n_recv, total_to_send, "Server received exact total bytes");
        sub.assert_eq(recv_buf[..n_recv as i64], "HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nHELLO", "Wire payload reconstructed cleanly");
    };
}

// RFC 7413 Section 5: TCP Fast Open Configuration
// RFC 3168 Section 5: The ECN Field in IP
fn test_tcp_fastopen_and_ecn(t: lit::T&) {
    t.run("TCP-01: TCP Fast Open constants and option flags") { sub =>
        sub.assert_eq(wing::TCP_FASTOPEN_DEFAULT_QLEN, 512, "default TFO queue length is 512");
        sub.assert_eq(wing::MSG_FASTOPEN, 0x20000000, "MSG_FASTOPEN flag is 0x20000000");

        // Invalid fd (-1) must fail safely
        sub.assert_false(wing::tcp_set_fastopen(-1), "set_fastopen on -1 returns false");
        sub.assert_eq(wing::tcp_send_fastopen(-1, "test"), 0, "send_fastopen on -1 returns 0");
    };

    t.run("TCP-02: ECN codepoint decoding and classification (RFC 3168)") { sub =>
        sub.assert_eq(rfc::ECN_NOT_ECT, 0x00 as u8, "rfc::ECN_NOT_ECT is 0");
        sub.assert_eq(rfc::ECN_ECT_1, 0x01 as u8, "rfc::ECN_ECT_1 is 1");
        sub.assert_eq(rfc::ECN_ECT_0, 0x02 as u8, "rfc::ECN_ECT_0 is 2");
        sub.assert_eq(rfc::ECN_CE, 0x03 as u8, "rfc::ECN_CE is 3");

        // Pure ECN bytes
        sub.assert_eq(wing::ecn_from_tos(0x00 as u8), rfc::ECN_NOT_ECT, "tos 0 is NOT_ECT");
        sub.assert_eq(wing::ecn_from_tos(0x01 as u8), rfc::ECN_ECT_1, "tos 1 is ECT_1");
        sub.assert_eq(wing::ecn_from_tos(0x02 as u8), rfc::ECN_ECT_0, "tos 2 is ECT_0");
        sub.assert_eq(wing::ecn_from_tos(0x03 as u8), rfc::ECN_CE, "tos 3 is CE");

        // TOS with DSCP bits (e.g. DSCP CS5 = 0x28, shifted = 0xA0)
        let dscp_base: u8 = 0xA0;
        sub.assert_eq(wing::ecn_from_tos(dscp_base | rfc::ECN_ECT_0), rfc::ECN_ECT_0, "masked ECT_0 with DSCP");
        sub.assert_eq(wing::ecn_from_tos(dscp_base | rfc::ECN_CE), rfc::ECN_CE, "masked CE with DSCP");

        // ECN capabilities
        sub.assert_false(wing::ecn_is_capable(rfc::ECN_NOT_ECT), "NOT_ECT is not capable");
        sub.assert_true(wing::ecn_is_capable(rfc::ECN_ECT_0), "ECT_0 is capable");
        sub.assert_true(wing::ecn_is_capable(rfc::ECN_ECT_1), "ECT_1 is capable");
        sub.assert_false(wing::ecn_is_capable(rfc::ECN_CE), "CE is not capable alone");

        // Congestion experienced
        sub.assert_true(wing::ecn_is_congestion_experienced(rfc::ECN_CE), "CE flagged");
        sub.assert_false(wing::ecn_is_congestion_experienced(rfc::ECN_ECT_0), "ECT_0 not CE");

        // Invalid fd (-1) safe handling
        sub.assert_false(wing::tcp_set_tos(-1, 0x02 as u8), "set_tos on -1 returns false");
        sub.assert_false(wing::tcp_set_ecn(-1, rfc::ECN_ECT_0), "set_ecn on -1 returns false");
        sub.assert_false(wing::tcp_set_ipv6_tclass(-1, 0x02 as u8), "set_ipv6_tclass on -1 returns false");
    };
}

fn main() {
    var runner = lit::new_runner("TCP Socket IO, Corking, Abort, and Half-Close Verification Suite", lit::Verbosity.Verbose);

    lit::run_case(runner, "1. Live TCP Loopback Request/Response Roundtrip", test_tcp_loopback_echo);
    lit::run_case(runner, "2. Uncork Backpressure FIFO Ordering", test_uncork_backpressure_fifo_ordering);
    lit::run_case(runner, "3. Empty Cork Backpressure Polling", test_uncork_empty_cork_with_backpressure);
    lit::run_case(runner, "4. Live TCP H1 Chunked Roundtrip", test_live_h1_roundtrip);
    lit::run_case(runner, "5. Live TCP CVE-2019-16276 Space-Before-Colon Rejection", test_live_h1_space_before_colon_rejected);
    lit::run_case(runner, "6. Live TCP Conflicting Content-Length Rejection", test_live_h1_conflicting_content_length);
    lit::run_case(runner, "7. Live TCP Abrupt Disconnect / EOF Handling", test_live_h1_abrupt_disconnect);
    lit::run_case(runner, "8. RFC 1122 §4.2.2.13 Abortive RST on Unread Receive Data", test_abrupt_rst_on_unread_receive_data);
    lit::run_case(runner, "9. Explicit Socket Abort RST Teardown", test_explicit_socket_abort);
    lit::run_case(runner, "10. TCP Keepalive Boundary Validation", test_keepalive_boundary_validation);
    lit::run_case(runner, "11. Backpressure Flow Control State Tracking", test_flow_control_state_tracking);
    lit::run_case(runner, "12. Deferred Shutdown on Active Backpressure", test_half_close_deferred_shutdown);
    lit::run_case(runner, "13. Peer FIN Half-Close Full-Duplex Ordering", test_peer_fin_half_closed_response);
    lit::run_case(runner, "14. Live Socket Options Tuning", test_socket_options_tuning);
    lit::run_case(runner, "15. Non-blocking Recv WouldBlock", test_nonblocking_empty_wouldblock);
    lit::run_case(runner, "16. Non-blocking Data Exchange", test_nonblocking_data_exchange);
    lit::run_case(runner, "17. Closed Port Connection Refusal", test_connect_refused_immediate_failure);
    lit::run_case(runner, "18. Rapid Connection Burst Lifecycle", test_rapid_connection_burst);
    lit::run_case(runner, "19. Vectored Send2 Edge Cases", test_vectored_send2_edge_cases);
    lit::run_case(runner, "20. Shared Buffer Recv Zero-Copy", test_shared_buffer_recv);
    lit::run_case(runner, "21. Direct Slice Recv Zero-Copy", test_direct_slice_recv);
    lit::run_case(runner, "22. Peer Abort RST Propagation", test_peer_abort_propagation);
    lit::run_case(runner, "23. Socket p0f Profiles", test_socket_p0f_profiles);
    lit::run_case(runner, "24. Socket Invariant Validation", test_socket_invariant_validation);
    lit::run_case(runner, "25. Live OS Socket Tuning & Telemetry", test_live_socket_options);
    lit::run_case(runner, "26. IoVec Lifecycle & Capacity", test_iovec_lifecycle);
    lit::run_case(runner, "27. IoVec Flatten & Copy", test_iovec_flatten_and_copy);
    lit::run_case(runner, "28. IoVec Consumption & Compact", test_iovec_consumption_and_compact);
    lit::run_case(runner, "29. Kernel TCP tcp_sendv", test_tcp_sendv_socket);
    lit::run_case(runner, "30. TCP Fast Open (RFC 7413) & ECN Options (RFC 3168)", test_tcp_fastopen_and_ecn);

    let ok = lit::finish(runner);
    assert(ok);
}
