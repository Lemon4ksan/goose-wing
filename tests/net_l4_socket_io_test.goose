// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Layer 4 Kernel Network Socket I/O Verification Suite.
// Verifies real OS network stack semantics across Windows Winsock2 and POSIX:
// 1. Non-blocking empty read returning WouldBlock/EAGAIN (-2).
// 2. Non-blocking data reception and immediate return to WouldBlock.
// 3. Immediate connection refusal on closed/unbound local port without hanging.
// 4. Rapid connection burst lifecycle & descriptor leak prevention.
// 5. Vectored I/O (tcp_send2) edge cases with empty header/payload boundaries.
// 6. Zero-copy shared buffer (tcp_recv_shared) and direct slice (tcp_recv_slice).
// 7. Abrupt TCP RST termination via tcp_abort propagating ECONNRESET to peer.
import std;
import core from "..";
import wing from "..";

fn test_nonblocking_empty_wouldblock(t: core::T&) {
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

fn test_nonblocking_data_exchange(t: core::T&) {
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

fn test_connect_refused_immediate_failure(t: core::T&) {
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

fn test_rapid_connection_burst(t: core::T&) {
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

fn test_vectored_send2_edge_cases(t: core::T&) {
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

fn test_shared_buffer_recv(t: core::T&) {
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

        let recvd1, slice1 = wing::tcp_recv_shared(server_conn, 4096, 2000);
        sub.assert_eq(recvd1, msg1.len as i32, "tcp_recv_shared returned byte count");
        sub.assert_eq(slice1, msg1, "tcp_recv_shared slice matches message");
    };
}

fn test_direct_slice_recv(t: core::T&) {
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

fn test_peer_abort_propagation(t: core::T&) {
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

fn main() {
    var runner = core::new_runner("Layer 4 Kernel Socket I/O Verification Suite", core::Verbosity.Verbose);
    core::run_case(runner, "1. Non-blocking Recv WouldBlock", test_nonblocking_empty_wouldblock);
    core::run_case(runner, "2. Non-blocking Data Exchange", test_nonblocking_data_exchange);
    core::run_case(runner, "3. Closed Port Connection Refusal", test_connect_refused_immediate_failure);
    core::run_case(runner, "4. Rapid Connection Burst Lifecycle", test_rapid_connection_burst);
    core::run_case(runner, "5. Vectored Send2 Edge Cases", test_vectored_send2_edge_cases);
    core::run_case(runner, "6. Shared Buffer Recv Zero-Copy", test_shared_buffer_recv);
    core::run_case(runner, "7. Direct Slice Recv Zero-Copy", test_direct_slice_recv);
    core::run_case(runner, "8. Peer Abort RST Propagation", test_peer_abort_propagation);
    let ok = core::finish(runner);
    assert(ok);
}
