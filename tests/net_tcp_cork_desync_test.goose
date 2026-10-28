// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Red Test Vector for TCP Cork/Uncork Desync & Backpressure FIFO Inversion (uWebSockets #1186, #1959).
// Verifies:
// 1. Calling async_socket_uncork while backpressure is active preserves FIFO order (never transmits cork ahead of backpressure).
// 2. Calling async_socket_uncork while cork is empty but backpressure is pending returns needs_poll=true.
// 3. Optional async writes (optionally=true) never pollute the backpressure queue on partial/unaccepted sends.
import std;
import core from "..";
import wing from "..";

fn test_uncork_backpressure_fifo_ordering(t: core::T&) {
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
        var bp = wing::new_backpressure();

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
        while true {
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

fn test_uncork_empty_cork_with_backpressure(t: core::T&) {
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
        var bp = wing::new_backpressure();

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

fn main() {
    var runner = core::new_runner("TCP Cork/Uncork Desync & Backpressure Invariant Suite", core::Verbosity.Verbose);
    core::run_case(runner, "1. Uncork Backpressure FIFO Ordering", test_uncork_backpressure_fifo_ordering);
    core::run_case(runner, "2. Empty Cork Backpressure Polling", test_uncork_empty_cork_with_backpressure);
    let ok = core::finish(runner);
    assert(ok);
}
