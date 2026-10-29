// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Verification suite for Vectorized Scatter/Gather I/O (IoVec & IoVecArray):
// - Zero-allocation chunk aggregation & capacity enforcement
// - Slice indexing & zero-copy accessor semantics
// - Flattening & bounded partial copy into destination slices
// - Head consumption & dynamic zero-shift offset tracking
// - Ring compaction under slot pressure
// - Real kernel TCP socket transmission via tcp_sendv
import std;
import core from "..";
import wing from "..";

fn test_iovec_lifecycle(t: core::T&) {
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

fn test_iovec_flatten_and_copy(t: core::T&) {
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

fn test_iovec_consumption_and_compact(t: core::T&) {
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

fn test_tcp_sendv_socket(t: core::T&) {
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

fn main() {
    var runner = core::new_runner("Vectorized Scatter/Gather I/O Suite", core::Verbosity.Verbose);
    core::run_case(runner, "1. IoVec Lifecycle & Capacity", test_iovec_lifecycle);
    core::run_case(runner, "2. IoVec Flatten & Copy", test_iovec_flatten_and_copy);
    core::run_case(runner, "3. IoVec Consumption & Compact", test_iovec_consumption_and_compact);
    core::run_case(runner, "4. Kernel TCP tcp_sendv", test_tcp_sendv_socket);
    let ok = core::finish(runner);
    assert(ok);
}
