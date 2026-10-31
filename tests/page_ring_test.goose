// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Verification Suite: Virtual Memory Page-Mirrored Ring Buffer
//
// RUN: goose build -o %t.exe %s
// RUN: %t.exe
import std;
import core from "..";
import lit from "github.com/Lemon4ksan/goose-lit@v0.1.0";

fn test_page_ring_lifecycle_and_wraparound(t: lit::T&) {
    t.run("PageRingBuffer Init, Cap and Boundaries") { sub =>
        var pr = core::PageRingBuffer { .. };
        let ok = core::page_ring_init(pr, 65536);
        sub.assert_true(ok);
        sub.assert_true(pr.is_open);
        sub.assert_eq(pr.capacity, 65536);
        sub.assert_eq(pr.count, 0);
        sub.assert_eq(core::page_ring_available(pr), 65536);
        sub.assert_true(core::page_ring_is_empty(pr));
        sub.assert_false(core::page_ring_is_full(pr));

        // Basic write and read
        let written, w_err = core::page_ring_write(pr, "hello world");
        sub.assert_eq(w_err, core::IoError.None);
        sub.assert_eq(written, 11);
        sub.assert_eq(pr.count, 11);
        sub.assert_eq(pr.head, 0);
        sub.assert_eq(pr.tail, 11);

        var buf: u8[32] = [0; 32];
        let read_n, r_err = core::page_ring_read(pr, buf[..11]);
        sub.assert_eq(r_err, core::IoError.None);
        sub.assert_eq(read_n, 11);
        sub.assert_eq(pr.count, 0);
        sub.assert_eq(pr.head, 11);
        sub.assert_eq(buf[..11], "hello world");

        core::page_ring_close(pr);
        sub.assert_false(pr.is_open);
    };

    t.run("Seamless Hardware Boundary Wraparound Without Split") { sub =>
        var pr = core::PageRingBuffer { .. };
        let ok = core::page_ring_init(pr, 65536);
        sub.assert_true(ok);

        // Advance tail to 5 bytes before the 64KB boundary:
        pr.tail = 65531;
        pr.head = 65531;
        pr.count = 0;

        // Write 15 bytes: bytes 0..4 go to [65531..65535], bytes 5..14 wrap to [0..9]
        // Thanks to virtual page mirroring, this is written in ONE single memcpy!
        let msg: const u8[:] = "0123456789ABCDE";
        let written, w_err = core::page_ring_write(pr, msg);
        sub.assert_eq(w_err, core::IoError.None);
        sub.assert_eq(written, 15);
        sub.assert_eq(pr.count, 15);
        sub.assert_eq(pr.tail, 10); // (65531 + 15) % 65536 = 10

        // Peek 15 bytes: should read across the boundary contiguously
        var peek_buf: u8[32] = [0; 32];
        let peek_n = core::page_ring_peek(pr, peek_buf[..15]);
        sub.assert_eq(peek_n, 15);
        sub.assert_eq(peek_buf[..15], msg);
        sub.assert_eq(pr.count, 15); // peek does not advance cursor

        // Read 15 bytes
        var read_buf: u8[32] = [0; 32];
        let read_n, r_err = core::page_ring_read(pr, read_buf[..15]);
        sub.assert_eq(r_err, core::IoError.None);
        sub.assert_eq(read_n, 15);
        sub.assert_eq(read_buf[..15], msg);
        sub.assert_eq(pr.count, 0);
        sub.assert_eq(pr.head, 10);

        core::page_ring_close(pr);
    };
}

fn test_page_ring_scanners_and_delimiters(t: lit::T&) {
    t.run("Delimiters Straddling 64KB Page Boundary") { sub =>
        var pr = core::PageRingBuffer { .. };
        let ok = core::page_ring_init(pr, 65536);
        sub.assert_true(ok);

        // Position tail so \r\n\r\n straddles the 64KB boundary:
        // tail = 65534 -> byte 0 is '\r' (at 65534), byte 1 is '\n' (at 65535),
        //                 byte 2 is '\r' (at 0), byte 3 is '\n' (at 1)
        pr.tail = 65534;
        pr.head = 65534;
        pr.count = 0;

        let payload: const u8[:] = "\r\n\r\nHello World";
        let written, w_err = core::page_ring_write(pr, payload);
        sub.assert_eq(w_err, core::IoError.None);
        sub.assert_eq(written, 15);
        sub.assert_eq(pr.count, 15);

        // Scan for CRLF: offset should be 0 (starts at pr.head)
        let crlf_idx = core::page_ring_find_crlf(pr);
        sub.assert_eq(crlf_idx, 0);

        // Scan for CRLFCRLF: offset should be 0
        let crlfcrlf_idx = core::page_ring_find_crlfcrlf(pr);
        sub.assert_eq(crlfcrlf_idx, 0);

        // Discard the 4 delimiter bytes:
        let dropped = core::page_ring_discard(pr, 4);
        sub.assert_eq(dropped, 4);
        sub.assert_eq(pr.count, 11);
        sub.assert_eq(pr.head, 2); // (65534 + 4) % 65536 = 2

        var body: u8[16] = [0; 16];
        let read_n, _ = core::page_ring_read(pr, body[..11]);
        sub.assert_eq(read_n, 11);
        sub.assert_eq(body[..11], "Hello World");
        sub.assert_eq(pr.count, 0);

        core::page_ring_close(pr);
    };

    t.run("Discard and Clear Operations") { sub =>
        var pr = core::PageRingBuffer { .. };
        let ok = core::page_ring_init(pr, 65536);
        sub.assert_true(ok);

        core::page_ring_write(pr, "1234567890");
        sub.assert_eq(pr.count, 10);
        let dropped = core::page_ring_discard(pr, 4);
        sub.assert_eq(dropped, 4);
        sub.assert_eq(pr.count, 6);

        var buf: u8[8] = [0; 8];
        let read_n, _ = core::page_ring_read(pr, buf[..6]);
        sub.assert_eq(read_n, 6);
        sub.assert_eq(buf[..6], "567890");

        core::page_ring_write(pr, "abcdef");
        sub.assert_eq(pr.count, 6);
        core::page_ring_clear(pr);
        sub.assert_eq(pr.count, 0);
        sub.assert_eq(pr.head, 0);
        sub.assert_eq(pr.tail, 0);

        core::page_ring_close(pr);
    };
}

fn test_page_ring_streaming_benchmark(t: lit::T&) {
    t.run("Continuous Streaming Throughput: PageRingBuffer vs PipeBuffer") { sub =>
        let iters = 50000;
        let chunk_size = 1024;
        var chunk: u8[1024] = [0; 1024];
        for i in 1024 {
            chunk[i] = ((i % 127) as u8) + 1;
        }

        // 1. Benchmark PipeBuffer (standard stack buffer with compact_pipe)
        var pipe = core::new_pipe_buffer();
        var pipe_sink: u8[1024] = [0; 1024];

        let watch_pipe = core::stopwatch();
        for _ in iters {
            let _, w_err = core::write(pipe, chunk[..chunk_size]);
            sub.assert_eq(w_err, core::IoError.None);

            let r_n, r_err = core::read(pipe, pipe_sink[..chunk_size]);
            sub.assert_eq(r_err, core::IoError.None);
            sub.assert_eq(r_n, chunk_size as i64);
        }
        let dt_pipe = core::elapsed(watch_pipe);

        // 2. Benchmark PageRingBuffer (hardware virtual memory page aliasing)
        var pr = core::PageRingBuffer { .. };
        let ok = core::page_ring_init(pr, 65536);
        sub.assert_true(ok);
        var pr_sink: u8[1024] = [0; 1024];

        let watch_ring = core::stopwatch();
        for _ in iters {
            let written, w_err = core::page_ring_write(pr, chunk[..chunk_size]);
            sub.assert_eq(w_err, core::IoError.None);
            sub.assert_eq(written, chunk_size as i64);

            let read_n, r_err = core::page_ring_read(pr, pr_sink[..chunk_size]);
            sub.assert_eq(r_err, core::IoError.None);
            sub.assert_eq(read_n, chunk_size as i64);
        }
        let dt_ring = core::elapsed(watch_ring);
        core::page_ring_close(pr);

        print("\n  [BENCHMARK] Streaming ", iters, " x 1KB chunks (51.20 MB total):");
        print("  - PipeBuffer (memmove compact): ", dt_pipe.as_micros(), " us (", dt_pipe.as_millis(), " ms)");
        print("  - PageRingBuffer (mirrored VM): ", dt_ring.as_micros(), " us (", dt_ring.as_millis(), " ms)");
        sub.assert_true(dt_ring.as_nanos() >= 0);
    };
}

fn main() {
    let runner = lit::new_runner("Virtual Memory Page-Mirrored Ring Buffer Suite");

    lit::run_case(runner, "1. Lifecycle, Allocation & Boundary Wraparound", test_page_ring_lifecycle_and_wraparound);
    lit::run_case(runner, "2. Vectorized Delimiters & Delimiter Straddling", test_page_ring_scanners_and_delimiters);
    lit::run_case(runner, "3. Streaming Throughput Benchmark vs PipeBuffer", test_page_ring_streaming_benchmark);

    let ok = lit::finish(runner);
    assert(ok);
}
