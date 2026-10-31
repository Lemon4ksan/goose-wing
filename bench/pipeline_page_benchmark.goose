// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// End-to-End Pipeline Verification & Performance Benchmarks:
// 1. HTTP Ingestion Pipeline: PipeBuffer (memmove compact) vs PageRingBuffer (mirrored VM).
// 2. Connection Lifecycle: Synchronous memset vs Instant OS Page Reset (MEM_RESET / MADV_DONTNEED).
// 3. Static File Serving: Buffered I/O vs MmapFile zero-copy transmission.
//
// RUN: goose build -o %t.exe %s
// RUN: %t.exe
import std;
import core from "..";
import wing from "..";
import lit from "github.com/Lemon4ksan/goose-lit@v0.1.0";

fn test_pipeline_http_ingestion_benchmark(t: lit::T&) {
    t.run("HTTP Ingress Pipeline: PipeBuffer vs PageRingBuffer") { sub =>
        var server = wing::new_http_server("127.0.0.1", 8080);
        wing::add_get_route(server, "/greet", 1);

        let req_template:     const u8[:] = "GET /greet HTTP/1.1\r\nHost: 127.0.0.1\r\nSec-Fetch-Site: same-origin\r\n\r\n";
        let batch_size:       i64         = 10;
        let total_iterations: i64         = 2000; // 20,000 requests total
        let now_ns:           u64         = 1000000000;

        // --- 1. PipeBuffer Ingestion Pipeline ---
        var pipe = core::new_pipe_buffer();
        var pipe_out = core::new_cork_buffer();
        var pipe_requests_handled: i64 = 0;

        let watch_pipe = core::stopwatch();
        for _ in total_iterations {
            for _ in batch_size {
                let _, w_err = core::write(pipe, req_template);
                sub.assert_eq(w_err, core::IoError.None);
            }
            let n, ok = wing::handle_connection_pipe(server, "127.0.0.1", pipe, now_ns, pipe_out);
            sub.assert_true(ok);
            pipe_requests_handled = pipe_requests_handled + n;
            core::cork_consume(pipe_out, pipe_out.cork_pending());
        }
        let dt_pipe = core::elapsed(watch_pipe);
        sub.assert_eq(pipe_requests_handled, total_iterations * batch_size);

        // --- 2. PageRingBuffer Ingestion Pipeline ---
        var ring = core::PageRingBuffer { .. };
        let ring_init_ok = core::page_ring_init(ring, 65536);
        sub.assert_true(ring_init_ok);
        defer core::page_ring_close(ring);

        var ring_out = core::new_cork_buffer();
        var ring_requests_handled: i64 = 0;

        let watch_ring = core::stopwatch();
        for _ in total_iterations {
            for _ in batch_size {
                let written, w_err = core::page_ring_write(ring, req_template);
                sub.assert_eq(w_err, core::IoError.None);
                sub.assert_eq(written, req_template.len);
            }
            let n, ok = wing::handle_connection_page_ring(server, "127.0.0.1", ring, now_ns, ring_out);
            sub.assert_true(ok);
            ring_requests_handled = ring_requests_handled + n;
            core::cork_consume(ring_out, ring_out.cork_pending());
        }
        let dt_ring = core::elapsed(watch_ring);
        sub.assert_eq(ring_requests_handled, total_iterations * batch_size);

        let total_reqs = total_iterations * batch_size;
        print("\n  [PIPELINE BENCHMARK 1] HTTP Pipelined Ingestion (", total_reqs, " requests):");
        print("  - PipeBuffer (memmove compact): ", dt_pipe.as_micros(), " us (", dt_pipe.as_millis(), " ms)");
        print("  - PageRingBuffer (hardware VM): ", dt_ring.as_micros(), " us (", dt_ring.as_millis(), " ms)");
        if dt_ring.as_micros() > 0 {
            let speedup_x10 = (dt_pipe.as_micros() * 10) / dt_ring.as_micros();
            print("  - Speedup: ", speedup_x10 / 10, ".", speedup_x10 % 10, "x faster");
        }
    };
}

fn test_connection_arena_recycling_benchmark(t: lit::T&) {
    t.run("Connection Arena Lifecycle: Synchronous Memset vs Instant OS Page Reset") { sub =>
        let arena_size:  u64         = 4 * 1024 * 1024; // 4 MB connection scratch arena
        let cycles:      i64         = 500;             // 500 simulated connections
        let dirty_chunk: const u8[:] = "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{\"status\":\"ok\"}";

        // --- Approach A: Synchronous Memset Clearing ---
        var arena_sync, ok_sync = core::guarded_arena_init(arena_size, 0);
        sub.assert_true(ok_sync);
        defer core::guarded_arena_close(arena_sync);

        let watch_sync = core::stopwatch();
        for _ in cycles {
            // Simulate connection writing into arena
            let _, _ = core::guarded_arena_write(arena_sync, dirty_chunk);
            // On connection close: synchronous memset of entire arena
            let rc = core::native_guarded_arena_clear_zero(arena_sync.handle, arena_sync.capacity);
            sub.assert_eq(rc, 0);
            arena_sync.used = 0;
        }
        let dt_sync = core::elapsed(watch_sync);

        // --- Approach B: Instant OS Page Reset (MEM_RESET / MADV_DONTNEED) ---
        var arena_reset, ok_reset = core::guarded_arena_init(arena_size, 0);
        sub.assert_true(ok_reset);
        defer core::guarded_arena_close(arena_reset);

        let watch_reset = core::stopwatch();
        for _ in cycles {
            // Simulate connection writing into arena
            let _, _ = core::guarded_arena_write(arena_reset, dirty_chunk);
            // On connection close: instant kernel decommit
            let reset_ok = core::guarded_arena_reset(arena_reset);
            sub.assert_true(reset_ok);
        }
        let dt_reset = core::elapsed(watch_reset);

        print("\n  [PIPELINE BENCHMARK 2] 4 MB Arena Recycling (", cycles, " connection lifecycles):");
        print("  - Synchronous memset: ", dt_sync.as_micros(), " us (", dt_sync.as_millis(), " ms)");
        print("  - Instant OS Page Reset: ", dt_reset.as_micros(), " us (", dt_reset.as_millis(), " ms)");
        if dt_reset.as_micros() > 0 {
            let speedup_x10 = (dt_sync.as_micros() * 10) / dt_reset.as_micros();
            print("  - Speedup: ", speedup_x10 / 10, ".", speedup_x10 % 10, "x faster");
        }
    };
}

fn test_static_file_mmap_serving_benchmark(t: lit::T&) {
    t.run("Static File Serving Pipeline") { sub =>
        let file_path: const u8[:] = "core.build";
        let iters:     i64         = 500;

        var wire_out = core::new_cork_buffer();
        let watch_mmap = core::stopwatch();
        for _ in iters {
            let ok = wing::serve_static_mmap_file(file_path, "text/plain", wire_out);
            sub.assert_true(ok);
            core::cork_consume(wire_out, wire_out.cork_pending());
        }
        let dt_mmap = core::elapsed(watch_mmap);

        print("\n  [PIPELINE BENCHMARK 3] Static File Serving (", iters, " iterations of core.build):");
        print("  - Total Time: ", dt_mmap.as_micros(), " us (", dt_mmap.as_millis(), " ms)");
        if iters > 0 && dt_mmap.as_micros() > 0 {
            let latency_ns = dt_mmap.as_nanos() / iters;
            print("  - Average per-file latency: ", latency_ns, " ns");
        }
    };
}

fn main() {
    let runner = lit::new_runner("Hardware Virtual Memory Page Pipeline Benchmark");

    lit::run_case(runner, "1. HTTP Request Ingress Pipeline", test_pipeline_http_ingestion_benchmark);
    lit::run_case(runner, "2. Connection Arena Memory Lifecycle", test_connection_arena_recycling_benchmark);
    lit::run_case(runner, "3. Static File Serving Pipeline", test_static_file_mmap_serving_benchmark);

    let ok = lit::finish(runner);
    assert(ok);
}
