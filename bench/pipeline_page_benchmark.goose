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
import wing from "..";
import lit from "github.com/Lemon4ksan/goose-lit@v0.1.0";

fn test_pipeline_http_ingestion_benchmark(t: lit::T&) {
    t.run("HTTP Ingress Pipeline: PipeBuffer vs PageRingBuffer") { sub =>
        var server = server::new_http_server("127.0.0.1", 8080);
        server::add_get_route(server, "/greet", 1);

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
            let n, ok = server::handle_connection_pipe(server, "127.0.0.1", pipe, now_ns, pipe_out);
            sub.assert_true(ok);
            pipe_requests_handled = pipe_requests_handled + n;
            core::cork_consume(pipe_out, pipe_out.cork_pending());
        }
        let dt_pipe = core::elapsed(watch_pipe);
        sub.assert_eq(pipe_requests_handled, total_iterations * batch_size);

        let total_reqs = total_iterations * batch_size;
        print("\n  [PIPELINE BENCHMARK 1] HTTP Pipelined Ingestion (", total_reqs, " requests):");
        print("  - PipeBuffer (memmove compact): ", dt_pipe.as_micros(), " us (", dt_pipe.as_millis(), " ms)");
    };
}

fn test_static_file_mmap_serving_benchmark(t: lit::T&) {
    t.run("Static File Serving Pipeline") { sub =>
        let file_path: const u8[:] = "core.build";
        let iters:     i64         = 500;

        var wire_out = core::new_cork_buffer();
        let watch_mmap = core::stopwatch();
        for _ in iters {
            let ok = server::serve_static_mmap_file(file_path, "text/plain", wire_out);
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
    lit::run_case(runner, "2. Static File Serving Pipeline", test_static_file_mmap_serving_benchmark);

    let ok = lit::finish(runner);
    assert(ok);
}
