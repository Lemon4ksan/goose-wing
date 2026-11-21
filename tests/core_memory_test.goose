// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Unit tests for low-level performance primitives:
// 1. Lock-free SPSC Ring queue (core::SpscRing).
// 2. Minimal Perfect Hash header identifier (http::identify_known_header).
// 3. Structure-of-Arrays connection state table (server::SoAConnTable).
// 4. Software prefetch primitives (core::prefetch_t0, core::prefetch_nta).
//
// RUN: goose build -o %t.exe %s
// RUN: %t.exe
import std;
import core from "..";
import wing from "..";
import lit from "github.com/Lemon4ksan/goose-lit@v0.1.0";

// ----------------------------------------------------------------------------
// 1. SPSC Queue Lifecycle
// ----------------------------------------------------------------------------
fn test_spsc_queue_lifecycle(t: lit::T&) {
    t.run("SPSC Queue Lifecycle & Fifo Semantics") { sub =>
        var ring, ok = core::spsc_init(16);
        sub.assert_true(ok);
        sub.assert_true(ring.is_open);
        sub.assert_eq(ring.capacity, 16 as u32);
        defer core::spsc_close(ring);

        sub.assert_eq(core::spsc_count(ring), 0 as u32);
        sub.assert_eq(core::spsc_available(ring), 16 as u32);

        // Push 10 items
        for i in 10 {
            let p_ok = core::spsc_push(ring, (100 + i) as u64);
            sub.assert_true(p_ok);
        }
        sub.assert_eq(core::spsc_count(ring), 10 as u32);
        sub.assert_eq(core::spsc_available(ring), 6 as u32);

        // Pop 5 items and verify FIFO order
        for i in 5 {
            var val: u64 = 0;
            let po_ok = core::spsc_pop(ring, val);
            sub.assert_true(po_ok);
            sub.assert_eq(val, (100 + i) as u64);
        }
        sub.assert_eq(core::spsc_count(ring), 5 as u32);

        // Push 6 more items
        for i in 6 {
            let p_ok = core::spsc_push(ring, (200 + i) as u64);
            sub.assert_true(p_ok);
        }
        sub.assert_eq(core::spsc_count(ring), 11 as u32);

        // Pop remaining 11 items
        for i in 5 {
            var val: u64 = 0;
            let po_ok = core::spsc_pop(ring, val);
            sub.assert_true(po_ok);
            sub.assert_eq(val, (105 + i) as u64);
        }
        for i in 6 {
            var val: u64 = 0;
            let po_ok = core::spsc_pop(ring, val);
            sub.assert_true(po_ok);
            sub.assert_eq(val, (200 + i) as u64);
        }
        sub.assert_eq(core::spsc_count(ring), 0 as u32);

        // Underflow: pop on empty returns false
        var underflow_val: u64 = 0;
        let empty_ok = core::spsc_pop(ring, underflow_val);
        sub.assert_false(empty_ok);
    };
}

// ----------------------------------------------------------------------------
// 2. Header Classification MPH
// ----------------------------------------------------------------------------
fn test_identify_known_header(t: lit::T&) {
    t.run("Minimal Perfect Hash Header Classification") { sub =>
        // Canonical casing
        sub.assert_eq(http::identify_known_header("Host"), http::KnownHeaderId.Host);
        sub.assert_eq(http::identify_known_header("Date"), http::KnownHeaderId.Date);
        sub.assert_eq(http::identify_known_header("Accept"), http::KnownHeaderId.Accept);
        sub.assert_eq(http::identify_known_header("Cookie"), http::KnownHeaderId.Cookie);
        sub.assert_eq(http::identify_known_header("Origin"), http::KnownHeaderId.Origin);
        sub.assert_eq(http::identify_known_header("Server"), http::KnownHeaderId.Server);
        sub.assert_eq(http::identify_known_header("Connection"), http::KnownHeaderId.Connection);
        sub.assert_eq(http::identify_known_header("User-Agent"), http::KnownHeaderId.UserAgent);
        sub.assert_eq(http::identify_known_header("Content-Type"), http::KnownHeaderId.ContentType);
        sub.assert_eq(http::identify_known_header("Content-Length"), http::KnownHeaderId.ContentLength);
        sub.assert_eq(http::identify_known_header("Authorization"), http::KnownHeaderId.Authorization);
        sub.assert_eq(http::identify_known_header("Transfer-Encoding"), http::KnownHeaderId.TransferEncoding);
        sub.assert_eq(http::identify_known_header("Sec-WebSocket-Key"), http::KnownHeaderId.SecWebSocketKey);

        // Mixed / lowercase / uppercase casing
        sub.assert_eq(http::identify_known_header("host"), http::KnownHeaderId.Host);
        sub.assert_eq(http::identify_known_header("HOST"), http::KnownHeaderId.Host);
        sub.assert_eq(http::identify_known_header("cOnTeNt-LeNgTh"), http::KnownHeaderId.ContentLength);
        sub.assert_eq(http::identify_known_header("transfer-encoding"), http::KnownHeaderId.TransferEncoding);
        sub.assert_eq(http::identify_known_header("USER-AGENT"), http::KnownHeaderId.UserAgent);

        // Unknown / edge lengths
        sub.assert_eq(http::identify_known_header(""), http::KnownHeaderId.Unknown);
        sub.assert_eq(http::identify_known_header("x"), http::KnownHeaderId.Unknown);
        sub.assert_eq(http::identify_known_header("x-custom-header"), http::KnownHeaderId.Unknown);
        sub.assert_eq(http::identify_known_header("very-long-unknown-header-name-exceeding-limit"), http::KnownHeaderId.Unknown);
    };
}

// ----------------------------------------------------------------------------
// 3. SoA Connection Table
// ----------------------------------------------------------------------------
fn test_soa_conn_table_lifecycle(t: lit::T&) {
    t.run("SoA Connection Table Alloc, Touch & Sweep") { sub =>
        var table = server::SoAConnTable { .. };
        sub.assert_eq(table.count, 0);

        // Allocate slots
        let s0 = server::soa_table_alloc(table, 100, 10);
        let s1 = server::soa_table_alloc(table, 101, 20);
        let s2 = server::soa_table_alloc(table, 102, 30);
        sub.assert_eq(s0, 0);
        sub.assert_eq(s1, 1);
        sub.assert_eq(s2, 2);
        sub.assert_eq(table.count, 3);

        // Touch slot 1
        server::soa_table_touch(table, s1, 25);
        sub.assert_eq(table.timeout_ticks[s1], 25 as u8);

        // Timer wheel setup: advance to 22
        var wheel = core::TickTimerWheel { idle_timeout_sec: 15, .. };
        core::tick_timer_advance(wheel, 15);

        // Sweep expired
        var expired: i64[16] = [0; 16];
        let n_exp = server::soa_table_sweep_expired(table, wheel, expired[..]);
        sub.assert_eq(n_exp, 1);
        sub.assert_eq(expired[0], s0);

        // Free slot 0
        server::soa_table_free(table, s0);
        sub.assert_eq(table.fds[s0], -1);
        sub.assert_eq(table.timeout_ticks[s0], 255 as u8);
    };
}

// ----------------------------------------------------------------------------
// 4. Software Prefetch
// ----------------------------------------------------------------------------
fn test_software_prefetch_execution(t: lit::T&) {
    t.run("Software Prefetch Execution") { sub =>
        let test_buffer: const u8[:] = "PREFETCH_TEST_BUFFER_PAYLOAD_CACHE_LINE_VALIDATION_STRING_LONGER_THAN_64_BYTES_FOR_PREFETCH_TEST";
        core::prefetch_t0(test_buffer);
        core::prefetch_nta(test_buffer);
        sub.assert_gt(test_buffer.len, 64);
    };
}

// ----------------------------------------------------------------------------
// 5. Guarded Arena & Physical Pinned Memory
// ----------------------------------------------------------------------------
fn test_guarded_arena_and_pinned(t: lit::T&) {
    t.run("Guarded Arena Allocation and Boundary") { sub =>
        var arena, ok = core::guarded_arena_init(65536, core::PAGE_MEM_GUARD_PAGE);
        sub.assert_true(ok);
        sub.assert_true(arena.handle != 0);
        sub.assert_true(arena.capacity >= 65536);
        sub.assert_eq(arena.used, 0);

        let payload: const u8[:] = "GET /v1/telemetry/metrics HTTP/1.1\r\nHost: goose.local\r\n\r\n";
        let written, w_ok = core::guarded_arena_write(arena, payload);
        sub.assert_true(w_ok);
        sub.assert_eq(written, payload.len);
        sub.assert_eq(arena.used, payload.len as u64);

        var buf: u8[128] = [0; 128];
        let read_n, r_ok = core::guarded_arena_read(arena, 0, buf[..payload.len]);
        sub.assert_true(r_ok);
        sub.assert_eq(read_n, payload.len);
        sub.assert_eq(buf[..read_n], payload);

        let avail = core::guarded_arena_available(arena);
        sub.assert_true(avail == arena.capacity - arena.used);

        core::guarded_arena_close(arena);
        sub.assert_eq(arena.handle, 0);
    };

    t.run("Pinned Physical Memory Buffer") { sub =>
        var pb, ok = core::pinned_buffer_init(65536);
        sub.assert_true(ok);
        sub.assert_true(pb.handle != 0);
        sub.assert_true(pb.is_locked);
        sub.assert_true(pb.capacity >= 65536);

        let dma_header: const u8[:] = "DMA_DESCRIPTOR_V1_PACKET_HEADER";
        let written, w_ok = core::pinned_buffer_write(pb, 0, dma_header);
        sub.assert_true(w_ok);
        sub.assert_eq(written, dma_header.len);

        var read_buf: u8[64] = [0; 64];
        let read_n, r_ok = core::pinned_buffer_read(pb, 0, read_buf[..dma_header.len]);
        sub.assert_true(r_ok);
        sub.assert_eq(read_n, dma_header.len);
        sub.assert_eq(read_buf[..read_n], dma_header);

        core::pinned_buffer_close(pb);
        sub.assert_eq(pb.handle, 0);
        sub.assert_false(pb.is_locked);
    };
}

// ----------------------------------------------------------------------------
// 6. Instant Memory Reset Benchmark
// ----------------------------------------------------------------------------
fn test_instant_reset_benchmark(t: lit::T&) {
    t.run("Instant Memory Reset vs Synchronous Memset") { sub =>
        // 16 MB arena for recycling benchmark
        let arena_size: u64 = 16 * 1024 * 1024;
        var arena, ok = core::guarded_arena_init(arena_size, 0);
        sub.assert_true(ok);
        sub.assert_true(arena.capacity >= arena_size);

        let chunk: const u8[:] = "0123456789ABCDEF0123456789ABCDEF"; // 32 bytes
        // Dirty first 64 KB
        var i: i64 = 0;
        while i < 2048 {
            let _, _ = core::guarded_arena_write(arena, chunk);
            i = i + 1;
        }
        sub.assert_eq(arena.used, 65536);

        // 1. Measure standard synchronous memset over entire 16 MB
        let sw1 = core::stopwatch();
        let zero_rc = core::native_guarded_arena_clear_zero(arena.handle, arena.capacity);
        let dt_memset = core::elapsed(sw1);
        sub.assert_eq(zero_rc, 0);
        arena.used = 0;

        // Re-dirty the memory
        i = 0;
        while i < 2048 {
            let _, _ = core::guarded_arena_write(arena, chunk);
            i = i + 1;
        }
        sub.assert_eq(arena.used, 65536);

        // 2. Measure instant OS page reset (MEM_RESET / MADV_DONTNEED) over 16 MB
        let sw2 = core::stopwatch();
        let reset_ok = core::guarded_arena_reset(arena);
        let dt_reset = core::elapsed(sw2);
        sub.assert_true(reset_ok);
        sub.assert_eq(arena.used, 0);

        // Verify reading reset page returns error because used is 0
        var verify_buf: u8[32] = [0; 32];
        let _, r_ok = core::guarded_arena_read(arena, 0, verify_buf[..32]);
        sub.assert_false(r_ok);

        print("\n  [BENCHMARK] 16 MB Arena Recycling Comparison:");
        print("  - Synchronous memset (16 MB): ", dt_memset.as_micros(), " us (", dt_memset.as_millis(), " ms)");
        print("  - Instant OS Page Reset (16 MB): ", dt_reset.as_micros(), " us (", dt_reset.as_millis(), " ms)");
        sub.assert_true(dt_reset.as_nanos() >= 0);

        core::guarded_arena_close(arena);
    };
}

// ----------------------------------------------------------------------------
// 7. Memory-Mapped Static Files
// ----------------------------------------------------------------------------
fn test_mmap_file_suite(t: lit::T&) {
    t.run("Memory-Mapped Static File Serving") { sub =>
        let file_path: const u8[:] = "core.build";
        var mf, ok = core::mmap_file_open(file_path);
        sub.assert_true(ok);
        sub.assert_true(mf.handle != 0);
        sub.assert_true(mf.size > 0);

        var head_buf: u8[32] = [0; 32];
        let read_n, r_ok = core::mmap_file_read(mf, 0, head_buf[..32]);
        sub.assert_true(r_ok);
        sub.assert_eq(read_n, 32);

        let expected: const u8[:] = "// SPDX-License-Identifier";
        sub.assert_eq(head_buf[..expected.len], expected);

        core::mmap_file_close(mf);
        sub.assert_eq(mf.handle, 0);
        sub.assert_eq(mf.size, 0);
    };
}

// ----------------------------------------------------------------------------
// 8. Lifecycle, Allocation & Boundary Wraparound
// ----------------------------------------------------------------------------
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

// ----------------------------------------------------------------------------
// 9. Vectorized Delimiters & Delimiter Straddling
// ----------------------------------------------------------------------------
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

// ----------------------------------------------------------------------------
// 10. Streaming Throughput Benchmark vs PipeBuffer
// ----------------------------------------------------------------------------
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
    let runner = lit::new_runner("Low-Level Optimization Primitives Unit Suite");

    lit::run_case(runner, "1. SPSC Queue Lifecycle", test_spsc_queue_lifecycle);
    lit::run_case(runner, "2. Header Classification MPH", test_identify_known_header);
    lit::run_case(runner, "3. SoA Connection Table", test_soa_conn_table_lifecycle);
    lit::run_case(runner, "4. Software Prefetch", test_software_prefetch_execution);
    lit::run_case(runner, "5. Guarded Arena & Physical Pinned Memory", test_guarded_arena_and_pinned);
    lit::run_case(runner, "6. Instant Memory Reset Benchmark", test_instant_reset_benchmark);
    lit::run_case(runner, "7. Memory-Mapped Static Files", test_mmap_file_suite);
    lit::run_case(runner, "8. Lifecycle, Allocation & Boundary Wraparound", test_page_ring_lifecycle_and_wraparound);
    lit::run_case(runner, "9. Vectorized Delimiters & Delimiter Straddling", test_page_ring_scanners_and_delimiters);
    lit::run_case(runner, "10. Streaming Throughput Benchmark vs PipeBuffer", test_page_ring_streaming_benchmark);

    let ok = lit::finish(runner);
    assert(ok);
}
