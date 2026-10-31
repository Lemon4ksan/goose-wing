// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Verification Suite: Hardware Virtual Memory Page Techniques
//
// RUN: goose build -o %t.exe %s
// RUN: %t.exe
import std;
import core from "..";
import lit from "github.com/Lemon4ksan/goose-lit@v0.1.0";

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

fn main() {
    let runner = lit::new_runner("Hardware Virtual Memory Page Techniques Suite");

    lit::run_case(runner, "1. Guarded Arena & Physical Pinned Memory", test_guarded_arena_and_pinned);
    lit::run_case(runner, "2. Instant Memory Reset Benchmark", test_instant_reset_benchmark);
    lit::run_case(runner, "3. Memory-Mapped Static Files", test_mmap_file_suite);

    let ok = lit::finish(runner);
    assert(ok);
}
