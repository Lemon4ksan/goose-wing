// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Unit tests for low-level performance primitives:
// 1. Lock-free SPSC Ring queue (core::SpscRing).
// 2. Minimal Perfect Hash header identifier (http::identify_known_header).
// 3. Structure-of-Arrays connection state table (server::SoAConnTable).
// 4. Memory-mapped static files (core::MmapFile) & PageRingBuffer lifecycle.
//
// RUN: goose build -o %t.exe %s
// RUN: %t.exe
import std;
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
// 4. Memory-Mapped Static Files
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
// 5. PageRingBuffer Lifecycle
// ----------------------------------------------------------------------------
fn test_page_ring_lifecycle(t: lit::T&) {
    t.run("PageRingBuffer Init, Cap and Close") { sub =>
        var pr = core::PageRingBuffer { .. };
        let ok = core::page_ring_init(pr, 65536);
        sub.assert_true(ok);
        sub.assert_true(pr.is_open);
        sub.assert_eq(pr.capacity, 65536);
        sub.assert_eq(pr.count, 0);
        sub.assert_eq(core::page_ring_available(pr), 65536);

        var buf: u8[16] = [0; 16];
        sub.assert_eq(core::page_ring_peek(pr, buf[..]), 0);
        sub.assert_eq(core::page_ring_discard(pr, 4), 0);
        core::page_ring_clear(pr);
        core::page_ring_close(pr);
        sub.assert_false(pr.is_open);
    };
}

fn main() {
    let runner = lit::new_runner("Low-Level Optimization Primitives Unit Suite");

    lit::run_case(runner, "1. SPSC Queue Lifecycle", test_spsc_queue_lifecycle);
    lit::run_case(runner, "2. Header Classification MPH", test_identify_known_header);
    lit::run_case(runner, "3. SoA Connection Table", test_soa_conn_table_lifecycle);
    lit::run_case(runner, "4. Memory-Mapped Static Files", test_mmap_file_suite);
    lit::run_case(runner, "5. PageRingBuffer Lifecycle", test_page_ring_lifecycle);

    let ok = lit::finish(runner);
    assert(ok);
}
