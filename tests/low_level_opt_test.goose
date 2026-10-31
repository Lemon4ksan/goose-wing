// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Unit tests for low-level performance primitives:
// 1. Lock-free SPSC Ring queue (core::SpscRing).
// 2. Minimal Perfect Hash header identifier (wing::identify_known_header).
// 3. Structure-of-Arrays connection state table (wing::SoAConnTable).
// 4. Software prefetch primitives (core::prefetch_t0, core::prefetch_nta).
//
// RUN: goose build -o %t.exe %s
// RUN: %t.exe
import std;
import core from "..";
import wing from "..";
import lit from "github.com/Lemon4ksan/goose-lit@v0.1.0";

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

fn test_identify_known_header(t: lit::T&) {
    t.run("Minimal Perfect Hash Header Classification") { sub =>
        // Canonical casing
        sub.assert_eq(wing::identify_known_header("Host"), wing::KnownHeaderId.Host);
        sub.assert_eq(wing::identify_known_header("Date"), wing::KnownHeaderId.Date);
        sub.assert_eq(wing::identify_known_header("Accept"), wing::KnownHeaderId.Accept);
        sub.assert_eq(wing::identify_known_header("Cookie"), wing::KnownHeaderId.Cookie);
        sub.assert_eq(wing::identify_known_header("Origin"), wing::KnownHeaderId.Origin);
        sub.assert_eq(wing::identify_known_header("Server"), wing::KnownHeaderId.Server);
        sub.assert_eq(wing::identify_known_header("Connection"), wing::KnownHeaderId.Connection);
        sub.assert_eq(wing::identify_known_header("User-Agent"), wing::KnownHeaderId.UserAgent);
        sub.assert_eq(wing::identify_known_header("Content-Type"), wing::KnownHeaderId.ContentType);
        sub.assert_eq(wing::identify_known_header("Content-Length"), wing::KnownHeaderId.ContentLength);
        sub.assert_eq(wing::identify_known_header("Authorization"), wing::KnownHeaderId.Authorization);
        sub.assert_eq(wing::identify_known_header("Transfer-Encoding"), wing::KnownHeaderId.TransferEncoding);
        sub.assert_eq(wing::identify_known_header("Sec-WebSocket-Key"), wing::KnownHeaderId.SecWebSocketKey);

        // Mixed / lowercase / uppercase casing
        sub.assert_eq(wing::identify_known_header("host"), wing::KnownHeaderId.Host);
        sub.assert_eq(wing::identify_known_header("HOST"), wing::KnownHeaderId.Host);
        sub.assert_eq(wing::identify_known_header("cOnTeNt-LeNgTh"), wing::KnownHeaderId.ContentLength);
        sub.assert_eq(wing::identify_known_header("transfer-encoding"), wing::KnownHeaderId.TransferEncoding);
        sub.assert_eq(wing::identify_known_header("USER-AGENT"), wing::KnownHeaderId.UserAgent);

        // Unknown / edge lengths
        sub.assert_eq(wing::identify_known_header(""), wing::KnownHeaderId.Unknown);
        sub.assert_eq(wing::identify_known_header("x"), wing::KnownHeaderId.Unknown);
        sub.assert_eq(wing::identify_known_header("x-custom-header"), wing::KnownHeaderId.Unknown);
        sub.assert_eq(wing::identify_known_header("very-long-unknown-header-name-exceeding-limit"), wing::KnownHeaderId.Unknown);
    };
}

fn test_soa_conn_table_lifecycle(t: lit::T&) {
    t.run("SoA Connection Table Alloc, Touch & Sweep") { sub =>
        var table = wing::SoAConnTable { .. };
        sub.assert_eq(table.count, 0);

        // Allocate slots
        let s0 = wing::soa_table_alloc(table, 100, 10);
        let s1 = wing::soa_table_alloc(table, 101, 20);
        let s2 = wing::soa_table_alloc(table, 102, 30);
        sub.assert_eq(s0, 0);
        sub.assert_eq(s1, 1);
        sub.assert_eq(s2, 2);
        sub.assert_eq(table.count, 3);

        // Touch slot 1
        wing::soa_table_touch(table, s1, 25);
        sub.assert_eq(table.timeout_ticks[s1], 25 as u8);

        // Timer wheel setup: advance to 22
        var wheel = wing::new_tick_timer_wheel(15);
        wing::tick_timer_advance(wheel, 15);

        // Sweep expired
        var expired: i64[16] = [0; 16];
        let n_exp = wing::soa_table_sweep_expired(table, wheel, expired[..]);
        sub.assert_eq(n_exp, 1);
        sub.assert_eq(expired[0], s0);

        // Free slot 0
        wing::soa_table_free(table, s0);
        sub.assert_eq(table.fds[s0], -1);
        sub.assert_eq(table.timeout_ticks[s0], 255 as u8);
    };
}

fn test_software_prefetch_execution(t: lit::T&) {
    t.run("Software Prefetch Execution") { sub =>
        let test_buffer: const u8[:] = "PREFETCH_TEST_BUFFER_PAYLOAD_CACHE_LINE_VALIDATION_STRING_LONGER_THAN_64_BYTES_FOR_PREFETCH_TEST";
        core::prefetch_t0(test_buffer);
        core::prefetch_nta(test_buffer);
        sub.assert_gt(test_buffer.len, 64);
    };
}

fn main() {
    let runner = lit::new_runner("Low-Level Optimization Primitives Unit Suite");

    lit::run_case(runner, "1. SPSC Queue Lifecycle", test_spsc_queue_lifecycle);
    lit::run_case(runner, "2. Header Classification MPH", test_identify_known_header);
    lit::run_case(runner, "3. SoA Connection Table", test_soa_conn_table_lifecycle);
    lit::run_case(runner, "4. Software Prefetch", test_software_prefetch_execution);

    let ok = lit::finish(runner);
    assert(ok);
}
