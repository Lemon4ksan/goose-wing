// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Direct Head-to-Head Comparative Benchmarks:
// 1. Queue Synchronization: Baseline Runtime Channel vs Cache-Padded Lock-Free SPSC Ring.
// 2. Header Dispatch: Baseline linear eq_ascii_fold scan vs Minimal Perfect Hash (MPH).
// 3. Reactor Sweeper: Baseline AoS (ReactorConnSlot 1048B) vs Structure-of-Arrays (SoA 1B ticks).
//
// RUN: goose build -o %t.exe %s
// RUN: %t.exe
import std;
import core from "..";
import wing from "..";
import lit from "github.com/Lemon4ksan/goose-lit@v0.1.0";

// Baseline header identifier: linear case-insensitive string comparisons
fn baseline_identify_header(name: const u8[:]) -> i32 {
    if core::eq_ascii_fold(name, "host") { return 1; }
    if core::eq_ascii_fold(name, "date") { return 2; }
    if core::eq_ascii_fold(name, "accept") { return 3; }
    if core::eq_ascii_fold(name, "cookie") { return 4; }
    if core::eq_ascii_fold(name, "origin") { return 5; }
    if core::eq_ascii_fold(name, "server") { return 6; }
    if core::eq_ascii_fold(name, "connection") { return 7; }
    if core::eq_ascii_fold(name, "user-agent") { return 8; }
    if core::eq_ascii_fold(name, "content-type") { return 9; }
    if core::eq_ascii_fold(name, "content-length") { return 10; }
    if core::eq_ascii_fold(name, "authorization") { return 11; }
    if core::eq_ascii_fold(name, "transfer-encoding") { return 12; }
    if core::eq_ascii_fold(name, "sec-websocket-key") { return 13; }
    return 0;
}

// Baseline AoS deadline sweeper over 1048-byte structs (matching ReactorConnSlot)
struct BaselineAosSlot {
    fd:           i64      = -1,
    leftover_len: i64      = 0,
    timeout_tick: u8       = 255,
    leftover:     u8[1024] = [0; 1024],
}

fn baseline_sweep_aos(
    slots:       BaselineAosSlot[:],
    wheel:       const wing::TickTimerWheel&,
    out_expired: i64[:],
) -> i64 {
    var expired_n: i64 = 0;
    for s in slots.len {
        let slot = slots[s];
        if slot.timeout_tick != 255 && wing::tick_timer_is_expired(wheel, slot.timeout_tick) {
            if slot.fd > 0 && expired_n < out_expired.len {
                out_expired[expired_n] = s;
                expired_n++;
            }
        }
    }
    return expired_n;
}

fn test_spsc_vs_channel_benchmark(t: lit::T&) {
    t.run("Queue Synchronization: Runtime Channel vs SPSC Lock-Free Ring") { sub =>
        let iters: i64 = 50000;

        // --- Baseline: Standard Runtime Channel ---
        core::set_channel_limit<u64>(1024);
        let watch_chan = core::stopwatch();
        for k in iters {
            let s_ok = core::send_msg(k as u64);
            sub.assert_true(s_ok);
            let val = core::recv_msg<u64>();
            sub.assert_eq(val, k as u64);
        }
        let dt_chan = core::elapsed(watch_chan);

        // --- Optimized: Cache-Line Aligned Lock-Free SPSC Ring ---
        var ring, ok = core::spsc_init(1024);
        sub.assert_true(ok);
        defer core::spsc_close(ring);

        var out_val: u64 = 0;
        let watch_spsc = core::stopwatch();
        for k in iters {
            let p_ok = core::spsc_push(ring, k as u64);
            sub.assert_true(p_ok);
            let po_ok = core::spsc_pop(ring, out_val);
            sub.assert_true(po_ok);
            sub.assert_eq(out_val, k as u64);
        }
        let dt_spsc = core::elapsed(watch_spsc);

        print("\n  [A/B BENCHMARK 1] Queue Throughput (", iters, " push/pop cycles):");
        print("  - Baseline Runtime Channel: ", dt_chan.as_micros(), " us (", dt_chan.as_millis(), " ms)");
        print("  - Optimized Lock-Free SPSC: ", dt_spsc.as_micros(), " us (", dt_spsc.as_millis(), " ms)");
        if dt_spsc.as_micros() > 0 {
            let speedup_x10 = (dt_chan.as_micros() * 10) / dt_spsc.as_micros();
            print("  - Speedup: ", speedup_x10 / 10, ".", speedup_x10 % 10, "x faster");
        }
    };
}

inline fn header_id_to_int(id: wing::KnownHeaderId) -> i64 {
    return match id {
        Host => 1,
        Date => 2,
        Accept => 3,
        Cookie => 4,
        Origin => 5,
        Server => 6,
        Connection => 7,
        UserAgent => 8,
        ContentType => 9,
        ContentLength => 10,
        Authorization => 11,
        TransferEncoding => 12,
        SecWebSocketKey => 13,
        _ => 0,
    };
}

fn test_perfect_hash_vs_linear_scan_benchmark(t: lit::T&) {
    t.run("Header Dispatch: Linear Scan vs Minimal Perfect Hash (MPH)") { sub =>
        let iters: i64         = 100000;
        let hdr_a: const u8[:] = "Content-Length";
        let hdr_b: const u8[:] = "Host";

        // --- Baseline: Linear case-folding comparisons ---
        var base_sum: i64 = 0;
        let watch_base = core::stopwatch();
        for k in iters {
            let h = if (k & 1) == 0 { hdr_a } else { hdr_b };
            base_sum = base_sum + (baseline_identify_header(h) as i64);
        }
        let dt_base = core::elapsed(watch_base);
        sub.assert_gt(base_sum, 0);

        // --- Optimized: Minimal Perfect Hash (MPH) ---
        var mph_sum: i64 = 0;
        let watch_mph = core::stopwatch();
        for k in iters {
            let h = if (k & 1) == 0 { hdr_a } else { hdr_b };
            mph_sum = mph_sum + header_id_to_int(wing::identify_known_header(h));
        }
        let dt_mph = core::elapsed(watch_mph);
        sub.assert_gt(mph_sum, 0);

        print("\n  [A/B BENCHMARK 2] Header Identification (", iters, " runtime lookups):");
        print("  - Baseline Linear Scan:   ", dt_base.as_micros(), " us (", dt_base.as_nanos(), " ns)");
        print("  - Optimized Perfect Hash: ", dt_mph.as_micros(), " us (", dt_mph.as_nanos(), " ns)");
        if dt_mph.as_nanos() > 0 {
            let speedup_x10 = (dt_base.as_nanos() * 10) / dt_mph.as_nanos();
            print("  - Speedup: ", speedup_x10 / 10, ".", speedup_x10 % 10, "x faster");
        }
    };
}

fn test_soa_vs_aos_sweeper_benchmark(t: lit::T&) {
    t.run("Reactor Sweeper: AoS (1048B Structs) vs SoA (1B Packed Ticks)") { sub =>
        let iters: i64 = 2000;
        let conns: i64 = 1024;

        var wheel = wing::new_tick_timer_wheel(15);
        wing::tick_timer_advance(wheel, 15);

        // --- Baseline AoS Setup ---
        var aos_slots: BaselineAosSlot[1024] = [BaselineAosSlot { .. }; 1024];
        for i in conns {
            aos_slots[i].fd = 1000 + i;
            aos_slots[i].timeout_tick = if i < 512 { 10 } else { 20 };
        }
        var aos_expired: i64[1024] = [0; 1024];

        let watch_aos = core::stopwatch();
        var aos_count: i64 = 0;
        for _ in iters {
            aos_count = baseline_sweep_aos(aos_slots[..], wheel, aos_expired[..]);
        }
        let dt_aos = core::elapsed(watch_aos);
        sub.assert_eq(aos_count, 512);

        // --- Optimized SoA Setup ---
        var soa_table = wing::SoAConnTable { .. };
        for i in conns {
            let slot = wing::soa_table_alloc(soa_table, 1000 + i, if i < 512 { 10 } else { 20 });
            sub.assert_eq(slot, i);
        }
        var soa_expired: i64[1024] = [0; 1024];

        let watch_soa = core::stopwatch();
        var soa_count: i64 = 0;
        for _ in iters {
            soa_count = wing::soa_table_sweep_expired(soa_table, wheel, soa_expired[..]);
        }
        let dt_soa = core::elapsed(watch_soa);
        sub.assert_eq(soa_count, 512);

        let total_sweeps = iters * conns;
        print("\n  [A/B BENCHMARK 3] Connection Deadline Sweeping (", total_sweeps, " slot inspections):");
        print("  - Baseline AoS (1048B Stride): ", dt_aos.as_micros(), " us (", dt_aos.as_millis(), " ms)");
        print("  - Optimized SoA (1B Contiguous): ", dt_soa.as_micros(), " us (", dt_soa.as_millis(), " ms)");
        if dt_soa.as_micros() > 0 {
            let speedup_x10 = (dt_aos.as_micros() * 10) / dt_soa.as_micros();
            print("  - Speedup: ", speedup_x10 / 10, ".", speedup_x10 % 10, "x faster");
        }
    };
}

fn test_software_prefetch(t: lit::T&) {
    t.run("Software Prefetch Execution") { sub =>
        let test_buffer: const u8[:] = "PREFETCH_TEST_BUFFER_PAYLOAD_CACHE_LINE_VALIDATION_STRING_LONGER_THAN_64_BYTES_FOR_PREFETCH_TEST";
        core::prefetch_t0(test_buffer);
        core::prefetch_nta(test_buffer);
        sub.assert_gt(test_buffer.len, 64);
    };
}

fn main() {
    let runner = lit::new_runner("Head-to-Head Optimization Benchmark Suite");

    lit::run_case(runner, "1. Queue Throughput: Channel vs SPSC", test_spsc_vs_channel_benchmark);
    lit::run_case(runner, "2. Header Dispatch: Linear Scan vs MPH", test_perfect_hash_vs_linear_scan_benchmark);
    lit::run_case(runner, "3. Reactor Sweeper: AoS vs SoA", test_soa_vs_aos_sweeper_benchmark);
    lit::run_case(runner, "4. Software Prefetch Primitives", test_software_prefetch);

    let ok = lit::finish(runner);
    assert(ok);
}
