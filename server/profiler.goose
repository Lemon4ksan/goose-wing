// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Hardware cycle-accurate pipeline profiler for goose-wing.
namespace wing;

import std;
import core from "..";

const PROF_STAGE_FRAMING:   i32 = 0;
const PROF_STAGE_REQ_LINE:  i32 = 1;
const PROF_STAGE_HEADERS:   i32 = 2;
const PROF_STAGE_HOST_VAL:  i32 = 3;
const PROF_STAGE_PIPELINE:  i32 = 4;
const PROF_STAGE_ROUTER:    i32 = 5;
const PROF_STAGE_HANDLER:   i32 = 6;
const PROF_STAGE_RESP_SER:  i32 = 7;
const PROF_STAGE_OUT_COPY:  i32 = 8;
const PROF_STAGE_SOCK_RECV: i32 = 9;
const PROF_STAGE_SOCK_SEND: i32 = 10;
const PROF_STAGE_MISC:      i32 = 11;

extern fn prof_rdtsc() -> u64 = "wing_rdtsc";
extern fn prof_reset() = "wing_prof_reset";
extern fn prof_record(stage_id: i32, cycles: u64) = "wing_prof_record";
extern fn prof_total_cycles(stage_id: i32) -> u64 = "wing_prof_total_cycles";
extern fn prof_sample_count(stage_id: i32) -> u64 = "wing_prof_sample_count";
extern fn prof_min_cycles(stage_id: i32) -> u64 = "wing_prof_min_cycles";
extern fn prof_max_cycles(stage_id: i32) -> u64 = "wing_prof_max_cycles";
extern fn prof_avg_cycles(stage_id: i32) -> f64 = "wing_prof_avg_cycles";
extern fn prof_print_summary() = "wing_prof_print_summary";

// ---- Dynamic Named Stage & Memory Watermark API -----------------------------

extern fn prof_enter(name: const u8[:]) -> i64 = "wing_prof_enter";
extern fn prof_leave(span_tok: i64) = "wing_prof_leave";
extern fn prof_stage_count() -> i32 = "wing_prof_stage_count";
extern fn prof_find_stage(name: const u8[:]) -> i32 = "wing_prof_find_stage";
extern fn prof_stage_self_cycles(stage_id: i32) -> u64 = "wing_prof_stage_self_cycles";
extern fn prof_stage_p50_cycles(stage_id: i32) -> u64 = "wing_prof_stage_p50_cycles";
extern fn prof_stage_p99_cycles(stage_id: i32) -> u64 = "wing_prof_stage_p99_cycles";
extern fn prof_stage_net_bytes(stage_id: i32) -> i64 = "wing_prof_stage_net_bytes";
extern fn prof_stage_scratch_bytes(stage_id: i32) -> i64 = "wing_prof_stage_scratch_bytes";
extern fn prof_stage_peak_bytes(stage_id: i32) -> i64 = "wing_prof_stage_peak_bytes";
extern fn prof_stage_pool_allocs(stage_id: i32) -> i64 = "wing_prof_stage_pool_allocs";
extern fn prof_stage_pool_frees(stage_id: i32) -> i64 = "wing_prof_stage_pool_frees";

inline fn prof_span<F: fn()>(name: const u8[:]) {
    let tok = prof_enter(name);
    defer prof_leave(tok);
    F();
}

// ---- Multi-Pass Benchmark Suite Engine (testing.B ergonomics) ---------------

extern fn wing_bench_begin_suite(suite_name: const u8[:], default_target_ns: i64) = "wing_bench_begin_suite";
extern fn wing_bench_should_run(bench_name: const u8[:]) -> i32 = "wing_bench_should_run";
extern fn wing_bench_begin_pass(
    bench_name: const u8[:], pass_idx: i32, target_ns: i64,
) -> i64 = "wing_bench_begin_pass";
extern fn wing_bench_end_pass(pass_idx: i32, cur_n: i64, target_ns: i64) -> i64 = "wing_bench_end_pass";
extern fn wing_bench_reset_timer() = "wing_bench_reset_timer";
extern fn wing_bench_stop_timer() = "wing_bench_stop_timer";
extern fn wing_bench_start_timer() = "wing_bench_start_timer";
extern fn wing_bench_set_bytes(n_bytes: i64) = "wing_bench_set_bytes";
extern fn wing_bench_mark_has_sub() = "wing_bench_mark_has_sub";
extern fn wing_bench_consume_has_sub() -> i32 = "wing_bench_consume_has_sub";
extern fn wing_bench_report_metric(val: f64, unit: const u8[:]) = "wing_bench_report_metric";
extern fn wing_bench_commit(bench_name: const u8[:], final_n: i64, bytes_per_op: i64) = "wing_bench_commit";
extern fn wing_bench_print_report() = "wing_bench_print_report";

struct Bench {
    name:         u8[..64] = [],
    n:            i64      = 1,
    bytes_per_op: i64      = 0,
    target_ns:    i64      = 50000000,
    pass_kind:    i32      = 0,
}

struct BenchSuite {
    suite_name: u8[..64] = [],
    target_ns:  i64      = 50000000,
}

struct BenchPostPassSchedule {
    steady_state_n: i64 = 1,
    watermark_n:    i64 = 1,
}

fn new_bench_suite(suite_name: const u8[:], target_ms: i64 = 50) -> BenchSuite {
    let eff_ns = max(target_ms, 1) * 1000000;
    var s = BenchSuite { target_ns: eff_ns, .. };
    let _ = s.suite_name.try_set(suite_name);
    wing_bench_begin_suite(suite_name, eff_ns);
    return s;
}

inline fn execute_bench_passes<F: fn(Bench&)>(b: Bench&) {
    var cur_n: i64 = 1;
    while true {
        let _ = wing_bench_begin_pass(b.name[..], 0, b.target_ns);
        b.n = cur_n;
        b.pass_kind = 0;
        F(b);
        let res_n = wing_bench_end_pass(0, cur_n, b.target_ns);
        if res_n > 0 {
            cur_n = res_n;
            break;
        }
        cur_n = core::sub_sat_i64(0, res_n);
    }

    let schedule = BenchPostPassSchedule { steady_state_n: cur_n, watermark_n: 1 };
    const for <N, A> in fields<BenchPostPassSchedule> {
        let pass_idx: i32 = if N == "steady_state_n" { 1 } else { 2 };
        let pass_n = schedule.A;
        let _ = wing_bench_begin_pass(b.name[..], pass_idx, b.target_ns);
        b.n = pass_n;
        b.pass_kind = pass_idx;
        F(b);
        let _ = wing_bench_end_pass(pass_idx, pass_n, b.target_ns);
    }
    wing_bench_commit(b.name[..], cur_n, b.bytes_per_op);
}

fn bench<F: fn(Bench&)>(suite: BenchSuite&, case_name: const u8[:]) {
    guard wing_bench_should_run(case_name) != 0 else { return; }
    let _ = wing_bench_consume_has_sub();
    var b = Bench { target_ns: suite.target_ns, .. };
    let _ = b.name.try_set(case_name);
    execute_bench_passes(b) { it => F(it); };

    if wing_bench_consume_has_sub() != 0 {
        b.n = 0;
        b.pass_kind = 3;
        F(b);
    }
}

fn run<F: fn(Bench&)>(parent: Bench&, sub_name: const u8[:]) {
    if parent.pass_kind != 3 {
        wing_bench_mark_has_sub();
        return;
    }
    var full_name: u8[..64] = [];
    let _ = full_name.try_set(parent.name[..]);
    let _ = full_name.try_append("/");
    let _ = full_name.try_append(sub_name);
    guard wing_bench_should_run(full_name[..]) != 0 else { return; }

    var b = Bench { target_ns: parent.target_ns, .. };
    let _ = b.name.try_set(full_name[..]);
    execute_bench_passes(b) { it => F(it); };
}

inline fn reset_timer(b: Bench&) {
    let _ = b.n;
    wing_bench_reset_timer();
}

inline fn stop_timer(b: Bench&) {
    let _ = b.n;
    wing_bench_stop_timer();
}

inline fn start_timer(b: Bench&) {
    let _ = b.n;
    wing_bench_start_timer();
}

inline fn set_bytes(b: Bench&, n_bytes: i64) {
    b.bytes_per_op = n_bytes;
    wing_bench_set_bytes(n_bytes);
}

inline fn report_metric(b: Bench&, val: f64, unit: const u8[:]) {
    let _ = b.n;
    wing_bench_report_metric(val, unit);
}

inline fn finish_suite(suite: const BenchSuite&) {
    let _ = suite.target_ns;
    wing_bench_print_report();
}
