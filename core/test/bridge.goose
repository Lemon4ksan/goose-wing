// Backward-compatibility aliases, std::test namespace bridges, and global UFCS bridges.
namespace core;

import std;
import core.time;
import core.test.context;
import core.test.mock;
import core.test.assert;
import core.test.runner;

// Backward-compatibility aliases & std::test namespace bridges

type test::T = core::T;
type test::Runner = core::Runner;
type test::Failure = core::Failure;
type test::Verbosity = core::Verbosity;
type test::MockClock = core::MockClock;
type test::FuzzRng = core::FuzzRng;

fn test::new_runner(suite_name: const u8[:], verbosity: Verbosity = Verbosity.Normal) -> Runner { return core::new_runner(suite_name, verbosity); }
fn test::new_test(name: const u8[:], level: i64 = 0) -> T { return core::new_test(name, level); }
fn test::new_mock_clock(initial_us: i64 = 1700000000000000) -> MockClock { return core::new_mock_clock(initial_us); }
fn test::new_fuzz_rng(seed: u64 = 0x853c49e6748fea9b) -> FuzzRng { return core::new_fuzz_rng(seed); }

fn test::advance_us(c: MockClock&, delta_us: i64) -> i64 { return core::advance_us(c, delta_us); }
fn test::advance_ms(c: MockClock&, delta_ms: i64) -> i64 { return core::advance_ms(c, delta_ms); }
fn test::advance_sec(c: MockClock&, delta_sec: i64) -> i64 { return core::advance_sec(c, delta_sec); }
fn test::advance_days(c: MockClock&, days: i64) -> i64 { return core::advance_days(c, days); }

fn test::run<F: fn(T&)>(t: T&, sub_name: const u8[:]) -> bool { return core::run(t, sub_name, F); }
fn test::run_table<Row, F: fn(T&, const Row&, i64)>(t: T&, table_name: const u8[:], rows: const Row[:]) -> bool { return core::run_table(t, table_name, rows, F); }
fn test::run_case<F: fn(T&)>(runner_ref: Runner&, case_name: const u8[:]) -> bool { return core::run_case(runner_ref, case_name, F); }
fn test::finish(runner_ref: const Runner&) -> bool { return core::finish(runner_ref); }

fn test::assert_true(t: T&, cond: bool, label: const u8[:] = "expected true") -> bool { return core::assert_true(t, cond, label); }
fn test::assert_false(t: T&, cond: bool, label: const u8[:] = "expected false") -> bool { return core::assert_false(t, cond, label); }
fn test::assert_ok(t: T&, ok_cond: bool, label: const u8[:] = "expected operation ok == true") -> bool { return core::assert_ok(t, ok_cond, label); }
fn test::assert_eq<Val>(t: T&, got: Val, want: Val, label: const u8[:] = "") -> bool { return core::assert_eq(t, got, want, label); }
fn test::assert_bytes_eq(t: T&, got: const u8[:], want: const u8[:], label: const u8[:] = "") -> bool { return core::assert_bytes_eq(t, got, want, label); }
fn test::assert_struct_eq<Val>(t: T&, got: const Val&, want: const Val&, label: const u8[:] = "") -> bool { return core::assert_struct_eq(t, got, want, label); }
fn test::assert_ne<Val>(t: T&, got: Val, want: Val, label: const u8[:] = "") -> bool { return core::assert_ne(t, got, want, label); }
fn test::assert_gt<Val>(t: T&, got: Val, bound: Val, label: const u8[:] = "") -> bool { return core::assert_gt(t, got, bound, label); }
fn test::assert_ge<Val>(t: T&, got: Val, bound: Val, label: const u8[:] = "") -> bool { return core::assert_ge(t, got, bound, label); }
fn test::assert_lt<Val>(t: T&, got: Val, bound: Val, label: const u8[:] = "") -> bool { return core::assert_lt(t, got, bound, label); }
fn test::assert_le<Val>(t: T&, got: Val, bound: Val, label: const u8[:] = "") -> bool { return core::assert_le(t, got, bound, label); }
fn test::assert_in_delta(t: T&, got: f64, want: f64, delta: f64, label: const u8[:] = "") -> bool { return core::assert_in_delta(t, got, want, delta, label); }
fn test::assert_contains(t: T&, haystack: const u8[:], needle: const u8[:], label: const u8[:] = "") -> bool { return core::assert_contains(t, haystack, needle, label); }
fn test::assert_not_contains(t: T&, haystack: const u8[:], needle: const u8[:], label: const u8[:] = "") -> bool { return core::assert_not_contains(t, haystack, needle, label); }
fn test::assert_elements_match<Val>(t: T&, a: const Val[:], b: const Val[:], label: const u8[:] = "") -> bool { return core::assert_elements_match(t, a, b, label); }

fn test::require_true(t: T&, cond: bool, label: const u8[:] = "required true") -> bool { return core::require_true(t, cond, label); }
fn test::require_false(t: T&, cond: bool, label: const u8[:] = "required false") -> bool { return core::require_false(t, cond, label); }
fn test::require_ok(t: T&, ok_cond: bool, label: const u8[:] = "required ok == true") -> bool { return core::require_ok(t, ok_cond, label); }
fn test::require_eq<Val>(t: T&, got: Val, want: Val, label: const u8[:] = "") -> bool { return core::require_eq(t, got, want, label); }
fn test::require_bytes_eq(t: T&, got: const u8[:], want: const u8[:], label: const u8[:] = "") -> bool { return core::require_bytes_eq(t, got, want, label); }
fn test::skip(t: T&, reason: const u8[:] = "") { core::skip(t, reason); }

// Global UFCS bridges for method-call syntax

fn ::run<F: fn(core::T&)>(t: core::T&, sub_name: const u8[:]) -> bool {
    return core::run(t, sub_name, F);
}

fn ::run_table<Row, F: fn(core::T&, const Row&, i64)>(t: core::T&, table_name: const u8[:], rows: const Row[:]) -> bool {
    return core::run_table(t, table_name, rows, F);
}

fn ::assert_true(t: core::T&, cond: bool, label: const u8[:] = "expected true") -> bool {
    return core::assert_true(t, cond, label);
}

fn ::assert_false(t: core::T&, cond: bool, label: const u8[:] = "expected false") -> bool {
    return core::assert_false(t, cond, label);
}

fn ::assert_ok(t: core::T&, ok_cond: bool, label: const u8[:] = "expected operation ok == true") -> bool {
    return core::assert_ok(t, ok_cond, label);
}

fn ::assert_eq<Val>(t: core::T&, got: Val, want: Val, label: const u8[:] = "") -> bool {
    return core::assert_eq(t, got, want, label);
}

fn ::assert_bytes_eq(t: core::T&, got: const u8[:], want: const u8[:], label: const u8[:] = "") -> bool {
    return core::assert_bytes_eq(t, got, want, label);
}

fn ::assert_struct_eq<Val>(t: core::T&, got: const Val&, want: const Val&, label: const u8[:] = "") -> bool {
    return core::assert_struct_eq(t, got, want, label);
}

fn ::assert_ne<Val>(t: core::T&, got: Val, want: Val, label: const u8[:] = "") -> bool {
    return core::assert_ne(t, got, want, label);
}

fn ::assert_gt<Val>(t: core::T&, got: Val, bound: Val, label: const u8[:] = "") -> bool {
    return core::assert_gt(t, got, bound, label);
}

fn ::assert_ge<Val>(t: core::T&, got: Val, bound: Val, label: const u8[:] = "") -> bool {
    return core::assert_ge(t, got, bound, label);
}

fn ::assert_lt<Val>(t: core::T&, got: Val, bound: Val, label: const u8[:] = "") -> bool {
    return core::assert_lt(t, got, bound, label);
}

fn ::assert_le<Val>(t: core::T&, got: Val, bound: Val, label: const u8[:] = "") -> bool {
    return core::assert_le(t, got, bound, label);
}

fn ::assert_in_delta(t: core::T&, got: f64, want: f64, delta: f64, label: const u8[:] = "") -> bool {
    return core::assert_in_delta(t, got, want, delta, label);
}

fn ::assert_contains(t: core::T&, haystack: const u8[:], needle: const u8[:], label: const u8[:] = "") -> bool {
    return core::assert_contains(t, haystack, needle, label);
}

fn ::assert_not_contains(t: core::T&, haystack: const u8[:], needle: const u8[:], label: const u8[:] = "") -> bool {
    return core::assert_not_contains(t, haystack, needle, label);
}

fn ::assert_elements_match<Val>(t: core::T&, a: const Val[:], b: const Val[:], label: const u8[:] = "") -> bool {
    return core::assert_elements_match(t, a, b, label);
}

fn ::require_true(t: core::T&, cond: bool, label: const u8[:] = "required true") -> bool {
    return core::require_true(t, cond, label);
}

fn ::require_false(t: core::T&, cond: bool, label: const u8[:] = "required false") -> bool {
    return core::require_false(t, cond, label);
}

fn ::require_ok(t: core::T&, ok_cond: bool, label: const u8[:] = "required ok == true") -> bool {
    return core::require_ok(t, ok_cond, label);
}

fn ::require_eq<Val>(t: core::T&, got: Val, want: Val, label: const u8[:] = "") -> bool {
    return core::require_eq(t, got, want, label);
}

fn ::require_bytes_eq(t: core::T&, got: const u8[:], want: const u8[:], label: const u8[:] = "") -> bool {
    return core::require_bytes_eq(t, got, want, label);
}

fn ::require_ne<Val>(t: core::T&, got: Val, want: Val, label: const u8[:] = "") -> bool {
    return core::require_ne(t, got, want, label);
}

fn ::require_gt<Val>(t: core::T&, got: Val, bound: Val, label: const u8[:] = "") -> bool {
    return core::require_gt(t, got, bound, label);
}

fn ::require_ge<Val>(t: core::T&, got: Val, bound: Val, label: const u8[:] = "") -> bool {
    return core::require_ge(t, got, bound, label);
}

fn ::require_lt<Val>(t: core::T&, got: Val, bound: Val, label: const u8[:] = "") -> bool {
    return core::require_lt(t, got, bound, label);
}

fn ::require_le<Val>(t: core::T&, got: Val, bound: Val, label: const u8[:] = "") -> bool {
    return core::require_le(t, got, bound, label);
}

fn ::skip(t: core::T&, reason: const u8[:] = "") {
    core::skip(t, reason);
}

fn ::is_failed(t: const core::T&) -> bool { return core::is_failed(t); }
fn ::is_ok(t: const core::T&) -> bool { return core::is_ok(t); }
fn ::is_passed(t: const core::T&) -> bool { return core::is_passed(t); }
fn ::is_aborted(t: const core::T&) -> bool { return core::is_aborted(t); }
fn ::is_skipped(t: const core::T&) -> bool { return core::is_skipped(t); }
fn ::count(t: const core::T&) -> i64 { return core::count(t); }
fn ::failures_len(t: const core::T&) -> i64 { return core::failures_len(t); }

fn ::run_case<F: fn(core::T&)>(runner_ref: core::Runner&, case_name: const u8[:]) -> bool {
    return core::run_case(runner_ref, case_name, F);
}

fn ::finish(runner_ref: const core::Runner&) -> bool {
    return core::finish(runner_ref);
}

fn ::advance_us(c: core::MockClock&, delta_us: i64) -> i64 { return core::advance_us(c, delta_us); }
fn ::advance_ms(c: core::MockClock&, delta_ms: i64) -> i64 { return core::advance_ms(c, delta_ms); }
fn ::advance_sec(c: core::MockClock&, delta_sec: i64) -> i64 { return core::advance_sec(c, delta_sec); }
fn ::advance_days(c: core::MockClock&, days: i64) -> i64 { return core::advance_days(c, days); }

fn ::next_u64(rng: core::FuzzRng&) -> u64 { return core::next_u64(rng); }
fn ::next_range(rng: core::FuzzRng&, min_val: i64, max_exclusive: i64) -> i64 { return core::next_range(rng, min_val, max_exclusive); }
fn ::next_bool(rng: core::FuzzRng&) -> bool { return core::next_bool(rng); }
fn ::next_ascii_string<B>(rng: core::FuzzRng&, out: B&, length: i64) { core::next_ascii_string(rng, out, length); }
