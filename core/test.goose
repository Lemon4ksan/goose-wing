// The Goose standard test library: candidate for `std::test`.
//
// Core Types:
//   T          - Test execution context and bounded failure diagnostics collector.
//   Runner     - Test suite lifecycle coordinator, timing reporter, and accumulator.
//   Failure    - Diagnostic record containing subtest name, summary, and structural diff.
//   Verbosity  - Suite reporting level enum (Silent, Normal, Verbose, Golden).
//   MockClock  - High-resolution deterministic virtual clock (microsecond scale).
//   FuzzRng    - Zero-allocation deterministic PRNG (Xorshift64*) for property fuzzing.
//   CallRecord - Typed spy and stub recording invocation count and canned return values.
//
// Standards & Specifications:
//   Go testify (assert, require, suite, mock) idioms adapted for Goose zero-heap model.
//   Compile-time structural diffing via `const for <N, A> in fields<T>`.
//   Deterministic golden output mode for reproducible bit-for-bit test runners.
//   Chromium CookieMonster and WPT test harness patterns.
namespace wing;

import std;
import os;
import core.time;

// ---- verbosity enum & failure diagnostics -----------------------------------

enum Verbosity {
    Silent,   // Only print failed tests and summary
    Normal,   // Print suite status and final summary
    Verbose,  // Detailed output for each test and subtest with timings
    Golden,   // Deterministic output without microsecond timings for .out comparisons
}

struct Failure {
    subtest: u8[..128] = [],
    summary: u8[..128] = [],
    detail: u8[..512] = [],
}

// ---- test context (T) & suite runner ---------------------------------------

struct T {
    name: u8[..128] = [],
    failed: bool = false,
    aborted: bool = false,
    skipped: bool = false,
    assertions_count: i64 = 0,
    failures_count: i64 = 0,
    failures: Failure[..64] = [],
    watch: Stopwatch = Stopwatch { start_ns: 0 },
    level: i64 = 0,
}

struct Runner {
    suite_name: u8[..128] = [],
    total_tests: i64 = 0,
    passed_tests: i64 = 0,
    failed_tests: i64 = 0,
    skipped_tests: i64 = 0,
    total_assertions: i64 = 0,
    total_failures: i64 = 0,
    verbosity: Verbosity = Verbosity.Normal,
    watch: Stopwatch = Stopwatch { start_ns: 0 },
}

// Constructors

fn new_runner(suite_name: const u8[:], verbosity: Verbosity = Verbosity.Normal) -> Runner {
    var r = Runner {
        suite_name: [],
        total_tests: 0,
        passed_tests: 0,
        failed_tests: 0,
        skipped_tests: 0,
        total_assertions: 0,
        total_failures: 0,
        verbosity: verbosity,
        watch: stopwatch(),
    };
    r.suite_name.append(suite_name);
    return r;
}

fn new_test(name: const u8[:], level: i64 = 0) -> T {
    var t = T {
        name: [],
        failed: false,
        aborted: false,
        skipped: false,
        assertions_count: 0,
        failures_count: 0,
        failures: [Failure { .. }; 0],
        watch: stopwatch(),
        level: level,
    };
    t.name.append(name);
    return t;
}

// Diagnostics registration

fn record_failure<B1, B2>(t: T&, summary: B1, detail: B2) {
    t.failed = true;
    t.failures_count += 1;
    if t.failures.len < t.failures.cap {
        var entry = Failure { .. };
        let name_slice = if t.name.len > entry.subtest.cap { t.name[..entry.subtest.cap] } else { t.name[..] };
        entry.subtest.append(name_slice);
        format(entry.summary, summary);
        format(entry.detail, detail);
        t.failures.push(entry);
    }
}

fn fail_now<B1, B2>(t: T&, summary: B1, detail: B2) {
    record_failure(t, summary, detail);
    t.aborted = true;
}

fn skip(t: T&, reason: const u8[:] = "") {
    t.skipped = true;
    t.aborted = true;
}

// Predicates

fn failed(t: const T&) -> bool { return t.failed; }
fn is_failed(t: const T&) -> bool { return failed(t); }
fn ok(t: const T&) -> bool { return !t.failed; }
fn is_ok(t: const T&) -> bool { return ok(t); }
fn passed(t: const T&) -> bool { return !t.failed && !t.skipped; }
fn is_passed(t: const T&) -> bool { return passed(t); }
fn aborted(t: const T&) -> bool { return t.aborted; }
fn is_aborted(t: const T&) -> bool { return aborted(t); }
fn skipped(t: const T&) -> bool { return t.skipped; }
fn is_skipped(t: const T&) -> bool { return skipped(t); }
fn count(t: const T&) -> i64 { return t.assertions_count; }
fn failures_len(t: const T&) -> i64 { return t.failures_count; }

// ---- virtual clock (MockClock) & property fuzzer (FuzzRng) -----------------

struct MockClock {
    now_us: i64 = 1700000000000000, // Deterministic epoch instant in microseconds
}

fn new_mock_clock(initial_us: i64 = 1700000000000000) -> MockClock {
    return MockClock { now_us: initial_us };
}

fn advance_us(clock: MockClock&, delta_us: i64) -> i64 {
    clock.now_us += delta_us;
    return clock.now_us;
}

fn advance_ms(clock: MockClock&, delta_ms: i64) -> i64 {
    clock.now_us += delta_ms * 1000;
    return clock.now_us;
}

fn advance_sec(clock: MockClock&, delta_sec: i64) -> i64 {
    clock.now_us += delta_sec * 1000000;
    return clock.now_us;
}

fn advance_days(clock: MockClock&, days: i64) -> i64 {
    clock.now_us += days * 86400000000;
    return clock.now_us;
}

fn monotonic_now(clock: const MockClock&) -> MonotonicInstant {
    let ns = if clock.now_us > 0 { (clock.now_us as u64) * 1000 } else { 0 as u64 };
    return MonotonicInstant { nanos: ns };
}

// Nanosecond-precision deterministic monotonic clock for GCRA and sub-microsecond tests
struct MockMonoClock {
    now_ns: u64 = 1000000000,
}

fn new_mock_mono_clock(initial_ns: u64 = 1000000000) -> MockMonoClock {
    return MockMonoClock { now_ns: initial_ns };
}

fn advance_ns(clock: MockMonoClock&, delta_ns: u64) -> u64 {
    clock.now_ns += delta_ns;
    return clock.now_ns;
}

fn advance_us(clock: MockMonoClock&, delta_us: u64) -> u64 {
    clock.now_ns += delta_us * 1000;
    return clock.now_ns;
}

fn advance_ms(clock: MockMonoClock&, delta_ms: u64) -> u64 {
    clock.now_ns += delta_ms * 1000000;
    return clock.now_ns;
}

fn advance_sec(clock: MockMonoClock&, delta_sec: u64) -> u64 {
    clock.now_ns += delta_sec * 1000000000;
    return clock.now_ns;
}

fn now(clock: const MockMonoClock&) -> MonotonicInstant {
    return MonotonicInstant { nanos: clock.now_ns };
}

fn monotonic_now(clock: const MockMonoClock&) -> MonotonicInstant {
    return MonotonicInstant { nanos: clock.now_ns };
}

// Deterministic Xorshift64* generator for zero-allocation property fuzzing
struct FuzzRng {
    state: u64 = 0x853c49e6748fea9b,
}

fn new_fuzz_rng(seed: u64 = 0x853c49e6748fea9b) -> FuzzRng {
    let initial_state = if seed == 0 { 0x853c49e6748fea9b } else { seed };
    return FuzzRng { state: initial_state };
}

fn next_u64(rng: FuzzRng&) -> u64 {
    var x = rng.state;
    x ^= x >> 12;
    x ^= x << 25;
    x ^= x >> 27;
    rng.state = x;
    return x * 0x2545F4914F6CDD1D;
}

fn next_range(rng: FuzzRng&, min_val: i64, max_exclusive: i64) -> i64 {
    if max_exclusive <= min_val { return min_val; }
    let span = (max_exclusive - min_val) as u64;
    return min_val + ((next_u64(rng) % span) as i64);
}

fn next_bool(rng: FuzzRng&) -> bool {
    return (next_u64(rng) & 1) == 1;
}

fn next_ascii_string<B>(rng: FuzzRng&, out: B&, length: i64) {
    let chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-";
    for i in length {
        let idx = (next_u64(rng) % 64) as i64;
        out.push(chars[idx]);
    }
}

// ---- typed test spies & stubs (CallRecord) ---------------------------------

struct CallRecord<Args, Ret> {
    call_count: i64 = 0,
    last_args: Args,
    canned_return: Ret,
}

fn spy<Args, Ret>(canned: Ret) -> CallRecord<Args, Ret> {
    return CallRecord<Args, Ret> {
        call_count: 0,
        last_args: Args { .. },
        canned_return: canned,
    };
}

fn record_call<Args, Ret>(spy_ref: CallRecord<Args, Ret>&, args: Args) -> Ret {
    spy_ref.call_count += 1;
    spy_ref.last_args = copy(args);
    return copy(spy_ref.canned_return);
}

fn reset_spy<Args, Ret>(spy_ref: CallRecord<Args, Ret>&) {
    spy_ref.call_count = 0;
}

// ---- compile-time structural diff & byte hex-dump --------------------------

fn append_hex_byte<B>(out: B&, b: u8) {
    let hex_chars = "0123456789ABCDEF";
    out.push(hex_chars[(b >> 4) as i64]);
    out.push(hex_chars[(b & 0x0F) as i64]);
}

// Byte slice differ displaying first mismatch index, hex dump, and ASCII context
fn format_bytes_diff<B>(out: B&, got: const u8[:], want: const u8[:]) {
    out.append("  len: got ");
    format(out, got.len, ", want ", want.len, "\n");
    let min_len = if got.len < want.len { got.len } else { want.len };
    var diff_idx = -1;
    for i in min_len {
        if got[i] != want[i] {
            diff_idx = i;
            break;
        }
    }
    if diff_idx < 0 && got.len != want.len {
        diff_idx = min_len;
    }
    if diff_idx >= 0 {
        format(out, "  first mismatch at byte [", diff_idx, "]:");
        if diff_idx < got.len {
            out.append(" got 0x");
            append_hex_byte(out, got[diff_idx]);
        } else {
            out.append(" got <EOF>");
        }
        if diff_idx < want.len {
            out.append(", want 0x");
            append_hex_byte(out, want[diff_idx]);
        } else {
            out.append(", want <EOF>");
        }
        out.push('\n');
    }
    format(out, "  got:  \"", got, "\"\n  want: \"", want, "\"");
}

// Compile-time struct diff engine utilizing `const for <N, A> in fields<Val>`
fn diff_struct_fields<Val, B>(out: B&, got: const Val&, want: const Val&) -> bool {
    var has_diff = false;
    const for <N, A> in fields<Val> {
        if got.A != want.A {
            has_diff = true;
            out.append("  field '");
            out.append(N);
            out.append("': got ");
            format(out, got.A);
            out.append(", want ");
            format(out, want.A);
            out.push('\n');
        }
    }
    return has_diff;
}

// ---- soft assertions (assert_*) --------------------------------------------

fn assert_true(t: T&, cond: bool, label: const u8[:] = "expected true") -> bool {
    if t.aborted { return false; }
    t.assertions_count += 1;
    if !cond {
        record_failure(t, "assert_true failed", label);
        return false;
    }
    return true;
}

fn assert_false(t: T&, cond: bool, label: const u8[:] = "expected false") -> bool {
    if t.aborted { return false; }
    t.assertions_count += 1;
    if cond {
        record_failure(t, "assert_false failed", label);
        return false;
    }
    return true;
}

fn assert_ok(t: T&, ok_cond: bool, label: const u8[:] = "expected operation ok == true") -> bool {
    return assert_true(t, ok_cond, label);
}

fn assert_eq<Val>(t: T&, got: Val, want: Val, label: const u8[:] = "") -> bool {
    if t.aborted { return false; }
    t.assertions_count += 1;
    if got != want {
        var det: u8[..512] = [];
        if label.len > 0 { format(det, label, "\n"); }
        format(det, "  got:  ", got, "\n  want: ", want);
        record_failure(t, "assert_eq mismatch", det[..]);
        return false;
    }
    return true;
}

fn assert_bytes_eq(t: T&, got: const u8[:], want: const u8[:], label: const u8[:] = "") -> bool {
    if t.aborted { return false; }
    t.assertions_count += 1;
    if got != want {
        var det: u8[..512] = [];
        if label.len > 0 { format(det, label, "\n"); }
        format_bytes_diff(det, got, want);
        record_failure(t, "assert_bytes_eq mismatch", det[..]);
        return false;
    }
    return true;
}

fn assert_struct_eq<Val>(t: T&, got: const Val&, want: const Val&, label: const u8[:] = "") -> bool {
    if t.aborted { return false; }
    t.assertions_count += 1;
    var det: u8[..512] = [];
    if label.len > 0 { format(det, label, "\n"); }
    if diff_struct_fields(det, got, want) {
        record_failure(t, "assert_struct_eq field mismatch", det[..]);
        return false;
    }
    return true;
}

fn assert_ne<Val>(t: T&, got: Val, want: Val, label: const u8[:] = "") -> bool {
    if t.aborted { return false; }
    t.assertions_count += 1;
    if got == want {
        var det: u8[..512] = [];
        if label.len > 0 { format(det, label, ": "); }
        format(det, "both values equal ", got);
        record_failure(t, "assert_ne violated", det[..]);
        return false;
    }
    return true;
}

fn assert_gt<Val>(t: T&, got: Val, bound: Val, label: const u8[:] = "") -> bool {
    if t.aborted { return false; }
    t.assertions_count += 1;
    if !(got > bound) {
        var det: u8[..256] = [];
        format(det, label, " expected ", got, " > ", bound);
        record_failure(t, "assert_gt failed", det[..]);
        return false;
    }
    return true;
}

fn assert_ge<Val>(t: T&, got: Val, bound: Val, label: const u8[:] = "") -> bool {
    if t.aborted { return false; }
    t.assertions_count += 1;
    if !(got >= bound) {
        var det: u8[..256] = [];
        format(det, label, " expected ", got, " >= ", bound);
        record_failure(t, "assert_ge failed", det[..]);
        return false;
    }
    return true;
}

fn assert_lt<Val>(t: T&, got: Val, bound: Val, label: const u8[:] = "") -> bool {
    if t.aborted { return false; }
    t.assertions_count += 1;
    if !(got < bound) {
        var det: u8[..256] = [];
        format(det, label, " expected ", got, " < ", bound);
        record_failure(t, "assert_lt failed", det[..]);
        return false;
    }
    return true;
}

fn assert_le<Val>(t: T&, got: Val, bound: Val, label: const u8[:] = "") -> bool {
    if t.aborted { return false; }
    t.assertions_count += 1;
    if !(got <= bound) {
        var det: u8[..256] = [];
        format(det, label, " expected ", got, " <= ", bound);
        record_failure(t, "assert_le failed", det[..]);
        return false;
    }
    return true;
}

fn assert_in_delta(t: T&, got: f64, want: f64, delta: f64, label: const u8[:] = "") -> bool {
    if t.aborted { return false; }
    t.assertions_count += 1;
    let diff = ::abs(got - want);
    if diff > delta {
        var det: u8[..256] = [];
        format(det, label, "\n  got: ", got, ", want: ", want, " (|diff|=", diff, " > ", delta, ")");
        record_failure(t, "assert_in_delta exceeded", det[..]);
        return false;
    }
    return true;
}

fn assert_contains(t: T&, haystack: const u8[:], needle: const u8[:], label: const u8[:] = "") -> bool {
    if t.aborted { return false; }
    t.assertions_count += 1;
    if find(haystack, needle) < 0 {
        var det: u8[..512] = [];
        format(det, label, "\n  haystack: \"", haystack, "\"\n  missing:  \"", needle, "\"");
        record_failure(t, "assert_contains failed", det[..]);
        return false;
    }
    return true;
}

fn assert_not_contains(t: T&, haystack: const u8[:], needle: const u8[:], label: const u8[:] = "") -> bool {
    if t.aborted { return false; }
    t.assertions_count += 1;
    if find(haystack, needle) >= 0 {
        var det: u8[..512] = [];
        format(det, label, "\n  haystack:  \"", haystack, "\"\n  forbidden: \"", needle, "\"");
        record_failure(t, "assert_not_contains failed", det[..]);
        return false;
    }
    return true;
}

// Multiset element matching without order dependency (Zero-Heap, bounded to 256 elements)
fn assert_elements_match<Val>(t: T&, a: const Val[:], b: const Val[:], label: const u8[:] = "") -> bool {
    if t.aborted { return false; }
    t.assertions_count += 1;
    if a.len != b.len || b.len > 256 {
        var det: u8[..256] = [];
        format(det, label, " length mismatch: a.len=", a.len, ", b.len=", b.len);
        record_failure(t, "assert_elements_match failed", det[..]);
        return false;
    }
    var used: bool[..256] = [];
    for i in b.len { used.push(false); }

    for i in a.len {
        var found = false;
        for j in b.len {
            if !used[j] && a[i] == b[j] {
                used[j] = true;
                found = true;
                break;
            }
        }
        if !found {
            var det: u8[..256] = [];
            format(det, label, " element at a[", i, "] = ", a[i], " has no unmatched counterpart in b");
            record_failure(t, "assert_elements_match mismatch", det[..]);
            return false;
        }
    }
    return true;
}

// ---- hard assertions (require_*) -------------------------------------------

fn require_true(t: T&, cond: bool, label: const u8[:] = "required true") -> bool {
    if !assert_true(t, cond, label) {
        t.aborted = true;
        return false;
    }
    return true;
}

fn require_false(t: T&, cond: bool, label: const u8[:] = "required false") -> bool {
    if !assert_false(t, cond, label) {
        t.aborted = true;
        return false;
    }
    return true;
}

fn require_ok(t: T&, ok_cond: bool, label: const u8[:] = "required ok == true") -> bool {
    return require_true(t, ok_cond, label);
}

fn require_eq<Val>(t: T&, got: Val, want: Val, label: const u8[:] = "") -> bool {
    if !assert_eq(t, got, want, label) {
        t.aborted = true;
        return false;
    }
    return true;
}

fn require_bytes_eq(t: T&, got: const u8[:], want: const u8[:], label: const u8[:] = "") -> bool {
    if !assert_bytes_eq(t, got, want, label) {
        t.aborted = true;
        return false;
    }
    return true;
}

fn require_ne<Val>(t: T&, got: Val, want: Val, label: const u8[:] = "") -> bool {
    if !assert_ne(t, got, want, label) {
        t.aborted = true;
        return false;
    }
    return true;
}

fn require_gt<Val>(t: T&, got: Val, bound: Val, label: const u8[:] = "") -> bool {
    if !assert_gt(t, got, bound, label) {
        t.aborted = true;
        return false;
    }
    return true;
}

fn require_ge<Val>(t: T&, got: Val, bound: Val, label: const u8[:] = "") -> bool {
    if !assert_ge(t, got, bound, label) {
        t.aborted = true;
        return false;
    }
    return true;
}

fn require_lt<Val>(t: T&, got: Val, bound: Val, label: const u8[:] = "") -> bool {
    if !assert_lt(t, got, bound, label) {
        t.aborted = true;
        return false;
    }
    return true;
}

fn require_le<Val>(t: T&, got: Val, bound: Val, label: const u8[:] = "") -> bool {
    if !assert_le(t, got, bound, label) {
        t.aborted = true;
        return false;
    }
    return true;
}

// ---- subtest execution, table runner & suite lifecycle ---------------------

fn run<F: fn(T&)>(test_context: T&, sub_name: const u8[:]) -> bool {
    if test_context.aborted { return false; }
    var subs = [new_test(sub_name, test_context.level + 1)];
    for &sub in subs {
        F(sub);
    }
    let sub = subs[0];
    test_context.assertions_count += sub.assertions_count;
    if sub.failed {
        test_context.failed = true;
        test_context.failures_count += sub.failures_count;
        for fail_idx in sub.failures.len {
            if test_context.failures.len < test_context.failures.cap {
                test_context.failures.push(sub.failures[fail_idx]);
            }
        }
    }
    return !sub.failed;
}

// Table-driven test runner
fn run_table<Row, F: fn(T&, const Row&, i64)>(
    test_context: T&,
    table_name: const u8[:],
    rows: const Row[:]
) -> bool {
    if test_context.aborted { return false; }
    var all_ok = true;
    for row_idx in rows.len {
        var row_title: u8[..128] = [];
        format(row_title, table_name, "[#", row_idx, "]");
        var subs = [new_test(row_title[..], test_context.level + 1)];
        for &sub in subs {
            F(sub, rows[row_idx], row_idx);
        }
        let sub = subs[0];
        test_context.assertions_count += sub.assertions_count;
        if sub.failed {
            all_ok = false;
            test_context.failed = true;
            test_context.failures_count += sub.failures_count;
            for fail_idx in sub.failures.len {
                if test_context.failures.len < test_context.failures.cap {
                    test_context.failures.push(sub.failures[fail_idx]);
                }
            }
        }
    }
    return all_ok;
}

fn run_case<F: fn(T&)>(runner_ref: Runner&, case_name: const u8[:]) -> bool {
    runner_ref.total_tests += 1;
    var test_context = new_test(case_name, 0);
    F(test_context);
    runner_ref.total_assertions += test_context.assertions_count;
    runner_ref.total_failures += test_context.failures_count;

    if test_context.skipped {
        runner_ref.skipped_tests += 1;
        if runner_ref.verbosity == Verbosity.Verbose || runner_ref.verbosity == Verbosity.Golden {
            print("  [SKIP] ", test_context.name[..]);
        }
        return true;
    }

    let elapsed_duration = elapsed(test_context.watch);
    if !test_context.failed {
        runner_ref.passed_tests += 1;
        if runner_ref.verbosity == Verbosity.Verbose {
            print("  [PASS] ", test_context.name[..], " (", test_context.assertions_count, " checks in ", elapsed_duration.as_micros(), " us)");
        } else if runner_ref.verbosity == Verbosity.Golden {
            print("  [PASS] ", test_context.name[..], " (", test_context.assertions_count, " checks)");
        }
        return true;
    } else {
        runner_ref.failed_tests += 1;
        print("  [FAIL] ", test_context.name[..], " (failed ", test_context.failures_count, " of ", test_context.assertions_count, " checks):");
        for fail_idx in test_context.failures.len {
            print("    #", fail_idx + 1, " [", test_context.failures[fail_idx].subtest[..], "] ", test_context.failures[fail_idx].summary[..]);
            if test_context.failures[fail_idx].detail.len > 0 {
                print(test_context.failures[fail_idx].detail[..]);
            }
        }
        return false;
    }
}

fn finish(runner_ref: const Runner&) -> bool {
    let total_duration = elapsed(runner_ref.watch);
    if runner_ref.verbosity != Verbosity.Silent || runner_ref.failed_tests > 0 {
        print("----------------------------------------------------------------------------");
        if runner_ref.verbosity == Verbosity.Golden {
            print("SUITE: ", runner_ref.suite_name[..], " | PASS: ", runner_ref.passed_tests, "/", runner_ref.total_tests,
                  " | FAIL: ", runner_ref.failed_tests, " | CHECKS: ", runner_ref.total_assertions);
        } else {
            print("SUITE: ", runner_ref.suite_name[..], " | PASS: ", runner_ref.passed_tests, "/", runner_ref.total_tests,
                  " | FAIL: ", runner_ref.failed_tests, " | CHECKS: ", runner_ref.total_assertions,
                  " | TIME: ", total_duration.as_micros(), " us");
        }
        print("----------------------------------------------------------------------------");
    }
    return runner_ref.failed_tests == 0;
}

// ---- format hooks for std::print / std::format -----------------------------

fn format<B>(out: B&, v: Verbosity) {
    match v {
        Silent => out.append("Silent"),
        Normal => out.append("Normal"),
        Verbose => out.append("Verbose"),
        Golden => out.append("Golden"),
    };
}

fn format<B>(out: B&, f: const Failure&) {
    if f.subtest.len > 0 {
        format(out, "[", f.subtest[..], "] ");
    }
    format(out, f.summary[..]);
    if f.detail.len > 0 {
        format(out, "\n", f.detail[..]);
    }
}

fn format<B>(out: B&, t: const T&) {
    format(out, "Test(", t.name[..], ", failed=", t.failed, ", assertions=", t.assertions_count, ")");
}

fn format<B>(out: B&, r: const Runner&) {
    format(out, "Suite(", r.suite_name[..], ", passed=", r.passed_tests, "/", r.total_tests, ", failed=", r.failed_tests, ")");
}

// ---- backward-compatibility aliases & std::test namespace bridges ----------

type test::T = wing::T;
type test::Runner = wing::Runner;
type test::Failure = wing::Failure;
type test::Verbosity = wing::Verbosity;
type test::MockClock = wing::MockClock;
type test::FuzzRng = wing::FuzzRng;

fn test::new_runner(suite_name: const u8[:], verbosity: Verbosity = Verbosity.Normal) -> Runner { return wing::new_runner(suite_name, verbosity); }
fn test::new_test(name: const u8[:], level: i64 = 0) -> T { return wing::new_test(name, level); }
fn test::new_mock_clock(initial_us: i64 = 1700000000000000) -> MockClock { return wing::new_mock_clock(initial_us); }
fn test::new_fuzz_rng(seed: u64 = 0x853c49e6748fea9b) -> FuzzRng { return wing::new_fuzz_rng(seed); }

fn test::advance_us(c: MockClock&, delta_us: i64) -> i64 { return wing::advance_us(c, delta_us); }
fn test::advance_ms(c: MockClock&, delta_ms: i64) -> i64 { return wing::advance_ms(c, delta_ms); }
fn test::advance_sec(c: MockClock&, delta_sec: i64) -> i64 { return wing::advance_sec(c, delta_sec); }
fn test::advance_days(c: MockClock&, days: i64) -> i64 { return wing::advance_days(c, days); }

fn test::run<F: fn(T&)>(t: T&, sub_name: const u8[:]) -> bool { return wing::run(t, sub_name, F); }
fn test::run_table<Row, F: fn(T&, const Row&, i64)>(t: T&, table_name: const u8[:], rows: const Row[:]) -> bool { return wing::run_table(t, table_name, rows, F); }
fn test::run_case<F: fn(T&)>(runner_ref: Runner&, case_name: const u8[:]) -> bool { return wing::run_case(runner_ref, case_name, F); }
fn test::finish(runner_ref: const Runner&) -> bool { return wing::finish(runner_ref); }

fn test::assert_true(t: T&, cond: bool, label: const u8[:] = "expected true") -> bool { return wing::assert_true(t, cond, label); }
fn test::assert_false(t: T&, cond: bool, label: const u8[:] = "expected false") -> bool { return wing::assert_false(t, cond, label); }
fn test::assert_ok(t: T&, ok_cond: bool, label: const u8[:] = "expected operation ok == true") -> bool { return wing::assert_ok(t, ok_cond, label); }
fn test::assert_eq<Val>(t: T&, got: Val, want: Val, label: const u8[:] = "") -> bool { return wing::assert_eq(t, got, want, label); }
fn test::assert_bytes_eq(t: T&, got: const u8[:], want: const u8[:], label: const u8[:] = "") -> bool { return wing::assert_bytes_eq(t, got, want, label); }
fn test::assert_struct_eq<Val>(t: T&, got: const Val&, want: const Val&, label: const u8[:] = "") -> bool { return wing::assert_struct_eq(t, got, want, label); }
fn test::assert_ne<Val>(t: T&, got: Val, want: Val, label: const u8[:] = "") -> bool { return wing::assert_ne(t, got, want, label); }
fn test::assert_gt<Val>(t: T&, got: Val, bound: Val, label: const u8[:] = "") -> bool { return wing::assert_gt(t, got, bound, label); }
fn test::assert_ge<Val>(t: T&, got: Val, bound: Val, label: const u8[:] = "") -> bool { return wing::assert_ge(t, got, bound, label); }
fn test::assert_lt<Val>(t: T&, got: Val, bound: Val, label: const u8[:] = "") -> bool { return wing::assert_lt(t, got, bound, label); }
fn test::assert_le<Val>(t: T&, got: Val, bound: Val, label: const u8[:] = "") -> bool { return wing::assert_le(t, got, bound, label); }
fn test::assert_in_delta(t: T&, got: f64, want: f64, delta: f64, label: const u8[:] = "") -> bool { return wing::assert_in_delta(t, got, want, delta, label); }
fn test::assert_contains(t: T&, haystack: const u8[:], needle: const u8[:], label: const u8[:] = "") -> bool { return wing::assert_contains(t, haystack, needle, label); }
fn test::assert_not_contains(t: T&, haystack: const u8[:], needle: const u8[:], label: const u8[:] = "") -> bool { return wing::assert_not_contains(t, haystack, needle, label); }
fn test::assert_elements_match<Val>(t: T&, a: const Val[:], b: const Val[:], label: const u8[:] = "") -> bool { return wing::assert_elements_match(t, a, b, label); }

fn test::require_true(t: T&, cond: bool, label: const u8[:] = "required true") -> bool { return wing::require_true(t, cond, label); }
fn test::require_false(t: T&, cond: bool, label: const u8[:] = "required false") -> bool { return wing::require_false(t, cond, label); }
fn test::require_ok(t: T&, ok_cond: bool, label: const u8[:] = "required ok == true") -> bool { return wing::require_ok(t, ok_cond, label); }
fn test::require_eq<Val>(t: T&, got: Val, want: Val, label: const u8[:] = "") -> bool { return wing::require_eq(t, got, want, label); }
fn test::require_bytes_eq(t: T&, got: const u8[:], want: const u8[:], label: const u8[:] = "") -> bool { return wing::require_bytes_eq(t, got, want, label); }
fn test::skip(t: T&, reason: const u8[:] = "") { wing::skip(t, reason); }

// ---- global UFCS bridges for method-call syntax ----------------------------

fn ::run<F: fn(wing::T&)>(t: wing::T&, sub_name: const u8[:]) -> bool {
    return wing::run(t, sub_name, F);
}

fn ::run_table<Row, F: fn(wing::T&, const Row&, i64)>(t: wing::T&, table_name: const u8[:], rows: const Row[:]) -> bool {
    return wing::run_table(t, table_name, rows, F);
}

fn ::assert_true(t: wing::T&, cond: bool, label: const u8[:] = "expected true") -> bool {
    return wing::assert_true(t, cond, label);
}

fn ::assert_false(t: wing::T&, cond: bool, label: const u8[:] = "expected false") -> bool {
    return wing::assert_false(t, cond, label);
}

fn ::assert_ok(t: wing::T&, ok_cond: bool, label: const u8[:] = "expected operation ok == true") -> bool {
    return wing::assert_ok(t, ok_cond, label);
}

fn ::assert_eq<Val>(t: wing::T&, got: Val, want: Val, label: const u8[:] = "") -> bool {
    return wing::assert_eq(t, got, want, label);
}

fn ::assert_bytes_eq(t: wing::T&, got: const u8[:], want: const u8[:], label: const u8[:] = "") -> bool {
    return wing::assert_bytes_eq(t, got, want, label);
}

fn ::assert_struct_eq<Val>(t: wing::T&, got: const Val&, want: const Val&, label: const u8[:] = "") -> bool {
    return wing::assert_struct_eq(t, got, want, label);
}

fn ::assert_ne<Val>(t: wing::T&, got: Val, want: Val, label: const u8[:] = "") -> bool {
    return wing::assert_ne(t, got, want, label);
}

fn ::assert_gt<Val>(t: wing::T&, got: Val, bound: Val, label: const u8[:] = "") -> bool {
    return wing::assert_gt(t, got, bound, label);
}

fn ::assert_ge<Val>(t: wing::T&, got: Val, bound: Val, label: const u8[:] = "") -> bool {
    return wing::assert_ge(t, got, bound, label);
}

fn ::assert_lt<Val>(t: wing::T&, got: Val, bound: Val, label: const u8[:] = "") -> bool {
    return wing::assert_lt(t, got, bound, label);
}

fn ::assert_le<Val>(t: wing::T&, got: Val, bound: Val, label: const u8[:] = "") -> bool {
    return wing::assert_le(t, got, bound, label);
}

fn ::assert_in_delta(t: wing::T&, got: f64, want: f64, delta: f64, label: const u8[:] = "") -> bool {
    return wing::assert_in_delta(t, got, want, delta, label);
}

fn ::assert_contains(t: wing::T&, haystack: const u8[:], needle: const u8[:], label: const u8[:] = "") -> bool {
    return wing::assert_contains(t, haystack, needle, label);
}

fn ::assert_not_contains(t: wing::T&, haystack: const u8[:], needle: const u8[:], label: const u8[:] = "") -> bool {
    return wing::assert_not_contains(t, haystack, needle, label);
}

fn ::assert_elements_match<Val>(t: wing::T&, a: const Val[:], b: const Val[:], label: const u8[:] = "") -> bool {
    return wing::assert_elements_match(t, a, b, label);
}

fn ::require_true(t: wing::T&, cond: bool, label: const u8[:] = "required true") -> bool {
    return wing::require_true(t, cond, label);
}

fn ::require_false(t: wing::T&, cond: bool, label: const u8[:] = "required false") -> bool {
    return wing::require_false(t, cond, label);
}

fn ::require_ok(t: wing::T&, ok_cond: bool, label: const u8[:] = "required ok == true") -> bool {
    return wing::require_ok(t, ok_cond, label);
}

fn ::require_eq<Val>(t: wing::T&, got: Val, want: Val, label: const u8[:] = "") -> bool {
    return wing::require_eq(t, got, want, label);
}

fn ::require_bytes_eq(t: wing::T&, got: const u8[:], want: const u8[:], label: const u8[:] = "") -> bool {
    return wing::require_bytes_eq(t, got, want, label);
}

fn ::require_ne<Val>(t: wing::T&, got: Val, want: Val, label: const u8[:] = "") -> bool {
    return wing::require_ne(t, got, want, label);
}

fn ::require_gt<Val>(t: wing::T&, got: Val, bound: Val, label: const u8[:] = "") -> bool {
    return wing::require_gt(t, got, bound, label);
}

fn ::require_ge<Val>(t: wing::T&, got: Val, bound: Val, label: const u8[:] = "") -> bool {
    return wing::require_ge(t, got, bound, label);
}

fn ::require_lt<Val>(t: wing::T&, got: Val, bound: Val, label: const u8[:] = "") -> bool {
    return wing::require_lt(t, got, bound, label);
}

fn ::require_le<Val>(t: wing::T&, got: Val, bound: Val, label: const u8[:] = "") -> bool {
    return wing::require_le(t, got, bound, label);
}

fn ::skip(t: wing::T&, reason: const u8[:] = "") {
    wing::skip(t, reason);
}

fn ::failed(t: const wing::T&) -> bool { return wing::failed(t); }
fn ::is_failed(t: const wing::T&) -> bool { return wing::is_failed(t); }
fn ::ok(t: const wing::T&) -> bool { return wing::ok(t); }
fn ::is_ok(t: const wing::T&) -> bool { return wing::is_ok(t); }
fn ::passed(t: const wing::T&) -> bool { return wing::passed(t); }
fn ::is_passed(t: const wing::T&) -> bool { return wing::is_passed(t); }
fn ::aborted(t: const wing::T&) -> bool { return wing::aborted(t); }
fn ::is_aborted(t: const wing::T&) -> bool { return wing::is_aborted(t); }
fn ::skipped(t: const wing::T&) -> bool { return wing::skipped(t); }
fn ::is_skipped(t: const wing::T&) -> bool { return wing::is_skipped(t); }
fn ::count(t: const wing::T&) -> i64 { return wing::count(t); }
fn ::failures_len(t: const wing::T&) -> i64 { return wing::failures_len(t); }

fn ::run_case<F: fn(wing::T&)>(runner_ref: wing::Runner&, case_name: const u8[:]) -> bool {
    return wing::run_case(runner_ref, case_name, F);
}

fn ::finish(runner_ref: const wing::Runner&) -> bool {
    return wing::finish(runner_ref);
}

fn ::advance_us(c: wing::MockClock&, delta_us: i64) -> i64 { return wing::advance_us(c, delta_us); }
fn ::advance_ms(c: wing::MockClock&, delta_ms: i64) -> i64 { return wing::advance_ms(c, delta_ms); }
fn ::advance_sec(c: wing::MockClock&, delta_sec: i64) -> i64 { return wing::advance_sec(c, delta_sec); }
fn ::advance_days(c: wing::MockClock&, days: i64) -> i64 { return wing::advance_days(c, days); }

fn ::next_u64(rng: wing::FuzzRng&) -> u64 { return wing::next_u64(rng); }
fn ::next_range(rng: wing::FuzzRng&, min_val: i64, max_exclusive: i64) -> i64 { return wing::next_range(rng, min_val, max_exclusive); }
fn ::next_bool(rng: wing::FuzzRng&) -> bool { return wing::next_bool(rng); }
fn ::next_ascii_string<B>(rng: wing::FuzzRng&, out: B&, length: i64) { wing::next_ascii_string(rng, out, length); }
