// Test execution context, failure tracking, verbosity modes, and lifecycle state.
namespace core;

import std;
import os;
import core.time;

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

fn is_failed(t: const T&) -> bool { return t.failed; }
fn is_ok(t: const T&) -> bool { return !t.failed; }
fn is_passed(t: const T&) -> bool { return !t.failed && !t.skipped; }
fn is_aborted(t: const T&) -> bool { return t.aborted; }
fn is_skipped(t: const T&) -> bool { return t.skipped; }
fn count(t: const T&) -> i64 { return t.assertions_count; }
fn failures_len(t: const T&) -> i64 { return t.failures_count; }

// Format hooks for std::print / std::format

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
