// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Subtest execution, table-driven runners, and test suite lifecycle management.
namespace core;

import std;
import core.time;
import core.test.context;

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
