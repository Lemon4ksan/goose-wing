// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Unit tests for hardware cycle profiler primitives.
//
// RUN: goose build -o %t.exe %s
// RUN: %t.exe
import std;
import core from "..";
import wing from "..";
import lit from "github.com/Lemon4ksan/goose-lit@v0.1.0";

fn test_hardware_cycle_profiler(t: lit::T&) {
    t.run("RDTSC Clock Monotonicity and Recording") { sub =>
        let c0 = wing::prof_rdtsc();
        var sum: i64 = 0;
        for i in 1000 {
            sum = sum + i;
        }
        let c1 = wing::prof_rdtsc();
        sub.assert_gt(c1, c0);
        sub.assert_gt(sum, 0);

        wing::prof_reset();
        sub.assert_eq(wing::prof_sample_count(wing::PROF_STAGE_FRAMING), 0);
        sub.assert_eq(wing::prof_total_cycles(wing::PROF_STAGE_FRAMING), 0);
        sub.assert_eq(wing::prof_min_cycles(wing::PROF_STAGE_FRAMING), 0);
        sub.assert_eq(wing::prof_max_cycles(wing::PROF_STAGE_FRAMING), 0);

        wing::prof_record(wing::PROF_STAGE_FRAMING, 100);
        wing::prof_record(wing::PROF_STAGE_FRAMING, 300);

        sub.assert_eq(wing::prof_sample_count(wing::PROF_STAGE_FRAMING), 2);
        sub.assert_eq(wing::prof_total_cycles(wing::PROF_STAGE_FRAMING), 400);
        sub.assert_eq(wing::prof_min_cycles(wing::PROF_STAGE_FRAMING), 100);
        sub.assert_eq(wing::prof_max_cycles(wing::PROF_STAGE_FRAMING), 300);
        sub.assert_gt(wing::prof_avg_cycles(wing::PROF_STAGE_FRAMING), 199.0);

        wing::prof_print_summary();
        wing::prof_reset();
    };
}

fn main() {
    let runner = lit::new_runner("Hardware Cycle Profiler Test Suite");
    lit::run_case(runner, "1. RDTSC Monotonicity & Record", test_hardware_cycle_profiler);
    let ok = lit::finish(runner);
    assert(ok);
}
