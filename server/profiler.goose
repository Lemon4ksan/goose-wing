// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Hardware cycle-accurate pipeline profiler for goose-wing.
namespace wing;

import std;

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
