// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Weak-linked C profiler hooks overridden by goose-lit/shim/profiler.c when linked.
namespace server_prof;

import std;

extern fn lit_prof_enter(name: const u8[:]) -> i64 = "lit_prof_enter";
extern fn lit_prof_leave(span_tok: i64) = "lit_prof_leave";
extern fn lit_rdtsc() -> u64 = "lit_rdtsc";
