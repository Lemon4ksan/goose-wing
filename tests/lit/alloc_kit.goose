// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// tests/lit/alloc_kit.goose - Bindings for the runtime allocation counter shim.
//
// Events counted while the counter is enabled: slice-pool span allocations
// (gs_slice_pool_place/regrow, gs_spans_alloc/regrow) and explicit note taps.
// wing_alloc_mark/growth sample the bump watermark of the data stack owning
// the probe buffer: a zero growth delta proves no growable array survived the
// measured region on that stack. Scratch that rewinds with its scope and
// inline bump stores are covered by static analysis (scripts/lint_invariants.py),
// not by this counter.
//
// Link the shim into a test program with a sidecar (verify_alloc_counter.build)
// and build with the interposition header so pool traffic is counted:
//   // RUN: goose build --cc gcc -O2 --include %S/alloc_hook.h -o %t.exe %s
namespace alloc_kit;

import std;

extern fn alloc_reset() = "wing_alloc_reset";
extern fn alloc_disable() = "wing_alloc_disable";
extern fn alloc_events() -> u64 = "wing_alloc_events";
extern fn alloc_bytes() -> u64 = "wing_alloc_bytes";
extern fn alloc_frees() -> u64 = "wing_alloc_frees";
extern fn alloc_note(bytes: i64) = "wing_alloc_note";
extern fn alloc_mark(probe: u8[>..]&) -> u64 = "wing_alloc_mark";
extern fn alloc_growth(probe: u8[>..]&, mark: u64) -> i64 = "wing_alloc_growth";
