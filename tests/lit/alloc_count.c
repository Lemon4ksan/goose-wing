// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// tests/lit/alloc_count.c - Runtime allocation counter shim for goose-wing.
//
// Goose has no heap: growable arrays bump-allocate on per-thread data stacks.
// The runtime's only function-call allocator paths are the slice-pool span
// primitives (gs_slice_pool_place/regrow/free, gs_spans_alloc/regrow/free).
// This shim counts those calls when the program is built with the
// alloc_hook.h interposition header (see verify_alloc_counter.build and the
// // RUN: line of verify_alloc_counter.goose), plus explicit wing_alloc_note
// taps and data-stack growth sampling through wing_alloc_mark/growth.
//
// Zero-overhead when disabled: production builds never splice alloc_hook.h,
// so the generated C calls the runtime primitives directly and this object
// is never invoked. Instrumented builds gate counting on the enabled flag
// (wing_alloc_reset enables, wing_alloc_disable turns counting off).

#include "goose.h"

// A build that splices alloc_hook.h into this unit too would rename the
// real primitives below; neutralize the renames before forwarding.
#undef gs_slice_pool_place
#undef gs_slice_pool_free
#undef gs_slice_pool_regrow
#undef gs_spans_alloc
#undef gs_spans_regrow
#undef gs_spans_free

// Opaque call-site location (file, line) forwarded untouched to the runtime.
typedef struct wing_ac_loc wing_ac_loc;

extern int64_t gs_slice_pool_place(gs_rref nodes, void *tree, int64_t len, int64_t cnt,
                                   const void *at);
extern void gs_slice_pool_free(gs_rref nodes, void *tree, int64_t idx, int64_t cnt,
                               const void *at);
extern int64_t gs_slice_pool_regrow(gs_rref nodes, void *tree, int64_t len, int64_t idx,
                                    int64_t ol, int64_t cnt, const void *at);
extern int64_t gs_spans_alloc(uint8_t *base, int64_t *n, uint8_t **top, int64_t len,
                              int64_t cnt);
extern int64_t gs_spans_regrow(uint8_t *base, int64_t *n, uint8_t **top, int64_t len,
                               int64_t idx, int64_t ol, int64_t cnt);
extern void gs_spans_free(uint8_t *base, int64_t *n, uint8_t **top, int64_t idx,
                          int64_t cnt);

static uint64_t ac_events = 0;
static uint64_t ac_bytes = 0;
static uint64_t ac_frees = 0;
static uint8_t ac_enabled = 0;

static void ac_count_alloc(int64_t elems) {
    if (!ac_enabled) return;
    ac_events++;
    if (elems > 0) ac_bytes += (uint64_t)elems;
}

static void ac_count_free(void) {
    if (!ac_enabled) return;
    ac_frees++;
}

void wing_alloc_reset(void) {
    ac_events = 0;
    ac_bytes = 0;
    ac_frees = 0;
    ac_enabled = 1;
}

void wing_alloc_disable(void) { ac_enabled = 0; }

uint64_t wing_alloc_events(void) { return ac_events; }

uint64_t wing_alloc_bytes(void) { return ac_bytes; }

uint64_t wing_alloc_frees(void) { return ac_frees; }

void wing_alloc_note(int64_t bytes) { ac_count_alloc(bytes); }

// The bump watermark (current top) of the data stack that owns `probe`.
uint64_t wing_alloc_mark(gs_rref probe) {
    return (uint64_t)(uintptr_t)probe.stk->top;
}

// Net growth of that data stack since the mark: surviving growable-array
// growth on the stack, in bytes (scratch that rewound with its scope nets 0).
int64_t wing_alloc_growth(gs_rref probe, uint64_t mark) {
    return (int64_t)((uint64_t)(uintptr_t)probe.stk->top - mark);
}

// Interposition targets: counting forwarders over the runtime primitives.

int64_t wing_ac_place(gs_rref nodes, void *tree, int64_t len, int64_t cnt,
                      const wing_ac_loc *at) {
    ac_count_alloc(cnt);
    return gs_slice_pool_place(nodes, tree, len, cnt, at);
}

void wing_ac_free(gs_rref nodes, void *tree, int64_t idx, int64_t cnt,
                  const wing_ac_loc *at) {
    ac_count_free();
    gs_slice_pool_free(nodes, tree, idx, cnt, at);
}

int64_t wing_ac_regrow(gs_rref nodes, void *tree, int64_t len, int64_t idx, int64_t ol,
                       int64_t cnt, const wing_ac_loc *at) {
    ac_count_alloc(cnt - ol);
    return gs_slice_pool_regrow(nodes, tree, len, idx, ol, cnt, at);
}

int64_t wing_ac_spans_alloc(uint8_t *base, int64_t *n, uint8_t **top, int64_t len,
                            int64_t cnt) {
    ac_count_alloc(cnt);
    return gs_spans_alloc(base, n, top, len, cnt);
}

int64_t wing_ac_spans_regrow(uint8_t *base, int64_t *n, uint8_t **top, int64_t len,
                             int64_t idx, int64_t ol, int64_t cnt) {
    ac_count_alloc(cnt - ol);
    return gs_spans_regrow(base, n, top, len, idx, ol, cnt);
}

void wing_ac_spans_free(uint8_t *base, int64_t *n, uint8_t **top, int64_t idx,
                        int64_t cnt) {
    ac_count_free();
    gs_spans_free(base, n, top, idx, cnt);
}
