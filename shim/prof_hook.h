// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

/* shim/prof_hook.h - Compile-time interposition for the Goose-Wing stage
   profiler and three-channel memory tracker (shim/profiler.c).

   Splice this header into the generated C of an instrumented build:

       goose build -O2 --include shim/prof_hook.h <target.goose> -o <out>

   When included into non-Goose C translation units (such as shim/profiler.c),
   the #if defined(GS) && !defined(WING_PROF_SHIM_INTERNAL) guard makes this
   header a complete no-op. */

#ifndef WING_PROF_HOOK_H
#define WING_PROF_HOOK_H

#if defined(GS) && !defined(WING_PROF_SHIM_INTERNAL)

#include <stddef.h>

#if !defined(__GNUC__) && !defined(__clang__)
#ifndef __builtin_expect
#define __builtin_expect(x, v) (x)
#endif
#endif

extern uint8_t g_prof_mem_active;

typedef void (*wing_prof_stack_query_fn_t)(void **out_stks_base, int32_t *out_stride,
                                           int32_t *out_top_off, int32_t *out_nstks);

void wing_prof_set_stack_query_fn(wing_prof_stack_query_fn_t fn);
void wing_prof_bind_stacks(void *stks_base, int32_t elem_stride, int32_t top_offset, int32_t nstks);
void wing_prof_gs_peak_tap(int32_t idx, uint8_t *cur_top);
void wing_prof_on_pool_alloc(int64_t bytes);
void wing_prof_on_pool_regrow(int64_t bytes);
void wing_prof_on_pool_free(void);

static void wing_prof_query_gs_stacks(void **out_stks_base, int32_t *out_stride,
                                      int32_t *out_top_off, int32_t *out_nstks) {
    *out_stks_base = (void *)gs_stks;
    *out_stride = (int32_t)sizeof(gs_stack);
    *out_top_off = (int32_t)offsetof(gs_stack, top);
    *out_nstks = (int32_t)gs_nstks;
}

#if defined(__GNUC__) || defined(__clang__)
__attribute__((constructor))
static void wing_prof_register_stack_hook(void) {
    wing_prof_set_stack_query_fn(wing_prof_query_gs_stacks);
}
#endif

static inline gs_stack *wing_prof_gs_tap(gs_stack *stks, int64_t nstks, int32_t idx) {
    if (__builtin_expect(g_prof_mem_active != 0, 0)) {
        wing_prof_bind_stacks((void *)stks, (int32_t)sizeof(gs_stack),
                              (int32_t)offsetof(gs_stack, top), (int32_t)nstks);
        wing_prof_gs_peak_tap(idx, stks[idx].top);
    }
    return &stks[idx];
}

#undef GS
#define GS(i) wing_prof_gs_tap(gs_stks, gs_nstks, (int32_t)(i))

static inline int64_t wing_prof_hook_place(gs_rref nodes, void *tree, int64_t len, int64_t cnt,
                                           const gs_loc *at) {
    if (__builtin_expect(g_prof_mem_active != 0, 0)) {
        wing_prof_on_pool_alloc(cnt);
    }
    return gs_slice_pool_place(nodes, tree, len, cnt, at);
}

static inline void wing_prof_hook_free(gs_rref nodes, void *tree, int64_t idx, int64_t cnt,
                                       const gs_loc *at) {
    if (__builtin_expect(g_prof_mem_active != 0, 0)) {
        wing_prof_on_pool_free();
    }
    gs_slice_pool_free(nodes, tree, idx, cnt, at);
}

static inline int64_t wing_prof_hook_regrow(gs_rref nodes, void *tree, int64_t len, int64_t idx,
                                            int64_t ol, int64_t cnt, const gs_loc *at) {
    if (__builtin_expect(g_prof_mem_active != 0, 0)) {
        if (cnt > ol) wing_prof_on_pool_regrow(cnt - ol);
    }
    return gs_slice_pool_regrow(nodes, tree, len, idx, ol, cnt, at);
}

static inline int64_t wing_prof_hook_spans_alloc(uint8_t *base, int64_t *n, uint8_t **top,
                                                 int64_t len, int64_t cnt) {
    if (__builtin_expect(g_prof_mem_active != 0, 0)) {
        wing_prof_on_pool_alloc(cnt);
    }
    return gs_spans_alloc(base, n, top, len, cnt);
}

static inline int64_t wing_prof_hook_spans_regrow(uint8_t *base, int64_t *n, uint8_t **top,
                                                  int64_t len, int64_t idx, int64_t ol, int64_t cnt) {
    if (__builtin_expect(g_prof_mem_active != 0, 0)) {
        if (cnt > ol) wing_prof_on_pool_regrow(cnt - ol);
    }
    return gs_spans_regrow(base, n, top, len, idx, ol, cnt);
}

static inline void wing_prof_hook_spans_free(uint8_t *base, int64_t *n, uint8_t **top,
                                             int64_t idx, int64_t cnt) {
    if (__builtin_expect(g_prof_mem_active != 0, 0)) {
        wing_prof_on_pool_free();
    }
    gs_spans_free(base, n, top, idx, cnt);
}

#define gs_slice_pool_place(nodes, tree, len, cnt, at) \
    wing_prof_hook_place(nodes, tree, len, cnt, at)
#define gs_slice_pool_free(nodes, tree, idx, cnt, at) \
    wing_prof_hook_free(nodes, tree, idx, cnt, at)
#define gs_slice_pool_regrow(nodes, tree, len, idx, ol, cnt, at) \
    wing_prof_hook_regrow(nodes, tree, len, idx, ol, cnt, at)
#define gs_spans_alloc(base, n, top, len, cnt) \
    wing_prof_hook_spans_alloc(base, n, top, len, cnt)
#define gs_spans_regrow(base, n, top, len, idx, ol, cnt) \
    wing_prof_hook_spans_regrow(base, n, top, len, idx, ol, cnt)
#define gs_spans_free(base, n, top, idx, cnt) \
    wing_prof_hook_spans_free(base, n, top, idx, cnt)

#if defined(WING_PROF_STRIP)
#if defined(__GNUC__) || defined(__clang__)
extern inline __attribute__((gnu_inline)) gs_i64 wing_prof_enter_noop(sl_u8 name) {
    (void)name;
    return -1;
}
extern inline __attribute__((gnu_inline)) void wing_prof_leave_noop(gs_i64 span_tok) {
    (void)span_tok;
}
#define wing_prof_enter(name) wing_prof_enter_noop(name)
#define wing_prof_leave(tok) wing_prof_leave_noop(tok)
#endif
#endif

#endif /* defined(GS) && !defined(WING_PROF_SHIM_INTERNAL) */

#endif /* WING_PROF_HOOK_H */
