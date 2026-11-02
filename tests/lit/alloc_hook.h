/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (c) 2026 Lemon4ksan */

/* tests/lit/alloc_hook.h - Compile-time interposition for the runtime
   allocation counter (alloc_count.c).

   Splice this header into the generated C of an instrumented build only:

       goose build --cc gcc -O2 --include tests/lit/alloc_hook.h -o out.exe t.goose

   Each macro renames one runtime allocator primitive to its counting
   forwarder in alloc_count.c. The generated TU's prototypes and call sites
   rename together; the forwarders call the real primitives (unrenamed in
   the runtime object) and bump the counters. Builds without this header
   compile exactly as before: zero overhead when disabled. */

#ifndef WING_ALLOC_HOOK_H
#define WING_ALLOC_HOOK_H

/* Counting forwarders in alloc_count.c. Splice point is after the generated
   runtime types (gs_rref, gs_loc), so these match the renamed prototypes. */
int64_t wing_ac_place(gs_rref nodes, void *tree, int64_t len, int64_t cnt,
                      const gs_loc *at);
void wing_ac_free(gs_rref nodes, void *tree, int64_t idx, int64_t cnt,
                  const gs_loc *at);
int64_t wing_ac_regrow(gs_rref nodes, void *tree, int64_t len, int64_t idx, int64_t ol,
                       int64_t cnt, const gs_loc *at);
int64_t wing_ac_spans_alloc(uint8_t *base, int64_t *n, uint8_t **top, int64_t len,
                            int64_t cnt);
int64_t wing_ac_spans_regrow(uint8_t *base, int64_t *n, uint8_t **top, int64_t len,
                             int64_t idx, int64_t ol, int64_t cnt);
void wing_ac_spans_free(uint8_t *base, int64_t *n, uint8_t **top, int64_t idx,
                        int64_t cnt);

#define gs_slice_pool_place(nodes, tree, len, cnt, at) \
    wing_ac_place(nodes, tree, len, cnt, at)
#define gs_slice_pool_free(nodes, tree, idx, cnt, at) \
    wing_ac_free(nodes, tree, idx, cnt, at)
#define gs_slice_pool_regrow(nodes, tree, len, idx, ol, cnt, at) \
    wing_ac_regrow(nodes, tree, len, idx, ol, cnt, at)
#define gs_spans_alloc(base, n, top, len, cnt) \
    wing_ac_spans_alloc(base, n, top, len, cnt)
#define gs_spans_regrow(base, n, top, len, idx, ol, cnt) \
    wing_ac_spans_regrow(base, n, top, len, idx, ol, cnt)
#define gs_spans_free(base, n, top, idx, cnt) \
    wing_ac_spans_free(base, n, top, idx, cnt)

#endif
