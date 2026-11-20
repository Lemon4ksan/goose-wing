// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

#define WING_PROF_SHIM_INTERNAL 1
// Hardware Cycle-Accurate Stage Profiler, Three-Channel Memory Auditor &
// testing.B Benchmark Engine for goose-wing.

#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if defined(_WIN32)
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <intrin.h>
#else
#include <time.h>
#if defined(__x86_64__) || defined(__i386__)
#include <x86intrin.h>
#endif
#endif

#if !defined(__GNUC__) && !defined(__clang__)
#ifndef __builtin_expect
#define __builtin_expect(x, v) (x)
#endif
#endif

typedef struct {
    const uint8_t *data;
    int64_t len;
} wing_prof_str_t;

typedef void (*wing_prof_stack_query_fn_t)(void **out_stks_base, int32_t *out_stride, int32_t *out_top_off,
                                           int32_t *out_nstks);

#define WING_PROF_LEGACY_STAGES 16
#define WING_PROF_MAX_STAGES 64
#define WING_PROF_MAX_SPAN_DEPTH 16
#define WING_PROF_SAMPLE_RING 4096
#define WING_PROF_PTR_CACHE_SZ 128
#define WING_PROF_MAX_STACKS 64
#define WING_PROF_MAX_BENCHMARKS 64

#define PROF_PASS_CALIBRATE 0
#define PROF_PASS_TIMING 1
#define PROF_PASS_MEMORY 2

typedef struct {
    char name[64];
    uint64_t name_hash;
    uint64_t total_cycles;
    uint64_t self_cycles;
    uint64_t count;
    uint64_t min_cycles;
    uint64_t max_cycles;
    int64_t net_bytes;
    int64_t scratch_bytes;
    int64_t peak_bytes;
    int64_t pool_allocs;
    int64_t pool_alloc_bytes;
    int64_t pool_frees;
    uint32_t samples[WING_PROF_SAMPLE_RING];
    uint8_t active;
} wing_prof_stage_t;

typedef struct {
    int32_t stage_id;
    uint32_t _pad;
    uint64_t t_enter;
    uint64_t child_cycles;
    uint8_t *stk_enter_top[WING_PROF_MAX_STACKS];
    uint8_t *stk_peak_top[WING_PROF_MAX_STACKS];
    int64_t enter_pool_allocs;
    int64_t enter_pool_bytes;
    int64_t enter_pool_frees;
} wing_prof_span_t;

typedef struct {
    uintptr_t ptr_key;
    int32_t stage_id;
    int32_t len;
} wing_prof_ptr_cache_t;

typedef struct {
    char name[64];
    uint64_t count;
    uint64_t self_cycles;
    uint64_t total_cycles;
    uint64_t min_cycles;
    uint64_t p50_cycles;
    uint64_t p99_cycles;
    uint64_t max_cycles;
    int64_t net_bytes;
    int64_t scratch_bytes;
    int64_t peak_bytes;
    int64_t pool_allocs;
    int64_t pool_frees;
} wing_bench_stage_snap_t;

typedef struct {
    char name[128];
    int64_t iters;
    double ns_per_op;
    double cycles_per_op;
    double mb_per_sec;
    int64_t bytes_per_op;
    int64_t net_b_per_op;
    int64_t scratch_b_per_op;
    int64_t peak_b;
    int64_t allocs_per_op;
    int64_t frees_per_op;
    double custom_metric_val;
    char custom_metric_unit[32];
    int32_t num_stages;
    wing_bench_stage_snap_t stages[WING_PROF_MAX_STAGES];
} wing_bench_result_t;

uint8_t g_prof_mem_active = 0;

static uint8_t g_prof_active = 0;
static int32_t g_prof_pass_mode = PROF_PASS_TIMING;
static uint8_t g_prof_calibrated = 0;
static uint64_t g_rdtsc_overhead_cycles = 0;
static double g_tsc_freq_ghz = 3.0;

static wing_prof_stage_t *g_prof_stages = NULL;
static int32_t g_prof_dynamic_count = WING_PROF_LEGACY_STAGES;
static wing_prof_ptr_cache_t g_ptr_cache[WING_PROF_PTR_CACHE_SZ];

static wing_prof_span_t g_span_stack[WING_PROF_MAX_SPAN_DEPTH];
static int32_t g_span_depth = 0;

static wing_prof_stack_query_fn_t g_stack_query_fn = NULL;
static uint8_t *g_stks_base = NULL;
static int32_t g_stk_stride = 0;
static int32_t g_stk_top_off = 0;
static int32_t g_nstks = 0;

static int64_t g_pool_alloc_events = 0;
static int64_t g_pool_alloc_bytes = 0;
static int64_t g_pool_free_events = 0;

static int32_t g_last_closed_stage_id = -1;
static uint8_t *g_last_closed_enter_top[WING_PROF_MAX_STACKS];
static uint8_t *g_last_closed_exit_top[WING_PROF_MAX_STACKS];

static char g_suite_name[128] = "Goose-Wing Benchmark Suite";
static int64_t g_suite_target_ns = 50000000LL;
static char g_filter_buf[128] = {0};
static uint8_t g_has_filter = 0;
static uint8_t g_machine_out = 0;

static uint64_t g_pass_start_ns = 0;
static uint64_t g_pass_elapsed_ns = 0;
static uint64_t g_pass_start_cyc = 0;
static uint64_t g_pass_elapsed_cyc = 0;
static uint64_t g_timing_pass_elapsed_ns = 0;
static uint64_t g_timing_pass_elapsed_cyc = 0;
static uint8_t g_timer_running = 0;
static uint8_t g_cur_has_sub = 0;
static int64_t g_cur_bytes_per_op = 0;
static double g_cur_metric_val = 0.0;
static char g_cur_metric_unit[32] = {0};

static uint8_t *g_bench_enter_top[WING_PROF_MAX_STACKS];
static uint8_t *g_bench_peak_top[WING_PROF_MAX_STACKS];
static int64_t g_bench_enter_allocs = 0;
static int64_t g_bench_enter_frees = 0;
static int64_t g_bench_last_net_b = 0;
static int64_t g_bench_last_scratch_b = 0;
static int64_t g_bench_last_peak_b = 0;
static int64_t g_bench_last_allocs = 0;
static int64_t g_bench_last_frees = 0;

static wing_bench_result_t *g_bench_results = NULL;
static int32_t g_bench_result_count = 0;

static const char *const k_legacy_stage_names[WING_PROF_LEGACY_STAGES] = {
    "0. Framing (CRLFCRLF)", "1. Request Line Parse",
    "2. Headers Tokenize",   "3. Host & Framing Val",
    "4. Pipeline & GCRA",    "5. Radix Router Match",
    "6. Handler Execution",  "7. Resp Serialization",
    "8. Output Buffer Copy", "9. Socket Recv Syscall",
    "10. Socket Send/Flush", "11. Misc/Overhead",
    "12. Extra 1",           "13. Extra 2",
    "14. Extra 3",           "15. Extra 4",
};

static inline uint64_t wing_rdtsc_start(void) {
#if defined(__x86_64__) || defined(__i386__) || defined(_M_X64) || defined(_M_IX86)
    unsigned int aux;
    return __rdtscp(&aux);
#elif defined(__aarch64__)
    uint64_t val;
    __asm__ volatile("isb; mrs %0, cntvct_el0" : "=r"(val));
    return val;
#else
    return 0;
#endif
}

static inline uint64_t wing_rdtsc_end(void) {
#if defined(__x86_64__) || defined(__i386__) || defined(_M_X64) || defined(_M_IX86)
    unsigned int aux;
    return __rdtscp(&aux);
#elif defined(__aarch64__)
    uint64_t val;
    __asm__ volatile("mrs %0, cntvct_el0; isb" : "=r"(val));
    return val;
#else
    return 0;
#endif
}

uint64_t wing_rdtsc(void) { return wing_rdtsc_start(); }

static uint64_t wing_clock_ns(void) {
#if defined(_WIN32)
    static LARGE_INTEGER freq = {0};
    if (freq.QuadPart == 0) {
        QueryPerformanceFrequency(&freq);
    }
    LARGE_INTEGER now;
    QueryPerformanceCounter(&now);
    if (freq.QuadPart <= 0) return 0;
    uint64_t sec = (uint64_t)(now.QuadPart / freq.QuadPart);
    uint64_t rem = (uint64_t)(now.QuadPart % freq.QuadPart);
    return sec * 1000000000ULL + (rem * 1000000000ULL) / (uint64_t)freq.QuadPart;
#else
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
#endif
}

static inline uint8_t *wing_get_stk_top(int32_t idx) {
    if (!g_stks_base || idx < 0 || idx >= g_nstks) return NULL;
    uint8_t *elem = g_stks_base + (size_t)idx * (size_t)g_stk_stride;
    uint8_t *top_val = NULL;
    memcpy(&top_val, elem + g_stk_top_off, sizeof(uint8_t *));
    return top_val;
}

void wing_prof_bind_stacks(void *stks_base, int32_t elem_stride, int32_t top_offset, int32_t nstks);

static void wing_prof_ensure_stacks_bound(void) {
    if (!g_stks_base && g_stack_query_fn != NULL) {
        void *base = NULL;
        int32_t stride = 0, top_off = 0, nstks = 0;
        g_stack_query_fn(&base, &stride, &top_off, &nstks);
        if (base != NULL && nstks > 0) {
            wing_prof_bind_stacks(base, stride, top_off, nstks);
        }
    }
}

void wing_prof_set_stack_query_fn(wing_prof_stack_query_fn_t fn) { g_stack_query_fn = fn; }

static int wing_prof_ensure_buffers(void) {
    if (!g_prof_stages) {
        g_prof_stages = (wing_prof_stage_t *)calloc(WING_PROF_MAX_STAGES, sizeof(wing_prof_stage_t));
    }
    if (!g_bench_results) {
        g_bench_results = (wing_bench_result_t *)calloc(WING_PROF_MAX_BENCHMARKS, sizeof(wing_bench_result_t));
    }
    return (g_prof_stages != NULL && g_bench_results != NULL);
}

static void wing_prof_init_stages_once(void) {
    if (!wing_prof_ensure_buffers()) return;
    if (g_prof_calibrated) return;
    g_prof_calibrated = 1;

    for (int32_t i = 0; i < WING_PROF_MAX_STAGES; i++) {
        memset(&g_prof_stages[i], 0, sizeof(wing_prof_stage_t));
        g_prof_stages[i].min_cycles = UINT64_MAX;
        if (i < WING_PROF_LEGACY_STAGES) {
            snprintf(g_prof_stages[i].name, sizeof(g_prof_stages[i].name), "%s", k_legacy_stage_names[i]);
            g_prof_stages[i].active = 1;
        }
    }
    g_prof_dynamic_count = WING_PROF_LEGACY_STAGES;

    uint64_t min_ovh = UINT64_MAX;
    for (int i = 0; i < 64; i++) {
        uint64_t t0 = wing_rdtsc_start();
        uint64_t t1 = wing_rdtsc_end();
        uint64_t d = (t1 > t0) ? (t1 - t0) : 0;
        if (d < min_ovh) min_ovh = d;
    }
    g_rdtsc_overhead_cycles = (min_ovh < 256) ? min_ovh : 0;

    uint64_t ns0 = wing_clock_ns();
    uint64_t c0 = wing_rdtsc_start();
    uint64_t ns1 = ns0;
    while (ns1 - ns0 < 2000000ULL) {
        ns1 = wing_clock_ns();
    }
    uint64_t c1 = wing_rdtsc_end();
    if (ns1 > ns0 && c1 > c0) {
        double ghz = (double)(c1 - c0) / (double)(ns1 - ns0);
        if (ghz >= 0.1 && ghz <= 10.0) {
            g_tsc_freq_ghz = ghz;
        }
    }

    const char *env_filter = getenv("WING_BENCH_FILTER");
    if (env_filter && env_filter[0] != '\0') {
        snprintf(g_filter_buf, sizeof(g_filter_buf), "%s", env_filter);
        g_has_filter = 1;
    }
    const char *env_mach = getenv("WING_PROF_MACHINE_OUT");
    if (env_mach && env_mach[0] == '1') {
        g_machine_out = 1;
    }
}

static void wing_prof_clear_stage_timings(void) {
    for (int32_t i = 0; i < WING_PROF_MAX_STAGES; i++) {
        g_prof_stages[i].total_cycles = 0;
        g_prof_stages[i].self_cycles = 0;
        g_prof_stages[i].count = 0;
        g_prof_stages[i].min_cycles = UINT64_MAX;
        g_prof_stages[i].max_cycles = 0;
    }
}

static void wing_prof_clear_stage_memory(void) {
    for (int32_t i = 0; i < WING_PROF_MAX_STAGES; i++) {
        g_prof_stages[i].net_bytes = 0;
        g_prof_stages[i].scratch_bytes = 0;
        g_prof_stages[i].peak_bytes = 0;
        g_prof_stages[i].pool_allocs = 0;
        g_prof_stages[i].pool_alloc_bytes = 0;
        g_prof_stages[i].pool_frees = 0;
    }
    g_last_closed_stage_id = -1;
}

void wing_prof_reset(void) {
    wing_prof_init_stages_once();
    wing_prof_clear_stage_timings();
    wing_prof_clear_stage_memory();
    memset(g_ptr_cache, 0, sizeof(g_ptr_cache));
    for (int32_t i = WING_PROF_LEGACY_STAGES; i < WING_PROF_MAX_STAGES; i++) {
        g_prof_stages[i].active = 0;
        g_prof_stages[i].name[0] = '\0';
        g_prof_stages[i].name_hash = 0;
    }
    g_prof_dynamic_count = WING_PROF_LEGACY_STAGES;
    g_span_depth = 0;
    g_pool_alloc_events = 0;
    g_pool_alloc_bytes = 0;
    g_pool_free_events = 0;
    g_prof_active = 1;
    g_prof_pass_mode = PROF_PASS_TIMING;
    g_prof_mem_active = 1;
    wing_prof_ensure_stacks_bound();
}

static inline uint64_t wing_fnv1a_64(const uint8_t *data, int64_t len) {
    uint64_t h = 14695981039346656037ULL;
    for (int64_t i = 0; i < len; i++) {
        h ^= (uint64_t)data[i];
        h *= 1099511628211ULL;
    }
    return h;
}

static int32_t wing_prof_resolve_stage(wing_prof_str_t name, int create_if_missing) {
    if (!name.data || name.len <= 0) return -1;
    wing_prof_init_stages_once();

    uintptr_t ptr_key = (uintptr_t)name.data;
    uint32_t p_slot = (uint32_t)((ptr_key >> 3) ^ (uintptr_t)name.len) & (WING_PROF_PTR_CACHE_SZ - 1);
    if (g_ptr_cache[p_slot].ptr_key == ptr_key && g_ptr_cache[p_slot].len == (int32_t)name.len) {
        return g_ptr_cache[p_slot].stage_id;
    }

    int64_t cmp_len = name.len < 63 ? name.len : 63;
    uint64_t h = wing_fnv1a_64(name.data, cmp_len);

    for (int32_t i = WING_PROF_LEGACY_STAGES; i < g_prof_dynamic_count; i++) {
        if (g_prof_stages[i].active && g_prof_stages[i].name_hash == h &&
            (int64_t)strlen(g_prof_stages[i].name) == cmp_len &&
            memcmp(g_prof_stages[i].name, name.data, (size_t)cmp_len) == 0) {
            g_ptr_cache[p_slot].ptr_key = ptr_key;
            g_ptr_cache[p_slot].len = (int32_t)name.len;
            g_ptr_cache[p_slot].stage_id = i;
            return i;
        }
    }

    if (!create_if_missing) return -1;
    if (g_prof_dynamic_count >= WING_PROF_MAX_STAGES) return -1;

    int32_t new_id = g_prof_dynamic_count++;
    wing_prof_stage_t *s = &g_prof_stages[new_id];
    memset(s, 0, sizeof(*s));
    s->min_cycles = UINT64_MAX;
    memcpy(s->name, name.data, (size_t)cmp_len);
    s->name[cmp_len] = '\0';
    s->name_hash = h;
    s->active = 1;

    g_ptr_cache[p_slot].ptr_key = ptr_key;
    g_ptr_cache[p_slot].len = (int32_t)name.len;
    g_ptr_cache[p_slot].stage_id = new_id;
    return new_id;
}

int64_t wing_prof_enter(wing_prof_str_t name) {
    if (__builtin_expect(!g_prof_active || g_prof_pass_mode == PROF_PASS_CALIBRATE, 0)) {
        return -1;
    }
    if (__builtin_expect(g_span_depth >= WING_PROF_MAX_SPAN_DEPTH, 0)) {
        return -1;
    }

    int32_t stage_id = wing_prof_resolve_stage(name, 1);
    if (stage_id < 0) return -1;

    g_last_closed_stage_id = -1;

    int32_t depth = g_span_depth++;
    wing_prof_span_t *span = &g_span_stack[depth];
    span->stage_id = stage_id;
    span->child_cycles = 0;

    if (__builtin_expect(g_prof_mem_active != 0, 0)) {
        wing_prof_ensure_stacks_bound();
        int32_t n = g_nstks;
        for (int32_t i = 0; i < n; i++) {
            uint8_t *t = wing_get_stk_top(i);
            span->stk_enter_top[i] = t;
            span->stk_peak_top[i] = t;
        }
        span->enter_pool_allocs = g_pool_alloc_events;
        span->enter_pool_bytes = g_pool_alloc_bytes;
        span->enter_pool_frees = g_pool_free_events;
    }

    span->t_enter = wing_rdtsc_start();
    return ((int64_t)depth << 32) | (uint32_t)stage_id;
}

void wing_prof_leave(int64_t span_tok) {
    if (__builtin_expect(span_tok < 0, 0)) return;
    uint64_t t_exit = wing_rdtsc_end();

    int32_t depth = (int32_t)((uint64_t)span_tok >> 32);
    int32_t stage_id = (int32_t)(span_tok & 0xFFFFFFFF);
    if (__builtin_expect(!g_prof_stages || depth < 0 || depth >= g_span_depth || stage_id < 0 ||
                             stage_id >= WING_PROF_MAX_STAGES,
                         0)) {
        return;
    }

    wing_prof_span_t *span = &g_span_stack[depth];
    g_span_depth = depth;

    uint64_t raw_elapsed = (t_exit > span->t_enter) ? (t_exit - span->t_enter) : 0;
    uint64_t net_elapsed = (raw_elapsed > g_rdtsc_overhead_cycles) ? (raw_elapsed - g_rdtsc_overhead_cycles) : 0;
    uint64_t self_delta = (net_elapsed > span->child_cycles) ? (net_elapsed - span->child_cycles) : 0;

    if (depth > 0) {
        g_span_stack[depth - 1].child_cycles += raw_elapsed;
    }

    wing_prof_stage_t *s = &g_prof_stages[stage_id];

    if (g_prof_pass_mode == PROF_PASS_TIMING) {
        uint8_t is_recursive = 0;
        for (int32_t i = 0; i < depth; i++) {
            if (g_span_stack[i].stage_id == stage_id) {
                is_recursive = 1;
                break;
            }
        }
        s->samples[s->count & (WING_PROF_SAMPLE_RING - 1)] =
            (net_elapsed > UINT32_MAX) ? UINT32_MAX : (uint32_t)net_elapsed;
        s->count++;
        if (!is_recursive) {
            s->total_cycles += net_elapsed;
        }
        s->self_cycles += self_delta;
        if (net_elapsed < s->min_cycles) s->min_cycles = net_elapsed;
        if (net_elapsed > s->max_cycles) s->max_cycles = net_elapsed;
    }

    if (__builtin_expect(g_prof_mem_active != 0, 0)) {
        int64_t net_d = 0;
        int64_t peak_d = 0;
        int32_t n = g_nstks;
        for (int32_t i = 0; i < n; i++) {
            uint8_t *cur = wing_get_stk_top(i);
            uint8_t *ent = span->stk_enter_top[i];
            uint8_t *pk = span->stk_peak_top[i];
            if (cur > pk) pk = cur;
            if (cur > ent) net_d += (int64_t)(cur - ent);
            if (pk > ent) peak_d += (int64_t)(pk - ent);
            g_last_closed_enter_top[i] = ent;
            g_last_closed_exit_top[i] = cur;
        }
        int64_t scratch_d = (peak_d > net_d) ? (peak_d - net_d) : 0;
        s->net_bytes += net_d;
        s->scratch_bytes += scratch_d;
        if (peak_d > s->peak_bytes) s->peak_bytes = peak_d;
        s->pool_allocs += (g_pool_alloc_events - span->enter_pool_allocs);
        s->pool_alloc_bytes += (g_pool_alloc_bytes - span->enter_pool_bytes);
        s->pool_frees += (g_pool_free_events - span->enter_pool_frees);
        g_last_closed_stage_id = stage_id;
    }
}

void wing_prof_bind_stacks(void *stks_base, int32_t elem_stride, int32_t top_offset, int32_t nstks) {
    if (!stks_base || nstks <= 0) return;
    int32_t capped = nstks < WING_PROF_MAX_STACKS ? nstks : WING_PROF_MAX_STACKS;
    uint8_t first_bind = (g_stks_base == NULL);
    g_stks_base = (uint8_t *)stks_base;
    g_stk_stride = elem_stride;
    g_stk_top_off = top_offset;
    g_nstks = capped;

    if (first_bind) {
        for (int32_t i = 0; i < capped; i++) {
            uint8_t *t = wing_get_stk_top(i);
            if (!g_bench_enter_top[i]) g_bench_enter_top[i] = t;
            if (!g_bench_peak_top[i]) g_bench_peak_top[i] = t;
            for (int32_t d = 0; d < g_span_depth; d++) {
                if (!g_span_stack[d].stk_enter_top[i]) g_span_stack[d].stk_enter_top[i] = t;
                if (!g_span_stack[d].stk_peak_top[i]) g_span_stack[d].stk_peak_top[i] = t;
            }
        }
    }
}

void wing_prof_gs_peak_tap(int32_t idx, uint8_t *cur_top) {
    if (!g_prof_mem_active || idx < 0 || idx >= WING_PROF_MAX_STACKS || !cur_top) return;

    if (cur_top > g_bench_peak_top[idx]) {
        g_bench_peak_top[idx] = cur_top;
    }
    for (int32_t d = 0; d < g_span_depth; d++) {
        if (cur_top > g_span_stack[d].stk_peak_top[idx]) {
            g_span_stack[d].stk_peak_top[idx] = cur_top;
        }
    }
    if (g_last_closed_stage_id >= 0 && g_last_closed_stage_id < WING_PROF_MAX_STAGES) {
        uint8_t *ent = g_last_closed_enter_top[idx];
        uint8_t *ext = g_last_closed_exit_top[idx];
        if (ent != NULL && cur_top == ext && cur_top > ent) {
            int64_t rewound = (int64_t)(cur_top - ent);
            wing_prof_stage_t *ls = &g_prof_stages[g_last_closed_stage_id];
            if (ls->net_bytes >= rewound) {
                ls->net_bytes -= rewound;
            } else {
                ls->net_bytes = 0;
            }
            ls->scratch_bytes += rewound;
            if (rewound > ls->peak_bytes) {
                ls->peak_bytes = rewound;
            }
            g_last_closed_exit_top[idx] = ent;
        }
    }
}

void wing_prof_on_pool_alloc(int64_t bytes) {
    if (!g_prof_mem_active) return;
    g_pool_alloc_events++;
    if (bytes > 0) g_pool_alloc_bytes += bytes;
}

void wing_prof_on_pool_regrow(int64_t bytes) {
    if (!g_prof_mem_active) return;
    g_pool_alloc_events++;
    if (bytes > 0) g_pool_alloc_bytes += bytes;
}

void wing_prof_on_pool_free(void) {
    if (!g_prof_mem_active) return;
    g_pool_free_events++;
}

void wing_prof_record(int32_t stage_id, uint64_t cycles) {
    wing_prof_init_stages_once();
    if (!g_prof_stages || stage_id < 0 || stage_id >= WING_PROF_MAX_STAGES) return;
    wing_prof_stage_t *s = &g_prof_stages[stage_id];
    s->samples[s->count & (WING_PROF_SAMPLE_RING - 1)] = (cycles > UINT32_MAX) ? UINT32_MAX : (uint32_t)cycles;
    s->total_cycles += cycles;
    s->self_cycles += cycles;
    s->count++;
    if (cycles < s->min_cycles) s->min_cycles = cycles;
    if (cycles > s->max_cycles) s->max_cycles = cycles;
    s->active = 1;
}

uint64_t wing_prof_total_cycles(int32_t stage_id) {
    if (!g_prof_stages || stage_id < 0 || stage_id >= WING_PROF_MAX_STAGES) return 0;
    return g_prof_stages[stage_id].total_cycles;
}

uint64_t wing_prof_sample_count(int32_t stage_id) {
    if (!g_prof_stages || stage_id < 0 || stage_id >= WING_PROF_MAX_STAGES) return 0;
    return g_prof_stages[stage_id].count;
}

uint64_t wing_prof_min_cycles(int32_t stage_id) {
    if (!g_prof_stages || stage_id < 0 || stage_id >= WING_PROF_MAX_STAGES) return 0;
    return g_prof_stages[stage_id].min_cycles == UINT64_MAX ? 0 : g_prof_stages[stage_id].min_cycles;
}

uint64_t wing_prof_max_cycles(int32_t stage_id) {
    if (!g_prof_stages || stage_id < 0 || stage_id >= WING_PROF_MAX_STAGES) return 0;
    return g_prof_stages[stage_id].max_cycles;
}

double wing_prof_avg_cycles(int32_t stage_id) {
    if (!g_prof_stages || stage_id < 0 || stage_id >= WING_PROF_MAX_STAGES) return 0.0;
    if (g_prof_stages[stage_id].count == 0) return 0.0;
    return (double)g_prof_stages[stage_id].total_cycles / (double)g_prof_stages[stage_id].count;
}

int32_t wing_prof_stage_count(void) {
    if (!g_prof_stages) return 0;
    int32_t cnt = 0;
    for (int32_t i = 0; i < g_prof_dynamic_count; i++) {
        if (i >= WING_PROF_LEGACY_STAGES ? g_prof_stages[i].active : (g_prof_stages[i].count > 0)) {
            cnt++;
        }
    }
    return cnt;
}

int32_t wing_prof_find_stage(wing_prof_str_t name) { return wing_prof_resolve_stage(name, 0); }

uint64_t wing_prof_stage_self_cycles(int32_t stage_id) {
    if (!g_prof_stages || stage_id < 0 || stage_id >= WING_PROF_MAX_STAGES) return 0;
    return g_prof_stages[stage_id].self_cycles;
}

static int wing_cmp_u32(const void *a, const void *b) {
    uint32_t va = *(const uint32_t *)a;
    uint32_t vb = *(const uint32_t *)b;
    return (va > vb) - (va < vb);
}

static uint64_t wing_prof_stage_percentile(int32_t stage_id, int32_t pct_num, int32_t pct_den) {
    if (!g_prof_stages || stage_id < 0 || stage_id >= WING_PROF_MAX_STAGES) return 0;
    wing_prof_stage_t *s = &g_prof_stages[stage_id];
    if (s->count == 0) return 0;
    size_t n = (s->count < WING_PROF_SAMPLE_RING) ? (size_t)s->count : WING_PROF_SAMPLE_RING;
    uint32_t tmp[WING_PROF_SAMPLE_RING];
    memcpy(tmp, s->samples, n * sizeof(uint32_t));
    qsort(tmp, n, sizeof(uint32_t), wing_cmp_u32);
    size_t idx = ((n - 1) * (size_t)pct_num + 49) / (size_t)pct_den;
    if (idx >= n) idx = n - 1;
    return (uint64_t)tmp[idx];
}

uint64_t wing_prof_stage_p50_cycles(int32_t stage_id) { return wing_prof_stage_percentile(stage_id, 50, 100); }

uint64_t wing_prof_stage_p99_cycles(int32_t stage_id) { return wing_prof_stage_percentile(stage_id, 99, 100); }

int64_t wing_prof_stage_net_bytes(int32_t stage_id) {
    if (!g_prof_stages || stage_id < 0 || stage_id >= WING_PROF_MAX_STAGES) return 0;
    return g_prof_stages[stage_id].net_bytes;
}

int64_t wing_prof_stage_scratch_bytes(int32_t stage_id) {
    if (!g_prof_stages || stage_id < 0 || stage_id >= WING_PROF_MAX_STAGES) return 0;
    return g_prof_stages[stage_id].scratch_bytes;
}

int64_t wing_prof_stage_peak_bytes(int32_t stage_id) {
    if (!g_prof_stages || stage_id < 0 || stage_id >= WING_PROF_MAX_STAGES) return 0;
    return g_prof_stages[stage_id].peak_bytes;
}

int64_t wing_prof_stage_pool_allocs(int32_t stage_id) {
    if (!g_prof_stages || stage_id < 0 || stage_id >= WING_PROF_MAX_STAGES) return 0;
    return g_prof_stages[stage_id].pool_allocs;
}

int64_t wing_prof_stage_pool_frees(int32_t stage_id) {
    if (!g_prof_stages || stage_id < 0 || stage_id >= WING_PROF_MAX_STAGES) return 0;
    return g_prof_stages[stage_id].pool_frees;
}

void wing_bench_begin_suite(wing_prof_str_t suite_name, int64_t default_target_ns) {
    wing_prof_init_stages_once();
    if (suite_name.data && suite_name.len > 0) {
        int64_t clen = suite_name.len < 127 ? suite_name.len : 127;
        memcpy(g_suite_name, suite_name.data, (size_t)clen);
        g_suite_name[clen] = '\0';
    }
    const char *env_ms = getenv("WING_BENCH_TIME_MS");
    if (!env_ms || env_ms[0] == '\0') {
        env_ms = getenv("WING_BENCH_TARGET_MS");
    }
    if (env_ms && env_ms[0] != '\0') {
        long ms = strtol(env_ms, NULL, 10);
        if (ms > 0) default_target_ns = (int64_t)ms * 1000000LL;
    }
    g_suite_target_ns = default_target_ns > 0 ? default_target_ns : 50000000LL;
    g_bench_result_count = 0;
}

int32_t wing_bench_should_run(wing_prof_str_t bench_name) {
    wing_prof_init_stages_once();
    if (!g_has_filter) return 1;
    if (!bench_name.data || bench_name.len <= 0) return 0;
    char tmp[128];
    int64_t clen = bench_name.len < 127 ? bench_name.len : 127;
    memcpy(tmp, bench_name.data, (size_t)clen);
    tmp[clen] = '\0';
    return strstr(tmp, g_filter_buf) != NULL ? 1 : 0;
}

static void wing_bench_snapshot_mem_baseline(void) {
    wing_prof_ensure_stacks_bound();
    for (int32_t i = 0; i < g_nstks; i++) {
        uint8_t *t = wing_get_stk_top(i);
        g_bench_enter_top[i] = t;
        g_bench_peak_top[i] = t;
    }
    g_bench_enter_allocs = g_pool_alloc_events;
    g_bench_enter_frees = g_pool_free_events;
}

int64_t wing_bench_begin_pass(wing_prof_str_t bench_name, int32_t pass_idx, int64_t target_ns) {
    (void)bench_name;
    (void)target_ns;
    wing_prof_init_stages_once();
    g_span_depth = 0;
    g_cur_bytes_per_op = 0;
    g_cur_metric_val = 0.0;
    g_cur_metric_unit[0] = '\0';

    if (pass_idx <= 0) {
        g_prof_pass_mode = PROF_PASS_CALIBRATE;
        g_prof_active = 0;
        g_prof_mem_active = 0;
    } else if (pass_idx == 1) {
        g_prof_pass_mode = PROF_PASS_TIMING;
        g_prof_active = 1;
        g_prof_mem_active = 0;
        wing_prof_clear_stage_timings();
    } else {
        g_prof_pass_mode = PROF_PASS_MEMORY;
        g_prof_active = 1;
        g_prof_mem_active = 1;
        wing_prof_clear_stage_memory();
        wing_bench_snapshot_mem_baseline();
    }

    g_pass_elapsed_ns = 0;
    g_pass_elapsed_cyc = 0;
    g_timer_running = 1;
    g_pass_start_ns = wing_clock_ns();
    g_pass_start_cyc = wing_rdtsc_start();
    return 1;
}

void wing_bench_reset_timer(void) {
    if (g_prof_pass_mode == PROF_PASS_TIMING) {
        wing_prof_clear_stage_timings();
    } else if (g_prof_pass_mode == PROF_PASS_MEMORY) {
        wing_prof_clear_stage_memory();
        wing_bench_snapshot_mem_baseline();
    }
    g_pass_elapsed_ns = 0;
    g_pass_elapsed_cyc = 0;
    g_timer_running = 1;
    g_pass_start_ns = wing_clock_ns();
    g_pass_start_cyc = wing_rdtsc_start();
}

void wing_bench_stop_timer(void) {
    if (!g_timer_running) return;
    uint64_t cyc_end = wing_rdtsc_end();
    uint64_t ns_end = wing_clock_ns();
    if (cyc_end > g_pass_start_cyc) g_pass_elapsed_cyc += (cyc_end - g_pass_start_cyc);
    if (ns_end > g_pass_start_ns) g_pass_elapsed_ns += (ns_end - g_pass_start_ns);
    g_timer_running = 0;
}

void wing_bench_start_timer(void) {
    if (g_timer_running) return;
    g_timer_running = 1;
    g_pass_start_ns = wing_clock_ns();
    g_pass_start_cyc = wing_rdtsc_start();
}

void wing_bench_set_bytes(int64_t n_bytes) { g_cur_bytes_per_op = n_bytes; }

void wing_bench_mark_has_sub(void) { g_cur_has_sub = 1; }

int32_t wing_bench_consume_has_sub(void) {
    int32_t v = (int32_t)g_cur_has_sub;
    g_cur_has_sub = 0;
    return v;
}

void wing_bench_report_metric(double val, wing_prof_str_t unit) {
    g_cur_metric_val = val;
    if (unit.data && unit.len > 0) {
        int64_t clen = unit.len < 31 ? unit.len : 31;
        memcpy(g_cur_metric_unit, unit.data, (size_t)clen);
        g_cur_metric_unit[clen] = '\0';
    }
}

int64_t wing_bench_end_pass(int32_t pass_idx, int64_t cur_n, int64_t target_ns) {
    wing_bench_stop_timer();
    int64_t eff_target = target_ns > 0 ? target_ns : g_suite_target_ns;
    const char *env_ms = getenv("WING_BENCH_TIME_MS");
    if (!env_ms || env_ms[0] == '\0') {
        env_ms = getenv("WING_BENCH_TARGET_MS");
    }
    if (env_ms && env_ms[0] != '\0') {
        long ms = strtol(env_ms, NULL, 10);
        if (ms > 0) eff_target = (int64_t)ms * 1000000LL;
    }

    if (pass_idx <= 0) {
        uint64_t elapsed = g_pass_elapsed_ns;
        if (elapsed >= (uint64_t)eff_target || cur_n >= 100000000LL) {
            return cur_n;
        }
        int64_t next_n;
        if (elapsed == 0) {
            next_n = cur_n * 100;
        } else {
            double ratio = (double)eff_target / (double)elapsed;
            if (ratio > 100.0) ratio = 100.0;
            if (ratio < 1.2) ratio = 1.2;
            next_n = (int64_t)((double)cur_n * ratio);
            if (next_n <= cur_n) next_n = cur_n + 1;
        }
        if (next_n > 100000000LL) next_n = 100000000LL;
        return -next_n;
    }

    if (pass_idx == 1) {
        g_timing_pass_elapsed_ns = g_pass_elapsed_ns;
        g_timing_pass_elapsed_cyc = g_pass_elapsed_cyc;
    } else if (pass_idx == 2) {
        int64_t net_b = 0;
        int64_t peak_b = 0;
        for (int32_t i = 0; i < g_nstks; i++) {
            uint8_t *cur = wing_get_stk_top(i);
            uint8_t *ent = g_bench_enter_top[i];
            uint8_t *pk = g_bench_peak_top[i];
            if (cur > pk) pk = cur;
            if (ent != NULL) {
                if (cur > ent) net_b += (int64_t)(cur - ent);
                if (pk > ent) peak_b += (int64_t)(pk - ent);
            }
        }
        g_bench_last_net_b = net_b;
        g_bench_last_peak_b = peak_b;
        g_bench_last_scratch_b = (peak_b > net_b) ? (peak_b - net_b) : 0;
        g_bench_last_allocs = g_pool_alloc_events - g_bench_enter_allocs;
        g_bench_last_frees = g_pool_free_events - g_bench_enter_frees;
        g_prof_mem_active = 0;
    }

    g_prof_active = 0;
    return cur_n;
}

void wing_bench_commit(wing_prof_str_t bench_name, int64_t final_n, int64_t bytes_per_op) {
    if (!wing_prof_ensure_buffers()) return;
    if (g_bench_result_count >= WING_PROF_MAX_BENCHMARKS) return;
    wing_bench_result_t *r = &g_bench_results[g_bench_result_count++];
    memset(r, 0, sizeof(*r));

    if (bench_name.data && bench_name.len > 0) {
        int64_t clen = bench_name.len < 127 ? bench_name.len : 127;
        memcpy(r->name, bench_name.data, (size_t)clen);
        r->name[clen] = '\0';
    }
    r->iters = final_n > 0 ? final_n : 1;
    r->ns_per_op = (double)g_timing_pass_elapsed_ns / (double)r->iters;
    r->cycles_per_op = (double)g_timing_pass_elapsed_cyc / (double)r->iters;
    int64_t bpo = bytes_per_op > 0 ? bytes_per_op : g_cur_bytes_per_op;
    r->bytes_per_op = bpo;
    if (bpo > 0 && r->ns_per_op > 0.0) {
        r->mb_per_sec = ((double)bpo * 1000.0) / r->ns_per_op;
    }
    r->net_b_per_op = g_bench_last_net_b;
    r->scratch_b_per_op = g_bench_last_scratch_b;
    r->peak_b = g_bench_last_peak_b;
    r->allocs_per_op = g_bench_last_allocs;
    r->frees_per_op = g_bench_last_frees;
    r->custom_metric_val = g_cur_metric_val;
    snprintf(r->custom_metric_unit, sizeof(r->custom_metric_unit), "%s", g_cur_metric_unit);

    int32_t sc = 0;
    for (int32_t i = 0; i < g_prof_dynamic_count && sc < WING_PROF_MAX_STAGES; i++) {
        wing_prof_stage_t *s = &g_prof_stages[i];
        if (s->count == 0 && s->scratch_bytes == 0 && s->net_bytes == 0 && s->pool_allocs == 0) {
            continue;
        }
        wing_bench_stage_snap_t *dst = &r->stages[sc++];
        snprintf(dst->name, sizeof(dst->name), "%s", s->name);
        dst->count = s->count;
        dst->self_cycles = s->self_cycles;
        dst->total_cycles = s->total_cycles;
        dst->min_cycles = s->min_cycles == UINT64_MAX ? 0 : s->min_cycles;
        dst->p50_cycles = wing_prof_stage_p50_cycles(i);
        dst->p99_cycles = wing_prof_stage_p99_cycles(i);
        dst->max_cycles = s->max_cycles;
        dst->net_bytes = s->net_bytes;
        dst->scratch_bytes = s->scratch_bytes;
        dst->peak_bytes = s->peak_bytes;
        dst->pool_allocs = s->pool_allocs;
        dst->pool_frees = s->pool_frees;
    }
    r->num_stages = sc;
}

void wing_bench_print_report(void) {
    if (g_bench_result_count == 0) return;

    printf("\n========================================================================================================="
           "===============\n");
    printf("  SUITE: %-56s (TSC ~%.2f GHz | rdtscp ovh: %llu cyc)\n", g_suite_name, g_tsc_freq_ghz,
           (unsigned long long)g_rdtsc_overhead_cycles);
    printf("==========================================================================================================="
           "=============\n");
    printf("%-34s | %9s | %9s | %9s | %9s | %8s | %9s | %9s\n", "Benchmark", "Iters", "ns/op", "cyc/op", "MB/s",
           "net B/op", "scr B/op", "allocs/op");
    printf("-----------------------------------+-----------+-----------+-----------+-----------+----------+-----------+"
           "-----------\n");

    for (int32_t b = 0; b < g_bench_result_count; b++) {
        const wing_bench_result_t *r = &g_bench_results[b];
        char mbs_buf[24];
        if (r->mb_per_sec > 0.0) {
            snprintf(mbs_buf, sizeof(mbs_buf), "%9.1f", r->mb_per_sec);
        } else {
            snprintf(mbs_buf, sizeof(mbs_buf), "%9s", "-");
        }
        printf("%-34s | %9lld | %9.1f | %9.1f | %s | %8lld | %9lld | %9lld", r->name, (long long)r->iters, r->ns_per_op,
               r->cycles_per_op, mbs_buf, (long long)r->net_b_per_op, (long long)r->scratch_b_per_op,
               (long long)r->allocs_per_op);
        if (r->custom_metric_unit[0] != '\0') {
            printf("  (%.2f %s)", r->custom_metric_val, r->custom_metric_unit);
        }
        printf("\n");
    }
    printf("==========================================================================================================="
           "=============\n");

    for (int32_t b = 0; b < g_bench_result_count; b++) {
        const wing_bench_result_t *r = &g_bench_results[b];
        if (r->num_stages == 0) continue;

        uint64_t sum_self = 0;
        for (int32_t i = 0; i < r->num_stages; i++) {
            sum_self += r->stages[i].self_cycles;
        }
        if (sum_self == 0) sum_self = 1;

        printf("\n  [Stage Breakdown: %s]\n", r->name);
        printf("  %-26s | %9s | %9s | %9s | %7s | %7s | %6s | %7s | %8s | %6s\n", "Stage", "Calls", "Self Cyc",
               "Total Cyc", "p50", "p99", "% Pipe", "Net B", "Scr B", "Allocs");
        printf("  "
               "---------------------------+-----------+-----------+-----------+---------+---------+--------+---------+"
               "----------+-------\n");

        for (int32_t i = 0; i < r->num_stages; i++) {
            const wing_bench_stage_snap_t *s = &r->stages[i];
            uint64_t calls = s->count > 0 ? s->count : 1;
            double self_avg = (double)s->self_cycles / (double)calls;
            double tot_avg = (double)s->total_cycles / (double)calls;
            double pct = ((double)s->self_cycles * 100.0) / (double)sum_self;
            printf("  %-26s | %9llu | %9.1f | %9.1f | %7llu | %7llu | %5.1f%% | %7lld | %8lld | %6lld\n", s->name,
                   (unsigned long long)s->count, self_avg, tot_avg, (unsigned long long)s->p50_cycles,
                   (unsigned long long)s->p99_cycles, pct, (long long)s->net_bytes, (long long)s->scratch_bytes,
                   (long long)s->pool_allocs);
        }
    }
    printf("\n");

    const char *no_tsv = getenv("WING_PROF_MACHINE_OUT");
    if (!no_tsv || no_tsv[0] != '0') {
        for (int32_t b = 0; b < g_bench_result_count; b++) {
            const wing_bench_result_t *r = &g_bench_results[b];
            printf("@WING_BENCH\t%s\t%s\t%lld\t%.3f\t%.3f\t%.3f\t%lld\t%lld\t%lld\t%lld\t%.4f\t%s\n", g_suite_name,
                   r->name, (long long)r->iters, r->ns_per_op, r->cycles_per_op, r->mb_per_sec,
                   (long long)r->net_b_per_op, (long long)r->scratch_b_per_op, (long long)r->peak_b,
                   (long long)r->allocs_per_op, r->custom_metric_val,
                   r->custom_metric_unit[0] ? r->custom_metric_unit : "-");

            uint64_t sum_self = 0;
            for (int32_t i = 0; i < r->num_stages; i++) {
                sum_self += r->stages[i].self_cycles;
            }
            if (sum_self == 0) sum_self = 1;

            for (int32_t i = 0; i < r->num_stages; i++) {
                const wing_bench_stage_snap_t *s = &r->stages[i];
                uint64_t calls = s->count > 0 ? s->count : 1;
                double self_avg = (double)s->self_cycles / (double)calls;
                double tot_avg = (double)s->total_cycles / (double)calls;
                double pct = ((double)s->self_cycles * 100.0) / (double)sum_self;
                printf("@WING_STAGE\t%s\t%s\t%llu\t%.3f\t%.3f\t%llu\t%llu\t%.2f\t%lld\t%lld\t%lld\t%lld\n", r->name,
                       s->name, (unsigned long long)s->count, self_avg, tot_avg, (unsigned long long)s->p50_cycles,
                       (unsigned long long)s->p99_cycles, pct, (long long)s->net_bytes, (long long)s->scratch_bytes,
                       (long long)s->peak_bytes, (long long)s->pool_allocs);
            }
        }
    }
}

void wing_prof_print_summary(void) {
    if (!g_prof_stages) {
        printf("[PROFILER] No samples recorded.\n");
        return;
    }
    uint64_t grand_self = 0;
    for (int32_t i = 0; i < g_prof_dynamic_count; i++) {
        grand_self += g_prof_stages[i].self_cycles;
    }
    if (grand_self == 0) {
        printf("[PROFILER] No samples recorded.\n");
        return;
    }

    printf("\n========================================================================================================="
           "=====\n");
    printf("                    GOOSE-WING SERVER PIPELINE CPU CLOCK CYCLE & MEMORY PROFILING REPORT                   "
           "   \n");
    printf("==========================================================================================================="
           "===\n");
    printf("%-26s | %9s | %9s | %9s | %7s | %7s | %6s | %8s | %8s\n", "Pipeline Stage", "Samples", "Self Avg",
           "Total Avg", "p50", "p99", "Pct %", "Scr B", "Allocs");
    printf("---------------------------+-----------+-----------+-----------+---------+---------+--------+----------+---"
           "-----\n");

    for (int32_t i = 0; i < g_prof_dynamic_count; i++) {
        wing_prof_stage_t *s = &g_prof_stages[i];
        if (s->count == 0) continue;
        double pct = ((double)s->self_cycles * 100.0) / (double)grand_self;
        double self_avg = (double)s->self_cycles / (double)s->count;
        double tot_avg = (double)s->total_cycles / (double)s->count;
        uint64_t p50 = wing_prof_stage_p50_cycles(i);
        uint64_t p99 = wing_prof_stage_p99_cycles(i);
        printf("%-26s | %9llu | %9.1f | %9.1f | %7llu | %7llu | %5.1f%% | %8lld | %6lld\n", s->name,
               (unsigned long long)s->count, self_avg, tot_avg, (unsigned long long)p50, (unsigned long long)p99, pct,
               (long long)s->scratch_bytes, (long long)s->pool_allocs);
    }
    printf("---------------------------+-----------+-----------+-----------+---------+---------+--------+----------+---"
           "-----\n");
    printf("%-26s | %9s | %9llu | %9s | %7s | %7s | 100.0%% | %8s | %6s\n", "TOTAL PIPELINE CYCLES", "-",
           (unsigned long long)grand_self, "-", "-", "-", "-", "-");
    printf("==========================================================================================================="
           "===\n\n");
}
