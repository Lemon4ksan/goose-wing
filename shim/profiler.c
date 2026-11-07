// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Hardware Cycle-Accurate Pipeline Profiler Shim for goose-wing
// Measures serialized RDTSC/RDTSCP clock cycles across server pipeline stages.

#include <stdint.h>
#include <stddef.h>
#include <stdio.h>

#if defined(_MSC_VER)
#include <intrin.h>
#elif defined(__x86_64__) || defined(__i386__)
#include <x86intrin.h>
#endif

#define WING_MAX_PROF_STAGES 16

typedef struct {
    const char *name;
    uint64_t total_cycles;
    uint64_t count;
    uint64_t min_cycles;
    uint64_t max_cycles;
} wing_prof_stage_t;

static wing_prof_stage_t g_prof_stages[WING_MAX_PROF_STAGES] = {
    {"0. Framing (CRLFCRLF)", 0, 0, UINT64_MAX, 0}, {"1. Request Line Parse", 0, 0, UINT64_MAX, 0},
    {"2. Headers Tokenize", 0, 0, UINT64_MAX, 0},   {"3. Host & Framing Val", 0, 0, UINT64_MAX, 0},
    {"4. Pipeline & GCRA", 0, 0, UINT64_MAX, 0},    {"5. Radix Router Match", 0, 0, UINT64_MAX, 0},
    {"6. Handler Execution", 0, 0, UINT64_MAX, 0},  {"7. Resp Serialization", 0, 0, UINT64_MAX, 0},
    {"8. Output Buffer Copy", 0, 0, UINT64_MAX, 0}, {"9. Socket Recv Syscall", 0, 0, UINT64_MAX, 0},
    {"10. Socket Send/Flush", 0, 0, UINT64_MAX, 0}, {"11. Misc/Overhead", 0, 0, UINT64_MAX, 0},
    {"12. Extra 1", 0, 0, UINT64_MAX, 0},           {"13. Extra 2", 0, 0, UINT64_MAX, 0},
    {"14. Extra 3", 0, 0, UINT64_MAX, 0},           {"15. Extra 4", 0, 0, UINT64_MAX, 0},
};

uint64_t wing_rdtsc(void) {
#if defined(__x86_64__) || defined(__i386__)
    unsigned int aux;
    return __rdtscp(&aux);
#elif defined(_M_X64) || defined(_M_IX86)
    unsigned int aux;
    return __rdtscp(&aux);
#else
    return 0;
#endif
}

void wing_prof_reset(void) {
    for (int i = 0; i < WING_MAX_PROF_STAGES; i++) {
        g_prof_stages[i].total_cycles = 0;
        g_prof_stages[i].count = 0;
        g_prof_stages[i].min_cycles = UINT64_MAX;
        g_prof_stages[i].max_cycles = 0;
    }
}

void wing_prof_record(int32_t stage_id, uint64_t cycles) {
    if (stage_id < 0 || stage_id >= WING_MAX_PROF_STAGES) return;
    wing_prof_stage_t *s = &g_prof_stages[stage_id];
    s->total_cycles += cycles;
    s->count++;
    if (cycles < s->min_cycles) s->min_cycles = cycles;
    if (cycles > s->max_cycles) s->max_cycles = cycles;
}

uint64_t wing_prof_total_cycles(int32_t stage_id) {
    if (stage_id < 0 || stage_id >= WING_MAX_PROF_STAGES) return 0;
    return g_prof_stages[stage_id].total_cycles;
}

uint64_t wing_prof_sample_count(int32_t stage_id) {
    if (stage_id < 0 || stage_id >= WING_MAX_PROF_STAGES) return 0;
    return g_prof_stages[stage_id].count;
}

uint64_t wing_prof_min_cycles(int32_t stage_id) {
    if (stage_id < 0 || stage_id >= WING_MAX_PROF_STAGES) return 0;
    return g_prof_stages[stage_id].min_cycles == UINT64_MAX ? 0 : g_prof_stages[stage_id].min_cycles;
}

uint64_t wing_prof_max_cycles(int32_t stage_id) {
    if (stage_id < 0 || stage_id >= WING_MAX_PROF_STAGES) return 0;
    return g_prof_stages[stage_id].max_cycles;
}

double wing_prof_avg_cycles(int32_t stage_id) {
    if (stage_id < 0 || stage_id >= WING_MAX_PROF_STAGES) return 0.0;
    if (g_prof_stages[stage_id].count == 0) return 0.0;
    return (double)g_prof_stages[stage_id].total_cycles / (double)g_prof_stages[stage_id].count;
}

void wing_prof_print_summary(void) {
    uint64_t grand_total = 0;
    for (int i = 0; i < WING_MAX_PROF_STAGES; i++) {
        grand_total += g_prof_stages[i].total_cycles;
    }
    if (grand_total == 0) {
        printf("[PROFILER] No samples recorded.\n");
        return;
    }

    printf("\n========================================================================================\n");
    printf("              GOOSE-WING SERVER PIPELINE CPU CLOCK CYCLE PROFILING REPORT               \n");
    printf("========================================================================================\n");
    printf("%-26s | %10s | %12s | %10s | %10s | %6s\n", "Pipeline Stage", "Samples", "Total Cycles", "Avg Cycles",
           "Min Cycles", "Pct %");
    printf("---------------------------+------------+--------------+------------+------------+--------\n");

    for (int i = 0; i < WING_MAX_PROF_STAGES; i++) {
        if (g_prof_stages[i].count == 0) continue;
        double pct = ((double)g_prof_stages[i].total_cycles * 100.0) / (double)grand_total;
        double avg = (double)g_prof_stages[i].total_cycles / (double)g_prof_stages[i].count;
        printf("%-26s | %10llu | %12llu | %10.1f | %10llu | %5.1f%%\n", g_prof_stages[i].name,
               (unsigned long long)g_prof_stages[i].count, (unsigned long long)g_prof_stages[i].total_cycles, avg,
               (unsigned long long)g_prof_stages[i].min_cycles, pct);
    }
    printf("---------------------------+------------+--------------+------------+------------+--------\n");
    printf("%-26s | %10s | %12llu | %10s | %10s | 100.0%%\n", "TOTAL PIPELINE CYCLES", "-",
           (unsigned long long)grand_total, "-", "-");
    printf("========================================================================================\n\n");
}
