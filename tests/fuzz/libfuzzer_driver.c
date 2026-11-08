// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Coverage-guided C fuzzing driver for goose-wing.
// Supports two build modes:
//   1. Native LLVM libFuzzer mode (-DLIBFUZZER_MAIN=0 -fsanitize=fuzzer,address,undefined)
//   2. Standalone AFL++/SanitizerCoverage edge-feedback mode (-fsanitize-coverage=trace-pc)
//      with 64 KB edge-transition bitmap and hit-count bucketing.

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

typedef int32_t gs_i32;
typedef int64_t gs_i64;
typedef uint64_t gs_u64;

#pragma pack(push, 1)
typedef struct {
    uint8_t *data;
    int64_t len;
} sl_u8;
#pragma pack(pop)

#ifdef __cplusplus
extern "C" {
#endif
void goose_init(int argc, char **argv);
gs_u64 wing_fuzz_test_one(gs_i32 target_id, sl_u8 raw);
#ifdef __cplusplus
}
#endif

#define COV_MAP_SIZE 65536U
#define MAX_INPUT_LEN 16384U
#define MAX_CORPUS_CAP 4096U

static uint8_t g_trace_bits[COV_MAP_SIZE];
static uint8_t g_virgin_bits[COV_MAP_SIZE];
static uintptr_t g_prev_loc = 0;
static int g_initialized = 0;
static int32_t g_target_id = -1;

#if defined(__has_attribute)
#if __has_attribute(no_sanitize_coverage)
#define NO_SANITIZE_COV __attribute__((no_sanitize_coverage))
#else
#define NO_SANITIZE_COV
#endif
#elif defined(__GNUC__) && !defined(__clang__)
#define NO_SANITIZE_COV __attribute__((no_sanitize_coverage))
#else
#define NO_SANITIZE_COV
#endif

// Compiler callback inserted at every basic block by `-fsanitize-coverage=trace-pc`.
NO_SANITIZE_COV void __sanitizer_cov_trace_pc(void) {
    uintptr_t cur_loc = (uintptr_t)__builtin_return_address(0);
    cur_loc = (cur_loc >> 4) ^ (cur_loc << 8);
    uintptr_t idx = (cur_loc ^ g_prev_loc) & (COV_MAP_SIZE - 1U);
    if (g_trace_bits[idx] < 255U) {
        g_trace_bits[idx]++;
    }
    g_prev_loc = cur_loc >> 1;
}

NO_SANITIZE_COV int LLVMFuzzerInitialize(int *argc, char ***argv) {
    if (!g_initialized) {
        goose_init(*argc, *argv);
        memset(g_virgin_bits, 0xFF, sizeof(g_virgin_bits));
        g_initialized = 1;
    }
    const char *env_target = getenv("WING_FUZZ_TARGET_ID");
    if (env_target != NULL) {
        g_target_id = (int32_t)atoi(env_target);
    }
    return 0;
}

NO_SANITIZE_COV int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (!g_initialized) {
        int dummy_argc = 1;
        char *dummy_argv_buf[] = { (char *)"wing_fuzzer", NULL };
        char **dummy_argv = dummy_argv_buf;
        LLVMFuzzerInitialize(&dummy_argc, &dummy_argv);
    }
    if (size == 0) {
        return 0;
    }
    size_t clamped = size > MAX_INPUT_LEN ? MAX_INPUT_LEN : size;
    int32_t tid = g_target_id;
    const uint8_t *payload = data;
    size_t payload_len = clamped;
    if (tid < 0) {
        tid = (int32_t)(data[0] % 18U);
        if (clamped > 1U) {
            payload = data + 1;
            payload_len = clamped - 1U;
        }
    }
    sl_u8 slice;
    slice.data = (uint8_t *)payload;
    slice.len = (int64_t)payload_len;
    (void)wing_fuzz_test_one(tid, slice);
    return 0;
}

#ifndef LIBFUZZER_EXTERNAL_MAIN

typedef struct {
    uint8_t *bytes;
    size_t len;
} CorpusEntry;

static CorpusEntry g_corpus[MAX_CORPUS_CAP];
static size_t g_corpus_count = 0;

NO_SANITIZE_COV static uint8_t bucketize_hit_count(uint8_t n) {
    if (n == 0) return 0;
    if (n == 1) return 1;
    if (n == 2) return 2;
    if (n == 3) return 4;
    if (n <= 7) return 8;
    if (n <= 15) return 16;
    if (n <= 31) return 32;
    if (n <= 127) return 64;
    return 128;
}

NO_SANITIZE_COV static size_t evaluate_new_coverage(size_t *total_edges_out) {
    size_t new_hits = 0;
    size_t active_edges = 0;
    for (size_t i = 0; i < COV_MAP_SIZE; i++) {
        uint8_t raw = g_trace_bits[i];
        if (raw != 0) {
            uint8_t bucket = bucketize_hit_count(raw);
            if ((g_virgin_bits[i] & bucket) != 0) {
                g_virgin_bits[i] &= (uint8_t)(~bucket);
                new_hits++;
            }
        }
        if (g_virgin_bits[i] != 0xFF) {
            active_edges++;
        }
    }
    *total_edges_out = active_edges;
    return new_hits;
}

NO_SANITIZE_COV static void add_to_corpus(const uint8_t *buf, size_t len) {
    if (len == 0 || len > MAX_INPUT_LEN) {
        return;
    }
    uint8_t *copy = (uint8_t *)malloc(len);
    if (!copy) {
        return;
    }
    memcpy(copy, buf, len);
    if (g_corpus_count < MAX_CORPUS_CAP) {
        g_corpus[g_corpus_count].bytes = copy;
        g_corpus[g_corpus_count].len = len;
        g_corpus_count++;
    } else {
        size_t slot = (size_t)rand() % MAX_CORPUS_CAP;
        free(g_corpus[slot].bytes);
        g_corpus[slot].bytes = copy;
        g_corpus[slot].len = len;
    }
}

NO_SANITIZE_COV static uint64_t xorshift64(uint64_t *state) {
    uint64_t x = *state;
    x ^= x >> 12;
    x ^= x << 25;
    x ^= x >> 27;
    *state = x;
    return x * 0x2545F4914F6CDD1DULL;
}

NO_SANITIZE_COV static size_t mutate_buffer(uint8_t *buf, size_t len, size_t max_cap, uint64_t *rng) {
    static const char *const kDict[] = {
        "\r\n\r\n",
        "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n",
        "POST / HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n",
        "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n",
        ":method", ":path", ":authority", ":scheme", ":status",
        "__Host-sid=1; Secure; Path=/",
        "u=3, i=?0",
        "\x16\x03\x03\x00\x35\x01\x00\x00\x31\x03\x03",
        "\xc3\x00\x00\x00\x01\x08\x83\x94\xc8\xf0\x3e\x51\x57\x08",
        "\x6b\x33\x43\xcf",
        "\x30\x82\x01\x0a\x02\x82\x01\x01\x00"
    };
    if (len == 0) {
        const char *seed = kDict[xorshift64(rng) % 15U];
        size_t slen = strlen(seed);
        memcpy(buf, seed, slen);
        return slen;
    }

    uint64_t steps = 1U + (xorshift64(rng) & 3U);
    for (uint64_t s = 0; s < steps; s++) {
        uint64_t op = xorshift64(rng) % 6U;
        if (op == 0 && len > 0) {
            size_t pos = (size_t)(xorshift64(rng) % len);
            buf[pos] ^= (uint8_t)(1U << (xorshift64(rng) & 7U));
        } else if (op == 1 && len > 0) {
            size_t pos = (size_t)(xorshift64(rng) % len);
            buf[pos] = (uint8_t)(xorshift64(rng) & 0xFFU);
        } else if (op == 2 && len > 2) {
            size_t pos = (size_t)(xorshift64(rng) % (len - 1U));
            size_t del = 1U + (size_t)(xorshift64(rng) % (len - pos));
            if (del < len) {
                memmove(buf + pos, buf + pos + del, len - pos - del);
                len -= del;
            }
        } else if (op == 3) {
            const char *tok = kDict[xorshift64(rng) % 15U];
            size_t tlen = strlen(tok);
            if (len + tlen <= max_cap) {
                size_t pos = (size_t)(xorshift64(rng) % (len + 1U));
                memmove(buf + pos + tlen, buf + pos, len - pos);
                memcpy(buf + pos, tok, tlen);
                len += tlen;
            }
        } else if (op == 4 && g_corpus_count > 1) {
            const CorpusEntry *other = &g_corpus[xorshift64(rng) % g_corpus_count];
            if (other->len > 0 && len > 0) {
                size_t split_a = (size_t)(xorshift64(rng) % len);
                size_t split_b = (size_t)(xorshift64(rng) % other->len);
                size_t tail = other->len - split_b;
                if (split_a + tail <= max_cap) {
                    memcpy(buf + split_a, other->bytes + split_b, tail);
                    len = split_a + tail;
                }
            }
        } else if (op == 5 && len >= 2) {
            size_t pos = (size_t)(xorshift64(rng) % (len - 1U));
            uint16_t interesting[] = {0x0000, 0x003F, 0x007F, 0x0080, 0x00FF, 0x3FFF, 0x4000, 0xFFFF};
            uint16_t val = interesting[xorshift64(rng) & 7U];
            buf[pos] = (uint8_t)(val >> 8);
            buf[pos + 1] = (uint8_t)(val & 0xFFU);
        }
    }
    return len;
}

NO_SANITIZE_COV static void load_seed_file(const char *path) {
    FILE *f = fopen(path, "rb");
    if (!f) {
        return;
    }
    uint8_t tmp[MAX_INPUT_LEN];
    size_t n = fread(tmp, 1, sizeof(tmp), f);
    fclose(f);
    if (n > 0) {
        memset(g_trace_bits, 0, sizeof(g_trace_bits));
        g_prev_loc = 0;
        LLVMFuzzerTestOneInput(tmp, n);
        size_t edges = 0;
        (void)evaluate_new_coverage(&edges);
        add_to_corpus(tmp, n);
    }
}

NO_SANITIZE_COV static void load_seed_manifest(const char *manifest_path) {
    FILE *mf = fopen(manifest_path, "r");
    if (!mf) {
        return;
    }
    char line[2048];
    while (fgets(line, sizeof(line), mf) != NULL) {
        size_t len = strlen(line);
        while (len > 0 && (line[len - 1] == '\n' || line[len - 1] == '\r')) {
            line[--len] = '\0';
        }
        if (len > 0) {
            load_seed_file(line);
        }
    }
    fclose(mf);
}

NO_SANITIZE_COV int main(int argc, char **argv) {
    LLVMFuzzerInitialize(&argc, &argv);

    int32_t target_id = -1;
    uint64_t max_iters = 5000;
    uint64_t rng_state = 0xCAFEBABE98765432ULL ^ (uint64_t)time(NULL);

    if (argc >= 2) {
        target_id = (int32_t)atoi(argv[1]);
        g_target_id = target_id;
    }
    if (argc >= 3) {
        max_iters = (uint64_t)strtoull(argv[2], NULL, 10);
    }

    for (int i = 3; i < argc; i++) {
        if (argv[i][0] == '@') {
            load_seed_manifest(argv[i] + 1);
        } else {
            load_seed_file(argv[i]);
        }
    }

    if (g_corpus_count == 0) {
        const char *boot = "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n";
        add_to_corpus((const uint8_t *)boot, strlen(boot));
    }

    uint8_t work_buf[MAX_INPUT_LEN];
    size_t total_edges = 0;
    size_t new_cov_events = 0;

    for (uint64_t iter = 0; iter < max_iters; iter++) {
        const CorpusEntry *base = &g_corpus[xorshift64(&rng_state) % g_corpus_count];
        size_t cur_len = base->len;
        memcpy(work_buf, base->bytes, cur_len);
        cur_len = mutate_buffer(work_buf, cur_len, MAX_INPUT_LEN, &rng_state);

        memset(g_trace_bits, 0, sizeof(g_trace_bits));
        g_prev_loc = 0;
        LLVMFuzzerTestOneInput(work_buf, cur_len);

        size_t discovered = evaluate_new_coverage(&total_edges);
        if (discovered > 0) {
            add_to_corpus(work_buf, cur_len);
            new_cov_events++;
        }
    }

    printf(
        "OK SANCOV_EXECS: %llu CORPUS: %zu EDGES: %zu NEW_COV: %zu\n",
        (unsigned long long)max_iters,
        g_corpus_count,
        total_edges,
        new_cov_events
    );
    return 0;
}

#endif
