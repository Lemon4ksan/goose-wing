// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Coverage-guided C fuzzing driver for goose-wing.
// Supports two build modes:
//   1. Native LLVM libFuzzer mode (-DLIBFUZZER_EXTERNAL_MAIN=1 -fsanitize=fuzzer,address,undefined)
//   2. Standalone AFL++/SanitizerCoverage edge-feedback mode (-fsanitize-coverage=trace-pc)
//      with 64 KB edge-transition bitmap, hit-count bucketing, constant-RAM RSS drift gate,
//      per-input monotonic time ceiling, and deterministic O(n) complexity DoS verification.

#if defined(__linux__) && !defined(_POSIX_C_SOURCE)
#define _POSIX_C_SOURCE 200809L
#endif

#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#if defined(_WIN32)
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#elif defined(__APPLE__)
#include <mach/mach.h>
#include <unistd.h>
#elif defined(__linux__)
#include <unistd.h>
#endif

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
gs_i32 wing_fuzz_target_count(void);
gs_i32 wing_fuzz_target_name(gs_i32 target_id, sl_u8 dst);
gs_u64 wing_fuzz_test_one(gs_i32 target_id, sl_u8 raw);
#ifdef __cplusplus
}
#endif

#define COV_MAP_SIZE 65536U
#define MAX_INPUT_LEN 16384U
#define MAX_CORPUS_CAP 4096U
#define MAX_TRACKED_TARGETS 128U
#define DEFAULT_MAX_RSS_DRIFT_KB 1024ULL
#define DEFAULT_MAX_INPUT_MS 50ULL
#define COMPLEXITY_FLOOR_NS 50000ULL
#define COMPLEXITY_MAX_RATIO 64.0
#define COMPLEXITY_NUM_PATTERNS 8U
#define COMPLEXITY_REPS 5U

typedef struct {
    uint64_t exec_count;
    uint64_t total_ns;
    uint64_t max_ns;
    size_t max_input_len;
} TargetTimingStats;

static uint8_t g_trace_bits[COV_MAP_SIZE];
static uint8_t g_virgin_bits[COV_MAP_SIZE];
static uintptr_t g_prev_loc = 0;
static int g_initialized = 0;
static int32_t g_target_id = -1;
static int32_t g_target_count = 0;
static uint64_t g_max_rss_drift_kb = DEFAULT_MAX_RSS_DRIFT_KB;
static uint64_t g_max_input_ms = DEFAULT_MAX_INPUT_MS;
static int g_abort_on_slow_input = 1;
static TargetTimingStats g_target_stats[MAX_TRACKED_TARGETS];

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

// ---- Portable Monotonic Clock & Process RSS Measurement --------------------

NO_SANITIZE_COV static uint64_t monotonic_ns(void) {
#if defined(_WIN32)
    static uint64_t s_qpf = 0;
    if (s_qpf == 0) {
        LARGE_INTEGER freq;
        if (QueryPerformanceFrequency(&freq) && freq.QuadPart > 0) {
            s_qpf = (uint64_t)freq.QuadPart;
        } else {
            s_qpf = 1;
        }
    }
    LARGE_INTEGER now;
    QueryPerformanceCounter(&now);
    uint64_t ticks = (uint64_t)now.QuadPart;
    uint64_t sec = ticks / s_qpf;
    uint64_t rem = ticks % s_qpf;
    return sec * 1000000000ULL + (rem * 1000000000ULL) / s_qpf;
#else
    struct timespec ts;
    if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0) {
        return 0;
    }
    return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
#endif
}

#ifndef LIBFUZZER_EXTERNAL_MAIN

#if defined(_WIN32)
typedef struct {
    DWORD cb;
    DWORD PageFaultCount;
    SIZE_T PeakWorkingSetSize;
    SIZE_T WorkingSetSize;
    SIZE_T QuotaPeakPagedPoolUsage;
    SIZE_T QuotaPagedPoolUsage;
    SIZE_T QuotaPeakNonPagedPoolUsage;
    SIZE_T QuotaNonPagedPoolUsage;
    SIZE_T PagefileUsage;
    SIZE_T PeakPagefileUsage;
} WingProcessMemoryCounters;

typedef BOOL(WINAPI *WingGetProcessMemoryInfoFn)(HANDLE, WingProcessMemoryCounters *, DWORD);

NO_SANITIZE_COV static WingGetProcessMemoryInfoFn resolve_win_mem_info(void) {
    static int s_probed = 0;
    static WingGetProcessMemoryInfoFn s_fn = NULL;
    if (s_probed) {
        return s_fn;
    }
    s_probed = 1;
    HMODULE k32 = GetModuleHandleA("kernel32.dll");
    if (k32 != NULL) {
        FARPROC sym = GetProcAddress(k32, "K32GetProcessMemoryInfo");
        if (sym != NULL) {
            memcpy(&s_fn, &sym, sizeof(s_fn));
            return s_fn;
        }
    }
    HMODULE psapi = LoadLibraryA("psapi.dll");
    if (psapi != NULL) {
        FARPROC sym = GetProcAddress(psapi, "GetProcessMemoryInfo");
        if (sym != NULL) {
            memcpy(&s_fn, &sym, sizeof(s_fn));
        }
    }
    return s_fn;
}
#endif

NO_SANITIZE_COV static uint64_t read_process_rss_bytes(void) {
#if defined(_WIN32)
    WingGetProcessMemoryInfoFn fn = resolve_win_mem_info();
    if (fn == NULL) {
        return 0;
    }
    WingProcessMemoryCounters pmc;
    memset(&pmc, 0, sizeof(pmc));
    pmc.cb = (DWORD)sizeof(pmc);
    if (!fn(GetCurrentProcess(), &pmc, pmc.cb)) {
        return 0;
    }
    // Prefer private committed bytes (PagefileUsage) over WorkingSetSize so lazy demand-paging of
    // read-only .text/.rdata code pages during coverage expansion does not trigger false RSS drift.
    return (uint64_t)(pmc.PagefileUsage != 0 ? pmc.PagefileUsage : pmc.WorkingSetSize);
#elif defined(__linux__)
    FILE *f = fopen("/proc/self/statm", "r");
    if (f == NULL) {
        return 0;
    }
    unsigned long long total_pages = 0;
    unsigned long long resident_pages = 0;
    int matched = fscanf(f, "%llu %llu", &total_pages, &resident_pages);
    fclose(f);
    if (matched != 2) {
        return 0;
    }
    long page_size = sysconf(_SC_PAGESIZE);
    if (page_size <= 0) {
        page_size = 4096;
    }
    return (uint64_t)resident_pages * (uint64_t)page_size;
#elif defined(__APPLE__)
    struct mach_task_basic_info info;
    mach_msg_type_number_t count = MACH_TASK_BASIC_INFO_COUNT;
    kern_return_t kr = task_info(mach_task_self(), MACH_TASK_BASIC_INFO, (task_info_t)&info, &count);
    if (kr != KERN_SUCCESS) {
        return 0;
    }
    return (uint64_t)info.resident_size;
#else
    return 0;
#endif
}

#endif // !LIBFUZZER_EXTERNAL_MAIN

NO_SANITIZE_COV static void fetch_target_name(int32_t tid, char *out, size_t out_cap) {
    if (out == NULL || out_cap == 0) {
        return;
    }
    uint8_t raw[64];
    sl_u8 dst;
    dst.data = raw;
    dst.len = (int64_t)(out_cap - 1U < sizeof(raw) ? out_cap - 1U : sizeof(raw));
    int32_t n = wing_fuzz_target_name(tid, dst);
    if (n <= 0) {
        snprintf(out, out_cap, "target_%d", (int)tid);
        return;
    }
    size_t copy_n = (size_t)n;
    if (copy_n >= out_cap) {
        copy_n = out_cap - 1U;
    }
    memcpy(out, raw, copy_n);
    out[copy_n] = '\0';
}

NO_SANITIZE_COV static uint64_t run_target_timed(int32_t tid, const uint8_t *payload, size_t payload_len) {
    sl_u8 slice;
    slice.data = (uint8_t *)payload;
    slice.len = (int64_t)payload_len;

    uint64_t t0 = monotonic_ns();
    (void)wing_fuzz_test_one(tid, slice);
    uint64_t t1 = monotonic_ns();
    uint64_t elapsed_ns = (t1 >= t0) ? (t1 - t0) : 0ULL;

    if (tid >= 0 && (uint32_t)tid < MAX_TRACKED_TARGETS) {
        TargetTimingStats *st = &g_target_stats[tid];
        st->exec_count++;
        st->total_ns += elapsed_ns;
        if (elapsed_ns > st->max_ns) {
            st->max_ns = elapsed_ns;
            st->max_input_len = payload_len;
        }
    }

    if (g_abort_on_slow_input && payload_len <= MAX_INPUT_LEN && g_max_input_ms > 0 &&
        elapsed_ns > g_max_input_ms * 1000000ULL) {
        char name[64];
        fetch_target_name(tid, name, sizeof(name));
        fprintf(stderr,
                "FAIL INPUT_TIME_CEILING_EXCEEDED target=%d (%s) len=%zu elapsed_ms=%.3f limit_ms=%" PRIu64 " hex=",
                (int)tid, name, payload_len, (double)elapsed_ns / 1e6, g_max_input_ms);
        size_t hex_n = payload_len < 32U ? payload_len : 32U;
        for (size_t i = 0; i < hex_n; i++) {
            fprintf(stderr, "%02x", (unsigned)payload[i]);
        }
        fprintf(stderr, "\n");
        fflush(stderr);
        exit(EXIT_FAILURE);
    }
    return elapsed_ns;
}

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
        memset(g_target_stats, 0, sizeof(g_target_stats));
        g_target_count = wing_fuzz_target_count();
        if (g_target_count <= 0) {
            fprintf(stderr, "FAIL wing_fuzz_target_count() returned %d\n", (int)g_target_count);
            exit(EXIT_FAILURE);
        }
        g_initialized = 1;
    }
    const char *env_target = getenv("WING_FUZZ_TARGET_ID");
    if (env_target != NULL && env_target[0] != '\0') {
        g_target_id = (int32_t)atoi(env_target);
    }
    const char *env_rss = getenv("WING_FUZZ_MAX_RSS_DRIFT_KB");
    if (env_rss != NULL && env_rss[0] != '\0') {
        g_max_rss_drift_kb = (uint64_t)strtoull(env_rss, NULL, 10);
    }
    const char *env_ms = getenv("WING_FUZZ_MAX_INPUT_MS");
    if (env_ms != NULL && env_ms[0] != '\0') {
        g_max_input_ms = (uint64_t)strtoull(env_ms, NULL, 10);
    }
    return 0;
}

NO_SANITIZE_COV int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (!g_initialized) {
        int dummy_argc = 1;
        char *dummy_argv_buf[] = {(char *)"wing_fuzzer", NULL};
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
        uint32_t count = (uint32_t)g_target_count;
        tid = (int32_t)((uint32_t)data[0] % count);
        if (clamped > 1U) {
            payload = data + 1;
            payload_len = clamped - 1U;
        }
    }
    (void)run_target_timed(tid, payload, payload_len);
    return 0;
}

#ifndef LIBFUZZER_EXTERNAL_MAIN

typedef struct {
    uint8_t *bytes;
    size_t len;
} CorpusEntry;

static CorpusEntry g_corpus[MAX_CORPUS_CAP];
static size_t g_corpus_count = 0;
static size_t g_driver_corpus_bytes = 0;
static uint64_t g_rng_state = 0xCAFEBABE98765432ULL;
static const char *g_corpus_out_dir = NULL;
static size_t g_saved_corpus_files = 0;

#define MAX_PERSIST_CORPUS_PER_RUN 256U

NO_SANITIZE_COV static uint64_t fnv1a64(const uint8_t *buf, size_t len) {
    uint64_t h = 0xCBF29CE484222325ULL;
    for (size_t i = 0; i < len; i++) {
        h ^= (uint64_t)buf[i];
        h *= 0x100000001B3ULL;
    }
    return h;
}

NO_SANITIZE_COV static void persist_corpus_entry(const uint8_t *buf, size_t len) {
    if (g_corpus_out_dir == NULL || g_corpus_out_dir[0] == '\0') {
        return;
    }
    if (len == 0 || len > MAX_INPUT_LEN || g_saved_corpus_files >= MAX_PERSIST_CORPUS_PER_RUN) {
        return;
    }
    uint64_t h = fnv1a64(buf, len);
    char path[1024];
    int n = snprintf(path, sizeof(path), "%s/cov_%016" PRIx64 ".bin", g_corpus_out_dir, h);
    if (n <= 0 || (size_t)n >= sizeof(path)) {
        return;
    }
    FILE *probe = fopen(path, "rb");
    if (probe != NULL) {
        fclose(probe);
        return;
    }
    FILE *out = fopen(path, "wb");
    if (out == NULL) {
        return;
    }
    (void)fwrite(buf, 1, len, out);
    fclose(out);
    g_saved_corpus_files++;
}

NO_SANITIZE_COV static uint64_t xorshift64(uint64_t *state) {
    uint64_t x = *state;
    if (x == 0) {
        x = 0x9E3779B97F4A7C15ULL;
    }
    x ^= x >> 12;
    x ^= x << 25;
    x ^= x >> 27;
    *state = x;
    return x * 0x2545F4914F6CDD1DULL;
}

NO_SANITIZE_COV static int64_t compute_target_rss_drift_bytes(uint64_t cur_rss, uint64_t base_rss, size_t cur_corpus,
                                                              size_t base_corpus) {
    int64_t rss_delta = (cur_rss >= base_rss) ? (int64_t)(cur_rss - base_rss) : -(int64_t)(base_rss - cur_rss);
    int64_t corpus_delta =
        (cur_corpus >= base_corpus) ? (int64_t)(cur_corpus - base_corpus) : -(int64_t)(base_corpus - cur_corpus);
    int64_t drift = rss_delta - corpus_delta;
    return drift > 0 ? drift : 0;
}

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
        g_driver_corpus_bytes += len;
    } else {
        size_t slot = (size_t)(xorshift64(&g_rng_state) % MAX_CORPUS_CAP);
        g_driver_corpus_bytes -= g_corpus[slot].len;
        free(g_corpus[slot].bytes);
        g_corpus[slot].bytes = copy;
        g_corpus[slot].len = len;
        g_driver_corpus_bytes += len;
    }
}

typedef struct {
    const char *bytes;
    size_t len;
} FuzzDictToken;

#define FUZZ_DICT_ENTRY(lit) {(lit), sizeof(lit) - 1U}

NO_SANITIZE_COV static size_t mutate_buffer(uint8_t *buf, size_t len, size_t max_cap, uint64_t *rng) {
    static const FuzzDictToken kDict[] = {
        FUZZ_DICT_ENTRY("\r\n\r\n"),
        FUZZ_DICT_ENTRY("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"),
        FUZZ_DICT_ENTRY("POST / HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n"),
        FUZZ_DICT_ENTRY("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"),
        FUZZ_DICT_ENTRY(":method"),
        FUZZ_DICT_ENTRY(":path"),
        FUZZ_DICT_ENTRY(":authority"),
        FUZZ_DICT_ENTRY(":scheme"),
        FUZZ_DICT_ENTRY(":status"),
        FUZZ_DICT_ENTRY("__Host-sid=1; Secure; Path=/"),
        FUZZ_DICT_ENTRY("u=3, i=?0"),
        FUZZ_DICT_ENTRY("--boundary\r\nContent-Disposition: form-data; name=\"a\"\r\n\r\nv\r\n--boundary--\r\n"),
        FUZZ_DICT_ENTRY("\x16\x03\x03\x00\x35\x01\x00\x00\x31\x03\x03"),
        FUZZ_DICT_ENTRY("\xc3\x00\x00\x00\x01\x08\x83\x94\xc8\xf0\x3e\x51\x57\x08"),
        FUZZ_DICT_ENTRY("\x6b\x33\x43\xcf"),
        FUZZ_DICT_ENTRY("\x30\x82\x01\x0a\x02\x82\x01\x01\x00"),
        FUZZ_DICT_ENTRY("-----BEGIN CERTIFICATE-----\n"),
        FUZZ_DICT_ENTRY("-----END CERTIFICATE-----\n"),
        FUZZ_DICT_ENTRY("-----BEGIN PRIVATE KEY-----\n"),
        FUZZ_DICT_ENTRY("-----END PRIVATE KEY-----\n"),
        FUZZ_DICT_ENTRY(
            "sig1=(\"@method\" \"@authority\" \"@path\");created=1700000000;keyid=\"k1\";alg=\"hmac-sha256\""),
        FUZZ_DICT_ENTRY("sha-256=:47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=:"),
        FUZZ_DICT_ENTRY("Digest realm=\"api\", nonce=\"abcd\", qop=\"auth\", algorithm=SHA-256"),
        FUZZ_DICT_ENTRY("PrivateToken challenge=AAAA, token-key=BBBB"),
        FUZZ_DICT_ENTRY("{\"keys\":[{\"kty\":\"OKP\",\"crv\":\"Ed25519\",\"kid\":\"k1\",\"x\":\"11qYAYKxCrfVS_"
                        "7TyWQHOg7hcvPapiMlrwIaaPcHURo\"}]}"),
        FUZZ_DICT_ENTRY(
            "eyJhbGciOiJFZERTQSIsInR5cCI6ImRwb3Arand0In0."
            "eyJodG0iOiJQT1NUIiwiaHR1IjoiaHR0cHM6Ly9hcGkuZXhhbXBsZS5jb20vdG9rIiwiaWF0IjoxNzAwMDAwMDAwLCJqdGkiOiIxIn0."),
        FUZZ_DICT_ENTRY("\x00\x00\x20\x00\x04\x00\x01\x00\x01"),
        FUZZ_DICT_ENTRY("\x00\x03GET\x05https\x0bexample.com\x01/"),
        FUZZ_DICT_ENTRY("\x00\x31\x00\x2f\x00"),
        FUZZ_DICT_ENTRY("\xf0\x00\x00\x00\x01\x08"),
        FUZZ_DICT_ENTRY("\xff\x6b\x33\x43\xcf\x08")};
    const size_t dict_len = sizeof(kDict) / sizeof(kDict[0]);
    if (len == 0) {
        const FuzzDictToken *seed = &kDict[xorshift64(rng) % dict_len];
        size_t slen = seed->len > max_cap ? max_cap : seed->len;
        memcpy(buf, seed->bytes, slen);
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
            const FuzzDictToken *tok = &kDict[xorshift64(rng) % dict_len];
            size_t tlen = tok->len;
            if (len + tlen <= max_cap) {
                size_t pos = (size_t)(xorshift64(rng) % (len + 1U));
                memmove(buf + pos + tlen, buf + pos, len - pos);
                memcpy(buf + pos, tok->bytes, tlen);
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

NO_SANITIZE_COV static void bootstrap_default_corpus(void) {
    static const char *const kSeeds[] = {
        "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n",
        "HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello",
        "POST /up HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n",
        "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n",
        "--boundary\r\nContent-Disposition: form-data; name=\"k\"\r\n\r\nv\r\n--boundary--\r\n",
        "\x16\x03\x01\x00\x20\x01\x00\x00\x1c\x03\x03\x00\x01\x02\x03\x04",
        "\x30\x82\x00\x10\x02\x01\x01\x04\x04test",
        "https://user:pass@example.com:8443/a/../b?k=v"};
    const size_t n_seeds = sizeof(kSeeds) / sizeof(kSeeds[0]);
    uint8_t buf[256];
    for (int32_t tid = 0; tid < g_target_count; tid++) {
        const char *s = kSeeds[(size_t)tid % n_seeds];
        size_t slen = strlen(s);
        if (slen + 1U > sizeof(buf)) {
            slen = sizeof(buf) - 1U;
        }
        buf[0] = (uint8_t)(tid & 0xFF);
        memcpy(buf + 1, s, slen);
        add_to_corpus(buf, slen + 1U);
    }
}

// ---- Deterministic O(n) Adversarial Complexity Gate ------------------------

NO_SANITIZE_COV static const char *complexity_pattern_name(uint32_t pat) {
    static const char *const kNames[COMPLEXITY_NUM_PATTERNS] = {
        "hdr_colons", "chunk_ext", "url_pct20", "asn1_3082", "hpack_ff", "mp_boundary", "dns_c00c", "quotes_slash"};
    return kNames[pat % COMPLEXITY_NUM_PATTERNS];
}

NO_SANITIZE_COV static void fill_repeated(uint8_t *dst, size_t len, const uint8_t *pat, size_t plen) {
    size_t pos = 0;
    while (pos < len) {
        size_t take = len - pos;
        if (take > plen) {
            take = plen;
        }
        memcpy(dst + pos, pat, take);
        pos += take;
    }
}

NO_SANITIZE_COV static void build_adversarial_pattern(uint32_t pat_id, uint8_t *buf, size_t len) {
    if (len == 0) {
        return;
    }
    if (pat_id == 0U) {
        const char *hdr = "GET / HTTP/1.1\r\nHost: a\r\n";
        const char *rep = "X-H:   :   :   \r\n";
        size_t hlen = strlen(hdr);
        if (hlen >= len) {
            memcpy(buf, hdr, len);
            return;
        }
        memcpy(buf, hdr, hlen);
        size_t body_len = len > hlen + 2U ? len - hlen - 2U : 0U;
        fill_repeated(buf + hlen, body_len, (const uint8_t *)rep, strlen(rep));
        if (hlen + body_len + 2U <= len) {
            buf[len - 2U] = '\r';
            buf[len - 1U] = '\n';
        }
        return;
    }
    if (pat_id == 1U) {
        const char *rep = "1;ext=val;ext=val;ext=val\r\na\r\n";
        size_t body_len = len > 5U ? len - 5U : len;
        fill_repeated(buf, body_len, (const uint8_t *)rep, strlen(rep));
        if (len > 5U) {
            memcpy(buf + body_len, "0\r\n\r\n", 5U);
        }
        return;
    }
    if (pat_id == 2U) {
        const char *pre = "https://example.com/";
        const char *rep = "%20a/../";
        size_t plen = strlen(pre);
        if (plen >= len) {
            memcpy(buf, pre, len);
            return;
        }
        memcpy(buf, pre, plen);
        fill_repeated(buf + plen, len - plen, (const uint8_t *)rep, strlen(rep));
        return;
    }
    if (pat_id == 3U) {
        size_t pos = 0;
        while (pos + 4U <= len) {
            size_t rem = len - pos - 4U;
            buf[pos + 0U] = 0x30U;
            buf[pos + 1U] = 0x82U;
            buf[pos + 2U] = (uint8_t)((rem >> 8) & 0xFFU);
            buf[pos + 3U] = (uint8_t)(rem & 0xFFU);
            pos += 4U;
        }
        while (pos < len) {
            buf[pos++] = 0x00U;
        }
        return;
    }
    if (pat_id == 4U) {
        buf[0] = 0x00U;
        if (len > 1U) {
            buf[1] = 0x7FU;
        }
        for (size_t i = 2U; i < len; i++) {
            buf[i] = 0xFFU;
        }
        return;
    }
    if (pat_id == 5U) {
        const char *rep = "--boundary\r\nContent-Disposition: form-data; name=\"a\"\r\n\r\n--boundar";
        fill_repeated(buf, len, (const uint8_t *)rep, strlen(rep));
        return;
    }
    if (pat_id == 6U) {
        static const uint8_t kDnsHdr[12] = {0x12, 0x34, 0x81, 0x80, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00};
        static const uint8_t kPtr[2] = {0xC0, 0x0C};
        if (len <= sizeof(kDnsHdr)) {
            memcpy(buf, kDnsHdr, len);
            return;
        }
        memcpy(buf, kDnsHdr, sizeof(kDnsHdr));
        fill_repeated(buf + sizeof(kDnsHdr), len - sizeof(kDnsHdr), kPtr, sizeof(kPtr));
        return;
    }
    const char *rep = "\"\\\"\\\\/\"\\\"\\\\/";
    fill_repeated(buf, len, (const uint8_t *)rep, strlen(rep));
}

NO_SANITIZE_COV static uint64_t measure_pattern_trimmed_ns(int32_t tid, const uint8_t *buf, size_t len) {
    uint64_t samples[COMPLEXITY_REPS];
    for (uint32_t r = 0; r < COMPLEXITY_REPS; r++) {
        samples[r] = run_target_timed(tid, buf, len);
    }
    for (uint32_t i = 1; i < COMPLEXITY_REPS; i++) {
        uint64_t key = samples[i];
        uint32_t j = i;
        while (j > 0 && samples[j - 1] > key) {
            samples[j] = samples[j - 1];
            j--;
        }
        samples[j] = key;
    }
    uint64_t mid_sum = samples[1] + samples[2] + samples[3];
    return mid_sum / 3ULL;
}

NO_SANITIZE_COV static int run_complexity_gate(int32_t filter_tid, int need_warmup) {
    static uint8_t s_pat_1k[1024];
    static uint8_t s_pat_4k[4096];
    static uint8_t s_pat_16k[16384];

    int32_t first_tid = (filter_tid >= 0 && filter_tid < g_target_count) ? filter_tid : 0;
    int32_t last_tid = (filter_tid >= 0 && filter_tid < g_target_count) ? filter_tid : (g_target_count - 1);

    int saved_abort = g_abort_on_slow_input;
    g_abort_on_slow_input = 0;

    /* Pre-fault each target's fixed data-stack working set at max 16 KB payload size before
       recording sweep_base_rss so one-time OS demand paging is not misclassified as a leak. */
    (void)need_warmup;
    build_adversarial_pattern(0U, s_pat_16k, sizeof(s_pat_16k));
    for (int32_t tid = first_tid; tid <= last_tid; tid++) {
        (void)run_target_timed(tid, s_pat_16k, sizeof(s_pat_16k));
    }
    build_adversarial_pattern(4U, s_pat_16k, sizeof(s_pat_16k));
    for (int32_t tid = first_tid; tid <= last_tid; tid++) {
        (void)run_target_timed(tid, s_pat_16k, sizeof(s_pat_16k));
    }

    uint64_t sweep_base_rss = read_process_rss_bytes();
    size_t sweep_base_corpus = g_driver_corpus_bytes;
    uint64_t sweep_peak_rss = sweep_base_rss;
    uint64_t max_rss_drift_bytes = g_max_rss_drift_kb * 1024ULL;
    uint64_t max_input_ns = g_max_input_ms * 1000000ULL;

    printf("\n=== O(n) Complexity & Constant-RAM Gate (%d targets, max_16kb=%" PRIu64
           "ms, max_ratio=%.1fx, max_rss=%" PRIu64 "KB) ===\n",
           (int)(last_tid - first_tid + 1), g_max_input_ms, COMPLEXITY_MAX_RATIO, g_max_rss_drift_kb);
    printf("%-3s %-24s %9s %9s %9s %7s %11s %-13s %s\n", "ID", "TARGET", "1KB(us)", "4KB(us)", "16KB(us)", "RATIO",
           "RSS_DR(KB)", "WORST_PAT", "STATUS");

    int failures = 0;
    int passed = 0;
    int total = 0;
    double global_max_ratio = 0.0;
    uint64_t global_max_16k_ns = 0;
    int64_t global_max_drift_bytes = 0;

    for (int32_t tid = first_tid; tid <= last_tid; tid++) {
        total++;
        double worst_ratio = 0.0;
        uint64_t rep_1k_ns = 0;
        uint64_t rep_4k_ns = 0;
        uint64_t rep_16k_ns = 0;
        uint64_t target_max_16k_ns = 0;
        uint32_t worst_pat = 0;

        for (uint32_t p = 0; p < COMPLEXITY_NUM_PATTERNS; p++) {
            build_adversarial_pattern(p, s_pat_1k, sizeof(s_pat_1k));
            build_adversarial_pattern(p, s_pat_4k, sizeof(s_pat_4k));
            build_adversarial_pattern(p, s_pat_16k, sizeof(s_pat_16k));

            uint64_t t1k = measure_pattern_trimmed_ns(tid, s_pat_1k, sizeof(s_pat_1k));
            uint64_t t4k = measure_pattern_trimmed_ns(tid, s_pat_4k, sizeof(s_pat_4k));
            uint64_t t16k = measure_pattern_trimmed_ns(tid, s_pat_16k, sizeof(s_pat_16k));

            uint64_t denom_ns = t1k > COMPLEXITY_FLOOR_NS ? t1k : COMPLEXITY_FLOOR_NS;
            double ratio = (double)t16k / (double)denom_ns;

            if (t16k > target_max_16k_ns) {
                target_max_16k_ns = t16k;
            }
            if (p == 0U || ratio > worst_ratio || (ratio == worst_ratio && t16k > rep_16k_ns)) {
                worst_ratio = ratio;
                rep_1k_ns = t1k;
                rep_4k_ns = t4k;
                rep_16k_ns = t16k;
                worst_pat = p;
            }
        }

        uint64_t cur_rss = read_process_rss_bytes();
        if (cur_rss > sweep_peak_rss) {
            sweep_peak_rss = cur_rss;
        }
        int64_t drift_bytes =
            compute_target_rss_drift_bytes(cur_rss, sweep_base_rss, g_driver_corpus_bytes, sweep_base_corpus);
        if (drift_bytes > global_max_drift_bytes) {
            global_max_drift_bytes = drift_bytes;
        }
        if (worst_ratio > global_max_ratio) {
            global_max_ratio = worst_ratio;
        }
        if (target_max_16k_ns > global_max_16k_ns) {
            global_max_16k_ns = target_max_16k_ns;
        }

        int time_ok = (g_max_input_ms == 0) || (target_max_16k_ns <= max_input_ns);
        int ratio_ok = worst_ratio <= COMPLEXITY_MAX_RATIO;
        int rss_ok = (uint64_t)drift_bytes <= max_rss_drift_bytes;
        int ok = time_ok && ratio_ok && rss_ok;
        if (ok) {
            passed++;
        } else {
            failures++;
        }

        char name[64];
        fetch_target_name(tid, name, sizeof(name));
        printf("%-3d %-24s %9.1f %9.1f %9.1f %6.2fx %11.1f %-13s %s\n", (int)tid, name, (double)rep_1k_ns / 1000.0,
               (double)rep_4k_ns / 1000.0, (double)rep_16k_ns / 1000.0, worst_ratio, (double)drift_bytes / 1024.0,
               complexity_pattern_name(worst_pat), ok ? "PASS" : "FAIL");
    }

    uint64_t final_rss = read_process_rss_bytes();
    if (final_rss > sweep_peak_rss) {
        sweep_peak_rss = final_rss;
    }
    int64_t final_drift =
        compute_target_rss_drift_bytes(final_rss, sweep_base_rss, g_driver_corpus_bytes, sweep_base_corpus);
    if (final_drift > global_max_drift_bytes) {
        global_max_drift_bytes = final_drift;
    }
    if ((uint64_t)global_max_drift_bytes > max_rss_drift_bytes) {
        failures++;
    }

    g_abort_on_slow_input = saved_abort;

    if (failures > 0) {
        fprintf(stderr,
                "FAIL COMPLEXITY_GATE passed=%d/%d max_ratio=%.2fx max_16kb_ms=%.3f baseline_rss=%" PRIu64
                " peak_rss=%" PRIu64 " final_rss=%" PRIu64
                " driver_corpus_bytes=%zu target_drift_kb=%.2f limit_kb=%" PRIu64 "\n",
                passed, total, global_max_ratio, (double)global_max_16k_ns / 1e6, sweep_base_rss, sweep_peak_rss,
                final_rss, g_driver_corpus_bytes, (double)global_max_drift_bytes / 1024.0, g_max_rss_drift_kb);
        return 1;
    }

    printf("OK COMPLEXITY_GATE passed=%d/%d max_ratio=%.2fx max_16kb_ms=%.3f rss_drift_kb=%.2f limit_kb=%" PRIu64 "\n",
           passed, total, global_max_ratio, (double)global_max_16k_ns / 1e6, (double)global_max_drift_bytes / 1024.0,
           g_max_rss_drift_kb);
    return 0;
}

NO_SANITIZE_COV static int is_flag_arg(const char *arg) { return arg[0] == '-' && arg[1] == '-'; }

NO_SANITIZE_COV int main(int argc, char **argv) {
    LLVMFuzzerInitialize(&argc, &argv);

    int32_t target_id = g_target_id;
    uint64_t max_iters = 5000;
    uint64_t max_seconds = 0;
    int check_complexity = 0;
    int has_explicit_seed = 0;
    uint64_t explicit_seed = 0;

    const char *env_seed = getenv("WING_FUZZ_SEED");
    if (env_seed != NULL && env_seed[0] != '\0') {
        explicit_seed = (uint64_t)strtoull(env_seed, NULL, 10);
        has_explicit_seed = 1;
    }
    const char *env_sec = getenv("WING_FUZZ_SECONDS");
    if (env_sec != NULL && env_sec[0] != '\0') {
        max_seconds = (uint64_t)strtoull(env_sec, NULL, 10);
    }

    int positional_idx = 0;
    const char *seed_args[256];
    size_t seed_arg_count = 0;

    for (int i = 1; i < argc; i++) {
        const char *arg = argv[i];
        if (strcmp(arg, "--check-complexity") == 0) {
            check_complexity = 1;
        } else if (strcmp(arg, "--target") == 0 && i + 1 < argc) {
            target_id = (int32_t)atoi(argv[++i]);
        } else if (strcmp(arg, "--execs") == 0 && i + 1 < argc) {
            max_iters = (uint64_t)strtoull(argv[++i], NULL, 10);
        } else if (strcmp(arg, "--seconds") == 0 && i + 1 < argc) {
            max_seconds = (uint64_t)strtoull(argv[++i], NULL, 10);
        } else if (strcmp(arg, "--corpus-out") == 0 && i + 1 < argc) {
            g_corpus_out_dir = argv[++i];
        } else if (strcmp(arg, "--max-rss-drift-kb") == 0 && i + 1 < argc) {
            g_max_rss_drift_kb = (uint64_t)strtoull(argv[++i], NULL, 10);
        } else if (strcmp(arg, "--max-input-ms") == 0 && i + 1 < argc) {
            g_max_input_ms = (uint64_t)strtoull(argv[++i], NULL, 10);
        } else if (strcmp(arg, "--seed") == 0 && i + 1 < argc) {
            explicit_seed = (uint64_t)strtoull(argv[++i], NULL, 10);
            has_explicit_seed = 1;
        } else if (!is_flag_arg(arg)) {
            if (positional_idx == 0) {
                target_id = (int32_t)atoi(arg);
                positional_idx++;
            } else if (positional_idx == 1) {
                max_iters = (uint64_t)strtoull(arg, NULL, 10);
                positional_idx++;
            } else if (seed_arg_count < 256U) {
                seed_args[seed_arg_count++] = arg;
            }
        }
    }

    g_target_id = target_id;
    g_rng_state = has_explicit_seed ? (explicit_seed != 0 ? explicit_seed : 0xCAFEBABE98765432ULL)
                                    : (0xCAFEBABE98765432ULL ^ (uint64_t)time(NULL));

    for (size_t i = 0; i < seed_arg_count; i++) {
        if (seed_args[i][0] == '@') {
            load_seed_manifest(seed_args[i] + 1);
        } else {
            load_seed_file(seed_args[i]);
        }
    }

    if (g_corpus_count == 0) {
        bootstrap_default_corpus();
    }

    uint8_t work_buf[MAX_INPUT_LEN];
    size_t total_edges = 0;
    size_t new_cov_events = 0;

    uint64_t warmup_iters = (max_iters > 0) ? (max_iters / 5ULL) : 200ULL;
    if (warmup_iters > 500ULL) {
        warmup_iters = 500ULL;
    }
    int baseline_captured = 0;
    uint64_t baseline_rss = 0;
    size_t baseline_corpus_bytes = 0;
    uint64_t peak_rss = 0;
    int64_t peak_drift_bytes = 0;
    uint64_t max_rss_drift_bytes = g_max_rss_drift_kb * 1024ULL;
    uint64_t deadline_ns = (max_seconds > 0) ? (monotonic_ns() + max_seconds * 1000000000ULL) : 0ULL;
    uint64_t actual_iters = 0;

    if ((max_iters > 0 || max_seconds > 0) && warmup_iters == 0) {
        baseline_rss = read_process_rss_bytes();
        baseline_corpus_bytes = g_driver_corpus_bytes;
        peak_rss = baseline_rss;
        baseline_captured = 1;
    }

    for (uint64_t iter = 0; (max_iters == 0 && max_seconds > 0) || iter < max_iters; iter++) {
        if (deadline_ns > 0 && iter > 0 && (iter & 15ULL) == 0ULL && monotonic_ns() >= deadline_ns) {
            break;
        }
        const CorpusEntry *base = &g_corpus[xorshift64(&g_rng_state) % g_corpus_count];
        size_t cur_len = base->len;
        memcpy(work_buf, base->bytes, cur_len);
        cur_len = mutate_buffer(work_buf, cur_len, MAX_INPUT_LEN, &g_rng_state);

        // Guarantee 100% target coverage in multi-target mode by sweeping every target ID.
        if (g_target_id < 0 && iter < (uint64_t)g_target_count && cur_len > 0) {
            work_buf[0] = (uint8_t)(iter % (uint64_t)g_target_count);
        }

        memset(g_trace_bits, 0, sizeof(g_trace_bits));
        g_prev_loc = 0;
        LLVMFuzzerTestOneInput(work_buf, cur_len);
        actual_iters = iter + 1ULL;

        size_t discovered = evaluate_new_coverage(&total_edges);
        if (discovered > 0) {
            add_to_corpus(work_buf, cur_len);
            persist_corpus_entry(work_buf, cur_len);
            new_cov_events++;
        }

        if (!baseline_captured && iter + 1ULL >= warmup_iters) {
            baseline_rss = read_process_rss_bytes();
            baseline_corpus_bytes = g_driver_corpus_bytes;
            peak_rss = baseline_rss;
            baseline_captured = 1;
        } else if (baseline_captured && ((iter + 1ULL) % 100ULL == 0ULL)) {
            uint64_t cur_rss = read_process_rss_bytes();
            if (cur_rss > peak_rss) {
                peak_rss = cur_rss;
            }
            int64_t drift =
                compute_target_rss_drift_bytes(cur_rss, baseline_rss, g_driver_corpus_bytes, baseline_corpus_bytes);
            if (drift > peak_drift_bytes) {
                peak_drift_bytes = drift;
            }
            if ((uint64_t)drift > max_rss_drift_bytes) {
                fprintf(stderr,
                        "FAIL RSS_DRIFT_EXCEEDED iter=%" PRIu64 " baseline_rss=%" PRIu64 " peak_rss=%" PRIu64
                        " final_rss=%" PRIu64 " driver_corpus_bytes=%zu"
                        " target_drift_kb=%.2f limit_kb=%" PRIu64 "\n",
                        iter + 1ULL, baseline_rss, peak_rss, cur_rss, g_driver_corpus_bytes, (double)drift / 1024.0,
                        g_max_rss_drift_kb);
                return EXIT_FAILURE;
            }
        }
    }

    uint64_t final_rss = read_process_rss_bytes();
    if (baseline_captured) {
        if (final_rss > peak_rss) {
            peak_rss = final_rss;
        }
        int64_t final_drift =
            compute_target_rss_drift_bytes(final_rss, baseline_rss, g_driver_corpus_bytes, baseline_corpus_bytes);
        if (final_drift > peak_drift_bytes) {
            peak_drift_bytes = final_drift;
        }
        if ((uint64_t)peak_drift_bytes > max_rss_drift_bytes) {
            fprintf(stderr,
                    "FAIL RSS_DRIFT_EXCEEDED baseline_rss=%" PRIu64 " peak_rss=%" PRIu64 " final_rss=%" PRIu64
                    " driver_corpus_bytes=%zu target_drift_kb=%.2f limit_kb=%" PRIu64 "\n",
                    baseline_rss, peak_rss, final_rss, g_driver_corpus_bytes, (double)peak_drift_bytes / 1024.0,
                    g_max_rss_drift_kb);
            return EXIT_FAILURE;
        }
    }

    int32_t targets_covered = 0;
    uint64_t worst_input_ns = 0;
    for (int32_t tid = 0; tid < g_target_count && (uint32_t)tid < MAX_TRACKED_TARGETS; tid++) {
        if (g_target_stats[tid].exec_count > 0) {
            targets_covered++;
        }
        if (g_target_stats[tid].max_ns > worst_input_ns) {
            worst_input_ns = g_target_stats[tid].max_ns;
        }
    }

    printf("OK SANCOV_EXECS: %" PRIu64 " TARGETS: %d/%d CORPUS: %zu (%zu B) EDGES: %zu NEW_COV: %zu"
           " MAX_INPUT_MS: %.3f RSS_DRIFT_KB: %.2f/%.0f SAVED: %zu\n",
           actual_iters, (int)targets_covered, (int)g_target_count, g_corpus_count, g_driver_corpus_bytes, total_edges,
           new_cov_events, (double)worst_input_ns / 1e6, (double)peak_drift_bytes / 1024.0, (double)g_max_rss_drift_kb,
           g_saved_corpus_files);

    if (check_complexity) {
        int rc = run_complexity_gate(target_id, actual_iters == 0);
        if (rc != 0) {
            return EXIT_FAILURE;
        }
    }

    return 0;
}

#endif
