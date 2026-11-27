// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// shim/simd.c - SIMD acceleration primitives for goose-wing
// Provides vectorized WebSocket unmasking, ASCII/UTF-8 fast scan, and CRLF delimiter detection.

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#ifndef __STDC_WANT_LIB_EXT1__
#define __STDC_WANT_LIB_EXT1__ 1
#endif
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <string.h>

#if defined(_WIN32)
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#ifndef LOAD_LIBRARY_SEARCH_SYSTEM32
#define LOAD_LIBRARY_SEARCH_SYSTEM32 0x00000800
#endif
#else
#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <unistd.h>
#if defined(__linux__)
#include <sys/random.h>
#endif
#endif

#if defined(_MSC_VER)
#include <intrin.h>
#elif defined(__x86_64__) || defined(__i386__)
#include <cpuid.h>
#include <immintrin.h>
#elif defined(__ARM_NEON) || defined(__aarch64__)
#include <arm_neon.h>
#endif

#pragma pack(push, 1)
typedef struct {
    uint8_t *data;
    int64_t len;
} wing_bytes_rw;
typedef struct {
    const uint8_t *data;
    int64_t len;
} wing_bytes_ro;
typedef struct {
    uint16_t *data;
    int64_t len;
} wing_u16_rw;
typedef struct {
    uint32_t *data;
    int64_t len;
} wing_u32_rw;
typedef struct {
    uint64_t *data;
    int64_t len;
} wing_u64_rw;
typedef struct {
    int32_t *data;
    int64_t len;
} wing_i32_rw;
#pragma pack(pop)

_Static_assert(sizeof(wing_bytes_rw) == sizeof(void *) + sizeof(int64_t), "wing_bytes_rw ABI mismatch");
_Static_assert(offsetof(wing_bytes_rw, len) == sizeof(void *), "wing_bytes_rw len offset mismatch");
_Static_assert(sizeof(wing_bytes_ro) == sizeof(void *) + sizeof(int64_t), "wing_bytes_ro ABI mismatch");
_Static_assert(sizeof(wing_u16_rw) == sizeof(void *) + sizeof(int64_t), "wing_u16_rw ABI mismatch");
_Static_assert(sizeof(wing_u32_rw) == sizeof(void *) + sizeof(int64_t), "wing_u32_rw ABI mismatch");
_Static_assert(sizeof(wing_u64_rw) == sizeof(void *) + sizeof(int64_t), "wing_u64_rw ABI mismatch");
_Static_assert(sizeof(wing_i32_rw) == sizeof(void *) + sizeof(int64_t), "wing_i32_rw ABI mismatch");

uint64_t wing_mulhi_u64(uint64_t a, uint64_t b) {
#if defined(__SIZEOF_INT128__)
    return (uint64_t)(((unsigned __int128)a * (unsigned __int128)b) >> 64);
#elif defined(_MSC_VER) && defined(_M_X64)
    return __umulh(a, b);
#else
    uint64_t a_lo = (uint32_t)a, a_hi = a >> 32;
    uint64_t b_lo = (uint32_t)b, b_hi = b >> 32;
    uint64_t p0 = a_lo * b_lo;
    uint64_t p1 = a_lo * b_hi;
    uint64_t p2 = a_hi * b_lo;
    uint64_t p3 = a_hi * b_hi;
    uint64_t cy = ((p0 >> 32) + (uint32_t)p1 + (uint32_t)p2) >> 32;
    return p3 + (p1 >> 32) + (p2 >> 32) + cy;
#endif
}

// High-speed vectorized byte search using platform memchr (AVX2 / SSE2)
int64_t wing_memchr(wing_bytes_ro slice, uint8_t b) {
    if (!slice.data || slice.len <= 0) return -1;
    const void *p = memchr(slice.data, b, (size_t)slice.len);
    if (!p) return -1;
    return (int64_t)((const uint8_t *)p - slice.data);
}

static inline void wing_zeroize_raw(void *ptr, size_t byte_len) {
    if (!ptr || byte_len == 0) return;
#if defined(_MSC_VER)
    SecureZeroMemory(ptr, byte_len);
#elif defined(__STDC_LIB_EXT1__)
    memset_s(ptr, (rsize_t)byte_len, 0, (rsize_t)byte_len);
#else
    volatile uint8_t *p = (volatile uint8_t *)ptr;
    size_t len = byte_len;
    while (len--) {
        *p++ = 0;
    }
#if defined(__GNUC__) || defined(__clang__)
    __asm__ __volatile__("" : : "r"(ptr) : "memory");
#endif
#endif
}

// Cryptographically secure memory zeroization immune to dead-store elimination (DSE).
void wing_secure_zeroize(wing_bytes_rw slice) {
    if (!slice.data || slice.len <= 0) return;
    wing_zeroize_raw(slice.data, (size_t)slice.len);
}

void wing_secure_zeroize_u16(wing_u16_rw slice) {
    if (!slice.data || slice.len <= 0 || (uint64_t)slice.len > SIZE_MAX / sizeof(uint16_t)) return;
    wing_zeroize_raw(slice.data, (size_t)slice.len * sizeof(uint16_t));
}

void wing_secure_zeroize_u32(wing_u32_rw slice) {
    if (!slice.data || slice.len <= 0 || (uint64_t)slice.len > SIZE_MAX / sizeof(uint32_t)) return;
    wing_zeroize_raw(slice.data, (size_t)slice.len * sizeof(uint32_t));
}

void wing_secure_zeroize_u64(wing_u64_rw slice) {
    if (!slice.data || slice.len <= 0 || (uint64_t)slice.len > SIZE_MAX / sizeof(uint64_t)) return;
    wing_zeroize_raw(slice.data, (size_t)slice.len * sizeof(uint64_t));
}

void wing_secure_zeroize_i32(wing_i32_rw slice) {
    if (!slice.data || slice.len <= 0 || (uint64_t)slice.len > SIZE_MAX / sizeof(int32_t)) return;
    wing_zeroize_raw(slice.data, (size_t)slice.len * sizeof(int32_t));
}

#if defined(__GNUC__) || defined(__clang__)
#define WING_SIMD_NOINLINE __attribute__((noinline))
#elif defined(_MSC_VER)
#define WING_SIMD_NOINLINE __declspec(noinline)
#else
#define WING_SIMD_NOINLINE
#endif

// Compiler value barriers preventing -O2/-O3 from turning CT bitmasks into conditional branches.
uint8_t wing_ct_barrier_u8(uint8_t v) {
#if defined(__GNUC__) || defined(__clang__)
    __asm__ __volatile__("" : "+r"(v));
    return v;
#else
    volatile uint8_t tmp = v;
    return tmp;
#endif
}

uint32_t wing_ct_barrier_u32(uint32_t v) {
#if defined(__GNUC__) || defined(__clang__)
    __asm__ __volatile__("" : "+r"(v));
    return v;
#else
    volatile uint32_t tmp = v;
    return tmp;
#endif
}

uint64_t wing_ct_barrier_u64(uint64_t v) {
#if defined(__GNUC__) || defined(__clang__)
    __asm__ __volatile__("" : "+r"(v));
    return v;
#else
    volatile uint64_t tmp = v;
    return tmp;
#endif
}

// Overwrites dead callee stack spills left behind by constant-time Goose crypto frames.
WING_SIMD_NOINLINE
void wing_secure_scrub_stack(void) {
    volatile uint8_t scrub[1024];
    wing_zeroize_raw((void *)scrub, sizeof(scrub));
}

// Constant-time byte copy using 64-bit SWAR words
void wing_ct_copy_bytes(wing_bytes_rw dst, wing_bytes_ro src) {
    if (!dst.data || !src.data) return;
    int64_t len = dst.len < src.len ? dst.len : src.len;
    if (len <= 0) return;
    int64_t i = 0;
    while (i + 8 <= len) {
        uint64_t w;
        memcpy(&w, src.data + i, 8);
        memcpy(dst.data + i, &w, 8);
        i += 8;
    }
    while (i < len) {
        dst.data[i] = src.data[i];
        i++;
    }
}

/* =========================================================================
 * SIMD Checksum Intrinsics: CRC-32 IEEE (VPCLMULQDQ / PCLMULQDQ) &
 * Adler-32 (AVX2 / SSSE3) with runtime CPUID dispatch + scalar fallback.
 * ========================================================================= */

#if defined(__GNUC__) || defined(__clang__)
#define WING_SIMD_TARGET_PCLMUL __attribute__((target("sse2,ssse3,sse4.1,pclmul")))
#define WING_SIMD_TARGET_SSSE3 __attribute__((target("sse2,ssse3")))
#define WING_SIMD_TARGET_AVX2 __attribute__((target("avx2")))
#define WING_SIMD_TARGET_VPCLMUL __attribute__((target("avx2,pclmul,vpclmulqdq")))
#else
#define WING_SIMD_TARGET_PCLMUL
#define WING_SIMD_TARGET_SSSE3
#define WING_SIMD_TARGET_AVX2
#define WING_SIMD_TARGET_VPCLMUL
#endif

#define WING_CAP_SSSE3 (1 << 0)
#define WING_CAP_PCLMUL (1 << 1)
#define WING_CAP_AVX2 (1 << 2)
#define WING_CAP_VPCLMUL (1 << 3)

static inline int wing_compress_cpu_caps(void) {
#if defined(__GNUC__) || defined(__clang__)
    static int cached = -1;
    int v = __atomic_load_n(&cached, __ATOMIC_RELAXED);
    if (v >= 0) return v;
    int caps = 0;
#if defined(__x86_64__) || defined(_M_X64)
    if (__builtin_cpu_supports("ssse3")) caps |= WING_CAP_SSSE3;
    if (__builtin_cpu_supports("sse4.1") && __builtin_cpu_supports("pclmul")) caps |= WING_CAP_PCLMUL;
    if (__builtin_cpu_supports("avx2")) {
        caps |= WING_CAP_AVX2;
        if (__builtin_cpu_supports("vpclmulqdq") && (caps & WING_CAP_PCLMUL)) {
            caps |= WING_CAP_VPCLMUL;
        }
    }
#endif
    __atomic_store_n(&cached, caps, __ATOMIC_RELAXED);
    return caps;
#elif defined(_MSC_VER) && defined(_M_X64)
    static volatile long cached = -1;
    long v = _InterlockedCompareExchange(&cached, -1, -1);
    if (v >= 0) return (int)v;
    int caps = 0;
    int info[4] = {0};
    __cpuid(info, 0);
    int max_leaf = info[0];
    if (max_leaf >= 1) {
        __cpuid(info, 1);
        int has_xsave = (info[2] & (1 << 26)) != 0;
        int has_osxsave = (info[2] & (1 << 27)) != 0;
        int has_avx = (info[2] & (1 << 28)) != 0;
        int has_ssse3 = (info[2] & (1 << 9)) != 0;
        int has_sse41 = (info[2] & (1 << 19)) != 0;
        int has_pclmul = (info[2] & (1 << 1)) != 0;
        if (has_ssse3) caps |= WING_CAP_SSSE3;
        if (has_sse41 && has_pclmul) caps |= WING_CAP_PCLMUL;
        if (has_xsave && has_osxsave && has_avx && max_leaf >= 7) {
            uint64_t xcr0 = _xgetbv(0);
            if ((xcr0 & 0x6ULL) == 0x6ULL) {
                int info7[4] = {0};
                __cpuidex(info7, 7, 0);
                if (info7[1] & (1 << 5)) caps |= WING_CAP_AVX2;
                if ((caps & (WING_CAP_AVX2 | WING_CAP_PCLMUL)) == (WING_CAP_AVX2 | WING_CAP_PCLMUL) &&
                    (info7[2] & (1 << 10))) {
                    caps |= WING_CAP_VPCLMUL;
                }
            }
        }
    }
    _InterlockedExchange(&cached, (long)caps);
    return caps;
#else
    return 0;
#endif
}

/* Reflected GF(2) folding constants for IEEE 802.3 CRC-32 (0xEDB88320):
 * P(x) = 0x104C11DB7, rk(n) = bit_reflect(x^n mod P(x), 33) */
#define WING_CRC32_P_REFL 0x1db710641ULL
#define WING_CRC32_MU_REFL 0x1f7011641ULL
#define WING_CRC32_RK64 0x163cd6124ULL
#define WING_CRC32_RK96 0x0ccaa009eULL
#define WING_CRC32_RK160 0x1751997d0ULL
#define WING_CRC32_RK224 0x15a546366ULL
#define WING_CRC32_RK288 0x0f1da05aaULL
#define WING_CRC32_RK480 0x1c6e41596ULL
#define WING_CRC32_RK544 0x154442bd4ULL
#define WING_CRC32_RK992 0x14a7fe880ULL
#define WING_CRC32_RK1056 0x1e88ef372ULL

static uint32_t wing_crc32_tables[8][256];
static int wing_crc32_tables_ready = 0;

static inline void wing_crc32_ensure_tables(void) {
#if defined(__GNUC__) || defined(__clang__)
    if (__atomic_load_n(&wing_crc32_tables_ready, __ATOMIC_ACQUIRE)) return;
#else
    if (wing_crc32_tables_ready) return;
#endif
    for (uint32_t i = 0; i < 256; i++) {
        uint32_t c = i;
        for (int k = 0; k < 8; k++)
            c = (c >> 1) ^ (0xEDB88320U & -(c & 1U));
        wing_crc32_tables[0][i] = c;
    }
    for (uint32_t i = 0; i < 256; i++) {
        uint32_t c = wing_crc32_tables[0][i];
        for (int t = 1; t < 8; t++) {
            c = wing_crc32_tables[0][c & 0xFFU] ^ (c >> 8);
            wing_crc32_tables[t][i] = c;
        }
    }
#if defined(__GNUC__) || defined(__clang__)
    __atomic_store_n(&wing_crc32_tables_ready, 1, __ATOMIC_RELEASE);
#else
    wing_crc32_tables_ready = 1;
#endif
}

static inline uint32_t wing_crc32_scalar_tail(uint32_t crc, const uint8_t *p, int64_t len) {
    wing_crc32_ensure_tables();
    while (len >= 8) {
        uint32_t lo, hi;
        memcpy(&lo, p, 4);
        memcpy(&hi, p + 4, 4);
        lo ^= crc;
        crc = wing_crc32_tables[7][lo & 0xFFU] ^ wing_crc32_tables[6][(lo >> 8) & 0xFFU] ^
              wing_crc32_tables[5][(lo >> 16) & 0xFFU] ^ wing_crc32_tables[4][lo >> 24] ^
              wing_crc32_tables[3][hi & 0xFFU] ^ wing_crc32_tables[2][(hi >> 8) & 0xFFU] ^
              wing_crc32_tables[1][(hi >> 16) & 0xFFU] ^ wing_crc32_tables[0][hi >> 24];
        p += 8;
        len -= 8;
    }
    for (int64_t i = 0; i < len; i++) {
        crc = wing_crc32_tables[0][(crc ^ p[i]) & 0xFFU] ^ (crc >> 8);
    }
    return crc;
}

#if defined(__x86_64__) || defined(_M_X64)
WING_SIMD_TARGET_PCLMUL
static inline uint32_t wing_crc32_reduce128(__m128i x0) {
    const __m128i rk_64_96 = _mm_set_epi64x((int64_t)WING_CRC32_RK64, (int64_t)WING_CRC32_RK96);
    const __m128i k_barrett = _mm_set_epi64x((int64_t)WING_CRC32_P_REFL, (int64_t)WING_CRC32_MU_REFL);
    const __m128i mask32 = _mm_set_epi32(0, 0, 0, -1);

    __m128i p1 = _mm_xor_si128(_mm_clmulepi64_si128(x0, rk_64_96, 0x00), _mm_srli_si128(x0, 8));
    __m128i p2 = _mm_clmulepi64_si128(_mm_and_si128(p1, mask32), rk_64_96, 0x10);
    __m128i v64 = _mm_xor_si128(p2, _mm_srli_si128(p1, 4));

    __m128i t1 = _mm_clmulepi64_si128(_mm_and_si128(v64, mask32), k_barrett, 0x00);
    __m128i t2 = _mm_clmulepi64_si128(_mm_and_si128(t1, mask32), k_barrett, 0x10);
    __m128i res = _mm_xor_si128(v64, t2);
    return (uint32_t)_mm_extract_epi32(res, 1);
}

WING_SIMD_TARGET_PCLMUL
static uint32_t wing_crc32_pclmul(uint32_t initial, const uint8_t *p, int64_t len) {
    uint32_t crc = initial ^ 0xFFFFFFFFU;
    if (len >= 64) {
        __m128i x0 = _mm_loadu_si128((const __m128i *)(p));
        __m128i x1 = _mm_loadu_si128((const __m128i *)(p + 16));
        __m128i x2 = _mm_loadu_si128((const __m128i *)(p + 32));
        __m128i x3 = _mm_loadu_si128((const __m128i *)(p + 48));
        x0 = _mm_xor_si128(x0, _mm_cvtsi32_si128((int)crc));
        p += 64;
        len -= 64;

        const __m128i k512 = _mm_set_epi64x((int64_t)WING_CRC32_RK480, (int64_t)WING_CRC32_RK544);
        while (len >= 64) {
            __m128i y0 = _mm_loadu_si128((const __m128i *)(p));
            __m128i y1 = _mm_loadu_si128((const __m128i *)(p + 16));
            __m128i y2 = _mm_loadu_si128((const __m128i *)(p + 32));
            __m128i y3 = _mm_loadu_si128((const __m128i *)(p + 48));

            x0 = _mm_xor_si128(
                _mm_xor_si128(_mm_clmulepi64_si128(x0, k512, 0x00), _mm_clmulepi64_si128(x0, k512, 0x11)), y0);
            x1 = _mm_xor_si128(
                _mm_xor_si128(_mm_clmulepi64_si128(x1, k512, 0x00), _mm_clmulepi64_si128(x1, k512, 0x11)), y1);
            x2 = _mm_xor_si128(
                _mm_xor_si128(_mm_clmulepi64_si128(x2, k512, 0x00), _mm_clmulepi64_si128(x2, k512, 0x11)), y2);
            x3 = _mm_xor_si128(
                _mm_xor_si128(_mm_clmulepi64_si128(x3, k512, 0x00), _mm_clmulepi64_si128(x3, k512, 0x11)), y3);
            p += 64;
            len -= 64;
        }

        const __m128i k128 = _mm_set_epi64x((int64_t)WING_CRC32_RK96, (int64_t)WING_CRC32_RK160);
        x1 = _mm_xor_si128(_mm_xor_si128(_mm_clmulepi64_si128(x0, k128, 0x00), _mm_clmulepi64_si128(x0, k128, 0x11)),
                           x1);
        x2 = _mm_xor_si128(_mm_xor_si128(_mm_clmulepi64_si128(x1, k128, 0x00), _mm_clmulepi64_si128(x1, k128, 0x11)),
                           x2);
        x3 = _mm_xor_si128(_mm_xor_si128(_mm_clmulepi64_si128(x2, k128, 0x00), _mm_clmulepi64_si128(x2, k128, 0x11)),
                           x3);

        while (len >= 16) {
            __m128i y = _mm_loadu_si128((const __m128i *)p);
            x3 = _mm_xor_si128(
                _mm_xor_si128(_mm_clmulepi64_si128(x3, k128, 0x00), _mm_clmulepi64_si128(x3, k128, 0x11)), y);
            p += 16;
            len -= 16;
        }
        crc = wing_crc32_reduce128(x3);
    } else if (len >= 16) {
        __m128i x0 = _mm_loadu_si128((const __m128i *)p);
        x0 = _mm_xor_si128(x0, _mm_cvtsi32_si128((int)crc));
        p += 16;
        len -= 16;
        const __m128i k128 = _mm_set_epi64x((int64_t)WING_CRC32_RK96, (int64_t)WING_CRC32_RK160);
        while (len >= 16) {
            __m128i y = _mm_loadu_si128((const __m128i *)p);
            x0 = _mm_xor_si128(
                _mm_xor_si128(_mm_clmulepi64_si128(x0, k128, 0x00), _mm_clmulepi64_si128(x0, k128, 0x11)), y);
            p += 16;
            len -= 16;
        }
        crc = wing_crc32_reduce128(x0);
    }
    if (len > 0) {
        crc = wing_crc32_scalar_tail(crc, p, len);
    }
    return crc ^ 0xFFFFFFFFU;
}

WING_SIMD_TARGET_VPCLMUL
static uint32_t wing_crc32_vpclmul(uint32_t initial, const uint8_t *p, int64_t len) {
    if (len < 128) return wing_crc32_pclmul(initial, p, len);

    uint32_t crc = initial ^ 0xFFFFFFFFU;
    __m256i x0 = _mm256_loadu_si256((const __m256i *)(p));
    __m256i x1 = _mm256_loadu_si256((const __m256i *)(p + 32));
    __m256i x2 = _mm256_loadu_si256((const __m256i *)(p + 64));
    __m256i x3 = _mm256_loadu_si256((const __m256i *)(p + 96));
    x0 = _mm256_xor_si256(x0, _mm256_zextsi128_si256(_mm_cvtsi32_si128((int)crc)));
    p += 128;
    len -= 128;

    const __m256i k1024 = _mm256_set_epi64x((int64_t)WING_CRC32_RK992, (int64_t)WING_CRC32_RK1056,
                                            (int64_t)WING_CRC32_RK992, (int64_t)WING_CRC32_RK1056);
    while (len >= 128) {
        __m256i y0 = _mm256_loadu_si256((const __m256i *)(p));
        __m256i y1 = _mm256_loadu_si256((const __m256i *)(p + 32));
        __m256i y2 = _mm256_loadu_si256((const __m256i *)(p + 64));
        __m256i y3 = _mm256_loadu_si256((const __m256i *)(p + 96));

        x0 = _mm256_xor_si256(
            _mm256_xor_si256(_mm256_clmulepi64_epi128(x0, k1024, 0x00), _mm256_clmulepi64_epi128(x0, k1024, 0x11)), y0);
        x1 = _mm256_xor_si256(
            _mm256_xor_si256(_mm256_clmulepi64_epi128(x1, k1024, 0x00), _mm256_clmulepi64_epi128(x1, k1024, 0x11)), y1);
        x2 = _mm256_xor_si256(
            _mm256_xor_si256(_mm256_clmulepi64_epi128(x2, k1024, 0x00), _mm256_clmulepi64_epi128(x2, k1024, 0x11)), y2);
        x3 = _mm256_xor_si256(
            _mm256_xor_si256(_mm256_clmulepi64_epi128(x3, k1024, 0x00), _mm256_clmulepi64_epi128(x3, k1024, 0x11)), y3);
        p += 128;
        len -= 128;
    }

    const __m256i k512 = _mm256_set_epi64x((int64_t)WING_CRC32_RK480, (int64_t)WING_CRC32_RK544,
                                           (int64_t)WING_CRC32_RK480, (int64_t)WING_CRC32_RK544);
    x0 = _mm256_xor_si256(
        _mm256_xor_si256(_mm256_clmulepi64_epi128(x0, k512, 0x00), _mm256_clmulepi64_epi128(x0, k512, 0x11)), x2);
    x1 = _mm256_xor_si256(
        _mm256_xor_si256(_mm256_clmulepi64_epi128(x1, k512, 0x00), _mm256_clmulepi64_epi128(x1, k512, 0x11)), x3);

    const __m256i k256 = _mm256_set_epi64x((int64_t)WING_CRC32_RK224, (int64_t)WING_CRC32_RK288,
                                           (int64_t)WING_CRC32_RK224, (int64_t)WING_CRC32_RK288);
    x0 = _mm256_xor_si256(
        _mm256_xor_si256(_mm256_clmulepi64_epi128(x0, k256, 0x00), _mm256_clmulepi64_epi128(x0, k256, 0x11)), x1);

    while (len >= 32) {
        __m256i y = _mm256_loadu_si256((const __m256i *)p);
        x0 = _mm256_xor_si256(
            _mm256_xor_si256(_mm256_clmulepi64_epi128(x0, k256, 0x00), _mm256_clmulepi64_epi128(x0, k256, 0x11)), y);
        p += 32;
        len -= 32;
    }

    __m128i lo = _mm256_castsi256_si128(x0);
    __m128i hi = _mm256_extracti128_si256(x0, 1);
    const __m128i k128 = _mm_set_epi64x((int64_t)WING_CRC32_RK96, (int64_t)WING_CRC32_RK160);
    __m128i s =
        _mm_xor_si128(_mm_xor_si128(_mm_clmulepi64_si128(lo, k128, 0x00), _mm_clmulepi64_si128(lo, k128, 0x11)), hi);

    while (len >= 16) {
        __m128i y = _mm_loadu_si128((const __m128i *)p);
        s = _mm_xor_si128(_mm_xor_si128(_mm_clmulepi64_si128(s, k128, 0x00), _mm_clmulepi64_si128(s, k128, 0x11)), y);
        p += 16;
        len -= 16;
    }

    crc = wing_crc32_reduce128(s);
    if (len > 0) crc = wing_crc32_scalar_tail(crc, p, len);
    return crc ^ 0xFFFFFFFFU;
}

WING_SIMD_TARGET_SSSE3
static uint32_t wing_adler32_ssse3(uint32_t initial, const uint8_t *p, int64_t len) {
    uint64_t s1 = (uint64_t)(initial & 0xFFFFU) % 65521U;
    uint64_t s2 = (uint64_t)((initial >> 16) & 0xFFFFU) % 65521U;

    const __m128i zero = _mm_setzero_si128();
    const __m128i ones16 = _mm_set1_epi16(1);
    const __m128i weights = _mm_set_epi8(1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16);

    while (len >= 16) {
        int64_t blocks = len >> 4;
        if (blocks > 347) blocks = 347; /* 347 * 16 = 5552 NMAX */

        __m128i vs1 = zero;
        __m128i vs2_prefix = zero;
        __m128i vs2_w = zero;

        for (int64_t b = 0; b < blocks; b++) {
            __m128i v = _mm_loadu_si128((const __m128i *)p);
            vs2_prefix = _mm_add_epi32(vs2_prefix, vs1);
            vs1 = _mm_add_epi32(vs1, _mm_sad_epu8(v, zero));
            __m128i prod = _mm_maddubs_epi16(v, weights);
            vs2_w = _mm_add_epi32(vs2_w, _mm_madd_epi16(prod, ones16));
            p += 16;
        }
        len -= blocks << 4;

        uint64_t sum1 =
            (uint64_t)(uint32_t)_mm_cvtsi128_si32(vs1) + (uint64_t)(uint32_t)_mm_cvtsi128_si32(_mm_srli_si128(vs1, 8));
        uint64_t sum_prefix = (uint64_t)(uint32_t)_mm_cvtsi128_si32(vs2_prefix) +
                              (uint64_t)(uint32_t)_mm_cvtsi128_si32(_mm_srli_si128(vs2_prefix, 8));
        __m128i w = _mm_add_epi32(vs2_w, _mm_srli_si128(vs2_w, 8));
        w = _mm_add_epi32(w, _mm_srli_si128(w, 4));
        uint64_t sum_w = (uint64_t)(uint32_t)_mm_cvtsi128_si32(w);

        s2 = (s2 + ((uint64_t)blocks << 4) * s1 + (sum_prefix << 4) + sum_w) % 65521U;
        s1 = (s1 + sum1) % 65521U;
    }

    while (len > 0) {
        s1 += *p++;
        if (s1 >= 65521U) s1 -= 65521U;
        s2 += s1;
        if (s2 >= 65521U) s2 -= 65521U;
        len--;
    }
    return (uint32_t)((s2 << 16) | s1);
}

WING_SIMD_TARGET_AVX2
static uint32_t wing_adler32_avx2(uint32_t initial, const uint8_t *p, int64_t len) {
    if (len < 32) return wing_adler32_ssse3(initial, p, len);

    uint64_t s1 = (uint64_t)(initial & 0xFFFFU) % 65521U;
    uint64_t s2 = (uint64_t)((initial >> 16) & 0xFFFFU) % 65521U;

    const __m256i zero = _mm256_setzero_si256();
    const __m256i ones16 = _mm256_set1_epi16(1);
    const __m256i weights = _mm256_set_epi8(1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21,
                                            22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32);

    while (len >= 32) {
        int64_t blocks = len >> 5;
        if (blocks > 173) blocks = 173; /* 173 * 32 = 5536 <= 5552 NMAX */

        __m256i vs1 = zero;
        __m256i vs2_prefix = zero;
        __m256i vs2_w = zero;

        for (int64_t b = 0; b < blocks; b++) {
            __m256i v = _mm256_loadu_si256((const __m256i *)p);
            vs2_prefix = _mm256_add_epi32(vs2_prefix, vs1);
            vs1 = _mm256_add_epi32(vs1, _mm256_sad_epu8(v, zero));
            __m256i prod = _mm256_maddubs_epi16(v, weights);
            vs2_w = _mm256_add_epi32(vs2_w, _mm256_madd_epi16(prod, ones16));
            p += 32;
        }
        len -= blocks << 5;

        __m128i s1_128 = _mm_add_epi32(_mm256_castsi256_si128(vs1), _mm256_extracti128_si256(vs1, 1));
        uint64_t sum1 =
            (uint64_t)(uint32_t)_mm_extract_epi32(s1_128, 0) + (uint64_t)(uint32_t)_mm_extract_epi32(s1_128, 2);

        __m128i p_128 = _mm_add_epi32(_mm256_castsi256_si128(vs2_prefix), _mm256_extracti128_si256(vs2_prefix, 1));
        uint64_t sum_prefix =
            (uint64_t)(uint32_t)_mm_extract_epi32(p_128, 0) + (uint64_t)(uint32_t)_mm_extract_epi32(p_128, 2);

        __m128i w_128 = _mm_add_epi32(_mm256_castsi256_si128(vs2_w), _mm256_extracti128_si256(vs2_w, 1));
        w_128 = _mm_add_epi32(w_128, _mm_srli_si128(w_128, 8));
        w_128 = _mm_add_epi32(w_128, _mm_srli_si128(w_128, 4));
        uint64_t sum_w = (uint64_t)(uint32_t)_mm_cvtsi128_si32(w_128);

        s2 = (s2 + ((uint64_t)blocks << 5) * s1 + (sum_prefix << 5) + sum_w) % 65521U;
        s1 = (s1 + sum1) % 65521U;
    }

    while (len > 0) {
        s1 += *p++;
        if (s1 >= 65521U) s1 -= 65521U;
        s2 += s1;
        if (s2 >= 65521U) s2 -= 65521U;
        len--;
    }
    return (uint32_t)((s2 << 16) | s1);
}
#endif

uint32_t wing_simd_crc32_update(uint32_t initial, wing_bytes_ro slice) {
    if (!slice.data || slice.len <= 0) return initial;
#if defined(__x86_64__) || defined(_M_X64)
    int caps = wing_compress_cpu_caps();
    if ((caps & WING_CAP_VPCLMUL) && slice.len >= 128) {
        return wing_crc32_vpclmul(initial, slice.data, slice.len);
    }
    if ((caps & WING_CAP_PCLMUL) && slice.len >= 16) {
        return wing_crc32_pclmul(initial, slice.data, slice.len);
    }
#endif
    return wing_crc32_scalar_tail(initial ^ 0xFFFFFFFFU, slice.data, slice.len) ^ 0xFFFFFFFFU;
}

uint32_t wing_simd_adler32_update(uint32_t initial, wing_bytes_ro slice) {
    if (!slice.data || slice.len <= 0) return initial;
#if defined(__x86_64__) || defined(_M_X64)
    int caps = wing_compress_cpu_caps();
    if ((caps & WING_CAP_AVX2) && slice.len >= 32) {
        return wing_adler32_avx2(initial, slice.data, slice.len);
    }
    if ((caps & WING_CAP_SSSE3) && slice.len >= 16) {
        return wing_adler32_ssse3(initial, slice.data, slice.len);
    }
#endif
    uint32_t s1 = (initial & 0xFFFFU) % 65521U;
    uint32_t s2 = ((initial >> 16) & 0xFFFFU) % 65521U;
    const uint8_t *p = slice.data;
    int64_t len = slice.len;
    while (len > 0) {
        int64_t chunk = len > 5552 ? 5552 : len;
        len -= chunk;
        while (chunk >= 16) {
            for (int k = 0; k < 16; k++) {
                s1 += p[k];
                s2 += s1;
            }
            p += 16;
            chunk -= 16;
        }
        while (chunk-- > 0) {
            s1 += *p++;
            s2 += s1;
        }
        s1 %= 65521U;
        s2 %= 65521U;
    }
    return (s2 << 16) | s1;
}

/* =========================================================================
 * SIMD-Accelerated Deflate Level-1 Fast Encoder (RFC 1951 Fixed + Stored)
 * ========================================================================= */

static uint16_t wing_fix_lit_pack[288];
static uint32_t wing_fix_len_pack[259];
static uint32_t wing_fix_dist_fast[513];
static uint8_t wing_rev5_lut[32];
static volatile int wing_fix_enc_ready = 0;

static inline uint32_t wing_bitrev_u32(uint32_t v, int bits) {
    uint32_t r = 0;
    for (int i = 0; i < bits; i++) {
        r = (r << 1) | (v & 1U);
        v >>= 1;
    }
    return r;
}

static void wing_populate_fix_enc_tables(void) {
    for (uint32_t s = 0; s <= 143; s++)
        wing_fix_lit_pack[s] = (uint16_t)((wing_bitrev_u32(0x30U + s, 8) << 4) | 8U);
    for (uint32_t s = 144; s <= 255; s++)
        wing_fix_lit_pack[s] = (uint16_t)((wing_bitrev_u32(0x190U + (s - 144U), 9) << 4) | 9U);
    for (uint32_t s = 256; s <= 279; s++)
        wing_fix_lit_pack[s] = (uint16_t)((wing_bitrev_u32(s - 256U, 7) << 4) | 7U);
    for (uint32_t s = 280; s <= 287; s++)
        wing_fix_lit_pack[s] = (uint16_t)((wing_bitrev_u32(0xC0U + (s - 280U), 8) << 4) | 8U);

    static const uint16_t lbase[29] = {3,  4,  5,  6,  7,  8,  9,  10, 11,  13,  15,  17,  19,  23, 27,
                                       31, 35, 43, 51, 59, 67, 83, 99, 115, 131, 163, 195, 227, 258};
    static const uint8_t lextra[29] = {0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2,
                                       2, 3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5, 0};
    for (int idx = 0; idx < 29; idx++) {
        uint32_t sym = 257U + (uint32_t)idx;
        uint32_t p = wing_fix_lit_pack[sym];
        uint32_t sbits = p & 0xFU;
        uint32_t scode = p >> 4;
        uint32_t eb = lextra[idx];
        uint32_t count = (idx == 28) ? 1U : (1U << eb);
        for (uint32_t k = 0; k < count; k++) {
            uint32_t mlen = lbase[idx] + k;
            if (mlen <= 258) {
                wing_fix_len_pack[mlen] = (sbits + eb) | ((scode | (k << sbits)) << 5);
            }
        }
    }

    for (uint32_t d = 0; d < 32; d++) {
        wing_rev5_lut[d] = (uint8_t)wing_bitrev_u32(d, 5);
    }

    static const uint16_t dbase[30] = {1,    2,    3,    4,    5,    7,    9,    13,    17,    25,
                                       33,   49,   65,   97,   129,  193,  257,  385,   513,   769,
                                       1025, 1537, 2049, 3073, 4097, 6145, 8193, 12289, 16385, 24577};
    static const uint8_t dextra[30] = {0, 0, 0, 0, 1, 1, 2, 2,  3,  3,  4,  4,  5,  5,  6,
                                       6, 7, 7, 8, 8, 9, 9, 10, 10, 11, 11, 12, 12, 13, 13};
    for (int idx = 0; idx < 18; idx++) {
        uint32_t eb = dextra[idx];
        uint32_t cnt = 1U << eb;
        uint32_t rev = wing_rev5_lut[idx];
        for (uint32_t k = 0; k < cnt; k++) {
            uint32_t dist = dbase[idx] + k;
            if (dist <= 512) {
                wing_fix_dist_fast[dist] = (5U + eb) | ((rev | (k << 5)) << 5);
            }
        }
    }
}

#if defined(_MSC_VER)
static INIT_ONCE wing_fix_enc_once = INIT_ONCE_STATIC_INIT;
static BOOL CALLBACK wing_fix_enc_init_cb(PINIT_ONCE once, PVOID param, PVOID *ctx) {
    (void)once;
    (void)param;
    (void)ctx;
    wing_populate_fix_enc_tables();
    return TRUE;
}
#endif

static void wing_init_fix_enc_tables(void) {
#if defined(_MSC_VER)
    (void)InitOnceExecuteOnce(&wing_fix_enc_once, wing_fix_enc_init_cb, NULL, NULL);
#elif defined(__GNUC__) || defined(__clang__)
    if (__atomic_load_n(&wing_fix_enc_ready, __ATOMIC_ACQUIRE) == 2) return;
    int expected = 0;
    if (__atomic_compare_exchange_n(&wing_fix_enc_ready, &expected, 1, 0, __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE)) {
        wing_populate_fix_enc_tables();
        __atomic_store_n(&wing_fix_enc_ready, 2, __ATOMIC_RELEASE);
        return;
    }
    while (__atomic_load_n(&wing_fix_enc_ready, __ATOMIC_ACQUIRE) != 2) {
#if defined(__x86_64__) || defined(__i386__)
        __builtin_ia32_pause();
#endif
    }
#else
    if (wing_fix_enc_ready == 2) return;
    wing_populate_fix_enc_tables();
    wing_fix_enc_ready = 2;
#endif
}

static inline uint32_t wing_bsr_u32(uint32_t d) {
#if defined(_MSC_VER)
    unsigned long idx = 0;
    _BitScanReverse(&idx, d);
    return (uint32_t)idx;
#else
    return 31U - (uint32_t)__builtin_clz(d);
#endif
}

static inline int wing_ctz_u64(uint64_t v) {
#if defined(_MSC_VER)
    unsigned long idx = 0;
    _BitScanForward64(&idx, v);
    return (int)idx;
#else
    return __builtin_ctzll(v);
#endif
}

static inline void wing_bw_put(uint64_t *bits, int *bc, uint32_t val, int nb, uint8_t *dst, int64_t *out_idx) {
    *bits |= ((uint64_t)val) << *bc;
    *bc += nb;
    if (*bc >= 32) {
        uint32_t w = (uint32_t)(*bits);
        memcpy(dst + *out_idx, &w, 4);
        *out_idx += 4;
        *bits >>= 32;
        *bc -= 32;
    }
}

static inline void wing_emit_dist_fast(uint32_t dist, uint64_t *bits, int *bc, uint8_t *dst, int64_t *out_idx) {
    if (dist <= 512U) {
        uint32_t dp = wing_fix_dist_fast[dist];
        wing_bw_put(bits, bc, dp >> 5, (int)(dp & 31U), dst, out_idx);
        return;
    }
    uint32_t d = dist - 1U;
    uint32_t msb = wing_bsr_u32(d);
    uint32_t code = (msb << 1) | ((d >> (msb - 1U)) & 1U);
    uint32_t eb = msb - 1U;
    uint32_t extra = d & ((1U << eb) - 1U);
    uint32_t comb = (uint32_t)wing_rev5_lut[code] | (extra << 5);
    wing_bw_put(bits, bc, comb, (int)(5U + eb), dst, out_idx);
}

#if defined(__x86_64__) || defined(_M_X64)
#if defined(__GNUC__) || defined(__clang__)
#define WING_SIMD_TARGET_AVX2_BMI __attribute__((target("avx2,bmi")))
#else
#define WING_SIMD_TARGET_AVX2_BMI
#endif

WING_SIMD_TARGET_AVX2_BMI
static inline int32_t wing_extend_match_avx2(const uint8_t *p, const uint8_t *c, int64_t rem_limit) {
    int64_t max_l = rem_limit < 258 ? rem_limit : 258;
    int64_t l = 4;
    if (l + 8 <= max_l) {
        uint64_t va, vb;
        memcpy(&va, p + l, 8);
        memcpy(&vb, c + l, 8);
        uint64_t diff = va ^ vb;
        if (diff != 0) return (int32_t)(l + (wing_ctz_u64(diff) >> 3));
        l = 12;
    }
    while (l + 32 <= max_l) {
        __m256i va = _mm256_loadu_si256((const __m256i *)(p + l));
        __m256i vb = _mm256_loadu_si256((const __m256i *)(c + l));
        uint32_t eq = (uint32_t)_mm256_movemask_epi8(_mm256_cmpeq_epi8(va, vb));
        uint32_t neq = ~eq;
        if (neq != 0) return (int32_t)(l + (int64_t)_tzcnt_u32(neq));
        l += 32;
    }
    while (l + 8 <= max_l) {
        uint64_t va, vb;
        memcpy(&va, p + l, 8);
        memcpy(&vb, c + l, 8);
        uint64_t diff = va ^ vb;
        if (diff != 0) return (int32_t)(l + (wing_ctz_u64(diff) >> 3));
        l += 8;
    }
    while (l < max_l && p[l] == c[l])
        l++;
    return (int32_t)l;
}

#define WING_LZ_HASH_MUL 0x1E35A7BDU

WING_SIMD_TARGET_AVX2_BMI
static int64_t wing_deflate_l1_chunk_avx2(const uint8_t *src, int64_t chunk_start, int64_t chunk_end, int is_final,
                                          uint32_t *head, int64_t head_len, uint64_t *bit_state, uint8_t *dst,
                                          int64_t dst_cap) {
    int64_t chunk_len = chunk_end - chunk_start;
    if (chunk_len < 0 || chunk_len > 65535) return -1;
    if (bit_state[1] > 31ULL) return -1;
    uint64_t bits = bit_state[0];
    int bc = (int)bit_state[1];
    int64_t out_idx = 0;
    int64_t stored_bytes = ((bc + 3 + 7) >> 3) + 4 + chunk_len;
    if (dst_cap < stored_bytes + 8) return -1;

    if (chunk_len == 0) {
        wing_bw_put(&bits, &bc, (uint32_t)(is_final ? 1U : 0U), 3, dst, &out_idx);
        while (bc >= 8) {
            dst[out_idx++] = (uint8_t)bits;
            bits >>= 8;
            bc -= 8;
        }
        if (bc > 0) {
            dst[out_idx++] = (uint8_t)bits;
            bits = 0;
            bc = 0;
        }
        dst[out_idx++] = 0;
        dst[out_idx++] = 0;
        dst[out_idx++] = 0xFF;
        dst[out_idx++] = 0xFF;
        bit_state[0] = bits;
        bit_state[1] = (uint64_t)bc;
        return out_idx;
    }

    uint32_t h_mask = (uint32_t)(head_len - 1);
    uint32_t h_shift = 32U - wing_bsr_u32((uint32_t)head_len);
    uint64_t saved_bits = bits;
    int saved_bc = bc;
    wing_bw_put(&bits, &bc, (uint32_t)(is_final ? 3U : 2U), 3, dst, &out_idx);

    int64_t pos = chunk_start;
    int64_t limit = chunk_end - 12;
    int64_t probe_mark = chunk_start + 2048;
    uint32_t miss = 32;
    uint32_t matches = 0;
    int bail_stored = 0;

    while (pos <= limit) {
        uint32_t v;
        memcpy(&v, src + pos, 4);
        uint32_t h = ((v * WING_LZ_HASH_MUL) >> h_shift) & h_mask;
        int64_t cand_p1 = (int64_t)head[h];
        head[h] = (uint32_t)(pos + 1);
        int64_t cand = cand_p1 - 1;
        int64_t dist = pos - cand;
        if (cand_p1 > 0 && dist > 0 && dist <= 32768) {
            uint32_t cv;
            memcpy(&cv, src + cand, 4);
            if (cv == v) {
                if (out_idx >= stored_bytes) {
                    bail_stored = 1;
                    break;
                }
                miss = 32;
                matches++;
                int32_t mlen = wing_extend_match_avx2(src + pos, src + cand, chunk_end - pos);
                uint32_t lp = wing_fix_len_pack[mlen];
                wing_bw_put(&bits, &bc, lp >> 5, (int)(lp & 31U), dst, &out_idx);
                wing_emit_dist_fast((uint32_t)dist, &bits, &bc, dst, &out_idx);
                pos += mlen;
                if (mlen <= 16 && pos <= limit) {
                    uint32_t av;
                    memcpy(&av, src + pos - 2, 4);
                    head[((av * WING_LZ_HASH_MUL) >> h_shift) & h_mask] = (uint32_t)(pos - 1);
                }
                continue;
            }
        }
        if (matches == 0 && pos >= probe_mark) {
            bail_stored = 1;
            break;
        }
        miss++;
        int64_t step = (int64_t)(miss >> 5);
        int64_t stop = pos + step;
        if (stop > limit + 1) stop = limit + 1;
        while (pos < stop) {
            if (out_idx >= stored_bytes) {
                bail_stored = 1;
                break;
            }
            uint16_t lit_p = wing_fix_lit_pack[src[pos++]];
            wing_bw_put(&bits, &bc, lit_p >> 4, (int)(lit_p & 15U), dst, &out_idx);
        }
        if (bail_stored) break;
    }

    if (!bail_stored) {
        while (pos < chunk_end) {
            if (out_idx >= stored_bytes) {
                bail_stored = 1;
                break;
            }
            uint16_t lit_p = wing_fix_lit_pack[src[pos++]];
            wing_bw_put(&bits, &bc, lit_p >> 4, (int)(lit_p & 15U), dst, &out_idx);
        }
    }
    if (!bail_stored) {
        if (out_idx >= stored_bytes) {
            bail_stored = 1;
        } else {
            wing_bw_put(&bits, &bc, 0U, 7, dst, &out_idx);
            while (bc >= 8) {
                if (out_idx >= dst_cap) {
                    bail_stored = 1;
                    break;
                }
                dst[out_idx++] = (uint8_t)bits;
                bits >>= 8;
                bc -= 8;
            }
            if (!bail_stored) {
                int64_t emitted_bytes = out_idx + ((bc - saved_bc + 7) >> 3);
                if (emitted_bytes >= stored_bytes) bail_stored = 1;
            }
        }
    }

    if (bail_stored) {
        out_idx = 0;
        bits = saved_bits;
        bc = saved_bc;
        wing_bw_put(&bits, &bc, (uint32_t)(is_final ? 1U : 0U), 3, dst, &out_idx);
        while (bc >= 8) {
            dst[out_idx++] = (uint8_t)bits;
            bits >>= 8;
            bc -= 8;
        }
        if (bc > 0) {
            dst[out_idx++] = (uint8_t)bits;
            bits = 0;
            bc = 0;
        }
        uint16_t blen = (uint16_t)chunk_len;
        uint16_t bnlen = (uint16_t)(~blen);
        memcpy(dst + out_idx, &blen, 2);
        memcpy(dst + out_idx + 2, &bnlen, 2);
        memcpy(dst + out_idx + 4, src + chunk_start, (size_t)chunk_len);
        out_idx += 4 + chunk_len;
    }

    if (is_final && bc > 0) {
        dst[out_idx++] = (uint8_t)bits;
        bits = 0;
        bc = 0;
    }
    bit_state[0] = bits;
    bit_state[1] = (uint64_t)bc;
    return out_idx;
}
#endif

int64_t wing_simd_deflate_l1_chunk(wing_bytes_ro src, int64_t chunk_start, int64_t chunk_end, int32_t is_final,
                                   wing_u32_rw head, wing_u64_rw bit_state, wing_bytes_rw dst) {
    if (!head.data || head.len < 64 || head.len > (1LL << 30) || (head.len & (head.len - 1)) != 0) return -1;
    if (!bit_state.data || bit_state.len < 2 || bit_state.data[1] > 31ULL) return -1;
    if (!dst.data || dst.len <= 0) return -1;
    if (chunk_start < 0 || chunk_end < chunk_start || chunk_end > src.len) return -1;
    if (chunk_end > chunk_start && !src.data) return -1;
#if defined(__x86_64__) || defined(_M_X64)
    if (wing_compress_cpu_caps() & WING_CAP_AVX2) {
        wing_init_fix_enc_tables();
        return wing_deflate_l1_chunk_avx2(src.data, chunk_start, chunk_end, is_final, head.data, head.len,
                                          bit_state.data, dst.data, dst.len);
    }
#endif
    return -2;
}

#if defined(_WIN32)
typedef LONG(WINAPI *wing_bcrypt_gen_random_fn)(void *, unsigned char *, unsigned long, unsigned long);
typedef BOOLEAN(WINAPI *wing_rtl_gen_random_fn)(void *, unsigned long);

static int32_t wing_win32_random_bytes(uint8_t *dst, int64_t len) {
    static wing_bcrypt_gen_random_fn cached_bcrypt = NULL;
    static wing_rtl_gen_random_fn cached_rtl = NULL;
    static volatile LONG init_state = 0;

    if (InterlockedCompareExchange(&init_state, 0, 0) != 2) {
        if (InterlockedCompareExchange(&init_state, 1, 0) == 0) {
            HMODULE h_bcrypt = LoadLibraryExA("bcrypt.dll", NULL, LOAD_LIBRARY_SEARCH_SYSTEM32);
            if (!h_bcrypt) h_bcrypt = LoadLibraryA("bcrypt.dll");
            if (h_bcrypt) {
                FARPROC p = GetProcAddress(h_bcrypt, "BCryptGenRandom");
                if (p) memcpy(&cached_bcrypt, &p, sizeof(cached_bcrypt));
            }
            if (!cached_bcrypt) {
                HMODULE h_advapi = LoadLibraryExA("advapi32.dll", NULL, LOAD_LIBRARY_SEARCH_SYSTEM32);
                if (!h_advapi) h_advapi = LoadLibraryA("advapi32.dll");
                if (h_advapi) {
                    FARPROC p = GetProcAddress(h_advapi, "SystemFunction036");
                    if (p) memcpy(&cached_rtl, &p, sizeof(cached_rtl));
                }
            }
            InterlockedExchange(&init_state, 2);
        } else {
            while (InterlockedCompareExchange(&init_state, 0, 0) != 2) {
                Sleep(0);
            }
        }
    }

    int64_t off = 0;
    while (off < len) {
        int64_t rem = len - off;
        unsigned long chunk = (rem > 0x40000000LL) ? 0x40000000UL : (unsigned long)rem;
        if (cached_bcrypt) {
            if (cached_bcrypt(NULL, dst + off, chunk, 0x00000002UL) != 0) return 0;
        } else if (cached_rtl) {
            if (!cached_rtl(dst + off, chunk)) return 0;
        } else {
            return 0;
        }
        off += (int64_t)chunk;
    }
    return 1;
}
#endif

int32_t wing_os_random_bytes(wing_bytes_rw dst) {
    if (!dst.data || dst.len <= 0) return 0;
#if defined(_WIN32)
    return wing_win32_random_bytes(dst.data, dst.len);
#elif defined(__APPLE__) || defined(__FreeBSD__) || defined(__OpenBSD__) || defined(__NetBSD__)
    arc4random_buf(dst.data, (size_t)dst.len);
    return 1;
#elif defined(__linux__)
    int64_t off = 0;
    while (off < dst.len) {
        ssize_t n = getrandom(dst.data + off, (size_t)(dst.len - off), 0);
        if (n < 0) {
            if (errno == EINTR) continue;
            return 0;
        }
        if (n == 0) return 0;
        off += (int64_t)n;
    }
    return 1;
#else
    int fd = open("/dev/urandom", O_RDONLY | O_CLOEXEC);
    if (fd < 0) return 0;
    int64_t off = 0;
    while (off < dst.len) {
        ssize_t n = read(fd, dst.data + off, (size_t)(dst.len - off));
        if (n < 0) {
            if (errno == EINTR) continue;
            close(fd);
            return 0;
        }
        if (n == 0) {
            close(fd);
            return 0;
        }
        off += (int64_t)n;
    }
    close(fd);
    return 1;
#endif
}

#if defined(__GNUC__) || defined(__clang__)
#define WING_WEAK __attribute__((weak))
#else
#define WING_WEAK
#endif

WING_WEAK int64_t lit_prof_enter(wing_bytes_ro name) {
    (void)name;
    return -1;
}

WING_WEAK void lit_prof_leave(int64_t span_tok) { (void)span_tok; }

WING_WEAK uint64_t lit_rdtsc(void) {
#if defined(_MSC_VER)
    return (uint64_t)__rdtsc();
#elif defined(__x86_64__) || defined(__i386__)
    return (uint64_t)__rdtsc();
#elif defined(__aarch64__)
    uint64_t v = 0;
    __asm__ __volatile__("mrs %0, cntvct_el0" : "=r"(v));
    return v;
#else
    return 0;
#endif
}
