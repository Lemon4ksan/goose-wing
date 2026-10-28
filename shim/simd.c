// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// shim/simd.c - SIMD acceleration primitives for goose-wing
// Provides vectorized WebSocket unmasking, ASCII/UTF-8 fast scan, and CRLF delimiter detection.

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <string.h>

#if defined(_MSC_VER)
#include <intrin.h>
#elif defined(__x86_64__) || defined(__i386__)
#include <cpuid.h>
#include <immintrin.h>
#elif defined(__ARM_NEON) || defined(__aarch64__)
#include <arm_neon.h>
#endif

typedef struct {
    uint8_t *data;
    int64_t len;
} wing_bytes_rw;
typedef struct {
    const uint8_t *data;
    int64_t len;
} wing_bytes_ro;

// Forward declaration from shim/tcp.c
int32_t wing_tcp_send(int64_t sock_fd, wing_bytes_ro data);

// Ultra-fast AVX2 vector batch cork buffer appending for fixed responses
// Streams 32-byte vector registers directly into cork buffer and flushes when full.
int64_t wing_fast_cork_append(int64_t conn, wing_bytes_rw cork_buf, int64_t cork_len, wing_bytes_ro resp) {
    if (!cork_buf.data || !resp.data || resp.len <= 0) return cork_len;
    int64_t clen = cork_len;
    int64_t rlen = resp.len;

    if (clen + rlen > cork_buf.len) {
        const uint8_t *p = cork_buf.data;
        size_t rem = (size_t)clen;
        int attempts = 0;
        while (rem > 0 && attempts++ < 16) {
            wing_bytes_ro to_send = {p, (int64_t)rem};
            int32_t sent = wing_tcp_send(conn, to_send);
            if (sent <= 0) return -1;
            p += sent;
            rem -= (size_t)sent;
        }
        if (rem > 0) return -1;
        clen = 0;
    }

    uint8_t *dst = cork_buf.data + clen;
    const uint8_t *src = resp.data;

#if defined(__AVX2__)
    if (rlen == 122) {
        // Plaintext response (122 bytes) in 4 AVX2 unrolled stores
        _mm256_storeu_si256((__m256i *)dst, _mm256_loadu_si256((const __m256i *)src));
        _mm256_storeu_si256((__m256i *)(dst + 32), _mm256_loadu_si256((const __m256i *)(src + 32)));
        _mm256_storeu_si256((__m256i *)(dst + 64), _mm256_loadu_si256((const __m256i *)(src + 64)));
        _mm256_storeu_si256((__m256i *)(dst + 90), _mm256_loadu_si256((const __m256i *)(src + 90)));
        return clen + 122;
    } else if (rlen == 488) {
        // 4x unrolled plaintext response (488 bytes) in 15 AVX2 stores + 8-byte trailer
        for (int k = 0; k < 15; k++) {
            _mm256_storeu_si256((__m256i *)(dst + k * 32), _mm256_loadu_si256((const __m256i *)(src + k * 32)));
        }
        memcpy(dst + 480, src + 480, 8);
        return clen + 488;
    } else if (rlen == 142) {
        // JSON response (142 bytes) in 4 AVX2 stores + 1 SSE2 store
        _mm256_storeu_si256((__m256i *)dst, _mm256_loadu_si256((const __m256i *)src));
        _mm256_storeu_si256((__m256i *)(dst + 32), _mm256_loadu_si256((const __m256i *)(src + 32)));
        _mm256_storeu_si256((__m256i *)(dst + 64), _mm256_loadu_si256((const __m256i *)(src + 64)));
        _mm256_storeu_si256((__m256i *)(dst + 96), _mm256_loadu_si256((const __m256i *)(src + 96)));
        _mm_storeu_si128((__m128i *)(dst + 126), _mm_loadu_si128((const __m128i *)(src + 126)));
        return clen + 142;
    }

    size_t i = 0;
    while (i + 32 <= (size_t)rlen) {
        _mm256_storeu_si256((__m256i *)(dst + i), _mm256_loadu_si256((const __m256i *)(src + i)));
        i += 32;
    }
    if (i + 16 <= (size_t)rlen) {
        _mm_storeu_si128((__m128i *)(dst + i), _mm_loadu_si128((const __m128i *)(src + i)));
        i += 16;
    }
    while (i < (size_t)rlen) {
        dst[i] = src[i];
        i++;
    }
#elif (defined(__SSE2__) || defined(__x86_64__) || defined(_M_AMD64))
    if (rlen == 122) {
        for (int k = 0; k < 7; k++) {
            _mm_storeu_si128((__m128i *)(dst + k * 16), _mm_loadu_si128((const __m128i *)(src + k * 16)));
        }
        _mm_storeu_si128((__m128i *)(dst + 106), _mm_loadu_si128((const __m128i *)(src + 106)));
        return clen + 122;
    } else if (rlen == 142) {
        for (int k = 0; k < 8; k++) {
            _mm_storeu_si128((__m128i *)(dst + k * 16), _mm_loadu_si128((const __m128i *)(src + k * 16)));
        }
        _mm_storeu_si128((__m128i *)(dst + 126), _mm_loadu_si128((const __m128i *)(src + 126)));
        return clen + 142;
    }

    size_t i = 0;
    while (i + 16 <= (size_t)rlen) {
        _mm_storeu_si128((__m128i *)(dst + i), _mm_loadu_si128((const __m128i *)(src + i)));
        i += 16;
    }
    while (i < (size_t)rlen) {
        dst[i] = src[i];
        i++;
    }
#else
    memcpy(dst, src, (size_t)rlen);
#endif

    return clen + rlen;
}

// Vectorized WebSocket payload XOR masking / unmasking (RFC 6455 §5.3)
// Replicates 4-byte mask across 128-bit/256-bit SIMD registers.
void wing_simd_mask_websocket(wing_bytes_rw slice, const uint8_t mask[4]) {
    uint8_t *data = slice.data;
    size_t len = (size_t)slice.len;
    if (!data || len == 0 || !mask) return;

    size_t i = 0;

    // 32-bit scalar pattern
    uint32_t mask32;
    memcpy(&mask32, mask, 4);

    // 64-bit scalar pattern
    uint64_t mask64 = ((uint64_t)mask32 << 32) | mask32;

#if (defined(__x86_64__) || defined(_M_AMD64)) && !defined(__ARM_NEON)
    // 128-bit SSE2 is universally available on x86_64
    __m128i mask128 = _mm_set1_epi32((int)mask32);

    while (i + 64 <= len) {
        __m128i v0 = _mm_loadu_si128((const __m128i *)(data + i));
        __m128i v1 = _mm_loadu_si128((const __m128i *)(data + i + 16));
        __m128i v2 = _mm_loadu_si128((const __m128i *)(data + i + 32));
        __m128i v3 = _mm_loadu_si128((const __m128i *)(data + i + 48));

        _mm_storeu_si128((__m128i *)(data + i), _mm_xor_si128(v0, mask128));
        _mm_storeu_si128((__m128i *)(data + i + 16), _mm_xor_si128(v1, mask128));
        _mm_storeu_si128((__m128i *)(data + i + 32), _mm_xor_si128(v2, mask128));
        _mm_storeu_si128((__m128i *)(data + i + 48), _mm_xor_si128(v3, mask128));

        i += 64;
    }

    while (i + 16 <= len) {
        __m128i v = _mm_loadu_si128((const __m128i *)(data + i));
        _mm_storeu_si128((__m128i *)(data + i), _mm_xor_si128(v, mask128));
        i += 16;
    }
#elif defined(__ARM_NEON) || defined(__aarch64__) || defined(_M_ARM64)
    uint8x16_t mask128 = vld1q_dup_u32(&mask32);
    while (i + 16 <= len) {
        uint8x16_t v = vld1q_u8(data + i);
        vst1q_u8(data + i, veorq_u8(v, mask128));
        i += 16;
    }
#endif

    // 64-bit unrolled tail
    while (i + 8 <= len) {
        uint64_t val;
        memcpy(&val, data + i, 8);
        val ^= mask64;
        memcpy(data + i, &val, 8);
        i += 8;
    }

    // Byte-by-byte tail (0..7 bytes)
    while (i < len) {
        data[i] ^= mask[i % 4];
        i++;
    }
}

// Fast SIMD check if buffer contains pure ASCII (0x00..0x7F)
// Returns 1 if all bytes < 0x80 (pure ASCII / valid 1-byte UTF-8), 0 otherwise.
int32_t wing_simd_is_pure_ascii(wing_bytes_ro slice) {
    const uint8_t *data = slice.data;
    size_t len = (size_t)slice.len;
    if (!data || len == 0) return 1;

    size_t i = 0;

#if (defined(__x86_64__) || defined(_M_AMD64)) && !defined(__ARM_NEON)
    while (i + 16 <= len) {
        __m128i v = _mm_loadu_si128((const __m128i *)(data + i));
        int mask = _mm_movemask_epi8(v);
        if (mask != 0) return 0;
        i += 16;
    }
#endif

    // 64-bit word check for remaining bytes
    while (i + 8 <= len) {
        uint64_t val;
        memcpy(&val, data + i, 8);
        if ((val & 0x8080808080808080ULL) != 0) return 0;
        i += 8;
    }

    while (i < len) {
        if (data[i] >= 0x80) return 0;
        i++;
    }

    return 1;
}

// Scans for CRLF (\r\n) in HTTP wire data using vectorization
// Returns offset of '\r' if found, or -1 if not found.
int64_t wing_simd_find_crlf(wing_bytes_ro slice) {
    const uint8_t *data = slice.data;
    size_t len = (size_t)slice.len;
    if (!data || len < 2) return -1;

    size_t i = 0;

#if (defined(__x86_64__) || defined(_M_AMD64)) && !defined(__ARM_NEON)
    __m128i cr = _mm_set1_epi8('\r');
    while (i + 16 <= len) {
        __m128i v = _mm_loadu_si128((const __m128i *)(data + i));
        __m128i cmp = _mm_cmpeq_epi8(v, cr);
        int mask = _mm_movemask_epi8(cmp);
        if (mask != 0) {
            for (int bit = 0; bit < 16; bit++) {
                if ((mask & (1 << bit)) != 0) {
                    size_t pos = i + bit;
                    if (pos + 1 < len && data[pos + 1] == '\n') {
                        return (int64_t)pos;
                    }
                }
            }
        }
        i += 16;
    }
#endif

    while (i + 1 < len) {
        if (data[i] == '\r' && data[i + 1] == '\n') {
            return (int64_t)i;
        }
        i++;
    }

    return -1;
}

// In-place zero-copy WebSocket payload unmasking with frame header overwrite (uWebSockets unmaskImprecise8)
// Shifts the unmasked payload back over the 6-, 8-, or 14-byte frame header directly.
void wing_simd_unmask_shifted(wing_bytes_rw slice, int64_t header_len, int64_t payload_len, const uint8_t mask[4]) {
    uint8_t *frame = slice.data;
    if (!frame || payload_len <= 0 || header_len <= 0 || !mask) return;
    if ((size_t)slice.len < (size_t)(header_len + payload_len)) return;

    uint32_t mask32;
    memcpy(&mask32, mask, 4);
    uint64_t mask64 = ((uint64_t)mask32 << 32) | mask32;

    uint8_t *src = frame + header_len;
    uint8_t *dst = frame;
    size_t len = (size_t)payload_len;
    size_t i = 0;

#if defined(__AVX2__)
    __m256i mask256 = _mm256_set1_epi32((int)mask32);
    while (i + 32 <= len) {
        __m256i v = _mm256_loadu_si256((const __m256i *)(src + i));
        _mm256_storeu_si256((__m256i *)(dst + i), _mm256_xor_si256(v, mask256));
        i += 32;
    }
#elif (defined(__x86_64__) || defined(_M_AMD64)) && !defined(__ARM_NEON)
    // 128-bit SSE2 vectorization: reads 16 bytes from (src + i) and stores unmasked to (dst + i).
    // Because dst lags src by header_len >= 6, load occurs before store, safe from clobbering.
    __m128i mask128 = _mm_set1_epi32((int)mask32);
    while (i + 16 <= len) {
        __m128i v = _mm_loadu_si128((const __m128i *)(src + i));
        _mm_storeu_si128((__m128i *)(dst + i), _mm_xor_si128(v, mask128));
        i += 16;
    }
#elif defined(__ARM_NEON) || defined(__aarch64__) || defined(_M_ARM64)
    uint8x16_t mask128 = vld1q_dup_u32(&mask32);
    while (i + 16 <= len) {
        uint8x16_t v = vld1q_u8(src + i);
        vst1q_u8(dst + i, veorq_u8(v, mask128));
        i += 16;
    }
#endif

    // 64-bit unrolled copy & XOR tail
    while (i + 8 <= len) {
        uint64_t loaded;
        memcpy(&loaded, src + i, 8);
        loaded ^= mask64;
        memcpy(dst + i, &loaded, 8);
        i += 8;
    }

    // Remaining tail (0..7 bytes)
    while (i < len) {
        dst[i] = src[i] ^ mask[i % 4];
        i++;
    }
}

// High-performance CRLFCRLF (\r\n\r\n) HTTP header delimiter scanner.
// Uses AVX2 / SSE2 32-byte & 16-byte parallel comparison registers with bitmask reduction.
int64_t wing_fast_find_crlfcrlf(wing_bytes_ro slice) {
    const uint8_t *data = slice.data;
    size_t len = (size_t)slice.len;
    if (!data || len < 4) return -1;

    size_t limit = len - 4;
    size_t i = 0;

#if defined(__AVX2__)
    const __m256i cr = _mm256_set1_epi8('\r');
    const __m256i lf = _mm256_set1_epi8('\n');

    while (i + 32 <= len) {
        __m256i chunk = _mm256_loadu_si256((const __m256i *)(data + i));
        uint32_t mask_cr = (uint32_t)_mm256_movemask_epi8(_mm256_cmpeq_epi8(chunk, cr));
        uint32_t mask_lf = (uint32_t)_mm256_movemask_epi8(_mm256_cmpeq_epi8(chunk, lf));

        uint32_t match = mask_cr & (mask_lf >> 1) & (mask_cr >> 2) & (mask_lf >> 3);
        if (match != 0) {
#if defined(__GNUC__) || defined(__clang__)
            int offset = __builtin_ctz(match);
#elif defined(_MSC_VER)
            unsigned long offset;
            _BitScanForward(&offset, match);
#else
            int offset = 0;
            while ((match & (1u << offset)) == 0)
                offset++;
#endif
            return (int64_t)(i + offset);
        }
        i += 29;
    }

    if (len >= 32 && i <= limit) {
        __m256i chunk = _mm256_loadu_si256((const __m256i *)(data + len - 32));
        uint32_t mask_cr = (uint32_t)_mm256_movemask_epi8(_mm256_cmpeq_epi8(chunk, cr));
        uint32_t mask_lf = (uint32_t)_mm256_movemask_epi8(_mm256_cmpeq_epi8(chunk, lf));

        uint32_t match = mask_cr & (mask_lf >> 1) & (mask_cr >> 2) & (mask_lf >> 3);
        if (match != 0) {
#if defined(__GNUC__) || defined(__clang__)
            int offset = __builtin_ctz(match);
#elif defined(_MSC_VER)
            unsigned long offset;
            _BitScanForward(&offset, match);
#else
            int offset = 0;
            while ((match & (1u << offset)) == 0)
                offset++;
#endif
            return (int64_t)(len - 32 + offset);
        }
        return -1;
    }
#elif defined(__SSE2__) || defined(__x86_64__) || defined(_M_AMD64)
    const __m128i cr = _mm_set1_epi8('\r');
    const __m128i lf = _mm_set1_epi8('\n');

    while (i + 16 <= len) {
        __m128i chunk = _mm_loadu_si128((const __m128i *)(data + i));
        uint32_t mask_cr = (uint32_t)_mm_movemask_epi8(_mm_cmpeq_epi8(chunk, cr));
        uint32_t mask_lf = (uint32_t)_mm_movemask_epi8(_mm_cmpeq_epi8(chunk, lf));

        uint32_t match = mask_cr & (mask_lf >> 1) & (mask_cr >> 2) & (mask_lf >> 3);
        if (match != 0) {
#if defined(__GNUC__) || defined(__clang__)
            int offset = __builtin_ctz(match);
#elif defined(_MSC_VER)
            unsigned long offset;
            _BitScanForward(&offset, match);
#else
            int offset = 0;
            while ((match & (1u << offset)) == 0)
                offset++;
#endif
            return (int64_t)(i + offset);
        }
        i += 13;
    }

    if (len >= 16 && i <= limit) {
        __m128i chunk = _mm_loadu_si128((const __m128i *)(data + len - 16));
        uint32_t mask_cr = (uint32_t)_mm_movemask_epi8(_mm_cmpeq_epi8(chunk, cr));
        uint32_t mask_lf = (uint32_t)_mm_movemask_epi8(_mm_cmpeq_epi8(chunk, lf));

        uint32_t match = mask_cr & (mask_lf >> 1) & (mask_cr >> 2) & (mask_lf >> 3);
        if (match != 0) {
#if defined(__GNUC__) || defined(__clang__)
            int offset = __builtin_ctz(match);
#elif defined(_MSC_VER)
            unsigned long offset;
            _BitScanForward(&offset, match);
#else
            int offset = 0;
            while ((match & (1u << offset)) == 0)
                offset++;
#endif
            return (int64_t)(len - 16 + offset);
        }
        return -1;
    }
#endif

    while (i <= limit) {
        uint32_t val;
        memcpy(&val, data + i, 4);
        if (val == 0x0A0D0A0D) {
            return (int64_t)i;
        }
        const uint8_t *next_cr = (const uint8_t *)memchr(data + i + 1, '\r', limit - i);
        if (!next_cr) return -1;
        i = (size_t)(next_cr - data);
    }
    return -1;
}

// 64-bit SWAR (SIMD Within A Register) character scanner (uWebSockets HttpParser.h)
// Evaluates 8 bytes in parallel in 1 CPU cycle for characters < n (e.g. n=32 detects control characters, CRLF, NUL)
static inline uint64_t wing_swar_has_less(uint64_t x, uint64_t n) {
    return (((x)-0x0101010101010101ULL * (n)) & ~(x) & 0x8080808080808080ULL);
}

// Scans slice 8 bytes at a time for any control character (< 32, including \r, \n, \t, \0)
// Returns offset of first control character, or len if none found.
int64_t wing_swar_find_ctl(wing_bytes_ro slice) {
    const uint8_t *data = slice.data;
    size_t len = (size_t)slice.len;
    if (!data || len == 0) return 0;

    size_t i = 0;
    while (i + 8 <= len) {
        uint64_t word;
        memcpy(&word, data + i, 8);
        if (wing_swar_has_less(word, 32)) {
            while (i < len && data[i] >= 32)
                i++;
            return (int64_t)i;
        }
        i += 8;
    }

    while (i < len) {
        if (data[i] < 32) return (int64_t)i;
        i++;
    }

    return (int64_t)len;
}

// High-throughput branchless/tableless integer-to-ASCII serializers (uWebSockets Utilities.h)
int32_t wing_fast_u64toa(uint64_t value, wing_bytes_rw dst) {
    if (!dst.data || dst.len < 1) return 0;
    if (value == 0) {
        dst.data[0] = '0';
        return 1;
    }
    char temp[24];
    char *p = temp;
    do {
        *p++ = (char)((value % 10) + '0');
        value /= 10;
    } while (value > 0);

    int32_t ret = (int32_t)(p - temp);
    if ((int64_t)ret > dst.len) return 0;

    uint8_t *out = dst.data;
    do {
        *out++ = (uint8_t)*--p;
    } while (p != temp);

    return ret;
}

int32_t wing_fast_u32toa_hex(uint32_t value, wing_bytes_rw dst) {
    if (!dst.data || dst.len < 1) return 0;
    static const char palette[] = "0123456789abcdef";
    char temp[16];
    char *p = temp;
    do {
        *p++ = palette[value & 15];
        value >>= 4;
    } while (value > 0);

    int32_t ret = (int32_t)(p - temp);
    if ((int64_t)ret > dst.len) return 0;

    uint8_t *out = dst.data;
    do {
        *out++ = (uint8_t)*--p;
    } while (p != temp);

    return ret;
}

// 64-bit SWAR parallel ASCII lowercase converter (Alex Hultman / uWebSockets HttpParser.h)
// Converts 8 ASCII bytes in parallel in 4 CPU cycles without branches.
// For any byte in 'A' (0x41) .. 'Z' (0x5A), sets bit 5 (0x20).
uint64_t wing_swar_to_lower_64(uint64_t v) {
    uint64_t is_upper = (v + 0x3F3F3F3F3F3F3F3FULL) & ~(v + 0x2525252525252525ULL) & 0x8080808080808080ULL;
    return v | (is_upper >> 2);
}

// In-place vectorized/SWAR ASCII lowercase conversion for HTTP header field names
void wing_swar_to_lower(wing_bytes_rw slice) {
    uint8_t *data = slice.data;
    size_t len = (size_t)slice.len;
    if (!data || len == 0) return;

    size_t i = 0;
    while (i + 8 <= len) {
        uint64_t word;
        memcpy(&word, data + i, 8);
        word = wing_swar_to_lower_64(word);
        memcpy(data + i, &word, 8);
        i += 8;
    }
    while (i < len) {
        uint8_t b = data[i];
        if (b >= 'A' && b <= 'Z') {
            data[i] = b | 32;
        }
        i++;
    }
}

// High-speed vectorized byte search using platform memchr (AVX2 / SSE2)
int64_t wing_memchr(wing_bytes_ro slice, uint8_t b) {
    if (!slice.data || slice.len <= 0) return -1;
    const void *p = memchr(slice.data, b, (size_t)slice.len);
    if (!p) return -1;
    return (int64_t)((const uint8_t *)p - slice.data);
}

// 64-bit SWAR case-insensitive equality comparison (8 bytes per cycle)
int32_t wing_swar_eq_ascii_fold(wing_bytes_ro a, wing_bytes_ro b) {
    if (a.len != b.len) return 0;
    if (a.data == b.data) return 1;
    size_t len = (size_t)a.len;
    const uint8_t *da = a.data;
    const uint8_t *db = b.data;
    if (!da || !db) return 0;
    if (memcmp(da, db, len) == 0) return 1;

    size_t i = 0;
    while (i + 8 <= len) {
        uint64_t wa, wb;
        memcpy(&wa, da + i, 8);
        memcpy(&wb, db + i, 8);
        if (wing_swar_to_lower_64(wa) != wing_swar_to_lower_64(wb)) {
            return 0;
        }
        i += 8;
    }
    while (i < len) {
        uint8_t ca = (da[i] >= 'A' && da[i] <= 'Z') ? (da[i] + 32) : da[i];
        uint8_t cb = (db[i] >= 'A' && db[i] <= 'Z') ? (db[i] + 32) : db[i];
        if (ca != cb) return 0;
        i++;
    }
    return 1;
}
