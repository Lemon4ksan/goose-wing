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
typedef struct {
    const uint32_t *data;
    int64_t len;
} wing_u32_ro;

// Forward declaration from shim/tcp.c
int32_t wing_tcp_send(int64_t sock_fd, wing_bytes_ro data);

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

// Ultra-fast AVX2 vector batch cork buffer appending for fixed responses
// Streams 32-byte vector registers directly into cork buffer and flushes when full.
int64_t wing_fast_cork_append(int64_t conn, wing_bytes_rw cork_buf, int64_t cork_len, wing_bytes_ro resp) {
    if (!cork_buf.data || cork_buf.len <= 0 || cork_len < 0 || cork_len > cork_buf.len) return -1;
    if (!resp.data || resp.len <= 0) return cork_len;
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

        if (rlen > cork_buf.len) {
            const uint8_t *rp = resp.data;
            size_t rrem = (size_t)rlen;
            attempts = 0;
            while (rrem > 0 && attempts++ < 32) {
                wing_bytes_ro to_send = {rp, (int64_t)rrem};
                int32_t sent = wing_tcp_send(conn, to_send);
                if (sent <= 0) return -1;
                rp += sent;
                rrem -= (size_t)sent;
            }
            return (rrem == 0) ? 0 : -1;
        }
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

// Scans active readable data for any control character (< 32, including \r, \n, \t, \0)
// Returns offset of first control character, or len if none found.
int64_t wing_swar_find_ctl(wing_bytes_ro slice) {
    if (!slice.data || slice.len <= 0) return 0;
    const uint8_t *data = slice.data;
    size_t len = (size_t)slice.len;

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
    for (int32_t i = 0; i < ret; i++) {
        out[i] = (uint8_t)temp[ret - 1 - i];
    }

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
    for (int32_t i = 0; i < ret; i++) {
        out[i] = (uint8_t)temp[ret - 1 - i];
    }

    return ret;
}

// 64-bit SWAR parallel ASCII lowercase converter (Alex Hultman / uWebSockets HttpParser.h)
// Converts 8 ASCII bytes in parallel in 4 CPU cycles without branches.
// For any byte in 'A' (0x41) .. 'Z' (0x5A), sets bit 5 (0x20).
uint64_t wing_swar_to_lower_64(uint64_t v) {
    uint64_t ascii = v & 0x7F7F7F7F7F7F7F7FULL;
    uint64_t not_high = ~v & 0x8080808080808080ULL;
    uint64_t is_upper = (ascii + 0x3F3F3F3F3F3F3F3FULL) & ~(ascii + 0x2525252525252525ULL) & not_high;
    return v | (is_upper >> 2);
}

// 64-bit SWAR parallel ASCII uppercase converter
// For any byte in 'a' (0x61) .. 'z' (0x7A), clears bit 5 (0x20).
uint64_t wing_swar_to_upper_64(uint64_t v) {
    uint64_t ascii = v & 0x7F7F7F7F7F7F7F7FULL;
    uint64_t not_high = ~v & 0x8080808080808080ULL;
    uint64_t is_lower = (ascii + 0x1F1F1F1F1F1F1F1FULL) & ~(ascii + 0x0505050505050505ULL) & not_high;
    return v ^ (is_lower >> 2);
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

// In-place vectorized/SWAR ASCII uppercase conversion
void wing_swar_to_upper(wing_bytes_rw slice) {
    uint8_t *data = slice.data;
    size_t len = (size_t)slice.len;
    if (!data || len == 0) return;

    size_t i = 0;
    while (i + 8 <= len) {
        uint64_t word;
        memcpy(&word, data + i, 8);
        word = wing_swar_to_upper_64(word);
        memcpy(data + i, &word, 8);
        i += 8;
    }
    while (i < len) {
        uint8_t b = data[i];
        if (b >= 'a' && b <= 'z') {
            data[i] = b - 32;
        }
        i++;
    }
}

// Vectorized packed-pair substring search (memchr 2.8.3 algorithm)
// Scans slice for occurrences of b1 at off1 and b2 at off2 using SIMD masks,
// then verifies candidate start with memcmp(..., needle.data, needle.len).
int64_t wing_simd_find_pair(wing_bytes_ro slice, uint8_t b1, int64_t off1, uint8_t b2, int64_t off2,
                            wing_bytes_ro needle) {
    if (!slice.data || !needle.data) return -1;
    int64_t nlen = needle.len;
    int64_t slen = slice.len;
    if (nlen <= 0) return 0;
    if (slen < nlen) return -1;
    if (off1 < 0 || off1 >= nlen || off2 < 0 || off2 >= nlen) return -1;

    int64_t limit = slen - nlen + 1;
    const uint8_t *s = slice.data;
    const uint8_t *nd = needle.data;
    size_t i = 0;

#if (defined(__AVX2__))
    __m256i vb1 = _mm256_set1_epi8((char)b1);
    __m256i vb2 = _mm256_set1_epi8((char)b2);
    while (i + 32 <= (size_t)limit) {
        __m256i v1 = _mm256_loadu_si256((const __m256i *)(s + i + off1));
        __m256i v2 = _mm256_loadu_si256((const __m256i *)(s + i + off2));
        __m256i eq = _mm256_and_si256(_mm256_cmpeq_epi8(v1, vb1), _mm256_cmpeq_epi8(v2, vb2));
        uint32_t mask = (uint32_t)_mm256_movemask_epi8(eq);
        while (mask != 0) {
#if defined(_MSC_VER)
            unsigned long bit;
            _BitScanForward(&bit, mask);
#else
            uint32_t bit = (uint32_t)__builtin_ctz(mask);
#endif
            size_t cand = i + bit;
            if (memcmp(s + cand, nd, (size_t)nlen) == 0) {
                return (int64_t)cand;
            }
            mask &= mask - 1;
        }
        i += 32;
    }
#elif (defined(__SSE2__) || defined(__x86_64__) || defined(_M_AMD64)) && !defined(__ARM_NEON)
    __m128i vb1 = _mm_set1_epi8((char)b1);
    __m128i vb2 = _mm_set1_epi8((char)b2);
    while (i + 16 <= (size_t)limit) {
        __m128i v1 = _mm_loadu_si128((const __m128i *)(s + i + off1));
        __m128i v2 = _mm_loadu_si128((const __m128i *)(s + i + off2));
        __m128i eq = _mm_and_si128(_mm_cmpeq_epi8(v1, vb1), _mm_cmpeq_epi8(v2, vb2));
        uint32_t mask = (uint32_t)(uint16_t)_mm_movemask_epi8(eq);
        while (mask != 0) {
#if defined(_MSC_VER)
            unsigned long bit;
            _BitScanForward(&bit, mask);
#else
            uint32_t bit = (uint32_t)__builtin_ctz(mask);
#endif
            size_t cand = i + bit;
            if (memcmp(s + cand, nd, (size_t)nlen) == 0) {
                return (int64_t)cand;
            }
            mask &= mask - 1;
        }
        i += 16;
    }
#elif defined(__ARM_NEON) || defined(__aarch64__)
    uint8x16_t vb1 = vdupq_n_u8(b1);
    uint8x16_t vb2 = vdupq_n_u8(b2);
    while (i + 16 <= (size_t)limit) {
        uint8x16_t v1 = vld1q_u8(s + i + off1);
        uint8x16_t v2 = vld1q_u8(s + i + off2);
        uint8x16_t eq = vandq_u8(vceqq_u8(v1, vb1), vceqq_u8(v2, vb2));
        if (vmaxvq_u8(eq) != 0) {
            for (size_t bit = 0; bit < 16; bit++) {
                if (s[i + bit + off1] == b1 && s[i + bit + off2] == b2) {
                    if (memcmp(s + i + bit, nd, (size_t)nlen) == 0) {
                        return (int64_t)(i + bit);
                    }
                }
            }
        }
        i += 16;
    }
#endif

    while (i < (size_t)limit) {
        if (s[i + off1] == b1 && s[i + off2] == b2) {
            if (memcmp(s + i, nd, (size_t)nlen) == 0) {
                return (int64_t)i;
            }
        }
        i++;
    }
    return -1;
}

// Reverse vectorized packed-pair substring search
int64_t wing_simd_rfind_pair(wing_bytes_ro slice, uint8_t b1, int64_t off1, uint8_t b2, int64_t off2,
                             wing_bytes_ro needle) {
    if (!slice.data || !needle.data) return -1;
    int64_t nlen = needle.len;
    int64_t slen = slice.len;
    if (nlen <= 0) return slen;
    if (slen < nlen) return -1;
    if (off1 < 0 || off1 >= nlen || off2 < 0 || off2 >= nlen) return -1;

    int64_t limit = slen - nlen + 1;
    const uint8_t *s = slice.data;
    const uint8_t *nd = needle.data;
    int64_t i = limit;

#if (defined(__AVX2__))
    __m256i vb1 = _mm256_set1_epi8((char)b1);
    __m256i vb2 = _mm256_set1_epi8((char)b2);
    while (i >= 32) {
        int64_t chunk_start = i - 32;
        __m256i v1 = _mm256_loadu_si256((const __m256i *)(s + chunk_start + off1));
        __m256i v2 = _mm256_loadu_si256((const __m256i *)(s + chunk_start + off2));
        __m256i eq = _mm256_and_si256(_mm256_cmpeq_epi8(v1, vb1), _mm256_cmpeq_epi8(v2, vb2));
        uint32_t mask = (uint32_t)_mm256_movemask_epi8(eq);
        while (mask != 0) {
#if defined(_MSC_VER)
            unsigned long bit;
            _BitScanReverse(&bit, mask);
#else
            uint32_t bit = 31 - (uint32_t)__builtin_clz(mask);
#endif
            int64_t cand = chunk_start + bit;
            if (memcmp(s + cand, nd, (size_t)nlen) == 0) {
                return cand;
            }
            mask &= ~((uint32_t)1 << bit);
        }
        i -= 32;
    }
#elif (defined(__SSE2__) || defined(__x86_64__) || defined(_M_AMD64)) && !defined(__ARM_NEON)
    __m128i vb1 = _mm_set1_epi8((char)b1);
    __m128i vb2 = _mm_set1_epi8((char)b2);
    while (i >= 16) {
        int64_t chunk_start = i - 16;
        __m128i v1 = _mm_loadu_si128((const __m128i *)(s + chunk_start + off1));
        __m128i v2 = _mm_loadu_si128((const __m128i *)(s + chunk_start + off2));
        __m128i eq = _mm_and_si128(_mm_cmpeq_epi8(v1, vb1), _mm_cmpeq_epi8(v2, vb2));
        uint32_t mask = (uint32_t)(uint16_t)_mm_movemask_epi8(eq);
        while (mask != 0) {
#if defined(_MSC_VER)
            unsigned long bit;
            _BitScanReverse(&bit, mask);
#else
            uint32_t bit = 31 - (uint32_t)__builtin_clz(mask);
#endif
            int64_t cand = chunk_start + bit;
            if (memcmp(s + cand, nd, (size_t)nlen) == 0) {
                return cand;
            }
            mask &= ~((uint32_t)1 << bit);
        }
        i -= 16;
    }
#endif

    while (i > 0) {
        i--;
        if (s[i + off1] == b1 && s[i + off2] == b2) {
            if (memcmp(s + i, nd, (size_t)nlen) == 0) {
                return i;
            }
        }
    }
    return -1;
}

// High-speed vectorized byte search using platform memchr (AVX2 / SSE2)
int64_t wing_memchr(wing_bytes_ro slice, uint8_t b) {
    if (!slice.data || slice.len <= 0) return -1;
    const void *p = memchr(slice.data, b, (size_t)slice.len);
    if (!p) return -1;
    return (int64_t)((const uint8_t *)p - slice.data);
}

// Vectorized byte counter using SSE2 / NEON / SWAR with hardware popcount
int64_t wing_simd_count_byte(wing_bytes_ro slice, uint8_t b) {
    const uint8_t *data = slice.data;
    size_t len = (size_t)slice.len;
    if (!data || len == 0) return 0;

    int64_t count = 0;
    size_t i = 0;

#if (defined(__x86_64__) || defined(_M_AMD64)) && !defined(__ARM_NEON)
    __m128i target = _mm_set1_epi8((char)b);
    while (i + 16 <= len) {
        __m128i v = _mm_loadu_si128((const __m128i *)(data + i));
        __m128i cmp = _mm_cmpeq_epi8(v, target);
        int mask = _mm_movemask_epi8(cmp);
#if defined(_MSC_VER)
        count += (int64_t)__popcnt((unsigned int)(uint16_t)mask);
#elif defined(__GNUC__) || defined(__clang__)
        count += (int64_t)__builtin_popcount(mask);
#else
        for (int bit = 0; bit < 16; bit++) {
            if ((mask & (1 << bit)) != 0) count++;
        }
#endif
        i += 16;
    }
#elif defined(__ARM_NEON) || defined(__aarch64__)
    uint8x16_t target = vdupq_n_u8(b);
    while (i + 16 <= len) {
        uint8x16_t v = vld1q_u8(data + i);
        uint8x16_t cmp = vceqq_u8(v, target);
        uint16_t sum = vaddlvq_u8(cmp);
        count += (int64_t)(sum / 255);
        i += 16;
    }
#endif

    while (i < len) {
        if (data[i] == b) count++;
        i++;
    }

    return count;
}

// High-speed reverse byte search using SSE2 vector comparison
int64_t wing_simd_last_index_of_byte(wing_bytes_ro slice, uint8_t b) {
    const uint8_t *data = slice.data;
    int64_t len = slice.len;
    if (!data || len <= 0) return -1;

#if (defined(__x86_64__) || defined(_M_AMD64)) && !defined(__ARM_NEON)
    __m128i target = _mm_set1_epi8((char)b);
    int64_t i = len;
    while (i >= 16) {
        int64_t chunk_start = i - 16;
        __m128i v = _mm_loadu_si128((const __m128i *)(data + chunk_start));
        __m128i cmp = _mm_cmpeq_epi8(v, target);
        int mask = _mm_movemask_epi8(cmp);
        if (mask != 0) {
#if defined(__GNUC__) || defined(__clang__)
            int bit = 31 - __builtin_clz(mask);
#elif defined(_MSC_VER)
            unsigned long bit;
            _BitScanReverse(&bit, (unsigned long)mask);
#else
            int bit = 15;
            while ((mask & (1 << bit)) == 0)
                bit--;
#endif
            return chunk_start + (int64_t)bit;
        }
        i -= 16;
    }
    while (i > 0) {
        i--;
        if (data[i] == b) return i;
    }
    return -1;
#else
    for (int64_t j = len - 1; j >= 0; j--) {
        if (data[j] == b) return j;
    }
    return -1;
#endif
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

// ---------------------------------------------------------------------------
// Software Prefetch Primitives for Cache-Line Acceleration
// ---------------------------------------------------------------------------

// Software prefetch to L1 Data Cache (temporal hint _MM_HINT_T0).
void wing_prefetch_t0(wing_bytes_ro slice) {
    if (!slice.data || slice.len <= 0) return;
    const char *p = (const char *)slice.data;
    size_t len = (size_t)slice.len;
    for (size_t i = 0; i < len; i += 64) {
#if defined(_MSC_VER)
        _mm_prefetch(p + i, _MM_HINT_T0);
#elif defined(__GNUC__) || defined(__clang__)
        __builtin_prefetch(p + i, 0, 3);
#endif
    }
}

// Non-temporal software prefetch for streaming one-pass reads (minimizes cache pollution).
void wing_prefetch_nta(wing_bytes_ro slice) {
    if (!slice.data || slice.len <= 0) return;
    const char *p = (const char *)slice.data;
    size_t len = (size_t)slice.len;
    for (size_t i = 0; i < len; i += 64) {
#if defined(_MSC_VER)
        _mm_prefetch(p + i, _MM_HINT_NTA);
#elif defined(__GNUC__) || defined(__clang__)
        __builtin_prefetch(p + i, 0, 0);
#endif
    }
}

// Cryptographically secure memory zeroization immune to dead-store elimination (DSE).
void wing_secure_zeroize(wing_bytes_rw slice) {
    if (!slice.data || slice.len <= 0) return;
#if defined(_MSC_VER)
    SecureZeroMemory(slice.data, (size_t)slice.len);
#elif defined(__STDC_LIB_EXT1__)
    memset_s(slice.data, (rsize_t)slice.len, 0, (rsize_t)slice.len);
#else
    volatile uint8_t *p = (volatile uint8_t *)slice.data;
    size_t len = (size_t)slice.len;
    while (len--) {
        *p++ = 0;
    }
#endif
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

#if defined(_MSC_VER) && !defined(__clang__)
static inline int wing_simd_ctz(unsigned int x) {
    unsigned long r;
    _BitScanForward(&r, x);
    return (int)r;
}
#define WING_CTZ(x) wing_simd_ctz(x)
#else
#define WING_CTZ(x) __builtin_ctz(x)
#endif

// Flat Register Routing (Tier 0 L0 Register Table)
// 16-slot Structure of Arrays (592 bytes) matching Goose L0RegisterTable.
typedef struct {
    uint64_t w0[16];           // Offset   0 (128 B)
    uint64_t w1[16];           // Offset 128 (128 B)
    uint16_t len[16];          // Offset 256  (32 B)
    uint8_t method_id[16];     // Offset 288  (16 B)
    uint8_t _pad1[16];         // Offset 304  (16 B)
    int32_t handler_id[16];    // Offset 320  (64 B)
    uint32_t entries_mask[16]; // Offset 384  (64 B)
    uint64_t pso_mask[16];     // Offset 448 (128 B)
    uint16_t active_mask;      // Offset 576   (2 B)
    uint16_t count;            // Offset 578   (2 B)
    uint8_t _pad2[12];         // Offset 580  (12 B)
} wing_l0_table_t;

// Matches an HTTP request wire path against the L0 Register Table using AVX2 or portable SWAR.
int32_t wing_simd_match_l0(wing_bytes_ro path, uint8_t method_id, const wing_l0_table_t *tbl) {
    if (!tbl || tbl->count == 0 || path.len <= 0 || path.len > 16) {
        return -1;
    }

    uint64_t w0 = 0;
    uint64_t w1 = 0;
    int64_t n0 = path.len < 8 ? path.len : 8;
    memcpy(&w0, path.data, (size_t)n0);
    if (path.len > 8) {
        int64_t rem = path.len - 8;
        int64_t n1 = rem < 8 ? rem : 8;
        memcpy(&w1, path.data + 8, (size_t)n1);
    }

#if defined(__AVX2__)
    __m256i req_w0 = _mm256_set1_epi64x((long long)w0);
    __m256i req_w1 = _mm256_set1_epi64x((long long)w1);

    for (int i = 0; i < 4; i++) {
        int base = i * 4;
        if (base >= (int)tbl->count) break;

        __m256i t_w0 = _mm256_loadu_si256((const __m256i *)(tbl->w0 + base));
        __m256i eq0 = _mm256_cmpeq_epi64(req_w0, t_w0);

        __m256i t_w1 = _mm256_loadu_si256((const __m256i *)(tbl->w1 + base));
        __m256i eq1 = _mm256_cmpeq_epi64(req_w1, t_w1);

        __m256i both = _mm256_and_si256(eq0, eq1);
        int mask = _mm256_movemask_pd(_mm256_castsi256_pd(both));

        while (mask != 0) {
            int bit = WING_CTZ((unsigned int)mask);
            int slot = base + bit;
            if (slot < (int)tbl->count && tbl->len[slot] == (uint16_t)path.len && tbl->method_id[slot] == method_id) {
                return slot;
            }
            mask &= mask - 1;
        }
    }
    return -1;
#else
    for (uint16_t i = 0; i < tbl->count; i++) {
        if (tbl->len[i] == (uint16_t)path.len && tbl->method_id[i] == method_id && tbl->w0[i] == w0 &&
            tbl->w1[i] == w1) {
            return (int32_t)i;
        }
    }
    return -1;
#endif
}

// Decodes RFC 7541 Appendix B Huffman-encoded `src` into `dst` using the 4096-entry
// nibble state transition table `table` (`fstate | (flags << 8) | (sym << 16)`).
// Returns decoded byte count (>= 0) on success, or -1 on invalid encoding or overflow.
int64_t wing_hpack_huff_decode(wing_bytes_ro src, wing_bytes_rw dst, wing_u32_ro table) {
    if (src.len < 0 || dst.len < 0 || !table.data || table.len != 4096) return -1;
    if (src.len == 0) return 0;
    if (!src.data || (!dst.data && dst.len > 0)) return -1;

    const uint8_t *s = src.data;
    uint8_t *out = dst.data;
    const uint32_t *tbl = table.data;
    int64_t s_len = src.len;
    int64_t d_len = dst.len;
    int64_t out_idx = 0;
    int64_t last_sym_byte = 0;
    uint8_t state = 0;
    uint8_t flags = 0x01; // HUFF_ACCEPTED

    for (int64_t i = 0; i < s_len; i++) {
        uint8_t c = s[i];
        int64_t next_i = i + 1;

        uint32_t d1 = tbl[((uint32_t)state << 4) | (c >> 4)];
        uint8_t f1 = (uint8_t)(d1 >> 8);
        if (f1 & 0x04) return -1; // HUFF_FAIL
        if (f1 & 0x02) { // HUFF_SYM
            if (out_idx >= d_len) return -1;
            out[out_idx++] = (uint8_t)(d1 >> 16);
            last_sym_byte = next_i;
        }
        state = (uint8_t)d1;

        uint32_t d2 = tbl[((uint32_t)state << 4) | (c & 0x0F)];
        uint8_t f2 = (uint8_t)(d2 >> 8);
        if (f2 & 0x04) return -1; // HUFF_FAIL
        if (f2 & 0x02) { // HUFF_SYM
            if (out_idx >= d_len) return -1;
            out[out_idx++] = (uint8_t)(d2 >> 16);
            last_sym_byte = next_i;
        }
        state = (uint8_t)d2;
        flags = f2;
    }

    if ((flags & 0x01) == 0 || last_sym_byte != s_len) return -1;
    return out_idx;
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

#define WING_CAP_SSSE3     (1 << 0)
#define WING_CAP_PCLMUL    (1 << 1)
#define WING_CAP_AVX2      (1 << 2)
#define WING_CAP_VPCLMUL   (1 << 3)

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
    long v = cached;
    if (v >= 0) return (int)v;
    int caps = 0;
    int info[4] = {0};
    __cpuid(info, 0);
    int max_leaf = info[0];
    if (max_leaf >= 1) {
        __cpuid(info, 1);
        int has_osxsave = (info[2] & (1 << 27)) != 0;
        int has_ssse3 = (info[2] & (1 << 9)) != 0;
        int has_sse41 = (info[2] & (1 << 19)) != 0;
        int has_pclmul = (info[2] & (1 << 1)) != 0;
        if (has_ssse3) caps |= WING_CAP_SSSE3;
        if (has_sse41 && has_pclmul) caps |= WING_CAP_PCLMUL;
        if (has_osxsave && max_leaf >= 7) {
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
    cached = caps;
    return caps;
#else
    return 0;
#endif
}

/* Reflected GF(2) folding constants for IEEE 802.3 CRC-32 (0xEDB88320):
 * P(x) = 0x104C11DB7, rk(n) = bit_reflect(x^n mod P(x), 33) */
#define WING_CRC32_P_REFL     0x1db710641ULL
#define WING_CRC32_MU_REFL    0x1f7011641ULL
#define WING_CRC32_RK64       0x163cd6124ULL
#define WING_CRC32_RK96       0x0ccaa009eULL
#define WING_CRC32_RK160      0x1751997d0ULL
#define WING_CRC32_RK224      0x15a546366ULL
#define WING_CRC32_RK288      0x0f1da05aaULL
#define WING_CRC32_RK480      0x1c6e41596ULL
#define WING_CRC32_RK544      0x154442bd4ULL
#define WING_CRC32_RK992      0x14a7fe880ULL
#define WING_CRC32_RK1056     0x1e88ef372ULL

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
        for (int k = 0; k < 8; k++) c = (c >> 1) ^ (0xEDB88320U & -(c & 1U));
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
        crc = wing_crc32_tables[7][lo & 0xFFU]
            ^ wing_crc32_tables[6][(lo >> 8) & 0xFFU]
            ^ wing_crc32_tables[5][(lo >> 16) & 0xFFU]
            ^ wing_crc32_tables[4][lo >> 24]
            ^ wing_crc32_tables[3][hi & 0xFFU]
            ^ wing_crc32_tables[2][(hi >> 8) & 0xFFU]
            ^ wing_crc32_tables[1][(hi >> 16) & 0xFFU]
            ^ wing_crc32_tables[0][hi >> 24];
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

            x0 = _mm_xor_si128(_mm_xor_si128(_mm_clmulepi64_si128(x0, k512, 0x00), _mm_clmulepi64_si128(x0, k512, 0x11)), y0);
            x1 = _mm_xor_si128(_mm_xor_si128(_mm_clmulepi64_si128(x1, k512, 0x00), _mm_clmulepi64_si128(x1, k512, 0x11)), y1);
            x2 = _mm_xor_si128(_mm_xor_si128(_mm_clmulepi64_si128(x2, k512, 0x00), _mm_clmulepi64_si128(x2, k512, 0x11)), y2);
            x3 = _mm_xor_si128(_mm_xor_si128(_mm_clmulepi64_si128(x3, k512, 0x00), _mm_clmulepi64_si128(x3, k512, 0x11)), y3);
            p += 64;
            len -= 64;
        }

        const __m128i k128 = _mm_set_epi64x((int64_t)WING_CRC32_RK96, (int64_t)WING_CRC32_RK160);
        x1 = _mm_xor_si128(_mm_xor_si128(_mm_clmulepi64_si128(x0, k128, 0x00), _mm_clmulepi64_si128(x0, k128, 0x11)), x1);
        x2 = _mm_xor_si128(_mm_xor_si128(_mm_clmulepi64_si128(x1, k128, 0x00), _mm_clmulepi64_si128(x1, k128, 0x11)), x2);
        x3 = _mm_xor_si128(_mm_xor_si128(_mm_clmulepi64_si128(x2, k128, 0x00), _mm_clmulepi64_si128(x2, k128, 0x11)), x3);

        while (len >= 16) {
            __m128i y = _mm_loadu_si128((const __m128i *)p);
            x3 = _mm_xor_si128(_mm_xor_si128(_mm_clmulepi64_si128(x3, k128, 0x00), _mm_clmulepi64_si128(x3, k128, 0x11)), y);
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
            x0 = _mm_xor_si128(_mm_xor_si128(_mm_clmulepi64_si128(x0, k128, 0x00), _mm_clmulepi64_si128(x0, k128, 0x11)), y);
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

    const __m256i k1024 = _mm256_set_epi64x(
        (int64_t)WING_CRC32_RK992, (int64_t)WING_CRC32_RK1056,
        (int64_t)WING_CRC32_RK992, (int64_t)WING_CRC32_RK1056
    );
    while (len >= 128) {
        __m256i y0 = _mm256_loadu_si256((const __m256i *)(p));
        __m256i y1 = _mm256_loadu_si256((const __m256i *)(p + 32));
        __m256i y2 = _mm256_loadu_si256((const __m256i *)(p + 64));
        __m256i y3 = _mm256_loadu_si256((const __m256i *)(p + 96));

        x0 = _mm256_xor_si256(_mm256_xor_si256(_mm256_clmulepi64_epi128(x0, k1024, 0x00), _mm256_clmulepi64_epi128(x0, k1024, 0x11)), y0);
        x1 = _mm256_xor_si256(_mm256_xor_si256(_mm256_clmulepi64_epi128(x1, k1024, 0x00), _mm256_clmulepi64_epi128(x1, k1024, 0x11)), y1);
        x2 = _mm256_xor_si256(_mm256_xor_si256(_mm256_clmulepi64_epi128(x2, k1024, 0x00), _mm256_clmulepi64_epi128(x2, k1024, 0x11)), y2);
        x3 = _mm256_xor_si256(_mm256_xor_si256(_mm256_clmulepi64_epi128(x3, k1024, 0x00), _mm256_clmulepi64_epi128(x3, k1024, 0x11)), y3);
        p += 128;
        len -= 128;
    }

    const __m256i k512 = _mm256_set_epi64x(
        (int64_t)WING_CRC32_RK480, (int64_t)WING_CRC32_RK544,
        (int64_t)WING_CRC32_RK480, (int64_t)WING_CRC32_RK544
    );
    x0 = _mm256_xor_si256(_mm256_xor_si256(_mm256_clmulepi64_epi128(x0, k512, 0x00), _mm256_clmulepi64_epi128(x0, k512, 0x11)), x2);
    x1 = _mm256_xor_si256(_mm256_xor_si256(_mm256_clmulepi64_epi128(x1, k512, 0x00), _mm256_clmulepi64_epi128(x1, k512, 0x11)), x3);

    const __m256i k256 = _mm256_set_epi64x(
        (int64_t)WING_CRC32_RK224, (int64_t)WING_CRC32_RK288,
        (int64_t)WING_CRC32_RK224, (int64_t)WING_CRC32_RK288
    );
    x0 = _mm256_xor_si256(_mm256_xor_si256(_mm256_clmulepi64_epi128(x0, k256, 0x00), _mm256_clmulepi64_epi128(x0, k256, 0x11)), x1);

    while (len >= 32) {
        __m256i y = _mm256_loadu_si256((const __m256i *)p);
        x0 = _mm256_xor_si256(_mm256_xor_si256(_mm256_clmulepi64_epi128(x0, k256, 0x00), _mm256_clmulepi64_epi128(x0, k256, 0x11)), y);
        p += 32;
        len -= 32;
    }

    __m128i lo = _mm256_castsi256_si128(x0);
    __m128i hi = _mm256_extracti128_si256(x0, 1);
    const __m128i k128 = _mm_set_epi64x((int64_t)WING_CRC32_RK96, (int64_t)WING_CRC32_RK160);
    __m128i s = _mm_xor_si128(_mm_xor_si128(_mm_clmulepi64_si128(lo, k128, 0x00), _mm_clmulepi64_si128(lo, k128, 0x11)), hi);

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
    const __m128i weights = _mm_set_epi8(
        1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16
    );

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

        uint64_t sum1 = (uint64_t)(uint32_t)_mm_cvtsi128_si32(vs1)
                      + (uint64_t)(uint32_t)_mm_cvtsi128_si32(_mm_srli_si128(vs1, 8));
        uint64_t sum_prefix = (uint64_t)(uint32_t)_mm_cvtsi128_si32(vs2_prefix)
                            + (uint64_t)(uint32_t)_mm_cvtsi128_si32(_mm_srli_si128(vs2_prefix, 8));
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
    const __m256i weights = _mm256_set_epi8(
         1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, 15, 16,
        17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32
    );

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
        uint64_t sum1 = (uint64_t)(uint32_t)_mm_extract_epi32(s1_128, 0)
                      + (uint64_t)(uint32_t)_mm_extract_epi32(s1_128, 2);

        __m128i p_128 = _mm_add_epi32(_mm256_castsi256_si128(vs2_prefix), _mm256_extracti128_si256(vs2_prefix, 1));
        uint64_t sum_prefix = (uint64_t)(uint32_t)_mm_extract_epi32(p_128, 0)
                            + (uint64_t)(uint32_t)_mm_extract_epi32(p_128, 2);

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
            for (int k = 0; k < 16; k++) { s1 += p[k]; s2 += s1; }
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

typedef struct {
    uint32_t *data;
    int64_t len;
} wing_u32_rw;

typedef struct {
    uint64_t *data;
    int64_t len;
} wing_u64_rw;

static uint16_t wing_fix_lit_pack[288];
static uint32_t wing_fix_len_pack[259];
static uint32_t wing_fix_dist_fast[513];
static uint8_t  wing_rev5_lut[32];
static int      wing_fix_enc_ready = 0;

static inline uint32_t wing_bitrev_u32(uint32_t v, int bits) {
    uint32_t r = 0;
    for (int i = 0; i < bits; i++) {
        r = (r << 1) | (v & 1U);
        v >>= 1;
    }
    return r;
}

static void wing_init_fix_enc_tables(void) {
#if defined(__GNUC__) || defined(__clang__)
    if (__atomic_load_n(&wing_fix_enc_ready, __ATOMIC_ACQUIRE)) return;
#else
    if (wing_fix_enc_ready) return;
#endif
    for (uint32_t s = 0; s <= 143; s++)
        wing_fix_lit_pack[s] = (uint16_t)((wing_bitrev_u32(0x30U + s, 8) << 4) | 8U);
    for (uint32_t s = 144; s <= 255; s++)
        wing_fix_lit_pack[s] = (uint16_t)((wing_bitrev_u32(0x190U + (s - 144U), 9) << 4) | 9U);
    for (uint32_t s = 256; s <= 279; s++)
        wing_fix_lit_pack[s] = (uint16_t)((wing_bitrev_u32(s - 256U, 7) << 4) | 7U);
    for (uint32_t s = 280; s <= 287; s++)
        wing_fix_lit_pack[s] = (uint16_t)((wing_bitrev_u32(0xC0U + (s - 280U), 8) << 4) | 8U);

    static const uint16_t lbase[29] = {
        3,4,5,6,7,8,9,10,11,13,15,17,19,23,27,31,35,43,51,59,67,83,99,115,131,163,195,227,258
    };
    static const uint8_t lextra[29] = {
        0,0,0,0,0,0,0,0,1,1,1,1,2,2,2,2,3,3,3,3,4,4,4,4,5,5,5,5,0
    };
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

    static const uint16_t dbase[30] = {
        1,2,3,4,5,7,9,13,17,25,33,49,65,97,129,193,257,385,513,769,
        1025,1537,2049,3073,4097,6145,8193,12289,16385,24577
    };
    static const uint8_t dextra[30] = {
        0,0,0,0,1,1,2,2,3,3,4,4,5,5,6,6,7,7,8,8,9,9,10,10,11,11,12,12,13,13
    };
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
#if defined(__GNUC__) || defined(__clang__)
    __atomic_store_n(&wing_fix_enc_ready, 1, __ATOMIC_RELEASE);
#else
    wing_fix_enc_ready = 1;
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

static inline void wing_bw_put(
    uint64_t *bits, int *bc, uint32_t val, int nb, uint8_t *dst, int64_t *out_idx
) {
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

static inline void wing_emit_dist_fast(
    uint32_t dist, uint64_t *bits, int *bc, uint8_t *dst, int64_t *out_idx
) {
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
    while (l < max_l && p[l] == c[l]) l++;
    return (int32_t)l;
}

#define WING_LZ_HASH_MUL 0x1E35A7BDU

WING_SIMD_TARGET_AVX2_BMI
static int64_t wing_deflate_l1_chunk_avx2(
    const uint8_t *src, int64_t chunk_start, int64_t chunk_end, int is_final,
    uint32_t *head, int64_t head_len, uint64_t *bit_state, uint8_t *dst, int64_t dst_cap
) {
    int64_t chunk_len = chunk_end - chunk_start;
    if (chunk_len < 0 || chunk_len > 65535) return -1;
    uint64_t bits = bit_state[0];
    int bc = (int)bit_state[1];
    int64_t out_idx = 0;
    int64_t stored_bytes = ((bc + 3 + 7) >> 3) + 4 + chunk_len;
    if (dst_cap < stored_bytes + 8) return -1;

    if (chunk_len == 0) {
        wing_bw_put(&bits, &bc, (uint32_t)(is_final ? 1U : 0U), 3, dst, &out_idx);
        while (bc >= 8) { dst[out_idx++] = (uint8_t)bits; bits >>= 8; bc -= 8; }
        if (bc > 0) { dst[out_idx++] = (uint8_t)bits; bits = 0; bc = 0; }
        dst[out_idx++] = 0; dst[out_idx++] = 0; dst[out_idx++] = 0xFF; dst[out_idx++] = 0xFF;
        bit_state[0] = bits; bit_state[1] = (uint64_t)bc;
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
        if (matches == 0 && pos >= probe_mark) { bail_stored = 1; break; }
        miss++;
        int64_t step = (int64_t)(miss >> 5);
        int64_t stop = pos + step;
        if (stop > limit + 1) stop = limit + 1;
        while (pos < stop) {
            uint16_t lit_p = wing_fix_lit_pack[src[pos++]];
            wing_bw_put(&bits, &bc, lit_p >> 4, (int)(lit_p & 15U), dst, &out_idx);
        }
    }

    if (!bail_stored) {
        while (pos < chunk_end) {
            uint16_t lit_p = wing_fix_lit_pack[src[pos++]];
            wing_bw_put(&bits, &bc, lit_p >> 4, (int)(lit_p & 15U), dst, &out_idx);
        }
        wing_bw_put(&bits, &bc, 0U, 7, dst, &out_idx);
        while (bc >= 8) { dst[out_idx++] = (uint8_t)bits; bits >>= 8; bc -= 8; }
        int64_t emitted_bytes = out_idx + ((bc - saved_bc + 7) >> 3);
        if (emitted_bytes >= stored_bytes) bail_stored = 1;
    }

    if (bail_stored) {
        out_idx = 0;
        bits = saved_bits;
        bc = saved_bc;
        wing_bw_put(&bits, &bc, (uint32_t)(is_final ? 1U : 0U), 3, dst, &out_idx);
        while (bc >= 8) { dst[out_idx++] = (uint8_t)bits; bits >>= 8; bc -= 8; }
        if (bc > 0) { dst[out_idx++] = (uint8_t)bits; bits = 0; bc = 0; }
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

int64_t wing_simd_deflate_l1_chunk(
    wing_bytes_ro src, int64_t chunk_start, int64_t chunk_end, int32_t is_final,
    wing_u32_rw head, wing_u64_rw bit_state, wing_bytes_rw dst
) {
    if (!head.data || head.len < 64 || (head.len & (head.len - 1)) != 0) return -1;
    if (!bit_state.data || bit_state.len < 2) return -1;
    if (!dst.data || dst.len <= 0) return -1;
    if (chunk_start < 0 || chunk_end < chunk_start || chunk_end > src.len) return -1;
    if (chunk_end > chunk_start && !src.data) return -1;
#if defined(__x86_64__) || defined(_M_X64)
    if (wing_compress_cpu_caps() & WING_CAP_AVX2) {
        wing_init_fix_enc_tables();
        return wing_deflate_l1_chunk_avx2(
            src.data, chunk_start, chunk_end, is_final,
            head.data, head.len, bit_state.data, dst.data, dst.len
        );
    }
#endif
    return -2;
}
