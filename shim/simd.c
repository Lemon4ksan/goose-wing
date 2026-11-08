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
