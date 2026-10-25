// shim/simd.c - SIMD acceleration primitives for goose-wing
// Provides vectorized WebSocket unmasking, ASCII/UTF-8 fast scan, and CRLF delimiter detection.

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

typedef struct { uint8_t *data; int64_t len; } wing_bytes_rw;
typedef struct { const uint8_t *data; int64_t len; } wing_bytes_ro;

// Vectorized WebSocket payload XOR masking / unmasking (RFC 6455 §5.3)
// Replicates 4-byte mask across 128-bit/256-bit SIMD registers.
void wing_simd_mask_websocket(wing_bytes_rw slice, const uint8_t mask[4]) {
    uint8_t* data = slice.data;
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
        __m128i v0 = _mm_loadu_si128((const __m128i*)(data + i));
        __m128i v1 = _mm_loadu_si128((const __m128i*)(data + i + 16));
        __m128i v2 = _mm_loadu_si128((const __m128i*)(data + i + 32));
        __m128i v3 = _mm_loadu_si128((const __m128i*)(data + i + 48));

        _mm_storeu_si128((__m128i*)(data + i),      _mm_xor_si128(v0, mask128));
        _mm_storeu_si128((__m128i*)(data + i + 16), _mm_xor_si128(v1, mask128));
        _mm_storeu_si128((__m128i*)(data + i + 32), _mm_xor_si128(v2, mask128));
        _mm_storeu_si128((__m128i*)(data + i + 48), _mm_xor_si128(v3, mask128));

        i += 64;
    }

    while (i + 16 <= len) {
        __m128i v = _mm_loadu_si128((const __m128i*)(data + i));
        _mm_storeu_si128((__m128i*)(data + i), _mm_xor_si128(v, mask128));
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
    const uint8_t* data = slice.data;
    size_t len = (size_t)slice.len;
    if (!data || len == 0) return 1;

    size_t i = 0;

#if (defined(__x86_64__) || defined(_M_AMD64)) && !defined(__ARM_NEON)
    while (i + 16 <= len) {
        __m128i v = _mm_loadu_si128((const __m128i*)(data + i));
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
    const uint8_t* data = slice.data;
    size_t len = (size_t)slice.len;
    if (!data || len < 2) return -1;

    size_t i = 0;

#if (defined(__x86_64__) || defined(_M_AMD64)) && !defined(__ARM_NEON)
    __m128i cr = _mm_set1_epi8('\r');
    while (i + 16 <= len) {
        __m128i v = _mm_loadu_si128((const __m128i*)(data + i));
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
