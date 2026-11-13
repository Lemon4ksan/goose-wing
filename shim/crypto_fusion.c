// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Fused AES-GCM AEAD Hardware Acceleration Shim (NIST SP 800-38D).
// Interleaves 4-block parallel AES-CTR encryption/decryption (_mm_aesenc_si128)
// with PCLMULQDQ Galois field multiplication (_mm_clmulepi64_si128) to hide
// instruction latency and maximize throughput on x86_64 CPUs.
// Includes runtime CPUID feature detection (__builtin_cpu_supports) and a
// constant-time scalar fallback when AES-NI / PCLMULQDQ are unavailable.

#include <stdint.h>
#include <stddef.h>
#include <string.h>

typedef struct {
    uint8_t *ptr;
    int64_t len;
} wing_slice;

// Zeroize sensitive stack buffers and unauthenticated plaintext without Dead Store Elimination (DSE).
static inline void wing_fusion_zeroize(volatile void *ptr, size_t len) {
    size_t i = 0;
    if ((((uintptr_t)ptr) & 7u) == 0u) {
        volatile uint64_t *qp = (volatile uint64_t *)ptr;
        size_t qwords = len >> 3;
        for (size_t q = 0; q < qwords; q++) {
            qp[q] = 0u;
        }
        i = qwords << 3;
    }
    volatile uint8_t *vp = (volatile uint8_t *)ptr;
    for (; i < len; i++) {
        vp[i] = 0u;
    }
#if defined(__GNUC__) || defined(__clang__)
    __asm__ __volatile__("" : : "r"(ptr) : "memory");
#endif
}

#if defined(__x86_64__) || defined(_M_X64)
#include <immintrin.h>
#include <wmmintrin.h>

#if defined(__GNUC__) || defined(__clang__)
#define WING_TARGET_AES_PCLMUL __attribute__((target("sse2,ssse3,sse4.1,aes,pclmul")))
#else
#define WING_TARGET_AES_PCLMUL
#endif

static inline int wing_cpu_has_aes_pclmul(void) {
#if defined(__GNUC__) || defined(__clang__)
    return __builtin_cpu_supports("aes") && __builtin_cpu_supports("pclmul");
#else
    return 1;
#endif
}

// Byte-swap 128-bit lane between big-endian (GHASH/GCM wire order) and little-endian (XMM register order).
WING_TARGET_AES_PCLMUL
static inline __m128i wing_bswap128(__m128i v) {
    const __m128i mask = _mm_set_epi8(0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15);
    return _mm_shuffle_epi8(v, mask);
}

WING_TARGET_AES_PCLMUL
static inline __m128i wing_gf128_reduce256_pclmul(__m128i tmp3, __m128i tmp6) {
    // 1. Left-shift 256-bit product by 1 bit (due to reflected bit-order of GHASH)
    __m128i tmp7 = _mm_srli_epi32(tmp3, 31);
    __m128i tmp8 = _mm_srli_epi32(tmp6, 31);
    tmp3 = _mm_slli_epi32(tmp3, 1);
    tmp6 = _mm_slli_epi32(tmp6, 1);
    __m128i tmp9 = _mm_srli_si128(tmp7, 12);
    tmp8 = _mm_slli_si128(tmp8, 4);
    tmp7 = _mm_slli_si128(tmp7, 4);
    tmp3 = _mm_or_si128(tmp3, tmp7);
    tmp6 = _mm_or_si128(tmp6, tmp8);
    tmp6 = _mm_or_si128(tmp6, tmp9);

    // 2. Modular reduction over GF(2^128) polynomial x^128 + x^7 + x^2 + x + 1
    tmp7 = _mm_slli_epi32(tmp3, 31);
    tmp8 = _mm_slli_epi32(tmp3, 30);
    tmp9 = _mm_slli_epi32(tmp3, 25);
    tmp7 = _mm_xor_si128(tmp7, tmp8);
    tmp7 = _mm_xor_si128(tmp7, tmp9);
    tmp8 = _mm_srli_si128(tmp7, 4);
    tmp7 = _mm_slli_si128(tmp7, 12);
    tmp3 = _mm_xor_si128(tmp3, tmp7);

    __m128i tmp2 = _mm_srli_epi32(tmp3, 1);
    __m128i tmp4 = _mm_srli_epi32(tmp3, 2);
    __m128i tmp5 = _mm_srli_epi32(tmp3, 7);
    tmp2 = _mm_xor_si128(tmp2, tmp4);
    tmp2 = _mm_xor_si128(tmp2, tmp5);
    tmp2 = _mm_xor_si128(tmp2, tmp8);
    tmp3 = _mm_xor_si128(tmp3, tmp2);
    return _mm_xor_si128(tmp6, tmp3);
}

// GF(2^128) carry-less multiplication and reduction modulo x^128 + x^7 + x^2 + x + 1
// in reflected GHASH bit representation using _mm_clmulepi64_si128.
WING_TARGET_AES_PCLMUL
static inline __m128i wing_gf128_mul_pclmul(__m128i a, __m128i h) {
    __m128i tmp3 = _mm_clmulepi64_si128(a, h, 0x00);
    __m128i tmp4 = _mm_clmulepi64_si128(a, h, 0x10);
    __m128i tmp5 = _mm_clmulepi64_si128(a, h, 0x01);
    __m128i tmp6 = _mm_clmulepi64_si128(a, h, 0x11);

    tmp4 = _mm_xor_si128(tmp4, tmp5);
    tmp5 = _mm_slli_si128(tmp4, 8);
    tmp4 = _mm_srli_si128(tmp4, 8);
    tmp3 = _mm_xor_si128(tmp3, tmp5);
    tmp6 = _mm_xor_si128(tmp6, tmp4);

    return wing_gf128_reduce256_pclmul(tmp3, tmp6);
}

// Aggregated 4-block Karatsuba GHASH with single modular reduction:
// Computes ((acc ^ bswap(c0)) * H^4) ^ (bswap(c1) * H^3) ^ (bswap(c2) * H^2) ^ (bswap(c3) * H)
WING_TARGET_AES_PCLMUL
static inline __m128i wing_gf128_mul_acc4_karatsuba_pclmul(__m128i acc, __m128i c0, __m128i c1, __m128i c2,
                                                           __m128i c3, __m128i h1, __m128i h2, __m128i h3,
                                                           __m128i h4) {
    __m128i d0 = _mm_xor_si128(acc, wing_bswap128(c0));
    __m128i d1 = wing_bswap128(c1);
    __m128i d2 = wing_bswap128(c2);
    __m128i d3 = wing_bswap128(c3);

    __m128i lo = _mm_clmulepi64_si128(d0, h4, 0x00);
    __m128i hi = _mm_clmulepi64_si128(d0, h4, 0x11);
    __m128i ab = _mm_clmulepi64_si128(_mm_xor_si128(d0, _mm_shuffle_epi32(d0, 0x4E)),
                                      _mm_xor_si128(h4, _mm_shuffle_epi32(h4, 0x4E)), 0x00);

    lo = _mm_xor_si128(lo, _mm_clmulepi64_si128(d1, h3, 0x00));
    hi = _mm_xor_si128(hi, _mm_clmulepi64_si128(d1, h3, 0x11));
    ab = _mm_xor_si128(ab, _mm_clmulepi64_si128(_mm_xor_si128(d1, _mm_shuffle_epi32(d1, 0x4E)),
                                                _mm_xor_si128(h3, _mm_shuffle_epi32(h3, 0x4E)), 0x00));

    lo = _mm_xor_si128(lo, _mm_clmulepi64_si128(d2, h2, 0x00));
    hi = _mm_xor_si128(hi, _mm_clmulepi64_si128(d2, h2, 0x11));
    ab = _mm_xor_si128(ab, _mm_clmulepi64_si128(_mm_xor_si128(d2, _mm_shuffle_epi32(d2, 0x4E)),
                                                _mm_xor_si128(h2, _mm_shuffle_epi32(h2, 0x4E)), 0x00));

    lo = _mm_xor_si128(lo, _mm_clmulepi64_si128(d3, h1, 0x00));
    hi = _mm_xor_si128(hi, _mm_clmulepi64_si128(d3, h1, 0x11));
    ab = _mm_xor_si128(ab, _mm_clmulepi64_si128(_mm_xor_si128(d3, _mm_shuffle_epi32(d3, 0x4E)),
                                                _mm_xor_si128(h1, _mm_shuffle_epi32(h1, 0x4E)), 0x00));

    __m128i mid = _mm_xor_si128(ab, _mm_xor_si128(lo, hi));
    __m128i tmp3 = _mm_xor_si128(lo, _mm_slli_si128(mid, 8));
    __m128i tmp6 = _mm_xor_si128(hi, _mm_srli_si128(mid, 8));
    return wing_gf128_reduce256_pclmul(tmp3, tmp6);
}

// AES-128 key schedule helper using _mm_aeskeygenassist_si128.
WING_TARGET_AES_PCLMUL
static inline __m128i wing_aes128_key_expand_step(__m128i key, __m128i gen) {
    gen = _mm_shuffle_epi32(gen, 0xFF);
    key = _mm_xor_si128(key, _mm_slli_si128(key, 4));
    key = _mm_xor_si128(key, _mm_slli_si128(key, 4));
    key = _mm_xor_si128(key, _mm_slli_si128(key, 4));
    return _mm_xor_si128(key, gen);
}

WING_TARGET_AES_PCLMUL
static inline void wing_aes128_expand_key(__m128i user_key, __m128i rk[15]) {
    rk[0] = user_key;
    rk[1] = wing_aes128_key_expand_step(rk[0], _mm_aeskeygenassist_si128(rk[0], 0x01));
    rk[2] = wing_aes128_key_expand_step(rk[1], _mm_aeskeygenassist_si128(rk[1], 0x02));
    rk[3] = wing_aes128_key_expand_step(rk[2], _mm_aeskeygenassist_si128(rk[2], 0x04));
    rk[4] = wing_aes128_key_expand_step(rk[3], _mm_aeskeygenassist_si128(rk[3], 0x08));
    rk[5] = wing_aes128_key_expand_step(rk[4], _mm_aeskeygenassist_si128(rk[4], 0x10));
    rk[6] = wing_aes128_key_expand_step(rk[5], _mm_aeskeygenassist_si128(rk[5], 0x20));
    rk[7] = wing_aes128_key_expand_step(rk[6], _mm_aeskeygenassist_si128(rk[6], 0x40));
    rk[8] = wing_aes128_key_expand_step(rk[7], _mm_aeskeygenassist_si128(rk[7], 0x80));
    rk[9] = wing_aes128_key_expand_step(rk[8], _mm_aeskeygenassist_si128(rk[8], 0x1B));
    rk[10] = wing_aes128_key_expand_step(rk[9], _mm_aeskeygenassist_si128(rk[9], 0x36));
}

WING_TARGET_AES_PCLMUL
static inline void wing_aes256_expand_step1(__m128i *t1, __m128i gen) {
    __m128i g = _mm_shuffle_epi32(gen, 0xFF);
    __m128i a = *t1;
    a = _mm_xor_si128(a, _mm_slli_si128(a, 4));
    a = _mm_xor_si128(a, _mm_slli_si128(a, 4));
    a = _mm_xor_si128(a, _mm_slli_si128(a, 4));
    *t1 = _mm_xor_si128(a, g);
}

WING_TARGET_AES_PCLMUL
static inline void wing_aes256_expand_step2(__m128i t1, __m128i *t3) {
    __m128i g = _mm_shuffle_epi32(_mm_aeskeygenassist_si128(t1, 0x00), 0xAA);
    __m128i a = *t3;
    a = _mm_xor_si128(a, _mm_slli_si128(a, 4));
    a = _mm_xor_si128(a, _mm_slli_si128(a, 4));
    a = _mm_xor_si128(a, _mm_slli_si128(a, 4));
    *t3 = _mm_xor_si128(a, g);
}

WING_TARGET_AES_PCLMUL
static inline void wing_aes256_expand_key(const uint8_t *key_ptr, __m128i rk[15]) {
    __m128i t1 = _mm_loadu_si128((const __m128i *)key_ptr);
    __m128i t3 = _mm_loadu_si128((const __m128i *)(key_ptr + 16));
    rk[0] = t1;
    rk[1] = t3;
    wing_aes256_expand_step1(&t1, _mm_aeskeygenassist_si128(t3, 0x01));
    rk[2] = t1;
    wing_aes256_expand_step2(t1, &t3);
    rk[3] = t3;
    wing_aes256_expand_step1(&t1, _mm_aeskeygenassist_si128(t3, 0x02));
    rk[4] = t1;
    wing_aes256_expand_step2(t1, &t3);
    rk[5] = t3;
    wing_aes256_expand_step1(&t1, _mm_aeskeygenassist_si128(t3, 0x04));
    rk[6] = t1;
    wing_aes256_expand_step2(t1, &t3);
    rk[7] = t3;
    wing_aes256_expand_step1(&t1, _mm_aeskeygenassist_si128(t3, 0x08));
    rk[8] = t1;
    wing_aes256_expand_step2(t1, &t3);
    rk[9] = t3;
    wing_aes256_expand_step1(&t1, _mm_aeskeygenassist_si128(t3, 0x10));
    rk[10] = t1;
    wing_aes256_expand_step2(t1, &t3);
    rk[11] = t3;
    wing_aes256_expand_step1(&t1, _mm_aeskeygenassist_si128(t3, 0x20));
    rk[12] = t1;
    wing_aes256_expand_step2(t1, &t3);
    rk[13] = t3;
    wing_aes256_expand_step1(&t1, _mm_aeskeygenassist_si128(t3, 0x40));
    rk[14] = t1;
    wing_fusion_zeroize(&t1, sizeof(t1));
    wing_fusion_zeroize(&t3, sizeof(t3));
}

WING_TARGET_AES_PCLMUL
static inline int wing_aes_expand_key_aesni(const uint8_t *key_ptr, int64_t key_len, __m128i rk[15]) {
    if (key_len == 32) {
        wing_aes256_expand_key(key_ptr, rk);
        return 14;
    }
    wing_aes128_expand_key(_mm_loadu_si128((const __m128i *)key_ptr), rk);
    return 10;
}

WING_TARGET_AES_PCLMUL
static inline __m128i wing_aes_enc_block_aesni(__m128i b, const __m128i rk[15], int nr) {
    b = _mm_xor_si128(b, rk[0]);
    for (int r = 1; r < nr; r++) {
        b = _mm_aesenc_si128(b, rk[r]);
    }
    return _mm_aesenclast_si128(b, rk[nr]);
}

WING_TARGET_AES_PCLMUL
static inline __m128i wing_make_ctr_block(const uint8_t iv[12], uint32_t ctr) {
    uint8_t blk[16];
    memcpy(blk, iv, 12);
    blk[12] = (uint8_t)(ctr >> 24);
    blk[13] = (uint8_t)(ctr >> 16);
    blk[14] = (uint8_t)(ctr >> 8);
    blk[15] = (uint8_t)(ctr);
    return _mm_loadu_si128((const __m128i *)blk);
}

WING_TARGET_AES_PCLMUL
static inline __m128i wing_ghash_aad_aesni(__m128i h_swp, const uint8_t *aad_ptr, int64_t aad_len) {
    __m128i ghash_acc = _mm_setzero_si128();
    int64_t off = 0;
    while (off + 16 <= aad_len) {
        __m128i a = _mm_loadu_si128((const __m128i *)(aad_ptr + off));
        ghash_acc = wing_gf128_mul_pclmul(_mm_xor_si128(ghash_acc, wing_bswap128(a)), h_swp);
        off += 16;
    }
    if (off < aad_len) {
        uint8_t a_pad[16] = {0};
        memcpy(a_pad, aad_ptr + off, (size_t)(aad_len - off));
        __m128i a = _mm_loadu_si128((const __m128i *)a_pad);
        ghash_acc = wing_gf128_mul_pclmul(_mm_xor_si128(ghash_acc, wing_bswap128(a)), h_swp);
    }
    return ghash_acc;
}

WING_TARGET_AES_PCLMUL
static inline __m128i wing_ghash_len_aesni(__m128i ghash_acc, __m128i h_swp, int64_t aad_len, int64_t ct_len) {
    uint8_t len_blk[16] = {0};
    uint64_t a_bits = ((uint64_t)aad_len) * 8u;
    uint64_t c_bits = ((uint64_t)ct_len) * 8u;
    for (int i = 0; i < 8; i++) {
        len_blk[i] = (uint8_t)(a_bits >> (56 - 8 * i));
        len_blk[8 + i] = (uint8_t)(c_bits >> (56 - 8 * i));
    }
    __m128i len_vec = _mm_loadu_si128((const __m128i *)len_blk);
    return wing_gf128_mul_pclmul(_mm_xor_si128(ghash_acc, wing_bswap128(len_vec)), h_swp);
}

WING_TARGET_AES_PCLMUL
static inline __m128i wing_aes_enc_block_bytes(__m128i blk, const uint8_t *rk_bytes, int nr) {
    __m128i s = _mm_xor_si128(blk, _mm_loadu_si128((const __m128i *)rk_bytes));
    for (int r = 1; r < nr; r++) {
        s = _mm_aesenc_si128(s, _mm_loadu_si128((const __m128i *)(rk_bytes + (size_t)r * 16u)));
    }
    return _mm_aesenclast_si128(s, _mm_loadu_si128((const __m128i *)(rk_bytes + (size_t)nr * 16u)));
}

// Fused 4-block AES-GCM encryption + aggregated Karatsuba GHASH using pre-expanded round keys.
WING_TARGET_AES_PCLMUL
static int64_t wing_aes_gcm_seal_aesni_rk(const uint8_t *rk_bytes, int nr, __m128i h1, __m128i h2, __m128i h3,
                                          __m128i h4, const uint8_t *iv_ptr, const uint8_t *src_ptr,
                                          int64_t src_len, const uint8_t *aad_ptr, int64_t aad_len,
                                          uint8_t *dst_ptr, uint8_t *tag_ptr) {
    const __m128i bswap_ctr_mask = _mm_set_epi8(12, 13, 14, 15, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0);
    const __m128i ctr_one_le = _mm_set_epi32(1, 0, 0, 0);
    const __m128i rk0 = _mm_loadu_si128((const __m128i *)rk_bytes);
    const __m128i rk_last = _mm_loadu_si128((const __m128i *)(rk_bytes + (size_t)nr * 16u));
    __m128i j0_vec = wing_make_ctr_block(iv_ptr, 1u);
    __m128i j0_enc = wing_aes_enc_block_bytes(j0_vec, rk_bytes, nr);
    __m128i ctr_le = _mm_add_epi32(_mm_shuffle_epi8(j0_vec, bswap_ctr_mask), ctr_one_le);
    __m128i ghash_acc = wing_ghash_aad_aesni(h1, aad_ptr, aad_len);

    int64_t offset = 0;
    if (offset + 64 <= src_len) {
        __m128i p0 = _mm_loadu_si128((const __m128i *)(src_ptr + offset));
        __m128i p1 = _mm_loadu_si128((const __m128i *)(src_ptr + offset + 16));
        __m128i p2 = _mm_loadu_si128((const __m128i *)(src_ptr + offset + 32));
        __m128i p3 = _mm_loadu_si128((const __m128i *)(src_ptr + offset + 48));

        __m128i b0 = _mm_xor_si128(_mm_shuffle_epi8(ctr_le, bswap_ctr_mask), rk0);
        ctr_le = _mm_add_epi32(ctr_le, ctr_one_le);
        __m128i b1 = _mm_xor_si128(_mm_shuffle_epi8(ctr_le, bswap_ctr_mask), rk0);
        ctr_le = _mm_add_epi32(ctr_le, ctr_one_le);
        __m128i b2 = _mm_xor_si128(_mm_shuffle_epi8(ctr_le, bswap_ctr_mask), rk0);
        ctr_le = _mm_add_epi32(ctr_le, ctr_one_le);
        __m128i b3 = _mm_xor_si128(_mm_shuffle_epi8(ctr_le, bswap_ctr_mask), rk0);
        ctr_le = _mm_add_epi32(ctr_le, ctr_one_le);

        for (int r = 1; r < nr; r++) {
            __m128i rkr = _mm_loadu_si128((const __m128i *)(rk_bytes + (size_t)r * 16u));
            b0 = _mm_aesenc_si128(b0, rkr);
            b1 = _mm_aesenc_si128(b1, rkr);
            b2 = _mm_aesenc_si128(b2, rkr);
            b3 = _mm_aesenc_si128(b3, rkr);
        }
        b0 = _mm_aesenclast_si128(b0, rk_last);
        b1 = _mm_aesenclast_si128(b1, rk_last);
        b2 = _mm_aesenclast_si128(b2, rk_last);
        b3 = _mm_aesenclast_si128(b3, rk_last);

        __m128i prev0 = _mm_xor_si128(p0, b0);
        __m128i prev1 = _mm_xor_si128(p1, b1);
        __m128i prev2 = _mm_xor_si128(p2, b2);
        __m128i prev3 = _mm_xor_si128(p3, b3);

        _mm_storeu_si128((__m128i *)(dst_ptr + offset), prev0);
        _mm_storeu_si128((__m128i *)(dst_ptr + offset + 16), prev1);
        _mm_storeu_si128((__m128i *)(dst_ptr + offset + 32), prev2);
        _mm_storeu_si128((__m128i *)(dst_ptr + offset + 48), prev3);
        offset += 64;

        while (offset + 64 <= src_len) {
            p0 = _mm_loadu_si128((const __m128i *)(src_ptr + offset));
            p1 = _mm_loadu_si128((const __m128i *)(src_ptr + offset + 16));
            p2 = _mm_loadu_si128((const __m128i *)(src_ptr + offset + 32));
            p3 = _mm_loadu_si128((const __m128i *)(src_ptr + offset + 48));

            b0 = _mm_xor_si128(_mm_shuffle_epi8(ctr_le, bswap_ctr_mask), rk0);
            ctr_le = _mm_add_epi32(ctr_le, ctr_one_le);
            b1 = _mm_xor_si128(_mm_shuffle_epi8(ctr_le, bswap_ctr_mask), rk0);
            ctr_le = _mm_add_epi32(ctr_le, ctr_one_le);
            b2 = _mm_xor_si128(_mm_shuffle_epi8(ctr_le, bswap_ctr_mask), rk0);
            ctr_le = _mm_add_epi32(ctr_le, ctr_one_le);
            b3 = _mm_xor_si128(_mm_shuffle_epi8(ctr_le, bswap_ctr_mask), rk0);
            ctr_le = _mm_add_epi32(ctr_le, ctr_one_le);

            __m128i d0 = _mm_xor_si128(ghash_acc, wing_bswap128(prev0));
            __m128i d1 = wing_bswap128(prev1);
            __m128i d2 = wing_bswap128(prev2);
            __m128i d3 = wing_bswap128(prev3);

            for (int r = 1; r <= 3; r++) {
                __m128i rkr = _mm_loadu_si128((const __m128i *)(rk_bytes + (size_t)r * 16u));
                b0 = _mm_aesenc_si128(b0, rkr);
                b1 = _mm_aesenc_si128(b1, rkr);
                b2 = _mm_aesenc_si128(b2, rkr);
                b3 = _mm_aesenc_si128(b3, rkr);
            }
            __m128i lo = _mm_clmulepi64_si128(d0, h4, 0x00);
            __m128i hi = _mm_clmulepi64_si128(d0, h4, 0x11);
            __m128i ab = _mm_clmulepi64_si128(_mm_xor_si128(d0, _mm_shuffle_epi32(d0, 0x4E)),
                                              _mm_xor_si128(h4, _mm_shuffle_epi32(h4, 0x4E)), 0x00);

            for (int r = 4; r <= 6; r++) {
                __m128i rkr = _mm_loadu_si128((const __m128i *)(rk_bytes + (size_t)r * 16u));
                b0 = _mm_aesenc_si128(b0, rkr);
                b1 = _mm_aesenc_si128(b1, rkr);
                b2 = _mm_aesenc_si128(b2, rkr);
                b3 = _mm_aesenc_si128(b3, rkr);
            }
            lo = _mm_xor_si128(lo, _mm_clmulepi64_si128(d1, h3, 0x00));
            hi = _mm_xor_si128(hi, _mm_clmulepi64_si128(d1, h3, 0x11));
            ab = _mm_xor_si128(ab, _mm_clmulepi64_si128(_mm_xor_si128(d1, _mm_shuffle_epi32(d1, 0x4E)),
                                                        _mm_xor_si128(h3, _mm_shuffle_epi32(h3, 0x4E)), 0x00));

            for (int r = 7; r <= 9; r++) {
                __m128i rkr = _mm_loadu_si128((const __m128i *)(rk_bytes + (size_t)r * 16u));
                b0 = _mm_aesenc_si128(b0, rkr);
                b1 = _mm_aesenc_si128(b1, rkr);
                b2 = _mm_aesenc_si128(b2, rkr);
                b3 = _mm_aesenc_si128(b3, rkr);
            }
            lo = _mm_xor_si128(lo, _mm_clmulepi64_si128(d2, h2, 0x00));
            hi = _mm_xor_si128(hi, _mm_clmulepi64_si128(d2, h2, 0x11));
            ab = _mm_xor_si128(ab, _mm_clmulepi64_si128(_mm_xor_si128(d2, _mm_shuffle_epi32(d2, 0x4E)),
                                                        _mm_xor_si128(h2, _mm_shuffle_epi32(h2, 0x4E)), 0x00));

            for (int r = 10; r < nr; r++) {
                __m128i rkr = _mm_loadu_si128((const __m128i *)(rk_bytes + (size_t)r * 16u));
                b0 = _mm_aesenc_si128(b0, rkr);
                b1 = _mm_aesenc_si128(b1, rkr);
                b2 = _mm_aesenc_si128(b2, rkr);
                b3 = _mm_aesenc_si128(b3, rkr);
            }
            lo = _mm_xor_si128(lo, _mm_clmulepi64_si128(d3, h1, 0x00));
            hi = _mm_xor_si128(hi, _mm_clmulepi64_si128(d3, h1, 0x11));
            ab = _mm_xor_si128(ab, _mm_clmulepi64_si128(_mm_xor_si128(d3, _mm_shuffle_epi32(d3, 0x4E)),
                                                        _mm_xor_si128(h1, _mm_shuffle_epi32(h1, 0x4E)), 0x00));

            b0 = _mm_aesenclast_si128(b0, rk_last);
            b1 = _mm_aesenclast_si128(b1, rk_last);
            b2 = _mm_aesenclast_si128(b2, rk_last);
            b3 = _mm_aesenclast_si128(b3, rk_last);

            __m128i mid = _mm_xor_si128(ab, _mm_xor_si128(lo, hi));
            ghash_acc = wing_gf128_reduce256_pclmul(_mm_xor_si128(lo, _mm_slli_si128(mid, 8)),
                                                    _mm_xor_si128(hi, _mm_srli_si128(mid, 8)));

            prev0 = _mm_xor_si128(p0, b0);
            prev1 = _mm_xor_si128(p1, b1);
            prev2 = _mm_xor_si128(p2, b2);
            prev3 = _mm_xor_si128(p3, b3);

            _mm_storeu_si128((__m128i *)(dst_ptr + offset), prev0);
            _mm_storeu_si128((__m128i *)(dst_ptr + offset + 16), prev1);
            _mm_storeu_si128((__m128i *)(dst_ptr + offset + 32), prev2);
            _mm_storeu_si128((__m128i *)(dst_ptr + offset + 48), prev3);
            offset += 64;
        }
        ghash_acc = wing_gf128_mul_acc4_karatsuba_pclmul(ghash_acc, prev0, prev1, prev2, prev3, h1, h2, h3, h4);
    }

    while (offset + 16 <= src_len) {
        __m128i p0 = _mm_loadu_si128((const __m128i *)(src_ptr + offset));
        __m128i ks = wing_aes_enc_block_bytes(_mm_shuffle_epi8(ctr_le, bswap_ctr_mask), rk_bytes, nr);
        ctr_le = _mm_add_epi32(ctr_le, ctr_one_le);
        __m128i c0 = _mm_xor_si128(p0, ks);
        _mm_storeu_si128((__m128i *)(dst_ptr + offset), c0);
        ghash_acc = wing_gf128_mul_pclmul(_mm_xor_si128(ghash_acc, wing_bswap128(c0)), h1);
        offset += 16;
    }

    if (offset < src_len) {
        int64_t rem = src_len - offset;
        uint8_t c_pad[16] = {0};
        uint8_t ks_bytes[16];
        __m128i ks = wing_aes_enc_block_bytes(_mm_shuffle_epi8(ctr_le, bswap_ctr_mask), rk_bytes, nr);
        _mm_storeu_si128((__m128i *)ks_bytes, ks);
        for (int64_t i = 0; i < rem; i++) {
            uint8_t c_b = src_ptr[offset + i] ^ ks_bytes[i];
            dst_ptr[offset + i] = c_b;
            c_pad[i] = c_b;
        }
        wing_fusion_zeroize(ks_bytes, sizeof(ks_bytes));
        __m128i c_vec = _mm_loadu_si128((const __m128i *)c_pad);
        ghash_acc = wing_gf128_mul_pclmul(_mm_xor_si128(ghash_acc, wing_bswap128(c_vec)), h1);
    }

    ghash_acc = wing_ghash_len_aesni(ghash_acc, h1, aad_len, src_len);
    __m128i tag_vec = _mm_xor_si128(wing_bswap128(ghash_acc), j0_enc);
    _mm_storeu_si128((__m128i *)tag_ptr, tag_vec);
    return src_len;
}

WING_TARGET_AES_PCLMUL
static int64_t wing_aes_gcm_seal_aesni(const uint8_t *key_ptr, int64_t key_len, const uint8_t *iv_ptr,
                                       const uint8_t *src_ptr, int64_t src_len, const uint8_t *aad_ptr,
                                       int64_t aad_len, uint8_t *dst_ptr, uint8_t *tag_ptr) {
    __m128i rk[15];
    int nr = wing_aes_expand_key_aesni(key_ptr, key_len, rk);

    __m128i h1 = wing_bswap128(wing_aes_enc_block_aesni(_mm_setzero_si128(), rk, nr));
    __m128i h2 = (src_len >= 64) ? wing_gf128_mul_pclmul(h1, h1) : h1;
    __m128i h3 = (src_len >= 64) ? wing_gf128_mul_pclmul(h2, h1) : h1;
    __m128i h4 = (src_len >= 64) ? wing_gf128_mul_pclmul(h3, h1) : h1;

    int64_t ret = wing_aes_gcm_seal_aesni_rk((const uint8_t *)rk, nr, h1, h2, h3, h4, iv_ptr, src_ptr, src_len,
                                             aad_ptr, aad_len, dst_ptr, tag_ptr);
    wing_fusion_zeroize(rk, sizeof(rk));
    return ret;
}

// Fused 4-block AES-GCM decryption + aggregated Karatsuba GHASH using pre-expanded round keys.
WING_TARGET_AES_PCLMUL
static int64_t wing_aes_gcm_open_aesni_rk(const uint8_t *rk_bytes, int nr, __m128i h1, __m128i h2, __m128i h3,
                                          __m128i h4, const uint8_t *iv_ptr, const uint8_t *src_ptr,
                                          int64_t src_len, const uint8_t *aad_ptr, int64_t aad_len,
                                          const uint8_t *tag_ptr, uint8_t *dst_ptr) {
    const __m128i bswap_ctr_mask = _mm_set_epi8(12, 13, 14, 15, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0);
    const __m128i ctr_one_le = _mm_set_epi32(1, 0, 0, 0);
    const __m128i rk0 = _mm_loadu_si128((const __m128i *)rk_bytes);
    const __m128i rk_last = _mm_loadu_si128((const __m128i *)(rk_bytes + (size_t)nr * 16u));
    __m128i j0_vec = wing_make_ctr_block(iv_ptr, 1u);
    __m128i j0_enc = wing_aes_enc_block_bytes(j0_vec, rk_bytes, nr);
    __m128i ctr_le = _mm_add_epi32(_mm_shuffle_epi8(j0_vec, bswap_ctr_mask), ctr_one_le);
    __m128i ghash_acc = wing_ghash_aad_aesni(h1, aad_ptr, aad_len);

    int64_t offset = 0;
    while (offset + 64 <= src_len) {
        __m128i c0 = _mm_loadu_si128((const __m128i *)(src_ptr + offset));
        __m128i c1 = _mm_loadu_si128((const __m128i *)(src_ptr + offset + 16));
        __m128i c2 = _mm_loadu_si128((const __m128i *)(src_ptr + offset + 32));
        __m128i c3 = _mm_loadu_si128((const __m128i *)(src_ptr + offset + 48));

        __m128i b0 = _mm_xor_si128(_mm_shuffle_epi8(ctr_le, bswap_ctr_mask), rk0);
        ctr_le = _mm_add_epi32(ctr_le, ctr_one_le);
        __m128i b1 = _mm_xor_si128(_mm_shuffle_epi8(ctr_le, bswap_ctr_mask), rk0);
        ctr_le = _mm_add_epi32(ctr_le, ctr_one_le);
        __m128i b2 = _mm_xor_si128(_mm_shuffle_epi8(ctr_le, bswap_ctr_mask), rk0);
        ctr_le = _mm_add_epi32(ctr_le, ctr_one_le);
        __m128i b3 = _mm_xor_si128(_mm_shuffle_epi8(ctr_le, bswap_ctr_mask), rk0);
        ctr_le = _mm_add_epi32(ctr_le, ctr_one_le);

        __m128i d0 = _mm_xor_si128(ghash_acc, wing_bswap128(c0));
        __m128i d1 = wing_bswap128(c1);
        __m128i d2 = wing_bswap128(c2);
        __m128i d3 = wing_bswap128(c3);

        for (int r = 1; r <= 3; r++) {
            __m128i rkr = _mm_loadu_si128((const __m128i *)(rk_bytes + (size_t)r * 16u));
            b0 = _mm_aesenc_si128(b0, rkr);
            b1 = _mm_aesenc_si128(b1, rkr);
            b2 = _mm_aesenc_si128(b2, rkr);
            b3 = _mm_aesenc_si128(b3, rkr);
        }
        __m128i lo = _mm_clmulepi64_si128(d0, h4, 0x00);
        __m128i hi = _mm_clmulepi64_si128(d0, h4, 0x11);
        __m128i ab = _mm_clmulepi64_si128(_mm_xor_si128(d0, _mm_shuffle_epi32(d0, 0x4E)),
                                          _mm_xor_si128(h4, _mm_shuffle_epi32(h4, 0x4E)), 0x00);

        for (int r = 4; r <= 6; r++) {
            __m128i rkr = _mm_loadu_si128((const __m128i *)(rk_bytes + (size_t)r * 16u));
            b0 = _mm_aesenc_si128(b0, rkr);
            b1 = _mm_aesenc_si128(b1, rkr);
            b2 = _mm_aesenc_si128(b2, rkr);
            b3 = _mm_aesenc_si128(b3, rkr);
        }
        lo = _mm_xor_si128(lo, _mm_clmulepi64_si128(d1, h3, 0x00));
        hi = _mm_xor_si128(hi, _mm_clmulepi64_si128(d1, h3, 0x11));
        ab = _mm_xor_si128(ab, _mm_clmulepi64_si128(_mm_xor_si128(d1, _mm_shuffle_epi32(d1, 0x4E)),
                                                    _mm_xor_si128(h3, _mm_shuffle_epi32(h3, 0x4E)), 0x00));

        for (int r = 7; r <= 9; r++) {
            __m128i rkr = _mm_loadu_si128((const __m128i *)(rk_bytes + (size_t)r * 16u));
            b0 = _mm_aesenc_si128(b0, rkr);
            b1 = _mm_aesenc_si128(b1, rkr);
            b2 = _mm_aesenc_si128(b2, rkr);
            b3 = _mm_aesenc_si128(b3, rkr);
        }
        lo = _mm_xor_si128(lo, _mm_clmulepi64_si128(d2, h2, 0x00));
        hi = _mm_xor_si128(hi, _mm_clmulepi64_si128(d2, h2, 0x11));
        ab = _mm_xor_si128(ab, _mm_clmulepi64_si128(_mm_xor_si128(d2, _mm_shuffle_epi32(d2, 0x4E)),
                                                    _mm_xor_si128(h2, _mm_shuffle_epi32(h2, 0x4E)), 0x00));

        for (int r = 10; r < nr; r++) {
            __m128i rkr = _mm_loadu_si128((const __m128i *)(rk_bytes + (size_t)r * 16u));
            b0 = _mm_aesenc_si128(b0, rkr);
            b1 = _mm_aesenc_si128(b1, rkr);
            b2 = _mm_aesenc_si128(b2, rkr);
            b3 = _mm_aesenc_si128(b3, rkr);
        }
        lo = _mm_xor_si128(lo, _mm_clmulepi64_si128(d3, h1, 0x00));
        hi = _mm_xor_si128(hi, _mm_clmulepi64_si128(d3, h1, 0x11));
        ab = _mm_xor_si128(ab, _mm_clmulepi64_si128(_mm_xor_si128(d3, _mm_shuffle_epi32(d3, 0x4E)),
                                                    _mm_xor_si128(h1, _mm_shuffle_epi32(h1, 0x4E)), 0x00));

        b0 = _mm_aesenclast_si128(b0, rk_last);
        b1 = _mm_aesenclast_si128(b1, rk_last);
        b2 = _mm_aesenclast_si128(b2, rk_last);
        b3 = _mm_aesenclast_si128(b3, rk_last);

        __m128i mid = _mm_xor_si128(ab, _mm_xor_si128(lo, hi));
        ghash_acc = wing_gf128_reduce256_pclmul(_mm_xor_si128(lo, _mm_slli_si128(mid, 8)),
                                                _mm_xor_si128(hi, _mm_srli_si128(mid, 8)));

        _mm_storeu_si128((__m128i *)(dst_ptr + offset), _mm_xor_si128(c0, b0));
        _mm_storeu_si128((__m128i *)(dst_ptr + offset + 16), _mm_xor_si128(c1, b1));
        _mm_storeu_si128((__m128i *)(dst_ptr + offset + 32), _mm_xor_si128(c2, b2));
        _mm_storeu_si128((__m128i *)(dst_ptr + offset + 48), _mm_xor_si128(c3, b3));

        offset += 64;
    }

    while (offset + 16 <= src_len) {
        __m128i c0 = _mm_loadu_si128((const __m128i *)(src_ptr + offset));
        __m128i ks = wing_aes_enc_block_bytes(_mm_shuffle_epi8(ctr_le, bswap_ctr_mask), rk_bytes, nr);
        ctr_le = _mm_add_epi32(ctr_le, ctr_one_le);
        ghash_acc = wing_gf128_mul_pclmul(_mm_xor_si128(ghash_acc, wing_bswap128(c0)), h1);
        _mm_storeu_si128((__m128i *)(dst_ptr + offset), _mm_xor_si128(c0, ks));
        offset += 16;
    }

    if (offset < src_len) {
        int64_t rem = src_len - offset;
        uint8_t c_pad[16] = {0};
        uint8_t ks_bytes[16];
        memcpy(c_pad, src_ptr + offset, (size_t)rem);
        __m128i ks = wing_aes_enc_block_bytes(_mm_shuffle_epi8(ctr_le, bswap_ctr_mask), rk_bytes, nr);
        _mm_storeu_si128((__m128i *)ks_bytes, ks);
        for (int64_t i = 0; i < rem; i++) {
            dst_ptr[offset + i] = c_pad[i] ^ ks_bytes[i];
        }
        wing_fusion_zeroize(ks_bytes, sizeof(ks_bytes));
        __m128i c_vec = _mm_loadu_si128((const __m128i *)c_pad);
        ghash_acc = wing_gf128_mul_pclmul(_mm_xor_si128(ghash_acc, wing_bswap128(c_vec)), h1);
    }

    ghash_acc = wing_ghash_len_aesni(ghash_acc, h1, aad_len, src_len);
    __m128i tag_vec = _mm_xor_si128(wing_bswap128(ghash_acc), j0_enc);
    uint8_t computed_tag[16];
    _mm_storeu_si128((__m128i *)computed_tag, tag_vec);

    uint8_t diff = 0;
    for (int i = 0; i < 16; i++) {
        diff |= (computed_tag[i] ^ tag_ptr[i]);
    }
    wing_fusion_zeroize(computed_tag, sizeof(computed_tag));
    if (diff != 0) {
        if (src_len > 0) {
            wing_fusion_zeroize(dst_ptr, (size_t)src_len);
        }
        return -1;
    }
    return src_len;
}

WING_TARGET_AES_PCLMUL
static int64_t wing_aes_gcm_open_aesni(const uint8_t *key_ptr, int64_t key_len, const uint8_t *iv_ptr,
                                       const uint8_t *src_ptr, int64_t src_len, const uint8_t *aad_ptr,
                                       int64_t aad_len, const uint8_t *tag_ptr, uint8_t *dst_ptr) {
    __m128i rk[15];
    int nr = wing_aes_expand_key_aesni(key_ptr, key_len, rk);

    __m128i h1 = wing_bswap128(wing_aes_enc_block_aesni(_mm_setzero_si128(), rk, nr));
    __m128i h2 = (src_len >= 64) ? wing_gf128_mul_pclmul(h1, h1) : h1;
    __m128i h3 = (src_len >= 64) ? wing_gf128_mul_pclmul(h2, h1) : h1;
    __m128i h4 = (src_len >= 64) ? wing_gf128_mul_pclmul(h3, h1) : h1;

    int64_t ret = wing_aes_gcm_open_aesni_rk((const uint8_t *)rk, nr, h1, h2, h3, h4, iv_ptr, src_ptr, src_len,
                                             aad_ptr, aad_len, tag_ptr, dst_ptr);
    wing_fusion_zeroize(rk, sizeof(rk));
    return ret;
}
#endif

// ---- Constant-Time Scalar Fallback (for non-AES-NI CPUs) -----------------

static const uint8_t WING_AES_SBOX[256] = {
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76, 0xca, 0x82, 0xc9,
    0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0, 0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f,
    0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15, 0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07,
    0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75, 0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3,
    0x29, 0xe3, 0x2f, 0x84, 0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58,
    0xcf, 0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8, 0x51, 0xa3,
    0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2, 0xcd, 0x0c, 0x13, 0xec, 0x5f,
    0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73, 0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88,
    0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb, 0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac,
    0x62, 0x91, 0x95, 0xe4, 0x79, 0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a,
    0xae, 0x08, 0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a, 0x70,
    0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e, 0xe1, 0xf8, 0x98, 0x11,
    0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf, 0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42,
    0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16};

static inline uint8_t wing_gf_xtime(uint8_t x) { return (uint8_t)((x << 1) ^ (((x >> 7) & 1u) * 0x1bu)); }

static int wing_aes_scalar_expand(const uint8_t *key, int64_t key_len, uint8_t rk[240]) {
    static const uint8_t rcon[10] = {0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36};
    int nk = (key_len == 32) ? 8 : 4;
    int words = (nk == 8) ? 60 : 44;
    memcpy(rk, key, (size_t)key_len);
    for (int i = nk; i < words; i++) {
        uint8_t t[4];
        memcpy(t, &rk[(i - 1) * 4], 4);
        if ((i % nk) == 0) {
            uint8_t tmp = t[0];
            t[0] = WING_AES_SBOX[t[1]] ^ rcon[(i / nk) - 1];
            t[1] = WING_AES_SBOX[t[2]];
            t[2] = WING_AES_SBOX[t[3]];
            t[3] = WING_AES_SBOX[tmp];
        } else if (nk == 8 && (i % nk) == 4) {
            for (int b = 0; b < 4; b++) {
                t[b] = WING_AES_SBOX[t[b]];
            }
        }
        for (int j = 0; j < 4; j++) {
            rk[i * 4 + j] = rk[(i - nk) * 4 + j] ^ t[j];
        }
    }
    return (nk == 8) ? 14 : 10;
}

static void wing_aes_scalar_enc(const uint8_t rk[240], int nr, const uint8_t in[16], uint8_t out[16]) {
    uint8_t s[16];
    for (int i = 0; i < 16; i++)
        s[i] = in[i] ^ rk[i];
    for (int r = 1; r <= nr; r++) {
        uint8_t t[16];
        for (int i = 0; i < 16; i++)
            t[i] = WING_AES_SBOX[s[i]];
        uint8_t sr[16] = {t[0], t[5],  t[10], t[15], t[4],  t[9], t[14], t[3],
                          t[8], t[13], t[2],  t[7],  t[12], t[1], t[6],  t[11]};
        if (r < nr) {
            for (int c = 0; c < 4; c++) {
                uint8_t a0 = sr[c * 4 + 0], a1 = sr[c * 4 + 1], a2 = sr[c * 4 + 2], a3 = sr[c * 4 + 3];
                uint8_t all = a0 ^ a1 ^ a2 ^ a3;
                s[c * 4 + 0] = a0 ^ all ^ wing_gf_xtime(a0 ^ a1);
                s[c * 4 + 1] = a1 ^ all ^ wing_gf_xtime(a1 ^ a2);
                s[c * 4 + 2] = a2 ^ all ^ wing_gf_xtime(a2 ^ a3);
                s[c * 4 + 3] = a3 ^ all ^ wing_gf_xtime(a3 ^ a0);
            }
        } else {
            memcpy(s, sr, 16);
        }
        for (int i = 0; i < 16; i++)
            s[i] ^= rk[r * 16 + i];
    }
    memcpy(out, s, 16);
}

static void wing_ghash_scalar_mul(uint8_t y[16], const uint8_t h[16]) {
    uint64_t vh = 0, vl = 0, zh = 0, zl = 0;
    for (int i = 0; i < 8; i++) {
        vh = (vh << 8) | h[i];
        vl = (vl << 8) | h[8 + i];
    }
    for (int i = 0; i < 128; i++) {
        uint8_t bit = (uint8_t)((y[i >> 3] >> (7 - (i & 7))) & 1u);
        uint64_t mask = (uint64_t)0 - (uint64_t)bit;
        zh ^= vh & mask;
        zl ^= vl & mask;
        uint64_t lsb = vl & 1u;
        vl = (vl >> 1) | (vh << 63);
        vh = (vh >> 1) ^ (((uint64_t)0 - lsb) & 0xE100000000000000ULL);
    }
    for (int i = 0; i < 8; i++) {
        y[i] = (uint8_t)(zh >> (56 - 8 * i));
        y[8 + i] = (uint8_t)(zl >> (56 - 8 * i));
    }
}

static void wing_ghash_aad_scalar(uint8_t y[16], const uint8_t h[16], const uint8_t *aad_ptr, int64_t aad_len) {
    int64_t off = 0;
    while (off < aad_len) {
        int64_t rem = aad_len - off;
        int64_t take = (rem >= 16) ? 16 : rem;
        for (int64_t i = 0; i < take; i++) {
            y[i] ^= aad_ptr[off + i];
        }
        wing_ghash_scalar_mul(y, h);
        off += take;
    }
}

static void wing_ghash_len_scalar(uint8_t y[16], const uint8_t h[16], int64_t aad_len, int64_t ct_len) {
    uint64_t a_bits = ((uint64_t)aad_len) * 8u;
    uint64_t c_bits = ((uint64_t)ct_len) * 8u;
    for (int i = 0; i < 8; i++) {
        y[i] ^= (uint8_t)(a_bits >> (56 - 8 * i));
        y[8 + i] ^= (uint8_t)(c_bits >> (56 - 8 * i));
    }
    wing_ghash_scalar_mul(y, h);
}

static int64_t wing_aes_gcm_seal_scalar_rk(const uint8_t rk[240], int nr, const uint8_t h_blk[16],
                                           const uint8_t *iv_ptr, const uint8_t *src_ptr, int64_t src_len,
                                           const uint8_t *aad_ptr, int64_t aad_len, uint8_t *dst_ptr,
                                           uint8_t *tag_ptr) {
    uint8_t j0[16];
    memcpy(j0, iv_ptr, 12);
    j0[12] = 0;
    j0[13] = 0;
    j0[14] = 0;
    j0[15] = 1;
    uint8_t j0_enc[16];
    wing_aes_scalar_enc(rk, nr, j0, j0_enc);

    uint8_t y[16] = {0};
    wing_ghash_aad_scalar(y, h_blk, aad_ptr, aad_len);

    uint32_t ctr = 2u;
    int64_t offset = 0;
    while (offset < src_len) {
        int64_t blk_len = (src_len - offset >= 16) ? 16 : (src_len - offset);
        uint8_t cb[16], ks[16];
        memcpy(cb, iv_ptr, 12);
        cb[12] = (uint8_t)(ctr >> 24);
        cb[13] = (uint8_t)(ctr >> 16);
        cb[14] = (uint8_t)(ctr >> 8);
        cb[15] = (uint8_t)(ctr);
        ctr += 1u;

        wing_aes_scalar_enc(rk, nr, cb, ks);
        for (int64_t i = 0; i < blk_len; i++) {
            uint8_t c_byte = src_ptr[offset + i] ^ ks[i];
            dst_ptr[offset + i] = c_byte;
            y[i] ^= c_byte;
        }
        wing_fusion_zeroize(ks, sizeof(ks));
        wing_ghash_scalar_mul(y, h_blk);
        offset += blk_len;
    }

    wing_ghash_len_scalar(y, h_blk, aad_len, src_len);
    for (int i = 0; i < 16; i++) {
        tag_ptr[i] = y[i] ^ j0_enc[i];
    }
    wing_fusion_zeroize(j0_enc, sizeof(j0_enc));
    wing_fusion_zeroize(y, sizeof(y));
    return src_len;
}

static int64_t wing_aes_gcm_seal_scalar(const uint8_t *key_ptr, int64_t key_len, const uint8_t *iv_ptr,
                                        const uint8_t *src_ptr, int64_t src_len, const uint8_t *aad_ptr,
                                        int64_t aad_len, uint8_t *dst_ptr, uint8_t *tag_ptr) {
    uint8_t rk[240];
    int nr = wing_aes_scalar_expand(key_ptr, key_len, rk);

    uint8_t zero_blk[16] = {0};
    uint8_t h_blk[16];
    wing_aes_scalar_enc(rk, nr, zero_blk, h_blk);

    int64_t ret = wing_aes_gcm_seal_scalar_rk(rk, nr, h_blk, iv_ptr, src_ptr, src_len, aad_ptr, aad_len, dst_ptr,
                                              tag_ptr);
    wing_fusion_zeroize(rk, sizeof(rk));
    wing_fusion_zeroize(h_blk, sizeof(h_blk));
    return ret;
}

static int64_t wing_aes_gcm_open_scalar_rk(const uint8_t rk[240], int nr, const uint8_t h_blk[16],
                                           const uint8_t *iv_ptr, const uint8_t *src_ptr, int64_t src_len,
                                           const uint8_t *aad_ptr, int64_t aad_len, const uint8_t *tag_ptr,
                                           uint8_t *dst_ptr) {
    uint8_t j0[16];
    memcpy(j0, iv_ptr, 12);
    j0[12] = 0;
    j0[13] = 0;
    j0[14] = 0;
    j0[15] = 1;
    uint8_t j0_enc[16];
    wing_aes_scalar_enc(rk, nr, j0, j0_enc);

    uint8_t y[16] = {0};
    wing_ghash_aad_scalar(y, h_blk, aad_ptr, aad_len);

    uint32_t ctr = 2u;
    int64_t offset = 0;
    while (offset < src_len) {
        int64_t blk_len = (src_len - offset >= 16) ? 16 : (src_len - offset);
        uint8_t cb[16], ks[16];
        memcpy(cb, iv_ptr, 12);
        cb[12] = (uint8_t)(ctr >> 24);
        cb[13] = (uint8_t)(ctr >> 16);
        cb[14] = (uint8_t)(ctr >> 8);
        cb[15] = (uint8_t)(ctr);
        ctr += 1u;

        wing_aes_scalar_enc(rk, nr, cb, ks);
        for (int64_t i = 0; i < blk_len; i++) {
            uint8_t c_byte = src_ptr[offset + i];
            y[i] ^= c_byte;
            dst_ptr[offset + i] = c_byte ^ ks[i];
        }
        wing_fusion_zeroize(ks, sizeof(ks));
        wing_ghash_scalar_mul(y, h_blk);
        offset += blk_len;
    }

    wing_ghash_len_scalar(y, h_blk, aad_len, src_len);

    uint8_t diff = 0;
    for (int i = 0; i < 16; i++) {
        uint8_t calc_t = y[i] ^ j0_enc[i];
        diff |= (calc_t ^ tag_ptr[i]);
    }
    wing_fusion_zeroize(j0_enc, sizeof(j0_enc));
    wing_fusion_zeroize(y, sizeof(y));
    if (diff != 0) {
        if (src_len > 0) {
            wing_fusion_zeroize(dst_ptr, (size_t)src_len);
        }
        return -1;
    }
    return src_len;
}

static int64_t wing_aes_gcm_open_scalar(const uint8_t *key_ptr, int64_t key_len, const uint8_t *iv_ptr,
                                        const uint8_t *src_ptr, int64_t src_len, const uint8_t *aad_ptr,
                                        int64_t aad_len, const uint8_t *tag_ptr, uint8_t *dst_ptr) {
    uint8_t rk[240];
    int nr = wing_aes_scalar_expand(key_ptr, key_len, rk);

    uint8_t zero_blk[16] = {0};
    uint8_t h_blk[16];
    wing_aes_scalar_enc(rk, nr, zero_blk, h_blk);

    int64_t ret = wing_aes_gcm_open_scalar_rk(rk, nr, h_blk, iv_ptr, src_ptr, src_len, aad_ptr, aad_len, tag_ptr,
                                              dst_ptr);
    wing_fusion_zeroize(rk, sizeof(rk));
    wing_fusion_zeroize(h_blk, sizeof(h_blk));
    return ret;
}

// ---- ChaCha20-Poly1305 AEAD Hardware & 128-bit Acceleration (RFC 8439) ----

static inline uint32_t wing_load32_le(const uint8_t *p) {
    uint32_t v;
    memcpy(&v, p, sizeof(v));
    return v;
}

static inline uint64_t wing_load64_le(const uint8_t *p) {
    uint64_t v;
    memcpy(&v, p, sizeof(v));
    return v;
}

static inline void wing_store32_le(uint8_t *p, uint32_t v) { memcpy(p, &v, sizeof(v)); }

static inline void wing_store64_le(uint8_t *p, uint64_t v) { memcpy(p, &v, sizeof(v)); }

static inline uint32_t wing_rotl32(uint32_t x, int n) { return (x << n) | (x >> (32 - n)); }

static inline void wing_chacha_qr(uint32_t *a, uint32_t *b, uint32_t *c, uint32_t *d) {
    *a += *b; *d = wing_rotl32(*d ^ *a, 16);
    *c += *d; *b = wing_rotl32(*b ^ *c, 12);
    *a += *b; *d = wing_rotl32(*d ^ *a, 8);
    *c += *d; *b = wing_rotl32(*b ^ *c, 7);
}

static void wing_chacha20_block_scalar(const uint32_t state[16], uint8_t out[64]) {
    uint32_t x[16];
    memcpy(x, state, 64);
    for (int i = 0; i < 10; i++) {
        wing_chacha_qr(&x[0], &x[4], &x[8],  &x[12]);
        wing_chacha_qr(&x[1], &x[5], &x[9],  &x[13]);
        wing_chacha_qr(&x[2], &x[6], &x[10], &x[14]);
        wing_chacha_qr(&x[3], &x[7], &x[11], &x[15]);
        wing_chacha_qr(&x[0], &x[5], &x[10], &x[15]);
        wing_chacha_qr(&x[1], &x[6], &x[11], &x[12]);
        wing_chacha_qr(&x[2], &x[7], &x[8],  &x[13]);
        wing_chacha_qr(&x[3], &x[4], &x[9],  &x[14]);
    }
    for (int i = 0; i < 16; i++) {
        wing_store32_le(out + i * 4, x[i] + state[i]);
    }
    wing_fusion_zeroize(x, sizeof(x));
}

#if (defined(__x86_64__) || defined(_M_X64)) && defined(__GNUC__)

#define WING_TARGET_AVX2 __attribute__((target("avx2")))

static inline int wing_cpu_has_avx2(void) { return __builtin_cpu_supports("avx2"); }

#define WING_AVX2_ROTL16(v) _mm256_shuffle_epi8((v), rot16_mask)
#define WING_AVX2_ROTL8(v) _mm256_shuffle_epi8((v), rot8_mask)
#define WING_AVX2_ROTL12(v) _mm256_or_si256(_mm256_slli_epi32((v), 12), _mm256_srli_epi32((v), 20))
#define WING_AVX2_ROTL7(v) _mm256_or_si256(_mm256_slli_epi32((v), 7), _mm256_srli_epi32((v), 25))

#define WING_AVX2_QR(a, b, c, d)                                                                                       \
    do {                                                                                                               \
        (a) = _mm256_add_epi32((a), (b));                                                                              \
        (d) = WING_AVX2_ROTL16(_mm256_xor_si256((d), (a)));                                                            \
        (c) = _mm256_add_epi32((c), (d));                                                                              \
        (b) = WING_AVX2_ROTL12(_mm256_xor_si256((b), (c)));                                                            \
        (a) = _mm256_add_epi32((a), (b));                                                                              \
        (d) = WING_AVX2_ROTL8(_mm256_xor_si256((d), (a)));                                                             \
        (c) = _mm256_add_epi32((c), (d));                                                                              \
        (b) = WING_AVX2_ROTL7(_mm256_xor_si256((b), (c)));                                                             \
    } while (0)

WING_TARGET_AVX2
static inline void wing_avx2_xor_4rows(__m256i r0, __m256i r1, __m256i r2, __m256i r3, const uint8_t *src,
                                       uint8_t *dst, int row_off) {
    __m256i t0 = _mm256_unpacklo_epi32(r0, r1);
    __m256i t1 = _mm256_unpackhi_epi32(r0, r1);
    __m256i t2 = _mm256_unpacklo_epi32(r2, r3);
    __m256i t3 = _mm256_unpackhi_epi32(r2, r3);

    __m256i u0 = _mm256_unpacklo_epi64(t0, t2);
    __m256i u1 = _mm256_unpackhi_epi64(t0, t2);
    __m256i u2 = _mm256_unpacklo_epi64(t1, t3);
    __m256i u3 = _mm256_unpackhi_epi64(t1, t3);

    _mm_storeu_si128((__m128i *)(dst + 0 * 64 + row_off),
                     _mm_xor_si128(_mm_loadu_si128((const __m128i *)(src + 0 * 64 + row_off)),
                                   _mm256_castsi256_si128(u0)));
    _mm_storeu_si128((__m128i *)(dst + 1 * 64 + row_off),
                     _mm_xor_si128(_mm_loadu_si128((const __m128i *)(src + 1 * 64 + row_off)),
                                   _mm256_castsi256_si128(u1)));
    _mm_storeu_si128((__m128i *)(dst + 2 * 64 + row_off),
                     _mm_xor_si128(_mm_loadu_si128((const __m128i *)(src + 2 * 64 + row_off)),
                                   _mm256_castsi256_si128(u2)));
    _mm_storeu_si128((__m128i *)(dst + 3 * 64 + row_off),
                     _mm_xor_si128(_mm_loadu_si128((const __m128i *)(src + 3 * 64 + row_off)),
                                   _mm256_castsi256_si128(u3)));

    _mm_storeu_si128((__m128i *)(dst + 4 * 64 + row_off),
                     _mm_xor_si128(_mm_loadu_si128((const __m128i *)(src + 4 * 64 + row_off)),
                                   _mm256_extracti128_si256(u0, 1)));
    _mm_storeu_si128((__m128i *)(dst + 5 * 64 + row_off),
                     _mm_xor_si128(_mm_loadu_si128((const __m128i *)(src + 5 * 64 + row_off)),
                                   _mm256_extracti128_si256(u1, 1)));
    _mm_storeu_si128((__m128i *)(dst + 6 * 64 + row_off),
                     _mm_xor_si128(_mm_loadu_si128((const __m128i *)(src + 6 * 64 + row_off)),
                                   _mm256_extracti128_si256(u2, 1)));
    _mm_storeu_si128((__m128i *)(dst + 7 * 64 + row_off),
                     _mm_xor_si128(_mm_loadu_si128((const __m128i *)(src + 7 * 64 + row_off)),
                                   _mm256_extracti128_si256(u3, 1)));
}

WING_TARGET_AVX2
static void wing_chacha20_xor_avx2(uint32_t init_state[16], const uint8_t *src, uint8_t *dst, int64_t len) {
    const __m256i rot16_mask = _mm256_set_epi8(
        13, 12, 15, 14, 9, 8, 11, 10, 5, 4, 7, 6, 1, 0, 3, 2,
        13, 12, 15, 14, 9, 8, 11, 10, 5, 4, 7, 6, 1, 0, 3, 2);
    const __m256i rot8_mask = _mm256_set_epi8(
        14, 13, 12, 15, 10, 9, 8, 11, 6, 5, 4, 7, 2, 1, 0, 3,
        14, 13, 12, 15, 10, 9, 8, 11, 6, 5, 4, 7, 2, 1, 0, 3);
    const __m256i ctr_offsets = _mm256_setr_epi32(0, 1, 2, 3, 4, 5, 6, 7);

    __m256i s0 = _mm256_set1_epi32((int)init_state[0]);
    __m256i s1 = _mm256_set1_epi32((int)init_state[1]);
    __m256i s2 = _mm256_set1_epi32((int)init_state[2]);
    __m256i s3 = _mm256_set1_epi32((int)init_state[3]);
    __m256i s4 = _mm256_set1_epi32((int)init_state[4]);
    __m256i s5 = _mm256_set1_epi32((int)init_state[5]);
    __m256i s6 = _mm256_set1_epi32((int)init_state[6]);
    __m256i s7 = _mm256_set1_epi32((int)init_state[7]);
    __m256i s8 = _mm256_set1_epi32((int)init_state[8]);
    __m256i s9 = _mm256_set1_epi32((int)init_state[9]);
    __m256i s10 = _mm256_set1_epi32((int)init_state[10]);
    __m256i s11 = _mm256_set1_epi32((int)init_state[11]);
    __m256i s13 = _mm256_set1_epi32((int)init_state[13]);
    __m256i s14 = _mm256_set1_epi32((int)init_state[14]);
    __m256i s15 = _mm256_set1_epi32((int)init_state[15]);

    int64_t off = 0;
    while (off + 512 <= len) {
        __m256i s12 = _mm256_add_epi32(_mm256_set1_epi32((int)init_state[12]), ctr_offsets);
        __m256i x0 = s0, x1 = s1, x2 = s2, x3 = s3;
        __m256i x4 = s4, x5 = s5, x6 = s6, x7 = s7;
        __m256i x8 = s8, x9 = s9, x10 = s10, x11 = s11;
        __m256i x12 = s12, x13 = s13, x14 = s14, x15 = s15;

        for (int r = 0; r < 10; r++) {
            WING_AVX2_QR(x0, x4, x8, x12);
            WING_AVX2_QR(x1, x5, x9, x13);
            WING_AVX2_QR(x2, x6, x10, x14);
            WING_AVX2_QR(x3, x7, x11, x15);
            WING_AVX2_QR(x0, x5, x10, x15);
            WING_AVX2_QR(x1, x6, x11, x12);
            WING_AVX2_QR(x2, x7, x8, x13);
            WING_AVX2_QR(x3, x4, x9, x14);
        }

        wing_avx2_xor_4rows(_mm256_add_epi32(x0, s0), _mm256_add_epi32(x1, s1), _mm256_add_epi32(x2, s2),
                            _mm256_add_epi32(x3, s3), src + off, dst + off, 0);
        wing_avx2_xor_4rows(_mm256_add_epi32(x4, s4), _mm256_add_epi32(x5, s5), _mm256_add_epi32(x6, s6),
                            _mm256_add_epi32(x7, s7), src + off, dst + off, 16);
        wing_avx2_xor_4rows(_mm256_add_epi32(x8, s8), _mm256_add_epi32(x9, s9), _mm256_add_epi32(x10, s10),
                            _mm256_add_epi32(x11, s11), src + off, dst + off, 32);
        wing_avx2_xor_4rows(_mm256_add_epi32(x12, s12), _mm256_add_epi32(x13, s13), _mm256_add_epi32(x14, s14),
                            _mm256_add_epi32(x15, s15), src + off, dst + off, 48);

        init_state[12] += 8u;
        off += 512;
    }

    while (off < len) {
        uint8_t ks[64];
        wing_chacha20_block_scalar(init_state, ks);
        init_state[12] += 1u;
        int64_t take = (len - off >= 64) ? 64 : (len - off);
        for (int64_t i = 0; i < take; i++) {
            dst[off + i] = src[off + i] ^ ks[i];
        }
        wing_fusion_zeroize(ks, sizeof(ks));
        off += take;
    }
}
#endif

static void wing_chacha20_xor_stream(const uint8_t key[32], const uint8_t iv[12], uint32_t ctr,
                                     const uint8_t *src, uint8_t *dst, int64_t len) {
    uint32_t st[16];
    st[0] = 0x61707865u;
    st[1] = 0x3320646eu;
    st[2] = 0x79622d32u;
    st[3] = 0x6b206574u;
    for (int i = 0; i < 8; i++) {
        st[4 + i] = wing_load32_le(key + i * 4);
    }
    st[12] = ctr;
    st[13] = wing_load32_le(iv + 0);
    st[14] = wing_load32_le(iv + 4);
    st[15] = wing_load32_le(iv + 8);

#if (defined(__x86_64__) || defined(_M_X64)) && defined(__GNUC__)
    if (len >= 512 && wing_cpu_has_avx2()) {
        wing_chacha20_xor_avx2(st, src, dst, len);
        wing_fusion_zeroize(st, sizeof(st));
        return;
    }
#endif

    int64_t off = 0;
    while (off < len) {
        uint8_t ks[64];
        wing_chacha20_block_scalar(st, ks);
        st[12] += 1u;
        int64_t take = (len - off >= 64) ? 64 : (len - off);
        for (int64_t i = 0; i < take; i++) {
            dst[off + i] = src[off + i] ^ ks[i];
        }
        wing_fusion_zeroize(ks, sizeof(ks));
        off += take;
    }
    wing_fusion_zeroize(st, sizeof(st));
}

typedef struct {
    uint64_t r0, r1, r2;
    uint64_t s1, s2;
    uint64_t h0, h1, h2;
    uint64_t pad0, pad1;
} wing_poly1305_state;

static void wing_poly1305_init(wing_poly1305_state *st, const uint8_t key[32]) {
    uint64_t t0 = wing_load64_le(key + 0) & 0x0ffffffc0fffffffULL;
    uint64_t t1 = wing_load64_le(key + 8) & 0x0ffffffc0ffffffcULL;

    st->r0 = t0 & 0x0fffffffffffULL;
    st->r1 = ((t0 >> 44) | (t1 << 20)) & 0x0fffffffffffULL;
    st->r2 = (t1 >> 24) & 0x03ffffffffffULL;

    st->s1 = st->r1 * 20u;
    st->s2 = st->r2 * 20u;

    st->h0 = 0;
    st->h1 = 0;
    st->h2 = 0;
    st->pad0 = wing_load64_le(key + 16);
    st->pad1 = wing_load64_le(key + 24);
}

#ifdef __SIZEOF_INT128__
static void wing_poly1305_blocks(wing_poly1305_state *st, const uint8_t *m, int64_t len, uint64_t hibit_40) {
    uint64_t h0 = st->h0, h1 = st->h1, h2 = st->h2;
    const uint64_t r0 = st->r0, r1 = st->r1, r2 = st->r2;
    const uint64_t s1 = st->s1, s2 = st->s2;

    while (len >= 16) {
        uint64_t t0 = wing_load64_le(m + 0);
        uint64_t t1 = wing_load64_le(m + 8);
        h0 += t0 & 0x0fffffffffffULL;
        h1 += ((t0 >> 44) | (t1 << 20)) & 0x0fffffffffffULL;
        h2 += (t1 >> 24) | hibit_40;

        __uint128_t d0 = ((__uint128_t)h0 * r0) + ((__uint128_t)h1 * s2) + ((__uint128_t)h2 * s1);
        __uint128_t d1 = ((__uint128_t)h0 * r1) + ((__uint128_t)h1 * r0) + ((__uint128_t)h2 * s2);
        __uint128_t d2 = ((__uint128_t)h0 * r2) + ((__uint128_t)h1 * r1) + ((__uint128_t)h2 * r0);

        uint64_t c = (uint64_t)(d0 >> 44);
        h0 = (uint64_t)d0 & 0x0fffffffffffULL;
        d1 += c;
        c = (uint64_t)(d1 >> 44);
        h1 = (uint64_t)d1 & 0x0fffffffffffULL;
        d2 += c;
        c = (uint64_t)(d2 >> 42);
        h2 = (uint64_t)d2 & 0x03ffffffffffULL;
        h0 += c * 5u;
        c = h0 >> 44;
        h0 &= 0x0fffffffffffULL;
        h1 += c;

        m += 16;
        len -= 16;
    }

    st->h0 = h0;
    st->h1 = h1;
    st->h2 = h2;
}
#else
static inline void wing_muladd_u128(uint64_t *lo_acc, uint64_t *hi_acc, uint64_t a, uint64_t b) {
    uint64_t a0 = a & 0xffffffffULL, a1 = a >> 32;
    uint64_t b0 = b & 0xffffffffULL, b1 = b >> 32;
    uint64_t p00 = a0 * b0;
    uint64_t p01 = a0 * b1;
    uint64_t p10 = a1 * b0;
    uint64_t p11 = a1 * b1;
    uint64_t mid = p01 + (p00 >> 32);
    uint64_t c0 = (mid < p01);
    uint64_t lo = (p00 & 0xffffffffULL) | (mid << 32);
    uint64_t lo2 = lo + (p10 << 32);
    uint64_t c1 = (lo2 < lo);
    uint64_t hi = p11 + (mid >> 32) + (p10 >> 32) + (c0 << 32) + c1;
    uint64_t s_lo = *lo_acc + lo2;
    *hi_acc += hi + (s_lo < *lo_acc);
    *lo_acc = s_lo;
}

static void wing_poly1305_blocks(wing_poly1305_state *st, const uint8_t *m, int64_t len, uint64_t hibit_40) {
    uint64_t h0 = st->h0, h1 = st->h1, h2 = st->h2;
    const uint64_t r0 = st->r0, r1 = st->r1, r2 = st->r2;
    const uint64_t s1 = st->s1, s2 = st->s2;

    while (len >= 16) {
        uint64_t t0 = wing_load64_le(m + 0);
        uint64_t t1 = wing_load64_le(m + 8);
        h0 += t0 & 0x0fffffffffffULL;
        h1 += ((t0 >> 44) | (t1 << 20)) & 0x0fffffffffffULL;
        h2 += (t1 >> 24) | hibit_40;

        uint64_t d0_lo = 0, d0_hi = 0, d1_lo = 0, d1_hi = 0, d2_lo = 0, d2_hi = 0;
        wing_muladd_u128(&d0_lo, &d0_hi, h0, r0);
        wing_muladd_u128(&d0_lo, &d0_hi, h1, s2);
        wing_muladd_u128(&d0_lo, &d0_hi, h2, s1);

        wing_muladd_u128(&d1_lo, &d1_hi, h0, r1);
        wing_muladd_u128(&d1_lo, &d1_hi, h1, r0);
        wing_muladd_u128(&d1_lo, &d1_hi, h2, s2);

        wing_muladd_u128(&d2_lo, &d2_hi, h0, r2);
        wing_muladd_u128(&d2_lo, &d2_hi, h1, r1);
        wing_muladd_u128(&d2_lo, &d2_hi, h2, r0);

        uint64_t c = (d0_lo >> 44) | (d0_hi << 20);
        h0 = d0_lo & 0x0fffffffffffULL;
        uint64_t s1_lo = d1_lo + c;
        uint64_t s1_hi = d1_hi + (s1_lo < d1_lo);
        c = (s1_lo >> 44) | (s1_hi << 20);
        h1 = s1_lo & 0x0fffffffffffULL;

        uint64_t s2_lo = d2_lo + c;
        uint64_t s2_hi = d2_hi + (s2_lo < d2_lo);
        c = (s2_lo >> 42) | (s2_hi << 22);
        h2 = s2_lo & 0x03ffffffffffULL;

        h0 += c * 5u;
        c = h0 >> 44;
        h0 &= 0x0fffffffffffULL;
        h1 += c;

        m += 16;
        len -= 16;
    }

    st->h0 = h0;
    st->h1 = h1;
    st->h2 = h2;
}
#endif

static void wing_poly1305_update_padded(wing_poly1305_state *st, const uint8_t *data, int64_t len) {
    int64_t full = len & ~15LL;
    if (full > 0) {
        wing_poly1305_blocks(st, data, full, 1ULL << 40);
    }
    int64_t rem = len - full;
    if (rem > 0) {
        uint8_t pad[16] = {0};
        memcpy(pad, data + full, (size_t)rem);
        wing_poly1305_blocks(st, pad, 16, 1ULL << 40);
    }
}

static void wing_poly1305_finish(wing_poly1305_state *st, uint8_t tag[16]) {
    uint64_t h0 = st->h0, h1 = st->h1, h2 = st->h2;
    uint64_t c = h1 >> 44;
    h1 &= 0x0fffffffffffULL;
    h2 += c;
    c = h2 >> 42;
    h2 &= 0x03ffffffffffULL;
    h0 += c * 5u;
    c = h0 >> 44;
    h0 &= 0x0fffffffffffULL;
    h1 += c;
    c = h1 >> 44;
    h1 &= 0x0fffffffffffULL;
    h2 += c;
    c = h2 >> 42;
    h2 &= 0x03ffffffffffULL;
    h0 += c * 5u;
    c = h0 >> 44;
    h0 &= 0x0fffffffffffULL;
    h1 += c;

    uint64_t g0 = h0 + 5u;
    c = g0 >> 44;
    g0 &= 0x0fffffffffffULL;
    uint64_t g1 = h1 + c;
    c = g1 >> 44;
    g1 &= 0x0fffffffffffULL;
    uint64_t g2 = h2 + c - (1ULL << 42);

    uint64_t mask = (g2 >> 63) - 1u;
    h0 = (h0 & ~mask) | (g0 & mask);
    h1 = (h1 & ~mask) | (g1 & mask);
    h2 = (h2 & ~mask) | (g2 & mask);

    uint64_t f0 = h0 | (h1 << 44);
    uint64_t f1 = (h1 >> 20) | (h2 << 24);
    uint64_t sum0 = f0 + st->pad0;
    uint64_t sum1 = f1 + st->pad1 + (uint64_t)(sum0 < f0);
    wing_store64_le(tag + 0, sum0);
    wing_store64_le(tag + 8, sum1);
    wing_fusion_zeroize(st, sizeof(*st));
}

int64_t wing_chacha_poly_seal_aead(wing_slice key, wing_slice iv, wing_slice src, wing_slice aad,
                                   wing_slice dst, wing_slice tag_out) {
    if (key.len != 32 || iv.len != 12 || tag_out.len != 16 || src.len < 0 || aad.len < 0 ||
        src.len > 0x3FFFFFFFF0LL || dst.len < src.len || key.ptr == NULL || iv.ptr == NULL || tag_out.ptr == NULL) {
        return -1;
    }
    if (src.len > 0 && (src.ptr == NULL || dst.ptr == NULL)) {
        return -1;
    }
    if (aad.len > 0 && aad.ptr == NULL) {
        return -1;
    }

    uint32_t st0[16] = {
        0x61707865u, 0x3320646eu, 0x79622d32u, 0x6b206574u,
        wing_load32_le(key.ptr + 0),  wing_load32_le(key.ptr + 4),
        wing_load32_le(key.ptr + 8),  wing_load32_le(key.ptr + 12),
        wing_load32_le(key.ptr + 16), wing_load32_le(key.ptr + 20),
        wing_load32_le(key.ptr + 24), wing_load32_le(key.ptr + 28),
        0u,
        wing_load32_le(iv.ptr + 0), wing_load32_le(iv.ptr + 4), wing_load32_le(iv.ptr + 8),
    };
    uint8_t otk_block[64];
    wing_chacha20_block_scalar(st0, otk_block);
    wing_fusion_zeroize(st0, sizeof(st0));

    if (src.len > 0) {
        wing_chacha20_xor_stream(key.ptr, iv.ptr, 1u, src.ptr, dst.ptr, src.len);
    }

    wing_poly1305_state poly;
    wing_poly1305_init(&poly, otk_block);
    wing_fusion_zeroize(otk_block, sizeof(otk_block));

    if (aad.len > 0) {
        wing_poly1305_update_padded(&poly, aad.ptr, aad.len);
    }
    if (src.len > 0) {
        wing_poly1305_update_padded(&poly, dst.ptr, src.len);
    }
    uint8_t lens_blk[16];
    wing_store64_le(lens_blk + 0, (uint64_t)aad.len);
    wing_store64_le(lens_blk + 8, (uint64_t)src.len);
    wing_poly1305_blocks(&poly, lens_blk, 16, 1ULL << 40);
    wing_poly1305_finish(&poly, tag_out.ptr);
    return src.len;
}

int64_t wing_chacha_poly_open_aead(wing_slice key, wing_slice iv, wing_slice src, wing_slice aad,
                                   wing_slice tag, wing_slice dst) {
    if (key.len != 32 || iv.len != 12 || tag.len != 16 || src.len < 0 || aad.len < 0 ||
        src.len > 0x3FFFFFFFF0LL || dst.len < src.len || key.ptr == NULL || iv.ptr == NULL || tag.ptr == NULL) {
        return -1;
    }
    if (src.len > 0 && (src.ptr == NULL || dst.ptr == NULL)) {
        return -1;
    }
    if (aad.len > 0 && aad.ptr == NULL) {
        return -1;
    }

    uint32_t st0[16] = {
        0x61707865u, 0x3320646eu, 0x79622d32u, 0x6b206574u,
        wing_load32_le(key.ptr + 0),  wing_load32_le(key.ptr + 4),
        wing_load32_le(key.ptr + 8),  wing_load32_le(key.ptr + 12),
        wing_load32_le(key.ptr + 16), wing_load32_le(key.ptr + 20),
        wing_load32_le(key.ptr + 24), wing_load32_le(key.ptr + 28),
        0u,
        wing_load32_le(iv.ptr + 0), wing_load32_le(iv.ptr + 4), wing_load32_le(iv.ptr + 8),
    };
    uint8_t otk_block[64];
    wing_chacha20_block_scalar(st0, otk_block);
    wing_fusion_zeroize(st0, sizeof(st0));

    wing_poly1305_state poly;
    wing_poly1305_init(&poly, otk_block);
    wing_fusion_zeroize(otk_block, sizeof(otk_block));

    if (aad.len > 0) {
        wing_poly1305_update_padded(&poly, aad.ptr, aad.len);
    }
    if (src.len > 0) {
        wing_poly1305_update_padded(&poly, src.ptr, src.len);
    }
    uint8_t lens_blk[16];
    wing_store64_le(lens_blk + 0, (uint64_t)aad.len);
    wing_store64_le(lens_blk + 8, (uint64_t)src.len);
    wing_poly1305_blocks(&poly, lens_blk, 16, 1ULL << 40);

    uint8_t computed_tag[16];
    wing_poly1305_finish(&poly, computed_tag);

    uint8_t diff = 0;
    for (int i = 0; i < 16; i++) {
        diff |= (computed_tag[i] ^ tag.ptr[i]);
    }
    wing_fusion_zeroize(computed_tag, sizeof(computed_tag));

    if (diff != 0) {
        if (src.len > 0) {
            wing_fusion_zeroize(dst.ptr, (size_t)src.len);
        }
        return -1;
    }

    if (src.len > 0) {
        wing_chacha20_xor_stream(key.ptr, iv.ptr, 1u, src.ptr, dst.ptr, src.len);
    }
    return src.len;
}

int64_t wing_aes_gcm_seal_aead(wing_slice key, wing_slice iv, wing_slice src, wing_slice aad,
                               wing_slice dst, wing_slice tag_out) {
    if ((key.len != 16 && key.len != 32) || iv.len != 12 || tag_out.len != 16 || src.len < 0 || aad.len < 0 ||
        dst.len < src.len || key.ptr == NULL || iv.ptr == NULL || tag_out.ptr == NULL) {
        return -1;
    }
    if (src.len > 0 && (src.ptr == NULL || dst.ptr == NULL)) {
        return -1;
    }
    if (aad.len > 0 && aad.ptr == NULL) {
        return -1;
    }
#if defined(__x86_64__) || defined(_M_X64)
    if (wing_cpu_has_aes_pclmul()) {
        return wing_aes_gcm_seal_aesni(key.ptr, key.len, iv.ptr, src.ptr, src.len, aad.ptr, aad.len, dst.ptr,
                                       tag_out.ptr);
    }
#endif
    return wing_aes_gcm_seal_scalar(key.ptr, key.len, iv.ptr, src.ptr, src.len, aad.ptr, aad.len, dst.ptr,
                                    tag_out.ptr);
}

int64_t wing_aes_gcm_open_aead(wing_slice key, wing_slice iv, wing_slice src, wing_slice aad,
                               wing_slice tag, wing_slice dst) {
    if ((key.len != 16 && key.len != 32) || iv.len != 12 || tag.len != 16 || src.len < 0 || aad.len < 0 ||
        dst.len < src.len || key.ptr == NULL || iv.ptr == NULL || tag.ptr == NULL) {
        return -1;
    }
    if (src.len > 0 && (src.ptr == NULL || dst.ptr == NULL)) {
        return -1;
    }
    if (aad.len > 0 && aad.ptr == NULL) {
        return -1;
    }
#if defined(__x86_64__) || defined(_M_X64)
    if (wing_cpu_has_aes_pclmul()) {
        return wing_aes_gcm_open_aesni(key.ptr, key.len, iv.ptr, src.ptr, src.len, aad.ptr, aad.len, tag.ptr,
                                       dst.ptr);
    }
#endif
    return wing_aes_gcm_open_scalar(key.ptr, key.len, iv.ptr, src.ptr, src.len, aad.ptr, aad.len, tag.ptr,
                                    dst.ptr);
}

int32_t wing_aes_gcm_decrypt(wing_slice key, wing_slice iv, wing_slice src, wing_slice dst) {
    if (key.len != 16 || iv.len != 12 || src.len < 16 || src.ptr == NULL) {
        return -1;
    }
    int64_t ct_len = src.len - 16;
    if (dst.len < ct_len) {
        return -1;
    }
    wing_slice ct = {src.ptr, ct_len};
    wing_slice aad = {NULL, 0};
    wing_slice tag = {src.ptr + ct_len, 16};
    return (int32_t)wing_aes_gcm_open_aead(key, iv, ct, aad, tag, dst);
}

#define WING_AES_GCM_STATE_BYTES 320
#define WING_AES_GCM_MODE_AESNI 1
#define WING_AES_GCM_MODE_SCALAR 2

#if defined(__x86_64__) || defined(_M_X64)
WING_TARGET_AES_PCLMUL
static void wing_aes_gcm_prepare_aesni(const uint8_t *key_ptr, int64_t key_len, uint8_t *ctx_ptr) {
    __m128i rk[15];
    memset(rk, 0, sizeof(rk));
    int nr = wing_aes_expand_key_aesni(key_ptr, key_len, rk);

    __m128i h1 = wing_bswap128(wing_aes_enc_block_aesni(_mm_setzero_si128(), rk, nr));
    __m128i h2 = wing_gf128_mul_pclmul(h1, h1);
    __m128i h3 = wing_gf128_mul_pclmul(h2, h1);
    __m128i h4 = wing_gf128_mul_pclmul(h3, h1);

    memcpy(ctx_ptr, rk, 240);
    _mm_storeu_si128((__m128i *)(ctx_ptr + 240), h1);
    _mm_storeu_si128((__m128i *)(ctx_ptr + 256), h2);
    _mm_storeu_si128((__m128i *)(ctx_ptr + 272), h3);
    _mm_storeu_si128((__m128i *)(ctx_ptr + 288), h4);
    int32_t meta[2] = {nr, WING_AES_GCM_MODE_AESNI};
    memcpy(ctx_ptr + 304, meta, sizeof(meta));
    wing_fusion_zeroize(rk, sizeof(rk));
}
#endif

int32_t wing_aes_gcm_prepare_key(wing_slice key, wing_slice ctx_out) {
    if ((key.len != 16 && key.len != 32) || ctx_out.len < WING_AES_GCM_STATE_BYTES || key.ptr == NULL ||
        ctx_out.ptr == NULL) {
        return -1;
    }
    memset(ctx_out.ptr, 0, WING_AES_GCM_STATE_BYTES);
#if defined(__x86_64__) || defined(_M_X64)
    if (wing_cpu_has_aes_pclmul()) {
        wing_aes_gcm_prepare_aesni(key.ptr, key.len, ctx_out.ptr);
        return 0;
    }
#endif
    uint8_t rk[240];
    memset(rk, 0, sizeof(rk));
    int nr = wing_aes_scalar_expand(key.ptr, key.len, rk);
    uint8_t zero_blk[16] = {0};
    uint8_t h_blk[16];
    wing_aes_scalar_enc(rk, nr, zero_blk, h_blk);
    memcpy(ctx_out.ptr, rk, sizeof(rk));
    memcpy(ctx_out.ptr + 240, h_blk, sizeof(h_blk));
    int32_t meta[2] = {nr, WING_AES_GCM_MODE_SCALAR};
    memcpy(ctx_out.ptr + 304, meta, sizeof(meta));
    wing_fusion_zeroize(rk, sizeof(rk));
    wing_fusion_zeroize(h_blk, sizeof(h_blk));
    return 0;
}

static inline int wing_aes_gcm_valid_prepared_args(wing_slice ctx, wing_slice iv, wing_slice src, wing_slice aad,
                                                   wing_slice dst, wing_slice tag_slice, int32_t *nr_out,
                                                   int32_t *mode_out) {
    if (ctx.len < WING_AES_GCM_STATE_BYTES || iv.len != 12 || tag_slice.len != 16 || src.len < 0 || aad.len < 0 ||
        dst.len < src.len || ctx.ptr == NULL || iv.ptr == NULL || tag_slice.ptr == NULL) {
        return 0;
    }
    if (src.len > 0 && (src.ptr == NULL || dst.ptr == NULL)) {
        return 0;
    }
    if (aad.len > 0 && aad.ptr == NULL) {
        return 0;
    }
    int32_t meta[2];
    memcpy(meta, ctx.ptr + 304, sizeof(meta));
    int32_t nr = meta[0];
    int32_t mode = meta[1];
    if ((nr != 10 && nr != 14) || (mode != WING_AES_GCM_MODE_AESNI && mode != WING_AES_GCM_MODE_SCALAR)) {
        return 0;
    }
    *nr_out = nr;
    *mode_out = mode;
    return 1;
}

int64_t wing_aes_gcm_seal_prepared(wing_slice ctx, wing_slice iv, wing_slice src, wing_slice aad, wing_slice dst,
                                   wing_slice tag_out) {
    int32_t nr = 0;
    int32_t mode = 0;
    if (!wing_aes_gcm_valid_prepared_args(ctx, iv, src, aad, dst, tag_out, &nr, &mode)) {
        return -1;
    }
#if defined(__x86_64__) || defined(_M_X64)
    if (mode == WING_AES_GCM_MODE_AESNI) {
        __m128i h1 = _mm_loadu_si128((const __m128i *)(ctx.ptr + 240));
        __m128i h2 = _mm_loadu_si128((const __m128i *)(ctx.ptr + 256));
        __m128i h3 = _mm_loadu_si128((const __m128i *)(ctx.ptr + 272));
        __m128i h4 = _mm_loadu_si128((const __m128i *)(ctx.ptr + 288));
        return wing_aes_gcm_seal_aesni_rk(ctx.ptr, nr, h1, h2, h3, h4, iv.ptr, src.ptr, src.len, aad.ptr, aad.len,
                                          dst.ptr, tag_out.ptr);
    }
#endif
    return wing_aes_gcm_seal_scalar_rk(ctx.ptr, nr, ctx.ptr + 240, iv.ptr, src.ptr, src.len, aad.ptr, aad.len,
                                       dst.ptr, tag_out.ptr);
}

int64_t wing_aes_gcm_open_prepared(wing_slice ctx, wing_slice iv, wing_slice src, wing_slice aad, wing_slice tag,
                                   wing_slice dst) {
    int32_t nr = 0;
    int32_t mode = 0;
    if (!wing_aes_gcm_valid_prepared_args(ctx, iv, src, aad, dst, tag, &nr, &mode)) {
        return -1;
    }
#if defined(__x86_64__) || defined(_M_X64)
    if (mode == WING_AES_GCM_MODE_AESNI) {
        __m128i h1 = _mm_loadu_si128((const __m128i *)(ctx.ptr + 240));
        __m128i h2 = _mm_loadu_si128((const __m128i *)(ctx.ptr + 256));
        __m128i h3 = _mm_loadu_si128((const __m128i *)(ctx.ptr + 272));
        __m128i h4 = _mm_loadu_si128((const __m128i *)(ctx.ptr + 288));
        return wing_aes_gcm_open_aesni_rk(ctx.ptr, nr, h1, h2, h3, h4, iv.ptr, src.ptr, src.len, aad.ptr, aad.len,
                                          tag.ptr, dst.ptr);
    }
#endif
    return wing_aes_gcm_open_scalar_rk(ctx.ptr, nr, ctx.ptr + 240, iv.ptr, src.ptr, src.len, aad.ptr, aad.len,
                                       tag.ptr, dst.ptr);
}
