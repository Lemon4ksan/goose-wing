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

#define WING_AES_GCM_MAX_PLAINTEXT 0xFFFFFFFE0LL
#define WING_AES_GCM_MAX_AAD 0x1FFFFFFFFFFFFFFFLL
#define WING_CHACHA20_POLY1305_MAX_PLAINTEXT 0x3FFFFFFFC0LL

#if (defined(__GNUC__) && __GNUC__ >= 11) || (defined(__clang__) && __clang_major__ >= 15)
#define WING_ZERO_REGS __attribute__((zero_call_used_regs("used")))
#else
#define WING_ZERO_REGS
#endif

#if defined(__GNUC__) || defined(__clang__)
#define WING_NOINLINE __attribute__((noinline))
#elif defined(_MSC_VER)
#define WING_NOINLINE __declspec(noinline)
#else
#define WING_NOINLINE
#endif

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

// Overwrites dead callee stack spills left behind by vectorized AES-GCM / ChaCha20 / Poly1305 frames.
WING_NOINLINE
static void wing_scrub_stack_1024(void) {
    volatile uint8_t scrub[1024];
    wing_fusion_zeroize(scrub, sizeof(scrub));
}

// Returns 1 if [src, src+len) and [dst, dst+len) partially overlap (exact in-place src == dst is allowed).
static inline int wing_slices_partial_overlap(const uint8_t *src, const uint8_t *dst, int64_t len) {
    if (len <= 0 || src == dst) return 0;
    uintptr_t s = (uintptr_t)src;
    uintptr_t d = (uintptr_t)dst;
    uintptr_t n = (uintptr_t)len;
    return (s < d) ? ((d - s) < n) : ((s - d) < n);
}

#if defined(__x86_64__) || defined(_M_X64)
#ifdef _MSC_VER
#include <intrin.h>
#endif
#include <immintrin.h>
#include <wmmintrin.h>

#if defined(__GNUC__) || defined(__clang__)
#define WING_TARGET_AES_PCLMUL __attribute__((target("sse2,ssse3,sse4.1,aes,pclmul")))
#else
#define WING_TARGET_AES_PCLMUL
#endif

static inline int wing_cpu_has_aes_pclmul(void) {
#if defined(__GNUC__) || defined(__clang__)
    return __builtin_cpu_supports("aes") && __builtin_cpu_supports("pclmul") && __builtin_cpu_supports("sse4.1") &&
           __builtin_cpu_supports("ssse3");
#elif defined(_MSC_VER)
    int regs[4] = {0, 0, 0, 0};
    __cpuid(regs, 1);
    const int need = (1 << 1) | (1 << 9) | (1 << 19) | (1 << 25);
    return (regs[2] & need) == need;
#else
    return 0;
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
static inline __m128i wing_gf128_mul_acc4_karatsuba_pclmul(__m128i acc, __m128i c0, __m128i c1, __m128i c2, __m128i c3,
                                                           __m128i h1, __m128i h2, __m128i h3, __m128i h4) {
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

WING_TARGET_AES_PCLMUL WING_ZERO_REGS static inline void wing_aes256_expand_key(const uint8_t *key_ptr,
                                                                                __m128i rk[15]) {
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
WING_TARGET_AES_PCLMUL WING_ZERO_REGS static int64_t
wing_aes_gcm_seal_aesni_rk(const uint8_t *rk_bytes, int nr, const __m128i h[4], const uint8_t *iv_ptr,
                           const uint8_t *src_ptr, int64_t src_len, const uint8_t *aad_ptr, int64_t aad_len,
                           uint8_t *dst_ptr, uint8_t *tag_ptr) {
    const __m128i h1 = h[0];
    const __m128i h2 = h[1];
    const __m128i h3 = h[2];
    const __m128i h4 = h[3];
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

WING_TARGET_AES_PCLMUL WING_ZERO_REGS static int64_t
wing_aes_gcm_seal_aesni(const uint8_t *key_ptr, int64_t key_len, const uint8_t *iv_ptr, const uint8_t *src_ptr,
                        int64_t src_len, const uint8_t *aad_ptr, int64_t aad_len, uint8_t *dst_ptr, uint8_t *tag_ptr) {
    __m128i rk[15];
    int nr = wing_aes_expand_key_aesni(key_ptr, key_len, rk);

    __m128i h[4];
    h[0] = wing_bswap128(wing_aes_enc_block_aesni(_mm_setzero_si128(), rk, nr));
    h[1] = (src_len >= 64) ? wing_gf128_mul_pclmul(h[0], h[0]) : h[0];
    h[2] = (src_len >= 64) ? wing_gf128_mul_pclmul(h[1], h[0]) : h[0];
    h[3] = (src_len >= 64) ? wing_gf128_mul_pclmul(h[2], h[0]) : h[0];

    int64_t ret = wing_aes_gcm_seal_aesni_rk((const uint8_t *)rk, nr, h, iv_ptr, src_ptr, src_len, aad_ptr, aad_len,
                                             dst_ptr, tag_ptr);
    wing_fusion_zeroize(h, sizeof(h));
    wing_fusion_zeroize(rk, sizeof(rk));
    return ret;
}

// Fused 4-block AES-GCM decryption + aggregated Karatsuba GHASH using pre-expanded round keys.
WING_TARGET_AES_PCLMUL WING_ZERO_REGS static int64_t
wing_aes_gcm_open_aesni_rk(const uint8_t *rk_bytes, int nr, const __m128i h[4], const uint8_t *iv_ptr,
                           const uint8_t *src_ptr, int64_t src_len, const uint8_t *aad_ptr, int64_t aad_len,
                           const uint8_t *tag_ptr, uint8_t *dst_ptr) {
    const __m128i h1 = h[0];
    const __m128i h2 = h[1];
    const __m128i h3 = h[2];
    const __m128i h4 = h[3];
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

WING_TARGET_AES_PCLMUL WING_ZERO_REGS static int64_t wing_aes_gcm_open_aesni(const uint8_t *key_ptr, int64_t key_len,
                                                                             const uint8_t *iv_ptr,
                                                                             const uint8_t *src_ptr, int64_t src_len,
                                                                             const uint8_t *aad_ptr, int64_t aad_len,
                                                                             const uint8_t *tag_ptr, uint8_t *dst_ptr) {
    __m128i rk[15];
    int nr = wing_aes_expand_key_aesni(key_ptr, key_len, rk);

    __m128i h[4];
    h[0] = wing_bswap128(wing_aes_enc_block_aesni(_mm_setzero_si128(), rk, nr));
    h[1] = (src_len >= 64) ? wing_gf128_mul_pclmul(h[0], h[0]) : h[0];
    h[2] = (src_len >= 64) ? wing_gf128_mul_pclmul(h[1], h[0]) : h[0];
    h[3] = (src_len >= 64) ? wing_gf128_mul_pclmul(h[2], h[0]) : h[0];

    int64_t ret = wing_aes_gcm_open_aesni_rk((const uint8_t *)rk, nr, h, iv_ptr, src_ptr, src_len, aad_ptr, aad_len,
                                             tag_ptr, dst_ptr);
    wing_fusion_zeroize(h, sizeof(h));
    wing_fusion_zeroize(rk, sizeof(rk));
    return ret;
}
#endif

// ---- Constant-Time Scalar Fallback (for non-AES-NI CPUs) -----------------

// Constant-time Boyar-Peralta (2010) bitsliced AES S-box over up to 32 bytes in parallel
// (bp[0] = MSB bit 7, bp[7] = LSB bit 0; zero lookup tables, zero secret-dependent branches).
static inline void wing_aes_sbox_bitslice(uint32_t bp[8]) {
    uint32_t x0 = bp[0], x1 = bp[1], x2 = bp[2], x3 = bp[3];
    uint32_t x4 = bp[4], x5 = bp[5], x6 = bp[6], x7 = bp[7];
    uint32_t y14 = x3 ^ x5, y13 = x0 ^ x6, y9 = x0 ^ x3, y8 = x0 ^ x5;
    uint32_t t0 = x1 ^ x2, y1 = t0 ^ x7, y4 = y1 ^ x3, y12 = y13 ^ y14;
    uint32_t y2 = y1 ^ x0, y5 = y1 ^ x6, y3 = y5 ^ y8, t1 = x4 ^ y12;
    uint32_t y15 = t1 ^ x5, y20 = t1 ^ x1, y6 = y15 ^ x7, y10 = y15 ^ t0;
    uint32_t y11 = y20 ^ y9, y7 = x7 ^ y11, y17 = y10 ^ y11, y19 = y10 ^ y8;
    uint32_t y16 = t0 ^ y11, y21 = y13 ^ y16, y18 = x0 ^ y16;
    uint32_t t2 = y12 & y15, t4 = (y3 & y6) ^ t2, t6 = (y4 & x7) ^ t2;
    uint32_t t7 = y13 & y16, t9 = (y5 & y1) ^ t7, t11 = (y2 & y7) ^ t7;
    uint32_t t12 = y9 & y11, t14 = (y14 & y17) ^ t12, t16 = (y8 & y10) ^ t12;
    uint32_t t21 = (t4 ^ t14) ^ y20, t22 = (t6 ^ t16) ^ y19;
    uint32_t t23 = (t9 ^ t14) ^ y21, t24 = (t11 ^ t16) ^ y18;
    uint32_t t25 = t21 ^ t22, t26 = t21 & t23, t27 = t24 ^ t26;
    uint32_t t28 = t25 & t27, t29 = t28 ^ t22, t30 = t23 ^ t24;
    uint32_t t31 = t22 ^ t26, t32 = t31 & t30, t33 = t32 ^ t24;
    uint32_t t34 = t23 ^ t33, t35 = t27 ^ t33, t36 = t24 & t35;
    uint32_t t37 = t36 ^ t34, t38 = t27 ^ t36, t39 = t29 & t38, t40 = t25 ^ t39;
    uint32_t t41 = t40 ^ t37, t42 = t29 ^ t33, t43 = t29 ^ t40, t44 = t33 ^ t37, t45 = t42 ^ t41;
    uint32_t z0 = t44 & y15, z1 = t37 & y6, z2 = t33 & x7, z3 = t43 & y16;
    uint32_t z4 = t40 & y1, z5 = t29 & y7, z6 = t42 & y11, z7 = t45 & y17;
    uint32_t z8 = t41 & y10, z9 = t44 & y12, z10 = t37 & y3, z11 = t33 & y4;
    uint32_t z12 = t43 & y13, z13 = t40 & y5, z14 = t29 & y2, z15 = t42 & y9;
    uint32_t z16 = t45 & y14, z17 = t41 & y8;
    uint32_t t46 = z15 ^ z16, t47 = z10 ^ z11, t48 = z5 ^ z13, t49 = z9 ^ z10;
    uint32_t t50 = z2 ^ z12, t51 = z2 ^ z5, t52 = z7 ^ z8, t53 = z0 ^ z3;
    uint32_t t54 = z6 ^ z7, t55 = z16 ^ z17, t56 = z12 ^ t48, t57 = t50 ^ t53;
    uint32_t t58 = z4 ^ t46, t59 = z3 ^ t54, t60 = t46 ^ t57, t61 = z14 ^ t57;
    uint32_t t62 = t52 ^ t58, t63 = t49 ^ t58, t64 = z4 ^ t59, t65 = t61 ^ t62;
    uint32_t t66 = z1 ^ t63, t67 = t64 ^ t65, s3 = t53 ^ t66;
    bp[0] = t59 ^ t63;
    bp[1] = t64 ^ (~s3);
    bp[2] = t55 ^ (~t67);
    bp[3] = s3;
    bp[4] = t51 ^ t66;
    bp[5] = t47 ^ t65;
    bp[6] = t56 ^ (~t62);
    bp[7] = t48 ^ (~t60);
}

static inline void wing_aes_sub_bytes_ct(uint8_t *buf, int count) {
    uint32_t bp[8] = {0, 0, 0, 0, 0, 0, 0, 0};
    for (int i = 0; i < count; i++) {
        uint32_t b = (uint32_t)buf[i];
        bp[0] |= ((b >> 7) & 1u) << i;
        bp[1] |= ((b >> 6) & 1u) << i;
        bp[2] |= ((b >> 5) & 1u) << i;
        bp[3] |= ((b >> 4) & 1u) << i;
        bp[4] |= ((b >> 3) & 1u) << i;
        bp[5] |= ((b >> 2) & 1u) << i;
        bp[6] |= ((b >> 1) & 1u) << i;
        bp[7] |= (b & 1u) << i;
    }
    wing_aes_sbox_bitslice(bp);
    for (int i = 0; i < count; i++) {
        uint32_t b = (((bp[0] >> i) & 1u) << 7) | (((bp[1] >> i) & 1u) << 6) | (((bp[2] >> i) & 1u) << 5) |
                     (((bp[3] >> i) & 1u) << 4) | (((bp[4] >> i) & 1u) << 3) | (((bp[5] >> i) & 1u) << 2) |
                     (((bp[6] >> i) & 1u) << 1) | ((bp[7] >> i) & 1u);
        buf[i] = (uint8_t)b;
    }
    wing_fusion_zeroize(bp, sizeof(bp));
}

static inline uint8_t wing_gf_xtime(uint8_t x) {
    uint8_t mask = (uint8_t)(0u - (uint8_t)(x >> 7));
    return (uint8_t)((x << 1) ^ (mask & 0x1bu));
}

static int wing_aes_scalar_expand(const uint8_t *key, int64_t key_len, uint8_t rk[240]) {
    static const uint8_t rcon[10] = {0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36};
    unsigned int nk = (key_len == 32) ? 8u : 4u;
    unsigned int nk_shift = (nk == 8u) ? 3u : 2u;
    unsigned int words = (nk == 8u) ? 60u : 44u;
    uint8_t t[4] = {0, 0, 0, 0};
    memcpy(rk, key, (size_t)key_len);
    for (unsigned int i = nk; i < words; i++) {
        memcpy(t, &rk[(i - 1u) * 4u], 4);
        if ((i & (nk - 1u)) == 0u) {
            uint8_t tmp = t[0];
            t[0] = t[1];
            t[1] = t[2];
            t[2] = t[3];
            t[3] = tmp;
            wing_aes_sub_bytes_ct(t, 4);
            t[0] ^= rcon[(i >> nk_shift) - 1u];
            wing_fusion_zeroize(&tmp, sizeof(tmp));
        } else if (nk == 8u && (i & 7u) == 4u) {
            wing_aes_sub_bytes_ct(t, 4);
        }
        for (unsigned int j = 0; j < 4u; j++) {
            rk[i * 4u + j] = rk[(i - nk) * 4u + j] ^ t[j];
        }
    }
    wing_fusion_zeroize(t, sizeof(t));
    return (nk == 8u) ? 14 : 10;
}

static void wing_aes_scalar_enc(const uint8_t rk[240], int nr, const uint8_t in[16], uint8_t out[16]) {
    uint8_t s[16];
    uint8_t t[16];
    uint8_t sr[16];
    for (int i = 0; i < 16; i++) {
        s[i] = in[i] ^ rk[i];
    }
    for (int r = 1; r <= nr; r++) {
        memcpy(t, s, 16);
        wing_aes_sub_bytes_ct(t, 16);
        sr[0] = t[0];
        sr[1] = t[5];
        sr[2] = t[10];
        sr[3] = t[15];
        sr[4] = t[4];
        sr[5] = t[9];
        sr[6] = t[14];
        sr[7] = t[3];
        sr[8] = t[8];
        sr[9] = t[13];
        sr[10] = t[2];
        sr[11] = t[7];
        sr[12] = t[12];
        sr[13] = t[1];
        sr[14] = t[6];
        sr[15] = t[11];
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
        for (int i = 0; i < 16; i++) {
            s[i] ^= rk[r * 16 + i];
        }
    }
    memcpy(out, s, 16);
    wing_fusion_zeroize(s, sizeof(s));
    wing_fusion_zeroize(t, sizeof(t));
    wing_fusion_zeroize(sr, sizeof(sr));
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

    int64_t ret =
        wing_aes_gcm_seal_scalar_rk(rk, nr, h_blk, iv_ptr, src_ptr, src_len, aad_ptr, aad_len, dst_ptr, tag_ptr);
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

    int64_t ret =
        wing_aes_gcm_open_scalar_rk(rk, nr, h_blk, iv_ptr, src_ptr, src_len, aad_ptr, aad_len, tag_ptr, dst_ptr);
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
    *a += *b;
    *d = wing_rotl32(*d ^ *a, 16);
    *c += *d;
    *b = wing_rotl32(*b ^ *c, 12);
    *a += *b;
    *d = wing_rotl32(*d ^ *a, 8);
    *c += *d;
    *b = wing_rotl32(*b ^ *c, 7);
}

static void wing_chacha20_block_scalar(const uint32_t state[16], uint8_t out[64]) {
    uint32_t x[16];
    memcpy(x, state, 64);
    for (int i = 0; i < 10; i++) {
        wing_chacha_qr(&x[0], &x[4], &x[8], &x[12]);
        wing_chacha_qr(&x[1], &x[5], &x[9], &x[13]);
        wing_chacha_qr(&x[2], &x[6], &x[10], &x[14]);
        wing_chacha_qr(&x[3], &x[7], &x[11], &x[15]);
        wing_chacha_qr(&x[0], &x[5], &x[10], &x[15]);
        wing_chacha_qr(&x[1], &x[6], &x[11], &x[12]);
        wing_chacha_qr(&x[2], &x[7], &x[8], &x[13]);
        wing_chacha_qr(&x[3], &x[4], &x[9], &x[14]);
    }
    for (int i = 0; i < 16; i++) {
        wing_store32_le(out + i * 4, x[i] + state[i]);
    }
    wing_fusion_zeroize(x, sizeof(x));
}

#if defined(__x86_64__) || defined(_M_X64)

#if defined(__GNUC__) || defined(__clang__)
#define WING_TARGET_SSSE3 __attribute__((target("sse2,ssse3")))
static inline int wing_cpu_has_ssse3(void) { return __builtin_cpu_supports("ssse3"); }
#elif defined(_MSC_VER)
#define WING_TARGET_SSSE3
static inline int wing_cpu_has_ssse3(void) {
    int regs[4] = {0, 0, 0, 0};
    __cpuid(regs, 1);
    return (regs[2] & (1 << 9)) != 0;
}
#else
#define WING_TARGET_SSSE3
static inline int wing_cpu_has_ssse3(void) { return 0; }
#endif

#define WING_SSE_ROTL16(v) _mm_shuffle_epi8((v), rot16_mask)
#define WING_SSE_ROTL8(v) _mm_shuffle_epi8((v), rot8_mask)
#define WING_SSE_ROTL12(v) _mm_or_si128(_mm_slli_epi32((v), 12), _mm_srli_epi32((v), 20))
#define WING_SSE_ROTL7(v) _mm_or_si128(_mm_slli_epi32((v), 7), _mm_srli_epi32((v), 25))

#define WING_SSE_QR(a, b, c, d)                                                                                        \
    do {                                                                                                               \
        (a) = _mm_add_epi32((a), (b));                                                                                 \
        (d) = WING_SSE_ROTL16(_mm_xor_si128((d), (a)));                                                                \
        (c) = _mm_add_epi32((c), (d));                                                                                 \
        (b) = WING_SSE_ROTL12(_mm_xor_si128((b), (c)));                                                                \
        (a) = _mm_add_epi32((a), (b));                                                                                 \
        (d) = WING_SSE_ROTL8(_mm_xor_si128((d), (a)));                                                                 \
        (c) = _mm_add_epi32((c), (d));                                                                                 \
        (b) = WING_SSE_ROTL7(_mm_xor_si128((b), (c)));                                                                 \
    } while (0)

WING_TARGET_SSSE3 WING_ZERO_REGS static void wing_chacha20_block_ssse3(const uint32_t state[16], uint8_t out[64]) {
    const __m128i rot16_mask = _mm_set_epi8(13, 12, 15, 14, 9, 8, 11, 10, 5, 4, 7, 6, 1, 0, 3, 2);
    const __m128i rot8_mask = _mm_set_epi8(14, 13, 12, 15, 10, 9, 8, 11, 6, 5, 4, 7, 2, 1, 0, 3);
    __m128i s0 = _mm_loadu_si128((const __m128i *)(state + 0));
    __m128i s1 = _mm_loadu_si128((const __m128i *)(state + 4));
    __m128i s2 = _mm_loadu_si128((const __m128i *)(state + 8));
    __m128i s3 = _mm_loadu_si128((const __m128i *)(state + 12));
    __m128i r0 = s0, r1 = s1, r2 = s2, r3 = s3;
    for (int i = 0; i < 10; i++) {
        WING_SSE_QR(r0, r1, r2, r3);
        r1 = _mm_shuffle_epi32(r1, _MM_SHUFFLE(0, 3, 2, 1));
        r2 = _mm_shuffle_epi32(r2, _MM_SHUFFLE(1, 0, 3, 2));
        r3 = _mm_shuffle_epi32(r3, _MM_SHUFFLE(2, 1, 0, 3));
        WING_SSE_QR(r0, r1, r2, r3);
        r1 = _mm_shuffle_epi32(r1, _MM_SHUFFLE(2, 1, 0, 3));
        r2 = _mm_shuffle_epi32(r2, _MM_SHUFFLE(1, 0, 3, 2));
        r3 = _mm_shuffle_epi32(r3, _MM_SHUFFLE(0, 3, 2, 1));
    }
    _mm_storeu_si128((__m128i *)(out + 0), _mm_add_epi32(r0, s0));
    _mm_storeu_si128((__m128i *)(out + 16), _mm_add_epi32(r1, s1));
    _mm_storeu_si128((__m128i *)(out + 32), _mm_add_epi32(r2, s2));
    _mm_storeu_si128((__m128i *)(out + 48), _mm_add_epi32(r3, s3));
}

WING_TARGET_SSSE3
static inline void wing_sse_xor_4rows(__m128i r0, __m128i r1, __m128i r2, __m128i r3, const uint8_t *src, uint8_t *dst,
                                      int row_off) {
    __m128i t0 = _mm_unpacklo_epi32(r0, r1);
    __m128i t1 = _mm_unpackhi_epi32(r0, r1);
    __m128i t2 = _mm_unpacklo_epi32(r2, r3);
    __m128i t3 = _mm_unpackhi_epi32(r2, r3);

    __m128i u0 = _mm_unpacklo_epi64(t0, t2);
    __m128i u1 = _mm_unpackhi_epi64(t0, t2);
    __m128i u2 = _mm_unpacklo_epi64(t1, t3);
    __m128i u3 = _mm_unpackhi_epi64(t1, t3);

    _mm_storeu_si128((__m128i *)(dst + 0 * 64 + row_off),
                     _mm_xor_si128(_mm_loadu_si128((const __m128i *)(src + 0 * 64 + row_off)), u0));
    _mm_storeu_si128((__m128i *)(dst + 1 * 64 + row_off),
                     _mm_xor_si128(_mm_loadu_si128((const __m128i *)(src + 1 * 64 + row_off)), u1));
    _mm_storeu_si128((__m128i *)(dst + 2 * 64 + row_off),
                     _mm_xor_si128(_mm_loadu_si128((const __m128i *)(src + 2 * 64 + row_off)), u2));
    _mm_storeu_si128((__m128i *)(dst + 3 * 64 + row_off),
                     _mm_xor_si128(_mm_loadu_si128((const __m128i *)(src + 3 * 64 + row_off)), u3));
}

WING_TARGET_SSSE3 WING_ZERO_REGS static int64_t wing_chacha20_xor_ssse3(uint32_t init_state[16], const uint8_t *src,
                                                                        uint8_t *dst, int64_t len) {
    const __m128i rot16_mask = _mm_set_epi8(13, 12, 15, 14, 9, 8, 11, 10, 5, 4, 7, 6, 1, 0, 3, 2);
    const __m128i rot8_mask = _mm_set_epi8(14, 13, 12, 15, 10, 9, 8, 11, 6, 5, 4, 7, 2, 1, 0, 3);
    const __m128i ctr_offsets = _mm_setr_epi32(0, 1, 2, 3);

    int64_t off = 0;
    while (off + 256 <= len) {
        __m128i x0 = _mm_set1_epi32((int)init_state[0]);
        __m128i x1 = _mm_set1_epi32((int)init_state[1]);
        __m128i x2 = _mm_set1_epi32((int)init_state[2]);
        __m128i x3 = _mm_set1_epi32((int)init_state[3]);
        __m128i x4 = _mm_set1_epi32((int)init_state[4]);
        __m128i x5 = _mm_set1_epi32((int)init_state[5]);
        __m128i x6 = _mm_set1_epi32((int)init_state[6]);
        __m128i x7 = _mm_set1_epi32((int)init_state[7]);
        __m128i x8 = _mm_set1_epi32((int)init_state[8]);
        __m128i x9 = _mm_set1_epi32((int)init_state[9]);
        __m128i x10 = _mm_set1_epi32((int)init_state[10]);
        __m128i x11 = _mm_set1_epi32((int)init_state[11]);
        __m128i x12 = _mm_add_epi32(_mm_set1_epi32((int)init_state[12]), ctr_offsets);
        __m128i x13 = _mm_set1_epi32((int)init_state[13]);
        __m128i x14 = _mm_set1_epi32((int)init_state[14]);
        __m128i x15 = _mm_set1_epi32((int)init_state[15]);

        for (int r = 0; r < 10; r++) {
            WING_SSE_QR(x0, x4, x8, x12);
            WING_SSE_QR(x1, x5, x9, x13);
            WING_SSE_QR(x2, x6, x10, x14);
            WING_SSE_QR(x3, x7, x11, x15);
            WING_SSE_QR(x0, x5, x10, x15);
            WING_SSE_QR(x1, x6, x11, x12);
            WING_SSE_QR(x2, x7, x8, x13);
            WING_SSE_QR(x3, x4, x9, x14);
        }

        wing_sse_xor_4rows(_mm_add_epi32(x0, _mm_set1_epi32((int)init_state[0])),
                           _mm_add_epi32(x1, _mm_set1_epi32((int)init_state[1])),
                           _mm_add_epi32(x2, _mm_set1_epi32((int)init_state[2])),
                           _mm_add_epi32(x3, _mm_set1_epi32((int)init_state[3])), src + off, dst + off, 0);
        wing_sse_xor_4rows(_mm_add_epi32(x4, _mm_set1_epi32((int)init_state[4])),
                           _mm_add_epi32(x5, _mm_set1_epi32((int)init_state[5])),
                           _mm_add_epi32(x6, _mm_set1_epi32((int)init_state[6])),
                           _mm_add_epi32(x7, _mm_set1_epi32((int)init_state[7])), src + off, dst + off, 16);
        wing_sse_xor_4rows(_mm_add_epi32(x8, _mm_set1_epi32((int)init_state[8])),
                           _mm_add_epi32(x9, _mm_set1_epi32((int)init_state[9])),
                           _mm_add_epi32(x10, _mm_set1_epi32((int)init_state[10])),
                           _mm_add_epi32(x11, _mm_set1_epi32((int)init_state[11])), src + off, dst + off, 32);
        wing_sse_xor_4rows(_mm_add_epi32(x12, _mm_add_epi32(_mm_set1_epi32((int)init_state[12]), ctr_offsets)),
                           _mm_add_epi32(x13, _mm_set1_epi32((int)init_state[13])),
                           _mm_add_epi32(x14, _mm_set1_epi32((int)init_state[14])),
                           _mm_add_epi32(x15, _mm_set1_epi32((int)init_state[15])), src + off, dst + off, 48);

        init_state[12] += 4u;
        off += 256;
    }

    const __m128i one_ctr = _mm_setr_epi32(1, 0, 0, 0);
    if (off + 64 <= len) {
        const __m128i s0 = _mm_loadu_si128((const __m128i *)(init_state + 0));
        const __m128i s1 = _mm_loadu_si128((const __m128i *)(init_state + 4));
        const __m128i s2 = _mm_loadu_si128((const __m128i *)(init_state + 8));
        __m128i s3 = _mm_loadu_si128((const __m128i *)(init_state + 12));
        while (off + 64 <= len) {
            __m128i r0 = s0, r1 = s1, r2 = s2, r3 = s3;
            for (int i = 0; i < 10; i++) {
                WING_SSE_QR(r0, r1, r2, r3);
                r1 = _mm_shuffle_epi32(r1, _MM_SHUFFLE(0, 3, 2, 1));
                r2 = _mm_shuffle_epi32(r2, _MM_SHUFFLE(1, 0, 3, 2));
                r3 = _mm_shuffle_epi32(r3, _MM_SHUFFLE(2, 1, 0, 3));
                WING_SSE_QR(r0, r1, r2, r3);
                r1 = _mm_shuffle_epi32(r1, _MM_SHUFFLE(2, 1, 0, 3));
                r2 = _mm_shuffle_epi32(r2, _MM_SHUFFLE(1, 0, 3, 2));
                r3 = _mm_shuffle_epi32(r3, _MM_SHUFFLE(0, 3, 2, 1));
            }
            _mm_storeu_si128((__m128i *)(dst + off + 0),
                             _mm_xor_si128(_mm_loadu_si128((const __m128i *)(src + off + 0)), _mm_add_epi32(r0, s0)));
            _mm_storeu_si128((__m128i *)(dst + off + 16),
                             _mm_xor_si128(_mm_loadu_si128((const __m128i *)(src + off + 16)), _mm_add_epi32(r1, s1)));
            _mm_storeu_si128((__m128i *)(dst + off + 32),
                             _mm_xor_si128(_mm_loadu_si128((const __m128i *)(src + off + 32)), _mm_add_epi32(r2, s2)));
            _mm_storeu_si128((__m128i *)(dst + off + 48),
                             _mm_xor_si128(_mm_loadu_si128((const __m128i *)(src + off + 48)), _mm_add_epi32(r3, s3)));
            s3 = _mm_add_epi32(s3, one_ctr);
            init_state[12] += 1u;
            off += 64;
        }
    }
    return off;
}
#endif

#if (defined(__x86_64__) || defined(_M_X64)) && defined(__GNUC__) && !(defined(__MINGW32__) && !defined(__clang__))

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
static inline void wing_avx2_xor_4rows(__m256i r0, __m256i r1, __m256i r2, __m256i r3, const uint8_t *src, uint8_t *dst,
                                       int row_off) {
    __m256i t0 = _mm256_unpacklo_epi32(r0, r1);
    __m256i t1 = _mm256_unpackhi_epi32(r0, r1);
    __m256i t2 = _mm256_unpacklo_epi32(r2, r3);
    __m256i t3 = _mm256_unpackhi_epi32(r2, r3);

    __m256i u0 = _mm256_unpacklo_epi64(t0, t2);
    __m256i u1 = _mm256_unpackhi_epi64(t0, t2);
    __m256i u2 = _mm256_unpacklo_epi64(t1, t3);
    __m256i u3 = _mm256_unpackhi_epi64(t1, t3);

    _mm_storeu_si128(
        (__m128i *)(dst + 0 * 64 + row_off),
        _mm_xor_si128(_mm_loadu_si128((const __m128i *)(src + 0 * 64 + row_off)), _mm256_castsi256_si128(u0)));
    _mm_storeu_si128(
        (__m128i *)(dst + 1 * 64 + row_off),
        _mm_xor_si128(_mm_loadu_si128((const __m128i *)(src + 1 * 64 + row_off)), _mm256_castsi256_si128(u1)));
    _mm_storeu_si128(
        (__m128i *)(dst + 2 * 64 + row_off),
        _mm_xor_si128(_mm_loadu_si128((const __m128i *)(src + 2 * 64 + row_off)), _mm256_castsi256_si128(u2)));
    _mm_storeu_si128(
        (__m128i *)(dst + 3 * 64 + row_off),
        _mm_xor_si128(_mm_loadu_si128((const __m128i *)(src + 3 * 64 + row_off)), _mm256_castsi256_si128(u3)));

    _mm_storeu_si128(
        (__m128i *)(dst + 4 * 64 + row_off),
        _mm_xor_si128(_mm_loadu_si128((const __m128i *)(src + 4 * 64 + row_off)), _mm256_extracti128_si256(u0, 1)));
    _mm_storeu_si128(
        (__m128i *)(dst + 5 * 64 + row_off),
        _mm_xor_si128(_mm_loadu_si128((const __m128i *)(src + 5 * 64 + row_off)), _mm256_extracti128_si256(u1, 1)));
    _mm_storeu_si128(
        (__m128i *)(dst + 6 * 64 + row_off),
        _mm_xor_si128(_mm_loadu_si128((const __m128i *)(src + 6 * 64 + row_off)), _mm256_extracti128_si256(u2, 1)));
    _mm_storeu_si128(
        (__m128i *)(dst + 7 * 64 + row_off),
        _mm_xor_si128(_mm_loadu_si128((const __m128i *)(src + 7 * 64 + row_off)), _mm256_extracti128_si256(u3, 1)));
}

WING_TARGET_AVX2 WING_ZERO_REGS static void wing_chacha20_xor_avx2(uint32_t init_state[16], const uint8_t *src,
                                                                   uint8_t *dst, int64_t len) {
    const __m256i rot16_mask = _mm256_set_epi8(13, 12, 15, 14, 9, 8, 11, 10, 5, 4, 7, 6, 1, 0, 3, 2, 13, 12, 15, 14, 9,
                                               8, 11, 10, 5, 4, 7, 6, 1, 0, 3, 2);
    const __m256i rot8_mask = _mm256_set_epi8(14, 13, 12, 15, 10, 9, 8, 11, 6, 5, 4, 7, 2, 1, 0, 3, 14, 13, 12, 15, 10,
                                              9, 8, 11, 6, 5, 4, 7, 2, 1, 0, 3);
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

static inline void wing_chacha20_block_fast(const uint32_t state[16], uint8_t out[64]) {
#if defined(__x86_64__) || defined(_M_X64)
    if (wing_cpu_has_ssse3()) {
        wing_chacha20_block_ssse3(state, out);
        return;
    }
#endif
    wing_chacha20_block_scalar(state, out);
}

static inline void wing_xor_bytes_fast(uint8_t *dst, const uint8_t *src, const uint8_t *ks, int64_t take) {
    int64_t i = 0;
    for (; i + 8 <= take; i += 8) {
        uint64_t a = wing_load64_le(src + i);
        uint64_t b = wing_load64_le(ks + i);
        wing_store64_le(dst + i, a ^ b);
    }
    for (; i < take; i++) {
        dst[i] = src[i] ^ ks[i];
    }
}

static void wing_chacha20_xor_state(uint32_t st[16], const uint8_t *src, uint8_t *dst, int64_t len) {
#if (defined(__x86_64__) || defined(_M_X64)) && defined(__GNUC__) && !(defined(__MINGW32__) && !defined(__clang__))
    if (len >= 512 && wing_cpu_has_avx2()) {
        wing_chacha20_xor_avx2(st, src, dst, len);
        return;
    }
#endif

    int64_t off = 0;
#if defined(__x86_64__) || defined(_M_X64)
    if (len >= 64 && wing_cpu_has_ssse3()) {
        off = wing_chacha20_xor_ssse3(st, src, dst, len);
    }
#endif

    while (off < len) {
        uint8_t ks[64];
        wing_chacha20_block_fast(st, ks);
        st[12] += 1u;
        int64_t take = (len - off >= 64) ? 64 : (len - off);
        wing_xor_bytes_fast(dst + off, src + off, ks, take);
        wing_fusion_zeroize(ks, sizeof(ks));
        off += take;
    }
}

typedef struct {
    uint64_t r0, r1, r2;
    uint64_t s1, s2;
    uint64_t r2_0, r2_1, r2_2;
    uint64_t s2_1, s2_2;
    uint64_t h0, h1, h2;
    uint64_t pad0, pad1;
    int has_r2;
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
    st->has_r2 = 0;
}

#ifdef __SIZEOF_INT128__
static inline void wing_poly1305_ensure_r2(wing_poly1305_state *st) {
    if (st->has_r2) return;
    const uint64_t r0 = st->r0, r1 = st->r1, r2 = st->r2;
    const uint64_t s1 = st->s1, s2 = st->s2;
    __uint128_t d0 = ((__uint128_t)r0 * r0) + ((__uint128_t)r1 * s2) + ((__uint128_t)r2 * s1);
    __uint128_t d1 = ((__uint128_t)r0 * r1) + ((__uint128_t)r1 * r0) + ((__uint128_t)r2 * s2);
    __uint128_t d2 = ((__uint128_t)r0 * r2) + ((__uint128_t)r1 * r1) + ((__uint128_t)r2 * r0);
    uint64_t c = (uint64_t)(d0 >> 44);
    uint64_t q0 = (uint64_t)d0 & 0x0fffffffffffULL;
    d1 += c;
    c = (uint64_t)(d1 >> 44);
    uint64_t q1 = (uint64_t)d1 & 0x0fffffffffffULL;
    d2 += c;
    c = (uint64_t)(d2 >> 42);
    uint64_t q2 = (uint64_t)d2 & 0x03ffffffffffULL;
    q0 += c * 5u;
    c = q0 >> 44;
    q0 &= 0x0fffffffffffULL;
    q1 += c;
    st->r2_0 = q0;
    st->r2_1 = q1;
    st->r2_2 = q2;
    st->s2_1 = q1 * 20u;
    st->s2_2 = q2 * 20u;
    st->has_r2 = 1;
}

WING_ZERO_REGS
static void wing_poly1305_blocks(wing_poly1305_state *st, const uint8_t *m, int64_t len, uint64_t hibit_40) {
    uint64_t h0 = st->h0, h1 = st->h1, h2 = st->h2;
    const uint64_t r0 = st->r0, r1 = st->r1, r2 = st->r2;
    const uint64_t s1 = st->s1, s2 = st->s2;

    if (len >= 32) {
        wing_poly1305_ensure_r2(st);
        const uint64_t r2_0 = st->r2_0, r2_1 = st->r2_1, r2_2 = st->r2_2;
        const uint64_t s2_1 = st->s2_1, s2_2 = st->s2_2;

        while (len >= 32) {
            uint64_t t0 = wing_load64_le(m + 0);
            uint64_t t1 = wing_load64_le(m + 8);
            uint64_t t2 = wing_load64_le(m + 16);
            uint64_t t3 = wing_load64_le(m + 24);

            h0 += t0 & 0x0fffffffffffULL;
            h1 += ((t0 >> 44) | (t1 << 20)) & 0x0fffffffffffULL;
            h2 += (t1 >> 24) | hibit_40;

            uint64_t m1_0 = t2 & 0x0fffffffffffULL;
            uint64_t m1_1 = ((t2 >> 44) | (t3 << 20)) & 0x0fffffffffffULL;
            uint64_t m1_2 = (t3 >> 24) | hibit_40;

            __uint128_t d0 = ((__uint128_t)h0 * r2_0) + ((__uint128_t)h1 * s2_2) + ((__uint128_t)h2 * s2_1) +
                             ((__uint128_t)m1_0 * r0) + ((__uint128_t)m1_1 * s2) + ((__uint128_t)m1_2 * s1);
            __uint128_t d1 = ((__uint128_t)h0 * r2_1) + ((__uint128_t)h1 * r2_0) + ((__uint128_t)h2 * s2_2) +
                             ((__uint128_t)m1_0 * r1) + ((__uint128_t)m1_1 * r0) + ((__uint128_t)m1_2 * s2);
            __uint128_t d2 = ((__uint128_t)h0 * r2_2) + ((__uint128_t)h1 * r2_1) + ((__uint128_t)h2 * r2_0) +
                             ((__uint128_t)m1_0 * r2) + ((__uint128_t)m1_1 * r1) + ((__uint128_t)m1_2 * r0);

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

            m += 32;
            len -= 32;
        }
    }

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

WING_ZERO_REGS
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

int64_t wing_chacha_poly_seal_aead(wing_slice key, wing_slice iv, wing_slice src, wing_slice aad, wing_slice dst,
                                   wing_slice tag_out) {
    if (key.len != 32 || iv.len != 12 || tag_out.len != 16 || src.len < 0 || aad.len < 0 ||
        src.len > WING_CHACHA20_POLY1305_MAX_PLAINTEXT || dst.len < src.len || key.ptr == NULL || iv.ptr == NULL ||
        tag_out.ptr == NULL) {
        return -1;
    }
    if (src.len > 0 && (src.ptr == NULL || dst.ptr == NULL || wing_slices_partial_overlap(src.ptr, dst.ptr, src.len))) {
        return -1;
    }
    if (aad.len > 0 && aad.ptr == NULL) {
        return -1;
    }

    uint32_t st0[16] = {
        0x61707865u,
        0x3320646eu,
        0x79622d32u,
        0x6b206574u,
        wing_load32_le(key.ptr + 0),
        wing_load32_le(key.ptr + 4),
        wing_load32_le(key.ptr + 8),
        wing_load32_le(key.ptr + 12),
        wing_load32_le(key.ptr + 16),
        wing_load32_le(key.ptr + 20),
        wing_load32_le(key.ptr + 24),
        wing_load32_le(key.ptr + 28),
        0u,
        wing_load32_le(iv.ptr + 0),
        wing_load32_le(iv.ptr + 4),
        wing_load32_le(iv.ptr + 8),
    };
    uint8_t otk_block[64];
    wing_chacha20_block_fast(st0, otk_block);

    if (src.len > 0) {
        st0[12] = 1u;
        wing_chacha20_xor_state(st0, src.ptr, dst.ptr, src.len);
    }
    wing_fusion_zeroize(st0, sizeof(st0));

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
    wing_scrub_stack_1024();
    return src.len;
}

int64_t wing_chacha_poly_open_aead(wing_slice key, wing_slice iv, wing_slice src, wing_slice aad, wing_slice tag,
                                   wing_slice dst) {
    if (key.len != 32 || iv.len != 12 || tag.len != 16 || src.len < 0 || aad.len < 0 ||
        src.len > WING_CHACHA20_POLY1305_MAX_PLAINTEXT || dst.len < src.len || key.ptr == NULL || iv.ptr == NULL ||
        tag.ptr == NULL) {
        return -1;
    }
    if (src.len > 0 && (src.ptr == NULL || dst.ptr == NULL || wing_slices_partial_overlap(src.ptr, dst.ptr, src.len))) {
        return -1;
    }
    if (aad.len > 0 && aad.ptr == NULL) {
        return -1;
    }

    uint32_t st0[16] = {
        0x61707865u,
        0x3320646eu,
        0x79622d32u,
        0x6b206574u,
        wing_load32_le(key.ptr + 0),
        wing_load32_le(key.ptr + 4),
        wing_load32_le(key.ptr + 8),
        wing_load32_le(key.ptr + 12),
        wing_load32_le(key.ptr + 16),
        wing_load32_le(key.ptr + 20),
        wing_load32_le(key.ptr + 24),
        wing_load32_le(key.ptr + 28),
        0u,
        wing_load32_le(iv.ptr + 0),
        wing_load32_le(iv.ptr + 4),
        wing_load32_le(iv.ptr + 8),
    };
    uint8_t otk_block[64];
    wing_chacha20_block_fast(st0, otk_block);

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
        wing_fusion_zeroize(st0, sizeof(st0));
        if (src.len > 0) {
            wing_fusion_zeroize(dst.ptr, (size_t)src.len);
        }
        wing_scrub_stack_1024();
        return -1;
    }

    if (src.len > 0) {
        st0[12] = 1u;
        wing_chacha20_xor_state(st0, src.ptr, dst.ptr, src.len);
    }
    wing_fusion_zeroize(st0, sizeof(st0));
    wing_scrub_stack_1024();
    return src.len;
}

int64_t wing_aes_gcm_seal_aead(wing_slice key, wing_slice iv, wing_slice src, wing_slice aad, wing_slice dst,
                               wing_slice tag_out) {
    if ((key.len != 16 && key.len != 32) || iv.len != 12 || tag_out.len != 16 || src.len < 0 || aad.len < 0 ||
        src.len > WING_AES_GCM_MAX_PLAINTEXT || aad.len > WING_AES_GCM_MAX_AAD || dst.len < src.len ||
        key.ptr == NULL || iv.ptr == NULL || tag_out.ptr == NULL) {
        return -1;
    }
    if (src.len > 0 && (src.ptr == NULL || dst.ptr == NULL || wing_slices_partial_overlap(src.ptr, dst.ptr, src.len))) {
        return -1;
    }
    if (aad.len > 0 && aad.ptr == NULL) {
        return -1;
    }
    int64_t ret = -1;
#if defined(__x86_64__) || defined(_M_X64)
    if (wing_cpu_has_aes_pclmul()) {
        ret =
            wing_aes_gcm_seal_aesni(key.ptr, key.len, iv.ptr, src.ptr, src.len, aad.ptr, aad.len, dst.ptr, tag_out.ptr);
        wing_scrub_stack_1024();
        return ret;
    }
#endif
    ret = wing_aes_gcm_seal_scalar(key.ptr, key.len, iv.ptr, src.ptr, src.len, aad.ptr, aad.len, dst.ptr, tag_out.ptr);
    wing_scrub_stack_1024();
    return ret;
}

int64_t wing_aes_gcm_open_aead(wing_slice key, wing_slice iv, wing_slice src, wing_slice aad, wing_slice tag,
                               wing_slice dst) {
    if ((key.len != 16 && key.len != 32) || iv.len != 12 || tag.len != 16 || src.len < 0 || aad.len < 0 ||
        src.len > WING_AES_GCM_MAX_PLAINTEXT || aad.len > WING_AES_GCM_MAX_AAD || dst.len < src.len ||
        key.ptr == NULL || iv.ptr == NULL || tag.ptr == NULL) {
        return -1;
    }
    if (src.len > 0 && (src.ptr == NULL || dst.ptr == NULL || wing_slices_partial_overlap(src.ptr, dst.ptr, src.len))) {
        return -1;
    }
    if (aad.len > 0 && aad.ptr == NULL) {
        return -1;
    }
    int64_t ret = -1;
#if defined(__x86_64__) || defined(_M_X64)
    if (wing_cpu_has_aes_pclmul()) {
        ret = wing_aes_gcm_open_aesni(key.ptr, key.len, iv.ptr, src.ptr, src.len, aad.ptr, aad.len, tag.ptr, dst.ptr);
        wing_scrub_stack_1024();
        return ret;
    }
#endif
    ret = wing_aes_gcm_open_scalar(key.ptr, key.len, iv.ptr, src.ptr, src.len, aad.ptr, aad.len, tag.ptr, dst.ptr);
    wing_scrub_stack_1024();
    return ret;
}

#define WING_AES_GCM_STATE_BYTES 320
#define WING_AES_GCM_MODE_AESNI 1
#define WING_AES_GCM_MODE_SCALAR 2

#if defined(__x86_64__) || defined(_M_X64)
WING_TARGET_AES_PCLMUL WING_ZERO_REGS static void wing_aes_gcm_prepare_aesni(const uint8_t *key_ptr, int64_t key_len,
                                                                             uint8_t *ctx_ptr) {
    __m128i rk[15];
    memset(rk, 0, sizeof(rk));
    int nr = wing_aes_expand_key_aesni(key_ptr, key_len, rk);

    __m128i h[4];
    h[0] = wing_bswap128(wing_aes_enc_block_aesni(_mm_setzero_si128(), rk, nr));
    h[1] = wing_gf128_mul_pclmul(h[0], h[0]);
    h[2] = wing_gf128_mul_pclmul(h[1], h[0]);
    h[3] = wing_gf128_mul_pclmul(h[2], h[0]);

    memcpy(ctx_ptr, rk, 240);
    memcpy(ctx_ptr + 240, h, sizeof(h));
    int32_t meta[2] = {nr, WING_AES_GCM_MODE_AESNI};
    memcpy(ctx_ptr + 304, meta, sizeof(meta));
    wing_fusion_zeroize(h, sizeof(h));
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
        wing_scrub_stack_1024();
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
        src.len > WING_AES_GCM_MAX_PLAINTEXT || aad.len > WING_AES_GCM_MAX_AAD || dst.len < src.len ||
        ctx.ptr == NULL || iv.ptr == NULL || tag_slice.ptr == NULL) {
        return 0;
    }
    if (src.len > 0 && (src.ptr == NULL || dst.ptr == NULL || wing_slices_partial_overlap(src.ptr, dst.ptr, src.len))) {
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
    int64_t ret = -1;
    if (mode == WING_AES_GCM_MODE_AESNI) {
#if defined(__x86_64__) || defined(_M_X64)
        if (!wing_cpu_has_aes_pclmul()) {
            return -1;
        }
        __m128i h[4];
        memcpy(h, ctx.ptr + 240, sizeof(h));
        ret = wing_aes_gcm_seal_aesni_rk(ctx.ptr, nr, h, iv.ptr, src.ptr, src.len, aad.ptr, aad.len, dst.ptr,
                                         tag_out.ptr);
        wing_fusion_zeroize(h, sizeof(h));
        wing_scrub_stack_1024();
        return ret;
#else
        return -1;
#endif
    }
    ret = wing_aes_gcm_seal_scalar_rk(ctx.ptr, nr, ctx.ptr + 240, iv.ptr, src.ptr, src.len, aad.ptr, aad.len, dst.ptr,
                                      tag_out.ptr);
    wing_scrub_stack_1024();
    return ret;
}

int64_t wing_aes_gcm_open_prepared(wing_slice ctx, wing_slice iv, wing_slice src, wing_slice aad, wing_slice tag,
                                   wing_slice dst) {
    int32_t nr = 0;
    int32_t mode = 0;
    if (!wing_aes_gcm_valid_prepared_args(ctx, iv, src, aad, dst, tag, &nr, &mode)) {
        return -1;
    }
    int64_t ret = -1;
    if (mode == WING_AES_GCM_MODE_AESNI) {
#if defined(__x86_64__) || defined(_M_X64)
        if (!wing_cpu_has_aes_pclmul()) {
            return -1;
        }
        __m128i h[4];
        memcpy(h, ctx.ptr + 240, sizeof(h));
        ret = wing_aes_gcm_open_aesni_rk(ctx.ptr, nr, h, iv.ptr, src.ptr, src.len, aad.ptr, aad.len, tag.ptr, dst.ptr);
        wing_fusion_zeroize(h, sizeof(h));
        wing_scrub_stack_1024();
        return ret;
#else
        return -1;
#endif
    }
    ret = wing_aes_gcm_open_scalar_rk(ctx.ptr, nr, ctx.ptr + 240, iv.ptr, src.ptr, src.len, aad.ptr, aad.len, tag.ptr,
                                      dst.ptr);
    wing_scrub_stack_1024();
    return ret;
}

void wing_ct_declassify(wing_slice s);
uint8_t wing_ct_declassify_u8(uint8_t v);

#ifndef WING_CTGRIND_VALGRIND
// Production no-op declassification barriers (overridden by Valgrind ctgrind under -DWING_CTGRIND_VALGRIND=1).
void wing_ct_declassify(wing_slice s) { (void)s; }

uint8_t wing_ct_declassify_u8(uint8_t v) { return v; }
#endif
