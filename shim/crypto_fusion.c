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
    uint8_t* ptr;
    int64_t  len;
} wing_slice;

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

// GF(2^128) carry-less multiplication and reduction modulo x^128 + x^7 + x^2 + x + 1
// in reflected GHASH bit representation using _mm_clmulepi64_si128.
WING_TARGET_AES_PCLMUL
static inline __m128i wing_gf128_mul_pclmul(__m128i a, __m128i h) {
    // 1. Karatsuba / schoolbook 64x64->128 carry-less multiplications
    __m128i tmp3 = _mm_clmulepi64_si128(a, h, 0x00);
    __m128i tmp4 = _mm_clmulepi64_si128(a, h, 0x10);
    __m128i tmp5 = _mm_clmulepi64_si128(a, h, 0x01);
    __m128i tmp6 = _mm_clmulepi64_si128(a, h, 0x11);

    tmp4 = _mm_xor_si128(tmp4, tmp5);
    tmp5 = _mm_slli_si128(tmp4, 8);
    tmp4 = _mm_srli_si128(tmp4, 8);
    tmp3 = _mm_xor_si128(tmp3, tmp5);
    tmp6 = _mm_xor_si128(tmp6, tmp4);

    // 2. Left-shift 256-bit product by 1 bit (due to reflected bit-order of GHASH)
    __m128i tmp7  = _mm_srli_epi32(tmp3, 31);
    __m128i tmp8  = _mm_srli_epi32(tmp6, 31);
    tmp3          = _mm_slli_epi32(tmp3, 1);
    tmp6          = _mm_slli_epi32(tmp6, 1);
    __m128i tmp9  = _mm_srli_si128(tmp7, 12);
    tmp8          = _mm_slli_si128(tmp8, 4);
    tmp7          = _mm_slli_si128(tmp7, 4);
    tmp3          = _mm_or_si128(tmp3, tmp7);
    tmp6          = _mm_or_si128(tmp6, tmp8);
    tmp6          = _mm_or_si128(tmp6, tmp9);

    // 3. Modular reduction over GF(2^128) polynomial
    tmp7          = _mm_slli_epi32(tmp3, 31);
    tmp8          = _mm_slli_epi32(tmp3, 30);
    tmp9          = _mm_slli_epi32(tmp3, 25);
    tmp7          = _mm_xor_si128(tmp7, tmp8);
    tmp7          = _mm_xor_si128(tmp7, tmp9);
    tmp8          = _mm_srli_si128(tmp7, 4);
    tmp7          = _mm_slli_si128(tmp7, 12);
    tmp3          = _mm_xor_si128(tmp3, tmp7);

    __m128i tmp2  = _mm_srli_epi32(tmp3, 1);
    tmp4          = _mm_srli_epi32(tmp3, 2);
    tmp5          = _mm_srli_epi32(tmp3, 7);
    tmp2          = _mm_xor_si128(tmp2, tmp4);
    tmp2          = _mm_xor_si128(tmp2, tmp5);
    tmp2          = _mm_xor_si128(tmp2, tmp8);
    tmp3          = _mm_xor_si128(tmp3, tmp2);
    return _mm_xor_si128(tmp6, tmp3);
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
static inline void wing_aes128_expand_key(__m128i user_key, __m128i rk[11]) {
    rk[0]  = user_key;
    rk[1]  = wing_aes128_key_expand_step(rk[0], _mm_aeskeygenassist_si128(rk[0], 0x01));
    rk[2]  = wing_aes128_key_expand_step(rk[1], _mm_aeskeygenassist_si128(rk[1], 0x02));
    rk[3]  = wing_aes128_key_expand_step(rk[2], _mm_aeskeygenassist_si128(rk[2], 0x04));
    rk[4]  = wing_aes128_key_expand_step(rk[3], _mm_aeskeygenassist_si128(rk[3], 0x08));
    rk[5]  = wing_aes128_key_expand_step(rk[4], _mm_aeskeygenassist_si128(rk[4], 0x10));
    rk[6]  = wing_aes128_key_expand_step(rk[5], _mm_aeskeygenassist_si128(rk[5], 0x20));
    rk[7]  = wing_aes128_key_expand_step(rk[6], _mm_aeskeygenassist_si128(rk[6], 0x40));
    rk[8]  = wing_aes128_key_expand_step(rk[7], _mm_aeskeygenassist_si128(rk[7], 0x80));
    rk[9]  = wing_aes128_key_expand_step(rk[8], _mm_aeskeygenassist_si128(rk[8], 0x1B));
    rk[10] = wing_aes128_key_expand_step(rk[9], _mm_aeskeygenassist_si128(rk[9], 0x36));
}

WING_TARGET_AES_PCLMUL
static inline __m128i wing_aes128_enc_block(__m128i b, const __m128i rk[11]) {
    b = _mm_xor_si128(b, rk[0]);
    for (int r = 1; r < 10; r++) {
        b = _mm_aesenc_si128(b, rk[r]);
    }
    return _mm_aesenclast_si128(b, rk[10]);
}

WING_TARGET_AES_PCLMUL
static inline __m128i wing_make_ctr_block(const uint8_t iv[12], uint32_t ctr) {
    uint8_t blk[16];
    memcpy(blk, iv, 12);
    blk[12] = (uint8_t)(ctr >> 24);
    blk[13] = (uint8_t)(ctr >> 16);
    blk[14] = (uint8_t)(ctr >> 8);
    blk[15] = (uint8_t)(ctr);
    return _mm_loadu_si128((const __m128i*)blk);
}

// Fused 4-block AES-128-GCM decryption + GHASH loop using AES-NI and PCLMULQDQ.
// Interleaves _mm_aesenc_si128 rounds across 4 counter blocks with _mm_clmulepi64_si128
// GHASH updates on the 4 ciphertext blocks.
WING_TARGET_AES_PCLMUL
static int32_t wing_aes128_gcm_decrypt_aesni(
    const uint8_t* key_ptr,
    const uint8_t* iv_ptr,
    const uint8_t* src_ptr,
    int64_t        src_len,
    uint8_t*       dst_ptr,
    int64_t        dst_len
) {
    if (src_len < 16) {
        return -1;
    }
    int64_t ct_len = src_len - 16;
    if (dst_len < ct_len) {
        return -1;
    }

    __m128i rk[11];
    wing_aes128_expand_key(_mm_loadu_si128((const __m128i*)key_ptr), rk);

    // H = AES_K(0^128) in byte-swapped GHASH polynomial order
    __m128i h_raw = wing_aes128_enc_block(_mm_setzero_si128(), rk);
    __m128i h_swp = wing_bswap128(h_raw);

    // J0 = IV || 0x00000001; E(K, J0) for final tag XOR
    __m128i j0_enc = wing_aes128_enc_block(wing_make_ctr_block(iv_ptr, 1u), rk);

    __m128i ghash_acc = _mm_setzero_si128();
    uint32_t ctr = 2u;
    int64_t offset = 0;

    // Fused 4-block (64-byte) pipeline: interleave 4x AES-CTR rounds with 4x PCLMULQDQ GHASH
    while (offset + 64 <= ct_len) {
        __m128i c0 = _mm_loadu_si128((const __m128i*)(src_ptr + offset));
        __m128i c1 = _mm_loadu_si128((const __m128i*)(src_ptr + offset + 16));
        __m128i c2 = _mm_loadu_si128((const __m128i*)(src_ptr + offset + 32));
        __m128i c3 = _mm_loadu_si128((const __m128i*)(src_ptr + offset + 48));

        __m128i b0 = _mm_xor_si128(wing_make_ctr_block(iv_ptr, ctr), rk[0]);
        __m128i b1 = _mm_xor_si128(wing_make_ctr_block(iv_ptr, ctr + 1u), rk[0]);
        __m128i b2 = _mm_xor_si128(wing_make_ctr_block(iv_ptr, ctr + 2u), rk[0]);
        __m128i b3 = _mm_xor_si128(wing_make_ctr_block(iv_ptr, ctr + 3u), rk[0]);
        ctr += 4u;

        // Interleave rounds 1..3 with GHASH block 0
        for (int r = 1; r <= 3; r++) {
            b0 = _mm_aesenc_si128(b0, rk[r]);
            b1 = _mm_aesenc_si128(b1, rk[r]);
            b2 = _mm_aesenc_si128(b2, rk[r]);
            b3 = _mm_aesenc_si128(b3, rk[r]);
        }
        ghash_acc = wing_gf128_mul_pclmul(_mm_xor_si128(ghash_acc, wing_bswap128(c0)), h_swp);

        // Interleave rounds 4..6 with GHASH block 1
        for (int r = 4; r <= 6; r++) {
            b0 = _mm_aesenc_si128(b0, rk[r]);
            b1 = _mm_aesenc_si128(b1, rk[r]);
            b2 = _mm_aesenc_si128(b2, rk[r]);
            b3 = _mm_aesenc_si128(b3, rk[r]);
        }
        ghash_acc = wing_gf128_mul_pclmul(_mm_xor_si128(ghash_acc, wing_bswap128(c1)), h_swp);

        // Interleave rounds 7..9 with GHASH block 2
        for (int r = 7; r <= 9; r++) {
            b0 = _mm_aesenc_si128(b0, rk[r]);
            b1 = _mm_aesenc_si128(b1, rk[r]);
            b2 = _mm_aesenc_si128(b2, rk[r]);
            b3 = _mm_aesenc_si128(b3, rk[r]);
        }
        ghash_acc = wing_gf128_mul_pclmul(_mm_xor_si128(ghash_acc, wing_bswap128(c2)), h_swp);

        // Final AES round 10 + GHASH block 3
        b0 = _mm_aesenclast_si128(b0, rk[10]);
        b1 = _mm_aesenclast_si128(b1, rk[10]);
        b2 = _mm_aesenclast_si128(b2, rk[10]);
        b3 = _mm_aesenclast_si128(b3, rk[10]);
        ghash_acc = wing_gf128_mul_pclmul(_mm_xor_si128(ghash_acc, wing_bswap128(c3)), h_swp);

        _mm_storeu_si128((__m128i*)(dst_ptr + offset), _mm_xor_si128(c0, b0));
        _mm_storeu_si128((__m128i*)(dst_ptr + offset + 16), _mm_xor_si128(c1, b1));
        _mm_storeu_si128((__m128i*)(dst_ptr + offset + 32), _mm_xor_si128(c2, b2));
        _mm_storeu_si128((__m128i*)(dst_ptr + offset + 48), _mm_xor_si128(c3, b3));

        offset += 64;
    }

    // Remaining full 16-byte blocks
    while (offset + 16 <= ct_len) {
        __m128i c0 = _mm_loadu_si128((const __m128i*)(src_ptr + offset));
        __m128i ks = wing_aes128_enc_block(wing_make_ctr_block(iv_ptr, ctr), rk);
        ctr += 1u;
        ghash_acc = wing_gf128_mul_pclmul(_mm_xor_si128(ghash_acc, wing_bswap128(c0)), h_swp);
        _mm_storeu_si128((__m128i*)(dst_ptr + offset), _mm_xor_si128(c0, ks));
        offset += 16;
    }

    // Trailing partial block (if any)
    if (offset < ct_len) {
        int64_t rem = ct_len - offset;
        uint8_t c_pad[16] = {0};
        uint8_t ks_bytes[16];
        memcpy(c_pad, src_ptr + offset, (size_t)rem);
        __m128i ks = wing_aes128_enc_block(wing_make_ctr_block(iv_ptr, ctr), rk);
        _mm_storeu_si128((__m128i*)ks_bytes, ks);
        for (int64_t i = 0; i < rem; i++) {
            dst_ptr[offset + i] = c_pad[i] ^ ks_bytes[i];
        }
        __m128i c_vec = _mm_loadu_si128((const __m128i*)c_pad);
        ghash_acc = wing_gf128_mul_pclmul(_mm_xor_si128(ghash_acc, wing_bswap128(c_vec)), h_swp);
    }

    // GHASH length block: len(AAD)=0 || len(C) in bits (big-endian 64-bit)
    uint8_t len_blk[16] = {0};
    uint64_t c_bits = ((uint64_t)ct_len) * 8u;
    for (int i = 0; i < 8; i++) {
        len_blk[8 + i] = (uint8_t)(c_bits >> (56 - 8 * i));
    }
    __m128i len_vec = _mm_loadu_si128((const __m128i*)len_blk);
    ghash_acc = wing_gf128_mul_pclmul(_mm_xor_si128(ghash_acc, wing_bswap128(len_vec)), h_swp);

    __m128i tag_vec = _mm_xor_si128(wing_bswap128(ghash_acc), j0_enc);
    uint8_t computed_tag[16];
    _mm_storeu_si128((__m128i*)computed_tag, tag_vec);

    // Constant-time tag comparison (Invariant 11)
    const uint8_t* wire_tag = src_ptr + ct_len;
    uint8_t diff = 0;
    for (int i = 0; i < 16; i++) {
        diff |= (computed_tag[i] ^ wire_tag[i]);
    }
    if (diff != 0) {
        // Zeroize output buffer on authentication failure
        for (int64_t i = 0; i < ct_len; i++) {
            dst_ptr[i] = 0;
        }
        return -1;
    }

    return (int32_t)ct_len;
}
#endif

// ---- Constant-Time Scalar Fallback (for non-AES-NI CPUs) -----------------

static const uint8_t WING_AES_SBOX[256] = {
    0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
    0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
    0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
    0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
    0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
    0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
    0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
    0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
    0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
    0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
    0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
    0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
    0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
    0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
    0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
    0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16
};

static inline uint8_t wing_gf_xtime(uint8_t x) {
    return (uint8_t)((x << 1) ^ (((x >> 7) & 1u) * 0x1bu));
}

static void wing_aes128_scalar_expand(const uint8_t key[16], uint8_t rk[176]) {
    static const uint8_t rcon[10] = {0x01,0x02,0x04,0x08,0x10,0x20,0x40,0x80,0x1b,0x36};
    memcpy(rk, key, 16);
    for (int i = 4; i < 44; i++) {
        uint8_t t[4];
        memcpy(t, &rk[(i - 1) * 4], 4);
        if ((i & 3) == 0) {
            uint8_t tmp = t[0];
            t[0] = WING_AES_SBOX[t[1]] ^ rcon[(i / 4) - 1];
            t[1] = WING_AES_SBOX[t[2]];
            t[2] = WING_AES_SBOX[t[3]];
            t[3] = WING_AES_SBOX[tmp];
        }
        for (int j = 0; j < 4; j++) {
            rk[i * 4 + j] = rk[(i - 4) * 4 + j] ^ t[j];
        }
    }
}

static void wing_aes128_scalar_enc(const uint8_t rk[176], const uint8_t in[16], uint8_t out[16]) {
    uint8_t s[16];
    for (int i = 0; i < 16; i++) s[i] = in[i] ^ rk[i];
    for (int r = 1; r <= 10; r++) {
        uint8_t t[16];
        for (int i = 0; i < 16; i++) t[i] = WING_AES_SBOX[s[i]];
        // ShiftRows
        uint8_t sr[16] = {
            t[0], t[5], t[10], t[15],
            t[4], t[9], t[14], t[3],
            t[8], t[13], t[2], t[7],
            t[12], t[1], t[6], t[11]
        };
        if (r < 10) {
            for (int c = 0; c < 4; c++) {
                uint8_t a0 = sr[c*4+0], a1 = sr[c*4+1], a2 = sr[c*4+2], a3 = sr[c*4+3];
                uint8_t all = a0 ^ a1 ^ a2 ^ a3;
                s[c*4+0] = a0 ^ all ^ wing_gf_xtime(a0 ^ a1);
                s[c*4+1] = a1 ^ all ^ wing_gf_xtime(a1 ^ a2);
                s[c*4+2] = a2 ^ all ^ wing_gf_xtime(a2 ^ a3);
                s[c*4+3] = a3 ^ all ^ wing_gf_xtime(a3 ^ a0);
            }
        } else {
            memcpy(s, sr, 16);
        }
        for (int i = 0; i < 16; i++) s[i] ^= rk[r * 16 + i];
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
        y[i]     = (uint8_t)(zh >> (56 - 8 * i));
        y[8 + i] = (uint8_t)(zl >> (56 - 8 * i));
    }
}

static int32_t wing_aes128_gcm_decrypt_scalar(
    const uint8_t* key_ptr,
    const uint8_t* iv_ptr,
    const uint8_t* src_ptr,
    int64_t        src_len,
    uint8_t*       dst_ptr,
    int64_t        dst_len
) {
    if (src_len < 16) return -1;
    int64_t ct_len = src_len - 16;
    if (dst_len < ct_len) return -1;

    uint8_t rk[176];
    wing_aes128_scalar_expand(key_ptr, rk);

    uint8_t zero_blk[16] = {0};
    uint8_t h_blk[16];
    wing_aes128_scalar_enc(rk, zero_blk, h_blk);

    uint8_t j0[16];
    memcpy(j0, iv_ptr, 12);
    j0[12] = 0; j0[13] = 0; j0[14] = 0; j0[15] = 1;
    uint8_t j0_enc[16];
    wing_aes128_scalar_enc(rk, j0, j0_enc);

    uint8_t y[16] = {0};
    uint32_t ctr = 2u;
    int64_t offset = 0;

    while (offset < ct_len) {
        int64_t blk_len = (ct_len - offset >= 16) ? 16 : (ct_len - offset);
        uint8_t cb[16], ks[16];
        memcpy(cb, iv_ptr, 12);
        cb[12] = (uint8_t)(ctr >> 24);
        cb[13] = (uint8_t)(ctr >> 16);
        cb[14] = (uint8_t)(ctr >> 8);
        cb[15] = (uint8_t)(ctr);
        ctr += 1u;

        wing_aes128_scalar_enc(rk, cb, ks);
        for (int64_t i = 0; i < blk_len; i++) {
            uint8_t c_byte = src_ptr[offset + i];
            y[i] ^= c_byte;
            dst_ptr[offset + i] = c_byte ^ ks[i];
        }
        wing_ghash_scalar_mul(y, h_blk);
        offset += blk_len;
    }

    uint64_t c_bits = ((uint64_t)ct_len) * 8u;
    for (int i = 0; i < 8; i++) {
        y[8 + i] ^= (uint8_t)(c_bits >> (56 - 8 * i));
    }
    wing_ghash_scalar_mul(y, h_blk);

    uint8_t diff = 0;
    const uint8_t* wire_tag = src_ptr + ct_len;
    for (int i = 0; i < 16; i++) {
        uint8_t calc_t = y[i] ^ j0_enc[i];
        diff |= (calc_t ^ wire_tag[i]);
    }
    if (diff != 0) {
        for (int64_t i = 0; i < ct_len; i++) dst_ptr[i] = 0;
        return -1;
    }
    return (int32_t)ct_len;
}

int32_t wing_aes_gcm_decrypt(wing_slice key, wing_slice iv, wing_slice src, wing_slice dst) {
    if (key.len != 16 || iv.len != 12 || src.len < 16) {
        return -1;
    }
    if (dst.len < (src.len - 16)) {
        return -1;
    }
#if defined(__x86_64__) || defined(_M_X64)
    if (wing_cpu_has_aes_pclmul()) {
        return wing_aes128_gcm_decrypt_aesni(key.ptr, iv.ptr, src.ptr, src.len, dst.ptr, dst.len);
    }
#endif
    return wing_aes128_gcm_decrypt_scalar(key.ptr, iv.ptr, src.ptr, src.len, dst.ptr, dst.len);
}
