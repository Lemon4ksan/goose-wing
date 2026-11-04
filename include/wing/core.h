// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

#ifndef WING_CORE_H
#define WING_CORE_H

#include <wing/types.h>

#ifdef __cplusplus
extern "C" {
#endif

// ============================================================================
// Byte Strings & UTF-8 Codecs (core/bytes/)
// ============================================================================

WING_API bool     wing_is_ascii(uint8_t b);
WING_API bool     wing_is_digit(uint8_t b);
WING_API bool     wing_is_hex_digit(uint8_t b);
WING_API bool     wing_is_alpha(uint8_t b);
WING_API bool     wing_is_alnum(uint8_t b);
WING_API uint8_t  wing_to_ascii_lower(uint8_t b);
WING_API uint8_t  wing_to_ascii_upper(uint8_t b);
WING_API bool     wing_eq_ascii_fold(wing_slice_t a, wing_slice_t b);

WING_API wing_slice_t wing_trim_lws(wing_slice_t s);
WING_API wing_slice_t wing_trim_ascii_whitespace(wing_slice_t s);
WING_API bool         wing_starts_with(wing_slice_t s, wing_slice_t prefix);
WING_API bool         wing_starts_with_fold(wing_slice_t s, wing_slice_t prefix);
WING_API bool         wing_ends_with(wing_slice_t s, wing_slice_t suffix);
WING_API int64_t      wing_index_of_byte(wing_slice_t s, uint8_t b);
WING_API int64_t      wing_index_of_slice(wing_slice_t s, wing_slice_t needle);
WING_API int64_t      wing_count_byte(wing_slice_t s, uint8_t b);

WING_API bool wing_parse_u64_dec(wing_slice_t s, uint64_t *out_val);
WING_API bool wing_parse_i64_dec(wing_slice_t s, int64_t *out_val);
WING_API bool wing_parse_u32_dec(wing_slice_t s, uint32_t *out_val);
WING_API bool wing_parse_hex_u64(wing_slice_t s, uint64_t *out_val);
WING_API bool wing_validate_utf8(wing_slice_t s);

// ============================================================================
// Constant-Time Cryptography & Key Schedule (core/crypto/)
// ============================================================================

WING_API bool    wing_ct_eq_bytes(wing_slice_t a, wing_slice_t b);
WING_API uint8_t wing_ct_select_u8(uint8_t mask, uint8_t a, uint8_t b);

WING_API void wing_sha256(wing_slice_t data, uint8_t out[32]);
WING_API void wing_sha384(wing_slice_t data, uint8_t out[48]);
WING_API void wing_sha512(wing_slice_t data, uint8_t out[64]);
WING_API void wing_sha1(wing_slice_t data, uint8_t out[20]);
WING_API void wing_md5(wing_slice_t data, uint8_t out[16]);
WING_API void wing_hmac_sha256(wing_slice_t key, wing_slice_t data, uint8_t out[32]);

WING_API bool wing_x25519_diffie_hellman(const uint8_t secret[32], const uint8_t peer_pub[32], uint8_t out[32]);
WING_API bool wing_ed25519_verify(const uint8_t pubkey[32], wing_slice_t message, const uint8_t signature[64]);

WING_API bool wing_aes128_gcm_seal_inplace(
    const uint8_t    key[16],
    const uint8_t    nonce[12],
    wing_mut_slice_t in_out,
    wing_slice_t     aad,
    uint8_t          out_tag[16]
);

WING_API bool wing_aes128_gcm_open_inplace(
    const uint8_t    key[16],
    const uint8_t    nonce[12],
    wing_mut_slice_t in_out,
    wing_slice_t     aad,
    const uint8_t    tag[16],
    int64_t         *out_plaintext_len
);

WING_API bool wing_aes256_gcm_seal_inplace(
    const uint8_t    key[32],
    const uint8_t    nonce[12],
    wing_mut_slice_t in_out,
    wing_slice_t     aad,
    uint8_t          out_tag[16]
);

WING_API bool wing_aes256_gcm_open_inplace(
    const uint8_t    key[32],
    const uint8_t    nonce[12],
    wing_mut_slice_t in_out,
    wing_slice_t     aad,
    const uint8_t    tag[16],
    int64_t         *out_plaintext_len
);

WING_API bool wing_chacha20_poly1305_seal_inplace(
    const uint8_t    key[32],
    const uint8_t    nonce[12],
    wing_mut_slice_t in_out,
    wing_slice_t     aad,
    uint8_t          out_tag[16]
);

WING_API bool wing_chacha20_poly1305_open_inplace(
    const uint8_t    key[32],
    const uint8_t    nonce[12],
    wing_mut_slice_t in_out,
    wing_slice_t     aad,
    const uint8_t    tag[16],
    int64_t         *out_plaintext_len
);

WING_API void wing_secure_zeroize_slice(wing_mut_slice_t buf);

WING_API bool wing_base64_encode(wing_slice_t data, wing_mut_slice_t *out, int64_t *written);
WING_API bool wing_base64_decode(wing_slice_t b64, wing_mut_slice_t *out, int64_t *written);
WING_API bool wing_base64_url_encode(wing_slice_t data, wing_mut_slice_t *out, int64_t *written);
WING_API bool wing_base64_url_decode(wing_slice_t b64, wing_mut_slice_t *out, int64_t *written);

WING_API uint32_t wing_crc32_ieee(wing_slice_t data);
WING_API uint32_t wing_adler32(wing_slice_t data);

// ============================================================================
// WHATWG URL Standard (core/url/)
// ============================================================================

typedef struct wing_url {
    wing_slice_t scheme;
    wing_slice_t username;
    wing_slice_t password;
    wing_slice_t host;
    uint16_t     port;
    wing_slice_t path;
    wing_slice_t query;
    wing_slice_t fragment;
} wing_url_t;

WING_API bool wing_parse_url(wing_slice_t raw, wing_url_t *out);
WING_API bool wing_resolve_url(const wing_url_t *base, wing_slice_t ref, wing_url_t *out);

// ============================================================================
// Monotonic Clocks & Time (core/time/)
// ============================================================================

typedef struct wing_instant {
    uint64_t raw_ns;
} wing_instant_t;

WING_API wing_instant_t wing_monotonic_now(void);
WING_API int64_t        wing_duration_nanos(wing_instant_t start, wing_instant_t end);

// ============================================================================
// Hardware SIMD & SWAR Wire Acceleration (shim/simd.c)
// ============================================================================

WING_API int32_t wing_simd_is_pure_ascii(wing_slice_t slice);
WING_API int64_t wing_simd_find_crlf(wing_slice_t slice);
WING_API int64_t wing_fast_find_crlfcrlf(wing_slice_t slice);
WING_API int64_t wing_swar_find_ctl(wing_slice_t slice);
WING_API void    wing_simd_mask_websocket(wing_mut_slice_t slice, const uint8_t mask[4]);
WING_API void    wing_swar_to_lower(wing_mut_slice_t slice);
WING_API void    wing_swar_to_upper(wing_mut_slice_t slice);
WING_API int32_t wing_fast_u64toa(uint64_t value, wing_mut_slice_t dst);
WING_API int32_t wing_fast_u32toa_hex(uint32_t value, wing_mut_slice_t dst);

// ============================================================================
// Virtual Memory Page-Mirrored Ring Buffer & Guarded Arena (shim/page_*.c)
// ============================================================================

#define WING_PAGE_GUARD_PAGE 0x01
#define WING_PAGE_HUGE_PAGES 0x02

WING_API int32_t wing_page_ring_create(uint32_t min_capacity, uint64_t *out_handle, uint32_t *out_capacity);
WING_API void    wing_page_ring_destroy(uint64_t handle);
WING_API int64_t wing_page_ring_write(uint64_t handle, uint64_t tail_offset, wing_slice_t src);
WING_API int64_t wing_page_ring_read(uint64_t handle, uint64_t head_offset, wing_mut_slice_t dst);
WING_API int64_t wing_page_ring_peek(uint64_t handle, uint64_t head_offset, wing_mut_slice_t dst);
WING_API int64_t wing_page_ring_find_crlf(uint64_t handle, uint64_t head_offset, uint32_t len);
WING_API int64_t wing_page_ring_find_crlfcrlf(uint64_t handle, uint64_t head_offset, uint32_t len);

WING_API int32_t wing_guarded_arena_create(
    uint64_t  requested_capacity,
    uint32_t  flags,
    uint64_t *out_handle,
    uint64_t *out_capacity
);
WING_API void    wing_guarded_arena_destroy(uint64_t handle);
WING_API int64_t wing_guarded_arena_write(uint64_t handle, uint64_t offset, wing_slice_t src);
WING_API int64_t wing_guarded_arena_read(uint64_t handle, uint64_t offset, wing_mut_slice_t dst);
WING_API int32_t wing_guarded_arena_reset(uint64_t handle);

// ============================================================================
// Lock-Free Cache-Line Aligned SPSC Queue (shim/spsc.c)
// ============================================================================

WING_API int32_t  wing_spsc_create(uint32_t min_capacity, uint64_t *out_handle, uint32_t *out_capacity);
WING_API void     wing_spsc_destroy(uint64_t handle);
WING_API int32_t  wing_spsc_push(uint64_t handle, uint64_t value);
WING_API int32_t  wing_spsc_pop(uint64_t handle, uint64_t *out_value);
WING_API uint32_t wing_spsc_count(uint64_t handle);
WING_API uint32_t wing_spsc_available(uint64_t handle);

#ifdef __cplusplus
}
#endif

#endif // WING_CORE_H
