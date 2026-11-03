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

#ifdef __cplusplus
}
#endif

#endif // WING_CORE_H
