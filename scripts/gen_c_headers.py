#!/usr/bin/env python3

# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Lemon4ksan

"""scripts/gen_c_headers.py.

Automated C99/C++ header generator and CI drift checker for goose-wing.
Maintains idiomatic C headers in include/wing/ and enforces API stability in CI.
"""

import argparse
import difflib
import sys
from pathlib import Path


HEADERS: dict[str, str] = {}

HEADERS["types.h"] = """// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

#ifndef WING_TYPES_H
#define WING_TYPES_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#if defined(_WIN32) || defined(__CYGWIN__)
  #if defined(WING_BUILD_SHARED)
    #define WING_API __declspec(dllexport)
  #elif defined(WING_USE_SHARED)
    #define WING_API __declspec(dllimport)
  #else
    #define WING_API
  #endif
#elif defined(__GNUC__) && __GNUC__ >= 4
  #define WING_API __attribute__((visibility("default")))
#else
  #define WING_API
#endif

#ifdef __cplusplus
extern "C" {
#endif

#define WING_VERSION_MAJOR 0
#define WING_VERSION_MINOR 1
#define WING_VERSION_PATCH 0

/**
 * @brief Returns the semantic version string of the wing library.
 */
WING_API const char *wing_version_string(void);

/**
 * @brief Zero-copy immutable byte slice matching Goose `const u8[:]`.
 */
typedef struct wing_slice {
    const uint8_t *ptr;
    int64_t        len;
} wing_slice_t;

/**
 * @brief Zero-copy mutable byte slice matching Goose `u8[:]`.
 */
typedef struct wing_mut_slice {
    uint8_t *ptr;
    int64_t  len;
} wing_mut_slice_t;

/**
 * @brief Construct an immutable wing_slice_t from a C string literal (excluding null terminator).
 */
#define WING_STR(s) ((wing_slice_t){ (const uint8_t*)(s), (int64_t)(sizeof(s) - 1) })

/**
 * @brief Construct an immutable wing_slice_t from a pointer and length.
 */
#define WING_SLICE(buf, n) ((wing_slice_t){ (const uint8_t*)(buf), (int64_t)(n) })

/**
 * @brief Construct a mutable wing_mut_slice_t from a pointer and length.
 */
#define WING_MUT_SLICE(buf, n) ((wing_mut_slice_t){ (uint8_t*)(buf), (int64_t)(n) })

#ifdef __cplusplus
}
#endif

#endif // WING_TYPES_H
"""

HEADERS["core.h"] = """// SPDX-License-Identifier: Apache-2.0
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
"""

HEADERS["http.h"] = """// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

#ifndef WING_HTTP_H
#define WING_HTTP_H

#include <wing/types.h>

#ifdef __cplusplus
extern "C" {
#endif

// ============================================================================
// HTTP Methods (RFC 9110 §9)
// ============================================================================

typedef enum wing_http_method {
    WING_HTTP_METHOD_UNKNOWN = 0,
    WING_HTTP_METHOD_GET     = 1,
    WING_HTTP_METHOD_HEAD    = 2,
    WING_HTTP_METHOD_POST    = 3,
    WING_HTTP_METHOD_PUT     = 4,
    WING_HTTP_METHOD_DELETE  = 5,
    WING_HTTP_METHOD_CONNECT = 6,
    WING_HTTP_METHOD_OPTIONS = 7,
    WING_HTTP_METHOD_TRACE   = 8,
    WING_HTTP_METHOD_PATCH   = 9,
} wing_http_method_t;

WING_API wing_http_method_t wing_http_method_parse(wing_slice_t str);
WING_API wing_slice_t       wing_http_method_string(wing_http_method_t method);

// ============================================================================
// HTTP Status Codes (RFC 9110 §15)
// ============================================================================

typedef enum wing_http_status {
    WING_HTTP_STATUS_OK                    = 200,
    WING_HTTP_STATUS_CREATED               = 201,
    WING_HTTP_STATUS_ACCEPTED              = 202,
    WING_HTTP_STATUS_NO_CONTENT            = 204,
    WING_HTTP_STATUS_PARTIAL_CONTENT       = 206,
    WING_HTTP_STATUS_MOVED_PERMANENTLY     = 301,
    WING_HTTP_STATUS_FOUND                 = 302,
    WING_HTTP_STATUS_SEE_OTHER             = 303,
    WING_HTTP_STATUS_NOT_MODIFIED          = 304,
    WING_HTTP_STATUS_TEMPORARY_REDIRECT    = 307,
    WING_HTTP_STATUS_PERMANENT_REDIRECT    = 308,
    WING_HTTP_STATUS_BAD_REQUEST           = 400,
    WING_HTTP_STATUS_UNAUTHORIZED          = 401,
    WING_HTTP_STATUS_FORBIDDEN             = 403,
    WING_HTTP_STATUS_NOT_FOUND             = 404,
    WING_HTTP_STATUS_METHOD_NOT_ALLOWED    = 405,
    WING_HTTP_STATUS_CONFLICT              = 409,
    WING_HTTP_STATUS_GONE                  = 410,
    WING_HTTP_STATUS_PAYLOAD_TOO_LARGE     = 413,
    WING_HTTP_STATUS_URI_TOO_LONG          = 414,
    WING_HTTP_STATUS_UNPROCESSABLE_ENTITY  = 422,
    WING_HTTP_STATUS_TOO_MANY_REQUESTS     = 429,
    WING_HTTP_STATUS_INTERNAL_SERVER_ERROR = 500,
    WING_HTTP_STATUS_NOT_IMPLEMENTED       = 501,
    WING_HTTP_STATUS_BAD_GATEWAY           = 502,
    WING_HTTP_STATUS_SERVICE_UNAVAILABLE   = 503,
    WING_HTTP_STATUS_GATEWAY_TIMEOUT       = 504,
} wing_http_status_t;

WING_API wing_slice_t wing_http_status_reason_phrase(int32_t status);

// ============================================================================
// Header Map & Canonical Headers (RFC 9110 §6.3 / RFC 9112 §5)
// ============================================================================

typedef struct wing_header_entry {
    wing_slice_t name;
    wing_slice_t value;
} wing_header_entry_t;

typedef struct wing_header_map {
    wing_header_entry_t *entries;
    int64_t              count;
    int64_t              capacity;
} wing_header_map_t;

WING_API bool         wing_header_map_set(wing_header_map_t *map, wing_slice_t name, wing_slice_t value);
WING_API bool         wing_header_map_append(wing_header_map_t *map, wing_slice_t name, wing_slice_t value);
WING_API wing_slice_t wing_header_map_get(const wing_header_map_t *map, wing_slice_t name);
WING_API bool         wing_header_map_contains(const wing_header_map_t *map, wing_slice_t name);
WING_API bool         wing_header_map_delete(wing_header_map_t *map, wing_slice_t name);
WING_API bool         wing_header_map_next_value(
    const wing_header_map_t *map,
    wing_slice_t             name,
    int64_t                 *cursor,
    wing_slice_t            *out_value
);

static inline void wing_header_map_init(
    wing_header_map_t   *map,
    wing_header_entry_t *storage,
    int64_t              capacity
) {
    if (map) {
        map->entries = storage;
        map->count = 0;
        map->capacity = capacity;
    }
}

// ============================================================================
// Chunked Transfer Framing & FSM (RFC 9112 §7.1)
// ============================================================================

typedef enum wing_chunked_state {
    WING_CHUNKED_SIZE      = 0,
    WING_CHUNKED_DATA      = 1,
    WING_CHUNKED_DATA_CRLF = 2,
    WING_CHUNKED_TRAILERS  = 3,
    WING_CHUNKED_COMPLETE  = 4,
    WING_CHUNKED_ERROR     = 5,
} wing_chunked_state_t;

typedef struct wing_chunked_decoder {
    wing_chunked_state_t state;
    int64_t              remaining_chunk_len;
    int64_t              total_decoded;
} wing_chunked_decoder_t;

static inline void wing_chunked_decoder_init(wing_chunked_decoder_t *dec) {
    if (dec) {
        dec->state = WING_CHUNKED_SIZE;
        dec->remaining_chunk_len = 0;
        dec->total_decoded = 0;
    }
}

WING_API bool wing_chunked_decode(
    wing_chunked_decoder_t *dec,
    wing_slice_t            raw,
    int64_t                *consumed,
    wing_slice_t           *chunk_data
);

// ============================================================================
// Problem Details for HTTP APIs (RFC 9457)
// ============================================================================

typedef struct wing_problem_details {
    wing_slice_t type_uri;
    wing_slice_t title;
    int32_t      status;
    wing_slice_t detail;
    wing_slice_t instance;
} wing_problem_details_t;

// ============================================================================
// Zero-Copy Cookie Parsing (RFC 6265bis §5.6)
// ============================================================================

typedef struct wing_cookie_span {
    uint16_t name_pos;
    uint16_t name_len;
    uint16_t val_pos;
    uint16_t val_len;
} wing_cookie_span_t;

WING_API bool         wing_next_cookie_span(wing_slice_t raw_header, int64_t *cursor, wing_cookie_span_t *out_span);
WING_API wing_slice_t wing_cookie_name(wing_slice_t raw, wing_cookie_span_t span);
WING_API wing_slice_t wing_cookie_value(wing_slice_t raw, wing_cookie_span_t span);
WING_API bool         wing_find_cookie_value(wing_slice_t raw_header, wing_slice_t name, wing_slice_t *out_value);

#ifdef __cplusplus
}
#endif

#endif // WING_HTTP_H
"""

HEADERS["tls.h"] = """// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

#ifndef WING_TLS_H
#define WING_TLS_H

#include <wing/types.h>

#ifdef __cplusplus
extern "C" {
#endif

// ============================================================================
// TLS Record Layer Content Types (RFC 8446 §5.1)
// ============================================================================

typedef enum wing_tls_content_type {
    WING_TLS_CONTENT_INVALID            = 0,
    WING_TLS_CONTENT_CHANGE_CIPHER_SPEC = 20,
    WING_TLS_CONTENT_ALERT              = 21,
    WING_TLS_CONTENT_HANDSHAKE          = 22,
    WING_TLS_CONTENT_APPLICATION_DATA   = 23,
} wing_tls_content_type_t;

// ============================================================================
// TLS Alert Levels & Descriptions (RFC 8446 §B.2)
// ============================================================================

typedef enum wing_tls_alert_level {
    WING_TLS_ALERT_LEVEL_WARNING = 1,
    WING_TLS_ALERT_LEVEL_FATAL   = 2,
} wing_tls_alert_level_t;

typedef enum wing_tls_alert_desc {
    WING_TLS_ALERT_CLOSE_NOTIFY            = 0,
    WING_TLS_ALERT_UNEXPECTED_MESSAGE      = 10,
    WING_TLS_ALERT_BAD_RECORD_MAC          = 20,
    WING_TLS_ALERT_RECORD_OVERFLOW         = 22,
    WING_TLS_ALERT_HANDSHAKE_FAILURE       = 40,
    WING_TLS_ALERT_BAD_CERTIFICATE         = 42,
    WING_TLS_ALERT_UNSUPPORTED_CERTIFICATE = 43,
    WING_TLS_ALERT_CERTIFICATE_REVOKED     = 44,
    WING_TLS_ALERT_CERTIFICATE_EXPIRED     = 45,
    WING_TLS_ALERT_CERTIFICATE_UNKNOWN     = 46,
    WING_TLS_ALERT_ILLEGAL_PARAMETER       = 47,
    WING_TLS_ALERT_UNKNOWN_CA              = 48,
    WING_TLS_ALERT_ACCESS_DENIED           = 49,
    WING_TLS_ALERT_DECODE_ERROR            = 50,
    WING_TLS_ALERT_DECRYPT_ERROR           = 51,
    WING_TLS_ALERT_PROTOCOL_VERSION        = 70,
    WING_TLS_ALERT_INSUFFICIENT_SECURITY   = 71,
    WING_TLS_ALERT_INTERNAL_ERROR          = 80,
    WING_TLS_ALERT_INAPPROPRIATE_FALLBACK  = 86,
    WING_TLS_ALERT_USER_CANCELED           = 90,
    WING_TLS_ALERT_NO_RENEGOTIATION        = 100,
    WING_TLS_ALERT_MISSING_EXTENSION       = 109,
    WING_TLS_ALERT_UNSUPPORTED_EXTENSION   = 110,
    WING_TLS_ALERT_UNRECOGNIZED_NAME       = 112,
    WING_TLS_ALERT_BAD_CERTIFICATE_STATUS_RESPONSE = 113,
    WING_TLS_ALERT_UNKNOWN_PSK_IDENTITY    = 115,
    WING_TLS_ALERT_CERTIFICATE_REQUIRED    = 116,
    WING_TLS_ALERT_NO_APPLICATION_PROTOCOL = 120,
} wing_tls_alert_desc_t;

// ============================================================================
// TLS 1.3 Cipher Suites (RFC 8446 §B.4)
// ============================================================================

typedef enum wing_tls_cipher_suite {
    WING_TLS_AES_128_GCM_SHA256       = 0x1301,
    WING_TLS_AES_256_GCM_SHA384       = 0x1302,
    WING_TLS_CHACHA20_POLY1305_SHA256 = 0x1303,
    WING_TLS_AES_128_CCM_SHA256       = 0x1304,
    WING_TLS_AES_128_CCM_8_SHA256     = 0x1305,
} wing_tls_cipher_suite_t;

// ============================================================================
// TLS Record Framing (RFC 8446 §5.1)
// ============================================================================

typedef struct wing_tls_record {
    uint8_t      content_type;
    uint16_t     legacy_version;
    wing_slice_t payload;
} wing_tls_record_t;

WING_API bool wing_parse_tls_record(wing_slice_t raw, wing_tls_record_t *out, int64_t *consumed);

// ============================================================================
// Encrypted Client Hello (ECH RFC 9460 / draft-ietf-tls-esni)
// ============================================================================

typedef struct wing_ech_config {
    uint16_t     version;
    uint16_t     kem_id;
    wing_slice_t public_name;
    wing_slice_t public_key;
    uint16_t     cipher_suite;
    uint8_t      max_name_len;
} wing_ech_config_t;

WING_API bool wing_parse_ech_config(wing_slice_t raw, wing_ech_config_t *out, int64_t *consumed);

// ============================================================================
// TLS Record Sequence Number & Nonce Derivation (RFC 8446 §5.3)
// ============================================================================

WING_API bool wing_tls_compute_record_nonce(const uint8_t iv[12], uint64_t seq_num, uint8_t out_nonce[12]);
WING_API bool wing_tls_increment_seq_num(uint64_t *seq_num);

// ============================================================================
// TLS Record Decryption & Authenticated Unpacking (RFC 8446 §5.2)
// ============================================================================

WING_API bool wing_tls_record_decrypt_aes128_gcm(
    const uint8_t    key[16],
    const uint8_t    iv[12],
    uint64_t         seq_num,
    wing_slice_t     record_header,
    wing_mut_slice_t record_payload,
    wing_slice_t    *out_inner_plaintext,
    uint8_t         *out_inner_content_type,
    uint8_t         *out_alert
);

WING_API bool wing_tls_record_decrypt_chacha20_poly1305(
    const uint8_t    key[32],
    const uint8_t    iv[12],
    uint64_t         seq_num,
    wing_slice_t     record_header,
    wing_mut_slice_t record_payload,
    wing_slice_t    *out_inner_plaintext,
    uint8_t         *out_inner_content_type,
    uint8_t         *out_alert
);

// ============================================================================
// X.509 Certificate Chain Parsing & Validation (RFC 5280 / RFC 6125)
// ============================================================================

typedef struct wing_x509_cert_summary {
    wing_slice_t subject_common_name;
    wing_slice_t issuer_common_name;
    int64_t      not_before_unix;
    int64_t      not_after_unix;
    uint8_t      public_key[32];
    uint16_t     signature_scheme;
    bool         is_ca;
} wing_x509_cert_summary_t;

WING_API bool wing_parse_x509_certificate(wing_slice_t der, wing_x509_cert_summary_t *out_cert);
WING_API bool wing_verify_certificate_san(wing_slice_t cert_der, wing_slice_t expected_hostname);

#ifdef __cplusplus
}
#endif

#endif // WING_TLS_H
"""

HEADERS["net.h"] = """// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

#ifndef WING_NET_H
#define WING_NET_H

#include <wing/types.h>

#ifdef __cplusplus
extern "C" {
#endif

// ============================================================================
// Socket Addresses & IP Families
// ============================================================================

typedef enum wing_ip_version {
    WING_IP_V4 = 4,
    WING_IP_V6 = 6,
} wing_ip_version_t;

typedef struct wing_sockaddr {
    wing_ip_version_t version;
    uint8_t           addr[16];
    uint16_t          port;
} wing_sockaddr_t;

// ============================================================================
// PROXY Protocol v1 & v2 (HAProxy specification)
// ============================================================================

typedef enum wing_proxy_version {
    WING_PROXY_VERSION_1 = 1,
    WING_PROXY_VERSION_2 = 2,
} wing_proxy_version_t;

typedef struct wing_proxy_header {
    wing_proxy_version_t version;
    wing_sockaddr_t      src;
    wing_sockaddr_t      dst;
} wing_proxy_header_t;

WING_API bool wing_parse_proxy_header(wing_slice_t raw, wing_proxy_header_t *out, int64_t *consumed);

// ============================================================================
// Poller & Event Multiplexing Flags
// ============================================================================

typedef enum wing_poll_event {
    WING_POLL_NONE  = 0x00,
    WING_POLL_READ  = 0x01,
    WING_POLL_WRITE = 0x02,
    WING_POLL_ERROR = 0x04,
    WING_POLL_HUP   = 0x08,
} wing_poll_event_t;

typedef struct wing_event {
    int64_t           fd;
    wing_poll_event_t events;
    void             *user_data;
} wing_event_t;

// ============================================================================
// Layer 4 Cross-Platform TCP Socket Transport (shim/tcp.c)
// ============================================================================

WING_API int32_t  wing_tcp_init(void);
WING_API void     wing_tcp_cleanup(void);
WING_API int64_t  wing_tcp_listen(wing_slice_t host, uint16_t port, int32_t backlog);
WING_API uint16_t wing_tcp_getsockname_port(int64_t sock_fd);
WING_API int64_t  wing_tcp_accept(int64_t listener_fd, uint32_t timeout_ms);
WING_API int64_t  wing_tcp_connect(wing_slice_t host, uint16_t port, uint32_t timeout_ms);
WING_API int32_t  wing_tcp_send(int64_t sock_fd, wing_slice_t data);
WING_API int32_t  wing_tcp_recv(int64_t sock_fd, wing_mut_slice_t buf, uint32_t timeout_ms);
WING_API void     wing_tcp_close(int64_t sock_fd);

#ifdef __cplusplus
}
#endif

#endif // WING_NET_H
"""

HEADERS["server.h"] = """// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

#ifndef WING_SERVER_H
#define WING_SERVER_H

#include <wing/types.h>
#include <wing/http.h>
#include <wing/net.h>

#ifdef __cplusplus
extern "C" {
#endif

// ============================================================================
// Server Request & Response Structures
// ============================================================================

typedef struct wing_server_request {
    wing_slice_t       method;
    wing_slice_t       path;
    wing_slice_t       query;
    wing_header_map_t  headers;
    wing_slice_t       body;
    wing_sockaddr_t    remote_addr;
} wing_server_request_t;

typedef struct wing_server_response {
    int32_t            status;
    wing_header_map_t  headers;
    wing_slice_t       body;
} wing_server_response_t;

// ============================================================================
// Route Handler Callback
// ============================================================================

typedef void (*wing_route_handler_fn)(
    const wing_server_request_t *req,
    wing_server_response_t      *res,
    void                        *user_data
);

// ============================================================================
// Server Configuration & Lifecycle
// ============================================================================

typedef struct wing_server_config {
    const char *host;
    uint16_t    port;
    int32_t     backlog;
    int32_t     num_workers;
    int64_t     max_body_bytes;
    int64_t     keepalive_timeout_ms;
} wing_server_config_t;

typedef struct wing_server wing_server_t;

WING_API wing_server_t *wing_server_create(const wing_server_config_t *config);
WING_API bool           wing_server_route(
    wing_server_t        *srv,
    wing_slice_t          method,
    wing_slice_t          path,
    wing_route_handler_fn handler,
    void                 *user_data
);
WING_API bool           wing_server_start(wing_server_t *srv);
WING_API void           wing_server_stop(wing_server_t *srv);
WING_API void           wing_server_destroy(wing_server_t *srv);

#ifdef __cplusplus
}
#endif

#endif // WING_SERVER_H
"""

HEADERS["wing.h"] = """// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

#ifndef WING_H
#define WING_H

/**
 * @file wing.h
 * @brief Umbrella header for the Goose-Wing C library interface.
 */

#include <wing/types.h>
#include <wing/core.h>
#include <wing/http.h>
#include <wing/tls.h>
#include <wing/net.h>
#include <wing/server.h>

#endif // WING_H
"""


def get_include_dir() -> Path:
    root = Path(__file__).resolve().parent.parent
    return root / "include" / "wing"


def run_generate(include_dir: Path) -> int:
    include_dir.mkdir(parents=True, exist_ok=True)
    count = 0
    for filename, content in HEADERS.items():
        file_path = include_dir / filename
        file_path.write_text(content, encoding="utf-8", newline="\n")
        count += 1
    print(f"[gen] Wrote {count} C header files to {include_dir.as_posix()}/")
    return 0


def run_check(include_dir: Path) -> int:
    drift_detected = False
    for filename, expected_content in HEADERS.items():
        file_path = include_dir / filename
        if not file_path.exists():
            print(f"[error] Missing header file: {file_path.as_posix()}", file=sys.stderr)
            drift_detected = True
            continue

        disk_content = file_path.read_text(encoding="utf-8")
        if disk_content != expected_content:
            print(f"[error] Header drift detected in {file_path.as_posix()}:", file=sys.stderr)
            diff = difflib.unified_diff(
                disk_content.splitlines(keepends=True),
                expected_content.splitlines(keepends=True),
                fromfile=f"{filename} (disk)",
                tofile=f"{filename} (expected)",
            )
            for line in diff:
                sys.stderr.write(line)
            drift_detected = True

    if drift_detected:
        print("\n[error] C headers in include/wing/ are out of date. Run: python scripts/gen_c_headers.py", file=sys.stderr)
        return 1

    print("[c-headers] Up to date.")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description="Generate and verify Goose-Wing C headers")
    parser.add_argument(
        "--check",
        action="store_true",
        help="Check that include/wing/ headers match generated output without writing",
    )
    args = parser.parse_args()

    include_dir = get_include_dir()
    if args.check:
        return run_check(include_dir)
    return run_generate(include_dir)


if __name__ == "__main__":
    sys.exit(main())
