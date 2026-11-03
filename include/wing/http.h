// SPDX-License-Identifier: Apache-2.0
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

WING_API void         wing_header_map_init(wing_header_map_t *map, wing_header_entry_t *storage, int64_t capacity);
WING_API bool         wing_header_map_set(wing_header_map_t *map, wing_slice_t name, wing_slice_t value);
WING_API bool         wing_header_map_append(wing_header_map_t *map, wing_slice_t name, wing_slice_t value);
WING_API wing_slice_t wing_header_map_get(const wing_header_map_t *map, wing_slice_t name);
WING_API bool         wing_header_map_contains(const wing_header_map_t *map, wing_slice_t name);
WING_API bool         wing_header_map_delete(wing_header_map_t *map, wing_slice_t name);

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

WING_API void wing_chunked_decoder_init(wing_chunked_decoder_t *dec);
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

#ifdef __cplusplus
}
#endif

#endif // WING_HTTP_H
