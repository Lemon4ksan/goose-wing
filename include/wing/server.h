// SPDX-License-Identifier: Apache-2.0
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
