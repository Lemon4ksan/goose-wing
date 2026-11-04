// SPDX-License-Identifier: Apache-2.0
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
