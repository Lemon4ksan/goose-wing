// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Layer 4 Cross-Platform TCP Socket C Shim for goose-wing.
// Zero-allocation, high-performance synchronous & non-blocking socket operations
// conforming exactly to Goose slice binary layout.

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#define WIN32_LEAN_AND_MEAN
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <sys/stat.h>
#include <time.h>

#ifdef _WIN32
#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0602
#endif
#include <winsock2.h>
#include <ws2tcpip.h>
#include <mstcpip.h>
#include <afunix.h>
#include <windows.h>
#include <signal.h>
#ifdef _MSC_VER
#pragma comment(lib, "ws2_32.lib")
#endif
#elif defined(__wasm__)
#include <unistd.h>
#include <errno.h>
typedef int SOCKET;
#define INVALID_SOCKET (-1)
#define SOCKET_ERROR (-1)
#define closesocket(s) close(s)
#define MSG_NOSIGNAL 0
#else
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <poll.h>
#include <sys/statvfs.h>
#include <sys/un.h>
#include <sys/ioctl.h>
#include <sys/uio.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <ifaddrs.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/time.h>
#include <signal.h>
#include <errno.h>
#include <pthread.h>
#if defined(__linux__)
#include <sched.h>
#ifndef SO_ORIGINAL_DST
#define SO_ORIGINAL_DST 80
#endif
#ifndef IP6T_SO_ORIGINAL_DST
#define IP6T_SO_ORIGINAL_DST 80
#endif
#ifndef IP_TRANSPARENT
#define IP_TRANSPARENT 19
#endif
#ifndef IPV6_TRANSPARENT
#define IPV6_TRANSPARENT 75
#endif
#ifndef IP_FREEBIND
#define IP_FREEBIND 15
#endif
#ifndef IPV6_FREEBIND
#define IPV6_FREEBIND 78
#endif
#ifndef IP_BIND_ADDRESS_NO_PORT
#define IP_BIND_ADDRESS_NO_PORT 24
#endif
#ifndef SO_MARK
#define SO_MARK 36
#endif
#ifndef F_SETPIPE_SZ
#define F_SETPIPE_SZ 1031
#endif
#ifndef SPLICE_F_MOVE
#define SPLICE_F_MOVE 1
#endif
#ifndef SPLICE_F_NONBLOCK
#define SPLICE_F_NONBLOCK 2
#endif
#endif
typedef int SOCKET;
#define INVALID_SOCKET (-1)
#define SOCKET_ERROR (-1)
#define closesocket(s) close(s)
#ifndef MSG_NOSIGNAL
#define MSG_NOSIGNAL 0
#endif
#endif

#ifndef MSG_NOSIGNAL
#define MSG_NOSIGNAL 0
#endif

#pragma pack(push, 1)
typedef struct {
    const uint8_t *data;
    int64_t len;
} wing_bytes_ro;
typedef struct {
    uint8_t *data;
    int64_t len;
} wing_bytes_rw;
typedef struct {
    int64_t *data;
    int64_t len;
} wing_slice_i64;
typedef struct {
    uint64_t *data;
    int64_t len;
} wing_slice_u64;
typedef struct {
    uint32_t *data;
    int64_t len;
} wing_slice_u32;
typedef struct {
    int32_t *data;
    int64_t len;
} wing_slice_i32;
typedef struct {
    uint16_t *data;
    int64_t len;
} wing_slice_u16;
typedef struct {
    const int32_t *data;
    int64_t len;
} wing_slice_i32_ro;
typedef struct {
    const uint32_t *data;
    int64_t len;
} wing_slice_u32_ro;
typedef struct {
    const uint16_t *data;
    int64_t len;
} wing_slice_u16_ro;
#pragma pack(pop)

#ifdef __wasm__
static volatile int g_wing_stop_requested = 0;
static volatile int g_wing_reload_requested = 0;
#else
static volatile sig_atomic_t g_wing_stop_requested = 0;
static volatile sig_atomic_t g_wing_reload_requested = 0;
static volatile sig_atomic_t g_wing_signals_installed = 0;
#endif

// Helper to copy a slice into a null-terminated stack string buffer
static void slice_to_cstr(wing_bytes_ro s, char *out, size_t max_out) {
    if (s.data == NULL || s.len <= 0 || max_out == 0) {
        out[0] = '\0';
        return;
    }
    size_t copy_len = (size_t)s.len < (max_out - 1) ? (size_t)s.len : (max_out - 1);
    memcpy(out, s.data, copy_len);
    out[copy_len] = '\0';
}

#if defined(__wasm__)

// WebAssembly L4 Transport Implementation
// Zero-allocation virtual loopback & WASI host socket subsystem

#define WASM_MAX_SOCKETS 32
#define WASM_SOCK_BUF_SIZE 65536

typedef struct {
    int active;
    int is_listener;
    int backlog;
    uint16_t port;
    char host[64];
    uint8_t rx_buf[WASM_SOCK_BUF_SIZE];
    int64_t rx_head;
    int64_t rx_tail;
    int peer_slot;
    int write_shut;
    int pending_conns[WASM_MAX_SOCKETS];
    int pending_head;
    int pending_tail;
} wasm_virtual_socket_t;

static wasm_virtual_socket_t g_wasm_sockets[WASM_MAX_SOCKETS];
static int g_wasm_sock_initialized = 0;

int32_t wing_tcp_init(void) {
    if (!g_wasm_sock_initialized) {
        memset(g_wasm_sockets, 0, sizeof(g_wasm_sockets));
        g_wasm_sock_initialized = 1;
    }
    return 0;
}

void wing_tcp_cleanup(void) {
    memset(g_wasm_sockets, 0, sizeof(g_wasm_sockets));
    g_wasm_sock_initialized = 0;
}

uint16_t wing_get_env_port(uint16_t default_port) {
    const char *p = getenv("WING_PORT");
    if (!p || !*p) p = getenv("GW_PORT");
    if (p && *p) {
        int val = atoi(p);
        if (val > 0 && val < 65536) return (uint16_t)val;
    }
    return default_port;
}

int64_t wing_get_env_workers(int64_t default_workers) {
    (void)default_workers;
    return 1;
}

int64_t wing_tcp_listen(wing_bytes_ro host, uint16_t port, int32_t backlog) {
    wing_tcp_init();
    for (int i = 1; i < WASM_MAX_SOCKETS; i++) {
        if (!g_wasm_sockets[i].active) {
            g_wasm_sockets[i].active = 1;
            g_wasm_sockets[i].is_listener = 1;
            g_wasm_sockets[i].port = (port == 0) ? (uint16_t)(10000 + i) : port;
            g_wasm_sockets[i].backlog = (backlog > 0 && backlog < WASM_MAX_SOCKETS) ? backlog : (WASM_MAX_SOCKETS - 1);
            g_wasm_sockets[i].peer_slot = -1;
            g_wasm_sockets[i].pending_head = 0;
            g_wasm_sockets[i].pending_tail = 0;
            slice_to_cstr(host, g_wasm_sockets[i].host, sizeof(g_wasm_sockets[i].host));
            return (int64_t)i;
        }
    }
    return -1;
}

int64_t wing_tcp_listen_unix(wing_bytes_ro path, int32_t backlog) { return wing_tcp_listen(path, 0, backlog); }

int64_t wing_tcp_connect_unix(wing_bytes_ro path) { return wing_tcp_connect(path, 0, 500); }

int64_t wing_tcp_connect_begin(wing_bytes_ro host, uint16_t port, int32_t *out_state) {
    int64_t fd = wing_tcp_connect(host, port, 0);
    if (out_state) *out_state = (fd > 0) ? 0 : -1;
    return fd;
}

int64_t wing_tcp_connect_unix_begin(wing_bytes_ro path, int32_t *out_state) {
    int64_t fd = wing_tcp_connect_unix(path);
    if (out_state) *out_state = (fd > 0) ? 0 : -1;
    return fd;
}

int32_t wing_tcp_connect_finish(int64_t sock_fd) {
    return (sock_fd > 0 && sock_fd < WASM_MAX_SOCKETS && g_wasm_sockets[sock_fd].active) ? 0 : -1;
}

int32_t wing_tcp_connect_poll(int64_t sock_fd) { return wing_tcp_connect_finish(sock_fd); }

int64_t wing_adopt_socket(int64_t raw_fd) { return raw_fd > 0 ? raw_fd : -1; }

uint16_t wing_tcp_getsockname_port(int64_t sock_fd) {
    if (sock_fd > 0 && sock_fd < WASM_MAX_SOCKETS && g_wasm_sockets[sock_fd].active) {
        return g_wasm_sockets[sock_fd].port;
    }
    return 0;
}

int32_t wing_tcp_get_peer_ip(int64_t sock_fd, wing_bytes_rw out_ip) {
    if (out_ip.data == NULL || out_ip.len <= 0) return -1;
    const char *src = "127.0.0.1";
    if (sock_fd > 0 && sock_fd < WASM_MAX_SOCKETS && g_wasm_sockets[sock_fd].active &&
        g_wasm_sockets[sock_fd].host[0] != '\0') {
        src = g_wasm_sockets[sock_fd].host;
    }
    int64_t len = (int64_t)strlen(src);
    if (len > out_ip.len) len = out_ip.len;
    memcpy(out_ip.data, src, (size_t)len);
    return (int32_t)len;
}

int64_t wing_tcp_accept(int64_t listener_fd, uint32_t timeout_ms) {
    (void)timeout_ms;
    if (listener_fd <= 0 || listener_fd >= WASM_MAX_SOCKETS || !g_wasm_sockets[listener_fd].active ||
        !g_wasm_sockets[listener_fd].is_listener) {
        return -1;
    }
    wasm_virtual_socket_t *lis = &g_wasm_sockets[listener_fd];
    if (lis->pending_head < lis->pending_tail) {
        int server_slot = lis->pending_conns[lis->pending_head % WASM_MAX_SOCKETS];
        lis->pending_head++;
        return (int64_t)server_slot;
    }
    return 0;
}

int64_t wing_tcp_accept_nonblocking(int64_t listener_fd) { return wing_tcp_accept(listener_fd, 0); }

int64_t wing_tcp_connect(wing_bytes_ro host, uint16_t port, uint32_t timeout_ms) {
    (void)timeout_ms;
    wing_tcp_init();

    int listener_idx = -1;
    for (int i = 1; i < WASM_MAX_SOCKETS; i++) {
        if (g_wasm_sockets[i].active && g_wasm_sockets[i].is_listener && g_wasm_sockets[i].port == port) {
            listener_idx = i;
            break;
        }
    }
    if (listener_idx < 0) return -1; // Connection refused

    wasm_virtual_socket_t *lis = &g_wasm_sockets[listener_idx];
    int pending_count = (int)(lis->pending_tail - lis->pending_head);
    int max_backlog = lis->backlog > 0 && lis->backlog < WASM_MAX_SOCKETS ? lis->backlog : (WASM_MAX_SOCKETS - 1);
    if (pending_count >= max_backlog || pending_count >= WASM_MAX_SOCKETS) {
        return -1; // Connection refused: listener backlog saturated
    }

    int client_slot = -1;
    int server_slot = -1;
    for (int i = 1; i < WASM_MAX_SOCKETS; i++) {
        if (!g_wasm_sockets[i].active) {
            if (client_slot < 0)
                client_slot = i;
            else if (server_slot < 0) {
                server_slot = i;
                break;
            }
        }
    }
    if (client_slot < 0 || server_slot < 0) return -1; // Out of virtual sockets

    // Set up client socket
    g_wasm_sockets[client_slot].active = 1;
    g_wasm_sockets[client_slot].is_listener = 0;
    g_wasm_sockets[client_slot].port = (uint16_t)(20000 + client_slot);
    g_wasm_sockets[client_slot].peer_slot = server_slot;
    g_wasm_sockets[client_slot].rx_head = 0;
    g_wasm_sockets[client_slot].rx_tail = 0;
    slice_to_cstr(host, g_wasm_sockets[client_slot].host, sizeof(g_wasm_sockets[client_slot].host));

    // Set up server accepted socket
    g_wasm_sockets[server_slot].active = 1;
    g_wasm_sockets[server_slot].is_listener = 0;
    g_wasm_sockets[server_slot].port = port;
    g_wasm_sockets[server_slot].peer_slot = client_slot;
    g_wasm_sockets[server_slot].rx_head = 0;
    g_wasm_sockets[server_slot].rx_tail = 0;
    slice_to_cstr(host, g_wasm_sockets[server_slot].host, sizeof(g_wasm_sockets[server_slot].host));

    // Enqueue server_slot onto listener FIFO
    lis->pending_conns[lis->pending_tail % WASM_MAX_SOCKETS] = server_slot;
    lis->pending_tail++;

    return (int64_t)client_slot;
}

int64_t wing_tcp_connect_ex(wing_bytes_ro host, uint16_t port, uint32_t timeout_ms, int32_t ip_family,
                            wing_bytes_ro local_bind_addr) {
    (void)local_bind_addr;
    if (ip_family < 0 || ip_family > 2) return -1;
    if (host.data != NULL && host.len > 0) {
        int has_colon = memchr(host.data, ':', (size_t)host.len) != NULL;
        if (ip_family == 1 && has_colon) return -1;
        if (ip_family == 2 && !has_colon && !(host.len == 9 && memcmp(host.data, "localhost", 9) == 0)) return -1;
    }
    return wing_tcp_connect(host, port, timeout_ms);
}

static int wing_wasm_is_ip_literal(const char *s, int *out_is_v6) {
    if (s == NULL || s[0] == '\0') return 0;
    int has_colon = (strchr(s, ':') != NULL);
    int has_dot = (strchr(s, '.') != NULL);
    if (!has_colon && !has_dot) return 0;
    for (const char *p = s; *p != '\0'; p++) {
        char c = *p;
        int ok = (c >= '0' && c <= '9') || c == '.';
        if (has_colon) {
            ok = ok || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F') || c == ':';
        }
        if (!ok) return 0;
    }
    if (out_is_v6) *out_is_v6 = has_colon;
    return 1;
}

int32_t wing_net_resolve_host(wing_bytes_ro host, int32_t ip_family, wing_bytes_rw out_buf) {
    if (host.data == NULL || host.len <= 0 || host.len >= 256) return -1;
    if (ip_family < 0 || ip_family > 2 || out_buf.data == NULL || out_buf.len <= 0) return -1;
    char h[256];
    slice_to_cstr(host, h, sizeof(h));
    size_t hlen = strlen(h);
    if (hlen >= 2 && h[0] == '[' && h[hlen - 1] == ']') {
        memmove(h, h + 1, hlen - 2);
        h[hlen - 2] = '\0';
        hlen -= 2;
    }
    if (strcmp(h, "localhost") == 0) {
        const char *res = (ip_family == 1) ? "127.0.0.1\n" : ((ip_family == 2) ? "::1\n" : "127.0.0.1\n::1\n");
        int64_t n = (int64_t)strlen(res);
        if (n > out_buf.len) return -1;
        memcpy(out_buf.data, res, (size_t)n);
        return (int32_t)n;
    }
    int is_v6 = 0;
    if (!wing_wasm_is_ip_literal(h, &is_v6)) return -1;
    if ((ip_family == 1 && is_v6) || (ip_family == 2 && !is_v6)) return -1;
    if ((int64_t)hlen + 1 > out_buf.len) return -1;
    memcpy(out_buf.data, h, hlen);
    out_buf.data[hlen] = '\n';
    return (int32_t)(hlen + 1);
}

int64_t wing_tcp_connect_ip(wing_bytes_ro ip, uint16_t port, uint32_t timeout_ms, int32_t ip_family,
                            wing_bytes_ro local_bind_addr) {
    if (ip.data == NULL || ip.len <= 0 || ip.len >= 128 || port == 0 || ip_family < 0 || ip_family > 2) return -1;
    char s[128];
    slice_to_cstr(ip, s, sizeof(s));
    size_t slen = strlen(s);
    if (slen >= 2 && s[0] == '[' && s[slen - 1] == ']') {
        memmove(s, s + 1, slen - 2);
        s[slen - 2] = '\0';
    }
    int is_v6 = 0;
    if (!wing_wasm_is_ip_literal(s, &is_v6)) return -1;
    if ((ip_family == 1 && is_v6) || (ip_family == 2 && !is_v6)) return -1;
    return wing_tcp_connect_ex(ip, port, timeout_ms, ip_family, local_bind_addr);
}

int32_t wing_tcp_send(int64_t sock_fd, wing_bytes_ro data) {
    if (sock_fd <= 0 || sock_fd >= WASM_MAX_SOCKETS || !g_wasm_sockets[sock_fd].active || data.data == NULL ||
        data.len <= 0) {
        return 0;
    }
    int peer = g_wasm_sockets[sock_fd].peer_slot;
    if (peer <= 0 || peer >= WASM_MAX_SOCKETS || !g_wasm_sockets[peer].active) {
        return -1; // Connection broken/closed
    }
    wasm_virtual_socket_t *p = &g_wasm_sockets[peer];
    int64_t avail = WASM_SOCK_BUF_SIZE - (p->rx_tail - p->rx_head);
    if (avail <= 0 && data.len > 0) {
        return -2; // WouldBlock (peer rx buffer full)
    }
    int64_t to_write = data.len < avail ? data.len : avail;
    for (int64_t i = 0; i < to_write; i++) {
        p->rx_buf[(p->rx_tail + i) % WASM_SOCK_BUF_SIZE] = data.data[i];
    }
    p->rx_tail += to_write;
    return (int32_t)to_write;
}

int32_t wing_tcp_send2(int64_t sock_fd, wing_bytes_ro hdr, wing_bytes_ro payload) {
    int32_t sent1 = wing_tcp_send(sock_fd, hdr);
    int32_t sent2 = wing_tcp_send(sock_fd, payload);
    return (sent1 >= 0 && sent2 >= 0) ? (sent1 + sent2) : -1;
}

int32_t wing_tcp_recv(int64_t sock_fd, wing_bytes_rw buf, uint32_t timeout_ms) {
    (void)timeout_ms;
    if (sock_fd <= 0 || sock_fd >= WASM_MAX_SOCKETS || !g_wasm_sockets[sock_fd].active || buf.data == NULL ||
        buf.len <= 0) {
        return -1;
    }
    wasm_virtual_socket_t *s = &g_wasm_sockets[sock_fd];
    int64_t readable = s->rx_tail - s->rx_head;
    if (readable <= 0) {
        if (s->peer_slot < 0 ||
            (s->peer_slot > 0 && s->peer_slot < WASM_MAX_SOCKETS && g_wasm_sockets[s->peer_slot].write_shut))
            return 0; // Peer closed connection or shut down write side (EOF)
        return -2;    // WouldBlock / Timeout (peer connected, no data ready)
    }
    int64_t to_read = buf.len < readable ? buf.len : readable;
    for (int64_t i = 0; i < to_read; i++) {
        buf.data[i] = s->rx_buf[(s->rx_head + i) % WASM_SOCK_BUF_SIZE];
    }
    s->rx_head += to_read;
    if (s->rx_head == s->rx_tail) {
        s->rx_head = 0;
        s->rx_tail = 0;
    } else if (s->rx_head >= WASM_SOCK_BUF_SIZE) {
        s->rx_head %= WASM_SOCK_BUF_SIZE;
        s->rx_tail %= WASM_SOCK_BUF_SIZE;
        if (s->rx_tail < s->rx_head) s->rx_tail += WASM_SOCK_BUF_SIZE;
    }
    return (int32_t)to_read;
}

int32_t wing_tcp_recv_nonblocking(int64_t sock_fd, wing_bytes_rw buf) { return wing_tcp_recv(sock_fd, buf, 0); }

void wing_tcp_close(int64_t sock_fd) {
    if (sock_fd > 0 && sock_fd < WASM_MAX_SOCKETS && g_wasm_sockets[sock_fd].active) {
        if (g_wasm_sockets[sock_fd].is_listener) {
            // Drain and close any unaccepted server sockets queued in pending_conns
            wasm_virtual_socket_t *lis = &g_wasm_sockets[sock_fd];
            while (lis->pending_head < lis->pending_tail) {
                int server_slot = lis->pending_conns[lis->pending_head % WASM_MAX_SOCKETS];
                lis->pending_head++;
                if (server_slot > 0 && server_slot < WASM_MAX_SOCKETS && g_wasm_sockets[server_slot].active) {
                    int peer = g_wasm_sockets[server_slot].peer_slot;
                    if (peer > 0 && peer < WASM_MAX_SOCKETS) {
                        g_wasm_sockets[peer].peer_slot = -1;
                    }
                    memset(&g_wasm_sockets[server_slot], 0, sizeof(wasm_virtual_socket_t));
                }
            }
        }
        int peer = g_wasm_sockets[sock_fd].peer_slot;
        if (peer > 0 && peer < WASM_MAX_SOCKETS) {
            g_wasm_sockets[peer].peer_slot = -1;
        }
        memset(&g_wasm_sockets[sock_fd], 0, sizeof(wasm_virtual_socket_t));
    }
}

int32_t wing_tcp_set_defer_accept(int64_t sock_fd, int32_t timeout_sec) {
    (void)sock_fd;
    (void)timeout_sec;
    return 0;
}
int32_t wing_tcp_set_user_timeout(int64_t sock_fd, uint32_t timeout_ms) {
    (void)sock_fd;
    (void)timeout_ms;
    return 0;
}
int32_t wing_tcp_set_keepalive_params(int64_t sock_fd, int32_t idle_sec, int32_t intvl_sec, int32_t cnt) {
    (void)sock_fd;
    (void)idle_sec;
    (void)intvl_sec;
    (void)cnt;
    return 0;
}
int32_t wing_tcp_set_syn_retries(int64_t sock_fd, int32_t count) {
    (void)sock_fd;
    (void)count;
    return 0;
}
int32_t wing_tcp_set_fastopen(int64_t sock_fd, int32_t qlen) {
    (void)sock_fd;
    (void)qlen;
    return 0;
}
int32_t wing_tcp_send_fastopen(int64_t sock_fd, wing_bytes_ro data) { return wing_tcp_send(sock_fd, data); }
int32_t wing_tcp_set_tos(int64_t sock_fd, int32_t tos) {
    (void)sock_fd;
    (void)tos;
    return 0;
}
int32_t wing_tcp_set_tclass(int64_t sock_fd, int32_t tclass) {
    (void)sock_fd;
    (void)tclass;
    return 0;
}
int64_t wing_tcp_get_notsent_bytes(int64_t sock_fd) {
    (void)sock_fd;
    return 0;
}
int64_t wing_tcp_get_readable_bytes(int64_t sock_fd) {
    if (sock_fd > 0 && sock_fd < WASM_MAX_SOCKETS && g_wasm_sockets[sock_fd].active) {
        return g_wasm_sockets[sock_fd].rx_tail - g_wasm_sockets[sock_fd].rx_head;
    }
    return 0;
}
int32_t wing_tcp_set_nonblocking(int64_t sock_fd, int32_t nonblocking) {
    (void)sock_fd;
    (void)nonblocking;
    return 0;
}
int32_t wing_tcp_set_quickack(int64_t sock_fd, int32_t enable) {
    (void)sock_fd;
    (void)enable;
    return 0;
}
int32_t wing_tcp_set_cork(int64_t sock_fd, int32_t enable) {
    (void)sock_fd;
    (void)enable;
    return 0;
}

int64_t wing_fast_cork_append(int64_t conn, wing_bytes_rw cork_buf, int64_t cork_len, wing_bytes_ro resp) {
    (void)conn;
    if (!cork_buf.data || !resp.data || resp.len <= 0) return cork_len;
    if (cork_len < 0 || cork_len + resp.len > cork_buf.len) return -1;
    memcpy(cork_buf.data + cork_len, resp.data, (size_t)resp.len);
    return cork_len + resp.len;
}

int32_t wing_set_cpu_affinity(int64_t cpu_id) {
    (void)cpu_id;
    return 0;
}
int32_t wing_tcp_set_incoming_cpu(int64_t sock_fd, int64_t cpu_id) {
    (void)sock_fd;
    (void)cpu_id;
    return 0;
}

int64_t wing_epoll_create(void) { return 1; }
int32_t wing_epoll_add(int64_t epfd, int64_t sock_fd, uint32_t events, uint64_t udata) {
    (void)epfd;
    (void)sock_fd;
    (void)events;
    (void)udata;
    return 0;
}
int32_t wing_epoll_mod(int64_t epfd, int64_t sock_fd, uint32_t events, uint64_t udata) {
    (void)epfd;
    (void)sock_fd;
    (void)events;
    (void)udata;
    return 0;
}
int32_t wing_epoll_del(int64_t epfd, int64_t sock_fd) {
    (void)epfd;
    (void)sock_fd;
    return 0;
}
int32_t wing_epoll_wait(int64_t epfd, wing_slice_i64 out_fds, wing_slice_u64 out_udata, int32_t timeout_ms) {
    (void)epfd;
    (void)out_fds;
    (void)out_udata;
    (void)timeout_ms;
    return 0;
}
int32_t wing_epoll_wait_events(int64_t epfd, wing_slice_i64 out_fds, wing_slice_u64 out_udata,
                               wing_slice_u32 out_events, int32_t timeout_ms) {
    (void)epfd;
    (void)out_fds;
    (void)out_udata;
    (void)out_events;
    (void)timeout_ms;
    return 0;
}
void wing_epoll_close(int64_t epfd) { (void)epfd; }

int64_t wing_udp_bind(wing_bytes_ro host, uint16_t port) { return wing_tcp_listen(host, port, 16); }
int32_t wing_udp_sendto(int64_t sock_fd, wing_bytes_ro data, wing_bytes_ro host, uint16_t port) {
    (void)host;
    (void)port;
    return wing_tcp_send(sock_fd, data);
}
int32_t wing_udp_recvfrom(int64_t sock_fd, wing_bytes_rw buf, uint32_t timeout_ms, uint32_t *peer_ip4,
                          uint16_t *peer_port) {
    if (peer_ip4) *peer_ip4 = 0x0100007F;
    if (peer_port) {
        if (sock_fd > 0 && sock_fd < WASM_MAX_SOCKETS && g_wasm_sockets[sock_fd].peer_slot > 0) {
            *peer_port = g_wasm_sockets[g_wasm_sockets[sock_fd].peer_slot].port;
        } else {
            *peer_port = 8080;
        }
    }
    return wing_tcp_recv(sock_fd, buf, timeout_ms);
}
int32_t wing_udp_sendto_ip4(int64_t sock_fd, wing_bytes_ro data, uint32_t peer_ip4, uint16_t peer_port) {
    (void)peer_ip4;
    (void)peer_port;
    return wing_tcp_send(sock_fd, data);
}

int32_t wing_udp_sendmmsg(int64_t sock_fd, wing_bytes_ro payloads, wing_slice_i32_ro lengths, wing_slice_u32_ro ips,
                          wing_slice_u16_ro ports, int32_t count) {
    if (sock_fd < 0 || count <= 0 || payloads.data == NULL || lengths.data == NULL || ips.data == NULL ||
        ports.data == NULL)
        return -1;
    if (lengths.len < count || ips.len < count || ports.len < count) return -1;
    if (sock_fd == 0) return count;
    int32_t sent = 0;
    int64_t offset = 0;
    for (int32_t i = 0; i < count; i++) {
        int32_t pkt_len = lengths.data[i];
        if (pkt_len < 0 || offset + pkt_len > payloads.len) break;
        wing_bytes_ro slice = {payloads.data + offset, pkt_len};
        int32_t r = wing_udp_sendto_ip4(sock_fd, slice, ips.data[i], ports.data[i]);
        if (r < 0) return sent > 0 ? sent : -1;
        offset += 1472;
        sent++;
    }
    return sent;
}

int32_t wing_udp_recvmmsg(int64_t sock_fd, wing_bytes_rw payloads, wing_slice_i32 lengths, wing_slice_u32 ips,
                          wing_slice_u16 ports, int32_t max_count, uint32_t timeout_ms) {
    if (sock_fd < 0 || max_count <= 0 || payloads.data == NULL || lengths.data == NULL || ips.data == NULL ||
        ports.data == NULL)
        return -1;
    if (lengths.len < max_count || ips.len < max_count || ports.len < max_count) return -1;
    if (sock_fd == 0) return 0;
    int32_t recvd = 0;
    for (int32_t i = 0; i < max_count; i++) {
        int64_t offset = (int64_t)i * 1472;
        if (offset + 1472 > payloads.len) break;
        wing_bytes_rw slice = {payloads.data + offset, 1472};
        int32_t r = wing_udp_recvfrom(sock_fd, slice, i == 0 ? timeout_ms : 0, &ips.data[i], &ports.data[i]);
        if (r < 0) break;
        lengths.data[i] = r;
        recvd++;
    }
    return recvd;
}

int64_t wing_tcp_listen_dual(wing_bytes_ro host, uint16_t port, int32_t backlog, int32_t flags) {
    (void)flags;
    return wing_tcp_listen(host, port, backlog);
}
int64_t wing_tcp_accept_info(int64_t listener_fd, int32_t mode_flags, wing_bytes_rw out_peer_ip,
                             int32_t *out_peer_ip_len, uint16_t *out_peer_port, wing_bytes_rw out_dst_ip,
                             int32_t *out_dst_ip_len, uint16_t *out_dst_port) {
    (void)mode_flags;
    int64_t c = wing_tcp_accept_nonblocking(listener_fd);
    if (c <= 0) return c;
    int32_t plen = wing_tcp_get_peer_ip(c, out_peer_ip);
    if (out_peer_ip_len) *out_peer_ip_len = plen;
    if (out_peer_port) *out_peer_port = 0;
    if (out_dst_ip.data && out_dst_ip.len >= 9) {
        memcpy(out_dst_ip.data, "127.0.0.1", 9);
        if (out_dst_ip_len) *out_dst_ip_len = 9;
    }
    if (out_dst_port) *out_dst_port = wing_tcp_getsockname_port(c);
    return c;
}
int64_t wing_tcp_connect_opts_begin(wing_bytes_ro src_ip, wing_bytes_ro dst_ip, uint16_t dst_port, uint32_t so_mark,
                                    int32_t ttl, int32_t mss, int32_t rcvbuf, int32_t tcp_nodelay, int32_t ka_idle,
                                    int32_t ka_intvl, int32_t ka_cnt, uint32_t user_timeout_ms, int32_t *out_state,
                                    int32_t *out_err) {
    (void)src_ip;
    (void)so_mark;
    (void)ttl;
    (void)mss;
    (void)rcvbuf;
    (void)tcp_nodelay;
    (void)ka_idle;
    (void)ka_intvl;
    (void)ka_cnt;
    (void)user_timeout_ms;
    if (out_err) *out_err = 0;
    return wing_tcp_connect_begin(dst_ip, dst_port, out_state);
}
int64_t wing_tcp_connect_bound_begin(wing_bytes_ro src_ip, wing_bytes_ro dst_ip, uint16_t dst_port, uint32_t so_mark,
                                     int32_t *out_state, int32_t *out_err) {
    return wing_tcp_connect_opts_begin(src_ip, dst_ip, dst_port, so_mark, 0, 0, 0, 1, 30, 5, 3, 15000, out_state,
                                       out_err);
}
int32_t wing_tcp_connect_status(int64_t sock_fd) { return wing_tcp_connect_finish(sock_fd); }
int32_t wing_tcp_recv_peek(int64_t sock_fd, wing_bytes_rw dst) {
    (void)sock_fd;
    (void)dst;
    return -2;
}
int32_t wing_tcp_set_ttl(int64_t sock_fd, int32_t ttl, int32_t is_ipv6) {
    (void)sock_fd;
    (void)ttl;
    (void)is_ipv6;
    return 0;
}
int32_t wing_tcp_set_mss(int64_t sock_fd, int32_t mss) {
    (void)sock_fd;
    (void)mss;
    return 0;
}
int32_t wing_tcp_set_rcvbuf(int64_t sock_fd, int32_t bytes) {
    (void)sock_fd;
    (void)bytes;
    return 0;
}
int32_t wing_pipe_create(int64_t *out_read_fd, int64_t *out_write_fd) {
    if (out_read_fd) *out_read_fd = -1;
    if (out_write_fd) *out_write_fd = -1;
    return -1;
}
void wing_pipe_close(int64_t read_fd, int64_t write_fd) {
    (void)read_fd;
    (void)write_fd;
}
int64_t wing_tcp_splice_chunk(int64_t src_fd, int64_t dst_fd, int64_t pipe_r, int64_t pipe_w, int64_t max_bytes,
                              int64_t *in_pipe_bytes) {
    (void)src_fd;
    (void)dst_fd;
    (void)pipe_r;
    (void)pipe_w;
    (void)max_bytes;
    (void)in_pipe_bytes;
    return -1;
}
int32_t wing_net_get_local_ips(wing_bytes_rw out_buf) {
    const char *ips = "127.0.0.1\n::1\n";
    int64_t n = (int64_t)strlen(ips);
    if (out_buf.data == NULL || out_buf.len < n) return -1;
    memcpy(out_buf.data, ips, (size_t)n);
    return (int32_t)n;
}
int64_t wing_udp_open_dual(wing_bytes_ro bind_ip, uint16_t bind_port, int32_t flags) {
    (void)flags;
    return wing_udp_bind(bind_ip, bind_port);
}
int32_t wing_udp_sendto_dual(int64_t sock_fd, wing_bytes_ro data, wing_bytes_ro dst_ip, uint16_t dst_port) {
    return wing_udp_sendto(sock_fd, data, dst_ip, dst_port);
}
int32_t wing_udp_recvfrom_dual(int64_t sock_fd, wing_bytes_rw out_buf, wing_bytes_rw out_peer_ip,
                               int32_t *out_peer_ip_len, uint16_t *out_peer_port) {
    uint32_t ip4 = 0;
    int32_t r = wing_udp_recvfrom(sock_fd, out_buf, 0, &ip4, out_peer_port);
    if (r >= 0 && out_peer_ip.data && out_peer_ip.len >= 9) {
        memcpy(out_peer_ip.data, "127.0.0.1", 9);
        if (out_peer_ip_len) *out_peer_ip_len = 9;
    }
    return r;
}
int32_t wing_udp_exchange_dual(wing_bytes_ro server_ip, uint16_t server_port, wing_bytes_ro query,
                               wing_bytes_rw out_resp, uint32_t timeout_ms) {
    (void)server_ip;
    (void)server_port;
    (void)query;
    (void)out_resp;
    (void)timeout_ms;
    return -1;
}
int32_t wing_fs_disk_usage_percent(wing_bytes_ro path) {
    (void)path;
    return -1;
}
int64_t wing_fs_file_mtime(wing_bytes_ro path) {
    (void)path;
    return -1;
}

#else

// Waits for read (want_write == 0) or write (want_write != 0) readiness up to timeout_ms.
// Uses poll(2) on POSIX to avoid FD_SETSIZE (1024) stack overflow UB at high connection counts.
// Returns 1 if ready, 0 on timeout, or -1 on error (including Winsock exceptfds connect error).
static int wing_wait_fd(SOCKET s, int want_write, uint32_t timeout_ms) {
#ifdef _WIN32
    fd_set rw_fds;
    FD_ZERO(&rw_fds);
    FD_SET(s, &rw_fds);
    fd_set except_fds;
    FD_ZERO(&except_fds);
    if (want_write) FD_SET(s, &except_fds);

    struct timeval tv;
    tv.tv_sec = (long)(timeout_ms / 1000U);
    tv.tv_usec = (long)((timeout_ms % 1000U) * 1000U);

    int sel = select((int)(s + 1), want_write ? NULL : &rw_fds, want_write ? &rw_fds : NULL,
                     want_write ? &except_fds : NULL, &tv);
    if (sel <= 0) return sel;
    if (want_write && FD_ISSET(s, &except_fds)) return -1;
    return 1;
#else
    struct pollfd pfd;
    pfd.fd = (int)s;
    pfd.events = (short)(want_write ? POLLOUT : POLLIN);
    pfd.revents = 0;
    int ms = timeout_ms > 2147483647U ? 2147483647 : (int)timeout_ms;
    int pr = 0;
    do {
        pr = poll(&pfd, 1, ms);
    } while (pr < 0 && errno == EINTR);
    if (pr <= 0) return pr;
    if (want_write && (pfd.revents & (POLLERR | POLLHUP | POLLNVAL)) != 0 && (pfd.revents & POLLOUT) == 0) {
        return -1;
    }
    return 1;
#endif
}

// Initializes socket subsystem (WSAStartup on Windows, ignore SIGPIPE on POSIX).
int32_t wing_tcp_init(void) {
#ifdef _WIN32
    WSADATA wsa_data;
    return (int32_t)WSAStartup(MAKEWORD(2, 2), &wsa_data);
#else
    signal(SIGPIPE, SIG_IGN);
    return 0;
#endif
}

// Cleans up socket subsystem (WSACleanup on Windows).
void wing_tcp_cleanup(void) {
#ifdef _WIN32
    WSACleanup();
#endif
}

// Reads port from WING_PORT environment variable, or returns default_port
uint16_t wing_get_env_port(uint16_t default_port) {
    const char *p = getenv("WING_PORT");
    if (!p || !*p) p = getenv("GW_PORT");
    if (p && *p) {
        int val = atoi(p);
        if (val > 0 && val < 65536) return (uint16_t)val;
    }
    return default_port;
}

// Creates, binds, and listens on host:port.
int64_t wing_tcp_listen(wing_bytes_ro host, uint16_t port, int32_t backlog) {
    wing_tcp_init();

    SOCKET s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (s == INVALID_SOCKET) {
        return -1;
    }
#ifdef _WIN32
    // uSockets #263: Do not inherit socket handles into child processes (prevents keep-alive hangs)
    SetHandleInformation((HANDLE)s, HANDLE_FLAG_INHERIT, 0);

    // uSockets #101 / #167: On Windows, use SO_EXCLUSIVEADDRUSE to prevent port hijacking attacks (CWE-200).
    // SO_REUSEADDR on Windows permits rogue processes to forcibly bind to the same port and steal connections.
    int opt = 1;
    setsockopt(s, SOL_SOCKET, SO_EXCLUSIVEADDRUSE, (const char *)&opt, sizeof(opt));
#else
    int opt = 1;
    setsockopt(s, SOL_SOCKET, SO_REUSEADDR, (const char *)&opt, sizeof(opt));
#if defined(SO_REUSEPORT)
    setsockopt(s, SOL_SOCKET, SO_REUSEPORT, (const char *)&opt, sizeof(opt));
#endif
#if defined(TCP_DEFER_ACCEPT)
    const char *def_env = getenv("WING_DEFER_ACCEPT");
    if (def_env && atoi(def_env) > 0) {
        int defer = atoi(def_env);
        setsockopt(s, IPPROTO_TCP, TCP_DEFER_ACCEPT, &defer, sizeof(defer));
    }
#endif
#endif

    char host_str[128];
    slice_to_cstr(host, host_str, sizeof(host_str));

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);

    if (host_str[0] == '\0' || strcmp(host_str, "0.0.0.0") == 0) {
        addr.sin_addr.s_addr = INADDR_ANY;
    } else if (strcmp(host_str, "127.0.0.1") == 0 || strcmp(host_str, "localhost") == 0) {
        addr.sin_addr.s_addr = inet_addr("127.0.0.1");
    } else {
        addr.sin_addr.s_addr = inet_addr(host_str);
    }

    if (bind(s, (struct sockaddr *)&addr, sizeof(addr)) == SOCKET_ERROR) {
        closesocket(s);
        return -1;
    }

    if (listen(s, backlog > 0 ? backlog : 128) == SOCKET_ERROR) {
        closesocket(s);
        return -1;
    }

    return (int64_t)s;
}

// Unix Domain Sockets (AF_UNIX) Listener (uWebSockets us_socket_context_listen_unix pattern).
int64_t wing_tcp_listen_unix(wing_bytes_ro path, int32_t backlog) {
    wing_tcp_init();

    char path_str[108];
    slice_to_cstr(path, path_str, sizeof(path_str));
    if (path_str[0] == '\0') {
        return -1;
    }

#ifdef _WIN32
    DeleteFileA(path_str);
    SOCKET s = socket(AF_UNIX, SOCK_STREAM, 0);
    if (s == INVALID_SOCKET) {
        return -1;
    }
    SetHandleInformation((HANDLE)s, HANDLE_FLAG_INHERIT, 0);
#else
    unlink(path_str);
    SOCKET s = socket(AF_UNIX, SOCK_STREAM, 0);
    if (s == INVALID_SOCKET) {
        return -1;
    }
#endif

    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, path_str, sizeof(addr.sun_path) - 1);

    if (bind(s, (struct sockaddr *)&addr, sizeof(addr)) == SOCKET_ERROR) {
        closesocket(s);
        return -1;
    }

    if (listen(s, backlog > 0 ? backlog : 128) == SOCKET_ERROR) {
        closesocket(s);
        return -1;
    }

    return (int64_t)s;
}

// Unix Domain Sockets (AF_UNIX) Client Connector (uWebSockets us_socket_context_connect_unix pattern).
int64_t wing_tcp_connect_unix(wing_bytes_ro path) {
    wing_tcp_init();

    char path_str[108];
    slice_to_cstr(path, path_str, sizeof(path_str));
    if (path_str[0] == '\0') {
        return -1;
    }

    SOCKET s = socket(AF_UNIX, SOCK_STREAM, 0);
    if (s == INVALID_SOCKET) {
        return -1;
    }
#ifdef _WIN32
    SetHandleInformation((HANDLE)s, HANDLE_FLAG_INHERIT, 0);
#endif

    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, path_str, sizeof(addr.sun_path) - 1);

    if (connect(s, (struct sockaddr *)&addr, sizeof(addr)) == SOCKET_ERROR) {
        closesocket(s);
        return -1;
    }

    return (int64_t)s;
}

// Begins a non-blocking AF_UNIX client connection.
// Sets *out_state to: 0 = connected immediately, 1 = in progress (wait POLL_WRITE), -1 = failed.
int64_t wing_tcp_connect_unix_begin(wing_bytes_ro path, int32_t *out_state) {
    if (out_state) *out_state = -1;
    wing_tcp_init();

    struct sockaddr_un addr;
    if (path.data == NULL || path.len <= 0 || (size_t)path.len >= sizeof(addr.sun_path)) {
        return -1;
    }
    char path_str[108];
    slice_to_cstr(path, path_str, sizeof(path_str));
    if (path_str[0] == '\0') {
        return -1;
    }

    SOCKET s = socket(AF_UNIX, SOCK_STREAM, 0);
    if (s == INVALID_SOCKET) {
        return -1;
    }
#ifdef _WIN32
    SetHandleInformation((HANDLE)s, HANDLE_FLAG_INHERIT, 0);
    u_long nonblocking = 1;
    ioctlsocket(s, FIONBIO, &nonblocking);
#else
    int flags = fcntl(s, F_GETFL, 0);
    if (flags >= 0) {
        fcntl(s, F_SETFL, flags | O_NONBLOCK);
    }
#endif

    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, path_str, sizeof(addr.sun_path) - 1);

    if (connect(s, (struct sockaddr *)&addr, sizeof(addr)) == SOCKET_ERROR) {
#ifdef _WIN32
        int err = WSAGetLastError();
        if (err == WSAEWOULDBLOCK || err == WSAEINPROGRESS) {
            if (out_state) *out_state = 1;
            return (int64_t)s;
        }
#else
        if (errno == EINPROGRESS || errno == EAGAIN || errno == EWOULDBLOCK) {
            if (out_state) *out_state = 1;
            return (int64_t)s;
        }
#endif
        closesocket(s);
        return -1;
    }

    if (out_state) *out_state = 0;
    return (int64_t)s;
}

// Adopts an externally accepted or inherited socket descriptor (uWebSockets us_adopt_accepted_socket pattern).
// Sanitizes the handle, sets non-blocking mode, disables inheritance, and configures TCP_NODELAY & SO_KEEPALIVE.
int64_t wing_adopt_socket(int64_t raw_fd) {
    if (raw_fd <= 0) return -1;
    wing_tcp_init();

    SOCKET s = (SOCKET)raw_fd;

#ifdef _WIN32
    // uSockets #263: Do not inherit socket handles into child processes
    SetHandleInformation((HANDLE)s, HANDLE_FLAG_INHERIT, 0);
    u_long mode = 1;
    ioctlsocket(s, FIONBIO, &mode);
#else
    int flags = fcntl(s, F_GETFL, 0);
    if (flags != -1) {
        fcntl(s, F_SETFL, flags | O_NONBLOCK);
    }
#endif

    int nodelay = 1;
    setsockopt(s, IPPROTO_TCP, TCP_NODELAY, (const char *)&nodelay, sizeof(nodelay));

    int keepalive = 1;
    setsockopt(s, SOL_SOCKET, SO_KEEPALIVE, (const char *)&keepalive, sizeof(keepalive));

    return (int64_t)s;
}

// Retrieves the locally bound port for an IPv4 or IPv6 socket.
uint16_t wing_tcp_getsockname_port(int64_t sock_fd) {
    if (sock_fd <= 0) return 0;
    struct sockaddr_storage ss;
#ifdef _WIN32
    int len = (int)sizeof(ss);
#else
    socklen_t len = (socklen_t)sizeof(ss);
#endif
    memset(&ss, 0, sizeof(ss));
    if (getsockname((SOCKET)sock_fd, (struct sockaddr *)&ss, &len) == SOCKET_ERROR) {
        return 0;
    }
    if (ss.ss_family == AF_INET6) {
        return ntohs(((const struct sockaddr_in6 *)&ss)->sin6_port);
    }
    return ntohs(((const struct sockaddr_in *)&ss)->sin_port);
}

int32_t wing_tcp_get_peer_ip(int64_t sock_fd, wing_bytes_rw out_ip) {
    if (out_ip.data == NULL || out_ip.len <= 0) return -1;
    const char *fallback = "127.0.0.1";
    if (sock_fd > 0) {
        struct sockaddr_in addr;
#ifdef _WIN32
        int len = sizeof(addr);
#else
        socklen_t len = sizeof(addr);
#endif
        memset(&addr, 0, sizeof(addr));
        if (getpeername((SOCKET)sock_fd, (struct sockaddr *)&addr, &len) == 0 && addr.sin_family == AF_INET) {
            const char *ip_str = inet_ntoa(addr.sin_addr);
            if (ip_str && ip_str[0] != '\0') {
                int64_t ip_len = (int64_t)strlen(ip_str);
                if (ip_len > out_ip.len) ip_len = out_ip.len;
                memcpy(out_ip.data, ip_str, (size_t)ip_len);
                return (int32_t)ip_len;
            }
        }
    }
    int64_t fb_len = (int64_t)strlen(fallback);
    if (fb_len > out_ip.len) fb_len = out_ip.len;
    memcpy(out_ip.data, fallback, (size_t)fb_len);
    return (int32_t)fb_len;
}

// Accepts an incoming connection with an optional timeout in milliseconds.
int64_t wing_tcp_accept(int64_t listener_fd, uint32_t timeout_ms) {
    if (listener_fd <= 0) return -1;
    SOCKET l = (SOCKET)listener_fd;

    if (timeout_ms > 0) {
        int sel = wing_wait_fd(l, 0, timeout_ms);
        if (sel <= 0) {
            return sel == 0 ? 0 : -1;
        }
    }

    struct sockaddr_storage client_addr;
#ifdef _WIN32
    int addr_len = (int)sizeof(client_addr);
#else
    socklen_t addr_len = (socklen_t)sizeof(client_addr);
#endif
    SOCKET client_sock = accept(l, (struct sockaddr *)&client_addr, &addr_len);
    if (client_sock == INVALID_SOCKET) {
        return -1;
    }
#ifdef _WIN32
    // uSockets #263: Do not inherit accepted socket handles into child processes
    SetHandleInformation((HANDLE)client_sock, HANDLE_FLAG_INHERIT, 0);
#endif

    int nodelay = 1;
    setsockopt(client_sock, IPPROTO_TCP, TCP_NODELAY, (const char *)&nodelay, sizeof(nodelay));

    return (int64_t)client_sock;
}

static int wing_parse_ip_sockaddr(const char *ip_str, uint16_t port, int force_family, struct sockaddr_storage *out_ss,
                                  int *out_family, int *out_len);

// Resolves host (IPv4, IPv6, bracketed IPv6, "localhost", or DNS via getaddrinfo) into `ss`.
// `ip_family`: 0 = AF_UNSPEC, 1 = AF_INET, 2 = AF_INET6. Returns 0 on success, -1 on failure.
static int wing_resolve_tcp_host_family(wing_bytes_ro host, uint16_t port, int allow_empty_loopback, int32_t ip_family,
                                        struct sockaddr_storage *ss, int *out_family,
#ifdef _WIN32
                                        int *out_len
#else
                                        socklen_t *out_len
#endif
) {
    memset(ss, 0, sizeof(*ss));
    if (ip_family < 0 || ip_family > 2) return -1;
    int req_family = (ip_family == 1) ? AF_INET : ((ip_family == 2) ? AF_INET6 : AF_UNSPEC);

    char host_str[256];
    if (host.data == NULL || host.len <= 0) {
        if (!allow_empty_loopback) return -1;
        host_str[0] = '\0';
    } else {
        if (host.len >= (int64_t)sizeof(host_str)) return -1;
        slice_to_cstr(host, host_str, sizeof(host_str));
    }

    // Strip optional RFC 3986 brackets around IPv6 literals ("[::1]" -> "::1").
    size_t hlen = strlen(host_str);
    if (hlen >= 2 && host_str[0] == '[' && host_str[hlen - 1] == ']') {
        memmove(host_str, host_str + 1, hlen - 2);
        host_str[hlen - 2] = '\0';
    }

    struct in_addr addr4;
    struct in6_addr addr6;
    if (host_str[0] == '\0' || strcmp(host_str, "localhost") == 0) {
        if (req_family == AF_INET6) {
            struct sockaddr_in6 *s6 = (struct sockaddr_in6 *)ss;
            s6->sin6_family = AF_INET6;
            s6->sin6_port = htons(port);
            s6->sin6_addr = in6addr_loopback;
            *out_family = AF_INET6;
            *out_len = (int)sizeof(struct sockaddr_in6);
            return 0;
        }
        struct sockaddr_in *s4 = (struct sockaddr_in *)ss;
        s4->sin_family = AF_INET;
        s4->sin_port = htons(port);
        s4->sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        *out_family = AF_INET;
        *out_len = (int)sizeof(struct sockaddr_in);
        return 0;
    }
    if (inet_pton(AF_INET, host_str, &addr4) == 1) {
        if (req_family == AF_INET6) return -1;
        struct sockaddr_in *s4 = (struct sockaddr_in *)ss;
        s4->sin_family = AF_INET;
        s4->sin_port = htons(port);
        s4->sin_addr = addr4;
        *out_family = AF_INET;
        *out_len = (int)sizeof(struct sockaddr_in);
        return 0;
    }
    if (inet_pton(AF_INET6, host_str, &addr6) == 1) {
        if (req_family == AF_INET) return -1;
        struct sockaddr_in6 *s6 = (struct sockaddr_in6 *)ss;
        s6->sin6_family = AF_INET6;
        s6->sin6_port = htons(port);
        s6->sin6_addr = addr6;
        *out_family = AF_INET6;
        *out_len = (int)sizeof(struct sockaddr_in6);
        return 0;
    }
#if !defined(__wasm__)
    struct addrinfo hints;
    struct addrinfo *res_info = NULL;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = req_family;
    hints.ai_socktype = SOCK_STREAM;
    if (getaddrinfo(host_str, NULL, &hints, &res_info) != 0 || res_info == NULL) {
        return -1;
    }
    int ok = -1;
    for (struct addrinfo *ai = res_info; ai != NULL; ai = ai->ai_next) {
        if (ai->ai_family == AF_INET && req_family != AF_INET6 && ai->ai_addrlen <= sizeof(*ss)) {
            memcpy(ss, ai->ai_addr, ai->ai_addrlen);
            ((struct sockaddr_in *)ss)->sin_port = htons(port);
            *out_family = AF_INET;
            *out_len = (int)sizeof(struct sockaddr_in);
            ok = 0;
            break;
        }
        if (ai->ai_family == AF_INET6 && req_family != AF_INET && ai->ai_addrlen <= sizeof(*ss)) {
            memcpy(ss, ai->ai_addr, ai->ai_addrlen);
            ((struct sockaddr_in6 *)ss)->sin6_port = htons(port);
            *out_family = AF_INET6;
            *out_len = (int)sizeof(struct sockaddr_in6);
            ok = 0;
            break;
        }
    }
    freeaddrinfo(res_info);
    return ok;
#else
    return -1;
#endif
}

static int wing_resolve_tcp_host(wing_bytes_ro host, uint16_t port, int allow_empty_loopback,
                                 struct sockaddr_storage *ss, int *out_family,
#ifdef _WIN32
                                 int *out_len
#else
                                 socklen_t *out_len
#endif
) {
    return wing_resolve_tcp_host_family(host, port, allow_empty_loopback, 0, ss, out_family, out_len);
}

static int wing_append_unique_ip_line(wing_bytes_rw out_buf, int64_t *pos, char seen[16][INET6_ADDRSTRLEN],
                                      int *seen_count, const char *ip_str) {
    if (ip_str == NULL || ip_str[0] == '\0') return 0;
    for (int i = 0; i < *seen_count; i++) {
        if (strcmp(seen[i], ip_str) == 0) return 0;
    }
    if (*seen_count >= 16) return 0;
    size_t slen = strlen(ip_str);
    if (slen >= INET6_ADDRSTRLEN || *pos + (int64_t)slen + 1 > out_buf.len) return 0;
    memcpy(seen[*seen_count], ip_str, slen + 1);
    (*seen_count)++;
    memcpy(out_buf.data + *pos, ip_str, slen);
    *pos += (int64_t)slen;
    out_buf.data[*pos] = '\n';
    *pos += 1;
    return 1;
}

// Resolves host (IPv4, IPv6, bracketed IPv6, "localhost", or DNS via getaddrinfo) into newline-separated
// canonical IP strings. `ip_family`: 0 = Auto, 1 = IPv4Only, 2 = IPv6Only. Returns byte count (> 0) or -1.
int32_t wing_net_resolve_host(wing_bytes_ro host, int32_t ip_family, wing_bytes_rw out_buf) {
    if (host.data == NULL || host.len <= 0 || host.len >= 256) return -1;
    if (ip_family < 0 || ip_family > 2 || out_buf.data == NULL || out_buf.len <= 0) return -1;
    if (wing_tcp_init() != 0) return -1;

    char host_str[256];
    slice_to_cstr(host, host_str, sizeof(host_str));
    size_t hlen = strlen(host_str);
    if (hlen >= 2 && host_str[0] == '[' && host_str[hlen - 1] == ']') {
        memmove(host_str, host_str + 1, hlen - 2);
        host_str[hlen - 2] = '\0';
    }
    if (host_str[0] == '\0') return -1;

    int64_t pos = 0;
    char seen[16][INET6_ADDRSTRLEN];
    int seen_count = 0;

    if (strcmp(host_str, "localhost") == 0) {
        if (ip_family != 2) wing_append_unique_ip_line(out_buf, &pos, seen, &seen_count, "127.0.0.1");
        if (ip_family != 1) wing_append_unique_ip_line(out_buf, &pos, seen, &seen_count, "::1");
        return pos > 0 ? (int32_t)pos : -1;
    }

    struct in_addr addr4;
    struct in6_addr addr6;
    char ipbuf[INET6_ADDRSTRLEN];
    if (inet_pton(AF_INET, host_str, &addr4) == 1) {
        if (ip_family == 2) return -1;
        if (inet_ntop(AF_INET, &addr4, ipbuf, sizeof(ipbuf)) == NULL) return -1;
        wing_append_unique_ip_line(out_buf, &pos, seen, &seen_count, ipbuf);
        return pos > 0 ? (int32_t)pos : -1;
    }
    if (inet_pton(AF_INET6, host_str, &addr6) == 1) {
        if (ip_family == 1) return -1;
        if (inet_ntop(AF_INET6, &addr6, ipbuf, sizeof(ipbuf)) == NULL) return -1;
        wing_append_unique_ip_line(out_buf, &pos, seen, &seen_count, ipbuf);
        return pos > 0 ? (int32_t)pos : -1;
    }

    int req_family = (ip_family == 1) ? AF_INET : ((ip_family == 2) ? AF_INET6 : AF_UNSPEC);
    struct addrinfo hints;
    struct addrinfo *res_info = NULL;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = req_family;
    hints.ai_socktype = SOCK_STREAM;
    if (getaddrinfo(host_str, NULL, &hints, &res_info) != 0 || res_info == NULL) {
        return -1;
    }
    for (struct addrinfo *ai = res_info; ai != NULL; ai = ai->ai_next) {
        ipbuf[0] = '\0';
        if (ai->ai_family == AF_INET && req_family != AF_INET6) {
            const struct sockaddr_in *s4 = (const struct sockaddr_in *)ai->ai_addr;
            if (inet_ntop(AF_INET, &s4->sin_addr, ipbuf, sizeof(ipbuf)) != NULL) {
                wing_append_unique_ip_line(out_buf, &pos, seen, &seen_count, ipbuf);
            }
        } else if (ai->ai_family == AF_INET6 && req_family != AF_INET) {
            const struct sockaddr_in6 *s6 = (const struct sockaddr_in6 *)ai->ai_addr;
            if (inet_ntop(AF_INET6, &s6->sin6_addr, ipbuf, sizeof(ipbuf)) != NULL) {
                wing_append_unique_ip_line(out_buf, &pos, seen, &seen_count, ipbuf);
            }
        }
    }
    freeaddrinfo(res_info);
    return pos > 0 ? (int32_t)pos : -1;
}

static int64_t wing_tcp_connect_sockaddr(const struct sockaddr_storage *ss, int family,
#ifdef _WIN32
                                         int addr_len,
#else
                                         socklen_t addr_len,
#endif
                                         uint32_t timeout_ms, wing_bytes_ro local_bind_addr) {
    SOCKET s = socket(family, SOCK_STREAM, IPPROTO_TCP);
    if (s == INVALID_SOCKET) {
        return -1;
    }
#ifdef _WIN32
    // uSockets #263: Do not inherit socket handles into child processes (prevents keep-alive hangs)
    SetHandleInformation((HANDLE)s, HANDLE_FLAG_INHERIT, 0);
#endif

    int nodelay = 1;
    setsockopt(s, IPPROTO_TCP, TCP_NODELAY, (const char *)&nodelay, sizeof(nodelay));

    if (local_bind_addr.data != NULL && local_bind_addr.len > 0) {
        if (local_bind_addr.len >= 128) {
            closesocket(s);
            return -1;
        }
        char bind_str[128];
        slice_to_cstr(local_bind_addr, bind_str, sizeof(bind_str));
        size_t blen = strlen(bind_str);
        if (blen >= 2 && bind_str[0] == '[' && bind_str[blen - 1] == ']') {
            memmove(bind_str, bind_str + 1, blen - 2);
            bind_str[blen - 2] = '\0';
        }
        struct sockaddr_storage bind_ss;
        int bind_family = 0;
        int bind_len = 0;
        if (wing_parse_ip_sockaddr(bind_str, 0, family, &bind_ss, &bind_family, &bind_len) != 0) {
            closesocket(s);
            return -1;
        }
#ifdef _WIN32
        if (bind(s, (struct sockaddr *)&bind_ss, bind_len) != 0) {
#else
        if (bind(s, (struct sockaddr *)&bind_ss, (socklen_t)bind_len) != 0) {
#endif
            closesocket(s);
            return -1;
        }
    }

    if (timeout_ms == 0) {
        if (connect(s, (const struct sockaddr *)ss, addr_len) == SOCKET_ERROR) {
            closesocket(s);
            return -1;
        }
        return (int64_t)s;
    }

#ifdef _WIN32
    u_long nonblocking = 1;
    ioctlsocket(s, FIONBIO, &nonblocking);
#else
    int flags = fcntl(s, F_GETFL, 0);
    fcntl(s, F_SETFL, flags | O_NONBLOCK);
#endif

    int res = connect(s, (const struct sockaddr *)ss, addr_len);
    if (res == SOCKET_ERROR) {
#ifdef _WIN32
        int err = WSAGetLastError();
        if (err != WSAEWOULDBLOCK) {
            closesocket(s);
            return -1;
        }
#else
        if (errno != EINPROGRESS) {
            closesocket(s);
            return -1;
        }
#endif
        int sel = wing_wait_fd(s, 1, timeout_ms);
        if (sel <= 0) {
            closesocket(s);
            return -1;
        }

        int sock_err = 0;
#ifdef _WIN32
        int err_len = (int)sizeof(sock_err);
#else
        socklen_t err_len = (socklen_t)sizeof(sock_err);
#endif
        getsockopt(s, SOL_SOCKET, SO_ERROR, (char *)&sock_err, &err_len);
        if (sock_err != 0) {
            closesocket(s);
            return -1;
        }
    }

#ifdef _WIN32
    nonblocking = 0;
    ioctlsocket(s, FIONBIO, &nonblocking);
#else
    flags = fcntl(s, F_GETFL, 0);
    fcntl(s, F_SETFL, flags & ~O_NONBLOCK);
#endif

    return (int64_t)s;
}

// Connects strictly to a numeric IPv4 or IPv6 literal without invoking DNS (getaddrinfo).
// Rejects hostnames, "localhost", and empty strings to prevent TOCTOU DNS rebinding.
int64_t wing_tcp_connect_ip(wing_bytes_ro ip, uint16_t port, uint32_t timeout_ms, int32_t ip_family,
                            wing_bytes_ro local_bind_addr) {
    if (ip.data == NULL || ip.len <= 0 || ip.len >= 128 || port == 0 || ip_family < 0 || ip_family > 2) return -1;
    wing_tcp_init();

    char ip_str[128];
    slice_to_cstr(ip, ip_str, sizeof(ip_str));
    size_t slen = strlen(ip_str);
    if (slen >= 2 && ip_str[0] == '[' && ip_str[slen - 1] == ']') {
        memmove(ip_str, ip_str + 1, slen - 2);
        ip_str[slen - 2] = '\0';
    }
    if (ip_str[0] == '\0') return -1;

    struct sockaddr_storage ss;
    memset(&ss, 0, sizeof(ss));
    int family = 0;
#ifdef _WIN32
    int addr_len = 0;
#else
    socklen_t addr_len = 0;
#endif
    struct in_addr addr4;
    struct in6_addr addr6;
    if (inet_pton(AF_INET, ip_str, &addr4) == 1) {
        if (ip_family == 2) return -1;
        struct sockaddr_in *s4 = (struct sockaddr_in *)&ss;
        s4->sin_family = AF_INET;
        s4->sin_port = htons(port);
        s4->sin_addr = addr4;
        family = AF_INET;
        addr_len = (int)sizeof(struct sockaddr_in);
    } else if (inet_pton(AF_INET6, ip_str, &addr6) == 1) {
        if (ip_family == 1) return -1;
        struct sockaddr_in6 *s6 = (struct sockaddr_in6 *)&ss;
        s6->sin6_family = AF_INET6;
        s6->sin6_port = htons(port);
        s6->sin6_addr = addr6;
        family = AF_INET6;
        addr_len = (int)sizeof(struct sockaddr_in6);
    } else {
        return -1;
    }
    return wing_tcp_connect_sockaddr(&ss, family, addr_len, timeout_ms, local_bind_addr);
}

// Connects to remote host:port with timeout, address family constraint
// (0 = AF_UNSPEC, 1 = AF_INET, 2 = AF_INET6), and optional local_bind_addr bind() before connect().
int64_t wing_tcp_connect_ex(wing_bytes_ro host, uint16_t port, uint32_t timeout_ms, int32_t ip_family,
                            wing_bytes_ro local_bind_addr) {
    if (port == 0 || ip_family < 0 || ip_family > 2) return -1;
    wing_tcp_init();

    struct sockaddr_storage ss;
    int family = AF_INET;
#ifdef _WIN32
    int addr_len = 0;
#else
    socklen_t addr_len = 0;
#endif
    if (wing_resolve_tcp_host_family(host, port, 1, ip_family, &ss, &family, &addr_len) != 0) {
        return -1;
    }
    return wing_tcp_connect_sockaddr(&ss, family, addr_len, timeout_ms, local_bind_addr);
}

// Connects to remote host:port (IPv4, IPv6, or DNS via getaddrinfo) with timeout in milliseconds.
int64_t wing_tcp_connect(wing_bytes_ro host, uint16_t port, uint32_t timeout_ms) {
    wing_bytes_ro empty_bind = {NULL, 0};
    return wing_tcp_connect_ex(host, port, timeout_ms, 0, empty_bind);
}

// Begins a non-blocking TCP client connection (IPv4, IPv6, or hostname).
// Sets *out_state to: 0 = connected immediately, 1 = in progress (wait POLL_WRITE), -1 = failed.
int64_t wing_tcp_connect_begin(wing_bytes_ro host, uint16_t port, int32_t *out_state) {
    if (out_state) *out_state = -1;
    if (host.data == NULL || host.len <= 0 || host.len >= 256 || port == 0) {
        return -1;
    }
    wing_tcp_init();

    struct sockaddr_storage ss;
    int family = AF_INET;
#ifdef _WIN32
    int addr_len = 0;
#else
    socklen_t addr_len = 0;
#endif
    if (wing_resolve_tcp_host(host, port, 0, &ss, &family, &addr_len) != 0) {
        return -1;
    }

    SOCKET s = socket(family, SOCK_STREAM, IPPROTO_TCP);
    if (s == INVALID_SOCKET) {
        return -1;
    }
#ifdef _WIN32
    SetHandleInformation((HANDLE)s, HANDLE_FLAG_INHERIT, 0);
    u_long nonblocking = 1;
    ioctlsocket(s, FIONBIO, &nonblocking);
#else
    int flags = fcntl(s, F_GETFL, 0);
    if (flags >= 0) {
        fcntl(s, F_SETFL, flags | O_NONBLOCK);
    }
#endif
    int nodelay = 1;
    setsockopt(s, IPPROTO_TCP, TCP_NODELAY, (const char *)&nodelay, sizeof(nodelay));

    if (connect(s, (struct sockaddr *)&ss, addr_len) == SOCKET_ERROR) {
#ifdef _WIN32
        int err = WSAGetLastError();
        if (err == WSAEWOULDBLOCK || err == WSAEINPROGRESS) {
            if (out_state) *out_state = 1;
            return (int64_t)s;
        }
#else
        if (errno == EINPROGRESS || errno == EAGAIN || errno == EWOULDBLOCK) {
            if (out_state) *out_state = 1;
            return (int64_t)s;
        }
#endif
        closesocket(s);
        return -1;
    }

    if (out_state) *out_state = 0;
    return (int64_t)s;
}

// Verifies completion of a non-blocking TCP/Unix connect via SO_ERROR.
// Returns 0 on successful connection, or -1 if the handshake failed.
int32_t wing_tcp_connect_finish(int64_t sock_fd) {
    if (sock_fd <= 0) return -1;
    int sock_err = 0;
#ifdef _WIN32
    int err_len = (int)sizeof(sock_err);
#else
    socklen_t err_len = (socklen_t)sizeof(sock_err);
#endif
    if (getsockopt((SOCKET)sock_fd, SOL_SOCKET, SO_ERROR, (char *)&sock_err, &err_len) != 0) {
        return -1;
    }
    return sock_err == 0 ? 0 : -1;
}

// Non-blocking readiness poll for an in-progress TCP connect.
// Returns: 0 = connected, 1 = still in progress, -1 = failed.
int32_t wing_tcp_connect_poll(int64_t sock_fd) {
    if (sock_fd <= 0) return -1;
    int ready = wing_wait_fd((SOCKET)sock_fd, 1, 0);
    if (ready == 0) return 1;
    if (ready < 0) return -1;
    return wing_tcp_connect_finish(sock_fd);
}

#ifdef _WIN32
extern int32_t wing_rio_hs_recv(int64_t sock_fd, uint8_t *dst, int64_t len, uint32_t timeout_ms);
extern int32_t wing_rio_hs_send(int64_t sock_fd, const uint8_t *data, int64_t len);
#endif

// Sends bytes to socket, ensuring complete write across non-blocking transient buffers.
int32_t wing_tcp_send(int64_t sock_fd, wing_bytes_ro data) {
    if (sock_fd <= 0 || data.data == NULL || data.len <= 0) return 0;
#ifdef _WIN32
    int32_t rio_sent = wing_rio_hs_send(sock_fd, data.data, data.len);
    if (rio_sent != -99) return rio_sent;
#endif
    SOCKET s = (SOCKET)sock_fd;
    const char *ptr = (const char *)data.data;
    size_t remaining = (size_t)data.len;

    while (remaining > 0) {
#ifdef _WIN32
        int sent = send(s, ptr, (int)remaining, 0);
        if (sent < 0) {
            int err = WSAGetLastError();
            if (err == WSAEWOULDBLOCK) {
                int32_t written = (int32_t)(data.len - remaining);
                return written > 0 ? written : -2;
            }
            return (data.len - remaining) > 0 ? (int32_t)(data.len - remaining) : -1;
        }
#else
        ssize_t sent = send(s, ptr, remaining, MSG_NOSIGNAL);
        if (sent < 0) {
            if (errno == EINTR) continue;
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                int32_t written = (int32_t)(data.len - remaining);
                return written > 0 ? written : -2;
            }
            return (data.len - remaining) > 0 ? (int32_t)(data.len - remaining) : -1;
        }
#endif
        if (sent == 0) break;
        ptr += sent;
        remaining -= (size_t)sent;
    }
    return (int32_t)(data.len - remaining);
}

// Receives bytes from socket into slice buffer.
int32_t wing_tcp_recv(int64_t sock_fd, wing_bytes_rw buf, uint32_t timeout_ms) {
    if (sock_fd <= 0 || buf.data == NULL || buf.len <= 0) return -1;
#ifdef _WIN32
    int32_t rio_got = wing_rio_hs_recv(sock_fd, buf.data, buf.len, timeout_ms);
    if (rio_got != -99) return rio_got;
#endif
    SOCKET s = (SOCKET)sock_fd;

    if (timeout_ms > 0) {
        int sel = wing_wait_fd(s, 0, timeout_ms);
        if (sel == 0) return -2; // Timeout
        if (sel < 0) return -1;  // Error
    }

#ifdef _WIN32
    int recvd = recv(s, (char *)buf.data, (int)buf.len, 0);
    if (recvd < 0 && WSAGetLastError() == WSAEWOULDBLOCK) return -2;
    return (int32_t)recvd;
#else
    ssize_t recvd = 0;
    do {
        recvd = recv(s, (char *)buf.data, (size_t)buf.len, 0);
    } while (recvd < 0 && errno == EINTR);
    if (recvd < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) return -2;
    return (int32_t)recvd;
#endif
}

// Closes socket handle.
void wing_tcp_close(int64_t sock_fd) {
    if (sock_fd > 0) {
        closesocket((SOCKET)sock_fd);
    }
}

// Shuts down socket send/receive channels (how: 0=SHUT_RD, 1=SHUT_WR, 2=SHUT_RDWR).
int32_t wing_tcp_shutdown(int64_t sock_fd, int32_t how) {
    if (sock_fd <= 0) return -1;
#if defined(__wasm__)
    if (sock_fd >= WASM_MAX_SOCKETS || !g_wasm_sockets[sock_fd].active) return -1;
    if (how == 1 || how == 2) {
        g_wasm_sockets[sock_fd].write_shut = 1;
    }
    return 0;
#elif defined(_WIN32)
    int win_how = SD_SEND;
    if (how == 0)
        win_how = SD_RECEIVE;
    else if (how == 2)
        win_how = SD_BOTH;
    return shutdown((SOCKET)sock_fd, win_how) == 0 ? 0 : -1;
#else
    int posix_how = SHUT_WR;
    if (how == 0)
        posix_how = SHUT_RD;
    else if (how == 2)
        posix_how = SHUT_RDWR;
    return shutdown((int)sock_fd, posix_how) == 0 ? 0 : -1;
#endif
}

// Configures SO_LINGER on socket (onoff: 0/1, linger_sec: timeout in seconds).
int32_t wing_tcp_set_linger(int64_t sock_fd, int32_t onoff, int32_t linger_sec) {
    if (sock_fd <= 0) return -1;
#if defined(__wasm__)
    (void)onoff;
    (void)linger_sec;
    return 0;
#else
    struct linger l;
    l.l_onoff = (u_short)(onoff ? 1 : 0);
    l.l_linger = (u_short)(linger_sec > 0 ? linger_sec : 0);
    return setsockopt((SOCKET)sock_fd, SOL_SOCKET, SO_LINGER, (const char *)&l, sizeof(l)) == 0 ? 0 : -1;
#endif
}

// Configures TCP_NODELAY (Nagle algorithm bypass) on socket.
int32_t wing_tcp_set_nodelay(int64_t sock_fd, int32_t enable) {
    if (sock_fd <= 0) return -1;
#if defined(__wasm__)
    (void)enable;
    return 0;
#else
    int val = enable ? 1 : 0;
    return setsockopt((SOCKET)sock_fd, IPPROTO_TCP, TCP_NODELAY, (const char *)&val, sizeof(val)) == 0 ? 0 : -1;
#endif
}

// Configures SO_REUSEADDR on socket.
int32_t wing_tcp_set_reuseaddr(int64_t sock_fd, int32_t enable) {
    if (sock_fd <= 0) return -1;
#if defined(__wasm__)
    (void)enable;
    return 0;
#elif defined(_WIN32)
    int val = enable ? 1 : 0;
    int res = setsockopt((SOCKET)sock_fd, SOL_SOCKET, SO_REUSEADDR, (const char *)&val, sizeof(val));
    if (res != 0) {
        int err = WSAGetLastError();
        if (err == WSAEINVAL) return 0; // Already bound with SO_EXCLUSIVEADDRUSE
        return -1;
    }
    return 0;
#else
    int val = enable ? 1 : 0;
    return setsockopt((SOCKET)sock_fd, SOL_SOCKET, SO_REUSEADDR, (const char *)&val, sizeof(val)) == 0 ? 0 : -1;
#endif
}

// Configures SO_REUSEPORT on socket (Linux / FreeBSD).
int32_t wing_tcp_set_reuseport(int64_t sock_fd, int32_t enable) {
    if (sock_fd <= 0) return -1;
#if defined(__wasm__)
    (void)enable;
    return 0;
#elif defined(SO_REUSEPORT)
    int val = enable ? 1 : 0;
    return setsockopt((SOCKET)sock_fd, SOL_SOCKET, SO_REUSEPORT, (const char *)&val, sizeof(val)) == 0 ? 0 : -1;
#else
    (void)enable;
    return 0;
#endif
}

// Cryptographically secure pseudorandom byte generator (BCryptGenRandom / RtlGenRandom on Windows, getrandom on Linux).
int32_t wing_crypto_random_bytes(wing_bytes_rw out) {
    if (out.data == NULL || out.len <= 0) return -1;
#ifdef _WIN32
#ifndef LOAD_LIBRARY_SEARCH_SYSTEM32
#define LOAD_LIBRARY_SEARCH_SYSTEM32 0x00000800u
#endif
    typedef LONG(WINAPI * BCryptGenRandomFn)(PVOID, PUCHAR, ULONG, ULONG);
    typedef BOOLEAN(NTAPI * RtlGenRandomFn)(PVOID, ULONG);
    static volatile PVOID g_pfnBCryptGenRandom = NULL;
    static volatile PVOID g_pfnRtlGenRandom = NULL;

    BCryptGenRandomFn pfnBCrypt =
        (BCryptGenRandomFn)InterlockedCompareExchangePointer(&g_pfnBCryptGenRandom, NULL, NULL);
    if (pfnBCrypt == NULL) {
        HMODULE hBCrypt = LoadLibraryExA("bcrypt.dll", NULL, LOAD_LIBRARY_SEARCH_SYSTEM32);
        if (hBCrypt != NULL) {
            void *sym = (void *)GetProcAddress(hBCrypt, "BCryptGenRandom");
            if (sym != NULL) {
                PVOID prev = InterlockedCompareExchangePointer(&g_pfnBCryptGenRandom, sym, NULL);
                if (prev != NULL) {
                    FreeLibrary(hBCrypt);
                    pfnBCrypt = (BCryptGenRandomFn)prev;
                } else {
                    pfnBCrypt = (BCryptGenRandomFn)sym;
                }
            } else {
                FreeLibrary(hBCrypt);
            }
        }
    }
    if (pfnBCrypt != NULL) {
        size_t offset = 0;
        size_t total = (size_t)out.len;
        while (offset < total) {
            ULONG chunk = (total - offset) > 0x7FFFFFFFu ? 0x7FFFFFFFu : (ULONG)(total - offset);
            // BCRYPT_USE_SYSTEM_PREFERRED_RNG = 0x00000002
            if (pfnBCrypt(NULL, (PUCHAR)(out.data + offset), chunk, 0x00000002u) < 0) {
                return -1;
            }
            offset += (size_t)chunk;
        }
        return 0;
    }

    RtlGenRandomFn pfnRtl = (RtlGenRandomFn)InterlockedCompareExchangePointer(&g_pfnRtlGenRandom, NULL, NULL);
    if (pfnRtl == NULL) {
        HMODULE hAdvApi = LoadLibraryExA("advapi32.dll", NULL, LOAD_LIBRARY_SEARCH_SYSTEM32);
        if (hAdvApi != NULL) {
            void *sym = (void *)GetProcAddress(hAdvApi, "SystemFunction036");
            if (sym != NULL) {
                PVOID prev = InterlockedCompareExchangePointer(&g_pfnRtlGenRandom, sym, NULL);
                if (prev != NULL) {
                    FreeLibrary(hAdvApi);
                    pfnRtl = (RtlGenRandomFn)prev;
                } else {
                    pfnRtl = (RtlGenRandomFn)sym;
                }
            } else {
                FreeLibrary(hAdvApi);
            }
        }
    }
    if (pfnRtl != NULL) {
        size_t offset = 0;
        size_t total = (size_t)out.len;
        while (offset < total) {
            ULONG chunk = (total - offset) > 0x7FFFFFFFu ? 0x7FFFFFFFu : (ULONG)(total - offset);
            if (!pfnRtl(out.data + offset, chunk)) {
                return -1;
            }
            offset += (size_t)chunk;
        }
        return 0;
    }
    return -1;
#elif defined(__linux__) && defined(SYS_getrandom)
    size_t offset = 0;
    size_t total = (size_t)out.len;
    while (offset < total) {
        long res = syscall(SYS_getrandom, out.data + offset, total - offset, 0);
        if (res < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        if (res == 0) return -1;
        offset += (size_t)res;
    }
    return 0;
#elif defined(__APPLE__) || defined(__FreeBSD__) || defined(__OpenBSD__) || defined(__NetBSD__)
    arc4random_buf(out.data, (size_t)out.len);
    return 0;
#else
    int flags = O_RDONLY;
#ifdef O_CLOEXEC
    flags |= O_CLOEXEC;
#endif
    int fd = open("/dev/urandom", flags);
    if (fd >= 0) {
        size_t offset = 0;
        size_t total = (size_t)out.len;
        while (offset < total) {
            ssize_t res = read(fd, out.data + offset, total - offset);
            if (res < 0) {
                if (errno == EINTR) continue;
                close(fd);
                return -1;
            }
            if (res == 0) {
                close(fd);
                return -1;
            }
            offset += (size_t)res;
        }
        close(fd);
        return 0;
    }
    return -1;
#endif
}

// Configures TCP_DEFER_ACCEPT (Linux) or SO_ACCEPTFILTER (FreeBSD) to defer accept until first data packet arrives.
int32_t wing_tcp_set_defer_accept(int64_t sock_fd, int32_t timeout_sec) {
    if (sock_fd <= 0) return -1;
#if defined(__linux__) && defined(TCP_DEFER_ACCEPT)
    int val = timeout_sec > 0 ? timeout_sec : 1;
    return setsockopt((int)sock_fd, IPPROTO_TCP, TCP_DEFER_ACCEPT, (const void *)&val, sizeof(val));
#elif defined(__FreeBSD__) && defined(SO_ACCEPTFILTER)
    struct accept_filter_arg afa;
    memset(&afa, 0, sizeof(afa));
    strncpy(afa.af_name, "dataready", sizeof(afa.af_name) - 1);
    return setsockopt((int)sock_fd, SOL_SOCKET, SO_ACCEPTFILTER, &afa, sizeof(afa));
#else
    (void)timeout_sec;
    return 0; // Graceful no-op on platforms without kernel defer-accept
#endif
}

// Configures TCP_USER_TIMEOUT (Linux RFC 5482) to aggressively abort connection on dead peer.
int32_t wing_tcp_set_user_timeout(int64_t sock_fd, uint32_t timeout_ms) {
    if (sock_fd <= 0) return -1;
#if defined(__linux__) && defined(TCP_USER_TIMEOUT)
    unsigned int val = timeout_ms;
    return setsockopt((int)sock_fd, IPPROTO_TCP, TCP_USER_TIMEOUT, (const void *)&val, sizeof(val));
#else
    (void)timeout_ms;
    return 0;
#endif
}

// Configures aggressive SO_KEEPALIVE profile (idle seconds, interval seconds, count).
int32_t wing_tcp_set_keepalive_params(int64_t sock_fd, int32_t idle_sec, int32_t intvl_sec, int32_t cnt) {
    if (sock_fd <= 0) return -1;
    int opt = 1;
    setsockopt((SOCKET)sock_fd, SOL_SOCKET, SO_KEEPALIVE, (const char *)&opt, sizeof(opt));
#ifdef _WIN32
    (void)cnt;
#if defined(TCP_KEEPCNT)
    if (cnt > 0) {
        DWORD keepcnt = (DWORD)cnt;
        setsockopt((SOCKET)sock_fd, IPPROTO_TCP, TCP_KEEPCNT, (const char *)&keepcnt, sizeof(keepcnt));
    }
#endif
    struct tcp_keepalive settings;
    settings.onoff = 1;
    settings.keepalivetime = (u_long)(idle_sec > 0 ? idle_sec * 1000 : 1000);
    settings.keepaliveinterval = (u_long)(intvl_sec > 0 ? intvl_sec * 1000 : 1000);
    DWORD bytes_ret = 0;
    return (WSAIoctl((SOCKET)sock_fd, SIO_KEEPALIVE_VALS, &settings, sizeof(settings), NULL, 0, &bytes_ret, NULL,
                     NULL) == 0)
               ? 0
               : -1;
#elif defined(__linux__)
    if (idle_sec > 0) setsockopt((int)sock_fd, IPPROTO_TCP, TCP_KEEPIDLE, &idle_sec, sizeof(idle_sec));
    if (intvl_sec > 0) setsockopt((int)sock_fd, IPPROTO_TCP, TCP_KEEPINTVL, &intvl_sec, sizeof(intvl_sec));
    if (cnt > 0) setsockopt((int)sock_fd, IPPROTO_TCP, TCP_KEEPCNT, &cnt, sizeof(cnt));
    return 0;
#elif defined(__APPLE__)
    if (idle_sec > 0) setsockopt((int)sock_fd, IPPROTO_TCP, TCP_KEEPALIVE, &idle_sec, sizeof(idle_sec));
    if (intvl_sec > 0) setsockopt((int)sock_fd, IPPROTO_TCP, TCP_KEEPINTVL, &intvl_sec, sizeof(intvl_sec));
    if (cnt > 0) setsockopt((int)sock_fd, IPPROTO_TCP, TCP_KEEPCNT, &cnt, sizeof(cnt));
    return 0;
#else
    (void)idle_sec;
    (void)intvl_sec;
    (void)cnt;
    return 0;
#endif
}

// Limits SYN retransmissions on connect (TCP_SYNCNT on Linux).
int32_t wing_tcp_set_syn_retries(int64_t sock_fd, int32_t count) {
    if (sock_fd <= 0) return -1;
#if defined(__linux__) && defined(TCP_SYNCNT)
    return setsockopt((int)sock_fd, IPPROTO_TCP, TCP_SYNCNT, (const void *)&count, sizeof(count));
#else
    (void)count;
    return 0;
#endif
}

// Configures TCP Fast Open (TCP_FASTOPEN, RFC 7413).
int32_t wing_tcp_set_fastopen(int64_t sock_fd, int32_t qlen) {
    if (sock_fd <= 0) return -1;
#if defined(_WIN32)
#ifdef TCP_FASTOPEN
    int val = qlen > 0 ? qlen : 512;
    setsockopt((SOCKET)sock_fd, IPPROTO_TCP, TCP_FASTOPEN, (const char *)&val, sizeof(val));
#endif
    return 0;
#elif defined(TCP_FASTOPEN)
    int val = qlen > 0 ? qlen : 512;
    return setsockopt((SOCKET)sock_fd, IPPROTO_TCP, TCP_FASTOPEN, (const void *)&val, sizeof(val)) == 0 ? 0 : -1;
#else
    (void)qlen;
    return 0;
#endif
}

// Sends initial data with SYN under TCP Fast Open (RFC 7413).
int32_t wing_tcp_send_fastopen(int64_t sock_fd, wing_bytes_ro data) {
    if (sock_fd <= 0 || data.data == NULL || data.len <= 0) return 0;
#if defined(__linux__) && defined(MSG_FASTOPEN)
    ssize_t res = send((SOCKET)sock_fd, (const void *)data.data, (size_t)data.len, MSG_FASTOPEN | MSG_NOSIGNAL);
    return res >= 0 ? (int32_t)res : -1;
#else
    return wing_tcp_send(sock_fd, data);
#endif
}

// Configures IP_TOS octet (RFC 3168 Section 6.1.1).
int32_t wing_tcp_set_tos(int64_t sock_fd, int32_t tos) {
    if (sock_fd <= 0) return -1;
#if defined(_WIN32)
#ifdef IP_TOS
    int val = tos;
    setsockopt((SOCKET)sock_fd, IPPROTO_IP, IP_TOS, (const char *)&val, sizeof(val));
#endif
    return 0;
#elif defined(IP_TOS)
    int val = tos;
    return setsockopt((SOCKET)sock_fd, IPPROTO_IP, IP_TOS, (const void *)&val, sizeof(val)) == 0 ? 0 : -1;
#else
    (void)tos;
    return 0;
#endif
}

// Configures IPV6_TCLASS octet (RFC 3168 Section 6.1.1).
int32_t wing_tcp_set_tclass(int64_t sock_fd, int32_t tclass) {
    if (sock_fd <= 0) return -1;
#if defined(_WIN32)
#ifdef IPV6_TCLASS
    int val = tclass;
    setsockopt((SOCKET)sock_fd, IPPROTO_IPV6, IPV6_TCLASS, (const char *)&val, sizeof(val));
#endif
    return 0;
#elif defined(IPV6_TCLASS)
    int val = tclass;
    return setsockopt((SOCKET)sock_fd, IPPROTO_IPV6, IPV6_TCLASS, (const void *)&val, sizeof(val)) == 0 ? 0 : -1;
#else
    (void)tclass;
    return 0;
#endif
}

// Queries kernel backlog of unacknowledged / unsent bytes in output queue.
int64_t wing_tcp_get_notsent_bytes(int64_t sock_fd) {
    if (sock_fd <= 0) return -1;
#if defined(TIOCOUTQ)
    int outq = 0;
    if (ioctl((int)sock_fd, TIOCOUTQ, &outq) == 0) {
        return (int64_t)outq;
    }
#endif
    return 0;
}

// Queries number of readable bytes currently available in socket receive buffer (FIONREAD).
int64_t wing_tcp_get_readable_bytes(int64_t sock_fd) {
    if (sock_fd <= 0) return -1;
#ifdef _WIN32
    u_long bytes = 0;
    if (ioctlsocket((SOCKET)sock_fd, FIONREAD, &bytes) == 0) {
        return (int64_t)bytes;
    }
#else
    int bytes = 0;
    if (ioctl((int)sock_fd, FIONREAD, &bytes) == 0) {
        return (int64_t)bytes;
    }
#endif
    return -1;
}

// Sends two slices (e.g. HTTP header and body) via vectored I/O in 1 syscall.
// Eliminates buffer concatenation in user space, matching uWebSockets bsd_write2.
int32_t wing_tcp_send2(int64_t sock_fd, wing_bytes_ro hdr, wing_bytes_ro payload) {
    if (sock_fd <= 0) return 0;
#ifdef _WIN32
    WSABUF bufs[2];
    DWORD count = 0;
    if (hdr.data != NULL && hdr.len > 0) {
        bufs[count].buf = (char *)hdr.data;
        bufs[count].len = (ULONG)hdr.len;
        count++;
    }
    if (payload.data != NULL && payload.len > 0) {
        bufs[count].buf = (char *)payload.data;
        bufs[count].len = (ULONG)payload.len;
        count++;
    }
    if (count == 0) return 0;
    DWORD sent = 0;
    int res = WSASend((SOCKET)sock_fd, bufs, count, &sent, 0, NULL, NULL);
    if (res == 0) return (int32_t)sent;
    return -1;
#else
    struct iovec bufs[2];
    int count = 0;
    if (hdr.data != NULL && hdr.len > 0) {
        bufs[count].iov_base = (void *)hdr.data;
        bufs[count].iov_len = (size_t)hdr.len;
        count++;
    }
    if (payload.data != NULL && payload.len > 0) {
        bufs[count].iov_base = (void *)payload.data;
        bufs[count].iov_len = (size_t)payload.len;
        count++;
    }
    if (count == 0) return 0;
    ssize_t sent = writev((int)sock_fd, bufs, count);
    return (int32_t)sent;
#endif
}

#if defined(__linux__)
#include <sys/epoll.h>
#endif

#ifdef _WIN32
#define WING_MAX_POLL_FDS 4096
typedef struct {
    SOCKET fds[WING_MAX_POLL_FDS];
    uint32_t events[WING_MAX_POLL_FDS];
    uint64_t udata[WING_MAX_POLL_FDS];
    int count;
} wing_poll_ctx_t;
#endif

// Reads worker count from WING_WORKERS environment variable, or returns default_workers
int64_t wing_get_env_workers(int64_t default_workers) {
    const char *w = getenv("WING_WORKERS");
    if (w && *w) {
        int val = atoi(w);
        if (val > 0 && val <= 128) return (int64_t)val;
    }
    return default_workers > 0 ? default_workers : 1;
}

// Configures socket non-blocking mode (O_NONBLOCK on POSIX, FIONBIO on Windows).
int32_t wing_tcp_set_nonblocking(int64_t sock_fd, int32_t nonblocking) {
    if (sock_fd <= 0) return -1;
#ifdef _WIN32
    u_long mode = nonblocking ? 1 : 0;
    return ioctlsocket((SOCKET)sock_fd, FIONBIO, &mode) == 0 ? 0 : -1;
#else
    int flags = fcntl((int)sock_fd, F_GETFL, 0);
    if (flags < 0) return -1;
    return fcntl((int)sock_fd, F_SETFL, nonblocking ? (flags | O_NONBLOCK) : (flags & ~O_NONBLOCK)) == 0 ? 0 : -1;
#endif
}

// Accepts an incoming connection immediately in non-blocking mode without timeout.
// Returns socket fd (> 0), 0 if no pending connections (EAGAIN/EWOULDBLOCK), or -1 on error.
int64_t wing_tcp_accept_nonblocking(int64_t listener_fd) {
    if (listener_fd <= 0) return -1;
    SOCKET l = (SOCKET)listener_fd;

#if defined(__linux__) && defined(SOCK_NONBLOCK) && defined(SOCK_CLOEXEC)
    int client_sock = accept4((int)l, NULL, NULL, SOCK_NONBLOCK | SOCK_CLOEXEC);
    if (client_sock < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) return 0;
        return -1;
    }
#else
    SOCKET client_sock = accept(l, NULL, NULL);
    if (client_sock == INVALID_SOCKET) {
#ifdef _WIN32
        int err = WSAGetLastError();
        if (err == WSAEWOULDBLOCK) return 0;
#else
        if (errno == EAGAIN || errno == EWOULDBLOCK) return 0;
#endif
        return -1;
    }
#ifdef _WIN32
    SetHandleInformation((HANDLE)client_sock, HANDLE_FLAG_INHERIT, 0);
    u_long mode = 1;
    ioctlsocket(client_sock, FIONBIO, &mode);
#else
    int flags = fcntl(client_sock, F_GETFL, 0);
    fcntl(client_sock, F_SETFL, flags | O_NONBLOCK);
#endif
#endif

    int nodelay = 1;
    setsockopt(client_sock, IPPROTO_TCP, TCP_NODELAY, (const char *)&nodelay, sizeof(nodelay));

    return (int64_t)client_sock;
}

// Sets TCP_QUICKACK (Linux delayed ACK bypass) on socket.
// Prevents 40ms delayed ACK stalls under high-throughput request/response ping-pong.
int32_t wing_tcp_set_quickack(int64_t sock_fd, int32_t enable) {
    if (sock_fd <= 0) return -1;
#if defined(__linux__) && defined(TCP_QUICKACK)
    int opt = enable ? 1 : 0;
    return setsockopt((int)sock_fd, IPPROTO_TCP, TCP_QUICKACK, &opt, sizeof(opt));
#else
    (void)enable;
    return 0; // No-op on Windows/macOS
#endif
}

// Sets TCP_CORK (Linux) to coalesce partial frames at kernel network stack level.
int32_t wing_tcp_set_cork(int64_t sock_fd, int32_t enable) {
    if (sock_fd <= 0) return -1;
#if defined(__linux__) && defined(TCP_CORK)
    int opt = enable ? 1 : 0;
    return setsockopt((int)sock_fd, IPPROTO_TCP, TCP_CORK, &opt, sizeof(opt));
#else
    (void)enable;
    return 0; // No-op on Windows/macOS
#endif
}

// Receives bytes from non-blocking socket immediately without blocking.
// Returns:
//   > 0 : bytes received
//     0 : peer closed connection cleanly (EOF / FIN)
//    -2 : WouldBlock / EAGAIN (no data ready right now)
//    -1 : socket error / connection reset
int32_t wing_tcp_recv_nonblocking(int64_t sock_fd, wing_bytes_rw buf) {
    if (sock_fd <= 0 || buf.data == NULL || buf.len <= 0) return -1;
    SOCKET s = (SOCKET)sock_fd;

    int recvd = recv(s, (char *)buf.data, (int)buf.len, 0);
    if (recvd > 0) return (int32_t)recvd;
    if (recvd == 0) return 0; // EOF / clean disconnect

#ifdef _WIN32
    int err = WSAGetLastError();
    if (err == WSAEWOULDBLOCK) return -2;
#else
    if (errno == EAGAIN || errno == EWOULDBLOCK) return -2;
#endif
    return -1;
}

// ---- Share-Nothing Epoll / Reactor Multiplexer C Engine ---------------------

#if defined(__linux__)

int64_t wing_epoll_create(void) {
    int fd = epoll_create1(EPOLL_CLOEXEC);
    return fd < 0 ? -1 : (int64_t)fd;
}

int32_t wing_epoll_add(int64_t epfd, int64_t sock_fd, uint32_t events, uint64_t udata) {
    if (epfd < 0 || sock_fd <= 0) return -1;
    struct epoll_event ev;
    ev.events = events;
    ev.data.u64 = udata;
    return epoll_ctl((int)epfd, EPOLL_CTL_ADD, (int)sock_fd, &ev) == 0 ? 0 : -1;
}

int32_t wing_epoll_mod(int64_t epfd, int64_t sock_fd, uint32_t events, uint64_t udata) {
    if (epfd < 0 || sock_fd <= 0) return -1;
    struct epoll_event ev;
    ev.events = events;
    ev.data.u64 = udata;
    return epoll_ctl((int)epfd, EPOLL_CTL_MOD, (int)sock_fd, &ev) == 0 ? 0 : -1;
}

int32_t wing_epoll_del(int64_t epfd, int64_t sock_fd) {
    if (epfd < 0 || sock_fd <= 0) return -1;
    return epoll_ctl((int)epfd, EPOLL_CTL_DEL, (int)sock_fd, NULL) == 0 ? 0 : -1;
}

int32_t wing_epoll_wait(int64_t epfd, wing_slice_i64 out_fds, wing_slice_u64 out_udata, int32_t timeout_ms) {
    if (epfd < 0 || out_udata.data == NULL || out_udata.len <= 0) return 0;
    int max_ev = (int)(out_udata.len < 1024 ? out_udata.len : 1024);
    struct epoll_event evs[1024];
    int n = epoll_wait((int)epfd, evs, max_ev, timeout_ms);
    if (n <= 0) return 0;
    if (out_fds.data != NULL && out_fds.len >= n) {
        for (int i = 0; i < n; i++) {
            out_fds.data[i] = (int64_t)(evs[i].data.u64 == 0xFFFFFFFFFFFFFFFFULL ? -1 : (int64_t)evs[i].data.u64);
            out_udata.data[i] = evs[i].data.u64;
        }
    } else {
        for (int i = 0; i < n; i++) {
            out_udata.data[i] = evs[i].data.u64;
        }
    }
    return n;
}

int32_t wing_epoll_wait_events(int64_t epfd, wing_slice_i64 out_fds, wing_slice_u64 out_udata,
                               wing_slice_u32 out_events, int32_t timeout_ms) {
    if (epfd < 0 || out_udata.data == NULL || out_udata.len <= 0 || out_events.data == NULL || out_events.len <= 0) {
        return 0;
    }
    int max_ev = (int)(out_udata.len < out_events.len ? out_udata.len : out_events.len);
    if (max_ev > 1024) max_ev = 1024;
    struct epoll_event evs[1024];
    int n = epoll_wait((int)epfd, evs, max_ev, timeout_ms);
    if (n <= 0) return 0;
    for (int i = 0; i < n; i++) {
        if (out_fds.data != NULL && i < out_fds.len) {
            out_fds.data[i] = (int64_t)(evs[i].data.u64 == 0xFFFFFFFFFFFFFFFFULL ? -1 : (int64_t)evs[i].data.u64);
        }
        out_udata.data[i] = evs[i].data.u64;
        uint32_t mask = 0;
        if (evs[i].events & EPOLLIN) mask |= 1U;
        if (evs[i].events & EPOLLOUT) mask |= 2U;
        if (evs[i].events & EPOLLERR) mask |= 4U;
        if (evs[i].events & (EPOLLHUP
#ifdef EPOLLRDHUP
                             | EPOLLRDHUP
#endif
                             )) {
            mask |= 8U;
        }
        out_events.data[i] = mask;
    }
    return n;
}

void wing_epoll_close(int64_t epfd) {
    if (epfd >= 0) close((int)epfd);
}

#else

// Windows & Darwin Cross-Platform WSAPoll fallback implementation
int64_t wing_epoll_create(void) {
    wing_poll_ctx_t *ctx = (wing_poll_ctx_t *)calloc(1, sizeof(wing_poll_ctx_t));
    if (!ctx) return -1;
    return (int64_t)(uintptr_t)ctx;
}

int32_t wing_epoll_add(int64_t epfd, int64_t sock_fd, uint32_t events, uint64_t udata) {
    wing_poll_ctx_t *ctx = (wing_poll_ctx_t *)(uintptr_t)epfd;
    if (!ctx || sock_fd <= 0 || ctx->count >= WING_MAX_POLL_FDS) return -1;
    for (int i = 0; i < ctx->count; i++) {
        if (ctx->fds[i] == (SOCKET)sock_fd) {
            ctx->events[i] = events;
            ctx->udata[i] = udata;
            return 0;
        }
    }
    ctx->fds[ctx->count] = (SOCKET)sock_fd;
    ctx->events[ctx->count] = events;
    ctx->udata[ctx->count] = udata;
    ctx->count++;
    return 0;
}

int32_t wing_epoll_mod(int64_t epfd, int64_t sock_fd, uint32_t events, uint64_t udata) {
    wing_poll_ctx_t *ctx = (wing_poll_ctx_t *)(uintptr_t)epfd;
    if (!ctx || sock_fd <= 0) return -1;
    for (int i = 0; i < ctx->count; i++) {
        if (ctx->fds[i] == (SOCKET)sock_fd) {
            ctx->events[i] = events;
            ctx->udata[i] = udata;
            return 0;
        }
    }
    return -1;
}

int32_t wing_epoll_del(int64_t epfd, int64_t sock_fd) {
    wing_poll_ctx_t *ctx = (wing_poll_ctx_t *)(uintptr_t)epfd;
    if (!ctx || sock_fd <= 0) return -1;
    for (int i = 0; i < ctx->count; i++) {
        if (ctx->fds[i] == (SOCKET)sock_fd) {
            ctx->fds[i] = ctx->fds[ctx->count - 1];
            ctx->events[i] = ctx->events[ctx->count - 1];
            ctx->udata[i] = ctx->udata[ctx->count - 1];
            ctx->count--;
            return 0;
        }
    }
    return -1;
}

int32_t wing_epoll_wait(int64_t epfd, wing_slice_i64 out_fds, wing_slice_u64 out_udata, int32_t timeout_ms) {
    wing_poll_ctx_t *ctx = (wing_poll_ctx_t *)(uintptr_t)epfd;
    if (!ctx || ctx->count <= 0) return 0;
    int limit = (out_udata.data != NULL && out_udata.len > 0) ? (int)out_udata.len : 0;
    if (out_fds.data != NULL && out_fds.len > 0 && (limit == 0 || (int)out_fds.len < limit)) {
        limit = (int)out_fds.len;
    }
    if (limit <= 0) return 0;

#ifdef _WIN32
    WSAPOLLFD pfd[WING_MAX_POLL_FDS];
    int count = ctx->count;
    for (int i = 0; i < count; i++) {
        pfd[i].fd = ctx->fds[i];
        pfd[i].events = (SHORT)((ctx->events[i] & 1 ? POLLRDNORM : 0) | (ctx->events[i] & 4 ? POLLWRNORM : 0));
        pfd[i].revents = 0;
    }
    int res = WSAPoll(pfd, (ULONG)count, timeout_ms);
    if (res <= 0) return 0;

    int ready = 0;
    for (int i = 0; i < count && ready < limit; i++) {
        if (pfd[i].revents != 0) {
            if (out_fds.data != NULL && ready < (int)out_fds.len) {
                out_fds.data[ready] = (int64_t)pfd[i].fd;
            }
            if (out_udata.data != NULL && ready < (int)out_udata.len) {
                out_udata.data[ready] = ctx->udata[i];
            }
            ready++;
        }
    }
    return ready;
#else
    return 0;
#endif
}

int32_t wing_epoll_wait_events(int64_t epfd, wing_slice_i64 out_fds, wing_slice_u64 out_udata,
                               wing_slice_u32 out_events, int32_t timeout_ms) {
    wing_poll_ctx_t *ctx = (wing_poll_ctx_t *)(uintptr_t)epfd;
    if (!ctx || ctx->count <= 0 || out_udata.data == NULL || out_udata.len <= 0 || out_events.data == NULL ||
        out_events.len <= 0) {
        return 0;
    }
    int limit = (int)(out_udata.len < out_events.len ? out_udata.len : out_events.len);
    if (out_fds.data != NULL && out_fds.len > 0 && (int)out_fds.len < limit) {
        limit = (int)out_fds.len;
    }
    if (limit <= 0) return 0;

#ifdef _WIN32
    WSAPOLLFD pfd[WING_MAX_POLL_FDS];
    int count = ctx->count;
    for (int i = 0; i < count; i++) {
        pfd[i].fd = ctx->fds[i];
        pfd[i].events = (SHORT)((ctx->events[i] & 1 ? POLLRDNORM : 0) | (ctx->events[i] & 4 ? POLLWRNORM : 0));
        pfd[i].revents = 0;
    }
    int res = WSAPoll(pfd, (ULONG)count, timeout_ms);
    if (res <= 0) return 0;

    int ready = 0;
    for (int i = 0; i < count && ready < limit; i++) {
        if (pfd[i].revents != 0) {
            if (out_fds.data != NULL && ready < (int)out_fds.len) {
                out_fds.data[ready] = (int64_t)pfd[i].fd;
            }
            out_udata.data[ready] = ctx->udata[i];
            uint32_t mask = 0;
            if (pfd[i].revents & (POLLRDNORM | POLLRDBAND)) mask |= 1U;
            if (pfd[i].revents & POLLWRNORM) mask |= 2U;
            if (pfd[i].revents & (POLLERR | POLLNVAL)) mask |= 4U;
            if (pfd[i].revents & POLLHUP) mask |= 8U;
            out_events.data[ready] = mask;
            ready++;
        }
    }
    return ready;
#else
    (void)timeout_ms;
    return 0;
#endif
}

void wing_epoll_close(int64_t epfd) {
    wing_poll_ctx_t *ctx = (wing_poll_ctx_t *)(uintptr_t)epfd;
    if (ctx) free(ctx);
}

#endif

// Pins current calling thread to specific CPU core ID.
// Uses physical-first core stride (0, 2, 4, 6, 8, 10) on SMT architectures to eliminate core sharing.
int32_t wing_set_cpu_affinity(int64_t cpu_id) {
    if (cpu_id < 0) return -1;
#if defined(__linux__)
    long total_cpus = sysconf(_SC_NPROCESSORS_ONLN);
    int target_cpu = (int)cpu_id;
    if (total_cpus > 1) {
        int phys = (int)(total_cpus / 2);
        target_cpu = (cpu_id < phys) ? (int)(cpu_id * 2) : (int)((cpu_id - phys) * 2 + 1);
    }
    cpu_set_t cpuset;
    CPU_ZERO(&cpuset);
    CPU_SET(target_cpu % (int)total_cpus, &cpuset);
    return pthread_setaffinity_np(pthread_self(), sizeof(cpu_set_t), &cpuset);
#elif defined(_WIN32)
    if (cpu_id >= 64) return -1;
    DWORD_PTR mask = ((DWORD_PTR)1) << cpu_id;
    return SetThreadAffinityMask(GetCurrentThread(), mask) != 0 ? 0 : -1;
#else
    (void)cpu_id;
    return 0;
#endif
}

// Binds listener socket's incoming connection queue directly to specific CPU core (SO_INCOMING_CPU on Linux).
// Ensures zero cross-core cache invalidation & zero IPI interrupts on multi-worker reactors.
int32_t wing_tcp_set_incoming_cpu(int64_t sock_fd, int64_t cpu_id) {
    if (sock_fd <= 0 || cpu_id < 0) return -1;
#if defined(__linux__)
#ifndef SO_INCOMING_CPU
#define SO_INCOMING_CPU 49
#endif
    if (!getenv("WING_INCOMING_CPU")) return 0;
    long total_cpus = sysconf(_SC_NPROCESSORS_ONLN);
    int target_cpu = (int)cpu_id;
    if (total_cpus > 1) {
        int phys = (int)(total_cpus / 2);
        target_cpu = (cpu_id < phys) ? (int)(cpu_id * 2) : (int)((cpu_id - phys) * 2 + 1);
    }
    int cpu = target_cpu % (int)total_cpus;
    return setsockopt((int)sock_fd, SOL_SOCKET, SO_INCOMING_CPU, &cpu, sizeof(cpu));
#else
    (void)sock_fd;
    (void)cpu_id;
    return 0;
#endif
}

// -----------------------------------------------------------------------------
// Layer 4 Cross-Platform UDP Datagram Operations (RFC 9000 QUIC / HTTP/3)
// -----------------------------------------------------------------------------

// Binds a UDP socket on host:port (non-inheritable, SO_REUSEADDR).
int64_t wing_udp_bind(wing_bytes_ro host, uint16_t port) {
    wing_tcp_init();

    SOCKET s = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (s == INVALID_SOCKET) {
        return -1;
    }
#ifdef _WIN32
    SetHandleInformation((HANDLE)s, HANDLE_FLAG_INHERIT, 0);
    int opt = 1;
    setsockopt(s, SOL_SOCKET, SO_REUSEADDR, (const char *)&opt, sizeof(opt));
#else
    int opt = 1;
    setsockopt(s, SOL_SOCKET, SO_REUSEADDR, (const char *)&opt, sizeof(opt));
#if defined(SO_REUSEPORT)
    setsockopt(s, SOL_SOCKET, SO_REUSEPORT, (const char *)&opt, sizeof(opt));
#endif
#endif

    char host_str[128];
    slice_to_cstr(host, host_str, sizeof(host_str));

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    if (host_str[0] == '\0' || strcmp(host_str, "0.0.0.0") == 0) {
        addr.sin_addr.s_addr = INADDR_ANY;
    } else if (strcmp(host_str, "127.0.0.1") == 0 || strcmp(host_str, "localhost") == 0) {
        addr.sin_addr.s_addr = inet_addr("127.0.0.1");
    } else {
        addr.sin_addr.s_addr = inet_addr(host_str);
    }

    if (bind(s, (struct sockaddr *)&addr, sizeof(addr)) == SOCKET_ERROR) {
        closesocket(s);
        return -1;
    }

    return (int64_t)s;
}

// Sends a UDP datagram to host:port.
int32_t wing_udp_sendto(int64_t sock_fd, wing_bytes_ro data, wing_bytes_ro host, uint16_t port) {
    if (sock_fd <= 0 || data.data == NULL || data.len < 0) {
        return -1;
    }
    SOCKET s = (SOCKET)sock_fd;

    char host_str[128];
    slice_to_cstr(host, host_str, sizeof(host_str));

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    if (host_str[0] == '\0' || strcmp(host_str, "127.0.0.1") == 0 || strcmp(host_str, "localhost") == 0) {
        addr.sin_addr.s_addr = inet_addr("127.0.0.1");
    } else {
        addr.sin_addr.s_addr = inet_addr(host_str);
        if (addr.sin_addr.s_addr == INADDR_NONE) {
#if !defined(__wasm__)
            struct addrinfo hints;
            struct addrinfo *res_info = NULL;
            memset(&hints, 0, sizeof(hints));
            hints.ai_family = AF_INET;
            hints.ai_socktype = SOCK_DGRAM;
            if (getaddrinfo(host_str, NULL, &hints, &res_info) != 0 || res_info == NULL) {
                return -1;
            }
            addr.sin_addr = ((struct sockaddr_in *)res_info->ai_addr)->sin_addr;
            freeaddrinfo(res_info);
#else
            return -1;
#endif
        }
    }

    int res = sendto(s, (const char *)data.data, (int)data.len, MSG_NOSIGNAL, (struct sockaddr *)&addr, sizeof(addr));
    return res;
}

// Receives a UDP datagram with timeout. Returns bytes read, or -2 on timeout, or -1 on error.
int32_t wing_udp_recvfrom(int64_t sock_fd, wing_bytes_rw buf, uint32_t timeout_ms, uint32_t *peer_ip4,
                          uint16_t *peer_port) {
    if (sock_fd <= 0 || buf.data == NULL || buf.len <= 0) {
        return -1;
    }
    SOCKET s = (SOCKET)sock_fd;

    if (timeout_ms > 0) {
        int sel = wing_wait_fd(s, 0, timeout_ms);
        if (sel == 0) {
            return -2; // Timeout
        }
        if (sel < 0) {
            return -1;
        }
    }

    struct sockaddr_in peer_addr;
#ifdef _WIN32
    int addr_len = sizeof(peer_addr);
#else
    socklen_t addr_len = sizeof(peer_addr);
#endif
    int res = recvfrom(s, (char *)buf.data, (int)buf.len, 0, (struct sockaddr *)&peer_addr, &addr_len);
    if (res >= 0) {
        if (peer_port) {
            *peer_port = ntohs(peer_addr.sin_port);
        }
        if (peer_ip4) {
            *peer_ip4 = peer_addr.sin_addr.s_addr;
        }
    }
    return res;
}

// Sends a UDP datagram directly to remote IPv4 (network byte order) and port.
int32_t wing_udp_sendto_ip4(int64_t sock_fd, wing_bytes_ro data, uint32_t peer_ip4, uint16_t peer_port) {
    if (sock_fd <= 0 || data.data == NULL || data.len < 0) {
        return -1;
    }
    SOCKET s = (SOCKET)sock_fd;

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(peer_port);
    addr.sin_addr.s_addr = peer_ip4;

    int res = sendto(s, (const char *)data.data, (int)data.len, MSG_NOSIGNAL, (struct sockaddr *)&addr, sizeof(addr));
    return res;
}

// Batched UDP datagram transmission (sendmmsg on Linux, sendto loop fallback on Windows/POSIX).
// Amortizes syscall transitions up to 32 packets per invocation.
int32_t wing_udp_sendmmsg(int64_t sock_fd, wing_bytes_ro payloads, wing_slice_i32_ro lengths, wing_slice_u32_ro ips,
                          wing_slice_u16_ro ports, int32_t count) {
    if (sock_fd < 0 || count <= 0 || count > 32) return -1;
    if (payloads.data == NULL || lengths.data == NULL || ips.data == NULL || ports.data == NULL) return -1;
    if (lengths.len < count || ips.len < count || ports.len < count) return -1;
    if (sock_fd == 0) {
        return count;
    }
#if defined(__linux__)
    struct mmsghdr msgs[32];
    struct iovec iovecs[32];
    struct sockaddr_in addrs[32];
    memset(msgs, 0, sizeof(msgs));
    memset(iovecs, 0, sizeof(iovecs));
    memset(addrs, 0, sizeof(addrs));
    for (int32_t i = 0; i < count; i++) {
        int64_t offset = (int64_t)i * 1472;
        int32_t pkt_len = lengths.data[i];
        if (pkt_len < 0 || pkt_len > 1472 || offset + pkt_len > payloads.len) return -1;
        addrs[i].sin_family = AF_INET;
        addrs[i].sin_port = htons(ports.data[i]);
        addrs[i].sin_addr.s_addr = ips.data[i];
        iovecs[i].iov_base = (void *)(payloads.data + offset);
        iovecs[i].iov_len = (size_t)pkt_len;
        msgs[i].msg_hdr.msg_name = &addrs[i];
        msgs[i].msg_hdr.msg_namelen = sizeof(struct sockaddr_in);
        msgs[i].msg_hdr.msg_iov = &iovecs[i];
        msgs[i].msg_hdr.msg_iovlen = 1;
    }
    int res = sendmmsg((int)sock_fd, msgs, (unsigned int)count, MSG_NOSIGNAL);
    return res >= 0 ? (int32_t)res : -1;
#else
    int32_t sent = 0;
    for (int32_t i = 0; i < count; i++) {
        int64_t offset = (int64_t)i * 1472;
        int32_t pkt_len = lengths.data[i];
        if (pkt_len < 0 || pkt_len > 1472 || offset + pkt_len > payloads.len) return sent > 0 ? sent : -1;
        wing_bytes_ro slice = {payloads.data + offset, pkt_len};
        int32_t r = wing_udp_sendto_ip4(sock_fd, slice, ips.data[i], ports.data[i]);
        if (r < 0) return sent > 0 ? sent : -1;
        sent++;
    }
    return sent;
#endif
}

// Batched UDP datagram reception (recvmmsg on Linux, recvfrom loop fallback on Windows/POSIX).
int32_t wing_udp_recvmmsg(int64_t sock_fd, wing_bytes_rw payloads, wing_slice_i32 lengths, wing_slice_u32 ips,
                          wing_slice_u16 ports, int32_t max_count, uint32_t timeout_ms) {
    if (sock_fd < 0 || max_count <= 0 || max_count > 32) return -1;
    if (payloads.data == NULL || lengths.data == NULL || ips.data == NULL || ports.data == NULL) return -1;
    if (lengths.len < max_count || ips.len < max_count || ports.len < max_count) return -1;
    if (sock_fd == 0) {
        return 0;
    }
#if defined(__linux__)
    struct mmsghdr msgs[32];
    struct iovec iovecs[32];
    struct sockaddr_in addrs[32];
    memset(msgs, 0, sizeof(msgs));
    memset(iovecs, 0, sizeof(iovecs));
    memset(addrs, 0, sizeof(addrs));
    for (int32_t i = 0; i < max_count; i++) {
        int64_t offset = (int64_t)i * 1472;
        if (offset + 1472 > payloads.len) return -1;
        iovecs[i].iov_base = (void *)(payloads.data + offset);
        iovecs[i].iov_len = 1472;
        msgs[i].msg_hdr.msg_name = &addrs[i];
        msgs[i].msg_hdr.msg_namelen = sizeof(struct sockaddr_in);
        msgs[i].msg_hdr.msg_iov = &iovecs[i];
        msgs[i].msg_hdr.msg_iovlen = 1;
    }
    struct timespec ts;
    struct timespec *ts_ptr = NULL;
    if (timeout_ms > 0) {
        ts.tv_sec = timeout_ms / 1000;
        ts.tv_nsec = (timeout_ms % 1000) * 1000000L;
        ts_ptr = &ts;
    }
    int res = recvmmsg((int)sock_fd, msgs, (unsigned int)max_count, MSG_DONTWAIT, ts_ptr);
    if (res < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) return 0;
        return -1;
    }
    for (int i = 0; i < res; i++) {
        lengths.data[i] = (int32_t)msgs[i].msg_len;
        ips.data[i] = addrs[i].sin_addr.s_addr;
        ports.data[i] = ntohs(addrs[i].sin_port);
    }
    return (int32_t)res;
#else
    int32_t recvd = 0;
    for (int32_t i = 0; i < max_count; i++) {
        int64_t offset = (int64_t)i * 1472;
        if (offset + 1472 > payloads.len) break;
        wing_bytes_rw slice = {payloads.data + offset, 1472};
        int32_t r = wing_udp_recvfrom(sock_fd, slice, i == 0 ? timeout_ms : 1, &ips.data[i], &ports.data[i]);
        if (r < 0) {
            if (r == -2) break;
            return recvd > 0 ? recvd : -1;
        }
        lengths.data[i] = r;
        recvd++;
    }
    return recvd;
#endif
}

// ---- Dual-Stack Proxy TCP, Pipe Splice, Local IPs, Dual-Stack UDP, and FS ----

static void wing_prepare_nonblocking_cloexec(SOCKET s) {
#ifdef _WIN32
    SetHandleInformation((HANDLE)s, HANDLE_FLAG_INHERIT, 0);
    u_long nb = 1;
    ioctlsocket(s, FIONBIO, &nb);
#else
    int fd_flags = fcntl(s, F_GETFD, 0);
    if (fd_flags >= 0) {
        fcntl(s, F_SETFD, fd_flags | FD_CLOEXEC);
    }
    int fl = fcntl(s, F_GETFL, 0);
    if (fl >= 0) {
        fcntl(s, F_SETFL, fl | O_NONBLOCK);
    }
#endif
}

static int wing_parse_ip_sockaddr(const char *ip_str, uint16_t port, int force_family, struct sockaddr_storage *out_ss,
                                  int *out_family, int *out_len) {
    memset(out_ss, 0, sizeof(*out_ss));
    if (ip_str[0] == '\0') {
        if (force_family == AF_INET6) {
            struct sockaddr_in6 *s6 = (struct sockaddr_in6 *)out_ss;
            s6->sin6_family = AF_INET6;
            s6->sin6_port = htons(port);
            s6->sin6_addr = in6addr_any;
            *out_family = AF_INET6;
            *out_len = (int)sizeof(*s6);
            return 0;
        }
        struct sockaddr_in *s4 = (struct sockaddr_in *)out_ss;
        s4->sin_family = AF_INET;
        s4->sin_port = htons(port);
        s4->sin_addr.s_addr = htonl(INADDR_ANY);
        *out_family = AF_INET;
        *out_len = (int)sizeof(*s4);
        return 0;
    }

    struct in_addr a4;
    if ((force_family == 0 || force_family == AF_INET) && inet_pton(AF_INET, ip_str, &a4) == 1) {
        struct sockaddr_in *s4 = (struct sockaddr_in *)out_ss;
        s4->sin_family = AF_INET;
        s4->sin_port = htons(port);
        s4->sin_addr = a4;
        *out_family = AF_INET;
        *out_len = (int)sizeof(*s4);
        return 0;
    }

    struct in6_addr a6;
    if ((force_family == 0 || force_family == AF_INET6) && inet_pton(AF_INET6, ip_str, &a6) == 1) {
        struct sockaddr_in6 *s6 = (struct sockaddr_in6 *)out_ss;
        s6->sin6_family = AF_INET6;
        s6->sin6_port = htons(port);
        s6->sin6_addr = a6;
        *out_family = AF_INET6;
        *out_len = (int)sizeof(*s6);
        return 0;
    }
    return -1;
}

static int32_t wing_format_sockaddr_ip_port(const struct sockaddr_storage *ss, wing_bytes_rw out_ip,
                                            uint16_t *out_port) {
    char buf[INET6_ADDRSTRLEN];
    buf[0] = '\0';
    uint16_t port = 0;

    if (ss->ss_family == AF_INET) {
        const struct sockaddr_in *s4 = (const struct sockaddr_in *)ss;
        if (inet_ntop(AF_INET, &s4->sin_addr, buf, sizeof(buf)) == NULL) return -1;
        port = ntohs(s4->sin_port);
    } else if (ss->ss_family == AF_INET6) {
        const struct sockaddr_in6 *s6 = (const struct sockaddr_in6 *)ss;
        if (IN6_IS_ADDR_V4MAPPED(&s6->sin6_addr)) {
            struct in_addr mapped;
            memcpy(&mapped, &s6->sin6_addr.s6_addr[12], 4);
            if (inet_ntop(AF_INET, &mapped, buf, sizeof(buf)) == NULL) return -1;
        } else if (inet_ntop(AF_INET6, &s6->sin6_addr, buf, sizeof(buf)) == NULL) {
            return -1;
        }
        port = ntohs(s6->sin6_port);
    } else {
        return -1;
    }

    if (out_port != NULL) *out_port = port;
    int64_t len = (int64_t)strlen(buf);
    if (out_ip.data == NULL || out_ip.len <= 0 || len > out_ip.len) return -1;
    memcpy(out_ip.data, buf, (size_t)len);
    return (int32_t)len;
}

static int wing_last_sock_err(void) {
#ifdef _WIN32
    return WSAGetLastError();
#else
    return errno;
#endif
}

static int32_t wing_map_connect_errno(int err) {
    if (err == 0) return 0;
#ifdef _WIN32
    if (err == WSAECONNREFUSED) return 1;
    if (err == WSAENETUNREACH || err == WSAEHOSTUNREACH) return 2;
    if (err == WSAETIMEDOUT) return 3;
#else
    if (err == ECONNREFUSED) return 1;
    if (err == ENETUNREACH || err == EHOSTUNREACH) return 2;
    if (err == ETIMEDOUT) return 3;
#endif
    return -1;
}

int64_t wing_tcp_listen_dual(wing_bytes_ro host, uint16_t port, int32_t backlog, int32_t flags) {
    if (wing_tcp_init() != 0) return -1;

    char host_str[128];
    slice_to_cstr(host, host_str, sizeof(host_str));

    int force_family = (flags & 2) ? AF_INET6 : 0;
    if (host_str[0] != '\0') {
        force_family = (strchr(host_str, ':') != NULL) ? AF_INET6 : AF_INET;
    }

    struct sockaddr_storage ss;
    int family = AF_INET;
    int addr_len = 0;
    if (wing_parse_ip_sockaddr(host_str, port, force_family, &ss, &family, &addr_len) != 0) return -1;

    SOCKET s = socket(family, SOCK_STREAM, IPPROTO_TCP);
    if (s == INVALID_SOCKET) return -1;

    wing_prepare_nonblocking_cloexec(s);

    int opt = 1;
#ifdef _WIN32
    setsockopt(s, SOL_SOCKET, SO_EXCLUSIVEADDRUSE, (const char *)&opt, sizeof(opt));
#else
    setsockopt(s, SOL_SOCKET, SO_REUSEADDR, (const char *)&opt, sizeof(opt));
#ifdef SO_REUSEPORT
    setsockopt(s, SOL_SOCKET, SO_REUSEPORT, (const char *)&opt, sizeof(opt));
#endif
#endif

    if (family == AF_INET6) {
        int v6only = 1;
        setsockopt(s, IPPROTO_IPV6, IPV6_V6ONLY, (const char *)&v6only, sizeof(v6only));
    }

#ifdef __linux__
    if (flags & 1) {
        int transp = 1;
        int rc_t = (family == AF_INET6) ? setsockopt(s, IPPROTO_IPV6, IPV6_TRANSPARENT, &transp, sizeof(transp))
                                        : setsockopt(s, IPPROTO_IP, IP_TRANSPARENT, &transp, sizeof(transp));
        if (rc_t != 0) {
            closesocket(s);
            return -1;
        }
    }
#endif

#ifdef _WIN32
    if (bind(s, (struct sockaddr *)&ss, addr_len) != 0) {
#else
    if (bind(s, (struct sockaddr *)&ss, (socklen_t)addr_len) != 0) {
#endif
        closesocket(s);
        return -1;
    }

    if (listen(s, backlog > 0 ? backlog : 512) != 0) {
        closesocket(s);
        return -1;
    }

    return (int64_t)s;
}

int64_t wing_tcp_accept_info(int64_t listener_fd, int32_t mode_flags, wing_bytes_rw out_peer_ip,
                             int32_t *out_peer_ip_len, uint16_t *out_peer_port, wing_bytes_rw out_dst_ip,
                             int32_t *out_dst_ip_len, uint16_t *out_dst_port) {
    if (listener_fd <= 0) return -1;
    if (out_peer_ip_len) *out_peer_ip_len = 0;
    if (out_dst_ip_len) *out_dst_ip_len = 0;
    if (out_peer_port) *out_peer_port = 0;
    if (out_dst_port) *out_dst_port = 0;

    struct sockaddr_storage peer_ss;
    memset(&peer_ss, 0, sizeof(peer_ss));
#ifdef _WIN32
    int peer_len = (int)sizeof(peer_ss);
    SOCKET c = accept((SOCKET)listener_fd, (struct sockaddr *)&peer_ss, &peer_len);
    if (c == INVALID_SOCKET) {
        return (WSAGetLastError() == WSAEWOULDBLOCK) ? 0 : -1;
    }
#else
    socklen_t peer_len = (socklen_t)sizeof(peer_ss);
#if defined(__linux__) && defined(SOCK_NONBLOCK) && defined(SOCK_CLOEXEC)
    SOCKET c = accept4((int)listener_fd, (struct sockaddr *)&peer_ss, &peer_len, SOCK_NONBLOCK | SOCK_CLOEXEC);
#else
    SOCKET c = accept((int)listener_fd, (struct sockaddr *)&peer_ss, &peer_len);
#endif
    if (c == INVALID_SOCKET) {
        return (errno == EAGAIN || errno == EWOULDBLOCK) ? 0 : -1;
    }
#endif

    wing_prepare_nonblocking_cloexec(c);
    int nodelay = 1;
    setsockopt(c, IPPROTO_TCP, TCP_NODELAY, (const char *)&nodelay, sizeof(nodelay));

    int32_t plen = wing_format_sockaddr_ip_port(&peer_ss, out_peer_ip, out_peer_port);
    if (plen < 0) {
        closesocket(c);
        return -1;
    }
    if (out_peer_ip_len) *out_peer_ip_len = plen;

    struct sockaddr_storage dst_ss;
    memset(&dst_ss, 0, sizeof(dst_ss));
    int dst_ok = 0;

#ifdef __linux__
    if (mode_flags == 2) {
        socklen_t dlen = (socklen_t)sizeof(dst_ss);
        if (peer_ss.ss_family == AF_INET6) {
            if (getsockopt(c, IPPROTO_IPV6, IP6T_SO_ORIGINAL_DST, &dst_ss, &dlen) == 0) dst_ok = 1;
        } else {
            if (getsockopt(c, IPPROTO_IP, SO_ORIGINAL_DST, &dst_ss, &dlen) == 0) dst_ok = 1;
        }
        if (!dst_ok) {
            closesocket(c);
            return -1;
        }
    }
#else
    (void)mode_flags;
#endif

    if (!dst_ok) {
#ifdef _WIN32
        int dlen = (int)sizeof(dst_ss);
#else
        socklen_t dlen = (socklen_t)sizeof(dst_ss);
#endif
        if (getsockname(c, (struct sockaddr *)&dst_ss, &dlen) != 0) {
            closesocket(c);
            return -1;
        }
    }

    int32_t dlen_str = wing_format_sockaddr_ip_port(&dst_ss, out_dst_ip, out_dst_port);
    if (dlen_str < 0) {
        closesocket(c);
        return -1;
    }
    if (out_dst_ip_len) *out_dst_ip_len = dlen_str;

    return (int64_t)c;
}

int32_t wing_tcp_set_mss(int64_t sock_fd, int32_t mss) {
    if (sock_fd <= 0 || mss < 536 || mss > 65495) return -1;
#if defined(TCP_MAXSEG) && !defined(_WIN32)
    int val = (int)mss;
    return setsockopt((SOCKET)sock_fd, IPPROTO_TCP, TCP_MAXSEG, (const char *)&val, sizeof(val)) == 0 ? 0 : -1;
#else
    (void)sock_fd;
    (void)mss;
    return 0;
#endif
}

int32_t wing_tcp_set_rcvbuf(int64_t sock_fd, int32_t bytes) {
    if (sock_fd <= 0 || bytes <= 0) return -1;
    int val = (int)bytes;
    return setsockopt((SOCKET)sock_fd, SOL_SOCKET, SO_RCVBUF, (const char *)&val, sizeof(val)) == 0 ? 0 : -1;
}

int64_t wing_tcp_connect_opts_begin(wing_bytes_ro src_ip, wing_bytes_ro dst_ip, uint16_t dst_port, uint32_t so_mark,
                                    int32_t ttl, int32_t mss, int32_t rcvbuf, int32_t tcp_nodelay, int32_t ka_idle,
                                    int32_t ka_intvl, int32_t ka_cnt, uint32_t user_timeout_ms, int32_t *out_state,
                                    int32_t *out_err) {
    if (out_state) *out_state = -1;
    if (out_err) *out_err = -1;
    if (dst_ip.data == NULL || dst_ip.len <= 0 || dst_ip.len >= 128 || dst_port == 0) return -1;
    if (wing_tcp_init() != 0) return -1;

    char dst_str[128];
    slice_to_cstr(dst_ip, dst_str, sizeof(dst_str));

    struct sockaddr_storage dst_ss;
    int family = AF_INET;
    int dst_len = 0;
    if (wing_parse_ip_sockaddr(dst_str, dst_port, 0, &dst_ss, &family, &dst_len) != 0) {
        if (out_err) *out_err = 2;
        return -1;
    }

    SOCKET s = socket(family, SOCK_STREAM, IPPROTO_TCP);
    if (s == INVALID_SOCKET) return -1;

    wing_prepare_nonblocking_cloexec(s);
    int opt = 1;
    setsockopt(s, SOL_SOCKET, SO_REUSEADDR, (const char *)&opt, sizeof(opt));
    int nd = tcp_nodelay ? 1 : 0;
    setsockopt(s, IPPROTO_TCP, TCP_NODELAY, (const char *)&nd, sizeof(nd));

#ifdef __linux__
    if (so_mark != 0) {
        uint32_t mk = so_mark;
        if (setsockopt(s, SOL_SOCKET, SO_MARK, &mk, sizeof(mk)) != 0) {
            closesocket(s);
            return -1;
        }
    }
    if (src_ip.data != NULL && src_ip.len > 0) {
        int fb = 1;
        if (family == AF_INET6) {
            setsockopt(s, IPPROTO_IPV6, IPV6_FREEBIND, &fb, sizeof(fb));
        } else {
            setsockopt(s, IPPROTO_IP, IP_FREEBIND, &fb, sizeof(fb));
            setsockopt(s, IPPROTO_IP, IP_BIND_ADDRESS_NO_PORT, &fb, sizeof(fb));
        }
    }
#else
    (void)so_mark;
#endif

    // Apply pre-connect SYN profile options (TTL/hop-limit, MSS, RCVBUF) BEFORE connect().
    if (ttl > 0 && ttl <= 255) {
        int t = (int)ttl;
        if (family == AF_INET6) {
            (void)setsockopt(s, IPPROTO_IPV6, IPV6_UNICAST_HOPS, (const char *)&t, sizeof(t));
        } else {
            (void)setsockopt(s, IPPROTO_IP, IP_TTL, (const char *)&t, sizeof(t));
        }
    }
    if (mss >= 536 && mss <= 65495) {
        (void)wing_tcp_set_mss((int64_t)s, mss);
    }
    if (rcvbuf > 0) {
        (void)wing_tcp_set_rcvbuf((int64_t)s, rcvbuf);
    }

    if (src_ip.data != NULL && src_ip.len > 0) {
        if (src_ip.len >= 128) {
            closesocket(s);
            return -1;
        }
        char src_str[128];
        slice_to_cstr(src_ip, src_str, sizeof(src_str));
        struct sockaddr_storage src_ss;
        int src_family = 0;
        int src_len = 0;
        if (wing_parse_ip_sockaddr(src_str, 0, family, &src_ss, &src_family, &src_len) != 0) {
            if (out_err) *out_err = 2;
            closesocket(s);
            return -1;
        }
#ifdef _WIN32
        if (bind(s, (struct sockaddr *)&src_ss, src_len) != 0) {
#else
        if (bind(s, (struct sockaddr *)&src_ss, (socklen_t)src_len) != 0) {
#endif
            closesocket(s);
            return -1;
        }
    }

    if (ka_idle > 0) {
        int ki = ka_intvl > 0 ? ka_intvl : 5;
        int kc = ka_cnt > 0 ? ka_cnt : 3;
        (void)wing_tcp_set_keepalive_params((int64_t)s, ka_idle, ki, kc);
    }
    if (user_timeout_ms > 0) {
        (void)wing_tcp_set_user_timeout((int64_t)s, user_timeout_ms);
    }

#ifdef _WIN32
    int rc = connect(s, (struct sockaddr *)&dst_ss, dst_len);
#else
    int rc = connect(s, (struct sockaddr *)&dst_ss, (socklen_t)dst_len);
#endif
    if (rc == 0) {
        if (out_state) *out_state = 0;
        if (out_err) *out_err = 0;
        return (int64_t)s;
    }

    int err = wing_last_sock_err();
#ifdef _WIN32
    if (err == WSAEWOULDBLOCK || err == WSAEINPROGRESS) {
#else
    if (err == EINPROGRESS || err == EAGAIN || err == EWOULDBLOCK) {
#endif
        if (out_state) *out_state = 1;
        if (out_err) *out_err = 0;
        return (int64_t)s;
    }

    if (out_err) *out_err = wing_map_connect_errno(err);
    closesocket(s);
    return -1;
}

int64_t wing_tcp_connect_bound_begin(wing_bytes_ro src_ip, wing_bytes_ro dst_ip, uint16_t dst_port, uint32_t so_mark,
                                     int32_t *out_state, int32_t *out_err) {
    return wing_tcp_connect_opts_begin(src_ip, dst_ip, dst_port, so_mark, 0, 0, 0, 1, 30, 5, 3, 15000, out_state,
                                       out_err);
}

int32_t wing_tcp_connect_status(int64_t sock_fd) {
    if (sock_fd <= 0) return -1;
    int sock_err = 0;
#ifdef _WIN32
    int err_len = (int)sizeof(sock_err);
#else
    socklen_t err_len = (socklen_t)sizeof(sock_err);
#endif
    if (getsockopt((SOCKET)sock_fd, SOL_SOCKET, SO_ERROR, (char *)&sock_err, &err_len) != 0) return -1;
    return wing_map_connect_errno(sock_err);
}

int32_t wing_tcp_recv_peek(int64_t sock_fd, wing_bytes_rw dst) {
    if (sock_fd <= 0 || dst.data == NULL || dst.len <= 0) return -1;
    int r = recv((SOCKET)sock_fd, (char *)dst.data, (int)dst.len, MSG_PEEK);
    if (r >= 0) return (int32_t)r;
    int err = wing_last_sock_err();
#ifdef _WIN32
    if (err == WSAEWOULDBLOCK) return -2;
#else
    if (err == EAGAIN || err == EWOULDBLOCK) return -2;
#endif
    return -1;
}

int32_t wing_tcp_set_ttl(int64_t sock_fd, int32_t ttl, int32_t is_ipv6) {
    if (sock_fd <= 0 || ttl <= 0 || ttl > 255) return -1;
    SOCKET s = (SOCKET)sock_fd;
    if (is_ipv6) {
        return setsockopt(s, IPPROTO_IPV6, IPV6_UNICAST_HOPS, (const char *)&ttl, sizeof(ttl)) == 0 ? 0 : -1;
    }
    return setsockopt(s, IPPROTO_IP, IP_TTL, (const char *)&ttl, sizeof(ttl)) == 0 ? 0 : -1;
}

int32_t wing_pipe_create(int64_t *out_read_fd, int64_t *out_write_fd) {
    if (out_read_fd) *out_read_fd = -1;
    if (out_write_fd) *out_write_fd = -1;
#ifdef __linux__
    int fds[2] = {-1, -1};
    if (pipe2(fds, O_NONBLOCK | O_CLOEXEC) != 0) return -1;
    (void)fcntl(fds[1], F_SETPIPE_SZ, 65536);
    if (out_read_fd) *out_read_fd = (int64_t)fds[0];
    if (out_write_fd) *out_write_fd = (int64_t)fds[1];
    return 0;
#else
    return -1;
#endif
}

void wing_pipe_close(int64_t read_fd, int64_t write_fd) {
#if !defined(_WIN32)
    if (read_fd >= 0) close((int)read_fd);
    if (write_fd >= 0) close((int)write_fd);
#else
    (void)read_fd;
    (void)write_fd;
#endif
}

int64_t wing_tcp_splice_chunk(int64_t src_fd, int64_t dst_fd, int64_t pipe_r, int64_t pipe_w, int64_t max_bytes,
                              int64_t *in_pipe_bytes) {
#ifdef __linux__
    if (src_fd <= 0 || dst_fd <= 0 || pipe_r < 0 || pipe_w < 0 || max_bytes <= 0 || in_pipe_bytes == NULL) return -1;
    if (*in_pipe_bytes == 0) {
        int64_t chunk = max_bytes < 65536 ? max_bytes : 65536;
        ssize_t pulled = splice((int)src_fd, NULL, (int)pipe_w, NULL, (size_t)chunk, SPLICE_F_MOVE | SPLICE_F_NONBLOCK);
        if (pulled == 0) return 0;
        if (pulled < 0) {
            return (errno == EAGAIN || errno == EWOULDBLOCK) ? -2 : -1;
        }
        *in_pipe_bytes = (int64_t)pulled;
    }
    int64_t total_out = 0;
    while (*in_pipe_bytes > 0) {
        ssize_t pushed =
            splice((int)pipe_r, NULL, (int)dst_fd, NULL, (size_t)(*in_pipe_bytes), SPLICE_F_MOVE | SPLICE_F_NONBLOCK);
        if (pushed > 0) {
            *in_pipe_bytes -= (int64_t)pushed;
            total_out += (int64_t)pushed;
            continue;
        }
        if (pushed < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
            return total_out > 0 ? total_out : -2;
        }
        return total_out > 0 ? total_out : -1;
    }
    return total_out;
#else
    (void)src_fd;
    (void)dst_fd;
    (void)pipe_r;
    (void)pipe_w;
    (void)max_bytes;
    (void)in_pipe_bytes;
    return -1;
#endif
}

static void wing_append_ip_line(wing_bytes_rw out_buf, int64_t *pos, const char *ip_str) {
    if (ip_str == NULL || ip_str[0] == '\0') return;
    size_t slen = strlen(ip_str);
    if (*pos + (int64_t)slen + 1 > out_buf.len) return;
    memcpy(out_buf.data + *pos, ip_str, slen);
    *pos += (int64_t)slen;
    out_buf.data[*pos] = '\n';
    *pos += 1;
}

int32_t wing_net_get_local_ips(wing_bytes_rw out_buf) {
    if (out_buf.data == NULL || out_buf.len <= 0) return -1;
    if (wing_tcp_init() != 0) return -1;
    int64_t pos = 0;

#ifdef _WIN32
    wing_append_ip_line(out_buf, &pos, "127.0.0.1");
    wing_append_ip_line(out_buf, &pos, "::1");
    char hostname[256];
    if (gethostname(hostname, sizeof(hostname)) == 0) {
        struct addrinfo hints;
        struct addrinfo *res = NULL;
        memset(&hints, 0, sizeof(hints));
        hints.ai_family = AF_UNSPEC;
        hints.ai_socktype = SOCK_STREAM;
        if (getaddrinfo(hostname, NULL, &hints, &res) == 0 && res != NULL) {
            for (struct addrinfo *p = res; p != NULL; p = p->ai_next) {
                char ipbuf[INET6_ADDRSTRLEN];
                ipbuf[0] = '\0';
                if (p->ai_family == AF_INET) {
                    const struct sockaddr_in *s4 = (const struct sockaddr_in *)p->ai_addr;
                    if (inet_ntop(AF_INET, &s4->sin_addr, ipbuf, sizeof(ipbuf)) != NULL) {
                        wing_append_ip_line(out_buf, &pos, ipbuf);
                    }
                } else if (p->ai_family == AF_INET6) {
                    const struct sockaddr_in6 *s6 = (const struct sockaddr_in6 *)p->ai_addr;
                    if (s6->sin6_scope_id == 0 && inet_ntop(AF_INET6, &s6->sin6_addr, ipbuf, sizeof(ipbuf)) != NULL) {
                        wing_append_ip_line(out_buf, &pos, ipbuf);
                    }
                }
            }
            freeaddrinfo(res);
        }
    }
#else
    struct ifaddrs *ifap = NULL;
    if (getifaddrs(&ifap) == 0 && ifap != NULL) {
        for (struct ifaddrs *ifa = ifap; ifa != NULL; ifa = ifa->ifa_next) {
            if (ifa->ifa_addr == NULL) continue;
            char ipbuf[INET6_ADDRSTRLEN];
            ipbuf[0] = '\0';
            if (ifa->ifa_addr->sa_family == AF_INET) {
                const struct sockaddr_in *s4 = (const struct sockaddr_in *)ifa->ifa_addr;
                if (inet_ntop(AF_INET, &s4->sin_addr, ipbuf, sizeof(ipbuf)) != NULL) {
                    wing_append_ip_line(out_buf, &pos, ipbuf);
                }
            } else if (ifa->ifa_addr->sa_family == AF_INET6) {
                const struct sockaddr_in6 *s6 = (const struct sockaddr_in6 *)ifa->ifa_addr;
                if (s6->sin6_scope_id == 0 && inet_ntop(AF_INET6, &s6->sin6_addr, ipbuf, sizeof(ipbuf)) != NULL) {
                    wing_append_ip_line(out_buf, &pos, ipbuf);
                }
            }
        }
        freeifaddrs(ifap);
    } else {
        wing_append_ip_line(out_buf, &pos, "127.0.0.1");
        wing_append_ip_line(out_buf, &pos, "::1");
    }
#endif
    return (int32_t)pos;
}

int64_t wing_udp_open_dual(wing_bytes_ro bind_ip, uint16_t bind_port, int32_t flags) {
    if (wing_tcp_init() != 0) return -1;

    char bind_str[128];
    slice_to_cstr(bind_ip, bind_str, sizeof(bind_str));

    int force_family = (flags & 2) ? AF_INET6 : AF_INET;
    if (bind_str[0] != '\0') {
        force_family = (strchr(bind_str, ':') != NULL) ? AF_INET6 : AF_INET;
    }

    struct sockaddr_storage ss;
    int family = AF_INET;
    int ss_len = 0;
    if (wing_parse_ip_sockaddr(bind_str, bind_port, force_family, &ss, &family, &ss_len) != 0) return -1;

    SOCKET s = socket(family, SOCK_DGRAM, IPPROTO_UDP);
    if (s == INVALID_SOCKET) return -1;

    wing_prepare_nonblocking_cloexec(s);
    int opt = 1;
    setsockopt(s, SOL_SOCKET, SO_REUSEADDR, (const char *)&opt, sizeof(opt));
    if (family == AF_INET6) {
        int v6only = 1;
        setsockopt(s, IPPROTO_IPV6, IPV6_V6ONLY, (const char *)&v6only, sizeof(v6only));
    }
#ifdef __linux__
    if ((flags & 4) != 0) {
        int fb = 1;
        if (family == AF_INET6) {
            setsockopt(s, IPPROTO_IPV6, IPV6_FREEBIND, &fb, sizeof(fb));
        } else {
            setsockopt(s, IPPROTO_IP, IP_FREEBIND, &fb, sizeof(fb));
        }
    }
#endif

    if (bind_str[0] != '\0' || bind_port != 0) {
#ifdef _WIN32
        if (bind(s, (struct sockaddr *)&ss, ss_len) != 0) {
#else
        if (bind(s, (struct sockaddr *)&ss, (socklen_t)ss_len) != 0) {
#endif
            closesocket(s);
            return -1;
        }
    }
    return (int64_t)s;
}

int32_t wing_udp_sendto_dual(int64_t sock_fd, wing_bytes_ro data, wing_bytes_ro dst_ip, uint16_t dst_port) {
    if (sock_fd <= 0 || data.data == NULL || data.len < 0 || dst_ip.data == NULL || dst_ip.len <= 0 ||
        dst_ip.len >= 128 || dst_port == 0) {
        return -1;
    }
    char dst_str[128];
    slice_to_cstr(dst_ip, dst_str, sizeof(dst_str));

    struct sockaddr_storage ss;
    int family = AF_INET;
    int ss_len = 0;
    if (wing_parse_ip_sockaddr(dst_str, dst_port, 0, &ss, &family, &ss_len) != 0) return -1;

#ifdef _WIN32
    int sent = sendto((SOCKET)sock_fd, (const char *)data.data, (int)data.len, 0, (struct sockaddr *)&ss, ss_len);
#else
    int sent =
        (int)sendto((int)sock_fd, data.data, (size_t)data.len, MSG_NOSIGNAL, (struct sockaddr *)&ss, (socklen_t)ss_len);
#endif
    if (sent >= 0) return (int32_t)sent;
    int err = wing_last_sock_err();
#ifdef _WIN32
    if (err == WSAEWOULDBLOCK) return -2;
#else
    if (err == EAGAIN || err == EWOULDBLOCK) return -2;
#endif
    return -1;
}

int32_t wing_udp_recvfrom_dual(int64_t sock_fd, wing_bytes_rw out_buf, wing_bytes_rw out_peer_ip,
                               int32_t *out_peer_ip_len, uint16_t *out_peer_port) {
    if (out_peer_ip_len) *out_peer_ip_len = 0;
    if (out_peer_port) *out_peer_port = 0;
    if (sock_fd <= 0 || out_buf.data == NULL || out_buf.len <= 0) return -1;

    struct sockaddr_storage peer_ss;
    memset(&peer_ss, 0, sizeof(peer_ss));
#ifdef _WIN32
    int addr_len = (int)sizeof(peer_ss);
#else
    socklen_t addr_len = (socklen_t)sizeof(peer_ss);
#endif
    int got =
        recvfrom((SOCKET)sock_fd, (char *)out_buf.data, (int)out_buf.len, 0, (struct sockaddr *)&peer_ss, &addr_len);
    if (got < 0) {
        int err = wing_last_sock_err();
#ifdef _WIN32
        if (err == WSAEWOULDBLOCK) return -2;
#else
        if (err == EAGAIN || err == EWOULDBLOCK) return -2;
#endif
        return -1;
    }
    if (out_peer_ip.data != NULL && out_peer_ip.len > 0) {
        int32_t plen = wing_format_sockaddr_ip_port(&peer_ss, out_peer_ip, out_peer_port);
        if (out_peer_ip_len && plen > 0) *out_peer_ip_len = plen;
    }
    return (int32_t)got;
}

static uint64_t wing_udp_mono_ms(void) {
#ifdef _WIN32
    return (uint64_t)GetTickCount64();
#else
    struct timespec ts;
    if (clock_gettime(CLOCK_MONOTONIC, &ts) == 0) {
        return (uint64_t)ts.tv_sec * 1000ULL + (uint64_t)(ts.tv_nsec / 1000000L);
    }
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return (uint64_t)tv.tv_sec * 1000ULL + (uint64_t)(tv.tv_usec / 1000L);
#endif
}

static int wing_udp_sockaddr_matches(const struct sockaddr_storage *expected, const struct sockaddr_storage *peer) {
    if (expected->ss_family == AF_INET && peer->ss_family == AF_INET) {
        const struct sockaddr_in *a = (const struct sockaddr_in *)expected;
        const struct sockaddr_in *b = (const struct sockaddr_in *)peer;
        return a->sin_port == b->sin_port && a->sin_addr.s_addr == b->sin_addr.s_addr;
    }
    if (expected->ss_family == AF_INET6 && peer->ss_family == AF_INET6) {
        const struct sockaddr_in6 *a = (const struct sockaddr_in6 *)expected;
        const struct sockaddr_in6 *b = (const struct sockaddr_in6 *)peer;
        return a->sin6_port == b->sin6_port && memcmp(&a->sin6_addr, &b->sin6_addr, sizeof(a->sin6_addr)) == 0 &&
               (a->sin6_scope_id == 0 || a->sin6_scope_id == b->sin6_scope_id);
    }
    return 0;
}

int32_t wing_udp_exchange_dual(wing_bytes_ro server_ip, uint16_t server_port, wing_bytes_ro query,
                               wing_bytes_rw out_resp, uint32_t timeout_ms) {
    if (server_ip.data == NULL || server_ip.len <= 0 || server_ip.len >= 128) return -1;
    if (query.data == NULL || query.len <= 0 || out_resp.data == NULL || out_resp.len <= 0) return -1;
    if (wing_tcp_init() != 0) return -1;

    char srv_str[128];
    slice_to_cstr(server_ip, srv_str, sizeof(srv_str));

    struct sockaddr_storage ss;
    int family = AF_INET;
    int ss_len = 0;
    if (wing_parse_ip_sockaddr(srv_str, server_port, 0, &ss, &family, &ss_len) != 0) return -1;

    SOCKET s = socket(family, SOCK_DGRAM, IPPROTO_UDP);
    if (s == INVALID_SOCKET) return -1;

    wing_prepare_nonblocking_cloexec(s);
#ifdef _WIN32
    int sent = sendto(s, (const char *)query.data, (int)query.len, 0, (struct sockaddr *)&ss, ss_len);
#else
    int sent = (int)sendto(s, query.data, (size_t)query.len, 0, (struct sockaddr *)&ss, (socklen_t)ss_len);
#endif
    if (sent != (int)query.len) {
        closesocket(s);
        return -1;
    }

    uint64_t deadline = wing_udp_mono_ms() + (uint64_t)timeout_ms;
    for (int attempt = 0; attempt < 128; attempt++) {
        uint64_t now = wing_udp_mono_ms();
        if (attempt > 0 && now >= deadline) {
            closesocket(s);
            return -2;
        }
        uint32_t rem_ms = (now < deadline) ? (uint32_t)(deadline - now) : 0U;
        int sel = wing_wait_fd(s, 0, rem_ms);
        if (sel <= 0) {
            closesocket(s);
            return sel == 0 ? -2 : -1;
        }

        struct sockaddr_storage peer_ss;
        memset(&peer_ss, 0, sizeof(peer_ss));
#ifdef _WIN32
        int peer_len = (int)sizeof(peer_ss);
#else
        socklen_t peer_len = (socklen_t)sizeof(peer_ss);
#endif
        int got = recvfrom(s, (char *)out_resp.data, (int)out_resp.len, 0, (struct sockaddr *)&peer_ss, &peer_len);
        if (got < 0) {
            int err = wing_last_sock_err();
#ifdef _WIN32
            if (err == WSAEWOULDBLOCK) continue;
#else
            if (err == EAGAIN || err == EWOULDBLOCK) continue;
#endif
            closesocket(s);
            return -1;
        }
        if (got == 0 || !wing_udp_sockaddr_matches(&ss, &peer_ss)) {
            continue;
        }
        closesocket(s);
        return (int32_t)got;
    }

    closesocket(s);
    return -2;
}

int32_t wing_fs_disk_usage_percent(wing_bytes_ro path) {
    if (path.data == NULL || path.len <= 0 || path.len >= 1024) return -1;
    char pstr[1024];
    slice_to_cstr(path, pstr, sizeof(pstr));
#ifdef _WIN32
    ULARGE_INTEGER avail_bytes, total_bytes, free_bytes;
    if (!GetDiskFreeSpaceExA(pstr, &avail_bytes, &total_bytes, &free_bytes)) return -1;
    if (total_bytes.QuadPart == 0) return 100;
    uint64_t used = total_bytes.QuadPart - avail_bytes.QuadPart;
    uint64_t pct = (used * 100ULL) / total_bytes.QuadPart;
    return (int32_t)(pct > 100ULL ? 100ULL : pct);
#else
    struct statvfs sv;
    if (statvfs(pstr, &sv) != 0) return -1;
    uint64_t used_blocks = (uint64_t)(sv.f_blocks - sv.f_bfree);
    uint64_t total_user = used_blocks + (uint64_t)sv.f_bavail;
    if (total_user == 0) return 100;
    uint64_t pct = (used_blocks * 100ULL) / total_user;
    return (int32_t)(pct > 100ULL ? 100ULL : pct);
#endif
}

int64_t wing_fs_file_mtime(wing_bytes_ro path) {
    if (path.data == NULL || path.len <= 0 || path.len >= 1024) return -1;
    char pstr[1024];
    slice_to_cstr(path, pstr, sizeof(pstr));
#ifdef _WIN32
    struct _stat64 st;
    if (_stat64(pstr, &st) != 0) return -1;
    return (int64_t)st.st_mtime;
#else
    struct stat st;
    if (stat(pstr, &st) != 0) return -1;
    return (int64_t)st.st_mtime;
#endif
}

#endif // !defined(__wasm__)

// ---- Cross-Platform Process Shutdown & Reload Signals ---------------------

#ifdef _WIN32
static void wing_win_crt_signal_handler(int sig) {
    (void)sig;
    g_wing_stop_requested = 1;
}

static BOOL WINAPI wing_win_console_ctrl_handler(DWORD ctrl_type) {
    switch (ctrl_type) {
    case CTRL_C_EVENT:
    case CTRL_BREAK_EVENT:
    case CTRL_CLOSE_EVENT:
    case CTRL_SHUTDOWN_EVENT:
        g_wing_stop_requested = 1;
        return TRUE;
    default:
        return FALSE;
    }
}

int32_t wing_install_shutdown_signals(void) {
    signal(SIGINT, wing_win_crt_signal_handler);
    signal(SIGTERM, wing_win_crt_signal_handler);
    if (!g_wing_signals_installed) {
        (void)SetConsoleCtrlHandler(wing_win_console_ctrl_handler, TRUE);
        g_wing_signals_installed = 1;
    }
    return 0;
}
#elif defined(__wasm__)
int32_t wing_install_shutdown_signals(void) { return 0; }
#else
static void wing_posix_stop_handler(int sig) {
    (void)sig;
    g_wing_stop_requested = 1;
}

static void wing_posix_reload_handler(int sig) {
    (void)sig;
    g_wing_reload_requested = 1;
}

int32_t wing_install_shutdown_signals(void) {
    struct sigaction sa_stop;
    memset(&sa_stop, 0, sizeof(sa_stop));
    sa_stop.sa_handler = wing_posix_stop_handler;
    sigemptyset(&sa_stop.sa_mask);
    // Omit SA_RESTART so blocking accept/poll/epoll_wait wakes immediately with EINTR.
    sa_stop.sa_flags = 0;
    if (sigaction(SIGINT, &sa_stop, NULL) != 0) return -1;
    if (sigaction(SIGTERM, &sa_stop, NULL) != 0) return -1;

    struct sigaction sa_reload;
    memset(&sa_reload, 0, sizeof(sa_reload));
    sa_reload.sa_handler = wing_posix_reload_handler;
    sigemptyset(&sa_reload.sa_mask);
    sa_reload.sa_flags = SA_RESTART;
    (void)sigaction(SIGHUP, &sa_reload, NULL);

    g_wing_signals_installed = 1;
    return 0;
}
#endif

int32_t wing_shutdown_requested(void) { return g_wing_stop_requested != 0 ? 1 : 0; }

void wing_request_shutdown(void) { g_wing_stop_requested = 1; }

void wing_reset_shutdown_signals(void) {
    g_wing_stop_requested = 0;
    g_wing_reload_requested = 0;
}

int32_t wing_consume_reload_signal(void) {
    if (g_wing_reload_requested != 0) {
        g_wing_reload_requested = 0;
        return 1;
    }
    return 0;
}

// Compile-time host OS identifier matching Goose net_internal::TargetPlatform:
// 0 = Windows, 1 = Linux, 2 = Darwin/BSD, 3 = Unknown/WASM.
int32_t wing_host_platform(void) {
#if defined(__wasm__)
    return 3;
#elif defined(_WIN32)
    return 0;
#elif defined(__linux__)
    return 1;
#elif defined(__APPLE__) || defined(__FreeBSD__) || defined(__OpenBSD__) || defined(__NetBSD__) ||                     \
    defined(__DragonFly__)
    return 2;
#else
    return 3;
#endif
}

// ---- Cross-Platform TLS State Locks ---------------------------------------
// Lock IDs: 0 = cipher slot table, 1 = entropy pool, 2 = session ticket cache.

#define WING_TLS_LOCK_COUNT 3

#if defined(_WIN32)
static SRWLOCK g_wing_tls_locks[WING_TLS_LOCK_COUNT] = {
    SRWLOCK_INIT,
    SRWLOCK_INIT,
    SRWLOCK_INIT,
};

void wing_tls_state_lock(int32_t lock_id) {
    if (lock_id < 0 || lock_id >= WING_TLS_LOCK_COUNT) return;
    AcquireSRWLockExclusive(&g_wing_tls_locks[lock_id]);
}

void wing_tls_state_unlock(int32_t lock_id) {
    if (lock_id < 0 || lock_id >= WING_TLS_LOCK_COUNT) return;
    ReleaseSRWLockExclusive(&g_wing_tls_locks[lock_id]);
}
#elif !defined(__wasm__)
static pthread_mutex_t g_wing_tls_locks[WING_TLS_LOCK_COUNT] = {
    PTHREAD_MUTEX_INITIALIZER,
    PTHREAD_MUTEX_INITIALIZER,
    PTHREAD_MUTEX_INITIALIZER,
};

void wing_tls_state_lock(int32_t lock_id) {
    if (lock_id < 0 || lock_id >= WING_TLS_LOCK_COUNT) return;
    pthread_mutex_lock(&g_wing_tls_locks[lock_id]);
}

void wing_tls_state_unlock(int32_t lock_id) {
    if (lock_id < 0 || lock_id >= WING_TLS_LOCK_COUNT) return;
    pthread_mutex_unlock(&g_wing_tls_locks[lock_id]);
}
#else
void wing_tls_state_lock(int32_t lock_id) { (void)lock_id; }

void wing_tls_state_unlock(int32_t lock_id) { (void)lock_id; }
#endif

void wing_write_stderr(wing_bytes_ro msg) {
    if (msg.data != NULL && msg.len > 0) {
        (void)fwrite(msg.data, 1, (size_t)msg.len, stderr);
        fflush(stderr);
    }
}
