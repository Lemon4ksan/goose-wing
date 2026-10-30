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

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#include <mstcpip.h>
#include <afunix.h>
#include <windows.h>
#ifdef _MSC_VER
#pragma comment(lib, "ws2_32.lib")
#endif
#elif defined(__wasm__)
#include <unistd.h>
#include <errno.h>
typedef int SOCKET;
#define INVALID_SOCKET (-1)
#define SOCKET_ERROR   (-1)
#define closesocket(s) close(s)
#define MSG_NOSIGNAL 0
#else
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/ioctl.h>
#include <sys/uio.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/time.h>
#include <signal.h>
#include <errno.h>
#if defined(__linux__)
#include <sched.h>
#include <pthread.h>
#endif
typedef int SOCKET;
#define INVALID_SOCKET (-1)
#define SOCKET_ERROR   (-1)
#define closesocket(s) close(s)
#ifndef MSG_NOSIGNAL
#define MSG_NOSIGNAL 0
#endif
#endif

#ifndef MSG_NOSIGNAL
#define MSG_NOSIGNAL 0
#endif

#pragma pack(push, 1)
typedef struct { const uint8_t *data; int64_t len; } wing_bytes_ro;
typedef struct { uint8_t *data; int64_t len; } wing_bytes_rw;
typedef struct { int64_t *data; int64_t len; } wing_slice_i64;
typedef struct { uint64_t *data; int64_t len; } wing_slice_u64;
typedef struct { uint32_t *data; int64_t len; } wing_slice_u32;
#pragma pack(pop)

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

int64_t wing_tcp_listen_unix(wing_bytes_ro path, int32_t backlog) {
    return wing_tcp_listen(path, 0, backlog);
}

int64_t wing_tcp_connect_unix(wing_bytes_ro path) {
    return wing_tcp_connect(path, 0, 500);
}

int64_t wing_adopt_socket(int64_t raw_fd) {
    return raw_fd > 0 ? raw_fd : -1;
}

uint16_t wing_tcp_getsockname_port(int64_t sock_fd) {
    if (sock_fd > 0 && sock_fd < WASM_MAX_SOCKETS && g_wasm_sockets[sock_fd].active) {
        return g_wasm_sockets[sock_fd].port;
    }
    return 0;
}

int64_t wing_tcp_accept(int64_t listener_fd, uint32_t timeout_ms) {
    (void)timeout_ms;
    if (listener_fd <= 0 || listener_fd >= WASM_MAX_SOCKETS || !g_wasm_sockets[listener_fd].active || !g_wasm_sockets[listener_fd].is_listener) {
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

int64_t wing_tcp_accept_nonblocking(int64_t listener_fd) {
    return wing_tcp_accept(listener_fd, 0);
}

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
            if (client_slot < 0) client_slot = i;
            else if (server_slot < 0) { server_slot = i; break; }
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

int32_t wing_tcp_send(int64_t sock_fd, wing_bytes_ro data) {
    if (sock_fd <= 0 || sock_fd >= WASM_MAX_SOCKETS || !g_wasm_sockets[sock_fd].active || data.data == NULL || data.len <= 0) {
        return 0;
    }
    int peer = g_wasm_sockets[sock_fd].peer_slot;
    if (peer <= 0 || peer >= WASM_MAX_SOCKETS || !g_wasm_sockets[peer].active) {
        return -1; // Connection broken/closed
    }
    wasm_virtual_socket_t *p = &g_wasm_sockets[peer];
    int64_t avail = WASM_SOCK_BUF_SIZE - (p->rx_tail - p->rx_head);
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
    if (sock_fd <= 0 || sock_fd >= WASM_MAX_SOCKETS || !g_wasm_sockets[sock_fd].active || buf.data == NULL || buf.len <= 0) {
        return -1;
    }
    wasm_virtual_socket_t *s = &g_wasm_sockets[sock_fd];
    int64_t readable = s->rx_tail - s->rx_head;
    if (readable <= 0) {
        if (s->peer_slot < 0 || (s->peer_slot > 0 && s->peer_slot < WASM_MAX_SOCKETS && g_wasm_sockets[s->peer_slot].write_shut)) return 0; // Peer closed connection or shut down write side (EOF)
        return -2; // WouldBlock / Timeout (peer connected, no data ready)
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

int32_t wing_tcp_recv_nonblocking(int64_t sock_fd, wing_bytes_rw buf) {
    return wing_tcp_recv(sock_fd, buf, 0);
}

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

int32_t wing_tcp_set_defer_accept(int64_t sock_fd, int32_t timeout_sec) { (void)sock_fd; (void)timeout_sec; return 0; }
int32_t wing_tcp_set_user_timeout(int64_t sock_fd, uint32_t timeout_ms) { (void)sock_fd; (void)timeout_ms; return 0; }
int32_t wing_tcp_set_keepalive_params(int64_t sock_fd, int32_t idle_sec, int32_t intvl_sec, int32_t cnt) { (void)sock_fd; (void)idle_sec; (void)intvl_sec; (void)cnt; return 0; }
int32_t wing_tcp_set_syn_retries(int64_t sock_fd, int32_t count) { (void)sock_fd; (void)count; return 0; }
int32_t wing_tcp_set_fastopen(int64_t sock_fd, int32_t qlen) { (void)sock_fd; (void)qlen; return 0; }
int32_t wing_tcp_send_fastopen(int64_t sock_fd, wing_bytes_ro data) { return wing_tcp_send(sock_fd, data); }
int32_t wing_tcp_set_tos(int64_t sock_fd, int32_t tos) { (void)sock_fd; (void)tos; return 0; }
int32_t wing_tcp_set_tclass(int64_t sock_fd, int32_t tclass) { (void)sock_fd; (void)tclass; return 0; }
int64_t wing_tcp_get_notsent_bytes(int64_t sock_fd) { (void)sock_fd; return 0; }
int64_t wing_tcp_get_readable_bytes(int64_t sock_fd) {
    if (sock_fd > 0 && sock_fd < WASM_MAX_SOCKETS && g_wasm_sockets[sock_fd].active) {
        return g_wasm_sockets[sock_fd].rx_tail - g_wasm_sockets[sock_fd].rx_head;
    }
    return 0;
}
int32_t wing_tcp_set_nonblocking(int64_t sock_fd, int32_t nonblocking) { (void)sock_fd; (void)nonblocking; return 0; }
int32_t wing_tcp_set_quickack(int64_t sock_fd, int32_t enable) { (void)sock_fd; (void)enable; return 0; }
int32_t wing_tcp_set_cork(int64_t sock_fd, int32_t enable) { (void)sock_fd; (void)enable; return 0; }

int64_t wing_fast_cork_append(int64_t conn, wing_bytes_rw cork_buf, int64_t cork_len, wing_bytes_ro resp) {
    (void)conn;
    if (!cork_buf.data || !resp.data || resp.len <= 0) return cork_len;
    if (cork_len < 0 || cork_len + resp.len > cork_buf.len) return -1;
    memcpy(cork_buf.data + cork_len, resp.data, (size_t)resp.len);
    return cork_len + resp.len;
}

int32_t wing_set_cpu_affinity(int64_t cpu_id) { (void)cpu_id; return 0; }
int32_t wing_tcp_set_incoming_cpu(int64_t sock_fd, int64_t cpu_id) { (void)sock_fd; (void)cpu_id; return 0; }

int64_t wing_epoll_create(void) { return 1; }
int32_t wing_epoll_add(int64_t epfd, int64_t sock_fd, uint32_t events, uint64_t udata) { (void)epfd; (void)sock_fd; (void)events; (void)udata; return 0; }
int32_t wing_epoll_mod(int64_t epfd, int64_t sock_fd, uint32_t events, uint64_t udata) { (void)epfd; (void)sock_fd; (void)events; (void)udata; return 0; }
int32_t wing_epoll_del(int64_t epfd, int64_t sock_fd) { (void)epfd; (void)sock_fd; return 0; }
int32_t wing_epoll_wait(int64_t epfd, wing_slice_i64 out_fds, wing_slice_u64 out_udata, int32_t timeout_ms) { (void)epfd; (void)out_fds; (void)out_udata; (void)timeout_ms; return 0; }
void wing_epoll_close(int64_t epfd) { (void)epfd; }

int64_t wing_udp_listen(wing_bytes_ro host, uint16_t port) { return wing_tcp_listen(host, port, 16); }
int64_t wing_udp_connect(wing_bytes_ro host, uint16_t port) { return wing_tcp_connect(host, port, 0); }
int32_t wing_udp_send(int64_t sock_fd, wing_bytes_ro data) { return wing_tcp_send(sock_fd, data); }
int32_t wing_udp_recv(int64_t sock_fd, wing_bytes_rw buf, uint32_t timeout_ms) { return wing_tcp_recv(sock_fd, buf, timeout_ms); }
int32_t wing_udp_recvfrom(int64_t sock_fd, wing_bytes_rw buf, uint32_t timeout_ms, uint32_t *peer_ip4, uint16_t *peer_port) {
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
    (void)peer_ip4; (void)peer_port;
    return wing_tcp_send(sock_fd, data);
}

#else

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

// Retrieves the locally bound port for a socket.
uint16_t wing_tcp_getsockname_port(int64_t sock_fd) {
    if (sock_fd <= 0) return 0;
    struct sockaddr_in addr;
    int len = sizeof(addr);
    memset(&addr, 0, sizeof(addr));
    if (getsockname((SOCKET)sock_fd, (struct sockaddr *)&addr, &len) == SOCKET_ERROR) {
        return 0;
    }
    return ntohs(addr.sin_port);
}

// Accepts an incoming connection with an optional timeout in milliseconds.
int64_t wing_tcp_accept(int64_t listener_fd, uint32_t timeout_ms) {
    if (listener_fd <= 0) return -1;
    SOCKET l = (SOCKET)listener_fd;

    if (timeout_ms > 0) {
        fd_set read_fds;
        FD_ZERO(&read_fds);
        FD_SET(l, &read_fds);

        struct timeval tv;
        tv.tv_sec = timeout_ms / 1000;
        tv.tv_usec = (timeout_ms % 1000) * 1000;

        int sel = select((int)(l + 1), &read_fds, NULL, NULL, &tv);
        if (sel <= 0) {
            return sel == 0 ? 0 : -1;
        }
    }

    struct sockaddr_in client_addr;
    int addr_len = sizeof(client_addr);
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

    int bufsize = 262144;
    setsockopt(client_sock, SOL_SOCKET, SO_SNDBUF, (const char *)&bufsize, sizeof(bufsize));
    setsockopt(client_sock, SOL_SOCKET, SO_RCVBUF, (const char *)&bufsize, sizeof(bufsize));

#if defined(__linux__) && defined(TCP_QUICKACK)
    int qack = 1;
    setsockopt(client_sock, IPPROTO_TCP, TCP_QUICKACK, &qack, sizeof(qack));
#endif

    return (int64_t)client_sock;
}

// Connects to remote host:port with timeout in milliseconds.
int64_t wing_tcp_connect(wing_bytes_ro host, uint16_t port, uint32_t timeout_ms) {
    wing_tcp_init();

    SOCKET s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (s == INVALID_SOCKET) {
        return -1;
    }
#ifdef _WIN32
    // uSockets #263: Do not inherit socket handles into child processes (prevents keep-alive hangs)
    SetHandleInformation((HANDLE)s, HANDLE_FLAG_INHERIT, 0);
#endif

    int nodelay = 1;
    setsockopt(s, IPPROTO_TCP, TCP_NODELAY, (const char *)&nodelay, sizeof(nodelay));

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
    }

    if (timeout_ms == 0) {
        if (connect(s, (struct sockaddr *)&addr, sizeof(addr)) == SOCKET_ERROR) {
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

    int res = connect(s, (struct sockaddr *)&addr, sizeof(addr));
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
        fd_set write_fds;
        FD_ZERO(&write_fds);
        FD_SET(s, &write_fds);

        // uSockets #258 / #259 & Winsock2 spec:
        // On Windows, connection failures (RST / ECONNREFUSED) are delivered via exceptfds, NOT writefds.
        // Without exceptfds, select() ignores connection errors and freezes until the entire timeout expires.
        fd_set except_fds;
        FD_ZERO(&except_fds);
        FD_SET(s, &except_fds);

        struct timeval tv;
        tv.tv_sec = timeout_ms / 1000;
        tv.tv_usec = (timeout_ms % 1000) * 1000;

        int sel = select((int)(s + 1), NULL, &write_fds, &except_fds, &tv);
        if (sel <= 0) {
            closesocket(s);
            return -1;
        }

        if (FD_ISSET(s, &except_fds)) {
            closesocket(s);
            return -1;
        }

        int sock_err = 0;
        int err_len = sizeof(sock_err);
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

// Sends bytes to socket, ensuring complete write across non-blocking transient buffers.
int32_t wing_tcp_send(int64_t sock_fd, wing_bytes_ro data) {
    if (sock_fd <= 0 || data.data == NULL || data.len <= 0) return 0;
    SOCKET s = (SOCKET)sock_fd;
    const char *ptr = (const char *)data.data;
    size_t remaining = (size_t)data.len;

    while (remaining > 0) {
#ifdef _WIN32
        int sent = send(s, ptr, (int)remaining, 0);
        if (sent < 0) {
            int err = WSAGetLastError();
            if (err == WSAEWOULDBLOCK) {
                return (int32_t)(data.len - remaining);
            }
            return (data.len - remaining) > 0 ? (int32_t)(data.len - remaining) : -1;
        }
#else
        ssize_t sent = send(s, ptr, remaining, MSG_NOSIGNAL);
        if (sent < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                return (int32_t)(data.len - remaining);
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
    SOCKET s = (SOCKET)sock_fd;

    if (timeout_ms > 0) {
        fd_set read_fds;
        FD_ZERO(&read_fds);
        FD_SET(s, &read_fds);

        struct timeval tv;
        tv.tv_sec = timeout_ms / 1000;
        tv.tv_usec = (timeout_ms % 1000) * 1000;

        int sel = select((int)(s + 1), &read_fds, NULL, NULL, &tv);
        if (sel == 0) return -2; // Timeout
        if (sel < 0) return -1;  // Error
    }

    int recvd = recv(s, (char *)buf.data, (int)buf.len, 0);
    return (int32_t)recvd;
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
    if (how == 0) win_how = SD_RECEIVE;
    else if (how == 2) win_how = SD_BOTH;
    return shutdown((SOCKET)sock_fd, win_how) == 0 ? 0 : -1;
#else
    int posix_how = SHUT_WR;
    if (how == 0) posix_how = SHUT_RD;
    else if (how == 2) posix_how = SHUT_RDWR;
    return shutdown((int)sock_fd, posix_how) == 0 ? 0 : -1;
#endif
}

// Configures SO_LINGER on socket (onoff: 0/1, linger_sec: timeout in seconds).
int32_t wing_tcp_set_linger(int64_t sock_fd, int32_t onoff, int32_t linger_sec) {
    if (sock_fd <= 0) return -1;
#if defined(__wasm__)
    (void)onoff; (void)linger_sec;
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

// Cryptographically secure pseudorandom byte generator (RtlGenRandom on Windows, getrandom on Linux).
int32_t wing_crypto_random_bytes(wing_bytes_rw out) {
    if (out.data == NULL || out.len <= 0) return 0;
#ifdef _WIN32
    typedef BOOLEAN (NTAPI *RtlGenRandomFn)(PVOID, ULONG);
    static RtlGenRandomFn pfnRtlGenRandom = NULL;
    if (pfnRtlGenRandom == NULL) {
        HMODULE hAdvApi = GetModuleHandleA("advapi32.dll");
        if (hAdvApi != NULL) {
            pfnRtlGenRandom = (RtlGenRandomFn)(void *)GetProcAddress(hAdvApi, "SystemFunction036");
        }
    }
    if (pfnRtlGenRandom != NULL) {
        if (pfnRtlGenRandom(out.data, (ULONG)out.len)) return 0;
    }
    return -1;
#elif defined(__linux__) && defined(SYS_getrandom)
    long res = syscall(SYS_getrandom, out.data, (size_t)out.len, 0);
    return res == (long)out.len ? 0 : -1;
#else
    int fd = open("/dev/urandom", O_RDONLY);
    if (fd >= 0) {
        ssize_t res = read(fd, out.data, (size_t)out.len);
        close(fd);
        return res == (ssize_t)out.len ? 0 : -1;
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
    return (WSAIoctl((SOCKET)sock_fd, SIO_KEEPALIVE_VALS, &settings, sizeof(settings), NULL, 0, &bytes_ret, NULL, NULL) == 0) ? 0 : -1;
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
    (void)idle_sec; (void)intvl_sec; (void)cnt;
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

// Sends multiple slices via vectored I/O (WSASend on Windows, writev on POSIX).
int32_t wing_tcp_sendv(int64_t sock_fd, const wing_bytes_ro *iov, int32_t iovcnt) {
    if (sock_fd <= 0 || iov == NULL || iovcnt <= 0) return 0;
#ifdef _WIN32
    WSABUF bufs[16];
    int count = iovcnt > 16 ? 16 : iovcnt;
    for (int i = 0; i < count; i++) {
        bufs[i].buf = (char *)iov[i].data;
        bufs[i].len = (ULONG)iov[i].len;
    }
    DWORD sent = 0;
    int res = WSASend((SOCKET)sock_fd, bufs, (DWORD)count, &sent, 0, NULL, NULL);
    if (res == 0) return (int32_t)sent;
    return -1;
#else
    struct iovec bufs[16];
    int count = iovcnt > 16 ? 16 : iovcnt;
    for (int i = 0; i < count; i++) {
        bufs[i].iov_base = (void *)iov[i].data;
        bufs[i].iov_len = (size_t)iov[i].len;
    }
    ssize_t sent = writev((int)sock_fd, bufs, count);
    return (int32_t)sent;
#endif
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

    int bufsize = 262144;
    setsockopt(client_sock, SOL_SOCKET, SO_SNDBUF, (const char *)&bufsize, sizeof(bufsize));
    setsockopt(client_sock, SOL_SOCKET, SO_RCVBUF, (const char *)&bufsize, sizeof(bufsize));

#if defined(__linux__) && defined(TCP_QUICKACK)
    int qack = 1;
    setsockopt(client_sock, IPPROTO_TCP, TCP_QUICKACK, &qack, sizeof(qack));
#endif

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
    if (!ctx || ctx->count <= 0 || out_fds.data == NULL || out_fds.len <= 0) return 0;

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
    for (int i = 0; i < count && ready < (int)out_fds.len; i++) {
        if (pfd[i].revents != 0) {
            out_fds.data[ready] = (int64_t)pfd[i].fd;
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
    if (getenv("WING_NO_INCOMING_CPU")) return 0;
    long total_cpus = sysconf(_SC_NPROCESSORS_ONLN);
    int target_cpu = (int)cpu_id;
    if (total_cpus > 1) {
        int phys = (int)(total_cpus / 2);
        target_cpu = (cpu_id < phys) ? (int)(cpu_id * 2) : (int)((cpu_id - phys) * 2 + 1);
    }
    int cpu = target_cpu % (int)total_cpus;
    return setsockopt((int)sock_fd, SOL_SOCKET, SO_INCOMING_CPU, &cpu, sizeof(cpu));
#else
    (void)sock_fd; (void)cpu_id;
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
    }

    int res = sendto(s, (const char *)data.data, (int)data.len, MSG_NOSIGNAL, (struct sockaddr *)&addr, sizeof(addr));
    return res;
}

// Receives a UDP datagram with timeout. Returns bytes read, or -2 on timeout, or -1 on error.
int32_t wing_udp_recvfrom(int64_t sock_fd, wing_bytes_rw buf, uint32_t timeout_ms, uint32_t *peer_ip4, uint16_t *peer_port) {
    if (sock_fd <= 0 || buf.data == NULL || buf.len <= 0) {
        return -1;
    }
    SOCKET s = (SOCKET)sock_fd;

    if (timeout_ms > 0) {
        fd_set readfds;
        FD_ZERO(&readfds);
        FD_SET(s, &readfds);

        struct timeval tv;
        tv.tv_sec = timeout_ms / 1000;
        tv.tv_usec = (timeout_ms % 1000) * 1000;

        int sel = select((int)s + 1, &readfds, NULL, NULL, &tv);
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

#endif // !defined(__wasm__)
