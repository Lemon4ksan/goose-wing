// Layer 4 Cross-Platform TCP Socket C Shim for goose-wing.
// Zero-allocation, high-performance synchronous & non-blocking socket operations
// conforming exactly to Goose slice binary layout.

#define WIN32_LEAN_AND_MEAN
#include <stdint.h>
#include <stddef.h>
#include <string.h>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#include <mstcpip.h>
#include <windows.h>
#pragma comment(lib, "ws2_32.lib")
#else
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/uio.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/time.h>
#include <errno.h>
typedef int SOCKET;
#define INVALID_SOCKET (-1)
#define SOCKET_ERROR   (-1)
#define closesocket(s) close(s)
#endif

#pragma pack(push, 1)
typedef struct { const uint8_t *data; int64_t len; } wing_bytes_ro;
typedef struct { uint8_t *data; int64_t len; } wing_bytes_rw;
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

// Initializes socket subsystem (WSAStartup on Windows).
int32_t wing_tcp_init(void) {
#ifdef _WIN32
    WSADATA wsa_data;
    return (int32_t)WSAStartup(MAKEWORD(2, 2), &wsa_data);
#else
    return 0;
#endif
}

// Cleans up socket subsystem (WSACleanup on Windows).
void wing_tcp_cleanup(void) {
#ifdef _WIN32
    WSACleanup();
#endif
}

// Creates, binds, and listens on host:port.
int64_t wing_tcp_listen(wing_bytes_ro host, uint16_t port, int32_t backlog) {
    wing_tcp_init();

    SOCKET s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (s == INVALID_SOCKET) {
        return -1;
    }

    int opt = 1;
    setsockopt(s, SOL_SOCKET, SO_REUSEADDR, (const char *)&opt, sizeof(opt));

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

    int nodelay = 1;
    setsockopt(client_sock, IPPROTO_TCP, TCP_NODELAY, (const char *)&nodelay, sizeof(nodelay));

    return (int64_t)client_sock;
}

// Connects to remote host:port with timeout in milliseconds.
int64_t wing_tcp_connect(wing_bytes_ro host, uint16_t port, uint32_t timeout_ms) {
    wing_tcp_init();

    SOCKET s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (s == INVALID_SOCKET) {
        return -1;
    }

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

        struct timeval tv;
        tv.tv_sec = timeout_ms / 1000;
        tv.tv_usec = (timeout_ms % 1000) * 1000;

        int sel = select((int)(s + 1), NULL, &write_fds, NULL, &tv);
        if (sel <= 0) {
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

// Sends bytes to socket.
int32_t wing_tcp_send(int64_t sock_fd, wing_bytes_ro data) {
    if (sock_fd <= 0 || data.data == NULL || data.len <= 0) return 0;
    int sent = send((SOCKET)sock_fd, (const char *)data.data, (int)data.len, 0);
    return (int32_t)sent;
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

// Cryptographically secure pseudorandom byte generator (RtlGenRandom on Windows, getrandom on Linux).
int32_t wing_crypto_random_bytes(wing_bytes_rw out) {
    if (out.data == NULL || out.len <= 0) return 0;
#ifdef _WIN32
    typedef BOOLEAN (NTAPI *RtlGenRandomFn)(PVOID, ULONG);
    static RtlGenRandomFn pfnRtlGenRandom = NULL;
    if (pfnRtlGenRandom == NULL) {
        HMODULE hAdvApi = GetModuleHandleA("advapi32.dll");
        if (hAdvApi != NULL) {
            pfnRtlGenRandom = (RtlGenRandomFn)GetProcAddress(hAdvApi, "SystemFunction036");
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

// Queries kernel backlog of unacknowledged / unsent bytes (tcpi_notsent_bytes via TCP_INFO).
int64_t wing_tcp_get_notsent_bytes(int64_t sock_fd) {
    if (sock_fd <= 0) return -1;
#if defined(__linux__) && defined(TCP_INFO)
    struct tcp_info info;
    socklen_t len = sizeof(info);
    if (getsockopt((int)sock_fd, IPPROTO_TCP, TCP_INFO, &info, &len) == 0) {
        return (int64_t)info.tcpi_notsent_bytes;
    }
#elif defined(TIOCOUTQ)
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
