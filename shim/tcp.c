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
#include <windows.h>
#pragma comment(lib, "ws2_32.lib")
#else
#include <sys/types.h>
#include <sys/socket.h>
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
