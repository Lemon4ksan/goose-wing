// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Layer 4 Windows Registered I/O (RIO) Kernel-Bypass C Shim.
// Queries the RIO Extension Function Table via SIO_GET_MULTIPLE_EXTENSION_FUNCTION_POINTER,
// manages page-locked registered memory buffers, RIONotify events, and AcceptEx RIO sockets.
#define WIN32_LEAN_AND_MEAN
#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0602
#endif

#include <stdint.h>
#include <stddef.h>
#include <string.h>

typedef struct {
    int32_t status;
    uint32_t bytes_transferred;
    uint64_t socket_context;
    uint64_t request_context;
} WING_RIO_RESULT_SLICE_ITEM;

_Static_assert(sizeof(WING_RIO_RESULT_SLICE_ITEM) == 24, "WING_RIO_RESULT_SLICE_ITEM must match Goose RioResult (24B)");

typedef struct {
    const char *data;
    int64_t len;
} wing_rio_str_ro;

typedef struct {
    uint8_t *data;
    int64_t len;
} wing_rio_bytes_rw;

typedef struct {
    WING_RIO_RESULT_SLICE_ITEM *data;
    int64_t len;
} wing_rio_results_rw;

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#include <mswsock.h>
#include <windows.h>

#ifndef SIO_GET_MULTIPLE_EXTENSION_FUNCTION_POINTER
#define SIO_GET_MULTIPLE_EXTENSION_FUNCTION_POINTER _WSAIORW(IOC_WS2, 36)
#endif

#ifndef WSA_FLAG_REGISTERED_IO
#define WSA_FLAG_REGISTERED_IO 0x100
#endif

#ifndef SO_UPDATE_ACCEPT_CONTEXT
#define SO_UPDATE_ACCEPT_CONTEXT 0x700B
#endif

static const GUID k_rio_guid = {0x8509E081, 0x96DD, 0x4005, {0xB1, 0x65, 0x9E, 0x2E, 0xE8, 0xC7, 0x9E, 0x3F}};
static const GUID k_acceptex_guid = {0xB5367DF1, 0xCBAC, 0x11CF, {0x95, 0xCA, 0x00, 0x80, 0x5F, 0x48, 0xA1, 0x92}};

typedef void *WING_RIO_BUFFERID;
#define WING_RIO_INVALID_BUFFERID ((WING_RIO_BUFFERID)(uintptr_t)0xFFFFFFFFUL)
#ifndef RIO_INVALID_BUFFERID
#define RIO_INVALID_BUFFERID ((void *)(uintptr_t)0xFFFFFFFFUL)
#endif
#ifndef RIO_INVALID_CQ
#define RIO_INVALID_CQ ((void *)0)
#endif
#ifndef RIO_INVALID_RQ
#define RIO_INVALID_RQ ((void *)0)
#endif
typedef void *WING_RIO_CQ;
typedef void *WING_RIO_RQ;

typedef struct _WING_RIO_BUF {
    WING_RIO_BUFFERID BufferId;
    ULONG Offset;
    ULONG Length;
} WING_RIO_BUF;

typedef struct _WING_RIO_RESULT {
    LONG Status;
    ULONG BytesTransferred;
    ULONGLONG ConnectionCorrelation;
    ULONGLONG RequestCorrelation;
} WING_RIO_RESULT;

_Static_assert(sizeof(WING_RIO_RESULT) == 24, "WING_RIO_RESULT must be 24 bytes");

typedef struct _WING_RIO_NOTIFICATION_COMPLETION {
    int Type; // RIO_EVENT_COMPLETION = 1
    union {
        struct {
            HANDLE EventHandle;
            BOOL NotifyReset;
        } Event;
        struct {
            HANDLE IocpHandle;
            PVOID CompletionKey;
            PVOID Overlapped;
        } Iocp;
    };
} WING_RIO_NOTIFICATION_COMPLETION;

typedef struct _WING_RIO_EXTENSION_FUNCTION_TABLE {
    DWORD cbSize;
    BOOL(PASCAL *RIOReceive)(WING_RIO_RQ SocketQueue, WING_RIO_BUF *pData, ULONG DataBufferCount, DWORD Flags,
                             PVOID RequestContext);
    int(PASCAL *RIOReceiveEx)(WING_RIO_RQ SocketQueue, WING_RIO_BUF *pData, ULONG DataBufferCount,
                              WING_RIO_BUF *pLocalAddress, WING_RIO_BUF *pRemoteAddress, WING_RIO_BUF *pControlContext,
                              WING_RIO_BUF *pFlags, DWORD Flags, PVOID RequestContext);
    BOOL(PASCAL *RIOSend)(WING_RIO_RQ SocketQueue, WING_RIO_BUF *pData, ULONG DataBufferCount, DWORD Flags,
                          PVOID RequestContext);
    BOOL(PASCAL *RIOSendEx)(WING_RIO_RQ SocketQueue, WING_RIO_BUF *pData, ULONG DataBufferCount,
                            WING_RIO_BUF *pLocalAddress, WING_RIO_BUF *pRemoteAddress, WING_RIO_BUF *pControlContext,
                            WING_RIO_BUF *pFlags, DWORD Flags, PVOID RequestContext);
    void(PASCAL *RIOCloseCompletionQueue)(WING_RIO_CQ CQ);
    WING_RIO_CQ(PASCAL *RIOCreateCompletionQueue)(DWORD QueueSize, void *NotificationCompletion);
    WING_RIO_RQ(PASCAL *RIOCreateRequestQueue)(SOCKET Socket, ULONG MaxOutstandingReceive, ULONG MaxReceiveDataBuffers,
                                               ULONG MaxOutstandingSend, ULONG MaxSendDataBuffers,
                                               WING_RIO_CQ ReceiveCQ, WING_RIO_CQ SendCQ, PVOID SocketContext);
    ULONG(PASCAL *RIODequeueCompletion)(WING_RIO_CQ CQ, WING_RIO_RESULT *Array, ULONG ArraySize);
    void(PASCAL *RIODeregisterBuffer)(WING_RIO_BUFFERID BufferId);
    INT(PASCAL *RIONotify)(WING_RIO_CQ CQ);
    WING_RIO_BUFFERID(PASCAL *RIORegisterBuffer)(PCHAR DataBuffer, DWORD DataLength);
    BOOL(PASCAL *RIOResizeCompletionQueue)(WING_RIO_CQ CQ, DWORD QueueSize);
    BOOL(PASCAL *RIOResizeRequestQueue)(WING_RIO_RQ SocketQueue, DWORD MaxOutstandingReceive, DWORD MaxOutstandingSend);
} WING_RIO_EXTENSION_FUNCTION_TABLE;

typedef BOOL(PASCAL *WING_LPFN_ACCEPTEX)(SOCKET sListenSocket, SOCKET sAcceptSocket, PVOID lpOutputBuffer,
                                         DWORD dwReceiveDataLength, DWORD dwLocalAddressLength,
                                         DWORD dwRemoteAddressLength, LPDWORD lpdwBytesReceived,
                                         LPOVERLAPPED lpOverlapped);

#define WING_RIO_MAX_CQS 64

typedef struct {
    WING_RIO_CQ cq;
    HANDLE ev;
} wing_rio_cq_slot;

static WING_RIO_EXTENSION_FUNCTION_TABLE g_rio;
static WING_LPFN_ACCEPTEX g_acceptex = NULL;
static wing_rio_cq_slot g_rio_cqs[WING_RIO_MAX_CQS];
static int g_rio_initialized = 0;
static int g_rio_available = 0;

static int init_rio_table(void) {
    if (g_rio_initialized) {
        return g_rio_available ? 0 : -1;
    }
    g_rio_initialized = 1;

    WSADATA wsa_data;
    if (WSAStartup(MAKEWORD(2, 2), &wsa_data) != 0) {
        return -1;
    }

    SOCKET s = WSASocketW(AF_INET, SOCK_STREAM, IPPROTO_TCP, NULL, 0, WSA_FLAG_REGISTERED_IO | WSA_FLAG_OVERLAPPED);
    if (s == INVALID_SOCKET) {
        s = WSASocketW(AF_INET, SOCK_STREAM, IPPROTO_TCP, NULL, 0, 0);
        if (s == INVALID_SOCKET) {
            return -1;
        }
    }

    memset(&g_rio, 0, sizeof(g_rio));
    g_rio.cbSize = sizeof(g_rio);

    GUID functionTableId = k_rio_guid;
    DWORD bytes = 0;
    int rc = WSAIoctl(s, SIO_GET_MULTIPLE_EXTENSION_FUNCTION_POINTER, &functionTableId, sizeof(functionTableId), &g_rio,
                      sizeof(g_rio), &bytes, NULL, NULL);

    GUID acceptexId = k_acceptex_guid;
    DWORD ax_bytes = 0;
    (void)WSAIoctl(s, SIO_GET_EXTENSION_FUNCTION_POINTER, &acceptexId, sizeof(acceptexId), &g_acceptex,
                   sizeof(g_acceptex), &ax_bytes, NULL, NULL);

    closesocket(s);

    if (rc == 0 && g_rio.cbSize >= sizeof(g_rio) && g_rio.RIORegisterBuffer != NULL) {
        g_rio_available = 1;
        return 0;
    }

    g_rio_available = 0;
    return -1;
}

#ifndef ENOSYS
#define ENOSYS 38
#endif

int32_t wing_rio_probe(void) {
    if (init_rio_table() == 0) {
        return 0;
    }
    return -ENOSYS;
}

int32_t wing_rio_available(void) {
    init_rio_table();
    return g_rio_available;
}

uint64_t wing_rio_register_buffer(void *buf, uint32_t len) {
    if (!g_rio_available && init_rio_table() != 0) {
        return 0;
    }
    if (!buf || len == 0 || !g_rio.RIORegisterBuffer) {
        return 0;
    }
    WING_RIO_BUFFERID id = g_rio.RIORegisterBuffer((char *)buf, len);
    if (id == NULL || id == WING_RIO_INVALID_BUFFERID || (uintptr_t)id == (uintptr_t)RIO_INVALID_BUFFERID) {
        return 0;
    }
    return (uint64_t)(uintptr_t)id;
}

uint64_t wing_rio_register_slice(wing_rio_bytes_rw buf) {
    if (!buf.data || buf.len <= 0 || buf.len > 0x7FFFFFFFLL) {
        return 0;
    }
    return wing_rio_register_buffer(buf.data, (uint32_t)buf.len);
}

void wing_rio_deregister_buffer(uint64_t buf_id) {
    if (g_rio_available && buf_id != 0 && g_rio.RIODeregisterBuffer) {
        g_rio.RIODeregisterBuffer((WING_RIO_BUFFERID)(uintptr_t)buf_id);
    }
}

uint64_t wing_rio_create_cq(uint32_t queue_size) {
    if (!g_rio_available && init_rio_table() != 0) {
        return 0;
    }
    if (!g_rio.RIOCreateCompletionQueue) {
        return 0;
    }

    HANDLE ev = CreateEventW(NULL, FALSE, FALSE, NULL);
    WING_RIO_NOTIFICATION_COMPLETION notif;
    memset(&notif, 0, sizeof(notif));
    void *notif_ptr = NULL;
    if (ev != NULL) {
        notif.Type = 1; // RIO_EVENT_COMPLETION
        notif.Event.EventHandle = ev;
        notif.Event.NotifyReset = TRUE;
        notif_ptr = &notif;
    }

    WING_RIO_CQ cq = g_rio.RIOCreateCompletionQueue(queue_size, notif_ptr);
    if (cq == NULL || (uintptr_t)cq == (uintptr_t)RIO_INVALID_CQ) {
        if (ev != NULL) CloseHandle(ev);
        return 0;
    }

    if (ev != NULL) {
        int stored = 0;
        for (int i = 0; i < WING_RIO_MAX_CQS; i++) {
            if (g_rio_cqs[i].cq == NULL) {
                g_rio_cqs[i].cq = cq;
                g_rio_cqs[i].ev = ev;
                stored = 1;
                break;
            }
        }
        if (!stored) {
            CloseHandle(ev);
        }
    }
    return (uint64_t)(uintptr_t)cq;
}

void wing_rio_close_cq(uint64_t cq_id) {
    if (g_rio_available && cq_id != 0 && g_rio.RIOCloseCompletionQueue) {
        WING_RIO_CQ cq = (WING_RIO_CQ)(uintptr_t)cq_id;
        g_rio.RIOCloseCompletionQueue(cq);
        for (int i = 0; i < WING_RIO_MAX_CQS; i++) {
            if (g_rio_cqs[i].cq == cq) {
                if (g_rio_cqs[i].ev != NULL) {
                    CloseHandle(g_rio_cqs[i].ev);
                }
                g_rio_cqs[i].cq = NULL;
                g_rio_cqs[i].ev = NULL;
                break;
            }
        }
    }
}

int32_t wing_rio_wait_cq(uint64_t cq_id, int32_t timeout_ms) {
    if (!g_rio_available || cq_id == 0 || !g_rio.RIONotify) {
        return -1;
    }
    WING_RIO_CQ cq = (WING_RIO_CQ)(uintptr_t)cq_id;
    HANDLE ev = NULL;
    for (int i = 0; i < WING_RIO_MAX_CQS; i++) {
        if (g_rio_cqs[i].cq == cq) {
            ev = g_rio_cqs[i].ev;
            break;
        }
    }
    if (ev == NULL) {
        return 0;
    }
    INT rc = g_rio.RIONotify(cq);
    if (rc != ERROR_SUCCESS) {
        return -1;
    }
    DWORD wait_ms = (timeout_ms < 0) ? INFINITE : (DWORD)timeout_ms;
    DWORD w = WaitForSingleObject(ev, wait_ms);
    if (w == WAIT_OBJECT_0) {
        return 1;
    }
    if (w == WAIT_TIMEOUT) {
        return 0;
    }
    return -1;
}

uint32_t wing_rio_dequeue_completion(uint64_t cq_id, void *results, uint32_t count) {
    if (!g_rio_available && init_rio_table() != 0) {
        return 0;
    }
    if (!cq_id || !results || !g_rio.RIODequeueCompletion) {
        return 0;
    }
    ULONG n = g_rio.RIODequeueCompletion((WING_RIO_CQ)(uintptr_t)cq_id, (WING_RIO_RESULT *)results, count);
    if (n == 0xFFFFFFFFUL) {
        return 0;
    }
    return (uint32_t)n;
}

int32_t wing_rio_dequeue_slice(uint64_t cq_id, wing_rio_results_rw dst) {
    if (!g_rio_available && init_rio_table() != 0) {
        return 0;
    }
    if (!cq_id || !dst.data || dst.len <= 0 || !g_rio.RIODequeueCompletion) {
        return 0;
    }
    ULONG cap = (dst.len > 1024) ? 1024 : (ULONG)dst.len;
    ULONG n = g_rio.RIODequeueCompletion((WING_RIO_CQ)(uintptr_t)cq_id, (WING_RIO_RESULT *)dst.data, cap);
    if (n == 0xFFFFFFFFUL) {
        return -1;
    }
    return (int32_t)n;
}

uint64_t wing_rio_create_rq(int64_t sock_fd, uint64_t cq_id, uint32_t max_recv, uint32_t max_send) {
    if (!g_rio_available && init_rio_table() != 0) {
        return 0;
    }
    if (sock_fd <= 0 || cq_id == 0 || !g_rio.RIOCreateRequestQueue) {
        return 0;
    }
    WING_RIO_RQ rq = g_rio.RIOCreateRequestQueue((SOCKET)sock_fd, max_recv, 1, max_send, 1,
                                                 (WING_RIO_CQ)(uintptr_t)cq_id, (WING_RIO_CQ)(uintptr_t)cq_id,
                                                 (PVOID)(uintptr_t)sock_fd);
    if ((uintptr_t)rq == (uintptr_t)RIO_INVALID_RQ) {
        return 0;
    }
    return (uint64_t)(uintptr_t)rq;
}

uint64_t wing_rio_create_rq_ctx(int64_t sock_fd, uint32_t max_recv, uint32_t max_send, uint64_t recv_cq,
                                uint64_t send_cq, uint64_t sock_ctx) {
    if (!g_rio_available && init_rio_table() != 0) {
        return 0;
    }
    if (sock_fd <= 0 || recv_cq == 0 || send_cq == 0 || !g_rio.RIOCreateRequestQueue) {
        return 0;
    }
    WING_RIO_RQ rq = g_rio.RIOCreateRequestQueue((SOCKET)sock_fd, max_recv, 1, max_send, 1,
                                                 (WING_RIO_CQ)(uintptr_t)recv_cq, (WING_RIO_CQ)(uintptr_t)send_cq,
                                                 (PVOID)(uintptr_t)sock_ctx);
    if ((uintptr_t)rq == (uintptr_t)RIO_INVALID_RQ) {
        return 0;
    }
    return (uint64_t)(uintptr_t)rq;
}

int32_t wing_rio_receive(uint64_t rq_id, uint64_t buf_id, uint32_t offset, uint32_t length, uint64_t req_context) {
    if (!g_rio_available || rq_id == 0 || buf_id == 0 || !g_rio.RIOReceive) {
        return -1;
    }
    WING_RIO_BUF buf;
    buf.BufferId = (WING_RIO_BUFFERID)(uintptr_t)buf_id;
    buf.Offset = offset;
    buf.Length = length;
    BOOL ok = g_rio.RIOReceive((WING_RIO_RQ)(uintptr_t)rq_id, &buf, 1, 0, (PVOID)(uintptr_t)req_context);
    return ok ? 0 : (int32_t)WSAGetLastError();
}

int32_t wing_rio_send(uint64_t rq_id, uint64_t buf_id, uint32_t offset, uint32_t length, uint64_t req_context) {
    if (!g_rio_available || rq_id == 0 || buf_id == 0 || !g_rio.RIOSend) {
        return -1;
    }
    WING_RIO_BUF buf;
    buf.BufferId = (WING_RIO_BUFFERID)(uintptr_t)buf_id;
    buf.Offset = offset;
    buf.Length = length;
    BOOL ok = g_rio.RIOSend((WING_RIO_RQ)(uintptr_t)rq_id, &buf, 1, 0, (PVOID)(uintptr_t)req_context);
    return ok ? 0 : (int32_t)WSAGetLastError();
}

int32_t wing_rio_post_recv(uint64_t rq_id, uint64_t buf_id, uint32_t offset, uint32_t length, uint64_t req_ctx) {
    return wing_rio_receive(rq_id, buf_id, offset, length, req_ctx);
}

int32_t wing_rio_post_send(uint64_t rq_id, uint64_t buf_id, uint32_t offset, uint32_t length, uint64_t req_ctx) {
    return wing_rio_send(rq_id, buf_id, offset, length, req_ctx);
}

int64_t wing_rio_listen(wing_rio_str_ro host, uint16_t port, int32_t backlog) {
    if (init_rio_table() != 0) {
        return -1;
    }
    SOCKET s = WSASocketW(AF_INET, SOCK_STREAM, IPPROTO_TCP, NULL, 0, WSA_FLAG_REGISTERED_IO | WSA_FLAG_OVERLAPPED);
    if (s == INVALID_SOCKET) {
        return -1;
    }
    SetHandleInformation((HANDLE)s, HANDLE_FLAG_INHERIT, 0);
    int opt = 1;
    setsockopt(s, SOL_SOCKET, SO_EXCLUSIVEADDRUSE, (const char *)&opt, sizeof(opt));

    char host_str[128];
    int64_t n = host.len < 127 ? host.len : 127;
    if (n > 0 && host.data != NULL) {
        memcpy(host_str, host.data, (size_t)n);
        host_str[n] = '\0';
    } else {
        host_str[0] = '\0';
    }

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

int64_t wing_rio_accept(int64_t listen_fd) {
    if (init_rio_table() != 0 || listen_fd <= 0 || !g_acceptex) {
        return -1;
    }
    SOCKET lsock = (SOCKET)listen_fd;

    SOCKET asock = WSASocketW(AF_INET, SOCK_STREAM, IPPROTO_TCP, NULL, 0, WSA_FLAG_REGISTERED_IO | WSA_FLAG_OVERLAPPED);
    if (asock == INVALID_SOCKET) {
        return -1;
    }
    SetHandleInformation((HANDLE)asock, HANDLE_FLAG_INHERIT, 0);

    HANDLE ev = CreateEventW(NULL, TRUE, FALSE, NULL);
    if (ev == NULL) {
        closesocket(asock);
        return -1;
    }

    OVERLAPPED ov;
    memset(&ov, 0, sizeof(ov));
    ov.hEvent = ev;
    uint8_t addr_buf[128];
    memset(addr_buf, 0, sizeof(addr_buf));
    DWORD bytes = 0;

    BOOL ok = g_acceptex(lsock, asock, addr_buf, 0, 32, 32, &bytes, &ov);
    if (!ok) {
        int err = WSAGetLastError();
        if (err != WSA_IO_PENDING) {
            CloseHandle(ev);
            closesocket(asock);
            return -1;
        }
        DWORD w = WaitForSingleObject(ev, 50);
        if (w != WAIT_OBJECT_0) {
            CancelIoEx((HANDLE)lsock, &ov);
            DWORD flags = 0;
            (void)WSAGetOverlappedResult(lsock, &ov, &bytes, TRUE, &flags);
            CloseHandle(ev);
            closesocket(asock);
            return -1;
        }
        DWORD flags = 0;
        if (!WSAGetOverlappedResult(lsock, &ov, &bytes, FALSE, &flags)) {
            CloseHandle(ev);
            closesocket(asock);
            return -1;
        }
    }

    CloseHandle(ev);
    (void)setsockopt(asock, SOL_SOCKET, SO_UPDATE_ACCEPT_CONTEXT, (const char *)&lsock, sizeof(lsock));
    int nodelay = 1;
    (void)setsockopt(asock, IPPROTO_TCP, TCP_NODELAY, (const char *)&nodelay, sizeof(nodelay));
    u_long nonblock = 1;
    (void)ioctlsocket(asock, FIONBIO, &nonblock);
    return (int64_t)asock;
}

typedef struct {
    SOCKET lsock;
    SOCKET asock;
    HANDLE ev;
    OVERLAPPED ov;
    uint8_t addr_buf[128];
    int pending;
} wing_rio_accept_slot;

#define WING_RIO_MAX_LISTENERS 8
static wing_rio_accept_slot g_rio_accept_slots[WING_RIO_MAX_LISTENERS];

int32_t wing_rio_is_listener(int64_t sock_fd) {
    if (sock_fd <= 0) {
        return 0;
    }
    SOCKET s = (SOCKET)sock_fd;
    struct sockaddr_in addr;
    int len = (int)sizeof(addr);
    if (getsockname(s, (struct sockaddr *)&addr, &len) != 0) {
        return 0;
    }
    WSAPOLLFD pfd;
    pfd.fd = s;
    pfd.events = POLLRDNORM;
    pfd.revents = 0;
    if (WSAPoll(&pfd, 1, 0) == SOCKET_ERROR && WSAGetLastError() == WSAENOTSOCK) {
        return 1;
    }
    return 0;
}

static void cleanup_rio_accept_slot(wing_rio_accept_slot *slot, int cancel_io) {
    if (!slot || !slot->pending) {
        return;
    }
    if (cancel_io && slot->lsock != INVALID_SOCKET && slot->lsock != 0) {
        CancelIoEx((HANDLE)slot->lsock, &slot->ov);
        DWORD bytes = 0;
        DWORD flags = 0;
        (void)WSAGetOverlappedResult(slot->lsock, &slot->ov, &bytes, FALSE, &flags);
    }
    if (slot->ev != NULL) {
        CloseHandle(slot->ev);
        slot->ev = NULL;
    }
    if (slot->asock != INVALID_SOCKET && slot->asock != 0) {
        closesocket(slot->asock);
        slot->asock = INVALID_SOCKET;
    }
    slot->lsock = 0;
    slot->pending = 0;
}

void wing_rio_cancel_accept(int64_t listen_fd) {
    if (listen_fd <= 0) {
        for (int i = 0; i < WING_RIO_MAX_LISTENERS; i++) {
            cleanup_rio_accept_slot(&g_rio_accept_slots[i], 1);
        }
        return;
    }
    SOCKET lsock = (SOCKET)listen_fd;
    for (int i = 0; i < WING_RIO_MAX_LISTENERS; i++) {
        if (g_rio_accept_slots[i].pending && g_rio_accept_slots[i].lsock == lsock) {
            cleanup_rio_accept_slot(&g_rio_accept_slots[i], 1);
        }
    }
}

static int64_t finalize_rio_accepted_socket(SOCKET lsock, SOCKET asock) {
    (void)setsockopt(asock, SOL_SOCKET, SO_UPDATE_ACCEPT_CONTEXT, (const char *)&lsock, sizeof(lsock));
    int nodelay = 1;
    (void)setsockopt(asock, IPPROTO_TCP, TCP_NODELAY, (const char *)&nodelay, sizeof(nodelay));
    u_long nonblock = 1;
    (void)ioctlsocket(asock, FIONBIO, &nonblock);
    return (int64_t)asock;
}

int64_t wing_rio_poll_accept(int64_t listen_fd, int32_t timeout_ms) {
    if (init_rio_table() != 0 || listen_fd <= 0 || !g_acceptex) {
        return -1;
    }
    SOCKET lsock = (SOCKET)listen_fd;
    wing_rio_accept_slot *slot = NULL;
    for (int i = 0; i < WING_RIO_MAX_LISTENERS; i++) {
        if (g_rio_accept_slots[i].pending && g_rio_accept_slots[i].lsock == lsock) {
            slot = &g_rio_accept_slots[i];
            break;
        }
    }
    if (!slot) {
        for (int i = 0; i < WING_RIO_MAX_LISTENERS; i++) {
            if (!g_rio_accept_slots[i].pending) {
                slot = &g_rio_accept_slots[i];
                break;
            }
        }
        if (!slot) {
            return -1;
        }
        SOCKET asock = WSASocketW(AF_INET, SOCK_STREAM, IPPROTO_TCP, NULL, 0,
                                  WSA_FLAG_REGISTERED_IO | WSA_FLAG_OVERLAPPED);
        if (asock == INVALID_SOCKET) {
            return -1;
        }
        SetHandleInformation((HANDLE)asock, HANDLE_FLAG_INHERIT, 0);
        HANDLE ev = CreateEventW(NULL, TRUE, FALSE, NULL);
        if (ev == NULL) {
            closesocket(asock);
            return -1;
        }
        memset(slot, 0, sizeof(*slot));
        slot->lsock = lsock;
        slot->asock = asock;
        slot->ev = ev;
        slot->ov.hEvent = ev;
        DWORD bytes = 0;
        BOOL ok = g_acceptex(lsock, asock, slot->addr_buf, 0, 32, 32, &bytes, &slot->ov);
        if (ok) {
            CloseHandle(ev);
            slot->ev = NULL;
            slot->asock = INVALID_SOCKET;
            slot->pending = 0;
            return finalize_rio_accepted_socket(lsock, asock);
        }
        if (WSAGetLastError() != WSA_IO_PENDING) {
            CloseHandle(ev);
            closesocket(asock);
            memset(slot, 0, sizeof(*slot));
            return -1;
        }
        slot->pending = 1;
    }

    DWORD wait_ms = (timeout_ms < 0) ? 0 : (DWORD)timeout_ms;
    DWORD w = WaitForSingleObject(slot->ev, wait_ms);
    if (w == WAIT_TIMEOUT) {
        return 0;
    }
    if (w != WAIT_OBJECT_0) {
        cleanup_rio_accept_slot(slot, 1);
        return -1;
    }
    DWORD bytes = 0;
    DWORD flags = 0;
    if (!WSAGetOverlappedResult(lsock, &slot->ov, &bytes, FALSE, &flags)) {
        cleanup_rio_accept_slot(slot, 0);
        return -1;
    }
    SOCKET accepted = slot->asock;
    CloseHandle(slot->ev);
    slot->ev = NULL;
    slot->asock = INVALID_SOCKET;
    slot->lsock = 0;
    slot->pending = 0;
    return finalize_rio_accepted_socket(lsock, accepted);
}

#else

#ifndef ENOSYS
#define ENOSYS 38
#endif

// Non-Windows platform stubs
int32_t wing_rio_probe(void) { return -ENOSYS; }
int32_t wing_rio_available(void) { return 0; }
uint64_t wing_rio_register_buffer(void *buf, uint32_t len) {
    (void)buf;
    (void)len;
    return 0;
}
uint64_t wing_rio_register_slice(wing_rio_bytes_rw buf) {
    (void)buf;
    return 0;
}
void wing_rio_deregister_buffer(uint64_t buf_id) { (void)buf_id; }
uint64_t wing_rio_create_cq(uint32_t queue_size) {
    (void)queue_size;
    return 0;
}
void wing_rio_close_cq(uint64_t cq_id) { (void)cq_id; }
int32_t wing_rio_wait_cq(uint64_t cq_id, int32_t timeout_ms) {
    (void)cq_id;
    (void)timeout_ms;
    return -ENOSYS;
}
uint32_t wing_rio_dequeue_completion(uint64_t cq_id, void *results, uint32_t count) {
    (void)cq_id;
    (void)results;
    (void)count;
    return 0;
}
int32_t wing_rio_dequeue_slice(uint64_t cq_id, wing_rio_results_rw dst) {
    (void)cq_id;
    (void)dst;
    return 0;
}
uint64_t wing_rio_create_rq(int64_t sock_fd, uint64_t cq_id, uint32_t max_recv, uint32_t max_send) {
    (void)sock_fd;
    (void)cq_id;
    (void)max_recv;
    (void)max_send;
    return 0;
}
uint64_t wing_rio_create_rq_ctx(int64_t sock_fd, uint32_t max_recv, uint32_t max_send, uint64_t recv_cq,
                                uint64_t send_cq, uint64_t sock_ctx) {
    (void)sock_fd;
    (void)max_recv;
    (void)max_send;
    (void)recv_cq;
    (void)send_cq;
    (void)sock_ctx;
    return 0;
}
int32_t wing_rio_receive(uint64_t rq_id, uint64_t buf_id, uint32_t offset, uint32_t length, uint64_t req_context) {
    (void)rq_id;
    (void)buf_id;
    (void)offset;
    (void)length;
    (void)req_context;
    return -ENOSYS;
}
int32_t wing_rio_send(uint64_t rq_id, uint64_t buf_id, uint32_t offset, uint32_t length, uint64_t req_context) {
    (void)rq_id;
    (void)buf_id;
    (void)offset;
    (void)length;
    (void)req_context;
    return -ENOSYS;
}
int32_t wing_rio_post_recv(uint64_t rq_id, uint64_t buf_id, uint32_t offset, uint32_t length, uint64_t req_ctx) {
    (void)rq_id;
    (void)buf_id;
    (void)offset;
    (void)length;
    (void)req_ctx;
    return -ENOSYS;
}
int32_t wing_rio_post_send(uint64_t rq_id, uint64_t buf_id, uint32_t offset, uint32_t length, uint64_t req_ctx) {
    (void)rq_id;
    (void)buf_id;
    (void)offset;
    (void)length;
    (void)req_ctx;
    return -ENOSYS;
}
int64_t wing_rio_listen(wing_rio_str_ro host, uint16_t port, int32_t backlog) {
    (void)host;
    (void)port;
    (void)backlog;
    return -ENOSYS;
}
int64_t wing_rio_accept(int64_t listen_fd) {
    (void)listen_fd;
    return -ENOSYS;
}
int32_t wing_rio_is_listener(int64_t sock_fd) {
    (void)sock_fd;
    return 0;
}
int64_t wing_rio_poll_accept(int64_t listen_fd, int32_t timeout_ms) {
    (void)listen_fd;
    (void)timeout_ms;
    return -ENOSYS;
}
void wing_rio_cancel_accept(int64_t listen_fd) { (void)listen_fd; }

#endif
