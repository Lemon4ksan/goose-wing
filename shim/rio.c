// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Layer 4 Windows Registered I/O (RIO) Kernel-Bypass C Shim.
// Queries the RIO Extension Function Table via SIO_GET_MULTIPLE_EXTENSION_FUNCTION_POINTER,
// manages page-locked registered memory buffers, RIONotify events, and IPv4/IPv6 AcceptEx RIO sockets.
#define WIN32_LEAN_AND_MEAN
#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0602
#endif

#include <stdint.h>
#include <stddef.h>
#include <string.h>

// Goose emits all structs and slice headers under #pragma pack(push, 1).
#pragma pack(push, 1)
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
#pragma pack(pop)

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

#ifndef IPV6_V6ONLY
#define IPV6_V6ONLY 27
#endif

static const GUID k_rio_guid = {0x8509E081, 0x96DD, 0x4005, {0xB1, 0x65, 0x9E, 0x2E, 0xE8, 0xC7, 0x9E, 0x3F}};
static const GUID k_acceptex_guid = {0xB5367DF1, 0xCBAC, 0x11CF, {0x95, 0xCA, 0x00, 0x80, 0x5F, 0x48, 0xA1, 0x92}};

typedef void *WING_RIO_BUFFERID;
#define WING_RIO_INVALID_BUFFERID_32 ((uintptr_t)0xFFFFFFFFUL)
#define WING_RIO_INVALID_BUFFERID_64 (~(uintptr_t)0)
#ifndef RIO_INVALID_CQ
#define RIO_INVALID_CQ ((void *)0)
#endif
#ifndef RIO_INVALID_RQ
#define RIO_INVALID_RQ ((void *)0)
#endif
#define WING_RIO_CORRUPT_CQ 0xFFFFFFFFUL

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

#define WING_RIO_MAX_CQS 256
#define WING_RIO_MAX_REG_BUFS 1024
#define WING_RIO_MAX_LISTENERS 64
#define WING_RIO_DEFER_CAP 256
#define WING_RIO_ACCEPT_ADDR_LEN ((DWORD)(sizeof(struct sockaddr_storage) + 16))

typedef struct {
    WING_RIO_CQ cq;
    HANDLE ev;
    int armed;
    int corrupt;
} wing_rio_cq_slot;

typedef struct {
    uint64_t buf_id;
    uint32_t len;
} wing_rio_reg_buf_entry;

typedef struct {
    int active;
    SOCKET fd;
    WING_RIO_RQ rq;
    WING_RIO_CQ rx_cq;
    WING_RIO_CQ tx_cq;
    WING_RIO_BUFFERID buf_id;
    uint8_t *slab;
    int64_t slab_len;
    uint32_t rx_off;
    uint32_t tx_off;
    uint32_t buf_size;
    uint64_t sock_ctx;
    uint8_t rx_stash[4096];
    uint32_t rx_stash_pos;
    uint32_t rx_stash_len;
    int rx_inflight;
    WING_RIO_CQ def_rx_cq;
    WING_RIO_RESULT def_rx[WING_RIO_DEFER_CAP];
    int def_rx_head;
    int def_rx_count;
    WING_RIO_CQ def_tx_cq;
    WING_RIO_RESULT def_tx[WING_RIO_DEFER_CAP];
    int def_tx_head;
    int def_tx_count;
} wing_rio_hs_ctx;

static WING_RIO_EXTENSION_FUNCTION_TABLE g_rio;
static WING_LPFN_ACCEPTEX g_acceptex = NULL;
static wing_rio_cq_slot g_rio_cqs[WING_RIO_MAX_CQS];
static wing_rio_reg_buf_entry g_rio_reg_bufs[WING_RIO_MAX_REG_BUFS];
static SRWLOCK g_rio_reg_lock = SRWLOCK_INIT;
static wing_rio_hs_ctx g_rio_hs;
static int g_rio_initialized = 0;
static int g_rio_available = 0;

static int record_rio_reg_buf(uint64_t buf_id, uint32_t len) {
    AcquireSRWLockExclusive(&g_rio_reg_lock);
    int free_idx = -1;
    for (int i = 0; i < WING_RIO_MAX_REG_BUFS; i++) {
        if (g_rio_reg_bufs[i].buf_id == buf_id) {
            g_rio_reg_bufs[i].len = len;
            ReleaseSRWLockExclusive(&g_rio_reg_lock);
            return 1;
        }
        if (free_idx < 0 && g_rio_reg_bufs[i].buf_id == 0) {
            free_idx = i;
        }
    }
    if (free_idx >= 0) {
        g_rio_reg_bufs[free_idx].buf_id = buf_id;
        g_rio_reg_bufs[free_idx].len = len;
        ReleaseSRWLockExclusive(&g_rio_reg_lock);
        return 1;
    }
    ReleaseSRWLockExclusive(&g_rio_reg_lock);
    return 0;
}

static void remove_rio_reg_buf(uint64_t buf_id) {
    AcquireSRWLockExclusive(&g_rio_reg_lock);
    for (int i = 0; i < WING_RIO_MAX_REG_BUFS; i++) {
        if (g_rio_reg_bufs[i].buf_id == buf_id) {
            g_rio_reg_bufs[i].buf_id = 0;
            g_rio_reg_bufs[i].len = 0;
            break;
        }
    }
    ReleaseSRWLockExclusive(&g_rio_reg_lock);
}

static int lookup_rio_reg_buf_len(uint64_t buf_id, uint32_t *out_len) {
    if (buf_id == 0) return 0;
    AcquireSRWLockShared(&g_rio_reg_lock);
    for (int i = 0; i < WING_RIO_MAX_REG_BUFS; i++) {
        if (g_rio_reg_bufs[i].buf_id == buf_id) {
            *out_len = g_rio_reg_bufs[i].len;
            ReleaseSRWLockShared(&g_rio_reg_lock);
            return 1;
        }
    }
    ReleaseSRWLockShared(&g_rio_reg_lock);
    return 0;
}

static void defer_push_rx(WING_RIO_CQ cq, const WING_RIO_RESULT *r) {
    if (g_rio_hs.def_rx_cq != cq) {
        g_rio_hs.def_rx_cq = cq;
        g_rio_hs.def_rx_head = 0;
        g_rio_hs.def_rx_count = 0;
    }
    if (g_rio_hs.def_rx_count < WING_RIO_DEFER_CAP) {
        int idx = (g_rio_hs.def_rx_head + g_rio_hs.def_rx_count) % WING_RIO_DEFER_CAP;
        g_rio_hs.def_rx[idx] = *r;
        g_rio_hs.def_rx_count++;
    }
}

static void defer_push_tx(WING_RIO_CQ cq, const WING_RIO_RESULT *r) {
    if (g_rio_hs.def_tx_cq != cq) {
        g_rio_hs.def_tx_cq = cq;
        g_rio_hs.def_tx_head = 0;
        g_rio_hs.def_tx_count = 0;
    }
    if (g_rio_hs.def_tx_count < WING_RIO_DEFER_CAP) {
        int idx = (g_rio_hs.def_tx_head + g_rio_hs.def_tx_count) % WING_RIO_DEFER_CAP;
        g_rio_hs.def_tx[idx] = *r;
        g_rio_hs.def_tx_count++;
    }
}

static wing_rio_cq_slot *find_rio_cq_slot(WING_RIO_CQ cq) {
    if (!cq) return NULL;
    for (int i = 0; i < WING_RIO_MAX_CQS; i++) {
        if (g_rio_cqs[i].cq == cq) {
            return &g_rio_cqs[i];
        }
    }
    return NULL;
}

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
#ifndef EINVAL
#define EINVAL 22
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

static uint64_t wing_rio_register_buffer(void *buf, uint32_t len) {
    if (!g_rio_available && init_rio_table() != 0) {
        return 0;
    }
    if (!buf || len == 0 || !g_rio.RIORegisterBuffer) {
        return 0;
    }
    WING_RIO_BUFFERID id = g_rio.RIORegisterBuffer((char *)buf, len);
    uintptr_t raw = (uintptr_t)id;
    if (raw == 0 || raw == WING_RIO_INVALID_BUFFERID_32 || raw == WING_RIO_INVALID_BUFFERID_64) {
        return 0;
    }
    if (!record_rio_reg_buf((uint64_t)raw, len)) {
        if (g_rio.RIODeregisterBuffer) {
            g_rio.RIODeregisterBuffer(id);
        }
        return 0;
    }
    return (uint64_t)raw;
}

uint64_t wing_rio_register_slice(wing_rio_bytes_rw buf) {
    if (!buf.data || buf.len <= 0 || buf.len > 0x7FFFFFFFLL) {
        return 0;
    }
    return wing_rio_register_buffer(buf.data, (uint32_t)buf.len);
}

void wing_rio_deregister_buffer(uint64_t buf_id) {
    uintptr_t raw = (uintptr_t)buf_id;
    if (g_rio_available && raw != 0 && raw != WING_RIO_INVALID_BUFFERID_32 && raw != WING_RIO_INVALID_BUFFERID_64 &&
        g_rio.RIODeregisterBuffer) {
        remove_rio_reg_buf(buf_id);
        g_rio.RIODeregisterBuffer((WING_RIO_BUFFERID)raw);
    }
}

uint64_t wing_rio_create_cq(uint32_t queue_size) {
    if (!g_rio_available && init_rio_table() != 0) {
        return 0;
    }
    if (queue_size == 0 || !g_rio.RIOCreateCompletionQueue) {
        return 0;
    }

    int slot_idx = -1;
    for (int i = 0; i < WING_RIO_MAX_CQS; i++) {
        if (g_rio_cqs[i].cq == NULL) {
            slot_idx = i;
            break;
        }
    }
    if (slot_idx < 0) {
        return 0;
    }

    // Manual-reset event paired with NotifyReset = TRUE:
    // RIODequeueCompletion atomically resets EventHandle when completions are drained.
    HANDLE ev = CreateEventW(NULL, TRUE, FALSE, NULL);
    if (ev == NULL) {
        return 0;
    }

    WING_RIO_NOTIFICATION_COMPLETION notif;
    memset(&notif, 0, sizeof(notif));
    notif.Type = 1; // RIO_EVENT_COMPLETION
    notif.Event.EventHandle = ev;
    notif.Event.NotifyReset = TRUE;

    WING_RIO_CQ cq = g_rio.RIOCreateCompletionQueue(queue_size, &notif);
    if (cq == NULL || (uintptr_t)cq == (uintptr_t)RIO_INVALID_CQ) {
        CloseHandle(ev);
        return 0;
    }

    g_rio_cqs[slot_idx].cq = cq;
    g_rio_cqs[slot_idx].ev = ev;
    g_rio_cqs[slot_idx].armed = 0;
    g_rio_cqs[slot_idx].corrupt = 0;
    return (uint64_t)(uintptr_t)cq;
}

void wing_rio_close_cq(uint64_t cq_id) {
    if (g_rio_available && cq_id != 0 && g_rio.RIOCloseCompletionQueue) {
        WING_RIO_CQ cq = (WING_RIO_CQ)(uintptr_t)cq_id;
        if (g_rio_hs.def_rx_cq == cq) {
            g_rio_hs.def_rx_cq = NULL;
            g_rio_hs.def_rx_head = 0;
            g_rio_hs.def_rx_count = 0;
        }
        if (g_rio_hs.def_tx_cq == cq) {
            g_rio_hs.def_tx_cq = NULL;
            g_rio_hs.def_tx_head = 0;
            g_rio_hs.def_tx_count = 0;
        }
        g_rio.RIOCloseCompletionQueue(cq);
        wing_rio_cq_slot *slot = find_rio_cq_slot(cq);
        if (slot) {
            if (slot->ev != NULL) {
                CloseHandle(slot->ev);
            }
            slot->cq = NULL;
            slot->ev = NULL;
            slot->armed = 0;
            slot->corrupt = 0;
        }
    }
}

int32_t wing_rio_cq_is_corrupt(uint64_t cq_id) {
    if (!g_rio_available || cq_id == 0) {
        return 0;
    }
    wing_rio_cq_slot *slot = find_rio_cq_slot((WING_RIO_CQ)(uintptr_t)cq_id);
    return (slot && slot->corrupt) ? 1 : 0;
}

int32_t wing_rio_wait_cq(uint64_t cq_id, int32_t timeout_ms) {
    if (!g_rio_available || cq_id == 0 || !g_rio.RIONotify) {
        return -1;
    }
    WING_RIO_CQ cq = (WING_RIO_CQ)(uintptr_t)cq_id;
    wing_rio_cq_slot *slot = find_rio_cq_slot(cq);
    if (!slot || slot->ev == NULL || slot->corrupt) {
        return -1;
    }
    if (!slot->armed) {
        INT rc = g_rio.RIONotify(cq);
        if (rc == ERROR_SUCCESS || rc == WSAEINVAL) {
            slot->armed = 1;
        } else {
            return -1;
        }
    }
    DWORD wait_ms = (timeout_ms < 0) ? INFINITE : (DWORD)timeout_ms;
    DWORD w = WaitForSingleObject(slot->ev, wait_ms);
    if (w == WAIT_OBJECT_0) {
        slot->armed = 0;
        return 1;
    }
    if (w == WAIT_TIMEOUT) {
        return 0;
    }
    slot->armed = 0;
    return -1;
}

int32_t wing_rio_dequeue_slice(uint64_t cq_id, wing_rio_results_rw dst) {
    if (!g_rio_available && init_rio_table() != 0) {
        return 0;
    }
    if (!cq_id || !dst.data || dst.len <= 0 || !g_rio.RIODequeueCompletion) {
        return 0;
    }

    WING_RIO_CQ cq = (WING_RIO_CQ)(uintptr_t)cq_id;
    wing_rio_cq_slot *slot = find_rio_cq_slot(cq);
    if (slot && slot->corrupt) {
        return -1;
    }
    WING_RIO_RESULT aligned_batch[256];
    int64_t total = 0;

    if (cq == g_rio_hs.def_rx_cq && g_rio_hs.def_rx_count > 0) {
        while (total < dst.len && g_rio_hs.def_rx_count > 0) {
            memcpy(dst.data + total, &g_rio_hs.def_rx[g_rio_hs.def_rx_head], sizeof(WING_RIO_RESULT));
            g_rio_hs.def_rx_head = (g_rio_hs.def_rx_head + 1) % WING_RIO_DEFER_CAP;
            g_rio_hs.def_rx_count--;
            total++;
        }
    } else if (cq == g_rio_hs.def_tx_cq && g_rio_hs.def_tx_count > 0) {
        while (total < dst.len && g_rio_hs.def_tx_count > 0) {
            memcpy(dst.data + total, &g_rio_hs.def_tx[g_rio_hs.def_tx_head], sizeof(WING_RIO_RESULT));
            g_rio_hs.def_tx_head = (g_rio_hs.def_tx_head + 1) % WING_RIO_DEFER_CAP;
            g_rio_hs.def_tx_count--;
            total++;
        }
    }

    while (total < dst.len) {
        ULONG cap = (dst.len - total > 256) ? 256 : (ULONG)(dst.len - total);
        ULONG n = g_rio.RIODequeueCompletion(cq, aligned_batch, cap);
        if (n == WING_RIO_CORRUPT_CQ) {
            if (slot) {
                slot->corrupt = 1;
            }
            return -1;
        }
        if (n == 0) {
            break;
        }
        memcpy(dst.data + total, aligned_batch, (size_t)n * sizeof(WING_RIO_RESULT));
        total += (int64_t)n;
        if (n < cap) {
            break;
        }
    }

    if (total > 0 && slot) {
        slot->armed = 0;
    }
    return (int32_t)total;
}

uint64_t wing_rio_create_rq_ctx(int64_t sock_fd, uint32_t max_recv, uint32_t max_send, uint64_t recv_cq,
                                uint64_t send_cq, uint64_t sock_ctx) {
    if (!g_rio_available && init_rio_table() != 0) {
        return 0;
    }
    if (sock_fd <= 0 || recv_cq == 0 || send_cq == 0 || !g_rio.RIOCreateRequestQueue) {
        return 0;
    }
    WING_RIO_RQ rq =
        g_rio.RIOCreateRequestQueue((SOCKET)sock_fd, max_recv, 1, max_send, 1, (WING_RIO_CQ)(uintptr_t)recv_cq,
                                    (WING_RIO_CQ)(uintptr_t)send_cq, (PVOID)(uintptr_t)sock_ctx);
    if ((uintptr_t)rq == (uintptr_t)RIO_INVALID_RQ) {
        return 0;
    }
    return (uint64_t)(uintptr_t)rq;
}

int32_t wing_rio_receive(uint64_t rq_id, uint64_t buf_id, uint32_t offset, uint32_t length, uint64_t req_context) {
    if (!g_rio_available || rq_id == 0 || buf_id == 0 || !g_rio.RIOReceive) {
        return -1;
    }
    uint32_t reg_len = 0;
    if (!lookup_rio_reg_buf_len(buf_id, &reg_len) || offset > reg_len || length > reg_len - offset) {
        return -EINVAL;
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
    uint32_t reg_len = 0;
    if (!lookup_rio_reg_buf_len(buf_id, &reg_len) || offset > reg_len || length > reg_len - offset) {
        return -EINVAL;
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

static int rio_span_valid(int64_t slab_len, uint32_t reg_len, uint32_t off, uint32_t size) {
    if (size == 0 || slab_len <= 0) return 0;
    if ((uint64_t)off > (uint64_t)slab_len || (uint64_t)size > (uint64_t)slab_len - (uint64_t)off) return 0;
    if (off > reg_len || size > reg_len - off) return 0;
    return 1;
}

void wing_rio_hs_begin(int64_t sock_fd, uint64_t rq_id, uint64_t rx_cq, uint64_t tx_cq, uint64_t buf_id,
                       wing_rio_bytes_rw slab, uint32_t rx_off, uint32_t tx_off, uint32_t buf_size, uint64_t sock_ctx) {
    uint32_t effective_buf_size = (buf_size > 4096) ? 4096 : buf_size;
    uint32_t reg_len = 0;
    int spans_ok = lookup_rio_reg_buf_len(buf_id, &reg_len) &&
                   rio_span_valid(slab.len, reg_len, rx_off, effective_buf_size) &&
                   rio_span_valid(slab.len, reg_len, tx_off, effective_buf_size);
    g_rio_hs.active =
        (sock_fd > 0 && rq_id != 0 && rx_cq != 0 && tx_cq != 0 && buf_id != 0 && slab.data != NULL && spans_ok);
    g_rio_hs.fd = (SOCKET)sock_fd;
    g_rio_hs.rq = (WING_RIO_RQ)(uintptr_t)rq_id;
    g_rio_hs.rx_cq = (WING_RIO_CQ)(uintptr_t)rx_cq;
    g_rio_hs.tx_cq = (WING_RIO_CQ)(uintptr_t)tx_cq;
    g_rio_hs.buf_id = (WING_RIO_BUFFERID)(uintptr_t)buf_id;
    g_rio_hs.slab = slab.data;
    g_rio_hs.slab_len = slab.len;
    g_rio_hs.rx_off = rx_off;
    g_rio_hs.tx_off = tx_off;
    g_rio_hs.buf_size = effective_buf_size;
    g_rio_hs.sock_ctx = sock_ctx;
    g_rio_hs.rx_stash_pos = 0;
    g_rio_hs.rx_stash_len = 0;
    g_rio_hs.rx_inflight = 0;
}

int32_t wing_rio_hs_is_rx_inflight(void) { return g_rio_hs.rx_inflight ? 1 : 0; }

int32_t wing_rio_hs_end(wing_rio_bytes_rw out_leftover) {
    int32_t rem = 0;
    if (g_rio_hs.active && g_rio_hs.rx_stash_pos < g_rio_hs.rx_stash_len) {
        uint32_t avail = g_rio_hs.rx_stash_len - g_rio_hs.rx_stash_pos;
        if (out_leftover.data != NULL && out_leftover.len > 0) {
            rem = (avail > (uint32_t)out_leftover.len) ? (int32_t)out_leftover.len : (int32_t)avail;
            memcpy(out_leftover.data, g_rio_hs.rx_stash + g_rio_hs.rx_stash_pos, (size_t)rem);
        }
    }
    g_rio_hs.active = 0;
    g_rio_hs.fd = INVALID_SOCKET;
    g_rio_hs.rx_stash_pos = 0;
    g_rio_hs.rx_stash_len = 0;
    g_rio_hs.rx_inflight = 0;
    return rem;
}

int32_t wing_rio_hs_recv(int64_t sock_fd, uint8_t *dst, int64_t len, uint32_t timeout_ms) {
    if (!g_rio_hs.active || (SOCKET)sock_fd != g_rio_hs.fd) {
        return -99;
    }
    if (!dst || len <= 0 || !g_rio.RIOReceive || !g_rio.RIODequeueCompletion) {
        return -1;
    }
    uint32_t reg_len = 0;
    if (!g_rio_hs.slab || !lookup_rio_reg_buf_len((uint64_t)(uintptr_t)g_rio_hs.buf_id, &reg_len) ||
        !rio_span_valid(g_rio_hs.slab_len, reg_len, g_rio_hs.rx_off, g_rio_hs.buf_size)) {
        return -1;
    }
    wing_rio_cq_slot *rx_slot = find_rio_cq_slot(g_rio_hs.rx_cq);
    if (rx_slot && rx_slot->corrupt) {
        return -1;
    }
    if (g_rio_hs.rx_stash_pos < g_rio_hs.rx_stash_len) {
        uint32_t avail = g_rio_hs.rx_stash_len - g_rio_hs.rx_stash_pos;
        uint32_t n = ((uint64_t)len < (uint64_t)avail) ? (uint32_t)len : avail;
        memcpy(dst, g_rio_hs.rx_stash + g_rio_hs.rx_stash_pos, n);
        g_rio_hs.rx_stash_pos += n;
        return (int32_t)n;
    }
    if (!g_rio_hs.rx_inflight) {
        WING_RIO_BUF buf;
        buf.BufferId = g_rio_hs.buf_id;
        buf.Offset = g_rio_hs.rx_off;
        buf.Length = g_rio_hs.buf_size;
        if (!g_rio.RIOReceive(g_rio_hs.rq, &buf, 1, 0, (PVOID)(uintptr_t)1)) {
            return -1;
        }
        g_rio_hs.rx_inflight = 1;
    }
    ULONGLONG deadline = GetTickCount64() + (ULONGLONG)(timeout_ms > 0 ? timeout_ms : 5000);
    WING_RIO_RESULT batch[64];
    for (;;) {
        ULONG n = g_rio.RIODequeueCompletion(g_rio_hs.rx_cq, batch, 64);
        if (n == WING_RIO_CORRUPT_CQ) {
            if (rx_slot) {
                rx_slot->corrupt = 1;
            }
            return -1;
        }
        if (n > 0) {
            wing_rio_cq_slot *cq_slot = find_rio_cq_slot(g_rio_hs.rx_cq);
            if (cq_slot) {
                cq_slot->armed = 0;
            }
            int matched = 0;
            WING_RIO_RESULT mres;
            memset(&mres, 0, sizeof(mres));
            for (ULONG i = 0; i < n; i++) {
                if (!matched && batch[i].ConnectionCorrelation == g_rio_hs.sock_ctx) {
                    matched = 1;
                    mres = batch[i];
                } else {
                    defer_push_rx(g_rio_hs.rx_cq, &batch[i]);
                }
            }
            if (matched) {
                g_rio_hs.rx_inflight = 0;
                if (mres.Status != 0 || mres.BytesTransferred == 0) {
                    return 0;
                }
                uint32_t got = (mres.BytesTransferred > g_rio_hs.buf_size) ? g_rio_hs.buf_size : mres.BytesTransferred;
                memcpy(g_rio_hs.rx_stash, g_rio_hs.slab + g_rio_hs.rx_off, got);
                g_rio_hs.rx_stash_pos = 0;
                g_rio_hs.rx_stash_len = got;
                uint32_t n_copy = ((uint64_t)len < (uint64_t)got) ? (uint32_t)len : got;
                memcpy(dst, g_rio_hs.rx_stash, n_copy);
                g_rio_hs.rx_stash_pos = n_copy;
                return (int32_t)n_copy;
            }
            continue;
        }
        ULONGLONG now = GetTickCount64();
        if (now >= deadline) {
            return -2;
        }
        int32_t rem = (int32_t)(deadline - now);
        if (rem > 5) {
            rem = 5;
        }
        (void)wing_rio_wait_cq((uint64_t)(uintptr_t)g_rio_hs.rx_cq, rem);
    }
}

int32_t wing_rio_hs_send(int64_t sock_fd, const uint8_t *data, int64_t len) {
    if (!g_rio_hs.active || (SOCKET)sock_fd != g_rio_hs.fd) {
        return -99;
    }
    if (!data || len <= 0 || !g_rio.RIOSend || !g_rio.RIODequeueCompletion) {
        return -1;
    }
    uint32_t reg_len = 0;
    if (!g_rio_hs.slab || !lookup_rio_reg_buf_len((uint64_t)(uintptr_t)g_rio_hs.buf_id, &reg_len) ||
        !rio_span_valid(g_rio_hs.slab_len, reg_len, g_rio_hs.tx_off, g_rio_hs.buf_size)) {
        return -1;
    }
    wing_rio_cq_slot *tx_slot = find_rio_cq_slot(g_rio_hs.tx_cq);
    if (tx_slot && tx_slot->corrupt) {
        return -1;
    }
    int64_t off = 0;
    WING_RIO_RESULT batch[64];
    while (off < len) {
        int64_t rem_len = len - off;
        uint32_t chunk = (rem_len > (int64_t)g_rio_hs.buf_size) ? g_rio_hs.buf_size : (uint32_t)rem_len;
        if (chunk == 0) {
            return -1;
        }
        memcpy(g_rio_hs.slab + g_rio_hs.tx_off, data + off, chunk);
        WING_RIO_BUF buf;
        buf.BufferId = g_rio_hs.buf_id;
        buf.Offset = g_rio_hs.tx_off;
        buf.Length = chunk;
        if (!g_rio.RIOSend(g_rio_hs.rq, &buf, 1, 0, (PVOID)(uintptr_t)2)) {
            return -1;
        }
        ULONGLONG deadline = GetTickCount64() + 5000ULL;
        int done = 0;
        while (!done) {
            ULONG n = g_rio.RIODequeueCompletion(g_rio_hs.tx_cq, batch, 64);
            if (n == WING_RIO_CORRUPT_CQ) {
                if (tx_slot) {
                    tx_slot->corrupt = 1;
                }
                return -1;
            }
            if (n > 0) {
                wing_rio_cq_slot *cq_slot = find_rio_cq_slot(g_rio_hs.tx_cq);
                if (cq_slot) {
                    cq_slot->armed = 0;
                }
                for (ULONG i = 0; i < n; i++) {
                    if (!done && batch[i].ConnectionCorrelation == g_rio_hs.sock_ctx) {
                        if (batch[i].Status != 0) {
                            return -1;
                        }
                        done = 1;
                    } else {
                        defer_push_tx(g_rio_hs.tx_cq, &batch[i]);
                    }
                }
                continue;
            }
            ULONGLONG now = GetTickCount64();
            if (now >= deadline) {
                return -1;
            }
            (void)wing_rio_wait_cq((uint64_t)(uintptr_t)g_rio_hs.tx_cq, 2);
        }
        off += (int64_t)chunk;
    }
    return (int32_t)off;
}

typedef struct {
    SOCKET lsock;
    int family;
    int active;
} wing_rio_listener_entry;

static wing_rio_listener_entry g_rio_listeners[WING_RIO_MAX_LISTENERS];

static void record_rio_listener(SOCKET s, int family) {
    int free_idx = -1;
    for (int i = 0; i < WING_RIO_MAX_LISTENERS; i++) {
        if (g_rio_listeners[i].active && g_rio_listeners[i].lsock == s) {
            g_rio_listeners[i].family = family;
            return;
        }
        if (!g_rio_listeners[i].active && free_idx < 0) {
            free_idx = i;
        }
    }
    if (free_idx >= 0) {
        g_rio_listeners[free_idx].lsock = s;
        g_rio_listeners[free_idx].family = family;
        g_rio_listeners[free_idx].active = 1;
    }
}

static void remove_rio_listener(SOCKET s) {
    for (int i = 0; i < WING_RIO_MAX_LISTENERS; i++) {
        if (g_rio_listeners[i].active && g_rio_listeners[i].lsock == s) {
            g_rio_listeners[i].active = 0;
            g_rio_listeners[i].lsock = 0;
            g_rio_listeners[i].family = 0;
        }
    }
}

int64_t wing_rio_listen(wing_rio_str_ro host, uint16_t port, int32_t backlog) {
    if (init_rio_table() != 0) {
        return -1;
    }

    char host_str[128];
    if (host.len < 0 || host.len >= (int64_t)sizeof(host_str)) {
        return -1;
    }
    if (host.len > 0) {
        if (host.data == NULL || memchr(host.data, '\0', (size_t)host.len) != NULL) {
            return -1;
        }
        memcpy(host_str, host.data, (size_t)host.len);
        host_str[host.len] = '\0';
    } else {
        host_str[0] = '\0';
    }

    const char *h = host_str;
    size_t hlen = strlen(h);
    char stripped[128];
    if (hlen >= 2 && h[0] == '[' && h[hlen - 1] == ']') {
        memcpy(stripped, h + 1, hlen - 2);
        stripped[hlen - 2] = '\0';
        h = stripped;
    }

    struct sockaddr_storage ss;
    memset(&ss, 0, sizeof(ss));
    int addr_len = 0;
    int family = AF_INET;

    struct in6_addr addr6;
    struct in_addr addr4;
    if (h[0] == '\0' || strcmp(h, "0.0.0.0") == 0) {
        struct sockaddr_in *s4 = (struct sockaddr_in *)&ss;
        s4->sin_family = AF_INET;
        s4->sin_port = htons(port);
        s4->sin_addr.s_addr = INADDR_ANY;
        addr_len = (int)sizeof(struct sockaddr_in);
    } else if (strcmp(h, "localhost") == 0) {
        struct sockaddr_in *s4 = (struct sockaddr_in *)&ss;
        s4->sin_family = AF_INET;
        s4->sin_port = htons(port);
        s4->sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        addr_len = (int)sizeof(struct sockaddr_in);
    } else if (inet_pton(AF_INET, h, &addr4) == 1) {
        struct sockaddr_in *s4 = (struct sockaddr_in *)&ss;
        s4->sin_family = AF_INET;
        s4->sin_port = htons(port);
        s4->sin_addr = addr4;
        addr_len = (int)sizeof(struct sockaddr_in);
    } else if (inet_pton(AF_INET6, h, &addr6) == 1) {
        family = AF_INET6;
        struct sockaddr_in6 *s6 = (struct sockaddr_in6 *)&ss;
        s6->sin6_family = AF_INET6;
        s6->sin6_port = htons(port);
        s6->sin6_addr = addr6;
        addr_len = (int)sizeof(struct sockaddr_in6);
    } else {
        return -1;
    }

    SOCKET s = WSASocketW(family, SOCK_STREAM, IPPROTO_TCP, NULL, 0, WSA_FLAG_REGISTERED_IO | WSA_FLAG_OVERLAPPED);
    if (s == INVALID_SOCKET) {
        return -1;
    }
    SetHandleInformation((HANDLE)s, HANDLE_FLAG_INHERIT, 0);
    int opt = 1;
    setsockopt(s, SOL_SOCKET, SO_EXCLUSIVEADDRUSE, (const char *)&opt, sizeof(opt));
    if (family == AF_INET6) {
        int v6only = 0;
        (void)setsockopt(s, IPPROTO_IPV6, IPV6_V6ONLY, (const char *)&v6only, sizeof(v6only));
    }

    if (bind(s, (struct sockaddr *)&ss, addr_len) == SOCKET_ERROR) {
        closesocket(s);
        return -1;
    }
    if (listen(s, backlog > 0 ? backlog : 128) == SOCKET_ERROR) {
        closesocket(s);
        return -1;
    }
    record_rio_listener(s, family);
    return (int64_t)s;
}

static int query_socket_family(SOCKET s) {
    for (int i = 0; i < WING_RIO_MAX_LISTENERS; i++) {
        if (g_rio_listeners[i].active && g_rio_listeners[i].lsock == s) {
            return g_rio_listeners[i].family;
        }
    }
    struct sockaddr_storage ss;
    int len = (int)sizeof(ss);
    memset(&ss, 0, sizeof(ss));
    if (getsockname(s, (struct sockaddr *)&ss, &len) == 0 && (ss.ss_family == AF_INET || ss.ss_family == AF_INET6)) {
        return (int)ss.ss_family;
    }
    return AF_INET;
}

static int64_t finalize_rio_accepted_socket(SOCKET lsock, SOCKET asock) {
    (void)setsockopt(asock, SOL_SOCKET, SO_UPDATE_ACCEPT_CONTEXT, (const char *)&lsock, sizeof(lsock));
    int nodelay = 1;
    (void)setsockopt(asock, IPPROTO_TCP, TCP_NODELAY, (const char *)&nodelay, sizeof(nodelay));
    u_long nonblock = 1;
    (void)ioctlsocket(asock, FIONBIO, &nonblock);
    return (int64_t)asock;
}

int64_t wing_rio_accept(int64_t listen_fd) {
    if (init_rio_table() != 0 || listen_fd <= 0 || !g_acceptex) {
        return -1;
    }
    SOCKET lsock = (SOCKET)listen_fd;
    int family = query_socket_family(lsock);

    for (int attempt = 0; attempt < 2; attempt++) {
        SOCKET asock =
            WSASocketW(family, SOCK_STREAM, IPPROTO_TCP, NULL, 0, WSA_FLAG_REGISTERED_IO | WSA_FLAG_OVERLAPPED);
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
        uint8_t addr_buf[WING_RIO_ACCEPT_ADDR_LEN * 2];
        memset(addr_buf, 0, sizeof(addr_buf));
        DWORD bytes = 0;

        BOOL ok =
            g_acceptex(lsock, asock, addr_buf, 0, WING_RIO_ACCEPT_ADDR_LEN, WING_RIO_ACCEPT_ADDR_LEN, &bytes, &ov);
        if (!ok) {
            int err = WSAGetLastError();
            if (err == WSAECONNRESET) {
                CloseHandle(ev);
                closesocket(asock);
                continue;
            }
            if (err != WSA_IO_PENDING) {
                CloseHandle(ev);
                closesocket(asock);
                return -1;
            }
            DWORD w = WaitForSingleObject(ev, 200);
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
                int oerr = WSAGetLastError();
                CloseHandle(ev);
                closesocket(asock);
                if (oerr == WSAECONNRESET) {
                    continue;
                }
                return -1;
            }
        }

        CloseHandle(ev);
        return finalize_rio_accepted_socket(lsock, asock);
    }
    return -1;
}

typedef struct {
    SOCKET lsock;
    SOCKET asock;
    HANDLE ev;
    OVERLAPPED ov;
    uint8_t addr_buf[WING_RIO_ACCEPT_ADDR_LEN * 2];
    int pending;
} wing_rio_accept_slot;

static wing_rio_accept_slot g_rio_accept_slots[WING_RIO_MAX_LISTENERS];

int32_t wing_rio_is_listener(int64_t sock_fd) {
    if (sock_fd <= 0) {
        return 0;
    }
    SOCKET s = (SOCKET)sock_fd;
    struct sockaddr_storage ss;
    int len = (int)sizeof(ss);
    if (getsockname(s, (struct sockaddr *)&ss, &len) != 0) {
        remove_rio_listener(s);
        return 0;
    }
    int accept_conn = 0;
    int opt_len = (int)sizeof(accept_conn);
    if (getsockopt(s, SOL_SOCKET, SO_ACCEPTCONN, (char *)&accept_conn, &opt_len) == 0 && !accept_conn) {
        remove_rio_listener(s);
        return 0;
    }
    WSAPOLLFD pfd;
    pfd.fd = s;
    pfd.events = POLLRDNORM;
    pfd.revents = 0;
    if (WSAPoll(&pfd, 1, 0) == SOCKET_ERROR && WSAGetLastError() == WSAENOTSOCK) {
        record_rio_listener(s, (ss.ss_family == AF_INET6) ? AF_INET6 : AF_INET);
        return 1;
    }
    remove_rio_listener(s);
    return 0;
}

static int32_t cleanup_rio_accept_slot(wing_rio_accept_slot *slot, int cancel_io) {
    if (!slot || !slot->pending) {
        return 0;
    }
    if (cancel_io && slot->lsock != INVALID_SOCKET && slot->lsock != 0) {
        CancelIoEx((HANDLE)slot->lsock, &slot->ov);
        DWORD bytes = 0;
        DWORD flags = 0;
        (void)WSAGetOverlappedResult(slot->lsock, &slot->ov, &bytes, TRUE, &flags);
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
    return 1;
}

int32_t wing_rio_cancel_accept(int64_t listen_fd) {
    int32_t cancelled = 0;
    if (listen_fd <= 0) {
        for (int i = 0; i < WING_RIO_MAX_LISTENERS; i++) {
            cancelled += cleanup_rio_accept_slot(&g_rio_accept_slots[i], 1);
            g_rio_listeners[i].active = 0;
        }
        return cancelled;
    }
    SOCKET lsock = (SOCKET)listen_fd;
    remove_rio_listener(lsock);
    for (int i = 0; i < WING_RIO_MAX_LISTENERS; i++) {
        if (g_rio_accept_slots[i].pending && g_rio_accept_slots[i].lsock == lsock) {
            cancelled += cleanup_rio_accept_slot(&g_rio_accept_slots[i], 1);
        }
    }
    return cancelled;
}

int64_t wing_rio_poll_accept(int64_t listen_fd, int32_t timeout_ms) {
    if (init_rio_table() != 0 || listen_fd <= 0 || !g_acceptex) {
        return -1;
    }
    SOCKET lsock = (SOCKET)listen_fd;
    int family = 0;

    for (int attempt = 0; attempt < 2; attempt++) {
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
            if (family == 0) {
                family = query_socket_family(lsock);
            }
            SOCKET asock =
                WSASocketW(family, SOCK_STREAM, IPPROTO_TCP, NULL, 0, WSA_FLAG_REGISTERED_IO | WSA_FLAG_OVERLAPPED);
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
            BOOL ok = g_acceptex(lsock, asock, slot->addr_buf, 0, WING_RIO_ACCEPT_ADDR_LEN, WING_RIO_ACCEPT_ADDR_LEN,
                                 &bytes, &slot->ov);
            if (ok) {
                CloseHandle(ev);
                slot->ev = NULL;
                slot->asock = INVALID_SOCKET;
                slot->pending = 0;
                return finalize_rio_accepted_socket(lsock, asock);
            }
            int err = WSAGetLastError();
            if (err == WSAECONNRESET) {
                CloseHandle(ev);
                closesocket(asock);
                memset(slot, 0, sizeof(*slot));
                continue;
            }
            if (err != WSA_IO_PENDING) {
                CloseHandle(ev);
                closesocket(asock);
                memset(slot, 0, sizeof(*slot));
                return -1;
            }
            slot->pending = 1;
        }

        DWORD wait_ms = (timeout_ms < 0) ? 0 : (DWORD)timeout_ms;
        if (wait_ms == 0) {
            if (!HasOverlappedIoCompleted(&slot->ov)) {
                return 0;
            }
        } else {
            DWORD w = WaitForSingleObject(slot->ev, wait_ms);
            if (w == WAIT_TIMEOUT) {
                return 0;
            }
            if (w != WAIT_OBJECT_0) {
                cleanup_rio_accept_slot(slot, 1);
                return -1;
            }
        }
        DWORD bytes = 0;
        DWORD flags = 0;
        if (!WSAGetOverlappedResult(lsock, &slot->ov, &bytes, FALSE, &flags)) {
            int oerr = WSAGetLastError();
            cleanup_rio_accept_slot(slot, 0);
            if (oerr == WSAECONNRESET) {
                continue;
            }
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
    return -1;
}

#else

#ifndef ENOSYS
#define ENOSYS 38
#endif
#ifndef EINVAL
#define EINVAL 22
#endif

// Non-Windows platform stubs
int32_t wing_rio_probe(void) { return -ENOSYS; }
int32_t wing_rio_available(void) { return 0; }
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
int32_t wing_rio_cq_is_corrupt(uint64_t cq_id) {
    (void)cq_id;
    return 0;
}
int32_t wing_rio_wait_cq(uint64_t cq_id, int32_t timeout_ms) {
    (void)cq_id;
    (void)timeout_ms;
    return -ENOSYS;
}
int32_t wing_rio_dequeue_slice(uint64_t cq_id, wing_rio_results_rw dst) {
    (void)cq_id;
    (void)dst;
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
int32_t wing_rio_cancel_accept(int64_t listen_fd) {
    (void)listen_fd;
    return 0;
}
void wing_rio_hs_begin(int64_t sock_fd, uint64_t rq_id, uint64_t rx_cq, uint64_t tx_cq, uint64_t buf_id,
                       wing_rio_bytes_rw slab, uint32_t rx_off, uint32_t tx_off, uint32_t buf_size, uint64_t sock_ctx) {
    (void)sock_fd;
    (void)rq_id;
    (void)rx_cq;
    (void)tx_cq;
    (void)buf_id;
    (void)slab;
    (void)rx_off;
    (void)tx_off;
    (void)buf_size;
    (void)sock_ctx;
}
int32_t wing_rio_hs_is_rx_inflight(void) { return 0; }
int32_t wing_rio_hs_end(wing_rio_bytes_rw out_leftover) {
    (void)out_leftover;
    return 0;
}

#endif
