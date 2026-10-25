// Layer 4 Windows Registered I/O (RIO) Kernel-Bypass C Shim.
// Queries the RIO Extension Function Table via SIO_GET_MULTIPLE_EXTENSION_FUNCTION_POINTER
// and manages page-locked registered memory buffers via mswsock.dll.
#define WIN32_LEAN_AND_MEAN
#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0602
#endif

#include <stdint.h>
#include <stddef.h>

#ifdef _WIN32
#include <winsock2.h>
#include <windows.h>

#ifndef SIO_GET_MULTIPLE_EXTENSION_FUNCTION_POINTER
#define SIO_GET_MULTIPLE_EXTENSION_FUNCTION_POINTER _WSAIORW(IOC_WS2, 36)
#endif

#ifndef WSA_FLAG_REGISTERED_IO
#define WSA_FLAG_REGISTERED_IO 0x100
#endif

static const GUID k_rio_guid = { 0x8509E081, 0x96DD, 0x4005, { 0xB1, 0x65, 0x9E, 0x2E, 0xE8, 0xC7, 0x9E, 0x3F } };

typedef void *RIO_BUFFERID;
#define RIO_INVALID_BUFFERID ((RIO_BUFFERID)0)
typedef void *RIO_CQ;
typedef void *RIO_RQ;

typedef struct _WING_RIO_BUF {
    RIO_BUFFERID BufferId;
    ULONG Offset;
    ULONG Length;
} WING_RIO_BUF;

typedef struct _WING_RIO_RESULT {
    LONG Status;
    ULONG BytesTransferred;
    ULONGLONG ConnectionCorrelation;
    ULONGLONG RequestCorrelation;
} WING_RIO_RESULT;

typedef struct _WING_RIO_EXTENSION_FUNCTION_TABLE {
    DWORD cbSize;
    BOOL (PASCAL *RIOReceive)(RIO_RQ SocketQueue, WING_RIO_BUF *pData, ULONG DataBufferCount, DWORD Flags, PVOID RequestContext);
    int (PASCAL *RIOReceiveEx)(RIO_RQ SocketQueue, WING_RIO_BUF *pData, ULONG DataBufferCount, WING_RIO_BUF *pLocalAddress, WING_RIO_BUF *pRemoteAddress, WING_RIO_BUF *pControlContext, WING_RIO_BUF *pFlags, DWORD Flags, PVOID RequestContext);
    BOOL (PASCAL *RIOSend)(RIO_RQ SocketQueue, WING_RIO_BUF *pData, ULONG DataBufferCount, DWORD Flags, PVOID RequestContext);
    BOOL (PASCAL *RIOSendEx)(RIO_RQ SocketQueue, WING_RIO_BUF *pData, ULONG DataBufferCount, WING_RIO_BUF *pLocalAddress, WING_RIO_BUF *pRemoteAddress, WING_RIO_BUF *pControlContext, WING_RIO_BUF *pFlags, DWORD Flags, PVOID RequestContext);
    void (PASCAL *RIOCloseCompletionQueue)(RIO_CQ CQ);
    RIO_CQ (PASCAL *RIOCreateCompletionQueue)(DWORD QueueSize, void *NotificationCompletion);
    RIO_RQ (PASCAL *RIOCreateRequestQueue)(SOCKET Socket, ULONG MaxOutstandingReceive, ULONG MaxReceiveDataBuffers, ULONG MaxOutstandingSend, ULONG MaxSendDataBuffers, RIO_CQ ReceiveCQ, RIO_CQ SendCQ, PVOID SocketContext);
    ULONG (PASCAL *RIODequeueCompletion)(RIO_CQ CQ, WING_RIO_RESULT *Array, ULONG ArraySize);
    void (PASCAL *RIODeregisterBuffer)(RIO_BUFFERID BufferId);
    void (PASCAL *RIONotify)(RIO_CQ CQ);
    RIO_BUFFERID (PASCAL *RIORegisterBuffer)(PCHAR DataBuffer, DWORD DataLength);
    BOOL (PASCAL *RIOResizeCompletionQueue)(RIO_CQ CQ, DWORD QueueSize);
    BOOL (PASCAL *RIOResizeRequestQueue)(RIO_RQ SocketQueue, DWORD MaxOutstandingReceive, DWORD MaxOutstandingSend);
} WING_RIO_EXTENSION_FUNCTION_TABLE;

static WING_RIO_EXTENSION_FUNCTION_TABLE g_rio;
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

    SOCKET s = WSASocketW(AF_INET, SOCK_STREAM, IPPROTO_TCP, NULL, 0, WSA_FLAG_REGISTERED_IO);
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
    int rc = WSAIoctl(s, SIO_GET_MULTIPLE_EXTENSION_FUNCTION_POINTER,
                      &functionTableId, sizeof(functionTableId),
                      &g_rio, sizeof(g_rio),
                      &bytes, NULL, NULL);

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
    if (!g_rio_available) {
        if (init_rio_table() != 0) {
            return 0;
        }
    }
    if (!buf || len == 0 || !g_rio.RIORegisterBuffer) {
        return 0;
    }
    RIO_BUFFERID id = g_rio.RIORegisterBuffer((char*)buf, len);
    if (id == RIO_INVALID_BUFFERID) {
        return 0;
    }
    return (uint64_t)(uintptr_t)id;
}

void wing_rio_deregister_buffer(uint64_t buf_id) {
    if (g_rio_available && buf_id != 0 && g_rio.RIODeregisterBuffer) {
        g_rio.RIODeregisterBuffer((RIO_BUFFERID)(uintptr_t)buf_id);
    }
}

uint64_t wing_rio_create_cq(uint32_t queue_size) {
    if (!g_rio_available && init_rio_table() != 0) {
        return 0;
    }
    if (!g_rio.RIOCreateCompletionQueue) {
        return 0;
    }
    RIO_CQ cq = g_rio.RIOCreateCompletionQueue(queue_size, NULL);
    return (uint64_t)(uintptr_t)cq;
}

void wing_rio_close_cq(uint64_t cq_id) {
    if (g_rio_available && cq_id != 0 && g_rio.RIOCloseCompletionQueue) {
        g_rio.RIOCloseCompletionQueue((RIO_CQ)(uintptr_t)cq_id);
    }
}

uint32_t wing_rio_dequeue_completion(uint64_t cq_id, void *results, uint32_t count) {
    if (!g_rio_available && init_rio_table() != 0) {
        return 0;
    }
    if (!cq_id || !results || !g_rio.RIODequeueCompletion) {
        return 0;
    }
    return g_rio.RIODequeueCompletion((RIO_CQ)(uintptr_t)cq_id, (WING_RIO_RESULT*)results, count);
}

#else

#ifndef ENOSYS
#define ENOSYS 38
#endif

// Non-Windows platform stubs
int32_t wing_rio_probe(void) { return -ENOSYS; }
int32_t wing_rio_available(void) { return 0; }
uint64_t wing_rio_register_buffer(void *buf, uint32_t len) { (void)buf; (void)len; return 0; }
void wing_rio_deregister_buffer(uint64_t buf_id) { (void)buf_id; }
uint64_t wing_rio_create_cq(uint32_t queue_size) { (void)queue_size; return 0; }
void wing_rio_close_cq(uint64_t cq_id) { (void)cq_id; }
uint32_t wing_rio_dequeue_completion(uint64_t cq_id, void *results, uint32_t count) {
    (void)cq_id; (void)results; (void)count; return 0;
}

#endif
