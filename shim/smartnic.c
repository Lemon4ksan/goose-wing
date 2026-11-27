// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Layer 4 SmartNIC & Hardware TLS Offload C Shim.
// Enables hardware offload of TCP and TLS 1.2 / 1.3 crypto directly onto SmartNIC ASICs / DPUs
// (e.g. NVIDIA BlueField, Mellanox ConnectX-6/7 Dx, Intel Mount Evans).
#include <stdint.h>
#include <stddef.h>

#pragma pack(push, 1)
typedef struct {
    const uint8_t *data;
    int64_t len;
} wing_bytes_ro;

typedef struct {
    uint8_t *data;
    int64_t len;
} wing_bytes_mut;
#pragma pack(pop)

_Static_assert(sizeof(wing_bytes_ro) == sizeof(const uint8_t *) + sizeof(int64_t), "wing_bytes_ro must be packed");
_Static_assert(offsetof(wing_bytes_ro, len) == sizeof(const uint8_t *), "wing_bytes_ro.len must follow data");
_Static_assert(sizeof(wing_bytes_mut) == sizeof(uint8_t *) + sizeof(int64_t), "wing_bytes_mut must be packed");
_Static_assert(offsetof(wing_bytes_mut, len) == sizeof(uint8_t *), "wing_bytes_mut.len must follow data");

#if defined(__linux__)
#include <unistd.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <errno.h>

#ifndef SOL_TCP
#define SOL_TCP 6
#endif

#ifndef TCP_ULP
#define TCP_ULP 31
#endif

#ifndef SOL_TLS
#define SOL_TLS 282
#endif

#ifndef TLS_TX
#define TLS_TX 1
#endif
#ifndef TLS_RX
#define TLS_RX 2
#endif

#ifndef TLS_SET_RECORD_TYPE
#define TLS_SET_RECORD_TYPE 1
#endif
#ifndef TLS_GET_RECORD_TYPE
#define TLS_GET_RECORD_TYPE 2
#endif

#ifndef TLS_1_2_VERSION
#define TLS_1_2_VERSION 0x0303
#endif
#ifndef TLS_1_3_VERSION
#define TLS_1_3_VERSION 0x0304
#endif

#ifndef TLS_CIPHER_AES_GCM_128
#define TLS_CIPHER_AES_GCM_128 51
#endif
#ifndef TLS_CIPHER_AES_GCM_256
#define TLS_CIPHER_AES_GCM_256 52
#endif

#ifndef TLS_OFFLOAD_SW
#define TLS_OFFLOAD_SW 1
#endif
#ifndef TLS_OFFLOAD_DEVICE
#define TLS_OFFLOAD_DEVICE 2
#endif

struct wing_tls_crypto_info_aes_gcm_128 {
    uint16_t version;
    uint16_t cipher_type;
    uint8_t iv[8];
    uint8_t key[16];
    uint8_t salt[4];
    uint8_t rec_seq[8];
};

struct wing_tls_crypto_info_aes_gcm_256 {
    uint16_t version;
    uint16_t cipher_type;
    uint8_t iv[8];
    uint8_t key[32];
    uint8_t salt[4];
    uint8_t rec_seq[8];
};

int32_t wing_smartnic_probe_ktls(void) {
    int s = socket(AF_INET, SOCK_STREAM, 0);
    if (s < 0) {
        return -errno;
    }
    int ret = setsockopt(s, SOL_TCP, TCP_ULP, "tls", sizeof("tls"));
    int err = errno;
    close(s);
    if (ret == 0 || err == ENOTCONN) {
        return 1;
    }
    return err > 0 ? -err : -1;
}

int32_t wing_smartnic_probe(void) {
    int rc = wing_smartnic_probe_ktls();
    return rc > 0 ? 0 : rc;
}

int32_t wing_smartnic_enable_ktls(int64_t fd) {
    if (fd <= 0) {
        return -EINVAL;
    }
    if (setsockopt((int)fd, SOL_TCP, TCP_ULP, "tls", sizeof("tls")) < 0) {
        return -errno;
    }
    return 0;
}

static void wing_zeroize_mem(void *ptr, size_t len) {
    volatile uint8_t *p = (volatile uint8_t *)ptr;
    for (size_t i = 0; i < len; ++i) {
        p[i] = 0;
    }
}

static int wing_has_valid_ktls_params(int64_t fd, wing_bytes_ro key, int64_t req_key_len, wing_bytes_ro iv,
                                      wing_bytes_ro salt, wing_bytes_ro rec_seq) {
    return fd > 0 && key.data != NULL && key.len == req_key_len && iv.data != NULL && iv.len >= 4 &&
           salt.data != NULL && salt.len >= 4 && rec_seq.data != NULL && rec_seq.len >= 8;
}

int32_t wing_smartnic_set_hardware_tls(int64_t fd, int32_t is_tx, uint16_t version, uint16_t cipher_type,
                                       wing_bytes_ro key, wing_bytes_ro iv, wing_bytes_ro salt, wing_bytes_ro rec_seq) {
    int opt = is_tx ? TLS_TX : TLS_RX;
    size_t iv_copy_len = (iv.len >= 8) ? 8 : (size_t)iv.len;
    if (cipher_type == TLS_CIPHER_AES_GCM_128 && wing_has_valid_ktls_params(fd, key, 16, iv, salt, rec_seq)) {
        struct wing_tls_crypto_info_aes_gcm_128 info;
        __builtin_memset(&info, 0, sizeof(info));
        info.version = version;
        info.cipher_type = cipher_type;
        __builtin_memcpy(info.iv, iv.data, iv_copy_len);
        __builtin_memcpy(info.key, key.data, 16);
        __builtin_memcpy(info.salt, salt.data, 4);
        __builtin_memcpy(info.rec_seq, rec_seq.data, 8);

        int rc = setsockopt((int)fd, SOL_TLS, opt, &info, sizeof(info));
        int err = (rc < 0) ? -errno : 0;
        wing_zeroize_mem(&info, sizeof(info));
        return err;
    } else if (cipher_type == TLS_CIPHER_AES_GCM_256 && wing_has_valid_ktls_params(fd, key, 32, iv, salt, rec_seq)) {
        struct wing_tls_crypto_info_aes_gcm_256 info;
        __builtin_memset(&info, 0, sizeof(info));
        info.version = version;
        info.cipher_type = cipher_type;
        __builtin_memcpy(info.iv, iv.data, iv_copy_len);
        __builtin_memcpy(info.key, key.data, 32);
        __builtin_memcpy(info.salt, salt.data, 4);
        __builtin_memcpy(info.rec_seq, rec_seq.data, 8);

        int rc = setsockopt((int)fd, SOL_TLS, opt, &info, sizeof(info));
        int err = (rc < 0) ? -errno : 0;
        wing_zeroize_mem(&info, sizeof(info));
        return err;
    }
    return -EINVAL;
}

int32_t wing_smartnic_recv_record(int64_t fd, wing_bytes_mut dst, wing_bytes_mut out_rt) {
    if (out_rt.data != NULL && out_rt.len > 0) {
        out_rt.data[0] = 0;
    }
    if (fd <= 0 || dst.data == NULL || dst.len <= 0) {
        return -EINVAL;
    }
    struct iovec iov;
    iov.iov_base = dst.data;
    iov.iov_len = (size_t)dst.len;

    union {
        char buf[CMSG_SPACE(sizeof(uint8_t))];
        struct cmsghdr align;
    } ctrl;
    memset(&ctrl, 0, sizeof(ctrl));

    struct msghdr msg;
    memset(&msg, 0, sizeof(msg));
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;
    msg.msg_control = ctrl.buf;
    msg.msg_controllen = sizeof(ctrl.buf);

    ssize_t n = recvmsg((int)fd, &msg, MSG_DONTWAIT);
    if (n < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            return -2;
        }
        return -errno;
    }
    if (n == 0) {
        return 0;
    }
    uint8_t rt = 23;
#if defined(__GNUC__) || defined(__clang__)
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wsign-compare"
#endif
    for (struct cmsghdr *cmsg = CMSG_FIRSTHDR(&msg); cmsg != NULL; cmsg = CMSG_NXTHDR(&msg, cmsg)) {
        if (cmsg->cmsg_level == SOL_TLS && cmsg->cmsg_type == TLS_GET_RECORD_TYPE &&
            cmsg->cmsg_len >= CMSG_LEN(sizeof(uint8_t))) {
            rt = *(const uint8_t *)CMSG_DATA(cmsg);
            break;
        }
    }
#if defined(__GNUC__) || defined(__clang__)
#pragma GCC diagnostic pop
#endif
    if (out_rt.data != NULL && out_rt.len > 0) {
        out_rt.data[0] = rt;
    }
    return (int32_t)n;
}

int32_t wing_smartnic_send_record(int64_t fd, wing_bytes_ro src, uint8_t record_type) {
    if (fd <= 0 || src.data == NULL || src.len <= 0) {
        return -EINVAL;
    }
    struct iovec iov;
    iov.iov_base = (void *)(uintptr_t)src.data;
    iov.iov_len = (size_t)src.len;

    union {
        char buf[CMSG_SPACE(sizeof(uint8_t))];
        struct cmsghdr align;
    } ctrl;
    memset(&ctrl, 0, sizeof(ctrl));

    struct msghdr msg;
    memset(&msg, 0, sizeof(msg));
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;
    if (record_type != 23) {
        msg.msg_control = ctrl.buf;
        msg.msg_controllen = sizeof(ctrl.buf);
        struct cmsghdr *cmsg = CMSG_FIRSTHDR(&msg);
        cmsg->cmsg_level = SOL_TLS;
        cmsg->cmsg_type = TLS_SET_RECORD_TYPE;
        cmsg->cmsg_len = CMSG_LEN(sizeof(uint8_t));
        *(uint8_t *)CMSG_DATA(cmsg) = record_type;
    }

    int flags = 0;
#ifdef MSG_NOSIGNAL
    flags |= MSG_NOSIGNAL;
#endif
    ssize_t sent = sendmsg((int)fd, &msg, flags);
    if (sent < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            return -2;
        }
        return -errno;
    }
    return (int32_t)sent;
}

#elif defined(_WIN32)
#include <winsock2.h>
#include <windows.h>

// Windows SmartNIC & Hardware Chimney Offload probing
int32_t wing_smartnic_probe(void) {
    // Windows RIO and Winsock Chimney Offload probe
    SOCKET s = WSASocketW(AF_INET, SOCK_STREAM, IPPROTO_TCP, NULL, 0, WSA_FLAG_OVERLAPPED);
    if (s == INVALID_SOCKET) {
        return -1;
    }
    closesocket(s);
    return 0;
}

int32_t wing_smartnic_probe_ktls(void) { return -1; }

int32_t wing_smartnic_enable_ktls(int64_t fd) {
    (void)fd;
    return -1;
}

int32_t wing_smartnic_set_hardware_tls(int64_t fd, int32_t is_tx, uint16_t version, uint16_t cipher_type,
                                       wing_bytes_ro key, wing_bytes_ro iv, wing_bytes_ro salt, wing_bytes_ro rec_seq) {
    (void)fd;
    (void)is_tx;
    (void)version;
    (void)cipher_type;
    (void)key;
    (void)iv;
    (void)salt;
    (void)rec_seq;
    return -1;
}

int32_t wing_smartnic_recv_record(int64_t fd, wing_bytes_mut dst, wing_bytes_mut out_rt) {
    (void)fd;
    (void)dst;
    if (out_rt.data != NULL && out_rt.len > 0) {
        out_rt.data[0] = 0;
    }
    return -1;
}

int32_t wing_smartnic_send_record(int64_t fd, wing_bytes_ro src, uint8_t record_type) {
    (void)fd;
    (void)src;
    (void)record_type;
    return -1;
}

#else

#ifndef ENOSYS
#define ENOSYS 38
#endif

int32_t wing_smartnic_probe(void) { return -ENOSYS; }
int32_t wing_smartnic_probe_ktls(void) { return -ENOSYS; }
int32_t wing_smartnic_enable_ktls(int64_t fd) {
    (void)fd;
    return -ENOSYS;
}
int32_t wing_smartnic_set_hardware_tls(int64_t fd, int32_t is_tx, uint16_t version, uint16_t cipher_type,
                                       wing_bytes_ro key, wing_bytes_ro iv, wing_bytes_ro salt, wing_bytes_ro rec_seq) {
    (void)fd;
    (void)is_tx;
    (void)version;
    (void)cipher_type;
    (void)key;
    (void)iv;
    (void)salt;
    (void)rec_seq;
    return -ENOSYS;
}
int32_t wing_smartnic_recv_record(int64_t fd, wing_bytes_mut dst, wing_bytes_mut out_rt) {
    (void)fd;
    (void)dst;
    if (out_rt.data != NULL && out_rt.len > 0) {
        out_rt.data[0] = 0;
    }
    return -ENOSYS;
}
int32_t wing_smartnic_send_record(int64_t fd, wing_bytes_ro src, uint8_t record_type) {
    (void)fd;
    (void)src;
    (void)record_type;
    return -ENOSYS;
}

#endif
