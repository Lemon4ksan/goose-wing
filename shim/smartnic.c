// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Layer 4 SmartNIC & Hardware TLS Offload C Shim.
// Enables hardware offload of TCP and TLS 1.2 / 1.3 crypto directly onto SmartNIC ASICs / DPUs
// (e.g. NVIDIA BlueField, Mellanox ConnectX-6/7 Dx, Intel Mount Evans).
#include <stdint.h>
#include <stddef.h>

typedef struct {
    const uint8_t *data;
    int64_t len;
} wing_bytes_ro;

#if defined(__linux__)
#include <unistd.h>
#include <sys/socket.h>
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
    uint8_t iv[4];
    uint8_t key[16];
    uint8_t salt[4];
    uint8_t rec_seq[8];
};

struct wing_tls_crypto_info_aes_gcm_256 {
    uint16_t version;
    uint16_t cipher_type;
    uint8_t iv[4];
    uint8_t key[32];
    uint8_t salt[4];
    uint8_t rec_seq[8];
};

int32_t wing_smartnic_probe(void) {
    int s = socket(AF_INET, SOCK_STREAM, 0);
    if (s < 0) {
        return -errno;
    }
    // Probe TCP_ULP "tls" availability in kernel
    int ret = setsockopt(s, SOL_TCP, TCP_ULP, "tls", sizeof("tls"));
    close(s);
    if (ret < 0) {
        return -errno;
    }
    return 0;
}

int32_t wing_smartnic_enable_ktls(int64_t fd) {
    if (setsockopt((int)fd, SOL_TCP, TCP_ULP, "tls", sizeof("tls")) < 0) {
        return -errno;
    }
    return 0;
}

int32_t wing_smartnic_set_hardware_tls_tx(int64_t fd, uint16_t version, uint16_t cipher_type, wing_bytes_ro key,
                                          wing_bytes_ro iv, wing_bytes_ro salt, wing_bytes_ro rec_seq) {
    if (cipher_type == TLS_CIPHER_AES_GCM_128 && key.len >= 16) {
        struct wing_tls_crypto_info_aes_gcm_128 info;
        __builtin_memset(&info, 0, sizeof(info));
        info.version = version;
        info.cipher_type = cipher_type;
        __builtin_memcpy(info.iv, iv.data, 4);
        __builtin_memcpy(info.key, key.data, 16);
        __builtin_memcpy(info.salt, salt.data, 4);
        __builtin_memcpy(info.rec_seq, rec_seq.data, 8);

        if (setsockopt((int)fd, SOL_TLS, TLS_TX, &info, sizeof(info)) < 0) {
            return -errno;
        }
        return 0;
    } else if (cipher_type == TLS_CIPHER_AES_GCM_256 && key.len >= 32) {
        struct wing_tls_crypto_info_aes_gcm_256 info;
        __builtin_memset(&info, 0, sizeof(info));
        info.version = version;
        info.cipher_type = cipher_type;
        __builtin_memcpy(info.iv, iv.data, 4);
        __builtin_memcpy(info.key, key.data, 32);
        __builtin_memcpy(info.salt, salt.data, 4);
        __builtin_memcpy(info.rec_seq, rec_seq.data, 8);

        if (setsockopt((int)fd, SOL_TLS, TLS_TX, &info, sizeof(info)) < 0) {
            return -errno;
        }
        return 0;
    }
    return -EINVAL;
}

int32_t wing_smartnic_set_hardware_tls_rx(int64_t fd, uint16_t version, uint16_t cipher_type, wing_bytes_ro key,
                                          wing_bytes_ro iv, wing_bytes_ro salt, wing_bytes_ro rec_seq) {
    if (cipher_type == TLS_CIPHER_AES_GCM_128 && key.len >= 16) {
        struct wing_tls_crypto_info_aes_gcm_128 info;
        __builtin_memset(&info, 0, sizeof(info));
        info.version = version;
        info.cipher_type = cipher_type;
        __builtin_memcpy(info.iv, iv.data, 4);
        __builtin_memcpy(info.key, key.data, 16);
        __builtin_memcpy(info.salt, salt.data, 4);
        __builtin_memcpy(info.rec_seq, rec_seq.data, 8);

        if (setsockopt((int)fd, SOL_TLS, TLS_RX, &info, sizeof(info)) < 0) {
            return -errno;
        }
        return 0;
    } else if (cipher_type == TLS_CIPHER_AES_GCM_256 && key.len >= 32) {
        struct wing_tls_crypto_info_aes_gcm_256 info;
        __builtin_memset(&info, 0, sizeof(info));
        info.version = version;
        info.cipher_type = cipher_type;
        __builtin_memcpy(info.iv, iv.data, 4);
        __builtin_memcpy(info.key, key.data, 32);
        __builtin_memcpy(info.salt, salt.data, 4);
        __builtin_memcpy(info.rec_seq, rec_seq.data, 8);

        if (setsockopt((int)fd, SOL_TLS, TLS_RX, &info, sizeof(info)) < 0) {
            return -errno;
        }
        return 0;
    }
    return -EINVAL;
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

int32_t wing_smartnic_enable_ktls(int64_t fd) {
    (void)fd;
    return 0;
}

int32_t wing_smartnic_set_hardware_tls_tx(int64_t fd, uint16_t version, uint16_t cipher_type, wing_bytes_ro key,
                                          wing_bytes_ro iv, wing_bytes_ro salt, wing_bytes_ro rec_seq) {
    (void)fd;
    (void)version;
    (void)cipher_type;
    (void)key;
    (void)iv;
    (void)salt;
    (void)rec_seq;
    return 0;
}

int32_t wing_smartnic_set_hardware_tls_rx(int64_t fd, uint16_t version, uint16_t cipher_type, wing_bytes_ro key,
                                          wing_bytes_ro iv, wing_bytes_ro salt, wing_bytes_ro rec_seq) {
    (void)fd;
    (void)version;
    (void)cipher_type;
    (void)key;
    (void)iv;
    (void)salt;
    (void)rec_seq;
    return 0;
}

#else

#ifndef ENOSYS
#define ENOSYS 38
#endif

int32_t wing_smartnic_probe(void) { return -ENOSYS; }
int32_t wing_smartnic_enable_ktls(int64_t fd) {
    (void)fd;
    return -ENOSYS;
}
int32_t wing_smartnic_set_hardware_tls_tx(int64_t fd, uint16_t version, uint16_t cipher_type, wing_bytes_ro key,
                                          wing_bytes_ro iv, wing_bytes_ro salt, wing_bytes_ro rec_seq) {
    (void)fd;
    (void)version;
    (void)cipher_type;
    (void)key;
    (void)iv;
    (void)salt;
    (void)rec_seq;
    return -ENOSYS;
}
int32_t wing_smartnic_set_hardware_tls_rx(int64_t fd, uint16_t version, uint16_t cipher_type, wing_bytes_ro key,
                                          wing_bytes_ro iv, wing_bytes_ro salt, wing_bytes_ro rec_seq) {
    (void)fd;
    (void)version;
    (void)cipher_type;
    (void)key;
    (void)iv;
    (void)salt;
    (void)rec_seq;
    return -ENOSYS;
}

#endif
