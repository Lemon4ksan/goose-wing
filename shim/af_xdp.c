// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Layer 4 Linux AF_XDP (XSK) Kernel-Bypass C Shim.
// Enables direct zero-copy packet exchange between userspace UMEM and NIC hardware rings
// without passing through the Linux network stack (sk_buff, iptables, qdisc).
#include <stdint.h>
#include <stddef.h>

#if defined(__linux__)
#include <unistd.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <errno.h>

#ifndef AF_XDP
#define AF_XDP 44
#endif

#ifndef SOL_XDP
#define SOL_XDP 283
#endif

#ifndef XDP_MMAP_OFFSETS
#define XDP_MMAP_OFFSETS 1
#endif
#ifndef XDP_RX_RING
#define XDP_RX_RING 2
#endif
#ifndef XDP_TX_RING
#define XDP_TX_RING 3
#endif
#ifndef XDP_UMEM_REG
#define XDP_UMEM_REG 4
#endif
#ifndef XDP_UMEM_FILL_RING
#define XDP_UMEM_FILL_RING 5
#endif
#ifndef XDP_UMEM_COMPLETION_RING
#define XDP_UMEM_COMPLETION_RING 6
#endif

#ifndef XDP_SHARED_UMEM
#define XDP_SHARED_UMEM (1 << 0)
#endif
#ifndef XDP_COPY
#define XDP_COPY (1 << 1)
#endif
#ifndef XDP_ZEROCOPY
#define XDP_ZEROCOPY (1 << 2)
#endif

struct wing_xdp_umem_reg {
    uint64_t addr; /* Start of UMEM memory pool */
    uint64_t len;  /* Length of UMEM memory pool */
    uint32_t chunk_size;
    uint32_t headroom;
    uint32_t flags;
};

struct wing_sockaddr_xdp {
    uint16_t sxdp_family;
    uint16_t sxdp_flags;
    uint32_t sxdp_ifindex;
    uint32_t sxdp_queue_id;
    uint32_t sxdp_shared_umem_fd;
};

int32_t wing_af_xdp_probe(void) {
    int s = socket(AF_XDP, SOCK_RAW, 0);
    if (s < 0) {
        return -errno;
    }
    close(s);
    return 0;
}

int64_t wing_af_xdp_create_socket(void) {
    int s = socket(AF_XDP, SOCK_RAW, 0);
    if (s < 0) {
        return -errno;
    }
    return (int64_t)s;
}

int32_t wing_af_xdp_register_umem(int64_t xsk_fd, uint64_t addr, uint64_t len, uint32_t chunk_size, uint32_t headroom) {
    struct wing_xdp_umem_reg mr;
    __builtin_memset(&mr, 0, sizeof(mr));
    mr.addr = addr;
    mr.len = len;
    mr.chunk_size = chunk_size;
    mr.headroom = headroom;

    if (setsockopt((int)xsk_fd, SOL_XDP, XDP_UMEM_REG, &mr, sizeof(mr)) < 0) {
        return -errno;
    }
    return 0;
}

int32_t wing_af_xdp_set_ring_size(int64_t xsk_fd, int32_t ring_opt, uint32_t entries) {
    if (setsockopt((int)xsk_fd, SOL_XDP, ring_opt, &entries, sizeof(entries)) < 0) {
        return -errno;
    }
    return 0;
}

int32_t wing_af_xdp_bind(int64_t xsk_fd, uint32_t ifindex, uint32_t queue_id, uint32_t flags) {
    struct wing_sockaddr_xdp sxdp;
    __builtin_memset(&sxdp, 0, sizeof(sxdp));
    sxdp.sxdp_family = AF_XDP;
    sxdp.sxdp_flags = (uint16_t)flags;
    sxdp.sxdp_ifindex = ifindex;
    sxdp.sxdp_queue_id = queue_id;

    if (bind((int)xsk_fd, (struct sockaddr *)&sxdp, sizeof(sxdp)) < 0) {
        return -errno;
    }
    return 0;
}

void wing_af_xdp_close(int64_t xsk_fd) {
    if (xsk_fd >= 0) {
        close((int)xsk_fd);
    }
}

#else

#ifndef ENOSYS
#define ENOSYS 38
#endif

int32_t wing_af_xdp_probe(void) { return -ENOSYS; }
int64_t wing_af_xdp_create_socket(void) { return -ENOSYS; }
int32_t wing_af_xdp_register_umem(int64_t xsk_fd, uint64_t addr, uint64_t len, uint32_t chunk_size, uint32_t headroom) {
    (void)xsk_fd;
    (void)addr;
    (void)len;
    (void)chunk_size;
    (void)headroom;
    return -ENOSYS;
}
int32_t wing_af_xdp_set_ring_size(int64_t xsk_fd, int32_t ring_opt, uint32_t entries) {
    (void)xsk_fd;
    (void)ring_opt;
    (void)entries;
    return -ENOSYS;
}
int32_t wing_af_xdp_bind(int64_t xsk_fd, uint32_t ifindex, uint32_t queue_id, uint32_t flags) {
    (void)xsk_fd;
    (void)ifindex;
    (void)queue_id;
    (void)flags;
    return -ENOSYS;
}
void wing_af_xdp_close(int64_t xsk_fd) { (void)xsk_fd; }

#endif
