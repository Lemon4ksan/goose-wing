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
#include <sys/mman.h>
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

#ifndef XDP_PGOFF_RX_RING
#define XDP_PGOFF_RX_RING 0ULL
#endif
#ifndef XDP_PGOFF_TX_RING
#define XDP_PGOFF_TX_RING 0x80000000ULL
#endif
#ifndef XDP_UMEM_PGOFF_FILL_RING
#define XDP_UMEM_PGOFF_FILL_RING 0x100000000ULL
#endif
#ifndef XDP_UMEM_PGOFF_COMPLETION_RING
#define XDP_UMEM_PGOFF_COMPLETION_RING 0x180000000ULL
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

struct wing_xdp_ring_offset {
    uint64_t producer;
    uint64_t consumer;
    uint64_t desc;
    uint64_t flags;
};

struct wing_xdp_mmap_offsets {
    struct wing_xdp_ring_offset rx;
    struct wing_xdp_ring_offset tx;
    struct wing_xdp_ring_offset fr;
    struct wing_xdp_ring_offset cr;
};

struct wing_xdp_desc {
    uint64_t addr;
    uint32_t len;
    uint32_t options;
};

#define WING_XSK_MAX_SOCKETS 16

typedef struct {
    void     *map_ptr;
    size_t    map_sz;
    uint32_t *producer;
    uint32_t *consumer;
    void     *descs;
    uint32_t  mask;
} wing_xsk_ring_view;

typedef struct {
    int64_t            xsk_fd;
    int32_t            mapped;
    wing_xsk_ring_view fill;
    wing_xsk_ring_view comp;
    wing_xsk_ring_view rx;
    wing_xsk_ring_view tx;
} wing_xsk_ctx;

static wing_xsk_ctx g_xsk_sockets[WING_XSK_MAX_SOCKETS];

static wing_xsk_ctx *find_xsk_ctx(int64_t xsk_fd) {
    if (xsk_fd < 0) return NULL;
    for (int i = 0; i < WING_XSK_MAX_SOCKETS; i++) {
        if (g_xsk_sockets[i].xsk_fd == xsk_fd && g_xsk_sockets[i].mapped) {
            return &g_xsk_sockets[i];
        }
    }
    return NULL;
}

static void unmap_xsk_ring(wing_xsk_ring_view *r) {
    if (r->map_ptr && r->map_ptr != MAP_FAILED) {
        munmap(r->map_ptr, r->map_sz);
    }
    __builtin_memset(r, 0, sizeof(*r));
}

static int map_one_xsk_ring(int fd, uint32_t entries, size_t elem_sz, uint64_t pgoff,
                            const struct wing_xdp_ring_offset *off, wing_xsk_ring_view *out) {
    size_t sz = (size_t)off->desc + (size_t)entries * elem_sz;
    void *ptr = mmap(NULL, sz, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_POPULATE, fd, (off_t)pgoff);
    if (ptr == MAP_FAILED) {
        return -errno;
    }
    uint8_t *base = (uint8_t *)ptr;
    out->map_ptr = ptr;
    out->map_sz = sz;
    out->producer = (uint32_t *)(base + off->producer);
    out->consumer = (uint32_t *)(base + off->consumer);
    out->descs = (void *)(base + off->desc);
    out->mask = entries - 1;
    return 0;
}

int32_t wing_af_xdp_mmap_rings(int64_t xsk_fd, uint32_t entries) {
    if (xsk_fd < 0 || entries == 0 || (entries & (entries - 1)) != 0) {
        return -EINVAL;
    }
    struct wing_xdp_mmap_offsets off;
    __builtin_memset(&off, 0, sizeof(off));
    socklen_t optlen = sizeof(off);
    if (getsockopt((int)xsk_fd, SOL_XDP, XDP_MMAP_OFFSETS, &off, &optlen) < 0) {
        return -errno;
    }
    int slot = -1;
    for (int i = 0; i < WING_XSK_MAX_SOCKETS; i++) {
        if (!g_xsk_sockets[i].mapped) {
            slot = i;
            break;
        }
    }
    if (slot < 0) return -ENOMEM;

    wing_xsk_ctx *ctx = &g_xsk_sockets[slot];
    __builtin_memset(ctx, 0, sizeof(*ctx));
    ctx->xsk_fd = xsk_fd;

    if (map_one_xsk_ring((int)xsk_fd, entries, sizeof(uint64_t), XDP_UMEM_PGOFF_FILL_RING, &off.fr, &ctx->fill) < 0 ||
        map_one_xsk_ring((int)xsk_fd, entries, sizeof(uint64_t), XDP_UMEM_PGOFF_COMPLETION_RING, &off.cr, &ctx->comp) < 0 ||
        map_one_xsk_ring((int)xsk_fd, entries, sizeof(struct wing_xdp_desc), XDP_PGOFF_RX_RING, &off.rx, &ctx->rx) < 0 ||
        map_one_xsk_ring((int)xsk_fd, entries, sizeof(struct wing_xdp_desc), XDP_PGOFF_TX_RING, &off.tx, &ctx->tx) < 0) {
        unmap_xsk_ring(&ctx->fill);
        unmap_xsk_ring(&ctx->comp);
        unmap_xsk_ring(&ctx->rx);
        unmap_xsk_ring(&ctx->tx);
        return -ENOMEM;
    }
    ctx->mapped = 1;
    return 0;
}

int32_t wing_af_xdp_fill_push(int64_t xsk_fd, uint64_t umem_offset) {
    wing_xsk_ctx *ctx = find_xsk_ctx(xsk_fd);
    if (!ctx) return -EBADF;
    uint32_t prod = *ctx->fill.producer;
    uint32_t cons = __atomic_load_n(ctx->fill.consumer, __ATOMIC_ACQUIRE);
    if ((prod - cons) > ctx->fill.mask) return -EBUSY;
    uint64_t *ring = (uint64_t *)ctx->fill.descs;
    ring[prod & ctx->fill.mask] = umem_offset;
    __atomic_store_n(ctx->fill.producer, prod + 1, __ATOMIC_RELEASE);
    return 0;
}

int32_t wing_af_xdp_tx_submit(int64_t xsk_fd, uint64_t addr, uint32_t len, uint32_t options) {
    wing_xsk_ctx *ctx = find_xsk_ctx(xsk_fd);
    if (!ctx) return -EBADF;
    uint32_t prod = *ctx->tx.producer;
    uint32_t cons = __atomic_load_n(ctx->tx.consumer, __ATOMIC_ACQUIRE);
    if ((prod - cons) > ctx->tx.mask) return -EBUSY;
    struct wing_xdp_desc *ring = (struct wing_xdp_desc *)ctx->tx.descs;
    uint32_t idx = prod & ctx->tx.mask;
    ring[idx].addr = addr;
    ring[idx].len = len;
    ring[idx].options = options;
    __atomic_store_n(ctx->tx.producer, prod + 1, __ATOMIC_RELEASE);
    (void)sendto((int)xsk_fd, NULL, 0, MSG_DONTWAIT, NULL, 0);
    return 0;
}

int32_t wing_af_xdp_rx_poll(int64_t xsk_fd, uint64_t *addr_out, uint32_t *len_out, uint32_t *options_out) {
    wing_xsk_ctx *ctx = find_xsk_ctx(xsk_fd);
    if (!ctx || !addr_out || !len_out || !options_out) return 0;
    uint32_t cons = *ctx->rx.consumer;
    uint32_t prod = __atomic_load_n(ctx->rx.producer, __ATOMIC_ACQUIRE);
    if (cons == prod) return 0;
    struct wing_xdp_desc *ring = (struct wing_xdp_desc *)ctx->rx.descs;
    uint32_t idx = cons & ctx->rx.mask;
    *addr_out = ring[idx].addr;
    *len_out = ring[idx].len;
    *options_out = ring[idx].options;
    __atomic_store_n(ctx->rx.consumer, cons + 1, __ATOMIC_RELEASE);
    return 1;
}

int32_t wing_af_xdp_complete_pop(int64_t xsk_fd, uint64_t *addr_out) {
    wing_xsk_ctx *ctx = find_xsk_ctx(xsk_fd);
    if (!ctx || !addr_out) return 0;
    uint32_t cons = *ctx->comp.consumer;
    uint32_t prod = __atomic_load_n(ctx->comp.producer, __ATOMIC_ACQUIRE);
    if (cons == prod) return 0;
    uint64_t *ring = (uint64_t *)ctx->comp.descs;
    *addr_out = ring[cons & ctx->comp.mask];
    __atomic_store_n(ctx->comp.consumer, cons + 1, __ATOMIC_RELEASE);
    return 1;
}

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
        wing_xsk_ctx *ctx = find_xsk_ctx(xsk_fd);
        if (ctx) {
            unmap_xsk_ring(&ctx->fill);
            unmap_xsk_ring(&ctx->comp);
            unmap_xsk_ring(&ctx->rx);
            unmap_xsk_ring(&ctx->tx);
            ctx->mapped = 0;
            ctx->xsk_fd = -1;
        }
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
int32_t wing_af_xdp_mmap_rings(int64_t xsk_fd, uint32_t entries) {
    (void)xsk_fd;
    (void)entries;
    return -ENOSYS;
}
int32_t wing_af_xdp_fill_push(int64_t xsk_fd, uint64_t umem_offset) {
    (void)xsk_fd;
    (void)umem_offset;
    return -ENOSYS;
}
int32_t wing_af_xdp_tx_submit(int64_t xsk_fd, uint64_t addr, uint32_t len, uint32_t options) {
    (void)xsk_fd;
    (void)addr;
    (void)len;
    (void)options;
    return -ENOSYS;
}
int32_t wing_af_xdp_rx_poll(int64_t xsk_fd, uint64_t *addr_out, uint32_t *len_out, uint32_t *options_out) {
    (void)xsk_fd;
    (void)addr_out;
    (void)len_out;
    (void)options_out;
    return 0;
}
int32_t wing_af_xdp_complete_pop(int64_t xsk_fd, uint64_t *addr_out) {
    (void)xsk_fd;
    (void)addr_out;
    return 0;
}
void wing_af_xdp_close(int64_t xsk_fd) { (void)xsk_fd; }

#endif
