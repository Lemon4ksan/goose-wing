// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Layer 4 Linux AF_XDP (XSK) Kernel-Bypass C Shim.
// Enables direct zero-copy packet exchange between userspace UMEM and NIC hardware rings
// without passing through the Linux network stack, plus a cross-platform UMEM loopback ring.
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

#ifndef EINVAL
#define EINVAL 22
#endif
#ifndef EBADF
#define EBADF 9
#endif
#ifndef EBUSY
#define EBUSY 16
#endif
#ifndef ENOMEM
#define ENOMEM 12
#endif
#ifndef ENOSYS
#define ENOSYS 38
#endif

typedef struct {
    const void *data;
    int64_t len;
} wing_xdp_ro_slice;

typedef struct {
    void *data;
    int64_t len;
} wing_xdp_rw_slice;

struct wing_xdp_desc {
    uint64_t addr;
    uint32_t len;
    uint32_t options;
};

#define WING_XSK_MAX_SOCKETS 16
#define WING_XSK_LOOPBACK_RING_CAP 64
#define WING_XSK_LOOPBACK_FD_BASE 0x40000000LL
#define WING_XSK_MAX_FRAME_BYTES 2048U

typedef struct {
    int32_t active;
    uint8_t *umem_base;
    uint64_t umem_len;
    uint32_t chunk_size;
    uint64_t fill_ring[WING_XSK_LOOPBACK_RING_CAP];
    uint32_t fill_head;
    uint32_t fill_tail;
    uint64_t comp_ring[WING_XSK_LOOPBACK_RING_CAP];
    uint32_t comp_head;
    uint32_t comp_tail;
    struct wing_xdp_desc rx_ring[WING_XSK_LOOPBACK_RING_CAP];
    uint32_t rx_head;
    uint32_t rx_tail;
    struct wing_xdp_desc tx_ring[WING_XSK_LOOPBACK_RING_CAP];
    uint32_t tx_head;
    uint32_t tx_tail;
} wing_xsk_loopback_slot;

static wing_xsk_loopback_slot g_xsk_loopback[WING_XSK_MAX_SOCKETS];

static wing_xsk_loopback_slot *find_loopback_slot(int64_t xsk_fd) {
    if (xsk_fd < WING_XSK_LOOPBACK_FD_BASE) {
        return NULL;
    }
    int64_t idx = xsk_fd - WING_XSK_LOOPBACK_FD_BASE;
    if (idx < 0 || idx >= WING_XSK_MAX_SOCKETS) {
        return NULL;
    }
    if (!g_xsk_loopback[idx].active) {
        return NULL;
    }
    return &g_xsk_loopback[idx];
}

static int validate_umem_span(const uint8_t *base, uint64_t umem_len, uint32_t chunk_size,
                              uint64_t addr, uint64_t span_len) {
    if (!base || umem_len == 0) {
        return 0;
    }
    uint64_t max_frame = WING_XSK_MAX_FRAME_BYTES;
    if (chunk_size > 0 && chunk_size < max_frame) {
        max_frame = chunk_size;
    }
    if (span_len > max_frame || addr > umem_len || span_len > (umem_len - addr)) {
        return 0;
    }
    return 1;
}

int64_t wing_af_xdp_open_loopback(uint32_t num_frames, uint32_t frame_size,
                                  uint64_t *umem_addr_out, uint64_t *umem_len_out) {
    if (num_frames == 0 || num_frames > 4096 || frame_size == 0 || frame_size > 4096) {
        return -EINVAL;
    }
    int slot_idx = -1;
    for (int i = 0; i < WING_XSK_MAX_SOCKETS; i++) {
        if (!g_xsk_loopback[i].active) {
            slot_idx = i;
            break;
        }
    }
    if (slot_idx < 0) {
        return -ENOMEM;
    }
    size_t total_bytes = (size_t)num_frames * (size_t)frame_size;
    uint8_t *mem = (uint8_t *)calloc(1, total_bytes);
    if (!mem) {
        return -ENOMEM;
    }
    wing_xsk_loopback_slot *s = &g_xsk_loopback[slot_idx];
    memset(s, 0, sizeof(*s));
    s->active = 1;
    s->umem_base = mem;
    s->umem_len = (uint64_t)total_bytes;
    s->chunk_size = frame_size;
    if (umem_addr_out) {
        *umem_addr_out = (uint64_t)(uintptr_t)mem;
    }
    if (umem_len_out) {
        *umem_len_out = (uint64_t)total_bytes;
    }
    return WING_XSK_LOOPBACK_FD_BASE + (int64_t)slot_idx;
}

int32_t wing_af_xdp_inject_loopback_rx(int64_t xsk_fd, uint64_t addr, uint32_t frame_len) {
    wing_xsk_loopback_slot *s = find_loopback_slot(xsk_fd);
    if (!s || frame_len == 0) {
        return -EBADF;
    }
    if (!validate_umem_span(s->umem_base, s->umem_len, s->chunk_size, addr, (uint64_t)frame_len)) {
        return -EINVAL;
    }
    if ((s->rx_tail - s->rx_head) >= WING_XSK_LOOPBACK_RING_CAP) {
        return -EBUSY;
    }
    uint32_t idx = s->rx_tail % WING_XSK_LOOPBACK_RING_CAP;
    s->rx_ring[idx].addr = addr;
    s->rx_ring[idx].len = frame_len;
    s->rx_ring[idx].options = 0;
    s->rx_tail++;
    return 0;
}

static int32_t loopback_fill_push(wing_xsk_loopback_slot *s, uint64_t umem_offset) {
    if (!validate_umem_span(s->umem_base, s->umem_len, s->chunk_size, umem_offset, 0)) {
        return -EINVAL;
    }
    if ((s->fill_tail - s->fill_head) >= WING_XSK_LOOPBACK_RING_CAP) {
        return -EBUSY;
    }
    s->fill_ring[s->fill_tail % WING_XSK_LOOPBACK_RING_CAP] = umem_offset;
    s->fill_tail++;
    return 0;
}

static int32_t loopback_tx_submit(wing_xsk_loopback_slot *s, uint64_t addr, uint32_t len, uint32_t options) {
    if (len == 0 || !validate_umem_span(s->umem_base, s->umem_len, s->chunk_size, addr, (uint64_t)len)) {
        return -EINVAL;
    }
    if ((s->tx_tail - s->tx_head) >= WING_XSK_LOOPBACK_RING_CAP) {
        return -EBUSY;
    }
    uint32_t idx = s->tx_tail % WING_XSK_LOOPBACK_RING_CAP;
    s->tx_ring[idx].addr = addr;
    s->tx_ring[idx].len = len;
    s->tx_ring[idx].options = options;
    s->tx_tail++;
    if ((s->comp_tail - s->comp_head) < WING_XSK_LOOPBACK_RING_CAP) {
        s->comp_ring[s->comp_tail % WING_XSK_LOOPBACK_RING_CAP] = addr;
        s->comp_tail++;
    }
    return 0;
}

static int32_t loopback_rx_poll(wing_xsk_loopback_slot *s, uint64_t *addr_out, uint32_t *len_out,
                                uint32_t *options_out) {
    if (!addr_out || !len_out || !options_out || s->rx_head == s->rx_tail) {
        return 0;
    }
    uint32_t idx = s->rx_head % WING_XSK_LOOPBACK_RING_CAP;
    *addr_out = s->rx_ring[idx].addr;
    *len_out = s->rx_ring[idx].len;
    *options_out = s->rx_ring[idx].options;
    s->rx_head++;
    return 1;
}

static int32_t loopback_complete_pop(wing_xsk_loopback_slot *s, uint64_t *addr_out) {
    if (!addr_out || s->comp_head == s->comp_tail) {
        return 0;
    }
    *addr_out = s->comp_ring[s->comp_head % WING_XSK_LOOPBACK_RING_CAP];
    s->comp_head++;
    return 1;
}

static void loopback_close(wing_xsk_loopback_slot *s) {
    if (s->umem_base) {
        free(s->umem_base);
    }
    memset(s, 0, sizeof(*s));
}

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
    uint64_t addr;
    uint64_t len;
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

typedef struct {
    void *map_ptr;
    size_t map_sz;
    uint32_t *producer;
    uint32_t *consumer;
    void *descs;
    uint32_t mask;
} wing_xsk_ring_view;

typedef struct {
    int64_t xsk_fd;
    int32_t mapped;
    uint8_t *umem_base;
    uint64_t umem_len;
    uint32_t chunk_size;
    wing_xsk_ring_view fill;
    wing_xsk_ring_view comp;
    wing_xsk_ring_view rx;
    wing_xsk_ring_view tx;
} wing_xsk_ctx;

static wing_xsk_ctx g_xsk_sockets[WING_XSK_MAX_SOCKETS];

static wing_xsk_ctx *find_xsk_ctx(int64_t xsk_fd) {
    if (xsk_fd < 0 || xsk_fd >= WING_XSK_LOOPBACK_FD_BASE) return NULL;
    for (int i = 0; i < WING_XSK_MAX_SOCKETS; i++) {
        if (g_xsk_sockets[i].xsk_fd == xsk_fd && (g_xsk_sockets[i].mapped || g_xsk_sockets[i].umem_base != NULL)) {
            return &g_xsk_sockets[i];
        }
    }
    return NULL;
}

static wing_xsk_ctx *ensure_xsk_ctx(int64_t xsk_fd) {
    wing_xsk_ctx *existing = find_xsk_ctx(xsk_fd);
    if (existing) return existing;
    for (int i = 0; i < WING_XSK_MAX_SOCKETS; i++) {
        if (!g_xsk_sockets[i].mapped && g_xsk_sockets[i].umem_base == NULL) {
            memset(&g_xsk_sockets[i], 0, sizeof(g_xsk_sockets[i]));
            g_xsk_sockets[i].xsk_fd = xsk_fd;
            return &g_xsk_sockets[i];
        }
    }
    return NULL;
}

static void unmap_xsk_ring(wing_xsk_ring_view *r) {
    if (r->map_ptr && r->map_ptr != MAP_FAILED) {
        munmap(r->map_ptr, r->map_sz);
    }
    memset(r, 0, sizeof(*r));
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
    memset(&off, 0, sizeof(off));
    socklen_t optlen = sizeof(off);
    if (getsockopt((int)xsk_fd, SOL_XDP, XDP_MMAP_OFFSETS, &off, &optlen) < 0) {
        return -errno;
    }
    wing_xsk_ctx *ctx = ensure_xsk_ctx(xsk_fd);
    if (!ctx) return -ENOMEM;

    if (map_one_xsk_ring((int)xsk_fd, entries, sizeof(uint64_t), XDP_UMEM_PGOFF_FILL_RING, &off.fr, &ctx->fill) < 0 ||
        map_one_xsk_ring((int)xsk_fd, entries, sizeof(uint64_t), XDP_UMEM_PGOFF_COMPLETION_RING, &off.cr, &ctx->comp) <
            0 ||
        map_one_xsk_ring((int)xsk_fd, entries, sizeof(struct wing_xdp_desc), XDP_PGOFF_RX_RING, &off.rx, &ctx->rx) <
            0 ||
        map_one_xsk_ring((int)xsk_fd, entries, sizeof(struct wing_xdp_desc), XDP_PGOFF_TX_RING, &off.tx, &ctx->tx) <
            0) {
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
    wing_xsk_loopback_slot *lb = find_loopback_slot(xsk_fd);
    if (lb) return loopback_fill_push(lb, umem_offset);
    wing_xsk_ctx *ctx = find_xsk_ctx(xsk_fd);
    if (!ctx || !ctx->mapped) return -EBADF;
    uint32_t prod = *ctx->fill.producer;
    uint32_t cons = __atomic_load_n(ctx->fill.consumer, __ATOMIC_ACQUIRE);
    if ((prod - cons) > ctx->fill.mask) return -EBUSY;
    uint64_t *ring = (uint64_t *)ctx->fill.descs;
    ring[prod & ctx->fill.mask] = umem_offset;
    __atomic_store_n(ctx->fill.producer, prod + 1, __ATOMIC_RELEASE);
    return 0;
}

int32_t wing_af_xdp_tx_submit(int64_t xsk_fd, uint64_t addr, uint32_t len, uint32_t options) {
    wing_xsk_loopback_slot *lb = find_loopback_slot(xsk_fd);
    if (lb) return loopback_tx_submit(lb, addr, len, options);
    wing_xsk_ctx *ctx = find_xsk_ctx(xsk_fd);
    if (!ctx || !ctx->mapped) return -EBADF;
    if (ctx->umem_base && !validate_umem_span(ctx->umem_base, ctx->umem_len, ctx->chunk_size, addr, (uint64_t)len)) {
        return -EINVAL;
    }
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
    wing_xsk_loopback_slot *lb = find_loopback_slot(xsk_fd);
    if (lb) return loopback_rx_poll(lb, addr_out, len_out, options_out);
    wing_xsk_ctx *ctx = find_xsk_ctx(xsk_fd);
    if (!ctx || !ctx->mapped || !addr_out || !len_out || !options_out) return 0;
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
    wing_xsk_loopback_slot *lb = find_loopback_slot(xsk_fd);
    if (lb) return loopback_complete_pop(lb, addr_out);
    wing_xsk_ctx *ctx = find_xsk_ctx(xsk_fd);
    if (!ctx || !ctx->mapped || !addr_out) return 0;
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
    memset(&mr, 0, sizeof(mr));
    mr.addr = addr;
    mr.len = len;
    mr.chunk_size = chunk_size;
    mr.headroom = headroom;

    if (setsockopt((int)xsk_fd, SOL_XDP, XDP_UMEM_REG, &mr, sizeof(mr)) < 0) {
        return -errno;
    }
    wing_xsk_ctx *ctx = ensure_xsk_ctx(xsk_fd);
    if (ctx) {
        ctx->umem_base = (uint8_t *)(uintptr_t)addr;
        ctx->umem_len = len;
        ctx->chunk_size = chunk_size;
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
    memset(&sxdp, 0, sizeof(sxdp));
    sxdp.sxdp_family = AF_XDP;
    sxdp.sxdp_flags = (uint16_t)flags;
    sxdp.sxdp_ifindex = ifindex;
    sxdp.sxdp_queue_id = queue_id;

    if (bind((int)xsk_fd, (struct sockaddr *)&sxdp, sizeof(sxdp)) < 0) {
        return -errno;
    }
    return 0;
}

int32_t wing_af_xdp_umem_write(int64_t xsk_fd, uint64_t addr, wing_xdp_ro_slice src) {
    if (!src.data || src.len < 0) return -EINVAL;
    uint8_t *base = NULL;
    uint64_t umem_len = 0;
    uint32_t chunk_size = 0;
    wing_xsk_loopback_slot *lb = find_loopback_slot(xsk_fd);
    if (lb) {
        base = lb->umem_base;
        umem_len = lb->umem_len;
        chunk_size = lb->chunk_size;
    } else {
        wing_xsk_ctx *ctx = find_xsk_ctx(xsk_fd);
        if (ctx) {
            base = ctx->umem_base;
            umem_len = ctx->umem_len;
            chunk_size = ctx->chunk_size;
        }
    }
    if (!validate_umem_span(base, umem_len, chunk_size, addr, (uint64_t)src.len)) {
        return -EINVAL;
    }
    if (src.len > 0) {
        memcpy(base + addr, src.data, (size_t)src.len);
    }
    return 0;
}

int32_t wing_af_xdp_umem_read(int64_t xsk_fd, uint64_t addr, uint32_t frame_len, wing_xdp_rw_slice dst) {
    if (!dst.data || dst.len < (int64_t)frame_len) return -EINVAL;
    uint8_t *base = NULL;
    uint64_t umem_len = 0;
    uint32_t chunk_size = 0;
    wing_xsk_loopback_slot *lb = find_loopback_slot(xsk_fd);
    if (lb) {
        base = lb->umem_base;
        umem_len = lb->umem_len;
        chunk_size = lb->chunk_size;
    } else {
        wing_xsk_ctx *ctx = find_xsk_ctx(xsk_fd);
        if (ctx) {
            base = ctx->umem_base;
            umem_len = ctx->umem_len;
            chunk_size = ctx->chunk_size;
        }
    }
    if (!validate_umem_span(base, umem_len, chunk_size, addr, (uint64_t)frame_len)) {
        return -EINVAL;
    }
    if (frame_len > 0) {
        memcpy(dst.data, base + addr, (size_t)frame_len);
    }
    return (int32_t)frame_len;
}

void wing_af_xdp_close(int64_t xsk_fd) {
    wing_xsk_loopback_slot *lb = find_loopback_slot(xsk_fd);
    if (lb) {
        loopback_close(lb);
        return;
    }
    if (xsk_fd >= 0) {
        wing_xsk_ctx *ctx = find_xsk_ctx(xsk_fd);
        if (ctx) {
            unmap_xsk_ring(&ctx->fill);
            unmap_xsk_ring(&ctx->comp);
            unmap_xsk_ring(&ctx->rx);
            unmap_xsk_ring(&ctx->tx);
            memset(ctx, 0, sizeof(*ctx));
            ctx->xsk_fd = -1;
        }
        close((int)xsk_fd);
    }
}

#else

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
    wing_xsk_loopback_slot *lb = find_loopback_slot(xsk_fd);
    if (lb) return loopback_fill_push(lb, umem_offset);
    return -ENOSYS;
}

int32_t wing_af_xdp_tx_submit(int64_t xsk_fd, uint64_t addr, uint32_t len, uint32_t options) {
    wing_xsk_loopback_slot *lb = find_loopback_slot(xsk_fd);
    if (lb) return loopback_tx_submit(lb, addr, len, options);
    return -ENOSYS;
}

int32_t wing_af_xdp_rx_poll(int64_t xsk_fd, uint64_t *addr_out, uint32_t *len_out, uint32_t *options_out) {
    wing_xsk_loopback_slot *lb = find_loopback_slot(xsk_fd);
    if (lb) return loopback_rx_poll(lb, addr_out, len_out, options_out);
    return 0;
}

int32_t wing_af_xdp_complete_pop(int64_t xsk_fd, uint64_t *addr_out) {
    wing_xsk_loopback_slot *lb = find_loopback_slot(xsk_fd);
    if (lb) return loopback_complete_pop(lb, addr_out);
    return 0;
}

int32_t wing_af_xdp_umem_write(int64_t xsk_fd, uint64_t addr, wing_xdp_ro_slice src) {
    if (!src.data || src.len < 0) return -EINVAL;
    wing_xsk_loopback_slot *lb = find_loopback_slot(xsk_fd);
    if (!lb) return -EBADF;
    if (!validate_umem_span(lb->umem_base, lb->umem_len, lb->chunk_size, addr, (uint64_t)src.len)) {
        return -EINVAL;
    }
    if (src.len > 0) {
        memcpy(lb->umem_base + addr, src.data, (size_t)src.len);
    }
    return 0;
}

int32_t wing_af_xdp_umem_read(int64_t xsk_fd, uint64_t addr, uint32_t frame_len, wing_xdp_rw_slice dst) {
    if (!dst.data || dst.len < (int64_t)frame_len) return -EINVAL;
    wing_xsk_loopback_slot *lb = find_loopback_slot(xsk_fd);
    if (!lb) return -EBADF;
    if (!validate_umem_span(lb->umem_base, lb->umem_len, lb->chunk_size, addr, (uint64_t)frame_len)) {
        return -EINVAL;
    }
    if (frame_len > 0) {
        memcpy(dst.data, lb->umem_base + addr, (size_t)frame_len);
    }
    return (int32_t)frame_len;
}

void wing_af_xdp_close(int64_t xsk_fd) {
    wing_xsk_loopback_slot *lb = find_loopback_slot(xsk_fd);
    if (lb) {
        loopback_close(lb);
    }
}

#endif
