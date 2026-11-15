// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Layer 4 Linux io_uring Kernel-Bypass C Shim.
// Executes direct Linux kernel syscalls (__NR_io_uring_setup, __NR_io_uring_enter)
// and mmaps SQ/CQ rings, SQE arrays, and provided buffer rings without external liburing dependencies.

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <stdint.h>
#include <stddef.h>

typedef struct {
    const void *data;
    int64_t len;
} wing_iovecs_ro;

uint64_t wing_uring_slice_addr(wing_iovecs_ro buf) {
    return (uint64_t)(uintptr_t)buf.data;
}

typedef struct {
    uint8_t opcode;
    uint8_t flags;
    uint16_t ioprio;
    int32_t fd;
    uint64_t off;
    uint64_t addr;
    uint32_t len;
    uint32_t op_flags;
    uint64_t user_data;
    uint16_t buf_index;
    uint16_t _pad[3];
} WING_URING_SQE;

_Static_assert(sizeof(WING_URING_SQE) == 48, "WING_URING_SQE must match Goose UringSqe (48B)");

typedef struct {
    uint64_t user_data;
    int32_t res;
    uint32_t flags;
} WING_URING_CQE;

_Static_assert(sizeof(WING_URING_CQE) == 16, "WING_URING_CQE must match Goose UringCqe (16B)");

typedef struct {
    const WING_URING_SQE *data;
    int64_t len;
} wing_sqes_ro;

typedef struct {
    WING_URING_CQE *data;
    int64_t len;
} wing_cqes_rw;

typedef struct {
    uint8_t *data;
    int64_t len;
} wing_uring_bytes_rw;

#if defined(__linux__)
#include <unistd.h>
#include <sys/syscall.h>
#include <sys/mman.h>
#include <linux/io_uring.h>
#include <errno.h>

#ifndef __NR_io_uring_setup
#define __NR_io_uring_setup 425
#endif
#ifndef __NR_io_uring_enter
#define __NR_io_uring_enter 426
#endif
#ifndef __NR_io_uring_register
#define __NR_io_uring_register 427
#endif

#ifndef IORING_OFF_SQ_RING
#define IORING_OFF_SQ_RING 0ULL
#endif
#ifndef IORING_OFF_CQ_RING
#define IORING_OFF_CQ_RING 0x8000000ULL
#endif
#ifndef IORING_OFF_SQES
#define IORING_OFF_SQES 0x10000000ULL
#endif
#ifndef IORING_FEAT_SINGLE_MMAP
#define IORING_FEAT_SINGLE_MMAP (1U << 0)
#endif
#ifndef IORING_ENTER_GETEVENTS
#define IORING_ENTER_GETEVENTS (1U << 0)
#endif
#ifndef IORING_OP_TIMEOUT
#define IORING_OP_TIMEOUT 11
#endif
#ifndef IORING_REGISTER_BUFFERS
#define IORING_REGISTER_BUFFERS 0
#endif
#ifndef IORING_UNREGISTER_BUFFERS
#define IORING_UNREGISTER_BUFFERS 1
#endif
#ifndef IORING_REGISTER_FILES
#define IORING_REGISTER_FILES 2
#endif
#ifndef IORING_REGISTER_PBUF_RING
#define IORING_REGISTER_PBUF_RING 22
#endif
#ifndef IORING_UNREGISTER_PBUF_RING
#define IORING_UNREGISTER_PBUF_RING 23
#endif
#ifndef IORING_FEAT_FAST_POLL
#define IORING_FEAT_FAST_POLL (1U << 5)
#endif
#ifndef IORING_ACCEPT_MULTISHOT
#define IORING_ACCEPT_MULTISHOT (1U << 0)
#endif

#define WING_URING_MAX_RINGS 16
#define WING_URING_MAX_PBUF_RINGS 16
#define WING_URING_TIMEOUT_SENTINEL 0xFFFFFFFFFFFFFFFFULL

typedef struct {
    int64_t tv_sec;
    long long tv_nsec;
} wing_kernel_timespec;

typedef struct {
    int64_t ring_fd;
    void *sq_ring_ptr;
    void *cq_ring_ptr;
    struct io_uring_sqe *sqes_ptr;
    size_t sq_ring_sz;
    size_t cq_ring_sz;
    size_t sqes_sz;
    int32_t single_mmap;
    uint32_t *sq_head;
    uint32_t *sq_tail;
    uint32_t *sq_ring_mask;
    uint32_t *sq_array;
    uint32_t *cq_head;
    uint32_t *cq_tail;
    uint32_t *cq_ring_mask;
    struct io_uring_cqe *cqes;
    wing_kernel_timespec timeout_ts;
} wing_uring_mmap_ctx;

typedef struct {
    uint64_t addr;
    uint32_t len;
    uint16_t bid;
    uint16_t resv;
} wing_pbuf_desc;

typedef struct {
    union {
        struct {
            uint64_t resv1;
            uint32_t resv2;
            uint16_t resv3;
            uint16_t tail;
        };
        wing_pbuf_desc bufs[1];
    };
} wing_pbuf_ring_hdr;

typedef struct {
    int32_t active;
    int64_t ring_fd;
    uint16_t bgid;
    uint32_t entries;
    uint32_t buf_size;
    wing_pbuf_ring_hdr *ring_ptr;
    size_t ring_map_sz;
    uint8_t *slab_ptr;
    size_t slab_map_sz;
} wing_pbuf_slot;

struct wing_uring_buf_reg {
    uint64_t ring_addr;
    uint32_t ring_entries;
    uint16_t bgid;
    uint16_t pad;
    uint64_t resv[3];
};

static wing_uring_mmap_ctx g_uring_rings[WING_URING_MAX_RINGS];
static wing_pbuf_slot g_pbuf_rings[WING_URING_MAX_PBUF_RINGS];

static wing_uring_mmap_ctx *find_uring_ctx(int64_t ring_fd) {
    if (ring_fd < 0) {
        return NULL;
    }
    for (int i = 0; i < WING_URING_MAX_RINGS; i++) {
        if (g_uring_rings[i].ring_fd == ring_fd && g_uring_rings[i].sqes_ptr != NULL) {
            return &g_uring_rings[i];
        }
    }
    return NULL;
}

static void unmap_uring_ctx(wing_uring_mmap_ctx *ctx) {
    if (!ctx) return;
    if (ctx->sqes_ptr && ctx->sqes_ptr != MAP_FAILED) {
        munmap(ctx->sqes_ptr, ctx->sqes_sz);
    }
    if (!ctx->single_mmap && ctx->cq_ring_ptr && ctx->cq_ring_ptr != MAP_FAILED) {
        munmap(ctx->cq_ring_ptr, ctx->cq_ring_sz);
    }
    if (ctx->sq_ring_ptr && ctx->sq_ring_ptr != MAP_FAILED) {
        munmap(ctx->sq_ring_ptr, ctx->sq_ring_sz);
    }
    __builtin_memset(ctx, 0, sizeof(*ctx));
    ctx->ring_fd = -1;
}

int32_t wing_uring_probe(void) {
    struct io_uring_params params;
    __builtin_memset(&params, 0, sizeof(params));
    long fd = syscall(__NR_io_uring_setup, 1, &params);
    if (fd < 0) {
        return -errno;
    }
    close((int)fd);
    return 0;
}

int64_t wing_uring_create(uint32_t entries, uint32_t flags) {
    struct io_uring_params params;
    __builtin_memset(&params, 0, sizeof(params));
    params.flags = flags;
    long fd = syscall(__NR_io_uring_setup, entries, &params);
    if (fd < 0) {
        return -errno;
    }

    int slot = -1;
    for (int i = 0; i < WING_URING_MAX_RINGS; i++) {
        if (g_uring_rings[i].sqes_ptr == NULL) {
            slot = i;
            break;
        }
    }
    if (slot >= 0) {
        wing_uring_mmap_ctx *ctx = &g_uring_rings[slot];
        __builtin_memset(ctx, 0, sizeof(*ctx));
        ctx->ring_fd = (int64_t)fd;
        size_t sring_sz = params.sq_off.array + params.sq_entries * sizeof(uint32_t);
        size_t cring_sz = params.cq_off.cqes + params.cq_entries * sizeof(struct io_uring_cqe);
        if (params.features & IORING_FEAT_SINGLE_MMAP) {
            if (cring_sz > sring_sz) sring_sz = cring_sz;
            cring_sz = sring_sz;
            ctx->single_mmap = 1;
        }
        ctx->sq_ring_sz = sring_sz;
        ctx->cq_ring_sz = cring_sz;
        ctx->sqes_sz = params.sq_entries * sizeof(struct io_uring_sqe);

        ctx->sq_ring_ptr =
            mmap(NULL, sring_sz, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_POPULATE, (int)fd, IORING_OFF_SQ_RING);
        if (ctx->sq_ring_ptr != MAP_FAILED) {
            ctx->cq_ring_ptr = ctx->single_mmap ? ctx->sq_ring_ptr
                                                : mmap(NULL, cring_sz, PROT_READ | PROT_WRITE,
                                                       MAP_SHARED | MAP_POPULATE, (int)fd, IORING_OFF_CQ_RING);
            ctx->sqes_ptr = (struct io_uring_sqe *)mmap(NULL, ctx->sqes_sz, PROT_READ | PROT_WRITE,
                                                        MAP_SHARED | MAP_POPULATE, (int)fd, IORING_OFF_SQES);
            if (ctx->cq_ring_ptr != MAP_FAILED && ctx->sqes_ptr != MAP_FAILED) {
                uint8_t *sq_base = (uint8_t *)ctx->sq_ring_ptr;
                uint8_t *cq_base = (uint8_t *)ctx->cq_ring_ptr;
                ctx->sq_head = (uint32_t *)(sq_base + params.sq_off.head);
                ctx->sq_tail = (uint32_t *)(sq_base + params.sq_off.tail);
                ctx->sq_ring_mask = (uint32_t *)(sq_base + params.sq_off.ring_mask);
                ctx->sq_array = (uint32_t *)(sq_base + params.sq_off.array);
                ctx->cq_head = (uint32_t *)(cq_base + params.cq_off.head);
                ctx->cq_tail = (uint32_t *)(cq_base + params.cq_off.tail);
                ctx->cq_ring_mask = (uint32_t *)(cq_base + params.cq_off.ring_mask);
                ctx->cqes = (struct io_uring_cqe *)(cq_base + params.cq_off.cqes);
            } else {
                unmap_uring_ctx(ctx);
            }
        } else {
            ctx->sq_ring_ptr = NULL;
        }
    }
    return (int64_t)fd;
}

int32_t wing_uring_submit_sqe(int64_t ring_fd, uint8_t opcode, uint8_t flags, uint16_t ioprio, int32_t fd, uint64_t off,
                              uint64_t addr, uint32_t len, uint64_t user_data, uint16_t buf_index) {
    wing_uring_mmap_ctx *ctx = find_uring_ctx(ring_fd);
    if (!ctx) {
        return -EBADF;
    }
    uint32_t tail = *ctx->sq_tail;
    uint32_t head = __atomic_load_n(ctx->sq_head, __ATOMIC_ACQUIRE);
    uint32_t mask = *ctx->sq_ring_mask;
    if ((tail - head) > mask) {
        return -EBUSY;
    }
    uint32_t idx = tail & mask;
    struct io_uring_sqe *sqe = &ctx->sqes_ptr[idx];
    __builtin_memset(sqe, 0, sizeof(*sqe));
    sqe->opcode = opcode;
    sqe->flags = flags;
    sqe->ioprio = ioprio;
    sqe->fd = fd;
    sqe->off = off;
    sqe->addr = addr;
    sqe->len = len;
    sqe->user_data = user_data;
    sqe->buf_index = buf_index;
    ctx->sq_array[idx] = idx;
    __atomic_store_n(ctx->sq_tail, tail + 1, __ATOMIC_RELEASE);
    return 0;
}

int32_t wing_uring_enter(int64_t ring_fd, uint32_t to_submit, uint32_t min_complete, uint32_t flags) {
    long ret = syscall(__NR_io_uring_enter, (int)ring_fd, to_submit, min_complete, flags, NULL, 0);
    if (ret < 0) {
        return -errno;
    }
    return (int32_t)ret;
}

int32_t wing_uring_submit_sqes(int64_t ring_fd, wing_sqes_ro sqes) {
    wing_uring_mmap_ctx *ctx = find_uring_ctx(ring_fd);
    if (!ctx) {
        return -EBADF;
    }
    if (sqes.data == NULL || sqes.len <= 0) {
        return 0;
    }
    uint32_t tail = *ctx->sq_tail;
    uint32_t head = __atomic_load_n(ctx->sq_head, __ATOMIC_ACQUIRE);
    uint32_t mask = *ctx->sq_ring_mask;
    int32_t queued = 0;

    for (int64_t i = 0; i < sqes.len; i++) {
        if ((tail - head) > mask) {
            break;
        }
        uint32_t idx = tail & mask;
        struct io_uring_sqe *sqe = &ctx->sqes_ptr[idx];
        const WING_URING_SQE *src = &sqes.data[i];
        __builtin_memset(sqe, 0, sizeof(*sqe));
        sqe->opcode = src->opcode;
        sqe->flags = src->flags;
        sqe->ioprio = src->ioprio;
        sqe->fd = src->fd;
        sqe->off = src->off;
        sqe->addr = src->addr;
        sqe->len = src->len;
        __builtin_memcpy(&sqe->rw_flags, &src->op_flags, sizeof(uint32_t));
        sqe->user_data = src->user_data;
        sqe->buf_index = src->buf_index;
        ctx->sq_array[idx] = idx;
        tail++;
        queued++;
    }

    if (queued > 0) {
        __atomic_store_n(ctx->sq_tail, tail, __ATOMIC_RELEASE);
        int32_t rc = wing_uring_enter(ring_fd, (uint32_t)queued, 0, 0);
        if (rc < 0) {
            return rc;
        }
    }
    return queued;
}

static int32_t drain_cqes_nonblocking(wing_uring_mmap_ctx *ctx, WING_URING_CQE *dst, int64_t cap) {
    int32_t count = 0;
    uint32_t head = *ctx->cq_head;
    uint32_t tail = __atomic_load_n(ctx->cq_tail, __ATOMIC_ACQUIRE);
    uint32_t mask = *ctx->cq_ring_mask;

    while (head != tail && count < cap) {
        struct io_uring_cqe *cqe = &ctx->cqes[head & mask];
        head++;
        if (cqe->user_data == WING_URING_TIMEOUT_SENTINEL) {
            continue;
        }
        dst[count].user_data = cqe->user_data;
        dst[count].res = cqe->res;
        dst[count].flags = cqe->flags;
        count++;
    }
    __atomic_store_n(ctx->cq_head, head, __ATOMIC_RELEASE);
    return count;
}

int32_t wing_uring_wait_cqes(int64_t ring_fd, wing_cqes_rw cqes, uint32_t min_complete, int64_t timeout_ns) {
    wing_uring_mmap_ctx *ctx = find_uring_ctx(ring_fd);
    if (!ctx) {
        return -EBADF;
    }
    if (cqes.data == NULL || cqes.len <= 0) {
        return 0;
    }

    int32_t got = drain_cqes_nonblocking(ctx, cqes.data, cqes.len);
    if ((uint32_t)got >= min_complete || min_complete == 0 || timeout_ns == 0) {
        return got;
    }

    uint32_t need = min_complete - (uint32_t)got;
    uint32_t to_submit = 0;
    if (timeout_ns > 0) {
        uint32_t tail = *ctx->sq_tail;
        uint32_t head = __atomic_load_n(ctx->sq_head, __ATOMIC_ACQUIRE);
        uint32_t mask = *ctx->sq_ring_mask;
        if ((tail - head) <= mask) {
            ctx->timeout_ts.tv_sec = timeout_ns / 1000000000LL;
            ctx->timeout_ts.tv_nsec = timeout_ns % 1000000000LL;
            uint32_t idx = tail & mask;
            struct io_uring_sqe *sqe = &ctx->sqes_ptr[idx];
            __builtin_memset(sqe, 0, sizeof(*sqe));
            sqe->opcode = IORING_OP_TIMEOUT;
            sqe->fd = -1;
            sqe->off = need;
            sqe->addr = (uint64_t)(uintptr_t)&ctx->timeout_ts;
            sqe->len = 1;
            sqe->user_data = WING_URING_TIMEOUT_SENTINEL;
            ctx->sq_array[idx] = idx;
            __atomic_store_n(ctx->sq_tail, tail + 1, __ATOMIC_RELEASE);
            to_submit = 1;
        }
    }

    int32_t rc = wing_uring_enter(ring_fd, to_submit, to_submit ? 1 : need, IORING_ENTER_GETEVENTS);
    if (rc < 0 && rc != -ETIME && rc != -EINTR) {
        return got > 0 ? got : rc;
    }

    got += drain_cqes_nonblocking(ctx, cqes.data + got, cqes.len - got);
    return got;
}

int32_t wing_uring_peek_cqe(int64_t ring_fd, uint64_t *user_data_out, int32_t *res_out, uint32_t *flags_out) {
    wing_uring_mmap_ctx *ctx = find_uring_ctx(ring_fd);
    if (!ctx || !user_data_out || !res_out || !flags_out) {
        return 0;
    }
    uint32_t head = *ctx->cq_head;
    uint32_t tail = __atomic_load_n(ctx->cq_tail, __ATOMIC_ACQUIRE);
    while (head != tail) {
        uint32_t idx = head & (*ctx->cq_ring_mask);
        struct io_uring_cqe *cqe = &ctx->cqes[idx];
        head++;
        if (cqe->user_data == WING_URING_TIMEOUT_SENTINEL) {
            __atomic_store_n(ctx->cq_head, head, __ATOMIC_RELEASE);
            continue;
        }
        *user_data_out = cqe->user_data;
        *res_out = cqe->res;
        *flags_out = cqe->flags;
        __atomic_store_n(ctx->cq_head, head, __ATOMIC_RELEASE);
        return 1;
    }
    return 0;
}

int32_t wing_uring_register(int64_t ring_fd, uint32_t opcode, const void *arg, uint32_t nr_args) {
    long ret = syscall(__NR_io_uring_register, (int)ring_fd, opcode, arg, nr_args);
    if (ret < 0) {
        return -errno;
    }
    return (int32_t)ret;
}

int32_t wing_uring_register_buffers(int64_t ring_fd, wing_iovecs_ro iovecs) {
    if (iovecs.data == NULL || iovecs.len <= 0) return -EINVAL;
    return wing_uring_register(ring_fd, IORING_REGISTER_BUFFERS, iovecs.data, (uint32_t)iovecs.len);
}

int32_t wing_uring_unregister_buffers(int64_t ring_fd) {
    return wing_uring_register(ring_fd, IORING_UNREGISTER_BUFFERS, NULL, 0);
}

int32_t wing_uring_has_fast_poll(int64_t ring_fd) {
    (void)ring_fd;
    struct io_uring_params params;
    __builtin_memset(&params, 0, sizeof(params));
    long fd = syscall(__NR_io_uring_setup, 1, &params);
    if (fd < 0) return 0;
    close((int)fd);
    return (params.features & IORING_FEAT_FAST_POLL) != 0 ? 1 : 0;
}

int32_t wing_uring_register_pbuf_ring(int64_t ring_fd, uint64_t ring_addr, uint32_t ring_entries, uint16_t bgid) {
    struct wing_uring_buf_reg reg;
    __builtin_memset(&reg, 0, sizeof(reg));
    reg.ring_addr = ring_addr;
    reg.ring_entries = ring_entries;
    reg.bgid = bgid;
    return wing_uring_register(ring_fd, IORING_REGISTER_PBUF_RING, &reg, 1);
}

int32_t wing_uring_alloc_pbuf_ring(int64_t ring_fd, uint16_t bgid, uint32_t entries, uint32_t buf_size,
                                   uint64_t *out_handle) {
    if (ring_fd < 0 || entries == 0 || entries > 32768 || (entries & (entries - 1)) != 0 || buf_size == 0 ||
        !out_handle) {
        return -EINVAL;
    }
    *out_handle = 0;
    int slot = -1;
    for (int i = 0; i < WING_URING_MAX_PBUF_RINGS; i++) {
        if (!g_pbuf_rings[i].active) {
            slot = i;
            break;
        }
    }
    if (slot < 0) {
        return -ENOMEM;
    }

    size_t ring_sz = (size_t)entries * sizeof(wing_pbuf_desc);
    if (ring_sz < 4096) ring_sz = 4096;
    size_t slab_sz = (size_t)entries * (size_t)buf_size;

    void *ring_mem = mmap(NULL, ring_sz, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (ring_mem == MAP_FAILED) {
        return -ENOMEM;
    }
    void *slab_mem = mmap(NULL, slab_sz, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (slab_mem == MAP_FAILED) {
        munmap(ring_mem, ring_sz);
        return -ENOMEM;
    }

    wing_pbuf_ring_hdr *hdr = (wing_pbuf_ring_hdr *)ring_mem;
    __builtin_memset(hdr, 0, ring_sz);
    uint8_t *slab = (uint8_t *)slab_mem;
    for (uint32_t i = 0; i < entries; i++) {
        hdr->bufs[i].addr = (uint64_t)(uintptr_t)(slab + (size_t)i * (size_t)buf_size);
        hdr->bufs[i].len = buf_size;
        hdr->bufs[i].bid = (uint16_t)i;
        hdr->bufs[i].resv = 0;
    }
    __atomic_store_n(&hdr->tail, (uint16_t)entries, __ATOMIC_RELEASE);

    int32_t rc = wing_uring_register_pbuf_ring(ring_fd, (uint64_t)(uintptr_t)hdr, entries, bgid);
    if (rc < 0) {
        munmap(slab_mem, slab_sz);
        munmap(ring_mem, ring_sz);
        return rc;
    }

    wing_pbuf_slot *ps = &g_pbuf_rings[slot];
    ps->active = 1;
    ps->ring_fd = ring_fd;
    ps->bgid = bgid;
    ps->entries = entries;
    ps->buf_size = buf_size;
    ps->ring_ptr = hdr;
    ps->ring_map_sz = ring_sz;
    ps->slab_ptr = slab;
    ps->slab_map_sz = slab_sz;
    *out_handle = (uint64_t)(slot + 1);
    return 0;
}

void wing_uring_free_pbuf_ring(uint64_t handle) {
    if (handle == 0 || handle > WING_URING_MAX_PBUF_RINGS) return;
    wing_pbuf_slot *ps = &g_pbuf_rings[handle - 1];
    if (!ps->active) return;

    struct wing_uring_buf_reg reg;
    __builtin_memset(&reg, 0, sizeof(reg));
    reg.bgid = ps->bgid;
    (void)wing_uring_register(ps->ring_fd, IORING_UNREGISTER_PBUF_RING, &reg, 1);

    if (ps->slab_ptr) munmap(ps->slab_ptr, ps->slab_map_sz);
    if (ps->ring_ptr) munmap(ps->ring_ptr, ps->ring_map_sz);
    __builtin_memset(ps, 0, sizeof(*ps));
}

int32_t wing_uring_read_pbuf(uint64_t handle, uint16_t bid, int32_t len, wing_uring_bytes_rw dst) {
    if (handle == 0 || handle > WING_URING_MAX_PBUF_RINGS || len < 0 || !dst.data || dst.len < 0) {
        return -EINVAL;
    }
    wing_pbuf_slot *ps = &g_pbuf_rings[handle - 1];
    if (!ps->active || (uint32_t)bid >= ps->entries) {
        return -EINVAL;
    }
    int32_t copy_n = len;
    if ((uint32_t)copy_n > ps->buf_size) copy_n = (int32_t)ps->buf_size;
    if ((int64_t)copy_n > dst.len) copy_n = (int32_t)dst.len;
    if (copy_n > 0) {
        __builtin_memcpy(dst.data, ps->slab_ptr + (size_t)bid * (size_t)ps->buf_size, (size_t)copy_n);
    }
    return copy_n;
}

void wing_uring_recycle_pbuf(uint64_t handle, uint16_t bid) {
    if (handle == 0 || handle > WING_URING_MAX_PBUF_RINGS) return;
    wing_pbuf_slot *ps = &g_pbuf_rings[handle - 1];
    if (!ps->active || (uint32_t)bid >= ps->entries) return;

    wing_pbuf_ring_hdr *hdr = ps->ring_ptr;
    uint16_t tail = __atomic_load_n(&hdr->tail, __ATOMIC_RELAXED);
    uint32_t idx = (uint32_t)tail & (ps->entries - 1);
    hdr->bufs[idx].addr = (uint64_t)(uintptr_t)(ps->slab_ptr + (size_t)bid * (size_t)ps->buf_size);
    hdr->bufs[idx].len = ps->buf_size;
    hdr->bufs[idx].bid = bid;
    hdr->bufs[idx].resv = 0;
    __atomic_store_n(&hdr->tail, (uint16_t)(tail + 1), __ATOMIC_RELEASE);
}

int32_t wing_uring_register_files(int64_t ring_fd, const int32_t *fds, uint32_t nr_files) {
    return wing_uring_register(ring_fd, IORING_REGISTER_FILES, fds, nr_files);
}

void wing_uring_close(int64_t ring_fd) {
    if (ring_fd >= 0) {
        for (int i = 0; i < WING_URING_MAX_PBUF_RINGS; i++) {
            if (g_pbuf_rings[i].active && g_pbuf_rings[i].ring_fd == ring_fd) {
                wing_uring_free_pbuf_ring((uint64_t)(i + 1));
            }
        }
        wing_uring_mmap_ctx *ctx = find_uring_ctx(ring_fd);
        if (ctx) {
            unmap_uring_ctx(ctx);
        }
        close((int)ring_fd);
    }
}

#else

#ifndef ENOSYS
#define ENOSYS 38
#endif

// Non-Linux platform stubs
int32_t wing_uring_probe(void) { return -ENOSYS; }
int64_t wing_uring_create(uint32_t entries, uint32_t flags) {
    (void)entries;
    (void)flags;
    return -ENOSYS;
}
int32_t wing_uring_submit_sqe(int64_t ring_fd, uint8_t opcode, uint8_t flags, uint16_t ioprio, int32_t fd, uint64_t off,
                              uint64_t addr, uint32_t len, uint64_t user_data, uint16_t buf_index) {
    (void)ring_fd;
    (void)opcode;
    (void)flags;
    (void)ioprio;
    (void)fd;
    (void)off;
    (void)addr;
    (void)len;
    (void)user_data;
    (void)buf_index;
    return -ENOSYS;
}
int32_t wing_uring_submit_sqes(int64_t ring_fd, wing_sqes_ro sqes) {
    (void)ring_fd;
    (void)sqes;
    return -ENOSYS;
}
int32_t wing_uring_wait_cqes(int64_t ring_fd, wing_cqes_rw cqes, uint32_t min_complete, int64_t timeout_ns) {
    (void)ring_fd;
    (void)cqes;
    (void)min_complete;
    (void)timeout_ns;
    return -ENOSYS;
}
int32_t wing_uring_peek_cqe(int64_t ring_fd, uint64_t *user_data_out, int32_t *res_out, uint32_t *flags_out) {
    (void)ring_fd;
    (void)user_data_out;
    (void)res_out;
    (void)flags_out;
    return 0;
}
int32_t wing_uring_enter(int64_t ring_fd, uint32_t to_submit, uint32_t min_complete, uint32_t flags) {
    (void)ring_fd;
    (void)to_submit;
    (void)min_complete;
    (void)flags;
    return -ENOSYS;
}
int32_t wing_uring_register(int64_t ring_fd, uint32_t opcode, const void *arg, uint32_t nr_args) {
    (void)ring_fd;
    (void)opcode;
    (void)arg;
    (void)nr_args;
    return -ENOSYS;
}
int32_t wing_uring_register_buffers(int64_t ring_fd, wing_iovecs_ro iovecs) {
    (void)ring_fd;
    (void)iovecs;
    return -ENOSYS;
}
int32_t wing_uring_unregister_buffers(int64_t ring_fd) {
    (void)ring_fd;
    return -ENOSYS;
}
int32_t wing_uring_has_fast_poll(int64_t ring_fd) {
    (void)ring_fd;
    return 0;
}
int32_t wing_uring_register_pbuf_ring(int64_t ring_fd, uint64_t ring_addr, uint32_t ring_entries, uint16_t bgid) {
    (void)ring_fd;
    (void)ring_addr;
    (void)ring_entries;
    (void)bgid;
    return -ENOSYS;
}
int32_t wing_uring_alloc_pbuf_ring(int64_t ring_fd, uint16_t bgid, uint32_t entries, uint32_t buf_size,
                                   uint64_t *out_handle) {
    (void)ring_fd;
    (void)bgid;
    (void)entries;
    (void)buf_size;
    if (out_handle) *out_handle = 0;
    return -ENOSYS;
}
void wing_uring_free_pbuf_ring(uint64_t handle) { (void)handle; }
int32_t wing_uring_read_pbuf(uint64_t handle, uint16_t bid, int32_t len, wing_uring_bytes_rw dst) {
    (void)handle;
    (void)bid;
    (void)len;
    (void)dst;
    return -ENOSYS;
}
void wing_uring_recycle_pbuf(uint64_t handle, uint16_t bid) {
    (void)handle;
    (void)bid;
}
int32_t wing_uring_register_files(int64_t ring_fd, const int32_t *fds, uint32_t nr_files) {
    (void)ring_fd;
    (void)fds;
    (void)nr_files;
    return -ENOSYS;
}
void wing_uring_close(int64_t ring_fd) { (void)ring_fd; }

#endif
