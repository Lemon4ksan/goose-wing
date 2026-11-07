// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Layer 4 Linux io_uring Kernel-Bypass C Shim.
// Executes direct Linux kernel syscalls (__NR_io_uring_setup, __NR_io_uring_enter)
// and mmaps SQ/CQ rings and SQE arrays without external liburing userland dependencies.

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <stdint.h>
#include <stddef.h>

typedef struct {
    const void *data;
    int64_t len;
} wing_iovecs_ro;

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

#define WING_URING_MAX_RINGS 16

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
} wing_uring_mmap_ctx;

static wing_uring_mmap_ctx g_uring_rings[WING_URING_MAX_RINGS];

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

int32_t wing_uring_peek_cqe(int64_t ring_fd, uint64_t *user_data_out, int32_t *res_out, uint32_t *flags_out) {
    wing_uring_mmap_ctx *ctx = find_uring_ctx(ring_fd);
    if (!ctx || !user_data_out || !res_out || !flags_out) {
        return 0;
    }
    uint32_t head = *ctx->cq_head;
    uint32_t tail = __atomic_load_n(ctx->cq_tail, __ATOMIC_ACQUIRE);
    if (head == tail) {
        return 0;
    }
    uint32_t idx = head & (*ctx->cq_ring_mask);
    struct io_uring_cqe *cqe = &ctx->cqes[idx];
    *user_data_out = cqe->user_data;
    *res_out = cqe->res;
    *flags_out = cqe->flags;
    __atomic_store_n(ctx->cq_head, head + 1, __ATOMIC_RELEASE);
    return 1;
}

int32_t wing_uring_enter(int64_t ring_fd, uint32_t to_submit, uint32_t min_complete, uint32_t flags) {
    long ret = syscall(__NR_io_uring_enter, (int)ring_fd, to_submit, min_complete, flags, NULL, 0);
    if (ret < 0) {
        return -errno;
    }
    return (int32_t)ret;
}

int32_t wing_uring_register(int64_t ring_fd, uint32_t opcode, const void *arg, uint32_t nr_args) {
    long ret = syscall(__NR_io_uring_register, (int)ring_fd, opcode, arg, nr_args);
    if (ret < 0) {
        return -errno;
    }
    return (int32_t)ret;
}

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

#ifndef IORING_FEAT_FAST_POLL
#define IORING_FEAT_FAST_POLL (1U << 5)
#endif

#ifndef IORING_ACCEPT_MULTISHOT
#define IORING_ACCEPT_MULTISHOT (1U << 0)
#endif

struct wing_uring_buf_reg {
    uint64_t ring_addr;
    uint32_t ring_entries;
    uint16_t bgid;
    uint16_t pad;
    uint64_t resv[3];
};

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

int32_t wing_uring_register_files(int64_t ring_fd, const int32_t *fds, uint32_t nr_files) {
    return wing_uring_register(ring_fd, IORING_REGISTER_FILES, fds, nr_files);
}

void wing_uring_close(int64_t ring_fd) {
    if (ring_fd >= 0) {
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
int32_t wing_uring_register_files(int64_t ring_fd, const int32_t *fds, uint32_t nr_files) {
    (void)ring_fd;
    (void)fds;
    (void)nr_files;
    return -ENOSYS;
}
void wing_uring_close(int64_t ring_fd) { (void)ring_fd; }

#endif
