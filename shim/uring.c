// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Layer 4 Linux io_uring Kernel-Bypass C Shim.
// Executes direct Linux kernel syscalls (__NR_io_uring_setup, __NR_io_uring_enter)
// without external liburing userland dependencies.

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
    return (int64_t)fd;
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
