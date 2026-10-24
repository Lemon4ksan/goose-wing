// Layer 4 Linux io_uring Kernel-Bypass C Shim.
// Executes direct Linux kernel syscalls (__NR_io_uring_setup, __NR_io_uring_enter)
// without external liburing userland dependencies.
#include <stdint.h>
#include <stddef.h>

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

void wing_uring_close(int64_t ring_fd) {
    if (ring_fd >= 0) {
        close((int)ring_fd);
    }
}

#else

// Non-Linux platform stubs
int32_t wing_uring_probe(void) { return -38; }
int64_t wing_uring_create(uint32_t entries, uint32_t flags) { (void)entries; (void)flags; return -38; }
int32_t wing_uring_enter(int64_t ring_fd, uint32_t to_submit, uint32_t min_complete, uint32_t flags) {
    (void)ring_fd; (void)to_submit; (void)min_complete; (void)flags; return -38;
}
void wing_uring_close(int64_t ring_fd) { (void)ring_fd; }

#endif
