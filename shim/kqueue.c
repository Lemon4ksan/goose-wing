// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Layer 4 macOS / Darwin / BSD kqueue Event Notification C Shim.
// Implements kqueue() with FD_CLOEXEC, EV_RECEIPT chunked changelist flushing (mio/libuv pattern),
// packed Goose slice marshalling, and nanosecond-resolution kevent() harvesting.
#include <stdint.h>
#include <stddef.h>

// Goose emits all structs and slice headers under #pragma pack(push, 1).
#pragma pack(push, 1)
typedef struct {
    uint64_t ident;
    int16_t filter;
    uint16_t flags;
    uint32_t fflags;
    int64_t data;
    uint64_t udata;
} WING_KEVENT;

_Static_assert(sizeof(WING_KEVENT) == 32, "WING_KEVENT must match packed Goose Kevent (32B)");

typedef struct {
    const WING_KEVENT *data;
    int64_t len;
} wing_kevents_ro;

typedef struct {
    WING_KEVENT *data;
    int64_t len;
} wing_kevents_rw;
#pragma pack(pop)

#if defined(__APPLE__) || defined(__FreeBSD__) || defined(__OpenBSD__) || defined(__NetBSD__) || defined(__DragonFly__)
#include <sys/types.h>
#include <sys/event.h>
#include <sys/time.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>

#ifndef EV_RECEIPT
#define EV_RECEIPT 0x0040
#endif

int32_t wing_kqueue_probe(void) {
    int kq = kqueue();
    if (kq < 0) {
        return -errno;
    }
    close(kq);
    return 0;
}

int64_t wing_kqueue_create(void) {
    int kq = kqueue();
    if (kq < 0) {
        return -errno;
    }
    if (fcntl(kq, F_SETFD, FD_CLOEXEC) < 0) {
        int err = errno ? errno : EIO;
        close(kq);
        return -err;
    }
    return (int64_t)kq;
}

int32_t wing_kqueue_kevent_slice(int64_t kq_fd, wing_kevents_ro changes, wing_kevents_rw events, int64_t timeout_ns) {
    if (kq_fd < 0) {
        return -EBADF;
    }

    // 1. Apply all queued changes in 64-entry EV_RECEIPT batches so:
    //    - batches > 64 entries (e.g. ReactorAccelRuntime kq_changes[..256]) are never truncated,
    //    - benign ENOENT/EBADF/EPIPE on EV_DELETE never abort subsequent EV_ADDs in the batch,
    //    - receipt entries never consume caller's ready-event output slots.
    if (changes.data != NULL && changes.len > 0) {
        struct kevent chg_buf[64];
        struct kevent rcpt_buf[64];
        int64_t off = 0;
        while (off < changes.len) {
            int chunk = (changes.len - off > 64) ? 64 : (int)(changes.len - off);
            for (int i = 0; i < chunk; i++) {
                const WING_KEVENT *src = &changes.data[off + i];
#if defined(__NetBSD__)
                intptr_t udata_val = (intptr_t)(uintptr_t)src->udata;
#else
                void *udata_val = (void *)(uintptr_t)src->udata;
#endif
                EV_SET(&chg_buf[i], (uintptr_t)src->ident, src->filter, (uint16_t)(src->flags | EV_RECEIPT),
                       src->fflags, (intptr_t)src->data, udata_val);
            }
            int rc = kevent((int)kq_fd, chg_buf, chunk, rcpt_buf, chunk, NULL);
            if (rc < 0) {
                if (errno == EINTR) {
                    continue;
                }
                return -errno;
            }
            for (int i = 0; i < rc; i++) {
                if ((rcpt_buf[i].flags & EV_ERROR) != 0 && rcpt_buf[i].data != 0) {
                    int err = (int)rcpt_buf[i].data;
                    if (err != ENOENT && err != EBADF && err != EPIPE) {
                        return -err;
                    }
                }
            }
            off += chunk;
        }
    }

    if (events.data == NULL || events.len <= 0) {
        return 0;
    }

    struct kevent ev_buf[256];
    int max_ev = (events.len > 256) ? 256 : (int)events.len;

    struct timespec ts;
    struct timespec *pts = NULL;
    if (timeout_ns >= 0) {
        ts.tv_sec = (time_t)(timeout_ns / 1000000000LL);
        ts.tv_nsec = (long)(timeout_ns % 1000000000LL);
        pts = &ts;
    }

    int ret = kevent((int)kq_fd, NULL, 0, ev_buf, max_ev, pts);
    if (ret < 0) {
        if (errno == EINTR) {
            return 0;
        }
        return -errno;
    }
    for (int i = 0; i < ret; i++) {
        events.data[i].ident = (uint64_t)ev_buf[i].ident;
        events.data[i].filter = (int16_t)ev_buf[i].filter;
        events.data[i].flags = (uint16_t)ev_buf[i].flags;
        events.data[i].fflags = (uint32_t)ev_buf[i].fflags;
        events.data[i].data = (int64_t)ev_buf[i].data;
        events.data[i].udata = (uint64_t)(uintptr_t)ev_buf[i].udata;
    }
    return ret;
}

void wing_kqueue_close(int64_t kq_fd) {
    if (kq_fd >= 0) {
        close((int)kq_fd);
    }
}

#else

#ifndef ENOSYS
#define ENOSYS 38
#endif

// Non-Darwin/BSD platform stubs
int32_t wing_kqueue_probe(void) { return -ENOSYS; }
int64_t wing_kqueue_create(void) { return -ENOSYS; }
int32_t wing_kqueue_kevent_slice(int64_t kq_fd, wing_kevents_ro changes, wing_kevents_rw events, int64_t timeout_ns) {
    (void)kq_fd;
    (void)changes;
    (void)events;
    (void)timeout_ns;
    return -ENOSYS;
}
void wing_kqueue_close(int64_t kq_fd) { (void)kq_fd; }

#endif
