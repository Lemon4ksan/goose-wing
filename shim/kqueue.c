// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Layer 4 macOS / Darwin / BSD kqueue Event Notification C Shim.
// Implements kqueue() and kevent() batch event multiplexing with nanosecond timers,
// explicit slice marshalling, and byte-accurate socket buffer accounting (struct kevent.data).
#include <stdint.h>
#include <stddef.h>

typedef struct {
    uint64_t ident;
    int16_t filter;
    uint16_t flags;
    uint32_t fflags;
    int64_t data;
    uint64_t udata;
} WING_KEVENT;

_Static_assert(sizeof(WING_KEVENT) == 32, "WING_KEVENT must match Goose Kevent (32B)");

typedef struct {
    const WING_KEVENT *data;
    int64_t len;
} wing_kevents_ro;

typedef struct {
    WING_KEVENT *data;
    int64_t len;
} wing_kevents_rw;

#if defined(__APPLE__) || defined(__FreeBSD__) || defined(__OpenBSD__) || defined(__NetBSD__)
#include <sys/types.h>
#include <sys/event.h>
#include <sys/time.h>
#include <unistd.h>
#include <errno.h>

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
    return (int64_t)kq;
}

int32_t wing_kqueue_kevent(int64_t kq_fd, const void *changelist, int32_t nchanges, void *eventlist, int32_t nevents,
                           int64_t timeout_ns) {
    struct timespec ts;
    struct timespec *pts = NULL;
    if (timeout_ns >= 0) {
        ts.tv_sec = timeout_ns / 1000000000LL;
        ts.tv_nsec = timeout_ns % 1000000000LL;
        pts = &ts;
    }
    int ret = kevent((int)kq_fd, (const struct kevent *)changelist, nchanges, (struct kevent *)eventlist, nevents, pts);
    if (ret < 0) {
        return -errno;
    }
    return ret;
}

int32_t wing_kqueue_kevent_slice(int64_t kq_fd, wing_kevents_ro changes, wing_kevents_rw events, int64_t timeout_ns) {
    if (kq_fd < 0) {
        return -EBADF;
    }
    struct kevent chg_buf[64];
    struct kevent ev_buf[64];

    int nchanges = 0;
    if (changes.data != NULL && changes.len > 0) {
        nchanges = (changes.len > 64) ? 64 : (int)changes.len;
        for (int i = 0; i < nchanges; i++) {
            EV_SET(&chg_buf[i], (uintptr_t)changes.data[i].ident, changes.data[i].filter, changes.data[i].flags,
                   changes.data[i].fflags, (intptr_t)changes.data[i].data, (void *)(uintptr_t)changes.data[i].udata);
        }
    }

    int max_ev = 0;
    if (events.data != NULL && events.len > 0) {
        max_ev = (events.len > 64) ? 64 : (int)events.len;
    }

    struct timespec ts;
    struct timespec *pts = NULL;
    if (timeout_ns >= 0) {
        ts.tv_sec = timeout_ns / 1000000000LL;
        ts.tv_nsec = timeout_ns % 1000000000LL;
        pts = &ts;
    }

    int ret = kevent((int)kq_fd, nchanges > 0 ? chg_buf : NULL, nchanges, max_ev > 0 ? ev_buf : NULL, max_ev, pts);
    if (ret < 0) {
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

// Non-Darwin platform stubs
int32_t wing_kqueue_probe(void) { return -ENOSYS; }
int64_t wing_kqueue_create(void) { return -ENOSYS; }
int32_t wing_kqueue_kevent(int64_t kq_fd, const void *changelist, int32_t nchanges, void *eventlist, int32_t nevents,
                           int64_t timeout_ns) {
    (void)kq_fd;
    (void)changelist;
    (void)nchanges;
    (void)eventlist;
    (void)nevents;
    (void)timeout_ns;
    return -ENOSYS;
}
int32_t wing_kqueue_kevent_slice(int64_t kq_fd, wing_kevents_ro changes, wing_kevents_rw events, int64_t timeout_ns) {
    (void)kq_fd;
    (void)changes;
    (void)events;
    (void)timeout_ns;
    return -ENOSYS;
}
void wing_kqueue_close(int64_t kq_fd) { (void)kq_fd; }

#endif
