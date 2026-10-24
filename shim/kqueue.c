// Layer 4 macOS / Darwin kqueue Event Notification C Shim.
// Implements kqueue() and kevent() batch event multiplexing with nanosecond timers
// and byte-accurate socket buffer accounting (struct kevent.data).
#include <stdint.h>
#include <stddef.h>

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

int32_t wing_kqueue_kevent(int64_t kq_fd, const void *changelist, int32_t nchanges,
                           void *eventlist, int32_t nevents, int64_t timeout_ns) {
    struct timespec ts;
    struct timespec *pts = NULL;
    if (timeout_ns >= 0) {
        ts.tv_sec = timeout_ns / 1000000000LL;
        ts.tv_nsec = timeout_ns % 1000000000LL;
        pts = &ts;
    }
    int ret = kevent((int)kq_fd, (const struct kevent*)changelist, nchanges,
                     (struct kevent*)eventlist, nevents, pts);
    if (ret < 0) {
        return -errno;
    }
    return ret;
}

void wing_kqueue_close(int64_t kq_fd) {
    if (kq_fd >= 0) {
        close((int)kq_fd);
    }
}

#else

// Non-Darwin platform stubs
int32_t wing_kqueue_probe(void) { return -38; }
int64_t wing_kqueue_create(void) { return -38; }
int32_t wing_kqueue_kevent(int64_t kq_fd, const void *changelist, int32_t nchanges,
                           void *eventlist, int32_t nevents, int64_t timeout_ns) {
    (void)kq_fd; (void)changelist; (void)nchanges; (void)eventlist; (void)nevents; (void)timeout_ns;
    return -38;
}
void wing_kqueue_close(int64_t kq_fd) { (void)kq_fd; }

#endif
