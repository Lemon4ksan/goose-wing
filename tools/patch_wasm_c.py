#!/usr/bin/env python3

# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Lemon4ksan

import re
import sys


def patch_file(path: str):
    with open(path, encoding="utf-8") as f:
        content = f.read()

    # 0. stack reserve & budget for 32-bit wasm memory
    t0 = """#ifndef GS_STACK_RESERVE
#define GS_STACK_RESERVE (2048ull << 20)  /* Address space reserved per stack. */
#endif"""
    r0 = """#if defined(__wasm__)
#define GS_STACK_RESERVE (2ull << 20)
#else
#define GS_STACK_RESERVE (2048ull << 20)  /* Address space reserved per stack. */
#endif"""

    t0_gap = """#ifndef GS_STACK_GAP
#define GS_STACK_GAP (1ull << 20)   /* Unmapped tail so runaway growth aborts. */
#endif"""
    r0_gap = """#if defined(__wasm__)
#define GS_STACK_GAP (64ull << 10)
#else
#define GS_STACK_GAP (1ull << 20)   /* Unmapped tail so runaway growth aborts. */
#endif"""

    t0_bud = """#ifndef GS_STACK_BUDGET
#define GS_STACK_BUDGET (32ull << 40)
#endif"""
    r0_bud = """#if defined(__wasm__)
#define GS_STACK_BUDGET (32ull << 20)
#else
#define GS_STACK_BUDGET (16384ull << 20)
#endif"""

    # 1. setjmp
    t1 = """#include <setjmp.h>
#include <stdarg.h>
/* No abort is raised in a signal handler, so the jump leaves the signal
   state alone. */
#ifdef _WIN32
#define gs_setjmp(b)  setjmp(b)
#define gs_longjmp    longjmp
#else
#define gs_setjmp(b)  _setjmp(b)
#define gs_longjmp    _longjmp
#endif"""

    r1 = """#if defined(__wasm__)
typedef int jmp_buf[1];
#define gs_setjmp(b)  (0)
#define gs_longjmp(b, v) abort()
#elif defined(_WIN32)
#include <setjmp.h>
#define gs_setjmp(b)  setjmp(b)
#define gs_longjmp    longjmp
#else
#include <setjmp.h>
#define gs_setjmp(b)  _setjmp(b)
#define gs_longjmp    _longjmp
#endif
#include <stdarg.h>"""

    # 2. posix memory/signals
    t2 = """static GS_NORETURN void gs_park(void) {
    for (;;) Sleep(INFINITE);
}

#else  /* posix */"""

    r2 = """static GS_NORETURN void gs_park(void) {
    for (;;) Sleep(INFINITE);
}

#elif defined(__wasm__)

#include <unistd.h>

static size_t gs_page_size = 65536;

static size_t gs_os_page_size(void) {
    return 65536;
}

static void gs_regions_init(void) {
    gs_page_size = 65536;
}

static void gs_native_stack_init(void) {
}

static void gs_native_stack_free(void) {
}

static uint8_t *gs_os_reserve(size_t usable, size_t size) {
    (void)usable;
    return (uint8_t *)calloc(1, size);
}

static void gs_release_region(const gs_region *r) {
    free(r->base);
}

static int gs_end_first(void) {
    return 1;
}

static GS_NORETURN void gs_park(void) {
    for (;;) ;
}

#else  /* posix */"""

    # 3. GS_REGION_MIN
    t3 = "#define GS_REGION_MIN (1u << 20)"
    r3 = """#ifndef GS_REGION_MIN
#define GS_REGION_MIN (64u << 10)
#endif"""

    # 4. gs_trim_memory
    t4 = """#ifdef _WIN32
        /* The access-fault handler commits the pages again on growth. */
        if (VirtualFree((void *)start, len, MEM_DECOMMIT))
            r->committed = (uint8_t *)start;
        else
            ok = 0;
#elif defined(__APPLE__)"""

    r4 = """#ifdef _WIN32
        /* The access-fault handler commits the pages again on growth. */
        if (VirtualFree((void *)start, len, MEM_DECOMMIT))
            r->committed = (uint8_t *)start;
        else
            ok = 0;
#elif defined(__wasm__)
        (void)len;
        r->committed = (uint8_t *)start;
#elif defined(__APPLE__)"""

    # 5. gs_os_threads
    t5 = """    SYSTEM_INFO si;
    GetSystemInfo(&si);
    return (int64_t)si.dwNumberOfProcessors;
}
#else"""

    r5 = """    SYSTEM_INFO si;
    GetSystemInfo(&si);
    return (int64_t)si.dwNumberOfProcessors;
}
#elif defined(__wasm__)
static int64_t gs_os_threads(void) {
    return 1;
}
#else"""

    # 6. gs_mutex / gs_cond
    t6 = """#define gs_cond_broadcast(c) WakeAllConditionVariable(c)

#else  /* posix */"""

    r6 = """#define gs_cond_broadcast(c) WakeAllConditionVariable(c)

#elif defined(__wasm__)

typedef int gs_mutex;
typedef int gs_cond;
#define GS_MUTEX_INIT 0
#define GS_COND_INIT  0
#define gs_mutex_init(m)   ((void)0)
#define gs_cond_init(c)    ((void)0)
#define gs_mutex_lock(m)   ((void)0)
#define gs_mutex_unlock(m) ((void)0)
#define gs_cond_wait(c, m) ((void)0)
#define gs_cond_signal(c)  ((void)0)
#define gs_cond_broadcast(c) ((void)0)

#else  /* posix */"""

    # 7. gs_thread_main
    t7 = """#ifdef _WIN32
static DWORD WINAPI gs_thread_main(LPVOID p)
#else
static void *gs_thread_main(void *p)
#endif"""

    r7 = """#ifdef _WIN32
static DWORD WINAPI gs_thread_main(LPVOID p)
#elif defined(__wasm__)
static void *gs_thread_main(void *p)
#else
static void *gs_thread_main(void *p)
#endif"""

    # 8. gs_thread_start
    t8 = """    int failed;
    #ifdef _WIN32
        HANDLE handle = CreateThread(NULL, 0, gs_thread_main, t, 0, NULL);
        failed = handle == NULL;
        /* Closing the handle does not stop the worker. Completion is tracked
           above, so callers never need to retain or join a native handle. */
        if (handle && !CloseHandle(handle)) gs_panic("cannot close thread handle");
    #else"""

    r8 = """    int failed;
    #ifdef _WIN32
        HANDLE handle = CreateThread(NULL, 0, gs_thread_main, t, 0, NULL);
        failed = handle == NULL;
        /* Closing the handle does not stop the worker. Completion is tracked
           above, so callers never need to retain or join a native handle. */
        if (handle && !CloseHandle(handle)) gs_panic("cannot close thread handle");
    #elif defined(__wasm__)
        (void)gs_thread_main;
        failed = 1;
    #else"""

    # 9. gs_cond_wait_until and gs_qinit
    t9 = """    #ifdef _WIN32
        int64_t ms = (left + 999999) / 1000000;
        SleepConditionVariableSRW(c, m, ms < INFINITE ? (DWORD)ms : INFINITE - 1, 0);
    #elif defined(__APPLE__)
        struct timespec ts = { (time_t)(left / 1000000000), (long)(left % 1000000000) };
        pthread_cond_timedwait_relative_np(c, m, &ts);
    #else
        struct timespec ts = { (time_t)(deadline / 1000000000), (long)(deadline % 1000000000) };
        pthread_cond_timedwait(c, m, &ts);
    #endif
    return 1;
}

GS_API void gs_qinit(gs_queue *q) {
    struct gs_qstate *s = (struct gs_qstate *)malloc(sizeof(struct gs_qstate));
    if (!s) gs_panic("out of memory creating a queue");
    s->head = s->tail = NULL;
    s->count = 0;
    s->limit = INT64_MAX;
    gs_mutex_init(&s->mutex);
    #if defined(_WIN32) || defined(__APPLE__)
        gs_cond_init(&s->cond);
    #else"""

    r9 = """    #ifdef _WIN32
        int64_t ms = (left + 999999) / 1000000;
        SleepConditionVariableSRW(c, m, ms < INFINITE ? (DWORD)ms : INFINITE - 1, 0);
    #elif defined(__wasm__)
        return 0;
    #elif defined(__APPLE__)
        struct timespec ts = { (time_t)(left / 1000000000), (long)(left % 1000000000) };
        pthread_cond_timedwait_relative_np(c, m, &ts);
    #else
        struct timespec ts = { (time_t)(deadline / 1000000000), (long)(deadline % 1000000000) };
        pthread_cond_timedwait(c, m, &ts);
    #endif
    return 1;
}

GS_API void gs_qinit(gs_queue *q) {
    struct gs_qstate *s = (struct gs_qstate *)malloc(sizeof(struct gs_qstate));
    if (!s) gs_panic("out of memory creating a queue");
    s->head = s->tail = NULL;
    s->count = 0;
    s->limit = INT64_MAX;
    gs_mutex_init(&s->mutex);
    #if defined(_WIN32) || defined(__APPLE__) || defined(__wasm__)
        gs_cond_init(&s->cond);
    #else"""

    # Normalize newlines
    def rep(text, target, repl):
        t_crlf = target.replace("\n", "\r\n")
        t_lf = target.replace("\r\n", "\n")
        if t_crlf in text:
            return text.replace(t_crlf, repl.replace("\n", "\r\n"))
        elif t_lf in text:
            return text.replace(t_lf, repl.replace("\r\n", "\n"))
        else:
            print(f"Warning: pattern not found in target: {target[:30]!r}")
            return text

    content = rep(content, t0, r0)
    content = rep(content, t0_gap, r0_gap)
    content = rep(content, t0_bud, r0_bud)
    content = rep(content, t1, r1)
    content = rep(content, t2, r2)
    content = rep(content, t3, r3)
    content = rep(content, t4, r4)
    content = rep(content, t5, r5)
    content = rep(content, t6, r6)
    content = rep(content, t7, r7)
    content = rep(content, t8, r8)
    content = rep(content, t9, r9)

    # Sanitize absolute local development paths in gs_file strings
    content = re.sub(
        r'static const char (gs_file\d+\[\]) = ".*?[/\\]stdlib[/\\]std\.goose";',
        r'static const char \1 = "stdlib/std.goose";',
        content,
    )
    content = re.sub(
        r'static const char (gs_file\d+\[\]) = "[A-Za-z]:[/\\][^"]*?[/\\]goose-wing[/\\]([^"]+)";',
        r'static const char \1 = "\2";',
        content,
    )

    with open(path, "w", encoding="utf-8") as f:
        f.write(content)
    print("Patched successfully for WebAssembly target.")


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: patch_wasm_c.py <file.c>")
        sys.exit(1)
    patch_file(sys.argv[1])
