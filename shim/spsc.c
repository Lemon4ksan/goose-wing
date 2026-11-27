// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Layer 4 High-Performance Cache-Line Aligned Lock-Free SPSC Ring Queue C Shim.
// Prevents False Sharing by padding producer and consumer cursors to separate 64-byte L1 cache lines.
// Employs acquire-release atomic memory orderings for zero-mutex inter-thread messaging.

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

#if defined(_WIN32)
#include <malloc.h>
#endif

#if defined(_MSC_VER) && !defined(__clang__)
#define WING_ALIGN_CACHE __declspec(align(128))
#include <windows.h>
#include <intrin.h>
#else
#define WING_ALIGN_CACHE __attribute__((aligned(128)))
#if __STDC_VERSION__ >= 201112L && !defined(__STDC_NO_ATOMICS__)
#include <stdatomic.h>
#endif
#endif

#define WING_CACHE_LINE 128

typedef struct {
    // Producer cache line (only written by producer thread)
    WING_ALIGN_CACHE volatile uint64_t tail;
    uint64_t cached_head;
    uint8_t pad_tail[WING_CACHE_LINE - 2 * sizeof(uint64_t)];

    // Consumer cache line (only written by consumer thread)
    WING_ALIGN_CACHE volatile uint64_t head;
    uint64_t cached_tail;
    uint8_t pad_head[WING_CACHE_LINE - 2 * sizeof(uint64_t)];

    // Read-only configuration cache line
    WING_ALIGN_CACHE uint32_t capacity;
    uint32_t mask;
    uint64_t *buffer;
} wing_spsc_ring_t;

static inline uint64_t spsc_load_relaxed(const volatile uint64_t *p) {
#if defined(_MSC_VER) && !defined(__clang__)
#if defined(_M_X64) || defined(_M_ARM64)
    return (uint64_t)ReadNoFence64((const volatile LONG64 *)p);
#else
    return (uint64_t)_InterlockedOr64((volatile LONG64 *)p, 0);
#endif
#else
    return __atomic_load_n(p, __ATOMIC_RELAXED);
#endif
}

static inline uint64_t spsc_load_acquire(const volatile uint64_t *p) {
#if defined(_MSC_VER) && !defined(__clang__)
#if defined(_M_ARM64)
    return (uint64_t)__ldar64((const volatile unsigned __int64 *)p);
#elif defined(_M_X64)
    return (uint64_t)ReadAcquire64((const volatile LONG64 *)p);
#else
    return (uint64_t)_InterlockedOr64((volatile LONG64 *)p, 0);
#endif
#else
    return __atomic_load_n(p, __ATOMIC_ACQUIRE);
#endif
}

static inline void spsc_store_release(volatile uint64_t *p, uint64_t v) {
#if defined(_MSC_VER) && !defined(__clang__)
#if defined(_M_ARM64)
    __stlr64((volatile unsigned __int64 *)p, v);
#elif defined(_M_X64)
    WriteRelease64((volatile LONG64 *)p, (LONG64)v);
#else
    (void)_InterlockedExchange64((volatile LONG64 *)p, (LONG64)v);
#endif
#else
    __atomic_store_n(p, v, __ATOMIC_RELEASE);
#endif
}

static uint32_t next_pow2_u32(uint32_t n) {
    if (n <= 2) return 2;
    n--;
    n |= n >> 1;
    n |= n >> 2;
    n |= n >> 4;
    n |= n >> 8;
    n |= n >> 16;
    return n + 1;
}

int32_t wing_spsc_create(uint32_t min_capacity, uint64_t *out_handle, uint32_t *out_capacity) {
    if (!out_handle || !out_capacity || min_capacity == 0 || min_capacity > 0x40000000u) {
        return -1;
    }

    uint32_t cap = next_pow2_u32(min_capacity);
    if (cap < 16) cap = 16;

    wing_spsc_ring_t *ring = NULL;
#if defined(_WIN32)
    ring = (wing_spsc_ring_t *)_aligned_malloc(sizeof(wing_spsc_ring_t), WING_CACHE_LINE);
    if (ring) memset(ring, 0, sizeof(wing_spsc_ring_t));
#elif defined(__wasm__)
    ring = (wing_spsc_ring_t *)calloc(1, sizeof(wing_spsc_ring_t));
#else
    if (posix_memalign((void **)&ring, WING_CACHE_LINE, sizeof(wing_spsc_ring_t)) != 0) {
        ring = NULL;
    } else {
        memset(ring, 0, sizeof(wing_spsc_ring_t));
    }
#endif
    if (!ring) return -2;

    ring->buffer = (uint64_t *)calloc(cap, sizeof(uint64_t));
    if (!ring->buffer) {
#if defined(_WIN32)
        _aligned_free(ring);
#else
        free(ring);
#endif
        return -3;
    }

    ring->capacity = cap;
    ring->mask = cap - 1;
    ring->tail = 0;
    ring->cached_head = 0;
    ring->head = 0;
    ring->cached_tail = 0;

    *out_handle = (uint64_t)(uintptr_t)ring;
    *out_capacity = cap;
    return 0;
}

void wing_spsc_destroy(uint64_t handle) {
    if (handle == 0) return;
    wing_spsc_ring_t *ring = (wing_spsc_ring_t *)(uintptr_t)handle;
    if (!ring) return;

    if (ring->buffer) {
        free(ring->buffer);
        ring->buffer = NULL;
    }
#if defined(_WIN32)
    _aligned_free(ring);
#else
    free(ring);
#endif
}

int32_t wing_spsc_push(uint64_t handle, uint64_t value) {
    if (handle == 0) return -1;
    wing_spsc_ring_t *ring = (wing_spsc_ring_t *)(uintptr_t)handle;
    if (!ring || !ring->buffer) return -2;

    uint64_t tail = spsc_load_relaxed(&ring->tail);
    if (tail - ring->cached_head >= ring->capacity) {
        ring->cached_head = spsc_load_acquire(&ring->head);
        if (tail - ring->cached_head >= ring->capacity) {
            return -3; // Queue is full
        }
    }

    ring->buffer[tail & ring->mask] = value;
    spsc_store_release(&ring->tail, tail + 1);

    return 0; // Success
}

int32_t wing_spsc_pop(uint64_t handle, uint64_t *out_value) {
    if (handle == 0 || !out_value) return -1;
    wing_spsc_ring_t *ring = (wing_spsc_ring_t *)(uintptr_t)handle;
    if (!ring || !ring->buffer) return -2;

    uint64_t head = spsc_load_relaxed(&ring->head);
    if (head == ring->cached_tail) {
        ring->cached_tail = spsc_load_acquire(&ring->tail);
        if (head == ring->cached_tail) {
            return -3; // Queue is empty
        }
    }

    *out_value = ring->buffer[head & ring->mask];
    spsc_store_release(&ring->head, head + 1);

    return 0; // Success
}

uint32_t wing_spsc_count(uint64_t handle) {
    if (handle == 0) return 0;
    wing_spsc_ring_t *ring = (wing_spsc_ring_t *)(uintptr_t)handle;
    if (!ring) return 0;

    uint64_t tail = spsc_load_acquire(&ring->tail);
    uint64_t head = spsc_load_acquire(&ring->head);

    return (uint32_t)(tail - head);
}

uint32_t wing_spsc_available(uint64_t handle) {
    if (handle == 0) return 0;
    wing_spsc_ring_t *ring = (wing_spsc_ring_t *)(uintptr_t)handle;
    if (!ring) return 0;

    uint32_t count = wing_spsc_count(handle);
    return (count < ring->capacity) ? (ring->capacity - count) : 0;
}
