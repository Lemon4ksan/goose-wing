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

#if defined(_MSC_VER)
#define WING_ALIGN64 __declspec(align(64))
#include <windows.h>
#else
#define WING_ALIGN64 __attribute__((aligned(64)))
#if __STDC_VERSION__ >= 201112L && !defined(__STDC_NO_ATOMICS__)
#include <stdatomic.h>
#endif
#endif

#define WING_CACHE_LINE 64

typedef struct {
    // Producer cache line (only written by producer thread)
    WING_ALIGN64 volatile uint64_t tail;
    uint8_t pad_tail[WING_CACHE_LINE - sizeof(uint64_t)];

    // Consumer cache line (only written by consumer thread)
    WING_ALIGN64 volatile uint64_t head;
    uint8_t pad_head[WING_CACHE_LINE - sizeof(uint64_t)];

    // Read-only configuration cache line
    WING_ALIGN64 uint32_t capacity;
    uint32_t mask;
    uint64_t *buffer;
} wing_spsc_ring_t;

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
    if (!out_handle || !out_capacity || min_capacity == 0) {
        return -1;
    }

    uint32_t cap = next_pow2_u32(min_capacity);
    if (cap < 16) cap = 16;

    wing_spsc_ring_t *ring = (wing_spsc_ring_t *)calloc(1, sizeof(wing_spsc_ring_t));
    if (!ring) return -2;

    ring->buffer = (uint64_t *)calloc(cap, sizeof(uint64_t));
    if (!ring->buffer) {
        free(ring);
        return -3;
    }

    ring->capacity = cap;
    ring->mask = cap - 1;
    ring->tail = 0;
    ring->head = 0;

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
    free(ring);
}

int32_t wing_spsc_push(uint64_t handle, uint64_t value) {
    if (handle == 0) return -1;
    wing_spsc_ring_t *ring = (wing_spsc_ring_t *)(uintptr_t)handle;
    if (!ring || !ring->buffer) return -2;

#if defined(_MSC_VER)
    uint64_t tail = ring->tail;
    uint64_t head = ring->head;
    _ReadWriteBarrier();
#else
    uint64_t tail = __atomic_load_n(&ring->tail, __ATOMIC_RELAXED);
    uint64_t head = __atomic_load_n(&ring->head, __ATOMIC_ACQUIRE);
#endif

    if (tail - head >= ring->capacity) {
        return -3; // Queue is full
    }

    ring->buffer[tail & ring->mask] = value;

#if defined(_MSC_VER)
    _ReadWriteBarrier();
    ring->tail = tail + 1;
#else
    __atomic_store_n(&ring->tail, tail + 1, __ATOMIC_RELEASE);
#endif

    return 0; // Success
}

int32_t wing_spsc_pop(uint64_t handle, uint64_t *out_value) {
    if (handle == 0 || !out_value) return -1;
    wing_spsc_ring_t *ring = (wing_spsc_ring_t *)(uintptr_t)handle;
    if (!ring || !ring->buffer) return -2;

#if defined(_MSC_VER)
    uint64_t head = ring->head;
    uint64_t tail = ring->tail;
    _ReadWriteBarrier();
#else
    uint64_t head = __atomic_load_n(&ring->head, __ATOMIC_RELAXED);
    uint64_t tail = __atomic_load_n(&ring->tail, __ATOMIC_ACQUIRE);
#endif

    if (head == tail) {
        return -3; // Queue is empty
    }

    *out_value = ring->buffer[head & ring->mask];

#if defined(_MSC_VER)
    _ReadWriteBarrier();
    ring->head = head + 1;
#else
    __atomic_store_n(&ring->head, head + 1, __ATOMIC_RELEASE);
#endif

    return 0; // Success
}

uint32_t wing_spsc_count(uint64_t handle) {
    if (handle == 0) return 0;
    wing_spsc_ring_t *ring = (wing_spsc_ring_t *)(uintptr_t)handle;
    if (!ring) return 0;

#if defined(_MSC_VER)
    uint64_t tail = ring->tail;
    uint64_t head = ring->head;
#else
    uint64_t tail = __atomic_load_n(&ring->tail, __ATOMIC_RELAXED);
    uint64_t head = __atomic_load_n(&ring->head, __ATOMIC_RELAXED);
#endif

    return (tail >= head) ? (uint32_t)(tail - head) : 0;
}

uint32_t wing_spsc_available(uint64_t handle) {
    if (handle == 0) return 0;
    wing_spsc_ring_t *ring = (wing_spsc_ring_t *)(uintptr_t)handle;
    if (!ring) return 0;

    uint32_t count = wing_spsc_count(handle);
    return (count < ring->capacity) ? (ring->capacity - count) : 0;
}
