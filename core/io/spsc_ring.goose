// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Cache-Line Aligned Lock-Free Single-Producer Single-Consumer (SPSC) Ring Queue.
// Eliminates False Sharing via 64-byte L1 cache-line padding between producer and consumer cursors.
// Employs acquire-release atomic memory orderings for zero-mutex inter-thread messaging.
namespace core;

import std;

extern fn native_spsc_create(
    min_capacity: u32,
    out_handle:   u64&,
    out_capacity: u32&,
) -> i32 = "wing_spsc_create";

extern fn native_spsc_destroy(handle: u64) = "wing_spsc_destroy";

extern fn native_spsc_push(
    handle: u64,
    val:    u64,
) -> i32 = "wing_spsc_push";

extern fn native_spsc_pop(
    handle:  u64,
    out_val: u64&,
) -> i32 = "wing_spsc_pop";

extern fn native_spsc_count(handle: u64) -> u32 = "wing_spsc_count";

extern fn native_spsc_available(handle: u64) -> u32 = "wing_spsc_available";

// Lock-free SPSC ring queue descriptor.
struct SpscRing {
    handle:   u64  = 0,
    capacity: u32  = 0,
    is_open:  bool = false,
}

// Initializes a cache-line aligned SPSC ring queue with capacity rounded to next power of 2.
fn spsc_init(min_capacity: u32) -> SpscRing, bool {
    guard min_capacity > 0 && min_capacity <= 0x40000000 else {
        return SpscRing {}, false;
    }

    var handle:     u64 = 0;
    var actual_cap: u32 = 0;
    let rc = native_spsc_create(min_capacity, handle, actual_cap);
    guard rc == 0 && handle != 0 else {
        return SpscRing {}, false;
    }

    return SpscRing {
        handle:   handle,
        capacity: actual_cap,
        is_open:  true,
    }, true;
}

// Releases ring queue memory buffers.
fn spsc_close(ring: SpscRing&) {
    if ring.is_open && ring.handle != 0 {
        native_spsc_destroy(ring.handle);
        ring.handle = 0;
        ring.capacity = 0;
        ring.is_open = false;
    }
}

// Pushes a 64-bit value into the queue using release memory ordering.
// Returns false if queue is full.
fn spsc_push(ring: const SpscRing&, val: u64) -> bool {
    guard ring.is_open && ring.handle != 0 else {
        return false;
    }

    let rc = native_spsc_push(ring.handle, val);
    return rc == 0;
}

// Pops a 64-bit value from the queue using acquire memory ordering.
// Returns false if queue is empty.
fn spsc_pop(ring: const SpscRing&, out_val: u64&) -> bool {
    guard ring.is_open && ring.handle != 0 else {
        return false;
    }

    let rc = native_spsc_pop(ring.handle, out_val);
    return rc == 0;
}

// Returns the number of currently queued items.
inline fn spsc_count(ring: const SpscRing&) -> u32 {
    guard ring.is_open && ring.handle != 0 else {
        return 0;
    }
    return native_spsc_count(ring.handle);
}

// Returns the remaining vacant slots in the queue.
inline fn spsc_available(ring: const SpscRing&) -> u32 {
    guard ring.is_open && ring.handle != 0 else {
        return 0;
    }
    return native_spsc_available(ring.handle);
}
