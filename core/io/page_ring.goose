// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Hardware Virtual Memory Page-Mirrored Ring Buffer.
// Maps contiguous physical pages twice: [0..cap) and [cap..2*cap) alias identical memory.
// Eliminates buffer wraparound splitting and memmove compaction during streaming network I/O.
namespace core;

import std;
import core.io.types;

// Native C shims (shim/page_ring.c)
extern fn native_page_ring_create(
    min_capacity: u32,
    out_handle:   u64&,
    out_capacity: u32&,
) -> i32 = "wing_page_ring_create";

extern fn native_page_ring_destroy(handle: u64) = "wing_page_ring_destroy";

extern fn native_page_ring_peek(
    handle:      u64,
    head_offset: u64,
    dst:         u8[:],
) -> i64 = "wing_page_ring_peek";

extern fn native_page_ring_recv(
    handle:      u64,
    tail_offset: u64,
    max_len:     u32,
    sock_fd:     i64,
    timeout_ms:  u32,
) -> i32 = "wing_page_ring_recv";

// Page-mirrored ring buffer state descriptor.
struct PageRingBuffer {
    handle:   u64  = 0,
    capacity: u32  = 0,
    head:     u64  = 0,
    tail:     u64  = 0,
    count:    u64  = 0,
    is_open:  bool = false,
}

// Allocates hardware page-mirrored buffer with at least min_cap bytes.
fn page_ring_init(pr: PageRingBuffer&, min_cap: u32 = 65536) -> bool {
    guard min_cap > 0 && min_cap <= 0x7FFF0000 else { return false; }
    var h: u64 = 0;
    var c: u32 = 0;
    let rc = native_page_ring_create(min_cap, h, c);
    guard rc == 0 else { return false; }

    if pr.is_open && pr.handle != 0 {
        native_page_ring_destroy(pr.handle);
    }
    pr.handle = h;
    pr.capacity = c;
    pr.head = 0;
    pr.tail = 0;
    pr.count = 0;
    pr.is_open = true;
    return true;
}

// Releases virtual memory mappings and closes descriptor.
fn page_ring_close(pr: PageRingBuffer&) {
    if pr.is_open && pr.handle != 0 {
        native_page_ring_destroy(pr.handle);
    }
    pr.handle = 0;
    pr.capacity = 0;
    pr.head = 0;
    pr.tail = 0;
    pr.count = 0;
    pr.is_open = false;
}

// Returns number of available bytes before buffer is full.
inline fn page_ring_available(pr: const PageRingBuffer&) -> i64 {
    guard pr.is_open && pr.count < pr.capacity else { return 0; }
    return (pr.capacity - pr.count) as i64;
}

// Resets read and write cursors without reallocating virtual memory.
fn page_ring_clear(pr: PageRingBuffer&) {
    pr.head = 0;
    pr.tail = 0;
    pr.count = 0;
}

inline fn ring_advance_cursor(current_pos: u64, delta: u64, ring_cap: u32) -> u64 {
    guard ring_cap > 0 else { return 0; }
    let cap = ring_cap as u64;
    return ((current_pos % cap) + (delta % cap)) % cap;
}

// Inspects bytes without advancing read cursor.
fn page_ring_peek(pr: const PageRingBuffer&, dst: u8[:]) -> i64 {
    guard pr.is_open && pr.count > 0 && dst.len > 0 else { return 0; }
    let to_read = min(dst.len, pr.count as i64);
    return native_page_ring_peek(pr.handle, pr.head, dst[..to_read]);
}

// Advances read cursor, discarding n bytes.
fn page_ring_discard(pr: PageRingBuffer&, n: i64) -> i64 {
    guard pr.is_open && n > 0 && pr.count > 0 else { return 0; }
    let to_drop = min(n, pr.count as i64) as u64;
    pr.head = ring_advance_cursor(pr.head, to_drop, pr.capacity);
    pr.count -= to_drop;
    return to_drop as i64;
}

// Directly receives incoming TCP socket octets into the mirrored pages.
fn page_ring_recv(
    pr:         PageRingBuffer&,
    sock_fd:    i64,
    max_len:    u32 = 0,
    timeout_ms: u32 = 0,
) -> i32 {
    guard pr.is_open && sock_fd >= 0 else { return -1; }
    let avail = page_ring_available(pr);
    guard avail > 0 else { return -1; }

    let limit = if max_len > 0 { min(max_len, avail as u32) } else { avail as u32 };
    let recvd = native_page_ring_recv(pr.handle, pr.tail, limit, sock_fd, timeout_ms);
    if recvd > 0 {
        pr.tail = ring_advance_cursor(pr.tail, recvd as u64, pr.capacity);
        pr.count += recvd as u64;
    }
    return recvd;
}
