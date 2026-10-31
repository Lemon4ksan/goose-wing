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

extern fn native_page_ring_write(
    handle:      u64,
    tail_offset: u64,
    src:         const u8[:],
) -> i64 = "wing_page_ring_write";

extern fn native_page_ring_read(
    handle:      u64,
    head_offset: u64,
    dst:         u8[:],
) -> i64 = "wing_page_ring_read";

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

extern fn native_page_ring_send(
    handle:      u64,
    head_offset: u64,
    len:         u32,
    sock_fd:     i64,
) -> i32 = "wing_page_ring_send";

extern fn native_page_ring_find_crlf(
    handle:      u64,
    head_offset: u64,
    len:         u32,
) -> i64 = "wing_page_ring_find_crlf";

extern fn native_page_ring_find_crlfcrlf(
    handle:      u64,
    head_offset: u64,
    len:         u32,
) -> i64 = "wing_page_ring_find_crlfcrlf";

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
    var h: u64 = 0;
    var c: u32 = 0;
    let rc = native_page_ring_create(min_cap, h, c);
    guard rc == 0 else { return false; }

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
    let rem = pr.capacity - (pr.count as i64);
    return if rem > 0 { rem } else { 0 };
}

inline fn page_ring_is_empty(pr: const PageRingBuffer&) -> bool {
    return pr.count == 0;
}

inline fn page_ring_is_full(pr: const PageRingBuffer&) -> bool {
    return pr.count >= pr.capacity;
}

// Resets read and write cursors without reallocating virtual memory.
fn page_ring_clear(pr: PageRingBuffer&) {
    pr.head = 0;
    pr.tail = 0;
    pr.count = 0;
}

inline fn ring_bounded_span(requested: i64, ceiling: i64) -> i64 {
    return if requested < ceiling { requested } else { ceiling };
}

inline fn ring_bounded_u32(requested: u32, ceiling: u32) -> u32 {
    return if requested < ceiling { requested } else { ceiling };
}

inline fn ring_advance_cursor(current_pos: u64, delta: u64, ring_cap: u32) -> u64 {
    guard ring_cap > 0 else { return 0; }
    return (current_pos + delta) % ring_cap;
}

// Writes bytes into the page-mirrored ring buffer without boundary wrapping logic.
fn page_ring_write(pr: PageRingBuffer&, src: const u8[:]) -> i64, IoError {
    guard pr.is_open else { return 0, IoError.Closed; }
    let avail = page_ring_available(pr);
    guard src.len > 0 && avail > 0 else {
        return 0, if avail == 0 { IoError.BufferFull } else { IoError.None };
    }

    let to_write = ring_bounded_span(src.len, avail);
    let written = native_page_ring_write(pr.handle, pr.tail, src[..to_write]);
    guard written > 0 else { return 0, IoError.ShortWrite; }

    pr.tail = ring_advance_cursor(pr.tail, written as u64, pr.capacity);
    pr.count += written as u64;
    return written, if written < src.len { IoError.ShortWrite } else { IoError.None };
}

// Reads and consumes bytes from the page-mirrored ring buffer.
fn page_ring_read(pr: PageRingBuffer&, dst: u8[:]) -> i64, IoError {
    guard pr.is_open else { return 0, IoError.Closed; }
    guard dst.len > 0 else { return 0, IoError.None; }
    guard pr.count > 0 else { return 0, IoError.Eof; }

    let to_read = ring_bounded_span(dst.len, pr.count as i64);
    let n = native_page_ring_read(pr.handle, pr.head, dst[..to_read]);
    guard n > 0 else { return 0, IoError.None; }

    pr.head = ring_advance_cursor(pr.head, n as u64, pr.capacity);
    pr.count -= n as u64;
    return n, IoError.None;
}

// Inspects bytes without advancing read cursor.
fn page_ring_peek(pr: const PageRingBuffer&, dst: u8[:]) -> i64 {
    guard pr.is_open && pr.count > 0 && dst.len > 0 else { return 0; }
    let to_read = ring_bounded_span(dst.len, pr.count as i64);
    return native_page_ring_peek(pr.handle, pr.head, dst[..to_read]);
}

// Advances read cursor, discarding n bytes.
fn page_ring_discard(pr: PageRingBuffer&, n: i64) -> i64 {
    guard pr.is_open && n > 0 && pr.count > 0 else { return 0; }
    let to_drop = ring_bounded_span(n, pr.count as i64) as u64;
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
    guard pr.is_open && sock_fd > 0 else { return -1; }
    let avail = page_ring_available(pr);
    guard avail > 0 else { return 0; }

    let limit = if max_len > 0 { ring_bounded_u32(max_len, avail as u32) } else { avail as u32 };
    let recvd = native_page_ring_recv(pr.handle, pr.tail, limit, sock_fd, timeout_ms);
    if recvd > 0 {
        pr.tail = ring_advance_cursor(pr.tail, recvd as u64, pr.capacity);
        pr.count += recvd as u64;
    }
    return recvd;
}

// Directly sends buffered octets from mirrored pages to TCP socket in a single write call.
fn page_ring_send(
    pr:      PageRingBuffer&,
    sock_fd: i64,
    max_len: u32 = 0,
) -> i32 {
    guard pr.is_open && sock_fd > 0 && pr.count > 0 else { return 0; }
    let c = pr.count as u32;
    let to_send = if max_len > 0 { ring_bounded_u32(max_len, c) } else { c };
    let sent = native_page_ring_send(pr.handle, pr.head, to_send, sock_fd);
    if sent > 0 {
        pr.head = ring_advance_cursor(pr.head, sent as u64, pr.capacity);
        pr.count -= sent as u64;
    }
    return sent;
}

// Scans active readable data for CRLF delimiter using vectorized scanner.
fn page_ring_find_crlf(pr: const PageRingBuffer&) -> i64 {
    guard pr.is_open && pr.count >= 2 else { return -1; }
    return native_page_ring_find_crlf(pr.handle, pr.head, pr.count as u32);
}

// Scans active readable data for CRLFCRLF (\r\n\r\n) HTTP delimiter using AVX2/SSE2.
fn page_ring_find_crlfcrlf(pr: const PageRingBuffer&) -> i64 {
    guard pr.is_open && pr.count >= 4 else { return -1; }
    return native_page_ring_find_crlfcrlf(pr.handle, pr.head, pr.count as u32);
}
