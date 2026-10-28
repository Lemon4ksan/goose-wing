// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Zero-heap circular FIFO ring buffer.
// Enables streaming producer-consumer pipelines without memmove / memory shifting.
namespace core;

import std;
import core.io.types;

struct RingBuffer {
    storage: u8[4096] = [0; 4096],
    head: i64 = 0, // Read position
    tail: i64 = 0, // Write position
    count: i64 = 0, // Current bytes stored
}

fn new_ring_buffer() -> RingBuffer {
    return RingBuffer {
        storage: [0; 4096],
        head: 0,
        tail: 0,
        count: 0,
    };
}

fn len(rb: const RingBuffer&) -> i64 {
    return rb.count;
}

fn cap(rb: const RingBuffer&) -> i64 {
    return 4096;
}

fn available(rb: const RingBuffer&) -> i64 {
    return 4096 - rb.count;
}

fn is_empty(rb: const RingBuffer&) -> bool {
    return rb.count == 0;
}

fn is_full(rb: const RingBuffer&) -> bool {
    return rb.count >= 4096;
}

fn clear(rb: RingBuffer&) {
    rb.head = 0;
    rb.tail = 0;
    rb.count = 0;
}

// Writes bytes into the ring buffer up to available space.
// Returns (bytes_written, IoError).
fn write(rb: RingBuffer&, src: const u8[:]) -> i64, IoError {
    guard src.len > 0 else { return 0, IoError.None; }
    let avail = available(rb);
    if avail == 0 {
        return 0, IoError.BufferFull;
    }
    let to_write = if src.len < avail { src.len } else { avail };
    for i in to_write {
        rb.storage[rb.tail] = src[i];
        rb.tail = (rb.tail + 1) % 4096;
    }
    rb.count += to_write;
    return to_write, if to_write < src.len { IoError.ShortWrite } else { IoError.None };
}

// Reads and consumes bytes from the ring buffer into dst.
// Returns (bytes_read, IoError).
fn read(rb: RingBuffer&, dst: u8[:]) -> i64, IoError {
    guard dst.len > 0 else { return 0, IoError.None; }
    if is_empty(rb) {
        return 0, IoError.Eof;
    }
    let to_read = if dst.len < rb.count { dst.len } else { rb.count };
    for i in to_read {
        dst[i] = rb.storage[rb.head];
        rb.head = (rb.head + 1) % 4096;
    }
    rb.count -= to_read;
    return to_read, IoError.None;
}

// Peeks at bytes without advancing head.
fn peek(rb: const RingBuffer&, dst: u8[:]) -> i64 {
    guard dst.len > 0 else { return 0; }
    if is_empty(rb) {
        return 0;
    }
    let to_peek = if dst.len < rb.count { dst.len } else { rb.count };
    var curr = rb.head;
    for i in to_peek {
        dst[i] = rb.storage[curr];
        curr = (curr + 1) % 4096;
    }
    return to_peek;
}

// Discards n bytes from the front of the ring buffer.
fn discard(rb: RingBuffer&, n: i64) -> i64 {
    guard n > 0 else { return 0; }
    let to_drop = if n < rb.count { n } else { rb.count };
    rb.head = (rb.head + to_drop) % 4096;
    rb.count -= to_drop;
    return to_drop;
}
