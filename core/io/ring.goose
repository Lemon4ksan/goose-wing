// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Zero-heap circular FIFO ring buffer.
// Enables streaming producer-consumer pipelines without memmove / memory shifting.
namespace core;

import std;
import core.io.types;

struct RingBuffer {
    storage: u8[4096] = [0; 4096],
    head:    i64      = 0, // Read position
    tail:    i64      = 0, // Write position
    count:   i64      = 0, // Current bytes stored
}

fn new_ring_buffer() -> RingBuffer {
    return RingBuffer {
        storage: [0; 4096],
        head:    0,
        tail:    0,
        count:   0,
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
// Uses two-chunk block copies to eliminate byte-by-byte loop overhead.
// Returns (bytes_written, IoError).
fn write(rb: RingBuffer&, src: const u8[:]) -> i64, IoError {
    guard src.len > 0 else { return 0, IoError.None; }
    let avail = available(rb);
    if avail == 0 {
        return 0, IoError.BufferFull;
    }
    let to_write = min(src.len, avail);
    let first_chunk = min(4096 - rb.tail, to_write);
    for i in first_chunk {
        rb.storage[rb.tail + i] = src[i];
    }
    let second_chunk = to_write - first_chunk;
    for i in second_chunk {
        rb.storage[i] = src[first_chunk + i];
    }
    rb.tail = (rb.tail + to_write) % 4096;
    rb.count += to_write;
    return to_write, if to_write < src.len { IoError.ShortWrite } else { IoError.None };
}

// Reads and consumes bytes from the ring buffer into dst.
// Automatically resets head and tail to 0 when buffer empties, eliminating artificial fragmentation.
// Returns (bytes_read, IoError).
fn read(rb: RingBuffer&, dst: u8[:]) -> i64, IoError {
    guard dst.len > 0 else { return 0, IoError.None; }
    if is_empty(rb) {
        return 0, IoError.Eof;
    }
    let to_read = min(dst.len, rb.count);
    let first_chunk = min(4096 - rb.head, to_read);
    for i in first_chunk {
        dst[i] = rb.storage[rb.head + i];
    }
    let second_chunk = to_read - first_chunk;
    for i in second_chunk {
        dst[first_chunk + i] = rb.storage[i];
    }
    rb.head = (rb.head + to_read) % 4096;
    rb.count -= to_read;
    if rb.count == 0 {
        rb.head = 0;
        rb.tail = 0;
    }
    return to_read, IoError.None;
}

// Peeks at bytes without advancing head.
fn peek(rb: const RingBuffer&, dst: u8[:]) -> i64 {
    guard dst.len > 0 else { return 0; }
    if is_empty(rb) {
        return 0;
    }
    let to_peek = min(dst.len, rb.count);
    let first_chunk = min(4096 - rb.head, to_peek);
    for i in first_chunk {
        dst[i] = rb.storage[rb.head + i];
    }
    let second_chunk = to_peek - first_chunk;
    for i in second_chunk {
        dst[first_chunk + i] = rb.storage[i];
    }
    return to_peek;
}

// Discards n bytes from the front of the ring buffer.
// Resets head and tail to 0 when count reaches 0 to avoid artificial fragmentation.
fn discard(rb: RingBuffer&, n: i64) -> i64 {
    guard n > 0 else { return 0; }
    let to_drop = min(n, rb.count);
    rb.head = (rb.head + to_drop) % 4096;
    rb.count -= to_drop;
    if rb.count == 0 {
        rb.head = 0;
        rb.tail = 0;
    }
    return to_drop;
}

// Yields the contiguous unread byte slices from the ring buffer without copying.
// When wrapped around the buffer boundary, returns (head_to_end, start_to_tail).
// When contiguous (no wrap), returns (head_to_tail, "").
fn read_slices(rb: const RingBuffer&) -> const u8[:], const u8[:] {
    guard rb.count > 0 else { return "", ""; }
    if rb.head + rb.count <= 4096 {
        return rb.storage[rb.head..rb.head + rb.count], "";
    }
    let first_len = 4096 - rb.head;
    let second_len = rb.count - first_len;
    return rb.storage[rb.head..4096], rb.storage[..second_len];
}

// Yields writable slice spans for zero-copy socket / transport receiving.
// Returns (first_span, second_span) representing available tail and wrapped capacity.
fn write_slices(rb: RingBuffer&) -> u8[:], u8[:] {
    let avail = available(rb);
    guard avail > 0 else { return rb.storage[..0], rb.storage[..0]; }
    if rb.tail >= rb.head && rb.count > 0 {
        let first_len = 4096 - rb.tail;
        let second_len = avail - first_len;
        if second_len > 0 {
            return rb.storage[rb.tail..4096], rb.storage[..second_len];
        }
        return rb.storage[rb.tail..rb.tail + avail], rb.storage[..0];
    }
    if rb.count == 0 {
        rb.head = 0;
        rb.tail = 0;
        return rb.storage[..4096], rb.storage[..0];
    }
    return rb.storage[rb.tail..rb.tail + avail], rb.storage[..0];
}

// Commits n bytes written into the ring buffer via zero-copy write spans.
fn commit_written(rb: RingBuffer&, n: i64) -> IoError {
    guard n >= 0 else { return IoError.InvalidArgument; }
    guard n <= available(rb) else { return IoError.BufferFull; }
    guard n > 0 else { return IoError.None; }
    rb.tail = (rb.tail + n) % 4096;
    rb.count += n;
    return IoError.None;
}

// Yields the largest single contiguous readable slice starting from head.
fn contiguous_readable(rb: const RingBuffer&) -> const u8[:] {
    let s1, _ = read_slices(rb);
    return s1;
}
