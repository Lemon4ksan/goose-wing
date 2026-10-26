// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Zero-heap, zero-allocation 16 KB outbound write corking buffer.
// Aggregates small frames and header fragments into a single 16384-byte buffer
// before flushing via vectored I/O (writev / WSASend), matching uWebSockets & sockudo-ws patterns.
namespace core;

import std;
import core.io.types;

const CORK_BUFFER_CAP: i64 = 16384; // 16 KB standard cork buffer size

struct CorkBuffer {
    storage: u8[16384] = [0; 16384],
    len: i64 = 0,
    is_corked: bool = true,
}

fn new_cork_buffer() -> CorkBuffer {
    return CorkBuffer {
        storage: [0; 16384],
        len: 0,
        is_corked: true,
    };
}

// Returns the number of buffered bytes waiting to be flushed.
fn cork_pending(cb: const CorkBuffer&) -> i64 {
    return cb.len;
}

// Returns remaining available capacity in the cork buffer.
fn cork_available(cb: const CorkBuffer&) -> i64 {
    let rem = CORK_BUFFER_CAP - cb.len;
    return if rem > 0 { rem } else { 0 };
}

fn cork_is_empty(cb: const CorkBuffer&) -> bool {
    return cb.len == 0;
}

fn cork_is_full(cb: const CorkBuffer&) -> bool {
    return cb.len >= CORK_BUFFER_CAP;
}

// Yields buffered bytes as a contiguous slice for sending.
fn cork_as_slice(cb: const CorkBuffer&) -> const u8[:] {
    let end = cb.len;
    return cb.storage[..end];
}

// Writes a slice into the cork buffer. Returns (bytes_written, IoError).
fn cork_write(cb: CorkBuffer&, src: const u8[:]) -> i64, IoError {
    guard src.len > 0 else { return 0, IoError.None; }
    let avail = cork_available(cb);
    if avail == 0 {
        return 0, IoError.BufferFull;
    }
    let to_copy = if src.len < avail { src.len } else { avail };
    for i in to_copy {
        cb.storage[cb.len + i] = src[i];
    }
    cb.len += to_copy;
    return to_copy, if to_copy < src.len { IoError.ShortWrite } else { IoError.None };
}

// Writes exactly src.len bytes, failing with BufferFull if capacity is insufficient.
fn cork_write_exact(cb: CorkBuffer&, src: const u8[:]) -> IoError {
    guard cork_available(cb) >= src.len else {
        return IoError.BufferFull;
    }
    for i in src.len {
        cb.storage[cb.len + i] = src[i];
    }
    cb.len += src.len;
    return IoError.None;
}

// Appends single byte to cork buffer.
fn cork_write_u8(cb: CorkBuffer&, b: u8) -> IoError {
    guard cork_available(cb) >= 1 else {
        return IoError.BufferFull;
    }
    cb.storage[cb.len] = b;
    cb.len += 1;
    return IoError.None;
}

// Appends 16-bit integer in Big-Endian wire order.
fn cork_write_u16_be(cb: CorkBuffer&, v: u16) -> IoError {
    guard cork_available(cb) >= 2 else {
        return IoError.BufferFull;
    }
    cb.storage[cb.len] = ((v >> 8) & 0xFF) as u8;
    cb.storage[cb.len + 1] = (v & 0xFF) as u8;
    cb.len += 2;
    return IoError.None;
}

// Appends 24-bit integer in Big-Endian wire order (RFC 9113 HTTP/2 framing).
fn cork_write_u24_be(cb: CorkBuffer&, v: u32) -> IoError {
    guard cork_available(cb) >= 3 else {
        return IoError.BufferFull;
    }
    cb.storage[cb.len] = ((v >> 16) & 0xFF) as u8;
    cb.storage[cb.len + 1] = ((v >> 8) & 0xFF) as u8;
    cb.storage[cb.len + 2] = (v & 0xFF) as u8;
    cb.len += 3;
    return IoError.None;
}

// Appends 32-bit integer in Big-Endian wire order.
fn cork_write_u32_be(cb: CorkBuffer&, v: u32) -> IoError {
    guard cork_available(cb) >= 4 else {
        return IoError.BufferFull;
    }
    cb.storage[cb.len] = ((v >> 24) & 0xFF) as u8;
    cb.storage[cb.len + 1] = ((v >> 16) & 0xFF) as u8;
    cb.storage[cb.len + 2] = ((v >> 8) & 0xFF) as u8;
    cb.storage[cb.len + 3] = (v & 0xFF) as u8;
    cb.len += 4;
    return IoError.None;
}

// Appends 64-bit integer in Big-Endian wire order.
fn cork_write_u64_be(cb: CorkBuffer&, v: u64) -> IoError {
    guard cork_available(cb) >= 8 else {
        return IoError.BufferFull;
    }
    cb.storage[cb.len] = ((v >> 56) & 0xFF) as u8;
    cb.storage[cb.len + 1] = ((v >> 48) & 0xFF) as u8;
    cb.storage[cb.len + 2] = ((v >> 40) & 0xFF) as u8;
    cb.storage[cb.len + 3] = ((v >> 32) & 0xFF) as u8;
    cb.storage[cb.len + 4] = ((v >> 24) & 0xFF) as u8;
    cb.storage[cb.len + 5] = ((v >> 16) & 0xFF) as u8;
    cb.storage[cb.len + 6] = ((v >> 8) & 0xFF) as u8;
    cb.storage[cb.len + 7] = (v & 0xFF) as u8;
    cb.len += 8;
    return IoError.None;
}

// Consumes n bytes from the front of the cork buffer (e.g. after a partial socket send).
fn cork_consume(cb: CorkBuffer&, n: i64) {
    guard n > 0 else { return; }
    if n >= cb.len {
        cb.len = 0;
        return;
    }
    let remaining = cb.len - n;
    for i in remaining {
        cb.storage[i] = cb.storage[n + i];
    }
    cb.len = remaining;
}

// Clears/resets the cork buffer for reuse.
fn cork_reset(cb: CorkBuffer&) {
    cb.len = 0;
    cb.is_corked = true;
}

// Generic appendable buffer interface implementations (matching u8[..N] & u8[>..])
fn append(cb: CorkBuffer&, src: const u8[:]) {
    cork_write(cb, src);
}

fn push(cb: CorkBuffer&, b: u8) {
    cork_write_u8(cb, b);
}

fn clear(cb: CorkBuffer&) {
    cork_reset(cb);
}
