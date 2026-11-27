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
    storage:   u8[16384] = [0; 16384],
    len:       i64       = 0,
    cap:       i64       = 16384,
    is_corked: bool      = true,
}

fn new_cork_buffer() -> CorkBuffer {
    return CorkBuffer {
        storage:   [0; 16384],
        len:       0,
        cap:       16384,
        is_corked: true,
    };
}

// Returns the number of buffered bytes waiting to be flushed.
inline fn cork_pending(cb: const CorkBuffer&) -> i64 {
    guard cb.len >= 0 else { return 0; }
    return cb.len;
}

// Returns remaining available capacity in the cork buffer.
inline fn cork_available(cb: const CorkBuffer&) -> i64 {
    return max(0, CORK_BUFFER_CAP - cb.len);
}

inline fn cork_is_empty(cb: const CorkBuffer&) -> bool {
    return cb.len == 0;
}

inline fn cork_is_full(cb: const CorkBuffer&) -> bool {
    return cb.len >= CORK_BUFFER_CAP;
}

// Yields buffered bytes as a contiguous slice for sending.
inline fn cork_as_slice(cb: const CorkBuffer&) -> const u8[:] {
    let end = clamp(cb.len, 0, CORK_BUFFER_CAP);
    return cb.storage[..end];
}

// Copies `src` into `dst[off..off + src.len]` using 64-bit word moves and a scalar tail.
inline fn copy_bytes_fast(dst: u8[:], off: i64, src: const u8[:]) {
    guard off >= 0 && src.len >= 0 && off <= dst.len - src.len else { return; }
    var i: i64 = 0;
    while i + 8 <= src.len {
        write_le_u64_at(dst, off + i, read_le_u64(src, i));
        i += 8;
    }
    while i < src.len {
        dst[off + i] = src[i];
        i += 1;
    }
}

// Writes a slice into the cork buffer. Returns (bytes_written, IoError).
inline fn cork_write(cb: CorkBuffer&, src: const u8[:]) -> i64, IoError {
    guard src.len > 0 else { return 0, IoError.None; }
    guard !cork_is_full(cb) else { return 0, IoError.BufferFull; }
    let avail = cork_available(cb);
    let to_copy = min(src.len, avail);
    copy_bytes_fast(cb.storage[..], cb.len, src[..to_copy]);
    cb.len += to_copy;
    return to_copy, if to_copy < src.len { IoError.ShortWrite } else { IoError.None };
}

// Writes exactly src.len bytes, failing with BufferFull if capacity is insufficient.
inline fn cork_write_exact(cb: CorkBuffer&, src: const u8[:]) -> IoError {
    guard cork_available(cb) >= src.len else {
        return IoError.BufferFull;
    }
    if src.len > 0 {
        copy_bytes_fast(cb.storage[..], cb.len, src);
        cb.len += src.len;
    }
    return IoError.None;
}

// Appends single byte to cork buffer.
fn cork_write_u8(cb: CorkBuffer&, b: u8) -> IoError {
    guard !cork_is_full(cb) else {
        return IoError.BufferFull;
    }
    cb.storage[cb.len] = b;
    cb.len += 1;
    return IoError.None;
}

// Appends 24-bit integer in Big-Endian wire order (RFC 9113 HTTP/2 framing).
fn cork_write_u24_be(cb: CorkBuffer&, v: u32) -> IoError {
    guard v <= 0xFFFFFF else {
        return IoError.InvalidArgument;
    }
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

fn resize(cb: CorkBuffer&, new_len: i64) {
    let clamped = clamp(new_len, 0, CORK_BUFFER_CAP);
    if clamped > cb.len {
        let safe_start = max(0, cb.len);
        for i in safe_start..clamped {
            cb.storage[i] = 0;
        }
    }
    cb.len = clamped;
}
