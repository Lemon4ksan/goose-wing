// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Zero-heap, zero-allocation slice stream writer.
// Serializes bytes and binary integers into fixed or caller-provided slices.
namespace core;

import std;
import core.io.types;

struct SliceWriter {
    buf: u8[:] = [],
    cursor: i64 = 0,
}

fn new_slice_writer(dest: u8[:]) -> SliceWriter {
    return SliceWriter {
        buf: dest,
        cursor: 0,
    };
}

fn available(w: const SliceWriter&) -> i64 {
    let rem = w.buf.len - w.cursor;
    return if rem > 0 { rem } else { 0 };
}

fn written(w: const SliceWriter&) -> i64 {
    return w.cursor;
}

fn reset(w: SliceWriter&) {
    w.cursor = 0;
}

// Yields sub-slice of bytes that have been written so far.
fn as_written_slice(w: const SliceWriter&) -> const u8[:] {
    let end = w.cursor;
    return w.buf[..end];
}

// Writes as many bytes from src as will fit.
// Returns (bytes_written, IoError).
fn write(w: SliceWriter&, src: const u8[:]) -> i64, IoError {
    let avail = available(w);
    if avail == 0 {
        return 0, IoError.BufferFull;
    }
    let to_copy = if src.len < avail { src.len } else { avail };
    for i in to_copy {
        w.buf[w.cursor + i] = src[i];
    }
    w.cursor += to_copy;
    return to_copy, if to_copy < src.len { IoError.ShortWrite } else { IoError.None };
}

// Writes exactly src.len bytes, failing with BufferFull if capacity is insufficient.
fn write_exact(w: SliceWriter&, src: const u8[:]) -> IoError {
    guard available(w) >= src.len else {
        return IoError.BufferFull;
    }
    for i in src.len {
        w.buf[w.cursor + i] = src[i];
    }
    w.cursor += src.len;
    return IoError.None;
}

// Writes single byte.
fn write_u8(w: SliceWriter&, b: u8) -> IoError {
    guard available(w) >= 1 else {
        return IoError.BufferFull;
    }
    w.buf[w.cursor] = b;
    w.cursor += 1;
    return IoError.None;
}

// Writes 16-bit integer in Big-Endian wire order.
fn write_u16_be(w: SliceWriter&, v: u16) -> IoError {
    guard available(w) >= 2 else {
        return IoError.BufferFull;
    }
    w.buf[w.cursor]     = ((v >> 8) & 0xFF) as u8;
    w.buf[w.cursor + 1] = (v & 0xFF) as u8;
    w.cursor += 2;
    return IoError.None;
}

// Writes 16-bit integer in Little-Endian order.
fn write_u16_le(w: SliceWriter&, v: u16) -> IoError {
    guard available(w) >= 2 else {
        return IoError.BufferFull;
    }
    w.buf[w.cursor]     = (v & 0xFF) as u8;
    w.buf[w.cursor + 1] = ((v >> 8) & 0xFF) as u8;
    w.cursor += 2;
    return IoError.None;
}

// Writes 24-bit integer in Big-Endian wire order (RFC 8446 TLS, RFC 9113 HTTP/2 framing).
fn write_u24_be(w: SliceWriter&, v: u32) -> IoError {
    guard available(w) >= 3 else {
        return IoError.BufferFull;
    }
    w.buf[w.cursor]     = ((v >> 16) & 0xFF) as u8;
    w.buf[w.cursor + 1] = ((v >> 8) & 0xFF) as u8;
    w.buf[w.cursor + 2] = (v & 0xFF) as u8;
    w.cursor += 3;
    return IoError.None;
}

// Writes 24-bit integer in Little-Endian order.
fn write_u24_le(w: SliceWriter&, v: u32) -> IoError {
    guard available(w) >= 3 else {
        return IoError.BufferFull;
    }
    w.buf[w.cursor]     = (v & 0xFF) as u8;
    w.buf[w.cursor + 1] = ((v >> 8) & 0xFF) as u8;
    w.buf[w.cursor + 2] = ((v >> 16) & 0xFF) as u8;
    w.cursor += 3;
    return IoError.None;
}

// Writes 32-bit integer in Big-Endian wire order.
fn write_u32_be(w: SliceWriter&, v: u32) -> IoError {
    guard available(w) >= 4 else {
        return IoError.BufferFull;
    }
    w.buf[w.cursor]     = ((v >> 24) & 0xFF) as u8;
    w.buf[w.cursor + 1] = ((v >> 16) & 0xFF) as u8;
    w.buf[w.cursor + 2] = ((v >> 8) & 0xFF) as u8;
    w.buf[w.cursor + 3] = (v & 0xFF) as u8;
    w.cursor += 4;
    return IoError.None;
}

// Writes 32-bit integer in Little-Endian order.
fn write_u32_le(w: SliceWriter&, v: u32) -> IoError {
    guard available(w) >= 4 else {
        return IoError.BufferFull;
    }
    w.buf[w.cursor]     = (v & 0xFF) as u8;
    w.buf[w.cursor + 1] = ((v >> 8) & 0xFF) as u8;
    w.buf[w.cursor + 2] = ((v >> 16) & 0xFF) as u8;
    w.buf[w.cursor + 3] = ((v >> 24) & 0xFF) as u8;
    w.cursor += 4;
    return IoError.None;
}

// Writes 64-bit integer in Big-Endian wire order.
fn write_u64_be(w: SliceWriter&, v: u64) -> IoError {
    guard available(w) >= 8 else {
        return IoError.BufferFull;
    }
    w.buf[w.cursor]     = ((v >> 56) & 0xFF) as u8;
    w.buf[w.cursor + 1] = ((v >> 48) & 0xFF) as u8;
    w.buf[w.cursor + 2] = ((v >> 40) & 0xFF) as u8;
    w.buf[w.cursor + 3] = ((v >> 32) & 0xFF) as u8;
    w.buf[w.cursor + 4] = ((v >> 24) & 0xFF) as u8;
    w.buf[w.cursor + 5] = ((v >> 16) & 0xFF) as u8;
    w.buf[w.cursor + 6] = ((v >> 8) & 0xFF) as u8;
    w.buf[w.cursor + 7] = (v & 0xFF) as u8;
    w.cursor += 8;
    return IoError.None;
}

// Writes 64-bit integer in Little-Endian order.
fn write_u64_le(w: SliceWriter&, v: u64) -> IoError {
    guard available(w) >= 8 else {
        return IoError.BufferFull;
    }
    w.buf[w.cursor]     = (v & 0xFF) as u8;
    w.buf[w.cursor + 1] = ((v >> 8) & 0xFF) as u8;
    w.buf[w.cursor + 2] = ((v >> 16) & 0xFF) as u8;
    w.buf[w.cursor + 3] = ((v >> 24) & 0xFF) as u8;
    w.buf[w.cursor + 4] = ((v >> 32) & 0xFF) as u8;
    w.buf[w.cursor + 5] = ((v >> 40) & 0xFF) as u8;
    w.buf[w.cursor + 6] = ((v >> 48) & 0xFF) as u8;
    w.buf[w.cursor + 7] = ((v >> 56) & 0xFF) as u8;
    w.cursor += 8;
    return IoError.None;
}

// Counting writer sink to measure payload sizes without memory buffering.
struct CountingWriter {
    total_written: i64 = 0,
}

fn new_counting_writer() -> CountingWriter {
    return CountingWriter { total_written: 0 };
}

fn write(cw: CountingWriter&, src: const u8[:]) -> i64, IoError {
    cw.total_written += src.len;
    return src.len, IoError.None;
}

fn reset(cw: CountingWriter&) {
    cw.total_written = 0;
}
