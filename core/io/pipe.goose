// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Zero-heap two-cursor streaming byte pipeline (inspired by System.IO.Pipelines).
// Eliminates buffer shifting, unnecessary copying, and premature allocations.
// Provides strict monotonicity invariants for cursor tracking (preventing .NET #107213 regressions).
namespace core;

import std;
import core.io.types;

const PIPE_BUFFER_CAP: i64 = 65536; // 64 KB bounded inline storage

struct PipeBuffer {
    storage:      u8[65536] = [0; 65536],
    consumed:     i64       = 0, // Absolute offset of fully consumed bytes
    examined:     i64       = 0, // Absolute offset of inspected bytes (monotonically non-decreasing)
    written:      i64       = 0, // Absolute offset of bytes written into the buffer
    is_completed: bool      = false,
}

fn new_pipe_buffer() -> PipeBuffer {
    return PipeBuffer {
        storage:      [0; 65536],
        consumed:     0,
        examined:     0,
        written:      0,
        is_completed: false,
    };
}

// Yields the contiguous slice of readable bytes that have not yet been consumed.
fn readable_slice(p: const PipeBuffer&) -> const u8[:] {
    if p.consumed >= p.written {
        return "";
    }
    return p.storage[p.consumed..p.written];
}

// Returns the number of readable unconsumed bytes currently available.
fn readable_len(p: const PipeBuffer&) -> i64 {
    return max(0, p.written - p.consumed);
}

// Returns remaining tail capacity without compacting.
fn write_space(p: const PipeBuffer&) -> i64 {
    return max(0, PIPE_BUFFER_CAP - p.written);
}

// Returns total capacity available if unconsumed bytes are compacted.
fn total_available(p: const PipeBuffer&) -> i64 {
    let used = max(0, p.written - p.consumed);
    return max(0, PIPE_BUFFER_CAP - used);
}

// Compacts the buffer by sliding unconsumed bytes to the front of storage.
fn compact_pipe(p: PipeBuffer&) {
    guard p.consumed > 0 else { return; }
    let unconsumed = p.written - p.consumed;
    if unconsumed > 0 {
        for i in unconsumed {
            p.storage[i] = p.storage[p.consumed + i];
        }
    }
    p.examined = max(0, p.examined - p.consumed);
    p.written = unconsumed;
    p.consumed = 0;
}

// Advances the read cursors after protocol parsing.
// consumed_delta: number of bytes fully consumed (must be <= readable_len).
// examined_delta: number of bytes examined during parsing (must be >= consumed_delta).
//
// Invariant guard (.NET issue #107213 mitigation):
// examined position is guaranteed monotonic: examined = max(new_examined, prev_examined).
fn advance_to(p: PipeBuffer&, consumed_delta: i64, examined_delta: i64) -> IoError {
    guard consumed_delta >= 0 && examined_delta >= 0 else {
        return IoError.InvalidArgument;
    }
    let cur_readable = readable_len(p);
    guard consumed_delta <= cur_readable && examined_delta <= cur_readable else {
        return IoError.InvalidArgument;
    }
    guard examined_delta >= consumed_delta else {
        return IoError.InvalidArgument;
    }

    let target_consumed = p.consumed + consumed_delta;
    let target_examined = p.consumed + examined_delta;

    // Enforce monotonicity of examined cursor
    p.examined = max(target_examined, p.examined);
    p.consumed = target_consumed;

    // Ensure examined is at least consumed
    if p.consumed > p.examined {
        p.examined = p.consumed;
    }

    // If all bytes have been consumed, reset cursors instantly without copying
    if p.consumed == p.written {
        p.consumed = 0;
        p.written = 0;
        p.examined = 0;
    } else if p.consumed > 0 && (p.consumed >= 32768 || write_space(p) < 4096) {
        compact_pipe(p);
    }

    return IoError.None;
}

// Provides a writable span for transport drivers to receive into.
// Automatically compacts if needed to ensure at least min_size bytes are available.
fn get_write_span(p: PipeBuffer&, min_size: i64 = 1) -> u8[:], IoError {
    guard !p.is_completed else {
        return p.storage[..0], IoError.Closed;
    }
    guard min_size > 0 && min_size <= PIPE_BUFFER_CAP else {
        return p.storage[..0], IoError.InvalidArgument;
    }
    if write_space(p) < min_size && p.consumed > 0 {
        compact_pipe(p);
    }
    if write_space(p) < min_size {
        return p.storage[..0], IoError.BufferFull;
    }
    return p.storage[p.written..], IoError.None;
}

// Commits bytes written by transport driver into the pipe.
fn commit_write(p: PipeBuffer&, bytes_written: i64) -> IoError {
    guard !p.is_completed else {
        return IoError.Closed;
    }
    guard bytes_written >= 0 else {
        return IoError.InvalidArgument;
    }
    guard p.written + bytes_written <= PIPE_BUFFER_CAP else {
        return IoError.BufferFull;
    }
    p.written += bytes_written;
    return IoError.None;
}

// High-level write helper copying src into the pipe.
fn write(p: PipeBuffer&, src: const u8[:]) -> i64, IoError {
    guard !p.is_completed else {
        return 0, IoError.Closed;
    }
    guard src.len > 0 else { return 0, IoError.None; }
    if write_space(p) < src.len && p.consumed > 0 {
        compact_pipe(p);
    }
    guard write_space(p) >= src.len else {
        return 0, IoError.BufferFull;
    }
    for i in src.len {
        p.storage[p.written + i] = src[i];
    }
    p.written += src.len;
    return src.len, IoError.None;
}

// Reads and consumes bytes from the pipe into dst.
// Returns (bytes_read, IoError).
fn read(p: PipeBuffer&, dst: u8[:]) -> i64, IoError {
    guard dst.len > 0 else { return 0, IoError.None; }
    let avail = readable_len(p);
    if avail == 0 {
        return 0, if p.is_completed { IoError.Eof } else { IoError.None };
    }
    let to_read = min(dst.len, avail);
    for i in to_read {
        dst[i] = p.storage[p.consumed + i];
    }
    advance_to(p, to_read, to_read);
    return to_read, IoError.None;
}

// Peeks at bytes in the pipe without advancing read cursors.
fn peek(p: const PipeBuffer&, dst: u8[:]) -> i64 {
    guard dst.len > 0 else { return 0; }
    let avail = readable_len(p);
    if avail == 0 { return 0; }
    let to_peek = min(dst.len, avail);
    for i in to_peek {
        dst[i] = p.storage[p.consumed + i];
    }
    return to_peek;
}

// Marks the pipe as completed by transport (no more writes will occur).
fn complete_pipe(p: PipeBuffer&) {
    p.is_completed = true;
}

// Resets pipe state, recycling the buffer for subsequent connections without reallocating.
fn pipe_reset(p: PipeBuffer&) {
    p.consumed = 0;
    p.examined = 0;
    p.written = 0;
    p.is_completed = false;
}

fn reset(p: PipeBuffer&) {
    pipe_reset(p);
}
