// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Vectorized Scatter/Gather I/O abstractions (IoVec & IoVecArray).
// Enables zero-allocation aggregation of multiple memory buffers (headers, frames, payload chunks)
// for atomic or batched network transmission (writev / WSASend semantics) without intermediate copying.
namespace core;

import std;
import core.io.types;

const IOVEC_CAPACITY: i32 = 16;

struct IoVec {
    base: const u8[:] = "",
}

struct IoVecArray {
    entries:     IoVec[..16] = [],
    head:        i32         = 0,
    head_offset: i64         = 0,
    total_bytes: i64         = 0,
}

// ---- Lifecycle & Inspection ----------------------------------------------

fn new_iovec_array() -> IoVecArray {
    return IoVecArray {
        entries:     [],
        head:        0,
        head_offset: 0,
        total_bytes: 0,
    };
}

fn iovec_clear(arr: IoVecArray&) {
    arr.entries.clear();
    arr.head = 0;
    arr.head_offset = 0;
    arr.total_bytes = 0;
}

fn iovec_total_bytes(arr: const IoVecArray&) -> i64 {
    guard arr.total_bytes >= 0 else { return 0; }
    return arr.total_bytes;
}

fn iovec_is_empty(arr: const IoVecArray&) -> bool {
    return arr.total_bytes <= 0 || arr.head >= (arr.entries.len as i32);
}

fn iovec_count(arr: const IoVecArray&) -> i32 {
    let raw_count = (arr.entries.len as i32) - arr.head;
    return if raw_count > 0 { raw_count } else { 0 };
}

// ---- Compaction and Insertion --------------------------------------------

fn iovec_compact(arr: IoVecArray&) {
    guard arr.head > 0 else { return; }
    var write_idx: i32 = 0;
    var read_idx:  i32 = arr.head;
    while read_idx < (arr.entries.len as i32) {
        if write_idx == 0 && arr.head_offset > 0 {
            let orig = arr.entries[read_idx].base;
            arr.entries[write_idx] = IoVec { base: orig[arr.head_offset..] };
        } else {
            arr.entries[write_idx] = arr.entries[read_idx];
        }
        write_idx += 1;
        read_idx += 1;
    }
    while (arr.entries.len as i32) > write_idx {
        arr.entries.pop();
    }
    arr.head = 0;
    arr.head_offset = 0;
}

fn iovec_push(arr: IoVecArray&, chunk: const u8[:]) -> bool {
    guard chunk.len > 0 else { return true; }
    if arr.entries.len >= 16 {
        iovec_compact(arr);
    }
    guard arr.entries.len < 16 else { return false; }
    arr.entries.push(IoVec { base: chunk });
    arr.total_bytes += chunk.len;
    return true;
}

// ---- Slice Access & Serialization ----------------------------------------

fn iovec_get(arr: const IoVecArray&, index: i32) -> const u8[:] {
    let eff_idx = arr.head + index;
    guard eff_idx >= 0 && eff_idx < (arr.entries.len as i32) else { return ""; }
    let raw = arr.entries[eff_idx].base;
    if index == 0 && arr.head_offset > 0 {
        return raw[arr.head_offset..];
    }
    return raw;
}

fn iovec_flatten<B>(arr: const IoVecArray&, out: B&) {
    var i: i32 = 0;
    let n = iovec_count(arr);
    while i < n {
        let chunk = iovec_get(arr, i);
        out.append(chunk);
        i += 1;
    }
}

fn iovec_copy_chunk(chunk: const u8[:], count: i64, dst: u8[:], dst_offset: i64) {
    var k: i64 = 0;
    while k < count {
        let dst_pos = dst_offset + k;
        dst[dst_pos] = chunk[k];
        k += 1;
    }
}

fn iovec_copy_to(arr: const IoVecArray&, dst: u8[:]) -> i64 {
    var dst_off: i64 = 0;
    var i:       i32 = 0;
    let n = iovec_count(arr);
    while i < n && dst_off < dst.len {
        let chunk = iovec_get(arr, i);
        let rem_dst = dst.len - dst_off;
        let to_copy = if chunk.len < rem_dst { chunk.len } else { rem_dst };
        iovec_copy_chunk(chunk, to_copy, dst, dst_off);
        dst_off += to_copy;
        i += 1;
    }
    return dst_off;
}

// ---- Partial Write Consumption -------------------------------------------

fn iovec_consume_head(arr: IoVecArray&, avail: i64, needed: i64) -> i64 {
    if needed < avail {
        arr.head_offset += needed;
        arr.total_bytes -= needed;
        return needed;
    }
    arr.total_bytes -= avail;
    arr.head += 1;
    arr.head_offset = 0;
    return avail;
}

fn iovec_consume(arr: IoVecArray&, bytes_to_consume: i64) -> i64 {
    guard bytes_to_consume > 0 else { return 0; }
    var rem = bytes_to_consume;
    var consumed_total: i64 = 0;
    while rem > 0 && !iovec_is_empty(arr) {
        let head_chunk = iovec_get(arr, 0);
        let avail = head_chunk.len;
        let consumed = iovec_consume_head(arr, avail, rem);
        consumed_total += consumed;
        rem -= consumed;
    }
    return consumed_total;
}
