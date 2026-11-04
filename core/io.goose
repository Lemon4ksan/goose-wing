// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Goose Core I/O Stream Module.
// Provides zero-heap, compile-time inlined streaming abstractions:
// - types: IoError status codes and buffer sizing constants.
// - ring: RingBuffer circular FIFO queue for non-blocking network socket buffering.
// - pipe: PipeBuffer two-cursor sliding window buffer.
// - cork: CorkBuffer packet coalescing aggregator.
// - vec: Vectorized Scatter/Gather I/O abstractions.
// - page_ring: Hardware PageRingBuffer virtual memory mirrored ring.
// - page_mem: GuardedArena, MmapFile, PinnedBuffer for OS memory pages.
// - cursor: ByteCursor zero-copy slice stream reader and bounded ByteBuilder.
namespace core;

import std;

import core.io.types;
import core.io.ring;
import core.io.pipe;
import core.io.cork;
import core.io.vec;
import core.io.page_ring;
import core.io.page_mem;
import core.io.cursor;

// Appends a 16-bit integer in Big-Endian wire order into any appendable buffer.
fn append_u16_be<B>(out: B&, v: u16) {
    let b: u8[2] = [(v >> 8) as u8, (v & 0xFF) as u8];
    out.append(b[..]);
}

// Appends a 24-bit integer in Big-Endian wire order into any appendable buffer.
fn append_u24_be<B>(out: B&, v: u32) {
    let b: u8[3] = [((v >> 16) & 0xFF) as u8, ((v >> 8) & 0xFF) as u8, (v & 0xFF) as u8];
    out.append(b[..]);
}

// Appends a 32-bit integer in Big-Endian wire order into any appendable buffer.
fn append_u32_be<B>(out: B&, v: u32) {
    let b: u8[4] = [
        ((v >> 24) & 0xFF) as u8,
        ((v >> 16) & 0xFF) as u8,
        ((v >> 8) & 0xFF) as u8,
        (v & 0xFF) as u8,
    ];
    out.append(b[..]);
}

// Appends a 64-bit integer in Big-Endian wire order into any appendable buffer.
fn append_u64_be<B>(out: B&, v: u64) {
    let b: u8[8] = [
        ((v >> 56) & 0xFF) as u8,
        ((v >> 48) & 0xFF) as u8,
        ((v >> 40) & 0xFF) as u8,
        ((v >> 32) & 0xFF) as u8,
        ((v >> 24) & 0xFF) as u8,
        ((v >> 16) & 0xFF) as u8,
        ((v >> 8) & 0xFF) as u8,
        (v & 0xFF) as u8,
    ];
    out.append(b[..]);
}
