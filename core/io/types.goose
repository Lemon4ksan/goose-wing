// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// I/O types, error models, and stream status codes.
// Conforms to Goose Core zero-heap systems semantics.
namespace core;

import std;

enum IoError {
    None,
    WouldBlock,       // Non-blocking operation cannot make immediate progress (EAGAIN / EWOULDBLOCK)
    Eof,              // Natural end of stream reached
    UnexpectedEof,    // Stream truncated unexpectedly during fixed-width or exact read
    BufferFull,       // Destination buffer exhausted, cannot accommodate write
    LimitExceeded,    // Bounded stream limiter threshold reached (DoS protection)
    ShortWrite,       // Incomplete write: fewer bytes accepted than provided
    Closed,           // Channel, descriptor, or stream has been closed
    InvalidArgument,  // Parameter out of range (e.g. negative length, null slice)
}

// Default capacity for fixed zero-heap circular buffers (4KB page-sized)
const DEFAULT_RING_BUFFER_CAP: i64 = 4096;

// Readiness bitmask flags shared across cross-framework async I/O reactors.
const POLL_NONE:   u32 = 0;
const POLL_READ:   u32 = 1 << 0;
const POLL_WRITE:  u32 = 1 << 1;
const POLL_ERROR:  u32 = 1 << 2;
const POLL_HANGUP: u32 = 1 << 3;
const POLL_TIMER:  u32 = 1 << 4;
const POLL_WAKE:   u32 = 1 << 5;

enum PollInterest {
    None,
    Read,
    Write,
    ReadWrite,
}

fn interest_to_poll_flags(_: PollInterest.None) -> u32 { return POLL_NONE; }
fn interest_to_poll_flags(_: PollInterest.Read) -> u32 { return POLL_READ; }
fn interest_to_poll_flags(_: PollInterest.Write) -> u32 { return POLL_WRITE; }
fn interest_to_poll_flags(_: PollInterest.ReadWrite) -> u32 { return POLL_READ | POLL_WRITE; }

enum PollTrigger {
    Level,
    Edge,
}

struct PollReadyEvent {
    tag:             u64  = 0,
    fd:              i32  = -1,
    events:          u32  = POLL_NONE,
    bytes_available: i64  = 0,
    is_eof:          bool = false,
    is_timer:        bool = false,
}

struct DialTarget {
    host:         const u8[:] = "",
    port:         u16         = 0,
    timeout_ms:   u32         = 5000,
    non_blocking: bool        = true,
}
