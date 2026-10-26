// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// I/O types, error models, and stream status codes.
// Conforms to Goose Core zero-heap systems semantics.
namespace core;

import std;

enum IoError {
    None,
    Eof,              // Natural end of stream reached
    UnexpectedEof,    // Stream truncated unexpectedly during fixed-width or exact read
    BufferFull,       // Destination buffer exhausted, cannot accommodate write
    LimitExceeded,    // Bounded stream limiter threshold reached (DoS protection)
    ShortWrite,       // Incomplete write: fewer bytes accepted than provided
    Closed,           // Channel, descriptor, or stream has been closed
    InvalidArgument,  // Parameter out of range (e.g. negative length, null slice)
}

fn io_error_name(err: IoError) -> const u8[:] {
    return match err {
        None => "None",
        Eof => "EOF",
        UnexpectedEof => "UnexpectedEOF",
        BufferFull => "BufferFull",
        LimitExceeded => "LimitExceeded",
        ShortWrite => "ShortWrite",
        Closed => "Closed",
        InvalidArgument => "InvalidArgument",
    };
}

// Default capacity for fixed zero-heap circular buffers (4KB page-sized)
const DEFAULT_RING_BUFFER_CAP: i64 = 4096;
