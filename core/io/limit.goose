// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Zero-heap bounded stream reader (DoS / infinite stream protection).
// Limits maximum consumed bytes, transitioning to LimitExceeded on overflow attempts.
namespace core;

import std;
import core.io.types;
import core.io.reader;

struct LimitReader {
    reader: SliceReader = SliceReader { .. },
    limit_remaining: i64 = 0,
    bytes_consumed: i64 = 0,
    exceeded: bool = false,
}

fn new_limit_reader(src: const u8[:], max_bytes: i64) -> LimitReader {
    return LimitReader {
        reader: new_slice_reader(src),
        limit_remaining: if max_bytes > 0 { max_bytes } else { 0 },
        bytes_consumed: 0,
        exceeded: false,
    };
}

fn remaining(lr: const LimitReader&) -> i64 {
    let r_rem = remaining(lr.reader);
    return if r_rem < lr.limit_remaining { r_rem } else { lr.limit_remaining };
}

fn is_eof(lr: const LimitReader&) -> bool {
    return is_eof(lr.reader) || lr.limit_remaining <= 0;
}

fn is_exhausted(lr: const LimitReader&) -> bool {
    return lr.limit_remaining <= 0;
}

// Reads up to dst.len bytes bounded by limit_remaining.
// If underlying stream is EOF, returns (0, Eof).
// If dst.len is 0, returns (0, None).
// If limit is already 0 and unread stream bytes remain, returns (0, LimitExceeded).
fn read(lr: LimitReader&, dst: u8[:]) -> i64, IoError {
    if dst.len == 0 {
        return 0, IoError.None;
    }
    if is_eof(lr.reader) {
        return 0, IoError.Eof;
    }
    if lr.limit_remaining <= 0 {
        lr.exceeded = true;
        return 0, IoError.LimitExceeded;
    }

    let to_read = if dst.len < lr.limit_remaining { dst.len } else { lr.limit_remaining };
    let n, err = read(lr.reader, dst[..to_read]);
    lr.limit_remaining -= n;
    lr.bytes_consumed += n;

    if err == IoError.Eof {
        return n, IoError.Eof;
    }
    return n, err;
}

// Zero-copy: yields slice up to count bytes, bounded by limit.
fn read_slice(lr: LimitReader&, count: i64) -> const u8[:], IoError {
    guard count >= 0 else {
        return "", IoError.InvalidArgument;
    }
    if count == 0 {
        return "", IoError.None;
    }
    if is_eof(lr.reader) {
        return "", IoError.UnexpectedEof;
    }
    guard count <= lr.limit_remaining else {
        lr.exceeded = true;
        return "", IoError.LimitExceeded;
    }
    let slice, err = read_slice(lr.reader, count);
    if err == IoError.None {
        lr.limit_remaining -= count;
        lr.bytes_consumed += count;
    }
    return slice, err;
}

// Reads single byte subject to limit.
fn read_u8(lr: LimitReader&) -> u8, IoError {
    if is_eof(lr.reader) {
        return 0, IoError.UnexpectedEof;
    }
    guard lr.limit_remaining >= 1 else {
        lr.exceeded = true;
        return 0, IoError.LimitExceeded;
    }
    let b, err = read_u8(lr.reader);
    if err == IoError.None {
        lr.limit_remaining -= 1;
        lr.bytes_consumed += 1;
    }
    return b, err;
}

// Reads 32-bit BE integer subject to 4-byte limit.
fn read_u32_be(lr: LimitReader&) -> u32, IoError {
    if is_eof(lr.reader) {
        return 0, IoError.UnexpectedEof;
    }
    guard lr.limit_remaining >= 4 else {
        lr.exceeded = true;
        return 0, IoError.LimitExceeded;
    }
    let val, err = read_u32_be(lr.reader);
    if err == IoError.None {
        lr.limit_remaining -= 4;
        lr.bytes_consumed += 4;
    }
    return val, err;
}
