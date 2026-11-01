// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Zero-heap Tee stream interceptor.
// Reads from a primary reader and simultaneously mirrors all consumed bytes into a sink.
namespace core;

import std;
import core.io.types;
import core.io.reader;
import core.io.writer;

struct TeeReader {
    reader:            SliceReader = SliceReader { .. },
    intercepted_total: i64         = 0,
}

fn new_tee_reader(src: const u8[:]) -> TeeReader {
    return TeeReader {
        reader:            new_slice_reader(src),
        intercepted_total: 0,
    };
}

fn remaining(tr: const TeeReader&) -> i64 {
    return remaining(tr.reader);
}

fn is_eof(tr: const TeeReader&) -> bool {
    return is_eof(tr.reader);
}

// Reads up to dst.len bytes and mirrors every read byte into sink buffer.
fn read_and_tap<Sink>(tr: TeeReader&, dst: u8[:], sink: Sink&) -> i64, IoError {
    let n, err = read(tr.reader, dst);
    if n > 0 {
        sink.append(dst[..n]);
        tr.intercepted_total += n;
    }
    return n, err;
}

// Zero-copy: yields slice of count bytes and mirrors it to sink.
fn read_slice_and_tap<Sink>(tr: TeeReader&, count: i64, sink: Sink&) -> const u8[:], IoError {
    let slice, err = read_slice(tr.reader, count);
    if err == IoError.None && slice.len > 0 {
        sink.append(slice);
        tr.intercepted_total += slice.len;
    }
    return slice, err;
}
