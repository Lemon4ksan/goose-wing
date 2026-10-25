// Zero-heap, zero-copy slice stream reader.
// Maintains cursor offset over a contiguous byte buffer with bounds-checked primitives.
namespace core;

import std;
import core.io.types;

struct SliceReader {
    data: const u8[:] = [],
    cursor: i64 = 0,
}

fn new_slice_reader(src: const u8[:]) -> SliceReader {
    return SliceReader {
        data: src,
        cursor: 0,
    };
}

fn remaining(r: const SliceReader&) -> i64 {
    let rem = r.data.len - r.cursor;
    return if rem > 0 { rem } else { 0 };
}

fn is_eof(r: const SliceReader&) -> bool {
    return r.cursor >= r.data.len;
}

fn reset(r: SliceReader&, src: const u8[:]) {
    r.data = src;
    r.cursor = 0;
}

// Reads up to dst.len bytes from the stream into dst.
// Returns (bytes_read, IoError).
fn read(r: SliceReader&, dst: u8[:]) -> i64, IoError {
    if is_eof(r) {
        return 0, IoError.Eof;
    }
    let rem = remaining(r);
    let to_copy = if dst.len < rem { dst.len } else { rem };
    for i in to_copy {
        dst[i] = r.data[r.cursor + i];
    }
    r.cursor += to_copy;
    return to_copy, IoError.None;
}

// Reads exactly dst.len bytes, failing with UnexpectedEof if stream has fewer bytes remaining.
fn read_exact(r: SliceReader&, dst: u8[:]) -> IoError {
    guard remaining(r) >= dst.len else {
        return IoError.UnexpectedEof;
    }
    for i in dst.len {
        dst[i] = r.data[r.cursor + i];
    }
    r.cursor += dst.len;
    return IoError.None;
}

// Zero-copy: yields a sub-slice of exact length count and advances cursor.
fn read_slice(r: SliceReader&, count: i64) -> const u8[:], IoError {
    guard count >= 0 else {
        return "", IoError.InvalidArgument;
    }
    guard remaining(r) >= count else {
        return "", IoError.UnexpectedEof;
    }
    let start = r.cursor;
    let end = r.cursor + count;
    r.cursor = end;
    return r.data[start..end], IoError.None;
}

// Reads single byte.
fn read_u8(r: SliceReader&) -> u8, IoError {
    guard remaining(r) >= 1 else {
        return 0, IoError.UnexpectedEof;
    }
    let b = r.data[r.cursor];
    r.cursor += 1;
    return b, IoError.None;
}

// Reads 16-bit unsigned integer in Big-Endian wire order.
fn read_u16_be(r: SliceReader&) -> u16, IoError {
    guard remaining(r) >= 2 else {
        return 0, IoError.UnexpectedEof;
    }
    let b0 = r.data[r.cursor] as u16;
    let b1 = r.data[r.cursor + 1] as u16;
    r.cursor += 2;
    return (b0 << 8) | b1, IoError.None;
}

// Reads 16-bit unsigned integer in Little-Endian order.
fn read_u16_le(r: SliceReader&) -> u16, IoError {
    guard remaining(r) >= 2 else {
        return 0, IoError.UnexpectedEof;
    }
    let b0 = r.data[r.cursor] as u16;
    let b1 = r.data[r.cursor + 1] as u16;
    r.cursor += 2;
    return (b1 << 8) | b0, IoError.None;
}

// Reads 24-bit unsigned integer in Big-Endian wire order (RFC 8446 TLS, RFC 9113 HTTP/2 framing).
fn read_u24_be(r: SliceReader&) -> u32, IoError {
    guard remaining(r) >= 3 else {
        return 0, IoError.UnexpectedEof;
    }
    let b0 = r.data[r.cursor] as u32;
    let b1 = r.data[r.cursor + 1] as u32;
    let b2 = r.data[r.cursor + 2] as u32;
    r.cursor += 3;
    return (b0 << 16) | (b1 << 8) | b2, IoError.None;
}

// Reads 24-bit unsigned integer in Little-Endian order.
fn read_u24_le(r: SliceReader&) -> u32, IoError {
    guard remaining(r) >= 3 else {
        return 0, IoError.UnexpectedEof;
    }
    let b0 = r.data[r.cursor] as u32;
    let b1 = r.data[r.cursor + 1] as u32;
    let b2 = r.data[r.cursor + 2] as u32;
    r.cursor += 3;
    return (b2 << 16) | (b1 << 8) | b0, IoError.None;
}

// Reads 32-bit unsigned integer in Big-Endian wire order.
fn read_u32_be(r: SliceReader&) -> u32, IoError {
    guard remaining(r) >= 4 else {
        return 0, IoError.UnexpectedEof;
    }
    let b0 = r.data[r.cursor] as u32;
    let b1 = r.data[r.cursor + 1] as u32;
    let b2 = r.data[r.cursor + 2] as u32;
    let b3 = r.data[r.cursor + 3] as u32;
    r.cursor += 4;
    return (b0 << 24) | (b1 << 16) | (b2 << 8) | b3, IoError.None;
}

// Reads 32-bit unsigned integer in Little-Endian order.
fn read_u32_le(r: SliceReader&) -> u32, IoError {
    guard remaining(r) >= 4 else {
        return 0, IoError.UnexpectedEof;
    }
    let b0 = r.data[r.cursor] as u32;
    let b1 = r.data[r.cursor + 1] as u32;
    let b2 = r.data[r.cursor + 2] as u32;
    let b3 = r.data[r.cursor + 3] as u32;
    r.cursor += 4;
    return (b3 << 24) | (b2 << 16) | (b1 << 8) | b0, IoError.None;
}

// Reads 64-bit unsigned integer in Big-Endian wire order.
fn read_u64_be(r: SliceReader&) -> u64, IoError {
    guard remaining(r) >= 8 else {
        return 0, IoError.UnexpectedEof;
    }
    let b0 = r.data[r.cursor] as u64;
    let b1 = r.data[r.cursor + 1] as u64;
    let b2 = r.data[r.cursor + 2] as u64;
    let b3 = r.data[r.cursor + 3] as u64;
    let b4 = r.data[r.cursor + 4] as u64;
    let b5 = r.data[r.cursor + 5] as u64;
    let b6 = r.data[r.cursor + 6] as u64;
    let b7 = r.data[r.cursor + 7] as u64;
    r.cursor += 8;
    return (b0 << 56) | (b1 << 48) | (b2 << 40) | (b3 << 32) |
           (b4 << 24) | (b5 << 16) | (b6 << 8) | b7, IoError.None;
}

// Reads 64-bit unsigned integer in Little-Endian order.
fn read_u64_le(r: SliceReader&) -> u64, IoError {
    guard remaining(r) >= 8 else {
        return 0, IoError.UnexpectedEof;
    }
    let b0 = r.data[r.cursor] as u64;
    let b1 = r.data[r.cursor + 1] as u64;
    let b2 = r.data[r.cursor + 2] as u64;
    let b3 = r.data[r.cursor + 3] as u64;
    let b4 = r.data[r.cursor + 4] as u64;
    let b5 = r.data[r.cursor + 5] as u64;
    let b6 = r.data[r.cursor + 6] as u64;
    let b7 = r.data[r.cursor + 7] as u64;
    r.cursor += 8;
    return (b7 << 56) | (b6 << 48) | (b5 << 40) | (b4 << 32) |
           (b3 << 24) | (b2 << 16) | (b1 << 8) | b0, IoError.None;
}

// Advances cursor forward by count bytes.
fn skip(r: SliceReader&, count: i64) -> IoError {
    guard count >= 0 else {
        return IoError.InvalidArgument;
    }
    guard remaining(r) >= count else {
        return IoError.UnexpectedEof;
    }
    r.cursor += count;
    return IoError.None;
}

// Peeks at next byte without advancing cursor.
fn peek(r: const SliceReader&) -> u8, bool {
    guard remaining(r) >= 1 else {
        return 0, false;
    }
    return r.data[r.cursor], true;
}

// Peeks at next count bytes as a slice without advancing cursor.
fn peek_slice(r: const SliceReader&, count: i64) -> const u8[:], bool {
    guard count >= 0 && remaining(r) >= count else {
        return "", false;
    }
    let start = r.cursor;
    let end = r.cursor + count;
    return r.data[start..end], true;
}
