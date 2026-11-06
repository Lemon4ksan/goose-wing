// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Zero-copy binary stream reader and bounded byte builder.
// Conforms to RFC 8446 wire encoding and ASN.1 DER length rules.
namespace core;

import std;

// Zero-copy cursor over an immutable byte slice.
struct ByteCursor {
    buf: const u8[:] = [],
}

// Initializes a ByteCursor wrapping the provided slice.
inline fn cursor_from(buf: const u8[:]) -> ByteCursor {
    return ByteCursor { buf: buf };
}

// Returns the remaining byte count in the cursor.
inline fn cursor_len(c: const ByteCursor&) -> i64 {
    guard c.buf.len >= 0 else { return 0; }
    return c.buf.len;
}

// Reads an 8-bit unsigned integer from the cursor, advancing it by 1.
//
// Example:
//   c.buf = [0x17, 0x03]
//   returns: ok = true, out = 0x17, c.buf = [0x03]
fn get_u8(c: ByteCursor&, out: u8&) -> bool {
    guard c.buf.len > 0 else { return false; }
    out = c.buf[0];
    c.buf = c.buf[1..];
    return true;
}

// Reads an 8-bit unsigned integer and returns it directly (Rule 9 value return).
//
// Example:
//   c.buf = [0x17, 0x03]
//   returns: val = 0x17, ok = true, c.buf = [0x03]
fn read_u8(c: ByteCursor&) -> u8, bool {
    guard c.buf.len > 0 else { return 0, false; }
    let val = c.buf[0];
    c.buf = c.buf[1..];
    return val, true;
}
// Reads a 16-bit big-endian unsigned integer, advancing cursor by 2.
//
// Example:
//   c.buf = [0x03, 0x03, 0xAA]
//   returns: ok = true, out = 0x0303, c.buf = [0xAA]
fn get_u16(c: ByteCursor&, out: u16&) -> bool {
    guard c.buf.len >= 2 else { return false; }
    out = ((c.buf[0] as u16) << 8) | c.buf[1];
    c.buf = c.buf[2..];
    return true;
}

// Reads a 16-bit big-endian integer directly (Rule 9 value return).
//
// Example:
//   c.buf = [0x03, 0x03, 0xAA]
//   returns: val = 0x0303, ok = true, c.buf = [0xAA]
fn read_u16(c: ByteCursor&) -> u16, bool {
    guard c.buf.len >= 2 else { return 0, false; }
    let val = ((c.buf[0] as u16) << 8) | c.buf[1];
    c.buf = c.buf[2..];
    return val, true;
}

// Reads a 24-bit big-endian unsigned integer, advancing cursor by 3.
//
// Example:
//   c.buf = [0x00, 0x01, 0x02, 0xFF]
//   returns: ok = true, out = 0x000102, c.buf = [0xFF]
fn get_u24(c: ByteCursor&, out: u32&) -> bool {
    guard c.buf.len >= 3 else { return false; }
    out = ((c.buf[0] as u32) << 16) | ((c.buf[1] as u32) << 8) | c.buf[2];
    c.buf = c.buf[3..];
    return true;
}

// Reads a 24-bit big-endian integer directly (Rule 9 value return).
//
// Example:
//   c.buf = [0x00, 0x01, 0x02, 0xFF]
//   returns: val = 0x000102, ok = true, c.buf = [0xFF]
fn read_u24(c: ByteCursor&) -> u32, bool {
    guard c.buf.len >= 3 else { return 0, false; }
    let val = ((c.buf[0] as u32) << 16) | ((c.buf[1] as u32) << 8) | c.buf[2];
    c.buf = c.buf[3..];
    return val, true;
}

// Reads a 32-bit big-endian unsigned integer, advancing cursor by 4.
//
// Example:
//   c.buf = [0x01, 0x02, 0x03, 0x04]
//   returns: ok = true, out = 0x01020304, c.buf = []
fn get_u32(c: ByteCursor&, out: u32&) -> bool {
    guard c.buf.len >= 4 else { return false; }
    out = ((c.buf[0] as u32) << 24) |
        ((c.buf[1] as u32) << 16) |
        ((c.buf[2] as u32) << 8) |
        c.buf[3];
    c.buf = c.buf[4..];
    return true;
}

// Reads a 32-bit big-endian integer directly (Rule 9 value return).
//
// Example:
//   c.buf = [0x01, 0x02, 0x03, 0x04]
//   returns: val = 0x01020304, ok = true, c.buf = []
fn read_u32(c: ByteCursor&) -> u32, bool {
    guard c.buf.len >= 4 else { return 0, false; }
    let val = ((c.buf[0] as u32) << 24) |
        ((c.buf[1] as u32) << 16) |
        ((c.buf[2] as u32) << 8) |
        c.buf[3];
    c.buf = c.buf[4..];
    return val, true;
}
// Consumes `count` bytes from cursor into a new ByteCursor.
//
// Example:
//   c.buf = "hello", count = 3
//   returns: ok = true, out.buf = "hel", c.buf = "lo"
fn get_bytes(c: ByteCursor&, out: ByteCursor&, count: i64) -> bool {
    guard count >= 0 && c.buf.len >= count else { return false; }
    out = ByteCursor { buf: c.buf[..count] };
    c.buf = c.buf[count..];
    return true;
}

// Consumes `count` bytes directly as a slice (Rule 9 value return).
//
// Example:
//   c.buf = "hello", count = 3
//   returns: slice = "hel", ok = true, c.buf = "lo"
fn read_bytes(c: ByteCursor&, count: i64) -> const u8[:], bool {
    guard count >= 0 && c.buf.len >= count else { return c.buf[..0], false; }
    let sub = c.buf[..count];
    c.buf = c.buf[count..];
    return sub, true;
}

// Reads an 8-bit length-prefixed slice into a ByteCursor.
// Leaves cursor unchanged on framing error.
//
// Example:
//   c.buf = [0x02, 0xAA, 0xBB, 0xCC]
//   returns: ok = true, out.buf = [0xAA, 0xBB], c.buf = [0xCC]
fn get_u8_length_prefixed(c: ByteCursor&, out: ByteCursor&) -> bool {
    let saved = c.buf;
    var length: u8 = 0;
    guard get_u8(c, length) else { return false; }
    guard get_bytes(c, out, length) else {
        c.buf = saved;
        return false;
    }
    return true;
}

// Reads an 8-bit length-prefixed slice directly (Rule 9 value return).
//
// Example:
//   c.buf = [0x02, 0xAA, 0xBB, 0xCC]
//   returns: slice = [0xAA, 0xBB], ok = true, c.buf = [0xCC]
fn read_u8_prefixed(c: ByteCursor&) -> const u8[:], bool {
    let saved = c.buf;
    var length: u8 = 0;
    guard get_u8(c, length) else { return c.buf[..0], false; }
    let sub, ok = read_bytes(c, length);
    guard ok else {
        c.buf = saved;
        return c.buf[..0], false;
    }
    return sub, true;
}

// Reads a 16-bit big-endian length-prefixed slice into a ByteCursor.
// Leaves cursor unchanged on framing error.
//
// Example:
//   c.buf = [0x00, 0x02, 0xAA, 0xBB]
//   returns: ok = true, out.buf = [0xAA, 0xBB], c.buf = []
fn get_u16_length_prefixed(c: ByteCursor&, out: ByteCursor&) -> bool {
    let saved = c.buf;
    var length: u16 = 0;
    guard get_u16(c, length) else { return false; }
    guard get_bytes(c, out, length) else {
        c.buf = saved;
        return false;
    }
    return true;
}

// Reads a 16-bit big-endian length-prefixed slice directly (Rule 9 value return).
//
// Example:
//   c.buf = [0x00, 0x02, 0xAA, 0xBB]
//   returns: slice = [0xAA, 0xBB], ok = true, c.buf = []
fn read_u16_prefixed(c: ByteCursor&) -> const u8[:], bool {
    let saved = c.buf;
    var length: u16 = 0;
    guard get_u16(c, length) else { return c.buf[..0], false; }
    let sub, ok = read_bytes(c, length);
    guard ok else {
        c.buf = saved;
        return c.buf[..0], false;
    }
    return sub, true;
}

// Reads a 24-bit big-endian length-prefixed slice into a ByteCursor.
// Leaves cursor unchanged on framing error.
//
// Example:
//   c.buf = [0x00, 0x00, 0x02, 0xAA, 0xBB]
//   returns: ok = true, out.buf = [0xAA, 0xBB], c.buf = []
fn get_u24_length_prefixed(c: ByteCursor&, out: ByteCursor&) -> bool {
    let saved = c.buf;
    var length: u32 = 0;
    guard get_u24(c, length) else { return false; }
    guard get_bytes(c, out, length) else {
        c.buf = saved;
        return false;
    }
    return true;
}

// Reads a 24-bit big-endian length-prefixed slice directly (Rule 9 value return).
//
// Example:
//   c.buf = [0x00, 0x00, 0x02, 0xAA, 0xBB]
//   returns: slice = [0xAA, 0xBB], ok = true, c.buf = []
fn read_u24_prefixed(c: ByteCursor&) -> const u8[:], bool {
    let saved = c.buf;
    var length: u32 = 0;
    guard get_u24(c, length) else { return c.buf[..0], false; }
    let sub, ok = read_bytes(c, length);
    guard ok else {
        c.buf = saved;
        return c.buf[..0], false;
    }
    return sub, true;
}

// Extracts the trailing byte from the cursor without scanning.
//
// Example:
//   c.buf = [0x01, 0x02, 0x17]
//   returns: ok = true, out = 0x17, c.buf = [0x01, 0x02]
fn get_last_u8(c: ByteCursor&, out: u8&) -> bool {
    let n = c.buf.len;
    guard n > 0 else { return false; }
    out = c.buf[n - 1];
    c.buf = c.buf[..n - 1];
    return true;
}
// Bounded dynamic byte buffer supporting up to 8 nested length-prefix frames.
struct ByteBuilder {
    offsets: i64[..8] = [],
    buf:     u8[>..]  = [],
}

// Initializes a fresh, empty ByteBuilder.
fn builder_init() -> ByteBuilder {
    return ByteBuilder { offsets: [], buf: [] };
}

// Appends an 8-bit unsigned integer to the builder.
fn put_u8(b: ByteBuilder&, val: u8) {
    b.buf.push(val);
}

// Appends a 16-bit big-endian unsigned integer to the builder.
fn put_u16(b: ByteBuilder&, val: u16) {
    b.buf.push(((val >> 8) & 0xFF) as u8);
    b.buf.push((val & 0xFF) as u8);
}

// Appends a 24-bit big-endian unsigned integer to the builder.
fn put_u24(b: ByteBuilder&, val: u32) {
    b.buf.push(((val >> 16) & 0xFF) as u8);
    b.buf.push(((val >> 8) & 0xFF) as u8);
    b.buf.push((val & 0xFF) as u8);
}

// Appends a 32-bit big-endian unsigned integer to the builder.
fn put_u32(b: ByteBuilder&, val: u32) {
    b.buf.push(((val >> 24) & 0xFF) as u8);
    b.buf.push(((val >> 16) & 0xFF) as u8);
    b.buf.push(((val >> 8) & 0xFF) as u8);
    b.buf.push((val & 0xFF) as u8);
}

// Appends raw byte slice to the builder.
fn put_bytes(b: ByteBuilder&, data: const u8[:]) {
    b.buf.append(data);
}

// Pushes an 8-bit length prefix placeholder onto the builder.
fn start_u8_prefix(b: ByteBuilder&) -> bool {
    guard b.offsets.len < b.offsets.cap else { return false; }
    b.offsets.push(b.buf.len);
    b.buf.push(0);
    return true;
}

// Backpatches the enclosing 8-bit length prefix.
fn finish_u8_prefix(b: ByteBuilder&) -> bool {
    guard b.offsets.len > 0 else { return false; }
    let start = b.offsets[b.offsets.len - 1];
    b.offsets.pop();
    guard start >= 0 && start < b.buf.len else {
        return false;
    }
    let body_len = b.buf.len - start - 1;
    guard body_len >= 0 && body_len <= 255 else {
        return false;
    }
    b.buf[start] = body_len as u8;
    return true;
}

// Pushes a 16-bit length prefix placeholder onto the builder.
fn start_u16_prefix(b: ByteBuilder&) -> bool {
    guard b.offsets.len < b.offsets.cap else { return false; }
    b.offsets.push(b.buf.len);
    b.buf.push(0);
    b.buf.push(0);
    return true;
}

// Backpatches the enclosing 16-bit length prefix.
fn finish_u16_prefix(b: ByteBuilder&) -> bool {
    guard b.offsets.len > 0 else { return false; }
    let start = b.offsets[b.offsets.len - 1];
    b.offsets.pop();
    guard start >= 0 && start + 1 < b.buf.len else {
        return false;
    }
    let body_len = b.buf.len - start - 2;
    guard body_len >= 0 && body_len <= 65535 else {
        return false;
    }
    b.buf[start] = ((body_len >> 8) & 0xFF) as u8;
    b.buf[start + 1] = (body_len & 0xFF) as u8;
    return true;
}

// Pushes a 24-bit length prefix placeholder onto the builder.
fn start_u24_prefix(b: ByteBuilder&) -> bool {
    guard b.offsets.len < b.offsets.cap else { return false; }
    b.offsets.push(b.buf.len);
    b.buf.push(0);
    b.buf.push(0);
    b.buf.push(0);
    return true;
}

// Backpatches the enclosing 24-bit length prefix.
fn finish_u24_prefix(b: ByteBuilder&) -> bool {
    guard b.offsets.len > 0 else { return false; }
    let start = b.offsets[b.offsets.len - 1];
    b.offsets.pop();
    guard start >= 0 && start + 2 < b.buf.len else {
        return false;
    }
    let body_len = b.buf.len - start - 3;
    guard body_len >= 0 && body_len <= 16777215 else {
        return false;
    }
    b.buf[start] = ((body_len >> 16) & 0xFF) as u8;
    b.buf[start + 1] = ((body_len >> 8) & 0xFF) as u8;
    b.buf[start + 2] = (body_len & 0xFF) as u8;
    return true;
}
