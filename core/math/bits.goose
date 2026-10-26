// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Bitwise rotation, powers of two, byte swapping, and endianness codecs.
namespace core;

import std;

// Circular bitwise left rotation (32-bit) with masked shift.
inline fn rotl32(x: u32, r: u32) -> u32 {
    return (x << (r & 31)) | (x >> ((0 - r) & 31));
}

// Circular bitwise right rotation (32-bit) with masked shift.
inline fn rotr32(x: u32, r: u32) -> u32 {
    return (x >> (r & 31)) | (x << ((0 - r) & 31));
}

// Circular bitwise left rotation (64-bit) with masked shift.
inline fn rotl64(x: u64, r: u32) -> u64 {
    let sh = (r & 63) as u64;
    let inv = ((0 - r) & 63) as u64;
    return (x << sh) | (x >> inv);
}

// Circular bitwise right rotation (64-bit) with masked shift.
inline fn rotr64(x: u64, r: u32) -> u64 {
    let sh = (r & 63) as u64;
    let inv = ((0 - r) & 63) as u64;
    return (x >> sh) | (x << inv);
}

// Returns true if x is a non-zero power of two (32-bit).
inline fn is_pow2_u32(x: u32) -> bool {
    return (x != 0) && ((x & (x - 1)) == 0);
}

// Returns true if x is a non-zero power of two (64-bit).
inline fn is_pow2_u64(x: u64) -> bool {
    return (x != 0) && ((x & (x - 1)) == 0);
}

// Computes the smallest power of two greater than or equal to x (32-bit).
// Guaranteed to return an actual power of two (clamps to 0x80000000 on overflow).
inline fn next_pow2_u32(x: u32) -> u32 {
    if x <= 1 {
        return 1;
    }
    if x > 0x80000000 {
        return 0x80000000;
    }
    let lz = clz(x - 1);
    return (1 as u32) << ((64 - lz) as u32);
}

// Computes the smallest power of two greater than or equal to x (64-bit).
// Guaranteed to return an actual power of two (clamps to 0x8000000000000000 on overflow).
inline fn next_pow2_u64(x: u64) -> u64 {
    if x <= 1 {
        return 1;
    }
    if x > 0x8000000000000000 {
        return 0x8000000000000000;
    }
    let lz = clz(x - 1);
    return (1 as u64) << ((64 - lz) as u64);
}

// Byte reversal for 16-bit integer (Host <-> Network Big-Endian).
inline fn bswap16(x: u16) -> u16 {
    return (x << 8) | (x >> 8);
}

// Byte reversal for 32-bit integer (Host <-> Network Big-Endian).
inline fn bswap32(x: u32) -> u32 {
    return ((x & 0x000000FF) << 24) |
           ((x & 0x0000FF00) << 8)  |
           ((x & 0x00FF0000) >> 8)  |
           ((x & 0xFF000000) >> 24);
}

// Byte reversal for 64-bit integer (Host <-> Network Big-Endian).
inline fn bswap64(x: u64) -> u64 {
    let hi = bswap32((x & 0xFFFFFFFF) as! u32) as u64;
    let lo = bswap32((x >> 32) as! u32) as u64;
    return (hi << 32) | lo;
}

// Reads a 16-bit unsigned integer in Little-Endian byte order from slice.
inline fn read_le_u16(data: const u8[:], offset: i64) -> u16 {
    let s = data[offset .. offset + 2];
    return (s[0]) | ((s[1] as u16) << 8);
}

// Reads a 24-bit unsigned integer in Little-Endian byte order from slice.
inline fn read_le_u24(data: const u8[:], offset: i64) -> u32 {
    let s = data[offset .. offset + 3];
    return (s[0]) |
           ((s[1] as u32) << 8) |
           ((s[2] as u32) << 16);
}

// Reads a 32-bit unsigned integer in Little-Endian byte order from slice.
inline fn read_le_u32(data: const u8[:], offset: i64) -> u32 {
    let s = data[offset .. offset + 4];
    return (s[0]) |
           ((s[1] as u32) << 8) |
           ((s[2] as u32) << 16) |
           ((s[3] as u32) << 24);
}

// Reads a 64-bit unsigned integer in Little-Endian byte order from slice.
inline fn read_le_u64(data: const u8[:], offset: i64) -> u64 {
    let s = data[offset .. offset + 8];
    return (s[0]) |
           ((s[1] as u64) << 8) |
           ((s[2] as u64) << 16) |
           ((s[3] as u64) << 24) |
           ((s[4] as u64) << 32) |
           ((s[5] as u64) << 40) |
           ((s[6] as u64) << 48) |
           ((s[7] as u64) << 56);
}

// Reads a 16-bit unsigned integer in Big-Endian (Network) byte order from slice.
inline fn read_be_u16(data: const u8[:], offset: i64) -> u16 {
    let s = data[offset .. offset + 2];
    return ((s[0] as u16) << 8) | (s[1]);
}

// Reads a 24-bit unsigned integer in Big-Endian (Network) byte order from slice.
inline fn read_be_u24(data: const u8[:], offset: i64) -> u32 {
    let s = data[offset .. offset + 3];
    return ((s[0] as u32) << 16) |
           ((s[1] as u32) << 8) |
           (s[2]);
}

// Reads a 32-bit unsigned integer in Big-Endian (Network) byte order from slice.
inline fn read_be_u32(data: const u8[:], offset: i64) -> u32 {
    let s = data[offset .. offset + 4];
    return ((s[0] as u32) << 24) |
           ((s[1] as u32) << 16) |
           ((s[2] as u32) << 8) |
           (s[3]);
}

// Reads a 64-bit unsigned integer in Big-Endian (Network) byte order from slice.
inline fn read_be_u64(data: const u8[:], offset: i64) -> u64 {
    let s = data[offset .. offset + 8];
    return ((s[0] as u64) << 56) |
           ((s[1] as u64) << 48) |
           ((s[2] as u64) << 40) |
           ((s[3] as u64) << 32) |
           ((s[4] as u64) << 24) |
           ((s[5] as u64) << 16) |
           ((s[6] as u64) << 8) |
           (s[7]);
}

// Writes a 16-bit unsigned integer in Big-Endian (Network) byte order into an appendable buffer.
inline fn write_be_u16<B>(out: B&, val: u16) {
    let bytes: u8[2] = [
        ((val >> 8) & 0xFF) as u8,
        (val & 0xFF) as u8,
    ];
    out.append(bytes[..]);
}

// Writes a 32-bit unsigned integer in Big-Endian (Network) byte order into an appendable buffer.
inline fn write_be_u32<B>(out: B&, val: u32) {
    let bytes: u8[4] = [
        ((val >> 24) & 0xFF) as u8,
        ((val >> 16) & 0xFF) as u8,
        ((val >> 8) & 0xFF) as u8,
        (val & 0xFF) as u8,
    ];
    out.append(bytes[..]);
}

// Writes a 64-bit unsigned integer in Big-Endian (Network) byte order into an appendable buffer.
inline fn write_be_u64<B>(out: B&, val: u64) {
    let bytes: u8[8] = [
        ((val >> 56) & 0xFF) as u8,
        ((val >> 48) & 0xFF) as u8,
        ((val >> 40) & 0xFF) as u8,
        ((val >> 32) & 0xFF) as u8,
        ((val >> 24) & 0xFF) as u8,
        ((val >> 16) & 0xFF) as u8,
        ((val >> 8) & 0xFF) as u8,
        (val & 0xFF) as u8,
    ];
    out.append(bytes[..]);
}

// Writes a 16-bit unsigned integer in Big-Endian (Network) byte order at specific offset in indexable buffer.
inline fn write_be_u16_at(dst: u8[:], offset: i64, val: u16) {
    dst[offset]     = ((val >> 8) & 0xFF) as! u8;
    dst[offset + 1] = (val & 0xFF) as! u8;
}

// Writes a 32-bit unsigned integer in Big-Endian (Network) byte order at specific offset in indexable buffer.
inline fn write_be_u32_at(dst: u8[:], offset: i64, val: u32) {
    dst[offset]     = ((val >> 24) & 0xFF) as! u8;
    dst[offset + 1] = ((val >> 16) & 0xFF) as! u8;
    dst[offset + 2] = ((val >> 8)  & 0xFF) as! u8;
    dst[offset + 3] = (val & 0xFF) as! u8;
}

// Writes a 64-bit unsigned integer in Big-Endian (Network) byte order at specific offset in indexable buffer.
inline fn write_be_u64_at(dst: u8[:], offset: i64, val: u64) {
    dst[offset]     = ((val >> 56) & 0xFF) as! u8;
    dst[offset + 1] = ((val >> 48) & 0xFF) as! u8;
    dst[offset + 2] = ((val >> 40) & 0xFF) as! u8;
    dst[offset + 3] = ((val >> 32) & 0xFF) as! u8;
    dst[offset + 4] = ((val >> 24) & 0xFF) as! u8;
    dst[offset + 5] = ((val >> 16) & 0xFF) as! u8;
    dst[offset + 6] = ((val >> 8)  & 0xFF) as! u8;
    dst[offset + 7] = (val & 0xFF) as! u8;
}

// Writes a 16-bit unsigned integer in Little-Endian byte order at specific offset in indexable buffer.
inline fn write_le_u16_at(dst: u8[:], offset: i64, val: u16) {
    dst[offset]     = (val & 0xFF) as! u8;
    dst[offset + 1] = ((val >> 8) & 0xFF) as! u8;
}

// Writes a 32-bit unsigned integer in Little-Endian byte order at specific offset in indexable buffer.
inline fn write_le_u32_at(dst: u8[:], offset: i64, val: u32) {
    dst[offset]     = (val & 0xFF) as! u8;
    dst[offset + 1] = ((val >> 8) & 0xFF) as! u8;
    dst[offset + 2] = ((val >> 16) & 0xFF) as! u8;
    dst[offset + 3] = ((val >> 24) & 0xFF) as! u8;
}

// Writes a 64-bit unsigned integer in Little-Endian byte order at specific offset in indexable buffer.
inline fn write_le_u64_at(dst: u8[:], offset: i64, val: u64) {
    dst[offset]     = (val & 0xFF) as! u8;
    dst[offset + 1] = ((val >> 8) & 0xFF) as! u8;
    dst[offset + 2] = ((val >> 16) & 0xFF) as! u8;
    dst[offset + 3] = ((val >> 24) & 0xFF) as! u8;
    dst[offset + 4] = ((val >> 32) & 0xFF) as! u8;
    dst[offset + 5] = ((val >> 40) & 0xFF) as! u8;
    dst[offset + 6] = ((val >> 48) & 0xFF) as! u8;
    dst[offset + 7] = ((val >> 56) & 0xFF) as! u8;
}

// Writes a 16-bit unsigned integer in Little-Endian byte order into an appendable buffer.
inline fn write_le_u16<B>(out: B&, val: u16) {
    let bytes: u8[2] = [
        (val & 0xFF) as u8,
        ((val >> 8) & 0xFF) as u8,
    ];
    out.append(bytes[..]);
}

// Writes a 32-bit unsigned integer in Little-Endian byte order into an appendable buffer.
inline fn write_le_u32<B>(out: B&, val: u32) {
    let bytes: u8[4] = [
        (val & 0xFF) as u8,
        ((val >> 8) & 0xFF) as u8,
        ((val >> 16) & 0xFF) as u8,
        ((val >> 24) & 0xFF) as u8,
    ];
    out.append(bytes[..]);
}

// Writes a 64-bit unsigned integer in Little-Endian byte order into an appendable buffer.
inline fn write_le_u64<B>(out: B&, val: u64) {
    let bytes: u8[8] = [
        (val & 0xFF) as u8,
        ((val >> 8) & 0xFF) as u8,
        ((val >> 16) & 0xFF) as u8,
        ((val >> 24) & 0xFF) as u8,
        ((val >> 32) & 0xFF) as u8,
        ((val >> 40) & 0xFF) as u8,
        ((val >> 48) & 0xFF) as u8,
        ((val >> 56) & 0xFF) as u8,
    ];
    out.append(bytes[..]);
}
