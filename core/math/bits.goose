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

// Returns true if x is a non-zero power of two (64-bit).
inline fn is_pow2_u64(x: u64) -> bool {
    return (x != 0) && ((x & (x - 1)) == 0);
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

// Reads a 16-bit unsigned integer in Little-Endian byte order from slice.
checkfree inline fn read_le_u16(data: const u8[:], offset: i64) -> u16 {
    guard offset >= 0 && offset <= data.len - 2 else { return 0; }
    let s = data[offset..offset + 2];
    return (s[0]) | ((s[1] as u16) << 8);
}

// Reads a 24-bit unsigned integer in Little-Endian byte order from slice.
checkfree inline fn read_le_u24(data: const u8[:], offset: i64) -> u32 {
    guard offset >= 0 && offset <= data.len - 3 else { return 0; }
    let s = data[offset..offset + 3];
    return (s[0]) |
           ((s[1] as u32) << 8) |
           ((s[2] as u32) << 16);
}

// Reads a 32-bit unsigned integer in Little-Endian byte order from slice.
checkfree inline fn read_le_u32(data: const u8[:], offset: i64) -> u32 {
    guard offset >= 0 && offset <= data.len - 4 else { return 0; }
    let s = data[offset..offset + 4];
    return (s[0]) |
           ((s[1] as u32) << 8) |
           ((s[2] as u32) << 16) |
           ((s[3] as u32) << 24);
}

// Reads a 64-bit unsigned integer in Little-Endian byte order from slice.
checkfree inline fn read_le_u64(data: const u8[:], offset: i64) -> u64 {
    guard offset >= 0 && offset <= data.len - 8 else { return 0; }
    let s = data[offset..offset + 8];
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
checkfree inline fn read_be_u16(data: const u8[:], offset: i64) -> u16 {
    guard offset >= 0 && offset <= data.len - 2 else { return 0; }
    let s = data[offset..offset + 2];
    return ((s[0] as u16) << 8) | (s[1]);
}

// Reads a 24-bit unsigned integer in Big-Endian (Network) byte order from slice.
checkfree inline fn read_be_u24(data: const u8[:], offset: i64) -> u32 {
    guard offset >= 0 && offset <= data.len - 3 else { return 0; }
    let s = data[offset..offset + 3];
    return ((s[0] as u32) << 16) |
           ((s[1] as u32) << 8) |
           (s[2]);
}

// Reads a 32-bit unsigned integer in Big-Endian (Network) byte order from slice.
checkfree inline fn read_be_u32(data: const u8[:], offset: i64) -> u32 {
    guard offset >= 0 && offset <= data.len - 4 else { return 0; }
    let s = data[offset..offset + 4];
    return ((s[0] as u32) << 24) |
           ((s[1] as u32) << 16) |
           ((s[2] as u32) << 8) |
           (s[3]);
}

// Reads a 64-bit unsigned integer in Big-Endian (Network) byte order from slice.
checkfree inline fn read_be_u64(data: const u8[:], offset: i64) -> u64 {
    guard offset >= 0 && offset <= data.len - 8 else { return 0; }
    let s = data[offset..offset + 8];
    return ((s[0] as u64) << 56) |
           ((s[1] as u64) << 48) |
           ((s[2] as u64) << 40) |
           ((s[3] as u64) << 32) |
           ((s[4] as u64) << 24) |
           ((s[5] as u64) << 16) |
           ((s[6] as u64) << 8) |
           (s[7]);
}

// Writes a 16-bit unsigned integer in Big-Endian (Network) byte order at specific offset in indexable buffer.
inline fn write_be_u16_at(dst: u8[:], offset: i64, val: u16) {
    dst[offset] = ((val >> 8) & 0xFF) as! u8;
    dst[offset + 1] = (val & 0xFF) as! u8;
}

// Writes a 32-bit unsigned integer in Big-Endian (Network) byte order at specific offset in indexable buffer.
inline fn write_be_u32_at(dst: u8[:], offset: i64, val: u32) {
    dst[offset] = ((val >> 24) & 0xFF) as! u8;
    dst[offset + 1] = ((val >> 16) & 0xFF) as! u8;
    dst[offset + 2] = ((val >> 8) & 0xFF) as! u8;
    dst[offset + 3] = (val & 0xFF) as! u8;
}

// Writes a 64-bit unsigned integer in Big-Endian (Network) byte order at specific offset in indexable buffer.
inline fn write_be_u64_at(dst: u8[:], offset: i64, val: u64) {
    dst[offset] = ((val >> 56) & 0xFF) as! u8;
    dst[offset + 1] = ((val >> 48) & 0xFF) as! u8;
    dst[offset + 2] = ((val >> 40) & 0xFF) as! u8;
    dst[offset + 3] = ((val >> 32) & 0xFF) as! u8;
    dst[offset + 4] = ((val >> 24) & 0xFF) as! u8;
    dst[offset + 5] = ((val >> 16) & 0xFF) as! u8;
    dst[offset + 6] = ((val >> 8) & 0xFF) as! u8;
    dst[offset + 7] = (val & 0xFF) as! u8;
}

// Writes a 32-bit unsigned integer in Little-Endian byte order at specific offset in indexable buffer.
inline fn write_le_u32_at(dst: u8[:], offset: i64, val: u32) {
    dst[offset] = (val & 0xFF) as! u8;
    dst[offset + 1] = ((val >> 8) & 0xFF) as! u8;
    dst[offset + 2] = ((val >> 16) & 0xFF) as! u8;
    dst[offset + 3] = ((val >> 24) & 0xFF) as! u8;
}

// Writes a 64-bit unsigned integer in Little-Endian byte order at specific offset in indexable buffer.
checkfree inline fn write_le_u64_at(dst: u8[:], offset: i64, val: u64) {
    guard offset >= 0 && offset <= dst.len - 8 else { return; }
    let s = dst[offset..offset + 8];
    s[0] = (val & 0xFF) as! u8;
    s[1] = ((val >> 8) & 0xFF) as! u8;
    s[2] = ((val >> 16) & 0xFF) as! u8;
    s[3] = ((val >> 24) & 0xFF) as! u8;
    s[4] = ((val >> 32) & 0xFF) as! u8;
    s[5] = ((val >> 40) & 0xFF) as! u8;
    s[6] = ((val >> 48) & 0xFF) as! u8;
    s[7] = ((val >> 56) & 0xFF) as! u8;
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

// 64-bit SWAR exact per-byte equality mask (sets 0x80 in each matching byte with zero inter-byte borrow).
checkfree inline fn swar_eq_mask(w: u64, b: u8) -> u64 {
    let x = w ^ (0x0101010101010101 * (b as u64));
    return (~(((x & 0x7F7F7F7F7F7F7F7F) + 0x7F7F7F7F7F7F7F7F) | x)) & 0x8080808080808080;
}

// 64-bit SWAR zero byte check (RFC 9110 / uWebSockets HttpParser algorithm).
checkfree inline fn swar_has_zero_byte(w: u64) -> bool {
    return ((w - 0x0101010101010101) & (~w) & 0x8080808080808080) != 0;
}

// 64-bit SWAR search for byte `b` in 8-byte word `w`.
checkfree inline fn swar_has_byte(w: u64, b: u8) -> bool {
    let mask = 0x0101010101010101 * (b as u64);
    return swar_has_zero_byte(w ^ mask);
}

// 64-bit SWAR control character check (< 0x20 or == 0x7F).
checkfree inline fn swar_has_ctl_or_del(w: u64) -> bool {
    let sub = w - 0x2020202020202020;
    let has_under_20 = (sub & (~w) & 0x8080808080808080) != 0;
    let has_del = swar_has_byte(w, 0x7F);
    return has_under_20 || has_del;
}
