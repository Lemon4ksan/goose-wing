// Bitwise rotation, powers of two, byte swapping, and endianness codecs.
namespace wing;

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
    var v = x - 1;
    v |= v >> 1;
    v |= v >> 2;
    v |= v >> 4;
    v |= v >> 8;
    v |= v >> 16;
    return v + 1;
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
    var v = x - 1;
    v |= v >> 1;
    v |= v >> 2;
    v |= v >> 4;
    v |= v >> 8;
    v |= v >> 16;
    v |= v >> 32;
    return v + 1;
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

// Reads a 32-bit unsigned integer in Little-Endian byte order from slice.
inline fn read_le_u32(data: const u8[:], offset: i64) -> u32 {
    let c = data[offset .. offset + 4];
    return c[0] |
           ((c[1] as u32) << 8) |
           ((c[2] as u32) << 16) |
           ((c[3] as u32) << 24);
}

// Reads a 64-bit unsigned integer in Little-Endian byte order from slice.
inline fn read_le_u64(data: const u8[:], offset: i64) -> u64 {
    let c = data[offset .. offset + 8];
    return c[0] |
           ((c[1] as u64) << 8) |
           ((c[2] as u64) << 16) |
           ((c[3] as u64) << 24) |
           ((c[4] as u64) << 32) |
           ((c[5] as u64) << 40) |
           ((c[6] as u64) << 48) |
           ((c[7] as u64) << 56);
}

// Reads a 16-bit unsigned integer in Big-Endian (Network) byte order from slice.
inline fn read_be_u16(data: const u8[:], offset: i64) -> u16 {
    let c = data[offset .. offset + 2];
    return ((c[0] as u16) << 8) | c[1];
}

// Reads a 24-bit unsigned integer in Big-Endian (Network) byte order from slice.
inline fn read_be_u24(data: const u8[:], offset: i64) -> u32 {
    let c = data[offset .. offset + 3];
    return ((c[0] as u32) << 16) |
           ((c[1] as u32) << 8) |
           c[2];
}

// Reads a 32-bit unsigned integer in Big-Endian (Network) byte order from slice.
inline fn read_be_u32(data: const u8[:], offset: i64) -> u32 {
    let c = data[offset .. offset + 4];
    return ((c[0] as u32) << 24) |
           ((c[1] as u32) << 16) |
           ((c[2] as u32) << 8) |
           c[3];
}

// Reads a 64-bit unsigned integer in Big-Endian (Network) byte order from slice.
inline fn read_be_u64(data: const u8[:], offset: i64) -> u64 {
    let c = data[offset .. offset + 8];
    return ((c[0] as u64) << 56) |
           ((c[1] as u64) << 48) |
           ((c[2] as u64) << 40) |
           ((c[3] as u64) << 32) |
           ((c[4] as u64) << 24) |
           ((c[5] as u64) << 16) |
           ((c[6] as u64) << 8) |
           c[7];
}

// Writes a 16-bit unsigned integer in Big-Endian (Network) byte order into an appendable buffer.
inline fn write_be_u16<B>(out: B&, val: u16) {
    out.push(((val >> 8) & 0xFF) as u8);
    out.push((val & 0xFF) as u8);
}

// Writes a 32-bit unsigned integer in Big-Endian (Network) byte order into an appendable buffer.
inline fn write_be_u32<B>(out: B&, val: u32) {
    out.push(((val >> 24) & 0xFF) as u8);
    out.push(((val >> 16) & 0xFF) as u8);
    out.push(((val >> 8) & 0xFF) as u8);
    out.push((val & 0xFF) as u8);
}

// Writes a 64-bit unsigned integer in Big-Endian (Network) byte order into an appendable buffer.
inline fn write_be_u64<B>(out: B&, val: u64) {
    write_be_u32(out, (val >> 32) as! u32);
    write_be_u32(out, (val & 0xFFFFFFFF) as! u32);
}
