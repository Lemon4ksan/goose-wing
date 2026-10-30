// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// RFC 1321 MD5 Message-Digest Algorithm.
// Used for HTTP Digest Access Authentication (RFC 2617 / RFC 7616 fallback) and Content-MD5 verification.
namespace core;

import std;

struct Md5Context {
    state:  u32[4] = [0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476],
    count:  u64    = 0,
    buffer: u8[64] = [0; 64],
}

fn md5_rotate_left(x: u32, n: u32) -> u32 {
    return (x << n) | (x >> (32 - n));
}

inline fn md5_decode_block(blk: const u8[64]&) -> u32[16] {
    var x: u32[16] = [0; 16];
    for i in 16 {
        let idx = i * 4;
        x[i] = blk[idx] |
               ((blk[idx + 1] as! u32) << 8) |
               ((blk[idx + 2] as! u32) << 16) |
               ((blk[idx + 3] as! u32) << 24);
    }
    return x;
}

fn md5_transform(state: u32[4]&, blk: const u8[64]&) {
    var a = state[0];
    var b = state[1];
    var c = state[2];
    var d = state[3];

    let x = md5_decode_block(blk);

    // Round 1
    a = b + md5_rotate_left(a + ((b & c) | ((~b) & d)) + x[0] + 0xd76aa478, 7);
    d = a + md5_rotate_left(d + ((a & b) | ((~a) & c)) + x[1] + 0xe8c7b756, 12);
    c = d + md5_rotate_left(c + ((d & a) | ((~d) & b)) + x[2] + 0x242070db, 17);
    b = c + md5_rotate_left(b + ((c & d) | ((~c) & a)) + x[3] + 0xc1bdceee, 22);
    a = b + md5_rotate_left(a + ((b & c) | ((~b) & d)) + x[4] + 0xf57c0faf, 7);
    d = a + md5_rotate_left(d + ((a & b) | ((~a) & c)) + x[5] + 0x4787c62a, 12);
    c = d + md5_rotate_left(c + ((d & a) | ((~d) & b)) + x[6] + 0xa8304613, 17);
    b = c + md5_rotate_left(b + ((c & d) | ((~c) & a)) + x[7] + 0xfd469501, 22);
    a = b + md5_rotate_left(a + ((b & c) | ((~b) & d)) + x[8] + 0x698098d8, 7);
    d = a + md5_rotate_left(d + ((a & b) | ((~a) & c)) + x[9] + 0x8b44f7af, 12);
    c = d + md5_rotate_left(c + ((d & a) | ((~d) & b)) + x[10] + 0xffff5bb1, 17);
    b = c + md5_rotate_left(b + ((c & d) | ((~c) & a)) + x[11] + 0x895cd7be, 22);
    a = b + md5_rotate_left(a + ((b & c) | ((~b) & d)) + x[12] + 0x6b901122, 7);
    d = a + md5_rotate_left(d + ((a & b) | ((~a) & c)) + x[13] + 0xfd987193, 12);
    c = d + md5_rotate_left(c + ((d & a) | ((~d) & b)) + x[14] + 0xa679438e, 17);
    b = c + md5_rotate_left(b + ((c & d) | ((~c) & a)) + x[15] + 0x49b40821, 22);

    // Round 2
    a = b + md5_rotate_left(a + ((b & d) | (c & (~d))) + x[1] + 0xf61e2562, 5);
    d = a + md5_rotate_left(d + ((a & c) | (b & (~c))) + x[6] + 0xc040b340, 9);
    c = d + md5_rotate_left(c + ((d & b) | (a & (~b))) + x[11] + 0x265e5a51, 14);
    b = c + md5_rotate_left(b + ((c & a) | (d & (~a))) + x[0] + 0xe9b6c7aa, 20);
    a = b + md5_rotate_left(a + ((b & d) | (c & (~d))) + x[5] + 0xd62f105d, 5);
    d = a + md5_rotate_left(d + ((a & c) | (b & (~c))) + x[10] + 0x02441453, 9);
    c = d + md5_rotate_left(c + ((d & b) | (a & (~b))) + x[15] + 0xd8a1e681, 14);
    b = c + md5_rotate_left(b + ((c & a) | (d & (~a))) + x[4] + 0xe7d3fbc8, 20);
    a = b + md5_rotate_left(a + ((b & d) | (c & (~d))) + x[9] + 0x21e1cde6, 5);
    d = a + md5_rotate_left(d + ((a & c) | (b & (~c))) + x[14] + 0xc33707d6, 9);
    c = d + md5_rotate_left(c + ((d & b) | (a & (~b))) + x[3] + 0xf4d50d87, 14);
    b = c + md5_rotate_left(b + ((c & a) | (d & (~a))) + x[8] + 0x455a14ed, 20);
    a = b + md5_rotate_left(a + ((b & d) | (c & (~d))) + x[13] + 0xa9e3e905, 5);
    d = a + md5_rotate_left(d + ((a & c) | (b & (~c))) + x[2] + 0xfcefa3f8, 9);
    c = d + md5_rotate_left(c + ((d & b) | (a & (~b))) + x[7] + 0x676f02d9, 14);
    b = c + md5_rotate_left(b + ((c & a) | (d & (~a))) + x[12] + 0x8d2a4c8a, 20);

    // Round 3
    a = b + md5_rotate_left(a + (b ^ c ^ d) + x[5] + 0xfffa3942, 4);
    d = a + md5_rotate_left(d + (a ^ b ^ c) + x[8] + 0x8771f681, 11);
    c = d + md5_rotate_left(c + (d ^ a ^ b) + x[11] + 0x6d9d6122, 16);
    b = c + md5_rotate_left(b + (c ^ d ^ a) + x[14] + 0xfde5380c, 23);
    a = b + md5_rotate_left(a + (b ^ c ^ d) + x[1] + 0xa4beea44, 4);
    d = a + md5_rotate_left(d + (a ^ b ^ c) + x[4] + 0x4bdecfa9, 11);
    c = d + md5_rotate_left(c + (d ^ a ^ b) + x[7] + 0xf6bb4b60, 16);
    b = c + md5_rotate_left(b + (c ^ d ^ a) + x[10] + 0xbebfbc70, 23);
    a = b + md5_rotate_left(a + (b ^ c ^ d) + x[13] + 0x289b7ec6, 4);
    d = a + md5_rotate_left(d + (a ^ b ^ c) + x[0] + 0xeaa127fa, 11);
    c = d + md5_rotate_left(c + (d ^ a ^ b) + x[3] + 0xd4ef3085, 16);
    b = c + md5_rotate_left(b + (c ^ d ^ a) + x[6] + 0x04881d05, 23);
    a = b + md5_rotate_left(a + (b ^ c ^ d) + x[9] + 0xd9d4d039, 4);
    d = a + md5_rotate_left(d + (a ^ b ^ c) + x[12] + 0xe6db99e5, 11);
    c = d + md5_rotate_left(c + (d ^ a ^ b) + x[15] + 0x1fa27cf8, 16);
    b = c + md5_rotate_left(b + (c ^ d ^ a) + x[2] + 0xc4ac5665, 23);

    // Round 4
    a = b + md5_rotate_left(a + (c ^ (b | (~d))) + x[0] + 0xf4292244, 6);
    d = a + md5_rotate_left(d + (b ^ (a | (~c))) + x[7] + 0x432aff97, 10);
    c = d + md5_rotate_left(c + (a ^ (d | (~b))) + x[14] + 0xab9423a7, 15);
    b = c + md5_rotate_left(b + (d ^ (c | (~a))) + x[5] + 0xfc93a039, 21);
    a = b + md5_rotate_left(a + (c ^ (b | (~d))) + x[12] + 0x655b59c3, 6);
    d = a + md5_rotate_left(d + (b ^ (a | (~c))) + x[3] + 0x8f0ccc92, 10);
    c = d + md5_rotate_left(c + (a ^ (d | (~b))) + x[10] + 0xffeff47d, 15);
    b = c + md5_rotate_left(b + (d ^ (c | (~a))) + x[1] + 0x85845dd1, 21);
    a = b + md5_rotate_left(a + (c ^ (b | (~d))) + x[8] + 0x6fa87e4f, 6);
    d = a + md5_rotate_left(d + (b ^ (a | (~c))) + x[15] + 0xfe2ce6e0, 10);
    c = d + md5_rotate_left(c + (a ^ (d | (~b))) + x[6] + 0xa3014314, 15);
    b = c + md5_rotate_left(b + (d ^ (c | (~a))) + x[13] + 0x4e0811a1, 21);
    a = b + md5_rotate_left(a + (c ^ (b | (~d))) + x[4] + 0xf7537e82, 6);
    d = a + md5_rotate_left(d + (b ^ (a | (~c))) + x[11] + 0xbd3af235, 10);
    c = d + md5_rotate_left(c + (a ^ (d | (~b))) + x[2] + 0x2ad7d2bb, 15);
    b = c + md5_rotate_left(b + (d ^ (c | (~a))) + x[9] + 0xeb86d391, 21);

    state[0] += a;
    state[1] += b;
    state[2] += c;
    state[3] += d;
}

// Computes 16-byte MD5 digest
fn md5(data: const u8[:]) -> u8[16] {
    var ctx = Md5Context { .. };
    var offset: i64 = 0;
    let len = data.len;
    ctx.count = (len as u64) * 8;

    while (len - offset) >= 64 {
        var chunk: u8[64] = [0; 64];
        for i in 64 { chunk[i] = data[offset + i]; }
        md5_transform(ctx.state, chunk);
        offset += 64;
    }

    var chunk: u8[64] = [0; 64];
    let remaining = len - offset;
    for i in remaining { chunk[i] = data[offset + i]; }
    chunk[remaining] = 0x80;

    if remaining >= 56 {
        md5_transform(ctx.state, chunk);
        for i in 64 { chunk[i] = 0; }
    }

    for i in 8 {
        chunk[56 + i] = ((ctx.count >> (i * 8)) & 0xFF) as u8;
    }
    md5_transform(ctx.state, chunk);

    var digest: u8[16] = [0; 16];
    for i in 4 {
        digest[i * 4] = (ctx.state[i] & 0xFF) as u8;
        digest[i * 4 + 1] = ((ctx.state[i] >> 8) & 0xFF) as u8;
        digest[i * 4 + 2] = ((ctx.state[i] >> 16) & 0xFF) as u8;
        digest[i * 4 + 3] = ((ctx.state[i] >> 24) & 0xFF) as u8;
    }
    return digest;
}
