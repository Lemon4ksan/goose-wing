// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Fast non-cryptographic hash functions (FNV-1a, wyhash64) and hash combinators.
namespace core;

import std;
import core.math.bits;
import core.math.arithmetic;

const FNV1A_32_OFFSET: u32 = 0x811C9DC5;
const FNV1A_32_PRIME:  u32 = 0x01000193;
const FNV1A_64_OFFSET: u64 = 0xCBF29CE484222325;
const FNV1A_64_PRIME:  u64 = 0x00000100000001B3;

// Computes 32-bit FNV-1a hash over byte slice.
inline fn fnv1a_32(data: const u8[:]) -> u32 {
    var h: u32 = FNV1A_32_OFFSET;
    for i in data.len {
        h ^= data[i];
        h *= FNV1A_32_PRIME;
    }
    return h;
}

// Computes 64-bit FNV-1a hash over byte slice.
inline fn fnv1a_64(data: const u8[:]) -> u64 {
    var h: u64 = FNV1A_64_OFFSET;
    for i in data.len {
        h ^= data[i];
        h *= FNV1A_64_PRIME;
    }
    return h;
}

const WYHASH_DEFAULT_SECRET: u64[4] = [
    0xa0761d6478bd642f,
    0xe7037ed1a0b428db,
    0x8ebc6af09c88c6e3,
    0x589965cc75374cc3,
];

inline fn wy_read_small(data: const u8[:], len: i64) -> u64 {
    guard len > 0 && len <= data.len else { return 0; }
    let mid = ((len as u64) >> 1) as i64;
    let last = sub_sat_i64(len, 1);
    return shl_sat_u64(data[0], 16) |
           shl_sat_u64(data[mid], 8) |
           data[last];
}

// Canonical WyHash64 non-cryptographic 64-bit hash function.
fn wyhash64_with_secret(data: const u8[:], seed_in: u64, secret: const u64[4]&) -> u64 {
    let len = data.len;
    var seed = seed_in ^ wymum(seed_in ^ secret[0], secret[1]);
    var a: u64 = 0;
    var b: u64 = 0;

    if len <= 16 {
        if len >= 4 {
            let half = (len >> 3) << 2;
            a = ((read_le_u32(data, 0) as u64) << 32) | read_le_u32(data, half);
            b = ((read_le_u32(data, len - 4) as u64) << 32) | read_le_u32(data, len - 4 - half);
        } else if len > 0 {
            a = wy_read_small(data, len);
            b = 0;
        } else {
            a = 0;
            b = 0;
        }
    } else {
        var i = len;
        var p = 0;
        if i > 48 {
            var see1 = seed;
            var see2 = seed;
            while i > 48 {
                seed = wymum(read_le_u64(data, p) ^ secret[1], read_le_u64(data, p + 8) ^ seed);
                see1 = wymum(read_le_u64(data, p + 16) ^ secret[2], read_le_u64(data, p + 24) ^ see1);
                see2 = wymum(read_le_u64(data, p + 32) ^ secret[3], read_le_u64(data, p + 40) ^ see2);
                p += 48;
                i -= 48;
            }
            seed ^= see1 ^ see2;
        }
        while i > 16 {
            seed = wymum(read_le_u64(data, p) ^ secret[1], read_le_u64(data, p + 8) ^ seed);
            i -= 16;
            p += 16;
        }
        a = read_le_u64(data, len - 16);
        b = read_le_u64(data, len - 8);
    }

    a ^= secret[1];
    b ^= seed;
    let lo, hi = mul_wide_u64(a, b);
    return wymum(lo ^ secret[0] ^ (len as u64), hi ^ secret[1]);
}

inline fn wyhash64(data: const u8[:], seed: u64 = 0) -> u64 {
    return wyhash64_with_secret(data, seed, WYHASH_DEFAULT_SECRET);
}

// Golden ratio non-commutative hash combiner (64-bit).
inline fn hash_combine_u64(seed: u64, val: u64) -> u64 {
    return seed ^ (val + 0x9e3779b97f4a7c15 + (seed << 6) + (seed >> 2));
}
