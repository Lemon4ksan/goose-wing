// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Pseudorandom number generators and Lemire fast-range reduction.
namespace core;

import std;
import core.math.ct;
import core.math.bits;
import core.math.arithmetic;

const WYP0_V42: u64 = 0x2d358dccaa6c78a5;
const WYP1_V42: u64 = 0x8bb84b93962eacc9;

// Bijective seed scrambler with Stafford constants (SplitMix64).
fn splitmix64(seed: u64&) -> u64 {
    seed += 0x9e3779b97f4a7c15;
    var z = seed;
    z = (z ^ (z >> 30)) * 0xbf58476d1ce4e5b9;
    z = (z ^ (z >> 27)) * 0x94d049bb133111eb;
    return z ^ (z >> 31);
}

// Canonical WyRand v4.2 generator state.
struct WyRand {
    state: u64 = 0,
}

fn new_wyrand(seed: u64 = 0) -> WyRand {
    var sm = seed;
    let s = if seed == 0 { splitmix64(sm) } else { seed };
    return WyRand { state: s };
}

inline fn next_u64(rng: WyRand&) -> u64 {
    rng.state += WYP0_V42;
    return wymum(rng.state ^ WYP1_V42, rng.state);
}

inline fn next_u32(rng: WyRand&) -> u32 {
    return (next_u64(rng) >> 32) as! u32;
}

// Branchless biased Lemire fast-range mapping for interval [0, range).
inline fn fast_range_biased_u64(random_word: u64, range: u64) -> u64 {
    let _, hi = mul_wide_u64(random_word, range);
    return hi;
}

// Unbiased Lemire fast-range mapping with rejection sampling for sensitive intervals.
fn fast_range_unbiased_u32(rng: WyRand&, range: u32) -> u32 {
    if range <= 1 {
        return 0;
    }
    var x = next_u32(rng);
    var m = (x as u64) * range;
    var l = (m & 0xFFFFFFFF) as! u32;
    if l < range {
        let threshold = (0 - range) % range;
        while l < threshold {
            x = next_u32(rng);
            m = (x as u64) * range;
            l = (m & 0xFFFFFFFF) as! u32;
        }
    }
    return (m >> 32) as! u32;
}
