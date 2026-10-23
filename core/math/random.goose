// High-performance pseudorandom number generators and Lemire fast-range reduction.
namespace wing;

import std;
import core.math.ct;
import core.math.bits;
import core.math.arithmetic;

const WYP0_V42: u64 = 0x2d358dccaa6c78a5;
const WYP1_V42: u64 = 0x8bb84b93962eacc9;
const WYP2_V42: u64 = 0x4b33a62ed433d4a3;
const WYP3_V42: u64 = 0x4d5a2da51de1aa47;

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

// Ultra-fast 64-bit to 32-bit PRNG (w1rand).
inline fn w1rand_next(state: u64&) -> u32 {
    state += WYP0_V42;
    let prod = wymum(state ^ WYP1_V42, state);
    return (prod >> 32) as! u32;
}

// Xoroshiro64** generator for low-state 32-bit random streams.
struct Xoroshiro64StarStar {
    s0: u32 = 0x9E3779BB,
    s1: u32 = 0x85EBCA77,
}

fn new_xoroshiro64_star_star(seed: u64) -> Xoroshiro64StarStar {
    var sm = seed;
    let w = splitmix64(sm);
    var lo = (w & 0xFFFFFFFF) as! u32;
    let hi = (w >> 32) as! u32;
    if lo == 0 && hi == 0 {
        lo = 0x9E3779BB;
    }
    return Xoroshiro64StarStar { s0: lo, s1: hi };
}

inline fn new_xoroshiro64(seed: u64) -> Xoroshiro64StarStar {
    return new_xoroshiro64_star_star(seed);
}

inline fn next_u32(rng: Xoroshiro64StarStar&) -> u32 {
    let s0 = rng.s0;
    var s1 = rng.s1;
    let result = rotl32(s0 * 0x9E3779BB, 5) * 5;

    s1 ^= s0;
    rng.s0 = rotl32(s0, 26) ^ s1 ^ (s1 << 9);
    rng.s1 = rotl32(s1, 13);
    return result;
}

// Variant Xoroshiro64* for fast floating point generation.
inline fn next_star_u32(rng: Xoroshiro64StarStar&) -> u32 {
    let s0 = rng.s0;
    var s1 = rng.s1;
    let result = s0 * 0x9E3779BB;

    s1 ^= s0;
    rng.s0 = rotl32(s0, 26) ^ s1 ^ (s1 << 9);
    rng.s1 = rotl32(s1, 13);
    return result;
}

// Branchless biased Lemire fast-range mapping for interval [0, range).
inline fn fast_range_biased_u32(random_word: u32, range: u32) -> u32 {
    let prod = (random_word as u64) * range;
    return (prod >> 32) as! u32;
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
