// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Open-addressed index table with backward-shift deletion.
// Designed for power-of-two capacity bucket slices (`FlatIndexBucket[1 << k]`) using `& mask`
// indexing, ABA generation counters, and single-pass GetOrPut probing.
namespace core;

import std;
import core.math.bits;
import core.math.arithmetic;

struct FlatIndexBucket {
    key:      u64  = 0,
    slot_idx: u16  = 0,
    gen:      u16  = 0,
    occupied: bool = false,
}

struct FlatIndexResult {
    bucket_idx: i32  = -1,
    slot_idx:   i32  = -1,
    gen:        u16  = 0,
    found:      bool = false,
}

// SplitMix64 avalanche mixer for 64-bit integer keys (fd, tag, stream_id, pre-hashed keys).
inline fn flat_index_hash_u64(key: u64) -> u64 {
    let z0 = key ^ (key >> 30);
    let m0, _ = mul_wide_u64(z0, 0xBF58476D1CE4E5B9);
    let z1 = m0 ^ (m0 >> 27);
    let m1, _ = mul_wide_u64(z1, 0x94D049BB133111EB);
    return m1 ^ (m1 >> 31);
}

// Looks up `key` in a power-of-two `buckets` slice in O(1) expected time.
fn flat_index_get(buckets: const FlatIndexBucket[:], key: u64) -> FlatIndexResult {
    let cap = buckets.len as u64;
    guard is_pow2_u64(cap) else { return FlatIndexResult { .. }; }
    let mask = sub_sat_u64(cap, 1);
    var pos = flat_index_hash_u64(key) & mask;

    for _ in buckets.len {
        let b .= buckets[pos as i64];
        if !b.occupied {
            return FlatIndexResult { .. };
        }
        if b.key == key {
            return FlatIndexResult {
                bucket_idx: pos as i32,
                slot_idx:   b.slot_idx,
                gen:        b.gen,
                found:      true,
            };
        }
        pos = add_sat_u64(pos, 1) & mask;
    }
    return FlatIndexResult { .. };
}

// Single-pass GetOrPut probe: returns `found = true` with `slot_idx` if `key` exists,
// or `found = false` with `bucket_idx >= 0` pointing to the first free bucket for `flat_index_commit_put`.
fn flat_index_get_or_put(buckets: const FlatIndexBucket[:], key: u64) -> FlatIndexResult {
    let cap = buckets.len as u64;
    guard is_pow2_u64(cap) else { return FlatIndexResult { .. }; }
    let mask = sub_sat_u64(cap, 1);
    var pos = flat_index_hash_u64(key) & mask;

    for _ in buckets.len {
        let b .= buckets[pos as i64];
        if !b.occupied {
            return FlatIndexResult {
                bucket_idx: pos as i32,
                slot_idx:   -1,
                gen:        b.gen,
                found:      false,
            };
        }
        if b.key == key {
            return FlatIndexResult {
                bucket_idx: pos as i32,
                slot_idx:   b.slot_idx,
                gen:        b.gen,
                found:      true,
            };
        }
        pos = add_sat_u64(pos, 1) & mask;
    }
    return FlatIndexResult { .. };
}

// Commits a new `(key, slot_idx)` into `bucket_idx` returned by `flat_index_get_or_put`.
// Increments the bucket ABA generation counter (skipping 0) and returns the new generation.
fn flat_index_commit_put(
    buckets:    FlatIndexBucket[:],
    bucket_idx: i32,
    key:        u64,
    slot_idx:   u16,
) -> u16, bool {
    guard bucket_idx >= 0 && bucket_idx < buckets.len else { return 0, false; }
    let b .= buckets[bucket_idx];
    guard !b.occupied else { return 0, false; }
    var next_gen = (add_sat_u64(b.gen, 1)) & 0xFFFF;
    if next_gen == 0 {
        next_gen = 1;
    }
    b.key = key;
    b.slot_idx = slot_idx;
    b.gen = next_gen as u16;
    b.occupied = true;
    return b.gen, true;
}

// Removes `key` using tombstone-free backward-shift deletion, preserving O(1) probe chains.
fn flat_index_remove(buckets: FlatIndexBucket[:], key: u64) -> FlatIndexResult {
    let cap = buckets.len as u64;
    guard is_pow2_u64(cap) else { return FlatIndexResult { .. }; }
    let mask = sub_sat_u64(cap, 1);
    var hole = flat_index_hash_u64(key) & mask;
    var found_res = FlatIndexResult { .. };

    for _ in buckets.len {
        let b .= buckets[hole as i64];
        if !b.occupied {
            return FlatIndexResult { .. };
        }
        if b.key == key {
            found_res = FlatIndexResult {
                bucket_idx: hole as i32,
                slot_idx:   b.slot_idx,
                gen:        b.gen,
                found:      true,
            };
            b.occupied = false;
            b.key = 0;
            break;
        }
        hole = add_sat_u64(hole, 1) & mask;
    }
    guard found_res.found else { return found_res; }

    var j = add_sat_u64(hole, 1) & mask;
    for _ in buckets.len {
        guard buckets[j as i64].occupied else { break; }
        let home = flat_index_hash_u64(buckets[j as i64].key) & mask;
        let dist_j = sub_sat_u64(add_sat_u64(j, cap), home) & mask;
        let dist_hole = sub_sat_u64(add_sat_u64(hole, cap), home) & mask;
        if dist_hole < dist_j {
            buckets[hole as i64] = buckets[j as i64];
            buckets[j as i64].occupied = false;
            buckets[j as i64].key = 0;
            hole = j;
        }
        j = add_sat_u64(j, 1) & mask;
    }
    return found_res;
}

// Clears all buckets while preserving ABA generation counters.
fn flat_index_clear(buckets: FlatIndexBucket[:]) {
    for &b in buckets {
        b.occupied = false;
        b.key = 0;
    }
}
