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

// ---- SWAR 8-way 7-bit control-tag index ------------------------------------

const SWAR_CTRL_EMPTY: u8 = 0x80;

const SWAR_CTRL_DELETED: u8 = 0xFE;

const SWAR_MASK_LO: u64 = 0x0101010101010101;

const SWAR_MASK_HI: u64 = 0x8080808080808080;

// Extracts a 7-bit control tag (0x00..0x7F) from the top bits of a 64-bit hash.
inline fn swar_tag_byte(hash: u64) -> u8 {
    return (hash >> 57) as u8;
}

// Loads an 8-byte SWAR control group starting at `base` in little-endian lane order.
inline fn swar_load_group_u64(ctrl: const u8[:], base: i64) -> u64 {
    guard base >= 0 && add_sat_i64(base, 8) <= ctrl.len else { return 0; }
    let b0: u64 = ctrl[base];
    return b0
        | ((ctrl[base + 1] as u64) << 8)
        | ((ctrl[base + 2] as u64) << 16)
        | ((ctrl[base + 3] as u64) << 24)
        | ((ctrl[base + 4] as u64) << 32)
        | ((ctrl[base + 5] as u64) << 40)
        | ((ctrl[base + 6] as u64) << 48)
        | ((ctrl[base + 7] as u64) << 56);
}

// Returns a bitmask with bit `8 * k + 7` set for each lane in `word` equal to `needle`.
inline fn swar_match_byte(word: u64, needle: u8) -> u64 {
    let n: u64 = needle;
    let spread = n * SWAR_MASK_LO;
    let x = word ^ spread;
    return (x - SWAR_MASK_LO) & (~x) & SWAR_MASK_HI;
}

// Returns a bitmask with bit `8 * k + 7` set for each never-used (`SWAR_CTRL_EMPTY`) lane.
inline fn swar_match_empty(word: u64) -> u64 {
    return swar_match_byte(word, SWAR_CTRL_EMPTY);
}

// Returns a bitmask with bit `8 * k + 7` set for each EMPTY or DELETED lane in `word`.
inline fn swar_match_free(word: u64) -> u64 {
    return word & SWAR_MASK_HI;
}

inline fn swar_probe_group_hit(
    keys:  const u64[:],
    slots: const u16[:],
    gens:  const u16[:],
    word:  u64,
    tag:   u8,
    base:  i64,
    key:   u64,
) -> FlatIndexResult {
    var m = swar_match_byte(word, tag);
    while m != 0 {
        let lane = ctz(m) >> 3;
        let idx = add_sat_i64(base, lane);
        if idx < keys.len && keys[idx] == key {
            return FlatIndexResult {
                bucket_idx: idx as i32,
                slot_idx:   slots[idx],
                gen:        gens[idx],
                found:      true,
            };
        }
        m &= m - 1;
    }
    return FlatIndexResult { .. };
}

inline fn swar_slices_valid(
    ctrl_len:  i64,
    keys_len:  i64,
    slots_len: i64,
    gens_len:  i64,
) -> bool {
    let cap = ctrl_len as u64;
    return cap >= 8
        && is_pow2_u64(cap)
        && keys_len == ctrl_len
        && slots_len == ctrl_len
        && gens_len == ctrl_len;
}

// Looks up `key` in parallel SoA SWAR index slices (power-of-two cap >= 8) in O(1) expected time.
fn swar_index_get(
    ctrl:  const u8[:],
    keys:  const u64[:],
    slots: const u16[:],
    gens:  const u16[:],
    key:   u64,
) -> FlatIndexResult {
    guard swar_slices_valid(ctrl.len, keys.len, slots.len, gens.len) else {
        return FlatIndexResult { .. };
    }
    let h = flat_index_hash_u64(key);
    let tag = swar_tag_byte(h);
    let groups = (ctrl.len as u64) >> 3;
    let g_mask = sub_sat_u64(groups, 1);
    var g = (h >> 3) & g_mask;

    for _ in groups {
        let base = (g << 3) as i64;
        let w = swar_load_group_u64(ctrl, base);
        let hit = swar_probe_group_hit(keys, slots, gens, w, tag, base, key);
        if hit.found {
            return hit;
        }
        if swar_match_empty(w) != 0 {
            return FlatIndexResult { .. };
        }
        g = add_sat_u64(g, 1) & g_mask;
    }
    return FlatIndexResult { .. };
}

// Single-pass GetOrPut SWAR probe: returns `found = true` with `slot_idx` if `key` exists,
// or `found = false` with `bucket_idx >= 0` pointing to the first free slot for `swar_index_commit_put`.
fn swar_index_get_or_put(
    ctrl:  const u8[:],
    keys:  const u64[:],
    slots: const u16[:],
    gens:  const u16[:],
    key:   u64,
) -> FlatIndexResult {
    guard swar_slices_valid(ctrl.len, keys.len, slots.len, gens.len) else {
        return FlatIndexResult { .. };
    }
    let h = flat_index_hash_u64(key);
    let tag = swar_tag_byte(h);
    let groups = (ctrl.len as u64) >> 3;
    let g_mask = sub_sat_u64(groups, 1);
    var g = (h >> 3) & g_mask;
    var first_free: i32 = -1;

    for _ in groups {
        let base = (g << 3) as i64;
        let w = swar_load_group_u64(ctrl, base);
        let hit = swar_probe_group_hit(keys, slots, gens, w, tag, base, key);
        if hit.found {
            return hit;
        }
        if first_free < 0 {
            let fm = swar_match_free(w);
            if fm != 0 {
                first_free = add_sat_i64(base, ctz(fm) >> 3) as i32;
            }
        }
        if swar_match_empty(w) != 0 {
            break;
        }
        g = add_sat_u64(g, 1) & g_mask;
    }
    guard first_free >= 0 else { return FlatIndexResult { .. }; }
    return FlatIndexResult {
        bucket_idx: first_free,
        slot_idx:   -1,
        gen:        gens[first_free as i64],
        found:      false,
    };
}

// Commits a new `(key, slot_idx)` into `bucket_idx` returned by `swar_index_get_or_put`.
// Increments the bucket ABA generation counter (skipping 0) and returns the new generation.
fn swar_index_commit_put(
    ctrl:       u8[:],
    keys:       u64[:],
    slots:      u16[:],
    gens:       u16[:],
    bucket_idx: i32,
    key:        u64,
    slot_idx:   u16,
) -> u16, bool {
    guard swar_slices_valid(ctrl.len, keys.len, slots.len, gens.len) else { return 0, false; }
    let bi = bucket_idx as i64;
    guard bi >= 0 && bi < ctrl.len && (ctrl[bi] & SWAR_CTRL_EMPTY) != 0 else {
        return 0, false;
    }
    var next_gen = add_sat_u64(gens[bi], 1) & 0xFFFF;
    if next_gen == 0 {
        next_gen = 1;
    }
    ctrl[bi] = swar_tag_byte(flat_index_hash_u64(key));
    keys[bi] = key;
    slots[bi] = slot_idx;
    gens[bi] = next_gen as u16;
    return gens[bi], true;
}

// Removes `key` from a SWAR index, emitting `SWAR_CTRL_EMPTY` if its 8-slot group already has an empty
// sentinel or `SWAR_CTRL_DELETED` otherwise.
fn swar_index_remove(
    ctrl:  u8[:],
    keys:  u64[:],
    slots: u16[:],
    gens:  u16[:],
    key:   u64,
) -> FlatIndexResult {
    guard swar_slices_valid(ctrl.len, keys.len, slots.len, gens.len) else {
        return FlatIndexResult { .. };
    }
    let h = flat_index_hash_u64(key);
    let tag = swar_tag_byte(h);
    let groups = (ctrl.len as u64) >> 3;
    let g_mask = sub_sat_u64(groups, 1);
    var g = (h >> 3) & g_mask;

    for _ in groups {
        let base = (g << 3) as i64;
        let w = swar_load_group_u64(ctrl, base);
        let hit = swar_probe_group_hit(keys, slots, gens, w, tag, base, key);
        if hit.found {
            let idx = hit.bucket_idx as i64;
            ctrl[idx] = if swar_match_empty(w) != 0 { SWAR_CTRL_EMPTY } else { SWAR_CTRL_DELETED };
            keys[idx] = 0;
            return hit;
        }
        if swar_match_empty(w) != 0 {
            return FlatIndexResult { .. };
        }
        g = add_sat_u64(g, 1) & g_mask;
    }
    return FlatIndexResult { .. };
}

// Clears all SWAR index slots to `SWAR_CTRL_EMPTY` while preserving ABA generation counters.
fn swar_index_clear(ctrl: u8[:], keys: u64[:]) {
    let n = min(ctrl.len, keys.len);
    for i in n {
        ctrl[i] = SWAR_CTRL_EMPTY;
        keys[i] = 0;
    }
}
