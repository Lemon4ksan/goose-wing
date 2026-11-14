// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Singleflight duplicate call suppression for coalescing identical concurrent requests.
namespace core;

import std;
import core.math.arithmetic;
import core.math.hash;

struct FlightEntry {
    key:          u8[..64] = [],
    key_hash:     u64      = 0,
    is_in_flight: bool     = false,
    is_done:      bool     = false,
    has_failed:   bool     = false,
    val:          i64      = 0,
    waiter_count: i32      = 0,
    shared:       bool     = false,
}

struct SingleflightGroup {
    entries:            FlightEntry[..32] = [],
    total_leader_calls: i64               = 0,
    total_shared_calls: i64               = 0,
}

// Finds the index of an entry by key and precomputed hash, or returns -1.
fn find_flight_entry_idx(g: const SingleflightGroup&, key_str: const u8[:], kh: u64) -> i64 {
    for idx in g.entries.len {
        if g.entries[idx].key_hash == kh && g.entries[idx].key[..] == key_str {
            return idx;
        }
    }
    return -1;
}

// Registers or joins an execution for key_str.
// Returns (is_leader, val, shared).
// If is_leader is true, the caller executes the operation and calls finish_call.
// If is_leader is false and execution is in-flight, returns (false, 0, true).
// If already completed, returns the cached result.
fn start_or_join(g: SingleflightGroup&, key_str: const u8[:]) -> bool, i64, bool {
    guard key_str.len <= 64 else {
        // Key exceeds entry capacity; execute unshared to prevent buffer truncation / permanent slot poisoning
        g.total_leader_calls = add_sat_i64(g.total_leader_calls, 1);
        return true, 0, false;
    }

    let kh = wyhash64(key_str);
    let idx = find_flight_entry_idx(g, key_str, kh);
    if idx >= 0 {
        if g.entries[idx].is_in_flight {
            if g.entries[idx].waiter_count < 0x7FFFFFFF {
                g.entries[idx].waiter_count += 1;
            }
            g.entries[idx].shared = true;
            g.total_shared_calls = add_sat_i64(g.total_shared_calls, 1);
            return false, 0, true; // Follower
        }
        if g.entries[idx].is_done {
            return false, g.entries[idx].val, g.entries[idx].shared; // Cached completion
        }
    }

    if g.entries.len < g.entries.cap {
        var new_entry = FlightEntry {
            key_hash:     kh,
            is_in_flight: true,
            ..
        };
        new_entry.key.append(key_str);
        g.entries.push(new_entry);
        g.total_leader_calls = add_sat_i64(g.total_leader_calls, 1);
        return true, 0, false; // Leader
    }

    // Capacity overflow fallback: execute unshared
    g.total_leader_calls = add_sat_i64(g.total_leader_calls, 1);
    return true, 0, false;
}

// Marks the in-flight key execution as finished with val and success status.
// Returns (true, waiter_count) if the key was found in-flight.
fn finish_call(g: SingleflightGroup&, key_str: const u8[:], val: i64, ok: bool = true) -> bool, i32 {
    let kh = wyhash64(key_str);
    let idx = find_flight_entry_idx(g, key_str, kh);
    if idx >= 0 && g.entries[idx].is_in_flight {
        g.entries[idx].is_in_flight = false;
        g.entries[idx].is_done = true;
        g.entries[idx].has_failed = !ok;
        g.entries[idx].val = val;
        let waiters = g.entries[idx].waiter_count;
        return true, waiters;
    }
    return false, 0;
}

// forget evicts key_str from the group immediately, allowing the next caller to execute as leader.
// Returns true if the key was found and removed, false otherwise.
fn forget(g: SingleflightGroup&, key_str: const u8[:]) -> bool {
    let kh = wyhash64(key_str);
    let idx = find_flight_entry_idx(g, key_str, kh);
    if idx >= 0 {
        g.entries[idx] = g.entries[g.entries.len - 1];
        g.entries.pop();
        return true;
    }
    return false;
}

// Removes key_str only if it was not shared with any concurrent caller (waiter_count == 0).
// Returns true if removed, false if preserved.
fn forget_unshared(g: SingleflightGroup&, key_str: const u8[:]) -> bool {
    let kh = wyhash64(key_str);
    let idx = find_flight_entry_idx(g, key_str, kh);
    if idx >= 0 {
        if g.entries[idx].waiter_count == 0 {
            g.entries[idx] = g.entries[g.entries.len - 1];
            g.entries.pop();
            return true;
        }
        return false;
    }
    return false;
}

// Queries whether key is currently executing in-flight.
fn is_in_flight(g: const SingleflightGroup&, key_str: const u8[:]) -> bool {
    let kh = wyhash64(key_str);
    let idx = find_flight_entry_idx(g, key_str, kh);
    return idx >= 0 && g.entries[idx].is_in_flight;
}

// Returns the count of concurrent waiters for key.
fn waiter_count(g: const SingleflightGroup&, key_str: const u8[:]) -> i32 {
    let kh = wyhash64(key_str);
    let idx = find_flight_entry_idx(g, key_str, kh);
    return if idx >= 0 { g.entries[idx].waiter_count } else { 0 };
}

// Returns whether the call for key was shared across multiple callers.
fn is_shared(g: const SingleflightGroup&, key_str: const u8[:]) -> bool {
    let kh = wyhash64(key_str);
    let idx = find_flight_entry_idx(g, key_str, kh);
    return idx >= 0 && g.entries[idx].shared;
}

// Retrieves the result value and completion status of a finished call.
fn result_value(g: const SingleflightGroup&, key_str: const u8[:]) -> i64, bool {
    let kh = wyhash64(key_str);
    let idx = find_flight_entry_idx(g, key_str, kh);
    if idx >= 0 && g.entries[idx].is_done {
        return g.entries[idx].val, !g.entries[idx].has_failed;
    }
    return 0, false;
}
