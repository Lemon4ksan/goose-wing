// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Structure-of-Arrays (SoA) High-Density Connection Table & Fast Timeout Sweeper.
// Eliminates cache pollution during 1-second timeout sweeps by decoupling
// 1-byte timeout ticks and 8-byte file descriptors from large payload buffers.
// Lazily allocates parallel columns on demand with zero startup footprint.
namespace wing;

import std;
import core from "..";

const SOA_TABLE_CAP:    i64 = 4096;
const SOA_INVALID_FD:   i64 = -1;
const SOA_INVALID_TICK: u8  = 255;

// Structure-of-Arrays connection state table.
root struct SoAConnTable {
    fds:            i64[>..]      = [],
    timeout_ticks:  u8[>..]       = [],
    leftover_lens:  u16[>..]      = [],
    leftover_offs:  i64[>..]      = [],
    tls_ct_lens:    u16[>..]      = [],
    tls_ct_offs:    i64[>..]      = [],
    conn_slots:     i32[>..]      = [],
    is_h2:          bool[>..]     = [],
    h2_slot_map:    i16[>..]      = [],
    has_tls:        bool[>..]     = [],
    tls_slots:      u16[>..]      = [],
    has_peer_ip:    bool[>..]     = [],
    peer_ip_hashes: u64[>..]      = [],
    peer_ips:       u8[..46][>..] = [],
    count:          i64           = 0,
    max_slots:      i64           = SOA_TABLE_CAP,
}

// Advances high-water mark for allocated connection slots.
inline fn advance_high_water_mark(current_limit: i64, slot: i64) -> i64 {
    let next_slot = core::add_sat_i64(slot, 1);
    return max(next_slot, current_limit);
}

// Records an expired connection slot into output array and returns incremented count.
inline fn record_expired_conn(dst: i64[:], current_count: i64, slot: i64) -> i64 {
    dst[current_count] = slot;
    return core::add_sat_i64(current_count, 1);
}

fn push_inactive_soa_slot(table: SoAConnTable&) {
    table.fds.push(SOA_INVALID_FD);
    table.timeout_ticks.push(SOA_INVALID_TICK);
    table.leftover_lens.push(0);
    table.leftover_offs.push(-1);
    table.tls_ct_lens.push(0);
    table.tls_ct_offs.push(-1);
    table.conn_slots.push(-1);
    table.is_h2.push(false);
    table.h2_slot_map.push(-1);
    table.has_tls.push(false);
    table.tls_slots.push(0xFFFF);
    table.has_peer_ip.push(false);
    table.peer_ip_hashes.push(0);
    table.peer_ips.push([]);
}

// Grows SoA columns lazily on demand so `slot` is addressable, raising `max_slots` when needed.
fn soa_table_ensure_slot(table: SoAConnTable&, slot: i64) -> bool {
    guard slot >= 0 else { return false; }
    if slot >= table.max_slots {
        table.max_slots = core::add_sat_i64(slot, 1);
    }
    while table.fds.len <= slot {
        push_inactive_soa_slot(table);
    }
    return true;
}

// Resets all parallel SoA columns for `slot`.
inline fn reset_soa_slot_fields(table: SoAConnTable&, slot: i64, fd: i64, timeout_tick: u8) {
    table.fds[slot] = fd;
    table.timeout_ticks[slot] = timeout_tick;
    table.leftover_lens[slot] = 0;
    table.leftover_offs[slot] = -1;
    table.tls_ct_lens[slot] = 0;
    table.tls_ct_offs[slot] = -1;
    table.conn_slots[slot] = -1;
    table.is_h2[slot] = false;
    table.h2_slot_map[slot] = -1;
    table.has_tls[slot] = false;
    table.tls_slots[slot] = 0xFFFF;
    table.has_peer_ip[slot] = false;
    table.peer_ip_hashes[slot] = 0;
    table.peer_ips[slot].clear();
}

// Resets all materialized slots in a SoAConnTable in place without allocating upfront capacity.
fn reset_soa_table_inplace(table: SoAConnTable&) {
    for i in table.fds.len {
        reset_soa_slot_fields(table, i, SOA_INVALID_FD, SOA_INVALID_TICK);
    }
    table.count = 0;
}

// Allocates an active connection slot in the SoA table, growing lazily up to `table.max_slots`.
fn soa_table_alloc(table: SoAConnTable&, fd: i64, timeout_tick: u8) -> i64 {
    guard fd > 0 else { return SOA_INVALID_FD; }
    let limit = min(table.fds.len, max(table.max_slots, 0));
    for i in limit {
        if table.fds[i] < 0 {
            reset_soa_slot_fields(table, i, fd, timeout_tick);
            table.count = advance_high_water_mark(table.count, i);
            return i;
        }
    }
    guard table.fds.len < table.max_slots else { return SOA_INVALID_FD; }
    let idx = table.fds.len;
    push_inactive_soa_slot(table);
    reset_soa_slot_fields(table, idx, fd, timeout_tick);
    table.count = advance_high_water_mark(table.count, idx);
    return idx;
}

// Returns whether `slot` is within the materialized bounds of the SoA connection table.
inline fn is_valid_slot(table: const SoAConnTable&, slot: i64) -> bool {
    return slot >= 0 && slot < table.fds.len;
}

// Returns whether `slot` is in bounds and currently holds an active file descriptor.
inline fn is_active_slot(table: const SoAConnTable&, slot: i64) -> bool {
    return table.is_valid_slot(slot) && table.fds[slot] > 0;
}

inline fn trim_soa_high_water_mark(table: SoAConnTable&) {
    while table.count > 0 && table.count <= table.fds.len {
        let last_idx = core::sub_sat_i64(table.count, 1);
        guard table.is_valid_slot(last_idx) && table.fds[last_idx] < 0 else {
            break;
        }
        table.count = last_idx;
    }
}

// Releases a connection slot in the SoA table.
fn soa_table_free(table: SoAConnTable&, slot: i64) {
    guard table.is_valid_slot(slot) else { return; }
    reset_soa_slot_fields(table, slot, SOA_INVALID_FD, SOA_INVALID_TICK);
    trim_soa_high_water_mark(table);
}

// Caches per-connection peer IP and its 64-bit FNV-1a hash in the SoA slot.
fn soa_table_set_peer_ip(table: SoAConnTable&, slot: i64, ip: const u8[:]) {
    guard table.is_active_slot(slot) else { return; }
    let resolved_ip = if ip.len > 0 { ip } else { "0.0.0.0" };
    let _ = table.peer_ips[slot].try_set(resolved_ip);
    table.peer_ip_hashes[slot] = core::fnv1a_64(resolved_ip);
    table.has_peer_ip[slot] = true;
}

// Returns cached peer IP slice for an active SoA slot, or empty slice if unpopulated.
inline fn soa_table_get_peer_ip(table: const SoAConnTable&, slot: i64) -> const u8[:] {
    guard table.is_active_slot(slot) && table.has_peer_ip[slot] else { return ""; }
    return table.peer_ips[slot][..];
}

// Updates the timeout tick for an active connection slot (activity refresh).
inline fn soa_table_touch(table: SoAConnTable&, slot: i64, new_tick: u8) {
    if slot == 0 && table.fds.len == 0 && table.max_slots > 0 {
        push_inactive_soa_slot(table);
    }
    guard table.is_active_slot(slot) else { return; }
    table.timeout_ticks[slot] = new_tick;
}

// Sweeps active connection deadlines with minimal memory bandwidth consumption.
// Scans tightly-packed 1-byte timeout ticks; returns count of expired connections found.
fn soa_table_sweep_expired(
    table:       SoAConnTable&,
    timer_wheel: const core::TickTimerWheel&,
    out_expired: i64[:],
) -> i64 {
    var expired_n: i64 = 0;
    let limit = min(max(table.count, 0), table.fds.len);

    for s in limit {
        let tick = table.timeout_ticks[s];
        guard tick != SOA_INVALID_TICK && core::tick_timer_is_expired(timer_wheel, tick) else { continue; }
        guard table.is_active_slot(s) else { continue; }
        guard expired_n < out_expired.len else { break; }
        expired_n = record_expired_conn(out_expired, expired_n, s);
    }

    return expired_n;
}
