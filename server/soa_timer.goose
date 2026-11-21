// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Structure-of-Arrays (SoA) High-Density Connection Table & Fast Timeout Sweeper.
// Eliminates cache pollution during 1-second timeout sweeps by decoupling
// 1-byte timeout ticks and 8-byte file descriptors from large payload buffers.
// Lazily allocates parallel columns on demand with zero startup footprint.
namespace server;

import std;
import core from "..";
import .internal;

const SOA_TABLE_CAP: i64 = 4096;

const SOA_INVALID_FD: i64 = -1;

const SOA_INVALID_TICK: u8 = 255;

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

// Grows SoA columns lazily on demand so `slot` is addressable, raising `max_slots` when needed.
fn soa_table_ensure_slot(table: SoAConnTable&, slot: i64) -> bool {
    guard slot >= 0 else { return false; }
    if slot >= table.max_slots {
        table.max_slots = core::add_sat_i64(slot, 1);
    }
    while table.fds.len <= slot {
        server_internal::push_inactive_soa_slot(table);
    }
    return true;
}

// Allocates an active connection slot in the SoA table, growing lazily up to `table.max_slots`.
fn soa_table_alloc(table: SoAConnTable&, fd: i64, timeout_tick: u8) -> i64 {
    guard fd > 0 else { return SOA_INVALID_FD; }
    let limit = min(table.fds.len, max(table.max_slots, 0));
    for i in limit {
        if table.fds[i] < 0 {
            server_internal::reset_soa_slot_fields(table, i, fd, timeout_tick);
            table.count = server_internal::advance_high_water_mark(table.count, i);
            return i;
        }
    }
    guard table.fds.len < table.max_slots else { return SOA_INVALID_FD; }
    let idx = table.fds.len;
    server_internal::push_inactive_soa_slot(table);
    server_internal::reset_soa_slot_fields(table, idx, fd, timeout_tick);
    table.count = server_internal::advance_high_water_mark(table.count, idx);
    return idx;
}

// Releases a connection slot in the SoA table.
fn soa_table_free(table: SoAConnTable&, slot: i64) {
    guard server_internal::is_valid_slot(table, slot) else { return; }
    server_internal::reset_soa_slot_fields(table, slot, SOA_INVALID_FD, SOA_INVALID_TICK);
    server_internal::trim_soa_high_water_mark(table);
}

// Caches per-connection peer IP and its 64-bit FNV-1a hash in the SoA slot.
fn soa_table_set_peer_ip(table: SoAConnTable&, slot: i64, ip: const u8[:]) {
    guard server_internal::is_active_slot(table, slot) else { return; }
    let resolved_ip = if ip.len > 0 { ip } else { "0.0.0.0" };
    let _ = table.peer_ips[slot].try_set(resolved_ip);
    table.peer_ip_hashes[slot] = core::fnv1a_64(resolved_ip);
    table.has_peer_ip[slot] = true;
}

// Returns cached peer IP slice for an active SoA slot, or empty slice if unpopulated.
inline fn soa_table_get_peer_ip(table: const SoAConnTable&, slot: i64) -> const u8[:] {
    guard server_internal::is_active_slot(table, slot) && table.has_peer_ip[slot] else { return ""; }
    return table.peer_ips[slot][..];
}

// Updates the timeout tick for an active connection slot (activity refresh).
inline fn soa_table_touch(table: SoAConnTable&, slot: i64, new_tick: u8) {
    if slot == 0 && table.fds.len == 0 && table.max_slots > 0 {
        server_internal::push_inactive_soa_slot(table);
    }
    guard server_internal::is_active_slot(table, slot) else { return; }
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
        guard server_internal::is_active_slot(table, s) else { continue; }
        guard expired_n < out_expired.len else { break; }
        expired_n = server_internal::record_expired_conn(out_expired, expired_n, s);
    }

    return expired_n;
}
