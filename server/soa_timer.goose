// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Structure-of-Arrays (SoA) High-Density Connection Table & Fast Timeout Sweeper.
// Eliminates cache pollution during 1-second timeout sweeps by decoupling
// 1-byte timeout ticks and 8-byte file descriptors from large payload buffers.
// Lazily allocates parallel columns on demand with zero startup footprint.
namespace server;

import std;
import core;
import .internal;

const SOA_TABLE_CAP: i64 = 4096;

const SOA_INVALID_FD: i64 = -1;

const SOA_INVALID_TICK: u8 = 255;

// Intrusive doubly-linked list node for O(1) timing wheel bucket membership.
struct SoATimerLink {
    prev: i32 = -1,
    next: i32 = -1,
}

// Structure-of-Arrays connection state table.
root struct SoAConnTable {
    fds:                     i64[>..]          = [],
    generations:             u32[>..]          = [],
    timeout_ticks:           u8[>..]           = [],
    half_close_deadlines_ms: i64[>..]          = [],
    tx_stall_deadlines_ms:   i64[>..]          = [],
    leftover_lens:           u16[>..]          = [],
    leftover_offs:           i64[>..]          = [],
    tls_ct_lens:             u16[>..]          = [],
    tls_ct_offs:             i64[>..]          = [],
    conn_slots:              i32[>..]          = [],
    is_h2:                   bool[>..]         = [],
    h2_slot_map:             i16[>..]          = [],
    has_tls:                 bool[>..]         = [],
    tls_slots:               u16[>..]          = [],
    tls_hs_map:              i16[>..]          = [],
    tls_snis:                u8[..255][>..]    = [],
    has_peer_ip:             bool[>..]         = [],
    peer_ip_hashes:          u64[>..]          = [],
    peer_ips:                u8[..46][>..]     = [],
    free_l0:                 u64[>..]          = [],
    free_l1:                 u64[>..]          = [],
    wheel_heads:             i32[240]          = [-1; 240],
    wheel_mask:              u64[4]            = [0; 4],
    timer_links:             SoATimerLink[>..] = [],
    count:                   i64               = 0,
    max_slots:               i64               = SOA_TABLE_CAP,
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
    let free_idx = server_internal::soa_free_find_lowest(table, limit);
    if free_idx >= 0 {
        server_internal::reset_soa_slot_fields(table, free_idx, fd, timeout_tick);
        table.count = server_internal::advance_high_water_mark(table.count, free_idx);
        return free_idx;
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
    server_internal::soa_wheel_relink(table, slot, new_tick);
}

// Sweeps active connection deadlines in O(1 + k) via the 240-bucket hashed timing wheel.
// Returns count of expired connection slots written into `out_expired`.
fn soa_table_sweep_expired(
    table:       SoAConnTable&,
    timer_wheel: const core::TickTimerWheel&,
    out_expired: i64[:],
) -> i64 {
    guard timer_wheel.last_elapsed > 0 && out_expired.len > 0 else { return 0; }
    let expired_mask = server_internal::build_elapsed_wheel_mask(timer_wheel);
    var expired_n: i64 = 0;

    for w in 4 {
        var active = table.wheel_mask[w] & expired_mask[w];
        while active != 0 && expired_n < out_expired.len {
            let bit = ctz(active);
            active &= active - 1;
            let bucket = (w << 6) | bit;
            expired_n = server_internal::collect_wheel_bucket_expired(table, bucket, out_expired, expired_n);
        }
    }
    return expired_n;
}
