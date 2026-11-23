// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Internal math, slot management, and header-formatting helpers for GCRA rate limiters.
namespace security_internal;

import std;
import core;
import rfc.http;

const GCRA_MAX_CLOCK_DRIFT_NS: u64 = 5000000000; // 5.0 seconds
const SLOT_RETRY_AFTER:        u8  = 60;

// Zero-allocation binary division without arithmetic overflow operator hazards.
fn fast_div_u64(n: u64, d: u64) -> u64 {
    guard d > 0 else { return 0; }
    guard n >= d else { return 0; }

    var cur_d = d;
    var cur_q: u64 = 1;
    let half_n = n >> 1;

    while cur_d <= half_n {
        cur_d = core::add_sat_u64(cur_d, cur_d);
        cur_q = core::add_sat_u64(cur_q, cur_q);
    }

    var rem_n = n;
    var quotient: u64 = 0;

    while cur_q > 0 {
        if rem_n >= cur_d {
            rem_n = core::sub_sat_u64(rem_n, cur_d);
            quotient = quotient | cur_q;
        }
        cur_d = cur_d >> 1;
        cur_q = cur_q >> 1;
    }

    return quotient;
}

// Clamps TAT if system clock drifted or jumped backward into the past.
inline fn clamp_clock_drift(tat_old: u64, now_ns: u64, limit_window: u64) -> u64 {
    let drift_threshold = core::add_sat_u64(limit_window, GCRA_MAX_CLOCK_DRIFT_NS);
    let max_future = core::add_sat_u64(now_ns, drift_threshold);
    guard tat_old > max_future else { return tat_old; }
    return core::add_sat_u64(now_ns, limit_window);
}

// Calculates remaining burst allowance after admission without underflow or overflow hazards.
inline fn calc_remaining_burst(
    tau_ns:    u64,
    t_ns:      u64,
    max_burst: u64,
    tat_new:   u64,
    now_ns:    u64,
) -> u64 {
    let t_safe = max(t_ns, 1);
    let baseline = core::add_sat_u64(now_ns, t_safe);
    guard tat_new > baseline else { return max_burst; }
    let diff = core::sub_sat_u64(tat_new, baseline);
    guard tau_ns > diff else { return 0; }
    let rem_cells = fast_div_u64(core::sub_sat_u64(tau_ns, diff), t_safe);
    return min(rem_cells, max_burst);
}

fn eval_gcra_config(
    config:      const security::GcraConfig&,
    initial_tat: u64,
    cost:        u64,
    now_ns:      u64,
) -> security::GcraDecision, u64 {
    let t = config.emission_interval_ns;
    let tau = config.tau_ns;
    let limit_window = config.limit_window_ns;
    let max_cells = core::add_sat_u64(config.max_burst, 1);
    let delta = core::mul_sat_u64(cost, t);

    guard cost <= max_cells && delta <= limit_window else {
        let over_retry = max(core::sub_sat_u64(delta, limit_window), 1);
        return security::GcraDecision {
            allowed:         false,
            remaining_burst: 0,
            retry_after_ns:  over_retry,
            reset_after_ns:  over_retry,
            tat_ns:          initial_tat,
            ..
        }, initial_tat;
    }

    let tat_old = clamp_clock_drift(initial_tat, now_ns, limit_window);
    let tat_base = core::ct_max_u64(now_ns, tat_old);
    let tat_new = core::add_sat_u64(tat_base, delta);
    let t_allow = core::sub_sat_u64(tat_new, limit_window);
    let retry_after = core::sub_sat_u64(t_allow, now_ns);

    guard now_ns >= t_allow else {
        return security::GcraDecision {
            allowed:         false,
            remaining_burst: 0,
            retry_after_ns:  retry_after,
            reset_after_ns:  retry_after,
            tat_ns:          tat_old,
            ..
        }, tat_old;
    }

    let rem = calc_remaining_burst(tau, t, config.max_burst, tat_new, now_ns);
    let reset_after = core::sub_sat_u64(tat_new, now_ns);

    return security::GcraDecision {
        allowed:         true,
        remaining_burst: rem,
        retry_after_ns:  0,
        reset_after_ns:  reset_after,
        tat_ns:          tat_new,
        ..
    }, tat_new;
}

// ---- GatewayRateLimiter internal helpers -----------------------------------

fn find_idle_or_oldest_slot(limiter: const security::GatewayRateLimiter&, now_ns: u64) -> i64, bool {
    for &entry, i in limiter.entries {
        if !entry.in_use {
            return i, true;
        }
    }
    var oldest_idx:  i64  = 0;
    var found:       bool = false;
    var oldest_seen: u64  = 0xFFFFFFFFFFFFFFFF;

    for &entry, i in limiter.entries {
        if entry.cell.tat_ns <= now_ns && entry.last_seen_ns <= oldest_seen {
            oldest_seen = entry.last_seen_ns;
            oldest_idx = i;
            found = true;
        }
    }
    return oldest_idx, found;
}

inline fn populate_entry(
    entry:     security::GatewayClientEntry&,
    client_id: const u8[:],
    now_ns:    u64,
) -> bool {
    guard entry.client_id.try_set(client_id) else { return false; }
    entry.cell.tat_ns = now_ns;
    entry.last_seen_ns = now_ns;
    entry.consecutive_rejects = 0;
    entry.in_use = true;
    return true;
}

inline fn push_new_client_slot(
    limiter:   security::GatewayRateLimiter&,
    client_id: const u8[:],
    now_ns:    u64,
) -> i64, bool {
    guard client_id.len <= 64 else { return 0, false; }
    var new_entry = security::GatewayClientEntry { in_use: false, .. };
    guard populate_entry(new_entry, client_id, now_ns) else { return 0, false; }
    guard limiter.entries.try_push(new_entry) else { return 0, false; }
    return core::sub_sat_i64(limiter.entries.len, 1), true;
}

fn allocate_client_entry(
    limiter:   security::GatewayRateLimiter&,
    client_id: const u8[:],
    now_ns:    u64,
) -> i64, bool {
    guard client_id.len <= 64 else { return 0, false; }
    let existing_idx, found_existing = security::find_client_slot(limiter, client_id);
    if found_existing {
        return existing_idx, true;
    }

    for &entry, i in limiter.entries {
        if !entry.in_use {
            guard populate_entry(entry, client_id, now_ns) else { return 0, false; }
            return i, true;
        }
    }

    if limiter.entries.len < limiter.entries.cap {
        return push_new_client_slot(limiter, client_id, now_ns);
    }

    let slot, found_evict = find_idle_or_oldest_slot(limiter, now_ns);
    guard found_evict && slot >= 0 && slot < limiter.entries.len else { return 0, false; }
    guard populate_entry(limiter.entries[slot], client_id, now_ns) else { return 0, false; }
    return slot, true;
}

inline fn record_client_admission(
    limiter: security::GatewayRateLimiter&,
    slot:    i64,
    dec:     const security::GcraDecision&,
) {
    if dec.allowed {
        limiter.total_allowed = core::add_sat_u64(limiter.total_allowed, 1);
        limiter.entries[slot].consecutive_rejects = 0;
    } else {
        limiter.total_rejected = core::add_sat_u64(limiter.total_rejected, 1);
        let next_rej = core::add_sat_u64(limiter.entries[slot].consecutive_rejects, 1);
        limiter.entries[slot].consecutive_rejects = next_rej as u32;
    }
}

inline fn record_fallback_admission(
    limiter: security::GatewayRateLimiter&,
    dec:     const security::GcraDecision&,
) {
    if dec.allowed {
        limiter.total_allowed = core::add_sat_u64(limiter.total_allowed, 1);
    } else {
        limiter.total_rejected = core::add_sat_u64(limiter.total_rejected, 1);
    }
}

inline fn should_evict_client(
    entry:       const security::GatewayClientEntry&,
    max_idle_ns: u64,
    now_ns:      u64,
) -> bool {
    guard entry.in_use else { return false; }
    let idle_time = core::sub_sat_u64(now_ns, entry.last_seen_ns);
    return idle_time > max_idle_ns && entry.cell.tat_ns <= now_ns;
}

inline fn deactivate_client_slot(entry: security::GatewayClientEntry&) {
    entry.in_use = false;
    entry.client_id.clear();
}

inline fn reset_entry_slot(entry: security::GatewayClientEntry&) {
    entry.in_use = false;
    entry.cell.tat_ns = 0;
    entry.consecutive_rejects = 0;
    entry.client_id.clear();
}

// ---- Sharded & Probabilistic GCRA internal helpers -------------------------

inline fn find_existing_slot(
    slots:   const security::KeyedGcraSlot[..16]&,
    key_str: const u8[:],
) -> i64, bool {
    for &slot, idx in slots {
        if slot.active && slot.key[..] == key_str {
            return idx, true;
        }
    }
    return 0, false;
}

fn allocate_shard_slot(shard: security::GcraShard&, now_ns: u64) -> i64, bool {
    for &slot, idx in shard.slots {
        if !slot.active {
            return idx, true;
        }
    }
    if shard.slots.try_push(security::KeyedGcraSlot { active: false, .. }) {
        return core::sub_sat_i64(shard.slots.len, 1), true;
    }
    for &slot, idx in shard.slots {
        if slot.cell.tat_ns <= now_ns {
            return idx, true;
        }
    }
    return 0, false;
}

fn admit_or_reject_new_rate_limit_slot(
    limiter:   security::ShardedGcraLimiter&,
    shard_idx: i64,
    eff_key:   const u8[:],
    cost_n:    u64,
    now_ns:    u64,
) -> security::RateLimitDecision {
    let slot_idx, ok_slot = allocate_shard_slot(limiter.shards[shard_idx], now_ns);
    if ok_slot {
        let slot .= limiter.shards[shard_idx].slots[slot_idx];
        let _ = slot.key.try_set(eff_key);
        slot.cell.tat_ns = now_ns;
        slot.active = true;
        return security::gcra_check_n(limiter.quota, slot.cell, cost_n, now_ns);
    }
    var min_tat: u64 = 0xFFFFFFFFFFFFFFFF;
    for &slot in limiter.shards[shard_idx].slots {
        min_tat = min(min_tat, slot.cell.tat_ns);
    }
    let retry_ns = core::sub_sat_u64(min_tat, now_ns);
    return security::RateLimitDecision.Rejected {
        retry_after_ns: if retry_ns > 0 { retry_ns } else { limiter.quota.emission_interval_ns },
        current_tat_ns: min_tat,
    };
}

inline fn advance_probabilistic_sample_slot(pgcra: security::ProbabilisticGcra&, rate: u64) -> bool {
    if !pgcra.initialized || pgcra.rng_state == 0 {
        pgcra.rng_state = core::sim_entropy_u64() ^ 0x853c49e6748fea9b;
        let init_mix = core::splitmix64(pgcra.rng_state);
        pgcra.window_pos = 0;
        pgcra.window_target = core::fast_range_biased_u64(init_mix, rate);
        pgcra.initialized = true;
    } else if pgcra.window_pos >= rate {
        let next_mix = core::splitmix64(pgcra.rng_state);
        pgcra.window_pos = 0;
        pgcra.window_target = core::fast_range_biased_u64(next_mix, rate);
    }
    let sampled = pgcra.window_pos == pgcra.window_target;
    pgcra.window_pos = core::add_sat_u64(pgcra.window_pos, 1);
    return sampled;
}

inline fn ceil_ns_to_sec(ns: u64) -> u64 {
    if ns == 0 { return 0; }
    if ns <= 1000000000 { return 1; }
    return fast_div_u64(core::add_sat_u64(ns, 999999999), 1000000000);
}

fn find_header_hash_entry_idx(
    map:   const http::HeaderMap&,
    name:  const u8[:],
    hname: u32,
    wk_id: u8,
) -> i64, bool {
    if wk_id != 0xFF {
        let slot_idx = map.inline_slots[wk_id as i64];
        if slot_idx != 0xFF && slot_idx < map.entries.len {
            return slot_idx, true;
        }
        return 0, false;
    }
    for &e, i in map.entries {
        if e.name_hash == hname && map.entry_name(e).eq_ascii_fold(name) {
            return i, true;
        }
    }
    return 0, false;
}

inline fn try_overwrite_ratelimit_entry_same_len(
    map:     http::HeaderMap&,
    idx:     i64,
    val_str: const u8[:],
) -> bool {
    guard idx >= 0 && idx < map.entries.len else { return false; }
    let e .= map.entries[idx];
    guard e.next_idx == 0xFF && e.reserved == http::HEADER_SRC_STACK && e.values_end <= map.raw_buf.len else {
        return false;
    }
    let v_begin = e.values_begin as i64;
    let v_end = e.values_end as i64;
    guard core::sub_sat_i64(v_end, v_begin) == val_str.len else { return false; }
    if map.raw_buf[v_begin..v_end] == val_str {
        return true;
    }
    core::ct_copy_bytes(map.raw_buf[v_begin..v_end], val_str);
    return true;
}

fn set_ratelimit_u64_header(
    map:   http::HeaderMap&,
    name:  const u8[:],
    hname: u32,
    wk_id: u8,
    val:   u64,
) {
    let idx, found = find_header_hash_entry_idx(map, name, hname, wk_id);
    let needed = core::add_sat_i64(name.len, 24);
    if !found &&
        map.entries.len < 128 &&
        core::add_sat_i64(map.raw_buf.len, needed) <= 8192 {
        let n_begin = map.raw_buf.len as u16;
        map.raw_buf.append(name);
        let n_end = map.raw_buf.len as u16;
        val.format_u64_dec(map.raw_buf);
        let v_end = map.raw_buf.len as u16;
        let new_idx = map.entries.len as u8;
        if wk_id != 0xFF {
            map.inline_slots[wk_id as i64] = new_idx;
        }
        map.entries.push(http::HeaderEntry {
            name_begin:    n_begin,
            name_end:      n_end,
            values_begin:  n_end,
            values_end:    v_end,
            next_idx:      0xFF,
            flags:         0,
            well_known_id: wk_id,
            reserved:      0,
            name_hash:     hname,
        });
        map.header_contains_comma.push(false);
        return;
    }
    var val_str: u8[..24] = [];
    val.format_u64_dec(val_str);
    if found && try_overwrite_ratelimit_entry_same_len(map, idx, val_str[..]) {
        return;
    }
    let _ = map.set_or_replace(name, val_str[..], false);
}

fn sample_gcra_jitter_ns(jitter: const security::GcraJitter&, prng_state: u64&) -> i64 {
    let min_val = max(jitter.min_ns, 0);
    guard jitter.max_ns > min_val else { return min_val; }
    if prng_state == 0 {
        let seeded = core::sim_entropy_u64() ^ 0x853c49e6748fea9b;
        prng_state = if seeded != 0 { seeded } else { 0x853c49e6748fea9b };
    }
    let mixed = core::splitmix64(prng_state);
    let span = (core::sub_sat_i64(jitter.max_ns, min_val)) as u64;
    let rem = core::fast_range_biased_u64(mixed, span);
    let offset = (min(rem, 0x7FFFFFFFFFFFFFFF)) as i64;
    return core::add_sat_i64(min_val, offset);
}

// ---- EdgeRateLimiter thread-local arena & open-addressed hash table --------

const EDGE_BUCKET_EMPTY:      i64 = -1;
const EDGE_BUCKET_TOMBSTONE:  i64 = -2;
const EDGE_CLOCK_SCAN_LIMIT:  i64 = 32;
const EDGE_MIN_BUCKET_CAP:    i64 = 8;
const EDGE_MAX_CLIENTS_LIMIT: i64 = 1048576;

struct EdgeRateSlotMeta {
    entries_offset: i64  = 0,
    entries_len:    i64  = 0,
    entries_cap:    i64  = 0,
    buckets_offset: i64  = 0,
    buckets_cap:    i64  = 0,
    tombstones:     i64  = 0,
    active:         bool = false,
}

root struct EdgeRateArena {
    slots:   EdgeRateSlotMeta[>..]             = [],
    entries: security::GatewayClientEntry[>..] = [],
    buckets: i64[>..]                          = [],
}

var g_edge_rl_arena: EdgeRateArena = EdgeRateArena { .. };

inline fn clamp_edge_max_clients(max_clients: i64) -> i64 {
    return min(max(max_clients, 1), EDGE_MAX_CLIENTS_LIMIT);
}

fn calc_edge_bucket_cap(eff_max: i64) -> i64 {
    let target = core::add_sat_i64(eff_max, eff_max);
    var cap = EDGE_MIN_BUCKET_CAP;
    while cap < target && cap < 0x20000000 {
        cap = core::add_sat_i64(cap, cap);
    }
    return cap;
}

fn clear_edge_arena_slot(slot_idx: i64) {
    guard slot_idx >= 0 && slot_idx < g_edge_rl_arena.slots.len else { return; }
    let meta .= g_edge_rl_arena.slots[slot_idx];
    for i in meta.entries_len {
        let e_idx = core::add_sat_i64(meta.entries_offset, i);
        if e_idx < g_edge_rl_arena.entries.len {
            reset_entry_slot(g_edge_rl_arena.entries[e_idx]);
        }
    }
    for b in meta.buckets_cap {
        let b_idx = core::add_sat_i64(meta.buckets_offset, b);
        if b_idx < g_edge_rl_arena.buckets.len {
            g_edge_rl_arena.buckets[b_idx] = EDGE_BUCKET_EMPTY;
        }
    }
    meta.entries_len = 0;
    meta.tombstones = 0;
}

fn alloc_edge_arena_slot(max_clients: i64) -> i64 {
    let eff_max = clamp_edge_max_clients(max_clients);
    let req_buckets = calc_edge_bucket_cap(eff_max);

    for &meta, i in g_edge_rl_arena.slots {
        if !meta.active && meta.entries_cap >= eff_max && meta.buckets_cap >= req_buckets {
            clear_edge_arena_slot(i);
            g_edge_rl_arena.slots[i].active = true;
            return i;
        }
    }

    let entries_off = g_edge_rl_arena.entries.len;
    let buckets_off = g_edge_rl_arena.buckets.len;
    for _ in eff_max {
        g_edge_rl_arena.entries.push(security::GatewayClientEntry { in_use: false, .. });
    }
    for _ in req_buckets {
        g_edge_rl_arena.buckets.push(EDGE_BUCKET_EMPTY);
    }
    g_edge_rl_arena.slots.push(EdgeRateSlotMeta {
        entries_offset: entries_off,
        entries_len:    0,
        entries_cap:    eff_max,
        buckets_offset: buckets_off,
        buckets_cap:    req_buckets,
        tombstones:     0,
        active:         true,
    });
    return core::sub_sat_i64(g_edge_rl_arena.slots.len, 1);
}

fn release_edge_arena_slot(slot_idx: i64) {
    guard slot_idx >= 0 && slot_idx < g_edge_rl_arena.slots.len else { return; }
    guard g_edge_rl_arena.slots[slot_idx].active else { return; }
    clear_edge_arena_slot(slot_idx);
    g_edge_rl_arena.slots[slot_idx].active = false;
}

fn edge_hash_start_pos(client_id: const u8[:], buckets_cap: i64) -> i64 {
    let cap_pos = max(buckets_cap, 1);
    let mask = (core::sub_sat_i64(cap_pos, 1)) as u64;
    let masked = core::fnv1a_64(client_id) & mask;
    return (min(masked, 0x7FFFFFFFFFFFFFFF)) as i64;
}

inline fn edge_bucket_matches(
    meta:      const EdgeRateSlotMeta&,
    b_val:     i64,
    client_id: const u8[:],
) -> bool {
    guard b_val >= 0 && b_val < meta.entries_len else { return false; }
    let e .= g_edge_rl_arena.entries[core::add_sat_i64(meta.entries_offset, b_val)];
    return e.in_use && e.client_id[..] == client_id;
}

fn edge_probe_bucket(slot_idx: i64, client_id: const u8[:]) -> i64, i64, i64, bool {
    let meta .= g_edge_rl_arena.slots[slot_idx];
    guard meta.buckets_cap > 0 else { return 0, -1, -1, false; }
    var pos = edge_hash_start_pos(client_id, meta.buckets_cap);
    var first_tomb: i64 = -1;

    for _ in meta.buckets_cap {
        let b_val = g_edge_rl_arena.buckets[core::add_sat_i64(meta.buckets_offset, pos)];
        if b_val == EDGE_BUCKET_EMPTY {
            return 0, pos, first_tomb, false;
        }
        if b_val == EDGE_BUCKET_TOMBSTONE && first_tomb < 0 {
            first_tomb = pos;
        } else if edge_bucket_matches(meta, b_val, client_id) {
            return b_val, pos, first_tomb, true;
        }
        pos = core::add_sat_i64(pos, 1);
        if pos >= meta.buckets_cap { pos = 0; }
    }
    return 0, -1, first_tomb, false;
}

fn edge_insert_clean_bucket(slot_idx: i64, client_id: const u8[:], local_idx: i64) {
    let meta .= g_edge_rl_arena.slots[slot_idx];
    guard meta.buckets_cap > 0 else { return; }
    var pos = edge_hash_start_pos(client_id, meta.buckets_cap);
    for _ in meta.buckets_cap {
        let abs_b = core::add_sat_i64(meta.buckets_offset, pos);
        if g_edge_rl_arena.buckets[abs_b] < 0 {
            g_edge_rl_arena.buckets[abs_b] = local_idx;
            return;
        }
        pos = core::add_sat_i64(pos, 1);
        if pos >= meta.buckets_cap { pos = 0; }
    }
}

fn rebuild_edge_slot_buckets(slot_idx: i64) {
    let meta .= g_edge_rl_arena.slots[slot_idx];
    for b in meta.buckets_cap {
        g_edge_rl_arena.buckets[core::add_sat_i64(meta.buckets_offset, b)] = EDGE_BUCKET_EMPTY;
    }
    meta.tombstones = 0;
    for i in meta.entries_len {
        let e .= g_edge_rl_arena.entries[core::add_sat_i64(meta.entries_offset, i)];
        if e.in_use {
            edge_insert_clean_bucket(slot_idx, e.client_id[..], i);
        }
    }
}

fn edge_remove_bucket_key(slot_idx: i64, client_id: const u8[:]) {
    let _, hit_pos, _, found = edge_probe_bucket(slot_idx, client_id);
    guard found && hit_pos >= 0 else { return; }
    let meta .= g_edge_rl_arena.slots[slot_idx];
    let abs_b = core::add_sat_i64(meta.buckets_offset, hit_pos);
    g_edge_rl_arena.buckets[abs_b] = EDGE_BUCKET_TOMBSTONE;
    meta.tombstones = core::add_sat_i64(meta.tombstones, 1);
}

fn edge_pick_clock_victim(
    slot_idx:     i64,
    start_cursor: i64,
    eff_max:      i64,
    now_ns:       u64,
) -> i64, i64 {
    let meta .= g_edge_rl_arena.slots[slot_idx];
    let count = min(meta.entries_len, eff_max);
    guard count > 0 else { return 0, 0; }
    var idx = if start_cursor >= 0 && start_cursor < count { start_cursor } else { 0 };
    let scan_len = min(EDGE_CLOCK_SCAN_LIMIT, count);
    var idle_idx:    i64 = -1;
    var idle_seen:   u64 = 0xFFFFFFFFFFFFFFFF;
    var oldest_idx:  i64 = idx;
    var oldest_seen: u64 = 0xFFFFFFFFFFFFFFFF;

    for _ in scan_len {
        let e .= g_edge_rl_arena.entries[core::add_sat_i64(meta.entries_offset, idx)];
        if e.last_seen_ns <= oldest_seen {
            oldest_seen = e.last_seen_ns;
            oldest_idx = idx;
        }
        if e.cell.tat_ns <= now_ns && e.last_seen_ns <= idle_seen {
            idle_seen = e.last_seen_ns;
            idle_idx = idx;
        }
        idx = core::add_sat_i64(idx, 1);
        if idx >= count { idx = 0; }
    }
    let victim = if idle_idx >= 0 { idle_idx } else { oldest_idx };
    var next_cur = core::add_sat_i64(victim, 1);
    if next_cur >= count { next_cur = 0; }
    return victim, next_cur;
}

inline fn edge_write_bucket_slot(slot_idx: i64, bucket_rel: i64, local_idx: i64) {
    let meta .= g_edge_rl_arena.slots[slot_idx];
    let abs_b = core::add_sat_i64(meta.buckets_offset, bucket_rel);
    if g_edge_rl_arena.buckets[abs_b] == EDGE_BUCKET_TOMBSTONE {
        meta.tombstones = core::sub_sat_i64(meta.tombstones, 1);
    }
    g_edge_rl_arena.buckets[abs_b] = local_idx;
}

fn edge_evict_and_insert(
    limiter:    security::EdgeRateLimiter&,
    slot_idx:   i64,
    client_id:  const u8[:],
    ins_bucket: i64,
    eff_max:    i64,
    now_ns:     u64,
) -> i64, bool, bool {
    let meta .= g_edge_rl_arena.slots[slot_idx];
    let victim_local, next_cur = edge_pick_clock_victim(
        slot_idx,
        limiter.next_evict_cursor,
        eff_max,
        now_ns,
    );
    limiter.next_evict_cursor = next_cur;
    let abs_victim = core::add_sat_i64(meta.entries_offset, victim_local);
    edge_remove_bucket_key(slot_idx, g_edge_rl_arena.entries[abs_victim].client_id[..]);
    guard populate_entry(g_edge_rl_arena.entries[abs_victim], client_id, now_ns) else {
        return 0, false, false;
    }
    if meta.tombstones > (meta.buckets_cap >> 2) {
        rebuild_edge_slot_buckets(slot_idx);
    } else {
        edge_write_bucket_slot(slot_idx, ins_bucket, victim_local);
    }
    return abs_victim, true, true;
}

fn edge_lookup_or_insert(
    limiter:   security::EdgeRateLimiter&,
    client_id: const u8[:],
    now_ns:    u64,
) -> i64, bool, bool {
    let slot_idx = limiter.arena_slot;
    guard slot_idx >= 0 && slot_idx < g_edge_rl_arena.slots.len else { return 0, false, false; }
    let meta .= g_edge_rl_arena.slots[slot_idx];
    guard meta.active else { return 0, false, false; }

    let local_idx, empty_pos, first_tomb, found = edge_probe_bucket(slot_idx, client_id);
    if found {
        return core::add_sat_i64(meta.entries_offset, local_idx), false, true;
    }

    var ins_bucket = if first_tomb >= 0 { first_tomb } else { empty_pos };
    if meta.tombstones > (meta.buckets_cap >> 2) || ins_bucket < 0 {
        rebuild_edge_slot_buckets(slot_idx);
        let _, re_empty, re_tomb, _ = edge_probe_bucket(slot_idx, client_id);
        ins_bucket = if re_tomb >= 0 { re_tomb } else { re_empty };
    }
    guard ins_bucket >= 0 else { return 0, false, false; }

    let eff_max = min(limiter.max_clients, meta.entries_cap);
    if meta.entries_len < eff_max {
        let new_local = meta.entries_len;
        let abs_entry = core::add_sat_i64(meta.entries_offset, new_local);
        guard populate_entry(g_edge_rl_arena.entries[abs_entry], client_id, now_ns) else {
            return 0, false, false;
        }
        edge_write_bucket_slot(slot_idx, ins_bucket, new_local);
        meta.entries_len = core::add_sat_i64(meta.entries_len, 1);
        return abs_entry, false, true;
    }
    return edge_evict_and_insert(limiter, slot_idx, client_id, ins_bucket, eff_max, now_ns);
}

inline fn record_edge_admission(
    limiter:   security::EdgeRateLimiter&,
    abs_entry: i64,
    dec:       const security::GcraDecision&,
) {
    if dec.allowed {
        limiter.total_allowed = core::add_sat_u64(limiter.total_allowed, 1);
        g_edge_rl_arena.entries[abs_entry].consecutive_rejects = 0;
    } else {
        limiter.total_rejected = core::add_sat_u64(limiter.total_rejected, 1);
        let next_rej = core::add_sat_u64(g_edge_rl_arena.entries[abs_entry].consecutive_rejects, 1);
        g_edge_rl_arena.entries[abs_entry].consecutive_rejects = next_rej as u32;
    }
}

inline fn record_edge_fallback_admission(
    limiter: security::EdgeRateLimiter&,
    dec:     const security::GcraDecision&,
) {
    if dec.allowed {
        limiter.total_allowed = core::add_sat_u64(limiter.total_allowed, 1);
    } else {
        limiter.total_rejected = core::add_sat_u64(limiter.total_rejected, 1);
    }
}

fn evict_idle_edge_arena_clients(slot_idx: i64, max_idle_ns: u64, now_ns: u64) -> i32 {
    guard slot_idx >= 0 && slot_idx < g_edge_rl_arena.slots.len else { return 0; }
    let meta .= g_edge_rl_arena.slots[slot_idx];
    guard meta.active else { return 0; }

    var i:       i64 = 0;
    var evicted: i64 = 0;
    while i < meta.entries_len {
        let e_idx = core::add_sat_i64(meta.entries_offset, i);
        if should_evict_client(g_edge_rl_arena.entries[e_idx], max_idle_ns, now_ns) {
            deactivate_client_slot(g_edge_rl_arena.entries[e_idx]);
            let last_idx = core::sub_sat_i64(meta.entries_len, 1);
            if i < last_idx {
                let last_abs = core::add_sat_i64(meta.entries_offset, last_idx);
                g_edge_rl_arena.entries[e_idx] = g_edge_rl_arena.entries[last_abs];
                reset_entry_slot(g_edge_rl_arena.entries[last_abs]);
            }
            meta.entries_len = last_idx;
            evicted = core::add_sat_i64(evicted, 1);
        } else {
            i = core::add_sat_i64(i, 1);
        }
    }
    if evicted > 0 {
        rebuild_edge_slot_buckets(slot_idx);
    }
    return evicted as i32;
}
