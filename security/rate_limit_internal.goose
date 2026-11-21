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
        pgcra.rng_state = (clock_ns() as u64) ^ 0x853c49e6748fea9b;
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
        let seeded = (clock_ns() as u64) ^ 0x853c49e6748fea9b;
        prng_state = if seeded != 0 { seeded } else { 0x853c49e6748fea9b };
    }
    let mixed = core::splitmix64(prng_state);
    let span = (core::sub_sat_i64(jitter.max_ns, min_val)) as u64;
    let rem = core::fast_range_biased_u64(mixed, span);
    let offset = (min(rem, 0x7FFFFFFFFFFFFFFF)) as i64;
    return core::add_sat_i64(min_val, offset);
}
