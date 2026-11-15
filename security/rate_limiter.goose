// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Generic Cell Rate Algorithm (GCRA) leaky-bucket rate limiter.
namespace wing;

import std;
import core from "..";
import rfc.http;
import security.gcra;

// ---- quota specification & decisions ---------------------------------------

struct GcraQuota {
    emission_interval_ns: u64 = 1000000000, // T = period / limit
    delay_tolerance_ns:   u64 = 0,          // tau = T * burst
    limit:                u64 = 1,
    period_ns:            u64 = 1000000000,
    burst:                u64 = 0,
}

// Calculates GCRA quota parameters from sustained limit, period, and burst tolerance.
// T = period / limit (emission interval), tau = T * burst (delay tolerance).
fn new_gcra_quota(limit: u64, period_ns: i64, burst: u64 = 0) -> GcraQuota {
    let p_ns = if period_ns > 0 { period_ns as u64 } else { SECOND as u64 };
    let l = max(limit, 1);
    let t_ns = max(fast_div_u64(p_ns, l), 1);
    let tau_ns = core::mul_sat_u64(t_ns, burst);

    return GcraQuota {
        emission_interval_ns: t_ns,
        delay_tolerance_ns:   tau_ns,
        limit:                l,
        period_ns:            p_ns,
        burst:                burst,
    };
}

enum RateLimitDecision {
    Allowed { remaining_burst: u64, new_tat_ns: u64, reset_after_ns: u64 },
    Reserved { wait_ns: u64, new_tat_ns: u64 },
    Rejected { retry_after_ns: u64, current_tat_ns: u64, insufficient_capacity: bool = false },
}

fn is_allowed(decision: const RateLimitDecision&) -> bool {
    return match decision {
        Allowed _ => true,
        Reserved _ => true,
        Rejected _ => false,
    };
}

// Single TAT state cell (64-bit scalar)
struct GcraCell {
    tat_ns: u64 = 0,
}

// Maximum allowable backward clock jump tolerance before clamping TAT
const GCRA_MAX_CLOCK_DRIFT_NS: u64 = 5000000000; // 5.0s

// Calculates remaining burst allowance after admission without underflow or overflow hazards.
inline fn gcra_remaining_burst(tau: u64, t: u64, burst: u64, tat: u64, now_ns: u64) -> u64 {
    let t_safe = max(t, 1);
    let baseline = core::add_sat_u64(now_ns, t_safe);
    guard tat > baseline else { return burst; }
    let diff = core::sub_sat_u64(tat, baseline);
    guard tau > diff else { return 0; }
    let rem = fast_div_u64(core::sub_sat_u64(tau, diff), t_safe);
    return min(rem, burst);
}

// Evaluates rate limit admission for a request consuming cost_n tokens at now_ns.
// Returns Allowed with remaining capacity, or Rejected with retry_after_ns.
fn gcra_check_n(quota: const GcraQuota&, cell: GcraCell&, cost_n: u64, now_ns: u64) -> RateLimitDecision {
    let t = max(quota.emission_interval_ns, 1);
    let tau = quota.delay_tolerance_ns;
    let delta = core::mul_sat_u64(cost_n, t);

    let limit_window = core::add_sat_u64(tau, t);
    var tat_old = cell.tat_ns;

    // Clock drift & backward jump protection:
    // If system or NTP clock jumps backward (now_ns < tat_old - drift_threshold),
    // clamp tat_old to the operational window (now_ns + limit_window) to prevent
    // prolonged client lockouts and denial of service.
    let drift_threshold = core::add_sat_u64(limit_window, GCRA_MAX_CLOCK_DRIFT_NS);
    if tat_old > core::add_sat_u64(now_ns, drift_threshold) {
        tat_old = core::add_sat_u64(now_ns, limit_window);
        cell.tat_ns = tat_old;
    }

    let tat_base = core::ct_max_u64(now_ns, tat_old);
    if delta > limit_window {
        let excess = core::sub_sat_u64(delta, limit_window);
        let base_wait = core::sub_sat_u64(tat_base, now_ns);
        return RateLimitDecision.Rejected {
            retry_after_ns:        core::add_sat_u64(base_wait, excess),
            current_tat_ns:        tat_old,
            insufficient_capacity: true,
        };
    }

    let tat_new = core::add_sat_u64(tat_base, delta);
    let t_allow = core::sub_sat_u64(tat_new, limit_window);

    if now_ns < t_allow {
        let retry_after = core::sub_sat_u64(t_allow, now_ns);
        return RateLimitDecision.Rejected {
            retry_after_ns: retry_after,
            current_tat_ns: tat_old,
        };
    }

    cell.tat_ns = tat_new;

    let rem = gcra_remaining_burst(tau, t, quota.burst, tat_new, now_ns);
    let reset_after = core::sub_sat_u64(tat_new, now_ns);

    return RateLimitDecision.Allowed {
        remaining_burst: rem,
        new_tat_ns:      tat_new,
        reset_after_ns:  reset_after,
    };
}

// Reserves cell capacity in advance up to max_wait_ns for multi-cost requests.
// Returns Reserved if the caller can wait, Allowed if immediate, or Rejected if wait exceeds max_wait_ns.
fn gcra_reserve_n(
    quota:       const GcraQuota&,
    cell:        GcraCell&,
    cost_n:      u64,
    now_ns:      u64,
    max_wait_ns: u64,
) -> RateLimitDecision {
    let t = max(quota.emission_interval_ns, 1);
    let tau = quota.delay_tolerance_ns;
    let delta = core::mul_sat_u64(cost_n, t);

    let limit_window = core::add_sat_u64(tau, t);
    var tat_old = cell.tat_ns;

    let drift_threshold = core::add_sat_u64(limit_window, GCRA_MAX_CLOCK_DRIFT_NS);
    if tat_old > core::add_sat_u64(now_ns, drift_threshold) {
        tat_old = core::add_sat_u64(now_ns, limit_window);
        cell.tat_ns = tat_old;
    }

    let tat_base = core::ct_max_u64(now_ns, tat_old);
    if delta > core::add_sat_u64(limit_window, max_wait_ns) {
        let excess = core::sub_sat_u64(delta, limit_window);
        let base_wait = core::sub_sat_u64(tat_base, now_ns);
        return RateLimitDecision.Rejected {
            retry_after_ns:        core::add_sat_u64(base_wait, excess),
            current_tat_ns:        tat_old,
            insufficient_capacity: true,
        };
    }

    let tat_new = core::add_sat_u64(tat_base, delta);
    let t_allow = core::sub_sat_u64(tat_new, limit_window);

    if now_ns >= t_allow {
        cell.tat_ns = tat_new;
        let reset_after = core::sub_sat_u64(tat_new, now_ns);
        let rem = gcra_remaining_burst(tau, t, quota.burst, tat_new, now_ns);

        return RateLimitDecision.Allowed {
            remaining_burst: rem,
            new_tat_ns:      tat_new,
            reset_after_ns:  reset_after,
        };
    }

    let wait_time = core::sub_sat_u64(t_allow, now_ns);
    if wait_time <= max_wait_ns {
        // Reserve the slot ahead of concurrent lighter requests
        cell.tat_ns = tat_new;
        return RateLimitDecision.Reserved {
            wait_ns:    wait_time,
            new_tat_ns: tat_new,
        };
    }

    return RateLimitDecision.Rejected {
        retry_after_ns: wait_time,
        current_tat_ns: tat_old,
    };
}

// ---- 256-micro-shard keyed table -------------------------------------------

struct KeyedGcraSlot {
    key:    u8[..64] = [],
    cell:   GcraCell = GcraCell { .. },
    active: bool     = false,
}

struct GcraShard {
    slots: KeyedGcraSlot[..16] = [],
}

struct ShardedGcraLimiter {
    quota:  GcraQuota      = GcraQuota { .. },
    shards: GcraShard[256] = [GcraShard { .. }; 256],
}

fn new_sharded_limiter(quota: GcraQuota) -> ShardedGcraLimiter {
    return ShardedGcraLimiter { quota: quota, .. };
}

fn format_gcra_key(key_str: const u8[:]) -> u8[..64] {
    var out: u8[..64] = [];
    if out.try_set(key_str) {
        return out;
    }
    out.try_set(key_str[..48]);
    let h = core::fnv1a_64(key_str);
    core::format_u64_hex_fixed(h, 16, out, false);
    return out;
}

inline fn find_existing_slot(slots: const KeyedGcraSlot[..16]&, key_str: const u8[:]) -> i32 {
    for idx in slots.len {
        if slots[idx].active && slots[idx].key[..] == key_str {
            return idx as i32;
        }
    }
    return -1;
}

// Allocates or reclaims a slot in `shard` when no active matching slot exists.
fn allocate_shard_slot(shard: GcraShard&, now_ns: u64) -> i32 {
    for idx in shard.slots.len {
        if !shard.slots[idx].active {
            return idx as i32;
        }
    }
    if shard.slots.try_push(KeyedGcraSlot { active: false, .. }) {
        return (core::sub_sat_i64(shard.slots.len, 1)) as i32;
    }
    for idx in shard.slots.len {
        if shard.slots[idx].cell.tat_ns <= now_ns {
            return idx as i32;
        }
    }
    return -1;
}

// Admits a new rate-limit key into `shard_idx` or rejects fail-closed if all slots are active and unexpired.
fn admit_or_reject_new_rate_limit_slot(
    limiter:   ShardedGcraLimiter&,
    shard_idx: i64,
    eff_key:   const u8[:],
    cost_n:    u64,
    now_ns:    u64,
) -> RateLimitDecision {
    let slot_idx = allocate_shard_slot(limiter.shards[shard_idx], now_ns);
    if slot_idx >= 0 {
        limiter.shards[shard_idx].slots[slot_idx].key.try_set(eff_key);
        limiter.shards[shard_idx].slots[slot_idx].cell.tat_ns = now_ns;
        limiter.shards[shard_idx].slots[slot_idx].active = true;
        return gcra_check_n(limiter.quota, limiter.shards[shard_idx].slots[slot_idx].cell, cost_n, now_ns);
    }
    // Shard full fallback: all slots active with unexpired TAT -> reject (fail-closed)
    var min_tat: u64 = 0xFFFFFFFFFFFFFFFF;
    for idx in limiter.shards[shard_idx].slots.len {
        min_tat = min(min_tat, limiter.shards[shard_idx].slots[idx].cell.tat_ns);
    }
    let retry_ns = core::sub_sat_u64(min_tat, now_ns);
    return RateLimitDecision.Rejected {
        retry_after_ns: if retry_ns > 0 { retry_ns } else { limiter.quota.emission_interval_ns },
        current_tat_ns: min_tat,
    };
}

// Checks and updates rate limit for a specific client key (IP, API-Key, Tenant).
fn check_rate_limit(
    limiter: ShardedGcraLimiter&,
    key_str: const u8[:],
    cost_n:  u64,
    now_ns:  u64,
) -> RateLimitDecision {
    let shard_idx = (core::fnv1a_64(key_str) & 0xFF) as i64;
    if key_str.len <= 64 {
        let existing = find_existing_slot(limiter.shards[shard_idx].slots, key_str);
        if existing >= 0 {
            return gcra_check_n(limiter.quota, limiter.shards[shard_idx].slots[existing as i64].cell, cost_n, now_ns);
        }
        return admit_or_reject_new_rate_limit_slot(limiter, shard_idx, key_str, cost_n, now_ns);
    }
    let eff_key = format_gcra_key(key_str);
    let existing = find_existing_slot(limiter.shards[shard_idx].slots, eff_key[..]);
    if existing >= 0 {
        return gcra_check_n(limiter.quota, limiter.shards[shard_idx].slots[existing as i64].cell, cost_n, now_ns);
    }
    return admit_or_reject_new_rate_limit_slot(limiter, shard_idx, eff_key[..], cost_n, now_ns);
}

// ---- probabilistic sampled gcra -------------------------------------------

struct ProbabilisticGcra {
    quota:         GcraQuota = GcraQuota { .. },
    cell:          GcraCell  = GcraCell { .. },
    sample_rate:   u64       = 20, // 5% sampling
    rng_state:     u64       = 0,
    window_pos:    u64       = 0,
    window_target: u64       = 0,
    initialized:   bool      = false,
}

fn new_probabilistic_gcra(quota: GcraQuota, sample_rate: u64 = 20) -> ProbabilisticGcra {
    let rate = if sample_rate > 0 { sample_rate } else { 20 as u64 };
    var seed = (clock_ns() as u64) ^ 0x853c49e6748fea9b;
    let first_mix = core::splitmix64(seed);
    return ProbabilisticGcra {
        quota:         quota,
        cell:          GcraCell { .. },
        sample_rate:   rate,
        rng_state:     seed,
        window_pos:    0,
        window_target: core::fast_range_biased_u64(first_mix, rate),
        initialized:   true,
    };
}

inline fn advance_probabilistic_sample_slot(pgcra: ProbabilisticGcra&, rate: u64) -> bool {
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

// Stratified 1-in-rate sampled check: applies cost * sample_rate once per random slot in each rate-window.
fn check_rate_limit(pgcra: ProbabilisticGcra&, cost_n: u64, now_ns: u64) -> RateLimitDecision {
    let rate = if pgcra.sample_rate > 0 { pgcra.sample_rate } else { 20 as u64 };
    let sampled = advance_probabilistic_sample_slot(pgcra, rate);

    let t = max(pgcra.quota.emission_interval_ns, 1);
    let tau = pgcra.quota.delay_tolerance_ns;
    let limit_window = core::add_sat_u64(tau, t);
    var tat_curr = pgcra.cell.tat_ns;
    let drift_threshold = core::add_sat_u64(limit_window, GCRA_MAX_CLOCK_DRIFT_NS);
    if tat_curr > core::add_sat_u64(now_ns, drift_threshold) {
        tat_curr = core::add_sat_u64(now_ns, limit_window);
        pgcra.cell.tat_ns = tat_curr;
    }

    if sampled {
        let dec = gcra_check_n(pgcra.quota, pgcra.cell, cost_n, now_ns);
        guard is_allowed(dec) else { return dec; }
        let extra_delta = core::mul_sat_u64(core::mul_sat_u64(cost_n, core::sub_sat_u64(rate, 1)), t);
        let tat_new = core::add_sat_u64(pgcra.cell.tat_ns, extra_delta);
        pgcra.cell.tat_ns = tat_new;
        return RateLimitDecision.Allowed {
            remaining_burst: gcra_remaining_burst(tau, t, pgcra.quota.burst, tat_new, now_ns),
            new_tat_ns:      tat_new,
            reset_after_ns:  core::sub_sat_u64(tat_new, now_ns),
        };
    }

    let t_allow = core::sub_sat_u64(tat_curr, limit_window);
    guard now_ns >= t_allow else {
        return RateLimitDecision.Rejected {
            retry_after_ns: core::sub_sat_u64(t_allow, now_ns),
            current_tat_ns: tat_curr,
        };
    }

    let rem = gcra_remaining_burst(tau, t, pgcra.quota.burst, tat_curr, now_ns);
    let reset_after = core::sub_sat_u64(tat_curr, now_ns);
    return RateLimitDecision.Allowed {
        remaining_burst: rem,
        new_tat_ns:      tat_curr,
        reset_after_ns:  reset_after,
    };
}

// ---- ietf ratelimit header formatting --------------------------------------

const SLOT_RETRY_AFTER: u8 = 60;

inline fn ceil_ns_to_sec(ns: u64) -> u64 {
    if ns == 0 { return 0; }
    if ns <= 1000000000 { return 1; }
    return fast_div_u64(core::add_sat_u64(ns, 999999999), 1000000000);
}

fn find_header_hash_entry_idx(map: const HeaderMap&, name: const u8[:], hname: u32, wk_id: u8) -> i64 {
    if wk_id != 0xFF {
        let slot_idx = map.inline_slots[wk_id as i64];
        return if slot_idx != 0xFF && slot_idx < map.entries.len { slot_idx } else { -1 };
    }
    for i in map.entries.len {
        let e = map.entries[i];
        if e.name_hash == hname && entry_name(map, e).eq_ascii_fold(name) {
            return i;
        }
    }
    return -1;
}

inline fn try_overwrite_ratelimit_entry_same_len(map: HeaderMap&, idx: i64, val_str: const u8[:]) -> bool {
    guard idx >= 0 && idx < map.entries.len else { return false; }
    let e = map.entries[idx];
    guard e.next_idx == 0xFF && e.reserved == HEADER_SRC_STACK && e.values_end <= map.raw_buf.len else {
        return false;
    }
    let v_begin = e.values_begin as i64;
    let v_end = e.values_end as i64;
    guard core::sub_sat_i64(v_end, v_begin) == val_str.len else { return false; }
    if map.raw_buf[v_begin..v_end] == val_str {
        return true;
    }
    for k in val_str.len {
        map.raw_buf[core::add_sat_i64(v_begin, k)] = val_str[k];
    }
    return true;
}

fn set_ratelimit_u64_header(map: HeaderMap&, name: const u8[:], hname: u32, wk_id: u8, val: u64) {
    let idx = find_header_hash_entry_idx(map, name, hname, wk_id);
    let needed = core::add_sat_i64(name.len, 24);
    if idx < 0 &&
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
        map.entries.push(HeaderEntry {
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
    if try_overwrite_ratelimit_entry_same_len(map, idx, val_str[..]) {
        return;
    }
    let _ = set_or_replace(map, name, val_str[..], false);
}

fn apply_rate_limit_headers<Res>(res: Res&, quota: const GcraQuota&, decision: const RateLimitDecision&) {
    set_ratelimit_u64_header(
        res.headers, rfc::HEADER_RATELIMIT_LIMIT, rfc::HASH_HDR_RATELIMIT_LIMIT, 0xFF, quota.limit,
    );

    match decision {
        Allowed a => {
            set_ratelimit_u64_header(
                res.headers,
                rfc::HEADER_RATELIMIT_REMAINING,
                rfc::HASH_HDR_RATELIMIT_REMAINING,
                0xFF,
                a.remaining_burst,
            );
            let reset_sec = ceil_ns_to_sec(a.reset_after_ns);
            set_ratelimit_u64_header(
                res.headers, rfc::HEADER_RATELIMIT_RESET, rfc::HASH_HDR_RATELIMIT_RESET, 0xFF, reset_sec,
            );
        },
        Reserved r => {
            set_ratelimit_u64_header(
                res.headers, rfc::HEADER_RATELIMIT_REMAINING, rfc::HASH_HDR_RATELIMIT_REMAINING, 0xFF, 0,
            );
            let reset_sec = ceil_ns_to_sec(r.wait_ns);
            set_ratelimit_u64_header(
                res.headers, rfc::HEADER_RATELIMIT_RESET, rfc::HASH_HDR_RATELIMIT_RESET, 0xFF, reset_sec,
            );
        },
        Rejected rej => {
            set_ratelimit_u64_header(
                res.headers, rfc::HEADER_RATELIMIT_REMAINING, rfc::HASH_HDR_RATELIMIT_REMAINING, 0xFF, 0,
            );
            let retry_sec = max(ceil_ns_to_sec(rej.retry_after_ns), 1);
            set_ratelimit_u64_header(
                res.headers, rfc::HEADER_RATELIMIT_RESET, rfc::HASH_HDR_RATELIMIT_RESET, 0xFF, retry_sec,
            );
            set_ratelimit_u64_header(
                res.headers,
                rfc::HEADER_RETRY_AFTER,
                rfc::HASH_HDR_RETRY_AFTER,
                SLOT_RETRY_AFTER,
                retry_sec,
            );
            // RFC 6585 Section 4: 429 Too Many Requests - Responses with the 429 status code MUST NOT be stored by a cache.
            let _ = set_or_replace(res.headers, "Cache-Control", "no-store", false);
            res.status_code = rfc::STATUS_TOO_MANY_REQUESTS;
        },
    };
}

// ---- jitter, capacity inspection & shard retention (COOKIERL-07 / COOKIERL-08) ----

struct GcraJitter {
    min_ns: i64 = 0,
    max_ns: i64 = 0,
}

// Converts a `RateLimitDecision` into a flat `GcraDecision` record.
fn to_gcra_decision(decision: const RateLimitDecision&) -> GcraDecision {
    return match decision {
        Allowed a => GcraDecision {
            allowed:               true,
            remaining_burst:       a.remaining_burst,
            retry_after_ns:        0,
            reset_after_ns:        a.reset_after_ns,
            wait_ns:               0,
            tat_ns:                a.new_tat_ns,
            insufficient_capacity: false,
        },
        Reserved r => GcraDecision {
            allowed:               true,
            remaining_burst:       0,
            retry_after_ns:        r.wait_ns,
            reset_after_ns:        0,
            wait_ns:               (min(r.wait_ns, 0x7FFFFFFFFFFFFFFF)) as i64,
            tat_ns:                r.new_tat_ns,
            insufficient_capacity: false,
        },
        Rejected rej => GcraDecision {
            allowed:               false,
            remaining_burst:       0,
            retry_after_ns:        rej.retry_after_ns,
            reset_after_ns:        0,
            wait_ns:               (min(rej.retry_after_ns, 0x7FFFFFFFFFFFFFFF)) as i64,
            tat_ns:                rej.current_tat_ns,
            insufficient_capacity: rej.insufficient_capacity,
        },
    };
}

// Samples a uniform random nanosecond offset in `[jitter.min_ns, jitter.max_ns)` using SplitMix64.
fn sample_gcra_jitter_ns(jitter: const GcraJitter&, prng_state: u64&) -> i64 {
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

// Applies a random jitter offset to `d.wait_ns` and `d.retry_after_ns` when rate-limited or waiting.
fn apply_jitter_to_decision(d: GcraDecision&, jitter: const GcraJitter&, prng_state: u64&) {
    guard !d.allowed || d.wait_ns > 0 else { return; }
    let offset = sample_gcra_jitter_ns(jitter, prng_state);
    guard offset > 0 else { return; }
    d.wait_ns = core::add_sat_i64(d.wait_ns, offset);
    d.retry_after_ns = core::add_sat_u64(d.retry_after_ns, offset as u64);
}

// Applies a random jitter offset directly to a `RateLimitDecision` (`Reserved` or `Rejected`).
fn apply_jitter_to_decision(d: RateLimitDecision&, jitter: const GcraJitter&, prng_state: u64&) {
    match d {
        Allowed _ => { return; },
        _ => {},
    };
    let offset = sample_gcra_jitter_ns(jitter, prng_state);
    guard offset > 0 else { return; }
    let off_u = offset as u64;
    match d {
        Allowed _ => {},
        Reserved r => {
            d = RateLimitDecision.Reserved {
                wait_ns:    core::add_sat_u64(r.wait_ns, off_u),
                new_tat_ns: r.new_tat_ns,
            };
        },
        Rejected rej => {
            d = RateLimitDecision.Rejected {
                retry_after_ns:        core::add_sat_u64(rej.retry_after_ns, off_u),
                current_tat_ns:        rej.current_tat_ns,
                insufficient_capacity: rej.insufficient_capacity,
            };
        },
    };
}

// Whether a `RateLimitDecision` was rejected specifically due to cost exceeding maximum bucket capacity.
fn is_insufficient_capacity(decision: const RateLimitDecision&) -> bool {
    return match decision {
        Rejected rej => rej.insufficient_capacity,
        _ => false,
    };
}

// Sweeps all 256 shards and reclaims active slots whose TAT is older than or equal to `drop_below_ns`.
// Returns the total number of reclaimed slots.
fn retain_recent_shards(limiter: ShardedGcraLimiter&, drop_below_ns: i64) -> i64 {
    guard drop_below_ns >= 0 else { return 0; }
    let threshold = drop_below_ns as u64;
    var reclaimed: i64 = 0;
    for &shard in limiter.shards {
        for &slot in shard.slots {
            if slot.active && slot.cell.tat_ns <= threshold {
                slot.active = false;
                slot.key.clear();
                slot.cell.tat_ns = 0;
                reclaimed = core::add_sat_i64(reclaimed, 1);
            }
        }
    }
    return reclaimed;
}
