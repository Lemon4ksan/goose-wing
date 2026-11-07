// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Generic Cell Rate Algorithm (GCRA) leaky-bucket rate limiter.
namespace wing;

import std;
import core from "..";
import rfc.http;
import proxy.gcra;

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
fn new_gcra_quota(limit: u64, period_dur: core::Duration, burst: u64 = 0) -> GcraQuota {
    let p_ns = if period_dur.nanos > 0 { period_dur.nanos as u64 } else { 1000000000 as u64 };
    let l = max(limit, 1);
    let t_ns = max(p_ns / l, 1);
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
    let diff = tat - baseline;
    guard tau > diff else { return 0; }
    let rem = (tau - diff) / t_safe;
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
        let excess = delta - limit_window;
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
        let retry_after = t_allow - now_ns;
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
        let excess = delta - limit_window;
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

    let wait_time = t_allow - now_ns;
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

fn format_gcra_key(key_str: const u8[:], out: u8[..64]&) {
    out.clear();
    if key_str.len <= 64 {
        out.append(key_str);
    } else {
        out.append(key_str[..48]);
        let h = core::fnv1a_64(key_str);
        for i in 16 {
            let shift = (15 - i) * 4;
            let nibble = ((h >> shift) & 0x0F) as u8;
            let ch = if nibble < 10 { '0' + nibble } else { 'a' + (nibble - 10) };
            out.push(ch);
        }
    }
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
    if shard.slots.len < shard.slots.cap {
        var new_slot = KeyedGcraSlot { active: false, .. };
        shard.slots.push(new_slot);
        return (core::sub_sat_i64(shard.slots.len, 1)) as i32;
    }
    for idx in shard.slots.len {
        if shard.slots[idx].cell.tat_ns <= now_ns {
            return idx as i32;
        }
    }
    return -1;
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
    }
    var eff_key: u8[..64] = [];
    format_gcra_key(key_str, eff_key);
    if key_str.len > 64 {
        let existing = find_existing_slot(limiter.shards[shard_idx].slots, eff_key[..]);
        if existing >= 0 {
            return gcra_check_n(limiter.quota, limiter.shards[shard_idx].slots[existing as i64].cell, cost_n, now_ns);
        }
    }
    let slot_idx = allocate_shard_slot(limiter.shards[shard_idx], now_ns);
    if slot_idx >= 0 {
        limiter.shards[shard_idx].slots[slot_idx].key.clear();
        limiter.shards[shard_idx].slots[slot_idx].key.append(eff_key[..]);
        limiter.shards[shard_idx].slots[slot_idx].cell.tat_ns = now_ns;
        limiter.shards[shard_idx].slots[slot_idx].active = true;
        return gcra_check_n(limiter.quota, limiter.shards[shard_idx].slots[slot_idx].cell, cost_n, now_ns);
    }
    // Shard full fallback: all slots active with unexpired TAT -> reject (fail-closed)
    var min_tat: u64 = 0xFFFFFFFFFFFFFFFF;
    for idx in limiter.shards[shard_idx].slots.len {
        let tat = limiter.shards[shard_idx].slots[idx].cell.tat_ns;
        if tat < min_tat {
            min_tat = tat;
        }
    }
    let retry_ns = core::sub_sat_u64(min_tat, now_ns);
    return RateLimitDecision.Rejected {
        retry_after_ns: if retry_ns > 0 { retry_ns } else { limiter.quota.emission_interval_ns },
        current_tat_ns: min_tat,
    };
}

// ---- probabilistic sampled gcra -------------------------------------------

struct ProbabilisticGcra {
    quota:       GcraQuota = GcraQuota { .. },
    cell:        GcraCell  = GcraCell { .. },
    sample_rate: u64       = 20, // 5% sampling
    rng_state:   u64       = 0x853c49e6748fea9b,
}

fn new_probabilistic_gcra(quota: GcraQuota, sample_rate: u64 = 20) -> ProbabilisticGcra {
    return ProbabilisticGcra {
        quota:       quota,
        cell:        GcraCell { .. },
        sample_rate: if sample_rate > 0 { sample_rate } else { 20 },
        rng_state:   0x853c49e6748fea9b,
    };
}

// 5% sampled check: 19 of 20 requests pass immediately without touch;
// 1 in 20 applies cost * sample_rate to the TAT cell.
fn check_rate_limit(pgcra: ProbabilisticGcra&, cost_n: u64, now_ns: u64) -> RateLimitDecision {
    let rate = if pgcra.sample_rate > 0 { pgcra.sample_rate } else { 20 as u64 };
    if pgcra.rng_state == 0 {
        pgcra.rng_state = 0x853c49e6748fea9b;
    }
    pgcra.rng_state ^= pgcra.rng_state >> 12;
    pgcra.rng_state ^= pgcra.rng_state & 0x7FFFFFFFFFFFFFFF;
    pgcra.rng_state ^= pgcra.rng_state >> 27;

    let t = max(pgcra.quota.emission_interval_ns, 1);
    let tau = pgcra.quota.delay_tolerance_ns;
    let limit_window = core::add_sat_u64(tau, t);
    var tat_curr = pgcra.cell.tat_ns;
    let drift_threshold = core::add_sat_u64(limit_window, GCRA_MAX_CLOCK_DRIFT_NS);
    if tat_curr > core::add_sat_u64(now_ns, drift_threshold) {
        tat_curr = core::add_sat_u64(now_ns, limit_window);
        pgcra.cell.tat_ns = tat_curr;
    }

    let q_samp = fast_div_u64(pgcra.rng_state, rate);
    let rem_samp = core::sub_sat_u64(pgcra.rng_state, core::mul_sat_u64(q_samp, rate));
    let sampled = rem_samp == 0;
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

fn apply_rate_limit_headers<Res>(res: Res&, quota: const GcraQuota&, decision: const RateLimitDecision&) {
    var limit_str: u8[..32] = [];
    core::format_u64_dec(quota.limit, limit_str);
    res.headers.set_header("RateLimit-Limit", limit_str[..]);

    match decision {
        Allowed a => {
            var rem_str: u8[..32] = [];
            core::format_u64_dec(a.remaining_burst, rem_str);
            res.headers.set_header("RateLimit-Remaining", rem_str[..]);

            var reset_str: u8[..32] = [];
            let reset_sec = core::add_sat_u64(a.reset_after_ns, 999999999) / 1000000000;
            core::format_u64_dec(reset_sec, reset_str);
            res.headers.set_header("RateLimit-Reset", reset_str[..]);
        },
        Reserved r => {
            res.headers.set_header("RateLimit-Remaining", "0");
            var reset_str: u8[..32] = [];
            let reset_sec = core::add_sat_u64(r.wait_ns, 999999999) / 1000000000;
            core::format_u64_dec(reset_sec, reset_str);
            res.headers.set_header("RateLimit-Reset", reset_str[..]);
        },
        Rejected rej => {
            res.headers.set_header("RateLimit-Remaining", "0");
            let retry_sec = core::add_sat_u64(rej.retry_after_ns, 999999999) / 1000000000;
            var retry_str: u8[..32] = [];
            core::format_u64_dec(retry_sec, retry_str);
            res.headers.set_header("RateLimit-Reset", retry_str[..]);
            res.headers.set_header("Retry-After", retry_str[..]);
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

// Samples a uniform random nanosecond offset in `[jitter.min_ns, jitter.max_ns)` using XorShift64.
fn sample_gcra_jitter_ns(jitter: const GcraJitter&, prng_state: u64&) -> i64 {
    let min_val = max(jitter.min_ns, 0);
    guard jitter.max_ns > min_val else { return min_val; }
    if prng_state == 0 {
        prng_state = 0x853c49e6748fea9b;
    }
    prng_state ^= prng_state >> 12;
    prng_state ^= prng_state >> 25;
    prng_state ^= prng_state >> 27;
    let mixed = core::add_sat_u64(prng_state, 0x9e3779b97f4a7c15);
    prng_state = mixed;
    let span = (core::sub_sat_i64(jitter.max_ns, min_val)) as u64;
    let q = fast_div_u64(mixed, span);
    let rem = core::sub_sat_u64(mixed, core::mul_sat_u64(q, span));
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
    for s_idx in 256 {
        let n_slots = limiter.shards[s_idx].slots.len;
        for idx in n_slots {
            let is_act = limiter.shards[s_idx].slots[idx].active;
            let tat = limiter.shards[s_idx].slots[idx].cell.tat_ns;
            if is_act && tat <= threshold {
                limiter.shards[s_idx].slots[idx].active = false;
                limiter.shards[s_idx].slots[idx].key.clear();
                limiter.shards[s_idx].slots[idx].cell.tat_ns = 0;
                reclaimed = core::add_sat_i64(reclaimed, 1);
            }
        }
    }
    return reclaimed;
}
