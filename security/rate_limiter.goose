// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Generic Cell Rate Algorithm (GCRA) leaky-bucket rate limiter.
namespace security;

import std;
import core;
import rfc.http;
import .gcra;
import .rate_limit_internal;

// ---- quota specification & decisions ---------------------------------------

struct GcraQuota {
    emission_interval_ns: u64 = 1000000000, // T = period / limit
    delay_tolerance_ns:   u64 = 0,          // tau = T * burst
    limit:                u64 = 1,
    period_ns:            u64 = 1000000000,
    burst:                u64 = 0,
}

enum RateLimitDecision {
    Allowed { remaining_burst: u64, new_tat_ns: u64, reset_after_ns: u64 },
    Reserved { wait_ns: u64, new_tat_ns: u64 },
    Rejected { retry_after_ns: u64, current_tat_ns: u64, insufficient_capacity: bool = false },
}

// Calculates GCRA quota parameters from sustained limit, period, and burst tolerance.
// T = period / limit (emission interval), tau = T * burst (delay tolerance).
fn new_gcra_quota(limit: u64, period_ns: i64, burst: u64 = 0) -> GcraQuota {
    let p_ns = if period_ns > 0 { period_ns as u64 } else { core::SECOND as u64 };
    let l = max(limit, 1);
    let t_ns = max(security_internal::fast_div_u64(p_ns, l), 1);
    let tau_ns = core::mul_sat_u64(t_ns, burst);

    return GcraQuota {
        emission_interval_ns: t_ns,
        delay_tolerance_ns:   tau_ns,
        limit:                l,
        period_ns:            p_ns,
        burst:                burst,
    };
}

fn is_allowed(decision: const RateLimitDecision&) -> bool {
    return match decision {
        Allowed _ => true,
        Reserved _ => true,
        Rejected _ => false,
    };
}

// Evaluates rate limit admission for a request consuming cost_n tokens at now_ns.
// Returns Allowed with remaining capacity, or Rejected with retry_after_ns.
fn gcra_check_n(quota: const GcraQuota&, cell: GcraCell&, cost_n: u64, now_ns: u64) -> RateLimitDecision {
    let t = max(quota.emission_interval_ns, 1);
    let tau = quota.delay_tolerance_ns;
    let delta = core::mul_sat_u64(cost_n, t);
    let limit_window = core::add_sat_u64(tau, t);

    let tat_old = security_internal::clamp_clock_drift(cell.tat_ns, now_ns, limit_window);
    cell.tat_ns = tat_old;

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
        return RateLimitDecision.Rejected {
            retry_after_ns: core::sub_sat_u64(t_allow, now_ns),
            current_tat_ns: tat_old,
        };
    }

    cell.tat_ns = tat_new;
    return RateLimitDecision.Allowed {
        remaining_burst: security_internal::calc_remaining_burst(tau, t, quota.burst, tat_new, now_ns),
        new_tat_ns:      tat_new,
        reset_after_ns:  core::sub_sat_u64(tat_new, now_ns),
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

    let tat_old = security_internal::clamp_clock_drift(cell.tat_ns, now_ns, limit_window);
    cell.tat_ns = tat_old;

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
        return RateLimitDecision.Allowed {
            remaining_burst: security_internal::calc_remaining_burst(tau, t, quota.burst, tat_new, now_ns),
            new_tat_ns:      tat_new,
            reset_after_ns:  core::sub_sat_u64(tat_new, now_ns),
        };
    }

    let wait_time = core::sub_sat_u64(t_allow, now_ns);
    if wait_time <= max_wait_ns {
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
    let _ = out.try_set(key_str[..48]);
    let h = core::fnv1a_64(key_str);
    core::format_u64_hex_fixed(h, 16, out, false);
    return out;
}

// Checks and updates rate limit for a specific client key (IP, API-Key, Tenant).
fn check_rate_limit(
    limiter: ShardedGcraLimiter&,
    key_str: const u8[:],
    cost_n:  u64,
    now_ns:  u64,
) -> RateLimitDecision {
    let shard_idx = (core::fnv1a_64(key_str) & 0xFF) as i64;
    var formatted: u8[..64] = [];
    let eff_key = if key_str.len <= 64 {
        key_str
    } else {
        formatted = format_gcra_key(key_str);
        formatted[..]
    };
    let existing, found = security_internal::find_existing_slot(limiter.shards[shard_idx].slots, eff_key);
    if found {
        return gcra_check_n(limiter.quota, limiter.shards[shard_idx].slots[existing].cell, cost_n, now_ns);
    }
    return security_internal::admit_or_reject_new_rate_limit_slot(
        limiter, shard_idx, eff_key, cost_n, now_ns,
    );
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
    var seed = core::sim_entropy_u64() ^ 0x853c49e6748fea9b;
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

// Stratified 1-in-rate sampled check: applies cost * sample_rate once per random slot in each rate-window.
fn check_rate_limit(pgcra: ProbabilisticGcra&, cost_n: u64, now_ns: u64) -> RateLimitDecision {
    let rate = if pgcra.sample_rate > 0 { pgcra.sample_rate } else { 20 as u64 };
    let sampled = security_internal::advance_probabilistic_sample_slot(pgcra, rate);

    let t = max(pgcra.quota.emission_interval_ns, 1);
    let tau = pgcra.quota.delay_tolerance_ns;
    let limit_window = core::add_sat_u64(tau, t);
    let tat_curr = security_internal::clamp_clock_drift(pgcra.cell.tat_ns, now_ns, limit_window);
    pgcra.cell.tat_ns = tat_curr;

    if sampled {
        let dec = gcra_check_n(pgcra.quota, pgcra.cell, cost_n, now_ns);
        guard is_allowed(dec) else { return dec; }
        let extra_delta = core::mul_sat_u64(core::mul_sat_u64(cost_n, core::sub_sat_u64(rate, 1)), t);
        let tat_new = core::add_sat_u64(pgcra.cell.tat_ns, extra_delta);
        pgcra.cell.tat_ns = tat_new;
        return RateLimitDecision.Allowed {
            remaining_burst: security_internal::calc_remaining_burst(tau, t, pgcra.quota.burst, tat_new, now_ns),
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

    return RateLimitDecision.Allowed {
        remaining_burst: security_internal::calc_remaining_burst(tau, t, pgcra.quota.burst, tat_curr, now_ns),
        new_tat_ns:      tat_curr,
        reset_after_ns:  core::sub_sat_u64(tat_curr, now_ns),
    };
}

// ---- ietf ratelimit header formatting --------------------------------------

fn apply_rate_limit_headers<Res>(res: Res&, quota: const GcraQuota&, decision: const RateLimitDecision&) {
    security_internal::set_ratelimit_u64_header(
        res.headers, rfc::HEADER_RATELIMIT_LIMIT, rfc::HASH_HDR_RATELIMIT_LIMIT, 0xFF, quota.limit,
    );

    match decision {
        Allowed a => {
            security_internal::set_ratelimit_u64_header(
                res.headers,
                rfc::HEADER_RATELIMIT_REMAINING,
                rfc::HASH_HDR_RATELIMIT_REMAINING,
                0xFF,
                a.remaining_burst,
            );
            let reset_sec = security_internal::ceil_ns_to_sec(a.reset_after_ns);
            security_internal::set_ratelimit_u64_header(
                res.headers, rfc::HEADER_RATELIMIT_RESET, rfc::HASH_HDR_RATELIMIT_RESET, 0xFF, reset_sec,
            );
        },
        Reserved r => {
            security_internal::set_ratelimit_u64_header(
                res.headers, rfc::HEADER_RATELIMIT_REMAINING, rfc::HASH_HDR_RATELIMIT_REMAINING, 0xFF, 0,
            );
            let reset_sec = security_internal::ceil_ns_to_sec(r.wait_ns);
            security_internal::set_ratelimit_u64_header(
                res.headers, rfc::HEADER_RATELIMIT_RESET, rfc::HASH_HDR_RATELIMIT_RESET, 0xFF, reset_sec,
            );
        },
        Rejected rej => {
            security_internal::set_ratelimit_u64_header(
                res.headers, rfc::HEADER_RATELIMIT_REMAINING, rfc::HASH_HDR_RATELIMIT_REMAINING, 0xFF, 0,
            );
            let retry_sec = max(security_internal::ceil_ns_to_sec(rej.retry_after_ns), 1);
            security_internal::set_ratelimit_u64_header(
                res.headers, rfc::HEADER_RATELIMIT_RESET, rfc::HASH_HDR_RATELIMIT_RESET, 0xFF, retry_sec,
            );
            security_internal::set_ratelimit_u64_header(
                res.headers,
                rfc::HEADER_RETRY_AFTER,
                rfc::HASH_HDR_RETRY_AFTER,
                security_internal::SLOT_RETRY_AFTER,
                retry_sec,
            );
            // RFC 6585 Section 4: 429 Too Many Requests - Responses with the 429 status code MUST NOT be stored by a cache.
            let _ = res.headers.set_or_replace("Cache-Control", "no-store", false);
            res.status_code = rfc::STATUS_TOO_MANY_REQUESTS;
        },
    };
}

// ---- jitter, capacity inspection & shard retention -------------------------

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

// Applies a random jitter offset to `d.wait_ns` and `d.retry_after_ns` when rate-limited or waiting.
fn apply_jitter_to_decision(d: GcraDecision&, jitter: const GcraJitter&, prng_state: u64&) {
    guard !d.allowed || d.wait_ns > 0 else { return; }
    let offset = security_internal::sample_gcra_jitter_ns(jitter, prng_state);
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
    let offset = security_internal::sample_gcra_jitter_ns(jitter, prng_state);
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
