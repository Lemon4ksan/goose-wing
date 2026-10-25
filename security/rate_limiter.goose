// Generic Cell Rate Algorithm (GCRA) leaky-bucket rate limiter.
namespace wing;

import std;
import client.response;

// ---- quota specification & decisions ---------------------------------------

struct GcraQuota {
    emission_interval_ns: u64 = 1000000000, // T = period / limit
    delay_tolerance_ns: u64 = 0,            // tau = T * burst
    limit: u64 = 1,
    period_ns: u64 = 1000000000,
    burst: u64 = 0,
}

// Calculates GCRA quota parameters from sustained limit, period, and burst tolerance.
// T = period / limit (emission interval), tau = T * burst (delay tolerance).
fn new_gcra_quota(limit: u64, period_dur: core::Duration, burst: u64 = 0) -> GcraQuota {
    let p_ns = if period_dur.nanos > 0 { period_dur.nanos as u64 } else { 1000000000 as u64 };
    let l = if limit > 0 { limit } else { 1 as u64 };
    let t_ns = p_ns / l;
    let tau_ns = t_ns * burst;

    return GcraQuota {
        emission_interval_ns: t_ns,
        delay_tolerance_ns: tau_ns,
        limit: l,
        period_ns: p_ns,
        burst: burst,
    };
}

enum RateLimitDecision {
    Allowed { remaining_burst: u64, new_tat_ns: u64, reset_after_ns: u64 },
    Reserved { wait_ns: u64, new_tat_ns: u64 },
    Rejected { retry_after_ns: u64, current_tat_ns: u64 },
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

// Evaluates rate limit admission for a request consuming cost_n tokens at now_ns.
// Returns Allowed with remaining capacity, or Rejected with retry_after_ns.
fn gcra_check_n(quota: const GcraQuota&, cell: GcraCell&, cost_n: u64, now_ns: u64) -> RateLimitDecision {
    let t = quota.emission_interval_ns;
    let tau = quota.delay_tolerance_ns;
    let delta = core::mul_sat_u64(cost_n, t);

    let tat_old = cell.tat_ns;
    let tat_base = core::ct_max_u64(now_ns, tat_old);
    let tat_new = core::add_sat_u64(tat_base, delta);

    let limit_window = tau + t;
    let t_allow = core::sub_sat_u64(tat_new, limit_window);

    if now_ns < t_allow {
        let retry_after = t_allow - now_ns;
        return RateLimitDecision.Rejected {
            retry_after_ns: retry_after,
            current_tat_ns: tat_old,
        };
    }

    cell.tat_ns = tat_new;

    // Remaining burst calculation
    var rem: u64 = 0;
    if (tat_new + tau) >= (now_ns + limit_window) {
        let diff = (tat_new + tau) - (now_ns + limit_window);
        rem = if tau > diff { (tau - diff) / t } else { 0 };
    } else {
        rem = quota.burst;
    }

    let reset_after = core::sub_sat_u64(tat_new, now_ns);

    return RateLimitDecision.Allowed {
        remaining_burst: rem,
        new_tat_ns: tat_new,
        reset_after_ns: reset_after,
    };
}

// Reserves cell capacity in advance up to max_wait_ns for multi-cost requests.
// Returns Reserved if the caller can wait, Allowed if immediate, or Rejected if wait exceeds max_wait_ns.
fn gcra_reserve_n(
    quota: const GcraQuota&,
    cell: GcraCell&,
    cost_n: u64,
    now_ns: u64,
    max_wait_ns: u64,
) -> RateLimitDecision {
    let t = quota.emission_interval_ns;
    let tau = quota.delay_tolerance_ns;
    let delta = core::mul_sat_u64(cost_n, t);

    let tat_old = cell.tat_ns;
    let tat_base = core::ct_max_u64(now_ns, tat_old);
    let tat_new = core::add_sat_u64(tat_base, delta);

    let limit_window = tau + t;
    let t_allow = core::sub_sat_u64(tat_new, limit_window);

    if now_ns >= t_allow {
        cell.tat_ns = tat_new;
        let reset_after = core::sub_sat_u64(tat_new, now_ns);
        return RateLimitDecision.Allowed {
            remaining_burst: quota.burst,
            new_tat_ns: tat_new,
            reset_after_ns: reset_after,
        };
    }

    let wait_time = t_allow - now_ns;
    if wait_time <= max_wait_ns {
        // Reserve the slot ahead of concurrent lighter requests
        cell.tat_ns = tat_new;
        return RateLimitDecision.Reserved {
            wait_ns: wait_time,
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
    key: u8[..64] = [],
    cell: GcraCell = GcraCell { .. },
    active: bool = false,
}

struct GcraShard {
    slots: KeyedGcraSlot[..16] = [],
}

struct ShardedGcraLimiter {
    quota: GcraQuota = GcraQuota { .. },
    shards: GcraShard[256] = [GcraShard { .. }; 256],
}

fn new_sharded_limiter(quota: GcraQuota) -> ShardedGcraLimiter {
    return ShardedGcraLimiter { quota: quota, .. };
}

// Checks and updates rate limit for a specific client key (IP, API-Key, Tenant).
fn check_keyed_rate_limit(
    limiter: ShardedGcraLimiter&,
    key_str: const u8[:],
    cost_n: u64,
    now_ns: u64,
) -> RateLimitDecision {
    let shard_idx = (core::fnv1a_64(key_str) & 0xFF) as i64;

    // Find existing slot
    for idx in limiter.shards[shard_idx].slots.len {
        if limiter.shards[shard_idx].slots[idx].active && limiter.shards[shard_idx].slots[idx].key[..] == key_str {
            return gcra_check_n(limiter.quota, limiter.shards[shard_idx].slots[idx].cell, cost_n, now_ns);
        }
    }

    // Allocate slot in shard or evict expired TAT
    var slot_idx: i32 = -1;
    for idx in limiter.shards[shard_idx].slots.len {
        if !limiter.shards[shard_idx].slots[idx].active || limiter.shards[shard_idx].slots[idx].cell.tat_ns <= now_ns {
            slot_idx = idx as i32;
            break;
        }
    }

    if slot_idx < 0 && limiter.shards[shard_idx].slots.len < limiter.shards[shard_idx].slots.cap {
        var new_slot = KeyedGcraSlot { active: false, .. };
        limiter.shards[shard_idx].slots.push(new_slot);
        slot_idx = (limiter.shards[shard_idx].slots.len - 1) as i32;
    }

    if slot_idx >= 0 {
        limiter.shards[shard_idx].slots[slot_idx].key.clear();
        limiter.shards[shard_idx].slots[slot_idx].key.append(key_str);
        limiter.shards[shard_idx].slots[slot_idx].cell.tat_ns = now_ns;
        limiter.shards[shard_idx].slots[slot_idx].active = true;
        return gcra_check_n(limiter.quota, limiter.shards[shard_idx].slots[slot_idx].cell, cost_n, now_ns);
    }

    // Shard full fallback
    var temp_cell = GcraCell { tat_ns: now_ns };
    return gcra_check_n(limiter.quota, temp_cell, cost_n, now_ns);
}

// ---- probabilistic sampled gcra -------------------------------------------

struct ProbabilisticGcra {
    quota: GcraQuota = GcraQuota { .. },
    cell: GcraCell = GcraCell { .. },
    sample_rate: u64 = 20, // 5% sampling
    rng_state: u64 = 0x853c49e6748fea9b,
}

fn new_probabilistic_gcra(quota: GcraQuota, sample_rate: u64 = 20) -> ProbabilisticGcra {
    return ProbabilisticGcra {
        quota: quota,
        cell: GcraCell { .. },
        sample_rate: if sample_rate > 0 { sample_rate } else { 20 },
        rng_state: 0x853c49e6748fea9b,
    };
}

// 5% sampled check: 19 of 20 requests pass immediately without touch;
// 1 in 20 applies cost * sample_rate to the TAT cell.
fn check_probabilistic(pgcra: ProbabilisticGcra&, cost_n: u64, now_ns: u64) -> RateLimitDecision {
    pgcra.rng_state ^= pgcra.rng_state >> 12;
    pgcra.rng_state ^= pgcra.rng_state << 25;
    pgcra.rng_state ^= pgcra.rng_state >> 27;

    let sampled = (pgcra.rng_state % pgcra.sample_rate) == 0;
    if !sampled {
        return RateLimitDecision.Allowed {
            remaining_burst: pgcra.quota.burst,
            new_tat_ns: pgcra.cell.tat_ns,
            reset_after_ns: 0,
        };
    }

    let scaled_cost = cost_n * pgcra.sample_rate;
    return gcra_check_n(pgcra.quota, pgcra.cell, scaled_cost, now_ns);
}

// ---- ietf ratelimit header formatting --------------------------------------

fn apply_rate_limit_headers(res: Response&, quota: const GcraQuota&, decision: const RateLimitDecision&) {
    var limit_str: u8[..32] = [];
    core::format_u64_dec(quota.limit, limit_str);
    res.headers.set_header("RateLimit-Limit", limit_str[..]);

    match decision {
        Allowed a => {
            var rem_str: u8[..32] = [];
            core::format_u64_dec(a.remaining_burst, rem_str);
            res.headers.set_header("RateLimit-Remaining", rem_str[..]);

            var reset_str: u8[..32] = [];
            let reset_sec = (a.reset_after_ns + 999999999) / 1000000000;
            core::format_i64_dec(reset_sec as i64, reset_str);
            res.headers.set_header("RateLimit-Reset", reset_str[..]);
        },
        Reserved r => {
            res.headers.set_header("RateLimit-Remaining", "0");
            var reset_str: u8[..32] = [];
            let reset_sec = (r.wait_ns + 999999999) / 1000000000;
            core::format_i64_dec(reset_sec as i64, reset_str);
            res.headers.set_header("RateLimit-Reset", reset_str[..]);
        },
        Rejected rej => {
            res.headers.set_header("RateLimit-Remaining", "0");
            let retry_sec = (rej.retry_after_ns + 999999999) / 1000000000;
            var retry_str: u8[..32] = [];
            core::format_i64_dec(retry_sec as i64, retry_str);
            res.headers.set_header("RateLimit-Reset", retry_str[..]);
            res.headers.set_header("Retry-After", retry_str[..]);
            res.status_code = 429; // Too Many Requests
        },
    };
}
