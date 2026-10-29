// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Generic Cell Rate Algorithm (GCRA) Rate Limiter and Gateway Sentinel Shield.
// Implements zero-allocation rate limiting with burst tolerance (tau),
// emission interval (T), Theoretical Arrival Time (TAT) tracking,
// and bounded multi-client tracking (RFC 7616 dual leaky-bucket).
namespace wing;

import std;
import core from "..";

// Maximum clock drift and backward NTP jump tolerance before clamping TAT
const GATEWAY_GCRA_MAX_DRIFT_NS: u64 = 5000000000; // 5.0 seconds
const GATEWAY_LIMITER_NONE: i32 = -1;

// Quota configuration specifying cell spacing (T) and burst headroom (tau)
struct GcraConfig {
    emission_interval_ns: u64 = 1000000, // T: time increment per cell (ns)
    tau_ns: u64 = 5000000,               // tau: burst tolerance delay (ns)
    max_burst: u64 = 5,                  // max allowable burst tokens
    limit_window_ns: u64 = 6000000,      // tau + T (precalculated window)
}

inline fn clamp_pos_u64(x: u64) -> u64 {
    guard x > 0 else { return 1; }
    return x;
}

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

// Configures GCRA quota from sustained requests per second and burst capacity.
fn new_gcra_config(rate_per_sec: u64, burst_capacity: u64) -> GcraConfig {
    let r = clamp_pos_u64(rate_per_sec);
    let t_raw = fast_div_u64(1000000000, r);
    let t_ns = clamp_pos_u64(t_raw);
    let tau_ns = core::mul_sat_u64(t_ns, burst_capacity);
    let win_ns = core::add_sat_u64(tau_ns, t_ns);

    return GcraConfig {
        emission_interval_ns: t_ns,
        tau_ns: tau_ns,
        max_burst: burst_capacity,
        limit_window_ns: win_ns,
    };
}

// Configures GCRA quota from explicit nanosecond interval and tau.
fn new_gcra_config_interval(interval_ns: u64, tau_ns: u64, max_burst: u64) -> GcraConfig {
    let t_ns = clamp_pos_u64(interval_ns);
    let win_ns = core::add_sat_u64(tau_ns, t_ns);

    return GcraConfig {
        emission_interval_ns: t_ns,
        tau_ns: tau_ns,
        max_burst: max_burst,
        limit_window_ns: win_ns,
    };
}

// Single TAT tracking cell
struct GcraTatCell {
    tat_ns: u64 = 0,
}

// Result of a GCRA rate check
struct GcraDecision {
    allowed: bool = false,
    remaining_burst: u64 = 0,
    retry_after_ns: u64 = 0,
    reset_after_ns: u64 = 0,
    tat_ns: u64 = 0,
}

// Clamps TAT if system clock drifted or jumped backward into the past.
inline fn clamp_clock_drift(tat_old: u64, now_ns: u64, limit_window: u64) -> u64 {
    let drift_threshold = core::add_sat_u64(limit_window, GATEWAY_GCRA_MAX_DRIFT_NS);
    let max_future = core::add_sat_u64(now_ns, drift_threshold);
    guard tat_old > max_future else { return tat_old; }
    return core::add_sat_u64(now_ns, limit_window);
}

// Calculates remaining burst allowance after admission without underflow or overflow hazards.
fn calc_remaining_burst(tau_ns: u64, t_ns: u64, max_burst: u64, tat_new: u64, now_ns: u64) -> u64 {
    let baseline = core::add_sat_u64(now_ns, t_ns);
    guard tat_new > baseline else { return max_burst; }
    let diff = core::sub_sat_u64(tat_new, baseline);
    guard tau_ns > diff else { return 0; }
    let rem_ns = core::sub_sat_u64(tau_ns, diff);
    let rem_cells = fast_div_u64(rem_ns, t_ns);
    return if rem_cells < max_burst { rem_cells } else { max_burst };
}

// Evaluates rate limit admission for cost units at now_ns and advances TAT on success.
fn gcra_check(config: const GcraConfig&, cell: GcraTatCell&, cost: u64, now_ns: u64) -> GcraDecision {
    let t = config.emission_interval_ns;
    let tau = config.tau_ns;
    let limit_window = config.limit_window_ns;
    let delta = core::mul_sat_u64(cost, t);

    let tat_old = clamp_clock_drift(cell.tat_ns, now_ns, limit_window);
    cell.tat_ns = tat_old;
    let tat_base = core::ct_max_u64(now_ns, tat_old);
    let tat_new = core::add_sat_u64(tat_base, delta);
    let t_allow = core::sub_sat_u64(tat_new, limit_window);
    let retry_after = core::sub_sat_u64(t_allow, now_ns);

    guard now_ns >= t_allow else {
        return GcraDecision {
            allowed: false,
            remaining_burst: 0,
            retry_after_ns: retry_after,
            reset_after_ns: retry_after,
            tat_ns: tat_old,
        };
    }

    cell.tat_ns = tat_new;
    let rem = calc_remaining_burst(tau, t, config.max_burst, tat_new, now_ns);
    let reset_after = core::sub_sat_u64(tat_new, now_ns);

    return GcraDecision {
        allowed: true,
        remaining_burst: rem,
        retry_after_ns: 0,
        reset_after_ns: reset_after,
        tat_ns: tat_new,
    };
}

// Evaluates rate limit admission without mutating TAT cell state.
fn gcra_peek(config: const GcraConfig&, cell: const GcraTatCell&, cost: u64, now_ns: u64) -> GcraDecision {
    let t = config.emission_interval_ns;
    let tau = config.tau_ns;
    let limit_window = config.limit_window_ns;
    let delta = core::mul_sat_u64(cost, t);

    let tat_old = clamp_clock_drift(cell.tat_ns, now_ns, limit_window);
    let tat_base = core::ct_max_u64(now_ns, tat_old);
    let tat_new = core::add_sat_u64(tat_base, delta);
    let t_allow = core::sub_sat_u64(tat_new, limit_window);
    let retry_after = core::sub_sat_u64(t_allow, now_ns);

    guard now_ns >= t_allow else {
        return GcraDecision {
            allowed: false,
            remaining_burst: 0,
            retry_after_ns: retry_after,
            reset_after_ns: retry_after,
            tat_ns: tat_old,
        };
    }

    let rem = calc_remaining_burst(tau, t, config.max_burst, tat_new, now_ns);
    let reset_after = core::sub_sat_u64(tat_new, now_ns);

    return GcraDecision {
        allowed: true,
        remaining_burst: rem,
        retry_after_ns: 0,
        reset_after_ns: reset_after,
        tat_ns: tat_new,
    };
}

// Applies penalty delay to TAT to rate-limit abusive clients or handle backpressure.
fn gcra_penalize(config: const GcraConfig&, cell: GcraTatCell&, penalty_ns: u64, now_ns: u64) {
    guard penalty_ns > 0 else { return; }
    let tat_old = clamp_clock_drift(cell.tat_ns, now_ns, config.limit_window_ns);
    cell.tat_ns = tat_old;
    let tat_base = core::ct_max_u64(now_ns, tat_old);
    cell.tat_ns = core::add_sat_u64(tat_base, penalty_ns);
}

// Resets single TAT cell state to zero.
fn gcra_reset(cell: GcraTatCell&) {
    cell.tat_ns = 0;
}

// ---- Bounded Multi-Client Gateway Rate Limiter -----------------------------

struct GatewayClientEntry {
    client_id: u8[..64] = [],
    cell: GcraTatCell = GcraTatCell { .. },
    last_seen_ns: u64 = 0,
    consecutive_rejects: u32 = 0,
    in_use: bool = false,
}

struct GatewayRateLimiter {
    config: GcraConfig = GcraConfig { .. },
    entries: GatewayClientEntry[..64] = [],
    total_allowed: u64 = 0,
    total_rejected: u64 = 0,
}

inline fn inc_limiter_allowed(limiter: GatewayRateLimiter&) {
    limiter.total_allowed = limiter.total_allowed + 1;
}

inline fn inc_limiter_rejected(limiter: GatewayRateLimiter&) {
    limiter.total_rejected = limiter.total_rejected + 1;
}

inline fn inc_client_rejects(entry: GatewayClientEntry&) {
    entry.consecutive_rejects = entry.consecutive_rejects + 1;
}

inline fn clear_client_rejects(entry: GatewayClientEntry&) {
    entry.consecutive_rejects = 0;
}

inline fn sub_one_i32(x: i32) -> i32 {
    return x - 1;
}

// Instantiates a new zero-allocation GatewayRateLimiter.
fn new_gateway_rate_limiter(rate_per_sec: u64, burst_capacity: u64) -> GatewayRateLimiter {
    return GatewayRateLimiter {
        config: new_gcra_config(rate_per_sec, burst_capacity),
        ..
    };
}

// Finds entry index by client ID, or returns GATEWAY_LIMITER_NONE if absent.
fn find_client_slot(limiter: const GatewayRateLimiter&, client_id: const u8[:]) -> i32 {
    let n = limiter.entries.len as i32;
    for i in n {
        if limiter.entries[i].in_use && limiter.entries[i].client_id[..] == client_id {
            return i;
        }
    }
    return GATEWAY_LIMITER_NONE;
}

// Finds an inactive or expired slot, or oldest active slot for replacement.
fn find_idle_or_oldest_slot(limiter: const GatewayRateLimiter&, now_ns: u64) -> i32 {
    let n = limiter.entries.len as i32;
    var oldest_idx: i32 = GATEWAY_LIMITER_NONE;
    var oldest_seen: u64 = 0xFFFFFFFFFFFFFFFF;

    for i in n {
        if !limiter.entries[i].in_use || limiter.entries[i].cell.tat_ns <= now_ns {
            return i;
        }
        if limiter.entries[i].last_seen_ns < oldest_seen {
            oldest_seen = limiter.entries[i].last_seen_ns;
            oldest_idx = i;
        }
    }
    return oldest_idx;
}

inline fn populate_entry(entry: GatewayClientEntry&, client_id: const u8[:], now_ns: u64) {
    entry.client_id.clear();
    let bounded_len = if client_id.len <= 64 { client_id.len } else { 64 };
    entry.client_id.append(client_id[..bounded_len]);
    entry.cell.tat_ns = now_ns;
    entry.last_seen_ns = now_ns;
    entry.consecutive_rejects = 0;
    entry.in_use = true;
}

inline fn push_new_client_slot(limiter: GatewayRateLimiter&, client_id: const u8[:], now_ns: u64) -> i32 {
    var new_entry = GatewayClientEntry { in_use: false, .. };
    populate_entry(new_entry, client_id, now_ns);
    limiter.entries.push(new_entry);
    let n = limiter.entries.len as i32;
    return sub_one_i32(n);
}

// Allocates or retrieves an existing entry slot in the bounded table.
fn allocate_client_entry(limiter: GatewayRateLimiter&, client_id: const u8[:], now_ns: u64) -> i32 {
    let existing_idx = find_client_slot(limiter, client_id);
    guard existing_idx == GATEWAY_LIMITER_NONE else { return existing_idx; }

    if limiter.entries.len < limiter.entries.cap {
        return push_new_client_slot(limiter, client_id, now_ns);
    }

    let slot = find_idle_or_oldest_slot(limiter, now_ns);
    guard slot != GATEWAY_LIMITER_NONE && slot < limiter.entries.len else { return GATEWAY_LIMITER_NONE; }

    populate_entry(limiter.entries[slot], client_id, now_ns);
    return slot;
}

// Handles admission record tracking for an allocated client entry.
inline fn record_client_admission(limiter: GatewayRateLimiter&, slot: i32, dec: const GcraDecision&) {
    if dec.allowed {
        inc_limiter_allowed(limiter);
        clear_client_rejects(limiter.entries[slot]);
    } else {
        inc_limiter_rejected(limiter);
        inc_client_rejects(limiter.entries[slot]);
    }
}

// Handles admission record tracking for table saturation fallback.
inline fn record_fallback_admission(limiter: GatewayRateLimiter&, dec: const GcraDecision&) {
    if dec.allowed {
        inc_limiter_allowed(limiter);
    } else {
        inc_limiter_rejected(limiter);
    }
}

// Checks and updates rate limit for a client ID in the gateway limiter.
fn check_gateway_rate_limit(
    limiter: GatewayRateLimiter&,
    client_id: const u8[:],
    cost: u64,
    now_ns: u64,
) -> GcraDecision {
    let slot = allocate_client_entry(limiter, client_id, now_ns);
    if slot >= 0 && slot < limiter.entries.len {
        limiter.entries[slot].last_seen_ns = now_ns;
        let dec = gcra_check(limiter.config, limiter.entries[slot].cell, cost, now_ns);
        record_client_admission(limiter, slot, dec);
        return dec;
    }

    var fallback_cell = GcraTatCell { tat_ns: now_ns };
    let dec = gcra_check(limiter.config, fallback_cell, cost, now_ns);
    record_fallback_admission(limiter, dec);
    return dec;
}

// Applies penalty delay to a specific client entry.
fn penalize_gateway_client(
    limiter: GatewayRateLimiter&,
    client_id: const u8[:],
    penalty_ns: u64,
    now_ns: u64,
) {
    let slot = find_client_slot(limiter, client_id);
    guard slot >= 0 && slot < limiter.entries.len else { return; }
    gcra_penalize(limiter.config, limiter.entries[slot].cell, penalty_ns, now_ns);
}

inline fn should_evict_client(entry: const GatewayClientEntry&, max_idle_ns: u64, now_ns: u64) -> bool {
    guard entry.in_use else { return false; }
    let idle_time = core::sub_sat_u64(now_ns, entry.last_seen_ns);
    return idle_time > max_idle_ns && entry.cell.tat_ns <= now_ns;
}

inline fn deactivate_client_slot(entry: GatewayClientEntry&) {
    entry.in_use = false;
    entry.client_id.clear();
}

inline fn inc_evicted_count(cnt: i32&) {
    cnt = cnt + 1;
}

// Evicts idle entries exceeding max_idle_ns that have no pending TAT delay.
fn evict_idle_gateway_clients(limiter: GatewayRateLimiter&, max_idle_ns: u64, now_ns: u64) -> i32 {
    var evicted: i32 = 0;
    let n = limiter.entries.len as i32;
    for i in n {
        if should_evict_client(limiter.entries[i], max_idle_ns, now_ns) {
            deactivate_client_slot(limiter.entries[i]);
            inc_evicted_count(evicted);
        }
    }
    return evicted;
}

inline fn reset_entry_slot(entry: GatewayClientEntry&) {
    entry.in_use = false;
    entry.cell.tat_ns = 0;
    entry.consecutive_rejects = 0;
    entry.client_id.clear();
}

// Resets all client entries and global counters in the gateway limiter.
fn reset_gateway_rate_limiter(limiter: GatewayRateLimiter&) {
    let n = limiter.entries.len as i32;
    for i in n {
        reset_entry_slot(limiter.entries[i]);
    }
    limiter.total_allowed = 0;
    limiter.total_rejected = 0;
}
