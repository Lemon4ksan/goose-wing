// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Generic Cell Rate Algorithm (GCRA) Rate Limiter and Gateway Sentinel Shield.
// Implements zero-allocation rate limiting with burst tolerance (tau),
// emission interval (T), Theoretical Arrival Time (TAT) tracking,
// and bounded multi-client tracking (RFC 7616 dual leaky-bucket).
namespace security;

import std;
import core;
import .rate_limit_internal;

// Quota configuration specifying cell spacing (T) and burst headroom (tau).
struct GcraConfig {
    emission_interval_ns: u64 = 1000000, // T: time increment per cell (ns)
    tau_ns:               u64 = 5000000, // tau: burst tolerance delay (ns)
    max_burst:            u64 = 5,       // max allowable burst tokens
    limit_window_ns:      u64 = 6000000, // tau + T (precalculated window)
}

// Single TAT state cell (with explicit penalty/reservation floor).
struct GcraCell {
    tat_ns:           u64 = 0,
    penalty_until_ns: u64 = 0,
}

// Result of a GCRA rate check.
struct GcraDecision {
    allowed:               bool = false,
    remaining_burst:       u64  = 0,
    retry_after_ns:        u64  = 0,
    reset_after_ns:        u64  = 0,
    wait_ns:               i64  = 0,
    tat_ns:                u64  = 0,
    insufficient_capacity: bool = false,
}

// Configures GCRA quota from sustained requests per second and burst capacity.
fn new_gcra_config(rate_per_sec: u64, burst_capacity: u64) -> GcraConfig {
    let r = max(rate_per_sec, 1);
    let t_ns = max(1000000000 / r, 1);
    let tau_ns = core::mul_sat_u64(t_ns, burst_capacity);
    let win_ns = core::add_sat_u64(tau_ns, t_ns);

    return GcraConfig {
        emission_interval_ns: t_ns,
        tau_ns:               tau_ns,
        max_burst:            burst_capacity,
        limit_window_ns:      win_ns,
    };
}

// Evaluates rate limit admission for cost units at now_ns and advances TAT only when allowed.
fn gcra_check(config: const GcraConfig&, cell: GcraCell&, cost: u64, now_ns: u64) -> GcraDecision {
    let dec, next_tat = security_internal::eval_gcra_config(
        config, cell.tat_ns, cost, now_ns, cell.penalty_until_ns,
    );
    if dec.allowed || next_tat < cell.tat_ns {
        cell.tat_ns = next_tat;
    }
    return dec;
}

// Evaluates rate limit admission without mutating TAT cell state.
fn gcra_peek(config: const GcraConfig&, cell: const GcraCell&, cost: u64, now_ns: u64) -> GcraDecision {
    let dec, _ = security_internal::eval_gcra_config(
        config, cell.tat_ns, cost, now_ns, cell.penalty_until_ns,
    );
    return dec;
}

// Applies penalty delay to TAT to rate-limit abusive clients or handle backpressure.
fn gcra_penalize(config: const GcraConfig&, cell: GcraCell&, penalty_ns: u64, now_ns: u64) {
    guard penalty_ns > 0 else { return; }
    let tat_old = security_internal::clamp_clock_drift(
        cell.tat_ns, now_ns, config.limit_window_ns, cell.penalty_until_ns,
    );
    let tat_base = core::ct_max_u64(now_ns, tat_old);
    let new_tat = core::add_sat_u64(tat_base, penalty_ns);
    cell.tat_ns = new_tat;
    cell.penalty_until_ns = core::ct_max_u64(cell.penalty_until_ns, new_tat);
}

// Resets single TAT cell state to zero.
fn gcra_reset(cell: GcraCell&) {
    cell.tat_ns = 0;
    cell.penalty_until_ns = 0;
}

// ---- Bounded Multi-Client Gateway Rate Limiter -----------------------------

struct GatewayClientEntry {
    client_id:           u8[..64] = [],
    cell:                GcraCell = GcraCell { .. },
    last_seen_ns:        u64      = 0,
    consecutive_rejects: u32      = 0,
    in_use:              bool     = false,
}

struct GatewayRateLimiter {
    config:         GcraConfig               = GcraConfig { .. },
    entries:        GatewayClientEntry[..64] = [],
    fallback_cell:  GcraCell                 = GcraCell { .. },
    total_allowed:  u64                      = 0,
    total_rejected: u64                      = 0,
}

// Instantiates a new zero-allocation GatewayRateLimiter.
fn new_gateway_rate_limiter(rate_per_sec: u64, burst_capacity: u64) -> GatewayRateLimiter {
    return GatewayRateLimiter {
        config: new_gcra_config(rate_per_sec, burst_capacity),
        ..
    };
}

// Finds entry index by client ID, returning `(idx, true)` or `(0, false)` if absent.
fn find_client_slot(limiter: const GatewayRateLimiter&, client_id: const u8[:]) -> i64, bool {
    guard client_id.len <= 64 else { return 0, false; }
    for &entry, i in limiter.entries {
        if entry.in_use && entry.client_id[..] == client_id {
            return i, true;
        }
    }
    return 0, false;
}

// Checks and updates rate limit for a client ID in the gateway limiter.
fn check_gateway_rate_limit(
    limiter:   GatewayRateLimiter&,
    client_id: const u8[:],
    cost:      u64,
    now_ns:    u64,
) -> GcraDecision {
    let slot, found = security_internal::allocate_client_entry(limiter, client_id, now_ns);
    if found && slot >= 0 && slot < limiter.entries.len {
        limiter.entries[slot].last_seen_ns = now_ns;
        let dec = gcra_check(limiter.config, limiter.entries[slot].cell, cost, now_ns);
        security_internal::record_client_admission(limiter, slot, dec);
        return dec;
    }

    let dec = gcra_check(limiter.config, limiter.fallback_cell, cost, now_ns);
    security_internal::record_fallback_admission(limiter, dec);
    return dec;
}

// Applies penalty delay to a specific client entry.
fn penalize_gateway_client(
    limiter:    GatewayRateLimiter&,
    client_id:  const u8[:],
    penalty_ns: u64,
    now_ns:     u64,
) {
    let slot, found = security_internal::allocate_client_entry(limiter, client_id, now_ns);
    if found && slot >= 0 && slot < limiter.entries.len {
        limiter.entries[slot].last_seen_ns = now_ns;
        gcra_penalize(limiter.config, limiter.entries[slot].cell, penalty_ns, now_ns);
        return;
    }
    gcra_penalize(limiter.config, limiter.fallback_cell, penalty_ns, now_ns);
}

// Evicts idle entries exceeding max_idle_ns that have no pending TAT delay.
fn evict_idle_gateway_clients(limiter: GatewayRateLimiter&, max_idle_ns: u64, now_ns: u64) -> i32 {
    var evicted: i64 = 0;
    for &entry in limiter.entries {
        if security_internal::should_evict_client(entry, max_idle_ns, now_ns) {
            security_internal::deactivate_client_slot(entry);
            evicted = core::add_sat_i64(evicted, 1);
        }
    }
    return evicted as i32;
}

// Resets all client entries and global counters in the gateway limiter.
fn reset_gateway_rate_limiter(limiter: GatewayRateLimiter&) {
    for &entry in limiter.entries {
        security_internal::reset_entry_slot(entry);
    }
    limiter.entries.clear();
    gcra_reset(limiter.fallback_cell);
    limiter.total_allowed = 0;
    limiter.total_rejected = 0;
}

// Evaluates GCRA rate-limit allowance for `key` at `now_ns` (UFCS hook for `wire::RateLimitService`).
// Resolves `now_ns == 0` via `core::sim_now_ns()` (failing closed if still 0) and routes empty keys
// through `limiter.fallback_cell` instead of bypassing rate limits.
fn allow_service_key(limiter: GatewayRateLimiter&, key: const u8[:], now_ns: u64) -> bool {
    let eff_now = if now_ns > 0 { now_ns } else { core::sim_now_ns() as u64 };
    guard eff_now > 0 else { return false; }
    if key.len == 0 {
        let dec = gcra_check(limiter.config, limiter.fallback_cell, 1, eff_now);
        if dec.allowed {
            limiter.total_allowed = core::add_sat_u64(limiter.total_allowed, 1);
        } else {
            limiter.total_rejected = core::add_sat_u64(limiter.total_rejected, 1);
        }
        return dec.allowed;
    }
    let dec = check_gateway_rate_limit(limiter, key, 1, eff_now);
    return dec.allowed;
}

// ---- High-Capacity Arena-Backed Edge Rate Limiter --------------------------

const DEFAULT_EDGE_RL_MAX_CLIENTS: i64 = 4096;

// High-capacity arena-backed GCRA rate limiter handle supporting 4096+ client IPs in O(1).
struct EdgeRateLimiter {
    config:            GcraConfig = GcraConfig { .. },
    max_clients:       i64        = DEFAULT_EDGE_RL_MAX_CLIENTS,
    fallback_cell:     GcraCell   = GcraCell { .. },
    total_allowed:     u64        = 0,
    total_rejected:    u64        = 0,
    evictions:         u64        = 0,
    next_evict_cursor: i64        = 0,
    arena_slot:        i64        = -1,
    generation:        u64        = 0,
}

// Instantiates an O(1) arena-backed EdgeRateLimiter with configurable client capacity.
fn new_edge_rate_limiter(
    rate_per_sec:   u64,
    burst_capacity: u64,
    max_clients:    i64 = DEFAULT_EDGE_RL_MAX_CLIENTS,
) -> EdgeRateLimiter {
    let eff_max = security_internal::clamp_edge_max_clients(max_clients);
    let slot, gen = security_internal::alloc_edge_arena_slot(eff_max);
    return EdgeRateLimiter {
        config:      new_gcra_config(rate_per_sec, burst_capacity),
        max_clients: eff_max,
        arena_slot:  slot,
        generation:  gen,
        ..
    };
}

// Releases the limiter's thread-local arena slot so subsequent limiters can reuse it.
fn release_edge_rate_limiter(limiter: EdgeRateLimiter&) {
    security_internal::release_edge_arena_slot(limiter.arena_slot, limiter.generation);
    limiter.arena_slot = -1;
    limiter.generation = 0;
    limiter.next_evict_cursor = 0;
}

// Checks and updates rate limit for a client ID in the high-capacity edge limiter.
fn check_edge_rate_limit(
    limiter:   EdgeRateLimiter&,
    client_id: const u8[:],
    cost:      u64,
    now_ns:    u64,
) -> GcraDecision {
    if client_id.len > 0 && client_id.len <= 64 && limiter.arena_slot >= 0 && limiter.generation != 0 {
        let abs_entry, evicted, ok = security_internal::edge_lookup_or_insert(
            limiter,
            client_id,
            now_ns,
        );
        if evicted {
            limiter.evictions = core::add_sat_u64(limiter.evictions, 1);
        }
        if ok && abs_entry >= 0 && abs_entry < security_internal::g_edge_rl_entries.len {
            let entry .= security_internal::g_edge_rl_entries[abs_entry];
            entry.last_seen_ns = now_ns;
            let dec = gcra_check(limiter.config, entry.cell, cost, now_ns);
            security_internal::record_edge_admission(limiter, abs_entry, dec);
            return dec;
        }
    }
    let dec = gcra_check(limiter.config, limiter.fallback_cell, cost, now_ns);
    security_internal::record_edge_fallback_admission(limiter, dec);
    return dec;
}

// Evicts idle entries exceeding max_idle_ns that have no pending TAT delay.
fn evict_idle_edge_clients(limiter: EdgeRateLimiter&, max_idle_ns: u64, now_ns: u64) -> i32 {
    guard limiter.arena_slot >= 0 && limiter.generation != 0 else { return 0; }
    let evicted = security_internal::evict_idle_edge_arena_clients(
        limiter.arena_slot,
        limiter.generation,
        max_idle_ns,
        now_ns,
    );
    if evicted > 0 {
        limiter.evictions = core::add_sat_u64(limiter.evictions, evicted as u64);
    }
    return evicted;
}
