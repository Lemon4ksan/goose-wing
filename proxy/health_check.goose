// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Layer 7 Active Background Health Check Prober and Target Lifecycle Engine.
// Implements active background health probing, HTTP wire probe generation,
// response status code validation, consecutive success/failure thresholds,
// and state machine transitions: UP, DOWN, PROBING (RFC 9110).
namespace wing;

import std;
import core from "..";
import proxy.load_balancer;

const HEALTH_SLOT_NONE: i32 = -1;

enum HealthState {
    Up,
    Down,
    Probing,
}

struct HealthCheckConfig {
    interval_ms:         u64      = 5000,
    timeout_ms:          u64      = 2000,
    healthy_threshold:   u32      = 2,
    unhealthy_threshold: u32      = 3,
    expected_status:     u16      = 200,
    path:                u8[..64] = "/healthz",
}

// Configures health check probing parameters with safety bounds.
fn new_health_check_config(
    interval_ms:      u64 = 5000,
    timeout_ms:       u64 = 2000,
    healthy_thresh:   u32 = 2,
    unhealthy_thresh: u32 = 3,
) -> HealthCheckConfig {
    return HealthCheckConfig {
        interval_ms:         if interval_ms > 0 { interval_ms } else { 5000 },
        timeout_ms:          if timeout_ms > 0 { timeout_ms } else { 2000 },
        healthy_threshold:   if healthy_thresh > 0 { healthy_thresh } else { 2 },
        unhealthy_threshold: if unhealthy_thresh > 0 { unhealthy_thresh } else { 3 },
        expected_status:     200,
        ..
    };
}

struct UpstreamHealth {
    state:                 HealthState = HealthState.Up,
    consecutive_successes: u32         = 0,
    consecutive_failures:  u32         = 0,
    last_probe_time_ms:    u64         = 0,
    last_rtt_us:           u32         = 0,
    total_probes:          u64         = 0,
    failed_probes:         u64         = 0,
}

inline fn handle_probing_success(health: UpstreamHealth&, successes: u32, threshold: u32) {
    if successes >= threshold {
        health.state = HealthState.Up;
    }
}

inline fn handle_down_success(health: UpstreamHealth&, successes: u32, threshold: u32) {
    health.state = HealthState.Probing;
    if successes >= threshold {
        health.state = HealthState.Up;
    }
}

// Transitions target state upon probe or request success.
fn record_probe_success(health: UpstreamHealth&, rtt_us: u32, config: const HealthCheckConfig&) -> HealthState {
    health.consecutive_failures = 0;
    let successes = core::add_sat_u32(health.consecutive_successes, 1);
    health.consecutive_successes = successes;
    health.total_probes = core::add_sat_u64(health.total_probes, 1);
    health.last_rtt_us = rtt_us;

    if health.state == HealthState.Probing {
        handle_probing_success(health, successes, config.healthy_threshold);
    } else if health.state == HealthState.Down {
        handle_down_success(health, successes, config.healthy_threshold);
    }

    return health.state;
}

// Transitions target state upon probe or request failure.
fn record_probe_failure(health: UpstreamHealth&, config: const HealthCheckConfig&) -> HealthState {
    health.consecutive_successes = 0;
    let fails = core::add_sat_u32(health.consecutive_failures, 1);
    health.consecutive_failures = fails;
    health.total_probes = core::add_sat_u64(health.total_probes, 1);
    health.failed_probes = core::add_sat_u64(health.failed_probes, 1);

    if fails >= config.unhealthy_threshold || health.state == HealthState.Probing {
        health.state = HealthState.Down;
    }

    return health.state;
}

// Initiates probing state for a down target.
fn enter_probing_state(health: UpstreamHealth&) -> bool {
    guard health.state == HealthState.Down else { return false; }
    health.state = HealthState.Probing;
    health.consecutive_successes = 0;
    return true;
}

// Determines if a target is due for background probing.
fn is_probe_due(health: const UpstreamHealth&, now_ms: u64, interval_ms: u64) -> bool {
    let elapsed = core::sub_sat_u64(now_ms, health.last_probe_time_ms);
    return elapsed >= interval_ms;
}

// Serializes HTTP/1.1 GET health probe request wire buffer.
fn format_health_probe_request(host: const u8[:], path: const u8[:], out: u8[>..]&) {
    out.clear();
    out.append("GET ");
    out.append(if path.len > 0 { path } else { "/healthz" });
    out.append(" HTTP/1.1\r\nHost: ");
    out.append(if host.len > 0 { host } else { "localhost" });
    out.append("\r\nUser-Agent: wing-health-probe\r\nConnection: close\r\nAccept: */*\r\n\r\n");
}

// Extracts 3-digit HTTP status code from HTTP/1.x response wire buffer without allocations.
//
// Example:
//   wire = "HTTP/1.1 200 OK\r\n"
//   returns: 200, true
fn parse_probe_status_code(wire: const u8[:]) -> u16, bool {
    // RFC 9112 Section 4: Status-Line — status-line = HTTP-version SP status-code SP [ reason-phrase ] CRLF
    guard wire.len >= 12 else { return 0, false; }
    let ok_ver = wire[..8] == "HTTP/1.1" || wire[..8] == "HTTP/1.0";
    guard ok_ver && wire[8] == ' ' else { return 0, false; }
    let ok_delim = wire.len == 12 || wire[12] == ' ' || wire[12] == '\r' || wire[12] == '\n';
    guard ok_delim else { return 0, false; }

    let status_u32, ok = core::parse_u32_dec(wire[9..12]);
    guard ok && status_u32 >= 100 && status_u32 <= 599 else { return 0, false; }
    return status_u32 as u16, true;
}

// Validates probe response against expected HTTP status code.
fn evaluate_probe_response(wire: const u8[:], expected_status: u16) -> bool {
    let status, ok = parse_probe_status_code(wire);
    guard ok else { return false; }
    return status == expected_status;
}

// Active background prober managing up to 16 upstream cluster targets
struct TargetProbeSlot {
    target_idx:       i32            = HEALTH_SLOT_NONE,
    health:           UpstreamHealth = UpstreamHealth { .. },
    active_in_flight: bool           = false,
    probe_start_ms:   u64            = 0,
    in_use:           bool           = false,
}

struct ClusterHealthChecker {
    config:                  HealthCheckConfig     = HealthCheckConfig { .. },
    slots:                   TargetProbeSlot[..16] = [],
    total_checks_dispatched: u64                   = 0,
}

fn new_cluster_health_checker(config: HealthCheckConfig) -> ClusterHealthChecker {
    return ClusterHealthChecker {
        config: config,
        ..
    };
}

fn find_probe_slot(checker: const ClusterHealthChecker&, target_idx: i32) -> i32 {
    guard target_idx >= 0 else { return HEALTH_SLOT_NONE; }
    let n = checker.slots.len as i32;
    for i in n {
        if checker.slots[i].in_use && checker.slots[i].target_idx == target_idx {
            return i;
        }
    }
    return HEALTH_SLOT_NONE;
}

inline fn init_probe_slot(slot: TargetProbeSlot&, target_idx: i32) {
    slot.target_idx = target_idx;
    slot.health = UpstreamHealth { .. };
    slot.active_in_flight = false;
    slot.probe_start_ms = 0;
    slot.in_use = true;
}

fn register_target_for_probing(checker: ClusterHealthChecker&, target_idx: i32) -> bool {
    guard target_idx >= 0 && target_idx < 16 else { return false; }
    let existing = find_probe_slot(checker, target_idx);
    guard existing == HEALTH_SLOT_NONE else { return true; }
    guard checker.slots.len < checker.slots.cap else { return false; }

    var new_slot = TargetProbeSlot { .. };
    init_probe_slot(new_slot, target_idx);
    checker.slots.push(new_slot);
    return true;
}

inline fn inc_checks_dispatched(checker: ClusterHealthChecker&) {
    checker.total_checks_dispatched = core::add_sat_u64(checker.total_checks_dispatched, 1);
}

// Prepares active probe request for target if probe is due and not in flight.
inline fn try_dispatch_probe_slot(
    slot:     TargetProbeSlot&,
    checker:  ClusterHealthChecker&,
    cluster:  const UpstreamCluster&,
    now_ms:   u64,
    out_wire: u8[>..]&,
) -> bool {
    let is_in_flight = slot.active_in_flight;
    guard !is_in_flight && is_probe_due(slot.health, now_ms, checker.config.interval_ms) else {
        return false;
    }

    slot.active_in_flight = true;
    slot.probe_start_ms = now_ms;
    slot.health.last_probe_time_ms = now_ms;
    inc_checks_dispatched(checker);

    let t_idx = slot.target_idx;
    let host_slice = cluster.targets[t_idx].host[..];
    let path_slice = checker.config.path[..];
    format_health_probe_request(host_slice, path_slice, out_wire);
    return true;
}

// Selects next target due for probing and prepares wire request.
fn poll_next_probe(
    checker:  ClusterHealthChecker&,
    cluster:  const UpstreamCluster&,
    now_ms:   u64,
    out_wire: u8[>..]&,
) -> i32, bool {
    let n = checker.slots.len as i32;
    for i in n {
        let t_idx = checker.slots[i].target_idx;
        guard t_idx >= 0 && t_idx < cluster.targets.len else { continue; }

        if try_dispatch_probe_slot(checker.slots[i], checker, cluster, now_ms, out_wire) {
            return t_idx, true;
        }
    }
    return HEALTH_SLOT_NONE, false;
}

inline fn clear_in_flight(slot: TargetProbeSlot&) {
    slot.active_in_flight = false;
    slot.probe_start_ms = 0;
}

// Synchronizes target health with UpstreamCluster
inline fn sync_cluster_target_health(cluster: UpstreamCluster&, target_idx: i32, new_state: HealthState) {
    guard target_idx >= 0 && target_idx < cluster.targets.len else { return; }
    let is_up = (new_state == HealthState.Up);
    cluster.targets[target_idx].is_healthy = is_up;
    if is_up {
        cluster.targets[target_idx].fails = 0;
        cluster.targets[target_idx].health_state = UpstreamHealthState.Up;
        cluster.circuit_open = false;
    } else if new_state == HealthState.Probing {
        cluster.targets[target_idx].health_state = UpstreamHealthState.Probing;
        cluster.targets[target_idx].successes = 1;
        cluster.circuit_open = false;
    } else {
        cluster.targets[target_idx].fails = cluster.max_fails;
        cluster.targets[target_idx].health_state = UpstreamHealthState.Down;
        update_cluster_circuit_state(cluster);
    }
}

inline fn sync_slot_from_cluster(slot: TargetProbeSlot&, cluster_state: UpstreamHealthState) {
    if cluster_state == UpstreamHealthState.Down {
        if slot.health.state != HealthState.Down {
            slot.health.state = HealthState.Down;
            slot.health.consecutive_successes = 0;
        }
    } else if cluster_state == UpstreamHealthState.Probing && slot.health.state == HealthState.Up {
        slot.health.state = HealthState.Probing;
        slot.health.consecutive_successes = 0;
    } else if cluster_state == UpstreamHealthState.Up && slot.health.state != HealthState.Up {
        slot.health.state = HealthState.Up;
        slot.health.consecutive_failures = 0;
    }
}

// Handles successful probe completion.
fn on_probe_success(
    checker:    ClusterHealthChecker&,
    cluster:    UpstreamCluster&,
    target_idx: i32,
    rtt_us:     u32,
) -> HealthState {
    guard target_idx >= 0 && target_idx < cluster.targets.len else {
        return HealthState.Down;
    }
    let slot_idx = find_probe_slot(checker, target_idx);
    guard slot_idx != HEALTH_SLOT_NONE && slot_idx < checker.slots.len else {
        return HealthState.Down;
    }

    sync_slot_from_cluster(checker.slots[slot_idx], cluster.targets[target_idx].health_state);
    clear_in_flight(checker.slots[slot_idx]);
    let new_state = record_probe_success(checker.slots[slot_idx].health, rtt_us, checker.config);
    sync_cluster_target_health(cluster, target_idx, new_state);
    return new_state;
}

// Handles failed probe completion.
fn on_probe_failure(
    checker:    ClusterHealthChecker&,
    cluster:    UpstreamCluster&,
    target_idx: i32,
) -> HealthState {
    guard target_idx >= 0 && target_idx < cluster.targets.len else {
        return HealthState.Down;
    }
    let slot_idx = find_probe_slot(checker, target_idx);
    guard slot_idx != HEALTH_SLOT_NONE && slot_idx < checker.slots.len else {
        return HealthState.Down;
    }

    sync_slot_from_cluster(checker.slots[slot_idx], cluster.targets[target_idx].health_state);
    clear_in_flight(checker.slots[slot_idx]);
    let new_state = record_probe_failure(checker.slots[slot_idx].health, checker.config);
    sync_cluster_target_health(cluster, target_idx, new_state);
    return new_state;
}

inline fn inc_timeouts_count(cnt: i32&) {
    cnt = (core::add_sat_u64(cnt as u64, 1)) as i32;
}

// Checks for probe timeouts in flight.
fn check_probe_timeouts(
    checker: ClusterHealthChecker&,
    cluster: UpstreamCluster&,
    now_ms:  u64,
) -> i32 {
    var timed_out_count: i32 = 0;
    let n = checker.slots.len as i32;

    for i in n {
        guard checker.slots[i].in_use && checker.slots[i].active_in_flight else { continue; }
        let elapsed = core::sub_sat_u64(now_ms, checker.slots[i].probe_start_ms);
        guard elapsed >= checker.config.timeout_ms else { continue; }
        let t_idx = checker.slots[i].target_idx;
        guard t_idx >= 0 && t_idx < cluster.targets.len else {
            clear_in_flight(checker.slots[i]);
            continue;
        }
        sync_slot_from_cluster(checker.slots[i], cluster.targets[t_idx].health_state);
        clear_in_flight(checker.slots[i]);
        let new_state = record_probe_failure(checker.slots[i].health, checker.config);
        sync_cluster_target_health(cluster, t_idx, new_state);
        inc_timeouts_count(timed_out_count);
    }
    return timed_out_count;
}
