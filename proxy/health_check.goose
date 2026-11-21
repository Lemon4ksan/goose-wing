// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Layer 7 Active Background Health Check Prober and Target Lifecycle Engine.
// Implements active background health probing, HTTP wire probe generation,
// response status code validation, consecutive success/failure thresholds,
// and state machine transitions: UP, DOWN, PROBING (RFC 9110).
namespace proxy;

import std;
import core;
import .load_balancer;
import .internal;

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

// Transitions target state upon probe or request success.
fn record_probe_success(health: UpstreamHealth&, rtt_us: u32, config: const HealthCheckConfig&) -> HealthState {
    health.consecutive_failures = 0;
    let successes = core::add_sat_u32(health.consecutive_successes, 1);
    health.consecutive_successes = successes;
    health.total_probes = core::add_sat_u64(health.total_probes, 1);
    health.last_rtt_us = rtt_us;

    if health.state == HealthState.Probing {
        proxy_internal::handle_probing_success(health, successes, config.healthy_threshold);
    } else if health.state == HealthState.Down {
        proxy_internal::handle_down_success(health, successes, config.healthy_threshold);
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

// Serializes HTTP/1.1 GET health probe request into `out`.
fn format_health_probe_request<B>(host: const u8[:], path: const u8[:], out: B&) -> bool {
    let safe_path = if proxy_internal::is_valid_probe_path(path) { path } else { "/healthz" };
    let safe_host = if proxy_internal::is_valid_upstream_host(host) { host } else { "localhost" };
    guard out.try_set("GET ") else { return false; }
    var committed = false;
    defer if !committed { out.clear(); };
    guard out.try_append(safe_path) else { return false; }
    guard out.try_append(" HTTP/1.1\r\nHost: ") else { return false; }
    guard out.try_append(safe_host) else { return false; }
    guard out.try_append("\r\nUser-Agent: wing-health-probe\r\nConnection: close\r\nAccept: */*\r\n\r\n") else {
        return false;
    }
    committed = true;
    return true;
}

// Extracts 3-digit HTTP status code from HTTP/1.x response wire buffer without allocations.
//
// Example:
//   wire = "HTTP/1.1 200 OK\r\n"
//   returns: 200, true
fn parse_probe_status_code(wire: const u8[:]) -> u16, bool {
    // RFC 9112 Section 4: Status Line - status-line = HTTP-version SP status-code SP [ reason-phrase ] CRLF.
    let status_line, _, has_crlf = wire.split_once("\r\n");
    guard has_crlf && status_line.len >= 13 else { return 0, false; }
    let ok_ver = status_line[..8] == "HTTP/1.1" || status_line[..8] == "HTTP/1.0";
    guard ok_ver && status_line[8] == ' ' && status_line[12] == ' ' else { return 0, false; }
    guard proxy_internal::is_valid_probe_reason_phrase(status_line[13..]) else { return 0, false; }

    let status_u32, ok = status_line[9..12].parse_u32_dec();
    guard ok && status_u32 >= 100 && status_u32 <= 599 else { return 0, false; }
    return status_u32 as u16, true;
}

// Validates probe response against expected HTTP status code.
fn evaluate_probe_response(wire: const u8[:], expected_status: u16) -> bool {
    let status, ok = parse_probe_status_code(wire);
    guard ok else { return false; }
    return status == expected_status;
}

// Active background prober managing up to 16 upstream cluster targets.
struct TargetProbeSlot {
    target_idx:       i32            = proxy_internal::HEALTH_SLOT_NONE,
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

fn new_cluster_health_checker(
    config: HealthCheckConfig = HealthCheckConfig { .. },
) -> ClusterHealthChecker {
    return ClusterHealthChecker {
        config: config,
        ..
    };
}

fn register_target_for_probing(checker: ClusterHealthChecker&, target_idx: i32) -> bool {
    guard target_idx >= 0 && target_idx < 16 else { return false; }
    let existing = proxy_internal::find_probe_slot(checker, target_idx);
    guard existing == proxy_internal::HEALTH_SLOT_NONE else { return true; }

    var new_slot = TargetProbeSlot { .. };
    proxy_internal::init_probe_slot(new_slot, target_idx);
    return checker.slots.try_push(new_slot);
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
    let slot_idx = proxy_internal::find_probe_slot(checker, target_idx);
    guard slot_idx != proxy_internal::HEALTH_SLOT_NONE && slot_idx < checker.slots.len else {
        return HealthState.Down;
    }

    let slot .= checker.slots[slot_idx];
    sync_slot_from_cluster(slot, cluster.targets[target_idx].health_state);
    proxy_internal::clear_in_flight(slot);
    let new_state = record_probe_success(slot.health, rtt_us, checker.config);
    proxy_internal::sync_cluster_target_health(cluster, target_idx, slot.health, new_state);
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
    let slot_idx = proxy_internal::find_probe_slot(checker, target_idx);
    guard slot_idx != proxy_internal::HEALTH_SLOT_NONE && slot_idx < checker.slots.len else {
        return HealthState.Down;
    }

    let slot .= checker.slots[slot_idx];
    sync_slot_from_cluster(slot, cluster.targets[target_idx].health_state);
    proxy_internal::clear_in_flight(slot);
    let new_state = record_probe_failure(slot.health, checker.config);
    proxy_internal::sync_cluster_target_health(cluster, target_idx, slot.health, new_state);
    return new_state;
}

// Checks for probe timeouts in flight.
fn check_probe_timeouts(
    checker: ClusterHealthChecker&,
    cluster: UpstreamCluster&,
    now_ms:  u64,
) -> i32 {
    var timed_out_count: i32 = 0;

    for &slot in checker.slots {
        guard slot.in_use && slot.active_in_flight else { continue; }
        let elapsed = core::sub_sat_u64(now_ms, slot.probe_start_ms);
        guard elapsed >= checker.config.timeout_ms else { continue; }
        let t_idx = slot.target_idx;
        guard t_idx >= 0 && t_idx < cluster.targets.len else {
            proxy_internal::clear_in_flight(slot);
            continue;
        }
        sync_slot_from_cluster(slot, cluster.targets[t_idx].health_state);
        proxy_internal::clear_in_flight(slot);
        let new_state = record_probe_failure(slot.health, checker.config);
        proxy_internal::sync_cluster_target_health(cluster, t_idx, slot.health, new_state);
        proxy_internal::inc_timeouts_count(timed_out_count);
    }
    return timed_out_count;
}
