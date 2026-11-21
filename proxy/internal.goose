// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Internal helpers, constants, and header/connection mechanics for package `proxy`.
namespace proxy_internal;

import std;
import core from "..";
import http.headers;
import http.forwarded;
import http.request;
import http.response;
import net.tcp;
import net.transport;
import net.pool;
import net.upstream_pool;
import wire.h1;
import wire.h1_exchange;
import .load_balancer;
import .health_check;
import .reverse_proxy;

// ---- Internal Constants ----------------------------------------------------

const NO_UPSTREAM_TARGET:       i32 = -1;
const KETAMA_POINTS_PER_WEIGHT: u32 = 16;
const HEALTH_SLOT_NONE:         i32 = -1;

// ---- Load Balancer & Ketama Helpers ----------------------------------------

inline fn is_valid_upstream_host(host: const u8[:]) -> bool {
    guard host.len > 0 else { return false; }
    for b in host {
        guard b > 0x20 && b < 0x7F &&
              b != '/' && b != '?' && b != '#' && b != '\\' && b != '@' && b != ',' else {
            return false;
        }
    }
    return true;
}

inline fn inc_active_conns(target: proxy::UpstreamTarget&) {
    target.active_conns = (core::add_sat_u64(target.active_conns as u64, 1)) as i32;
}

inline fn inc_total_requests(target: proxy::UpstreamTarget&) {
    target.total_requests = core::add_sat_u64(target.total_requests, 1);
}

inline fn record_target_dispatch(target: proxy::UpstreamTarget&) {
    inc_active_conns(target);
    inc_total_requests(target);
}

inline fn dec_active_conns(target: proxy::UpstreamTarget&) {
    let cur = target.active_conns;
    guard cur > 0 else { return; }
    target.active_conns = (core::sub_sat_u64(cur as u64, 1)) as i32;
}

inline fn inc_target_successes(target: proxy::UpstreamTarget&) -> i32 {
    let s = (core::add_sat_u64(target.successes as u64, 1)) as i32;
    target.successes = s;
    return s;
}

inline fn inc_target_fails(target: proxy::UpstreamTarget&) -> i32 {
    let fails = (core::add_sat_u64(target.fails as u64, 1)) as i32;
    target.fails = fails;
    return fails;
}

inline fn advance_rr_index(cur_rr: i32, n: i32) -> i32 {
    let next_rr = (core::add_sat_u64(cur_rr as u64, 1)) as i32;
    return if next_rr >= n { 0 } else { next_rr };
}

inline fn current_monotonic_ms() -> i64 {
    return core::as_millis(core::duration_since(core::monotonic_now(), core::MonotonicInstant {}));
}

inline fn is_backend_routable(target: const proxy::UpstreamTarget&, now_ms: i64) -> bool {
    if target.ejected_until_ms > 0 && now_ms < target.ejected_until_ms {
        return false;
    }
    return target.is_healthy || target.health_state == proxy::UpstreamHealthState.Probing;
}

inline fn is_target_selectable(target: const proxy::UpstreamTarget&) -> bool {
    let now_ms = if target.ejected_until_ms > 0 { current_monotonic_ms() } else { 0 };
    return is_backend_routable(target, now_ms);
}

fn select_round_robin(cluster: proxy::UpstreamCluster&, n: i32) -> i32, bool {
    for _ in n {
        let idx = cluster.rr_index;
        cluster.rr_index = advance_rr_index(cluster.rr_index, n);

        if is_target_selectable(cluster.targets[idx]) {
            record_target_dispatch(cluster.targets[idx]);
            return idx, true;
        }
    }
    return NO_UPSTREAM_TARGET, false;
}

fn find_least_conn_target(cluster: const proxy::UpstreamCluster&, n: i32) -> i32 {
    var best_idx: i32 = NO_UPSTREAM_TARGET;

    for i in n {
        guard is_target_selectable(cluster.targets[i]) else { continue; }
        if best_idx == NO_UPSTREAM_TARGET {
            best_idx = i;
        } else {
            best_idx = proxy::evaluate_two_choice(
                cluster.targets[best_idx],
                best_idx,
                cluster.targets[i],
                i,
            );
        }
    }
    return best_idx;
}

fn select_least_connections(cluster: proxy::UpstreamCluster&, n: i32) -> i32, bool {
    let best_idx = find_least_conn_target(cluster, n);
    if best_idx >= 0 {
        record_target_dispatch(cluster.targets[best_idx]);
        return best_idx, true;
    }
    return NO_UPSTREAM_TARGET, false;
}

// Fast Lemire reduction without division or modulo.
inline fn pick_random_index(cluster: proxy::UpstreamCluster&, n: i32) -> i32 {
    let r_val = proxy::next_prng(cluster.rng_state);
    return (((r_val & 0xFFFFFFFF) * (n as u64)) >> 32) as i32;
}

fn pick_two_distinct(cluster: proxy::UpstreamCluster&, n: i32) -> i32, i32 {
    let r1 = pick_random_index(cluster, n);
    var r2 = pick_random_index(cluster, n);
    if r2 == r1 {
        r2 = advance_rr_index(r1, n);
    }
    return r1, r2;
}

fn select_p2c(cluster: proxy::UpstreamCluster&, n: i32) -> i32, bool {
    if n == 1 {
        if is_target_selectable(cluster.targets[0]) {
            record_target_dispatch(cluster.targets[0]);
            return 0, true;
        }
        return NO_UPSTREAM_TARGET, false;
    }

    let r1, r2 = pick_two_distinct(cluster, n);
    let h1 = is_target_selectable(cluster.targets[r1]);
    let h2 = is_target_selectable(cluster.targets[r2]);

    if h1 && h2 {
        let chosen = proxy::evaluate_two_choice(cluster.targets[r1], r1, cluster.targets[r2], r2);
        record_target_dispatch(cluster.targets[chosen]);
        return chosen, true;
    }
    if h1 {
        record_target_dispatch(cluster.targets[r1]);
        return r1, true;
    }
    if h2 {
        record_target_dispatch(cluster.targets[r2]);
        return r2, true;
    }
    // Fallback to least-connections scan when both random choices are unhealthy
    // to prevent dropping traffic when other cluster targets remain healthy.
    return select_least_connections(cluster, n);
}

// Evaluates target circuit breaker state against consecutive healthy/unhealthy thresholds.
fn evaluate_circuit_breaker(target: proxy::UpstreamTarget&, max_fails_override: i32 = 0) -> bool {
    let unhealthy_thresh = if target.unhealthy_threshold > 0 {
        target.unhealthy_threshold
    } else if max_fails_override > 0 {
        max_fails_override
    } else {
        3
    };
    let healthy_thresh = if target.healthy_threshold > 0 { target.healthy_threshold } else { 2 };

    if target.fails >= unhealthy_thresh {
        target.health_state = proxy::UpstreamHealthState.Down;
        target.is_healthy = false;
        return false;
    }

    if target.health_state == proxy::UpstreamHealthState.Down {
        if target.successes > 0 {
            target.health_state = proxy::UpstreamHealthState.Probing;
        } else {
            target.is_healthy = false;
            return false;
        }
    }

    if target.health_state == proxy::UpstreamHealthState.Probing {
        if target.successes >= healthy_thresh {
            target.health_state = proxy::UpstreamHealthState.Up;
            target.is_healthy = true;
            return true;
        }
        target.is_healthy = false;
        return false;
    }

    target.health_state = proxy::UpstreamHealthState.Up;
    target.is_healthy = true;
    return true;
}

fn update_cluster_circuit_state(cluster: proxy::UpstreamCluster&) {
    var any_healthy = false;
    for &t in cluster.targets {
        if is_target_selectable(t) {
            any_healthy = true;
            break;
        }
    }
    if !any_healthy {
        cluster.circuit_open = true;
    }
}

// Inserts `pt` into sorted `ring.points`, deduplicating identical 32-bit hash positions.
fn insert_ketama_point(ring: proxy::KetamaRing&, pt: proxy::KetamaPoint) {
    var lo: u64 = 0;
    var hi: u64 = ring.points.len as u64;
    while lo < hi {
        let mid = core::add_sat_u64(lo, core::sub_sat_u64(hi, lo) >> 1);
        let cur = ring.points[mid as i64].hash;
        if cur == pt.hash {
            return;
        }
        if cur < pt.hash {
            lo = core::add_sat_u64(mid, 1);
        } else {
            hi = mid;
        }
    }
    guard ring.points.try_push(pt) else { return; }
    var pos: u64 = core::sub_sat_u64(ring.points.len as u64, 1);
    while pos > lo {
        let prev = core::sub_sat_u64(pos, 1);
        ring.points[pos as i64] = ring.points[prev as i64];
        pos = prev;
    }
    ring.points[lo as i64] = pt;
}

inline fn calc_ketama_target_points(w: i64, total_weight: i64, target_count: i64, ring_cap: i64) -> i64 {
    let pts_per_w = KETAMA_POINTS_PER_WEIGHT as i64;
    let raw_total = core::mul_sat_i64(total_weight, pts_per_w);
    if raw_total <= ring_cap {
        return core::mul_sat_i64(w, pts_per_w);
    }
    let avail = max(core::sub_sat_i64(ring_cap, target_count), 0);
    let scaled = core::div_euclid_i64(core::mul_sat_i64(w, avail), max(total_weight, 1));
    return core::add_sat_i64(1, scaled);
}

// Binary-searches `ring.points` for the first point with `hash >= key_hash`, wrapping to index 0.
fn find_ketama_start_idx(ring: const proxy::KetamaRing&, key_hash: u32) -> i64 {
    var lo: u64 = 0;
    var hi: u64 = ring.points.len as u64;
    while lo < hi {
        let mid = core::add_sat_u64(lo, core::sub_sat_u64(hi, lo) >> 1);
        let cur = ring.points[mid as i64].hash;
        if cur < key_hash {
            lo = core::add_sat_u64(mid, 1);
        } else {
            hi = mid;
        }
    }
    if lo >= (ring.points.len as u64) {
        return 0;
    }
    return lo as i64;
}

fn gcd_positive_i32(a_in: i32, b_in: i32) -> i32 {
    var a = max(a_in, 1);
    var b = max(b_in, 1);
    while a != b {
        if a > b {
            a = core::sub_sat_i64(a, b) as i32;
        } else {
            b = core::sub_sat_i64(b, a) as i32;
        }
    }
    return max(a, 1);
}

inline fn step_weighted_round_robin(bal: proxy::DynamicWeightBalancer&, n: i32) -> i64 {
    let next_idx = core::add_sat_i64(bal.current_index, 1) as i32;
    bal.current_index = if next_idx >= n || next_idx < 0 { 0 } else { next_idx };
    if bal.current_index == 0 {
        bal.current_weight = core::sub_sat_i64(bal.current_weight, bal.weight_gcd) as i32;
        if bal.current_weight <= 0 {
            bal.current_weight = bal.max_effective_weight;
        }
    }
    return bal.current_index;
}

// ---- Health Check Helpers --------------------------------------------------

inline fn handle_probing_success(health: proxy::UpstreamHealth&, successes: u32, threshold: u32) {
    if successes >= threshold {
        health.state = proxy::HealthState.Up;
    }
}

inline fn handle_down_success(health: proxy::UpstreamHealth&, successes: u32, threshold: u32) {
    health.state = proxy::HealthState.Probing;
    if successes >= threshold {
        health.state = proxy::HealthState.Up;
    }
}

inline fn is_valid_probe_path(path: const u8[:]) -> bool {
    guard path.len > 0 && path[0] == '/' else { return false; }
    for b in path {
        guard b > 0x20 && b < 0x7F else { return false; }
    }
    return true;
}

inline fn is_valid_probe_reason_phrase(reason: const u8[:]) -> bool {
    for b in reason {
        guard (b >= 0x20 && b <= 0x7E) || b >= 0x80 || b == '\t' else { return false; }
    }
    return true;
}

fn find_probe_slot(checker: const proxy::ClusterHealthChecker&, target_idx: i32) -> i32 {
    guard target_idx >= 0 else { return HEALTH_SLOT_NONE; }
    for &slot, i in checker.slots {
        if slot.in_use && slot.target_idx == target_idx {
            return i as i32;
        }
    }
    return HEALTH_SLOT_NONE;
}

inline fn init_probe_slot(slot: proxy::TargetProbeSlot&, target_idx: i32) {
    slot.target_idx = target_idx;
    slot.health = proxy::UpstreamHealth { .. };
    slot.active_in_flight = false;
    slot.probe_start_ms = 0;
    slot.in_use = true;
}

inline fn clear_in_flight(slot: proxy::TargetProbeSlot&) {
    slot.active_in_flight = false;
    slot.probe_start_ms = 0;
}

inline fn sync_cluster_target_health(
    cluster:    proxy::UpstreamCluster&,
    target_idx: i32,
    health:     const proxy::UpstreamHealth&,
    new_state:  proxy::HealthState,
) {
    guard target_idx >= 0 && target_idx < cluster.targets.len else { return; }
    let target .= cluster.targets[target_idx];
    let is_up = (new_state == proxy::HealthState.Up);
    target.is_healthy = is_up;
    if is_up {
        if health.consecutive_failures == 0 {
            target.fails = 0;
        } else {
            target.fails = max(target.fails, health.consecutive_failures as i32);
        }
        target.health_state = proxy::UpstreamHealthState.Up;
        cluster.circuit_open = false;
    } else if new_state == proxy::HealthState.Probing {
        target.health_state = proxy::UpstreamHealthState.Probing;
        target.successes = max(health.consecutive_successes as i32, 1);
        cluster.circuit_open = false;
    } else {
        target.fails = max(cluster.max_fails, health.consecutive_failures as i32);
        target.health_state = proxy::UpstreamHealthState.Down;
        update_cluster_circuit_state(cluster);
    }
}

inline fn inc_timeouts_count(cnt: i32&) {
    cnt = (core::add_sat_u64(cnt as u64, 1)) as i32;
}

// ---- Reverse Proxy Header, Authority & Connection Helpers ------------------

fn format_chained_xff(buf: u8[..1024]&, existing_xff: const u8[:], client_ip: const u8[:]) -> bool {
    var committed = false;
    defer if !committed { buf.clear(); };
    guard buf.try_set(existing_xff) else { return false; }
    guard buf.try_append(", ") else { return false; }
    guard buf.try_append(client_ip) else { return false; }
    committed = true;
    return true;
}

fn append_chained_xff(out_headers: http::HeaderMap&, existing_xff: const u8[:], client_ip: const u8[:]) -> bool {
    var chained: u8[..1024] = [];
    guard format_chained_xff(chained, existing_xff, client_ip) else { return false; }
    return http::append_header(out_headers, "X-Forwarded-For", chained[..]);
}

fn append_forwarded_for(out_headers: http::HeaderMap&, existing_xff: const u8[:], client_ip: const u8[:]) -> bool {
    guard client_ip.len > 0 else { return true; }
    if existing_xff.len > 0 {
        return append_chained_xff(out_headers, existing_xff, client_ip);
    }
    return http::append_header(out_headers, "X-Forwarded-For", client_ip);
}

inline fn is_standard_h2_request_pseudo(name: const u8[:]) -> bool {
    return name == ":method" ||
        name == ":scheme" ||
        name == ":authority" ||
        name == ":path" ||
        name == ":protocol";
}

fn should_forward_header(
    name:       const u8[:],
    val:        const u8[:],
    in_headers: const http::HeaderMap&,
    config:     const proxy::Config&,
) -> bool {
    if name.eq_ascii_fold("host") {
        return config.preserve_host;
    }
    if proxy::is_forwarded_metadata_header(name) {
        return false;
    }
    if name.eq_ascii_fold("max-forwards") {
        return true;
    }
    // RFC 9112 Section 6.3: Message Body Length - remove Content-Length if Transfer-Encoding is present.
    if name.eq_ascii_fold("content-length") && http::has_header(in_headers, "transfer-encoding") {
        return false;
    }
    guard config.strip_hop_by_hop else { return true; }

    if http::is_hop_by_hop_header_name(name) {
        // RFC 9110 Section 7.6.1: Connection - TE may only be forwarded if the value is trailers.
        return name.eq_ascii_fold("te") && val.trim_lws().eq_ascii_fold("trailers");
    }

    if http::is_token_in_connection_header_map(in_headers, name) {
        return false;
    }

    return true;
}

inline fn check_cl_match(val: const u8[:], first_found: bool&, target_val: i64&) -> bool {
    let parsed_cl, ok_cl = http::validate_content_length_value(val);
    guard ok_cl else { return false; }
    if !first_found {
        target_val = parsed_cl;
        first_found = true;
        return true;
    }
    return parsed_cl == target_val;
}

inline fn append_canonical_content_length(
    out_headers: http::HeaderMap&,
    name:        const u8[:],
    val:         const u8[:],
) -> bool {
    let parsed_cl, ok_cl = http::validate_content_length_value(val);
    guard ok_cl else { return false; }
    var cl_buf: u8[..24] = [];
    parsed_cl.format_i64_dec(cl_buf);
    return http::append_header(out_headers, name, cl_buf[..]);
}

// Validates framing header integrity before forwarding.
fn has_consistent_framing_headers(in_headers: const http::HeaderMap&) -> bool {
    // RFC 9110 Section 7.6.1: Connection - MUST NOT send connection option for end-to-end framing or routing fields.
    guard !http::is_token_in_connection_header_map(in_headers, "content-length") else { return false; }
    guard !http::is_token_in_connection_header_map(in_headers, "transfer-encoding") else { return false; }
    guard !http::is_token_in_connection_header_map(in_headers, "host") else { return false; }
    guard !http::is_token_in_connection_header_map(in_headers, "max-forwards") else { return false; }

    var first_cl_found = false;
    var first_cl_val: i64 = 0;
    var has_te = false;

    for &entry in in_headers.entries {
        let name = http::entry_name(in_headers, entry);
        let val = http::entry_value(in_headers, entry);

        if name.eq_ascii_fold("content-length") {
            guard check_cl_match(val, first_cl_found, first_cl_val) else { return false; }
        }
        if name.eq_ascii_fold("transfer-encoding") {
            guard !has_te && http::validate_transfer_encoding_value(val) else { return false; }
            has_te = true;
        }
    }
    // RFC 9112 Section 6.3: Message Body Length - reject messages with both Transfer-Encoding and Content-Length.
    guard !(first_cl_found && has_te) else { return false; }
    return true;
}

fn copy_filtered_headers(
    in_headers:  const http::HeaderMap&,
    out_headers: http::HeaderMap&,
    config:      const proxy::Config&,
) -> bool {
    for &entry in in_headers.entries {
        let name = http::entry_name(in_headers, entry);
        let val = http::entry_value(in_headers, entry);

        if is_standard_h2_request_pseudo(name) {
            continue;
        }
        // RFC 9113 Section 8.3: HTTP Control Data - reject non-standard or unstripped pseudo-headers.
        guard http::is_valid_header_name(name) && http::is_valid_header_value(val) else { return false; }

        if name.eq_ascii_fold("content-length") {
            if !http::has_header(out_headers, "content-length") &&
               should_forward_header(name, val, in_headers, config) {
                guard append_canonical_content_length(out_headers, name, val) else { return false; }
            }
            continue;
        }

        if should_forward_header(name, val, in_headers, config) {
            guard http::append_header(out_headers, name, val) else { return false; }
        }
    }
    return true;
}

fn format_via(buf: u8[..64]&, pseudonym: const u8[:], http_version: const u8[:]) -> bool {
    let ver_suffix, has_http = http_version.strip_prefix("HTTP/");
    let ver_str = if has_http && ver_suffix.len > 0 {
        ver_suffix
    } else if http_version.len > 0 {
        http_version
    } else {
        "1.1"
    };
    var committed = false;
    defer if !committed { buf.clear(); };
    guard buf.try_set(ver_str) else { return false; }
    guard buf.try_append(" ") else { return false; }
    guard buf.try_append(pseudonym) else { return false; }
    committed = true;
    return true;
}

// Extracts the `received-by` pseudonym or host[:port] token from a single RFC 9110 Via hop.
//
// Example:
//   hop = "1.1 wing-gw (Goose)"
//   returns: "wing-gw"
inline fn extract_via_received_by(hop: const u8[:]) -> const u8[:] {
    let trimmed = hop.trim_lws();
    var idx: i64 = 0;
    while idx < trimmed.len && !core::is_lws(trimmed[idx]) {
        idx = core::add_sat_i64(idx, 1);
    }
    let after_proto = trimmed[idx..].trim_lws_start();
    var end_idx: i64 = 0;
    while end_idx < after_proto.len && !core::is_lws(after_proto[end_idx]) && after_proto[end_idx] != '(' {
        end_idx = core::add_sat_i64(end_idx, 1);
    }
    return after_proto[..end_idx];
}

inline fn strip_via_port(received_by: const u8[:]) -> const u8[:] {
    guard received_by.len > 0 else { return ""; }
    if received_by[0] == '[' {
        let close_idx = received_by.index_of_byte(']');
        if close_idx > 0 {
            return received_by[..core::add_sat_i64(close_idx, 1)];
        }
        return received_by;
    }
    let col = received_by.last_index_of_byte(':');
    return if col > 0 { received_by[..col] } else { received_by };
}

inline fn matches_via_pseudonym(hop: const u8[:], pseudonym: const u8[:]) -> bool {
    let received_by = extract_via_received_by(hop);
    guard received_by.len > 0 else { return false; }
    if received_by.eq_ascii_fold(pseudonym) {
        return true;
    }
    return !pseudonym.contains_byte(':') && strip_via_port(received_by).eq_ascii_fold(pseudonym);
}

// Finds the next unparenthesized comma in an RFC 9110 Section 7.6.3 `Via` header value.
//
// Example:
//   s = "1.1 edge (gw, 1.1 wing), 1.1 backend"
//   returns: 23 (index of the comma after ')')
fn find_next_via_comma(s: const u8[:]) -> i64 {
    var i:           i64 = 0;
    var paren_depth: i64 = 0;
    while i < s.len {
        let b = s[i];
        if paren_depth > 0 && b == '\\' {
            i = core::add_sat_i64(i, 2);
            continue;
        }
        if b == '(' {
            paren_depth = core::add_sat_i64(paren_depth, 1);
        } else if b == ')' && paren_depth > 0 {
            paren_depth = core::sub_sat_i64(paren_depth, 1);
        } else if b == ',' && paren_depth == 0 {
            return i;
        }
        i = core::add_sat_i64(i, 1);
    }
    return s.len;
}

fn has_via_pseudonym_loop(combined_via: const u8[:], pseudonym: const u8[:]) -> bool {
    guard combined_via.len > 0 && pseudonym.len > 0 else { return false; }
    var cursor: i64 = 0;
    while cursor < combined_via.len {
        let rel_comma = find_next_via_comma(combined_via[cursor..]);
        let comma_idx = core::add_sat_i64(cursor, rel_comma);
        if matches_via_pseudonym(combined_via[cursor..comma_idx], pseudonym) {
            return true;
        }
        if comma_idx >= combined_via.len {
            break;
        }
        cursor = core::add_sat_i64(comma_idx, 1);
    }
    return false;
}

fn inject_via_header(
    out_headers:  http::HeaderMap&,
    in_headers:   const http::HeaderMap&,
    pseudonym:    const u8[:],
    http_version: const u8[:],
) -> bool {
    var combined: u8[..1024] = [];
    let has_existing = http::has_header(in_headers, "Via");
    if has_existing {
        guard http::get_combined(in_headers, "Via", combined, 950) else { return false; }
        // RFC 9110 Section 7.6.3: Via - detect forwarding loops when own pseudonym is already present.
        guard !has_via_pseudonym_loop(combined[..], pseudonym) else { return false; }
    }
    guard pseudonym.len > 0 else {
        guard combined.len > 0 else { return true; }
        return http::append_header(out_headers, "Via", combined[..]);
    }
    var via_buf: u8[..64] = [];
    guard format_via(via_buf, pseudonym, http_version) else { return false; }
    guard combined.len > 0 else {
        return http::append_header(out_headers, "Via", via_buf[..]);
    }
    guard combined.try_append(", ") && combined.try_append(via_buf[..]) else { return false; }
    return http::append_header(out_headers, "Via", combined[..]);
}

fn append_forwarded_metadata_xff(
    out_headers:        http::HeaderMap&,
    in_headers:         const http::HeaderMap&,
    client_ip:          const u8[:],
    trust_incoming_xff: bool,
) -> bool {
    guard trust_incoming_xff && http::has_header(in_headers, "X-Forwarded-For") else {
        return append_forwarded_for(out_headers, "", client_ip);
    }
    var combined_buf: u8[..1024] = [];
    guard http::get_combined(in_headers, "X-Forwarded-For", combined_buf, 1024) else { return false; }
    return append_forwarded_for(out_headers, combined_buf[..], client_ip);
}

inline fn populate_forwarded_for_node(elem: http::ForwardedElement&, client_ip: const u8[:]) -> bool {
    // RFC 7239 Section 6: Node Identifiers - IPv6 addresses MUST be enclosed in square brackets.
    if client_ip.contains_byte(':') && !core::starts_with(client_ip, "[") {
        return elem.for_node.try_set("[") &&
            elem.for_node.try_append(client_ip) &&
            elem.for_node.try_push(']');
    }
    return elem.for_node.try_set(client_ip);
}

fn inject_forwarded_metadata(
    out_headers: http::HeaderMap&,
    in_headers:  const http::HeaderMap&,
    client_ip:   const u8[:],
    proto:       const u8[:],
    config:      const proxy::Config&,
) -> bool {
    guard append_forwarded_metadata_xff(
        out_headers,
        in_headers,
        client_ip,
        config.trust_incoming_xff,
    ) else { return false; }

    let orig_host = http::get_header(in_headers, "Host");
    if proto.len > 0 {
        guard http::append_header(out_headers, "X-Forwarded-Proto", proto) else { return false; }
    }
    let existing_xf_host = http::get_header(in_headers, "X-Forwarded-Host");
    if config.trust_incoming_xff && existing_xf_host.len > 0 {
        guard http::append_header(out_headers, "X-Forwarded-Host", existing_xf_host) else { return false; }
    } else if orig_host.len > 0 && !config.preserve_host {
        guard http::append_header(out_headers, "X-Forwarded-Host", orig_host) else { return false; }
    }
    if config.emit_rfc7239_forwarded {
        var elem = http::ForwardedElement { .. };
        guard elem.by.try_set(config.via_pseudonym[..]) else { return false; }
        guard populate_forwarded_for_node(elem, client_ip) else { return false; }
        guard elem.host.try_set(orig_host) else { return false; }
        guard elem.proto.try_set(proto) else { return false; }
        guard http::append_forwarded_header(out_headers, elem) else { return false; }
    }
    return true;
}

inline fn is_target_concurrency_saturated(target: const proxy::UpstreamTarget&, max_conns: i32) -> bool {
    guard max_conns > 0 else { return false; }
    return target.active_conns > max_conns;
}

// Formats upstream Host authority per RFC 9110 §7.2 and RFC 3986 §3.2.2,
// bracketing bare IPv6 literals and avoiding duplicate :port suffixes.
fn format_upstream_authority(host: const u8[:], port: u16, preserve_host: bool, out: u8[..128]&) -> bool {
    guard host.len > 0 && host.len <= 112 else { return false; }
    var committed = false;
    defer if !committed { out.clear(); };
    let _, after_colon, has_colon = host.split_once_byte(':');
    let is_bracketed = host[0] == '[';
    let is_bare_ipv6 = !is_bracketed && has_colon && after_colon.contains_byte(':');
    if is_bare_ipv6 {
        guard out.try_set("[") else { return false; }
        guard out.try_append(host) else { return false; }
        guard out.try_push(']') else { return false; }
    } else {
        guard out.try_set(host) else { return false; }
    }
    let has_port = if is_bracketed { core::find(host, "]:") >= 0 } else { has_colon && !is_bare_ipv6 };
    if !preserve_host && !has_port && port != 80 && port != 443 && port > 0 {
        guard out.try_append(":") else { return false; }
        port.format_u64_dec(out);
    }
    committed = true;
    return true;
}

fn ensure_forwarded_body_framing(
    forward_headers: http::HeaderMap&,
    body:            const u8[:],
    method:          const u8[:] = "",
) -> bool {
    let has_cl = http::has_header(forward_headers, "content-length");
    let has_te = http::has_header(forward_headers, "transfer-encoding");
    guard !(has_cl && has_te) else { return false; }
    if has_cl {
        let parsed_cl, ok_cl = http::validate_content_length_value(
            http::get_header(forward_headers, "content-length"),
        );
        guard ok_cl else { return false; }
        return parsed_cl == body.len;
    }
    if body.len == 0 {
        if method == "POST" || method == "PUT" || method == "PATCH" {
            return http::append_header(forward_headers, "Content-Length", "0");
        }
        return true;
    }
    var cl_buf: u8[..32] = [];
    body.len.format_i64_dec(cl_buf);
    return http::append_header(forward_headers, "Content-Length", cl_buf[..]);
}

// Enforces RFC 9110 Section 7.6.2 Max-Forwards hop decrement and zero-hop halt on TRACE and OPTIONS.
fn apply_max_forwards_policy(method: const u8[:], forward_headers: http::HeaderMap&) -> bool {
    guard method.eq_ascii_fold("TRACE") || method.eq_ascii_fold("OPTIONS") else {
        return true;
    }
    var found = false;
    var hops: u64 = 0;
    for &entry in forward_headers.entries {
        let name = http::entry_name(forward_headers, entry);
        if !name.eq_ascii_fold("max-forwards") {
            continue;
        }
        let val = http::entry_value(forward_headers, entry).trim_lws();
        let parsed, ok = val.parse_u64_dec();
        guard ok else { return false; }
        if !found {
            hops = parsed;
            found = true;
        } else {
            guard parsed == hops else { return false; }
        }
    }
    guard found else { return true; }
    // RFC 9110 Section 7.6.2: Max-Forwards - MUST NOT forward the request when Max-Forwards is zero.
    guard hops > 0 else { return false; }
    var mf_buf: u8[..24] = [];
    let next_hops = core::sub_sat_u64(hops, 1);
    next_hops.format_u64_dec(mf_buf);
    return http::set_or_replace(forward_headers, "Max-Forwards", mf_buf[..]);
}

inline fn transport_from_upstream_fd(fd: i32) -> net::Transport {
    let pipe_slot, is_b_end, is_virt = net::decode_virtual_pipe_fd(fd);
    if is_virt {
        return net::Transport.Virtual { pipe_slot: pipe_slot, is_b_end: is_b_end };
    }
    return net::Transport.Tcp { fd: fd };
}

fn acquire_or_dial_upstream_conn(
    pool:       net::StreamPool&,
    warm_pool:  net::UpstreamPool&,
    target:     const proxy::UpstreamTarget&,
    timeout_ms: u32,
    now_ns:     i64,
) -> i32, i32, bool {
    let pool_key = net::new_pool_key(
        net::PoolScheme.Http,
        target.host[..],
        target.port,
        net::new_direct_proxy_chain(),
        net::NetworkAnonymizationKey { .. },
        net::TlsAndDnsPolicy { .. },
    );
    let existing_cid, has_pooled = net::acquire_pooled_connection(pool, pool_key, "", now_ns);
    if has_pooled && existing_cid > 0 {
        return existing_cid, -1, true;
    }
    let warm_fd, has_warm = net::acquire_upstream_conn(warm_pool, pool_key.origin_endpoint, 0, 0);
    if has_warm && warm_fd >= 0 {
        let warm_t = transport_from_upstream_fd(warm_fd);
        let warm_cid = net::register_connection(
            pool, pool_key, net::NegotiatedProtocol.Http11, warm_t, "", 1, now_ns,
        );
        guard warm_cid > 0 else {
            let _ = net::release_upstream_conn(warm_pool, warm_fd, net::EPOLLRDHUP);
            return -1, -1, false;
        }
        return warm_cid, warm_fd, true;
    }
    let sock = net::tcp_connect(target.host[..], target.port, timeout_ms);
    guard sock > 0 else { return -1, -1, false; }
    var t = net::Transport.Tcp { fd: sock };
    let new_cid = net::register_connection(pool, pool_key, net::NegotiatedProtocol.Http11, t, "", 1, now_ns);
    guard new_cid > 0 else {
        t.close();
        return -1, -1, false;
    }
    return new_cid, -1, true;
}

inline fn finalize_proxy_upstream_conn(
    rp:        proxy::ReverseProxy&,
    pool:      net::StreamPool&,
    conn_id:   i32,
    c_idx:     i64,
    warm_fd:   i32,
    can_reuse: bool,
    now_ns:    i64,
) {
    if warm_fd >= 0 {
        pool.conns[c_idx].transport = net::Transport.Disconnected;
        pool.close_pooled_connection(conn_id);
        let ev: u32 = if can_reuse { 0 } else { net::EPOLLRDHUP };
        let _ = net::release_upstream_conn(rp.warm_upstreams, warm_fd, ev);
        return;
    }
    if can_reuse {
        pool.release_connection(conn_id, now_ns);
    } else {
        pool.close_pooled_connection(conn_id);
    }
}

fn read_and_parse_upstream_headers(
    conn:       net::PooledConnection&,
    out_resp:   http::Response&,
    timeout_ms: u32,
) -> i64, bool {
    let hdr_end_idx, ok_hdr = wing::read_response_headers(conn, timeout_ms);
    let rx = conn.rx_buf[..];
    let body_start = core::add_sat_i64(hdr_end_idx, 4);
    guard ok_hdr && hdr_end_idx >= 0 && body_start <= rx.len else { return -1, false; }
    guard wing::parse_response_headers(rx[..hdr_end_idx], out_resp) else { return -1, false; }
    return body_start, true;
}

enum HintCaptureMode {
    Ignore,
    Capture,
}

fn exchange_prepared_wire_impl(
    conn:            net::PooledConnection&,
    method:          const u8[:],
    wire_req:        const u8[:],
    out_resp:        http::Response&,
    out_early_hints: http::EarlyHintsResponse&,
    hint_mode:       HintCaptureMode,
    timeout_ms:      u32,
) -> proxy::WireReuse, bool {
    http::reset_response(out_resp);
    out_early_hints = http::EarlyHintsResponse { .. };
    guard wing::send_all(conn.transport, wire_req) else { return proxy::WireReuse.Close, false; }

    var dummy_req = http::new_request(method, "/");
    // RFC 9110 Section 15.2: Informational 1xx - cap consecutive 1xx interim responses to 5.
    for interim_step in 6 {
        guard interim_step < 5 else { return proxy::WireReuse.Close, false; }
        let leftover_start, ok_hdr = read_and_parse_upstream_headers(conn, out_resp, timeout_ms);
        let rx = conn.rx_buf[..];
        guard ok_hdr && leftover_start >= 0 && leftover_start <= rx.len else {
            return proxy::WireReuse.Close, false;
        }
        let sc = out_resp.status_code;
        let is_interim = sc >= 100 && sc < 200 && sc != 101;
        guard is_interim else {
            var leftover: u8[..8192] = [];
            guard leftover.try_set(rx[leftover_start..]) else { return proxy::WireReuse.Close, false; }
            conn.rx_buf.clear();
            let ok_body, keep_alive = wing::pump_response_body(
                conn, dummy_req, out_resp, leftover[..], timeout_ms,
            );
            let reuse = if keep_alive { proxy::WireReuse.KeepAlive } else { proxy::WireReuse.Close };
            return reuse, ok_body;
        }
        // RFC 9112 Section 6.3: Message Body Length - 1xx responses MUST NOT carry Transfer-Encoding or Content-Length.
        guard !out_resp.had_te_cl_conflict &&
            !http::has_header(out_resp.headers, "Transfer-Encoding") &&
            !http::has_header(out_resp.headers, "Content-Length") else {
            return proxy::WireReuse.Close, false;
        }
        if sc == 103 && hint_mode == HintCaptureMode.Capture {
            var up_tmp = proxy::UpstreamResponse { early_hints: out_early_hints, .. };
            proxy::capture_upstream_early_hints(out_resp, up_tmp);
            out_early_hints = up_tmp.early_hints;
        }
        conn.rx_buf.compact_wire_buffer(leftover_start);
    }
    return proxy::WireReuse.Close, false;
}

inline fn is_valid_accel_redirect_target(target: const u8[:]) -> bool {
    guard target.len > 0 && target[0] == '/' && !core::starts_with(target, "//") else {
        return false;
    }
    return wire::is_valid_h1_request_target(target);
}

inline fn matches_backend_url_prefix(url_val: const u8[:], backend_url_prefix: const u8[:]) -> bool {
    guard backend_url_prefix.len > 0 && url_val.len >= backend_url_prefix.len else {
        return false;
    }
    let scheme_idx = core::find(backend_url_prefix, "://");
    if scheme_idx >= 0 {
        let auth_start = core::add_sat_i64(scheme_idx, 3);
        guard backend_url_prefix.len > auth_start else { return false; }
        let slash_rel = backend_url_prefix[auth_start..].index_of_byte('/');
        if slash_rel >= 0 {
            let origin_len = core::add_sat_i64(auth_start, slash_rel);
            let origin_ok = url_val[..origin_len].eq_ascii_fold(backend_url_prefix[..origin_len]);
            let path_ok = core::starts_with(url_val[origin_len..], backend_url_prefix[origin_len..]);
            guard origin_ok && path_ok else { return false; }
        } else {
            guard url_val[..backend_url_prefix.len].eq_ascii_fold(backend_url_prefix) else {
                return false;
            }
        }
    } else {
        guard core::starts_with(url_val, backend_url_prefix) else { return false; }
    }

    if core::ends_with(backend_url_prefix, "/") {
        return true;
    }
    let rem = url_val[backend_url_prefix.len..];
    return rem.len == 0 || rem[0] == '/' || rem[0] == '?' || rem[0] == '#';
}

inline fn filter_single_upstream_response_header<B>(
    in_headers:          const http::HeaderMap&,
    entry_idx:           i64,
    backend_url_prefix:  const u8[:],
    public_url_prefix:   const u8[:],
    out_headers:         http::HeaderMap&,
    out_location_buf:    B&,
    accel:               proxy::UpstreamAccelControl&,
    first_loc_entry_idx: i64&,
) -> bool {
    let entry .= in_headers.entries[entry_idx];
    let name = http::entry_name(in_headers, entry);
    let val = http::entry_value(in_headers, entry);
    if name == ":status" {
        return true;
    }
    // RFC 9110 Section 5.1: Field Names - reject malformed or unstripped pseudo-headers in responses.
    guard http::is_valid_header_name(name) && http::is_valid_header_value(val) else { return false; }

    if name.starts_with_fold("x-accel-") {
        return proxy::parse_x_accel_control_header(name, val, accel);
    }
    if http::is_hop_by_hop_header_name(name) || http::is_token_in_connection_header_map(in_headers, name) {
        return true;
    }
    if name.eq_ascii_fold("content-length") {
        if !http::has_header(out_headers, "content-length") {
            return append_canonical_content_length(out_headers, name, val);
        }
        return true;
    }
    if name.eq_ascii_fold("location") {
        // RFC 9110 Section 10.2.2: Location - reject conflicting duplicate Location header fields.
        let clean_loc = val.trim_lws();
        if first_loc_entry_idx >= 0 {
            let prev_loc = http::entry_value(in_headers, in_headers.entries[first_loc_entry_idx]).trim_lws();
            return clean_loc == prev_loc;
        }
        first_loc_entry_idx = entry_idx;
        let rewritten, ok_loc = proxy::try_rewrite_upstream_url(
            clean_loc, backend_url_prefix, public_url_prefix, out_location_buf,
        );
        guard ok_loc else { return false; }
        return http::append_header(out_headers, name, rewritten);
    }
    if name.eq_ascii_fold("content-location") {
        // RFC 9110 Section 8.7: Content-Location - rewrite matching internal backend origin prefix.
        var cloc_buf: u8[..512] = [];
        let rewritten_cloc, ok_cloc = proxy::try_rewrite_upstream_url(
            val.trim_lws(), backend_url_prefix, public_url_prefix, cloc_buf,
        );
        guard ok_cloc else { return false; }
        return http::append_header(out_headers, name, rewritten_cloc);
    }
    return http::append_header(out_headers, name, val);
}
