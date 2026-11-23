// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Internal load-balancer, health-check, and upstream wire exchange helpers for package proxy.
namespace proxy_internal;

import std;
import core;
import http.headers;
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
    guard !target.draining else { return false; }
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

// Nginx smooth weighted round-robin: adds weight to wrr_current_weight for each routable target,
// picks the target with maximum current weight, and subtracts total routable weight.
fn select_weighted_rr(cluster: proxy::UpstreamCluster&, n: i32) -> i32, bool {
    var total_weight: i64 = 0;
    var best_idx:     i32 = NO_UPSTREAM_TARGET;
    var best_cw:      i32 = 0;

    for i in n {
        let t .= cluster.targets[i];
        guard is_target_selectable(t) else { continue; }
        let w = max(t.weight as i64, 1);
        let next_cw = core::add_sat_i64(t.wrr_current_weight, w) as i32;
        t.wrr_current_weight = next_cw;
        total_weight = core::add_sat_i64(total_weight, w);
        if best_idx == NO_UPSTREAM_TARGET || next_cw > best_cw {
            best_idx = i;
            best_cw = next_cw;
        }
    }
    guard best_idx >= 0 else { return NO_UPSTREAM_TARGET, false; }
    let chosen .= cluster.targets[best_idx];
    chosen.wrr_current_weight = core::sub_sat_i64(chosen.wrr_current_weight, total_weight) as i32;
    record_target_dispatch(chosen);
    return best_idx, true;
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
    cluster.circuit_open = !any_healthy;
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

// ---- Upstream Authority & Connection Exchange Helpers ---------------------

inline fn is_target_concurrency_saturated(target: const proxy::UpstreamTarget&, max_conns: i32) -> bool {
    guard max_conns > 0 else { return false; }
    return target.active_conns > max_conns;
}

// Formats upstream Host authority per RFC 9110 §7.2 and RFC 3986 §3.2.2,
// bracketing bare IPv6 literals and avoiding duplicate :port suffixes.
fn format_upstream_authority(host: const u8[:], port: u16, preserve_host: bool, out: u8[..160]&) -> bool {
    guard host.len > 0 && host.len <= 128 else { return false; }
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

fn read_and_parse_upstream_headers<B>(
    conn:       net::PooledConnection&,
    hdr_buf:    B&,
    out_resp:   http::Response&,
    timeout_ms: u32,
) -> i64, bool {
    let hdr_end_idx, ok_hdr = wing::read_response_headers_into(conn, hdr_buf, timeout_ms);
    let rx = hdr_buf[..];
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

    var hdr_buf: u8[..16384] = [];
    if conn.rx_buf.len > 0 {
        guard hdr_buf.try_append(conn.rx_buf[..]) else { return proxy::WireReuse.Close, false; }
        conn.rx_buf.clear();
    }

    var dummy_req = http::new_request(method, "/");
    // RFC 9110 Section 15.2: Informational 1xx - cap consecutive 1xx interim responses to 5.
    for interim_step in 6 {
        guard interim_step < 5 else { return proxy::WireReuse.Close, false; }
        let leftover_start, ok_hdr = read_and_parse_upstream_headers(conn, hdr_buf, out_resp, timeout_ms);
        let rx = hdr_buf[..];
        guard ok_hdr && leftover_start >= 0 && leftover_start <= rx.len else {
            return proxy::WireReuse.Close, false;
        }
        let sc = out_resp.status_code;
        let is_interim = sc >= 100 && sc < 200 && sc != 101;
        guard is_interim else {
            let ok_body, keep_alive = wing::pump_response_body(
                conn, dummy_req, out_resp, rx[leftover_start..], timeout_ms,
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
        hdr_buf.compact_wire_buffer(leftover_start);
    }
    return proxy::WireReuse.Close, false;
}
