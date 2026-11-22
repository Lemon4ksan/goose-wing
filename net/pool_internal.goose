// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Internal helpers for WantQueue, UpstreamPool, Happy Eyeballs, StreamPool, and Retry-After.
namespace net_internal;

import std;
import core;
import dns.svcb;
import cookie.psl;
import .want_queue;
import .proxy;
import .tcp;
import .transport;
import .pool;
import .upstream_pool;
import .happy_eyeballs;
import .retry;
import .internal;

// ---- WantQueue Helpers -----------------------------------------------------

inline fn compact_want_queue(q: net::WantQueue&) {
    var new_head: net::WantConn[..32] = [];
    if q.head_pos < q.head.len {
        for &item in q.head[q.head_pos..] {
            if !item.cancelled {
                new_head.push(copy(item));
            }
        }
    }
    var new_tail: net::WantConn[..32] = [];
    for &t_item in q.tail {
        if !t_item.cancelled {
            if new_head.len < 32 {
                new_head.push(copy(t_item));
            } else {
                new_tail.push(copy(t_item));
            }
        }
    }
    q.head = new_head;
    q.head_pos = 0;
    q.tail = new_tail;
}

// ---- UpstreamPool Helpers --------------------------------------------------

inline fn is_epoll_rdhup_signaled(events: u32) -> bool {
    return (events & net::EPOLLRDHUP) != 0;
}

inline fn matches_upstream_partition(
    entry:           const net::UpstreamConnEntry&,
    endpoint:        const net::OriginEndpoint&,
    tls_fingerprint: u64,
    nik:             u64,
) -> bool {
    return entry.nik == nik &&
           entry.tls_fingerprint == tls_fingerprint &&
           entry.endpoint.origin_endpoint_equals(endpoint);
}

inline fn close_upstream_entry_fd(entry: net::UpstreamConnEntry&) {
    if entry.fd >= 0 {
        if net::is_virtual_pipe_fd(entry.fd) {
            net::virtual_fd_close(entry.fd);
        } else {
            net::tcp_close(entry.fd);
        }
        entry.fd = -1;
    }
}

inline fn evict_upstream_rdhup(pool: net::UpstreamPool&, cur: net::UpstreamConnEntry&) {
    close_upstream_entry_fd(cur);
    cur.healthy = false;
    pool.evicted_rdhup = core::add_sat_u64(pool.evicted_rdhup, 1);
}

// ---- Happy Eyeballs Helpers ------------------------------------------------

fn populate_svcb_alpn_flags(rec: const dns::HttpsRecord&, meta: net::ConnectionEndpointMetadata&) {
    for &alpn_tok in rec.alpns {
        let tok = alpn_tok[..];
        if tok == "h3" || tok.starts_with("h3-") {
            meta.alpn_h3 = true;
        } else if tok == "h2" {
            meta.alpn_h2 = true;
        }
    }
}

fn populate_svcb_ip_hints(rec: const dns::HttpsRecord&, meta: net::ConnectionEndpointMetadata&) {
    var ip6_buf: u8[..64] = [];
    for &ip6 in rec.ipv6_hints {
        core::format_ipv6_bytes(ip6, ip6_buf);
        guard meta.ipv6_hints.try_push(ip6_buf) else { break; }
    }
    var ip4_buf: u8[..64] = [];
    for ip4 in rec.ipv4_hints {
        core::format_ipv4_u32(ip4, ip4_buf);
        guard meta.ipv4_hints.try_push(ip4_buf) else { break; }
    }
}

inline fn maybe_arm_last_resort_nat64(
    manager: net::AttemptManager&,
    cand:    const net::DnsCandidate&,
    now_ms:  i64,
) {
    guard manager.enable_nat64_synthesis && cand.family == net::AddressFamily.IPv6 && !manager.last_resort_armed else {
        return;
    }
    var has_more_ipv6 = false;
    for i in manager.current_attempt_idx..manager.pending_candidates.len {
        if manager.pending_candidates[i].family == net::AddressFamily.IPv6 {
            has_more_ipv6 = true;
            break;
        }
    }
    if !has_more_ipv6 {
        manager.last_resort_armed = true;
        manager.last_resort_deadline_ms = core::add_sat_i64(now_ms, rfc::HE_LAST_RESORT_SYNTHESIS_DELAY_MS);
    }
}

fn launch_next_candidate_attempt(manager: net::AttemptManager&, now_ms: i64) -> bool {
    guard manager.current_attempt_idx < manager.pending_candidates.len else { return false; }
    guard manager.attempts.len < 16 else { return false; }

    let cand = manager.pending_candidates[manager.current_attempt_idx];
    manager.current_attempt_idx = core::add_sat_i64(manager.current_attempt_idx, 1);

    let aid = manager.next_id;
    manager.next_id = core::add_sat_i64(aid, 1) as i32;

    var attempt = net::ConnectionAttempt {
        attempt_id:    aid,
        candidate:     copy(cand),
        start_time_ms: now_ms,
        state:         net::AttemptState.Connecting,
    };
    manager.attempts.push(attempt);

    manager.next_attempt_start_ms = core::add_sat_i64(now_ms, manager.effective_cad_ms);

    maybe_arm_last_resort_nat64(manager, cand, now_ms);

    return true;
}

fn synthesize_nat64_candidate(manager: net::AttemptManager&) {
    guard manager.pending_candidates.len < manager.pending_candidates.cap else { return; }
    var v4_ip:   u8[..256] = [];
    var v4_port: u16       = 443;
    var v4_proto = net::L4Protocol.Tcp;
    var v4_prec: i32 = 30;
    var found_v4 = false;

    for &c in manager.pending_candidates {
        if c.family == net::AddressFamily.IPv4 {
            v4_ip.append(c.ip[..]);
            v4_port = c.port;
            v4_proto = c.l4_proto;
            v4_prec = c.precedence;
            found_v4 = true;
            break;
        }
    }
    if !found_v4 {
        for &att in manager.attempts {
            if att.candidate.family == net::AddressFamily.IPv4 {
                v4_ip.append(att.candidate.ip[..]);
                v4_port = att.candidate.port;
                v4_proto = att.candidate.l4_proto;
                v4_prec = att.candidate.precedence;
                found_v4 = true;
                break;
            }
        }
    }
    var syn_ip: u8[..256] = [];
    if found_v4 {
        syn_ip.append("64:ff9b::");
        let _ = syn_ip.try_append(v4_ip[..]);
    } else {
        syn_ip.append("64:ff9b::192.0.2.1");
    }
    var nat64_cand = net::new_dns_candidate(
        net::AddressFamily.IPv6,
        syn_ip[..],
        v4_port,
        v4_proto,
        v4_prec,
    );
    let _ = manager.pending_candidates.try_push(nat64_cand);
}

// ---- StreamPool Helpers ----------------------------------------------------

inline fn set_canonical_host<B>(dst: B&, raw_host: const u8[:]) -> bool {
    guard dst.try_set(raw_host) else { return false; }
    to_lower(dst[..]);
    return true;
}

fn pool_scheme_to_u64(s: net::PoolScheme) -> u64 {
    return match s {
        Http => 1,
        Https => 2,
        Ws => 3,
        Wss => 4,
        H2c => 5,
    };
}

inline fn wyhash64_ascii_fold(data: const u8[:], seed: u64) -> u64 {
    var folded: u8[..256] = [];
    for b in data {
        guard folded.try_push(core::to_lower_ascii_byte(b)) else { break; }
    }
    return core::wyhash64(folded[..], seed);
}

inline fn has_empty_dns_label(name: const u8[:]) -> bool {
    if name.len == 0 || name.starts_with(".") || name.ends_with(".") {
        return true;
    }
    return core::contains(name, "..");
}

inline fn is_all_numeric_dot_host(host: const u8[:]) -> bool {
    var saw_digit = false;
    for b in host {
        if b == '.' {
            continue;
        }
        if !core::is_ascii_digit(b) {
            return false;
        }
        saw_digit = true;
    }
    return saw_digit;
}

fn find_closed_connection_slot(pool: const net::StreamPool&) -> i32 {
    for &c, idx in pool.conns {
        if c.closed {
            return idx as i32;
        }
    }
    return -1;
}

fn acquire_connection_slot(pool: net::StreamPool&, now_ns: i64) -> i32 {
    guard pool.conns.len >= 64 else { return -1; }
    let closed_idx = find_closed_connection_slot(pool);
    if closed_idx >= 0 {
        return closed_idx;
    }
    guard evict_oldest_idle_connection(pool, now_ns) else { return -2; }
    return find_closed_connection_slot(pool);
}

fn group_record_closed(pool: net::StreamPool&, key: const net::PoolKey&, active: bool) {
    let grp_idx = pool.find_group_index(key);
    guard grp_idx >= 0 else { return; }
    let grp .= pool.groups[grp_idx];
    if active {
        if grp.active_conns > 0 {
            grp.active_conns = core::sub_sat_i64(grp.active_conns, 1) as i32;
        }
    } else {
        if grp.idle_conns > 0 {
            grp.idle_conns = core::sub_sat_i64(grp.idle_conns, 1) as i32;
        }
    }
}

fn group_record_acquired(pool: net::StreamPool&, key: const net::PoolKey&) {
    let grp_idx = pool.find_group_index(key);
    guard grp_idx >= 0 else { return; }
    let grp .= pool.groups[grp_idx];
    grp.active_conns = core::add_sat_i64(grp.active_conns, 1) as i32;
    if grp.idle_conns > 0 {
        grp.idle_conns = core::sub_sat_i64(grp.idle_conns, 1) as i32;
    }
}

fn group_record_released(pool: net::StreamPool&, key: const net::PoolKey&) {
    let grp_idx = pool.find_group_index(key);
    guard grp_idx >= 0 else { return; }
    let grp .= pool.groups[grp_idx];
    if grp.active_conns > 0 {
        grp.active_conns = core::sub_sat_i64(grp.active_conns, 1) as i32;
    }
    grp.idle_conns = core::add_sat_i64(grp.idle_conns, 1) as i32;
}

fn evict_oldest_idle_connection(pool: net::StreamPool&, now_ns: i64) -> bool {
    var oldest_idx = -1;
    var oldest_idle_ns: i64 = 0;

    for &c, idx in pool.conns {
        if !c.closed && c.active_allocations == 0 {
            if oldest_idx == -1 || c.idle_at_ns < oldest_idle_ns {
                oldest_idx = idx as i32;
                oldest_idle_ns = c.idle_at_ns;
            }
        }
    }

    if oldest_idx >= 0 {
        let victim .= pool.conns[oldest_idx];
        group_record_closed(pool, victim.key, false);
        victim.transport.close();
        net::release_hpack_slot(victim);
        victim.rx_buf.clear();
        victim.closed = true;
        victim.no_new_exchanges = true;
        return true;
    }
    return false;
}

fn evict_oldest_idle_in_group(pool: net::StreamPool&, key: const net::PoolKey&) -> bool {
    var oldest_idx = -1;
    var oldest_idle_ns: i64 = 0;

    for &c, idx in pool.conns {
        if !c.closed && c.active_allocations == 0 && c.key.pool_key_equals(key) {
            if oldest_idx == -1 || c.idle_at_ns < oldest_idle_ns {
                oldest_idx = idx as i32;
                oldest_idle_ns = c.idle_at_ns;
            }
        }
    }

    guard oldest_idx >= 0 else { return false; }
    let victim .= pool.conns[oldest_idx];
    group_record_closed(pool, victim.key, false);
    victim.transport.close();
    net::release_hpack_slot(victim);
    victim.rx_buf.clear();
    victim.closed = true;
    victim.no_new_exchanges = true;
    return true;
}

fn count_proxy_chain_sockets(pool: const net::StreamPool&, proxy_chain: const net::ProxyChain&) -> i64, i64 {
    var active: i64 = 0;
    var idle:   i64 = 0;
    for &c in pool.conns {
        if !c.closed && c.key.proxy_chain.proxy_chain_equals(proxy_chain) {
            if c.active_allocations > 0 {
                active = core::add_sat_i64(active, 1);
            } else {
                idle = core::add_sat_i64(idle, 1);
            }
        }
    }
    return active, idle;
}

fn evict_oldest_idle_for_proxy(pool: net::StreamPool&, proxy_chain: const net::ProxyChain&) -> bool {
    var oldest_idx = -1;
    var oldest_idle_ns: i64 = 0;

    for &c, idx in pool.conns {
        if !c.closed && c.active_allocations == 0 && c.key.proxy_chain.proxy_chain_equals(proxy_chain) {
            if oldest_idx == -1 || c.idle_at_ns < oldest_idle_ns {
                oldest_idx = idx as i32;
                oldest_idle_ns = c.idle_at_ns;
            }
        }
    }

    guard oldest_idx >= 0 else { return false; }
    let victim .= pool.conns[oldest_idx];
    group_record_closed(pool, victim.key, false);
    victim.transport.close();
    net::release_hpack_slot(victim);
    victim.rx_buf.clear();
    victim.closed = true;
    victim.no_new_exchanges = true;
    return true;
}

fn count_host_sockets(pool: const net::StreamPool&, host: const u8[:]) -> i64, i64 {
    var active: i64 = 0;
    var idle:   i64 = 0;
    for &c in pool.conns {
        if !c.closed && c.key.origin_endpoint.host[..].eq_ascii_fold(host) {
            if c.active_allocations > 0 {
                active = core::add_sat_i64(active, 1);
            } else {
                idle = core::add_sat_i64(idle, 1);
            }
        }
    }
    return active, idle;
}

fn evict_oldest_idle_for_host(pool: net::StreamPool&, host: const u8[:]) -> bool {
    var oldest_idx = -1;
    var oldest_idle_ns: i64 = 0;

    for &c, idx in pool.conns {
        if !c.closed && c.active_allocations == 0 && c.key.origin_endpoint.host[..].eq_ascii_fold(host) {
            if oldest_idx == -1 || c.idle_at_ns < oldest_idle_ns {
                oldest_idx = idx as i32;
                oldest_idle_ns = c.idle_at_ns;
            }
        }
    }

    guard oldest_idx >= 0 else { return false; }
    let victim .= pool.conns[oldest_idx];
    group_record_closed(pool, victim.key, false);
    victim.transport.close();
    net::release_hpack_slot(victim);
    victim.rx_buf.clear();
    victim.closed = true;
    victim.no_new_exchanges = true;
    return true;
}

fn enforce_host_socket_quota(pool: net::StreamPool&, key: const net::PoolKey&) -> bool {
    guard pool.max_conns_per_host > 0 else { return true; }
    let cap = min(pool.max_conns_per_host, 64);
    let host = key.origin_endpoint.host[..];
    let h_active, h_idle = count_host_sockets(pool, host);
    let total_host = core::add_sat_i64(h_active, h_idle);
    guard total_host >= cap else { return true; }
    if h_idle > 0 {
        let _ = evict_oldest_idle_for_host(pool, host);
    }
    return h_active < cap;
}

fn enforce_group_socket_quota(pool: net::StreamPool&, key: const net::PoolKey&) -> bool {
    let grp_idx = pool.find_group_index(key);
    guard grp_idx >= 0 && pool.max_sockets_per_group > 0 else { return true; }
    let grp .= pool.groups[grp_idx];
    let total_grp = core::add_sat_i64(grp.active_conns, grp.idle_conns);
    guard total_grp >= pool.max_sockets_per_group else { return true; }
    if grp.idle_conns > 0 {
        let _ = evict_oldest_idle_in_group(pool, key);
    }
    return grp.active_conns < pool.max_sockets_per_group;
}

fn enforce_proxy_chain_socket_quota(pool: net::StreamPool&, key: const net::PoolKey&) -> bool {
    guard !key.proxy_chain.is_direct && pool.max_sockets_per_proxy > 0 else { return true; }
    let p_active, p_idle = count_proxy_chain_sockets(pool, key.proxy_chain);
    let total_proxy = core::add_sat_i64(p_active, p_idle);
    guard total_proxy >= pool.max_sockets_per_proxy else { return true; }
    if p_idle > 0 {
        let _ = evict_oldest_idle_for_proxy(pool, key.proxy_chain);
    }
    return p_active < pool.max_sockets_per_proxy;
}

inline fn mark_multiplexed_acquired(c: net::PooledConnection&) {
    c.active_allocations = core::add_sat_i64(c.active_allocations, 1) as i32;
    c.use_count = core::add_sat_i64(c.use_count, 1);
}

inline fn try_acquire_direct_conn(
    pool:                net::StreamPool&,
    c:                   net::PooledConnection&,
    key:                 const net::PoolKey&,
    now_ns:              i64,
    do_extensive_checks: bool,
) -> i32, bool {
    guard !c.closed && c.key.pool_key_equals(key) else { return -1, false; }
    let was_idle = c.active_allocations == 0;
    let is_h2_h3 = c.protocol == net::NegotiatedProtocol.Http2 || c.protocol == net::NegotiatedProtocol.Http3Quic;
    let has_capacity = if is_h2_h3 { c.active_allocations < c.max_concurrent_streams } else { was_idle };
    guard has_capacity else { return -1, false; }

    let healthy = c.is_connection_healthy(
        now_ns, do_extensive_checks, net::IDLE_CONNECTION_HEALTHY_NS, pool.idle_timeout_ns,
    );
    guard healthy else {
        if c.closed {
            group_record_closed(pool, c.key, !was_idle);
        }
        return -1, false;
    }

    mark_multiplexed_acquired(c);
    if was_idle {
        group_record_acquired(pool, c.key);
    }
    return c.conn_id, true;
}

inline fn try_acquire_coalesced_conn(
    pool:                net::StreamPool&,
    c:                   net::PooledConnection&,
    key:                 const net::PoolKey&,
    target_resolved_ip:  const u8[:],
    now_ns:              i64,
    do_extensive_checks: bool,
) -> i32, bool {
    guard !c.closed && c.active_allocations < c.max_concurrent_streams else { return -1, false; }
    let can_coalesce, is_negative = c.can_coalesce_h2_connection(key, target_resolved_ip);
    if is_negative {
        pool.negative_ip_pool_result_count = core::add_sat_i64(pool.negative_ip_pool_result_count, 1);
    }
    guard can_coalesce else { return -1, false; }
    let was_idle = c.active_allocations == 0;
    let healthy = c.is_connection_healthy(
        now_ns, do_extensive_checks, net::IDLE_CONNECTION_HEALTHY_NS, pool.idle_timeout_ns,
    );
    if !healthy {
        if c.closed {
            group_record_closed(pool, c.key, !was_idle);
        }
        return -1, false;
    }
    mark_multiplexed_acquired(c);
    if was_idle {
        group_record_acquired(pool, c.key);
    }
    return c.conn_id, true;
}

fn try_handoff_to_group_waiter(
    pool:       net::StreamPool&,
    c:          net::PooledConnection&,
    out_waiter: net::WantConn&,
) -> bool {
    guard !pool.disable_keepalive && !c.no_new_exchanges && !c.remote_rst && !c.source_exhausted else {
        return false;
    }
    let grp_idx = pool.find_group_index(c.key);
    guard grp_idx >= 0 && !pool.groups[grp_idx].wait_queue.is_queue_empty() else { return false; }
    let w_item, ok_w = pool.groups[grp_idx].wait_queue.pop_want();
    guard ok_w else { return false; }
    c.use_count = core::add_sat_i64(c.use_count, 1);
    out_waiter = w_item;
    out_waiter.ready = true;
    out_waiter.assigned_conn_id = c.conn_id;
    out_waiter.reused = true;
    return true;
}

fn finalize_idle_or_draining_conn(pool: net::StreamPool&, c: net::PooledConnection&, now_ns: i64) {
    if pool.disable_keepalive || c.no_new_exchanges || c.remote_rst || c.source_exhausted {
        group_record_closed(pool, c.key, true);
        c.transport.close();
        net::release_hpack_slot(c);
        c.rx_buf.clear();
        c.closed = true;
        c.no_new_exchanges = true;
        return;
    }
    c.idle_at_ns = now_ns;
    group_record_released(pool, c.key);
}

inline fn is_origin_group_unused(grp: const net::ConnectionGroup&) -> bool {
    return grp.active_conns <= 0 &&
           grp.idle_conns <= 0 &&
           grp.dials_in_progress <= 0 &&
           grp.wait_queue.is_queue_empty();
}

// ---- Retry-After Helpers ---------------------------------------------------

fn try_parse_retry_after_seconds(clean: const u8[:]) -> i64, bool {
    for ch in clean {
        guard core::is_ascii_digit(ch) else { return 0, false; }
    }
    let secs, ok_s = core::parse_digits(clean);
    guard ok_s && secs >= 0 else { return 0, false; }
    return core::retry_after_sec_to_ms_sat(secs), true;
}

fn try_parse_retry_after_http_date(clean: const u8[:], now_unix_ms: i64) -> i64, bool {
    let parsed_time, ok_t = core::parse_http_date(clean);
    guard ok_t else { return 0, false; }

    let target_unix_ms = parsed_time.unix_milli();
    if target_unix_ms <= now_unix_ms {
        return 0, true;
    }
    return core::sub_sat_i64(target_unix_ms, now_unix_ms), true;
}
