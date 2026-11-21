// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Resilient connection pooling, 5-dimensional PoolKey partitioning,
// two-slice WantQueue, liveness health checks, and HTTP/2 IP coalescing.
namespace net;

import std;
import core from "..";
import .isolation;
import .want_queue;
import .proxy;
import .transport;
import .udp;
import .internal;
import http2.hpack;
import cookie.psl;

// ---- pool key dimensions & enums ----------------------------------------

// Transport scheme classification for connection grouping.
enum PoolScheme {
    Http,
    Https,
    Ws,
    Wss,
    H2c,
}

// Returns whether the scheme requires cryptographic TLS transport.
fn is_cryptographic_scheme(scheme_val: PoolScheme) -> bool {
    return scheme_val == PoolScheme.Https || scheme_val == PoolScheme.Wss;
}

// Normalizes WebSocket schemes to their underlying HTTP counterparts for preconnect.
fn normalize_preconnect_scheme(scheme_val: PoolScheme) -> PoolScheme {
    return match scheme_val {
        Ws => PoolScheme.Http,
        Wss => PoolScheme.Https,
        _ => scheme_val,
    };
}

// Target origin endpoint (canonical host and TCP/UDP port).
struct OriginEndpoint {
    host:       u8[..256] = [],
    port:       u16       = 80,
    overflowed: bool      = false,
}

fn new_origin_endpoint(host_str: const u8[:], port_num: u16) -> OriginEndpoint {
    var ep = OriginEndpoint { port: port_num, .. };
    if !net_internal::set_canonical_host(ep.host, host_str) {
        ep.overflowed = true;
    }
    return ep;
}

fn origin_endpoint_equals(a: const OriginEndpoint&, b: const OriginEndpoint&) -> bool {
    guard !a.overflowed && !b.overflowed else { return false; }
    return a.port == b.port && a.host[..].eq_ascii_fold(b.host[..]);
}

// Client privacy mode governing client certificates and credential isolation.
enum PrivacyMode {
    Disabled,
    Enabled,
    EnabledWithoutClientCerts,
    EnabledPartitionedStateAllowed,
}

// DNS-over-HTTPS (DoH) security mode.
enum SecureDnsPolicy {
    Allow,
    Disable,
    Bootstrap,
}

// TLS and DNS security policies affecting connection compatibility.
struct TlsAndDnsPolicy {
    privacy_mode:                 PrivacyMode     = PrivacyMode.Disabled,
    secure_dns_policy:            SecureDnsPolicy = SecureDnsPolicy.Allow,
    disable_cert_network_fetches: bool            = false,
    target_network_id:            u64             = 0,
}

fn tls_and_dns_policy_equals(a: const TlsAndDnsPolicy&, b: const TlsAndDnsPolicy&) -> bool {
    return a.privacy_mode == b.privacy_mode &&
           a.secure_dns_policy == b.secure_dns_policy &&
           a.disable_cert_network_fetches == b.disable_cert_network_fetches &&
           a.target_network_id == b.target_network_id;
}

// 5-dimensional composite key isolating sockets in the connection pool.
struct PoolKey {
    scheme:             PoolScheme              = PoolScheme.Http,
    origin_endpoint:    OriginEndpoint          = OriginEndpoint { .. },
    proxy_chain:        ProxyChain              = ProxyChain { .. },
    partition_key:      NetworkAnonymizationKey = NetworkAnonymizationKey { .. },
    tls_and_dns_policy: TlsAndDnsPolicy         = TlsAndDnsPolicy { .. },
}

fn new_pool_key(
    scheme_val:    PoolScheme,
    host_str:      const u8[:],
    port_num:      u16,
    proxy_val:     ProxyChain,
    partition_val: NetworkAnonymizationKey,
    policy_val:    TlsAndDnsPolicy,
) -> PoolKey {
    return PoolKey {
        scheme:             scheme_val,
        origin_endpoint:    new_origin_endpoint(host_str, port_num),
        proxy_chain:        proxy_val,
        partition_key:      partition_val,
        tls_and_dns_policy: policy_val,
    };
}

fn pool_key_equals(a: const PoolKey&, b: const PoolKey&) -> bool {
    if a.scheme != b.scheme { return false; }
    if !a.origin_endpoint.origin_endpoint_equals(b.origin_endpoint) { return false; }
    if !a.proxy_chain.proxy_chain_equals(b.proxy_chain) { return false; }
    if !a.partition_key.network_anonymization_key_equals(b.partition_key) { return false; }
    if !a.tls_and_dns_policy.tls_and_dns_policy_equals(b.tls_and_dns_policy) { return false; }
    return true;
}

// Computes 64-bit WyHash composite hash for PoolKey partitioning and socket grouping.
fn pool_key_hash(k: const PoolKey&) -> u64 {
    var h: u64 = net_internal::wyhash64_ascii_fold(k.origin_endpoint.host[..], k.origin_endpoint.port);
    h = core::hash_combine_u64(h, net_internal::pool_scheme_to_u64(k.scheme));
    h = core::hash_combine_u64(h, k.proxy_chain.servers.len as u64);
    for &srv in k.proxy_chain.servers {
        let sh = net_internal::wyhash64_ascii_fold(srv.host[..], srv.port);
        h = core::hash_combine_u64(h, sh);
    }
    h = core::hash_combine_u64(h, k.partition_key.nonce);
    let part_h = net_internal::wyhash64_ascii_fold(
        k.partition_key.top_frame_site[..],
        k.partition_key.network_isolation_partition,
    );
    h = core::hash_combine_u64(h, part_h);
    h = core::hash_combine_u64(h, k.tls_and_dns_policy.target_network_id);
    return h;
}

// ---- pooled connection & liveness checks --------------------------------

enum NegotiatedProtocol {
    Http11,
    Http2,
    Http3Quic,
}

// Active or idle pooled TCP/TLS/QUIC connection representation.
struct PooledConnection {
    conn_id:                i32                 = -1,
    key:                    PoolKey             = PoolKey { .. },
    protocol:               NegotiatedProtocol  = NegotiatedProtocol.Http11,
    transport:              Transport           = Transport.Disconnected,
    rx_buf:                 u8[..8192]          = [],
    resolved_ip:            u8[..64]            = [],
    san_hosts:              u8[..128][..8]      = [],
    cert_valid:             bool                = true,
    active_allocations:     i32                 = 0,
    max_concurrent_streams: i32                 = 1,
    idle_at_ns:             i64                 = 0,
    created_at_ns:          i64                 = 0,
    use_count:              i64                 = 0,
    source_exhausted:       bool                = false, // Simulates MSG_PEEK | MSG_DONTWAIT detection of EOF/FIN
    remote_rst:             bool                = false,
    no_new_exchanges:       bool                = false,
    closed:                 bool                = false,
    hpack_enc:              http2::DynamicTable = http2::new_dynamic_table(4096),
    hpack_dec:              http2::DynamicTable = http2::new_dynamic_table(4096),
    next_h2_stream_id:      u32                 = 1,
    h2_preface_sent:        bool                = false,
}

const IDLE_CONNECTION_HEALTHY_NS:   i64 = 1000000000; // 1 second threshold for extensive checks
const DEFAULT_IDLE_CONN_TIMEOUT_NS: i64 = 90000000000; // 90 seconds
const DEFAULT_DIAL_TIMEOUT_NS:      i64 = 30000000000; // 30 seconds
const DEFAULT_KEEP_ALIVE_NS:        i64 = 30000000000; // 30 seconds

const DEFAULT_MAX_SOCKETS_PER_GROUP:       i32 = 6;
const DEFAULT_MAX_SOCKETS_PER_PROXY_CHAIN: i32 = 32;
const DEFAULT_SOCKET_SOFT_CAP_PER_POOL:    i32 = 256;

// OkHttp RealConnection.isHealthy parity: validates whether an idle or active socket
// is still alive, performing non-blocking peek when idle duration exceeds threshold.
fn is_connection_healthy(
    conn:                 PooledConnection&,
    now_ns:               i64,
    do_extensive_checks:  bool = false,
    healthy_threshold_ns: i64  = IDLE_CONNECTION_HEALTHY_NS,
    max_idle_ns:          i64  = DEFAULT_IDLE_CONN_TIMEOUT_NS,
) -> bool {
    if conn.closed || conn.no_new_exchanges || conn.remote_rst {
        return false;
    }

    // Active multiplexed streams on HTTP/2 or QUIC remain healthy while active
    if conn.active_allocations > 0 {
        return true;
    }

    let idle_duration_ns = core::ct_max_i64(0, core::sub_sat_i64(now_ns, conn.idle_at_ns));

    if max_idle_ns > 0 && idle_duration_ns > max_idle_ns {
        conn.transport.close();
        conn.rx_buf.clear();
        conn.no_new_exchanges = true;
        conn.closed = true;
        return false;
    }

    if do_extensive_checks || idle_duration_ns >= healthy_threshold_ns {
        // Non-blocking check for received FIN (stream exhaustion)
        if conn.source_exhausted {
            conn.transport.close();
            conn.rx_buf.clear();
            conn.no_new_exchanges = true;
            conn.closed = true;
            return false;
        }
    }

    return true;
}

// Checks if a candidate host matches an active TLS Subject Alternative Name (SAN).
fn matches_san_pattern(pattern: const u8[:], target_host: const u8[:]) -> bool {
    // RFC 6125 Section 6.4.3: Checking of Wildcard Certificates - SAN DNSName MUST NOT end with trailing dot
    guard pattern.len > 0 && !pattern.ends_with(".") else { return false; }
    let host = if target_host.len > 1 && target_host.ends_with(".") {
        target_host[..core::sub_sat_i64(target_host.len, 1)]
    } else {
        target_host
    };
    guard !host.contains_byte('*') &&
          !net_internal::has_empty_dns_label(host) &&
          !net_internal::has_empty_dns_label(pattern) else {
        return false;
    }

    if pattern.eq_ascii_fold(host) {
        return true;
    }
    // RFC 6125 Section 1.7.2: Out of Scope - wildcards MUST NOT match IPv4 or IPv6 literals
    guard pattern.starts_with("*.") &&
          !host.contains_byte(':') &&
          !net_internal::is_all_numeric_dot_host(host) else {
        return false;
    }
    let suffix = pattern[2..];
    guard !suffix.contains_byte('*') && suffix.contains_byte('.') && !cookie::is_public_suffix(suffix) else {
        return false;
    }
    let label, host_suffix, has_dot = host.split_once_byte('.');
    let _, tld, _ = host.rsplit_once_byte('.');
    let _, is_numeric_tld = core::parse_digits(tld);
    guard has_dot && label.len > 0 && !is_numeric_tld else {
        return false;
    }
    return suffix.eq_ascii_fold(host_suffix);
}

// HTTP/2 IP-based connection coalescing (JobController & AttemptManager parity).
// Reuses an existing HTTP/2 session to domain B if its resolved IP matches domain A,
// its TLS certificate covers domain B, and its partition key, privacy mode, and proxy match.
fn can_coalesce_h2_connection(
    conn:               const PooledConnection&,
    target_key:         const PoolKey&,
    target_resolved_ip: const u8[:],
) -> bool, bool {
    // Both must be HTTPS over HTTP/2 on the same authoritative port (RFC 9113 §9.1.1)
    guard conn.protocol == NegotiatedProtocol.Http2 &&
          conn.key.scheme == PoolScheme.Https &&
          target_key.scheme == PoolScheme.Https &&
          conn.key.origin_endpoint.port == target_key.origin_endpoint.port else {
        return false, false;
    }

    // IP addresses must match exactly
    guard conn.resolved_ip.len > 0 &&
          target_resolved_ip.len > 0 &&
          conn.resolved_ip[..].eq_ascii_fold(target_resolved_ip) else {
        return false, false;
    }

    // Partition key, proxy chain, and privacy mode must match 100%
    guard conn.key.partition_key.network_anonymization_key_equals(target_key.partition_key) &&
          conn.key.proxy_chain.proxy_chain_equals(target_key.proxy_chain) &&
          conn.key.tls_and_dns_policy.tls_and_dns_policy_equals(target_key.tls_and_dns_policy) else {
        return false, false;
    }

    // Certificate must be valid and cover the target hostname
    guard conn.cert_valid else { return false, true; }

    let target_host = target_key.origin_endpoint.host[..];
    for &san in conn.san_hosts {
        if matches_san_pattern(san[..], target_host) {
            return true, false;
        }
    }

    // IP matched but certificate or SAN did not cover the new origin
    return false, true;
}

// ---- stream pool and connection group management ------------------------

enum RespectLimits {
    Enabled,
    Disabled,
}

enum ProbeGateState {
    Unprobed,
    Probing { probe_conn_id: i32 },
    ResolvedHttp11,
    ResolvedHttp2,
}

struct ConnectionGroup {
    key:               PoolKey        = PoolKey { .. },
    key_hash:          u64            = 0,
    active_conns:      i32            = 0,
    idle_conns:        i32            = 0,
    dials_in_progress: i32            = 0,
    probe_gate:        ProbeGateState = ProbeGateState.Unprobed,
    wait_queue:        WantQueue      = WantQueue { .. },
}

struct StreamPool {
    conns:                         PooledConnection[..64]    = [],
    groups:                        ConnectionGroup[..32]     = [],
    group_index:                   core::FlatIndexBucket[64] = [core::FlatIndexBucket { .. }; 64],
    max_sockets_per_group:         i32                       = DEFAULT_MAX_SOCKETS_PER_GROUP,
    max_sockets_per_proxy:         i32                       = DEFAULT_MAX_SOCKETS_PER_PROXY_CHAIN,
    socket_soft_cap:               i32                       = DEFAULT_SOCKET_SOFT_CAP_PER_POOL,
    idle_timeout_ns:               i64                       = DEFAULT_IDLE_CONN_TIMEOUT_NS,
    enable_ip_coalescing_h2:       bool                      = true,
    negative_ip_pool_result_count: i64                       = 0,
    next_conn_id:                  i32                       = 1,
}

fn new_stream_pool(
    max_per_group: i32 = DEFAULT_MAX_SOCKETS_PER_GROUP,
    max_per_proxy: i32 = DEFAULT_MAX_SOCKETS_PER_PROXY_CHAIN,
    soft_cap:      i32 = DEFAULT_SOCKET_SOFT_CAP_PER_POOL,
) -> StreamPool {
    return StreamPool {
        max_sockets_per_group: max_per_group,
        max_sockets_per_proxy: max_per_proxy,
        socket_soft_cap:       soft_cap,
        ..
    };
}

// Finds an existing connection group by key.
fn find_group_index(pool: const StreamPool&, key: const PoolKey&) -> i32 {
    let kh = pool_key_hash(key);
    let res = core::flat_index_get(pool.group_index[..], kh);
    if res.found && res.slot_idx >= 0 && res.slot_idx < pool.groups.len {
        if pool.groups[res.slot_idx].key.pool_key_equals(key) {
            return res.slot_idx;
        }
    }
    for &grp, idx in pool.groups {
        if grp.key_hash == kh && grp.key.pool_key_equals(key) {
            return idx as i32;
        }
    }
    return -1;
}

// Finds an existing connection group or creates a new one using single-pass GetOrPut.
fn find_or_create_group(pool: StreamPool&, key: const PoolKey&) -> i32 {
    let kh = pool_key_hash(key);
    let probe = core::flat_index_get_or_put(pool.group_index[..], kh);
    if probe.found {
        if probe.slot_idx >= 0 && probe.slot_idx < pool.groups.len {
            if pool.groups[probe.slot_idx].key.pool_key_equals(key) {
                return probe.slot_idx;
            }
        }
        for &grp, idx in pool.groups {
            if grp.key_hash == kh && grp.key.pool_key_equals(key) {
                return idx as i32;
            }
        }
    }
    let grp = ConnectionGroup {
        key:        copy(key),
        key_hash:   kh,
        wait_queue: WantQueue { .. },
        ..
    };
    guard pool.groups.try_push(grp) else { return -1; }
    let new_idx = core::sub_sat_i64(pool.groups.len, 1);
    if !probe.found && probe.bucket_idx >= 0 {
        let _, _ = core::flat_index_commit_put(pool.group_index[..], probe.bucket_idx, kh, new_idx as u16);
    }
    return new_idx as i32;
}

// Marks a pooled connection as closed, freeing it for slot reclamation.
fn close_pooled_connection(pool: StreamPool&, conn_id: i32) -> bool {
    for &c in pool.conns {
        if c.conn_id == conn_id && !c.closed {
            net_internal::group_record_closed(pool, c.key, c.active_allocations > 0);
            c.transport.close();
            c.rx_buf.clear();
            c.closed = true;
            c.no_new_exchanges = true;
            c.active_allocations = 0;
            return true;
        }
    }
    return false;
}

// Verifies per-group (`max_sockets_per_group`) and per-proxy (`max_sockets_per_proxy`) limits,
// evicting idle sockets in the group or proxy chain before rejecting saturated active groups.
fn can_allocate_group_socket(
    pool:           StreamPool&,
    key:            const PoolKey&,
    respect_limits: RespectLimits = RespectLimits.Enabled,
) -> bool {
    guard respect_limits == RespectLimits.Enabled else { return true; }
    guard net_internal::enforce_group_socket_quota(pool, key) else { return false; }
    return net_internal::enforce_proxy_chain_socket_quota(pool, key);
}

// Closes and evicts all connections from the stream pool, resetting buffers.
fn drain_stream_pool(pool: StreamPool&) {
    for i in pool.conns.len {
        let c .= pool.conns[i];
        if !c.closed {
            net_internal::group_record_closed(pool, c.key, c.active_allocations > 0);
            c.transport.close();
            c.rx_buf.clear();
            c.closed = true;
            c.no_new_exchanges = true;
            c.active_allocations = 0;
        }
    }
}

// OkHttp RealRoutePlanner priority rule: always prefer reusing an already-bound
// or pooled healthy connection over launching delayed/new connection plans.
fn acquire_pooled_connection(
    pool:                StreamPool&,
    key:                 const PoolKey&,
    target_resolved_ip:  const u8[:],
    now_ns:              i64,
    do_extensive_checks: bool = false,
) -> i32, bool {
    // 1. Direct pool match for exact key
    for i in pool.conns.len {
        let cid, ok = net_internal::try_acquire_direct_conn(pool, pool.conns[i], key, now_ns, do_extensive_checks);
        if ok {
            return cid, true;
        }
    }

    // 2. HTTP/2 IP coalescing match across origins
    if pool.enable_ip_coalescing_h2 && key.scheme == PoolScheme.Https && target_resolved_ip.len > 0 {
        for i in pool.conns.len {
            let cid, ok = net_internal::try_acquire_coalesced_conn(
                pool, pool.conns[i], key, target_resolved_ip, now_ns, do_extensive_checks,
            );
            if ok {
                return cid, true;
            }
        }
    }

    return -1, false;
}

// Inserts a newly dialed connection into the pool after quota and soft-cap checks.
// Reclaims closed or evicted slots when pool reaches capacity, preventing starvation (RFC 9110 §9.3.1).
fn register_connection(
    pool:           StreamPool&,
    key:            const PoolKey&,
    proto:          NegotiatedProtocol,
    resolved_ip:    const u8[:],
    max_streams:    i32,
    now_ns:         i64,
    respect_limits: RespectLimits = RespectLimits.Enabled,
) -> i32 {
    guard resolved_ip.len <= 64 else { return -1; }
    guard pool.find_group_index(key) >= 0 || pool.groups.len < pool.groups.cap else { return -1; }
    guard can_allocate_group_socket(pool, key, respect_limits) else { return -1; }
    if respect_limits == RespectLimits.Enabled && pool.conns.len >= pool.socket_soft_cap {
        let _ = net_internal::evict_oldest_idle_connection(pool, now_ns);
    }

    let slot_idx = net_internal::acquire_connection_slot(pool, now_ns);
    guard slot_idx != -2 else { return -1; }

    let grp_idx = pool.find_or_create_group(key);
    guard grp_idx >= 0 else { return -1; }

    let cid = pool.next_conn_id;
    pool.next_conn_id = core::add_sat_i64(cid, 1) as i32;

    var conn = PooledConnection {
        conn_id:                cid,
        key:                    copy(key),
        protocol:               proto,
        max_concurrent_streams: max_streams,
        active_allocations:     1,
        idle_at_ns:             0,
        created_at_ns:          now_ns,
        use_count:              1,
        cert_valid:             true,
        ..
    };
    guard conn.resolved_ip.try_append(resolved_ip) else { return -1; }

    if slot_idx >= 0 {
        pool.conns[slot_idx] = conn;
    } else {
        pool.conns.push(conn);
    }

    pool.groups[grp_idx].active_conns = core::add_sat_i64(pool.groups[grp_idx].active_conns, 1) as i32;
    return cid;
}

// Finds the index of an active pooled connection by ID.
fn find_connection_index(pool: const StreamPool&, conn_id: i32) -> i32 {
    for &c, idx in pool.conns {
        if c.conn_id == conn_id && !c.closed {
            return idx as i32;
        }
    }
    return -1;
}

// Registers a newly established transport into the pool.
fn register_connection(
    pool:           StreamPool&,
    key:            const PoolKey&,
    proto:          NegotiatedProtocol,
    t:              Transport,
    resolved_ip:    const u8[:],
    max_streams:    i32,
    now_ns:         i64,
    respect_limits: RespectLimits = RespectLimits.Enabled,
) -> i32 {
    let cid = register_connection(pool, key, proto, resolved_ip, max_streams, now_ns, respect_limits);
    let idx = if cid > 0 { pool.find_connection_index(cid) } else { -1 };
    if idx >= 0 {
        let conn .= pool.conns[idx];
        conn.transport = t;
        match t {
            Tls tl => tls::copy_slot_san_hosts(tl.cipher_slot, conn.san_hosts),
            _ => {},
        };
        return cid;
    }
    var t_cleanup = t;
    t_cleanup.close();
    return cid;
}

// Enqueues a waiter into the ConnectionGroup's `WantQueue` when per-group socket limits are reached.
fn enqueue_group_waiter(pool: StreamPool&, key: const PoolKey&, req_id: u64) -> bool {
    let grp_idx = pool.find_or_create_group(key);
    guard grp_idx >= 0 else { return false; }
    let w = WantConn {
        req_id:           req_id,
        ready:            false,
        cancelled:        false,
        assigned_conn_id: -1,
        reused:           false,
        err_code:         0,
    };
    return pool.groups[grp_idx].wait_queue.push_want(w);
}

// Releases an active allocation back to the pool, or immediately hands the connection off
// to the next queued `WantConn` waiter in the group if one is pending.
fn release_connection_or_handoff(
    pool:       StreamPool&,
    conn_id:    i32,
    now_ns:     i64,
    out_waiter: WantConn&,
) -> bool, bool {
    for &c in pool.conns {
        if c.conn_id == conn_id && !c.closed {
            guard c.active_allocations > 0 else { return false, false; }
            out_waiter = WantConn { .. };
            if net_internal::try_handoff_to_group_waiter(pool, c, out_waiter) {
                return true, true;
            }
            c.active_allocations = core::sub_sat_i64(c.active_allocations, 1) as i32;
            if c.active_allocations == 0 {
                net_internal::finalize_idle_or_draining_conn(pool, c, now_ns);
            }
            return true, false;
        }
    }
    return false, false;
}

// Releases an active allocation back to the pool, transitioning to idle when count reaches 0.
fn release_connection(pool: StreamPool&, conn_id: i32, now_ns: i64) -> bool {
    var dummy_waiter = WantConn { .. };
    let ok_rel, _ = release_connection_or_handoff(pool, conn_id, now_ns, dummy_waiter);
    return ok_rel;
}

// ---- HTTPS ALPN Probe Gate & Connection Lifecycle Guards -------------------

// Evaluates whether a new parallel dial to an HTTPS origin should wait in `WantQueue`
// until the first TLS + ALPN handshake resolves `h2` vs `http/1.1`.
fn should_hold_for_alpn_probe(
    scheme:            PoolScheme,
    allow_h2:          bool,
    gate:              ProbeGateState,
    dials_in_progress: i32,
) -> bool {
    guard allow_h2 && is_cryptographic_scheme(scheme) else { return false; }
    return match gate {
        Probing _ => dials_in_progress > 0,
        _ => false,
    };
}

// Updates `ProbeGateState` when a probe connection finishes TLS handshake or fails.
fn settle_alpn_probe(
    gate:       ProbeGateState&,
    conn_id:    i32,
    succeeded:  bool,
    negotiated: NegotiatedProtocol,
) {
    let is_current_probe = match gate {
        Probing p => p.probe_conn_id == conn_id,
        _ => false,
    };
    guard is_current_probe else { return; }
    if !succeeded {
        gate = ProbeGateState.Unprobed;
        return;
    }
    gate = match negotiated {
        Http2 => ProbeGateState.ResolvedHttp2,
        _ => ProbeGateState.ResolvedHttp11,
    };
}

struct ConnLifecyclePolicy {
    max_requests_per_conn: i64 = 0,
    max_conn_ttl_ns:       i64 = 0,
    max_pipelining:        i32 = 1,
}

enum H1RequestSafety {
    SafeIdempotent,
    NonIdempotent,
    UpgradeOrConnect,
    StreamingUnrewindableBody,
}

// RFC 9112 Section 9.3.2: Pipelining - only idempotent requests may be pipelined over HTTP/1.1.
fn can_dispatch_on_h1_conn(
    active_allocations: i32,
    policy:             const ConnLifecyclePolicy&,
    safety:             H1RequestSafety,
) -> bool {
    let limit = max(policy.max_pipelining, 1);
    guard active_allocations < limit else { return false; }
    if active_allocations <= 0 {
        return true;
    }
    return safety == H1RequestSafety.SafeIdempotent;
}

// Evaluates whether a connection reached its request cap or age ceiling and should retire.
fn should_retire_connection(
    use_count:     i64,
    created_at_ns: i64,
    now_ns:        i64,
    policy:        const ConnLifecyclePolicy&,
) -> bool {
    if policy.max_requests_per_conn > 0 && use_count >= policy.max_requests_per_conn {
        return true;
    }
    if policy.max_conn_ttl_ns > 0 {
        let age_ns = core::sub_sat_i64(now_ns, created_at_ns);
        if age_ns >= policy.max_conn_ttl_ns {
            return true;
        }
    }
    return false;
}

// Evicts unused ConnectionGroup entries (zero active/idle/dialing sockets and empty WantQueue)
// so multi-origin dispatchers do not exhaust the fixed group table ceiling.
fn reclaim_idle_origin_groups(pool: StreamPool&) -> i32 {
    var kept:      ConnectionGroup[..32] = [];
    var reclaimed: i64                   = 0;
    for &grp in pool.groups {
        if net_internal::is_origin_group_unused(grp) {
            reclaimed = core::add_sat_i64(reclaimed, 1);
        } else {
            let _ = kept.try_push(copy(grp));
        }
    }
    if reclaimed > 0 {
        pool.groups = kept;
        core::flat_index_clear(pool.group_index[..]);
        for &g, gi in pool.groups {
            let gp = core::flat_index_get_or_put(pool.group_index[..], g.key_hash);
            if !gp.found && gp.bucket_idx >= 0 {
                let _, _ = core::flat_index_commit_put(pool.group_index[..], gp.bucket_idx, g.key_hash, gi as u16);
            }
        }
    }
    return reclaimed as i32;
}
