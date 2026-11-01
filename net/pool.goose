// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Resilient connection pooling, 5-dimensional PoolKey partitioning,
// two-slice WantQueue, liveness health checks, and HTTP/2 IP coalescing.
namespace wing;

import std;
import core from "..";
import .proxy;

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
    host: u8[..256] = [],
    port: u16       = 80,
}

fn new_origin_endpoint(host_str: const u8[:], port_num: u16) -> OriginEndpoint {
    var ep = OriginEndpoint { port: port_num, .. };
    ep.host.append(host_str);
    to_lower(ep.host[..]);
    return ep;
}

fn origin_endpoint_equals(a: const OriginEndpoint&, b: const OriginEndpoint&) -> bool {
    return a.port == b.port && eq_ascii_fold(a.host[..], b.host[..]);
}

// Specification of a single proxy node.
struct ProxyServer {
    scheme: ProxyScheme = ProxyScheme.Direct,
    host:   u8[..256]   = [],
    port:   u16         = 0,
}

fn new_proxy_server(scheme_val: ProxyScheme, host_str: const u8[:], port_num: u16) -> ProxyServer {
    var ps = ProxyServer { scheme: scheme_val, port: port_num, .. };
    ps.host.append(host_str);
    to_lower(ps.host[..]);
    return ps;
}

fn proxy_server_equals(a: const ProxyServer&, b: const ProxyServer&) -> bool {
    return a.scheme == b.scheme && a.port == b.port && eq_ascii_fold(a.host[..], b.host[..]);
}

// Ordered proxy chain (direct or multi-hop forwarding route).
struct ProxyChain {
    servers:   ProxyServer[..4] = [],
    is_direct: bool             = true,
}

fn new_direct_proxy_chain() -> ProxyChain {
    return ProxyChain { is_direct: true, .. };
}

fn new_single_proxy_chain(ps: ProxyServer) -> ProxyChain {
    var pc = ProxyChain { is_direct: (ps.scheme == ProxyScheme.Direct), .. };
    pc.servers.push(ps);
    return pc;
}

fn proxy_chain_equals(a: const ProxyChain&, b: const ProxyChain&) -> bool {
    if a.is_direct != b.is_direct { return false; }
    if a.is_direct && b.is_direct { return true; }
    if a.servers.len != b.servers.len { return false; }
    for &s_a, i in a.servers {
        if !s_a.proxy_server_equals(b.servers[i]) { return false; }
    }
    return true;
}

// Network Anonymization Key (Chromium NAK / NIK parity) for cross-site partition isolation.
// All 4 components (top_frame_site, is_cross_site, nonce, network_isolation_partition)
// and optional worker_session_id must be compared to prevent cross-site side-channel leaks.
struct NetworkAnonymizationKey {
    top_frame_site:              u8[..128] = [],
    is_cross_site:               bool      = false,
    nonce:                       u64       = 0,
    network_isolation_partition: u32       = 0,
    worker_session_id:           u32       = 0,
}

fn new_network_anonymization_key(
    top_site:     const u8[:],
    cross_site:   bool = false,
    nonce_val:    u64  = 0,
    partition_id: u32  = 0,
    worker_id:    u32  = 0,
) -> NetworkAnonymizationKey {
    var nak = NetworkAnonymizationKey {
        is_cross_site:               cross_site,
        nonce:                       nonce_val,
        network_isolation_partition: partition_id,
        worker_session_id:           worker_id,
        ..
    };
    nak.top_frame_site.append(top_site);
    to_lower(nak.top_frame_site[..]);
    return nak;
}

fn network_anonymization_key_equals(a: const NetworkAnonymizationKey&, b: const NetworkAnonymizationKey&) -> bool {
    if a.nonce != b.nonce { return false; }
    if a.is_cross_site != b.is_cross_site { return false; }
    if a.network_isolation_partition != b.network_isolation_partition { return false; }
    if a.worker_session_id != b.worker_session_id { return false; }
    return eq_ascii_fold(a.top_frame_site[..], b.top_frame_site[..]);
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

fn pool_scheme_to_u64(s: PoolScheme) -> u64 {
    return match s {
        Http => 1,
        Https => 2,
        Ws => 3,
        Wss => 4,
        H2c => 5,
    };
}

// Computes 64-bit WyHash composite hash for PoolKey partitioning and socket grouping.
fn pool_key_hash(k: const PoolKey&) -> u64 {
    var h: u64 = core::wyhash64(k.origin_endpoint.host[..], k.origin_endpoint.port);
    h = core::hash_combine_u64(h, pool_scheme_to_u64(k.scheme));
    h = core::hash_combine_u64(h, k.proxy_chain.servers.len as u64);
    for &srv in k.proxy_chain.servers {
        let sh = core::wyhash64(srv.host[..], srv.port);
        h = core::hash_combine_u64(h, sh);
    }
    h = core::hash_combine_u64(h, k.partition_key.nonce);
    let part_h = core::wyhash64(k.partition_key.top_frame_site[..], k.partition_key.network_isolation_partition);
    h = core::hash_combine_u64(h, part_h);
    h = core::hash_combine_u64(h, k.tls_and_dns_policy.target_network_id);
    return h;
}

// ---- two-slice want_conn_queue (Go transport wantConnQueue parity) ------

struct WantConn {
    req_id:           u64     = 0,
    key:              PoolKey = PoolKey { .. },
    ready:            bool    = false,
    cancelled:        bool    = false,
    assigned_conn_id: i32     = -1,
    reused:           bool    = false,
    err_code:         i32     = 0,
}

// Zero-reallocation dual-slice queue avoiding shifts during frequent push/pop operations.
// Separates consumer (head, head_pos) and producer (tail) cache lines to prevent false sharing.
struct WantQueue {
    head:          WantConn[..32] = [],
    head_pos:      i64            = 0,
    _pad_consumer: u8[56]         = [0; 56],
    tail:          WantConn[..32] = [],
}

fn queue_len(q: const WantQueue&) -> i64 {
    let head_remaining = core::ct_max_i64(0, q.head.len - q.head_pos);
    return head_remaining + q.tail.len;
}

fn is_queue_empty(q: const WantQueue&) -> bool {
    return queue_len(q) == 0;
}

// Appends a connection requirement to the tail slice.
fn push_want(q: WantQueue&, item: WantConn) -> bool {
    if q.tail.len < 32 {
        q.tail.push(item);
        return true;
    }
    // If tail is full, try compacting head if it was drained
    if q.head_pos >= q.head.len {
        q.head.clear();
        for &t_item in q.tail {
            q.head.push(copy(t_item));
        }
        q.head_pos = 0;
        q.tail.clear();
        q.tail.push(item);
        return true;
    }
    return false;
}

// Pops the front item from the queue, promoting tail to head when head is exhausted.
fn pop_want(q: WantQueue&) -> WantConn, bool {
    while q.head_pos < q.head.len {
        let item = q.head[q.head_pos];
        q.head_pos++;
        if !item.cancelled {
            return item, true;
        }
    }

    if q.tail.len > 0 {
        q.head.clear();
        for &t_item in q.tail {
            q.head.push(copy(t_item));
        }
        q.head_pos = 0;
        q.tail.clear();

        while q.head_pos < q.head.len {
            let item = q.head[q.head_pos];
            q.head_pos++;
            if !item.cancelled {
                return item, true;
            }
        }
    }

    return WantConn { .. }, false;
}

// Cancels a waiter by request ID without shifting elements in the queue.
fn cancel_want(q: WantQueue&, req_id: u64) -> bool {
    for &item in q.head[q.head_pos..] {
        if item.req_id == req_id {
            item.cancelled = true;
            return true;
        }
    }
    for &item in q.tail {
        if item.req_id == req_id {
            item.cancelled = true;
            return true;
        }
    }
    return false;
}

// ---- pooled connection & liveness checks --------------------------------

enum NegotiatedProtocol {
    Http11,
    Http2,
    Http3Quic,
}

// Active or idle pooled TCP/TLS/QUIC connection representation.
struct PooledConnection {
    conn_id:                i32                = -1,
    key:                    PoolKey            = PoolKey { .. },
    protocol:               NegotiatedProtocol = NegotiatedProtocol.Http11,
    resolved_ip:            u8[..64]           = [],
    san_hosts:              u8[..128][..8]     = [],
    cert_valid:             bool               = true,
    active_allocations:     i32                = 0,
    max_concurrent_streams: i32                = 1,
    idle_at_ns:             i64                = 0,
    created_at_ns:          i64                = 0,
    use_count:              i64                = 0,
    source_exhausted:       bool               = false, // Simulates MSG_PEEK | MSG_DONTWAIT detection of EOF/FIN
    remote_rst:             bool               = false,
    no_new_exchanges:       bool               = false,
    closed:                 bool               = false,
}

let IDLE_CONNECTION_HEALTHY_NS:   i64 = 1000000000; // 1 second threshold for extensive checks
let DEFAULT_IDLE_CONN_TIMEOUT_NS: i64 = 90000000000; // 90 seconds
let DEFAULT_DIAL_TIMEOUT_NS:      i64 = 30000000000; // 30 seconds
let DEFAULT_KEEP_ALIVE_NS:        i64 = 30000000000; // 30 seconds

let DEFAULT_MAX_SOCKETS_PER_GROUP:       i32 = 6;
let DEFAULT_MAX_SOCKETS_PER_PROXY_CHAIN: i32 = 32;
let DEFAULT_SOCKET_SOFT_CAP_PER_POOL:    i32 = 256;

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

    let idle_duration_ns = core::ct_max_i64(0, now_ns - conn.idle_at_ns);

    if max_idle_ns > 0 && idle_duration_ns > max_idle_ns {
        conn.no_new_exchanges = true;
        conn.closed = true;
        return false;
    }

    if do_extensive_checks || idle_duration_ns >= healthy_threshold_ns {
        // Non-blocking check for received FIN (stream exhaustion)
        if conn.source_exhausted {
            conn.no_new_exchanges = true;
            conn.closed = true;
            return false;
        }
    }

    return true;
}

// Checks if a candidate host matches an active TLS Subject Alternative Name (SAN).
fn matches_san_pattern(pattern: const u8[:], target_host: const u8[:]) -> bool {
    // Reject candidate host containing wildcard '*'
    guard !core::contains_byte(target_host, '*') else { return false; }

    if eq_ascii_fold(pattern, target_host) {
        return true;
    }
    // Wildcard SAN check (*.example.com) per RFC 6125 §6.4.3
    if starts_with(pattern, "*.") && target_host.len > 2 {
        let suffix = pattern[2..];
        // Wildcards MUST NOT apply to top-level domains (*.com)
        guard core::contains_byte(suffix, '.') else { return false; }

        var dot_idx = -1;
        for i in target_host.len {
            if target_host[i] == '.' { dot_idx = i; break; }
        }
        if dot_idx > 0 {
            let host_suffix = target_host[dot_idx + 1..];
            return eq_ascii_fold(suffix, host_suffix);
        }
    }
    return false;
}

// HTTP/2 IP-based connection coalescing (JobController & AttemptManager parity).
// Reuses an existing HTTP/2 session to domain B if its resolved IP matches domain A,
// its TLS certificate covers domain B, and its partition key, privacy mode, and proxy match.
fn can_coalesce_h2_connection(
    conn:               const PooledConnection&,
    target_key:         const PoolKey&,
    target_resolved_ip: const u8[:],
) -> bool, bool {
    // Both must be HTTPS over HTTP/2
    guard conn.protocol == NegotiatedProtocol.Http2 &&
          conn.key.scheme == PoolScheme.Https &&
          target_key.scheme == PoolScheme.Https else {
        return false, false;
    }

    // IP addresses must match exactly
    guard conn.resolved_ip.len > 0 &&
          target_resolved_ip.len > 0 &&
          eq_ascii_fold(conn.resolved_ip[..], target_resolved_ip) else {
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

struct ConnectionGroup {
    key:               PoolKey   = PoolKey { .. },
    key_hash:          u64       = 0,
    active_conns:      i32       = 0,
    idle_conns:        i32       = 0,
    dials_in_progress: i32       = 0,
    wait_queue:        WantQueue = WantQueue { .. },
}

struct StreamPool {
    conns:                         PooledConnection[..64] = [],
    groups:                        ConnectionGroup[..32]  = [],
    max_sockets_per_group:         i32                    = DEFAULT_MAX_SOCKETS_PER_GROUP,
    max_sockets_per_proxy:         i32                    = DEFAULT_MAX_SOCKETS_PER_PROXY_CHAIN,
    socket_soft_cap:               i32                    = DEFAULT_SOCKET_SOFT_CAP_PER_POOL,
    idle_timeout_ns:               i64                    = DEFAULT_IDLE_CONN_TIMEOUT_NS,
    enable_ip_coalescing_h2:       bool                   = true,
    negative_ip_pool_result_count: i64                    = 0,
    next_conn_id:                  i32                    = 1,
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
    for &grp, idx in pool.groups {
        if grp.key_hash == kh && grp.key.pool_key_equals(key) {
            return idx as i32;
        }
    }
    return -1;
}

// Finds an existing connection group or creates a new one.
fn find_or_create_group(pool: StreamPool&, key: const PoolKey&) -> i32 {
    let idx = pool.find_group_index(key);
    if idx >= 0 {
        return idx;
    }
    let kh = pool_key_hash(key);
    if pool.groups.len < 32 {
        var grp = ConnectionGroup {
            key:        copy(key),
            key_hash:   kh,
            wait_queue: WantQueue { .. },
            ..
        };
        pool.groups.push(grp);
        return (pool.groups.len - 1) as i32;
    }
    return -1;
}

// Scans for a closed connection slot that can be reclaimed.
fn find_closed_connection_slot(pool: const StreamPool&) -> i32 {
    for &c, idx in pool.conns {
        if c.closed {
            return idx as i32;
        }
    }
    return -1;
}

// Reclaims an available or evicted connection slot, preventing capacity starvation (RFC 9110 §9.3.1).
fn acquire_connection_slot(pool: StreamPool&, now_ns: i64) -> i32 {
    guard pool.conns.len >= 64 else { return -1; }
    let closed_idx = find_closed_connection_slot(pool);
    if closed_idx >= 0 {
        return closed_idx;
    }
    guard pool.evict_oldest_idle_connection(now_ns) else { return -2; }
    return find_closed_connection_slot(pool);
}

fn group_record_closed(pool: StreamPool&, key: const PoolKey&, active: bool) {
    let grp_idx = pool.find_group_index(key);
    guard grp_idx >= 0 else { return; }
    if active {
        if pool.groups[grp_idx].active_conns > 0 { pool.groups[grp_idx].active_conns--; }
    } else {
        if pool.groups[grp_idx].idle_conns > 0 { pool.groups[grp_idx].idle_conns--; }
    }
}

fn group_record_acquired(pool: StreamPool&, key: const PoolKey&) {
    let grp_idx = pool.find_group_index(key);
    guard grp_idx >= 0 else { return; }
    pool.groups[grp_idx].active_conns++;
    if pool.groups[grp_idx].idle_conns > 0 { pool.groups[grp_idx].idle_conns--; }
}

fn group_record_released(pool: StreamPool&, key: const PoolKey&) {
    let grp_idx = pool.find_group_index(key);
    guard grp_idx >= 0 else { return; }
    if pool.groups[grp_idx].active_conns > 0 { pool.groups[grp_idx].active_conns--; }
    pool.groups[grp_idx].idle_conns++;
}

// Marks a pooled connection as closed, freeing it for slot reclamation.
fn close_pooled_connection(pool: StreamPool&, conn_id: i32) -> bool {
    for &c in pool.conns {
        if c.conn_id == conn_id && !c.closed {
            group_record_closed(pool, c.key, c.active_allocations > 0);
            c.closed = true;
            c.no_new_exchanges = true;
            c.active_allocations = 0;
            return true;
        }
    }
    return false;
}

// Evicts the oldest idle connection in the pool when soft cap is reached.
fn evict_oldest_idle_connection(pool: StreamPool&, now_ns: i64) -> bool {
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
        group_record_closed(pool, pool.conns[oldest_idx].key, false);
        pool.conns[oldest_idx].closed = true;
        pool.conns[oldest_idx].no_new_exchanges = true;
        return true;
    }
    return false;
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
    for &c in pool.conns {
        guard !c.closed && c.key.pool_key_equals(key) else { continue; }
        let is_h2_h3 = c.protocol == NegotiatedProtocol.Http2 || c.protocol == NegotiatedProtocol.Http3Quic;
        if is_h2_h3 {
            guard c.active_allocations < c.max_concurrent_streams else { continue; }
            let healthy = c.is_connection_healthy(
                now_ns, do_extensive_checks, IDLE_CONNECTION_HEALTHY_NS, pool.idle_timeout_ns,
            );
            guard healthy else { continue; }
            c.active_allocations++;
            c.use_count++;
            return c.conn_id, true;
        }

        guard c.active_allocations == 0 else { continue; }
        let healthy = c.is_connection_healthy(
            now_ns, do_extensive_checks, IDLE_CONNECTION_HEALTHY_NS, pool.idle_timeout_ns,
        );
        guard healthy else { continue; }
        c.active_allocations = 1;
        c.use_count++;
        group_record_acquired(pool, c.key);
        return c.conn_id, true;
    }

    // 2. HTTP/2 IP coalescing match across origins
    if pool.enable_ip_coalescing_h2 && key.scheme == PoolScheme.Https && target_resolved_ip.len > 0 {
        for &c in pool.conns {
            guard !c.closed && c.active_allocations < c.max_concurrent_streams else { continue; }
            let can_coalesce, is_negative = c.can_coalesce_h2_connection(key, target_resolved_ip);
            if is_negative {
                pool.negative_ip_pool_result_count++;
            }
            guard can_coalesce else { continue; }
            let healthy = c.is_connection_healthy(
                now_ns, do_extensive_checks, IDLE_CONNECTION_HEALTHY_NS, pool.idle_timeout_ns,
            );
            guard healthy else { continue; }
            c.active_allocations++;
            c.use_count++;
            return c.conn_id, true;
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
    if respect_limits == RespectLimits.Enabled && pool.conns.len >= pool.socket_soft_cap {
        pool.evict_oldest_idle_connection(now_ns);
    }

    let slot_idx = acquire_connection_slot(pool, now_ns);
    guard slot_idx != -2 else { return -1; }

    let cid = pool.next_conn_id;
    pool.next_conn_id++;

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
    conn.resolved_ip.append(resolved_ip);

    if slot_idx >= 0 {
        pool.conns[slot_idx] = conn;
    } else {
        pool.conns.push(conn);
    }

    let grp_idx = pool.find_or_create_group(key);
    if grp_idx >= 0 {
        pool.groups[grp_idx].active_conns++;
    }

    return cid;
}

// Releases an active allocation back to the pool, transitioning to idle when count reaches 0.
fn release_connection(pool: StreamPool&, conn_id: i32, now_ns: i64) -> bool {
    for &c in pool.conns {
        if c.conn_id == conn_id {
            if c.active_allocations > 0 {
                c.active_allocations--;
            }
            if c.active_allocations == 0 {
                c.idle_at_ns = now_ns;
                group_record_released(pool, c.key);
            }
            return true;
        }
    }
    return false;
}
