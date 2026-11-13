// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Server-side warm upstream connection pool with EPOLLRDHUP eviction.
namespace wing;

import std;
import core from "..";
import .pool;
import .tcp;

const EPOLLRDHUP: u32 = 0x2000;

// Maximum warm upstream connections in `UpstreamPool`.
const UPSTREAM_POOL_CAPACITY: i32 = 64;

// Warm upstream origin connection entry isolated by (endpoint, tls_fingerprint, nik: u64).
struct UpstreamConnEntry {
    fd:              i32            = -1,
    endpoint:        OriginEndpoint = OriginEndpoint { .. },
    tls_fingerprint: u64            = 0,
    nik:             u64            = 0,
    epoll_events:    u32            = 0,
    in_use:          bool           = false,
    healthy:         bool           = true,
}

// Zero-allocation upstream pool indexing up to 64 warm origin connections.
struct UpstreamPool {
    entries:       UpstreamConnEntry[..64] = [],
    evicted_rdhup: u64                     = 0,
}

inline fn is_epoll_rdhup_signaled(events: u32) -> bool {
    return (events & EPOLLRDHUP) != 0;
}

inline fn matches_upstream_partition(
    entry:           const UpstreamConnEntry&,
    endpoint:        const OriginEndpoint&,
    tls_fingerprint: u64,
    nik:             u64,
) -> bool {
    return entry.nik == nik &&
           entry.tls_fingerprint == tls_fingerprint &&
           entry.endpoint.origin_endpoint_equals(endpoint);
}

inline fn close_upstream_entry_fd(entry: UpstreamConnEntry&) {
    if entry.fd >= 0 {
        tcp_close(entry.fd);
        entry.fd = -1;
    }
}

// Registers a warm upstream connection into `UpstreamPool`, reusing evicted slots or appending up to 64.
// Fails closed with `false` if all 64 slots are active (Invariant 13).
fn register_upstream_conn(
    pool:            UpstreamPool&,
    fd:              i32,
    endpoint:        const OriginEndpoint&,
    tls_fingerprint: u64,
    nik:             u64,
) -> bool {
    guard fd >= 0 else { return false; }
    let entry = UpstreamConnEntry {
        fd:              fd,
        endpoint:        copy(endpoint),
        tls_fingerprint: tls_fingerprint,
        nik:             nik,
        epoll_events:    0,
        in_use:          false,
        healthy:         true,
    };
    for i in pool.entries.len {
        let cur .= pool.entries[i];
        if !cur.healthy && !cur.in_use {
            close_upstream_entry_fd(cur);
            cur = entry;
            return true;
        }
    }
    guard pool.entries.try_push(entry) else {
        return false;
    }
    return true;
}

inline fn evict_upstream_rdhup(pool: UpstreamPool&, cur: UpstreamConnEntry&) {
    close_upstream_entry_fd(cur);
    cur.healthy = false;
    pool.evicted_rdhup = core::add_sat_u64(pool.evicted_rdhup, 1);
}

// Signals epoll event flags (including EPOLLRDHUP = 0x2000) on an upstream socket descriptor.
// Immediately marks idle connections with EPOLLRDHUP as unhealthy and evicts them.
fn notify_upstream_epoll_events(pool: UpstreamPool&, fd: i32, events: u32) -> bool {
    var matched = false;
    for i in pool.entries.len {
        let cur .= pool.entries[i];
        guard cur.fd == fd && cur.healthy else { continue; }
        cur.epoll_events |= events;
        matched = true;
        if is_epoll_rdhup_signaled(cur.epoll_events) && !cur.in_use {
            evict_upstream_rdhup(pool, cur);
        }
    }
    return matched;
}

// Acquires a warm idle upstream connection matching `(endpoint, tls_fingerprint, nik)`.
// Evicts and skips any connection that has signaled `EPOLLRDHUP` (`0x2000`) while idle.
fn acquire_upstream_conn(
    pool:            UpstreamPool&,
    endpoint:        const OriginEndpoint&,
    tls_fingerprint: u64,
    nik:             u64,
) -> i32, bool {
    for i in pool.entries.len {
        let cur .= pool.entries[i];
        guard cur.healthy && !cur.in_use else { continue; }
        if is_epoll_rdhup_signaled(cur.epoll_events) {
            evict_upstream_rdhup(pool, cur);
            continue;
        }
        if matches_upstream_partition(cur, endpoint, tls_fingerprint, nik) {
            cur.in_use = true;
            return cur.fd, true;
        }
    }
    return -1, false;
}

// Releases an acquired upstream connection back to the idle pool if healthy.
fn release_upstream_conn(pool: UpstreamPool&, fd: i32, events: u32 = 0) -> bool {
    for i in pool.entries.len {
        let cur .= pool.entries[i];
        guard cur.fd == fd && cur.in_use else { continue; }
        cur.in_use = false;
        let effective_events = events | cur.epoll_events;
        cur.epoll_events = effective_events;
        if is_epoll_rdhup_signaled(effective_events) {
            evict_upstream_rdhup(pool, cur);
            return false;
        }
        return cur.healthy;
    }
    return false;
}
