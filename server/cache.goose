// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// server/cache.goose
// Coalescing High-Throughput HTTP Route Cache (uWebSockets HttpCache.h).
// Protects endpoints from thundering herds by caching rendered HTTP wire responses.
// Uses dual-expiry windows (lower_expiry_ms, upper_expiry_ms):
// - lower_expiry_ms: Freshness window; requests served instantly from cache.
// - upper_expiry_ms: Maximum staleness; served during background refresh to prevent herd spikes.
namespace wing;

import std;
import core from "..";

enum CacheLookup {
    HitFresh,
    HitStaleNeedsUpdate,
    Miss,
}

struct HttpRouteCache {
    created_ms:      u64         = 0,
    lower_expiry_ms: u64         = 1000,
    upper_expiry_ms: u64         = 5000,
    handler_id:      i32         = -1,
    content_type:    u8[..64]    = [],
    wire:            u8[..16384] = [],
    is_valid:        bool        = false,
    is_updating:     bool        = false,
}

fn new_http_route_cache(lower_expiry_ms: u64 = 1000, upper_expiry_ms: u64 = 5000) -> HttpRouteCache {
    return HttpRouteCache {
        lower_expiry_ms: lower_expiry_ms,
        upper_expiry_ms: upper_expiry_ms,
        created_ms:      0,
        handler_id:      -1,
        is_valid:        false,
        is_updating:     false,
        ..
    };
}

// Looks up cached wire response at time now_ms
fn cache_lookup(c: const HttpRouteCache&, now_ms: u64, handler_id: i32 = -1) -> CacheLookup {
    guard c.is_valid && c.wire.len > 0 else {
        return CacheLookup.Miss;
    }
    if handler_id >= 0 && c.handler_id >= 0 && c.handler_id != handler_id {
        return CacheLookup.Miss;
    }
    let age = if now_ms >= c.created_ms { now_ms - c.created_ms } else { 0 };
    if age <= c.lower_expiry_ms {
        return CacheLookup.HitFresh;
    }
    if age <= c.upper_expiry_ms {
        return CacheLookup.HitStaleNeedsUpdate;
    }
    return CacheLookup.Miss;
}

// Stores rendered wire bytes into cache
fn cache_store(
    c:            HttpRouteCache&,
    now_ms:       u64,
    wire_data:    const u8[:],
    handler_id:   i32         = -1,
    content_type: const u8[:] = "",
) -> bool {
    guard wire_data.len <= c.wire.cap && content_type.len <= c.content_type.cap else { return false; }
    c.wire.clear();
    c.wire.append(wire_data);
    c.content_type.clear();
    c.content_type.append(content_type);
    c.handler_id = handler_id;
    c.created_ms = now_ms;
    c.is_valid = true;
    c.is_updating = false;
    return true;
}

// Invalidates cache
fn cache_invalidate(c: HttpRouteCache&) {
    c.is_valid = false;
    c.wire.clear();
}
