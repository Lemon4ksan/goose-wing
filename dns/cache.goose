// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Deterministic zero-allocation DNS cache with TTL and Stale-While-Revalidate (RFC 1035 & RFC 5861).
// Backed by an intrusive doubly-linked LRU list over a bounded 16-entry array.
namespace dns;

import std;
import core;
import .svcb;
import .internal;

// ---- DNS Cache with TTL and Stale-While-Revalidate (RFC 1035 & RFC 5861) -

enum CacheStatus {
    Fresh,   // Within TTL
    Stale,   // Expired past TTL, but within stale-while-revalidate window
    Expired, // Beyond stale window or not found
}

struct CacheEntry {
    domain:          u8[..255]        = [],
    qtype:           u16              = rfc::DNS_QTYPE_A,
    ipv4_hints:      u32[..8]         = [],
    ipv6_hints:      u8[16][..8]      = [],
    https_records:   HttpsRecord[..2] = [],
    inserted_at_sec: i64              = 0,
    ttl_sec:         u32              = 300,
    stale_ttl_sec:   u32              = 86400, // 24-hour max stale grace period
    valid:           bool             = false,
    lru_prev:        i32              = -1,
    lru_next:        i32              = -1,
}

struct Cache {
    entries:  CacheEntry[..16] = [],
    lru_head: i32              = -1,
    lru_tail: i32              = -1,
}

// Looks up a cached entry by domain and query type, returning a zero-copy reference and status.
fn lookup(
    cache:   const Cache&,
    domain:  const u8[:],
    qtype:   u16,
    now_sec: i64,
) -> const CacheEntry?, CacheStatus {
    guard domain.len > 0 && domain.len <= 255 else { return null, CacheStatus.Expired; }
    for &e in cache.entries {
        guard e.valid && e.qtype == qtype && e.domain.len == domain.len else { continue; }
        guard e.domain[..].eq_ascii_fold(domain) else { continue; }
        guard e.ttl_sec > 0 && now_sec >= e.inserted_at_sec else { return null, CacheStatus.Expired; }
        let elapsed = core::sub_sat_i64(now_sec, e.inserted_at_sec);
        let ttl_i64: i64 = e.ttl_sec;
        if elapsed < ttl_i64 {
            return e, CacheStatus.Fresh;
        }
        let total_ttl_i64 = core::add_sat_i64(ttl_i64, e.stale_ttl_sec);
        if elapsed < total_ttl_i64 {
            return e, CacheStatus.Stale;
        }
        return null, CacheStatus.Expired;
    }
    return null, CacheStatus.Expired;
}

// Inserts or refreshes a DNS cache entry, updating LRU recency or evicting the oldest entry.
fn insert(cache: Cache&, entry: const CacheEntry&) {
    for &cur, i in cache.entries {
        let is_match = cur.valid &&
            cur.qtype == entry.qtype &&
            cur.domain.len == entry.domain.len &&
            cur.domain[..].eq_ascii_fold(entry.domain[..]);
        if is_match {
            // RFC 1035 Section 4.1.3: Resource record format - zero TTL prohibits caching
            if entry.ttl_sec == 0 {
                dns_internal::detach_lru(cache, i as i32);
                cur.valid = false;
                return;
            }
            let prev = cur.lru_prev;
            let next = cur.lru_next;
            cur = entry;
            cur.valid = true;
            cur.lru_prev = prev;
            cur.lru_next = next;
            dns_internal::touch_lru(cache, i as i32);
            return;
        }
    }
    guard entry.ttl_sec > 0 else { return; }

    for &e, i in cache.entries {
        if !e.valid {
            dns_internal::place_entry_at_tail(cache, i as i32, entry);
            return;
        }
    }

    let new_idx = cache.entries.len as i32;
    if cache.entries.try_push(entry) {
        dns_internal::init_slot_at_tail(cache, new_idx);
        return;
    }

    let victim_idx: i32 = if cache.lru_head >= 0 && cache.lru_head < cache.entries.len {
        cache.lru_head
    } else {
        0
    };
    dns_internal::detach_lru(cache, victim_idx);
    dns_internal::place_entry_at_tail(cache, victim_idx, entry);
}
