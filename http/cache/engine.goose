// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// RFC 9111: HTTP Caching engine, transaction state machine, and storage coordinator.
// Implements lookup, freshness evaluation, conditional revalidation, 304 header merge,
// cascade invalidation for unsafe methods, single-flight request collapsing, and O(1) LRU eviction.
namespace http;

import std;
import core from "../..";
import http.request;
import http.response;
import http.headers;
import http.novarysearch;
import http.cache.cache_control;
import http.cache.freshness;
import http.cache.validators;
import http.cache.cache_groups;
import http.targeted_cache;
import http.status_diagnostics;
import http.cache.internal;

// ---- cache options ---------------------------------------------------------

// Configuration options governing cache storage limits, heuristics, and sharing mode.
struct CacheOptions {
    shared:                bool     = false,
    cache_private:         bool     = false,
    heuristic_fraction:    i64      = 10,
    immutable_min_ttl_sec: i64      = 31536000,
    ignore_cargo_cult:     bool     = true,
    max_entry_size:        i64      = 4096,
    target_name:           u8[..48] = [],
}

// Constructs CacheOptions with RFC 9111 baseline defaults.
// ---- cached entry model ----------------------------------------------------

// Cached HTTP representation including headers, body, Vary invariants, and intrusive LRU pointers.
struct CachedEntry {
    url_hash:          u32             = 0,
    url:               u8[..2048]      = [],
    method:            u8[..16]        = "GET",
    status_code:       i32             = 200,
    headers:           HeaderMap       = HeaderMap { .. },
    cc:                CacheControl    = CacheControl { .. },
    etag:              EntityTag       = EntityTag { .. },
    last_modified_sec: i64             = 0,
    timestamps:        CacheTimestamps = CacheTimestamps { .. },
    vary:              VarySnapshot    = VarySnapshot { .. },
    nvs:               NoVarySearch    = NoVarySearch { .. },
    body:              u8[..4096]      = [],
    head_only:         bool            = false,
    security_zeroed:   bool            = false,
    is_valid:          bool            = false,
    prev_lru:          i32             = -1,
    next_lru:          i32             = -1,
}

// ---- lookup and response decisions -----------------------------------------

// Classification of cache lookup outcome.
enum LookupResultKind {
    Hit,
    Revalidate,
    Miss,
    Fail504,
}

// Result of a cache lookup operation.
struct LookupDecision {
    kind:                     LookupResultKind = LookupResultKind.Miss,
    entry_idx:                i64              = -1,
    conditional_headers:      HeaderMap        = HeaderMap { .. },
    status_code:              i32              = 0,
    revalidate_in_background: bool             = false,
    cached_response:          Response         = Response { .. },
}

// Classification of on_response cache action.
enum ResponseDecisionKind {
    StoreAndReturn,
    FreshenAndReturn,
    PassThrough,
}

// Result of evaluating a network response against caching policies.
struct ResponseDecision {
    kind:      ResponseDecisionKind = ResponseDecisionKind.PassThrough,
    entry_idx: i64                  = -1,
    response:  Response             = Response { .. },
}

// ---- writers / single-flight request collapsing ----------------------------

enum CacheLockStatus {
    Idle,
    Waiting,
    Done,
    TransientError,
    GiveUp,
    AgeTimeout,
}

struct WriterSlot {
    key_hash:       u64             = 0,
    active:         bool            = false,
    acquired_at_ms: i64             = 0,
    age_timeout_ms: i64             = 10000,
    status:         CacheLockStatus = CacheLockStatus.Idle,
    stale_writer:   bool            = false,
}

struct CacheWriterFlight {
    key:          u8[..256] = [],
    is_active:    bool      = false,
    waiter_count: i32       = 0,
    total_bytes:  i64       = 0,
    completed:    bool      = false,
    aborted:      bool      = false,
}

// Single-flight coordinator for concurrent network transactions (Chromium & Pingora parity).
struct CacheWriters {
    flights: CacheWriterFlight[..16] = [],
    slots:   WriterSlot[..64]        = [],
    group:   core::SingleflightGroup = core::SingleflightGroup { .. },
}

// Registers or joins an in-flight network transaction for key.
// Returns (flight_idx, is_leader). Leader executes network fetch; joiner shares result.
fn start_writer_or_join(writers: CacheWriters&, key: const u8[:]) -> i64, bool {
    for &flight, idx in writers.flights {
        if flight.is_active && flight.key[..] == key {
            flight.waiter_count++;
            return idx, false;
        }
    }

    // Reuse any inactive slot without shifting existing flight indices
    for &flight, idx in writers.flights {
        if !flight.is_active {
            guard flight.key.try_set(key) else { return -1, false; }
            flight.is_active = true;
            flight.waiter_count = 0;
            flight.total_bytes = 0;
            flight.completed = false;
            flight.aborted = false;
            return idx, true;
        }
    }

    guard writers.flights.len < writers.flights.cap else { return -1, true; }

    var flight = CacheWriterFlight {
        is_active:    true,
        waiter_count: 0,
        total_bytes:  0,
        completed:    false,
        aborted:      false,
        ..
    };
    guard flight.key.try_set(key) else { return -1, false; }
    writers.flights.push(flight);
    return writers.flights.len - 1, true;
}

// Marks the in-flight writer transaction as successfully completed and frees its slot.
fn finish_writer(writers: CacheWriters&, flight_idx: i64) {
    guard flight_idx >= 0 && flight_idx < writers.flights.len else { return; }
    writers.flights[flight_idx].completed = true;
    writers.flights[flight_idx].is_active = false;
}

// Marks the in-flight writer transaction as aborted and frees its slot.
fn abort_writer(writers: CacheWriters&, flight_idx: i64) {
    guard flight_idx >= 0 && flight_idx < writers.flights.len else { return; }
    writers.flights[flight_idx].aborted = true;
    writers.flights[flight_idx].is_active = false;
}

// Acquires a cache stampede write lock for `hash` at `now_ms` with `age_timeout_ms` expiration.
// Preempts any expired `Waiting` lock (`now_ms - acquired_at_ms >= age_timeout_ms`) or `GiveUp` slot.
fn acquire_at(writers: CacheWriters&, hash: u64, now_ms: i64, age_timeout_ms: i64) -> bool {
    let eff_timeout = if age_timeout_ms > 0 { age_timeout_ms } else { 10000 };
    for &slot in writers.slots {
        if slot.key_hash == hash {
            return http_internal::try_acquire_matching_slot(slot, now_ms, eff_timeout);
        }
    }
    for &slot in writers.slots {
        if !slot.active {
            slot.key_hash = hash;
            slot.active = true;
            slot.acquired_at_ms = now_ms;
            slot.age_timeout_ms = eff_timeout;
            slot.status = CacheLockStatus.Waiting;
            slot.stale_writer = false;
            return true;
        }
    }
    return writers.slots.try_push(WriterSlot {
        key_hash:       hash,
        active:         true,
        acquired_at_ms: now_ms,
        age_timeout_ms: eff_timeout,
        status:         CacheLockStatus.Waiting,
        stale_writer:   false,
    });
}

// Acquires a cache stampede write lock for `hash` with default age timeout.
fn acquire(writers: CacheWriters&, hash: u64) -> bool {
    return writers.acquire_at(hash, 0, 10000);
}

// Releases a cache stampede write lock for `hash` and records terminal `status` (`Done`, `GiveUp`, etc.).
fn release_with_status(writers: CacheWriters&, hash: u64, status: CacheLockStatus) {
    for &slot in writers.slots {
        if slot.key_hash == hash {
            slot.active = false;
            slot.status = status;
            return;
        }
    }
}

// ---- http cache engine container -------------------------------------------

// HTTP cache coordinator with intrusive O(1) LRU list.
struct Cache {
    options:             CacheOptions      = CacheOptions { .. },
    entries:             CachedEntry[..16] = [],
    writers:             CacheWriters      = CacheWriters { .. },
    lru_head:            i32               = -1,
    lru_tail:            i32               = -1,
    total_hits:          i64               = 0,
    total_misses:        i64               = 0,
    total_revalidations: i64               = 0,
    total_stores:        i64               = 0,
    total_invalidations: i64               = 0,
}

// Checks whether target_url (which may be relative) shares origin with base_url (RFC 9111 §4.4).
fn is_same_origin_url(target_url: const u8[:], base_url_raw: const u8[:]) -> bool {
    let parsed_base, err_base = core::parse_url(base_url_raw);
    guard err_base == core::UrlParseError.None && parsed_base.valid else { return false; }
    let parsed_target, err_target = core::parse_url_with_base(target_url, parsed_base);
    guard err_target == core::UrlParseError.None && parsed_target.valid else { return false; }
    let orig_base = core::origin_from_url(parsed_base);
    let orig_target = core::origin_from_url(parsed_target);
    return core::is_same_origin(orig_base, orig_target);
}

// ---- lookup logic (rfc 9111 section 4) -------------------------------------

// Builds conditional request headers (If-None-Match and If-Modified-Since) for revalidation.
fn build_revalidation_headers(entry: const CachedEntry&) -> HeaderMap {
    var cond = HeaderMap { .. };
    if entry.etag.valid {
        var etag_buf: u8[..160] = [];
        if entry.etag.is_weak { etag_buf.append("W/"); }
        etag_buf.push('"');
        etag_buf.append(entry.etag.tag[..]);
        etag_buf.push('"');
        cond.append_header("If-None-Match", etag_buf[..]);
    }
    let lm_raw = entry.headers.get_header("last-modified");
    if lm_raw.len > 0 {
        cond.append_header("If-Modified-Since", lm_raw);
    }
    return cond;
}

// Performs cache lookup for an incoming request (RFC 9111 Section 4).
// Evaluates freshness, Vary matching, and returns Hit, Revalidate, Miss, or Fail504.
fn lookup(
    cache:       Cache&,
    req:         const Request&,
    cur_now_sec: i64,
    cur_mono_ns: u64 = 0,
) -> LookupDecision {
    var dec = LookupDecision { .. };

    let is_get = req.method[..].eq_ascii_fold("GET");
    let is_head = req.method[..].eq_ascii_fold("HEAD");
    guard is_get || is_head else {
        cache.total_misses = core::add_sat_i64(cache.total_misses, 1);
        dec.kind = LookupResultKind.Miss;
        return dec;
    }

    let req_cc = parse_cache_control_headers(
        req.headers,
        CacheControlParseOptions { is_request: true, ignore_cargo_cult: cache.options.ignore_cargo_cult },
    );

    if req_cc.is_no_store() {
        cache.total_misses = core::add_sat_i64(cache.total_misses, 1);
        dec.kind = LookupResultKind.Miss;
        return dec;
    }

    let req_hash = http_internal::hash_fnv1a(req.url[..]);
    let matched_idx = http_internal::find_matching_entry(cache.entries[..], req.url[..], req_hash, req.headers, is_get);

    if matched_idx < 0 {
        cache.total_misses = core::add_sat_i64(cache.total_misses, 1);
        if req_cc.is_only_if_cached() {
            dec.kind = LookupResultKind.Fail504;
            dec.status_code = 504;
            return dec;
        }
        let _, _ = cache.writers.start_writer_or_join(req.url[..]);
        let _ = cache.writers.acquire(req_hash);
        dec.kind = LookupResultKind.Miss;
        return dec;
    }

    // Touch LRU on access
    http_internal::lru_touch(cache, matched_idx);

    let matched_entry .= cache.entries[matched_idx];
    let eval_dec = http_internal::evaluate_matched_cache_entry(
        matched_entry,
        cache.options,
        req,
        req_cc,
        matched_idx,
        cur_now_sec,
        cur_mono_ns,
    );
    if eval_dec.kind == LookupResultKind.Hit {
        cache.total_hits = core::add_sat_i64(cache.total_hits, 1);
    } else if eval_dec.kind == LookupResultKind.Revalidate {
        cache.total_revalidations = core::add_sat_i64(cache.total_revalidations, 1);
        let _, _ = cache.writers.start_writer_or_join(req.url[..]);
        let _ = cache.writers.acquire(req_hash);
    } else {
        cache.total_misses = core::add_sat_i64(cache.total_misses, 1);
    }
    return eval_dec;
}

// ---- on_response helpers ---------------------------------------------------

// Handles 304 Not Modified response by merging fresh headers into cached entry.
fn freshen_cached_entry_304(
    cache:                Cache&,
    revalidate_entry_idx: i64,
    resp:                 const Response&,
    ts:                   const CacheTimestamps&,
    req_headers:          const HeaderMap& = HeaderMap { .. },
) -> ResponseDecision {
    var dec = ResponseDecision { .. };
    guard revalidate_entry_idx >= 0 && revalidate_entry_idx < cache.entries.len else {
        dec.kind = ResponseDecisionKind.PassThrough;
        dec.response = copy(resp);
        return dec;
    }

    var entry = &cache.entries[revalidate_entry_idx];
    guard entry.is_valid && !entry.security_zeroed else {
        dec.kind = ResponseDecisionKind.PassThrough;
        dec.response = copy(resp);
        return dec;
    }
    let resp_304_headers = http_internal::response_headers_to_map(resp);
    entry.headers.merge_cached_headers_304(resp_304_headers);
    if !http_internal::refresh_entry_vary_and_nvs(entry, req_headers) {
        entry.is_valid = false;
        http_internal::lru_detach(cache, revalidate_entry_idx as i32);
    }

    entry.timestamps.request_sec = ts.request_sec;
    entry.timestamps.request_mono_ns = ts.request_mono_ns;
    entry.timestamps.response_sec = ts.response_sec;
    entry.timestamps.response_mono_ns = ts.response_mono_ns;
    entry.timestamps.now_sec = ts.response_sec;
    if ts.has_monotonic {
        entry.timestamps.now_mono_ns = ts.response_mono_ns;
        entry.timestamps.has_monotonic = true;
    }
    let target_cc = if cache.options.shared {
        if cache.options.target_name.len > 0 { cache.options.target_name[..] } else { "cdn" }
    } else {
        ""
    };
    entry.cc = parse_targeted_cache_control_headers(
        entry.headers,
        target_cc,
        CacheControlParseOptions { is_request: false, ignore_cargo_cult: cache.options.ignore_cargo_cult },
    );

    let etag_raw = entry.headers.get_header("etag");
    if etag_raw.len > 0 {
        entry.etag = parse_etag(etag_raw);
    }
    let lm_raw = entry.headers.get_header("last-modified");
    if lm_raw.len > 0 {
        let d_val, ok_d = core::parse_http_date(lm_raw);
        if ok_d { entry.last_modified_sec = core::unix(d_val); }
    }

    if entry.is_valid {
        http_internal::lru_touch(cache, revalidate_entry_idx);
    }
    http_internal::entry_to_response(entry, ts.response_sec, dec.response);
    var cs_304 = CacheStatusEntry {
        hit:        true,
        fwd_status: 304,
        ..
    };
    let cname_304 = if cache.options.target_name.len > 0 { cache.options.target_name[..] } else { "GooseCache" };
    cs_304.cache_name.try_set(cname_304);
    cs_304.fwd.try_set("uri-miss");
    var cs_304_buf: u8[..256] = [];
    format_cache_status(cs_304, cs_304_buf);
    dec.response.set_header("Cache-Status", cs_304_buf[..]);
    dec.kind = ResponseDecisionKind.FreshenAndReturn;
    dec.entry_idx = revalidate_entry_idx;
    return dec;
}

// ---- on_response handler (store, freshen 304, or passthrough) ---------------

// Coordinates post-network response caching, 304 revalidations, and unsafe invalidations (RFC 9111).
fn on_response(
    cache:                Cache&,
    req:                  const Request&,
    resp:                 const Response&,
    ts:                   const CacheTimestamps&,
    revalidate_entry_idx: i64 = -1,
) -> ResponseDecision {
    var dec = ResponseDecision { response: copy(resp), .. };
    var writer_stored = false;
    defer http_internal::finalize_inflight_cache_writer(
        cache.writers,
        req.method[..],
        req.url[..],
        writer_stored,
        resp.status_code,
    );

    let is_get = req.method[..].eq_ascii_fold("GET");
    let is_head = req.method[..].eq_ascii_fold("HEAD");
    let m = req.method[..];
    let is_unsafe = m.eq_ascii_fold("POST") || m.eq_ascii_fold("PUT") ||
        m.eq_ascii_fold("DELETE") || m.eq_ascii_fold("PATCH");

    if is_unsafe && resp.status_code >= 200 && resp.status_code < 400 {
        cache.check_invalidation(req, resp);
        dec.kind = ResponseDecisionKind.PassThrough;
        return dec;
    }

    if resp.status_code == 304 {
        dec = cache.freshen_cached_entry_304(revalidate_entry_idx, resp, ts, req.headers);
        writer_stored = dec.kind == ResponseDecisionKind.FreshenAndReturn;
        return dec;
    }

    if http_internal::try_serve_stale_on_gateway_error(cache, req, resp, ts, revalidate_entry_idx, dec) {
        writer_stored = true;
        return dec;
    }

    guard is_get || is_head else {
        dec.kind = ResponseDecisionKind.PassThrough;
        return dec;
    }

    let req_cc = parse_cache_control_headers(
        req.headers,
        CacheControlParseOptions { is_request: true, ignore_cargo_cult: cache.options.ignore_cargo_cult },
    );
    let resp_headers = http_internal::response_headers_to_map(resp);
    let target_cc = if cache.options.shared {
        if cache.options.target_name.len > 0 { cache.options.target_name[..] } else { "cdn" }
    } else {
        ""
    };
    let resp_cc = parse_targeted_cache_control_headers(
        resp_headers,
        target_cc,
        CacheControlParseOptions { is_request: false, ignore_cargo_cult: cache.options.ignore_cargo_cult },
    );

    guard req.url.len <= 2048 && req.method.len <= 16 &&
          http_internal::is_response_cacheable(cache.options, req_cc, req.headers, resp, resp_cc) else {
        dec.kind = ResponseDecisionKind.PassThrough;
        return dec;
    }

    writer_stored = http_internal::store_cacheable_response(cache, req, resp, resp_headers, resp_cc, ts, is_head, dec);
    return dec;
}

// ---- invalidation cascade (rfc 9111 section 4.4) ---------------------------

// Invalidates all cached entries whose URL matches target_url (exact or No-Vary-Search equivalent).
fn invalidate_matching_url(cache: Cache&, target_url: const u8[:]) -> i64 {
    var count: i64 = 0;
    let target_hash = http_internal::hash_fnv1a(target_url);
    for &entry, idx in cache.entries {
        if entry.is_valid {
            let exact = entry.url_hash == target_hash && entry.url[..] == target_url;
            let nvs_eq = entry.nvs.is_valid && are_urls_nvs_equivalent(entry.url[..], target_url, entry.nvs);
            if exact || nvs_eq {
                entry.is_valid = false;
                entry.security_zeroed = true;
                http_internal::lru_detach(cache, idx as i32);
                count = core::add_sat_i64(count, 1);
            }
        }
    }
    return count;
}

// Invalidates stored responses on unsafe method completion (POST, PUT, DELETE, PATCH).
// Invalidates the request URI and any same-origin Location and Content-Location URIs (RFC 9111 §4.4).
fn check_invalidation(cache: Cache&, req: const Request&, resp: const Response&) -> i64 {
    var count = cache.invalidate_matching_url(req.url[..]);

    var base_orig = core::Origin { .. };
    let parsed_base, err_base = core::parse_url(req.url[..]);
    if err_base == core::UrlParseError.None && parsed_base.valid {
        base_orig = core::origin_from_url(parsed_base);
        count += http_internal::invalidate_target_if_same_origin(
            cache, resp.header("Location"), parsed_base, base_orig,
        );
        count += http_internal::invalidate_target_if_same_origin(
            cache, resp.header("Content-Location"), parsed_base, base_orig,
        );
    }

    // RFC 9875 §3: Cache-Group-Invalidation is ignored for safe-method responses (on_response only
    // reaches this path for unsafe methods); group purges do not cascade (RFC 9875 §2.2.1).
    var group_tags: CacheGroupTag[..32] = [];
    if parse_cache_group_list(resp.header("Cache-Group-Invalidation"), group_tags) {
        let group_base_url = if err_base == core::UrlParseError.None && parsed_base.valid { req.url[..] } else { "" };
        for &tag in group_tags {
            count = core::add_sat_i64(count, cache.invalidate_group(tag.name[..], group_base_url));
        }
    }

    cache.total_invalidations += count;
    return count;
}

// ---- scalable data-stack http cache (root struct) --------------------------

// Dynamically sized HTTP cache engine on Goose's data stack for CDN and edge deployments.
root struct ScalableCache {
    options:      CacheOptions     = CacheOptions { .. },
    entries:      CachedEntry[>..] = [],
    max_entries:  i64              = 64,
    max_body_cap: i64              = 4096,
    lru_head:     i32              = -1,
    lru_tail:     i32              = -1,
}

// Initializes a `ScalableHttpCache` with dynamic entry capacity and body cap.
fn init_scalable_cache(cache: ScalableCache&, max_entries: i64, max_body_cap: i64 = 4096) {
    let eff_max = if max_entries > 0 { max_entries } else { 64 };
    let eff_body = if max_body_cap > 0 { min(max_body_cap, 4096) } else { 4096 };
    cache.max_entries = eff_max;
    cache.max_body_cap = eff_body;
    cache.options.max_entry_size = eff_body;
    cache.entries.clear();
    cache.lru_head = -1;
    cache.lru_tail = -1;
}

// Performs RFC 9111 cache lookup on `ScalableHttpCache` (compatible with `stage_client_cache_lookup<Cache>`).
fn lookup(
    cache:   ScalableCache&,
    req:     const Request&,
    now_sec: i64,
) -> LookupDecision {
    var dec = LookupDecision { .. };
    let is_get = req.method[..].eq_ascii_fold("GET");
    let is_head = req.method[..].eq_ascii_fold("HEAD");
    guard is_get || is_head else {
        dec.kind = LookupResultKind.Miss;
        return dec;
    }

    let req_cc = parse_cache_control_headers(
        req.headers,
        CacheControlParseOptions { is_request: true, ignore_cargo_cult: cache.options.ignore_cargo_cult },
    );
    if req_cc.is_no_store() {
        dec.kind = LookupResultKind.Miss;
        return dec;
    }

    let req_hash = http_internal::hash_fnv1a(req.url[..]);
    let matched_idx = http_internal::find_matching_entry(cache.entries[..], req.url[..], req_hash, req.headers, is_get);
    if matched_idx < 0 {
        if req_cc.is_only_if_cached() {
            dec.kind = LookupResultKind.Fail504;
            dec.status_code = 504;
        }
        return dec;
    }

    http_internal::touch_scalable_lru(cache, matched_idx as i32);
    let matched_entry .= cache.entries[matched_idx];
    return http_internal::evaluate_matched_cache_entry(
        matched_entry,
        cache.options,
        req,
        req_cc,
        matched_idx,
        now_sec,
        0,
    );
}

// Stores a cacheable HTTP response in `ScalableHttpCache` with O(1) LRU eviction at `max_entries`.
fn store_response(
    cache:   ScalableCache&,
    req:     const Request&,
    resp:    const Response&,
    now_sec: i64,
) -> bool {
    let is_get = req.method[..].eq_ascii_fold("GET");
    let is_head = req.method[..].eq_ascii_fold("HEAD");
    guard is_get || is_head else { return false; }
    guard resp.body.len <= cache.max_body_cap else { return false; }
    guard req.url.len <= 2048 && req.method.len <= 16 else { return false; }

    let req_cc = parse_cache_control_headers(
        req.headers,
        CacheControlParseOptions { is_request: true, ignore_cargo_cult: cache.options.ignore_cargo_cult },
    );
    let resp_headers = http_internal::response_headers_to_map(resp);
    let resp_cc = parse_targeted_cache_control_headers(
        resp_headers,
        http_internal::resolve_target_cache_name(cache.options),
        CacheControlParseOptions { is_request: false, ignore_cargo_cult: cache.options.ignore_cargo_cult },
    );
    guard http_internal::is_response_cacheable(cache.options, req_cc, req.headers, resp, resp_cc) else {
        return false;
    }

    var sanitized = HeaderMap { .. };
    resp_headers.sanitize_for_storage(sanitized, cache.options.shared, resp_cc);
    let ts = CacheTimestamps {
        request_sec:  now_sec,
        response_sec: now_sec,
        now_sec:      now_sec,
        ..
    };
    var entry = CachedEntry {
        url_hash:        http_internal::hash_fnv1a(req.url[..]),
        status_code:     resp.status_code,
        headers:         sanitized,
        cc:              resp_cc,
        timestamps:      ts,
        head_only:       is_head,
        security_zeroed: false,
        is_valid:        true,
        ..
    };
    guard http_internal::refresh_entry_vary_and_nvs(entry, req.headers) else { return false; }
    http_internal::populate_entry_validators(entry);
    entry.url.append(req.url[..]);
    entry.method.append(req.method[..]);
    entry.body.append(resp.body[..]);
    return http_internal::upsert_scalable_cache_entry(cache, entry, req.headers);
}

// Coordinates post-network response caching on `ScalableHttpCache` (compatible with `stage_client_cache_store<Cache>`).
fn on_response(
    cache:                ScalableCache&,
    req:                  const Request&,
    resp:                 const Response&,
    ts:                   const CacheTimestamps&,
    revalidate_entry_idx: i64 = -1,
) -> ResponseDecision {
    var dec = ResponseDecision { response: copy(resp), .. };
    if cache.max_entries <= 0 || cache.max_body_cap <= 0 {
        init_scalable_cache(cache, cache.max_entries, cache.max_body_cap);
    }
    let m = req.method[..];
    let is_unsafe = m.eq_ascii_fold("POST") || m.eq_ascii_fold("PUT") ||
        m.eq_ascii_fold("DELETE") || m.eq_ascii_fold("PATCH");
    if is_unsafe && resp.status_code >= 200 && resp.status_code < 400 {
        http_internal::invalidate_scalable_on_unsafe(cache, req, resp);
        dec.kind = ResponseDecisionKind.PassThrough;
        return dec;
    }
    if http_internal::freshen_scalable_304_entry(cache, req, resp, ts, revalidate_entry_idx, dec) {
        return dec;
    }
    if cache.store_response(req, resp, ts.response_sec) {
        dec.kind = ResponseDecisionKind.StoreAndReturn;
        dec.entry_idx = cache.lru_head;
    }
    return dec;
}
