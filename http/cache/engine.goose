// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// RFC 9111: HTTP Caching engine, transaction state machine, and storage coordinator.
// Implements lookup, freshness evaluation, conditional revalidation, 304 header merge,
// cascade invalidation for unsafe methods, single-flight request collapsing, and O(1) LRU eviction.
namespace wing;

import std;
import core from "../..";
import client.request;
import client.response;
import http.headers;
import http.novarysearch;
import http.cache.cache_control;
import http.cache.freshness;
import http.cache.validators;
import http.cache.cache_groups;
import http.targeted_cache;
import http.status_diagnostics;

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
    url_hash:        u32             = 0,
    url:             u8[..2048]      = [],
    method:          u8[..16]        = "GET",
    status_code:     i32             = 200,
    headers:         HeaderMap       = HeaderMap { .. },
    cc:              CacheControl    = CacheControl { .. },
    etag:            EntityTag       = EntityTag { .. },
    last_modified:   core::Time      = core::Time { .. },
    timestamps:      CacheTimestamps = CacheTimestamps { .. },
    vary:            VarySnapshot    = VarySnapshot { .. },
    nvs:             NoVarySearch    = NoVarySearch { .. },
    body:            u8[..4096]      = [],
    head_only:       bool            = false,
    security_zeroed: bool            = false,
    is_valid:        bool            = false,
    prev_lru:        i32             = -1,
    next_lru:        i32             = -1,
}

// Constructs an empty, uninitialized CachedEntry.
// Computes FNV-1a hash of a byte slice for fast URL pre-matching.
fn hash_fnv1a(s: const u8[:]) -> u32 {
    var h: u32 = 2166136261;
    for b in s {
        h ^= b;
        h *= 16777619;
    }
    return h;
}

inline fn advance_monotonic_for_age(cur_ts: CacheTimestamps&, cur_now: core::Time, orig_now: core::Time) {
    if cur_ts.has_monotonic {
        let diff_sec = cur_now.wall_sec - orig_now.wall_sec;
        if diff_sec > 0 {
            cur_ts.now_mono.nanos += (diff_sec as u64) * 1000000000;
        }
    }
}

// Converts a CachedEntry to an application Response, attaching calculated Age header (RFC 9111 §5.1).
// Returns false if buffer capacities are exceeded (Invariant 13).
fn entry_to_response(entry: const CachedEntry&, cur_now: core::Time, out_resp: Response&) -> bool {
    guard out_resp.effective_url.try_set(entry.url[..]) &&
          out_resp.final_method.try_set(entry.method[..]) else {
        return false;
    }
    out_resp.status_code = entry.status_code;

    out_resp.headers.clear();
    for &h_entry in entry.headers.entries {
        let h_name = entry.headers.raw_buf[h_entry.name_begin..h_entry.name_end];
        let h_val = entry.headers.raw_buf[h_entry.values_begin..h_entry.values_end];
        if !h_name.eq_ascii_fold("age") {
            guard append_header(out_resp.headers, h_name, h_val) else { return false; }
        }
    }

    var cur_ts = entry.timestamps;
    cur_ts.now = cur_now;
    advance_monotonic_for_age(cur_ts, cur_now, entry.timestamps.now);
    let date_raw = entry.headers.get_header("date");
    var date_time = cur_ts.response_time;
    if date_raw.len > 0 {
        let d, ok_d = core::parse_http_date(date_raw);
        if ok_d { date_time = d; }
    }
    let apparent_age = compute_apparent_age(cur_ts.response_time, date_time);
    let orig_age = parse_age_header(entry.headers.get_header("age"));
    let cur_age = compute_current_age(apparent_age, orig_age, cur_ts);

    var age_str: u8[..64] = [];
    format(age_str, cur_age);
    guard append_header(out_resp.headers, "Age", age_str[..]) else { return false; }

    out_resp.body.clear();
    out_resp.body.append(entry.body[..]);
    return true;
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

// Constructs a zero-initialized CacheWriters container.
// Registers or joins an in-flight network transaction for key.
// Returns (is_leader, flight_idx). Leader executes network fetch; joiner shares result.
fn start_writer_or_join(writers: CacheWriters&, key: const u8[:]) -> bool, i64 {
    for &flight, idx in writers.flights {
        if flight.is_active && flight.key[..] == key {
            flight.waiter_count++;
            return false, idx;
        }
    }

    // Reuse any inactive slot without shifting existing flight indices
    for &flight, idx in writers.flights {
        if !flight.is_active {
            guard flight.key.try_set(key) else { return false, -1; }
            flight.is_active = true;
            flight.waiter_count = 0;
            flight.total_bytes = 0;
            flight.completed = false;
            flight.aborted = false;
            return true, idx;
        }
    }

    guard writers.flights.len < writers.flights.cap else { return true, -1; }

    var flight = CacheWriterFlight {
        is_active:    true,
        waiter_count: 0,
        total_bytes:  0,
        completed:    false,
        aborted:      false,
        ..
    };
    guard flight.key.try_set(key) else { return false, -1; }
    writers.flights.push(flight);
    return true, writers.flights.len - 1;
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

inline fn try_acquire_matching_slot(slot: WriterSlot&, now_ms: i64, eff_timeout: i64) -> bool {
    if slot.active && slot.status == CacheLockStatus.Waiting {
        let elapsed = core::sub_sat_i64(now_ms, slot.acquired_at_ms);
        guard elapsed >= slot.age_timeout_ms else { return false; }
        slot.status = CacheLockStatus.Waiting;
        slot.acquired_at_ms = now_ms;
        slot.age_timeout_ms = eff_timeout;
        slot.stale_writer = true;
        return true;
    }
    if slot.status == CacheLockStatus.GiveUp {
        return true;
    }
    slot.active = true;
    slot.acquired_at_ms = now_ms;
    slot.age_timeout_ms = eff_timeout;
    slot.status = CacheLockStatus.Waiting;
    slot.stale_writer = false;
    return true;
}

// Acquires a cache stampede write lock for `hash` at `now_ms` with `age_timeout_ms` expiration.
// Preempts any expired `Waiting` lock (`now_ms - acquired_at_ms >= age_timeout_ms`) or `GiveUp` slot.
fn acquire_at(writers: CacheWriters&, hash: u64, now_ms: i64, age_timeout_ms: i64) -> bool {
    let eff_timeout = if age_timeout_ms > 0 { age_timeout_ms } else { 10000 };
    for &slot in writers.slots {
        if slot.key_hash == hash {
            return try_acquire_matching_slot(slot, now_ms, eff_timeout);
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
struct HttpCache {
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

// Constructs a new HttpCache engine with specified options.
fn new_http_cache(options: CacheOptions = CacheOptions { .. }) -> HttpCache {
    return HttpCache {
        options: options,
        writers: CacheWriters { .. },
        ..
    };
}

// ---- intrusive O(1) LRU operations ----------------------------------------

// Detaches entry at idx from the intrusive LRU list without copying struct data.
fn lru_detach(cache: HttpCache&, idx: i32) {
    guard idx >= 0 && idx < cache.entries.len else { return; }
    let p = cache.entries[idx as i64].prev_lru;
    let n = cache.entries[idx as i64].next_lru;
    if p >= 0 { cache.entries[p as i64].next_lru = n; } else { cache.lru_head = n; }
    if n >= 0 { cache.entries[n as i64].prev_lru = p; } else { cache.lru_tail = p; }
    cache.entries[idx as i64].prev_lru = -1;
    cache.entries[idx as i64].next_lru = -1;
}

// Pushes entry at idx to the MRU head of the intrusive LRU list in O(1).
fn lru_push_front(cache: HttpCache&, idx: i32) {
    guard idx >= 0 && idx < cache.entries.len else { return; }
    cache.entries[idx as i64].next_lru = cache.lru_head;
    cache.entries[idx as i64].prev_lru = -1;
    if cache.lru_head >= 0 {
        cache.entries[cache.lru_head as i64].prev_lru = idx;
    } else {
        cache.lru_tail = idx;
    }
    cache.lru_head = idx;
}

// Promotes accessed entry to MRU head.
fn lru_touch(cache: HttpCache&, idx: i64) {
    lru_detach(cache, idx as i32);
    lru_push_front(cache, idx as i32);
}

// ---- header conversion and url origin helpers ------------------------------

// Returns a copy of response headers with `status_code` populated.
fn response_headers_to_map(resp: const Response&) -> HeaderMap {
    var map = copy(resp.headers);
    map.status_code = resp.status_code;
    return map;
}

// Checks if request contains Authorization or Proxy-Authorization.
fn request_has_authorization(req_headers: const HeaderMap&) -> bool {
    return req_headers.has_header("authorization") || req_headers.has_header("proxy-authorization");
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

// Searches cache entries for matching URL and valid Vary variant.
// Returns entry index or -1 on miss.
fn find_matching_entry(
    entries:     const CachedEntry[:],
    req_url:     const u8[:],
    req_hash:    u32,
    req_headers: const HeaderMap&,
    is_get:      bool,
) -> i64 {
    var matched_idx:      i64 = -1;
    var newest_date_unix: i64 = -1;

    for &entry, idx in entries {
        if !entry.is_valid || entry.security_zeroed { continue; }
        let exact_match = entry.url_hash == req_hash && entry.url[..] == req_url;
        if !exact_match && !are_urls_nvs_equivalent(entry.url[..], req_url, entry.nvs) { continue; }
        if is_get && entry.head_only { continue; }
        if entry.vary.has_star { continue; }
        if !entry.vary.matches_vary(req_headers) { continue; }

        let date_raw = entry.headers.get_header("date");
        var d_unix: i64 = 0;
        if date_raw.len > 0 {
            let d_val, ok_d = core::parse_http_date(date_raw);
            if ok_d { d_unix = core::unix(d_val); }
        }
        if d_unix >= newest_date_unix {
            newest_date_unix = d_unix;
            matched_idx = idx;
        }
    }
    return matched_idx;
}

fn evaluate_suffix_byte_range(end_str: const u8[:], total_len: i64) -> i32, i64, i64 {
    let suffix_len, ok_s = end_str.trim_lws().parse_i64_dec();
    guard ok_s && suffix_len >= 0 else { return 200, 0, 0; }
    if suffix_len == 0 || total_len <= 0 { return 416, 0, 0; }
    let eff_suffix = min(suffix_len, total_len);
    return 206, core::sub_sat_i64(total_len, eff_suffix), core::sub_sat_i64(total_len, 1);
}

// Evaluates a single byte-range-spec (`bytes=first-last`, `bytes=first-`, `bytes=-suffix`)
// against `total_len` (RFC 9110 §14.1.2). Returns (status_code: 200|206|416, first_pos, last_pos).
fn evaluate_single_byte_range(raw_range: const u8[:], total_len: i64) -> i32, i64, i64 {
    let trimmed = raw_range.trim_lws();
    guard trimmed.len > 6 && trimmed.starts_with_fold("bytes=") else { return 200, 0, 0; }
    let spec = trimmed[6..].trim_lws();
    guard !spec.contains_byte(',') else { return 200, 0, 0; }
    let start_str, end_str, has_dash = spec.split_once_byte('-');
    guard has_dash else { return 200, 0, 0; }

    if start_str.len == 0 {
        return evaluate_suffix_byte_range(end_str, total_len);
    }

    let first_pos, ok_f = start_str.trim_lws().parse_i64_dec();
    guard ok_f && first_pos >= 0 else { return 200, 0, 0; }
    var last_pos = core::sub_sat_i64(total_len, 1);
    if end_str.len > 0 {
        let parsed_last, ok_l = end_str.trim_lws().parse_i64_dec();
        guard ok_l && parsed_last >= first_pos else { return 200, 0, 0; }
        last_pos = parsed_last;
    }
    if total_len <= 0 || first_pos >= total_len {
        return 416, 0, 0;
    }
    return 206, first_pos, min(last_pos, core::sub_sat_i64(total_len, 1));
}

fn populate_cached_206_response(entry: const CachedEntry&, first_pos: i64, last_pos: i64, resp: Response&) {
    let total_len = entry.body.len;
    let slice_end = core::add_sat_i64(last_pos, 1);
    guard first_pos >= 0 && slice_end >= first_pos && slice_end <= total_len else { return; }
    let slice_len = core::sub_sat_i64(slice_end, first_pos);
    resp.status_code = 206;
    resp.body.clear();
    resp.body.append(entry.body[first_pos..slice_end]);
    var cr_206: u8[..64] = "bytes ";
    first_pos.format_i64_dec(cr_206);
    cr_206.push('-');
    last_pos.format_i64_dec(cr_206);
    cr_206.push('/');
    total_len.format_i64_dec(cr_206);
    resp.set_header("Content-Range", cr_206[..]);
    var cl_str: u8[..32] = [];
    slice_len.format_i64_dec(cl_str);
    resp.set_header("Content-Length", cl_str[..]);
}

fn apply_cached_range_if_requested(entry: const CachedEntry&, req: const Request&, resp: Response&) {
    guard entry.status_code == 200 && req.method[..].eq_ascii_fold("GET") else { return; }
    let range_hdr = req.headers.get_header("range");
    guard range_hdr.len > 0 else { return; }

    let if_range_hdr = req.headers.get_header("if-range");
    if if_range_hdr.len > 0 && !evaluate_cache_if_range(if_range_hdr, entry.etag, entry.last_modified) {
        return;
    }

    let total_len = entry.body.len;
    let status, first_pos, last_pos = evaluate_single_byte_range(range_hdr, total_len);
    if status == 416 {
        resp.status_code = 416;
        resp.body.clear();
        var cr_416: u8[..64] = "bytes */";
        total_len.format_i64_dec(cr_416);
        resp.set_header("Content-Range", cr_416[..]);
        resp.set_header("Content-Length", "0");
    } else if status == 206 {
        populate_cached_206_response(entry, first_pos, last_pos, resp);
    }
}

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

fn evaluate_matched_cache_entry(
    matched_entry: const CachedEntry&,
    options:       const CacheOptions&,
    req:           const Request&,
    req_cc:        const CacheControl&,
    matched_idx:   i64,
    cur_now:       core::Time,
    cur_mono:      core::MonotonicInstant,
) -> LookupDecision {
    var dec = LookupDecision { .. };
    var ts = matched_entry.timestamps;
    ts.now = cur_now;
    if cur_mono.nanos > 0 {
        ts.now_mono = cur_mono;
        ts.has_monotonic = true;
    } else {
        advance_monotonic_for_age(ts, cur_now, matched_entry.timestamps.now);
    }

    let metrics = evaluate_freshness(
        matched_entry.cc,
        req_cc,
        matched_entry.headers,
        ts,
        FreshnessPolicy { shared: options.shared, security_zeroed: matched_entry.security_zeroed },
        options.heuristic_fraction,
        options.immutable_min_ttl_sec,
    );

    let can_serve = (metrics.is_fresh || metrics.stale_allowed) && !metrics.requires_revalidation;
    if can_serve {
        dec.kind = LookupResultKind.Hit;
        dec.entry_idx = matched_idx;
        dec.revalidate_in_background = metrics.stale_while_revalidate_allowed;
        matched_entry.entry_to_response(cur_now, dec.cached_response);
        apply_cached_range_if_requested(matched_entry, req, dec.cached_response);
        var cs_entry = CacheStatusEntry {
            hit: true,
            ttl: max(0, core::sub_sat_i64(metrics.freshness_lifetime_sec, metrics.current_age_sec)),
            ..
        };
        let cname = if options.target_name.len > 0 { options.target_name[..] } else { "GooseCache" };
        cs_entry.cache_name.try_set(cname);
        var cs_buf: u8[..256] = [];
        format_cache_status(cs_entry, cs_buf);
        dec.cached_response.set_header("Cache-Status", cs_buf[..]);
        return dec;
    }

    if req_cc.is_only_if_cached() {
        dec.kind = LookupResultKind.Fail504;
        dec.status_code = 504;
        return dec;
    }

    dec.kind = LookupResultKind.Revalidate;
    dec.entry_idx = matched_idx;
    dec.conditional_headers = matched_entry.build_revalidation_headers();
    return dec;
}

// Performs cache lookup for an incoming request (RFC 9111 Section 4).
// Evaluates freshness, Vary matching, and returns Hit, Revalidate, Miss, or Fail504.
fn lookup(
    cache:    HttpCache&,
    req:      const Request&,
    cur_now:  core::Time,
    cur_mono: core::MonotonicInstant = core::MonotonicInstant { .. },
) -> LookupDecision {
    var dec = LookupDecision { .. };

    let is_get = req.method[..].eq_ascii_fold("GET");
    let is_head = req.method[..].eq_ascii_fold("HEAD");
    guard is_get || is_head else {
        cache.total_misses++;
        dec.kind = LookupResultKind.Miss;
        return dec;
    }

    let req_cc = parse_cache_control_headers(
        req.headers,
        CacheControlParseOptions { is_request: true, ignore_cargo_cult: cache.options.ignore_cargo_cult },
    );

    if req_cc.is_no_store() {
        cache.total_misses++;
        dec.kind = LookupResultKind.Miss;
        return dec;
    }

    let req_hash = hash_fnv1a(req.url[..]);
    let matched_idx = find_matching_entry(cache.entries[..], req.url[..], req_hash, req.headers, is_get);

    if matched_idx < 0 {
        cache.total_misses++;
        if req_cc.is_only_if_cached() {
            dec.kind = LookupResultKind.Fail504;
            dec.status_code = 504;
            return dec;
        }
        dec.kind = LookupResultKind.Miss;
        return dec;
    }

    // Touch LRU on access
    cache.lru_touch(matched_idx);

    let matched_entry .= cache.entries[matched_idx];
    let eval_dec = evaluate_matched_cache_entry(
        matched_entry,
        cache.options,
        req,
        req_cc,
        matched_idx,
        cur_now,
        cur_mono,
    );
    if eval_dec.kind == LookupResultKind.Hit {
        cache.total_hits++;
    } else if eval_dec.kind == LookupResultKind.Revalidate {
        cache.total_revalidations++;
    } else {
        cache.total_misses++;
    }
    return eval_dec;
}

// ---- on_response helpers ---------------------------------------------------

fn refresh_entry_vary_and_nvs(entry: CachedEntry&, req_headers: const HeaderMap&) -> bool {
    if entry.headers.has_header("vary") {
        var vary_combined: u8[..512] = [];
        guard get_combined(entry.headers, "vary", vary_combined, 512) else { return false; }
        entry.vary = record_vary_snapshot(vary_combined[..], req_headers);
        guard !entry.vary.has_star && entry.vary.valid else { return false; }
    }
    let nvs_raw = entry.headers.get_header("no-vary-search");
    if nvs_raw.len > 0 {
        let parsed_nvs, ok_nvs = parse_no_vary_search(nvs_raw);
        entry.nvs = if ok_nvs { parsed_nvs } else { NoVarySearch { .. } };
    }
    return true;
}

// Handles 304 Not Modified response by merging fresh headers into cached entry.
fn freshen_cached_entry_304(
    cache:                HttpCache&,
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
    let resp_304_headers = resp.response_headers_to_map();
    entry.headers.merge_cached_headers_304(resp_304_headers);
    if !refresh_entry_vary_and_nvs(entry, req_headers) {
        entry.is_valid = false;
        cache.lru_detach(revalidate_entry_idx as i32);
    }

    entry.timestamps.request_time = ts.request_time;
    entry.timestamps.request_mono = ts.request_mono;
    entry.timestamps.response_time = ts.response_time;
    entry.timestamps.response_mono = ts.response_mono;
    entry.timestamps.now = ts.response_time;
    if ts.has_monotonic {
        entry.timestamps.now_mono = ts.response_mono;
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
        if ok_d { entry.last_modified = d_val; }
    }

    if entry.is_valid {
        cache.lru_touch(revalidate_entry_idx);
    }
    entry.entry_to_response(ts.response_time, dec.response);
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

// Evaluates whether a network response is permissible for storage under RFC 9111 rules.
fn is_response_cacheable(
    options:     const CacheOptions&,
    req_cc:      const CacheControl&,
    req_headers: const HeaderMap&,
    resp:        const Response&,
    resp_cc:     const CacheControl&,
) -> bool {
    if resp.status_code == 206 { return false; }
    if req_cc.is_no_store() || resp_cc.is_no_store() { return false; }
    if resp_cc.is_must_understand() && !rfc::is_heuristically_cacheable_status(resp.status_code) { return false; }

    // RFC 9111 Section 3: Status codes not heuristically cacheable require explicit freshness or public directive
    if !rfc::is_heuristically_cacheable_status(resp.status_code) {
        let has_explicit = has_max_age(resp_cc) || has_s_maxage(resp_cc) ||
            is_public(resp_cc) || resp.header("Expires").len > 0;
        if !has_explicit { return false; }
    }

    if options.shared {
        let priv_blocked = resp_cc.is_private() &&
            (resp_cc.private_overflow || resp_cc.private_fields.len == 0) &&
            !options.cache_private;
        if priv_blocked {
            return false;
        }
        if req_headers.request_has_authorization() {
            let auth_ok = resp_cc.is_public() || resp_cc.is_must_revalidate() || resp_cc.has_s_maxage();
            if !auth_ok { return false; }
        }
    }

    guard resp.body.len <= 4096 else { return false; }
    return resp.body.len <= options.max_entry_size;
}

// Stores or updates a cached entry using O(1) LRU insertion and eviction.
fn upsert_cache_entry(cache: HttpCache&, entry: CachedEntry, req_headers: const HeaderMap&) -> i64 {
    for &existing, idx in cache.entries {
        let exact_match = existing.url_hash == entry.url_hash && existing.url[..] == entry.url[..];
        let nvs_match = are_urls_nvs_equivalent(existing.url[..], entry.url[..], existing.nvs) ||
            are_urls_nvs_equivalent(existing.url[..], entry.url[..], entry.nvs);
        if (exact_match || nvs_match) && existing.vary.matches_vary(req_headers) {
            if existing.is_valid && !existing.head_only && entry.head_only {
                cache.lru_touch(idx);
                return idx;
            }
            if existing.is_valid {
                cache.lru_detach(idx as i32);
            }
            existing = entry;
            cache.lru_push_front(idx as i32);
            return idx;
        }
    }

    // Reuse any invalidated slot before expanding or evicting live entries
    for &slot, idx in cache.entries {
        if !slot.is_valid {
            slot = entry;
            cache.lru_push_front(idx as i32);
            return idx;
        }
    }

    if cache.entries.try_push(entry) {
        let new_idx = (cache.entries.len - 1) as i32;
        cache.lru_push_front(new_idx);
        return new_idx;
    }

    // Evict LRU tail in O(1) without shifting any elements
    let victim_idx = cache.lru_tail;
    guard victim_idx >= 0 else { return -1; }
    cache.lru_detach(victim_idx);
    cache.entries[victim_idx as i64] = entry;
    cache.lru_push_front(victim_idx);
    return victim_idx;
}

// ---- on_response handler (store, freshen 304, or passthrough) ---------------

// Coordinates post-network response caching, 304 revalidations, and unsafe invalidations (RFC 9111).
fn on_response(
    cache:                HttpCache&,
    req:                  const Request&,
    resp:                 const Response&,
    ts:                   const CacheTimestamps&,
    revalidate_entry_idx: i64 = -1,
) -> ResponseDecision {
    var dec = ResponseDecision { response: copy(resp), .. };

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
        return cache.freshen_cached_entry_304(revalidate_entry_idx, resp, ts, req.headers);
    }

    // RFC 5861 Section 4: stale-if-error fallback on 5xx gateway/origin error (500, 502, 503, 504)
    let is_gateway_error = resp.status_code == 500 || (resp.status_code >= 502 && resp.status_code <= 504);
    let valid_reval_idx = revalidate_entry_idx >= 0 && revalidate_entry_idx < cache.entries.len;
    if is_gateway_error && valid_reval_idx {
        let entry = cache.entries[revalidate_entry_idx];
        if entry.is_valid {
            let req_cc = parse_cache_control_headers(
                req.headers,
                CacheControlParseOptions { is_request: true, ignore_cargo_cult: cache.options.ignore_cargo_cult },
            );
            let age_hdr = parse_age_header(get_header(entry.headers, "age"));

            var eval_ts = entry.timestamps;
            eval_ts.now = ts.response_time;
            if ts.has_monotonic {
                eval_ts.now_mono = ts.response_mono;
                eval_ts.has_monotonic = true;
            }

            let date_raw = get_header(entry.headers, "date");
            var date_time = entry.timestamps.response_time;
            if date_raw.len > 0 {
                let d, ok_d = core::parse_http_date(date_raw);
                if ok_d { date_time = d; }
            }
            let apparent = compute_apparent_age(entry.timestamps.response_time, date_time);
            let cur_age = compute_current_age(apparent, age_hdr, eval_ts);
            let lifetime = compute_freshness_lifetime(
                entry.cc, entry.headers, eval_ts, cache.options.shared,
                cache.options.heuristic_fraction, cache.options.immutable_min_ttl_sec,
            );
            let can_stale_err = evaluate_stale_if_error(
                entry.cc,
                req_cc,
                cur_age,
                lifetime,
                FreshnessPolicy { shared: cache.options.shared, security_zeroed: entry.security_zeroed },
            );
            if can_stale_err {
                dec.kind = ResponseDecisionKind.FreshenAndReturn;
                dec.entry_idx = revalidate_entry_idx;
                entry.entry_to_response(ts.response_time, dec.response);
                return dec;
            }
        }
    }

    guard is_get || is_head else {
        dec.kind = ResponseDecisionKind.PassThrough;
        return dec;
    }

    let req_cc = parse_cache_control_headers(
        req.headers,
        CacheControlParseOptions { is_request: true, ignore_cargo_cult: cache.options.ignore_cargo_cult },
    );
    let resp_headers = resp.response_headers_to_map();
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

    guard req.url.len <= 2048 && req.method.len <= 16 else {
        dec.kind = ResponseDecisionKind.PassThrough;
        return dec;
    }

    guard is_response_cacheable(cache.options, req_cc, req.headers, resp, resp_cc) else {
        dec.kind = ResponseDecisionKind.PassThrough;
        return dec;
    }

    var vary_snap = VarySnapshot { .. };
    if resp_headers.has_header("vary") {
        var vary_combined: u8[..512] = [];
        guard get_combined(resp_headers, "vary", vary_combined, 512) else {
            dec.kind = ResponseDecisionKind.PassThrough;
            return dec;
        }
        vary_snap = record_vary_snapshot(vary_combined[..], req.headers);
        guard !vary_snap.has_star && vary_snap.valid else {
            dec.kind = ResponseDecisionKind.PassThrough;
            return dec;
        }
    }

    var nvs_snap = NoVarySearch { .. };
    let nvs_raw = resp_headers.get_header("no-vary-search");
    if nvs_raw.len > 0 {
        let parsed_nvs, ok_nvs = parse_no_vary_search(nvs_raw);
        if ok_nvs { nvs_snap = parsed_nvs; }
    }

    var sanitized = HeaderMap { .. };
    resp_headers.sanitize_for_storage(sanitized, cache.options.shared, resp_cc);

    let lm_raw = resp_headers.get_header("last-modified");
    var lm_time = core::Time { .. };
    if lm_raw.len > 0 {
        let p_lm, ok_lm = core::parse_http_date(lm_raw);
        if ok_lm { lm_time = p_lm; }
    }

    var entry = CachedEntry {
        url_hash:        hash_fnv1a(req.url[..]),
        status_code:     resp.status_code,
        headers:         sanitized,
        cc:              resp_cc,
        etag:            parse_etag(resp_headers.get_header("etag")),
        last_modified:   lm_time,
        timestamps:      ts,
        vary:            vary_snap,
        nvs:             nvs_snap,
        head_only:       is_head,
        security_zeroed: false,
        is_valid:        true,
        ..
    };
    entry.url.append(req.url[..]);
    entry.method.append(req.method[..]);
    entry.body.append(resp.body[..]);

    let store_idx = cache.upsert_cache_entry(entry, req.headers);
    cache.total_stores++;
    var cs_store = CacheStatusEntry {
        stored:     true,
        fwd_status: resp.status_code,
        ..
    };
    let cname_st = if cache.options.target_name.len > 0 { cache.options.target_name[..] } else { "GooseCache" };
    cs_store.cache_name.try_set(cname_st);
    cs_store.fwd.try_set("uri-miss");
    var cs_store_buf: u8[..256] = [];
    format_cache_status(cs_store, cs_store_buf);
    dec.response.set_header("Cache-Status", cs_store_buf[..]);
    dec.kind = ResponseDecisionKind.StoreAndReturn;
    dec.entry_idx = store_idx;
    return dec;
}

// ---- invalidation cascade (rfc 9111 section 4.4) ---------------------------

// Invalidates all cached entries whose URL matches target_url.
fn invalidate_matching_url(cache: HttpCache&, target_url: const u8[:]) -> i64 {
    var count: i64 = 0;
    let target_hash = hash_fnv1a(target_url);
    for &entry, idx in cache.entries {
        if entry.is_valid &&
           entry.url_hash == target_hash &&
           entry.url[..] == target_url {
            entry.is_valid = false;
            entry.security_zeroed = true;
            cache.lru_detach(idx as i32);
            count++;
        }
    }
    return count;
}

// Invalidates a target header URL (Location or Content-Location) if valid and same-origin.
fn invalidate_target_if_same_origin(
    cache:      HttpCache&,
    header_raw: const u8[:],
    base_url:   const core::Url&,
    base_orig:  core::Origin,
) -> i64 {
    guard header_raw.len > 0 && base_url.valid else { return 0; }
    let target_url, err = core::parse_url_with_base(header_raw, base_url);
    guard err == core::UrlParseError.None && target_url.valid else { return 0; }
    let target_orig = core::origin_from_url(target_url);
    guard core::is_same_origin(target_orig, base_orig) else { return 0; }
    return cache.invalidate_matching_url(core::href(target_url));
}

// Invalidates stored responses on unsafe method completion (POST, PUT, DELETE, PATCH).
// Invalidates the request URI and any same-origin Location and Content-Location URIs (RFC 9111 §4.4).
fn check_invalidation(cache: HttpCache&, req: const Request&, resp: const Response&) -> i64 {
    var count = cache.invalidate_matching_url(req.url[..]);

    var base_orig = core::Origin { .. };
    let parsed_base, err_base = core::parse_url(req.url[..]);
    if err_base == core::UrlParseError.None && parsed_base.valid {
        base_orig = core::origin_from_url(parsed_base);
        count += invalidate_target_if_same_origin(cache, resp.header("Location"), parsed_base, base_orig);
        count += invalidate_target_if_same_origin(cache, resp.header("Content-Location"), parsed_base, base_orig);
    }

    // RFC 9875 §3: Cache-Group-Invalidation is ignored for safe-method responses (on_response only
    // reaches this path for unsafe methods); group purges do not cascade (RFC 9875 §2.2.1).
    var group_tags:  CacheGroupTag[..32] = [];
    var group_count: i32                 = 0;
    if parse_cache_group_list(resp.header("Cache-Group-Invalidation"), group_tags, group_count) {
        for slot in 0..group_count {
            count = add_invalidated_entries(count, cache.invalidate_group(group_tags[slot].name[..], base_orig));
        }
    }

    cache.total_invalidations += count;
    return count;
}

// ---- scalable data-stack http cache (root struct) --------------------------

// Dynamically sized HTTP cache engine on Goose's data stack for CDN and edge deployments.
root struct ScalableHttpCache {
    options:      CacheOptions     = CacheOptions { .. },
    entries:      CachedEntry[>..] = [],
    max_entries:  i64              = 64,
    max_body_cap: i64              = 4096,
    lru_head:     i32              = -1,
    lru_tail:     i32              = -1,
}

// Initializes a `ScalableHttpCache` with dynamic entry capacity and body cap.
fn init_scalable_http_cache(cache: ScalableHttpCache&, max_entries: i64, max_body_cap: i64 = 4096) {
    let eff_max = if max_entries > 0 { max_entries } else { 64 };
    let eff_body = if max_body_cap > 0 { min(max_body_cap, 4096) } else { 4096 };
    cache.max_entries = eff_max;
    cache.max_body_cap = eff_body;
    cache.options.max_entry_size = eff_body;
    cache.entries.clear();
    cache.lru_head = -1;
    cache.lru_tail = -1;
}

// Detaches entry at `idx` from `ScalableHttpCache` intrusive O(1) LRU list in-place.
fn detach_scalable_lru(cache: ScalableHttpCache&, idx: i32) {
    guard idx >= 0 && idx < cache.entries.len else { return; }
    let node .= cache.entries[idx as i64];
    let p = node.prev_lru;
    let n = node.next_lru;
    if p >= 0 && p < cache.entries.len {
        cache.entries[p as i64].next_lru = n;
    } else if cache.lru_head == idx {
        cache.lru_head = n;
    }
    if n >= 0 && n < cache.entries.len {
        cache.entries[n as i64].prev_lru = p;
    } else if cache.lru_tail == idx {
        cache.lru_tail = p;
    }
    node.prev_lru = -1;
    node.next_lru = -1;
}

// Attaches entry at `idx` to the MRU tail of `ScalableHttpCache` intrusive O(1) LRU list.
fn attach_scalable_lru_tail(cache: ScalableHttpCache&, idx: i32) {
    guard idx >= 0 && idx < cache.entries.len else { return; }
    let tail = cache.lru_tail;
    let node .= cache.entries[idx as i64];
    node.prev_lru = tail;
    node.next_lru = -1;
    if tail >= 0 && tail < cache.entries.len {
        cache.entries[tail as i64].next_lru = idx;
    } else {
        cache.lru_head = idx;
    }
    cache.lru_tail = idx;
}

// Promotes accessed entry at `idx` to the MRU tail of `ScalableHttpCache` in O(1).
fn touch_scalable_lru(cache: ScalableHttpCache&, idx: i32) {
    guard idx >= 0 && idx < cache.entries.len else { return; }
    if cache.lru_tail == idx {
        return;
    }
    detach_scalable_lru(cache, idx);
    attach_scalable_lru_tail(cache, idx);
}

// Performs RFC 9111 cache lookup on `ScalableHttpCache` (compatible with `stage_client_cache_lookup<Cache>`).
fn lookup(
    cache:  ScalableHttpCache&,
    req:    const Request&,
    now_ts: core::Time,
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

    let req_hash = hash_fnv1a(req.url[..]);
    let matched_idx = find_matching_entry(cache.entries[..], req.url[..], req_hash, req.headers, is_get);
    if matched_idx < 0 {
        if req_cc.is_only_if_cached() {
            dec.kind = LookupResultKind.Fail504;
            dec.status_code = 504;
        }
        return dec;
    }

    touch_scalable_lru(cache, matched_idx as i32);
    let matched_entry .= cache.entries[matched_idx];
    return evaluate_matched_cache_entry(
        matched_entry,
        cache.options,
        req,
        req_cc,
        matched_idx,
        now_ts,
        core::MonotonicInstant { .. },
    );
}

fn try_update_existing_scalable_entry(
    cache:       ScalableHttpCache&,
    entry:       const CachedEntry&,
    req_headers: const HeaderMap&,
) -> bool {
    for i in cache.entries.len {
        let existing .= cache.entries[i];
        let exact_match = existing.url_hash == entry.url_hash && existing.url[..] == entry.url[..];
        let nvs_match = are_urls_nvs_equivalent(existing.url[..], entry.url[..], existing.nvs) ||
            are_urls_nvs_equivalent(existing.url[..], entry.url[..], entry.nvs);
        if (exact_match || nvs_match) && existing.vary.matches_vary(req_headers) {
            if existing.is_valid && !existing.head_only && entry.head_only {
                touch_scalable_lru(cache, i as i32);
                return true;
            }
            if existing.is_valid {
                detach_scalable_lru(cache, i as i32);
            }
            existing = copy(entry);
            attach_scalable_lru_tail(cache, i as i32);
            return true;
        }
    }
    return false;
}

fn upsert_scalable_cache_entry(
    cache:       ScalableHttpCache&,
    entry:       const CachedEntry&,
    req_headers: const HeaderMap&,
) -> bool {
    if try_update_existing_scalable_entry(cache, entry, req_headers) {
        return true;
    }
    for i in cache.entries.len {
        let slot .= cache.entries[i];
        if !slot.is_valid {
            slot = copy(entry);
            attach_scalable_lru_tail(cache, i as i32);
            return true;
        }
    }
    let eff_max = if cache.max_entries > 0 { cache.max_entries } else { 64 };
    if cache.entries.len < eff_max {
        let new_idx = cache.entries.len as i32;
        cache.entries.push(copy(entry));
        attach_scalable_lru_tail(cache, new_idx);
        return true;
    }
    let victim_idx = cache.lru_head;
    guard victim_idx >= 0 && victim_idx < cache.entries.len else { return false; }
    detach_scalable_lru(cache, victim_idx);
    let victim .= cache.entries[victim_idx as i64];
    victim = copy(entry);
    attach_scalable_lru_tail(cache, victim_idx);
    return true;
}

fn populate_entry_validators(entry: CachedEntry&) {
    let etag_raw = entry.headers.get_header("etag");
    if etag_raw.len > 0 {
        entry.etag = parse_etag(etag_raw);
    }
    let lm_raw = entry.headers.get_header("last-modified");
    if lm_raw.len > 0 {
        let d_val, ok_d = core::parse_http_date(lm_raw);
        if ok_d { entry.last_modified = d_val; }
    }
}

fn resolve_target_cache_name(options: const CacheOptions&) -> const u8[:] {
    guard options.shared else { return ""; }
    if options.target_name.len > 0 {
        return options.target_name[..];
    }
    return "cdn";
}

// Stores a cacheable HTTP response in `ScalableHttpCache` with O(1) LRU eviction at `max_entries`.
fn store_response(
    cache:  ScalableHttpCache&,
    req:    const Request&,
    resp:   const Response&,
    now_ts: core::Time,
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
    let resp_headers = resp.response_headers_to_map();
    let resp_cc = parse_targeted_cache_control_headers(
        resp_headers,
        resolve_target_cache_name(cache.options),
        CacheControlParseOptions { is_request: false, ignore_cargo_cult: cache.options.ignore_cargo_cult },
    );
    guard is_response_cacheable(cache.options, req_cc, req.headers, resp, resp_cc) else {
        return false;
    }

    var sanitized = HeaderMap { .. };
    resp_headers.sanitize_for_storage(sanitized, cache.options.shared, resp_cc);
    let ts = CacheTimestamps {
        request_time:  now_ts,
        response_time: now_ts,
        now:           now_ts,
        ..
    };
    var entry = CachedEntry {
        url_hash:        hash_fnv1a(req.url[..]),
        status_code:     resp.status_code,
        headers:         sanitized,
        cc:              resp_cc,
        timestamps:      ts,
        head_only:       is_head,
        security_zeroed: false,
        is_valid:        true,
        ..
    };
    guard refresh_entry_vary_and_nvs(entry, req.headers) else { return false; }
    populate_entry_validators(entry);
    entry.url.append(req.url[..]);
    entry.method.append(req.method[..]);
    entry.body.append(resp.body[..]);
    return upsert_scalable_cache_entry(cache, entry, req.headers);
}
