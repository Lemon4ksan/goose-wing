// RFC 9111: HTTP Caching engine, transaction state machine, and storage coordinator.
// Implements lookup, freshness evaluation, conditional revalidation, 304 header merge,
// cascade invalidation for unsafe methods, single-flight request collapsing, and O(1) LRU eviction.
namespace wing;

import std;
import core.time;
import core.url;
import core.sync;
import app.profile;
import app.request;
import app.response;
import http.headers;
import http.cache.cache_control;
import http.cache.freshness;
import http.cache.validators;

// ---- cache options ---------------------------------------------------------

// Configuration options governing cache storage limits, heuristics, and sharing mode.
struct CacheOptions {
    shared: bool = false,
    cache_private: bool = false,
    heuristic_fraction: i64 = 10,
    immutable_min_ttl_sec: i64 = 31536000,
    ignore_cargo_cult: bool = true,
    max_entry_size: i64 = 65536,
}

// Constructs CacheOptions with RFC 9111 baseline defaults.
fn new_cache_options() -> CacheOptions {
    return CacheOptions { .. };
}

// ---- cached entry model ----------------------------------------------------

// Cached HTTP representation including headers, body, Vary invariants, and intrusive LRU pointers.
struct CachedEntry {
    url_hash: u32 = 0,
    url: u8[..2048] = [],
    method: u8[..16] = "GET",
    status_code: i32 = 200,
    headers: HeaderMap = HeaderMap { .. },
    cc: CacheControl = CacheControl { .. },
    etag: EntityTag = EntityTag { .. },
    last_modified: Time = Time { .. },
    timestamps: CacheTimestamps = CacheTimestamps { .. },
    vary: VarySnapshot = VarySnapshot { .. },
    body: u8[..65536] = [],
    head_only: bool = false,
    security_zeroed: bool = false,
    is_valid: bool = false,
    prev_lru: i32 = -1,
    next_lru: i32 = -1,
}

// Constructs an empty, uninitialized CachedEntry.
fn new_cached_entry() -> CachedEntry {
    return CachedEntry { .. };
}

// Computes FNV-1a hash of a byte slice for fast URL pre-matching.
fn hash_fnv1a(s: const u8[:]) -> u32 {
    var h: u32 = 2166136261;
    for b in s {
        h ^= b;
        h *= 16777619;
    }
    return h;
}

// Formats an integer into an inline ASCII buffer without dynamic allocation.
fn format_int_buffer(out_buf: u8[..64]&, val: i64) {
    out_buf.clear();
    if val == 0 {
        out_buf.push('0');
        return;
    }
    var temp: u8[32] = [0; 32];
    var pos: i64 = 0;
    var n = if val < 0 { -val } else { val };
    while n > 0 {
        temp[pos] = ('0' + (n % 10)) as u8;
        n /= 10;
        pos++;
    }
    if val < 0 { out_buf.push('-'); }
    while pos > 0 {
        pos--;
        out_buf.push(temp[pos]);
    }
}

// Converts a CachedEntry to an application Response, attaching calculated Age header (RFC 9111 §5.1).
fn entry_to_response(entry: const CachedEntry&, cur_now: Time, out_resp: Response&) {
    out_resp.status_code = entry.status_code;
    out_resp.effective_url.clear();
    out_resp.effective_url.append(entry.url[..]);
    out_resp.final_method.clear();
    out_resp.final_method.append(entry.method[..]);

    out_resp.headers.clear();
    for h_entry in entry.headers.entries {
        let h_name = entry.headers.raw_buf[h_entry.name_begin..h_entry.name_end];
        let h_val = entry.headers.raw_buf[h_entry.values_begin..h_entry.values_end];
        if !eq_ascii_fold(h_name, "age") && out_resp.headers.len < 32 {
            out_resp.headers.push(make_header(h_name, h_val));
        }
    }

    var cur_ts = entry.timestamps;
    cur_ts.now = cur_now;
    let date_raw = get_header(entry.headers, "date");
    var date_time = cur_ts.response_time;
    if date_raw.len > 0 {
        let d, ok_d = parse_http_date(date_raw);
        if ok_d { date_time = d; }
    }
    let apparent_age = compute_apparent_age(cur_ts.response_time, date_time);
    let orig_age = parse_age_header(get_header(entry.headers, "age"));
    let cur_age = compute_current_age(apparent_age, orig_age, cur_ts);

    var age_str: u8[..64] = [];
    format_int_buffer(age_str, cur_age);
    if out_resp.headers.len < 32 {
        out_resp.headers.push(make_header("Age", age_str[..]));
    }

    out_resp.body.clear();
    out_resp.body.append(entry.body[..]);
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
    kind: LookupResultKind = LookupResultKind.Miss,
    entry_idx: i64 = -1,
    conditional_headers: HeaderMap = HeaderMap { .. },
    status_code: i32 = 0,
    cached_response: Response = Response { .. },
}

// Classification of on_response cache action.
enum ResponseDecisionKind {
    StoreAndReturn,
    FreshenAndReturn,
    PassThrough,
}

// Result of evaluating a network response against caching policies.
struct ResponseDecision {
    kind: ResponseDecisionKind = ResponseDecisionKind.PassThrough,
    entry_idx: i64 = -1,
    response: Response = Response { .. },
}

// ---- writers / single-flight request collapsing ----------------------------

struct CacheWriterFlight {
    key: u8[..256] = [],
    is_active: bool = false,
    waiter_count: i32 = 0,
    total_bytes: i64 = 0,
    completed: bool = false,
    aborted: bool = false,
}

// Single-flight coordinator for concurrent network transactions (Chromium HttpCache::Writers parity).
struct CacheWriters {
    flights: CacheWriterFlight[..16] = [],
    group: SingleflightGroup = SingleflightGroup { .. },
}

// Constructs a zero-initialized CacheWriters container.
fn new_cache_writers() -> CacheWriters {
    return CacheWriters { .. };
}

// Registers or joins an in-flight network transaction for key.
// Returns (is_leader, flight_idx). Leader executes network fetch; joiner shares result.
fn start_writer_or_join(writers: CacheWriters&, key: const u8[:]) -> bool, i64 {
    for idx in writers.flights.len {
        if writers.flights[idx].is_active && writers.flights[idx].key[..] == key {
            writers.flights[idx].waiter_count++;
            return false, idx;
        }
    }

    guard writers.flights.len < 16 else { return true, -1; }

    var flight = CacheWriterFlight {
        is_active: true,
        waiter_count: 0,
        total_bytes: 0,
        completed: false,
        aborted: false,
        ..
    };
    flight.key.append(key);
    writers.flights.push(flight);
    return true, writers.flights.len - 1;
}

// Marks the in-flight writer transaction as successfully completed and frees its slot.
fn finish_writer(writers: CacheWriters&, flight_idx: i64) {
    guard flight_idx >= 0 && flight_idx < writers.flights.len else { return; }
    writers.flights[flight_idx].completed = true;
    writers.flights[flight_idx].is_active = false;
    writers.flights[flight_idx] = writers.flights[writers.flights.len - 1];
    writers.flights.pop();
}

// Marks the in-flight writer transaction as aborted and frees its slot.
fn abort_writer(writers: CacheWriters&, flight_idx: i64) {
    guard flight_idx >= 0 && flight_idx < writers.flights.len else { return; }
    writers.flights[flight_idx].aborted = true;
    writers.flights[flight_idx].is_active = false;
    writers.flights[flight_idx] = writers.flights[writers.flights.len - 1];
    writers.flights.pop();
}

// ---- http cache engine container -------------------------------------------

// High-performance HTTP caching coordinator with intrusive O(1) LRU list.
struct HttpCache {
    options: CacheOptions = CacheOptions { .. },
    entries: CachedEntry[..64] = [],
    writers: CacheWriters = CacheWriters { .. },
    lru_head: i32 = -1,
    lru_tail: i32 = -1,
    total_hits: i64 = 0,
    total_misses: i64 = 0,
    total_revalidations: i64 = 0,
    total_stores: i64 = 0,
    total_invalidations: i64 = 0,
}

// Constructs a new HttpCache engine with specified options.
fn new_http_cache(options: CacheOptions = CacheOptions { .. }) -> HttpCache {
    return HttpCache {
        options: options,
        writers: new_cache_writers(),
        ..
    };
}

// ---- intrusive O(1) LRU operations ----------------------------------------

// Detaches entry at idx from the intrusive LRU list without copying struct data.
fn lru_detach(cache: HttpCache&, idx: i32) {
    let p = cache.entries[idx as i64].prev_lru;
    let n = cache.entries[idx as i64].next_lru;
    if p >= 0 { cache.entries[p as i64].next_lru = n; } else { cache.lru_head = n; }
    if n >= 0 { cache.entries[n as i64].prev_lru = p; } else { cache.lru_tail = p; }
    cache.entries[idx as i64].prev_lru = -1;
    cache.entries[idx as i64].next_lru = -1;
}

// Pushes entry at idx to the MRU head of the intrusive LRU list in O(1).
fn lru_push_front(cache: HttpCache&, idx: i32) {
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

// Converts request headers from app Request to HeaderMap.
fn request_headers_to_map(req: const Request&) -> HeaderMap {
    var map = new_header_map();
    for &h in req.headers { append_header(map, h.name[..], h.value[..]); }
    return map;
}

// Converts response headers from app Response to HeaderMap.
fn response_headers_to_map(resp: const Response&) -> HeaderMap {
    var map = new_header_map();
    map.status_code = resp.status_code;
    for &h in resp.headers { append_header(map, h.name[..], h.value[..]); }
    return map;
}

// Checks if request contains Authorization or Proxy-Authorization.
fn request_has_authorization(req_headers: const HeaderMap&) -> bool {
    return has_header(req_headers, "authorization") || has_header(req_headers, "proxy-authorization");
}

// Checks whether two URLs share the same origin, preventing cross-origin poisoning (RFC 9111 §4.4).
fn is_same_origin_url(url_a: const u8[:], url_b: const u8[:]) -> bool {
    let parsed_a, err_a = parse_url(url_a);
    let parsed_b, err_b = parse_url(url_b);
    guard err_a == UrlParseError.None && err_b == UrlParseError.None else { return false; }
    let orig_a = origin_from_url(parsed_a);
    let orig_b = origin_from_url(parsed_b);
    return is_same_origin(orig_a, orig_b);
}

// ---- lookup logic (rfc 9111 section 4) -------------------------------------

// Searches cache entries for matching URL and valid Vary variant.
// Returns entry index or -1 on miss.
fn find_matching_entry(
    cache: const HttpCache&,
    req_url: const u8[:],
    req_hash: u32,
    req_headers: const HeaderMap&,
    is_get: bool
) -> i64 {
    var matched_idx: i64 = -1;
    var newest_date_unix: i64 = -1;

    for idx in cache.entries.len {
        let entry = cache.entries[idx];
        if !entry.is_valid || entry.security_zeroed { continue; }
        if entry.url_hash != req_hash || entry.url[..] != req_url { continue; }
        if is_get && entry.head_only { continue; }
        if entry.vary.has_star { continue; }
        if !matches_vary(entry.vary, req_headers) { continue; }

        let date_raw = get_header(entry.headers, "date");
        var d_unix: i64 = 0;
        if date_raw.len > 0 {
            let d_val, ok_d = parse_http_date(date_raw);
            if ok_d { d_unix = unix(d_val); }
        }
        if d_unix >= newest_date_unix {
            newest_date_unix = d_unix;
            matched_idx = idx;
        }
    }
    return matched_idx;
}

// Builds conditional request headers (If-None-Match and If-Modified-Since) for revalidation.
fn build_revalidation_headers(entry: const CachedEntry&) -> HeaderMap {
    var cond = new_header_map();
    if entry.etag.valid {
        var etag_buf: u8[..160] = [];
        if entry.etag.is_weak { etag_buf.append("W/"); }
        etag_buf.push('"');
        etag_buf.append(entry.etag.tag[..]);
        etag_buf.push('"');
        append_header(cond, "If-None-Match", etag_buf[..]);
    }
    let lm_raw = get_header(entry.headers, "last-modified");
    if lm_raw.len > 0 {
        append_header(cond, "If-Modified-Since", lm_raw);
    }
    return cond;
}

// Performs cache lookup for an incoming request (RFC 9111 Section 4).
// Evaluates freshness, Vary matching, and returns Hit, Revalidate, Miss, or Fail504.
fn lookup(
    cache: HttpCache&,
    req: const Request&,
    cur_now: Time,
    cur_mono: MonotonicInstant = MonotonicInstant { .. }
) -> LookupDecision {
    var dec = LookupDecision { .. };

    let is_get = eq_ascii_fold(req.method[..], "GET");
    let is_head = eq_ascii_fold(req.method[..], "HEAD");
    guard is_get || is_head else {
        cache.total_misses++;
        dec.kind = LookupResultKind.Miss;
        return dec;
    }

    let req_headers = request_headers_to_map(req);
    let req_cc = parse_cache_control_headers(req_headers, true, cache.options.ignore_cargo_cult);

    if is_no_store(req_cc) {
        cache.total_misses++;
        dec.kind = LookupResultKind.Miss;
        return dec;
    }

    let req_hash = hash_fnv1a(req.url[..]);
    let matched_idx = find_matching_entry(cache, req.url[..], req_hash, req_headers, is_get);

    if matched_idx < 0 {
        cache.total_misses++;
        if is_only_if_cached(req_cc) {
            dec.kind = LookupResultKind.Fail504;
            dec.status_code = 504;
            return dec;
        }
        dec.kind = LookupResultKind.Miss;
        return dec;
    }

    // Touch LRU on access
    lru_touch(cache, matched_idx);

    let matched_entry = cache.entries[matched_idx];
    var ts = matched_entry.timestamps;
    ts.now = cur_now;
    if cur_mono.nanos > 0 {
        ts.now_mono = cur_mono;
        ts.has_monotonic = true;
    }

    let metrics = evaluate_freshness(
        matched_entry.cc, req_cc, matched_entry.headers, ts,
        cache.options.shared, matched_entry.security_zeroed,
        cache.options.heuristic_fraction, cache.options.immutable_min_ttl_sec
    );

    if (metrics.is_fresh && !metrics.requires_revalidation) || (metrics.stale_allowed && !metrics.requires_revalidation) {
        cache.total_hits++;
        dec.kind = LookupResultKind.Hit;
        dec.entry_idx = matched_idx;
        entry_to_response(matched_entry, cur_now, dec.cached_response);
        return dec;
    }

    if is_only_if_cached(req_cc) {
        cache.total_misses++;
        dec.kind = LookupResultKind.Fail504;
        dec.status_code = 504;
        return dec;
    }

    cache.total_revalidations++;
    dec.kind = LookupResultKind.Revalidate;
    dec.entry_idx = matched_idx;
    dec.conditional_headers = build_revalidation_headers(matched_entry);
    return dec;
}

// ---- on_response helpers ---------------------------------------------------

// Handles 304 Not Modified response by merging fresh headers into cached entry.
fn freshen_cached_entry_304(
    cache: HttpCache&,
    revalidate_entry_idx: i64,
    resp: const Response&,
    ts: const CacheTimestamps&
) -> ResponseDecision {
    var dec = ResponseDecision { .. };
    guard revalidate_entry_idx >= 0 && revalidate_entry_idx < cache.entries.len else {
        dec.kind = ResponseDecisionKind.PassThrough;
        dec.response = copy(resp);
        return dec;
    }

    var entry = &cache.entries[revalidate_entry_idx];
    let resp_304_headers = response_headers_to_map(resp);
    merge_cached_headers_304(entry.headers, resp_304_headers);

    entry.timestamps.response_time = ts.response_time;
    entry.timestamps.response_mono = ts.response_mono;
    entry.cc = parse_cache_control_headers(entry.headers, false, cache.options.ignore_cargo_cult);

    lru_touch(cache, revalidate_entry_idx);
    entry_to_response(cache.entries[revalidate_entry_idx], ts.response_time, dec.response);
    dec.kind = ResponseDecisionKind.FreshenAndReturn;
    dec.entry_idx = revalidate_entry_idx;
    return dec;
}

// Evaluates whether a network response is permissible for storage under RFC 9111 rules.
fn is_response_cacheable(
    cache: const HttpCache&,
    req_cc: const CacheControl&,
    req_headers: const HeaderMap&,
    resp: const Response&,
    resp_cc: const CacheControl&
) -> bool {
    if is_no_store(req_cc) || is_no_store(resp_cc) { return false; }
    if is_must_understand(resp_cc) && !is_heuristically_cacheable_status(resp.status_code) { return false; }

    if cache.options.shared {
        if is_private(resp_cc) && resp_cc.private_fields.len == 0 && !cache.options.cache_private {
            return false;
        }
        if request_has_authorization(req_headers) {
            let auth_ok = is_public(resp_cc) || is_must_revalidate(resp_cc) || has_s_maxage(resp_cc);
            if !auth_ok { return false; }
        }
    }

    return resp.body.len <= cache.options.max_entry_size;
}

// Stores or updates a cached entry using O(1) LRU insertion and eviction.
fn upsert_cache_entry(cache: HttpCache&, entry: CachedEntry, req_headers: const HeaderMap&) -> i64 {
    for idx in cache.entries.len {
        if cache.entries[idx].url_hash == entry.url_hash &&
           cache.entries[idx].url[..] == entry.url[..] &&
           matches_vary(cache.entries[idx].vary, req_headers) {
            cache.entries[idx] = entry;
            lru_touch(cache, idx);
            return idx;
        }
    }

    if cache.entries.len < 64 {
        cache.entries.push(entry);
        let new_idx = (cache.entries.len - 1) as i32;
        lru_push_front(cache, new_idx);
        return new_idx;
    }

    // Evict LRU tail in O(1) without shifting any elements
    let victim_idx = cache.lru_tail;
    lru_detach(cache, victim_idx);
    cache.entries[victim_idx] = entry;
    lru_push_front(cache, victim_idx);
    return victim_idx;
}

// ---- on_response handler (store, freshen 304, or passthrough) ---------------

// Coordinates post-network response caching, 304 revalidations, and unsafe invalidations (RFC 9111).
fn on_response(
    cache: HttpCache&,
    req: const Request&,
    resp: const Response&,
    ts: const CacheTimestamps&,
    revalidate_entry_idx: i64 = -1
) -> ResponseDecision {
    var dec = ResponseDecision { response: copy(resp), .. };

    let is_get = eq_ascii_fold(req.method[..], "GET");
    let is_head = eq_ascii_fold(req.method[..], "HEAD");
    let is_unsafe = eq_ascii_fold(req.method[..], "POST") || eq_ascii_fold(req.method[..], "PUT") ||
                    eq_ascii_fold(req.method[..], "DELETE") || eq_ascii_fold(req.method[..], "PATCH");

    if is_unsafe && resp.status_code >= 200 && resp.status_code < 400 {
        check_invalidation(cache, req, resp);
        dec.kind = ResponseDecisionKind.PassThrough;
        return dec;
    }

    if resp.status_code == 304 {
        return freshen_cached_entry_304(cache, revalidate_entry_idx, resp, ts);
    }

    guard is_get || is_head else {
        dec.kind = ResponseDecisionKind.PassThrough;
        return dec;
    }

    let req_headers = request_headers_to_map(req);
    let req_cc = parse_cache_control_headers(req_headers, true, cache.options.ignore_cargo_cult);
    let resp_headers = response_headers_to_map(resp);
    let resp_cc = parse_cache_control_headers(resp_headers, false, cache.options.ignore_cargo_cult);

    guard is_response_cacheable(cache, req_cc, req_headers, resp, resp_cc) else {
        dec.kind = ResponseDecisionKind.PassThrough;
        return dec;
    }

    let vary_snap = record_vary_snapshot(get_header(resp_headers, "vary"), req_headers);
    guard !vary_snap.has_star else {
        dec.kind = ResponseDecisionKind.PassThrough;
        return dec;
    }

    var sanitized = new_header_map();
    sanitize_for_storage(resp_headers, sanitized, cache.options.shared, resp_cc);

    let lm_raw = get_header(resp_headers, "last-modified");
    var lm_time = Time { .. };
    if lm_raw.len > 0 {
        let p_lm, ok_lm = parse_http_date(lm_raw);
        if ok_lm { lm_time = p_lm; }
    }

    var entry = new_cached_entry();
    entry.url_hash = hash_fnv1a(req.url[..]);
    entry.url.append(req.url[..]);
    entry.method.append(req.method[..]);
    entry.status_code = resp.status_code;
    entry.headers = sanitized;
    entry.cc = resp_cc;
    entry.etag = parse_etag(get_header(resp_headers, "etag"));
    entry.last_modified = lm_time;
    entry.timestamps = ts;
    entry.vary = vary_snap;
    entry.body.append(resp.body[..]);
    entry.head_only = is_head;
    entry.security_zeroed = false;
    entry.is_valid = true;

    let store_idx = upsert_cache_entry(cache, entry, req_headers);
    cache.total_stores++;
    dec.kind = ResponseDecisionKind.StoreAndReturn;
    dec.entry_idx = store_idx;
    return dec;
}

// ---- invalidation cascade (rfc 9111 section 4.4) ---------------------------

// Invalidates all cached entries whose URL matches target_url.
fn invalidate_matching_url(cache: HttpCache&, target_url: const u8[:]) -> i64 {
    var count: i64 = 0;
    let target_hash = hash_fnv1a(target_url);
    for idx in cache.entries.len {
        if cache.entries[idx].is_valid &&
           cache.entries[idx].url_hash == target_hash &&
           cache.entries[idx].url[..] == target_url {
            cache.entries[idx].is_valid = false;
            cache.entries[idx].security_zeroed = true;
            lru_detach(cache, idx as i32);
            count++;
        }
    }
    return count;
}

// Invalidates stored responses on unsafe method completion (POST, PUT, DELETE, PATCH).
// Invalidates the request URI and any same-origin Location and Content-Location URIs (RFC 9111 §4.4).
fn check_invalidation(cache: HttpCache&, req: const Request&, resp: const Response&) -> i64 {
    var count = invalidate_matching_url(cache, req.url[..]);

    let loc_raw = header(resp, "Location");
    if loc_raw.len > 0 && is_same_origin_url(loc_raw, req.url[..]) {
        count += invalidate_matching_url(cache, loc_raw);
    }

    let cl_raw = header(resp, "Content-Location");
    if cl_raw.len > 0 && is_same_origin_url(cl_raw, req.url[..]) {
        count += invalidate_matching_url(cache, cl_raw);
    }

    cache.total_invalidations += count;
    return count;
}
