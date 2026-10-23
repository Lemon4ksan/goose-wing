// RFC 9111: HTTP Caching engine, transaction state machine, and storage coordinator.
// Implements lookup, freshness evaluation, conditional revalidation, 304 header merge,
// cascade invalidation for unsafe methods, request collapsing, and CVE defenses.
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

struct CacheOptions {
    shared: bool = false,
    cache_private: bool = false,
    heuristic_fraction: i64 = 10,
    immutable_min_ttl_sec: i64 = 31536000,
    ignore_cargo_cult: bool = true,
    max_entry_size: i64 = 65536,
}

fn new_cache_options() -> CacheOptions {
    return CacheOptions { .. };
}

// ---- cached entry model ----------------------------------------------------

struct CachedEntry {
    key: u8[..512] = [],
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
}

fn new_cached_entry() -> CachedEntry {
    return CachedEntry { .. };
}

// Formats an integer into an inline ASCII buffer
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
    if val < 0 {
        out_buf.push('-');
    }
    while pos > 0 {
        pos--;
        out_buf.push(temp[pos]);
    }
}

// Converts a CachedEntry to an application Response, attaching calculated Age header
fn entry_to_response(entry: const CachedEntry&, cur_now: Time, out_resp: Response&) {
    out_resp.status_code = entry.status_code;
    out_resp.effective_url.clear();
    out_resp.effective_url.append(entry.url[..]);
    out_resp.final_method.clear();
    out_resp.final_method.append(entry.method[..]);

    // Populate response headers from cached entry
    out_resp.headers.clear();
    for h_entry in entry.headers.entries {
        let h_name = entry.headers.raw_buf[h_entry.name_begin..h_entry.name_end];
        let h_val = entry.headers.raw_buf[h_entry.values_begin..h_entry.values_end];
        if !eq_ascii_fold(h_name, "age") {
            if out_resp.headers.len < 32 {
                let item = make_header(h_name, h_val);
                out_resp.headers.push(item);
            }
        }
    }

    // RFC 9111 Section 5.1: "A cache that sends a stored response MUST generate an Age header field"
    var cur_ts = entry.timestamps;
    cur_ts.now = cur_now;
    let date_raw = get_header(entry.headers, "date");
    var date_time = cur_ts.response_time;
    if date_raw.len > 0 {
        let d, ok_d = parse_http_date(date_raw);
        if ok_d {
            date_time = d;
        }
    }
    let apparent_age = compute_apparent_age(cur_ts.response_time, date_time);
    let orig_age = parse_age_header(get_header(entry.headers, "age"));
    let cur_age = compute_current_age(apparent_age, orig_age, cur_ts);

    var age_str: u8[..64] = [];
    format_int_buffer(age_str, cur_age);
    if out_resp.headers.len < 32 {
        let age_item = make_header("Age", age_str[..]);
        out_resp.headers.push(age_item);
    }

    // Copy body bytes
    out_resp.body.clear();
    out_resp.body.append(entry.body[..]);
}

// ---- lookup and response decisions -----------------------------------------

enum LookupResultKind {
    Hit,
    Revalidate,
    Miss,
    Fail504,
}

struct LookupDecision {
    kind: LookupResultKind = LookupResultKind.Miss,
    entry_idx: i64 = -1,
    conditional_headers: HeaderMap = HeaderMap { .. },
    status_code: i32 = 0,
    cached_response: Response = Response { .. },
}

enum ResponseDecisionKind {
    StoreAndReturn,
    FreshenAndReturn,
    PassThrough,
}

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

struct CacheWriters {
    flights: CacheWriterFlight[..16] = [],
    group: SingleflightGroup = SingleflightGroup { .. },
}

fn new_cache_writers() -> CacheWriters {
    return CacheWriters { .. };
}

// Coordinates concurrent requests for the same cache key
fn start_writer_or_join(writers: CacheWriters&, key: const u8[:]) -> bool, i64 {
    for idx in writers.flights.len {
        if writers.flights[idx].is_active && writers.flights[idx].key[..] == key {
            writers.flights[idx].waiter_count++;
            return false, idx; // Joined in-flight network transaction
        }
    }

    if writers.flights.len < 16 {
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
        return true, writers.flights.len - 1; // Leader transaction
    }

    return true, -1;
}

fn finish_writer(writers: CacheWriters&, flight_idx: i64) {
    if flight_idx >= 0 && flight_idx < writers.flights.len {
        writers.flights[flight_idx].completed = true;
        writers.flights[flight_idx].is_active = false;
        // Shift remove
        writers.flights[flight_idx] = writers.flights[writers.flights.len - 1];
        writers.flights.pop();
    }
}

fn abort_writer(writers: CacheWriters&, flight_idx: i64) {
    if flight_idx >= 0 && flight_idx < writers.flights.len {
        writers.flights[flight_idx].aborted = true;
        writers.flights[flight_idx].is_active = false;
        writers.flights[flight_idx] = writers.flights[writers.flights.len - 1];
        writers.flights.pop();
    }
}

// ---- http cache engine container -------------------------------------------

struct HttpCache {
    options: CacheOptions = CacheOptions { .. },
    entries: CachedEntry[..64] = [],
    writers: CacheWriters = CacheWriters { .. },
    total_hits: i64 = 0,
    total_misses: i64 = 0,
    total_revalidations: i64 = 0,
    total_stores: i64 = 0,
    total_invalidations: i64 = 0,
}

fn new_http_cache(options: CacheOptions = CacheOptions { .. }) -> HttpCache {
    return HttpCache {
        options: options,
        writers: new_cache_writers(),
        ..
    };
}

// Converts request headers from app Request (HeaderItem[..32]) to HeaderMap
fn request_headers_to_map(req: const Request&) -> HeaderMap {
    var map = new_header_map();
    for &h in req.headers {
        append_header(map, h.name[..], h.value[..]);
    }
    return map;
}

// Converts response headers from app Response (HeaderItem[..32]) to HeaderMap
fn response_headers_to_map(resp: const Response&) -> HeaderMap {
    var map = new_header_map();
    map.status_code = resp.status_code;
    for &h in resp.headers {
        append_header(map, h.name[..], h.value[..]);
    }
    return map;
}

// Checks if request has Authorization header
fn request_has_authorization(req_headers: const HeaderMap&) -> bool {
    return has_header(req_headers, "authorization") || has_header(req_headers, "proxy-authorization");
}

// ---- url origin comparison for invalidation defense ------------------------

// Checks whether two URLs share the same origin (scheme, host, and port)
// Prevents cross-origin cache poisoning via Location / Content-Location headers (RFC 9111 §4.4)
fn is_same_origin_url(url_a: const u8[:], url_b: const u8[:]) -> bool {
    let parsed_a, err_a = parse_url(url_a);
    let parsed_b, err_b = parse_url(url_b);
    guard err_a == UrlParseError.None && err_b == UrlParseError.None else { return false; }

    let orig_a = origin_from_url(parsed_a);
    let orig_b = origin_from_url(parsed_b);
    return is_same_origin(orig_a, orig_b);
}

// ---- lookup logic (rfc 9111 section 4) -------------------------------------

fn lookup(
    cache: HttpCache&,
    req: const Request&,
    cur_now: Time,
    cur_mono: MonotonicInstant = MonotonicInstant { .. }
) -> LookupDecision {
    var dec = LookupDecision { .. };

    // RFC 9111 §2: Only GET and HEAD methods are cacheable
    let is_get = eq_ascii_fold(req.method[..], "GET");
    let is_head = eq_ascii_fold(req.method[..], "HEAD");
    if !is_get && !is_head {
        cache.total_misses++;
        dec.kind = LookupResultKind.Miss;
        return dec;
    }

    let req_headers = request_headers_to_map(req);
    let req_cc = parse_cache_control_headers(req_headers, true, cache.options.ignore_cargo_cult);

    // Request no-store prevents serving from cache
    if is_no_store(req_cc) {
        cache.total_misses++;
        dec.kind = LookupResultKind.Miss;
        return dec;
    }

    // Search cache entries for matching URL and valid variant
    var matched_idx: i64 = -1;
    var newest_date_unix: i64 = -1;

    for idx in cache.entries.len {
        let entry = cache.entries[idx];
        if !entry.is_valid || entry.security_zeroed {
            continue;
        }

        // Match URL
        if entry.url[..] != req.url[..] {
            continue;
        }

        // HEAD response cannot satisfy GET request (RFC 9111 §4.3.5)
        if is_get && entry.head_only {
            continue;
        }

        // CVE-2026-93750 defense: Vary: * can never match
        if entry.vary.has_star {
            continue;
        }

        // Match Vary headers against incoming request
        if !matches_vary(entry.vary, req_headers) {
            continue;
        }

        // RFC 9111 §4.1: If multiple entries match, prefer the newest one by Date
        let date_raw = get_header(entry.headers, "date");
        var d_unix: i64 = 0;
        if date_raw.len > 0 {
            let d_val, ok_d = parse_http_date(date_raw);
            if ok_d {
                d_unix = unix(d_val);
            }
        }
        if d_unix >= newest_date_unix {
            newest_date_unix = d_unix;
            matched_idx = idx;
        }
    }

    // If no matching entry found in cache
    if matched_idx < 0 {
        cache.total_misses++;
        // RFC 9111 Section 5.2.1.7: only-if-cached must return 504 on cache miss
        if is_only_if_cached(req_cc) {
            dec.kind = LookupResultKind.Fail504;
            dec.status_code = 504;
            return dec;
        }
        dec.kind = LookupResultKind.Miss;
        return dec;
    }

    // Matching entry found -> evaluate freshness
    let matched_entry = cache.entries[matched_idx];
    var ts = matched_entry.timestamps;
    ts.now = cur_now;
    if cur_mono.nanos > 0 {
        ts.now_mono = cur_mono;
        ts.has_monotonic = true;
    }

    let metrics = evaluate_freshness(
        matched_entry.cc,
        req_cc,
        matched_entry.headers,
        ts,
        cache.options.shared,
        matched_entry.security_zeroed,
        cache.options.heuristic_fraction,
        cache.options.immutable_min_ttl_sec
    );

    // If response is fresh and doesn't require revalidation, or stale is allowed
    if (metrics.is_fresh && !metrics.requires_revalidation) || (metrics.stale_allowed && !metrics.requires_revalidation) {
        cache.total_hits++;
        dec.kind = LookupResultKind.Hit;
        dec.entry_idx = matched_idx;
        entry_to_response(matched_entry, cur_now, dec.cached_response);
        return dec;
    }

    // Revalidation is required
    // If request contains only-if-cached, cache CANNOT contact origin network!
    if is_only_if_cached(req_cc) {
        cache.total_misses++;
        dec.kind = LookupResultKind.Fail504;
        dec.status_code = 504;
        return dec;
    }

    // Build conditional request headers
    cache.total_revalidations++;
    dec.kind = LookupResultKind.Revalidate;
    dec.entry_idx = matched_idx;
    dec.conditional_headers = new_header_map();

    if matched_entry.etag.valid {
        // Build quoted ETag for If-None-Match
        var etag_buf: u8[..160] = [];
        if matched_entry.etag.is_weak {
            etag_buf.append("W/");
        }
        etag_buf.push('"');
        etag_buf.append(matched_entry.etag.tag[..]);
        etag_buf.push('"');
        append_header(dec.conditional_headers, "If-None-Match", etag_buf[..]);
    }

    let lm_raw = get_header(matched_entry.headers, "last-modified");
    if lm_raw.len > 0 {
        append_header(dec.conditional_headers, "If-Modified-Since", lm_raw);
    }

    return dec;
}

// ---- on_response handler (store, freshen 304, or passthrough) ---------------

fn on_response(
    cache: HttpCache&,
    req: const Request&,
    resp: const Response&,
    ts: const CacheTimestamps&,
    revalidate_entry_idx: i64 = -1
) -> ResponseDecision {
    var dec = ResponseDecision { .. };
    dec.response = copy(resp);

    let is_get = eq_ascii_fold(req.method[..], "GET");
    let is_head = eq_ascii_fold(req.method[..], "HEAD");

    // Check if unsafe method succeeded (POST, PUT, DELETE, PATCH returning 2xx or 3xx)
    let is_unsafe = eq_ascii_fold(req.method[..], "POST") ||
                    eq_ascii_fold(req.method[..], "PUT") ||
                    eq_ascii_fold(req.method[..], "DELETE") ||
                    eq_ascii_fold(req.method[..], "PATCH");

    if is_unsafe && resp.status_code >= 200 && resp.status_code < 400 {
        check_invalidation(cache, req, resp);
        dec.kind = ResponseDecisionKind.PassThrough;
        return dec;
    }

    // Handle 304 Not Modified revalidation
    if resp.status_code == 304 {
        if revalidate_entry_idx >= 0 && revalidate_entry_idx < cache.entries.len {
            var entry = &cache.entries[revalidate_entry_idx];
            let resp_304_headers = response_headers_to_map(resp);

            // RFC 9111 Section 3.2: Merge fresh headers from 304 response
            merge_cached_headers_304(entry.headers, resp_304_headers);

            // Update timestamps and re-parse Cache-Control
            entry.timestamps.response_time = ts.response_time;
            entry.timestamps.response_mono = ts.response_mono;
            entry.cc = parse_cache_control_headers(entry.headers, false, cache.options.ignore_cargo_cult);

            // Synthesize fresh response from updated cached entry
            entry_to_response(cache.entries[revalidate_entry_idx], ts.response_time, dec.response);
            dec.kind = ResponseDecisionKind.FreshenAndReturn;
            dec.entry_idx = revalidate_entry_idx;
            return dec;
        }
        dec.kind = ResponseDecisionKind.PassThrough;
        return dec;
    }

    // Only GET and HEAD responses are storable
    if !is_get && !is_head {
        dec.kind = ResponseDecisionKind.PassThrough;
        return dec;
    }

    // Check request Cache-Control
    let req_headers = request_headers_to_map(req);
    let req_cc = parse_cache_control_headers(req_headers, true, cache.options.ignore_cargo_cult);
    if is_no_store(req_cc) {
        dec.kind = ResponseDecisionKind.PassThrough;
        return dec;
    }

    // Check response Cache-Control
    let resp_headers = response_headers_to_map(resp);
    let resp_cc = parse_cache_control_headers(resp_headers, false, cache.options.ignore_cargo_cult);
    if is_no_store(resp_cc) {
        dec.kind = ResponseDecisionKind.PassThrough;
        return dec;
    }

    // RFC 9111 Section 5.2.2.3: must-understand directive
    if is_must_understand(resp_cc) && !is_heuristically_cacheable_status(resp.status_code) {
        dec.kind = ResponseDecisionKind.PassThrough;
        return dec;
    }

    // Shared cache restrictions (RFC 9111 Section 3.5 & Section 5.2.2.4)
    if cache.options.shared {
        // Unqualified private in shared cache cannot be stored
        if is_private(resp_cc) && resp_cc.private_fields.len == 0 && !cache.options.cache_private {
            dec.kind = ResponseDecisionKind.PassThrough;
            return dec;
        }

        // Authorization header restrictions (RFC 9111 Section 3.5)
        if request_has_authorization(req_headers) {
            let auth_allowed = is_public(resp_cc) || is_must_revalidate(resp_cc) || has_s_maxage(resp_cc);
            if !auth_allowed {
                dec.kind = ResponseDecisionKind.PassThrough;
                return dec;
            }
        }
    }

    // Check entry body size limit
    if resp.body.len > cache.options.max_entry_size {
        dec.kind = ResponseDecisionKind.PassThrough;
        return dec;
    }

    // Record Vary snapshot
    let vary_raw = get_header(resp_headers, "vary");
    let vary_snap = record_vary_snapshot(vary_raw, req_headers);

    // CVE-2026-93750 defense: Vary: * responses must never be stored in cache
    if vary_snap.has_star {
        dec.kind = ResponseDecisionKind.PassThrough;
        return dec;
    }

    // Prepare sanitized headers
    var sanitized_headers = new_header_map();
    sanitize_for_storage(resp_headers, sanitized_headers, cache.options.shared, resp_cc);

    // Parse ETag and Last-Modified
    let etag_raw = get_header(resp_headers, "etag");
    let etag_val = parse_etag(etag_raw);

    let lm_raw = get_header(resp_headers, "last-modified");
    var lm_time = Time { .. };
    if lm_raw.len > 0 {
        let parsed_lm, ok_lm = parse_http_date(lm_raw);
        if ok_lm {
            lm_time = parsed_lm;
        }
    }

    // Create new CachedEntry
    var entry = new_cached_entry();
    entry.url.append(req.url[..]);
    entry.method.clear();
    entry.method.append(req.method[..]);
    entry.status_code = resp.status_code;
    entry.headers = sanitized_headers;
    entry.cc = resp_cc;
    entry.etag = etag_val;
    entry.last_modified = lm_time;
    entry.timestamps = ts;
    entry.vary = vary_snap;
    entry.body.append(resp.body[..]);
    entry.head_only = is_head;
    entry.security_zeroed = false;
    entry.is_valid = true;

    // Check if replacing an existing entry for this URL and Vary match
    var store_idx: i64 = -1;
    for idx in cache.entries.len {
        if cache.entries[idx].url[..] == req.url[..] && matches_vary(cache.entries[idx].vary, req_headers) {
            store_idx = idx;
            break;
        }
    }

    if store_idx >= 0 {
        cache.entries[store_idx] = entry;
    } else if cache.entries.len < 64 {
        cache.entries.push(entry);
        store_idx = cache.entries.len - 1;
    } else {
        // Evict entry 0 (simple FIFO eviction)
        for i in 1..cache.entries.len {
            cache.entries[i - 1] = cache.entries[i];
        }
        cache.entries[cache.entries.len - 1] = entry;
        store_idx = cache.entries.len - 1;
    }

    cache.total_stores++;
    dec.kind = ResponseDecisionKind.StoreAndReturn;
    dec.entry_idx = store_idx;
    return dec;
}

// ---- invalidation cascade (rfc 9111 section 4.4) ---------------------------

// Invalidates stored responses on unsafe method completion (POST, PUT, DELETE, PATCH).
// Invalidates the request URI and any same-origin Location and Content-Location URIs.
// Applies security-zeroing so entries can never be resurrected by max-stale.
fn check_invalidation(cache: HttpCache&, req: const Request&, resp: const Response&) -> i64 {
    var count: i64 = 0;

    // 1. Invalidate request URI
    for idx in cache.entries.len {
        if cache.entries[idx].is_valid && cache.entries[idx].url[..] == req.url[..] {
            cache.entries[idx].is_valid = false;
            cache.entries[idx].security_zeroed = true;
            count++;
        }
    }

    // 2. Invalidate same-origin Location header URI if present
    let loc_raw = header(resp, "Location");
    if loc_raw.len > 0 && is_same_origin_url(loc_raw, req.url[..]) {
        for idx in cache.entries.len {
            if cache.entries[idx].is_valid && cache.entries[idx].url[..] == loc_raw {
                cache.entries[idx].is_valid = false;
                cache.entries[idx].security_zeroed = true;
                count++;
            }
        }
    }

    // 3. Invalidate same-origin Content-Location header URI if present
    let cl_raw = header(resp, "Content-Location");
    if cl_raw.len > 0 && is_same_origin_url(cl_raw, req.url[..]) {
        for idx in cache.entries.len {
            if cache.entries[idx].is_valid && cache.entries[idx].url[..] == cl_raw {
                cache.entries[idx].is_valid = false;
                cache.entries[idx].security_zeroed = true;
                count++;
            }
        }
    }

    cache.total_invalidations += count;
    return count;
}
