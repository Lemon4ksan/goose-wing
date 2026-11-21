// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Internal helpers for `http` (http/cache/internal.goose).
namespace http_internal;

import std;
import core;
import http.cache.cache_control;
import http.cache.cache_groups;
import http.cache.engine;
import http.cache.freshness;
import http.cache.validators;
import http.headers;
import http.novarysearch;
import http.request;
import http.response;
import http.status_diagnostics;
import http.targeted_cache;

// ---- http/cache/cache_control.goose internal helpers ----

// Extracts comma-separated or quoted field names into an inline fixed-capacity array.
//
// Example:
//   raw_val = "\"Set-Cookie\", \"Private-Token\""
//   appends names to out_fields, sets overflow=false
fn parse_field_names(raw_val: const u8[:], out_fields: u8[..64][..16]&, overflow: bool&) {
    let s = raw_val.trim_lws().trim_byte('"').trim_lws();
    guard s.len > 0 else {
        overflow = true;
        return;
    }

    var added_any = false;
    var tok = core::make_byte_tokenizer(s, ',');
    loop {
        let name_tok, ok = tok.token_next();
        guard ok else { break; }
        let trimmed_name = name_tok.trim_lws();
        if trimmed_name.len == 0 {
            continue;
        }
        if !http::is_valid_header_name(trimmed_name) {
            overflow = true;
            return;
        }
        var buf: u8[..64] = [];
        if !buf.try_set(trimmed_name) || !out_fields.try_push(buf) {
            overflow = true;
        }
        added_any = true;
    }
    if !added_any {
        overflow = true;
    }
}

// Applies boolean or field-list Cache-Control directives.
fn apply_cache_control_boolean(name: const u8[:], val: const u8[:], cc: http::CacheControl&) -> bool {
    if name.eq_ascii_fold("no-store") {
        if val != "?0" {
            cc.flags |= http::CC_NO_STORE;
        }
        return true;
    }
    if name.eq_ascii_fold("no-cache") {
        if val == "?0" { return true; }
        cc.flags |= http::CC_NO_CACHE;
        if val.len > 0 && val != "?1" {
            let v_trim = val.trim_lws();
            if v_trim[0] == '"' && (v_trim.len < 2 || v_trim[v_trim.len - 1] != '"') {
                cc.no_cache_overflow = true;
                return true;
            }
            let s = v_trim.trim_byte('"').trim_lws();
            if s.len > 0 {
                parse_field_names(val, cc.no_cache_fields, cc.no_cache_overflow);
            } else {
                cc.no_cache_overflow = true;
            }
        } else {
            cc.no_cache_overflow = true;
        }
        return true;
    }
    if name.eq_ascii_fold("must-revalidate") {
        if val != "?0" { cc.flags |= http::CC_MUST_REVALIDATE; }
        return true;
    }
    if name.eq_ascii_fold("proxy-revalidate") {
        if val != "?0" { cc.flags |= http::CC_PROXY_REVALIDATE; }
        return true;
    }
    if name.eq_ascii_fold("must-understand") {
        if val != "?0" { cc.flags |= http::CC_MUST_UNDERSTAND; }
        return true;
    }
    if name.eq_ascii_fold("public") {
        if val != "?0" { cc.flags |= http::CC_PUBLIC; }
        return true;
    }
    if name.eq_ascii_fold("private") {
        if val == "?0" { return true; }
        cc.flags |= http::CC_PRIVATE;
        if val.len > 0 && val != "?1" {
            let v_trim = val.trim_lws();
            if v_trim[0] == '"' && (v_trim.len < 2 || v_trim[v_trim.len - 1] != '"') {
                cc.private_overflow = true;
                return true;
            }
            let s = v_trim.trim_byte('"').trim_lws();
            if s.len > 0 {
                parse_field_names(val, cc.private_fields, cc.private_overflow);
            } else {
                cc.private_overflow = true;
            }
        } else {
            cc.private_overflow = true;
        }
        return true;
    }
    if name.eq_ascii_fold("immutable") {
        if val != "?0" { cc.flags |= http::CC_IMMUTABLE; }
        return true;
    }
    if name.eq_ascii_fold("only-if-cached") {
        if val != "?0" { cc.flags |= http::CC_ONLY_IF_CACHED; }
        return true;
    }
    if name.eq_ascii_fold("no-transform") {
        if val != "?0" { cc.flags |= http::CC_NO_TRANSFORM; }
        return true;
    }
    return false;
}

// Applies delta-seconds numeric Cache-Control directives.
fn apply_cache_control_numeric(name: const u8[:], val: const u8[:], cc: http::CacheControl&) -> bool {
    if name.eq_ascii_fold("max-age") {
        let secs, ok = http::parse_delta_seconds(val);
        if ok { cc.flags |= http::CC_HAS_MAX_AGE; cc.max_age = secs; }
        else { cc.flags |= http::CC_INVALID_FRESHNESS; }
        return true;
    }
    if name.eq_ascii_fold("s-maxage") {
        let secs, ok = http::parse_delta_seconds(val);
        if ok { cc.flags |= http::CC_HAS_S_MAXAGE; cc.s_maxage = secs; }
        else { cc.flags |= http::CC_INVALID_FRESHNESS; }
        return true;
    }
    if name.eq_ascii_fold("max-stale") {
        if val.len > 0 {
            let secs, ok = http::parse_delta_seconds(val);
            if ok {
                cc.flags |= http::CC_HAS_MAX_STALE;
                cc.max_stale = secs;
            }
        } else {
            cc.flags |= http::CC_HAS_MAX_STALE;
            cc.max_stale = -1;
        }
        return true;
    }
    if name.eq_ascii_fold("min-fresh") {
        let secs, ok = http::parse_delta_seconds(val);
        if ok { cc.flags |= http::CC_HAS_MIN_FRESH; cc.min_fresh = secs; }
        else { cc.flags |= http::CC_INVALID_FRESHNESS; }
        return true;
    }
    if name.eq_ascii_fold("stale-while-revalidate") {
        let secs, ok = http::parse_delta_seconds(val);
        if ok { cc.flags |= http::CC_STALE_WHILE_REVALIDATE; cc.stale_while_revalidate = secs; }
        return true;
    }
    if name.eq_ascii_fold("stale-if-error") {
        let secs, ok = http::parse_delta_seconds(val);
        if ok { cc.flags |= http::CC_STALE_IF_ERROR; cc.stale_if_error = secs; }
        return true;
    }
    return false;
}

// Dispatches a single name[=value] directive token.
fn apply_directive(name: const u8[:], val: const u8[:], cc: http::CacheControl&, ignore_cargo_cult: bool) {
    if apply_cache_control_boolean(name, val, cc) { return; }
    if apply_cache_control_numeric(name, val, cc) { return; }
    if ignore_cargo_cult && (name.eq_ascii_fold("pre-check") || name.eq_ascii_fold("post-check")) {
        // Legacy IE directives safely ignored
    }
}

// ---- http/cache/engine.goose internal helpers ----

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

inline fn advance_monotonic_for_age(cur_ts: http::CacheTimestamps&, cur_now_sec: i64, orig_now_sec: i64) {
    if cur_ts.has_monotonic {
        let diff_sec = cur_now_sec - orig_now_sec;
        if diff_sec > 0 {
            cur_ts.now_mono_ns = core::add_sat_u64(cur_ts.now_mono_ns, (diff_sec as u64) * 1000000000);
        }
    }
}

// Converts a CachedEntry to an application Response, attaching calculated Age header (RFC 9111 §5.1).
// Returns false if buffer capacities are exceeded (Invariant 13).
fn entry_to_response(entry: const http::CachedEntry&, cur_now_sec: i64, out_resp: http::Response&) -> bool {
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
            guard http::append_header(out_resp.headers, h_name, h_val) else { return false; }
        }
    }

    var cur_ts = entry.timestamps;
    cur_ts.now_sec = cur_now_sec;
    advance_monotonic_for_age(cur_ts, cur_now_sec, entry.timestamps.now_sec);
    let date_raw = entry.headers.get_header("date");
    var date_sec = cur_ts.response_sec;
    if date_raw.len > 0 {
        let d, ok_d = core::parse_http_date(date_raw);
        if ok_d { date_sec = core::unix(d); }
    }
    let apparent_age = http::compute_apparent_age(cur_ts.response_sec, date_sec);
    let orig_age = http::parse_age_header(entry.headers.get_header("age"));
    let cur_age = http::compute_current_age(apparent_age, orig_age, cur_ts);

    var age_str: u8[..64] = [];
    format(age_str, cur_age);
    guard http::append_header(out_resp.headers, "Age", age_str[..]) else { return false; }

    out_resp.body.clear();
    out_resp.body.append(entry.body[..]);
    return true;
}

inline fn try_acquire_matching_slot(slot: http::WriterSlot&, now_ms: i64, eff_timeout: i64) -> bool {
    if slot.active && slot.status == http::CacheLockStatus.Waiting {
        let elapsed = core::sub_sat_i64(now_ms, slot.acquired_at_ms);
        guard elapsed >= slot.age_timeout_ms else { return false; }
        slot.status = http::CacheLockStatus.Waiting;
        slot.acquired_at_ms = now_ms;
        slot.age_timeout_ms = eff_timeout;
        slot.stale_writer = true;
        return true;
    }
    if slot.status == http::CacheLockStatus.GiveUp {
        return true;
    }
    slot.active = true;
    slot.acquired_at_ms = now_ms;
    slot.age_timeout_ms = eff_timeout;
    slot.status = http::CacheLockStatus.Waiting;
    slot.stale_writer = false;
    return true;
}

fn find_active_writer_flight(writers: const http::CacheWriters&, key: const u8[:]) -> i64 {
    for &flight, idx in writers.flights {
        if flight.is_active && flight.key[..] == key {
            return idx;
        }
    }
    return -1;
}

fn finalize_inflight_cache_writer(
    writers:             http::CacheWriters&,
    method:              const u8[:],
    url:                 const u8[:],
    stored_or_freshened: bool,
    status_code:         i32,
) {
    guard method.eq_ascii_fold("GET") || method.eq_ascii_fold("HEAD") else { return; }
    let flight_idx = find_active_writer_flight(writers, url);
    if flight_idx >= 0 {
        if stored_or_freshened {
            writers.finish_writer(flight_idx);
        } else {
            writers.abort_writer(flight_idx);
        }
    }
    let is_5xx = status_code >= 500 && status_code < 600;
    let lock_status = if is_5xx && !stored_or_freshened {
        http::CacheLockStatus.TransientError
    } else if stored_or_freshened {
        http::CacheLockStatus.Done
    } else {
        http::CacheLockStatus.GiveUp
    };
    writers.release_with_status(hash_fnv1a(url), lock_status);
}

// Detaches entry at idx from the intrusive LRU list without copying struct data.
fn lru_detach(cache: http::Cache&, idx: i32) {
    guard idx >= 0 && idx < cache.entries.len else { return; }
    let p = cache.entries[idx as i64].prev_lru;
    let n = cache.entries[idx as i64].next_lru;
    if p >= 0 { cache.entries[p as i64].next_lru = n; } else { cache.lru_head = n; }
    if n >= 0 { cache.entries[n as i64].prev_lru = p; } else { cache.lru_tail = p; }
    cache.entries[idx as i64].prev_lru = -1;
    cache.entries[idx as i64].next_lru = -1;
}

// Pushes entry at idx to the MRU head of the intrusive LRU list in O(1).
fn lru_push_front(cache: http::Cache&, idx: i32) {
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
fn lru_touch(cache: http::Cache&, idx: i64) {
    lru_detach(cache, idx as i32);
    lru_push_front(cache, idx as i32);
}

// Returns a copy of response headers with `status_code` populated.
fn response_headers_to_map(resp: const http::Response&) -> http::HeaderMap {
    var map = copy(resp.headers);
    map.status_code = resp.status_code;
    return map;
}

// Checks if request contains Authorization or Proxy-Authorization.
fn request_has_authorization(req_headers: const http::HeaderMap&) -> bool {
    return req_headers.has_header("authorization") || req_headers.has_header("proxy-authorization");
}

// Searches cache entries for matching URL and valid Vary variant.
// Returns entry index or -1 on miss.
fn find_matching_entry(
    entries:     const http::CachedEntry[:],
    req_url:     const u8[:],
    req_hash:    u32,
    req_headers: const http::HeaderMap&,
    is_get:      bool,
) -> i64 {
    var matched_idx:      i64 = -1;
    var newest_date_unix: i64 = -1;

    for &entry, idx in entries {
        if !entry.is_valid || entry.security_zeroed { continue; }
        let exact_match = entry.url_hash == req_hash && entry.url[..] == req_url;
        if !exact_match && !http::are_urls_nvs_equivalent(entry.url[..], req_url, entry.nvs) { continue; }
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

fn populate_cached_206_response(entry: const http::CachedEntry&, first_pos: i64, last_pos: i64, resp: http::Response&) {
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

fn apply_cached_range_if_requested(entry: const http::CachedEntry&, req: const http::Request&, resp: http::Response&) {
    guard entry.status_code == 200 && req.method[..].eq_ascii_fold("GET") else { return; }
    let range_hdr = req.headers.get_header("range");
    guard range_hdr.len > 0 else { return; }

    let if_range_hdr = req.headers.get_header("if-range");
    if if_range_hdr.len > 0 && !http::evaluate_cache_if_range(if_range_hdr, entry.etag, entry.last_modified_sec) {
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

fn evaluate_matched_cache_entry(
    matched_entry: const http::CachedEntry&,
    options:       const http::CacheOptions&,
    req:           const http::Request&,
    req_cc:        const http::CacheControl&,
    matched_idx:   i64,
    cur_now_sec:   i64,
    cur_mono_ns:   u64,
) -> http::LookupDecision {
    var dec = http::LookupDecision { .. };
    var ts = matched_entry.timestamps;
    ts.now_sec = cur_now_sec;
    if cur_mono_ns > 0 {
        ts.now_mono_ns = cur_mono_ns;
        ts.has_monotonic = true;
    } else {
        advance_monotonic_for_age(ts, cur_now_sec, matched_entry.timestamps.now_sec);
    }

    let metrics = http::evaluate_freshness(
        matched_entry.cc,
        req_cc,
        matched_entry.headers,
        ts,
        http::FreshnessPolicy { shared: options.shared, security_zeroed: matched_entry.security_zeroed },
        options.heuristic_fraction,
        options.immutable_min_ttl_sec,
    );

    let can_serve = (metrics.is_fresh || metrics.stale_allowed) && !metrics.requires_revalidation;
    if can_serve {
        dec.kind = http::LookupResultKind.Hit;
        dec.entry_idx = matched_idx;
        dec.revalidate_in_background = metrics.stale_while_revalidate_allowed;
        entry_to_response(matched_entry, cur_now_sec, dec.cached_response);
        apply_cached_range_if_requested(matched_entry, req, dec.cached_response);
        var cs_entry = http::CacheStatusEntry {
            hit: true,
            ttl: max(0, core::sub_sat_i64(metrics.freshness_lifetime_sec, metrics.current_age_sec)),
            ..
        };
        let cname = if options.target_name.len > 0 { options.target_name[..] } else { "GooseCache" };
        cs_entry.cache_name.try_set(cname);
        var cs_buf: u8[..256] = [];
        http::format_cache_status(cs_entry, cs_buf);
        dec.cached_response.set_header("Cache-Status", cs_buf[..]);
        return dec;
    }

    if req_cc.is_only_if_cached() {
        dec.kind = http::LookupResultKind.Fail504;
        dec.status_code = 504;
        return dec;
    }

    dec.kind = http::LookupResultKind.Revalidate;
    dec.entry_idx = matched_idx;
    dec.conditional_headers = matched_entry.build_revalidation_headers();
    return dec;
}

fn refresh_entry_vary_and_nvs(entry: http::CachedEntry&, req_headers: const http::HeaderMap&) -> bool {
    if entry.headers.has_header("vary") {
        var vary_combined: u8[..512] = [];
        guard http::get_combined(entry.headers, "vary", vary_combined, 512) else { return false; }
        entry.vary = http::record_vary_snapshot(vary_combined[..], req_headers);
        guard !entry.vary.has_star && entry.vary.valid else { return false; }
    }
    let nvs_raw = entry.headers.get_header("no-vary-search");
    if nvs_raw.len > 0 {
        let parsed_nvs, ok_nvs = http::parse_no_vary_search(nvs_raw);
        entry.nvs = if ok_nvs { parsed_nvs } else { http::NoVarySearch { .. } };
    }
    return true;
}

// Evaluates whether a network response is permissible for storage under RFC 9111 rules.
fn is_response_cacheable(
    options:     const http::CacheOptions&,
    req_cc:      const http::CacheControl&,
    req_headers: const http::HeaderMap&,
    resp:        const http::Response&,
    resp_cc:     const http::CacheControl&,
) -> bool {
    if resp.status_code == 206 || req_cc.is_no_store() { return false; }
    // RFC 9111 Section 5.2.2.3: must-understand - Overrides response no-store when status caching semantics are implemented
    if resp_cc.is_must_understand() {
        if !rfc::is_heuristically_cacheable_status(resp.status_code) { return false; }
    } else if resp_cc.is_no_store() {
        return false;
    }

    // RFC 9111 Section 3: Storing Responses in Caches - Non-default status codes require explicit freshness or cacheability directive
    if !rfc::is_heuristically_cacheable_status(resp.status_code) {
        let has_explicit = http::has_max_age(resp_cc) ||
            (options.shared && http::has_s_maxage(resp_cc)) ||
            (!options.shared && http::is_private(resp_cc)) ||
            http::is_public(resp_cc) || resp.header("Expires").len > 0;
        if !has_explicit { return false; }
    }

    if options.shared {
        let priv_blocked = resp_cc.is_private() &&
            (resp_cc.private_overflow || resp_cc.private_fields.len == 0) &&
            !options.cache_private;
        if priv_blocked {
            return false;
        }
        if request_has_authorization(req_headers) {
            let auth_ok = resp_cc.is_public() || resp_cc.is_must_revalidate() || resp_cc.has_s_maxage();
            if !auth_ok { return false; }
        }
    }

    guard resp.body.len <= 4096 else { return false; }
    return resp.body.len <= options.max_entry_size;
}

// Stores or updates a cached entry using O(1) LRU insertion and eviction.
fn upsert_cache_entry(
    cache:       http::Cache&,
    entry:       const http::CachedEntry&,
    req_headers: const http::HeaderMap&,
) -> i64 {
    for &existing, idx in cache.entries {
        let exact_match = existing.url_hash == entry.url_hash && existing.url[..] == entry.url[..];
        let nvs_match = http::are_urls_nvs_equivalent(existing.url[..], entry.url[..], existing.nvs) ||
            http::are_urls_nvs_equivalent(existing.url[..], entry.url[..], entry.nvs);
        if (exact_match || nvs_match) && existing.vary.matches_vary(req_headers) {
            if existing.is_valid && !existing.head_only && entry.head_only {
                lru_touch(cache, idx);
                return idx;
            }
            if existing.is_valid {
                lru_detach(cache, idx as i32);
            }
            existing = entry;
            lru_push_front(cache, idx as i32);
            return idx;
        }
    }

    // Reuse any invalidated slot before expanding or evicting live entries
    for &slot, idx in cache.entries {
        if !slot.is_valid {
            slot = entry;
            lru_push_front(cache, idx as i32);
            return idx;
        }
    }

    if cache.entries.try_push(entry) {
        let new_idx = (cache.entries.len - 1) as i32;
        lru_push_front(cache, new_idx);
        return new_idx;
    }

    // Evict LRU tail in O(1) without shifting any elements
    let victim_idx = cache.lru_tail;
    guard victim_idx >= 0 else { return -1; }
    lru_detach(cache, victim_idx);
    cache.entries[victim_idx as i64] = entry;
    lru_push_front(cache, victim_idx);
    return victim_idx;
}

// Evaluates RFC 5861 Section 4 stale-if-error fallback on 5xx gateway/origin errors (500, 502, 503, 504).
fn try_serve_stale_on_gateway_error(
    cache:                const http::Cache&,
    req:                  const http::Request&,
    resp:                 const http::Response&,
    ts:                   const http::CacheTimestamps&,
    revalidate_entry_idx: i64,
    dec:                  http::ResponseDecision&,
) -> bool {
    let is_gateway_error = resp.status_code == 500 || (resp.status_code >= 502 && resp.status_code <= 504);
    guard is_gateway_error && revalidate_entry_idx >= 0 && revalidate_entry_idx < cache.entries.len else {
        return false;
    }
    let entry = cache.entries[revalidate_entry_idx];
    guard entry.is_valid else { return false; }

    let req_cc = http::parse_cache_control_headers(
        req.headers,
        http::CacheControlParseOptions { is_request: true, ignore_cargo_cult: cache.options.ignore_cargo_cult },
    );
    let age_hdr = http::parse_age_header(http::get_header(entry.headers, "age"));

    var eval_ts = entry.timestamps;
    eval_ts.now_sec = ts.response_sec;
    if ts.has_monotonic {
        eval_ts.now_mono_ns = ts.response_mono_ns;
        eval_ts.has_monotonic = true;
    }

    let date_raw = http::get_header(entry.headers, "date");
    var date_sec = entry.timestamps.response_sec;
    if date_raw.len > 0 {
        let d, ok_d = core::parse_http_date(date_raw);
        if ok_d { date_sec = core::unix(d); }
    }
    let apparent = http::compute_apparent_age(entry.timestamps.response_sec, date_sec);
    let cur_age = http::compute_current_age(apparent, age_hdr, eval_ts);
    let lifetime = http::compute_freshness_lifetime(
        entry.cc, entry.headers, eval_ts, cache.options.shared,
        cache.options.heuristic_fraction, cache.options.immutable_min_ttl_sec,
    );
    let can_stale_err = evaluate_stale_if_error(
        entry.cc,
        req_cc,
        cur_age,
        lifetime,
        http::FreshnessPolicy { shared: cache.options.shared, security_zeroed: entry.security_zeroed },
    );
    guard can_stale_err else { return false; }
    dec.kind = http::ResponseDecisionKind.FreshenAndReturn;
    dec.entry_idx = revalidate_entry_idx;
    entry_to_response(entry, ts.response_sec, dec.response);
    return true;
}

// Validates Vary/No-Vary-Search metadata, sanitizes headers, and stores a cacheable GET/HEAD response.
fn store_cacheable_response(
    cache:        http::Cache&,
    req:          const http::Request&,
    resp:         const http::Response&,
    resp_headers: const http::HeaderMap&,
    resp_cc:      const http::CacheControl&,
    ts:           const http::CacheTimestamps&,
    is_head:      bool,
    dec:          http::ResponseDecision&,
) -> bool {
    var vary_snap = http::VarySnapshot { .. };
    if resp_headers.has_header("vary") {
        var vary_combined: u8[..512] = [];
        guard http::get_combined(resp_headers, "vary", vary_combined, 512) else {
            dec.kind = http::ResponseDecisionKind.PassThrough;
            return false;
        }
        vary_snap = http::record_vary_snapshot(vary_combined[..], req.headers);
        guard !vary_snap.has_star && vary_snap.valid else {
            dec.kind = http::ResponseDecisionKind.PassThrough;
            return false;
        }
    }

    var nvs_snap = http::NoVarySearch { .. };
    let nvs_raw = resp_headers.get_header("no-vary-search");
    if nvs_raw.len > 0 {
        let parsed_nvs, ok_nvs = http::parse_no_vary_search(nvs_raw);
        if ok_nvs { nvs_snap = parsed_nvs; }
    }

    var sanitized = http::HeaderMap { .. };
    resp_headers.sanitize_for_storage(sanitized, cache.options.shared, resp_cc);

    let lm_raw = resp_headers.get_header("last-modified");
    var lm_sec: i64 = 0;
    if lm_raw.len > 0 {
        let p_lm, ok_lm = core::parse_http_date(lm_raw);
        if ok_lm { lm_sec = core::unix(p_lm); }
    }

    var entry = http::CachedEntry {
        url_hash:          hash_fnv1a(req.url[..]),
        status_code:       resp.status_code,
        headers:           sanitized,
        cc:                resp_cc,
        etag:              http::parse_etag(resp_headers.get_header("etag")),
        last_modified_sec: lm_sec,
        timestamps:        ts,
        vary:              vary_snap,
        nvs:               nvs_snap,
        head_only:         is_head,
        security_zeroed:   false,
        is_valid:          true,
        ..
    };
    entry.url.append(req.url[..]);
    entry.method.append(req.method[..]);
    entry.body.append(resp.body[..]);

    let store_idx = upsert_cache_entry(cache, entry, req.headers);
    cache.total_stores = core::add_sat_i64(cache.total_stores, 1);
    var cs_store = http::CacheStatusEntry {
        stored:     true,
        fwd_status: resp.status_code,
        ..
    };
    let cname_st = if cache.options.target_name.len > 0 { cache.options.target_name[..] } else { "GooseCache" };
    cs_store.cache_name.try_set(cname_st);
    cs_store.fwd.try_set("uri-miss");
    var cs_store_buf: u8[..256] = [];
    http::format_cache_status(cs_store, cs_store_buf);
    dec.response.set_header("Cache-Status", cs_store_buf[..]);
    dec.kind = http::ResponseDecisionKind.StoreAndReturn;
    dec.entry_idx = store_idx;
    return true;
}

// Invalidates a target header URL (Location or Content-Location) if valid and same-origin.
fn invalidate_target_if_same_origin(
    cache:      http::Cache&,
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

// Detaches entry at `idx` from `ScalableHttpCache` intrusive O(1) LRU list in-place.
fn detach_scalable_lru(cache: http::ScalableCache&, idx: i32) {
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

// Attaches entry at `idx` to the MRU head of `ScalableHttpCache` intrusive O(1) LRU list.
fn attach_scalable_lru_head(cache: http::ScalableCache&, idx: i32) {
    guard idx >= 0 && idx < cache.entries.len else { return; }
    let head = cache.lru_head;
    let node .= cache.entries[idx as i64];
    node.next_lru = head;
    node.prev_lru = -1;
    if head >= 0 && head < cache.entries.len {
        cache.entries[head as i64].prev_lru = idx;
    } else {
        cache.lru_tail = idx;
    }
    cache.lru_head = idx;
}

// Promotes accessed entry at `idx` to the MRU head of `ScalableHttpCache` in O(1).
fn touch_scalable_lru(cache: http::ScalableCache&, idx: i32) {
    guard idx >= 0 && idx < cache.entries.len else { return; }
    if cache.lru_head == idx {
        return;
    }
    detach_scalable_lru(cache, idx);
    attach_scalable_lru_head(cache, idx);
}

fn try_update_existing_scalable_entry(
    cache:       http::ScalableCache&,
    entry:       const http::CachedEntry&,
    req_headers: const http::HeaderMap&,
) -> bool {
    for i in cache.entries.len {
        let existing .= cache.entries[i];
        let exact_match = existing.url_hash == entry.url_hash && existing.url[..] == entry.url[..];
        let nvs_match = http::are_urls_nvs_equivalent(existing.url[..], entry.url[..], existing.nvs) ||
            http::are_urls_nvs_equivalent(existing.url[..], entry.url[..], entry.nvs);
        if (exact_match || nvs_match) && existing.vary.matches_vary(req_headers) {
            if existing.is_valid && !existing.head_only && entry.head_only {
                touch_scalable_lru(cache, i as i32);
                return true;
            }
            if existing.is_valid {
                detach_scalable_lru(cache, i as i32);
            }
            existing = copy(entry);
            attach_scalable_lru_head(cache, i as i32);
            return true;
        }
    }
    return false;
}

fn upsert_scalable_cache_entry(
    cache:       http::ScalableCache&,
    entry:       const http::CachedEntry&,
    req_headers: const http::HeaderMap&,
) -> bool {
    if try_update_existing_scalable_entry(cache, entry, req_headers) {
        return true;
    }
    for i in cache.entries.len {
        let slot .= cache.entries[i];
        if !slot.is_valid {
            slot = copy(entry);
            attach_scalable_lru_head(cache, i as i32);
            return true;
        }
    }
    let eff_max = if cache.max_entries > 0 { cache.max_entries } else { 64 };
    if cache.entries.len < eff_max {
        let new_idx = cache.entries.len as i32;
        cache.entries.push(copy(entry));
        attach_scalable_lru_head(cache, new_idx);
        return true;
    }
    let victim_idx = cache.lru_tail;
    guard victim_idx >= 0 && victim_idx < cache.entries.len else { return false; }
    detach_scalable_lru(cache, victim_idx);
    let victim .= cache.entries[victim_idx as i64];
    victim = copy(entry);
    attach_scalable_lru_head(cache, victim_idx);
    return true;
}

fn populate_entry_validators(entry: http::CachedEntry&) {
    let etag_raw = entry.headers.get_header("etag");
    if etag_raw.len > 0 {
        entry.etag = http::parse_etag(etag_raw);
    }
    let lm_raw = entry.headers.get_header("last-modified");
    if lm_raw.len > 0 {
        let d_val, ok_d = core::parse_http_date(lm_raw);
        if ok_d { entry.last_modified_sec = core::unix(d_val); }
    }
}

fn resolve_target_cache_name(options: const http::CacheOptions&) -> const u8[:] {
    guard options.shared else { return ""; }
    if options.target_name.len > 0 {
        return options.target_name[..];
    }
    return "cdn";
}

fn invalidate_scalable_matching_url(cache: http::ScalableCache&, target_url: const u8[:]) {
    let target_hash = hash_fnv1a(target_url);
    for i in cache.entries.len {
        let entry .= cache.entries[i];
        if entry.is_valid {
            let exact = entry.url_hash == target_hash && entry.url[..] == target_url;
            let nvs_eq = entry.nvs.is_valid && http::are_urls_nvs_equivalent(entry.url[..], target_url, entry.nvs);
            if exact || nvs_eq {
                entry.is_valid = false;
                entry.security_zeroed = true;
                detach_scalable_lru(cache, i as i32);
            }
        }
    }
}

fn invalidate_scalable_on_unsafe(cache: http::ScalableCache&, req: const http::Request&, resp: const http::Response&) {
    invalidate_scalable_matching_url(cache, req.url[..]);
    let base_url, err_b = core::parse_url(req.url[..]);
    guard err_b == core::UrlParseError.None && base_url.valid else { return; }
    let base_orig = core::origin_from_url(base_url);
    let loc_hdr = resp.header("Location");
    if loc_hdr.len > 0 {
        let t_url, t_err = core::parse_url_with_base(loc_hdr, base_url);
        let same_t = t_err == core::UrlParseError.None && t_url.valid &&
            core::is_same_origin(core::origin_from_url(t_url), base_orig);
        if same_t {
            invalidate_scalable_matching_url(cache, core::href(t_url));
        }
    }
    let cloc_hdr = resp.header("Content-Location");
    if cloc_hdr.len > 0 {
        let c_url, c_err = core::parse_url_with_base(cloc_hdr, base_url);
        let same_c = c_err == core::UrlParseError.None && c_url.valid &&
            core::is_same_origin(core::origin_from_url(c_url), base_orig);
        if same_c {
            invalidate_scalable_matching_url(cache, core::href(c_url));
        }
    }
}

inline fn freshen_scalable_304_entry(
    cache:     http::ScalableCache&,
    req:       const http::Request&,
    resp:      const http::Response&,
    ts:        const http::CacheTimestamps&,
    entry_idx: i64,
    dec:       http::ResponseDecision&,
) -> bool {
    guard resp.status_code == 304 && entry_idx >= 0 && entry_idx < cache.entries.len else {
        return false;
    }
    let entry .= cache.entries[entry_idx];
    guard entry.is_valid && !entry.security_zeroed else { return false; }
    let resp_304_headers = response_headers_to_map(resp);
    entry.headers.merge_cached_headers_304(resp_304_headers);
    entry.cc = http::parse_targeted_cache_control_headers(
        entry.headers,
        resolve_target_cache_name(cache.options),
        http::CacheControlParseOptions { is_request: false, ignore_cargo_cult: cache.options.ignore_cargo_cult },
    );
    if !refresh_entry_vary_and_nvs(entry, req.headers) {
        entry.is_valid = false;
        detach_scalable_lru(cache, entry_idx as i32);
    }
    entry.timestamps = ts;
    populate_entry_validators(entry);
    if entry.is_valid {
        touch_scalable_lru(cache, entry_idx as i32);
    }
    entry_to_response(entry, ts.response_sec, dec.response);
    dec.kind = http::ResponseDecisionKind.FreshenAndReturn;
    dec.entry_idx = entry_idx;
    return true;
}

// ---- http/cache/freshness.goose internal helpers ----

// Computes freshness lifetime from Expires header relative to ref_sec (RFC 9111 §4.2.1 & §5.3).
// If Expires is "0" or invalid date format, lifetime is 0 and immediately stale (RFC 9111 §5.3 & §4.2.2).
fn compute_expires_lifetime(resp_headers: const http::HeaderMap&, ref_sec: i64) -> i64, bool {
    let expires_raw = http::get_header(resp_headers, "expires");
    let trimmed = expires_raw.trim_lws();
    guard trimmed.len > 0 else { return 0, false; }

    let exp_time, ok_exp = core::parse_http_date(trimmed);
    // RFC 9111 §5.3 & §4.2.2: An invalid date format (or "0") means immediately stale (lifetime = 0)
    // and prevents fallback to heuristic freshness from Last-Modified.
    guard ok_exp else { return 0, true; }

    let date_raw = http::get_header(resp_headers, "date");
    var base_sec = ref_sec;
    if date_raw.len > 0 {
        let d_time, ok_d = core::parse_http_date(date_raw);
        if ok_d { base_sec = core::unix(d_time); }
    }

    let diff = core::unix(exp_time) - base_sec;
    return max(0, diff), true;
}

// Computes heuristic freshness lifetime (default 10% of Date - Last-Modified) (RFC 9111 §4.2.2).
fn compute_last_modified_heuristic(
    resp_headers:       const http::HeaderMap&,
    ref_sec:            i64,
    heuristic_fraction: i64,
) -> i64 {
    guard rfc::is_heuristically_cacheable_status(resp_headers.status_code) else { return 0; }

    let lm_raw = http::get_header(resp_headers, "last-modified");
    guard lm_raw.len > 0 else { return 0; }

    let lm_time, ok_lm = core::parse_http_date(lm_raw);
    guard ok_lm else { return 0; }

    let date_raw = http::get_header(resp_headers, "date");
    var base_sec = ref_sec;
    if date_raw.len > 0 {
        let d_time, ok_d = core::parse_http_date(date_raw);
        if ok_d { base_sec = core::unix(d_time); }
    }

    let delta = base_sec - core::unix(lm_time);
    guard delta > 0 else { return 0; }

    let heuristic = (delta * heuristic_fraction) / 100;
    return max(0, heuristic);
}

// Evaluates whether serving stale response is permitted under max-stale or stale-while-revalidate.
fn evaluate_stale_allowance(
    resp_cc:     const http::CacheControl&,
    req_cc:      const http::CacheControl&,
    current_age: i64,
    lifetime:    i64,
    policy:      http::FreshnessPolicy,
    out_swr:     bool&,
) -> bool {
    out_swr = false;
    guard !http::is_max_stale_blocked(resp_cc, policy) else { return false; }
    guard current_age >= lifetime else { return false; }

    let stale_sec = current_age - lifetime;

    // 1. Client max-stale (RFC 9111 Section 5.2.1: Request Directives - Client max-stale directive)
    if http::has_max_stale(req_cc) {
        if req_cc.max_stale < 0 || stale_sec <= req_cc.max_stale {
            return true;
        }
    }

    // 2. Server stale-while-revalidate (RFC 5861 Section 3)
    if http::has_stale_while_revalidate(resp_cc) && resp_cc.stale_while_revalidate >= 0 {
        if stale_sec <= resp_cc.stale_while_revalidate {
            out_swr = true;
            return true;
        }
    }

    return false;
}

// Evaluates whether a stale cached response can be served during upstream error (RFC 5861 Section 4).
fn evaluate_stale_if_error(
    resp_cc:     const http::CacheControl&,
    req_cc:      const http::CacheControl&,
    current_age: i64,
    lifetime:    i64,
    policy:      http::FreshnessPolicy,
) -> bool {
    guard !http::is_max_stale_blocked(resp_cc, policy) else { return false; }
    guard current_age >= lifetime else { return false; }
    let stale_sec = current_age - lifetime;

    var max_sie: i32 = -1;
    if http::has_stale_if_error(req_cc) && req_cc.stale_if_error >= 0 {
        max_sie = req_cc.stale_if_error;
    } else if http::has_stale_if_error(resp_cc) && resp_cc.stale_if_error >= 0 {
        max_sie = resp_cc.stale_if_error;
    }

    if max_sie >= 0 {
        return stale_sec <= max_sie;
    }
    return false;
}

// ---- http/cache/validators.goose internal helpers ----

fn read_next_etag_token(s: const u8[:], cursor: i64&) -> const u8[:] {
    let rem = s[cursor..].trim_start_bytes(" \t,");
    cursor = s.len - rem.len;
    guard rem.len > 0 else { return ""; }

    var in_quotes = false;
    var end_idx: i64 = 0;
    while end_idx < rem.len {
        let b = rem[end_idx];
        if b == '"' {
            in_quotes = !in_quotes;
        } else if b == ',' && !in_quotes {
            break;
        }
        end_idx++;
    }
    let tag = rem[..end_idx].trim_lws();
    cursor += if end_idx < rem.len { end_idx + 1 } else { end_idx };
    return tag;
}

// Constructs a zero-initialized VarySnapshot.
// Checks if field_name already exists in recorded vary items.
fn has_vary_field(items: const http::VaryItem[..16]&, field_name: const u8[:]) -> bool {
    for &item in items {
        if item.name[..].eq_ascii_fold(field_name) { return true; }
    }
    return false;
}

// Extracts canonical header value from request headers for Vary recording.
//
// Example:
//   field_name = "Accept-Encoding", req_headers has "Accept-Encoding: gzip"
//   returns: true, out_val="gzip", is_oversized=false
fn extract_vary_value(
    req_headers:  const http::HeaderMap&,
    field_name:   const u8[:],
    out_val:      u8[..256]&,
    is_oversized: bool&,
) -> bool {
    guard http::has_header(req_headers, field_name) else { return false; }
    var val_buf: u8[..512] = [];
    let ok_c = http::get_combined(req_headers, field_name, val_buf, 512);
    guard ok_c else {
        is_oversized = true;
        return false;
    }
    let raw = val_buf[..].trim_lws();

    guard out_val.try_append(raw) else {
        is_oversized = true;
        return false;
    }
    return true;
}

// Checks whether a header must be stripped prior to storage in cache.
fn should_strip_from_cache(entry_flags: u8, name: const u8[:], shared: bool, cc: const http::CacheControl&) -> bool {
    if (entry_flags & http::HEADER_FLAG_SECURITY_STATE) != 0 ||
       name.eq_ascii_fold("strict-transport-security") ||
       name.eq_ascii_fold("x-content-type-options") ||
       name.eq_ascii_fold("x-webkit-csp") ||
       name.starts_with_fold("x-content-") ||
       name.starts_with_fold("x-webkit-") {
        return true;
    }
    if (entry_flags & http::HEADER_FLAG_CHALLENGE) != 0 ||
       name.eq_ascii_fold("www-authenticate") ||
       name.eq_ascii_fold("proxy-authenticate") {
        return true;
    }
    if shared && ((entry_flags & http::HEADER_FLAG_COOKIE_STATE) != 0 ||
       name.eq_ascii_fold("set-cookie") ||
       name.eq_ascii_fold("set-cookie2") ||
       name.eq_ascii_fold("clear-site-data")) {
        return true;
    }
    if shared && (cc.flags & http::CC_PRIVATE) != 0 {
        for &f in cc.private_fields {
            if f[..].eq_ascii_fold(name) { return true; }
        }
    }
    if (cc.flags & http::CC_NO_CACHE) != 0 {
        for &f in cc.no_cache_fields {
            if f[..].eq_ascii_fold(name) { return true; }
        }
    }
    return false;
}
