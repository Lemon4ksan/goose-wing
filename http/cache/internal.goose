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
