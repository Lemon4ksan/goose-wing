// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Internal helpers for `http` (http/cache/store_internal.goose).
namespace http_internal;

import std;
import core;
import rfc.http;
import http.cache.cache_control;
import http.cache.cache_groups;
import http.cache.engine;
import http.cache.freshness;
import http.cache.validators;
import http.cache.internal;
import http.headers;
import http.novarysearch;
import http.request;
import http.response;
import http.status_diagnostics;
import http.targeted_cache;

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
        dec.status_code = rfc::STATUS_GATEWAY_TIMEOUT;
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

fn has_explicit_cacheability(
    options: const http::CacheOptions&,
    resp:    const http::Response&,
    resp_cc: const http::CacheControl&,
) -> bool {
    return http::has_max_age(resp_cc) ||
        (options.shared && http::has_s_maxage(resp_cc)) ||
        (!options.shared && http::is_private(resp_cc)) ||
        http::is_public(resp_cc) || resp.header("Expires").len > 0;
}

fn is_shared_cache_permitted(
    options:     const http::CacheOptions&,
    req_headers: const http::HeaderMap&,
    resp:        const http::Response&,
    resp_cc:     const http::CacheControl&,
) -> bool {
    guard options.shared else { return true; }
    let priv_blocked = resp_cc.is_private() &&
        (resp_cc.private_overflow || resp_cc.private_fields.len == 0) &&
        !options.cache_private;
    if priv_blocked { return false; }
    let has_set_cookie = resp.header("Set-Cookie").len > 0 || resp.header("Set-Cookie2").len > 0;
    if has_set_cookie && !resp_cc.is_public() && !options.cache_set_cookie {
        return false;
    }
    if request_has_authorization(req_headers) {
        return resp_cc.is_public() || resp_cc.is_must_revalidate() || resp_cc.has_s_maxage();
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
    if !rfc::is_heuristically_cacheable_status(resp.status_code) && !has_explicit_cacheability(options, resp, resp_cc) {
        return false;
    }
    guard is_shared_cache_permitted(options, req_headers, resp, resp_cc) else { return false; }
    guard resp.body.len <= 4096 else { return false; }
    return resp.body.len <= options.max_entry_size;
}

fn entry_matches_cache_slot(
    existing:    const http::CachedEntry&,
    entry:       const http::CachedEntry&,
    req_headers: const http::HeaderMap&,
) -> bool {
    let exact_match = existing.url_hash == entry.url_hash && existing.url[..] == entry.url[..];
    let nvs_match = http::are_urls_nvs_equivalent(existing.url[..], entry.url[..], existing.nvs) ||
        http::are_urls_nvs_equivalent(existing.url[..], entry.url[..], entry.nvs);
    return (exact_match || nvs_match) && existing.vary.matches_vary(req_headers);
}

// Stores or updates a cached entry using O(1) LRU insertion and eviction.
fn upsert_cache_entry(
    cache:       http::Cache&,
    entry:       const http::CachedEntry&,
    req_headers: const http::HeaderMap&,
) -> i64 {
    for &existing, idx in cache.entries {
        guard entry_matches_cache_slot(existing, entry, req_headers) else { continue; }
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

    // Reuse any invalidated slot before expanding or evicting live entries
    for &slot, idx in cache.entries {
        if !slot.is_valid {
            slot = entry;
            lru_push_front(cache, idx as i32);
            return idx;
        }
    }

    if cache.entries.try_push(entry) {
        let new_idx = core::sub_sat_i64(cache.entries.len, 1) as i32;
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
    canon_url:    const u8[:],
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
        url_hash:          hash_fnv1a(canon_url),
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
    entry.url.append(canon_url);
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
    base_orig:  const core::Origin&,
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
    var canon_buf: u8[..2048] = [];
    let target_url = if canonicalize_cache_url(req.url[..], canon_buf) { canon_buf[..] } else { req.url[..] };
    invalidate_scalable_matching_url(cache, target_url);
    let base_url, err_b = core::parse_url(target_url);
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
    let evicted_by_cc = entry.cc.is_no_store() ||
        (cache.options.shared && entry.cc.is_private() && !cache.options.cache_private &&
         entry.cc.private_fields.len == 0);
    if !refresh_entry_vary_and_nvs(entry, req.headers) || evicted_by_cc {
        entry.is_valid = false;
        entry.security_zeroed = true;
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
