// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// In-memory cookie jar with hierarchical indexing and priority eviction
// (RFC 6265bis, CHIPS).
namespace cookie;

import std;
import core;
import .limits;
import .constants;
import .canonical;
import .psl;
import .policy;
import .parser;
import .store;
import http.headers;

// ---- canonical cookie jar container ----------------------------------------

// In-memory cookie store indexed by eTLD+1 with priority-based eviction
// and partition key isolation.
struct CanonicalCookieJar {
    max_cookies_per_domain:    i64 = cookie_internal::K_DOMAIN_MAX_COOKIES,
    target_cookies_per_domain: i64 = cookie_internal::K_DOMAIN_TARGET_COOKIES,

    quota_low:    i64 = cookie_internal::K_DOMAIN_COOKIES_QUOTA_LOW,
    quota_medium: i64 = cookie_internal::K_DOMAIN_COOKIES_QUOTA_MEDIUM,
    quota_high:   i64 = cookie_internal::K_DOMAIN_COOKIES_QUOTA_HIGH,

    max_cookies_global:    i64 = cookie_internal::K_MAX_COOKIES,
    purge_cookies_global:  i64 = cookie_internal::K_PURGE_COOKIES,
    target_cookies_global: i64 = cookie_internal::K_GLOBAL_TARGET_COOKIES,

    seq_counter: i64 = 1,

    overwritten_count:          i64  = 0,
    evicted_expired_count:      i64  = 0,
    evicted_domain_count:       i64  = 0,
    evicted_global_count:       i64  = 0,
    evicted_chips_count:        i64  = 0,
    expired_overwrite_count:    i64  = 0,
    rejected_security_count:    i64  = 0,
    strict_secure_cookies:      bool = false,
    access_update_threshold_us: i64  = cookie_internal::K_ACCESS_UPDATE_THRESHOLD_US,

    cookies: CanonicalCookie[>..] = [],
}

// Appends a new cookie directly to the jar for fluent chaining.
fn add(jar: CanonicalCookieJar&, name: const u8[:], val: const u8[:]) -> CanonicalCookie& {
    var new_cookie = CanonicalCookie { .. };
    let _ = new_cookie.name.try_set(name);
    let _ = new_cookie.value.try_set(val);
    new_cookie.creation_seq = jar.seq_counter;
    jar.seq_counter = core::add_sat_i64(jar.seq_counter, 1);
    return jar.cookies.push(new_cookie);
}

// Purges expired cookies across the jar and returns the count removed.
fn purge_expired(jar: CanonicalCookieJar&, now_us: i64) -> i64 {
    let before_count = jar.cookies.len;
    jar.cookies.retain() { !it.is_expired(now_us) };
    let evicted_count = core::sub_sat_i64(before_count, jar.cookies.len);
    jar.evicted_expired_count = core::add_sat_i64(jar.evicted_expired_count, evicted_count);
    return evicted_count;
}

// ---- selective deletion engine ---------------------------------------------

// Filter criteria for selective cookie deletion across time ranges, domains, and partitions.
struct DeletionInfo {
    start_utc:          i64       = 0,
    end_utc:            i64       = 0,
    session_only:       bool      = false,
    domain:             u8[..128] = [],
    name:               u8[..128] = [],
    partition_key:      u8[..256] = [],
    top_frame_site_key: u8[..256] = [],
    purge_non_secure:   bool      = false,
}

fn cookie_internal::cookie_matches_deletion_partition_and_security(
    cookie_val: const cookie::CanonicalCookie&,
    filter:     const cookie::DeletionInfo&,
) -> bool {
    if filter.partition_key.len > 0 && cookie_val.partition_key[..] != filter.partition_key[..] {
        return false;
    }
    if filter.top_frame_site_key.len > 0
        && cookie_val.partition_key[..] != filter.top_frame_site_key[..] {
        return false;
    }
    if filter.purge_non_secure
        && (cookie_val.secure || cookie_val.source_scheme == cookie::SourceScheme.Secure) {
        return false;
    }
    return true;
}

fn cookie_internal::cookie_matches_deletion_filter(
    cookie_val: const cookie::CanonicalCookie&,
    filter:     const cookie::DeletionInfo&,
) -> bool {
    if filter.start_utc > 0 && cookie_val.creation_utc < filter.start_utc { return false; }
    if filter.end_utc > 0 && cookie_val.creation_utc > filter.end_utc { return false; }
    if filter.session_only && cookie_val.persistent { return false; }
    if filter.name.len > 0 && cookie_val.name[..] != filter.name[..] { return false; }
    if filter.domain.len > 0 {
        let clean_filter_domain = filter.domain[..].trim_byte('.');
        let clean_cookie_domain = cookie_val.domain[..].trim_byte('.');
        if !clean_cookie_domain.eq_ascii_fold(clean_filter_domain) { return false; }
    }
    return cookie_internal::cookie_matches_deletion_partition_and_security(cookie_val, filter);
}

// Removes all cookies matching filter and returns the number of deleted cookies.
fn delete_matching(jar: CanonicalCookieJar&, filter: const DeletionInfo&) -> i64 {
    let before_count = jar.cookies.len;
    jar.cookies.retain() { !cookie_internal::cookie_matches_deletion_filter(it, filter) };
    return core::sub_sat_i64(before_count, jar.cookies.len);
}

// Removes cookies with creation_utc in [start_utc, end_utc] (or >= start_utc when end_utc == 0).
fn delete_all_created_in_time_range(jar: CanonicalCookieJar&, start_utc: i64, end_utc: i64) -> i64 {
    let before_count = jar.cookies.len;
    jar.cookies.retain() {
        !(it.creation_utc >= start_utc && (end_utc == 0 || it.creation_utc <= end_utc))
    };
    return core::sub_sat_i64(before_count, jar.cookies.len);
}

// Removes non-persistent session cookies (and optionally non-secure cookies) and returns the count removed.
fn delete_session_cookies(jar: CanonicalCookieJar&, purge_non_secure: bool = false) -> i64 {
    let before_count = jar.cookies.len;
    jar.cookies.retain() {
        if purge_non_secure && (!it.secure && it.source_scheme != SourceScheme.Secure) {
            false
        } else {
            it.persistent
        }
    };
    return core::sub_sat_i64(before_count, jar.cookies.len);
}

// Safely inserts a pre-built CanonicalCookie through security validation, collision handling, and GC.
fn set(jar: CanonicalCookieJar&, cookie_val: const CanonicalCookie&, now_us: i64) -> bool {
    let is_sec = cookie_val.secure || (cookie_val.source_scheme == SourceScheme.Secure);
    return jar.set_canonical_cookie(
        cookie_val,
        SourceOptions { is_http_api: true, url_is_secure: is_sec },
        now_us,
    );
}

// Queries a cookie value by name for a specific request URL.
fn get(
    jar:           CanonicalCookieJar&,
    req_url:       const u8[:],
    name:          const u8[:],
    now_us:        i64,
    access:        AccessOptions = AccessOptions { .. },
    partition_key: const u8[:]   = "",
) -> const u8[:] {
    let parsed_url = parse_canonical_cookie_url(req_url);
    guard parsed_url.host.len > 0 else { return ""; }
    var best_idx: i64  = 0;
    var has_best: bool = false;
    for &cookie_val, idx in jar.cookies {
        if cookie_val.name[..] != name { continue; }
        if !cookie_internal::cookie_matches_request(
            cookie_val,
            parsed_url.host[..], parsed_url.path[..],
            parsed_url.scheme[..], parsed_url.port,
            SourceOptions { is_http_api: true, url_is_secure: parsed_url.is_secure },
            partition_key, access, now_us,
        ) {
            continue;
        }
        if !has_best || cookie_internal::request_cookie_order_less(cookie_val, jar.cookies[best_idx]) {
            best_idx = idx;
            has_best = true;
        }
    }

    guard has_best else { return ""; }
    let delta_us = core::sub_sat_i64(now_us, jar.cookies[best_idx].last_access_utc);
    if jar.access_update_threshold_us <= 0 || delta_us >= jar.access_update_threshold_us {
        jar.cookies[best_idx].last_access_utc = now_us;
    }
    return jar.cookies[best_idx].value[..];
}

// Queries a cookie value by name globally from the jar (first match).
fn get(jar: const CanonicalCookieJar&, name: const u8[:]) -> const u8[:] {
    for &cookie_val in jar.cookies {
        if cookie_val.name[..] == name {
            return cookie_val.value[..];
        }
    }
    return "";
}

// ---- ingestion & insertion pipeline ----------------------------------------

fn cookie_internal::insert_fresh_cookie(
    jar:        cookie::CanonicalCookieJar&,
    new_cookie: const cookie::CanonicalCookie&,
    now_us:     i64,
) {
    let idx = jar.cookies.len;
    jar.cookies.push(new_cookie);
    let slot .= jar.cookies[idx];
    if slot.creation_utc <= 0 { slot.creation_utc = now_us; }
    if slot.last_update_utc <= 0 { slot.last_update_utc = now_us; }
    if slot.last_access_utc <= 0 { slot.last_access_utc = now_us; }
    slot.creation_seq = jar.seq_counter;
    jar.seq_counter = core::add_sat_i64(jar.seq_counter, 1);
}

// Inserts new_cookie into jar, enforcing prefix rules, origin security,
// overwrite precedence, and memory quotas (RFC 6265bis Section 5.6).
fn set_canonical_cookie(
    jar:        CanonicalCookieJar&,
    new_cookie: const CanonicalCookie&,
    opts:       SourceOptions,
    now_us:     i64,
) -> bool {
    guard validate_security(new_cookie, opts) else {
        jar.rejected_security_count = core::add_sat_i64(jar.rejected_security_count, 1);
        return false;
    }

    if !opts.is_http_api && cookie_internal::has_httponly_shadowing_collision(jar, new_cookie) {
        jar.rejected_security_count = core::add_sat_i64(jar.rejected_security_count, 1);
        return false;
    }

    let collision_idx, found = cookie_internal::find_canonical_cookie_collision_index(jar, new_cookie);
    if found {
        let ok = cookie_internal::handle_cookie_collision(
            jar, new_cookie, collision_idx, opts.url_is_secure, now_us,
        );
        if ok && !new_cookie.is_expired(now_us) {
            var etld_plus_one: u8[..256] = [];
            extract_etld_plus_one(new_cookie.domain[..], etld_plus_one);
            cookie_internal::enforce_post_insertion_quotas(jar, new_cookie, etld_plus_one[..], now_us);
        }
        return ok;
    }

    if new_cookie.is_expired(now_us) {
        jar.evicted_expired_count = core::add_sat_i64(jar.evicted_expired_count, 1);
        return true;
    }

    if cookie_internal::has_secure_shadowing_collision(jar, new_cookie, opts.url_is_secure) {
        jar.rejected_security_count = core::add_sat_i64(jar.rejected_security_count, 1);
        return false;
    }

    var etld_plus_one: u8[..256] = [];
    extract_etld_plus_one(new_cookie.domain[..], etld_plus_one);

    cookie_internal::insert_fresh_cookie(jar, new_cookie, now_us);
    cookie_internal::enforce_post_insertion_quotas(jar, new_cookie, etld_plus_one[..], now_us);
    return true;
}

fn cookie_internal::assign_partition_key(
    parsed_cookie: cookie::CanonicalCookie&,
    parsed_url:    const cookie::CanonicalCookieURL&,
    partition_key: const u8[:],
) -> bool {
    if partition_key.len > 0 {
        return parsed_cookie.partition_key.try_set(partition_key);
    }
    if parsed_cookie.partition_key.len > 0 {
        return true;
    }

    let sch = if parsed_url.is_secure { "https" } else { "http" };
    var etld: u8[..128] = [];
    cookie::extract_etld_plus_one(parsed_url.host[..], etld);
    let host_part = if etld.len > 0 { etld[..] } else { parsed_url.host[..] };

    var committed = false;
    defer if !committed { parsed_cookie.partition_key.clear(); };
    guard parsed_cookie.partition_key.try_set(sch)
        && parsed_cookie.partition_key.try_append("://")
        && parsed_cookie.partition_key.try_append(host_part) else {
        return false;
    }
    committed = true;
    return true;
}

// Ingests a raw Set-Cookie header directly for a given request URL.
//
// Enforces prefix requirements (__Host-/__Secure-), rejects control characters,
// caps name+value at 4,096 bytes, preserves creation_utc on overwrite, and
// treats loopback endpoints as trustworthy secure contexts.
fn set_cookie_header(
    jar:            CanonicalCookieJar&,
    req_url:        const u8[:],
    set_cookie_raw: const u8[:],
    now_us:         i64,
    is_http_api:    bool        = true,
    partition_key:  const u8[:] = "",
) -> bool {
    let parsed_url = parse_canonical_cookie_url(req_url);
    guard parsed_url.host.len > 0 else { return false; }
    var def_path: u8[..256] = [];
    compute_default_path(parsed_url.path[..], def_path);

    var parsed_cookie, cause, ok = parse_canonical_set_cookie(
        set_cookie_raw, parsed_url.host[..], def_path[..], now_us,
    );
    guard ok else { return false; }

    if parsed_cookie.partitioned {
        guard cookie_internal::assign_partition_key(parsed_cookie, parsed_url, partition_key) else {
            return false;
        }
    }

    cookie_internal::adjust_origin_bound_cookies_on_insert(
        parsed_cookie, parsed_url.host[..], parsed_url.port, parsed_url.is_secure,
    );
    let effective_secure = parsed_url.is_secure || is_trustworthy_non_crypto_host(parsed_url.host[..]);
    return jar.set_canonical_cookie(
        parsed_cookie,
        SourceOptions { is_http_api: is_http_api, url_is_secure: effective_secure },
        now_us,
    );
}

// Ingests a raw Set-Cookie header for req_url with an explicit CHIPS partition key.
fn set_cookie_header(
    jar:            CanonicalCookieJar&,
    req_url:        const u8[:],
    set_cookie_raw: const u8[:],
    now_us:         i64,
    partition_key:  const u8[:],
) -> bool {
    return jar.set_cookie_header(req_url, set_cookie_raw, now_us, true, partition_key);
}

// ---- outgoing request routing & serialization ------------------------------

// Formats an outgoing HTTP Cookie header for the specified endpoint into out.
fn build_cookie_header<B>(
    jar:       CanonicalCookieJar&,
    host:      const u8[:],
    path:      const u8[:],
    is_secure: bool,
    now_us:    i64,
    out:       B&,
) {
    var matched_indices: u16[..180] = [];
    jar.get_canonical_cookies_for_request(
        host, path,
        if is_secure { "https" } else { "http" },
        if is_secure { 443 } else { 80 },
        SourceOptions { is_http_api: true, url_is_secure: is_secure },
        "", now_us, matched_indices,
    );
    cookie_internal::format_cookie_header_from_indices(jar, matched_indices[..], out);
}

// Formats an outgoing HTTP Cookie header directly from a request URL into out.
fn build_cookie_header<B>(
    jar:     CanonicalCookieJar&,
    req_url: const u8[:],
    now_us:  i64,
    out:     B&,
) {
    jar.build_cookie_header(req_url, now_us, "", out);
}

// Formats an outgoing HTTP Cookie header for a request URL and partition key into out.
fn build_cookie_header<B>(
    jar:           CanonicalCookieJar&,
    req_url:       const u8[:],
    now_us:        i64,
    partition_key: const u8[:],
    out:           B&,
) {
    let parsed_url = parse_canonical_cookie_url(req_url);
    guard parsed_url.host.len > 0 else { return; }
    var matched_indices: u16[..180] = [];
    jar.get_canonical_cookies_for_request(
        parsed_url.host[..],
        parsed_url.path[..],
        parsed_url.scheme[..],
        parsed_url.port,
        SourceOptions { is_http_api: true, url_is_secure: parsed_url.is_secure },
        partition_key,
        now_us,
        matched_indices,
    );
    cookie_internal::format_cookie_header_from_indices(jar, matched_indices[..], out);
}

// Formats an outgoing HTTP Cookie header with explicit is_http_api and partition_key into out.
fn build_request_cookie_header<B>(
    jar:           CanonicalCookieJar&,
    req_url:       const u8[:],
    is_http_api:   bool,
    partition_key: const u8[:],
    now_us:        i64,
    out:           B&,
) {
    let parsed_url = parse_canonical_cookie_url(req_url);
    guard parsed_url.host.len > 0 else { return; }
    var matched_indices: u16[..180] = [];
    jar.get_canonical_cookies_for_request(
        parsed_url.host[..],
        parsed_url.path[..],
        parsed_url.scheme[..],
        parsed_url.port,
        SourceOptions { is_http_api: is_http_api, url_is_secure: parsed_url.is_secure },
        partition_key,
        now_us,
        matched_indices,
    );
    cookie_internal::format_cookie_header_from_indices(jar, matched_indices[..], out);
}

// Populates out_indices with matching cookie slot indices for req_url sorted per RFC 6265 Section 5.4.
fn get_canonical_cookies_for_request(
    jar:           CanonicalCookieJar&,
    req_url:       const u8[:],
    is_http_api:   bool,
    partition_key: const u8[:],
    now_us:        i64,
    out_indices:   u16[..180]&,
    access:        AccessOptions = AccessOptions { .. },
) {
    let parsed_url = parse_canonical_cookie_url(req_url);
    guard parsed_url.host.len > 0 else {
        out_indices.clear();
        return;
    }
    jar.get_canonical_cookies_for_request(
        parsed_url.host[..],
        parsed_url.path[..],
        parsed_url.scheme[..],
        parsed_url.port,
        SourceOptions { is_http_api: is_http_api, url_is_secure: parsed_url.is_secure },
        partition_key,
        now_us,
        out_indices,
        access,
    );
}

fn cookie_internal::collect_matching_cookie_indices(
    jar:           const cookie::CanonicalCookieJar&,
    host:          const u8[:],
    path:          const u8[:],
    scheme:        const u8[:],
    port:          i32,
    source:        cookie::SourceOptions,
    partition_key: const u8[:],
    now_us:        i64,
    out_indices:   u16[..180]&,
    access:        cookie::AccessOptions = cookie::AccessOptions { .. },
) {
    out_indices.clear();
    for &cookie_val, idx in jar.cookies {
        if !cookie_internal::cookie_matches_request(
            cookie_val, host, path, scheme, port,
            source, partition_key, access, now_us,
        ) {
            continue;
        }
        guard out_indices.try_push(idx as u16) else { break; }
    }
}

fn cookie_internal::stamp_accessed_cookies(
    jar:     cookie::CanonicalCookieJar&,
    indices: const u16[:],
    now_us:  i64,
) {
    for i in indices.len {
        let idx = indices[i] as i64;
        guard idx >= 0 && idx < jar.cookies.len else { continue; }
        let delta_us = core::sub_sat_i64(now_us, jar.cookies[idx].last_access_utc);
        if jar.access_update_threshold_us <= 0 || delta_us >= jar.access_update_threshold_us {
            jar.cookies[idx].last_access_utc = now_us;
        }
    }
}

fn cookie_internal::sort_cookie_indices(
    jar:         const cookie::CanonicalCookieJar&,
    out_indices: u16[..180]&,
) {
    out_indices.stable_sort() { idx_a, idx_b =>
        cookie_internal::request_cookie_order_less(jar.cookies[idx_a as i64], jar.cookies[idx_b as i64])
    };
}

// Collects matching cookie slot indices sorted by longest path then earliest creation, updating last_access_utc.
fn get_canonical_cookies_for_request(
    jar:           CanonicalCookieJar&,
    host:          const u8[:],
    path:          const u8[:],
    scheme:        const u8[:],
    port:          i32,
    source:        SourceOptions,
    partition_key: const u8[:],
    now_us:        i64,
    out_indices:   u16[..180]&,
    access:        AccessOptions = AccessOptions { .. },
) {
    cookie_internal::collect_matching_cookie_indices(
        jar, host, path, scheme, port, source, partition_key, now_us, out_indices, access,
    );
    cookie_internal::stamp_accessed_cookies(jar, out_indices[..], now_us);
    cookie_internal::sort_cookie_indices(jar, out_indices);
}

// Formats matched cookies for an outgoing HTTP request directly into headers under "Cookie".
// Returns false on capacity overflow without mutating headers.
fn encode_cookie_header_to_map(
    jar:           CanonicalCookieJar&,
    host:          const u8[:],
    path:          const u8[:],
    scheme:        const u8[:],
    port:          i32,
    source:        SourceOptions,
    partition_key: const u8[:],
    now_us:        i64,
    access:        AccessOptions,
    headers:       http::HeaderMap&,
) -> bool {
    var matched_indices: u16[..180] = [];
    cookie_internal::collect_matching_cookie_indices(
        jar, host, path, scheme, port, source, partition_key, now_us, matched_indices, access,
    );
    cookie_internal::sort_cookie_indices(jar, matched_indices);
    if matched_indices.len == 0 {
        let _ = headers.remove_header("Cookie");
        return true;
    }

    var cookie_hdr_val: u8[..8192] = [];
    for i in matched_indices.len {
        let idx = matched_indices[i] as i64;
        guard idx >= 0 && idx < jar.cookies.len else { continue; }
        guard cookie_internal::try_append_cookie_pair(
            cookie_hdr_val, jar.cookies[idx], cookie_hdr_val.len > 0,
        ) else {
            return false;
        }
    }
    if cookie_hdr_val.len == 0 {
        let _ = headers.remove_header("Cookie");
        return true;
    }
    guard headers.set_or_replace("Cookie", cookie_hdr_val[..], true) else {
        return false;
    }
    cookie_internal::stamp_accessed_cookies(jar, matched_indices[..], now_us);
    return true;
}

// ---- quotas & garbage collection engine ------------------------------------

fn cookie_internal::garbage_collect_per_domain(
    jar:           cookie::CanonicalCookieJar&,
    etld_plus_one: const u8[:],
    now_us:        i64,
) -> i64 {
    var domain_count = cookie_internal::count_domain_cookies(jar, etld_plus_one);
    guard domain_count > jar.max_cookies_per_domain else { return 0; }

    var total_evicted: i64 = 0;
    let expired_evicted = cookie_internal::evict_domain_expired_cookies(jar, etld_plus_one, now_us);
    total_evicted = core::add_sat_i64(total_evicted, expired_evicted);
    domain_count = core::sub_sat_i64(domain_count, expired_evicted);

    if jar.strict_secure_cookies {
        let non_sec_evicted = cookie_internal::evict_domain_non_secure_cookies(jar, etld_plus_one);
        total_evicted = core::add_sat_i64(total_evicted, non_sec_evicted);
        domain_count = core::sub_sat_i64(domain_count, non_sec_evicted);
    }

    guard domain_count > jar.target_cookies_per_domain else { return total_evicted; }

    var need_to_evict = core::sub_sat_i64(domain_count, jar.target_cookies_per_domain);
    var low_excess:  i64 = 0;
    var med_excess:  i64 = 0;
    var high_excess: i64 = 0;
    cookie_internal::calculate_domain_priority_excesses(
        jar, etld_plus_one, low_excess, med_excess, high_excess,
    );

    let prio_evicted = cookie_internal::purge_domain_priority_rounds(
        jar, etld_plus_one, need_to_evict, low_excess, med_excess, high_excess,
    );
    total_evicted = core::add_sat_i64(total_evicted, prio_evicted);

    if need_to_evict > 0 {
        let fallback_evicted = cookie_internal::purge_domain_fallback(jar, etld_plus_one, need_to_evict);
        jar.evicted_domain_count = core::add_sat_i64(jar.evicted_domain_count, fallback_evicted);
        total_evicted = core::add_sat_i64(total_evicted, fallback_evicted);
    }

    return total_evicted;
}

// Executes global garbage collection across jar when count exceeds max_cookies_global.
// Cookies accessed within the last 30 days remain immune unless none are older.
fn garbage_collect_global(jar: CanonicalCookieJar&, now_us: i64) -> i64 {
    guard jar.cookies.len > jar.max_cookies_global else { return 0; }

    var total_evicted: i64 = 0;
    let expired_evicted = jar.purge_expired(now_us);
    total_evicted = core::add_sat_i64(total_evicted, expired_evicted);

    guard jar.cookies.len > jar.target_cookies_global else { return total_evicted; }

    let need_to_evict = core::sub_sat_i64(jar.cookies.len, jar.target_cookies_global);
    var non_immune_evicted = cookie_internal::evict_global_non_immune_cookies(jar, need_to_evict, now_us);
    if non_immune_evicted == 0 {
        non_immune_evicted = cookie_internal::evict_global_lru_fallback_cookies(jar, need_to_evict);
    }
    jar.evicted_global_count = core::add_sat_i64(jar.evicted_global_count, non_immune_evicted);
    total_evicted = core::add_sat_i64(total_evicted, non_immune_evicted);

    return total_evicted;
}

fn cookie_internal::enforce_chips_quota(
    jar:           cookie::CanonicalCookieJar&,
    partition_key: const u8[:],
    etld_plus_one: const u8[:],
    now_us:        i64,
) -> i64 {
    guard partition_key.len > 0 else { return 0; }

    var candidate_indices: u16[..512] = [];
    var total_bytes:       i64        = 0;
    cookie_internal::gather_chips_candidates(
        jar, partition_key, etld_plus_one, candidate_indices, total_bytes,
    );

    var rem_count = candidate_indices.len;
    let max_part_bytes = cookie_internal::K_PER_PARTITION_DOMAIN_MAX_COOKIE_BYTES;
    guard total_bytes > max_part_bytes || rem_count > jar.max_cookies_per_domain else {
        return 0;
    }

    candidate_indices.stable_sort() { idx_a, idx_b =>
        cookie_internal::chips_lra_candidate_less(
            jar.cookies[idx_a as i64], jar.cookies[idx_b as i64],
        )
    };

    var to_delete_seqs: i64[..512] = [];
    for i in candidate_indices.len {
        if total_bytes <= max_part_bytes && rem_count <= jar.max_cookies_per_domain {
            break;
        }
        let idx = candidate_indices[i] as i64;
        guard idx >= 0 && idx < jar.cookies.len else { continue; }
        let candidate_cookie .= jar.cookies[idx];
        total_bytes = core::sub_sat_i64(total_bytes, candidate_cookie.payload_size());
        rem_count = core::sub_sat_i64(rem_count, 1);
        guard to_delete_seqs.try_push(candidate_cookie.creation_seq) else { break; }
    }

    if to_delete_seqs.len > 0 {
        jar.cookies.retain() { !to_delete_seqs.contains(it.creation_seq) };
        jar.evicted_chips_count = core::add_sat_i64(jar.evicted_chips_count, to_delete_seqs.len);
    }

    return to_delete_seqs.len;
}

// ---- internal implementation helpers ---------------------------------------

fn cookie_internal::evict_top_creation_seqs<I>(
    jar:               cookie::CanonicalCookieJar&,
    candidate_indices: const I[:],
    limit:             i64,
) -> i64 {
    var to_delete_seqs: i64[..512] = [];
    let evict_count = min(limit, candidate_indices.len);
    for i in evict_count {
        let idx = candidate_indices[i] as i64;
        guard idx >= 0 && idx < jar.cookies.len else { continue; }
        guard to_delete_seqs.try_push(jar.cookies[idx].creation_seq) else { break; }
    }
    if to_delete_seqs.len > 0 {
        jar.cookies.retain() { !to_delete_seqs.contains(it.creation_seq) };
    }
    return to_delete_seqs.len;
}

fn cookie_internal::purge_domain_priority_rounds(
    jar:           cookie::CanonicalCookieJar&,
    etld_plus_one: const u8[:],
    need_to_evict: i64&,
    low_excess:    i64&,
    med_excess:    i64&,
    high_excess:   i64&,
) -> i64 {
    var evicted_count: i64 = 0;
    for round_idx in 1..7 {
        if need_to_evict <= 0 { break; }

        let target_prio, protect_sec, quota_allowed = cookie_internal::resolve_domain_purge_round_params(
            round_idx, need_to_evict, low_excess, med_excess, high_excess,
        );
        if quota_allowed <= 0 { continue; }

        let round_evicted = cookie_internal::purge_domain_priority_round(
            jar, etld_plus_one, target_prio, protect_sec, quota_allowed,
        );
        if round_evicted <= 0 { continue; }

        cookie_internal::deduct_domain_priority_excess(
            target_prio, round_evicted, low_excess, med_excess, high_excess,
        );
        jar.evicted_domain_count = core::add_sat_i64(jar.evicted_domain_count, round_evicted);
        evicted_count = core::add_sat_i64(evicted_count, round_evicted);
        need_to_evict = core::sub_sat_i64(need_to_evict, round_evicted);
    }
    return evicted_count;
}

fn cookie_internal::enforce_post_insertion_quotas(
    jar:           cookie::CanonicalCookieJar&,
    new_cookie:    const cookie::CanonicalCookie&,
    etld_plus_one: const u8[:],
    now_us:        i64,
) {
    if new_cookie.partition_key.len > 0 {
        let _ = cookie_internal::enforce_chips_quota(
            jar, new_cookie.partition_key[..], etld_plus_one, now_us,
        );
    }
    let _ = cookie_internal::garbage_collect_per_domain(jar, etld_plus_one, now_us);
    let _ = jar.garbage_collect_global(now_us);
}

fn cookie_internal::has_secure_shadowing_collision(
    jar:           const cookie::CanonicalCookieJar&,
    new_cookie:    const cookie::CanonicalCookie&,
    url_is_secure: bool,
) -> bool {
    for &existing in jar.cookies {
        if cookie_internal::would_insecure_overwrite_secure(existing, new_cookie, url_is_secure) {
            return true;
        }
    }
    return false;
}

fn cookie_internal::has_httponly_shadowing_collision(
    jar:        const cookie::CanonicalCookieJar&,
    new_cookie: const cookie::CanonicalCookie&,
) -> bool {
    for &existing in jar.cookies {
        if existing.httponly &&
            existing.name[..] == new_cookie.name[..] &&
            existing.partition_key[..] == new_cookie.partition_key[..] &&
            (cookie::domain_match(existing.domain[..], new_cookie.domain[..]) ||
             cookie::domain_match(new_cookie.domain[..], existing.domain[..])) &&
            (cookie::path_match(existing.path[..], new_cookie.path[..]) ||
             cookie::path_match(new_cookie.path[..], existing.path[..])) {
                return true;
            }
    }
    return false;
}

fn cookie_internal::gather_chips_candidates(
    jar:               const cookie::CanonicalCookieJar&,
    partition_key:     const u8[:],
    etld_plus_one:     const u8[:],
    candidate_indices: u16[..512]&,
    total_bytes:       i64&,
) {
    candidate_indices.clear();
    for &cookie_val, idx in jar.cookies {
        guard cookie_val.partitioned || cookie_val.partition_key.len > 0 else { continue; }
        guard cookie_val.partition_key[..] == partition_key else { continue; }
        guard cookie_internal::matches_effective_domain(cookie_val, etld_plus_one) else { continue; }
        total_bytes = core::add_sat_i64(total_bytes, cookie_val.payload_size());
        guard candidate_indices.try_push(idx as u16) else { break; }
    }
}

fn cookie_internal::priority_rank(priority_level: cookie::Priority) -> i32 {
    return match priority_level {
        Low => 0,
        Medium => 1,
        High => 2,
        Unknown => 1,
    };
}

fn cookie_internal::matches_effective_domain(
    cookie_val:           const cookie::CanonicalCookie&,
    target_etld_plus_one: const u8[:],
) -> bool {
    var candidate_etld: u8[..256] = [];
    cookie::extract_etld_plus_one(cookie_val.domain[..], candidate_etld);
    return candidate_etld[..].eq_ascii_fold(target_etld_plus_one);
}

// Finds an existing cookie slot matching `new_cookie`'s tuple key
// `(name, domain, path, host_only, partition_key, scheme, port)`.
//
// Example:
//   jar contains "sid=1" on example.com "/", new_cookie is "sid=2" on example.com "/"
//   returns: idx = 0, found = true
fn cookie_internal::find_canonical_cookie_collision_index(
    jar:        const cookie::CanonicalCookieJar&,
    new_cookie: const cookie::CanonicalCookie&,
) -> i64, bool {
    let clean_new_domain = new_cookie.domain[..].trim_byte('.');
    for &existing, cookie_idx in jar.cookies {
        if existing.name[..] != new_cookie.name[..] { continue; }
        if existing.host_only != new_cookie.host_only { continue; }
        if existing.path[..] != new_cookie.path[..] { continue; }
        if existing.partition_key[..] != new_cookie.partition_key[..] { continue; }
        let secure_upgrades_non_secure = new_cookie.source_scheme == cookie::SourceScheme.Secure
            && existing.source_scheme == cookie::SourceScheme.NonSecure;
        let port_match = secure_upgrades_non_secure
            || existing.source_port == -1 || new_cookie.source_port == -1
            || existing.source_port == new_cookie.source_port;
        let scheme_match = secure_upgrades_non_secure
            || existing.source_scheme == cookie::SourceScheme.Unset
            || new_cookie.source_scheme == cookie::SourceScheme.Unset
            || existing.source_scheme == new_cookie.source_scheme;
        if !port_match || !scheme_match { continue; }
        if existing.domain[..].trim_byte('.').eq_ascii_fold(clean_new_domain) {
            return cookie_idx, true;
        }
    }
    return 0, false;
}

fn cookie_internal::would_insecure_overwrite_secure(
    existing:      const cookie::CanonicalCookie&,
    new_cookie:    const cookie::CanonicalCookie&,
    url_is_secure: bool,
) -> bool {
    if !existing.secure || url_is_secure { return false; }
    if existing.name[..] != new_cookie.name[..] { return false; }
    if existing.partition_key[..] != new_cookie.partition_key[..] { return false; }

    let domain_matches = cookie::domain_match(existing.domain[..], new_cookie.domain[..])
        || cookie::domain_match(new_cookie.domain[..], existing.domain[..]);
    guard domain_matches else { return false; }

    return cookie::path_match(new_cookie.path[..], existing.path[..])
        || cookie::path_match(existing.path[..], new_cookie.path[..]);
}

fn cookie_internal::count_domain_cookies(
    jar:           const cookie::CanonicalCookieJar&,
    etld_plus_one: const u8[:],
) -> i64 {
    var count: i64 = 0;
    for &cookie_val in jar.cookies {
        if cookie_internal::matches_effective_domain(cookie_val, etld_plus_one) {
            count = core::add_sat_i64(count, 1);
        }
    }
    return count;
}

fn cookie_internal::domain_gc_candidate_less(
    cookie_a: const cookie::CanonicalCookie&,
    cookie_b: const cookie::CanonicalCookie&,
) -> bool {
    if cookie_a.secure != cookie_b.secure {
        return !cookie_a.secure;
    }
    if cookie_a.host_only != cookie_b.host_only {
        return !cookie_a.host_only;
    }
    if cookie_a.last_access_utc != cookie_b.last_access_utc {
        return cookie_a.last_access_utc < cookie_b.last_access_utc;
    }
    return cookie_a.creation_seq < cookie_b.creation_seq;
}

fn cookie_internal::global_gc_candidate_less(
    cookie_a: const cookie::CanonicalCookie&,
    cookie_b: const cookie::CanonicalCookie&,
) -> bool {
    if cookie_a.priority != cookie_b.priority {
        return cookie_internal::priority_rank(cookie_a.priority)
            < cookie_internal::priority_rank(cookie_b.priority);
    }
    return cookie_internal::domain_gc_candidate_less(cookie_a, cookie_b);
}

fn cookie_internal::chips_lra_candidate_less(
    cookie_a: const cookie::CanonicalCookie&,
    cookie_b: const cookie::CanonicalCookie&,
) -> bool {
    if cookie_a.last_access_utc != cookie_b.last_access_utc {
        return cookie_a.last_access_utc < cookie_b.last_access_utc;
    }
    return cookie_a.creation_seq < cookie_b.creation_seq;
}

fn cookie_internal::request_cookie_order_less(
    cookie_a: const cookie::CanonicalCookie&,
    cookie_b: const cookie::CanonicalCookie&,
) -> bool {
    if cookie_a.path.len != cookie_b.path.len {
        return cookie_a.path.len > cookie_b.path.len;
    }
    if cookie_a.creation_utc != cookie_b.creation_utc {
        return cookie_a.creation_utc < cookie_b.creation_utc;
    }
    return cookie_a.creation_seq < cookie_b.creation_seq;
}

fn cookie_internal::evict_domain_expired_cookies(
    jar:           cookie::CanonicalCookieJar&,
    etld_plus_one: const u8[:],
    now_us:        i64,
) -> i64 {
    let before_count = jar.cookies.len;
    jar.cookies.retain() {
        !(cookie_internal::matches_effective_domain(it, etld_plus_one) && it.is_expired(now_us))
    };
    let evicted_count = core::sub_sat_i64(before_count, jar.cookies.len);
    jar.evicted_expired_count = core::add_sat_i64(jar.evicted_expired_count, evicted_count);
    return evicted_count;
}

fn cookie_internal::evict_domain_non_secure_cookies(
    jar:           cookie::CanonicalCookieJar&,
    etld_plus_one: const u8[:],
) -> i64 {
    let before_count = jar.cookies.len;
    jar.cookies.retain() {
        !(cookie_internal::matches_effective_domain(it, etld_plus_one) && !it.secure)
    };
    let evicted_count = core::sub_sat_i64(before_count, jar.cookies.len);
    jar.rejected_security_count = core::add_sat_i64(jar.rejected_security_count, evicted_count);
    return evicted_count;
}

inline fn cookie_internal::count_cookie_priority(
    prio: cookie::Priority,
    low:  i64&,
    med:  i64&,
    high: i64&,
) {
    match prio {
        Low => { low = core::add_sat_i64(low, 1); },
        High => { high = core::add_sat_i64(high, 1); },
        _ => { med = core::add_sat_i64(med, 1); },
    };
}

fn cookie_internal::calculate_domain_priority_excesses(
    jar:           const cookie::CanonicalCookieJar&,
    etld_plus_one: const u8[:],
    low_excess:    i64&,
    med_excess:    i64&,
    high_excess:   i64&,
) {
    var low_count:  i64 = 0;
    var med_count:  i64 = 0;
    var high_count: i64 = 0;

    for &cookie_val in jar.cookies {
        if !cookie_internal::matches_effective_domain(cookie_val, etld_plus_one) { continue; }
        cookie_internal::count_cookie_priority(cookie_val.priority, low_count, med_count, high_count);
    }

    low_excess = max(0, core::sub_sat_i64(low_count, jar.quota_low));
    med_excess = max(0, core::sub_sat_i64(med_count, jar.quota_medium));
    high_excess = max(0, core::sub_sat_i64(high_count, jar.quota_high));
}

fn cookie_internal::resolve_domain_purge_round_params(
    round_idx:     i64,
    need_to_evict: i64,
    low_excess:    i64,
    med_excess:    i64,
    high_excess:   i64,
) -> cookie::Priority, bool, i64 {
    if round_idx == 1 {
        return cookie::Priority.Low, true, min(need_to_evict, low_excess);
    }
    if round_idx == 2 {
        return cookie::Priority.Low, false, min(need_to_evict, low_excess);
    }
    if round_idx == 3 {
        return cookie::Priority.Medium, true, min(need_to_evict, med_excess);
    }
    if round_idx == 4 {
        return cookie::Priority.High, true, min(need_to_evict, high_excess);
    }
    if round_idx == 5 {
        return cookie::Priority.Medium, false, min(need_to_evict, med_excess);
    }
    return cookie::Priority.High, false, min(need_to_evict, high_excess);
}

fn cookie_internal::purge_domain_priority_round(
    jar:           cookie::CanonicalCookieJar&,
    etld_plus_one: const u8[:],
    target_prio:   cookie::Priority,
    protect_sec:   bool,
    quota_allowed: i64,
) -> i64 {
    var candidate_indices: u16[..512] = [];
    for &cookie_val, idx in jar.cookies {
        guard cookie_val.priority == target_prio else { continue; }
        guard !protect_sec || !cookie_val.secure else { continue; }
        guard cookie_internal::matches_effective_domain(cookie_val, etld_plus_one) else { continue; }
        guard candidate_indices.try_push(idx as u16) else { break; }
    }
    guard candidate_indices.len > 0 else { return 0; }

    candidate_indices.stable_sort() { idx_a, idx_b =>
        cookie_internal::domain_gc_candidate_less(
            jar.cookies[idx_a as i64], jar.cookies[idx_b as i64],
        )
    };
    return cookie_internal::evict_top_creation_seqs(jar, candidate_indices[..], quota_allowed);
}

fn cookie_internal::deduct_domain_priority_excess(
    target_prio:   cookie::Priority,
    evicted_count: i64,
    low_excess:    i64&,
    med_excess:    i64&,
    high_excess:   i64&,
) {
    match target_prio {
        Low => { low_excess = core::sub_sat_i64(low_excess, evicted_count); },
        Medium => { med_excess = core::sub_sat_i64(med_excess, evicted_count); },
        _ => { high_excess = core::sub_sat_i64(high_excess, evicted_count); },
    };
}

fn cookie_internal::purge_domain_fallback(
    jar:           cookie::CanonicalCookieJar&,
    etld_plus_one: const u8[:],
    need_to_evict: i64,
) -> i64 {
    var candidate_indices: u16[..512] = [];
    for &cookie_val, idx in jar.cookies {
        if cookie_internal::matches_effective_domain(cookie_val, etld_plus_one) {
            guard candidate_indices.try_push(idx as u16) else { break; }
        }
    }
    guard candidate_indices.len > 0 else { return 0; }

    candidate_indices.stable_sort() { idx_a, idx_b =>
        cookie_internal::global_gc_candidate_less(
            jar.cookies[idx_a as i64], jar.cookies[idx_b as i64],
        )
    };
    return cookie_internal::evict_top_creation_seqs(jar, candidate_indices[..], need_to_evict);
}

fn cookie_internal::evict_global_non_immune_cookies(
    jar:           cookie::CanonicalCookieJar&,
    need_to_evict: i64,
    now_us:        i64,
) -> i64 {
    var candidate_indices: i32[..3400] = [];
    for &cookie_val, idx in jar.cookies {
        let elapsed_us = core::sub_sat_i64(now_us, cookie_val.last_access_utc);
        if elapsed_us >= cookie_internal::K_SAFE_FROM_GLOBAL_PURGE_US {
            guard candidate_indices.try_push(idx as i32) else { break; }
        }
    }
    guard candidate_indices.len > 0 else { return 0; }

    candidate_indices.stable_sort() { idx_a, idx_b =>
        cookie_internal::global_gc_candidate_less(
            jar.cookies[idx_a as i64], jar.cookies[idx_b as i64],
        )
    };
    return cookie_internal::evict_top_creation_seqs(jar, candidate_indices[..], need_to_evict);
}

fn cookie_internal::evict_global_lru_fallback_cookies(
    jar:           cookie::CanonicalCookieJar&,
    need_to_evict: i64,
) -> i64 {
    guard need_to_evict > 0 else { return 0; }
    var candidate_indices: i32[..3400] = [];
    for &cookie_val, idx in jar.cookies {
        if !cookie_val.secure || cookie_val.priority == cookie::Priority.Low {
            guard candidate_indices.try_push(idx as i32) else { break; }
        }
    }
    if candidate_indices.len == 0 && jar.cookies.len >= cookie_internal::K_MAX_COOKIES {
        for &cookie_val, idx in jar.cookies {
            guard candidate_indices.try_push(idx as i32) else { break; }
        }
    }
    guard candidate_indices.len > 0 else { return 0; }

    candidate_indices.stable_sort() { idx_a, idx_b =>
        cookie_internal::global_gc_candidate_less(
            jar.cookies[idx_a as i64], jar.cookies[idx_b as i64],
        )
    };
    return cookie_internal::evict_top_creation_seqs(jar, candidate_indices[..], need_to_evict);
}

fn cookie_internal::handle_cookie_collision(
    jar:           cookie::CanonicalCookieJar&,
    new_cookie:    const cookie::CanonicalCookie&,
    collision_idx: i64,
    url_is_secure: bool,
    now_us:        i64,
) -> bool {
    let existing .= jar.cookies[collision_idx];

    if cookie_internal::would_insecure_overwrite_secure(existing, new_cookie, url_is_secure) {
        jar.rejected_security_count = core::add_sat_i64(jar.rejected_security_count, 1);
        return false;
    }

    if new_cookie.is_expired(now_us) {
        jar.cookies.remove_at(collision_idx);
        jar.evicted_expired_count = core::add_sat_i64(jar.evicted_expired_count, 1);
        jar.overwritten_count = core::add_sat_i64(jar.overwritten_count, 1);
        jar.expired_overwrite_count = core::add_sat_i64(jar.expired_overwrite_count, 1);
        return true;
    }

    // Preserve original creation_utc and creation_seq across overwrites.
    let orig_creation_utc = existing.creation_utc;
    let orig_creation_seq = existing.creation_seq;
    jar.cookies[collision_idx] = new_cookie;
    let slot .= jar.cookies[collision_idx];
    slot.creation_utc = orig_creation_utc;
    slot.creation_seq = orig_creation_seq;
    slot.last_update_utc = now_us;
    slot.last_access_utc = now_us;
    jar.overwritten_count = core::add_sat_i64(jar.overwritten_count, 1);
    return true;
}

fn cookie_internal::cookie_matches_request(
    cookie_val:    const cookie::CanonicalCookie&,
    host:          const u8[:],
    path:          const u8[:],
    scheme:        const u8[:],
    port:          i32,
    source:        cookie::SourceOptions,
    partition_key: const u8[:],
    access:        cookie::AccessOptions,
    now_us:        i64,
) -> bool {
    if cookie_val.is_expired(now_us) { return false; }
    if !cookie_val.matches_domain(host) { return false; }
    if !cookie_val.matches_path(path) { return false; }
    if cookie_val.secure && !source.url_is_secure && !cookie::is_trustworthy_non_crypto_host(host) {
        return false;
    }
    if cookie_val.httponly && !source.is_http_api { return false; }
    if !cookie_val.is_sendable_for_samesite(access, now_us) { return false; }
    if !cookie_internal::is_sendable_for_obc(cookie_val, scheme, port, host) { return false; }
    if cookie_val.partitioned && cookie_val.partition_key[..] != partition_key { return false; }
    return true;
}
