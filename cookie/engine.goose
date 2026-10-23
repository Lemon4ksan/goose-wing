// In-memory cookie jar with hierarchical indexing and priority eviction
// (RFC 6265bis, CHIPS).
namespace wing;

import std;
import cookie.constants;
import cookie.canonical;
import cookie.psl;
import cookie.policy;
import cookie.parser;
import cookie.store;

// ---- canonical cookie jar container ----------------------------------------

// An in-memory cookie store indexed by eTLD+1, with priority-based eviction
// and partition key isolation.
struct CanonicalCookieJar {
    // Quotas and thresholds
    max_cookies_per_domain: i64 = K_DOMAIN_MAX_COOKIES,       // 180
    purge_cookies_per_domain: i64 = K_DOMAIN_PURGE_COOKIES,   // 30
    target_cookies_per_domain: i64 = K_DOMAIN_TARGET_COOKIES, // 150

    quota_low: i64 = K_DOMAIN_COOKIES_QUOTA_LOW,              // 30
    quota_medium: i64 = K_DOMAIN_COOKIES_QUOTA_MEDIUM,        // 50
    quota_high: i64 = K_DOMAIN_COOKIES_QUOTA_HIGH,            // 70

    max_cookies_global: i64 = K_MAX_COOKIES,                  // 3300
    purge_cookies_global: i64 = K_PURGE_COOKIES,              // 300
    target_cookies_global: i64 = K_GLOBAL_TARGET_COOKIES,     // 3000

    seq_counter: i64 = 1,

    // Telemetry counters
    overwritten_count: i64 = 0,
    evicted_expired_count: i64 = 0,
    evicted_domain_count: i64 = 0,
    evicted_global_count: i64 = 0,
    evicted_chips_count: i64 = 0,
    expired_overwrite_count: i64 = 0,
    rejected_security_count: i64 = 0,
    strict_secure_cookies: bool = false,
    access_update_threshold_us: i64 = 60000000, // 60s (Chromium kDefaultAccessUpdateThresholdSeconds)

    cookies: CanonicalCookie[>..] = [],
}

// Factory constructor for CanonicalCookieJar.
fn new_canonical_cookie_jar() -> CanonicalCookieJar {
    return CanonicalCookieJar {
        max_cookies_per_domain: K_DOMAIN_MAX_COOKIES,
        purge_cookies_per_domain: K_DOMAIN_PURGE_COOKIES,
        target_cookies_per_domain: K_DOMAIN_TARGET_COOKIES,
        quota_low: K_DOMAIN_COOKIES_QUOTA_LOW,
        quota_medium: K_DOMAIN_COOKIES_QUOTA_MEDIUM,
        quota_high: K_DOMAIN_COOKIES_QUOTA_HIGH,
        max_cookies_global: K_MAX_COOKIES,
        purge_cookies_global: K_PURGE_COOKIES,
        target_cookies_global: K_GLOBAL_TARGET_COOKIES,
        seq_counter: 1,
        overwritten_count: 0,
        evicted_expired_count: 0,
        evicted_domain_count: 0,
        evicted_global_count: 0,
        evicted_chips_count: 0,
        expired_overwrite_count: 0,
        rejected_security_count: 0,
        strict_secure_cookies: false,
        access_update_threshold_us: 60000000,
        cookies: [],
    };
}

// Adds a new cookie directly to the jar in-place and returns a reference for fluent chaining:
// jar.add("session_id", "val").with_domain("example.com").with_secure();
fn add(jar: CanonicalCookieJar&, name: const u8[:], val: const u8[:]) -> CanonicalCookie& {
    var new_cookie = CanonicalCookie { .. };
    new_cookie.name.append(name);
    new_cookie.value.append(val);
    new_cookie.creation_seq = jar.seq_counter;
    jar.seq_counter += 1;
    return jar.cookies.push(new_cookie);
}

// Purges expired cookies across the entire jar with a clean single-line retain closure.
fn purge_expired(jar: CanonicalCookieJar&, now_us: i64) -> i64 {
    let before_count = jar.cookies.len;
    jar.cookies.retain() { !it.is_expired(now_us) };
    let evicted_count = before_count - jar.cookies.len;
    jar.evicted_expired_count += evicted_count;
    return evicted_count;
}

// ---- selective deletion engine (cookie deletion filter) --------------------

struct CookieDeletionInfo {
    start_utc: i64 = 0,
    end_utc: i64 = 0,
    session_only: bool = false,
    domain: u8[..128] = [],
    name: u8[..128] = [],
    partition_key: u8[..256] = [],
    top_frame_site_key: u8[..256] = [],
    purge_non_secure: bool = false,
}

fn cookie_matches_deletion_filter(cookie_val: const CanonicalCookie&, filter: const CookieDeletionInfo&) -> bool {
    if filter.start_utc > 0 && cookie_val.creation_utc < filter.start_utc { return false; }
    if filter.end_utc > 0 && cookie_val.creation_utc > filter.end_utc { return false; }
    if filter.session_only && cookie_val.persistent { return false; }
    if filter.domain.len > 0 && !eq_ascii_fold(cookie_val.domain[..], filter.domain[..]) { return false; }
    if filter.name.len > 0 && cookie_val.name[..] != filter.name[..] { return false; }
    if filter.partition_key.len > 0 && cookie_val.partition_key[..] != filter.partition_key[..] { return false; }
    if filter.top_frame_site_key.len > 0 && cookie_val.partition_key[..] != filter.top_frame_site_key[..] { return false; }
    if filter.purge_non_secure && (cookie_val.secure || cookie_val.source_scheme == CookieSourceScheme.Secure) { return false; }
    return true; // Matches filter -> should be deleted
}

fn delete_matching(jar: CanonicalCookieJar&, filter: const CookieDeletionInfo&) -> i64 {
    let before_count = jar.cookies.len;
    jar.cookies.retain() { !cookie_matches_deletion_filter(it, filter) };
    return before_count - jar.cookies.len;
}

fn delete_all_created_in_time_range(jar: CanonicalCookieJar&, start_utc: i64, end_utc: i64) -> i64 {
    let before_count = jar.cookies.len;
    jar.cookies.retain() {
        !(it.creation_utc >= start_utc && (end_utc == 0 || it.creation_utc <= end_utc))
    };
    return before_count - jar.cookies.len;
}

fn delete_session_cookies(jar: CanonicalCookieJar&, purge_non_secure: bool = false) -> i64 {
    let before_count = jar.cookies.len;
    jar.cookies.retain() {
        if purge_non_secure && (!it.secure && it.source_scheme != CookieSourceScheme.Secure) {
            false
        } else {
            it.persistent
        }
    };
    return before_count - jar.cookies.len;
}

// Safely inserts a pre-built CanonicalCookie through full security validation, collision overwrite and GC.
fn set(jar: CanonicalCookieJar&, cookie_val: CanonicalCookie, now_us: i64) -> bool {
    let is_sec = cookie_val.secure || (cookie_val.source_scheme == CookieSourceScheme.Secure);
    return set_canonical_cookie(jar, cookie_val, true, is_sec, now_us);
}

fn insert(jar: CanonicalCookieJar&, cookie_val: CanonicalCookie, now_us: i64) -> bool {
    return set(jar, cookie_val, now_us);
}

// Queries a cookie value by name for a specific request URL.
fn get(
    jar: CanonicalCookieJar&,
    req_url: const u8[:],
    name: const u8[:],
    now_us: i64,
    is_same_site: bool = true,
    is_top_level_navigation: bool = true,
    is_safe_method: bool = true,
    partition_key: const u8[:] = ""
) -> const u8[:] {
    let parsed_url = parse_canonical_cookie_url(req_url);
    for cookie_idx in jar.cookies.len {
        let cookie_val = jar.cookies[cookie_idx];
        if cookie_val.name[..] != name { continue; }

        if !cookie_matches_request(
            cookie_val, parsed_url.host[..], parsed_url.path[..],
            parsed_url.scheme[..], parsed_url.port, parsed_url.is_secure,
            true, partition_key, is_same_site, is_top_level_navigation, is_safe_method, now_us
        ) {
            continue;
        }

        let delta_us = now_us - jar.cookies[cookie_idx].last_access_utc;
        if jar.access_update_threshold_us <= 0 || delta_us >= jar.access_update_threshold_us {
            jar.cookies[cookie_idx].last_access_utc = now_us;
        }
        return jar.cookies[cookie_idx].value[..];
    }
    return "";
}

// Queries a cookie value by name globally from the jar (first match).
fn get(jar: const CanonicalCookieJar&, name: const u8[:]) -> const u8[:] {
    for cookie_idx in jar.cookies.len {
        if jar.cookies[cookie_idx].name[..] == name {
            return jar.cookies[cookie_idx].value[..];
        }
    }
    return "";
}

// ---- ingestion & insertion pipeline ----------------------------------------

// Inserts new_cookie into jar, enforcing prefix rules (__Host-, __Secure-),
// origin security, overwrite precedence, and memory quotas (RFC 6265bis Section 5.6).
// Returns false if the cookie violates security policies.
fn set_canonical_cookie(
    jar: CanonicalCookieJar&,
    new_cookie: CanonicalCookie&,
    is_http_api: bool,
    url_is_secure: bool,
    now_us: i64,
) -> bool {
    // 1. Security invariants validation
    if !validate_canonical_cookie_security(new_cookie, url_is_secure, is_http_api) ||
       (!is_http_api && !validate_script_cookie_name(new_cookie.name[..])) {
        jar.rejected_security_count += 1;
        return false;
    }

    // 2. Collision resolution & Expired Overwrite Handling
    let collision_idx = find_canonical_cookie_collision_index(jar, new_cookie);
    if collision_idx >= 0 {
        return handle_cookie_collision(jar, new_cookie, collision_idx, url_is_secure, now_us);
    }

    if is_expired(new_cookie, now_us) {
        jar.evicted_expired_count += 1;
        return true;
    }

    // 3. RFC 6265bis Section 5.6: Secure Shadowing Protection
    if has_secure_shadowing_collision(jar, new_cookie, url_is_secure) {
        jar.rejected_security_count += 1;
        return false;
    }

    // 4. Calculate effective domain & insert
    var etld_plus_one: u8[..256] = [];
    get_canonical_cookie_effective_domain(new_cookie, etld_plus_one);

    new_cookie.creation_utc = now_us;
    new_cookie.last_update_utc = now_us;
    new_cookie.last_access_utc = now_us;
    new_cookie.creation_seq = jar.seq_counter;
    jar.seq_counter += 1;
    jar.cookies.push(new_cookie);

    // 5. Enforce quotas & background GC
    enforce_post_insertion_quotas(jar, new_cookie, etld_plus_one[..], now_us);
    return true;
}

// Ingests a raw Set-Cookie header directly for a given request URL.
//
// Caller Contract & Nuances:
// - Security Channel: HTTPS URLs and localhost/127.0.0.1/[::1] endpoints are treated as trustworthy secure contexts.
// - Layered Prefixes: __Secure- requires a secure channel; __Host- requires secure context, Path=/, and NO Domain.
// - CTL Characters: Any ASCII control byte (0x00..0x1F or 0x7F) causes set_cookie_header to return false immediately.
// - Size Caps: Name + Value must not exceed 4,096 bytes (returns false if exceeded).
// - Collision Overwrites: Overwriting an existing cookie preserves its original creation_utc timestamp.
// - Access Throttling: Repeated reads within 60 seconds throttle last_access_utc updates to prevent write storms.
fn set_cookie_header(
    jar: CanonicalCookieJar&,
    req_url: const u8[:],
    set_cookie_raw: const u8[:],
    now_us: i64,
    is_http_api: bool = true,
    partition_key: const u8[:] = "",
) -> bool {
    let parsed_url = parse_canonical_cookie_url(req_url);
    var def_path: u8[..256] = [];
    default_cookie_path_calc(parsed_url.path[..], def_path);

    var parsed_cookie, cause, ok = parse_canonical_set_cookie(set_cookie_raw, parsed_url.host[..], def_path[..], now_us);
    guard ok else { return false; }

    if partition_key.len > 0 {
        parsed_cookie.partition_key.clear();
        parsed_cookie.partition_key.append(partition_key);
    }

    adjust_origin_bound_cookies_on_insert(parsed_cookie, parsed_url.host[..], parsed_url.port, parsed_url.is_secure);
    let effective_secure_channel = parsed_url.is_secure || trustworthy_non_crypto_host(parsed_url.host[..]);
    return set_canonical_cookie(jar, parsed_cookie, is_http_api, effective_secure_channel, now_us);
}

fn set_cookie_header(
    jar: CanonicalCookieJar&,
    req_url: const u8[:],
    set_cookie_raw: const u8[:],
    now_us: i64,
    partition_key: const u8[:],
) -> bool {
    return set_cookie_header(jar, req_url, set_cookie_raw, now_us, true, partition_key);
}

// ---- outgoing request routing & serialization ------------------------------

// High-level declarative helper for generating outgoing HTTP Cookie header.
fn build_cookie_header<B>(
    jar: CanonicalCookieJar&,
    out: B&,
    host: const u8[:],
    path: const u8[:],
    is_secure: bool,
    now_us: i64,
) {
    var matched: CanonicalCookie[>..] = [];
    get_canonical_cookies_for_request(
        jar, host, path,
        if is_secure { "https" } else { "http" },
        if is_secure { 443 } else { 80 },
        is_secure, true, "", now_us, matched
    );
    format_cookie_header_value(out, matched[..]);
}

// Builds an outgoing HTTP Cookie header directly from an arbitrary request URL.
fn build_cookie_header<B>(
    jar: CanonicalCookieJar&,
    req_url: const u8[:],
    out: B&,
    now_us: i64,
    partition_key: const u8[:] = "",
) {
    let parsed_url = parse_canonical_cookie_url(req_url);
    var matched: CanonicalCookie[>..] = [];
    get_canonical_cookies_for_request(
        jar,
        parsed_url.host[..],
        parsed_url.path[..],
        parsed_url.scheme[..],
        parsed_url.port,
        parsed_url.is_secure,
        true,
        partition_key,
        now_us,
        matched
    );
    format_cookie_header_value(out, matched[..]);
}

// Builds an outgoing HTTP Cookie header for a request with explicit is_http_api and partition_key
fn build_request_cookie_header<B>(
    jar: CanonicalCookieJar&,
    req_url: const u8[:],
    is_http_api: bool,
    partition_key: const u8[:],
    now_us: i64,
    out: B&
) {
    let parsed_url = parse_canonical_cookie_url(req_url);
    var matched: CanonicalCookie[>..] = [];
    get_canonical_cookies_for_request(
        jar,
        parsed_url.host[..],
        parsed_url.path[..],
        parsed_url.scheme[..],
        parsed_url.port,
        parsed_url.is_secure,
        is_http_api,
        partition_key,
        now_us,
        matched
    );
    format_cookie_header_value(out, matched[..]);
}

// URL-based overload for get_canonical_cookies_for_request.
fn get_canonical_cookies_for_request(
    jar: CanonicalCookieJar&,
    req_url: const u8[:],
    is_http_api: bool,
    partition_key: const u8[:],
    now_us: i64,
    out: CanonicalCookie[>..]&,
    is_same_site: bool = true,
    is_top_level_navigation: bool = true,
    is_safe_method: bool = true,
) {
    let parsed_url = parse_canonical_cookie_url(req_url);
    get_canonical_cookies_for_request(
        jar,
        parsed_url.host[..],
        parsed_url.path[..],
        parsed_url.scheme[..],
        parsed_url.port,
        parsed_url.is_secure,
        is_http_api,
        partition_key,
        now_us,
        out,
        is_same_site,
        is_top_level_navigation,
        is_safe_method
    );
}

// Queries and extracts matching cookies for an outgoing HTTP request.
// Updates last_access_utc for retrieved cookies.
// Returns cookies sorted per RFC 6265 Section 5.4:
// 1. Longest Path first (path.len descending)
// 2. Earliest creation_utc first (creation_utc ascending)
fn get_canonical_cookies_for_request(
    jar: CanonicalCookieJar&,
    host: const u8[:],
    path: const u8[:],
    scheme: const u8[:],
    port: i32,
    is_secure: bool,
    is_http_api: bool,
    partition_key: const u8[:],
    now_us: i64,
    out: CanonicalCookie[>..]&,
    is_same_site: bool = true,
    is_top_level_navigation: bool = true,
    is_safe_method: bool = true,
) {
    for cookie_idx in jar.cookies.len {
        var cookie_val = jar.cookies[cookie_idx];

        if !cookie_matches_request(
            cookie_val, host, path, scheme, port,
            is_secure, is_http_api, partition_key,
            is_same_site, is_top_level_navigation, is_safe_method,
            now_us
        ) {
            continue;
        }

        let delta_us = now_us - jar.cookies[cookie_idx].last_access_utc;
        if jar.access_update_threshold_us <= 0 || delta_us >= jar.access_update_threshold_us {
            jar.cookies[cookie_idx].last_access_utc = now_us;
            cookie_val.last_access_utc = now_us;
        }
        out.push(cookie_val);
    }

    stable_sort(out[..]) { cookie_a, cookie_b => request_cookie_order_less(cookie_a, cookie_b) };
}

// ---- quotas & garbage collection engine ------------------------------------

// Executes Domain Garbage Collection for a specific effective domain (eTLD+1).
// Trigger: domain count > max_cookies_per_domain (180).
// Target: reduce down to target_cookies_per_domain (150).
fn garbage_collect_per_domain(jar: CanonicalCookieJar&, etld_plus_one: const u8[:], now_us: i64) -> i64 {
    var domain_count = count_domain_cookies(jar, etld_plus_one);
    guard domain_count > jar.max_cookies_per_domain else { return 0; }

    var total_evicted: i64 = 0;
    let expired_evicted = evict_domain_expired_cookies(jar, etld_plus_one, now_us);
    total_evicted += expired_evicted;
    domain_count -= expired_evicted;

    // GC-04: strict_secure_cookies policy evicts all non-secure cookies first
    if jar.strict_secure_cookies {
        let non_sec_evicted = evict_domain_non_secure_cookies(jar, etld_plus_one);
        total_evicted += non_sec_evicted;
        domain_count -= non_sec_evicted;
    }

    guard domain_count > jar.target_cookies_per_domain else { return total_evicted; }

    var need_to_evict = domain_count - jar.target_cookies_per_domain;
    var low_excess: i64 = 0;
    var med_excess: i64 = 0;
    var high_excess: i64 = 0;
    calculate_domain_priority_excesses(jar, etld_plus_one, low_excess, med_excess, high_excess);

    total_evicted += purge_domain_priority_rounds(jar, etld_plus_one, need_to_evict, low_excess, med_excess, high_excess);

    if need_to_evict > 0 {
        let fallback_evicted = purge_domain_fallback(jar, etld_plus_one, need_to_evict);
        jar.evicted_domain_count += fallback_evicted;
        total_evicted += fallback_evicted;
    }

    return total_evicted;
}

// Executes Global Garbage Collection across the entire jar.
// Trigger: total cookies > max_cookies_global (3300).
// Target: reduce down to target_cookies_global (3000).
// Cookies accessed within the last 30 days are protected from global eviction.
fn garbage_collect_global(jar: CanonicalCookieJar&, now_us: i64) -> i64 {
    guard jar.cookies.len > jar.max_cookies_global else { return 0; }

    var total_evicted: i64 = 0;
    let expired_evicted = evict_global_expired_cookies(jar, now_us);
    total_evicted += expired_evicted;

    guard jar.cookies.len > jar.target_cookies_global else { return total_evicted; }

    let need_to_evict = jar.cookies.len - jar.target_cookies_global;
    let non_immune_evicted = evict_global_non_immune_cookies(jar, need_to_evict, now_us);
    jar.evicted_global_count += non_immune_evicted;
    total_evicted += non_immune_evicted;

    return total_evicted;
}

// Enforces CHIPS Partition memory quota (10 KB per partition-domain pair).
// Evicts oldest partitioned cookies by LRA until total memory <= 10240 bytes.
fn enforce_chips_quota(
    jar: CanonicalCookieJar&,
    partition_key: const u8[:],
    etld_plus_one: const u8[:],
    now_us: i64,
) -> i64 {
    guard partition_key.len > 0 else { return 0; }

    var candidates: CanonicalCookie[>..] = [];
    var total_bytes: i64 = 0;
    gather_chips_candidates(jar, partition_key, etld_plus_one, candidates, total_bytes);

    guard total_bytes > K_PER_PARTITION_DOMAIN_MAX_COOKIE_BYTES else { return 0; }

    stable_sort(candidates[..]) { cookie_a, cookie_b => chips_lra_candidate_less(cookie_a, cookie_b) };

    var to_delete_seqs: i64[>..] = [];
    var evicted_count: i64 = 0;

    for candidate_idx in candidates.len {
        if total_bytes <= K_PER_PARTITION_DOMAIN_MAX_COOKIE_BYTES { break; }
        let candidate_cookie = candidates[candidate_idx];
        total_bytes -= payload_size(candidate_cookie);
        to_delete_seqs.push(candidate_cookie.creation_seq);
        evicted_count += 1;
    }

    if to_delete_seqs.len > 0 {
        retain(jar.cookies) { cookie_val => seq_not_in_list(cookie_val.creation_seq, to_delete_seqs[..]) };
        jar.evicted_chips_count += evicted_count;
    }

    return evicted_count;
}

// ---- internal implementation helpers ---------------------------------------

fn purge_domain_priority_rounds(
    jar: CanonicalCookieJar&,
    etld_plus_one: const u8[:],
    need_to_evict: i64&,
    low_excess: i64&,
    med_excess: i64&,
    high_excess: i64&,
) -> i64 {
    var evicted_count: i64 = 0;
    for round_idx in 1..7 {
        if need_to_evict <= 0 { break; }

        let target_prio, protect_sec, quota_allowed = resolve_domain_purge_round_params(
            round_idx, need_to_evict, low_excess, med_excess, high_excess
        );
        if quota_allowed <= 0 { continue; }

        let round_evicted = purge_domain_priority_round(
            jar, etld_plus_one, target_prio, protect_sec, quota_allowed
        );
        if round_evicted <= 0 { continue; }

        deduct_domain_priority_excess(target_prio, round_evicted, low_excess, med_excess, high_excess);
        jar.evicted_domain_count += round_evicted;
        evicted_count += round_evicted;
        need_to_evict -= round_evicted;
    }
    return evicted_count;
}

fn enforce_post_insertion_quotas(
    jar: CanonicalCookieJar&,
    new_cookie: const CanonicalCookie&,
    etld_plus_one: const u8[:],
    now_us: i64,
) {
    if (new_cookie.partitioned || new_cookie.partition_key.len > 0) && new_cookie.partition_key.len > 0 {
        enforce_chips_quota(jar, new_cookie.partition_key[..], etld_plus_one, now_us);
    }
    garbage_collect_per_domain(jar, etld_plus_one, now_us);
    garbage_collect_global(jar, now_us);
}

fn has_secure_shadowing_collision(
    jar: const CanonicalCookieJar&,
    new_cookie: const CanonicalCookie&,
    url_is_secure: bool,
) -> bool {
    for cookie_idx in jar.cookies.len {
        let existing = jar.cookies[cookie_idx];
        if would_insecure_overwrite_secure(existing, new_cookie, url_is_secure) {
            return true;
        }
    }
    return false;
}

fn gather_chips_candidates<B>(
    jar: const CanonicalCookieJar&,
    partition_key: const u8[:],
    etld_plus_one: const u8[:],
    candidates: B&,
    total_bytes: i64&,
) {
    for cookie_idx in jar.cookies.len {
        let cookie_val = jar.cookies[cookie_idx];
        if (cookie_val.partitioned || cookie_val.partition_key.len > 0) &&
           cookie_val.partition_key[..] == partition_key &&
           cookie_matches_effective_domain(cookie_val, etld_plus_one) {
            total_bytes += payload_size(cookie_val);
            candidates.push(cookie_val);
        }
    }
}

fn priority_rank(priority_level: CookiePriority) -> i32 {
    return match priority_level {
        Low => 0,
        Medium => 1,
        High => 2,
    };
}

fn get_canonical_cookie_effective_domain<B>(cookie_val: const CanonicalCookie&, out: B&) {
    if ip_address_literal(cookie_val.domain[..]) || count_dots(cookie_val.domain[..]) == 0 {
        out.append(cookie_val.domain[..]);
    } else {
        extract_etld_plus_one(cookie_val.domain[..], out);
    }
}

fn cookie_matches_effective_domain(cookie_val: const CanonicalCookie&, target_etld_plus_one: const u8[:]) -> bool {
    var candidate_etld: u8[..256] = [];
    get_canonical_cookie_effective_domain(cookie_val, candidate_etld);
    return eq_ascii_fold(candidate_etld[..], target_etld_plus_one);
}

fn find_canonical_cookie_collision_index(jar: const CanonicalCookieJar&, new_cookie: const CanonicalCookie&) -> i64 {
    for cookie_idx in jar.cookies.len {
        let existing = jar.cookies[cookie_idx];
        if existing.name[..] == new_cookie.name[..] &&
           existing.domain[..] == new_cookie.domain[..] &&
           existing.path[..] == new_cookie.path[..] &&
           existing.host_only == new_cookie.host_only &&
           existing.partition_key[..] == new_cookie.partition_key[..] &&
           existing.source_port == new_cookie.source_port &&
           existing.source_scheme == new_cookie.source_scheme {
            return cookie_idx;
        }
    }
    return -1;
}

fn would_insecure_overwrite_secure(
    existing: const CanonicalCookie&,
    new_cookie: const CanonicalCookie&,
    url_is_secure: bool,
) -> bool {
    if !existing.secure { return false; }
    if url_is_secure { return false; }
    if existing.name[..] != new_cookie.name[..] { return false; }
    if existing.partition_key[..] != new_cookie.partition_key[..] { return false; }

    let domain_matches = cookie_domain_match(existing.domain[..], new_cookie.domain[..]) ||
                         cookie_domain_match(new_cookie.domain[..], existing.domain[..]);
    guard domain_matches else { return false; }

    return cookie_path_match(new_cookie.path[..], existing.path[..]);
}

fn count_domain_cookies(jar: const CanonicalCookieJar&, etld_plus_one: const u8[:]) -> i64 {
    var count: i64 = 0;
    for cookie_idx in jar.cookies.len {
        if cookie_matches_effective_domain(jar.cookies[cookie_idx], etld_plus_one) {
            count += 1;
        }
    }
    return count;
}

fn seq_not_in_list(seq: i64, list: const i64[:]) -> bool {
    for list_seq in list {
        if seq == list_seq { return false; }
    }
    return true;
}

fn domain_gc_candidate_less(cookie_a: const CanonicalCookie&, cookie_b: const CanonicalCookie&) -> bool {
    if cookie_a.secure != cookie_b.secure {
        return !cookie_a.secure; // Non-secure evicted before secure
    }
    if cookie_a.host_only != cookie_b.host_only {
        return !cookie_a.host_only; // Domain evicted before host-only
    }
    if cookie_a.last_access_utc != cookie_b.last_access_utc {
        return cookie_a.last_access_utc < cookie_b.last_access_utc; // Oldest access first
    }
    return cookie_a.creation_seq < cookie_b.creation_seq;
}

fn fallback_gc_candidate_less(cookie_a: const CanonicalCookie&, cookie_b: const CanonicalCookie&) -> bool {
    if cookie_a.priority != cookie_b.priority {
        return priority_rank(cookie_a.priority) < priority_rank(cookie_b.priority);
    }
    return domain_gc_candidate_less(cookie_a, cookie_b);
}

fn global_gc_candidate_less(cookie_a: const CanonicalCookie&, cookie_b: const CanonicalCookie&) -> bool {
    if cookie_a.priority != cookie_b.priority {
        return priority_rank(cookie_a.priority) < priority_rank(cookie_b.priority);
    }
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

fn chips_lra_candidate_less(cookie_a: const CanonicalCookie&, cookie_b: const CanonicalCookie&) -> bool {
    if cookie_a.last_access_utc != cookie_b.last_access_utc {
        return cookie_a.last_access_utc < cookie_b.last_access_utc;
    }
    return cookie_a.creation_seq < cookie_b.creation_seq;
}

fn request_cookie_order_less(cookie_a: const CanonicalCookie&, cookie_b: const CanonicalCookie&) -> bool {
    if cookie_a.path.len != cookie_b.path.len {
        return cookie_a.path.len > cookie_b.path.len; // Longest path first
    }
    if cookie_a.creation_utc != cookie_b.creation_utc {
        return cookie_a.creation_utc < cookie_b.creation_utc; // Earliest creation first
    }
    return cookie_a.creation_seq < cookie_b.creation_seq;
}

fn evict_domain_expired_cookies(jar: CanonicalCookieJar&, etld_plus_one: const u8[:], now_us: i64) -> i64 {
    var expired_seqs: i64[>..] = [];
    for cookie_idx in jar.cookies.len {
        let cookie_val = jar.cookies[cookie_idx];
        if cookie_matches_effective_domain(cookie_val, etld_plus_one) && is_expired(cookie_val, now_us) {
            expired_seqs.push(cookie_val.creation_seq);
        }
    }
    guard expired_seqs.len > 0 else { return 0; }

    retain(jar.cookies) { cookie_val => seq_not_in_list(cookie_val.creation_seq, expired_seqs[..]) };
    jar.evicted_expired_count += expired_seqs.len;
    return expired_seqs.len;
}

fn evict_domain_non_secure_cookies(jar: CanonicalCookieJar&, etld_plus_one: const u8[:]) -> i64 {
    var non_sec_seqs: i64[>..] = [];
    for cookie_idx in jar.cookies.len {
        let cookie_val = jar.cookies[cookie_idx];
        if cookie_matches_effective_domain(cookie_val, etld_plus_one) && !cookie_val.secure {
            non_sec_seqs.push(cookie_val.creation_seq);
        }
    }
    guard non_sec_seqs.len > 0 else { return 0; }

    retain(jar.cookies) { cookie_val => seq_not_in_list(cookie_val.creation_seq, non_sec_seqs[..]) };
    jar.rejected_security_count += non_sec_seqs.len;
    return non_sec_seqs.len;
}

fn calculate_domain_priority_excesses(
    jar: const CanonicalCookieJar&,
    etld_plus_one: const u8[:],
    low_excess: i64&,
    med_excess: i64&,
    high_excess: i64&,
) {
    var low_count: i64 = 0;
    var med_count: i64 = 0;
    var high_count: i64 = 0;

    for cookie_idx in jar.cookies.len {
        let cookie_val = jar.cookies[cookie_idx];
        if cookie_matches_effective_domain(cookie_val, etld_plus_one) {
            match cookie_val.priority {
                Low => { low_count += 1; },
                Medium => { med_count += 1; },
                High => { high_count += 1; },
            };
        }
    }

    low_excess = max(0, low_count - jar.quota_low);
    med_excess = max(0, med_count - jar.quota_medium);
    high_excess = max(0, high_count - jar.quota_high);
}

fn resolve_domain_purge_round_params(
    round_idx: i64,
    need_to_evict: i64,
    low_excess: i64,
    med_excess: i64,
    high_excess: i64,
) -> CookiePriority, bool, i64 {
    if round_idx == 1 {
        return CookiePriority.Low, true, min(need_to_evict, low_excess);
    }
    if round_idx == 2 {
        return CookiePriority.Low, false, min(need_to_evict, low_excess);
    }
    if round_idx == 3 {
        return CookiePriority.Medium, true, min(need_to_evict, med_excess);
    }
    if round_idx == 4 {
        // High Non-Secure evicted BEFORE Medium Secure per Chromium V24!
        return CookiePriority.High, true, min(need_to_evict, high_excess);
    }
    if round_idx == 5 {
        return CookiePriority.Medium, false, min(need_to_evict, med_excess);
    }
    return CookiePriority.High, false, min(need_to_evict, high_excess);
}

fn purge_domain_priority_round(
    jar: CanonicalCookieJar&,
    etld_plus_one: const u8[:],
    target_prio: CookiePriority,
    protect_sec: bool,
    quota_allowed: i64,
) -> i64 {
    var candidates: CanonicalCookie[>..] = [];
    for cookie_idx in jar.cookies.len {
        let cookie_val = jar.cookies[cookie_idx];
        if cookie_matches_effective_domain(cookie_val, etld_plus_one) && cookie_val.priority == target_prio {
            if !protect_sec || !cookie_val.secure {
                candidates.push(cookie_val);
            }
        }
    }
    guard candidates.len > 0 else { return 0; }

    stable_sort(candidates[..]) { cookie_a, cookie_b => domain_gc_candidate_less(cookie_a, cookie_b) };

    let evict_count = min(quota_allowed, candidates.len);
    var to_delete_seqs: i64[>..] = [];
    for candidate_idx in evict_count {
        to_delete_seqs.push(candidates[candidate_idx].creation_seq);
    }

    retain(jar.cookies) { cookie_val => seq_not_in_list(cookie_val.creation_seq, to_delete_seqs[..]) };
    return evict_count;
}

fn deduct_domain_priority_excess(
    target_prio: CookiePriority,
    evicted_count: i64,
    low_excess: i64&,
    med_excess: i64&,
    high_excess: i64&,
) {
    if target_prio == CookiePriority.Low {
        low_excess -= evicted_count;
    } else if target_prio == CookiePriority.Medium {
        med_excess -= evicted_count;
    } else {
        high_excess -= evicted_count;
    }
}

fn purge_domain_fallback(jar: CanonicalCookieJar&, etld_plus_one: const u8[:], need_to_evict: i64) -> i64 {
    var fallback_candidates: CanonicalCookie[>..] = [];
    for cookie_idx in jar.cookies.len {
        let cookie_val = jar.cookies[cookie_idx];
        if cookie_matches_effective_domain(cookie_val, etld_plus_one) {
            fallback_candidates.push(cookie_val);
        }
    }
    stable_sort(fallback_candidates[..]) { cookie_a, cookie_b => fallback_gc_candidate_less(cookie_a, cookie_b) };

    let evict_fallback = min(need_to_evict, fallback_candidates.len);
    var fallback_seqs: i64[>..] = [];
    for candidate_idx in evict_fallback {
        fallback_seqs.push(fallback_candidates[candidate_idx].creation_seq);
    }
    retain(jar.cookies) { cookie_val => seq_not_in_list(cookie_val.creation_seq, fallback_seqs[..]) };
    return evict_fallback;
}

fn evict_global_expired_cookies(jar: CanonicalCookieJar&, now_us: i64) -> i64 {
    var expired_seqs: i64[>..] = [];
    for cookie_idx in jar.cookies.len {
        let cookie_val = jar.cookies[cookie_idx];
        if is_expired(cookie_val, now_us) {
            expired_seqs.push(cookie_val.creation_seq);
        }
    }
    guard expired_seqs.len > 0 else { return 0; }

    retain(jar.cookies) { cookie_val => seq_not_in_list(cookie_val.creation_seq, expired_seqs[..]) };
    jar.evicted_expired_count += expired_seqs.len;
    return expired_seqs.len;
}

fn evict_global_non_immune_cookies(jar: CanonicalCookieJar&, need_to_evict: i64, now_us: i64) -> i64 {
    var candidates: CanonicalCookie[>..] = [];
    for cookie_idx in jar.cookies.len {
        let cookie_val = jar.cookies[cookie_idx];
        let elapsed_us = now_us - cookie_val.last_access_utc;
        if elapsed_us >= K_SAFE_FROM_GLOBAL_PURGE_US {
            candidates.push(cookie_val);
        }
    }
    guard candidates.len > 0 else { return 0; }

    stable_sort(candidates[..]) { cookie_a, cookie_b => global_gc_candidate_less(cookie_a, cookie_b) };

    let evict_count = min(need_to_evict, candidates.len);
    var to_delete_seqs: i64[>..] = [];
    for candidate_idx in evict_count {
        to_delete_seqs.push(candidates[candidate_idx].creation_seq);
    }

    retain(jar.cookies) { cookie_val => seq_not_in_list(cookie_val.creation_seq, to_delete_seqs[..]) };
    return evict_count;
}

fn handle_cookie_collision(
    jar: CanonicalCookieJar&,
    new_cookie: CanonicalCookie&,
    collision_idx: i64,
    url_is_secure: bool,
    now_us: i64,
) -> bool {
    let existing = jar.cookies[collision_idx];

    // RFC 6265bis Section 5.6 / Chromium: Non-secure cannot overwrite existing Secure cookie
    if would_insecure_overwrite_secure(existing, new_cookie, url_is_secure) {
        jar.rejected_security_count += 1;
        return false;
    }

    // Chromium Expired Overwrite: if new cookie is already expired (Max-Age=0 or past Expires),
    // immediately remove the collided cookie from memory without keeping a dead record.
    if is_expired(new_cookie, now_us) {
        remove_at(jar.cookies, collision_idx);
        jar.evicted_expired_count += 1;
        jar.overwritten_count += 1;
        jar.expired_overwrite_count += 1;
        return true;
    }

    // Allowed Overwrite: CRITICAL INVARIANT: preserve existing.creation_utc!
    new_cookie.creation_utc = existing.creation_utc;
    new_cookie.creation_seq = existing.creation_seq;
    new_cookie.last_update_utc = now_us;
    new_cookie.last_access_utc = now_us;

    jar.cookies[collision_idx] = new_cookie;
    jar.overwritten_count += 1;
    return true;
}

fn cookie_matches_request(
    cookie_val: const CanonicalCookie&,
    host: const u8[:],
    path: const u8[:],
    scheme: const u8[:],
    port: i32,
    is_secure: bool,
    is_http_api: bool,
    partition_key: const u8[:],
    is_same_site: bool,
    is_top_level_navigation: bool,
    is_safe_method: bool,
    now_us: i64,
) -> bool {
    if is_expired(cookie_val, now_us) { return false; }
    if !matches_domain(cookie_val, host) { return false; }
    if !matches_path(cookie_val, path) { return false; }
    if cookie_val.secure && !is_secure && !trustworthy_non_crypto_host(host) { return false; }
    if cookie_val.httponly && !is_http_api { return false; }
    if !is_cookie_sendable_for_samesite(cookie_val, is_same_site, is_top_level_navigation, is_safe_method, now_us) { return false; }
    if !is_cookie_sendable_for_obc(cookie_val, scheme, port, host) { return false; }
    if cookie_val.partitioned && cookie_val.partition_key[..] != partition_key { return false; }
    return true;
}
