// Memory Management, 2-Level Indexing & Garbage Collection Engine
// Clean Room Implementation conforming to Chromium net/cookies/CookieMonster and RFC 6265bis.
namespace wing;

import std;
import cookie.constants;
import cookie.canonical;
import cookie.psl;
import cookie.parser;
import cookie.policy;

// Rank priority for comparison (Low = 0, Medium = 1, High = 2).
fn priority_rank(p: CookiePriority) -> i32 {
    return match p {
        Low => 0,
        Medium => 1,
        High => 2,
    };
}

// CanonicalCookieJar encapsulates the two-level indexed in-memory Cookie store
// and multi-tiered Garbage Collection engine of Chromium's CookieMonster.
struct CanonicalCookieJar {
    seq_counter: i64 = 0,

    // Domain Garbage Collection thresholds & quotas (Chromium CookieMonster hysteresis model)
    max_cookies_per_domain: i64 = 180,       // K_DOMAIN_MAX_COOKIES
    purge_cookies_per_domain: i64 = 30,      // K_DOMAIN_PURGE_COOKIES
    target_cookies_per_domain: i64 = 150,    // K_DOMAIN_TARGET_COOKIES

    quota_low: i64 = 30,                     // K_DOMAIN_COOKIES_QUOTA_LOW
    quota_medium: i64 = 50,                  // K_DOMAIN_COOKIES_QUOTA_MEDIUM
    quota_high: i64 = 70,                    // K_DOMAIN_COOKIES_QUOTA_HIGH

    // Global Garbage Collection thresholds
    max_cookies_global: i64 = 3300,          // K_MAX_COOKIES
    purge_cookies_global: i64 = 300,         // K_PURGE_COOKIES
    target_cookies_global: i64 = 3000,       // K_GLOBAL_TARGET_COOKIES

    // Telemetry & metrics
    evicted_expired_count: i64 = 0,
    evicted_domain_count: i64 = 0,
    evicted_global_count: i64 = 0,
    evicted_chips_count: i64 = 0,
    rejected_security_count: i64 = 0,
    overwritten_count: i64 = 0,

    // Resizable field must be the final field in Goose structs
    cookies: CanonicalCookie[>..] = [],
}

// Creates an initialized CanonicalCookieJar with Chromium CookieMonster defaults.
fn new_canonical_cookie_jar() -> CanonicalCookieJar {
    return CanonicalCookieJar {
        seq_counter: 0,
        max_cookies_per_domain: K_DOMAIN_MAX_COOKIES,
        purge_cookies_per_domain: K_DOMAIN_PURGE_COOKIES,
        target_cookies_per_domain: K_DOMAIN_TARGET_COOKIES,
        quota_low: K_DOMAIN_COOKIES_QUOTA_LOW,
        quota_medium: K_DOMAIN_COOKIES_QUOTA_MEDIUM,
        quota_high: K_DOMAIN_COOKIES_QUOTA_HIGH,
        max_cookies_global: K_MAX_COOKIES,
        purge_cookies_global: K_PURGE_COOKIES,
        target_cookies_global: K_GLOBAL_TARGET_COOKIES,
        evicted_expired_count: 0,
        evicted_domain_count: 0,
        evicted_global_count: 0,
        evicted_chips_count: 0,
        rejected_security_count: 0,
        overwritten_count: 0,
        cookies: [],
    };
}

// Helper to filter retained elements by seq list
fn seq_not_in_list(seq: i64, list: const i64[:]) -> bool {
    for s in list {
        if seq == s { return false; }
    }
    return true;
}

// Extracts the effective domain (eTLD+1 or direct host) for a CanonicalCookie.
fn get_canonical_cookie_effective_domain(c: const CanonicalCookie&, out: u8[..256]&) {
    out.clear();
    if c.domain.len > 0 {
        extract_etld_plus_one(c.domain[..], out);
    }
}

// Tests whether a CanonicalCookie belongs to the specified effective domain (eTLD+1).
fn cookie_matches_effective_domain(c: const CanonicalCookie&, etld_plus_one: const u8[:]) -> bool {
    var c_etld: u8[..256] = [];
    get_canonical_cookie_effective_domain(c, c_etld);
    return eq_ascii_fold(c_etld[..], etld_plus_one);
}

// Finds an existing cookie in the jar colliding with `c` according to the canonical key:
// (name, domain, path, host_only, partition_key, source_port, source_scheme).
fn find_canonical_cookie_collision_index(jar: const CanonicalCookieJar&, c: const CanonicalCookie&) -> i64 {
    for i in jar.cookies.len {
        let existing = jar.cookies[i];
        if existing.name[..] == c.name[..] &&
           eq_ascii_fold(existing.domain[..], c.domain[..]) &&
           existing.path[..] == c.path[..] &&
           existing.host_only == c.host_only &&
           existing.partition_key[..] == c.partition_key[..] &&
           existing.source_port == c.source_port &&
           existing.source_scheme == c.source_scheme {
            return i;
        }
    }
    return -1;
}

// Enforces RFC 6265bis §5.6 / "cookie-alone" / Chromium Secure Cookie Invariant:
// An insecure cookie or non-secure URL CANNOT overwrite or shadow an existing Secure cookie
// matching the same (name, domain, path, partition_key).
fn would_insecure_overwrite_secure(existing: const CanonicalCookie&, new_cookie: const CanonicalCookie&, url_is_secure: bool) -> bool {
    if !existing.secure { return false; }
    if url_is_secure && new_cookie.secure { return false; }

    if existing.name[..] == new_cookie.name[..] &&
       eq_ascii_fold(existing.domain[..], new_cookie.domain[..]) &&
       existing.path[..] == new_cookie.path[..] &&
       existing.partition_key[..] == new_cookie.partition_key[..] {
        return true;
    }
    return false;
}

// Domain GC candidate comparator:
// 1. OBC: Domain cookies (!host_only) evicted before Host-only cookies (host_only)
// 2. LRA: Oldest last_access_utc first
// 3. Tie-breaker: Oldest creation_utc first
// 4. Sequence tie-breaker: creation_seq first
fn domain_gc_candidate_less(a: const CanonicalCookie&, b: const CanonicalCookie&) -> bool {
    // Domain cookies evicted before origin-bound host-only cookies
    if !a.host_only && b.host_only { return true; }
    if a.host_only && !b.host_only { return false; }

    // Least Recently Accessed (LRA)
    if a.last_access_utc != b.last_access_utc {
        return a.last_access_utc < b.last_access_utc;
    }

    // Tie-breaker: creation_utc
    if a.creation_utc != b.creation_utc {
        return a.creation_utc < b.creation_utc;
    }

    return a.creation_seq < b.creation_seq;
}

// Fallback comparator when priority quotas are exhausted
fn fallback_gc_candidate_less(a: const CanonicalCookie&, b: const CanonicalCookie&) -> bool {
    let pa = priority_rank(a.priority);
    let pb = priority_rank(b.priority);
    if pa != pb { return pa < pb; }
    if !a.secure && b.secure { return true; }
    if a.secure && !b.secure { return false; }
    return domain_gc_candidate_less(a, b);
}

// Executes Domain Garbage Collection for a specific effective domain (eTLD+1).
// Trigger: domain count > max_cookies_per_domain (180).
// Target: reduce down to target_cookies_per_domain (150).
// Sequence:
//   Step 1: Expire expired cookies.
//   Step 2 & 3: 6 Purge Rounds with priority quotas (Low=30, Med=50, High=70):
//     Round 1: Low Non-Secure
//     Round 2: Low Secure
//     Round 3: Medium Non-Secure
//     Round 4: High Non-Secure  (High Non-Secure evicted before Medium Secure!)
//     Round 5: Medium Secure
//     Round 6: High Secure
// Returns total number of evicted cookies.
fn garbage_collect_per_domain(jar: CanonicalCookieJar&, etld_plus_one: const u8[:], now_us: i64) -> i64 {
    var domain_count: i64 = 0;
    for i in jar.cookies.len {
        if cookie_matches_effective_domain(jar.cookies[i], etld_plus_one) {
            domain_count += 1;
        }
    }

    if domain_count <= jar.max_cookies_per_domain {
        return 0;
    }

    var total_evicted: i64 = 0;

    // Step 1: Evict expired cookies for this domain
    var expired_seqs: i64[>..] = [];
    for i in jar.cookies.len {
        let c = jar.cookies[i];
        if cookie_matches_effective_domain(c, etld_plus_one) && is_cookie_expired(c, now_us) {
            expired_seqs.push(c.creation_seq);
        }
    }
    if expired_seqs.len > 0 {
        retain(jar.cookies) { c => seq_not_in_list(c.creation_seq, expired_seqs[..]) };
        jar.evicted_expired_count += expired_seqs.len;
        total_evicted += expired_seqs.len;
        domain_count -= expired_seqs.len;
    }

    if domain_count <= jar.target_cookies_per_domain {
        return total_evicted;
    }

    var need_to_evict = domain_count - jar.target_cookies_per_domain;

    // Tally priority counts for this domain
    var low_count: i64 = 0;
    var med_count: i64 = 0;
    var high_count: i64 = 0;
    for i in jar.cookies.len {
        let c = jar.cookies[i];
        if cookie_matches_effective_domain(c, etld_plus_one) {
            match c.priority {
                Low => { low_count += 1; },
                Medium => { med_count += 1; },
                High => { high_count += 1; },
            };
        }
    }

    var low_excess = max(0, low_count - jar.quota_low);
    var med_excess = max(0, med_count - jar.quota_medium);
    var high_excess = max(0, high_count - jar.quota_high);

    // 6 Rounds of Priority Quota Purge
    for round_idx in 1..7 {
        if need_to_evict <= 0 { break; }

        var target_prio = CookiePriority.Low;
        var protect_sec = true;
        var quota_allowed: i64 = 0;

        if round_idx == 1 {
            // Round 1: Low Priority, protect Secure (evict Low Non-Secure)
            target_prio = CookiePriority.Low;
            protect_sec = true;
            quota_allowed = min(need_to_evict, low_excess);
        } else if round_idx == 2 {
            // Round 2: Low Priority, unprotect Secure (evict Low Secure)
            target_prio = CookiePriority.Low;
            protect_sec = false;
            quota_allowed = min(need_to_evict, low_excess);
        } else if round_idx == 3 {
            // Round 3: Medium Priority, protect Secure (evict Medium Non-Secure)
            target_prio = CookiePriority.Medium;
            protect_sec = true;
            quota_allowed = min(need_to_evict, med_excess);
        } else if round_idx == 4 {
            // Round 4: High Priority, protect Secure (evict High Non-Secure)
            // CRITICAL: High Non-Secure is evicted BEFORE Medium Secure!
            target_prio = CookiePriority.High;
            protect_sec = true;
            quota_allowed = min(need_to_evict, high_excess);
        } else if round_idx == 5 {
            // Round 5: Medium Priority, unprotect Secure (evict Medium Secure)
            target_prio = CookiePriority.Medium;
            protect_sec = false;
            quota_allowed = min(need_to_evict, med_excess);
        } else if round_idx == 6 {
            // Round 6: High Priority, unprotect Secure (evict High Secure)
            target_prio = CookiePriority.High;
            protect_sec = false;
            quota_allowed = min(need_to_evict, high_excess);
        }

        if quota_allowed <= 0 { continue; }

        // Gather candidates matching priority and security mode
        var candidates: CanonicalCookie[>..] = [];
        for i in jar.cookies.len {
            let c = jar.cookies[i];
            if cookie_matches_effective_domain(c, etld_plus_one) && c.priority == target_prio {
                if !protect_sec || !c.secure {
                    candidates.push(c);
                }
            }
        }

        if candidates.len == 0 { continue; }

        // Sort candidates: OBC (domain before host) and LRA (oldest access first)
        stable_sort(candidates[..]) { a, b => domain_gc_candidate_less(a, b) };

        let evict_this_round = min(quota_allowed, candidates.len);
        var to_delete_seqs: i64[>..] = [];
        for k in evict_this_round {
            to_delete_seqs.push(candidates[k].creation_seq);
        }

        retain(jar.cookies) { c => seq_not_in_list(c.creation_seq, to_delete_seqs[..]) };

        if target_prio == CookiePriority.Low {
            low_excess -= evict_this_round;
        } else if target_prio == CookiePriority.Medium {
            med_excess -= evict_this_round;
        } else {
            high_excess -= evict_this_round;
        }

        jar.evicted_domain_count += evict_this_round;
        total_evicted += evict_this_round;
        need_to_evict -= evict_this_round;
    }

    // Fallback pass: if need_to_evict > 0, evict regardless of quota (Low -> Med -> High)
    if need_to_evict > 0 {
        var fallback_candidates: CanonicalCookie[>..] = [];
        for i in jar.cookies.len {
            let c = jar.cookies[i];
            if cookie_matches_effective_domain(c, etld_plus_one) {
                fallback_candidates.push(c);
            }
        }
        stable_sort(fallback_candidates[..]) { a, b => fallback_gc_candidate_less(a, b) };

        let evict_fallback = min(need_to_evict, fallback_candidates.len);
        var fb_seqs: i64[>..] = [];
        for k in evict_fallback {
            fb_seqs.push(fallback_candidates[k].creation_seq);
        }
        retain(jar.cookies) { c => seq_not_in_list(c.creation_seq, fb_seqs[..]) };
        jar.evicted_domain_count += evict_fallback;
        total_evicted += evict_fallback;
    }

    return total_evicted;
}

// Global GC candidate comparator:
// 1. Priority: Low < Medium < High
// 2. Security: Non-Secure before Secure
// 3. OBC: Domain cookies before Host-only cookies
// 4. LRA: oldest last_access_utc first
// 5. Tie-breaker: oldest creation_utc
fn global_gc_candidate_less(a: const CanonicalCookie&, b: const CanonicalCookie&) -> bool {
    let pa = priority_rank(a.priority);
    let pb = priority_rank(b.priority);
    if pa != pb { return pa < pb; }

    if !a.secure && b.secure { return true; }
    if a.secure && !b.secure { return false; }

    if !a.host_only && b.host_only { return true; }
    if a.host_only && !b.host_only { return false; }

    if a.last_access_utc != b.last_access_utc {
        return a.last_access_utc < b.last_access_utc;
    }

    if a.creation_utc != b.creation_utc {
        return a.creation_utc < b.creation_utc;
    }

    return a.creation_seq < b.creation_seq;
}

// Executes Global Garbage Collection across the entire jar.
// Trigger: total cookies > max_cookies_global (3300).
// Target: reduce down to target_cookies_global (3000).
// 30-Day Purge Immunity: cookies accessed within the last 30 days are immune!
// Returns total number of evicted cookies.
fn garbage_collect_global(jar: CanonicalCookieJar&, now_us: i64) -> i64 {
    if jar.cookies.len <= jar.max_cookies_global {
        return 0;
    }

    var total_evicted: i64 = 0;

    // Step 1: Evict expired cookies globally
    var expired_seqs: i64[>..] = [];
    for i in jar.cookies.len {
        let c = jar.cookies[i];
        if is_cookie_expired(c, now_us) {
            expired_seqs.push(c.creation_seq);
        }
    }
    if expired_seqs.len > 0 {
        retain(jar.cookies) { c => seq_not_in_list(c.creation_seq, expired_seqs[..]) };
        jar.evicted_expired_count += expired_seqs.len;
        total_evicted += expired_seqs.len;
    }

    if jar.cookies.len <= jar.target_cookies_global {
        return total_evicted;
    }

    var need_to_evict = jar.cookies.len - jar.target_cookies_global;

    // Step 2: Gather non-immune candidates (accessed >= 30 days ago)
    var candidates: CanonicalCookie[>..] = [];
    for i in jar.cookies.len {
        let c = jar.cookies[i];
        let elapsed = now_us - c.last_access_utc;
        if elapsed < K_SAFE_FROM_GLOBAL_PURGE_US {
            // IMMUNE from global purge!
            continue;
        }
        candidates.push(c);
    }

    if candidates.len == 0 {
        return total_evicted;
    }

    // Sort non-immune candidates
    stable_sort(candidates[..]) { a, b => global_gc_candidate_less(a, b) };

    let evict_count = min(need_to_evict, candidates.len);
    var to_delete_seqs: i64[>..] = [];
    for k in evict_count {
        to_delete_seqs.push(candidates[k].creation_seq);
    }

    retain(jar.cookies) { c => seq_not_in_list(c.creation_seq, to_delete_seqs[..]) };

    jar.evicted_global_count += evict_count;
    total_evicted += evict_count;
    return total_evicted;
}

// Comparator for CHIPS LRA eviction
fn chips_lra_candidate_less(a: const CanonicalCookie&, b: const CanonicalCookie&) -> bool {
    if a.last_access_utc != b.last_access_utc {
        return a.last_access_utc < b.last_access_utc;
    }
    if a.creation_utc != b.creation_utc {
        return a.creation_utc < b.creation_utc;
    }
    return a.creation_seq < b.creation_seq;
}

// Enforces CHIPS Partition memory quota (10 KB per partition-domain pair).
// Evicts oldest partitioned cookies by LRA until total memory <= 10240 bytes.
fn enforce_chips_quota(jar: CanonicalCookieJar&, partition_key: const u8[:], etld_plus_one: const u8[:], now_us: i64) -> i64 {
    if partition_key.len == 0 { return 0; }

    var total_bytes: i64 = 0;
    var candidates: CanonicalCookie[>..] = [];

    for i in jar.cookies.len {
        let c = jar.cookies[i];
        if c.partitioned && c.partition_key[..] == partition_key && cookie_matches_effective_domain(c, etld_plus_one) {
            let cookie_bytes = payload_size(c) + c.domain.len + c.path.len;
            total_bytes += cookie_bytes;
            candidates.push(c);
        }
    }

    if total_bytes <= K_PER_PARTITION_DOMAIN_MAX_COOKIE_BYTES {
        return 0;
    }

    // Sort by LRA (oldest access first)
    stable_sort(candidates[..]) { a, b => chips_lra_candidate_less(a, b) };

    var to_delete_seqs: i64[>..] = [];
    var evicted_count: i64 = 0;

    for k in candidates.len {
        if total_bytes <= K_PER_PARTITION_DOMAIN_MAX_COOKIE_BYTES {
            break;
        }
        let c = candidates[k];
        let cookie_bytes = payload_size(c) + c.domain.len + c.path.len;
        total_bytes -= cookie_bytes;
        to_delete_seqs.push(c.creation_seq);
        evicted_count += 1;
    }

    if to_delete_seqs.len > 0 {
        retain(jar.cookies) { c => seq_not_in_list(c.creation_seq, to_delete_seqs[..]) };
        jar.evicted_chips_count += evicted_count;
    }

    return evicted_count;
}

// Ingestion entry point into the Canonical Cookie Monster Jar:
// 1. Enforces multi-tier security invariants (prefixes, secure requirements, script API checks).
// 2. Checks collision and overwrite rules (non-secure cannot overwrite secure).
// 3. On overwrite: PRESERVES creation_utc immutable invariant!
// 4. On new insert: assigns creation_utc and creation_seq.
// 5. Triggers CHIPS quota, Domain GC, and Global GC.
fn set_canonical_cookie(
    jar: CanonicalCookieJar&,
    c: CanonicalCookie&,
    is_http_api: bool,
    url_is_secure: bool,
    now_us: i64
) -> bool {
    // 1. Security invariants validation
    if !validate_canonical_cookie_security(c, url_is_secure, is_http_api) {
        jar.rejected_security_count += 1;
        return false;
    }

    // If written via non-HTTP script API (document.cookie), enforce script name validation
    if !is_http_api && !validate_script_cookie_name(c.name[..]) {
        jar.rejected_security_count += 1;
        return false;
    }

    // 2. Determine effective domain
    var etld_plus_one: u8[..256] = [];
    get_canonical_cookie_effective_domain(c, etld_plus_one);

    // 3. Collision resolution
    let collision_idx = find_canonical_cookie_collision_index(jar, c);
    if collision_idx >= 0 {
        let existing = jar.cookies[collision_idx];

        // RFC 6265bis §5.6 / Chromium: Non-secure cannot overwrite existing Secure cookie
        if would_insecure_overwrite_secure(existing, c, url_is_secure) {
            jar.rejected_security_count += 1;
            return false;
        }

        // Allowed Overwrite:
        // CRITICAL INVARIANT: preserve existing.creation_utc!
        c.creation_utc = existing.creation_utc;
        c.creation_seq = existing.creation_seq;
        c.last_update_utc = now_us;
        c.last_access_utc = now_us;

        jar.cookies[collision_idx] = c;
        jar.overwritten_count += 1;
        return true;
    }

    // 4. RFC 6265bis §5.6: Secure Shadowing Protection
    // An insecure cookie cannot be created if a Secure cookie with the same name, domain, path exists
    for i in jar.cookies.len {
        let existing = jar.cookies[i];
        if would_insecure_overwrite_secure(existing, c, url_is_secure) {
            jar.rejected_security_count += 1;
            return false;
        }
    }

    // 5. Insert new cookie
    c.creation_utc = now_us;
    c.last_update_utc = now_us;
    c.last_access_utc = now_us;
    c.creation_seq = jar.seq_counter;
    jar.seq_counter += 1;

    jar.cookies.push(c);

    // 6. CHIPS quota check
    if c.partitioned && c.partition_key.len > 0 {
        enforce_chips_quota(jar, c.partition_key[..], etld_plus_one[..], now_us);
    }

    // 7. Domain GC
    garbage_collect_per_domain(jar, etld_plus_one[..], now_us);

    // 8. Global GC
    garbage_collect_global(jar, now_us);

    return true;
}

// Counts cookies belonging to a specific effective domain (eTLD+1).
fn count_domain_cookies(jar: const CanonicalCookieJar&, etld_plus_one: const u8[:]) -> i64 {
    var count: i64 = 0;
    for i in jar.cookies.len {
        if cookie_matches_effective_domain(jar.cookies[i], etld_plus_one) {
            count += 1;
        }
    }
    return count;
}

// Comparator for request outgoing cookie ordering (RFC 6265 §5.4)
fn request_cookie_order_less(a: const CanonicalCookie&, b: const CanonicalCookie&) -> bool {
    if a.path.len != b.path.len {
        return a.path.len > b.path.len; // Longest path first
    }
    if a.creation_utc != b.creation_utc {
        return a.creation_utc < b.creation_utc; // Earliest creation first
    }
    return a.creation_seq < b.creation_seq;
}

// Queries and extracts matching cookies for an outgoing HTTP request.
// Updates last_access_utc for retrieved cookies.
// Returns cookies sorted per RFC 6265 §5.4:
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
    out: CanonicalCookie[>..]&
) {
    for i in jar.cookies.len {
        var c = jar.cookies[i];

        // Expired cookies excluded
        if is_cookie_expired(c, now_us) {
            continue;
        }

        // Domain matching: Host-only exact match vs Domain-cookie suffix match
        if c.host_only {
            if !eq_ascii_fold(c.domain[..], host) {
                continue;
            }
        } else {
            if !cookie_domain_match(host, c.domain[..]) {
                continue;
            }
        }

        // Path matching: req_path first, cookie_path second
        if !cookie_path_match(path, c.path[..]) {
            continue;
        }

        // Secure flag isolation
        if c.secure && !is_secure {
            continue;
        }

        // HttpOnly isolation
        if c.httponly && !is_http_api {
            continue;
        }

        // Origin-Bound Cookies (OBC) port isolation
        if !is_cookie_sendable_for_obc(c, scheme, port) {
            continue;
        }

        // CHIPS Partitioning matching
        if c.partitioned {
            if c.partition_key[..] != partition_key {
                continue;
            }
        }

        // Update last_access_utc for LRA
        jar.cookies[i].last_access_utc = now_us;
        c.last_access_utc = now_us;

        out.push(c);
    }

    // RFC 6265 §5.4 sorting:
    // Longest path length first; tie-breaker: earliest creation_utc first.
    stable_sort(out[..]) { a, b => request_cookie_order_less(a, b) };
}

// --- Idiomatic Fluent Helpers on CanonicalCookieJar (UFCS) ---

// Adds a new cookie directly to the jar in-place and returns a reference for fluent chaining:
// let c .= jar.add("session_id", "val").with_domain("example.com").with_secure();
fn add(jar: CanonicalCookieJar&, name: const u8[:], val: const u8[:]) -> CanonicalCookie& {
    var c = CanonicalCookie { .. };
    c.name.append(name);
    c.value.append(val);
    c.creation_seq = jar.seq_counter;
    jar.seq_counter += 1;
    return jar.cookies.push(c);
}

// Purges expired cookies across the entire jar with a clean single-line retain closure:
fn purge_expired(jar: CanonicalCookieJar&, now_us: i64) -> i64 {
    let before = jar.cookies.len;
    jar.cookies.retain() { !it.is_expired(now_us) };
    let evicted = before - jar.cookies.len;
    jar.evicted_expired_count += evicted;
    return evicted;
}

// High-level declarative helper for generating outgoing HTTP Cookie header
fn build_cookie_header<B>(
    jar: CanonicalCookieJar&,
    out: B&,
    host: const u8[:],
    path: const u8[:],
    is_secure: bool,
    now_us: i64
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
    partition_key: const u8[:] = ""
) {
    let u = parse_canonical_cookie_url(req_url);
    var matched: CanonicalCookie[>..] = [];
    get_canonical_cookies_for_request(
        jar,
        u.host[..],
        u.path[..],
        u.scheme[..],
        u.port,
        u.is_secure,
        true,
        partition_key,
        now_us,
        matched
    );
    format_cookie_header_value(out, matched[..]);
}

// Ingests a raw Set-Cookie header directly for a given request URL.
fn set_cookie_header(
    jar: CanonicalCookieJar&,
    req_url: const u8[:],
    set_cookie_raw: const u8[:],
    now_us: i64,
    is_http_api: bool = true
) -> bool {
    let u = parse_canonical_cookie_url(req_url);
    var def_path: u8[..256] = [];
    default_cookie_path_calc(u.path[..], def_path);
    var c, cause, ok = parse_canonical_set_cookie(set_cookie_raw, u.host[..], def_path[..], now_us);
    if !ok {
        return false;
    }
    c.source_scheme = if u.is_secure { CookieSourceScheme.Secure } else { CookieSourceScheme.NonSecure };
    c.source_port = u.port;
    return set_canonical_cookie(jar, c, is_http_api, u.is_secure, now_us);
}

// Queries a cookie value by name for a specific request URL.
fn get(
    jar: CanonicalCookieJar&,
    req_url: const u8[:],
    name: const u8[:],
    now_us: i64
) -> const u8[:] {
    let u = parse_canonical_cookie_url(req_url);
    for i in jar.cookies.len {
        if jar.cookies[i].name[..] != name { continue; }
        let c = jar.cookies[i];
        if is_cookie_expired(c, now_us) { continue; }
        if c.host_only {
            if !eq_ascii_fold(c.domain[..], u.host[..]) { continue; }
        } else {
            if !cookie_domain_match(u.host[..], c.domain[..]) { continue; }
        }
        if !cookie_path_match(u.path[..], c.path[..]) { continue; }
        if c.secure && !u.is_secure { continue; }
        if !is_cookie_sendable_for_obc(c, u.scheme[..], u.port) { continue; }

        jar.cookies[i].last_access_utc = now_us;
        return jar.cookies[i].value[..];
    }
    return "";
}

// Queries a cookie value by name globally from the jar (first match).
fn get(jar: const CanonicalCookieJar&, name: const u8[:]) -> const u8[:] {
    for i in jar.cookies.len {
        if jar.cookies[i].name[..] == name {
            return jar.cookies[i].value[..];
        }
    }
    return "";
}

