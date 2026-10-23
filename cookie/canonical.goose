// Canonical Cookie Model (CanonicalCookie).
// Clean room implementation of Chromium CookieMonster canonical data structure and semantics.
//
// Core Types:
//   CanonicalCookie - In-memory and persistent cookie entity with microsecond lifecycle timestamps.
//
// Standards & Specifications:
//   RFC 6265bis Section 5.3 - Storage model, microsecond timestamps, and canonicalization.
//   RFC 6265bis Section 5.4 - Canonical unique key collision resolution.
//   CHIPS (Cookies Having Independent Partitioned State) top-frame partition key model.
//   Origin-Bound Cookies (OBC) source scheme and source port binding.
namespace wing;

import std;
import cookie.constants;
import cookie.psl;
import cookie.parser;
import cookie.policy;
import cookie.engine;
import cookie.store;

// ---- canonical cookie model ------------------------------------------------

// CanonicalCookie represents the atomic, fully-validated state of an HTTP cookie
// in memory and persistent storage, containing origin bindings, microsecond lifecycle
// timestamps, partition keys, and security isolation metadata.
struct CanonicalCookie {
    name: u8[..256] = [],
    value: u8[..4096] = [],
    encrypted_value: u8[..4096] = [],
    domain: u8[..256] = [],
    path: u8[..256] = "/",
    creation_utc: i64 = 0,     // Microsecond UTC timestamp (immutable across overwrites)
    last_access_utc: i64 = 0,  // Microsecond UTC timestamp (Least Recently Accessed key)
    last_update_utc: i64 = 0,  // Microsecond UTC timestamp
    expires_utc: i64 = 0,      // Microsecond UTC timestamp (capped at 400 days)
    partition_key: u8[..256] = [], // Scheme + eTLD+1 (CHIPS top frame site key)
    source_port: i32 = -1,     // 1..65535 or -1 (unset/unknown)
    host_only: bool = true,
    persistent: bool = false,  // True if Max-Age or Expires was specified
    secure: bool = false,
    httponly: bool = false,
    partitioned: bool = false,
    same_site: CookieSameSite = CookieSameSite.Default,
    priority: CookiePriority = CookiePriority.Medium,
    source_scheme: CookieSourceScheme = CookieSourceScheme.Unset,
    creation_seq: i64 = 0,
}

// Standalone constructor for CanonicalCookie.
fn new_canonical_cookie(name: const u8[:], val: const u8[:]) -> CanonicalCookie {
    var new_cookie = CanonicalCookie { .. };
    new_cookie.name.append(name);
    new_cookie.value.append(val);
    return new_cookie;
}

// ---- lifecycle & expiration predicates -------------------------------------

// Evaluates whether a cookie is expired relative to microsecond timestamp now_us.
// Session cookies (persistent == false) never expire automatically by time.
fn expired(cookie_val: const CanonicalCookie&, now_us: i64) -> bool {
    if !cookie_val.persistent { return false; }
    if cookie_val.expires_utc <= 0 { return true; }
    return cookie_val.expires_utc <= now_us;
}

// Idiomatic boolean alias for expired(cookie_val, now_us).
fn is_expired(cookie_val: const CanonicalCookie&, now_us: i64) -> bool {
    return expired(cookie_val, now_us);
}

// Cookie Incrementalism: evaluates if the cookie is still within the 2-minute
// Lax-allowing-unsafe (Lax+POST) window from its creation_utc.
fn in_lax_allowing_unsafe_window(cookie_val: const CanonicalCookie&, now_us: i64) -> bool {
    if cookie_val.same_site != CookieSameSite.Default { return false; }
    let elapsed_us = now_us - cookie_val.creation_utc;
    return elapsed_us >= 0 && elapsed_us <= K_LAX_ALLOWING_UNSAFE_WINDOW_US;
}

fn is_in_lax_allowing_unsafe_window(cookie_val: const CanonicalCookie&, now_us: i64) -> bool {
    return in_lax_allowing_unsafe_window(cookie_val, now_us);
}

// Combined payload size in bytes (RFC 6265bis Section 5.5: name + value <= 4096 bytes).
fn payload_size(cookie_val: const CanonicalCookie&) -> i64 {
    return cookie_val.name.len + cookie_val.value.len;
}

// ---- fluent in-place builder methods (ufcs) --------------------------------

fn with_value(cookie_ref: CanonicalCookie&, val: const u8[:]) -> CanonicalCookie& {
    cookie_ref.value.clear();
    cookie_ref.value.append(val);
    return cookie_ref;
}

fn with_domain(cookie_ref: CanonicalCookie&, domain_val: const u8[:], host_only: bool = false) -> CanonicalCookie& {
    cookie_ref.domain.clear();
    var clean_domain = domain_val;
    var is_host = host_only;
    if clean_domain.len > 0 && clean_domain[0] == '.' {
        clean_domain = clean_domain[1..];
        is_host = false;
    }
    cookie_ref.domain.append(clean_domain);
    cookie_ref.host_only = is_host;
    return cookie_ref;
}

fn with_host(cookie_ref: CanonicalCookie&, host_val: const u8[:]) -> CanonicalCookie& {
    cookie_ref.domain.clear();
    if host_val.len > 0 && host_val[0] == '.' {
        cookie_ref.domain.append(host_val[1..]);
    } else {
        cookie_ref.domain.append(host_val);
    }
    cookie_ref.host_only = true;
    return cookie_ref;
}

fn with_path(cookie_ref: CanonicalCookie&, path_val: const u8[:]) -> CanonicalCookie& {
    cookie_ref.path.clear();
    cookie_ref.path.append(path_val);
    return cookie_ref;
}

fn with_secure(cookie_ref: CanonicalCookie&, is_secure: bool = true) -> CanonicalCookie& {
    cookie_ref.secure = is_secure;
    if is_secure && cookie_ref.source_scheme == CookieSourceScheme.Unset {
        cookie_ref.source_scheme = CookieSourceScheme.Secure;
    }
    return cookie_ref;
}

fn with_http_only(cookie_ref: CanonicalCookie&, is_http_only: bool = true) -> CanonicalCookie& {
    cookie_ref.httponly = is_http_only;
    return cookie_ref;
}

fn with_same_site(cookie_ref: CanonicalCookie&, same_site_mode: CookieSameSite) -> CanonicalCookie& {
    cookie_ref.same_site = same_site_mode;
    return cookie_ref;
}

fn with_priority(cookie_ref: CanonicalCookie&, priority_level: CookiePriority) -> CanonicalCookie& {
    cookie_ref.priority = priority_level;
    return cookie_ref;
}

fn with_partition_key(cookie_ref: CanonicalCookie&, key: const u8[:]) -> CanonicalCookie& {
    cookie_ref.partition_key.clear();
    cookie_ref.partition_key.append(key);
    cookie_ref.partitioned = (key.len > 0);
    return cookie_ref;
}

fn with_max_age_seconds(cookie_ref: CanonicalCookie&, seconds: i64, now_us: i64) -> CanonicalCookie& {
    let max_allowed_seconds = K_MAX_COOKIE_AGE_US / 1000000;
    let capped_sec = if seconds > max_allowed_seconds { max_allowed_seconds } else { seconds };
    cookie_ref.expires_utc = now_us + capped_sec * 1000000;
    cookie_ref.persistent = true;
    return cookie_ref;
}

fn with_expires_utc(cookie_ref: CanonicalCookie&, expires_us: i64) -> CanonicalCookie& {
    cookie_ref.expires_utc = expires_us;
    cookie_ref.persistent = true;
    return cookie_ref;
}

fn with_source(cookie_ref: CanonicalCookie&, scheme: CookieSourceScheme, port: i32) -> CanonicalCookie& {
    cookie_ref.source_scheme = scheme;
    cookie_ref.source_port = port;
    return cookie_ref;
}

// ---- matching & routing predicates (ufcs) --------------------------------

fn matches_domain(cookie_val: const CanonicalCookie&, host: const u8[:]) -> bool {
    if cookie_val.host_only {
        return eq_ascii_fold(cookie_val.domain[..], host);
    }
    return cookie_domain_match(host, cookie_val.domain[..]);
}

fn matches_path(cookie_val: const CanonicalCookie&, req_path: const u8[:]) -> bool {
    return cookie_path_match(req_path, cookie_val.path[..]);
}

// ---- unique key formatting & serialization --------------------------------

// Computes the canonical unique key for collision resolution.
// In modern CookieMonster with OBC & CHIPS, cookies are unique on:
// (name, domain, path, host_only, partition_key, source_scheme, source_port).
fn format_unique_key<B>(out: B&, cookie_val: const CanonicalCookie&) {
    out.append(cookie_val.name[..]);
    out.push('\0');
    out.append(cookie_val.domain[..]);
    out.push('\0');
    out.append(cookie_val.path[..]);
    out.push('\0');
    out.append(if cookie_val.host_only { "H" } else { "D" });
    out.push('\0');
    out.append(cookie_val.partition_key[..]);
    out.push('\0');
    format(out, cookie_val.source_port as i64);
    out.push('\0');
    out.append(source_scheme_to_string(cookie_val.source_scheme));
}

// Classic RFC 6265 unique key (name, domain, path) for legacy equivalence checks.
fn format_legacy_unique_key<B>(out: B&, cookie_val: const CanonicalCookie&) {
    out.append(cookie_val.name[..]);
    out.push('\0');
    out.append(cookie_val.domain[..]);
    out.push('\0');
    out.append(cookie_val.path[..]);
}

// Serializes CanonicalCookie into a standard Set-Cookie string.
fn format<B>(out: B&, cookie_val: const CanonicalCookie&) {
    out.append(cookie_val.name[..]);
    out.push('=');
    out.append(cookie_val.value[..]);

    if !cookie_val.host_only && cookie_val.domain.len > 0 {
        out.append("; Domain=");
        out.append(cookie_val.domain[..]);
    }
    if cookie_val.path.len > 0 {
        out.append("; Path=");
        out.append(cookie_val.path[..]);
    }
    if cookie_val.secure { out.append("; Secure"); }
    if cookie_val.httponly { out.append("; HttpOnly"); }
    if cookie_val.partitioned { out.append("; Partitioned"); }

    if cookie_val.same_site != CookieSameSite.Default {
        out.append("; SameSite=");
        out.append(same_site_to_string(cookie_val.same_site));
    }
    if cookie_val.priority != CookiePriority.Medium {
        out.append("; Priority=");
        out.append(priority_to_string(cookie_val.priority));
    }
}
