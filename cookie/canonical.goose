// Canonical Cookie Model (CanonicalCookie)
// Clean room implementation of Chromium CookieMonster canonical data structure and semantics.
namespace wing;

import std;
import cookie.constants;
import cookie.psl;
import cookie.parser;
import cookie.policy;
import cookie.engine;
import cookie.store;

// CanonicalCookie represents the atomic, fully-validated state of an HTTP cookie
// in memory and persistent storage, containing origin bindings, microsecond lifecycle
// timestamps, partition keys, and security isolation metadata.
struct CanonicalCookie {
    name: u8[..256] = [],
    value: u8[..4096] = [],
    domain: u8[..256] = [],
    path: u8[..256] = "/",
    creation_utc: i64 = 0,     // microsecond UTC timestamp (immutable across overwrites)
    last_access_utc: i64 = 0,  // microsecond UTC timestamp (LRA key)
    last_update_utc: i64 = 0,  // microsecond UTC timestamp
    expires_utc: i64 = 0,      // microsecond UTC timestamp (capped at 400 days)
    partition_key: u8[..256] = [], // scheme + eTLD+1 (CHIPS top frame)
    source_port: i32 = -1,     // 1..65535 or -1 (unset/unknown)
    host_only: bool = true,
    persistent: bool = false,  // true if Max-Age or Expires set
    secure: bool = false,
    httponly: bool = false,
    partitioned: bool = false,
    same_site: CookieSameSite = CookieSameSite.Default,
    priority: CookiePriority = CookiePriority.Medium,
    source_scheme: CookieSourceScheme = CookieSourceScheme.Unset,
    creation_seq: i64 = 0,
}

// Returns true if cookie is expired relative to current microsecond timestamp now_us.
fn is_cookie_expired(c: const CanonicalCookie&, now_us: i64) -> bool {
    if !c.persistent { return false; }
    if c.expires_utc <= 0 { return true; }
    return c.expires_utc <= now_us;
}

// Cookie Incrementalism: Check if the cookie is still within the 2-minute
// Lax-allowing-unsafe (Lax+POST) window from its creation_utc.
fn is_in_lax_allowing_unsafe_window(c: const CanonicalCookie&, now_us: i64) -> bool {
    if c.same_site != CookieSameSite.Default { return false; }
    let elapsed = now_us - c.creation_utc;
    return elapsed >= 0 && elapsed <= K_LAX_ALLOWING_UNSAFE_WINDOW_US;
}

// Combined payload size in bytes (RFC 6265bis §5.5: name + value <= 4096 bytes).
fn payload_size(c: const CanonicalCookie&) -> i64 {
    return c.name.len + c.value.len;
}

// Computes the canonical unique key for collision resolution.
// In modern CookieMonster with OBC & CHIPS, cookies are unique on:
// (name, domain, path, host_only, partition_key, source_scheme, source_port).
fn format_unique_key<B>(out: B&, c: const CanonicalCookie&) {
    out.append(c.name[..]);
    out.push('\0');
    out.append(c.domain[..]);
    out.push('\0');
    out.append(c.path[..]);
    out.push('\0');
    out.append(if c.host_only { "H" } else { "D" });
    out.push('\0');
    out.append(c.partition_key[..]);
    out.push('\0');
    format(out, c.source_port as i64);
    out.push('\0');
    out.append(source_scheme_to_string(c.source_scheme));
}

// Classic RFC 6265 unique key (name, domain, path) for legacy equivalence checks.
fn format_legacy_unique_key<B>(out: B&, c: const CanonicalCookie&) {
    out.append(c.name[..]);
    out.push('\0');
    out.append(c.domain[..]);
    out.push('\0');
    out.append(c.path[..]);
}

// Serializes CanonicalCookie into a standard Set-Cookie string.
fn format<B>(out: B&, c: const CanonicalCookie&) {
    out.append(c.name[..]);
    out.push('=');
    out.append(c.value[..]);

    if !c.host_only && c.domain.len > 0 {
        out.append("; Domain=");
        out.append(c.domain[..]);
    }
    if c.path.len > 0 {
        out.append("; Path=");
        out.append(c.path[..]);
    }
    if c.secure { out.append("; Secure"); }
    if c.httponly { out.append("; HttpOnly"); }
    if c.partitioned { out.append("; Partitioned"); }

    if c.same_site != CookieSameSite.Default {
        out.append("; SameSite=");
        out.append(same_site_to_string(c.same_site));
    }
    if c.priority != CookiePriority.Medium {
        out.append("; Priority=");
        out.append(priority_to_string(c.priority));
    }
}

// --- Idiomatic Fluent Builder Methods (UFCS) ---

fn with_value(c: CanonicalCookie&, val: const u8[:]) -> CanonicalCookie& {
    c.value.clear();
    c.value.append(val);
    return c;
}

fn with_domain(c: CanonicalCookie&, d: const u8[:]) -> CanonicalCookie& {
    c.domain.clear();
    c.domain.append(d);
    c.host_only = (d.len == 0);
    return c;
}

fn with_path(c: CanonicalCookie&, p: const u8[:]) -> CanonicalCookie& {
    c.path.clear();
    c.path.append(p);
    return c;
}

fn with_secure(c: CanonicalCookie&, s: bool = true) -> CanonicalCookie& {
    c.secure = s;
    if s && c.source_scheme == CookieSourceScheme.Unset {
        c.source_scheme = CookieSourceScheme.Secure;
    }
    return c;
}

fn with_http_only(c: CanonicalCookie&, h: bool = true) -> CanonicalCookie& {
    c.httponly = h;
    return c;
}

fn with_same_site(c: CanonicalCookie&, s: CookieSameSite) -> CanonicalCookie& {
    c.same_site = s;
    return c;
}

fn with_priority(c: CanonicalCookie&, p: CookiePriority) -> CanonicalCookie& {
    c.priority = p;
    return c;
}

fn with_partition_key(c: CanonicalCookie&, key: const u8[:]) -> CanonicalCookie& {
    c.partition_key.clear();
    c.partition_key.append(key);
    c.partitioned = (key.len > 0);
    return c;
}

fn with_max_age_seconds(c: CanonicalCookie&, seconds: i64, now_us: i64) -> CanonicalCookie& {
    let capped_sec = if seconds > (K_MAX_COOKIE_AGE_US / 1000000) { K_MAX_COOKIE_AGE_US / 1000000 } else { seconds };
    c.expires_utc = now_us + capped_sec * 1000000;
    c.persistent = true;
    return c;
}

fn with_expires_utc(c: CanonicalCookie&, expires_us: i64) -> CanonicalCookie& {
    c.expires_utc = expires_us;
    c.persistent = true;
    return c;
}

fn with_source(c: CanonicalCookie&, scheme: CookieSourceScheme, port: i32) -> CanonicalCookie& {
    c.source_scheme = scheme;
    c.source_port = port;
    return c;
}

// Convenient predicate aliases for UFCS closures
fn is_expired(c: const CanonicalCookie&, now_us: i64) -> bool {
    return is_cookie_expired(c, now_us);
}

fn matches_domain(c: const CanonicalCookie&, host: const u8[:]) -> bool {
    if c.host_only {
        return eq_ascii_fold(c.domain[..], host);
    }
    return cookie_domain_match(host, c.domain[..]);
}

fn matches_path(c: const CanonicalCookie&, req_path: const u8[:]) -> bool {
    return cookie_path_match(req_path, c.path[..]);
}
