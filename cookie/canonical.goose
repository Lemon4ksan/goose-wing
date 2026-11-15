// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Canonical cookie data structure and serialization (RFC 6265bis, CHIPS).
namespace wing;

import std;
import core from "..";
import .limits;
import .constants;
import .policy;
import http.headers;

// ---- canonical cookie model ------------------------------------------------

// Options for cookie request matching and same-site sendability.
struct CookieAccessOptions {
    is_same_site:            bool = true,
    is_top_level_navigation: bool = true,
    is_safe_method:          bool = true,
    had_cross_site_hop:      bool = false,
}

// Source options for cookie insertion and security validation.
struct CookieSourceOptions {
    is_http_api:   bool = true,
    url_is_secure: bool = true,
}

// Context options for cookie frame and channel security.
struct CookieInclusionOptions {
    is_main_frame:     bool = true,
    is_secure_channel: bool = true,
}

// Represents a validated HTTP cookie in memory or persistent storage.
struct CanonicalCookie {
    name:            u8[..256]          = [],
    value:           u8[..4096]         = [],
    encrypted_value: u8[..4096]         = [],
    domain:          u8[..256]          = [],
    path:            u8[..256]          = "/",
    creation_utc:    i64                = 0, // Microsecond UTC timestamp (immutable across overwrites)
    last_access_utc: i64                = 0, // Microsecond UTC timestamp (Least Recently Accessed key)
    last_update_utc: i64                = 0, // Microsecond UTC timestamp
    expires_utc:     i64                = 0, // Microsecond UTC timestamp (capped at 400 days)
    partition_key:   u8[..256]          = [], // Scheme + eTLD+1 (CHIPS top frame site key)
    source_port:     i32                = -1, // 1..65535 or -1 (unset/unknown)
    host_only:       bool               = true,
    has_domain_attr: bool               = false,
    has_path_attr:   bool               = false,
    persistent:      bool               = false, // True if Max-Age or Expires was specified
    secure:          bool               = false,
    httponly:        bool               = false,
    partitioned:     bool               = false,
    same_site:       CookieSameSite     = CookieSameSite.Default,
    priority:        CookiePriority     = CookiePriority.Medium,
    source_scheme:   CookieSourceScheme = CookieSourceScheme.Unset,
    creation_seq:    i64                = 0,
}

inline fn is_prohibited_canonical_ctl(s: const u8[:]) -> bool {
    for b in s {
        if (b <= 0x08) || (b >= 0x0A && b <= 0x1F) || b == 0x7F {
            return true;
        }
    }
    return false;
}

inline fn is_valid_canonical_cookie_name(name: const u8[:]) -> bool {
    for b in name {
        guard core::is_tchar(b) else { return false; }
    }
    return true;
}

inline fn is_valid_canonical_cookie_val(val: const u8[:]) -> bool {
    let is_quoted = val.len >= 2 && val[0] == '"' && val[core::sub_sat_i64(val.len, 1)] == '"';
    let body = if is_quoted { val[1..^1] } else { val };
    for b in body {
        guard core::is_ascii_vchar(b) && b != '"' && b != ',' && b != ';' && b != '\\' else {
            return false;
        }
    }
    return true;
}

inline fn is_valid_canonical_domain_attr(dom: const u8[:]) -> bool {
    guard dom.len > 0 && dom[core::sub_sat_i64(dom.len, 1)] != '.' else { return false; }
    if !core::is_ip_address_literal(dom) && (core::contains(dom, "..") || dom.contains_byte(':')) {
        return false;
    }
    for b in dom {
        if b <= 0x20 || b >= 0x7F || b == ';' || b == '/' || b == '?' || b == '#' || b == '\\' {
            return false;
        }
    }
    return true;
}

// Constructs a CanonicalCookie, verifying that name and value do not exceed
// 4096 bytes and contain no prohibited octets or control characters (RFC 6265 Section 4.1.1).
fn new_canonical_cookie(name: const u8[:], val: const u8[:]) -> CanonicalCookie {
    var new_cookie = CanonicalCookie { .. };
    guard core::add_sat_i64(name.len, val.len) <= cookie_internal::K_MAX_COOKIE_NAME_VAL_LEN else {
        return new_cookie;
    }
    guard is_valid_canonical_cookie_name(name) && is_valid_canonical_cookie_val(val) else {
        return new_cookie;
    }
    if name.len == 0 && val.contains_byte('=') {
        return new_cookie;
    }
    var committed = false;
    defer if !committed {
        new_cookie.name.clear();
        new_cookie.value.clear();
    };
    guard new_cookie.name.try_set(name) && new_cookie.value.try_set(val) else {
        return new_cookie;
    }
    committed = true;
    return new_cookie;
}

// ---- lifecycle & expiration predicates -------------------------------------

// Evaluates whether a cookie is expired relative to microsecond timestamp now_us.
// Session cookies (persistent == false) never expire automatically by time.
// Persistent cookies expire if expires_utc <= now_us or expires_utc <= 0.
fn is_expired(cookie_val: const CanonicalCookie&, now_us: i64) -> bool {
    if !cookie_val.persistent { return false; }
    if cookie_val.expires_utc <= 0 { return true; }
    return cookie_val.expires_utc <= now_us;
}

// Whether a cookie with default SameSite is within the 2-minute window allowing
// unsafe top-level navigations (RFC 6265bis Lax-allowing-unsafe).
fn is_in_lax_allowing_unsafe_window(cookie_val: const CanonicalCookie&, now_us: i64) -> bool {
    if cookie_val.same_site != CookieSameSite.Default { return false; }
    let elapsed_us = core::sub_sat_i64(now_us, cookie_val.creation_utc);
    return elapsed_us >= 0 && elapsed_us <= cookie_internal::K_LAX_ALLOWING_UNSAFE_WINDOW_US;
}

// Combined size of name and value in bytes (RFC 6265bis Section 5.5).
fn payload_size(cookie_val: const CanonicalCookie&) -> i64 {
    return core::add_sat_i64(cookie_val.name.len, cookie_val.value.len);
}

// ---- fluent in-place builder methods (ufcs) --------------------------------

// Replaces the cookie value in-place and returns cookie_ref for chaining.
fn with_value(cookie_ref: CanonicalCookie&, val: const u8[:]) -> CanonicalCookie& {
    guard core::add_sat_i64(cookie_ref.name.len, val.len) <= cookie_internal::K_MAX_COOKIE_NAME_VAL_LEN
        && is_valid_canonical_cookie_val(val) else {
        return cookie_ref;
    }
    if cookie_ref.name.len == 0 && val.contains_byte('=') {
        return cookie_ref;
    }
    let _ = cookie_ref.value.try_set(val);
    return cookie_ref;
}

// Sets the Domain attribute in-place, stripping any leading dot (RFC 6265 Section 5.2.3).
fn with_domain(cookie_ref: CanonicalCookie&, domain_val: const u8[:], host_only: bool = false) -> CanonicalCookie& {
    cookie_ref.has_domain_attr = true;
    let has_lead_dot = domain_val.len > 0 && domain_val[0] == '.';
    let clean_domain = if has_lead_dot { domain_val[1..] } else { domain_val };
    let is_host = if has_lead_dot { false } else { host_only };
    if !core::is_pure_ascii(clean_domain) {
        var ace_buf: u8[..256] = [];
        guard core::punycode_encode_domain(clean_domain, ace_buf)
            && is_valid_canonical_domain_attr(ace_buf[..])
            && cookie_ref.domain.try_set(ace_buf[..]) else {
            return cookie_ref;
        }
        cookie_ref.host_only = is_host;
        return cookie_ref;
    }
    guard is_valid_canonical_domain_attr(clean_domain) else { return cookie_ref; }
    guard cookie_ref.domain.try_set(clean_domain) else { return cookie_ref; }
    to_lower(cookie_ref.domain[..]);
    cookie_ref.host_only = is_host;
    return cookie_ref;
}

// Configures the cookie as host-only for host_val (RFC 6265 Section 5.3).
fn with_host(cookie_ref: CanonicalCookie&, host_val: const u8[:]) -> CanonicalCookie& {
    let clean = if host_val.len > 0 && host_val[0] == '.' { host_val[1..] } else { host_val };
    if !core::is_pure_ascii(clean) {
        var ace_buf: u8[..256] = [];
        guard core::punycode_encode_domain(clean, ace_buf)
            && is_valid_canonical_domain_attr(ace_buf[..])
            && cookie_ref.domain.try_set(ace_buf[..]) else {
            return cookie_ref;
        }
        cookie_ref.host_only = true;
        return cookie_ref;
    }
    guard is_valid_canonical_domain_attr(clean) else { return cookie_ref; }
    guard cookie_ref.domain.try_set(clean) else { return cookie_ref; }
    to_lower(cookie_ref.domain[..]);
    cookie_ref.host_only = true;
    return cookie_ref;
}

// Sets the cookie Path attribute in-place.
fn with_path(cookie_ref: CanonicalCookie&, path_val: const u8[:]) -> CanonicalCookie& {
    guard path_val.len > 0 && path_val[0] == '/'
        && !is_prohibited_canonical_ctl(path_val)
        && !path_val.contains_byte(';') else {
        return cookie_ref;
    }
    guard cookie_ref.path.try_set(path_val) else { return cookie_ref; }
    cookie_ref.has_path_attr = true;
    return cookie_ref;
}

// Sets the Secure attribute and defaults unset source_scheme to Secure.
fn with_secure(cookie_ref: CanonicalCookie&, is_secure: bool = true) -> CanonicalCookie& {
    cookie_ref.secure = is_secure;
    if is_secure && cookie_ref.source_scheme == CookieSourceScheme.Unset {
        cookie_ref.source_scheme = CookieSourceScheme.Secure;
    }
    return cookie_ref;
}

// Sets the HttpOnly attribute in-place.
fn with_http_only(cookie_ref: CanonicalCookie&, is_http_only: bool = true) -> CanonicalCookie& {
    cookie_ref.httponly = is_http_only;
    return cookie_ref;
}

// Sets the SameSite enforcement mode in-place.
fn with_same_site(cookie_ref: CanonicalCookie&, same_site_mode: CookieSameSite) -> CanonicalCookie& {
    cookie_ref.same_site = same_site_mode;
    return cookie_ref;
}

// Sets the eviction priority tier in-place.
fn with_priority(cookie_ref: CanonicalCookie&, priority_level: CookiePriority) -> CanonicalCookie& {
    cookie_ref.priority = priority_level;
    return cookie_ref;
}

// Sets the CHIPS top-frame partition key and updates the Partitioned flag.
fn with_partition_key(cookie_ref: CanonicalCookie&, key: const u8[:]) -> CanonicalCookie& {
    guard cookie_ref.partition_key.try_set(key) else { return cookie_ref; }
    cookie_ref.partitioned = (key.len > 0);
    return cookie_ref;
}

// RFC 6265 Section 5.2.2: The Max-Age Attribute - If delta-seconds is less than or equal to zero (0), let expiry-time be the earliest representable date and time.
fn with_max_age_seconds(cookie_ref: CanonicalCookie&, seconds: i64, now_us: i64) -> CanonicalCookie& {
    cookie_ref.persistent = true;
    if seconds <= 0 {
        cookie_ref.expires_utc = 0;
        return cookie_ref;
    }
    let capped_sec = min(seconds, cookie_internal::K_MAX_COOKIE_AGE_SEC);
    let delta_us = core::mul_sat_i64(capped_sec, 1000000);
    cookie_ref.expires_utc = core::add_sat_i64(now_us, delta_us);
    return cookie_ref;
}

// Sets an explicit microsecond UTC expiration timestamp and marks the cookie persistent.
fn with_expires_utc(cookie_ref: CanonicalCookie&, expires_us: i64) -> CanonicalCookie& {
    cookie_ref.expires_utc = expires_us;
    cookie_ref.persistent = true;
    return cookie_ref;
}

// Sets the origin-bound source scheme and port in-place.
fn with_source(cookie_ref: CanonicalCookie&, scheme: CookieSourceScheme, port: i32) -> CanonicalCookie& {
    cookie_ref.source_scheme = scheme;
    cookie_ref.source_port = port;
    return cookie_ref;
}

// ---- matching & routing predicates (ufcs) --------------------------------

// Whether host matches the cookie's host-only or domain-scoped rule (RFC 6265 Section 5.1.3 & RFC 6055).
fn matches_domain(cookie_val: const CanonicalCookie&, host: const u8[:]) -> bool {
    let clean_host = host.trim_byte('.').trim_byte('[').trim_byte(']');
    let clean_domain = cookie_val.domain[..].trim_byte('.').trim_byte('[').trim_byte(']');
    guard clean_host.len > 0 && clean_domain.len > 0 else { return false; }

    // RFC 6265 Section 5.1.3: If either host or cookie domain is an IP address,
    // domain-matching cannot be used; exact equality is required.
    if core::is_ip_address_literal(clean_host) || core::is_ip_address_literal(clean_domain) {
        return clean_domain.eq_ascii_fold(clean_host);
    }

    if cookie_val.host_only {
        return clean_domain.eq_ascii_fold(clean_host);
    }
    return cookie_domain_match(clean_host, clean_domain);
}

// Whether req_path matches the cookie's Path attribute (RFC 6265 Section 5.1.4).
fn matches_path(cookie_val: const CanonicalCookie&, req_path: const u8[:]) -> bool {
    return cookie_path_match(req_path, cookie_val.path[..]);
}

// ---- unique key formatting & serialization --------------------------------

inline fn is_serializable_canonical_cookie(cookie_val: const CanonicalCookie&) -> bool {
    let cname = cookie_val.name[..];
    let cval = cookie_val.value[..];
    guard is_valid_canonical_cookie_name(cname) && is_valid_canonical_cookie_val(cval) else {
        return false;
    }
    if cname.len == 0 && cval.contains_byte('=') {
        return false;
    }
    if !cookie_val.host_only && cookie_val.domain.len > 0 {
        guard is_valid_canonical_domain_attr(cookie_val.domain[..]) else { return false; }
    }
    if cookie_val.path.len > 0 {
        guard !is_prohibited_canonical_ctl(cookie_val.path[..]) && !cookie_val.path[..].contains_byte(';') else {
            return false;
        }
    }
    return true;
}

inline fn try_format_cookie_bool_flags<B>(out: B&, cookie_val: const CanonicalCookie&) -> bool {
    if cookie_val.secure {
        guard out.try_append("; Secure") else { return false; }
    }
    if cookie_val.httponly {
        guard out.try_append("; HttpOnly") else { return false; }
    }
    if cookie_val.partitioned {
        guard out.try_append("; Partitioned") else { return false; }
    }
    return true;
}

inline fn try_format_cookie_enum_attrs<B>(out: B&, cookie_val: const CanonicalCookie&) -> bool {
    if cookie_val.same_site != CookieSameSite.Default &&
        cookie_val.same_site != CookieSameSite.Unknown {
        guard out.try_append("; SameSite=") &&
            out.try_append(same_site_to_string(cookie_val.same_site)) else {
            return false;
        }
    }
    if cookie_val.priority != CookiePriority.Medium &&
        cookie_val.priority != CookiePriority.Unknown {
        guard out.try_append("; Priority=") &&
            out.try_append(priority_to_string(cookie_val.priority)) else {
            return false;
        }
    }
    if cookie_val.persistent && cookie_val.expires_utc <= 0 {
        guard out.try_append("; Max-Age=0") else { return false; }
    }
    return true;
}

// Serializes cookie into a Set-Cookie header string with bounded-buffer rollback.
fn try_format<B>(out: B&, cookie_val: const CanonicalCookie&) -> bool {
    guard is_serializable_canonical_cookie(cookie_val) else {
        return false;
    }
    let saved_len = out.len;
    var committed = false;
    defer if !committed { out.resize(saved_len); };

    if cookie_val.name.len > 0 {
        guard out.try_append(cookie_val.name[..]) && out.try_push('=') else { return false; }
    }
    guard out.try_append(cookie_val.value[..]) else { return false; }

    if !cookie_val.host_only && cookie_val.domain.len > 0 {
        guard out.try_append("; Domain=") && out.try_append(cookie_val.domain[..]) else { return false; }
    }
    if cookie_val.path.len > 0 {
        guard out.try_append("; Path=") && out.try_append(cookie_val.path[..]) else { return false; }
    }
    guard try_format_cookie_bool_flags(out, cookie_val) &&
        try_format_cookie_enum_attrs(out, cookie_val) else {
        return false;
    }
    committed = true;
    return true;
}

// Serializes cookie into a Set-Cookie header string.
fn format<B>(out: B&, cookie_val: const CanonicalCookie&) {
    if !try_format(out, cookie_val) {
        return;
    }
}

// Converts `c` into a removal cookie in-place (clears value, marks persistent, and sets expires_utc = 0)
// so `format` emits `name=; Path=...; Max-Age=0`.
fn make_removal(c: CanonicalCookie&) {
    c.value.clear();
    c.persistent = true;
    c.expires_utc = 0;
}

const COOKIE_DELTA_ORIGINAL: u8 = 0;
const COOKIE_DELTA_ADDED:    u8 = 1;
const COOKIE_DELTA_REMOVED:  u8 = 2;

// Bounded server-side cookie jar tracking request `original` cookies versus response `added` / `removed` deltas.
struct ServerCookieDeltaJar {
    cookies: CanonicalCookie[..64] = [],
    states:  u8[..64]              = [],
}

fn find_delta_cookie_idx(jar: const ServerCookieDeltaJar&, name: const u8[:]) -> i64 {
    for idx in jar.cookies.len {
        if jar.cookies[idx].name[..] == name {
            return idx;
        }
    }
    return -1;
}

// Records a cookie parsed from an incoming HTTP `Cookie` request header without marking it as a response delta.
fn add_original(jar: ServerCookieDeltaJar&, c: CanonicalCookie) -> bool {
    let idx = find_delta_cookie_idx(jar, c.name[..]);
    if idx >= 0 {
        jar.cookies[idx] = c;
        jar.states[idx] = COOKIE_DELTA_ORIGINAL;
        return true;
    }
    let saved_len = jar.cookies.len;
    var committed = false;
    defer if !committed {
        jar.cookies.resize(saved_len);
        jar.states.resize(saved_len);
    };
    guard jar.cookies.try_push(c) && jar.states.try_push(COOKIE_DELTA_ORIGINAL) else { return false; }
    committed = true;
    return true;
}

// Adds or updates a cookie in the server jar and marks it for emission in `Set-Cookie` response deltas.
fn add(jar: ServerCookieDeltaJar&, c: CanonicalCookie) -> bool {
    let idx = find_delta_cookie_idx(jar, c.name[..]);
    if idx >= 0 {
        jar.cookies[idx] = c;
        jar.states[idx] = COOKIE_DELTA_ADDED;
        return true;
    }
    let saved_len = jar.cookies.len;
    var committed = false;
    defer if !committed {
        jar.cookies.resize(saved_len);
        jar.states.resize(saved_len);
    };
    guard jar.cookies.try_push(c) && jar.states.try_push(COOKIE_DELTA_ADDED) else { return false; }
    committed = true;
    return true;
}

// Removes a cookie from the server jar. If the cookie was present in `original` cookies, converts it into
// a removal cookie (`Max-Age=0`) in the response delta; otherwise deletes it from the jar.
fn remove(jar: ServerCookieDeltaJar&, c: CanonicalCookie) -> bool {
    let idx = find_delta_cookie_idx(jar, c.name[..]);
    guard idx >= 0 else { return false; }
    let cur_state = jar.states[idx];
    if cur_state == COOKIE_DELTA_ORIGINAL || cur_state == COOKIE_DELTA_REMOVED {
        let existing .= jar.cookies[idx];
        var rem = c;
        if !c.has_domain_attr && c.domain.len == 0 && existing.domain.len > 0 {
            let _ = rem.domain.try_set(existing.domain[..]);
            rem.host_only = existing.host_only;
            rem.has_domain_attr = existing.has_domain_attr;
        }
        if !c.has_path_attr && existing.path.len > 0 {
            let _ = rem.path.try_set(existing.path[..]);
            rem.has_path_attr = existing.has_path_attr;
        }
        rem.secure = existing.secure || c.secure;
        rem.partitioned = existing.partitioned || c.partitioned;
        if rem.partitioned && rem.partition_key.len == 0 && existing.partition_key.len > 0 {
            let _ = rem.partition_key.try_set(existing.partition_key[..]);
        }
        make_removal(rem);
        jar.cookies[idx] = rem;
        jar.states[idx] = COOKIE_DELTA_REMOVED;
        return true;
    }
    let last_idx = core::sub_sat_i64(jar.cookies.len, 1);
    if idx < last_idx {
        jar.cookies[idx] = jar.cookies[last_idx];
        jar.states[idx] = jar.states[last_idx];
    }
    let _ = jar.cookies.pop();
    let _ = jar.states.pop();
    return true;
}

// Emits `Set-Cookie` headers into `headers` exclusively for `COOKIE_DELTA_ADDED`
// and `COOKIE_DELTA_REMOVED` entries in `jar`.
fn flush_cookie_deltas(jar: const ServerCookieDeltaJar&, headers: HeaderMap&) -> bool {
    let saved_headers = headers;
    var committed = false;
    defer if !committed {
        headers = saved_headers;
    };
    let n = min(jar.cookies.len, jar.states.len);
    for idx in n {
        let state = jar.states[idx];
        if state == COOKIE_DELTA_ADDED || state == COOKIE_DELTA_REMOVED {
            var cookie_line: u8[..5120] = [];
            guard try_format(cookie_line, jar.cookies[idx]) else {
                return false;
            }
            guard append_header(headers, "Set-Cookie", cookie_line[..]) else {
                return false;
            }
        }
    }
    committed = true;
    return true;
}
