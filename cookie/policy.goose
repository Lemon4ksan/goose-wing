// Multi-tier Security, Isolation & Cookie Policy Engine.
// Clean Room Implementation of draft-ietf-httpbis-layered-cookies, RFC 6265bis SameSite & OBC.
namespace wing;

import std;
import cookie.constants;
import cookie.canonical;
import cookie.psl;

// ---- http method & origin trust ----

// Checks whether an HTTP method is considered safe per RFC 9110 (GET, HEAD, OPTIONS, TRACE).
fn safe_http_method(method: const u8[:]) -> bool {
    return eq_ascii_fold(method, "GET") ||
           eq_ascii_fold(method, "HEAD") ||
           eq_ascii_fold(method, "OPTIONS") ||
           eq_ascii_fold(method, "TRACE");
}

fn is_safe_http_method(method: const u8[:]) -> bool {
    return safe_http_method(method);
}

// Checks whether host is a trustworthy non-cryptographic origin (e.g. localhost, 127.0.0.1, ::1)
// per W3C Secure Contexts / Chromium origin-bound cookies.
fn trustworthy_non_crypto_host(host: const u8[:]) -> bool {
    let clean_host = if host.len > 0 && host[0] == '.' { host[1..] } else { host };
    return clean_host == "localhost" || clean_host == "127.0.0.1" || clean_host == "::1";
}

fn is_trustworthy_non_crypto_host(host: const u8[:]) -> bool {
    return trustworthy_non_crypto_host(host);
}

// ---- origin-bound adjustment ----

// Rewrites source_port and source_scheme for trustworthy non-cryptographic origins.
// Chromium OBC: if a trustworthy non-cryptographic origin sets a Secure cookie on default port 80,
// source_port is modified to 443 and source_scheme marked as Secure so future standard HTTPS access
// is not blocked by port mismatch.
fn adjust_origin_bound_cookies_on_insert(
    cookie_ref: CanonicalCookie&,
    host: const u8[:],
    port: i32,
    is_secure_channel: bool,
) {
    if is_secure_channel {
        cookie_ref.source_scheme = CookieSourceScheme.Secure;
        cookie_ref.source_port = if port > 0 { port } else { 443 };
        return;
    }

    if trustworthy_non_crypto_host(host) && cookie_ref.secure && (port == 80 || port <= 0) {
        cookie_ref.source_scheme = CookieSourceScheme.Secure;
        cookie_ref.source_port = 443; // Automatic port rewrite
    } else {
        cookie_ref.source_scheme = CookieSourceScheme.NonSecure;
        cookie_ref.source_port = if port > 0 { port } else { 80 };
    }
}

// ---- script api & prefix security validation ----

// Validates cookie name against non-HTTP script APIs (document.cookie, CookieStore API).
// draft-ietf-httpbis-layered-cookies §4.1.3 & WHATWG:
// Case-insensitive check: if byte-lowercased name starts with "__http-" or "__host-http-",
// return false to prevent script shadowing of protected HTTP-only cookies.
fn validate_script_cookie_name(name: const u8[:]) -> bool {
    var lower_buf: u8[..64] = [];
    let check_len = if name.len < 16 { name.len } else { 16 };
    for char_idx in check_len {
        let char_byte = name[char_idx];
        lower_buf.push(if char_byte >= 'A' && char_byte <= 'Z' { char_byte + 32 } else { char_byte });
    }
    let lower_prefix = lower_buf[..];
    if starts_with(lower_prefix, "__http-") || starts_with(lower_prefix, "__host-http-") {
        return false;
    }
    return true;
}

// Validates cookie security invariants across prefixes, channels, and APIs.
// Implements:
// 1. __Secure- (case-sensitive on HTTP): requires Secure + Secure origin.
// 2. __Host- (case-sensitive on HTTP): requires Secure + Secure origin + host_only + Path=/.
// 3. __Http- (case-sensitive on HTTP): requires Secure + Secure origin + HttpOnly; rejected from script.
// 4. __Host-Http- (case-sensitive on HTTP): requires Secure + Secure origin + HttpOnly + host_only + Path=/; rejected from script.
// 5. Partitioned (CHIPS): requires Secure.
// 6. SameSite=None: strictly requires Secure.
// 7. Non-HTTP script context: prohibits HttpOnly, blocks byte-lowercased __http- / __host-http-.
fn validate_canonical_cookie_security(
    cookie_val: const CanonicalCookie&,
    is_secure_channel: bool,
    is_http_api: bool,
) -> bool {
    let cookie_name = cookie_val.name[..];

    // Non-HTTP API restrictions
    if !is_http_api {
        if cookie_val.httponly { return false; } // Script cannot set HttpOnly
        if !validate_script_cookie_name(cookie_name) { return false; }
    }

    // RFC 6265bis SameSite=None and CHIPS Partitioned both require Secure
    if cookie_val.same_site == CookieSameSite.None && !cookie_val.secure { return false; }
    if cookie_val.partitioned && !cookie_val.secure { return false; }

    return validate_security_cookie_prefixes(cookie_val, cookie_name, is_secure_channel, is_http_api);
}

// ---- schemeful same-site engine ----

// Schemeful Same-Site: compares two origins by (scheme, eTLD+1).
// Transition between http://example.com and https://example.com is cross-site!
fn schemeful_same_site(scheme1: const u8[:], host1: const u8[:], scheme2: const u8[:], host2: const u8[:]) -> bool {
    guard eq_ascii_fold(scheme1, scheme2) else { return false; }

    var etld1: u8[..128] = [];
    var etld2: u8[..128] = [];
    extract_etld_plus_one(host1, etld1);
    extract_etld_plus_one(host2, etld2);

    return eq_ascii_fold(etld1[..], etld2[..]);
}

fn is_schemeful_same_site(scheme1: const u8[:], host1: const u8[:], scheme2: const u8[:], host2: const u8[:]) -> bool {
    return schemeful_same_site(scheme1, host1, scheme2, host2);
}

// ---- request sendability evaluation ----

// Evaluates whether a cookie is sendable for a request under RFC 6265bis SameSite rules.
// Implements:
// - SameSite=Strict: sendable only in same-site context.
// - SameSite=Lax: sendable same-site OR top-level cross-site navigation with safe method (GET/HEAD).
// - SameSite=Default: Lax with Lax-allowing-unsafe (Lax+POST) 2-minute window from creation_utc.
// - SameSite=None: sendable cross-site if channel is secure.
fn cookie_sendable_for_samesite(
    cookie_val: const CanonicalCookie&,
    is_same_site: bool,
    is_top_level_navigation: bool,
    is_safe_method: bool,
    now_us: i64,
) -> bool {
    if is_same_site {
        return true;
    }

    // Cross-site subresources (fetch, img, iframe) block all SameSite cookies except None
    if !is_top_level_navigation {
        return cookie_val.same_site == CookieSameSite.None;
    }

    // Top-level cross-site navigation
    return match cookie_val.same_site {
        Strict => false,
        Lax => is_safe_method,
        None => true,
        Default => {
            if is_safe_method {
                true
            } else {
                in_lax_allowing_unsafe_window(cookie_val, now_us)
            }
        },
    };
}

fn is_cookie_sendable_for_samesite(
    cookie_val: const CanonicalCookie&,
    is_same_site: bool,
    is_top_level_navigation: bool,
    is_safe_method: bool,
    now_us: i64,
) -> bool {
    return cookie_sendable_for_samesite(cookie_val, is_same_site, is_top_level_navigation, is_safe_method, now_us);
}

// Evaluates whether a cookie is sendable under Origin-Bound Cookies (OBC) port isolation.
// Host-only cookies strictly enforce source_port match.
// Domain cookies opt-out of port isolation.
// Trustworthy non-crypto origins (localhost, 127.0.0.1) allow HTTP scheme and port 80/443 interop.
fn cookie_sendable_for_obc(
    cookie_val: const CanonicalCookie&,
    req_scheme: const u8[:],
    req_port: i32,
    host: const u8[:] = "",
) -> bool {
    let is_trustworthy = host.len > 0 && trustworthy_non_crypto_host(host);

    // Scheme check: Secure cookies require secure request scheme (or trustworthy non-crypto origin)
    if cookie_val.source_scheme == CookieSourceScheme.Secure && !eq_ascii_fold(req_scheme, "https") && !is_trustworthy {
        return false;
    }

    // Port check: applied to host-only cookies
    if cookie_val.host_only && cookie_val.source_port > 0 && req_port > 0 {
        if is_trustworthy && cookie_val.source_port == 443 && req_port == 80 {
            return true;
        }
        if cookie_val.source_port != req_port {
            return false;
        }
    }

    return true;
}

fn is_cookie_sendable_for_obc(
    cookie_val: const CanonicalCookie&,
    req_scheme: const u8[:],
    req_port: i32,
    host: const u8[:] = "",
) -> bool {
    return cookie_sendable_for_obc(cookie_val, req_scheme, req_port, host);
}

// ---- internal implementation helpers ----

fn validate_security_cookie_prefixes(
    cookie_val: const CanonicalCookie&,
    cookie_name: const u8[:],
    is_secure_channel: bool,
    is_http_api: bool,
) -> bool {
    // Anti-Shadowing / Cookie Crumbles defense (USENIX Security / SHAD-01):
    // A nameless cookie cannot have a value starting with security prefixes
    if cookie_name.len == 0 {
        let val = cookie_val.value[..];
        if starts_with(val, "__Host-") || starts_with(val, "__Secure-") ||
           starts_with(val, "__Http-") || starts_with(val, "__Host-Http-") {
            return false;
        }
    }

    // Prefix: __Secure-
    if starts_with(cookie_name, "__Secure-") {
        if !cookie_val.secure || !is_secure_channel { return false; }
    }

    // Prefix: __Host-
    if starts_with(cookie_name, "__Host-") {
        if !cookie_val.secure || !is_secure_channel { return false; }
        if !cookie_val.host_only || cookie_val.path[..] != "/" { return false; }
    }

    // Prefix: __Http- (draft-ietf-httpbis-layered-cookies)
    if starts_with(cookie_name, "__Http-") {
        if !is_http_api { return false; }
        if !cookie_val.secure || !is_secure_channel || !cookie_val.httponly { return false; }
    }

    // Prefix: __Host-Http- (draft-ietf-httpbis-layered-cookies)
    if starts_with(cookie_name, "__Host-Http-") {
        if !is_http_api { return false; }
        if !cookie_val.secure || !is_secure_channel || !cookie_val.httponly { return false; }
        if !cookie_val.host_only || cookie_val.path[..] != "/" { return false; }
    }

    return true;
}
