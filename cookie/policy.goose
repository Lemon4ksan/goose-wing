// Multi-tier Security, Isolation & Cookie Policy Engine.
// Clean Room Implementation of draft-ietf-httpbis-layered-cookies, RFC 6265bis SameSite & OBC.
namespace wing;

import std;
import cookie.constants;
import cookie.canonical;
import cookie.psl;

// Checks whether an HTTP method is considered safe per RFC 9110 (GET, HEAD, OPTIONS, TRACE).
fn is_safe_http_method(method: const u8[:]) -> bool {
    return eq_ascii_fold(method, "GET") ||
           eq_ascii_fold(method, "HEAD") ||
           eq_ascii_fold(method, "OPTIONS") ||
           eq_ascii_fold(method, "TRACE");
}

// Checks whether host is a trustworthy non-cryptographic origin (e.g. localhost, 127.0.0.1, ::1)
// per W3C Secure Contexts / Chromium origin-bound cookies.
fn is_trustworthy_non_crypto_host(host: const u8[:]) -> bool {
    let clean = if host.len > 0 && host[0] == '.' { host[1..] } else { host };
    return clean == "localhost" || clean == "127.0.0.1" || clean == "::1";
}

// Rewrites source_port and source_scheme for trustworthy non-cryptographic origins.
// Chromium OBC: if a trustworthy non-cryptographic origin sets a Secure cookie on default port 80,
// source_port is modified to 443 and source_scheme marked as Secure so future standard HTTPS access
// is not blocked by port mismatch.
fn adjust_origin_bound_cookies_on_insert(c: CanonicalCookie&, host: const u8[:], port: i32, is_secure_channel: bool) {
    if is_secure_channel {
        c.source_scheme = CookieSourceScheme.Secure;
        c.source_port = if port > 0 { port } else { 443 };
    } else {
        if is_trustworthy_non_crypto_host(host) && c.secure && (port == 80 || port <= 0) {
            c.source_scheme = CookieSourceScheme.Secure;
            c.source_port = 443; // Automatic port rewrite
        } else {
            c.source_scheme = CookieSourceScheme.NonSecure;
            c.source_port = if port > 0 { port } else { 80 };
        }
    }
}

// Validates cookie name against non-HTTP script APIs (document.cookie, CookieStore API).
// draft-ietf-httpbis-layered-cookies §4.1.3 & WHATWG:
// Case-insensitive check: if byte-lowercased name starts with "__http-" or "__host-http-",
// return false to prevent script shadowing of protected HTTP-only cookies.
fn validate_script_cookie_name(name: const u8[:]) -> bool {
    var lower_buf: u8[..64] = [];
    let check_len = if name.len < 16 { name.len } else { 16 };
    for i in check_len {
        let b = name[i];
        lower_buf.push(if b >= 'A' && b <= 'Z' { b + 32 } else { b });
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
fn validate_canonical_cookie_security(c: const CanonicalCookie&, is_secure_channel: bool, is_http_api: bool) -> bool {
    let n = c.name[..];

    // Non-HTTP API restrictions
    if !is_http_api {
        if c.httponly { return false; } // Script cannot set HttpOnly
        if !validate_script_cookie_name(n) { return false; }
    }

    // RFC 6265bis SameSite=None requires Secure
    if c.same_site == CookieSameSite.None && !c.secure {
        return false;
    }

    // CHIPS Partitioned requires Secure
    if c.partitioned && !c.secure {
        return false;
    }

    // Prefix: __Secure-
    if starts_with(n, "__Secure-") {
        if !c.secure || !is_secure_channel { return false; }
    }

    // Prefix: __Host-
    if starts_with(n, "__Host-") {
        if !c.secure || !is_secure_channel { return false; }
        if !c.host_only || c.path[..] != "/" { return false; }
    }

    // Prefix: __Http- (draft-ietf-httpbis-layered-cookies)
    if starts_with(n, "__Http-") {
        if !is_http_api { return false; }
        if !c.secure || !is_secure_channel || !c.httponly { return false; }
    }

    // Prefix: __Host-Http- (draft-ietf-httpbis-layered-cookies)
    if starts_with(n, "__Host-Http-") {
        if !is_http_api { return false; }
        if !c.secure || !is_secure_channel || !c.httponly { return false; }
        if !c.host_only || c.path[..] != "/" { return false; }
    }

    return true;
}

// Schemeful Same-Site: compares two origins by (scheme, eTLD+1).
// Transition between http://example.com and https://example.com is cross-site!
fn is_schemeful_same_site(scheme1: const u8[:], host1: const u8[:], scheme2: const u8[:], host2: const u8[:]) -> bool {
    guard eq_ascii_fold(scheme1, scheme2) else { return false; }

    var etld1: u8[..128] = [];
    var etld2: u8[..128] = [];
    extract_etld_plus_one(host1, etld1);
    extract_etld_plus_one(host2, etld2);

    return eq_ascii_fold(etld1[..], etld2[..]);
}

// Evaluates whether a cookie is sendable for a request under RFC 6265bis SameSite rules.
// Implements:
// - SameSite=Strict: sendable only in same-site context.
// - SameSite=Lax: sendable same-site OR top-level cross-site navigation with safe method (GET/HEAD).
// - SameSite=Default: Lax with Lax-allowing-unsafe (Lax+POST) 2-minute window from creation_utc.
// - SameSite=None: sendable cross-site if channel is secure.
fn is_cookie_sendable_for_samesite(
    c: const CanonicalCookie&,
    is_same_site: bool,
    is_top_level_navigation: bool,
    is_safe_method: bool,
    now_us: i64
) -> bool {
    if is_same_site {
        return true;
    }

    // Cross-site subresources (fetch, img, iframe) block all SameSite cookies except None
    if !is_top_level_navigation {
        return c.same_site == CookieSameSite.None;
    }

    // Top-level cross-site navigation
    return match c.same_site {
        Strict => false,
        Lax => is_safe_method,
        None => true,
        Default => {
            if is_safe_method {
                true
            } else {
                // Lax-allowing-unsafe (Lax+POST) exception within 2 minutes of creation
                is_in_lax_allowing_unsafe_window(c, now_us)
            }
        },
    };
}

// Evaluates whether a cookie is sendable under Origin-Bound Cookies (OBC) port isolation.
// Host-only cookies strictly enforce source_port match.
// Domain cookies opt-out of port isolation.
// Trustworthy non-crypto origins (localhost, 127.0.0.1) allow HTTP scheme and port 80/443 interop.
fn is_cookie_sendable_for_obc(c: const CanonicalCookie&, req_scheme: const u8[:], req_port: i32, host: const u8[:] = "") -> bool {
    let is_trustworthy = host.len > 0 && is_trustworthy_non_crypto_host(host);

    // Scheme check: Secure cookies require secure request scheme (or trustworthy non-crypto origin)
    if c.source_scheme == CookieSourceScheme.Secure && !eq_ascii_fold(req_scheme, "https") && !is_trustworthy {
        return false;
    }

    // Port check: applied to host-only cookies
    if c.host_only && c.source_port > 0 && req_port > 0 {
        if is_trustworthy && c.source_port == 443 && req_port == 80 {
            return true;
        }
        if c.source_port != req_port {
            return false;
        }
    }

    return true;
}
