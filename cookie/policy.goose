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

    // Prohibited CTL rejection (DELETE_COOKIE_CONTROL_CHAR = 11 / crbug.com/238041)
    if has_prohibited_cookie_ctl(cookie_name) ||
       has_prohibited_cookie_ctl(cookie_val.value[..]) ||
       has_prohibited_cookie_ctl(cookie_val.domain[..]) ||
       has_prohibited_cookie_ctl(cookie_val.path[..]) {
        return false;
    }

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

// ---- SiteForCookies and Navigation Context (RFC 6265bis / Chromium net::SiteForCookies) ----

struct SiteForCookies {
    scheme: u8[..16] = [],
    registrable_domain: u8[..128] = [],
    schemefully_same: bool = true,
    is_null: bool = false,
}

fn site_for_cookies_from_url(url: const u8[:]) -> SiteForCookies {
    let parsed = parse_canonical_cookie_url(url);
    var s = SiteForCookies { schemefully_same: true, is_null: false, .. };
    s.scheme.append(parsed.scheme[..]);
    extract_etld_plus_one(parsed.host[..], s.registrable_domain);
    return s;
}

fn site_for_cookies_from_parsed_url(url_val: const Url&) -> SiteForCookies {
    var s = SiteForCookies { schemefully_same: true, is_null: false, .. };
    s.scheme.append(scheme(url_val));
    extract_etld_plus_one(hostname(url_val), s.registrable_domain);
    return s;
}

fn null_site_for_cookies() -> SiteForCookies {
    return SiteForCookies { is_null: true, schemefully_same: false };
}

fn format_site_for_cookies<B>(out: B&, site: const SiteForCookies&) {
    out.append("SiteForCookies: {site=");
    if site.is_null {
        out.append("null; schemefully_same=false}");
    } else {
        out.append(site.scheme[..]);
        out.append("://");
        out.append(site.registrable_domain[..]);
        out.append("; schemefully_same=");
        out.append(if site.schemefully_same { "true" } else { "false" });
        out.push('}');
    }
}

fn compare_with_frame_tree_site_and_revise(site: SiteForCookies&, frame_url: const u8[:]) {
    guard !site.is_null else { return; }
    let frame_site = site_for_cookies_from_url(frame_url);

    if !eq_ascii_fold(site.registrable_domain[..], frame_site.registrable_domain[..]) {
        site.is_null = true;
        site.schemefully_same = false;
        site.scheme.clear();
        site.registrable_domain.clear();
        return;
    }

    if !eq_ascii_fold(site.scheme[..], frame_site.scheme[..]) {
        site.schemefully_same = false;
    }
}

// Computes SiteForCookies evaluating the full ancestor chain (RFC 6265bis §5.2.1 / CTX-01, CTX-02)
fn compute_site_for_cookies_with_ancestors(
    top_url: const u8[:],
    ancestor_urls: const u8[:][:],
    is_sandboxed: bool = false
) -> SiteForCookies {
    if is_sandboxed || starts_with(top_url, "data:") || starts_with(top_url, "about:") {
        return null_site_for_cookies();
    }

    var top_site = site_for_cookies_from_url(top_url);
    for a_url in ancestor_urls {
        compare_with_frame_tree_site_and_revise(top_site, a_url);
        if top_site.is_null {
            return null_site_for_cookies();
        }
    }
    return top_site;
}

fn is_first_party(site: const SiteForCookies&, req_url: const u8[:], compute_schemefully: bool = true) -> bool {
    guard !site.is_null else { return false; }
    if compute_schemefully && !site.schemefully_same { return false; }

    let req_site = site_for_cookies_from_url(req_url);
    if !eq_ascii_fold(site.registrable_domain[..], req_site.registrable_domain[..]) {
        return false;
    }
    if compute_schemefully && !eq_ascii_fold(site.scheme[..], req_site.scheme[..]) {
        return false;
    }
    return true;
}

fn is_request_same_site(site: const SiteForCookies&, req_url: const u8[:]) -> bool {
    return is_first_party(site, req_url, true);
}

// ---- Chromium net::CookieInclusionStatus codes -----------------------------

let EXCLUDE_UNKNOWN: i64 = 0;
let EXCLUDE_SAMESITE_STRICT: i64 = 1;
let EXCLUDE_SAMESITE_LAX: i64 = 2;
let EXCLUDE_SAMESITE_UNSPECIFIED_TREATED_AS_LAX: i64 = 3;
let EXCLUDE_SAMESITE_NONE_INSECURE: i64 = 4;
let EXCLUDE_NONCOOKIEABLE_SCHEME: i64 = 5;
let EXCLUDE_SECURE_ONLY: i64 = 6;
let EXCLUDE_HTTP_ONLY: i64 = 7;
let EXCLUDE_DOMAIN_MISMATCH: i64 = 8;
let EXCLUDE_NOT_ON_PATH: i64 = 9;
let EXCLUDE_FAILURE_TO_STORE: i64 = 10;
let WARN_SAMESITE_LAX_ALLOWING_UNSAFE: i64 = 11;
let WARN_CROSS_SITE_REDIRECT_DOWNGRADE_CHANGES_INCLUSION: i64 = 12;

// ---- FirstPartyURLPolicy and IsolationInfo ---------------------------------

enum FirstPartyURLPolicy {
    NEVER_CHANGE_FIRST_PARTY_URL,
    UPDATE_FIRST_PARTY_URL_ON_REDIRECT,
}

enum SameSiteContextType {
    CrossSite,
    SameSiteLaxMethodUnsafe,
    SameSiteLax,
    SameSiteStrict,
}

struct SameSiteCookieContext {
    context_type: SameSiteContextType = SameSiteContextType.CrossSite,
    schemefully_same: bool = true,
    is_reload: bool = false,
    had_cross_site_hop: bool = false,
}

fn new_samesite_context(ctx_type: SameSiteContextType) -> SameSiteCookieContext {
    return SameSiteCookieContext { context_type: ctx_type, .. };
}

fn can_set_canonical_cookie_for_context(
    cookie_val: const CanonicalCookie&,
    context: const SameSiteCookieContext&,
    is_main_frame: bool,
    is_secure_channel: bool
) -> bool, i64 {
    // Cross-site subresources or non-main frame navigations cannot set SameSite cookies
    if !is_main_frame && context.context_type == SameSiteContextType.CrossSite {
        match cookie_val.same_site {
            Strict => { return false, EXCLUDE_SAMESITE_STRICT; },
            Lax => { return false, EXCLUDE_SAMESITE_LAX; },
            Default => { return false, EXCLUDE_SAMESITE_UNSPECIFIED_TREATED_AS_LAX; },
            None => {
                if !is_secure_channel { return false, EXCLUDE_SAMESITE_NONE_INSECURE; }
            },
        };
    }
    if cookie_val.same_site == CookieSameSite.None && !is_secure_channel {
        return false, EXCLUDE_SAMESITE_NONE_INSECURE;
    }
    return true, EXCLUDE_UNKNOWN;
}
