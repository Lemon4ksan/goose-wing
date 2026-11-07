// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Cookie security and isolation policy: SameSite, prefixes, and Origin-Bound Cookies
// (RFC 6265bis, CHIPS).
namespace wing;

import std;
import core from "..";
import .limits;
import .constants;
import .canonical;
import .psl;
import .parser;

// ---- http method & origin trust --------------------------------------------

// Whether host is a local loopback origin (localhost, 127.0.0.1, ::1, [::1]).
fn is_trustworthy_non_crypto_host(host: const u8[:]) -> bool {
    let clean_host = core::trim_byte(core::trim_byte(core::trim_byte(host, '.'), '['), ']');
    return eq_ascii_fold(clean_host, "localhost") || clean_host == "127.0.0.1" || clean_host == "::1";
}

// ---- origin-bound adjustment -----------------------------------------------

// Rewrites source_port and source_scheme for local loopback origins (Chromium OBC).
fn adjust_origin_bound_cookies_on_insert(
    cookie_ref:        CanonicalCookie&,
    host:              const u8[:],
    port:              i32,
    is_secure_channel: bool,
) {
    if is_secure_channel {
        cookie_ref.source_scheme = CookieSourceScheme.Secure;
        cookie_ref.source_port = if port > 0 { port } else { 443 };
        return;
    }

    if is_trustworthy_non_crypto_host(host) && cookie_ref.secure && (port == 80 || port <= 0) {
        cookie_ref.source_scheme = CookieSourceScheme.Secure;
        cookie_ref.source_port = 443; // Automatic port rewrite
    } else {
        cookie_ref.source_scheme = CookieSourceScheme.NonSecure;
        cookie_ref.source_port = if port > 0 { port } else { 80 };
    }
}

// ---- script api & prefix security validation -------------------------------

// Validates cookie names accessed from non-HTTP script APIs to prevent
// shadowing protected prefixes.
fn validate_script_cookie_name(name: const u8[:]) -> bool {
    if starts_with_fold(name, "__http-") || starts_with_fold(name, "__host-http-") {
        return false;
    }
    return true;
}

// Validates cookie security invariants for prefixes (__Secure-, __Host-,
// __Http-, __Host-Http-), Partitioned attributes, and SameSite=None (RFC 6265bis Section 5.6).
fn validate_canonical_cookie_security(
    cookie_val: const CanonicalCookie&,
    opts:       CookieSourceOptions = CookieSourceOptions { .. },
) -> bool {
    let cookie_name = cookie_val.name[..];
    if core::add_sat_i64(cookie_name.len, cookie_val.value.len) > internal::K_MAX_COOKIE_NAME_VAL_LEN {
        return false;
    }

    // Reject control characters
    if has_prohibited_cookie_ctl(cookie_name) ||
       has_prohibited_cookie_ctl(cookie_val.value[..]) ||
       has_prohibited_cookie_ctl(cookie_val.domain[..]) ||
       has_prohibited_cookie_ctl(cookie_val.path[..]) {
        return false;
    }

    if !cookie_val.host_only && is_public_suffix_domain(cookie_val.domain[..]) {
        return false;
    }

    // Non-HTTP API restrictions
    if !opts.is_http_api {
        if cookie_val.httponly { return false; } // Script cannot set HttpOnly
        if !validate_script_cookie_name(cookie_name) { return false; }
    }

    let is_trustworthy = opts.url_is_secure || is_trustworthy_non_crypto_host(cookie_val.domain[..]);
    if cookie_val.secure && !is_trustworthy { return false; }

    // RFC 6265bis SameSite=None and CHIPS Partitioned both require Secure
    if cookie_val.same_site == CookieSameSite.None && !cookie_val.secure { return false; }
    if cookie_val.partitioned {
        if !cookie_val.secure { return false; }
        if cookie_val.partition_key.len == 0 || has_prohibited_cookie_ctl(cookie_val.partition_key[..]) {
            return false;
        }
    }

    return validate_security_cookie_prefixes(cookie_val, cookie_name, opts);
}

// ---- schemeful same-site engine --------------------------------------------

// Schemeful Same-Site: compares two origins by (scheme, eTLD+1).
// Transition between http://example.com and https://example.com is cross-site!
fn is_schemeful_same_site(scheme1: const u8[:], host1: const u8[:], scheme2: const u8[:], host2: const u8[:]) -> bool {
    guard core::eq_ascii_fold(scheme1, scheme2) else { return false; }

    var etld1: u8[..128] = [];
    var etld2: u8[..128] = [];
    psl_extract_etld_plus_one(host1, etld1);
    psl_extract_etld_plus_one(host2, etld2);

    return core::eq_ascii_fold(etld1[..], etld2[..]);
}

// ---- request sendability evaluation ----------------------------------------

// Whether a cookie is sendable in the given request context (RFC 6265bis).
fn is_cookie_sendable_for_samesite(
    cookie_val: const CanonicalCookie&,
    access:     CookieAccessOptions,
    now_us:     i64,
) -> bool {
    if access.is_same_site {
        return true;
    }

    // Cross-site subresources (fetch, img, iframe) block all SameSite cookies except None
    if !access.is_top_level_navigation {
        return cookie_val.same_site == CookieSameSite.None;
    }

    // Top-level cross-site navigation
    return match cookie_val.same_site {
        Strict => false,
        Lax => access.is_safe_method,
        None => true,
        Default => {
            if access.is_safe_method {
                true
            } else {
                !access.had_cross_site_hop && is_in_lax_allowing_unsafe_window(cookie_val, now_us)
            }
        },
        Unknown => false,
    };
}

// Evaluates sendability under Origin-Bound Cookies (OBC) port isolation.
fn is_cookie_sendable_for_obc(
    cookie_val: const CanonicalCookie&,
    req_scheme: const u8[:],
    req_port:   i32,
    host:       const u8[:] = "",
) -> bool {
    let is_trustworthy = host.len > 0 && is_trustworthy_non_crypto_host(host);

    // Scheme check: Secure cookies require secure request scheme (or trustworthy non-crypto origin)
    if cookie_val.source_scheme == CookieSourceScheme.Secure
        && !core::eq_ascii_fold(req_scheme, "https") && !is_trustworthy {
        return false;
    }

    // Port check: applied to host-only cookies
    if cookie_val.host_only && cookie_val.source_port > 0 && req_port > 0 {
        if is_trustworthy {
            return true;
        }
        if cookie_val.source_port != req_port {
            return false;
        }
    }

    return true;
}

// ---- internal implementation helpers ---------------------------------------

fn validate_security_cookie_prefixes(
    cookie_val:  const CanonicalCookie&,
    cookie_name: const u8[:],
    opts:        CookieSourceOptions,
) -> bool {
    // Nameless cookies cannot have values starting with security prefixes
    if cookie_name.len == 0 {
        let cookie_value = cookie_val.value[..];
        if starts_with_fold(cookie_value, "__host-http-") ||
           starts_with_fold(cookie_value, "__host-") ||
           starts_with_fold(cookie_value, "__http-") ||
           starts_with_fold(cookie_value, "__secure-") {
            return false;
        }
    }

    // Prefix: __Host-Http- (draft-ietf-httpbis-layered-cookies, check before __Host- / __Http-)
    if starts_with_fold(cookie_name, "__host-http-") {
        if !opts.is_http_api { return false; }
        if !cookie_val.secure || !opts.url_is_secure || !cookie_val.httponly { return false; }
        if cookie_val.has_domain_attr || !cookie_val.host_only
            || !cookie_val.has_path_attr || cookie_val.path[..] != "/" {
            return false;
        }
    } else if starts_with_fold(cookie_name, "__host-") {
        // Prefix: __Host-
        if !cookie_val.secure || !opts.url_is_secure { return false; }
        if cookie_val.has_domain_attr || !cookie_val.host_only
            || !cookie_val.has_path_attr || cookie_val.path[..] != "/" {
            return false;
        }
    } else if starts_with_fold(cookie_name, "__http-") {
        // Prefix: __Http- (draft-ietf-httpbis-layered-cookies)
        if !opts.is_http_api { return false; }
        if !cookie_val.secure || !opts.url_is_secure || !cookie_val.httponly { return false; }
    } else if starts_with_fold(cookie_name, "__secure-") {
        // Prefix: __Secure-
        if !cookie_val.secure || !opts.url_is_secure { return false; }
    }

    return true;
}

// ---- site for cookies and navigation context -------------------------------

struct SiteForCookies {
    scheme:             u8[..16]  = [],
    registrable_domain: u8[..128] = [],
    schemefully_same:   bool      = true,
    is_null:            bool      = false,
}

fn site_for_cookies_from_url(url: const u8[:]) -> SiteForCookies {
    let parsed = parse_canonical_cookie_url(url);
    var site = SiteForCookies { schemefully_same: true, is_null: false, .. };
    let _ = site.scheme.try_set(parsed.scheme[..]);
    psl_extract_etld_plus_one(parsed.host[..], site.registrable_domain);
    return site;
}

fn site_for_cookies_from_parsed_url(url_val: const core::Url&) -> SiteForCookies {
    var site = SiteForCookies { schemefully_same: true, is_null: false, .. };
    let _ = site.scheme.try_set(scheme(url_val));
    psl_extract_etld_plus_one(hostname(url_val), site.registrable_domain);
    return site;
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

    if !core::eq_ascii_fold(site.registrable_domain[..], frame_site.registrable_domain[..]) {
        site.is_null = true;
        site.schemefully_same = false;
        site.scheme.clear();
        site.registrable_domain.clear();
        return;
    }

    if !core::eq_ascii_fold(site.scheme[..], frame_site.scheme[..]) {
        site.schemefully_same = false;
    }
}

// Computes SiteForCookies evaluating the full ancestor chain (RFC 6265bis Section 5.2.1 / CTX-01, CTX-02)
fn compute_site_for_cookies_with_ancestors(
    top_url:       const u8[:],
    ancestor_urls: const u8[:][:],
    is_sandboxed:  bool = false,
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
    if !core::eq_ascii_fold(site.registrable_domain[..], req_site.registrable_domain[..]) {
        return false;
    }
    if compute_schemefully && !core::eq_ascii_fold(site.scheme[..], req_site.scheme[..]) {
        return false;
    }
    return true;
}

fn is_request_same_site(site: const SiteForCookies&, req_url: const u8[:]) -> bool {
    return is_first_party(site, req_url, true);
}

// ---- Chromium net::CookieInclusionStatus codes -----------------------------

let EXCLUDE_UNKNOWN:                                      i64 = 0;
let EXCLUDE_SAMESITE_STRICT:                              i64 = 1;
let EXCLUDE_SAMESITE_LAX:                                 i64 = 2;
let EXCLUDE_SAMESITE_UNSPECIFIED_TREATED_AS_LAX:          i64 = 3;
let EXCLUDE_SAMESITE_NONE_INSECURE:                       i64 = 4;
let EXCLUDE_NONCOOKIEABLE_SCHEME:                         i64 = 5;
let EXCLUDE_SECURE_ONLY:                                  i64 = 6;
let EXCLUDE_HTTP_ONLY:                                    i64 = 7;
let EXCLUDE_DOMAIN_MISMATCH:                              i64 = 8;
let EXCLUDE_NOT_ON_PATH:                                  i64 = 9;
let EXCLUDE_FAILURE_TO_STORE:                             i64 = 10;
let WARN_SAMESITE_LAX_ALLOWING_UNSAFE:                    i64 = 11;
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
    context_type:       SameSiteContextType = SameSiteContextType.CrossSite,
    schemefully_same:   bool                = true,
    is_reload:          bool                = false,
    had_cross_site_hop: bool                = false,
}

fn can_set_canonical_cookie_for_context(
    cookie_val: const CanonicalCookie&,
    context:    const SameSiteCookieContext&,
    opts:       CookieInclusionOptions = CookieInclusionOptions { .. },
) -> bool, i64 {
    // Cross-site contexts cannot set SameSite cookies (RFC 6265bis Section 5.5 Step 19)
    if context.context_type == SameSiteContextType.CrossSite {
        match cookie_val.same_site {
            Strict => { return false, EXCLUDE_SAMESITE_STRICT; },
            Lax => { return false, EXCLUDE_SAMESITE_LAX; },
            Default => { return false, EXCLUDE_SAMESITE_UNSPECIFIED_TREATED_AS_LAX; },
            None => {
                if !opts.is_secure_channel { return false, EXCLUDE_SAMESITE_NONE_INSECURE; }
            },
            Unknown => { return false, EXCLUDE_UNKNOWN; },
        };
    }
    if cookie_val.same_site == CookieSameSite.None && !opts.is_secure_channel {
        return false, EXCLUDE_SAMESITE_NONE_INSECURE;
    }
    return true, EXCLUDE_UNKNOWN;
}
