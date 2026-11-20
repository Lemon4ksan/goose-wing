// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Cookie security and isolation policy: SameSite, prefixes, and Origin-Bound Cookies
// (RFC 6265bis, CHIPS).
namespace cookie;

import std;
import core from "..";
import .limits;
import .constants;
import .canonical;
import .psl;
import .parser;
import http.request;

// ---- http method & origin trust --------------------------------------------

// Whether host is a local loopback origin (localhost, 127.0.0.1, ::1, [::1]).
fn is_trustworthy_non_crypto_host(host: const u8[:]) -> bool {
    let clean_host = host.trim_byte('.').trim_byte('[').trim_byte(']');
    return clean_host.eq_ascii_fold("localhost") || clean_host == "127.0.0.1" || clean_host == "::1";
}

// ---- origin-bound adjustment -----------------------------------------------

// Rewrites source_port and source_scheme for local loopback origins (Chromium OBC).
fn cookie_internal::adjust_origin_bound_cookies_on_insert(
    cookie_ref:        cookie::CanonicalCookie&,
    host:              const u8[:],
    port:              i32,
    is_secure_channel: bool,
) {
    if is_secure_channel {
        cookie_ref.source_scheme = cookie::SourceScheme.Secure;
        cookie_ref.source_port = if port > 0 { port } else { 443 };
        return;
    }

    if cookie::is_trustworthy_non_crypto_host(host) && cookie_ref.secure && (port == 80 || port <= 0) {
        cookie_ref.source_scheme = cookie::SourceScheme.Secure;
        cookie_ref.source_port = 443; // Automatic port rewrite
    } else {
        cookie_ref.source_scheme = cookie::SourceScheme.NonSecure;
        cookie_ref.source_port = if port > 0 { port } else { 80 };
    }
}

// ---- script api & prefix security validation -------------------------------

// Validates cookie names accessed from non-HTTP script APIs to prevent
// shadowing protected prefixes.
fn cookie_internal::validate_script_cookie_name(name: const u8[:]) -> bool {
    if name.starts_with_fold("__http-") || name.starts_with_fold("__host-http-") {
        return false;
    }
    return true;
}

// Validates cookie security invariants for prefixes (__Secure-, __Host-,
// __Http-, __Host-Http-), Partitioned attributes, and SameSite=None (RFC 6265bis Section 5.6).
fn validate_security(
    cookie_val: const CanonicalCookie&,
    opts:       SourceOptions = SourceOptions { .. },
) -> bool {
    let cookie_name = cookie_val.name[..];
    if core::add_sat_i64(cookie_name.len, cookie_val.value.len) > cookie_internal::K_MAX_COOKIE_NAME_VAL_LEN {
        return false;
    }

    // Reject control characters and invalid RFC 6265 name/value/domain syntax
    if cookie_internal::has_prohibited_ctl(cookie_name) ||
       cookie_internal::has_prohibited_ctl(cookie_val.value[..]) ||
       cookie_internal::has_prohibited_ctl(cookie_val.domain[..]) ||
       cookie_internal::has_prohibited_ctl(cookie_val.path[..]) {
        return false;
    }
    if !cookie_internal::is_valid_cookie_name(cookie_name) ||
       !cookie_internal::is_valid_cookie_val(cookie_val.value[..]) ||
       (cookie_name.len == 0 && cookie_val.value[..].contains_byte('=')) {
        return false;
    }
    if cookie_val.domain.len > 0 && !cookie_internal::is_valid_domain_attr(cookie_val.domain[..]) {
        return false;
    }

    if !cookie_val.host_only && is_public_suffix_domain(cookie_val.domain[..]) {
        return false;
    }

    if !opts.is_http_api {
        if cookie_val.httponly { return false; } // Script cannot set HttpOnly
        if !cookie_internal::validate_script_cookie_name(cookie_name) { return false; }
    }

    let is_trustworthy = opts.url_is_secure || is_trustworthy_non_crypto_host(cookie_val.domain[..]);
    if cookie_val.secure && !is_trustworthy { return false; }

    // RFC 6265bis SameSite=None and CHIPS Partitioned both require Secure
    if cookie_val.same_site == SameSite.None && !cookie_val.secure { return false; }
    if cookie_val.partitioned {
        if !cookie_val.secure { return false; }
        if cookie_val.partition_key.len == 0
            || cookie_internal::has_prohibited_ctl(cookie_val.partition_key[..]) {
            return false;
        }
    }

    return cookie_internal::validate_security_prefixes(cookie_val, cookie_name, opts);
}

// ---- schemeful same-site engine --------------------------------------------

// Extracts a non-public-suffix site domain (registrable domain, IP literal, or local host) into `out`.
// Rejects empty/invalid hosts and bare known public suffixes (RFC 6265bis Section 5.2.1).
//
// Example:
//   host = "app.example.co.uk", out = []
//   returns: true, out = "example.co.uk"
fn cookie_internal::extract_site_domain<B>(host: const u8[:], out: B&) -> bool {
    let db = cookie::PslDatabase { use_dafsa: true, .. };
    guard !db.is_known_public_suffix(host) else { return false; }
    var tmp: u8[..256] = [];
    db.extract_etld_plus_one(host, tmp);
    guard tmp.len > 0 else { return false; }
    return out.try_set(tmp[..]);
}

// Schemeful Same-Site: compares two origins by (scheme, eTLD+1).
// Transition between http://example.com and https://example.com is cross-site!
fn is_schemeful_same_site(scheme1: const u8[:], host1: const u8[:], scheme2: const u8[:], host2: const u8[:]) -> bool {
    guard scheme1.len > 0 && scheme1.eq_ascii_fold(scheme2) else { return false; }

    var etld1: u8[..256] = [];
    var etld2: u8[..256] = [];
    guard cookie_internal::extract_site_domain(host1, etld1) else { return false; }
    guard cookie_internal::extract_site_domain(host2, etld2) else { return false; }

    return etld1[..].eq_ascii_fold(etld2[..]);
}

// ---- request sendability evaluation ----------------------------------------

// Whether a cookie is sendable in the given request context (RFC 6265bis).
fn is_sendable_for_samesite(
    cookie_val: const CanonicalCookie&,
    access:     AccessOptions,
    now_us:     i64,
) -> bool {
    if access.is_same_site {
        return true;
    }

    // Cross-site subresources (fetch, img, iframe) block all SameSite cookies except None
    if !access.is_top_level_navigation {
        return cookie_val.same_site == SameSite.None;
    }

    // Top-level cross-site navigation
    return match cookie_val.same_site {
        Strict => false,
        Lax => access.is_safe_method,
        None => true,
        _ => {
            if access.is_safe_method {
                true
            } else {
                !access.had_cross_site_hop && cookie_internal::is_in_lax_allowing_unsafe_window(cookie_val, now_us)
            }
        },
    };
}

// Evaluates sendability under Origin-Bound Cookies (OBC) port isolation.
fn cookie_internal::is_sendable_for_obc(
    cookie_val: const cookie::CanonicalCookie&,
    req_scheme: const u8[:],
    req_port:   i32,
    host:       const u8[:] = "",
) -> bool {
    let is_trustworthy = host.len > 0 && cookie::is_trustworthy_non_crypto_host(host);

    // Scheme check: Secure cookies require secure request scheme (or trustworthy non-crypto origin)
    if cookie_val.source_scheme == cookie::SourceScheme.Secure
        && !req_scheme.eq_ascii_fold("https") && !is_trustworthy {
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

fn cookie_internal::validate_security_prefixes(
    cookie_val:  const cookie::CanonicalCookie&,
    cookie_name: const u8[:],
    opts:        cookie::SourceOptions,
) -> bool {
    guard cookie_internal::has_valid_prefix_attributes(cookie_val, cookie_name) else {
        return false;
    }
    if cookie_name.starts_with_fold("__host-http-") || cookie_name.starts_with_fold("__http-") {
        return opts.is_http_api && opts.url_is_secure;
    }
    if cookie_name.starts_with_fold("__host-") || cookie_name.starts_with_fold("__secure-") {
        return opts.url_is_secure;
    }
    return true;
}

// ---- site for cookies and navigation context -------------------------------

fn site_for_cookies_from_url(url: const u8[:]) -> wing::SiteForCookies {
    let parsed = parse_canonical_cookie_url(url);
    var site = wing::SiteForCookies { schemefully_same: true, is_null: false, .. };
    guard parsed.scheme.len > 0 && site.scheme.try_set(parsed.scheme[..]) else {
        return null_site_for_cookies();
    }
    guard cookie_internal::extract_site_domain(parsed.host[..], site.registrable_domain) else {
        return null_site_for_cookies();
    }
    return site;
}

fn site_for_cookies_from_parsed_url(url_val: const core::Url&) -> wing::SiteForCookies {
    var site = wing::SiteForCookies { schemefully_same: true, is_null: false, .. };
    let scheme_slice = url_val.scheme();
    guard scheme_slice.len > 0 && site.scheme.try_set(scheme_slice) else {
        return null_site_for_cookies();
    }
    guard cookie_internal::extract_site_domain(url_val.hostname(), site.registrable_domain) else {
        return null_site_for_cookies();
    }
    return site;
}

fn null_site_for_cookies() -> wing::SiteForCookies {
    return wing::SiteForCookies { is_null: true, schemefully_same: false };
}

fn format_site_for_cookies<B>(site: const wing::SiteForCookies&, out: B&) {
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

fn compare_with_frame_tree_site_and_revise(site: wing::SiteForCookies&, frame_url: const u8[:]) {
    guard !site.is_null else { return; }
    let frame_site = site_for_cookies_from_url(frame_url);

    if frame_site.is_null || !site.registrable_domain[..].eq_ascii_fold(frame_site.registrable_domain[..]) {
        site.is_null = true;
        site.schemefully_same = false;
        site.scheme.clear();
        site.registrable_domain.clear();
        return;
    }

    if !site.scheme[..].eq_ascii_fold(frame_site.scheme[..]) {
        site.schemefully_same = false;
    }
}

// Computes SiteForCookies evaluating the full ancestor chain (RFC 6265bis Section 5.2.1 / CTX-01, CTX-02)
fn compute_site_for_cookies_with_ancestors(
    top_url:       const u8[:],
    ancestor_urls: const u8[:][:],
    is_sandboxed:  bool = false,
) -> wing::SiteForCookies {
    if is_sandboxed ||
       top_url.starts_with_fold("data:") ||
       top_url.starts_with_fold("about:") ||
       top_url.starts_with_fold("javascript:") ||
       top_url.starts_with_fold("blob:") {
        return null_site_for_cookies();
    }

    var top_site = site_for_cookies_from_url(top_url);
    guard !top_site.is_null else { return null_site_for_cookies(); }
    for a_url in ancestor_urls {
        compare_with_frame_tree_site_and_revise(top_site, a_url);
        if top_site.is_null {
            return null_site_for_cookies();
        }
    }
    return top_site;
}

fn is_first_party(site: const wing::SiteForCookies&, req_url: const u8[:], compute_schemefully: bool = true) -> bool {
    guard !site.is_null else { return false; }
    if compute_schemefully && !site.schemefully_same { return false; }

    let req_site = site_for_cookies_from_url(req_url);
    guard !req_site.is_null else { return false; }
    if !site.registrable_domain[..].eq_ascii_fold(req_site.registrable_domain[..]) {
        return false;
    }
    if compute_schemefully && !site.scheme[..].eq_ascii_fold(req_site.scheme[..]) {
        return false;
    }
    return true;
}

fn is_request_same_site(site: const wing::SiteForCookies&, req_url: const u8[:]) -> bool {
    return is_first_party(site, req_url, true);
}

// ---- Chromium net::CookieInclusionStatus codes -----------------------------

const cookie_internal::EXCLUDE_UNKNOWN: i64 = 0;
const cookie_internal::EXCLUDE_SAMESITE_STRICT: i64 = 1;
const cookie_internal::EXCLUDE_SAMESITE_LAX: i64 = 2;
const cookie_internal::EXCLUDE_SAMESITE_UNSPECIFIED_TREATED_AS_LAX: i64 = 3;
const cookie_internal::EXCLUDE_SAMESITE_NONE_INSECURE: i64 = 4;

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

fn can_set_for_context(
    cookie_val: const CanonicalCookie&,
    context:    const SameSiteCookieContext&,
    opts:       InclusionOptions = InclusionOptions { .. },
) -> i64, bool {
    if cookie_val.same_site == SameSite.None && !opts.is_secure_channel {
        return cookie_internal::EXCLUDE_SAMESITE_NONE_INSECURE, false;
    }
    // Cross-site contexts cannot set SameSite cookies (RFC 6265bis Section 5.5 Step 19).
    guard context.context_type == SameSiteContextType.CrossSite else {
        return cookie_internal::EXCLUDE_UNKNOWN, true;
    }
    if cookie_val.same_site == SameSite.Strict {
        return cookie_internal::EXCLUDE_SAMESITE_STRICT, false;
    }
    if cookie_val.same_site == SameSite.Lax {
        return cookie_internal::EXCLUDE_SAMESITE_LAX, false;
    }
    if cookie_val.same_site == SameSite.Default {
        return cookie_internal::EXCLUDE_SAMESITE_UNSPECIFIED_TREATED_AS_LAX, false;
    }
    if cookie_val.same_site == SameSite.Unknown {
        return cookie_internal::EXCLUDE_UNKNOWN, false;
    }
    return cookie_internal::EXCLUDE_UNKNOWN, true;
}
