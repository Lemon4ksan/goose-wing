// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// HTTP redirect state machine and header sanitization (RFC 9110 Section 15.4, WHATWG Fetch Section 4.5).
// Handles method rewriting, referrer policy calculation, and sensitive header stripping.
namespace wing;

import std;
import cookie.constants;
import cookie.policy;

// ---- redirect enumerations and policies ------------------------------------

enum RedirectMode {
    Follow,
    Manual,
    Error,
}

enum ReferrerPolicy {
    NoReferrer,
    NoReferrerWhenDowngrade,
    Origin,
    OriginWhenCrossOrigin,
    SameOrigin,
    StrictOrigin,
    StrictOriginWhenCrossOrigin,
    UnsafeUrl,
}

enum RedirectError {
    None,
    MissingLocation,
    MultipleLocationHeaders,
    InvalidLocationUrl,
    ForbiddenRedirectScheme,
    CorsCredentialsInRedirectUrl,
    SchemeDowngradeBlocked,
    TooManyRedirects,
    RedirectBlockedByPolicy,
    CannotRewindBody,
    SsrfBlockedUrl,
    SsrfBlockedIp,
}

fn redirect_error_to_string(err: RedirectError) -> const u8[:] {
    return match err {
        None => "None",
        MissingLocation => "ERR_MISSING_LOCATION",
        MultipleLocationHeaders => "ERR_MULTIPLE_LOCATION_HEADERS",
        InvalidLocationUrl => "ERR_INVALID_LOCATION_URL",
        ForbiddenRedirectScheme => "ERR_FORBIDDEN_REDIRECT_SCHEME",
        CorsCredentialsInRedirectUrl => "ERR_CORS_CREDENTIALS_IN_REDIRECT_URL",
        SchemeDowngradeBlocked => "ERR_SCHEME_DOWNGRADE_BLOCKED",
        TooManyRedirects => "ERR_TOO_MANY_REDIRECTS",
        RedirectBlockedByPolicy => "ERR_REDIRECT_BLOCKED_BY_POLICY",
        CannotRewindBody => "ERR_CANNOT_REWIND_BODY",
        SsrfBlockedUrl => "ERR_SSRF_BLOCKED_URL",
        SsrfBlockedIp => "ERR_SSRF_BLOCKED_IP",
    };
}

// Parses a Referrer-Policy header value, supporting comma-separated tokens (RFC 9110 Section 15.4).
//
// Example:
//   val = "no-referrer-when-downgrade, strict-origin-when-cross-origin"
//   returns: ReferrerPolicy.StrictOriginWhenCrossOrigin
fn parse_referrer_policy(val: const u8[:]) -> ReferrerPolicy {
    var chosen = ReferrerPolicy.StrictOriginWhenCrossOrigin;
    each_split(val, ',') { raw_token =>
        let t = trim(raw_token);
        if eq_ascii_fold(t, "no-referrer") {
            chosen = ReferrerPolicy.NoReferrer;
        } else if eq_ascii_fold(t, "no-referrer-when-downgrade") {
            chosen = ReferrerPolicy.NoReferrerWhenDowngrade;
        } else if eq_ascii_fold(t, "origin") {
            chosen = ReferrerPolicy.Origin;
        } else if eq_ascii_fold(t, "origin-when-cross-origin") {
            chosen = ReferrerPolicy.OriginWhenCrossOrigin;
        } else if eq_ascii_fold(t, "same-origin") {
            chosen = ReferrerPolicy.SameOrigin;
        } else if eq_ascii_fold(t, "strict-origin") {
            chosen = ReferrerPolicy.StrictOrigin;
        } else if eq_ascii_fold(t, "strict-origin-when-cross-origin") {
            chosen = ReferrerPolicy.StrictOriginWhenCrossOrigin;
        } else if eq_ascii_fold(t, "unsafe-url") {
            chosen = ReferrerPolicy.UnsafeUrl;
        }
    };
    return chosen;
}

fn referrer_policy_to_string(policy: ReferrerPolicy) -> const u8[:] {
    return match policy {
        NoReferrer => "no-referrer",
        NoReferrerWhenDowngrade => "no-referrer-when-downgrade",
        Origin => "origin",
        OriginWhenCrossOrigin => "origin-when-cross-origin",
        SameOrigin => "same-origin",
        StrictOrigin => "strict-origin",
        StrictOriginWhenCrossOrigin => "strict-origin-when-cross-origin",
        UnsafeUrl => "unsafe-url",
    };
}

// ---- redirect info structure -----------------------------------------------

struct RedirectOptions {
    cors_mode:          bool = false,
    is_main_frame:      bool = false,
    has_initiator:      bool = false,
    tainted_origin:     bool = false,
    had_cross_site_hop: bool = false,
}

struct RedirectSiteOptions {
    has_initiator:      bool = false,
    had_cross_site_hop: bool = false,
}

struct RedirectReferrerOptions {
    is_cross_origin: bool = false,
    is_downgrade:    bool = false,
}

struct RedirectOriginOptions {
    is_cross_origin: bool = false,
    tainted_origin:  bool = false,
    cors_mode:       bool = false,
    clear_body:      bool = false,
}

struct RedirectSanitizeOptions {
    cors_mode:                   bool = false,
    tainted_origin:              bool = false,
    enable_referer:              bool = false,
    trusted_location_forwarding: bool = false,
}

struct RedirectInfo {
    status_code:                  i32            = 0,
    new_method:                   u8[..16]       = [],
    new_url:                      core::Url      = core::Url { .. },
    new_site_for_cookies:         SiteForCookies = SiteForCookies { .. },
    new_referrer:                 u8[..2048]     = [],
    new_referrer_policy:          ReferrerPolicy = ReferrerPolicy.StrictOriginWhenCrossOrigin,
    insecure_scheme_was_upgraded: bool           = false,
    is_cross_origin:              bool           = false,
    is_scheme_downgrade:          bool           = false,
    is_port_changed:              bool           = false,
    is_cross_site_tainted:        bool           = false,
    clear_body:                   bool           = false,
    error:                        RedirectError  = RedirectError.None,
}

// ---- pure function compute_redirect_info -----------------------------------

// Computes redirect metadata for an HTTP redirect response (RFC 9110, WHATWG Fetch).
// Mutates method and body flags, sets cross-origin status, and calculates referrer.
fn compute_redirect_info(
    current_method:          const u8[:],
    status_code:             i32,
    current_url_str:         const u8[:],
    location_header:         const u8[:],
    current_referrer_policy: ReferrerPolicy,
    current_referrer:        const u8[:],
    options:                 RedirectOptions = RedirectOptions { .. },
) -> RedirectInfo {
    let cur_u = core::new_url(current_url_str);
    let sfc = site_for_cookies_from_url(current_url_str);
    var dummy_chain: core::Url[..1] = [];
    var dummy_orig = core::new_opaque_origin();
    return compute_redirect_info(
        status_code,
        current_method,
        cur_u,
        location_header,
        "",
        current_referrer_policy,
        current_referrer,
        sfc,
        FirstPartyURLPolicy.NEVER_CHANGE_FIRST_PARTY_URL,
        dummy_chain[..],
        dummy_orig,
        options,
        "",
    );
}

fn mutate_redirect_method<B>(
    status_code:    i32,
    current_method: const u8[:],
    out_method:     B&,
    clear_body:     bool&,
) {
    out_method.clear();
    clear_body = false;

    if !rfc::is_redirect_status(status_code) {
        out_method.append(current_method);
        return;
    }

    let should_rewrite = if status_code == rfc::STATUS_MOVED_PERMANENTLY || status_code == rfc::STATUS_FOUND {
        eq_ascii_fold(current_method, "POST")
    } else if status_code == rfc::STATUS_SEE_OTHER {
        !eq_ascii_fold(current_method, "GET") && !eq_ascii_fold(current_method, "HEAD")
    } else {
        false
    };

    if should_rewrite {
        out_method.append("GET");
        clear_body = true;
    } else {
        out_method.append(current_method);
    }
}

fn inherit_target_fragment(
    target_url:                        core::Url&,
    current_url:                       const core::Url&,
    clean_loc:                         const u8[:],
    preserve_fragment_on_redirect_url: const u8[:],
) {
    let target_hash = target_url.hash();
    let curr_hash = current_url.hash();
    if target_hash.len == 0 && curr_hash.len > 0 {
        if preserve_fragment_on_redirect_url.len == 0 || clean_loc != preserve_fragment_on_redirect_url {
            guard target_url.href.len + curr_hash.len <= target_url.href.cap else {
                return;
            }
            target_url.hash_start = target_url.href.len as i32;
            target_url.href.append(curr_hash);
            target_url.hash_end = target_url.href.len as i32;
        }
    }
}

fn compute_redirect_site_for_cookies(
    current_url:              const core::Url&,
    new_url:                  const core::Url&,
    first_party_policy:       FirstPartyURLPolicy,
    current_site_for_cookies: const SiteForCookies&,
    url_chain:                const core::Url[:],
    initiator:                const core::Origin&,
    options:                  RedirectSiteOptions,
) -> SiteForCookies, bool {
    let same_site_step = is_schemeful_same_site(
        current_url.scheme(), core::hostname(current_url),
        core::scheme(new_url), core::hostname(new_url),
    );
    let initiator_ok = !options.has_initiator || (
        initiator.kind != core::OriginKind.Opaque && is_schemeful_same_site(
            initiator.scheme[..], initiator.host[..],
            core::scheme(new_url), core::hostname(new_url),
        )
    );

    if first_party_policy == FirstPartyURLPolicy.NEVER_CHANGE_FIRST_PARTY_URL {
        // Subresources / background requests: once tainted, remains null forever
        let is_first_p = is_first_party(current_site_for_cookies, core::href(new_url), true);

        if options.had_cross_site_hop || !same_site_step || !is_first_p || !initiator_ok {
            return null_site_for_cookies(), true;
        }
        return copy(current_site_for_cookies), false;
    }

    // Main-frame top-level navigation: SiteForCookies updates to target
    let new_site = site_for_cookies_from_parsed_url(new_url);
    var chain_tainted = options.had_cross_site_hop || !same_site_step || !initiator_ok;
    for &hop_url in url_chain {
        if !is_schemeful_same_site(
            core::scheme(hop_url), core::hostname(hop_url),
            core::scheme(new_url), core::hostname(new_url),
        ) {
            chain_tainted = true;
        }
    }
    return new_site, chain_tainted;
}

fn validate_redirect_target(
    location_header: const u8[:],
    current_url:     const core::Url&,
    options:         RedirectOptions,
) -> core::Url, RedirectError {
    let clean_loc = trim(location_header);
    guard clean_loc.len > 0 else {
        return core::Url { .. }, RedirectError.MissingLocation;
    }

    let parsed_target, parse_err = core::parse_url_with_base(clean_loc, current_url);
    guard parsed_target.valid else {
        return core::Url { .. }, RedirectError.InvalidLocationUrl;
    }

    if !core::is_http_or_https(parsed_target) {
        return core::Url { .. }, RedirectError.ForbiddenRedirectScheme;
    }

    if options.cors_mode && core::has_credentials(parsed_target) {
        let same_orig = core::is_same_origin_url(current_url, parsed_target);
        if !same_orig || options.tainted_origin {
            return core::Url { .. }, RedirectError.CorsCredentialsInRedirectUrl;
        }
    }

    return parsed_target, RedirectError.None;
}

fn classify_redirect_origin_relation(
    current_url:         const core::Url&,
    target_url:          const core::Url&,
    out_is_downgrade:    bool&,
    out_is_cross_origin: bool&,
    out_is_port_changed: bool&,
) {
    let same_orig = core::is_same_origin_url(current_url, target_url);
    let is_downgrade = (current_url.scheme() == "https" && target_url.scheme() == "http");
    let port_changed = current_url.effective_port() != target_url.effective_port();
    out_is_downgrade = is_downgrade;
    out_is_cross_origin = !same_orig || is_downgrade;
    out_is_port_changed = port_changed;
}

// Computes redirect metadata for an HTTP redirect response (RFC 9110, WHATWG Fetch).
// Mutates method and body flags, sets cross-origin status, and calculates referrer.
fn compute_redirect_info(
    status_code:                       i32,
    current_method:                    const u8[:],
    current_url:                       const core::Url&,
    location_header:                   const u8[:],
    response_referrer_policy_header:   const u8[:],
    current_referrer_policy:           ReferrerPolicy,
    current_referrer:                  const u8[:],
    current_site_for_cookies:          const SiteForCookies&,
    first_party_policy:                FirstPartyURLPolicy,
    url_chain:                         const core::Url[:],
    initiator:                         const core::Origin&,
    options:                           RedirectOptions,
    preserve_fragment_on_redirect_url: const u8[:] = "",
) -> RedirectInfo {
    var info = RedirectInfo {
        status_code:         status_code,
        new_referrer_policy: current_referrer_policy,
        ..
    };

    let parsed_target, val_err = validate_redirect_target(location_header, current_url, options);
    guard val_err == RedirectError.None else {
        info.error = val_err;
        return info;
    }

    info.new_url = parsed_target;
    inherit_target_fragment(info.new_url, current_url, trim(location_header), preserve_fragment_on_redirect_url);
    mutate_redirect_method(status_code, current_method, info.new_method, info.clear_body);

    classify_redirect_origin_relation(
        current_url,
        info.new_url,
        info.is_scheme_downgrade,
        info.is_cross_origin,
        info.is_port_changed,
    );

    if response_referrer_policy_header.len > 0 {
        info.new_referrer_policy = parse_referrer_policy(response_referrer_policy_header);
    }

    compute_new_referrer(
        current_url,
        info.new_url,
        info.new_referrer_policy,
        RedirectReferrerOptions {
            is_cross_origin: info.is_cross_origin,
            is_downgrade:    info.is_scheme_downgrade,
        },
        info.new_referrer,
    );

    let sfc, tainted = compute_redirect_site_for_cookies(
        current_url,
        info.new_url,
        first_party_policy,
        current_site_for_cookies,
        url_chain,
        initiator,
        RedirectSiteOptions {
            has_initiator:      options.has_initiator,
            had_cross_site_hop: options.had_cross_site_hop,
        },
    );
    info.new_site_for_cookies = sfc;
    info.is_cross_site_tainted = tainted;

    return info;
}

// ---- referrer calculation helper -------------------------------------------

fn should_drop_referrer(policy: ReferrerPolicy, options: RedirectReferrerOptions) -> bool {
    if policy == ReferrerPolicy.NoReferrer {
        return true;
    }
    if options.is_downgrade {
        if policy == ReferrerPolicy.NoReferrerWhenDowngrade ||
            policy == ReferrerPolicy.StrictOrigin ||
            policy == ReferrerPolicy.StrictOriginWhenCrossOrigin {
            return true;
        }
    }
    if options.is_cross_origin && policy == ReferrerPolicy.SameOrigin {
        return true;
    }
    return false;
}

fn is_origin_only_referrer(policy: ReferrerPolicy, is_cross_origin: bool) -> bool {
    if policy == ReferrerPolicy.Origin || policy == ReferrerPolicy.StrictOrigin {
        return true;
    }
    if is_cross_origin {
        if policy == ReferrerPolicy.OriginWhenCrossOrigin ||
            policy == ReferrerPolicy.StrictOriginWhenCrossOrigin {
            return true;
        }
    }
    return false;
}

fn serialize_stripped_full_referrer<B>(source_url: const core::Url&, out: B&) {
    out.append(source_url.scheme());
    out.append("://");
    out.append(source_url.host());
    out.append(source_url.pathname());
    out.append(source_url.search());
}

fn compute_new_referrer<B>(
    source_url: const core::Url&,
    target_url: const core::Url&,
    policy:     ReferrerPolicy,
    options:    RedirectReferrerOptions,
    out:        B&,
) {
    out.clear();

    if should_drop_referrer(policy, options) {
        return;
    }

    if is_origin_only_referrer(policy, options.is_cross_origin) {
        core::serialize_origin(core::origin_from_url(source_url), out);
        return;
    }

    serialize_stripped_full_referrer(source_url, out);
}

// ---- header sanitization on redirect ---------------------------------------

// Strips payload and conditional validator headers in a single O(N) pass
// when a redirect mutates request to GET (RFC 9110 Section 15.4).
fn remove_payload_and_conditional_headers(headers: HeaderMap&) {
    var found = false;
    var write_entry_i: i64 = 0;
    var write_raw_pos: u16 = 0;
    let total_entries = headers.entries.len;

    for read_i in total_entries {
        let name = entry_name(headers, headers.entries[read_i]);
        if rfc::is_payload_or_conditional_header(name) {
            found = true;
            continue;
        }
        compact_kept_entry_in_place(headers, read_i, write_entry_i, write_raw_pos);
    }
    if found {
        finish_in_place_compaction(headers, write_entry_i, write_raw_pos);
    }
}

// Sanitizes or drops Origin header on cross-origin redirect hops (WHATWG Fetch Section 4.4).
//
// Example:
//   headers = [Origin: "https://a.com"], options = { is_cross_origin = true, clear_body = true }
//   headers becomes: [] (Origin header removed)
fn sanitize_origin_header_on_redirect(
    headers: HeaderMap&,
    options: RedirectOriginOptions,
) {
    if has_header(headers, "Origin") && (options.is_cross_origin || options.tainted_origin) {
        if options.clear_body && !options.cors_mode && !options.tainted_origin {
            remove_header_by_name(headers, "Origin");
        } else {
            set_header(headers, "Origin", "null");
        }
    }
}

// Sanitizes outbound headers across redirect hops (RFC 9110 Section 15.4, WHATWG Fetch Section 4.4).
// Strips Cookie headers, removes credentials on cross-origin or downgrade hops, and drops payload headers.
//
// Example:
//   headers = [Cookie: "id=1", Host: "a.com"], redirect_info.is_cross_origin = true
//   headers becomes: [] (Cookie and Host stripped)
fn sanitize_headers_on_redirect(
    headers:       HeaderMap&,
    redirect_info: const RedirectInfo&,
    options:       RedirectSanitizeOptions = RedirectSanitizeOptions { .. },
) {
    // Cookie header is stripped and re-evaluated from the cookie jar for the new URL.
    remove_header_by_name(headers, "Cookie");

    // Go #82350: Strip stale Host header on cross-origin redirects
    if redirect_info.is_cross_origin {
        remove_header_by_name(headers, "Host");
    }

    // Strip sensitive headers on cross-origin redirects or scheme downgrades.
    let strip_auth = redirect_info.is_scheme_downgrade ||
        (redirect_info.is_cross_origin && (!options.trusted_location_forwarding || redirect_info.is_port_changed));
    if strip_auth {
        remove_sensitive_headers(headers);
    }

    // Strip payload and representation headers when mutating to GET.
    if redirect_info.clear_body {
        remove_payload_and_conditional_headers(headers);
    }

    // Origin header sanitization (WHATWG Fetch)
    sanitize_origin_header_on_redirect(
        headers,
        RedirectOriginOptions {
            is_cross_origin: redirect_info.is_cross_origin,
            tainted_origin:  options.tainted_origin,
            cors_mode:       options.cors_mode,
            clear_body:      redirect_info.clear_body,
        },
    );

    // Referer Header Application
    remove_header_by_name(headers, "Referer");
    if options.enable_referer && redirect_info.new_referrer.len > 0 {
        set_header(headers, "Referer", redirect_info.new_referrer[..]);
    }
}
