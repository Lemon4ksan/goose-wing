// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// HTTP redirect state machine and header sanitization (RFC 9110 Section 15.4, WHATWG Fetch Section 4.5).
// Handles method rewriting, referrer policy calculation, and sensitive header stripping.
namespace client;

import std;
import core;
import cookie.constants;
import cookie.policy;
import http.headers;
import http.request;
import .internal;

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

// Parses a Referrer-Policy header value, supporting comma-separated tokens (RFC 9110 Section 15.4).
// Preserves `fallback` when the header contains only unrecognized or empty tokens.
//
// Example:
//   val = "no-referrer-when-downgrade, strict-origin-when-cross-origin", fallback = ReferrerPolicy.NoReferrer
//   returns: ReferrerPolicy.StrictOriginWhenCrossOrigin
fn parse_referrer_policy_with_fallback(val: const u8[:], fallback: ReferrerPolicy) -> ReferrerPolicy {
    var chosen = fallback;
    each_split(val, ',') { raw_token =>
        let t = raw_token.trim_lws();
        if t.eq_ascii_fold("no-referrer") {
            chosen = ReferrerPolicy.NoReferrer;
        } else if t.eq_ascii_fold("no-referrer-when-downgrade") {
            chosen = ReferrerPolicy.NoReferrerWhenDowngrade;
        } else if t.eq_ascii_fold("origin") {
            chosen = ReferrerPolicy.Origin;
        } else if t.eq_ascii_fold("origin-when-cross-origin") {
            chosen = ReferrerPolicy.OriginWhenCrossOrigin;
        } else if t.eq_ascii_fold("same-origin") {
            chosen = ReferrerPolicy.SameOrigin;
        } else if t.eq_ascii_fold("strict-origin") {
            chosen = ReferrerPolicy.StrictOrigin;
        } else if t.eq_ascii_fold("strict-origin-when-cross-origin") {
            chosen = ReferrerPolicy.StrictOriginWhenCrossOrigin;
        } else if t.eq_ascii_fold("unsafe-url") {
            chosen = ReferrerPolicy.UnsafeUrl;
        }
    };
    return chosen;
}

// ---- redirect info structure -----------------------------------------------

struct RedirectOptions {
    cors_mode:          bool = false,
    is_main_frame:      bool = false,
    has_initiator:      bool = false,
    tainted_origin:     bool = false,
    had_cross_site_hop: bool = false,
}

struct RedirectSanitizeOptions {
    cors_mode:                   bool = false,
    tainted_origin:              bool = false,
    enable_referer:              bool = false,
    trusted_location_forwarding: bool = false,
}

struct RedirectInfo {
    status_code:                  i32                  = 0,
    new_method:                   u8[..16]             = [],
    new_url:                      core::Url            = core::Url { .. },
    new_site_for_cookies:         http::SiteForCookies = http::SiteForCookies { .. },
    new_referrer:                 u8[..2048]           = [],
    new_referrer_policy:          ReferrerPolicy       = ReferrerPolicy.StrictOriginWhenCrossOrigin,
    insecure_scheme_was_upgraded: bool                 = false,
    is_cross_origin:              bool                 = false,
    is_scheme_downgrade:          bool                 = false,
    is_port_changed:              bool                 = false,
    is_cross_site_tainted:        bool                 = false,
    clear_body:                   bool                 = false,
    error:                        RedirectError        = RedirectError.None,
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
    let sfc = cookie::site_for_cookies_from_url(current_url_str);
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
        cookie::FirstPartyURLPolicy.NEVER_CHANGE_FIRST_PARTY_URL,
        dummy_chain[..],
        dummy_orig,
        options,
        "",
    );
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
    current_site_for_cookies:          const http::SiteForCookies&,
    first_party_policy:                cookie::FirstPartyURLPolicy,
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

    let parsed_target, val_err = client_internal::validate_redirect_target(location_header, current_url, options);
    guard val_err == RedirectError.None else {
        info.error = val_err;
        return info;
    }

    info.new_url = parsed_target;
    let loc_trimmed = location_header.trim_ascii_space();
    client_internal::inherit_target_fragment(info.new_url, current_url, loc_trimmed, preserve_fragment_on_redirect_url);
    let body_act = client_internal::mutate_redirect_method(status_code, current_method, info.new_method);
    info.clear_body = body_act == client_internal::RedirectBodyAction.Clear;

    let rel = client_internal::classify_redirect_origin_relation(current_url, info.new_url);
    info.is_scheme_downgrade = rel.is_downgrade;
    info.is_cross_origin = rel.is_cross_origin;
    info.is_port_changed = rel.is_port_changed;

    if response_referrer_policy_header.len > 0 {
        info.new_referrer_policy = parse_referrer_policy_with_fallback(
            response_referrer_policy_header,
            current_referrer_policy,
        );
    }

    var ref_source = current_url;
    var ref_is_cross_origin = info.is_cross_origin;
    var ref_is_downgrade = info.is_scheme_downgrade;
    if current_referrer.len > 0 {
        let parsed_ref = core::new_url(current_referrer);
        if parsed_ref.valid {
            ref_source = parsed_ref;
            let ref_rel = client_internal::classify_redirect_origin_relation(parsed_ref, info.new_url);
            ref_is_downgrade = ref_rel.is_downgrade;
            ref_is_cross_origin = ref_rel.is_cross_origin;
        }
    }

    client_internal::compute_new_referrer(
        ref_source,
        info.new_url,
        info.new_referrer_policy,
        client_internal::RedirectReferrerOptions {
            is_cross_origin: ref_is_cross_origin,
            is_downgrade:    ref_is_downgrade,
        },
        info.new_referrer,
    );

    let sfc, tainted = client_internal::compute_redirect_site_for_cookies(
        current_url,
        info.new_url,
        first_party_policy,
        current_site_for_cookies,
        url_chain,
        initiator,
        client_internal::RedirectSiteOptions {
            has_initiator:      options.has_initiator,
            had_cross_site_hop: options.had_cross_site_hop,
        },
    );
    info.new_site_for_cookies = sfc;
    info.is_cross_site_tainted = tainted;

    return info;
}

// ---- header sanitization on redirect ---------------------------------------

// Sanitizes outbound headers across redirect hops (RFC 9110 Section 15.4, WHATWG Fetch Section 4.4).
// Strips Cookie headers, removes credentials on cross-origin or downgrade hops, and drops payload headers.
//
// Example:
//   headers = [Cookie: "id=1", Host: "a.com"], redirect_info.is_cross_origin = true
//   headers becomes: [] (Cookie and Host stripped)
fn sanitize_headers_on_redirect(
    headers:       http::HeaderMap&,
    redirect_info: const RedirectInfo&,
    options:       RedirectSanitizeOptions = RedirectSanitizeOptions { .. },
) {
    // Cookie header is stripped and re-evaluated from the cookie jar for the new URL.
    http::remove_header_by_name(headers, "Cookie");

    // Go #82350: Strip stale Host header on cross-origin redirects.
    if redirect_info.is_cross_origin {
        http::remove_header_by_name(headers, "Host");
    }

    // Strip sensitive headers on cross-origin redirects or scheme downgrades.
    let strip_auth = redirect_info.is_scheme_downgrade ||
        (redirect_info.is_cross_origin && (!options.trusted_location_forwarding || redirect_info.is_port_changed));
    if strip_auth {
        http::remove_sensitive_headers(headers);
        http::remove_header_by_name(headers, "DPoP");
        http::remove_header_by_name(headers, "Signature");
        http::remove_header_by_name(headers, "Signature-Input");
    }
    if redirect_info.is_scheme_downgrade {
        client_internal::remove_sec_headers_on_downgrade(headers, redirect_info.new_url);
    }

    // Strip payload and representation headers when mutating to GET.
    if redirect_info.clear_body {
        client_internal::remove_payload_and_conditional_headers(headers);
    }

    // Origin header sanitization (WHATWG Fetch).
    client_internal::sanitize_origin_header_on_redirect(
        headers,
        client_internal::RedirectOriginOptions {
            is_cross_origin: redirect_info.is_cross_origin,
            tainted_origin:  options.tainted_origin,
            cors_mode:       options.cors_mode,
            clear_body:      redirect_info.clear_body,
        },
    );

    // Referer Header Application.
    http::remove_header_by_name(headers, "Referer");
    if options.enable_referer && redirect_info.new_referrer.len > 0 {
        http::set_header(headers, "Referer", redirect_info.new_referrer[..]);
    }
}

// ---- redirect hop cache taint & custom header strip policy -----------------

struct RedirectHopCacheTaint {
    saw_no_store: bool = false,
    saw_private:  bool = false,
}

// Aggregates `no-store` and `private` Cache-Control directives across intermediate redirect hops
// so outer caches do not store a final 200 response under an uncacheable initial redirect key.
fn record_redirect_hop_cache_headers(taint: RedirectHopCacheTaint&, hop_headers: const http::HeaderMap&) {
    for &entry in hop_headers.entries {
        guard http::entry_name(hop_headers, entry).eq_ascii_fold("cache-control") else { continue; }
        let cc = http::entry_value(hop_headers, entry);
        guard cc.len > 0 else { continue; }
        each_split(cc, ',') { raw_dir =>
            let d_name, _, _ = raw_dir.trim_lws().split_once_byte('=');
            let token = d_name.trim_lws();
            if token.eq_ascii_fold("no-store") {
                taint.saw_no_store = true;
            } else if token.eq_ascii_fold("private") {
                taint.saw_private = true;
            }
        };
    }
}

struct CustomRedirectStripPolicy {
    always_strip:       u8[..64][..8] = [],
    cross_origin_strip: u8[..64][..8] = [],
}

// Strips caller-configured unconditional and cross-origin header names across a redirect hop.
fn apply_custom_redirect_strip(
    headers:         http::HeaderMap&,
    is_cross_origin: bool,
    policy:          const CustomRedirectStripPolicy&,
) {
    for &name in policy.always_strip {
        http::remove_header_by_name(headers, name[..]);
    }
    if is_cross_origin {
        for &name in policy.cross_origin_strip {
            http::remove_header_by_name(headers, name[..]);
        }
    }
}
