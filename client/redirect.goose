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

fn parse_referrer_policy(val: const u8[:]) -> ReferrerPolicy {
    var chosen = ReferrerPolicy.StrictOriginWhenCrossOrigin;
    each_split(val, ',') { raw_token =>
        let t = trim(raw_token);
        if eq_ascii_fold(t, "no-referrer") { chosen = ReferrerPolicy.NoReferrer; }
        else if eq_ascii_fold(t, "no-referrer-when-downgrade") { chosen = ReferrerPolicy.NoReferrerWhenDowngrade; }
        else if eq_ascii_fold(t, "origin") { chosen = ReferrerPolicy.Origin; }
        else if eq_ascii_fold(t, "origin-when-cross-origin") { chosen = ReferrerPolicy.OriginWhenCrossOrigin; }
        else if eq_ascii_fold(t, "same-origin") { chosen = ReferrerPolicy.SameOrigin; }
        else if eq_ascii_fold(t, "strict-origin") { chosen = ReferrerPolicy.StrictOrigin; }
        else if eq_ascii_fold(t, "strict-origin-when-cross-origin") { chosen = ReferrerPolicy.StrictOriginWhenCrossOrigin; }
        else if eq_ascii_fold(t, "unsafe-url") { chosen = ReferrerPolicy.UnsafeUrl; }
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

struct RedirectInfo {
    status_code: i32 = 0,
    new_method: u8[..16] = [],
    new_url: core::Url = core::Url { .. },
    new_site_for_cookies: SiteForCookies = SiteForCookies { .. },
    new_referrer: u8[..2048] = [],
    new_referrer_policy: ReferrerPolicy = ReferrerPolicy.StrictOriginWhenCrossOrigin,
    insecure_scheme_was_upgraded: bool = false,
    is_cross_origin: bool = false,
    is_scheme_downgrade: bool = false,
    is_port_changed: bool = false,
    is_cross_site_tainted: bool = false,
    clear_body: bool = false,
    error: RedirectError = RedirectError.None,
}

// ---- pure function compute_redirect_info -----------------------------------

// Computes redirect metadata for an HTTP redirect response (RFC 9110, WHATWG Fetch).
// Mutates method and body flags, sets cross-origin status, and calculates referrer.
fn compute_redirect_info(
    current_method: const u8[:],
    status_code: i32,
    current_url_str: const u8[:],
    location_header: const u8[:],
    current_referrer_policy: ReferrerPolicy,
    current_referrer: const u8[:],
    cors_mode: bool,
    is_main_frame: bool
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
        false,
        cors_mode,
        false,
        is_main_frame,
        false,
        ""
    );
}

fn mutate_redirect_method<B>(
    status_code: i32,
    current_method: const u8[:],
    out_method: B&,
    clear_body: bool&
) {
    out_method.clear();
    clear_body = false;

    let should_rewrite = if status_code == 301 || status_code == 302 {
        eq_ascii_fold(current_method, "POST")
    } else if status_code == 303 {
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
    target_url: core::Url&,
    current_url: const core::Url&,
    clean_loc: const u8[:],
    preserve_fragment_on_redirect_url: const u8[:]
) {
    let target_hash = hash(target_url);
    let curr_hash = hash(current_url);
    if target_hash.len == 0 && curr_hash.len > 0 {
        if preserve_fragment_on_redirect_url.len == 0 || clean_loc != preserve_fragment_on_redirect_url {
            target_url.hash_start = target_url.href.len as i32;
            target_url.href.append(curr_hash);
            target_url.hash_end = target_url.href.len as i32;
        }
    }
}

fn compute_redirect_site_for_cookies(
    current_url: const core::Url&,
    new_url: const core::Url&,
    first_party_policy: FirstPartyURLPolicy,
    current_site_for_cookies: const SiteForCookies&,
    url_chain: const core::Url[:],
    initiator: const core::Origin&,
    has_initiator: bool,
    had_cross_site_hop: bool,
) -> SiteForCookies, bool {
    let same_site_step = core::is_schemeful_same_site_urls(current_url, new_url);

    if first_party_policy == FirstPartyURLPolicy.NEVER_CHANGE_FIRST_PARTY_URL {
        // Subresources / background requests: once tainted, remains null forever
        let is_first_p = is_first_party(current_site_for_cookies, href(new_url), true);
        let initiator_ok = !has_initiator || core::is_same_site_origin_url(initiator, new_url);

        if had_cross_site_hop || !same_site_step || !is_first_p || !initiator_ok {
            return null_site_for_cookies(), true;
        }
        return copy(current_site_for_cookies), false;
    }

    // Main-frame top-level navigation: SiteForCookies updates to target
    let new_site = site_for_cookies_from_parsed_url(new_url);
    var chain_tainted = had_cross_site_hop || !same_site_step;
    if has_initiator && !core::is_same_site_origin_url(initiator, new_url) {
        chain_tainted = true;
    }
    for &hop_url in url_chain {
        if !core::is_schemeful_same_site_urls(hop_url, new_url) {
            chain_tainted = true;
        }
    }
    return new_site, chain_tainted;
}

fn validate_redirect_target(
    location_header: const u8[:],
    current_url: const core::Url&,
    cors_mode: bool,
    tainted_origin: bool
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

    if cors_mode && core::has_credentials(parsed_target) {
        let same_orig = core::is_same_origin_url(current_url, parsed_target);
        if !same_orig || tainted_origin {
            return core::Url { .. }, RedirectError.CorsCredentialsInRedirectUrl;
        }
    }

    return parsed_target, RedirectError.None;
}

fn classify_redirect_origin_relation(
    current_url: const core::Url&,
    target_url: const core::Url&,
    out_is_downgrade: bool&,
    out_is_cross_origin: bool&,
    out_is_port_changed: bool&
) {
    let same_orig = core::is_same_origin_url(current_url, target_url);
    let is_downgrade = (scheme(current_url) == "https" && scheme(target_url) == "http");
    let port_changed = effective_port(current_url) != effective_port(target_url);
    out_is_downgrade = is_downgrade;
    out_is_cross_origin = !same_orig || is_downgrade;
    out_is_port_changed = port_changed;
}

// Computes redirect metadata for an HTTP redirect response (RFC 9110, WHATWG Fetch).
// Mutates method and body flags, sets cross-origin status, and calculates referrer.
fn compute_redirect_info(
    status_code: i32,
    current_method: const u8[:],
    current_url: const core::Url&,
    location_header: const u8[:],
    response_referrer_policy_header: const u8[:],
    current_referrer_policy: ReferrerPolicy,
    current_referrer: const u8[:],
    current_site_for_cookies: const SiteForCookies&,
    first_party_policy: FirstPartyURLPolicy,
    url_chain: const core::Url[:],
    initiator: const core::Origin&,
    has_initiator: bool,
    cors_mode: bool,
    tainted_origin: bool,
    is_main_frame: bool,
    had_cross_site_hop: bool,
    preserve_fragment_on_redirect_url: const u8[:] = "",
) -> RedirectInfo {
    var info = RedirectInfo {
        status_code: status_code,
        new_referrer_policy: current_referrer_policy,
        ..
    };

    let parsed_target, val_err = validate_redirect_target(location_header, current_url, cors_mode, tainted_origin);
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
        info.is_port_changed
    );

    if response_referrer_policy_header.len > 0 {
        info.new_referrer_policy = parse_referrer_policy(response_referrer_policy_header);
    }

    compute_new_referrer(
        current_url,
        info.new_url,
        info.new_referrer_policy,
        info.is_cross_origin,
        info.is_scheme_downgrade,
        info.new_referrer
    );

    let sfc, tainted = compute_redirect_site_for_cookies(
        current_url,
        info.new_url,
        first_party_policy,
        current_site_for_cookies,
        url_chain,
        initiator,
        has_initiator,
        had_cross_site_hop
    );
    info.new_site_for_cookies = sfc;
    info.is_cross_site_tainted = tainted;

    return info;
}

// ---- referrer calculation helper -------------------------------------------

fn should_drop_referrer(policy: ReferrerPolicy, is_cross_origin: bool, is_downgrade: bool) -> bool {
    if policy == ReferrerPolicy.NoReferrer {
        return true;
    }
    if is_downgrade && (policy == ReferrerPolicy.NoReferrerWhenDowngrade ||
                        policy == ReferrerPolicy.StrictOrigin ||
                        policy == ReferrerPolicy.StrictOriginWhenCrossOrigin) {
        return true;
    }
    if is_cross_origin && policy == ReferrerPolicy.SameOrigin {
        return true;
    }
    return false;
}

fn is_origin_only_referrer(policy: ReferrerPolicy, is_cross_origin: bool) -> bool {
    return policy == ReferrerPolicy.Origin ||
           policy == ReferrerPolicy.StrictOrigin ||
           (is_cross_origin && (policy == ReferrerPolicy.OriginWhenCrossOrigin ||
                                policy == ReferrerPolicy.StrictOriginWhenCrossOrigin));
}

fn serialize_stripped_full_referrer<B>(source_url: const core::Url&, out: B&) {
    out.append(scheme(source_url));
    out.append("://");
    out.append(host(source_url));
    out.append(pathname(source_url));
    out.append(search(source_url));
}

fn compute_new_referrer<B>(
    source_url: const core::Url&,
    target_url: const core::Url&,
    policy: ReferrerPolicy,
    is_cross_origin: bool,
    is_downgrade: bool,
    out: B&
) {
    out.clear();

    if should_drop_referrer(policy, is_cross_origin, is_downgrade) {
        return;
    }

    if is_origin_only_referrer(policy, is_cross_origin) {
        core::serialize_origin(core::origin_from_url(source_url), out);
        return;
    }

    serialize_stripped_full_referrer(source_url, out);
}

// ---- header sanitization on redirect ---------------------------------------

fn is_payload_or_conditional_header(hname: const u8[:]) -> bool {
    return eq_ascii_fold(hname, "content-type") ||
           eq_ascii_fold(hname, "content-length") ||
           eq_ascii_fold(hname, "content-encoding") ||
           eq_ascii_fold(hname, "content-language") ||
           eq_ascii_fold(hname, "content-location") ||
           eq_ascii_fold(hname, "transfer-encoding") ||
           eq_ascii_fold(hname, "digest") ||
           eq_ascii_fold(hname, "if-match") ||
           eq_ascii_fold(hname, "if-none-match") ||
           eq_ascii_fold(hname, "if-modified-since") ||
           eq_ascii_fold(hname, "if-unmodified-since") ||
           eq_ascii_fold(hname, "if-range") ||
           eq_ascii_fold(hname, "expect") ||
           eq_ascii_fold(hname, "te");
}

// Strips payload and conditional validator headers in a single O(N) pass when a redirect mutates request to GET (RFC 9110 Section 15.4).
fn remove_payload_and_conditional_headers(headers: HeaderItem[..32]&) {
    var write_idx = 0;
    for read_idx in headers.len {
        if !is_payload_or_conditional_header(headers[read_idx].name[..]) {
            if write_idx != read_idx {
                headers[write_idx] = copy(headers[read_idx]);
            }
            write_idx++;
        }
    }
    while headers.len > write_idx {
        headers.pop();
    }
}

// Sanitizes or drops Origin header on cross-origin redirect hops (WHATWG Fetch Section 4.4).
fn sanitize_origin_header_on_redirect(
    headers: HeaderItem[..32]&,
    is_cross_origin: bool,
    tainted_origin: bool,
    cors_mode: bool,
    clear_body: bool,
) {
    let origin_idx = find_header_index(headers[..], "Origin");
    if origin_idx >= 0 && (is_cross_origin || tainted_origin) {
        if cors_mode || tainted_origin {
            headers[origin_idx].value.clear();
            headers[origin_idx].value.append("null");
        } else if clear_body {
            remove_header_by_name(headers, "Origin");
        }
    }
}

// Sanitizes outbound headers across redirect hops. Strips Cookie headers, removes
// credentials on cross-origin or scheme downgrades, and drops payload headers
// when mutating to GET.
fn sanitize_headers_on_redirect(
    headers: HeaderItem[..32]&,
    redirect_info: const RedirectInfo&,
    cors_mode: bool,
    tainted_origin: bool,
    enable_referer: bool,
    trusted_location_forwarding: bool = false
) {
    // Cookie header is stripped and re-evaluated from the cookie jar for the new URL.
    remove_header_by_name(headers, "Cookie");

    // Strip sensitive headers on cross-origin redirects or scheme downgrades.
    if redirect_info.is_scheme_downgrade || (redirect_info.is_cross_origin && (!trusted_location_forwarding || redirect_info.is_port_changed)) {
        remove_sensitive_headers(headers);
    }

    // Strip payload and representation headers when mutating to GET.
    if redirect_info.clear_body {
        remove_payload_and_conditional_headers(headers);
    }

    // Origin header sanitization (WHATWG Fetch)
    sanitize_origin_header_on_redirect(
        headers,
        redirect_info.is_cross_origin,
        tainted_origin,
        cors_mode,
        redirect_info.clear_body
    );

    // Referer Header Application
    remove_header_by_name(headers, "Referer");
    if enable_referer && redirect_info.new_referrer.len > 0 {
        if headers.len < headers.cap {
            headers.push(make_header("Referer", redirect_info.new_referrer[..]));
        }
    }
}
