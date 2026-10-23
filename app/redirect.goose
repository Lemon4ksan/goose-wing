// Deterministic HTTP Redirect State Machine (ComputeRedirectInfo & RedirectUtil).
// RFC 9110, W3C Referrer Policy, RFC 6265bis #1331/#1348, and Chromium net::RedirectInfo.
//
// Core Types:
//   RedirectMode    - Redirection handling strategy (Follow, Manual, Error).
//   ReferrerPolicy  - W3C Referrer-Policy specification enum.
//   RedirectError   - Lexical, scheme, SSRF, or credential diagnostic error enum.
//   RedirectInfo    - Output record tracking mutated method, target URL, referrers, and security status.
//
// Standards & Specifications:
//   RFC 9110 HTTP Redirection Status Codes (301, 302, 303 method mutation; 307, 308 method preservation).
//   W3C Referrer Policy Specification (compute_new_referrer).
//   CVE-2023-45143, CVE-2024-1968, CVE-2026-55553 Sensitive header stripping on cross-origin / downgrade hops.
//   RFC 6265bis #1348 Monotonic cross-site redirect chain tainting.
namespace wing;

import std;
import core.url;
import cookie.constants;
import cookie.policy;
import app.profile;

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
    new_url: Url = Url { .. },
    new_site_for_cookies: SiteForCookies = SiteForCookies { .. },
    new_referrer: u8[..2048] = [],
    new_referrer_policy: ReferrerPolicy = ReferrerPolicy.StrictOriginWhenCrossOrigin,
    insecure_scheme_was_upgraded: bool = false,
    is_cross_origin: bool = false,
    is_scheme_downgrade: bool = false,
    is_cross_site_tainted: bool = false,
    clear_body: bool = false,
    error: RedirectError = RedirectError.None,
}

// ---- pure function compute_redirect_info -----------------------------------

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
    let cur_u = new_url(current_url_str);
    let sfc = site_for_cookies_from_url(current_url_str);
    var dummy_chain: Url[..1] = [];
    var dummy_orig = new_opaque_origin();
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
    if status_code == 301 || status_code == 302 {
        if eq_ascii_fold(current_method, "POST") {
            out_method.append("GET");
            clear_body = true;
        } else {
            out_method.append(current_method);
            clear_body = false;
        }
    } else if status_code == 303 {
        if !eq_ascii_fold(current_method, "GET") && !eq_ascii_fold(current_method, "HEAD") {
            out_method.append("GET");
            clear_body = true;
        } else {
            out_method.append(current_method);
            clear_body = false;
        }
    } else { // 307 Temporary Redirect and 308 Permanent Redirect preserve method and body
        out_method.append(current_method);
        clear_body = false;
    }
}

fn inherit_target_fragment(
    target_url: Url&,
    current_url: const Url&,
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
    current_url: const Url&,
    new_url: const Url&,
    first_party_policy: FirstPartyURLPolicy,
    current_site_for_cookies: const SiteForCookies&,
    url_chain: const Url[:],
    initiator: const Origin&,
    has_initiator: bool,
    had_cross_site_hop: bool,
) -> SiteForCookies, bool {
    let same_site_step = is_schemeful_same_site_urls(current_url, new_url);

    if first_party_policy == FirstPartyURLPolicy.NEVER_CHANGE_FIRST_PARTY_URL {
        // Subresources / background requests: once tainted, remains null forever
        let is_first_p = is_first_party(current_site_for_cookies, href(new_url), true);
        let initiator_ok = !has_initiator || is_same_site_origin_url(initiator, new_url);

        if had_cross_site_hop || !same_site_step || !is_first_p || !initiator_ok {
            return null_site_for_cookies(), true;
        }
        return copy(current_site_for_cookies), false;
    }

    // Main-frame top-level navigation: SiteForCookies updates to target
    let new_site = site_for_cookies_from_parsed_url(new_url);
    var chain_tainted = had_cross_site_hop || !same_site_step;
    if has_initiator && !is_same_site_origin_url(initiator, new_url) {
        chain_tainted = true;
    }
    for &hop_url in url_chain {
        if !is_schemeful_same_site_urls(hop_url, new_url) {
            chain_tainted = true;
        }
    }
    return new_site, chain_tainted;
}

fn validate_redirect_target(
    location_header: const u8[:],
    current_url: const Url&,
    cors_mode: bool,
    tainted_origin: bool
) -> Url, RedirectError {
    let clean_loc = trim(location_header);
    guard clean_loc.len > 0 else {
        return Url { .. }, RedirectError.MissingLocation;
    }

    let parsed_target, parse_err = parse_url_with_base(clean_loc, current_url);
    guard parsed_target.valid else {
        return Url { .. }, RedirectError.InvalidLocationUrl;
    }

    if !is_http_or_https(parsed_target) {
        return Url { .. }, RedirectError.ForbiddenRedirectScheme;
    }

    if cors_mode && has_credentials(parsed_target) {
        let same_orig = is_same_origin_url(current_url, parsed_target);
        if !same_orig || tainted_origin {
            return Url { .. }, RedirectError.CorsCredentialsInRedirectUrl;
        }
    }

    return parsed_target, RedirectError.None;
}

fn compute_redirect_info(
    status_code: i32,
    current_method: const u8[:],
    current_url: const Url&,
    location_header: const u8[:],
    response_referrer_policy_header: const u8[:],
    current_referrer_policy: ReferrerPolicy,
    current_referrer: const u8[:],
    current_site_for_cookies: const SiteForCookies&,
    first_party_policy: FirstPartyURLPolicy,
    url_chain: const Url[:],
    initiator: const Origin&,
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

    // 1 & 2. Location & CORS Validation
    let parsed_target, val_err = validate_redirect_target(location_header, current_url, cors_mode, tainted_origin);
    guard val_err == RedirectError.None else {
        info.error = val_err;
        return info;
    }

    // 3. Fragment Inheritance (WHATWG Fetch / Chromium NetworkDelegate)
    info.new_url = parsed_target;
    inherit_target_fragment(info.new_url, current_url, trim(location_header), preserve_fragment_on_redirect_url);

    // 4. HTTP Method Mutation & Body Clearing (RFC 9110 / WHATWG Fetch)
    mutate_redirect_method(status_code, current_method, info.new_method, info.clear_body);

    // 5. Origin and Scheme Comparison (CVE-2024-1968 defense)
    let same_orig = is_same_origin_url(current_url, info.new_url);
    let is_downgrade = (scheme(current_url) == "https" && scheme(info.new_url) == "http");
    info.is_scheme_downgrade = is_downgrade;
    info.is_cross_origin = !same_orig || is_downgrade;

    // 6. Referrer-Policy and Referrer Computation
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

    // 7. SiteForCookies & Monotonic Redirect Chain Tainting (RFC 6265bis #1348)
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

fn compute_new_referrer<B>(
    source_url: const Url&,
    target_url: const Url&,
    policy: ReferrerPolicy,
    is_cross_origin: bool,
    is_downgrade: bool,
    out: B&
) {
    out.clear();

    // Strips username, password, and hash for referrer baseline
    var clean_source: u8[..2048] = [];
    clean_source.append(scheme(source_url));
    clean_source.append("://");
    clean_source.append(host(source_url));
    clean_source.append(pathname(source_url));
    clean_source.append(search(source_url));

    var source_origin: u8[..256] = [];
    serialize_origin(origin_from_url(source_url), source_origin);

    match policy {
        NoReferrer => { return; },
        NoReferrerWhenDowngrade => {
            if is_downgrade { return; }
            out.append(clean_source[..]);
        },
        Origin => {
            out.append(source_origin[..]);
        },
        OriginWhenCrossOrigin => {
            if is_cross_origin {
                out.append(source_origin[..]);
            } else {
                out.append(clean_source[..]);
            }
        },
        SameOrigin => {
            if is_cross_origin { return; }
            out.append(clean_source[..]);
        },
        StrictOrigin => {
            if is_downgrade { return; }
            out.append(source_origin[..]);
        },
        StrictOriginWhenCrossOrigin => {
            if is_downgrade { return; }
            if is_cross_origin {
                out.append(source_origin[..]);
            } else {
                out.append(clean_source[..]);
            }
        },
        UnsafeUrl => {
            out.append(clean_source[..]);
        },
    };
}

// ---- header sanitization on redirect (cve defense) -------------------------

fn sanitize_headers_on_redirect(
    headers: HeaderItem[..32]&,
    redirect_info: const RedirectInfo&,
    cors_mode: bool,
    tainted_origin: bool,
    enable_referer: bool,
    trusted_location_forwarding: bool = false
) {
    // 1. CVE-2023-45143: Cookie header is NEVER preserved across hops; always stripped
    // and freshly synthesized from CanonicalCookieJar for new_url.
    remove_header_by_name(headers, "Cookie");

    // 2. Sensitive Header Stripping on Cross-Origin or Scheme Downgrade
    // Covers Authorization, Proxy-Authorization, X-API-Key, X-Auth-Token, X-Access-Token
    // Defends against CVE-2024-1968, CVE-2026-55553, CVE-2026-64684
    if redirect_info.is_scheme_downgrade || (redirect_info.is_cross_origin && !trusted_location_forwarding) {
        remove_sensitive_headers(headers);
    }

    // 3. Payload and Representation Header Stripping on Method Mutation to GET (crbug #40686262)
    if redirect_info.clear_body {
        remove_header_by_name(headers, "Content-Type");
        remove_header_by_name(headers, "Content-Length");
        remove_header_by_name(headers, "Content-Encoding");
        remove_header_by_name(headers, "Content-Language");
        remove_header_by_name(headers, "Content-Location");
        remove_header_by_name(headers, "Transfer-Encoding");
        remove_header_by_name(headers, "Digest");
    }

    // 4. Origin Header Sanitization (Mozilla #1444278 / WHATWG Fetch)
    for &hdr in headers {
        if eq_ascii_fold(hdr.name[..], "Origin") {
            if redirect_info.is_cross_origin || tainted_origin {
                if cors_mode || tainted_origin {
                    hdr.value.clear();
                    hdr.value.append("null");
                } else if redirect_info.clear_body {
                    remove_header_by_name(headers, "Origin");
                    break;
                }
            }
        }
    }

    // 5. Referer Header Application
    remove_header_by_name(headers, "Referer");
    if enable_referer && redirect_info.new_referrer.len > 0 {
        if headers.len < 32 {
            headers.push(make_header("Referer", redirect_info.new_referrer[..]));
        }
    }
}

fn remove_header_by_name(headers: HeaderItem[..32]&, target_name: const u8[:]) {
    var write_idx = 0;
    for read_idx in headers.len {
        if !eq_ascii_fold(headers[read_idx].name[..], target_name) {
            if write_idx != read_idx {
                headers[write_idx] = headers[read_idx];
            }
            write_idx++;
        }
    }
    while headers.len > write_idx {
        headers.pop();
    }
}

fn remove_sensitive_headers(headers: HeaderItem[..32]&) {
    var write_idx = 0;
    for read_idx in headers.len {
        let is_sens = headers[read_idx].is_sensitive || is_heuristic_sensitive_header(headers[read_idx].name[..]);
        if !is_sens {
            if write_idx != read_idx {
                headers[write_idx] = headers[read_idx];
            }
            write_idx++;
        }
    }
    while headers.len > write_idx {
        headers.pop();
    }
}
