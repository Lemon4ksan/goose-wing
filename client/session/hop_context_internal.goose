// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Internal request execution context, URL/query/origin helpers, redirect transitions, and RFC 6265bis cookie bridge.
namespace client_internal;

import std;
import core;
import rfc.http;
import cookie.constants;
import cookie.canonical;
import cookie.psl;
import cookie.parser;
import cookie.policy;
import cookie.engine;
import fingerprint.profile;
import http.request;
import http.response;
import http.headers;
import http.hsts;
import wire.pipeline;
import client.redirect;
import client.client;
import client.internal;
import .ssrf;

struct RequestExecutionContext {
    url_chain:           core::Url[..16]             = [],
    current_method:      u8[..16]                    = [],
    headers:             http::HeaderMap             = http::HeaderMap { .. },
    rewind_buf:          u8[..4096]                  = [],
    rewindable:          bool                        = true,
    body_consumed:       bool                        = false,
    initiator:           core::Origin                = core::Origin { .. },
    has_initiator:       bool                        = false,
    top_frame_origin:    core::Origin                = core::Origin { .. },
    site_for_cookies:    http::SiteForCookies        = http::SiteForCookies { .. },
    first_party_policy:  cookie::FirstPartyURLPolicy = cookie::FirstPartyURLPolicy.UPDATE_FIRST_PARTY_URL_ON_REDIRECT,
    is_main_frame:       bool                        = true,
    is_reload:           bool                        = false,
    redirect_mode:       client::RedirectMode        = client::RedirectMode.Follow,
    redirect_count:      i64                         = 0,
    max_redirects:       i64                         = 10,
    tainted_origin:      bool                        = false,
    had_cross_site_hop:  bool                        = false,
    cors_mode:           bool                        = false,
    auth_retried:        bool                        = false,
    early_data_disabled: bool                        = false,

    current_referrer:        u8[..2048]             = [],
    current_referrer_policy: client::ReferrerPolicy = client::ReferrerPolicy.StrictOriginWhenCrossOrigin,
    timeout_ms:              i64                    = 0,
    body:                    u8[>..]                = [],
}

// Extracts origin string "host:port" from parsed Url.
fn format_url_origin<B>(url_val: const core::Url&, out: B&) {
    let host = url_val.hostname();
    let port = url_val.effective_port();
    out.append(host);
    out.push(':');
    format(out, port);
}

fn target_has_scheme(target: const u8[:]) -> bool {
    guard target.len >= 4 else { return false; }
    return core::find(target, "://") >= 0;
}

fn resolve_target_origin<B>(target: const u8[:], out: B&) {
    if target_has_scheme(target) {
        let parsed, _ = core::parse_url(target);
        if parsed.valid {
            format_url_origin(parsed, out);
            return;
        }
    }
    out.append(target);
}

inline fn format_h2_request_target_path<B>(current_url: const core::Url&, out_path: B&) -> bool {
    let p_str = current_url.pathname();
    if p_str.len > 0 {
        guard out_path.try_append(p_str) else { return false; }
    } else {
        guard out_path.try_push('/') else { return false; }
    }
    let q_str = current_url.search();
    if q_str.len > 0 {
        guard out_path.try_append(q_str) else { return false; }
    }
    return out_path.len <= 1024;
}

inline fn append_single_query_param<B>(
    query_item: const http::QueryItem&,
    sep:        u8,
    out:        B&,
) -> bool {
    guard out.try_push(sep) else { return false; }
    guard core::append_query_component(query_item.key[..], out) else { return false; }
    guard out.try_push('=') else { return false; }
    return core::append_query_component(query_item.value[..], out);
}

// Appends query parameters to a URL buffer, preserving trailing fragment if present (RFC 3986 Section 4.1).
fn append_query_params_preserving_fragment<B>(
    out:          B&,
    query_params: const http::QueryItem[:],
) {
    guard query_params.len > 0 else { return; }

    let hash_pos = out[..].index_of_byte('#');
    let pre_hash = if hash_pos >= 0 { out[..hash_pos] } else { out[..] };
    let has_query_mark = pre_hash.contains_byte('?');

    var hash_buf: u8[..2048] = [];
    if hash_pos >= 0 {
        let _ = hash_buf.try_set(out[hash_pos..]);
        out.resize(hash_pos);
    }

    for &query_item, param_idx in query_params {
        let sep: u8 = if param_idx == 0 && !has_query_mark { '?' } else { '&' };
        guard append_single_query_param(query_item, sep, out) else { break; }
    }

    if hash_buf.len > 0 {
        let _ = out.try_append(hash_buf[..]);
    }
}

// Builds the effective request URL from base_url, req_url, and query_params.
// Fragments are preserved and appended after query parameters (RFC 3986 Section 4.1).
fn build_effective_url<B>(
    base_url:     const u8[:],
    req_url:      const u8[:],
    query_params: const http::QueryItem[:],
    out:          B&,
) {
    out.clear();
    let parsed_base = core::new_url(base_url);
    if parsed_base.valid {
        let eff_url = parsed_base.resolve_endpoint(req_url);
        let _ = out.try_append(eff_url.href[..]);
    } else if req_url.starts_with_fold("http://") || req_url.starts_with_fold("https://") {
        let _ = out.try_append(req_url);
    } else {
        let _ = out.try_append(base_url);
        if base_url.len > 0 && !core::ends_with(base_url, "/") && !core::starts_with(req_url, "/") {
            let _ = out.try_push('/');
        }
        let _ = out.try_append(req_url);
    }

    append_query_params_preserving_fragment(out, query_params);
}

fn validate_hop_prerequisites(session: const client::Session&, current_url: const core::Url&) -> http::Error {
    if session.https_only && current_url.scheme() != "https" {
        return http::make_error(rfc::STATUS_BAD_REQUEST, "ssrf_guard", "https_only policy violated");
    }
    let ssrf_err = client::validate_url_against_ssrf(current_url, session.ssrf_guard);
    if ssrf_err != client::RedirectError.None {
        return http::make_error(rfc::STATUS_FORBIDDEN, "ssrf_guard", redirect_error_to_string(ssrf_err));
    }
    return http::Error { .. };
}

fn finalize_success_response(ctx: const RequestExecutionContext&, resp: http::Response&) {
    resp.redirect_count = ctx.redirect_count;
    let _ = resp.final_method.try_set(ctx.current_method[..]);
    resp.url_chain.clear();
    for &hop_u in ctx.url_chain {
        var u_str: u8[..256] = [];
        let h = hop_u.href[..];
        let n = min(h.len, u_str.cap);
        let _ = u_str.try_set(h[..n]);
        guard resp.url_chain.try_push(u_str) else { break; }
    }
}

fn merge_session_and_request_headers(
    headers:         http::HeaderMap&,
    default_headers: const http::HeaderMap&,
    req_headers:     const http::HeaderMap&,
    profile:         fingerprint::Profile,
) {
    http::copy_headers(default_headers, headers);
    for &e in req_headers.entries {
        let name = http::entry_name(req_headers, e);
        http::remove_header_by_name(headers, name);
    }
    http::append_all_headers(req_headers, headers);
    if profile != fingerprint::Profile.None && http::find_header(headers, "accept-encoding").len == 0 {
        http::set_header(headers, "Accept-Encoding", "zstd, br, gzip");
    }
}

// Sanitizes the Hop-0 request `Referer` header and `ctx.current_referrer` according to `ctx.current_referrer_policy`.
//
// Example:
//   ctx.current_referrer = "https://a.example/secret?k=1", parsed_initial = "https://b.example/api"
//   sets ctx.current_referrer = "https://a.example/" and Referer header = "https://a.example/"
fn sanitize_initial_request_referrer(
    session:        const client::Session&,
    ctx:            RequestExecutionContext&,
    parsed_initial: const core::Url&,
) {
    guard ctx.current_referrer.len > 0 else { return; }
    let parsed_ref = core::new_url(ctx.current_referrer[..]);
    guard parsed_ref.valid else { return; }
    let rel = classify_redirect_origin_relation(parsed_ref, parsed_initial);
    var sanitized_ref: u8[..2048] = [];
    compute_new_referrer(
        parsed_ref,
        parsed_initial,
        ctx.current_referrer_policy,
        RedirectReferrerOptions {
            is_cross_origin: rel.is_cross_origin,
            is_downgrade:    rel.is_downgrade,
        },
        sanitized_ref,
    );
    let _ = ctx.current_referrer.try_set(sanitized_ref[..]);
    if session.enable_referer && sanitized_ref.len > 0 {
        http::set_header(ctx.headers, "Referer", sanitized_ref[..]);
    } else {
        http::remove_header_by_name(ctx.headers, "Referer");
    }
}

fn init_execution_context(
    session:        const client::Session&,
    req:            const http::Request&,
    parsed_initial: const core::Url&,
) -> RequestExecutionContext {
    var ctx = RequestExecutionContext {
        current_method:          copy(req.method),
        rewindable:              req.rewindable,
        body_consumed:           false,
        early_data_disabled:     req.disallow_early_data,
        cors_mode:               req.cors_mode,
        tainted_origin:          req.tainted_origin,
        is_main_frame:           req.is_main_frame,
        is_reload:               req.is_reload,
        redirect_mode:           session.redirect_mode,
        redirect_count:          0,
        max_redirects:           session.max_redirects,
        first_party_policy:      req.first_party_policy,
        current_referrer_policy: session.default_referrer_policy,
        timeout_ms:              req.timeout,
        ..
    };

    let req_ref = http::header(req, "Referer");
    if req_ref.len > 0 {
        let _ = ctx.current_referrer.try_set(req_ref);
    }

    ctx.body.append(req.body[..]);
    if req.rewind_buf.len > 0 {
        let _ = ctx.rewind_buf.try_set(req.rewind_buf[..]);
    } else if req.rewindable && req.body.len <= 4096 {
        let _ = ctx.rewind_buf.try_set(req.body[..]);
    } else if ctx.body.len > 0 {
        ctx.rewindable = false;
    }

    if req.has_initiator {
        ctx.initiator = copy(req.initiator);
        ctx.has_initiator = true;
    } else {
        ctx.initiator = core::origin_from_url(parsed_initial);
        ctx.has_initiator = true;
    }

    if ctx.top_frame_origin.host.len == 0 {
        ctx.top_frame_origin = core::origin_from_url(parsed_initial);
    }

    if req.has_site_for_cookies {
        ctx.site_for_cookies = copy(req.site_for_cookies);
    } else {
        ctx.site_for_cookies = cookie::site_for_cookies_from_parsed_url(parsed_initial);
    }

    merge_session_and_request_headers(
        ctx.headers, session.default_headers, req.headers, session.profile,
    );
    sanitize_initial_request_referrer(session, ctx, parsed_initial);
    let _ = ctx.url_chain.try_push(parsed_initial);
    return ctx;
}

struct SameSiteEvalFlags {
    is_first_p:     bool = false,
    init_same_site: bool = false,
    safe_method:    bool = false,
}

fn classify_main_frame_samesite(
    ctx:   const RequestExecutionContext&,
    flags: SameSiteEvalFlags,
) -> cookie::SameSiteContextType {
    if ctx.first_party_policy == cookie::FirstPartyURLPolicy.NEVER_CHANGE_FIRST_PARTY_URL && !flags.is_first_p {
        return cookie::SameSiteContextType.CrossSite;
    }
    if ctx.had_cross_site_hop {
        return if flags.safe_method {
            cookie::SameSiteContextType.SameSiteLax
        } else {
            cookie::SameSiteContextType.CrossSite
        };
    }
    if flags.is_first_p && flags.init_same_site {
        return cookie::SameSiteContextType.SameSiteStrict;
    }
    return if flags.safe_method {
        cookie::SameSiteContextType.SameSiteLax
    } else {
        cookie::SameSiteContextType.SameSiteLaxMethodUnsafe
    };
}

fn classify_subframe_samesite(
    ctx:   const RequestExecutionContext&,
    flags: SameSiteEvalFlags,
) -> cookie::SameSiteContextType {
    if ctx.had_cross_site_hop || !flags.is_first_p {
        return cookie::SameSiteContextType.CrossSite;
    }
    if flags.init_same_site {
        return cookie::SameSiteContextType.SameSiteStrict;
    }
    return if flags.safe_method {
        cookie::SameSiteContextType.SameSiteLax
    } else {
        cookie::SameSiteContextType.SameSiteLaxMethodUnsafe
    };
}

// Computes the SameSite cookie context for a request hop.
fn compute_hop_samesite_context(
    ctx:         const RequestExecutionContext&,
    current_url: const core::Url&,
    safe_method: bool,
) -> cookie::SameSiteCookieContext {
    let is_first_p = !ctx.site_for_cookies.is_null &&
        cookie::is_first_party(ctx.site_for_cookies, current_url.href[..], true);
    let init_same_site = !ctx.has_initiator || (
        ctx.initiator.kind != core::OriginKind.Opaque && cookie::is_schemeful_same_site(
            ctx.initiator.scheme[..], ctx.initiator.host[..],
            current_url.scheme(), current_url.hostname(),
        )
    );
    let flags = SameSiteEvalFlags {
        is_first_p:     is_first_p,
        init_same_site: init_same_site,
        safe_method:    safe_method,
    };
    let samesite_ctx_type = if ctx.site_for_cookies.is_null {
        cookie::SameSiteContextType.CrossSite
    } else if ctx.is_main_frame {
        classify_main_frame_samesite(ctx, flags)
    } else {
        classify_subframe_samesite(ctx, flags)
    };
    return cookie::SameSiteCookieContext {
        context_type:       samesite_ctx_type,
        schemefully_same:   ctx.site_for_cookies.schemefully_same,
        is_reload:          ctx.is_reload,
        had_cross_site_hop: ctx.had_cross_site_hop,
    };
}

// Computes the SameSite cookie context for Set-Cookie response ingestion
// (Chromium `net::cookie_util::ComputeSameSiteContextForResponse` / `MakeInclusiveForSet`,
// `cookie_util.cc:992-1047`): main-frame navigations whose target URL is first-party
// relative to `site_for_cookies` can set `SameSite=Lax` and `SameSite=Strict` cookies.
fn compute_hop_samesite_context_for_response(
    ctx:               const RequestExecutionContext&,
    current_url:       const core::Url&,
    req_samesite_eval: const cookie::SameSiteCookieContext&,
) -> cookie::SameSiteCookieContext {
    var resp_ctx = copy(req_samesite_eval);
    if ctx.is_main_frame && !ctx.site_for_cookies.is_null {
        let is_first_p = cookie::is_first_party(ctx.site_for_cookies, current_url.href[..], true);
        if is_first_p && resp_ctx.context_type == cookie::SameSiteContextType.CrossSite {
            resp_ctx.context_type = cookie::SameSiteContextType.SameSiteLax;
        }
    }
    return resp_ctx;
}

fn append_site_partition_key<B>(
    scheme:       const u8[:],
    fallback_sch: const u8[:],
    raw_host:     const u8[:],
    extract_etld: bool,
    out:          B&,
) -> bool {
    let eff_sch = if scheme.len > 0 { scheme } else { fallback_sch };
    guard eff_sch.len > 0 else { return false; }
    var etld: u8[..128] = [];
    if extract_etld {
        cookie::extract_etld_plus_one(raw_host, etld);
    }
    let site_host = if extract_etld && etld.len > 0 { etld[..] } else { raw_host };
    return out.try_append(eff_sch) && out.try_append("://") && out.try_append(site_host);
}

// Derives the top-level site partition key for CHIPS cookies (RFC 6265bis).
//
// Example:
//   ctx.top_frame_origin = "https://example.com"
//   returns: out = "https://example.com"
fn compute_hop_partition_key<B>(
    ctx:         const RequestExecutionContext&,
    current_url: const core::Url&,
    out:         B&,
) {
    var committed = false;
    defer if !committed { out.clear(); };
    out.clear();
    let fallback_sch = current_url.scheme();
    if ctx.top_frame_origin.host.len > 0 {
        committed = append_site_partition_key(
            ctx.top_frame_origin.scheme[..], fallback_sch, ctx.top_frame_origin.host[..], true, out,
        );
        return;
    }
    if !ctx.site_for_cookies.is_null && ctx.site_for_cookies.registrable_domain.len > 0 {
        committed = append_site_partition_key(
            ctx.site_for_cookies.scheme[..], fallback_sch, ctx.site_for_cookies.registrable_domain[..], false, out,
        );
        return;
    }
    committed = append_site_partition_key(fallback_sch, fallback_sch, current_url.hostname(), true, out);
}

// Matches and attaches Cookie headers from the canonical jar to outbound request headers.
fn prepare_hop_cookie_header(
    session:       client::Session&,
    ctx:           RequestExecutionContext&,
    current_url:   const core::Url&,
    samesite_eval: const cookie::SameSiteCookieContext&,
    safe_method:   bool,
) {
    let is_sec_channel = current_url.is_secure_scheme() ||
        cookie::is_trustworthy_non_crypto_host(current_url.hostname());
    var part_key: u8[..256] = [];
    compute_hop_partition_key(ctx, current_url, part_key);
    let allow_lax = (ctx.is_main_frame && samesite_eval.context_type != cookie::SameSiteContextType.CrossSite) ||
        samesite_eval.context_type == cookie::SameSiteContextType.SameSiteLax ||
        samesite_eval.context_type == cookie::SameSiteContextType.SameSiteLaxMethodUnsafe;
    let _ = cookie::encode_cookie_header_to_map(
        session.jar,
        current_url.hostname(),
        current_url.pathname(),
        current_url.scheme(),
        current_url.effective_port(),
        cookie::SourceOptions { is_http_api: true, url_is_secure: is_sec_channel },
        part_key[..],
        session.virtual_clock_us,
        cookie::AccessOptions {
            is_same_site:            samesite_eval.context_type == cookie::SameSiteContextType.SameSiteStrict,
            is_top_level_navigation: allow_lax,
            is_safe_method:          safe_method,
            had_cross_site_hop:      samesite_eval.had_cross_site_hop,
        },
        ctx.headers,
    );
}

// Ingests Set-Cookie headers from an incoming response hop into the canonical jar.
fn ingest_hop_response_cookies(
    session:       client::Session&,
    ctx:           const RequestExecutionContext&,
    current_url:   const core::Url&,
    samesite_eval: const cookie::SameSiteCookieContext&,
    resp_headers:  const http::HeaderMap&,
) {
    let resp_samesite = compute_hop_samesite_context_for_response(ctx, current_url, samesite_eval);
    var def_path: u8[..256] = [];
    cookie::compute_default_path(current_url.pathname(), def_path);
    let is_sec_channel = current_url.is_secure_scheme() ||
        cookie::is_trustworthy_non_crypto_host(current_url.hostname());
    let opts = cookie::InclusionOptions {
        is_main_frame:     ctx.is_main_frame,
        is_secure_channel: is_sec_channel,
    };
    var part_key: u8[..256] = [];
    compute_hop_partition_key(ctx, current_url, part_key);

    for &e in resp_headers.entries {
        let ename = http::entry_name(resp_headers, e);
        guard ename.eq_ascii_fold("set-cookie") else { continue; }
        let set_cookie_str = http::entry_value(resp_headers, e);
        var parsed_cookie, _, cookie_ok = cookie::parse_canonical_set_cookie(
            set_cookie_str,
            current_url.hostname(),
            def_path[..],
            session.virtual_clock_us,
        );
        guard cookie_ok else { continue; }
        let _, can_write = cookie::can_set_for_context(parsed_cookie, resp_samesite, opts);
        guard can_write else { continue; }
        session.jar.set_cookie_header(current_url.href[..], set_cookie_str, session.virtual_clock_us, part_key[..]);
    }
}

fn apply_redirect_transition(
    session:       const client::Session&,
    ctx:           RequestExecutionContext&,
    redirect_info: const client::RedirectInfo&,
) -> http::Error {
    if !redirect_info.clear_body && !ctx.rewindable && (ctx.body_consumed || ctx.body.len > 0) {
        return http::make_error(rfc::STATUS_BAD_REQUEST, "body_rewind", "http: cannot rewind body");
    }
    guard redirect_info.new_method.len <= ctx.current_method.cap &&
        redirect_info.new_referrer.len <= ctx.current_referrer.cap else {
        return http::make_error(rfc::STATUS_BAD_REQUEST, "redirect", "redirect state exceeds capacity");
    }

    ctx.had_cross_site_hop = ctx.had_cross_site_hop || redirect_info.is_cross_site_tainted;
    if ctx.cors_mode && redirect_info.is_cross_origin && ctx.url_chain.len > 0 {
        let prev_idx = core::sub_sat_i64(ctx.url_chain.len, 1);
        let prev_orig = core::origin_from_url(ctx.url_chain[prev_idx]);
        if !ctx.has_initiator || !core::is_same_origin(ctx.initiator, prev_orig) {
            ctx.tainted_origin = true;
        }
    }
    if ctx.is_main_frame && ctx.first_party_policy == cookie::FirstPartyURLPolicy.UPDATE_FIRST_PARTY_URL_ON_REDIRECT {
        ctx.top_frame_origin = core::origin_from_url(redirect_info.new_url);
    }
    ctx.site_for_cookies = redirect_info.new_site_for_cookies;
    ctx.auth_retried = false;
    let _ = ctx.current_method.try_set(redirect_info.new_method[..]);
    let _ = ctx.current_referrer.try_set(redirect_info.new_referrer[..]);
    ctx.current_referrer_policy = redirect_info.new_referrer_policy;

    if redirect_info.clear_body {
        ctx.body.clear();
        ctx.rewind_buf.clear();
        ctx.rewindable = false;
        ctx.body_consumed = false;
    } else {
        ctx.body.clear();
        ctx.body.append(ctx.rewind_buf[..]);
        ctx.body_consumed = false;
    }

    let is_trusted = is_trusted_location_host(session, redirect_info.new_url.hostname());
    client::sanitize_headers_on_redirect(
        ctx.headers,
        redirect_info,
        client::RedirectSanitizeOptions {
            cors_mode:                   ctx.cors_mode,
            tainted_origin:              ctx.tainted_origin,
            enable_referer:              session.enable_referer,
            trusted_location_forwarding: is_trusted,
        },
    );
    return http::Error { .. };
}

// RFC 9110 Section 15.4: Redirection 3xx - Checks whether response headers contain conflicting Location fields.
fn has_conflicting_location_headers(headers: const http::HeaderMap&, loc_hdr: const u8[:]) -> bool {
    let expected_loc = loc_hdr.trim_lws();
    for &e in headers.entries {
        guard http::entry_name(headers, e).eq_ascii_fold("location") else { continue; }
        if http::entry_value(headers, e).trim_lws() != expected_loc {
            return true;
        }
    }
    return false;
}

fn process_redirect_hop(
    session:     client::Session&,
    ctx:         RequestExecutionContext&,
    resp:        http::Response&,
    current_url: const core::Url&,
    loc_hdr:     const u8[:],
) -> bool, http::Error {
    if ctx.redirect_mode == client::RedirectMode.Manual {
        return false, http::Error { .. };
    }
    if ctx.redirect_mode == client::RedirectMode.Error {
        return false, http::make_error(rfc::STATUS_BAD_REQUEST, "redirect", "redirects disabled by mode");
    }
    if ctx.redirect_count >= ctx.max_redirects || ctx.url_chain.len >= ctx.url_chain.cap {
        return false, http::make_error(rfc::STATUS_BAD_REQUEST, "redirect", "maximum redirect hops exceeded");
    }
    if has_conflicting_location_headers(resp.headers, loc_hdr) {
        let err_msg = redirect_error_to_string(client::RedirectError.MultipleLocationHeaders);
        return false, http::make_error(rfc::STATUS_BAD_GATEWAY, "redirect", err_msg);
    }

    // RFC 6797 Section 8.3: URI Loading and Port Mapping - Upgrade http:// redirect target for known HSTS hosts.
    var upgraded_loc_buf: u8[..2048] = [];
    var hsts_upgraded = false;
    let hsts_stage_on = wire::is_ingress_stage_enabled(session.wire_pipeline, wire::STAGE_ID_CLI_IN_URL_HSTS);
    if session.enable_hsts && hsts_stage_on && loc_hdr.len > 0 {
        let prelim_target, prelim_err = core::parse_url_with_base(loc_hdr.trim_lws(), current_url);
        if prelim_err == core::UrlParseError.None && prelim_target.valid && !prelim_target.is_secure_scheme() {
            let now_sec = div_euclid(session.virtual_clock_us, 1000000);
            hsts_upgraded = http::hsts_upgrade_url(session.hsts, prelim_target.href[..], now_sec, upgraded_loc_buf);
        }
    }
    let eff_loc = if hsts_upgraded { upgraded_loc_buf[..] } else { loc_hdr };

    var combined_ref_policy: u8[..256] = [];
    let _ = http::get_combined(resp.headers, "Referrer-Policy", combined_ref_policy, 256);
    var redirect_info = client::compute_redirect_info(
        resp.status_code,
        ctx.current_method[..],
        current_url,
        eff_loc,
        combined_ref_policy[..],
        ctx.current_referrer_policy,
        ctx.current_referrer[..],
        ctx.site_for_cookies,
        ctx.first_party_policy,
        ctx.url_chain[..],
        ctx.initiator,
        client::RedirectOptions {
            has_initiator:      ctx.has_initiator,
            cors_mode:          ctx.cors_mode,
            tainted_origin:     ctx.tainted_origin,
            is_main_frame:      ctx.is_main_frame,
            had_cross_site_hop: ctx.had_cross_site_hop,
        },
    );
    redirect_info.insecure_scheme_was_upgraded = hsts_upgraded;

    guard redirect_info.error == client::RedirectError.None else {
        return false, http::make_error(
            rfc::STATUS_BAD_REQUEST, "redirect", redirect_error_to_string(redirect_info.error),
        );
    }

    let redirect_err = apply_redirect_transition(session, ctx, redirect_info);
    guard http::ok(redirect_err) else { return false, redirect_err; }

    let _ = ctx.url_chain.try_push(redirect_info.new_url);
    ctx.redirect_count = core::add_sat_i64(ctx.redirect_count, 1);
    return true, http::Error { .. };
}
