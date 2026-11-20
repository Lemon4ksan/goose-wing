// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Cookie Jar integration for client request hops and response ingestion (RFC 6265bis).
namespace wing;

import std;
import core from "../..";
import cookie.constants;
import cookie.canonical;
import cookie.psl;
import cookie.parser;
import cookie.policy;
import cookie.engine;
import client.session.ssrf;
import client.session.mock;
import client.client;

// Computes the SameSite cookie context for a request hop.
fn compute_hop_samesite_context(
    ctx:         const RequestExecutionContext&,
    current_url: const core::Url&,
    safe_method: bool,
) -> cookie::SameSiteCookieContext {
    var samesite_ctx_type = cookie::SameSiteContextType.CrossSite;
    let is_first_p = !ctx.site_for_cookies.is_null &&
        cookie::is_first_party(ctx.site_for_cookies, current_url.href[..], true);
    let init_same_site = !ctx.has_initiator || (
        ctx.initiator.kind != core::OriginKind.Opaque && cookie::is_schemeful_same_site(
            ctx.initiator.scheme[..], ctx.initiator.host[..],
            current_url.scheme(), current_url.hostname(),
        )
    );

    if ctx.site_for_cookies.is_null {
        samesite_ctx_type = cookie::SameSiteContextType.CrossSite;
    } else if ctx.is_main_frame {
        if ctx.first_party_policy == cookie::FirstPartyURLPolicy.NEVER_CHANGE_FIRST_PARTY_URL && !is_first_p {
            samesite_ctx_type = cookie::SameSiteContextType.CrossSite;
        } else if ctx.had_cross_site_hop {
            samesite_ctx_type = if safe_method {
                cookie::SameSiteContextType.SameSiteLax
            } else {
                cookie::SameSiteContextType.CrossSite
            };
        } else if is_first_p && init_same_site {
            samesite_ctx_type = cookie::SameSiteContextType.SameSiteStrict;
        } else if safe_method {
            samesite_ctx_type = cookie::SameSiteContextType.SameSiteLax;
        } else {
            samesite_ctx_type = cookie::SameSiteContextType.SameSiteLaxMethodUnsafe;
        }
    } else {
        if ctx.had_cross_site_hop || !is_first_p {
            samesite_ctx_type = cookie::SameSiteContextType.CrossSite;
        } else if init_same_site {
            samesite_ctx_type = cookie::SameSiteContextType.SameSiteStrict;
        } else if safe_method {
            samesite_ctx_type = cookie::SameSiteContextType.SameSiteLax;
        } else {
            samesite_ctx_type = cookie::SameSiteContextType.SameSiteLaxMethodUnsafe;
        }
    }

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
    out.clear();
    let fallback_sch = current_url.scheme();
    if ctx.top_frame_origin.host.len > 0 {
        let top_sch = if ctx.top_frame_origin.scheme.len > 0 { ctx.top_frame_origin.scheme[..] } else { fallback_sch };
        guard top_sch.len > 0 else { return; }
        var top_etld: u8[..128] = [];
        cookie::extract_etld_plus_one(ctx.top_frame_origin.host[..], top_etld);
        let site_host = if top_etld.len > 0 { top_etld[..] } else { ctx.top_frame_origin.host[..] };
        guard out.try_append(top_sch) && out.try_append("://") && out.try_append(site_host) else {
            out.clear();
            return;
        }
    } else if !ctx.site_for_cookies.is_null && ctx.site_for_cookies.registrable_domain.len > 0 {
        let sfc_sch = if ctx.site_for_cookies.scheme.len > 0 { ctx.site_for_cookies.scheme[..] } else { fallback_sch };
        guard sfc_sch.len > 0 else { return; }
        guard out.try_append(sfc_sch) && out.try_append("://") &&
            out.try_append(ctx.site_for_cookies.registrable_domain[..]) else {
            out.clear();
            return;
        }
    } else {
        guard fallback_sch.len > 0 else { return; }
        var etld: u8[..128] = [];
        cookie::extract_etld_plus_one(current_url.hostname(), etld);
        let site_host = if etld.len > 0 { etld[..] } else { current_url.hostname() };
        guard out.try_append(fallback_sch) && out.try_append("://") && out.try_append(site_host) else {
            out.clear();
            return;
        }
    }
}

// Matches and attaches Cookie headers from the canonical jar to outbound request headers.
fn prepare_hop_cookie_header(
    session:       Session&,
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
    session:       Session&,
    ctx:           const RequestExecutionContext&,
    current_url:   const core::Url&,
    samesite_eval: const cookie::SameSiteCookieContext&,
    resp_headers:  const HeaderMap&,
) {
    let resp_samesite = compute_hop_samesite_context_for_response(ctx, current_url, samesite_eval);
    for i in resp_headers.entries.len {
        let e = resp_headers.entries[i];
        let ename = entry_name(resp_headers, e);
        guard ename.eq_ascii_fold("set-cookie") else { continue; }
        let set_cookie_str = entry_value(resp_headers, e);
        var def_path: u8[..256] = [];
        cookie::compute_default_path(current_url.pathname(), def_path);
        var parsed_cookie, parse_cause, cookie_ok = cookie::parse_canonical_set_cookie(
            set_cookie_str,
            current_url.hostname(),
            def_path[..],
            session.virtual_clock_us,
        );
        guard cookie_ok else {
            continue;
        }
        let is_sec_channel = current_url.is_secure_scheme() ||
            cookie::is_trustworthy_non_crypto_host(current_url.hostname());
        let opts = cookie::InclusionOptions {
            is_main_frame:     ctx.is_main_frame,
            is_secure_channel: is_sec_channel,
        };
        let _, can_write = cookie::can_set_for_context(
            parsed_cookie,
            resp_samesite,
            opts,
        );
        guard can_write else {
            continue;
        }
        var part_key: u8[..256] = [];
        compute_hop_partition_key(ctx, current_url, part_key);
        session.jar.set_cookie_header(current_url.href[..], set_cookie_str, session.virtual_clock_us, part_key[..]);
    }
}
