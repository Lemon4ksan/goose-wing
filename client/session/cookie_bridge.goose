// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Cookie Jar integration for client request hops and response ingestion (RFC 6265bis).
namespace wing;

import std;
import cookie.constants;
import cookie.canonical;
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
) -> SameSiteCookieContext {
    var samesite_ctx_type = SameSiteContextType.CrossSite;
    let is_first_p = is_first_party(ctx.site_for_cookies, href(current_url), true);

    if ctx.is_main_frame {
        if ctx.had_cross_site_hop {
            samesite_ctx_type = if safe_method {
                SameSiteContextType.SameSiteLax
            } else {
                SameSiteContextType.CrossSite
            };
        } else if is_first_p {
            samesite_ctx_type = SameSiteContextType.SameSiteStrict;
        } else if safe_method {
            samesite_ctx_type = SameSiteContextType.SameSiteLax;
        } else {
            samesite_ctx_type = SameSiteContextType.SameSiteLaxMethodUnsafe;
        }
    } else {
        if ctx.had_cross_site_hop || !is_first_p {
            samesite_ctx_type = SameSiteContextType.CrossSite;
        } else {
            samesite_ctx_type = SameSiteContextType.SameSiteStrict;
        }
    }

    return SameSiteCookieContext {
        context_type:       samesite_ctx_type,
        schemefully_same:   ctx.site_for_cookies.schemefully_same,
        is_reload:          ctx.is_reload,
        had_cross_site_hop: ctx.had_cross_site_hop,
    };
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
    if ctx.top_frame_origin.host.len > 0 {
        let sch = if ctx.top_frame_origin.scheme.len > 0 { ctx.top_frame_origin.scheme[..] } else { "https" };
        out.append(sch);
        out.append("://");
        out.append(ctx.top_frame_origin.host[..]);
    } else if !ctx.site_for_cookies.is_null && ctx.site_for_cookies.registrable_domain.len > 0 {
        let sch = if ctx.site_for_cookies.scheme.len > 0 { ctx.site_for_cookies.scheme[..] } else { "https" };
        out.append(sch);
        out.append("://");
        out.append(ctx.site_for_cookies.registrable_domain[..]);
    } else {
        out.append(current_url.scheme());
        out.append("://");
        var etld: u8[..128] = [];
        psl_extract_etld_plus_one(current_url.hostname(), etld);
        if etld.len > 0 {
            out.append(etld[..]);
        } else {
            out.append(current_url.hostname());
        }
    }
}

// Matches and attaches Cookie headers from the canonical jar to outbound request headers.
fn prepare_hop_cookie_header(
    session:       Session&,
    ctx:           RequestExecutionContext&,
    current_url:   const core::Url&,
    samesite_eval: const SameSiteCookieContext&,
    safe_method:   bool,
) {
    let is_sec_channel = current_url.is_secure_scheme() || is_trustworthy_non_crypto_host(current_url.hostname());
    var part_key: u8[..256] = [];
    compute_hop_partition_key(ctx, current_url, part_key);
    let _ = encode_cookie_header_to_map(
        session.jar,
        current_url.hostname(),
        current_url.pathname(),
        current_url.scheme(),
        current_url.effective_port(),
        CookieSourceOptions { is_http_api: true, url_is_secure: is_sec_channel },
        part_key[..],
        session.virtual_clock_us,
        CookieAccessOptions {
            is_same_site:            samesite_eval.context_type == SameSiteContextType.SameSiteStrict,
            is_top_level_navigation: ctx.is_main_frame,
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
    samesite_eval: const SameSiteCookieContext&,
    resp_headers:  const HeaderMap&,
) {
    for i in resp_headers.entries.len {
        let e = resp_headers.entries[i];
        let ename = entry_name(resp_headers, e);
        guard eq_ascii_fold(ename, "set-cookie") else { continue; }
        let set_cookie_str = entry_value(resp_headers, e);
        var def_path: u8[..256] = [];
        compute_default_cookie_path(current_url.pathname(), def_path);
        var parsed_cookie, parse_cause, cookie_ok = parse_canonical_set_cookie(
            set_cookie_str,
            current_url.hostname(),
            def_path[..],
            session.virtual_clock_us,
        );
        guard cookie_ok else {
            continue;
        }
        let is_sec_channel = current_url.is_secure_scheme() ||
            is_trustworthy_non_crypto_host(current_url.hostname());
        let opts = CookieInclusionOptions {
            is_main_frame:     ctx.is_main_frame,
            is_secure_channel: is_sec_channel,
        };
        let can_write, code = can_set_canonical_cookie_for_context(
            parsed_cookie,
            samesite_eval,
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
