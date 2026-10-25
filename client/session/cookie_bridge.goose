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
    ctx: const RequestExecutionContext&,
    current_url: const core::Url&,
    safe_method: bool,
) -> SameSiteCookieContext {
    var samesite_ctx_type = SameSiteContextType.CrossSite;
    let is_first_p = is_first_party(ctx.site_for_cookies, href(current_url), true);

    if ctx.is_main_frame {
        if ctx.had_cross_site_hop {
            samesite_ctx_type = if safe_method { SameSiteContextType.SameSiteLax } else { SameSiteContextType.CrossSite };
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
        context_type: samesite_ctx_type,
        schemefully_same: ctx.site_for_cookies.schemefully_same,
        is_reload: ctx.is_reload,
        had_cross_site_hop: ctx.had_cross_site_hop,
    };
}

// Matches and attaches Cookie headers from the canonical jar to outbound request headers.
fn prepare_hop_cookie_header(
    session: Session&,
    ctx: RequestExecutionContext&,
    current_url: const core::Url&,
    samesite_eval: const SameSiteCookieContext&,
    safe_method: bool,
) {
    var matched_cookies: CanonicalCookie[>..] = [];
    let is_sec_channel = current_url.is_secure_scheme() || is_trustworthy_non_crypto_host(current_url.hostname());
    session.jar.get_canonical_cookies_for_request(
        current_url.hostname(),
        current_url.pathname(),
        current_url.scheme(),
        current_url.effective_port(),
        is_sec_channel,
        true,
        "",
        session.virtual_clock_us,
        matched_cookies,
        samesite_eval.context_type != SameSiteContextType.CrossSite,
        ctx.is_main_frame,
        safe_method
    );

    remove_header_by_name(ctx.headers, "Cookie");
    if matched_cookies.len > 0 {
        var cookie_hdr_val: u8[..2048] = [];
        format_cookie_header_value(cookie_hdr_val, matched_cookies[..]);
        if cookie_hdr_val.len > 0 && ctx.headers.len < 32 {
            ctx.headers.push(make_header("Cookie", cookie_hdr_val[..], true));
        }
    }
}

// Ingests Set-Cookie headers from an incoming response hop into the canonical jar.
fn ingest_hop_response_cookies(
    session: Session&,
    ctx: const RequestExecutionContext&,
    current_url: const core::Url&,
    samesite_eval: const SameSiteCookieContext&,
    set_cookies: const u8[..256][..16]&,
) {
    for &set_cookie_str in set_cookies {
        var def_path: u8[..256] = [];
        compute_default_cookie_path(current_url.pathname(), def_path);
        var parsed_cookie, parse_cause, cookie_ok = parse_canonical_set_cookie(set_cookie_str[..], current_url.hostname(), def_path[..], session.virtual_clock_us);
        if cookie_ok {
            let is_sec_channel = current_url.is_secure_scheme() || is_trustworthy_non_crypto_host(current_url.hostname());
            let can_write, code = can_set_canonical_cookie_for_context(
                parsed_cookie,
                samesite_eval,
                ctx.is_main_frame,
                is_sec_channel
            );
            if can_write {
                session.jar.set_cookie_header(current_url.href[..], set_cookie_str[..], session.virtual_clock_us);
            }
        }
    }
}
