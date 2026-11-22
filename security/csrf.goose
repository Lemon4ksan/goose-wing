// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Fetch Metadata resource isolation and cross-origin request protection.
namespace security;

import std;
import core;
import rfc.http;
import .policy_internal;
import .fetch_policy_internal;

// ---- fetch metadata attribute taxonomy -------------------------------------

enum SecFetchSite {
    Unknown,
    SameOrigin,
    SameSite,
    CrossSite,
    None,
    Missing,
}

enum SecFetchMode {
    Navigate,
    SameOrigin,
    Cors,
    NoCors,
    WebSocket,
    Other,
}

enum SecFetchDest {
    Document,
    NestedDocument,
    Iframe,
    Frame,
    Embed,
    Object,
    Script,
    Image,
    Style,
    Font,
    Empty,
    Other,
}

enum CsrfRejectReason {
    CrossSiteStateMutation,
    DisallowedSameSiteSubdomain,
    CrossSiteFramingOrXssi,
    CrossSiteUnauthorizedSubresource,
    OriginHostMismatch,
    MissingBrowserHeadersWithSessionCookie,
    MissingUserActivationOnSensitiveNav,
}

enum CsrfDecision {
    Allow,
    RejectForbidden { reason: CsrfRejectReason },
    AllowExempt,
}

enum CsrfTargetScheme {
    Https,
    Http,
}

// 5-attribute vector projection pi_FM(r) = (sigma, mu, delta, u, m)
struct FetchContext {
    method_is_safe:                bool         = true,
    method:                        u8[..16]     = "GET",
    site:                          SecFetchSite = SecFetchSite.Missing,
    mode:                          SecFetchMode = SecFetchMode.Other,
    dest:                          SecFetchDest = SecFetchDest.Other,
    user_activated:                bool         = false,
    has_origin:                    bool         = false,
    origin:                        u8[..256]    = [],
    has_referer:                   bool         = false,
    referer:                       u8[..512]    = [],
    target_scheme:                 u8[..16]     = "https",
    target_host:                   u8[..256]    = [],
    path:                          u8[..512]    = "/",
    has_session_cookie:            bool         = false,
    has_explicit_auth:             bool         = false,
    is_sensitive_navigation_route: bool         = false,
}

struct CrossOriginGuard {
    allow_same_site:                          bool            = false,
    require_user_activation_on_sensitive_nav: bool            = true,
    allow_cross_site_static_assets:           bool            = true,
    trusted_origins:                          u8[..128][..16] = [],
    exempt_paths:                             u8[..128][..16] = [],
}

// Parses Sec-Fetch-Site string value.
//
// Example:
//   val = "same-origin"
//   returns: SecFetchSite.SameOrigin
fn parse_sec_fetch_site(val: const u8[:]) -> SecFetchSite {
    let clean = security_internal::strip_sf_parameters(val);
    guard clean.len > 0 else { return SecFetchSite.Unknown; }
    const for <N, V> in variants<SecFetchSite> {
        let v = default<V>();
        let tok = security_internal::wire_token(v);
        if tok.len > 0 && clean == tok {
            let candidate: SecFetchSite = v;
            return candidate;
        }
    }
    return SecFetchSite.Unknown;
}

// Parses Sec-Fetch-Mode string value.
//
// Example:
//   val = "navigate"
//   returns: SecFetchMode.Navigate
fn parse_sec_fetch_mode(val: const u8[:]) -> SecFetchMode {
    let clean = security_internal::strip_sf_parameters(val);
    const for <N, V> in variants<SecFetchMode> {
        let v = default<V>();
        let tok = security_internal::wire_token(v);
        if tok.len > 0 && clean == tok {
            let candidate: SecFetchMode = v;
            return candidate;
        }
    }
    return SecFetchMode.Other;
}

// Parses Sec-Fetch-Dest string value.
//
// Example:
//   val = "document"
//   returns: SecFetchDest.Document
fn parse_sec_fetch_dest(val: const u8[:]) -> SecFetchDest {
    let clean = security_internal::strip_sf_parameters(val);
    const for <N, V> in variants<SecFetchDest> {
        let v = default<V>();
        let tok = security_internal::wire_token(v);
        if tok.len > 0 && clean == tok {
            let candidate: SecFetchDest = v;
            return candidate;
        }
    }
    return SecFetchDest.Other;
}

fn csrf_reject_reason_to_string(reason: CsrfRejectReason) -> const u8[:] {
    const for <N, V> in variants<CsrfRejectReason> {
        let v: CsrfRejectReason = default<V>();
        if reason == v { return N; }
    }
    return "Unknown";
}

fn is_allowed(decision: const CsrfDecision&) -> bool {
    return match decision {
        Allow => true,
        AllowExempt => true,
        RejectForbidden _ => false,
    };
}

// ---- CrossOriginGuard policy & CSRF tokens ---------------------------------

fn add_trusted_origin(guard_cfg: CrossOriginGuard&, origin_str: const u8[:]) -> bool {
    let trimmed = origin_str.trim_lws();
    guard trimmed.len > 0 else { return false; }
    var entry: u8[..128] = [];
    guard entry.try_set(trimmed) else { return false; }
    return guard_cfg.trusted_origins.try_push(entry);
}

fn add_exempt_path(guard_cfg: CrossOriginGuard&, path_str: const u8[:]) -> bool {
    let trimmed = path_str.trim_lws();
    guard trimmed.len > 0 && trimmed[0] == '/' else { return false; }
    var entry: u8[..128] = [];
    guard entry.try_set(trimmed) else { return false; }
    return guard_cfg.exempt_paths.try_push(entry);
}

// Branchless constant-time case-insensitive ASCII comparison.
fn subtle_equal_ascii_fold(a: const u8[:], b: const u8[:]) -> bool {
    guard a.len == b.len else { return false; }
    var diff: u32 = 0;
    for i in a.len {
        let ca = core::to_lower_ascii_byte(a[i]);
        let cb = core::to_lower_ascii_byte(b[i]);
        diff |= (ca ^ cb);
    }
    return diff == 0;
}

// Constant-time double-submit CSRF token validation.
fn validate_csrf_token(cookie_token: const u8[:], request_token: const u8[:]) -> bool {
    guard cookie_token.len > 0 && request_token.len > 0 else { return false; }
    return core::ct_eq_bytes(cookie_token, request_token);
}

// Masks a CSRF token using a one-time pad XOR mask into out: [mask (N bytes) | masked_secret (N bytes)].
fn mask_csrf_token<B>(mask: const u8[:], raw_secret: const u8[:], out: B&) -> bool {
    guard mask.len > 0 && mask.len == raw_secret.len else { return false; }
    guard core::mul_sat_i64(mask.len, 2) <= out.cap else { return false; }
    guard out.try_set(mask) else { return false; }
    for i in mask.len { out.push(raw_secret[i] ^ mask[i]); }
    return true;
}

// Unmasks and validates a masked CSRF token against expected raw secret in constant time.
fn verify_masked_csrf_token(masked_token: const u8[:], expected_unmasked: const u8[:]) -> bool {
    let n = expected_unmasked.len;
    guard n > 0 && masked_token.len == core::mul_sat_i64(n, 2) else { return false; }
    var diff: u32 = 0;
    for i in n {
        let mask_byte = masked_token[i];
        let masked_secret_byte = masked_token[core::add_sat_i64(n, i)];
        let unmasked_byte = masked_secret_byte ^ mask_byte;
        diff |= (unmasked_byte ^ expected_unmasked[i]);
    }
    return diff == 0;
}

// Extracts scheme + authority origin prefix from a URL or Origin string (RFC 6454 §4).
// Returns empty slice for opaque ("null") or malformed URLs.
//
// Example:
//   url_or_origin = "https://partner.example.com/checkout?id=1"
//   returns: "https://partner.example.com"
fn extract_origin_from_url(url_or_origin: const u8[:]) -> const u8[:] {
    let s = url_or_origin.trim_lws();
    let scheme_len: i64 = block {
        if s.starts_with_fold("https://") { break 8; }
        if s.starts_with_fold("http://") { break 7; }
        0
    };
    guard scheme_len > 0 else { return s[..0]; }
    let rest = s[scheme_len..];
    let delim = core::find_byteset(rest, "/?#");
    let end_idx = if delim >= 0 { delim } else { rest.len };

    let origin = s[..core::add_sat_i64(scheme_len, end_idx)];
    guard extract_hostname_from_origin(origin).len > 0 else {
        return s[..0];
    }
    let norm_host = security_internal::strip_default_origin_port(origin[scheme_len..], scheme_len == 8);
    return origin[..core::add_sat_i64(scheme_len, norm_host.len)];
}

// Extracts host from URL or Origin string (RFC 6454 / RFC 3986).
// Requires valid http:// or https:// scheme prefix; returns empty slice for opaque origins (e.g. "null").
//
// Example:
//   url_or_origin = "https://example.com:8080/path"
//   returns: "example.com:8080"
fn extract_host_from_url(url_or_origin: const u8[:]) -> const u8[:] {
    let origin = extract_origin_from_url(url_or_origin);
    guard origin.len > 0 else { return origin; }
    if origin.starts_with_fold("https://") {
        return origin[8..];
    }
    return origin[7..];
}

// Extracts normalized path from relative or absolute URL (RFC 3986 §3.3).
// Strips query parameters and fragments before authority removal to prevent query-slash smuggling.
//
// Example:
//   raw = "https://example.com/api/webhook?foo=bar"
//   returns: "/api/webhook"
fn extract_path_from_url(raw: const u8[:]) -> const u8[:] {
    var s = raw.trim_lws();
    let query_idx = s.index_of_byte('?');
    if query_idx >= 0 { s = s[..query_idx]; }
    let hash_idx = s.index_of_byte('#');
    if hash_idx >= 0 { s = s[..hash_idx]; }

    let prefixes: const u8[:][5] = ["https://", "http://", "wss://", "ws://", "//"];
    for pref in prefixes {
        let rest, ok = s.strip_prefix_fold(pref);
        if ok {
            let slash = rest.index_of_byte('/');
            s = if slash >= 0 { rest[slash..] } else { "/" };
            break;
        }
    }
    return if s.len > 0 { s } else { "/" };
}

// Evaluates Fetch Metadata headers against isolation policy.
// Allows same-origin, direct browser navigation, and safe top-level GET/HEAD navigations.
// Rejects cross-site mutative requests (POST, PUT, DELETE, PATCH) unless origin is trusted or exempt.
fn evaluate_fetch_metadata(guard_cfg: const CrossOriginGuard&, ctx: const FetchContext&) -> CsrfDecision {
    if security_internal::is_path_exempt(guard_cfg, ctx.path[..]) {
        return CsrfDecision.AllowExempt;
    }
    if ctx.site == SecFetchSite.None || ctx.site == SecFetchSite.SameOrigin {
        return CsrfDecision.Allow;
    }
    if ctx.site == SecFetchSite.SameSite {
        return security_internal::evaluate_samesite_fetch(guard_cfg, ctx);
    }
    if ctx.site == SecFetchSite.CrossSite || ctx.site == SecFetchSite.Unknown {
        return security_internal::evaluate_crosssite_fetch(guard_cfg, ctx);
    }
    if ctx.has_origin || ctx.has_referer {
        return security_internal::evaluate_fallback_origin_fetch(guard_cfg, ctx);
    }
    if ctx.has_session_cookie && !ctx.method_is_safe {
        return CsrfDecision.RejectForbidden {
            reason: CsrfRejectReason.MissingBrowserHeadersWithSessionCookie,
        };
    }
    return CsrfDecision.Allow;
}

// Extracts FetchContext from an incoming Request.
//
// Example:
//   req.method = "POST", target_host = "api.example.com"
//   returns: ctx with method = "POST", target_host = "api.example.com"
fn extract_fetch_context<Req>(
    req:              const Req&,
    target_host:      const u8[:]      = "",
    is_sensitive_nav: bool             = false,
    target_scheme:    CsrfTargetScheme = CsrfTargetScheme.Https,
) -> FetchContext {
    var ctx = FetchContext { .. };
    ctx.is_sensitive_navigation_route = is_sensitive_nav;
    let m_len = min(req.method.len, ctx.method.cap);
    let _ = ctx.method.try_set(req.method[..m_len]);

    ctx.method_is_safe = security_internal::is_csrf_safe_method(req.method[..]);
    if target_scheme == CsrfTargetScheme.Http {
        let _ = ctx.target_scheme.try_set("http");
    }
    if !ctx.target_host.try_set(target_host) {
        ctx.target_host.clear();
    }

    let req_path = extract_path_from_url(req.url[..]);
    if !server::canonicalize_route_path(req_path, ctx.path) {
        ctx.path.clear();
    }

    var seen = security_internal::SecFetchHeaderSeen { .. };
    for &e in req.headers.entries {
        let name = req.headers.entry_name(e);
        let val = req.headers.entry_value(e).trim_lws();
        if !security_internal::apply_sec_fetch_site_mode(ctx, name, val, seen) &&
            !security_internal::apply_sec_fetch_dest_user(ctx, name, val, seen) {
            security_internal::apply_auth_and_origin_headers(ctx, name, val);
        }
    }

    return ctx;
}

// Evaluates Fetch Metadata CSRF policy directly against an incoming request.
// Fast-paths safe methods (`GET`, `HEAD`, `OPTIONS`, `QUERY`) when `Sec-Fetch-Site` is not cross-site.
fn evaluate_request_csrf<Req>(
    guard_cfg:        const CrossOriginGuard&,
    req:              const Req&,
    target_host:      const u8[:],
    is_sensitive_nav: bool             = false,
    target_scheme:    CsrfTargetScheme = CsrfTargetScheme.Https,
) -> CsrfDecision {
    if !is_sensitive_nav && guard_cfg.exempt_paths.len == 0 &&
        security_internal::is_csrf_safe_method(req.method[..]) {
        let site = security_internal::scan_request_sec_fetch_site(req);
        if site == SecFetchSite.SameOrigin || site == SecFetchSite.None || site == SecFetchSite.Missing {
            return CsrfDecision.Allow;
        }
    }
    let ctx = extract_fetch_context(req, target_host, is_sensitive_nav, target_scheme);
    return evaluate_fetch_metadata(guard_cfg, ctx);
}

// Injects Vary and HSTS headers on protected responses to prevent proxy cache desynchronization.
fn apply_isolation_headers<Res>(res: Res&) {
    if res.headers.inline_slots[security_internal::CSRF_VARY_SLOT as i64] == 0xFF {
        if !security_internal::append_known_isolation_header(
            res.headers,
            rfc::HEADER_VARY,
            rfc::FETCH_METADATA_VARY_VALUE,
            security_internal::CSRF_VARY_SLOT,
            http::HEADER_FLAG_CONTAINS_COMMA,
            rfc::HASH_HDR_VARY,
            true,
        ) {
            res.set_header(rfc::HEADER_VARY, rfc::FETCH_METADATA_VARY_VALUE);
        }
    } else {
        security_internal::merge_response_vary_tokens(res.headers, rfc::FETCH_METADATA_VARY_VALUE);
    }

    if res.headers.inline_slots[security_internal::CSRF_HSTS_SLOT as i64] == 0xFF {
        if !security_internal::append_known_isolation_header(
            res.headers,
            rfc::HEADER_STRICT_TRANSPORT_SECURITY,
            rfc::HSTS_DEFAULT_VALUE,
            security_internal::CSRF_HSTS_SLOT,
            http::HEADER_FLAG_SECURITY_STATE,
            rfc::HASH_HDR_STRICT_TRANSPORT_SECURITY,
            false,
        ) {
            res.set_header(rfc::HEADER_STRICT_TRANSPORT_SECURITY, rfc::HSTS_DEFAULT_VALUE);
        }
    }
}
