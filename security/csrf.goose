// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Fetch Metadata resource isolation and cross-origin request protection.
namespace wing;

import std;
import core from "..";

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

// Parses Sec-Fetch-Site string value.
//
// Example:
//   val = "same-origin"
//   returns: SecFetchSite.SameOrigin
fn parse_sec_fetch_site(val: const u8[:]) -> SecFetchSite {
    let clean = trim_lws(val);
    if clean.len == 0 { return SecFetchSite.Missing; }
    if core::eq_ascii_fold(clean, "same-origin") { return SecFetchSite.SameOrigin; }
    if core::eq_ascii_fold(clean, "same-site") { return SecFetchSite.SameSite; }
    if core::eq_ascii_fold(clean, "cross-site") { return SecFetchSite.CrossSite; }
    if core::eq_ascii_fold(clean, "none") { return SecFetchSite.None; }
    return SecFetchSite.Unknown;
}

// Parses Sec-Fetch-Mode string value.
//
// Example:
//   val = "navigate"
//   returns: SecFetchMode.Navigate
fn parse_sec_fetch_mode(val: const u8[:]) -> SecFetchMode {
    let clean = trim_lws(val);
    if core::eq_ascii_fold(clean, "navigate") { return SecFetchMode.Navigate; }
    if core::eq_ascii_fold(clean, "same-origin") { return SecFetchMode.SameOrigin; }
    if core::eq_ascii_fold(clean, "cors") { return SecFetchMode.Cors; }
    if core::eq_ascii_fold(clean, "no-cors") { return SecFetchMode.NoCors; }
    if core::eq_ascii_fold(clean, "websocket") { return SecFetchMode.WebSocket; }
    return SecFetchMode.Other;
}

// Parses Sec-Fetch-Dest string value.
//
// Example:
//   val = "document"
//   returns: SecFetchDest.Document
fn parse_sec_fetch_dest(val: const u8[:]) -> SecFetchDest {
    let clean = trim_lws(val);
    if core::eq_ascii_fold(clean, "document") { return SecFetchDest.Document; }
    if core::eq_ascii_fold(clean, "nested-document") { return SecFetchDest.NestedDocument; }
    if core::eq_ascii_fold(clean, "iframe") { return SecFetchDest.Iframe; }
    if core::eq_ascii_fold(clean, "frame") { return SecFetchDest.Frame; }
    if core::eq_ascii_fold(clean, "embed") { return SecFetchDest.Embed; }
    if core::eq_ascii_fold(clean, "object") { return SecFetchDest.Object; }
    if core::eq_ascii_fold(clean, "script") { return SecFetchDest.Script; }
    if core::eq_ascii_fold(clean, "image") { return SecFetchDest.Image; }
    if core::eq_ascii_fold(clean, "style") { return SecFetchDest.Style; }
    if core::eq_ascii_fold(clean, "font") { return SecFetchDest.Font; }
    if core::eq_ascii_fold(clean, "empty") { return SecFetchDest.Empty; }
    return SecFetchDest.Other;
}

fn is_embedding_dest(dest: SecFetchDest) -> bool {
    return dest == SecFetchDest.Iframe || dest == SecFetchDest.Frame ||
           dest == SecFetchDest.Object || dest == SecFetchDest.Embed ||
           dest == SecFetchDest.Script;
}

fn is_static_asset_dest(dest: SecFetchDest) -> bool {
    return dest == SecFetchDest.Image || dest == SecFetchDest.Style || dest == SecFetchDest.Font;
}

fn csrf_reject_reason_to_string(reason: CsrfRejectReason) -> const u8[:] {
    return match reason {
        CrossSiteStateMutation => "CrossSiteStateMutation",
        DisallowedSameSiteSubdomain => "DisallowedSameSiteSubdomain",
        CrossSiteFramingOrXssi => "CrossSiteFramingOrXssi",
        CrossSiteUnauthorizedSubresource => "CrossSiteUnauthorizedSubresource",
        OriginHostMismatch => "OriginHostMismatch",
        MissingBrowserHeadersWithSessionCookie => "MissingBrowserHeadersWithSessionCookie",
        MissingUserActivationOnSensitiveNav => "MissingUserActivationOnSensitiveNav",
    };
}

fn is_allowed(decision: const CsrfDecision&) -> bool {
    return match decision {
        Allow => true,
        AllowExempt => true,
        RejectForbidden _ => false,
    };
}

// ---- crossoriginguard policy & state machine -------------------------------

struct CrossOriginGuard {
    allow_same_site:                          bool            = false,
    require_user_activation_on_sensitive_nav: bool            = true,
    allow_cross_site_static_assets:           bool            = true,
    trusted_origins:                          u8[..128][..16] = [],
    exempt_paths:                             u8[..128][..16] = [],
}

fn add_trusted_origin(guard_cfg: CrossOriginGuard&, origin_str: const u8[:]) -> bool {
    guard guard_cfg.trusted_origins.len < guard_cfg.trusted_origins.cap else { return false; }
    guard origin_str.len <= 128 else { return false; }
    var entry: u8[..128] = [];
    entry.append(origin_str);
    guard_cfg.trusted_origins.push(entry);
    return true;
}

fn add_exempt_path(guard_cfg: CrossOriginGuard&, path_str: const u8[:]) -> bool {
    guard guard_cfg.exempt_paths.len < guard_cfg.exempt_paths.cap else { return false; }
    guard path_str.len <= 128 else { return false; }
    var entry: u8[..128] = [];
    entry.append(path_str);
    guard_cfg.exempt_paths.push(entry);
    return true;
}

fn is_path_exempt(guard_cfg: const CrossOriginGuard&, path_str: const u8[:]) -> bool {
    for &p in guard_cfg.exempt_paths {
        if p[..] == path_str {
            return true;
        }
    }
    return false;
}

// Branchless constant-time case-insensitive ASCII comparison.
fn subtle_equal_ascii_fold(a: const u8[:], b: const u8[:]) -> bool {
    guard a.len == b.len else { return false; }
    var diff: u32 = 0;
    for i in a.len {
        let ca = if a[i] >= 'A' && a[i] <= 'Z' { a[i] + 32 } else { a[i] };
        let cb = if b[i] >= 'A' && b[i] <= 'Z' { b[i] + 32 } else { b[i] };
        diff |= (ca ^ cb);
    }
    let non_zero = (diff | (0 - diff)) >> 31;
    return non_zero == 0;
}

// Constant-time double-submit CSRF token validation.
fn validate_csrf_token(cookie_token: const u8[:], request_token: const u8[:]) -> bool {
    guard cookie_token.len > 0 && request_token.len > 0 else { return false; }
    return core::ct_eq_bytes(cookie_token, request_token);
}

// Masks a CSRF token using a one-time pad XOR mask into out: [mask (N bytes) | masked_secret (N bytes)].
fn mask_csrf_token<B>(mask: const u8[:], raw_secret: const u8[:], out: B&) -> bool {
    guard mask.len > 0 && mask.len == raw_secret.len else { return false; }
    guard (mask.len * 2) <= out.cap else { return false; }
    out.clear();
    for b in mask { out.push(b); }
    for i in mask.len { out.push(raw_secret[i] ^ mask[i]); }
    return true;
}

// Unmasks and validates a masked CSRF token against expected raw secret in constant time.
fn verify_masked_csrf_token(masked_token: const u8[:], expected_unmasked: const u8[:]) -> bool {
    let n = expected_unmasked.len;
    guard n > 0 && masked_token.len == n * 2 else { return false; }
    var diff: u32 = 0;
    for i in n {
        let mask_byte = masked_token[i];
        let masked_secret_byte = masked_token[n + i];
        let unmasked_byte = masked_secret_byte ^ mask_byte;
        diff |= (unmasked_byte ^ expected_unmasked[i]);
    }
    let non_zero = (diff | (0 - diff)) >> 31;
    return non_zero == 0;
}

fn is_origin_trusted(guard_cfg: const CrossOriginGuard&, origin_str: const u8[:]) -> bool {
    guard origin_str.len > 0 else { return false; }
    for &orig in guard_cfg.trusted_origins {
        if subtle_equal_ascii_fold(orig[..], origin_str) {
            return true;
        }
    }
    return false;
}

// Extracts scheme + authority origin prefix from a URL or Origin string (RFC 6454 §4).
// Returns empty slice for opaque ("null") or malformed URLs.
//
// Example:
//   url_or_origin = "https://partner.example.com/checkout?id=1"
//   returns: "https://partner.example.com"
fn extract_origin_from_url(url_or_origin: const u8[:]) -> const u8[:] {
    let s = trim_lws(url_or_origin);
    var scheme_len: i64 = 0;
    if starts_with_fold(s, "https://") {
        scheme_len = 8;
    } else if starts_with_fold(s, "http://") {
        scheme_len = 7;
    } else {
        return s[..0];
    }
    let rest = s[scheme_len..];
    var end_idx = rest.len;
    let slash_idx = core::index_of_byte(rest, '/');
    if slash_idx >= 0 && slash_idx < end_idx { end_idx = slash_idx; }
    let query_idx = core::index_of_byte(rest, '?');
    if query_idx >= 0 && query_idx < end_idx { end_idx = query_idx; }
    let hash_idx = core::index_of_byte(rest, '#');
    if hash_idx >= 0 && hash_idx < end_idx { end_idx = hash_idx; }

    let host = rest[..end_idx];
    if host.len == 0 || core::contains_byte(host, '@') || core::contains_byte(host, '\\') {
        return s[..0];
    }
    return s[..scheme_len + end_idx];
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
    if starts_with_fold(origin, "https://") {
        return origin[8..];
    }
    return origin[7..];
}

fn evaluate_samesite_fetch(guard_cfg: const CrossOriginGuard&, ctx: const FetchContext&) -> CsrfDecision {
    if ctx.method_is_safe {
        return CsrfDecision.Allow;
    }
    if guard_cfg.allow_same_site || (ctx.has_origin && is_origin_trusted(guard_cfg, ctx.origin[..])) {
        return CsrfDecision.Allow;
    }
    return CsrfDecision.RejectForbidden { reason: CsrfRejectReason.DisallowedSameSiteSubdomain };
}

fn evaluate_crosssite_fetch(guard_cfg: const CrossOriginGuard&, ctx: const FetchContext&) -> CsrfDecision {
    // Unsafe state mutations across sites are unconditionally blocked
    if !ctx.method_is_safe {
        if ctx.has_origin && is_origin_trusted(guard_cfg, ctx.origin[..]) {
            return CsrfDecision.Allow;
        }
        return CsrfDecision.RejectForbidden { reason: CsrfRejectReason.CrossSiteStateMutation };
    }

    // Top-level navigation (GET / HEAD)
    let is_doc_nav = ctx.dest == SecFetchDest.Document || ctx.dest == SecFetchDest.NestedDocument;
    if ctx.mode == SecFetchMode.Navigate && is_doc_nav {
        if ctx.is_sensitive_navigation_route && guard_cfg.require_user_activation_on_sensitive_nav &&
            !ctx.user_activated {
            return CsrfDecision.RejectForbidden { reason: CsrfRejectReason.MissingUserActivationOnSensitiveNav };
        }
        return CsrfDecision.Allow;
    }

    // Cross-site embedding into frame/object/embed/script -> block XS-Leaks / XSSI
    if is_embedding_dest(ctx.dest) {
        return CsrfDecision.RejectForbidden { reason: CsrfRejectReason.CrossSiteFramingOrXssi };
    }

    // Cross-site subresources
    if guard_cfg.allow_cross_site_static_assets && is_static_asset_dest(ctx.dest) {
        return CsrfDecision.Allow;
    }

    return CsrfDecision.RejectForbidden { reason: CsrfRejectReason.CrossSiteUnauthorizedSubresource };
}

fn evaluate_fallback_origin_fetch(guard_cfg: const CrossOriginGuard&, ctx: const FetchContext&) -> CsrfDecision {
    let candidate = if ctx.has_origin { ctx.origin[..] } else { ctx.referer[..] };
    let candidate_origin = extract_origin_from_url(candidate);
    let candidate_host = extract_host_from_url(candidate);
    let cand_scheme = if starts_with_fold(candidate_origin, "https://") {
        "https"
    } else if starts_with_fold(candidate_origin, "http://") {
        "http"
    } else {
        ""
    };
    let scheme_ok = ctx.target_scheme.len == 0 || subtle_equal_ascii_fold(cand_scheme, ctx.target_scheme[..]);

    if candidate_host.len > 0 && scheme_ok && subtle_equal_ascii_fold(candidate_host, ctx.target_host[..]) {
        return CsrfDecision.Allow;
    }
    if candidate_origin.len > 0 && is_origin_trusted(guard_cfg, candidate_origin) {
        return CsrfDecision.Allow;
    }
    if !ctx.method_is_safe {
        return CsrfDecision.RejectForbidden { reason: CsrfRejectReason.OriginHostMismatch };
    }
    return CsrfDecision.Allow;
}

// Evaluates Fetch Metadata headers against isolation policy.
// Allows same-origin, direct browser navigation, and safe top-level GET/HEAD navigations.
// Rejects cross-site mutative requests (POST, PUT, DELETE, PATCH) unless origin is trusted or exempt.
fn evaluate_fetch_metadata(guard_cfg: const CrossOriginGuard&, ctx: const FetchContext&) -> CsrfDecision {
    if is_path_exempt(guard_cfg, ctx.path[..]) {
        return CsrfDecision.AllowExempt;
    }

    if ctx.site == SecFetchSite.None || ctx.site == SecFetchSite.SameOrigin {
        return CsrfDecision.Allow;
    }

    if ctx.site == SecFetchSite.SameSite {
        return evaluate_samesite_fetch(guard_cfg, ctx);
    }

    if ctx.site == SecFetchSite.CrossSite || ctx.site == SecFetchSite.Unknown {
        return evaluate_crosssite_fetch(guard_cfg, ctx);
    }

    if ctx.has_origin || ctx.has_referer {
        return evaluate_fallback_origin_fetch(guard_cfg, ctx);
    }

    if ctx.has_session_cookie && !ctx.method_is_safe {
        return CsrfDecision.RejectForbidden { reason: CsrfRejectReason.MissingBrowserHeadersWithSessionCookie };
    }

    return CsrfDecision.Allow;
}

// Extracts normalized path from relative or absolute URL (RFC 3986 §3.3).
// Strips query parameters and fragments before authority removal to prevent query-slash smuggling.
//
// Example:
//   raw = "https://example.com/api/webhook?foo=bar"
//   returns: "/api/webhook"
fn extract_path_from_url(raw: const u8[:]) -> const u8[:] {
    var s = trim_lws(raw);
    let query_idx = core::index_of_byte(s, '?');
    if query_idx >= 0 { s = s[..query_idx]; }
    let hash_idx = core::index_of_byte(s, '#');
    if hash_idx >= 0 { s = s[..hash_idx]; }

    if starts_with_fold(s, "https://") {
        s = s[8..];
        let slash = core::index_of_byte(s, '/');
        s = if slash >= 0 { s[slash..] } else { "/" };
    } else if starts_with_fold(s, "http://") {
        s = s[7..];
        let slash = core::index_of_byte(s, '/');
        s = if slash >= 0 { s[slash..] } else { "/" };
    }
    return if s.len > 0 { s } else { "/" };
}

// Extracts FetchContext from an incoming Request.
//
// Example:
//   req.method = "POST", target_host = "api.example.com"
//   returns: ctx with method = "POST", target_host = "api.example.com"
fn extract_fetch_context<Req>(req: const Req&, target_host: const u8[:]) -> FetchContext {
    var ctx = FetchContext { .. };
    ctx.method.clear();
    let m_len = min(req.method.len, ctx.method.cap);
    ctx.method.append(req.method[..m_len]);

    // RFC 9110 Section 9.2.1 & RFC 10008 Section 2: safe methods
    let m = req.method[..];
    ctx.method_is_safe = (m == "GET" || m == "HEAD" || m == "OPTIONS" || m == "QUERY");
    if starts_with_fold(req.url[..], "http://") {
        ctx.target_scheme.clear();
        ctx.target_scheme.append("http");
    }
    ctx.target_host.clear();
    let th_len = min(target_host.len, ctx.target_host.cap);
    ctx.target_host.append(target_host[..th_len]);

    let req_path = extract_path_from_url(req.url[..]);
    ctx.path.try_set(req_path);

    for &h in req.headers {
        let name = h.name[..];
        let val = trim_lws(h.value[..]);

        if core::eq_ascii_fold(name, "Sec-Fetch-Site") {
            let parsed_site = parse_sec_fetch_site(val);
            if ctx.site == SecFetchSite.Missing {
                ctx.site = parsed_site;
            } else if parsed_site != ctx.site {
                ctx.site = SecFetchSite.CrossSite;
            }
        } else if core::eq_ascii_fold(name, "Sec-Fetch-Mode") {
            ctx.mode = parse_sec_fetch_mode(val);
        } else if core::eq_ascii_fold(name, "Sec-Fetch-Dest") {
            ctx.dest = parse_sec_fetch_dest(val);
        } else if core::eq_ascii_fold(name, "Sec-Fetch-User") {
            ctx.user_activated = (val == "?1");
        } else if core::eq_ascii_fold(name, "Origin") {
            if !ctx.has_origin {
                ctx.has_origin = true;
                ctx.origin.try_set(val);
            }
        } else if core::eq_ascii_fold(name, "Referer") {
            if !ctx.has_referer {
                ctx.has_referer = true;
                ctx.referer.try_set(val);
            }
        } else if core::eq_ascii_fold(name, "Cookie") {
            ctx.has_session_cookie = true;
        } else if core::eq_ascii_fold(name, "Authorization") || core::eq_ascii_fold(name, "X-API-Key") {
            ctx.has_explicit_auth = true;
        }
    }

    return ctx;
}

// Injects Vary and HSTS headers on protected responses to prevent proxy cache desynchronization.
fn apply_isolation_headers<Res>(res: Res&) {
    let vary_key = "Vary";
    let vary_val = "Sec-Fetch-Dest, Sec-Fetch-Mode, Sec-Fetch-Site, Origin";

    let existing_vary = res.headers.find_header(vary_key);
    if existing_vary.len > 0 {
        if !header_list_has_token(existing_vary, "Sec-Fetch-Site") &&
            existing_vary.len + 2 + vary_val.len <= 2048 {
            var merged: u8[..2048] = [];
            merged.append(existing_vary);
            merged.append(", ");
            merged.append(vary_val);
            set_header(res, vary_key, merged[..]);
        }
    } else {
        set_header(res, vary_key, vary_val);
    }

    if !has_header(res, "Strict-Transport-Security") {
        set_header(res, "Strict-Transport-Security", "max-age=63072000; includeSubDomains; preload");
    }
}
