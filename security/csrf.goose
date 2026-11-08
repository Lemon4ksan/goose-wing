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
    let clean = val.trim_lws();
    if clean.len == 0 { return SecFetchSite.Missing; }
    if clean.eq_ascii_fold(rfc::SEC_FETCH_SITE_SAME_ORIGIN) { return SecFetchSite.SameOrigin; }
    if clean.eq_ascii_fold(rfc::SEC_FETCH_SITE_SAME_SITE) { return SecFetchSite.SameSite; }
    if clean.eq_ascii_fold(rfc::SEC_FETCH_SITE_CROSS_SITE) { return SecFetchSite.CrossSite; }
    if clean.eq_ascii_fold(rfc::SEC_FETCH_SITE_NONE) { return SecFetchSite.None; }
    return SecFetchSite.Unknown;
}

// Parses Sec-Fetch-Mode string value.
//
// Example:
//   val = "navigate"
//   returns: SecFetchMode.Navigate
fn parse_sec_fetch_mode(val: const u8[:]) -> SecFetchMode {
    let clean = val.trim_lws();
    if clean.eq_ascii_fold(rfc::SEC_FETCH_MODE_NAVIGATE) { return SecFetchMode.Navigate; }
    if clean.eq_ascii_fold(rfc::SEC_FETCH_MODE_SAME_ORIGIN) { return SecFetchMode.SameOrigin; }
    if clean.eq_ascii_fold(rfc::SEC_FETCH_MODE_CORS) { return SecFetchMode.Cors; }
    if clean.eq_ascii_fold(rfc::SEC_FETCH_MODE_NO_CORS) { return SecFetchMode.NoCors; }
    if clean.eq_ascii_fold(rfc::SEC_FETCH_MODE_WEBSOCKET) { return SecFetchMode.WebSocket; }
    return SecFetchMode.Other;
}

// Parses Sec-Fetch-Dest string value.
//
// Example:
//   val = "document"
//   returns: SecFetchDest.Document
fn parse_sec_fetch_dest(val: const u8[:]) -> SecFetchDest {
    let clean = val.trim_lws();
    if clean.eq_ascii_fold("document") { return SecFetchDest.Document; }
    if clean.eq_ascii_fold("nested-document") { return SecFetchDest.NestedDocument; }
    if clean.eq_ascii_fold("iframe") { return SecFetchDest.Iframe; }
    if clean.eq_ascii_fold("frame") { return SecFetchDest.Frame; }
    if clean.eq_ascii_fold("embed") { return SecFetchDest.Embed; }
    if clean.eq_ascii_fold("object") { return SecFetchDest.Object; }
    if clean.eq_ascii_fold("script") { return SecFetchDest.Script; }
    if clean.eq_ascii_fold("image") { return SecFetchDest.Image; }
    if clean.eq_ascii_fold("style") { return SecFetchDest.Style; }
    if clean.eq_ascii_fold("font") { return SecFetchDest.Font; }
    if clean.eq_ascii_fold("empty") { return SecFetchDest.Empty; }
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

fn is_path_exempt(guard_cfg: const CrossOriginGuard&, path_str: const u8[:]) -> bool {
    guard path_str.len > 0 else { return false; }
    for &p in guard_cfg.exempt_paths {
        let prefix = p[..];
        guard prefix.len > 0 && core::starts_with(path_str, prefix) else { continue; }
        let plen = prefix.len;
        if path_str.len == plen { return true; }
        if core::ends_with(prefix, "/") { return true; }
        if path_str[plen] == '/' { return true; }
    }
    return false;
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

    let host = rest[..end_idx];
    if host.len == 0 || host.contains_byte('@') || host.contains_byte('\\') {
        return s[..0];
    }
    return s[..core::add_sat_i64(scheme_len, end_idx)];
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
    if ctx.has_origin && is_origin_trusted(guard_cfg, ctx.origin[..]) {
        return CsrfDecision.Allow;
    }

    // Unsafe state mutations across sites are unconditionally blocked
    if !ctx.method_is_safe {
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
    let cand_scheme = if candidate_origin.starts_with_fold("https://") {
        "https"
    } else if candidate_origin.starts_with_fold("http://") {
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
    var s = raw.trim_lws();
    let query_idx = s.index_of_byte('?');
    if query_idx >= 0 { s = s[..query_idx]; }
    let hash_idx = s.index_of_byte('#');
    if hash_idx >= 0 { s = s[..hash_idx]; }

    if s.starts_with_fold("https://") {
        s = s[8..];
        let slash = s.index_of_byte('/');
        s = if slash >= 0 { s[slash..] } else { "/" };
    } else if s.starts_with_fold("http://") {
        s = s[7..];
        let slash = s.index_of_byte('/');
        s = if slash >= 0 { s[slash..] } else { "/" };
    }
    return if s.len > 0 { s } else { "/" };
}

// Extracts FetchContext from an incoming Request.
//
// Example:
//   req.method = "POST", target_host = "api.example.com"
//   returns: ctx with method = "POST", target_host = "api.example.com"
fn extract_fetch_context<Req>(
    req:              const Req&,
    target_host:      const u8[:],
    is_sensitive_nav: bool = false,
) -> FetchContext {
    var ctx = FetchContext { .. };
    ctx.is_sensitive_navigation_route = is_sensitive_nav;
    let m_len = min(req.method.len, ctx.method.cap);
    ctx.method.try_set(req.method[..m_len]);

    // RFC 9110 Section 9.2.1 & RFC 10008 Section 2: safe methods
    let m = req.method[..];
    ctx.method_is_safe = (m == "GET" || m == "HEAD" || m == "OPTIONS" || m == "QUERY");
    if req.url[..].starts_with_fold("http://") {
        ctx.target_scheme.try_set("http");
    }
    let th_len = min(target_host.len, ctx.target_host.cap);
    ctx.target_host.try_set(target_host[..th_len]);

    let req_path = extract_path_from_url(req.url[..]);
    if !canonicalize_route_path(req_path, ctx.path) {
        ctx.path.clear();
    }

    for &e in req.headers.entries {
        let name = entry_name(req.headers, e);
        let val = entry_value(req.headers, e).trim_lws();

        if name.eq_ascii_fold(rfc::HEADER_SEC_FETCH_SITE) {
            let parsed_site = parse_sec_fetch_site(val);
            if ctx.site == SecFetchSite.Missing {
                ctx.site = parsed_site;
            } else if parsed_site != ctx.site {
                ctx.site = SecFetchSite.CrossSite;
            }
        } else if name.eq_ascii_fold(rfc::HEADER_SEC_FETCH_MODE) {
            ctx.mode = parse_sec_fetch_mode(val);
        } else if name.eq_ascii_fold(rfc::HEADER_SEC_FETCH_DEST) {
            ctx.dest = parse_sec_fetch_dest(val);
        } else if name.eq_ascii_fold(rfc::HEADER_SEC_FETCH_USER) {
            ctx.user_activated = (val == "?1");
        } else if name.eq_ascii_fold(rfc::HEADER_ORIGIN) {
            if !ctx.has_origin {
                ctx.has_origin = true;
                ctx.origin.try_set(val);
            }
        } else if name.eq_ascii_fold(rfc::HEADER_REFERER) {
            if !ctx.has_referer {
                ctx.has_referer = true;
                ctx.referer.try_set(val);
            }
        } else if name.eq_ascii_fold(rfc::HEADER_COOKIE) {
            ctx.has_session_cookie = true;
        } else if name.eq_ascii_fold(rfc::HEADER_AUTHORIZATION) || name.eq_ascii_fold("X-API-Key") {
            ctx.has_explicit_auth = true;
        }
    }

    return ctx;
}

const CSRF_VARY_SLOT: u8 = 34;
const CSRF_HSTS_SLOT: u8 = 46;

// RFC 9110 §9.2.1 & RFC 10008 §2: safe HTTP methods.
inline fn is_csrf_safe_method(m: const u8[:]) -> bool {
    return m == rfc::METHOD_GET || m == rfc::METHOD_HEAD || m == rfc::METHOD_OPTIONS || m == rfc::METHOD_QUERY;
}

// Scans request headers for `Sec-Fetch-Site` without materializing `FetchContext`.
// Returns `SecFetchSite.Missing` when absent, or `SecFetchSite.CrossSite` on conflicting duplicates.
//
// Example:
//   req with header "Sec-Fetch-Site: same-origin"
//   returns: SecFetchSite.SameOrigin
fn scan_request_sec_fetch_site<Req>(req: const Req&) -> SecFetchSite {
    var site = SecFetchSite.Missing;
    for &e in req.headers.entries {
        guard e.well_known_id == 0xFF else { continue; }
        let name = entry_name(req.headers, e);
        guard name.len == 14 && name.eq_ascii_fold(rfc::HEADER_SEC_FETCH_SITE) else { continue; }
        let parsed = parse_sec_fetch_site(entry_value(req.headers, e).trim_lws());
        if site == SecFetchSite.Missing {
            site = parsed;
        } else if parsed != site {
            site = SecFetchSite.CrossSite;
        }
    }
    return site;
}

// Evaluates Fetch Metadata CSRF policy directly against an incoming request.
// Fast-paths safe methods (`GET`, `HEAD`, `OPTIONS`, `QUERY`) when `Sec-Fetch-Site` is not cross-site.
fn evaluate_request_csrf<Req>(
    guard_cfg:        const CrossOriginGuard&,
    req:              const Req&,
    target_host:      const u8[:],
    is_sensitive_nav: bool = false,
) -> CsrfDecision {
    if guard_cfg.exempt_paths.len == 0 && is_csrf_safe_method(req.method[..]) {
        let site = scan_request_sec_fetch_site(req);
        if site != SecFetchSite.CrossSite && site != SecFetchSite.Unknown {
            return CsrfDecision.Allow;
        }
    }
    let ctx = extract_fetch_context(req, target_host, is_sensitive_nav);
    return evaluate_fetch_metadata(guard_cfg, ctx);
}

fn append_known_isolation_header(
    map:            HeaderMap&,
    name:           const u8[:],
    val:            const u8[:],
    slot:           u8,
    flags:          u8,
    hname:          u32,
    contains_comma: bool,
) -> bool {
    let needed = core::add_sat_i64(name.len, val.len);
    guard map.entries.len < 128 && core::add_sat_i64(map.raw_buf.len, needed) <= 8192 else {
        return false;
    }
    let n_begin = map.raw_buf.len as u16;
    map.raw_buf.append(name);
    let n_end = map.raw_buf.len as u16;
    map.raw_buf.append(val);
    let v_end = map.raw_buf.len as u16;
    let new_idx = map.entries.len as u8;
    map.inline_slots[slot as i64] = new_idx;
    map.entries.push(HeaderEntry {
        name_begin:    n_begin,
        name_end:      n_end,
        values_begin:  n_end,
        values_end:    v_end,
        next_idx:      0xFF,
        flags:         flags,
        well_known_id: slot,
        reserved:      0,
        name_hash:     hname,
    });
    map.header_contains_comma.push(contains_comma);
    return true;
}

// Injects Vary and HSTS headers on protected responses to prevent proxy cache desynchronization.
fn apply_isolation_headers<Res>(res: Res&) {
    if res.headers.inline_slots[CSRF_VARY_SLOT as i64] == 0xFF {
        if !append_known_isolation_header(
            res.headers,
            rfc::HEADER_VARY,
            rfc::FETCH_METADATA_VARY_VALUE,
            CSRF_VARY_SLOT,
            HEADER_FLAG_CONTAINS_COMMA,
            rfc::HASH_HDR_VARY,
            true,
        ) {
            set_header(res, rfc::HEADER_VARY, rfc::FETCH_METADATA_VARY_VALUE);
        }
    } else {
        let existing_vary = res.headers.find_header(rfc::HEADER_VARY);
        if existing_vary != rfc::FETCH_METADATA_VARY_VALUE &&
            !header_list_has_token(existing_vary, rfc::HEADER_SEC_FETCH_SITE) {
            var merged: u8[..2048] = [];
            if merged.try_set(existing_vary) &&
                merged.try_append(", ") &&
                merged.try_append(rfc::FETCH_METADATA_VARY_VALUE) {
                set_header(res, rfc::HEADER_VARY, merged[..]);
            }
        }
    }

    if res.headers.inline_slots[CSRF_HSTS_SLOT as i64] == 0xFF {
        if !append_known_isolation_header(
            res.headers,
            rfc::HEADER_STRICT_TRANSPORT_SECURITY,
            rfc::HSTS_DEFAULT_VALUE,
            CSRF_HSTS_SLOT,
            HEADER_FLAG_SECURITY_STATE,
            rfc::HASH_HDR_STRICT_TRANSPORT_SECURITY,
            false,
        ) {
            set_header(res, rfc::HEADER_STRICT_TRANSPORT_SECURITY, rfc::HSTS_DEFAULT_VALUE);
        }
    }
}
