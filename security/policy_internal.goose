// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Internal helpers for CORS, Cross-Origin Isolation, CSRF Fetch Metadata, and SSRF validation.
namespace security_internal;

import std;
import core;
import rfc.http;

// ---- CORS internal helpers -------------------------------------------------

// Validates characters in a CORS subdomain label sequence (RFC 1035 / WHATWG Fetch §3.2).
//
// Example:
//   sub = "stage.app"
//   returns: true
inline fn validate_cors_subdomain(sub: const u8[:]) -> bool {
    var prev_dot = false;
    let last_idx = core::sub_sat_i64(sub.len, 1);
    for i in sub.len {
        let b = sub[i];
        if b == '.' {
            if prev_dot || i == 0 || i == last_idx { return false; }
            prev_dot = true;
        } else if b == '-' {
            if prev_dot || i == 0 || i == last_idx { return false; }
            let next_idx = core::add_sat_i64(i, 1);
            if next_idx < sub.len && sub[next_idx] == '.' { return false; }
            prev_dot = false;
        } else if core::is_ascii_alphanumeric(b) {
            prev_dot = false;
        } else {
            return false;
        }
    }
    return true;
}

// Verifies whether candidate host matches wildcard domain suffix "*.domain.tld".
//
// Example:
//   cand_rest = "api.example.com", pat_rest = "*.example.com"
//   returns: true
inline fn match_cors_wildcard_host(cand_rest: const u8[:], pat_rest: const u8[:]) -> bool {
    guard pat_rest.starts_with_fold("*.") else { return false; }
    let domain_suffix = pat_rest[2..];
    guard domain_suffix.contains_byte('.') else { return false; }
    guard cand_rest.len > domain_suffix.len && cand_rest.ends_with_fold(domain_suffix) else { return false; }
    let prefix_len = core::sub_sat_i64(cand_rest.len, domain_suffix.len);
    let dot_idx = core::sub_sat_i64(prefix_len, 1);
    guard dot_idx > 0 && cand_rest[dot_idx] == '.' else { return false; }

    let sub = cand_rest[..dot_idx];
    return validate_cors_subdomain(sub);
}

fn has_wildcard_origin(policy: const security::CorsPolicy&) -> bool {
    guard policy.allowed_origins.len > 0 else { return false; }
    for &orig in policy.allowed_origins {
        if orig[..].trim_lws() == "*" {
            return true;
        }
    }
    return false;
}

inline fn is_valid_cors_token(tok: const u8[:]) -> bool {
    guard tok.len > 0 else { return false; }
    for b in tok {
        guard core::is_tchar(b) else { return false; }
    }
    return true;
}

inline fn validate_cors_token_list(list: const u8[:], allow_wildcard: bool) -> bool {
    guard list.trim_lws().len > 0 else { return true; }
    var tok_iter = core::make_byte_tokenizer(list, ',');
    loop {
        let item, ok = core::token_next(tok_iter);
        guard ok else { break; }
        let trimmed = item.trim_lws();
        if trimmed == "*" {
            guard allow_wildcard else { return false; }
            continue;
        }
        guard !trimmed.contains_byte('*') && is_valid_cors_token(trimmed) else { return false; }
    }
    return true;
}

inline fn header_list_has_token(
    header_val:     const u8[:],
    token:          const u8[:],
    allow_wildcard: bool = true,
) -> bool {
    var tok_iter = core::make_byte_tokenizer(header_val, ',');
    loop {
        let item, ok = core::token_next(tok_iter);
        guard ok else { break; }
        let trimmed = item.trim_lws();
        if (allow_wildcard && trimmed == "*") || trimmed.eq_ascii_fold(token) {
            return true;
        }
    }
    return false;
}

inline fn headers_vary_has_token<H>(headers: const H&, token: const u8[:]) -> bool {
    for &e in headers.entries {
        guard headers.entry_name(e).eq_ascii_fold(rfc::HEADER_VARY) else { continue; }
        if header_list_has_token(headers.entry_value(e), token) {
            return true;
        }
    }
    return false;
}

inline fn headers_vary_has_all_tokens<H>(headers: const H&, required_list: const u8[:]) -> bool {
    var tok_iter = core::make_byte_tokenizer(required_list, ',');
    loop {
        let item, ok = core::token_next(tok_iter);
        guard ok else { break; }
        let tok = item.trim_lws();
        if tok.len > 0 && !headers_vary_has_token(headers, tok) {
            return false;
        }
    }
    return true;
}

inline fn append_missing_vary_tokens<H>(
    headers:       const H&,
    required_list: const u8[:],
    merged:        u8[..2048]&,
) -> bool {
    var tok_iter = core::make_byte_tokenizer(required_list, ',');
    loop {
        let item, ok = core::token_next(tok_iter);
        guard ok else { break; }
        let tok = item.trim_lws();
        if tok.len == 0 || headers_vary_has_token(headers, tok) {
            continue;
        }
        if merged.len > 0 && !merged.try_append(", ") {
            return false;
        }
        guard merged.try_append(tok) else { return false; }
    }
    return true;
}

// Merges `required_list` tokens across all existing `Vary` header lines (RFC 9110 Section 12.5.5).
// Falls back to `Vary: *` if combined `Vary` value exceeds 2048 bytes.
fn merge_response_vary_tokens<H>(headers: H&, required_list: const u8[:]) {
    if headers_vary_has_all_tokens(headers, required_list) {
        return;
    }
    var merged: u8[..2048] = [];
    for &e in headers.entries {
        guard headers.entry_name(e).eq_ascii_fold(rfc::HEADER_VARY) else { continue; }
        let val = headers.entry_value(e).trim_lws();
        guard val.len > 0 else { continue; }
        if merged.len > 0 && !merged.try_append(", ") {
            headers.set_header(rfc::HEADER_VARY, "*");
            return;
        }
        if !merged.try_append(val) {
            headers.set_header(rfc::HEADER_VARY, "*");
            return;
        }
    }
    if !append_missing_vary_tokens(headers, required_list, merged) {
        headers.set_header(rfc::HEADER_VARY, "*");
        return;
    }
    headers.set_header(rfc::HEADER_VARY, merged[..]);
}

fn apply_cors_preflight_headers<Res>(policy: const security::CorsPolicy&, res: Res&) {
    if policy.allowed_methods.len > 0 {
        res.headers.set_header(rfc::HEADER_ACCESS_CONTROL_ALLOW_METHODS, policy.allowed_methods[..]);
    }
    if policy.allowed_headers.len > 0 {
        res.headers.set_header(rfc::HEADER_ACCESS_CONTROL_ALLOW_HEADERS, policy.allowed_headers[..]);
    }
    if policy.max_age_sec > 0 {
        var age_str: u8[..32] = [];
        policy.max_age_sec.format_i64_dec(age_str);
        res.headers.set_header(rfc::HEADER_ACCESS_CONTROL_MAX_AGE, age_str[..]);
    }
    res.status_code = rfc::STATUS_NO_CONTENT;
}

inline fn find_unique_cors_header<H>(headers: const H&, target_name: const u8[:]) -> const u8[:], bool {
    var val = headers.raw_buf[..0];
    var seen = false;
    for &e in headers.entries {
        guard headers.entry_name(e).eq_ascii_fold(target_name) else { continue; }
        guard !seen else { return headers.raw_buf[..0], false; }
        val = headers.entry_value(e).trim_lws();
        seen = true;
    }
    return val, true;
}

// ---- Cross-Origin Isolation & Structured Field helpers ---------------------

inline fn is_valid_sf_param_key(key: const u8[:]) -> bool {
    guard key.len > 0 else { return false; }
    let first = key[0];
    guard core::is_ascii_lower(first) || first == '*' else { return false; }
    for b in key {
        let ok = core::is_ascii_lower(b) || core::is_ascii_digit(b) ||
            b == '_' || b == '-' || b == '.' || b == '*';
        guard ok else { return false; }
    }
    return true;
}

inline fn is_valid_sf_quoted_val(val: const u8[:]) -> bool {
    guard val.len >= 2 && val[0] == '"' && val[val.len - 1] == '"' else { return false; }
    let inner = val[1..^1];
    var escaped = false;
    for b in inner {
        guard core::is_ascii_printable(b) else { return false; }
        if escaped {
            guard b == '"' || b == '\\' else { return false; }
            escaped = false;
        } else if b == '\\' {
            escaped = true;
        } else if b == '"' {
            return false;
        }
    }
    return !escaped;
}

inline fn is_valid_sf_param_val(val: const u8[:]) -> bool {
    guard val.len > 0 else { return false; }
    if val[0] == '"' {
        return is_valid_sf_quoted_val(val);
    }
    for b in val {
        guard core::is_ascii_vchar(b) && b != '"' && b != ';' && b != ',' else { return false; }
    }
    return true;
}

inline fn is_valid_sf_param_tail(params: const u8[:]) -> bool {
    var rem = params;
    loop {
        let seg, tail, has_more = rem.split_once_unquoted_byte(';');
        let after_sp = seg.trim_start_byte(' ');
        guard after_sp.len > 0 else { return false; }
        let key, val_raw, has_eq = after_sp.split_once_byte('=');
        guard is_valid_sf_param_key(key) else { return false; }
        if has_eq {
            guard is_valid_sf_param_val(val_raw) else { return false; }
        }
        guard has_more else { break; }
        rem = tail;
    }
    return true;
}

// Extracts the primary token before any RFC 8941 structured field parameters (';').
inline fn strip_sf_parameters(val: const u8[:]) -> const u8[:] {
    let trimmed = val.trim_lws();
    guard trimmed.find_unquoted_byte(',') == trimmed.len else { return ";"; }
    let head, params, has_semi = trimmed.split_once_byte(';');
    let clean = head.trim_lws();
    if has_semi && (clean.len == 0 || !is_valid_sf_param_tail(params)) {
        return ";";
    }
    return clean;
}

inline fn wire_token(v: security::CoopPolicy.Unknown) -> const u8[:] { return ""; }
inline fn wire_token(v: security::CoopPolicy.UnsafeNone) -> const u8[:] { return "unsafe-none"; }

inline fn wire_token(v: security::CoopPolicy.SameOriginAllowPopups) -> const u8[:] {
    return "same-origin-allow-popups";
}

inline fn wire_token(v: security::CoopPolicy.SameOrigin) -> const u8[:] { return "same-origin"; }

inline fn wire_token(v: security::CoepPolicy.Unknown) -> const u8[:] { return ""; }
inline fn wire_token(v: security::CoepPolicy.UnsafeNone) -> const u8[:] { return "unsafe-none"; }
inline fn wire_token(v: security::CoepPolicy.Credentialless) -> const u8[:] { return "credentialless"; }
inline fn wire_token(v: security::CoepPolicy.RequireCorp) -> const u8[:] { return "require-corp"; }

inline fn wire_token(v: security::CorpPolicy.Unknown) -> const u8[:] { return ""; }
inline fn wire_token(v: security::CorpPolicy.None) -> const u8[:] { return ""; }
inline fn wire_token(v: security::CorpPolicy.SameOrigin) -> const u8[:] { return "same-origin"; }
inline fn wire_token(v: security::CorpPolicy.SameSite) -> const u8[:] { return "same-site"; }
inline fn wire_token(v: security::CorpPolicy.CrossOrigin) -> const u8[:] { return "cross-origin"; }

inline fn is_valid_origin_port(port_str: const u8[:]) -> bool {
    guard port_str.len > 0 && port_str.len <= 5 else { return false; }
    let port, ok = port_str.parse_u32_dec();
    return ok && port >= 1 && port <= 65535;
}

inline fn is_valid_ipv6_bracket_body(body: const u8[:]) -> bool {
    guard body.len >= 2 && body.contains_byte(':') else { return false; }
    for b in body {
        guard core::is_ascii_hexdigit(b) || b == ':' || b == '.' else { return false; }
    }
    return true;
}

inline fn is_valid_reg_hostname(host: const u8[:]) -> bool {
    guard host.len > 0 && !core::starts_with(host, ".") &&
        !core::ends_with(host, ".") && !core::contains(host, "..") else {
        return false;
    }
    for b in host {
        guard core::is_ascii_alphanumeric(b) || b == '.' || b == '-' || b == '_' else { return false; }
    }
    return true;
}

// ---- CSRF Fetch Metadata internal helpers ----------------------------------

const CSRF_VARY_SLOT: u8 = 34;
const CSRF_HSTS_SLOT: u8 = 46;

struct SecFetchHeaderSeen {
    site: bool = false,
    mode: bool = false,
    dest: bool = false,
    user: bool = false,
}

inline fn wire_token(v: security::SecFetchSite.Unknown) -> const u8[:] { return ""; }
inline fn wire_token(v: security::SecFetchSite.SameOrigin) -> const u8[:] { return rfc::SEC_FETCH_SITE_SAME_ORIGIN; }
inline fn wire_token(v: security::SecFetchSite.SameSite) -> const u8[:] { return rfc::SEC_FETCH_SITE_SAME_SITE; }
inline fn wire_token(v: security::SecFetchSite.CrossSite) -> const u8[:] { return rfc::SEC_FETCH_SITE_CROSS_SITE; }
inline fn wire_token(v: security::SecFetchSite.None) -> const u8[:] { return rfc::SEC_FETCH_SITE_NONE; }
inline fn wire_token(v: security::SecFetchSite.Missing) -> const u8[:] { return ""; }

inline fn wire_token(v: security::SecFetchMode.Navigate) -> const u8[:] { return rfc::SEC_FETCH_MODE_NAVIGATE; }
inline fn wire_token(v: security::SecFetchMode.SameOrigin) -> const u8[:] { return rfc::SEC_FETCH_MODE_SAME_ORIGIN; }
inline fn wire_token(v: security::SecFetchMode.Cors) -> const u8[:] { return rfc::SEC_FETCH_MODE_CORS; }
inline fn wire_token(v: security::SecFetchMode.NoCors) -> const u8[:] { return rfc::SEC_FETCH_MODE_NO_CORS; }
inline fn wire_token(v: security::SecFetchMode.WebSocket) -> const u8[:] { return rfc::SEC_FETCH_MODE_WEBSOCKET; }
inline fn wire_token(v: security::SecFetchMode.Other) -> const u8[:] { return ""; }

inline fn wire_token(v: security::SecFetchDest.Document) -> const u8[:] { return "document"; }
inline fn wire_token(v: security::SecFetchDest.NestedDocument) -> const u8[:] { return "nested-document"; }
inline fn wire_token(v: security::SecFetchDest.Iframe) -> const u8[:] { return "iframe"; }
inline fn wire_token(v: security::SecFetchDest.Frame) -> const u8[:] { return "frame"; }
inline fn wire_token(v: security::SecFetchDest.Embed) -> const u8[:] { return "embed"; }
inline fn wire_token(v: security::SecFetchDest.Object) -> const u8[:] { return "object"; }
inline fn wire_token(v: security::SecFetchDest.Script) -> const u8[:] { return "script"; }
inline fn wire_token(v: security::SecFetchDest.Image) -> const u8[:] { return "image"; }
inline fn wire_token(v: security::SecFetchDest.Style) -> const u8[:] { return "style"; }
inline fn wire_token(v: security::SecFetchDest.Font) -> const u8[:] { return "font"; }
inline fn wire_token(v: security::SecFetchDest.Empty) -> const u8[:] { return "empty"; }
inline fn wire_token(v: security::SecFetchDest.Other) -> const u8[:] { return ""; }

inline fn is_embedding_dest(dest: security::SecFetchDest) -> bool {
    return dest == security::SecFetchDest.Iframe || dest == security::SecFetchDest.Frame ||
        dest == security::SecFetchDest.Object || dest == security::SecFetchDest.Embed ||
        dest == security::SecFetchDest.Script;
}

inline fn is_static_asset_dest(dest: security::SecFetchDest) -> bool {
    return dest == security::SecFetchDest.Image ||
        dest == security::SecFetchDest.Style ||
        dest == security::SecFetchDest.Font;
}

fn is_path_exempt(guard_cfg: const security::CrossOriginGuard&, path_str: const u8[:]) -> bool {
    guard path_str.len > 0 else { return false; }
    for &p in guard_cfg.exempt_paths {
        let prefix = p[..];
        guard prefix.len > 0 && core::starts_with(path_str, prefix) else { continue; }
        let plen = prefix.len;
        if path_str.len == plen || core::ends_with(prefix, "/") || path_str[plen] == '/' {
            return true;
        }
    }
    return false;
}

fn is_origin_trusted(guard_cfg: const security::CrossOriginGuard&, origin_str: const u8[:]) -> bool {
    let trimmed = origin_str.trim_lws();
    guard trimmed.len > 0 else { return false; }
    let norm_cand = security::extract_origin_from_url(trimmed);
    if trimmed.starts_with_fold("https://") || trimmed.starts_with_fold("http://") {
        guard norm_cand.len > 0 else { return false; }
    }
    let cand = if norm_cand.len > 0 { norm_cand } else { trimmed };
    for &orig in guard_cfg.trusted_origins {
        let norm_pat = security::extract_origin_from_url(orig[..]);
        let pat = if norm_pat.len > 0 { norm_pat } else { orig[..] };
        if security::subtle_equal_ascii_fold(pat, cand) {
            return true;
        }
    }
    return false;
}

inline fn strip_default_origin_port(host_port: const u8[:], is_https: bool) -> const u8[:] {
    if is_https {
        let stripped, ok = host_port.strip_suffix(":443");
        if ok { return stripped; }
    } else {
        let stripped, ok = host_port.strip_suffix(":80");
        if ok { return stripped; }
    }
    return host_port;
}

fn evaluate_samesite_fetch(
    guard_cfg: const security::CrossOriginGuard&,
    ctx:       const security::FetchContext&,
) -> security::CsrfDecision {
    if guard_cfg.allow_same_site || (ctx.has_origin && is_origin_trusted(guard_cfg, ctx.origin[..])) {
        return security::CsrfDecision.Allow;
    }
    guard ctx.method_is_safe else {
        return security::CsrfDecision.RejectForbidden {
            reason: security::CsrfRejectReason.DisallowedSameSiteSubdomain,
        };
    }
    if ctx.is_sensitive_navigation_route && guard_cfg.require_user_activation_on_sensitive_nav &&
        !ctx.user_activated {
        return security::CsrfDecision.RejectForbidden {
            reason: security::CsrfRejectReason.MissingUserActivationOnSensitiveNav,
        };
    }
    if is_embedding_dest(ctx.dest) {
        return security::CsrfDecision.RejectForbidden {
            reason: security::CsrfRejectReason.CrossSiteFramingOrXssi,
        };
    }
    return security::CsrfDecision.Allow;
}

fn evaluate_crosssite_fetch(
    guard_cfg: const security::CrossOriginGuard&,
    ctx:       const security::FetchContext&,
) -> security::CsrfDecision {
    if ctx.has_origin && is_origin_trusted(guard_cfg, ctx.origin[..]) {
        return security::CsrfDecision.Allow;
    }
    if !ctx.method_is_safe {
        return security::CsrfDecision.RejectForbidden {
            reason: security::CsrfRejectReason.CrossSiteStateMutation,
        };
    }
    let is_doc_nav = ctx.dest == security::SecFetchDest.Document ||
        ctx.dest == security::SecFetchDest.NestedDocument;
    if ctx.mode == security::SecFetchMode.Navigate && is_doc_nav {
        if ctx.is_sensitive_navigation_route && guard_cfg.require_user_activation_on_sensitive_nav &&
            !ctx.user_activated {
            return security::CsrfDecision.RejectForbidden {
                reason: security::CsrfRejectReason.MissingUserActivationOnSensitiveNav,
            };
        }
        return security::CsrfDecision.Allow;
    }
    if is_embedding_dest(ctx.dest) {
        return security::CsrfDecision.RejectForbidden {
            reason: security::CsrfRejectReason.CrossSiteFramingOrXssi,
        };
    }
    if guard_cfg.allow_cross_site_static_assets && is_static_asset_dest(ctx.dest) {
        return security::CsrfDecision.Allow;
    }
    return security::CsrfDecision.RejectForbidden {
        reason: security::CsrfRejectReason.CrossSiteUnauthorizedSubresource,
    };
}

fn evaluate_fallback_origin_fetch(
    guard_cfg: const security::CrossOriginGuard&,
    ctx:       const security::FetchContext&,
) -> security::CsrfDecision {
    let candidate = if ctx.has_origin { ctx.origin[..] } else { ctx.referer[..] };
    let candidate_origin = security::extract_origin_from_url(candidate);
    let candidate_host = security::extract_host_from_url(candidate);
    let cand_scheme = if candidate_origin.starts_with_fold("https://") {
        "https"
    } else if candidate_origin.starts_with_fold("http://") {
        "http"
    } else {
        ""
    };
    let scheme_ok = ctx.target_scheme.len == 0 ||
        security::subtle_equal_ascii_fold(cand_scheme, ctx.target_scheme[..]);
    let is_https = cand_scheme == "https";
    let norm_cand_host = strip_default_origin_port(candidate_host, is_https);
    let norm_target_host = strip_default_origin_port(ctx.target_host[..], is_https);

    if norm_cand_host.len > 0 && scheme_ok && security::subtle_equal_ascii_fold(norm_cand_host, norm_target_host) {
        return security::CsrfDecision.Allow;
    }
    if candidate_origin.len > 0 && is_origin_trusted(guard_cfg, candidate_origin) {
        return security::CsrfDecision.Allow;
    }
    if !ctx.method_is_safe {
        return security::CsrfDecision.RejectForbidden {
            reason: security::CsrfRejectReason.OriginHostMismatch,
        };
    }
    return security::CsrfDecision.Allow;
}

inline fn apply_sec_fetch_site_mode(
    ctx:  security::FetchContext&,
    name: const u8[:],
    val:  const u8[:],
    seen: SecFetchHeaderSeen&,
) -> bool {
    if name.eq_ascii_fold(rfc::HEADER_SEC_FETCH_SITE) {
        let parsed_site = security::parse_sec_fetch_site(val);
        if !seen.site {
            ctx.site = parsed_site;
            seen.site = true;
        } else {
            ctx.site = security::SecFetchSite.CrossSite;
        }
        return true;
    }
    if name.eq_ascii_fold(rfc::HEADER_SEC_FETCH_MODE) {
        let parsed_mode = security::parse_sec_fetch_mode(val);
        if !seen.mode {
            ctx.mode = parsed_mode;
            seen.mode = true;
        } else {
            ctx.mode = security::SecFetchMode.Other;
        }
        return true;
    }
    return false;
}

inline fn apply_sec_fetch_dest_user(
    ctx:  security::FetchContext&,
    name: const u8[:],
    val:  const u8[:],
    seen: SecFetchHeaderSeen&,
) -> bool {
    if name.eq_ascii_fold(rfc::HEADER_SEC_FETCH_DEST) {
        let parsed_dest = security::parse_sec_fetch_dest(val);
        if !seen.dest {
            ctx.dest = parsed_dest;
            seen.dest = true;
        } else {
            ctx.dest = security::SecFetchDest.Other;
        }
        return true;
    }
    if name.eq_ascii_fold(rfc::HEADER_SEC_FETCH_USER) {
        let parsed_user = (strip_sf_parameters(val) == "?1");
        if !seen.user {
            ctx.user_activated = parsed_user;
            seen.user = true;
        } else {
            ctx.user_activated = false;
        }
        return true;
    }
    return false;
}

inline fn apply_auth_and_origin_headers(
    ctx:  security::FetchContext&,
    name: const u8[:],
    val:  const u8[:],
) {
    if name.eq_ascii_fold(rfc::HEADER_ORIGIN) {
        if ctx.has_origin || !ctx.origin.try_set(val) { ctx.origin.clear(); }
        ctx.has_origin = true;
    } else if name.eq_ascii_fold(rfc::HEADER_REFERER) {
        if ctx.has_referer || !ctx.referer.try_set(val) { ctx.referer.clear(); }
        ctx.has_referer = true;
    } else if name.eq_ascii_fold(rfc::HEADER_COOKIE) {
        ctx.has_session_cookie = true;
    } else if name.eq_ascii_fold(rfc::HEADER_AUTHORIZATION) || name.eq_ascii_fold("X-API-Key") {
        ctx.has_explicit_auth = true;
    }
}

inline fn is_csrf_safe_method(m: const u8[:]) -> bool {
    return m == rfc::METHOD_GET || m == rfc::METHOD_HEAD ||
        m == rfc::METHOD_OPTIONS || m == rfc::METHOD_QUERY;
}

// Scans request headers for `Sec-Fetch-Site` without materializing `FetchContext`.
//
// Example:
//   req with header "Sec-Fetch-Site: same-origin"
//   returns: SecFetchSite.SameOrigin
fn scan_request_sec_fetch_site<Req>(req: const Req&) -> security::SecFetchSite {
    var site = security::SecFetchSite.Missing;
    var seen_site = false;
    for &e in req.headers.entries {
        guard e.well_known_id == 0xFF else { continue; }
        let name = req.headers.entry_name(e);
        guard name.len == 14 && name.eq_ascii_fold(rfc::HEADER_SEC_FETCH_SITE) else { continue; }
        let parsed = security::parse_sec_fetch_site(req.headers.entry_value(e).trim_lws());
        if !seen_site {
            site = parsed;
            seen_site = true;
        } else {
            site = security::SecFetchSite.CrossSite;
        }
    }
    return site;
}

fn append_known_isolation_header(
    map:            http::HeaderMap&,
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
    map.entries.push(http::HeaderEntry {
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

// ---- SSRF IP & domain validation internal helpers --------------------------

enum MetadataIpMatch {
    NotMatched,
    Allowed,
    Blocked,
}

fn is_private_ipv4_octets(octet0: i32, octet1: i32) -> bool {
    if octet0 == 0 { return true; }                                      // 0.0.0.0/8
    if octet0 == 10 { return true; }                                     // 10.0.0.0/8
    if octet0 == 127 { return true; }                                    // 127.0.0.0/8 Loopback
    if octet0 == 169 && octet1 == 254 { return true; }                   // 169.254.0.0/16 Link-Local / Cloud Metadata
    if octet0 == 172 && (octet1 >= 16 && octet1 <= 31) { return true; }  // 172.16.0.0/12
    if octet0 == 192 && octet1 == 168 { return true; }                   // 192.168.0.0/16
    // 198.18.0.0/15 Benchmarking (RFC 2544 / RFC 6890)
    if octet0 == 198 && (octet1 == 18 || octet1 == 19) { return true; }
    if octet0 == 100 && (octet1 >= 64 && octet1 <= 127) { return true; } // 100.64.0.0/10 CGNAT
    if octet0 >= 224 { return true; }                                    // 224.0.0.0/4 Multicast & Reserved
    return false;
}

fn is_private_ipv4_4octets(octet0: i32, octet1: i32, octet2: i32, octet3: i32) -> bool {
    if is_private_ipv4_octets(octet0, octet1) { return true; }
    if octet0 == 192 && octet1 == 0 && octet2 == 0 { return true; }    // 192.0.0.0/24 (RFC 6890 §2.1)
    if octet0 == 192 && octet1 == 0 && octet2 == 2 { return true; }    // 192.0.2.0/24 TEST-NET-1 (RFC 5737)
    if octet0 == 192 && octet1 == 88 && octet2 == 99 { return true; }  // 192.88.99.0/24 6to4 Relay Anycast (RFC 7526)
    if octet0 == 198 && octet1 == 51 && octet2 == 100 { return true; } // 198.51.100.0/24 TEST-NET-2 (RFC 5737)
    if octet0 == 203 && octet1 == 0 && octet2 == 113 { return true; }  // 203.0.113.0/24 TEST-NET-3 (RFC 5737)
    return false;
}

// Parses an IPv4 octet/part in decimal, octal (leading 0), or hex (0x prefix).
//
// Example:
//   part = "0x7f"
//   returns: val = 127, ok = true
fn parse_ipv4_part(part: const u8[:]) -> u64, bool {
    guard part.len > 0 else { return 0, false; }
    var base: u64 = 10;
    var start_idx = 0;
    if part.starts_with_fold("0x") {
        base = 16;
        start_idx = 2;
        guard part.len > 2 else { return 0, false; }
    } else if part.len >= 2 && part[0] == '0' {
        base = 8;
        start_idx = 1;
    }

    var val: u64 = 0;
    for i in start_idx..part.len {
        let hex = core::hex_digit_to_val(part[i]);
        guard hex >= 0 else { return 0, false; }
        let digit = hex as u64;
        val = core::add_sat_u64(core::mul_sat_u64(val, base), digit);
        guard digit < base && val <= 0xFFFFFFFF else { return 0, false; }
    }
    return val, true;
}

inline fn pack_flexible_ipv4_octets(nums: const u64[4]&, n: i64, octets: u8[4]&) -> bool {
    var ip_u32: u64 = 0;
    if n == 1 {
        guard nums[0] <= 0xFFFFFFFF else { return false; }
        ip_u32 = nums[0];
    } else if n == 2 {
        guard nums[0] <= 0xFF && nums[1] <= 0xFFFFFF else { return false; }
        ip_u32 = (nums[0] << 24) | nums[1];
    } else if n == 3 {
        guard nums[0] <= 0xFF && nums[1] <= 0xFF && nums[2] <= 0xFFFF else { return false; }
        ip_u32 = (nums[0] << 24) | (nums[1] << 16) | nums[2];
    } else if n == 4 {
        guard nums[0] <= 0xFF && nums[1] <= 0xFF && nums[2] <= 0xFF && nums[3] <= 0xFF else { return false; }
        ip_u32 = (nums[0] << 24) | (nums[1] << 16) | (nums[2] << 8) | nums[3];
    } else {
        return false;
    }
    octets[0] = ((ip_u32 >> 24) & 0xFF) as u8;
    octets[1] = ((ip_u32 >> 16) & 0xFF) as u8;
    octets[2] = ((ip_u32 >> 8) & 0xFF) as u8;
    octets[3] = (ip_u32 & 0xFF) as u8;
    return true;
}

// Parses IPv4 addresses in standard dotted-decimal, octal, hex, dword, or
// shorthand notation into 4 canonical octets.
//
// Example:
//   clean_ip = "127.0.0.1"
//   returns: ok = true, octets = [127, 0, 0, 1]
fn parse_flexible_ipv4(clean_ip: const u8[:], octets: u8[4]&) -> bool {
    guard clean_ip.len > 0 && clean_ip[0] != '.' && clean_ip[clean_ip.len - 1] != '.' else {
        return false;
    }
    var nums:  u64[4] = [0, 0, 0, 0];
    var count: i64    = 0;
    var tok = core::make_byte_tokenizer(clean_ip, '.');
    loop {
        let part, has_tok = core::token_next(tok);
        guard has_tok else { break; }
        guard part.len > 0 && count < 4 else { return false; }
        let val, ok = parse_ipv4_part(part);
        guard ok else { return false; }
        nums[count] = val;
        count = core::add_sat_i64(count, 1);
    }
    return pack_flexible_ipv4_octets(nums, count, octets);
}

fn is_private_ipv4(clean_ip: const u8[:]) -> bool {
    var octets: u8[4] = [0, 0, 0, 0];
    guard parse_flexible_ipv4(clean_ip, octets) else { return false; }
    return is_private_ipv4_4octets(octets[0], octets[1], octets[2], octets[3]);
}

// Parses a 1..4 digit hexadecimal IPv6 segment into a 16-bit integer.
//
// Example:
//   s = "1f90"
//   returns: 8080, ok = true
fn parse_ssrf_hex_u16(s: const u8[:]) -> u16, bool {
    guard s.len > 0 && s.len <= 4 else { return 0, false; }
    var val: u32 = 0;
    for b in s {
        let h = core::hex_digit_to_val(b);
        guard h >= 0 else { return 0, false; }
        val = (val << 4) | (h as u32);
    }
    return val as u16, true;
}

fn is_private_ipv4_mapped_hex(suffix: const u8[:]) -> bool {
    let part1, part2, has_colon = suffix.split_once_byte(':');
    if !has_colon {
        let val_low, ok_low = parse_ssrf_hex_u16(suffix);
        guard ok_low else { return false; }
        let o2 = ((val_low >> 8) & 0xFF) as i32;
        let o3 = (val_low & 0xFF) as i32;
        return is_private_ipv4_4octets(0, 0, o2, o3);
    }
    guard part1.len > 0 && part2.len > 0 && !part2.contains_byte(':') else { return false; }

    let val1, ok1 = parse_ssrf_hex_u16(part1);
    let val2, ok2 = parse_ssrf_hex_u16(part2);
    guard ok1 && ok2 else { return false; }

    return is_private_ipv4_4octets(
        (val1 >> 8) & 0xFF,
        val1 & 0xFF,
        (val2 >> 8) & 0xFF,
        val2 & 0xFF,
    );
}

fn is_private_6to4_prefix(eff_ip: const u8[:]) -> bool {
    guard core::starts_with(eff_ip, "2002:") else { return false; }
    let rem = eff_ip[5..];
    let seg1, rem2, has_col = rem.split_once_byte(':');
    let p1 = if has_col { seg1 } else { rem };
    guard p1.len > 0 else { return true; }
    let hex_val1, ok1 = parse_ssrf_hex_u16(p1);
    guard ok1 else { return true; }
    let o0 = ((hex_val1 >> 8) & 0xFF) as i32;
    let o1 = (hex_val1 & 0xFF) as i32;
    if is_private_ipv4_octets(o0, o1) {
        return true;
    }
    guard has_col && rem2.len > 0 else { return false; }
    var o2: i32 = 0;
    if rem2[0] != ':' {
        let seg2, _, has_col2 = rem2.split_once_byte(':');
        let p2 = if has_col2 { seg2 } else { rem2 };
        guard p2.len > 0 else { return true; }
        let hex_val2, ok2 = parse_ssrf_hex_u16(p2);
        guard ok2 else { return true; }
        o2 = (hex_val2 >> 8) & 0xFF;
    }
    return (o0 == 192 && o1 == 0 && (o2 == 0 || o2 == 2)) ||
        (o0 == 198 && o1 == 51 && o2 == 100) ||
        (o0 == 203 && o1 == 0 && o2 == 113) ||
        (o0 == 192 && o1 == 88 && o2 == 99);
}

inline fn is_ipv6_local_or_multicast_prefix(eff_ip: const u8[:]) -> bool {
    if eff_ip == "::1" || eff_ip == "::" {
        return true;
    }
    if core::starts_with(eff_ip, "fc") || core::starts_with(eff_ip, "fd") ||
        core::starts_with(eff_ip, "fe8") || core::starts_with(eff_ip, "fe9") ||
        core::starts_with(eff_ip, "fea") || core::starts_with(eff_ip, "feb") ||
        core::starts_with(eff_ip, "fec") || core::starts_with(eff_ip, "fed") ||
        core::starts_with(eff_ip, "fee") || core::starts_with(eff_ip, "fef") ||
        core::starts_with(eff_ip, "ff") {
        return true;
    }
    // Benchmarking (RFC 5180), Documentation (RFC 3849), Teredo (RFC 4380), Discard-Only (RFC 6666)
    if core::starts_with(eff_ip, "2001:2::") || core::starts_with(eff_ip, "2001:2:0:") ||
        core::starts_with(eff_ip, "2001:db8:") || core::starts_with(eff_ip, "2001:0:") ||
        core::starts_with(eff_ip, "2001::") || core::starts_with(eff_ip, "100::") {
        return true;
    }
    // ORCHIDv2 (RFC 7343: 2001:20::/28)
    return core::starts_with(eff_ip, "2001:2") && eff_ip.len >= 8 &&
        eff_ip[7] == ':' && core::is_ascii_hexdigit(eff_ip[6]);
}

fn is_private_or_reserved_ipv6(eff_ip: const u8[:]) -> bool {
    if is_ipv6_local_or_multicast_prefix(eff_ip) {
        return true;
    }
    if core::starts_with(eff_ip, "::ffff:") || core::starts_with(eff_ip, "0:0:0:0:0:ffff:") {
        let raw_suffix = if core::starts_with(eff_ip, "::ffff:") { eff_ip[7..] } else { eff_ip[15..] };
        let suffix = if core::starts_with(raw_suffix, "0:") { raw_suffix[2..] } else { raw_suffix };
        return is_private_ipv4(suffix) || is_private_ipv4_mapped_hex(suffix);
    }
    if eff_ip.contains_byte('.') {
        let last_colon = eff_ip.last_index_of_byte(':');
        let next_col = core::add_sat_i64(last_colon, 1);
        if last_colon >= 0 && next_col < eff_ip.len && is_private_ipv4(eff_ip[next_col..]) {
            return true;
        }
    }
    if core::starts_with(eff_ip, "::") && !core::starts_with(eff_ip, "::ffff:") {
        let suffix = eff_ip[2..];
        return is_private_ipv4(suffix) || is_private_ipv4_mapped_hex(suffix);
    }
    if core::starts_with(eff_ip, "64:ff9b:1:") || eff_ip == "64:ff9b:1::" {
        return true;
    }
    if core::starts_with(eff_ip, "64:ff9b::") {
        let suffix = eff_ip[9..];
        if suffix.len == 0 { return true; }
        return is_private_ipv4(suffix) || is_private_ipv4_mapped_hex(suffix);
    }
    return is_private_6to4_prefix(eff_ip);
}

inline fn is_forbidden_ipv6(host: const u8[:]) -> bool {
    let h = if host.len >= 2 && host[0] == '[' && host[host.len - 1] == ']' {
        host[1..^1]
    } else {
        host
    };
    if h == "::1" || h == "::" || h == "0:0:0:0:0:0:0:1" || h == "0:0:0:0:0:0:0:0" { return true; }
    if core::starts_with(h, "::ffff:") || core::starts_with(h, "0:0:0:0:0:ffff:") { return true; }
    if core::starts_with(h, "fe8") || core::starts_with(h, "fe9") ||
        core::starts_with(h, "fea") || core::starts_with(h, "feb") {
        return true;
    }
    if core::starts_with(h, "fc") || core::starts_with(h, "fd") {
        return true;
    }
    return core::starts_with(h, "0::") || core::starts_with(h, "0:0:") || core::starts_with(h, "::");
}

inline fn is_all_digits_or_dots(host: const u8[:]) -> bool {
    guard host.len > 0 else { return false; }
    for b in host {
        if b != '.' && !core::is_ascii_digit(b) {
            return false;
        }
    }
    return true;
}

inline fn has_hex_prefix(host: const u8[:]) -> bool {
    guard host.len >= 2 else { return false; }
    let limit = core::sub_sat_i64(host.len, 1);
    for i in limit {
        let next_i = core::add_sat_i64(i, 1);
        if host[i] == '0' && (host[next_i] == 'x' || host[next_i] == 'X') { return true; }
    }
    return false;
}

inline fn is_invalid_ipv4_octet_state(octet_len: i64, first_zero: bool, octet_val: i64) -> bool {
    return octet_len == 0 || (octet_len > 1 && first_zero) || octet_len > 3 || octet_val > 255;
}

inline fn is_forbidden_internal_domain(host: const u8[:]) -> bool {
    let h = host.trim_end_byte('.');
    if h.eq_ascii_fold("localhost") || h.eq_ascii_fold("metadata.google.internal") ||
        h.eq_ascii_fold("instance-data") {
        return true;
    }
    if h.ends_with_fold(".localhost") || h.ends_with_fold(".local") { return true; }
    if h.ends_with_fold(".internal") || h.ends_with_fold(".lan") { return true; }
    return h.ends_with_fold(".corp");
}

inline fn is_cloud_metadata_or_reserved_ipv4_octets(o0: i32, o1: i32) -> bool {
    return o0 == 0 || (o0 == 169 && o1 == 254) || o0 >= 224;
}

fn is_cloud_metadata_ipv4_suffix(suffix: const u8[:]) -> bool {
    var octets: u8[4] = [0, 0, 0, 0];
    if parse_flexible_ipv4(suffix, octets) {
        return is_cloud_metadata_or_reserved_ipv4_octets(octets[0], octets[1]);
    }
    let p1, p2, has_colon = suffix.split_once_byte(':');
    if !has_colon {
        let _, ok_low = parse_ssrf_hex_u16(suffix);
        guard ok_low else { return false; }
        return is_cloud_metadata_or_reserved_ipv4_octets(0, 0);
    }
    guard p1.len > 0 && p2.len > 0 && !p2.contains_byte(':') else { return false; }
    let val1, ok1 = parse_ssrf_hex_u16(p1);
    let _, ok2 = parse_ssrf_hex_u16(p2);
    guard ok1 && ok2 else { return false; }
    return is_cloud_metadata_or_reserved_ipv4_octets((val1 >> 8) & 0xFF, val1 & 0xFF);
}

inline fn is_cloud_metadata_mapped_or_nat64_ipv6(eff_ip: const u8[:]) -> MetadataIpMatch {
    if core::starts_with(eff_ip, "::ffff:") || core::starts_with(eff_ip, "0:0:0:0:0:ffff:") {
        let raw_sfx = if core::starts_with(eff_ip, "::ffff:") { eff_ip[7..] } else { eff_ip[15..] };
        let suffix = if core::starts_with(raw_sfx, "0:") { raw_sfx[2..] } else { raw_sfx };
        return if is_cloud_metadata_ipv4_suffix(suffix) {
            MetadataIpMatch.Blocked
        } else {
            MetadataIpMatch.Allowed
        };
    }
    if core::starts_with(eff_ip, "64:ff9b::") {
        let suffix = eff_ip[9..];
        let blocked = if suffix.len == 0 { true } else { is_cloud_metadata_ipv4_suffix(suffix) };
        return if blocked { MetadataIpMatch.Blocked } else { MetadataIpMatch.Allowed };
    }
    return MetadataIpMatch.NotMatched;
}

inline fn is_ipv6_link_local_prefix(eff_ip: const u8[:]) -> bool {
    return core::starts_with(eff_ip, "fe8") || core::starts_with(eff_ip, "fe9") ||
        core::starts_with(eff_ip, "fea") || core::starts_with(eff_ip, "feb");
}

fn is_cloud_metadata_or_reserved_ipv6(eff_ip: const u8[:]) -> bool {
    if eff_ip == "::" || core::starts_with(eff_ip, "ff") || eff_ip == "fd00:ec2::254" ||
        is_ipv6_link_local_prefix(eff_ip) {
        return true;
    }
    let map_match = is_cloud_metadata_mapped_or_nat64_ipv6(eff_ip);
    if map_match != MetadataIpMatch.NotMatched {
        return map_match == MetadataIpMatch.Blocked;
    }
    if core::starts_with(eff_ip, "::") && !core::starts_with(eff_ip, "::ffff:") {
        let suffix = eff_ip[2..];
        if suffix.len > 0 && is_cloud_metadata_ipv4_suffix(suffix) {
            return true;
        }
    }
    if eff_ip.contains_byte('.') {
        let last_colon = eff_ip.last_index_of_byte(':');
        let next_col = core::add_sat_i64(last_colon, 1);
        if last_colon >= 0 && next_col < eff_ip.len && is_cloud_metadata_ipv4_suffix(eff_ip[next_col..]) {
            return true;
        }
    }
    if core::starts_with(eff_ip, "2002:") {
        let rem = eff_ip[5..];
        let p1, _, has_col = rem.split_once_byte(':');
        let h1 = if has_col && p1.len > 0 { p1 } else { rem };
        let hex_val1, ok1 = parse_ssrf_hex_u16(h1);
        if ok1 {
            return is_cloud_metadata_or_reserved_ipv4_octets((hex_val1 >> 8) & 0xFF, hex_val1 & 0xFF);
        }
    }
    return false;
}

inline fn strip_ssrf_ip_brackets_and_zone(ip_str: const u8[:]) -> const u8[:] {
    var clean_ip = ip_str;
    if clean_ip.len > 2 && clean_ip[0] == '[' && clean_ip[clean_ip.len - 1] == ']' {
        clean_ip = clean_ip[1..^1];
    }
    let before_pct, _, has_pct = clean_ip.split_once_byte('%');
    if has_pct {
        clean_ip = before_pct;
    }
    return clean_ip;
}

inline fn normalize_ssrf_ip_chars(clean_ip: const u8[:], lower_buf: u8[..256]&) -> const u8[:], bool {
    guard clean_ip.len > 0 && clean_ip.len <= 256 else { return clean_ip[..0], false; }
    lower_buf.clear();
    clean_ip.to_lower_ascii(lower_buf);
    return lower_buf[..], true;
}
