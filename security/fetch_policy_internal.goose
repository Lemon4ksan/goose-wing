// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Internal helpers for Cross-Origin Isolation, RFC 8941 Structured Fields, and CSRF Fetch Metadata.
namespace security_internal;

import std;
import core;
import rfc.http;

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
    guard val.len >= 2 else { return false; }
    let end = core::sub_sat_i64(val.len, 1);
    guard val[0] == '"' && val[end] == '"' else { return false; }
    let inner = val[1..end];
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
