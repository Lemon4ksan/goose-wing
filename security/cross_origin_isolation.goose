// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// W3C Cross-Origin Isolation Engine (COOP, COEP, CORP).
// Enforces HTML5 §7.2 Cross-Origin-Opener-Policy, Cross-Origin-Embedder-Policy,
// and Cross-Origin-Resource-Policy for Spectre process sandboxing and secure context verification.
namespace wing;

import std;
import core from "..";
import rfc.http;

// ---- Policy Enumerations -------------------------------------------------

enum CoopPolicy {
    Unknown,
    UnsafeNone,
    SameOriginAllowPopups,
    SameOrigin,
}

enum CoepPolicy {
    Unknown,
    UnsafeNone,
    Credentialless,
    RequireCorp,
}

enum CorpPolicy {
    Unknown,
    None,
    SameOrigin,
    SameSite,
    CrossOrigin,
}

// ---- Context Model -------------------------------------------------------

struct CrossOriginIsolationContext {
    coop:                     CoopPolicy = CoopPolicy.UnsafeNone,
    coep:                     CoepPolicy = CoepPolicy.UnsafeNone,
    is_cross_origin_isolated: bool       = false,
    document_origin:          u8[..128]  = [],
}

// ---- Policy Parsers ------------------------------------------------------

// Extracts the primary token before any RFC 8941 structured field parameters (';').
// Rejects unquoted commas (multi-item lists) and leading semicolons without a token.
inline fn strip_sf_parameters(val: const u8[:]) -> const u8[:] {
    guard val.find_unquoted_byte(',') == val.len else { return ";"; }
    let head, _, has_semi = val.split_once_byte(';');
    let clean = head.trim_lws();
    if has_semi && clean.len == 0 {
        return ";";
    }
    return clean;
}

inline fn wire_token(v: CoopPolicy.Unknown) -> const u8[:] { return ""; }
inline fn wire_token(v: CoopPolicy.UnsafeNone) -> const u8[:] { return "unsafe-none"; }
inline fn wire_token(v: CoopPolicy.SameOriginAllowPopups) -> const u8[:] { return "same-origin-allow-popups"; }
inline fn wire_token(v: CoopPolicy.SameOrigin) -> const u8[:] { return "same-origin"; }

// Parses Cross-Origin-Opener-Policy header value (W3C HTML §7.2).
//
// Example:
//   val = "same-origin; report-to=\"coop-ep\""
//   returns: CoopPolicy.SameOrigin
fn parse_coop(val: const u8[:]) -> CoopPolicy {
    let clean = strip_sf_parameters(val);
    if clean.len == 0 { return CoopPolicy.UnsafeNone; }
    const for <N, V> in variants<CoopPolicy> {
        let v = default<V>();
        let tok = wire_token(v);
        if tok.len > 0 && clean.eq_ascii_fold(tok) {
            let candidate: CoopPolicy = v;
            return candidate;
        }
    }
    return CoopPolicy.Unknown;
}

inline fn wire_token(v: CoepPolicy.Unknown) -> const u8[:] { return ""; }
inline fn wire_token(v: CoepPolicy.UnsafeNone) -> const u8[:] { return "unsafe-none"; }
inline fn wire_token(v: CoepPolicy.Credentialless) -> const u8[:] { return "credentialless"; }
inline fn wire_token(v: CoepPolicy.RequireCorp) -> const u8[:] { return "require-corp"; }

// Parses Cross-Origin-Embedder-Policy header value (W3C HTML §7.2).
//
// Example:
//   val = "require-corp; report-to=\"coep-ep\""
//   returns: CoepPolicy.RequireCorp
fn parse_coep(val: const u8[:]) -> CoepPolicy {
    let clean = strip_sf_parameters(val);
    if clean.len == 0 { return CoepPolicy.UnsafeNone; }
    const for <N, V> in variants<CoepPolicy> {
        let v = default<V>();
        let tok = wire_token(v);
        if tok.len > 0 && clean.eq_ascii_fold(tok) {
            let candidate: CoepPolicy = v;
            return candidate;
        }
    }
    return CoepPolicy.Unknown;
}

inline fn wire_token(v: CorpPolicy.Unknown) -> const u8[:] { return ""; }
inline fn wire_token(v: CorpPolicy.None) -> const u8[:] { return ""; }
inline fn wire_token(v: CorpPolicy.SameOrigin) -> const u8[:] { return "same-origin"; }
inline fn wire_token(v: CorpPolicy.SameSite) -> const u8[:] { return "same-site"; }
inline fn wire_token(v: CorpPolicy.CrossOrigin) -> const u8[:] { return "cross-origin"; }

// Parses Cross-Origin-Resource-Policy header value (W3C Fetch §4.5).
//
// Example:
//   val = "same-origin"
//   returns: CorpPolicy.SameOrigin
fn parse_corp(val: const u8[:]) -> CorpPolicy {
    let clean = strip_sf_parameters(val);
    if clean.len == 0 { return CorpPolicy.None; }
    const for <N, V> in variants<CorpPolicy> {
        let v = default<V>();
        let tok = wire_token(v);
        if tok.len > 0 && clean.eq_ascii_fold(tok) {
            let candidate: CorpPolicy = v;
            return candidate;
        }
    }
    return CorpPolicy.Unknown;
}

// Extracts host from an origin or URL string (RFC 3986 §3.2.2).
//
// Example:
//   origin_or_url = "https://example.com:8080/path"
//   returns: "example.com"
fn extract_hostname_from_origin(origin_or_url: const u8[:]) -> const u8[:] {
    var s = origin_or_url.trim_lws();
    if s.starts_with_fold("https://") {
        s = s[8..];
    } else if s.starts_with_fold("http://") {
        s = s[7..];
    } else {
        return "";
    }
    let delim = core::find_byteset(s, "/?#");
    let auth = if delim >= 0 { s[..delim] } else { s };
    guard auth.len > 0 && !auth.contains_byte('@') && !auth.contains_byte('\\') else { return ""; }

    if auth[0] == '[' {
        let close_idx = auth.index_of_byte(']');
        let end_bracket = core::add_sat_i64(close_idx, 1);
        guard close_idx > 1 && (end_bracket == auth.len || auth[end_bracket] == ':') else { return ""; }
        return auth[..end_bracket];
    }
    let colon_idx = auth.index_of_byte(':');
    if colon_idx >= 0 {
        return auth[..colon_idx];
    }
    return auth;
}

// ---- Context Lifecycle & Subresource Verification ------------------------

// Updates isolation context from document response headers and computes crossOriginIsolated status
fn update_isolation_context(
    ctx:             CrossOriginIsolationContext&,
    coop_header:     const u8[:],
    coep_header:     const u8[:],
    document_origin: const u8[:],
) -> bool {
    guard ctx.document_origin.try_set(document_origin) else { return false; }
    ctx.coop = parse_coop(coop_header);
    ctx.coep = parse_coep(coep_header);

    // Context is cross-origin isolated if:
    // COOP is same-origin AND COEP is require-corp or credentialless (W3C HTML §7.2)
    let is_corp = ctx.coep == CoepPolicy.RequireCorp || ctx.coep == CoepPolicy.Credentialless;
    ctx.is_cross_origin_isolated = ctx.coop == CoopPolicy.SameOrigin && is_corp;
    return true;
}

// Updates isolation context directly from a HeaderMap (RFC 9110 / W3C HTML §7.2)
fn update_from_headers(
    ctx:             CrossOriginIsolationContext&,
    headers:         const HeaderMap&,
    document_origin: const u8[:],
) -> bool {
    let coop = headers.get_header(rfc::HEADER_CROSS_ORIGIN_OPENER_POLICY);
    let coep = headers.get_header(rfc::HEADER_CROSS_ORIGIN_EMBEDDER_POLICY);
    return update_isolation_context(ctx, coop, coep, document_origin);
}

// Checks whether a subresource response is permitted to load under the active parent context (WHATWG Fetch §4.5).
fn is_subresource_allowed(
    ctx:                     const CrossOriginIsolationContext&,
    subresource_origin:      const u8[:],
    subresource_corp_header: const u8[:],
) -> bool {
    let doc_orig = ctx.document_origin[..].trim_lws();
    let sub_orig = subresource_origin.trim_lws();
    let doc_valid = doc_orig.len > 0 && !doc_orig.eq_ascii_fold("null");
    let sub_valid = sub_orig.len > 0 && !sub_orig.eq_ascii_fold("null");
    let is_same_origin = doc_valid && sub_valid && doc_orig.eq_ascii_fold(sub_orig);
    guard !is_same_origin else { return true; }

    let corp = parse_corp(subresource_corp_header);
    guard corp != CorpPolicy.SameOrigin && corp != CorpPolicy.Unknown else { return false; }

    if corp == CorpPolicy.SameSite {
        // WHATWG Fetch §4.5.7: Both origins must have a scheme, and if document_origin is https,
        // subresource must also be https.
        let doc_is_https = doc_orig.starts_with_fold("https://");
        let doc_is_http = doc_orig.starts_with_fold("http://");
        let sub_is_https = sub_orig.starts_with_fold("https://");
        let sub_is_http = sub_orig.starts_with_fold("http://");
        guard (doc_is_https || doc_is_http) && (sub_is_https || sub_is_http) else { return false; }
        guard !doc_is_https || sub_is_https else { return false; }

        let doc_host = extract_hostname_from_origin(doc_orig);
        let sub_host = extract_hostname_from_origin(sub_orig);
        guard doc_host.len > 0 && sub_host.len > 0 else { return false; }
        if doc_host[0] == '[' || sub_host[0] == '[' {
            return doc_host.eq_ascii_fold(sub_host);
        }
        var doc_etld: u8[..128] = [];
        var sub_etld: u8[..128] = [];
        core::extract_etld_plus_one(doc_host, doc_etld);
        core::extract_etld_plus_one(sub_host, sub_etld);
        return doc_etld.len > 0 && sub_etld.len > 0 && doc_etld[..].eq_ascii_fold(sub_etld[..]);
    }

    if ctx.coep == CoepPolicy.RequireCorp || ctx.coep == CoepPolicy.Credentialless {
        return corp == CorpPolicy.CrossOrigin;
    }

    return true;
}

// Injects strict same-origin COOP, require-corp COEP, and same-origin CORP headers.
fn apply_strict_cross_origin_isolation<Res>(res: Res&) {
    res.headers.set_header(rfc::HEADER_CROSS_ORIGIN_OPENER_POLICY, wire_token(default<CoopPolicy.SameOrigin>()));
    res.headers.set_header(rfc::HEADER_CROSS_ORIGIN_EMBEDDER_POLICY, wire_token(default<CoepPolicy.RequireCorp>()));
    res.headers.set_header(rfc::HEADER_CROSS_ORIGIN_RESOURCE_POLICY, wire_token(default<CorpPolicy.SameOrigin>()));
}
