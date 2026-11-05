// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// W3C Cross-Origin Isolation Engine (COOP, COEP, CORP).
// Enforces HTML5 §7.2 Cross-Origin-Opener-Policy, Cross-Origin-Embedder-Policy,
// and Cross-Origin-Resource-Policy for Spectre process sandboxing and secure context verification.
namespace wing;

import std;
import core from "..";

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
inline fn strip_sf_parameters(val: const u8[:]) -> const u8[:] {
    let head, _, _ = split_once(val, ";");
    return trim_lws(head);
}

// Parses Cross-Origin-Opener-Policy header value (W3C HTML §7.2).
//
// Example:
//   val = "same-origin; report-to=\"coop-ep\""
//   returns: CoopPolicy.SameOrigin
fn parse_coop(val: const u8[:]) -> CoopPolicy {
    let clean = strip_sf_parameters(val);
    if clean.len == 0 || eq_ascii_fold(clean, "unsafe-none") {
        return CoopPolicy.UnsafeNone;
    } else if eq_ascii_fold(clean, "same-origin") {
        return CoopPolicy.SameOrigin;
    } else if eq_ascii_fold(clean, "same-origin-allow-popups") {
        return CoopPolicy.SameOriginAllowPopups;
    }
    return CoopPolicy.Unknown;
}

// Parses Cross-Origin-Embedder-Policy header value (W3C HTML §7.2).
//
// Example:
//   val = "require-corp; report-to=\"coep-ep\""
//   returns: CoepPolicy.RequireCorp
fn parse_coep(val: const u8[:]) -> CoepPolicy {
    let clean = strip_sf_parameters(val);
    if clean.len == 0 || eq_ascii_fold(clean, "unsafe-none") {
        return CoepPolicy.UnsafeNone;
    } else if eq_ascii_fold(clean, "require-corp") {
        return CoepPolicy.RequireCorp;
    } else if eq_ascii_fold(clean, "credentialless") {
        return CoepPolicy.Credentialless;
    }
    return CoepPolicy.Unknown;
}

// Parses Cross-Origin-Resource-Policy header value (W3C Fetch §4.5).
//
// Example:
//   val = "same-origin"
//   returns: CorpPolicy.SameOrigin
fn parse_corp(val: const u8[:]) -> CorpPolicy {
    let clean = strip_sf_parameters(val);
    if clean.len == 0 {
        return CorpPolicy.None;
    } else if eq_ascii_fold(clean, "same-origin") {
        return CorpPolicy.SameOrigin;
    } else if eq_ascii_fold(clean, "same-site") {
        return CorpPolicy.SameSite;
    } else if eq_ascii_fold(clean, "cross-origin") {
        return CorpPolicy.CrossOrigin;
    }
    return CorpPolicy.Unknown;
}

// Extracts host from an origin or URL string (RFC 3986 §3.2.2).
//
// Example:
//   origin_or_url = "https://example.com:8080/path"
//   returns: "example.com"
fn extract_hostname_from_origin(origin_or_url: const u8[:]) -> const u8[:] {
    var s = trim_lws(origin_or_url);
    if starts_with_fold(s, "https://") { s = s[8..]; }
    else if starts_with_fold(s, "http://") { s = s[7..]; }
    guard s.len > 0 else { return ""; }

    var end_idx = s.len;
    for i in s.len {
        let b = s[i];
        if b == '/' || b == '?' || b == '#' || b == '\\' {
            end_idx = i;
            break;
        }
    }
    let auth = s[..end_idx];
    guard auth.len > 0 && !core::contains_byte(auth, '@') else { return ""; }

    if auth[0] == '[' {
        let close_idx = core::index_of_byte(auth, ']');
        guard close_idx > 1 else { return ""; }
        return auth[..close_idx + 1];
    }
    let colon_idx = core::index_of_byte(auth, ':');
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
    guard document_origin.len <= ctx.document_origin.cap else { return false; }
    ctx.coop = parse_coop(coop_header);
    ctx.coep = parse_coep(coep_header);
    ctx.document_origin.clear();
    ctx.document_origin.append(document_origin);

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
    let coop = headers.get_header("cross-origin-opener-policy");
    let coep = headers.get_header("cross-origin-embedder-policy");
    return update_isolation_context(ctx, coop, coep, document_origin);
}

// Updates isolation context directly from a HeaderItem slice
fn update_from_headers(
    ctx:             CrossOriginIsolationContext&,
    headers:         const HeaderItem[:],
    document_origin: const u8[:],
) -> bool {
    let coop = headers.find_header("cross-origin-opener-policy");
    let coep = headers.find_header("cross-origin-embedder-policy");
    return update_isolation_context(ctx, coop, coep, document_origin);
}

// Checks whether a subresource response is permitted to load under the active parent context (WHATWG Fetch §4.5).
fn is_subresource_allowed(
    ctx:                     const CrossOriginIsolationContext&,
    subresource_origin:      const u8[:],
    subresource_corp_header: const u8[:],
) -> bool {
    let doc_orig = trim_lws(ctx.document_origin[..]);
    let sub_orig = trim_lws(subresource_origin);
    let doc_valid = doc_orig.len > 0 && !eq_ascii_fold(doc_orig, "null");
    let sub_valid = sub_orig.len > 0 && !eq_ascii_fold(sub_orig, "null");
    let is_same_origin = doc_valid && sub_valid && eq_ascii_fold(doc_orig, sub_orig);
    guard !is_same_origin else { return true; }

    let corp = parse_corp(subresource_corp_header);
    guard corp != CorpPolicy.SameOrigin && corp != CorpPolicy.Unknown else { return false; }

    if corp == CorpPolicy.SameSite {
        // WHATWG Fetch §4.5.7: Both origins must have a scheme, and if document_origin is https,
        // subresource must also be https.
        let doc_is_https = core::starts_with_fold(doc_orig, "https://");
        let doc_is_http = core::starts_with_fold(doc_orig, "http://");
        let sub_is_https = core::starts_with_fold(sub_orig, "https://");
        let sub_is_http = core::starts_with_fold(sub_orig, "http://");
        guard (doc_is_https || doc_is_http) && (sub_is_https || sub_is_http) else { return false; }
        guard !doc_is_https || sub_is_https else { return false; }

        let doc_host = extract_hostname_from_origin(doc_orig);
        let sub_host = extract_hostname_from_origin(sub_orig);
        guard doc_host.len > 0 && sub_host.len > 0 else { return false; }
        if doc_host[0] == '[' || sub_host[0] == '[' {
            return eq_ascii_fold(doc_host, sub_host);
        }
        var doc_etld: u8[..128] = [];
        var sub_etld: u8[..128] = [];
        core::extract_etld_plus_one(doc_host, doc_etld);
        core::extract_etld_plus_one(sub_host, sub_etld);
        return doc_etld.len > 0 && sub_etld.len > 0 && eq_ascii_fold(doc_etld[..], sub_etld[..]);
    }

    if ctx.coep == CoepPolicy.RequireCorp || ctx.coep == CoepPolicy.Credentialless {
        return corp == CorpPolicy.CrossOrigin;
    }

    return true;
}
