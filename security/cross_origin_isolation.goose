// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// W3C Cross-Origin Isolation Engine (COOP, COEP, CORP).
// Enforces HTML5 §7.2 Cross-Origin-Opener-Policy, Cross-Origin-Embedder-Policy,
// and Cross-Origin-Resource-Policy for Spectre process sandboxing and secure context verification.
namespace wing;

import std;
import core from "..";

// ---- 1. Policy Enumerations -------------------------------------------------

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

// ---- 2. Context Model -------------------------------------------------------

struct CrossOriginIsolationContext {
    coop:                     CoopPolicy = CoopPolicy.UnsafeNone,
    coep:                     CoepPolicy = CoepPolicy.UnsafeNone,
    is_cross_origin_isolated: bool       = false,
    document_origin:          u8[..128]  = [],
}

// ---- 3. Policy Parsers ------------------------------------------------------

// Parses Cross-Origin-Opener-Policy header value (W3C HTML §7.2).
//
// Example:
//   val = "same-origin"
//   returns: CoopPolicy.SameOrigin
fn parse_coop(val: const u8[:]) -> CoopPolicy {
    let clean = trim_lws(val);
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
//   val = "require-corp"
//   returns: CoepPolicy.RequireCorp
fn parse_coep(val: const u8[:]) -> CoepPolicy {
    let clean = trim_lws(val);
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
    let clean = trim_lws(val);
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

// Extracts host from an origin or URL string.
//
// Example:
//   origin_or_url = "https://example.com:8080/path"
//   returns: "example.com"
fn extract_hostname_from_origin(origin_or_url: const u8[:]) -> const u8[:] {
    var s = trim_lws(origin_or_url);
    if starts_with(s, "https://") { s = s[8..]; }
    else if starts_with(s, "http://") { s = s[7..]; }
    guard s.len > 0 else { return s; }
    for i in s.len {
        let b = s[i];
        if b == '/' || b == '?' || b == '#' || b == ':' {
            return s[..i];
        }
    }
    return s;
}

// ---- 4. Context Lifecycle & Subresource Verification ------------------------

// Updates isolation context from document response headers and computes crossOriginIsolated status
fn update_isolation_context(
    ctx:             CrossOriginIsolationContext&,
    coop_header:     const u8[:],
    coep_header:     const u8[:],
    document_origin: const u8[:],
) -> bool {
    ctx.coop = parse_coop(coop_header);
    ctx.coep = parse_coep(coep_header);
    ctx.document_origin.clear();
    guard document_origin.len <= ctx.document_origin.cap else { return false; }
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

// Checks whether a subresource response is permitted to load under the active parent context
fn is_subresource_allowed(
    ctx:                     const CrossOriginIsolationContext&,
    subresource_origin:      const u8[:],
    subresource_corp_header: const u8[:],
) -> bool {
    let is_same_origin = eq_ascii_fold(ctx.document_origin[..], subresource_origin);
    guard !is_same_origin else { return true; }

    let corp = parse_corp(subresource_corp_header);
    guard corp != CorpPolicy.SameOrigin else { return false; }

    if corp == CorpPolicy.SameSite {
        // WHATWG Fetch §4.5.7: If document_origin has https scheme, subresource_origin must also be https
        let doc_is_https = core::starts_with_fold(ctx.document_origin[..], "https://");
        let sub_is_https = core::starts_with_fold(subresource_origin, "https://");
        guard !doc_is_https || sub_is_https else { return false; }
        var doc_etld: u8[..128] = [];
        var sub_etld: u8[..128] = [];
        core::extract_etld_plus_one(extract_hostname_from_origin(ctx.document_origin[..]), doc_etld);
        core::extract_etld_plus_one(extract_hostname_from_origin(subresource_origin), sub_etld);
        return doc_etld.len > 0 && sub_etld.len > 0 && eq_ascii_fold(doc_etld[..], sub_etld[..]);
    }

    if ctx.coep == CoepPolicy.RequireCorp {
        return corp == CorpPolicy.CrossOrigin;
    }

    return true;
}
