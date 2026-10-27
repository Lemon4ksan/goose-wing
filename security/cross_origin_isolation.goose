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
    UnsafeNone,
    SameOriginAllowPopups,
    SameOrigin,
}

enum CoepPolicy {
    UnsafeNone,
    Credentialless,
    RequireCorp,
}

enum CorpPolicy {
    None,
    SameOrigin,
    SameSite,
    CrossOrigin,
}

// ---- 2. Context Model -------------------------------------------------------

struct CrossOriginIsolationContext {
    coop: CoopPolicy = CoopPolicy.UnsafeNone,
    coep: CoepPolicy = CoepPolicy.UnsafeNone,
    is_cross_origin_isolated: bool = false,
    document_origin: u8[..128] = [],
}

// ---- 3. Policy Parsers ------------------------------------------------------

fn parse_coop(val: const u8[:]) -> CoopPolicy {
    let clean = trim_lws(val);
    if eq_ascii_fold(clean, "same-origin") {
        return CoopPolicy.SameOrigin;
    } else if eq_ascii_fold(clean, "same-origin-allow-popups") {
        return CoopPolicy.SameOriginAllowPopups;
    }
    return CoopPolicy.UnsafeNone;
}

fn parse_coep(val: const u8[:]) -> CoepPolicy {
    let clean = trim_lws(val);
    if eq_ascii_fold(clean, "require-corp") {
        return CoepPolicy.RequireCorp;
    } else if eq_ascii_fold(clean, "credentialless") {
        return CoepPolicy.Credentialless;
    }
    return CoepPolicy.UnsafeNone;
}

fn parse_corp(val: const u8[:]) -> CorpPolicy {
    let clean = trim_lws(val);
    if eq_ascii_fold(clean, "same-origin") {
        return CorpPolicy.SameOrigin;
    } else if eq_ascii_fold(clean, "same-site") {
        return CorpPolicy.SameSite;
    } else if eq_ascii_fold(clean, "cross-origin") {
        return CorpPolicy.CrossOrigin;
    }
    return CorpPolicy.None;
}

// Extracts host from an origin or URL string (e.g. "https://example.com:8080" -> "example.com")
fn extract_hostname_from_origin(origin_or_url: const u8[:]) -> const u8[:] {
    var s = trim_lws(origin_or_url);
    if starts_with(s, "https://") { s = s[8..]; }
    else if starts_with(s, "http://") { s = s[7..]; }
    for i in s.len {
        if s[i] == '/' || s[i] == '?' || s[i] == '#' || s[i] == ':' {
            return s[..i];
        }
    }
    return s;
}

// ---- 4. Context Lifecycle & Subresource Verification ------------------------

// Updates isolation context from document response headers and computes crossOriginIsolated status
fn update_isolation_context(
    ctx: CrossOriginIsolationContext&,
    coop_header: const u8[:],
    coep_header: const u8[:],
    document_origin: const u8[:],
) {
    ctx.coop = parse_coop(coop_header);
    ctx.coep = parse_coep(coep_header);
    ctx.document_origin.clear();
    if document_origin.len <= ctx.document_origin.cap {
        ctx.document_origin.append(document_origin);
    }

    // Context is cross-origin isolated if:
    // COOP is same-origin AND COEP is require-corp or credentialless (W3C HTML §7.2)
    ctx.is_cross_origin_isolated = (ctx.coop == CoopPolicy.SameOrigin) &&
                                   (ctx.coep == CoepPolicy.RequireCorp || ctx.coep == CoepPolicy.Credentialless);
}

// Updates isolation context directly from a HeaderMap (RFC 9110 / W3C HTML §7.2)
fn update_from_headers(
    ctx: CrossOriginIsolationContext&,
    headers: const HeaderMap&,
    document_origin: const u8[:],
) {
    let coop = headers.get_header("cross-origin-opener-policy");
    let coep = headers.get_header("cross-origin-embedder-policy");
    update_isolation_context(ctx, coop, coep, document_origin);
}

// Updates isolation context directly from a HeaderItem slice
fn update_from_headers(
    ctx: CrossOriginIsolationContext&,
    headers: const HeaderItem[:],
    document_origin: const u8[:],
) {
    let coop = headers.find_header("cross-origin-opener-policy");
    let coep = headers.find_header("cross-origin-embedder-policy");
    update_isolation_context(ctx, coop, coep, document_origin);
}

// Checks whether a subresource response is permitted to load under the active parent context
fn is_subresource_allowed(
    ctx: const CrossOriginIsolationContext&,
    subresource_origin: const u8[:],
    subresource_corp_header: const u8[:],
) -> bool {
    let is_same_origin = eq_ascii_fold(ctx.document_origin[..], subresource_origin);
    if is_same_origin {
        // Same-origin subresources are always allowed
        return true;
    }

    let corp = parse_corp(subresource_corp_header);

    // If parent context requires CORP (COEP: require-corp)
    if ctx.coep == CoepPolicy.RequireCorp {
        // Under require-corp: cross-origin MUST explicitly opt-in with Cross-Origin-Resource-Policy: cross-origin.
        // If it sends same-site, check whether document and subresource actually share the same eTLD+1!
        if corp == CorpPolicy.SameSite {
            var doc_etld: u8[..128] = [];
            var sub_etld: u8[..128] = [];
            core::extract_etld_plus_one(extract_hostname_from_origin(ctx.document_origin[..]), doc_etld);
            core::extract_etld_plus_one(extract_hostname_from_origin(subresource_origin), sub_etld);
            return doc_etld.len > 0 && sub_etld.len > 0 && eq_ascii_fold(doc_etld[..], sub_etld[..]);
        }
        return corp == CorpPolicy.CrossOrigin;
    }

    // Default browser behavior without require-corp:
    // If subresource declared CORP: same-origin, reject cross-origin embedding
    if corp == CorpPolicy.SameOrigin {
        return false;
    }

    // If subresource declared CORP: same-site, allow only if same-site with document
    if corp == CorpPolicy.SameSite {
        var doc_etld: u8[..128] = [];
        var sub_etld: u8[..128] = [];
        core::extract_etld_plus_one(extract_hostname_from_origin(ctx.document_origin[..]), doc_etld);
        core::extract_etld_plus_one(extract_hostname_from_origin(subresource_origin), sub_etld);
        return doc_etld.len > 0 && sub_etld.len > 0 && eq_ascii_fold(doc_etld[..], sub_etld[..]);
    }

    return true;
}
