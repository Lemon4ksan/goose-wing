// W3C Cross-Origin Isolation Engine (COOP, COEP, CORP).
// Enforces HTML5 §7.2 Cross-Origin-Opener-Policy, Cross-Origin-Embedder-Policy,
// and Cross-Origin-Resource-Policy for Spectre process sandboxing and secure context verification.
namespace wing;

import std;

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
    if eq_ascii_fold(val, "same-origin") {
        return CoopPolicy.SameOrigin;
    } else if eq_ascii_fold(val, "same-origin-allow-popups") {
        return CoopPolicy.SameOriginAllowPopups;
    }
    return CoopPolicy.UnsafeNone;
}

fn parse_coep(val: const u8[:]) -> CoepPolicy {
    if eq_ascii_fold(val, "require-corp") {
        return CoepPolicy.RequireCorp;
    } else if eq_ascii_fold(val, "credentialless") {
        return CoepPolicy.Credentialless;
    }
    return CoepPolicy.UnsafeNone;
}

fn parse_corp(val: const u8[:]) -> CorpPolicy {
    if eq_ascii_fold(val, "same-origin") {
        return CorpPolicy.SameOrigin;
    } else if eq_ascii_fold(val, "same-site") {
        return CorpPolicy.SameSite;
    } else if eq_ascii_fold(val, "cross-origin") {
        return CorpPolicy.CrossOrigin;
    }
    return CorpPolicy.None;
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
    ctx.document_origin.append(document_origin);

    // Context is cross-origin isolated if:
    // COOP is same-origin AND COEP is require-corp or credentialless (W3C HTML §7.2)
    ctx.is_cross_origin_isolated = (ctx.coop == CoopPolicy.SameOrigin) &&
                                   (ctx.coep == CoepPolicy.RequireCorp || ctx.coep == CoepPolicy.Credentialless);
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
        // Subresource MUST explicitly opt in via Cross-Origin-Resource-Policy: cross-origin
        return corp == CorpPolicy.CrossOrigin;
    }

    // Default browser behavior without require-corp:
    // If subresource declared CORP: same-origin, reject cross-origin embedding
    if corp == CorpPolicy.SameOrigin {
        return false;
    }

    return true;
}
