// Fetch Metadata resource isolation and cross-origin request protection.
namespace wing;

import std;
import core.url;
import app.profile;
import app.request;
import app.response;

// ---- fetch metadata attribute taxonomy -------------------------------------

enum SecFetchSite {
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
    method_is_safe: bool = true,
    method: u8[..16] = "GET",
    site: SecFetchSite = SecFetchSite.Missing,
    mode: SecFetchMode = SecFetchMode.Other,
    dest: SecFetchDest = SecFetchDest.Other,
    user_activated: bool = false,
    has_origin: bool = false,
    origin: u8[..256] = [],
    has_referer: bool = false,
    referer: u8[..512] = [],
    target_scheme: u8[..16] = "https",
    target_host: u8[..256] = [],
    path: u8[..512] = "/",
    has_session_cookie: bool = false,
    has_explicit_auth: bool = false,
    is_sensitive_navigation_route: bool = false,
}

// Parses Sec-Fetch-Site string value.
fn parse_sec_fetch_site(val: const u8[:]) -> SecFetchSite {
    let clean = trim(val);
    if clean == "same-origin" { return SecFetchSite.SameOrigin; }
    if clean == "same-site" { return SecFetchSite.SameSite; }
    if clean == "cross-site" { return SecFetchSite.CrossSite; }
    if clean == "none" { return SecFetchSite.None; }
    return SecFetchSite.Missing;
}

// Parses Sec-Fetch-Mode string value.
fn parse_sec_fetch_mode(val: const u8[:]) -> SecFetchMode {
    let clean = trim(val);
    if clean == "navigate" { return SecFetchMode.Navigate; }
    if clean == "same-origin" { return SecFetchMode.SameOrigin; }
    if clean == "cors" { return SecFetchMode.Cors; }
    if clean == "no-cors" { return SecFetchMode.NoCors; }
    if clean == "websocket" { return SecFetchMode.WebSocket; }
    return SecFetchMode.Other;
}

// Parses Sec-Fetch-Dest string value.
fn parse_sec_fetch_dest(val: const u8[:]) -> SecFetchDest {
    let clean = trim(val);
    if clean == "document" { return SecFetchDest.Document; }
    if clean == "nested-document" { return SecFetchDest.NestedDocument; }
    if clean == "iframe" { return SecFetchDest.Iframe; }
    if clean == "frame" { return SecFetchDest.Frame; }
    if clean == "embed" { return SecFetchDest.Embed; }
    if clean == "object" { return SecFetchDest.Object; }
    if clean == "script" { return SecFetchDest.Script; }
    if clean == "image" { return SecFetchDest.Image; }
    if clean == "style" { return SecFetchDest.Style; }
    if clean == "font" { return SecFetchDest.Font; }
    if clean == "empty" { return SecFetchDest.Empty; }
    return SecFetchDest.Other;
}

// ---- crossoriginguard policy & state machine -------------------------------

struct CrossOriginGuard {
    allow_same_site: bool = false,
    require_user_activation_on_sensitive_nav: bool = true,
    allow_cross_site_static_assets: bool = true,
    trusted_origins: u8[..128][..16] = [],
    exempt_paths: u8[..128][..16] = [],
}

fn new_cross_origin_guard() -> CrossOriginGuard {
    return CrossOriginGuard { .. };
}

fn add_trusted_origin(guard_cfg: CrossOriginGuard&, origin_str: const u8[:]) -> bool {
    guard guard_cfg.trusted_origins.len < guard_cfg.trusted_origins.cap else { return false; }
    var entry: u8[..128] = [];
    entry.append(origin_str);
    guard_cfg.trusted_origins.push(entry);
    return true;
}

fn add_exempt_path(guard_cfg: CrossOriginGuard&, path_str: const u8[:]) -> bool {
    guard guard_cfg.exempt_paths.len < guard_cfg.exempt_paths.cap else { return false; }
    var entry: u8[..128] = [];
    entry.append(path_str);
    guard_cfg.exempt_paths.push(entry);
    return true;
}

fn is_path_exempt(guard_cfg: const CrossOriginGuard&, path_str: const u8[:]) -> bool {
    for idx in guard_cfg.exempt_paths.len {
        if guard_cfg.exempt_paths[idx][..] == path_str {
            return true;
        }
    }
    return false;
}

fn is_origin_trusted(guard_cfg: const CrossOriginGuard&, origin_str: const u8[:]) -> bool {
    guard origin_str.len > 0 else { return false; }
    for idx in guard_cfg.trusted_origins.len {
        if guard_cfg.trusted_origins[idx][..] == origin_str {
            return true;
        }
    }
    return false;
}

// Extracts host from URL or Origin string (e.g. "https://example.com:8080" -> "example.com:8080")
fn extract_host_from_url(url_or_origin: const u8[:]) -> const u8[:] {
    var s = url_or_origin;
    if starts_with(s, "https://") { s = s[8..]; }
    else if starts_with(s, "http://") { s = s[7..]; }
    for i in s.len {
        if s[i] == '/' || s[i] == '?' || s[i] == '#' {
            return s[..i];
        }
    }
    return s;
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
    if ctx.mode == SecFetchMode.Navigate && (ctx.dest == SecFetchDest.Document || ctx.dest == SecFetchDest.NestedDocument) {
        if ctx.is_sensitive_navigation_route && guard_cfg.require_user_activation_on_sensitive_nav && !ctx.user_activated {
            return CsrfDecision.RejectForbidden { reason: CsrfRejectReason.MissingUserActivationOnSensitiveNav };
        }
        return CsrfDecision.Allow;
    }

    // Cross-site embedding into frame/object/embed/script -> block XS-Leaks / XSSI
    if ctx.dest == SecFetchDest.Iframe || ctx.dest == SecFetchDest.Frame ||
       ctx.dest == SecFetchDest.Object || ctx.dest == SecFetchDest.Embed ||
       ctx.dest == SecFetchDest.Script {
        return CsrfDecision.RejectForbidden { reason: CsrfRejectReason.CrossSiteFramingOrXssi };
    }

    // Cross-site subresources
    if guard_cfg.allow_cross_site_static_assets &&
       (ctx.dest == SecFetchDest.Image || ctx.dest == SecFetchDest.Style || ctx.dest == SecFetchDest.Font) {
        return CsrfDecision.Allow;
    }

    return CsrfDecision.RejectForbidden { reason: CsrfRejectReason.CrossSiteUnauthorizedSubresource };
}

fn evaluate_fallback_origin_fetch(guard_cfg: const CrossOriginGuard&, ctx: const FetchContext&) -> CsrfDecision {
    let candidate = if ctx.has_origin { ctx.origin[..] } else { ctx.referer[..] };
    let candidate_host = extract_host_from_url(candidate);

    if candidate_host.len > 0 && candidate_host == ctx.target_host[..] {
        return CsrfDecision.Allow;
    }
    if is_origin_trusted(guard_cfg, candidate) {
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

    if ctx.site == SecFetchSite.CrossSite {
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

// Extracts FetchContext from an incoming Request.
fn extract_fetch_context(req: const Request&, target_host: const u8[:]) -> FetchContext {
    var ctx = FetchContext { .. };
    ctx.method.append(req.method[..]);
    ctx.method_is_safe = (req.method[..] == "GET" || req.method[..] == "HEAD" || req.method[..] == "OPTIONS");
    ctx.target_host.append(target_host);

    for idx in req.headers.len {
        let name = req.headers[idx].name[..];
        let val = req.headers[idx].value[..];

        if eq_ascii_fold(name, "Sec-Fetch-Site") {
            ctx.site = parse_sec_fetch_site(val);
        } else if eq_ascii_fold(name, "Sec-Fetch-Mode") {
            ctx.mode = parse_sec_fetch_mode(val);
        } else if eq_ascii_fold(name, "Sec-Fetch-Dest") {
            ctx.dest = parse_sec_fetch_dest(val);
        } else if eq_ascii_fold(name, "Sec-Fetch-User") {
            ctx.user_activated = (trim(val) == "?1");
        } else if eq_ascii_fold(name, "Origin") {
            ctx.origin.append(trim(val));
            ctx.has_origin = true;
        } else if eq_ascii_fold(name, "Referer") {
            ctx.referer.append(trim(val));
            ctx.has_referer = true;
        } else if eq_ascii_fold(name, "Cookie") {
            ctx.has_session_cookie = true;
        } else if eq_ascii_fold(name, "Authorization") || eq_ascii_fold(name, "X-API-Key") {
            ctx.has_explicit_auth = true;
        }
    }

    return ctx;
}

// Injects Vary and HSTS headers on protected responses to prevent proxy cache desynchronization.
fn apply_isolation_headers(res: Response&) {
    let vary_key = "Vary";
    let vary_val = "Sec-Fetch-Dest, Sec-Fetch-Mode, Sec-Fetch-Site, Origin";

    var found_vary = false;
    for &hdr in res.headers {
        if eq_ascii_fold(hdr.name[..], vary_key) {
            found_vary = true;
            if find(hdr.value[..], "Sec-Fetch-Site") < 0 {
                hdr.value.append(", ");
                hdr.value.append(vary_val);
            }
            break;
        }
    }
    if !found_vary && res.headers.len < res.headers.cap {
        res.headers.push(make_header(vary_key, vary_val));
    }

    var found_hsts = false;
    for &hdr in res.headers {
        if eq_ascii_fold(hdr.name[..], "Strict-Transport-Security") {
            found_hsts = true;
            break;
        }
    }
    if !found_hsts && res.headers.len < res.headers.cap {
        res.headers.push(make_header("Strict-Transport-Security", "max-age=63072000; includeSubDomains; preload"));
    }
}
