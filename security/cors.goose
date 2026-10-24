// Cross-Origin Resource Sharing (CORS) policy engine.
namespace wing;

import std;
import client.request;
import client.response;

enum CorsResult {
    NoCors,
    AllowedActual,
    AllowedPreflight,
    RejectedOrigin,
    InvalidConfig,
}

struct CorsPolicy {
    allow_credentials: bool = false,
    allowed_origins: u8[..128][..16] = [],
    allowed_methods: u8[..128] = "GET, POST, PUT, DELETE, PATCH, OPTIONS",
    allowed_headers: u8[..256] = "Content-Type, Authorization, X-Requested-With, X-API-Key",
    expose_headers: u8[..256] = "Content-Length, X-Trace-Id, RateLimit-Limit, RateLimit-Remaining, RateLimit-Reset",
    max_age_sec: i64 = 86400, // 24 hours preflight cache
}

// Creates a default CORS policy.
fn new_cors_policy() -> CorsPolicy {
    return CorsPolicy { .. };
}

// Appends an allowed origin pattern to the CORS policy.
fn add_allowed_origin(policy: CorsPolicy&, origin_pattern: const u8[:]) -> bool {
    guard policy.allowed_origins.len < policy.allowed_origins.cap else { return false; }
    var entry: u8[..128] = [];
    entry.append(origin_pattern);
    policy.allowed_origins.push(entry);
    return true;
}

// Matches origin against a pattern with strict scheme and subdomain enforcement:
// E.g. pattern "https://*.example.com" matches "https://app.example.com",
// but REJECTS "http://app.example.com", "https://evil.com", "https://notexample.com".
fn match_cors_origin_pattern(candidate: const u8[:], pattern: const u8[:]) -> bool {
    guard candidate.len > 0 && pattern.len > 0 else { return false; }

    if pattern == "*" || candidate == pattern {
        return true;
    }

    // Protocol-specific wildcard: check scheme prefix up to "://"
    var cand_colon = -1;
    for i in candidate.len {
        if candidate[i] == ':' { cand_colon = i; break; }
    }
    var pat_colon = -1;
    for i in pattern.len {
        if pattern[i] == ':' { pat_colon = i; break; }
    }
    guard cand_colon > 0 && pat_colon > 0 else { return false; }
    guard candidate[..cand_colon] == pattern[..pat_colon] else { return false; }

    let cand_host = candidate[cand_colon + 3..];
    let pat_host = pattern[pat_colon + 3..];

    // Check if pattern contains wildcard "*.domain"
    guard starts_with(pat_host, "*.") else { return false; }
    let domain_suffix = pat_host[2..];
    guard cand_host.len > domain_suffix.len && ends_with(cand_host, domain_suffix) else { return false; }
    let prefix_len = cand_host.len - domain_suffix.len;
    return cand_host[prefix_len - 1] == '.';
}

// Validates whether the incoming Origin is permitted under policy.
fn is_cors_origin_allowed(policy: const CorsPolicy&, origin_str: const u8[:]) -> bool {
    guard origin_str.len > 0 else { return false; }

    // Disallow "null" origin when credentials are enabled
    if policy.allow_credentials && origin_str == "null" {
        return false;
    }

    for idx in policy.allowed_origins.len {
        let pat = policy.allowed_origins[idx][..];
        // Wildcard origin is forbidden when credentials are enabled
        if policy.allow_credentials && pat == "*" {
            continue;
        }
        if match_cors_origin_pattern(origin_str, pat) {
            return true;
        }
    }
    return false;
}

// Returns true if the policy configures only wildcard '*' origins.
fn has_only_wildcard_origin(policy: const CorsPolicy&) -> bool {
    guard policy.allowed_origins.len > 0 else { return false; }
    for idx in policy.allowed_origins.len {
        if policy.allowed_origins[idx][..] != "*" {
            return false;
        }
    }
    return true;
}

// Populates preflight response headers and sets 204 No Content status.
fn apply_cors_preflight_headers(policy: const CorsPolicy&, res: Response&) {
    if policy.allowed_methods.len > 0 {
        res.headers.push(make_header("Access-Control-Allow-Methods", policy.allowed_methods[..]));
    }
    if policy.allowed_headers.len > 0 {
        res.headers.push(make_header("Access-Control-Allow-Headers", policy.allowed_headers[..]));
    }
    if policy.max_age_sec > 0 {
        var age_str: u8[..32] = [];
        format(age_str, policy.max_age_sec);
        res.headers.push(make_header("Access-Control-Max-Age", age_str[..]));
    }
    res.status_code = 204; // No Content
}

// Evaluates CORS rules against request Origin and populates response headers.
// Returns CorsResult indicating whether the request was allowed, preflighted, or rejected.
// Wildcard '*' origin is disallowed when allow_credentials is true.
fn evaluate_cors(policy: const CorsPolicy&, req: const Request&, res: Response&) -> CorsResult {
    var origin_idx: i32 = -1;
    for idx in req.headers.len {
        if eq_ascii_fold(req.headers[idx].name[..], "Origin") {
            origin_idx = idx as i32;
            break;
        }
    }

    guard origin_idx >= 0 else { return CorsResult.NoCors; }
    let origin = trim(req.headers[origin_idx].value[..]);
    guard origin.len > 0 else { return CorsResult.NoCors; }

    // Check configuration validity: allow_credentials == true with only "*" origin is invalid
    if policy.allow_credentials && has_only_wildcard_origin(policy) {
        return CorsResult.InvalidConfig;
    }

    guard is_cors_origin_allowed(policy, origin) else {
        return CorsResult.RejectedOrigin;
    }

    let is_single_wildcard = policy.allowed_origins.len == 1 && policy.allowed_origins[0][..] == "*";
    let allow_origin_val = if !policy.allow_credentials && is_single_wildcard { "*" } else { origin };
    res.headers.push(make_header("Access-Control-Allow-Origin", allow_origin_val));

    if policy.allow_credentials {
        res.headers.push(make_header("Access-Control-Allow-Credentials", "true"));
    }

    if req.method[..] == "OPTIONS" {
        apply_cors_preflight_headers(policy, res);
        return CorsResult.AllowedPreflight;
    }

    if policy.expose_headers.len > 0 {
        res.headers.push(make_header("Access-Control-Expose-Headers", policy.expose_headers[..]));
    }

    return CorsResult.AllowedActual;
}
