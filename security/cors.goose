// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Cross-Origin Resource Sharing (CORS) policy engine.
namespace wing;

import std;
import core from "..";
import rfc.http;

enum CorsResult {
    NoCors,
    AllowedActual,
    AllowedPreflight,
    RejectedOrigin,
    InvalidConfig,
}

struct CorsPolicy {
    allow_credentials:          bool            = false,
    reject_non_matching_origin: bool            = false,
    allowed_origins:            u8[..128][..16] = [],
    allowed_methods:            u8[..128]       = "GET, POST, PUT, DELETE, PATCH, OPTIONS, QUERY",
    allowed_headers:            u8[..256]       = "Content-Type, Authorization, X-Requested-With, X-API-Key",
    expose_headers:             u8[..256]       = "Content-Length, X-Trace-Id, RateLimit-Limit, RateLimit-Reset",
    max_age_sec:                i64             = 86400, // 24 hours preflight cache
}

// Appends an allowed origin pattern to the CORS policy.
fn add_allowed_origin(policy: CorsPolicy&, origin_pattern: const u8[:]) -> bool {
    guard policy.allowed_origins.len < policy.allowed_origins.cap else { return false; }
    let trimmed = trim_lws(origin_pattern);
    guard trimmed.len > 0 && trimmed.len <= 128 else { return false; }
    var entry: u8[..128] = [];
    entry.append(trimmed);
    policy.allowed_origins.push(entry);
    return true;
}

// Validates characters in a CORS subdomain label sequence (RFC 1035 / WHATWG Fetch §3.2).
//
// Example:
//   sub = "stage.app"
//   returns: true
inline fn validate_cors_subdomain(sub: const u8[:]) -> bool {
    var prev_dot = false;
    for i in sub.len {
        let b = sub[i];
        let is_alnum = (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z') || (b >= '0' && b <= '9');
        if b == '.' {
            if prev_dot || i == 0 || i == sub.len - 1 { return false; }
            prev_dot = true;
        } else if b == '-' {
            if prev_dot || i == 0 || i == sub.len - 1 { return false; }
            if i + 1 < sub.len && sub[i + 1] == '.' { return false; }
            prev_dot = false;
        } else if is_alnum {
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
    guard starts_with_fold(pat_rest, "*.") else { return false; }
    let domain_suffix = pat_rest[2..];
    guard core::contains_byte(domain_suffix, '.') else { return false; }
    guard cand_rest.len > domain_suffix.len && ends_with_fold(cand_rest, domain_suffix) else { return false; }
    let prefix_len = cand_rest.len - domain_suffix.len;
    guard cand_rest[prefix_len - 1] == '.' else { return false; }

    let sub = cand_rest[..prefix_len - 1];
    guard sub.len > 0 else { return false; }
    return validate_cors_subdomain(sub);
}

// Matches origin against a pattern with strict scheme and subdomain enforcement:
// E.g. pattern "https://*.example.com" matches "https://app.example.com",
// but REJECTS "http://app.example.com", "https://evil.com", "https://notexample.com".
//
// Example:
//   candidate = "https://api.example.com", pattern = "https://*.example.com"
//   returns: true
fn match_cors_origin_pattern(candidate: const u8[:], pattern: const u8[:]) -> bool {
    let cand = trim_lws(candidate);
    let pat = trim_lws(pattern);
    guard cand.len > 0 && pat.len > 0 else { return false; }

    // RFC 6454 / Fetch §3.2.2: Opaque origin "null" MUST NOT match wildcard '*' or subdomain patterns
    if eq_ascii_fold(cand, "null") {
        return eq_ascii_fold(pat, "null");
    }

    if pat == "*" || eq_ascii_fold(cand, pat) {
        return true;
    }

    // Protocol-specific wildcard: check scheme prefix up to "://"
    let cand_scheme, cand_rest, cand_ok = split_once(cand, "://");
    let pat_scheme, pat_rest, pat_ok = split_once(pat, "://");
    guard cand_ok && pat_ok else { return false; }
    guard eq_ascii_fold(cand_scheme, pat_scheme) else { return false; }

    return match_cors_wildcard_host(cand_rest, pat_rest);
}

// Validates whether the incoming Origin is permitted under policy.
fn is_origin_allowed(policy: const CorsPolicy&, origin_str: const u8[:]) -> bool {
    let clean_origin = trim_lws(origin_str);
    guard clean_origin.len > 0 else { return false; }

    // Disallow "null" origin when credentials are enabled (RFC 6454 / Fetch §3.2.2)
    if policy.allow_credentials && eq_ascii_fold(clean_origin, "null") {
        return false;
    }

    for idx in policy.allowed_origins.len {
        let pat = trim_lws(policy.allowed_origins[idx][..]);
        // Wildcard origin is forbidden when credentials are enabled
        if policy.allow_credentials && pat == "*" {
            continue;
        }
        if match_cors_origin_pattern(clean_origin, pat) {
            return true;
        }
    }
    return false;
}

// Returns true if the policy configures any wildcard '*' origins.
fn has_wildcard_origin(policy: const CorsPolicy&) -> bool {
    guard policy.allowed_origins.len > 0 else { return false; }
    for idx in policy.allowed_origins.len {
        if trim_lws(policy.allowed_origins[idx][..]) == "*" {
            return true;
        }
    }
    return false;
}

// Validates policy configuration invariants (Fetch §3.2.2 forbids '*' with allow_credentials).
fn validate_cors_policy(policy: const CorsPolicy&) -> bool {
    return !(policy.allow_credentials && has_wildcard_origin(policy));
}

// Checks whether a comma-separated HTTP header value contains a specific token (case-insensitive, RFC 9110 §5.6.1).
inline fn header_list_has_token(header_val: const u8[:], token: const u8[:]) -> bool {
    var rest = header_val;
    while rest.len > 0 {
        let item, after, has_comma = split_once(rest, ",");
        let trimmed = trim_lws(item);
        if trimmed == "*" || eq_ascii_fold(trimmed, token) {
            return true;
        }
        if !has_comma { break; }
        rest = after;
    }
    return false;
}

// Injects Vary: Origin header on dynamic CORS responses (RFC 9111 / WHATWG Fetch §3.2.4).
inline fn apply_cors_vary_header<Res>(res: Res&) {
    let existing_vary = res.headers.find_header(rfc::HEADER_VARY);
    if existing_vary.len == 0 {
        res.headers.set_header(rfc::HEADER_VARY, rfc::HEADER_ORIGIN);
    } else if !header_list_has_token(existing_vary, rfc::HEADER_ORIGIN) {
        guard existing_vary.len + 8 <= 2048 else { return; }
        var new_vary: u8[..2048] = [];
        new_vary.append(existing_vary);
        new_vary.append(", Origin");
        res.headers.set_header(rfc::HEADER_VARY, new_vary[..]);
    }
}

// Populates preflight response headers and sets 204 No Content status.
fn apply_cors_preflight_headers<Res>(policy: const CorsPolicy&, res: Res&) {
    if policy.allowed_methods.len > 0 {
        res.headers.set_header(rfc::HEADER_ACCESS_CONTROL_ALLOW_METHODS, policy.allowed_methods[..]);
    }
    if policy.allowed_headers.len > 0 {
        res.headers.set_header(rfc::HEADER_ACCESS_CONTROL_ALLOW_HEADERS, policy.allowed_headers[..]);
    }
    if policy.max_age_sec > 0 {
        var age_str: u8[..32] = [];
        core::format_i64_dec(policy.max_age_sec, age_str);
        res.headers.set_header(rfc::HEADER_ACCESS_CONTROL_MAX_AGE, age_str[..]);
    }
    res.status_code = rfc::STATUS_NO_CONTENT;
}

// Evaluates CORS rules against request Origin and populates response headers.
// Returns CorsResult indicating whether the request was allowed, preflighted, or rejected.
// Wildcard '*' origin is disallowed when allow_credentials is true.
fn evaluate_cors<Req, Res>(policy: const CorsPolicy&, req: const Req&, res: Res&) -> CorsResult {
    let origin_raw = req.headers.find_header(rfc::HEADER_ORIGIN);
    guard origin_raw.len > 0 else { return CorsResult.NoCors; }
    let origin = trim_lws(origin_raw);
    guard origin.len > 0 else { return CorsResult.NoCors; }

    // Check configuration validity: allow_credentials == true with wildcard "*" origin is invalid (Fetch §3.2.2)
    if !validate_cors_policy(policy) {
        return CorsResult.InvalidConfig;
    }

    guard is_origin_allowed(policy, origin) else {
        return CorsResult.RejectedOrigin;
    }

    let is_wildcard_allow = !policy.allow_credentials && has_wildcard_origin(policy);
    let allow_origin_val = if is_wildcard_allow { "*" } else { origin };
    res.headers.set_header(rfc::HEADER_ACCESS_CONTROL_ALLOW_ORIGIN, allow_origin_val);

    if !is_wildcard_allow {
        apply_cors_vary_header(res);
    }

    if policy.allow_credentials {
        res.headers.set_header(rfc::HEADER_ACCESS_CONTROL_ALLOW_CREDENTIALS, "true");
    }

    let req_method_hdr = trim_lws(req.headers.find_header(rfc::HEADER_ACCESS_CONTROL_REQUEST_METHOD));
    if req.method[..] == rfc::METHOD_OPTIONS && req_method_hdr.len > 0 {
        apply_cors_preflight_headers(policy, res);
        return CorsResult.AllowedPreflight;
    }

    if policy.expose_headers.len > 0 {
        res.headers.set_header(rfc::HEADER_ACCESS_CONTROL_EXPOSE_HEADERS, policy.expose_headers[..]);
    }

    return CorsResult.AllowedActual;
}
