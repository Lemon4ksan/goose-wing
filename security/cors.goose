// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Cross-Origin Resource Sharing (CORS) policy engine.
namespace wing;

import std;
import core from "..";

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
    guard origin_pattern.len <= 128 else { return false; }
    var entry: u8[..128] = [];
    entry.append(origin_pattern);
    policy.allowed_origins.push(entry);
    return true;
}

// Matches origin against a pattern with strict scheme and subdomain enforcement:
// E.g. pattern "https://*.example.com" matches "https://app.example.com",
// but REJECTS "http://app.example.com", "https://evil.com", "https://notexample.com".
fn match_cors_origin_pattern(candidate: const u8[:], pattern: const u8[:]) -> bool {
    let cand = trim_lws(candidate);
    let pat = trim_lws(pattern);
    guard cand.len > 0 && pat.len > 0 else { return false; }

    if pat == "*" || eq_ascii_fold(cand, pat) {
        return true;
    }

    // Protocol-specific wildcard: check scheme prefix up to "://"
    let cand_scheme, cand_rest, cand_ok = split_once(cand, "://");
    let pat_scheme, pat_rest, pat_ok = split_once(pat, "://");
    guard cand_ok && pat_ok else { return false; }
    guard eq_ascii_fold(cand_scheme, pat_scheme) else { return false; }

    // Check if pattern contains wildcard "*.domain"
    guard starts_with_fold(pat_rest, "*.") else { return false; }
    let domain_suffix = pat_rest[2..];
    guard cand_rest.len > domain_suffix.len && ends_with_fold(cand_rest, domain_suffix) else { return false; }
    let prefix_len = cand_rest.len - domain_suffix.len;
    return cand_rest[prefix_len - 1] == '.';
}

// Validates whether the incoming Origin is permitted under policy.
fn is_origin_allowed(policy: const CorsPolicy&, origin_str: const u8[:]) -> bool {
    let clean_origin = trim_lws(origin_str);
    guard clean_origin.len > 0 else { return false; }

    // Disallow "null" origin when credentials are enabled
    if policy.allow_credentials && clean_origin == "null" {
        return false;
    }

    for idx in policy.allowed_origins.len {
        let pat = policy.allowed_origins[idx][..];
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
fn apply_cors_preflight_headers<Res>(policy: const CorsPolicy&, res: Res&) {
    if policy.allowed_methods.len > 0 {
        res.headers.set_header("Access-Control-Allow-Methods", policy.allowed_methods[..]);
    }
    if policy.allowed_headers.len > 0 {
        res.headers.set_header("Access-Control-Allow-Headers", policy.allowed_headers[..]);
    }
    if policy.max_age_sec > 0 {
        var age_str: u8[..32] = [];
        core::format_i64_dec(policy.max_age_sec, age_str);
        res.headers.set_header("Access-Control-Max-Age", age_str[..]);
    }
    res.status_code = 204; // No Content
}

// Evaluates CORS rules against request Origin and populates response headers.
// Returns CorsResult indicating whether the request was allowed, preflighted, or rejected.
// Wildcard '*' origin is disallowed when allow_credentials is true.
fn evaluate_cors<Req, Res>(policy: const CorsPolicy&, req: const Req&, res: Res&) -> CorsResult {
    let origin_raw = req.headers.find_header("Origin");
    guard origin_raw.len > 0 else { return CorsResult.NoCors; }
    let origin = trim_lws(origin_raw);
    guard origin.len > 0 else { return CorsResult.NoCors; }

    // Check configuration validity: allow_credentials == true with only "*" origin is invalid
    if policy.allow_credentials && has_only_wildcard_origin(policy) {
        return CorsResult.InvalidConfig;
    }

    guard is_origin_allowed(policy, origin) else {
        return CorsResult.RejectedOrigin;
    }

    let is_single_wildcard = policy.allowed_origins.len == 1 && policy.allowed_origins[0][..] == "*";
    let allow_origin_val = if !policy.allow_credentials && is_single_wildcard { "*" } else { origin };
    res.headers.set_header("Access-Control-Allow-Origin", allow_origin_val);

    if policy.allow_credentials {
        res.headers.set_header("Access-Control-Allow-Credentials", "true");
    }

    if req.method[..] == "OPTIONS" {
        apply_cors_preflight_headers(policy, res);
        return CorsResult.AllowedPreflight;
    }

    if policy.expose_headers.len > 0 {
        res.headers.set_header("Access-Control-Expose-Headers", policy.expose_headers[..]);
    }

    return CorsResult.AllowedActual;
}
