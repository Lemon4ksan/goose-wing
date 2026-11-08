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
    RejectedPreflightMethod,
    RejectedPreflightHeaders,
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
    let trimmed = origin_pattern.trim_lws();
    guard trimmed.len > 0 else { return false; }
    var entry: u8[..128] = [];
    guard entry.try_set(trimmed) else { return false; }
    return policy.allowed_origins.try_push(entry);
}

// Validates characters in a CORS subdomain label sequence (RFC 1035 / WHATWG Fetch §3.2).
//
// Example:
//   sub = "stage.app"
//   returns: true
inline fn validate_cors_subdomain(sub: const u8[:]) -> bool {
    var prev_dot = false;
    let last_idx = core::sub_sat_i64(sub.len, 1);
    for i in sub.len {
        let b = sub[i];
        if b == '.' {
            if prev_dot || i == 0 || i == last_idx { return false; }
            prev_dot = true;
        } else if b == '-' {
            if prev_dot || i == 0 || i == last_idx { return false; }
            let next_idx = core::add_sat_i64(i, 1);
            if next_idx < sub.len && sub[next_idx] == '.' { return false; }
            prev_dot = false;
        } else if core::is_ascii_alphanumeric(b) {
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
    guard pat_rest.starts_with_fold("*.") else { return false; }
    let domain_suffix = pat_rest[2..];
    guard domain_suffix.contains_byte('.') else { return false; }
    guard cand_rest.len > domain_suffix.len && cand_rest.ends_with_fold(domain_suffix) else { return false; }
    let prefix_len = core::sub_sat_i64(cand_rest.len, domain_suffix.len);
    let dot_idx = core::sub_sat_i64(prefix_len, 1);
    guard dot_idx > 0 && cand_rest[dot_idx] == '.' else { return false; }

    let sub = cand_rest[..dot_idx];
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
    let cand = candidate.trim_lws();
    let pat = pattern.trim_lws();
    guard cand.len > 0 && pat.len > 0 else { return false; }

    // RFC 6454 / Fetch §3.2.2: Opaque origin "null" MUST NOT match wildcard '*' or subdomain patterns
    if cand.eq_ascii_fold("null") {
        return pat.eq_ascii_fold("null");
    }

    if pat == "*" || cand.eq_ascii_fold(pat) {
        return true;
    }

    // Protocol-specific wildcard: check scheme prefix up to "://"
    let cand_scheme, cand_rest, cand_ok = cand.split_once("://");
    let pat_scheme, pat_rest, pat_ok = pat.split_once("://");
    guard cand_ok && pat_ok else { return false; }
    guard cand_scheme.eq_ascii_fold(pat_scheme) else { return false; }

    return match_cors_wildcard_host(cand_rest, pat_rest);
}

// Validates whether the incoming Origin is permitted under policy.
fn is_origin_allowed(policy: const CorsPolicy&, origin_str: const u8[:]) -> bool {
    let clean_origin = origin_str.trim_lws();
    guard clean_origin.len > 0 else { return false; }

    // Disallow "null" origin when credentials are enabled (RFC 6454 / Fetch §3.2.2)
    if policy.allow_credentials && clean_origin.eq_ascii_fold("null") {
        return false;
    }

    for idx in policy.allowed_origins.len {
        let pat = policy.allowed_origins[idx][..].trim_lws();
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
        if policy.allowed_origins[idx][..].trim_lws() == "*" {
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
    var tok_iter = core::make_byte_tokenizer(header_val, ',');
    loop {
        let item, ok = core::token_next(tok_iter);
        guard ok else { break; }
        let trimmed = item.trim_lws();
        if trimmed == "*" || trimmed.eq_ascii_fold(token) {
            return true;
        }
    }
    return false;
}

// Injects Vary: Origin header on dynamic CORS responses (RFC 9111 / WHATWG Fetch §3.2.4).
inline fn apply_cors_vary_header<Res>(res: Res&) {
    let existing_vary = res.headers.find_header(rfc::HEADER_VARY);
    if existing_vary.len == 0 {
        res.headers.set_header(rfc::HEADER_VARY, rfc::HEADER_ORIGIN);
    } else if !header_list_has_token(existing_vary, rfc::HEADER_ORIGIN) {
        var new_vary: u8[..2048] = [];
        guard new_vary.try_set(existing_vary) else { return; }
        guard new_vary.try_append(", Origin") else { return; }
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
        policy.max_age_sec.format_i64_dec(age_str);
        res.headers.set_header(rfc::HEADER_ACCESS_CONTROL_MAX_AGE, age_str[..]);
    }
    res.status_code = rfc::STATUS_NO_CONTENT;
}

// Checks whether all comma-separated tokens in `requested_list` are present in `allowed_list` (WHATWG Fetch §3.2.3).
fn are_cors_request_headers_allowed(allowed_list: const u8[:], requested_list: const u8[:]) -> bool {
    var tok_iter = core::make_byte_tokenizer(requested_list, ',');
    loop {
        let item, ok = core::token_next(tok_iter);
        guard ok else { break; }
        let tok = item.trim_lws();
        if tok.len > 0 {
            let safelisted = tok.eq_ascii_fold("accept") ||
                tok.eq_ascii_fold("accept-language") ||
                tok.eq_ascii_fold("content-language");
            if !safelisted && !header_list_has_token(allowed_list, tok) {
                return false;
            }
        }
    }
    return true;
}

struct ClientCorsVerifyOptions {
    tainted_origin:      bool = false,
    include_credentials: bool = false,
}

// Validates an inbound HTTP response against WHATWG Fetch §4.9 CORS protocol check on the client side.
fn verify_client_cors_response<H>(
    resp_headers:   const H&,
    request_origin: const u8[:],
    opts:           ClientCorsVerifyOptions = ClientCorsVerifyOptions { .. },
) -> bool {
    let acao = resp_headers.find_header(rfc::HEADER_ACCESS_CONTROL_ALLOW_ORIGIN).trim_lws();
    guard acao.len > 0 else { return false; }
    let expected_origin = if opts.tainted_origin { "null" } else { request_origin.trim_lws() };

    if opts.include_credentials {
        guard acao != "*" && acao.eq_ascii_fold(expected_origin) else { return false; }
        let acac = resp_headers.find_header(rfc::HEADER_ACCESS_CONTROL_ALLOW_CREDENTIALS).trim_lws();
        return acac == "true";
    }

    if acao == "*" {
        return true;
    }
    return acao.eq_ascii_fold(expected_origin);
}

// Evaluates CORS rules against request Origin and populates response headers.
// Returns CorsResult indicating whether the request was allowed, preflighted, or rejected.
// Wildcard '*' origin is disallowed when allow_credentials is true.
fn evaluate_cors<Req, Res>(policy: const CorsPolicy&, req: const Req&, res: Res&) -> CorsResult {
    let origin_raw = req.headers.find_header(rfc::HEADER_ORIGIN);
    guard origin_raw.len > 0 else { return CorsResult.NoCors; }
    let origin = origin_raw.trim_lws();
    guard origin.len > 0 else { return CorsResult.NoCors; }

    // Check configuration validity: allow_credentials == true with wildcard "*" origin is invalid (Fetch §3.2.2)
    if !validate_cors_policy(policy) {
        return CorsResult.InvalidConfig;
    }

    guard is_origin_allowed(policy, origin) else {
        return CorsResult.RejectedOrigin;
    }

    let req_method_hdr = req.headers.find_header(rfc::HEADER_ACCESS_CONTROL_REQUEST_METHOD).trim_lws();
    let is_preflight = req.method[..] == rfc::METHOD_OPTIONS && req_method_hdr.len > 0;
    if is_preflight {
        guard header_list_has_token(policy.allowed_methods[..], req_method_hdr) else {
            return CorsResult.RejectedPreflightMethod;
        }
        let req_hdrs = req.headers.find_header(rfc::HEADER_ACCESS_CONTROL_REQUEST_HEADERS).trim_lws();
        if req_hdrs.len > 0 && !are_cors_request_headers_allowed(policy.allowed_headers[..], req_hdrs) {
            return CorsResult.RejectedPreflightHeaders;
        }
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

    if is_preflight {
        apply_cors_preflight_headers(policy, res);
        return CorsResult.AllowedPreflight;
    }

    if policy.expose_headers.len > 0 {
        res.headers.set_header(rfc::HEADER_ACCESS_CONTROL_EXPOSE_HEADERS, policy.expose_headers[..]);
    }

    return CorsResult.AllowedActual;
}
