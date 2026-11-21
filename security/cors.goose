// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Cross-Origin Resource Sharing (CORS) policy engine.
namespace security;

import std;
import core;
import rfc.http;
import .policy_internal;

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

struct ClientCorsVerifyOptions {
    tainted_origin:      bool = false,
    include_credentials: bool = false,
}

// Appends an allowed origin pattern to the CORS policy.
fn add_allowed_origin(policy: CorsPolicy&, origin_pattern: const u8[:]) -> bool {
    let trimmed = origin_pattern.trim_lws();
    guard trimmed.len > 0 else { return false; }
    var entry: u8[..128] = [];
    guard entry.try_set(trimmed) else { return false; }
    return policy.allowed_origins.try_push(entry);
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

    return security_internal::match_cors_wildcard_host(cand_rest, pat_rest);
}

// Validates whether the incoming Origin is permitted under policy.
fn is_origin_allowed(policy: const CorsPolicy&, origin_str: const u8[:]) -> bool {
    let clean_origin = origin_str.trim_lws();
    guard clean_origin.len > 0 else { return false; }

    // Disallow "null" origin when credentials are enabled (RFC 6454 / Fetch §3.2.2)
    if policy.allow_credentials && clean_origin.eq_ascii_fold("null") {
        return false;
    }

    for &orig in policy.allowed_origins {
        let pat = orig[..].trim_lws();
        if policy.allow_credentials && pat == "*" {
            continue;
        }
        if match_cors_origin_pattern(clean_origin, pat) {
            return true;
        }
    }
    return false;
}

// Validates policy configuration invariants (Fetch §3.2.2 forbids '*' or 'null' with allow_credentials).
fn validate_cors_policy(policy: const CorsPolicy&) -> bool {
    guard policy.max_age_sec >= -1 else { return false; }
    if policy.allow_credentials {
        for &orig in policy.allowed_origins {
            let pat = orig[..].trim_lws();
            if pat == "*" || pat.eq_ascii_fold("null") {
                return false;
            }
        }
    }
    let allow_wild = !policy.allow_credentials;
    return security_internal::validate_cors_token_list(policy.allowed_methods[..], allow_wild) &&
        security_internal::validate_cors_token_list(policy.allowed_headers[..], allow_wild);
}

// Injects Vary: Origin header on dynamic CORS responses (RFC 9111 / WHATWG Fetch §3.2.4).
inline fn apply_cors_vary_header<Res>(res: Res&) {
    security_internal::merge_response_vary_tokens(res.headers, rfc::HEADER_ORIGIN);
}

// Checks whether all comma-separated tokens in `requested_list` are present in `allowed_list` (WHATWG Fetch §3.2.3).
fn are_cors_request_headers_allowed(
    allowed_list:   const u8[:],
    requested_list: const u8[:],
    allow_wildcard: bool = true,
) -> bool {
    var saw_token = false;
    var tok_iter = core::make_byte_tokenizer(requested_list, ',');
    loop {
        let item, ok = core::token_next(tok_iter);
        guard ok else { break; }
        let tok = item.trim_lws();
        guard security_internal::is_valid_cors_token(tok) else { return false; }
        saw_token = true;
        let safelisted = tok.eq_ascii_fold("accept") ||
            tok.eq_ascii_fold("accept-language") ||
            tok.eq_ascii_fold("content-language");
        let can_use_wildcard = allow_wildcard && !tok.eq_ascii_fold("authorization");
        if !safelisted && !security_internal::header_list_has_token(allowed_list, tok, can_use_wildcard) {
            return false;
        }
    }
    return saw_token;
}

// Validates an inbound HTTP response against WHATWG Fetch §4.9 CORS protocol check on the client side.
fn verify_client_cors_response<H>(
    resp_headers:   const H&,
    request_origin: const u8[:],
    opts:           ClientCorsVerifyOptions = ClientCorsVerifyOptions { .. },
) -> bool {
    let acao, acao_unique = security_internal::find_unique_cors_header(
        resp_headers,
        rfc::HEADER_ACCESS_CONTROL_ALLOW_ORIGIN,
    );
    guard acao_unique && acao.len > 0 && !acao.contains_byte(',') else { return false; }
    let expected_origin = if opts.tainted_origin { "null" } else { request_origin.trim_lws() };

    if opts.include_credentials {
        guard acao != "*" && acao.eq_ascii_fold(expected_origin) else { return false; }
        let acac, acac_unique = security_internal::find_unique_cors_header(
            resp_headers,
            rfc::HEADER_ACCESS_CONTROL_ALLOW_CREDENTIALS,
        );
        return acac_unique && acac == "true";
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
    let origin, origin_unique = security_internal::find_unique_cors_header(req.headers, rfc::HEADER_ORIGIN);
    guard origin_unique else { return CorsResult.RejectedOrigin; }
    guard origin.len > 0 else { return CorsResult.NoCors; }
    guard !origin.contains_byte(',') else { return CorsResult.RejectedOrigin; }

    // Check configuration validity: allow_credentials == true with wildcard "*" origin is invalid (Fetch §3.2.2)
    guard validate_cors_policy(policy) else { return CorsResult.InvalidConfig; }
    guard is_origin_allowed(policy, origin) else { return CorsResult.RejectedOrigin; }

    let req_method_hdr = req.headers.find_header(rfc::HEADER_ACCESS_CONTROL_REQUEST_METHOD).trim_lws();
    let is_preflight = req.method[..] == rfc::METHOD_OPTIONS && req_method_hdr.len > 0;
    if is_preflight {
        let allow_wild = !policy.allow_credentials;
        guard security_internal::is_valid_cors_token(req_method_hdr) &&
            security_internal::header_list_has_token(policy.allowed_methods[..], req_method_hdr, allow_wild) else {
            return CorsResult.RejectedPreflightMethod;
        }
        let req_hdrs_raw = req.headers.find_header(rfc::HEADER_ACCESS_CONTROL_REQUEST_HEADERS);
        if req_hdrs_raw.len > 0 &&
            !are_cors_request_headers_allowed(policy.allowed_headers[..], req_hdrs_raw, allow_wild) {
            return CorsResult.RejectedPreflightHeaders;
        }
    }

    let is_wildcard_allow = !policy.allow_credentials && security_internal::has_wildcard_origin(policy);
    let allow_origin_val = if is_wildcard_allow { "*" } else { origin };
    res.headers.set_header(rfc::HEADER_ACCESS_CONTROL_ALLOW_ORIGIN, allow_origin_val);

    if !is_wildcard_allow {
        apply_cors_vary_header(res);
    }

    if policy.allow_credentials {
        res.headers.set_header(rfc::HEADER_ACCESS_CONTROL_ALLOW_CREDENTIALS, "true");
    }

    if is_preflight {
        security_internal::apply_cors_preflight_headers(policy, res);
        return CorsResult.AllowedPreflight;
    }

    if policy.expose_headers.len > 0 {
        res.headers.set_header(rfc::HEADER_ACCESS_CONTROL_EXPOSE_HEADERS, policy.expose_headers[..]);
    }

    return CorsResult.AllowedActual;
}
