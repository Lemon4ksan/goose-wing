// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Internal server pipeline ingress stages, Forwarded/IP parsing, and cookie/JWT auth.
namespace server_internal;

import std;
import core;
import rfc.http;
import http.headers;
import http.request;
import http.response;
import http.negotiate;
import http.digest_fields;
import http.server_timing;
import http.problem;
import http.compression_dict;
import security.gcra;
import security.csrf;
import security.cors;
import security.crypto_jar;
import auth.jwt;
import auth.jwks;
import auth.dpop;
import wire.pipeline;
import .router;
import .router_internal;
import .router_l0_internal;
import .pool;
import .edge_filter;
import .cache;
import .prof_hooks;
import .pipeline;

inline fn is_valid_forwarded_quoted_body(inner: const u8[:]) -> bool {
    var rem = inner;
    while rem.len > 0 {
        let b = rem[0];
        if b == '\\' {
            guard rem.len >= 2 else { return false; }
            let esc = rem[1];
            guard esc == ' ' || esc == '\t' || (esc >= 0x21 && esc != 0x7F) else { return false; }
            rem = rem[2..];
            continue;
        }
        guard b != '"' && (b == ' ' || b == '\t' || (b >= 0x21 && b != 0x7F)) else { return false; }
        rem = rem[1..];
    }
    return true;
}

inline fn is_valid_forwarded_port(port_str: const u8[:]) -> bool {
    guard port_str.len > 0 else { return false; }
    if port_str[0] == '_' {
        guard port_str.len >= 2 else { return false; }
        for b in port_str[1..] {
            let ok = core::is_ascii_alphanumeric(b) || b == '.' || b == '_' || b == '-';
            guard ok else { return false; }
        }
        return true;
    }
    let port_num, ok_port = core::parse_port_number(port_str);
    return ok_port && port_num > 0;
}

inline fn is_valid_ipv4_address_slice(ip: const u8[:]) -> bool {
    var rest = ip;
    for _ in 3 {
        let head, tail, ok_dot = rest.split_once_byte('.');
        guard ok_dot && head.len > 0 else { return false; }
        let _, ok_oct = core::parse_ipv4_decimal_octet(head);
        guard ok_oct else { return false; }
        rest = tail;
    }
    let _, ok_last = core::parse_ipv4_decimal_octet(rest);
    return ok_last;
}

inline fn normalize_forwarded_bracket_ipv6(val: const u8[:]) -> const u8[:] {
    let after_open = val[1..];
    let v6_body, after_close, has_close = after_open.split_once_byte(']');
    var ipv6_buf: u8[..64] = [];
    guard has_close && v6_body.len > 0 && core::parse_and_compress_ipv6(v6_body, ipv6_buf) else {
        return "";
    }
    if after_close.len > 0 {
        guard after_close[0] == ':' && is_valid_forwarded_port(after_close[1..]) else {
            return "";
        }
    }
    return v6_body;
}

inline fn unquote_forwarded_node(raw_val: const u8[:]) -> const u8[:] {
    guard raw_val.len > 0 else { return ""; }
    if raw_val[0] == '"' {
        let after_q, ok_l = raw_val.strip_prefix("\"");
        let inner_q, ok_r = after_q.strip_suffix("\"");
        guard ok_l && ok_r && is_valid_forwarded_quoted_body(inner_q) else { return ""; }
        return inner_q;
    }
    return if raw_val.contains_byte('"') { "" } else { raw_val };
}

// RFC 7239 Section 6: Node Identifiers - normalizes a forwarded IP value, rejecting `unknown` and `_obfnode`.
//
// Example:
//   raw_val = "\"[2001:db8:cafe::17]:4711\""
//   returns: "2001:db8:cafe::17"
fn normalize_forwarded_ip(raw_val: const u8[:]) -> const u8[:] {
    let val = unquote_forwarded_node(raw_val);
    guard val.len > 0 && !val.eq_ascii_fold("unknown") && val[0] != '_' else { return ""; }
    if val[0] == '[' {
        return normalize_forwarded_bracket_ipv6(val);
    }

    let host_part, after_col1, has_col1 = val.split_once_byte(':');
    if !has_col1 {
        return if is_valid_ipv4_address_slice(val) { val } else { "" };
    }
    if after_col1.contains_byte(':') {
        var ipv6_buf: u8[..64] = [];
        return if core::parse_and_compress_ipv6(val, ipv6_buf) { val } else { "" };
    }
    guard host_part.len > 0 && is_valid_forwarded_port(after_col1) && is_valid_ipv4_address_slice(host_part) else {
        return "";
    }
    return host_part;
}

// RFC 7239 Section 4: Forwarded HTTP Header Field - parses a `for=` parameter pair without BWS around `=`.
//
// Example:
//   pair = "for=\"192.0.2.60:4711\""
//   returns: "192.0.2.60"
fn parse_forwarded_pair(pair: const u8[:]) -> const u8[:] {
    let trimmed = pair.trim_lws();
    let key, raw_val, has_eq = trimmed.split_once_byte('=');
    guard has_eq && key.eq_ascii_fold("for") && raw_val.len > 0 else { return ""; }
    if raw_val[0] == '"' {
        let after_q, ok_l = raw_val.strip_prefix("\"");
        let inner, ok_r = after_q.strip_suffix("\"");
        guard ok_l && ok_r && inner.len > 0 && is_valid_forwarded_quoted_body(inner) else { return ""; }
        let _, after_c1, has_c1 = inner.split_once_byte(':');
        if inner[0] != '[' && has_c1 && after_c1.contains_byte(':') {
            return "";
        }
        return normalize_forwarded_ip(inner);
    }
    for b in raw_val {
        guard core::is_tchar(b) else { return ""; }
    }
    return normalize_forwarded_ip(raw_val);
}

inline fn is_trusted_proxy_peer(trust_proxy_headers: bool, client_ip: const u8[:]) -> bool {
    return trust_proxy_headers || client_ip == "127.0.0.1" || client_ip == "::1";
}

fn has_custom_forwarding_header(map: const http::HeaderMap&) -> bool {
    for &e in map.entries {
        if e.well_known_id == 0xFF {
            return true;
        }
    }
    return false;
}

// Stage 13 (Server Ingress): Post-auth GCRA rate limiting keyed on verified JWT `sub:<subject>`.
fn stage_server_ratelimit_subject<Limiter>(
    limiter: Limiter&,
    enabled: bool,
    subject: const u8[:],
    now_ns:  u64,
    res:     http::Response&,
) -> wire::StageVerdict {
    guard enabled && subject.len > 0 else { return wire::StageVerdict.Continue; }
    let _prof = server_prof::lit_prof_enter("stage.ratelimit_subject");
    defer server_prof::lit_prof_leave(_prof);
    var composite_key: u8[..128] = [];
    composite_key.append("sub:");
    composite_key.append(subject[..min(subject.len, 96)]);
    let rl_decision = limiter.check_rate_limit(composite_key[..], 1, now_ns);
    security::apply_rate_limit_headers(res, limiter.quota, rl_decision);
    guard rl_decision.is_allowed() else {
        return wire::StageVerdict.ShortCircuit { status_code: rfc::STATUS_TOO_MANY_REQUESTS as u16 };
    }
    return wire::StageVerdict.Continue;
}

// RFC 6265 Section 4.2.1: Syntax - Extracts value of session cookie parameter.
//
// Example:
//   cookie_hdr = "id=123; session=abc456; theme=dark"
//   returns: "abc456"
fn extract_session_cookie_value(cookie_hdr: const u8[:]) -> const u8[:] {
    var tok = core::make_byte_tokenizer(cookie_hdr, ';');
    loop {
        let pair, ok = core::token_next(tok);
        guard ok else { break; }
        let k, v, has_eq = pair.split_once_byte('=');
        if has_eq && k.trim_lws() == "session" {
            return v.trim_lws();
        }
    }
    return "";
}

// RFC 6750 Section 2.1: Authorization Request Header Field - "Bearer" 1*SP b64token
fn is_b64token_slice(tok: const u8[:]) -> bool {
    guard tok.len > 0 && tok[0] != '=' else { return false; }
    var seen_pad = false;
    for b in tok {
        if b == '=' {
            seen_pad = true;
        } else {
            let ok_ch = core::is_ascii_alphanumeric(b)
                || b == '-' || b == '.' || b == '_' || b == '~' || b == '+' || b == '/';
            guard !seen_pad && ok_ch else { return false; }
        }
    }
    return true;
}

// Extracts Bearer token from an Authorization header value (RFC 6750 §2.1).
//
// Example:
//   auth_hdr = "Bearer eyJhbGciOiJIUzI1NiJ9.e30.sig"
//   returns: "eyJhbGciOiJIUzI1NiJ9.e30.sig"
fn extract_bearer_token(auth_hdr: const u8[:]) -> const u8[:] {
    let trimmed = auth_hdr.trim_lws();
    let rest, ok_pfx = trimmed.strip_prefix_fold("Bearer ");
    guard ok_pfx else { return ""; }
    let tok = rest.trim_start_byte(' ');
    guard is_b64token_slice(tok) else { return ""; }
    return tok;
}

// Stage 0 (Server Ingress): Connection liveliness / Slowloris defense.
fn stage_server_slowloris(
    timer:   ConnectionTimer&,
    enabled: bool,
    now_ns:  u64,
    res:     http::Response&,
) -> wire::StageVerdict {
    guard enabled else { return wire::StageVerdict.Continue; }
    let _prof = server_prof::lit_prof_enter("stage.slowloris");
    defer server_prof::lit_prof_leave(_prof);
    guard check_connection_tick(timer, now_ns) else {
        res.status_code = rfc::STATUS_REQUEST_TIMEOUT;
        return wire::StageVerdict.Abort { err_code: rfc::STATUS_REQUEST_TIMEOUT };
    }
    notify_request_start(timer);
    return wire::StageVerdict.Continue;
}

// Stage 1 (Server Ingress): RFC 9110 §10.1.1 `Expect: 100-continue` validation.
fn stage_server_expect_100(req: const http::Request&, res: http::Response&) -> wire::StageVerdict {
    let _prof = server_prof::lit_prof_enter("stage.expect_100");
    defer server_prof::lit_prof_leave(_prof);
    guard server::validate_pipeline_expect_header(req) else {
        res.status_code = rfc::STATUS_EXPECTATION_FAILED;
        return wire::StageVerdict.ShortCircuit { status_code: rfc::STATUS_EXPECTATION_FAILED as u16 };
    }
    return wire::StageVerdict.Continue;
}

// Stage 2 (Server Ingress): Zero-allocation L7 `server::EdgeFilter` rule inspection.
fn stage_server_edge_filter(
    filter: server::EdgeFilter&,
    req:    const http::Request&,
    res:    http::Response&,
) -> wire::StageVerdict {
    guard filter.enabled && filter.rules.len > 0 else { return wire::StageVerdict.Continue; }
    let _prof = server_prof::lit_prof_enter("stage.edge_filter");
    defer server_prof::lit_prof_leave(_prof);
    let verdict = server::evaluate_edge_filter(filter, req.method[..], req.url[..], req.headers);
    return match verdict {
        Pass => wire::StageVerdict.Continue,
        BlockForbidden => {
            res.status_code = rfc::STATUS_FORBIDDEN;
            wire::StageVerdict.ShortCircuit { status_code: rfc::STATUS_FORBIDDEN as u16 }
        },
        ThrottleRate => {
            res.status_code = rfc::STATUS_TOO_MANY_REQUESTS;
            wire::StageVerdict.ShortCircuit { status_code: rfc::STATUS_TOO_MANY_REQUESTS as u16 }
        },
        DropConnection => {
            res.status_code = rfc::STATUS_BAD_REQUEST;
            wire::StageVerdict.Abort { err_code: rfc::STATUS_BAD_REQUEST }
        },
    };
}

// Stage 3 (Server Ingress): Global GCRA IP rate limiting via UFCS `limiter.check_rate_limit(...)`.
fn stage_server_ratelimit_ip<Limiter>(
    limiter: Limiter&,
    enabled: bool,
    peer_ip: const u8[:],
    now_ns:  u64,
    res:     http::Response&,
) -> wire::StageVerdict {
    guard enabled else { return wire::StageVerdict.Continue; }
    let _prof = server_prof::lit_prof_enter("stage.ratelimit_ip");
    defer server_prof::lit_prof_leave(_prof);
    let rl_decision = limiter.check_rate_limit(peer_ip, 1, now_ns);
    security::apply_rate_limit_headers(res, limiter.quota, rl_decision);
    guard rl_decision.is_allowed() else {
        return wire::StageVerdict.ShortCircuit { status_code: rfc::STATUS_TOO_MANY_REQUESTS as u16 };
    }
    return wire::StageVerdict.Continue;
}

// Stage 4 (Server Ingress): L0 SIMD / Radix trie route matching via UFCS `router.match_route(...)`.
fn stage_server_route_match<Router>(
    router:    const Router&,
    req:       const http::Request&,
    ext:       RequestExtensions&,
    out_match: server::RouteMatchResult&,
    res:       http::Response&,
) -> wire::StageVerdict {
    let _prof = server_prof::lit_prof_enter("stage.route_match");
    defer server_prof::lit_prof_leave(_prof);
    out_match = router.match_route(req.method[..], req.url[..], ext.params, ext.canon_url);
    return match out_match {
        NotFound => {
            res.status_code = rfc::STATUS_NOT_FOUND;
            wire::StageVerdict.ShortCircuit { status_code: rfc::STATUS_NOT_FOUND as u16 }
        },
        MethodNotAllowed mna => {
            res.status_code = rfc::STATUS_METHOD_NOT_ALLOWED;
            http::set_header(res, rfc::HEADER_ALLOW, mna.allow_header[..]);
            wire::StageVerdict.ShortCircuit { status_code: rfc::STATUS_METHOD_NOT_ALLOWED as u16 }
        },
        Found _ => {
            let _ = ext.matched_route.try_set(ext.canon_url[..min(ext.canon_url.len, 64)]);
            wire::StageVerdict.Continue
        },
    };
}

// Stage 5 (Server Ingress): Per-route GCRA rate limiting keyed on `<peer_ip>:<route_path>`.
fn stage_server_ratelimit_route<Limiter>(
    limiter:    Limiter&,
    enabled:    bool,
    peer_ip:    const u8[:],
    route_path: const u8[:],
    now_ns:     u64,
    res:        http::Response&,
) -> wire::StageVerdict {
    guard enabled else { return wire::StageVerdict.Continue; }
    let _prof = server_prof::lit_prof_enter("stage.ratelimit_route");
    defer server_prof::lit_prof_leave(_prof);
    var composite_key: u8[..128] = [];
    composite_key.append(peer_ip[..min(peer_ip.len, 48)]);
    composite_key.push(':');
    composite_key.append(route_path[..min(route_path.len, 64)]);
    let rl_decision = limiter.check_rate_limit(composite_key[..], 1, now_ns);
    security::apply_rate_limit_headers(res, limiter.quota, rl_decision);
    guard rl_decision.is_allowed() else {
        return wire::StageVerdict.ShortCircuit { status_code: rfc::STATUS_TOO_MANY_REQUESTS as u16 };
    }
    return wire::StageVerdict.Continue;
}

// Stage 6 (Server Ingress): W3C CORS preflight and origin validation.
fn stage_server_cors(
    cors_policy: const security::CorsPolicy&,
    enabled:     bool,
    req:         const http::Request&,
    res:         http::Response&,
) -> wire::StageVerdict {
    guard enabled else { return wire::StageVerdict.Continue; }
    let _prof = server_prof::lit_prof_enter("stage.cors");
    defer server_prof::lit_prof_leave(_prof);
    let cors_res = security::evaluate_cors(cors_policy, req, res);
    if cors_res == security::CorsResult.AllowedPreflight {
        return wire::StageVerdict.ShortCircuit { status_code: res.status_code as u16 };
    }
    if cors_res == security::CorsResult.InvalidConfig {
        res.status_code = rfc::STATUS_INTERNAL_SERVER_ERROR;
        return wire::StageVerdict.ShortCircuit { status_code: rfc::STATUS_INTERNAL_SERVER_ERROR as u16 };
    }
    if cors_res == security::CorsResult.RejectedOrigin {
        let has_acrm = http::header(req, rfc::HEADER_ACCESS_CONTROL_REQUEST_METHOD).len > 0;
        let is_preflight = req.method[..] == rfc::METHOD_OPTIONS && has_acrm;
        if is_preflight || cors_policy.reject_non_matching_origin {
            res.status_code = rfc::STATUS_FORBIDDEN;
            return wire::StageVerdict.ShortCircuit { status_code: rfc::STATUS_FORBIDDEN as u16 };
        }
    }
    return wire::StageVerdict.Continue;
}

// Stage 7 (Server Ingress): Fetch Metadata (`Sec-Fetch-*`) cross-origin isolation & CSRF guard.
fn stage_server_csrf(
    csrf_guard:    const security::CrossOriginGuard&,
    enabled:       bool,
    target_host:   const u8[:],
    req:           const http::Request&,
    res:           http::Response&,
    target_scheme: security::CsrfTargetScheme = security::CsrfTargetScheme.Https,
) -> wire::StageVerdict {
    guard enabled else { return wire::StageVerdict.Continue; }
    let _prof = server_prof::lit_prof_enter("stage.csrf");
    defer server_prof::lit_prof_leave(_prof);
    let csrf_res = security::evaluate_request_csrf(csrf_guard, req, target_host, false, target_scheme);
    security::apply_isolation_headers(res);
    return match csrf_res {
        RejectForbidden _ => {
            res.status_code = rfc::STATUS_FORBIDDEN;
            wire::StageVerdict.ShortCircuit { status_code: rfc::STATUS_FORBIDDEN as u16 }
        },
        _ => wire::StageVerdict.Continue,
    };
}

// Stage 8 (Server Ingress): Authenticated session cookie decryption via UFCS `jar.open(...)`.
fn stage_server_auth_cookie<Jar>(
    jar:    const Jar&,
    req:    const http::Request&,
    ext:    RequestExtensions&,
    now_ns: u64,
) -> wire::StageVerdict {
    if req.presence_mask != 0 && (req.presence_mask & http::HDR_PRESENCE_COOKIE) == 0 {
        return wire::StageVerdict.Continue;
    }
    let _prof = server_prof::lit_prof_enter("stage.auth_cookie");
    defer server_prof::lit_prof_leave(_prof);
    let now_sec = if now_ns > 0 { div_euclid(now_ns, 1000000000) as i64 } else { core::now().wall_sec };
    for &e in req.headers.entries {
        guard http::entry_name(req.headers, e).eq_ascii_fold(rfc::HEADER_COOKIE) else { continue; }
        var rem = http::entry_value(req.headers, e);
        while rem.len > 0 {
            let session_val = extract_session_cookie_value(rem);
            guard session_val.len > 0 else { break; }
            ext.session_data.clear();
            if jar.open("session", session_val, now_sec, ext.session_data) {
                ext.populated_entries |= ENTRY_COOKIES;
                return wire::StageVerdict.Continue;
            }
            let semi = rem.index_of_byte(';');
            guard semi >= 0 else { break; }
            rem = rem[core::add_sat_i64(semi, 1)..];
        }
    }
    return wire::StageVerdict.Continue;
}

// Stage 9 (Server Ingress): RFC 7519 / RFC 8725 JWT Bearer token verification against `Jwks`.
fn stage_server_auth_jwt(
    jwks:        const auth::Jwks&,
    jwt_options: const auth::JwtValidationOptions&,
    req:         const http::Request&,
    ext:         RequestExtensions&,
    now_ns:      u64,
    res:         http::Response&,
) -> wire::StageVerdict {
    guard jwks.keys.len > 0 else {
        res.status_code = rfc::STATUS_SERVICE_UNAVAILABLE;
        return wire::StageVerdict.ShortCircuit { status_code: rfc::STATUS_SERVICE_UNAVAILABLE as u16 };
    }
    let _prof = server_prof::lit_prof_enter("stage.auth_jwt");
    defer server_prof::lit_prof_leave(_prof);
    let auth_val = http::header(req, rfc::HEADER_AUTHORIZATION);
    let token = extract_bearer_token(auth_val);
    guard token.len > 0 else {
        res.status_code = rfc::STATUS_UNAUTHORIZED;
        http::set_header(res, rfc::HEADER_WWW_AUTHENTICATE, "Bearer");
        return wire::StageVerdict.ShortCircuit { status_code: rfc::STATUS_UNAUTHORIZED as u16 };
    }
    var out_hdr = auth::JwtHeader { .. };
    var out_claims = auth::JwtClaims { .. };
    let now_sec = if now_ns > 0 { div_euclid(now_ns, 1000000000) as i64 } else { core::now().wall_sec };
    let err = auth::verify_jwt(jwks, token, jwt_options, now_sec, out_hdr, out_claims);
    guard err == auth::JwtError.None else {
        res.status_code = rfc::STATUS_UNAUTHORIZED;
        http::set_header(res, rfc::HEADER_WWW_AUTHENTICATE, "Bearer error=\"invalid_token\"");
        return wire::StageVerdict.ShortCircuit { status_code: rfc::STATUS_UNAUTHORIZED as u16 };
    }
    let _ = ext.auth_subject.try_set(out_claims.sub[..min(out_claims.sub.len, 64)]);
    ext.jwt_claims = out_claims;
    ext.populated_entries |= ENTRY_SECURITY;
    return wire::StageVerdict.Continue;
}
