// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Server request execution pipeline with rate limiting, CORS/CSRF evaluation, routing, and pooling.
namespace wing;

import std;
import core from "..";
import .router;
import .pool;

struct ServerPipelineConfig {
    limiter:                ShardedGcraLimiter       = ShardedGcraLimiter { .. },
    csrf_guard:             CrossOriginGuard         = CrossOriginGuard { .. },
    cors_policy:            CorsPolicy               = CorsPolicy { .. },
    router:                 RadixRouter              = RadixRouter { .. },
    private_jar:            PrivateJar               = PrivateJar { .. },
    header_pool:            internal::HeaderMapPool  = internal::HeaderMapPool { .. },
    ext_pool:               internal::ExtensionsPool = internal::ExtensionsPool { .. },
    target_host:            u8[..128]                = "example.com",
    deadline_ns:            u64                      = 30000000000, // 30s
    enable_rate_limiter:    bool                     = true,
    enable_csrf_guard:      bool                     = true,
    enable_cors:            bool                     = true,
    enable_slowloris_timer: bool                     = true,
    trust_proxy_headers:    bool                     = false,
}

fn new_server_pipeline_config(target_host: const u8[:], quota: GcraQuota) -> ServerPipelineConfig {
    var cfg = ServerPipelineConfig {
        limiter:             new_sharded_limiter(quota),
        csrf_guard:          CrossOriginGuard { .. },
        cors_policy:         CorsPolicy { .. },
        router:              new_radix_router(),
        private_jar:         new_private_jar(KeyStore { .. }),
        header_pool:         internal::HeaderMapPool { .. },
        ext_pool:            internal::ExtensionsPool { .. },
        target_host:         [],
        deadline_ns:         30000000000,
        trust_proxy_headers: false,
    };
    cfg.target_host.append(target_host);
    return cfg;
}

fn new_default_server_pipeline_config(target_host: const u8[:]) -> ServerPipelineConfig {
    return new_server_pipeline_config(target_host, new_gcra_quota(1000, core::secs(1), 100));
}

enum PipelineOutcome {
    Handled,
    RateLimited,
    CsrfRejected,
    CorsPreflight,
    MethodNotAllowed,
    RouteNotFound,
    SlowlorisClosed,
    ExpectationFailed,
}

// Validates Expect header compliance per RFC 9110 Section 10.1.1.
// Returns true if valid or absent; false if unsupported expectation requested.
fn validate_pipeline_expect_header(req: const Request&) -> bool {
    for &hdr in req.headers {
        if eq_ascii_fold(hdr.name[..], "expect") {
            let exp_val = hdr.value[..];
            if !eq_ascii_fold(exp_val, "100-continue") {
                return false;
            }
        }
    }
    return true;
}

// Evaluates CORS policies and Sec-Fetch-* cross-origin isolation metadata.
// Returns (outcome, is_terminal): if is_terminal is true, the request must not proceed further.
fn evaluate_pipeline_cors_and_csrf(
    cfg: ServerPipelineConfig&,
    req: const Request&,
    res: Response&,
) -> PipelineOutcome, bool {
    let cors_res = evaluate_cors(cfg.cors_policy, req, res);
    if cors_res == CorsResult.AllowedPreflight {
        return PipelineOutcome.CorsPreflight, true;
    }

    let fetch_ctx = extract_fetch_context(req, cfg.target_host[..]);
    let csrf_res = evaluate_fetch_metadata(cfg.csrf_guard, fetch_ctx);
    apply_isolation_headers(res);

    match csrf_res {
        RejectForbidden _ => {
            res.status_code = 403; // Forbidden
            return PipelineOutcome.CsrfRejected, true;
        },
        _ => {},
    };

    return PipelineOutcome.Handled, false;
}

// Extracts value of session cookie parameter (RFC 6265 §4.2.1).
//
// Example:
//   cookie_hdr = "id=123; session=abc456; theme=dark"
//   returns: "abc456"
fn extract_session_cookie_value(cookie_hdr: const u8[:]) -> const u8[:] {
    var pos = 0;
    while pos < cookie_hdr.len {
        while pos < cookie_hdr.len && (cookie_hdr[pos] == ' ' || cookie_hdr[pos] == '\t') {
            pos++;
        }
        let pair_start = pos;
        while pos < cookie_hdr.len && cookie_hdr[pos] != ';' {
            pos++;
        }
        let pair = cookie_hdr[pair_start..pos];
        if pos < cookie_hdr.len && cookie_hdr[pos] == ';' {
            pos++;
        }
        var eq_idx = -1;
        for i in pair.len {
            if pair[i] == '=' {
                eq_idx = i;
                break;
            }
        }
        if eq_idx > 0 && core::trim_lws(pair[..eq_idx]) == "session" {
            return core::trim_lws(pair[eq_idx + 1..]);
        }
    }
    return "";
}

// Decrypts encrypted session cookie from request headers into private jar if enabled.
fn decrypt_pipeline_session_cookie(
    cfg:    ServerPipelineConfig&,
    req:    const Request&,
    ext:    internal::RequestExtensions&,
    now_ns: u64,
) {
    let now_sec = (now_ns / 1000000000) as i64;
    var plain_cookie: u8[>..] = [];
    for idx in req.headers.len {
        guard eq_ascii_fold(req.headers[idx].name[..], "Cookie") else { continue; }
        let session_val = extract_session_cookie_value(req.headers[idx].value[..]);
        guard session_val.len > 0 else { return; }
        plain_cookie.clear();
        guard private_jar_open(cfg.private_jar, "session", session_val, now_sec, plain_cookie) else { return; }
        ext.session_data.clear();
        guard plain_cookie.len <= ext.session_data.cap else { return; }
        ext.session_data.append(plain_cookie[..]);
        ext.populated_entries |= internal::ENTRY_COOKIES;
        return;
    }
}

fn dispatch_matched_route(
    cfg:          ServerPipelineConfig&,
    req:          const Request&,
    now_ns:       u64,
    res:          Response&,
    out_future:   internal::InlineHandlerFuture&,
    match_res:    RouteMatchResult,
    ext_slot_idx: i32,
) -> PipelineOutcome {
    let e_idx = ext_slot_idx as i64;
    match match_res {
        NotFound => {
            internal::release_extensions(cfg.ext_pool, ext_slot_idx);
            res.status_code = 404; // Not Found
            return PipelineOutcome.RouteNotFound;
        },
        MethodNotAllowed mna => {
            res.status_code = 405; // Method Not Allowed
            res.headers.push(make_header("Allow", mna.allow_header[..]));
            internal::release_extensions(cfg.ext_pool, ext_slot_idx);
            return PipelineOutcome.MethodNotAllowed;
        },
        Found f => {
            // RFC 10008 Section 2: Servers MUST fail QUERY requests if Content-Type is missing
            if req.method[..] == "QUERY" && header(req, "Content-Type").len == 0 {
                internal::release_extensions(cfg.ext_pool, ext_slot_idx);
                res.status_code = 400; // Bad Request
                return PipelineOutcome.Handled;
            }

            // Stage 6: Cookie decryption & handler dispatch
            if (f.entries_mask & internal::ENTRY_COOKIES) != 0 {
                decrypt_pipeline_session_cookie(cfg, req, cfg.ext_pool.slots[e_idx], now_ns);
            }

            out_future = internal::new_inline_handler_future(f.handler_id as u16);
            internal::poll_future(out_future);

            res.status_code = 200;
            internal::release_extensions(cfg.ext_pool, ext_slot_idx);
            return PipelineOutcome.Handled;
        },
    };
}

// Normalizes an RFC 7239 forwarded IP value, stripping quotes, brackets, and ports.
//
// Example:
//   raw_val = "\"[2001:db8:cafe::17]:4711\""
//   returns: "2001:db8:cafe::17"
fn normalize_forwarded_ip(raw_val: const u8[:]) -> const u8[:] {
    var val = raw_val;
    if core::starts_with(val, "\"") && core::ends_with(val, "\"") && val.len >= 2 {
        val = val[1..(val.len - 1)];
    }
    guard val.len > 0 else { return ""; }

    if core::starts_with(val, "[") {
        let close_br = core::index_of_byte(val, ']');
        guard close_br > 1 else { return ""; }
        return val[1..close_br];
    }

    let col1 = core::index_of_byte(val, ':');
    guard col1 > 0 else { return val; }
    let col2 = core::index_of_byte(val[(col1 + 1)..], ':');
    guard col2 < 0 else { return val; }
    return val[..col1];
}

// Parses a single key=value pair from a Forwarded header element.
//
// Example:
//   pair = "for=\"192.0.2.60:4711\""
//   returns: "192.0.2.60"
fn parse_forwarded_pair(pair: const u8[:]) -> const u8[:] {
    let trimmed = core::trim_lws(pair);
    let eq_idx = core::index_of_byte(trimmed, '=');
    guard eq_idx > 0 else { return ""; }
    let key = core::trim_lws(trimmed[..eq_idx]);
    guard eq_ascii_fold(key, "for") else { return ""; }
    return normalize_forwarded_ip(core::trim_lws(trimmed[(eq_idx + 1)..]));
}

// Extracts the client IP from the first element of an RFC 7239 Forwarded header.
//
// Example:
//   fwd = "for=\"192.0.2.60:4711\";proto=http, for=198.51.100.17"
//   returns: "192.0.2.60"
fn extract_rfc7239_forwarded_for(fwd: const u8[:]) -> const u8[:] {
    guard fwd.len > 0 else { return ""; }
    let comma_idx = core::index_of_byte(fwd, ',');
    let elem = if comma_idx >= 0 { fwd[..comma_idx] } else { fwd };

    var pos: i64 = 0;
    while pos < elem.len {
        let sc = core::index_of_byte(elem[pos..], ';');
        let pair = if sc >= 0 { elem[pos..(pos + sc)] } else { elem[pos..] };
        pos = if sc >= 0 { pos + sc + 1 } else { elem.len };

        let ip = parse_forwarded_pair(pair);
        guard ip.len == 0 else { return ip; }
    }
    return "";
}

// Extracts the effective client IP, checking proxy forwarding headers if trusted or local.
// Priority: RFC 7239 Forwarded ("for=..."), X-Real-IP, X-Forwarded-For, client_ip.
//
// Example:
//   trust = true, client_ip = "127.0.0.1", req header "Forwarded: for=192.0.2.60"
//   returns: "192.0.2.60"
fn extract_effective_client_ip(
    trust_proxy_headers: bool,
    client_ip:           const u8[:],
    req:                 const Request&,
) -> const u8[:] {
    if !trust_proxy_headers && client_ip != "127.0.0.1" && client_ip != "::1" {
        return client_ip;
    }
    let fwd = header(req, "forwarded");
    if fwd.len > 0 {
        let fwd_ip = extract_rfc7239_forwarded_for(fwd);
        if fwd_ip.len > 0 {
            return fwd_ip;
        }
    }
    let real_ip = core::trim_lws(header(req, "x-real-ip"));
    if real_ip.len > 0 {
        return real_ip;
    }
    let xff = header(req, "x-forwarded-for");
    if xff.len > 0 {
        let comma_idx = core::index_of_byte(xff, ',');
        let first_ip = if comma_idx >= 0 {
            core::trim_lws(xff[..comma_idx])
        } else {
            core::trim_lws(xff)
        };
        if first_ip.len > 0 {
            return first_ip;
        }
    }
    return client_ip;
}

// Executes an incoming request through the configured pipeline stages.
//
// Pipeline stages:
// 1. Connection liveliness / timeout check (Slowloris defense)
// 2. Expect header validation (RFC 9110 Section 10.1.1)
// 3. GCRA rate limiter check & header application
// 4. CORS preflight and Fetch Metadata CSRF isolation
// 5. Radix trie route matching & extension acquisition
// 6. Authenticated session cookie decryption & inline handler dispatch
fn execute_pipeline(
    cfg:        ServerPipelineConfig&,
    conn_timer: internal::ConnectionTimer&,
    client_ip:  const u8[:],
    req:        const Request&,
    now_ns:     u64,
    res:        Response&,
    out_future: internal::InlineHandlerFuture&,
) -> PipelineOutcome {
    let eff_ip = extract_effective_client_ip(cfg.trust_proxy_headers, client_ip, req);

    if cfg.enable_slowloris_timer {
        internal::notify_request_start(conn_timer);

        // Stage 1: Connection liveliness / timeout check
        guard internal::check_connection_tick(conn_timer, now_ns) else {
            internal::notify_request_end(conn_timer);
            res.status_code = 408; // Request Timeout
            return PipelineOutcome.SlowlorisClosed;
        }
    }

    // Stage 2: Expect header validation (RFC 9110 Section 10.1.1)
    guard validate_pipeline_expect_header(req) else {
        if cfg.enable_slowloris_timer { internal::notify_request_end(conn_timer); }
        res.status_code = 417; // Expectation Failed
        return PipelineOutcome.ExpectationFailed;
    }

    // Stage 3: Rate limiter check
    if cfg.enable_rate_limiter {
        let rl_decision = check_rate_limit(cfg.limiter, eff_ip, 1, now_ns);
        apply_rate_limit_headers(res, cfg.limiter.quota, rl_decision);
        if !is_allowed(rl_decision) {
            if cfg.enable_slowloris_timer { internal::notify_request_end(conn_timer); }
            return PipelineOutcome.RateLimited;
        }
    }

    // Stage 4: CORS and Fetch Metadata isolation check
    if cfg.enable_cors || cfg.enable_csrf_guard {
        let security_outcome, is_terminal = evaluate_pipeline_cors_and_csrf(cfg, req, res);
        if is_terminal {
            if cfg.enable_slowloris_timer { internal::notify_request_end(conn_timer); }
            return security_outcome;
        }
    }

    // Stage 5: Radix trie route matching
    let ext_slot_idx = internal::acquire_extensions(cfg.ext_pool);
    guard ext_slot_idx >= 0 else {
        if cfg.enable_slowloris_timer { internal::notify_request_end(conn_timer); }
        res.status_code = 503; // Service Unavailable / Pool Exhausted
        return PipelineOutcome.RateLimited;
    }
    let e_idx = ext_slot_idx as i64;
    cfg.ext_pool.slots[e_idx].peer_ip.append(eff_ip);
    cfg.ext_pool.slots[e_idx].canon_url.clear();

    let match_res = match_route(
        cfg.router,
        req.method[..],
        req.url[..],
        cfg.ext_pool.slots[e_idx].params,
        cfg.ext_pool.slots[e_idx].canon_url,
    );

    let outcome = dispatch_matched_route(cfg, req, now_ns, res, out_future, match_res, ext_slot_idx);
    if cfg.enable_slowloris_timer { internal::notify_request_end(conn_timer); }
    return outcome;
}
