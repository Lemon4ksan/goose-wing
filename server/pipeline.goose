// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Server request execution pipeline with rate limiting, CORS/CSRF evaluation, routing, and pooling.
namespace wing;

import std;
import core from "..";
import .router;
import .pool;

struct ServerPipelineConfig {
    limiter:                 ShardedGcraLimiter       = ShardedGcraLimiter { .. },
    csrf_guard:              CrossOriginGuard         = CrossOriginGuard { .. },
    cors_policy:             CorsPolicy               = CorsPolicy { .. },
    router:                  RadixRouter              = RadixRouter { .. },
    private_jar:             PrivateJar               = PrivateJar { .. },
    header_pool:             internal::HeaderMapPool  = internal::HeaderMapPool { .. },
    ext_pool:                internal::ExtensionsPool = internal::ExtensionsPool { .. },
    target_host:             u8[..128]                = "example.com",
    deadline_ns:             u64                      = 30000000000, // 30s
    enable_rate_limiter:     bool                     = true,
    enable_csrf_guard:       bool                     = true,
    enable_cors:             bool                     = true,
    enable_slowloris_timer:  bool                     = true,
    trust_proxy_headers:     bool                     = false,
    server_pso_capabilities: u64                      = 0xFFFFFFFFFFFFFFFF,
}

fn new_server_pipeline_config(target_host: const u8[:], quota: GcraQuota) -> ServerPipelineConfig {
    var cfg = ServerPipelineConfig {
        limiter:                 new_sharded_limiter(quota),
        csrf_guard:              CrossOriginGuard { .. },
        cors_policy:             CorsPolicy { .. },
        router:                  new_radix_router(),
        private_jar:             new_private_jar(KeyStore { .. }),
        header_pool:             internal::HeaderMapPool { .. },
        ext_pool:                internal::ExtensionsPool { .. },
        target_host:             [],
        deadline_ns:             30000000000,
        trust_proxy_headers:     false,
        server_pso_capabilities: 0xFFFFFFFFFFFFFFFF,
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

// Executes pre-handler ingress stages matching the effective PSO mask.
// Returns (outcome, is_terminal): if is_terminal is true, the request must not proceed further.
fn dispatch_ingress_pipeline(
    cfg:    ServerPipelineConfig&,
    req:    const Request&,
    res:    Response&,
    ext:    internal::RequestExtensions&,
    mask:   u64,
    now_ns: u64,
) -> PipelineOutcome, bool {
    // Stage: Expect 100-continue validation (RFC 9110 Section 10.1.1)
    if (mask & STAGE_INGRESS_EXPECT_100) != 0 {
        guard validate_pipeline_expect_header(req) else {
            res.status_code = 417; // Expectation Failed
            return PipelineOutcome.ExpectationFailed, true;
        }
    }

    // Stage: Global GCRA IP rate limiter
    if (mask & STAGE_INGRESS_IP_RATELIMIT) != 0 && cfg.enable_rate_limiter {
        let rl_decision = check_rate_limit(cfg.limiter, ext.peer_ip[..], 1, now_ns);
        apply_rate_limit_headers(res, cfg.limiter.quota, rl_decision);
        guard is_allowed(rl_decision) else {
            return PipelineOutcome.RateLimited, true;
        }
    }

    // Stage: CORS preflight and Fetch Metadata CSRF isolation
    let has_cors_csrf = (mask & (STAGE_INGRESS_CORS_PREFLIGHT | STAGE_INGRESS_FETCH_CSRF)) != 0;
    if has_cors_csrf && (cfg.enable_cors || cfg.enable_csrf_guard) {
        let sec_outcome, is_term = evaluate_pipeline_cors_and_csrf(cfg, req, res);
        guard !is_term else { return sec_outcome, true; }
    }

    // Stage: Authenticated session cookie decryption
    if (mask & STAGE_INGRESS_AUTH_COOKIE) != 0 {
        decrypt_pipeline_session_cookie(cfg, req, ext, now_ns);
    }

    return PipelineOutcome.Handled, false;
}

// Executes post-handler egress stages matching the effective PSO mask.
fn dispatch_egress_pipeline(
    _cfg: ServerPipelineConfig&,
    _req: const Request&,
    res:  Response&,
    mask: u64,
) {
    if (mask & STAGE_EGRESS_SECURITY_HEADERS) != 0 {
        apply_isolation_headers(res);
    }
}

// RFC 6265 Section 4.2.1: Syntax - Extracts value of session cookie parameter.
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
        let eq_idx = core::index_of_byte(pair, '=');
        if eq_idx > 0 && core::trim_lws(pair[..eq_idx]) == "session" {
            return core::trim_lws(pair[(eq_idx + 1)..]);
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
    for idx in req.headers.len {
        guard eq_ascii_fold(req.headers[idx].name[..], "Cookie") else { continue; }
        let session_val = extract_session_cookie_value(req.headers[idx].value[..]);
        guard session_val.len > 0 else { return; }
        ext.session_data.clear();
        guard private_jar_open(cfg.private_jar, "session", session_val, now_sec, ext.session_data) else { return; }
        ext.populated_entries |= internal::ENTRY_COOKIES;
        return;
    }
}

const METRICS_PAYLOAD: const u8[:] =
    "{\"engine\":\"goose-wing\",\"memory_allocations\":0,\"heap_bytes\":0,\"architecture\":\"zero_alloc_stack\"}";

// Dispatches standard route payloads and headers based on handler_id.
fn apply_route_payload(handler_id: i32, res: Response&) {
    if handler_id == 1001 {
        set_header(res, "Content-Type", "text/plain");
        res.body.clear();
        res.body.append("Hello, World!");
    } else if handler_id == 1002 {
        set_header(res, "Content-Type", "application/json");
        res.body.clear();
        res.body.append("{\"message\":\"Hello, World!\"}");
    } else if handler_id == 1003 {
        set_header(res, "Content-Type", "application/json");
        res.body.clear();
        res.body.append(METRICS_PAYLOAD);
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

            // Authenticated session cookie decryption (if requested and not yet decrypted)
            let wants_cookie = (f.entries_mask & internal::ENTRY_COOKIES) != 0;
            let cookie_unpopulated = (cfg.ext_pool.slots[e_idx].populated_entries & internal::ENTRY_COOKIES) == 0;
            if wants_cookie && cookie_unpopulated {
                decrypt_pipeline_session_cookie(cfg, req, cfg.ext_pool.slots[e_idx], now_ns);
            }

            out_future = internal::new_inline_handler_future(f.handler_id as u16);
            internal::poll_future(out_future);

            res.status_code = 200;
            apply_route_payload(f.handler_id, res);
            handle_head_method_suppression(req.method[..], res);
            internal::release_extensions(cfg.ext_pool, ext_slot_idx);
            return PipelineOutcome.Handled;
        },
    };
}

// RFC 9110 Section 9.3.2: HEAD - Suppress body for HEAD requests while preserving Content-Length.
fn handle_head_method_suppression(req_method: const u8[:], res: Response&) {
    guard req_method == "HEAD" else { return; }
    if header(res, "content-length").len == 0 && res.body.len > 0 {
        var cl_buf: u8[..32] = [];
        core::format_i64_dec(res.body.len, cl_buf);
        res.headers.push(make_header("Content-Length", cl_buf[..]));
    }
    res.body.clear();
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

// Resolves the effective pipeline mask from route match result and server capabilities.
inline fn resolve_route_effective_pso(res: RouteMatchResult, caps: u64) -> u64 {
    return match res {
        Found f => f.pso_mask & caps,
        _ => caps,
    };
}

// Finalizes slowloris request lifecycle tracking.
inline fn notify_pipeline_timer_end(timer_enabled: bool, timer: internal::ConnectionTimer&) {
    if timer_enabled {
        internal::notify_request_end(timer);
    }
}

// Executes an incoming request through the configured pipeline stages.
//
// Pipeline stages:
// 1. Connection liveliness / timeout check (Slowloris defense)
// 2. Radix trie route matching & extension acquisition
// 3. Ingress PSO dispatch (Expect header, Rate limiting, CORS/CSRF, Cookie decryption)
// 4. Handler execution & response generation
// 5. Egress PSO dispatch (Security headers, transformations)
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

    // Acquire request extensions from pool
    let ext_slot_idx = internal::acquire_extensions(cfg.ext_pool);
    guard ext_slot_idx >= 0 else {
        notify_pipeline_timer_end(cfg.enable_slowloris_timer, conn_timer);
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

    let effective_pso = resolve_route_effective_pso(match_res, cfg.server_pso_capabilities);
    cfg.ext_pool.slots[e_idx].effective_pso = effective_pso;

    if effective_pso != 0 {
        let ingress_outcome, is_terminal = dispatch_ingress_pipeline(
            cfg,
            req,
            res,
            cfg.ext_pool.slots[e_idx],
            effective_pso,
            now_ns,
        );
        if is_terminal {
            internal::release_extensions(cfg.ext_pool, ext_slot_idx);
            notify_pipeline_timer_end(cfg.enable_slowloris_timer, conn_timer);
            return ingress_outcome;
        }
    }

    let outcome = dispatch_matched_route(cfg, req, now_ns, res, out_future, match_res, ext_slot_idx);

    if outcome == PipelineOutcome.Handled {
        dispatch_egress_pipeline(cfg, req, res, effective_pso);
    }

    notify_pipeline_timer_end(cfg.enable_slowloris_timer, conn_timer);
    if req.method[..] == "HEAD" {
        res.body.clear();
    }
    return outcome;
}
