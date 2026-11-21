// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Server request execution pipeline with Tier 2 L7 stage bricks, UFCS-replaceable subsystems,
// rate limiting, CORS/CSRF evaluation, routing, JWT/cookie auth, route caching, and pooling.
namespace server;

import std;
import core from "..";
import rfc.http;
import .router;
import .pool;
import .edge_filter;
import .cache;
import .profiler;
import http.digest_fields;
import http.signatures;
import http.security_txt;
import http.problem;
import http.negotiate;
import http.server_timing;
import auth.dpop;
import security.cors;
import security.crypto_jar;
import security.csrf;
import security.rate_limiter;
import wire.pipeline;
import .pipeline_internal;
import .h1_codec;
import .h1_codec_internal;
import .router_internal;

struct ServerCompressAndEtagMemo {
    etag_src:         u8[..512]  = [],
    etag_val:         u8[..32]   = [],
    gzip_src:         u8[..512]  = [],
    gzip_dst:         u8[..512]  = [],
    gzip_level:       i32        = 0,
    compress_scratch: u8[..8192] = [],
}

struct ServerPipelineConfig {
    limiter:                 security::ShardedGcraLimiter      = security::ShardedGcraLimiter { .. },
    tier_limiters:           security::ShardedGcraLimiter[..4] = [],
    csrf_guard:              security::CrossOriginGuard        = security::CrossOriginGuard { .. },
    cors_policy:             security::CorsPolicy              = security::CorsPolicy { .. },
    router:                  RadixRouter                       = RadixRouter { .. },
    private_jar:             security::PrivateJar              = security::PrivateJar { .. },
    edge_filter:             EdgeFilter                        = EdgeFilter { .. },
    route_cache:             HttpRouteCache                    = HttpRouteCache { .. },
    jwks:                    auth::Jwks                        = auth::Jwks { .. },
    jwt_options:             auth::JwtValidationOptions        = auth::JwtValidationOptions { .. },
    security_txt:            http::SecurityTxt                 = http::SecurityTxt { .. },
    dpop_replay_cache:       auth::DPoPReplayCache             = auth::DPoPReplayCache { .. },
    dpop_public_key:         u8[..64]                          = [],
    sig_key_id:              u8[..64]                          = [],
    sig_public_key:          u8[..64]                          = [],
    verify_request_digest:   bool                              = false,
    emit_problem_details:    bool                              = false,
    wire_pipeline:           wire::WirePipeline                = wire::default_server_pipeline(),
    header_pool:             server_internal::HeaderMapPool    = server_internal::HeaderMapPool { .. },
    ext_pool:                server_internal::ExtensionsPool   = server_internal::ExtensionsPool { .. },
    slab_pool:               server_internal::SpillSlabPool    = server_internal::SpillSlabPool { .. },
    memo:                    ServerCompressAndEtagMemo         = ServerCompressAndEtagMemo { .. },
    target_host:             u8[..256]                         = "example.com",
    deadline_ns:             u64                               = 30000000000, // 30s
    gzip_level:              i32                               = 1,
    enable_rate_limiter:     bool                              = true,
    enable_csrf_guard:       bool                              = true,
    enable_cors:             bool                              = true,
    enable_slowloris_timer:  bool                              = true,
    tls_enabled:             bool                              = true,
    trust_proxy_headers:     bool                              = false,
    server_pso_capabilities: u64                               = 0xFFFFFFFFFFFFFFFF,
    hdr_scan_cursor:         i64                               = 0,
    last_valid_host:         u8[..128]                         = [],
    has_valid_host:          bool                              = false,
}

// Initializes an existing `ServerPipelineConfig` in place without allocating a stack temporary.
fn init_server_pipeline_config_inplace(
    cfg:         ServerPipelineConfig&,
    target_host: const u8[:],
    quota:       security::GcraQuota,
) {
    cfg.limiter.quota = quota;
    init_radix_router_inplace(cfg.router);
    cfg.wire_pipeline = wire::default_server_pipeline();
    let _ = cfg.target_host.try_set(target_host);
    cfg.deadline_ns = 30000000000;
    cfg.gzip_level = 1;
    cfg.trust_proxy_headers = false;
    cfg.server_pso_capabilities = 0xFFFFFFFFFFFFFFFF;
}

fn new_server_pipeline_config(target_host: const u8[:], quota: security::GcraQuota) -> ServerPipelineConfig {
    var cfg = ServerPipelineConfig {
        limiter:                 security::new_sharded_limiter(quota),
        csrf_guard:              security::CrossOriginGuard { .. },
        cors_policy:             security::CorsPolicy { .. },
        router:                  new_radix_router(),
        private_jar:             security::new_private_jar(security::KeyStore { .. }),
        edge_filter:             EdgeFilter { .. },
        route_cache:             HttpRouteCache { .. },
        jwks:                    auth::Jwks { .. },
        jwt_options:             auth::JwtValidationOptions { .. },
        wire_pipeline:           wire::default_server_pipeline(),
        header_pool:             server_internal::HeaderMapPool { .. },
        ext_pool:                server_internal::ExtensionsPool { .. },
        slab_pool:               server_internal::SpillSlabPool { .. },
        target_host:             [],
        deadline_ns:             30000000000,
        gzip_level:              1,
        trust_proxy_headers:     false,
        server_pso_capabilities: 0xFFFFFFFFFFFFFFFF,
        ..
    };
    let _ = cfg.target_host.try_set(target_host);
    return cfg;
}

fn new_default_server_pipeline_config(target_host: const u8[:]) -> ServerPipelineConfig {
    return new_server_pipeline_config(target_host, security::new_gcra_quota(1000, wing::secs(1), 100));
}

// Configures or updates a parameter-slot GCRA rate limiter (slot 0..3) in `cfg.tier_limiters`.
fn configure_tier_limiter(cfg: ServerPipelineConfig&, slot: u8, quota: security::GcraQuota) -> bool {
    guard slot < 4 else { return false; }
    while cfg.tier_limiters.len <= slot {
        guard cfg.tier_limiters.try_push(security::ShardedGcraLimiter { .. }) else { return false; }
    }
    cfg.tier_limiters[slot] = security::new_sharded_limiter(quota);
    return true;
}

enum PipelineOutcome {
    Handled,
    Pending,
    RateLimited,
    CsrfRejected,
    CorsPreflight,
    MethodNotAllowed,
    RouteNotFound,
    SlowlorisClosed,
    ExpectationFailed,
}

// Per-request server stage execution context passed to custom `<UserStage>` hooks.
struct ServerStageCtx {
    ext_slot_idx:    i32             = -1,
    handler_id:      i32             = -1,
    entries_mask:    u32             = 0,
    pso_mask:        u64             = 0,
    ingress_mask:    u64             = wire::STAGE_SRV_IN_DEFAULT_MASK,
    egress_mask:     u64             = wire::STAGE_SRV_OUT_DEFAULT_MASK,
    now_ns:          u64             = 0,
    outcome:         PipelineOutcome = PipelineOutcome.Handled,
    hdr_scan_cursor: i64             = 0,
    last_valid_host: u8[..128]       = [],
    has_valid_host:  bool            = false,
    wake_token:      core::WakeToken = core::WakeToken { .. },
    is_pending:      bool            = false,
}

// Marks an in-flight route handler as parked until the caller's `sctx.wake_token` fires.
fn suspend_server_request(sctx: ServerStageCtx&) -> bool {
    guard core::wake_token_is_valid(sctx.wake_token) else { return false; }
    sctx.is_pending = true;
    return true;
}

// Extracts a route path parameter by name from the active request extension slot (`:id`, `*wildcard`).
fn route_param(
    cfg:  const ServerPipelineConfig&,
    ctx:  const ServerStageCtx&,
    name: const u8[:],
) -> const u8[:], bool {
    guard ctx.ext_slot_idx >= 0 && ctx.ext_slot_idx < cfg.ext_pool.slots.len else {
        return "", false;
    }
    let idx = ctx.ext_slot_idx;
    return http::param_by_name(cfg.ext_pool.slots[idx].params, name, cfg.ext_pool.slots[idx].canon_url[..]);
}

// Extracts a route path parameter by name, returning `default_val` if absent.
fn route_param_or(
    cfg:         const ServerPipelineConfig&,
    ctx:         const ServerStageCtx&,
    name:        const u8[:],
    default_val: const u8[:],
) -> const u8[:] {
    let val, ok = route_param(cfg, ctx, name);
    return if ok { val } else { default_val };
}

// Returns the effective client IP address for the active request extension slot.
fn peer_ip(cfg: const ServerPipelineConfig&, ctx: const ServerStageCtx&) -> const u8[:] {
    guard ctx.ext_slot_idx >= 0 && ctx.ext_slot_idx < cfg.ext_pool.slots.len else { return ""; }
    return cfg.ext_pool.slots[ctx.ext_slot_idx].peer_ip[..];
}

// Returns the verified JWT `sub` claim populated by `stage_server_auth_jwt`.
fn auth_subject(cfg: const ServerPipelineConfig&, ctx: const ServerStageCtx&) -> const u8[:] {
    guard ctx.ext_slot_idx >= 0 && ctx.ext_slot_idx < cfg.ext_pool.slots.len else { return ""; }
    return cfg.ext_pool.slots[ctx.ext_slot_idx].auth_subject[..];
}

// Returns the verified `JwtClaims` populated by `stage_server_auth_jwt`.
fn auth_claims(cfg: const ServerPipelineConfig&, ctx: const ServerStageCtx&) -> const auth::JwtClaims& {
    let idx = if ctx.ext_slot_idx >= 0 && ctx.ext_slot_idx < cfg.ext_pool.slots.len {
        ctx.ext_slot_idx
    } else {
        0
    };
    return cfg.ext_pool.slots[idx].jwt_claims;
}

// Returns the decrypted `PrivateJar` session cookie payload populated by `stage_server_auth_cookie`.
fn session_data(cfg: const ServerPipelineConfig&, ctx: const ServerStageCtx&) -> const u8[:] {
    guard ctx.ext_slot_idx >= 0 && ctx.ext_slot_idx < cfg.ext_pool.slots.len else { return ""; }
    return cfg.ext_pool.slots[ctx.ext_slot_idx].session_data[..];
}

// Programmable user stage slot identifiers (slots 16..19 in `WirePipeline.custom_bindings`).
const STAGE_ID_USER_0: u8 = 16;

const STAGE_ID_USER_1: u8 = 17;

const STAGE_ID_USER_2: u8 = 18;

const STAGE_ID_USER_3: u8 = 19;

// Default zero-cost no-op custom slot hook implementation for `wire::NoOpStage`.
inline fn on_server_custom_slot(
    _stage:      wire::NoOpStage&,
    _slot_id:    u8,
    _param_slot: u8,
    _cfg:        ServerPipelineConfig&,
    _req:        const http::Request&,
    _sctx:       ServerStageCtx&,
    _res:        http::Response&,
) -> wire::StageVerdict {
    return wire::StageVerdict.Continue;
}

// Composes two independent server stages `<First, Next>` sequentially at a custom stage slot (`STAGE_ID_USER_0..3`).
inline fn on_server_custom_slot<First, Next>(
    chain:      wire::StageChain<First, Next>&,
    slot_id:    u8,
    param_slot: u8,
    cfg:        ServerPipelineConfig&,
    req:        const http::Request&,
    sctx:       ServerStageCtx&,
    res:        http::Response&,
) -> wire::StageVerdict {
    var p = wire::begin_pipeline();
    if p.step(chain.first.on_server_custom_slot(slot_id, param_slot, cfg, req, sctx, res)) {
        let _ = p.step(chain.next.on_server_custom_slot(slot_id, param_slot, cfg, req, sctx, res));
    }
    return p.verdict;
}

// Default zero-cost no-op custom slot hook fallback for stages that only implement `on_server_stage`.
inline fn on_server_custom_slot<Stage>(
    _stage:      Stage&,
    _slot_id:    i64,
    _param_slot: u8,
    _cfg:        ServerPipelineConfig&,
    _req:        const http::Request&,
    _sctx:       ServerStageCtx&,
    _res:        http::Response&,
) -> wire::StageVerdict {
    return wire::StageVerdict.Continue;
}

// Default zero-cost no-op server hook implementation for `wire::NoOpStage` by `ServerHookPhase`.
inline fn on_server_stage(
    _stage: wire::NoOpStage&,
    _phase: wire::ServerHookPhase,
    _cfg:   ServerPipelineConfig&,
    _req:   const http::Request&,
    _ctx:   ServerStageCtx&,
    _res:   http::Response&,
) -> wire::StageVerdict {
    return wire::StageVerdict.Continue;
}

// Composes two independent server stages `<First, Next>` sequentially at each `ServerHookPhase`.
// Short-circuits or aborts immediately if `chain.first` does not return `StageVerdict.Continue`.
inline fn on_server_stage<First, Next>(
    chain: wire::StageChain<First, Next>&,
    phase: wire::ServerHookPhase,
    cfg:   ServerPipelineConfig&,
    req:   const http::Request&,
    ctx:   ServerStageCtx&,
    res:   http::Response&,
) -> wire::StageVerdict {
    var p = wire::begin_pipeline();
    if p.step(chain.first.on_server_stage(phase, cfg, req, ctx, res)) {
        let _ = p.step(chain.next.on_server_stage(phase, cfg, req, ctx, res));
    }
    return p.verdict;
}

// Opt-in error-mapping stage wrapper (`onError` equivalent) that formats
// unhandled 4xx/5xx `ShortCircuit` or `OnError` responses into RFC 9457 `ProblemDetails` JSON.
struct ProblemErrorGuardStage<Inner> {
    inner: Inner,
}

inline fn on_server_stage<Inner>(
    guard_stage: ProblemErrorGuardStage<Inner>&,
    phase:       wire::ServerHookPhase,
    cfg:         ServerPipelineConfig&,
    req:         const http::Request&,
    ctx:         ServerStageCtx&,
    res:         http::Response&,
) -> wire::StageVerdict {
    let v = guard_stage.inner.on_server_stage(phase, cfg, req, ctx, res);
    match v {
        ShortCircuit sc => {
            if sc.status_code >= 400 && res.body.len == 0 {
                http::respond_problem(res, sc.status_code as i32, "Request Rejected");
            }
        },
        _ => {
            if phase == wire::ServerHookPhase.OnError && res.status_code >= 400 && res.body.len == 0 {
                http::respond_problem(res, res.status_code, "Request Rejected");
            }
        },
    };
    return v;
}

// Validates Expect header compliance per RFC 9110 Section 10.1.1.
// Returns true if valid or absent; false if unsupported expectation requested.
fn validate_pipeline_expect_header(req: const http::Request&) -> bool {
    if req.presence_mask != 0 && (req.presence_mask & http::HDR_PRESENCE_EXPECT) == 0 {
        return true;
    }
    for &e in req.headers.entries {
        if http::entry_name(req.headers, e).eq_ascii_fold(rfc::HEADER_EXPECT) {
            let exp_val = http::entry_value(req.headers, e);
            if !exp_val.eq_ascii_fold(rfc::EXPECT_100_CONTINUE) {
                return false;
            }
        }
    }
    return true;
}

// Extracts the client IP from the first element of an RFC 7239 Forwarded header.
//
// Example:
//   fwd = "for=\"192.0.2.60:4711\";proto=http, for=198.51.100.17"
//   returns: "192.0.2.60"
fn extract_rfc7239_forwarded_for(fwd: const u8[:]) -> const u8[:] {
    var rem = fwd;
    while rem.len > 0 {
        let comma_idx = rem.find_unquoted_byte(',');
        let elem = rem[..comma_idx];
        rem = if comma_idx < rem.len { rem[core::add_sat_i64(comma_idx, 1)..] } else { "" };

        var elem_rem = elem;
        while elem_rem.len > 0 {
            let sc = elem_rem.find_unquoted_byte(';');
            let pair = elem_rem[..sc];
            elem_rem = if sc < elem_rem.len { elem_rem[core::add_sat_i64(sc, 1)..] } else { "" };

            let ip = server_internal::parse_forwarded_pair(pair);
            if ip.len > 0 {
                return ip;
            }
        }
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
    req:                 const http::Request&,
) -> const u8[:] {
    guard server_internal::is_trusted_proxy_peer(trust_proxy_headers, client_ip) &&
        server_internal::has_custom_forwarding_header(req.headers) else {
        return client_ip;
    }
    let fwd = http::header(req, rfc::HEADER_FORWARDED);
    if fwd.len > 0 {
        let fwd_ip = extract_rfc7239_forwarded_for(fwd);
        if fwd_ip.len > 0 && fwd_ip.len <= 48 {
            return fwd_ip;
        }
    }
    let real_ip = server_internal::normalize_forwarded_ip(http::header(req, rfc::HEADER_X_REAL_IP).trim_lws());
    if real_ip.len > 0 && real_ip.len <= 48 {
        return real_ip;
    }
    let xff = http::header(req, rfc::HEADER_X_FORWARDED_FOR);
    if xff.len > 0 {
        let comma_idx = xff.index_of_byte(',');
        let raw_first = if comma_idx >= 0 {
            xff[..comma_idx].trim_lws()
        } else {
            xff.trim_lws()
        };
        let first_ip = server_internal::normalize_forwarded_ip(raw_first);
        if first_ip.len > 0 && first_ip.len <= 48 {
            return first_ip;
        }
    }
    return client_ip;
}

// Stage 0 (Server Ingress): Connection liveliness / Slowloris defense.
fn stage_server_slowloris(
    timer:   server_internal::ConnectionTimer&,
    enabled: bool,
    now_ns:  u64,
    res:     http::Response&,
) -> wire::StageVerdict {
    guard enabled else { return wire::StageVerdict.Continue; }
    let _prof = prof_enter("stage.slowloris");
    defer prof_leave(_prof);
    guard server_internal::check_connection_tick(timer, now_ns) else {
        res.status_code = 408; // Request Timeout
        return wire::StageVerdict.Abort { err_code: 408 };
    }
    server_internal::notify_request_start(timer);
    return wire::StageVerdict.Continue;
}

// Stage 1 (Server Ingress): RFC 9110 §10.1.1 `Expect: 100-continue` validation.
fn stage_server_expect_100(req: const http::Request&, res: http::Response&) -> wire::StageVerdict {
    let _prof = prof_enter("stage.expect_100");
    defer prof_leave(_prof);
    guard validate_pipeline_expect_header(req) else {
        res.status_code = 417; // Expectation Failed
        return wire::StageVerdict.ShortCircuit { status_code: 417 };
    }
    return wire::StageVerdict.Continue;
}

// Stage 2 (Server Ingress): Zero-allocation L7 `EdgeFilter` rule inspection.
fn stage_server_edge_filter(
    filter: EdgeFilter&,
    req:    const http::Request&,
    res:    http::Response&,
) -> wire::StageVerdict {
    guard filter.enabled && filter.rules.len > 0 else { return wire::StageVerdict.Continue; }
    let _prof = prof_enter("stage.edge_filter");
    defer prof_leave(_prof);
    let verdict = evaluate_edge_filter(filter, req.method[..], req.url[..], req.headers);
    return match verdict {
        Pass => wire::StageVerdict.Continue,
        BlockForbidden => {
            res.status_code = 403;
            wire::StageVerdict.ShortCircuit { status_code: 403 }
        },
        ThrottleRate => {
            res.status_code = 429;
            wire::StageVerdict.ShortCircuit { status_code: 429 }
        },
        DropConnection => {
            res.status_code = 400;
            wire::StageVerdict.Abort { err_code: 400 }
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
    let _prof = prof_enter("stage.ratelimit_ip");
    defer prof_leave(_prof);
    let rl_decision = limiter.check_rate_limit(peer_ip, 1, now_ns);
    security::apply_rate_limit_headers(res, limiter.quota, rl_decision);
    guard rl_decision.is_allowed() else {
        return wire::StageVerdict.ShortCircuit { status_code: 429 };
    }
    return wire::StageVerdict.Continue;
}

// Stage 4 (Server Ingress): L0 SIMD / Radix trie route matching via UFCS `router.match_route(...)`.
fn stage_server_route_match<Router>(
    router:    const Router&,
    req:       const http::Request&,
    ext:       server_internal::RequestExtensions&,
    out_match: RouteMatchResult&,
    res:       http::Response&,
) -> wire::StageVerdict {
    let _prof = prof_enter("stage.route_match");
    defer prof_leave(_prof);
    out_match = router.match_route(req.method[..], req.url[..], ext.params, ext.canon_url);
    return match out_match {
        NotFound => {
            res.status_code = 404;
            wire::StageVerdict.ShortCircuit { status_code: 404 }
        },
        MethodNotAllowed mna => {
            res.status_code = 405;
            http::set_header(res, rfc::HEADER_ALLOW, mna.allow_header[..]);
            wire::StageVerdict.ShortCircuit { status_code: 405 }
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
    let _prof = prof_enter("stage.ratelimit_route");
    defer prof_leave(_prof);
    var composite_key: u8[..128] = [];
    composite_key.append(peer_ip[..min(peer_ip.len, 48)]);
    composite_key.push(':');
    composite_key.append(route_path[..min(route_path.len, 64)]);
    let rl_decision = limiter.check_rate_limit(composite_key[..], 1, now_ns);
    security::apply_rate_limit_headers(res, limiter.quota, rl_decision);
    guard rl_decision.is_allowed() else {
        return wire::StageVerdict.ShortCircuit { status_code: 429 };
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
    let _prof = prof_enter("stage.cors");
    defer prof_leave(_prof);
    let cors_res = security::evaluate_cors(cors_policy, req, res);
    if cors_res == security::CorsResult.AllowedPreflight {
        return wire::StageVerdict.ShortCircuit { status_code: res.status_code as u16 };
    }
    if cors_res == security::CorsResult.RejectedOrigin || cors_res == security::CorsResult.InvalidConfig {
        let has_acrm = http::header(req, rfc::HEADER_ACCESS_CONTROL_REQUEST_METHOD).len > 0;
        let is_preflight = req.method[..] == rfc::METHOD_OPTIONS && has_acrm;
        if is_preflight || cors_policy.reject_non_matching_origin {
            res.status_code = 403;
            return wire::StageVerdict.ShortCircuit { status_code: 403 };
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
    let _prof = prof_enter("stage.csrf");
    defer prof_leave(_prof);
    let csrf_res = security::evaluate_request_csrf(csrf_guard, req, target_host, false, target_scheme);
    security::apply_isolation_headers(res);
    return match csrf_res {
        RejectForbidden _ => {
            res.status_code = 403;
            wire::StageVerdict.ShortCircuit { status_code: 403 }
        },
        _ => wire::StageVerdict.Continue,
    };
}

// Stage 8 (Server Ingress): Authenticated session cookie decryption via UFCS `jar.open(...)`.
fn stage_server_auth_cookie<Jar>(
    jar:    const Jar&,
    req:    const http::Request&,
    ext:    server_internal::RequestExtensions&,
    now_ns: u64,
) -> wire::StageVerdict {
    if req.presence_mask != 0 && (req.presence_mask & http::HDR_PRESENCE_COOKIE) == 0 {
        return wire::StageVerdict.Continue;
    }
    let _prof = prof_enter("stage.auth_cookie");
    defer prof_leave(_prof);
    let now_sec = (now_ns / 1000000000) as i64;
    for &e in req.headers.entries {
        guard http::entry_name(req.headers, e).eq_ascii_fold(rfc::HEADER_COOKIE) else { continue; }
        var rem = http::entry_value(req.headers, e);
        while rem.len > 0 {
            let session_val = server_internal::extract_session_cookie_value(rem);
            guard session_val.len > 0 else { break; }
            ext.session_data.clear();
            if jar.open("session", session_val, now_sec, ext.session_data) {
                ext.populated_entries |= server_internal::ENTRY_COOKIES;
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
    ext:         server_internal::RequestExtensions&,
    now_ns:      u64,
    res:         http::Response&,
) -> wire::StageVerdict {
    guard jwks.keys.len > 0 else { return wire::StageVerdict.Continue; }
    let _prof = prof_enter("stage.auth_jwt");
    defer prof_leave(_prof);
    let auth_val = http::header(req, rfc::HEADER_AUTHORIZATION);
    let token = server_internal::extract_bearer_token(auth_val);
    guard token.len > 0 else {
        res.status_code = 401;
        http::set_header(res, rfc::HEADER_WWW_AUTHENTICATE, "Bearer");
        return wire::StageVerdict.ShortCircuit { status_code: 401 };
    }
    var out_hdr = auth::JwtHeader { .. };
    var out_claims = auth::JwtClaims { .. };
    let now_sec = (now_ns / 1000000000) as i64;
    let err = auth::verify_jwt(jwks, token, jwt_options, now_sec, out_hdr, out_claims);
    guard err == auth::JwtError.None else {
        res.status_code = 401;
        http::set_header(res, rfc::HEADER_WWW_AUTHENTICATE, "Bearer error=\"invalid_token\"");
        return wire::StageVerdict.ShortCircuit { status_code: 401 };
    }
    let _ = ext.auth_subject.try_set(out_claims.sub[..min(out_claims.sub.len, 64)]);
    ext.jwt_claims = out_claims;
    ext.populated_entries |= server_internal::ENTRY_SECURITY;
    return wire::StageVerdict.Continue;
}

// Stage 10 (Server Ingress): Coalescing route cache lookup via UFCS `cache.cache_lookup(now_ms)`.
fn stage_server_cache_lookup(
    cache:      HttpRouteCache&,
    req:        const http::Request&,
    now_ms:     u64,
    res:        http::Response&,
    handler_id: i32 = -1,
) -> wire::StageVerdict {
    // RFC 9111 Section 3.5: Storing Responses to Authenticated Requests - bypass shared route cache on Authorization
    let has_auth = (req.presence_mask & http::HDR_PRESENCE_AUTHORIZATION) != 0
        || http::has_header(req.headers, rfc::HEADER_AUTHORIZATION);
    guard !has_auth && (req.method[..] == "GET" || req.method[..] == "HEAD") else {
        return wire::StageVerdict.Continue;
    }
    let _prof = prof_enter("stage.cache_lookup");
    defer prof_leave(_prof);
    let lookup = cache.cache_lookup(now_ms, handler_id, req.url[..]);
    return match lookup {
        HitFresh => server_internal::populate_cached_response(cache, res),
        HitStaleNeedsUpdate => {
            if !cache.is_updating {
                cache.is_updating = true;
                wire::StageVerdict.Continue
            } else {
                server_internal::populate_cached_response(cache, res)
            }
        },
        Miss => wire::StageVerdict.Continue,
    };
}

// Stage 0 (Server Egress): RFC 9110 §8.8.3 ETag generation & §13.1.2 `If-None-Match` 304 evaluation.
fn stage_server_etag(
    req:  const http::Request&,
    res:  http::Response&,
    memo: ServerCompressAndEtagMemo& = ServerCompressAndEtagMemo { .. },
) -> wire::StageVerdict {
    guard res.status_code == 200 else { return wire::StageVerdict.Continue; }
    let _prof = prof_enter("stage.etag");
    defer prof_leave(_prof);
    if http::get_inline(res.headers, http::WellKnownHeader.ETag).len == 0 && res.body.len > 0 {
        server_internal::populate_missing_response_etag(res, memo);
    }
    let etag_slice = http::get_inline(res.headers, http::WellKnownHeader.ETag);
    guard etag_slice.len > 0 else { return wire::StageVerdict.Continue; }
    let inm = http::get_inline(req.headers, http::WellKnownHeader.IfNoneMatch);
    if inm.len > 0 && (req.method[..] == "GET" || req.method[..] == "HEAD") {
        let parsed = http::parse_etag(etag_slice);
        if http::match_if_none_match(inm, parsed) {
            res.status_code = 304;
            res.body.clear();
            return wire::StageVerdict.ShortCircuit { status_code: 304 };
        }
    }
    return wire::StageVerdict.Continue;
}

fn client_accepts_encoding(accept_enc: const u8[:], token: const u8[:]) -> bool {
    guard accept_enc.len > 0 && token.len > 0 else { return false; }
    if accept_enc.eq_ascii_fold(token) {
        return true;
    }
    var pos: i64 = 0;
    while pos < accept_enc.len {
        let comma = accept_enc[pos..].index_of_byte(',');
        let item = if comma >= 0 {
            accept_enc[pos..pos + comma]
        } else {
            accept_enc[pos..]
        };
        let trimmed = item.trim_lws();
        let semi = trimmed.index_of_byte(';');
        let coding = if semi >= 0 {
            trimmed[..semi].trim_lws()
        } else {
            trimmed
        };
        let params = if semi >= 0 { trimmed[semi + 1..] } else { "" };
        if coding.eq_ascii_fold(token) && !http::is_zero_qvalue(params) {
            return true;
        }
        if comma < 0 { break; }
        pos += comma + 1;
    }
    return false;
}

inline fn select_dynamic_gzip_level(body_len: i64, configured_level: i32 = 1) -> i32 {
    if body_len < 128 {
        return 0;
    }
    if configured_level >= 1 && configured_level <= 9 {
        return configured_level;
    }
    return 1;
}

// RFC 9111 Section 5.2.2.6: no-transform - Returns true if Cache-Control contains the no-transform directive.
fn has_cache_no_transform(headers: const http::HeaderMap&) -> bool {
    let cc = http::get_inline(headers, http::WellKnownHeader.CacheControl);
    guard cc.len > 0 else { return false; }
    var tok = core::make_byte_tokenizer(cc, ',');
    while true {
        let dir, ok = core::token_next(tok);
        if !ok { break; }
        let name, _, _ = dir.trim_lws().split_once_byte('=');
        if name.trim_lws().eq_ascii_fold("no-transform") {
            return true;
        }
    }
    return false;
}

// Guard predicate for `stage_server_compress` before invoking zstd/brotli/gzip encoders.
inline fn is_compressible_response(res: const http::Response&, min_bytes: i64 = 1) -> bool {
    guard res.body.len >= min_bytes else { return false; }
    guard res.status_code != 204 && res.status_code != 206 && res.status_code != 304 else {
        return false;
    }
    guard http::get_inline(res.headers, http::WellKnownHeader.ContentEncoding).len == 0 else {
        return false;
    }
    return !has_cache_no_transform(res.headers);
}

// Stage 1..3 (Server Egress): Dynamic response compression (`zstd`, `br`, `gzip`) per `Accept-Encoding`.
fn stage_server_compress(
    req:   const http::Request&,
    res:   http::Response&,
    mask:  u64,
    memo:  ServerCompressAndEtagMemo& = ServerCompressAndEtagMemo { .. },
    level: i32                        = 1,
) -> wire::StageVerdict {
    guard is_compressible_response(res) else {
        return wire::StageVerdict.Continue;
    }
    let accept_enc = http::get_inline(req.headers, http::WellKnownHeader.AcceptEncoding);
    guard accept_enc.len > 0 else { return wire::StageVerdict.Continue; }
    let _prof = prof_enter("stage.compress");
    defer prof_leave(_prof);

    let allow_zstd = (mask & (STAGE_EGRESS_COMPRESS_ZSTD | wire::STAGE_SRV_OUT_COMPRESS_ZSTD)) != 0;
    let allow_br = (mask & (STAGE_EGRESS_COMPRESS_BROTLI | wire::STAGE_SRV_OUT_COMPRESS_BR)) != 0;
    let allow_gzip = (mask & (STAGE_EGRESS_COMPRESS_GZIP | wire::STAGE_SRV_OUT_COMPRESS_GZIP)) != 0;

    if allow_zstd && client_accepts_encoding(accept_enc, "zstd") && server_internal::try_compress_zstd(res, memo) {
        return wire::StageVerdict.Continue;
    }
    if allow_br && client_accepts_encoding(accept_enc, "br") && server_internal::try_compress_brotli(res, memo) {
        return wire::StageVerdict.Continue;
    }
    if allow_gzip && client_accepts_encoding(accept_enc, "gzip") {
        let gz_level = select_dynamic_gzip_level(res.body.len, level);
        if !server_internal::try_apply_gzip_memo(res, memo, gz_level) {
            server_internal::compress_gzip_uncached(res, memo, level);
        }
    }
    return wire::StageVerdict.Continue;
}

// Stage 4 (Server Egress): Coalescing route cache store via UFCS `cache.cache_store(now_ms, body)`.
fn stage_server_cache_store(
    cache:      HttpRouteCache&,
    now_ms:     u64,
    res:        http::Response&,
    handler_id: i32         = -1,
    url_key:    const u8[:] = "",
) -> wire::StageVerdict {
    let _prof = prof_enter("stage.cache_store");
    defer prof_leave(_prof);
    // RFC 9111 Section 4.1: Calculating Cache Keys with the Vary Header Field - skip unkeyed Vary responses
    if res.status_code == 200 && res.body.len > 0 && !http::has_header(res.headers, rfc::HEADER_VARY) {
        let ctype = http::get_inline(res.headers, http::WellKnownHeader.ContentType);
        let existing_etag = http::get_inline(res.headers, http::WellKnownHeader.ETag);
        if existing_etag.len > 0 {
            let _ = cache.cache_store(now_ms, res.body[..], handler_id, ctype, url_key, existing_etag);
        } else {
            var etag_buf: u8[..32] = [];
            etag_buf.push('"');
            let body_hash = core::xxh64(res.body[..], 0);
            body_hash.format_u64_hex(etag_buf);
            etag_buf.push('"');
            if !res.headers.append_known_pipeline_header(
                rfc::HEADER_ETAG,
                etag_buf[..],
                http::SLOT_ETAG,
                0,
                http::HASH_HDR_ETAG,
                false,
            ) {
                let _ = http::append_header(res.headers, rfc::HEADER_ETAG, etag_buf[..]);
            }
            let _ = cache.cache_store(now_ms, res.body[..], handler_id, ctype, url_key, etag_buf[..]);
        }
    } else {
        cache.is_updating = false;
    }
    return wire::StageVerdict.Continue;
}

// Stage 5 (Server Egress): Cross-origin isolation and HSTS security headers.
fn stage_server_security_headers(res: http::Response&) -> wire::StageVerdict {
    let _prof = prof_enter("stage.security_headers");
    defer prof_leave(_prof);
    let existing_vary = http::get_inline(res.headers, http::WellKnownHeader.Vary);
    let existing_hsts = http::get_inline(res.headers, http::WellKnownHeader.StrictTransportSecurity);
    if existing_hsts.len > 0 && core::starts_with(existing_vary, rfc::FETCH_METADATA_VARY_VALUE) {
        return wire::StageVerdict.Continue;
    }
    if existing_vary.len == 0 && existing_hsts.len == 0 {
        if !res.headers.append_known_pipeline_header(
            rfc::HEADER_VARY,
            rfc::FETCH_METADATA_VARY_VALUE,
            http::SLOT_VARY,
            http::HEADER_FLAG_CONTAINS_COMMA,
            rfc::HASH_HDR_VARY,
            true,
        ) {
            let _ = http::append_header(res.headers, rfc::HEADER_VARY, rfc::FETCH_METADATA_VARY_VALUE);
        }
        if !res.headers.append_known_pipeline_header(
            rfc::HEADER_STRICT_TRANSPORT_SECURITY,
            rfc::HSTS_DEFAULT_VALUE,
            http::SLOT_HSTS,
            http::HEADER_FLAG_SECURITY_STATE,
            rfc::HASH_HDR_STRICT_TRANSPORT_SECURITY,
            false,
        ) {
            let _ = http::append_header(res.headers, rfc::HEADER_STRICT_TRANSPORT_SECURITY, rfc::HSTS_DEFAULT_VALUE);
        }
        return wire::StageVerdict.Continue;
    }
    security::apply_isolation_headers(res);
    return wire::StageVerdict.Continue;
}

// Stage 7..8 (Server Egress): RFC 9218 / Server-Timing metrics and access log emission.
fn stage_server_metrics_log(
    ext:    const server_internal::RequestExtensions&,
    res:    http::Response&,
    mask:   u64,
    now_ns: u64,
) -> wire::StageVerdict {
    let _prof = prof_enter("stage.metrics_log");
    defer prof_leave(_prof);
    let want_metrics = (mask & (STAGE_EGRESS_METRICS | wire::STAGE_SRV_OUT_METRICS)) != 0;
    let want_log = (mask & (STAGE_EGRESS_ACCESS_LOG | wire::STAGE_SRV_OUT_ACCESS_LOG)) != 0;
    let has_timing = server_internal::has_custom_header_hash(
        res.headers,
        rfc::HEADER_SERVER_TIMING,
        http::HASH_HDR_SERVER_TIMING,
    );
    if want_metrics && !has_timing {
        let dur_ns = if now_ns >= ext.start_time_ns && ext.start_time_ns > 0 {
            core::sub_sat_u64(now_ns, ext.start_time_ns)
        } else {
            0
        };
        var timing_buf: u8[..64] = [];
        timing_buf.append("wing;dur=");
        let _ = http::format_dur_ms_tenths(dur_ns, timing_buf);
        if !res.headers.append_known_pipeline_header(
            rfc::HEADER_SERVER_TIMING,
            timing_buf[..],
            0xFF,
            0,
            http::HASH_HDR_SERVER_TIMING,
            false,
        ) {
            let _ = http::append_header(res.headers, rfc::HEADER_SERVER_TIMING, timing_buf[..]);
        }
    }
    if want_log
        && ext.matched_route.len > 0
        && !server_internal::has_custom_header_hash(res.headers, "X-Matched-Route", http::HASH_HDR_X_MATCHED_ROUTE) {
        server_internal::append_matched_route_log_header(res.headers, ext.matched_route[..]);
    }
    return wire::StageVerdict.Continue;
}

struct ServerBodyStreamState {
    sha256_ctx:      core::Sha256Ctx = core::Sha256Ctx { .. },
    expected_sha256: u8[..32]        = [],
    compressed_buf:  u8[..16384]     = [],
    verify_digest:   bool            = false,
    decompress_gzip: bool            = false,
    decompress_zstd: bool            = false,
    bytes_processed: u64             = 0,
    has_error:       bool            = false,
}

// Initializes streaming body verification (`Content-Digest`) and decompression (`Content-Encoding`) state.
fn begin_server_body_stream(req: const http::Request&, ingress_mask: u64) -> ServerBodyStreamState, bool {
    var state = ServerBodyStreamState { .. };
    if (ingress_mask & wire::STAGE_SRV_IN_CONTENT_DIGEST) != 0 {
        let cd_hdr = http::header(req, rfc::HEADER_CONTENT_DIGEST);
        if cd_hdr.len > 0 {
            let dig, ok_dig = server_internal::extract_sha256_content_digest(cd_hdr);
            guard ok_dig else {
                state.has_error = true;
                return state, false;
            }
            state.expected_sha256 = dig;
            state.verify_digest = true;
        }
    }
    if (ingress_mask & wire::STAGE_SRV_IN_DECOMPRESS) != 0 {
        let ce_hdr = http::header(req, rfc::HEADER_CONTENT_ENCODING).trim_lws();
        if ce_hdr.len > 0 {
            if ce_hdr.eq_ascii_fold("gzip") || ce_hdr.eq_ascii_fold("x-gzip") {
                state.decompress_gzip = true;
            } else if ce_hdr.eq_ascii_fold("zstd") {
                state.decompress_zstd = true;
            } else if !ce_hdr.eq_ascii_fold("identity") {
                state.has_error = true;
                return state, false;
            }
        }
    }
    return state, true;
}

// Default zero-cost no-op streaming body chunk hook for `wire::NoOpStage`.
inline fn on_server_body_chunk(
    _stage:   wire::NoOpStage&,
    _cfg:     ServerPipelineConfig&,
    _req:     const http::Request&,
    _ctx:     ServerStageCtx&,
    _chunk:   const u8[:],
    _is_last: bool,
    _res:     http::Response&,
) -> wire::StageVerdict {
    return wire::StageVerdict.Continue;
}

// Composes two independent server stages `<First, Next>` sequentially on each streaming body chunk.
inline fn on_server_body_chunk<First, Next>(
    chain:   wire::StageChain<First, Next>&,
    cfg:     ServerPipelineConfig&,
    req:     const http::Request&,
    ctx:     ServerStageCtx&,
    chunk:   const u8[:],
    is_last: bool,
    res:     http::Response&,
) -> wire::StageVerdict {
    var p = wire::begin_pipeline();
    if p.step(chain.first.on_server_body_chunk(cfg, req, ctx, chunk, is_last, res)) {
        let _ = p.step(chain.next.on_server_body_chunk(cfg, req, ctx, chunk, is_last, res));
    }
    return p.verdict;
}

// Processes a streaming body chunk through decompression, SHA-256 digest verification, and `<UserStage>`.
fn feed_server_body_chunk_with_stage<UserStage>(
    cfg:        ServerPipelineConfig&,
    state:      ServerBodyStreamState&,
    req:        const http::Request&,
    sctx:       ServerStageCtx&,
    chunk:      const u8[:],
    is_last:    bool,
    res:        http::Response&,
    user_stage: UserStage&,
) -> wire::StageVerdict {
    guard !state.has_error else {
        res.status_code = 400;
        return wire::StageVerdict.ShortCircuit { status_code: 400 };
    }
    var decoded: u8[..16384] = [];
    let is_compressed = state.decompress_zstd || state.decompress_gzip;
    if is_compressed {
        guard state.compressed_buf.try_append(chunk) else {
            state.has_error = true;
            res.status_code = 413;
            return wire::StageVerdict.ShortCircuit { status_code: 413 };
        }
        if !is_last {
            return wire::StageVerdict.Continue;
        }
        guard server_internal::decompress_buffered_server_stream(state, decoded) else {
            state.has_error = true;
            res.status_code = 400;
            return wire::StageVerdict.ShortCircuit { status_code: 400 };
        }
    }
    let active_chunk = if is_compressed { decoded[..] } else { chunk };
    state.bytes_processed = core::add_sat_u64(state.bytes_processed, active_chunk.len as u64);
    if state.verify_digest {
        core::sha256_update(state.sha256_ctx, active_chunk);
        if is_last {
            let actual = core::sha256_final(state.sha256_ctx);
            guard core::ct_eq_bytes(actual[..], state.expected_sha256[..]) else {
                state.has_error = true;
                res.status_code = 400;
                return wire::StageVerdict.ShortCircuit { status_code: 400 };
            }
        }
    }
    return user_stage.on_server_body_chunk(cfg, req, sctx, active_chunk, is_last, res);
}

// Executes ordered `StageBinding` entries in `cfg.wire_pipeline.custom_bindings`.
// Returns (outcome, is_terminal): if is_terminal is true, the request must not proceed further.
fn dispatch_custom_stage_bindings<UserStage>(
    cfg:        ServerPipelineConfig&,
    req:        const http::Request&,
    res:        http::Response&,
    ext:        server_internal::RequestExtensions&,
    now_ns:     u64,
    sctx:       ServerStageCtx&,
    user_stage: UserStage&,
) -> PipelineOutcome, bool {
    for &b in cfg.wire_pipeline.custom_bindings {
        let v = server_internal::execute_bound_ingress_stage_verdict(cfg, b, req, res, ext, now_ns, sctx, user_stage);
        let outcome, is_term = server_internal::map_bound_stage_verdict(b.stage_id, v, res);
        guard !is_term else { return outcome, true; }
    }
    return PipelineOutcome.Handled, false;
}

// Executes post-handler egress stages matching the effective PSO or server egress mask.
fn dispatch_egress_pipeline(
    cfg:          ServerPipelineConfig&,
    req:          const http::Request&,
    res:          http::Response&,
    mask:         u64,
    now_ns:       u64 = 0,
    ext_slot_idx: i32 = -1,
) {
    let egress_mask = mask & 0xFFFFFFFF00000000;
    let compress_bits = STAGE_EGRESS_COMPRESS_GZIP | STAGE_EGRESS_COMPRESS_BROTLI | STAGE_EGRESS_COMPRESS_ZSTD;
    if (egress_mask & compress_bits) != 0 {
        let _ = stage_server_compress(req, res, egress_mask, cfg.memo, cfg.gzip_level);
    }
    if http::header(req, rfc::HEADER_WANT_CONTENT_DIGEST).len > 0 && res.body.len > 0 {
        let _ = http::set_response_content_digest(res);
    }
    if (egress_mask & STAGE_EGRESS_ETAG) != 0 {
        let _ = stage_server_etag(req, res, cfg.memo);
    }
    if (egress_mask & STAGE_EGRESS_SECURITY_HEADERS) != 0 {
        let _ = stage_server_security_headers(res);
    }
    if (egress_mask & (STAGE_EGRESS_METRICS | STAGE_EGRESS_ACCESS_LOG)) != 0 {
        if ext_slot_idx >= 0 && ext_slot_idx < cfg.ext_pool.slots.len {
            let _ = stage_server_metrics_log(cfg.ext_pool.slots[ext_slot_idx], res, egress_mask, now_ns);
        } else {
            var dummy_ext = server_internal::RequestExtensions { start_time_ns: now_ns, .. };
            let _ = stage_server_metrics_log(dummy_ext, res, egress_mask, now_ns);
        }
    }
}

// Resumes a parked request after `Wake`, running `ResumeHandler`, error hooks, cache store, and egress stages.
fn resume_server_pipeline_egress<UserStage>(
    cfg:        ServerPipelineConfig&,
    req:        const http::Request&,
    now_ns:     u64,
    sctx:       ServerStageCtx&,
    res:        http::Response&,
    user_stage: UserStage&,
) -> PipelineOutcome {
    sctx.is_pending = false;
    sctx.ext_slot_idx = -1;
    sctx.now_ns = now_ns;
    res.status_code = 0;

    var outcome = PipelineOutcome.Handled;
    let resume_v = user_stage.on_server_stage(wire::ServerHookPhase.ResumeHandler, cfg, req, sctx, res);
    match resume_v {
        ShortCircuit sc => {
            if res.status_code == 0 {
                res.status_code = sc.status_code as i32;
            }
        },
        Abort _ => {
            outcome = PipelineOutcome.CsrfRejected;
            if res.status_code == 0 {
                res.status_code = 500;
            }
        },
        _ => {},
    };
    guard outcome == PipelineOutcome.Handled else {
        return server_internal::complete_pipeline_egress_and_hooks(
            cfg, req, now_ns, res, -1, sctx.pso_mask, outcome, sctx, user_stage,
        );
    }
    if res.status_code == 0 {
        res.status_code = 200;
        if sctx.handler_id >= 0 {
            server_internal::apply_route_payload(cfg, sctx.handler_id, res);
        }
    }
    server_internal::maybe_store_server_route_cache(cfg, req, now_ns, res, sctx.handler_id, sctx.egress_mask);
    return server_internal::complete_pipeline_egress_and_hooks(
        cfg, req, now_ns, res, -1, sctx.pso_mask, outcome, sctx, user_stage,
    );
}

// Executes an incoming request using a caller-owned `ServerStageCtx` carrying `wake_token`.
// Returns `PipelineOutcome.Pending` if `suspend_server_request(sctx)` was called during handling.
fn execute_server_pipeline_async<UserStage>(
    cfg:        ServerPipelineConfig&,
    conn_timer: server_internal::ConnectionTimer&,
    client_ip:  const u8[:],
    req:        const http::Request&,
    now_ns:     u64,
    res:        http::Response&,
    out_future: server_internal::InlineHandlerFuture&,
    sctx:       ServerStageCtx&,
    user_stage: UserStage&,
) -> PipelineOutcome {
    let eff_ip = extract_effective_client_ip(cfg.trust_proxy_headers, client_ip, req);

    // Stage 1: Connection liveliness / timeout check (Slowloris defense)
    let slow_v = stage_server_slowloris(conn_timer, cfg.enable_slowloris_timer, now_ns, res);
    match slow_v {
        Abort _ => { return PipelineOutcome.SlowlorisClosed; },
        _ => {},
    };

    // Acquire request extensions from pool
    let ext_slot_idx = server_internal::acquire_extensions(cfg.ext_pool);
    guard ext_slot_idx >= 0 else {
        server_internal::notify_pipeline_timer_end(cfg.enable_slowloris_timer, conn_timer);
        res.status_code = 503; // Service Unavailable / Pool Exhausted
        return PipelineOutcome.RateLimited;
    }
    defer server_internal::release_extensions(cfg.ext_pool, ext_slot_idx);
    defer sctx.ext_slot_idx = -1;
    defer server_internal::notify_pipeline_timer_end(cfg.enable_slowloris_timer, conn_timer);

    let e_idx = ext_slot_idx as i64;
    let _ = cfg.ext_pool.slots[e_idx].peer_ip.try_set(eff_ip[..min(eff_ip.len, 48)]);
    cfg.ext_pool.slots[e_idx].canon_url.clear();
    cfg.ext_pool.slots[e_idx].start_time_ns = now_ns;

    sctx.ext_slot_idx = ext_slot_idx;
    sctx.handler_id = -1;
    sctx.entries_mask = 0;
    sctx.pso_mask = cfg.server_pso_capabilities;
    sctx.ingress_mask = cfg.wire_pipeline.ingress_mask;
    sctx.egress_mask = cfg.wire_pipeline.egress_mask;
    sctx.now_ns = now_ns;
    sctx.outcome = PipelineOutcome.Handled;
    sctx.is_pending = false;

    let pre_route_v = user_stage.on_server_stage(wire::ServerHookPhase.PreRoute, cfg, req, sctx, res);
    match pre_route_v {
        ShortCircuit sc => {
            if res.status_code == 0 {
                res.status_code = sc.status_code as i32;
            }
            return PipelineOutcome.Handled;
        },
        Abort _ => {
            return PipelineOutcome.CsrfRejected;
        },
        _ => {},
    };

    if cfg.security_txt.is_valid && http::is_security_txt_path(req.url[..]) &&
       (req.method[..] == "GET" || req.method[..] == "HEAD") {
        res.status_code = 200;
        http::set_header(res, "Content-Type", "text/plain; charset=utf-8");
        res.body.clear();
        http::format_security_txt(cfg.security_txt, res.body);
        server_internal::handle_head_method_suppression(req.method[..], res);
        return PipelineOutcome.Handled;
    }

    let match_res = server_internal::resolve_pipeline_route_match(cfg, req, cfg.ext_pool.slots[e_idx], sctx, res);

    let effective_pso = server_internal::resolve_route_effective_pso(match_res, cfg.server_pso_capabilities);
    cfg.ext_pool.slots[e_idx].effective_pso = effective_pso;
    sctx.pso_mask = effective_pso;

    if effective_pso != 0 {
        let ingress_outcome, is_terminal = server_internal::dispatch_ingress_pipeline(
            cfg,
            req,
            res,
            cfg.ext_pool.slots[e_idx],
            effective_pso,
            now_ns,
            sctx,
            user_stage,
        );
        if is_terminal {
            return ingress_outcome;
        }
    }

    return server_internal::finalize_post_auth_and_egress(
        cfg, req, now_ns, res, out_future, match_res, ext_slot_idx, effective_pso, sctx, user_stage,
    );
}

// Executes an incoming request through the configured pipeline stages with a compile-time `<UserStage>` hook.
fn execute_server_pipeline_with_stage<UserStage>(
    cfg:        ServerPipelineConfig&,
    conn_timer: server_internal::ConnectionTimer&,
    client_ip:  const u8[:],
    req:        const http::Request&,
    now_ns:     u64,
    res:        http::Response&,
    out_future: server_internal::InlineHandlerFuture&,
    user_stage: UserStage&,
) -> PipelineOutcome {
    var sctx = ServerStageCtx { now_ns: now_ns, .. };
    return execute_server_pipeline_async(
        cfg, conn_timer, client_ip, req, now_ns, res, out_future, sctx, user_stage,
    );
}

// Executes an incoming request through the configured pipeline stages.
//
// Pipeline stages:
// 1. Connection liveliness / timeout check (Slowloris defense)
// 2. Radix trie route matching & extension acquisition
// 3. Ingress PSO dispatch (Expect header, EdgeFilter, Rate limiting, CORS/CSRF, Cookie/JWT auth)
// 4. Handler execution, Route Cache lookup/store & response generation
// 5. Egress PSO dispatch (ETag, Compression, Security headers, Metrics/Access log)
fn execute_pipeline(
    cfg:        ServerPipelineConfig&,
    conn_timer: server_internal::ConnectionTimer&,
    client_ip:  const u8[:],
    req:        const http::Request&,
    now_ns:     u64,
    res:        http::Response&,
    out_future: server_internal::InlineHandlerFuture&,
) -> PipelineOutcome {
    var noop = wire::NoOpStage {};
    return execute_server_pipeline_with_stage(cfg, conn_timer, client_ip, req, now_ns, res, out_future, noop);
}
