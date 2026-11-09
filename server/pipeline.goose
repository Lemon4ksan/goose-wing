// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Server request execution pipeline with Tier 2 L7 stage bricks, UFCS-replaceable subsystems,
// rate limiting, CORS/CSRF evaluation, routing, JWT/cookie auth, route caching, and pooling.
namespace wing;

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
import auth.dpop;
import wire.pipeline;

struct ServerPipelineConfig {
    limiter:                 ShardedGcraLimiter       = ShardedGcraLimiter { .. },
    tier_limiters:           ShardedGcraLimiter[..4]  = [],
    csrf_guard:              CrossOriginGuard         = CrossOriginGuard { .. },
    cors_policy:             CorsPolicy               = CorsPolicy { .. },
    router:                  RadixRouter              = RadixRouter { .. },
    private_jar:             PrivateJar               = PrivateJar { .. },
    edge_filter:             EdgeFilter               = EdgeFilter { .. },
    route_cache:             HttpRouteCache           = HttpRouteCache { .. },
    jwks:                    Jwks                     = Jwks { .. },
    jwt_options:             JwtValidationOptions     = JwtValidationOptions { .. },
    security_txt:            SecurityTxt              = SecurityTxt { .. },
    dpop_replay_cache:       DPoPReplayCache          = DPoPReplayCache { .. },
    dpop_public_key:         u8[..64]                 = [],
    sig_key_id:              u8[..64]                 = [],
    sig_public_key:          u8[..64]                 = [],
    verify_request_digest:   bool                     = false,
    emit_problem_details:    bool                     = false,
    wire_pipeline:           wire::WirePipeline       = wire::default_server_pipeline(),
    header_pool:             internal::HeaderMapPool  = internal::HeaderMapPool { .. },
    ext_pool:                internal::ExtensionsPool = internal::ExtensionsPool { .. },
    slab_pool:               internal::SpillSlabPool  = internal::SpillSlabPool { .. },
    target_host:             u8[..256]                = "example.com",
    deadline_ns:             u64                      = 30000000000, // 30s
    enable_rate_limiter:     bool                     = true,
    enable_csrf_guard:       bool                     = true,
    enable_cors:             bool                     = true,
    enable_slowloris_timer:  bool                     = true,
    trust_proxy_headers:     bool                     = false,
    server_pso_capabilities: u64                      = 0xFFFFFFFFFFFFFFFF,
    hdr_scan_cursor:         i64                      = 0,
    last_valid_host:         u8[..128]                = [],
    has_valid_host:          bool                     = false,
}

fn new_server_pipeline_config(target_host: const u8[:], quota: GcraQuota) -> ServerPipelineConfig {
    var cfg = ServerPipelineConfig {
        limiter:                 new_sharded_limiter(quota),
        csrf_guard:              CrossOriginGuard { .. },
        cors_policy:             CorsPolicy { .. },
        router:                  new_radix_router(),
        private_jar:             new_private_jar(KeyStore { .. }),
        edge_filter:             EdgeFilter { .. },
        route_cache:             HttpRouteCache { .. },
        jwks:                    Jwks { .. },
        jwt_options:             JwtValidationOptions { .. },
        wire_pipeline:           wire::default_server_pipeline(),
        header_pool:             internal::HeaderMapPool { .. },
        ext_pool:                internal::ExtensionsPool { .. },
        slab_pool:               internal::SpillSlabPool { .. },
        target_host:             [],
        deadline_ns:             30000000000,
        trust_proxy_headers:     false,
        server_pso_capabilities: 0xFFFFFFFFFFFFFFFF,
        ..
    };
    let _ = cfg.target_host.try_set(target_host);
    return cfg;
}

fn new_default_server_pipeline_config(target_host: const u8[:]) -> ServerPipelineConfig {
    return new_server_pipeline_config(target_host, new_gcra_quota(1000, core::secs(1), 100));
}

// Configures or updates a parameter-slot GCRA rate limiter (slot 0..3) in `cfg.tier_limiters`.
fn configure_tier_limiter(cfg: ServerPipelineConfig&, slot: u8, quota: GcraQuota) -> bool {
    guard slot < 4 else { return false; }
    while cfg.tier_limiters.len <= slot {
        guard cfg.tier_limiters.try_push(ShardedGcraLimiter { .. }) else { return false; }
    }
    cfg.tier_limiters[slot] = new_sharded_limiter(quota);
    return true;
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
    return param_by_name(cfg.ext_pool.slots[idx].params, name, cfg.ext_pool.slots[idx].canon_url[..]);
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
fn auth_claims(cfg: const ServerPipelineConfig&, ctx: const ServerStageCtx&) -> const JwtClaims& {
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

// Default zero-cost no-op server hook implementation for `wire::NoOpStage` by `ServerHookPhase`.
inline fn on_server_stage(
    _stage: wire::NoOpStage&,
    _phase: wire::ServerHookPhase,
    _cfg:   ServerPipelineConfig&,
    _req:   const Request&,
    _ctx:   ServerStageCtx&,
    _res:   Response&,
) -> wire::StageVerdict {
    return wire::StageVerdict.Continue;
}

// Composes two independent server stages `<First, Next>` sequentially at each `ServerHookPhase`.
// Short-circuits or aborts immediately if `chain.first` does not return `StageVerdict.Continue`.
inline fn on_server_stage<First, Next>(
    chain: wire::StageChain<First, Next>&,
    phase: wire::ServerHookPhase,
    cfg:   ServerPipelineConfig&,
    req:   const Request&,
    ctx:   ServerStageCtx&,
    res:   Response&,
) -> wire::StageVerdict {
    var p = wire::begin_pipeline();
    if p.step(chain.first.on_server_stage(phase, cfg, req, ctx, res)) {
        let _ = p.step(chain.next.on_server_stage(phase, cfg, req, ctx, res));
    }
    return p.verdict;
}

// Validates Expect header compliance per RFC 9110 Section 10.1.1.
// Returns true if valid or absent; false if unsupported expectation requested.
fn validate_pipeline_expect_header(req: const Request&) -> bool {
    if req.presence_mask != 0 && (req.presence_mask & HDR_PRESENCE_EXPECT) == 0 {
        return true;
    }
    for &e in req.headers.entries {
        if entry_name(req.headers, e).eq_ascii_fold(rfc::HEADER_EXPECT) {
            let exp_val = entry_value(req.headers, e);
            if !exp_val.eq_ascii_fold(rfc::EXPECT_100_CONTINUE) {
                return false;
            }
        }
    }
    return true;
}

// ---- Narrow-Input Autonomous Server Stage Bricks ---------------------------

// Stage 0 (Server Ingress): Connection liveliness / Slowloris defense.
fn stage_server_slowloris(
    timer:   internal::ConnectionTimer&,
    enabled: bool,
    now_ns:  u64,
    res:     Response&,
) -> wire::StageVerdict {
    guard enabled else { return wire::StageVerdict.Continue; }
    let _prof = prof_enter("stage.slowloris");
    defer prof_leave(_prof);
    guard internal::check_connection_tick(timer, now_ns) else {
        res.status_code = 408; // Request Timeout
        return wire::StageVerdict.Abort { err_code: 408 };
    }
    internal::notify_request_start(timer);
    return wire::StageVerdict.Continue;
}

// Stage 1 (Server Ingress): RFC 9110 §10.1.1 `Expect: 100-continue` validation.
fn stage_server_expect_100(req: const Request&, res: Response&) -> wire::StageVerdict {
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
    req:    const Request&,
    res:    Response&,
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
    res:     Response&,
) -> wire::StageVerdict {
    guard enabled else { return wire::StageVerdict.Continue; }
    let _prof = prof_enter("stage.ratelimit_ip");
    defer prof_leave(_prof);
    let rl_decision = limiter.check_rate_limit(peer_ip, 1, now_ns);
    apply_rate_limit_headers(res, limiter.quota, rl_decision);
    guard is_allowed(rl_decision) else {
        return wire::StageVerdict.ShortCircuit { status_code: 429 };
    }
    return wire::StageVerdict.Continue;
}

// Stage 4 (Server Ingress): L0 SIMD / Radix trie route matching via UFCS `router.match_route(...)`.
fn stage_server_route_match<Router>(
    router:    const Router&,
    req:       const Request&,
    ext:       internal::RequestExtensions&,
    out_match: RouteMatchResult&,
    res:       Response&,
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
            set_header(res, rfc::HEADER_ALLOW, mna.allow_header[..]);
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
    res:        Response&,
) -> wire::StageVerdict {
    guard enabled else { return wire::StageVerdict.Continue; }
    let _prof = prof_enter("stage.ratelimit_route");
    defer prof_leave(_prof);
    var composite_key: u8[..128] = [];
    composite_key.append(peer_ip[..min(peer_ip.len, 48)]);
    composite_key.push(':');
    composite_key.append(route_path[..min(route_path.len, 64)]);
    let rl_decision = limiter.check_rate_limit(composite_key[..], 1, now_ns);
    apply_rate_limit_headers(res, limiter.quota, rl_decision);
    guard is_allowed(rl_decision) else {
        return wire::StageVerdict.ShortCircuit { status_code: 429 };
    }
    return wire::StageVerdict.Continue;
}

// Stage 13 (Server Ingress): Post-auth GCRA rate limiting keyed on verified JWT `sub:<subject>`.
fn stage_server_ratelimit_subject<Limiter>(
    limiter: Limiter&,
    enabled: bool,
    subject: const u8[:],
    now_ns:  u64,
    res:     Response&,
) -> wire::StageVerdict {
    guard enabled && subject.len > 0 else { return wire::StageVerdict.Continue; }
    let _prof = prof_enter("stage.ratelimit_subject");
    defer prof_leave(_prof);
    var composite_key: u8[..128] = [];
    composite_key.append("sub:");
    composite_key.append(subject[..min(subject.len, 96)]);
    let rl_decision = limiter.check_rate_limit(composite_key[..], 1, now_ns);
    apply_rate_limit_headers(res, limiter.quota, rl_decision);
    guard is_allowed(rl_decision) else {
        return wire::StageVerdict.ShortCircuit { status_code: 429 };
    }
    return wire::StageVerdict.Continue;
}

// Stage 6 (Server Ingress): W3C CORS preflight and origin validation.
fn stage_server_cors(
    cors_policy: const CorsPolicy&,
    enabled:     bool,
    req:         const Request&,
    res:         Response&,
) -> wire::StageVerdict {
    guard enabled else { return wire::StageVerdict.Continue; }
    let _prof = prof_enter("stage.cors");
    defer prof_leave(_prof);
    let cors_res = evaluate_cors(cors_policy, req, res);
    if cors_res == CorsResult.AllowedPreflight {
        return wire::StageVerdict.ShortCircuit { status_code: res.status_code as u16 };
    }
    if cors_res == CorsResult.RejectedOrigin || cors_res == CorsResult.InvalidConfig {
        let has_acrm = header(req, rfc::HEADER_ACCESS_CONTROL_REQUEST_METHOD).len > 0;
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
    csrf_guard:  const CrossOriginGuard&,
    enabled:     bool,
    target_host: const u8[:],
    req:         const Request&,
    res:         Response&,
) -> wire::StageVerdict {
    guard enabled else { return wire::StageVerdict.Continue; }
    let _prof = prof_enter("stage.csrf");
    defer prof_leave(_prof);
    let csrf_res = evaluate_request_csrf(csrf_guard, req, target_host);
    apply_isolation_headers(res);
    return match csrf_res {
        RejectForbidden _ => {
            res.status_code = 403;
            wire::StageVerdict.ShortCircuit { status_code: 403 }
        },
        _ => wire::StageVerdict.Continue,
    };
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
        let eq_idx = pair.index_of_byte('=');
        if eq_idx > 0 && pair[..eq_idx].trim_lws() == "session" {
            return pair[(eq_idx + 1)..].trim_lws();
        }
    }
    return "";
}

// Stage 8 (Server Ingress): Authenticated session cookie decryption via UFCS `jar.private_jar_open(...)`.
fn stage_server_auth_cookie<Jar>(
    jar:    const Jar&,
    req:    const Request&,
    ext:    internal::RequestExtensions&,
    now_ns: u64,
) -> wire::StageVerdict {
    if req.presence_mask != 0 && (req.presence_mask & HDR_PRESENCE_COOKIE) == 0 {
        return wire::StageVerdict.Continue;
    }
    let _prof = prof_enter("stage.auth_cookie");
    defer prof_leave(_prof);
    let now_sec = (now_ns / 1000000000) as i64;
    for &e in req.headers.entries {
        guard entry_name(req.headers, e).eq_ascii_fold(rfc::HEADER_COOKIE) else { continue; }
        var rem = entry_value(req.headers, e);
        while rem.len > 0 {
            let session_val = extract_session_cookie_value(rem);
            guard session_val.len > 0 else { break; }
            ext.session_data.clear();
            if jar.private_jar_open("session", session_val, now_sec, ext.session_data) {
                ext.populated_entries |= internal::ENTRY_COOKIES;
                return wire::StageVerdict.Continue;
            }
            let semi = rem.index_of_byte(';');
            guard semi >= 0 else { break; }
            rem = rem[core::add_sat_i64(semi, 1)..];
        }
    }
    return wire::StageVerdict.Continue;
}

// Extracts Bearer token from an Authorization header value (RFC 6750 §2.1).
//
// Example:
//   auth_hdr = "Bearer eyJhbGciOiJIUzI1NiJ9.e30.sig"
//   returns: "eyJhbGciOiJIUzI1NiJ9.e30.sig"
fn extract_bearer_token(auth_hdr: const u8[:]) -> const u8[:] {
    let trimmed = auth_hdr.trim_lws();
    guard trimmed.len > 7 else { return ""; }
    guard trimmed[..7].eq_ascii_fold("Bearer ") else { return ""; }
    return trimmed[7..].trim_lws();
}

// Stage 9 (Server Ingress): RFC 7519 / RFC 8725 JWT Bearer token verification against `Jwks`.
fn stage_server_auth_jwt(
    jwks:        const Jwks&,
    jwt_options: const JwtValidationOptions&,
    req:         const Request&,
    ext:         internal::RequestExtensions&,
    now_ns:      u64,
    res:         Response&,
) -> wire::StageVerdict {
    guard jwks.keys.len > 0 else { return wire::StageVerdict.Continue; }
    let _prof = prof_enter("stage.auth_jwt");
    defer prof_leave(_prof);
    let auth_val = header(req, rfc::HEADER_AUTHORIZATION);
    let token = extract_bearer_token(auth_val);
    guard token.len > 0 else {
        res.status_code = 401;
        set_header(res, rfc::HEADER_WWW_AUTHENTICATE, "Bearer");
        return wire::StageVerdict.ShortCircuit { status_code: 401 };
    }
    var out_hdr = JwtHeader { .. };
    var out_claims = JwtClaims { .. };
    let now_sec = (now_ns / 1000000000) as i64;
    let err = verify(token, jwks, jwt_options, now_sec, out_hdr, out_claims);
    guard err == JwtError.None else {
        res.status_code = 401;
        set_header(res, rfc::HEADER_WWW_AUTHENTICATE, "Bearer error=\"invalid_token\"");
        return wire::StageVerdict.ShortCircuit { status_code: 401 };
    }
    let _ = ext.auth_subject.try_set(out_claims.sub[..min(out_claims.sub.len, 64)]);
    ext.jwt_claims = out_claims;
    ext.populated_entries |= internal::ENTRY_SECURITY;
    return wire::StageVerdict.Continue;
}

inline fn populate_cached_response(cache: const HttpRouteCache&, res: Response&) -> wire::StageVerdict {
    res.status_code = 200;
    let _ = res.body.try_set(cache.wire[..]);
    if cache.content_type.len > 0 {
        if !res.headers.append_known_pipeline_header(
            rfc::HEADER_CONTENT_TYPE,
            cache.content_type[..],
            SLOT_CONTENT_TYPE,
            0,
            HASH_HDR_CONTENT_TYPE,
            false,
        ) {
            let _ = append_header(res.headers, rfc::HEADER_CONTENT_TYPE, cache.content_type[..]);
        }
        res.presence_mask |= RES_PRESENCE_CONTENT_TYPE;
    }
    if cache.etag.len > 0 {
        if !res.headers.append_known_pipeline_header(
            rfc::HEADER_ETAG,
            cache.etag[..],
            SLOT_ETAG,
            0,
            HASH_HDR_ETAG,
            false,
        ) {
            let _ = append_header(res.headers, rfc::HEADER_ETAG, cache.etag[..]);
        }
    }
    return wire::StageVerdict.ShortCircuit { status_code: 200 };
}

// Stage 10 (Server Ingress): Coalescing route cache lookup via UFCS `cache.cache_lookup(now_ms)`.
fn stage_server_cache_lookup(
    cache:      HttpRouteCache&,
    req:        const Request&,
    now_ms:     u64,
    res:        Response&,
    handler_id: i32 = -1,
) -> wire::StageVerdict {
    guard req.method[..] == "GET" || req.method[..] == "HEAD" else {
        return wire::StageVerdict.Continue;
    }
    let _prof = prof_enter("stage.cache_lookup");
    defer prof_leave(_prof);
    let lookup = cache.cache_lookup(now_ms, handler_id, req.url[..]);
    return match lookup {
        HitFresh => populate_cached_response(cache, res),
        HitStaleNeedsUpdate => {
            if !cache.is_updating {
                cache.is_updating = true;
                wire::StageVerdict.Continue
            } else {
                populate_cached_response(cache, res)
            }
        },
        Miss => wire::StageVerdict.Continue,
    };
}

struct ServerCompressAndEtagMemo {
    etag_src:         u8[..512]  = [],
    etag_val:         u8[..32]   = [],
    gzip_src:         u8[..512]  = [],
    gzip_dst:         u8[..512]  = [],
    compress_scratch: u8[..2048] = [],
}

var g_server_memo: ServerCompressAndEtagMemo = ServerCompressAndEtagMemo { .. };

inline fn populate_missing_response_etag(res: Response&) {
    if res.body.len <= 512 && g_server_memo.etag_src.len > 0 && res.body[..] == g_server_memo.etag_src[..] {
        if !res.headers.append_known_pipeline_header(
            rfc::HEADER_ETAG,
            g_server_memo.etag_val[..],
            SLOT_ETAG,
            0,
            HASH_HDR_ETAG,
            false,
        ) {
            let _ = append_header(res.headers, rfc::HEADER_ETAG, g_server_memo.etag_val[..]);
        }
        return;
    }
    var etag_hdr: u8[..32] = [];
    etag_hdr.push('"');
    let body_hash = core::xxh64(res.body[..], 0);
    body_hash.format_u64_hex(etag_hdr);
    etag_hdr.push('"');
    if res.body.len <= 512 {
        let _ = g_server_memo.etag_src.try_set(res.body[..]);
        let _ = g_server_memo.etag_val.try_set(etag_hdr[..]);
    }
    if !res.headers.append_known_pipeline_header(
        rfc::HEADER_ETAG,
        etag_hdr[..],
        SLOT_ETAG,
        0,
        HASH_HDR_ETAG,
        false,
    ) {
        let _ = append_header(res.headers, rfc::HEADER_ETAG, etag_hdr[..]);
    }
}

// Stage 0 (Server Egress): RFC 9110 §8.8.3 ETag generation & §13.1.2 `If-None-Match` 304 evaluation.
fn stage_server_etag(req: const Request&, res: Response&) -> wire::StageVerdict {
    guard res.status_code == 200 else { return wire::StageVerdict.Continue; }
    let _prof = prof_enter("stage.etag");
    defer prof_leave(_prof);
    if get_inline(res.headers, WellKnownHeader.ETag).len == 0 && res.body.len > 0 {
        populate_missing_response_etag(res);
    }
    let etag_slice = get_inline(res.headers, WellKnownHeader.ETag);
    guard etag_slice.len > 0 else { return wire::StageVerdict.Continue; }
    let inm = get_inline(req.headers, WellKnownHeader.IfNoneMatch);
    if inm.len > 0 && (req.method[..] == "GET" || req.method[..] == "HEAD") {
        let parsed = parse_etag(etag_slice);
        if match_if_none_match(inm, parsed) {
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
        if coding.eq_ascii_fold(token) && !is_zero_qvalue(params) {
            return true;
        }
        if comma < 0 { break; }
        pos += comma + 1;
    }
    return false;
}

inline fn append_vary_accept_encoding(res: Response&) {
    let cur = get_inline(res.headers, WellKnownHeader.Vary);
    if cur.len == 0 {
        if !res.headers.append_known_pipeline_header(
            rfc::HEADER_VARY,
            rfc::HEADER_ACCEPT_ENCODING,
            SLOT_VARY,
            0,
            rfc::HASH_HDR_VARY,
            false,
        ) {
            let _ = append_header(res.headers, rfc::HEADER_VARY, rfc::HEADER_ACCEPT_ENCODING);
        }
    } else if cur == rfc::FETCH_METADATA_VARY_VALUE {
        let combined = "Sec-Fetch-Dest, Sec-Fetch-Mode, Sec-Fetch-Site, Origin, Accept-Encoding";
        if !res.headers.update_single_vary_value(combined) {
            let _ = set_or_replace(res.headers, rfc::HEADER_VARY, combined, false);
        }
    } else if !cur.contains_fold(rfc::HEADER_ACCEPT_ENCODING) {
        var vbuf: u8[..128] = [];
        guard vbuf.try_set(cur) && vbuf.try_append(", Accept-Encoding") else { return; }
        if !res.headers.update_single_vary_value(vbuf[..]) {
            let _ = set_or_replace(res.headers, rfc::HEADER_VARY, vbuf[..], false);
        }
    }
}

inline fn finalize_compressed_response(res: Response&, encoding: const u8[:], suffix: const u8[:]) {
    if !res.headers.append_known_pipeline_header(
        rfc::HEADER_CONTENT_ENCODING,
        encoding,
        SLOT_CONTENT_ENCODING,
        0,
        HASH_HDR_CONTENT_ENCODING,
        false,
    ) {
        let _ = set_or_replace(res.headers, rfc::HEADER_CONTENT_ENCODING, encoding, false);
    }
    if get_inline(res.headers, WellKnownHeader.ContentLength).len > 0 {
        remove_header(res, rfc::HEADER_CONTENT_LENGTH);
    }
    let etag = get_inline(res.headers, WellKnownHeader.ETag);
    let last_idx = core::sub_sat_i64(etag.len, 1);
    if etag.len >= 2 && etag[last_idx] == '"' && core::add_sat_i64(etag.len, suffix.len) <= 64 {
        var new_etag: u8[..64] = [];
        new_etag.append(etag[..last_idx]);
        new_etag.append(suffix);
        new_etag.push('"');
        let _ = set_or_replace(res.headers, rfc::HEADER_ETAG, new_etag[..], false);
    }
    append_vary_accept_encoding(res);
}

inline fn select_dynamic_gzip_level(body_len: i64) -> i32 {
    return if body_len < 128 { 0 } else { 6 };
}

fn try_compress_zstd(res: Response&) -> bool {
    g_server_memo.compress_scratch.clear();
    guard core::zstd_compress(res.body[..], g_server_memo.compress_scratch) else { return false; }
    let _ = res.body.try_set(g_server_memo.compress_scratch[..]);
    finalize_compressed_response(res, "zstd", "-zstd");
    return true;
}

fn try_compress_brotli(res: Response&) -> bool {
    g_server_memo.compress_scratch.clear();
    guard core::brotli_compress(res.body[..], g_server_memo.compress_scratch, 1) else { return false; }
    let _ = res.body.try_set(g_server_memo.compress_scratch[..]);
    finalize_compressed_response(res, "br", "-br");
    return true;
}

fn compress_gzip_uncached(res: Response&) {
    g_server_memo.compress_scratch.clear();
    let gz_level = select_dynamic_gzip_level(res.body.len);
    if core::gzip_compress(res.body[..], g_server_memo.compress_scratch, gz_level) {
        if res.body.len <= 512 && g_server_memo.compress_scratch.len <= 512 {
            let _ = g_server_memo.gzip_src.try_set(res.body[..]);
            let _ = g_server_memo.gzip_dst.try_set(g_server_memo.compress_scratch[..]);
        }
        let _ = res.body.try_set(g_server_memo.compress_scratch[..]);
        finalize_compressed_response(res, "gzip", "-gzip");
    }
}

// Stage 1..3 (Server Egress): Dynamic response compression (`zstd`, `br`, `gzip`) per `Accept-Encoding`.
fn stage_server_compress(
    req:  const Request&,
    res:  Response&,
    mask: u64,
) -> wire::StageVerdict {
    guard res.body.len > 0 && get_inline(res.headers, WellKnownHeader.ContentEncoding).len == 0 else {
        return wire::StageVerdict.Continue;
    }
    let accept_enc = get_inline(req.headers, WellKnownHeader.AcceptEncoding);
    guard accept_enc.len > 0 else { return wire::StageVerdict.Continue; }
    let _prof = prof_enter("stage.compress");
    defer prof_leave(_prof);

    let allow_zstd = (mask & (STAGE_EGRESS_COMPRESS_ZSTD | wire::STAGE_SRV_OUT_COMPRESS_ZSTD)) != 0;
    let allow_br = (mask & (STAGE_EGRESS_COMPRESS_BROTLI | wire::STAGE_SRV_OUT_COMPRESS_BR)) != 0;
    let allow_gzip = (mask & (STAGE_EGRESS_COMPRESS_GZIP | wire::STAGE_SRV_OUT_COMPRESS_GZIP)) != 0;

    if allow_zstd && client_accepts_encoding(accept_enc, "zstd") && try_compress_zstd(res) {
        return wire::StageVerdict.Continue;
    }
    if allow_br && client_accepts_encoding(accept_enc, "br") && try_compress_brotli(res) {
        return wire::StageVerdict.Continue;
    }
    if allow_gzip && client_accepts_encoding(accept_enc, "gzip") {
        if res.body.len <= 512 && g_server_memo.gzip_src.len > 0 && res.body[..] == g_server_memo.gzip_src[..] {
            let _ = res.body.try_set(g_server_memo.gzip_dst[..]);
            finalize_compressed_response(res, "gzip", "-gzip");
            return wire::StageVerdict.Continue;
        }
        compress_gzip_uncached(res);
    }
    return wire::StageVerdict.Continue;
}

// Stage 4 (Server Egress): Coalescing route cache store via UFCS `cache.cache_store(now_ms, body)`.
fn stage_server_cache_store(
    cache:      HttpRouteCache&,
    now_ms:     u64,
    res:        Response&,
    handler_id: i32         = -1,
    url_key:    const u8[:] = "",
) -> wire::StageVerdict {
    let _prof = prof_enter("stage.cache_store");
    defer prof_leave(_prof);
    if res.status_code == 200 && res.body.len > 0 {
        let ctype = get_inline(res.headers, WellKnownHeader.ContentType);
        let existing_etag = get_inline(res.headers, WellKnownHeader.ETag);
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
                SLOT_ETAG,
                0,
                HASH_HDR_ETAG,
                false,
            ) {
                let _ = append_header(res.headers, rfc::HEADER_ETAG, etag_buf[..]);
            }
            let _ = cache.cache_store(now_ms, res.body[..], handler_id, ctype, url_key, etag_buf[..]);
        }
    } else {
        cache.is_updating = false;
    }
    return wire::StageVerdict.Continue;
}

// Stage 5 (Server Egress): Cross-origin isolation and HSTS security headers.
fn stage_server_security_headers(res: Response&) -> wire::StageVerdict {
    let _prof = prof_enter("stage.security_headers");
    defer prof_leave(_prof);
    let existing_vary = get_inline(res.headers, WellKnownHeader.Vary);
    let existing_hsts = get_inline(res.headers, WellKnownHeader.StrictTransportSecurity);
    if existing_hsts.len > 0 && core::starts_with(existing_vary, rfc::FETCH_METADATA_VARY_VALUE) {
        return wire::StageVerdict.Continue;
    }
    if existing_vary.len == 0 && existing_hsts.len == 0 {
        if !res.headers.append_known_pipeline_header(
            rfc::HEADER_VARY,
            rfc::FETCH_METADATA_VARY_VALUE,
            SLOT_VARY,
            HEADER_FLAG_CONTAINS_COMMA,
            rfc::HASH_HDR_VARY,
            true,
        ) {
            let _ = append_header(res.headers, rfc::HEADER_VARY, rfc::FETCH_METADATA_VARY_VALUE);
        }
        if !res.headers.append_known_pipeline_header(
            rfc::HEADER_STRICT_TRANSPORT_SECURITY,
            rfc::HSTS_DEFAULT_VALUE,
            SLOT_HSTS,
            HEADER_FLAG_SECURITY_STATE,
            rfc::HASH_HDR_STRICT_TRANSPORT_SECURITY,
            false,
        ) {
            let _ = append_header(res.headers, rfc::HEADER_STRICT_TRANSPORT_SECURITY, rfc::HSTS_DEFAULT_VALUE);
        }
        return wire::StageVerdict.Continue;
    }
    apply_isolation_headers(res);
    return wire::StageVerdict.Continue;
}

fn has_custom_header_hash(map: const HeaderMap&, name: const u8[:], hname: u32) -> bool {
    for &e in map.entries {
        if e.name_hash == hname && entry_name(map, e).eq_ascii_fold(name) {
            return true;
        }
    }
    return false;
}

fn is_clean_header_bytes(src: const u8[:]) -> bool {
    for b in src {
        if b == '\r' || b == '\n' || b == 0 {
            return false;
        }
    }
    return true;
}

fn append_matched_route_log_header(map: HeaderMap&, route_slice: const u8[:]) {
    if is_clean_header_bytes(route_slice) {
        let has_comma = route_slice.contains_byte(',');
        let flags = if has_comma { HEADER_FLAG_CONTAINS_COMMA } else { 0 };
        if !map.append_known_pipeline_header(
            "X-Matched-Route",
            route_slice,
            0xFF,
            flags,
            HASH_HDR_X_MATCHED_ROUTE,
            has_comma,
        ) {
            let _ = append_header(map, "X-Matched-Route", route_slice);
        }
        return;
    }
    var clean_route: u8[..256] = [];
    sanitize_header_bytes(route_slice, clean_route);
    if clean_route.len > 0 {
        let _ = append_header(map, "X-Matched-Route", clean_route[..]);
    }
}

// Stage 7..8 (Server Egress): RFC 9218 / Server-Timing metrics and access log emission.
fn stage_server_metrics_log(
    ext:    const internal::RequestExtensions&,
    res:    Response&,
    mask:   u64,
    now_ns: u64,
) -> wire::StageVerdict {
    let _prof = prof_enter("stage.metrics_log");
    defer prof_leave(_prof);
    let want_metrics = (mask & (STAGE_EGRESS_METRICS | wire::STAGE_SRV_OUT_METRICS)) != 0;
    let want_log = (mask & (STAGE_EGRESS_ACCESS_LOG | wire::STAGE_SRV_OUT_ACCESS_LOG)) != 0;
    if want_metrics && !has_custom_header_hash(res.headers, rfc::HEADER_SERVER_TIMING, HASH_HDR_SERVER_TIMING) {
        let dur_ns = if now_ns >= ext.start_time_ns && ext.start_time_ns > 0 {
            now_ns - ext.start_time_ns
        } else {
            0
        };
        var timing_buf: u8[..64] = [];
        timing_buf.append("wing;dur=");
        let dur_us = dur_ns / 1000;
        dur_us.format_u64_dec(timing_buf);
        if !res.headers.append_known_pipeline_header(
            rfc::HEADER_SERVER_TIMING,
            timing_buf[..],
            0xFF,
            0,
            HASH_HDR_SERVER_TIMING,
            false,
        ) {
            let _ = append_header(res.headers, rfc::HEADER_SERVER_TIMING, timing_buf[..]);
        }
    }
    if want_log
        && ext.matched_route.len > 0
        && !has_custom_header_hash(res.headers, "X-Matched-Route", HASH_HDR_X_MATCHED_ROUTE) {
        append_matched_route_log_header(res.headers, ext.matched_route[..]);
    }
    return wire::StageVerdict.Continue;
}

inline fn cors_short_circuit_outcome(status_code: u16) -> PipelineOutcome {
    if status_code == 403 {
        return PipelineOutcome.CsrfRejected;
    }
    return PipelineOutcome.CorsPreflight;
}

// Evaluates CORS policies and Sec-Fetch-* cross-origin isolation metadata.
// Returns (outcome, is_terminal): if is_terminal is true, the request must not proceed further.
fn evaluate_pipeline_cors_and_csrf(
    cfg:  ServerPipelineConfig&,
    req:  const Request&,
    res:  Response&,
    mask: u64 = STAGE_INGRESS_CORS_PREFLIGHT | STAGE_INGRESS_FETCH_CSRF,
) -> PipelineOutcome, bool {
    if (mask & (STAGE_INGRESS_CORS_PREFLIGHT | wire::STAGE_SRV_IN_CORS)) != 0 {
        let v_cors = stage_server_cors(cfg.cors_policy, cfg.enable_cors, req, res);
        match v_cors {
            ShortCircuit sc => {
                return cors_short_circuit_outcome(sc.status_code), true;
            },
            _ => {},
        };
    }

    if (mask & (STAGE_INGRESS_FETCH_CSRF | wire::STAGE_SRV_IN_CSRF)) != 0 {
        let v_csrf = stage_server_csrf(cfg.csrf_guard, cfg.enable_csrf_guard, cfg.target_host[..], req, res);
        match v_csrf {
            ShortCircuit _ => { return PipelineOutcome.CsrfRejected, true; },
            _ => {},
        };
    }

    return PipelineOutcome.Handled, false;
}

inline fn select_stage_limiter(cfg: ServerPipelineConfig&, param_slot: u8) -> ShardedGcraLimiter& {
    if param_slot < cfg.tier_limiters.len {
        return cfg.tier_limiters[param_slot];
    }
    return cfg.limiter;
}

fn execute_bound_ingress_stage_verdict(
    cfg:    ServerPipelineConfig&,
    b:      const wire::StageBinding&,
    req:    const Request&,
    res:    Response&,
    ext:    internal::RequestExtensions&,
    now_ns: u64,
) -> wire::StageVerdict {
    if b.stage_id == wire::STAGE_ID_SRV_IN_EXPECT_100 {
        return stage_server_expect_100(req, res);
    }
    if b.stage_id == wire::STAGE_ID_SRV_IN_EDGE_FILTER {
        return stage_server_edge_filter(cfg.edge_filter, req, res);
    }
    if b.stage_id == wire::STAGE_ID_SRV_IN_RATELIMIT_IP {
        let lim .= select_stage_limiter(cfg, b.param_slot);
        return stage_server_ratelimit_ip(lim, cfg.enable_rate_limiter, ext.peer_ip[..], now_ns, res);
    }
    if b.stage_id == wire::STAGE_ID_SRV_IN_RATELIMIT_ROUTE {
        let lim .= select_stage_limiter(cfg, b.param_slot);
        let rpath = if ext.canon_url.len > 0 { ext.canon_url[..] } else { req.url[..] };
        return stage_server_ratelimit_route(lim, cfg.enable_rate_limiter, ext.peer_ip[..], rpath, now_ns, res);
    }
    if b.stage_id == wire::STAGE_ID_SRV_IN_CORS {
        return stage_server_cors(cfg.cors_policy, cfg.enable_cors, req, res);
    }
    if b.stage_id == wire::STAGE_ID_SRV_IN_CSRF {
        return stage_server_csrf(cfg.csrf_guard, cfg.enable_csrf_guard, cfg.target_host[..], req, res);
    }
    if b.stage_id == wire::STAGE_ID_SRV_IN_AUTH_COOKIE {
        return stage_server_auth_cookie(cfg.private_jar, req, ext, now_ns);
    }
    if b.stage_id == wire::STAGE_ID_SRV_IN_AUTH_JWT {
        return stage_server_auth_jwt(cfg.jwks, cfg.jwt_options, req, ext, now_ns, res);
    }
    if b.stage_id == wire::STAGE_ID_SRV_IN_RATELIMIT_SUBJECT {
        let lim .= select_stage_limiter(cfg, b.param_slot);
        return stage_server_ratelimit_subject(lim, cfg.enable_rate_limiter, ext.auth_subject[..], now_ns, res);
    }
    return wire::StageVerdict.Continue;
}

inline fn map_bound_stage_verdict(stage_id: u8, v: wire::StageVerdict) -> PipelineOutcome, bool {
    match v {
        Continue => { return PipelineOutcome.Handled, false; },
        ShortCircuit sc => {
            if stage_id == wire::STAGE_ID_SRV_IN_EXPECT_100 {
                return PipelineOutcome.ExpectationFailed, true;
            }
            if stage_id == wire::STAGE_ID_SRV_IN_CORS {
                return cors_short_circuit_outcome(sc.status_code), true;
            }
            if sc.status_code == 429 {
                return PipelineOutcome.RateLimited, true;
            }
            return PipelineOutcome.CsrfRejected, true;
        },
        _ => { return PipelineOutcome.CsrfRejected, true; },
    };
}

// Executes ordered `StageBinding` entries in `cfg.wire_pipeline.custom_bindings`.
// Returns (outcome, is_terminal): if is_terminal is true, the request must not proceed further.
fn dispatch_custom_stage_bindings(
    cfg:    ServerPipelineConfig&,
    req:    const Request&,
    res:    Response&,
    ext:    internal::RequestExtensions&,
    now_ns: u64,
) -> PipelineOutcome, bool {
    for &b in cfg.wire_pipeline.custom_bindings {
        let v = execute_bound_ingress_stage_verdict(cfg, b, req, res, ext, now_ns);
        let outcome, is_term = map_bound_stage_verdict(b.stage_id, v);
        guard !is_term else { return outcome, true; }
    }
    return PipelineOutcome.Handled, false;
}

// Executes pre-handler ingress stages matching the effective PSO or server ingress mask.
// Returns (outcome, is_terminal): if is_terminal is true, the request must not proceed further.
fn dispatch_ingress_pipeline(
    cfg:    ServerPipelineConfig&,
    req:    const Request&,
    res:    Response&,
    ext:    internal::RequestExtensions&,
    mask:   u64,
    now_ns: u64,
) -> PipelineOutcome, bool {
    if cfg.wire_pipeline.has_custom_order {
        let custom_out, is_term = dispatch_custom_stage_bindings(cfg, req, res, ext, now_ns);
        guard !is_term else { return custom_out, true; }
        if !evaluate_server_integrity_and_crypto(cfg, req, now_ns, res) {
            return PipelineOutcome.CsrfRejected, true;
        }
        return PipelineOutcome.Handled, false;
    }

    // Stage: Expect 100-continue validation (RFC 9110 Section 10.1.1)
    if (mask & STAGE_INGRESS_EXPECT_100) != 0 {
        match stage_server_expect_100(req, res) {
            ShortCircuit _ => { return PipelineOutcome.ExpectationFailed, true; },
            _ => {},
        };
    }

    // Stage: EdgeFilter L7 inspection
    match stage_server_edge_filter(cfg.edge_filter, req, res) {
        ShortCircuit sc => {
            if sc.status_code == 429 {
                return PipelineOutcome.RateLimited, true;
            }
            return PipelineOutcome.CsrfRejected, true;
        },
        Abort _ => { return PipelineOutcome.CsrfRejected, true; },
        _ => {},
    };

    // Stage: Global GCRA IP rate limiter
    if (mask & STAGE_INGRESS_IP_RATELIMIT) != 0 {
        match stage_server_ratelimit_ip(cfg.limiter, cfg.enable_rate_limiter, ext.peer_ip[..], now_ns, res) {
            ShortCircuit _ => { return PipelineOutcome.RateLimited, true; },
            _ => {},
        };
    }

    // Stage: Per-route GCRA rate limiter
    if (mask & STAGE_INGRESS_ROUTE_RATELIMIT) != 0 {
        match stage_server_ratelimit_route(
            cfg.limiter,
            cfg.enable_rate_limiter,
            ext.peer_ip[..],
            ext.canon_url[..],
            now_ns,
            res,
        ) {
            ShortCircuit _ => { return PipelineOutcome.RateLimited, true; },
            _ => {},
        };
    }

    // Stage: CORS preflight and Fetch Metadata CSRF isolation
    let cors_csrf_mask = mask & (STAGE_INGRESS_CORS_PREFLIGHT | STAGE_INGRESS_FETCH_CSRF);
    if cors_csrf_mask != 0 && (cfg.enable_cors || cfg.enable_csrf_guard) {
        let sec_outcome, is_term = evaluate_pipeline_cors_and_csrf(cfg, req, res, cors_csrf_mask);
        guard !is_term else { return sec_outcome, true; }
    }

    // Stage: Authenticated session cookie decryption
    if (mask & STAGE_INGRESS_AUTH_COOKIE) != 0 {
        let _ = stage_server_auth_cookie(cfg.private_jar, req, ext, now_ns);
    }

    // Stage: JWT Bearer token verification
    if (mask & STAGE_INGRESS_AUTH_JWT) != 0 {
        match stage_server_auth_jwt(cfg.jwks, cfg.jwt_options, req, ext, now_ns, res) {
            ShortCircuit _ => { return PipelineOutcome.CsrfRejected, true; },
            _ => {},
        };
    }

    if !evaluate_server_integrity_and_crypto(cfg, req, now_ns, res) {
        return PipelineOutcome.CsrfRejected, true;
    }

    return PipelineOutcome.Handled, false;
}

fn evaluate_server_integrity_and_crypto(
    cfg:    ServerPipelineConfig&,
    req:    const Request&,
    now_ns: u64,
    res:    Response&,
) -> bool {
    if cfg.verify_request_digest && header(req, "Content-Digest").len > 0 {
        if !verify_request_content_digest(req) {
            if cfg.emit_problem_details {
                respond_problem(res, 400, "Bad Request", "Content-Digest verification failed");
            } else {
                res.status_code = 400;
            }
            return false;
        }
    }
    if cfg.dpop_public_key.len > 0 {
        let dpop_jwt = header(req, "DPoP");
        let now_sec = (now_ns / 1000000000) as i64;
        let ok_dpop = dpop_jwt.len > 0 && verify_dpop_proof_with_replay_cache(
            dpop_jwt, cfg.dpop_public_key[..], req.method[..], req.url[..], now_sec, cfg.dpop_replay_cache,
        );
        if !ok_dpop {
            res.status_code = 401;
            return false;
        }
    }
    if cfg.sig_public_key.len > 0 {
        if !verify_request_ed25519(req, cfg.sig_key_id[..], cfg.sig_public_key[..]) {
            res.status_code = 401;
            return false;
        }
    }
    return true;
}

// Executes post-handler egress stages matching the effective PSO or server egress mask.
fn dispatch_egress_pipeline(
    cfg:          ServerPipelineConfig&,
    req:          const Request&,
    res:          Response&,
    mask:         u64,
    now_ns:       u64 = 0,
    ext_slot_idx: i32 = -1,
) {
    let egress_mask = mask & 0xFFFFFFFF00000000;
    let compress_bits = STAGE_EGRESS_COMPRESS_GZIP | STAGE_EGRESS_COMPRESS_BROTLI | STAGE_EGRESS_COMPRESS_ZSTD;
    if (egress_mask & compress_bits) != 0 {
        let _ = stage_server_compress(req, res, egress_mask);
    }
    if (egress_mask & STAGE_EGRESS_ETAG) != 0 {
        let _ = stage_server_etag(req, res);
    }
    if (egress_mask & STAGE_EGRESS_SECURITY_HEADERS) != 0 {
        let _ = stage_server_security_headers(res);
    }
    if (egress_mask & (STAGE_EGRESS_METRICS | STAGE_EGRESS_ACCESS_LOG)) != 0 {
        if ext_slot_idx >= 0 && ext_slot_idx < cfg.ext_pool.slots.len {
            let _ = stage_server_metrics_log(cfg.ext_pool.slots[ext_slot_idx], res, egress_mask, now_ns);
        } else {
            var dummy_ext = internal::RequestExtensions { start_time_ns: now_ns, .. };
            let _ = stage_server_metrics_log(dummy_ext, res, egress_mask, now_ns);
        }
    }
}

// Dispatches route payloads and headers registered in `cfg.router.static_payloads` for `handler_id`.
fn apply_route_payload(cfg: const ServerPipelineConfig&, handler_id: i32, res: Response&) {
    let _ = get_static_route_payload(cfg.router, handler_id, res);
}

fn execute_found_route_handler<UserStage>(
    cfg:          ServerPipelineConfig&,
    req:          const Request&,
    now_ns:       u64,
    res:          Response&,
    out_future:   internal::InlineHandlerFuture&,
    f:            const RouteMatchFound&,
    ext_slot_idx: i32,
    sctx:         ServerStageCtx&,
    user_stage:   UserStage&,
) -> PipelineOutcome {
    if req.method[..] == rfc::METHOD_QUERY && header(req, rfc::HEADER_CONTENT_TYPE).len == 0 {
        res.status_code = 400; // Bad Request
        return PipelineOutcome.Handled;
    }

    let wants_cookie = (f.entries_mask & internal::ENTRY_COOKIES) != 0;
    let cookie_unpopulated = (cfg.ext_pool.slots[ext_slot_idx].populated_entries & internal::ENTRY_COOKIES) == 0;
    if wants_cookie && cookie_unpopulated {
        let _ = stage_server_auth_cookie(cfg.private_jar, req, cfg.ext_pool.slots[ext_slot_idx], now_ns);
    }

    let now_ms = now_ns / 1000000;
    if (f.ingress_mask & wire::STAGE_SRV_IN_CACHE_LOOKUP) != 0 {
        let c_v = stage_server_cache_lookup(cfg.route_cache, req, now_ms, res, f.handler_id);
        let is_cached = match c_v { ShortCircuit _ => true, _ => false };
        if is_cached {
            return PipelineOutcome.Handled;
        }
    }

    let _prof_h = prof_enter("stage.handler");
    out_future = internal::new_inline_handler_future(f.handler_id as u16);
    internal::poll_future(out_future);

    res.status_code = 0;
    let route_v = user_stage.on_server_stage(wire::ServerHookPhase.RouteHandler, cfg, req, sctx, res);
    match route_v {
        ShortCircuit sc => {
            if res.status_code == 0 {
                res.status_code = sc.status_code as i32;
            }
        },
        Abort _ => {
            prof_leave(_prof_h);
            cfg.route_cache.is_updating = false;
            return PipelineOutcome.CsrfRejected;
        },
        _ => {},
    };

    if res.status_code == 0 {
        res.status_code = 200;
        apply_route_payload(cfg, f.handler_id, res);
    }
    prof_leave(_prof_h);
    if (f.egress_mask & wire::STAGE_SRV_OUT_CACHE_STORE) != 0 {
        let _ = stage_server_cache_store(cfg.route_cache, now_ms, res, f.handler_id, req.url[..]);
    } else {
        cfg.route_cache.is_updating = false;
    }
    return PipelineOutcome.Handled;
}

fn dispatch_matched_route<UserStage>(
    cfg:          ServerPipelineConfig&,
    req:          const Request&,
    now_ns:       u64,
    res:          Response&,
    out_future:   internal::InlineHandlerFuture&,
    match_res:    RouteMatchResult,
    ext_slot_idx: i32,
    sctx:         ServerStageCtx&,
    user_stage:   UserStage&,
) -> PipelineOutcome {
    match match_res {
        NotFound => {
            if cfg.emit_problem_details {
                respond_problem(res, 404, "Not Found", "The requested resource was not found");
            } else {
                res.status_code = 404; // Not Found
            }
            return PipelineOutcome.RouteNotFound;
        },
        MethodNotAllowed mna => {
            if cfg.emit_problem_details {
                respond_problem(res, 405, "Method Not Allowed", "The HTTP method is not allowed");
            } else {
                res.status_code = 405; // Method Not Allowed
            }
            set_header(res, rfc::HEADER_ALLOW, mna.allow_header[..]);
            return PipelineOutcome.MethodNotAllowed;
        },
        Found f => {
            return execute_found_route_handler(
                cfg, req, now_ns, res, out_future, f, ext_slot_idx, sctx, user_stage,
            );
        },
    };
}

// RFC 9110 Section 9.3.2: HEAD - Suppress body for HEAD requests while preserving Content-Length.
fn handle_head_method_suppression(req_method: const u8[:], res: Response&) {
    guard req_method == rfc::METHOD_HEAD else { return; }
    if header(res, rfc::HEADER_CONTENT_LENGTH).len == 0 && res.body.len > 0 {
        var cl_buf: u8[..32] = [];
        res.body.len.format_i64_dec(cl_buf);
        set_header(res, rfc::HEADER_CONTENT_LENGTH, cl_buf[..]);
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
        val = val[1..^1];
    }
    guard val.len > 0 else { return ""; }

    if core::starts_with(val, "[") {
        let close_br = val.index_of_byte(']');
        guard close_br > 1 else { return ""; }
        return val[1..close_br];
    }

    let col1 = val.index_of_byte(':');
    guard col1 > 0 else { return val; }
    let col2 = val[(col1 + 1)..].index_of_byte(':');
    guard col2 < 0 else { return val; }
    return val[..col1];
}

// Parses a single key=value pair from a Forwarded header element.
//
// Example:
//   pair = "for=\"192.0.2.60:4711\""
//   returns: "192.0.2.60"
fn parse_forwarded_pair(pair: const u8[:]) -> const u8[:] {
    let trimmed = pair.trim_lws();
    let eq_idx = trimmed.index_of_byte('=');
    guard eq_idx > 0 else { return ""; }
    let key = trimmed[..eq_idx].trim_lws();
    guard key.eq_ascii_fold("for") else { return ""; }
    return normalize_forwarded_ip(trimmed[(eq_idx + 1)..].trim_lws());
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

            let ip = parse_forwarded_pair(pair);
            if ip.len > 0 {
                return ip;
            }
        }
    }
    return "";
}

inline fn is_trusted_proxy_peer(trust_proxy_headers: bool, client_ip: const u8[:]) -> bool {
    return trust_proxy_headers || client_ip == "127.0.0.1" || client_ip == "::1";
}

fn has_custom_forwarding_header(map: const HeaderMap&) -> bool {
    for &e in map.entries {
        if e.well_known_id == 0xFF {
            return true;
        }
    }
    return false;
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
    guard is_trusted_proxy_peer(trust_proxy_headers, client_ip) &&
        has_custom_forwarding_header(req.headers) else {
        return client_ip;
    }
    let fwd = header(req, rfc::HEADER_FORWARDED);
    if fwd.len > 0 {
        let fwd_ip = extract_rfc7239_forwarded_for(fwd);
        if fwd_ip.len > 0 && fwd_ip.len <= 48 {
            return fwd_ip;
        }
    }
    let real_ip = normalize_forwarded_ip(header(req, rfc::HEADER_X_REAL_IP).trim_lws());
    if real_ip.len > 0 && real_ip.len <= 48 {
        return real_ip;
    }
    let xff = header(req, rfc::HEADER_X_FORWARDED_FOR);
    if xff.len > 0 {
        let comma_idx = xff.index_of_byte(',');
        let raw_first = if comma_idx >= 0 {
            xff[..comma_idx].trim_lws()
        } else {
            xff.trim_lws()
        };
        let first_ip = normalize_forwarded_ip(raw_first);
        if first_ip.len > 0 && first_ip.len <= 48 {
            return first_ip;
        }
    }
    return client_ip;
}

// Resolves the effective pipeline mask from route match result and server capabilities.
inline fn resolve_route_effective_pso(res: RouteMatchResult, caps: u64) -> u64 {
    return match res {
        Found f => f.pso_mask & caps,
        _ => (DEFAULT_ROUTE_PSO_MASK | STAGE_INGRESS_CORS_PREFLIGHT) & caps,
    };
}

// Updates `sctx` fields (`handler_id`, `entries_mask`, `ingress_mask`, `egress_mask`) from `match_res`.
inline fn sync_stage_ctx_with_route(sctx: ServerStageCtx&, match_res: RouteMatchResult) {
    match match_res {
        Found f => {
            sctx.handler_id = f.handler_id;
            sctx.entries_mask = f.entries_mask;
            sctx.ingress_mask = f.ingress_mask;
            sctx.egress_mask = f.egress_mask;
        },
        _ => {},
    };
}

// Finalizes slowloris request lifecycle tracking.
inline fn notify_pipeline_timer_end(timer_enabled: bool, timer: internal::ConnectionTimer&) {
    if timer_enabled {
        internal::notify_request_end(timer);
    }
}

// Executes an incoming request through the configured pipeline stages with a compile-time `<UserStage>` hook.
fn execute_server_pipeline_with_stage<UserStage>(
    cfg:        ServerPipelineConfig&,
    conn_timer: internal::ConnectionTimer&,
    client_ip:  const u8[:],
    req:        const Request&,
    now_ns:     u64,
    res:        Response&,
    out_future: internal::InlineHandlerFuture&,
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
    let ext_slot_idx = internal::acquire_extensions(cfg.ext_pool);
    guard ext_slot_idx >= 0 else {
        notify_pipeline_timer_end(cfg.enable_slowloris_timer, conn_timer);
        res.status_code = 503; // Service Unavailable / Pool Exhausted
        return PipelineOutcome.RateLimited;
    }
    defer internal::release_extensions(cfg.ext_pool, ext_slot_idx);
    defer notify_pipeline_timer_end(cfg.enable_slowloris_timer, conn_timer);

    let e_idx = ext_slot_idx as i64;
    let _ = cfg.ext_pool.slots[e_idx].peer_ip.try_set(eff_ip[..min(eff_ip.len, 48)]);
    cfg.ext_pool.slots[e_idx].canon_url.clear();
    cfg.ext_pool.slots[e_idx].start_time_ns = now_ns;

    var sctx = ServerStageCtx {
        ext_slot_idx: ext_slot_idx,
        pso_mask:     cfg.server_pso_capabilities,
        ingress_mask: cfg.wire_pipeline.ingress_mask,
        egress_mask:  cfg.wire_pipeline.egress_mask,
        now_ns:       now_ns,
        outcome:      PipelineOutcome.Handled,
        ..
    };

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

    if cfg.security_txt.is_valid && is_security_txt_path(req.url[..]) &&
       (req.method[..] == "GET" || req.method[..] == "HEAD") {
        res.status_code = 200;
        set_header(res, "Content-Type", "text/plain; charset=utf-8");
        res.body.clear();
        format_security_txt(cfg.security_txt, res.body);
        handle_head_method_suppression(req.method[..], res);
        return PipelineOutcome.Handled;
    }

    let _prof_rm = prof_enter("stage.route_match");
    let match_res = cfg.router.match_route(
        req.method[..],
        req.url[..],
        cfg.ext_pool.slots[e_idx].params,
        cfg.ext_pool.slots[e_idx].canon_url,
    );
    match match_res {
        Found _ => {
            let c_len = min(cfg.ext_pool.slots[e_idx].canon_url.len, 64);
            let _ = cfg.ext_pool.slots[e_idx].matched_route.try_set(cfg.ext_pool.slots[e_idx].canon_url[..c_len]);
        },
        _ => {},
    };
    sync_stage_ctx_with_route(sctx, match_res);
    prof_leave(_prof_rm);

    let effective_pso = resolve_route_effective_pso(match_res, cfg.server_pso_capabilities);
    cfg.ext_pool.slots[e_idx].effective_pso = effective_pso;
    sctx.pso_mask = effective_pso;

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
            return ingress_outcome;
        }
    }

    let user_in_v = user_stage.on_server_stage(wire::ServerHookPhase.PostAuth, cfg, req, sctx, res);
    match user_in_v {
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

    let outcome = dispatch_matched_route(
        cfg, req, now_ns, res, out_future, match_res, ext_slot_idx, sctx, user_stage,
    );
    sctx.outcome = outcome;

    if outcome == PipelineOutcome.Handled {
        dispatch_egress_pipeline(cfg, req, res, effective_pso, now_ns, ext_slot_idx);
        let user_out_v = user_stage.on_server_stage(wire::ServerHookPhase.PreSerialize, cfg, req, sctx, res);
        match user_out_v {
            ShortCircuit sc => {
                res.status_code = sc.status_code as i32;
            },
            _ => {},
        };
    }

    handle_head_method_suppression(req.method[..], res);
    return outcome;
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
    conn_timer: internal::ConnectionTimer&,
    client_ip:  const u8[:],
    req:        const Request&,
    now_ns:     u64,
    res:        Response&,
    out_future: internal::InlineHandlerFuture&,
) -> PipelineOutcome {
    var noop = wire::NoOpStage {};
    return execute_server_pipeline_with_stage(cfg, conn_timer, client_ip, req, now_ns, res, out_future, noop);
}

// ---- Streaming L7 Body Chunk Pipeline ---------------------------------------

struct ServerBodyStreamState {
    sha256_ctx:      core::Sha256Ctx = core::Sha256Ctx { .. },
    expected_sha256: u8[..32]        = [],
    verify_digest:   bool            = false,
    decompress_gzip: bool            = false,
    decompress_zstd: bool            = false,
    bytes_processed: u64             = 0,
    has_error:       bool            = false,
}

// Extracts and decodes the 32-byte SHA-256 digest from an RFC 9530 Content-Digest header.
//
// Example:
//   hdr = "sha-256=:uU0nuZNNPgilLlLX2n2r+sSE7+N6U4DukIj3rOLvzek=:"
//   returns: [185, 77, 39, 185, ...], true
fn extract_sha256_content_digest(hdr: const u8[:]) -> u8[..32], bool {
    var out_sha256: u8[..32]          = [];
    var entries:    SfDictEntry[..16] = [];
    guard parse_sf_dict(hdr, entries) else { return out_sha256, false; }
    for &e in entries {
        guard e.key[..].eq_ascii_fold(rfc::DIGEST_ALG_SHA256) else { continue; }
        guard e.item.kind == SfType.Binary else { return out_sha256, false; }
        guard core::base64_decode(e.item.str_val[..], out_sha256) && out_sha256.len == 32 else {
            out_sha256.clear();
            return out_sha256, false;
        }
        return out_sha256, true;
    }
    return out_sha256, false;
}

// Initializes streaming body verification (`Content-Digest`) and decompression (`Content-Encoding`) state.
fn begin_server_body_stream(req: const Request&, ingress_mask: u64) -> ServerBodyStreamState, bool {
    var state = ServerBodyStreamState { .. };
    if (ingress_mask & wire::STAGE_SRV_IN_CONTENT_DIGEST) != 0 {
        let cd_hdr = header(req, rfc::HEADER_CONTENT_DIGEST);
        if cd_hdr.len > 0 {
            let dig, ok_dig = extract_sha256_content_digest(cd_hdr);
            guard ok_dig else {
                state.has_error = true;
                return state, false;
            }
            state.expected_sha256 = dig;
            state.verify_digest = true;
        }
    }
    if (ingress_mask & wire::STAGE_SRV_IN_DECOMPRESS) != 0 {
        let ce_hdr = header(req, rfc::HEADER_CONTENT_ENCODING).trim_lws();
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
    _req:     const Request&,
    _ctx:     ServerStageCtx&,
    _chunk:   const u8[:],
    _is_last: bool,
    _res:     Response&,
) -> wire::StageVerdict {
    return wire::StageVerdict.Continue;
}

// Composes two independent server stages `<First, Next>` sequentially on each streaming body chunk.
inline fn on_server_body_chunk<First, Next>(
    chain:   wire::StageChain<First, Next>&,
    cfg:     ServerPipelineConfig&,
    req:     const Request&,
    ctx:     ServerStageCtx&,
    chunk:   const u8[:],
    is_last: bool,
    res:     Response&,
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
    req:        const Request&,
    sctx:       ServerStageCtx&,
    chunk:      const u8[:],
    is_last:    bool,
    res:        Response&,
    user_stage: UserStage&,
) -> wire::StageVerdict {
    guard !state.has_error else {
        res.status_code = 400;
        return wire::StageVerdict.ShortCircuit { status_code: 400 };
    }
    var decoded: u8[..16384] = [];
    if state.decompress_zstd && chunk.len > 0 {
        let ok_z, _ = core::zstd_decompress_with_limit(chunk, decoded, 16384);
        guard ok_z else {
            state.has_error = true;
            res.status_code = 400;
            return wire::StageVerdict.ShortCircuit { status_code: 400 };
        }
    } else if state.decompress_gzip && chunk.len > 0 {
        let ok_g, _ = core::gzip_decompress_with_limit(chunk, decoded, 16384);
        guard ok_g else {
            state.has_error = true;
            res.status_code = 400;
            return wire::StageVerdict.ShortCircuit { status_code: 400 };
        }
    }
    let active_chunk = if (state.decompress_zstd || state.decompress_gzip) && chunk.len > 0 {
        decoded[..]
    } else {
        chunk
    };
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
