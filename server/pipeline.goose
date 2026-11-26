// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Server request execution pipeline with Tier 2 L7 stage bricks, UFCS-replaceable subsystems,
// rate limiting, CORS/CSRF evaluation, routing, JWT/cookie auth, route caching, and pooling.
namespace server;

import std;
import core;
import rfc.http;
import .router;
import .pool;
import .edge_filter;
import .cache;
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
import .pipeline_ingress_internal;
import .pipeline_egress_internal;
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
    limiter:                   security::ShardedGcraLimiter      = security::ShardedGcraLimiter { .. },
    tier_limiters:             security::ShardedGcraLimiter[..4] = [],
    csrf_guard:                security::CrossOriginGuard        = security::CrossOriginGuard { .. },
    cors_policy:               security::CorsPolicy              = security::CorsPolicy { .. },
    router:                    RadixRouter                       = RadixRouter { .. },
    private_jar:               security::PrivateJar              = security::PrivateJar { .. },
    edge_filter:               EdgeFilter                        = EdgeFilter { .. },
    route_cache:               HttpRouteCache                    = HttpRouteCache { .. },
    jwks:                      auth::Jwks                        = auth::Jwks { .. },
    jwt_options:               auth::JwtValidationOptions        = auth::JwtValidationOptions { .. },
    security_txt:              http::SecurityTxt                 = http::SecurityTxt { .. },
    dpop_replay_cache:         auth::DPoPReplayCache             = auth::DPoPReplayCache { .. },
    dpop_public_key:           u8[..64]                          = [],
    sig_key_id:                u8[..64]                          = [],
    sig_public_key:            u8[..64]                          = [],
    verify_request_digest:     bool                              = false,
    emit_problem_details:      bool                              = false,
    wire_pipeline:             wire::WirePipeline                = wire::default_server_pipeline(),
    header_pool:               server_internal::HeaderMapPool    = server_internal::HeaderMapPool { .. },
    ext_pool:                  server_internal::ExtensionsPool   = server_internal::ExtensionsPool { .. },
    slab_pool:                 server_internal::SpillSlabPool    = server_internal::SpillSlabPool { .. },
    memo:                      ServerCompressAndEtagMemo         = ServerCompressAndEtagMemo { .. },
    target_host:               u8[..256]                         = [],
    deadline_ns:               u64                               = 30000000000, // 30s
    gzip_level:                i32                               = 1,
    enable_rate_limiter:       bool                              = true,
    enable_csrf_guard:         bool                              = true,
    enable_cors:               bool                              = true,
    enable_slowloris_timer:    bool                              = true,
    tls_enabled:               bool                              = true,
    trust_proxy_headers:       bool                              = false,
    server_pso_capabilities:   u64                               = 0xFFFFFFFFFFFFFFFF,
    hdr_scan_cursor:           i64                               = 0,
    last_valid_host:           u8[..128]                         = [],
    has_valid_host:            bool                              = false,
    max_header_bytes:          i64                               = 16384,
    max_body_bytes:            i64                               = 10485760,
    max_h2_concurrent_streams: u32                               = 100,
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
    cfg.max_header_bytes = 16384;
    cfg.max_body_bytes = 10485760;
    cfg.max_h2_concurrent_streams = 100;
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
    let slot .= cfg.ext_pool.slots[ctx.ext_slot_idx];
    guard (slot.populated_entries & server_internal::ENTRY_SECURITY) != 0 else { return ""; }
    return slot.auth_subject[..];
}

// Returns the verified `JwtClaims` populated by `stage_server_auth_jwt` and `true`,
// or `(empty, false)` when the request has no authenticated security slot.
fn auth_claims(cfg: const ServerPipelineConfig&, ctx: const ServerStageCtx&) -> auth::JwtClaims, bool {
    guard ctx.ext_slot_idx >= 0 && ctx.ext_slot_idx < cfg.ext_pool.slots.len else {
        return auth::JwtClaims { .. }, false;
    }
    let slot .= cfg.ext_pool.slots[ctx.ext_slot_idx];
    guard (slot.populated_entries & server_internal::ENTRY_SECURITY) != 0 else {
        return auth::JwtClaims { .. }, false;
    }
    return slot.jwt_claims, true;
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

// Returns true when `<Stage>` does not intercept static L0 GET routes
// (`PreRoute`, `PostAuth`, `PreSerialize`, `AfterResponse`), permitting L0 fast-path bypass.
inline fn allows_fast_l0_static(_stage: const wire::NoOpStage&) -> bool {
    return true;
}

inline fn allows_fast_l0_static<Stage>(_stage: const Stage&) -> bool {
    return false;
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
        res.status_code = rfc::STATUS_BAD_REQUEST;
        return wire::StageVerdict.ShortCircuit { status_code: rfc::STATUS_BAD_REQUEST as u16 };
    }
    var decoded: u8[..16384] = [];
    let is_compressed = state.decompress_zstd || state.decompress_gzip;
    if is_compressed {
        guard state.compressed_buf.try_append(chunk) else {
            state.has_error = true;
            res.status_code = rfc::STATUS_CONTENT_TOO_LARGE;
            return wire::StageVerdict.ShortCircuit { status_code: rfc::STATUS_CONTENT_TOO_LARGE as u16 };
        }
        if !is_last {
            return wire::StageVerdict.Continue;
        }
        guard server_internal::decompress_buffered_server_stream(state, decoded) else {
            state.has_error = true;
            res.status_code = rfc::STATUS_BAD_REQUEST;
            return wire::StageVerdict.ShortCircuit { status_code: rfc::STATUS_BAD_REQUEST as u16 };
        }
    }
    let active_chunk = if is_compressed { decoded[..] } else { chunk };
    state.bytes_processed = core::add_sat_u64(state.bytes_processed, active_chunk.len as u64);
    if cfg.max_body_bytes >= 0 && state.bytes_processed > (cfg.max_body_bytes as u64) {
        state.has_error = true;
        res.status_code = rfc::STATUS_CONTENT_TOO_LARGE;
        return wire::StageVerdict.ShortCircuit { status_code: rfc::STATUS_CONTENT_TOO_LARGE as u16 };
    }
    if state.verify_digest {
        core::sha256_update(state.sha256_ctx, active_chunk);
        if is_last {
            let actual = core::sha256_final(state.sha256_ctx);
            guard core::ct_eq_bytes(actual[..], state.expected_sha256[..]) else {
                state.has_error = true;
                res.status_code = rfc::STATUS_BAD_REQUEST;
                return wire::StageVerdict.ShortCircuit { status_code: rfc::STATUS_BAD_REQUEST as u16 };
            }
        }
    }
    return user_stage.on_server_body_chunk(cfg, req, sctx, active_chunk, is_last, res);
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
                res.status_code = rfc::STATUS_INTERNAL_SERVER_ERROR;
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
        res.status_code = rfc::STATUS_OK;
        if sctx.handler_id >= 0 {
            server_internal::apply_route_payload(cfg, sctx.handler_id, res);
        }
    }
    server_internal::maybe_store_server_route_cache(cfg, req, now_ns, res, sctx.handler_id, sctx.egress_mask);
    return server_internal::complete_pipeline_egress_and_hooks(
        cfg, req, now_ns, res, -1, sctx.pso_mask, outcome, sctx, user_stage,
    );
}

// Validates request header and body sizes against configured DoS ceilings.
// Returns 0 when within limits, 431 for oversized headers, or 413 for oversized body/Content-Length.
fn check_pipeline_dos_limits(cfg: const ServerPipelineConfig&, req: const http::Request&) -> i32 {
    if cfg.max_header_bytes > 0 && req.headers.raw_buf.len > cfg.max_header_bytes {
        return rfc::STATUS_REQUEST_HEADER_FIELDS_TOO_LARGE;
    }
    guard cfg.max_body_bytes >= 0 else { return 0; }
    if req.body.len > cfg.max_body_bytes {
        return rfc::STATUS_CONTENT_TOO_LARGE;
    }
    let check_cl = req.presence_mask == 0 || (req.presence_mask & http::HDR_PRESENCE_CONTENT_LENGTH) != 0;
    guard check_cl else { return 0; }
    let cl_raw = http::header(req, rfc::HEADER_CONTENT_LENGTH);
    guard cl_raw.len > 0 else { return 0; }
    let cl_val, ok_cl = cl_raw.trim_lws().parse_i64_dec();
    if ok_cl && cl_val > cfg.max_body_bytes {
        return rfc::STATUS_CONTENT_TOO_LARGE;
    }
    return 0;
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
    let limit_status = check_pipeline_dos_limits(cfg, req);
    if limit_status != 0 {
        res.status_code = limit_status;
        http::set_header(res, "Connection", "close");
        return PipelineOutcome.Handled;
    }

    let eff_ip = extract_effective_client_ip(cfg.trust_proxy_headers, client_ip, req);

    // Stage 1: Connection liveliness / timeout check (Slowloris defense)
    let slow_v = server_internal::stage_server_slowloris(conn_timer, cfg.enable_slowloris_timer, now_ns, res);
    match slow_v {
        Abort _ => { return PipelineOutcome.SlowlorisClosed; },
        _ => {},
    };

    // Acquire request extensions from pool
    let ext_slot_idx = server_internal::acquire_extensions(cfg.ext_pool);
    guard ext_slot_idx >= 0 else {
        server_internal::notify_pipeline_timer_end(cfg.enable_slowloris_timer, conn_timer);
        res.status_code = rfc::STATUS_SERVICE_UNAVAILABLE;
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
        res.status_code = rfc::STATUS_OK;
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
