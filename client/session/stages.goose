// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Tier 2 Composable L7 Client Stage Bricks, UFCS Subsystem Hooks, and Programmable Pipeline Conveyor.
namespace client;

import std;
import core from "../..";
import rfc.http;
import cookie.constants;
import cookie.policy;
import http.request;
import http.response;
import http.headers;
import http.cache.validators;
import http.cache.engine;
import http.signatures;
import security.cors;
import security.cross_origin_isolation;
import client.client;
import client.session.exec;
import .internal;
import wire.pipeline;

// ---- 1. Public Composable L7 Client Stage Bricks ----------------------------

// Performs RFC 9111 HTTP cache lookup and conditional header injection via UFCS on `cache: Cache&`.
// Returns `(StageVerdict.ShortCircuit, -1)` on fresh cache hit, `(StageVerdict.Abort, -1)` on
// `only-if-cached` miss, or `(StageVerdict.Continue, reval_idx)`.
fn stage_cache_lookup<Cache>(
    req:             const http::Request&,
    eff_url:         const u8[:],
    now_sec:         i64,
    headers:         http::HeaderMap&,
    out_resp:        http::Response&,
    cache:           Cache&,
    enable_cache:    bool,
    method_override: const u8[:] = "",
) -> wire::StageVerdict, i64 {
    guard enable_cache else { return wire::StageVerdict.Continue, -1; }
    var lookup_req = copy(req);
    let _ = lookup_req.url.try_set(eff_url);
    if method_override.len > 0 {
        let _ = lookup_req.method.try_set(method_override);
    }
    lookup_req.headers = copy(headers);
    let lookup_dec = cache.lookup(lookup_req, now_sec);
    if lookup_dec.kind == http::LookupResultKind.Hit {
        out_resp = copy(lookup_dec.cached_response);
        for &e in out_resp.headers.entries {
            http::update_response_presence(out_resp, http::entry_name(out_resp.headers, e));
        }
        http::copy_headers(headers, out_resp.sent_headers);
        return wire::StageVerdict.ShortCircuit { status_code: out_resp.status_code as u16 }, -1;
    }
    if lookup_dec.kind == http::LookupResultKind.Fail504 {
        out_resp = http::Response {
            status_code: rfc::STATUS_GATEWAY_TIMEOUT,
            ..
        };
        let _ = out_resp.effective_url.try_set(eff_url);
        return wire::StageVerdict.Abort { err_code: rfc::STATUS_GATEWAY_TIMEOUT }, -1;
    }
    var reval_idx: i64 = -1;
    if lookup_dec.kind == http::LookupResultKind.Revalidate {
        reval_idx = lookup_dec.entry_idx;
        if reval_idx >= 0 && reval_idx < cache.entries.len {
            let cond_map = cache.entries[reval_idx].build_revalidation_headers();
            client_internal::apply_cache_revalidation_headers(cond_map, headers);
        }
    }
    return wire::StageVerdict.Continue, reval_idx;
}

// Loads matching cookies from `jar: Jar&` into `headers` via UFCS `jar.encode_cookie_header_to_map(...)`.
fn stage_cookie_load<Jar>(
    headers:       http::HeaderMap&,
    current_url:   const core::Url&,
    samesite_eval: const cookie::SameSiteCookieContext&,
    is_main_frame: bool,
    part_key:      const u8[:],
    safe_method:   bool,
    now_us:        i64,
    jar:           Jar&,
    enable_jar:    bool,
) -> wire::StageVerdict {
    guard enable_jar else { return wire::StageVerdict.Continue; }
    let is_sec_channel = current_url.is_secure_scheme() ||
        cookie::is_trustworthy_non_crypto_host(current_url.hostname());
    let is_top_nav = is_main_frame && samesite_eval.context_type != cookie::SameSiteContextType.CrossSite;
    let _ = jar.encode_cookie_header_to_map(
        current_url.hostname(),
        current_url.pathname(),
        current_url.scheme(),
        current_url.effective_port(),
        cookie::SourceOptions { is_http_api: true, url_is_secure: is_sec_channel },
        part_key,
        now_us,
        cookie::AccessOptions {
            is_same_site:            samesite_eval.context_type == cookie::SameSiteContextType.SameSiteStrict,
            is_top_level_navigation: is_top_nav,
            is_safe_method:          safe_method,
            had_cross_site_hop:      samesite_eval.had_cross_site_hop,
        },
        headers,
    );
    return wire::StageVerdict.Continue;
}

// Updates RFC 9111 HTTP cache and handles 304 Not Modified freshening via UFCS `cache.on_response(...)`.
fn stage_cache_store<Cache>(
    req:            const http::Request&,
    headers:        const http::HeaderMap&,
    effective_url:  const u8[:],
    method:         const u8[:],
    out_resp:       http::Response&,
    cache_ts:       http::CacheTimestamps&,
    revalidate_idx: i64,
    cache:          Cache&,
    enable_cache:   bool,
) -> wire::StageVerdict {
    guard enable_cache else { return wire::StageVerdict.Continue; }
    cache_ts.response_sec = cache_ts.now_sec;
    var hop_req = copy(req);
    let _ = hop_req.url.try_set(effective_url);
    let _ = hop_req.method.try_set(method);
    hop_req.headers = copy(headers);
    let resp_dec = cache.on_response(hop_req, out_resp, cache_ts, revalidate_idx);
    if resp_dec.kind == http::ResponseDecisionKind.FreshenAndReturn {
        out_resp = copy(resp_dec.response);
        for &e in out_resp.headers.entries {
            http::update_response_presence(out_resp, http::entry_name(out_resp.headers, e));
        }
    }
    return wire::StageVerdict.Continue;
}

// Validates client-side CORS (`Access-Control-Allow-Origin`) and CORP (`Cross-Origin-Resource-Policy`)
// on cross-origin responses when `ctx.cors_mode` or `Cross-Origin-Resource-Policy` is present.
fn validate_cors_and_corp_response(
    ctx:         const RequestExecutionContext&,
    current_url: const core::Url&,
    resp:        const http::Response&,
) -> http::Error {
    guard ctx.has_initiator else { return http::Error { .. }; }
    let is_opaque = ctx.initiator.kind == core::OriginKind.Opaque;
    let is_tainted = ctx.tainted_origin || is_opaque;
    let target_orig = core::origin_from_url(current_url);
    var init_orig_str:   u8[..256] = [];
    var target_orig_str: u8[..256] = [];
    core::serialize_origin(ctx.initiator, init_orig_str);
    core::serialize_origin(target_orig, target_orig_str);
    guard !init_orig_str[..].eq_ascii_fold(target_orig_str[..]) || is_tainted else {
        return http::Error { .. };
    }

    let corp_hdr = http::header(resp, "Cross-Origin-Resource-Policy");
    if corp_hdr.len > 0 {
        var iso_ctx = security::CrossOriginIsolationContext { .. };
        let _ = iso_ctx.document_origin.try_set(init_orig_str[..]);
        if !security::is_subresource_allowed(iso_ctx, target_orig_str[..], corp_hdr) {
            return http::make_error(rfc::STATUS_FORBIDDEN, "corp", "ERR_BLOCKED_BY_RESPONSE: CORP violation");
        }
    }

    if ctx.cors_mode {
        let raw_orig = http::find_header(ctx.headers, "Origin");
        let req_orig = if raw_orig.len > 0 { raw_orig } else if is_tainted { "null" } else { "" };
        if req_orig.len > 0 {
            let include_creds = http::find_header(ctx.headers, "Cookie").len > 0 ||
                http::find_header(ctx.headers, "Authorization").len > 0;
            let cors_opts = security::ClientCorsVerifyOptions {
                tainted_origin:      is_tainted,
                include_credentials: include_creds,
            };
            if !security::verify_client_cors_response(resp.headers, req_orig, cors_opts) {
                return http::make_error(rfc::STATUS_FORBIDDEN, "cors", "ERR_FAILED: CORS response check failed");
            }
        }
    }
    return http::Error { .. };
}

fn verify_response_signature(
    session:     const Client&,
    req:         const http::Request&,
    current_url: const core::Url&,
    method:      const u8[:],
    headers:     const http::HeaderMap&,
    resp:        const http::Response&,
) -> bool {
    guard session.sig_public_key.len == 32 else { return true; }
    let has_sig = http::has_header(resp, rfc::HEADER_SIGNATURE) && http::has_header(resp, rfc::HEADER_SIGNATURE_INPUT);
    guard has_sig else { return false; }
    var hop_req = copy(req);
    let _ = hop_req.method.try_set(method);
    let _ = hop_req.url.try_set(current_url.href[..]);
    hop_req.headers = copy(headers);
    return http::verify_response_ed25519(resp, hop_req, session.sig_key_id[..], session.sig_public_key[..]);
}

// ---- 2. Programmable Client Stage Context & User Hooks ----------------------

// Context passed to user-injected client stages (`on_stage`).
struct StageCtx {
    current_url:    core::Url          = core::Url { .. },
    current_method: u8[..16]           = [],
    headers:        http::HeaderMap    = http::HeaderMap { .. },
    pipeline:       wire::WirePipeline = wire::default_client_pipeline(),
    redirect_count: i32                = 0,
    auth_retried:   bool               = false,
    now_us:         i64                = 0,
    last_error:     http::Error        = http::Error { .. },
    // Resizable field must be final
    resp: http::Response = http::Response { .. },
}

// Default no-op check for `wire::NoOpStage` to skip `HeaderMap` / `Response` stack copies on the default path.
inline fn is_noop_stage(_stage: const wire::NoOpStage&) -> bool {
    return true;
}

// Generic fallback returning false for any custom `<Stage>` implementation.
inline fn is_noop_stage<Stage>(_stage: const Stage&) -> bool {
    return false;
}

// Default no-op hook for `wire::NoOpStage` by `ClientHookPhase`.
inline fn on_stage(
    _stage: wire::NoOpStage&,
    _phase: wire::ClientHookPhase,
    _ctx:   StageCtx&,
) -> wire::StageVerdict {
    return wire::StageVerdict.Continue;
}

// Default no-op fallback for custom client stages that only implement `on_custom_slot`.
inline fn on_stage<Stage>(
    _stage: Stage&,
    _phase: wire::ClientHookPhase,
    _ctx:   StageCtx&,
) -> wire::StageVerdict {
    return wire::StageVerdict.Continue;
}

// Composes two independent client stages `<First, Next>` sequentially at each `ClientHookPhase`.
// Short-circuits, retries, or aborts immediately if `chain.first` does not return `StageVerdict.Continue`.
inline fn invoke_stage_hook<First, Next>(
    chain: wire::StageChain<First, Next>&,
    tag:   u8,
    phase: wire::ClientHookPhase,
    ctx:   StageCtx&,
) -> wire::StageVerdict {
    var p = wire::begin_pipeline();
    if p.step(invoke_stage_hook(chain.first, tag, phase, ctx)) {
        let _ = p.step(invoke_stage_hook(chain.next, tag, phase, ctx));
    }
    return p.verdict;
}

// Invokes `on_stage` on a single leaf client `<Stage>` (`_tag: i64` ranks below `tag: u8` for `StageChain`).
inline fn invoke_stage_hook<Stage>(
    stage: Stage&,
    _tag:  i64,
    phase: wire::ClientHookPhase,
    ctx:   StageCtx&,
) -> wire::StageVerdict {
    return stage.on_stage(phase, ctx);
}

// Default no-op custom slot hook for `wire::NoOpStage`.
inline fn on_custom_slot(
    _stage:    wire::NoOpStage&,
    _slot_id:  u8,
    _ctx:      StageCtx&,
    _headers:  http::HeaderMap&,
    _out_resp: http::Response&,
) -> wire::StageVerdict {
    return wire::StageVerdict.Continue;
}

// Composes two independent client stages `<First, Next>` sequentially at a custom stage slot (`STAGE_ID_USER_0..3`).
inline fn on_custom_slot<First, Next>(
    chain:    wire::StageChain<First, Next>&,
    slot_id:  u8,
    ctx:      StageCtx&,
    headers:  http::HeaderMap&,
    out_resp: http::Response&,
) -> wire::StageVerdict {
    var p = wire::begin_pipeline();
    if p.step(chain.first.on_custom_slot(slot_id, ctx, headers, out_resp)) {
        let _ = p.step(chain.next.on_custom_slot(slot_id, ctx, headers, out_resp));
    }
    return p.verdict;
}

// Default no-op fallback for custom client stages that only implement `on_stage`.
inline fn on_custom_slot<Stage>(
    _stage:    Stage&,
    _slot_id:  i64,
    _ctx:      StageCtx&,
    _headers:  http::HeaderMap&,
    _out_resp: http::Response&,
) -> wire::StageVerdict {
    return wire::StageVerdict.Continue;
}

// ---- 3. Public Pre-Hop & Top-Level Pipeline Entrypoints ---------------------

// Runs all enabled pre-hop client ingress stages in `session.wire_pipeline.ingress_stages` order,
// followed by `<UserStage>` at `ClientHookPhase.PreWireHop`.
fn run_pre_hop_stages<UserStage>(
    session:       Client&,
    ctx:           RequestExecutionContext&,
    current_url:   core::Url&,
    samesite_eval: cookie::SameSiteCookieContext&,
    safe_method:   bool,
    now_sec:       i64,
    out_resp:      http::Response&,
    out_err:       http::Error&,
    user_stage:    UserStage&,
) -> wire::StageVerdict {
    var p = wire::begin_pipeline();
    for i in session.wire_pipeline.ingress_stages.len {
        let stage_id = session.wire_pipeline.ingress_stages[i];
        guard wire::is_ingress_stage_enabled(session.wire_pipeline, stage_id) else { continue; }
        let v = if wire::is_user_stage_slot(stage_id) {
            client_internal::invoke_client_custom_slot(
                user_stage, stage_id, session, ctx, current_url, out_resp, out_err,
            )
        } else {
            client_internal::dispatch_client_ingress_stage(
                stage_id,
                session,
                ctx,
                current_url,
                samesite_eval,
                safe_method,
                now_sec,
                out_err,
            )
        };
        if !p.step(v) {
            return p.verdict;
        }
    }

    if !is_noop_stage(user_stage) {
        var s_ctx = StageCtx {
            current_url:    current_url,
            current_method: copy(ctx.current_method),
            headers:        copy(ctx.headers),
            pipeline:       session.wire_pipeline,
            redirect_count: ctx.redirect_count as i32,
            auth_retried:   ctx.auth_retried,
            now_us:         session.virtual_clock_us,
            last_error:     out_err,
            resp:           copy(out_resp),
        };
        let hook_v = invoke_stage_hook(user_stage, 0 as u8, wire::ClientHookPhase.PreWireHop, s_ctx);
        ctx.headers = copy(s_ctx.headers);
        if !p.step(hook_v) {
            out_resp = copy(s_ctx.resp);
            if !http::ok(s_ctx.last_error) {
                out_err = s_ctx.last_error;
            }
            return p.verdict;
        }
    }
    return wire::StageVerdict.Continue;
}

// Executes a client request through `session.wire_pipeline` with an injected compile-time `<UserStage>` hook.
fn execute_pipeline_with_stage<UserStage>(
    session:    Client&,
    req:        const http::Request&,
    user_stage: UserStage&,
) -> http::Response, http::Error {
    var raw_eff_url: u8[..2048] = [];
    build_effective_url(session.base_url[..], req.url[..], req.query_params[..], raw_eff_url);

    let req_sec = div_euclid(session.virtual_clock_us, 1000000);
    var cache_ts = http::CacheTimestamps {
        request_sec: req_sec,
        now_sec:     req_sec,
        ..
    };

    var ctx = RequestExecutionContext { .. };
    var pre_resp = http::Response { .. };
    var pre_err = http::Error { .. };
    var cache_revalidate_idx: i64 = -1;

    let pre_verdict = client_internal::run_client_preflight_stages(
        session,
        req,
        raw_eff_url,
        cache_ts,
        ctx,
        pre_resp,
        pre_err,
        cache_revalidate_idx,
        user_stage,
    );
    var pre_p = wire::begin_pipeline();
    if !pre_p.step(pre_verdict) {
        return pre_resp, pre_err;
    }

    while ctx.redirect_count <= ctx.max_redirects {
        var resp = http::Response { .. };
        var hop_err = http::Error { .. };
        let done = client_internal::execute_single_client_hop_iteration(
            session,
            ctx,
            req,
            cache_ts,
            cache_revalidate_idx,
            resp,
            hop_err,
            user_stage,
        );
        if done {
            return resp, hop_err;
        }
    }

    let err_max = http::make_error(rfc::STATUS_BAD_REQUEST, "redirect", "maximum redirect hops exceeded");
    return http::Response { .. }, err_max;
}
