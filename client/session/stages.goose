// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Public programmable L7 client stage context, compile-time stage hooks, and pipeline runner.
namespace client;

import std;
import core;
import rfc.http;
import http.request;
import http.response;
import http.headers;
import http.cache.engine;
import wire.pipeline;
import client.client;
import .hop_context_internal;
import .pipeline_internal;

// ---- 1. Programmable Client Stage Context & User Hooks ----------------------

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

// ---- 2. Top-Level Programmable Pipeline Entrypoint --------------------------

// Executes a client request through `session.wire_pipeline` with an injected compile-time `<UserStage>` hook.
fn execute_pipeline_with_stage<UserStage>(
    session:    Client&,
    req:        const http::Request&,
    user_stage: UserStage&,
) -> http::Response, http::Error {
    var raw_eff_url: u8[..2048] = [];
    client_internal::build_effective_url(session.base_url[..], req.url[..], req.query_params[..], raw_eff_url);

    let req_sec = div_euclid(effective_clock_us(session), 1000000);
    var cache_ts = http::CacheTimestamps {
        request_sec: req_sec,
        now_sec:     req_sec,
        ..
    };

    var ctx = client_internal::RequestExecutionContext { .. };
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
