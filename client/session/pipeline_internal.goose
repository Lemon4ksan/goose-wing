// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Internal L7 client pipeline conveyor (preflight, ingress/egress dispatch, auth-retry loop, and single-hop driver).
namespace client_internal;

import std;
import core;
import rfc.http;
import cookie.policy;
import http.request;
import http.response;
import http.headers;
import http.cache.engine;
import wire.pipeline;
import client.client;
import client.internal;
import .stages;
import .tls_hop_internal;
import .hop_context_internal;
import .hop_auth_internal;
import .stage_bricks_internal;
import .hop_dispatch_internal;

fn run_preflight_cache_lookup(
    session:              client::Client&,
    req:                  const http::Request&,
    parsed_initial:       const core::Url&,
    cache_ts:             const http::CacheTimestamps&,
    ctx:                  RequestExecutionContext&,
    out_resp:             http::Response&,
    out_err:              http::Error&,
    cache_revalidate_idx: i64&,
) -> wire::StageVerdict {
    var cache_hdrs = copy(ctx.headers);
    let cookie_stage_on = wire::is_ingress_stage_enabled(session.wire_pipeline, wire::STAGE_ID_CLI_IN_COOKIE_LOAD);
    if session.enable_cookie_jar && cookie_stage_on {
        var tmp_ctx = copy(ctx);
        let safe_m = rfc::is_safe_http_method(tmp_ctx.current_method[..]);
        let ss_eval = compute_hop_samesite_context(tmp_ctx, parsed_initial, safe_m);
        prepare_hop_cookie_header(session, tmp_ctx, parsed_initial, ss_eval, safe_m);
        cache_hdrs = copy(tmp_ctx.headers);
    }
    let v_cache, reval_idx = stage_cache_lookup(
        req,
        parsed_initial.href[..],
        cache_ts.now_sec,
        cache_hdrs,
        out_resp,
        session.cache,
        session.enable_cache,
    );
    cache_revalidate_idx = reval_idx;
    if cache_revalidate_idx >= 0 {
        let inm = http::get_header(cache_hdrs, "If-None-Match");
        if inm.len > 0 { http::set_header(ctx.headers, "If-None-Match", inm); }
        let ims = http::get_header(cache_hdrs, "If-Modified-Since");
        if ims.len > 0 { http::set_header(ctx.headers, "If-Modified-Since", ims); }
    }
    match v_cache {
        ShortCircuit _ => {
            out_err = http::Error { .. };
            return v_cache;
        },
        Abort ab => {
            out_err = http::make_error(ab.err_code, "cache", "504 Gateway Timeout (only-if-cached miss)");
            return v_cache;
        },
        _ => {},
    };
    return wire::StageVerdict.Continue;
}

fn run_preflight_user_hook<UserStage>(
    session:        const client::Client&,
    parsed_initial: const core::Url&,
    ctx:            RequestExecutionContext&,
    out_resp:       http::Response&,
    out_err:        http::Error&,
    user_stage:     UserStage&,
) -> wire::StageVerdict {
    guard !client::is_noop_stage(user_stage) else { return wire::StageVerdict.Continue; }
    var s_ctx = client::StageCtx {
        current_url:    parsed_initial,
        current_method: copy(ctx.current_method),
        headers:        copy(ctx.headers),
        pipeline:       session.wire_pipeline,
        redirect_count: ctx.redirect_count as i32,
        auth_retried:   ctx.auth_retried,
        now_us:         session.virtual_clock_us,
        last_error:     out_err,
        resp:           copy(out_resp),
    };
    let u_verdict = client::invoke_stage_hook(user_stage, 0 as u8, wire::ClientHookPhase.PreFlight, s_ctx);
    ctx.headers = copy(s_ctx.headers);
    match u_verdict {
        ShortCircuit sc => {
            out_resp = copy(s_ctx.resp);
            if out_resp.status_code == 0 {
                out_resp.status_code = sc.status_code as i32;
            }
            return u_verdict;
        },
        Abort ab => {
            out_err = if !http::ok(s_ctx.last_error) {
                s_ctx.last_error
            } else {
                http::make_error(ab.err_code, "user_stage", "aborted by client pre-flight stage")
            };
            return u_verdict;
        },
        _ => {},
    };
    return wire::StageVerdict.Continue;
}

fn run_client_preflight_stages<UserStage>(
    session:              client::Client&,
    req:                  const http::Request&,
    raw_eff_url:          u8[..2048]&,
    cache_ts:             const http::CacheTimestamps&,
    ctx:                  RequestExecutionContext&,
    out_resp:             http::Response&,
    out_err:              http::Error&,
    cache_revalidate_idx: i64&,
    user_stage:           UserStage&,
) -> wire::StageVerdict {
    let now_sec = div_euclid(session.virtual_clock_us, 1000000);
    if wire::is_ingress_stage_enabled(session.wire_pipeline, wire::STAGE_ID_CLI_IN_URL_HSTS) {
        let _ = stage_client_url_hsts(raw_eff_url, session.hsts, session.enable_hsts, now_sec);
    }

    let parsed_initial, _ = core::parse_url(raw_eff_url[..]);
    guard parsed_initial.valid else {
        out_err = http::make_error(rfc::STATUS_BAD_REQUEST, "url_parse", "invalid request url");
        return wire::StageVerdict.Abort { err_code: rfc::STATUS_BAD_REQUEST };
    }

    ctx = init_execution_context(session, req, parsed_initial);
    if wire::is_ingress_stage_enabled(session.wire_pipeline, wire::STAGE_ID_CLI_IN_CACHE_LOOKUP) {
        let v_cache = run_preflight_cache_lookup(
            session, req, parsed_initial, cache_ts, ctx, out_resp, out_err, cache_revalidate_idx,
        );
        var cp = wire::begin_pipeline();
        if !cp.step(v_cache) {
            return v_cache;
        }
    }
    return run_preflight_user_hook(session, parsed_initial, ctx, out_resp, out_err, user_stage);
}

fn invoke_client_custom_slot<UserStage>(
    user_stage:  UserStage&,
    slot_id:     u8,
    session:     const client::Client&,
    ctx:         RequestExecutionContext&,
    current_url: const core::Url&,
    out_resp:    http::Response&,
    out_err:     http::Error&,
) -> wire::StageVerdict {
    guard !client::is_noop_stage(user_stage) else { return wire::StageVerdict.Continue; }
    var s_ctx = client::StageCtx {
        current_url:    current_url,
        current_method: copy(ctx.current_method),
        pipeline:       session.wire_pipeline,
        redirect_count: ctx.redirect_count as i32,
        auth_retried:   ctx.auth_retried,
        now_us:         session.virtual_clock_us,
        last_error:     out_err,
        ..
    };
    let v = client::on_custom_slot(user_stage, slot_id, s_ctx, ctx.headers, out_resp);
    if !http::ok(s_ctx.last_error) {
        out_err = s_ctx.last_error;
    }
    return v;
}

fn dispatch_ingress_dict_stage(
    session:     client::Client&,
    ctx:         RequestExecutionContext&,
    current_url: const core::Url&,
    now_sec:     i64,
) -> wire::StageVerdict {
    var origin_buf: u8[..128] = [];
    format_url_origin(current_url, origin_buf);
    let is_https = current_url.is_secure_scheme();
    let curr_path = current_url.pathname();
    if is_https && session.enable_compression_dict {
        var dict_req = http::Request { headers: copy(ctx.headers), .. };
        if attach_dictionary_request_headers(session, origin_buf[..], curr_path, dict_req) {
            ctx.headers = copy(dict_req.headers);
        }
    }
    return stage_client_dict_negotiate(
        ctx.headers,
        session.dict_cache,
        session.enable_compression_dict,
        origin_buf[..],
        curr_path,
        is_https,
        now_sec,
    );
}

fn dispatch_client_ingress_stage(
    stage_id:      u8,
    session:       client::Client&,
    ctx:           RequestExecutionContext&,
    current_url:   core::Url&,
    samesite_eval: cookie::SameSiteCookieContext&,
    safe_method:   bool,
    now_sec:       i64,
    out_err:       http::Error&,
) -> wire::StageVerdict {
    if stage_id == wire::STAGE_ID_CLI_IN_URL_HSTS {
        let v = stage_client_url_hsts(current_url, session.hsts, session.enable_hsts, now_sec);
        let last_idx = core::sub_sat_i64(ctx.url_chain.len, 1);
        if ctx.url_chain.len > 0 && last_idx < ctx.url_chain.len {
            ctx.url_chain[last_idx] = current_url;
        }
        return v;
    }
    if stage_id == wire::STAGE_ID_CLI_IN_SSRF_GUARD {
        let v_ssrf = stage_client_ssrf_guard(current_url, session.https_only, session.ssrf_guard);
        match v_ssrf {
            Abort ab => {
                out_err = validate_hop_prerequisites(session, current_url);
                return wire::StageVerdict.Abort { err_code: ab.err_code };
            },
            _ => {
                return wire::StageVerdict.Continue;
            },
        };
    }
    if stage_id == wire::STAGE_ID_CLI_IN_COOKIE_LOAD {
        samesite_eval = compute_hop_samesite_context(ctx, current_url, safe_method);
        var part_key: u8[..256] = [];
        compute_hop_partition_key(ctx, current_url, part_key);
        return stage_cookie_load(
            ctx.headers,
            current_url,
            samesite_eval,
            ctx.is_main_frame,
            part_key[..],
            safe_method,
            session.virtual_clock_us,
            session.jar,
            session.enable_cookie_jar,
        );
    }
    if stage_id == wire::STAGE_ID_CLI_IN_DICT_NEGOTIATE {
        return dispatch_ingress_dict_stage(session, ctx, current_url, now_sec);
    }
    if stage_id == wire::STAGE_ID_CLI_IN_INTERCEPTOR_AUTH {
        apply_client_early_data_and_dpop_headers(session, ctx, current_url, now_sec);
        let v_auth = stage_client_auth_header(
            session.pipeline,
            ctx.headers,
            current_url.href[..],
            ctx.current_method[..],
            ctx.body.len,
            ctx.redirect_count,
        );
        apply_client_request_signature(session, ctx, current_url);
        return v_auth;
    }
    return wire::StageVerdict.Continue;
}

// Runs all enabled pre-hop client ingress stages in `session.wire_pipeline.ingress_stages` order,
// followed by `<UserStage>` at `ClientHookPhase.PreWireHop`.
fn run_pre_hop_stages<UserStage>(
    session:       client::Client&,
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
            invoke_client_custom_slot(
                user_stage, stage_id, session, ctx, current_url, out_resp, out_err,
            )
        } else {
            dispatch_client_ingress_stage(
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

    if !client::is_noop_stage(user_stage) {
        var s_ctx = client::StageCtx {
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
        let hook_v = client::invoke_stage_hook(user_stage, 0 as u8, wire::ClientHookPhase.PreWireHop, s_ctx);
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

fn dispatch_client_egress_stage(
    stage_id:             u8,
    session:              client::Client&,
    ctx:                  RequestExecutionContext&,
    req:                  const http::Request&,
    current_url:          const core::Url&,
    samesite_eval:        const cookie::SameSiteCookieContext&,
    safe_method:          bool,
    cache_ts:             http::CacheTimestamps&,
    cache_revalidate_idx: i64,
    out_resp:             http::Response&,
    out_err:              http::Error&,
) -> wire::StageVerdict {
    if stage_id == wire::STAGE_ID_CLI_OUT_AUTH_CHALLENGE {
        let auth_v = stage_client_auth_challenge(session, ctx, current_url, samesite_eval, safe_method, out_resp);
        if auth_v != wire::StageVerdict.RetryAuth {
            ctx.body_consumed = true;
        }
        return auth_v;
    }
    if stage_id == wire::STAGE_ID_CLI_OUT_COOKIE_STORE {
        var part_key: u8[..256] = [];
        compute_hop_partition_key(ctx, current_url, part_key);
        let resp_samesite = compute_hop_samesite_context_for_response(ctx, current_url, samesite_eval);
        return stage_client_cookie_store(
            out_resp.headers,
            current_url,
            resp_samesite,
            ctx.is_main_frame,
            part_key[..],
            session.virtual_clock_us,
            session.jar,
            session.enable_cookie_jar,
        );
    }
    if stage_id == wire::STAGE_ID_CLI_OUT_ALT_SVC {
        let is_https = current_url.is_secure_scheme();
        var origin_buf: u8[..128] = [];
        format_url_origin(current_url, origin_buf);
        let curr_path = current_url.pathname();
        let now_sec = div_euclid(session.virtual_clock_us, 1000000);
        ingest_session_dictionary_response(session, is_https, origin_buf[..], out_resp);
        return stage_client_alt_svc(
            out_resp,
            current_url,
            is_https,
            origin_buf[..],
            curr_path,
            now_sec,
            session.altsvc,
            session.enable_altsvc,
            session.hsts,
            session.enable_hsts && !session.insecure_skip_verify,
            session.dict_cache,
            session.enable_compression_dict,
        );
    }
    if stage_id == wire::STAGE_ID_CLI_OUT_DECOMPRESS {
        return run_client_decompress_and_limit_stage(session, req, current_url, ctx, out_resp, out_err);
    }
    if stage_id == wire::STAGE_ID_CLI_OUT_CACHE_STORE {
        return stage_cache_store(
            req,
            ctx.headers,
            current_url.href[..],
            ctx.current_method[..],
            out_resp,
            cache_ts,
            cache_revalidate_idx,
            session.cache,
            session.enable_cache,
        );
    }
    if stage_id == wire::STAGE_ID_CLI_OUT_REDIRECT {
        return stage_client_redirect(session, ctx, out_resp, current_url, out_err);
    }
    return wire::StageVerdict.Continue;
}

fn run_client_post_hop_stages<UserStage>(
    session:              client::Client&,
    ctx:                  RequestExecutionContext&,
    req:                  const http::Request&,
    current_url:          const core::Url&,
    samesite_eval:        const cookie::SameSiteCookieContext&,
    safe_method:          bool,
    cache_ts:             http::CacheTimestamps&,
    cache_revalidate_idx: i64,
    out_resp:             http::Response&,
    out_err:              http::Error&,
    user_stage:           UserStage&,
) -> wire::StageVerdict {
    var p = wire::begin_pipeline();
    if !client::is_noop_stage(user_stage) {
        var s_ctx = client::StageCtx {
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
        let hook_v = client::invoke_stage_hook(user_stage, 0 as u8, wire::ClientHookPhase.PostWireHop, s_ctx);
        out_resp = copy(s_ctx.resp);
        if !p.step(hook_v) {
            if !http::ok(s_ctx.last_error) {
                out_err = s_ctx.last_error;
            }
            return p.verdict;
        }
    }
    for i in session.wire_pipeline.egress_stages.len {
        let stage_id = session.wire_pipeline.egress_stages[i];
        guard wire::is_egress_stage_enabled(session.wire_pipeline, stage_id) else { continue; }
        let v = if wire::is_user_stage_slot(stage_id) {
            invoke_client_custom_slot(user_stage, stage_id, session, ctx, current_url, out_resp, out_err)
        } else {
            dispatch_client_egress_stage(
                stage_id, session, ctx, req, current_url, samesite_eval, safe_method,
                cache_ts, cache_revalidate_idx, out_resp, out_err,
            )
        };
        if !p.step(v) {
            return p.verdict;
        }
    }
    ctx.body_consumed = true;
    finalize_success_response(ctx, out_resp);
    return wire::StageVerdict.Continue;
}

fn execute_client_auth_retry_hop<UserStage>(
    session:              client::Client&,
    ctx:                  RequestExecutionContext&,
    req:                  const http::Request&,
    current_url:          const core::Url&,
    samesite_eval:        const cookie::SameSiteCookieContext&,
    safe_method:          bool,
    cache_ts:             http::CacheTimestamps&,
    cache_revalidate_idx: i64,
    resp:                 http::Response&,
    hop_err:              http::Error&,
    user_stage:           UserStage&,
) -> wire::StageVerdict, bool {
    let retry_start_us = session.virtual_clock_us;
    if wire::is_ingress_stage_enabled(session.wire_pipeline, wire::STAGE_ID_CLI_IN_INTERCEPTOR_AUTH) {
        let _ = stage_client_auth_header(
            session.pipeline, ctx.headers, current_url.href[..], ctx.current_method[..],
            ctx.body.len, ctx.redirect_count,
        );
        apply_client_request_signature(session, ctx, current_url);
    }
    resp, hop_err = execute_mock_or_echo_hop(session, ctx, current_url);
    let retry_dur_us = core::sub_sat_i64(session.virtual_clock_us, retry_start_us);
    apply_network_interceptors_response(session.pipeline, resp, ctx.redirect_count, retry_dur_us);
    guard http::ok(hop_err) else { return wire::StageVerdict.Abort { err_code: hop_err.code }, false; }
    guard check_response_body_size_limit(session, resp, hop_err) else {
        return wire::StageVerdict.Abort { err_code: hop_err.code }, false;
    }

    let post_v = run_client_post_hop_stages(
        session, ctx, req, current_url, samesite_eval, safe_method,
        cache_ts, cache_revalidate_idx, resp, hop_err, user_stage,
    );
    return post_v, true;
}

fn resolve_client_verdict_outcome(
    v:       wire::StageVerdict,
    resp:    http::Response&,
    hop_err: http::Error&,
    err_msg: const u8[:],
) -> bool {
    match v {
        FollowRedirect => {
            return false;
        },
        ShortCircuit sc => {
            if resp.status_code == 0 {
                resp.status_code = sc.status_code;
            }
            hop_err = http::Error { .. };
            return true;
        },
        Abort ab => {
            if http::ok(hop_err) {
                hop_err = http::make_error(ab.err_code, "pipeline", err_msg);
            }
            return true;
        },
        _ => {
            hop_err = http::Error { .. };
            return true;
        },
    };
    return true;
}

fn run_client_auth_retry_loop<UserStage>(
    session:       client::Client&,
    ctx:           RequestExecutionContext&,
    req:           const http::Request&,
    current_url:   const core::Url&,
    samesite_eval: const cookie::SameSiteCookieContext&,
    safe_method:   bool,
    cache_ts:      http::CacheTimestamps&,
    hop_reval_idx: i64,
    resp:          http::Response&,
    hop_err:       http::Error&,
    user_stage:    UserStage&,
    post_v:        wire::StageVerdict&,
) -> bool {
    for _ in 2 {
        let is_retry_auth = match post_v { RetryAuth => true, _ => false };
        guard is_retry_auth else { break; }
        let next_v, retry_ok = execute_client_auth_retry_hop(
            session, ctx, req, current_url, samesite_eval, safe_method,
            cache_ts, hop_reval_idx, resp, hop_err, user_stage,
        );
        guard retry_ok else { return false; }
        post_v = next_v;
    }
    return true;
}

fn execute_single_client_hop_iteration<UserStage>(
    session:              client::Client&,
    ctx:                  RequestExecutionContext&,
    req:                  const http::Request&,
    cache_ts:             http::CacheTimestamps&,
    cache_revalidate_idx: i64,
    resp:                 http::Response&,
    hop_err:              http::Error&,
    user_stage:           UserStage&,
) -> bool {
    let chain_len = ctx.url_chain.len;
    let last_idx = core::sub_sat_i64(chain_len, 1);
    guard chain_len > 0 && last_idx < ctx.url_chain.len else {
        hop_err = http::make_error(rfc::STATUS_BAD_REQUEST, "url_parse", "empty request url chain");
        return true;
    }
    var current_url = ctx.url_chain[last_idx];
    let safe_method = rfc::is_safe_http_method(ctx.current_method[..]);
    var samesite_eval = compute_hop_samesite_context(ctx, current_url, safe_method);
    let now_sec = div_euclid(session.virtual_clock_us, 1000000);

    let pre_hop_v = run_pre_hop_stages(
        session, ctx, current_url, samesite_eval, safe_method, now_sec, resp, hop_err, user_stage,
    );
    var pre_p = wire::begin_pipeline();
    if !pre_p.step(pre_hop_v) {
        let _ = resolve_client_verdict_outcome(pre_hop_v, resp, hop_err, "aborted by client ingress stage");
        return true;
    }

    var hop_reval_idx = if ctx.redirect_count == 0 { cache_revalidate_idx } else { -1 };
    let cache_lookup_on = wire::is_ingress_stage_enabled(session.wire_pipeline, wire::STAGE_ID_CLI_IN_CACHE_LOOKUP);
    if ctx.redirect_count > 0 && cache_lookup_on {
        let v_redir_cache, r_idx = stage_cache_lookup(
            req, current_url.href[..], cache_ts.now_sec, ctx.headers, resp,
            session.cache, session.enable_cache, ctx.current_method[..],
        );
        hop_reval_idx = r_idx;
        if !pre_p.step(v_redir_cache) {
            finalize_success_response(ctx, resp);
            let _ = resolve_client_verdict_outcome(
                v_redir_cache, resp, hop_err, "504 Gateway Timeout (only-if-cached miss)",
            );
            return true;
        }
    }

    let hop_start_us = session.virtual_clock_us;
    resp, hop_err = execute_mock_or_echo_hop(session, ctx, current_url);
    guard http::ok(hop_err) else { return true; }
    guard check_response_body_size_limit(session, resp, hop_err) else { return true; }
    ctx.body_consumed = true;

    let hop_dur_us = core::sub_sat_i64(session.virtual_clock_us, hop_start_us);
    apply_network_interceptors_response(session.pipeline, resp, ctx.redirect_count, hop_dur_us);

    var post_v = run_client_post_hop_stages(
        session, ctx, req, current_url, samesite_eval, safe_method,
        cache_ts, hop_reval_idx, resp, hop_err, user_stage,
    );
    guard run_client_auth_retry_loop(
        session, ctx, req, current_url, samesite_eval, safe_method,
        cache_ts, hop_reval_idx, resp, hop_err, user_stage, post_v,
    ) else {
        return true;
    }

    return resolve_client_verdict_outcome(post_v, resp, hop_err, "aborted by client egress stage");
}

fn execute_request_inner(session: client::Client&, req: const http::Request&) -> http::Response, http::Error {
    var noop = wire::NoOpStage {};
    return client::execute_pipeline_with_stage(session, req, noop);
}
