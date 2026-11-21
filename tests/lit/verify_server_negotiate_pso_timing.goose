// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// RUN: goose %s | %FileCheck %s

import std;
import core from "../..";
import wing from "../..";

struct ContractAuthRoute {
    params:  i32,
    cookies: i32,
    claims:  i32,
    peer_ip: i32,
    etag:    i32,
}

struct ContractPublicRoute {
    id: i32,
}

struct LifecycleTestStage {
    short_circuit_post_auth: bool = false,
    on_error_calls:          i32  = 0,
    after_response_calls:    i32  = 0,
}

fn server::on_server_stage(
    stage: LifecycleTestStage&,
    phase: wire::ServerHookPhase,
    _cfg:  server::ServerPipelineConfig&,
    _req:  const http::Request&,
    _ctx:  server::ServerStageCtx&,
    res:   http::Response&,
) -> wire::StageVerdict {
    match phase {
        PostAuth => {
            if stage.short_circuit_post_auth {
                return wire::StageVerdict.ShortCircuit { status_code: 401 };
            }
            return wire::StageVerdict.Continue;
        },
        RouteHandler => {
            res.status_code = 200;
            http::set_header(res, "Content-Type", "text/plain");
            res.body.clear();
            res.body.append("hello world hello world hello world");
            return wire::StageVerdict.Continue;
        },
        OnError => {
            stage.on_error_calls = core::add_sat_i64(stage.on_error_calls, 1) as i32;
            return wire::StageVerdict.Continue;
        },
        AfterResponse => {
            stage.after_response_calls = core::add_sat_i64(stage.after_response_calls, 1) as i32;
            return wire::StageVerdict.Continue;
        },
        _ => {
            return wire::StageVerdict.Continue;
        },
    };
}

fn matched_handler_id(res: server::RouteMatchResult) -> i32 {
    match res {
        Found f => { return f.handler_id; },
        _ => { return -1; },
    };
}

fn verify_negotiate() {
    let q0, ok0 = http::parse_qvalue_token("0.85");
    let q1, ok1 = http::parse_qvalue_milliths("level=1; q=0.750");
    let q_bad, ok_bad = http::parse_qvalue_milliths("q=1.5");
    let spec = http::match_media_specificity("text/*", "text/html; charset=utf-8");
    let sc_acc_q, sc_acc_s = http::score_accept_candidate("text/*;q=0.5, application/json;q=0.9", "application/json");
    print(
        "qvalue:",
        ok0,
        " ",
        q0,
        " ",
        ok1,
        " ",
        q1,
        " ",
        ok_bad,
        " ",
        q_bad,
        " spec:",
        spec,
        " sc:",
        sc_acc_q,
        "/",
        sc_acc_s,
    );
    // CHECK: qvalue:true 850 true 750 false 0 spec:2 sc:900/3

    let media_offers: (const u8[:])[3] = ["text/html", "application/json", "text/plain"];
    let m_pick = http::negotiate_accept(
        "text/*;q=0.8, application/json;q=0.9, text/html;q=0",
        media_offers[..],
    );
    let m_blocked = http::negotiate_accept("text/html;q=0", media_offers[..1], "none");
    print("accept:", m_pick, " blocked:", m_blocked);
    // CHECK: accept:application/json blocked:none

    let sc_enc_q, sc_enc_s = http::score_encoding_candidate("gzip;q=0.8, br;q=1.0", "br");
    let enc_offers: (const u8[:])[3] = ["gzip", "br", "zstd"];
    let e_pick = http::negotiate_encoding("gzip;q=0.8, br;q=1.0, zstd;q=0", enc_offers[..]);
    let e_none = http::negotiate_encoding("br;q=0", enc_offers[1..2]);
    print("encoding:", sc_enc_q, "/", sc_enc_s, " ", e_pick, " none_len:", e_none.len);
    // CHECK: encoding:1000/2 br none_len:0

    let l_spec = http::match_language_specificity("en", "en-US");
    let sc_lang_q, sc_lang_s = http::score_language_candidate("fr-CA, en;q=0.8", "en-US");
    let lang_offers: (const u8[:])[3] = ["de", "en-US", "fr"];
    let l_pick = http::negotiate_language("fr-CA, fr;q=0.7, en;q=0.9", lang_offers[..]);
    print("lang:", l_spec, " ", sc_lang_q, "/", sc_lang_s, " ", l_pick);
    // CHECK: lang:2 800/2 en-US
}

fn verify_server_timing() {
    var rec = http::ServerTimingRecorder {};
    rec.clear();
    let idx = rec.start_span("db", 1000000, "primary");
    let ended = rec.end_span(idx, 3400000);
    let rec_ok = rec.record_duration_ns("cache", 500000, "hit");

    var dur_buf: u8[..32] = [];
    let _ = http::format_dur_ms_tenths(2450000, dur_buf);
    var desc_buf: u8[..32] = [];
    let _ = http::append_timing_desc_quoted("a\"b", desc_buf);

    var hdr_line: u8[..256] = [];
    let fmt_ok = http::format_server_timing(rec, hdr_line);

    var res = http::Response {};
    let emit_ok = http::emit_server_timing(rec, res);
    let hdr_val = http::header(res, "Server-Timing");
    print("timing:", ended, " ", rec_ok, " ", dur_buf[..], " ", desc_buf[..], " ", fmt_ok, " ", emit_ok);
    // CHECK: timing:true true 2.4 ;desc="a\"b" true true
    print("timing_hdr:", hdr_val);
    // CHECK: timing_hdr:db;dur=2.4;desc="primary", cache;dur=0.5;desc="hit"
}

fn verify_router_pso_and_groups() {
    let m_auth = server::infer_contract_masks<ContractAuthRoute>();
    let m_pub = server::infer_contract_masks<ContractPublicRoute>();
    let has_jwt = (m_auth.pso_mask & server::STAGE_INGRESS_AUTH_JWT) != 0;
    let has_cookie = (m_auth.pso_mask & server::STAGE_INGRESS_AUTH_COOKIE) != 0;
    let has_etag = (m_auth.pso_mask & server::STAGE_EGRESS_ETAG) != 0;
    let pub_no_jwt = (m_pub.pso_mask & server::STAGE_INGRESS_AUTH_JWT) == 0;
    print("infer:", m_auth.entries_mask, " ", has_jwt, " ", has_cookie, " ", has_etag, " ", pub_no_jwt);
    // CHECK: infer:15 true true true true

    var router = server::new_radix_router();
    let ok_c = server::add_route_for_contract<ContractAuthRoute>(router, "GET", "/contract/:id", 10);

    var joined: u8[..128] = [];
    let ok_j = server::join_route_prefix("/api/v1/", "users", joined);

    var base_p: u8[..128] = [];
    var full_p: u8[..128] = [];
    let ok_sp = server::split_trailing_optional_param("/items/:id?", base_p, full_p);

    let grp, ok_grp = server::make_route_group("/api/v1", server::DEFAULT_ROUTE_PSO_MASK, 2);
    let ok_gr = server::add_group_route(router, grp, "GET", "/posts/:slug?", 20);
    let ok_opt = server::add_optional_route(router, "GET", "/brace/{id?}", 25);
    let _ = ok_opt;

    let methods: (const u8[:])[2] = ["POST", "PUT"];
    let ok_m = server::add_route_methods(router, methods[..], "/multi", 30);

    var params = http::ZeroAllocParams {};
    let r1 = matched_handler_id(server::match_route(router, "GET", "/api/v1/posts", params));
    let r2 = matched_handler_id(server::match_route(router, "GET", "/api/v1/posts/hello", params));
    let r3 = matched_handler_id(server::match_route(router, "PUT", "/multi", params));
    print("routes:", ok_c, " ", ok_j, " ", joined[..], " ", ok_sp, " ", base_p[..], " ", full_p[..]);
    // CHECK: routes:true true /api/v1/users true /items /items/:id
    print("matches:", ok_grp, " ", ok_gr, " ", ok_m, " ", r1, " ", r2, " ", r3);
    // CHECK: matches:true true true 20 20 30
}

fn verify_pipeline_fixes_and_cork() {
    var cfg = server::new_default_server_pipeline_config("example.com");
    cfg.enable_rate_limiter = false;
    cfg.enable_csrf_guard = false;
    cfg.enable_cors = false;
    cfg.enable_slowloris_timer = false;

    let pso = server::STAGE_EGRESS_COMPRESS_GZIP | server::STAGE_EGRESS_METRICS;
    let _ = server::add_route(cfg.router, "GET", "/test", 1, 0, pso);

    var timer = server_internal::ConnectionTimer {};
    var req = http::new_request("HEAD", "/test");
    http::set_header(req, "Host", "example.com");
    http::set_header(req, "Accept-Encoding", "gzip");
    var res = http::Response {};
    var out_fut = server_internal::InlineHandlerFuture {};
    var stage = LifecycleTestStage { short_circuit_post_auth: true, .. };
    var guarded = server::ProblemErrorGuardStage<LifecycleTestStage> { inner: stage };

    let outcome = server::execute_server_pipeline_with_stage(
        cfg,
        timer,
        "127.0.0.1",
        req,
        2500000,
        res,
        out_fut,
        guarded,
    );
    let st_hdr = http::header(res, "Server-Timing");
    let ct_hdr = http::header(res, "Content-Type");
    print(
        "post_auth_head:",
        outcome == server::PipelineOutcome.Handled,
        " status:",
        res.status_code,
        " body_len:",
        res.body.len,
        " ct:",
        ct_hdr,
        " err:",
        guarded.inner.on_error_calls,
        " after:",
        guarded.inner.after_response_calls,
        " st:",
        st_hdr.starts_with("wing;dur="),
    );
    // CHECK: post_auth_head:true status:401 body_len:0 ct:application/problem+json err:1 after:1 st:true

    var res_nt = http::Response { status_code: 200, .. };
    res_nt.body.append("hello world hello world");
    http::set_header(res_nt, "Cache-Control", "public, no-transform");
    let has_nt = server::has_cache_no_transform(res_nt.headers);
    let comp_nt = server::is_compressible_response(res_nt);
    var res_206 = http::Response { status_code: 206, .. };
    res_206.body.append("partial content bytes");
    let comp_206 = server::is_compressible_response(res_206);
    print("compress_guard:", has_nt, " ", comp_nt, " ", comp_206);
    // CHECK: compress_guard:true false false

    var stream_res = http::Response {};
    server::init_text_stream_response(stream_res);
    var sc = server::new_server_cork(1);
    let b_ok = server::cork_begin_http1_chunked(sc, stream_res, "wing") > 0;
    let c_ok = server::cork_write_http1_chunk(sc, "hello") > 0;
    let s_ok = server::cork_write_sse_chunk(sc, "ping", "data1", "1", 0, false) > 0;
    let e_ok = server::cork_end_http1_chunked(sc, false) > 0;
    print("cork_stream:", b_ok, " ", c_ok, " ", s_ok, " ", e_ok);
    // CHECK: cork_stream:true true true true
}

fn main() {
    verify_negotiate();
    verify_server_timing();
    verify_router_pso_and_groups();
    verify_pipeline_fixes_and_cork();
}
