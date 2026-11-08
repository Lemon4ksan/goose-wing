// RUN: goose %s | %FileCheck %s

import std;
import core from "../..";
import wing from "../..";

struct ChunkCounterStage {
    chunk_count: i64  = 0,
    saw_last:    bool = false,
}

fn wing::on_server_body_chunk(
    stage:   ChunkCounterStage&,
    _cfg:    wing::ServerPipelineConfig&,
    _req:    const wing::Request&,
    _ctx:    wing::ServerStageCtx&,
    _chunk:  const u8[:],
    is_last: bool,
    _res:    wing::Response&,
) -> wire::StageVerdict {
    stage.chunk_count += 1;
    if is_last {
        stage.saw_last = true;
    }
    return wire::StageVerdict.Continue;
}

struct ChunkDigestEchoStage {
    collected: u8[..256] = [],
}

fn wing::on_server_body_chunk(
    stage:   ChunkDigestEchoStage&,
    _cfg:    wing::ServerPipelineConfig&,
    _req:    const wing::Request&,
    _ctx:    wing::ServerStageCtx&,
    chunk:   const u8[:],
    is_last: bool,
    res:     wing::Response&,
) -> wire::StageVerdict {
    guard stage.collected.try_append(chunk) else {
        res.status_code = 413;
        return wire::StageVerdict.ShortCircuit { status_code: 413 };
    }
    if is_last {
        res.status_code = 200;
        let _ = res.body.try_set(stage.collected[..]);
    }
    return wire::StageVerdict.Continue;
}

fn make_bearer_jwt(secret: const u8[:], sub_val: const u8[:], out_hdr: u8[..4096]&) -> bool {
    out_hdr.clear();
    var hdr = wing::new_jwt_header(wing::JwtAlg.HS256, "k1");
    var claims = wing::JwtClaims { exp: 2000000000, .. };
    let _ = claims.sub.try_set(sub_val);
    var tok: u8[..2048] = [];
    guard wing::sign_jwt_hmac(hdr, claims, secret, tok) else { return false; }
    guard out_hdr.try_append("Bearer ") && out_hdr.try_append(tok[..]) else {
        out_hdr.clear();
        return false;
    }
    return true;
}

fn test_multi_limiter_and_xds_hot_swap() {
    var cfg = wing::new_default_server_pipeline_config("api.example.com");
    cfg.enable_csrf_guard = false;
    cfg.enable_cors = false;
    let _ = wing::add_route(cfg.router, "GET", "/v1/orders", 1);

    let secret = "0123456789abcdef0123456789abcdef";
    let _ = wing::add_symmetric_key(cfg.jwks, "k1", wing::JwtAlg.HS256, secret);

    // Slot 0: IP rate limiter (high burst 10)
    // Slot 1: Route rate limiter (medium burst 5)
    // Slot 2: Post-JWT Subject rate limiter (strict 1 req/60s, burst 0)
    let ok_s0 = wing::configure_tier_limiter(cfg, 0, wing::new_gcra_quota(10, core::secs(60), 10));
    let ok_s1 = wing::configure_tier_limiter(cfg, 1, wing::new_gcra_quota(5, core::secs(60), 5));
    let ok_s2 = wing::configure_tier_limiter(cfg, 2, wing::new_gcra_quota(1, core::secs(60), 0));
    print("tier_limiters_init: ", ok_s0 && ok_s1 && ok_s2, " len: ", cfg.tier_limiters.len);

    wire::clear_stage_bindings(cfg.wire_pipeline);
    let _ = wire::add_stage_binding(cfg.wire_pipeline, wire::STAGE_ID_SRV_IN_EXPECT_100, 0);
    let _ = wire::add_stage_binding(cfg.wire_pipeline, wire::STAGE_ID_SRV_IN_RATELIMIT_IP, 0);
    let _ = wire::add_stage_binding(cfg.wire_pipeline, wire::STAGE_ID_SRV_IN_RATELIMIT_ROUTE, 1);
    let _ = wire::add_stage_binding(cfg.wire_pipeline, wire::STAGE_ID_SRV_IN_AUTH_JWT, 0);
    let _ = wire::add_stage_binding(cfg.wire_pipeline, wire::STAGE_ID_SRV_IN_RATELIMIT_SUBJECT, 2);
    print("custom_order: ", cfg.wire_pipeline.has_custom_order, " bindings: ", cfg.wire_pipeline.custom_bindings.len);

    var auth_alpha: u8[..4096] = [];
    var auth_beta:  u8[..4096] = [];
    let _ = make_bearer_jwt(secret, "tenant-alpha", auth_alpha);
    let _ = make_bearer_jwt(secret, "tenant-beta", auth_beta);

    var req_alpha = wing::new_request("GET", "/v1/orders");
    wing::set_header(req_alpha, "Authorization", auth_alpha[..]);

    var req_beta = wing::new_request("GET", "/v1/orders");
    wing::set_header(req_beta, "Authorization", auth_beta[..]);

    var timer = internal::new_connection_timer(30000000000, 1000000000);
    let now_ns: u64 = 100000000000;

    // 1st request for tenant-alpha succeeds (200)
    var res1 = wing::Response { .. };
    var fut1 = internal::new_inline_handler_future(0);
    let out1 = wing::execute_pipeline(cfg, timer, "198.51.100.7", req_alpha, now_ns, res1, fut1);
    print("alpha_req1: ", out1 == wing::PipelineOutcome.Handled, " status: ", res1.status_code);

    // 2nd immediate request for tenant-alpha hits slot 2 subject rate limit (429)
    var res2 = wing::Response { .. };
    var fut2 = internal::new_inline_handler_future(0);
    let out2 = wing::execute_pipeline(cfg, timer, "198.51.100.7", req_alpha, now_ns, res2, fut2);
    print("alpha_req2_limited: ", out2 == wing::PipelineOutcome.RateLimited, " status: ", res2.status_code);

    // Request from same IP & route for tenant-beta succeeds because slot 0 (IP) & slot 1 (route) have remaining burst
    var res3 = wing::Response { .. };
    var fut3 = internal::new_inline_handler_future(0);
    let out3 = wing::execute_pipeline(cfg, timer, "198.51.100.7", req_beta, now_ns, res3, fut3);
    print("beta_req1_allowed: ", out3 == wing::PipelineOutcome.Handled, " status: ", res3.status_code);

    // Transactional rollback test: invalid param_slot (9) must fail and preserve existing 5 bindings
    let bad_bindings: const wire::StageBinding[2] = [
        wire::StageBinding { stage_id: wire::STAGE_ID_SRV_IN_RATELIMIT_IP, param_slot: 0 },
        wire::StageBinding { stage_id: wire::STAGE_ID_SRV_IN_RATELIMIT_SUBJECT, param_slot: 9 },
    ];
    let swap_bad = wire::replace_ingress_bindings(cfg.wire_pipeline, bad_bindings[..]);
    print("swap_bad_ok: ", swap_bad, " preserved_len: ", cfg.wire_pipeline.custom_bindings.len);

    // Valid xDS hot-swap: remove STAGE_ID_SRV_IN_RATELIMIT_SUBJECT at runtime without restart
    let xds_bindings: const wire::StageBinding[3] = [
        wire::StageBinding { stage_id: wire::STAGE_ID_SRV_IN_RATELIMIT_IP, param_slot: 0 },
        wire::StageBinding { stage_id: wire::STAGE_ID_SRV_IN_RATELIMIT_ROUTE, param_slot: 1 },
        wire::StageBinding { stage_id: wire::STAGE_ID_SRV_IN_AUTH_JWT, param_slot: 0 },
    ];
    let swap_ok = wire::replace_ingress_bindings(cfg.wire_pipeline, xds_bindings[..]);
    var res4 = wing::Response { .. };
    var fut4 = internal::new_inline_handler_future(0);
    let out4 = wing::execute_pipeline(cfg, timer, "198.51.100.7", req_alpha, now_ns, res4, fut4);
    print(
        "xds_swap_ok: ",
        swap_ok,
        " alpha_after_xds: ",
        out4 == wing::PipelineOutcome.Handled,
        " status: ",
        res4.status_code,
    );
}

fn test_streaming_body_chunk_pipeline() {
    var cfg = wing::new_default_server_pipeline_config("upload.example.com");
    var sctx = wing::ServerStageCtx { .. };

    // 1. Valid streaming multi-chunk body with RFC 9530 Content-Digest + StageChain
    var req = wing::new_request("POST", "/v1/ingest");
    let _ = req.body.try_set("hello world");
    let _ = wing::set_content_digest(req, "sha-256");

    let mask = wire::STAGE_SRV_IN_CONTENT_DIGEST | wire::STAGE_SRV_IN_DECOMPRESS;
    var stream_state, ok_begin = wing::begin_server_body_stream(req, mask);
    var noop = wire::NoOpStage {};
    var res = wing::Response { .. };
    let v_noop = wing::feed_server_body_chunk_with_stage(cfg, stream_state, req, sctx, "", false, res, noop);
    let noop_ok = match v_noop { Continue => true, _ => false };

    var chain = wire::chain_stages(ChunkCounterStage {}, ChunkDigestEchoStage {});
    let v1 = wing::feed_server_body_chunk_with_stage(cfg, stream_state, req, sctx, "hello ", false, res, chain);
    let v2 = wing::feed_server_body_chunk_with_stage(cfg, stream_state, req, sctx, "world", true, res, chain);
    let v1_ok = match v1 { Continue => true, _ => false };
    let v2_ok = match v2 { Continue => true, _ => false };
    print(
        "stream_ok: ",
        ok_begin && noop_ok && v1_ok && v2_ok,
        " chunks: ",
        chain.first.chunk_count,
        " bytes: ",
        stream_state.bytes_processed,
        " body: ",
        res.body[..],
    );

    // 2. Tampered streaming body chunk rejected with 400 on final chunk SHA-256 check
    var bad_state, _ = wing::begin_server_body_stream(req, mask);
    var bad_res = wing::Response { .. };
    var bad_chain = wire::chain_stages(ChunkCounterStage {}, ChunkDigestEchoStage {});
    let _ = wing::feed_server_body_chunk_with_stage(cfg, bad_state, req, sctx, "hello ", false, bad_res, bad_chain);
    let v_tamper = wing::feed_server_body_chunk_with_stage(
        cfg, bad_state, req, sctx, "tampered!", true, bad_res, bad_chain,
    );
    let tamper_sc = match v_tamper { ShortCircuit sc => sc.status_code, _ => 0 };
    print("tamper_rejected: ", tamper_sc == 400, " status: ", bad_res.status_code, " err: ", bad_state.has_error);
}

fn main() {
    test_multi_limiter_and_xds_hot_swap();
    test_streaming_body_chunk_pipeline();
}

// CHECK: tier_limiters_init: true len: 3
// CHECK-NEXT: custom_order: true bindings: 5
// CHECK-NEXT: alpha_req1: true status: 200
// CHECK-NEXT: alpha_req2_limited: true status: 429
// CHECK-NEXT: beta_req1_allowed: true status: 200
// CHECK-NEXT: swap_bad_ok: false preserved_len: 5
// CHECK-NEXT: xds_swap_ok: true alpha_after_xds: true status: 200
// CHECK-NEXT: stream_ok: true chunks: 2 bytes: 11 body: hello world
// CHECK-NEXT: tamper_rejected: true status: 400 err: true
