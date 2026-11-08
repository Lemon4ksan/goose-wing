// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Consolidated Goose LIT Verification Suite: lit_grpc_and_proxy
// RUN: goose build -O2 -o %t.exe %s
// RUN: %t.exe | %FileCheck %s

import std;
import core from "../..";
import wing from "../..";
import wire_kit from ".";

// ============================================================================
// 1. rfc_repro_grpc_bug_hunter (1/7)
// ============================================================================
// CHECK: === [1/7] rfc_repro_grpc_bug_hunter ===

// tests/lit/rfc_repro_grpc_bug_hunter.goose
// Cross-component and RFC edge-case regression suite for gRPC and gRPC-Web.
//

fn dummy_unary_ok(
    _id:  u16,
    _ctx: wing::GrpcServerContext&,
    _req: const u8[:],
    res:  u8[>..]&,
) -> wing::GrpcStatus {
    res.append("pong");
    return wing::grpc_ok();
}

fn test_f001_protobuf_tag_bounds() {
    // 1. Tag with (tag >> 3) == 0x100000001 (overflows u32 and > PB_MAX_FIELD_NUM):
    // tag = (0x100000001 << 3) | 0 = 0x800000008 -> varint [0x88, 0x80, 0x80, 0x80, 0x80, 0x01]
    let hi_varint: u8[7] = [0x88, 0x80, 0x80, 0x80, 0x80, 0x01, 0x2A];
    let _, ok_v1 = wing::pb_read_varint_field(hi_varint[..], 1);
    assert(!ok_v1);

    let hi_bytes: u8[8] = [0x8A, 0x80, 0x80, 0x80, 0x80, 0x01, 0x01, 'x'];
    let _, ok_b1 = wing::pb_read_bytes_field(hi_bytes[..], 1);
    assert(!ok_b1);

    // 2. Field number 0 (tag = 0x00, wire_type = 0) before valid field 1:
    let zero_fnum: u8[4] = [0x00, 0x01, 0x08, 0x2A];
    let _, ok_v0 = wing::pb_read_varint_field(zero_fnum[..], 1);
    assert(!ok_v0);

    let zero_fnum_b: u8[5] = [0x00, 0x01, 0x12, 0x01, 'a'];
    let _, ok_b0 = wing::pb_read_bytes_field(zero_fnum_b[..], 1);
    assert(!ok_b0);
    print("F001_PB_TAG_BOUNDS: OK");
}

fn test_f002_grpc_web_trailer_injection() {
    var ctx = wing::GrpcServerContext { .. };
    // Reject CRLF in metadata/trailer value and reserved keys
    assert(!wing::add_response_trailer(ctx, "x-custom", "val\r\ngrpc-status: 0"));
    assert(!wing::add_response_trailer(ctx, "grpc-status", "0"));
    assert(!wing::add_response_trailer(ctx, "grpc-message", "spoof"));
    assert(!wing::add_response_metadata(ctx, "content-type", "text/plain"));
    assert(!wing::add_response_metadata(ctx, "", "empty-key"));

    // Direct encode_grpc_web_trailers_with_meta defense against spoofed extra_trailers
    var spoofed: wing::GrpcMetadata[..16] = [];
    var e1 = wing::GrpcMetadata { .. };
    let _ = e1.key.try_set("grpc-status");
    let _ = e1.value.try_set("0");
    spoofed.push(e1);
    var e2 = wing::GrpcMetadata { .. };
    let _ = e2.key.try_set("x-inj");
    let _ = e2.value.try_set("v\r\ngrpc-status: 0");
    spoofed.push(e2);

    var frame: u8[>..] = [];
    wing::encode_grpc_web_trailers_with_meta(
        wing::GrpcStatusCode.PermissionDenied,
        "denied",
        spoofed[..],
        frame,
    );
    var payload: u8[>..] = [];
    var is_tr = false;
    var is_comp = false;
    let ok_dec, _ = wing::decode_grpc_web_frame(frame[..], 0, payload, is_tr, is_comp);
    assert(ok_dec && is_tr);
    var st = wing::GrpcStatusCode.Ok;
    var msg: u8[..256] = [];
    assert(wing::parse_grpc_web_trailers(payload[..], st, msg));
    assert(st == wing::GrpcStatusCode.PermissionDenied);
    print("F002_TRAILER_INJECTION: OK");
}

fn test_f003_grpc_web_text_multi_chunk() {
    // Frame 1: 5-byte empty LPM [0,0,0,0,0] -> Base64 "AAAAAAA="
    // Frame 2: Trailer frame for grpc-status: 0\r\n -> Base64
    var f1: u8[>..] = [];
    wing::encode_grpc_lpm("", f1, false);
    var b64_1: u8[>..] = [];
    wing::encode_grpc_web_text(f1[..], b64_1);

    var f2: u8[>..] = [];
    wing::encode_grpc_web_trailers(wing::GrpcStatusCode.Ok, "done", f2);
    var b64_2: u8[>..] = [];
    wing::encode_grpc_web_text(f2[..], b64_2);

    var stream_b64: u8[>..] = [];
    stream_b64.append(b64_1[..]);
    stream_b64.append(b64_2[..]);

    var decoded: u8[>..] = [];
    assert(wing::decode_grpc_web_text(stream_b64[..], decoded));
    assert(decoded.len == f1.len + f2.len);

    // Mid-quantum invalid padding must still be rejected
    var bad_out: u8[>..] = [];
    assert(!wing::decode_grpc_web_text("AA=A", bad_out));
    assert(!wing::decode_grpc_web_text("=A==", bad_out));
    print("F003_WEB_TEXT_MULTICHUNK: OK");
}

fn test_f004_bounded_buffers_and_stream_parser() {
    // 1. decode_grpc_message into u8[..64] with 100-byte input must not overflow cap 64
    var long_in:   u8[100]  = ['z'; 100];
    var small_out: u8[..64] = [];
    wing::decode_grpc_message(long_in[..], small_out);
    assert(small_out.len == 64);

    // 2. encode_grpc_message with default max_out_len (-1) into u8[..64] with 40 '%' bytes
    var pct_in:    u8[40]   = ['%'; 40];
    var small_enc: u8[..64] = [];
    wing::encode_grpc_message(pct_in[..], small_enc);
    assert(small_enc.len <= 64);

    // 3. decode_grpc_lpm into u8[..8] with 16-byte payload must fail cleanly without abort
    var lpm_16: u8[>..] = [];
    wing::encode_grpc_lpm("0123456789abcdef", lpm_16, false);
    var tiny_payload: u8[..8] = [];
    var is_comp = true;
    let ok_lpm, consumed = wing::decode_grpc_lpm(lpm_16[..], 0, tiny_payload, is_comp);
    assert(!ok_lpm && consumed == 0 && is_comp);

    // 4. GrpcStreamParser with max_size = 10 must accept a 10-byte payload (15 wire bytes)
    var parser = wing::new_grpc_stream_parser(10);
    var lpm_10: u8[>..] = [];
    wing::encode_grpc_lpm("0123456789", lpm_10, false);
    assert(wing::feed(parser, lpm_10[..]));
    var msg_out: u8[..16] = [];
    var msg_comp = false;
    assert(wing::next_message(parser, msg_out, msg_comp));
    assert(msg_out[..] == "0123456789");
    print("F004_BOUNDED_BUFFERS: OK");
}

fn test_f005_timeout_encoding_and_zero_deadline() {
    // 1. encode_grpc_timeout with 100_000_500 ms (>= 10^8, not divisible by 1000)
    // must emit <= 8 digits so parse_grpc_timeout accepts it.
    var to_buf: u8[..32] = [];
    wing::encode_grpc_timeout(100000500, to_buf);
    let parsed_ns, ok_to = wing::parse_grpc_timeout(to_buf[..]);
    assert(ok_to && parsed_ns > 0);

    // 2. grpc-timeout: 0S must immediately expire in dispatch_grpc_unary
    var d = wing::new_grpc_server_dispatcher();
    assert(wing::register_unary(d, "test.Svc", "Call", 1));
    var req = wing::new_request("POST", "/test.Svc/Call");
    wing::set_header(req, "content-type", rfc::GRPC_CONTENT_TYPE_PROTO);
    wing::set_header(req, "grpc-timeout", "0S");
    wing::encode_grpc_lpm("hi", req.body, false);
    var res = wing::Response { .. };
    assert(wing::dispatch_grpc_unary(d, req, 5000000, res, dummy_unary_ok));
    assert(wing::header(res, rfc::HEADER_GRPC_STATUS) == "4");
    print("F005_TIMEOUT_AND_ZERO_DEADLINE: OK");
}

fn test_f006_status_and_client_parsers() {
    // 1. Non-200 HTTP status (503) with grpc-status: 0 must map to Unavailable, not Ok
    var hdrs = wing::HeaderMap { .. };
    hdrs.status_code = 503;
    let _ = wing::append_header(hdrs, rfc::HEADER_GRPC_STATUS, "0");
    var trs = wing::HeaderMap { .. };
    var msg: u8[..256] = [];
    var st_503 = wing::GrpcStatusCode.Ok;
    let _ = wing::extract_grpc_status(hdrs, trs, st_503, msg);
    assert(st_503 == wing::GrpcStatusCode.Unavailable);

    // 2. HTTP/2 :status pseudo-header ("503") when hdrs.status_code is left at default 200
    var hdrs2 = wing::HeaderMap { .. };
    let _ = wing::append_header(hdrs2, ":status", "503");
    var st_pseudo = wing::GrpcStatusCode.Ok;
    let _ = wing::extract_grpc_status(hdrs2, trs, st_pseudo, msg);
    assert(st_pseudo == wing::GrpcStatusCode.Unavailable);

    // 3. process_grpc_web_response must reject invalid Base64 and truncated frames
    var resp = wing::GrpcResponse { .. };
    assert(!wing::process_grpc_web_response("!!!not_base64!!!", rfc::GRPC_WEB_TEXT_CONTENT_TYPE, resp));
    assert(!wing::process_grpc_web_response("\x00\x00\x00\x00\x05hi", rfc::GRPC_WEB_CONTENT_TYPE, resp));

    // 4. process_grpc_web_response with trailer frame missing grpc-status must set Unknown
    var tr_no_status: u8[>..] = [];
    tr_no_status.push(rfc::GRPC_WEB_FLAG_TRAILERS);
    let raw_tr = "grpc-message: oops\r\n";
    let tr_len = raw_tr.len as u32;
    tr_no_status.push(((tr_len >> 24) & 0xFF) as u8);
    tr_no_status.push(((tr_len >> 16) & 0xFF) as u8);
    tr_no_status.push(((tr_len >> 8) & 0xFF) as u8);
    tr_no_status.push((tr_len & 0xFF) as u8);
    tr_no_status.append(raw_tr);
    var resp_no_st = wing::GrpcResponse { .. };
    let _ = wing::process_grpc_web_response(tr_no_status[..], rfc::GRPC_WEB_CONTENT_TYPE, resp_no_st);
    assert(resp_no_st.status == wing::GrpcStatusCode.Unknown);
    print("F006_CLIENT_AND_STATUS: OK");
}

fn test_f007_server_dispatch_and_encoding() {
    var d = wing::new_grpc_server_dispatcher();
    assert(wing::register_unary(d, "test.Svc", "Call", 1));

    // 1. Compressed LPM (flag=1) with identity/missing grpc-encoding must be rejected (Internal=13)
    var req_comp = wing::new_request("POST", "/test.Svc/Call");
    wing::set_header(req_comp, "content-type", rfc::GRPC_CONTENT_TYPE_PROTO);
    req_comp.body.push(rfc::GRPC_FLAG_COMPRESSED);
    req_comp.body.append("\x00\x00\x00\x00");
    var res_comp = wing::Response { .. };
    assert(wing::dispatch_grpc_unary(d, req_comp, 1000, res_comp, dummy_unary_ok));
    assert(wing::header(res_comp, rfc::HEADER_GRPC_STATUS) == "13");

    // 2. Unsupported grpc-encoding ("snappy") even with uncompressed LPM must return Unimplemented (12)
    // and include grpc-accept-encoding header
    var req_enc = wing::new_request("POST", "/test.Svc/Call");
    wing::set_header(req_enc, "content-type", rfc::GRPC_CONTENT_TYPE_PROTO);
    wing::set_header(req_enc, "grpc-encoding", "snappy");
    wing::encode_grpc_lpm("hi", req_enc.body, false);
    var res_enc = wing::Response { .. };
    assert(wing::dispatch_grpc_unary(d, req_enc, 1000, res_enc, dummy_unary_ok));
    assert(wing::header(res_enc, rfc::HEADER_GRPC_STATUS) == "12");
    assert(wing::header(res_enc, rfc::HEADER_GRPC_ACCEPT_ENCODING).len > 0);

    // 3. parse_grpc_path rejects extra slash or query string in method name
    var svc: u8[..64] = [];
    var mth: u8[..64] = [];
    assert(!wing::parse_grpc_path("/test.Svc/Call/Extra", svc, mth));
    assert(!wing::parse_grpc_path("/test.Svc/Call?foo=1", svc, mth));

    // 4. handle_grpc_h2_control_frame rejects SETTINGS on non-zero stream_id
    let bad_hdr = wire::WireFrameHeader {
        length:     0,
        frame_type: rfc::H2_FRAME_SETTINGS,
        flags:      0,
        stream_id:  1,
    };
    assert(!wing::handle_grpc_h2_control_frame(-1, bad_hdr, ""));
    print("F007_SERVER_DISPATCH: OK");
}

fn run_01_rfc_repro_grpc_bug_hunter() {
    test_f001_protobuf_tag_bounds();
    test_f002_grpc_web_trailer_injection();
    test_f003_grpc_web_text_multi_chunk();
    test_f004_bounded_buffers_and_stream_parser();
    test_f005_timeout_encoding_and_zero_deadline();
    test_f006_status_and_client_parsers();
    test_f007_server_dispatch_and_encoding();
}

// CHECK: F001_PB_TAG_BOUNDS: OK
// CHECK: F002_TRAILER_INJECTION: OK
// CHECK: F003_WEB_TEXT_MULTICHUNK: OK
// CHECK: F004_BOUNDED_BUFFERS: OK
// CHECK: F005_TIMEOUT_AND_ZERO_DEADLINE: OK
// CHECK: F006_CLIENT_AND_STATUS: OK
// CHECK: F007_SERVER_DISPATCH: OK

// ============================================================================
// 2. verify_gcra_proxy_chaos (2/7)
// ============================================================================
// CHECK: === [2/7] verify_gcra_proxy_chaos ===

// tests/lit/verify_gcra_proxy_chaos.goose
// Pathological verification suite for GCRA rate limiter mathematical boundaries,
// burst limit precision, TAT overflow/underflow, NTP clock skew,
// and upstream load balancer health check state flapping / circuit breaker chaos.
//

const U64_MAX_LIMIT:   u64 = 0xFFFFFFFFFFFFFFFF;
const NEAR_MAX_OFFSET: u64 = 20000000000;

// ---- Section 1: GCRA Burst Limit Precision & Fractional Recovery -----------

// crap:trusted-bounds
fn test_gcra_burst_precision() {
    // Sustained: 10 req/s (T = 100ms = 100,000,000ns), Burst: 3 (tau = 300,000,000ns)
    // Limit window = tau + T = 400,000,000ns (allows 4 back-to-back requests at t0)
    let quota = wing::new_gcra_quota(10, core::secs(1), 3);
    assert(quota.emission_interval_ns == 100000000);
    assert(quota.delay_tolerance_ns == 300000000);

    var cell = wing::GcraCell { tat_ns: 0 };
    let t0: u64 = 1000000000;

    // Request 1: allowed, TAT becomes t0 + 100ms
    let d1 = wing::gcra_check_n(quota, cell, 1, t0);
    assert(wing::is_allowed(d1));
    assert(cell.tat_ns == core::add_sat_u64(t0, 100000000));

    // Request 2: allowed, TAT becomes t0 + 200ms
    let d2 = wing::gcra_check_n(quota, cell, 1, t0);
    assert(wing::is_allowed(d2));

    // Request 3: allowed, TAT becomes t0 + 300ms
    let d3 = wing::gcra_check_n(quota, cell, 1, t0);
    assert(wing::is_allowed(d3));

    // Request 4: allowed (burst capacity exhausted: TAT = t0 + 400ms = limit window boundary)
    let d4 = wing::gcra_check_n(quota, cell, 1, t0);
    assert(wing::is_allowed(d4));
    assert(cell.tat_ns == core::add_sat_u64(t0, 400000000));

    // Request 5 at t0: REJECTED! TAT would exceed limit window
    let d5 = wing::gcra_check_n(quota, cell, 1, t0);
    assert(!wing::is_allowed(d5));

    // Fractional clock recovery: advance clock by 50ms (half of T)
    // 50ms is insufficient to recover a 100ms token -> must still reject
    let t_half = core::add_sat_u64(t0, 50000000);
    let d_half = wing::gcra_check_n(quota, cell, 1, t_half);
    assert(!wing::is_allowed(d_half));

    // Full clock recovery: advance clock by full 100ms (t0 + 100ms)
    // 1 token has leaked out of bucket -> exactly 1 request allowed
    let t_full = core::add_sat_u64(t0, 100000000);
    let d_rec1 = wing::gcra_check_n(quota, cell, 1, t_full);
    assert(wing::is_allowed(d_rec1));

    // Immediate second request at t_full is rejected again
    let d_rec2 = wing::gcra_check_n(quota, cell, 1, t_full);
    assert(!wing::is_allowed(d_rec2));

    print("GCRA_BURST_PRECISION: burst_exhausted=true fractional_rejected=true full_recovered=true");
}

// ---- Section 2: TAT Saturation, Arithmetic Overflow & Underflow Bounds ------

// crap:trusted-bounds
fn test_gcra_boundary_overflow_underflow() {
    // 1. Division by zero protection: zero period duration or astronomical rate
    let q_zero = wing::new_gcra_quota(5000000, core::Duration { nanos: 1000000 }, 5);
    assert(q_zero.emission_interval_ns >= 1);
    var cell_zero = wing::GcraCell { tat_ns: 0 };
    let d_zero = wing::gcra_check_n(q_zero, cell_zero, 1, 1000);
    assert(wing::is_allowed(d_zero));

    // 2. High-value timestamp near u64::MAX (preventing arithmetic wrap-around)
    let q_sat = wing::new_gcra_quota(1, core::secs(1), 5);
    let near_max: u64 = core::sub_sat_u64(U64_MAX_LIMIT, NEAR_MAX_OFFSET);
    var cell_sat = wing::GcraCell { tat_ns: near_max };

    // Request consuming cost = 3 near u64 boundary
    let d_sat = wing::gcra_check_n(q_sat, cell_sat, 3, near_max);
    assert(wing::is_allowed(d_sat));
    assert(cell_sat.tat_ns > near_max);

    // 3. Cold-start underflow defense: cell.tat_ns = 0
    let now_cold: u64 = 5000000000;
    var cell_cold = wing::GcraCell { tat_ns: 0 };
    let d_cold = wing::gcra_check_n(q_sat, cell_cold, 1, now_cold);
    assert(wing::is_allowed(d_cold));
    assert(cell_cold.tat_ns == core::add_sat_u64(now_cold, q_sat.emission_interval_ns));

    print("GCRA_ARITH_BOUNDS: div_zero_safe=true u64_sat_safe=true cold_start_ok=true");
}

// ---- Section 3: NTP Backward Clock Jump & Clock Skew Resilience ------------

// crap:trusted-bounds
fn test_gcra_ntp_backward_jump() {
    let quota = wing::new_gcra_quota(10, core::secs(1), 2);
    var cell = wing::GcraCell { tat_ns: 60000000000 };

    // Sudden NTP backward step: system clock steps back to 10s (50 seconds in past)
    let now_skewed: u64 = 10000000000;
    let dec = wing::gcra_check_n(quota, cell, 1, now_skewed);
    assert(!wing::is_allowed(dec));

    // Operational limit window is tau + T = 200ms + 100ms = 300ms
    let lim_win = core::add_sat_u64(quota.delay_tolerance_ns, quota.emission_interval_ns);
    let tat_clamped = core::add_sat_u64(now_skewed, lim_win);

    // Synchronizing cell with clamped TAT restores service after retry interval
    cell.tat_ns = tat_clamped;
    let now_recovered = core::add_sat_u64(now_skewed, 200000000);
    let dec_rec = wing::gcra_check_n(quota, cell, 1, now_recovered);
    assert(wing::is_allowed(dec_rec));

    print("GCRA_NTP_BACKWARD_JUMP: clamped_retry_after=true resumed_after_skew=true");
}

// ---- Section 4: Multi-Cell Priority Reservation (Governor #16) --------------

// crap:trusted-bounds
fn test_gcra_reservation_preemption() {
    let quota = wing::new_gcra_quota(1, core::secs(1), 0);
    var cell = wing::GcraCell { tat_ns: 0 };
    let now: u64 = 1000000000;

    // Normal cell at t=1.0s consumes immediate slot
    let d1 = wing::gcra_check_n(quota, cell, 1, now);
    assert(wing::is_allowed(d1));
    assert(cell.tat_ns == core::add_sat_u64(now, 1000000000));

    // Heavy batch request arrives needing 3 tokens (cost_n = 3)
    let d_res = wing::gcra_reserve_n(quota, cell, 3, now, 5000000000);
    assert(wing::is_allowed(d_res));
    assert(cell.tat_ns == core::add_sat_u64(now, 4000000000));

    // Light request (cost_n = 1) arrives 500ms later and tries to steal capacity
    let d_steal = wing::gcra_check_n(quota, cell, 1, core::add_sat_u64(now, 500000000));
    assert(!wing::is_allowed(d_steal));

    // When the reservation delay passes (now + 4s), quota resumes
    let now_resume = core::add_sat_u64(now, 4000000000);
    let d_resumed = wing::gcra_check_n(quota, cell, 1, now_resume);
    assert(wing::is_allowed(d_resumed));

    print("GCRA_RESERVATION: reserved_3_slots=true preemption_preserved=true resumed=true");
}

// ---- Section 5: Long Rate Limiting Key Normalization & Shard Isolation ------

// crap:trusted-bounds
fn test_gcra_long_key_normalization() {
    let quota = wing::new_gcra_quota(2, core::secs(1), 1);
    var limiter = wing::new_sharded_limiter(quota);
    let now: u64 = 2000000000;

    // Key exceeding 64 bytes (80-byte header string)
    let long_key = "x-client-session-very-long-unique-telemetry-identifier-0123456789-abcdefghijklmnop";
    assert(long_key.len > 64);

    var eff_key: u8[..64] = [];
    wing::format_gcra_key(long_key, eff_key);
    assert(eff_key.len == 64);

    // Normalizing does not crash and isolates keys
    let d_long1 = wing::check_rate_limit(limiter, long_key, 1, now);
    let d_long2 = wing::check_rate_limit(limiter, long_key, 1, now);
    let d_long3 = wing::check_rate_limit(limiter, long_key, 1, now);

    assert(wing::is_allowed(d_long1));
    assert(wing::is_allowed(d_long2));
    assert(!wing::is_allowed(d_long3));

    // Distinct key must remain completely unaffected
    let d_other = wing::check_rate_limit(limiter, "independent-client-key", 1, now);
    assert(wing::is_allowed(d_other));

    print("GCRA_KEY_NORMALIZATION: len_64_normalized=true isolation_verified=true");
}

// ---- Section 6: Upstream Health Check State Flapping & Circuit Breaker -----

// crap:trusted-bounds
fn test_proxy_health_check_flapping() {
    var cluster = wing::new_upstream_cluster(wing::LbPolicy.RoundRobin, 3);
    assert(wing::add_upstream_target(cluster, "10.0.1.1", 8080));
    assert(wing::add_upstream_target(cluster, "10.0.1.2", 8080));

    // Target 0 experiences flapping (alternating single failure and recovery)
    wing::record_upstream_failure(cluster, 0);
    assert(cluster.targets[0].is_healthy);

    wing::record_upstream_success(cluster, 0);
    assert(cluster.targets[0].fails == 0);

    wing::record_upstream_failure(cluster, 0);
    assert(cluster.targets[0].is_healthy);
    wing::record_upstream_success(cluster, 0);
    assert(cluster.targets[0].fails == 0);

    // Sustained 3 failures -> trips target 0 to unhealthy
    wing::record_upstream_failure(cluster, 0);
    wing::record_upstream_failure(cluster, 0);
    wing::record_upstream_failure(cluster, 0);
    assert(!cluster.targets[0].is_healthy);
    assert(!cluster.circuit_open);

    // Selection now exclusively routes to Target 1
    let chosen1, ok1 = wing::select_upstream(cluster);
    let chosen2, ok2 = wing::select_upstream(cluster);
    assert(ok1 && chosen1 == 1);
    assert(ok2 && chosen2 == 1);

    print("PROXY_HEALTH_FLAPPING: flap_resilient=true sustained_failure_isolated=true");
}

// ---- Section 7: Total Cluster Circuit Breaker Full Trip & Self-Healing ------

// crap:trusted-bounds
fn test_proxy_circuit_breaker_full_trip() {
    var cluster = wing::new_upstream_cluster(wing::LbPolicy.RoundRobin, 2);
    assert(wing::add_upstream_target(cluster, "srv-alpha", 80));
    assert(wing::add_upstream_target(cluster, "srv-beta", 80));

    // Fail all targets to trip entire cluster circuit
    wing::record_upstream_failure(cluster, 0);
    wing::record_upstream_failure(cluster, 0);
    assert(!cluster.targets[0].is_healthy);

    wing::record_upstream_failure(cluster, 1);
    wing::record_upstream_failure(cluster, 1);
    assert(!cluster.targets[1].is_healthy);

    // Entire cluster circuit is now open (all backends dead)
    assert(cluster.circuit_open);
    let _, ok_trip = wing::select_upstream(cluster);
    assert(!ok_trip);

    // Active health probe returns success on srv-beta (Target 1)
    wing::record_upstream_success(cluster, 1);
    assert(cluster.targets[1].is_healthy);
    assert(!cluster.circuit_open);

    let chosen, ok_heal = wing::select_upstream(cluster);
    assert(ok_heal && chosen == 1);

    print("PROXY_CIRCUIT_BREAKER: full_trip_fast_fails=true self_healed_on_probe=true");
}

// ---- Section 8: Degraded Routing Under Least-Connections Policy -------------

// crap:trusted-bounds
fn test_proxy_lb_degraded_routing() {
    var cluster = wing::new_upstream_cluster(wing::LbPolicy.LeastConnections, 2);
    assert(wing::add_upstream_target(cluster, "node-1", 8080));
    assert(wing::add_upstream_target(cluster, "node-2", 8080));
    assert(wing::add_upstream_target(cluster, "node-3", 8080));

    // Node 1 has 5 active connections
    cluster.targets[0].active_conns = 5;
    // Node 2 has 2 active connections
    cluster.targets[1].active_conns = 2;
    // Node 3 has 0 active connections but is DOWN
    cluster.targets[2].is_healthy = false;

    // Least-connections must skip node-3 (down) and choose node-2 (least active: 2 < 5)
    let chosen, ok = wing::select_upstream(cluster);
    assert(ok && chosen == 1);
    assert(cluster.targets[1].active_conns == 3);

    // Release connection
    wing::release_upstream_connection(cluster, chosen);
    assert(cluster.targets[1].active_conns == 2);

    print("PROXY_LB_DEGRADED: unhealthy_skipped=true least_conn_chosen=true");
}

// ---- Main Entry Point ------------------------------------------------------

// crap:trusted-bounds
fn run_02_verify_gcra_proxy_chaos() {
    print("=== LIT GCRA Rate Limiter & Proxy Chaos Verification ===");
    test_gcra_burst_precision();
    test_gcra_boundary_overflow_underflow();
    test_gcra_ntp_backward_jump();
    test_gcra_reservation_preemption();
    test_gcra_long_key_normalization();
    test_proxy_health_check_flapping();
    test_proxy_circuit_breaker_full_trip();
    test_proxy_lb_degraded_routing();
}

// CHECK: === LIT GCRA Rate Limiter & Proxy Chaos Verification ===
// CHECK-NEXT: GCRA_BURST_PRECISION: burst_exhausted=true fractional_rejected=true full_recovered=true
// CHECK-NEXT: GCRA_ARITH_BOUNDS: div_zero_safe=true u64_sat_safe=true cold_start_ok=true
// CHECK-NEXT: GCRA_NTP_BACKWARD_JUMP: clamped_retry_after=true resumed_after_skew=true
// CHECK-NEXT: GCRA_RESERVATION: reserved_3_slots=true preemption_preserved=true resumed=true
// CHECK-NEXT: GCRA_KEY_NORMALIZATION: len_64_normalized=true isolation_verified=true
// CHECK-NEXT: PROXY_HEALTH_FLAPPING: flap_resilient=true sustained_failure_isolated=true
// CHECK-NEXT: PROXY_CIRCUIT_BREAKER: full_trip_fast_fails=true self_healed_on_probe=true
// CHECK-NEXT: PROXY_LB_DEGRADED: unhealthy_skipped=true least_conn_chosen=true

// ============================================================================
// 3. verify_grpc_lpm_edge (3/7)
// ============================================================================
// CHECK: === [3/7] verify_grpc_lpm_edge ===

// tests/lit/verify_grpc_lpm_edge.goose
// Verification of gRPC Length-Prefixed Message (LPM) framing and RFC bounds via wing::grpc.
//

// Wire adapter for verify_split_stream and fuzzing using wing's real decode_grpc_lpm_slice
fn wing_validate_grpc_lpm_wire(buf: const u8[:]) -> i64 {
    let payload_slice, _, _, ok = wing::decode_grpc_lpm_slice(buf, 0);
    if ok {
        return payload_slice.len;
    }
    guard buf.len >= (rfc::GRPC_LPM_HEADER_LEN as i64) else { return -1; }
    let flag = buf[0];
    guard (flag & ~rfc::GRPC_FLAG_COMPRESSED) == 0 else { return -2; }
    return -1;
}

fn run_03_verify_grpc_lpm_edge() {
    var lpm_pkt: u8[>..] = [];
    assert(wire_kit::parse_hex("000000000568656C6C6F", lpm_pkt));

    // Verify encode round-trip with wing::encode_grpc_lpm
    var encoded: u8[>..] = [];
    wing::encode_grpc_lpm("hello", encoded, false);
    assert(encoded[..] == lpm_pkt[..]);

    assert(wire_kit::verify_split_stream(lpm_pkt[..], -1, 5, wing_validate_grpc_lpm_wire));
    assert(wire_kit::fuzz_payload(lpm_pkt[..], 100, wing_validate_grpc_lpm_wire));
    print("GRPC_LPM_SPLIT: OK");

    var ovf1: u8[>..] = []; wire_kit::parse_hex("00FFFFFFFF", ovf1);
    assert(wing_validate_grpc_lpm_wire(ovf1[..]) == -1);

    var ovf2: u8[>..] = []; wire_kit::parse_hex("00FFFFFFFB", ovf2);
    assert(wing_validate_grpc_lpm_wire(ovf2[..]) == -1);

    var bad_flag: u8[>..] = []; wire_kit::parse_hex("0200000000", bad_flag);
    assert(wing_validate_grpc_lpm_wire(bad_flag[..]) == -2);
    print("GRPC_LPM_INVARIANTS: OK");
}

// CHECK: GRPC_LPM_SPLIT: OK
// CHECK: GRPC_LPM_INVARIANTS: OK

// ============================================================================
// 4. verify_grpc_protocol (4/7)
// ============================================================================
// CHECK: === [4/7] verify_grpc_protocol ===

// tests/lit/verify_grpc_protocol.goose
// Native LIT verification suite for Wave 4 Track B:
// GRPCCLI-01..09 (Connect Protocol Unary GET, EndStream 0x02 Envelope,
// grpc-status-details-bin Any unpacking & code-match, Health Check,
// Compressed-Flag 0x01 validation, grpc-web-text Accept negotiation,
// H2 RST_STREAM mapping, Alt-Svc IPv6 & ALPN %XX, GrpcStreamParser cursor).
//

fn idempotent_echo_handler(
    handler_id:  u16,
    ctx:         wing::GrpcServerContext&,
    req_payload: const u8[:],
    res_payload: u8[>..]&,
) -> wing::GrpcStatus {
    let _ = handler_id;
    let _ = ctx;
    res_payload.append(req_payload);
    return wing::grpc_ok();
}

fn verify_connect_unary_get() {
    var params = wing::ConnectUnaryGetParams { .. };
    var payload: u8[>..] = [];
    let st = wing::parse_connect_get_query(
        "?connect=v1&encoding=proto&base64=1&message=cGluZw",
        params,
        payload,
    );
    assert(st == wing::GrpcStatusCode.Ok);
    assert(params.has_version);
    assert(params.base64);
    assert(params.encoding[..] == "proto");
    assert(payload[..] == "ping");

    // Server dispatch of idempotent GET vs non-idempotent rejection
    var disp = wing::GrpcServerDispatcher { .. };
    assert(wing::register_unary(
        disp,
        "test.Echo",
        "GetPing",
        1,
        wing::GrpcIdempotency.NoSideEffects,
    ));
    assert(wing::register_unary(
        disp,
        "test.Echo",
        "Mutate",
        2,
    ));
    assert(wing::register_bidi_streaming(disp, "test.Echo", "Chat", 3));
    assert(wing::find_method_by_name(disp, "test.Echo", "Chat") >= 0);

    var req = wing::new_request("GET", "/test.Echo/GetPing?connect=v1&encoding=proto&base64=1&message=cGluZw");
    var res = wing::Response { .. };
    assert(wing::dispatch_grpc_unary(disp, req, 1000, res, 0, idempotent_echo_handler));
    assert(res.status_code == 200);
    assert(res.body[..] == "ping");

    var req_mut = wing::new_request("GET", "/test.Echo/Mutate?connect=v1&encoding=proto&base64=1&message=cGluZw");
    var res_mut = wing::Response { .. };
    assert(wing::dispatch_grpc_unary(disp, req_mut, 1000, res_mut, 0, idempotent_echo_handler));
    assert(res_mut.status_code == 405);
    print("GRPCCLI_01_CONNECT_GET: OK");
}

fn verify_connect_end_stream() {
    var tr = wing::HeaderMap { .. };
    let _ = wing::append_header(tr, "x-custom-meta", "val123");
    var wire: u8[..512] = [];
    assert(wing::encode_connect_end_stream(
        wing::GrpcStatusCode.Unauthenticated,
        "expired token",
        tr,
        wire,
    ));
    assert(wire[0] == wing::CONNECT_FLAG_END_STREAM);
    let json_len = core::read_be_u32(wire[..], 1) as i64;
    let json_end = core::add_sat_i64(5, json_len);
    let json_slice = wire[5..json_end];

    var out_status = wing::GrpcStatusCode.Ok;
    var out_msg: u8[..256] = [];
    var out_tr = wing::HeaderMap { .. };
    assert(wing::parse_connect_end_stream(json_slice, out_status, out_msg, out_tr));
    assert(out_status == wing::GrpcStatusCode.Unauthenticated);
    assert(out_msg[..] == "expired token");
    assert(wing::get_header(out_tr, "x-custom-meta") == "val123");
    print("GRPCCLI_02_CONNECT_END_STREAM: OK");
}

fn verify_grpc_status_details_and_health() {
    // Build a google.rpc.Status with code=3 (InvalidArgument), message="bad field", and 1 Any detail
    var any_pb: u8[..128] = [];
    assert(wing::pb_write_bytes_field(1, "type.googleapis.com/BadRequest", any_pb));
    assert(wing::pb_write_bytes_field(2, "field_x", any_pb));

    var status_pb: u8[..256] = [];
    assert(wing::pb_write_varint_field(1, 3, status_pb));
    assert(wing::pb_write_bytes_field(2, "bad field", status_pb));
    assert(wing::pb_write_bytes_field(3, any_pb[..], status_pb));

    var b64_buf: u8[..512] = [];
    core::base64_encode(status_pb[..], b64_buf);

    var st_code = wing::GrpcStatusCode.Ok;
    var st_msg:  u8[..256]                  = [];
    var details: wing::GrpcErrorDetail[..4] = [];
    assert(wing::decode_grpc_status_details(
        b64_buf[..],
        wing::GrpcStatusCode.InvalidArgument,
        st_code,
        st_msg,
        details,
    ));
    assert(st_code == wing::GrpcStatusCode.InvalidArgument);
    assert(st_msg[..] == "bad field");
    assert(details.len == 1);
    assert(details[0].type_url[..] == "type.googleapis.com/BadRequest");
    assert(details[0].value[..] == "field_x");

    // Code mismatch override -> Internal
    assert(wing::decode_grpc_status_details(
        b64_buf[..],
        wing::GrpcStatusCode.NotFound,
        st_code,
        st_msg,
        details,
    ));
    assert(st_code == wing::GrpcStatusCode.Internal);
    assert(details.len == 0);
    print("GRPCCLI_03_STATUS_DETAILS: OK");

    // Health check protocol (GRPCCLI-04)
    var disp = wing::GrpcServerDispatcher { .. };
    assert(wing::set_grpc_service_health(disp, "my.Service", wing::GrpcServingStatus.Serving));
    var req_pb: u8[..64] = [];
    assert(wing::pb_write_bytes_field(1, "my.Service", req_pb));
    var lpm_req: u8[>..] = [];
    wing::encode_grpc_lpm(req_pb[..], lpm_req, false);

    var h_req = wing::new_request("POST", "/grpc.health.v1.Health/Check");
    wing::set_header(h_req.headers, "content-type", "application/grpc");
    h_req.body.append(lpm_req[..]);
    var h_res = wing::Response { .. };
    assert(wing::dispatch_grpc_unary(disp, h_req, 1000, h_res, 0, idempotent_echo_handler));
    assert(wing::get_header(h_res.trailers, "grpc-status") == "0");
    print("GRPCCLI_04_HEALTH_CHECK: OK");
}

fn verify_compression_webtext_rst_altsvc_and_cursor() {
    // GRPCCLI-05: Compressed flag 0x01 with empty or "identity" encoding -> Internal
    assert(wing::validate_recv_compression(true, "", true) == wing::GrpcStatusCode.Internal);
    assert(wing::validate_recv_compression(true, "identity", false) == wing::GrpcStatusCode.Internal);
    assert(wing::validate_recv_compression(true, "gzip", true) == wing::GrpcStatusCode.Ok);
    assert(wing::validate_recv_compression(true, "br", true) == wing::GrpcStatusCode.Unimplemented);
    print("GRPCCLI_05_COMPRESSION_FLAG: OK");

    // GRPCCLI-06: Accept: application/grpc-web-text negotiation
    var cfg = wing::GrpcCallConfig { is_web_text: true, .. };
    let _ = cfg.service.try_set("pkg.Svc");
    let _ = cfg.method.try_set("Call");
    var hdrs = wing::HeaderMap { .. };
    wing::build_grpc_request_headers(cfg, "example.com", "https", hdrs);
    assert(wing::get_header(hdrs, "accept") == "application/grpc-web-text+proto");
    let ok_res = wing::GrpcResponse { status: wing::GrpcStatusCode.Ok, .. };
    assert(wing::is_grpc_success(ok_res));
    print("GRPCCLI_06_WEB_TEXT_ACCEPT: OK");

    // GRPCCLI-07: H2 RST_STREAM to gRPC status mapping
    assert(wing::h2_error_to_grpc_status(rfc::H2_ERR_CANCEL) == wing::GrpcStatusCode.Cancelled);
    assert(wing::h2_error_to_grpc_status(rfc::H2_ERR_ENHANCE_YOUR_CALM) == wing::GrpcStatusCode.ResourceExhausted);
    assert(wing::h2_error_to_grpc_status(rfc::H2_ERR_INADEQUATE_SECURITY) == wing::GrpcStatusCode.PermissionDenied);
    assert(wing::h2_error_to_grpc_status(rfc::H2_ERR_REFUSED_STREAM) == wing::GrpcStatusCode.Unavailable);
    print("GRPCCLI_07_RST_STREAM_MAP: OK");

    // GRPCCLI-08: Alt-Svc IPv6 authority & ALPN %XX percent-decoding
    var altsvc_list: wing::AltSvcEndpoint[..4] = [];
    let ok_alt, is_clear = wing::parse_altsvc_header(
        "h3%2D29=\"[2001:db8::1]:443\"; ma=60",
        altsvc_list,
    );
    assert(ok_alt && !is_clear);
    assert(altsvc_list.len == 1);
    assert(altsvc_list[0].proto[..] == "h3-29");
    assert(altsvc_list[0].host[..] == "[2001:db8::1]");
    assert(altsvc_list[0].port == 443);
    print("GRPCCLI_08_ALTSVC_IPV6_ALPN: OK");

    // GRPCCLI-09: GrpcStreamParser read_pos cursor without per-message shift
    var parser = wing::new_grpc_stream_parser(1024);
    var stream_bytes: u8[>..] = [];
    wing::encode_grpc_lpm("msg1", stream_bytes, false);
    wing::encode_grpc_lpm("msg2", stream_bytes, false);
    assert(parser.feed(stream_bytes[..]));
    var out1: u8[>..] = [];
    var comp1 = false;
    assert(wing::next_message(parser, out1, comp1));
    assert(out1[..] == "msg1");
    assert(parser.read_pos == 9);
    var out2: u8[>..] = [];
    var comp2 = false;
    assert(wing::next_message(parser, out2, comp2));
    assert(out2[..] == "msg2");
    assert(parser.read_pos == 0);
    print("GRPCCLI_09_PARSER_READ_POS: OK");
}

fn run_04_verify_grpc_protocol() {
    verify_connect_unary_get();
    verify_connect_end_stream();
    verify_grpc_status_details_and_health();
    verify_compression_webtext_rst_altsvc_and_cursor();
}

// CHECK: GRPCCLI_01_CONNECT_GET: OK
// CHECK: GRPCCLI_02_CONNECT_END_STREAM: OK
// CHECK: GRPCCLI_03_STATUS_DETAILS: OK
// CHECK: GRPCCLI_04_HEALTH_CHECK: OK
// CHECK: GRPCCLI_05_COMPRESSION_FLAG: OK
// CHECK: GRPCCLI_06_WEB_TEXT_ACCEPT: OK
// CHECK: GRPCCLI_07_RST_STREAM_MAP: OK
// CHECK: GRPCCLI_08_ALTSVC_IPV6_ALPN: OK
// CHECK: GRPCCLI_09_PARSER_READ_POS: OK

// ============================================================================
// 5. verify_proxy_grpc (5/7)
// ============================================================================
// CHECK: === [5/7] verify_proxy_grpc ===

// tests/lit/verify_proxy_grpc.goose
// Verification of Reverse Proxy streaming forwarding, Load Balancer flapping mitigation,
// GCRA multi-cell burst guard, gRPC bidirectional LPM streaming, and Protowire status serialization.
//

fn test_proxy_splice_and_userspace_streaming() {
    let tcp_splice = wing::can_use_kernel_splice(wing::ProxyTransportKind.PlainTcp, false);
    let connect_splice = wing::can_use_kernel_splice(wing::ProxyTransportKind.Http1Connect, false);
    let tls_splice = wing::can_use_kernel_splice(wing::ProxyTransportKind.Tls, true);
    let ws_splice = wing::can_use_kernel_splice(wing::ProxyTransportKind.WebSocket, false);
    let wt_splice = wing::can_use_kernel_splice(wing::ProxyTransportKind.WebTransport, true);

    print(
        "PROXY_SPLICE_ELIGIBILITY: tcp=", tcp_splice,
        " connect=", connect_splice,
        " tls=", tls_splice,
        " ws=", ws_splice,
        " wt=", wt_splice, "\n",
    );
    // CHECK: PROXY_SPLICE_ELIGIBILITY: tcp=true connect=true tls=false ws=false wt=false

    // Userspace zero-copy ring-buffer streaming (incoming_slice / advance_read)
    var src_ring = wing::ProxyStreamRing { .. };
    var dst_ring = wing::ProxyStreamRing { .. };

    let ok_feed1 = wing::feed_stream_chunk(src_ring, "PING");
    assert(ok_feed1);
    let slice1 = wing::incoming_slice(src_ring);
    assert(slice1 == "PING");

    // WebSocket RFC 6455 §5.3 XOR masking transfer
    let ws_mask: u8[4] = [0x11, 0x22, 0x33, 0x44];
    let xfer_len, ok_xfer = wing::forward_userspace_stream_chunk(
        src_ring,
        dst_ring,
        wing::ProxyTransportKind.WebSocket,
        ws_mask,
    );
    assert(ok_xfer && xfer_len == 4);
    assert(wing::incoming_slice(src_ring).len == 0);

    let dst_view = wing::incoming_slice(dst_ring);
    assert(dst_view.len == 4);
    assert(dst_view[0] == ('P' ^ 0x11));
    assert(dst_view[1] == ('I' ^ 0x22));
    assert(dst_view[2] == ('N' ^ 0x33));
    assert(dst_view[3] == ('G' ^ 0x44));
    assert(wing::advance_read(dst_ring, 4));
    assert(wing::incoming_slice(dst_ring).len == 0);

    // Overflow rejection (Invariant 13): fill 16380 bytes, then attempt 8 bytes (exceeds 16384 cap)
    var full_ring = wing::ProxyStreamRing { .. };
    var chunk_8k: u8[..8192] = [];
    for _ in 8190 {
        chunk_8k.push('A');
    }
    assert(wing::feed_stream_chunk(full_ring, chunk_8k[..])); // 8190
    assert(wing::feed_stream_chunk(full_ring, chunk_8k[..])); // 16380
    let ok_overflow = wing::feed_stream_chunk(full_ring, "12345678");
    if ok_overflow {
        print("WING_BUFFER_OVERFLOW_SILENT_DROP\n");
    }

    print(
        "PROXY_RING_STREAMING: xfer_len=", xfer_len,
        " drained=", (wing::incoming_slice(dst_ring).len == 0),
        " overflow_rejected=", !ok_overflow, "\n",
    );
    // CHECK: PROXY_RING_STREAMING: xfer_len=4 drained=true overflow_rejected=true
}

fn test_load_balancer_flapping_and_gcra_burst_guard() {
    var cluster = wing::new_upstream_cluster(wing::LbPolicy.RoundRobin, 0);
    wing::add_upstream_target(cluster, "10.0.0.10", 8080);
    wing::set_target_health_thresholds(cluster, 0, 2, 3);

    // 2 consecutive failures (< unhealthy_threshold=3) -> stays Up
    let st_f1 = wing::record_probe_result(cluster.targets[0], false);
    let st_f2 = wing::record_probe_result(cluster.targets[0], false);
    let still_up = (st_f1 == wing::UpstreamHealthState.Up && st_f2 == wing::UpstreamHealthState.Up);

    // 3rd consecutive failure -> trips to Down
    let st_f3 = wing::record_probe_result(cluster.targets[0], false);
    let tripped_down = (st_f3 == wing::UpstreamHealthState.Down && !cluster.targets[0].is_healthy);

    // 1st consecutive success in Down -> transitions to Probing (Half-Open), not yet healthy
    let st_s1 = wing::record_probe_result(cluster.targets[0], true);
    let in_probing = (st_s1 == wing::UpstreamHealthState.Probing && !cluster.targets[0].is_healthy);

    // 2nd consecutive success (reaches healthy_threshold=2) -> closes circuit to Up
    let st_s2 = wing::record_probe_result(cluster.targets[0], true);
    let recovered_up = (st_s2 == wing::UpstreamHealthState.Up && cluster.targets[0].is_healthy);

    print(
        "LB_FLAP_HYSTERESIS: still_up_at_2=", still_up,
        " tripped_at_3=", tripped_down,
        " half_open_at_1=", in_probing,
        " closed_at_2=", recovered_up, "\n",
    );
    // CHECK: LB_FLAP_HYSTERESIS: still_up_at_2=true tripped_at_3=true half_open_at_1=true closed_at_2=true

    // Multi-cell GCRA burst check: reject cost > (max_burst + 1) without mutating TAT
    let cfg = wing::new_gcra_config(10, 2); // T=100ms, tau=200ms, limit_window=300ms (max 3 cells)
    var cell = wing::GcraTatCell { tat_ns: 1000000000 };
    let peek_over = wing::gcra_peek(cfg, cell, 10, 1000000000);
    let dec_over = wing::gcra_check(cfg, cell, 10, 1000000000);
    print(
        "GCRA_MULTI_CELL_GUARD: allowed=", (dec_over.allowed || peek_over.allowed),
        " tat_preserved=", (cell.tat_ns == 1000000000), "\n",
    );
    // CHECK: GCRA_MULTI_CELL_GUARD: allowed=false tat_preserved=true
}

fn test_grpc_bidi_streaming_and_status_details() {
    var stream = wing::H2Stream {
        stream_id:   1,
        state:       wing::H2StreamState.Open,
        send_window: 65535,
        recv_window: 65535,
        active:      true,
        ..
    };

    var raw_in: u8[..64] = [];
    wing::encode_grpc_lpm("hello", raw_in, false);
    wing::encode_grpc_lpm("world", raw_in, false);

    var reader = wing::GrpcLpmReader { .. };
    var writer = wing::GrpcLpmWriter { .. };

    let ok_feed = wing::feed_grpc_lpm_reader(reader, raw_in[..]);
    let ok_bidi = wing::dispatch_grpc_bidi_streaming(stream, reader, writer);

    // Verify truncated LPM frame is rejected
    let truncated: u8[7] = [0x00, 0x00, 0x00, 0x00, 0x05, 'a', 'b'];
    var bad_reader = wing::GrpcLpmReader { .. };
    let ok_trunc = wing::feed_grpc_lpm_reader(bad_reader, truncated[..]);

    print(
        "GRPC_BIDI_LPM: feed_ok=", ok_feed,
        " dispatch_ok=", ok_bidi,
        " out_msgs=", writer.message_count,
        " out_bytes=", writer.wire_buf.len,
        " trunc_rejected=", !ok_trunc, "\n",
    );
    // CHECK: GRPC_BIDI_LPM: feed_ok=true dispatch_ok=true out_msgs=2 out_bytes=20 trunc_rejected=true

    // Verify build_grpc_status_details byte-for-byte Protobuf wire encoding:
    // code = 3 (INVALID_ARGUMENT) -> 0x08 0x03
    // msg = "bad" (len 3) -> 0x12 0x03 'b' 'a' 'd'
    var status_buf: u8[16] = [0; 16];
    let written, ok_status = wing::build_grpc_status_details(3, "bad", status_buf[..]);
    let wire_match = (written == 7 &&
        status_buf[0] == 0x08 &&
        status_buf[1] == 0x03 &&
        status_buf[2] == 0x12 &&
        status_buf[3] == 0x03 &&
        status_buf[4] == 'b' &&
        status_buf[5] == 'a' &&
        status_buf[6] == 'd');

    // Small buffer capacity overflow rejection (Invariant 13)
    var tiny_buf: u8[4] = [0; 4];
    let tiny_written, ok_tiny = wing::build_grpc_status_details(3, "bad", tiny_buf[..]);
    if ok_tiny {
        print("WING_BUFFER_OVERFLOW_SILENT_DROP\n");
    }

    print(
        "GRPC_STATUS_DETAILS: ok=", ok_status,
        " len=", written,
        " wire_match=", wire_match,
        " tiny_rejected=", (!ok_tiny && tiny_written == 0), "\n",
    );
    // CHECK: GRPC_STATUS_DETAILS: ok=true len=7 wire_match=true tiny_rejected=true
    // CHECK-NOT: WING_BUFFER_OVERFLOW_SILENT_DROP
}

fn run_05_verify_proxy_grpc() {
    test_proxy_splice_and_userspace_streaming();
    test_load_balancer_flapping_and_gcra_burst_guard();
    test_grpc_bidi_streaming_and_status_details();
}

// ============================================================================
// 6. verify_proxy_regressions (6/7)
// ============================================================================
// CHECK: === [6/7] verify_proxy_regressions ===

// tests/lit/verify_proxy_regressions.goose
// Regression test suite verifying fixes for proxy subsystem bugs:
// 1. Load balancer Down target hysteresis bypass (flapping bug)
// 2. Health check target_idx OOB bounds checks
// 3. GCRA client_id > 64 byte rate limit bypass
// 4. ReverseProxy duplicate Via header on forwarding
// 5. Client cert DER bounds check safety
// 6. Probing slot sync on Down cluster target
// 7. add_upstream_target empty host validation
//

// 1. Verify load balancer Down target recovery hysteresis
fn test_lb_down_hysteresis() {
    var cluster = wing::new_upstream_cluster(wing::LbPolicy.RoundRobin, 0);
    assert(wing::add_upstream_target(cluster, "srv-1", 80, 1));
    assert(wing::set_target_health_thresholds(cluster, 0, 2, 3));

    // Force target 0 into Down state
    cluster.targets[0].health_state = wing::UpstreamHealthState.Down;
    cluster.targets[0].is_healthy = false;
    cluster.targets[0].successes = 0;
    cluster.targets[0].fails = 3;

    // First success on Down target with threshold 2: transitions to Probing!
    wing::record_upstream_success(cluster, 0);
    assert(cluster.targets[0].health_state == wing::UpstreamHealthState.Probing);
    assert(!cluster.targets[0].is_healthy);
    assert(!cluster.circuit_open);

    // Second success: threshold 2 is met, now transitions to Up!
    wing::record_upstream_success(cluster, 0);
    assert(cluster.targets[0].health_state == wing::UpstreamHealthState.Up);
    assert(cluster.targets[0].is_healthy);
    assert(!cluster.circuit_open);
    print("LB_DOWN_HYSTERESIS: ok\n");
}

// 2. Verify health check OOB target_idx bounds protection
fn test_health_check_bounds() {
    var cfg = wing::new_health_check_config(1000, 500, 2, 3);
    var checker = wing::new_cluster_health_checker(cfg);
    var cluster = wing::new_upstream_cluster(wing::LbPolicy.RoundRobin, 3);
    assert(wing::add_upstream_target(cluster, "srv-1", 80, 1));
    assert(wing::register_target_for_probing(checker, 0));

    // target_idx 99 is out-of-bounds (cluster has only 1 target). Must return Down safely without panicking.
    let s1 = wing::on_probe_success(checker, cluster, 99, 100);
    assert(s1 == wing::HealthState.Down);

    let s2 = wing::on_probe_failure(checker, cluster, 99);
    assert(s2 == wing::HealthState.Down);

    // Corrupt a slot with invalid target_idx to test check_probe_timeouts bounds guard
    checker.slots[0].target_idx = 99;
    checker.slots[0].active_in_flight = true;
    checker.slots[0].probe_start_ms = 1000;
    let timed_out = wing::check_probe_timeouts(checker, cluster, 2000);
    assert(timed_out == 0);

    print("HEALTH_CHECK_BOUNDS: ok\n");
}
// 3. Verify GCRA rate limiter tracks and limits oversized client_id (> 64 bytes)
fn test_gcra_oversized_client_id() {
    var limiter = wing::new_gateway_rate_limiter(10, 2); // 10 req/s, burst 2
    let now_ns: u64 = 1000000000;
    // 68-byte client ID
    let long_id = "client-token-with-oversized-identifier-exceeding-64-bytes-0123456789abc";
    assert(long_id.len > 64);

    // Initial burst requests should be allowed
    let d1 = wing::check_gateway_rate_limit(limiter, long_id, 1, now_ns);
    assert(d1.allowed);
    let d2 = wing::check_gateway_rate_limit(limiter, long_id, 1, now_ns);
    assert(d2.allowed);
    let d3 = wing::check_gateway_rate_limit(limiter, long_id, 1, now_ns);
    assert(d3.allowed);

    // Subsequent requests in the same millisecond must be rate-limited, NOT bypassed!
    let d4 = wing::check_gateway_rate_limit(limiter, long_id, 1, now_ns);
    assert(!d4.allowed);

    print("GCRA_OVERSIZED_CLIENT_ID: ok\n");
}

// 4. Verify ReverseProxy does not duplicate Via header on forwarding
fn test_reverse_proxy_via_dedup() {
    var in_headers = wing::HeaderMap { .. };
    assert(wing::append_header(in_headers, "Host", "api.example.com"));
    assert(wing::append_header(in_headers, "Via", "1.0 upstream-cache"));

    var out_headers = wing::HeaderMap { .. };
    var cfg = wing::ProxyConfig { .. };
    cfg.via_pseudonym.clear();
    cfg.via_pseudonym.append("wing-gw");

    let ok = wing::filter_and_forward_headers(
        in_headers,
        out_headers,
        "192.0.2.1",
        "https",
        "backend.internal:8080",
        cfg,
    );
    assert(ok);

    // Count Via headers in out_headers: must be exactly 1!
    var via_count = 0;
    for i in out_headers.entries.len {
        let entry = out_headers.entries[i];
        let name = out_headers.raw_buf[entry.name_begin..entry.name_end];
        if core::eq_ascii_fold(name, "via") {
            via_count++;
        }
    }
    assert(via_count == 1);
    let v = wing::get_header(out_headers, "Via");
    assert(v == "1.0 upstream-cache, 1.1 wing-gw");

    print("REVERSE_PROXY_VIA_DEDUP: ok\n");
}
// 5. Verify client cert DER length mismatch does not abort
fn test_reverse_proxy_client_cert_safety() {
    var in_headers = wing::HeaderMap { .. };
    assert(wing::append_header(in_headers, "Host", "api.example.com"));

    var out_headers = wing::HeaderMap { .. };
    var cfg = wing::ProxyConfig { .. };
    cfg.forward_client_cert = true;
    cfg.client_cert_der_len = 100; // mismatch: client_cert_der has len 0!

    // Must not panic or crash
    let ok = wing::filter_and_forward_headers(
        in_headers,
        out_headers,
        "192.0.2.1",
        "https",
        "backend:8080",
        cfg,
    );
    assert(ok);
    print("CLIENT_CERT_SAFETY: ok\n");
}

// 6. Verify add_upstream_target rejects empty host
fn test_add_target_empty_host() {
    var cluster = wing::new_upstream_cluster(wing::LbPolicy.RoundRobin, 3);
    assert(!wing::add_upstream_target(cluster, "", 80, 1));
    assert(cluster.targets.len == 0);
    print("ADD_TARGET_EMPTY_HOST: ok\n");
}

// 7. Verify probing slot sync when cluster target drops Down
fn test_health_check_probing_sync() {
    var slot = wing::TargetProbeSlot { .. };
    slot.health.state = wing::HealthState.Probing;
    slot.health.consecutive_successes = 1;

    // Cluster drops to Down: slot must sync to Down and clear successes!
    wing::sync_slot_from_cluster(slot, wing::UpstreamHealthState.Down);
    assert(slot.health.state == wing::HealthState.Down);
    assert(slot.health.consecutive_successes == 0);
    print("HEALTH_CHECK_PROBING_SYNC: ok\n");
}

// 8. F001: prepare_proxy_request_at must fail closed on wire buffer overflow, bad URI, or Content-Length mismatch
fn test_f001_wire_serialization_and_cl_mismatch() {
    var proxy = wing::new_reverse_proxy(wing::LbPolicy.RoundRobin);
    assert(wing::add_upstream_target(proxy.cluster, "backend.internal", 8080, 1));

    var in_headers = wing::HeaderMap { .. };
    assert(wing::append_header(in_headers, "Host", "public.example.com"));

    //Tiny wire buffer that overflows during encode_h1_request
    var tiny_wire: u8[..16] = [];
    let idx_over, ok_over = wing::prepare_proxy_request_at(
        proxy, "GET", "/api/v1/resource", in_headers, "192.0.2.10", "https", "", tiny_wire, 1000000000,
    );
    assert(!ok_over && idx_over == wing::PROXY_TARGET_NONE);
    assert(proxy.cluster.targets[0].active_conns == 0);
    assert(proxy.total_forwarded == 0 && proxy.total_dropped == 1);

    // Content-Length header in in_headers contradicting actual body length (RFC 9112 §6.2)
    var bad_cl_headers = wing::HeaderMap { .. };
    assert(wing::append_header(bad_cl_headers, "Host", "public.example.com"));
    assert(wing::append_header(bad_cl_headers, "Content-Length", "999"));
    var full_wire: u8[>..] = [];
    let idx_cl, ok_cl = wing::prepare_proxy_request_at(
        proxy, "POST", "/submit", bad_cl_headers, "192.0.2.10", "https", "hello", full_wire, 1000000000,
    );
    assert(!ok_cl && idx_cl == wing::PROXY_TARGET_NONE);
    assert(proxy.cluster.targets[0].active_conns == 0);
    print("F001_WIRE_AND_CL_GUARD: ok\n");
}

// 9. F002: Multi-header Via preservation (RFC 9110 §7.6.3) and XFF overflow fail-closed
fn test_f002_multi_via_and_xff_overflow() {
    var in_headers = wing::HeaderMap { .. };
    assert(wing::append_header(in_headers, "Host", "api.example.com"));
    assert(wing::append_header(in_headers, "Via", "1.1 edge-proxy"));
    assert(wing::append_header(in_headers, "Via", "1.1 mesh-proxy"));

    var out_headers = wing::HeaderMap { .. };
    var cfg = wing::ProxyConfig { .. };
    cfg.via_pseudonym.clear();
    cfg.via_pseudonym.append("wing-gw");

    assert(wing::filter_and_forward_headers(in_headers, out_headers, "192.0.2.1", "https", "backend:8080", cfg));
    let v = wing::get_header(out_headers, "Via");
    assert(v == "1.1 edge-proxy, 1.1 mesh-proxy, 1.1 wing-gw");

    // Multi-header XFF exceeding 1024 bytes when trust_incoming_xff = true must fail closed (not panic or drop hops)
    var xff_headers = wing::HeaderMap { .. };
    assert(wing::append_header(xff_headers, "Host", "api.example.com"));
    assert(wing::append_header(xff_headers, "X-Forwarded-For", "10.0.0.1"));
    var big_xff: u8[..600] = [];
    for _ in 550 { big_xff.push('1'); }
    assert(wing::append_header(xff_headers, "X-Forwarded-For", big_xff[..]));
    assert(wing::append_header(xff_headers, "X-Forwarded-For", big_xff[..]));
    cfg.trust_incoming_xff = true;
    var out_xff = wing::HeaderMap { .. };
    let ok_xff = wing::filter_and_forward_headers(xff_headers, out_xff, "192.0.2.1", "https", "backend:8080", cfg);
    assert(!ok_xff);
    print("F002_MULTI_VIA_AND_XFF_GUARD: ok\n");
}

// 10. F003: Reject Connection: content-length / host and format bare IPv6 / pre-ported upstream Host cleanly
fn test_f003_connection_smuggle_and_ipv6_host() {
    var smuggle_cl = wing::HeaderMap { .. };
    assert(wing::append_header(smuggle_cl, "Host", "api.example.com"));
    assert(wing::append_header(smuggle_cl, "Connection", "keep-alive, content-length"));
    assert(wing::append_header(smuggle_cl, "Content-Length", "5"));
    var out_smuggle = wing::HeaderMap { .. };
    var cfg = wing::ProxyConfig { .. };
    assert(!wing::filter_and_forward_headers(smuggle_cl, out_smuggle, "192.0.2.1", "http", "backend:8080", cfg));

    var proxy = wing::new_reverse_proxy(wing::LbPolicy.RoundRobin);
    assert(wing::add_upstream_target(proxy.cluster, "2001:db8::1", 8080, 1));
    var in_hdr = wing::HeaderMap { .. };
    assert(wing::append_header(in_hdr, "Host", "edge.example.com"));
    var wire: u8[>..] = [];
    let _, ok_v6 = wing::prepare_proxy_request_at(proxy, "GET", "/v6", in_hdr, "192.0.2.1", "http", "", wire, 1000000000);
    assert(ok_v6);
    assert(core::contains(wire[..], "Host: [2001:db8::1]:8080\r\n"));
    print("F003_CONN_SMUGGLE_AND_IPV6_HOST: ok\n");
}

// 11. F004: exchange_prepared_wire_on_conn caps 1xx responses (RFC 9110 §15.2) and drains conn.rx_buf
fn test_f004_exchange_interim_and_rx_buf() {
    var conn_flood = wing::PooledConnection {
        transport: wing::Transport.Mock { route_idx: 0, cursor: 0 },
        ..
    };
    for _ in 7 {
        conn_flood.rx_buf.append("HTTP/1.1 100 Continue\r\n\r\n");
    }
    conn_flood.rx_buf.append("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK");
    var resp_flood = wing::Response { .. };
    let ok_flood, _ = wing::exchange_prepared_wire_on_conn(conn_flood, "GET", "GET / HTTP/1.1\r\nHost: a\r\n\r\n", resp_flood, 100);
    assert(!ok_flood);

    var conn_clean = wing::PooledConnection {
        transport: wing::Transport.Mock { route_idx: 0, cursor: 0 },
        ..
    };
    conn_clean.rx_buf.append("HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\nPONG");
    var resp_clean = wing::Response { .. };
    resp_clean.body.append("STALE_BODY");
    let ok_clean, ka = wing::exchange_prepared_wire_on_conn(conn_clean, "GET", "GET / HTTP/1.1\r\nHost: a\r\n\r\n", resp_clean, 100);
    assert(ok_clean && ka);
    assert(resp_clean.body[..] == "PONG");
    assert(conn_clean.rx_buf.len == 0);
    print("F004_EXCHANGE_1XX_AND_RX_BUF: ok\n");
}

// 12. F005 & F006: Health check Probing/Up sync + status parser & GCRA slot reuse / penalty
fn test_f005_and_f006_health_and_gcra() {
    var cluster = wing::new_upstream_cluster(wing::LbPolicy.RoundRobin, 2);
    assert(wing::add_upstream_target(cluster, "10.0.0.1", 8080, 1));
    var checker = wing::new_cluster_health_checker(wing::new_health_check_config(1000, 500, 2, 2));
    assert(!wing::register_target_for_probing(checker, -1));
    assert(wing::register_target_for_probing(checker, 0));

    let _, ok_4digit = wing::parse_probe_status_code("HTTP/1.1 2000 OK\r\n\r\n");
    assert(!ok_4digit);

    wing::on_probe_failure(checker, cluster, 0);
    wing::on_probe_failure(checker, cluster, 0);
    assert(cluster.circuit_open);
    // 1st probe success enters Probing and must reopen circuit for trial traffic
    wing::on_probe_success(checker, cluster, 0, 200);
    assert(!cluster.circuit_open);
    // Passive recovery to Up must sync back to slot so next probe success keeps target Up
    wing::record_upstream_success(cluster, 0);
    assert(cluster.targets[0].is_healthy);
    wing::on_probe_success(checker, cluster, 0, 200);
    assert(cluster.targets[0].is_healthy);

    var limiter = wing::new_gateway_rate_limiter(10, 1);
    let _ = wing::check_gateway_rate_limit(limiter, "10.0.0.1", 1, 1000000000);
    assert(wing::evict_idle_gateway_clients(limiter, 100, 5000000000) == 1);
    let _ = wing::check_gateway_rate_limit(limiter, "10.0.0.2", 1, 5000000000);
    assert(limiter.entries.len == 1);
    wing::penalize_gateway_client(limiter, "10.0.0.99", 5000000000, 5000000000);
    assert(!wing::check_gateway_rate_limit(limiter, "10.0.0.99", 1, 5100000000).allowed);
    wing::reset_gateway_rate_limiter(limiter);
    assert(limiter.entries.len == 0);
    print("F005_F006_HEALTH_AND_GCRA: ok\n");
}

// 13. SRVPROXY-01 & SRVPROXY-02: 103 Early Hints serializer, no-early-hints: 1 suppression, CASPer cookie & proxy 103 capture
fn test_srvproxy_01_02_early_hints_and_casper() {
    let hints, ok_hints = wing::parse_early_hints(
        103, "</style.css>; rel=preload; as=style; crossorigin, </app.js>; rel=preload; as=script",
    );
    assert(ok_hints && hints.links.len == 2);

    var out_103: u8[..512] = [];
    assert(!wing::format_early_hints_http1(hints, "1", out_103));
    assert(out_103.len == 0);
    assert(wing::format_early_hints_http1(hints, "", out_103));
    assert(core::contains(out_103[..], "HTTP/1.1 103 Early Hints\r\nLink: </style.css>; rel=preload; as=style; crossorigin\r\n"));

    var cset = wing::CasperSet { .. };
    assert(!wing::casper_lookup_and_insert(cset, "/style.css", "v1"));
    assert(wing::casper_lookup_and_insert(cset, "/style.css", "v1"));
    assert(!wing::casper_lookup_and_insert(cset, "/app.js", "v2"));

    var cookie_buf: u8[..128] = [];
    assert(wing::encode_casper_cookie(cset, cookie_buf));
    assert(cookie_buf.len > 0);

    var decoded_set = wing::CasperSet { .. };
    assert(wing::decode_casper_cookie(cookie_buf[..], decoded_set));
    assert(decoded_set.keys.len == cset.keys.len);
    assert(wing::casper_lookup_and_insert(decoded_set, "/style.css", "v1"));

    var conn_103 = wing::PooledConnection {
        transport: wing::Transport.Mock { route_idx: 0, cursor: 0 },
        ..
    };
    conn_103.rx_buf.append("HTTP/1.1 103 Early Hints\r\nLink: </hero.webp>; rel=preload; as=image\r\n\r\nHTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK");
    var up_resp = wing::UpstreamResponse { .. };
    var early_hints = wing::EarlyHintsResponse { .. };
    var has_eh = false;
    let ok_ex, ka_ex = wing::exchange_prepared_wire_on_conn_with_hints(
        conn_103, "GET", "GET / HTTP/1.1\r\nHost: a\r\n\r\n", up_resp.resp, early_hints, has_eh, 100,
    );
    up_resp.early_hints = early_hints;
    up_resp.has_early_hints = has_eh;
    assert(ok_ex && ka_ex);
    assert(up_resp.has_early_hints);
    assert(up_resp.early_hints.links.len == 1);
    assert(up_resp.early_hints.links[0].uri[..] == "/hero.webp");
    assert(up_resp.resp.status_code == 200);
    print("SRVPROXY_01_02_EARLY_HINTS_CASPER: ok\n");
}

// 14. SRVPROXY-03 & SRVPROXY-04: Ketama consistent hashing ring & cache stampede AgeTimeout / GiveUp
fn test_srvproxy_03_04_ketama_and_cache_lock() {
    var cluster = wing::new_upstream_cluster(wing::LbPolicy.ConsistentHash, 3);
    assert(wing::add_upstream_target(cluster, "10.0.0.1", 8080, 1));
    assert(wing::add_upstream_target(cluster, "10.0.0.2", 8080, 2));
    assert(wing::add_upstream_target(cluster, "10.0.0.3", 8080, 1));

    var ring = wing::KetamaRing { .. };
    wing::build_ketama_ring(cluster, ring);
    assert(ring.points.len > 0);

    let idx1, ok1 = wing::select_consistent_backend(cluster, ring, "/users/42", 1000);
    let idx2, ok2 = wing::select_consistent_backend(cluster, ring, "/users/42", 1000);
    assert(ok1 && ok2 && idx1 == idx2);

    cluster.targets[idx1].ejected_until_ms = 5000;
    let idx_failover, ok_fo = wing::select_consistent_backend(cluster, ring, "/users/42", 2000);
    assert(ok_fo && idx_failover != idx1);

    let idx_recovered, ok_rec = wing::select_consistent_backend(cluster, ring, "/users/42", 6000);
    assert(ok_rec && idx_recovered == idx1);

    var writers = wing::CacheWriters { .. };
    let is_ldr, fl_idx = wing::start_writer_or_join(writers, "/asset");
    assert(is_ldr && fl_idx >= 0);
    wing::abort_writer(writers, fl_idx);
    assert(wing::acquire_at(writers, 0xABCD, 1000, 5000));
    assert(!wing::acquire_at(writers, 0xABCD, 3000, 5000));
    // Preempt expired lock after age_timeout_ms (1000 + 5000 <= 6000)
    assert(wing::acquire_at(writers, 0xABCD, 6000, 5000));
    wing::release_with_status(writers, 0xABCD, wing::CacheLockStatus.GiveUp);
    assert(wing::acquire(writers, 0xABCD));
    wing::release_with_status(writers, 0xABCD, wing::CacheLockStatus.Done);
    print("SRVPROXY_03_04_KETAMA_CACHE_LOCK: ok\n");
}

// 15. SRVPROXY-05..08: X-Accel-* filtering, Location rewrite, empty POST CL:0, 304 CL, PROXYv2 CRC32C & FastHTTP Host/CRLF
fn test_srvproxy_05_06_07_08_headers_crc32c_and_memo() {
    var up_hdrs = wing::HeaderMap { .. };
    assert(wing::append_header(up_hdrs, "X-Accel-Buffering", "no"));
    assert(wing::append_header(up_hdrs, "X-Accel-Expires", "120"));
    assert(wing::append_header(up_hdrs, "X-Accel-Limit-Rate", "65536"));
    assert(wing::append_header(up_hdrs, "X-Accel-Redirect", "/internal/files/a.bin"));
    assert(wing::append_header(up_hdrs, "Location", "http://10.0.0.1:8080/app/login"));
    assert(wing::append_header(up_hdrs, "Content-Type", "text/plain"));

    var client_hdrs = wing::HeaderMap { .. };
    var loc_buf: u8[..512] = [];
    var accel = wing::UpstreamAccelControl { .. };
    assert(wing::process_and_filter_upstream_response_headers(
        up_hdrs, "http://10.0.0.1:8080/app", "https://example.com/public", client_hdrs, loc_buf, accel,
    ));
    assert(accel.disable_buffering && accel.has_accel_expires && accel.accel_expires_sec == 120);
    assert(accel.limit_rate_bps == 65536 && accel.accel_redirect[..] == "/internal/files/a.bin");
    assert(wing::get_header(client_hdrs, "X-Accel-Buffering") == "");
    assert(wing::get_header(client_hdrs, "Location") == "https://example.com/public/login");

    var proxy = wing::new_reverse_proxy(wing::LbPolicy.RoundRobin);
    assert(wing::add_upstream_target(proxy.cluster, "backend.internal", 8080, 1));
    var post_hdr = wing::HeaderMap { .. };
    assert(wing::append_header(post_hdr, "Host", "edge.example.com"));
    var post_wire: u8[>..] = [];
    let _, ok_post = wing::prepare_proxy_request_at(proxy, "POST", "/empty", post_hdr, "192.0.2.1", "http", "", post_wire, 1000);
    assert(ok_post && core::contains(post_wire[..], "Content-Length: 0\r\n"));

    var res_304 = wing::Response { status_code: 304, .. };
    res_304.set_header("Content-Length", "4096");
    res_304.set_header("ETag", "\"v1\"");
    var wire_304: u8[..512] = [];
    wing::serialize_http1_response(res_304, "wing", wire_304);
    assert(core::contains(wire_304[..], "Content-Length: 4096\r\n"));

    var pp2_hdr = wing::ProxyHeader {
        version:  wing::ProxyProtocolVersion.V2,
        command:  wing::ProxyCommand.Proxy,
        family:   wing::ProxyAddressFamily.Inet4,
        src_ipv4: [192, 0, 2, 10],
        dst_ipv4: [198, 51, 100, 1],
        src_port: 54321,
        dst_port: 443,
        ..
    };
    var pp2_wire: u8[..128] = [];
    assert(wing::format_proxy_v2(pp2_hdr, pp2_wire));
    assert(wing::append_proxy_v2_crc32c(pp2_wire));
    let parsed_pp2, consumed_pp2, ok_pp2 = wing::parse_proxy_v2(pp2_wire[..]);
    assert(ok_pp2 && consumed_pp2 == pp2_wire.len && parsed_pp2.src_port == 54321);
    pp2_wire[pp2_wire.len - 1] = pp2_wire[pp2_wire.len - 1] ^ 0xFF;
    let _, _, ok_bad = wing::parse_proxy_v2(pp2_wire[..]);
    assert(!ok_bad);

    var last_host: u8[..128] = [];
    var has_host = false;
    assert(wing::validate_span_host_header_memoized(post_hdr, 0, last_host, has_host));
    assert(has_host && last_host[..] == "edge.example.com");
    assert(wing::validate_span_host_header_memoized(post_hdr, 0, last_host, has_host));

    var scan_cur: i64 = 0;
    let partial_req = "GET / HTTP/1.1\r\nHost: edge.example.com\r\n";
    assert(wing::scan_crlfcrlf_incremental(partial_req, scan_cur) == -1 && scan_cur == partial_req.len);
    let full_req = "GET / HTTP/1.1\r\nHost: edge.example.com\r\n\r\n";
    assert(wing::scan_crlfcrlf_incremental(full_req, scan_cur) == 38 && scan_cur == 0);

    var date_buf: u8[..64] = [];
    wing::format_local_http_date(date_buf, 1700000000);
    var srv = wing::new_http_server_with_quota("127.0.0.1", 8080, wing::new_gcra_quota(100, core::secs(1), 10));
    wing::refresh_http_server_date(srv, 1700000000);
    wing::add_put_route(srv, "/put", 1);
    wing::add_delete_route(srv, "/del", 2);
    var stg_req = wing::new_request("PUT", "/put");
    var stg_match = wing::RouteMatchResult.NotFound;
    let _ = wing::stage_server_route_match(srv.pipeline.router, stg_req, srv.pipeline.ext_pool.slots[0], stg_match, res_304);
    var te_buf: u8[..64] = [];
    let _ = wing::collect_transfer_encoding_headers(stg_req.headers, te_buf);
    assert(wing::serve_page_ring(srv, -1, 0) == 0);
    assert(!wing::send_static_mmap_file(-1, "/nonexistent", "text/plain"));
    print("SRVPROXY_05_06_07_08_ALL: ok\n");
}

fn run_06_verify_proxy_regressions() {
    test_lb_down_hysteresis();
    // CHECK: LB_DOWN_HYSTERESIS: ok
    test_health_check_bounds();
    // CHECK: HEALTH_CHECK_BOUNDS: ok
    test_gcra_oversized_client_id();
    // CHECK: GCRA_OVERSIZED_CLIENT_ID: ok
    test_reverse_proxy_via_dedup();
    // CHECK: REVERSE_PROXY_VIA_DEDUP: ok
    test_reverse_proxy_client_cert_safety();
    // CHECK: CLIENT_CERT_SAFETY: ok
    test_add_target_empty_host();
    // CHECK: ADD_TARGET_EMPTY_HOST: ok
    test_health_check_probing_sync();
    // CHECK: HEALTH_CHECK_PROBING_SYNC: ok
    test_f001_wire_serialization_and_cl_mismatch();
    // CHECK: F001_WIRE_AND_CL_GUARD: ok
    test_f002_multi_via_and_xff_overflow();
    // CHECK: F002_MULTI_VIA_AND_XFF_GUARD: ok
    test_f003_connection_smuggle_and_ipv6_host();
    // CHECK: F003_CONN_SMUGGLE_AND_IPV6_HOST: ok
    test_f004_exchange_interim_and_rx_buf();
    // CHECK: F004_EXCHANGE_1XX_AND_RX_BUF: ok
    test_f005_and_f006_health_and_gcra();
    // CHECK: F005_F006_HEALTH_AND_GCRA: ok
    test_srvproxy_01_02_early_hints_and_casper();
    // CHECK: SRVPROXY_01_02_EARLY_HINTS_CASPER: ok
    test_srvproxy_03_04_ketama_and_cache_lock();
    // CHECK: SRVPROXY_03_04_KETAMA_CACHE_LOCK: ok
    test_srvproxy_05_06_07_08_headers_crc32c_and_memo();
    // CHECK: SRVPROXY_05_06_07_08_ALL: ok
    print("ALL_PROXY_REGRESSIONS_PASS\n");
    // CHECK: ALL_PROXY_REGRESSIONS_PASS
}

// ============================================================================
// 7. verify_reverse_proxy (7/7)
// ============================================================================
// CHECK: === [7/7] verify_reverse_proxy ===

// RFC 9110 §7.6: Layer 7 Reverse Proxy Hop-by-Hop Filter and Load Balancer Verification

fn test_load_balancer_round_robin() {
    var cluster = wing::new_upstream_cluster(wing::LbPolicy.RoundRobin, 3);
    wing::add_upstream_target(cluster, "10.0.0.1", 8080);
    wing::add_upstream_target(cluster, "10.0.0.2", 8080);
    wing::add_upstream_target(cluster, "10.0.0.3", 8080);

    let idx1, ok1 = wing::select_upstream(cluster);
    let idx2, ok2 = wing::select_upstream(cluster);
    let idx3, ok3 = wing::select_upstream(cluster);
    let idx4, ok4 = wing::select_upstream(cluster);

    print("LB_RR: ", ok1, " ", idx1, " -> ", ok2, " ", idx2, " -> ", ok3, " ", idx3, " -> ", ok4, " ", idx4, "\n");
    // CHECK: LB_RR: true 0 -> true 1 -> true 2 -> true 0
}

fn test_load_balancer_circuit_breaker() {
    var cluster = wing::new_upstream_cluster(wing::LbPolicy.RoundRobin, 2);
    wing::add_upstream_target(cluster, "10.0.0.1", 8080);
    wing::add_upstream_target(cluster, "10.0.0.2", 8080);

    // Fail target 0 twice -> marks target 0 unhealthy
    wing::record_upstream_failure(cluster, 0);
    wing::record_upstream_failure(cluster, 0);

    let idx1, ok1 = wing::select_upstream(cluster);
    let idx2, ok2 = wing::select_upstream(cluster);

    // Fail target 1 twice -> trips circuit breaker
    wing::record_upstream_failure(cluster, 1);
    wing::record_upstream_failure(cluster, 1);

    let idx3, ok3 = wing::select_upstream(cluster);

    print(
        "LB_CB: t0_fail_routed_to_t1=", (idx1 == 1 && idx2 == 1),
        " circuit_open=", cluster.circuit_open,
        " exhausted=", !ok3, "\n",
    );
    // CHECK: LB_CB: t0_fail_routed_to_t1=true circuit_open=true exhausted=true

    // Recover target 0
    wing::record_upstream_success(cluster, 0);
    let idx4, ok4 = wing::select_upstream(cluster);
    print("LB_RECOVER: ok=", ok4, " target=", idx4, " circuit_open=", cluster.circuit_open, "\n");
    // CHECK: LB_RECOVER: ok=true target=0 circuit_open=false
}

fn test_load_balancer_least_connections() {
    var cluster = wing::new_upstream_cluster(wing::LbPolicy.LeastConnections, 3);
    wing::add_upstream_target(cluster, "srv-a", 80);
    wing::add_upstream_target(cluster, "srv-b", 80);

    // Target 0 has 5 active connections, target 1 has 1 active connection
    cluster.targets[0].active_conns = 5;
    cluster.targets[1].active_conns = 1;

    let chosen, ok = wing::select_upstream(cluster);
    print("LB_LEAST_CONN: chosen=", chosen, " active_conns=", cluster.targets[chosen].active_conns, "\n");
    // CHECK: LB_LEAST_CONN: chosen=1 active_conns=2

    wing::release_upstream_connection(cluster, chosen);
    print("LB_RELEASE: conns_after_release=", cluster.targets[1].active_conns, "\n");
    // CHECK: LB_RELEASE: conns_after_release=1
}

fn test_reverse_proxy_hop_by_hop_stripping() {
    var in_headers = wing::HeaderMap { .. };
    wing::append_header(in_headers, "Host", "frontend.example.com");
    wing::append_header(in_headers, "User-Agent", "curl/8.0");
    wing::append_header(in_headers, "Connection", "keep-alive, X-Foo-Internal");
    wing::append_header(in_headers, "Keep-Alive", "timeout=5");
    wing::append_header(in_headers, "Upgrade", "websocket");
    wing::append_header(in_headers, "Transfer-Encoding", "chunked");
    wing::append_header(in_headers, "X-Foo-Internal", "secret-token");
    wing::append_header(in_headers, "X-Custom-Data", "retained-value");
    wing::append_header(in_headers, "TE", "trailers");

    var out_headers = wing::HeaderMap { .. };
    var cfg = wing::ProxyConfig { .. };
    cfg.preserve_host = false;
    cfg.via_pseudonym.clear();
    cfg.via_pseudonym.append("wing-gw");

    wing::filter_and_forward_headers(
        in_headers,
        out_headers,
        "203.0.113.195",
        "https",
        "backend.internal:8080",
        cfg,
    );

    let h_host = wing::get_header(out_headers, "Host");
    let h_ua = wing::get_header(out_headers, "User-Agent");
    let h_conn = wing::get_header(out_headers, "Connection");
    let h_ka = wing::get_header(out_headers, "Keep-Alive");
    let h_upg = wing::get_header(out_headers, "Upgrade");
    let h_te = wing::get_header(out_headers, "TE");
    let h_internal = wing::get_header(out_headers, "X-Foo-Internal");
    let h_data = wing::get_header(out_headers, "X-Custom-Data");
    let h_xff = wing::get_header(out_headers, "X-Forwarded-For");
    let h_proto = wing::get_header(out_headers, "X-Forwarded-Proto");
    let h_xfh = wing::get_header(out_headers, "X-Forwarded-Host");
    let h_via = wing::get_header(out_headers, "Via");

    print("H_HOST: ", h_host, "\n");
    // CHECK: H_HOST: backend.internal:8080
    print("H_UA: ", h_ua, "\n");
    // CHECK: H_UA: curl/8.0
    print("H_STRIPPED: conn=", h_conn.len, " ka=", h_ka.len, " upg=", h_upg.len, " internal=", h_internal.len, "\n");
    // CHECK: H_STRIPPED: conn=0 ka=0 upg=0 internal=0
    print("H_TE_TRAILERS: ", h_te, "\n");
    // CHECK: H_TE_TRAILERS: trailers
    print("H_CUSTOM: ", h_data, "\n");
    // CHECK: H_CUSTOM: retained-value
    print("H_XFF: ", h_xff, "\n");
    // CHECK: H_XFF: 203.0.113.195
    print("H_PROTO: ", h_proto, "\n");
    // CHECK: H_PROTO: https
    print("H_XFH: ", h_xfh, "\n");
    // CHECK: H_XFH: frontend.example.com
    print("H_VIA: ", h_via, "\n");
    // CHECK: H_VIA: 1.1 wing-gw
}

fn test_reverse_proxy_xff_chaining() {
    var in_headers = wing::HeaderMap { .. };
    wing::append_header(in_headers, "Host", "api.example.com");
    wing::append_header(in_headers, "X-Forwarded-For", "198.51.100.1, 10.0.0.1");

    var out_headers = wing::HeaderMap { .. };
    var cfg = wing::ProxyConfig { .. };
    cfg.trust_incoming_xff = true;

    wing::filter_and_forward_headers(
        in_headers,
        out_headers,
        "192.0.2.42",
        "http",
        "app-cluster",
        cfg,
    );

    let chained_xff = wing::get_header(out_headers, "X-Forwarded-For");
    print("XFF_CHAINED: ", chained_xff, "\n");
    // CHECK: XFF_CHAINED: 198.51.100.1, 10.0.0.1, 192.0.2.42
}

fn test_reverse_proxy_xff_untrusted_perimeter() {
    var in_headers = wing::HeaderMap { .. };
    wing::append_header(in_headers, "Host", "api.example.com");
    wing::append_header(in_headers, "X-Forwarded-For", "127.0.0.1, 10.0.0.1");

    var out_headers = wing::HeaderMap { .. };
    let cfg = wing::ProxyConfig { .. }; // trust_incoming_xff is false by default

    wing::filter_and_forward_headers(
        in_headers,
        out_headers,
        "192.0.2.42",
        "http",
        "app-cluster",
        cfg,
    );

    let perimeter_xff = wing::get_header(out_headers, "X-Forwarded-For");
    print("XFF_PERIMETER: ", perimeter_xff, "\n");
    // CHECK: XFF_PERIMETER: 192.0.2.42
}

fn test_upstream_request_wire_serialization() {
    var proxy = wing::new_reverse_proxy(wing::LbPolicy.RoundRobin);
    wing::add_upstream_target(proxy.cluster, "upstream.local:9000", 9000);

    var in_headers = wing::HeaderMap { .. };
    wing::append_header(in_headers, "Host", "public.example.com");
    wing::append_header(in_headers, "Accept", "application/json");

    var wire_out: u8[>..] = [];
    let body = "{\"event\":\"ping\"}";

    let idx, ok = wing::prepare_proxy_request(
        proxy,
        "POST",
        "/api/v2/events",
        in_headers,
        "172.16.0.5",
        "https",
        body,
        wire_out,
    );

    print("WIRE_OK: ", ok, " target_idx=", idx, "\n");
    // CHECK: WIRE_OK: true target_idx=0

    let wire_str = wire_out[..];
    print("WIRE_START: ", wire_str[0..28], "\n");
    // CHECK: WIRE_START: POST /api/v2/events HTTP/1.1
    print("WIRE_TOTAL_LEN: ", wire_out.len > 100, "\n");
    // CHECK: WIRE_TOTAL_LEN: true
}

fn run_07_verify_reverse_proxy() {
    print("=== LIT Reverse Proxy & Load Balancer Verification ===\n");
    test_load_balancer_round_robin();
    test_load_balancer_circuit_breaker();
    test_load_balancer_least_connections();
    test_reverse_proxy_hop_by_hop_stripping();
    test_reverse_proxy_xff_chaining();
    test_reverse_proxy_xff_untrusted_perimeter();
    test_upstream_request_wire_serialization();
}

fn main() {
    print("\n=== [1/7] rfc_repro_grpc_bug_hunter ===\n");
    run_01_rfc_repro_grpc_bug_hunter();
    print("\n=== [2/7] verify_gcra_proxy_chaos ===\n");
    run_02_verify_gcra_proxy_chaos();
    print("\n=== [3/7] verify_grpc_lpm_edge ===\n");
    run_03_verify_grpc_lpm_edge();
    print("\n=== [4/7] verify_grpc_protocol ===\n");
    run_04_verify_grpc_protocol();
    print("\n=== [5/7] verify_proxy_grpc ===\n");
    run_05_verify_proxy_grpc();
    print("\n=== [6/7] verify_proxy_regressions ===\n");
    run_06_verify_proxy_regressions();
    print("\n=== [7/7] verify_reverse_proxy ===\n");
    run_07_verify_reverse_proxy();
}
