// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// RUN: goose build --debug -O0 -o %t.exe %s
// RUN: %t.exe | %FileCheck %s

import std;
import wing_h1 from "../..";

const ROUTE_PROTECTED: u64 = 1 << 0;

struct AuthGateStage {
    required_token: const u8[:] = "secret-42",
    blocked_count:  i64         = 0,
    abort_header:   const u8[:] = "X-Kill-Conn",
}

fn h1::on_ingress(
    st:  AuthGateStage&,
    req: const h1::RequestView&,
    ctx: h1::StageCtx&,
    res: h1::ResponseView&,
) -> h1::StageVerdict {
    if h1::has_header(req, st.abort_header) {
        return h1::StageVerdict.Abort;
    }
    if (ctx.stage_mask & ROUTE_PROTECTED) != 0 {
        let tok = h1::header(req, "x-api-token");
        if tok != st.required_token {
            st.blocked_count += 1;
            h1::set_text_view(res, 401, "Unauthorized");
            return h1::StageVerdict.ShortCircuit;
        }
    }
    return h1::StageVerdict.Continue;
}

fn h1::on_egress(
    _st:  AuthGateStage&,
    _req: const h1::RequestView&,
    _ctx: const h1::StageCtx&,
    res:  h1::ResponseView&,
) {
    let _ = h1::add_header(res, "X-Pipeline", "vulkan-h1");
}

struct TraceHeaderStage {
    seen_requests: i64 = 0,
}

fn h1::on_ingress(
    st:   TraceHeaderStage&,
    _req: const h1::RequestView&,
    _ctx: h1::StageCtx&,
    _res: h1::ResponseView&,
) -> h1::StageVerdict {
    st.seen_requests += 1;
    return h1::StageVerdict.Continue;
}

fn h1::on_egress(
    _st:  TraceHeaderStage&,
    req:  const h1::RequestView&,
    _ctx: const h1::StageCtx&,
    res:  h1::ResponseView&,
) {
    let trace_id = h1::header(req, "x-trace");
    if trace_id.len > 0 {
        let _ = h1::add_header(res, "X-Trace-Echo", trace_id);
    }
}

struct AppHandler {
    calls: i64 = 0,
}

fn handle_route(
    h:   AppHandler&,
    req: const h1::RequestView&,
    ctx: const h1::StageCtx&,
    res: h1::ResponseView&,
) {
    h.calls += 1;
    if ctx.handler_id == 1 {
        h1::set_json_view(res, 200, "{\"ok\":true}");
        return;
    }
    if ctx.handler_id == 2 {
        h1::set_text_view(res, 200, "static-me");
        return;
    }
    if ctx.handler_id == 3 {
        let uid, ok_id = h1::route_param(ctx, "id");
        var role_buf: u8[..64] = [];
        let qm = h1::query_param(req, "role", role_buf);
        let _ = h1::set_body_buf(res, 200, "text/plain", "user=");
        if ok_id {
            let _ = h1::write_body(res, uid);
        }
        if qm == h1::QueryMatch.Value {
            let _ = h1::write_body(res, " role=");
            let _ = h1::write_body(res, role_buf[..]);
        }
        return;
    }
    if ctx.handler_id == 4 {
        let fp, ok_fp = h1::route_param(ctx, "filepath");
        let _ = h1::set_body_buf(res, 200, "text/plain", if ok_fp { fp } else { "" });
        return;
    }
    if ctx.handler_id == 5 {
        let _ = h1::set_body_buf(res, 200, "text/plain", req.body);
        return;
    }
    if ctx.handler_id == 6 {
        h1::set_text_view(res, 200, "secret-ok");
        return;
    }
}

fn build_test_router() -> h1::Router {
    var r = h1::Router { .. };
    let _ = h1::add_route(r, "GET", "/health", 1);
    // Register param route BEFORE static /users/me to prove insertion-order independent precedence.
    let _ = h1::add_route(r, "GET", "/users/:id", 3);
    let _ = h1::add_route(r, "GET", "/users/me", 2);
    let _ = h1::add_route(r, "GET", "/files/{*filepath}", 4);
    let _ = h1::add_route(r, "POST", "/echo", 5);
    let _ = h1::add_route(r, "GET", "/admin/secret", 6, ROUTE_PROTECTED);
    return r;
}

fn test_csprng_api() {
    var empty: u8[0] = [];
    let empty_ok = core::csprng_fill(empty[..]);

    var b1: u8[32] = [0; 32];
    var b2: u8[32] = [0; 32];
    let ok1 = core::csprng_fill(b1[..]);
    let ok2 = core::csprng_fill(b2[..]);
    var nz1: i64 = 0;
    var nz2: i64 = 0;
    for b in b1 { if b != 0 { nz1 += 1; } }
    for b in b2 { if b != 0 { nz2 += 1; } }

    let u1, oku1 = core::csprng_u64();
    let u2, oku2 = core::csprng_u64();
    print(
        "csprng: empty=", empty_ok,
        " fill=", ok1 && ok2 && nz1 > 0 && nz2 > 0 && b1[..] != b2[..],
        " u64=", oku1 && oku2 && u1 != u2,
    );
}

fn test_routing_query_and_middleware() {
    let router = build_test_router();
    var stage = h1::chain_stages(AuthGateStage { .. }, TraceHeaderStage { .. });
    var handler = AppHandler { .. };
    var out: u8[..4096] = [];

    // 1. Static precedence over earlier-registered :id param
    let r_me = "GET /users/me HTTP/1.1\r\nHost: local\r\nX-Trace: t-me\r\n\r\n";
    let h1_n, c1, ok1, cl1 = h1::serve_wire_pipelined(router, r_me, stage, handler, out);
    let p1, _, s1 = h1::parse_response_view(out[..], false);
    let me_ok = ok1 && !cl1 && h1_n == 1 && c1 == r_me.len &&
        s1 == h1::ParseStatus.Complete && p1.status_code == 200 &&
        p1.body == "static-me" &&
        h1::header(p1, "x-pipeline") == "vulkan-h1" &&
        h1::header(p1, "x-trace-echo") == "t-me";

    // 2. Canonicalized path + param extraction + percent-decoded query params
    let r_user = "GET /api/../users//42?role=admin+ops&flag&empty= HTTP/1.1\r\nHost: local\r\n\r\n";
    let _, _, ok2, _ = h1::serve_wire_pipelined(router, r_user, stage, handler, out);
    let p2, _, s2 = h1::parse_response_view(out[..], false);
    let req_q, _, sq = h1::parse_request_view(r_user);
    var flag_buf: u8[..16] = [];
    let q_flag = h1::query_param(req_q, "flag", flag_buf);
    let q_miss = h1::query_param(req_q, "nope", flag_buf);
    let user_ok = ok2 && s2 == h1::ParseStatus.Complete && sq == h1::ParseStatus.Complete &&
        p2.body == "user=42 role=admin ops" &&
        q_flag == h1::QueryMatch.Valueless &&
        q_miss == h1::QueryMatch.Missing;

    // 3. Wildcard catch-all + HEAD->GET automatic fallback + 405 Method Not Allowed + 404
    let r_wild = "GET /files/a/b/c.txt HTTP/1.1\r\nHost: local\r\n\r\n";
    let _, _, ok3, _ = h1::serve_wire_pipelined(router, r_wild, stage, handler, out);
    let p3, _, _ = h1::parse_response_view(out[..], false);
    let wild_ok = ok3 && p3.status_code == 200 && p3.body == "a/b/c.txt";

    let r_head = "HEAD /health HTTP/1.1\r\nHost: local\r\n\r\n";
    let _, _, ok_hd, _ = h1::serve_wire_pipelined(router, r_head, stage, handler, out);
    let p_hd, hd_len, s_hd = h1::parse_response_view(out[..], true);
    let head_ok = ok_hd && s_hd == h1::ParseStatus.Complete && p_hd.status_code == 200 &&
        p_hd.body.len == 0 && hd_len == out.len && h1::header(p_hd, "content-length") == "11";

    let r_405 = "DELETE /health HTTP/1.1\r\nHost: local\r\n\r\n";
    let _, _, ok_405, _ = h1::serve_wire_pipelined(router, r_405, stage, handler, out);
    let p_405, _, _ = h1::parse_response_view(out[..], false);
    let mna_ok = ok_405 && p_405.status_code == 405 && h1::header(p_405, "allow") == "GET";

    let r_404 = "GET /unknown HTTP/1.1\r\nHost: local\r\n\r\n";
    let _, _, ok_404, _ = h1::serve_wire_pipelined(router, r_404, stage, handler, out);
    let p_404, _, _ = h1::parse_response_view(out[..], false);
    let nf_ok = ok_404 && p_404.status_code == 404;

    // 4. Middleware short-circuit (401) + allowed with valid token + Abort verdict
    let r_denied = "GET /admin/secret HTTP/1.1\r\nHost: local\r\n\r\n";
    let calls_before = handler.calls;
    let _, _, ok_den, _ = h1::serve_wire_pipelined(router, r_denied, stage, handler, out);
    let p_den, _, _ = h1::parse_response_view(out[..], false);
    let den_ok = ok_den && p_den.status_code == 401 && handler.calls == calls_before &&
        stage.first.blocked_count == 1 && h1::header(p_den, "x-pipeline") == "vulkan-h1";

    let r_allow = "GET /admin/secret HTTP/1.1\r\nHost: local\r\nX-Api-Token: secret-42\r\n\r\n";
    let _, _, ok_alw, _ = h1::serve_wire_pipelined(router, r_allow, stage, handler, out);
    let p_alw, _, _ = h1::parse_response_view(out[..], false);
    let alw_ok = ok_alw && p_alw.status_code == 200 && p_alw.body == "secret-ok";

    let r_abort = "GET /health HTTP/1.1\r\nHost: local\r\nX-Kill-Conn: 1\r\n\r\n";
    let _, _, ok_ab, close_ab = h1::serve_wire_pipelined(router, r_abort, stage, handler, out);
    let abort_ok = !ok_ab && close_ab && out.len == 0;

    print(
        "routing: me=", me_ok, " user=", user_ok, " wild=", wild_ok,
        " head=", head_ok, " mna=", mna_ok, " nf=", nf_ok,
        " mw=", den_ok && alw_ok && abort_ok,
    );
}

fn test_pipelining_chunked_and_smuggling() {
    let router = build_test_router();
    var noop = h1::NoOpStage {};
    var handler = AppHandler { .. };

    // 1. Keep-alive 3x pipelining over MemoryStream -> RingBuffer -> Http1 -> Router
    var ms = h1::MemoryStream { .. };
    var burst: u8[..256] = [];
    burst.append("GET /health HTTP/1.1\r\nHost: local\r\n\r\n");
    burst.append("POST /echo HTTP/1.1\r\nHost: local\r\nContent-Length: 5\r\n\r\nhello");
    burst.append("GET /users/me HTTP/1.1\r\nHost: local\r\nConnection: close\r\n\r\n");
    let fed = h1::feed_input(ms, burst[..]);
    let served = h1::serve_stream(ms, router, noop, handler, 100);
    var rx: u8[4096] = [0; 4096];
    let out_len = h1::drain_output(ms, rx[..]);
    let resp_slice = rx[..out_len];

    let r1, n1, s1 = h1::parse_response_view(resp_slice, false);
    let r2, n2, s2 = h1::parse_response_view(resp_slice[n1..], false);
    let r3, n3, s3 = h1::parse_response_view(resp_slice[(n1 + n2)..], false);
    let pipe_ok = fed && served == 3 &&
        s1 == h1::ParseStatus.Complete && r1.body == "{\"ok\":true}" &&
        s2 == h1::ParseStatus.Complete && r2.body == "hello" &&
        s3 == h1::ParseStatus.Complete && r3.body == "static-me" &&
        (n1 + n2 + n3) == out_len;

    // 2. Fragmented request across two RingBuffer writes + chunked body decode
    var ring = core::RingBuffer { .. };
    var out: u8[..4096] = [];
    let _, _ = core::write(ring, "POST /echo HTTP/1.1\r\nHost: local\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhel");
    let h_part, ok_part, _ = h1::serve_ring_pipelined(router, ring, noop, handler, out);
    let _, _ = core::write(ring, "lo\r\n6;ext=1\r\n world\r\n0\r\n\r\n");
    let h_full, ok_full, _ = h1::serve_ring_pipelined(router, ring, noop, handler, out);
    let pc, _, sc = h1::parse_response_view(out[..], false);
    var dec_buf: u8[..64] = [];
    let dec_n, dec_st = h1::decode_chunked_body(pc.body, dec_buf);
    let chunk_ok = h_part == 0 && ok_part && h_full == 1 && ok_full &&
        sc == h1::ParseStatus.Complete && dec_st == h1::ParseStatus.Complete &&
        dec_n == pc.body.len && dec_buf[..] == "hello world";

    // 3. RFC 9112 smuggling & invalid wire rejections + overflow rollback
    let smuggle_te_cl = "POST /echo HTTP/1.1\r\nHost: local\r\nTransfer-Encoding: chunked\r\nContent-Length: 5\r\n\r\n0\r\n\r\n";
    let _, _, ok_smug, close_smug = h1::serve_wire_pipelined(router, smuggle_te_cl, noop, handler, out);
    let p_smug, _, _ = h1::parse_response_view(out[..], false);

    let dup_host = "GET /health HTTP/1.1\r\nHost: a\r\nHost: b\r\n\r\n";
    let _, _, st_dup = h1::parse_request_view(dup_host);
    let no_host = "GET /health HTTP/1.1\r\n\r\n";
    let _, _, st_noh = h1::parse_request_view(no_host);
    let bare_lf = "GET /health HTTP/1.1\nHost: a\r\n\r\n";
    let _, _, st_lf = h1::parse_request_view(bare_lf);

    var tiny_out: u8[..8] = "keep";
    let ovf_enc = h1::encode_client_request("GET", "/health", "local", "", "", tiny_out);
    let rb_ok = !ovf_enc && tiny_out[..] == "keep";

    let sec_ok = !ok_smug && close_smug && p_smug.status_code == 400 &&
        st_dup == h1::ParseStatus.BadRequest &&
        st_noh == h1::ParseStatus.BadRequest &&
        st_lf == h1::ParseStatus.BadRequest &&
        rb_ok;

    print("wire: pipe=", pipe_ok, " chunk=", chunk_ok, " sec=", sec_ok);
}

fn test_live_loopback_tcp_and_client() {
    let router = build_test_router();
    var stage = h1::chain_stages(AuthGateStage { .. }, TraceHeaderStage { .. });
    var handler = AppHandler { .. };

    var lis, ok_lis = h1::tcp_listen("127.0.0.1", 0, 16);
    guard ok_lis && lis.port > 0 else {
        print("tcp: listen_failed=true");
        return;
    }
    defer h1::close(lis);

    // 1. Live loopback pipelined keep-alive + Connection: close via serve_tcp_listener
    var cli1, ok_c1 = h1::tcp_connect("127.0.0.1", lis.port, 2000);
    guard ok_c1 else {
        print("tcp: connect1_failed=true");
        return;
    }
    defer h1::close(cli1);

    var req_wire: u8[..1024] = [];
    let e1 = h1::encode_client_request("GET", "/health", "127.0.0.1", "X-Trace: tcp1\r\n", "", req_wire);
    let e2 = h1::encode_client_request(
        "GET", "/users/99?role=sre", "127.0.0.1", "Connection: close\r\n", "", req_wire,
    );
    let sent1 = h1::send_all(cli1, req_wire[..]);

    let served_tcp = h1::serve_tcp_listener(lis, router, stage, handler, 1, 2000);

    var tcp_rx: u8[..4096] = [];
    var chunk:  u8[1024]   = [0; 1024];
    loop {
        let got = h1::recv_slice(cli1, chunk[..], 2000);
        if got <= 0 { break; }
        tcp_rx.append(chunk[..got]);
    }
    let tr1, tn1, ts1 = h1::parse_response_view(tcp_rx[..], false);
    let tr2, tn2, ts2 = h1::parse_response_view(tcp_rx[tn1..], false);
    let tcp1_ok = e1 && e2 && sent1 && served_tcp == 2 &&
        ts1 == h1::ParseStatus.Complete && tr1.status_code == 200 &&
        tr1.body == "{\"ok\":true}" && h1::header(tr1, "x-trace-echo") == "tcp1" &&
        ts2 == h1::ParseStatus.Complete && tr2.status_code == 200 &&
        tr2.body == "user=99 role=sre" && (tn1 + tn2) == tcp_rx.len;

    // 2. Live loopback zero-copy vectored response (`send_response_vectored`) + `exchange_stream`
    var cli2, ok_c2 = h1::tcp_connect("127.0.0.1", lis.port, 2000);
    guard ok_c2 else {
        print("tcp: connect2_failed=true");
        return;
    }
    defer h1::close(cli2);

    var srv2, ok_s2 = h1::accept(lis, 2000);
    guard ok_s2 else {
        print("tcp: accept2_failed=true");
        return;
    }
    defer h1::close(srv2);

    var vres = h1::ResponseView { .. };
    h1::set_json_view(vres, 200, "{\"vectored\":true}");
    vres.close_conn = true;
    let vec_sent = h1::send_response_vectored(srv2, vres, false);

    var rx_buf: u8[..2048] = [];
    let cres, ok_ex = h1::exchange_stream(
        cli2, "GET", "/health", "127.0.0.1", "Connection: close\r\n", "", rx_buf, 2000,
    );
    let tcp2_ok = vec_sent && ok_ex && cres.status_code == 200 && cres.body == "{\"vectored\":true}";

    print("tcp: pipe2=", tcp1_ok, " vectored=", tcp2_ok);
}

fn test_bb_f02_chunked_strict() {
    var cur: i64 = 0;
    let _, _, st_0x = h1::parse_next_chunk_span("0x5\r\nhello\r\n", cur);
    let _, _, st_sp = h1::parse_next_chunk_span(" 5\r\nhello\r\n", cur);
    let _, _, st_nul = h1::parse_next_chunk_span("5;a\x00b\r\nhello\r\n", cur);
    let _, _, st_cr = h1::parse_next_chunk_span("5;a\rb\r\nhello\r\n", cur);
    let _, _, st_lf = h1::parse_next_chunk_span("5\r\nhello\n", cur);
    let ok = st_0x == h1::ParseStatus.BadRequest &&
        st_sp == h1::ParseStatus.BadRequest &&
        st_nul == h1::ParseStatus.BadRequest &&
        st_cr == h1::ParseStatus.BadRequest &&
        st_lf == h1::ParseStatus.BadRequest;
    print("chunk_strict: ", ok);
}

fn main() {
    test_csprng_api();
    test_routing_query_and_middleware();
    test_pipelining_chunked_and_smuggling();
    test_live_loopback_tcp_and_client();
    test_bb_f02_chunked_strict();
}

// CHECK: csprng: empty=false fill=true u64=true
// CHECK-NEXT: routing: me=true user=true wild=true head=true mna=true nf=true mw=true
// CHECK-NEXT: wire: pipe=true chunk=true sec=true
// CHECK-NEXT: tcp: pipe2=true vectored=true
// CHECK-NEXT: chunk_strict: true
