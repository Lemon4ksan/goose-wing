// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// tests/lit/verify_module_seams_regress.goose
// Regression test suite for cross-module integration seams (H2/H3 client/server bridges,
// pipeline stage ordering, TLS SNI routing, and TLS X.509 SAN connection coalescing).
//
// RUN: goose build -O2 -o %t.exe %s
// RUN: %t.exe | %FileCheck %s

import std;
import core from "../..";
import wing from "../..";

var g_seam_server:  wing::HttpServer       = wing::new_http_server("goose-wing/1.0");
var g_seam_session: wing::Session          = wing::new_session();
var g_seam_pool:    wing::StreamPool       = wing::StreamPool { .. };
var g_cli_h3:       internal::H3Connection = internal::H3Connection { .. };
var g_srv_h3_1:     internal::H3Connection = internal::H3Connection { .. };
var g_srv_h3_2:     internal::H3Connection = internal::H3Connection { .. };

// 1. Bug 1 & Bug 2: Client HTTP/2 multi-frame / multi-read response drain + trailing HEADERS (gRPC)
fn test_client_h2_trailers_and_incremental_drain() {
    var enc_dt = internal::new_dynamic_table(4096);
    var dec_dt = internal::new_dynamic_table(4096);

    // Build initial response HEADERS (:status = 200, content-type = application/grpc) without END_STREAM
    var init_pseudo = internal::H2PseudoHeaders { has_status: true, status: 200, .. };
    var init_hdrs = wing::HeaderMap { .. };
    wing::append_header(init_hdrs, "content-type", "application/grpc");

    var chunk1: u8[..1024] = [];
    assert(wire::encode_h2_headers_frame_from_map(enc_dt, 1, init_pseudo, init_hdrs, false, chunk1, 16384));

    // Build DATA frame (without END_STREAM) + Trailing HEADERS frame (grpc-status: 0, END_STREAM = true)
    var chunk2: u8[..1024] = [];
    assert(wire::encode_data_frame(1, "GRPC_PAYLOAD", false, chunk2));

    var trail_pseudo = internal::H2PseudoHeaders { is_trailer: true, .. };
    var trail_hdrs = wing::HeaderMap { .. };
    wing::append_header(trail_hdrs, "grpc-status", "0");
    wing::append_header(trail_hdrs, "grpc-message", "OK");
    assert(wire::encode_h2_headers_frame_from_map(enc_dt, 1, trail_pseudo, trail_hdrs, true, chunk2, 16384));

    // Feed chunk1 then chunk2 into rx_accum (simulating 2 socket reads in recv_h2_response_loop)
    var rx_accum: u8[..4096] = [];
    var resp = wing::Response { .. };
    var got_hdrs = false;
    var ctrl_out: u8[..256] = [];

    rx_accum.append(chunk1[..]);
    let ok1, done1 = wing::drain_h2_response_frames(rx_accum, 1, false, dec_dt, resp, got_hdrs, ctrl_out);
    assert(ok1 && !done1 && got_hdrs);
    assert(rx_accum.len == 0); // Must drain consumed frame bytes so read 2 does not re-decode chunk1!

    rx_accum.append(chunk2[..]);
    let ok2, done2 = wing::drain_h2_response_frames(rx_accum, 1, false, dec_dt, resp, got_hdrs, ctrl_out);
    assert(ok2 && done2);
    assert(resp.status_code == 200);
    assert(wing::header(resp, "content-type") == "application/grpc");
    assert(resp.body[..] == "GRPC_PAYLOAD");
    assert(wing::trailer(resp, "grpc-status") == "0");
    assert(wing::trailer(resp, "grpc-message") == "OK");
    print("SEAM_H2_CLIENT_TRAILERS_DRAIN: OK");
}

// 2. Bug 3 & Bug 4: Client HTTP/3 request query string preservation + Server HTTP/3 trailers roundtrip
fn test_h3_query_and_trailers_seam() {
    assert(wing::add_static_route(g_seam_server.pipeline.router, "POST", "/grpc.Echo/Call", "application/grpc", "H3_GRPC_BODY", 77));

    // Client builds HTTP/3 request for URL with query string "?trace=99&mode=fast"
    let u = core::new_url("https://example.com/grpc.Echo/Call?trace=99&mode=fast");
    var ctx = wing::RequestExecutionContext { .. };
    ctx.current_method.append("POST");
    ctx.body.append("REQ_DATA");
    wing::append_header(ctx.headers, "te", "trailers");

    let h3_settings = wing::H3Settings { .. };
    g_cli_h3 = internal::new_h3_client_connection(h3_settings);
    let sid, ok_s = internal::open_request_stream(g_cli_h3);
    assert(ok_s && sid == 0);

    var req_wire: u8[..4096] = [];
    assert(wing::encode_h3_client_request(g_cli_h3, sid, ctx, u, req_wire));

    g_srv_h3_1 = internal::new_h3_server_connection(h3_settings);
    var tx_wire: u8[..4096] = [];
    assert(wing::handle_h3_server_datagram(g_seam_server, g_srv_h3_1, sid, "127.0.0.1", req_wire[..], 1000, tx_wire));

    // Verify server received the full :path including "?trace=99&mode=fast"
    assert(g_srv_h3_1.streams[0].req_path[..] == "/grpc.Echo/Call?trace=99&mode=fast");

    // Verify server HTTP/3 response encoder emits trailing HEADERS when trailers are present
    var srv_trailers = wing::HeaderMap { .. };
    wing::append_header(srv_trailers, "grpc-status", "0");
    var tx_with_trailers: u8[..4096] = [];
    g_srv_h3_2 = internal::new_h3_server_connection(h3_settings);
    assert(internal::handle_stream_data(g_srv_h3_2, sid, true, req_wire[..], true) == rfc::H3_ERR_NO_ERROR);
    var extra_hdrs = wing::HeaderMap { .. };
    wing::append_header(extra_hdrs, "content-type", "application/grpc");
    assert(internal::send_response_headers_body_and_trailers(
        g_srv_h3_2, sid, 200, extra_hdrs, "H3_GRPC_BODY", srv_trailers, tx_with_trailers,
    ));

    let h_err = internal::handle_stream_data(g_cli_h3, sid, true, tx_with_trailers[..], true);
    assert(h_err == rfc::H3_ERR_NO_ERROR);
    var cli_trailers = wing::HeaderMap { .. };
    assert(internal::copy_stream_trailers(g_cli_h3, sid, cli_trailers));
    assert(wing::get_header(cli_trailers, "grpc-status") == "0");
    print("SEAM_H3_QUERY_AND_TRAILERS: OK");
}

// 3. Bug 5: Client WirePipeline.egress_stages custom ordering
fn test_client_egress_pipeline_custom_order() {
    // Configure egress_stages with only REDIRECT (omitting COOKIE_STORE)
    g_seam_session.wire_pipeline.egress_stages.clear();
    g_seam_session.wire_pipeline.egress_stages.push(wire::STAGE_ID_CLI_OUT_REDIRECT);

    wing::mock_route(g_seam_session, "GET", "https://example.com/start", 302, "");
    wing::add_mock_header(g_seam_session, "Location", "https://example.com/final");
    wing::add_mock_set_cookie(g_seam_session, "skipped_cookie=1; Path=/");
    wing::mock_route(g_seam_session, "GET", "https://example.com/final", 200, "done");

    var req = wing::new_get("https://example.com/start");
    let resp, err = wing::execute_request(g_seam_session, req);
    assert(wing::ok(err) && resp.status_code == 200);
    // Because STAGE_ID_CLI_OUT_COOKIE_STORE was omitted from egress_stages, cookie must not be stored
    assert(wing::get(g_seam_session.jar, "skipped_cookie") == "");
    print("SEAM_CLIENT_EGRESS_STAGES_ORDER: OK");
}

// 4. Bug 6: Server TLS ClientHello SNI extraction & SniRegistry wiring
fn test_server_tls_sni_extraction() {
    let client_random: u8[32] = [0x11; 32];
    let client_pub:    u8[32] = [0x22; 32];
    var ch_payload: u8[..2048] = [];
    wing::build_tls13_client_hello_payload(
        client_random, client_pub, "Api.Example.COM", "h2,http/1.1", ch_payload,
    );
    var ch_msg: u8[..2048] = [];
    ch_msg.push(rfc::TLS_HS_CLIENT_HELLO);
    core::append_u24_be(ch_msg, ch_payload.len as u32);
    ch_msg.append(ch_payload[..]);

    var sid:         u8[..32]  = [];
    var out_pub:     u8[32]    = [0; 32];
    var out_alpn:    u8[..32]  = [];
    var out_sni:     u8[..255] = [];
    var psk_resumed: bool      = false;
    var psk_secret:  u8[32]    = [0; 32];

    assert(wing::parse_client_hello_for_server_sni(
        ch_msg[..], "h2,http/1.1", sid, out_pub, out_alpn, out_sni, psk_resumed, psk_secret,
    ));
    assert(out_alpn[..] == "h2");
    assert(out_sni[..] == "api.example.com");
    print("SEAM_TLS_SERVER_SNI: OK");
}

// 5. Bug 7: Client TLS X.509 SAN extraction -> PooledConnection HTTP/2 IP coalescing
fn test_tls_san_to_pool_coalescing() {
    let seed: u8[32] = [0x42; 32];
    var cert_der: u8[..2048] = [];
    assert(wing::build_test_ed25519_cert_der(seed, "example.com", "*.example.com", "93.184.216.34", cert_der));

    let slot_idx = wing::alloc_tls_cipher_slot();
    assert(slot_idx != 0xFFFF);
    assert(wing::tls_populate_slot_san_hosts_from_der(slot_idx, cert_der[..]));

    let direct_proxy = wing::new_direct_proxy_chain();
    let nak = wing::NetworkAnonymizationKey { .. };
    let pol = wing::TlsAndDnsPolicy { .. };
    var key_a = wing::new_pool_key(wing::PoolScheme.Https, "a.example.com", 443, direct_proxy, nak, pol);
    var key_b = wing::new_pool_key(wing::PoolScheme.Https, "b.example.com", 443, direct_proxy, nak, pol);
    let tp = wing::Transport.Tls { fd: 99, record_seq_rx: 0, record_seq_tx: 0, cipher_slot: slot_idx };

    let cid = wing::register_connection(g_seam_pool, key_a, wing::NegotiatedProtocol.Http2, tp, "93.184.216.34", 100, 1000);
    assert(cid > 0);
    let coalesced_id, ok_coal = wing::acquire_pooled_connection(g_seam_pool, key_b, "93.184.216.34", 1001);
    assert(ok_coal && coalesced_id == cid);

    wing::free_tls_cipher_slot(slot_idx);
    print("SEAM_TLS_SAN_POOL_COALESCING: OK");
}

struct TestCustomEchoStage {
    active: bool = true,
}

fn wing::on_server_stage(
    _stage: TestCustomEchoStage&,
    phase:  wire::ServerHookPhase,
    _cfg:   wing::ServerPipelineConfig&,
    req:    const wing::Request&,
    _ctx:   wing::ServerStageCtx&,
    res:    wing::Response&,
) -> wire::StageVerdict {
    if phase == wire::ServerHookPhase.PostAuth && req.url[..] == "/echo" {
        res.status_code = 200;
        wing::set_header(res, "Content-Type", "text/plain");
        res.body.clear();
        res.body.append("ECHO:");
        res.body.append(req.body[..]);
        return wire::StageVerdict.ShortCircuit { status_code: 200 };
    }
    return wire::StageVerdict.Continue;
}

// 6. Bug 8: Server custom <UserStage> hook phase and ShortCircuit verdict integration
fn test_server_custom_stage_hook_seam() {
    wing::add_post_route(g_seam_server, "/echo", 202);
    var req = wing::new_request("POST", "/echo");
    wing::append_header(req.headers, "Host", "example.com");
    wing::append_header(req.headers, "Sec-Fetch-Site", "same-origin");
    req.body.append("payload42");

    var res = wing::Response { .. };
    var echo_stage = TestCustomEchoStage { .. };
    let outcome = wing::dispatch_server_request_with_stage(g_seam_server, "127.0.0.1", req, 2000, res, echo_stage);
    assert(outcome == wing::PipelineOutcome.Handled);
    assert(res.status_code == 200);
    assert(res.body[..] == "ECHO:payload42");
    print("SEAM_SERVER_CUSTOM_STAGE_HOOK: OK");
}

var g_h2_srv_sess = internal::new_h2_server_session("goose-wing/1.0", 1000);

fn test_h2_server_flow_window_and_closed_stream_seams() {
    wing::add_static_get_route(g_seam_server, "/ping", "text/plain", "PONG", 77);
    var client_dt = internal::new_dynamic_table(rfc::HPACK_DEFAULT_MAX_DYN_SIZE);

    var wire1: u8[..256] = [];
    wire1.append(rfc::H2_CLIENT_PREFACE[..]);
    // SETTINGS: INITIAL_WINDOW_SIZE (0x04) = 0
    let set_hdr = internal::FrameHeader { length: 6, frame_type: rfc::H2_FRAME_SETTINGS, flags: 0, stream_id: 0 };
    internal::encode_frame_header_to(set_hdr, wire1);
    core::append_u16_be(wire1, rfc::H2_SETTING_INITIAL_WINDOW_SIZE);
    core::append_u32_be(wire1, 0);

    var req_hblock: u8[..128] = [];
    internal::encode_hpack_field(client_dt, req_hblock, ":method", "GET", internal::HpackIndexing.Incremental, false);
    internal::encode_hpack_field(client_dt, req_hblock, ":scheme", "http", internal::HpackIndexing.Incremental, false);
    internal::encode_hpack_field(client_dt, req_hblock, ":path", "/ping", internal::HpackIndexing.Incremental, false);
    internal::encode_hpack_field(client_dt, req_hblock, ":authority", "localhost", internal::HpackIndexing.Incremental, false);
    let h_hdr = internal::FrameHeader {
        length:     req_hblock.len as u32,
        frame_type: rfc::H2_FRAME_HEADERS,
        flags:      rfc::H2_FLAG_END_HEADERS | rfc::H2_FLAG_END_STREAM,
        stream_id:  5,
    };
    internal::encode_frame_header_to(h_hdr, wire1);
    wire1.append(req_hblock[..]);

    var out1: u8[..1024] = [];
    let _, ok1 = internal::handle_h2_server_ingress(g_h2_srv_sess, g_seam_server.pipeline, g_seam_server.timer, "127.0.0.1", wire1[..], 1000, out1);
    assert(ok1);
    assert(g_h2_srv_sess.conn.active_stream_count == 1);

    // Grant 4 bytes via WINDOW_UPDATE on stream 5
    var wire2: u8[..64] = [];
    internal::emit_window_update(5, 4, wire2);
    var out2: u8[..1024] = [];
    let _, ok2 = internal::handle_h2_server_ingress(g_h2_srv_sess, g_seam_server.pipeline, g_seam_server.timer, "127.0.0.1", wire2[..], 1010, out2);
    assert(ok2);
    assert(out2.len == 13 && out2[3] == rfc::H2_FRAME_DATA && (out2[4] & rfc::H2_FLAG_END_STREAM) != 0);
    assert(g_h2_srv_sess.conn.active_stream_count == 0);

    // Sending smaller stream ID (3 < 5) that was implicitly closed by opening stream 5 (RFC 9113 §5.1.1) returns STREAM_CLOSED
    let small_hdr = internal::FrameHeader {
        length:     req_hblock.len as u32,
        frame_type: rfc::H2_FRAME_HEADERS,
        flags:      rfc::H2_FLAG_END_HEADERS | rfc::H2_FLAG_END_STREAM,
        stream_id:  3,
    };
    let err_small = internal::on_ingress_frame_header(g_h2_srv_sess.conn, small_hdr, 1020);
    assert(err_small == rfc::H2_ERR_STREAM_CLOSED);
    print("SEAM_H2_FLOW_AND_CLOSED_STREAMS: OK");
}

// Seam 8: HTTP/2 client `recv_h2_response_loop` must continue reading across >16 sliced chunks
// until END_STREAM (`done == true`) rather than truncating after 16 reads or returning after HEADERS-only.
fn test_h2_client_sliced_stream_recv_seam() {
    let cli_fd = wing::udp_bind("127.0.0.1", 0);
    let srv_fd = wing::udp_bind("127.0.0.1", 0);
    assert(cli_fd > 0 && srv_fd > 0);
    let cli_port = wing::tcp_getsockname_port(cli_fd);

    var srv_enc = internal::new_dynamic_table(rfc::HPACK_DEFAULT_MAX_DYN_SIZE);
    var hblock: u8[..128] = [];
    internal::encode_hpack_field(srv_enc, hblock, ":status", "200", internal::HpackIndexing.Incremental, false);

    var wire: u8[..256] = [];
    let h_hdr = internal::FrameHeader {
        length:     hblock.len as u32,
        frame_type: rfc::H2_FRAME_HEADERS,
        flags:      rfc::H2_FLAG_END_HEADERS,
        stream_id:  1,
    };
    internal::encode_frame_header_to(h_hdr, wire);
    wire.append(hblock[..]);

    let body_msg = "SLICED_H2_BODY_PAYLOAD_24_CHUNKS_OK";
    let d_hdr = internal::FrameHeader {
        length:     body_msg.len as u32,
        frame_type: rfc::H2_FRAME_DATA,
        flags:      rfc::H2_FLAG_END_STREAM,
        stream_id:  1,
    };
    internal::encode_frame_header_to(d_hdr, wire);
    wire.append(body_msg);

    // Send 1 byte per datagram (> 50 datagrams total, exceeding the old 16-step cap)
    for i in wire.len {
        let _ = wing::native_udp_sendto(srv_fd, wire[i..i + 1], "127.0.0.1", cli_port);
    }

    var tp: wing::Transport = wing::Transport.Udp { fd: cli_fd, peer_ip4: 0x7F000001, peer_port: 9999 };
    var cli_dec = internal::new_dynamic_table(rfc::HPACK_DEFAULT_MAX_DYN_SIZE);
    var resp = wing::Response { .. };
    let ok_h2 = wing::recv_h2_response_loop(tp, 1, false, cli_dec, 200, resp);
    wing::tcp_close(cli_fd);
    wing::tcp_close(srv_fd);

    assert(ok_h2);
    assert(resp.status_code == 200);
    assert(resp.body[..] == body_msg);
    print("SEAM_H2_CLIENT_SLICED_STREAM: OK");
}

// Seam 10 & 11: HTTP/1.1 client `parse_response_headers` must preserve the final header line
// when `conn.rx_buf[..hdr_end_idx]` is sliced at `\r\n\r\n`, and `dispatch_pooled_h1_hop`
// must clear `Request.method` default `"GET"` before setting `curr_method` (not emit `"GETHEAD"`).
fn test_h1_client_last_response_header_preserved_seam() {
    let raw_rx = "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nSet-Cookie: a=1\r\nConnection: close\r\n\r\nOK";
    let hdr_end_idx = core::fast_find_crlfcrlf(raw_rx);
    assert(hdr_end_idx > 0);
    var resp = wing::Response { .. };
    assert(wing::parse_response_headers(raw_rx[..hdr_end_idx], resp));
    assert(resp.status_code == 200);
    assert(resp.header("Content-Type") == "text/plain");
    assert(resp.header("Set-Cookie") == "a=1");
    assert(resp.header("Connection") == "close");

    let lfd = wing::tcp_listen("127.0.0.1", 0);
    assert(lfd > 0);
    let srv_port = wing::tcp_getsockname_port(lfd);
    let cli_fd = wing::tcp_connect("127.0.0.1", srv_port, 200);
    let srv_fd = wing::tcp_accept(lfd, 200);
    assert(cli_fd > 0 && srv_fd > 0);
    let head_resp = "HTTP/1.1 200 OK\r\nContent-Length: 500\r\nConnection: close\r\n\r\n";
    let _ = wing::tcp_send(srv_fd, head_resp);

    g_seam_session.timeout_ms = 200;
    let pkey = wing::new_pool_key(
        wing::PoolScheme.Http, "127.0.0.1", srv_port,
        wing::new_direct_proxy_chain(),
        wing::new_network_anonymization_key("127.0.0.1", false),
        wing::TlsAndDnsPolicy { .. },
    );
    let tp: wing::Transport = wing::Transport.Tcp { fd: cli_fd };
    let cid = wing::register_connection(g_seam_session.pool, pkey, wing::NegotiatedProtocol.Http11, tp, "127.0.0.1", 1, 1000);
    var ctx = wing::RequestExecutionContext { .. };
    let u = core::new_url("http://127.0.0.1/head-check");
    var hop_resp = wing::Response { .. };
    let ok_hop = wing::dispatch_pooled_h1_hop(g_seam_session, cid, "HEAD", ctx, u, false, "http://127.0.0.1", "/head-check", 1, 1000, hop_resp);
    var wire_req: u8[..512] = [];
    let n_req = wing::tcp_recv(srv_fd, wire_req, 512, 100);
    wing::tcp_close(srv_fd);
    wing::tcp_close(lfd);

    assert(ok_hop);
    assert(n_req >= 16);
    assert(core::starts_with(wire_req[..n_req], "HEAD /head-check HTTP/1.1\r\n"));
    print("SEAM_H1_LAST_RESPONSE_HEADER: OK");
}

fn seam_grpc_echo_handler(
    route_tag: u16,
    ctx:       wing::GrpcServerContext&,
    payload:   const u8[:],
    out_body:  u8[>..]&,
) -> wing::GrpcStatus {
    let _ = route_tag;
    let _ = ctx;
    out_body.append(payload);
    return wing::grpc_ok();
}

// Seam 12, 13 & 14:
// - `build_tls13_client_hello_payload` with IP literal ("127.0.0.1") must NOT emit illegal
//   RFC 6066 SNI HostName extension that `parse_client_hello_for_server_sni` rejects.
// - `emit_grpc_h2_response_frames` must split payloads > 16384 bytes across multiple DATA frames.
// - `handle_grpc_h2_wire_frame` must wait for `H2_FLAG_END_STREAM` across multi-DATA frames.
fn test_grpc_h2_large_multiframe_and_sni_ip_seam() {
    let rnd:   u8[32] = [0x11; 32];
    let pub_k: u8[32] = [0x22; 32];
    var ch_body: u8[..512] = [];
    wing::build_tls13_client_hello_payload(rnd, pub_k, "127.0.0.1", "h2", ch_body);
    var ch_hs: u8[..520] = [];
    ch_hs.push(rfc::TLS_HS_CLIENT_HELLO);
    core::append_u24_be(ch_hs, ch_body.len as u32);
    ch_hs.append(ch_body[..]);
    var sid:         u8[..32]  = [];
    var out_pub:     u8[32]    = [0; 32];
    var out_alpn:    u8[..32]  = [];
    var out_sni:     u8[..255] = [];
    var psk_resumed: bool      = false;
    var psk_secret:  u8[32]    = [0; 32];
    assert(wing::parse_client_hello_for_server_sni(
        ch_hs[..], "h2,http/1.1", sid, out_pub, out_alpn, out_sni, psk_resumed, psk_secret,
    ));
    assert(out_sni.len == 0);

    var enc = internal::new_dynamic_table(rfc::HPACK_DEFAULT_MAX_DYN_SIZE);
    var big_res = wing::Response { status_code: 200, .. };
    let _ = wing::append_header(big_res.headers, "content-type", "application/grpc");
    let _ = wing::append_header(big_res.trailers, "grpc-status", "0");
    for i in 20000 {
        let _ = i;
        big_res.body.push('A');
    }
    var out_frames: u8[..32768] = [];
    wing::emit_grpc_h2_response_frames(enc, 1, big_res, out_frames);
    var pos:              i64 = 0;
    var data_frame_count: i64 = 0;
    while pos + 9 <= out_frames.len {
        let fhdr, _, ok_fh = wire::parse_frame_header(out_frames[pos..pos + 9]);
        assert(ok_fh);
        if fhdr.frame_type == rfc::H2_FRAME_DATA {
            data_frame_count++;
            assert(fhdr.length <= rfc::H2_DEFAULT_MAX_FRAME_SIZE);
        }
        pos += 9 + (fhdr.length as i64);
    }
    assert(data_frame_count == 2);

    var disp = wing::GrpcServerDispatcher { .. };
    let _ = wing::register_unary(disp, "test.Echo", "Unary", 1);
    var hdec = internal::new_dynamic_table(rfc::HPACK_DEFAULT_MAX_DYN_SIZE);
    var henc = internal::new_dynamic_table(rfc::HPACK_DEFAULT_MAX_DYN_SIZE);
    var pending = wing::Request { .. };
    let _ = pending.method.try_set("POST");
    let _ = pending.url.try_set("/test.Echo/Unary");
    let _ = wing::append_header(pending.headers, "content-type", "application/grpc");
    var wire_out: u8[..65536] = [];
    let hdr_part1 = wire::WireFrameHeader { length: 5, frame_type: rfc::H2_FRAME_DATA, flags: 0, stream_id: 1 };
    let lpm_prefix: u8[5] = [0, 0, 0, 0, 4];
    assert(wing::handle_grpc_h2_wire_frame(-1, g_seam_server, disp, "127.0.0.1", hdec, henc, pending, hdr_part1, lpm_prefix[..], wire_out, seam_grpc_echo_handler));
    assert(wire_out.len == 0);
    let hdr_part2 = wire::WireFrameHeader { length: 4, frame_type: rfc::H2_FRAME_DATA, flags: rfc::H2_FLAG_END_STREAM, stream_id: 1 };
    assert(wing::handle_grpc_h2_wire_frame(-1, g_seam_server, disp, "127.0.0.1", hdec, henc, pending, hdr_part2, "PING", wire_out, seam_grpc_echo_handler));
    assert(wire_out.len > 0);

    // Seam 18: `tls_send_encrypted_record` must allocate `payload.len + 22` bytes (5-byte header + 1-byte inner type + 16-byte tag)
    let lfd_tls = wing::tcp_listen("127.0.0.1", 0);
    assert(lfd_tls > 0);
    let tls_port = wing::tcp_getsockname_port(lfd_tls);
    let cfd_tls = wing::tcp_connect("127.0.0.1", tls_port, 200);
    let sfd_tls = wing::tcp_accept(lfd_tls, 200);
    assert(cfd_tls > 0 && sfd_tls > 0);
    let slot_t = wing::alloc_tls_cipher_slot();
    wing::g_tls_cipher_slots[slot_t as i64].cipher_suite = rfc::TLS_CIPHER_AES_128_GCM_SHA256;
    wing::g_tls_cipher_slots[slot_t as i64].key_len = 16;
    assert(wing::tls_send_encrypted_record(cfd_tls, slot_t, rfc::TLS_CONTENT_APPLICATION_DATA, "HELLO_TLS13"));
    wing::free_tls_cipher_slot(slot_t);
    wing::tcp_close(cfd_tls);
    wing::tcp_close(sfd_tls);
    wing::tcp_close(lfd_tls);
    print("SEAM_GRPC_H2_LARGE_AND_SNI_IP: OK");
}

// Seam 19, 20 & 21:
// - `run_client_preflight_stages` must pass canonical `parsed_initial.href` to `stage_client_cache_lookup`
//   so root URLs without trailing slash ("http://127.0.0.1:8080") match `stage_client_cache_store`.
// - `encode_h2_client_request` + `should_skip_h2_entry` + `H2ServerSession` must support RFC 8441
//   Extended CONNECT (`:protocol = websocket`) without duplicating `:method`/`:protocol` after
//   pseudo-headers, and `H2ServerSession` must preserve `:protocol`, `:scheme`, `:path`, `:authority`
//   on `req.headers` for `validate_h2_websocket_handshake`.
fn test_proxy_cache_h2_extended_connect_seams() {
    g_seam_session = wing::Client { .. };
    g_seam_session.virtual_clock_us = 0;
    g_seam_session.enable_cache = true;
    let parsed_root = core::new_url("http://127.0.0.1:18080");
    var req_root = wing::new_request("GET", "http://127.0.0.1:18080");
    var cached_resp = wing::Response { status_code: 200, .. };
    let _ = wing::append_header(cached_resp.headers, "Cache-Control", "max-age=60");
    let _ = wing::append_header(cached_resp.headers, "ETag", "\"v1\"");
    cached_resp.body.append("CACHED_ROOT_PAYLOAD");
    var ts = wing::CacheTimestamps { .. };
    let _ = wing::stage_client_cache_store(
        req_root, req_root.headers, parsed_root, "GET", cached_resp, ts, -1, g_seam_session.cache, g_seam_session.enable_cache,
    );

    let early_resp, early_err = wing::execute_request(g_seam_session, req_root);
    assert(wing::ok(early_err) && early_resp.status_code == 200);
    assert(early_resp.body[..] == "CACHED_ROOT_PAYLOAD");

    var ws_req = wing::Request { .. };
    wing::format_h2_websocket_request(ws_req, "/ws", "127.0.0.1:18080", "http", "chat");
    var ws_ctx = wing::RequestExecutionContext { .. };
    wing::copy_headers(ws_req.headers, ws_ctx.headers);
    let u_ws = core::new_url("http://127.0.0.1:18080/ws");
    var dt_cli = internal::new_dynamic_table(rfc::HPACK_DEFAULT_MAX_DYN_SIZE);
    var h2_wire: u8[..4096] = [];
    assert(wing::encode_h2_client_request("CONNECT", u_ws, false, ws_ctx, dt_cli, 1, false, h2_wire));

    var fhdr, _, ok_fh = wire::parse_frame_header(h2_wire[..9]);
    assert(ok_fh && fhdr.frame_type == rfc::H2_FRAME_HEADERS);
    var dt_srv = internal::new_dynamic_table(rfc::HPACK_DEFAULT_MAX_DYN_SIZE);
    var dec_pseudo = internal::H2PseudoHeaders { .. };
    var dec_map = wing::HeaderMap { .. };
    let dec_err = wire::decode_hpack_to_map(dt_srv, h2_wire[9..9 + (fhdr.length as i64)], dec_pseudo, dec_map);
    assert(dec_err == rfc::H2_ERR_NO_ERROR);
    assert(dec_pseudo.has_protocol && dec_pseudo.protocol[..] == "websocket");

    var st = internal::H2ServerStream { stream_id: 1, active: true, .. };
    assert(internal::apply_decoded_pseudo_to_stream(st, dec_pseudo));
    wing::append_all_headers(dec_map, st.headers);
    var srv_req = wing::new_request(st.method[..], st.path[..]);
    internal::copy_stream_headers_and_trailers(st, srv_req);
    assert(wing::validate_h2_websocket_request(srv_req));
    print("SEAM_PROXY_CACHE_H2_EXT_CONNECT: OK");
}

fn main() {
    test_client_h2_trailers_and_incremental_drain();
    test_h3_query_and_trailers_seam();
    test_client_egress_pipeline_custom_order();
    test_server_tls_sni_extraction();
    test_tls_san_to_pool_coalescing();
    test_server_custom_stage_hook_seam();
    test_h2_server_flow_window_and_closed_stream_seams();
    test_h2_client_sliced_stream_recv_seam();
    test_h1_client_last_response_header_preserved_seam();
    test_grpc_h2_large_multiframe_and_sni_ip_seam();
    test_proxy_cache_h2_extended_connect_seams();
}

// CHECK: SEAM_H2_CLIENT_TRAILERS_DRAIN: OK
// CHECK-NEXT: SEAM_H3_QUERY_AND_TRAILERS: OK
// CHECK-NEXT: SEAM_CLIENT_EGRESS_STAGES_ORDER: OK
// CHECK-NEXT: SEAM_TLS_SERVER_SNI: OK
// CHECK-NEXT: SEAM_TLS_SAN_POOL_COALESCING: OK
// CHECK-NEXT: SEAM_SERVER_CUSTOM_STAGE_HOOK: OK
// CHECK-NEXT: SEAM_H2_FLOW_AND_CLOSED_STREAMS: OK
// CHECK-NEXT: SEAM_H2_CLIENT_SLICED_STREAM: OK
// CHECK-NEXT: SEAM_H1_LAST_RESPONSE_HEADER: OK
// CHECK-NEXT: SEAM_GRPC_H2_LARGE_AND_SNI_IP: OK
// CHECK-NEXT: SEAM_PROXY_CACHE_H2_EXT_CONNECT: OK
