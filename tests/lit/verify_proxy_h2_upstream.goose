// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Verification suite for opt-in HTTP/2 upstream client/multiplexer (`proxy/h2_upstream.goose`):
// gRPC/Connect-RPC proxying, slow WAN fan-out, full-duplex bidi streaming, and RFC 9113 security.
//
// RUN: goose build -O2 -o %t.exe %s
// RUN: %t.exe | %FileCheck %s

import std;
import wing from "../..";

// ---- Wire Framing Test Helpers ---------------------------------------------

fn append_h2_frame(
    out:        u8[>..]&,
    frame_type: u8,
    flags:      u8,
    stream_id:  u32,
    payload:    const u8[:],
) {
    let hdr = wire::WireFrameHeader {
        length:     payload.len as u32,
        frame_type: frame_type,
        flags:      flags,
        stream_id:  stream_id,
    };
    assert(wire::encode_frame_header(hdr, out));
    out.append(payload);
}

fn append_h2_resp_headers(
    out:        u8[>..]&,
    dt:         http2::DynamicTable&,
    stream_id:  u32,
    status:     i32,
    hdrs:       const http::HeaderMap&,
    end_stream: bool,
) {
    let pseudo = http2::PseudoHeaders {
        status:     status,
        has_status: true,
        ..
    };
    var hpack_buf: u8[..16384] = [];
    assert(wire::encode_hpack_from_map(dt, pseudo, hdrs, hpack_buf, true));
    let flags: u8 = rfc::H2_FLAG_END_HEADERS | (if end_stream { rfc::H2_FLAG_END_STREAM } else { 0 });
    append_h2_frame(out, rfc::H2_FRAME_HEADERS, flags, stream_id, hpack_buf[..]);
}

fn append_h2_resp_trailers(
    out:       u8[>..]&,
    dt:        http2::DynamicTable&,
    stream_id: u32,
    hdrs:      const http::HeaderMap&,
) {
    let pseudo = http2::PseudoHeaders { is_trailer: true, .. };
    var hpack_buf: u8[..16384] = [];
    assert(wire::encode_hpack_from_map(dt, pseudo, hdrs, hpack_buf, true));
    let flags: u8 = rfc::H2_FLAG_END_HEADERS | rfc::H2_FLAG_END_STREAM;
    append_h2_frame(out, rfc::H2_FRAME_HEADERS, flags, stream_id, hpack_buf[..]);
}

fn pump_up_to_edge(up: proxy::H2UpstreamSession&, edge: http2::H2EdgeSession&) {
    var w: u8[>..] = [];
    let n = proxy::h2_upstream_drain_wire(up, w);
    if n > 0 {
        let fed, ok = http2::h2_edge_feed(edge, w[..]);
        assert(ok && fed == w.len);
    }
}

fn pump_edge_to_up(edge: http2::H2EdgeSession&, up: proxy::H2UpstreamSession&) {
    var w: u8[>..] = [];
    let n = http2::h2_edge_drain_wire(edge, w);
    if n > 0 {
        assert(proxy::h2_upstream_feed(up, w[..]));
    }
}

// ---- Test 1: Preface, Initial SETTINGS, Header Filtering, Sensitive HPACK ----

fn test_h2_up_preface_headers_and_sensitive() {
    let cfg = proxy::H2UpstreamConfig {
        transport:              proxy::H2UpstreamTransport.H2c,
        initial_window_size:    65535,
        max_concurrent_streams: 64,
        max_frame_size:         16384,
        max_header_list_size:   8192,
        ..
    };
    var sess = proxy::h2_upstream_open(cfg);
    defer proxy::h2_upstream_close(sess);
    assert(sess.slot_idx >= 0 && sess.generation != 0);
    assert(proxy::h2_upstream_can_open_stream(sess));
    assert(proxy::h2_upstream_active_streams(sess) == 0);
    assert(!proxy::h2_upstream_is_draining(sess));

    // Client preface + initial SETTINGS with ENABLE_PUSH = 0
    var init_wire: u8[>..] = [];
    let init_n = proxy::h2_upstream_drain_wire(sess, init_wire);
    assert(init_n > 24);
    assert(core::starts_with(init_wire[..], rfc::H2_CLIENT_PREFACE[..]));

    var r_init = wire::new_wire_h2_frame_reader(init_wire[24..]);
    let sf_h, sf_p, ok_sf = wire::next_frame(r_init);
    assert(ok_sf && sf_h.frame_type == rfc::H2_FRAME_SETTINGS && sf_h.stream_id == 0);
    assert((sf_h.flags & rfc::H2_FLAG_ACK) == 0);
    var saw_disable_push = false;
    var off: i64 = 0;
    while off + 6 <= sf_p.len {
        let pid = core::read_be_u16(sf_p, off);
        let pval = core::read_be_u32(sf_p, off + 2);
        if pid == rfc::H2_SETTING_ENABLE_PUSH {
            assert(pval == 0);
            saw_disable_push = true;
        }
        off += 6;
    }
    assert(saw_disable_push);

    // Open gRPC stream: preserves te: trailers, strips H1 hop-by-hop, lowers names,
    // preserves HEADER_FLAG_SENSITIVE -> HPACK NeverIndexed (0x10..0x1F)
    var in_hdrs = http::HeaderMap { .. };
    assert(http::append_header(in_hdrs, "Content-Type", "application/grpc+proto"));
    assert(http::append_header(in_hdrs, "TE", "Trailers"));
    assert(http::append_header(in_hdrs, "Connection", "keep-alive, x-drop-me"));
    assert(http::append_header(in_hdrs, "Keep-Alive", "timeout=5"));
    assert(http::append_header(in_hdrs, "Proxy-Connection", "keep-alive"));
    assert(http::append_header(in_hdrs, "Transfer-Encoding", "chunked"));
    assert(http::append_header(in_hdrs, "Upgrade", "h2c"));
    assert(http::append_header(in_hdrs, "X-Drop-Me", "secret-hop"));
    assert(http::append_header(in_hdrs, "Authorization", "Bearer tok-123"));
    assert(http::set_or_replace(in_hdrs, "X-Secret-Key", "custom-never-index", true));

    let sid, ok_open = proxy::h2_upstream_open_stream(
        sess,
        "POST",
        "https",
        "grpc.backend.internal:443",
        "/pkg.Echo/Call",
        in_hdrs,
        "203.0.113.10",
        proxy::H2UpstreamStreamEnd.OpenBody,
        proxy::H2UpstreamHeaderFilter.ApplyProxyFilters,
    );
    assert(ok_open && sid == 1);
    assert(proxy::h2_upstream_active_streams(sess) == 1);

    var req_wire: u8[>..] = [];
    assert(proxy::h2_upstream_drain_wire(sess, req_wire) > 0);
    var rr = wire::new_wire_h2_frame_reader(req_wire[..]);
    let hh, hp, ok_hh = wire::next_frame(rr);
    assert(ok_hh && hh.frame_type == rfc::H2_FRAME_HEADERS && hh.stream_id == 1);
    assert((hh.flags & rfc::H2_FLAG_END_HEADERS) != 0);
    assert((hh.flags & rfc::H2_FLAG_END_STREAM) == 0);

    // Inspect decoded headers and ensure NeverIndexed fields were NOT inserted into server decoder dynamic table
    var srv_dec = http2::new_dynamic_table(4096);
    var dec_pseudo = http2::PseudoHeaders { .. };
    var dec_map = http::HeaderMap { .. };
    let dec_err = http2::decode_hpack_to_map(srv_dec, hp, dec_pseudo, dec_map, 8192, true);
    assert(dec_err == rfc::H2_ERR_NO_ERROR);
    assert(dec_pseudo.method[..] == "POST");
    assert(dec_pseudo.scheme[..] == "https");
    assert(dec_pseudo.authority[..] == "grpc.backend.internal:443");
    assert(dec_pseudo.path[..] == "/pkg.Echo/Call");
    assert(http::get_header(dec_map, "te") == "trailers");
    assert(http::get_header(dec_map, "content-type") == "application/grpc+proto");
    assert(http::get_header(dec_map, "authorization") == "Bearer tok-123");
    assert(http::get_header(dec_map, "x-secret-key") == "custom-never-index");
    assert(http::get_header(dec_map, "x-forwarded-for") == "203.0.113.10");
    assert(http::get_header(dec_map, "x-forwarded-proto") == "https");
    assert(http::has_header(dec_map, "via"));
    assert(!http::has_header(dec_map, "connection"));
    assert(!http::has_header(dec_map, "keep-alive"));
    assert(!http::has_header(dec_map, "proxy-connection"));
    assert(!http::has_header(dec_map, "transfer-encoding"));
    assert(!http::has_header(dec_map, "upgrade"));
    assert(!http::has_header(dec_map, "x-drop-me"));

    // Verify neither authorization nor x-secret-key entered HPACK dynamic table
    var dyn_i: u64 = 0;
    while dyn_i < srv_dec.count {
        let dn, _, ok_dn = http2::get_indexed_header_slices(srv_dec, 62 + dyn_i);
        assert(ok_dn);
        assert(dn != "authorization" && dn != "x-secret-key");
        dyn_i += 1;
    }

    // Verify server response header encoded with HPACK NeverIndexed (0x10) sets HEADER_FLAG_SENSITIVE
    var resp_hpack: u8[..512] = [];
    var srv_enc = http2::new_dynamic_table(4096);
    assert(http2::encode_hpack_field(srv_enc, resp_hpack, ":status", "200", http2::HpackIndexing.Incremental, true));
    assert(http2::encode_hpack_field(srv_enc, resp_hpack, "x-upstream-secret", "s3cr3t", http2::HpackIndexing.NeverIndexed, true));
    var resp_wire: u8[>..] = [];
    append_h2_frame(resp_wire, rfc::H2_FRAME_HEADERS, rfc::H2_FLAG_END_HEADERS | rfc::H2_FLAG_END_STREAM, 1, resp_hpack[..]);
    assert(proxy::h2_upstream_feed(sess, resp_wire[..]));

    var ev = proxy::H2UpstreamEvent { .. };
    assert(proxy::h2_upstream_poll_event(sess, ev));
    assert(ev.kind == proxy::H2UpstreamEventKind.ResponseHead);
    assert(ev.stream_id == 1 && ev.status_code == 200 && ev.end_stream);
    var saw_sens_flag = false;
    for &e in ev.headers.entries {
        if http::entry_name(ev.headers, e) == "x-upstream-secret" {
            assert(http::is_sensitive(e));
            saw_sens_flag = true;
        }
    }
    assert(saw_sens_flag);

    // DirectHeaders mode skips Via/X-Forwarded-* injection while still stripping H1 hop-by-hop
    let sid3, ok3 = proxy::h2_upstream_open_stream(
        sess,
        "GET",
        "https",
        "grpc.backend.internal:443",
        "/direct",
        in_hdrs,
        "203.0.113.10",
        proxy::H2UpstreamStreamEnd.EndStream,
        proxy::H2UpstreamHeaderFilter.DirectHeaders,
    );
    assert(ok3 && sid3 == 3);
    req_wire.clear();
    assert(proxy::h2_upstream_drain_wire(sess, req_wire) > 0);
    var rr3 = wire::new_wire_h2_frame_reader(req_wire[..]);
    let hh3, hp3, ok_hh3 = wire::next_frame(rr3);
    assert(ok_hh3 && (hh3.flags & rfc::H2_FLAG_END_STREAM) != 0);
    var dec_p3 = http2::PseudoHeaders { .. };
    var dec_m3 = http::HeaderMap { .. };
    assert(http2::decode_hpack_to_map(srv_dec, hp3, dec_p3, dec_m3, 8192, true) == rfc::H2_ERR_NO_ERROR);
    assert(!http::has_header(dec_m3, "via") && !http::has_header(dec_m3, "x-forwarded-for"));
    assert(!http::has_header(dec_m3, "connection") && http::get_header(dec_m3, "te") == "trailers");

    print("H2_UP_PREFACE_AND_SENSITIVE: OK\n");
    // CHECK: H2_UP_PREFACE_AND_SENSITIVE: OK
}

// ---- Test 2: gRPC LPM + Connect-RPC Loopback via H2EdgeSession -------------

fn test_h2_up_grpc_and_connect_loopback() {
    var up = proxy::h2_upstream_open(proxy::H2UpstreamConfig {
        transport: proxy::H2UpstreamTransport.H2Tls,
        ..
    });
    defer proxy::h2_upstream_close(up);
    var edge = http2::h2_edge_open(128, 65535);
    defer http2::h2_edge_close(edge);

    // Exchange prefaces and initial SETTINGS
    pump_up_to_edge(up, edge);
    pump_edge_to_up(edge, up);
    pump_up_to_edge(up, edge);

    // 1. gRPC LPM streaming call with trailing grpc-status / grpc-message / grpc-status-details-bin
    var g_hdrs = http::HeaderMap { .. };
    assert(http::append_header(g_hdrs, "content-type", "application/grpc+proto"));
    assert(http::append_header(g_hdrs, "te", "trailers"));
    let sid_g, ok_g = proxy::h2_upstream_open_stream(
        up,
        "POST",
        "https",
        "grpc.local:443",
        "/echo.Echo/Unary",
        g_hdrs,
        "10.0.0.2",
        proxy::H2UpstreamStreamEnd.OpenBody,
        proxy::H2UpstreamHeaderFilter.ApplyProxyFilters,
    );
    assert(ok_g && sid_g == 1);

    var lpm_req: u8[>..] = [];
    grpc::encode_lpm("hello-grpc-proxy", lpm_req, false);
    let sent_g, ok_sg = proxy::h2_upstream_send_data(up, sid_g, lpm_req[..], true);
    assert(ok_sg && sent_g == lpm_req.len);
    pump_up_to_edge(up, edge);

    var eev = http2::H2EdgeEvent { .. };
    var srv_got_head = false;
    var srv_got_body: u8[>..] = [];
    var srv_got_end = false;
    while http2::h2_edge_poll_event(edge, eev) {
        if eev.kind == http2::H2EdgeEventKind.RequestHead && eev.stream_id == 1 {
            assert(http::get_header(eev.headers, "te") == "trailers");
            assert(http::get_header(eev.headers, "content-type") == "application/grpc+proto");
            srv_got_head = true;
        } else if eev.kind == http2::H2EdgeEventKind.RequestData && eev.stream_id == 1 {
            srv_got_body.append(eev.data);
        } else if eev.kind == http2::H2EdgeEventKind.RequestEnd && eev.stream_id == 1 {
            srv_got_end = true;
        }
    }
    assert(srv_got_head && srv_got_end);
    var req_parser = grpc::new_stream_parser();
    assert(grpc::feed(req_parser, srv_got_body[..]));
    var dec_msg: u8[..64] = [];
    var dec_comp = false;
    assert(grpc::next_message(req_parser, dec_msg, dec_comp));
    assert(!dec_comp && dec_msg[..] == "hello-grpc-proxy");

    // Server sends 200 headers + LPM response + trailing HEADERS (via raw wire frame on edge or raw feed)
    var srv_resp_h = http::HeaderMap { .. };
    assert(http::append_header(srv_resp_h, "content-type", "application/grpc+proto"));
    assert(http2::h2_edge_send_headers(edge, 1, 200, srv_resp_h, false));
    var lpm_resp: u8[>..] = [];
    grpc::encode_lpm("pong-grpc", lpm_resp, false);
    let rs, ok_rs = http2::h2_edge_send_data(edge, 1, lpm_resp[..], false);
    assert(ok_rs && rs == lpm_resp.len);
    pump_edge_to_up(edge, up);

    var uev = proxy::H2UpstreamEvent { .. };
    var got_g_head = false;
    var g_rx: u8[>..] = [];
    while proxy::h2_upstream_poll_event(up, uev) {
        if uev.kind == proxy::H2UpstreamEventKind.ResponseHead && uev.stream_id == 1 {
            assert(uev.status_code == 200 && !uev.end_stream);
            got_g_head = true;
        } else if uev.kind == proxy::H2UpstreamEventKind.ResponseData && uev.stream_id == 1 {
            g_rx.append(uev.data);
        }
    }
    assert(got_g_head);
    var resp_parser = grpc::new_stream_parser();
    assert(grpc::feed(resp_parser, g_rx[..]));
    assert(grpc::next_message(resp_parser, dec_msg, dec_comp));
    assert(dec_msg[..] == "pong-grpc");

    // Feed trailing HEADERS(END_STREAM) preserving grpc-status, grpc-message, grpc-status-details-bin
    var tr_hdrs = http::HeaderMap { .. };
    assert(http::append_header(tr_hdrs, "grpc-status", "0"));
    assert(http::append_header(tr_hdrs, "grpc-message", "ok%20done"));
    assert(http::append_header(tr_hdrs, "grpc-status-details-bin", "CAA="));
    var srv_tr_dt = http2::new_dynamic_table(4096);
    var tr_wire: u8[>..] = [];
    append_h2_resp_trailers(tr_wire, srv_tr_dt, 1, tr_hdrs);
    assert(proxy::h2_upstream_feed(up, tr_wire[..]));

    assert(proxy::h2_upstream_poll_event(up, uev));
    assert(uev.kind == proxy::H2UpstreamEventKind.ResponseTrailers);
    assert(uev.stream_id == 1 && uev.end_stream);
    assert(http::get_header(uev.headers, "grpc-status") == "0");
    assert(http::get_header(uev.headers, "grpc-message") == "ok%20done");
    assert(http::get_header(uev.headers, "grpc-status-details-bin") == "CAA=");
    assert(proxy::h2_upstream_active_streams(up) == 0);

    // 2. Connect-RPC streaming envelope (application/connect+proto + EndStream 0x02)
    var c_hdrs = http::HeaderMap { .. };
    assert(http::append_header(c_hdrs, "content-type", "application/connect+proto"));
    let sid_c, ok_c = proxy::h2_upstream_open_stream(
        up,
        "POST",
        "https",
        "connect.local:443",
        "/pkg.Svc/Stream",
        c_hdrs,
        "10.0.0.2",
        proxy::H2UpstreamStreamEnd.OpenBody,
        proxy::H2UpstreamHeaderFilter.DirectHeaders,
    );
    assert(ok_c && sid_c == 3);
    var conn_msg: u8[>..] = [];
    grpc::encode_lpm("connect-req", conn_msg, false);
    let cs1, ok_cs1 = proxy::h2_upstream_send_data(up, sid_c, conn_msg[..], true);
    assert(ok_cs1 && cs1 == conn_msg.len);
    pump_up_to_edge(up, edge);
    while http2::h2_edge_poll_event(edge, eev) {}

    var c_resp_h = http::HeaderMap { .. };
    assert(http::append_header(c_resp_h, "content-type", "application/connect+proto"));
    assert(http2::h2_edge_send_headers(edge, 3, 200, c_resp_h, false));
    var c_env: u8[>..] = [];
    grpc::encode_lpm("connect-reply", c_env, false);
    var c_end_tr = http::HeaderMap { .. };
    assert(http::append_header(c_end_tr, "x-connect-trace", "tr-9"));
    assert(grpc::encode_connect_end_stream(grpc::StatusCode.Ok, "", c_end_tr, c_env));
    let cs2, ok_cs2 = http2::h2_edge_send_data(edge, 3, c_env[..], true);
    assert(ok_cs2 && cs2 == c_env.len);
    pump_edge_to_up(edge, up);

    var got_c_head = false;
    var got_c_end = false;
    var c_rx: u8[>..] = [];
    while proxy::h2_upstream_poll_event(up, uev) {
        if uev.kind == proxy::H2UpstreamEventKind.ResponseHead && uev.stream_id == 3 {
            got_c_head = true;
        } else if uev.kind == proxy::H2UpstreamEventKind.ResponseData && uev.stream_id == 3 {
            c_rx.append(uev.data);
        } else if uev.kind == proxy::H2UpstreamEventKind.ResponseEnd && uev.stream_id == 3 {
            got_c_end = true;
        }
    }
    assert(got_c_head && got_c_end && c_rx.len > 10);
    var c_out_st = grpc::StatusCode.Internal;
    var c_out_msg: u8[..256] = [];
    var c_out_tr = http::HeaderMap { .. };
    var p_lpm_len: u32 = 0;
    let lpm_sl, _, cons_lpm, ok_lpm_sl = grpc::decode_lpm_slice(c_rx[..], 0);
    assert(ok_lpm_sl && lpm_sl == "connect-reply");
    p_lpm_len = cons_lpm;
    assert(c_rx[p_lpm_len] == rfc::CONNECT_FLAG_END_STREAM);
    assert(grpc::parse_connect_end_stream(c_rx[p_lpm_len + 5..], c_out_st, c_out_msg, c_out_tr));
    assert(c_out_st == grpc::StatusCode.Ok);
    assert(http::get_header(c_out_tr, "x-connect-trace") == "tr-9");

    print("H2_UP_GRPC_AND_CONNECT: OK\n");
    // CHECK: H2_UP_GRPC_AND_CONNECT: OK
}

// ---- Test 3: Full-Duplex Bidirectional Streaming & Request Trailers ---------

fn test_h2_up_full_duplex_bidi_streaming() {
    var up = proxy::h2_upstream_open(proxy::H2UpstreamConfig { .. });
    defer proxy::h2_upstream_close(up);
    var dump: u8[>..] = [];
    let _ = proxy::h2_upstream_drain_wire(up, dump);

    var hdrs = http::HeaderMap { .. };
    assert(http::append_header(hdrs, "content-type", "application/grpc"));
    assert(http::append_header(hdrs, "te", "trailers"));
    let sid, ok_open = proxy::h2_upstream_open_stream(
        up, "POST", "https", "bidi.internal", "/chat.Bidi/Talk", hdrs, "10.0.0.9",
    );
    assert(ok_open && sid == 1);

    // Client sends chunk 1 WITHOUT END_STREAM
    let s1, ok_s1 = proxy::h2_upstream_send_data(up, sid, "req-frame-1", false);
    assert(ok_s1 && s1 == 11);

    // Server sends 103 Early Hints + 200 OK + resp chunk 1 BEFORE client EOF!
    var srv_dt = http2::new_dynamic_table(4096);
    var w_srv: u8[>..] = [];
    var eh_hdrs = http::HeaderMap { .. };
    assert(http::append_header(eh_hdrs, "link", "</proto.bin>; rel=preload"));
    append_h2_resp_headers(w_srv, srv_dt, sid, 103, eh_hdrs, false);
    var ok_hdrs = http::HeaderMap { .. };
    assert(http::append_header(ok_hdrs, "content-type", "application/grpc"));
    append_h2_resp_headers(w_srv, srv_dt, sid, 200, ok_hdrs, false);
    append_h2_frame(w_srv, rfc::H2_FRAME_DATA, 0, sid, "srv-frame-1");

    // Feed split arbitrarily (byte chunks of 7 bytes)
    var pos: i64 = 0;
    while pos < w_srv.len {
        let end = min(w_srv.len, pos + 7);
        assert(proxy::h2_upstream_feed(up, w_srv[pos..end]));
        pos = end;
    }

    var ev = proxy::H2UpstreamEvent { .. };
    assert(proxy::h2_upstream_poll_event(up, ev));
    assert(ev.kind == proxy::H2UpstreamEventKind.ResponseHead && ev.status_code == 103 && !ev.end_stream);
    assert(proxy::h2_upstream_poll_event(up, ev));
    assert(ev.kind == proxy::H2UpstreamEventKind.ResponseHead && ev.status_code == 200 && !ev.end_stream);
    assert(proxy::h2_upstream_poll_event(up, ev));
    assert(ev.kind == proxy::H2UpstreamEventKind.ResponseData && ev.data == "srv-frame-1");
    assert(proxy::h2_upstream_active_streams(up) == 1);

    // Client continues sending request chunk 2 and request trailers (END_STREAM) while stream is full-duplex
    let s2, ok_s2 = proxy::h2_upstream_send_data(up, sid, "req-frame-2", false);
    assert(ok_s2 && s2 == 11);
    var req_tr = http::HeaderMap { .. };
    assert(http::append_header(req_tr, "x-req-digest", "sha256=abc"));
    assert(proxy::h2_upstream_send_trailers(up, sid, req_tr));

    // Sending more data or trailers after local END_STREAM must fail cleanly
    let s3, ok_s3 = proxy::h2_upstream_send_data(up, sid, "late", true);
    assert(!ok_s3 && s3 == 0);
    assert(!proxy::h2_upstream_send_trailers(up, sid, req_tr));

    dump.clear();
    assert(proxy::h2_upstream_drain_wire(up, dump) > 0);
    var rr = wire::new_wire_h2_frame_reader(dump[..]);
    var saw_req_tr = false;
    while wire::has_next(rr) {
        let fh, fp, ok_f = wire::next_frame(rr);
        assert(ok_f);
        if fh.frame_type == rfc::H2_FRAME_HEADERS && fh.stream_id == sid && (fh.flags & rfc::H2_FLAG_END_STREAM) != 0 {
            let _ = fp;
            saw_req_tr = true;
        }
    }
    assert(saw_req_tr);

    // Server sends final DATA + ResponseTrailers
    var w_srv2: u8[>..] = [];
    append_h2_frame(w_srv2, rfc::H2_FRAME_DATA, 0, sid, "srv-frame-2");
    var resp_tr = http::HeaderMap { .. };
    assert(http::append_header(resp_tr, "grpc-status", "0"));
    append_h2_resp_trailers(w_srv2, srv_dt, sid, resp_tr);
    assert(proxy::h2_upstream_feed(up, w_srv2[..]));

    assert(proxy::h2_upstream_poll_event(up, ev));
    assert(ev.kind == proxy::H2UpstreamEventKind.ResponseData && ev.data == "srv-frame-2");
    assert(proxy::h2_upstream_poll_event(up, ev));
    assert(ev.kind == proxy::H2UpstreamEventKind.ResponseTrailers && http::get_header(ev.headers, "grpc-status") == "0");
    assert(proxy::h2_upstream_active_streams(up) == 0);

    print("H2_UP_FULL_DUPLEX_BIDI: OK\n");
    // CHECK: H2_UP_FULL_DUPLEX_BIDI: OK
}

// ---- Test 4: Slow WAN Fan-Out, Flow Control, PING, GOAWAY Drain, Chunks ----

fn test_h2_up_wan_fanout_flow_control_and_goaway() {
    var up = proxy::h2_upstream_open(proxy::H2UpstreamConfig {
        initial_window_size:    131072,
        max_concurrent_streams: 128,
        ..
    });
    defer proxy::h2_upstream_close(up);
    var dump: u8[>..] = [];
    let _ = proxy::h2_upstream_drain_wire(up, dump);

    // Server advertises MAX_CONCURRENT_STREAMS = 16, INITIAL_WINDOW_SIZE = 1000
    var srv_set: u8[>..] = [];
    let s_params: wire::WireSetting[2] = [
        wire::WireSetting { id: rfc::H2_SETTING_MAX_CONCURRENT_STREAMS, val: 16 },
        wire::WireSetting { id: rfc::H2_SETTING_INITIAL_WINDOW_SIZE, val: 1000 },
    ];
    assert(wire::encode_settings_frame(s_params[..], srv_set));
    let ping_in: u8[8] = [0xAA, 0xBB, 0xCC, 0xDD, 1, 2, 3, 4];
    append_h2_frame(srv_set, rfc::H2_FRAME_PING, 0, 0, ping_in[..]);
    assert(proxy::h2_upstream_feed(up, srv_set[..]));

    // Client sends PING and server ACKs it
    let ping_out: u8[8] = [9, 8, 7, 6, 5, 4, 3, 2];
    assert(proxy::h2_upstream_send_ping(up, ping_out[..]));
    dump.clear();
    assert(proxy::h2_upstream_drain_wire(up, dump) > 0);
    var rp = wire::new_wire_h2_frame_reader(dump[..]);
    var saw_set_ack = false;
    var saw_ping_ack = false;
    var saw_ping_req = false;
    while wire::has_next(rp) {
        let fh, fp, ok_p = wire::next_frame(rp);
        assert(ok_p);
        if fh.frame_type == rfc::H2_FRAME_SETTINGS && (fh.flags & rfc::H2_FLAG_ACK) != 0 {
            saw_set_ack = true;
        } else if fh.frame_type == rfc::H2_FRAME_PING && (fh.flags & rfc::H2_FLAG_ACK) != 0 {
            assert(fp == ping_in[..]);
            saw_ping_ack = true;
        } else if fh.frame_type == rfc::H2_FRAME_PING && (fh.flags & rfc::H2_FLAG_ACK) == 0 {
            assert(fp == ping_out[..]);
            saw_ping_req = true;
        }
    }
    assert(saw_set_ack && saw_ping_ack && saw_ping_req);

    var srv_ping_ack: u8[>..] = [];
    append_h2_frame(srv_ping_ack, rfc::H2_FRAME_PING, rfc::H2_FLAG_ACK, 0, ping_out[..]);
    assert(proxy::h2_upstream_feed(up, srv_ping_ack[..]));
    var ev = proxy::H2UpstreamEvent { .. };
    assert(proxy::h2_upstream_poll_event(up, ev));
    assert(ev.kind == proxy::H2UpstreamEventKind.PingAck && ev.opaque_data[..] == ping_out[..]);

    // Fan-out 16 concurrent odd streams; 17th must be rejected by peer_max_concurrent_streams=16
    var h = http::HeaderMap { .. };
    for i in 16 {
        let sid, ok_s = proxy::h2_upstream_open_stream(
            up, "POST", "https", "wan.internal", "/fan", h, "",
        );
        assert(ok_s && sid == ((i * 2 + 1) as u32));
    }
    assert(proxy::h2_upstream_active_streams(up) == 16);
    assert(!proxy::h2_upstream_can_open_stream(up));
    let sid_ovf, ok_ovf = proxy::h2_upstream_open_stream(up, "GET", "https", "wan.internal", "/ovf", h, "");
    assert(!ok_ovf && sid_ovf == 0);

    // Two-level flow-control pause on stream 1 (window = 1000)
    var big_req: u8[2500] = ['M'; 2500];
    let n_a, ok_na = proxy::h2_upstream_send_data(up, 1, big_req[..], true);
    assert(ok_na && n_a == 1000);
    let n_b, ok_nb = proxy::h2_upstream_send_data(up, 1, big_req[1000..], true);
    assert(ok_nb && n_b == 0);
    var wu_s1: u8[>..] = [];
    assert(wire::encode_window_update_frame(1, 1500, wu_s1));
    assert(proxy::h2_upstream_feed(up, wu_s1[..]));
    let n_c, ok_nc = proxy::h2_upstream_send_data(up, 1, big_req[1000..], true);
    assert(ok_nc && n_c == 1500);

    // Receive >64 KiB DATA on stream 3 -> auto WINDOW_UPDATE replenishment
    var srv_dt = http2::new_dynamic_table(4096);
    var h3_wire: u8[>..] = [];
    append_h2_resp_headers(h3_wire, srv_dt, 3, 200, h, false);
    assert(proxy::h2_upstream_feed(up, h3_wire[..]));
    assert(proxy::h2_upstream_poll_event(up, ev) && ev.kind == proxy::H2UpstreamEventKind.ResponseHead);

    var rx_chunk: u8[16384] = ['R'; 16384];
    var total_rx: i64       = 0;
    var wu_cnt:   i32       = 0;
    for k in 6 {
        var dw: u8[>..] = [];
        append_h2_frame(dw, rfc::H2_FRAME_DATA, if k == 5 { rfc::H2_FLAG_END_STREAM } else { 0 }, 3, rx_chunk[..]);
        assert(proxy::h2_upstream_feed(up, dw[..]));
        while proxy::h2_upstream_poll_event(up, ev) {
            if ev.kind == proxy::H2UpstreamEventKind.ResponseData {
                total_rx += ev.data.len;
            }
        }
        dump.clear();
        let _ = proxy::h2_upstream_drain_wire(up, dump);
        var rwu = wire::new_wire_h2_frame_reader(dump[..]);
        while wire::has_next(rwu) {
            let wh, _, ok_w = wire::next_frame(rwu);
            assert(ok_w);
            if wh.frame_type == rfc::H2_FRAME_WINDOW_UPDATE {
                wu_cnt += 1;
            }
        }
    }
    assert(total_rx == 98304 && wu_cnt >= 6);

    // Graceful GOAWAY(last_stream_id = 3, NO_ERROR):
    // Streams > 3 are closed for retry; draining = true; can_open_stream = false; stream 1 still completes
    var go_p: u8[..8] = [];
    go_p.append_u32_be(3);
    go_p.append_u32_be(rfc::H2_ERR_NO_ERROR);
    var go_w: u8[>..] = [];
    append_h2_frame(go_w, rfc::H2_FRAME_GOAWAY, 0, 0, go_p[..]);
    assert(proxy::h2_upstream_feed(up, go_w[..]));
    assert(proxy::h2_upstream_is_draining(up));
    assert(!proxy::h2_upstream_can_open_stream(up));
    assert(proxy::h2_upstream_poll_event(up, ev) && ev.kind == proxy::H2UpstreamEventKind.GoAway);
    assert(ev.last_stream_id == 3 && ev.error_code == rfc::H2_ERR_NO_ERROR);
    // Stream 1 and stream 3 are <= 3; stream 3 has remote closed (still local open -> active), streams 5..31 closed
    let sid_after_go, ok_after_go = proxy::h2_upstream_open_stream(up, "GET", "https", "wan.internal", "/x", h, "");
    assert(!ok_after_go && sid_after_go == 0);

    // Finish stream 1 and stream 3 cleanly
    var fin_w: u8[>..] = [];
    append_h2_resp_headers(fin_w, srv_dt, 1, 204, h, true);
    assert(proxy::h2_upstream_feed(up, fin_w[..]));
    assert(proxy::h2_upstream_poll_event(up, ev) && ev.kind == proxy::H2UpstreamEventKind.ResponseHead && ev.end_stream);
    let z3, ok_z3 = proxy::h2_upstream_send_data(up, 3, "", true);
    assert(ok_z3 && z3 == 0);
    assert(proxy::h2_upstream_active_streams(up) == 0);

    print("H2_UP_FANOUT_FC_GOAWAY: OK\n");
    // CHECK: H2_UP_FANOUT_FC_GOAWAY: OK
}

// ---- Test 5: Zero-Byte END_STREAM Wire Backpressure, CONTINUATION & Chunks -

fn test_h2_up_backpressure_continuation_and_chunks() {
    var up = proxy::h2_upstream_open(proxy::H2UpstreamConfig {
        initial_window_size:  1048576,
        max_header_list_size: 32768,
        ..
    });
    defer proxy::h2_upstream_close(up);
    var dump: u8[>..] = [];
    let _ = proxy::h2_upstream_drain_wire(up, dump);

    // Expand peer send window so we can fill wire_out near 147456 cap
    var srv_set: u8[>..] = [];
    let wp: wire::WireSetting[1] = [
        wire::WireSetting { id: rfc::H2_SETTING_INITIAL_WINDOW_SIZE, val: 262144 },
    ];
    assert(wire::encode_settings_frame(wp[..], srv_set));
    var wu0: u8[4] = [0x00, 0x04, 0x00, 0x00];
    append_h2_frame(srv_set, rfc::H2_FRAME_WINDOW_UPDATE, 0, 0, wu0[..]);
    assert(proxy::h2_upstream_feed(up, srv_set[..]));
    dump.clear();
    let _ = proxy::h2_upstream_drain_wire(up, dump);

    var h = http::HeaderMap { .. };
    let sid1, ok1 = proxy::h2_upstream_open_stream(up, "POST", "https", "bp.local", "/fill", h, "");
    let sid3, ok3 = proxy::h2_upstream_open_stream(up, "POST", "https", "bp.local", "/zero", h, "");
    assert(ok1 && ok3);
    dump.clear();
    let _ = proxy::h2_upstream_drain_wire(up, dump);

    var big_fill: u8[>..] = [];
    for _ in 147370 { big_fill.push('F'); }
    let sf, ok_sf = proxy::h2_upstream_send_data(up, sid1, big_fill[..], false);
    assert(ok_sf && sf == 147370);

    // With < 9 bytes left in wire_out, h2_upstream_send_data(up, sid3, "", true) MUST return (0, false) without closing sid3
    let nz, ok_nz = proxy::h2_upstream_send_data(up, sid3, "", true);
    assert(!ok_nz && nz == 0);
    assert(proxy::h2_upstream_active_streams(up) == 2);

    dump.clear();
    assert(proxy::h2_upstream_drain_wire(up, dump) > 0);
    let nz2, ok_nz2 = proxy::h2_upstream_send_data(up, sid3, "", true);
    assert(ok_nz2 && nz2 == 0);
    dump.clear();
    assert(proxy::h2_upstream_drain_wire(up, dump) == rfc::H2_FRAME_HEADER_LEN);
    var r3 = wire::new_wire_h2_frame_reader(dump[..]);
    let fh3, fp3, ok_r3 = wire::next_frame(r3);
    assert(ok_r3 && fh3.stream_id == sid3 && (fh3.flags & rfc::H2_FLAG_END_STREAM) != 0 && fp3.len == 0);

    // Outbound >16 KiB request header block -> HEADERS + CONTINUATION
    var big_hdrs = http::HeaderMap { .. };
    var big_val: u8[1500] = ['v'; 1500];
    let v_off = big_hdrs.raw_buf.len as u16;
    assert(big_hdrs.raw_buf.try_append(big_val[..]));
    let v_end = big_hdrs.raw_buf.len as u16;
    for i in 16 {
        var name: u8[..16] = [];
        assert(name.try_append("x-big-req-"));
        (i as u64).format_u64_dec(name);
        let n_off = big_hdrs.raw_buf.len as u16;
        assert(big_hdrs.raw_buf.try_append(name[..]));
        let n_end = big_hdrs.raw_buf.len as u16;
        assert(big_hdrs.entries.try_push(http::HeaderEntry {
            name_begin:    n_off,
            name_end:      n_end,
            values_begin:  v_off,
            values_end:    v_end,
            next_idx:      0xFF,
            flags:         0,
            well_known_id: 0xFF,
            reserved:      0,
            name_hash:     http::hash_header_name(name[..]),
        }));
        assert(big_hdrs.header_contains_comma.try_push(false));
    }
    let sid5, ok5 = proxy::h2_upstream_open_stream(
        up, "GET", "https", "bp.local", "/big", big_hdrs, "",
        proxy::H2UpstreamStreamEnd.EndStream,
        proxy::H2UpstreamHeaderFilter.DirectHeaders,
    );
    assert(ok5 && sid5 == 5);
    dump.clear();
    assert(proxy::h2_upstream_drain_wire(up, dump) > 16384);
    var rbig = wire::new_wire_h2_frame_reader(dump[..]);
    let bh1, _, ok_b1 = wire::next_frame(rbig);
    let bh2, _, ok_b2 = wire::next_frame(rbig);
    assert(ok_b1 && bh1.frame_type == rfc::H2_FRAME_HEADERS && bh1.length == 16384);
    assert((bh1.flags & rfc::H2_FLAG_END_HEADERS) == 0 && (bh1.flags & rfc::H2_FLAG_END_STREAM) != 0);
    assert(ok_b2 && bh2.frame_type == rfc::H2_FRAME_CONTINUATION && (bh2.flags & rfc::H2_FLAG_END_HEADERS) != 0);

    // Inbound CONTINUATION reassembly on stream 5
    var srv_dt = http2::new_dynamic_table(4096);
    var resp_hpack: u8[..256] = [];
    var srv_h = http::HeaderMap { .. };
    assert(http::append_header(srv_h, "x-split-hdr", "reassembled-ok"));
    let p200 = http2::PseudoHeaders { status: 200, has_status: true, .. };
    assert(wire::encode_hpack_from_map(srv_dt, p200, srv_h, resp_hpack, true));
    let sp = resp_hpack.len / 2;
    var cont_in: u8[>..] = [];
    append_h2_frame(cont_in, rfc::H2_FRAME_HEADERS, rfc::H2_FLAG_END_STREAM, sid5, resp_hpack[..sp]);
    append_h2_frame(cont_in, rfc::H2_FRAME_CONTINUATION, rfc::H2_FLAG_END_HEADERS, sid5, resp_hpack[sp..]);
    assert(proxy::h2_upstream_feed(up, cont_in[..]));
    var ev = proxy::H2UpstreamEvent { .. };
    assert(proxy::h2_upstream_poll_event(up, ev) && ev.kind == proxy::H2UpstreamEventKind.ResponseHead);
    assert(ev.status_code == 200 && ev.end_stream && http::get_header(ev.headers, "x-split-hdr") == "reassembled-ok");

    // Chunk pool reclamation across 300 x 4 KiB inbound frames
    var chunk4k: u8[4096] = [0x5A; 4096];
    var h_s1:    u8[>..]  = [];
    append_h2_resp_headers(h_s1, srv_dt, sid1, 200, h, false);
    assert(proxy::h2_upstream_feed(up, h_s1[..]));
    assert(proxy::h2_upstream_poll_event(up, ev) && ev.kind == proxy::H2UpstreamEventKind.ResponseHead);

    var rx_total: u64 = 0;
    for r in 300 {
        var dw: u8[>..] = [];
        append_h2_frame(dw, rfc::H2_FRAME_DATA, if r == 299 { rfc::H2_FLAG_END_STREAM } else { 0 }, sid1, chunk4k[..]);
        assert(proxy::h2_upstream_feed(up, dw[..]));
        while proxy::h2_upstream_poll_event(up, ev) {
            if ev.kind == proxy::H2UpstreamEventKind.ResponseData {
                assert(ev.data.len == 4096 && ev.data[0] == 0x5A);
                rx_total += ev.data.len as u64;
            }
        }
        dump.clear();
        let _ = proxy::h2_upstream_drain_wire(up, dump);
    }
    assert(rx_total == 300 * 4096);
    assert(proxy::g_h2_up_chunks.len <= 16);

    print("H2_UP_BACKPRESSURE_CONT_CHUNKS: OK\n");
    // CHECK: H2_UP_BACKPRESSURE_CONT_CHUNKS: OK
}

// ---- Test 6: Security, Validation, RST_STREAM, PUSH_PROMISE, ABA & Threads -

thread_fn up_worker_thread(arg: i64) {
    let _ = arg;
    var up = proxy::h2_upstream_open(proxy::H2UpstreamConfig { .. });
    defer proxy::h2_upstream_close(up);
    var edge = http2::h2_edge_open(128, 65535);
    defer http2::h2_edge_close(edge);

    pump_up_to_edge(up, edge);
    pump_edge_to_up(edge, up);
    pump_up_to_edge(up, edge);

    var h = http::HeaderMap { .. };
    let sid, ok = proxy::h2_upstream_open_stream(
        up, "GET", "https", "thread.local", "/ping", h, "",
        proxy::H2UpstreamStreamEnd.EndStream,
        proxy::H2UpstreamHeaderFilter.DirectHeaders,
    );
    assert(ok && sid == 1);
    pump_up_to_edge(up, edge);

    var eev = http2::H2EdgeEvent { .. };
    assert(http2::h2_edge_poll_event(edge, eev) && eev.kind == http2::H2EdgeEventKind.RequestHead);
    assert(http2::h2_edge_send_headers(edge, 1, 200, h, false));
    let s, ok_s = http2::h2_edge_send_data(edge, 1, "thread-ok", true);
    assert(ok_s && s == 9);
    pump_edge_to_up(edge, up);

    var uev = proxy::H2UpstreamEvent { .. };
    assert(proxy::h2_upstream_poll_event(up, uev) && uev.kind == proxy::H2UpstreamEventKind.ResponseHead);
    assert(proxy::h2_upstream_poll_event(up, uev) && uev.kind == proxy::H2UpstreamEventKind.ResponseData && uev.data == "thread-ok");
    assert(proxy::h2_upstream_poll_event(up, uev) && uev.kind == proxy::H2UpstreamEventKind.ResponseEnd);
}

fn test_h2_up_security_and_aba() {
    var up = proxy::h2_upstream_open(proxy::H2UpstreamConfig { .. });
    var dump: u8[>..] = [];
    let _ = proxy::h2_upstream_drain_wire(up, dump);

    // 1. Reject :pseudo in headers, invalid method/scheme/path, and disallowed trailer fields
    var bad_pseudo = http::HeaderMap { .. };
    assert(http::append_header(bad_pseudo, ":status", "200"));
    let bs1, ok_bs1 = proxy::h2_upstream_open_stream(up, "GET", "https", "ex.com", "/", bad_pseudo, "");
    assert(!ok_bs1 && bs1 == 0);

    var clean_h = http::HeaderMap { .. };
    let bs2, ok_bs2 = proxy::h2_upstream_open_stream(up, "BAD METHOD", "https", "ex.com", "/", clean_h, "");
    assert(!ok_bs2 && bs2 == 0);
    let bs3, ok_bs3 = proxy::h2_upstream_open_stream(up, "GET", "https", "ex.com", "no-leading-slash", clean_h, "");
    assert(!ok_bs3 && bs3 == 0);

    // Transactional rollback on peer_max_header_list_size exceeded
    var lim_set: u8[>..] = [];
    let lim_p: wire::WireSetting[1] = [
        wire::WireSetting { id: rfc::H2_SETTING_MAX_HEADER_LIST_SIZE, val: 100 },
    ];
    assert(wire::encode_settings_frame(lim_p[..], lim_set));
    assert(proxy::h2_upstream_feed(up, lim_set[..]));
    dump.clear();
    let _ = proxy::h2_upstream_drain_wire(up, dump);

    var too_big = http::HeaderMap { .. };
    var big_v: u8[100] = ['q'; 100];
    assert(http::append_header(too_big, "x-too-big", big_v[..]));
    let bs4, ok_bs4 = proxy::h2_upstream_open_stream(
        up, "GET", "https", "ex.com", "/ok", too_big, "",
        proxy::H2UpstreamStreamEnd.EndStream,
        proxy::H2UpstreamHeaderFilter.DirectHeaders,
    );
    assert(!ok_bs4 && bs4 == 0);
    dump.clear();
    assert(proxy::h2_upstream_drain_wire(up, dump) == 0);

    // Remove header limit for remaining tests
    var unlim_set: u8[>..] = [];
    let unlim_p: wire::WireSetting[1] = [
        wire::WireSetting { id: rfc::H2_SETTING_MAX_HEADER_LIST_SIZE, val: 8192 },
    ];
    assert(wire::encode_settings_frame(unlim_p[..], unlim_set));
    assert(proxy::h2_upstream_feed(up, unlim_set[..]));

    let sid1, ok1 = proxy::h2_upstream_open_stream(up, "POST", "https", "ex.com", "/tr", clean_h, "");
    assert(ok1 && sid1 == 1);
    var bad_tr1 = http::HeaderMap { .. };
    assert(http::append_header(bad_tr1, ":status", "200"));
    assert(!proxy::h2_upstream_send_trailers(up, sid1, bad_tr1));

    var bad_tr2 = http::HeaderMap { .. };
    assert(http::append_header(bad_tr2, "host", "evil.com"));
    assert(!proxy::h2_upstream_send_trailers(up, sid1, bad_tr2));

    var bad_tr3 = http::HeaderMap { .. };
    assert(http::append_header(bad_tr3, "te", "trailers"));
    assert(!proxy::h2_upstream_send_trailers(up, sid1, bad_tr3));

    // Local reset_stream + late DATA tolerance
    assert(proxy::h2_upstream_reset_stream(up, sid1, rfc::H2_ERR_CANCEL));
    assert(proxy::h2_upstream_active_streams(up) == 0);
    var late_data: u8[>..] = [];
    append_h2_frame(late_data, rfc::H2_FRAME_DATA, rfc::H2_FLAG_END_STREAM, sid1, "late-bytes");
    assert(proxy::h2_upstream_feed(up, late_data[..]));

    // Peer RST_STREAM
    let sid3, ok3 = proxy::h2_upstream_open_stream(up, "GET", "https", "ex.com", "/rst", clean_h, "");
    assert(ok3 && sid3 == 3);
    var rst_w: u8[>..] = [];
    var rst_p: u8[..4] = [];
    rst_p.append_u32_be(rfc::H2_ERR_REFUSED_STREAM);
    append_h2_frame(rst_w, rfc::H2_FRAME_RST_STREAM, 0, sid3, rst_p[..]);
    assert(proxy::h2_upstream_feed(up, rst_w[..]));
    var ev = proxy::H2UpstreamEvent { .. };
    assert(proxy::h2_upstream_poll_event(up, ev));
    assert(ev.kind == proxy::H2UpstreamEventKind.StreamReset && ev.stream_id == sid3);
    assert(ev.error_code == rfc::H2_ERR_REFUSED_STREAM);
    assert(proxy::h2_upstream_active_streams(up) == 0);

    // 2. Reject server PUSH_PROMISE with PROTOCOL_ERROR
    let sid5, ok5 = proxy::h2_upstream_open_stream(up, "GET", "https", "ex.com", "/push", clean_h, "");
    assert(ok5 && sid5 == 5);
    var pp_w: u8[>..] = [];
    var pp_p: u8[..8] = [];
    pp_p.append_u32_be(2);
    pp_p.push(0x82);
    append_h2_frame(pp_w, rfc::H2_FRAME_PUSH_PROMISE, rfc::H2_FLAG_END_HEADERS, sid5, pp_p[..]);
    assert(!proxy::h2_upstream_feed(up, pp_w[..]));
    assert(proxy::h2_upstream_poll_event(up, ev));
    assert(ev.kind == proxy::H2UpstreamEventKind.ProtocolError && ev.error_code == rfc::H2_ERR_PROTOCOL_ERROR);
    dump.clear();
    assert(proxy::h2_upstream_drain_wire(up, dump) > 0);

    // 3. ABA guard on closed session reused by a fresh session + idempotent close
    let stale = up;
    proxy::h2_upstream_close(up);
    proxy::h2_upstream_close(up);
    var fresh = proxy::h2_upstream_open(proxy::H2UpstreamConfig { .. });
    assert(fresh.slot_idx == stale.slot_idx && fresh.generation != stale.generation);
    var mut_stale = stale;
    assert(!proxy::h2_upstream_feed(mut_stale, ""));
    assert(!proxy::h2_upstream_can_open_stream(mut_stale));
    assert(!proxy::h2_upstream_send_goaway(mut_stale, rfc::H2_ERR_NO_ERROR));
    proxy::h2_upstream_close(fresh);

    // 4. Server sending SETTINGS(ENABLE_PUSH=1) triggers PROTOCOL_ERROR
    var s_push_cfg = proxy::h2_upstream_open(proxy::H2UpstreamConfig { .. });
    defer proxy::h2_upstream_close(s_push_cfg);
    var bad_set: u8[>..] = [];
    let ep_set: wire::WireSetting[1] = [
        wire::WireSetting { id: rfc::H2_SETTING_ENABLE_PUSH, val: 1 },
    ];
    assert(wire::encode_settings_frame(ep_set[..], bad_set));
    assert(!proxy::h2_upstream_feed(s_push_cfg, bad_set[..]));
    assert(proxy::h2_upstream_poll_event(s_push_cfg, ev));
    assert(ev.kind == proxy::H2UpstreamEventKind.ProtocolError && ev.error_code == rfc::H2_ERR_PROTOCOL_ERROR);

    // 5. Thread-local isolation via thread_spawn
    let tid = thread_spawn(up_worker_thread, 1);
    assert(thread_wait(tid));

    print("H2_UP_SECURITY_ABA_THREADS: OK\n");
    // CHECK: H2_UP_SECURITY_ABA_THREADS: OK
}

// ---- Test 7: Max Frame Clamp, Connection-Filter Bypass, HPACK Updates & Cookie Sensitivity

fn feed_and_assert_proto_err(sess: proxy::H2UpstreamSession&, wire: const u8[:], expected_err: u32) {
    assert(!proxy::h2_upstream_feed(sess, wire));
    var ev = proxy::H2UpstreamEvent { .. };
    var saw_err = false;
    while proxy::h2_upstream_poll_event(sess, ev) {
        if ev.kind == proxy::H2UpstreamEventKind.ProtocolError {
            assert(ev.error_code == expected_err);
            saw_err = true;
        }
    }
    assert(saw_err);
}

fn push_hpack_literal_no_idx(out: u8[>..]&, name: const u8[:], val: const u8[:], never_idx: bool) {
    out.push(if never_idx { 0x10 } else { 0x00 });
    out.push(name.len as u8);
    out.append(name);
    out.push(val.len as u8);
    out.append(val);
}

fn test_h2_up_config_clamp_and_conn_strip() {
    let cfg = proxy::H2UpstreamConfig {
        transport:            proxy::H2UpstreamTransport.H2c,
        max_frame_size:       100000,
        max_header_list_size: 8192,
        ..
    };
    var up = proxy::h2_upstream_open(cfg);
    defer proxy::h2_upstream_close(up);

    var init_w: u8[>..] = [];
    assert(proxy::h2_upstream_drain_wire(up, init_w) > 24);
    var r_init = wire::new_wire_h2_frame_reader(init_w[24..]);
    let sf_h, sf_p, ok_sf = wire::next_frame(r_init);
    assert(ok_sf && sf_h.frame_type == rfc::H2_FRAME_SETTINGS);
    var saw_frame_cap = false;
    var saw_hdr_cap = false;
    var off: i64 = 0;
    while off + 6 <= sf_p.len {
        let pid = core::read_be_u16(sf_p, off);
        let pval = core::read_be_u32(sf_p, off + 2);
        if pid == rfc::H2_SETTING_MAX_FRAME_SIZE {
            assert(pval == 16384);
            saw_frame_cap = true;
        }
        if pid == rfc::H2_SETTING_MAX_HEADER_LIST_SIZE {
            assert(pval == 8192);
            saw_hdr_cap = true;
        }
        off += 6;
    }
    assert(saw_frame_cap && saw_hdr_cap);

    // Downstream Connection header must NOT strip proxy-synthesized forwarding headers
    var in_hdrs = http::HeaderMap { .. };
    assert(http::append_header(
        in_hdrs,
        "Connection",
        "x-forwarded-for, via, forwarded, x-forwarded-proto, client-cert, x-drop-me",
    ));
    assert(http::append_header(in_hdrs, "X-Drop-Me", "hop-secret"));
    assert(http::append_header(in_hdrs, "X-Custom", "kept"));

    let sid, ok_open = proxy::h2_upstream_open_stream(
        up, "POST", "https", "api.internal", "/submit", in_hdrs, "198.51.100.7",
    );
    assert(ok_open && sid == 1);

    var req_w: u8[>..] = [];
    assert(proxy::h2_upstream_drain_wire(up, req_w) > 0);
    var rr = wire::new_wire_h2_frame_reader(req_w[..]);
    let hh, hp, ok_hh = wire::next_frame(rr);
    assert(ok_hh && hh.frame_type == rfc::H2_FRAME_HEADERS && hh.stream_id == sid);
    var srv_dec = http2::new_dynamic_table(4096);
    var dec_pseudo = http2::PseudoHeaders { .. };
    var dec_map = http::HeaderMap { .. };
    assert(http2::decode_hpack_to_map(srv_dec, hp, dec_pseudo, dec_map, 8192, true) == rfc::H2_ERR_NO_ERROR);
    assert(http::get_header(dec_map, "x-forwarded-for") == "198.51.100.7");
    assert(http::get_header(dec_map, "x-forwarded-proto") == "https");
    assert(http::has_header(dec_map, "via"));
    assert(http::get_header(dec_map, "x-custom") == "kept");
    assert(!http::has_header(dec_map, "x-drop-me"));
    assert(!http::has_header(dec_map, "connection"));

    // Exact 16384-byte DATA frame must decode without wire_in deadlock
    var srv_w: u8[>..] = [];
    var srv_enc = http2::new_dynamic_table(4096);
    var rh = http::HeaderMap { .. };
    append_h2_resp_headers(srv_w, srv_enc, sid, 200, rh, false);
    var big16k: u8[16384] = [0x6B; 16384];
    append_h2_frame(srv_w, rfc::H2_FRAME_DATA, rfc::H2_FLAG_END_STREAM, sid, big16k[..]);
    assert(proxy::h2_upstream_feed(up, srv_w[..]));
    var ev = proxy::H2UpstreamEvent { .. };
    assert(proxy::h2_upstream_poll_event(up, ev) && ev.kind == proxy::H2UpstreamEventKind.ResponseHead);
    assert(proxy::h2_upstream_poll_event(up, ev) && ev.kind == proxy::H2UpstreamEventKind.ResponseData);
    assert(ev.data.len == 16384 && ev.data[0] == 0x6B && ev.data[16383] == 0x6B);
    assert(proxy::h2_upstream_poll_event(up, ev) && ev.kind == proxy::H2UpstreamEventKind.ResponseEnd);

    print("H2_UP_CLAMP_AND_FILTER: OK\n");
    // CHECK: H2_UP_CLAMP_AND_FILTER: OK
}

fn test_h2_up_dynamic_table_updates_and_cookie_mark() {
    var up = proxy::h2_upstream_open(proxy::H2UpstreamConfig { .. });
    defer proxy::h2_upstream_close(up);
    var dump: u8[>..] = [];
    let _ = proxy::h2_upstream_drain_wire(up, dump);

    var srv_dec = http2::new_dynamic_table(4096);
    var h1 = http::HeaderMap { .. };
    assert(http::append_header(h1, "x-cache-seed", "populate-dyn-table-entry"));
    let s1, ok1 = proxy::h2_upstream_open_stream(
        up, "GET", "https", "ex.com", "/s1", h1, "",
        proxy::H2UpstreamStreamEnd.EndStream, proxy::H2UpstreamHeaderFilter.DirectHeaders,
    );
    assert(ok1 && s1 == 1);
    var w1: u8[>..] = [];
    assert(proxy::h2_upstream_drain_wire(up, w1) > 0);
    var r1 = wire::new_wire_h2_frame_reader(w1[..]);
    let fh1, fp1, ok_f1 = wire::next_frame(r1);
    assert(ok_f1 && fh1.frame_type == rfc::H2_FRAME_HEADERS);
    var p1 = http2::PseudoHeaders { .. };
    var m1 = http::HeaderMap { .. };
    assert(http2::decode_hpack_to_map(srv_dec, fp1, p1, m1, 8192, true) == rfc::H2_ERR_NO_ERROR);
    assert(srv_dec.count > 0);

    // Non-OPTIONS "*" request rejected; OPTIONS "*" permitted
    let bad_star, ok_star = proxy::h2_upstream_open_stream(
        up, "GET", "https", "ex.com", "*", h1, "",
        proxy::H2UpstreamStreamEnd.EndStream, proxy::H2UpstreamHeaderFilter.DirectHeaders,
    );
    assert(!ok_star && bad_star == 0);
    let opt_sid, ok_opt = proxy::h2_upstream_open_stream(
        up, "OPTIONS", "https", "ex.com", "*", h1, "",
        proxy::H2UpstreamStreamEnd.EndStream, proxy::H2UpstreamHeaderFilter.DirectHeaders,
    );
    assert(ok_opt && opt_sid == 3);
    dump.clear();
    let _ = proxy::h2_upstream_drain_wire(up, dump);

    // Peer shrinks HEADER_TABLE_SIZE to 0 -> client must emit 001xxxxx (0x20) update before next HEADERS
    var set0: u8[>..] = [];
    let s_zero: wire::WireSetting[1] = [
        wire::WireSetting { id: rfc::H2_SETTING_HEADER_TABLE_SIZE, val: 0 },
    ];
    assert(wire::encode_settings_frame(s_zero[..], set0));
    assert(proxy::h2_upstream_feed(up, set0[..]));
    dump.clear();
    assert(proxy::h2_upstream_drain_wire(up, dump) > 0);

    let s5, ok5 = proxy::h2_upstream_open_stream(
        up, "GET", "https", "ex.com", "/s5", h1, "",
        proxy::H2UpstreamStreamEnd.EndStream, proxy::H2UpstreamHeaderFilter.DirectHeaders,
    );
    assert(ok5 && s5 == 5);
    var w5: u8[>..] = [];
    assert(proxy::h2_upstream_drain_wire(up, w5) > 0);
    var r5 = wire::new_wire_h2_frame_reader(w5[..]);
    let fh5, fp5, ok_f5 = wire::next_frame(r5);
    assert(ok_f5 && fh5.frame_type == rfc::H2_FRAME_HEADERS);
    assert(fp5.len > 0 && fp5[0] == 0x20);
    var p5 = http2::PseudoHeaders { .. };
    var m5 = http::HeaderMap { .. };
    assert(http2::decode_hpack_to_map(srv_dec, fp5, p5, m5, 8192, true) == rfc::H2_ERR_NO_ERROR);
    assert(srv_dec.current_max_size == 0);

    // Shrink 0 then grow 4096 between requests -> must emit [0, 4096] updates cleanly
    var set_grow: u8[>..] = [];
    let s_4k: wire::WireSetting[1] = [
        wire::WireSetting { id: rfc::H2_SETTING_HEADER_TABLE_SIZE, val: 4096 },
    ];
    assert(wire::encode_settings_frame(s_zero[..], set_grow));
    assert(wire::encode_settings_frame(s_4k[..], set_grow));
    assert(proxy::h2_upstream_feed(up, set_grow[..]));
    dump.clear();
    assert(proxy::h2_upstream_drain_wire(up, dump) > 0);

    let s7, ok7 = proxy::h2_upstream_open_stream(
        up, "GET", "https", "ex.com", "/s7", h1, "",
        proxy::H2UpstreamStreamEnd.EndStream, proxy::H2UpstreamHeaderFilter.DirectHeaders,
    );
    assert(ok7 && s7 == 7);
    var w7: u8[>..] = [];
    assert(proxy::h2_upstream_drain_wire(up, w7) > 0);
    var r7 = wire::new_wire_h2_frame_reader(w7[..]);
    let fh7, fp7, ok_f7 = wire::next_frame(r7);
    assert(ok_f7 && fh7.frame_type == rfc::H2_FRAME_HEADERS && fp7.len >= 4);
    assert(fp7[0] == 0x20 && fp7[1] == 0x3F && fp7[2] == 0xE1 && fp7[3] == 0x1F);
    var p7 = http2::PseudoHeaders { .. };
    var m7 = http::HeaderMap { .. };
    assert(http2::decode_hpack_to_map(srv_dec, fp7, p7, m7, 8192, true) == rfc::H2_ERR_NO_ERROR);
    assert(srv_dec.current_max_size == 4096);

    // Merged cookie marked NeverIndexed on 2nd fragment marks "cookie", NOT neighboring header
    var raw_hp: u8[>..] = [];
    raw_hp.push(0x88); // :status 200
    push_hpack_literal_no_idx(raw_hp, "cookie", "a=1", false);
    push_hpack_literal_no_idx(raw_hp, "x-pub", "ok", false);
    push_hpack_literal_no_idx(raw_hp, "cookie", "sec=2", true);
    var rw: u8[>..] = [];
    append_h2_frame(rw, rfc::H2_FRAME_HEADERS, rfc::H2_FLAG_END_HEADERS | rfc::H2_FLAG_END_STREAM, s7, raw_hp[..]);
    assert(proxy::h2_upstream_feed(up, rw[..]));
    var ev = proxy::H2UpstreamEvent { .. };
    assert(proxy::h2_upstream_poll_event(up, ev) && ev.kind == proxy::H2UpstreamEventKind.ResponseHead);
    var cookie_sens = false;
    var pub_sens = false;
    for &e in ev.headers.entries {
        if http::entry_name(ev.headers, e) == "cookie" {
            assert(http::entry_value(ev.headers, e) == "a=1; sec=2");
            cookie_sens = http::is_sensitive(e);
        }
        if http::entry_name(ev.headers, e) == "x-pub" {
            assert(http::entry_value(ev.headers, e) == "ok");
            pub_sens = http::is_sensitive(e);
        }
    }
    assert(cookie_sens && !pub_sens);

    print("H2_UP_DYN_UPDATES_COOKIE: OK\n");
    // CHECK: H2_UP_DYN_UPDATES_COOKIE: OK
}

// ---- Test 8: Sans-IO TLS 1.3 ALPN "h2" Loopback & ALPN Validator -----------

fn tls_pump_hs_wire(src: tls::TlsEndpoint&, dst: tls::TlsEndpoint&) {
    var buf: u8[16384] = [0; 16384];
    let n, st = tls::tls_endpoint_drain_wire(src, buf[..]);
    assert(st == tls::TlsBackendStatus.Ok || st == tls::TlsBackendStatus.WantRead || st == tls::TlsBackendStatus.WantWrite);
    if n > 0 {
        let fed, fst = tls::tls_endpoint_feed_wire(dst, buf[..n]);
        assert(fed == n);
        assert(fst == tls::TlsBackendStatus.Ok || fst == tls::TlsBackendStatus.WantRead || fst == tls::TlsBackendStatus.WantWrite);
    }
}

fn tls_exchange_up_to_edge(
    up:     proxy::H2UpstreamSession&,
    cli_ep: tls::TlsEndpoint&,
    srv_ep: tls::TlsEndpoint&,
    edge:   http2::H2EdgeSession&,
) {
    var plain: u8[>..] = [];
    let pn = proxy::h2_upstream_drain_wire(up, plain);
    if pn > 0 {
        let wn, wst = tls::tls_endpoint_write_app(cli_ep, plain[..]);
        assert(wn == pn && wst == tls::TlsBackendStatus.Ok);
    }
    tls_pump_hs_wire(cli_ep, srv_ep);
    var app_buf: u8[16384] = [0; 16384];
    let rn, rst = tls::tls_endpoint_read_app(srv_ep, app_buf[..]);
    assert(rst == tls::TlsBackendStatus.Ok || rst == tls::TlsBackendStatus.WantRead);
    if rn > 0 {
        let fed, ok = http2::h2_edge_feed(edge, app_buf[..rn]);
        assert(ok && fed == rn);
    }
}

fn tls_exchange_edge_to_up(
    edge:   http2::H2EdgeSession&,
    srv_ep: tls::TlsEndpoint&,
    cli_ep: tls::TlsEndpoint&,
    up:     proxy::H2UpstreamSession&,
) {
    var plain: u8[>..] = [];
    let pn = http2::h2_edge_drain_wire(edge, plain);
    if pn > 0 {
        let wn, wst = tls::tls_endpoint_write_app(srv_ep, plain[..]);
        assert(wn == pn && wst == tls::TlsBackendStatus.Ok);
    }
    tls_pump_hs_wire(srv_ep, cli_ep);
    var app_buf: u8[16384] = [0; 16384];
    let rn, rst = tls::tls_endpoint_read_app(cli_ep, app_buf[..]);
    assert(rst == tls::TlsBackendStatus.Ok || rst == tls::TlsBackendStatus.WantRead);
    if rn > 0 {
        assert(proxy::h2_upstream_feed(up, app_buf[..rn]));
    }
}

fn test_h2_up_tls13_alpn_loopback() {
    var seed:     u8[32]     = [0x42; 32];
    var cert_der: u8[..2048] = [];
    assert(tls::build_test_ed25519_cert_der(seed, "h2.internal.test", "h2.internal.test", "127.0.0.1", cert_der));
    var trust = tls::TrustAnchorStore { .. };
    assert(tls::add_trust_anchor_cert_der(trust, cert_der[..]));

    var srv_cfg = tls::TlsBackendConfig {
        kind:               tls::TlsBackendKind.PureGoose,
        min_version:        tls::TlsMinVersion.Tls13,
        is_server:          true,
        priv_seed:          seed,
        require_alpn_match: true,
        ..
    };
    assert(srv_cfg.cert_der.try_set(cert_der[..]));
    assert(srv_cfg.alpn_wire.try_set("\x02h2"));

    var cli_cfg = tls::TlsBackendConfig {
        kind:               tls::TlsBackendKind.PureGoose,
        min_version:        tls::TlsMinVersion.Tls13,
        is_server:          false,
        use_system_roots:   false,
        trust_store:        trust,
        require_alpn_match: true,
        ..
    };
    assert(cli_cfg.server_name.try_set("h2.internal.test"));
    assert(cli_cfg.alpn_wire.try_set("\x02h2"));

    var srv_ep, srv_st = tls::tls_endpoint_open(srv_cfg);
    var cli_ep, cli_st = tls::tls_endpoint_open(cli_cfg);
    assert(srv_st == tls::TlsBackendStatus.Ok && cli_st == tls::TlsBackendStatus.Ok);
    defer tls::tls_endpoint_close(srv_ep);
    defer tls::tls_endpoint_close(cli_ep);

    var round: i64 = 0;
    while (!tls::tls_endpoint_is_established(cli_ep) || !tls::tls_endpoint_is_established(srv_ep)) && round < 16 {
        let _ = tls::tls_endpoint_step_handshake(cli_ep);
        tls_pump_hs_wire(cli_ep, srv_ep);
        let _ = tls::tls_endpoint_step_handshake(srv_ep);
        tls_pump_hs_wire(srv_ep, cli_ep);
        round += 1;
    }
    assert(tls::tls_endpoint_is_established(cli_ep) && tls::tls_endpoint_is_established(srv_ep));
    let cli_alpn = tls::tls_endpoint_selected_alpn(cli_ep);
    assert(cli_alpn[..] == "h2");

    var up_tls = proxy::H2UpstreamSession { .. };
    up_tls = proxy::h2_upstream_open(proxy::H2UpstreamConfig { transport: proxy::H2UpstreamTransport.H2Tls, .. });
    defer proxy::h2_upstream_close(up_tls);
    assert(proxy::h2_upstream_validate_alpn(up_tls, cli_alpn[..]));
    assert(!proxy::h2_upstream_validate_alpn(up_tls, "http/1.1"));
    assert(!proxy::h2_upstream_validate_alpn(up_tls, ""));

    var up_h2c = proxy::h2_upstream_open(proxy::H2UpstreamConfig { transport: proxy::H2UpstreamTransport.H2c, .. });
    defer proxy::h2_upstream_close(up_h2c);
    assert(proxy::h2_upstream_validate_alpn(up_h2c, ""));
    assert(proxy::h2_upstream_validate_alpn(up_h2c, "h2c"));
    assert(!proxy::h2_upstream_validate_alpn(up_h2c, "h2"));

    var edge = http2::h2_edge_open(64, 65535);
    defer http2::h2_edge_close(edge);
    tls_exchange_up_to_edge(up_tls, cli_ep, srv_ep, edge);
    tls_exchange_edge_to_up(edge, srv_ep, cli_ep, up_tls);
    tls_exchange_up_to_edge(up_tls, cli_ep, srv_ep, edge);

    var hdrs = http::HeaderMap { .. };
    let sid, ok_req = proxy::h2_upstream_open_stream(
        up_tls, "GET", "https", "h2.internal.test", "/tls-h2", hdrs, "127.0.0.1",
        proxy::H2UpstreamStreamEnd.EndStream, proxy::H2UpstreamHeaderFilter.DirectHeaders,
    );
    assert(ok_req && sid == 1);
    tls_exchange_up_to_edge(up_tls, cli_ep, srv_ep, edge);

    var eev = http2::H2EdgeEvent { .. };
    assert(http2::h2_edge_poll_event(edge, eev) && eev.kind == http2::H2EdgeEventKind.RequestHead);
    assert(eev.headers.entries.len >= 0);
    assert(http2::h2_edge_send_headers(edge, 1, 200, hdrs, false));
    let ds, ok_ds = http2::h2_edge_send_data(edge, 1, "tls13-h2-ok", true);
    assert(ok_ds && ds == 11);
    tls_exchange_edge_to_up(edge, srv_ep, cli_ep, up_tls);

    var uev = proxy::H2UpstreamEvent { .. };
    assert(proxy::h2_upstream_poll_event(up_tls, uev) && uev.kind == proxy::H2UpstreamEventKind.ResponseHead);
    assert(uev.status_code == 200);
    assert(proxy::h2_upstream_poll_event(up_tls, uev) && uev.kind == proxy::H2UpstreamEventKind.ResponseData);
    assert(uev.data == "tls13-h2-ok");
    assert(proxy::h2_upstream_poll_event(up_tls, uev) && uev.kind == proxy::H2UpstreamEventKind.ResponseEnd);

    print("H2_UP_TLS13_ALPN_LOOPBACK: OK\n");
    // CHECK: H2_UP_TLS13_ALPN_LOOPBACK: OK
}

// ---- Test 9: Coalesced WINDOW_UPDATE, Zero Pool Leaks & RFC Edge Errors ---

fn probe_failed_hdr_or_trailer_decode(case_idx: i64) {
    var up = proxy::h2_upstream_open(proxy::H2UpstreamConfig { .. });
    defer proxy::h2_upstream_close(up);
    var dump: u8[>..] = [];
    let _ = proxy::h2_upstream_drain_wire(up, dump);

    var req_h = http::HeaderMap { .. };
    let sid, ok = proxy::h2_upstream_open_stream(
        up, "POST", "https", "ex.com", "/probe", req_h, "",
        proxy::H2UpstreamStreamEnd.EndStream, proxy::H2UpstreamHeaderFilter.DirectHeaders,
    );
    assert(ok && sid == 1);
    var srv_enc = http2::new_dynamic_table(4096);
    var sw: u8[>..] = [];
    if (case_idx % 4) == 0 {
        var rh = http::HeaderMap { .. };
        assert(http::append_header(rh, "content-length", "5"));
        append_h2_resp_headers(sw, srv_enc, sid, 200, rh, true);
    } else if (case_idx % 4) == 1 {
        var bad_hp: u8[>..] = [];
        push_hpack_literal_no_idx(bad_hp, ":status", "99", false);
        append_h2_frame(sw, rfc::H2_FRAME_HEADERS, rfc::H2_FLAG_END_HEADERS, sid, bad_hp[..]);
    } else if (case_idx % 4) == 2 {
        var rh = http::HeaderMap { .. };
        append_h2_resp_headers(sw, srv_enc, sid, 200, rh, false);
        var bad_tr: u8[>..] = [];
        push_hpack_literal_no_idx(bad_tr, "host", "bad-trailer.com", false);
        append_h2_frame(
            sw,
            rfc::H2_FRAME_HEADERS,
            rfc::H2_FLAG_END_HEADERS | rfc::H2_FLAG_END_STREAM,
            sid,
            bad_tr[..],
        );
    } else {
        var rh = http::HeaderMap { .. };
        assert(http::append_header(rh, "content-length", "10"));
        append_h2_resp_headers(sw, srv_enc, sid, 200, rh, false);
        append_h2_frame(sw, rfc::H2_FRAME_DATA, 0, sid, "12345");
        var tr = http::HeaderMap { .. };
        assert(http::append_header(tr, "grpc-status", "0"));
        append_h2_resp_trailers(sw, srv_enc, sid, tr);
    }
    feed_and_assert_proto_err(up, sw[..], rfc::H2_ERR_PROTOCOL_ERROR);
}

fn test_h2_up_window_coalesce_and_leaks() {
    // 1. 6000 x 1-byte DATA frames without wire drain emits 0 WINDOW_UPDATE; crossing 16384 emits coalesced updates
    var up = proxy::h2_upstream_open(proxy::H2UpstreamConfig { .. });
    defer proxy::h2_upstream_close(up);
    var dump: u8[>..] = [];
    let _ = proxy::h2_upstream_drain_wire(up, dump);

    var h = http::HeaderMap { .. };
    let sid, ok = proxy::h2_upstream_open_stream(
        up, "GET", "https", "wan.ex", "/tiny-chunks", h, "",
        proxy::H2UpstreamStreamEnd.EndStream, proxy::H2UpstreamHeaderFilter.DirectHeaders,
    );
    assert(ok && sid == 1);
    dump.clear();
    let _ = proxy::h2_upstream_drain_wire(up, dump);

    var srv_enc = http2::new_dynamic_table(4096);
    var hdr_w: u8[>..] = [];
    append_h2_resp_headers(hdr_w, srv_enc, sid, 200, h, false);
    assert(proxy::h2_upstream_feed(up, hdr_w[..]));
    var ev = proxy::H2UpstreamEvent { .. };
    assert(proxy::h2_upstream_poll_event(up, ev) && ev.kind == proxy::H2UpstreamEventKind.ResponseHead);

    var rx_total: i64 = 0;
    for b in 12 {
        let _ = b;
        var batch: u8[>..] = [];
        for i in 500 {
            let _ = i;
            append_h2_frame(batch, rfc::H2_FRAME_DATA, 0, sid, "a");
        }
        assert(proxy::h2_upstream_feed(up, batch[..]));
        while proxy::h2_upstream_poll_event(up, ev) {
            if ev.kind == proxy::H2UpstreamEventKind.ResponseData {
                rx_total += ev.data.len;
            }
        }
    }
    assert(rx_total == 6000);
    dump.clear();
    assert(proxy::h2_upstream_drain_wire(up, dump) == 0);

    var rest_w: u8[>..]  = [];
    var c8k:    u8[8192] = ['b'; 8192];
    var c2192:  u8[2192] = ['c'; 2192];
    append_h2_frame(rest_w, rfc::H2_FRAME_DATA, 0, sid, c8k[..]);
    append_h2_frame(rest_w, rfc::H2_FRAME_DATA, 0, sid, c2192[..]);
    assert(proxy::h2_upstream_feed(up, rest_w[..]));
    while proxy::h2_upstream_poll_event(up, ev) {
        if ev.kind == proxy::H2UpstreamEventKind.ResponseData {
            rx_total += ev.data.len;
        }
    }
    assert(rx_total == 16384);
    var wu_w: u8[>..] = [];
    assert(proxy::h2_upstream_drain_wire(up, wu_w) == 26);
    var wr = wire::new_wire_h2_frame_reader(wu_w[..]);
    let w1h, w1p, ok1 = wire::next_frame(wr);
    let w2h, w2p, ok2 = wire::next_frame(wr);
    assert(ok1 && w1h.frame_type == rfc::H2_FRAME_WINDOW_UPDATE && w1h.stream_id == 0);
    assert(core::read_be_u32(w1p, 0) == 16384);
    assert(ok2 && w2h.frame_type == rfc::H2_FRAME_WINDOW_UPDATE && w2h.stream_id == sid);
    assert(core::read_be_u32(w2p, 0) == 16384);

    // 2. Zero H2UpHeaderNode pool leak across failed header/trailer decodes
    probe_failed_hdr_or_trailer_decode(0);
    let base_hdr_pool = proxy::g_h2_up_headers.len;
    for k in 20 {
        probe_failed_hdr_or_trailer_decode(k);
    }
    assert(proxy::g_h2_up_headers.len <= base_hdr_pool + 1);

    print("H2_UP_COALESCE_AND_NO_LEAK: OK\n");
    // CHECK: H2_UP_COALESCE_AND_NO_LEAK: OK
}

fn complete_one_up_stream(up: proxy::H2UpstreamSession&, enc: http2::DynamicTable&) -> u32 {
    var h = http::HeaderMap { .. };
    let sid, ok = proxy::h2_upstream_open_stream(
        up, "GET", "https", "ex.com", "/reuse", h, "",
        proxy::H2UpstreamStreamEnd.EndStream, proxy::H2UpstreamHeaderFilter.DirectHeaders,
    );
    assert(ok);
    var dump: u8[>..] = [];
    let _ = proxy::h2_upstream_drain_wire(up, dump);
    var sw: u8[>..] = [];
    append_h2_resp_headers(sw, enc, sid, 200, h, true);
    assert(proxy::h2_upstream_feed(up, sw[..]));
    var ev = proxy::H2UpstreamEvent { .. };
    assert(proxy::h2_upstream_poll_event(up, ev) && ev.kind == proxy::H2UpstreamEventKind.ResponseHead);
    assert(!proxy::h2_upstream_poll_event(up, ev));
    return sid;
}

fn test_h2_up_status_and_window_errors() {
    var req_h = http::HeaderMap { .. };
    var srv_enc = http2::new_dynamic_table(4096);

    // 1. 304 Not Modified with non-zero Content-Length + END_STREAM allowed; 204/304 DATA rejected
    var u304 = proxy::h2_upstream_open(proxy::H2UpstreamConfig { .. });
    defer proxy::h2_upstream_close(u304);
    let s304, ok304 = proxy::h2_upstream_open_stream(
        u304, "GET", "https", "ex.com", "/cached", req_h, "",
        proxy::H2UpstreamStreamEnd.EndStream, proxy::H2UpstreamHeaderFilter.DirectHeaders,
    );
    assert(ok304 && s304 == 1);
    var w304: u8[>..] = [];
    var rh304 = http::HeaderMap { .. };
    assert(http::append_header(rh304, "content-length", "1234"));
    append_h2_resp_headers(w304, srv_enc, s304, 304, rh304, true);
    assert(proxy::h2_upstream_feed(u304, w304[..]));
    var ev = proxy::H2UpstreamEvent { .. };
    assert(proxy::h2_upstream_poll_event(u304, ev) && ev.kind == proxy::H2UpstreamEventKind.ResponseHead);
    assert(ev.status_code == 304 && ev.end_stream && http::get_header(ev.headers, "content-length") == "1234");

    let no_body_codes: i32[2] = [204, 304];
    for st_code in no_body_codes {
        var u_bad = proxy::h2_upstream_open(proxy::H2UpstreamConfig { .. });
        let sb, okb = proxy::h2_upstream_open_stream(
            u_bad, "GET", "https", "ex.com", "/nobody", req_h, "",
            proxy::H2UpstreamStreamEnd.EndStream, proxy::H2UpstreamHeaderFilter.DirectHeaders,
        );
        assert(okb && sb == 1);
        var enc_b = http2::new_dynamic_table(4096);
        var wb: u8[>..] = [];
        append_h2_resp_headers(wb, enc_b, sb, st_code, req_h, false);
        append_h2_frame(wb, rfc::H2_FRAME_DATA, rfc::H2_FLAG_END_STREAM, sb, "x");
        feed_and_assert_proto_err(u_bad, wb[..], rfc::H2_ERR_PROTOCOL_ERROR);
        proxy::h2_upstream_close(u_bad);
    }

    // 2. WINDOW_UPDATE inc == 0 and send-window overflow on open stream -> RST_STREAM + StreamReset
    var uw = proxy::h2_upstream_open(proxy::H2UpstreamConfig { .. });
    defer proxy::h2_upstream_close(uw);
    var dump: u8[>..] = [];
    let _ = proxy::h2_upstream_drain_wire(uw, dump);
    let sw1, ok_sw1 = proxy::h2_upstream_open_stream(
        uw, "POST", "https", "ex.com", "/w1", req_h, "",
        proxy::H2UpstreamStreamEnd.OpenBody, proxy::H2UpstreamHeaderFilter.DirectHeaders,
    );
    let sw3, ok_sw3 = proxy::h2_upstream_open_stream(
        uw, "POST", "https", "ex.com", "/w3", req_h, "",
        proxy::H2UpstreamStreamEnd.OpenBody, proxy::H2UpstreamHeaderFilter.DirectHeaders,
    );
    assert(ok_sw1 && sw1 == 1 && ok_sw3 && sw3 == 3);
    dump.clear();
    let _ = proxy::h2_upstream_drain_wire(uw, dump);

    var wu_bad: u8[>..] = [];
    var wu0_p:  u8[..4] = [];
    wu0_p.append_u32_be(0);
    append_h2_frame(wu_bad, rfc::H2_FRAME_WINDOW_UPDATE, 0, sw1, wu0_p[..]);
    var wumax_p: u8[..4] = [];
    wumax_p.append_u32_be(0x7FFFFFFF);
    append_h2_frame(wu_bad, rfc::H2_FRAME_WINDOW_UPDATE, 0, sw3, wumax_p[..]);
    assert(proxy::h2_upstream_feed(uw, wu_bad[..]));

    assert(proxy::h2_upstream_poll_event(uw, ev) && ev.kind == proxy::H2UpstreamEventKind.StreamReset);
    assert(ev.stream_id == sw1 && ev.error_code == rfc::H2_ERR_PROTOCOL_ERROR);
    assert(proxy::h2_upstream_poll_event(uw, ev) && ev.kind == proxy::H2UpstreamEventKind.StreamReset);
    assert(ev.stream_id == sw3 && ev.error_code == rfc::H2_ERR_FLOW_CONTROL_ERROR);
    var rst_out: u8[>..] = [];
    assert(proxy::h2_upstream_drain_wire(uw, rst_out) == 26);
    var rr = wire::new_wire_h2_frame_reader(rst_out[..]);
    let rf1, rp1, ok_r1 = wire::next_frame(rr);
    let rf2, rp2, ok_r2 = wire::next_frame(rr);
    assert(ok_r1 && rf1.frame_type == rfc::H2_FRAME_RST_STREAM && rf1.stream_id == sw1);
    assert(core::read_be_u32(rp1, 0) == rfc::H2_ERR_PROTOCOL_ERROR);
    assert(ok_r2 && rf2.frame_type == rfc::H2_FRAME_RST_STREAM && rf2.stream_id == sw3);
    assert(core::read_be_u32(rp2, 0) == rfc::H2_ERR_FLOW_CONTROL_ERROR);

    // 3. Idle/even WINDOW_UPDATE and idle/even DATA -> PROTOCOL_ERROR; reused-slot closed sid -> STREAM_CLOSED / ignored WU
    var wu_idle_p: u8[..4] = [];
    wu_idle_p.append_u32_be(100);
    for bad_case in 5 {
        var ub = proxy::h2_upstream_open(proxy::H2UpstreamConfig { .. });
        var fw: u8[>..] = [];
        if bad_case == 0 {
            append_h2_frame(fw, rfc::H2_FRAME_WINDOW_UPDATE, 0, 99, wu0_p[..]);
        } else if bad_case == 1 {
            append_h2_frame(fw, rfc::H2_FRAME_WINDOW_UPDATE, 0, 99, wu_idle_p[..]);
        } else if bad_case == 2 {
            append_h2_frame(fw, rfc::H2_FRAME_WINDOW_UPDATE, 0, 2, wu_idle_p[..]);
        } else if bad_case == 3 {
            append_h2_frame(fw, rfc::H2_FRAME_DATA, 0, 99, "bad");
        } else {
            append_h2_frame(fw, rfc::H2_FRAME_DATA, 0, 2, "bad");
        }
        feed_and_assert_proto_err(ub, fw[..], rfc::H2_ERR_PROTOCOL_ERROR);
        proxy::h2_upstream_close(ub);
    }

    var ur = proxy::h2_upstream_open(proxy::H2UpstreamConfig { .. });
    defer proxy::h2_upstream_close(ur);
    var enc_r = http2::new_dynamic_table(4096);
    var first_sid: u32 = 0;
    for i in 135 {
        let cur = complete_one_up_stream(ur, enc_r);
        if i == 0 {
            first_sid = cur;
        }
    }
    assert(first_sid == 1);
    var closed_wu: u8[>..] = [];
    append_h2_frame(closed_wu, rfc::H2_FRAME_WINDOW_UPDATE, 0, first_sid, wu_idle_p[..]);
    assert(proxy::h2_upstream_feed(ur, closed_wu[..]));
    var late_closed_data: u8[>..] = [];
    append_h2_frame(late_closed_data, rfc::H2_FRAME_DATA, rfc::H2_FLAG_END_STREAM, first_sid, "late");
    feed_and_assert_proto_err(ur, late_closed_data[..], rfc::H2_ERR_STREAM_CLOSED);

    print("H2_UP_STATUS_AND_WINDOW_ERR: OK\n");
    // CHECK: H2_UP_STATUS_AND_WINDOW_ERR: OK
}

fn main() {
    test_h2_up_preface_headers_and_sensitive();
    test_h2_up_grpc_and_connect_loopback();
    test_h2_up_full_duplex_bidi_streaming();
    test_h2_up_wan_fanout_flow_control_and_goaway();
    test_h2_up_backpressure_continuation_and_chunks();
    test_h2_up_security_and_aba();
    test_h2_up_config_clamp_and_conn_strip();
    test_h2_up_dynamic_table_updates_and_cookie_mark();
    test_h2_up_tls13_alpn_loopback();
    test_h2_up_window_coalesce_and_leaks();
    test_h2_up_status_and_window_errors();
}
