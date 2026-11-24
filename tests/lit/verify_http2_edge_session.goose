// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Verification of TLS ALPN strict mismatch handling (`require_alpn_match` + Alert 120)
// and public sans-IO streaming `http2::H2EdgeSession` (RFC 7301, RFC 9113, RFC 7541).
//
// RUN: goose build -O2 -o %t.exe %s
// RUN: %t.exe | %FileCheck %s

import std;
import wing from "../..";

// ---- TLS Loopback Test Helpers ---------------------------------------------

fn append_pem_block(label: const u8[:], der: const u8[:], out: u8[>..]&) {
    out.append("-----BEGIN ");
    out.append(label);
    out.append("-----\n");
    var b64: u8[>..] = [];
    core::base64_encode(der, b64);
    var pos: i64 = 0;
    while pos < b64.len {
        let end = min(pos + 64, b64.len);
        out.append(b64[pos..end]);
        out.push('\n');
        pos = end;
    }
    out.append("-----END ");
    out.append(label);
    out.append("-----\n");
}

fn build_ed25519_pkcs8_pem(seed: const u8[32]&, out_pem: u8[>..]&) {
    out_pem.clear();
    var der: u8[>..] = [
        0x30, 0x2E, 0x02, 0x01, 0x00,
        0x30, 0x05, 0x06, 0x03, 0x2B, 0x65, 0x70,
        0x04, 0x22, 0x04, 0x20,
    ];
    for i in 32 { der.push(seed[i]); }
    append_pem_block("PRIVATE KEY", der[..], out_pem);
}

fn drain_and_feed_tls(src: tls::TlsEndpoint&, dst: tls::TlsEndpoint&) -> bool {
    var buf: u8[4096] = [0; 4096];
    while true {
        let n, st = tls::tls_endpoint_drain_wire(src, buf[..]);
        guard st == tls::TlsBackendStatus.Ok else { return false; }
        if n <= 0 { return true; }
        let fed, fst = tls::tls_endpoint_feed_wire(dst, buf[..n]);
        guard fst == tls::TlsBackendStatus.Ok && fed == n else { return false; }
    }
    return true;
}

fn pump_tls_until_established(cli: tls::TlsEndpoint&, srv: tls::TlsEndpoint&) -> bool {
    for _ in 32 {
        let cst = tls::tls_endpoint_step_handshake(cli);
        guard cst == tls::TlsBackendStatus.Ok ||
            cst == tls::TlsBackendStatus.WantRead ||
            cst == tls::TlsBackendStatus.WantWrite else {
            return false;
        }
        guard drain_and_feed_tls(cli, srv) else { return false; }
        let sst = tls::tls_endpoint_step_handshake(srv);
        guard sst == tls::TlsBackendStatus.Ok ||
            sst == tls::TlsBackendStatus.WantRead ||
            sst == tls::TlsBackendStatus.WantWrite else {
            return false;
        }
        guard drain_and_feed_tls(srv, cli) else { return false; }
        if cli.established && srv.established {
            return true;
        }
    }
    return false;
}

fn run_alpn_loopback_case(
    cert_pem:           const u8[:],
    key_pem:            const u8[:],
    trust:              const tls::TrustAnchorStore&,
    cli_alpn:           const u8[:],
    require_alpn_match: bool,
    srv_kind:           tls::TlsBackendKind = tls::TlsBackendKind.PureGoose,
    cli_kind:           tls::TlsBackendKind = tls::TlsBackendKind.PureGoose,
) -> tls::TlsBackendStatus, u8[..255], u8[..255], u8[..64] {
    var srv_cfg = tls::TlsBackendConfig {
        kind:                  srv_kind,
        is_server:             true,
        defer_sni_credentials: true,
        require_alpn_match:    require_alpn_match,
        ..
    };
    assert(srv_cfg.alpn_wire.try_set("h2,http/1.1"));
    var srv, srv_st = tls::tls_endpoint_open(srv_cfg);
    assert(srv_st == tls::TlsBackendStatus.Ok);
    defer tls::tls_endpoint_close(srv);

    var cli_cfg = tls::TlsBackendConfig {
        kind:                   cli_kind,
        is_server:              false,
        trust_store:            trust,
        use_system_roots:       false,
        enable_session_tickets: false,
        ..
    };
    assert(cli_cfg.server_name.try_set("edge.example.test"));
    assert(cli_cfg.alpn_wire.try_set(cli_alpn));
    var cli, cli_st = tls::tls_endpoint_open(cli_cfg);
    assert(cli_st == tls::TlsBackendStatus.Ok);
    defer tls::tls_endpoint_close(cli);

    assert(tls::tls_endpoint_step_handshake(cli) == tls::TlsBackendStatus.WantRead);
    assert(drain_and_feed_tls(cli, srv));

    var alert_rec: u8[..64] = [];
    let sst0 = tls::tls_endpoint_step_handshake(srv);
    if sst0 == tls::TlsBackendStatus.HandshakeError {
        var raw_al: u8[64] = [0; 64];
        let al_n, al_st = tls::tls_endpoint_drain_wire(srv, raw_al[..]);
        assert(al_st == tls::TlsBackendStatus.Ok && al_n > 0);
        assert(alert_rec.try_set(raw_al[..al_n]));
        return sst0, [], [], alert_rec;
    }

    assert(sst0 == tls::TlsBackendStatus.NeedSniCredentials);
    assert(tls::tls_endpoint_client_sni(srv)[..] == "edge.example.test");
    assert(tls::tls_endpoint_set_server_credentials_pem(srv, cert_pem, key_pem) == tls::TlsBackendStatus.Ok);
    assert(pump_tls_until_established(cli, srv));

    let srv_alpn = tls::tls_endpoint_selected_alpn(srv);
    let cli_alpn_sel = tls::tls_endpoint_selected_alpn(cli);
    return tls::TlsBackendStatus.Ok, srv_alpn, cli_alpn_sel, alert_rec;
}

fn test_tls_alpn_hardening() {
    let seed: u8[32] = [0x47; 32];
    var cert_der: u8[..2048] = [];
    assert(tls::build_test_ed25519_cert_der(
        seed, "edge.example.test", "edge.example.test", "127.0.0.1", cert_der,
    ));
    var cert_pem: u8[>..] = [];
    append_pem_block("CERTIFICATE", cert_der[..], cert_pem);
    var key_pem: u8[>..] = [];
    build_ed25519_pkcs8_pem(seed, key_pem);

    var trust = tls::TrustAnchorStore { .. };
    assert(tls::add_trust_anchor_cert_der(trust, cert_der[..]));

    // 1. Client offers ["h2", "http/1.1"] -> negotiates "h2"
    let st_h2, s_h2, c_h2, _ = run_alpn_loopback_case(
        cert_pem[..], key_pem[..], trust, "h2,http/1.1", true,
    );
    assert(st_h2 == tls::TlsBackendStatus.Ok && s_h2[..] == "h2" && c_h2[..] == "h2");

    // 2. Client offers ["http/1.1"] -> negotiates "http/1.1"
    let st_h1, s_h1, c_h1, _ = run_alpn_loopback_case(
        cert_pem[..], key_pem[..], trust, "http/1.1", true,
    );
    assert(st_h1 == tls::TlsBackendStatus.Ok && s_h1[..] == "http/1.1" && c_h1[..] == "http/1.1");

    // 3. Client offers ["foo/1"] with require_alpn_match: true -> fails with fatal alert 120
    let st_bad, _, _, al_rec = run_alpn_loopback_case(
        cert_pem[..], key_pem[..], trust, "foo/1", true,
    );
    assert(st_bad == tls::TlsBackendStatus.HandshakeError);
    assert(al_rec.len == 7);
    assert(al_rec[0] == rfc::TLS_CONTENT_ALERT);
    assert(al_rec[5] == 2 && al_rec[6] == rfc::TLS_ALERT_NO_APPLICATION_PROTOCOL);

    // 4. Backward compatibility: require_alpn_match: false allows mismatch without ALPN selected
    let st_opt, s_opt, c_opt, _ = run_alpn_loopback_case(
        cert_pem[..], key_pem[..], trust, "foo/1", false,
    );
    assert(st_opt == tls::TlsBackendStatus.Ok && s_opt.len == 0 && c_opt.len == 0);

    // 5. Non-deferred SNI server also fails closed with alert 120 when require_alpn_match == true
    var direct_srv_cfg = tls::TlsBackendConfig {
        kind:                  tls::TlsBackendKind.PureGoose,
        is_server:             true,
        defer_sni_credentials: false,
        require_alpn_match:    true,
        ..
    };
    assert(direct_srv_cfg.alpn_wire.try_set("h2,http/1.1"));
    assert(direct_srv_cfg.cert_der.try_set(cert_der[..]));
    direct_srv_cfg.priv_seed = seed;
    var dsrv, dsrv_st = tls::tls_endpoint_open(direct_srv_cfg);
    assert(dsrv_st == tls::TlsBackendStatus.Ok);
    defer tls::tls_endpoint_close(dsrv);

    var dcli_cfg = tls::TlsBackendConfig {
        kind:                   tls::TlsBackendKind.PureGoose,
        is_server:              false,
        trust_store:            trust,
        use_system_roots:       false,
        enable_session_tickets: false,
        ..
    };
    assert(dcli_cfg.server_name.try_set("edge.example.test"));
    assert(dcli_cfg.alpn_wire.try_set("bad/9"));
    var dcli, dcli_st = tls::tls_endpoint_open(dcli_cfg);
    assert(dcli_st == tls::TlsBackendStatus.Ok);
    defer tls::tls_endpoint_close(dcli);

    assert(tls::tls_endpoint_step_handshake(dcli) == tls::TlsBackendStatus.WantRead);
    assert(drain_and_feed_tls(dcli, dsrv));
    assert(tls::tls_endpoint_step_handshake(dsrv) == tls::TlsBackendStatus.HandshakeError);
    var dal: u8[64] = [0; 64];
    let dal_n, dal_st = tls::tls_endpoint_drain_wire(dsrv, dal[..]);
    assert(dal_st == tls::TlsBackendStatus.Ok && dal_n == 7);
    assert(dal[0] == rfc::TLS_CONTENT_ALERT && dal[5] == 2 && dal[6] == rfc::TLS_ALERT_NO_APPLICATION_PROTOCOL);

    // 6. Empty server ALPN list + require_alpn_match: true -> fails closed with alert 120
    var empty_srv_cfg = tls::TlsBackendConfig {
        kind:                  tls::TlsBackendKind.PureGoose,
        is_server:             true,
        defer_sni_credentials: false,
        require_alpn_match:    true,
        ..
    };
    assert(empty_srv_cfg.cert_der.try_set(cert_der[..]));
    empty_srv_cfg.priv_seed = seed;
    var esrv, esrv_st = tls::tls_endpoint_open(empty_srv_cfg);
    assert(esrv_st == tls::TlsBackendStatus.Ok);
    defer tls::tls_endpoint_close(esrv);

    var ecli_cfg = tls::TlsBackendConfig {
        kind:                   tls::TlsBackendKind.PureGoose,
        is_server:              false,
        trust_store:            trust,
        use_system_roots:       false,
        enable_session_tickets: false,
        ..
    };
    assert(ecli_cfg.server_name.try_set("edge.example.test"));
    assert(ecli_cfg.alpn_wire.try_set("h2"));
    var ecli, ecli_st = tls::tls_endpoint_open(ecli_cfg);
    assert(ecli_st == tls::TlsBackendStatus.Ok);
    defer tls::tls_endpoint_close(ecli);

    assert(tls::tls_endpoint_step_handshake(ecli) == tls::TlsBackendStatus.WantRead);
    assert(drain_and_feed_tls(ecli, esrv));
    assert(tls::tls_endpoint_step_handshake(esrv) == tls::TlsBackendStatus.HandshakeError);
    let eal_n, eal_st = tls::tls_endpoint_drain_wire(esrv, dal[..]);
    assert(eal_st == tls::TlsBackendStatus.Ok && eal_n == 7);
    assert(dal[0] == rfc::TLS_CONTENT_ALERT && dal[5] == 2 && dal[6] == rfc::TLS_ALERT_NO_APPLICATION_PROTOCOL);

    // 7. TlsBackendKind.Auto routes strict ALPN / in-memory trust cleanly and rejects mismatch
    let st_auto_ok, s_aok, c_aok, _ = run_alpn_loopback_case(
        cert_pem[..],
        key_pem[..],
        trust,
        "h2,http/1.1",
        true,
        tls::TlsBackendKind.Auto,
        tls::TlsBackendKind.Auto,
    );
    assert(st_auto_ok == tls::TlsBackendStatus.Ok && s_aok[..] == "h2" && c_aok[..] == "h2");

    let st_auto_bad, _, _, auto_al = run_alpn_loopback_case(
        cert_pem[..],
        key_pem[..],
        trust,
        "foo/1",
        true,
        tls::TlsBackendKind.Auto,
        tls::TlsBackendKind.Auto,
    );
    assert(st_auto_bad == tls::TlsBackendStatus.HandshakeError);
    assert(auto_al.len == 7 && auto_al[0] == rfc::TLS_CONTENT_ALERT);
    assert(auto_al[5] == 2 && auto_al[6] == rfc::TLS_ALERT_NO_APPLICATION_PROTOCOL);

    // 8. Client omitting ALPN (!has_alpn) completes without ALPN even under require_alpn_match: true
    let st_no_alpn, s_no, c_no, _ = run_alpn_loopback_case(
        cert_pem[..],
        key_pem[..],
        trust,
        "",
        true,
        tls::TlsBackendKind.Auto,
        tls::TlsBackendKind.Auto,
    );
    assert(st_no_alpn == tls::TlsBackendStatus.Ok && s_no.len == 0 && c_no.len == 0);

    print("TLS_ALPN_HARDENING: OK");
    // CHECK: TLS_ALPN_HARDENING: OK
}

// ---- HTTP/2 Wire Frame Encoding Test Helpers -------------------------------

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

fn append_h2_req_headers(
    out:        u8[>..]&,
    dt:         http2::DynamicTable&,
    stream_id:  u32,
    method:     const u8[:],
    path:       const u8[:],
    hdrs:       const http::HeaderMap&,
    end_stream: bool,
) {
    let pseudo = http2::PseudoHeaders {
        method:        method,
        scheme:        "https",
        authority:     "edge.example.test",
        path:          path,
        has_method:    true,
        has_scheme:    true,
        has_authority: true,
        has_path:      true,
        ..
    };
    var hpack_buf: u8[..16384] = [];
    assert(wire::encode_hpack_from_map(dt, pseudo, hdrs, hpack_buf, true));
    let flags: u8 = rfc::H2_FLAG_END_HEADERS | (if end_stream { rfc::H2_FLAG_END_STREAM } else { 0 });
    append_h2_frame(out, rfc::H2_FRAME_HEADERS, flags, stream_id, hpack_buf[..]);
}

// ---- H2EdgeSession Functional & Edge Tests ---------------------------------

fn test_h2_edge_preface_multiplex_upload_sse() {
    var sess = http2::h2_edge_open(128, 65535);
    defer http2::h2_edge_close(sess);
    assert(sess.slot_idx >= 0 && sess.generation != 0);

    // Feed 24-byte preface split across two calls + client SETTINGS
    var cli_wire: u8[>..] = [];
    cli_wire.append(rfc::H2_CLIENT_PREFACE[..]);
    let cli_settings: wire::WireSetting[2] = [
        wire::WireSetting { id: rfc::H2_SETTING_MAX_CONCURRENT_STREAMS, val: 128 },
        wire::WireSetting { id: rfc::H2_SETTING_INITIAL_WINDOW_SIZE, val: 65535 },
    ];
    assert(wire::encode_settings_frame(cli_settings[..], cli_wire));

    let c1, ok1 = http2::h2_edge_feed(sess, cli_wire[..10]);
    assert(ok1 && c1 == 10);
    let c2, ok2 = http2::h2_edge_feed(sess, cli_wire[10..]);
    assert(ok2 && c2 == cli_wire.len - 10);

    var srv_wire: u8[>..] = [];
    let drained = http2::h2_edge_drain_wire(sess, srv_wire);
    assert(drained > 0);

    var r = wire::new_wire_h2_frame_reader(srv_wire[..]);
    let sfh, sf_pay, ok_sf = wire::next_frame(r);
    assert(ok_sf && sfh.frame_type == rfc::H2_FRAME_SETTINGS && (sfh.flags & rfc::H2_FLAG_ACK) == 0);
    assert(sf_pay.len == 24);
    let ackh, _, ok_ack = wire::next_frame(r);
    assert(ok_ack && ackh.frame_type == rfc::H2_FRAME_SETTINGS && (ackh.flags & rfc::H2_FLAG_ACK) != 0);

    // Client ACKs server SETTINGS + sends PING + PRIORITY(5B)
    var ctrl_wire: u8[>..] = [];
    append_h2_frame(ctrl_wire, rfc::H2_FRAME_SETTINGS, rfc::H2_FLAG_ACK, 0, "");
    let ping_opaque: u8[8] = [1, 2, 3, 4, 5, 6, 7, 8];
    append_h2_frame(ctrl_wire, rfc::H2_FRAME_PING, 0, 0, ping_opaque[..]);
    let prio_pay: u8[5] = [0x00, 0x00, 0x00, 0x00, 15];
    append_h2_frame(ctrl_wire, rfc::H2_FRAME_PRIORITY, 0, 1, prio_pay[..]);
    let c3, ok3 = http2::h2_edge_feed(sess, ctrl_wire[..]);
    assert(ok3 && c3 == ctrl_wire.len);

    srv_wire.clear();
    let _ = http2::h2_edge_drain_wire(sess, srv_wire);
    var r_ping = wire::new_wire_h2_frame_reader(srv_wire[..]);
    let ph, p_pay, ok_p = wire::next_frame(r_ping);
    assert(ok_p && ph.frame_type == rfc::H2_FRAME_PING && (ph.flags & rfc::H2_FLAG_ACK) != 0);
    assert(p_pay == ping_opaque[..]);

    // Multiplex 4 concurrent streams:
    //   Stream 1: GET /alpha (end_stream=true)
    //   Stream 3: POST /upload (128 KiB streaming upload across 8x16 KiB DATA frames)
    //   Stream 5: GET /events (SSE incremental multi-chunk response)
    //   Stream 7: POST /trailers (body + trailing HEADERS)
    var cli_dt = http2::new_dynamic_table(4096);
    var h1 = http::HeaderMap { .. };
    assert(http::append_header(h1, "x-req", "one"));
    var h3 = http::HeaderMap { .. };
    assert(http::append_header(h3, "content-type", "application/octet-stream"));
    var h5 = http::HeaderMap { .. };
    assert(http::append_header(h5, "accept", "text/event-stream"));
    var h7 = http::HeaderMap { .. };
    assert(http::append_header(h7, "te", "trailers"));

    var reqs_wire: u8[>..] = [];
    append_h2_req_headers(reqs_wire, cli_dt, 1, "GET", "/alpha", h1, true);
    append_h2_req_headers(reqs_wire, cli_dt, 3, "POST", "/upload", h3, false);
    append_h2_req_headers(reqs_wire, cli_dt, 5, "GET", "/events", h5, true);
    append_h2_req_headers(reqs_wire, cli_dt, 7, "POST", "/trailers", h7, false);

    let cr, ok_cr = http2::h2_edge_feed(sess, reqs_wire[..]);
    assert(ok_cr && cr == reqs_wire.len);

    // Poll all 4 RequestHead events immediately without waiting for body DATA
    var ev = http2::H2EdgeEvent { .. };
    var seen_heads: i32 = 0;
    while http2::h2_edge_poll_event(sess, ev) {
        assert(ev.kind == http2::H2EdgeEventKind.RequestHead);
        seen_heads += 1;
        if ev.stream_id == 1 {
            assert(ev.end_stream);
            assert(http::get_header(ev.headers, ":method") == "GET");
            assert(http::get_header(ev.headers, ":path") == "/alpha");
            assert(http::get_header(ev.headers, "x-req") == "one");
        } else if ev.stream_id == 3 {
            assert(!ev.end_stream);
            assert(http::get_header(ev.headers, ":method") == "POST");
        } else if ev.stream_id == 5 {
            assert(ev.end_stream);
            assert(http::get_header(ev.headers, ":path") == "/events");
        } else {
            assert(ev.stream_id == 7 && !ev.end_stream);
            assert(http::get_header(ev.headers, "te") == "trailers");
        }
    }
    assert(seen_heads == 4);

    // Stream 3: 128 KiB (8 x 16 KiB) streaming POST upload with WINDOW_UPDATE replenishment
    var upload_chunk: u8[16384] = [0; 16384];
    var total_rx:     i64       = 0;
    var wu_count:     i32       = 0;
    var rx_ended = false;
    for chunk_idx in 8 {
        for j in 16384 {
            upload_chunk[j] = ((chunk_idx * 31 + j) & 0xFF) as u8;
        }
        var d_wire: u8[>..] = [];
        let is_last = chunk_idx == 7;
        append_h2_frame(
            d_wire,
            rfc::H2_FRAME_DATA,
            if is_last { rfc::H2_FLAG_END_STREAM } else { 0 },
            3,
            upload_chunk[..],
        );
        // Split frame across two feed calls on chunk 2 to verify partial frame reassembly
        if chunk_idx == 2 {
            let f1, ok_f1 = http2::h2_edge_feed(sess, d_wire[..5000]);
            let f2, ok_f2 = http2::h2_edge_feed(sess, d_wire[5000..]);
            assert(ok_f1 && ok_f2 && f1 + f2 == d_wire.len);
        } else {
            let f_all, ok_fall = http2::h2_edge_feed(sess, d_wire[..]);
            assert(ok_fall && f_all == d_wire.len);
        }

        while http2::h2_edge_poll_event(sess, ev) {
            if ev.kind == http2::H2EdgeEventKind.RequestData {
                assert(ev.stream_id == 3 && ev.data.len == 16384);
                assert(ev.data[0] == ((chunk_idx * 31) & 0xFF) as u8);
                assert(ev.data[16383] == ((chunk_idx * 31 + 16383) & 0xFF) as u8);
                total_rx += ev.data.len;
            } else if ev.kind == http2::H2EdgeEventKind.RequestEnd {
                assert(ev.stream_id == 3 && ev.end_stream);
                rx_ended = true;
            }
        }

        srv_wire.clear();
        let _ = http2::h2_edge_drain_wire(sess, srv_wire);
        var rw = wire::new_wire_h2_frame_reader(srv_wire[..]);
        while wire::has_next(rw) {
            let wh, _, ok_w = wire::next_frame(rw);
            assert(ok_w);
            if wh.frame_type == rfc::H2_FRAME_WINDOW_UPDATE {
                wu_count += 1;
            }
        }
    }
    assert(total_rx == 131072 && rx_ended && wu_count >= 8);

    // Stream 7: DATA + trailing HEADERS
    var tr_wire: u8[>..] = [];
    append_h2_frame(tr_wire, rfc::H2_FRAME_DATA, 0, 7, "hello-tr");
    var tr_hdrs = http::HeaderMap { .. };
    assert(http::append_header(tr_hdrs, "x-checksum", "abc123"));
    var tr_hpack: u8[..1024] = [];
    let tr_pseudo = http2::PseudoHeaders { is_trailer: true, .. };
    assert(wire::encode_hpack_from_map(cli_dt, tr_pseudo, tr_hdrs, tr_hpack, true));
    append_h2_frame(
        tr_wire,
        rfc::H2_FRAME_HEADERS,
        rfc::H2_FLAG_END_HEADERS | rfc::H2_FLAG_END_STREAM,
        7,
        tr_hpack[..],
    );
    let ct, ok_ct = http2::h2_edge_feed(sess, tr_wire[..]);
    assert(ok_ct && ct == tr_wire.len);
    var saw_tr_data = false;
    var saw_tr_end = false;
    while http2::h2_edge_poll_event(sess, ev) {
        if ev.kind == http2::H2EdgeEventKind.RequestData {
            assert(ev.stream_id == 7 && ev.data == "hello-tr");
            saw_tr_data = true;
        } else if ev.kind == http2::H2EdgeEventKind.RequestEnd {
            assert(ev.stream_id == 7 && ev.end_stream);
            assert(http::get_header(ev.headers, "x-checksum") == "abc123");
            saw_tr_end = true;
        }
    }
    assert(saw_tr_data && saw_tr_end);

    // Stream 5: SSE incremental response flush before end_stream = true
    var sse_hdrs = http::HeaderMap { .. };
    assert(http::append_header(sse_hdrs, "content-type", "text/event-stream"));
    assert(http::append_header(sse_hdrs, "connection", "keep-alive"));
    assert(http2::h2_edge_send_headers(sess, 5, 200, sse_hdrs, false));
    srv_wire.clear();
    let _ = http2::h2_edge_drain_wire(sess, srv_wire);
    var rs0 = wire::new_wire_h2_frame_reader(srv_wire[..]);
    let sh0, _, ok_s0 = wire::next_frame(rs0);
    assert(ok_s0 && sh0.frame_type == rfc::H2_FRAME_HEADERS);
    assert((sh0.flags & rfc::H2_FLAG_END_STREAM) == 0);
    assert((sh0.flags & rfc::H2_FLAG_END_HEADERS) != 0);

    let s1, ok_d1 = http2::h2_edge_send_data(sess, 5, "data: tick1\n\n", false);
    assert(ok_d1 && s1 == 13);
    srv_wire.clear();
    let _ = http2::h2_edge_drain_wire(sess, srv_wire);
    var rs1 = wire::new_wire_h2_frame_reader(srv_wire[..]);
    let dh1, dp1, ok_dp1 = wire::next_frame(rs1);
    assert(ok_dp1 && dh1.frame_type == rfc::H2_FRAME_DATA);
    assert((dh1.flags & rfc::H2_FLAG_END_STREAM) == 0 && dp1 == "data: tick1\n\n");

    let s2, ok_d2 = http2::h2_edge_send_data(sess, 5, "data: tick2\n\n", true);
    assert(ok_d2 && s2 == 13);
    srv_wire.clear();
    let _ = http2::h2_edge_drain_wire(sess, srv_wire);
    var rs2 = wire::new_wire_h2_frame_reader(srv_wire[..]);
    let dh2, dp2, ok_dp2 = wire::next_frame(rs2);
    assert(ok_dp2 && dh2.frame_type == rfc::H2_FRAME_DATA);
    assert((dh2.flags & rfc::H2_FLAG_END_STREAM) != 0 && dp2 == "data: tick2\n\n");

    // Stream 1: Send >16 KiB response header block -> HEADERS + CONTINUATION split
    var big_hdrs = http::HeaderMap { .. };
    var big_val: u8[1500] = ['v'; 1500];
    let val_off = big_hdrs.raw_buf.len as u16;
    assert(big_hdrs.raw_buf.try_append(big_val[..]));
    let val_end = big_hdrs.raw_buf.len as u16;
    for i in 16 {
        var name: u8[..16] = [];
        assert(name.try_append("x-big-hdr-"));
        (i as u64).format_u64_dec(name);
        let n_off = big_hdrs.raw_buf.len as u16;
        assert(big_hdrs.raw_buf.try_append(name[..]));
        let n_end = big_hdrs.raw_buf.len as u16;
        let idx = big_hdrs.entries.len as u8;
        assert(big_hdrs.entries.try_push(http::HeaderEntry {
            name_begin:    n_off,
            name_end:      n_end,
            values_begin:  val_off,
            values_end:    val_end,
            next_idx:      0xFF,
            flags:         0,
            well_known_id: 0xFF,
            reserved:      0,
            name_hash:     http::hash_header_name(name[..]),
        }));
        assert(big_hdrs.header_contains_comma.try_push(false));
        let _ = idx;
    }
    assert(http2::h2_edge_send_headers(sess, 1, 200, big_hdrs, true));
    srv_wire.clear();
    let _ = http2::h2_edge_drain_wire(sess, srv_wire);
    var rbig = wire::new_wire_h2_frame_reader(srv_wire[..]);
    let bh1, bf1, ok_b1 = wire::next_frame(rbig);
    let bh2, bf2, ok_b2 = wire::next_frame(rbig);
    assert(ok_b1 && bh1.frame_type == rfc::H2_FRAME_HEADERS);
    assert(bh1.length == 16384 && (bh1.flags & rfc::H2_FLAG_END_HEADERS) == 0);
    assert((bh1.flags & rfc::H2_FLAG_END_STREAM) != 0);
    assert(ok_b2 && bh2.frame_type == rfc::H2_FRAME_CONTINUATION);
    assert((bh2.flags & rfc::H2_FLAG_END_HEADERS) != 0 && (bh2.flags & rfc::H2_FLAG_END_STREAM) == 0);

    var combined_hpack: u8[>..] = [];
    combined_hpack.append(bf1);
    combined_hpack.append(bf2);
    assert(combined_hpack.len > 16384);
    var srv_dec = http2::new_dynamic_table(4096);
    var dec_pseudo = http2::PseudoHeaders { .. };
    var dec_map = http::HeaderMap { .. };
    var dec_off: u64 = 0;
    var updates_ok = true;
    var upd_cnt:   u32 = 0;
    var big_count: i32 = 0;
    while dec_off < (combined_hpack.len as u64) {
        dec_map.clear();
        dec_pseudo.has_regular_header = false;
        let next_off, step_err = http2::decode_hpack_field_step_to_map(
            srv_dec, combined_hpack[..], dec_off, updates_ok, upd_cnt,
            dec_pseudo, dec_map, 65536, true,
        );
        assert(step_err == rfc::H2_ERR_NO_ERROR);
        if dec_map.entries.len > 0 {
            let v15 = http::get_header(dec_map, "x-big-hdr-15");
            if v15.len == 1500 {
                big_count += 1;
            }
        }
        dec_off = next_off;
    }
    assert(dec_pseudo.has_status && dec_pseudo.status == 200 && big_count == 1);

    print("H2_EDGE_STREAMING_AND_CONTINUATION: OK");
    // CHECK: H2_EDGE_STREAMING_AND_CONTINUATION: OK
}

fn test_h2_edge_security_and_aba() {
    // 1. Reject RFC 9113 forbidden hop-by-hop headers (Connection, Transfer-Encoding, Upgrade)
    var sess = http2::h2_edge_open(128, 65535);
    var cli_wire: u8[>..] = [];
    cli_wire.append(rfc::H2_CLIENT_PREFACE[..]);
    append_h2_frame(cli_wire, rfc::H2_FRAME_SETTINGS, 0, 0, "");
    let c0, ok0 = http2::h2_edge_feed(sess, cli_wire[..]);
    assert(ok0 && c0 == cli_wire.len);
    var dump: u8[>..] = [];
    let _ = http2::h2_edge_drain_wire(sess, dump);

    var bad_dt = http2::new_dynamic_table(4096);
    let bad_names: const u8[:][3] = ["connection", "transfer-encoding", "upgrade"];
    let bad_vals:  const u8[:][3] = ["close", "chunked", "websocket"];
    for i in 3 {
        var hpack_bad: u8[..512] = [];
        let inc = http2::HpackIndexing.None;
        assert(http2::encode_hpack_field(bad_dt, hpack_bad, ":method", "GET", inc, false));
        assert(http2::encode_hpack_field(bad_dt, hpack_bad, ":scheme", "https", inc, false));
        assert(http2::encode_hpack_field(bad_dt, hpack_bad, ":authority", "edge.example.test", inc, false));
        assert(http2::encode_hpack_field(bad_dt, hpack_bad, ":path", "/bad", inc, false));
        assert(http2::encode_hpack_field(bad_dt, hpack_bad, bad_names[i], bad_vals[i], inc, false));
        var w: u8[>..] = [];
        append_h2_frame(
            w, rfc::H2_FRAME_HEADERS, rfc::H2_FLAG_END_HEADERS | rfc::H2_FLAG_END_STREAM, (i * 2 + 1) as u32, hpack_bad[..],
        );
        let cf, ok_f = http2::h2_edge_feed(sess, w[..]);
        assert(ok_f && cf == w.len);
        var ev = http2::H2EdgeEvent { .. };
        assert(http2::h2_edge_poll_event(sess, ev));
        assert(ev.kind == http2::H2EdgeEventKind.StreamReset);
        assert(ev.error_code == rfc::H2_ERR_PROTOCOL_ERROR);
        dump.clear();
        let _ = http2::h2_edge_drain_wire(sess, dump);
        var rr = wire::new_wire_h2_frame_reader(dump[..]);
        let rh, _, ok_r = wire::next_frame(rr);
        assert(ok_r && rh.frame_type == rfc::H2_FRAME_RST_STREAM);
    }

    // Verify two-level flow-control backpressure (0 silent drops)
    var ok_h = http::HeaderMap { .. };
    var w_ok: u8[>..] = [];
    append_h2_req_headers(w_ok, bad_dt, 9, "GET", "/fc", ok_h, true);
    let cs_set: wire::WireSetting[1] = [
        wire::WireSetting { id: rfc::H2_SETTING_INITIAL_WINDOW_SIZE, val: 1000 },
    ];
    assert(wire::encode_settings_frame(cs_set[..], w_ok));
    let cf9, ok_f9 = http2::h2_edge_feed(sess, w_ok[..]);
    assert(ok_f9 && cf9 == w_ok.len);
    var ev9 = http2::H2EdgeEvent { .. };
    assert(http2::h2_edge_poll_event(sess, ev9) && ev9.kind == http2::H2EdgeEventKind.RequestHead);
    assert(http2::h2_edge_send_headers(sess, 9, 200, ok_h, false));
    var big_body: u8[2500] = ['Z'; 2500];
    let s_a, ok_sa = http2::h2_edge_send_data(sess, 9, big_body[..], true);
    assert(ok_sa && s_a == 1000);
    let s_b, ok_sb = http2::h2_edge_send_data(sess, 9, big_body[1000..], true);
    assert(ok_sb && s_b == 0);
    var wu_wire: u8[>..] = [];
    assert(wire::encode_window_update_frame(9, 1500, wu_wire));
    let _, ok_wu = http2::h2_edge_feed(sess, wu_wire[..]);
    assert(ok_wu);
    let s_d, ok_sd = http2::h2_edge_send_data(sess, 9, big_body[1000..], true);
    assert(ok_sd && s_d == 1500);

    dump.clear();
    let _ = http2::h2_edge_drain_wire(sess, dump);
    var r9 = wire::new_wire_h2_frame_reader(dump[..]);
    var data9_bytes:     i64  = 0;
    var saw_end_stream9: bool = false;
    while wire::has_next(r9) {
        let dh9, dp9, ok_r9 = wire::next_frame(r9);
        assert(ok_r9);
        if dh9.stream_id == 9 && dh9.frame_type == rfc::H2_FRAME_DATA {
            data9_bytes += dp9.len;
            if data9_bytes < 2500 {
                assert((dh9.flags & rfc::H2_FLAG_END_STREAM) == 0);
            } else {
                assert((dh9.flags & rfc::H2_FLAG_END_STREAM) != 0);
                saw_end_stream9 = true;
            }
        }
    }
    assert(data9_bytes == 2500 && saw_end_stream9);

    // 2. ABA guard on closed session reused by a fresh session
    let stale_sess = sess;
    http2::h2_edge_close(sess);
    var sess_new = http2::h2_edge_open(128, 65535);
    assert(sess_new.slot_idx == stale_sess.slot_idx && sess_new.generation != stale_sess.generation);
    var mut_stale = stale_sess;
    let _, stale_feed_ok = http2::h2_edge_feed(mut_stale, rfc::H2_CLIENT_PREFACE[..]);
    assert(!stale_feed_ok);
    assert(!http2::h2_edge_send_goaway(mut_stale, 0));
    http2::h2_edge_close(sess_new);

    // 3. Rapid Reset flood (RST_STREAM burst beyond token bucket -> GOAWAY(ENHANCE_YOUR_CALM))
    var flood_sess = http2::h2_edge_open(128, 65535);
    defer http2::h2_edge_close(flood_sess);
    var flood_pref: u8[>..] = [];
    flood_pref.append(rfc::H2_CLIENT_PREFACE[..]);
    append_h2_frame(flood_pref, rfc::H2_FRAME_SETTINGS, 0, 0, "");
    let _, ok_p = http2::h2_edge_feed(flood_sess, flood_pref[..]);
    assert(ok_p);
    var f_dt = http2::new_dynamic_table(4096);
    var empty_h = http::HeaderMap { .. };
    var hit_calm = false;
    for k in 1010 {
        let sid = (k * 2 + 1) as u32;
        var fw: u8[>..] = [];
        append_h2_req_headers(fw, f_dt, sid, "GET", "/rst", empty_h, false);
        var rst_p: u8[4] = [0, 0, 0, rfc::H2_ERR_CANCEL as u8];
        append_h2_frame(fw, rfc::H2_FRAME_RST_STREAM, 0, sid, rst_p[..]);
        let _, ok_fw = http2::h2_edge_feed(flood_sess, fw[..]);
        var fev = http2::H2EdgeEvent { .. };
        while http2::h2_edge_poll_event(flood_sess, fev) {
            if fev.kind == http2::H2EdgeEventKind.ProtocolError &&
               fev.error_code == rfc::H2_ERR_ENHANCE_YOUR_CALM {
                hit_calm = true;
            }
        }
        if !ok_fw {
            break;
        }
    }
    assert(hit_calm);
    dump.clear();
    let _ = http2::h2_edge_drain_wire(flood_sess, dump);
    var gr = wire::new_wire_h2_frame_reader(dump[..]);
    var saw_goaway_calm = false;
    while wire::has_next(gr) {
        let gh, gp, ok_g = wire::next_frame(gr);
        assert(ok_g);
        if gh.frame_type == rfc::H2_FRAME_GOAWAY && gp.len >= 8 {
            let err_c = core::read_be_u32(gp, 4);
            if err_c == rfc::H2_ERR_ENHANCE_YOUR_CALM {
                saw_goaway_calm = true;
            }
        }
    }
    assert(saw_goaway_calm);

    // 4. CONTINUATION interleaving violation -> GOAWAY(PROTOCOL_ERROR)
    var cont_sess = http2::h2_edge_open(128, 65535);
    defer http2::h2_edge_close(cont_sess);
    var cont_pref: u8[>..] = [];
    cont_pref.append(rfc::H2_CLIENT_PREFACE[..]);
    append_h2_frame(cont_pref, rfc::H2_FRAME_SETTINGS, 0, 0, "");
    let _, ok_cp = http2::h2_edge_feed(cont_sess, cont_pref[..]);
    assert(ok_cp);
    var cw: u8[>..] = [];
    let frag: u8[2] = [0x82, 0x87];
    append_h2_frame(cw, rfc::H2_FRAME_HEADERS, 0, 1, frag[..]);
    let ping_p: u8[8] = [0; 8];
    append_h2_frame(cw, rfc::H2_FRAME_PING, 0, 0, ping_p[..]);
    let _, ok_cf = http2::h2_edge_feed(cont_sess, cw[..]);
    assert(!ok_cf);
    var cev = http2::H2EdgeEvent { .. };
    var saw_proto_err = false;
    while http2::h2_edge_poll_event(cont_sess, cev) {
        if cev.kind == http2::H2EdgeEventKind.ProtocolError &&
           cev.error_code == rfc::H2_ERR_PROTOCOL_ERROR {
            saw_proto_err = true;
        }
    }
    assert(saw_proto_err);

    // 5. Partial header split, padded DATA, 103 Early Hints, client GOAWAY, reset_stream, send_goaway, WINDOW_UPDATE overflow
    var s5 = http2::h2_edge_open(128, 65535);
    defer http2::h2_edge_close(s5);
    var p5_cli: u8[>..] = [];
    p5_cli.append(rfc::H2_CLIENT_PREFACE[..]);
    append_h2_frame(p5_cli, rfc::H2_FRAME_SETTINGS, 0, 0, "");
    var p5_dt = http2::new_dynamic_table(4096);
    var p5_h = http::HeaderMap { .. };
    append_h2_req_headers(p5_cli, p5_dt, 1, "POST", "/pad", p5_h, false);
    let pad_pay: u8[7] = [0x02, 'o', 'k', '!', '!', 0x00, 0x00];
    append_h2_frame(p5_cli, rfc::H2_FRAME_DATA, rfc::H2_FLAG_PADDED | rfc::H2_FLAG_END_STREAM, 1, pad_pay[..]);
    append_h2_req_headers(p5_cli, p5_dt, 3, "GET", "/rstme", p5_h, true);
    var go_p: u8[..8] = [];
    go_p.append_u32_be(0);
    go_p.append_u32_be(rfc::H2_ERR_NO_ERROR);
    append_h2_frame(p5_cli, rfc::H2_FRAME_GOAWAY, 0, 0, go_p[..]);
    var p5_off: i64 = 0;
    let p5_splits: i64[4] = [24, 5, 19, p5_cli.len];
    for sp in p5_splits {
        if p5_off < p5_cli.len {
            let end_i = min(p5_cli.len, if sp == p5_cli.len { sp } else { p5_off + sp });
            let got, ok_p5 = http2::h2_edge_feed(s5, p5_cli[p5_off..end_i]);
            assert(ok_p5 && got == end_i - p5_off);
            p5_off = end_i;
        }
    }
    var ev5 = http2::H2EdgeEvent { .. };
    var s5_pad_ok = false;
    var s5_goaway_ok = false;
    while http2::h2_edge_poll_event(s5, ev5) {
        if ev5.kind == http2::H2EdgeEventKind.RequestData && ev5.stream_id == 1 {
            assert(ev5.data == "ok!!");
            s5_pad_ok = true;
        } else if ev5.kind == http2::H2EdgeEventKind.GoAway {
            assert(ev5.stream_id == 0 && ev5.error_code == rfc::H2_ERR_NO_ERROR);
            s5_goaway_ok = true;
        }
    }
    assert(s5_pad_ok && s5_goaway_ok);
    assert(http2::h2_edge_send_headers(s5, 1, 103, p5_h, false));
    assert(http2::h2_edge_send_headers(s5, 1, 200, p5_h, true));
    assert(http2::h2_edge_reset_stream(s5, 3, rfc::H2_ERR_CANCEL));
    assert(http2::h2_edge_send_goaway(s5, rfc::H2_ERR_NO_ERROR));
    var wu_over: u8[>..] = [];
    assert(wire::encode_window_update_frame(0, 0x7FFFFFFF, wu_over));
    let _, ok_wuo = http2::h2_edge_feed(s5, wu_over[..]);
    assert(!ok_wuo);
    assert(http2::h2_edge_poll_event(s5, ev5) && ev5.kind == http2::H2EdgeEventKind.ProtocolError);
    assert(ev5.error_code == rfc::H2_ERR_FLOW_CONTROL_ERROR);

    print("H2_EDGE_SECURITY_AND_ABA: OK");
    // CHECK: H2_EDGE_SECURITY_AND_ABA: OK
}

thread_fn edge_worker_thread(arg: i64) {
    let _ = arg;
    var sess = http2::h2_edge_open(128, 65535);
    defer http2::h2_edge_close(sess);
    var cli_wire: u8[>..] = [];
    cli_wire.append(rfc::H2_CLIENT_PREFACE[..]);
    append_h2_frame(cli_wire, rfc::H2_FRAME_SETTINGS, 0, 0, "");
    var dt = http2::new_dynamic_table(4096);
    var hdrs = http::HeaderMap { .. };
    append_h2_req_headers(cli_wire, dt, 1, "GET", "/thread", hdrs, true);
    let _, ok = http2::h2_edge_feed(sess, cli_wire[..]);
    assert(ok);
    var ev = http2::H2EdgeEvent { .. };
    assert(http2::h2_edge_poll_event(sess, ev) && ev.kind == http2::H2EdgeEventKind.RequestHead);
    assert(http::get_header(ev.headers, ":path") == "/thread");
    assert(http2::h2_edge_send_headers(sess, 1, 200, hdrs, true));
    var out_w: u8[>..] = [];
    assert(http2::h2_edge_drain_wire(sess, out_w) > 0);
}

fn test_h2_edge_round1_regressions() {
    // 1. No conn_recv_window leak on post-reset DATA + even idle stream fails closed with GOAWAY
    var s1 = http2::h2_edge_open(128, 65535);
    defer http2::h2_edge_close(s1);
    var out1: u8[>..] = [];
    let _ = http2::h2_edge_drain_wire(s1, out1);
    var r_init = wire::new_wire_h2_frame_reader(out1[..]);
    let init_h, init_p, ok_init = wire::next_frame(r_init);
    assert(ok_init && init_h.frame_type == rfc::H2_FRAME_SETTINGS && init_p.len == 24);
    assert(core::read_be_u16(init_p, 18) == rfc::H2_SETTING_MAX_HEADER_LIST_SIZE);
    assert(core::read_be_u32(init_p, 20) == 65535);

    var w1: u8[>..] = [];
    w1.append(rfc::H2_CLIENT_PREFACE[..]);
    append_h2_frame(w1, rfc::H2_FRAME_SETTINGS, 0, 0, "");
    var dt1 = http2::new_dynamic_table(4096);
    var h1 = http::HeaderMap { .. };
    append_h2_req_headers(w1, dt1, 1, "POST", "/drop", h1, false);
    let _, ok_w1 = http2::h2_edge_feed(s1, w1[..]);
    assert(ok_w1);
    assert(http2::h2_edge_reset_stream(s1, 1, rfc::H2_ERR_CANCEL));
    out1.clear();
    let _ = http2::h2_edge_drain_wire(s1, out1);

    var big_chunk:    u8[16384] = [0x41; 16384];
    var conn_wu_seen: i32       = 0;
    for k in 5 {
        var dw: u8[>..] = [];
        append_h2_frame(dw, rfc::H2_FRAME_DATA, if k == 4 { rfc::H2_FLAG_END_STREAM } else { 0 }, 1, big_chunk[..]);
        let _, ok_dk = http2::h2_edge_feed(s1, dw[..]);
        assert(ok_dk);
        out1.clear();
        let _ = http2::h2_edge_drain_wire(s1, out1);
        var rd = wire::new_wire_h2_frame_reader(out1[..]);
        var saw_rst_sc = false;
        while wire::has_next(rd) {
            let dh, dp, ok_dh = wire::next_frame(rd);
            assert(ok_dh);
            if dh.frame_type == rfc::H2_FRAME_RST_STREAM && dp.len == 4 {
                if core::read_be_u32(dp, 0) == rfc::H2_ERR_STREAM_CLOSED {
                    saw_rst_sc = true;
                }
            } else if dh.frame_type == rfc::H2_FRAME_WINDOW_UPDATE && dh.stream_id == 0 {
                conn_wu_seen += 1;
            }
        }
        assert(saw_rst_sc);
    }
    assert(conn_wu_seen >= 5);

    var ev1 = http2::H2EdgeEvent { .. };
    while http2::h2_edge_poll_event(s1, ev1) {}
    var w3: u8[>..] = [];
    append_h2_req_headers(w3, dt1, 3, "POST", "/ok", h1, false);
    for _ in 4 {
        append_h2_frame(w3, rfc::H2_FRAME_DATA, 0, 3, big_chunk[..]);
    }
    append_h2_frame(w3, rfc::H2_FRAME_DATA, rfc::H2_FLAG_END_STREAM, 3, "");
    let _, ok_w3 = http2::h2_edge_feed(s1, w3[..]);
    assert(ok_w3);
    var rx3: i64 = 0;
    while http2::h2_edge_poll_event(s1, ev1) {
        if ev1.kind == http2::H2EdgeEventKind.RequestData && ev1.stream_id == 3 {
            rx3 += ev1.data.len;
        }
    }
    assert(rx3 == 65536);

    // Even idle stream ID 2 (<= last_peer_stream_id 3) MUST fail connection with GOAWAY(PROTOCOL_ERROR)
    var w_even: u8[>..] = [];
    append_h2_frame(w_even, rfc::H2_FRAME_DATA, rfc::H2_FLAG_END_STREAM, 2, "bad");
    let _, ok_even = http2::h2_edge_feed(s1, w_even[..]);
    assert(!ok_even);
    var saw_even_err = false;
    while http2::h2_edge_poll_event(s1, ev1) {
        if ev1.kind == http2::H2EdgeEventKind.ProtocolError && ev1.error_code == rfc::H2_ERR_PROTOCOL_ERROR {
            saw_even_err = true;
        }
    }
    assert(saw_even_err);

    // 2. Drained PING frames exceed 64 cleanly; undrained PING flood triggers ENHANCE_YOUR_CALM
    var s_ping = http2::h2_edge_open(128, 65535);
    defer http2::h2_edge_close(s_ping);
    var ping_pref: u8[>..] = [];
    ping_pref.append(rfc::H2_CLIENT_PREFACE[..]);
    append_h2_frame(ping_pref, rfc::H2_FRAME_SETTINGS, 0, 0, "");
    let _, ok_pp = http2::h2_edge_feed(s_ping, ping_pref[..]);
    assert(ok_pp);
    out1.clear();
    let _ = http2::h2_edge_drain_wire(s_ping, out1);
    let p_bytes: u8[8] = [0x11; 8];
    var pf: u8[>..] = [];
    append_h2_frame(pf, rfc::H2_FRAME_PING, 0, 0, p_bytes[..]);
    for _ in 72 {
        let _, ok_p1 = http2::h2_edge_feed(s_ping, pf[..]);
        assert(ok_p1);
        out1.clear();
        assert(http2::h2_edge_drain_wire(s_ping, out1) > 0);
    }

    var s_flood = http2::h2_edge_open(128, 65535);
    defer http2::h2_edge_close(s_flood);
    let _, ok_pf0 = http2::h2_edge_feed(s_flood, ping_pref[..]);
    assert(ok_pf0);
    out1.clear();
    let _ = http2::h2_edge_drain_wire(s_flood, out1);
    var ping_flood_hit = false;
    for _ in 70 {
        let _, ok_p2 = http2::h2_edge_feed(s_flood, pf[..]);
        if !ok_p2 {
            ping_flood_hit = true;
            break;
        }
    }
    assert(ping_flood_hit);

    // 3. Split REFUSED_STREAM CONTINUATION updates last_peer_stream_id, syncs HPACK, and handles pipelined DATA/RST
    var s_ref = http2::h2_edge_open(1, 65535);
    defer http2::h2_edge_close(s_ref);
    var ref_dt = http2::new_dynamic_table(4096);
    var ref_w: u8[>..] = [];
    ref_w.append(rfc::H2_CLIENT_PREFACE[..]);
    append_h2_frame(ref_w, rfc::H2_FRAME_SETTINGS, 0, 0, "");
    var h_empty = http::HeaderMap { .. };
    append_h2_req_headers(ref_w, ref_dt, 1, "POST", "/hold", h_empty, false);
    let _, ok_r1 = http2::h2_edge_feed(s_ref, ref_w[..]);
    assert(ok_r1);

    var ref_h = http::HeaderMap { .. };
    assert(http::append_header(ref_h, "x-refused-dyn", "synced-val-42"));
    var ref_hpack: u8[..1024] = [];
    let ref_pseudo = http2::PseudoHeaders {
        method:        "POST",
        scheme:        "https",
        authority:     "edge.example.test",
        path:          "/refused",
        has_method:    true,
        has_scheme:    true,
        has_authority: true,
        has_path:      true,
        ..
    };
    assert(wire::encode_hpack_from_map(ref_dt, ref_pseudo, ref_h, ref_hpack, true));
    let split_at = ref_hpack.len / 2;
    var ref_split: u8[>..] = [];
    append_h2_frame(ref_split, rfc::H2_FRAME_HEADERS, 0, 3, ref_hpack[..split_at]);
    append_h2_frame(ref_split, rfc::H2_FRAME_CONTINUATION, rfc::H2_FLAG_END_HEADERS, 3, ref_hpack[split_at..]);
    append_h2_frame(ref_split, rfc::H2_FRAME_DATA, rfc::H2_FLAG_END_STREAM, 3, "late-data");
    var rst3: u8[4] = [0, 0, 0, rfc::H2_ERR_CANCEL as u8];
    append_h2_frame(ref_split, rfc::H2_FRAME_RST_STREAM, 0, 3, rst3[..]);
    append_h2_frame(ref_split, rfc::H2_FRAME_DATA, rfc::H2_FLAG_END_STREAM, 1, "");
    let _, ok_r3 = http2::h2_edge_feed(s_ref, ref_split[..]);
    assert(ok_r3);
    assert(http2::h2_edge_send_headers(s_ref, 1, 200, h_empty, true));

    // Stream 5 now uses dynamic table entry installed during refused split stream 3
    var w5: u8[>..] = [];
    append_h2_req_headers(w5, ref_dt, 5, "GET", "/after-refused", ref_h, true);
    let _, ok_r5 = http2::h2_edge_feed(s_ref, w5[..]);
    assert(ok_r5);
    var saw_dyn5 = false;
    while http2::h2_edge_poll_event(s_ref, ev1) {
        if ev1.kind == http2::H2EdgeEventKind.RequestHead && ev1.stream_id == 5 {
            assert(http::get_header(ev1.headers, "x-refused-dyn") == "synced-val-42");
            saw_dyn5 = true;
        }
    }
    assert(saw_dyn5);

    // 4. peer_max_header_list_size enforcement transactionally rejects oversized response headers
    var s_lim = http2::h2_edge_open(128, 65535);
    defer http2::h2_edge_close(s_lim);
    var lim_w: u8[>..] = [];
    lim_w.append(rfc::H2_CLIENT_PREFACE[..]);
    let lim_set: wire::WireSetting[1] = [
        wire::WireSetting { id: rfc::H2_SETTING_MAX_HEADER_LIST_SIZE, val: 120 },
    ];
    assert(wire::encode_settings_frame(lim_set[..], lim_w));
    var lim_dt = http2::new_dynamic_table(4096);
    append_h2_req_headers(lim_w, lim_dt, 1, "GET", "/lim", h_empty, true);
    let _, ok_lim = http2::h2_edge_feed(s_lim, lim_w[..]);
    assert(ok_lim);
    out1.clear();
    let _ = http2::h2_edge_drain_wire(s_lim, out1);

    var big_resp = http::HeaderMap { .. };
    var val_100: u8[100] = ['q'; 100];
    assert(http::append_header(big_resp, "x-too-big", val_100[..]));
    assert(!http2::h2_edge_send_headers(s_lim, 1, 200, big_resp, true));
    out1.clear();
    assert(http2::h2_edge_drain_wire(s_lim, out1) == 0);

    var ok_resp = http::HeaderMap { .. };
    assert(http::append_header(ok_resp, "server", "wing"));
    assert(http2::h2_edge_send_headers(s_lim, 1, 200, ok_resp, true));
    assert(http2::h2_edge_drain_wire(s_lim, out1) > 0);

    print("H2_EDGE_ROUND1_REGRESSIONS: OK");
    // CHECK: H2_EDGE_ROUND1_REGRESSIONS: OK
}

fn test_h2_edge_zero_data_and_chunk_reclaim() {
    // 1. h2_edge_send_data(sess, sid, "", true) returns (0, false) without closing stream when wire_out has < 9 bytes free.
    var s = http2::h2_edge_open(128, 131072);
    defer http2::h2_edge_close(s);

    var req_w: u8[>..] = [];
    req_w.append(rfc::H2_CLIENT_PREFACE[..]);
    let set_win: wire::WireSetting[1] = [
        wire::WireSetting { id: rfc::H2_SETTING_INITIAL_WINDOW_SIZE, val: 262144 },
    ];
    assert(wire::encode_settings_frame(set_win[..], req_w));
    var wu4: u8[4] = [0x00, 0x04, 0x00, 0x00]; // 262144
    append_h2_frame(req_w, rfc::H2_FRAME_WINDOW_UPDATE, 0, 0, wu4[..]);
    var dt = http2::new_dynamic_table(4096);
    var empty_h = http::HeaderMap { .. };
    append_h2_req_headers(req_w, dt, 1, "GET", "/fill", empty_h, true);
    append_h2_req_headers(req_w, dt, 3, "GET", "/zero", empty_h, true);
    let _, ok_f = http2::h2_edge_feed(s, req_w[..]);
    assert(ok_f);

    var ev = http2::H2EdgeEvent { .. };
    while http2::h2_edge_poll_event(s, ev) {}

    // Drain initial server SETTINGS + SETTINGS ACK so wire_out starts empty, then fill wire_out until < 9 bytes free.
    var dump: u8[>..] = [];
    let _ = http2::h2_edge_drain_wire(s, dump);
    assert(http2::h2_edge_send_headers(s, 1, 200, empty_h, false));
    assert(http2::h2_edge_send_headers(s, 3, 200, empty_h, false));
    dump.clear();
    let _ = http2::h2_edge_drain_wire(s, dump);

    // Send 147370-byte body on stream 1 across 16384-byte chunks so remaining wire_out capacity is < 9 bytes.
    var big_fill: u8[>..] = [];
    for _ in 147370 { big_fill.push('x'); }
    let sent_fill, ok_fill = http2::h2_edge_send_data(s, 1, big_fill[..], false);
    assert(ok_fill && sent_fill == 147370);
    // Ensure remaining free room in wire_out is strictly < 9 bytes.
    let s_slot_idx = s.slot_idx;
    let wire_cap = http2::g_h2_edge_slots[s_slot_idx].wire_out.cap;
    let rem_room = wire_cap - http2::g_h2_edge_slots[s_slot_idx].wire_out.len;
    assert(rem_room < rfc::H2_FRAME_HEADER_LEN);

    let nz, ok_z = http2::h2_edge_send_data(s, 3, "", true);
    assert(!ok_z && nz == 0);

    dump.clear();
    assert(http2::h2_edge_drain_wire(s, dump) == wire_cap - rem_room);
    let nz2, ok_z2 = http2::h2_edge_send_data(s, 3, "", true);
    assert(ok_z2 && nz2 == 0);
    dump.clear();
    assert(http2::h2_edge_drain_wire(s, dump) == rfc::H2_FRAME_HEADER_LEN);
    var r3 = wire::new_wire_h2_frame_reader(dump[..]);
    let fh3, fp3, ok_r3 = wire::next_frame(r3);
    assert(ok_r3 && fh3.stream_id == 3 && fh3.frame_type == rfc::H2_FRAME_DATA);
    assert((fh3.flags & rfc::H2_FLAG_END_STREAM) != 0 && fp3.len == 0);

    // 2. Concurrent multiplexed uploads across two sessions keep g_h2_edge_data_chunks strictly bounded.
    var sa = http2::h2_edge_open(128, 1048576);
    var sb = http2::h2_edge_open(128, 1048576);
    defer http2::h2_edge_close(sa);
    defer http2::h2_edge_close(sb);

    var dta = http2::new_dynamic_table(4096);
    var dtb = http2::new_dynamic_table(4096);
    var wa: u8[>..] = [];
    wa.append(rfc::H2_CLIENT_PREFACE[..]);
    append_h2_frame(wa, rfc::H2_FRAME_SETTINGS, 0, 0, "");
    append_h2_req_headers(wa, dta, 1, "POST", "/hold", empty_h, false);
    append_h2_frame(wa, rfc::H2_FRAME_DATA, rfc::H2_FLAG_END_STREAM, 1, "held-unpolled-event");
    let _, oka = http2::h2_edge_feed(sa, wa[..]);
    assert(oka);

    var wb_init: u8[>..] = [];
    wb_init.append(rfc::H2_CLIENT_PREFACE[..]);
    append_h2_frame(wb_init, rfc::H2_FRAME_SETTINGS, 0, 0, "");
    append_h2_req_headers(wb_init, dtb, 1, "POST", "/stream", empty_h, false);
    let _, okb0 = http2::h2_edge_feed(sb, wb_init[..]);
    assert(okb0);
    while http2::h2_edge_poll_event(sb, ev) {}

    var chunk_4k: u8[4096] = [0x4B; 4096];
    var total_rx: u64      = 0;
    for r in 300 {
        var wu_b: u8[>..] = [];
        append_h2_frame(wu_b, rfc::H2_FRAME_DATA, if r == 299 { rfc::H2_FLAG_END_STREAM } else { 0 }, 1, chunk_4k[..]);
        let _, okb = http2::h2_edge_feed(sb, wu_b[..]);
        assert(okb);
        while http2::h2_edge_poll_event(sb, ev) {
            if ev.kind == http2::H2EdgeEventKind.RequestData {
                assert(ev.data.len == 4096 && ev.data[0] == 0x4B);
                total_rx += ev.data.len as u64;
            }
        }
        dump.clear();
        let _ = http2::h2_edge_drain_wire(sb, dump);
    }
    assert(total_rx == 300 * 4096);
    assert(http2::g_h2_edge_data_chunks.len <= 16);

    print("H2_EDGE_ZERO_AND_CHUNKS_OK: OK");
    // CHECK: H2_EDGE_ZERO_AND_CHUNKS_OK: OK
}

fn test_h2_edge_thread_safety() {
    let tid = thread_spawn(edge_worker_thread, 1);
    assert(thread_wait(tid));
    print("H2_EDGE_THREAD_SAFETY: OK");
    // CHECK: H2_EDGE_THREAD_SAFETY: OK
}

fn verify_min_dyn_size_updates_in_headers(sess: http2::H2EdgeSession&, stream_id: u32) {
    var hdrs = http::HeaderMap { .. };
    assert(!http2::h2_edge_send_headers(sess, stream_id, 99, hdrs, false));
    assert(http2::h2_edge_send_headers(sess, stream_id, 200, hdrs, true));
    var out: u8[>..] = [];
    let _ = http2::h2_edge_drain_wire(sess, out);
    var rd = wire::new_wire_h2_frame_reader(out[..]);
    var saw_hdr = false;
    while wire::has_next(rd) {
        let fh, fp, ok = wire::next_frame(rd);
        assert(ok);
        if fh.frame_type == rfc::H2_FRAME_HEADERS && fh.stream_id == stream_id {
            assert((fp[0] & 0xE0) == 0x20);
            let sz1, off1, ok1 = http2::hpack_decode_int(fp, 0, 5);
            assert(ok1 && sz1 == 256 && off1 < (fp.len as u64));
            assert((fp[off1 as i64] & 0xE0) == 0x20);
            let sz2, _, ok2 = http2::hpack_decode_int(fp, off1, 5);
            assert(ok2 && sz2 == 1024);
            var cli_dec = http2::new_dynamic_table(4096);
            var ps = http2::PseudoHeaders { .. };
            var rm = http::HeaderMap { .. };
            assert(http2::decode_hpack_to_map(cli_dec, fp, ps, rm) == rfc::H2_ERR_NO_ERROR);
            assert(ps.has_status && ps.status == 200 && cli_dec.current_max_size == 1024);
            saw_hdr = true;
        }
    }
    assert(saw_hdr);
}

fn test_h2_edge_hpack_min_dyn_size() {
    var s_hp = http2::h2_edge_open(128, 65535);
    defer http2::h2_edge_close(s_hp);
    var w: u8[>..] = [];
    w.append(rfc::H2_CLIENT_PREFACE[..]);
    let s_first: wire::WireSetting[2] = [
        wire::WireSetting { id: rfc::H2_SETTING_HEADER_TABLE_SIZE, val: 256 },
        wire::WireSetting { id: rfc::H2_SETTING_NO_RFC7540_PRIORITIES, val: 1 },
    ];
    assert(wire::encode_settings_frame(s_first[..], w));
    let s_second: wire::WireSetting[2] = [
        wire::WireSetting { id: rfc::H2_SETTING_HEADER_TABLE_SIZE, val: 1024 },
        wire::WireSetting { id: rfc::H2_SETTING_NO_RFC7540_PRIORITIES, val: 1 },
    ];
    assert(wire::encode_settings_frame(s_second[..], w));
    var cdt = http2::new_dynamic_table(4096);
    var h0 = http::HeaderMap { .. };
    append_h2_req_headers(w, cdt, 1, "GET", "/min-dyn", h0, true);
    let _, ok_w = http2::h2_edge_feed(s_hp, w[..]);
    assert(ok_w);
    var dump: u8[>..] = [];
    let _ = http2::h2_edge_drain_wire(s_hp, dump);

    assert(!http2::h2_edge_reset_stream(s_hp, 99, rfc::H2_ERR_CANCEL));
    dump.clear();
    assert(http2::h2_edge_drain_wire(s_hp, dump) == 0);
    verify_min_dyn_size_updates_in_headers(s_hp, 1);

    var w_flip: u8[>..] = [];
    let s_flip: wire::WireSetting[1] = [
        wire::WireSetting { id: rfc::H2_SETTING_NO_RFC7540_PRIORITIES, val: 0 },
    ];
    assert(wire::encode_settings_frame(s_flip[..], w_flip));
    let _, ok_flip = http2::h2_edge_feed(s_hp, w_flip[..]);
    assert(!ok_flip);
    var ev = http2::H2EdgeEvent { .. };
    var saw_flip_err = false;
    while http2::h2_edge_poll_event(s_hp, ev) {
        if ev.kind == http2::H2EdgeEventKind.ProtocolError &&
           ev.error_code == rfc::H2_ERR_PROTOCOL_ERROR {
            saw_flip_err = true;
        }
    }
    assert(saw_flip_err);
}

fn test_h2_edge_rfc9218_rejects() {
    var s_late = http2::h2_edge_open(128, 65535);
    defer http2::h2_edge_close(s_late);
    var w_late: u8[>..] = [];
    w_late.append(rfc::H2_CLIENT_PREFACE[..]);
    let s_empty: wire::WireSetting[1] = [
        wire::WireSetting { id: rfc::H2_SETTING_ENABLE_PUSH, val: 0 },
    ];
    assert(wire::encode_settings_frame(s_empty[..], w_late));
    let _, ok_l0 = http2::h2_edge_feed(s_late, w_late[..]);
    assert(ok_l0);
    w_late.clear();
    let s_enable_late: wire::WireSetting[1] = [
        wire::WireSetting { id: rfc::H2_SETTING_NO_RFC7540_PRIORITIES, val: 1 },
    ];
    assert(wire::encode_settings_frame(s_enable_late[..], w_late));
    let _, ok_l1 = http2::h2_edge_feed(s_late, w_late[..]);
    assert(!ok_l1);

    var s_pu = http2::h2_edge_open(128, 65535);
    defer http2::h2_edge_close(s_pu);
    var w_pu: u8[>..] = [];
    w_pu.append(rfc::H2_CLIENT_PREFACE[..]);
    let pu_zero: u8[4] = [0, 0, 0, 0];
    append_h2_frame(w_pu, rfc::H2_FRAME_PRIORITY_UPDATE, 0, 0, pu_zero[..]);
    let _, ok_pu = http2::h2_edge_feed(s_pu, w_pu[..]);
    assert(!ok_pu);
    var ev = http2::H2EdgeEvent { .. };
    var saw_pu_err = false;
    while http2::h2_edge_poll_event(s_pu, ev) {
        if ev.kind == http2::H2EdgeEventKind.ProtocolError &&
           ev.error_code == rfc::H2_ERR_PROTOCOL_ERROR {
            saw_pu_err = true;
        }
    }
    assert(saw_pu_err);
}

fn test_h2_edge_rfc9218_and_hpack_regressions() {
    test_h2_edge_hpack_min_dyn_size();
    test_h2_edge_rfc9218_rejects();
    print("H2_EDGE_RFC9218_AND_HPACK: OK");
    // CHECK: H2_EDGE_RFC9218_AND_HPACK: OK
}

fn test_h2_edge_headers_self_dep_and_pad() {
    var s_hp = http2::h2_edge_open(128, 65535);
    defer http2::h2_edge_close(s_hp);
    var w: u8[>..] = [];
    w.append(rfc::H2_CLIENT_PREFACE[..]);
    append_h2_frame(w, rfc::H2_FRAME_SETTINGS, 0, 0, "");
    let _, ok_0 = http2::h2_edge_feed(s_hp, w[..]);
    assert(ok_0);
    var dump: u8[>..] = [];
    let _ = http2::h2_edge_drain_wire(s_hp, dump);

    // HEADERS + FLAG_PRIORITY self-dependency emits RST_STREAM(PROTOCOL_ERROR) and keeps conn open.
    var dt = http2::new_dynamic_table(4096);
    var hpack_frag: u8[>..] = [];
    assert(http2::encode_hpack_field(dt, hpack_frag, ":method", "GET", http2::HpackIndexing.None, false));
    assert(http2::encode_hpack_field(dt, hpack_frag, ":scheme", "https", http2::HpackIndexing.None, false));
    assert(http2::encode_hpack_field(dt, hpack_frag, ":path", "/self", http2::HpackIndexing.None, false));
    var hdr_self: u8[>..] = [];
    hdr_self.append_u32_be(1);
    hdr_self.push(15);
    hdr_self.append(hpack_frag[..]);
    var wf: u8[>..] = [];
    let flags_self = rfc::H2_FLAG_END_HEADERS | rfc::H2_FLAG_END_STREAM | rfc::H2_FLAG_PRIORITY;
    append_h2_frame(wf, rfc::H2_FRAME_HEADERS, flags_self, 1, hdr_self[..]);
    let _, ok_self = http2::h2_edge_feed(s_hp, wf[..]);
    assert(ok_self);
    var ev = http2::H2EdgeEvent { .. };
    assert(http2::h2_edge_poll_event(s_hp, ev) && ev.kind == http2::H2EdgeEventKind.StreamReset);
    assert(ev.stream_id == 1 && ev.error_code == rfc::H2_ERR_PROTOCOL_ERROR);

    // Connection remains usable on stream 3 after stream 1 self-dependency reset.
    var h0 = http::HeaderMap { .. };
    var w3: u8[>..] = [];
    append_h2_req_headers(w3, dt, 3, "GET", "/ok", h0, true);
    let _, ok_3 = http2::h2_edge_feed(s_hp, w3[..]);
    assert(ok_3);
    assert(http2::h2_edge_poll_event(s_hp, ev) && ev.kind == http2::H2EdgeEventKind.RequestHead);
    assert(ev.stream_id == 3);

    // Invalid HEADERS padding remains connection error GOAWAY(PROTOCOL_ERROR).
    let bad_pad: u8[3] = [0x09, 0x82, 0x86];
    var w_bad: u8[>..] = [];
    let bad_flags = rfc::H2_FLAG_END_HEADERS | rfc::H2_FLAG_PADDED;
    append_h2_frame(w_bad, rfc::H2_FRAME_HEADERS, bad_flags, 5, bad_pad[..]);
    let _, ok_bad = http2::h2_edge_feed(s_hp, w_bad[..]);
    assert(!ok_bad);
    assert(http2::h2_edge_poll_event(s_hp, ev) && ev.kind == http2::H2EdgeEventKind.ProtocolError);
    assert(ev.error_code == rfc::H2_ERR_PROTOCOL_ERROR);
}

fn test_h2_edge_rfc9113_conformance_regressions() {
    // 1. First frame after 24B preface MUST be non-ACK SETTINGS (RFC 9113 Section 3.4).
    var s_noset = http2::h2_edge_open(128, 65535);
    defer http2::h2_edge_close(s_noset);
    var bad_first: u8[>..] = [];
    bad_first.append(rfc::H2_CLIENT_PREFACE[..]);
    let ping_p: u8[8] = [0x22; 8];
    append_h2_frame(bad_first, rfc::H2_FRAME_PING, 0, 0, ping_p[..]);
    let _, ok_bf = http2::h2_edge_feed(s_noset, bad_first[..]);
    assert(!ok_bf);
    var ev = http2::H2EdgeEvent { .. };
    assert(http2::h2_edge_poll_event(s_noset, ev) && ev.kind == http2::H2EdgeEventKind.ProtocolError);
    assert(ev.error_code == rfc::H2_ERR_PROTOCOL_ERROR);

    // 2. PRIORITY frame depending on itself emits RST_STREAM(PROTOCOL_ERROR) (RFC 7540 Section 5.3.1 / h2spec 5.3.1).
    var s_prio = http2::h2_edge_open(128, 65535);
    defer http2::h2_edge_close(s_prio);
    var wp: u8[>..] = [];
    wp.append(rfc::H2_CLIENT_PREFACE[..]);
    append_h2_frame(wp, rfc::H2_FRAME_SETTINGS, 0, 0, "");
    var drain_p: u8[>..] = [];
    let _, ok_wp = http2::h2_edge_feed(s_prio, wp[..]);
    assert(ok_wp);
    let _ = http2::h2_edge_drain_wire(s_prio, drain_p);
    var self_prio: u8[5]   = [0x00, 0x00, 0x00, 0x01, 15];
    var pw:        u8[>..] = [];
    append_h2_frame(pw, rfc::H2_FRAME_PRIORITY, 0, 1, self_prio[..]);
    let _, ok_sp = http2::h2_edge_feed(s_prio, pw[..]);
    assert(ok_sp);
    assert(http2::h2_edge_poll_event(s_prio, ev) && ev.kind == http2::H2EdgeEventKind.StreamReset);
    assert(ev.stream_id == 1 && ev.error_code == rfc::H2_ERR_PROTOCOL_ERROR);

    // 3. Multi-CONTINUATION header block ~8300 RFC 7541 bytes fits under 16384 limit (h2spec 6.10).
    var dt = http2::new_dynamic_table(4096);
    var dummy_val: u8[3950] = ['a'; 3950];
    var hpack_big: u8[>..]  = [];
    var inc = http2::HpackIndexing.Incremental;
    assert(http2::encode_hpack_field(dt, hpack_big, ":method", "GET", http2::HpackIndexing.None, false));
    assert(http2::encode_hpack_field(dt, hpack_big, ":scheme", "https", http2::HpackIndexing.None, false));
    assert(http2::encode_hpack_field(dt, hpack_big, ":path", "/big", http2::HpackIndexing.None, false));
    assert(http2::encode_hpack_field(dt, hpack_big, "x-d1", dummy_val[..], inc, false));
    assert(http2::encode_hpack_field(dt, hpack_big, "x-d2", dummy_val[..], inc, false));
    var big_w: u8[>..] = [];
    append_h2_frame(big_w, rfc::H2_FRAME_HEADERS, rfc::H2_FLAG_END_STREAM, 3, hpack_big[..20]);
    append_h2_frame(big_w, rfc::H2_FRAME_CONTINUATION, 0, 3, hpack_big[20..hpack_big.len - 1]);
    append_h2_frame(big_w, rfc::H2_FRAME_CONTINUATION, rfc::H2_FLAG_END_HEADERS, 3, hpack_big[hpack_big.len - 1..]);
    let _, ok_bw = http2::h2_edge_feed(s_prio, big_w[..]);
    assert(ok_bw);
    assert(http2::h2_edge_poll_event(s_prio, ev) && ev.kind == http2::H2EdgeEventKind.RequestHead);
    assert(ev.stream_id == 3 && http::get_header(ev.headers, "x-d2").len == 3950);

    // 4. Even idle stream ID in PRIORITY_UPDATE fails connection with GOAWAY(PROTOCOL_ERROR).
    var pu_bad: u8[..16] = [];
    pu_bad.append_u32_be(2);
    pu_bad.append("u=0");
    var pu_w: u8[>..] = [];
    append_h2_frame(pu_w, rfc::H2_FRAME_PRIORITY_UPDATE, 0, 0, pu_bad[..]);
    let _, ok_pu = http2::h2_edge_feed(s_prio, pu_w[..]);
    assert(!ok_pu);
    assert(http2::h2_edge_poll_event(s_prio, ev) && ev.kind == http2::H2EdgeEventKind.ProtocolError);
    assert(ev.error_code == rfc::H2_ERR_PROTOCOL_ERROR);

    test_h2_edge_headers_self_dep_and_pad();

    print("H2_EDGE_RFC9113_REGRESSIONS: OK");
    // CHECK: H2_EDGE_RFC9113_REGRESSIONS: OK
}

fn main() {
    test_tls_alpn_hardening();
    test_h2_edge_preface_multiplex_upload_sse();
    test_h2_edge_security_and_aba();
    test_h2_edge_round1_regressions();
    test_h2_edge_zero_data_and_chunk_reclaim();
    test_h2_edge_thread_safety();
    test_h2_edge_rfc9218_and_hpack_regressions();
    test_h2_edge_rfc9113_conformance_regressions();
}
