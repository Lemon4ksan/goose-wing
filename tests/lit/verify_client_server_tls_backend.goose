// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// End-to-End Verification of Pluggable TLS Backend Wiring in client::Config,
// client::Session, net::Transport.TlsBackend, server::HttpServer, and DST WS nonce.
//
// RUN: goose build -O0 -o %t.exe %s
// RUN: %t.exe | %FileCheck %s

import std;
import wing from "../..";

fn get_test_pem_paths(out_cert: u8[..256]&, out_key: u8[..256]&) {
    out_cert.clear();
    out_key.clear();
    var tmp_dir: u8[>..] = [];
    if !(env("TEMP", tmp_dir) || env("TMP", tmp_dir) || env("TMPDIR", tmp_dir)) {
        tmp_dir.append("/tmp");
    }
    assert(out_cert.try_append(tmp_dir[..]) && out_cert.try_append("/wing_tls_backend_test_cert.pem"));
    assert(out_key.try_append(tmp_dir[..]) && out_key.try_append("/wing_tls_backend_test_key.pem"));
}

fn put_asn1_len(b: core::ByteBuilder&, n: i64) {
    if n >= 256 {
        b.put_u8(0x82);
        b.put_u8(((n >> 8) & 0xFF) as u8);
        b.put_u8((n & 0xFF) as u8);
    } else if n >= 128 {
        b.put_u8(0x81);
        b.put_u8((n & 0xFF) as u8);
    } else {
        b.put_u8((n & 0xFF) as u8);
    }
}

fn wrap_asn1(tag: u8, payload: const u8[:], out: u8[..2048]&) {
    var b = core::builder_init();
    b.put_u8(tag);
    put_asn1_len(b, payload.len);
    b.put_bytes(payload);
    assert(out.try_set(b.buf[..]));
}

// Builds a self-signed X.509 v3 ECDSA P-256 certificate (accepted by PureGoose, OpenSSL 3, and Schannel).
fn build_test_p256_cert_der(
    priv_key:    const u8[32]&,
    common_name: const u8[:],
    dns_san:     const u8[:],
    out_der:     u8[..2048]&,
) -> bool {
    out_der.clear();
    let pub65 = core::ecdsa_p256_public_key(priv_key);
    let ecdsa_sha256_alg = "\x30\x0A\x06\x08\x2A\x86\x48\xCE\x3D\x04\x03\x02";

    var b_tbs = core::builder_init();
    // version [0] EXPLICIT INTEGER v3 (2) + serialNumber (INTEGER 7)
    b_tbs.put_bytes("\xA0\x03\x02\x01\x02\x02\x01\x07");
    b_tbs.put_bytes(ecdsa_sha256_alg);

    // issuer & subject: CN = common_name
    var b_cn = core::builder_init();
    b_cn.put_u8(0x30);
    b_cn.put_u8((7 + common_name.len) as u8);
    b_cn.put_bytes("\x06\x03\x55\x04\x03\x0C");
    b_cn.put_u8(common_name.len as u8);
    b_cn.put_bytes(common_name);

    var b_name = core::builder_init();
    b_name.put_u8(0x30);
    b_name.put_u8((2 + b_cn.buf.len) as u8);
    b_name.put_u8(0x31);
    b_name.put_u8(b_cn.buf.len as u8);
    b_name.put_bytes(b_cn.buf[..]);
    b_tbs.put_bytes(b_name.buf[..]);

    // validity: 2024-01-01 to 2035-12-31
    b_tbs.put_bytes("\x30\x1E\x17\x0D240101000000Z\x17\x0D351231235959Z");
    b_tbs.put_bytes(b_name.buf[..]);

    // SPKI: id-ecPublicKey + secp256r1 + uncompressed 65-byte point
    b_tbs.put_bytes("\x30\x59\x30\x13\x06\x07\x2A\x86\x48\xCE\x3D\x02\x01");
    b_tbs.put_bytes("\x06\x08\x2A\x86\x48\xCE\x3D\x03\x01\x07\x03\x42\x00");
    b_tbs.put_bytes(pub65[..]);

    // extensions [3]: BasicConstraints (cA=true) + SubjectAltName (DNS + IP 127.0.0.1)
    var b_ext = core::builder_init();
    b_ext.put_bytes("\x30\x0C\x06\x03\x55\x1D\x13\x04\x05\x30\x03\x01\x01\xFF");

    var b_san = core::builder_init();
    b_san.put_u8(0x82);
    b_san.put_u8(dns_san.len as u8);
    b_san.put_bytes(dns_san);
    b_san.put_bytes("\x87\x04\x7F\x00\x00\x01");

    var b_san_seq = core::builder_init();
    b_san_seq.put_u8(0x30);
    b_san_seq.put_u8(b_san.buf.len as u8);
    b_san_seq.put_bytes(b_san.buf[..]);

    b_ext.put_u8(0x30);
    b_ext.put_u8((7 + b_san_seq.buf.len) as u8);
    b_ext.put_bytes("\x06\x03\x55\x1D\x11\x04");
    b_ext.put_u8(b_san_seq.buf.len as u8);
    b_ext.put_bytes(b_san_seq.buf[..]);

    b_tbs.put_u8(0xA3);
    b_tbs.put_u8((2 + b_ext.buf.len) as u8);
    b_tbs.put_u8(0x30);
    b_tbs.put_u8(b_ext.buf.len as u8);
    b_tbs.put_bytes(b_ext.buf[..]);

    var tbs_wrapped: u8[..2048] = [];
    wrap_asn1(0x30, b_tbs.buf[..], tbs_wrapped);

    let raw_sig = core::ecdsa_p256_sign(priv_key, tbs_wrapped[..]);
    var der_sig: u8[..72] = [];
    guard core::ecdsa_p256_encode_der_sig(raw_sig, der_sig) else { return false; }

    var b_cert = core::builder_init();
    b_cert.put_bytes(tbs_wrapped[..]);
    b_cert.put_bytes(ecdsa_sha256_alg);
    b_cert.put_u8(0x03);
    b_cert.put_u8((1 + der_sig.len) as u8);
    b_cert.put_u8(0x00);
    b_cert.put_bytes(der_sig[..]);

    wrap_asn1(0x30, b_cert.buf[..], out_der);
    return out_der.len > 0;
}

// Builds a PKCS#8 DER private key for ECDSA P-256 (RFC 5958 + RFC 5915).
fn build_test_p256_pkcs8_der(priv_key: const u8[32]&, out_der: u8[..512]&) -> bool {
    out_der.clear();
    let pub65 = core::ecdsa_p256_public_key(priv_key);

    var b_ec = core::builder_init();
    b_ec.put_bytes("\x02\x01\x01\x04\x20");
    b_ec.put_bytes(priv_key[..]);
    b_ec.put_bytes("\xA1\x44\x03\x42\x00");
    b_ec.put_bytes(pub65[..]);

    var b_ec_seq = core::builder_init();
    b_ec_seq.put_u8(0x30);
    put_asn1_len(b_ec_seq, b_ec.buf.len);
    b_ec_seq.put_bytes(b_ec.buf[..]);

    var b_pki = core::builder_init();
    b_pki.put_bytes("\x02\x01\x00\x30\x13\x06\x07\x2A\x86\x48\xCE\x3D\x02\x01");
    b_pki.put_bytes("\x06\x08\x2A\x86\x48\xCE\x3D\x03\x01\x07\x04");
    put_asn1_len(b_pki, b_ec_seq.buf.len);
    b_pki.put_bytes(b_ec_seq.buf[..]);

    var b_full = core::builder_init();
    b_full.put_u8(0x30);
    put_asn1_len(b_full, b_pki.buf.len);
    b_full.put_bytes(b_pki.buf[..]);
    return out_der.try_set(b_full.buf[..]);
}

fn encode_pem_block(label: const u8[:], der: const u8[:], out: u8[>..]&) {
    out.clear();
    out.append("-----BEGIN ");
    out.append(label);
    out.append("-----\n");
    var b64: u8[>..] = [];
    core::base64_encode(der, b64);
    var pos: i64 = 0;
    while pos < b64.len {
        let end = min(core::add_sat_i64(pos, 64), b64.len);
        out.append(b64[pos..end]);
        out.push('\n');
        pos = end;
    }
    out.append("-----END ");
    out.append(label);
    out.append("-----\n");
}

fn format_loopback_url(port: u16, path: const u8[:], out: u8[..128]&) {
    out.clear();
    let _ = out.try_append("https://localhost:");
    port.format_u64_dec(out);
    let _ = out.try_append(path);
}

// ---- 1. client::Config Defaults & Backend Setters --------------------------

fn test_client_config_and_setters() {
    print("=== 1. client::Config & Setters ===");
    // CHECK: === 1. client::Config & Setters ===

    var def_c = client::new_client();
    let def_ok = (def_c.tls_backend == tls::TlsBackendKind.PureGoose) &&
        (def_c.tls_min_version == tls::TlsMinVersion.Tls13) &&
        (def_c.tls_ca_file.len == 0);

    var cfg_ossl = client::Config {
        tls_backend:     tls::TlsBackendKind.SystemOpenSsl,
        tls_min_version: tls::TlsMinVersion.Tls12,
        tls_ca_file:     "certs/custom-ca.pem",
        ..
    };
    var c_ossl = client::new_client(cfg_ossl);
    let ossl_cfg_ok = (c_ossl.tls_backend == tls::TlsBackendKind.SystemOpenSsl) &&
        (c_ossl.tls_min_version == tls::TlsMinVersion.Tls12) &&
        (c_ossl.tls_ca_file[..] == "certs/custom-ca.pem");

    var cfg_sch = client::Config {
        tls_backend:     tls::TlsBackendKind.SystemSchannel,
        tls_min_version: tls::TlsMinVersion.Tls12,
        ..
    };
    var c_sch = client::new_client(cfg_sch);
    assert(c_sch.tls_backend == tls::TlsBackendKind.SystemSchannel);
    assert(c_sch.tls_min_version == tls::TlsMinVersion.Tls12);

    c_sch.insecure_skip_verify = true;
    c_sch.set_tls_backend(tls::TlsBackendKind.Auto);
    c_sch.set_tls_min_version(tls::TlsMinVersion.Tls13);
    assert(c_sch.set_tls_ca_file("certs/root.pem"));
    let setter_ok = (c_sch.tls_backend == tls::TlsBackendKind.Auto) &&
        (c_sch.tls_min_version == tls::TlsMinVersion.Tls13) &&
        (c_sch.tls_ca_file[..] == "certs/root.pem") &&
        !c_sch.insecure_skip_verify;

    // Negative: oversize CA path (> 256 bytes) must fail without clobbering prior path.
    var long_path: u8[300] = ['a'; 300];
    let reject_oversize = !c_sch.set_tls_ca_file(long_path[..]) &&
        (c_sch.tls_ca_file[..] == "certs/root.pem");

    print("client_cfg_defaults=", def_ok, " custom_cfg=", ossl_cfg_ok,
        " setters=", setter_ok, " reject_oversize=", reject_oversize);
    // CHECK: client_cfg_defaults=true custom_cfg=true setters=true reject_oversize=true
}

// ---- 2. Live Loopback TCP via Transport.TlsBackend (PureGoose H1 & H2) -----

thread_fn pure_transport_loopback_worker(listener_fd: i64) {
    let seed: u8[32] = [0x33; 32];
    var cert_der: u8[..2048] = [];
    assert(build_test_p256_cert_der(seed, "localhost", "localhost", cert_der));

    // Conn 1: HTTP/1.1 ALPN encrypted GET/200 exchange over net::Transport.TlsBackend
    let conn1 = net::tcp_accept(listener_fd, 5000);
    assert(conn1 > 0);
    var srv_cfg1 = tls::TlsBackendConfig {
        kind:      tls::TlsBackendKind.PureGoose,
        is_server: true,
        priv_seed: seed,
        ..
    };
    assert(srv_cfg1.cert_der.try_set(cert_der[..]));
    let alpn_h1: u8[9] = [8, 'h', 't', 't', 'p', '/', '1', '.', '1'];
    assert(srv_cfg1.alpn_wire.try_set(alpn_h1[..]));

    let slot1, neg1, st1 = tls::endpoint_server_handshake_fd(conn1, srv_cfg1, 5000);
    assert(st1 == tls::TlsBackendStatus.Ok && slot1 >= 0 && neg1[..] == "http/1.1");

    var tr1: net::Transport = net::Transport.TlsBackend { fd: conn1, endpoint_slot: slot1 };
    assert(tr1.is_connected());
    var rx1: u8[1024] = [0; 1024];
    let n1 = tr1.recv_slice(rx1[..], 5000);
    assert(n1 > 0 && core::starts_with(rx1[..n1], "GET /hello HTTP/1.1\r\n"));
    let resp1 = "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 21\r\nConnection: close\r\n\r\nhello-from-tlsbackend";
    assert(tr1.send(resp1) == resp1.len as i32);
    tr1.close();
    tr1.close();
    assert(!tr1.is_connected());

    // Conn 2: ALPN "h2" negotiation over net::Transport.TlsBackend
    let conn2 = net::tcp_accept(listener_fd, 5000);
    assert(conn2 > 0);
    let alpn_h2: u8[3] = [2, 'h', '2'];
    assert(srv_cfg1.alpn_wire.try_set(alpn_h2[..]));
    let slot2, neg2, st2 = tls::endpoint_server_handshake_fd(conn2, srv_cfg1, 5000);
    assert(st2 == tls::TlsBackendStatus.Ok && slot2 >= 0 && neg2[..] == "h2");
    var tr2: net::Transport = net::Transport.TlsBackend { fd: conn2, endpoint_slot: slot2 };
    var rx2: u8[256]        = [0; 256];
    let n2 = tr2.recv_slice(rx2[..], 5000);
    assert(n2 > 0 && rx2[..n2] == "PRI * HTTP/2.0");
    assert(tr2.send("H2-OK") == 5);
    tr2.close();

    // Conn 3: Untrusted client handshake (server accepts, client rejects cert)
    let conn3 = net::tcp_accept(listener_fd, 5000);
    assert(conn3 > 0);
    let slot3, _, st3 = tls::endpoint_server_handshake_fd(conn3, srv_cfg1, 2000);
    if st3 == tls::TlsBackendStatus.Ok && slot3 >= 0 {
        tls::endpoint_transport_close(conn3, slot3);
    } else {
        net::tcp_close(conn3);
    }
}

fn test_loopback_tls_backend_transport_pure() {
    print("=== 2. Loopback Transport.TlsBackend (PureGoose) ===");
    // CHECK: === 2. Loopback Transport.TlsBackend (PureGoose) ===

    let seed: u8[32] = [0x33; 32];
    var cert_der: u8[..2048] = [];
    assert(build_test_p256_cert_der(seed, "localhost", "localhost", cert_der));
    var trust = tls::TrustAnchorStore { .. };
    assert(tls::add_trust_anchor_cert_der(trust, cert_der[..]));

    let listener = net::tcp_listen("127.0.0.1", 0, 8);
    assert(listener > 0);
    let port = net::tcp_getsockname_port(listener);
    assert(port > 0);

    let tid = thread_spawn(pure_transport_loopback_worker, listener);

    // Conn 1: HTTP/1.1
    let fd1 = net::tcp_connect("127.0.0.1", port, 5000);
    assert(fd1 > 0);
    var cli_cfg1 = tls::TlsBackendConfig {
        kind:                 tls::TlsBackendKind.PureGoose,
        is_server:            false,
        insecure_skip_verify: false,
        trust_store:          trust,
        ..
    };
    assert(cli_cfg1.server_name.try_set("localhost"));
    let alpn_both: u8[12] = [2, 'h', '2', 8, 'h', 't', 't', 'p', '/', '1', '.', '1'];
    assert(cli_cfg1.alpn_wire.try_set(alpn_both[..]));

    let cslot1, cneg1, cst1 = tls::endpoint_client_handshake_fd(fd1, cli_cfg1, 5000);
    assert(cst1 == tls::TlsBackendStatus.Ok && cslot1 >= 0);
    var ctr1: net::Transport = net::Transport.TlsBackend { fd: fd1, endpoint_slot: cslot1 };
    assert(ctr1.is_connected());
    let req1 = "GET /hello HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n";
    assert(ctr1.send(req1) == req1.len as i32);
    var resp_buf: u8[1024] = [0; 1024];
    var total_rx: i64      = 0;
    while total_rx < 1024 {
        let nr = ctr1.recv_slice(resp_buf[total_rx..], 5000);
        if nr <= 0 { break; }
        total_rx = core::add_sat_i64(total_rx, nr);
    }
    let h1_ok = (cneg1[..] == "http/1.1") &&
        core::starts_with(resp_buf[..total_rx], "HTTP/1.1 200 OK\r\n") &&
        core::ends_with(resp_buf[..total_rx], "hello-from-tlsbackend");
    ctr1.close();
    ctr1.close();
    assert(!ctr1.is_connected());

    // Conn 2: H2 ALPN
    let fd2 = net::tcp_connect("127.0.0.1", port, 5000);
    assert(fd2 > 0);
    let cslot2, cneg2, cst2 = tls::endpoint_client_handshake_fd(fd2, cli_cfg1, 5000);
    assert(cst2 == tls::TlsBackendStatus.Ok && cslot2 >= 0);
    var ctr2: net::Transport = net::Transport.TlsBackend { fd: fd2, endpoint_slot: cslot2 };
    assert(ctr2.send("PRI * HTTP/2.0") == 14);
    var rx2: u8[64] = [0; 64];
    let n2 = ctr2.recv_slice(rx2[..], 5000);
    let h2_ok = (cneg2[..] == "h2") && (n2 == 5) && (rx2[..n2] == "H2-OK");
    ctr2.close();

    // Conn 3: Untrusted cert rejection -> VerifyError
    let fd3 = net::tcp_connect("127.0.0.1", port, 5000);
    assert(fd3 > 0);
    var bad_cfg = tls::TlsBackendConfig {
        kind:                 tls::TlsBackendKind.PureGoose,
        is_server:            false,
        insecure_skip_verify: false,
        ..
    };
    assert(bad_cfg.server_name.try_set("localhost"));
    let bad_slot, _, bad_st = tls::endpoint_client_handshake_fd(fd3, bad_cfg, 5000);
    net::tcp_close(fd3);
    let verify_err_ok = (bad_slot == -1) && (bad_st == tls::TlsBackendStatus.VerifyError);

    assert(thread_wait(tid));
    net::tcp_close(listener);
    print("pure_h1_loopback=", h1_ok, " pure_h2_alpn=", h2_ok, " verify_err=", verify_err_ok);
    // CHECK: pure_h1_loopback=true pure_h2_alpn=true verify_err=true
}

// ---- 3. client::Session + server::HttpServer Live Loopback (Auto / OpenSSL)

fn serve_one_backend_http_conn(
    srv:       server::HttpServer&,
    conn_fd:   i64,
    alpn_wire: const u8[:],
    exp_alpn:  const u8[:],
) {
    var tr, neg_alpn, st = server::accept_tls_backend_connection(srv, conn_fd, alpn_wire, 5000);
    assert(st == tls::TlsBackendStatus.Ok && neg_alpn[..] == exp_alpn);
    defer tr.close();

    var rx_buf:   u8[8192]    = [0; 8192];
    var wire_out: u8[..16384] = [];
    let nr = tr.recv_slice(rx_buf[..], 5000);
    assert(nr > 0);
    let _, ok_h = server::handle_connection_wire(srv, "127.0.0.1", rx_buf[..nr], 1000000000, wire_out);
    assert(ok_h && wire_out.len > 0);
    assert(wing::send_all(tr, wire_out[..]));
}

thread_fn session_auto_server_worker(listener_fd: i64) {
    var cpath: u8[..256] = [];
    var kpath: u8[..256] = [];
    get_test_pem_paths(cpath, kpath);
    let use_ossl = tls::tls_backend_available(tls::TlsBackendKind.SystemOpenSsl);

    var srv = server::new_http_server("127.0.0.1", 0);
    srv.pipeline.enable_csrf_guard = false;
    assert(server::add_static_route(srv.pipeline.router, "GET", "/ping", "text/plain", "pong-auto-h1"));
    assert(server::add_static_route(srv.pipeline.router, "GET", "/h2ping", "text/plain", "pong-auto-h2"));

    assert(server::configure_server_tls_backend(
        srv, tls::TlsBackendKind.PureGoose, tls::TlsMinVersion.Tls13, cpath[..], kpath[..],
    ));

    // Conn 1: HTTP/1.1 via client::Session with TlsBackendKind.Auto (OpenSSL 3 when available, else PureGoose)
    let c1 = net::tcp_accept(listener_fd, 5000);
    assert(c1 > 0);
    let alpn_h1: u8[9] = [8, 'h', 't', 't', 'p', '/', '1', '.', '1'];
    serve_one_backend_http_conn(srv, c1, alpn_h1[..], "http/1.1");

    // Conn 2: HTTP/2 via client::Session with TlsBackendKind.Auto (ALPN "h2")
    let c2 = net::tcp_accept(listener_fd, 5000);
    assert(c2 > 0);
    let alpn_h2: u8[3] = [2, 'h', '2'];
    serve_one_backend_http_conn(srv, c2, alpn_h2[..], "h2");

    // Conn 3 & 4: Explicit SystemOpenSsl client + SystemOpenSsl server when OpenSSL 3 is available
    if use_ossl {
        let c3 = net::tcp_accept(listener_fd, 5000);
        assert(c3 > 0);
        serve_one_backend_http_conn(srv, c3, alpn_h1[..], "http/1.1");

        assert(server::configure_server_tls_backend(
            srv, tls::TlsBackendKind.SystemOpenSsl, tls::TlsMinVersion.Tls13, cpath[..], kpath[..],
        ));
        let c4 = net::tcp_accept(listener_fd, 5000);
        assert(c4 > 0);
        serve_one_backend_http_conn(srv, c4, alpn_h1[..], "http/1.1");
    }
}

fn test_client_session_auto_and_openssl_loopback() {
    print("=== 3. client::Session + server::HttpServer Live Loopback ===");
    // CHECK: === 3. client::Session + server::HttpServer Live Loopback ===

    let seed: u8[32] = [0x47; 32];
    var cert_der: u8[..2048] = [];
    var key_der:  u8[..512]  = [];
    assert(build_test_p256_cert_der(seed, "localhost", "localhost", cert_der));
    assert(build_test_p256_pkcs8_der(seed, key_der));

    var cert_pem: u8[>..] = [];
    var key_pem:  u8[>..] = [];
    encode_pem_block("CERTIFICATE", cert_der[..], cert_pem);
    encode_pem_block("PRIVATE KEY", key_der[..], key_pem);

    var check_srv_cfg = tls::ServerHandshakeConfig { .. };
    assert(tls::load_server_credentials_pem(cert_pem[..], key_pem[..], check_srv_cfg));

    var cpath: u8[..256] = [];
    var kpath: u8[..256] = [];
    get_test_pem_paths(cpath, kpath);
    assert(write_file_atomic(cpath[..], cert_pem[..]));
    assert(write_file_atomic(kpath[..], key_pem[..]));

    let use_ossl = tls::tls_backend_available(tls::TlsBackendKind.SystemOpenSsl);

    let listener = net::tcp_listen("127.0.0.1", 0, 8);
    assert(listener > 0);
    let port = net::tcp_getsockname_port(listener);
    assert(port > 0);

    let tid = thread_spawn(session_auto_server_worker, listener);

    // Request 1: client::Session (TlsBackendKind.Auto + tls_ca_file) -> HTTP/1.1 200
    var s1 = client::new_session(client::Config {
        timeout_ms:  5000,
        tls_backend: tls::TlsBackendKind.Auto,
        tls_ca_file: cpath[..],
        ..
    });
    defer s1.close();
    s1.ssrf_guard.enabled = false;
    var u1: u8[..128] = [];
    format_loopback_url(port, "/ping", u1);
    var req1 = http::new_get(u1[..]);
    let r1, e1 = client::execute_request(s1, req1);
    let auto_h1_ok = http::ok(e1) && r1.status_code == 200 && r1.body[..] == "pong-auto-h1";

    // Request 2: fresh client::Session (TlsBackendKind.Auto + tls_ca_file) -> HTTP/2 200
    var s2 = client::new_session(client::Config {
        timeout_ms:  5000,
        tls_backend: tls::TlsBackendKind.Auto,
        tls_ca_file: cpath[..],
        ..
    });
    defer s2.close();
    s2.ssrf_guard.enabled = false;
    var u2: u8[..128] = [];
    format_loopback_url(port, "/h2ping", u2);
    var req2 = http::new_get(u2[..]);
    let r2, e2 = client::execute_request(s2, req2);
    let auto_h2_ok = http::ok(e2) && r2.status_code == 200 &&
        r2.protocol[..] == "HTTP/2" && r2.body[..] == "pong-auto-h2";

    // Request 3 & 4: Explicit SystemOpenSsl client + SystemOpenSsl server (when OpenSSL 3 is loaded)
    var ossl_live_ok = !use_ossl;
    if use_ossl {
        var s3 = client::new_session(client::Config {
            timeout_ms:  5000,
            tls_backend: tls::TlsBackendKind.SystemOpenSsl,
            tls_ca_file: cpath[..],
            ..
        });
        defer s3.close();
        s3.ssrf_guard.enabled = false;
        var req3 = http::new_get(u1[..]);
        let r3, e3 = client::execute_request(s3, req3);
        let cli_ossl_ok = http::ok(e3) && r3.status_code == 200 && r3.body[..] == "pong-auto-h1";

        var s4 = client::new_session(client::Config {
            timeout_ms:  5000,
            tls_backend: tls::TlsBackendKind.PureGoose,
            ..
        });
        defer s4.close();
        s4.ssrf_guard.enabled = false;
        let _, ok_ca4 = client::load_trust_anchors_pem_file(s4, cpath[..]);
        assert(ok_ca4);
        var req4 = http::new_get(u1[..]);
        let r4, e4 = client::execute_request(s4, req4);
        let srv_ossl_ok = http::ok(e4) && r4.status_code == 200 && r4.body[..] == "pong-auto-h1";
        ossl_live_ok = cli_ossl_ok && srv_ossl_ok;
    }

    assert(thread_wait(tid));
    net::tcp_close(listener);
    print("openssl_runtime_active=", use_ossl);
    print("session_auto_h1=", auto_h1_ok, " session_auto_h2=", auto_h2_ok, " ossl_path_ok=", ossl_live_ok);
    // CHECK: session_auto_h1=true session_auto_h2=true ossl_path_ok=true
}

// ---- 4. server::HttpServer Config Validation & DST WS Nonce Determinism ----

fn test_server_config_and_dst_nonce() {
    print("=== 4. HttpServer TLS Config & DST Nonce Determinism ===");
    // CHECK: === 4. HttpServer TLS Config & DST Nonce Determinism ===

    var srv = server::new_http_server("127.0.0.1", 8443);
    let def_srv_ok = (srv.tls_backend == tls::TlsBackendKind.PureGoose) &&
        (srv.tls_min_version == tls::TlsMinVersion.Tls13) &&
        (srv.tls_cert_pem_file.len == 0) &&
        (srv.tls_key_pem_file.len == 0);

    assert(server::configure_server_tls_backend(
        srv, tls::TlsBackendKind.SystemOpenSsl, tls::TlsMinVersion.Tls12, "srv.crt", "srv.key",
    ));
    let set_srv_ok = (srv.tls_backend == tls::TlsBackendKind.SystemOpenSsl) &&
        (srv.tls_min_version == tls::TlsMinVersion.Tls12) &&
        (srv.tls_cert_pem_file[..] == "srv.crt") &&
        (srv.tls_key_pem_file[..] == "srv.key");

    // Negative: half-PEM pair and oversize paths must fail transactionally.
    let reject_half = !server::configure_server_tls_backend(
        srv, tls::TlsBackendKind.PureGoose, tls::TlsMinVersion.Tls13, "only_cert.pem", "",
    );
    var big_path: u8[300] = ['z'; 300];
    let reject_big = !server::configure_server_tls_backend(
        srv, tls::TlsBackendKind.PureGoose, tls::TlsMinVersion.Tls13, big_path[..], "k.pem",
    );
    let preserved = (srv.tls_backend == tls::TlsBackendKind.SystemOpenSsl) &&
        (srv.tls_cert_pem_file[..] == "srv.crt");

    // Negative: accept_tls_backend_connection rejects invalid fd cleanly.
    let bad_tr, _, bad_st = server::accept_tls_backend_connection(srv, -1, "", 100);
    let reject_fd = !bad_tr.is_connected() && (bad_st == tls::TlsBackendStatus.Error);

    // DST determinism: prepare_ws_upgrade_request must use core::sim_rng_fill when active.
    core::sim_rng_enable(0xBEEF2026);
    var s_a = client::new_session();
    var key_a: u8[..64] = [];
    let _ = client_internal::prepare_ws_upgrade_request(s_a, "wss://example.com/ws", key_a);

    core::sim_rng_enable(0xBEEF2026);
    var s_b = client::new_session();
    var key_b: u8[..64] = [];
    let _ = client_internal::prepare_ws_upgrade_request(s_b, "wss://example.com/ws", key_b);

    core::sim_rng_enable(0xCAFE9999);
    var s_c = client::new_session();
    var key_c: u8[..64] = [];
    let _ = client_internal::prepare_ws_upgrade_request(s_c, "wss://example.com/ws", key_c);
    core::sim_rng_disable();

    let dst_det_ok = (key_a.len > 0) && (key_a[..] == key_b[..]) && (key_a[..] != key_c[..]);

    print("srv_cfg_ok=", def_srv_ok && set_srv_ok && reject_half && reject_big && preserved && reject_fd,
        " dst_ws_nonce_det=", dst_det_ok);
    // CHECK: srv_cfg_ok=true dst_ws_nonce_det=true
}

fn main() {
    test_client_config_and_setters();
    test_loopback_tls_backend_transport_pure();
    test_client_session_auto_and_openssl_loopback();
    test_server_config_and_dst_nonce();
}
