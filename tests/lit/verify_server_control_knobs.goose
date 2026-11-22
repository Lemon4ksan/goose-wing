// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Verification of Server Control Knobs:
// 1. mTLS (`configure_server_mtls`), ALPN (`set_server_tls_alpn`), keylog (`set_server_tls_keylog_file`).
// 2. Live OpenSSL 3 loopback mTLS acceptance/rejection, configured ALPN, and NSS keylog emission.
// 3. Server timeouts (`set_server_timeouts`) synced into `srv.timer` & `srv.pipeline.deadline_ns`.
// 4. DoS limits (`set_server_limits`): 431 oversized headers, 413 oversized body/CL/chunked, H2 SETTINGS.
// 5. Header visibility (`ServerHeaderPolicy`: Standard, OmitServer, OmitDate, OmitBoth) on wire.
// 6. Socket options (`ServerSocketOptions`, `set_server_socket_options`, `listen_http_server`) & `max_connections`.
//
// RUN: goose build -O0 -o %t.exe %s
// RUN: %t.exe | %FileCheck %s

import std;
import wing from "../..";

fn make_tmp_file_path(suffix: const u8[:], out: u8[..256]&) {
    out.clear();
    var tmp_dir: u8[>..] = [];
    if !(env("TEMP", tmp_dir) || env("TMP", tmp_dir) || env("TMPDIR", tmp_dir)) {
        tmp_dir.append("/tmp");
    }
    assert(out.try_append(tmp_dir[..]) && out.try_push('/') && out.try_append(suffix));
}

fn put_der_len(b: core::ByteBuilder&, n: i64) {
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

fn wrap_der_tlv(tag: u8, payload: const u8[:], out: u8[..2048]&) {
    var b = core::builder_init();
    b.put_u8(tag);
    put_der_len(b, payload.len);
    b.put_bytes(payload);
    assert(out.try_set(b.buf[..]));
}

fn encode_pem_file_bytes(label: const u8[:], der: const u8[:], out: u8[>..]&) {
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

fn build_p256_cert_der(priv_key: const u8[32]&, cn: const u8[:], out_der: u8[..2048]&) -> bool {
    out_der.clear();
    let pub65 = core::ecdsa_p256_public_key(priv_key);
    let alg = "\x30\x0A\x06\x08\x2A\x86\x48\xCE\x3D\x04\x03\x02";

    var b_tbs = core::builder_init();
    b_tbs.put_bytes("\xA0\x03\x02\x01\x02\x02\x01\x15");
    b_tbs.put_bytes(alg);

    var b_cn = core::builder_init();
    b_cn.put_u8(0x30);
    b_cn.put_u8((7 + cn.len) as u8);
    b_cn.put_bytes("\x06\x03\x55\x04\x03\x0C");
    b_cn.put_u8(cn.len as u8);
    b_cn.put_bytes(cn);

    var b_name = core::builder_init();
    b_name.put_u8(0x30);
    b_name.put_u8((2 + b_cn.buf.len) as u8);
    b_name.put_u8(0x31);
    b_name.put_u8(b_cn.buf.len as u8);
    b_name.put_bytes(b_cn.buf[..]);
    b_tbs.put_bytes(b_name.buf[..]);
    b_tbs.put_bytes("\x30\x1E\x17\x0D240101000000Z\x17\x0D351231235959Z");
    b_tbs.put_bytes(b_name.buf[..]);
    b_tbs.put_bytes("\x30\x59\x30\x13\x06\x07\x2A\x86\x48\xCE\x3D\x02\x01");
    b_tbs.put_bytes("\x06\x08\x2A\x86\x48\xCE\x3D\x03\x01\x07\x03\x42\x00");
    b_tbs.put_bytes(pub65[..]);

    var b_ext = core::builder_init();
    b_ext.put_bytes("\x30\x0C\x06\x03\x55\x1D\x13\x04\x05\x30\x03\x01\x01\xFF");

    var b_san = core::builder_init();
    b_san.put_u8(0x82);
    b_san.put_u8(cn.len as u8);
    b_san.put_bytes(cn);
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
    wrap_der_tlv(0x30, b_tbs.buf[..], tbs_wrapped);
    let raw_sig = core::ecdsa_p256_sign(priv_key, tbs_wrapped[..]);
    var der_sig: u8[..72] = [];
    guard core::ecdsa_p256_encode_der_sig(raw_sig, der_sig) else { return false; }

    var b_cert = core::builder_init();
    b_cert.put_bytes(tbs_wrapped[..]);
    b_cert.put_bytes(alg);
    b_cert.put_u8(0x03);
    b_cert.put_u8((1 + der_sig.len) as u8);
    b_cert.put_u8(0x00);
    b_cert.put_bytes(der_sig[..]);
    wrap_der_tlv(0x30, b_cert.buf[..], out_der);
    return out_der.len > 0;
}

fn build_p256_pkcs8_der(priv_key: const u8[32]&, out_der: u8[..512]&) -> bool {
    out_der.clear();
    let pub65 = core::ecdsa_p256_public_key(priv_key);
    var b_ec = core::builder_init();
    b_ec.put_bytes("\x02\x01\x01\x04\x20");
    b_ec.put_bytes(priv_key[..]);
    b_ec.put_bytes("\xA1\x44\x03\x42\x00");
    b_ec.put_bytes(pub65[..]);

    var b_ec_seq = core::builder_init();
    b_ec_seq.put_u8(0x30);
    put_der_len(b_ec_seq, b_ec.buf.len);
    b_ec_seq.put_bytes(b_ec.buf[..]);

    var b_pki = core::builder_init();
    b_pki.put_bytes("\x02\x01\x00\x30\x13\x06\x07\x2A\x86\x48\xCE\x3D\x02\x01");
    b_pki.put_bytes("\x06\x08\x2A\x86\x48\xCE\x3D\x03\x01\x07\x04");
    put_der_len(b_pki, b_ec_seq.buf.len);
    b_pki.put_bytes(b_ec_seq.buf[..]);

    var b_full = core::builder_init();
    b_full.put_u8(0x30);
    put_der_len(b_full, b_pki.buf.len);
    b_full.put_bytes(b_pki.buf[..]);
    return out_der.try_set(b_full.buf[..]);
}

fn write_test_keypair_pem(
    seed:      const u8[32]&,
    cn:        const u8[:],
    cert_path: const u8[:],
    key_path:  const u8[:],
) {
    var cert_der: u8[..2048] = [];
    var key_der:  u8[..512]  = [];
    assert(build_p256_cert_der(seed, cn, cert_der));
    assert(build_p256_pkcs8_der(seed, key_der));
    var cert_pem: u8[>..] = [];
    var key_pem:  u8[>..] = [];
    encode_pem_file_bytes("CERTIFICATE", cert_der[..], cert_pem);
    encode_pem_file_bytes("PRIVATE KEY", key_der[..], key_pem);
    assert(write_file_atomic(cert_path, cert_pem[..]));
    assert(write_file_atomic(key_path, key_pem[..]));
}

fn has_valid_keylog_traffic_secret(content: const u8[:]) -> bool {
    return core::contains(content, "CLIENT_HANDSHAKE_TRAFFIC_SECRET ") &&
        core::contains(content, "SERVER_HANDSHAKE_TRAFFIC_SECRET ") &&
        core::contains(content, "CLIENT_TRAFFIC_SECRET_0 ") &&
        core::contains(content, "SERVER_TRAFFIC_SECRET_0 ");
}

// ---- 1. Server mTLS, ALPN, and Keylog Validation ---------------------------

fn test_server_tls_controls_validation() {
    print("=== 1. Server mTLS, ALPN, and Keylog Validation ===");
    // CHECK: === 1. Server mTLS, ALPN, and Keylog Validation ===

    var srv = server::new_http_server("127.0.0.1", 0);
    let defaults_ok = srv.tls_ca_file.len == 0 &&
        !srv.tls_require_client_cert &&
        srv.tls_alpn_wire.len == 0 &&
        srv.tls_keylog_file.len == 0 &&
        srv.tls_handshake_timeout_ms == 5000;

    // Valid mTLS configuration
    assert(server::configure_server_mtls(srv, "certs/client-ca.pem", true));
    let mtls_set = srv.tls_require_client_cert && srv.tls_ca_file[..] == "certs/client-ca.pem";

    // Negative: empty CA when require_client_cert=true fails transactionally
    let reject_empty_ca = !server::configure_server_mtls(srv, "", true) &&
        srv.tls_require_client_cert &&
        srv.tls_ca_file[..] == "certs/client-ca.pem";

    // Negative: oversize CA path (> 256 bytes) fails transactionally
    var big_path: u8[300] = ['x'; 300];
    let reject_big_ca = !server::configure_server_mtls(srv, big_path[..], true) &&
        srv.tls_ca_file[..] == "certs/client-ca.pem";

    // Disable mTLS cleanly with require_client_cert=false
    let disable_mtls = server::configure_server_mtls(srv, "", false) &&
        !srv.tls_require_client_cert &&
        srv.tls_ca_file.len == 0;

    // ALPN wire validation (valid, malformed, oversize, reset)
    let alpn_h1:  u8[9] = [8, 'h', 't', 't', 'p', '/', '1', '.', '1'];
    let alpn_bad: u8[3] = [5, 'h', '2'];
    var alpn_big: u8[70] = [1; 70];
    assert(server::set_server_tls_alpn(srv, alpn_h1[..]));
    let alpn_ok = srv.tls_alpn_wire[..] == alpn_h1[..] &&
        !server::set_server_tls_alpn(srv, alpn_bad[..]) &&
        !server::set_server_tls_alpn(srv, alpn_big[..]) &&
        srv.tls_alpn_wire[..] == alpn_h1[..] &&
        server::set_server_tls_alpn(srv, "") &&
        srv.tls_alpn_wire.len == 0;

    // Keylog file validation
    assert(server::set_server_tls_keylog_file(srv, "/tmp/wing_srv.keylog"));
    let keylog_ok = srv.tls_keylog_file[..] == "/tmp/wing_srv.keylog" &&
        !server::set_server_tls_keylog_file(srv, big_path[..]) &&
        srv.tls_keylog_file[..] == "/tmp/wing_srv.keylog" &&
        server::set_server_tls_keylog_file(srv, "") &&
        srv.tls_keylog_file.len == 0;

    print("defaults=", defaults_ok, " mtls_val=", mtls_set && reject_empty_ca && reject_big_ca && disable_mtls,
        " alpn_val=", alpn_ok, " keylog_val=", keylog_ok);
    // CHECK: defaults=true mtls_val=true alpn_val=true keylog_val=true
}

// ---- 2. Live OpenSSL 3 Loopback mTLS, ALPN & Keylog -----------------------

fn get_mtls_test_paths(
    srv_cert: u8[..256]&,
    srv_key:  u8[..256]&,
    cli_cert: u8[..256]&,
    cli_key:  u8[..256]&,
    keylog:   u8[..256]&,
) {
    make_tmp_file_path("wing_srv_knobs_srv.crt", srv_cert);
    make_tmp_file_path("wing_srv_knobs_srv.key", srv_key);
    make_tmp_file_path("wing_srv_knobs_cli.crt", cli_cert);
    make_tmp_file_path("wing_srv_knobs_cli.key", cli_key);
    make_tmp_file_path("wing_srv_knobs_srv.keylog", keylog);
}

thread_fn openssl_mtls_server_worker(listener_fd: i64) {
    var sc: u8[..256] = [];
    var sk: u8[..256] = [];
    var cc: u8[..256] = [];
    var ck: u8[..256] = [];
    var kl: u8[..256] = [];
    get_mtls_test_paths(sc, sk, cc, ck, kl);

    var srv = server::new_http_server("127.0.0.1", 0);
    srv.pipeline.enable_csrf_guard = false;
    assert(server::add_static_route(srv.pipeline.router, "GET", "/mtls", "text/plain", "mtls-verified"));
    assert(server::configure_server_tls_backend(
        srv, tls::TlsBackendKind.SystemOpenSsl, tls::TlsMinVersion.Tls13, sc[..], sk[..],
    ));
    assert(server::configure_server_mtls(srv, cc[..], true));
    let alpn_h1: u8[9] = [8, 'h', 't', 't', 'p', '/', '1', '.', '1'];
    assert(server::set_server_tls_alpn(srv, alpn_h1[..]));
    assert(server::set_server_tls_keylog_file(srv, kl[..]));
    server::set_server_timeouts(srv, 10000, 3000, 5000, 4000);

    // Conn 1: client without cert MUST be rejected by mTLS server.
    let c1 = net::tcp_accept(listener_fd, 5000);
    assert(c1 > 0);
    var tr1, _, st1 = server::accept_tls_backend_connection(srv, c1);
    assert(st1 != tls::TlsBackendStatus.Ok && !tr1.is_connected());
    net::tcp_close(c1);

    // Conn 2: client with trusted cert MUST succeed, negotiate srv.tls_alpn_wire, and emit keylog.
    let c2 = net::tcp_accept(listener_fd, 5000);
    assert(c2 > 0);
    var tr2, neg2, st2 = server::accept_tls_backend_connection(srv, c2);
    assert(st2 == tls::TlsBackendStatus.Ok && neg2[..] == "http/1.1");
    var rx2:  u8[4096]   = [0; 4096];
    var out2: u8[..8192] = [];
    let nr2 = tr2.recv_slice(rx2[..], 4000);
    assert(nr2 > 0);
    let _, ok2 = server::handle_connection_wire(srv, "127.0.0.1", rx2[..nr2], 1000000000, out2);
    assert(ok2 && out2.len > 0 && wing::send_all(tr2, out2[..]));
    tr2.close();

    // Conn 3: disable require_client_cert (even with ca_file populated) -> client without cert succeeds.
    assert(server::configure_server_mtls(srv, cc[..], false));
    let c3 = net::tcp_accept(listener_fd, 5000);
    assert(c3 > 0);
    var tr3, neg3, st3 = server::accept_tls_backend_connection(srv, c3);
    assert(st3 == tls::TlsBackendStatus.Ok && neg3[..] == "http/1.1");
    var rx3:  u8[4096]   = [0; 4096];
    var out3: u8[..8192] = [];
    let nr3 = tr3.recv_slice(rx3[..], 4000);
    assert(nr3 > 0);
    let _, ok3 = server::handle_connection_wire(srv, "127.0.0.1", rx3[..nr3], 1000000000, out3);
    assert(ok3 && out3.len > 0 && wing::send_all(tr3, out3[..]));
    tr3.close();
}

fn run_ossl_client_get(
    port:      u16,
    ca_path:   const u8[:],
    cert_path: const u8[:],
    key_path:  const u8[:],
) -> bool, u8[..64], bool {
    var neg_out: u8[..64] = [];
    let fd = net::tcp_connect("127.0.0.1", port, 4000);
    guard fd > 0 else { return false, neg_out, false; }
    var cfg = tls::TlsBackendConfig {
        kind:      tls::TlsBackendKind.SystemOpenSsl,
        is_server: false,
        ..
    };
    assert(cfg.server_name.try_set("localhost"));
    assert(cfg.ca_file.try_set(ca_path));
    if cert_path.len > 0 {
        assert(cfg.cert_pem_file.try_set(cert_path));
        assert(cfg.key_pem_file.try_set(key_path));
    }
    let alpn_both: u8[12] = [2, 'h', '2', 8, 'h', 't', 't', 'p', '/', '1', '.', '1'];
    assert(cfg.alpn_wire.try_set(alpn_both[..]));

    let slot, neg, st = tls::endpoint_client_handshake_fd(fd, cfg, 4000);
    neg_out = neg;
    guard st == tls::TlsBackendStatus.Ok && slot >= 0 else {
        net::tcp_close(fd);
        return false, neg_out, false;
    }
    var tr: net::Transport = net::Transport.TlsBackend { fd: fd, endpoint_slot: slot };
    defer tr.close();
    let req = "GET /mtls HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n";
    guard wing::send_all(tr, req) else { return true, neg_out, false; }
    var rx:    u8[4096] = [0; 4096];
    var total: i64      = 0;
    while total < 4096 {
        let nr = tr.recv_slice(rx[total..], 4000);
        if nr <= 0 { break; }
        total = core::add_sat_i64(total, nr);
    }
    let body_ok = total > 0 && core::contains(rx[..total], "mtls-verified");
    return true, neg_out, body_ok;
}

fn test_openssl_mtls_alpn_keylog_loopback() {
    print("=== 2. Live OpenSSL mTLS, ALPN & Keylog Loopback ===");
    // CHECK: === 2. Live OpenSSL mTLS, ALPN & Keylog Loopback ===

    let use_ossl = tls::tls_backend_available(tls::TlsBackendKind.SystemOpenSsl);
    print("openssl_available=", use_ossl);
    if !use_ossl {
        print("mtls_reject_nocert=true mtls_accept_cert=true mtls_disabled_ok=true srv_keylog_ok=true");
        return;
    }

    var sc: u8[..256] = [];
    var sk: u8[..256] = [];
    var cc: u8[..256] = [];
    var ck: u8[..256] = [];
    var kl: u8[..256] = [];
    get_mtls_test_paths(sc, sk, cc, ck, kl);

    let srv_seed: u8[32] = [0x61; 32];
    let cli_seed: u8[32] = [0x62; 32];
    write_test_keypair_pem(srv_seed, "localhost", sc[..], sk[..]);
    write_test_keypair_pem(cli_seed, "client.local", cc[..], ck[..]);
    let _ = delete_file(kl[..]);
    defer {
        let _ = delete_file(sc[..]);
        let _ = delete_file(sk[..]);
        let _ = delete_file(cc[..]);
        let _ = delete_file(ck[..]);
        let _ = delete_file(kl[..]);
    };

    let listener = net::tcp_listen("127.0.0.1", 0, 8);
    assert(listener > 0);
    let port = net::tcp_getsockname_port(listener);
    let tid = thread_spawn(openssl_mtls_server_worker, listener);

    let hs1, _, body1 = run_ossl_client_get(port, sc[..], "", "");
    let reject_nocert = !(hs1 && body1);

    let hs2, neg2, body2 = run_ossl_client_get(port, sc[..], cc[..], ck[..]);
    let accept_cert = hs2 && body2 && neg2[..] == "http/1.1";

    let hs3, neg3, body3 = run_ossl_client_get(port, sc[..], "", "");
    let disabled_ok = hs3 && body3 && neg3[..] == "http/1.1";

    assert(thread_wait(tid));
    net::tcp_close(listener);

    var kl_bytes: u8[>..] = [];
    let keylog_ok = read_file(kl[..], kl_bytes) && has_valid_keylog_traffic_secret(kl_bytes[..]);

    print("mtls_reject_nocert=", reject_nocert, " mtls_accept_cert=", accept_cert,
        " mtls_disabled_ok=", disabled_ok, " srv_keylog_ok=", keylog_ok);
    // CHECK: mtls_reject_nocert=true mtls_accept_cert=true mtls_disabled_ok=true srv_keylog_ok=true
}

// ---- 3. Server Timeouts Synchronization ------------------------------------

fn test_server_timeouts_sync() {
    print("=== 3. Server Timeouts Synchronization ===");
    // CHECK: === 3. Server Timeouts Synchronization ===

    var srv = server::new_http_server("127.0.0.1", 0);
    let def_ok = srv.idle_timeout_ms == 30000 &&
        srv.read_header_timeout_ms == 5000 &&
        srv.read_body_timeout_ms == 15000 &&
        srv.tls_handshake_timeout_ms == 5000 &&
        srv.timer.half_deadline_ns == 15000000000;

    server::set_server_timeouts(srv, 6000, 1200, 3400, 900);
    let fields_ok = srv.idle_timeout_ms == 6000 &&
        srv.read_header_timeout_ms == 1200 &&
        srv.read_body_timeout_ms == 3400 &&
        srv.tls_handshake_timeout_ms == 900 &&
        srv.pipeline.deadline_ns == 6000000000 &&
        srv.timer.half_deadline_ns == 3000000000;

    // Verify timer now expires after 2 x 3s = 6s (instead of default 30s).
    srv.timer.last_tick_mono_ns = 1000000000;
    srv.timer.missed_ticks = 0;
    let alive_at_4s = server_internal::check_connection_tick(srv.timer, 4000000000);
    let expired_at_7s = !server_internal::check_connection_tick(srv.timer, 7000000000);

    print("timeout_defaults=", def_ok, " timeout_synced=", fields_ok,
        " timer_enforced=", alive_at_4s && expired_at_7s);
    // CHECK: timeout_defaults=true timeout_synced=true timer_enforced=true
}

// ---- 4. DoS Limits: 431 Headers, 413 Body/CL/Chunked & H2 SETTINGS ---------

fn test_server_dos_limits() {
    print("=== 4. DoS Limits (431 / 413 / H2 SETTINGS) ===");
    // CHECK: === 4. DoS Limits (431 / 413 / H2 SETTINGS) ===

    var srv = server::new_http_server("127.0.0.1", 0);
    srv.pipeline.enable_csrf_guard = false;
    srv.pipeline.enable_rate_limiter = false;
    server::add_post_route(srv, "/upload", 1);
    server::add_get_route(srv, "/ok", 2);
    server::set_server_limits(srv, 128, 32, 4, 42);

    let cfg_ok = srv.max_header_bytes == 128 &&
        srv.max_body_bytes == 32 &&
        srv.max_connections == 4 &&
        srv.max_h2_concurrent_streams == 42 &&
        srv.pipeline.max_header_bytes == 128 &&
        srv.pipeline.max_body_bytes == 32 &&
        srv.pipeline.max_h2_concurrent_streams == 42;

    // 4a. Oversized headers (> 128 bytes) -> 431 Request Header Fields Too Large
    var big_hdr_req: u8[..512] = [];
    assert(big_hdr_req.try_append("GET /ok HTTP/1.1\r\nHost: localhost\r\nX-Pad: "));
    for _ in 120 { assert(big_hdr_req.try_push('A')); }
    assert(big_hdr_req.try_append("\r\n\r\n"));

    var out_431: u8[..4096] = [];
    let _, ok_431 = server::handle_connection_wire(srv, "127.0.0.1", big_hdr_req[..], 1000000000, out_431);
    let wire_431_ok = !ok_431 &&
        core::starts_with(out_431[..], "HTTP/1.1 431 Request Header Fields Too Large\r\n");

    var out_431_pipe: u8[..4096] = [];
    let _, _, ok_431_p, close_431_p = server::handle_connection_wire_pipelined_stream(
        srv, "127.0.0.1", big_hdr_req[..], 1000000000, out_431_pipe,
    );
    let pipe_431_ok = !ok_431_p && close_431_p &&
        core::starts_with(out_431_pipe[..], "HTTP/1.1 431 Request Header Fields Too Large\r\n");

    // 4b. Oversized Content-Length (> 32 bytes) -> 413 Content Too Large (even before body arrives)
    let cl_over = "POST /upload HTTP/1.1\r\nHost: localhost\r\nContent-Length: 64\r\n\r\nshort";
    var out_413: u8[..4096] = [];
    let _, ok_413 = server::handle_connection_wire(srv, "127.0.0.1", cl_over, 1000000000, out_413);
    let cl_413_ok = !ok_413 && core::starts_with(out_413[..], "HTTP/1.1 413 Content Too Large\r\n");

    // 4c. Oversized chunked body (> 32 bytes) -> 413 Content Too Large
    let chunk_over = "POST /upload HTTP/1.1\r\nHost: localhost\r\nTransfer-Encoding: chunked\r\n\r\n28\r\n0123456789012345678901234567890123456789\r\n0\r\n\r\n";
    var out_chunk_413: u8[..4096] = [];
    let _, ok_c413 = server::handle_connection_wire(srv, "127.0.0.1", chunk_over, 1000000000, out_chunk_413);
    let chunk_413_ok = !ok_c413 && core::starts_with(out_chunk_413[..], "HTTP/1.1 413 Content Too Large\r\n");

    // 4d. Within limits -> 200 OK
    let valid_post = "POST /upload HTTP/1.1\r\nHost: localhost\r\nContent-Length: 5\r\n\r\nhello";
    var out_ok: u8[..4096] = [];
    let _, ok_200 = server::handle_connection_wire(srv, "127.0.0.1", valid_post, 1000000000, out_ok);
    let valid_200_ok = ok_200 && core::starts_with(out_ok[..], "HTTP/1.1 200 OK\r\n");

    // 4e. Direct pipeline DoS check (`check_pipeline_dos_limits`)
    var d_req = http::new_request("POST", "/upload");
    assert(http::append_header(d_req.headers, "Content-Length", "100"));
    let pipe_cl_413 = server::check_pipeline_dos_limits(srv.pipeline, d_req) == 413;

    // 4f. HTTP/2 SETTINGS_MAX_CONCURRENT_STREAMS advertised on wire as 42
    var h2_out: u8[..4096] = [];
    let _, ok_h2 = server::handle_connection_wire(
        srv, "127.0.0.1", rfc::H2_CLIENT_PREFACE, 1000000000, h2_out,
    );
    let h2_settings_ok = ok_h2 && h2_out.len >= 15 &&
        h2_out[3] == rfc::H2_FRAME_SETTINGS &&
        core::read_be_u16(h2_out[..], 9) == rfc::H2_SETTING_MAX_CONCURRENT_STREAMS &&
        core::read_be_u32(h2_out[..], 11) == 42;

    print("limits_cfg=", cfg_ok, " h431=", wire_431_ok && pipe_431_ok,
        " h413=", cl_413_ok && chunk_413_ok && pipe_cl_413,
        " within_ok=", valid_200_ok, " h2_streams_42=", h2_settings_ok);
    // CHECK: limits_cfg=true h431=true h413=true within_ok=true h2_streams_42=true
}

// ---- 5. Header Visibility Hygiene (ServerHeaderPolicy) ---------------------

fn test_server_header_visibility() {
    print("=== 5. Header Visibility Policy ===");
    // CHECK: === 5. Header Visibility Policy ===

    var srv = server::new_http_server("127.0.0.1", 0);
    srv.pipeline.enable_csrf_guard = false;
    srv.pipeline.enable_rate_limiter = false;
    assert(server::add_static_route(srv.pipeline.router, "GET", "/hi", "text/plain", "hi"));
    let req_wire = "GET /hi HTTP/1.1\r\nHost: localhost\r\n\r\n";

    var out_std: u8[..2048] = [];
    server::set_server_header_visibility(srv, server::ServerHeaderPolicy.Standard);
    let _, ok_std = server::handle_connection_wire(srv, "127.0.0.1", req_wire, 1000000000, out_std);
    let std_ok = ok_std && core::contains(out_std[..], "\r\nServer: ") && core::contains(out_std[..], "\r\nDate: ");

    var out_nosrv: u8[..2048] = [];
    server::set_server_header_visibility(srv, server::ServerHeaderPolicy.OmitServer);
    let _, ok_ns = server::handle_connection_wire(srv, "127.0.0.1", req_wire, 1000000000, out_nosrv);
    let nosrv_ok = ok_ns && !core::contains(out_nosrv[..], "\r\nServer: ") && core::contains(out_nosrv[..], "\r\nDate: ");

    var out_nodate: u8[..2048] = [];
    server::set_server_header_visibility(srv, server::ServerHeaderPolicy.OmitDate);
    let _, ok_nd = server::handle_connection_wire(srv, "127.0.0.1", req_wire, 1000000000, out_nodate);
    let nodate_ok = ok_nd && core::contains(out_nodate[..], "\r\nServer: ") && !core::contains(out_nodate[..], "\r\nDate: ");

    // OmitBoth on both single-turn wire AND pipelined static L0 route AND chunked response
    var out_none: u8[..2048] = [];
    server::set_server_header_visibility(srv, server::ServerHeaderPolicy.OmitBoth);
    let _, ok_nb = server::handle_connection_wire(srv, "127.0.0.1", req_wire, 1000000000, out_none);
    var out_pipe_none: u8[..2048] = [];
    let _, _, ok_pnb, _ = server::handle_connection_wire_pipelined_stream(
        srv, "127.0.0.1", req_wire, 1000000000, out_pipe_none,
    );
    var ch_res = http::Response { status_code: 200, .. };
    http::set_header(ch_res, "Transfer-Encoding", "chunked");
    ch_res.body.append("chunk-body");
    var out_chunk_none: u8[..2048] = [];
    server::serialize_http1_response(
        ch_res, srv.server_name[..], out_chunk_none, 0, server::ServerHeaderPolicy.OmitBoth,
    );
    let both_ok = ok_nb && ok_pnb &&
        !core::contains(out_none[..], "\r\nServer: ") && !core::contains(out_none[..], "\r\nDate: ") &&
        !core::contains(out_pipe_none[..], "\r\nServer: ") && !core::contains(out_pipe_none[..], "\r\nDate: ") &&
        !core::contains(out_chunk_none[..], "\r\nServer: ") && !core::contains(out_chunk_none[..], "\r\nDate: ");

    print("std=", std_ok, " omit_server=", nosrv_ok, " omit_date=", nodate_ok, " omit_both=", both_ok);
    // CHECK: std=true omit_server=true omit_date=true omit_both=true
}

// ---- 6. Socket Options, listen_http_server & max_connections Cap -----------

thread_fn single_conn_cap_worker(listener_fd: i64) {
    var srv = server::new_http_server("127.0.0.1", 0);
    srv.pipeline.enable_csrf_guard = false;
    srv.pipeline.enable_rate_limiter = false;
    assert(server::add_static_route(srv.pipeline.router, "GET", "/cap", "text/plain", "cap-ok"));
    server::set_server_limits(srv, 4096, 4096, 1, 100);
    server::set_server_header_visibility(srv, server::ServerHeaderPolicy.OmitBoth);
    let served = server::serve(srv, listener_fd, 0);
    assert(served == 1);
}

fn test_socket_options_and_listen_http_server() {
    print("=== 6. Socket Options & listen_http_server ===");
    // CHECK: === 6. Socket Options & listen_http_server ===

    var srv = server::new_http_server("127.0.0.1", 0);
    let opts = server::ServerSocketOptions {
        listen_backlog: 64,
        so_reuseport:   true,
        tcp_nodelay:    false,
    };
    server::set_server_socket_options(srv, opts);
    let opts_ok = srv.listen_backlog == 64 && srv.so_reuseport && !srv.tcp_nodelay;

    let lfd = server::listen_http_server(srv);
    assert(lfd > 0);
    let port = net::tcp_getsockname_port(lfd);
    assert(port > 0);

    let tid = thread_spawn(single_conn_cap_worker, lfd);
    let cfd = net::tcp_connect("127.0.0.1", port, 4000);
    assert(cfd > 0);
    let req = "GET /cap HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n";
    assert(net::tcp_send(cfd, req) == req.len as i32);
    var rx: u8[..2048] = [];
    for _ in 8 {
        let nr = net::tcp_recv(cfd, rx, 2048, 2000);
        if nr <= 0 { break; }
    }
    net::tcp_close(cfd);
    assert(thread_wait(tid));
    net::tcp_close(lfd);

    let resp_ok = core::starts_with(rx[..], "HTTP/1.1 200 OK\r\n") &&
        core::contains(rx[..], "cap-ok") &&
        !core::contains(rx[..], "\r\nServer: ") &&
        !core::contains(rx[..], "\r\nDate: ");

    // Also verify reactor_listen_accelerated respects srv.listen_backlog
    let afd = server::reactor_listen_accelerated(srv);
    let accel_ok = afd > 0 && net::tcp_getsockname_port(afd) > 0;
    if afd > 0 { net::tcp_close(afd); }

    print("sock_opts=", opts_ok, " listen_and_cap=", resp_ok, " accel_listen=", accel_ok);
    // CHECK: sock_opts=true listen_and_cap=true accel_listen=true
}

fn main() {
    test_server_tls_controls_validation();
    test_openssl_mtls_alpn_keylog_loopback();
    test_server_timeouts_sync();
    test_server_dos_limits();
    test_server_header_visibility();
    test_socket_options_and_listen_http_server();
}
