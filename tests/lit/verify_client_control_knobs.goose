// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Verification of client and net control knobs:
// 1. net::IpFamily, net::tcp_connect_ex (local_bind_addr + family filter),
//    net::TcpConnectOptions, and net::StreamPool (max_conns_per_host + disable_keepalive).
// 2. Promoted client::Config fields, setters, add_no_proxy/is_no_proxy_host,
//    add_resolve_override, and live dead-proxy bypass via no_proxy.
// 3. auto_decompress: false preserving raw gzip bytes vs true decompressing,
//    and max_response_body_bytes rejecting oversize raw & decompressed bodies fail-closed.
// 4. Live loopback TLS 1.3 + HTTP/1.1 verifying tls_alpn, mTLS PEM files,
//    tls_enable_pq_hybrid, tls_enable_session_tickets, tls_require_ocsp_stapling,
//    tls_crl_file, tls_keylog_file, enable_ktls_offload, resolve_override, and split timeouts.
//
// RUN: goose build -O0 -o %t.exe %s
// RUN: %t.exe | %FileCheck %s

import std;
import os;
import wing from "../..";

fn make_temp_path(suffix: const u8[:], out: u8[..256]&) {
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

fn encode_pem(label: const u8[:], der: const u8[:], out: u8[>..]&) {
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

fn build_cn_name_der(cn: const u8[:], out: u8[..256]&) {
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
    assert(out.try_set(b_name.buf[..]));
}

fn make_p256_cert_der(priv_key: const u8[32]&, dns_san: const u8[:], out_der: u8[..2048]&) -> bool {
    let pub65 = core::ecdsa_p256_public_key(priv_key);
    let alg = "\x30\x0A\x06\x08\x2A\x86\x48\xCE\x3D\x04\x03\x02";
    var name_der: u8[..256] = [];
    build_cn_name_der(dns_san, name_der);

    var b_tbs = core::builder_init();
    b_tbs.put_bytes("\xA0\x03\x02\x01\x02\x02\x01\x0B");
    b_tbs.put_bytes(alg);
    b_tbs.put_bytes(name_der[..]);
    b_tbs.put_bytes("\x30\x1E\x17\x0D240101000000Z\x17\x0D351231235959Z");
    b_tbs.put_bytes(name_der[..]);
    b_tbs.put_bytes("\x30\x59\x30\x13\x06\x07\x2A\x86\x48\xCE\x3D\x02\x01");
    b_tbs.put_bytes("\x06\x08\x2A\x86\x48\xCE\x3D\x03\x01\x07\x03\x42\x00");
    b_tbs.put_bytes(pub65[..]);

    var b_ext = core::builder_init();
    b_ext.put_bytes("\x30\x0C\x06\x03\x55\x1D\x13\x04\x05\x30\x03\x01\x01\xFF");
    var b_san = core::builder_init();
    b_san.put_u8(0x82);
    b_san.put_u8(dns_san.len as u8);
    b_san.put_bytes(dns_san);
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

    var tmp_der: u8[..2048] = [];
    wrap_der_tlv(0x30, b_cert.buf[..], tmp_der);
    return out_der.try_set(tmp_der[..]);
}

fn make_p256_pkcs8_der(priv_key: const u8[32]&, out_der: u8[..512]&) -> bool {
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

fn make_p256_crl_der(
    issuer_priv:    const u8[32]&,
    issuer_cn:      const u8[:],
    revoked_serial: u8,
    out_der:        u8[..2048]&,
) -> bool {
    let alg = "\x30\x0A\x06\x08\x2A\x86\x48\xCE\x3D\x04\x03\x02";
    var name_der: u8[..256] = [];
    build_cn_name_der(issuer_cn, name_der);

    var b_entry = core::builder_init();
    b_entry.put_bytes("\x02\x01");
    b_entry.put_u8(revoked_serial);
    b_entry.put_bytes("\x17\x0D240102000000Z");

    var entry_tlv: u8[..2048] = [];
    wrap_der_tlv(0x30, b_entry.buf[..], entry_tlv);
    var rev_list: u8[..2048] = [];
    wrap_der_tlv(0x30, entry_tlv[..], rev_list);

    var b_tbs = core::builder_init();
    b_tbs.put_bytes("\x02\x01\x01");
    b_tbs.put_bytes(alg);
    b_tbs.put_bytes(name_der[..]);
    b_tbs.put_bytes("\x17\x0D240101000000Z");
    b_tbs.put_bytes("\x17\x0D351231235959Z");
    b_tbs.put_bytes(rev_list[..]);

    var tbs_wrapped: u8[..2048] = [];
    wrap_der_tlv(0x30, b_tbs.buf[..], tbs_wrapped);
    let raw_sig = core::ecdsa_p256_sign(issuer_priv, tbs_wrapped[..]);
    var der_sig: u8[..72] = [];
    guard core::ecdsa_p256_encode_der_sig(raw_sig, der_sig) else { return false; }

    var b_crl = core::builder_init();
    b_crl.put_bytes(tbs_wrapped[..]);
    b_crl.put_bytes(alg);
    b_crl.put_u8(0x03);
    b_crl.put_u8((1 + der_sig.len) as u8);
    b_crl.put_u8(0x00);
    b_crl.put_bytes(der_sig[..]);

    var tmp_der: u8[..2048] = [];
    wrap_der_tlv(0x30, b_crl.buf[..], tmp_der);
    return out_der.try_set(tmp_der[..]);
}

// ---- 1. Net IP Family, Local Bind, and StreamPool Knobs --------------------

thread_fn accept_two_and_close_worker(listener_fd: i64) {
    for _ in 2 {
        let conn = net::tcp_accept(listener_fd, 5000);
        if conn > 0 {
            sleep_ms(30);
            net::tcp_close(conn);
        }
    }
}

fn test_net_ip_family_bind_and_pool() {
    print("=== 1. Net IP Family, Local Bind & StreamPool ===");
    // CHECK: === 1. Net IP Family, Local Bind & StreamPool ===

    let lst = net::tcp_listen("127.0.0.1", 0, 8);
    assert(lst > 0);
    let port = net::tcp_getsockname_port(lst);
    let tid = thread_spawn(accept_two_and_close_worker, lst);

    let fd_v4 = net::tcp_connect_ex("127.0.0.1", port, 2000, net::IpFamily.Ipv4Only, "127.0.0.1");
    let v4_bind_ok = fd_v4 > 0;
    if fd_v4 > 0 { net::tcp_close(fd_v4); }

    let fd_v6_on_v4 = net::tcp_connect_ex("127.0.0.1", port, 1000, net::IpFamily.Ipv6Only, "");
    let fd_v4_on_v6 = net::tcp_connect_ex("::1", port, 1000, net::IpFamily.Ipv4Only, "");
    let family_reject_ok = fd_v6_on_v4 < 0 && fd_v4_on_v6 < 0;

    var opts_ok = net::TcpConnectOptions {
        dst_ip:    "127.0.0.1",
        dst_port:  port,
        ip_family: net::IpFamily.Ipv4Only,
        ..
    };
    assert(opts_ok.local_bind_addr.try_set("127.0.0.1"));
    var st_ok:  i32 = 0;
    var err_ok: i32 = 0;
    let fd_opts = net::tcp_connect_with_options(opts_ok, st_ok, err_ok);
    let opts_bind_ok = fd_opts > 0;
    if fd_opts > 0 { net::tcp_close(fd_opts); }

    var opts_bad = opts_ok;
    opts_bad.ip_family = net::IpFamily.Ipv6Only;
    var st_bad:  i32 = 0;
    var err_bad: i32 = 0;
    let opts_reject_ok = net::tcp_connect_with_options(opts_bad, st_bad, err_bad) < 0;

    assert(thread_wait(tid));
    net::tcp_close(lst);

    // StreamPool max_conns_per_host & disable_keepalive enforcement
    var pool = net::new_stream_pool();
    net::configure_stream_pool(pool, 2, false, 5000000000);
    let pool_cfg_ok = pool.max_conns_per_host == 2 && !pool.disable_keepalive && pool.idle_timeout_ns == 5000000000;

    let nik = net::new_network_isolation_key("cap.wing.test", "cap.wing.test");
    let key = net::new_pool_key(
        net::PoolScheme.Http, "cap.wing.test", 80, net::new_direct_proxy_chain(),
        net::nik_to_anonymization_key(nik, false),
        net::TlsAndDnsPolicy { .. },
    );
    let c1 = net::register_connection(
        pool, key, net::NegotiatedProtocol.Http11, net::Transport.Mock { route_idx: 0, cursor: 0 }, "127.0.0.1", 1, 1000,
    );
    let c2 = net::register_connection(
        pool, key, net::NegotiatedProtocol.Http11, net::Transport.Mock { route_idx: 1, cursor: 0 }, "127.0.0.1", 1, 2000,
    );
    let cap_blocks_third_active = !net::can_allocate_group_socket(pool, key);
    net::release_connection(pool, c1, 3000);
    let cap_allows_after_evict = net::can_allocate_group_socket(pool, key);

    net::configure_stream_pool(pool, 2, true, -1);
    let acq_id, acq_ok = net::acquire_pooled_connection(pool, key, "127.0.0.1", 4000);
    net::release_connection(pool, c2, 4500);
    let no_ka_ok = !acq_ok && acq_id < 0 && pool.find_connection_index(c2) < 0;
    net::drain_stream_pool(pool);

    print("v4_bind=", v4_bind_ok, " family_reject=", family_reject_ok, " opts_bind=", opts_bind_ok,
        " opts_reject=", opts_reject_ok, " pool_cap=", pool_cfg_ok && cap_blocks_third_active && cap_allows_after_evict,
        " no_keepalive=", no_ka_ok);
    // CHECK: v4_bind=true family_reject=true opts_bind=true opts_reject=true pool_cap=true no_keepalive=true
}

// ---- 2. Promoted Config Fields, Setters, No-Proxy & Resolve Override -------

fn test_promoted_config_setters_and_no_proxy() {
    print("=== 2. Promoted Config, Setters & No-Proxy ===");
    // CHECK: === 2. Promoted Config, Setters & No-Proxy ===

    var sess = client::new_client(client::Config {
        timeout_ms:                 8000,
        connect_timeout_ms:         900,
        tls_handshake_timeout_ms:   1200,
        read_timeout_ms:            1500,
        pool_idle_timeout_ms:       4500,
        redirect_mode:              client::RedirectMode.Error,
        max_redirects:              4,
        https_only:                 true,
        enable_referer:             false,
        default_referrer_policy:    client::ReferrerPolicy.Origin,
        enable_hsts:                false,
        enable_doh:                 true,
        enable_ech:                 true,
        http2_prior_knowledge:      true,
        auto_decompress:            false,
        max_response_body_bytes:    2048,
        max_retries:                3,
        verify_content_digest:      true,
        enable_early_data:          true,
        enable_har_telemetry:       true,
        allow_loopback_ssrf:        true,
        tls_client_cert_file:       "c.pem",
        tls_client_key_file:        "k.pem",
        tls_enable_pq_hybrid:       true,
        tls_alpn:                   "http/1.1",
        tls_enable_session_tickets: false,
        tls_require_ocsp_stapling:  true,
        tls_crl_file:               "revoked.crl",
        tls_keylog_file:            "keys.log",
        enable_ktls_offload:        true,
        ip_family:                  net::IpFamily.Ipv4Only,
        local_bind_addr:            "127.0.0.1",
        tcp_nodelay:                false,
        tcp_keepalive_idle_sec:     15,
        tcp_keepalive_intvl_sec:    4,
        tcp_keepalive_cnt:          2,
        disable_keepalive:          true,
        max_conns_per_host:         5,
        use_env_proxy:              true,
        ..
    });

    let retry_pol, has_retry = client::find_retry_policy(sess.pipeline);
    let cfg_ok = sess.connect_timeout_ms == 900 && sess.tls_handshake_timeout_ms == 1200 &&
        sess.read_timeout_ms == 1500 && sess.pool_idle_timeout_ms == 4500 &&
        sess.pool.idle_timeout_ns == 4500000000 && sess.pool.max_conns_per_host == 5 &&
        sess.pool.disable_keepalive && sess.redirect_mode == client::RedirectMode.Error &&
        !sess.follow_redirects && sess.max_redirects == 4 && sess.https_only &&
        !sess.enable_referer && sess.default_referrer_policy == client::ReferrerPolicy.Origin &&
        !sess.enable_hsts && sess.enable_doh && sess.enable_ech && sess.http2_prior_knowledge &&
        !sess.auto_decompress && sess.max_response_body_bytes == 2048 && sess.max_retries == 3 &&
        has_retry && retry_pol.max_retries == 3 && sess.verify_content_digest &&
        sess.enable_early_data && sess.enable_har_telemetry && sess.allow_loopback_ssrf &&
        !sess.ssrf_guard.deny_local_network && sess.tls_enable_pq_hybrid &&
        sess.tls_alpn[..] == "http/1.1" && !sess.tls_enable_session_tickets &&
        sess.tls_require_ocsp_stapling && sess.tls_crl_file[..] == "revoked.crl" &&
        sess.tls_keylog_file[..] == "keys.log" && sess.enable_ktls_offload &&
        sess.ip_family == net::IpFamily.Ipv4Only && sess.local_bind_addr[..] == "127.0.0.1" &&
        !sess.tcp_nodelay && sess.tcp_keepalive_idle_sec == 15 &&
        sess.tcp_keepalive_intvl_sec == 4 && sess.tcp_keepalive_cnt == 2 && sess.use_env_proxy;

    let mut_ok = !client::set_tls_client_cert(sess, "only_cert.pem", "") &&
        client::set_tls_client_cert(sess, "a.pem", "b.pem") &&
        client::set_tls_client_cert(sess, "", "") &&
        client::set_tls_alpn(sess, "h2,http/1.1") &&
        !client::set_tls_alpn(sess, " , ") &&
        client::set_tls_crl_file(sess, "") &&
        client::set_tls_keylog_file(sess, "") &&
        !client::add_resolve_override(sess, "api.wing.test", 443, "not-an-ip") &&
        client::add_resolve_override(sess, "api.wing.test", 443, "127.0.0.1") &&
        client::add_resolve_override(sess, "api.wing.test", 443, "127.0.0.2") &&
        sess.resolve_overrides.len == 1 && sess.resolve_overrides[0].ip[..] == "127.0.0.2";

    client::set_tls_enable_pq_hybrid(sess, false);
    client::set_tls_enable_session_tickets(sess, true);
    client::set_tls_require_ocsp_stapling(sess, false);
    client::set_ip_family(sess, net::IpFamily.Auto);
    client::set_auto_decompress(sess, true);
    client::set_max_response_body_bytes(sess, -10);
    let setters_ok = mut_ok && !sess.tls_enable_pq_hybrid && sess.tls_enable_session_tickets &&
        !sess.tls_require_ocsp_stapling && sess.ip_family == net::IpFamily.Auto &&
        sess.auto_decompress && sess.max_response_body_bytes == 0;

    var np = client::new_client();
    assert(client::add_no_proxy(np, "exact.corp"));
    assert(client::add_no_proxy(np, ".internal.local"));
    assert(client::add_no_proxy(np, "10.0.0.0/8"));
    assert(client::add_no_proxy(np, "fd00::/8"));
    assert(client::add_no_proxy(np, "localhost"));
    let np_ok = client::is_no_proxy_host(np, "EXACT.CORP:443") &&
        !client::is_no_proxy_host(np, "sub.exact.corp") &&
        client::is_no_proxy_host(np, "api.internal.local") &&
        client::is_no_proxy_host(np, "internal.local") &&
        !client::is_no_proxy_host(np, "badinternal.local") &&
        client::is_no_proxy_host(np, "10.42.1.9:8080") &&
        !client::is_no_proxy_host(np, "11.0.0.1") &&
        client::is_no_proxy_host(np, "[fd12::1]:443") &&
        client::is_no_proxy_host(np, "localhost") &&
        client::is_no_proxy_host(np, "svc.localhost");

    var np_star = client::new_client();
    assert(client::add_no_proxy(np_star, "*"));
    let star_ok = client::is_no_proxy_host(np_star, "anything.example.org");

    print("promoted_cfg=", cfg_ok, " setters=", setters_ok, " no_proxy=", np_ok && star_ok);
    // CHECK: promoted_cfg=true setters=true no_proxy=true
}

// ---- 3. auto_decompress & max_response_body_bytes Enforcement --------------

fn test_auto_decompress_and_body_limits() {
    print("=== 3. auto_decompress & max_response_body_bytes ===");
    // CHECK: === 3. auto_decompress & max_response_body_bytes ===

    var plain: u8[..256] = [];
    for _ in 5 {
        assert(plain.try_append("WING-GZIP-PASSTHROUGH-0123456789"));
    }
    var gz: u8[..256] = [];
    assert(core::gzip_compress(plain[..], gz));
    assert(gz.len > 20 && gz.len < 80 && gz[0] == 0x1F && gz[1] == 0x8B);

    // 3a. auto_decompress: false preserves raw gzip bytes and Content-Encoding header.
    var c_raw = client::new_client(client::Config {
        auto_decompress:         false,
        max_response_body_bytes: 80,
        ..
    });
    let _ = client::mock_route(c_raw, "GET", "https://api.example/gz", 200, gz[..]);
    client::add_mock_header(c_raw, "Content-Encoding", "gzip");
    let r_raw, e_raw = client::get(c_raw, "https://api.example/gz");
    let raw_ok = http::ok(e_raw) && r_raw.status_code == 200 &&
        r_raw.body[..] == gz[..] && r_raw.header("Content-Encoding") == "gzip";

    // 3b. auto_decompress: true inflates gzip body to plaintext.
    var c_dec = client::new_client(client::Config { auto_decompress: true, .. });
    let _ = client::mock_route(c_dec, "GET", "https://api.example/gz", 200, gz[..]);
    client::add_mock_header(c_dec, "Content-Encoding", "gzip");
    let r_dec, e_dec = client::get(c_dec, "https://api.example/gz");
    let dec_ok = http::ok(e_dec) && r_dec.body[..] == plain[..];

    // 3c. max_response_body_bytes rejects decompressed overflow fail-closed (zip-bomb guard).
    client::set_max_response_body_bytes(c_dec, 80);
    let r_bomb, e_bomb = client::get(c_dec, "https://api.example/gz");
    let bomb_reject_ok = !http::ok(e_bomb) && e_bomb.code == 413 && r_bomb.body.len == 0;

    // 3d. max_response_body_bytes rejects oversize raw wire body fail-closed.
    client::set_max_response_body_bytes(c_raw, 20);
    let r_big, e_big = client::get(c_raw, "https://api.example/gz");
    let raw_reject_ok = !http::ok(e_big) && e_big.code == 413 && r_big.body.len == 0;

    print("raw_passthrough=", raw_ok, " auto_dec=", dec_ok,
        " decomp_limit_reject=", bomb_reject_ok, " raw_limit_reject=", raw_reject_ok);
    // CHECK: raw_passthrough=true auto_dec=true decomp_limit_reject=true raw_limit_reject=true
}

// ---- 4. Live Loopback TLS 1.3, mTLS, ALPN, CRL, Keylog, Resolve & Timeouts -

thread_fn tls_knobs_server_worker(listener_fd: i64) {
    let srv_seed: u8[32] = [0x61; 32];
    let cli_seed: u8[32] = [0x62; 32];
    var srv_cert: u8[..2048] = [];
    var cli_cert: u8[..2048] = [];
    assert(make_p256_cert_der(srv_seed, "api.wing.test", srv_cert));
    assert(make_p256_cert_der(cli_seed, "cli.wing.test", cli_cert));

    var cli_trust = tls::TrustAnchorStore { .. };
    assert(tls::add_trust_anchor_cert_der(cli_trust, cli_cert[..]));

    var srv_cfg = tls::ServerHandshakeConfig {
        priv_seed:            srv_seed,
        handshake_timeout_ms: 2500,
        require_client_cert:  true,
        client_trust_store:   cli_trust,
        ..
    };
    assert(srv_cfg.cert_der.try_set(srv_cert[..]));
    assert(srv_cfg.alpn.try_set("h2,http/1.1"));

    // Conn 1: full mTLS + ALPN http/1.1 + resolve override + non-revoking CRL + keylog.
    let c1 = net::tcp_accept(listener_fd, 5000);
    assert(c1 > 0);
    let s1, ok1 = tls::server_handshake(c1, srv_cfg);
    assert(ok1 && s1 != 0xFFFF);
    var req_buf: u8[2048] = [0; 2048];
    let n1 = tls::transport_recv_slice(c1, s1, req_buf[..], 2500);
    let neg_alpn = tls::session_alpn(s1);
    let saw_host = n1 > 0 && core::contains(req_buf[..n1], "Host: api.wing.test");
    if neg_alpn == "http/1.1" && saw_host {
        let _ = tls::transport_send(
            c1, s1, "HTTP/1.1 200 OK\r\nContent-Length: 21\r\nConnection: close\r\n\r\nALPN=http/1.1;MTLS=OK",
        );
    } else {
        let _ = tls::transport_send(
            c1, s1, "HTTP/1.1 500 Internal Server Error\r\nContent-Length: 4\r\nConnection: close\r\n\r\nFAIL",
        );
    }
    sleep_ms(30);
    tls::transport_close(c1, s1);

    // Conn 2 (require_ocsp_stapling) & Conn 3 (revoked CRL): client rejects during handshake.
    for _ in 2 {
        let cx = net::tcp_accept(listener_fd, 5000);
        if cx > 0 {
            let sx, okx = tls::server_handshake(cx, srv_cfg);
            if okx {
                tls::transport_close(cx, sx);
            } else {
                net::tcp_close(cx);
            }
        }
    }
}

thread_fn plain_http_and_timeout_worker(listener_fd: i64) {
    // Conn 1: direct request bypassing dead proxy via no_proxy.
    let c1 = net::tcp_accept(listener_fd, 5000);
    if c1 > 0 {
        var rx: u8[1024] = [0; 1024];
        let _ = net::tcp_recv_slice(c1, rx[..], 2500);
        let _ = net::tcp_send(
            c1, "HTTP/1.1 200 OK\r\nContent-Length: 9\r\nConnection: close\r\n\r\nDIRECT-OK",
        );
        sleep_ms(30);
        net::tcp_close(c1);
    }
    // Conn 2: reads request then stalls to trigger client read_timeout_ms.
    let c2 = net::tcp_accept(listener_fd, 5000);
    if c2 > 0 {
        var rx2: u8[1024] = [0; 1024];
        let _ = net::tcp_recv_slice(c2, rx2[..], 2500);
        sleep_ms(300);
        net::tcp_close(c2);
    }
}

thread_fn silent_tls_worker(listener_fd: i64) {
    let conn = net::tcp_accept(listener_fd, 5000);
    if conn > 0 {
        sleep_ms(300);
        net::tcp_close(conn);
    }
}

fn test_live_tls_knobs() {
    print("=== 4. Live TLS mTLS, ALPN, Resolve, CRL, OCSP, Keylog ===");
    // CHECK: === 4. Live TLS mTLS, ALPN, Resolve, CRL, OCSP, Keylog ===

    let srv_seed: u8[32] = [0x61; 32];
    let cli_seed: u8[32] = [0x62; 32];
    var srv_cert_der: u8[..2048] = [];
    var cli_cert_der: u8[..2048] = [];
    var cli_key_der:  u8[..512]  = [];
    var crl_ok_der:   u8[..2048] = [];
    var crl_rev_der:  u8[..2048] = [];
    assert(make_p256_cert_der(srv_seed, "api.wing.test", srv_cert_der));
    assert(make_p256_cert_der(cli_seed, "cli.wing.test", cli_cert_der));
    assert(make_p256_pkcs8_der(cli_seed, cli_key_der));
    assert(make_p256_crl_der(srv_seed, "api.wing.test", 0x59, crl_ok_der));
    assert(make_p256_crl_der(srv_seed, "api.wing.test", 0x0B, crl_rev_der));

    var ca_pem:      u8[>..] = [];
    var cli_crt_pem: u8[>..] = [];
    var cli_key_pem: u8[>..] = [];
    var crl_ok_pem:  u8[>..] = [];
    var crl_rev_pem: u8[>..] = [];
    encode_pem("CERTIFICATE", srv_cert_der[..], ca_pem);
    encode_pem("CERTIFICATE", cli_cert_der[..], cli_crt_pem);
    encode_pem("PRIVATE KEY", cli_key_der[..], cli_key_pem);
    encode_pem("X509 CRL", crl_ok_der[..], crl_ok_pem);
    encode_pem("X509 CRL", crl_rev_der[..], crl_rev_pem);

    var ca_path:      u8[..256] = [];
    var cli_crt_path: u8[..256] = [];
    var cli_key_path: u8[..256] = [];
    var crl_ok_path:  u8[..256] = [];
    var crl_rev_path: u8[..256] = [];
    var keylog_path:  u8[..256] = [];
    make_temp_path("wing_cli_knobs_ca.pem", ca_path);
    make_temp_path("wing_cli_knobs_mtls.crt", cli_crt_path);
    make_temp_path("wing_cli_knobs_mtls.key", cli_key_path);
    make_temp_path("wing_cli_knobs_ok.crl", crl_ok_path);
    make_temp_path("wing_cli_knobs_rev.crl", crl_rev_path);
    make_temp_path("wing_cli_knobs_keys.log", keylog_path);
    let _ = delete_file(keylog_path[..]);
    assert(write_file_atomic(ca_path[..], ca_pem[..]));
    assert(write_file_atomic(cli_crt_path[..], cli_crt_pem[..]));
    assert(write_file_atomic(cli_key_path[..], cli_key_pem[..]));
    assert(write_file_atomic(crl_ok_path[..], crl_ok_pem[..]));
    assert(write_file_atomic(crl_rev_path[..], crl_rev_pem[..]));
    defer {
        let _ = delete_file(ca_path[..]);
        let _ = delete_file(cli_crt_path[..]);
        let _ = delete_file(cli_key_path[..]);
        let _ = delete_file(crl_ok_path[..]);
        let _ = delete_file(crl_rev_path[..]);
        let _ = delete_file(keylog_path[..]);
    };

    let lst = net::tcp_listen("127.0.0.1", 0, 8);
    assert(lst > 0);
    let port = net::tcp_getsockname_port(lst);
    let tid = thread_spawn(tls_knobs_server_worker, lst);

    var url_buf: u8[..128] = [];
    format(url_buf, "https://api.wing.test:", port, "/knobs");

    var sess = client::new_client(client::Config {
        timeout_ms:                 4000,
        connect_timeout_ms:         2000,
        tls_handshake_timeout_ms:   2500,
        read_timeout_ms:            2500,
        allow_loopback_ssrf:        true,
        tls_ca_file:                ca_path[..],
        tls_use_system_roots:       false,
        tls_client_cert_file:       cli_crt_path[..],
        tls_client_key_file:        cli_key_path[..],
        tls_alpn:                   "http/1.1",
        tls_enable_pq_hybrid:       true,
        tls_enable_session_tickets: false,
        tls_crl_file:               crl_ok_path[..],
        tls_keylog_file:            keylog_path[..],
        enable_ktls_offload:        true,
        ip_family:                  net::IpFamily.Ipv4Only,
        local_bind_addr:            "127.0.0.1",
        disable_keepalive:          true,
        ..
    });
    assert(client::add_resolve_override(sess, "api.wing.test", port, "127.0.0.1"));

    let r1, e1 = client::get(sess, url_buf[..]);
    let ok_mtls_alpn = http::ok(e1) && r1.status_code == 200 &&
        r1.protocol[..] == "HTTP/1.1" && r1.body[..] == "ALPN=http/1.1;MTLS=OK";

    var klog_bytes: u8[>..] = [];
    let ok_keylog = read_file(keylog_path[..], klog_bytes) &&
        core::contains(klog_bytes[..], "CLIENT_HANDSHAKE_TRAFFIC_SECRET ") &&
        core::contains(klog_bytes[..], "CLIENT_TRAFFIC_SECRET_0 ");

    // Conn 2: tls_require_ocsp_stapling: true fails closed without stapled OCSP.
    client::set_tls_require_ocsp_stapling(sess, true);
    let _, e_ocsp = client::get(sess, url_buf[..]);
    let ok_ocsp_reject = !http::ok(e_ocsp);

    // Conn 3: tls_crl_file revoking server cert serial 0x0B fails closed.
    client::set_tls_require_ocsp_stapling(sess, false);
    assert(client::set_tls_crl_file(sess, crl_rev_path[..]));
    let _, e_crl = client::get(sess, url_buf[..]);
    let ok_crl_reject = !http::ok(e_crl);

    client::close(sess);
    assert(thread_wait(tid));
    net::tcp_close(lst);

    print("mtls_alpn_resolve=", ok_mtls_alpn, " keylog=", ok_keylog,
        " ocsp_reject=", ok_ocsp_reject, " crl_reject=", ok_crl_reject);
    // CHECK: mtls_alpn_resolve=true keylog=true ocsp_reject=true crl_reject=true
}

fn test_live_no_proxy_and_split_timeouts() {
    print("=== 5. Live No-Proxy Bypass & Split Timeouts ===");
    // CHECK: === 5. Live No-Proxy Bypass & Split Timeouts ===

    let lst = net::tcp_listen("127.0.0.1", 0, 8);
    assert(lst > 0);
    let port = net::tcp_getsockname_port(lst);
    let tid = thread_spawn(plain_http_and_timeout_worker, lst);

    var url_buf: u8[..128] = [];
    format(url_buf, "http://127.0.0.1:", port, "/direct");

    // 5a. Dead proxy is bypassed via add_no_proxy("127.0.0.1") so direct request succeeds.
    var sess = client::new_client(client::Config {
        proxy_url:           "http://127.0.0.1:1",
        timeout_ms:          4000,
        connect_timeout_ms:  1500,
        read_timeout_ms:     1500,
        allow_loopback_ssrf: true,
        disable_keepalive:   true,
        ..
    });
    assert(client::add_no_proxy(sess, "127.0.0.1"));
    let r_dir, e_dir = client::get(sess, url_buf[..]);
    let ok_bypass = http::ok(e_dir) && r_dir.status_code == 200 && r_dir.body[..] == "DIRECT-OK";

    // 5b. read_timeout_ms: 80 aborts stalled HTTP response fast.
    sess.read_timeout_ms = 80;
    let t_r0 = core::monotonic_now().nanos;
    let _, e_rto = client::get(sess, url_buf[..]);
    let read_ms = core::sub_sat_u64(core::monotonic_now().nanos, t_r0) / 1000000;
    let ok_read_to = !http::ok(e_rto) && read_ms < 2500;
    client::close(sess);
    assert(thread_wait(tid));
    net::tcp_close(lst);

    // 5c. tls_handshake_timeout_ms: 80 aborts silent TLS peer fast.
    let lst_tls = net::tcp_listen("127.0.0.1", 0, 4);
    assert(lst_tls > 0);
    let port_tls = net::tcp_getsockname_port(lst_tls);
    let tid_tls = thread_spawn(silent_tls_worker, lst_tls);

    var tls_url: u8[..128] = [];
    format(tls_url, "https://127.0.0.1:", port_tls, "/slow");
    var sess_tls = client::new_client(client::Config {
        timeout_ms:               5000,
        connect_timeout_ms:       1500,
        tls_handshake_timeout_ms: 80,
        allow_loopback_ssrf:      true,
        insecure_skip_verify:     true,
        ..
    });
    let t_h0 = core::monotonic_now().nanos;
    let _, e_hto = client::get(sess_tls, tls_url[..]);
    let hs_ms = core::sub_sat_u64(core::monotonic_now().nanos, t_h0) / 1000000;
    let ok_tls_to = !http::ok(e_hto) && hs_ms < 2500;
    client::close(sess_tls);
    assert(thread_wait(tid_tls));
    net::tcp_close(lst_tls);

    print("no_proxy_bypass=", ok_bypass, " read_timeout_fast=", ok_read_to, " tls_timeout_fast=", ok_tls_to);
    // CHECK: no_proxy_bypass=true read_timeout_fast=true tls_timeout_fast=true
}

fn main() {
    test_net_ip_family_bind_and_pool();
    test_promoted_config_setters_and_no_proxy();
    test_auto_decompress_and_body_limits();
    test_live_tls_knobs();
    test_live_no_proxy_and_split_timeouts();

    print("=== ALL CLIENT & NET CONTROL KNOBS PASSED ===");
    // CHECK: === ALL CLIENT & NET CONTROL KNOBS PASSED ===
}
