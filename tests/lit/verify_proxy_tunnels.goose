// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Live loopback E2E verification of SOCKS5h remote DNS, HTTP CONNECT, and HTTPS
// forward proxy (TLS-in-TLS) tunneling in `client::Session` and `net::Transport`.
//
// RUN: goose build -O0 -o %t.exe %s
// RUN: %t.exe | %FileCheck %s

import std;
import wing from "../..";

struct RelayTarget {
    listen_fd:   i64 = -1,
    origin_port: u16 = 0,
}

fn send_all_raw_fd(fd: i64, data: const u8[:]) -> bool {
    var off: i64 = 0;
    while off < data.len {
        let n = net::tcp_send(fd, data[off..]);
        guard n > 0 else { return false; }
        off = core::add_sat_i64(off, n);
    }
    return true;
}

fn pump_bidirectional_raw_and_transport(client_t: net::Transport, up_fd: i64) {
    let _ = net::tcp_set_nonblocking(up_fd, true);
    var c_buf: u8[4096] = [0; 4096];
    var u_buf: u8[4096] = [0; 4096];
    for _ in 4000 {
        let n_c = client_t.recv_slice(c_buf[..], 10);
        if n_c > 0 {
            guard send_all_raw_fd(up_fd, c_buf[..n_c]) else { break; }
        } else if n_c == 0 || n_c == -1 {
            break;
        }
        let n_u = net::tcp_recv_nonblocking_slice(up_fd, u_buf[..]);
        if n_u > 0 {
            guard client_t.send(u_buf[..n_u]) == n_u else { break; }
        } else if n_u == 0 || n_u == -1 {
            break;
        }
    }
}

thread_fn plain_origin_worker(listen_fd: i64) {
    let conn = net::tcp_accept(listen_fd, 5000);
    guard conn > 0 else { return; }
    defer net::tcp_close(conn);
    var rx: u8[1024] = [0; 1024];
    let n = net::tcp_recv_slice(conn, rx[..], 5000);
    guard n > 0 else { return; }
    let body = if core::contains(rx[..n], "/socks5h") { "PONG-SOCKS5H" } else { "PONG-HTTP-CONNECT" };
    var resp: u8[..256] = [];
    format(resp, "HTTP/1.1 200 OK\r\nContent-Length: ", body.len, "\r\nConnection: close\r\n\r\n", body);
    let _ = send_all_raw_fd(conn, resp[..]);
}

thread_fn socks5h_proxy_worker(cfg: RelayTarget) {
    let conn = net::tcp_accept(cfg.listen_fd, 5000);
    guard conn > 0 else { return; }
    defer net::tcp_close(conn);

    // 1. Greeting + Username/Password (RFC 1928 / RFC 1929)
    var buf: u8[256] = [0; 256];
    let n1 = net::tcp_recv_slice(conn, buf[..], 5000);
    guard n1 >= 3 && buf[0] == 0x05 else { return; }
    let m_sel: u8[2] = [0x05, 0x02];
    guard send_all_raw_fd(conn, m_sel[..]) else { return; }

    let n2 = net::tcp_recv_slice(conn, buf[..], 5000);
    guard n2 >= 5 && buf[0] == 0x01 else { return; }
    let ulen = buf[1] as i64;
    let p_off = core::add_sat_i64(2, ulen);
    guard p_off < n2 else { return; }
    let plen = buf[p_off] as i64;
    let p_start = core::add_sat_i64(p_off, 1);
    let p_end = core::add_sat_i64(p_start, plen);
    guard p_end <= n2 && buf[2..p_off] == "bot" && buf[p_start..p_end] == "s3cr3t" else { return; }
    let a_ok: u8[2] = [0x01, 0x00];
    guard send_all_raw_fd(conn, a_ok[..]) else { return; }

    // 2. CONNECT with ATYP=0x03 (domain name proving local DNS was skipped!)
    let n3 = net::tcp_recv_slice(conn, buf[..], 5000);
    guard n3 >= 7 && buf[0] == 0x05 && buf[1] == 0x01 && buf[3] == 0x03 else { return; }
    let dlen = buf[4] as i64;
    let d_end = core::add_sat_i64(5, dlen);
    guard d_end <= n3 && buf[5..d_end] == "blocked.telegram.invalid" else { return; }

    let up_fd = net::tcp_connect("127.0.0.1", cfg.origin_port, 5000);
    guard up_fd > 0 else { return; }
    defer net::tcp_close(up_fd);

    let rep_ok: u8[10] = [0x05, 0x00, 0x00, 0x01, 127, 0, 0, 1, 0, 80];
    guard send_all_raw_fd(conn, rep_ok[..]) else { return; }
    pump_bidirectional_raw_and_transport(net::Transport.Tcp { fd: conn }, up_fd);
}

fn check_connect_head(raw: const u8[:], expect_host: const u8[:], expect_user: const u8[:], expect_pwd: const u8[:]) -> bool {
    guard core::starts_with(raw, "CONNECT ") else { return false; }
    let after_m = raw[8..];
    let target, _, ok_sp = after_m.split_once_byte(' ');
    guard ok_sp else { return false; }
    let host, _, ok_hp = net::parse_authority_host_port(target, 0, net::PortRequirement.Required);
    guard ok_hp && host[..] == expect_host else { return false; }
    let idx = raw.index_of_fold("proxy-authorization:");
    guard idx >= 0 else { return false; }
    let val_start = core::add_sat_i64(idx, 20);
    let line_tail = raw[val_start..];
    let line_end = line_tail.index_of_byte('\r');
    guard line_end > 0 else { return false; }
    var u: u8[..128] = [];
    var p: u8[..256] = [];
    defer core::secure_zeroize_slice(p[..]);
    guard net::decode_basic_proxy_auth(line_tail[..line_end], u, p) else { return false; }
    return core::ct_eq_bytes(u[..], expect_user) && core::ct_eq_bytes(p[..], expect_pwd);
}

thread_fn http_connect_proxy_worker(cfg: RelayTarget) {
    let conn = net::tcp_accept(cfg.listen_fd, 5000);
    guard conn > 0 else { return; }
    defer net::tcp_close(conn);
    var req_buf: u8[1024] = [0; 1024];
    let n = net::tcp_recv_slice(conn, req_buf[..], 5000);
    guard n > 0 && check_connect_head(req_buf[..n], "blocked.vk.invalid", "vkbot", "pass123") else { return; }
    let up_fd = net::tcp_connect("127.0.0.1", cfg.origin_port, 5000);
    guard up_fd > 0 else { return; }
    defer net::tcp_close(up_fd);
    guard send_all_raw_fd(conn, "HTTP/1.1 200 Connection Established\r\n\r\n") else { return; }
    pump_bidirectional_raw_and_transport(net::Transport.Tcp { fd: conn }, up_fd);
}

thread_fn tls_origin_worker(listen_fd: i64) {
    let conn = net::tcp_accept(listen_fd, 5000);
    guard conn > 0 else { return; }
    let seed: u8[32] = [0x44; 32];
    var cert: u8[..2048] = [];
    guard tls::build_test_ed25519_cert_der(seed, "blocked.max.invalid", "blocked.max.invalid", "", cert) else {
        net::tcp_close(conn);
        return;
    }
    var cfg = tls::ServerHandshakeConfig { priv_seed: seed, .. };
    let _ = cfg.cert_der.try_set(cert[..]);
    let _ = cfg.alpn.try_set("http/1.1");
    let slot, ok = tls::server_handshake(conn, cfg);
    guard ok else {
        net::tcp_close(conn);
        return;
    }
    var tr: net::Transport = net::Transport.Tls { fd: conn, record_seq_rx: 0, record_seq_tx: 0, cipher_slot: slot };
    defer tr.close();
    var rx: u8[1024] = [0; 1024];
    let n = tr.recv_slice(rx[..], 5000);
    guard n > 0 && core::starts_with(rx[..n], "GET /secret HTTP/1.1\r\n") else { return; }
    let resp = "HTTP/1.1 200 OK\r\nContent-Length: 15\r\nConnection: close\r\n\r\nPONG-TLS-IN-TLS";
    let _ = tr.send(resp);
}

thread_fn https_proxy_worker(cfg: RelayTarget) {
    let conn = net::tcp_accept(cfg.listen_fd, 5000);
    guard conn > 0 else { return; }
    let seed: u8[32] = [0x22; 32];
    var cert: u8[..2048] = [];
    guard tls::build_test_ed25519_cert_der(seed, "127.0.0.1", "localhost", "127.0.0.1", cert) else {
        net::tcp_close(conn);
        return;
    }
    var scfg = tls::ServerHandshakeConfig { priv_seed: seed, .. };
    let _ = scfg.cert_der.try_set(cert[..]);
    let _ = scfg.alpn.try_set("http/1.1");
    let slot, ok = tls::server_handshake(conn, scfg);
    guard ok else {
        net::tcp_close(conn);
        return;
    }
    var tr: net::Transport = net::Transport.Tls { fd: conn, record_seq_rx: 0, record_seq_tx: 0, cipher_slot: slot };
    defer tr.close();

    var req_buf: u8[1024] = [0; 1024];
    let n = tr.recv_slice(req_buf[..], 5000);
    guard n > 0 && check_connect_head(req_buf[..n], "blocked.max.invalid", "relay", "topsecret") else { return; }
    let up_fd = net::tcp_connect("127.0.0.1", cfg.origin_port, 5000);
    guard up_fd > 0 else { return; }
    defer net::tcp_close(up_fd);
    guard tr.send("HTTP/1.1 200 Connection Established\r\n\r\n") == 39 else { return; }
    pump_bidirectional_raw_and_transport(tr, up_fd);
}

fn test_proxy_config_and_fail_closed() {
    var sess = client::new_session();
    sess.set_allow_loopback_ssrf(true);
    assert(sess.set_proxy("socks5h://bot:s3cr3t@127.0.0.1:1080"));
    assert(sess.set_proxy("https://relay:pass@proxy.example:443"));
    assert(!sess.set_proxy("ftp://bad.example:21"));
    assert(!sess.set_proxy("not-a-url"));
    assert(sess.set_proxy(""));
    assert(sess.proxy_url.len == 0);

    // Fail-closed: malformed raw proxy_url must error, never silently fall back to direct!
    let _ = sess.proxy_url.try_set("ftp://invalid.proxy");
    let req = http::new_request("GET", "http://127.0.0.1:9/");
    let _, err = client::do(sess, req);
    assert(!http::ok(err) && err.code == 400);
    print("PROXY_CONFIG_FAIL_CLOSED_OK");
}

fn test_live_socks5h_remote_dns() {
    let orig_l = net::tcp_listen("127.0.0.1", 0, 4);
    let prox_l = net::tcp_listen("127.0.0.1", 0, 4);
    assert(orig_l > 0 && prox_l > 0);
    let orig_port = net::tcp_getsockname_port(orig_l);
    let prox_port = net::tcp_getsockname_port(prox_l);
    let t_orig = thread_spawn(plain_origin_worker, orig_l);
    let t_prox = thread_spawn(socks5h_proxy_worker, RelayTarget { listen_fd: prox_l, origin_port: orig_port });

    var sess = client::new_session();
    var purl: u8[..128] = [];
    format(purl, "socks5h://bot:s3cr3t@127.0.0.1:", prox_port);
    assert(sess.set_proxy(purl[..]));
    let req = http::new_request("GET", "http://blocked.telegram.invalid/socks5h");
    let resp, err = client::do(sess, req);
    assert(http::ok(err) && resp.status_code == 200 && resp.body[..] == "PONG-SOCKS5H");
    sess.close();
    let _ = thread_wait(t_prox);
    let _ = thread_wait(t_orig);
    net::tcp_close(prox_l);
    net::tcp_close(orig_l);
    print("LIVE_SOCKS5H_REMOTE_DNS_OK");
}

fn test_live_http_connect_remote_dns() {
    let orig_l = net::tcp_listen("127.0.0.1", 0, 4);
    let prox_l = net::tcp_listen("127.0.0.1", 0, 4);
    assert(orig_l > 0 && prox_l > 0);
    let orig_port = net::tcp_getsockname_port(orig_l);
    let prox_port = net::tcp_getsockname_port(prox_l);
    let t_orig = thread_spawn(plain_origin_worker, orig_l);
    let t_prox = thread_spawn(http_connect_proxy_worker, RelayTarget { listen_fd: prox_l, origin_port: orig_port });

    var sess = client::new_session();
    var purl: u8[..128] = [];
    format(purl, "http://vkbot:pass123@127.0.0.1:", prox_port);
    assert(sess.set_proxy(purl[..]));
    let req = http::new_request("GET", "http://blocked.vk.invalid/connect");
    let resp, err = client::do(sess, req);
    assert(http::ok(err) && resp.status_code == 200 && resp.body[..] == "PONG-HTTP-CONNECT");
    sess.close();
    let _ = thread_wait(t_prox);
    let _ = thread_wait(t_orig);
    net::tcp_close(prox_l);
    net::tcp_close(orig_l);
    print("LIVE_HTTP_CONNECT_REMOTE_DNS_OK");
}

fn test_live_https_proxy_tls_in_tls() {
    let orig_l = net::tcp_listen("127.0.0.1", 0, 4);
    let prox_l = net::tcp_listen("127.0.0.1", 0, 4);
    assert(orig_l > 0 && prox_l > 0);
    let orig_port = net::tcp_getsockname_port(orig_l);
    let prox_port = net::tcp_getsockname_port(prox_l);
    let t_orig = thread_spawn(tls_origin_worker, orig_l);
    let t_prox = thread_spawn(https_proxy_worker, RelayTarget { listen_fd: prox_l, origin_port: orig_port });

    var sess = client::new_session();
    sess.set_tls_use_system_roots(false);
    var p_cert: u8[..2048] = [];
    var o_cert: u8[..2048] = [];
    let p_seed: u8[32] = [0x22; 32];
    let o_seed: u8[32] = [0x44; 32];
    assert(tls::build_test_ed25519_cert_der(p_seed, "127.0.0.1", "localhost", "127.0.0.1", p_cert));
    assert(tls::build_test_ed25519_cert_der(o_seed, "blocked.max.invalid", "blocked.max.invalid", "", o_cert));
    assert(tls::add_trust_anchor_cert_der(sess.trust_store, p_cert[..]));
    assert(tls::add_trust_anchor_cert_der(sess.trust_store, o_cert[..]));

    var purl: u8[..128] = [];
    format(purl, "https://relay:topsecret@127.0.0.1:", prox_port);
    assert(sess.set_proxy(purl[..]));
    let req = http::new_request("GET", "https://blocked.max.invalid/secret");
    let resp, err = client::do(sess, req);
    assert(http::ok(err) && resp.status_code == 200 && resp.body[..] == "PONG-TLS-IN-TLS");
    sess.close();
    let _ = thread_wait(t_prox);
    let _ = thread_wait(t_orig);
    net::tcp_close(prox_l);
    net::tcp_close(orig_l);
    print("LIVE_HTTPS_PROXY_TLS_IN_TLS_OK");
}

fn main() {
    test_proxy_config_and_fail_closed();
    test_live_socks5h_remote_dns();
    test_live_http_connect_remote_dns();
    test_live_https_proxy_tls_in_tls();
}

// CHECK: PROXY_CONFIG_FAIL_CLOSED_OK
// CHECK-NEXT: LIVE_SOCKS5H_REMOTE_DNS_OK
// CHECK-NEXT: LIVE_HTTP_CONNECT_REMOTE_DNS_OK
// CHECK-NEXT: LIVE_HTTPS_PROXY_TLS_IN_TLS_OK
