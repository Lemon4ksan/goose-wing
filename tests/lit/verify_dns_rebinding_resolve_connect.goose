// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// RUN: goose build -O0 -o %t.exe %s
// RUN: %t.exe | %FileCheck %s

// Verifies DNS-rebinding-safe resolve-then-connect primitives (`net::resolve_host_ips`,
// `net::tcp_connect_ip`, `net::tcp_connect_resolved`), explicit TLS SNI over an IP-pinned
// socket, and `client::Session` post-resolution SSRF enforcement.

import std;
import os;
import wing from "../..";

let EGRESS_SRV_SEED: u8[32] = [0x61; 32];

thread_fn tls_sni_echo_worker(lst: i64) {
    defer net::tcp_close(lst);
    var cert_der: u8[..2048] = [];
    guard tls::build_test_ed25519_cert_der(
        EGRESS_SRV_SEED, "egress.wing.test", "egress.wing.test", "", cert_der,
    ) else { return; }

    var srv_cfg = tls::ServerHandshakeConfig {
        priv_seed:            EGRESS_SRV_SEED,
        handshake_timeout_ms: 2500,
        ..
    };
    let _ = srv_cfg.cert_der.try_set(cert_der[..]);
    let _ = srv_cfg.alpn.try_set("http/1.1");

    for _ in 3 {
        let cfd = net::tcp_accept(lst, 3000);
        guard cfd > 0 else { return; }
        let slot, ok_hs = tls::server_handshake(cfd, srv_cfg);
        if !ok_hs {
            net::tcp_close(cfd);
            continue;
        }
        var rx: u8[512] = [0; 512];
        let n = tls::transport_recv_slice(cfd, slot, rx[..], 1500);
        if n > 0 {
            let reply = "HTTP/1.1 200 OK\r\nContent-Length: 9\r\nConnection: close\r\n\r\nSNI_BOUND";
            let _ = tls::transport_send(cfd, slot, reply);
        }
        sleep_ms(20);
        tls::transport_close(cfd, slot);
    }
}

fn check_resolve_and_connect_ip(port: u16) -> bool {
    var ips: u8[..64][..16] = [];
    guard net::resolve_host_ips("127.0.0.1", ips, net::IpFamily.Ipv4Only) &&
        ips.len == 1 && ips[0][..] == "127.0.0.1" else { return false; }

    // Mismatched IP family fails closed and clears `ips` transactionally.
    guard !net::resolve_host_ips("127.0.0.1", ips, net::IpFamily.Ipv6Only) && ips.len == 0 else {
        return false;
    }

    guard net::resolve_host_ips("[::1]", ips, net::IpFamily.Ipv6Only) &&
        ips.len == 1 && ips[0][..] == "::1" else { return false; }

    guard net::resolve_host_ips("localhost", ips, net::IpFamily.Auto) && ips.len >= 1 else {
        return false;
    }
    for &ip in ips {
        guard security::is_private_or_reserved_ip(ip[..]) else { return false; }
    }

    // `tcp_connect_ip` MUST reject hostnames, "localhost", empty, and non-canonical IPv4 without DNS.
    guard net::tcp_connect_ip("localhost", port, 500) < 0 else { return false; }
    guard net::tcp_connect_ip("example.com", port, 500) < 0 else { return false; }
    guard net::tcp_connect_ip("", port, 500) < 0 else { return false; }
    guard net::tcp_connect_ip("127.1", port, 500) < 0 else { return false; }
    guard net::tcp_connect_ip("0177.0.0.1", port, 500) < 0 else { return false; }
    guard net::tcp_connect_ip("127.0.0.1", port, 500, net::IpFamily.Ipv6Only) < 0 else { return false; }
    return true;
}

fn check_resolved_filter_and_explicit_sni(port: u16) -> bool {
    var peer_ip: u8[..64] = [];

    // 1. Egress-relay SSRF defense: "localhost" resolves to 127.0.0.1/::1 and is rejected BEFORE connect().
    let blocked_fd = net::tcp_connect_resolved("localhost", port, peer_ip, 1000) { ip, allowed =>
        allowed = !security::is_private_or_reserved_ip(ip);
    };
    guard blocked_fd < 0 && peer_ip.len == 0 else { return false; }

    // 2. Build trust anchor matching the server's Ed25519 cert for "egress.wing.test".
    var cert_der: u8[..2048] = [];
    guard tls::build_test_ed25519_cert_der(
        EGRESS_SRV_SEED, "egress.wing.test", "egress.wing.test", "", cert_der,
    ) else { return false; }
    var store = tls::TrustAnchorStore { .. };
    guard tls::add_trust_anchor_cert_der(store, cert_der[..]) else { return false; }

    // 3. Connect by resolved numeric IP ("127.0.0.1") while sending explicit TLS SNI "egress.wing.test".
    let fd_ok = net::tcp_connect_resolved("localhost", port, peer_ip, 1500, net::IpFamily.Ipv4Only) { ip, allowed =>
        allowed = ip == "127.0.0.1";
    };
    guard fd_ok > 0 && peer_ip[..] == "127.0.0.1" else { return false; }

    var tls_ok = tls::ClientHandshakeConfig {
        trust_store:          store,
        use_system_roots:     false,
        handshake_timeout_ms: 2000,
        ..
    };
    let _ = tls_ok.server_name.try_set("egress.wing.test");
    let _ = tls_ok.alpn.try_set("http/1.1");
    let slot_ok, hs_ok = tls::client_handshake(fd_ok, tls_ok);
    guard hs_ok else { net::tcp_close(fd_ok); return false; }

    let req = "GET / HTTP/1.1\r\nHost: egress.wing.test\r\nConnection: close\r\n\r\n";
    let sent = tls::transport_send(fd_ok, slot_ok, req);
    var rx: u8[256] = [0; 256];
    let n = tls::transport_recv_slice(fd_ok, slot_ok, rx[..], 1500);
    tls::transport_close(fd_ok, slot_ok);
    guard sent > 0 && n > 0 && core::contains(rx[..n], "SNI_BOUND") else { return false; }

    // 4. Explicit SNI/SAN mismatch on the same IP-pinned socket MUST fail verification.
    let fd_bad = net::tcp_connect_ip("127.0.0.1", port, 1500, net::IpFamily.Ipv4Only);
    guard fd_bad > 0 else { return false; }
    var tls_bad = tls::ClientHandshakeConfig {
        trust_store:          store,
        use_system_roots:     false,
        handshake_timeout_ms: 2000,
        ..
    };
    let _ = tls_bad.server_name.try_set("wrong.wing.test");
    let _ = tls_bad.alpn.try_set("http/1.1");
    let slot_bad, hs_bad = tls::client_handshake(fd_bad, tls_bad);
    if hs_bad {
        tls::transport_close(fd_bad, slot_bad);
        return false;
    }
    net::tcp_close(fd_bad);
    return true;
}

fn check_client_session_ssrf_and_ip_pin(port: u16) -> bool {
    var url_local: u8[..128] = [];
    format(url_local, "https://localhost:", port, "/");
    var url_host: u8[..128] = [];
    format(url_host, "https://egress.wing.test:", port, "/");

    // 1. Enabled ssrf_guard blocks localhost and DNS-override rebinding to 127.0.0.1.
    var strict_sess = client::new_client(client::Config {
        timeout_ms:          2000,
        allow_loopback_ssrf: false,
        ..
    });
    strict_sess.ssrf_guard = security::new_ssrf_guard_policy();
    let _, err_loc = client::get(strict_sess, url_local[..]);
    guard !http::ok(err_loc) && err_loc.code == rfc::STATUS_FORBIDDEN else { return false; }

    assert(client::add_resolve_override(strict_sess, "egress.wing.test", port, "127.0.0.1"));
    let _, err_rebind = client::get(strict_sess, url_host[..]);
    guard !http::ok(err_rebind) && err_rebind.code == rfc::STATUS_FORBIDDEN else { return false; }
    client::close(strict_sess);

    // 2. With allow_loopback_ssrf + trust anchor, Session dials 127.0.0.1 by IP and verifies SNI "egress.wing.test".
    var cert_der: u8[..2048] = [];
    guard tls::build_test_ed25519_cert_der(
        EGRESS_SRV_SEED, "egress.wing.test", "egress.wing.test", "", cert_der,
    ) else { return false; }

    var allow_sess = client::new_client(client::Config {
        timeout_ms:           3000,
        allow_loopback_ssrf:  true,
        tls_use_system_roots: false,
        tls_alpn:             "http/1.1",
        ip_family:            net::IpFamily.Ipv4Only,
        disable_keepalive:    true,
        ..
    });
    guard tls::add_trust_anchor_cert_der(allow_sess.trust_store, cert_der[..]) else { return false; }
    assert(client::add_resolve_override(allow_sess, "egress.wing.test", port, "127.0.0.1"));

    let resp, err_ok = client::get(allow_sess, url_host[..]);
    client::close(allow_sess);
    return http::ok(err_ok) && resp.status_code == 200 && resp.body[..] == "SNI_BOUND";
}

fn main() {
    let lst = net::tcp_listen("127.0.0.1", 0, 8);
    assert(lst > 0);
    let port = net::tcp_getsockname_port(lst);
    let tid = thread_spawn(tls_sni_echo_worker, lst);

    let ok1 = check_resolve_and_connect_ip(port);
    let ok2 = check_resolved_filter_and_explicit_sni(port);
    let ok3 = check_client_session_ssrf_and_ip_pin(port);
    assert(thread_wait(tid));

    // CHECK: RESOLVE_AND_CONNECT_IP: true
    // CHECK-NEXT: RESOLVED_FILTER_AND_SNI: true
    // CHECK-NEXT: CLIENT_SESSION_SSRF_PIN: true
    print("RESOLVE_AND_CONNECT_IP: ", ok1);
    print("RESOLVED_FILTER_AND_SNI: ", ok2);
    print("CLIENT_SESSION_SSRF_PIN: ", ok3);
    assert(ok1 && ok2 && ok3);
}
