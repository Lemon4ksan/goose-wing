// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Live Loopback Verification: TLS 1.3 + HTTP/2 (ALPN h2) + X.509 Trust Store
//
// RUN: goose build -O2 -o %t.exe %s
// RUN: %t.exe | %FileCheck %s

import std;
import core from "../..";
import wing from "../..";

fn format_loopback_url(port: u16, path: const u8[:], out: u8[..128]&) {
    out.clear();
    let _ = out.try_append("https://localhost:");
    port.format_u64_dec(out);
    let _ = out.try_append(path);
}

thread_fn tls_h2_server_worker(listener_fd: i64) {
    var srv = server::new_http_server();
    srv.pipeline.enable_csrf_guard = false;
    let r1 = server::add_static_route(
        srv.pipeline.router,
        "GET",
        "/hello",
        "text/plain",
        "hello-h2-loopback",
    );
    let r2 = server::add_static_route(
        srv.pipeline.router,
        "POST",
        "/submit",
        "application/json",
        "{\"ok\":true}",
    );
    assert(r1 && r2);

    let seed: u8[32] = [0x42; 32];
    var cert_der: u8[..2048] = [];
    let cert_ok = tls::build_test_ed25519_cert_der(
        seed,
        "localhost",
        "localhost",
        "127.0.0.1",
        cert_der,
    );
    assert(cert_ok);

    var tls_cfg = tls::ServerHandshakeConfig { .. };
    assert(tls_cfg.cert_der.try_set(cert_der[..]));
    tls_cfg.priv_seed = seed;
    assert(tls_cfg.alpn.try_set("h2,http/1.1"));

    let _ = server::serve_tls(srv, listener_fd, tls_cfg, 2);
}

fn run_trusted_h2_session(port: u16, cert_der: const u8[:]) {
    var cfg = client::Config { timeout_ms: 5000, .. };
    var sess = client::new_session(cfg);
    defer sess.close();
    sess.ssrf_guard.enabled = false;
    sess.insecure_skip_verify = false;
    assert(tls::add_trust_anchor_cert_der(sess.trust_store, cert_der));

    var url_get: u8[..128] = [];
    format_loopback_url(port, "/hello", url_get);
    var req_get = http::new_get(url_get[..]);
    let res_get, err_get = client::execute_request(sess, req_get);
    assert(http::ok(err_get));
    print("get_status=", res_get.status_code, " proto=", res_get.protocol[..],
        " ct=", res_get.header("content-type"), " body=", res_get.body[..]);

    var url_post: u8[..128] = [];
    format_loopback_url(port, "/submit", url_post);
    var req_post = http::new_post(url_post[..]);
    req_post.text("ping-body");
    let res_post, err_post = client::execute_request(sess, req_post);
    assert(http::ok(err_post));
    print("post_status=", res_post.status_code, " proto=", res_post.protocol[..],
        " ct=", res_post.header("content-type"), " body=", res_post.body[..]);
}

fn run_untrusted_client_check(port: u16) {
    var cfg = client::Config { timeout_ms: 5000, .. };
    var sess = client::new_session(cfg);
    defer sess.close();
    sess.ssrf_guard.enabled = false;
    sess.insecure_skip_verify = false;

    var url: u8[..128] = [];
    format_loopback_url(port, "/hello", url);
    var req = http::new_get(url[..]);
    let _, err = client::execute_request(sess, req);
    let rejected = !http::ok(err) && err.kind == http::ErrorKind.Tls;
    print("untrusted_rejected=", rejected);
}

fn main() {
    let listener = net::tcp_listen("127.0.0.1", 0, 16);
    assert(listener >= 0);
    let port = net::tcp_getsockname_port(listener);
    assert(port > 0);

    let seed: u8[32] = [0x42; 32];
    var cert_der: u8[..2048] = [];
    assert(tls::build_test_ed25519_cert_der(seed, "localhost", "localhost", "127.0.0.1", cert_der));

    let tid = thread_spawn(tls_h2_server_worker, listener);
    run_trusted_h2_session(port, cert_der[..]);
    run_untrusted_client_check(port);
    assert(thread_wait(tid));
    net::tcp_close(listener);
}

// CHECK: get_status=200 proto=HTTP/2 ct=text/plain body=hello-h2-loopback
// CHECK-NEXT: post_status=200 proto=HTTP/2 ct=application/json body={"ok":true}
// CHECK-NEXT: untrusted_rejected=true
