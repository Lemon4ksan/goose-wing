// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Native Goose TLS 1.3 & HTTPS (HTTP/2 over ALPN) E2E Verification Client.
// Exercises client::Client full RFC 8446 TLS 1.3 handshake, X.509 Ed25519
// trust-store verification, IP SAN matching, untrusted certificate rejection,
// ALPN h2 negotiation, and pooled TLS+H2 stream multiplexing against tools/tls/server.goose.
import std;
import core from "../..";
import wing from "../..";

fn make_https_base_url(port: u16, out: u8[..128]&) {
    out.clear();
    out.append("https://127.0.0.1:");
    core::format_u64_dec(port, out);
}

// 1. Default strict client::Client (empty trust store) MUST reject untrusted self-signed cert
fn run_untrusted_cert_reject(port: u16) -> bool {
    var base: u8[..128] = [];
    make_https_base_url(port, base);
    var s = client::new_client(client::Config {
        base_url:             base[..],
        timeout_ms:           3000,
        insecure_skip_verify: false,
        ..
    });
    s.ssrf_guard.enabled = false;

    let _, err = client::get(s, "/secure-hello");
    return !http::ok(err);
}

// 2 & 3. Verified TLS 1.3 + ALPN h2 GET and pooled stream reuse POST
fn run_verified_tls13_h2_and_reuse(port: u16) -> bool, bool {
    var base: u8[..128] = [];
    make_https_base_url(port, base);
    var s = client::new_client(client::Config {
        base_url:             base[..],
        timeout_ms:           3000,
        insecure_skip_verify: false,
        ..
    });
    s.ssrf_guard.enabled = false;

    let seed: u8[32] = [0x42; 32];
    var cert_der: u8[..2048] = [];
    guard tls::build_test_ed25519_cert_der(
        seed, "goose-wing.local", "goose-wing.local", "127.0.0.1", cert_der,
    ) else {
        return false, false;
    }
    guard tls::add_trust_anchor_cert_der(s.trust_store, cert_der[..]) else {
        return false, false;
    }

    let r1, err1 = client::get(s, "/secure-hello");
    let ok1 = http::ok(err1) &&
        r1.status_code == 200 &&
        r1.protocol[..] == "HTTP/2" &&
        r1.body[..] == "Hello over TLS 1.3!";
    guard ok1 else {
        client::close(s);
        return false, false;
    }

    let r2, err2 = client::post(s, "/secure-echo") { req =>
        http::text(req, "EncryptedPostPayload_2026");
    };
    let reused_conn = s.pool.conns.len == 1 && s.pool.conns[0].next_h2_stream_id == 5;
    let ok2 = http::ok(err2) &&
        r2.status_code == 200 &&
        r2.protocol[..] == "HTTP/2" &&
        r2.body[..] == "TLS_ECHO_OK" &&
        reused_conn;
    client::close(s);
    return true, ok2;
}

fn main() {
    let port = net::get_env_port(0);
    if port == 0 {
        print("TLS_CLI_ERR: missing PORT\n");
        return;
    }

    let ok_reject = run_untrusted_cert_reject(port);
    print(if ok_reject { "TLS_CLI_UNTRUSTED_REJECT: PASS\n" } else { "TLS_CLI_UNTRUSTED_REJECT: FAIL\n" });

    let ok_h2, ok_reuse = run_verified_tls13_h2_and_reuse(port);
    print(if ok_h2 { "TLS_CLI_VERIFIED_H2: PASS\n" } else { "TLS_CLI_VERIFIED_H2: FAIL\n" });
    print(if ok_reuse { "TLS_CLI_H2_STREAM_REUSE: PASS\n" } else { "TLS_CLI_H2_STREAM_REUSE: FAIL\n" });
}
