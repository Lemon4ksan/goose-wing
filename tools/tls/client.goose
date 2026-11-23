// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Native Goose TLS 1.3 & HTTPS (HTTP/2 over ALPN) E2E Verification Client.
// Supports default E2E mode (env PORT), pluggable `TlsEndpoint` probe mode (`probe`),
// and live post-handshake bad-record-MAC negative probe (`badmac`).
import std;
import wing from "../..";

fn make_https_base_url(port: u16, out: u8[..128]&) {
    out.clear();
    let _ = out.try_append("https://127.0.0.1:");
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

// Parses a backend name token into `tls::TlsBackendKind`.
//
// Example:
//   raw = "openssl"
//   returns: tls::TlsBackendKind.SystemOpenSsl, true
fn parse_backend_kind(raw: const u8[:]) -> tls::TlsBackendKind, bool {
    if raw == "pure" { return tls::TlsBackendKind.PureGoose, true; }
    if raw == "openssl" { return tls::TlsBackendKind.SystemOpenSsl, true; }
    if raw == "schannel" { return tls::TlsBackendKind.SystemSchannel, true; }
    if raw == "auto" { return tls::TlsBackendKind.Auto, true; }
    return tls::TlsBackendKind.PureGoose, false;
}

// Parses a minimum TLS version token (`tls13` or `tls12`) into `tls::TlsMinVersion`.
//
// Example:
//   raw = "tls12"
//   returns: tls::TlsMinVersion.Tls12, true
fn parse_min_version(raw: const u8[:]) -> tls::TlsMinVersion, bool {
    if raw == "tls13" { return tls::TlsMinVersion.Tls13, true; }
    if raw == "tls12" { return tls::TlsMinVersion.Tls12, true; }
    return tls::TlsMinVersion.Tls13, false;
}

fn status_name(st: tls::TlsBackendStatus) -> const u8[:] {
    return match st {
        Ok => "Ok",
        WantRead => "WantRead",
        WantWrite => "WantWrite",
        NeedSniCredentials => "NeedSniCredentials",
        Closed => "Closed",
        Unavailable => "Unavailable",
        HandshakeError => "HandshakeError",
        VerifyError => "VerifyError",
        Error => "Error",
    };
}

// Encodes comma-separated ALPN protocol names into RFC 7301 wire format.
//
// Example:
//   csv = "h2,http/1.1"
//   returns: true, out = [2, 'h', '2', 8, 'h', 't', 't', 'p', '/', '1', '.', '1']
fn encode_alpn_csv(csv: const u8[:], out: u8[..64]&) -> bool {
    out.clear();
    guard csv.len > 0 && csv != "-" else { return true; }
    var tok = core::make_byte_tokenizer(csv, ',');
    while true {
        let item, more = core::token_next(tok);
        guard more else { break; }
        let p = item.trim_lws();
        guard p.len > 0 && p.len <= 255 else {
            out.clear();
            return false;
        }
        guard out.try_push(p.len as u8) && out.try_append(p) else {
            out.clear();
            return false;
        }
    }
    return true;
}

fn flush_ep_to_tcp(fd: i64, ep: tls::TlsEndpoint&) -> bool {
    var wire: u8[16384] = [0; 16384];
    for _ in 16 {
        let n, st = tls::tls_endpoint_drain_wire(ep, wire[..]);
        guard st == tls::TlsBackendStatus.Ok else { return false; }
        if n <= 0 { return true; }
        guard net::tcp_send(fd, wire[..n]) == (n as i32) else { return false; }
    }
    return true;
}

fn recv_tcp_to_ep(fd: i64, ep: tls::TlsEndpoint&, rx: u8[:]) -> tls::TlsBackendStatus {
    let recvd = net::tcp_recv_slice(fd, rx, 3000);
    if recvd == -2 { return tls::TlsBackendStatus.WantRead; }
    guard recvd > 0 else { return tls::TlsBackendStatus.Closed; }
    let fed, st = tls::tls_endpoint_feed_wire(ep, rx[..recvd]);
    guard st == tls::TlsBackendStatus.Ok && fed == recvd else {
        return tls::TlsBackendStatus.Error;
    }
    return tls::TlsBackendStatus.Ok;
}

fn drive_tls_handshake(fd: i64, ep: tls::TlsEndpoint&) -> tls::TlsBackendStatus {
    var rx: u8[16384] = [0; 16384];
    for _ in 64 {
        let st = tls::tls_endpoint_step_handshake(ep);
        let _ = flush_ep_to_tcp(fd, ep);
        if st == tls::TlsBackendStatus.Ok || tls::tls_endpoint_is_established(ep) {
            return tls::TlsBackendStatus.Ok;
        }
        if st != tls::TlsBackendStatus.WantRead && st != tls::TlsBackendStatus.WantWrite {
            return st;
        }
        let rst = recv_tcp_to_ep(fd, ep, rx[..]);
        if rst == tls::TlsBackendStatus.Closed {
            let fst = tls::tls_endpoint_step_handshake(ep);
            return if fst == tls::TlsBackendStatus.WantRead {
                tls::TlsBackendStatus.HandshakeError
            } else {
                fst
            };
        }
        guard rst == tls::TlsBackendStatus.Ok || rst == tls::TlsBackendStatus.WantRead else {
            return rst;
        }
    }
    return tls::TlsBackendStatus.HandshakeError;
}

fn build_probe_config(
    kind:    tls::TlsBackendKind,
    min_ver: tls::TlsMinVersion,
    sni:     const u8[:],
    ca_path: const u8[:],
    alpn:    const u8[:],
    cfg:     tls::TlsBackendConfig&,
) -> bool {
    cfg = tls::TlsBackendConfig {
        kind:                 kind,
        min_version:          min_ver,
        is_server:            false,
        insecure_skip_verify: false,
        ..
    };
    guard cfg.server_name.try_set(sni) && encode_alpn_csv(alpn, cfg.alpn_wire) else {
        return false;
    }
    guard ca_path.len > 0 && ca_path != "-" else { return true; }
    if kind == tls::TlsBackendKind.PureGoose || kind == tls::TlsBackendKind.Auto {
        let added, ok_pem = tls::load_trust_anchors_pem_file(cfg.trust_store, ca_path);
        guard ok_pem && added > 0 else { return false; }
    }
    if kind != tls::TlsBackendKind.PureGoose {
        guard cfg.ca_file.try_set(ca_path) else { return false; }
    }
    return true;
}

fn send_probe_http_get(fd: i64, ep: tls::TlsEndpoint&, sni: const u8[:]) -> bool {
    var get_req: u8[..256] = [];
    guard get_req.try_append("GET / HTTP/1.1\r\nHost: ") &&
          get_req.try_append(sni) &&
          get_req.try_append("\r\nConnection: close\r\n\r\n") else {
        return false;
    }
    let nw, stw = tls::tls_endpoint_write_app(ep, get_req[..]);
    return stw == tls::TlsBackendStatus.Ok && nw > 0 && flush_ep_to_tcp(fd, ep);
}

fn exchange_probe_http(fd: i64, ep: tls::TlsEndpoint&, sni: const u8[:]) -> i64 {
    guard send_probe_http_get(fd, ep, sni) else { return 0; }
    var rx_wire: u8[8192] = [0; 8192];
    var app_buf: u8[2048] = [0; 2048];
    var tcp_eof = false;
    for _ in 32 {
        let nr, str = tls::tls_endpoint_read_app(ep, app_buf[..]);
        if nr > 0 { return nr; }
        guard str == tls::TlsBackendStatus.WantRead || str == tls::TlsBackendStatus.Ok else {
            break;
        }
        if tcp_eof { continue; }
        let rst = recv_tcp_to_ep(fd, ep, rx_wire[..]);
        if rst == tls::TlsBackendStatus.Closed {
            tcp_eof = true;
            continue;
        }
        guard rst == tls::TlsBackendStatus.Ok else { break; }
    }
    return 0;
}

fn run_probe_cmd(a: u8[:][>..]&) {
    guard a.len >= 9 else {
        print("PROBE\tBadArgs\t-\t0\n");
        return;
    }
    let kind, ok_k = parse_backend_kind(a[2]);
    let min_ver, ok_v = parse_min_version(a[3]);
    let port_u, ok_p = a[5].parse_u64_dec();
    guard ok_k && ok_v && ok_p && port_u > 0 && port_u <= 65535 else {
        print("PROBE\tBadArgs\t-\t0\n");
        return;
    }

    var cfg = tls::TlsBackendConfig { .. };
    guard build_probe_config(kind, min_ver, a[6], a[7], a[8], cfg) else {
        print("PROBE\tConfigError\t-\t0\n");
        return;
    }

    var ep, open_st = tls::tls_endpoint_open(cfg);
    if open_st != tls::TlsBackendStatus.Ok {
        print("PROBE\t", status_name(open_st), "\t-\t0\n");
        return;
    }
    defer tls::tls_endpoint_close(ep);

    let fd = net::tcp_connect(a[4], port_u as u16, 4000);
    guard fd > 0 else {
        print("PROBE\tConnectError\t-\t0\n");
        return;
    }
    defer net::tcp_close(fd);

    let hs_st = drive_tls_handshake(fd, ep);
    if hs_st != tls::TlsBackendStatus.Ok {
        print("PROBE\t", status_name(hs_st), "\t-\t0\n");
        return;
    }

    let sel = tls::tls_endpoint_selected_alpn(ep);
    let alpn_s = if sel.len > 0 { sel[..] } else { "-" };
    let app_got = exchange_probe_http(fd, ep, a[6]);
    print("PROBE\tOk\t", alpn_s, "\t", app_got, "\n");
}

// Completes a live TLS 1.3 handshake with `tools/tls/server.goose`, flips one byte in the
// AEAD authentication tag of an encrypted application record, and verifies fail-closed teardown.
fn run_bad_record_mac_probe(host: const u8[:], port: u16) -> bool {
    let seed: u8[32] = [0x42; 32];
    var cert_der: u8[..2048] = [];
    guard tls::build_test_ed25519_cert_der(
        seed, "goose-wing.local", "goose-wing.local", "127.0.0.1", cert_der,
    ) else { return false; }

    var cfg = tls::TlsBackendConfig {
        kind:                 tls::TlsBackendKind.PureGoose,
        min_version:          tls::TlsMinVersion.Tls13,
        is_server:            false,
        insecure_skip_verify: false,
        ..
    };
    guard cfg.server_name.try_set("goose-wing.local") &&
          encode_alpn_csv("http/1.1", cfg.alpn_wire) &&
          tls::add_trust_anchor_cert_der(cfg.trust_store, cert_der[..]) else {
        return false;
    }

    var ep, open_st = tls::tls_endpoint_open(cfg);
    guard open_st == tls::TlsBackendStatus.Ok else { return false; }
    defer tls::tls_endpoint_close(ep);

    let fd = net::tcp_connect(host, port, 3000);
    guard fd > 0 else { return false; }
    defer net::tcp_close(fd);

    guard drive_tls_handshake(fd, ep) == tls::TlsBackendStatus.Ok else { return false; }

    let req_bytes = "GET /secure-hello HTTP/1.1\r\nHost: goose-wing.local\r\n\r\n";
    let nw, stw = tls::tls_endpoint_write_app(ep, req_bytes);
    guard stw == tls::TlsBackendStatus.Ok && nw == req_bytes.len else { return false; }

    var wire: u8[2048] = [0; 2048];
    let wn, wd = tls::tls_endpoint_drain_wire(ep, wire[..]);
    guard wd == tls::TlsBackendStatus.Ok && wn > 22 else { return false; }

    // Corrupt the final byte of the TLS 1.3 AEAD authentication tag.
    let last_idx = core::sub_sat_i64(wn, 1);
    wire[last_idx] = wire[last_idx] ^ 0xFF;
    guard net::tcp_send(fd, wire[..wn]) == (wn as i32) else { return false; }

    // Server must either send a fatal alert or close the TCP socket without returning app data.
    var resp: u8[512] = [0; 512];
    let rn = net::tcp_recv_slice(fd, resp[..], 1500);
    if rn <= 0 { return true; }
    return resp[0] == 0x15;
}

fn main() {
    let a = args();
    if a.len >= 2 && a[1] == "probe" {
        run_probe_cmd(a);
        return;
    }
    if a.len >= 4 && a[1] == "badmac" {
        let port_u, ok_p = a[3].parse_u64_dec();
        let ok = ok_p && port_u > 0 && port_u <= 65535 && run_bad_record_mac_probe(a[2], port_u as u16);
        print(if ok { "TLS_BAD_RECORD_MAC: PASS\n" } else { "TLS_BAD_RECORD_MAC: FAIL\n" });
        return;
    }

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
