// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Native TLS Interop Canary Probe for goose-wing (`PureGoose`, `SystemOpenSsl`, `SystemSchannel`).
// Drives pluggable `tls::TlsEndpoint` over live TCP sockets to verify TLS 1.3 strictness,
// opt-in TLS 1.2 fallback, ALPN negotiation, and X.509 certificate/hostname validation.
import std;
import wing from "../..";

// Parses a backend name token into `tls::TlsBackendKind`.
//
// Example:
//   raw = "openssl"
//   returns: tls::TlsBackendKind.SystemOpenSsl, true
fn parse_backend_kind(raw: const u8[:]) -> tls::TlsBackendKind, bool {
    if raw == "pure" { return tls::TlsBackendKind.PureGoose, true; }
    if raw == "openssl" { return tls::TlsBackendKind.SystemOpenSsl, true; }
    if raw == "schannel" { return tls::TlsBackendKind.SystemSchannel, true; }
    if raw == "secure_transport" { return tls::TlsBackendKind.SystemSecureTransport, true; }
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

fn backend_kind_str(kind: tls::TlsBackendKind) -> const u8[:] {
    return match kind {
        PureGoose => "pure",
        SystemOpenSsl => "openssl",
        SystemSchannel => "schannel",
        SystemSecureTransport => "secure_transport",
        Auto => "auto",
    };
}

fn status_str(st: tls::TlsBackendStatus) -> const u8[:] {
    return match st {
        Ok => "Ok",
        WantRead => "WantRead",
        WantWrite => "WantWrite",
        Closed => "Closed",
        Unavailable => "Unavailable",
        HandshakeError => "HandshakeError",
        VerifyError => "VerifyError",
        Error => "Error",
    };
}

// Encodes comma-separated ALPN protocol names into RFC 7301 length-prefixed wire bytes.
// Clears `out` and returns false on empty protocol, length > 255, or buffer overflow.
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

fn flush_tls_wire_to_tcp(fd: i64, ep: tls::TlsEndpoint&) -> bool {
    var wire: u8[16384] = [0; 16384];
    for _ in 16 {
        let n, st = tls::tls_endpoint_drain_wire(ep, wire[..]);
        guard st == tls::TlsBackendStatus.Ok else { return false; }
        if n <= 0 { return true; }
        let sent = net::tcp_send(fd, wire[..n]);
        guard sent == (n as i32) else { return false; }
    }
    return true;
}

fn recv_tcp_into_tls(fd: i64, ep: tls::TlsEndpoint&, rx_buf: u8[:]) -> tls::TlsBackendStatus {
    let recvd = net::tcp_recv_slice(fd, rx_buf, 3000);
    if recvd == -2 { return tls::TlsBackendStatus.WantRead; }
    guard recvd > 0 else { return tls::TlsBackendStatus.Closed; }
    let fed, st = tls::tls_endpoint_feed_wire(ep, rx_buf[..recvd]);
    guard st == tls::TlsBackendStatus.Ok && fed == recvd else {
        return tls::TlsBackendStatus.Error;
    }
    return tls::TlsBackendStatus.Ok;
}

fn run_tcp_tls_handshake(fd: i64, ep: tls::TlsEndpoint&) -> tls::TlsBackendStatus {
    var rx_buf: u8[16384] = [0; 16384];
    for _ in 64 {
        let st = tls::tls_endpoint_step_handshake(ep);
        let _ = flush_tls_wire_to_tcp(fd, ep);
        if st == tls::TlsBackendStatus.Ok || tls::tls_endpoint_is_established(ep) {
            return tls::TlsBackendStatus.Ok;
        }
        if st != tls::TlsBackendStatus.WantRead && st != tls::TlsBackendStatus.WantWrite {
            return st;
        }
        let rst = recv_tcp_into_tls(fd, ep, rx_buf[..]);
        if rst == tls::TlsBackendStatus.Closed {
            let final_st = tls::tls_endpoint_step_handshake(ep);
            return if final_st == tls::TlsBackendStatus.WantRead {
                tls::TlsBackendStatus.HandshakeError
            } else {
                final_st
            };
        }
        guard rst == tls::TlsBackendStatus.Ok || rst == tls::TlsBackendStatus.WantRead else {
            return rst;
        }
    }
    return tls::TlsBackendStatus.HandshakeError;
}

fn send_canary_http_get(fd: i64, ep: tls::TlsEndpoint&, sni: const u8[:]) -> bool {
    var req_buf: u8[..512] = [];
    guard req_buf.try_append("GET / HTTP/1.1\r\nHost: ") &&
          req_buf.try_append(sni) &&
          req_buf.try_append("\r\nConnection: close\r\n\r\n") else {
        return false;
    }
    let nw, stw = tls::tls_endpoint_write_app(ep, req_buf[..]);
    return stw == tls::TlsBackendStatus.Ok && nw > 0 && flush_tls_wire_to_tcp(fd, ep);
}

fn exchange_canary_app_data(fd: i64, ep: tls::TlsEndpoint&, sni: const u8[:]) -> i64 {
    guard send_canary_http_get(fd, ep, sni) else { return 0; }
    var rx_wire: u8[8192] = [0; 8192];
    var app_buf: u8[4096] = [0; 4096];
    var tcp_eof = false;
    for _ in 32 {
        let nr, str = tls::tls_endpoint_read_app(ep, app_buf[..]);
        if nr > 0 { return nr; }
        guard str == tls::TlsBackendStatus.WantRead || str == tls::TlsBackendStatus.Ok else {
            return 0;
        }
        if tcp_eof { continue; }
        let rst = recv_tcp_into_tls(fd, ep, rx_wire[..]);
        if rst == tls::TlsBackendStatus.Closed {
            tcp_eof = true;
            continue;
        }
        guard rst == tls::TlsBackendStatus.Ok else { break; }
    }
    return 0;
}

fn build_canary_config(
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
    guard cfg.server_name.try_set(sni) else { return false; }
    guard encode_alpn_csv(alpn, cfg.alpn_wire) else { return false; }
    guard ca_path.len > 0 && ca_path != "-" else { return true; }

    let needs_pure = kind == tls::TlsBackendKind.PureGoose || kind == tls::TlsBackendKind.Auto;
    if needs_pure {
        let added, ok_pem = tls::load_trust_anchors_pem_file(cfg.trust_store, ca_path);
        guard ok_pem && added > 0 else { return false; }
    }
    if kind != tls::TlsBackendKind.PureGoose {
        guard cfg.ca_file.try_set(ca_path) else { return false; }
    }
    return true;
}

fn run_probe(a: u8[:][>..]&) {
    guard a.len >= 9 else {
        print("CANARY\tBadArgs\t-\t-\t0\n");
        exit(2);
    }
    let kind, ok_k = parse_backend_kind(a[2]);
    let min_ver, ok_v = parse_min_version(a[3]);
    let host = a[4];
    let port_u, ok_p = a[5].parse_u64_dec();
    let sni = a[6];
    let ca_path = a[7];
    let alpn = a[8];
    guard ok_k && ok_v && ok_p && port_u > 0 && port_u <= 65535 else {
        print("CANARY\tBadArgs\t-\t-\t0\n");
        exit(2);
    }

    var cfg = tls::TlsBackendConfig { .. };
    guard build_canary_config(kind, min_ver, sni, ca_path, alpn, cfg) else {
        print("CANARY\tConfigError\t-\t-\t0\n");
        return;
    }

    var ep, open_st = tls::tls_endpoint_open(cfg);
    if open_st != tls::TlsBackendStatus.Ok {
        print("CANARY\t", status_str(open_st), "\t", backend_kind_str(kind), "\t-\t0\n");
        return;
    }
    defer tls::tls_endpoint_close(ep);

    let fd = net::tcp_connect(host, port_u as u16, 4000);
    if fd <= 0 {
        print("CANARY\tConnectError\t", backend_kind_str(ep.active_kind), "\t-\t0\n");
        return;
    }
    defer net::tcp_close(fd);

    let hs_st = run_tcp_tls_handshake(fd, ep);
    if hs_st != tls::TlsBackendStatus.Ok {
        print("CANARY\t", status_str(hs_st), "\t", backend_kind_str(ep.active_kind), "\t-\t0\n");
        return;
    }

    let sel_alpn = tls::tls_endpoint_selected_alpn(ep);
    let alpn_out = if sel_alpn.len > 0 { sel_alpn[..] } else { "-" };
    let app_n = exchange_canary_app_data(fd, ep, sni);
    print("CANARY\tOk\t", backend_kind_str(ep.active_kind), "\t", alpn_out, "\t", app_n, "\n");
}

fn print_backend_availability() {
    let p = if tls::tls_backend_available(tls::TlsBackendKind.PureGoose) { 1 } else { 0 };
    let o = if tls::tls_backend_available(tls::TlsBackendKind.SystemOpenSsl) { 1 } else { 0 };
    let s = if tls::tls_backend_available(tls::TlsBackendKind.SystemSchannel) { 1 } else { 0 };
    let st = if tls::tls_backend_available(tls::TlsBackendKind.SystemSecureTransport) { 1 } else { 0 };
    print("BACKENDS\tpure=", p, "\topenssl=", o, "\tschannel=", s, "\tsecure_transport=", st, "\n");
}

fn main() {
    let a = args();
    guard a.len >= 2 else {
        print("ERR:USAGE\n");
        exit(2);
    }
    if a[1] == "backends" {
        print_backend_availability();
        return;
    }
    if a[1] == "probe" {
        run_probe(a);
        return;
    }
    print("ERR:UNKNOWN_CMD\n");
    exit(2);
}
