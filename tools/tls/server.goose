// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Dedicated TLS 1.3 Interop Server for goose-wing E2E Verification.
// Conforms to RFC 8446 (TLS 1.3), RFC 6066 (SNI), RFC 7301 (ALPN), and RFC 8879 (Cert Compression).
import std;
import wing from "../..";

// RFC 8446 Section 6.2: Alert Descriptions used for fail-closed state-machine rejections.
const TLS_ALERT_LEVEL_FATAL:        u8  = 2;
const TLS_ALERT_UNEXPECTED_MESSAGE: u8  = 10;
const TLS_ALERT_ILLEGAL_PARAMETER:  u8  = 47;
const TLS_ALERT_DECODE_ERROR:       u8  = 50;
const TLS_ALERT_PROTOCOL_VERSION:   u8  = 70;
const TLS_ALERT_NO_APP_PROTOCOL:    u8  = 120;
const TLS_EXT_SUPPORTED_VERSIONS:   u16 = 43;
const TLS_VERSION_1_3_WIRE:         u16 = 0x0304;

fn send_fatal_tls_alert(conn: i64, alert_desc: u8) {
    let rec: u8[7] = [0x15, 0x03, 0x03, 0x00, 0x02, TLS_ALERT_LEVEL_FATAL, alert_desc];
    let _ = net::tcp_send(conn, rec[..]);
}

// Verifies that a ClientHello `supported_versions` extension advertises TLS 1.3 (0x0304).
//
// Example:
//   ext_raw = [0x02, 0x03, 0x04]
//   returns: true
fn supported_versions_has_tls13(ext_raw: const u8[:]) -> bool {
    guard ext_raw.len >= 3 else { return false; }
    let list_len = ext_raw[0] as i64;
    guard list_len >= 2 && (list_len & 1) == 0 && ext_raw.len >= core::add_sat_i64(1, list_len) else {
        return false;
    }
    var i: i64 = 1;
    let end_idx = core::add_sat_i64(1, list_len);
    while core::add_sat_i64(i, 2) <= end_idx {
        let ver = core::read_be_u16(ext_raw, i);
        if ver == TLS_VERSION_1_3_WIRE {
            return true;
        }
        i = core::add_sat_i64(i, 2);
    }
    return false;
}

// Parses ClientHello extensions for SNI, ALPN, and RFC 8446 TLS 1.3 supported_versions.
// Returns 0 on success or a fatal TLS Alert description code on protocol violation.
//
// Example:
//   ch_payload = valid TLS 1.3 ClientHello body with SNI + ALPN + supported_versions(0x0304)
//   returns: 0, sni_str populated, out_alpn negotiated
fn parse_client_hello_sni_alpn(
    ch_payload: const u8[:],
    sni_str:    u8[..255]&,
    out_alpn:   tls::NegotiatedAlpn&,
) -> u8 {
    guard ch_payload.len > 34 else { return TLS_ALERT_DECODE_ERROR; }
    let sess_id_len = ch_payload[34] as i64;
    let mut_idx = core::add_sat_i64(35, sess_id_len);
    guard ch_payload.len >= core::add_sat_i64(mut_idx, 2) else { return TLS_ALERT_DECODE_ERROR; }

    let cs_len = core::read_be_u16(ch_payload, mut_idx) as i64;
    let comp_idx = core::add_sat_i64(core::add_sat_i64(mut_idx, 2), cs_len);
    guard ch_payload.len > comp_idx else { return TLS_ALERT_DECODE_ERROR; }

    let comp_len = ch_payload[comp_idx] as i64;
    let ext_start = core::add_sat_i64(core::add_sat_i64(comp_idx, 1), comp_len);
    guard ch_payload.len >= core::add_sat_i64(ext_start, 2) else { return TLS_ALERT_DECODE_ERROR; }

    let ext_total_len = core::read_be_u16(ch_payload, ext_start) as i64;
    let ext_end = core::add_sat_i64(core::add_sat_i64(ext_start, 2), ext_total_len);
    guard ch_payload.len >= ext_end else { return TLS_ALERT_DECODE_ERROR; }

    let exts_slice = ch_payload[ext_start..ext_end];
    var entries: tls::ExtensionEntry[..32] = [];
    guard tls::parse_extensions_block(exts_slice, entries) else {
        return TLS_ALERT_ILLEGAL_PARAMETER;
    }

    let sv_raw, has_sv = tls::find_extension(entries, TLS_EXT_SUPPORTED_VERSIONS);
    guard has_sv && supported_versions_has_tls13(sv_raw) else {
        return TLS_ALERT_PROTOCOL_VERSION;
    }

    let sni_raw, has_sni = tls::find_extension(entries, rfc::TLS_EXT_SERVER_NAME);
    if has_sni {
        guard tls::parse_sni_extension(sni_raw, sni_str) else {
            return TLS_ALERT_DECODE_ERROR;
        }
    }

    let alpn_raw, has_alpn = tls::find_extension(entries, rfc::TLS_EXT_ALPN);
    if has_alpn {
        out_alpn = tls::negotiate_alpn(alpn_raw, false);
        guard out_alpn == tls::NegotiatedAlpn.H2 || out_alpn == tls::NegotiatedAlpn.Http11 else {
            return TLS_ALERT_NO_APP_PROTOCOL;
        }
    }
    return 0;
}

fn send_tls13_server_hello(conn: i64) {
    var sh_builder = core::builder_init();
    core::put_u16(sh_builder, 0x0303); // Legacy version

    for _ in 32 {
        core::put_u8(sh_builder, 0x5A);
    }

    core::put_u8(sh_builder, 0);
    core::put_u16(sh_builder, 0x1301); // TLS_AES_128_GCM_SHA256
    core::put_u8(sh_builder, 0);

    core::start_u16_prefix(sh_builder);
    core::put_u16(sh_builder, TLS_EXT_SUPPORTED_VERSIONS);
    core::start_u16_prefix(sh_builder);
    core::put_u16(sh_builder, TLS_VERSION_1_3_WIRE);
    core::finish_u16_prefix(sh_builder);
    core::finish_u16_prefix(sh_builder);

    var hs_msg: u8[..256] = [];
    guard hs_msg.try_push(rfc::TLS_HS_SERVER_HELLO) else { return; }
    hs_msg.append_u24_be(sh_builder.buf.len as u32);
    guard hs_msg.try_append(sh_builder.buf[..]) else { return; }

    var record_out: u8[..300] = [];
    guard record_out.try_push(0x16) &&
          record_out.try_push(0x03) &&
          record_out.try_push(0x03) else { return; }
    record_out.append_u16_be(hs_msg.len as u16);
    guard record_out.try_append(hs_msg[..]) else { return; }

    // Append ChangeCipherSpec (RFC 8446 Appendix D.4 compatibility)
    let ccs: u8[6] = [0x14, 0x03, 0x03, 0x00, 0x01, 0x01];
    guard record_out.try_append(ccs[..]) else { return; }

    let _ = net::tcp_send(conn, record_out[..]);
}

fn handle_tls_handshake_record(
    conn:           i64,
    server:         const server::HttpServer&,
    record_payload: const u8[:],
) {
    guard record_payload.len >= 4 else {
        send_fatal_tls_alert(conn, TLS_ALERT_DECODE_ERROR);
        return;
    }
    let msg_type = record_payload[0];
    let msg_len = core::read_be_u24(record_payload, 1) as i64;
    let body_end = core::add_sat_i64(4, msg_len);
    guard msg_type == rfc::TLS_HS_CLIENT_HELLO && record_payload.len >= body_end else {
        send_fatal_tls_alert(conn, TLS_ALERT_UNEXPECTED_MESSAGE);
        return;
    }

    let ch_payload = record_payload[4..body_end];
    var sni_str: u8[..255] = [];
    var negotiated_alpn = tls::NegotiatedAlpn.None;
    let alert_code = parse_client_hello_sni_alpn(ch_payload, sni_str, negotiated_alpn);
    if alert_code != 0 {
        send_fatal_tls_alert(conn, alert_code);
        return;
    }
    let _ = negotiated_alpn;

    if sni_str.len > 0 {
        let _, ok_sni = server::resolve_sni_credentials(server, sni_str[..]);
        guard ok_sni else {
            send_fatal_tls_alert(conn, TLS_ALERT_ILLEGAL_PARAMETER);
            return;
        }
    }

    send_tls13_server_hello(conn);
}

fn is_synthetic_wire_client_hello(record_payload: const u8[:]) -> bool {
    guard record_payload.len >= 38 else { return false; }
    return record_payload[6] == 0x42 &&
        record_payload[7] == 0x42 &&
        record_payload[8] == 0x42 &&
        record_payload[9] == 0x42;
}

fn serve_live_tls13_session(
    conn:           i64,
    server:         server::HttpServer&,
    tls_cfg:        const tls::ServerHandshakeConfig&,
    record_payload: const u8[:],
) {
    let slot_idx, ok_hs = tls::server_handshake_with_ch(conn, record_payload, tls_cfg);
    guard ok_hs else {
        send_fatal_tls_alert(conn, TLS_ALERT_ILLEGAL_PARAMETER);
        return;
    }

    var pipe = core::new_pipe_buffer();
    var cork = core::new_cork_buffer();
    let h2_idx = server::alloc_temp_h2_session(server.pipeline, server.server_name[..], 0);
    guard h2_idx >= 0 && h2_idx < server::REACTOR_MAX_H2_SESSIONS else {
        tls::free_cipher_slot(slot_idx);
        return;
    }

    loop {
        let recvd = server::tls_recv_pipe(conn, slot_idx, pipe, 4096, 2000);
        if recvd <= 0 { break; }

        let now_ns = core::as_nanos(core::monotonic_now());
        let _, ok = server::handle_connection_pipe(
            server, "127.0.0.1", pipe, now_ns, cork, server::g_default_reactor.h2_sessions[h2_idx],
        );
        let should_close = !ok || server::response_wire_has_connection_close(core::cork_as_slice(cork));
        if !ok {
            if cork.cork_pending() > 0 { server::tls_flush_cork(conn, slot_idx, cork); }
            break;
        }
        if cork.cork_pending() > 0 {
            let sent = server::tls_flush_cork(conn, slot_idx, cork);
            if sent <= 0 || should_close { break; }
        } else if should_close {
            break;
        }
    }
    server::free_reactor_h2_session(h2_idx as i16, server.pipeline);
    tls::free_cipher_slot(slot_idx);
}

fn dispatch_first_tls_record(
    conn:           i64,
    server:         server::HttpServer&,
    tls_cfg:        const tls::ServerHandshakeConfig&,
    content_type:   u8,
    record_payload: const u8[:],
) -> bool {
    if content_type == 0x16 {
        if is_synthetic_wire_client_hello(record_payload) {
            handle_tls_handshake_record(conn, server, record_payload);
            return false;
        }
        serve_live_tls13_session(conn, server, tls_cfg, record_payload);
        return true;
    }
    if content_type == 0x15 {
        return true;
    }
    // Unexpected ChangeCipherSpec (0x14), ApplicationData (0x17), or invalid record before handshake.
    send_fatal_tls_alert(conn, TLS_ALERT_UNEXPECTED_MESSAGE);
    return true;
}

fn try_handle_shutdown_request(
    conn:     i64,
    server:   server::HttpServer&,
    in_buf:   const u8[:],
    out_wire: u8[..256]&,
) -> bool, bool {
    guard in_buf.len >= 14 && in_buf[..14] == "GET /shutdown " else { return false, false; }
    let hdr_end = core::fast_find_crlfcrlf(in_buf);
    guard hdr_end >= 0 else { return true, false; }
    out_wire.clear();
    let _ = server::handle_connection_wire(server, "127.0.0.1", in_buf, 0, out_wire);
    let _ = net::tcp_send(conn, out_wire[..]);
    return true, true;
}

fn handle_tls_connection(
    conn:    i64,
    server:  server::HttpServer&,
    tls_cfg: const tls::ServerHandshakeConfig&,
) -> bool {
    var in_buf:   u8[>..]    = [];
    var out_wire: u8[..256]  = [];
    var rem:      u8[>..]    = [];
    var chunk:    u8[..4096] = [];

    while true {
        chunk.clear();
        let recvd = net::tcp_recv(conn, chunk, 4096, 500);
        if recvd == -2 { continue; }
        if recvd <= 0 { break; }
        in_buf.append(chunk[..recvd]);

        let is_sd, sd_done = try_handle_shutdown_request(conn, server, in_buf[..], out_wire);
        if sd_done { return false; }
        if is_sd { continue; }
        if in_buf.len < 5 { continue; }

        let content_type = in_buf[0];
        let record_len = core::read_be_u16(in_buf[..], 3) as i64;
        let total_record_len = core::add_sat_i64(5, record_len);
        if in_buf.len < total_record_len { continue; }

        let should_break = dispatch_first_tls_record(
            conn, server, tls_cfg, content_type, in_buf[5..total_record_len],
        );
        if should_break { break; }

        rem.clear();
        rem.append(in_buf[total_record_len..]);
        in_buf.clear();
        in_buf.append(rem[..]);
    }
    return true;
}

fn drain_ep_wire(conn: i64, ep: tls::TlsEndpoint&) -> bool {
    var wire: u8[16640] = [0; 16640];
    for _ in 64 {
        let n, st = tls::tls_endpoint_drain_wire(ep, wire[..]);
        guard st == tls::TlsBackendStatus.Ok else { return false; }
        if n <= 0 { return true; }
        var sent_total: i64 = 0;
        while sent_total < n {
            let sent = net::tcp_send(conn, wire[sent_total..n]) as i64;
            guard sent > 0 else { return false; }
            sent_total = core::add_sat_i64(sent_total, sent);
        }
    }
    return true;
}

fn resolve_and_install_sni(
    conn:   i64,
    server: const server::HttpServer&,
    ep:     tls::TlsEndpoint&,
) -> bool {
    let sni = tls::tls_endpoint_client_sni(ep);
    guard sni.len > 0 else {
        send_fatal_tls_alert(conn, TLS_ALERT_ILLEGAL_PARAMETER);
        return false;
    }
    let creds, ok_sni = server::resolve_sni_credentials(server, sni[..]);
    guard ok_sni else {
        send_fatal_tls_alert(conn, TLS_ALERT_ILLEGAL_PARAMETER);
        return false;
    }
    let st = tls::tls_endpoint_set_server_credentials_pem(ep, creds.cert_pem, creds.key_pem);
    guard st == tls::TlsBackendStatus.Ok else {
        send_fatal_tls_alert(conn, TLS_ALERT_ILLEGAL_PARAMETER);
        return false;
    }
    return true;
}

fn feed_sni_hs_chunk(
    conn:             i64,
    server:           server::HttpServer&,
    ep:               tls::TlsEndpoint&,
    checked_shutdown: bool&,
    sd_buf:           u8[..256]&,
    out_wire:         u8[..256]&,
) -> bool, bool {
    var chunk: u8[..4096] = [];
    let recvd = net::tcp_recv(conn, chunk, 4096, 5000);
    guard recvd > 0 else { return false, true; }
    if !checked_shutdown {
        if sd_buf.try_append(chunk[..recvd]) {
            let is_sd, sd_done = try_handle_shutdown_request(conn, server, sd_buf[..], out_wire);
            if sd_done { return false, false; }
            if is_sd { return true, true; }
        }
        checked_shutdown = true;
    }
    let fed, fst = tls::tls_endpoint_feed_wire(ep, chunk[..recvd]);
    guard fst == tls::TlsBackendStatus.Ok && fed == recvd else { return false, true; }
    return true, true;
}

fn drive_sni_endpoint_handshake(
    conn:   i64,
    server: server::HttpServer&,
    ep:     tls::TlsEndpoint&,
) -> bool, bool {
    var sd_buf:   u8[..256] = [];
    var out_wire: u8[..256] = [];
    var checked_shutdown = false;

    for _ in 128 {
        let st = tls::tls_endpoint_step_handshake(ep);
        let _ = drain_ep_wire(conn, ep);
        if st == tls::TlsBackendStatus.Ok || tls::tls_endpoint_is_established(ep) {
            return true, true;
        }
        if st == tls::TlsBackendStatus.NeedSniCredentials {
            guard resolve_and_install_sni(conn, server, ep) else { return false, true; }
            continue;
        }
        if st == tls::TlsBackendStatus.WantWrite { continue; }
        guard st == tls::TlsBackendStatus.WantRead else { return false, true; }

        let fed_ok, keep_running = feed_sni_hs_chunk(
            conn, server, ep, checked_shutdown, sd_buf, out_wire,
        );
        guard fed_ok else { return false, keep_running; }
    }
    return false, true;
}

fn send_sni_echo_reply(
    conn:    i64,
    ep:      tls::TlsEndpoint&,
    sni:     const u8[:],
    payload: const u8[:],
) {
    var resp: u8[..4608] = [];
    guard resp.try_append("EDGE_ECHO ") &&
        resp.try_append(sni) &&
        resp.try_append(":") &&
        resp.try_append(payload) else {
        return;
    }
    let wn, wst = tls::tls_endpoint_write_app(ep, resp[..]);
    if wst == tls::TlsBackendStatus.Ok && wn > 0 {
        let _ = drain_ep_wire(conn, ep);
    }
    let _ = tls::tls_endpoint_shutdown(ep);
    let _ = drain_ep_wire(conn, ep);
}

fn pull_sni_app_chunk(conn: i64, ep: tls::TlsEndpoint&) -> bool {
    var chunk: u8[..4096] = [];
    let recvd = net::tcp_recv(conn, chunk, 4096, 5000);
    guard recvd > 0 else { return false; }
    let fed, fst = tls::tls_endpoint_feed_wire(ep, chunk[..recvd]);
    return fst == tls::TlsBackendStatus.Ok && fed == recvd;
}

fn serve_sni_echo_session(conn: i64, ep: tls::TlsEndpoint&) {
    var app_rx:  u8[1024]   = [0; 1024];
    var req_buf: u8[..4096] = [];
    let sni = tls::tls_endpoint_client_sni(ep);

    for _ in 64 {
        let n, rst = tls::tls_endpoint_read_app(ep, app_rx[..]);
        if n > 0 {
            guard req_buf.try_append(app_rx[..n]) else { return; }
            if req_buf[..].contains_byte('\n') || req_buf.len >= req_buf.cap {
                send_sni_echo_reply(conn, ep, sni[..], req_buf[..]);
                return;
            }
            continue;
        }
        if rst == tls::TlsBackendStatus.Ok { continue; }
        guard rst == tls::TlsBackendStatus.WantRead && pull_sni_app_chunk(conn, ep) else {
            return;
        }
    }
}

fn handle_sni_endpoint_connection(conn: i64, server: server::HttpServer&) -> bool {
    var ep_cfg = tls::TlsBackendConfig {
        kind:                   tls::TlsBackendKind.PureGoose,
        is_server:              true,
        defer_sni_credentials:  true,
        enable_session_tickets: false,
        ..
    };
    guard ep_cfg.alpn_wire.try_set("\x02h2\x08http/1.1") else { return true; }
    var ep, open_st = tls::tls_endpoint_open(ep_cfg);
    guard open_st == tls::TlsBackendStatus.Ok else { return true; }
    defer tls::tls_endpoint_close(ep);

    let hs_ok, keep_running = drive_sni_endpoint_handshake(conn, server, ep);
    if hs_ok {
        serve_sni_echo_session(conn, ep);
    }
    return keep_running;
}

// Finds the `:` separating `<fullchain_pem>` and `<key_pem>`, skipping a leading
// Windows drive prefix such as `C:\` or `C:/`.
//
// Example:
//   rest = "C:\\tmp\\a.pem:C:\\tmp\\a.key"
//   returns: 12
fn find_sni_pair_colon(rest: const u8[:]) -> i64 {
    var i: i64 = 0;
    while i < rest.len {
        if rest[i] == ':' {
            let is_win_drive = i == 1 &&
                core::is_ascii_alpha(rest[0]) &&
                rest.len >= 3 &&
                (rest[2] == '\\' || rest[2] == '/');
            if !is_win_drive {
                return i;
            }
        }
        i = core::add_sat_i64(i, 1);
    }
    return -1;
}

// Parses `--sni-map <domain>=<fullchain_pem>:<key_pem>` (also accepts `|` separator
// and preserves Windows drive prefixes such as `C:\...`).
//
// Example:
//   raw = "a.edge.test=C:\\tmp\\chain.pem:C:\\tmp\\key.pem"
//   returns: true, out_domain = "a.edge.test", out_cert = "C:\\tmp\\chain.pem", out_key = "C:\\tmp\\key.pem"
fn parse_sni_map_spec(
    raw:        const u8[:],
    out_domain: u8[..255]&,
    out_cert:   u8[..512]&,
    out_key:    u8[..512]&,
) -> bool {
    out_domain.clear();
    out_cert.clear();
    out_key.clear();
    let domain, rest, ok_eq = raw.split_once_byte('=');
    guard ok_eq && domain.len > 0 && rest.len > 0 else { return false; }

    var cert_s: const u8[:] = "";
    var key_s:  const u8[:] = "";
    let pipe_cert, pipe_key, has_pipe = rest.split_once_byte('|');
    if has_pipe {
        cert_s = pipe_cert;
        key_s = pipe_key;
    } else {
        let sep_idx = find_sni_pair_colon(rest);
        guard sep_idx > 0 && core::add_sat_i64(sep_idx, 1) < rest.len else { return false; }
        cert_s = rest[..sep_idx];
        key_s = rest[core::add_sat_i64(sep_idx, 1)..];
    }
    guard cert_s.len > 0 && key_s.len > 0 else { return false; }
    guard out_domain.try_set(domain) &&
        out_cert.try_set(cert_s) &&
        out_key.try_set(key_s) else {
        out_domain.clear();
        out_cert.clear();
        out_key.clear();
        return false;
    }
    return true;
}

fn print_usage() {
    print("Usage: tls_server [--port <port>] [--sni-map <domain>=<fullchain_pem>:<key_pem>]...\n");
    print("  --port <port>   Listen port (0 for ephemeral; defaults to WING_PORT/PORT env).\n");
    print("  --sni-map       Repeatable SNI mapping for PureGoose TlsEndpoint deferred-SNI mode\n");
    print("                  (also accepts '|' between fullchain_pem and key_pem).\n");
}

fn load_one_sni_map(
    spec:     const u8[:],
    server:   server::HttpServer&,
    cert_pem: u8[>..]&,
    key_pem:  u8[>..]&,
) -> bool {
    var domain:    u8[..255] = [];
    var cert_path: u8[..512] = [];
    var key_path:  u8[..512] = [];
    guard parse_sni_map_spec(spec, domain, cert_path, key_path) else { return false; }

    cert_pem.clear();
    core::secure_zeroize_slice(key_pem[..]);
    key_pem.clear();
    guard read_file(cert_path[..], cert_pem) && read_file(key_path[..], key_pem) else {
        return false;
    }
    return server::add_server_name(server, domain[..], cert_pem[..], key_pem[..]);
}

fn load_cli_sni_maps(
    cli_args:  u8[:][>..]&,
    server:    server::HttpServer&,
    sni_count: i64&,
) -> bool {
    var cert_pem: u8[>..] = [];
    var key_pem:  u8[>..] = [];
    defer core::secure_zeroize_slice(key_pem[..]);

    var i: i64 = 1;
    while i < cli_args.len {
        let next_i = core::add_sat_i64(i, 1);
        if cli_args[i] == "--port" {
            i = core::add_sat_i64(i, 2);
            continue;
        }
        guard cli_args[i] == "--sni-map" && next_i < cli_args.len else { return false; }
        guard load_one_sni_map(cli_args[next_i], server, cert_pem, key_pem) else {
            return false;
        }
        sni_count = core::add_sat_i64(sni_count, 1);
        i = core::add_sat_i64(i, 2);
    }
    return true;
}

fn parse_cli_port_and_help(
    cli_args:  u8[:][>..]&,
    port_val:  u16&,
    show_help: bool&,
) -> bool {
    var i: i64 = 1;
    while i < cli_args.len {
        if cli_args[i] == "--help" || cli_args[i] == "-h" {
            show_help = true;
            return true;
        }
        let next_i = core::add_sat_i64(i, 1);
        guard (cli_args[i] == "--port" || cli_args[i] == "--sni-map") && next_i < cli_args.len else {
            return false;
        }
        if cli_args[i] == "--port" {
            let p_u64, ok_p = cli_args[next_i].parse_u64_dec();
            guard ok_p && p_u64 <= 65535 else { return false; }
            port_val = p_u64 as u16;
        }
        i = core::add_sat_i64(i, 2);
    }
    return true;
}

fn main() {
    let cli_args = args();
    var port_val = net::get_env_port(0);
    var show_help = false;
    guard parse_cli_port_and_help(cli_args, port_val, show_help) else {
        print("ERROR_INVALID_ARGS\n");
        exit(2);
    }
    if show_help {
        print_usage();
        return;
    }

    let listener = net::tcp_listen("0.0.0.0", port_val, 128);
    if listener <= 0 {
        print("ERROR_FAILED_TO_LISTEN\n");
        return;
    }
    let port = net::tcp_getsockname_port(listener);

    var server = server::new_http_server("0.0.0.0", port);
    let _ = server.server_name.try_set("goose-tls/1.3");
    server::add_static_get_route(server, "/secure-hello", "text/plain", "Hello over TLS 1.3!", 1);
    let _ = server::add_static_route(server.pipeline.router, "POST", "/secure-echo", "text/plain", "TLS_ECHO_OK", 2);
    server::add_static_get_route(server, "/shutdown", "text/plain", "BYE\n", 99);

    var sni_count: i64 = 0;
    guard load_cli_sni_maps(cli_args, server, sni_count) else {
        net::tcp_close(listener);
        print("ERROR_INVALID_SNI_MAP\n");
        exit(2);
    }
    if sni_count == 0 {
        let _ = server::add_server_name(server, "goose-wing.local", "CERT-GOOSE-WING", "KEY-GOOSE-WING");
        let _ = server::add_server_name(server, "*.goose-wing.local", "CERT-WILDCARD-GOOSE-WING", "KEY-WILDCARD-GOOSE-WING");
    }

    let seed: u8[32] = [0x42; 32];
    var cert_der: u8[..2048] = [];
    let _ = tls::build_test_ed25519_cert_der(seed, "goose-wing.local", "goose-wing.local", "127.0.0.1", cert_der);
    var tls_cfg = tls::ServerHandshakeConfig {
        priv_seed: seed,
        ..
    };
    tls_cfg.cert_der.append(cert_der[..]);
    tls_cfg.alpn.append("h2,http/1.1");

    print("READY_PORT:", port, "\n");

    var is_running = true;
    while is_running {
        let conn = net::tcp_accept(listener, 200);
        if conn <= 0 { continue; }
        is_running = if sni_count > 0 {
            handle_sni_endpoint_connection(conn, server)
        } else {
            handle_tls_connection(conn, server, tls_cfg)
        };
        net::tcp_close(conn);
    }

    net::tcp_close(listener);
}
