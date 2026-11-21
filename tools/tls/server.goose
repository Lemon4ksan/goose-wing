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

fn main() {
    let port_env = net::get_env_port(0);
    let listener = net::tcp_listen("0.0.0.0", port_env, 128);
    if listener <= 0 {
        print("ERROR_FAILED_TO_LISTEN\n");
        return;
    }
    let port = net::tcp_getsockname_port(listener);

    var server = server::new_http_server("0.0.0.0", port);
    let _ = server.server_name.try_set("goose-tls/1.3");
    let _ = server::add_server_name(server, "goose-wing.local", "CERT-GOOSE-WING", "KEY-GOOSE-WING");
    let _ = server::add_server_name(server, "*.goose-wing.local", "CERT-WILDCARD-GOOSE-WING", "KEY-WILDCARD-GOOSE-WING");
    server::add_static_get_route(server, "/secure-hello", "text/plain", "Hello over TLS 1.3!", 1);
    let _ = server::add_static_route(server.pipeline.router, "POST", "/secure-echo", "text/plain", "TLS_ECHO_OK", 2);
    server::add_static_get_route(server, "/shutdown", "text/plain", "BYE\n", 99);

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
        is_running = handle_tls_connection(conn, server, tls_cfg);
        net::tcp_close(conn);
    }

    net::tcp_close(listener);
}
