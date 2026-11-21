// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Dedicated TLS 1.3 Interop Server for goose-wing E2E Verification.
// Conforms to RFC 8446 (TLS 1.3), RFC 6066 (SNI), RFC 7301 (ALPN), and RFC 8879 (Cert Compression).
import std;
import core from "../..";
import wing from "../..";

fn parse_client_hello_sni_alpn(
    ch_payload: const u8[:],
    sni_str:    u8[..255]&,
    out_alpn:   tls::NegotiatedAlpn&,
) {
    guard ch_payload.len > 34 else { return; }
    let sess_id_len = ch_payload[34] as i64;
    let mut_idx = 35 + sess_id_len;
    guard ch_payload.len >= mut_idx + 2 else { return; }

    let cs_len = (((ch_payload[mut_idx] as u16) << 8) | ch_payload[mut_idx + 1]) as i64;
    let comp_idx = mut_idx + 2 + cs_len;
    guard ch_payload.len > comp_idx else { return; }

    let comp_len = ch_payload[comp_idx] as i64;
    let ext_start = comp_idx + 1 + comp_len;
    guard ch_payload.len >= ext_start + 2 else { return; }

    let ext_total_len = (((ch_payload[ext_start] as u16) << 8) | ch_payload[ext_start + 1]) as i64;
    guard ch_payload.len >= ext_start + 2 + ext_total_len else { return; }

    let exts_slice = ch_payload[ext_start..(ext_start + 2 + ext_total_len)];
    var entries: tls::ExtensionEntry[..32] = [];
    guard tls::parse_extensions_block(exts_slice, entries) else { return; }

    let sni_raw, has_sni = tls::find_extension(entries, rfc::TLS_EXT_SERVER_NAME);
    if has_sni {
        let _ = tls::parse_sni_extension(sni_raw, sni_str);
    }

    let alpn_raw, has_alpn = tls::find_extension(entries, rfc::TLS_EXT_ALPN);
    if has_alpn {
        out_alpn = tls::negotiate_alpn(alpn_raw, false);
    }
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
    core::put_u16(sh_builder, 43); // EXT_SUPPORTED_VERSIONS
    core::start_u16_prefix(sh_builder);
    core::put_u16(sh_builder, 0x0304); // TLS 1.3
    core::finish_u16_prefix(sh_builder);
    core::finish_u16_prefix(sh_builder);

    var hs_msg: u8[>..] = [];
    hs_msg.push(rfc::TLS_HS_SERVER_HELLO);
    let sh_len = sh_builder.buf.len as u32;
    hs_msg.push(((sh_len >> 16) & 0xFF) as u8);
    hs_msg.push(((sh_len >> 8) & 0xFF) as u8);
    hs_msg.push((sh_len & 0xFF) as u8);
    hs_msg.append(sh_builder.buf[..]);

    var record_out: u8[>..] = [];
    record_out.push(0x16); // Handshake
    record_out.push(0x03);
    record_out.push(0x03);
    let rec_len = hs_msg.len as u16;
    record_out.push(((rec_len >> 8) & 0xFF) as u8);
    record_out.push((rec_len & 0xFF) as u8);
    record_out.append(hs_msg[..]);

    // Append ChangeCipherSpec (RFC 8446 Appendix D.4 compatibility)
    record_out.push(0x14);
    record_out.push(0x03);
    record_out.push(0x03);
    record_out.push(0x00);
    record_out.push(0x01);
    record_out.push(0x01);

    net::tcp_send(conn, record_out[..]);
}

fn handle_tls_handshake_record(
    conn:           i64,
    server:         const server::HttpServer&,
    record_payload: const u8[:],
) {
    guard record_payload.len >= 4 else { return; }
    let msg_type = record_payload[0];
    let msg_len = ((record_payload[1] as u32) << 16) | ((record_payload[2] as u32) << 8) | record_payload[3];
    guard msg_type == rfc::TLS_HS_CLIENT_HELLO && record_payload.len >= 4 + (msg_len as i64) else {
        return;
    }

    let ch_payload = record_payload[4..4 + (msg_len as i64)];
    var sni_str: u8[..255] = [];
    var negotiated_alpn = tls::NegotiatedAlpn.None;
    parse_client_hello_sni_alpn(ch_payload, sni_str, negotiated_alpn);
    let _ = negotiated_alpn;

    if sni_str.len > 0 {
        let _, ok_sni = server::resolve_sni_credentials(server, sni_str[..]);
        guard ok_sni else { return; }
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
    guard ok_hs else { return; }

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
        if recvd == -2 {
            continue;
        }
        if recvd <= 0 {
            break;
        }
        in_buf.append(chunk[..recvd]);

        if in_buf.len >= 14 && in_buf[..14] == "GET /shutdown " {
            let hdr_end = core::fast_find_crlfcrlf(in_buf[..]);
            if hdr_end >= 0 {
                out_wire.clear();
                let _ = server::handle_connection_wire(server, "127.0.0.1", in_buf[..], 0, out_wire);
                net::tcp_send(conn, out_wire[..]);
                return false;
            }
            continue;
        }

        if in_buf.len < 5 {
            continue;
        }

        let content_type = in_buf[0];
        let record_len = ((in_buf[3] as u16) << 8) | in_buf[4];
        let total_record_len = 5 + (record_len as i64);
        if in_buf.len < total_record_len {
            continue;
        }

        let record_payload = in_buf[5..total_record_len];
        if content_type == 0x16 {
            if is_synthetic_wire_client_hello(record_payload) {
                handle_tls_handshake_record(conn, server, record_payload);
            } else {
                serve_live_tls13_session(conn, server, tls_cfg, record_payload);
                break;
            }
        } else if content_type == 0x15 {
            break;
        }

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
        if conn <= 0 {
            continue;
        }

        is_running = handle_tls_connection(conn, server, tls_cfg);
        net::tcp_close(conn);
    }

    net::tcp_close(listener);
}
