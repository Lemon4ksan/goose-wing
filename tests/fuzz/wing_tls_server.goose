// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Live TLS 1.3 + HTTP/1.1 / HTTP/2 interop server for OpenSSL differential testing.
// Issues post-handshake NewSessionTicket and handles KeyUpdate and 1-RTT resumption.
import std;
import core from "../..";
import wing from "../..";

const NST_LIFETIME_SEC: u32 = 3600;
const RECV_BUF_BYTES:   i64 = 4096;
const RECV_TIMEOUT_MS:  u32 = 5000;
const ACCEPT_POLL_MS:   u32 = 200;

fn print_cert_hex_line(cert_der: const u8[:]) {
    var hex_line: u8[..4200] = [];
    let _ = hex_line.try_append("CERT_HEX:");
    for b in cert_der {
        core::format_u64_hex_fixed(b, 2, hex_line, false);
    }
    print(hex_line[..]);
}

fn issue_session_ticket(conn: i64, slot_idx: u16, seq: u64) {
    var nonce_buf: u8[..32] = [];
    seq.format_u64_dec(nonce_buf);

    var ticket_buf: u8[..64] = [];
    let _ = ticket_buf.try_append("wing-nst-");
    seq.format_u64_dec(ticket_buf);

    let _ = tls::send_new_session_ticket(
        conn,
        slot_idx,
        NST_LIFETIME_SEC,
        nonce_buf[..],
        ticket_buf[..],
    );
}

fn run_session_io(
    conn:     i64,
    slot_idx: u16,
    server:   server::HttpServer&,
    pipe:     core::PipeBuffer&,
    cork:     core::CorkBuffer&,
) {
    defer tls::transport_close(conn, slot_idx);
    pipe.pipe_reset();
    cork.cork_reset();

    let h2_idx = server::alloc_temp_h2_session(server.pipeline, server.server_name[..], 0);
    guard h2_idx >= 0 && h2_idx < server::REACTOR_MAX_H2_SESSIONS else { return; }
    defer server::free_reactor_h2_session(h2_idx as i16, server.pipeline);

    loop {
        let recvd = server::tls_recv_pipe(conn, slot_idx, pipe, RECV_BUF_BYTES, RECV_TIMEOUT_MS);
        if recvd <= 0 { break; }

        let now_ns = core::monotonic_now().as_nanos();
        let _, ok = server::handle_connection_pipe(
            server,
            "127.0.0.1",
            pipe,
            now_ns,
            cork,
            server::g_default_reactor.h2_sessions[h2_idx],
        );
        let should_close = !ok || server::response_wire_has_connection_close(cork.cork_as_slice());
        if cork.cork_pending() > 0 {
            let sent = server::tls_flush_cork(conn, slot_idx, cork);
            if sent <= 0 { break; }
        }
        if !ok || should_close { break; }
    }
}

fn setup_tls_server(port: u16, out_cert: u8[..2048]&) -> server::HttpServer, tls::ServerHandshakeConfig {
    var server = server::new_http_server("127.0.0.1", port);
    server.pipeline.enable_rate_limiter = false;
    server.pipeline.enable_slowloris_timer = false;
    let _ = server.server_name.try_set("localhost");
    assert(server::add_static_route(
        server.pipeline.router,
        "GET",
        "/h1",
        "text/plain",
        "hello-from-wing-TLS1.3",
    ));
    assert(server::add_static_route(
        server.pipeline.router,
        "GET",
        "/ping",
        "text/plain",
        "OK",
    ));

    let seed: u8[32] = [0x42; 32];
    assert(tls::build_test_ed25519_cert_der(seed, "localhost", "localhost", "127.0.0.1", out_cert));

    var tls_cfg = tls::ServerHandshakeConfig { priv_seed: seed, .. };
    assert(tls_cfg.cert_der.try_set(out_cert[..]));
    assert(tls_cfg.alpn.try_set("http/1.1,h2"));
    return server, tls_cfg;
}

fn main() {
    let listener = net::tcp_listen("127.0.0.1", 0, 128);
    guard listener > 0 else {
        print("FATAL: listen failed");
        return;
    }
    defer net::tcp_close(listener);

    let port = net::tcp_getsockname_port(listener);
    var cert_der: u8[..2048] = [];
    var server, tls_cfg = setup_tls_server(port, cert_der);

    print_cert_hex_line(cert_der[..]);
    print("READY_PORT:", port);

    var pipe = core::new_pipe_buffer();
    var cork = core::new_cork_buffer();
    var ticket_seq: u64 = 0;

    while true {
        let conn = net::tcp_accept(listener, ACCEPT_POLL_MS);
        if conn <= 0 { continue; }

        let slot_idx, ok_hs = tls::server_handshake(conn, tls_cfg);
        if !ok_hs {
            net::tcp_close(conn);
            continue;
        }
        ticket_seq = core::add_sat_u64(ticket_seq, 1);
        issue_session_ticket(conn, slot_idx, ticket_seq);
        run_session_io(conn, slot_idx, server, pipe, cork);
    }
}
