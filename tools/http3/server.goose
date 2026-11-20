// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Dedicated HTTP/3 & QUIC UDP Server for goose-wing E2E Verification.
// Conforms to RFC 9000 (QUIC Transport), RFC 9114 (HTTP/3), and RFC 9204 (QPACK).
import std;
import core from "../..";
import wing from "../..";

fn dispatch_incoming_datagram(
    sock:      i64,
    server:    wing::HttpServer&,
    ep:        wing::H3ServerEndpoint&,
    datagram:  const u8[:],
    peer_ip:   u32,
    peer_port: u16,
    out_wire:  u8[..2048]&,
) -> bool {
    let udp_tr = wing::Transport.Udp {
        fd:        sock,
        peer_ip4:  peer_ip,
        peer_port: peer_port,
    };
    if datagram.len >= 8 && datagram[..8] == "SHUTDOWN" {
        let _ = wing::send(udp_tr, "BYE");
        return false;
    }

    let now_ns = core::as_nanos(core::monotonic_now());
    if wing::handle_h3_quic_datagram(server, ep, "127.0.0.1", datagram, now_ns, out_wire) {
        let _ = wing::send(udp_tr, out_wire[..]);
    }
    return true;
}

inline fn is_recv_timeout(recvd: i32) -> bool {
    return recvd == -2;
}

inline fn is_recv_valid(recvd: i32, max_len: i64) -> bool {
    return recvd > 0 && recvd <= max_len;
}

fn poll_and_dispatch_datagram(
    sock:     i64,
    server:   wing::HttpServer&,
    ep:       wing::H3ServerEndpoint&,
    in_buf:   u8[:],
    out_wire: u8[..2048]&,
) -> bool {
    var peer_port: u16 = 0;
    var peer_ip:   u32 = 0;
    let recvd = wing::udp_recvfrom(sock, in_buf, 500, peer_ip, peer_port);
    if is_recv_timeout(recvd) {
        return true;
    }
    guard is_recv_valid(recvd, in_buf.len) else {
        return false;
    }
    return dispatch_incoming_datagram(
        sock, server, ep, in_buf[..(recvd as i64)], peer_ip, peer_port, out_wire,
    );
}

fn run_server_loop(sock: i64, server: wing::HttpServer&, ep: wing::H3ServerEndpoint&) {
    var in_buf:   u8[65536]  = [0; 65536];
    var out_wire: u8[..2048] = [];
    var is_running = true;
    while is_running {
        is_running = poll_and_dispatch_datagram(sock, server, ep, in_buf[..], out_wire);
    }
}

fn main() {
    let port_env = wing::get_env_port(0);
    let sock = wing::udp_bind("0.0.0.0", port_env);
    guard sock > 0 else {
        print("ERROR_FAILED_TO_BIND\n");
        return;
    }

    let port = wing::tcp_getsockname_port(sock);
    var server = wing::new_http_server("0.0.0.0", port);
    wing::add_static_get_route(server, "/", "text/plain", "Hello from goose-wing HTTP/3!", 1);
    wing::add_static_get_route(
        server, "/api/info", "application/json", "{\"protocol\":\"h3\",\"engine\":\"goose-wing\"}", 2,
    );
    let _ = wing::add_static_route(server.pipeline.router, "POST", "/echo", "text/plain", "H3_POST_ACK", 3);

    let settings = fingerprint::H3Settings {
        qpack_max_table_capacity: 4096,
        max_field_section_size:   65536,
        qpack_blocked_streams:    16,
        enable_connect_protocol:  1,
    };
    var ep = wing::new_h3_server_endpoint(settings);

    print("READY_PORT:", port, "\n");

    run_server_loop(sock, server, ep);

    wing::tcp_close(sock);
}
