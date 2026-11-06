// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Dedicated HTTP/2 Server for h2spec Conformance Testing (RFC 9113 & RFC 7540).
// HTTP/2 implementation in pure Goose for h2spec testing.
import std;
import core from "../..";
import wing from "../..";

fn serve_h2spec_connection(
    conn:     i64,
    server:   wing::HttpServer&,
    in_buf:   u8[>..]&,
    out_wire: u8[>..]&,
) -> bool {
    in_buf.clear();
    var chunk: u8[..4096] = [];
    loop {
        chunk.clear();
        let recvd = wing::tcp_recv(conn, chunk, 4096, 500);
        if recvd == -2 {
            continue;
        }
        if recvd <= 0 {
            break;
        }
        in_buf.append(chunk[..recvd]);

        // 1. HTTP/2 Connection Preface check
        if wing::is_partial_h2_client_preface(in_buf[..]) {
            continue;
        }
        if wing::is_h2_client_preface(in_buf[..]) {
            let _ = wing::serve_h2_connection(server, conn, in_buf[..], 50);
            break;
        }

        // If it starts with "PRI " but is not valid preface -> RFC 9113 Section 3.4: HTTP/2 Connection Preface
        if in_buf.len >= 4 && in_buf[..4] == "PRI " {
            break;
        }

        // 2. Check for HTTP/1 shutdown or fallback
        let hdr_end = core::fast_find_crlfcrlf(in_buf[..]);
        if hdr_end >= 0 {
            if core::starts_with(in_buf[..], "GET /shutdown") {
                out_wire.clear();
                let _ = wing::handle_connection_wire(server, "127.0.0.1", in_buf[..], 0, out_wire);
                wing::tcp_send(conn, out_wire[..]);
                return false;
            }
            break;
        }
    }
    return true;
}

fn main() {
    let listener = wing::tcp_listen("127.0.0.1", 0, 128);
    if listener <= 0 {
        print("ERROR_FAILED_TO_LISTEN\n");
        return;
    }
    let port = wing::tcp_getsockname_port(listener);

    var server = wing::new_http_server("127.0.0.1", port);
    let _ = server.server_name.try_set("goose-h2spec/1.0");
    wing::add_static_get_route(server, "/", "text/plain", "OK", 100);
    wing::add_static_get_route(server, "/ping", "text/plain", "PONG", 101);
    wing::add_post_route(server, "/ping", 102);
    wing::add_post_route(server, "/echo", 202);
    wing::add_static_get_route(server, "/shutdown", "text/plain", "BYE\n", 999);

    print("READY_PORT:", port, "\n");

    var in_buf:   u8[>..] = [];
    var out_wire: u8[>..] = [];
    var is_running = true;
    while is_running {
        let conn = wing::tcp_accept(listener, 200);
        if conn <= 0 {
            continue;
        }
        is_running = serve_h2spec_connection(conn, server, in_buf, out_wire);
        wing::tcp_close(conn);
    }

    wing::tcp_close(listener);
}
