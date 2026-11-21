// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Dedicated HTTP/2 Server for h2spec Conformance Testing (RFC 9113 & RFC 7540).
// HTTP/2 implementation in pure Goose for h2spec testing.
import std;
import wing from "../..";

var g_h2spec_server = server::new_http_server("127.0.0.1", 0);

fn main() {
    let listener = net::tcp_listen("127.0.0.1", 0, 128);
    if listener <= 0 {
        print("ERROR_FAILED_TO_LISTEN\n");
        return;
    }
    let port = net::tcp_getsockname_port(listener);

    g_h2spec_server.port = port;
    let _ = g_h2spec_server.server_name.try_set("goose-h2spec/1.0");
    server::add_static_get_route(g_h2spec_server, "/", "text/plain", "OK_H2SPEC_DATA", 100);
    server::add_static_get_route(g_h2spec_server, "/ping", "text/plain", "PONG_H2SPEC_DATA", 101);
    server::add_post_route(g_h2spec_server, "/ping", 102);
    server::add_post_route(g_h2spec_server, "/echo", 202);
    server::add_static_get_route(g_h2spec_server, "/shutdown", "text/plain", "BYE\n", 999);

    print("READY_PORT:", port, "\n");
    server::serve_http_listener(listener, g_h2spec_server, 25);
    net::tcp_close(listener);
}
