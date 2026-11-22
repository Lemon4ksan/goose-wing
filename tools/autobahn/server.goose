// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Dedicated WebSocket Echo Server for Autobahn Testsuite (RFC 6455 Compliance).
// RFC-conformant WebSocket implementation in pure Goose.
import std;
import wing from "../..";

fn main() {
    let port_env = net::get_env_port(0);
    let listener = net::tcp_listen("0.0.0.0", port_env, 128);
    if listener <= 0 {
        print("ERROR_FAILED_TO_LISTEN\n");
        return;
    }
    let port = net::tcp_getsockname_port(listener);

    var server = server::new_http_server("0.0.0.0", port);
    let _ = server.server_name.try_set("goose-autobahn/1.0");
    let ws_behavior = realtime::WsBehavior {
        max_payload_length: 16777216,
        idle_timeout_s:     30,
        compression:        realtime::WS_COMPRESS_DEDICATED,
        ..
    };
    let _ = server::add_ws_route(server, "/", ws_behavior);
    server::add_static_get_route(server, "/shutdown", "text/plain", "BYE\n", 99);

    print("READY_PORT:", port, "\n");

    var in_buf:   u8[>..] = [];
    var frag_buf: u8[>..] = [];
    var out_wire: u8[>..] = [];
    server::serve_http_listener_buf(listener, server, in_buf, frag_buf, out_wire);
    net::tcp_close(listener);
}
