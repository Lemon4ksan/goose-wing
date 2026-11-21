// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// goose-wing Network Chaos Test Server
// Exercises serve_reactor under TCP packet fragmentation, micro-slicing, and pipelining.
import std;
import wing from "../..";

fn main() {
    let port_env = net::get_env_port(0);

    var server = server::new_http_server();
    server::add_static_get_route(server, "/", "text/plain", "OK", 1);
    server::add_post_route(server, "/echo", 2);
    server::add_static_get_route(server, "/health", "text/plain", "HEALTHY", 3);

    let listener = net::tcp_listen("0.0.0.0", port_env, 4096);
    guard listener > 0 else {
        print("ERROR_FAILED_TO_LISTEN\n");
        return;
    }

    let port = net::tcp_getsockname_port(listener);
    print("READY_PORT:", port, "\n");

    server::serve_reactor(server, listener, 0);
}
