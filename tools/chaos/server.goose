// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// goose-wing Network Chaos Test Server
// Exercises serve_reactor under TCP packet fragmentation, micro-slicing, and pipelining.
import std;
import core from "../..";
import wing from "../..";

fn main() {
    let port_env = wing::get_env_port(0);

    var server = wing::new_http_server();
    wing::add_route(server.pipeline.router, "GET", "/", 1);
    wing::add_route(server.pipeline.router, "POST", "/echo", 2);
    wing::add_route(server.pipeline.router, "GET", "/health", 3);

    let listener = wing::tcp_listen("0.0.0.0", port_env, 4096);
    guard listener > 0 else {
        print("ERROR_FAILED_TO_LISTEN\n");
        return;
    }

    let port = wing::tcp_getsockname_port(listener);
    print("READY_PORT:", port, "\n");

    wing::serve_reactor(server, listener, 0);
}
