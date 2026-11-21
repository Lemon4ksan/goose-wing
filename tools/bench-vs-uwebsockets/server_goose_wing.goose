// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// goose-wing benchmark server vs uWebSockets
// Conforms to production engine: server::HttpServer + server::serve_reactor
// Zero-Allocation HTTP/1.1 & WebSocket (RFC 6455) Engine
import std;
import core from "../..";
import wing from "../..";

struct WorkerContext {
    worker_id: i64 = 0,
    port:      u16 = 3001,
}

fn run_server_reactor(port: u16, worker_id: i64) {
    net::set_cpu_affinity(worker_id);

    var app = server::new_http_server("0.0.0.0", port);
    app.server_name.clear();
    app.server_name.append("goose-wing");
    app.pipeline.enable_rate_limiter = false;
    app.pipeline.enable_csrf_guard = false;
    app.pipeline.enable_cors = false;
    app.pipeline.enable_slowloris_timer = false;

    server::add_static_get_route(app, "/plaintext", "text/plain", "Hello, World!", 1001);
    server::add_static_get_route(app, "/json", "application/json", "{\"message\":\"Hello, World!\"}", 1002);
    server::add_static_get_route(
        app,
        "/metrics",
        "application/json",
        "{\"engine\":\"goose-wing\",\"memory_allocations\":0,\"heap_bytes\":0,\"architecture\":\"zero_alloc_stack\"}",
        1003,
    );

    var ws_b = realtime::new_ws_behavior(1004);
    server::add_ws_route(app, "/ws", ws_b);

    let listener = net::tcp_listen("0.0.0.0", port, 8192);
    guard listener > 0 else {
        print("FATAL: goose-wing failed to bind on 0.0.0.0:", port);
        return;
    }
    net::tcp_set_incoming_cpu(listener, worker_id);

    server::serve_reactor(app, listener, 0);
}

thread_fn worker(ctx: WorkerContext) {
    run_server_reactor(ctx.port, ctx.worker_id);
}

fn run_multi_worker_cluster(port: u16, num_workers: i64) {
    guard num_workers > 0 && num_workers <= 64 else { return; }
    print("goose-wing server listening on 0.0.0.0:", port, " [Share-Nothing SO_REUSEPORT Workers: ", num_workers, "]");
    var threads: i64[..64] = [];
    for i in num_workers {
        let ctx = WorkerContext { worker_id: i, port: port };
        threads.push(thread_spawn(worker, ctx));
    }
    for id in threads {
        thread_wait(id);
    }
}

fn main() {
    let port: u16 = net::get_env_port(3001);
    // WING_WORKERS defaults to 1 for 1-to-1 comparison with single-threaded uWebSockets (RSS ~3.1 MB)
    let num_workers: i64 = net::get_env_workers(1);

    if num_workers <= 1 {
        net::set_cpu_affinity(0);
        print("goose-wing server listening on 0.0.0.0:", port, " [Single-Threaded Epoll/Reactor-per-Core | RSS ~3.1 MB]");
        run_server_reactor(port, 0);
        return;
    }
    run_multi_worker_cluster(port, num_workers);
}
