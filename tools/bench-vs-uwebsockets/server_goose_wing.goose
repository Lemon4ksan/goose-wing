// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// goose-wing benchmark server vs uWebSockets
// Conforms to production engine: server::HttpServer + server::serve_reactor[_tls]_with_stage
// Zero-Allocation HTTP/1.1, HTTP/2 (h2c & TLS ALPN h2), Dynamic Routing & WebSocket (RFC 6455) Engine
import std;
import wing from "../..";

const USER_JSON_P1: const u8[:] = "\",\"username\":\"edge_user\",\"tier\":\"enterprise\",\"region\":\"eu-central-1\",\"waf_policy\":{\"mode\":\"enforce\",\"sqli_guard\":true,\"xss_guard\":true,\"rate_limit\":10000,\"geo_allow\":[\"DE\",\"FR\",\"NL\",\"US\",\"GB\",\"JP\",\"SG\",\"CA\"],\"bot_score_min\":30},\"permissions\":[\"edge:read\",\"edge:write\",\"routes:manage\",\"tls:terminate\",\"waf:inspect\",\"metrics:read\",\"audit:stream\",\"cache:purge\",\"origins:balance\"],\"limits\":{\"max_rps\":250000,\"max_conns\":100000,\"max_body_kb\":10240,\"burst_window_ms\":1000},";
const USER_JSON_P2: const u8[:] = "\"origins\":[{\"host\":\"10.0.1.10\",\"port\":8443,\"weight\":100,\"healthy\":true,\"rtt_us\":142},{\"host\":\"10.0.1.11\",\"port\":8443,\"weight\":100,\"healthy\":true,\"rtt_us\":158},{\"host\":\"10.0.2.10\",\"port\":8443,\"weight\":80,\"healthy\":true,\"rtt_us\":194},{\"host\":\"10.0.2.11\",\"port\":8443,\"weight\":80,\"healthy\":true,\"rtt_us\":201}],\"feature_flags\":{\"http2\":true,\"http3\":true,\"ktls\":true,\"io_uring\":true,\"early_data\":false,\"strict_host_validation\":true,\"zero_copy_static\":true,\"packed_radix_router\":true,\"swar_header_scanner\":true,\"soa_timer_wheel\":true},";
const USER_JSON_P3: const u8[:] = "\"tags\":[\"edge\",\"waf\",\"api-gateway\",\"zero-alloc\",\"tls13\",\"h2\",\"keepalive\",\"low-latency\",\"multi-worker\",\"reuseport\",\"production\",\"v2\",\"canary\",\"verified\"],\"audit_trail\":[{\"seq\":1,\"action\":\"session.verified\",\"actor\":\"gateway-01\",\"status\":\"ok\",\"cost_us\":4},{\"seq\":2,\"action\":\"waf.prefilter\",\"actor\":\"ruleset-2026\",\"status\":\"pass\",\"cost_us\":2},{\"seq\":3,\"action\":\"route.resolved\",\"actor\":\"radix-tree\",\"status\":\"hit\",\"cost_us\":1},{\"seq\":4,\"action\":\"origin.selected\",\"actor\":\"maglev-ring\",\"status\":\"ready\",\"cost_us\":1},";
const USER_JSON_P4: const u8[:] = "{\"seq\":5,\"action\":\"cache.checked\",\"actor\":\"l1-slab\",\"status\":\"bypass\",\"cost_us\":1},{\"seq\":6,\"action\":\"response.sealed\",\"actor\":\"worker-loop\",\"status\":\"sent\",\"cost_us\":2}],\"telemetry\":{\"node\":\"eu-edge-04\",\"build\":\"2026.11\",\"padding\":\"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\"}}";

struct BenchApiStage {}

inline fn server::allows_fast_l0_static(_stage: const BenchApiStage&) -> bool {
    return true;
}

fn server::on_server_stage(
    _stage: BenchApiStage&,
    phase:  wire::ServerHookPhase,
    cfg:    server::ServerPipelineConfig&,
    _req:   const http::Request&,
    sctx:   server::ServerStageCtx&,
    res:    http::Response&,
) -> wire::StageVerdict {
    guard phase == wire::ServerHookPhase.RouteHandler else {
        return wire::StageVerdict.Continue;
    }
    guard sctx.handler_id == 2001 else {
        return wire::StageVerdict.Continue;
    }
    let id_val = server::route_param_or(cfg, sctx, "id", "0");
    res.body.clear();
    res.body.append("{\"id\":\"");
    res.body.append(id_val);
    res.body.append(USER_JSON_P1);
    res.body.append(USER_JSON_P2);
    res.body.append(USER_JSON_P3);
    res.body.append(USER_JSON_P4);
    res.status_code = 200;
    http::set_header(res, "Content-Type", "application/json");
    http::set_header(res, "Cache-Control", "no-store");
    http::set_header(res, "X-Route-Match", "users-by-id");
    return wire::StageVerdict.ShortCircuit { status_code: 200 };
}

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
    server::add_static_get_route(app, "/health", "application/json", "{\"status\":\"ok\"}", 1005);
    server::add_static_get_route(app, "/v1/status", "application/json", "{\"version\":\"1.0\",\"healthy\":true}", 1006);
    server::add_static_get_route(app, "/api/v1/auth/session", "application/json", "{\"authenticated\":false}", 1007);
    server::add_static_get_route(app, "/api/v1/audit/events", "application/json", "{\"events\":[]}", 1008);
    server::add_get_route(app, "/api/v1/orgs/:org", 2002);
    server::add_get_route(app, "/api/v1/orders/:id", 2003);
    server::add_get_route(app, "/api/v1/products/:cat/:id", 2004);
    server::add_get_route(app, "/api/v1/users/:id", 2001);

    var ws_b = realtime::new_ws_behavior(1004);
    server::add_ws_route(app, "/ws", ws_b);

    let listener = net::tcp_listen("0.0.0.0", port, 8192);
    guard listener > 0 else {
        print("FATAL: goose-wing failed to bind on 0.0.0.0:", port);
        return;
    }
    net::tcp_set_incoming_cpu(listener, worker_id);

    var stage = BenchApiStage {};
    if port == 3443 {
        let seed: u8[32] = [0x42; 32];
        var cert_der: u8[..2048] = [];
        let _ = tls::build_test_ed25519_cert_der(seed, "localhost", "localhost", "127.0.0.1", cert_der);
        var tls_cfg = tls::ServerHandshakeConfig {
            priv_seed: seed,
            ..
        };
        tls_cfg.cert_der.append(cert_der[..]);
        tls_cfg.alpn.append("h2,http/1.1");
        server::serve_reactor_tls_with_stage(app, listener, tls_cfg, stage, 0);
        return;
    }
    server::serve_reactor_with_stage(app, listener, stage, 0);
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
    let port:        u16 = net::get_env_port(3001);
    let num_workers: i64 = net::get_env_workers(1);

    if num_workers <= 1 {
        net::set_cpu_affinity(0);
        print("goose-wing server listening on 0.0.0.0:", port, " [Single-Threaded Epoll/Reactor-per-Core | RSS ~3.1 MB]");
        run_server_reactor(port, 0);
        return;
    }
    run_multi_worker_cluster(port, num_workers);
}
