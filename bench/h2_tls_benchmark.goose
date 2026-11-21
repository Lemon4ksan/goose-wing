// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// HTTP/2 over TLS 1.3 End-to-End Performance Benchmark
// Measures throughput (req/s), latency distribution (p50, p90, p99),
// and process RSS memory footprint under TLS 1.3 + ALPN h2 multiplexing.
import std;
import core from "..";
import wing from "..";

fn format_ms_x100<B>(ns: i64, out: B&) {
    let clamped = max(ns, 0) as u64;
    let scaled = core::div_euclid_i64(clamped as i64, 10000) as u64;
    let whole = core::div_euclid_i64(scaled as i64, 100) as u64;
    let frac = core::rem_euclid_i64(scaled as i64, 100) as u64;
    whole.format_u64_dec(out);
    let _ = out.try_push('.');
    if frac < 10 {
        let _ = out.try_push('0');
    }
    frac.format_u64_dec(out);
}

fn build_benchmark_cert(out_der: u8[..2048]&) {
    let seed: u8[32] = [0x42; 32];
    out_der.clear();
    let ok = tls::build_test_ed25519_cert_der(
        seed,
        "localhost",
        "localhost",
        "127.0.0.1",
        out_der,
    );
    assert(ok);
}

var g_bench_app: server::HttpServer = server::HttpServer { .. };

struct UserApiStage {
    _unused: i32 = 0,
}

fn server::on_server_stage(
    _stage: UserApiStage&,
    phase:  wire::ServerHookPhase,
    cfg:    server::ServerPipelineConfig&,
    req:    const http::Request&,
    ctx:    server::ServerStageCtx&,
    res:    http::Response&,
) -> wire::StageVerdict {
    guard phase == wire::ServerHookPhase.RouteHandler && ctx.handler_id == 2001 else {
        return wire::StageVerdict.Continue;
    }
    let uid = server::route_param_or(cfg, ctx, "id", "0");
    let raw_region = http::header(req, "x-client-region");
    let region = if raw_region.len > 0 { raw_region } else { "unknown" };
    let authed = http::header(req, "authorization").len > 0;

    http::set_header(res, "content-type", "application/json");
    http::set_header(res, "x-engine", "goose-wing");
    http::set_header(res, "cache-control", "no-store");

    res.body.clear();
    res.body.append("{\"id\":");
    core::format_json_string(res.body, uid);
    res.body.append(",\"region\":");
    core::format_json_string(res.body, region);
    if authed {
        res.body.append(",\"authenticated\":true");
    } else {
        res.body.append(",\"authenticated\":false");
    }
    res.body.append(",\"engine\":\"goose-wing\",\"proto\":\"h2\"}");
    res.status_code = 200;
    return wire::StageVerdict.ShortCircuit { status_code: 200 };
}

fn run_h2_tls_server(port: u16, max_conns: i64, accel_str: const u8[:]) {
    server::init_http_server_inplace(g_bench_app, "127.0.0.1", port);
    g_bench_app.pipeline.enable_csrf_guard = false;
    g_bench_app.pipeline.enable_cors = false;
    g_bench_app.pipeline.enable_rate_limiter = false;
    g_bench_app.pipeline.enable_slowloris_timer = false;
    if accel_str == "poll" {
        g_bench_app.accel_mode = net::ReactorAccelMode.PollFallback;
    } else if accel_str == "rio" {
        g_bench_app.accel_mode = net::ReactorAccelMode.Rio;
    } else {
        g_bench_app.accel_mode = net::ReactorAccelMode.Auto;
    }

    assert(server::add_static_route(
        g_bench_app.pipeline.router,
        "GET",
        "/plaintext",
        "text/plain",
        "Hello, HTTP/2 over TLS 1.3!",
    ));
    assert(server::add_static_route(
        g_bench_app.pipeline.router,
        "GET",
        "/json",
        "application/json",
        "{\"status\":200,\"message\":\"ok\",\"engine\":\"goose-wing\",\"protocol\":\"h2\",\"tls\":\"1.3\"}",
    ));
    server::add_get_route(g_bench_app, "/api/v1/users/{id}", 2001);

    var cert_der: u8[..2048] = [];
    build_benchmark_cert(cert_der);

    var tls_cfg = tls::ServerHandshakeConfig { .. };
    assert(tls_cfg.cert_der.try_set(cert_der[..]));
    tls_cfg.priv_seed = [0x42; 32];
    assert(tls_cfg.alpn.try_set("h2,http/1.1"));

    let listener = if accel_str == "poll" {
        net::tcp_listen("127.0.0.1", port, 1024)
    } else {
        server::reactor_listen_accelerated(g_bench_app, 1024)
    };
    guard listener > 0 else {
        print("FATAL: Failed to bind listener on 127.0.0.1:", port);
        return;
    }
    print("SERVER_READY port=", port);
    var stage = UserApiStage {};
    let _ = server::serve_reactor_tls_with_stage(g_bench_app, listener, tls_cfg, stage, max_conns);
    net::tcp_close(listener);
}

fn run_h2_tls_client(port: u16, iters: i64, path: const u8[:]) {
    var cert_der: u8[..2048] = [];
    build_benchmark_cert(cert_der);

    var cfg = client::Config { timeout_ms: 10000, .. };
    var sess = client::new_session(cfg);
    defer sess.close();
    sess.ssrf_guard.enabled = false;
    sess.insecure_skip_verify = false;
    assert(tls::add_trust_anchor_cert_der(sess.trust_store, cert_der[..]));

    var url: u8[..128] = [];
    let _ = url.try_append("https://127.0.0.1:");
    port.format_u64_dec(url);
    let _ = url.try_append(path);

    let warmup = min(max(iters >> 3, 5), 50);
    for _ in warmup {
        var req = http::new_get(url[..]);
        let res, err = client::execute_request(sess, req);
        assert(http::ok(err) && res.status_code == 200);
    }

    var latencies: i64[>..] = [];
    let watch_total = core::stopwatch();
    for _ in iters {
        let t_req = core::stopwatch();
        var req = http::new_get(url[..]);
        let res, err = client::execute_request(sess, req);
        let dt_ns = core::elapsed(t_req).as_nanos();
        assert(http::ok(err) && res.status_code == 200);
        latencies.push(dt_ns);
    }
    let total_elapsed = core::elapsed(watch_total);
    let total_elapsed_ns = max(total_elapsed.as_nanos(), 1);

    sort(latencies[..]);
    let n = latencies.len;
    assert(n > 0);
    let p50_ns = latencies[(n * 50) / 100];
    let p90_ns = latencies[(n * 90) / 100];
    let p99_ns = latencies[(n * 99) / 100];
    let min_ns = latencies[0];
    let max_ns = latencies[n - 1];

    let req_per_sec = core::div_euclid_i64(
        core::mul_sat_u64(n as u64, 1000000000) as i64,
        total_elapsed_ns,
    ) as u64;

    var p50_buf: u8[..32] = [];
    var p90_buf: u8[..32] = [];
    var p99_buf: u8[..32] = [];
    var min_buf: u8[..32] = [];
    var max_buf: u8[..32] = [];
    format_ms_x100(p50_ns, p50_buf);
    format_ms_x100(p90_ns, p90_buf);
    format_ms_x100(p99_ns, p99_buf);
    format_ms_x100(min_ns, min_buf);
    format_ms_x100(max_ns, max_buf);

    print(
        "H2_TLS_RESULT requests=", n,
        " elapsed_ms=", total_elapsed.as_millis(),
        " req_per_sec=", req_per_sec,
        " p50_ms=", p50_buf[..],
        " p90_ms=", p90_buf[..],
        " p99_ms=", p99_buf[..],
        " min_ms=", min_buf[..],
        " max_ms=", max_buf[..],
    );
}

fn main() {
    let argv = args();
    var is_server = false;
    var is_client = false;
    var port:      u16         = 8443;
    var iters:     i64         = 1000;
    var max_conns: i64         = 0;
    var path:      const u8[:] = "/plaintext";
    var accel_str: const u8[:] = "auto";

    var i: u64 = 1;
    let argc = argv.len as u64;
    while i < argc {
        let arg = argv[i];
        let next_i = core::add_sat_u64(i, 1);
        if arg == "--server" {
            is_server = true;
            if next_i < argc {
                let parsed, ok = argv[next_i].parse_u32_dec();
                if ok && parsed > 0 && parsed <= 65535 {
                    port = parsed as u16;
                    i = next_i;
                }
            }
        } else if arg == "--client" {
            is_client = true;
            if next_i < argc {
                let parsed, ok = argv[next_i].parse_u32_dec();
                if ok && parsed > 0 && parsed <= 65535 {
                    port = parsed as u16;
                    i = next_i;
                }
            }
        } else if arg == "--iters" && next_i < argc {
            let parsed, ok = argv[next_i].parse_i64_dec();
            if ok && parsed > 0 {
                iters = parsed;
                i = next_i;
            }
        } else if arg == "--conns" && next_i < argc {
            let parsed, ok = argv[next_i].parse_i64_dec();
            if ok && parsed > 0 {
                max_conns = parsed;
                i = next_i;
            }
        } else if arg == "--path" && next_i < argc {
            path = argv[next_i];
            i = next_i;
        } else if arg == "--accel" && next_i < argc {
            accel_str = argv[next_i];
            i = next_i;
        }
        i = core::add_sat_u64(i, 1);
    }

    if is_server {
        run_h2_tls_server(port, max_conns, accel_str);
    } else if is_client {
        run_h2_tls_client(port, iters, path);
    } else {
        print("Usage: h2_tls_benchmark --server <port> [--conns <max_conns>] [--accel auto|rio|poll]");
        print("       h2_tls_benchmark --client <port> [--iters <N>] [--path <path>]");
    }
}
