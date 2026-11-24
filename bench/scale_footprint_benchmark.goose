// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Showcase C: Edge Footprint, Cold Start, 1,000 Live Connections,
// 10,000-Slot SoAConnTable Scaling & Zero-Heap Allocation Proof
import std;
import wing from "..";
import lit from "github.com/Lemon4ksan/goose-lit@v0.1.0";

var g_scale_app: server::HttpServer = server::HttpServer { .. };

struct ItemApiStage {
    _unused: i32 = 0,
}

fn server::on_server_stage(
    _stage: ItemApiStage&,
    phase:  wire::ServerHookPhase,
    cfg:    server::ServerPipelineConfig&,
    req:    const http::Request&,
    ctx:    server::ServerStageCtx&,
    res:    http::Response&,
) -> wire::StageVerdict {
    guard phase == wire::ServerHookPhase.RouteHandler && ctx.handler_id == 3001 else {
        return wire::StageVerdict.Continue;
    }
    let item_id = server::route_param_or(cfg, ctx, "id", "0");
    let raw_region = http::header(req, "x-client-region");
    let region = if raw_region.len > 0 { raw_region } else { "unknown" };

    http::set_header(res, "content-type", "application/json");
    http::set_header(res, "x-engine", "goose-wing");
    res.body.clear();
    res.body.append("{\"id\":");
    core::format_json_string(res.body, item_id);
    res.body.append(",\"region\":");
    core::format_json_string(res.body, region);
    res.body.append(",\"engine\":\"goose-wing\"}");
    res.status_code = 200;
    return wire::StageVerdict.ShortCircuit { status_code: 200 };
}

fn setup_scale_server(port: u16) {
    server::init_http_server_inplace(g_scale_app, "127.0.0.1", port);
    g_scale_app.pipeline.enable_csrf_guard = false;
    g_scale_app.pipeline.enable_cors = false;
    g_scale_app.pipeline.enable_rate_limiter = false;
    g_scale_app.pipeline.enable_slowloris_timer = false;
    g_scale_app.accel_mode = net::ReactorAccelMode.PollFallback;
    assert(server::add_static_route(g_scale_app.pipeline.router, "GET", "/ping", "text/plain", "PONG"));
    server::add_get_route(g_scale_app, "/api/v1/items/{id}", 3001);
}

fn run_http_server(port: u16) {
    setup_scale_server(port);
    let lfd = net::tcp_listen("127.0.0.1", port, 2048);
    guard lfd > 0 else {
        print("FATAL: listen failed on port ", port);
        return;
    }
    print("SERVER_READY port=", port);
    var stage = ItemApiStage {};
    let _ = server::serve_reactor_with_stage(g_scale_app, lfd, stage, 0);
    net::tcp_close(lfd);
}

fn run_soa_probe(port: u16, populate: bool) {
    var table = server::SoAConnTable { max_slots: 10240, .. };
    var wheel = core::TickTimerWheel { idle_timeout_sec: 15, .. };
    if populate {
        let tick = core::tick_timer_arm(wheel, 15);
        var active: i64 = 0;
        for i in 10000 {
            let fd = 1000 + i;
            let slot = server::soa_table_alloc(table, fd, tick);
            if slot >= 0 {
                server::soa_table_set_peer_ip(table, slot, "10.0.0.42");
                active += 1;
            }
        }
        assert(active == 10000 && table.count == 10000);
        var expired: i64[256] = [0; 256];
        let _ = server::soa_table_sweep_expired(table, wheel, expired[..]);
    }
    let lfd = net::tcp_listen("127.0.0.1", port, 16);
    assert(lfd > 0);
    sleep_ms(5000);
    net::tcp_close(lfd);
}

fn run_zero_alloc_proof(iters: i64) {
    setup_scale_server(8080);
    var stage = ItemApiStage {};
    var conn_timer = server_internal::new_connection_timer(30000000000, 1000000000);
    var fut = server_internal::InlineHandlerFuture { .. };
    var req = http::Request { .. };
    var res = http::Response { .. };

    var raw_http_buf: u8[..256] = [];
    let _ = raw_http_buf.try_append("GET /api/v1/items/42 HTTP/1.1\r\n");
    let _ = raw_http_buf.try_append("Host: localhost\r\n");
    let _ = raw_http_buf.try_append("X-Client-Region: eu-central-1\r\n");
    let _ = raw_http_buf.try_append("Authorization: Bearer tok42\r\n\r\n");
    let raw_http = raw_http_buf[..];

    var probe: u8[>..] = [];
    {
        let ok_w, _ = server::parse_http1_wire_request(raw_http, req);
        assert(ok_w);
        http::reset_response(res);
        let _ = server::execute_server_pipeline_with_stage(
            g_scale_app.pipeline, conn_timer, "127.0.0.1", req, 1000000, res, fut, stage,
        );
        assert(res.status_code == 200);
    }

    lit::alloc_reset();
    let mark = lit::alloc_mark(probe);

    for i in iters {
        let ok_p, _ = server::parse_http1_wire_request(raw_http, req);
        assert(ok_p);
        http::reset_response(res);
        let now_ns = ((i + 2) * 1000000) as u64;
        let _ = server::execute_server_pipeline_with_stage(
            g_scale_app.pipeline, conn_timer, "127.0.0.1", req, now_ns, res, fut, stage,
        );
        assert(res.status_code == 200);
    }

    let growth = lit::alloc_growth(probe, mark);
    let events = lit::alloc_events();
    let bytes = lit::alloc_bytes();
    let frees = lit::alloc_frees();
    assert(events == 0 && bytes == 0 && growth == 0);
    print(
        "ZERO_ALLOC_PROOF iters=", iters,
        " events=", events,
        " bytes=", bytes,
        " frees=", frees,
        " stack_growth=", growth,
    );
}

fn main() {
    let argv = args();
    var mode:  const u8[:] = "";
    var port:  u16         = 8082;
    var iters: i64         = 10000;

    var i: u64 = 1;
    let argc = argv.len as u64;
    while i < argc {
        let arg = argv[i];
        let next_i = core::add_sat_u64(i, 1);
        if arg == "--http-server" && next_i < argc {
            mode = "http-server";
            let p, ok = argv[next_i].parse_u32_dec();
            if ok && p > 0 && p <= 65535 {
                port = p as u16;
                i = next_i;
            }
        } else if arg == "--soa-idle" && next_i < argc {
            mode = "soa-idle";
            let p, ok = argv[next_i].parse_u32_dec();
            if ok && p > 0 && p <= 65535 {
                port = p as u16;
                i = next_i;
            }
        } else if arg == "--soa-10k" && next_i < argc {
            mode = "soa-10k";
            let p, ok = argv[next_i].parse_u32_dec();
            if ok && p > 0 && p <= 65535 {
                port = p as u16;
                i = next_i;
            }
        } else if arg == "--zero-alloc-proof" {
            mode = "zero-alloc-proof";
        } else if arg == "--iters" && next_i < argc {
            let v, ok = argv[next_i].parse_i64_dec();
            if ok && v > 0 {
                iters = v;
                i = next_i;
            }
        }
        i = core::add_sat_u64(i, 1);
    }

    if mode == "http-server" {
        run_http_server(port);
    } else if mode == "soa-idle" {
        run_soa_probe(port, false);
    } else if mode == "soa-10k" {
        run_soa_probe(port, true);
    } else if mode == "zero-alloc-proof" {
        run_zero_alloc_proof(iters);
    } else {
        print(
            "Usage: scale_footprint_benchmark --http-server PORT | --soa-idle PORT | ",
            "--soa-10k PORT | --zero-alloc-proof [--iters N]",
        );
    }
}
