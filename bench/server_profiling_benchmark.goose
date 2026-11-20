// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Server Pipeline Hardware Cycle & Memory Watermark Profiling Benchmark
// Measures serialized RDTSC clock cycles, p50/p99 tail latency, and three-channel
// Goose memory watermarks across HTTP/1.1 framing and L7 pipeline stages.
//
// RUN: goose build --include shim/prof_hook.h -o %t.exe %s
// RUN: %t.exe
import std;
import core from "..";
import wing from "..";

fn wire_req_plaintext() -> const u8[:] {
    return "GET /plaintext HTTP/1.1\r\nHost: localhost:8080\r\nUser-Agent: goose-client/1.0\r\nAccept: */*\r\nConnection: keep-alive\r\n\r\n";
}

fn wire_req_api() -> const u8[:] {
    return "GET /api/v1/users/42 HTTP/1.1\r\nHost: example.com\r\nAccept: application/json\r\nUser-Agent: goose-bench/1.0\r\nConnection: keep-alive\r\n\r\n";
}

fn wire_req_gzip() -> const u8[:] {
    return "GET /metrics HTTP/1.1\r\nHost: example.com\r\nAccept-Encoding: gzip\r\nUser-Agent: goose-bench/1.0\r\nConnection: keep-alive\r\n\r\n";
}

fn setup_l0_server() -> wing::HttpServer {
    var server = wing::new_http_server("127.0.0.1", 8080);
    server.pipeline.enable_rate_limiter = false;
    server.pipeline.enable_csrf_guard = false;
    server.pipeline.enable_cors = false;
    server.pipeline.enable_slowloris_timer = false;
    let _ = wing::add_static_route(
        server.pipeline.router,
        "GET",
        "/plaintext",
        "text/plain",
        "Hello, World!",
        1001,
    );
    return server;
}

fn setup_full_pipeline_server() -> wing::HttpServer {
    var server = wing::new_http_server("127.0.0.1", 8080);
    server.pipeline.enable_rate_limiter = true;
    server.pipeline.limiter = security::new_sharded_limiter(
        security::new_gcra_quota(100000000, wing::secs(1), 10000000),
    );
    server.pipeline.enable_csrf_guard = true;
    server.pipeline.enable_cors = true;
    server.pipeline.enable_slowloris_timer = true;

    let in_mask = wire::STAGE_SRV_IN_DEFAULT_MASK | wire::STAGE_SRV_IN_CACHE_LOOKUP;
    let out_mask = wire::STAGE_SRV_OUT_CACHE_STORE
        | wire::STAGE_SRV_OUT_ETAG
        | wire::STAGE_SRV_OUT_SECURITY_HEADERS
        | wire::STAGE_SRV_OUT_METRICS;
    let _ = wing::add_route_pso(
        server.pipeline.router,
        "GET",
        "/api/v1/users/{id}",
        1002,
        in_mask,
        out_mask,
    );

    let gz_in_mask = wire::STAGE_SRV_IN_DEFAULT_MASK;
    let gz_out_mask = wire::STAGE_SRV_OUT_COMPRESS_GZIP
        | wire::STAGE_SRV_OUT_ETAG
        | wire::STAGE_SRV_OUT_SECURITY_HEADERS;
    let _ = wing::add_route_pso(
        server.pipeline.router,
        "GET",
        "/metrics",
        1003,
        gz_in_mask,
        gz_out_mask,
    );
    return server;
}

fn main() {
    var suite = wing::new_bench_suite("Goose-Wing L7 Server Stage Profiling Suite", 25);

    suite.bench("L0_Plaintext_GET") { b =>
        var server = setup_l0_server();
        let req_wire = wire_req_plaintext();
        var resp_wire: u8[..2048] = [];
        b.set_bytes(req_wire.len);
        b.reset_timer();
        for _ in b.n {
            let _, _, _, _ = wing::handle_connection_wire_pipelined_stream(
                server, "127.0.0.1", req_wire, 1000000000, resp_wire,
            );
        }
    };

    suite.bench("L0_Plaintext_GET_Memoized") { b =>
        var server = setup_l0_server();
        wing::set_header_memoization(server, true);
        let req_wire = wire_req_plaintext();
        var resp_wire: u8[..2048] = [];
        b.set_bytes(req_wire.len);
        b.reset_timer();
        for _ in b.n {
            let _, _, _, _ = wing::handle_connection_wire_pipelined_stream(
                server, "127.0.0.1", req_wire, 1000000000, resp_wire,
            );
        }
        wing::set_header_memoization(server, false);
    };

    suite.bench("Dynamic_Route_JSON_Serialize") { b =>
        var server = setup_full_pipeline_server();
        server.pipeline.enable_rate_limiter = false;
        server.pipeline.enable_csrf_guard = false;
        server.pipeline.enable_cors = false;
        server.pipeline.enable_slowloris_timer = false;
        let req_wire = wire_req_api();
        var resp_wire: u8[..2048] = [];
        b.set_bytes(req_wire.len);
        b.reset_timer();
        for _ in b.n {
            wing::cache_invalidate(server.pipeline.route_cache);
            let _, _, _, _ = wing::handle_connection_wire_pipelined_stream(
                server, "127.0.0.1", req_wire, 1000000000, resp_wire,
            );
        }
    };

    suite.bench("Full_Pipeline_Auth_Cache_Hit") { b =>
        var server = setup_full_pipeline_server();
        let req_wire = wire_req_api();
        var resp_wire: u8[..2048] = [];
        let _, _, _, _ = wing::handle_connection_wire_pipelined_stream(
            server, "127.0.0.1", req_wire, 1000000000, resp_wire,
        );
        b.set_bytes(req_wire.len);
        b.reset_timer();
        for _ in b.n {
            let _, _, _, _ = wing::handle_connection_wire_pipelined_stream(
                server, "127.0.0.1", req_wire, 1000000000, resp_wire,
            );
        }
    };

    suite.bench("Full_Pipeline_Auth_Cache_Miss") { b =>
        var server = setup_full_pipeline_server();
        let req_wire = wire_req_api();
        var resp_wire: u8[..2048] = [];
        b.set_bytes(req_wire.len);
        b.reset_timer();
        for _ in b.n {
            wing::cache_invalidate(server.pipeline.route_cache);
            let _, _, _, _ = wing::handle_connection_wire_pipelined_stream(
                server, "127.0.0.1", req_wire, 1000000000, resp_wire,
            );
        }
    };

    suite.bench("Full_Pipeline_Gzip_Compress") { b =>
        var server = setup_full_pipeline_server();
        let req_wire = wire_req_gzip();
        var resp_wire: u8[..2048] = [];
        b.set_bytes(req_wire.len);
        b.reset_timer();
        for _ in b.n {
            let _, _, _, _ = wing::handle_connection_wire_pipelined_stream(
                server, "127.0.0.1", req_wire, 1000000000, resp_wire,
            );
        }
    };

    suite.bench("HTTP1_Pipelined_16x") { b =>
        var server = setup_l0_server();
        let single_req = wire_req_plaintext();
        var batch_wire: u8[..4096] = [];
        for _ in 16 {
            batch_wire.append(single_req);
        }
        var resp_wire: u8[..8192] = [];
        b.set_bytes(batch_wire.len);
        b.report_metric(16.0, "reqs/op");
        b.reset_timer();
        for _ in b.n {
            let _, _, _, _ = wing::handle_connection_wire_pipelined_stream(
                server, "127.0.0.1", batch_wire[..], 1000000000, resp_wire,
            );
        }
    };

    suite.bench("HTTP1_Pipelined_16x_Memoized") { b =>
        var server = setup_l0_server();
        wing::set_header_memoization(server, true);
        let single_req = wire_req_plaintext();
        var batch_wire: u8[..4096] = [];
        for _ in 16 {
            batch_wire.append(single_req);
        }
        var resp_wire: u8[..8192] = [];
        b.set_bytes(batch_wire.len);
        b.report_metric(16.0, "reqs/op");
        b.reset_timer();
        for _ in b.n {
            let _, _, _, _ = wing::handle_connection_wire_pipelined_stream(
                server, "127.0.0.1", batch_wire[..], 1000000000, resp_wire,
            );
        }
        wing::set_header_memoization(server, false);
    };

    suite.bench("Live_TCP_Roundtrip") { b =>
        var server = setup_l0_server();
        let req_wire = wire_req_plaintext();
        let listener = wing::tcp_listen("127.0.0.1", 0, 16);
        guard listener > 0 else { return; }
        let srv_port = wing::tcp_getsockname_port(listener);
        guard srv_port > 0 else {
            wing::tcp_close(listener);
            return;
        }
        let client = wing::tcp_connect("127.0.0.1", srv_port, 2000);
        guard client > 0 else {
            wing::tcp_close(listener);
            return;
        }
        let server_conn = wing::tcp_accept(listener, 2000);
        guard server_conn > 0 else {
            wing::tcp_close(client);
            wing::tcp_close(listener);
            return;
        }

        var srv_buf:   u8[..2048] = [];
        var cli_buf:   u8[..2048] = [];
        var resp_wire: u8[..2048] = [];
        b.set_bytes(req_wire.len);
        b.reset_timer();

        for _ in b.n {
            let _ = wing::tcp_send(client, req_wire);

            srv_buf.clear();
            let tok_r = wing::prof_enter("net.tcp_recv");
            let recvd = wing::tcp_recv(server_conn, srv_buf, 2048, 2000);
            wing::prof_leave(tok_r);

            resp_wire.clear();
            let _, _, _, _ = wing::handle_connection_wire_pipelined_stream(
                server, "127.0.0.1", srv_buf[..max(recvd as i64, 0)], 1000000000, resp_wire,
            );

            let tok_s = wing::prof_enter("net.tcp_send");
            let _ = wing::tcp_send(server_conn, resp_wire[..]);
            wing::prof_leave(tok_s);

            cli_buf.clear();
            let _ = wing::tcp_recv(client, cli_buf, 2048, 2000);
        }

        b.stop_timer();
        wing::tcp_close(client);
        wing::tcp_close(server_conn);
        wing::tcp_close(listener);
    };

    suite.finish_suite();
}
