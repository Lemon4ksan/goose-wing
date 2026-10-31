// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Server Pipeline Hardware Cycle Profiling Benchmark
// Measures serialized RDTSC clock cycles across each individual stage of HTTP request processing.
//
// RUN: goose build -o %t.exe %s
// RUN: %t.exe
import std;
import core from "..";
import wing from "..";

fn test_wire_req_plaintext() -> const u8[:] {
    return "GET /plaintext HTTP/1.1\r\nHost: localhost:8080\r\nUser-Agent: goose-client/1.0\r\nAccept: */*\r\nConnection: keep-alive\r\n\r\n";
}

fn test_wire_req_api() -> const u8[:] {
    return "GET /api/v1/users/42 HTTP/1.1\r\nHost: api.example.com\r\nAuthorization: Bearer 7a8b9c0d1e2f3a4b5c6d7e8f\r\nAccept: application/json\r\nUser-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)\r\nConnection: keep-alive\r\n\r\n";
}

fn test_wire_req_heavy() -> const u8[:] {
    return "POST /submit HTTP/1.1\r\nHost: service.internal:8443\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: 27\r\nUser-Agent: custom-agent/2.1.0\r\nAccept: text/html,application/xhtml+xml\r\nAccept-Encoding: gzip, deflate, br\r\nAccept-Language: en-US,en;q=0.9\r\nSec-Fetch-Mode: navigate\r\nConnection: keep-alive\r\n\r\nfield1=alpha&field2=bravo42";
}

fn setup_profiled_server() -> wing::HttpServer {
    var server = wing::new_http_server("127.0.0.1", 8080);
    server.pipeline.enable_rate_limiter = true;
    server.pipeline.limiter = wing::new_sharded_limiter(
        wing::new_gcra_quota(1000000, core::secs(1), 100000),
    );
    server.pipeline.enable_csrf_guard = false;
    server.pipeline.enable_cors = false;

    // Route 1: /plaintext
    wing::add_route(server.pipeline.router, "GET", "/plaintext", 1, 0);

    // Route 2: /api/v1/users/{id}
    wing::add_route(server.pipeline.router, "GET", "/api/v1/users/{id}", 2, 0);

    // Route 3: /submit
    wing::add_route(server.pipeline.router, "POST", "/submit", 3, 0);

    return server;
}

fn profile_isolated_stages(server: wing::HttpServer&, req_wire: const u8[:], iters: i64) {
    var req = wing::new_request("GET", "");
    var res = wing::Response { .. };
    var tracker = wing::HeaderPresenceTracker { .. };
    var params = wing::ZeroAllocParams { .. };
    var canon_url: u8[..256]  = [];
    var out_wire:  u8[..2048] = [];
    var cork = core::new_cork_buffer();

    let crlf_pos = core::fast_find_crlfcrlf(req_wire);
    let first_line_end = find(req_wire, "\r\n");
    let req_line = req_wire[..first_line_end];
    let headers_part = req_wire[(first_line_end + 2)..];

    // Warmup 1000 iterations
    for _ in 1000 {
        let _ = core::fast_find_crlfcrlf(req_wire);
    }

    // Stage 0: CRLFCRLF Framing
    for _ in iters {
        let t0 = wing::prof_rdtsc();
        let pos = core::fast_find_crlfcrlf(req_wire);
        let t1 = wing::prof_rdtsc();
        wing::prof_record(wing::PROF_STAGE_FRAMING, t1 - t0);
    }

    // Stage 1: Request Line Parse
    for _ in iters {
        wing::reset_request(req);
        let t0 = wing::prof_rdtsc();
        let ok = wing::parse_http1_request_line(req_line, req);
        let t1 = wing::prof_rdtsc();
        wing::prof_record(wing::PROF_STAGE_REQ_LINE, t1 - t0);
    }

    // Stage 2: Headers Block Tokenize & Parse
    for _ in iters {
        wing::reset_request(req);
        tracker = wing::HeaderPresenceTracker { .. };
        let t0 = wing::prof_rdtsc();
        let ok = wing::parse_http1_headers_stream(headers_part, req, tracker);
        let t1 = wing::prof_rdtsc();
        wing::prof_record(wing::PROF_STAGE_HEADERS, t1 - t0);
    }

    // Stage 3: Host Header & RFC Validation
    let host_val: const u8[:] = "localhost:8080";
    for _ in iters {
        let t0 = wing::prof_rdtsc();
        let ok = wing::validate_host_header_structure(host_val);
        let t1 = wing::prof_rdtsc();
        wing::prof_record(wing::PROF_STAGE_HOST_VAL, t1 - t0);
    }

    // Stage 4: GCRA Rate Limiter
    var now_ns: u64 = 1000000000;
    for i in iters {
        let t0 = wing::prof_rdtsc();
        let decision = wing::check_rate_limit(server.pipeline.limiter, "127.0.0.1", 1, now_ns);
        let t1 = wing::prof_rdtsc();
        wing::prof_record(wing::PROF_STAGE_PIPELINE, t1 - t0);
        now_ns += 1000;
    }

    // Stage 5: Radix Router Path Matching
    for _ in iters {
        wing::clear(params);
        canon_url.clear();
        let t0 = wing::prof_rdtsc();
        let match_res = wing::match_route(server.pipeline.router, "GET", "/plaintext", params, canon_url);
        let t1 = wing::prof_rdtsc();
        wing::prof_record(wing::PROF_STAGE_ROUTER, t1 - t0);
    }

    // Stage 6: Handler Execution & Response Setup
    for _ in iters {
        wing::reset_response(res);
        let t0 = wing::prof_rdtsc();
        res.status_code = 200;
        res.body.clear();
        res.body.append("Hello, World!");
        var hdr = wing::HeaderItem { .. };
        hdr.name.append("Content-Type");
        hdr.value.append("text/plain");
        res.headers.push(hdr);
        let t1 = wing::prof_rdtsc();
        wing::prof_record(wing::PROF_STAGE_HANDLER, t1 - t0);
    }

    // Stage 7: HTTP/1.1 Response Serialization
    for _ in iters {
        out_wire.clear();
        let t0 = wing::prof_rdtsc();
        wing::serialize_http1_response(res, "goose-wing", out_wire);
        let t1 = wing::prof_rdtsc();
        wing::prof_record(wing::PROF_STAGE_RESP_SER, t1 - t0);
    }

    // Stage 8: Output Buffer / Cork Append
    for _ in iters {
        cork.cork_reset();
        let t0 = wing::prof_rdtsc();
        cork.cork_write(out_wire[..]);
        let t1 = wing::prof_rdtsc();
        wing::prof_record(wing::PROF_STAGE_OUT_COPY, t1 - t0);
    }
}

fn profile_live_tcp_roundtrip(server: wing::HttpServer&, req_wire: const u8[:], iters: i64) {
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
    var req = wing::new_request("GET", "");
    var res = wing::Response { .. };

    for _ in iters {
        // 1. Client send
        wing::tcp_send(client, req_wire);

        // 2. Server recv syscall
        srv_buf.clear();
        let t_recv0 = wing::prof_rdtsc();
        let recvd = wing::tcp_recv(server_conn, srv_buf, 2048, 2000);
        let t_recv1 = wing::prof_rdtsc();
        wing::prof_record(wing::PROF_STAGE_SOCK_RECV, t_recv1 - t_recv0);

        // 3. Server pipeline dispatch
        resp_wire.clear();
        let now_ns: u64 = 1000000000;
        let count, _, ok, _ = wing::handle_connection_wire_pipelined_stream(
            server, "127.0.0.1", srv_buf[..recvd as i64], now_ns, resp_wire,
        );

        // 4. Server send syscall
        let t_send0 = wing::prof_rdtsc();
        wing::tcp_send(server_conn, resp_wire[..]);
        let t_send1 = wing::prof_rdtsc();
        wing::prof_record(wing::PROF_STAGE_SOCK_SEND, t_send1 - t_send0);

        // 5. Client recv drain
        cli_buf.clear();
        wing::tcp_recv(client, cli_buf, 2048, 2000);
    }

    wing::tcp_close(client);
    wing::tcp_close(server_conn);
    wing::tcp_close(listener);
}

fn main() {
    print("========================================================================\n");
    print("     Goose-Wing Server Pipeline Profiler & CPU Clock Cycle Analysis     \n");
    print("========================================================================\n");

    var server = setup_profiled_server();
    let iters: i64 = 50000;

    // 1. Plaintext GET request (5 headers)
    print("\n--- [PROFILE 1] Plaintext GET Request (50,000 samples) ---\n");
    wing::prof_reset();
    profile_isolated_stages(server, test_wire_req_plaintext(), iters);
    wing::prof_print_summary();

    // 2. Dynamic API GET request with param (/api/v1/users/42)
    print("\n--- [PROFILE 2] Parameterized JSON API Request (50,000 samples) ---\n");
    wing::prof_reset();
    profile_isolated_stages(server, test_wire_req_api(), iters);
    wing::prof_print_summary();

    // 3. Heavy POST request (10 headers + body)
    print("\n--- [PROFILE 3] Heavy 10-Header POST Request (50,000 samples) ---\n");
    wing::prof_reset();
    profile_isolated_stages(server, test_wire_req_heavy(), iters);
    wing::prof_print_summary();

    // 4. Live TCP network roundtrip (Kernel Winsock syscalls vs in-memory)
    print("\n--- [PROFILE 4] Live Loopback TCP Syscall Overhead (2,000 roundtrips) ---\n");
    wing::prof_reset();
    profile_live_tcp_roundtrip(server, test_wire_req_plaintext(), 2000);
    wing::prof_print_summary();
}
