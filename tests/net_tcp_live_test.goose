// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Live TCP loopback verification suite using native OS sockets
import std;
import core from "..";
import wing from "..";

fn test_tcp_loopback_echo(t: core::T&) {
    // 1. Listen on ephemeral port
    let listener = wing::tcp_listen("127.0.0.1", 0, 16);
    t.assert_true(listener > 0, "Listener socket must be created successfully");

    let port = wing::tcp_getsockname_port(listener);
    t.assert_true(port > 0, "Bound port must be non-zero ephemeral port");

    // 2. Connect client
    let client = wing::tcp_connect("127.0.0.1", port, 2000);
    t.assert_true(client > 0, "Client must connect to loopback listener");

    // 3. Accept connection on server
    let server_conn = wing::tcp_accept(listener, 2000);
    t.assert_true(server_conn > 0, "Server must accept connection");

    // 4. Send HTTP request from client
    let req_bytes: const u8[:] = "GET /status HTTP/1.1\r\nHost: localhost\r\n\r\n";
    let sent = wing::tcp_send(client, req_bytes);
    t.assert_eq(sent, req_bytes.len as i32, "Client sent all bytes");

    // 5. Server receives and parses wire request
    var srv_buf: u8[..1024] = [];
    let recvd = wing::tcp_recv(server_conn, srv_buf, 1024, 2000);
    t.assert_true(recvd > 0, "Server received request bytes");

    var req = wing::Request {};
    let ok_req, consumed = wing::parse_http1_wire_request(srv_buf[..], req);
    t.assert_true(ok_req, "Server successfully parsed HTTP/1.1 request");
    t.assert_eq(req.method[..], "GET", "Method is GET");
    t.assert_eq(req.url[..], "/status", "Path is /status");

    // 6. Server sends HTTP/1.1 200 OK response
    let resp_bytes: const u8[:] = "HTTP/1.1 200 OK\r\nContent-Length: 5\r\nConnection: close\r\n\r\nHELLO";
    let resp_sent = wing::tcp_send(server_conn, resp_bytes);
    t.assert_eq(resp_sent, resp_bytes.len as i32, "Server sent response");

    // 7. Client receives response
    var cli_buf: u8[..1024] = [];
    let cli_recvd = wing::tcp_recv(client, cli_buf, 1024, 2000);
    t.assert_true(cli_recvd > 0, "Client received response");

    var resp = wing::Response {};
    let ok_resp, resp_consumed = wing::parse_http1_wire_response(cli_buf[..], resp);
    t.assert_true(ok_resp, "Client parsed HTTP/1.1 response");
    t.assert_eq(resp.status_code, 200, "Status is 200");
    t.assert_eq(resp.body[..], "HELLO", "Body is HELLO");

    // 8. Clean socket shutdown
    wing::tcp_close(client);
    wing::tcp_close(server_conn);
    wing::tcp_close(listener);
}

fn main() {
    var runner = core::new_runner("Live TCP Loopback Suite", core::Verbosity.Verbose);
    core::run_case(runner, "1. Live TCP Loopback Request/Response Roundtrip", test_tcp_loopback_echo);
    let ok = core::finish(runner);
    assert(ok);
}
