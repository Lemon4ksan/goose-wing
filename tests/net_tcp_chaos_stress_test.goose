// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Comprehensive E2E Chaos Stress Test using Live OS TCP Sockets.
// Operates either standalone or through an intermediate ToxiProxy.
import std;
import core from "..";
import wing from "..";

// Verifies end-to-end HTTP/1.1 request/response roundtrip with streaming wire parsing
fn test_live_h1_roundtrip(t: core::T&) {
    let listener = wing::tcp_listen("127.0.0.1", 0, 16);
    t.assert_true(listener > 0, "Listener started");
    let srv_port = wing::tcp_getsockname_port(listener);
    t.assert_true(srv_port > 0, "Got bound port");

    let client = wing::tcp_connect("127.0.0.1", srv_port, 2000);
    t.assert_true(client > 0, "Client connected");

    let server_conn = wing::tcp_accept(listener, 2000);
    t.assert_true(server_conn > 0, "Server accepted");

    // Client sends chunked request
    let req_wire: const u8[:] = "POST /upload HTTP/1.1\r\nHost: localhost\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nHELLO\r\n0\r\n\r\n";
    let sent = wing::tcp_send(client, req_wire);
    t.assert_eq(sent, req_wire.len as i32, "Sent chunked request");

    // Server reads wire and parses request
    var srv_buf: u8[..2048] = [];
    let recvd = wing::tcp_recv(server_conn, srv_buf, 2048, 2000);
    t.assert_true(recvd > 0, "Server read bytes");

    var req = wing::Request {};
    let ok_req, consumed = wing::parse_http1_wire_request(srv_buf[..], req);
    t.assert_true(ok_req, "Parsed request");
    t.assert_eq(req.method[..], "POST", "Method is POST");
    t.assert_eq(req.body[..], "HELLO", "Body unchunked to HELLO");

    // Server sends response
    let resp_wire: const u8[:] = "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nOK";
    wing::tcp_send(server_conn, resp_wire);

    // Client receives response
    var cli_buf: u8[..1024] = [];
    let cli_recvd = wing::tcp_recv(client, cli_buf, 1024, 2000);
    t.assert_true(cli_recvd > 0, "Client read response");

    var resp = wing::Response {};
    let ok_resp, _ = wing::parse_http1_wire_response(cli_buf[..], resp);
    t.assert_true(ok_resp, "Parsed response");
    t.assert_eq(resp.status_code, 200, "Status is 200");
    t.assert_eq(resp.body[..], "OK", "Body is OK");

    wing::tcp_close(client);
    wing::tcp_close(server_conn);
    wing::tcp_close(listener);
}

// Verifies server rejects malformed space-before-colon request (CVE-2019-16276)
fn test_live_h1_space_before_colon_rejected(t: core::T&) {
    let listener = wing::tcp_listen("127.0.0.1", 0, 16);
    let srv_port = wing::tcp_getsockname_port(listener);
    let client = wing::tcp_connect("127.0.0.1", srv_port, 2000);
    let server_conn = wing::tcp_accept(listener, 2000);

    // Smuggled header with space before colon
    let evil_req: const u8[:] = "GET /test HTTP/1.1\r\nHost: localhost\r\nTransfer-Encoding : chunked\r\n\r\n";
    wing::tcp_send(client, evil_req);

    var srv_buf: u8[..1024] = [];
    wing::tcp_recv(server_conn, srv_buf, 1024, 2000);

    var req = wing::Request {};
    let ok_req, _ = wing::parse_http1_wire_request(srv_buf[..], req);
    t.assert_false(ok_req, "Space before colon request MUST be rejected by wire parser");

    wing::tcp_close(client);
    wing::tcp_close(server_conn);
    wing::tcp_close(listener);
}

// Verifies server rejects conflicting Content-Length headers over live TCP
fn test_live_h1_conflicting_content_length(t: core::T&) {
    let listener = wing::tcp_listen("127.0.0.1", 0, 16);
    let srv_port = wing::tcp_getsockname_port(listener);
    let client = wing::tcp_connect("127.0.0.1", srv_port, 2000);
    let server_conn = wing::tcp_accept(listener, 2000);

    let evil_req: const u8[:] = "POST /test HTTP/1.1\r\nHost: localhost\r\nContent-Length: 5\r\nContent-Length: 6\r\n\r\nHELLO";
    wing::tcp_send(client, evil_req);

    var srv_buf: u8[..1024] = [];
    wing::tcp_recv(server_conn, srv_buf, 1024, 2000);

    var req = wing::Request {};
    let ok_req, _ = wing::parse_http1_wire_request(srv_buf[..], req);
    t.assert_false(ok_req, "Conflicting Content-Length headers MUST be rejected");

    wing::tcp_close(client);
    wing::tcp_close(server_conn);
    wing::tcp_close(listener);
}

// Verifies server detects connection reset / EOF cleanly
fn test_live_h1_abrupt_disconnect(t: core::T&) {
    let listener = wing::tcp_listen("127.0.0.1", 0, 16);
    let srv_port = wing::tcp_getsockname_port(listener);
    let client = wing::tcp_connect("127.0.0.1", srv_port, 2000);
    let server_conn = wing::tcp_accept(listener, 2000);

    // Client closes socket immediately without sending full headers
    wing::tcp_close(client);

    var srv_buf: u8[..1024] = [];
    let recvd = wing::tcp_recv(server_conn, srv_buf, 1024, 1000);
    // recvd == 0 indicates clean peer FIN, or negative on error
    t.assert_true(recvd <= 0, "Server detects disconnect/EOF cleanly");

    wing::tcp_close(server_conn);
    wing::tcp_close(listener);
}

fn main() {
    var runner = core::new_runner("Live TCP & Chaos Stress Suite", core::Verbosity.Verbose);

    core::run_case(runner, "1. Live TCP H1 Chunked Roundtrip", test_live_h1_roundtrip);
    core::run_case(runner, "2. Live TCP CVE-2019-16276 Space-Before-Colon Rejection", test_live_h1_space_before_colon_rejected);
    core::run_case(runner, "3. Live TCP Conflicting Content-Length Rejection", test_live_h1_conflicting_content_length);
    core::run_case(runner, "4. Live TCP Abrupt Disconnect / EOF Handling", test_live_h1_abrupt_disconnect);

    let ok = core::finish(runner);
    assert(ok);
}
