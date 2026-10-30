// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Dedicated HTTP/2 Server for h2spec Conformance Testing (RFC 9113 & RFC 7540).
// HTTP/2 implementation in pure Goose for h2spec testing.
import std;
import core from "../..";
import wing from "../..";

fn handle_h2_session(conn: i64, initial_buf: const u8[:]) {
    var sess = internal::new_h2_server_session("goose-h2spec/1.0", 1000);
    var pipeline = wing::new_default_server_pipeline_config("127.0.0.1");
    var timer = internal::new_connection_timer(30000000000, 1000000000);
    wing::add_route(pipeline.router, "GET", "/", 100);
    wing::add_route(pipeline.router, "GET", "/ping", 101);
    wing::add_route(pipeline.router, "POST", "/ping", 102);
    wing::add_route(pipeline.router, "POST", "/echo", 202);

    var h2_in: u8[>..] = [];
    h2_in.append(initial_buf);

    var now_ms: u64 = 1000;
    while true {
        var out_wire: u8[>..] = [];
        let consumed, ok = internal::handle_h2_server_ingress(sess, pipeline, timer, "127.0.0.1", h2_in[..], now_ms, out_wire);

        if out_wire.len > 0 {
            wing::tcp_send(conn, out_wire[..]);
        }

        if !ok {
            // Protocol error or Goaway triggered
            break;
        }

        if consumed > 0 {
            var rem: u8[>..] = [];
            rem.append(h2_in[consumed..]);
            h2_in.clear();
            h2_in.append(rem[..]);
        }

        var chunk: u8[..4096] = [];
        let recvd = wing::tcp_recv(conn, chunk, 4096, 50);
        if recvd == -2 {
            // Timeout: wait for more frames
            continue;
        }
        if recvd <= 0 {
            break;
        }
        h2_in.append(chunk[..recvd]);
        now_ms += 10;
    }
}

fn main() {
    let listener = wing::tcp_listen("127.0.0.1", 0, 128);
    if listener <= 0 {
        print("ERROR_FAILED_TO_LISTEN\n");
        return;
    }
    let port = wing::tcp_getsockname_port(listener);
    print("READY_PORT:", port, "\n");

    var is_running = true;
    while is_running {
        let conn = wing::tcp_accept(listener, 200);
        if conn <= 0 {
            continue;
        }

        var in_buf: u8[>..] = [];
        while true {
            var chunk: u8[..4096] = [];
            let recvd = wing::tcp_recv(conn, chunk, 4096, 500);
            if recvd == -2 {
                continue;
            }
            if recvd <= 0 {
                break;
            }
            in_buf.append(chunk[..recvd]);

            // 1. HTTP/2 Connection Preface check
            if wing::is_partial_h2_client_preface(in_buf[..]) {
                continue;
            }
            if wing::is_h2_client_preface(in_buf[..]) {
                handle_h2_session(conn, in_buf[..]);
                break;
            }

            // If it starts with "PRI " but is not valid preface -> RFC 9113 Section 3.4: HTTP/2 Connection Preface - Invalid preface error
            if in_buf.len >= 4 && in_buf[..4] == "PRI " {
                // Terminate TCP connection immediately per RFC 9113 Section 3.4: HTTP/2 Connection Preface - Connection termination
                break;
            }

            // 2. Check for HTTP/1 shutdown or fallback
            let hdr_end = core::index_of_slice(in_buf[..], "\r\n\r\n");
            if hdr_end >= 0 {
                if core::index_of_slice(in_buf[..], "GET /shutdown") >= 0 {
                    let resp: const u8[:] = "HTTP/1.1 200 OK\r\nContent-Length: 4\r\nConnection: close\r\n\r\nBYE\n";
                    wing::tcp_send(conn, resp);
                    is_running = false;
                    break;
                }
                // Invalid HTTP/2 preface or bad request on H2 port: close connection
                break;
            }
        }

        wing::tcp_close(conn);
    }

    wing::tcp_close(listener);
}
