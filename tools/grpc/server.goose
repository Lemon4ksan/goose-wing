// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Dedicated gRPC and gRPC-Web Server for goose-wing E2E Verification.
// Implements RFC gRPC over HTTP/2, RFC 7540/9113, and gRPC-Web (binary and text).
import std;
import core from "../..";
import wing from "../..";

fn extract_protobuf_greeting_name(req_payload: const u8[:]) -> const u8[:] {
    if req_payload.len >= 2 && req_payload[0] == 0x0A {
        let p_len = req_payload[1] as i64;
        if req_payload.len >= 2 + p_len {
            return req_payload[2..(2 + p_len)];
        }
    }
    return req_payload;
}

fn handle_say_hello(
    ctx:         wing::GrpcServerContext&,
    req_payload: const u8[:],
    res_payload: u8[>..]&,
    out_status:  wing::GrpcStatusCode&,
    out_message: u8[..256]&,
) {
    let auth = wing::get_metadata(ctx, "authorization");
    if auth == "Bearer invalid-token" {
        out_status = wing::GrpcStatusCode.Unauthenticated;
        out_message.append("Invalid authorization token");
        return;
    }

    wing::add_response_metadata(ctx, "x-server-version", "wing-grpc-v2");
    wing::add_response_metadata(ctx, "x-grpc-engine", "goose-wing");

    let name_slice = extract_protobuf_greeting_name(req_payload);
    var greeting: u8[..512] = [];
    greeting.append("Hello, ");
    greeting.append(name_slice[..min(name_slice.len, 490)]);
    greeting.push('!');

    if req_payload.len >= 2 && req_payload[0] == 0x0A {
        res_payload.push(0x0A);
        res_payload.push(greeting.len as u8);
        res_payload.append(greeting[..]);
    } else {
        res_payload.append(greeting[..]);
    }

    out_status = wing::GrpcStatusCode.Ok;
}

fn grpc_test_unary_handler(
    handler_id:  u16,
    ctx:         wing::GrpcServerContext&,
    req_payload: const u8[:],
    res_payload: u8[>..]&,
    out_status:  wing::GrpcStatusCode&,
    out_message: u8[..256]&,
) {
    if handler_id == 1 {
        handle_say_hello(ctx, req_payload, res_payload, out_status, out_message);
        return;
    }
    if handler_id == 2 {
        for &m in ctx.metadata {
            let k = m.key[..];
            if core::starts_with_fold(k, "x-echo-") {
                wing::add_response_metadata(ctx, k, m.value[..]);
            }
        }
        res_payload.append(req_payload);
        out_status = wing::GrpcStatusCode.Ok;
        return;
    }
    if handler_id == 3 {
        out_status = wing::GrpcStatusCode.PermissionDenied;
        out_message.append("Access denied by goose security policy");
    }
}

fn is_http1_body_complete(in_buf: const u8[:], hdr_end: i64) -> bool {
    let _ = hdr_end;
    var tracker = wing::HeaderPresenceTracker { .. };
    var body_start: i64 = 0;
    var probe_req = wing::Request { .. };
    guard wing::parse_http1_request_headers(in_buf, probe_req, tracker, body_start) else {
        return true;
    }
    if (tracker.mask & wing::HDR_PRESENCE_CONTENT_LENGTH) != 0 {
        return in_buf.len >= body_start + tracker.parsed_cl;
    }
    return true;
}

fn serve_grpc_connection(
    conn:       i64,
    server:     wing::HttpServer&,
    dispatcher: const wing::GrpcServerDispatcher&,
    in_buf:     u8[>..]&,
    out_wire:   u8[>..]&,
) -> bool {
    in_buf.clear();
    var chunk: u8[..4096] = [];
    loop {
        chunk.clear();
        let recvd = wing::tcp_recv(conn, chunk, 4096, 500);
        if recvd == -2 {
            continue;
        }
        if recvd <= 0 {
            break;
        }
        in_buf.append(chunk[..recvd]);

        if wing::is_partial_h2_client_preface(in_buf[..]) {
            continue;
        }
        if wing::is_h2_client_preface(in_buf[..]) {
            wing::serve_grpc_h2_connection(server, dispatcher, conn, in_buf[..], grpc_test_unary_handler);
            return true;
        }

        let hdr_end = core::fast_find_crlfcrlf(in_buf[..]);
        if hdr_end >= 0 {
            if core::starts_with(in_buf[..], "GET /shutdown") {
                out_wire.clear();
                let _ = wing::handle_connection_wire(server, "127.0.0.1", in_buf[..], 0, out_wire);
                wing::tcp_send(conn, out_wire[..]);
                return false;
            }
            if is_http1_body_complete(in_buf[..], hdr_end) {
                wing::serve_grpc_web_http1(server, dispatcher, conn, in_buf[..], grpc_test_unary_handler);
                return true;
            }
        }
    }
    return true;
}

fn main() {
    let port_env = wing::get_env_port(0);
    var server = wing::new_http_server("0.0.0.0", port_env);
    let _ = server.server_name.try_set("goose-grpc-web/1.0");
    wing::add_static_get_route(server, "/shutdown", "text/plain", "BYE\n", 99);
    wing::add_post_route(server, "/helloworld.Greeter/SayHello", 1);
    wing::add_post_route(server, "/echo.EchoService/Echo", 2);
    wing::add_post_route(server, "/echo.EchoService/Fail", 3);

    var dispatcher = wing::new_grpc_server_dispatcher();
    wing::register_unary(dispatcher, "helloworld.Greeter", "SayHello", 1);
    wing::register_unary(dispatcher, "echo.EchoService", "Echo", 2);
    wing::register_unary(dispatcher, "echo.EchoService", "Fail", 3);

    let listener = wing::tcp_listen("0.0.0.0", port_env, 128);
    if listener <= 0 {
        print("ERROR_FAILED_TO_LISTEN\n");
        return;
    }
    let port = wing::tcp_getsockname_port(listener);
    print("READY_PORT:", port, "\n");

    var in_buf:   u8[>..] = [];
    var out_wire: u8[>..] = [];
    var is_running = true;
    while is_running {
        let conn = wing::tcp_accept(listener, 200);
        if conn <= 0 {
            continue;
        }
        is_running = serve_grpc_connection(conn, server, dispatcher, in_buf, out_wire);
        wing::tcp_close(conn);
    }

    wing::tcp_close(listener);
}
