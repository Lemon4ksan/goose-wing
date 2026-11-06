// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Dedicated gRPC and gRPC-Web Server for goose-wing E2E Verification.
// Implements RFC gRPC over HTTP/2, RFC 7540/9113, and gRPC-Web (binary and text).
import std;
import core from "../..";
import wing from "../..";

fn handle_say_hello(
    ctx:         wing::GrpcServerContext&,
    req_payload: const u8[:],
    res_payload: u8[>..]&,
) -> wing::GrpcStatus {
    let auth = wing::get_metadata(ctx, "authorization");
    if auth == "Bearer invalid-token" {
        return wing::grpc_error(wing::GrpcStatusCode.Unauthenticated, "Invalid authorization token");
    }

    wing::add_response_metadata(ctx, "x-server-version", "wing-grpc-v2");
    wing::add_response_metadata(ctx, "x-grpc-engine", "goose-wing");

    let pb_name, is_pb = wing::pb_read_bytes_field(req_payload, 1);
    let name_slice = if is_pb { pb_name } else { req_payload };
    var greeting: u8[..512] = [];
    greeting.append("Hello, ");
    greeting.append(name_slice[..min(name_slice.len, 490)]);
    greeting.push('!');

    if is_pb {
        var pb_out: u8[..540] = [];
        let _ = wing::pb_write_bytes_field(1, greeting[..], pb_out);
        res_payload.append(pb_out[..]);
    } else {
        res_payload.append(greeting[..]);
    }

    return wing::grpc_ok();
}

fn grpc_test_unary_handler(
    handler_id:  u16,
    ctx:         wing::GrpcServerContext&,
    req_payload: const u8[:],
    res_payload: u8[>..]&,
) -> wing::GrpcStatus {
    if handler_id == 1 {
        return handle_say_hello(ctx, req_payload, res_payload);
    }
    if handler_id == 2 {
        for &m in ctx.metadata {
            let k = m.key[..];
            if core::starts_with_fold(k, "x-echo-") {
                wing::add_response_metadata(ctx, k, m.value[..]);
            }
        }
        res_payload.append(req_payload);
        return wing::grpc_ok();
    }
    return wing::grpc_error(wing::GrpcStatusCode.PermissionDenied, "Access denied by goose security policy");
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

    wing::serve_grpc_listener(listener, server, dispatcher, grpc_test_unary_handler);
    wing::tcp_close(listener);
}
