// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Native Goose gRPC-over-HTTP/2 E2E Verification Client.
// Exercises wing::Client with HTTP/2 prior knowledge, LPM framing,
// custom metadata reflection, HTTP/2 trailers (grpc-status / grpc-message),
// and multi-DATA frame 32 KB payloads against tools/grpc/server.goose.
import std;
import core from "../..";
import wing from "../..";

fn make_grpc_h2_client(port: u16) -> wing::Client {
    var base: u8[..128] = [];
    base.append("http://127.0.0.1:");
    core::format_u64_dec(port, base);

    var s = wing::new_client(wing::ClientConfig {
        base_url:   base[..],
        timeout_ms: 4000,
        ..
    });
    s.ssrf_guard.enabled = false;
    s.http2_prior_knowledge = true;
    return s;
}

fn run_h2_say_hello(s: wing::Client&) -> bool {
    let resp, err = wing::post(s, "/helloworld.Greeter/SayHello") { req =>
        wing::set_header(req, "content-type", "application/grpc");
        wing::set_header(req, "te", "trailers");
        wing::encode_grpc_lpm("GooseNativeH2", req.body, false);
    };
    guard wing::ok(err) && resp.status_code == 200 && resp.protocol[..] == "HTTP/2" else {
        return false;
    }
    guard resp.header("x-server-version") == "wing-grpc-v2" else { return false; }
    guard resp.header("x-grpc-engine") == "goose-wing" else { return false; }
    guard wing::get_header(resp.trailers, "grpc-status") == "0" else { return false; }

    let msg, is_comp, _, ok_lpm = wing::decode_grpc_lpm_slice(resp.body[..], 0);
    return ok_lpm && !is_comp && msg == "Hello, GooseNativeH2!";
}

fn run_h2_metadata_echo(s: wing::Client&) -> bool {
    let resp, err = wing::post(s, "/echo.EchoService/Echo") { req =>
        wing::set_header(req, "content-type", "application/grpc");
        wing::set_header(req, "te", "trailers");
        wing::set_header(req, "x-echo-trace-id", "h2-native-trace-777");
        wing::encode_grpc_lpm("NativeH2EchoPayload", req.body, false);
    };
    guard wing::ok(err) && resp.status_code == 200 && resp.protocol[..] == "HTTP/2" else {
        return false;
    }
    guard resp.header("x-echo-trace-id") == "h2-native-trace-777" else { return false; }
    guard wing::get_header(resp.trailers, "grpc-status") == "0" else { return false; }

    let msg, _, _, ok_lpm = wing::decode_grpc_lpm_slice(resp.body[..], 0);
    return ok_lpm && msg == "NativeH2EchoPayload";
}

fn run_h2_unauthenticated(s: wing::Client&) -> bool {
    let resp, err = wing::post(s, "/helloworld.Greeter/SayHello") { req =>
        wing::set_header(req, "content-type", "application/grpc");
        wing::set_header(req, "te", "trailers");
        wing::set_header(req, "authorization", "Bearer invalid-token");
        wing::encode_grpc_lpm("Mallory", req.body, false);
    };
    guard wing::ok(err) && resp.status_code == 200 && resp.protocol[..] == "HTTP/2" else {
        return false;
    }
    var st = wing::GrpcStatusCode.Ok;
    var msg: u8[..256] = [];
    guard wing::extract_grpc_status(resp.headers, resp.trailers, st, msg) else {
        return false;
    }
    return st == wing::GrpcStatusCode.Unauthenticated && core::contains(msg[..], "Invalid authorization token");
}

fn run_h2_permission_denied(s: wing::Client&) -> bool {
    let resp, err = wing::post(s, "/echo.EchoService/Fail") { req =>
        wing::set_header(req, "content-type", "application/grpc");
        wing::set_header(req, "te", "trailers");
        wing::encode_grpc_lpm("", req.body, false);
    };
    guard wing::ok(err) && resp.status_code == 200 && resp.protocol[..] == "HTTP/2" else {
        return false;
    }
    var st = wing::GrpcStatusCode.Ok;
    var msg: u8[..256] = [];
    guard wing::extract_grpc_status(resp.headers, resp.trailers, st, msg) else {
        return false;
    }
    return st == wing::GrpcStatusCode.PermissionDenied && core::contains(msg[..], "Access denied");
}

fn run_h2_large_32kb_payload(s: wing::Client&) -> bool {
    var big_in: u8[..32768] = [];
    while big_in.len < 32768 {
        big_in.append("0123456789abcdef0123456789ABCDEF");
    }

    let resp, err = wing::post(s, "/echo.EchoService/Echo") { req =>
        wing::set_header(req, "content-type", "application/grpc");
        wing::set_header(req, "te", "trailers");
        wing::encode_grpc_lpm(big_in[..], req.body, false);
    };
    guard wing::ok(err) && resp.status_code == 200 && resp.protocol[..] == "HTTP/2" else {
        return false;
    }
    guard wing::get_header(resp.trailers, "grpc-status") == "0" else { return false; }

    let msg, _, _, ok_lpm = wing::decode_grpc_lpm_slice(resp.body[..], 0);
    return ok_lpm && msg.len == 32768 && msg == big_in[..];
}

fn main() {
    let port = wing::get_env_port(0);
    if port == 0 {
        print("GRPC_CLI_ERR: missing PORT\n");
        return;
    }
    var s = make_grpc_h2_client(port);

    let ok1 = run_h2_say_hello(s);
    print(if ok1 { "GRPC_H2_SAY_HELLO: PASS\n" } else { "GRPC_H2_SAY_HELLO: FAIL\n" });

    let ok2 = run_h2_metadata_echo(s);
    print(if ok2 { "GRPC_H2_METADATA_ECHO: PASS\n" } else { "GRPC_H2_METADATA_ECHO: FAIL\n" });

    let ok3 = run_h2_unauthenticated(s);
    print(if ok3 { "GRPC_H2_UNAUTHENTICATED: PASS\n" } else { "GRPC_H2_UNAUTHENTICATED: FAIL\n" });

    let ok4 = run_h2_permission_denied(s);
    print(if ok4 { "GRPC_H2_PERMISSION_DENIED: PASS\n" } else { "GRPC_H2_PERMISSION_DENIED: FAIL\n" });

    let ok5 = run_h2_large_32kb_payload(s);
    print(if ok5 { "GRPC_H2_LARGE_32KB: PASS\n" } else { "GRPC_H2_LARGE_32KB: FAIL\n" });
}
