// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Native Goose HTTP/3 & Alt-Svc E2E Verification Client.
// Exercises client::Client with RFC 7838 Alt-Svc h3 promotion, live UDP HTTP/3
// request/response framing (QPACK HEADERS + DATA), and query-string routing
// against tools/http3/server.goose.
import std;
import wing from "../..";

fn make_h3_client(port: u16, out_origin: u8[..128]&) -> client::Client {
    var base: u8[..128] = [];
    base.append("https://127.0.0.1:");
    core::format_u64_dec(port, base);

    out_origin.clear();
    out_origin.append("127.0.0.1:");
    core::format_u64_dec(port, out_origin);

    var s = client::new_client(client::Config {
        base_url:   base[..],
        timeout_ms: 3000,
        ..
    });
    s.ssrf_guard.enabled = false;
    s.enable_altsvc = true;
    s.enable_protocol_racing = true;

    var altsvc_hdr: u8[..128] = [];
    http::format_altsvc_header(altsvc_hdr, "h3", port, 86400, true);
    http::update(s.altsvc, out_origin[..], altsvc_hdr[..], 1700000000);
    return s;
}

fn run_h3_get_root(s: client::Client&, origin: const u8[:]) -> bool {
    let resp, err = client::get(s, "/");
    guard http::ok(err) && resp.status_code == 200 else { return false; }
    guard resp.protocol[..] == "HTTP/3" else { return false; }
    guard resp.body[..] == "Hello from goose-wing HTTP/3!" else { return false; }
    return http::failed_attempts(s.altsvc, origin) == 0 && !http::is_broken(s.altsvc, origin, 1700000000);
}

fn run_h3_get_query_json(s: client::Client&) -> bool {
    let resp, err = client::get(s, "/api/info?client=goose-wing&v=3");
    guard http::ok(err) && resp.status_code == 200 else { return false; }
    guard resp.protocol[..] == "HTTP/3" else { return false; }
    guard resp.header("content-type") == "application/json" else { return false; }
    return resp.body[..] == "{\"protocol\":\"h3\",\"engine\":\"goose-wing\"}";
}

fn run_h3_post_data(s: client::Client&) -> bool {
    let resp, err = client::post(s, "/echo") { req =>
        http::text(req, "NativeH3PostBody_2026");
    };
    guard http::ok(err) && resp.status_code == 200 else { return false; }
    guard resp.protocol[..] == "HTTP/3" else { return false; }
    return resp.body[..] == "H3_POST_ACK";
}

fn main() {
    let port = net::get_env_port(0);
    if port == 0 {
        print("H3_CLI_ERR: missing PORT\n");
        return;
    }
    var origin: u8[..128] = [];
    var s = make_h3_client(port, origin);

    let ok1 = run_h3_get_root(s, origin[..]);
    print(if ok1 { "H3_NATIVE_GET_ROOT: PASS\n" } else { "H3_NATIVE_GET_ROOT: FAIL\n" });

    let ok2 = run_h3_get_query_json(s);
    print(if ok2 { "H3_NATIVE_GET_QUERY: PASS\n" } else { "H3_NATIVE_GET_QUERY: FAIL\n" });

    let ok3 = run_h3_post_data(s);
    print(if ok3 { "H3_NATIVE_POST_DATA: PASS\n" } else { "H3_NATIVE_POST_DATA: FAIL\n" });
}
