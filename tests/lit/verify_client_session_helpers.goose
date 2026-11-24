// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// RUN: goose %s | %FileCheck %s
import std;
import wing from "../..";

struct LoginReq {
    username: u8[..32]               = [],
    password: core::Secret<u8[..64]> = core::Secret<u8[..64]> { .. },
}

struct LoginRes {
    token: u8[..64] = [],
}

struct ItemIdParam {
    id: i64 = 0,
}

struct ItemOut {
    id:   i64      = 0,
    name: u8[..32] = [],
}

fn main() {
    // 1. http::Request mutators (`basic_auth`, `accept_json`, `bytes`, `json_secret` + `reset_request`).
    var r = http::new_request("POST", "/login");
    let ok_ba = http::basic_auth(r, "alice", "p@ss");
    let ok_acc = http::accept_json(r);
    let auth_hdr = http::header(r, "Authorization");
    // CHECK: req_hdrs=true true Basic YWxpY2U6cEBzcw== application/json
    print("req_hdrs=", ok_ba, " ", ok_acc, " ", auth_hdr, " ", http::header(r, "Accept"), "\n");

    let ok_b = http::bytes(r, "bin-data", "application/custom");
    // CHECK: req_bytes=true bin-data false
    print("req_bytes=", ok_b, " ", r.body[..], " ", r.is_secret_body, "\n");

    let login_in = LoginReq {
        username: "alice",
        password: core::Secret<u8[..64]> { val: "hunter2" },
    };
    let ok_sec = http::json_secret(r, login_in);
    // CHECK: sec_req=true true false {"username":"alice","password":"hunter2"}
    print("sec_req=", ok_sec, " ", r.is_secret_body, " ", r.rewindable, " ", r.body[..], "\n");

    http::reset_request(r);
    // CHECK: sec_reset=false 0 0
    print("sec_reset=", r.is_secret_body, " ", r.body.len, " ", r.rewind_buf.len, "\n");

    // 2. Origin-scoped Bearer auth + relative URL circuit breaker + HAR suppression on secret body.
    var c = client::new_client("https://api.example.com");
    c.enable_har_telemetry = true;
    let _ = client::add_app_logging(c, client::LogLevel.Body);
    let scoped_ok = client::set_base_url_bearer_auth(c, "tok-origin-1");
    let _ = client::mock_route(c, "GET", "https://api.example.com/v1/echo", 200, "{\"ok\":1}");
    let _ = client::mock_route(c, "GET", "https://other.evil.com/leak", 200, "{\"ok\":2}");
    let _ = client::mock_route(c, "GET", "https://api.example.com/v1/limit", 429, "{}");
    client::add_mock_header(c, "Retry-After", "120");

    let r_same, err_same = c.get("/v1/echo");
    let _ = err_same;
    let same_sent = http::get_header(r_same.sent_headers, "Authorization");
    let r_other, err_other = c.get("https://other.evil.com/leak");
    let _ = err_other;
    let other_sent = http::get_header(r_other.sent_headers, "Authorization");
    // CHECK: scoped=true Bearer tok-origin-1 empty=true
    print("scoped=", scoped_ok, " ", same_sent, " empty=", other_sent.len == 0, "\n");

    // Relative URL 429 Retry-After trips host circuit breaker for base_url host.
    let r_lim, _ = c.get("/v1/limit");
    let r_cb, err_cb = c.get("/v1/echo");
    // CHECK: cb=429 503 circuit_breaker
    print("cb=", r_lim.status_code, " ", r_cb.status_code, " ", err_cb.stage[..], "\n");

    // Secret request omits body size log and skips HAR update.
    c.last_har_json = "untouched";
    client::clear_pipeline_logs(c);
    var c_sec = client::new_client("https://auth.example.com");
    c_sec.enable_har_telemetry = true;
    let _ = c_sec.last_har_json.try_set("untouched");
    let _ = client::add_app_logging(c_sec, client::LogLevel.Body);
    let _ = client::mock_route(c_sec, "POST", "https://auth.example.com/login", 200, "{\"token\":\"jwt-9\"}");
    let login_spec = client::EndpointSpec<client::EmptyPart, client::EmptyPart, LoginReq, LoginRes> {
        method:        "POST",
        path_template: "/login",
    };
    let empty = client::EmptyPart {};
    let l_res, l_raw, l_err = client::call_secret(c_sec, login_spec, empty, empty, login_in);
    let _ = l_raw;
    var has_body_log = false;
    for &entry in c_sec.pipeline.log_entries {
        if core::contains(entry[..], "--> (body") {
            has_body_log = true;
        }
    }
    // CHECK: call_sec=true jwt-9 har=untouched body_log=false
    print(
        "call_sec=", http::ok(l_err),
        " ", l_res.token[..],
        " har=", c_sec.last_har_json[..],
        " body_log=", has_body_log, "\n",
    );

    // 3. SSRF toggle, zeroize_auth, and call_session / call_session_no_body.
    client::set_allow_loopback_ssrf(c_sec, true);
    // CHECK: ssrf=true false
    print("ssrf=", c_sec.allow_loopback_ssrf, " ", c_sec.ssrf_guard.deny_local_network, "\n");

    let _ = c_sec.set_proxy("http://proxy.local:8080");
    let _ = c_sec.sig_private_key.try_set("secret-key-bytes");
    let _ = c_sec.set_base_url_bearer_auth("secret-bearer");
    client::default_header(c_sec, "X-API-Key", "k-123");
    client::zeroize_auth(c_sec);
    // CHECK: wiped=0 0 0 0 0
    print(
        "wiped=", c_sec.pipeline.bearer_token.len,
        " ", c_sec.sig_private_key.len,
        " ", c_sec.proxy_url.len,
        " ", c_sec.pipeline.active_mask & client::INTERCEPTOR_APP_AUTH_BEARER,
        " ", http::get_header(c_sec.default_headers, "X-API-Key").len, "\n",
    );

    var c_api = client::new_client("https://items.example.com");
    let _ = client::mock_route(c_api, "GET", "https://items.example.com/items/5", 200, "{\"id\":5,\"name\":\"pen\"}");
    let _ = client::mock_route(c_api, "POST", "https://items.example.com/items/5/ping", 204, "");
    let get_item_spec = client::EndpointSpec<ItemIdParam, client::EmptyPart, client::EmptyPart, ItemOut> {
        method:        "GET",
        path_template: "/items/:id",
    };
    let ping_spec = client::EndpointSpec<ItemIdParam, client::EmptyPart, client::EmptyPart, ItemOut> {
        method:        "POST",
        path_template: "/items/:id/ping",
    };
    let item_p = ItemIdParam { id: 5 };
    let item, _, item_err = client::call_session_no_body(c_api, get_item_spec, item_p, empty);
    let _, ping_raw, ping_err = client::call_session(c_api, ping_spec, item_p, empty, empty);
    // CHECK: contract=true 5:pen 204:true
    print(
        "contract=", http::ok(item_err),
        " ", item.id, ":", item.name[..],
        " ", ping_raw.status_code, ":", http::ok(ping_err), "\n",
    );

    let get_only_spec = client::EndpointSpec<client::EmptyPart, client::EmptyPart, client::EmptyPart, ItemOut> {
        method:        "GET",
        path_template: "/items/1",
    };
    let q_only_spec = client::EndpointSpec<client::EmptyPart, ItemIdParam, client::EmptyPart, ItemOut> {
        method:        "GET",
        path_template: "/search",
    };
    let body_only_spec = client::EndpointSpec<client::EmptyPart, client::EmptyPart, ItemIdParam, ItemOut> {
        method:        "POST",
        path_template: "/items",
    };
    let _ = client::mock_route(c_api, "GET", "https://items.example.com/items/1", 200, "{\"id\":1,\"name\":\"one\"}");
    let _ = client::mock_route(c_api, "GET", "https://items.example.com/search?id=9", 200, "{\"id\":9,\"name\":\"nine\"}");
    let _ = client::mock_route(c_api, "POST", "https://items.example.com/items", 200, "{\"id\":2,\"name\":\"two\"}");
    let cg_out, _, cg_err = client::call_get(c_api, get_only_spec) { req => http::accept_json(req); };
    let item9 = ItemIdParam { id: 9 };
    let cq_out, _, cq_err = client::call_query(c_api, q_only_spec, item9) { req => http::accept_json(req); };
    let cb_out, _, cb_err = client::call_body(c_api, body_only_spec, item_p) { req => http::accept_json(req); };
    let cs_out, _, cs_err = client::call_secret_body(c_sec, login_spec, login_in) { req => http::accept_json(req); };
    // CHECK: sugar_calls=true 1 true 9 true 2 true jwt-9
    print(
        "sugar_calls=", http::ok(cg_err), " ", cg_out.id,
        " ", http::ok(cq_err), " ", cq_out.id,
        " ", http::ok(cb_err), " ", cb_out.id,
        " ", http::ok(cs_err), " ", cs_out.token[..], "\n",
    );

    // 4. Long 512-byte RFC 9457 ProblemDetails truncation without panic.
    var long_detail: u8[..512] = [];
    for _i in 400 {
        let _ = long_detail.try_push('a');
    }
    var prob_res = http::Response { status_code: 422, .. };
    http::respond_problem(prob_res, 422, "Validation Failed Long Title Exceeding SixtyFour Bytes For Stage", long_detail[..]);
    let no_err = http::Error { .. };
    let _, prob_err = client::decode_json_or_problem<ItemOut>(prob_res, no_err);
    // CHECK: prob=false 422 true true
    print(
        "prob=", http::ok(prob_err),
        " ", prob_err.code,
        " ", prob_err.stage.len <= 64 && prob_err.stage.len > 0,
        " ", prob_err.message.len == 256, "\n",
    );
}
