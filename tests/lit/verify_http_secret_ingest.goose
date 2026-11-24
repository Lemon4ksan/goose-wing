// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// RUN: goose %s | %FileCheck %s
import std;
import json;
import wing from "../..";

struct SecretBodyDto {
    user:     u8[..32]               = [],
    password: core::Secret<u8[..64]> = core::Secret<u8[..64]> { .. },
}

struct FullIngestDto {
    id:           dto::Path<i64>                        = dto::Path<i64> { .. },
    limit:        dto::Query<core::Opt<i32>>            = dto::Query<core::Opt<i32>> { .. },
    x_request_id: dto::Header<core::Opt<u8[..64]>>      = dto::Header<core::Opt<u8[..64]>> { .. },
    session_id:   dto::Cookie<core::Opt<u8[..64]>>      = dto::Cookie<core::Opt<u8[..64]>> { .. },
    auth:         dto::Bearer<core::Secret<u8[..4096]>> = dto::Bearer<core::Secret<u8[..4096]>> { .. },
    ip:           dto::ClientIp                         = dto::ClientIp {},
    display_name: u8[..64]                              = [],
}

struct GetOnlyIngestDto {
    id:   dto::Path<i64>             = dto::Path<i64> { .. },
    page: dto::Query<core::Opt<i32>> = dto::Query<core::Opt<i32>> { .. },
}

fn test_secret_wrapper() {
    var dto_obj = SecretBodyDto {
        user:     "alice",
        password: core::Secret<u8[..64]> { val: "s3cr3t-pass" },
    };

    var redacted: u8[>..] = [];
    http::encode_json_struct(dto_obj, redacted);
    // CHECK: redacted={"user":"alice","password":"******"}
    print("redacted=", redacted[..], "\n");

    var wire: u8[>..] = [];
    http::encode_json_struct_unredacted(dto_obj, wire);
    // CHECK: wire={"user":"alice","password":"s3cr3t-pass"}
    print("wire=", wire[..], "\n");

    var q_out: u8[..64] = [];
    let ok_q = dto_obj.password.query_format(q_out);
    // CHECK: q=true ******
    print("q=", ok_q, " ", q_out[..], "\n");

    let eq_ok = core::ct_eq(dto_obj.password, "s3cr3t-pass");
    let eq_bad = core::ct_eq(dto_obj.password, "wrong");
    // CHECK: ct=true false
    print("ct=", eq_ok, " ", eq_bad, "\n");

    http::zeroize_struct_secrets(dto_obj);
    // CHECK: wiped_len=0
    print("wiped_len=", dto_obj.password.val.len, "\n");

    var vp = http::ValidationProblem { .. };
    var rb_dto = SecretBodyDto { .. };
    let _ok_bind = http::bind_json("{\"password\":\"secret\",\"user\":\"bob\"}", rb_dto, vp);
    var bad2 = SecretBodyDto { .. };
    let ok_bad = http::bind_json("{\"password\":\"leaked\"", bad2, vp);
    // CHECK: rb_fail=false len=0
    print("rb_fail=", ok_bad, " len=", bad2.password.val.len, "\n");

    var parsed_sec = core::Secret<u8[..8]> { .. };
    let ok_qp_ok = parsed_sec.query_parse("tok123");
    let ok_qp_ovf = parsed_sec.query_parse("too-long-token-value");
    // CHECK: qp=true false 0
    print("qp=", ok_qp_ok, " ", ok_qp_ovf, " ", parsed_sec.val.len, "\n");
}

fn test_ingest_dto() {
    var req = http::new_request("POST", "//a//users//42?tag=x");
    http::set_header(req, "Authorization", "bearer tok-secret-99");
    http::set_header(req, "X-Request-Id", "req-7");
    http::set_header(req, "Cookie", "session_id=c-42; theme=dark");
    http::raw_json(
        req,
        "{\"id\":999,\"auth\":\"spoof\",\"ip\":\"1.2.3.4\",\"display_name\":\"Alice\"}",
    );

    var params = http::ZeroAllocParams { .. };
    // canon_url is "/users/42" -> indices 7..9
    let _ = http::add_param(params, "id", 0, 0, 7, 9);

    var req_dto = FullIngestDto { .. };
    var vp = http::ValidationProblem { .. };
    let ok = http::ingest_dto(req, params, "/users/42", "10.0.0.5", req_dto, vp);
    // CHECK: ingest_ok=true id=42 opt=false hdr=true:req-7 ck=true:c-42 ip=10.0.0.5 name=Alice
    print(
        "ingest_ok=", ok,
        " id=", req_dto.id.val,
        " opt=", req_dto.limit.val.present,
        " hdr=", req_dto.x_request_id.val.present, ":", req_dto.x_request_id.val.value[..],
        " ck=", req_dto.session_id.val.present, ":", req_dto.session_id.val.value[..],
        " ip=", req_dto.ip.val[..],
        " name=", req_dto.display_name[..], "\n",
    );
    // CHECK: auth_tok=tok-secret-99
    print("auth_tok=", req_dto.auth.val.val[..], "\n");

    // GET DTO without body fields must succeed even with empty body.
    var get_req = http::new_request("GET", "/users/42?page=3");
    var get_dto = GetOnlyIngestDto { .. };
    var vp_get = http::ValidationProblem { .. };
    let ok_get = http::ingest_dto(get_req, params, "/users/42", "127.0.0.1", get_dto, vp_get);
    // CHECK: get_ok=true page=true:3
    print("get_ok=", ok_get, " page=", get_dto.page.val.present, ":", get_dto.page.val.value, "\n");

    // Negative: missing Bearer -> 401 and wipes any parsed secrets.
    var no_auth_req = http::new_request("POST", "/users/42");
    http::raw_json(no_auth_req, "{\"display_name\":\"Bob\"}");
    var dto_401 = FullIngestDto { .. };
    var vp_401 = http::ValidationProblem { .. };
    let ok_401 = http::ingest_dto(no_auth_req, params, "/users/42", "10.0.0.5", dto_401, vp_401);
    // CHECK: st401=false 401 0
    print("st401=", ok_401, " ", vp_401.problem.status, " ", dto_401.auth.val.val.len, "\n");

    // Negative: present-but-invalid optional query -> 422.
    var bad_q_req = http::new_request("GET", "/users/42?page=abc");
    var bad_q_dto = GetOnlyIngestDto { .. };
    var vp_422 = http::ValidationProblem { .. };
    let ok_422 = http::ingest_dto(bad_q_req, params, "/users/42", "127.0.0.1", bad_q_dto, vp_422);
    // CHECK: st422=false 422
    print("st422=", ok_422, " ", vp_422.problem.status, "\n");

    // Negative: malformed top-level JSON body -> 400.
    var bad_json_req = http::new_request("POST", "/users/42");
    http::set_header(bad_json_req, "Authorization", "Bearer valid-tok");
    http::raw_json(bad_json_req, "{bad");
    var dto_400 = FullIngestDto { .. };
    var vp_400 = http::ValidationProblem { .. };
    let ok_400 = http::ingest_dto(bad_json_req, params, "/users/42", "10.0.0.5", dto_400, vp_400);
    // CHECK: st400=false 400
    print("st400=", ok_400, " ", vp_400.problem.status, "\n");
}

fn main() {
    test_secret_wrapper();
    test_ingest_dto();
}
