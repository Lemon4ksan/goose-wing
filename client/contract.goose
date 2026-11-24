// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Shared end-to-end client/server endpoint contracts without code generation.
namespace client;

import std;
import core;
import http.request;
import http.response;
import .client;
import .stream_facade_internal;
import .session.verbs;

// Marker struct for contract endpoints without path parameters, query parameters, or bodies.
struct EmptyPart {}

// Returns `true` if struct type `T` declares at least one field.
fn type_is_non_empty<T>() -> bool {
    var has_fields = false;
    const for <Name, Acc> in fields<T> {
        has_fields = true;
    }
    return has_fields;
}

// ---- shared endpoint specification & execution -----------------------------

struct EndpointSpec<Params, Query, ReqBody, ResBody> {
    method:        u8[..16]  = "GET",
    path_template: u8[..256] = "/",
}

fn build_contract_request_head<Params, Query, ReqBody, ResBody>(
    spec:      const EndpointSpec<Params, Query, ReqBody, ResBody>&,
    base_url:  const u8[:],
    params:    const Params&,
    query_dto: const Query&,
    out_req:   http::Request&,
) -> bool {
    var committed = false;
    defer if !committed { http::reset_request(out_req); };
    http::reset_request(out_req);
    guard spec.method.len > 0 && out_req.method.try_set(spec.method[..]) else {
        return false;
    }
    let clean_base = base_url.trim_end_byte('/');
    guard out_req.url.try_append(clean_base) else { return false; }
    guard client_internal::expand_contract_path(spec.path_template[..], params, out_req.url) else {
        return false;
    }
    if type_is_non_empty<Query>() {
        guard client_internal::apply_contract_query(out_req, query_dto) else { return false; }
    }
    committed = true;
    return true;
}

// Populates `out_req` from `spec`, `base_url`, path `params`, `query_dto`, and JSON `body_dto`.
// Resets `out_req` and returns `false` on any path expansion or capacity error.
fn build_contract_request<Params, Query, ReqBody, ResBody>(
    spec:      const EndpointSpec<Params, Query, ReqBody, ResBody>&,
    base_url:  const u8[:],
    params:    const Params&,
    query_dto: const Query&,
    body_dto:  const ReqBody&,
    out_req:   http::Request&,
) -> bool {
    guard build_contract_request_head(spec, base_url, params, query_dto, out_req) else {
        return false;
    }
    if type_is_non_empty<ReqBody>() {
        http::json(out_req, body_dto);
    }
    return true;
}

// Decodes JSON response body into `ResBody` only on HTTP 2xx responses.
//
// Example:
//   res.status_code = 200, res.body = "{\"id\":1}" -> returns (ResBody { id: 1 }, Error.None)
//   res.status_code = 401, res.body = "{\"error\":\"denied\"}" -> skips decode, returns Error.None
fn decode_contract_response<ResBody>(res: const http::Response&) -> ResBody, http::Error {
    var out_body = ResBody { .. };
    if res.status_code >= 200 && res.status_code < 300 && type_is_non_empty<ResBody>() {
        let dec_err = http::json(res, out_body);
        return out_body, dec_err;
    }
    return out_body, http::Error { .. };
}

// Builds and executes a typed contract request against `c` and decodes 2xx JSON into `ResBody`.
fn call_endpoint<Params, Query, ReqBody, ResBody>(
    c:         Client&,
    spec:      const EndpointSpec<Params, Query, ReqBody, ResBody>&,
    base_url:  const u8[:],
    params:    const Params&,
    query_dto: const Query&,
    body_dto:  const ReqBody&,
) -> ResBody, http::Response, http::Error {
    var req = http::Request { .. };
    guard build_contract_request(spec, base_url, params, query_dto, body_dto, req) else {
        let err = http::make_error(400, "invalid_url", "contract request build failed", http::ErrorKind.InvalidUrl);
        return ResBody { .. }, http::Response { .. }, err;
    }
    let res, err = do(c, req);
    guard http::ok(err) else {
        return ResBody { .. }, res, err;
    }
    let out_body, dec_err = decode_contract_response<ResBody>(res);
    return out_body, res, dec_err;
}

// Trailing-block overload letting callers configure headers, Bearer auth, or timeouts before dispatch.
fn call_endpoint<Params, Query, ReqBody, ResBody, F: fn(http::Request&)>(
    c:         Client&,
    spec:      const EndpointSpec<Params, Query, ReqBody, ResBody>&,
    base_url:  const u8[:],
    params:    const Params&,
    query_dto: const Query&,
    body_dto:  const ReqBody&,
) -> ResBody, http::Response, http::Error {
    var req = http::Request { .. };
    guard build_contract_request(spec, base_url, params, query_dto, body_dto, req) else {
        let err = http::make_error(400, "invalid_url", "contract request build failed", http::ErrorKind.InvalidUrl);
        return ResBody { .. }, http::Response { .. }, err;
    }
    F(&req);
    let res, err = do(c, req);
    guard http::ok(err) else {
        return ResBody { .. }, res, err;
    }
    let out_body, dec_err = decode_contract_response<ResBody>(res);
    return out_body, res, dec_err;
}

// Executes a contract endpoint using `c.base_url` and translates non-2xx RFC 9457 problems into `http::Error`.
fn call_session<Params, Query, ReqBody, ResBody>(
    c:         Client&,
    spec:      const EndpointSpec<Params, Query, ReqBody, ResBody>&,
    params:    const Params&,
    query_dto: const Query&,
    body_dto:  const ReqBody&,
) -> ResBody, http::Response, http::Error {
    var req = http::Request { .. };
    guard build_contract_request(spec, c.base_url[..], params, query_dto, body_dto, req) else {
        let err = http::make_error(400, "invalid_url", "contract request build failed", http::ErrorKind.InvalidUrl);
        return ResBody { .. }, http::Response { .. }, err;
    }
    let res, err = do(c, req);
    let out_body, out_err = decode_json_or_problem<ResBody>(res, err);
    return out_body, res, out_err;
}

// Executes a contract endpoint with `ReqBody = EmptyPart` using `c.base_url` without passing dummy `EmptyPart {}`.
fn call_session_no_body<Params, Query, ResBody>(
    c:         Client&,
    spec:      const EndpointSpec<Params, Query, EmptyPart, ResBody>&,
    params:    const Params&,
    query_dto: const Query&,
) -> ResBody, http::Response, http::Error {
    var req = http::Request { .. };
    guard build_contract_request_head(spec, c.base_url[..], params, query_dto, req) else {
        let err = http::make_error(400, "invalid_url", "contract request build failed", http::ErrorKind.InvalidUrl);
        return ResBody { .. }, http::Response { .. }, err;
    }
    let res, err = do(c, req);
    let out_body, out_err = decode_json_or_problem<ResBody>(res, err);
    return out_body, res, out_err;
}

// Executes a contract endpoint whose `ReqBody` carries `core::Secret` fields, encoding unredacted wire JSON
// via `http::json_secret` and wiping body/rewind buffers before return.
fn call_secret<Params, Query, ReqBody, ResBody>(
    c:         Client&,
    spec:      const EndpointSpec<Params, Query, ReqBody, ResBody>&,
    params:    const Params&,
    query_dto: const Query&,
    body_dto:  const ReqBody&,
) -> ResBody, http::Response, http::Error {
    var req = http::Request { .. };
    defer http::reset_request(req);
    guard build_contract_request_head(spec, c.base_url[..], params, query_dto, req) else {
        let err = http::make_error(400, "invalid_url", "contract request build failed", http::ErrorKind.InvalidUrl);
        return ResBody { .. }, http::Response { .. }, err;
    }
    if type_is_non_empty<ReqBody>() {
        let _ = http::json_secret(req, body_dto);
    }
    let res, err = do(c, req);
    let out_body, out_err = decode_json_or_problem<ResBody>(res, err);
    return out_body, res, out_err;
}

fn invalid_contract_url_err<ResBody>() -> ResBody, http::Response, http::Error {
    let err = http::make_error(400, "invalid_url", "contract request build failed", http::ErrorKind.InvalidUrl);
    return ResBody { .. }, http::Response { .. }, err;
}

fn finish_contract_request<ResBody>(
    c:   Client&,
    req: http::Request&,
) -> ResBody, http::Response, http::Error {
    let res, err = do(c, req);
    let out_body, out_err = decode_json_or_problem<ResBody>(res, err);
    return out_body, res, out_err;
}

// Executes a parameterless GET contract endpoint over `c.base_url` with request configuration block `F`.
fn call_get<ResBody, F: fn(http::Request&)>(
    c:    Client&,
    spec: const EndpointSpec<EmptyPart, EmptyPart, EmptyPart, ResBody>&,
) -> ResBody, http::Response, http::Error {
    var req = http::Request { .. };
    let empty = EmptyPart {};
    guard build_contract_request_head(spec, c.base_url[..], empty, empty, req) else {
        return invalid_contract_url_err<ResBody>();
    }
    F(&req);
    return finish_contract_request<ResBody>(c, req);
}

// Executes a typed-query contract endpoint over `c.base_url` with request configuration block `F`.
fn call_query<Query, ResBody, F: fn(http::Request&)>(
    c:         Client&,
    spec:      const EndpointSpec<EmptyPart, Query, EmptyPart, ResBody>&,
    query_dto: const Query&,
) -> ResBody, http::Response, http::Error {
    var req = http::Request { .. };
    let empty = EmptyPart {};
    guard build_contract_request_head(spec, c.base_url[..], empty, query_dto, req) else {
        return invalid_contract_url_err<ResBody>();
    }
    F(&req);
    return finish_contract_request<ResBody>(c, req);
}

// Executes a typed-JSON-body contract endpoint over `c.base_url` with request configuration block `F`.
fn call_body<ReqBody, ResBody, F: fn(http::Request&)>(
    c:        Client&,
    spec:     const EndpointSpec<EmptyPart, EmptyPart, ReqBody, ResBody>&,
    body_dto: const ReqBody&,
) -> ResBody, http::Response, http::Error {
    var req = http::Request { .. };
    let empty = EmptyPart {};
    guard build_contract_request(spec, c.base_url[..], empty, empty, body_dto, req) else {
        return invalid_contract_url_err<ResBody>();
    }
    F(&req);
    return finish_contract_request<ResBody>(c, req);
}

// Executes a typed-JSON-body endpoint containing `core::Secret` fields with automatic request wiping.
fn call_secret_body<ReqBody, ResBody, F: fn(http::Request&)>(
    c:        Client&,
    spec:     const EndpointSpec<EmptyPart, EmptyPart, ReqBody, ResBody>&,
    body_dto: const ReqBody&,
) -> ResBody, http::Response, http::Error {
    var req = http::Request { .. };
    defer http::reset_request(req);
    let empty = EmptyPart {};
    guard build_contract_request_head(spec, c.base_url[..], empty, empty, req) else {
        return invalid_contract_url_err<ResBody>();
    }
    if type_is_non_empty<ReqBody>() {
        let _ = http::json_secret(req, body_dto);
    }
    F(&req);
    return finish_contract_request<ResBody>(c, req);
}
