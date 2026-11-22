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
    if type_is_non_empty<ReqBody>() {
        http::json(out_req, body_dto);
    }
    committed = true;
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
