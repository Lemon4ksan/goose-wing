// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Shared end-to-end client/server endpoint contracts without code generation.
namespace client;

import std;
import core from "..";
import http.request;
import http.response;
import .client;
import .internal;
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

// Builds and executes a typed contract request against `c` and decodes the JSON response into `ResBody`.
fn call_endpoint<Params, Query, ReqBody, ResBody>(
    c:         Client&,
    spec:      const EndpointSpec<Params, Query, ReqBody, ResBody>&,
    base_url:  const u8[:],
    params:    const Params&,
    query_dto: const Query&,
    body_dto:  const ReqBody&,
) -> ResBody, http::Response, http::Error {
    var out_body = ResBody { .. };
    var req = http::Request { .. };
    guard build_contract_request(spec, base_url, params, query_dto, body_dto, req) else {
        let err = http::make_error(400, "invalid_url", "contract request build failed", http::ErrorKind.InvalidUrl);
        return out_body, http::Response { .. }, err;
    }
    let res, err = do(c, req);
    if !http::ok(err) {
        return out_body, res, err;
    }
    if type_is_non_empty<ResBody>() {
        let dec_err = http::json(res, out_body);
        return out_body, res, dec_err;
    }
    return out_body, res, http::Error { .. };
}
