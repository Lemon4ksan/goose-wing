// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Shared end-to-end client/server endpoint contracts without code generation.
namespace wing;

import std;
import core from "..";
import .request;
import .response;
import .client;
import .session.exec;

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

// ---- scalar wire formatters ------------------------------------------------

fn format_bound_scalar<B>(val: i64, out: B&) -> bool {
    var tmp: u8[..32] = [];
    val.format_i64_dec(tmp);
    return out.try_append(tmp[..]);
}

fn format_bound_scalar<B>(val: u64, out: B&) -> bool {
    var tmp: u8[..32] = [];
    val.format_u64_dec(tmp);
    return out.try_append(tmp[..]);
}

fn format_bound_scalar<B>(val: i32, out: B&) -> bool {
    var tmp: u8[..32] = [];
    (val as i64).format_i64_dec(tmp);
    return out.try_append(tmp[..]);
}

fn format_bound_scalar<B>(val: u32, out: B&) -> bool {
    var tmp: u8[..32] = [];
    val.format_u32_dec(tmp);
    return out.try_append(tmp[..]);
}

fn format_bound_scalar<B>(val: bool, out: B&) -> bool {
    let lit = if val { "true" } else { "false" };
    return out.try_append(lit);
}

fn format_bound_scalar<B>(val: const u8[:], out: B&) -> bool {
    return out.try_append(val);
}

// ---- path & query contract builders ----------------------------------------

// Formats path parameter `param_name` from `params` into `out`, rejecting empty values,
// path separators (`/`), query/fragment delimiters (`?`, `#`), and control characters.
// Rolls back `out` on failure.
fn format_path_param_segment<Params, B>(
    param_name: const u8[:],
    params:     const Params&,
    out:        B&,
) -> bool {
    let saved_len = out.len;
    var committed = false;
    defer if !committed { out.resize(saved_len); };
    var seg_buf: u8[..256] = [];
    var matched = false;
    var fmt_ok = false;
    const for <Name, Acc> in fields<Params> {
        if !matched && Name == param_name {
            matched = true;
            fmt_ok = format_bound_scalar(params.Acc, seg_buf);
        }
    }
    guard matched && fmt_ok && seg_buf.len > 0 else { return false; }
    for b in seg_buf[..] {
        guard b >= 0x20 && b != 0x7F && b != '/' && b != '?' && b != '#' else { return false; }
    }
    guard out.try_append(seg_buf[..]) else { return false; }
    committed = true;
    return true;
}

// Expands `:param` placeholders in `path_template` using `params` and appends the path to `out`.
// Rolls back `out` on missing parameters, unsafe characters, or capacity overflow.
fn expand_contract_path<Params, B>(
    path_template: const u8[:],
    params:        const Params&,
    out:           B&,
) -> bool {
    let saved_len = out.len;
    var committed = false;
    defer if !committed { out.resize(saved_len); };
    guard path_template.len > 0 else { return false; }
    var idx: i64 = 0;
    while idx < path_template.len {
        let b = path_template[idx];
        if b == ':' {
            let start = core::add_sat_i64(idx, 1);
            var end = core::add_sat_i64(idx, 1);
            while end < path_template.len && path_template[end] != '/' {
                end = core::add_sat_i64(end, 1);
            }
            let param_name = path_template[start..end];
            guard param_name.len > 0 && format_path_param_segment(param_name, params, out) else {
                return false;
            }
            idx = end;
        } else {
            guard out.try_push(b) else { return false; }
            idx = core::add_sat_i64(idx, 1);
        }
    }
    committed = true;
    return true;
}

// Appends all fields of `query_dto` as query parameters on `req`.
// Rolls back `req.query_params` on capacity overflow.
fn apply_contract_query<Query>(req: Request&, query_dto: const Query&) -> bool {
    let saved_len = req.query_params.len;
    var committed = false;
    defer if !committed { req.query_params.resize(saved_len); };
    var all_ok = true;
    const for <Name, Acc> in fields<Query> {
        if all_ok {
            var val_buf: u8[..256] = [];
            let ok_q = format_bound_scalar(query_dto.Acc, val_buf) && query(req, Name, val_buf[..]);
            all_ok = all_ok && ok_q;
        }
    }
    guard all_ok else { return false; }
    committed = true;
    return true;
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
    out_req:   Request&,
) -> bool {
    var committed = false;
    defer if !committed { reset_request(out_req); };
    reset_request(out_req);
    guard spec.method.len > 0 && out_req.method.try_set(spec.method[..]) else {
        return false;
    }
    let clean_base = base_url.trim_end_byte('/');
    guard out_req.url.try_append(clean_base) else { return false; }
    guard expand_contract_path(spec.path_template[..], params, out_req.url) else {
        return false;
    }
    if type_is_non_empty<Query>() {
        guard apply_contract_query(out_req, query_dto) else { return false; }
    }
    if type_is_non_empty<ReqBody>() {
        json(out_req, body_dto);
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
) -> ResBody, Response, Error {
    var out_body = ResBody { .. };
    var req = Request { .. };
    guard build_contract_request(spec, base_url, params, query_dto, body_dto, req) else {
        let err = make_error(400, "invalid_url", "contract request build failed", ErrorKind.InvalidUrl);
        return out_body, Response { .. }, err;
    }
    let res, err = do(c, req);
    if !ok(err) {
        return out_body, res, err;
    }
    if type_is_non_empty<ResBody>() {
        let dec_err = json(res, out_body);
        return out_body, res, dec_err;
    }
    return out_body, res, Error { .. };
}
