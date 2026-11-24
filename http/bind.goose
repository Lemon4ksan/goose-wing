// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Declarative zero-allocation request binding (Query, Headers, Params, Cookies, JSON) via const for.
namespace http;

import std;
import json;
import core;
import .headers;
import .json_codec;
import .problem;
import .dto;
import .request;
import .secret;
import http.message_internal;

// ---- zero-allocation route parameter spans ---------------------------------

struct ParamSpan {
    name:      u8[..32] = [],
    key_start: u16      = 0,
    key_end:   u16      = 0,
    val_start: u16      = 0,
    val_end:   u16      = 0,
}

struct ZeroAllocParams {
    spans: ParamSpan[8] = [ParamSpan { .. }; 8],
    len:   i64          = 0,
}

fn clear(params: ZeroAllocParams&) {
    params.len = 0;
}

fn add_param(
    params:  ZeroAllocParams&,
    k_start: u16,
    k_end:   u16,
    v_start: u16,
    v_end:   u16,
) -> bool {
    guard params.len >= 0 && params.len < params.spans.len else { return false; }
    params.spans[params.len] = ParamSpan {
        name:      [],
        key_start: k_start,
        key_end:   k_end,
        val_start: v_start,
        val_end:   v_end,
    };
    params.len = core::add_sat_i64(params.len, 1);
    return true;
}

fn add_param(
    params:  ZeroAllocParams&,
    name:    const u8[:],
    k_start: u16,
    k_end:   u16,
    v_start: u16,
    v_end:   u16,
) -> bool {
    guard params.len >= 0 && params.len < params.spans.len else { return false; }
    let idx = params.len;
    guard params.spans[idx].name.try_set(name) else { return false; }
    params.spans[idx].key_start = k_start;
    params.spans[idx].key_end = k_end;
    params.spans[idx].val_start = v_start;
    params.spans[idx].val_end = v_end;
    params.len = core::add_sat_i64(params.len, 1);
    return true;
}

fn param_val(params: const ZeroAllocParams&, idx: i64, req_path: const u8[:]) -> const u8[:] {
    guard idx >= 0 && idx < params.len else { return ""; }
    let span = params.spans[idx];
    guard span.val_end <= req_path.len && span.val_start <= span.val_end else { return ""; }
    return req_path[(span.val_start as i64)..(span.val_end as i64)];
}

fn param_key(params: const ZeroAllocParams&, idx: i64, route_template: const u8[:]) -> const u8[:] {
    guard idx >= 0 && idx < params.len else { return ""; }
    let span = &params.spans[idx];
    if span.key_end <= route_template.len && span.key_start < span.key_end {
        return route_template[(span.key_start as i64)..(span.key_end as i64)];
    }
    if span.name.len > 0 {
        return span.name[..];
    }
    return "";
}

fn param_by_name(
    params:         const ZeroAllocParams&,
    name:           const u8[:],
    route_template: const u8[:],
    req_path:       const u8[:],
) -> const u8[:], bool {
    for idx in params.len {
        let k = params.param_key(idx, route_template);
        if k == name {
            return params.param_val(idx, req_path), true;
        }
    }
    return "", false;
}

fn param_by_name(
    params:   const ZeroAllocParams&,
    name:     const u8[:],
    req_path: const u8[:],
) -> const u8[:], bool {
    for idx in params.len {
        if params.spans[idx].name[..] == name {
            return params.param_val(idx, req_path), true;
        }
    }
    return "", false;
}

// Binds URL query parameters into `out` and records validation failures in `vp`.
// Rolls back `out` on any validation error.
fn bind_query<T>(
    raw_url_or_query: const u8[:],
    out:              T&,
    vp:               ValidationProblem&,
) -> bool {
    let saved = copy(out);
    var committed = false;
    defer if !committed { out = copy(saved); };
    let no_frag, _, _ = raw_url_or_query.partition_byte('#');
    let head, q_tail, has_q = no_frag.split_once_byte('?');
    let raw_q = if has_q { q_tail } else { head };
    var all_ok = true;
    const for <Name, Acc> in fields<T> {
        if !(vp.abort_early && !all_ok) {
            let ok_q = out.Acc.query_bind_field(raw_q, Name);
            let loc = ValidationLocation.Query;
            let ok_chk = check_field(vp, ok_q, loc, Name, "invalid_query_param", "missing or invalid query parameter");
            all_ok = all_ok && ok_chk;
        }
    }
    guard all_ok else { return false; }
    committed = true;
    return true;
}

// Binds HTTP headers from `headers` into `out` (mapping `snake_case` field names to `kebab-case`).
// Rolls back `out` on any validation error.
fn bind_headers<T>(
    headers: const HeaderMap&,
    out:     T&,
    vp:      ValidationProblem&,
) -> bool {
    let saved = copy(out);
    var committed = false;
    defer if !committed { out = copy(saved); };
    var all_ok = true;
    const for <Name, Acc> in fields<T> {
        if !(vp.abort_early && !all_ok) {
            var hdr_name: u8[..64] = [];
            let name_ok = http_internal::normalize_field_to_header_name(Name, hdr_name);
            let raw_val = if name_ok { get_header(headers, hdr_name[..]) } else { "" };
            let prop = if name_ok { hdr_name[..] } else { Name };
            let ok_hdr = name_ok && raw_val.len > 0 && out.Acc.query_parse(raw_val);
            let loc = ValidationLocation.Header;
            let ok_chk = check_field(vp, ok_hdr, loc, prop, "invalid_header", "missing or invalid request header");
            all_ok = all_ok && ok_chk;
        }
    }
    guard all_ok else { return false; }
    committed = true;
    return true;
}

// Binds zero-allocation router path parameters from `params` and `req_path` into `out`.
// Rolls back `out` on any validation error.
fn bind_params<T>(
    params:   const ZeroAllocParams&,
    req_path: const u8[:],
    out:      T&,
    vp:       ValidationProblem&,
) -> bool {
    let saved = copy(out);
    var committed = false;
    defer if !committed { out = copy(saved); };
    var all_ok = true;
    let limit = min(params.len, params.spans.len);
    const for <Name, Acc> in fields<T> {
        if !(vp.abort_early && !all_ok) {
            var raw_val: const u8[:] = "";
            var found = false;
            for idx in limit {
                let span = params.spans[idx];
                let s_idx = span.val_start as i64;
                let e_idx = span.val_end as i64;
                let ok_span = !found && span.name[..] == Name && s_idx >= 0 && e_idx >= s_idx && e_idx <= req_path.len;
                raw_val = if ok_span { req_path[s_idx..e_idx] } else { raw_val };
                found = found || ok_span;
            }
            let ok_p = found && out.Acc.query_parse(raw_val);
            let loc = ValidationLocation.PathParam;
            let ok_chk = check_field(vp, ok_p, loc, Name, "invalid_path_param", "missing or invalid path parameter");
            all_ok = all_ok && ok_chk;
        }
    }
    guard all_ok else { return false; }
    committed = true;
    return true;
}

// Binds cookies from a raw `Cookie` request header into `out`.
// Rolls back `out` on any validation error.
fn bind_cookies<T>(
    cookie_hdr: const u8[:],
    out:        T&,
    vp:         ValidationProblem&,
) -> bool {
    let saved = copy(out);
    var committed = false;
    defer if !committed { out = copy(saved); };
    var all_ok = true;
    const for <Name, Acc> in fields<T> {
        if !(vp.abort_early && !all_ok) {
            let raw_val, found = http_internal::find_raw_cookie_value(cookie_hdr, Name);
            let ok_c = found && out.Acc.query_parse(raw_val);
            if !check_field(vp, ok_c, ValidationLocation.Cookie, Name, "invalid_cookie", "missing or invalid cookie") {
                all_ok = false;
            }
        }
    }
    guard all_ok else { return false; }
    committed = true;
    return true;
}

// Binds a JSON object payload from `json_bytes` into `out` and records field errors in `vp`.
// Rolls back `out` on any syntax or field validation error.
fn bind_json<T>(
    json_bytes: const u8[:],
    out:        T&,
    vp:         ValidationProblem&,
) -> bool {
    let saved = copy(out);
    defer zeroize_struct_secrets(saved);
    var committed = false;
    defer if !committed {
        zeroize_struct_secrets(out);
        out = copy(saved);
    };
    if json_bytes.len == 0 {
        let _ = http_internal::record_field_error(
            vp, ValidationLocation.Body, "$", "empty JSON request body", "invalid_json",
        );
        return false;
    }
    var reader = json::reader(json_bytes);
    var all_ok = true;
    json::each_member(reader) { key =>
        if !(vp.abort_early && !all_ok) {
            if !http_internal::bind_json_member(key, reader, out, vp) {
                all_ok = false;
            }
        } else {
            json::skip(reader);
        }
    };
    if !json::finish(reader) {
        if all_ok {
            let _ = http_internal::record_field_error(
                vp, ValidationLocation.Body, "$", "malformed JSON document", "invalid_json",
            );
        }
        all_ok = false;
    }
    guard all_ok else { return false; }
    committed = true;
    return true;
}

// ---- multi-source DTO ingestion (Path, Query, Header, Cookie, Bearer, ClientIp, JSON body) ----

const INGEST_SRC_JSON_BODY: u8 = 0;
const INGEST_SRC_PATH:      u8 = 1;
const INGEST_SRC_QUERY:     u8 = 2;
const INGEST_SRC_HEADER:    u8 = 3;
const INGEST_SRC_COOKIE:    u8 = 4;
const INGEST_SRC_BEARER:    u8 = 5;
const INGEST_SRC_CLIENT_IP: u8 = 6;

const MIN_BEARER_CAP_BYTES: i64 = 4096;

// Zeroization and JSON-decode skip bridges so `zeroize_struct_secrets` and
// `bind_json_member` compile cleanly across all `dto::*` wrapper fields.
fn dto::zeroize_if_secret<T>(v: dto::Path<T>&) { http::zeroize_field_val(v.val); }
fn dto::zeroize_if_secret<T>(v: dto::Query<T>&) { http::zeroize_field_val(v.val); }
fn dto::zeroize_if_secret<T>(v: dto::Header<T>&) { http::zeroize_field_val(v.val); }
fn dto::zeroize_if_secret<T>(v: dto::Cookie<T>&) { http::zeroize_field_val(v.val); }
fn dto::zeroize_if_secret<B>(v: dto::Bearer<B>&) { http::zeroize_field_val(v.val); }
fn dto::zeroize_if_secret(_v: dto::ClientIp&) {}

fn dto::json_decode<T>(_dst: dto::Path<T>&, r: json::Reader&) { json::skip(r); }
fn dto::json_decode<T>(_dst: dto::Query<T>&, r: json::Reader&) { json::skip(r); }
fn dto::json_decode<T>(_dst: dto::Header<T>&, r: json::Reader&) { json::skip(r); }
fn dto::json_decode<T>(_dst: dto::Cookie<T>&, r: json::Reader&) { json::skip(r); }
fn dto::json_decode<B>(_dst: dto::Bearer<B>&, r: json::Reader&) { json::skip(r); }
fn dto::json_decode(_dst: dto::ClientIp&, r: json::Reader&) { json::skip(r); }

// Source-kind identification via receiver-namespace UFCS.
fn ingest_source_kind<T>(_v: const T&) -> u8 { return INGEST_SRC_JSON_BODY; }
fn field_ingest_source_kind<T>(v: const T&) -> u8 { return v.ingest_source_kind(); }
fn dto::ingest_source_kind<T>(_v: const dto::Path<T>&) -> u8 { return http::INGEST_SRC_PATH; }
fn dto::ingest_source_kind<T>(_v: const dto::Query<T>&) -> u8 { return http::INGEST_SRC_QUERY; }
fn dto::ingest_source_kind<T>(_v: const dto::Header<T>&) -> u8 { return http::INGEST_SRC_HEADER; }
fn dto::ingest_source_kind<T>(_v: const dto::Cookie<T>&) -> u8 { return http::INGEST_SRC_COOKIE; }
fn dto::ingest_source_kind<B>(_v: const dto::Bearer<B>&) -> u8 { return http::INGEST_SRC_BEARER; }
fn dto::ingest_source_kind(_v: const dto::ClientIp&) -> u8 { return http::INGEST_SRC_CLIENT_IP; }

fn has_bearer_min_cap<B>(buf: const B&) -> bool {
    return buf.cap >= MIN_BEARER_CAP_BYTES;
}

fn core::has_bearer_min_cap<B>(sec: const core::Secret<B>&) -> bool {
    return sec.val.cap >= http::MIN_BEARER_CAP_BYTES;
}

fn check_bearer_min_cap<B>(v: const B&) -> bool {
    return v.has_bearer_min_cap();
}

fn reset_optional_or_req_val<T>(_dst: T&) -> bool {
    return false;
}

fn core::reset_optional_or_req_val<T>(dst: core::Opt<T>&) -> bool {
    dst.present = false;
    dst.value = default<T>();
    return true;
}

fn core::reset_optional_or_req_val<B>(_dst: core::Secret<B>&) -> bool {
    return false;
}

fn reset_field_val<T>(dst: T&) -> bool {
    return dst.reset_optional_or_req_val();
}

fn bind_present_optional_or_req<T>(dst: T&, raw_val: const u8[:]) -> bool {
    return parse_query_field_val(dst, raw_val);
}

fn core::bind_present_optional_or_req<T>(dst: core::Opt<T>&, raw_val: const u8[:]) -> bool {
    var parsed = default<T>();
    guard http::parse_query_field_val(parsed, raw_val) else { return false; }
    dst.value = copy(parsed);
    dst.present = true;
    return true;
}

fn core::bind_present_optional_or_req<B>(dst: core::Secret<B>&, raw_val: const u8[:]) -> bool {
    return core::query_parse(dst, raw_val);
}

fn bind_present_field_val<T>(dst: T&, raw_val: const u8[:]) -> bool {
    return dst.bind_present_optional_or_req(raw_val);
}

// Default Pass-1 hook for JSON-body fields (returns `true` immediately; bound in Pass 2).
fn bind_ingest_non_body_field<T>(
    _dst:          T&,
    _name:         const u8[:],
    _req:          const Request&,
    _params:       const ZeroAllocParams&,
    _route_path:   const u8[:],
    _peer_ip:      const u8[:],
    _vp:           ValidationProblem&,
    _has_auth_err: bool&,
) -> bool {
    return true;
}

fn field_bind_non_body<T>(
    dst:          T&,
    name:         const u8[:],
    req:          const Request&,
    params:       const ZeroAllocParams&,
    route_path:   const u8[:],
    peer_ip:      const u8[:],
    vp:           ValidationProblem&,
    has_auth_err: bool&,
) -> bool {
    return dst.bind_ingest_non_body_field(name, req, params, route_path, peer_ip, vp, has_auth_err);
}

fn dto::bind_ingest_non_body_field<T>(
    dst:           dto::Path<T>&,
    name:          const u8[:],
    _req:          const http::Request&,
    params:        const http::ZeroAllocParams&,
    route_path:    const u8[:],
    _peer_ip:      const u8[:],
    vp:            http::ValidationProblem&,
    _has_auth_err: bool&,
) -> bool {
    let raw_val, found = http::param_by_name(params, name, route_path);
    let ok_p = found && http::parse_query_field_val(dst.val, raw_val);
    let loc = http::ValidationLocation.PathParam;
    return http::check_field(vp, ok_p, loc, name, "invalid_path_param", "missing or invalid path parameter");
}

fn dto::bind_ingest_non_body_field<T>(
    dst:           dto::Query<T>&,
    name:          const u8[:],
    req:           const http::Request&,
    _params:       const http::ZeroAllocParams&,
    _route_path:   const u8[:],
    _peer_ip:      const u8[:],
    vp:            http::ValidationProblem&,
    _has_auth_err: bool&,
) -> bool {
    for &item in req.query_params {
        if item.key[..] == name {
            let ok_qp = http::bind_present_field_val(dst.val, item.value[..]);
            let loc = http::ValidationLocation.Query;
            return http::check_field(vp, ok_qp, loc, name, "invalid_query_param", "missing or invalid query parameter");
        }
    }
    let raw_q = http::extract_request_query(req.url[..]);
    let ok_q = dst.val.query_bind_field(raw_q, name);
    let loc = http::ValidationLocation.Query;
    return http::check_field(vp, ok_q, loc, name, "invalid_query_param", "missing or invalid query parameter");
}

fn dto::bind_ingest_non_body_field<T>(
    dst:           dto::Header<T>&,
    name:          const u8[:],
    req:           const http::Request&,
    _params:       const http::ZeroAllocParams&,
    _route_path:   const u8[:],
    _peer_ip:      const u8[:],
    vp:            http::ValidationProblem&,
    _has_auth_err: bool&,
) -> bool {
    var hdr_name: u8[..64] = [];
    let name_ok = http_internal::normalize_field_to_header_name(name, hdr_name);
    let raw_val = if name_ok { http::get_header(req.headers, hdr_name[..]) } else { "" };
    let prop = if name_ok { hdr_name[..] } else { name };
    let ok_h = if !name_ok {
        false
    } else if raw_val.len == 0 {
        http::reset_field_val(dst.val)
    } else {
        http::bind_present_field_val(dst.val, raw_val)
    };
    let loc = http::ValidationLocation.Header;
    return http::check_field(vp, ok_h, loc, prop, "invalid_header", "missing or invalid request header");
}

fn dto::bind_ingest_non_body_field<T>(
    dst:           dto::Cookie<T>&,
    name:          const u8[:],
    req:           const http::Request&,
    _params:       const http::ZeroAllocParams&,
    _route_path:   const u8[:],
    _peer_ip:      const u8[:],
    vp:            http::ValidationProblem&,
    _has_auth_err: bool&,
) -> bool {
    let cookie_hdr = http::get_header(req.headers, "Cookie");
    let raw_val, found = http_internal::find_raw_cookie_value(cookie_hdr, name);
    let ok_c = if !found {
        http::reset_field_val(dst.val)
    } else {
        http::bind_present_field_val(dst.val, raw_val)
    };
    let loc = http::ValidationLocation.Cookie;
    return http::check_field(vp, ok_c, loc, name, "invalid_cookie", "missing or invalid cookie");
}

fn dto::bind_ingest_non_body_field<B>(
    dst:          dto::Bearer<B>&,
    _name:        const u8[:],
    req:          const http::Request&,
    _params:      const http::ZeroAllocParams&,
    _route_path:  const u8[:],
    _peer_ip:     const u8[:],
    vp:           http::ValidationProblem&,
    has_auth_err: bool&,
) -> bool {
    guard http::check_bearer_min_cap(dst.val) else {
        has_auth_err = true;
        let loc = http::ValidationLocation.Header;
        return http::check_field(vp, false, loc, "Authorization", "bearer_cap", "bearer buffer capacity < 4096");
    }
    let auth_hdr = http::get_header(req.headers, "Authorization");
    let tok, ok_tok = http_internal::extract_bearer_token(auth_hdr);
    let ok_b = ok_tok && http::parse_query_field_val(dst.val, tok);
    if !ok_b {
        has_auth_err = true;
    }
    let loc = http::ValidationLocation.Header;
    return http::check_field(vp, ok_b, loc, "Authorization", "invalid_bearer", "missing or invalid bearer token");
}

fn dto::bind_ingest_non_body_field(
    dst:           dto::ClientIp&,
    _name:         const u8[:],
    _req:          const http::Request&,
    _params:       const http::ZeroAllocParams&,
    _route_path:   const u8[:],
    peer_ip:       const u8[:],
    vp:            http::ValidationProblem&,
    _has_auth_err: bool&,
) -> bool {
    let ok_ip = peer_ip.len > 0 && dst.val.try_set(peer_ip);
    let loc = http::ValidationLocation.Header;
    return http::check_field(vp, ok_ip, loc, "peer_ip", "missing_client_ip", "missing or invalid client IP");
}

// Computes deterministic HTTP error status for failed `ingest_dto` (`401` -> `400` -> `422`).
fn resolve_ingest_error_status(vp: const ValidationProblem&, has_auth_err: bool) -> i32 {
    if has_auth_err {
        return 401;
    }
    for &e in vp.errors {
        if e.code[..] == "invalid_json" {
            return 400;
        }
    }
    return 422;
}

// Binds multi-source DTO fields (`Path`, `Query`, `Header`, `Cookie`, `Bearer`, `ClientIp`, and JSON body)
// from `req`, `params` (against canonicalized `route_path`), and `peer_ip`. Rolls back and wipes secret
// fields on any validation failure, setting `vp.problem.status` to `401`, `400`, or `422`.
//
// Example:
//   route_path = "/users/42", params has id=42, req.body = "{\"name\":\"ann\"}"
//   returns: true, out.id.val = 42, out.name = "ann"
fn ingest_dto<T>(
    req:        const Request&,
    params:     const ZeroAllocParams&,
    route_path: const u8[:],
    peer_ip:    const u8[:],
    out:        T&,
    vp:         ValidationProblem&,
) -> bool {
    let saved = copy(out);
    defer zeroize_struct_secrets(saved);
    var committed = false;
    defer if !committed {
        zeroize_struct_secrets(out);
        out = copy(saved);
    };

    var all_ok = true;
    var has_body_fields = false;
    var has_auth_err = false;
    const for <Name, Acc> in fields<T> {
        let is_body = field_ingest_source_kind(out.Acc) == INGEST_SRC_JSON_BODY;
        has_body_fields = has_body_fields || is_body;
        if !is_body && !(vp.abort_early && !all_ok) {
            let ok_f = field_bind_non_body(out.Acc, Name, req, params, route_path, peer_ip, vp, has_auth_err);
            all_ok = all_ok && ok_f;
        }
    }

    if has_body_fields && !(vp.abort_early && !all_ok) {
        let ok_b = bind_json(req.body[..], out, vp);
        all_ok = all_ok && ok_b;
    }

    guard all_ok else {
        vp.problem.status = resolve_ingest_error_status(vp, has_auth_err);
        return false;
    }

    committed = true;
    return true;
}
