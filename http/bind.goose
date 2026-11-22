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
import http.internal;

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
    var committed = false;
    defer if !committed { out = copy(saved); };
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
