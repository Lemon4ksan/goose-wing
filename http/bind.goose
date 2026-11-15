// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Declarative zero-allocation request binding (Query, Headers, Params, Cookies, JSON) via const for.
namespace wing;

import std;
import json;
import core from "..";
import .headers;
import .problem;

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

// ---- scalar text parsers ---------------------------------------------------

// Parses a signed 64-bit decimal integer from `raw` into `dst`.
//
// Example:
//   raw = "-42"
//   returns: true, dst = -42
fn parse_bound_scalar(raw: const u8[:], dst: i64&) -> bool {
    let val, ok = raw.parse_i64_dec();
    guard ok else { return false; }
    dst = val;
    return true;
}

// Parses an unsigned 64-bit decimal integer from `raw` into `dst`.
//
// Example:
//   raw = "1024"
//   returns: true, dst = 1024
fn parse_bound_scalar(raw: const u8[:], dst: u64&) -> bool {
    let val, ok = raw.parse_u64_dec();
    guard ok else { return false; }
    dst = val;
    return true;
}

// Parses a signed 32-bit decimal integer from `raw` into `dst`.
//
// Example:
//   raw = "200"
//   returns: true, dst = 200
fn parse_bound_scalar(raw: const u8[:], dst: i32&) -> bool {
    let val, ok = raw.parse_i32_dec();
    guard ok else { return false; }
    dst = val;
    return true;
}

// Parses an unsigned 32-bit decimal integer from `raw` into `dst`.
//
// Example:
//   raw = "8080"
//   returns: true, dst = 8080
fn parse_bound_scalar(raw: const u8[:], dst: u32&) -> bool {
    let val, ok = raw.parse_u32_dec();
    guard ok else { return false; }
    dst = val;
    return true;
}

// Parses a boolean literal (`true`, `false`, `1`, `0`) from `raw` into `dst`.
//
// Example:
//   raw = "true"
//   returns: true, dst = true
fn parse_bound_scalar(raw: const u8[:], dst: bool&) -> bool {
    if raw.eq_ascii_fold("true") || raw == "1" {
        dst = true;
        return true;
    }
    if raw.eq_ascii_fold("false") || raw == "0" {
        dst = false;
        return true;
    }
    return false;
}

// Copies `raw` into bounded byte buffer `dst`, failing if `raw.len > dst.cap`.
//
// Example:
//   raw = "alice"
//   returns: true, dst = "alice"
fn parse_bound_scalar<B>(raw: const u8[:], dst: B&) -> bool {
    return dst.try_set(raw);
}

// ---- header & cookie wire helpers ------------------------------------------

// Converts a `snake_case` struct field name into a lowercase hyphenated HTTP header name.
// Rolls back `out` on capacity overflow.
//
// Example:
//   field_name = "x_request_id"
//   returns: true, out = "x-request-id"
fn normalize_field_to_header_name<B>(field_name: const u8[:], out: B&) -> bool {
    let saved_len = out.len;
    var committed = false;
    defer if !committed { out.resize(saved_len); };
    out.clear();
    guard field_name.len > 0 else { return false; }
    for b in field_name {
        let lower_b: u8 = if b >= 'A' && b <= 'Z' { b | 0x20 } else { b };
        let mapped:  u8 = if b == '_' { '-' } else { lower_b };
        guard out.try_push(mapped) else { return false; }
    }
    committed = true;
    return true;
}

// Extracts the raw value of cookie `target_name` from an RFC 6265 `Cookie` request header.
// Strips optional surrounding double quotes.
//
// Example:
//   cookie_hdr = "theme=dark; sid=\"abc123\"", target_name = "sid"
//   returns: "abc123", true
fn find_raw_cookie_value(
    cookie_hdr:  const u8[:],
    target_name: const u8[:],
) -> const u8[:], bool {
    guard cookie_hdr.len > 0 && target_name.len > 0 else { return "", false; }
    var tok = core::make_byte_tokenizer(cookie_hdr, ';');
    while true {
        let seg, ok = core::token_next(tok);
        if !ok { break; }
        let k, v, has_eq = seg.trim_lws().split_once_byte('=');
        if has_eq && k.trim_lws() == target_name {
            return v.trim_lws().trim_byte('"'), true;
        }
    }
    return "", false;
}

// ---- JSON field readers ----------------------------------------------------

fn read_bound_json_field(reader: json::Reader&, dst: i64&) -> bool {
    let c = json::peek(reader);
    guard (c >= '0' && c <= '9') || c == '-' else {
        json::fail(reader, "expected integer");
        return false;
    }
    dst = json::read_int(reader);
    return true;
}

fn read_bound_json_field(reader: json::Reader&, dst: u64&) -> bool {
    let c = json::peek(reader);
    guard c >= '0' && c <= '9' else {
        json::fail(reader, "expected unsigned integer");
        return false;
    }
    let val = json::read_int(reader);
    guard val >= 0 else {
        json::fail(reader, "negative unsigned integer");
        return false;
    }
    dst = val as u64;
    return true;
}

fn read_bound_json_field(reader: json::Reader&, dst: i32&) -> bool {
    let c = json::peek(reader);
    guard (c >= '0' && c <= '9') || c == '-' else {
        json::fail(reader, "expected i32");
        return false;
    }
    let val = json::read_int(reader);
    guard val >= -2147483648 && val <= 2147483647 else {
        json::fail(reader, "i32 out of range");
        return false;
    }
    dst = val as i32;
    return true;
}

fn read_bound_json_field(reader: json::Reader&, dst: f64&) -> bool {
    let c = json::peek(reader);
    guard (c >= '0' && c <= '9') || c == '-' else {
        json::fail(reader, "expected number");
        return false;
    }
    dst = json::read_number(reader);
    return true;
}

fn read_bound_json_field(reader: json::Reader&, dst: bool&) -> bool {
    let c = json::peek(reader);
    guard c == 't' || c == 'f' else {
        json::fail(reader, "expected boolean");
        return false;
    }
    dst = json::read_bool(reader);
    return true;
}

fn read_bound_json_field<B>(reader: json::Reader&, dst: B&) -> bool {
    guard core::read_json_string_into(reader, dst) else {
        json::fail(reader, "invalid or oversize string");
        return false;
    }
    return true;
}

// Dispatches a single JSON object key to the matching field in `out` via `const for`.
fn bind_json_member<T>(
    key:    const u8[:],
    reader: json::Reader&,
    out:    T&,
    vp:     ValidationProblem&,
) -> bool {
    var matched = false;
    var field_ok = true;
    const for <Name, Acc> in fields<T> {
        if !matched && key == Name {
            matched = true;
            let ok_read = read_bound_json_field(reader, out.Acc);
            let loc = ValidationLocation.Body;
            let ok_chk = check_field(vp, ok_read, loc, Name, "invalid_json_field", "invalid JSON field value");
            field_ok = field_ok && ok_chk;
        }
    }
    if !matched {
        json::skip(reader);
    }
    return field_ok;
}

// ---- declarative `const for` request binders -------------------------------

// Binds URL query parameters into `out` and records validation failures in `vp`.
// Rolls back `out` on any validation error.
fn bind_query<T>(
    raw_url_or_query: const u8[:],
    out:              T&,
    vp:               ValidationProblem&,
) -> bool {
    let saved = out;
    var committed = false;
    defer if !committed { out = saved; };
    let no_frag, _, _ = raw_url_or_query.partition_byte('#');
    let head, q_tail, has_q = no_frag.split_once_byte('?');
    let raw_q = if has_q { q_tail } else { head };
    var all_ok = true;
    const for <Name, Acc> in fields<T> {
        if !(vp.abort_early && !all_ok) {
            var val_buf: u8[..512] = [];
            let ok_q = raw_q.get_query_param_fast(Name, val_buf) && parse_bound_scalar(val_buf[..], out.Acc);
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
    let saved = out;
    var committed = false;
    defer if !committed { out = saved; };
    var all_ok = true;
    const for <Name, Acc> in fields<T> {
        if !(vp.abort_early && !all_ok) {
            var hdr_name: u8[..64] = [];
            let name_ok = normalize_field_to_header_name(Name, hdr_name);
            let raw_val = if name_ok { get_header(headers, hdr_name[..]) } else { "" };
            let prop = if name_ok { hdr_name[..] } else { Name };
            let ok_hdr = name_ok && raw_val.len > 0 && parse_bound_scalar(raw_val, out.Acc);
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
    let saved = out;
    var committed = false;
    defer if !committed { out = saved; };
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
            let ok_p = found && parse_bound_scalar(raw_val, out.Acc);
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
    let saved = out;
    var committed = false;
    defer if !committed { out = saved; };
    var all_ok = true;
    const for <Name, Acc> in fields<T> {
        if !(vp.abort_early && !all_ok) {
            let raw_val, found = find_raw_cookie_value(cookie_hdr, Name);
            let ok_c = found && parse_bound_scalar(raw_val, out.Acc);
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
    let saved = out;
    var committed = false;
    defer if !committed { out = saved; };
    if json_bytes.len == 0 {
        let _ = record_field_error(vp, ValidationLocation.Body, "$", "empty JSON request body", "invalid_json");
        return false;
    }
    var reader = json::reader(json_bytes);
    var all_ok = true;
    json::each_member(reader) { key =>
        if !(vp.abort_early && !all_ok) {
            if !bind_json_member(key, reader, out, vp) {
                all_ok = false;
            }
        } else {
            json::skip(reader);
        }
    };
    if !json::finish(reader) {
        if all_ok {
            let _ = record_field_error(vp, ValidationLocation.Body, "$", "malformed JSON document", "invalid_json");
        }
        all_ok = false;
    }
    guard all_ok else { return false; }
    committed = true;
    return true;
}
