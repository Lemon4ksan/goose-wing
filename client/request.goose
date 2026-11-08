// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// HTTP request representation with headers, query parameters, body rewind,
// and security context metadata (RFC 9110).
namespace wing;

import std;
import core from "..";
import json;
import cookie.policy;
import http.priority;
import http.incremental;
import http.trace;

// ---- request & query item models -------------------------------------------

struct QueryItem {
    key:   u8[..64]  = [],
    value: u8[..256] = [],
}

struct Request {
    method:               u8[..16]            = "GET",
    url:                  u8[..2048]          = [],
    timeout:              i64                 = 0,
    headers:              HeaderMap           = HeaderMap { .. },
    presence_mask:        u32                 = 0,
    trailers:             HeaderMap           = HeaderMap { .. },
    query_params:         QueryItem[..16]     = [],
    rewind_buf:           u8[..4096]          = [],
    rewindable:           bool                = true,
    body_consumed:        bool                = false,
    cors_mode:            bool                = false,
    tainted_origin:       bool                = false,
    is_main_frame:        bool                = true,
    is_reload:            bool                = false,
    initiator:            core::Origin        = core::Origin { .. },
    has_initiator:        bool                = false,
    site_for_cookies:     SiteForCookies      = SiteForCookies { .. },
    has_site_for_cookies: bool                = false,
    first_party_policy:   FirstPartyURLPolicy = FirstPartyURLPolicy.UPDATE_FIRST_PARTY_URL_ON_REDIRECT,
    is_http10:            bool                = false,
    body:                 u8[>..]             = [],
}

// ---- json reflection writers -----------------------------------------------

fn write_json_field(out: u8[>..]&, val_str: const u8[:]) {
    json::format_string(out, val_str);
}

fn write_json_field(out: u8[>..]&, val_i64: i64) {
    json::format_int(out, val_i64);
}

fn write_json_field(out: u8[>..]&, val_i32: i32) {
    json::format_int(out, val_i32);
}

fn write_json_field(out: u8[>..]&, val_f64: f64) {
    json::format_number(out, val_f64);
}

fn write_json_field(out: u8[>..]&, val_bool: bool) {
    json::format_bool(out, val_bool);
}

// ---- request factories -----------------------------------------------------

fn reset_request(req: Request&) {
    let _ = req.method.try_set("GET");
    req.url.clear();
    req.headers.clear();
    req.presence_mask = 0;
    req.trailers.clear();
    req.query_params.clear();
    req.rewind_buf.clear();
    req.body.clear();
    req.timeout = 0;
    req.rewindable = true;
    req.body_consumed = false;
    req.cors_mode = false;
    req.tainted_origin = false;
    req.is_main_frame = true;
    req.is_reload = false;
    req.has_initiator = false;
    req.has_site_for_cookies = false;
    req.is_http10 = false;
}

fn new_request(method: const u8[:], url: const u8[:]) -> Request {
    var req = Request { .. };
    let _ = req.method.try_set(method);
    let _ = req.url.try_set(url);
    return req;
}

fn new_request<F: fn(Request&)>(method: const u8[:], url: const u8[:]) -> Request {
    var req = new_request(method, url);
    F(&req);
    return req;
}

fn new_get(url: const u8[:]) -> Request {
    return new_request("GET", url);
}

fn new_get<F: fn(Request&)>(url: const u8[:]) -> Request {
    return new_request("GET", url, F);
}

fn new_post(url: const u8[:]) -> Request {
    return new_request("POST", url);
}

fn new_post<F: fn(Request&)>(url: const u8[:]) -> Request {
    return new_request("POST", url, F);
}

// Creates a new HTTP QUERY request (RFC 10008 Section 2).
// Servers MUST fail the request if Content-Type is missing or inconsistent.
fn new_query(url: const u8[:], body: const u8[:], content_type: const u8[:]) -> Request {
    var req = new_request("QUERY", url);
    req.body.append(body);
    set_header(req, "Content-Type", content_type);
    req.rewind_buf.clear();
    req.rewindable = req.rewind_buf.try_set(body);
    req.body_consumed = false;
    return req;
}

fn new_query<F: fn(Request&)>(url: const u8[:], body: const u8[:], content_type: const u8[:]) -> Request {
    var req = new_query(url, body, content_type);
    F(&req);
    return req;
}

// Returns the value of a request header by name.
fn header(req: const Request&, name: const u8[:]) -> const u8[:] {
    return get_header(req.headers, name);
}

fn has_header(req: const Request&, name: const u8[:]) -> bool {
    return has_header(req.headers, name);
}

// Returns the value of a request trailer by name (case-insensitive lookup)
fn trailer(req: const Request&, name: const u8[:]) -> const u8[:] {
    return get_header(req.trailers, name);
}

fn has_trailer(req: const Request&, name: const u8[:]) -> bool {
    return has_header(req.trailers, name);
}

fn add_trailer(req: Request&, name: const u8[:], value: const u8[:]) {
    guard !rfc::is_disallowed_trailer_field(name) else { return; }
    set_header(req.trailers, name, value, false);
}

// ---- ufcs request mutators -------------------------------------------------

// Sets an HTTP header marked sensitive so it is purged on cross-origin redirects.
fn sensitive_header(req: Request&, name: const u8[:], value: const u8[:]) {
    set_header(req.headers, name, value, true);
    if has_header(req.headers, name) {
        let known_id = identify_known_header(name);
        if known_id != KnownHeaderId.Unknown {
            req.presence_mask |= header_id_to_bit(known_id);
        }
    }
}

// Sets a header on the request. Matches existing headers case-insensitively,
// drops control characters, and marks credential headers sensitive.
fn set_header(req: Request&, name: const u8[:], value: const u8[:]) {
    set_header(req.headers, name, value, false);
    if has_header(req.headers, name) {
        let known_id = identify_known_header(name);
        if known_id != KnownHeaderId.Unknown {
            req.presence_mask |= header_id_to_bit(known_id);
        }
    }
}

fn remove_header(req: Request&, name: const u8[:]) -> bool {
    let known_id = identify_known_header(name);
    if known_id != KnownHeaderId.Unknown {
        req.presence_mask &= ~header_id_to_bit(known_id);
    }
    return remove_header(req.headers, name);
}

fn bearer(req: Request&, token: const u8[:]) {
    var val: u8[>..] = "Bearer ";
    val.append(token);
    sensitive_header(req, "Authorization", val[..]);
}

// Invariant 13: Strict capacity overflow error propagation.
// Rejects when query parameters capacity is reached or key/value length exceeds bounds.
fn query(req: Request&, key: const u8[:], value: const u8[:]) -> bool {
    var param_item = QueryItem { .. };
    guard param_item.key.try_set(key) && param_item.value.try_set(value) else {
        return false;
    }
    return req.query_params.try_push(param_item);
}

fn timeout_ms(req: Request&, ms: i64) {
    req.timeout = ms;
}

fn set_timeout_ms(req: Request&, ms: i64) {
    req.timeout = ms;
}

fn text(req: Request&, body_str: const u8[:]) {
    set_header(req, "Content-Type", "text/plain; charset=utf-8");
    req.body.clear();
    req.body.append(body_str);
    req.rewind_buf.clear();
    req.rewindable = req.rewind_buf.try_set(body_str);
    req.body_consumed = false;
}

fn raw_json(req: Request&, json_str: const u8[:]) {
    set_header(req, "Content-Type", "application/json");
    req.body.clear();
    req.body.append(json_str);
    req.rewind_buf.clear();
    req.rewindable = req.rewind_buf.try_set(json_str);
    req.body_consumed = false;
}

fn json<T>(req: Request&, payload: const T&) {
    set_header(req, "Content-Type", "application/json");
    req.body.clear();
    req.body.push('{');
    var first = true;
    const for <Name, Acc> in fields<T> {
        if !first { req.body.push(','); }
        first = false;
        json::format_key(req.body, Name);
        write_json_field(req.body, payload.Acc);
    }
    req.body.push('}');
    req.rewind_buf.clear();
    req.rewindable = req.rewind_buf.try_set(req.body[..]);
    req.body_consumed = false;
}

fn set_stream_body(req: Request&, stream_bytes: const u8[:], rewindable: bool = false) {
    req.body.clear();
    req.body.append(stream_bytes);
    req.rewind_buf.clear();
    req.rewindable = rewindable && req.rewind_buf.try_set(stream_bytes);
    req.body_consumed = false;
}

fn set_initiator(req: Request&, orig: core::Origin) {
    req.initiator = copy(orig);
    req.has_initiator = true;
}

// ---- middleware & signers --------------------------------------------------

// Sets RFC 9218 HTTP Priority header ("Priority: u=..., i") and RFC 10036 Incremental header.
// Urgency ranges from 0 (highest) to 7 (lowest), default is 3.
fn set_priority(req: Request&, urgency: i32, incremental: bool = false) {
    let u: u8 = if urgency >= 0 && urgency <= 7 { urgency as u8 } else { rfc::PRIORITY_URGENCY_DEFAULT };
    var p = PriorityParam { urgency: u, incremental: incremental };
    var wire_val: u8[..32] = [];
    serialize_http_priority(p, wire_val);
    set_header(req, "priority", wire_val[..]);
    if incremental {
        let _ = append_incremental_header(req.headers, true);
    }
}

fn enrich_tracing(req: Request&, trace_id: const u8[:], tracestate_raw: const u8[:] = "") {
    set_header(req, "X-Trace-Id", trace_id);
    let tp, ok_tp = parse_traceparent(trace_id);
    if ok_tp {
        var tp_wire: u8[..64] = [];
        format_traceparent(tp, tp_wire);
        set_header(req, "traceparent", tp_wire[..]);
        set_header(req, "X-B3-Sampled", if traceparent_is_sampled(tp) { "1" } else { "0" });
    } else {
        set_header(req, "X-B3-Sampled", "1");
    }
    if tracestate_raw.len > 0 {
        let ts, ok_ts = parse_tracestate(tracestate_raw);
        if ok_ts {
            var ts_wire: u8[..512] = [];
            format_tracestate(ts, ts_wire);
            set_header(req, "tracestate", ts_wire[..]);
        }
    }
}

// RFC 2104 Section 2: Definition of HMAC - Computes cryptographic HMAC-SHA256 signature
// over the request body and sets the X-Signature-256 header as a 64-character lowercase hex string.
// If the body is empty, signs an empty slice. Zero heap allocations on hot path.
fn sign_hmac_sha256(req: Request&, secret_key: const u8[:]) {
    let body_bytes: const u8[:] = if req.body.len > 0 { req.body[..] } else { "" };
    let mac = core::hmac_sha256(secret_key, body_bytes);
    var sig_hex: u8[..64] = [];
    for b in mac {
        b.format_u8_hex(sig_hex);
    }
    set_header(req, "X-Signature-256", sig_hex[..]);
}
