// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// HTTP request representation with headers, query parameters, body rewind,
// and security context metadata (RFC 9110).
namespace wing;

import std;
import json;
import cookie.policy;
import http.priority;

// ---- request & query item models -------------------------------------------

struct QueryItem {
    key: u8[..64] = [],
    value: u8[..256] = [],
}

struct Request {
    method: u8[..16] = "GET",
    url: u8[..2048] = [],
    timeout: i64 = 0,
    headers: HeaderItem[..32] = [],
    bloom_filter: HeaderBloomFilter = HeaderBloomFilter { .. },
    trailers: HeaderItem[..16] = [],
    query_params: QueryItem[..16] = [],
    rewind_buf: u8[..4096] = [],
    rewindable: bool = true,
    body_consumed: bool = false,
    cors_mode: bool = false,
    tainted_origin: bool = false,
    is_main_frame: bool = true,
    is_reload: bool = false,
    initiator: core::Origin = core::Origin { .. },
    has_initiator: bool = false,
    site_for_cookies: SiteForCookies = SiteForCookies { .. },
    has_site_for_cookies: bool = false,
    first_party_policy: FirstPartyURLPolicy = FirstPartyURLPolicy.UPDATE_FIRST_PARTY_URL_ON_REDIRECT,
    is_http10: bool = false,
    body: u8[>..] = [],
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
    req.method.clear();
    req.method.append("GET");
    req.url.clear();
    req.headers.clear();
    req.bloom_filter.clear();
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
    req.method.clear();
    req.method.append(method);
    req.url.append(url);
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
    return req;
}

fn new_query<F: fn(Request&)>(url: const u8[:], body: const u8[:], content_type: const u8[:]) -> Request {
    var req = new_query(url, body, content_type);
    F(&req);
    return req;
}

// Returns the value of a request header by name (case-insensitive lookup with 256-bit Bloom filter)
fn header(req: const Request&, name: const u8[:]) -> const u8[:] {
    if !might_have_header(req.bloom_filter, name) {
        return "";
    }
    return find_header(req.headers[..], name);
}

fn has_header(req: const Request&, name: const u8[:]) -> bool {
    if !might_have_header(req.bloom_filter, name) {
        return false;
    }
    return has_header(req.headers[..], name);
}

// Returns the value of a request trailer by name (case-insensitive lookup)
fn trailer(req: const Request&, name: const u8[:]) -> const u8[:] {
    return find_header(req.trailers[..], name);
}

fn has_trailer(req: const Request&, name: const u8[:]) -> bool {
    return has_header(req.trailers[..], name);
}

fn add_trailer(req: Request&, name: const u8[:], value: const u8[:]) {
    guard !is_disallowed_trailer_field(name) else { return; }
    set_header(req.trailers, name, value, false);
}

// ---- ufcs request mutators -------------------------------------------------

// Sets an HTTP header marked sensitive so it is purged on cross-origin redirects.
fn sensitive_header(req: Request&, name: const u8[:], value: const u8[:]) {
    add_header(req.bloom_filter, name);
    set_header(req.headers, name, value, true);
}

// Sets a header on the request. Matches existing headers case-insensitively,
// drops control characters, and marks credential headers sensitive.
fn set_header(req: Request&, name: const u8[:], value: const u8[:]) {
    add_header(req.bloom_filter, name);
    set_header(req.headers, name, value, false);
}

fn remove_header(req: Request&, name: const u8[:]) -> bool {
    return remove_header_by_name(req.headers, name);
}

fn bearer(req: Request&, token: const u8[:]) {
    var val: u8[>..] = "Bearer ";
    val.append(token);
    sensitive_header(req, "Authorization", val[..]);
}

// Invariant 13: Strict capacity overflow error propagation.
// Rejects when query parameters capacity is reached or key/value length exceeds bounds.
fn query(req: Request&, key: const u8[:], value: const u8[:]) -> bool {
    guard req.query_params.len < req.query_params.cap && key.len <= 64 && value.len <= 256 else {
        return false;
    }
    var param_item = QueryItem { .. };
    param_item.key.append(key);
    param_item.value.append(value);
    req.query_params.push(param_item);
    return true;
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
    req.rewind_buf.append(body_str);
    req.rewindable = true;
    req.body_consumed = false;
}

fn raw_json(req: Request&, json_str: const u8[:]) {
    set_header(req, "Content-Type", "application/json");
    req.body.clear();
    req.body.append(json_str);
    req.rewind_buf.clear();
    req.rewind_buf.append(json_str);
    req.rewindable = true;
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
    req.rewind_buf.append(req.body[..]);
    req.rewindable = true;
    req.body_consumed = false;
}

fn set_json<T>(req: Request&, payload: const T&) {
    json(req, payload);
}

fn set_stream_body(req: Request&, stream_bytes: const u8[:], rewindable: bool = false) {
    req.body.clear();
    req.body.append(stream_bytes);
    req.rewindable = rewindable;
    req.rewind_buf.clear();
    if rewindable {
        req.rewind_buf.append(stream_bytes);
    }
    req.body_consumed = false;
}

fn set_initiator(req: Request&, orig: core::Origin) {
    req.initiator = copy(orig);
    req.has_initiator = true;
}

fn set_site_for_cookies(req: Request&, sfc: const SiteForCookies&) {
    req.site_for_cookies = copy(sfc);
    req.has_site_for_cookies = true;
}

fn set_first_party_policy(req: Request&, policy: FirstPartyURLPolicy) {
    req.first_party_policy = policy;
}

// ---- middleware & signers --------------------------------------------------

// Sets RFC 9218 HTTP Priority header ("Priority: u=..., i").
// Urgency ranges from 0 (highest) to 7 (lowest), default is 3.
fn set_priority(req: Request&, urgency: i32, incremental: bool = false) {
    let u: u8 = if urgency >= 0 && urgency <= 7 { urgency as u8 } else { PRIORITY_URGENCY_DEFAULT };
    var p = HttpPriority { urgency: u, incremental: incremental };
    var wire_val: u8[>..] = [];
    serialize_http_priority(p, wire_val);
    set_header(req, "priority", wire_val[..]);
}

fn enrich_tracing(req: Request&, trace_id: const u8[:]) {
    set_header(req, "X-Trace-Id", trace_id);
    set_header(req, "X-B3-Sampled", "1");
}

// RFC 2104 Section 2: Definition of HMAC - Computes cryptographic HMAC-SHA256 signature
// over the request body and sets the X-Signature-256 header as a 64-character lowercase hex string.
// If the body is empty, signs an empty slice. Zero heap allocations on hot path.
fn sign_hmac_sha256(req: Request&, secret_key: const u8[:]) {
    let body_bytes: const u8[:] = if req.body.len > 0 { req.body[..] } else { "" };
    let mac = core::hmac_sha256(secret_key, body_bytes);
    var sig_hex: u8[..64] = [];
    for b in mac {
        core::format_u8_hex(b, sig_hex);
    }
    set_header(req, "X-Signature-256", sig_hex[..]);
}
