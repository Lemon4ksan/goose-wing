// Unified Request model: procedural mutation + trailing-closure builder DSL.
namespace wing;

import std;
import json;

struct QueryItem {
    key: u8[..64] = [],
    value: u8[..256] = [],
}

struct Request {
    method: u8[..16] = "GET",
    url: u8[..512] = [],
    timeout: i64 = 0,
    headers: HeaderItem[..32] = [],
    query_params: QueryItem[..16] = [],
    body: u8[>..] = [],
}

// --- Overloaded JSON field writers for compile-time struct reflection ---

fn write_json_field(out: u8[>..]&, v: const u8[:]) {
    json::format_string(out, v);
}

fn write_json_field(out: u8[>..]&, v: i64) {
    json::format_int(out, v);
}

fn write_json_field(out: u8[>..]&, v: i32) {
    json::format_int(out, v);
}

fn write_json_field(out: u8[>..]&, v: f64) {
    json::format_number(out, v);
}

fn write_json_field(out: u8[>..]&, v: bool) {
    json::format_bool(out, v);
}

// --- Request Factories (Standalone & Trailing Closure) ---

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

// --- UFCS Request Mutators (work identically inside `{ req => ... }` and outside) ---

fn header(req: Request&, name: const u8[:], value: const u8[:]) {
    for &h in req.headers {
        if eq_ascii_fold(h.name[..], name) {
            h.value.clear();
            h.value.append(value);
            return;
        }
    }
    if req.headers.len < 32 {
        req.headers.push(make_header(name, value));
    }
}

fn set_header(req: Request&, name: const u8[:], value: const u8[:]) {
    header(req, name, value);
}

fn bearer(req: Request&, token: const u8[:]) {
    var h = HeaderItem { .. };
    h.name.append("Authorization");
    h.value.append("Bearer ");
    h.value.append(token);
    for &existing in req.headers {
        if eq_ascii_fold(existing.name[..], "Authorization") {
            existing.value.clear();
            existing.value.append(h.value[..]);
            return;
        }
    }
    if req.headers.len < 32 {
        req.headers.push(h);
    }
}

fn set_bearer(req: Request&, token: const u8[:]) {
    bearer(req, token);
}

fn query(req: Request&, key: const u8[:], value: const u8[:]) {
    if req.query_params.len < 16 {
        var q = QueryItem { .. };
        q.key.append(key);
        q.value.append(value);
        req.query_params.push(q);
    }
}

fn set_query(req: Request&, key: const u8[:], value: const u8[:]) {
    query(req, key, value);
}

fn timeout_ms(req: Request&, ms: i64) {
    req.timeout = ms;
}

fn set_timeout_ms(req: Request&, ms: i64) {
    req.timeout = ms;
}

fn text(req: Request&, body_str: const u8[:]) {
    header(req, "Content-Type", "text/plain; charset=utf-8");
    req.body.clear();
    req.body.append(body_str);
}

fn raw_json(req: Request&, json_str: const u8[:]) {
    header(req, "Content-Type", "application/json");
    req.body.clear();
    req.body.append(json_str);
}

fn json<T>(req: Request&, payload: const T&) {
    header(req, "Content-Type", "application/json");
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
}

fn set_json<T>(req: Request&, payload: const T&) {
    json(req, payload);
}

// --- Composable Middleware & Signers (operate on Request& before session.do) ---

fn enrich_tracing(req: Request&, trace_id: const u8[:]) {
    header(req, "X-Trace-Id", trace_id);
    header(req, "X-B3-Sampled", "1");
}

fn sign_hmac_sha256(req: Request&, secret_key: const u8[:]) {
    // Lightweight deterministic signature stub for the shell skeleton
    var sig: u8[..128] = "hmac-sha256:";
    sig.append(secret_key);
    sig.append(":len=");
    format(sig, req.body.len);
    header(req, "X-Signature-256", sig[..]);
}
