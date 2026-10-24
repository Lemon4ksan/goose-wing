// HTTP request representation with headers, query parameters, body rewind,
// and security context metadata (RFC 9110).
namespace wing;

import std;
import json;
import cookie.policy;

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

// ---- ufcs request mutators -------------------------------------------------

// Sets a header on the request. Matches existing headers case-insensitively,
// drops control characters, and marks credential headers sensitive.
fn header(req: Request&, name: const u8[:], value: const u8[:]) {
    let hdr = make_header(name, value);
    for &header_entry in req.headers {
        if eq_ascii_fold(header_entry.name[..], hdr.name[..]) {
            header_entry.value.clear();
            header_entry.value.append(hdr.value[..]);
            header_entry.is_sensitive = hdr.is_sensitive;
            return;
        }
    }
    if req.headers.len < 32 {
        req.headers.push(hdr);
    }
}

// Sets an HTTP header marked sensitive so it is purged on cross-origin redirects.
fn sensitive_header(req: Request&, name: const u8[:], value: const u8[:]) {
    let hdr = make_header(name, value, true);
    for &header_entry in req.headers {
        if eq_ascii_fold(header_entry.name[..], hdr.name[..]) {
            header_entry.value.clear();
            header_entry.value.append(hdr.value[..]);
            header_entry.is_sensitive = true;
            return;
        }
    }
    if req.headers.len < 32 {
        req.headers.push(hdr);
    }
}

fn set_header(req: Request&, name: const u8[:], value: const u8[:]) {
    header(req, name, value);
}

fn bearer(req: Request&, token: const u8[:]) {
    var auth_header = HeaderItem { is_sensitive: true, .. };
    auth_header.name.append("Authorization");
    auth_header.value.append("Bearer ");
    auth_header.value.append(token);
    for &existing in req.headers {
        if eq_ascii_fold(existing.name[..], "Authorization") {
            existing.value.clear();
            existing.value.append(auth_header.value[..]);
            existing.is_sensitive = true;
            return;
        }
    }
    if req.headers.len < 32 {
        req.headers.push(auth_header);
    }
}

fn set_bearer(req: Request&, token: const u8[:]) {
    bearer(req, token);
}

fn query(req: Request&, key: const u8[:], value: const u8[:]) {
    if req.query_params.len < 16 {
        var param_item = QueryItem { .. };
        param_item.key.append(key);
        param_item.value.append(value);
        req.query_params.push(param_item);
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
    req.rewind_buf.clear();
    req.rewind_buf.append(body_str);
    req.rewindable = true;
    req.body_consumed = false;
}

fn raw_json(req: Request&, json_str: const u8[:]) {
    header(req, "Content-Type", "application/json");
    req.body.clear();
    req.body.append(json_str);
    req.rewind_buf.clear();
    req.rewind_buf.append(json_str);
    req.rewindable = true;
    req.body_consumed = false;
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

fn set_initiator(req: Request&, orig: const core::Origin&) {
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
