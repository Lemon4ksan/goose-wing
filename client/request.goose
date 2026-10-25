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

// Sets a header on the request. Matches existing headers case-insensitively,
// drops control characters, and marks credential headers sensitive.
fn header(req: Request&, name: const u8[:], value: const u8[:]) {
    add_header(req.bloom_filter, name);
    set_header(req.headers, name, value, false);
}

// Sets an HTTP header marked sensitive so it is purged on cross-origin redirects.
fn sensitive_header(req: Request&, name: const u8[:], value: const u8[:]) {
    add_header(req.bloom_filter, name);
    set_header(req.headers, name, value, true);
}

fn set_header(req: Request&, name: const u8[:], value: const u8[:]) {
    add_header(req.bloom_filter, name);
    set_header(req.headers, name, value, false);
}

fn remove_header(req: Request&, name: const u8[:]) -> bool {
    return remove_header_by_name(req.headers, name);
}

fn bearer(req: Request&, token: const u8[:]) {
    var val: u8[..384] = "Bearer ";
    val.append(token);
    set_header(req.headers, "Authorization", val[..], true);
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
