// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Transport-free server domain reply and error types with RFC 9457 boundary serialization.
namespace server;

import std;
import core;
import rfc.http;
import http.headers;
import http.response;
import http.problem;
import http.json_codec;
import http.json_helpers;

// Marker payload struct for empty HTTP replies (`204 No Content`, `304 Not Modified`, redirects).
struct EmptyBody {}

// Transport-agnostic domain error translated to RFC 9457 `ProblemDetails` at the HTTP boundary.
struct DomainError {
    status:          i32       = rfc::STATUS_INTERNAL_SERVER_ERROR,
    title:           u8[..128] = [],
    code:            u8[..64]  = [],
    detail:          u8[..512] = [],
    type_uri:        u8[..256] = [],
    retry_after_sec: i32       = 0,
}

// Response header entry stored on `Reply<T>` prior to boundary serialization.
struct ReplyHeader {
    name:  u8[..64]  = [],
    value: u8[..256] = [],
}

// Domain handler return container holding either a typed payload `T` or a `DomainError`.
struct Reply<T> {
    status:             i32              = rfc::STATUS_OK,
    is_error:           bool             = false,
    headers_overflowed: bool             = false,
    location:           u8[..512]        = [],
    headers:            ReplyHeader[..8] = [],
    err:                DomainError      = DomainError { .. },
    body:               T                = default<T>(),
}

// Constructs a `DomainError` safely truncating string fields at UTF-8 codepoint boundaries.
//
// Example:
//   make_domain_error(404, "Not Found", "user_missing", "user id 42 does not exist")
//   returns: DomainError { status: 404, title: "Not Found", code: "user_missing", ... }
fn make_domain_error(
    status:   i32,
    title:    const u8[:],
    code:     const u8[:],
    detail:   const u8[:] = "",
    type_uri: const u8[:] = "",
) -> DomainError {
    var e = DomainError { status: status, .. };
    let t_src = if title.len > 0 { title } else { rfc::status_phrase(status) };
    let _ = e.title.try_set(http::truncate_utf8_safe(t_src, e.title.cap));
    let _ = e.code.try_set(http::truncate_utf8_safe(code, e.code.cap));
    let _ = e.detail.try_set(http::truncate_utf8_safe(detail, e.detail.cap));
    let _ = e.type_uri.try_set(http::truncate_utf8_safe(type_uri, e.type_uri.cap));
    return e;
}

fn err_bad_request(code: const u8[:], detail: const u8[:] = "") -> DomainError {
    return make_domain_error(rfc::STATUS_BAD_REQUEST, "Bad Request", code, detail);
}

fn err_unauthorized(detail: const u8[:] = "authentication required") -> DomainError {
    return make_domain_error(rfc::STATUS_UNAUTHORIZED, "Unauthorized", "unauthorized", detail);
}

fn err_forbidden(detail: const u8[:] = "access denied") -> DomainError {
    return make_domain_error(rfc::STATUS_FORBIDDEN, "Forbidden", "forbidden", detail);
}

fn err_not_found(detail: const u8[:] = "resource not found") -> DomainError {
    return make_domain_error(rfc::STATUS_NOT_FOUND, "Not Found", "not_found", detail);
}

fn err_method_not_allowed(detail: const u8[:] = "method not allowed") -> DomainError {
    return make_domain_error(
        rfc::STATUS_METHOD_NOT_ALLOWED, "Method Not Allowed", "method_not_allowed", detail,
    );
}

fn err_conflict(code: const u8[:], detail: const u8[:] = "") -> DomainError {
    return make_domain_error(rfc::STATUS_CONFLICT, "Conflict", code, detail);
}

fn err_validation(code: const u8[:], detail: const u8[:] = "") -> DomainError {
    return make_domain_error(rfc::STATUS_UNPROCESSABLE_CONTENT, "Unprocessable Content", code, detail);
}

fn err_rate_limited(retry_after_sec: i32, detail: const u8[:] = "rate limit exceeded") -> DomainError {
    var e = make_domain_error(rfc::STATUS_TOO_MANY_REQUESTS, "Too Many Requests", "rate_limited", detail);
    e.retry_after_sec = max(retry_after_sec, 0);
    return e;
}

fn err_internal(detail: const u8[:] = "internal server error") -> DomainError {
    return make_domain_error(rfc::STATUS_INTERNAL_SERVER_ERROR, "Internal Server Error", "internal_error", detail);
}

fn err_bad_gateway(detail: const u8[:] = "upstream request failed") -> DomainError {
    return make_domain_error(rfc::STATUS_BAD_GATEWAY, "Bad Gateway", "bad_gateway", detail);
}

fn err_unavailable(detail: const u8[:] = "service temporarily unavailable") -> DomainError {
    return make_domain_error(rfc::STATUS_SERVICE_UNAVAILABLE, "Service Unavailable", "unavailable", detail);
}

fn ok_reply(status: i32 = rfc::STATUS_OK) -> Reply<EmptyBody> {
    return Reply<EmptyBody> { status: status, .. };
}

fn ok<T>(body: T) -> Reply<T> {
    return Reply<T> { status: rfc::STATUS_OK, body: body, .. };
}

fn created<T>(body: T) -> Reply<T> {
    return Reply<T> { status: rfc::STATUS_CREATED, body: body, .. };
}

fn accepted<T>(body: T) -> Reply<T> {
    return Reply<T> { status: rfc::STATUS_ACCEPTED, body: body, .. };
}

fn no_content() -> Reply<EmptyBody> {
    return Reply<EmptyBody> { status: rfc::STATUS_NO_CONTENT, .. };
}

fn not_modified() -> Reply<EmptyBody> {
    return Reply<EmptyBody> { status: rfc::STATUS_NOT_MODIFIED, .. };
}

fn redirect_to(location: const u8[:], status: i32 = rfc::STATUS_FOUND) -> Reply<EmptyBody> {
    var rep = Reply<EmptyBody> {
        status: if rfc::is_redirect_status(status) { status } else { rfc::STATUS_FOUND },
        ..
    };
    let _ = rep.location.try_set(location);
    return rep;
}

fn fail<T>(err: DomainError) -> Reply<T> {
    return Reply<T> { status: err.status, is_error: true, err: err, .. };
}

// Appends a custom response header to `r`. Marks `r.headers_overflowed = true` and returns `false` on overflow.
fn with_header<T>(r: Reply<T>&, name: const u8[:], value: const u8[:]) -> bool {
    guard name.len > 0 && name.len <= 64 && value.len <= 256 && r.headers.len < r.headers.cap else {
        r.headers_overflowed = true;
        return false;
    }
    var item = ReplyHeader { .. };
    guard item.name.try_set(name) && item.value.try_set(value) else {
        r.headers_overflowed = true;
        return false;
    }
    guard r.headers.try_push(item) else {
        r.headers_overflowed = true;
        return false;
    }
    return true;
}

// Attaches a `Cache-Control` response header to `r`, propagating capacity overflow.
fn with_cache_control<T>(r: Reply<T>&, directive: const u8[:]) -> bool {
    return with_header(r, "Cache-Control", directive);
}

// Serializes a `DomainError` into `res` as an RFC 9457 `application/problem+json` response.
fn write_domain_error_response(res: http::Response&, err: const DomainError&) {
    var prob = http::ProblemDetails { status: err.status, .. };
    let title_src = if err.title.len > 0 { err.title[..] } else { rfc::status_phrase(err.status) };
    let _ = prob.title.try_set(http::truncate_utf8_safe(title_src, prob.title.cap));
    let _ = prob.detail.try_set(err.detail[..]);
    if err.type_uri.len > 0 {
        let _ = prob.type_uri.try_set(err.type_uri[..]);
    } else if err.code.len > 0 {
        let _ = prob.type_uri.try_append("urn:wing:error:");
        let _ = prob.type_uri.try_append(http::truncate_utf8_safe(err.code[..], 200));
    }
    http::write_problem_response(res, prob);
    if err.status == rfc::STATUS_TOO_MANY_REQUESTS || err.status >= rfc::STATUS_INTERNAL_SERVER_ERROR {
        http::set_header(res, "Cache-Control", "no-store");
    }
    if err.retry_after_sec > 0 {
        var ra_buf: u8[..32] = [];
        err.retry_after_sec.format_i64_dec(ra_buf);
        http::set_header(res, "Retry-After", ra_buf[..]);
    }
}

fn write_reply_body(body: const EmptyBody&, res: http::Response&) {
    res.body.clear();
}

fn write_reply_body<T>(body: const T&, res: http::Response&) {
    http::set_header(res, "Content-Type", "application/json; charset=utf-8");
    res.body.clear();
    http::encode_json_struct(body, res.body);
}

// Serializes a `Reply<T>` into `http::Response` once at the transport boundary.
// Short-circuits immediately on domain error or header overflow so custom headers never overwrite errors.
//
// Example:
//   write_reply(res, server::ok(UserOut { id: 1 }))
//   populates res.status_code = 200, Content-Type: application/json; charset=utf-8, res.body = {"id":1}
fn write_reply<T>(res: http::Response&, rep: const Reply<T>&) {
    if rep.is_error {
        write_domain_error_response(res, rep.err);
        return;
    }
    if rep.headers_overflowed {
        http::respond_problem(res, 500, "Internal Server Error", "response header capacity exceeded");
        return;
    }
    if rfc::is_redirect_status(rep.status) {
        guard http::respond_redirect(res, rep.location[..], rep.status) else {
            http::respond_problem(res, 500, "Internal Server Error", "invalid redirect target");
            return;
        }
    } else if rep.status == rfc::STATUS_NO_CONTENT {
        http::respond_no_content(res);
    } else if rep.status == rfc::STATUS_NOT_MODIFIED {
        res.status_code = rfc::STATUS_NOT_MODIFIED;
        res.body.clear();
        let _ = http::remove_header(res, "Content-Type");
        let _ = http::remove_header(res, "Content-Length");
        if res.is_http1() {
            let _ = http::remove_header(res, "Transfer-Encoding");
        }
    } else {
        res.status_code = rep.status;
        write_reply_body(rep.body, res);
    }
    for &h in rep.headers {
        http::set_header(res, h.name[..], h.value[..]);
    }
}

// Serializes a `Reply<EmptyBody>` status/error/headers paired with a caller-owned `out` DTO.
// Supports both fixed and resizable `T[>..]` output structs without copying `out` into `Reply<T>`.
fn write_out_reply<T>(res: http::Response&, rep: const Reply<EmptyBody>&, out: const T&) {
    if rep.is_error {
        write_domain_error_response(res, rep.err);
        return;
    }
    if rep.headers_overflowed {
        http::respond_problem(res, 500, "Internal Server Error", "response header capacity exceeded");
        return;
    }
    if rfc::is_redirect_status(rep.status) ||
        rep.status == rfc::STATUS_NO_CONTENT ||
        rep.status == rfc::STATUS_NOT_MODIFIED {
        write_reply(res, rep);
        return;
    }
    res.status_code = rep.status;
    write_reply_body(out, res);
    for &h in rep.headers {
        http::set_header(res, h.name[..], h.value[..]);
    }
}
