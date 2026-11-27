// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// RFC 9457: Problem Details for HTTP APIs (obsoleting RFC 7807).
// Standardized machine-readable JSON representation for HTTP error responses.
namespace http;

import std;
import core;
import json;
import .response;
import .headers;
import http.message_internal;

// RFC 9457 Section 3: The Problem Details JSON Object.
struct ProblemDetails {
    status:     i32       = 0,
    type_uri:   u8[..256] = [],
    title:      u8[..128] = [],
    detail:     u8[..512] = [],
    instance:   u8[..256] = [],
    redact_5xx: bool      = false,
}

// Formats a ProblemDetails structure into an RFC 9457 JSON byte buffer.
//
// Example:
//   problem = ProblemDetails { status: 404, title: "Resource Not Found" }
//   returns: {"type":"about:blank","status":404,"title":"Resource Not Found"}
fn serialize_problem_details<B>(problem: const ProblemDetails&, out: B&) {
    let has_valid_status = problem.status >= 100 && problem.status <= 599;
    let eff_status = if has_valid_status { problem.status } else { 500 };
    let redact = problem.redact_5xx && eff_status >= 500;

    out.append("{\"type\":");
    if problem.type_uri.len > 0 && !http_internal::is_unsafe_uri_scheme(problem.type_uri[..]) {
        core::format_json_string(out, problem.type_uri[..]);
    } else {
        out.append("\"about:blank\"");
    }
    if has_valid_status {
        out.append(",\"status\":");
        problem.status.format_i64_dec(out);
    }

    if problem.title.len > 0 {
        out.append(",\"title\":");
        core::format_json_string(out, problem.title[..]);
    }
    if !redact && problem.detail.len > 0 {
        out.append(",\"detail\":");
        core::format_json_string(out, problem.detail[..]);
    }
    if !redact && problem.instance.len > 0 && !http_internal::is_unsafe_uri_scheme(problem.instance[..]) {
        out.append(",\"instance\":");
        core::format_json_string(out, problem.instance[..]);
    }
    out.push('}');
}

// Parses an RFC 9457 JSON problem details document into a typed ProblemDetails struct.
// Defends against duplicate keys and injection via canonical streaming JSON reader.
//
// Example:
//   raw = "{\"type\":\"https://example.com/probs/out-of-credit\",\"title\":\"Out of Credit\",\"status\":403}"
//   returns: true, out.status = 403, out.title = "Out of Credit"
fn parse_problem_details(json_src: const u8[:], out: ProblemDetails&) -> bool {
    out = ProblemDetails { .. };
    var committed = false;
    defer if !committed { out = ProblemDetails { .. }; };

    guard json_src.len > 0 else { return false; }
    var reader = json::reader(json_src);
    var field_err = false;

    json::each_member(reader) { key =>
        if !http_internal::parse_problem_core_fields(key, reader, out, field_err) &&
           !http_internal::parse_problem_descriptive_fields(key, reader, out, field_err) {
            json::skip(reader);
        }
    };

    guard !field_err && json::finish(reader) else { return false; }
    if out.type_uri.len == 0 {
        out.type_uri.append("about:blank");
    }
    committed = true;
    return true;
}

// Creates an RFC 9457 compliant error Response with application/problem+json.
fn new_problem_response(problem: const ProblemDetails&) -> Response {
    let eff_status = if problem.status >= 100 && problem.status <= 599 { problem.status } else { 500 };
    var res = Response { status_code: eff_status, .. };
    set_header(res, "Content-Type", rfc::MIME_PROBLEM_JSON);
    set_header(res, "X-Content-Type-Options", "nosniff");
    serialize_problem_details(problem, res.body);
    return res;
}

// Populates an existing server `Response` in-place with an RFC 9457 `application/problem+json` body.
fn write_problem_response(res: Response&, problem: const ProblemDetails&) {
    res.status_code = if problem.status >= 100 && problem.status <= 599 { problem.status } else { 500 };
    set_header(res, "Content-Type", rfc::MIME_PROBLEM_JSON);
    set_header(res, "X-Content-Type-Options", "nosniff");
    res.body.clear();
    serialize_problem_details(problem, res.body);
}

// Populates `res` in-place with an RFC 9457 problem response constructed from `status_code`, `title`, and `detail`.
fn respond_problem(
    res:         Response&,
    status_code: i32,
    title:       const u8[:],
    detail:      const u8[:] = "",
    type_uri:    const u8[:] = "",
) {
    let eff_status = if status_code >= 100 && status_code <= 599 { status_code } else { 500 };
    var prob = ProblemDetails { status: eff_status, .. };
    let _ = prob.title.try_set(title);
    let _ = prob.detail.try_set(detail);
    if !http_internal::is_unsafe_uri_scheme(type_uri) {
        let _ = prob.type_uri.try_set(type_uri);
    }
    write_problem_response(res, prob);
}

// ---- RFC 9457 structured field validation problems -------------------------

enum ValidationLocation {
    Unknown,
    Query,
    Header,
    PathParam,
    Cookie,
    Body,
    Response,
}

// Returns the lowercase wire token for a validation error location.
fn location_wire_name(loc: ValidationLocation) -> const u8[:] {
    if loc == ValidationLocation.Query { return "query"; }
    if loc == ValidationLocation.Header { return "header"; }
    if loc == ValidationLocation.PathParam { return "path"; }
    if loc == ValidationLocation.Cookie { return "cookie"; }
    if loc == ValidationLocation.Body { return "body"; }
    if loc == ValidationLocation.Response { return "response"; }
    return "unknown";
}

struct FieldValidationError {
    on:       ValidationLocation = ValidationLocation.Unknown,
    property: u8[..64]           = [],
    code:     u8[..32]           = [],
    summary:  u8[..160]          = [],
}

struct ValidationProblem {
    problem:     ProblemDetails             = ProblemDetails { status: 422, .. },
    errors:      FieldValidationError[..16] = [],
    abort_early: bool                       = false,
    overflowed:  bool                       = false,
}

enum ValidationDetailMode {
    Detailed,
    Redacted,
}

// Evaluates predicate `ok`; when `false`, records a field error in `vp` and returns `false`.
fn check_field(
    vp:       ValidationProblem&,
    ok:       bool,
    on:       ValidationLocation,
    property: const u8[:],
    code:     const u8[:],
    summary:  const u8[:],
) -> bool {
    if ok { return true; }
    let _ = http_internal::record_field_error(vp, on, property, summary, code);
    return false;
}

// Returns `true` when zero field validation errors have been recorded and `vp` has not overflowed.
fn is_valid_problem(vp: const ValidationProblem&) -> bool {
    return vp.errors.len == 0 && !vp.overflowed;
}

// Serializes `vp` as an RFC 9457 JSON document with an `"errors"` extension member in `Detailed` mode,
// or omits `"detail"` and `"errors"` in `Redacted` production mode.
//
// Example:
//   vp = ValidationProblem { .. } (with 1 query error on "page")
//   mode = ValidationDetailMode.Redacted
//   out = {"type":"about:blank","status":422,"title":"Validation Failed"}
fn serialize_validation_problem<B>(
    vp:   const ValidationProblem&,
    out:  B&,
    mode: ValidationDetailMode = ValidationDetailMode.Detailed,
) {
    let st = if vp.problem.status >= 100 && vp.problem.status <= 599 { vp.problem.status } else { 422 };
    let redact = vp.problem.redact_5xx && st >= 500;
    out.append("{\"type\":");
    if vp.problem.type_uri.len > 0 && !http_internal::is_unsafe_uri_scheme(vp.problem.type_uri[..]) {
        core::format_json_string(out, vp.problem.type_uri[..]);
    } else {
        out.append("\"about:blank\"");
    }
    out.append(",\"status\":");
    st.format_i64_dec(out);
    out.append(",\"title\":");
    if vp.problem.title.len > 0 {
        core::format_json_string(out, vp.problem.title[..]);
    } else {
        out.append("\"Validation Failed\"");
    }
    if mode == ValidationDetailMode.Detailed && !redact && vp.problem.detail.len > 0 {
        out.append(",\"detail\":");
        core::format_json_string(out, vp.problem.detail[..]);
    }
    let has_safe_inst = vp.problem.instance.len > 0 && !http_internal::is_unsafe_uri_scheme(vp.problem.instance[..]);
    if !redact && has_safe_inst {
        out.append(",\"instance\":");
        core::format_json_string(out, vp.problem.instance[..]);
    }
    if mode == ValidationDetailMode.Detailed {
        out.append(",\"errors\":[");
        for &err, idx in vp.errors {
            if idx > 0 { out.push(','); }
            out.append("{\"on\":\"");
            out.append(location_wire_name(err.on));
            out.append("\",\"property\":");
            core::format_json_string(out, err.property[..]);
            out.append(",\"code\":");
            core::format_json_string(out, err.code[..]);
            out.append(",\"summary\":");
            core::format_json_string(out, err.summary[..]);
            out.push('}');
        }
        out.push(']');
        if vp.overflowed {
            out.append(",\"overflowed\":true");
        }
    }
    out.push('}');
}

// Populates `res` in-place with an RFC 9457 `application/problem+json` validation error response.
fn write_validation_problem_response(
    res:  Response&,
    vp:   const ValidationProblem&,
    mode: ValidationDetailMode = ValidationDetailMode.Detailed,
) {
    res.status_code = if vp.problem.status >= 100 && vp.problem.status <= 599 { vp.problem.status } else { 422 };
    set_header(res, "Content-Type", rfc::MIME_PROBLEM_JSON);
    set_header(res, "X-Content-Type-Options", "nosniff");
    res.body.clear();
    serialize_validation_problem(vp, res.body, mode);
}
