// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// RFC 9457: Problem Details for HTTP APIs (obsoleting RFC 7807).
// Standardized machine-readable JSON representation for HTTP error responses.
namespace wing;

import std;
import core from "..";
import json;
import client.response;
import .headers;

// RFC 9457 Section 3: The Problem Details JSON Object.
struct ProblemDetails {
    status:   i32       = 0,
    type_uri: u8[..256] = [],
    title:    u8[..128] = [],
    detail:   u8[..512] = [],
    instance: u8[..256] = [],
}

// Formats a ProblemDetails structure into an RFC 9457 JSON byte buffer.
//
// Example:
//   problem = ProblemDetails { status: 404, title: "Resource Not Found" }
//   returns: {"type":"about:blank","status":404,"title":"Resource Not Found"}
fn serialize_problem_details<B>(problem: const ProblemDetails&, out: B&) {
    out.append("{\"type\":");
    if problem.type_uri.len > 0 {
        core::format_json_string(out, problem.type_uri[..]);
    } else {
        out.append("\"about:blank\"");
    }
    out.append(",\"status\":");
    problem.status.format_i64_dec(out);

    if problem.title.len > 0 {
        out.append(",\"title\":");
        core::format_json_string(out, problem.title[..]);
    }
    if problem.detail.len > 0 {
        out.append(",\"detail\":");
        core::format_json_string(out, problem.detail[..]);
    }
    if problem.instance.len > 0 {
        out.append(",\"instance\":");
        core::format_json_string(out, problem.instance[..]);
    }
    out.push('}');
}

// RFC 9457 Section 3.1: Members of a Problem Details Object - Ignore members whose JSON type does not match.
fn read_problem_string_member<B>(reader: json::Reader&, dst: B&, out_err: bool&) {
    if json::peek(reader) != '"' {
        json::skip(reader);
        return;
    }
    if !core::read_json_string_into(reader, dst) {
        out_err = true;
    }
}

// Parses core status and type fields from JSON reader (RFC 9457 Section 3.1).
//
// Example:
//   key = "status", reader has integer 404
//   stores: out.status = 404, returns: true
fn parse_problem_core_fields(
    key:     const u8[:],
    reader:  json::Reader&,
    out:     ProblemDetails&,
    out_err: bool&,
) -> bool {
    if key == "status" {
        let ch = json::peek(reader);
        if (ch >= '0' && ch <= '9') || ch == '-' {
            out.status = json::read_int(reader) as i32;
        } else {
            json::skip(reader);
        }
        return true;
    }
    if key == "type" {
        read_problem_string_member(reader, out.type_uri, out_err);
        return true;
    }
    return false;
}

// Parses descriptive title, detail, and instance fields from JSON reader (RFC 9457 Section 3.1).
//
// Example:
//   key = "title", reader has string "Not Found"
//   stores: out.title = "Not Found", returns: true
fn parse_problem_descriptive_fields(
    key:     const u8[:],
    reader:  json::Reader&,
    out:     ProblemDetails&,
    out_err: bool&,
) -> bool {
    if key == "title" {
        read_problem_string_member(reader, out.title, out_err);
        return true;
    }
    if key == "detail" {
        read_problem_string_member(reader, out.detail, out_err);
        return true;
    }
    if key == "instance" {
        read_problem_string_member(reader, out.instance, out_err);
        return true;
    }
    return false;
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
        if !parse_problem_core_fields(key, reader, out, field_err) &&
           !parse_problem_descriptive_fields(key, reader, out, field_err) {
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
    var res = Response { status_code: problem.status, .. };
    set_header(res, "Content-Type", rfc::MIME_PROBLEM_JSON);
    serialize_problem_details(problem, res.body);
    return res;
}

// Populates an existing server `Response` in-place with an RFC 9457 `application/problem+json` body.
fn write_problem_response(res: Response&, problem: const ProblemDetails&) {
    res.status_code = problem.status;
    set_header(res, "Content-Type", rfc::MIME_PROBLEM_JSON);
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
    var prob = ProblemDetails { status: status_code, .. };
    let _ = prob.title.try_set(title);
    let _ = prob.detail.try_set(detail);
    let _ = prob.type_uri.try_set(type_uri);
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

// Appends a sanitized field-level validation failure to `vp.errors`.
// Sets `vp.overflowed = true` and returns `false` if the bounded 16-entry error array is full.
fn record_field_error(
    vp:       ValidationProblem&,
    on:       ValidationLocation,
    property: const u8[:],
    summary:  const u8[:],
    code:     const u8[:] = "invalid_field",
) -> bool {
    var item = FieldValidationError { on: on, .. };
    sanitize_untrusted_for_error(property, item.property);
    let code_len = min(code.len, item.code.cap);
    item.code.append(code[..code_len]);
    let sum_len = min(summary.len, item.summary.cap);
    item.summary.append(summary[..sum_len]);
    guard vp.errors.try_push(item) else {
        vp.overflowed = true;
        return false;
    }
    return true;
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
    let _ = record_field_error(vp, on, property, summary, code);
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
    out.append("{\"type\":");
    if vp.problem.type_uri.len > 0 {
        core::format_json_string(out, vp.problem.type_uri[..]);
    } else {
        out.append("\"about:blank\"");
    }
    out.append(",\"status\":");
    let st = if vp.problem.status > 0 { vp.problem.status } else { 422 };
    st.format_i64_dec(out);
    out.append(",\"title\":");
    if vp.problem.title.len > 0 {
        core::format_json_string(out, vp.problem.title[..]);
    } else {
        out.append("\"Validation Failed\"");
    }
    if mode == ValidationDetailMode.Detailed && vp.problem.detail.len > 0 {
        out.append(",\"detail\":");
        core::format_json_string(out, vp.problem.detail[..]);
    }
    if vp.problem.instance.len > 0 {
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
    res.status_code = if vp.problem.status > 0 { vp.problem.status } else { 422 };
    set_header(res, "Content-Type", rfc::MIME_PROBLEM_JSON);
    res.body.clear();
    serialize_validation_problem(vp, res.body, mode);
}
