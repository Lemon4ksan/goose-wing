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
        out.status = json::read_int(reader) as i32;
        return true;
    }
    if key == "type" {
        if !core::read_json_string_into(reader, out.type_uri) {
            out_err = true;
        }
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
        if !core::read_json_string_into(reader, out.title) {
            out_err = true;
        }
        return true;
    }
    if key == "detail" {
        if !core::read_json_string_into(reader, out.detail) {
            out_err = true;
        }
        return true;
    }
    if key == "instance" {
        if !core::read_json_string_into(reader, out.instance) {
            out_err = true;
        }
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
    out.status = 0;
    out.type_uri.clear();
    out.title.clear();
    out.detail.clear();
    out.instance.clear();

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
