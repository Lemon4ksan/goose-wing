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
    out.append("{\"type\":\"");
    if problem.type_uri.len > 0 {
        out.append(problem.type_uri[..]);
    } else {
        out.append("about:blank");
    }
    out.append("\",\"status\":");
    core::format_i64_dec(problem.status as i64, out);

    if problem.title.len > 0 {
        out.append(",\"title\":\"");
        out.append(problem.title[..]);
        out.push('"');
    }
    if problem.detail.len > 0 {
        out.append(",\"detail\":\"");
        out.append(problem.detail[..]);
        out.push('"');
    }
    if problem.instance.len > 0 {
        out.append(",\"instance\":\"");
        out.append(problem.instance[..]);
        out.push('"');
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
    scratch: u8[>..]&,
    out:     ProblemDetails&,
) -> bool {
    if key == "status" {
        out.status = json::read_int(reader) as i32;
        return true;
    }
    if key == "type" {
        let s = json::read_string(reader, scratch);
        guard s.len <= out.type_uri.cap else { return false; }
        out.type_uri.clear();
        out.type_uri.append(s);
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
    scratch: u8[>..]&,
    out:     ProblemDetails&,
) -> bool {
    if key == "title" {
        let s = json::read_string(reader, scratch);
        guard s.len <= out.title.cap else { return false; }
        out.title.clear();
        out.title.append(s);
        return true;
    }
    if key == "detail" {
        let s = json::read_string(reader, scratch);
        guard s.len <= out.detail.cap else { return false; }
        out.detail.clear();
        out.detail.append(s);
        return true;
    }
    if key == "instance" {
        let s = json::read_string(reader, scratch);
        guard s.len <= out.instance.cap else { return false; }
        out.instance.clear();
        out.instance.append(s);
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
    var scratch: u8[>..] = [];

    json::each_member(reader) { key =>
        if !parse_problem_core_fields(key, reader, scratch, out) &&
           !parse_problem_descriptive_fields(key, reader, scratch, out) {
            json::skip(reader);
        }
    };

    guard json::finish(reader) else { return false; }
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
