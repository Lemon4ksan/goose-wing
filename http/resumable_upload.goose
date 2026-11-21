// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// IETF draft-ietf-httpbis-resumable-upload-14 (Resumable Uploads for HTTP).
// Standardizes chunked, interrupted, and resumable data uploads replacing legacy protocols (tus.io).
// Uses RFC 8941 Structured Fields for Upload-Offset and Upload-Complete (?0 / ?1).
namespace http;

import std;
import core from "..";
import .request;
import .response;
import .sfv;

// ---- Resumable Uploads Constants (draft-14) -------------------------------

struct ResumableUploadState {
    upload_url: u8[..512] = [],
    total_size: i64       = 0,
    offset:     i64       = 0,
    complete:   bool      = false,
    chunk_size: i64       = 65536,
}

// Initializes a resumable upload session
fn init_resumable_upload(total_size: i64, chunk_size: i64 = 65536) -> ResumableUploadState {
    return ResumableUploadState {
        total_size: total_size,
        chunk_size: chunk_size,
        offset:     0,
        complete:   false,
        ..
    };
}

// ---- Header Formatting and Parsing Helpers -------------------------------

// Parses an integer from header value (returns 0 and false if invalid or negative).
//
// Example:
//   val = " 1048576 "
//   returns: 1048576, ok = true
fn parse_upload_int(val: const u8[:]) -> i64, bool {
    let parsed, ok = parse_sf_item(val);
    guard ok && parsed.item.kind == SfType.Integer && parsed.item.int_val >= 0 else { return 0, false; }
    return parsed.item.int_val, true;
}

// Parses RFC 8941 Structured Field boolean: ?1 = true, ?0 = false.
//
// Example:
//   val = "?1"
//   returns: true, ok = true
fn parse_upload_boolean(val: const u8[:]) -> bool, bool {
    let parsed, ok = parse_sf_item(val);
    guard ok && parsed.item.kind == SfType.Boolean else { return false, false; }
    return parsed.item.bool_val, true;
}

// ---- Request Formatting (draft-ietf-httpbis-resumable-upload-14) ---------

// Formats a POST request to initiate a resumable upload resource
fn format_upload_creation_request(
    req:         Request&,
    endpoint:    const u8[:],
    first_chunk: const u8[:],
    is_complete: bool,
) {
    let _ = req.method.try_set("POST");
    let _ = req.url.try_set(endpoint);

    // Upload-Complete: ?0 or ?1
    set_header(req, rfc::HEADER_UPLOAD_COMPLETE, if is_complete { "?1" } else { "?0" });

    if first_chunk.len > 0 {
        set_header(req, "Content-Type", rfc::MIME_PARTIAL_UPLOAD);
        req.body.clear();
        req.body.append(first_chunk);
    }
}

// Handles response to creation request: extracts Location and Upload-Offset
fn handle_creation_response(res: const Response&, state: ResumableUploadState&) -> bool {
    guard res.status_code == 201 || res.status_code == 200 else { return false; }

    var has_loc = false;
    var loc_buf: u8[..512] = [];
    var new_offset = state.offset;
    var new_complete = state.complete;
    for &e in res.headers.entries {
        let name = entry_name(res.headers, e);
        let val = entry_value(res.headers, e);
        if name.eq_ascii_fold("location") {
            guard val.len > 0 && loc_buf.try_set(val) else { return false; }
            has_loc = true;
        } else if name.eq_ascii_fold(rfc::HEADER_UPLOAD_OFFSET) {
            let off_val, off_ok = parse_upload_int(val);
            guard off_ok else { return false; }
            new_offset = off_val;
        } else if name.eq_ascii_fold(rfc::HEADER_UPLOAD_COMPLETE) {
            let comp_val, comp_ok = parse_upload_boolean(val);
            guard comp_ok else { return false; }
            new_complete = comp_val;
        }
    }
    guard has_loc || new_complete else { return false; }
    if has_loc {
        guard state.upload_url.try_set(loc_buf[..]) else { return false; }
    }
    state.offset = new_offset;
    state.complete = new_complete;
    return true;
}

// Formats a PATCH request to append a data chunk to the upload URL
fn format_upload_chunk_request(
    req:         Request&,
    state:       const ResumableUploadState&,
    chunk:       const u8[:],
    is_complete: bool,
) {
    let _ = req.method.try_set("PATCH");
    let _ = req.url.try_set(state.upload_url[..]);

    set_header(req, "Content-Type", rfc::MIME_PARTIAL_UPLOAD);

    // Upload-Offset: <offset>
    var offset_str: u8[..32] = [];
    state.offset.format_i64_dec(offset_str);
    set_header(req, rfc::HEADER_UPLOAD_OFFSET, offset_str[..]);

    // Upload-Complete: ?0 or ?1
    set_header(req, rfc::HEADER_UPLOAD_COMPLETE, if is_complete { "?1" } else { "?0" });

    req.body.clear();
    req.body.append(chunk);
}

// Handles response to PATCH chunk append: updates offset and completion
fn handle_chunk_response(res: const Response&, state: ResumableUploadState&) -> bool {
    guard res.status_code == 204 || res.status_code == 200 || res.status_code == 201 else { return false; }

    var found_offset = false;
    var new_offset = state.offset;
    var new_complete = state.complete;
    for &e in res.headers.entries {
        let name = entry_name(res.headers, e);
        let val = entry_value(res.headers, e);
        if name.eq_ascii_fold(rfc::HEADER_UPLOAD_OFFSET) {
            let off_val, off_ok = parse_upload_int(val);
            guard off_ok else { return false; }
            new_offset = off_val;
            found_offset = true;
        } else if name.eq_ascii_fold(rfc::HEADER_UPLOAD_COMPLETE) {
            let comp_val, comp_ok = parse_upload_boolean(val);
            guard comp_ok else { return false; }
            new_complete = comp_val;
        }
    }
    guard found_offset else { return false; }
    state.offset = new_offset;
    state.complete = new_complete;
    return true;
}

// Formats a HEAD request to query the server's current offset after connection interruption
fn format_upload_offset_query(req: Request&, upload_url: const u8[:]) {
    let _ = req.method.try_set("HEAD");
    let _ = req.url.try_set(upload_url);
}

// Handles response to HEAD offset query: restores state.offset
fn handle_offset_query_response(res: const Response&, state: ResumableUploadState&) -> bool {
    guard res.status_code == 204 || res.status_code == 200 else { return false; }

    var found_offset = false;
    var new_offset = state.offset;
    var new_complete = state.complete;
    for &e in res.headers.entries {
        let name = entry_name(res.headers, e);
        let val = entry_value(res.headers, e);
        if name.eq_ascii_fold(rfc::HEADER_UPLOAD_OFFSET) {
            let off_val, off_ok = parse_upload_int(val);
            guard off_ok else { return false; }
            new_offset = off_val;
            found_offset = true;
        } else if name.eq_ascii_fold(rfc::HEADER_UPLOAD_COMPLETE) {
            let comp_val, comp_ok = parse_upload_boolean(val);
            guard comp_ok else { return false; }
            new_complete = comp_val;
        }
    }
    guard found_offset else { return false; }
    state.offset = new_offset;
    state.complete = new_complete;
    return true;
}
