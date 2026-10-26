// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// IETF draft-ietf-httpbis-resumable-upload-14 (Resumable Uploads for HTTP).
// Standardizes chunked, interrupted, and resumable data uploads replacing legacy protocols (tus.io).
// Uses RFC 8941 Structured Fields for Upload-Offset and Upload-Complete (?0 / ?1).
namespace wing;

import std;
import client.request;
import client.response;

// ---- 1. Resumable Uploads Constants (draft-14) -------------------------------

const HEADER_UPLOAD_OFFSET: const u8[:] = "Upload-Offset";
const HEADER_UPLOAD_COMPLETE: const u8[:] = "Upload-Complete";
const MIME_PARTIAL_UPLOAD: const u8[:] = "application/partial-upload";
const STATUS_RESUMABLE_SUPPORTED: i32 = 104;

// ---- 2. Resumable Upload Session State ---------------------------------------

struct ResumableUploadState {
    upload_url: u8[..512] = [],
    total_size: i64 = 0,
    offset: i64 = 0,
    complete: bool = false,
    chunk_size: i64 = 65536,
}

// Initializes a resumable upload session
fn init_resumable_upload(total_size: i64, chunk_size: i64 = 65536) -> ResumableUploadState {
    return ResumableUploadState {
        total_size: total_size,
        chunk_size: chunk_size,
        offset: 0,
        complete: false,
        ..
    };
}

// ---- 3. Header Formatting and Parsing Helpers -------------------------------

// Formats an integer to string buffer
fn upload_format_int<B>(out: B&, val: i64) {
    if val == 0 {
        out.push('0' as u8);
        return;
    }
    var v = val;
    var digits: u8[..32] = [];
    while v > 0 {
        let d = (v % 10) as u8;
        digits.push(('0' as u8) + d);
        v /= 10;
    }
    var i = digits.len;
    while i > 0 {
        i -= 1;
        out.push(digits[i]);
    }
}

// Parses an integer from header value
fn parse_upload_int(val: const u8[:]) -> i64 {
    var num: i64 = 0;
    var started = false;
    for b in val {
        if b >= '0' && b <= '9' {
            num = num * 10 + (b - '0');
            started = true;
        } else if started {
            break;
        }
    }
    return num;
}

// Parses RFC 8941 Structured Field boolean: ?1 = true, ?0 = false
fn parse_upload_boolean(val: const u8[:]) -> bool {
    var i = 0;
    while i < val.len && (val[i] == ' ' || val[i] == '\t') {
        i += 1;
    }
    if i + 1 < val.len && val[i] == '?' {
        return val[i + 1] == '1';
    }
    return false;
}

// ---- 4. Request Formatting (draft-ietf-httpbis-resumable-upload-14) ---------

// Formats a POST request to initiate a resumable upload resource
fn format_upload_creation_request(
    req: Request&,
    endpoint: const u8[:],
    first_chunk: const u8[:],
    is_complete: bool,
) {
    req.method.clear();
    req.method.append("POST");
    req.url.clear();
    req.url.append(endpoint);

    // Upload-Complete: ?0 or ?1
    set_header(req, HEADER_UPLOAD_COMPLETE, if is_complete { "?1" } else { "?0" });

    if first_chunk.len > 0 {
        set_header(req, "Content-Type", MIME_PARTIAL_UPLOAD);
        req.body.clear();
        req.body.append(first_chunk);
    }
}

// Handles response to creation request: extracts Location and Upload-Offset
fn handle_creation_response(res: const Response&, state: ResumableUploadState&) -> bool {
    guard res.status_code == 201 || res.status_code == 200 else { return false; }

    var has_loc = false;
    for idx in res.headers.len {
        let name = res.headers[idx].name[..];
        let val = res.headers[idx].value[..];
        if eq_ascii_fold(name, "location") {
            state.upload_url.clear();
            state.upload_url.append(val);
            has_loc = true;
        } else if eq_ascii_fold(name, HEADER_UPLOAD_OFFSET) {
            state.offset = parse_upload_int(val);
        } else if eq_ascii_fold(name, HEADER_UPLOAD_COMPLETE) {
            state.complete = parse_upload_boolean(val);
        }
    }
    return has_loc;
}

// Formats a PATCH request to append a data chunk to the upload URL
fn format_upload_chunk_request(
    req: Request&,
    state: const ResumableUploadState&,
    chunk: const u8[:],
    is_complete: bool,
) {
    req.method.clear();
    req.method.append("PATCH");
    req.url.clear();
    req.url.append(state.upload_url[..]);

    set_header(req, "Content-Type", MIME_PARTIAL_UPLOAD);

    // Upload-Offset: <offset>
    var offset_str: u8[..32] = [];
    upload_format_int(offset_str, state.offset);
    set_header(req, HEADER_UPLOAD_OFFSET, offset_str[..]);

    // Upload-Complete: ?0 or ?1
    set_header(req, HEADER_UPLOAD_COMPLETE, if is_complete { "?1" } else { "?0" });

    req.body.clear();
    req.body.append(chunk);
}

// Handles response to PATCH chunk append: updates offset and completion
fn handle_chunk_response(res: const Response&, state: ResumableUploadState&) -> bool {
    // 204 No Content is expected for successful PATCH
    guard res.status_code == 204 || res.status_code == 200 else { return false; }

    for idx in res.headers.len {
        let name = res.headers[idx].name[..];
        let val = res.headers[idx].value[..];
        if eq_ascii_fold(name, HEADER_UPLOAD_OFFSET) {
            state.offset = parse_upload_int(val);
        } else if eq_ascii_fold(name, HEADER_UPLOAD_COMPLETE) {
            state.complete = parse_upload_boolean(val);
        }
    }
    return true;
}

// Formats a HEAD request to query the server's current offset after connection interruption
fn format_upload_offset_query(req: Request&, upload_url: const u8[:]) {
    req.method.clear();
    req.method.append("HEAD");
    req.url.clear();
    req.url.append(upload_url);
}

// Handles response to HEAD offset query: restores state.offset
fn handle_offset_query_response(res: const Response&, state: ResumableUploadState&) -> bool {
    guard res.status_code == 204 || res.status_code == 200 else { return false; }

    var found_offset = false;
    for idx in res.headers.len {
        let name = res.headers[idx].name[..];
        let val = res.headers[idx].value[..];
        if eq_ascii_fold(name, HEADER_UPLOAD_OFFSET) {
            state.offset = parse_upload_int(val);
            found_offset = true;
        } else if eq_ascii_fold(name, HEADER_UPLOAD_COMPLETE) {
            state.complete = parse_upload_boolean(val);
        }
    }
    return found_offset;
}
