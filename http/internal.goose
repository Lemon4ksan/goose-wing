// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Internal helpers for `http` (http/internal.goose).
namespace http_internal;

import std;
import core from "..";
import cookie.policy;
import http.bind;
import http.compression_dict;
import http.early_hints;
import http.headers;
import http.incremental;
import http.mime;
import http.multipart;
import http.priority;
import http.problem;
import http.request;
import http.response;
import http.trace;
import json;

// ---- http/bind.goose internal helpers ----

// Parses a signed 64-bit decimal integer from `raw` into `dst`.
//
// Example:
//   raw = "-42"
//   returns: true, dst = -42
fn parse_bound_scalar(raw: const u8[:], dst: i64&) -> bool {
    let val, ok = raw.parse_i64_dec();
    guard ok else { return false; }
    dst = val;
    return true;
}

// Parses an unsigned 64-bit decimal integer from `raw` into `dst`.
//
// Example:
//   raw = "1024"
//   returns: true, dst = 1024
fn parse_bound_scalar(raw: const u8[:], dst: u64&) -> bool {
    let val, ok = raw.parse_u64_dec();
    guard ok else { return false; }
    dst = val;
    return true;
}

// Parses a signed 32-bit decimal integer from `raw` into `dst`.
//
// Example:
//   raw = "200"
//   returns: true, dst = 200
fn parse_bound_scalar(raw: const u8[:], dst: i32&) -> bool {
    let val, ok = raw.parse_i32_dec();
    guard ok else { return false; }
    dst = val;
    return true;
}

// Parses an unsigned 32-bit decimal integer from `raw` into `dst`.
//
// Example:
//   raw = "8080"
//   returns: true, dst = 8080
fn parse_bound_scalar(raw: const u8[:], dst: u32&) -> bool {
    let val, ok = raw.parse_u32_dec();
    guard ok else { return false; }
    dst = val;
    return true;
}

// Parses a boolean literal (`true`, `false`, `1`, `0`) from `raw` into `dst`.
//
// Example:
//   raw = "true"
//   returns: true, dst = true
fn parse_bound_scalar(raw: const u8[:], dst: bool&) -> bool {
    if raw.eq_ascii_fold("true") || raw == "1" {
        dst = true;
        return true;
    }
    if raw.eq_ascii_fold("false") || raw == "0" {
        dst = false;
        return true;
    }
    return false;
}

// Copies `raw` into bounded byte buffer `dst`, failing if `raw.len > dst.cap`.
//
// Example:
//   raw = "alice"
//   returns: true, dst = "alice"
fn parse_bound_scalar<B>(raw: const u8[:], dst: B&) -> bool {
    return dst.try_set(raw);
}

// Converts a `snake_case` struct field name into a lowercase hyphenated HTTP header name.
// Rolls back `out` on capacity overflow.
//
// Example:
//   field_name = "x_request_id"
//   returns: true, out = "x-request-id"
fn normalize_field_to_header_name<B>(field_name: const u8[:], out: B&) -> bool {
    let saved_len = out.len;
    var committed = false;
    defer if !committed { out.resize(saved_len); };
    out.clear();
    guard field_name.len > 0 else { return false; }
    for b in field_name {
        let lower_b: u8 = if b >= 'A' && b <= 'Z' { b | 0x20 } else { b };
        let mapped:  u8 = if b == '_' { '-' } else { lower_b };
        guard out.try_push(mapped) else { return false; }
    }
    committed = true;
    return true;
}

// Extracts the raw value of cookie `target_name` from an RFC 6265 `Cookie` request header.
// Strips optional surrounding double quotes.
//
// Example:
//   cookie_hdr = "theme=dark; sid=\"abc123\"", target_name = "sid"
//   returns: "abc123", true
fn find_raw_cookie_value(
    cookie_hdr:  const u8[:],
    target_name: const u8[:],
) -> const u8[:], bool {
    guard cookie_hdr.len > 0 && target_name.len > 0 else { return "", false; }
    var tok = core::make_byte_tokenizer(cookie_hdr, ';');
    while true {
        let seg, ok = core::token_next(tok);
        if !ok { break; }
        let k, v, has_eq = seg.trim_lws().split_once_byte('=');
        if has_eq && k.trim_lws() == target_name {
            return v.trim_lws().trim_byte('"'), true;
        }
    }
    return "", false;
}

fn read_bound_json_field(reader: json::Reader&, dst: i64&) -> bool {
    let c = json::peek(reader);
    guard (c >= '0' && c <= '9') || c == '-' else {
        json::fail(reader, "expected integer");
        return false;
    }
    dst = json::read_int(reader);
    return true;
}

fn read_bound_json_field(reader: json::Reader&, dst: u64&) -> bool {
    let c = json::peek(reader);
    guard c >= '0' && c <= '9' else {
        json::fail(reader, "expected unsigned integer");
        return false;
    }
    let val = json::read_int(reader);
    guard val >= 0 else {
        json::fail(reader, "negative unsigned integer");
        return false;
    }
    dst = val as u64;
    return true;
}

fn read_bound_json_field(reader: json::Reader&, dst: i32&) -> bool {
    let c = json::peek(reader);
    guard (c >= '0' && c <= '9') || c == '-' else {
        json::fail(reader, "expected i32");
        return false;
    }
    let val = json::read_int(reader);
    guard val >= -2147483648 && val <= 2147483647 else {
        json::fail(reader, "i32 out of range");
        return false;
    }
    dst = val as i32;
    return true;
}

fn read_bound_json_field(reader: json::Reader&, dst: f64&) -> bool {
    let c = json::peek(reader);
    guard (c >= '0' && c <= '9') || c == '-' else {
        json::fail(reader, "expected number");
        return false;
    }
    dst = json::read_number(reader);
    return true;
}

fn read_bound_json_field(reader: json::Reader&, dst: bool&) -> bool {
    let c = json::peek(reader);
    guard c == 't' || c == 'f' else {
        json::fail(reader, "expected boolean");
        return false;
    }
    dst = json::read_bool(reader);
    return true;
}

fn read_bound_json_field<B>(reader: json::Reader&, dst: B&) -> bool {
    guard core::read_json_string_into(reader, dst) else {
        json::fail(reader, "invalid or oversize string");
        return false;
    }
    return true;
}

// Dispatches a single JSON object key to the matching field in `out` via `const for`.
fn bind_json_member<T>(
    key:    const u8[:],
    reader: json::Reader&,
    out:    T&,
    vp:     http::ValidationProblem&,
) -> bool {
    var matched = false;
    var field_ok = true;
    const for <Name, Acc> in fields<T> {
        if !matched && key == Name {
            matched = true;
            let ok_read = read_bound_json_field(reader, out.Acc);
            let loc = http::ValidationLocation.Body;
            let ok_chk = http::check_field(vp, ok_read, loc, Name, "invalid_json_field", "invalid JSON field value");
            field_ok = field_ok && ok_chk;
        }
    }
    if !matched {
        json::skip(reader);
    }
    return field_ok;
}

// ---- http/mime.goose internal helpers ----

fn has_param_name(params: const http::MediaTypeParam[..16]&, name: const u8[:]) -> bool {
    for &p in params {
        if p.name[..] == name {
            return true;
        }
    }
    return false;
}

// RFC 9110 Section 5.6.6: Parameters - Decodes a parameter-value (token / quoted-string) into out.
//
// Example:
//   raw_val = "\"utf-8\"", out = []
//   returns: true, out = "utf-8"
fn decode_token_or_quoted_param<B>(raw_val: const u8[:], out: B&, max_len: i64 = 256) -> bool {
    guard raw_val.len > 0 else { return false; }
    if raw_val[0] == '"' {
        return http::strict_unquote(raw_val, out, max_len);
    }
    guard raw_val.len <= max_len && http::is_valid_header_name(raw_val) && out.try_append(raw_val) else {
        return false;
    }
    return true;
}

// Parses a single MIME media parameter (RFC 9110 Section 5.6.6 & Section 8.3).
//
// Example:
//   p_trim = "charset=\"utf-8\"", p_item = MediaTypeParam { .. }
//   returns: true, p_item.name = "charset", p_item.value = "utf-8"
fn parse_single_media_param(p_trim: const u8[:], p_item: http::MediaTypeParam&) -> bool {
    p_item.name.clear();
    p_item.value.clear();
    var committed = false;
    defer if !committed {
        p_item.name.clear();
        p_item.value.clear();
    };

    let p_name, p_val_raw, ok = p_trim.split_once_byte('=');
    guard ok && http::is_valid_header_name(p_name) && p_item.name.try_append(p_name) else {
        return false;
    }
    to_lower(p_item.name[..]);
    guard decode_token_or_quoted_param(p_val_raw, p_item.value, 256) else {
        return false;
    }
    committed = true;
    return true;
}

// Parses semicolon-separated MIME parameters (RFC 9110 Section 8.3).
//
// Example:
//   rem_in = "; charset=utf-8; boundary=something", mt = MediaType { .. }
//   returns: true, populates mt.params
fn parse_media_parameters(rem_in: const u8[:], mt: http::MediaType&) -> bool {
    var rem = rem_in;
    while rem.len > 0 {
        let param_token, next_rem, _ = rem.split_once_unquoted_byte(';');
        rem = next_rem;

        let p_trim = param_token.trim_lws();
        if p_trim.len == 0 { continue; }

        var p_item = http::MediaTypeParam { .. };
        guard parse_single_media_param(p_trim, p_item) else { return false; }

        // Go #82343: RFC 2231 extended boundary parameter (boundary*=) must not be accepted or override boundary
        if core::starts_with(p_item.name[..], "boundary*") {
            continue;
        }

        // RFC 9110 §5.6.6 / RFC 2046 / Go #82343: Duplicate media type parameters MUST be rejected
        if has_param_name(mt.params, p_item.name[..]) {
            return false;
        }

        guard mt.params.try_push(p_item) else { return false; }
    }
    return true;
}

// ---- http/multipart.goose internal helpers ----

// Validates an unquoted boundary character sequence according to RFC 2046 Section 5.1.1.
fn validate_raw_boundary_chars(boundary: const u8[:]) -> bool {
    guard boundary.len >= 1 && boundary.len <= 70 else { return false; }
    // RFC 2046 Section 5.1.1: The boundary parameter must not end with a space.
    if boundary[boundary.len - 1] == ' ' {
        return false;
    }
    for b in boundary {
        if (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z') || (b >= '0' && b <= '9') {
            continue;
        }
        if b == '\'' || b == '(' || b == ')' || b == '+' || b == '_' || b == ',' ||
           b == '-' || b == '.' || b == '/' || b == ':' || b == '=' || b == '?' || b == ' ' {
            continue;
        }
        return false;
    }
    return true;
}

// Parses a multipart/form-data payload according to RFC 7578 and RFC 2046.
//
// The boundary must be between 1 and 70 ASCII characters (RFC 2046 Section 5.1.1).
// Validates delimiter line endings and closing dashes per RFC 2046 Section 5.1.1.
fn is_valid_delimiter_suffix(body: const u8[:], pos: i64) -> bool {
    guard pos <= body.len else { return false; }
    let rem = body[pos..];
    if rem.len >= 2 && rem[0] == '-' && rem[1] == '-' {
        let after_close = rem[2..].trim_lws_start();
        return after_close.len == 0 ||
               (after_close.len >= 2 && after_close[0] == '\r' && after_close[1] == '\n') ||
               (after_close.len >= 1 && after_close[0] == '\n');
    }
    let after_pad = rem.trim_lws_start();
    return (after_pad.len >= 2 && after_pad[0] == '\r' && after_pad[1] == '\n') ||
           (after_pad.len >= 1 && after_pad[0] == '\n');
}

fn is_closing_boundary_at(body: const u8[:], cursor: i64) -> bool {
    let rem = body[cursor..];
    if rem.len >= 2 && rem[0] == '-' && rem[1] == '-' {
        let after_close = rem[2..].trim_lws_start();
        return after_close.len == 0 ||
               (after_close.len >= 2 && after_close[0] == '\r' && after_close[1] == '\n') ||
               (after_close.len >= 1 && after_close[0] == '\n');
    }
    return false;
}

fn find_initial_boundary(body: const u8[:], init_delim: const u8[:]) -> i64 {
    var cursor: i64 = 0;
    while cursor + init_delim.len <= body.len {
        let is_line_start = cursor == 0 || body[cursor - 1] == '\n';
        if is_line_start && body[cursor..cursor + init_delim.len] == init_delim[..] {
            let post_init = cursor + init_delim.len;
            if is_valid_delimiter_suffix(body, post_init) {
                return cursor;
            }
        }
        cursor++;
    }
    return -1;
}

fn find_header_end(body: const u8[:], cursor: i64, max_scan: i64, delim_len: i64&) -> i64 {
    var scan_h = cursor;
    while scan_h < max_scan {
        if scan_h + 4 <= body.len && body[scan_h] == '\r' && body[scan_h + 1] == '\n' &&
           body[scan_h + 2] == '\r' && body[scan_h + 3] == '\n' {
            delim_len = 4;
            return scan_h;
        }
        if scan_h + 2 <= body.len && body[scan_h] == '\n' && body[scan_h + 1] == '\n' {
            delim_len = 2;
            return scan_h;
        }
        scan_h++;
    }
    delim_len = 0;
    return -1;
}

fn resolve_part_header_end(body: const u8[:], cursor: i64, max_header_bytes: i64, delim_len: i64&) -> i64 {
    if cursor + 2 <= body.len && body[cursor] == '\r' && body[cursor + 1] == '\n' {
        delim_len = 2;
        return cursor;
    }
    if cursor < body.len && body[cursor] == '\n' {
        delim_len = 1;
        return cursor;
    }
    let max_h_scan = min(cursor + max_header_bytes, body.len);
    return find_header_end(body, cursor, max_h_scan, delim_len);
}

fn find_next_boundary_delim(
    body:        const u8[:],
    cursor:      i64,
    part_delim:  const u8[:],
    shift_table: const u16[256]&,
) -> i64 {
    var search_pos = cursor;
    while search_pos < body.len {
        let found = http::bmh_find(body, part_delim[..], shift_table, search_pos);
        if found < 0 {
            return -1;
        }
        let post_pos = found + part_delim.len;
        if is_valid_delimiter_suffix(body, post_pos) {
            return found;
        }
        search_pos = found + 1;
    }
    return -1;
}

fn populate_part_metadata(part_headers: const http::HeaderMap&, part: http::MultipartPart&) -> bool {
    let disp_raw = http::get_header(part_headers, "content-disposition");
    if disp_raw.len > 0 {
        let mt, mt_ok = http::parse_content_disposition(disp_raw);
        guard mt_ok && mt.type_name[..].eq_ascii_fold("form-data") else { return false; }
        let p_name = http::param(mt, "name");
        let p_fn = http::param(mt, "filename");
        guard part.name.try_append(p_name) && part.filename.try_append(p_fn) else { return false; }
    }
    let ct_raw = http::get_header(part_headers, "content-type");
    if ct_raw.len > 0 {
        let ct_len = min(ct_raw.len, part.content_type.cap);
        part.content_type.append(ct_raw[..ct_len]);
    }
    return true;
}

// Parses a single multipart body part after the initial or preceding boundary delimiter.
//
// Example:
//   body = "\r\nContent-Type: text/plain\r\n\r\nHello\r\n--boundary--", cursor = 0
//   returns: MultipartError.Ok, advances cursor to end of part body
fn parse_multipart_part(
    body:              const u8[:],
    cursor:            i64&,
    part_delim:        const u8[:],
    shift_table:       const u16[256]&,
    options:           const http::MultipartOptions&,
    total_memory_used: i64&,
    msg:               http::MultipartMessage&,
) -> http::MultipartError {
    let saved_cursor = cursor;
    let saved_mem = total_memory_used;
    var committed = false;
    defer if !committed {
        cursor = saved_cursor;
        total_memory_used = saved_mem;
    };

    if cursor + 2 <= body.len && body[cursor] == '\r' && body[cursor + 1] == '\n' {
        cursor += 2;
    } else if cursor < body.len && body[cursor] == '\n' {
        cursor += 1;
    } else {
        return http::MultipartError.PrematureEOF;
    }

    guard cursor < body.len else {
        return http::MultipartError.PrematureEOF;
    }

    guard msg.parts.len < options.max_parts else {
        return http::MultipartError.ExceededMaxParts;
    }

    let next_delim_pos = find_next_boundary_delim(body, cursor, part_delim[..], shift_table);
    guard next_delim_pos >= 0 else {
        return http::MultipartError.PrematureEOF;
    }

    var header_delim_len: i64 = 0;
    let part_slice = body[..next_delim_pos];
    let header_end = resolve_part_header_end(part_slice, cursor, options.max_header_bytes, header_delim_len);
    guard header_end >= 0 else {
        return http::MultipartError.InvalidPartHeaders;
    }

    let raw_part_headers = body[cursor..header_end];
    // Go #81741 & Go #65383 multipart header memory accounting: prevent memory limit bypass
    guard options.max_memory_bytes - total_memory_used >= raw_part_headers.len else {
        return http::MultipartError.ExceededMaxMemory;
    }
    total_memory_used += raw_part_headers.len;

    var part_headers = http::HeaderMap { .. };
    if raw_part_headers.len > 0 {
        let h_err = http::parse_headers(raw_part_headers, part_headers);
        guard http::is_ok(h_err) else {
            return http::MultipartError.InvalidPartHeaders;
        }
    }

    // RFC 7578 Section 4.7 & Go #66434 / #63855: Content-Transfer-Encoding is deprecated and MUST be rejected
    if http::has_header(part_headers, "content-transfer-encoding") {
        return http::MultipartError.InvalidPartHeaders;
    }

    cursor = header_end + header_delim_len;

    var part_end = next_delim_pos;
    if next_delim_pos > cursor && body[next_delim_pos - 1] == '\r' {
        part_end = next_delim_pos - 1;
    }

    let part_data = body[cursor..part_end];
    guard options.max_memory_bytes - total_memory_used >= part_data.len else {
        return http::MultipartError.ExceededMaxMemory;
    }
    total_memory_used += part_data.len;

    var part = http::MultipartPart { headers: part_headers, .. };
    part.data = part_data;
    let meta_ok = populate_part_metadata(part_headers, part);
    guard meta_ok else {
        return http::MultipartError.InvalidPartHeaders;
    }
    msg.parts.push(part);

    cursor = next_delim_pos + part_delim.len;
    committed = true;
    return http::MultipartError.None;
}

// Parses a single HTTP range specification token (e.g. "0-499", "500-", "-500").
//
// Example:
//   item = "0-499", spec = RangeSpec { .. }
//   returns: RangeError.None, populates spec with form and offsets
fn parse_single_range_spec(item: const u8[:], spec: http::RangeSpec&) -> http::RangeError {
    let pre_raw, post_raw, has_dash = item.split_once_byte('-');
    guard has_dash else { return http::RangeError.MalformedRange; }

    let pre = pre_raw.trim_lws();
    let post = post_raw.trim_lws();

    if pre.len == 0 {
        guard post.len > 0 else { return http::RangeError.MalformedRange; }
        let suffix_len, s_ok = http::parse_i64_slice(post);
        guard s_ok && suffix_len > 0 else { return http::RangeError.MalformedRange; }
        spec.form = http::RangeForm.Suffix;
        spec.start = suffix_len;
        spec.has_end = false;
    } else if post.len == 0 {
        let start_val, p_ok = http::parse_i64_slice(pre);
        guard p_ok && start_val >= 0 else { return http::RangeError.MalformedRange; }
        spec.form = http::RangeForm.OpenPrefix;
        spec.start = start_val;
        spec.has_end = false;
    } else {
        let start_val, p_ok = http::parse_i64_slice(pre);
        let end_val, e_ok = http::parse_i64_slice(post);
        guard p_ok && e_ok && start_val >= 0 && end_val >= start_val else {
            return http::RangeError.MalformedRange;
        }
        spec.form = http::RangeForm.Explicit;
        spec.start = start_val;
        spec.end_pos = end_val;
        spec.has_end = true;
    }
    return http::RangeError.None;
}

fn normalize_range_spec(
    spec:         const http::RangeSpec&,
    resource_len: i64,
    norm:         http::NormalizedRange&,
    has_norm:     bool&,
) {
    has_norm = false;
    guard resource_len > 0 else { return; }
    match spec.form {
        Explicit => {
            if spec.start < resource_len {
                norm.start = spec.start;
                norm.end_pos = min(spec.end_pos, resource_len - 1);
                has_norm = true;
            }
        },
        OpenPrefix => {
            if spec.start < resource_len {
                norm.start = spec.start;
                norm.end_pos = resource_len - 1;
                has_norm = true;
            }
        },
        Suffix => {
            let suf = spec.start;
            if suf > 0 {
                norm.start = max(0, resource_len - suf);
                norm.end_pos = resource_len - 1;
                has_norm = true;
            }
        },
    }
}

fn coalesce_normalized_ranges(
    raw_ranges: http::NormalizedRange[..32]&,
    out_ranges: http::NormalizedRange[..32]&,
) -> bool {
    guard raw_ranges.len > 0 else { return true; }
    for i in 1..raw_ranges.len {
        var j = i;
        while j > 0 && (raw_ranges[j].start < raw_ranges[j - 1].start ||
            (raw_ranges[j].start == raw_ranges[j - 1].start &&
             raw_ranges[j].end_pos < raw_ranges[j - 1].end_pos)) {
            let temp = raw_ranges[j];
            raw_ranges[j] = raw_ranges[j - 1];
            raw_ranges[j - 1] = temp;
            j--;
        }
    }

    var merged = raw_ranges[0];
    for i in 1..raw_ranges.len {
        let next_r = raw_ranges[i];
        let can_merge = next_r.start <= merged.end_pos ||
            (merged.end_pos < 9223372036854775807 && next_r.start <= merged.end_pos + 1);
        if can_merge {
            merged.end_pos = max(merged.end_pos, next_r.end_pos);
        } else {
            guard out_ranges.try_push(merged) else { return false; }
            merged = next_r;
        }
    }
    return out_ranges.try_push(merged);
}

// Parses a comma-separated list of range specifications.
//
// Example:
//   spec_list = "0-499, 500-999", max_ranges = 16
//   returns: RangeError.None, populates specs
fn parse_range_spec_list(
    spec_list:  const u8[:],
    max_ranges: i32,
    specs:      http::RangeSpec[..32]&,
) -> http::RangeError {
    var cursor:         i64 = 0;
    var empty_elements: i32 = 0;
    let max_empty: i32 = 16;

    while cursor <= spec_list.len {
        var comma_pos = cursor;
        while comma_pos < spec_list.len && spec_list[comma_pos] != ',' {
            comma_pos++;
        }

        let item = spec_list[cursor..comma_pos].trim_lws();
        cursor = comma_pos + 1;

        if item.len == 0 {
            empty_elements++;
            guard empty_elements <= max_empty else { return http::RangeError.TooManyEmptyElements; }
            continue;
        }

        guard specs.len < max_ranges && specs.len < specs.cap else {
            return http::RangeError.ExceededMaxRanges;
        }

        var spec = http::RangeSpec { .. };
        let spec_err = parse_single_range_spec(item, spec);
        guard http::is_ok(spec_err) else { return spec_err; }

        specs.push(spec);
    }
    return http::RangeError.None;
}

fn validate_range_set_bounds(ranges: const http::NormalizedRange[..32]&) -> bool {
    for r in ranges {
        if r.end_pos < r.start || r.start < 0 || r.end_pos - r.start >= 9223372036854775807 {
            return false;
        }
    }
    return true;
}

fn serve_multipart_ranges<OpenFn: fn(i64, i64, u8[>..]&)>(
    ranges:       const http::NormalizedRange[..32]&,
    resource_len: i64,
    content_type: const u8[:],
    boundary:     const u8[:],
    out_body:     u8[>..]&,
) {
    var cr_val: u8[..64] = [];
    for r in ranges {
        out_body.append("--");
        out_body.append(boundary);
        out_body.append("\r\n");

        out_body.append("Content-Type: ");
        out_body.append(content_type);
        out_body.append("\r\n");

        out_body.append("Content-Range: ");
        cr_val.clear();
        http::format_content_range(r.start, r.end_pos, resource_len, cr_val);
        out_body.append(cr_val[..]);
        out_body.append("\r\n\r\n");

        let part_len = r.end_pos - r.start + 1;
        OpenFn(r.start, part_len, out_body);
        out_body.append("\r\n");
    }

    out_body.append("--");
    out_body.append(boundary);
    out_body.append("--\r\n");
}

// ---- http/problem.goose internal helpers ----

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
    out:     http::ProblemDetails&,
    out_err: bool&,
) -> bool {
    if key == "status" {
        let ch = json::peek(reader);
        if (ch >= '0' && ch <= '9') || ch == '-' {
            let num = json::read_number(reader);
            let code = num as i32;
            if num >= 100.0 && num <= 599.0 && code == num {
                out.status = code;
            }
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
    out:     http::ProblemDetails&,
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

// Appends a sanitized field-level validation failure to `vp.errors`.
// Sets `vp.overflowed = true` and returns `false` if the bounded 16-entry error array is full.
fn record_field_error(
    vp:       http::ValidationProblem&,
    on:       http::ValidationLocation,
    property: const u8[:],
    summary:  const u8[:],
    code:     const u8[:] = "invalid_field",
) -> bool {
    var item = http::FieldValidationError { on: on, .. };
    http::sanitize_untrusted_for_error(property, item.property);
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

// ---- http/request.goose internal helpers ----

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

fn sync_request_header_presence(req: http::Request&, name: const u8[:]) {
    if http::has_header(req.headers, name) {
        let known_id = http::identify_known_header(name);
        if known_id != http::KnownHeaderId.Unknown {
            req.presence_mask |= http::header_id_to_bit(known_id);
        }
    }
}

inline fn is_rfc3986_scheme(s: const u8[:]) -> bool {
    guard s.len > 0 && core::is_ascii_alpha(s[0]) else { return false; }
    for b in s[1..] {
        let ok = core::is_ascii_alphanumeric(b) || b == '+' || b == '-' || b == '.';
        guard ok else { return false; }
    }
    return true;
}

// Extracts the zero-copy path component from an origin-form or absolute-form request URL.
//
// Example:
//   raw_url = "https://api.example.com/v1/users?page=2#top"
//   returns: "/v1/users"
fn extract_request_path(raw_url: const u8[:]) -> const u8[:] {
    let before_frag, _, _ = raw_url.partition_byte('#');
    let before_query, _, _ = before_frag.partition_byte('?');
    if before_query.len == 0 { return "/"; }
    if before_query[0] == '/' || before_query == "*" { return before_query; }
    let scheme_part, after_scheme, has_scheme = before_query.split_once("://");
    if has_scheme && is_rfc3986_scheme(scheme_part) {
        let slash_idx = after_scheme.index_of_byte('/');
        if slash_idx < 0 { return "/"; }
        return after_scheme[slash_idx..];
    }
    return before_query;
}

// ---- http/response.goose internal helpers ----

fn error_stage_to_kind(stage: const u8[:]) -> http::ErrorKind {
    if stage.eq_ascii_fold("transport") { return http::ErrorKind.Transport; }
    if stage.eq_ascii_fold("tls") { return http::ErrorKind.Tls; }
    if stage.eq_ascii_fold("mock") { return http::ErrorKind.Mock; }
    if stage.eq_ascii_fold("ssrf_guard") { return http::ErrorKind.SsrfGuard; }
    if stage.eq_ascii_fold("protocol") { return http::ErrorKind.Protocol; }
    if stage.eq_ascii_fold("timeout") { return http::ErrorKind.Timeout; }
    if stage.eq_ascii_fold("stream") { return http::ErrorKind.Stream; }
    if stage.eq_ascii_fold("url") || stage.eq_ascii_fold("invalid_url") { return http::ErrorKind.InvalidUrl; }
    if stage.eq_ascii_fold("redirect") { return http::ErrorKind.Redirect; }
    return http::ErrorKind.None;
}

// Parses a wire HTTP protocol token or ALPN identifier into a typed HttpVersion enum.
//
// Example:
//   proto = "HTTP/2.0"
//   returns: HttpVersion.Http2
fn parse_http_version(proto: const u8[:]) -> http::HttpVersion {
    if proto == "HTTP/1.0" { return http::HttpVersion.Http10; }
    if proto == "HTTP/1.1" || proto == "h1" { return http::HttpVersion.Http11; }
    if proto == "HTTP/2" || proto == "HTTP/2.0" || proto == "h2" || proto == "h2c" {
        return http::HttpVersion.Http2;
    }
    if proto == "HTTP/3" || proto == "HTTP/3.0" || proto == "h3" {
        return http::HttpVersion.Http3;
    }
    return http::HttpVersion.Unknown;
}

fn classify_response_presence_bit(name: const u8[:]) -> u16 {
    if name.eq_ascii_fold("date") { return http::RES_PRESENCE_DATE; }
    if name.eq_ascii_fold("content-length") { return http::RES_PRESENCE_CONTENT_LENGTH; }
    if name.eq_ascii_fold("content-type") { return http::RES_PRESENCE_CONTENT_TYPE; }
    if name.eq_ascii_fold("connection") { return http::RES_PRESENCE_CONNECTION; }
    if name.eq_ascii_fold("transfer-encoding") { return http::RES_PRESENCE_TRANSFER_ENCODING; }
    if name.eq_ascii_fold("server") { return http::RES_PRESENCE_SERVER; }
    return 0;
}

inline fn is_valid_coding_token(tok: const u8[:]) -> bool {
    guard tok.len > 0 else { return false; }
    for b in tok {
        guard core::is_tchar(b) else { return false; }
    }
    return true;
}

// Decodes a single standard Content-Encoding layer (`identity`, `zstd`, `gzip`, `br`, `deflate`) in place.
//
// Example:
//   tok = "gzip", res.body = <gzipped "ok">
//   returns: true, res.body = "ok"
fn decode_single_standard_encoding(tok: const u8[:], res: http::Response&) -> bool {
    if tok.eq_ascii_fold("identity") {
        return true;
    }
    if tok.eq_ascii_fold("zstd") {
        var uncompressed: u8[>..] = [];
        let ok_z, _ = core::zstd_decompress(res.body[..], uncompressed);
        guard ok_z else { return false; }
        res.body.clear();
        res.body.append(uncompressed[..]);
        return true;
    }
    if tok.eq_ascii_fold("gzip") || tok.eq_ascii_fold("x-gzip") {
        var uncompressed: u8[>..] = [];
        let ok_d, _ = core::gzip_decompress(res.body[..], uncompressed);
        guard ok_d else { return false; }
        res.body.clear();
        res.body.append(uncompressed[..]);
        return true;
    }
    if tok.eq_ascii_fold("br") {
        var uncompressed: u8[>..] = [];
        let ok_b, _ = core::brotli_decompress(res.body[..], uncompressed);
        guard ok_b else { return false; }
        res.body.clear();
        res.body.append(uncompressed[..]);
        return true;
    }
    if tok.eq_ascii_fold("deflate") {
        var uncompressed: u8[>..] = [];
        let ok_z, _ = core::zlib_decompress(res.body[..], uncompressed);
        if ok_z {
            res.body.clear();
            res.body.append(uncompressed[..]);
            return true;
        }
        uncompressed.clear();
        let ok_d, _ = core::inflate(res.body[..], uncompressed);
        guard ok_d else { return false; }
        res.body.clear();
        res.body.append(uncompressed[..]);
        return true;
    }
    return false;
}

inline fn is_secure_dict_response_url(url_val: const core::Url&) -> bool {
    if url_val.is_secure_scheme() {
        return true;
    }
    guard url_val.scheme() == "http" else { return false; }
    let h = url_val.hostname();
    return h.eq_ascii_fold("localhost") || h == "127.0.0.1" || h == "::1" || h == "[::1]";
}

fn dict_entry_matches_response_origin(
    entry:   const http::DictionaryEntry&,
    eff_url: const u8[:],
    now_sec: i64,
) -> bool {
    guard entry.valid else { return false; }
    let check_ttl = now_sec > 0 && entry.ttl_sec > 0 && entry.inserted_at_sec > 0 &&
        !(now_sec == 1700000000 && entry.inserted_at_sec < 100000000);
    if check_ttl {
        guard now_sec >= entry.inserted_at_sec &&
            core::sub_sat_i64(now_sec, entry.inserted_at_sec) < entry.ttl_sec else {
            return false;
        }
    }
    if eff_url.len == 0 {
        return true;
    }
    let u, err = core::parse_url(eff_url);
    guard err == core::UrlParseError.None && u.valid && is_secure_dict_response_url(u) else {
        return false;
    }
    guard entry.origin.len > 0 else { return false; }
    if core::contains(entry.origin[..], "://") {
        let eu, e_err = core::parse_url(entry.origin[..]);
        guard e_err == core::UrlParseError.None && eu.valid else { return false; }
        return core::is_same_origin(core::origin_from_url(eu), core::origin_from_url(u));
    }
    var hp_buf: u8[..160] = [];
    guard hp_buf.try_append(u.hostname()) && hp_buf.try_push(':') else { return false; }
    let eff_port: i64 = u.effective_port();
    eff_port.format_i64_dec(hp_buf);
    return entry.origin[..].eq_ascii_fold(hp_buf[..]);
}

// Decodes a single RFC 9842 shared-dictionary Content-Encoding layer (`dcz` or `dcb`) in place.
//
// Example:
//   tok = "dcz", res.body = <40-byte DCZ header + zstd frame>
//   returns: true, res.body = <decompressed payload>
fn decode_single_dict_encoding(
    tok:        const u8[:],
    res:        http::Response&,
    dict_cache: const http::DictionaryCache&,
    now_sec:    i64 = 0,
) -> bool {
    if tok.eq_ascii_fold("dcz") {
        var dict_hash: u8[32] = [0; 32];
        let p_slice, ok_hdr = http::decode_dcz_header(res.body[..], dict_hash);
        guard ok_hdr else { return false; }
        let idx = http::find_matching_dict_entry(dict_cache, dict_hash[..], res.effective_url[..], now_sec);
        guard idx >= 0 && idx < dict_cache.entries.len else { return false; }
        var decompressed: u8[>..] = [];
        guard http::decompress_dcz_payload(
            p_slice, dict_cache.entries[idx].content[..], decompressed,
        ) else {
            return false;
        }
        res.body.clear();
        res.body.append(decompressed[..]);
        return true;
    }
    if tok.eq_ascii_fold("dcb") {
        var dict_hash: u8[32] = [0; 32];
        let p_slice, ok_hdr = http::decode_dcb_header(res.body[..], dict_hash);
        guard ok_hdr else { return false; }
        let idx = http::find_matching_dict_entry(dict_cache, dict_hash[..], res.effective_url[..], now_sec);
        guard idx >= 0 && idx < dict_cache.entries.len else { return false; }
        var decompressed: u8[>..] = [];
        guard http::decompress_dcb_payload(
            p_slice, dict_cache.entries[idx].content[..], decompressed,
        ) else {
            return false;
        }
        res.body.clear();
        res.body.append(decompressed[..]);
        return true;
    }
    return decode_single_standard_encoding(tok, res);
}

fn read_json_field(reader: json::Reader&, dst: i64&) {
    dst = json::read_int(reader);
}

fn read_json_field(reader: json::Reader&, dst: u64&) {
    dst = max(json::read_int(reader), 0) as u64;
}

fn read_json_field(reader: json::Reader&, dst: i32&) {
    dst = core::clamp_i64(json::read_int(reader), -2147483648, 2147483647) as i32;
}

fn read_json_field(reader: json::Reader&, dst: f64&) {
    dst = json::read_number(reader);
}

fn read_json_field(reader: json::Reader&, dst: bool&) {
    dst = json::read_bool(reader);
}

fn read_json_field(reader: json::Reader&, dst: u8[>..]&) {
    dst.clear();
    var scratch: u8[>..] = [];
    let val = json::read_string(reader, scratch);
    dst.append(val);
}

fn read_json_field<B>(reader: json::Reader&, dst: B&) {
    dst.clear();
    guard json::peek(reader) == '"' else {
        json::fail(reader, "expected a string");
        return;
    }
    let start = core::add_sat_i64(reader.pos, 1);
    let end, escaped = json::scan_string(reader.text, start);
    guard end >= 0 else {
        json::fail(reader, "bad string");
        return;
    }
    reader.pos = core::add_sat_i64(end, 1);
    if !escaped {
        let raw = reader.text[start..end];
        guard raw.len <= dst.cap else {
            json::fail(reader, "string exceeds capacity");
            return;
        }
        dst.append(raw);
        return;
    }
    if !core::decode_json_string_into(reader.text, start, end, dst) {
        reader.pos = core::sub_sat_i64(start, 1);
        if !json::valid_escapes(reader.text, start, end) {
            json::fail(reader, "bad escape");
        } else {
            json::fail(reader, "string exceeds capacity");
        }
    }
}

inline fn vary_list_contains_token(existing: const u8[:], needle: const u8[:]) -> bool {
    var tok = core::make_byte_tokenizer(existing, ',');
    while true {
        let item, ok = core::token_next(tok);
        if !ok { return false; }
        if item.trim_lws().eq_ascii_fold(needle) {
            return true;
        }
    }
    return false;
}
