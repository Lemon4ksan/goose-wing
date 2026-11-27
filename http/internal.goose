// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Internal helpers for `http` (http/internal.goose).
namespace http_internal;

import std;
import core;
import rfc.http;
import http.headers;
import http.mime;
import http.multipart;
import http.request;

// ---- http/multipart.goose internal helpers ----

// Validates an unquoted boundary character sequence according to RFC 2046 Section 5.1.1.
fn validate_raw_boundary_chars(boundary: const u8[:]) -> bool {
    guard boundary.len >= 1 && boundary.len <= rfc::MULTIPART_MAX_BOUNDARY_LEN else { return false; }
    // RFC 2046 Section 5.1.1: The boundary parameter must not end with a space.
    if boundary[boundary.len - 1] == ' ' {
        return false;
    }
    for b in boundary {
        if core::is_ascii_alphanumeric(b) {
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
    if is_closing_boundary_at(body, pos) {
        return true;
    }
    let after_pad = body[pos..].trim_lws_start();
    return (after_pad.len >= 2 && after_pad[0] == '\r' && after_pad[1] == '\n') ||
           (after_pad.len >= 1 && after_pad[0] == '\n');
}

fn is_closing_boundary_at(body: const u8[:], cursor: i64) -> bool {
    guard cursor <= body.len else { return false; }
    let rem = body[cursor..];
    if rem.len >= 2 && rem[0] == '-' && rem[1] == '-' {
        let after_close = rem[2..].trim_lws_start();
        return after_close.len == 0 ||
               (after_close.len >= 2 && after_close[0] == '\r' && after_close[1] == '\n') ||
               (after_close.len >= 1 && after_close[0] == '\n');
    }
    return false;
}

fn epilogue_bytes_after_closing(body: const u8[:], cursor: i64) -> i64 {
    guard cursor + 2 <= body.len else { return 0; }
    let after_pad = body[cursor + 2..].trim_lws_start();
    if after_pad.len >= 2 && after_pad[0] == '\r' && after_pad[1] == '\n' {
        return after_pad.len - 2;
    }
    if after_pad.len >= 1 && after_pad[0] == '\n' {
        return after_pad.len - 1;
    }
    return after_pad.len;
}

fn find_initial_boundary(
    body:               const u8[:],
    init_delim:         const u8[:],
    max_preamble_bytes: i64 = 4096,
) -> i64 {
    let limit = min(body.len - init_delim.len, max(0, max_preamble_bytes));
    var cursor: i64 = 0;
    while cursor <= limit {
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

// Strips directory paths and rejects unsafe multipart filenames (`.`, `..`, empty, NUL, CTLs, `:`).
//
// Example:
//   raw_fn = "../../etc/passwd", out = []
//   returns: true, out = "passwd"
fn sanitize_multipart_filename(raw_fn: const u8[:], out: u8[..256]&) -> bool {
    out.clear();
    for b in raw_fn {
        guard b >= 0x20 && b != 0x7F else { return false; }
    }
    let slash_idx = raw_fn.last_index_of_byte('/');
    let bslash_idx = raw_fn.last_index_of_byte('\\');
    let sep_idx = max(slash_idx, bslash_idx);
    let base = if sep_idx >= 0 { raw_fn[sep_idx + 1..] } else { raw_fn };
    guard base.len > 0 && base != "." && base != ".." && !base.contains_byte(':') else {
        return false;
    }
    return out.try_set(base);
}

// Decodes an RFC 8187 UTF-8 `filename*` ext-value (`UTF-8''...`), validates UTF-8, and sanitizes basename.
//
// Example:
//   ext_val = "UTF-8''hello%20world.txt", out = []
//   returns: true, out = "hello world.txt"
fn decode_rfc8187_filename(ext_val: const u8[:], out: u8[..256]&) -> bool {
    out.clear();
    let after_cs, has_cs = ext_val.strip_prefix_fold("utf-8'");
    guard has_cs else { return false; }
    let _, encoded, has_lang = after_cs.split_once_byte('\'');
    guard has_lang else { return false; }
    for b, i in encoded {
        if b == '%' {
            let valid_hex = i + 2 < encoded.len &&
                core::is_ascii_hexdigit(encoded[i + 1]) &&
                core::is_ascii_hexdigit(encoded[i + 2]);
            guard valid_hex else { return false; }
        }
    }
    var decoded: u8[..256] = [];
    guard core::percent_decode(encoded, decoded) && core::validate_utf8(decoded[..]) else {
        return false;
    }
    return sanitize_multipart_filename(decoded[..], out);
}

fn populate_part_metadata(part_headers: const http::HeaderMap&, part: http::MultipartPart&) -> bool {
    let disp_raw = http::get_header(part_headers, "content-disposition");
    if disp_raw.len > 0 {
        let mt, mt_ok = http::parse_content_disposition(disp_raw);
        guard mt_ok && mt.type_name[..].eq_ascii_fold("form-data") else { return false; }
        let p_name = http::param(mt, "name");
        guard part.name.try_append(p_name) else { return false; }
        if http::has_param(mt, "filename*") {
            let ext_fn = http::param(mt, "filename*");
            guard decode_rfc8187_filename(ext_fn, part.filename) else { return false; }
        } else if http::has_param(mt, "filename") {
            let raw_fn = http::param(mt, "filename");
            guard sanitize_multipart_filename(raw_fn, part.filename) else { return false; }
        }
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
    body:               const u8[:],
    cursor:             i64&,
    part_delim:         const u8[:],
    shift_table:        const u16[256]&,
    options:            const http::MultipartOptions&,
    total_memory_used:  i64&,
    total_part_headers: i64&,
    msg:                http::MultipartMessage&,
) -> http::MultipartError {
    let saved_cursor = cursor;
    let saved_mem = total_memory_used;
    let saved_hdrs = total_part_headers;
    var committed = false;
    defer if !committed {
        cursor = saved_cursor;
        total_memory_used = saved_mem;
        total_part_headers = saved_hdrs;
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
    guard part_headers.entries.len <= options.max_headers_per_part else {
        return http::MultipartError.InvalidPartHeaders;
    }
    guard options.max_total_part_headers - total_part_headers >= part_headers.entries.len else {
        return http::MultipartError.InvalidPartHeaders;
    }
    total_part_headers += part_headers.entries.len;

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
    if part.filename.len == 0 && part_data.len > options.max_non_file_field_bytes {
        return http::MultipartError.ExceededMaxMemory;
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
    for &r in ranges {
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
    for &r in ranges {
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
