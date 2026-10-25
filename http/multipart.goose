// Multipart form-data parsing (RFC 7578, RFC 2046) and HTTP range request
// handling (RFC 9110 Section 14, Section 13.1.5).
namespace wing;

import std;
import http.headers;
import http.mime;

// ---- multipart errors & options --------------------------------------------

enum MultipartError {
    None,
    EmptyInput,
    InvalidBoundaryLength,      // outside 1..70 characters (RFC 2046 Section 5.1.1)
    InvalidBoundaryCharacters,
    MissingBoundaryDelimiter,
    PrematureEOF,
    ExceededMaxParts,
    ExceededMaxMemory,
    ExceededMaxPayload,
    InvalidPartHeaders,
}

fn is_ok(err: MultipartError) -> bool {
    return err == MultipartError.None;
}

struct MultipartOptions {
    max_parts: i32 = 64,
    max_memory_bytes: i64 = 12582912,       // 12 MB in-memory field buffering quota (ovr framework style)
    max_payload_bytes: i64 = 67108864,      // 64 MB maximum overall payload
    max_header_bytes: i64 = 8192,           // 8 KB per-part header block
}

fn default_multipart_options() -> MultipartOptions {
    return MultipartOptions { .. };
}

// ---- multipart part and message model --------------------------------------

struct MultipartPart {
    name: u8[..64] = [],
    filename: u8[..256] = [],
    content_type: u8[..64] = [],
    headers: HeaderMap = HeaderMap { .. },
    data: const u8[:] = "",
}

struct MultipartMessage {
    valid: bool = true,
    parts: MultipartPart[>..] = [],
}

// ---- boyer-moore-horspool search -------------------------------------------

// Computes the Boyer-Moore-Horspool shift table for needle. Shift values
// are u16 so jump offsets up to 65535 bytes do not overflow to zero.
fn build_bmh_shift_table(needle: const u8[:], table: u16[256]&) {
    let needle_len = needle.len;
    let default_shift = core::ct_min_i64(needle_len, 65535) as u16;

    for i in 256 {
        table[i] = default_shift;
    }

    guard needle_len > 1 else { return; }
    for i in 0..needle_len - 1 {
        let b = needle[i] as i64;
        let shift = (needle_len - 1 - i) as u16;
        table[b] = shift;
    }
}

// The index of needle in haystack starting from start_pos, or -1.
fn bmh_find(haystack: const u8[:], needle: const u8[:], table: const u16[256]&, start_pos: i64 = 0) -> i64 {
    let n_len = needle.len;
    let h_len = haystack.len;
    guard n_len > 0 && h_len >= n_len else { return -1; }

    var i = start_pos + n_len - 1;
    while i < h_len {
        var k: i64 = 0;
        while k < n_len && haystack[i - k] == needle[n_len - 1 - k] {
            k++;
        }
        if k == n_len {
            return i - n_len + 1;
        }
        let last_b = haystack[i] as i64;
        let shift = table[last_b] as i64;
        // Shift at least one byte on mismatch.
        i += if shift > 0 { shift } else { 1 };
    }
    return -1;
}

// Whether boundary contains only characters allowed by RFC 2046 Section 5.1.1.
fn validate_boundary_string(boundary: const u8[:]) -> bool {
    guard boundary.len >= 1 && boundary.len <= 70 else { return false; }
    for b in boundary {
        if (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z') || (b >= '0' && b <= '9') {
            continue;
        }
        if b == '\'' || b == '(' || b == ')' || b == '+' || b == '_' || b == ',' ||
           b == '-' || b == '.' || b == '/' || b == ':' || b == '=' || b == '?' {
            continue;
        }
        return false;
    }
    return true;
}

// ---- multipart parsing -----------------------------------------------------

// Parses a multipart/form-data payload according to RFC 7578 and RFC 2046.
//
// The boundary must be between 1 and 70 ASCII characters (RFC 2046 Section 5.1.1).
fn find_initial_boundary(body: const u8[:], init_delim: const u8[:]) -> i64 {
    var cursor: i64 = 0;
    while cursor + init_delim.len <= body.len {
        if body[cursor..cursor + init_delim.len] == init_delim[..] {
            if cursor == 0 || body[cursor - 1] == '\n' {
                let post_init = cursor + init_delim.len;
                var pad_init = post_init;
                while pad_init < body.len && (body[pad_init] == ' ' || body[pad_init] == '\t') {
                    pad_init++;
                }
                if (pad_init + 2 <= body.len && body[pad_init] == '-' && body[pad_init + 1] == '-') ||
                   (pad_init + 2 <= body.len && body[pad_init] == '\r' && body[pad_init + 1] == '\n') ||
                   (pad_init < body.len && body[pad_init] == '\n') {
                    return cursor;
                }
            }
        }
        cursor++;
    }
    return -1;
}

fn find_header_end(body: const u8[:], cursor: i64, max_scan: i64, delim_len: i64&) -> i64 {
    var scan_h = cursor;
    while scan_h < max_scan {
        if scan_h + 4 <= body.len && body[scan_h] == '\r' && body[scan_h + 1] == '\n' && body[scan_h + 2] == '\r' && body[scan_h + 3] == '\n' {
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

fn find_next_boundary_delim(body: const u8[:], cursor: i64, part_delim: const u8[:], shift_table: const u16[256]&) -> i64 {
    var search_pos = cursor;
    while search_pos < body.len {
        let found = bmh_find(body, part_delim[..], shift_table, search_pos);
        if found < 0 {
            return -1;
        }
        let post_pos = found + part_delim.len;
        var pad_pos = post_pos;
        while pad_pos < body.len && (body[pad_pos] == ' ' || body[pad_pos] == '\t') {
            pad_pos++;
        }
        if (pad_pos + 2 <= body.len && body[pad_pos] == '-' && body[pad_pos + 1] == '-') ||
           (pad_pos + 2 <= body.len && body[pad_pos] == '\r' && body[pad_pos + 1] == '\n') ||
           (pad_pos < body.len && body[pad_pos] == '\n') {
            return found;
        }
        search_pos = found + 1;
    }
    return -1;
}

fn populate_part_metadata(part_headers: const HeaderMap&, part: MultipartPart&) {
    let disp_raw = get_header(part_headers, "content-disposition");
    if disp_raw.len > 0 {
        let mt, mt_ok = parse_content_disposition(disp_raw);
        if mt_ok {
            let p_name = param(mt, "name");
            part.name.append(p_name);
            let p_fn = param(mt, "filename");
            part.filename.append(p_fn);
        }
    }
    let ct_raw = get_header(part_headers, "content-type");
    if ct_raw.len > 0 {
        part.content_type.append(ct_raw);
    }
}

// Delimiters are matched using a 16-bit Boyer-Moore-Horspool shift table,
// requiring CRLF, LF, or '--' immediately after the boundary to avoid prefix
// collisions. Total memory and part counts are bounded by options.
fn parse_multipart(body: const u8[:], boundary: const u8[:], options: MultipartOptions = default_multipart_options()) -> MultipartMessage, MultipartError {
    var msg = MultipartMessage { .. };
    guard body.len > 0 else { return msg, MultipartError.EmptyInput; }

    guard boundary.len >= 1 && boundary.len <= 70 else {
        msg.valid = false;
        return msg, MultipartError.InvalidBoundaryLength;
    }
    guard validate_boundary_string(boundary) else {
        msg.valid = false;
        return msg, MultipartError.InvalidBoundaryCharacters;
    }
    guard body.len <= options.max_payload_bytes else {
        msg.valid = false;
        return msg, MultipartError.ExceededMaxPayload;
    }

    var init_delim: u8[..74] = "--";
    init_delim.append(boundary);

    var part_delim: u8[..76] = "\n--";
    part_delim.append(boundary);

    var shift_table: u16[256] = [0; 256];
    build_bmh_shift_table(part_delim[..], shift_table);

    var cursor = find_initial_boundary(body, init_delim[..]);
    guard cursor >= 0 else {
        msg.valid = false;
        return msg, MultipartError.MissingBoundaryDelimiter;
    }
    cursor += init_delim.len;

    var total_memory_used: i64 = 0;

    while cursor < body.len {
        while cursor < body.len && (body[cursor] == ' ' || body[cursor] == '\t') {
            cursor++;
        }

        if cursor + 2 <= body.len && body[cursor] == '-' && body[cursor + 1] == '-' {
            break; // Closing boundary "--" reached
        }

        if cursor + 2 <= body.len && body[cursor] == '\r' && body[cursor + 1] == '\n' {
            cursor += 2;
        } else if cursor < body.len && body[cursor] == '\n' {
            cursor += 1;
        } else {
            msg.valid = false;
            return msg, MultipartError.PrematureEOF;
        }

        guard msg.parts.len < options.max_parts else {
            msg.valid = false;
            return msg, MultipartError.ExceededMaxParts;
        }

        var header_delim_len: i64 = 0;
        let max_h_scan = if cursor + options.max_header_bytes < body.len { cursor + options.max_header_bytes } else { body.len };
        let header_end = find_header_end(body, cursor, max_h_scan, header_delim_len);
        guard header_end >= 0 else {
            msg.valid = false;
            return msg, MultipartError.InvalidPartHeaders;
        }

        let raw_part_headers = body[cursor..header_end];
        // Go #81741 / CVE-2026-94440 & Go #65383: Account for header memory to prevent limit bypass
        total_memory_used += raw_part_headers.len;
        guard total_memory_used <= options.max_memory_bytes else {
            msg.valid = false;
            return msg, MultipartError.ExceededMaxMemory;
        }

        var part_headers = HeaderMap { .. };
        let h_err = parse_headers(raw_part_headers, part_headers);
        guard is_ok(h_err) else {
            msg.valid = false;
            return msg, MultipartError.InvalidPartHeaders;
        }

        // RFC 7578 Section 4.7 & Go #66434 / #63855: Content-Transfer-Encoding is deprecated and MUST be rejected
        if has_header(part_headers, "content-transfer-encoding") {
            msg.valid = false;
            return msg, MultipartError.InvalidPartHeaders;
        }

        cursor = header_end + header_delim_len;

        let next_delim_pos = find_next_boundary_delim(body, cursor, part_delim[..], shift_table);
        guard next_delim_pos >= 0 else {
            msg.valid = false;
            return msg, MultipartError.PrematureEOF;
        }

        var part_end = next_delim_pos;
        if next_delim_pos > cursor && body[next_delim_pos - 1] == '\r' {
            part_end = next_delim_pos - 1;
        }

        let part_data = body[cursor..part_end];
        total_memory_used += part_data.len;
        guard total_memory_used <= options.max_memory_bytes else {
            msg.valid = false;
            return msg, MultipartError.ExceededMaxMemory;
        }

        var part = MultipartPart { headers: part_headers, .. };
        part.data = part_data;
        populate_part_metadata(part_headers, part);
        msg.parts.push(part);

        cursor = next_delim_pos + part_delim.len;
    }

    msg.valid = true;
    return msg, MultipartError.None;
}

// ---- range requests and coalescing -----------------------------------------

enum RangeError {
    None,
    EmptyRange,
    InvalidUnit,                // Only 'bytes' is supported
    MalformedRange,
    Unsatisfiable,              // 416 Range Not Satisfiable
    ExceededMaxRanges,          // > 16 ranges
    TooManyEmptyElements,       // Ceiling on empty commas
}

fn is_ok(err: RangeError) -> bool {
    return err == RangeError.None;
}

enum RangeForm {
    Explicit,                   // bytes=0-999
    OpenPrefix,                 // bytes=5000-
    Suffix,                     // bytes=-500
}

struct RangeSpec {
    form: RangeForm = RangeForm.Explicit,
    start: i64 = 0,
    end_pos: i64 = 0,
    has_end: bool = true,
}

struct NormalizedRange {
    start: i64 = 0,
    end_pos: i64 = 0,
}

struct RangeSet {
    ranges: NormalizedRange[..16] = [],
    is_satisfiable: bool = true,
    coalesced: bool = false,
    resource_length: i64 = 0,
}

fn parse_i64_slice(s: const u8[:]) -> i64, bool {
    guard s.len > 0 else { return 0, false; }
    for b in s {
        guard b >= '0' && b <= '9' else { return 0, false; }
    }
    let val, ok = core::parse_u64_dec(s);
    guard ok && val <= 9223372036854775807 else { return 0, false; }
    return val as! i64, true;
}

fn parse_single_range_spec(item: const u8[:], spec: RangeSpec&) -> RangeError {
    let pre_raw, post_raw, has_dash = item.split_once_byte('-');
    guard has_dash else { return RangeError.MalformedRange; }

    let pre = pre_raw.trim_lws();
    let post = post_raw.trim_lws();

    if pre.len == 0 {
        guard post.len > 0 else { return RangeError.MalformedRange; }
        let suffix_len, s_ok = parse_i64_slice(post);
        guard s_ok && suffix_len > 0 else { return RangeError.MalformedRange; }
        spec.form = RangeForm.Suffix;
        spec.start = suffix_len;
        spec.has_end = false;
    } else if post.len == 0 {
        let start_val, p_ok = parse_i64_slice(pre);
        guard p_ok && start_val >= 0 else { return RangeError.MalformedRange; }
        spec.form = RangeForm.OpenPrefix;
        spec.start = start_val;
        spec.has_end = false;
    } else {
        let start_val, p_ok = parse_i64_slice(pre);
        let end_val, e_ok = parse_i64_slice(post);
        guard p_ok && e_ok && start_val >= 0 && end_val >= start_val else {
            return RangeError.MalformedRange;
        }
        spec.form = RangeForm.Explicit;
        spec.start = start_val;
        spec.end_pos = end_val;
        spec.has_end = true;
    }
    return RangeError.None;
}

fn normalize_range_spec(spec: const RangeSpec&, resource_len: i64, norm: NormalizedRange&, has_norm: bool&) {
    has_norm = false;
    guard resource_len > 0 else { return; }
    match spec.form {
        Explicit => {
            if spec.start < resource_len {
                norm.start = spec.start;
                norm.end_pos = if spec.end_pos < resource_len { spec.end_pos } else { resource_len - 1 };
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
                norm.start = core::ct_max_i64(0, resource_len - suf);
                norm.end_pos = resource_len - 1;
                has_norm = true;
            }
        },
    }
}

fn coalesce_normalized_ranges(raw_ranges: NormalizedRange[..32]&, out_ranges: NormalizedRange[..16]&) {
    for i in 1..raw_ranges.len {
        var j = i;
        while j > 0 && raw_ranges[j].start < raw_ranges[j - 1].start {
            let temp = raw_ranges[j];
            raw_ranges[j] = raw_ranges[j - 1];
            raw_ranges[j - 1] = temp;
            j--;
        }
    }

    var merged = raw_ranges[0];
    for i in 1..raw_ranges.len {
        let next_r = raw_ranges[i];
        if next_r.start <= merged.end_pos || (merged.end_pos < 9223372036854775807 && next_r.start <= merged.end_pos + 1) {
            merged.end_pos = core::ct_max_i64(merged.end_pos, next_r.end_pos);
        } else {
            if out_ranges.len < 16 {
                out_ranges.push(merged);
            }
            merged = next_r;
        }
    }
    if out_ranges.len < 16 {
        out_ranges.push(merged);
    }
}

// Parses an HTTP Range header into normalized intervals (RFC 9110 Section 14.1.2).
// When with_coalesce is true, overlapping and adjacent ranges are merged.
fn parse_range_header(
    header_val: const u8[:],
    resource_len: i64,
    with_coalesce: bool = true,
    max_ranges: i32 = 16,
) -> RangeSet, RangeError {
    var rs = RangeSet { resource_length: resource_len, is_satisfiable: true, coalesced: false, .. };
    let trimmed = trim_lws(header_val);
    guard trimmed.len > 0 else { return rs, RangeError.EmptyRange; }

    guard trimmed.len >= 6 && eq_ascii_fold(trimmed[..6], "bytes=") else {
        return rs, RangeError.InvalidUnit;
    }

    let spec_list = trimmed[6..];
    var specs: RangeSpec[..32] = [];
    var raw_ranges: NormalizedRange[..32] = [];

    var cursor: i64 = 0;
    var empty_elements: i32 = 0;
    let max_empty: i32 = 16;

    while cursor <= spec_list.len {
        var comma_pos = cursor;
        while comma_pos < spec_list.len && spec_list[comma_pos] != ',' {
            comma_pos++;
        }

        let item = trim_lws(spec_list[cursor..comma_pos]);
        cursor = comma_pos + 1;

        if item.len == 0 {
            empty_elements++;
            guard empty_elements <= max_empty else { return rs, RangeError.TooManyEmptyElements; }
            continue;
        }

        guard specs.len < max_ranges else {
            return rs, RangeError.ExceededMaxRanges;
        }

        var spec = RangeSpec { .. };
        let spec_err = parse_single_range_spec(item, spec);
        guard is_ok(spec_err) else { return rs, spec_err; }

        specs.push(spec);
    }

    guard specs.len > 0 else { return rs, RangeError.EmptyRange; }

    for spec in specs {
        var norm = NormalizedRange { .. };
        var has_norm = false;
        normalize_range_spec(spec, resource_len, norm, has_norm);
        if has_norm {
            raw_ranges.push(norm);
        }
    }

    if raw_ranges.len == 0 {
        rs.is_satisfiable = false;
        return rs, RangeError.Unsatisfiable;
    }

    if with_coalesce && raw_ranges.len > 1 {
        coalesce_normalized_ranges(raw_ranges, rs.ranges);
        rs.coalesced = true;
    } else {
        for r in raw_ranges {
            if rs.ranges.len < 16 {
                rs.ranges.push(r);
            }
        }
        rs.coalesced = false;
    }

    return rs, RangeError.None;
}

// Appends a formatted Content-Range header value (RFC 9110 Section 14.4).
fn format_content_range(start: i64, end_pos: i64, total_len: i64, out: u8[>..]&) {
    out.append("bytes ");
    if start >= 0 && end_pos >= start {
        format(out, start);
        out.push('-');
        format(out, end_pos);
    } else {
        out.push('*');
    }
    out.push('/');
    if total_len >= 0 {
        format(out, total_len);
    } else {
        out.push('*');
    }
}

// Evaluates an If-Range condition against an ETag or modification time.
// Weak ETags are rejected; date comparisons truncate to whole seconds (RFC 9110 Section 13.1.5).
fn evaluate_if_range(
    if_range_header: const u8[:],
    etag: const u8[:],
    mod_time: core::Time,
) -> bool {
    let trimmed = trim_lws(if_range_header);
    guard trimmed.len > 0 else { return false; }

    // If strong ETag (starts with '"' and ends with '"', not weak W/"...")
    if trimmed[0] == '"' && trimmed[trimmed.len - 1] == '"' {
        guard !starts_with_fold(trimmed, "w/") else { return false; } // Weak ETags forbidden
        return trimmed == etag;
    }

    // Otherwise, parse as HTTP-date (IMF-fixdate, RFC 850, or asctime)
    let parsed_date, date_ok = core::parse_http_date(trimmed);
    guard date_ok else { return false; }

    // Compare timestamps truncated to whole seconds (RFC 9110 Section 13.1.5).
    let mod_sec = core::unix(mod_time);
    let parsed_sec = core::unix(parsed_date);
    return mod_sec == parsed_sec;
}

// Validates a Content-Range header for a byte-range PATCH payload.
fn validate_byterange_patch(content_range_val: const u8[:], body_len: i64) -> i64, i64, bool {
    let trimmed = trim_lws(content_range_val);
    guard trimmed.len >= 6 && eq_ascii_fold(trimmed[..6], "bytes ") else {
        return 0, 0, false;
    }

    let rem = trimmed[6..];
    // Unsatisfied form "bytes */1000" is an explicit syntax error in PATCH
    guard rem.len > 0 && rem[0] != '*' else { return 0, 0, false; }

    var slash_pos: i64 = -1;
    for i in rem.len {
        if rem[i] == '/' {
            slash_pos = i;
            break;
        }
    }
    guard slash_pos > 0 else { return 0, 0, false; }

    let range_part = rem[..slash_pos];
    let start_raw, end_raw, has_dash = range_part.split_once_byte('-');
    guard has_dash && start_raw.len > 0 && end_raw.len > 0 else { return 0, 0, false; }

    let start_val, s_ok = parse_i64_slice(start_raw);
    let end_val, e_ok = parse_i64_slice(end_raw);
    guard s_ok && e_ok && start_val >= 0 && end_val >= start_val else {
        return 0, 0, false;
    }

    guard end_val - start_val < 9223372036854775807 else { return 0, 0, false; }
    let expected_len = end_val - start_val + 1;
    guard body_len == expected_len else { return 0, 0, false; }

    return start_val, end_val, true;
}

// Handles an RFC 9110 range request, writing status, headers, and body slices.
// Serves an HTTP GET range request, writing status code, headers, and payload (RFC 9110 Section 14).
fn serve_range_request<OpenFn: fn(i64, i64, u8[>..]&)>(
    req_range_header: const u8[:],
    if_range_header: const u8[:],
    etag: const u8[:],
    mod_time: core::Time,
    resource_len: i64,
    content_type: const u8[:],
    out_status: i32&,
    out_headers: HeaderMap&,
    out_body: u8[>..]&,
) {
    reset_for_keep_alive(out_headers);
    insert_header(out_headers, "accept-ranges", "bytes");

    // Check If-Range if present
    if if_range_header.len > 0 {
        let is_match = evaluate_if_range(if_range_header, etag, mod_time);
        if !is_match {
            out_status = 200;
            insert_header(out_headers, "content-type", content_type);
            var len_str: u8[..32] = [];
            format(len_str, resource_len);
            insert_header(out_headers, "content-length", len_str[..]);
            OpenFn(0, resource_len, out_body);
            return;
        }
    }

    // Parse and coalesce ranges
    let rs, r_err = parse_range_header(req_range_header, resource_len, true, 16);
    if !rs.is_satisfiable || !is_ok(r_err) {
        out_status = 416;
        var cr_val: u8[>..] = [];
        format_content_range(-1, -1, resource_len, cr_val);
        insert_header(out_headers, "content-range", cr_val[..]);
        insert_header(out_headers, "content-length", "0");
        return;
    }

    if rs.ranges.len == 1 {
        // Single-part 206 Partial Content (optimization)
        out_status = 206;
        let r = rs.ranges[0];
        var cr_val: u8[>..] = [];
        format_content_range(r.start, r.end_pos, resource_len, cr_val);
        insert_header(out_headers, "content-range", cr_val[..]);
        insert_header(out_headers, "content-type", content_type);

        let part_len = r.end_pos - r.start + 1;
        var len_str: u8[..32] = [];
        format(len_str, part_len);
        insert_header(out_headers, "content-length", len_str[..]);

        OpenFn(r.start, part_len, out_body);
    } else {
        // Multipart 206 Partial Content: multipart/byteranges; boundary=...
        out_status = 206;
        let boundary = "goose-byterange-boundary-42";
        var ct_val: u8[>..] = "multipart/byteranges; boundary=";
        ct_val.append(boundary);
        insert_header(out_headers, "content-type", ct_val[..]);

        for r in rs.ranges {
            out_body.append("--");
            out_body.append(boundary);
            out_body.append("\r\n");

            out_body.append("Content-Type: ");
            out_body.append(content_type);
            out_body.append("\r\n");

            out_body.append("Content-Range: ");
            var cr_val: u8[>..] = [];
            format_content_range(r.start, r.end_pos, resource_len, cr_val);
            out_body.append(cr_val[..]);
            out_body.append("\r\n\r\n");

            let part_len = r.end_pos - r.start + 1;
            OpenFn(r.start, part_len, out_body);
            out_body.append("\r\n");
        }

        out_body.append("--");
        out_body.append(boundary);
        out_body.append("--\r\n");

        var len_str: u8[..32] = [];
        format(len_str, out_body.len as i64);
        insert_header(out_headers, "content-length", len_str[..]);
    }
}
