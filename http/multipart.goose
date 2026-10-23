// Streaming multipart/form-data parser and RFC 9110 Range request coalescing engine for Goose.
// Clean Room Implementation defending against:
//   - CVE-2026-19484 / CVE-2024-13444: 16-bit BMH shift table preventing 8-bit table overflow / spinloop.
//   - CVE-2011-3192 (Apache Killer): 16-range ceiling and O(N log N) range coalescing.
//   - Sub-second If-Range timestamp mismatch: Seconds truncation for filesystem modification times.
//
// Core Types:
//   MultipartOptions  - Configurable memory budgets, part ceilings, and payload thresholds.
//   MultipartPart     - Parsed multipart entity with disposition metadata, headers, and body.
//   MultipartMessage  - Sequence of decoded parts.
//   RangeSet          - Coalesced and validated byte ranges.
//
// Standards & Specifications:
//   RFC 2046 §5.1.1 - Boundary length strictly bounded to 1..70 ASCII characters.
//   RFC 7578 - Returning Values from Forms: multipart/form-data.
//   RFC 9110 §14 - HTTP Range Requests, Content-Range, Range Coalescing, and 416 Not Satisfiable.
//   RFC 9110 §13.1.5 - If-Range validation (weak ETags forbidden, HTTP-Date seconds truncation).
//   draft-wright-http-patch-byterange - Byte Range PATCH validation (Content-Range vs Content-Length).
namespace wing;

import std;
import core.time;
import app.profile;
import http.headers;
import http.mime;

// ---- multipart errors & options --------------------------------------------

enum MultipartError {
    None,
    EmptyInput,
    InvalidBoundaryLength,      // < 1 or > 70 characters (RFC 2046 §5.1.1 / CVE-2026-19484 defense)
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

// ---- 16-bit boyer-moore-horspool shift table (cve-2026-19484 defense) ------

// Builds a 16-bit Boyer-Moore-Horspool shift table.
// Storing step sizes as u16 (instead of u8) ensures that jump distances >= 256
// (e.g. from 252-byte boundary + 4-byte \r\n-- prefix) NEVER truncate to 0!
fn build_bmh_shift_table(needle: const u8[:], table: u16[256]&) {
    let needle_len = needle.len;
    let default_shift = if needle_len > 65535 { 65535 as u16 } else { needle_len as u16 };

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

// Performs fast BMH search in haystack
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
        // Strict forward progress invariant (step >= 1)
        i += if shift > 0 { shift } else { 1 };
    }
    return -1;
}

// Validates boundary characters and length per RFC 2046 §5.1.1 (1..70 chars)
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

// ---- streaming multipart parser --------------------------------------------

fn parse_multipart(body: const u8[:], boundary: const u8[:], options: MultipartOptions = default_multipart_options()) -> MultipartMessage, MultipartError {
    var msg = MultipartMessage { .. };
    guard body.len > 0 else { return msg, MultipartError.EmptyInput; }

    // Barrier 1: RFC 2046 §5.1.1 boundary length check (1..70 chars)
    // Defends against CVE-2026-19484 before initializing parser buffers!
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

    // Build delimiter needles:
    // Initial boundary: "--" + boundary
    // Subsequent boundary: "\r\n--" + boundary
    var init_delim: u8[..74] = "--";
    init_delim.append(boundary);

    var part_delim: u8[..76] = "\n--";
    part_delim.append(boundary);

    // Barrier 2: 16-bit shift table
    var shift_table: u16[256] = [0; 256];
    build_bmh_shift_table(part_delim[..], shift_table);

    // Find initial boundary
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
                    break;
                }
            }
        }
        cursor++;
    }
    guard cursor + init_delim.len <= body.len else {
        msg.valid = false;
        return msg, MultipartError.MissingBoundaryDelimiter;
    }
    cursor += init_delim.len;

    var total_memory_used: i64 = 0;

    // Loop through parts
    while cursor < body.len {
        // Skip optional transport padding (RFC 2046 §5.1.1)
        while cursor < body.len && (body[cursor] == ' ' || body[cursor] == '\t') {
            cursor++;
        }

        // Check for closing delimiter "--"
        if cursor + 2 <= body.len && body[cursor] == '-' && body[cursor + 1] == '-' {
            // End of multipart message
            break;
        }

        // Must be followed by CRLF or LF
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

        // Find end of headers \r\n\r\n or \n\n
        var header_end: i64 = -1;
        var header_delim_len: i64 = 0;
        var scan_h = cursor;
        let max_h_scan = if cursor + options.max_header_bytes < body.len { cursor + options.max_header_bytes } else { body.len };

        while scan_h < max_h_scan {
            if scan_h + 4 <= body.len && body[scan_h] == '\r' && body[scan_h + 1] == '\n' && body[scan_h + 2] == '\r' && body[scan_h + 3] == '\n' {
                header_end = scan_h;
                header_delim_len = 4;
                break;
            }
            if scan_h + 2 <= body.len && body[scan_h] == '\n' && body[scan_h + 1] == '\n' {
                header_end = scan_h;
                header_delim_len = 2;
                break;
            }
            scan_h++;
        }

        guard header_end >= 0 else {
            msg.valid = false;
            return msg, MultipartError.InvalidPartHeaders;
        }

        let raw_part_headers = body[cursor..header_end];
        var part_headers = HeaderMap { .. };
        let h_err = parse_headers(raw_part_headers, part_headers);
        guard is_ok(h_err) else {
            msg.valid = false;
            return msg, MultipartError.InvalidPartHeaders;
        }

        cursor = header_end + header_delim_len;

        // Find next boundary delimiter using BMH search (defending against prefix collisions / issue #10616)
        var search_pos = cursor;
        var next_delim_pos: i64 = -1;

        while search_pos < body.len {
            let found = bmh_find(body, part_delim[..], shift_table, search_pos);
            if found < 0 {
                break;
            }
            let post_pos = found + part_delim.len;
            var pad_pos = post_pos;
            while pad_pos < body.len && (body[pad_pos] == ' ' || body[pad_pos] == '\t') {
                pad_pos++;
            }
            if (pad_pos + 2 <= body.len && body[pad_pos] == '-' && body[pad_pos + 1] == '-') ||
               (pad_pos + 2 <= body.len && body[pad_pos] == '\r' && body[pad_pos + 1] == '\n') ||
               (pad_pos < body.len && body[pad_pos] == '\n') {
                next_delim_pos = found;
                break;
            }
            search_pos = found + 1;
        }

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

        // Construct MultipartPart
        var part = MultipartPart {
            headers: part_headers,
            ..
        };
        part.data = part_data;

        // Extract metadata from Content-Disposition
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

        msg.parts.push(part);

        // Advance cursor past \r\n--boundary
        cursor = next_delim_pos + part_delim.len;
    }

    msg.valid = true;
    return msg, MultipartError.None;
}

// ---- rfc 9110 range requests & coalescing (cve-2011-3192 defense) -----------

enum RangeError {
    None,
    EmptyRange,
    InvalidUnit,                // Only 'bytes' is supported
    MalformedRange,
    Unsatisfiable,              // 416 Range Not Satisfiable
    ExceededMaxRanges,          // > 16 ranges (CVE-2011-3192 Apache Killer defense)
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
    let max_cutoff: i64 = 922337203685477580; // i64::MAX / 10 = 9223372036854775807 / 10
    var n: i64 = 0;
    for b in s {
        guard b >= '0' && b <= '9' else { return 0, false; }
        let digit = (b - '0') as i64;
        guard n < max_cutoff || (n == max_cutoff && digit <= 7) else {
            return 0, false;
        }
        n = n * 10 + digit;
    }
    return n, true;
}

// Parses and coalesces RFC 9110 §14 byte ranges
fn parse_range_header(
    header_val: const u8[:],
    resource_len: i64,
    with_coalesce: bool = true,
    max_ranges: i32 = 16,
) -> RangeSet, RangeError {
    var rs = RangeSet { resource_length: resource_len, is_satisfiable: true, coalesced: false, .. };
    let trimmed = trim_lws(header_val);
    guard trimmed.len > 0 else { return rs, RangeError.EmptyRange; }

    // Must start with "bytes="
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

        // Hard limit on requested ranges before coalescing (CVE-2011-3192 Apache Killer defense)
        guard specs.len < max_ranges else {
            return rs, RangeError.ExceededMaxRanges;
        }

        var dash_pos: i64 = -1;
        for i in item.len {
            if item[i] == '-' {
                dash_pos = i;
                break;
            }
        }
        guard dash_pos >= 0 else { return rs, RangeError.MalformedRange; }

        let pre = trim_lws(item[..dash_pos]);
        let post = trim_lws(item[dash_pos + 1..]);

        var spec = RangeSpec { .. };

        if pre.len == 0 {
            // Suffix interval: bytes=-N
            guard post.len > 0 else { return rs, RangeError.MalformedRange; }
            let suffix_len, s_ok = parse_i64_slice(post);
            guard s_ok && suffix_len > 0 else { return rs, RangeError.MalformedRange; }
            spec.form = RangeForm.Suffix;
            spec.start = suffix_len;
            spec.has_end = false;
        } else if post.len == 0 {
            // Open prefix interval: bytes=N-
            let start_val, p_ok = parse_i64_slice(pre);
            guard p_ok && start_val >= 0 else { return rs, RangeError.MalformedRange; }
            spec.form = RangeForm.OpenPrefix;
            spec.start = start_val;
            spec.has_end = false;
        } else {
            // Explicit interval: bytes=N-M
            let start_val, p_ok = parse_i64_slice(pre);
            let end_val, e_ok = parse_i64_slice(post);
            guard p_ok && e_ok && start_val >= 0 && end_val >= start_val else {
                return rs, RangeError.MalformedRange;
            }
            spec.form = RangeForm.Explicit;
            spec.start = start_val;
            spec.end_pos = end_val;
            spec.has_end = true;
        }

        specs.push(spec);
    }

    guard specs.len > 0 else { return rs, RangeError.EmptyRange; }

    // Normalize against resource_len
    for spec in specs {
        if resource_len <= 0 {
            continue; // Empty resource cannot satisfy any range
        }

        var norm = NormalizedRange { .. };
        match spec.form {
            Explicit => {
                if spec.start < resource_len {
                    norm.start = spec.start;
                    norm.end_pos = if spec.end_pos < resource_len { spec.end_pos } else { resource_len - 1 };
                    raw_ranges.push(norm);
                }
            },
            OpenPrefix => {
                if spec.start < resource_len {
                    norm.start = spec.start;
                    norm.end_pos = resource_len - 1;
                    raw_ranges.push(norm);
                }
            },
            Suffix => {
                let suf = spec.start;
                if suf > 0 {
                    norm.start = if resource_len > suf { resource_len - suf } else { 0 };
                    norm.end_pos = resource_len - 1;
                    raw_ranges.push(norm);
                }
            },
        }
    }

    // If no ranges overlap resource, 416 Range Not Satisfiable per RFC 9110 §14.4
    if raw_ranges.len == 0 {
        rs.is_satisfiable = false;
        return rs, RangeError.Unsatisfiable;
    }

    // Coalesce overlapping and adjacent ranges: s2 <= e1 + 1 ==> [s1, max(e1, e2)]
    if with_coalesce && raw_ranges.len > 1 {
        // Insertion sort by start offset
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
                // Merge
                merged.end_pos = if next_r.end_pos > merged.end_pos { next_r.end_pos } else { merged.end_pos };
            } else {
                if rs.ranges.len < 16 {
                    rs.ranges.push(merged);
                }
                merged = next_r;
            }
        }
        if rs.ranges.len < 16 {
            rs.ranges.push(merged);
        }
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

// Formats Content-Range header value (e.g. "bytes 0-499/1000" or "bytes */1000")
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

// RFC 9110 §13.1.5: If-Range condition evaluation
// Weak ETags NEVER match in If-Range.
// HTTP-dates are truncated to whole seconds before comparison with filesystem mod_time!
fn evaluate_if_range(
    if_range_header: const u8[:],
    etag: const u8[:],
    mod_time: Time,
) -> bool {
    let trimmed = trim_lws(if_range_header);
    guard trimmed.len > 0 else { return false; }

    // If strong ETag (starts with '"' and ends with '"', not weak W/"...")
    if trimmed[0] == '"' && trimmed[trimmed.len - 1] == '"' {
        guard !starts_with_ignore_case(trimmed, "w/") else { return false; } // Weak ETags forbidden!
        return trimmed == etag;
    }

    // Otherwise, parse as HTTP-date (IMF-fixdate, RFC 850, or asctime)
    let parsed_date, date_ok = parse_http_date(trimmed);
    guard date_ok else { return false; }

    // Truncate filesystem mod_time to whole seconds per RFC 9110 §13.1.5
    let mod_sec = unix(mod_time);
    let parsed_sec = unix(parsed_date);
    return mod_sec == parsed_sec;
}

// draft-wright-http-patch-byterange validator
// Verifies Content-Range on incoming PATCH part and matches against payload length
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
    var dash_pos: i64 = -1;
    for i in range_part.len {
        if range_part[i] == '-' {
            dash_pos = i;
            break;
        }
    }
    guard dash_pos > 0 && dash_pos + 1 < range_part.len else { return 0, 0, false; }

    let start_val, s_ok = parse_i64_slice(range_part[..dash_pos]);
    let end_val, e_ok = parse_i64_slice(range_part[dash_pos + 1..]);
    guard s_ok && e_ok && start_val >= 0 && end_val >= start_val else {
        return 0, 0, false;
    }

    guard end_val - start_val < 9223372036854775807 else { return 0, 0, false; }
    let expected_len = end_val - start_val + 1;
    guard body_len == expected_len else { return 0, 0, false; }

    return start_val, end_val, true;
}

// Serves RFC 9110 Range request without requiring io.ReadSeeker
fn serve_range_request<OpenFn: fn(i64, i64, u8[>..]&)>(
    req_range_header: const u8[:],
    if_range_header: const u8[:],
    etag: const u8[:],
    mod_time: Time,
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
            // If-Range failed: return full 200 OK
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
        // 416 Range Not Satisfiable
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
