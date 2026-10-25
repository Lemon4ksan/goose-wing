// HTTP header lexical validation, SWAR scanning, and framing checks (RFC 9110, RFC 9112, RFC 9113).
namespace wing;

import std;

let CRLF_BYTES: const u8[2] = ['\r', '\n'];
let CRLF_SET: ByteSet = byte_set(CRLF_BYTES[..]);

let COLON_BYTES: const u8[1] = [':'];
let COLON_SET: ByteSet = byte_set(COLON_BYTES[..]);

let NULL_BYTES: const u8[1] = [0];
let NULL_SET: ByteSet = byte_set(NULL_BYTES[..]);

// ---- lexical validation & fast word operations -----------------------------

fn is_tchar(b: u8) -> bool {
    if (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z') || (b >= '0' && b <= '9') {
        return true;
    }
    return b == '!' || b == '#' || b == '$' || b == '%' || b == '&' || b == '\'' ||
           b == '*' || b == '+' || b == '-' || b == '.' || b == '^' || b == '_' ||
           b == '`' || b == '|' || b == '~';
}

fn is_valid_header_name(name: const u8[:]) -> bool {
    guard name.len > 0 else { return false; }
    for b in name {
        guard is_tchar(b) else { return false; }
    }
    return true;
}

// RFC 9113 Section 8.2.1: Wire lowercase ASCII validation for HTTP/2 & HTTP/3 headers
fn is_valid_header_name_h2(name: const u8[:]) -> bool {
    guard name.len > 0 else { return false; }
    let is_pseudo = name[0] == ':';
    let start_idx: i64 = if is_pseudo { 1 } else { 0 };
    guard start_idx < name.len else { return false; }
    for i in start_idx..name.len {
        let b = name[i];
        if b >= 'A' && b <= 'Z' { return false; }
        guard is_tchar(b) else { return false; }
    }
    return true;
}

fn has_embedded_nulls(data: const u8[:]) -> bool {
    return find_any(data, NULL_SET) >= 0;
}

fn is_valid_header_value(val: const u8[:]) -> bool {
    for b in val {
        // Rejects NUL, CR, LF, and all CTLs (0x00-0x08, 0x0A-0x1F, 0x7F) except HTAB (0x09)
        if b < 0x20 {
            if b != 0x09 { return false; }
        } else if b == 0x7F {
            return false;
        }
    }
    return true;
}

// RFC 9110 Section 8.6 & RFC 9112 Section 6.3: Content-Length validation & anti-smuggling parser
fn parse_cl_digits(s: const u8[:], out_val: i64&) -> bool {
    for b in s {
        guard b >= '0' && b <= '9' else { return false; }
    }
    let num, ok = core::parse_u64_dec(s);
    guard ok && num <= 9223372036854775807 else { return false; }
    out_val = num as! i64;
    return true;
}

fn validate_content_length_value(val: const u8[:], out_val: i64&) -> bool {
    let trimmed = trim_lws(val);
    guard trimmed.len > 0 else { return false; }

    var has_comma = false;
    for b in trimmed {
        if b == ',' {
            has_comma = true;
            break;
        }
    }

    if !has_comma {
        return parse_cl_digits(trimmed, out_val);
    }

    guard trimmed[0] != ',' && trimmed[trimmed.len - 1] != ',' else { return false; }

    var first_parsed = false;
    var target_val: i64 = 0;
    var cursor: i64 = 0;

    while cursor < trimmed.len {
        var comma_idx = cursor;
        while comma_idx < trimmed.len && trimmed[comma_idx] != ',' {
            comma_idx++;
        }

        let piece = trim_lws(trimmed[cursor..comma_idx]);
        guard piece.len > 0 else { return false; }

        var piece_num: i64 = 0;
        guard parse_cl_digits(piece, piece_num) else { return false; }

        if !first_parsed {
            target_val = piece_num;
            first_parsed = true;
        } else {
            guard piece_num == target_val else { return false; }
        }

        cursor = comma_idx + 1;
    }

    guard first_parsed else { return false; }
    out_val = target_val;
    return true;
}

// RFC 9112 Section 7.3: Standard registered transfer codings
fn is_valid_transfer_coding(coding: const u8[:]) -> bool {
    return eq_ascii_fold(coding, "chunked") ||
           eq_ascii_fold(coding, "gzip") ||
           eq_ascii_fold(coding, "deflate") ||
           eq_ascii_fold(coding, "compress");
}

// Validates a Transfer-Encoding header value (RFC 9112 Section 6.3, Section 7.1).
// Only chunked, gzip, deflate, and compress are recognized; if chunked is
// present, it must appear last and exactly once.
fn validate_transfer_encoding_value(val: const u8[:]) -> bool {
    let trimmed = trim_lws(val);
    guard trimmed.len > 0 else { return false; }
    guard trimmed[0] != ',' && trimmed[trimmed.len - 1] != ',' else { return false; }

    var cursor: i64 = 0;
    var count: i32 = 0;
    var chunked_count: i32 = 0;
    var last_is_chunked = false;

    while cursor <= trimmed.len {
        var comma_idx = cursor;
        while comma_idx < trimmed.len && trimmed[comma_idx] != ',' {
            comma_idx++;
        }

        let piece = trim_lws(trimmed[cursor..comma_idx]);
        guard piece.len > 0 else { return false; }
        guard is_valid_transfer_coding(piece) else { return false; }

        let is_chunked = eq_ascii_fold(piece, "chunked");
        if is_chunked {
            chunked_count++;
            last_is_chunked = true;
        } else {
            last_is_chunked = false;
        }
        count++;

        if comma_idx == trimmed.len {
            break;
        }
        cursor = comma_idx + 1;
    }

    guard count > 0 else { return false; }
    // RFC 9112 Section 7.1: Chunked must not be applied more than once
    guard chunked_count <= 1 else { return false; }
    // RFC 9112 Section 6.3: If present in a request, chunked must be the final encoding
    guard last_is_chunked else { return false; }

    return true;
}

// 64-bit SWAR Little-Endian pack
fn swar_pack_u64_le(buf: const u8[:], offset: i64) -> u64 {
    var w: u64 = 0;
    for i in 8 {
        let b = buf[offset + i] as u64;
        w |= (b << ((i * 8) as u64));
    }
    return w;
}

// 64-bit SWAR zero byte check
fn swar_has_zero_byte(w: u64) -> bool {
    return ((w - 0x0101010101010101) & (~w) & 0x8080808080808080) != 0;
}

// 64-bit SWAR byte search
fn swar_has_byte(w: u64, b: u8) -> bool {
    let mask = 0x0101010101010101 * (b as u64);
    return swar_has_zero_byte(w ^ mask);
}

// 64-bit SWAR control character check (< 0x20 or == 0x7F)
fn swar_has_ctl_or_del(w: u64) -> bool {
    // Check if any byte is < 0x20
    let sub = w - 0x2020202020202020;
    let has_under_20 = (sub & (~w) & 0x8080808080808080) != 0;
    let has_del = swar_has_byte(w, 0x7F);
    return has_under_20 || has_del;
}

// Fast header name hash (FNV-1a 32-bit case-folded)
fn hash_header_name(name: const u8[:]) -> u32 {
    var h: u32 = core::FNV1A_32_OFFSET;
    for b in name {
        let folded = if b >= 'A' && b <= 'Z' { b + 32 } else { b };
        h = (h ^ folded) * core::FNV1A_32_PRIME;
    }
    return h;
}

// ---- wire parser lexical helpers -------------------------------------------

fn is_line_whitespace_only(line: const u8[:]) -> bool {
    for b in line {
        if b != ' ' && b != '\t' {
            return false;
        }
    }
    return true;
}

fn advance_crlf(buf: const u8[:], cursor: i64&, line_end: i64) -> bool {
    cursor = line_end;
    let buf_len = buf.len;
    if cursor < buf_len && buf[cursor] == '\r' {
        guard cursor + 1 < buf_len && buf[cursor + 1] == '\n' else {
            return false;
        }
        cursor += 2;
        return true;
    }
    if cursor < buf_len && buf[cursor] == '\n' {
        cursor++;
        return true;
    }
    return true;
}
