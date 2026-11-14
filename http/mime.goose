// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Media types (RFC 9110 Section 8.3) and Content-Disposition (RFC 6266, RFC 7578).
// Provides media type and disposition parameter parsing, strict unquoting,
// and case-insensitive parameter lookup.
namespace wing;

import std;
import core from "..";

// ---- string unquoting ------------------------------------------------------

// Unquotes a double-quoted string (RFC 9110 Section 5.6.4).
// Rejects unclosed quotes, escaped trailing delimiters, and control characters.
fn strict_unquote<B>(input: const u8[:], out: B&, max_out_len: i64 = 65536) -> bool {
    guard input.len >= 2 else { return false; }
    guard input[0] == '"' && input[input.len - 1] == '"' else { return false; }

    // Check terminal quote escaping: count trailing backslashes immediately before closing quote
    var slash_count: i64 = 0;
    var idx = input.len - 2;
    while idx >= 1 && input[idx] == '\\' {
        slash_count++;
        idx--;
    }
    // If odd number of slashes precedes terminal quote, the terminal quote is escaped!
    guard (slash_count & 1) == 0 else { return false; }

    var i: i64 = 1;
    let end_idx = input.len - 1;
    while i < end_idx {
        let b = input[i];
        if b == '\\' {
            guard i + 1 < end_idx else { out.clear(); return false; }
            let next_b = input[i + 1];
            // Quoted-pair allows visible ASCII and space
            guard (next_b >= 0x20 && next_b <= 0x7E) || next_b == '\t' else { out.clear(); return false; }
            guard out.len < max_out_len else { out.clear(); return false; }
            out.push(next_b);
            i += 2;
        } else {
            // Rejects unescaped interior double-quote and CTLs except HTAB (RFC 9110 §5.6.4)
            if b == '"' {
                out.clear();
                return false;
            }
            if b < 0x20 {
                guard b == '\t' else { out.clear(); return false; }
            } else if b == 0x7F {
                out.clear();
                return false;
            }
            guard out.len < max_out_len else { out.clear(); return false; }
            out.push(b);
            i++;
        }
    }
    return true;
}

// Liberal unquote for legacy or non-critical headers
fn unquote<B>(input: const u8[:], out: B&, max_out_len: i64 = 65536) -> bool {
    guard input.len >= 2 && input[0] == '"' && input[input.len - 1] == '"' else {
        guard out.len + input.len <= max_out_len else { out.clear(); return false; }
        out.append(input);
        return true;
    }
    return strict_unquote(input, out, max_out_len);
}

fn has_param_name(params: const MediaTypeParam[..16]&, name: const u8[:]) -> bool {
    for &p in params {
        if p.name[..] == name {
            return true;
        }
    }
    return false;
}

// ---- media type parsing ----------------------------------------------------

struct MediaTypeParam {
    name:  u8[..64]  = [],
    value: u8[..256] = [],
}

struct MediaType {
    mime_type: u8[..64]             = [],
    type_name: u8[..32]             = [],
    subtype:   u8[..32]             = [],
    params:    MediaTypeParam[..16] = [],
    valid:     bool                 = false,
}

// RFC 9110 Section 5.6.6: Parameters - Decodes a parameter-value (token / quoted-string) into out.
//
// Example:
//   raw_val = "\"utf-8\"", out = []
//   returns: true, out = "utf-8"
fn decode_token_or_quoted_param<B>(raw_val: const u8[:], out: B&, max_len: i64 = 256) -> bool {
    guard raw_val.len > 0 else { return false; }
    if raw_val[0] == '"' {
        return strict_unquote(raw_val, out, max_len);
    }
    guard raw_val.len <= max_len && is_valid_header_name(raw_val) && out.try_append(raw_val) else {
        return false;
    }
    return true;
}

// Parses a single MIME media parameter (RFC 9110 Section 5.6.6 & Section 8.3).
//
// Example:
//   p_trim = "charset=\"utf-8\"", p_item = MediaTypeParam { .. }
//   returns: true, p_item.name = "charset", p_item.value = "utf-8"
fn parse_single_media_param(p_trim: const u8[:], p_item: MediaTypeParam&) -> bool {
    p_item.name.clear();
    p_item.value.clear();
    var committed = false;
    defer if !committed {
        p_item.name.clear();
        p_item.value.clear();
    };

    let p_name, p_val_raw, ok = p_trim.split_once_byte('=');
    guard ok && is_valid_header_name(p_name) && p_item.name.try_append(p_name) else {
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
fn parse_media_parameters(rem_in: const u8[:], mt: MediaType&) -> bool {
    var rem = rem_in;
    while rem.len > 0 {
        let param_token, next_rem, _ = rem.split_once_unquoted_byte(';');
        rem = next_rem;

        let p_trim = param_token.trim_lws();
        if p_trim.len == 0 { continue; }

        var p_item = MediaTypeParam { .. };
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

// Parses a Content-Type or media type header value (RFC 9110 Section 8.3).
//
// Example:
//   raw = "text/html; charset=utf-8"
//   returns: MediaType { type_name: "text", subtype: "html", valid: true, .. }, true
fn parse_media_type(raw: const u8[:]) -> MediaType, bool {
    var mt = MediaType { .. };
    defer if !mt.valid { mt = MediaType { .. }; };
    let trimmed = raw.trim_lws();
    guard trimmed.len > 0 else { return mt, false; }
    if has_embedded_nulls(trimmed) { return mt, false; }

    let mime_part_raw, params_part, has_semi = trimmed.split_once_byte(';');
    let mime_part = mime_part_raw.trim_lws();

    let raw_type, raw_sub, has_slash = mime_part.split_once_byte('/');
    guard has_slash && raw_type.len > 0 && raw_sub.len > 0 else { return mt, false; }
    guard is_valid_header_name(raw_type) && is_valid_header_name(raw_sub) else { return mt, false; }
    guard mt.type_name.try_append(raw_type) && mt.subtype.try_append(raw_sub) else { return mt, false; }

    to_lower(mt.type_name[..]);
    to_lower(mt.subtype[..]);

    format(mt.mime_type, mt.type_name[..], "/", mt.subtype[..]);

    // Parse parameters
    if has_semi {
        guard parse_media_parameters(params_part, mt) else { return mt, false; }
    }

    mt.valid = true;
    return mt, true;
}

// RFC 6266 / RFC 7578: Content-Disposition parser
// disposition = disposition-type *( ";" disposition-parm )
//
// Example:
//   raw = "form-data; name=\"upload\"; filename=\"file.txt\""
//   returns: MediaType { type_name: "form-data", valid: true, .. }, true
fn parse_content_disposition(raw: const u8[:]) -> MediaType, bool {
    var mt = MediaType { .. };
    defer if !mt.valid { mt = MediaType { .. }; };
    let trimmed = raw.trim_lws();
    guard trimmed.len > 0 else { return mt, false; }
    if has_embedded_nulls(trimmed) { return mt, false; }

    let disp_part_raw, params_part, has_semi = trimmed.split_once_byte(';');
    let disp_part = disp_part_raw.trim_lws();
    guard is_valid_header_name(disp_part) && mt.type_name.try_append(disp_part) else { return mt, false; }

    to_lower(mt.type_name[..]);
    mt.mime_type.append(mt.type_name[..]);

    if has_semi {
        guard parse_media_parameters(params_part, mt) else { return mt, false; }
    }

    mt.valid = true;
    return mt, true;
}

fn param(mt: const MediaType&, key: const u8[:]) -> const u8[:] {
    for &p in mt.params {
        if p.name[..].eq_ascii_fold(key) {
            return p.value[..];
        }
    }
    return "";
}

fn has_param(mt: const MediaType&, key: const u8[:]) -> bool {
    for &p in mt.params {
        if p.name[..].eq_ascii_fold(key) {
            return true;
        }
    }
    return false;
}

fn is_multipart(mt: const MediaType&) -> bool {
    return mt.type_name[..].eq_ascii_fold("multipart");
}

fn boundary(mt: const MediaType&) -> const u8[:] {
    return param(mt, "boundary");
}

fn charset(mt: const MediaType&) -> const u8[:] {
    return param(mt, "charset");
}
