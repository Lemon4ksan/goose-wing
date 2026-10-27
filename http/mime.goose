// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Media types (RFC 9110 Section 8.3) and Structured Field Values (RFC 8941, RFC 9651).
// Provides media type / parameter parsing, strict unquoting, and SFV item,
// list, and dictionary decoding.
namespace wing;

import std;
import http.headers;

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
    guard (slash_count % 2) == 0 else { return false; }

    var i: i64 = 1;
    let end_idx = input.len - 1;
    while i < end_idx {
        let b = input[i];
        if b == '\\' {
            guard i + 1 < end_idx else { return false; }
            let next_b = input[i + 1];
            // Quoted-pair allows visible ASCII and space
            guard (next_b >= 0x20 && next_b <= 0x7E) || next_b == '\t' else { return false; }
            guard out.len < max_out_len else { return false; }
            out.push(next_b);
            i += 2;
        } else {
            // Rejects CTLs except HTAB
            if b < 0x20 {
                guard b == '\t' else { return false; }
            } else if b == 0x7F {
                return false;
            }
            guard out.len < max_out_len else { return false; }
            out.push(b);
            i++;
        }
    }
    return true;
}

// Liberal unquote for legacy or non-critical headers
fn unquote<B>(input: const u8[:], out: B&) -> bool {
    guard input.len >= 2 && input[0] == '"' && input[input.len - 1] == '"' else {
        out.append(input);
        return true;
    }
    return strict_unquote(input, out);
}

// ---- media type parsing ----------------------------------------------------

struct MediaTypeParam {
    name: u8[..64] = [],
    value: u8[..256] = [],
}

struct MediaType {
    mime_type: u8[..64] = [],
    type_name: u8[..32] = [],
    subtype: u8[..32] = [],
    params: MediaTypeParam[..16] = [],
    valid: bool = false,
}

fn parse_single_media_param(p_trim: const u8[:], p_item: MediaTypeParam&) -> bool {
    let p_name_raw, p_val_raw, ok = p_trim.split_once_byte('=');
    guard ok && p_name_raw.len > 0 else { return false; }

    let p_name = p_name_raw.trim_lws();
    let p_val_raw = p_val_raw.trim_lws();
    guard is_valid_header_name(p_name) else { return false; }
    guard p_name.len <= p_item.name.cap else { return false; }

    p_item.name.append(p_name);
    to_lower(p_item.name[..]);

    if p_val_raw.len > 0 && p_val_raw[0] == '"' {
        guard strict_unquote(p_val_raw, p_item.value, 256) else { return false; }
    } else {
        guard is_valid_header_value(p_val_raw) else { return false; }
        guard p_val_raw.len <= p_item.value.cap else { return false; }
        p_item.value.append(p_val_raw);
    }
    return true;
}

fn parse_media_parameters(rem_in: const u8[:], mt: MediaType&) -> bool {
    var rem = rem_in;
    while rem.len > 0 {
        var next_semi: i64 = -1;
        var in_quotes = false;
        for i in rem.len {
            let b = rem[i];
            if b == '"' {
                var slash_count: i64 = 0;
                var j = i - 1;
                while j >= 0 && rem[j] == '\\' {
                    slash_count++;
                    j--;
                }
                if (slash_count % 2) == 0 {
                    in_quotes = !in_quotes;
                }
            } else if b == ';' && !in_quotes {
                next_semi = i;
                break;
            }
        }

        let param_token = if next_semi >= 0 { rem[..next_semi] } else { rem };
        rem = if next_semi >= 0 { rem[next_semi + 1..] } else { "" };

        let p_trim = trim_lws(param_token);
        if p_trim.len == 0 { continue; }

        var p_item = MediaTypeParam { .. };
        guard parse_single_media_param(p_trim, p_item) else { return false; }

        // Go #82343: RFC 2231 extended boundary parameter (boundary*=) must not be accepted or override boundary
        if core::starts_with(p_item.name[..], "boundary*") {
            continue;
        }

        // RFC 2046 / Go #82343: Duplicate boundary parameter MUST be rejected
        if p_item.name[..] == "boundary" {
            for &existing in mt.params {
                if existing.name[..] == "boundary" {
                    return false;
                }
            }
        }

        guard mt.params.len < mt.params.cap else { return false; }
        mt.params.push(p_item);
    }
    return true;
}

fn parse_media_type(raw: const u8[:]) -> MediaType, bool {
    var mt = MediaType { .. };
    let trimmed = trim_lws(raw);
    guard trimmed.len > 0 else { return mt, false; }
    if has_embedded_nulls(trimmed) { return mt, false; }

    let mime_part_raw, params_part, has_semi = trimmed.split_once_byte(';');
    let mime_part = mime_part_raw.trim_lws();

    let raw_type, raw_sub, has_slash = mime_part.split_once_byte('/');
    guard has_slash && raw_type.len > 0 && raw_sub.len > 0 else { return mt, false; }
    guard is_valid_header_name(raw_type) && is_valid_header_name(raw_sub) else { return mt, false; }
    guard raw_type.len <= mt.type_name.cap && raw_sub.len <= mt.subtype.cap else { return mt, false; }

    mt.type_name.append(raw_type);
    to_lower(mt.type_name[..]);
    mt.subtype.append(raw_sub);
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
fn parse_content_disposition(raw: const u8[:]) -> MediaType, bool {
    var mt = MediaType { .. };
    let trimmed = trim_lws(raw);
    guard trimmed.len > 0 else { return mt, false; }
    if has_embedded_nulls(trimmed) { return mt, false; }

    let disp_part_raw, params_part, has_semi = trimmed.split_once_byte(';');
    let disp_part = disp_part_raw.trim_lws();
    guard is_valid_header_name(disp_part) else { return mt, false; }
    guard disp_part.len <= mt.type_name.cap else { return mt, false; }

    mt.type_name.append(disp_part);
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
        if eq_ascii_fold(p.name[..], key) {
            return p.value[..];
        }
    }
    return "";
}

fn has_param(mt: const MediaType&, key: const u8[:]) -> bool {
    for &p in mt.params {
        if eq_ascii_fold(p.name[..], key) {
            return true;
        }
    }
    return false;
}

fn is_multipart(mt: const MediaType&) -> bool {
    return eq_ascii_fold(mt.type_name[..], "multipart");
}

fn boundary(mt: const MediaType&) -> const u8[:] {
    return param(mt, "boundary");
}

fn charset(mt: const MediaType&) -> const u8[:] {
    return param(mt, "charset");
}

// ---- structured field values -----------------------------------------------

enum SfvType {
    Integer,
    Decimal,
    String,
    Token,
    ByteSequence,
    Boolean,
    Date,
    DisplayString,
}

struct SfvBareItem {
    kind: SfvType = SfvType.Boolean,
    int_val: i64 = 0,               // For Integer, Date, and Decimal (scaled * 1000 in milliths)
    bool_val: bool = false,         // For Boolean
    text: u8[..1088] = [],          // For String, Token, ByteSequence, DisplayString (>= 1024 bytes per RFC 8941)
}

struct SfvParam {
    key: u8[..64] = [],
    value: SfvBareItem = SfvBareItem { .. },
}

struct SfvItem {
    bare: SfvBareItem = SfvBareItem { .. },
    params: SfvParam[..16] = [],
}

struct SfvMember {
    is_inner_list: bool = false,
    item: SfvItem = SfvItem { .. },
    inner_list: SfvItem[..32] = [],
    inner_params: SfvParam[..16] = [],
}

struct SfvList {
    members: SfvMember[..64] = [],
    valid: bool = true,
}

struct SfvDictEntry {
    key: u8[..64] = [],
    member: SfvMember = SfvMember { .. },
}

struct SfvDict {
    entries: SfvDictEntry[..64] = [],
    valid: bool = true,
}

// Helper: skips optional ASCII whitespace SP and HTAB
fn sfv_skip_ows(raw: const u8[:], cursor: i64&) {
    while cursor < raw.len && (raw[cursor] == ' ' || raw[cursor] == '\t') {
        cursor++;
    }
}

// RFC 8941 Section 3.1.2: Dictionary key parser
// key = ( lcalpha / "*" ) *( lcalpha / DIGIT / "_" / "-" / "." / "*" )
fn parse_sfv_key(raw: const u8[:], cursor: i64&, out_key: u8[..64]&) -> bool {
    guard cursor < raw.len else { return false; }
    let first = raw[cursor];
    // First char MUST be lowercase ASCII 'a'..'z' or '*'
    guard (first >= 'a' && first <= 'z') || first == '*' else { return false; }

    out_key.clear();
    out_key.push(first);
    cursor++;

    while cursor < raw.len {
        let b = raw[cursor];
        if (b >= 'a' && b <= 'z') || (b >= '0' && b <= '9') || b == '_' || b == '-' || b == '.' || b == '*' {
            guard out_key.len < out_key.cap else { return false; }
            out_key.push(b);
            cursor++;
        } else if b >= 'A' && b <= 'Z' {
            // Uppercase in key is a STRICT SYNTAX ERROR per RFC 8941 Section 3.1.2
            return false;
        } else {
            break;
        }
    }
    return true;
}

fn parse_sfv_decimal_tail(raw: const u8[:], cursor: i64&, num_val: i64, int_digit_count: i64, is_neg: bool, out_bare: SfvBareItem&) -> bool {
    // sf-decimal: up to 12 int digits, 1..3 frac digits (RFC 8941 Section 3.3.2)
    guard int_digit_count >= 1 && int_digit_count <= 12 else { return false; }
    cursor++; // skip '.'
    guard cursor < raw.len && raw[cursor] >= '0' && raw[cursor] <= '9' else { return false; }

    var frac_digits: i64 = 0;
    var frac_val: i64 = 0;
    while cursor < raw.len && raw[cursor] >= '0' && raw[cursor] <= '9' {
        frac_digits++;
        guard frac_digits <= 3 else { return false; }
        frac_val = frac_val * 10 + (raw[cursor] - '0');
        cursor++;
    }

    if frac_digits == 1 { frac_val *= 100; }
    else if frac_digits == 2 { frac_val *= 10; }

    var total_scaled = num_val * 1000 + frac_val;
    if is_neg { total_scaled = -total_scaled; }

    out_bare.kind = SfvType.Decimal;
    out_bare.int_val = total_scaled;
    return true;
}

// RFC 8941 Section 3.3.1: sf-integer & Section 3.3.2: sf-decimal
fn parse_sfv_integer_or_decimal(raw: const u8[:], cursor: i64&, out_bare: SfvBareItem&) -> bool {
    guard cursor < raw.len else { return false; }
    var is_neg = false;

    if raw[cursor] == '-' {
        is_neg = true;
        cursor++;
        guard cursor < raw.len else { return false; }
    }

    var num_val: i64 = 0;
    var int_digit_count: i64 = 0;
    guard cursor < raw.len && raw[cursor] >= '0' && raw[cursor] <= '9' else { return false; }

    while cursor < raw.len && raw[cursor] >= '0' && raw[cursor] <= '9' {
        int_digit_count++;
        guard int_digit_count <= 15 else { return false; }
        let d = raw[cursor] - '0';
        num_val = num_val * 10 + d;
        cursor++;
    }

    if cursor < raw.len && raw[cursor] == '.' {
        return parse_sfv_decimal_tail(raw, cursor, num_val, int_digit_count, is_neg, out_bare);
    }

    guard int_digit_count >= 1 && int_digit_count <= 15 else { return false; }
    let max_val: i64 = 999999999999999;
    guard num_val <= max_val else { return false; }

    out_bare.kind = SfvType.Integer;
    out_bare.int_val = if is_neg { -num_val } else { num_val };
    return true;
}

// RFC 8941 Section 3.3.3: sf-string
// DQUOTE *chr DQUOTE, printable ASCII %x20-7E, escaped only as \" or \\
fn parse_sfv_string(raw: const u8[:], cursor: i64&, out_bare: SfvBareItem&) -> bool {
    guard cursor < raw.len && raw[cursor] == '"' else { return false; }
    cursor++; // skip initial '"'

    out_bare.kind = SfvType.String;
    out_bare.text.clear();

    while cursor < raw.len {
        let b = raw[cursor];
        if b == '"' {
            cursor++; // successfully consumed closing '"'
            return true;
        } else if b == '\\' {
            cursor++;
            guard cursor < raw.len else { return false; }
            let esc = raw[cursor];
            // RFC 8941 Section 3.3.3: ONLY \" and \\ are permitted escape sequences
            guard esc == '"' || esc == '\\' else { return false; }
            guard out_bare.text.try_push(esc) else { return false; }
            cursor++;
        } else {
            // Printable ASCII %x20-7E only
            guard b >= 0x20 && b <= 0x7E else { return false; }
            guard out_bare.text.try_push(b) else { return false; }
            cursor++;
        }
    }
    return false; // Unclosed string
}

// RFC 8941 Section 3.3.4: sf-token
// ( ALPHA / "*" ) *( tchar / ":" / "/" )
fn parse_sfv_token(raw: const u8[:], cursor: i64&, out_bare: SfvBareItem&) -> bool {
    guard cursor < raw.len else { return false; }
    let first = raw[cursor];
    guard (first >= 'a' && first <= 'z') || (first >= 'A' && first <= 'Z') || first == '*' else { return false; }

    out_bare.kind = SfvType.Token;
    out_bare.text.clear();
    out_bare.text.push(first);
    cursor++;

    while cursor < raw.len {
        let b = raw[cursor];
        if is_tchar(b) || b == ':' || b == '/' {
            guard out_bare.text.len < out_bare.text.cap else { return false; }
            out_bare.text.push(b);
            cursor++;
        } else {
            break;
        }
    }
    return true;
}

// RFC 8941 Section 3.3.5: sf-binary
// ":" *(base64) ":"
fn parse_sfv_binary(raw: const u8[:], cursor: i64&, out_bare: SfvBareItem&) -> bool {
    guard cursor < raw.len && raw[cursor] == ':' else { return false; }
    cursor++; // skip initial ':'

    out_bare.kind = SfvType.ByteSequence;
    out_bare.text.clear();

    var b64_bytes: u8[..1088] = [];
    while cursor < raw.len && raw[cursor] != ':' {
        let b = raw[cursor];
        guard (b >= 'A' && b <= 'Z') || (b >= 'a' && b <= 'z') || (b >= '0' && b <= '9') || b == '+' || b == '/' || b == '=' else {
            return false;
        }
        guard b64_bytes.len < b64_bytes.cap else { return false; }
        b64_bytes.push(b);
        cursor++;
    }
    guard cursor < raw.len && raw[cursor] == ':' else { return false; }
    cursor++; // skip closing ':'

    // Decode Base64
    guard decode_base64(b64_bytes[..], out_bare.text) else { return false; }
    return true;
}

fn b64_val(c: u8) -> i32 {
    if c >= 'A' && c <= 'Z' { return c - 'A'; }
    if c >= 'a' && c <= 'z' { return c - 'a' + 26; }
    if c >= '0' && c <= '9' { return c - '0' + 52; }
    if c == '+' { return 62; }
    if c == '/' { return 63; }
    return -1;
}

fn decode_base64<B>(src: const u8[:], out: B&) -> bool {
    guard (src.len % 4) == 0 else { return false; }
    var i: i64 = 0;
    while i < src.len {
        let c0 = src[i];
        let c1 = src[i + 1];
        let c2 = src[i + 2];
        let c3 = src[i + 3];

        let v0 = b64_val(c0);
        let v1 = b64_val(c1);
        guard v0 >= 0 && v1 >= 0 else { return false; }

        if c2 == '=' {
            guard c3 == '=' && i + 4 == src.len else { return false; }
            guard (v1 & 0x0F) == 0 else { return false; } // non-zero pad bits
            guard out.len < out.cap else { return false; }
            out.push(((v0 << 2) | (v1 >> 4)) as u8);
        } else if c3 == '=' {
            guard i + 4 == src.len else { return false; }
            let v2 = b64_val(c2);
            guard v2 >= 0 else { return false; }
            guard (v2 & 0x03) == 0 else { return false; } // non-zero pad bits
            guard out.len + 2 <= out.cap else { return false; }
            out.push(((v0 << 2) | (v1 >> 4)) as u8);
            out.push(((v1 << 4) | (v2 >> 2)) as u8);
        } else {
            let v2 = b64_val(c2);
            let v3 = b64_val(c3);
            guard v2 >= 0 && v3 >= 0 else { return false; }
            guard out.len + 3 <= out.cap else { return false; }
            out.push(((v0 << 2) | (v1 >> 4)) as u8);
            out.push(((v1 << 4) | (v2 >> 2)) as u8);
            out.push(((v2 << 6) | v3) as u8);
        }
        i += 4;
    }
    return true;
}

// RFC 8941 Section 3.3.6: sf-boolean ("?0" or "?1")
fn parse_sfv_boolean(raw: const u8[:], cursor: i64&, out_bare: SfvBareItem&) -> bool {
    guard cursor + 1 < raw.len && raw[cursor] == '?' else { return false; }
    let b = raw[cursor + 1];
    guard b == '0' || b == '1' else { return false; }
    out_bare.kind = SfvType.Boolean;
    out_bare.bool_val = (b == '1');
    cursor += 2;
    return true;
}

// RFC 9651 Section 3.3.7: sf-date ("@" sf-integer)
fn parse_sfv_date(raw: const u8[:], cursor: i64&, out_bare: SfvBareItem&) -> bool {
    guard cursor < raw.len && raw[cursor] == '@' else { return false; }
    cursor++; // skip '@'
    var item = SfvBareItem { .. };
    guard parse_sfv_integer_or_decimal(raw, cursor, item) else { return false; }
    guard item.kind == SfvType.Integer else { return false; } // Decimal date is forbidden
    out_bare.kind = SfvType.Date;
    out_bare.int_val = item.int_val;
    return true;
}

inline fn lower_hex_val(b: u8) -> i32 {
    if b >= '0' && b <= '9' { return b - '0'; }
    if b >= 'a' && b <= 'f' { return b - 'a' + 10; }
    return -1;
}

// RFC 9651 Section 3.3.8: sf-displaystring (%" DQUOTE *(unescaped / pct-encoded) DQUOTE)
fn parse_sfv_display_string(raw: const u8[:], cursor: i64&, out_bare: SfvBareItem&) -> bool {
    guard cursor + 1 < raw.len && raw[cursor] == '%' && raw[cursor + 1] == '"' else { return false; }
    cursor += 2; // skip %"

    out_bare.kind = SfvType.DisplayString;
    out_bare.text.clear();

    while cursor < raw.len {
        let b = raw[cursor];
        if b == '"' {
            cursor++; // consumed closing quote
            // Validate that decoded bytes are valid UTF-8
            guard validate_utf8(out_bare.text[..]) else { return false; }
            return true;
        } else if b == '%' {
            // Percent-encoded byte %xx: MUST use lowercase hex digits per RFC 9651 Section 3.3.8
            guard cursor + 2 < raw.len else { return false; }
            let v0 = lower_hex_val(raw[cursor + 1]);
            let v1 = lower_hex_val(raw[cursor + 2]);
            guard v0 >= 0 && v1 >= 0 else { return false; } // Uppercase hex (A-F) is FORBIDDEN
            let decoded_byte = ((v0 << 4) | v1) as u8;
            guard out_bare.text.try_push(decoded_byte) else { return false; }
            cursor += 3;
        } else {
            // Printable ASCII %x20-7E except % and "
            guard b >= 0x20 && b <= 0x7E && b != '%' && b != '"' else { return false; }
            guard out_bare.text.try_push(b) else { return false; }
            cursor++;
        }
    }
    return false;
}

// UTF-8 byte sequence validator
fn validate_utf8(data: const u8[:]) -> bool {
    var i: i64 = 0;
    while i < data.len {
        let b0 = data[i];
        if b0 <= 0x7F {
            i++;
        } else if (b0 & 0xE0) == 0xC0 {
            guard i + 1 < data.len else { return false; }
            let b1 = data[i + 1];
            guard (b1 & 0xC0) == 0x80 else { return false; }
            guard b0 >= 0xC2 else { return false; } // Overlong
            i += 2;
        } else if (b0 & 0xF0) == 0xE0 {
            guard i + 2 < data.len else { return false; }
            let b1 = data[i + 1];
            let b2 = data[i + 2];
            guard (b1 & 0xC0) == 0x80 && (b2 & 0xC0) == 0x80 else { return false; }
            if b0 == 0xE0 && b1 < 0xA0 { return false; } // Overlong
            if b0 == 0xED && b1 >= 0xA0 { return false; } // UTF-16 surrogates U+D800..U+DFFF
            i += 3;
        } else if (b0 & 0xF8) == 0xF0 {
            guard i + 3 < data.len else { return false; }
            let b1 = data[i + 1];
            let b2 = data[i + 2];
            let b3 = data[i + 3];
            guard (b1 & 0xC0) == 0x80 && (b2 & 0xC0) == 0x80 && (b3 & 0xC0) == 0x80 else { return false; }
            if b0 == 0xF0 && b1 < 0x90 { return false; } // Overlong
            if b0 == 0xF4 && b1 > 0x8F { return false; } // Above U+10FFFF
            guard b0 <= 0xF4 else { return false; }
            i += 4;
        } else {
            return false;
        }
    }
    return true;
}

// RFC 8941 Section 3.3: Bare item dispatcher
fn parse_sfv_bare_item(raw: const u8[:], cursor: i64&, out_bare: SfvBareItem&) -> bool {
    guard cursor < raw.len else { return false; }
    let b = raw[cursor];

    if b == '"' {
        return parse_sfv_string(raw, cursor, out_bare);
    }
    if b == '%' && cursor + 1 < raw.len && raw[cursor + 1] == '"' {
        return parse_sfv_display_string(raw, cursor, out_bare);
    }
    if b == '?' {
        return parse_sfv_boolean(raw, cursor, out_bare);
    }
    if b == '@' {
        return parse_sfv_date(raw, cursor, out_bare);
    }
    if b == ':' {
        return parse_sfv_binary(raw, cursor, out_bare);
    }
    if (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z') || b == '*' {
        return parse_sfv_token(raw, cursor, out_bare);
    }
    if (b >= '0' && b <= '9') || b == '-' {
        return parse_sfv_integer_or_decimal(raw, cursor, out_bare);
    }
    return false;
}

// RFC 8941 Section 3.1.2: Parameters parser (*( ";" *SP key [ "=" bare-item ] ))
fn parse_sfv_parameters(raw: const u8[:], cursor: i64&, out_params: SfvParam[..16]&) -> bool {
    while cursor < raw.len && raw[cursor] == ';' {
        cursor++; // skip ';'
        sfv_skip_ows(raw, cursor);

        var param_key: u8[..64] = [];
        guard parse_sfv_key(raw, cursor, param_key) else { return false; }

        var param_val = SfvBareItem { kind: SfvType.Boolean, bool_val: true, .. };
        if cursor < raw.len && raw[cursor] == '=' {
            cursor++; // skip '='
            guard parse_sfv_bare_item(raw, cursor, param_val) else { return false; }
        }

        // Add or overwrite duplicate param key
        var found = false;
        for &p in out_params {
            if p.key[..] == param_key[..] {
                p.value = param_val;
                found = true;
                break;
            }
        }
        if !found {
            guard out_params.len < out_params.cap else { return false; }
            var new_p = SfvParam { key: param_key, value: param_val };
            out_params.push(new_p);
        }
    }
    return true;
}

// RFC 8941 Section 3.3: Item parser
fn parse_sfv_item(raw: const u8[:], out: SfvItem&) -> bool {
    var cursor: i64 = 0;
    sfv_skip_ows(raw, cursor);
    guard cursor < raw.len else { return false; }

    var bare = SfvBareItem { .. };
    guard parse_sfv_bare_item(raw, cursor, bare) else { return false; }

    var params: SfvParam[..16] = [];
    guard parse_sfv_parameters(raw, cursor, params) else { return false; }

    sfv_skip_ows(raw, cursor);
    guard cursor == raw.len else { return false; } // Strict atomicity: no trailing junk!

    out.bare = bare;
    out.params.clear();
    for &p in params { out.params.push(p); }
    return true;
}

fn parse_sfv_inner_list(raw: const u8[:], cursor: i64&, member: SfvMember&) -> bool {
    member.is_inner_list = true;
    cursor++; // skip '('
    while cursor < raw.len {
        sfv_skip_ows(raw, cursor);
        if cursor < raw.len && raw[cursor] == ')' {
            cursor++;
            break;
        }
        var item = SfvItem { .. };
        guard parse_sfv_bare_item(raw, cursor, item.bare) else { return false; }
        guard parse_sfv_parameters(raw, cursor, item.params) else { return false; }
        guard member.inner_list.len < member.inner_list.cap else { return false; }
        member.inner_list.push(item);
        guard cursor < raw.len && (raw[cursor] == ' ' || raw[cursor] == ')') else { return false; }
    }
    return parse_sfv_parameters(raw, cursor, member.inner_params);
}

fn parse_sfv_member_item(raw: const u8[:], cursor: i64&, member: SfvMember&) -> bool {
    member.is_inner_list = false;
    guard parse_sfv_bare_item(raw, cursor, member.item.bare) else { return false; }
    return parse_sfv_parameters(raw, cursor, member.item.params);
}

fn sfv_advance_comma(raw: const u8[:], cursor: i64&, has_more: bool&) -> bool {
    has_more = false;
    sfv_skip_ows(raw, cursor);
    if cursor == raw.len {
        return true;
    }
    guard raw[cursor] == ',' else { return false; }
    cursor++; // skip ','
    sfv_skip_ows(raw, cursor);
    guard cursor < raw.len else { return false; } // Trailing comma without following member
    has_more = true;
    return true;
}

// RFC 8941 Section 3.1: List parser (supports items and inner lists)
fn parse_sfv_list(raw: const u8[:], out: SfvList&) -> bool {
    out.members.clear();
    out.valid = false;

    var cursor: i64 = 0;
    sfv_skip_ows(raw, cursor);
    if cursor == raw.len {
        out.valid = true;
        return true; // Empty list is valid
    }

    while cursor < raw.len {
        var member = SfvMember { .. };
        if raw[cursor] == '(' {
            guard parse_sfv_inner_list(raw, cursor, member) else { return false; }
        } else {
            guard parse_sfv_member_item(raw, cursor, member) else { return false; }
        }

        guard out.members.len < out.members.cap else { return false; }
        out.members.push(member);

        var has_more = false;
        guard sfv_advance_comma(raw, cursor, has_more) else { return false; }
        if !has_more { break; }
    }

    out.valid = true;
    return true;
}

// RFC 8941 Section 3.2: Dictionary parser
fn parse_sfv_dict(raw: const u8[:], out: SfvDict&) -> bool {
    out.entries.clear();
    out.valid = false;

    var cursor: i64 = 0;
    sfv_skip_ows(raw, cursor);
    if cursor == raw.len {
        out.valid = true;
        return true; // Empty dictionary is valid
    }

    while cursor < raw.len {
        var key: u8[..64] = [];
        guard parse_sfv_key(raw, cursor, key) else { return false; }

        var member = SfvMember { .. };
        if cursor < raw.len && raw[cursor] == '=' {
            cursor++; // skip '='
            if cursor < raw.len && raw[cursor] == '(' {
                guard parse_sfv_inner_list(raw, cursor, member) else { return false; }
            } else {
                guard parse_sfv_member_item(raw, cursor, member) else { return false; }
            }
        } else {
            // Bare key with no '=' defaults to boolean true with optional parameters
            member.is_inner_list = false;
            member.item.bare = SfvBareItem { kind: SfvType.Boolean, bool_val: true, .. };
            guard parse_sfv_parameters(raw, cursor, member.item.params) else { return false; }
        }

        // Duplicate key updates in-place per RFC 8941 Section 3.2
        var found = false;
        for &entry in out.entries {
            if entry.key[..] == key[..] {
                entry.member = member;
                found = true;
                break;
            }
        }
        if !found {
            guard out.entries.len < out.entries.cap else { return false; }
            var new_entry = SfvDictEntry { key: key, member: member };
            out.entries.push(new_entry);
        }

        var has_more = false;
        guard sfv_advance_comma(raw, cursor, has_more) else { return false; }
        if !has_more { break; }
    }

    out.valid = true;
    return true;
}

// Decimal serialization per RFC 8941 Section 4.1.5
fn serialize_sfv_decimal(scaled_milli: i64, out: u8[>..]&) {
    if scaled_milli < 0 {
        out.push('-');
    }
    let abs_val = if scaled_milli < 0 { -scaled_milli } else { scaled_milli };
    let int_part = abs_val / 1000;
    var frac_part = abs_val % 1000;

    format(out, int_part);
    out.push('.');

    // At least 1 digit after dot, strip trailing zeros
    if frac_part == 0 {
        out.push('0');
    } else if (frac_part % 100) == 0 {
        format(out, frac_part / 100);
    } else if (frac_part % 10) == 0 {
        let d = frac_part / 10;
        if d < 10 { out.push('0'); }
        format(out, d);
    } else {
        if frac_part < 10 { out.push('0'); out.push('0'); }
        else if frac_part < 100 { out.push('0'); }
        format(out, frac_part);
    }
}
