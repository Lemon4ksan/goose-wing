// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// RFC 8941 & RFC 9651 Structured Field Values for HTTP.
// Provides zero-allocation parsing, inspection, and serialization of HTTP
// structured fields (sf-item, sf-list, sf-dictionary, sf-inner-list, sf-parameters).
namespace wing;

import std;
import core from "..";

// ---- Data Types & Enums --------------------------------------------------

enum SfType {
    Integer,
    Decimal,
    String,
    Token,
    Binary,
    Boolean,
    Date,
    DisplayString,
}

struct SfItem {
    kind:     SfType      = SfType.Token,
    int_val:  i64         = 0,
    dec_val:  f64         = 0.0,
    str_val:  const u8[:] = "",
    bool_val: bool        = false,
}

struct SfParameter {
    key:  const u8[:] = "",
    item: SfItem      = SfItem { .. },
}

struct SfParameterizedItem {
    item:          SfItem           = SfItem { .. },
    params:        SfParameter[..8] = [],
    is_inner_list: bool             = false,
    inner_items:   SfItem[..8]      = [],
}

struct SfDictEntry {
    key:           const u8[:]      = "",
    is_inner_list: bool             = false,
    item:          SfItem           = SfItem { .. },
    params:        SfParameter[..8] = [],
    inner_items:   SfItem[..8]      = [],
}

// ---- Whitespace & Index Scanners -----------------------------------------

fn sf_skip_ws(src: const u8[:], pos: i64) -> i64 {
    var p = pos;
    while p < src.len && core::is_lws(src[p]) {
        p = p + 1;
    }
    return p;
}

fn sf_skip_ws_and_commas(src: const u8[:], pos: i64) -> i64 {
    var p = pos;
    while p < src.len {
        let ch = src[p];
        if core::is_lws(ch) || ch == ',' {
            p = p + 1;
        } else {
            break;
        }
    }
    return p;
}

// ---- Primitive Parsers ---------------------------------------------------

// Parses an RFC 8941 Boolean: ?0 or ?1
fn sf_parse_boolean(src: const u8[:], pos: i64, out_item: SfItem&, out_next: i64&) -> bool {
    let p_plus_1 = pos + 1;
    if p_plus_1 >= src.len || src[pos] != '?' {
        return false;
    }
    let b = src[p_plus_1];
    let next_idx = pos + 2;
    if b == '1' {
        out_item.kind = SfType.Boolean;
        out_item.bool_val = true;
        out_next = next_idx;
        return true;
    }
    if b == '0' {
        out_item.kind = SfType.Boolean;
        out_item.bool_val = false;
        out_next = next_idx;
        return true;
    }
    return false;
}

checkfree inline fn sf_check_escape(src: const u8[:], p: i64) -> bool {
    let p_esc = p + 1;
    guard p_esc < src.len else { return false; }
    let ch = src[p_esc];
    return ch == '\\' || ch == '"';
}

// Parses an RFC 8941 String: "..." with escaping (\", \\)
fn sf_parse_string(src: const u8[:], pos: i64, out_item: SfItem&, out_next: i64&) -> bool {
    if pos >= src.len || src[pos] != '"' {
        return false;
    }
    let start = pos + 1;
    var p = pos + 1;
    while p < src.len {
        let ch = src[p];
        if ch == '\\' {
            guard sf_check_escape(src, p) else { return false; }
            p = p + 2;
        } else if ch == '"' {
            out_item.kind = SfType.String;
            out_item.str_val = src[start..p];
            out_next = p + 1;
            return true;
        } else if !core::is_ascii_printable(ch) {
            return false;
        } else {
            p = p + 1;
        }
    }
    return false;
}

// Parses an RFC 8941 Byte Sequence: :base64:
fn sf_parse_binary(src: const u8[:], pos: i64, out_item: SfItem&, out_next: i64&) -> bool {
    if pos >= src.len || src[pos] != ':' {
        return false;
    }
    let start = core::add_sat_i64(pos, 1);
    var p = core::add_sat_i64(pos, 1);
    var eq_count:   i64 = 0;
    var data_count: i64 = 0;
    while p < src.len {
        let ch = src[p];
        if ch == ':' {
            let b64_len = core::sub_sat_i64(p, start);
            guard (b64_len & 3) == 0 && eq_count <= 2 && (eq_count == 0 || data_count > 0) else { return false; }
            out_item.kind = SfType.Binary;
            out_item.str_val = src[start..p];
            out_next = core::add_sat_i64(p, 1);
            return true;
        }
        if ch == '=' {
            eq_count = core::add_sat_i64(eq_count, 1);
        } else {
            guard eq_count == 0 else { return false; }
            guard core::is_ascii_alpha(ch) || core::is_ascii_digit(ch) || ch == '+' || ch == '/' else {
                return false;
            }
            data_count = core::add_sat_i64(data_count, 1);
        }
        p = core::add_sat_i64(p, 1);
    }
    return false;
}

// Parses an RFC 8941 Token: starts with alpha or *, followed by tchar, :, /
fn sf_parse_token(src: const u8[:], pos: i64, out_item: SfItem&, out_next: i64&) -> bool {
    if pos >= src.len {
        return false;
    }
    let first = src[pos];
    if !core::is_ascii_alpha(first) && first != '*' {
        return false;
    }
    let start = pos;
    var p = start + 1;
    while p < src.len {
        let ch = src[p];
        if core::is_tchar(ch) || ch == ':' || ch == '/' {
            p = p + 1;
        } else {
            break;
        }
    }
    out_item.kind = SfType.Token;
    out_item.str_val = src[start..p];
    out_next = p;
    return true;
}

// Scans an integer digit sequence into an accumulator
fn sf_scan_digits(
    src:        const u8[:],
    pos:        i64,
    max_digits: i32,
    out_accum:  i64&,
    out_count:  i32&,
    out_next:   i64&,
) -> bool {
    var p = pos;
    var accum: i64 = 0;
    var count: i32 = 0;
    while p < src.len && core::is_ascii_digit(src[p]) {
        let digit = (src[p] - '0') as i64;
        accum = accum * 10 + digit;
        count = count + 1;
        p = p + 1;
        if count > max_digits {
            return false;
        }
    }
    out_accum = accum;
    out_count = count;
    out_next = p;
    return count > 0;
}

// Parses fractional component of decimal
fn sf_parse_fraction(
    src:       const u8[:],
    dot_pos:   i64,
    int_accum: i64,
    is_neg:    bool,
    out_item:  SfItem&,
    out_next:  i64&,
) -> bool {
    var frac_accum: i64 = 0;
    var frac_count: i32 = 0;
    var frac_end:   i64 = 0;
    let next_p = core::add_sat_i64(dot_pos, 1);
    let ok = sf_scan_digits(src, next_p, 3, frac_accum, frac_count, frac_end);
    if !ok {
        return false;
    }
    var factor: f64 = 1.0;
    var scaled_frac = frac_accum;
    if frac_count == 1 {
        factor = 0.1;
        scaled_frac = core::mul_sat_i64(frac_accum, 100);
    } else if frac_count == 2 {
        factor = 0.01;
        scaled_frac = core::mul_sat_i64(frac_accum, 10);
    } else if frac_count == 3 {
        factor = 0.001;
    }

    let frac_f = frac_accum * factor;
    var total_f = int_accum + frac_f;
    let abs_milli = core::add_sat_i64(core::mul_sat_i64(int_accum, 1000), scaled_frac);
    if is_neg {
        total_f = -total_f;
    }
    out_item.kind = SfType.Decimal;
    out_item.int_val = if is_neg { core::sub_sat_i64(0, abs_milli) } else { abs_milli };
    out_item.dec_val = total_f;
    out_next = frac_end;
    return true;
}

// Parses an RFC 8941 Integer or Decimal
fn sf_parse_number(src: const u8[:], pos: i64, out_item: SfItem&, out_next: i64&) -> bool {
    if pos >= src.len {
        return false;
    }
    var p = pos;
    var is_neg = false;
    if src[p] == '-' {
        is_neg = true;
        p = p + 1;
        if p >= src.len || !core::is_ascii_digit(src[p]) {
            return false;
        }
    }

    var int_accum:  i64 = 0;
    var int_digits: i32 = 0;
    var int_end:    i64 = 0;
    if !sf_scan_digits(src, p, 15, int_accum, int_digits, int_end) {
        return false;
    }
    p = int_end;

    if p < src.len && src[p] == '.' {
        if int_digits > 12 {
            return false;
        }
        return sf_parse_fraction(src, p, int_accum, is_neg, out_item, out_next);
    }

    out_item.kind = SfType.Integer;
    out_item.int_val = if is_neg { -int_accum } else { int_accum };
    out_next = p;
    return true;
}

// Parses an RFC 9651 Date: @<integer>
fn sf_parse_date(src: const u8[:], pos: i64, out_item: SfItem&, out_next: i64&) -> bool {
    if pos >= src.len || src[pos] != '@' {
        return false;
    }
    var num_item = SfItem { .. };
    var n_next: i64 = 0;
    let next_p = pos + 1;
    if !sf_parse_number(src, next_p, num_item, n_next) || num_item.kind != SfType.Integer {
        return false;
    }
    out_item.kind = SfType.Date;
    out_item.int_val = num_item.int_val;
    out_next = n_next;
    return true;
}

const SF_LC_HEX_LUT: const u8[256] = [
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 255, 255, 255, 255, 255, 255,
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
    255, 10, 11, 12, 13, 14, 15, 255, 255, 255, 255, 255, 255, 255, 255, 255,
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
];

const UTF8_DFA_CLASS: const i64[256] = [
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9,
    7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7,
    8, 8, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
    10, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 4, 3, 3, 11, 6, 6, 6, 5, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8,
];

const UTF8_DFA_TRANS: const i64[108] = [
    0, 12, 24, 36, 60, 96, 84, 12, 12, 12, 48, 72, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12,
    12, 0, 12, 12, 12, 12, 12, 0, 12, 0, 12, 12, 12, 24, 12, 12, 12, 12, 12, 24, 12, 24, 12, 12,
    12, 12, 12, 12, 12, 12, 12, 24, 12, 12, 12, 12, 12, 24, 12, 12, 12, 12, 12, 12, 12, 24, 12, 12,
    12, 12, 12, 12, 12, 12, 12, 36, 12, 36, 12, 12, 12, 36, 12, 12, 12, 12, 12, 36, 12, 36, 12, 12,
    12, 36, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12,
];

checkfree inline fn sf_hex_lc_val(c: u8) -> u8, bool {
    let v = SF_LC_HEX_LUT[c];
    return v, v != 255;
}

checkfree inline fn sf_decode_pct_hex(hi: u8, lo: u8) -> u8, bool {
    let v1, ok1 = sf_hex_lc_val(hi);
    let v2, ok2 = sf_hex_lc_val(lo);
    return (v1 * 16) | v2, ok1 && ok2;
}

inline fn sf_step_utf8_dfa(b: u8, state: i64&) -> bool {
    let cls = UTF8_DFA_CLASS[b];
    let idx = core::add_sat_i64(state, cls);
    guard idx >= 0 && idx < 108 else { return false; }
    state = UTF8_DFA_TRANS[idx];
    return state != 12;
}

fn validate_display_string(raw_str: const u8[:]) -> bool {
    var state: i64 = 0;
    var i:     i64 = 0;
    while i < raw_str.len {
        let b = raw_str[i];
        if b == '%' {
            let i1 = core::add_sat_i64(i, 1);
            let i2 = core::add_sat_i64(i, 2);
            guard i2 < raw_str.len else { return false; }
            let dec_b, hex_ok = sf_decode_pct_hex(raw_str[i1], raw_str[i2]);
            guard hex_ok && sf_step_utf8_dfa(dec_b, state) else { return false; }
            i = core::add_sat_i64(i, 3);
        } else {
            guard b >= 0x20 && b <= 0x7E && b != '%' && b != '"' else { return false; }
            guard sf_step_utf8_dfa(b, state) else { return false; }
            i = core::add_sat_i64(i, 1);
        }
    }
    return state == 0;
}

// Unescapes an RFC 9651 Structured Field String body (handling `\"` and `\\`) into `out`.
//
// Example:
//   raw = "hello \\\"world\\\"", out = []
//   returns: true, out = "hello \"world\""
fn sf_unescape_string<B>(raw: const u8[:], out: B&) -> bool {
    out.clear();
    var committed = false;
    defer if !committed { out.clear(); };
    var i: i64 = 0;
    while i < raw.len {
        let ch = raw[i];
        if ch == '\\' {
            let next_i = core::add_sat_i64(i, 1);
            guard next_i < raw.len else { return false; }
            let esc = raw[next_i];
            guard (esc == '"' || esc == '\\') && out.try_push(esc) else { return false; }
            i = core::add_sat_i64(i, 2);
        } else if ch == '"' || !core::is_ascii_printable(ch) {
            return false;
        } else {
            guard out.try_push(ch) else { return false; }
            i = core::add_sat_i64(i, 1);
        }
    }
    committed = true;
    return true;
}

// Decodes an RFC 9651 Display String body (percent-decoding `%xx` and validating UTF-8) into `out`.
//
// Example:
//   raw = "hello%20%c3%bc", out = []
//   returns: true, out = "hello \xc3\xbc"
fn sf_decode_display_string<B>(raw: const u8[:], out: B&) -> bool {
    out.clear();
    var committed = false;
    defer if !committed { out.clear(); };
    var state: i64 = 0;
    var i:     i64 = 0;
    while i < raw.len {
        let b = raw[i];
        var dec_b: u8  = 0;
        var step:  i64 = 1;
        if b == '%' {
            let i1 = core::add_sat_i64(i, 1);
            let i2 = core::add_sat_i64(i, 2);
            guard i2 < raw.len else { return false; }
            let pct_b, hex_ok = sf_decode_pct_hex(raw[i1], raw[i2]);
            guard hex_ok else { return false; }
            dec_b = pct_b;
            step = 3;
        } else {
            guard b >= 0x20 && b <= 0x7E && b != '%' && b != '"' else { return false; }
            dec_b = b;
        }
        guard sf_step_utf8_dfa(dec_b, state) && out.try_push(dec_b) else { return false; }
        i = core::add_sat_i64(i, step);
    }
    guard state == 0 else { return false; }
    committed = true;
    return true;
}

// Parses an RFC 9651 Section 3.3.4 Display String: %"..."
fn sf_parse_display_string(src: const u8[:], pos: i64, out_item: SfItem&, out_next: i64&) -> bool {
    guard pos + 1 < src.len && src[pos] == '%' && src[pos + 1] == '"' else { return false; }
    let start_idx = pos + 2;
    var p = pos + 2;
    while p < src.len {
        let ch = src[p];
        if ch == '"' {
            let raw_str = src[start_idx..p];
            guard validate_display_string(raw_str) else { return false; }
            out_item.kind = SfType.DisplayString;
            out_item.str_val = raw_str;
            out_next = p + 1;
            return true;
        }
        p = p + 1;
    }
    return false;
}

// Parses any bare RFC 8941 & RFC 9651 item
fn sf_parse_bare_item(src: const u8[:], pos: i64, out_item: SfItem&, out_next: i64&) -> bool {
    if pos >= src.len {
        return false;
    }
    let ch = src[pos];
    if ch == '%' {
        return sf_parse_display_string(src, pos, out_item, out_next);
    }
    if ch == '?' {
        return sf_parse_boolean(src, pos, out_item, out_next);
    }
    if ch == '"' {
        return sf_parse_string(src, pos, out_item, out_next);
    }
    if ch == ':' {
        return sf_parse_binary(src, pos, out_item, out_next);
    }
    if ch == '@' {
        return sf_parse_date(src, pos, out_item, out_next);
    }
    if ch == '-' || core::is_ascii_digit(ch) {
        return sf_parse_number(src, pos, out_item, out_next);
    }
    if core::is_ascii_alpha(ch) || ch == '*' {
        return sf_parse_token(src, pos, out_item, out_next);
    }
    return false;
}

inline fn is_sf_key_char(b: u8) -> bool {
    return (b >= 'a' && b <= 'z') || core::is_ascii_digit(b) || b == '_' || b == '-' || b == '.' || b == '*';
}

// Parses an RFC 8941 Key: lcalpha, digit, _, -, ., *
//
// Example:
//   src = "foo_bar=1", pos = 0
//   returns: "foo_bar", next_pos = 7, ok = true
fn sf_parse_key(src: const u8[:], pos: i64) -> const u8[:], i64, bool {
    if pos >= src.len {
        return "", pos, false;
    }
    let first = src[pos];
    if !((first >= 'a' && first <= 'z') || first == '*') {
        return "", pos, false;
    }
    let start = pos;
    var p = start + 1;
    while p < src.len && is_sf_key_char(src[p]) {
        p = p + 1;
    }
    return src[start..p], p, true;
}

// Parses parameters: ;key=val;flag;key2=val2
fn sf_parse_parameters(src: const u8[:], pos: i64, out_params: SfParameter[..8]&, out_next: i64&) -> bool {
    var p = pos;
    while p < src.len {
        p = sf_skip_ws(src, p);
        if p >= src.len || src[p] != ';' {
            break;
        }
        p = p + 1; // skip ';'
        p = sf_skip_ws(src, p);

        let key, k_next, ok_k = sf_parse_key(src, p);
        if !ok_k {
            return false;
        }
        p = k_next;

        var val_item = SfItem { kind: SfType.Boolean, bool_val: true };
        if p < src.len && src[p] == '=' {
            p = p + 1; // skip '='
            var v_next: i64 = 0;
            if !sf_parse_bare_item(src, p, val_item, v_next) {
                return false;
            }
            p = v_next;
        }

        var found_idx: i64 = -1;
        for i in out_params.len {
            if out_params[i].key == key {
                found_idx = i;
                break;
            }
        }
        let param = SfParameter { key: key, item: val_item };
        if found_idx >= 0 {
            out_params[found_idx] = param;
        } else if out_params.len < 8 {
            out_params.push(param);
        } else {
            return false;
        }
    }
    out_next = p;
    return true;
}

// ---- Item, List, & Dictionary High-Level Parsers -------------------------

// Parses a standalone parameterized item (RFC 8941 Section 3.3).
//
// Example:
//   input = "123; foo=bar"
//   returns: result with item kind Integer, value 123, ok = true
fn parse_sf_item(input: const u8[:]) -> SfParameterizedItem, bool {
    var result = SfParameterizedItem { .. };
    let trimmed = input.trim_ascii_space();
    if trimmed.len == 0 {
        return result, false;
    }
    var pos: i64 = 0;
    var bare_item = SfItem { .. };
    var n_pos: i64 = 0;
    if !sf_parse_bare_item(trimmed, pos, bare_item, n_pos) {
        return result, false;
    }
    result.item = bare_item;
    pos = n_pos;

    var params_next: i64 = 0;
    if !sf_parse_parameters(trimmed, pos, result.params, params_next) {
        return result, false;
    }
    let end_p = sf_skip_ws(trimmed, params_next);
    if end_p != trimmed.len {
        return result, false;
    }
    return result, true;
}

// Helper: parses inner list contents (item1 item2 ...) per RFC 8941 §4.2.1.2
fn sf_parse_inner_list_items(
    src:         const u8[:],
    pos:         i64,
    inner_items: SfItem[..8]&,
    out_next:    i64&,
) -> bool {
    var p = core::add_sat_i64(pos, 1); // skip '('
    while p < src.len {
        while p < src.len && src[p] == ' ' {
            p = core::add_sat_i64(p, 1);
        }
        if p < src.len && src[p] == ')' {
            out_next = core::add_sat_i64(p, 1);
            return true;
        }
        let item_start = p;
        var inner_item = SfItem { .. };
        var in_next:     i64              = 0;
        var item_params: SfParameter[..8] = [];
        var params_next: i64              = 0;
        guard sf_parse_bare_item(src, p, inner_item, in_next) &&
              sf_parse_parameters(src, in_next, item_params, params_next) &&
              inner_items.len < 8 else {
            return false;
        }
        if item_params.len == 1 && item_params[0].key == "req" && src[item_start] == '"' {
            let req_end = core::add_sat_i64(in_next, 4);
            if req_end <= src.len && src[in_next..req_end] == ";req" {
                inner_item.str_val = src[core::add_sat_i64(item_start, 1)..req_end];
            }
        }
        p = in_next;
        while p < params_next && src[p] != ' ' && src[p] != ')' {
            p = core::add_sat_i64(p, 1);
        }
        inner_items.push(inner_item);
        guard p < src.len && (src[p] == ' ' || src[p] == ')') else { return false; }
    }
    return false;
}

// Helper: parses inner list contents (item1 item2 ...) per RFC 8941 §4.2.1.2
fn sf_parse_inner_list(src: const u8[:], pos: i64, entry: SfDictEntry&, out_next: i64&) -> bool {
    entry.is_inner_list = true;
    return sf_parse_inner_list_items(src, pos, entry.inner_items, out_next);
}

// Parses a single dictionary entry value and its parameters
fn sf_parse_dict_entry_value(src: const u8[:], pos: i64, entry: SfDictEntry&, out_next: i64&) -> bool {
    var p = pos;
    if p < src.len && src[p] == '=' {
        p = p + 1; // skip '='
        if p < src.len && src[p] == '(' {
            var in_next: i64 = 0;
            if !sf_parse_inner_list(src, p, entry, in_next) {
                return false;
            }
            p = in_next;
        } else {
            var item_val = SfItem { .. };
            var v_next: i64 = 0;
            if !sf_parse_bare_item(src, p, item_val, v_next) {
                return false;
            }
            entry.item = item_val;
            p = v_next;
        }
    }

    var params_next: i64 = 0;
    if !sf_parse_parameters(src, p, entry.params, params_next) {
        return false;
    }
    out_next = params_next;
    return true;
}

// Parses a single dictionary entry (key[=val][;params])
fn sf_parse_single_dict_entry(src: const u8[:], pos: i64, entry: SfDictEntry&, out_next: i64&) -> bool {
    let key, k_next, ok_k = sf_parse_key(src, pos);
    if !ok_k {
        return false;
    }
    entry.key = key;
    entry.item = SfItem { kind: SfType.Boolean, bool_val: true };

    var val_next: i64 = 0;
    if !sf_parse_dict_entry_value(src, k_next, entry, val_next) {
        return false;
    }
    out_next = val_next;
    return true;
}

// RFC 8941 Section 3.2.2: Duplicate dictionary keys overwrite the existing member in place.
fn upsert_sf_dict_entry(out_entries: SfDictEntry[..16]&, entry: SfDictEntry) -> bool {
    for i in out_entries.len {
        if out_entries[i].key == entry.key {
            out_entries[i] = entry;
            return true;
        }
    }
    return out_entries.try_push(entry);
}

// Parses an RFC 8941 Dictionary (Section 3.2): key=val, key2, key3=(a b);param
//
// Example:
//   input = "a=1, b=2"
//   returns: true, out_entries has 2 dictionary entries
fn parse_sf_dict(input: const u8[:], out_entries: SfDictEntry[..16]&) -> bool {
    out_entries.clear();
    let trimmed = input.trim_ascii_space();
    if trimmed.len == 0 {
        return true;
    }
    var committed = false;
    defer if !committed { out_entries.clear(); };
    var p: i64 = 0;
    while p < trimmed.len {
        var entry = SfDictEntry { .. };
        var entry_next: i64 = 0;
        guard sf_parse_single_dict_entry(trimmed, p, entry, entry_next) else { return false; }
        p = entry_next;

        guard upsert_sf_dict_entry(out_entries, entry) else { return false; }

        p = sf_skip_ws(trimmed, p);
        if p < trimmed.len {
            guard trimmed[p] == ',' else { return false; }
            p = sf_skip_ws(trimmed, core::add_sat_i64(p, 1));
            guard p < trimmed.len else { return false; }
        }
    }
    committed = true;
    return true;
}

// Helper: parses a single list entry (bare item or inner list)
fn sf_parse_single_list_entry(src: const u8[:], pos: i64, p_item: SfParameterizedItem&, out_next: i64&) -> bool {
    var i_next: i64 = 0;
    if pos < src.len && src[pos] == '(' {
        p_item.is_inner_list = true;
        if !sf_parse_inner_list_items(src, pos, p_item.inner_items, i_next) {
            return false;
        }
    } else {
        var item = SfItem { .. };
        if !sf_parse_bare_item(src, pos, item, i_next) {
            return false;
        }
        p_item.item = item;
    }

    var params_next: i64 = 0;
    if !sf_parse_parameters(src, i_next, p_item.params, params_next) {
        return false;
    }
    out_next = params_next;
    return true;
}

// Parses an RFC 8941 List (Section 3.1): item1, item2, "string", ?1
//
// Example:
//   input = "1, 2, \"three\""
//   returns: true, out_items has 3 elements
fn parse_sf_list(input: const u8[:], out_items: SfParameterizedItem[..16]&) -> bool {
    out_items.clear();
    let trimmed = input.trim_ascii_space();
    if trimmed.len == 0 {
        return true;
    }
    var committed = false;
    defer if !committed { out_items.clear(); };
    var p: i64 = 0;
    while p < trimmed.len {
        var p_item = SfParameterizedItem { .. };
        var item_next: i64 = 0;
        guard sf_parse_single_list_entry(trimmed, p, p_item, item_next) else { return false; }
        p = item_next;

        guard out_items.try_push(p_item) else { return false; }

        p = sf_skip_ws(trimmed, p);
        if p < trimmed.len {
            guard trimmed[p] == ',' else { return false; }
            p = sf_skip_ws(trimmed, core::add_sat_i64(p, 1));
            guard p < trimmed.len else { return false; }
        }
    }
    committed = true;
    return true;
}

// ---- Zero-Alloc Fast Dictionary Accessors --------------------------------

// Extracts integer value for key from an RFC 8941 dictionary without heap allocations.
fn sf_dict_get_int(dict_str: const u8[:], key: const u8[:], default_val: i64 = 0) -> i64 {
    var entries: SfDictEntry[..16] = [];
    if !parse_sf_dict(dict_str, entries) {
        return default_val;
    }
    for &entry in entries {
        if entry.key == key && !entry.is_inner_list && entry.item.kind == SfType.Integer {
            return entry.item.int_val;
        }
    }
    return default_val;
}

// Extracts boolean value for key from an RFC 8941 dictionary.
// In RFC 8941, bare keys like `flag` in `flag, u=3` default to boolean true `?1`.
fn sf_dict_get_bool(dict_str: const u8[:], key: const u8[:], default_val: bool = false) -> bool {
    var entries: SfDictEntry[..16] = [];
    if !parse_sf_dict(dict_str, entries) {
        return default_val;
    }
    for &entry in entries {
        if entry.key == key {
            if !entry.is_inner_list && entry.item.kind == SfType.Boolean {
                return entry.item.bool_val;
            }
        }
    }
    return default_val;
}

// Extracts token or string value for key from an RFC 8941 dictionary.
fn sf_dict_get_token(dict_str: const u8[:], key: const u8[:]) -> const u8[:] {
    var entries: SfDictEntry[..16] = [];
    if !parse_sf_dict(dict_str, entries) {
        return "";
    }
    for &entry in entries {
        let is_str = entry.item.kind == SfType.Token || entry.item.kind == SfType.String;
        if entry.key == key && !entry.is_inner_list && is_str {
            return entry.item.str_val;
        }
    }
    return "";
}

// Checks if key exists in dictionary.
fn sf_dict_has_key(dict_str: const u8[:], key: const u8[:]) -> bool {
    var entries: SfDictEntry[..16] = [];
    if !parse_sf_dict(dict_str, entries) {
        return false;
    }
    for &entry in entries {
        if entry.key == key {
            return true;
        }
    }
    return false;
}

// ---- Serialization Helpers -----------------------------------------------

inline fn sf_serialize_item<B>(kind: SfType.Integer, item: const SfItem&, out: B&) {
    item.int_val.format_i64_dec(out);
}

inline fn sf_serialize_item<B>(kind: SfType.Decimal, item: const SfItem&, out: B&) {
    let abs_milli: u64 = if item.int_val < 0 {
        core::sub_sat_i64(0, item.int_val) as u64
    } else {
        item.int_val as u64
    };
    if item.int_val < 0 { out.push('-' as u8); }
    let int_part = abs_milli / 1000;
    int_part.format_u64_dec(out);
    out.push('.' as u8);
    let frac = abs_milli % 1000;
    out.push(core::add_sat_u64('0', frac / 100) as u8);
    if (frac % 100) != 0 {
        out.push(core::add_sat_u64('0', (frac / 10) % 10) as u8);
    }
    if (frac % 10) != 0 {
        out.push(core::add_sat_u64('0', frac % 10) as u8);
    }
}

inline fn sf_serialize_item<B>(kind: SfType.Boolean, item: const SfItem&, out: B&) {
    out.append(if item.bool_val { "?1" } else { "?0" });
}

inline fn sf_serialize_item<B>(kind: SfType.Token, item: const SfItem&, out: B&) {
    out.append(item.str_val);
}

inline fn sf_serialize_item<B>(kind: SfType.String, item: const SfItem&, out: B&) {
    out.push('"' as u8);
    for i in item.str_val.len {
        let ch = item.str_val[i];
        if ch == '"' || ch == '\\' {
            out.push('\\' as u8);
        }
        out.push(ch);
    }
    out.push('"' as u8);
}

inline fn sf_serialize_item<B>(kind: SfType.Binary, item: const SfItem&, out: B&) {
    out.push(':' as u8);
    out.append(item.str_val);
    out.push(':' as u8);
}

inline fn sf_serialize_item<B>(kind: SfType.Date, item: const SfItem&, out: B&) {
    out.push('@' as u8);
    item.int_val.format_i64_dec(out);
}

inline fn sf_serialize_item<B>(kind: SfType.DisplayString, item: const SfItem&, out: B&) {
    out.append("%\"");
    out.append(item.str_val);
    out.push('"' as u8);
}

fn sf_serialize_item<B>(item: const SfItem&, out: B&) {
    sf_serialize_item(item.kind, item, out);
}

fn sf_serialize_parameters<B>(params: const SfParameter[:], out: B&) {
    for &p in params {
        out.push(';' as u8);
        out.append(p.key);
        if p.item.kind == SfType.Boolean && p.item.bool_val {
            // omit "= ?1" per RFC 8941 Section 4.1.1.2
            continue;
        }
        out.push('=' as u8);
        sf_serialize_item(p.item, out);
    }
}

fn sf_serialize_dict_entry<B>(entry: const SfDictEntry&, out: B&) {
    out.append(entry.key);
    if entry.is_inner_list {
        out.append("=(");
        for idx in entry.inner_items.len {
            if idx > 0 {
                out.push(' ' as u8);
            }
            sf_serialize_item(entry.inner_items[idx], out);
        }
        out.push(')' as u8);
    } else if entry.item.kind == SfType.Boolean && entry.item.bool_val {
        // omit "=?1" for default boolean true dictionary keys
    } else {
        out.push('=' as u8);
        sf_serialize_item(entry.item, out);
    }
    sf_serialize_parameters(entry.params[..], out);
}
