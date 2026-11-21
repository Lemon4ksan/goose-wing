// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Internal helpers for `http` (http/sfv_sig_internal.goose).
namespace http_internal;

import std;
import core;
import http.request;
import http.response;
import http.sfv;
import http.signatures;

// ---- http/sfv.goose internal helpers ----

fn sf_skip_ws(src: const u8[:], pos: i64) -> i64 {
    var p = pos;
    while p < src.len && core::is_lws(src[p]) {
        p = p + 1;
    }
    return p;
}

fn sf_skip_sp(src: const u8[:], pos: i64) -> i64 {
    var p = pos;
    while p < src.len && src[p] == ' ' {
        p = core::add_sat_i64(p, 1);
    }
    return p;
}

// Parses an RFC 8941 Boolean: ?0 or ?1
fn sf_parse_boolean(src: const u8[:], pos: i64, out_item: http::SfItem&, out_next: i64&) -> bool {
    let p_plus_1 = pos + 1;
    if p_plus_1 >= src.len || src[pos] != '?' {
        return false;
    }
    let b = src[p_plus_1];
    let next_idx = pos + 2;
    if b == '1' {
        out_item.kind = http::SfType.Boolean;
        out_item.bool_val = true;
        out_next = next_idx;
        return true;
    }
    if b == '0' {
        out_item.kind = http::SfType.Boolean;
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
fn sf_parse_string(src: const u8[:], pos: i64, out_item: http::SfItem&, out_next: i64&) -> bool {
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
            out_item.kind = http::SfType.String;
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
fn sf_parse_binary(src: const u8[:], pos: i64, out_item: http::SfItem&, out_next: i64&) -> bool {
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
            out_item.kind = http::SfType.Binary;
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

// Decodes the Base64 payload of an RFC 8941/9651 Binary (`SfType.Binary`) item into `out`.
// RFC 8941 Section 4.2.7 permits non-zero padding bits in trailing `=` / `==` groups.
//
// Example:
//   item = SfItem { kind: SfType.Binary, str_val: "aGVsbG8=" }, out = []
//   returns: true, out = "hello"
fn sf_decode_byte_sequence<B>(item: const http::SfItem&, out: B&) -> bool {
    out.clear();
    let encoded = item.str_val;
    guard item.kind == http::SfType.Binary && (encoded.len & 3) == 0 else { return false; }
    var committed = false;
    defer if !committed { out.clear(); };

    var buf:  u64 = 0;
    var bits: u64 = 0;
    var idx:  i64 = 0;
    while idx < encoded.len {
        let ch = encoded[idx];
        if ch == '=' {
            guard bits == 4 || bits == 2 else { return false; }
            let expected_pad: i64 = if bits == 4 { 2 } else { 1 };
            guard core::sub_sat_i64(encoded.len, idx) == expected_pad else { return false; }
            var p = idx;
            while p < encoded.len {
                guard encoded[p] == '=' else { return false; }
                p = core::add_sat_i64(p, 1);
            }
            committed = true;
            return true;
        }
        let v = core::base64_val(ch);
        guard v >= 0 else { return false; }
        buf = core::shl_sat_u64(buf & 0xFF, 6) | (v as u64);
        bits = core::add_sat_u64(bits, 6);
        if bits >= 8 {
            bits = core::sub_sat_u64(bits, 8);
            let byte_out = ((buf >> bits) & 0xFF) as u8;
            guard out.try_push(byte_out) else { return false; }
        }
        idx = core::add_sat_i64(idx, 1);
    }
    committed = true;
    return true;
}

// Parses an RFC 8941 Token: starts with alpha or *, followed by tchar, :, /
fn sf_parse_token(src: const u8[:], pos: i64, out_item: http::SfItem&, out_next: i64&) -> bool {
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
    out_item.kind = http::SfType.Token;
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
    out_item:  http::SfItem&,
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
    out_item.kind = http::SfType.Decimal;
    out_item.int_val = if is_neg { core::sub_sat_i64(0, abs_milli) } else { abs_milli };
    out_item.dec_val = total_f;
    out_next = frac_end;
    return true;
}

// Parses an RFC 8941 Integer or Decimal
fn sf_parse_number(src: const u8[:], pos: i64, out_item: http::SfItem&, out_next: i64&) -> bool {
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

    out_item.kind = http::SfType.Integer;
    out_item.int_val = if is_neg { -int_accum } else { int_accum };
    out_next = p;
    return true;
}

// Parses an RFC 9651 Date: @<integer>
fn sf_parse_date(src: const u8[:], pos: i64, out_item: http::SfItem&, out_next: i64&) -> bool {
    if pos >= src.len || src[pos] != '@' {
        return false;
    }
    var num_item = http::SfItem { .. };
    var n_next: i64 = 0;
    let next_p = pos + 1;
    if !sf_parse_number(src, next_p, num_item, n_next) || num_item.kind != http::SfType.Integer {
        return false;
    }
    out_item.kind = http::SfType.Date;
    out_item.int_val = num_item.int_val;
    out_next = n_next;
    return true;
}

checkfree inline fn sf_hex_lc_val(c: u8) -> u8, bool {
    let v = http::SF_LC_HEX_LUT[c];
    return v, v != 255;
}

checkfree inline fn sf_decode_pct_hex(hi: u8, lo: u8) -> u8, bool {
    let v1, ok1 = sf_hex_lc_val(hi);
    let v2, ok2 = sf_hex_lc_val(lo);
    return (v1 * 16) | v2, ok1 && ok2;
}

inline fn sf_step_utf8_dfa(b: u8, state: i64&) -> bool {
    let cls = http::UTF8_DFA_CLASS[b];
    let idx = core::add_sat_i64(state, cls);
    guard idx >= 0 && idx < 108 else { return false; }
    state = http::UTF8_DFA_TRANS[idx];
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

// Parses an RFC 9651 Section 3.3.4 Display String: %"..."
fn sf_parse_display_string(src: const u8[:], pos: i64, out_item: http::SfItem&, out_next: i64&) -> bool {
    guard pos + 1 < src.len && src[pos] == '%' && src[pos + 1] == '"' else { return false; }
    let start_idx = pos + 2;
    var p = pos + 2;
    while p < src.len {
        let ch = src[p];
        if ch == '"' {
            let raw_str = src[start_idx..p];
            guard validate_display_string(raw_str) else { return false; }
            out_item.kind = http::SfType.DisplayString;
            out_item.str_val = raw_str;
            out_next = p + 1;
            return true;
        }
        p = p + 1;
    }
    return false;
}

// Parses any bare RFC 8941 & RFC 9651 item
fn sf_parse_bare_item(src: const u8[:], pos: i64, out_item: http::SfItem&, out_next: i64&) -> bool {
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
    if p < src.len && src[p] >= 'A' && src[p] <= 'Z' {
        return "", pos, false;
    }
    return src[start..p], p, true;
}

// Parses parameters: ;key=val;flag;key2=val2 (RFC 8941 Section 3.1.2: *( ";" *SP parameter ))
fn sf_parse_parameters(src: const u8[:], pos: i64, out_params: http::SfParameter[..8]&, out_next: i64&) -> bool {
    var p = pos;
    while p < src.len && src[p] == ';' {
        p = sf_skip_sp(src, p + 1); // skip ';' and *SP

        let key, k_next, ok_k = sf_parse_key(src, p);
        if !ok_k {
            return false;
        }
        p = k_next;

        var val_item = http::SfItem { kind: http::SfType.Boolean, bool_val: true };
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
        let param = http::SfParameter { key: key, item: val_item };
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

fn copy_inner_item_params(src: const http::SfParameter[..8]&, dst: http::SfItemParam[..4]&) -> bool {
    dst.clear();
    for &ip in src {
        var p = http::SfItemParam {
            kind:     ip.item.kind,
            int_val:  ip.item.int_val,
            dec_val:  ip.item.dec_val,
            bool_val: ip.item.bool_val,
        };
        guard p.key.try_set(ip.key) &&
              p.str_val.try_set(ip.item.str_val) &&
              dst.try_push(p) else {
            return false;
        }
    }
    return true;
}

// Helper: parses inner list contents (item1 item2 ...) per RFC 8941 §4.2.1.2
fn sf_parse_inner_list_items(
    src:         const u8[:],
    pos:         i64,
    inner_items: http::SfItem[..8]&,
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
        var inner_item = http::SfItem { .. };
        var in_next:     i64                    = 0;
        var item_params: http::SfParameter[..8] = [];
        var params_next: i64                    = 0;
        guard sf_parse_bare_item(src, p, inner_item, in_next) &&
              sf_parse_parameters(src, in_next, item_params, params_next) &&
              copy_inner_item_params(item_params, inner_item.params) &&
              inner_items.len < 8 else {
            return false;
        }
        inner_items.push(inner_item);
        p = params_next;
        guard p < src.len && (src[p] == ' ' || src[p] == ')') else { return false; }
    }
    return false;
}

// Parses a single dictionary entry value and its parameters
fn sf_parse_dict_entry_value(src: const u8[:], pos: i64, entry: http::SfDictEntry&, out_next: i64&) -> bool {
    var p = pos;
    if p < src.len && src[p] == '=' {
        p = p + 1; // skip '='
        if p < src.len && src[p] == '(' {
            var in_next: i64 = 0;
            if !http::sf_parse_inner_list(src, p, entry, in_next) {
                return false;
            }
            p = in_next;
        } else {
            var item_val = http::SfItem { .. };
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
fn sf_parse_single_dict_entry(src: const u8[:], pos: i64, entry: http::SfDictEntry&, out_next: i64&) -> bool {
    let key, k_next, ok_k = sf_parse_key(src, pos);
    if !ok_k {
        return false;
    }
    entry.key = key;
    entry.item = http::SfItem { kind: http::SfType.Boolean, bool_val: true };

    var val_next: i64 = 0;
    if !sf_parse_dict_entry_value(src, k_next, entry, val_next) {
        return false;
    }
    out_next = val_next;
    return true;
}

// RFC 8941 Section 3.2.2: Duplicate dictionary keys overwrite the existing member in place.
fn upsert_sf_dict_entry(out_entries: http::SfDictEntry[..16]&, entry: http::SfDictEntry) -> bool {
    for i in out_entries.len {
        if out_entries[i].key == entry.key {
            out_entries[i] = entry;
            return true;
        }
    }
    return out_entries.try_push(entry);
}

// Helper: parses a single list entry (bare item or inner list)
fn sf_parse_single_list_entry(src: const u8[:], pos: i64, p_item: http::SfParameterizedItem&, out_next: i64&) -> bool {
    var i_next: i64 = 0;
    if pos < src.len && src[pos] == '(' {
        p_item.is_inner_list = true;
        if !sf_parse_inner_list_items(src, pos, p_item.inner_items, i_next) {
            return false;
        }
    } else {
        var item = http::SfItem { .. };
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

fn sf_item_to_sfv_bare(item: const http::SfItem&, out_bare: http::SfvBareItem&) -> bool {
    var tmp = http::SfvBareItem { .. };
    var ok = false;
    if item.kind == http::SfType.Integer {
        tmp.kind = http::SfvType.Integer;
        tmp.int_val = item.int_val;
        ok = true;
    } else if item.kind == http::SfType.Decimal {
        tmp.kind = http::SfvType.Decimal;
        tmp.int_val = item.int_val;
        ok = true;
    } else if item.kind == http::SfType.Boolean {
        tmp.kind = http::SfvType.Boolean;
        tmp.bool_val = item.bool_val;
        ok = true;
    } else if item.kind == http::SfType.Date {
        tmp.kind = http::SfvType.Date;
        tmp.int_val = item.int_val;
        ok = true;
    } else if item.kind == http::SfType.Token {
        tmp.kind = http::SfvType.Token;
        ok = tmp.text.try_set(item.str_val);
    } else if item.kind == http::SfType.String {
        tmp.kind = http::SfvType.String;
        ok = http::sf_unescape_string(item.str_val, tmp.text);
    } else if item.kind == http::SfType.Binary {
        tmp.kind = http::SfvType.ByteSequence;
        ok = item.str_val.len <= 1088 && sf_decode_byte_sequence(item, tmp.text);
    } else if item.kind == http::SfType.DisplayString {
        tmp.kind = http::SfvType.DisplayString;
        ok = http::sf_decode_display_string(item.str_val, tmp.text);
    }
    guard ok else { return false; }
    out_bare = tmp;
    return true;
}

// RFC 8941 Section 3.3: Bare item dispatcher
//
// Example:
//   raw = "123; param", cursor = 0
//   returns: true, out_bare.kind = SfvType.Integer, out_bare.int_val = 123
fn parse_sfv_bare_item(raw: const u8[:], cursor: i64&, out_bare: http::SfvBareItem&) -> bool {
    var item = http::SfItem { .. };
    var next_pos: i64 = 0;
    guard sf_parse_bare_item(raw, cursor, item, next_pos) else { return false; }
    guard sf_item_to_sfv_bare(item, out_bare) else { return false; }
    cursor = next_pos;
    return true;
}

fn upsert_sfv_param(
    out_params: http::SfvParam[..16]&,
    param_key:  const u8[..64]&,
    param_val:  const http::SfvBareItem&,
) -> bool {
    for &p in out_params {
        if p.key[..] == param_key[..] {
            p.value = param_val;
            return true;
        }
    }
    return out_params.try_push(http::SfvParam { key: param_key, value: param_val });
}

// Validates and skips RFC 8941 parameters without storing them, leaving `cursor` unchanged on error.
//
// Example:
//   raw = "; a=1; b=?0, \"next\"", cursor = 0
//   returns: true, cursor = 11 (points to ',')
fn skip_sfv_parameters(raw: const u8[:], cursor: i64&) -> bool {
    let saved_cursor = cursor;
    var committed = false;
    defer if !committed { cursor = saved_cursor; };

    while cursor < raw.len && raw[cursor] == ';' {
        cursor = sf_skip_sp(raw, core::add_sat_i64(cursor, 1));
        let _, next_key, ok_key = sf_parse_key(raw, cursor);
        guard ok_key else { return false; }
        cursor = next_key;
        if cursor < raw.len && raw[cursor] == '=' {
            cursor = core::add_sat_i64(cursor, 1);
            var ignored = http::SfvBareItem { .. };
            guard parse_sfv_bare_item(raw, cursor, ignored) else { return false; }
        }
    }
    committed = true;
    return true;
}

// RFC 8941 Section 3.1.2: Parameters parser (*( ";" *SP key [ "=" bare-item ] ))
// Leaves `cursor` and `out_params` unchanged on error.
//
// Example:
//   raw = "; q=0.5; v=?1", cursor = 0, out_params = []
//   returns: true, cursor advances past parameters
fn parse_sfv_parameters(raw: const u8[:], cursor: i64&, out_params: http::SfvParam[..16]&) -> bool {
    let saved_cursor = cursor;
    var staged = copy(out_params);
    var committed = false;
    defer if !committed { cursor = saved_cursor; };

    while cursor < raw.len && raw[cursor] == ';' {
        cursor = sf_skip_sp(raw, core::add_sat_i64(cursor, 1)); // skip ';' and *SP

        var param_key: u8[..64] = [];
        guard http::parse_sfv_key(raw, cursor, param_key) else { return false; }

        var param_val = http::SfvBareItem { kind: http::SfvType.Boolean, bool_val: true, .. };
        if cursor < raw.len && raw[cursor] == '=' {
            cursor = core::add_sat_i64(cursor, 1); // skip '='
            guard parse_sfv_bare_item(raw, cursor, param_val) else { return false; }
        }

        guard upsert_sfv_param(staged, param_key, param_val) else { return false; }
    }
    out_params = staged;
    committed = true;
    return true;
}

// RFC 8941 Section 3.1.1: Inner list parser
//
// Example:
//   raw = "(1 2 3); q=0.5", cursor = 0, member = SfvMember { .. }
//   returns: true, cursor advances past inner list
fn parse_sfv_inner_list(raw: const u8[:], cursor: i64&, member: http::SfvMember&) -> bool {
    member.is_inner_list = true;
    cursor = core::add_sat_i64(cursor, 1); // skip '('
    var closed = false;
    while cursor < raw.len {
        cursor = sf_skip_sp(raw, cursor);
        if cursor < raw.len && raw[cursor] == ')' {
            cursor = core::add_sat_i64(cursor, 1);
            closed = true;
            break;
        }
        var item = http::SfvItem { .. };
        guard parse_sfv_bare_item(raw, cursor, item.bare) else { return false; }
        guard parse_sfv_parameters(raw, cursor, item.params) else { return false; }
        guard member.inner_list.try_push(item) else { return false; }
        guard cursor < raw.len && (raw[cursor] == ' ' || raw[cursor] == ')') else { return false; }
    }
    guard closed else { return false; }
    return parse_sfv_parameters(raw, cursor, member.inner_params);
}

// Parses a single member item within an SFV list or dict.
//
// Example:
//   raw = "token; q=1", cursor = 0, member = SfvMember { .. }
//   returns: true, cursor advances past member
fn parse_sfv_member_item(raw: const u8[:], cursor: i64&, member: http::SfvMember&) -> bool {
    member.is_inner_list = false;
    guard parse_sfv_bare_item(raw, cursor, member.item.bare) else { return false; }
    return parse_sfv_parameters(raw, cursor, member.item.params);
}

// Advances cursor across OWS and an optional comma separator between SFV members.
//
// Example:
//   raw = ", next", cursor = 0, has_more = false
//   returns: true, cursor = 2, has_more = true
fn sfv_advance_comma(raw: const u8[:], cursor: i64&, has_more: bool&) -> bool {
    has_more = false;
    cursor = sf_skip_ws(raw, cursor);
    if cursor == raw.len {
        return true;
    }
    guard raw[cursor] == ',' else { return false; }
    cursor = sf_skip_ws(raw, core::add_sat_i64(cursor, 1)); // skip ',' and OWS
    guard cursor < raw.len else { return false; } // Trailing comma without following member
    has_more = true;
    return true;
}

fn upsert_sfv_dict_entry(
    entries: http::SfvDictEntry[..64]&,
    key:     const u8[..64]&,
    member:  const http::SfvMember&,
) -> bool {
    for &entry in entries {
        if entry.key[..] == key[..] {
            entry.member = member;
            return true;
        }
    }
    return entries.try_push(http::SfvDictEntry { key: key, member: member });
}

// Parses a dictionary entry member value (after key) and its parameters.
//
// Example:
//   raw = "=123; a=1", cursor = 0, member = SfvMember { .. }
//   returns: true, cursor = 9
fn parse_sfv_dict_entry_member(raw: const u8[:], cursor: i64&, member: http::SfvMember&) -> bool {
    if cursor < raw.len && raw[cursor] == '=' {
        cursor = core::add_sat_i64(cursor, 1); // skip '='
        if cursor < raw.len && raw[cursor] == '(' {
            return parse_sfv_inner_list(raw, cursor, member);
        }
        return parse_sfv_member_item(raw, cursor, member);
    }
    member.is_inner_list = false;
    member.item.bare = http::SfvBareItem { kind: http::SfvType.Boolean, bool_val: true, .. };
    return parse_sfv_parameters(raw, cursor, member.item.params);
}

fn sf_serialize_item_params<B>(params: const http::SfItemParam[:], out: B&) {
    for &p in params {
        out.push(';' as u8);
        out.append(p.key[..]);
        if p.kind == http::SfType.Boolean && p.bool_val {
            continue;
        }
        out.push('=' as u8);
        let tmp = http::SfItem {
            kind:     p.kind,
            int_val:  p.int_val,
            dec_val:  p.dec_val,
            str_val:  p.str_val[..],
            bool_val: p.bool_val,
        };
        http::sf_serialize_item(tmp, out);
    }
}

// ---- http/signatures.goose internal helpers ----

fn is_default_port(scheme: const u8[:], port: i32) -> bool {
    if port <= 0 { return true; }
    if scheme.eq_ascii_fold("http") && port == 80 { return true; }
    if scheme.eq_ascii_fold("https") && port == 443 { return true; }
    if scheme.eq_ascii_fold("ws") && port == 80 { return true; }
    if scheme.eq_ascii_fold("wss") && port == 443 { return true; }
    return false;
}

// RFC 9421 Section 2.1: HTTP Fields - Component names MUST be lowercased and MUST NOT be @signature-params.
fn is_valid_component_name(comp: const u8[:]) -> bool {
    guard comp.len > 0 && comp != "@signature-params" && comp != "@signature-params;req" else {
        return false;
    }
    for b in comp {
        if b >= 'A' && b <= 'Z' {
            return false;
        }
    }
    return true;
}

fn has_duplicate_component_before(
    components: const u8[..32][..16]&,
    limit:      i64,
    comp:       const u8[:],
) -> bool {
    for j in limit {
        if components[j][..] == comp {
            return true;
        }
    }
    return false;
}

// RFC 9421 Section 2.5: Creating the Signature Base - Component identifiers MUST be unique and lowercase.
fn has_valid_unique_components(components: const u8[..32][..16]&) -> bool {
    for i in components.len {
        let comp = components[i][..];
        guard is_valid_component_name(comp) && !has_duplicate_component_before(components, i, comp) else {
            return false;
        }
    }
    return true;
}

// Extracts special URL components (@authority, @path, @query, @scheme) per RFC 9421 §2.2.6.
//
// Example:
//   url_str = "https://example.com/foo?bar=1", comp = "@authority"
//   returns: true, out populated with "example.com"
fn extract_url_component<B>(url_str: const u8[:], comp: const u8[:], out: B&) -> bool {
    out.clear();
    guard is_valid_component_name(comp) else { return false; }
    let view, err = core::parse_url_view(url_str);
    let _ = err;
    guard view.valid else { return false; }
    if comp == "@authority" {
        guard out.try_append(view.host) else {
            out.clear();
            return false;
        }
        to_lower(out[..]);
        if view.port > 0 && !is_default_port(view.scheme, view.port) {
            var pbuf: u8[..16] = [];
            view.port.format_i64_dec(pbuf);
            guard out.try_push(':') && out.try_append(pbuf[..]) else {
                out.clear();
                return false;
            }
        }
        return true;
    }
    if comp == "@path" {
        let p = if view.pathname.len > 0 { view.pathname } else { "/" };
        guard out.try_set(p) else {
            out.clear();
            return false;
        }
        return true;
    }
    if comp == "@query" {
        let q = if view.search.len > 0 { view.search } else { "?" };
        guard out.try_set(q) else {
            out.clear();
            return false;
        }
        return true;
    }
    if comp == "@request-target" {
        let p = if view.pathname.len > 0 { view.pathname } else { "/" };
        guard out.try_append(p) && (view.search.len == 0 || out.try_append(view.search)) else {
            out.clear();
            return false;
        }
        return true;
    }
    if comp == "@scheme" {
        guard out.try_set(view.scheme) else {
            out.clear();
            return false;
        }
        to_lower(out[..]);
        return true;
    }
    return false;
}

// RFC 9421 Section 2.1: HTTP Fields - Strip leading/trailing OWS and fold obs-fold CRLF+WSP to SP while preserving internal whitespace.
//
// Example:
//   s = "a\r\n   b", start = 1
//   returns: next = 6 (points to 'b'), ok = true
inline fn consume_obs_fold_wsp(s: const u8[:], start: i64) -> i64, bool {
    let lf_idx = core::add_sat_i64(start, 1);
    let ws_start = core::add_sat_i64(start, 2);
    guard ws_start < s.len && s[lf_idx] == '\n' && core::is_lws(s[ws_start]) else {
        return start, false;
    }
    var next = core::add_sat_i64(ws_start, 1);
    while next < s.len && core::is_lws(s[next]) {
        next = core::add_sat_i64(next, 1);
    }
    return next, true;
}

fn normalize_header_value<B>(val: const u8[:], out: B&) -> bool {
    let trimmed = val.trim_lws_start().trim_end_bytes(" \t\r\n");
    if trimmed.len == 0 {
        return true;
    }
    var i: i64 = 0;
    while i < trimmed.len {
        let ch = trimmed[i];
        if ch == '\r' {
            let next_i, ok_fold = consume_obs_fold_wsp(trimmed, i);
            guard ok_fold && out.try_push(' ' as u8) else {
                out.clear();
                return false;
            }
            i = next_i;
            continue;
        }
        guard ch != '\n' && out.try_push(ch) else {
            out.clear();
            return false;
        }
        i = core::add_sat_i64(i, 1);
    }
    return true;
}

// Extracts and concatenates comma-separated header field values (RFC 9421 §2.1).
//
// Example:
//   headers = [{"date", "Tue, 20 Apr 2021"}], name = "date"
//   returns: true, out = "Tue, 20 Apr 2021"
fn extract_combined_header_value<B>(headers: const http::HeaderMap&, name: const u8[:], out: B&) -> bool {
    guard is_valid_component_name(name) else {
        out.clear();
        return false;
    }
    var found = false;
    for &e in headers.entries {
        guard http::entry_name(headers, e).eq_ascii_fold(name) else { continue; }
        var norm_buf: u8[..4096] = [];
        guard normalize_header_value(http::entry_value(headers, e), norm_buf) else {
            out.clear();
            return false;
        }
        if found {
            guard out.try_append(", ") else {
                out.clear();
                return false;
            }
        }
        guard out.try_append(norm_buf[..]) else {
            out.clear();
            return false;
        }
        found = true;
    }
    return found;
}

// Extracts component value per RFC 9421 Section 2.
//
// Example:
//   req has method "GET", comp = "@method"
//   returns: true, out populated with "GET"
fn extract_component_value<B>(req: const http::Request&, comp: const u8[:], out: B&) -> bool {
    guard is_valid_component_name(comp) else {
        out.clear();
        return false;
    }
    if comp == "@method" {
        guard out.try_set(req.method[..]) else {
            out.clear();
            return false;
        }
        return true;
    }
    if comp == "@target-uri" {
        guard out.try_set(req.url[..]) else {
            out.clear();
            return false;
        }
        return true;
    }
    if comp.len > 0 && comp[0] == '@' {
        return extract_url_component(req.url[..], comp, out);
    }
    out.clear();
    return extract_combined_header_value(req.headers, comp, out);
}

fn strip_req_component_suffix(comp: const u8[:]) -> const u8[:], bool {
    guard comp.len > 4 && comp[^4..] == ";req" else { return comp, false; }
    return comp[..^4], true;
}

// Extracts component value from Response (RFC 9421 §2.2), supporting @status and ";req" parameters.
//
// Example:
//   res has status 200, comp = "@status"
//   returns: true, out populated with "200"
fn extract_response_component_value<B>(
    res:  const http::Response&,
    req:  const http::Request&,
    comp: const u8[:],
    out:  B&,
) -> bool {
    out.clear();
    guard is_valid_component_name(comp) else { return false; }
    if comp == "@status" {
        var st_buf: u8[..16] = [];
        res.status_code.format_i64_dec(st_buf);
        return out.try_set(st_buf[..]);
    }
    let req_comp, is_req = strip_req_component_suffix(comp);
    if is_req {
        return extract_component_value(req, req_comp, out);
    }
    return extract_combined_header_value(res.headers, comp, out);
}

fn append_escaped_string_param<B>(s: const u8[:], out: B&) -> bool {
    for b in s {
        if (b == '"' || b == '\\') && !out.try_push('\\' as u8) {
            return false;
        }
        guard out.try_push(b) else { return false; }
    }
    return true;
}

fn append_named_sig_int_param<B>(key: const u8[:], val: i64, out: B&) -> bool {
    var ibuf: u8[..24] = [];
    val.format_i64_dec(ibuf);
    return out.try_push(';' as u8) && out.try_append(key) && out.try_push('=' as u8) && out.try_append(ibuf[..]);
}

fn append_named_sig_str_param<B>(key: const u8[:], val: const u8[:], out: B&) -> bool {
    guard out.try_push(';' as u8) && out.try_append(key) && out.try_append("=\"") else { return false; }
    return append_escaped_string_param(val, out) && out.try_push('"' as u8);
}

// Formats the "@signature-params" inner-list and parameters (RFC 9421 Section 2.5)
fn format_signature_params<B>(params: const http::SignatureParams&, out: B&) -> bool {
    let saved_len = out.len;
    var committed = false;
    defer if !committed { out.resize(saved_len); };
    guard out.try_push('(' as u8) else { return false; }
    for idx in params.components.len {
        if idx > 0 && !out.try_push(' ' as u8) { return false; }
        let base_comp, has_req = strip_req_component_suffix(params.components[idx][..]);
        guard out.try_push('"' as u8) && out.try_append(base_comp) && out.try_push('"' as u8) else {
            return false;
        }
        if has_req && !out.try_append(";req") { return false; }
    }
    guard out.try_push(')' as u8) else { return false; }

    if params.created > 0 && !append_named_sig_int_param("created", params.created, out) { return false; }
    if params.expires > 0 && !append_named_sig_int_param("expires", params.expires, out) { return false; }
    if params.key_id.len > 0 && !append_named_sig_str_param("keyid", params.key_id[..], out) { return false; }
    if params.alg.len > 0 && !append_named_sig_str_param("alg", params.alg[..], out) { return false; }
    if params.nonce.len > 0 && !append_named_sig_str_param("nonce", params.nonce[..], out) { return false; }
    committed = true;
    return true;
}

fn build_signature_base_from_params_line<B>(
    req:             const http::Request&,
    components:      const u8[..32][..16]&,
    sig_params_line: const u8[:],
    out:             B&,
) -> bool {
    out.clear();
    guard has_valid_unique_components(components) else { return false; }
    var committed = false;
    defer if !committed { out.clear(); };
    for idx in components.len {
        let comp = components[idx][..];
        var val: u8[..4096] = [];
        guard extract_component_value(req, comp, val) else { return false; }
        guard out.try_push('"' as u8) &&
              out.try_append(comp) &&
              out.try_append("\": ") &&
              out.try_append(val[..]) &&
              out.try_push('\n' as u8) else {
            return false;
        }
    }
    guard out.try_append("\"@signature-params\": ") && out.try_append(sig_params_line) else { return false; }
    committed = true;
    return true;
}

fn build_response_signature_base_from_params_line<B>(
    res:             const http::Response&,
    req:             const http::Request&,
    components:      const u8[..32][..16]&,
    sig_params_line: const u8[:],
    out:             B&,
) -> bool {
    out.clear();
    guard has_valid_unique_components(components) else { return false; }
    var committed = false;
    defer if !committed { out.clear(); };
    for idx in components.len {
        let comp = components[idx][..];
        var val: u8[..4096] = [];
        guard extract_response_component_value(res, req, comp, val) else { return false; }
        let base_comp, has_req = strip_req_component_suffix(comp);
        guard out.try_push('"' as u8) && out.try_append(base_comp) && out.try_push('"' as u8) else {
            return false;
        }
        if has_req && !out.try_append(";req") { return false; }
        guard out.try_append(": ") && out.try_append(val[..]) && out.try_push('\n' as u8) else {
            return false;
        }
    }
    guard out.try_append("\"@signature-params\": ") && out.try_append(sig_params_line) else { return false; }
    committed = true;
    return true;
}

fn build_response_signature_base<B>(
    res:    const http::Response&,
    req:    const http::Request&,
    params: const http::SignatureParams&,
    out:    B&,
) -> bool {
    out.clear();
    var sp_line: u8[..2048] = [];
    guard format_signature_params(params, sp_line) else { return false; }
    return build_response_signature_base_from_params_line(res, req, params.components, sp_line[..], out);
}

fn compute_rsa_raw_signature(
    alg:        const u8[:],
    secret_key: const u8[:],
    sig_base:   const u8[:],
    out_sig:    u8[..512]&,
) -> bool {
    out_sig.clear();
    let klen = secret_key.len;
    guard klen > 0 && (klen & 1) == 0 else { return false; }
    let half = klen >> 1;
    if alg == rfc::SIG_ALG_RSA_V1_5_SHA256 {
        guard klen >= 128 &&
              core::rsa_pkcs1_sha256_sign(secret_key[..half], secret_key[half..], sig_base, out_sig) else {
            out_sig.clear();
            return false;
        }
        return true;
    }
    if alg == rfc::SIG_ALG_RSA_PSS_SHA512 {
        let salt64 = core::sha512(sig_base);
        guard klen >= 256 &&
              core::rsa_pss_sha512_sign(secret_key[..half], secret_key[half..], salt64[..], sig_base, out_sig) else {
            out_sig.clear();
            return false;
        }
        return true;
    }
    return false;
}

// RFC 9421 Section 2.3: Signature Parameters - Reject negative timestamps and enforce clock skew.
fn validate_signature_created(created: i64, expires: i64, now_sec: i64) -> bool {
    guard created >= 0 && expires >= 0 else { return false; }
    if created > 0 && expires > 0 {
        guard created < expires else { return false; }
    }
    if created > 0 && now_sec > 0 {
        guard core::add_sat_i64(now_sec, 60) >= created else { return false; }
    }
    return true;
}

fn validate_signature_expires(expires: i64, now_sec: i64) -> bool {
    guard expires >= 0 else { return false; }
    if expires > 0 && now_sec > 0 {
        guard core::sub_sat_i64(now_sec, 60) <= expires else { return false; }
    }
    return true;
}

fn validate_signature_timestamps(params: const http::SignatureParams&, now_sec: i64) -> bool {
    guard validate_signature_created(params.created, params.expires, now_sec) else { return false; }
    return validate_signature_expires(params.expires, now_sec);
}

fn format_signature_header_value<B>(label: const u8[:], b64_sig: const u8[:], out: B&) -> bool {
    out.clear();
    guard out.try_append(label) && out.try_append("=:") && out.try_append(b64_sig) && out.try_push(':') else {
        out.clear();
        return false;
    }
    return true;
}

fn format_signature_input_header_value<B>(params: const http::SignatureParams&, out: B&) -> bool {
    out.clear();
    guard out.try_append(params.label[..]) && out.try_push('=') && format_signature_params(params, out) else {
        out.clear();
        return false;
    }
    return true;
}

fn attach_request_signature_headers(
    req:     http::Request&,
    params:  const http::SignatureParams&,
    b64_sig: const u8[:],
) -> bool {
    var input_hdr: u8[..4096] = [];
    var sig_hdr:   u8[..4096] = [];
    guard format_signature_input_header_value(params, input_hdr) &&
          format_signature_header_value(params.label[..], b64_sig, sig_hdr) else {
        return false;
    }
    http::set_header(req, rfc::HEADER_SIGNATURE_INPUT, input_hdr[..]);
    http::set_header(req, rfc::HEADER_SIGNATURE, sig_hdr[..]);
    return true;
}

fn attach_response_signature_headers(
    res:     http::Response&,
    params:  const http::SignatureParams&,
    b64_sig: const u8[:],
) -> bool {
    var input_hdr: u8[..4096] = [];
    var sig_hdr:   u8[..4096] = [];
    guard format_signature_input_header_value(params, input_hdr) &&
          format_signature_header_value(params.label[..], b64_sig, sig_hdr) else {
        return false;
    }
    res.set_header(rfc::HEADER_SIGNATURE_INPUT, input_hdr[..]);
    res.set_header(rfc::HEADER_SIGNATURE, sig_hdr[..]);
    return true;
}

inline fn sf_f64_to_milliths(d: f64) -> i64 {
    let scaled = d * 1000.0;
    let adjusted = if scaled >= 0.0 { scaled + 0.5 } else { scaled - 0.5 };
    return adjusted as i64;
}

fn append_wire_item_params<B>(params: const http::SfItemParam[:], out: B&) -> bool {
    for &p in params {
        guard out.try_push(';' as u8) && out.try_append(p.key[..]) else { return false; }
        if p.kind == http::SfType.Boolean && p.bool_val {
            continue;
        }
        guard out.try_push('=' as u8) &&
              http::append_wire_sf_bare(p.kind, p.int_val, p.dec_val, p.str_val[..], p.bool_val, out) else {
            return false;
        }
    }
    return true;
}

fn append_wire_dict_params<B>(params: const http::SfParameter[:], out: B&) -> bool {
    for &p in params {
        guard out.try_push(';' as u8) && out.try_append(p.key) else { return false; }
        if p.item.kind == http::SfType.Boolean && p.item.bool_val {
            continue;
        }
        guard out.try_push('=' as u8) &&
              http::append_wire_sf_bare(
                  p.item.kind, p.item.int_val, p.item.dec_val, p.item.str_val, p.item.bool_val, out,
              ) else {
                  return false;
              }
    }
    return true;
}

fn serialize_wire_sig_params<B>(entry: const http::SfDictEntry&, out: B&) -> bool {
    out.clear();
    var committed = false;
    defer if !committed { out.clear(); };
    guard out.try_push('(' as u8) else { return false; }
    for idx in entry.inner_items.len {
        if idx > 0 && !out.try_push(' ' as u8) { return false; }
        let it = &entry.inner_items[idx];
        guard http::append_wire_sf_bare(it.kind, it.int_val, it.dec_val, it.str_val, it.bool_val, out) &&
              append_wire_item_params(it.params[..], out) else {
            return false;
        }
    }
    guard out.try_push(')' as u8) && append_wire_dict_params(entry.params[..], out) else {
        return false;
    }
    committed = true;
    return true;
}

inline fn sf_str_param_matches(item: const http::SfItem&, expected: const u8[:]) -> bool {
    var unq: u8[..128] = [];
    return item.kind == http::SfType.String && http::sf_unescape_string(item.str_val, unq) && unq[..] == expected;
}

fn check_sig_entry_param(
    p:            const http::SfParameter&,
    params:       const http::SignatureParams&,
    seen_mask:    u32&,
    wire_created: i64&,
    wire_expires: i64&,
) -> bool {
    if p.key == "alg" {
        return sf_str_param_matches(p.item, params.alg[..]);
    }
    if p.key == "keyid" {
        guard sf_str_param_matches(p.item, params.key_id[..]) else { return false; }
        seen_mask = seen_mask | 1;
        return true;
    }
    if p.key == "created" {
        guard p.item.kind == http::SfType.Integer && p.item.int_val >= 0 &&
              (params.created == 0 || p.item.int_val == params.created) else {
            return false;
        }
        wire_created = p.item.int_val;
        seen_mask = seen_mask | 2;
        return true;
    }
    if p.key == "expires" {
        guard p.item.kind == http::SfType.Integer && p.item.int_val >= 0 &&
              (params.expires == 0 || p.item.int_val == params.expires) else {
            return false;
        }
        wire_expires = p.item.int_val;
        seen_mask = seen_mask | 4;
        return true;
    }
    if p.key == "nonce" {
        guard sf_str_param_matches(p.item, params.nonce[..]) else { return false; }
        seen_mask = seen_mask | 8;
        return true;
    }
    return true;
}

fn verify_sig_entry_match(
    entry:        const http::SfDictEntry&,
    params:       const http::SignatureParams&,
    wire_created: i64&,
    wire_expires: i64&,
) -> bool {
    guard entry.inner_items.len == params.components.len else { return false; }
    for i in params.components.len {
        guard http::matches_signature_component(entry.inner_items[i], params.components[i][..]) else {
            return false;
        }
    }
    var seen_mask: u32 = 0;
    for &p in entry.params {
        guard check_sig_entry_param(p, params, seen_mask, wire_created, wire_expires) else {
            return false;
        }
    }
    if params.key_id.len > 0 && (seen_mask & 1) == 0 { return false; }
    if params.created > 0 && (seen_mask & 2) == 0 { return false; }
    if params.expires > 0 && (seen_mask & 4) == 0 { return false; }
    if params.nonce.len > 0 && (seen_mask & 8) == 0 { return false; }
    return true;
}

// RFC 9421 Section 3.2: Verifying a Signature - Match label, components, and wire parameters.
fn find_verified_sig_params_line<B>(
    sig_input_val:  const u8[:],
    label:          const u8[:],
    params:         const http::SignatureParams&,
    out_sig_params: B&,
    out_created:    i64&,
    out_expires:    i64&,
) -> bool {
    out_sig_params.clear();
    out_created = 0;
    out_expires = 0;
    guard params.created >= 0 && params.expires >= 0 && has_valid_unique_components(params.components) else {
        return false;
    }
    var entries: http::SfDictEntry[..16] = [];
    guard http::parse_sf_dict(sig_input_val, entries) else { return false; }
    for &entry in entries {
        guard entry.key == label && entry.is_inner_list else { continue; }
        var wc: i64 = 0;
        var we: i64 = 0;
        guard verify_sig_entry_match(entry, params, wc, we) &&
              serialize_wire_sig_params(entry, out_sig_params) else {
            out_sig_params.clear();
            return false;
        }
        out_created = wc;
        out_expires = we;
        return true;
    }
    return false;
}

fn validate_and_decode_signature_headers(
    headers:        const http::HeaderMap&,
    label:          const u8[:],
    params:         const http::SignatureParams&,
    now_sec:        i64,
    out_sig_params: u8[..2048]&,
    out_sig:        u8[..512]&,
) -> bool {
    out_sig_params.clear();
    out_sig.clear();
    var comb_in: u8[..4096] = [];
    guard headers.get_header(rfc::HEADER_SIGNATURE_INPUT).len > 0 &&
          headers.get_combined(rfc::HEADER_SIGNATURE_INPUT, comb_in, 4096) else {
        return false;
    }
    var wire_created: i64 = 0;
    var wire_expires: i64 = 0;
    guard find_verified_sig_params_line(
        comb_in[..],
        label,
        params,
        out_sig_params,
        wire_created,
        wire_expires,
    ) else {
        return false;
    }
    guard validate_signature_created(wire_created, wire_expires, now_sec) &&
          validate_signature_expires(wire_expires, now_sec) else {
        out_sig_params.clear();
        return false;
    }

    var comb_sig: u8[..4096] = [];
    guard headers.get_header(rfc::HEADER_SIGNATURE).len > 0 &&
          headers.get_combined(rfc::HEADER_SIGNATURE, comb_sig, 4096) else {
        out_sig_params.clear();
        return false;
    }

    let received_b64, ok = http::extract_signature_value(comb_sig[..], label);
    guard ok && core::base64_decode(received_b64, out_sig) else {
        out_sig_params.clear();
        out_sig.clear();
        return false;
    }
    return true;
}
