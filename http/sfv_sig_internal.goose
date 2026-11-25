// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Internal helpers for `http` (http/sfv_sig_internal.goose).
namespace http_internal;

import std;
import core;
import http.sfv;

// ---- http/sfv.goose internal helpers ----

fn sf_skip_ws(src: const u8[:], pos: i64) -> i64 {
    var p = pos;
    let n = src.len;
    while p < n && core::is_lws(src[p]) { p += 1; }
    return p;
}

fn sf_skip_sp(src: const u8[:], pos: i64) -> i64 {
    var p = pos;
    let n = src.len;
    while p < n && src[p] == ' ' { p += 1; }
    return p;
}

// Parses an RFC 8941 Boolean: ?0 or ?1
fn sf_parse_boolean(src: const u8[:], pos: i64, out_item: http::SfItem&, out_next: i64&) -> bool {
    guard pos + 1 < src.len && src[pos] == '?' else { return false; }
    let b = src[pos + 1];
    guard b == '0' || b == '1' else { return false; }
    out_item.kind = http::SfType.Boolean;
    out_item.bool_val = b == '1';
    out_next = pos + 2;
    return true;
}

checkfree fn sf_check_escape(src: const u8[:], p: i64) -> bool {
    guard p >= 0 && p + 1 < src.len else { return false; }
    let ch = src[p + 1];
    return ch == '\\' || ch == '"';
}

// Parses an RFC 8941 String: "..." with escaping (\", \\)
fn sf_parse_string(src: const u8[:], pos: i64, out_item: http::SfItem&, out_next: i64&) -> bool {
    let n = src.len;
    guard pos < n && src[pos] == '"' else { return false; }
    var p = pos + 1;
    while p < n {
        let ch = src[p];
        if ch == '\\' {
            guard sf_check_escape(src, p) else { return false; }
            p += 2;
        } else if ch == '"' {
            out_item.kind = http::SfType.String;
            out_item.str_val = src[pos + 1..p];
            out_next = p + 1;
            return true;
        } else {
            guard core::is_ascii_printable(ch) else { return false; }
            p += 1;
        }
    }
    return false;
}

// Parses an RFC 8941 Byte Sequence: :base64:
fn sf_parse_binary(src: const u8[:], pos: i64, out_item: http::SfItem&, out_next: i64&) -> bool {
    let n = src.len;
    guard pos < n && src[pos] == ':' else { return false; }
    var p = pos + 1;
    var eq_count:   i64 = 0;
    var data_count: i64 = 0;
    while p < n {
        let ch = src[p];
        if ch == ':' {
            guard ((p - (pos + 1)) & 3) == 0 && eq_count <= 2 && (eq_count == 0 || data_count > 0) else {
                return false;
            }
            out_item.kind = http::SfType.Binary;
            out_item.str_val = src[pos + 1..p];
            out_next = p + 1;
            return true;
        }
        if ch == '=' {
            eq_count += 1;
        } else {
            guard eq_count == 0 && (core::is_ascii_alphanumeric(ch) || ch == '+' || ch == '/') else { return false; }
            data_count += 1;
        }
        p += 1;
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
    let total = encoded.len;
    guard item.kind == http::SfType.Binary && (total & 3) == 0 else { return false; }
    var committed = false;
    defer if !committed { out.clear(); };

    var buf:  u64 = 0;
    var bits: u64 = 0;
    for idx in total {
        let ch = encoded[idx];
        if ch == '=' {
            guard bits == 4 || bits == 2 else { return false; }
            let expected_pad: i64 = if bits == 4 { 2 } else { 1 };
            guard total - idx == expected_pad else { return false; }
            for p in idx..total {
                guard encoded[p] == '=' else { return false; }
            }
            committed = true;
            return true;
        }
        let v = core::base64_val(ch);
        guard v >= 0 else { return false; }
        buf = ((buf & 0xFF) << 6) | (v as u64);
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            guard out.try_push(((buf >> bits) & 0xFF) as u8) else { return false; }
        }
    }
    committed = true;
    return true;
}

// Parses an RFC 8941 Token: starts with alpha or *, followed by tchar, :, /
fn sf_parse_token(src: const u8[:], pos: i64, out_item: http::SfItem&, out_next: i64&) -> bool {
    let n = src.len;
    guard pos < n && (core::is_ascii_alpha(src[pos]) || src[pos] == '*') else { return false; }
    var p = pos + 1;
    while p < n && (core::is_tchar(src[p]) || src[p] == ':' || src[p] == '/') {
        p += 1;
    }
    out_item.kind = http::SfType.Token;
    out_item.str_val = src[pos..p];
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
    let n = src.len;
    var accum: i64 = 0;
    var count: i32 = 0;
    while p < n && core::is_ascii_digit(src[p]) {
        count += 1;
        guard count <= max_digits else { return false; }
        accum = accum * 10 + (src[p] - '0');
        p += 1;
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

checkfree fn sf_decode_pct_hex(hi: u8, lo: u8) -> i32 {
    let v1 = http::SF_LC_HEX_LUT[hi];
    let v2 = http::SF_LC_HEX_LUT[lo];
    if v1 == 255 || v2 == 255 { return -1; }
    return ((v1 << 4) | v2);
}

fn sf_step_utf8_dfa(b: u8, state: i64&) -> bool {
    let idx = state + http::UTF8_DFA_CLASS[b];
    guard idx >= 0 && idx < 108 else { return false; }
    state = http::UTF8_DFA_TRANS[idx];
    return state != 12;
}

fn validate_display_string(raw_str: const u8[:]) -> bool {
    var state: i64 = 0;
    var i:     i64 = 0;
    let total = raw_str.len;
    while i < total {
        let b = raw_str[i];
        if b == '%' {
            guard core::add_sat_i64(i, 2) < total else { return false; }
            let dec = sf_decode_pct_hex(
                raw_str[core::add_sat_i64(i, 1)], raw_str[core::add_sat_i64(i, 2)],
            );
            guard dec >= 0 && sf_step_utf8_dfa(dec as u8, state) else { return false; }
            i = core::add_sat_i64(i, 3);
        } else {
            guard b >= 0x20 && b <= 0x7E && b != '"' && sf_step_utf8_dfa(b, state) else { return false; }
            i = core::add_sat_i64(i, 1);
        }
    }
    return state == 0;
}

// Parses an RFC 9651 Section 3.3.4 Display String: %"..."
fn sf_parse_display_string(src: const u8[:], pos: i64, out_item: http::SfItem&, out_next: i64&) -> bool {
    let n = src.len;
    guard pos + 1 < n && src[pos] == '%' && src[pos + 1] == '"' else { return false; }
    let start_idx = pos + 2;
    for p in start_idx..n {
        if src[p] == '"' {
            let raw_str = src[start_idx..p];
            guard validate_display_string(raw_str) else { return false; }
            out_item.kind = http::SfType.DisplayString;
            out_item.str_val = raw_str;
            out_next = p + 1;
            return true;
        }
    }
    return false;
}

// Parses any bare RFC 8941 & RFC 9651 item
fn sf_parse_bare_item(src: const u8[:], pos: i64, out_item: http::SfItem&, out_next: i64&) -> bool {
    guard pos < src.len else { return false; }
    let ch = src[pos];
    if ch == '%' { return sf_parse_display_string(src, pos, out_item, out_next); }
    if ch == '?' { return sf_parse_boolean(src, pos, out_item, out_next); }
    if ch == '"' { return sf_parse_string(src, pos, out_item, out_next); }
    if ch == ':' { return sf_parse_binary(src, pos, out_item, out_next); }
    if ch == '@' { return sf_parse_date(src, pos, out_item, out_next); }
    if ch == '-' || core::is_ascii_digit(ch) { return sf_parse_number(src, pos, out_item, out_next); }
    if core::is_ascii_alpha(ch) || ch == '*' { return sf_parse_token(src, pos, out_item, out_next); }
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
    let n = src.len;
    guard pos < n else { return "", pos, false; }
    let first = src[pos];
    guard (first >= 'a' && first <= 'z') || first == '*' else { return "", pos, false; }
    var p = pos + 1;
    while p < n && is_sf_key_char(src[p]) { p += 1; }
    guard p >= n || src[p] < 'A' || src[p] > 'Z' else { return "", pos, false; }
    return src[pos..p], p, true;
}

// Parses parameters: ;key=val;flag;key2=val2 (RFC 8941 Section 3.1.2: *( ";" *SP parameter ))
fn sf_parse_parameters(src: const u8[:], pos: i64, out_params: http::SfParameter[..8]&, out_next: i64&) -> bool {
    var p = pos;
    let n = src.len;
    while p < n && src[p] == ';' {
        p = sf_skip_sp(src, p + 1); // skip ';' and *SP
        let key, k_next, ok_k = sf_parse_key(src, p);
        guard ok_k else { return false; }
        p = k_next;

        var val_item = http::SfItem { kind: http::SfType.Boolean, bool_val: true };
        if p < n && src[p] == '=' {
            var v_next: i64 = 0;
            guard sf_parse_bare_item(src, p + 1, val_item, v_next) else { return false; }
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
        } else {
            guard out_params.try_push(param) else { return false; }
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
    inner_items: http::SfItem[..16]&,
    out_next:    i64&,
) -> bool {
    var p = pos + 1; // skip '('
    let n = src.len;
    while p < n {
        p = sf_skip_sp(src, p);
        if p < n && src[p] == ')' {
            out_next = p + 1;
            return true;
        }
        var inner_item = http::SfItem { .. };
        var in_next:     i64                    = 0;
        var item_params: http::SfParameter[..8] = [];
        var params_next: i64                    = 0;
        guard sf_parse_bare_item(src, p, inner_item, in_next) &&
              sf_parse_parameters(src, in_next, item_params, params_next) &&
              copy_inner_item_params(item_params, inner_item.params) &&
              inner_items.try_push(inner_item) else {
            return false;
        }
        p = params_next;
        guard p < n && (src[p] == ' ' || src[p] == ')') else { return false; }
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
