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
    item:   SfItem           = SfItem { .. },
    params: SfParameter[..8] = [],
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
    let start = pos + 1;
    var p = pos + 1;
    while p < src.len {
        let ch = src[p];
        if ch == ':' {
            out_item.kind = SfType.Binary;
            out_item.str_val = src[start..p];
            out_next = p + 1;
            return true;
        }
        guard core::is_ascii_alpha(ch) || core::is_ascii_digit(ch) || ch == '+' || ch == '/' || ch == '=' else {
            return false;
        }
        p = p + 1;
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
    let next_p = dot_pos + 1;
    let ok = sf_scan_digits(src, next_p, 3, frac_accum, frac_count, frac_end);
    if !ok {
        return false;
    }
    var factor: f64 = 1.0;
    if frac_count == 1 { factor = 0.1; }
    if frac_count == 2 { factor = 0.01; }
    if frac_count == 3 { factor = 0.001; }

    let frac_f = frac_accum * factor;
    var total_f = int_accum + frac_f;
    if is_neg {
        total_f = -total_f;
    }
    out_item.kind = SfType.Decimal;
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

fn validate_display_string(raw_str: const u8[:]) -> bool {
    var decoded: u8[..512] = [];
    var i:       i64       = 0;
    while i < raw_str.len {
        let b = raw_str[i];
        if b == '%' {
            guard i + 2 < raw_str.len else { return false; }
            let c1 = raw_str[i + 1];
            let c2 = raw_str[i + 2];
            let v1 = if c1 >= '0' && c1 <= '9' {
                (c1 - '0') as i32
            } else if c1 >= 'a' && c1 <= 'f' {
                (c1 - 'a' + 10) as i32
            } else {
                -1
            };
            let v2 = if c2 >= '0' && c2 <= '9' {
                (c2 - '0') as i32
            } else if c2 >= 'a' && c2 <= 'f' {
                (c2 - 'a' + 10) as i32
            } else {
                -1
            };
            guard v1 >= 0 && v2 >= 0 else { return false; }
            guard decoded.len < decoded.cap else { return false; }
            decoded.push(((v1 << 4) | v2) as u8);
            i += 3;
        } else {
            guard b >= 0x20 && b <= 0x7E && b != '%' && b != '"' else { return false; }
            guard decoded.len < decoded.cap else { return false; }
            decoded.push(b);
            i += 1;
        }
    }
    return core::validate_utf8(decoded[..]);
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
    let trimmed = core::trim_ascii_space(input);
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

// Helper: parses inner list contents (item1 item2 ...)
fn sf_parse_inner_list(src: const u8[:], pos: i64, entry: SfDictEntry&, out_next: i64&) -> bool {
    entry.is_inner_list = true;
    var p = pos + 1; // skip '('
    while p < src.len && src[p] != ')' {
        p = sf_skip_ws(src, p);
        if p < src.len && src[p] == ')' {
            break;
        }
        var inner_item = SfItem { .. };
        var in_next: i64 = 0;
        if !sf_parse_bare_item(src, p, inner_item, in_next) {
            return false;
        }
        if entry.inner_items.len < 8 {
            entry.inner_items.push(inner_item);
        } else {
            return false;
        }
        p = in_next;
    }
    if p >= src.len || src[p] != ')' {
        return false;
    }
    out_next = p + 1; // skip ')'
    return true;
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

// Parses an RFC 8941 Dictionary (Section 3.2): key=val, key2, key3=(a b);param
//
// Example:
//   input = "a=1, b=2"
//   returns: true, out_entries has 2 dictionary entries
fn parse_sf_dict(input: const u8[:], out_entries: SfDictEntry[..16]&) -> bool {
    out_entries.clear();
    let trimmed = core::trim_ascii_space(input);
    if trimmed.len == 0 {
        return true;
    }
    var p: i64 = 0;
    while p < trimmed.len {
        var entry = SfDictEntry { .. };
        var entry_next: i64 = 0;
        if !sf_parse_single_dict_entry(trimmed, p, entry, entry_next) {
            out_entries.clear();
            return false;
        }
        p = entry_next;

        var found_idx: i64 = -1;
        for i in out_entries.len {
            if out_entries[i].key == entry.key {
                found_idx = i;
                break;
            }
        }
        if found_idx >= 0 {
            out_entries[found_idx] = entry;
        } else if out_entries.len < 16 {
            out_entries.push(entry);
        } else {
            out_entries.clear();
            return false;
        }

        p = sf_skip_ws(trimmed, p);
        if p < trimmed.len {
            if trimmed[p] != ',' {
                out_entries.clear();
                return false;
            }
            p = p + 1; // skip ','
            p = sf_skip_ws(trimmed, p);
            if p >= trimmed.len {
                out_entries.clear();
                return false;
            }
        }
    }
    return true;
}

// Helper: parses a single list entry
fn sf_parse_single_list_entry(src: const u8[:], pos: i64, p_item: SfParameterizedItem&, out_next: i64&) -> bool {
    var item = SfItem { .. };
    var i_next: i64 = 0;
    if !sf_parse_bare_item(src, pos, item, i_next) {
        return false;
    }
    p_item.item = item;

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
    let trimmed = core::trim_ascii_space(input);
    if trimmed.len == 0 {
        return true;
    }
    var p: i64 = 0;
    while p < trimmed.len {
        var p_item = SfParameterizedItem { .. };
        var item_next: i64 = 0;
        if !sf_parse_single_list_entry(trimmed, p, p_item, item_next) {
            out_items.clear();
            return false;
        }
        p = item_next;

        if out_items.len < 16 {
            out_items.push(p_item);
        } else {
            out_items.clear();
            return false;
        }

        p = sf_skip_ws(trimmed, p);
        if p < trimmed.len {
            if trimmed[p] != ',' {
                out_items.clear();
                return false;
            }
            p = p + 1; // skip ','
            p = sf_skip_ws(trimmed, p);
            if p >= trimmed.len {
                out_items.clear();
                return false;
            }
        }
    }
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

fn sf_serialize_item<B>(item: const SfItem&, out: B&) {
    if item.kind == SfType.Integer {
        core::format_i64_dec(item.int_val, out);
    } else if item.kind == SfType.Boolean {
        out.append(if item.bool_val { "?1" } else { "?0" });
    } else if item.kind == SfType.Token {
        out.append(item.str_val);
    } else if item.kind == SfType.String {
        out.push('"' as u8);
        for i in item.str_val.len {
            let ch = item.str_val[i];
            if ch == '"' || ch == '\\' {
                out.push('\\' as u8);
            }
            out.push(ch);
        }
        out.push('"' as u8);
    } else if item.kind == SfType.Binary {
        out.push(':' as u8);
        out.append(item.str_val);
        out.push(':' as u8);
    } else if item.kind == SfType.Date {
        out.push('@' as u8);
        core::format_i64_dec(item.int_val, out);
    } else if item.kind == SfType.DisplayString {
        out.append("%\"");
        out.append(item.str_val);
        out.push('"' as u8);
    }
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
