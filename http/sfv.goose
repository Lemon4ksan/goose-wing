// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// RFC 8941 & RFC 9651 Structured Field Values for HTTP.
// Provides zero-allocation parsing, inspection, and serialization of HTTP
// structured fields (sf-item, sf-list, sf-dictionary, sf-inner-list, sf-parameters).
namespace http;

import std;
import core;
import http.sfv_sig_internal;
import http.sfv_wire_internal;

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

struct SfItemParam {
    key:      u8[..32] = [],
    kind:     SfType   = SfType.Boolean,
    int_val:  i64      = 0,
    dec_val:  f64      = 0.0,
    str_val:  u8[..64] = [],
    bool_val: bool     = true,
}

struct SfItem {
    kind:     SfType           = SfType.Token,
    int_val:  i64              = 0,
    dec_val:  f64              = 0.0,
    str_val:  const u8[:]      = "",
    bool_val: bool             = false,
    params:   SfItemParam[..4] = [],
}

struct SfParameter {
    key:  const u8[:] = "",
    item: SfItem      = SfItem { .. },
}

struct SfParameterizedItem {
    item:          SfItem           = SfItem { .. },
    params:        SfParameter[..8] = [],
    is_inner_list: bool             = false,
    inner_items:   SfItem[..16]     = [],
}

struct SfDictEntry {
    key:           const u8[:]      = "",
    is_inner_list: bool             = false,
    item:          SfItem           = SfItem { .. },
    params:        SfParameter[..8] = [],
    inner_items:   SfItem[..16]     = [],
}

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
    kind:     SfvType    = SfvType.Boolean,
    int_val:  i64        = 0,       // For Integer, Date, and Decimal (scaled * 1000 in milliths)
    bool_val: bool       = false,   // For Boolean
    text:     u8[..1088] = [],      // For String, Token, ByteSequence, DisplayString (>= 1024 bytes per RFC 8941)
}

struct SfvParam {
    key:   u8[..64]    = [],
    value: SfvBareItem = SfvBareItem { .. },
}

struct SfvItem {
    bare:   SfvBareItem    = SfvBareItem { .. },
    params: SfvParam[..16] = [],
}

struct SfvMember {
    is_inner_list: bool           = false,
    item:          SfvItem        = SfvItem { .. },
    inner_list:    SfvItem[..32]  = [],
    inner_params:  SfvParam[..16] = [],
}

struct SfvList {
    members: SfvMember[..64] = [],
    valid:   bool            = true,
}

struct SfvDictEntry {
    key:    u8[..64]  = [],
    member: SfvMember = SfvMember { .. },
}

struct SfvDict {
    entries: SfvDictEntry[..64] = [],
    valid:   bool               = true,
}

// ---- Whitespace & Index Scanners -----------------------------------------

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
            let pct_b, hex_ok = http_internal::sf_decode_pct_hex(raw[i1], raw[i2]);
            guard hex_ok else { return false; }
            dec_b = pct_b;
            step = 3;
        } else {
            guard b >= 0x20 && b <= 0x7E && b != '%' && b != '"' else { return false; }
            dec_b = b;
        }
        guard http_internal::sf_step_utf8_dfa(dec_b, state) && out.try_push(dec_b) else { return false; }
        i = core::add_sat_i64(i, step);
    }
    guard state == 0 else { return false; }
    committed = true;
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
    let trimmed = input.trim_lws();
    if trimmed.len == 0 {
        return result, false;
    }
    var pos: i64 = 0;
    var bare_item = SfItem { .. };
    var n_pos: i64 = 0;
    if !http_internal::sf_parse_bare_item(trimmed, pos, bare_item, n_pos) {
        return result, false;
    }
    result.item = bare_item;
    pos = n_pos;

    var params_next: i64 = 0;
    if !http_internal::sf_parse_parameters(trimmed, pos, result.params, params_next) {
        return result, false;
    }
    let end_p = http_internal::sf_skip_ws(trimmed, params_next);
    if end_p != trimmed.len {
        return result, false;
    }
    return result, true;
}

// Returns true when `item.params` contains a boolean-true flag parameter named `key`.
fn sf_item_has_flag_param(item: const SfItem&, key: const u8[:]) -> bool {
    for &p in item.params {
        if p.key[..] == key && p.kind == SfType.Boolean && p.bool_val {
            return true;
        }
    }
    return false;
}

// Helper: parses inner list contents (item1 item2 ...) per RFC 8941 §4.2.1.2
fn sf_parse_inner_list(src: const u8[:], pos: i64, entry: SfDictEntry&, out_next: i64&) -> bool {
    entry.is_inner_list = true;
    return http_internal::sf_parse_inner_list_items(src, pos, entry.inner_items, out_next);
}

// Parses an RFC 8941 Dictionary (Section 3.2): key=val, key2, key3=(a b);param
//
// Example:
//   input = "a=1, b=2"
//   returns: true, out_entries has 2 dictionary entries
fn parse_sf_dict(input: const u8[:], out_entries: SfDictEntry[..16]&) -> bool {
    out_entries.clear();
    let trimmed = input.trim_lws();
    if trimmed.len == 0 {
        return true;
    }
    var committed = false;
    defer if !committed { out_entries.clear(); };
    var p: i64 = 0;
    while p < trimmed.len {
        var entry = SfDictEntry { .. };
        var entry_next: i64 = 0;
        guard http_internal::sf_parse_single_dict_entry(trimmed, p, entry, entry_next) else { return false; }
        p = entry_next;

        guard http_internal::upsert_sf_dict_entry(out_entries, entry) else { return false; }

        p = http_internal::sf_skip_ws(trimmed, p);
        if p < trimmed.len {
            guard trimmed[p] == ',' else { return false; }
            p = http_internal::sf_skip_ws(trimmed, core::add_sat_i64(p, 1));
            guard p < trimmed.len else { return false; }
        }
    }
    committed = true;
    return true;
}

// Parses an RFC 8941 List (Section 3.1): item1, item2, "string", ?1
//
// Example:
//   input = "1, 2, \"three\""
//   returns: true, out_items has 3 elements
fn parse_sf_list(input: const u8[:], out_items: SfParameterizedItem[..16]&) -> bool {
    out_items.clear();
    let trimmed = input.trim_lws();
    if trimmed.len == 0 {
        return true;
    }
    var committed = false;
    defer if !committed { out_items.clear(); };
    var p: i64 = 0;
    while p < trimmed.len {
        var p_item = SfParameterizedItem { .. };
        var item_next: i64 = 0;
        guard http_internal::sf_parse_single_list_entry(trimmed, p, p_item, item_next) else { return false; }
        p = item_next;

        guard out_items.try_push(p_item) else { return false; }

        p = http_internal::sf_skip_ws(trimmed, p);
        if p < trimmed.len {
            guard trimmed[p] == ',' else { return false; }
            p = http_internal::sf_skip_ws(trimmed, core::add_sat_i64(p, 1));
            guard p < trimmed.len else { return false; }
        }
    }
    committed = true;
    return true;
}

// ---- Owned Decoded SFV Parsers (SfvItem, SfvList, SfvDict) ---------------

// RFC 8941 Section 3.1.2: Dictionary key parser
// key = ( lcalpha / "*" ) *( lcalpha / DIGIT / "_" / "-" / "." / "*" )
//
// Example:
//   raw = "key_name=123", cursor = 0, out_key = []
//   returns: true, cursor = 8, out_key = "key_name"
fn parse_sfv_key(raw: const u8[:], cursor: i64&, out_key: u8[..64]&) -> bool {
    let key_slice, next_pos, ok = http_internal::sf_parse_key(raw, cursor);
    guard ok && out_key.try_set(key_slice) else { return false; }
    cursor = next_pos;
    return true;
}

// RFC 8941 Section 3.3: Item parser
//
// Example:
//   raw = "123; q=1", out = SfvItem { .. }
//   returns: true, out.bare.int_val = 123
fn parse_sfv_item(raw: const u8[:], out: SfvItem&) -> bool {
    var cursor = http_internal::sf_skip_ws(raw, 0);
    guard cursor < raw.len else { return false; }

    var bare = SfvBareItem { .. };
    guard http_internal::parse_sfv_bare_item(raw, cursor, bare) else { return false; }

    var params: SfvParam[..16] = [];
    guard http_internal::parse_sfv_parameters(raw, cursor, params) else { return false; }

    cursor = http_internal::sf_skip_ws(raw, cursor);
    guard cursor == raw.len else { return false; } // Strict atomicity: no trailing junk!

    out.bare = bare;
    out.params.clear();
    for &p in params { out.params.push(p); }
    return true;
}

// RFC 8941 Section 3.1: List parser (supports items and inner lists)
//
// Example:
//   raw = "a, b, (c d)", out = SfvList { .. }
//   returns: true, out.members has parsed elements
fn parse_sfv_list(raw: const u8[:], out: SfvList&) -> bool {
    out.members.clear();
    out.valid = false;
    defer if !out.valid { out.members.clear(); };

    var cursor = http_internal::sf_skip_ws(raw, 0);
    if cursor == raw.len {
        out.valid = true;
        return true; // Empty list is valid
    }

    while cursor < raw.len {
        var member = SfvMember { .. };
        if raw[cursor] == '(' {
            guard http_internal::parse_sfv_inner_list(raw, cursor, member) else { return false; }
        } else {
            guard http_internal::parse_sfv_member_item(raw, cursor, member) else { return false; }
        }

        guard out.members.try_push(member) else { return false; }

        var has_more = false;
        guard http_internal::sfv_advance_comma(raw, cursor, has_more) else { return false; }
        if !has_more { break; }
    }

    out.valid = true;
    return true;
}

// RFC 8941 Section 3.2: Dictionary parser
//
// Example:
//   raw = "en=\"English\", de=\"German\"", out = SfvDict { .. }
//   returns: true, out.entries has dictionary entries
fn parse_sfv_dict(raw: const u8[:], out: SfvDict&) -> bool {
    out.entries.clear();
    out.valid = false;
    defer if !out.valid { out.entries.clear(); };

    var cursor = http_internal::sf_skip_ws(raw, 0);
    if cursor == raw.len {
        out.valid = true;
        return true; // Empty dictionary is valid
    }

    while cursor < raw.len {
        var key: u8[..64] = [];
        guard parse_sfv_key(raw, cursor, key) else { return false; }

        var member = SfvMember { .. };
        guard http_internal::parse_sfv_dict_entry_member(raw, cursor, member) else { return false; }
        guard http_internal::upsert_sfv_dict_entry(out.entries, key, member) else { return false; }

        var has_more = false;
        guard http_internal::sfv_advance_comma(raw, cursor, has_more) else { return false; }
        if !has_more { break; }
    }

    out.valid = true;
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

// Decimal serialization per RFC 8941 Section 4.1.5
fn serialize_sfv_decimal<B>(scaled_milli: i64, out: B&) {
    if scaled_milli < 0 {
        out.push('-');
    }
    let abs_milli = if scaled_milli < 0 {
        core::sub_sat_i64(0, scaled_milli)
    } else {
        scaled_milli
    };
    var raw_digits: u8[..24] = [];
    abs_milli.format_i64_dec(raw_digits);

    var padded: u8[..28] = [];
    if raw_digits.len == 1 {
        padded.append("000");
    } else if raw_digits.len == 2 {
        padded.append("00");
    } else if raw_digits.len == 3 {
        padded.append("0");
    }
    padded.append(raw_digits[..]);

    let split_idx = core::sub_sat_i64(padded.len, 3);
    out.append(padded[..split_idx]);
    out.push('.');
    let frac_full = padded[split_idx..];
    let frac_t1, _ = frac_full.strip_suffix("0");
    let frac_t2, _ = frac_t1.strip_suffix("0");
    out.append(frac_t2);
}

inline fn sf_serialize_item<B>(kind: SfType.Integer, item: const SfItem&, out: B&) {
    item.int_val.format_i64_dec(out);
}

inline fn sf_serialize_item<B>(kind: SfType.Decimal, item: const SfItem&, out: B&) {
    serialize_sfv_decimal(item.int_val, out);
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
            http_internal::sf_serialize_item_params(entry.inner_items[idx].params[..], out);
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
