// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Internal helpers for `http` (http/sfv_wire_internal.goose).
namespace http_internal;

import std;
import core;
import http.sfv;
import http.sfv_sig_internal;

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
