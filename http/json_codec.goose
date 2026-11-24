// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Compile-time reflective JSON and query codec via Goose `const for` and receiver-namespace UFCS.
// Supports scalars, `u8[..N]`, `u8[>..]`, `T[>..]`, `core::Opt<T>`, nested structs, and user enums.
namespace http;

import std;
import core;
import json;

// ---- JSON field omission and recursive encoder -----------------------------

fn is_omitted_json_field<T>(_v: const T&) -> bool {
    return false;
}

fn core::is_omitted_json_field<T>(v: const core::Opt<T>&) -> bool {
    return !v.present;
}

fn json_encode(v: bool, out: u8[>..]&) { json::format_bool(out, v); }
fn json_encode(v: i8, out: u8[>..]&) { json::format_int(out, v); }
fn json_encode(v: u8, out: u8[>..]&) { json::format_int(out, v); }
fn json_encode(v: i16, out: u8[>..]&) { json::format_int(out, v); }
fn json_encode(v: u16, out: u8[>..]&) { json::format_int(out, v); }
fn json_encode(v: i32, out: u8[>..]&) { json::format_int(out, v); }
fn json_encode(v: u32, out: u8[>..]&) { json::format_int(out, v); }
fn json_encode(v: i64, out: u8[>..]&) { json::format_int(out, v); }
fn json_encode(v: u64, out: u8[>..]&) { v.format_u64_dec(out); }
fn json_encode(v: f64, out: u8[>..]&) { json::format_number(out, v); }
fn json_encode(v: const u8[:], out: u8[>..]&) { json::format_string(out, v); }

fn encode_json_field_val<T>(v: const T&, out: u8[>..]&) {
    v.json_encode(out);
}

fn core::json_encode<T>(v: const core::Opt<T>&, out: u8[>..]&) {
    if !v.present {
        out.append("null");
        return;
    }
    http::encode_json_field_val(v.value, out);
}

fn encode_arr_by_tag(xs: const u8[:], out: u8[>..]&) {
    json::format_string(out, xs);
}

fn encode_arr_by_tag<E>(xs: const E[:], out: u8[>..]&) {
    out.push('[');
    for &x, i in xs {
        if i > 0 { out.push(','); }
        x.json_encode(out);
    }
    out.push(']');
}

fn json_encode<B>(arr: const B&, out: u8[>..]&) {
    encode_arr_by_tag(arr[..], out);
}

// Serializes struct `obj` as a JSON object into `out`, omitting absent `core::Opt<T>` fields.
fn encode_json_struct<T>(obj: const T&, out: u8[>..]&) {
    out.push('{');
    var first = true;
    const for <Name, Acc> in fields<T> {
        if !obj.Acc.is_omitted_json_field() {
            if !first { out.push(','); }
            first = false;
            json::format_key(out, Name);
            obj.Acc.json_encode(out);
        }
    }
    out.push('}');
}

// ---- Recursive JSON decoder with slice-tag dispatch ------------------------

struct ByteBufTag {}
struct ElemArrTag<E> {}

fn arr_tag(_s: u8[:]) -> ByteBufTag { return ByteBufTag {}; }
fn arr_tag<E>(_s: E[:]) -> ElemArrTag<E> { return ElemArrTag<E> {}; }

fn read_checked_json_int(r: json::Reader&, lo: i64, hi: i64) -> i64, bool {
    let c = json::peek(r);
    guard (c >= '0' && c <= '9') || c == '-' else {
        json::fail(r, "expected integer");
        return 0, false;
    }
    let v = json::read_int(r);
    guard r.error.len == 0 else { return 0, false; }
    guard v >= lo && v <= hi else {
        json::fail(r, "integer out of range");
        return 0, false;
    }
    return v, true;
}

fn json_decode(dst: bool&, r: json::Reader&) {
    let c = json::peek(r);
    guard c == 't' || c == 'f' else {
        json::fail(r, "expected boolean");
        return;
    }
    dst = json::read_bool(r);
}

fn json_decode(dst: i64&, r: json::Reader&) {
    let c = json::peek(r);
    guard (c >= '0' && c <= '9') || c == '-' else {
        json::fail(r, "expected integer");
        return;
    }
    dst = json::read_int(r);
}

fn json_decode(dst: u64&, r: json::Reader&) {
    let at = json::skip_space(r.text, r.pos);
    r.pos = at;
    guard at < r.text.len else {
        json::fail(r, "expected unsigned integer");
        return;
    }
    guard r.text[at] != '-' else {
        json::fail(r, "negative unsigned integer");
        return;
    }
    guard core::is_ascii_digit(r.text[at]) else {
        json::fail(r, "expected unsigned integer");
        return;
    }
    var end = at;
    while end < r.text.len && core::is_ascii_digit(r.text[end]) {
        end = core::add_sat_i64(end, 1);
    }
    guard !(core::sub_sat_i64(end, at) > 1 && r.text[at] == '0') else {
        json::fail(r, "leading zero in integer");
        return;
    }
    if end < r.text.len {
        let next = r.text[end];
        guard next != '.' && next != 'e' && next != 'E' else {
            json::fail(r, "expected unsigned integer");
            return;
        }
    }
    let val, ok = r.text[at..end].parse_u64_dec();
    guard ok else {
        json::fail(r, "u64 out of range");
        return;
    }
    r.pos = end;
    dst = val;
}

fn json_decode(dst: i32&, r: json::Reader&) {
    let c = json::peek(r);
    guard (c >= '0' && c <= '9') || c == '-' else {
        json::fail(r, "expected integer");
        return;
    }
    let v = json::read_int(r);
    if r.error.len == 0 {
        dst = core::clamp_i64(v, -2147483648, 2147483647) as i32;
    }
}

fn json_decode(dst: u32&, r: json::Reader&) {
    let v, ok = read_checked_json_int(r, 0, 4294967295);
    if ok { dst = v as u32; }
}

fn json_decode(dst: i16&, r: json::Reader&) {
    let v, ok = read_checked_json_int(r, -32768, 32767);
    if ok { dst = v as i16; }
}

fn json_decode(dst: u16&, r: json::Reader&) {
    let v, ok = read_checked_json_int(r, 0, 65535);
    if ok { dst = v as u16; }
}

fn json_decode(dst: i8&, r: json::Reader&) {
    let v, ok = read_checked_json_int(r, -128, 127);
    if ok { dst = v as i8; }
}

fn json_decode(dst: u8&, r: json::Reader&) {
    let v, ok = read_checked_json_int(r, 0, 255);
    if ok { dst = v as u8; }
}

fn json_decode(dst: f64&, r: json::Reader&) {
    let c = json::peek(r);
    guard (c >= '0' && c <= '9') || c == '-' else {
        json::fail(r, "expected number");
        return;
    }
    dst = json::read_number(r);
}

// Decodes a JSON value from `r` into `dst` via receiver-namespace UFCS.
//
// Example:
//   r positioned at `"admin"`, dst: DemoRole& -> dst = DemoRole.Admin
fn decode_json_field_val<T>(dst: T&, r: json::Reader&) {
    dst.json_decode(r);
}

fn core::json_decode<T>(dst: core::Opt<T>&, r: json::Reader&) {
    if json::peek(r) == 'n' {
        json::skip(r);
        dst.present = false;
        dst.value = default<T>();
        return;
    }
    var parsed = default<T>();
    http::decode_json_field_val(parsed, r);
    if r.error.len == 0 {
        dst.value = copy(parsed);
        dst.present = true;
    }
}

// Decodes a JSON string into growable byte buffer `dst`.
//
// Example:
//   r positioned at `"wing"` -> dst = "wing"
fn decode_tagged(_t: ByteBufTag, dst: u8[>..]&, r: json::Reader&) {
    dst.clear();
    var scratch: u8[>..] = [];
    let val = json::read_string(r, scratch);
    if r.error.len == 0 {
        dst.append(val);
    }
}

// Decodes a JSON string into bounded byte buffer `dst`, failing `r` on capacity overflow.
//
// Example:
//   r positioned at `"ok"`, dst = u8[..8] -> dst = "ok"
fn decode_tagged<B>(_t: ByteBufTag, dst: B&, r: json::Reader&) {
    if !core::read_json_string_into(r, dst) && r.error.len == 0 {
        json::fail(r, "string exceeds capacity");
    }
}

// Decodes a JSON array into growable array `dst`.
//
// Example:
//   r positioned at `[1,2]` -> dst = [1, 2]
fn decode_tagged<E>(_t: ElemArrTag<E>, dst: E[>..]&, r: json::Reader&) {
    dst.clear();
    json::each_element(r) {
        var el = default<E>();
        el.json_decode(r);
        if r.error.len == 0 {
            dst.push(el);
        }
    };
}

// Decodes a JSON array into fixed-capacity bounded array `dst`, failing `r` on overflow.
//
// Example:
//   r positioned at `[{"v":"5"}]`, dst = Item[..8] -> dst.len = 1
fn decode_bounded_array<B, E>(dst: B&, r: json::Reader&) {
    dst.clear();
    json::each_element(r) {
        if dst.len >= dst.cap {
            json::fail(r, "array exceeds capacity");
            return;
        }
        var el = default<E>();
        el.json_decode(r);
        if r.error.len == 0 {
            dst.push(el);
        }
    };
}

fn json_decode<B>(arr: B&, r: json::Reader&) {
    decode_tagged(arr_tag(arr[..]), arr, r);
}

// Serializes any JSON-encodable value `val` (struct, array, or scalar) into `out`.
fn to_json<T>(val: const T&, out: u8[>..]&) {
    out.clear();
    val.json_encode(out);
}

// Decodes a JSON document `raw` into `out`, rolling back `out` on syntax or schema error.
//
// Example:
//   raw = "[{\"slot\":1}]", out: NestedTag[>..]& -> returns true, out.len = 1
fn from_json<T>(raw: const u8[:], out: T&) -> bool {
    guard raw.len > 0 else { return false; }
    let saved = copy(out);
    var committed = false;
    defer if !committed { out = copy(saved); };
    var r = json::reader(raw);
    out.json_decode(r);
    guard json::finish(r) else { return false; }
    committed = true;
    return true;
}

// Decodes a JSON object from `r` into struct `out` via `const for` reflection.
// Unknown JSON keys are skipped cleanly.
//
// Example:
//   r positioned at `{"id":7}` -> out.id = 7
fn decode_json_struct<T>(out: T&, r: json::Reader&) {
    json::each_member(r) { key =>
        var matched = false;
        const for <Name, Acc> in fields<T> {
            if !matched && key == Name {
                out.Acc.json_decode(r);
                matched = true;
            }
        }
        if !matched {
            json::skip(r);
        }
    };
}

// ---- Reflective query/param/header scalar parsers & formatters -------------

fn is_omitted_query_field<T>(_v: const T&) -> bool {
    return false;
}

fn core::is_omitted_query_field<T>(v: const core::Opt<T>&) -> bool {
    return !v.present;
}

fn is_omitted_query_field_val<T>(v: const T&) -> bool {
    return v.is_omitted_query_field();
}

fn query_parse(dst: i64&, raw: const u8[:]) -> bool {
    let val, ok = raw.parse_i64_dec();
    guard ok else { return false; }
    dst = val;
    return true;
}

fn query_parse(dst: u64&, raw: const u8[:]) -> bool {
    let val, ok = raw.parse_u64_dec();
    guard ok else { return false; }
    dst = val;
    return true;
}

fn query_parse(dst: i32&, raw: const u8[:]) -> bool {
    let val, ok = raw.parse_i32_dec();
    guard ok else { return false; }
    dst = val;
    return true;
}

fn query_parse(dst: u32&, raw: const u8[:]) -> bool {
    let val, ok = raw.parse_u32_dec();
    guard ok else { return false; }
    dst = val;
    return true;
}

fn query_parse(dst: i16&, raw: const u8[:]) -> bool {
    let val, ok = raw.parse_i32_dec();
    guard ok && val >= -32768 && val <= 32767 else { return false; }
    dst = val as i16;
    return true;
}

fn query_parse(dst: u16&, raw: const u8[:]) -> bool {
    let val, ok = raw.parse_u32_dec();
    guard ok && val <= 65535 else { return false; }
    dst = val as u16;
    return true;
}

fn query_parse(dst: i8&, raw: const u8[:]) -> bool {
    let val, ok = raw.parse_i32_dec();
    guard ok && val >= -128 && val <= 127 else { return false; }
    dst = val as i8;
    return true;
}

fn query_parse(dst: u8&, raw: const u8[:]) -> bool {
    let val, ok = raw.parse_u32_dec();
    guard ok && val <= 255 else { return false; }
    dst = val as u8;
    return true;
}

fn query_parse(dst: bool&, raw: const u8[:]) -> bool {
    if raw.eq_ascii_fold("true") || raw == "1" {
        dst = true;
        return true;
    }
    if raw.eq_ascii_fold("false") || raw == "0" {
        dst = false;
        return true;
    }
    return false;
}

fn query_parse<B>(dst: B&, raw: const u8[:]) -> bool {
    return dst.try_set(raw);
}

// Parses scalar/enum/string query value `raw` into `dst` via receiver-namespace UFCS.
//
// Example:
//   raw = "42", dst: u8& -> returns true, dst = 42
fn parse_query_field_val<T>(dst: T&, raw: const u8[:]) -> bool {
    return dst.query_parse(raw);
}

fn query_bind_field<T>(dst: T&, raw_q: const u8[:], name: const u8[:]) -> bool {
    var val_buf: u8[..512] = [];
    return raw_q.get_query_param_fast(name, val_buf) == core::QueryParamMatch.Value &&
        dst.query_parse(val_buf[..]);
}

fn core::query_bind_field<T>(dst: core::Opt<T>&, raw_q: const u8[:], name: const u8[:]) -> bool {
    if !raw_q.has_query_param_fast(name) {
        dst.present = false;
        dst.value = default<T>();
        return true;
    }
    var val_buf: u8[..512] = [];
    let matched = raw_q.get_query_param_fast(name, val_buf);
    guard matched == core::QueryParamMatch.Value else { return false; }
    var parsed = default<T>();
    guard http::parse_query_field_val(parsed, val_buf[..]) else { return false; }
    dst.value = copy(parsed);
    dst.present = true;
    return true;
}

fn query_format<B>(val: i64, out: B&) -> bool {
    var tmp: u8[..32] = [];
    val.format_i64_dec(tmp);
    return out.try_append(tmp[..]);
}

fn query_format<B>(val: u64, out: B&) -> bool {
    var tmp: u8[..32] = [];
    val.format_u64_dec(tmp);
    return out.try_append(tmp[..]);
}

fn query_format<B>(val: i32, out: B&) -> bool {
    return query_format(val as i64, out);
}

fn query_format<B>(val: u32, out: B&) -> bool {
    var tmp: u8[..32] = [];
    val.format_u32_dec(tmp);
    return out.try_append(tmp[..]);
}

fn query_format<B>(val: i16, out: B&) -> bool {
    return query_format(val as i64, out);
}

fn query_format<B>(val: u16, out: B&) -> bool {
    return query_format(val as u32, out);
}

fn query_format<B>(val: i8, out: B&) -> bool {
    return query_format(val as i64, out);
}

fn query_format<B>(val: u8, out: B&) -> bool {
    return query_format(val as u32, out);
}

fn query_format<B>(val: bool, out: B&) -> bool {
    return out.try_append(if val { "true" } else { "false" });
}

fn query_format<B>(val: const u8[:], out: B&) -> bool {
    return out.try_append(val);
}

// Formats scalar/enum/string query value `val` into `out` via receiver-namespace UFCS.
//
// Example:
//   val = 5, out = [] -> returns true, out = "5"
fn format_query_field_val<T, B>(val: const T&, out: B&) -> bool {
    return val.query_format(out);
}

fn core::query_format<T, B>(v: const core::Opt<T>&, out: B&) -> bool {
    guard v.present else { return true; }
    return http::format_query_field_val(v.value, out);
}
