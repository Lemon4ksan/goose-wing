// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Ergonomic application-layer JSON helpers: DOM path extraction, lenient reflective decoding,
// and an auto-comma streaming JsonWriter.
namespace http;

import std;
import core;
import json;
import .json_codec;

// ---- UTF-8 safe truncation and DOM path extraction -------------------------

// Truncates `s` to at most `max_bytes` without splitting a multi-byte UTF-8 sequence.
//
// Example:
//   s = "Привет" (12 bytes), max_bytes = 5 -> returns "Пр" (4 bytes)
fn truncate_utf8_safe(s: const u8[:], max_bytes: i64) -> const u8[:] {
    guard max_bytes > 0 else { return ""; }
    guard s.len > max_bytes else { return s; }
    var cut = max_bytes;
    while cut > 0 && (s[cut] & 0xC0) == 0x80 {
        cut = core::sub_sat_i64(cut, 1);
    }
    return s[..cut];
}

// Navigates dot-separated object keys from `root` (e.g. `"data.returnUrl"`).
//
// Example:
//   root = {"data":{"id":7}}, path = "data.id" -> Node(Int 7)
fn json_path(root: json::Node?, path: const u8[:]) -> json::Node? {
    var cur = root;
    guard path.len > 0 else { return cur; }
    var tok = core::make_byte_tokenizer(path, '.');
    loop {
        let seg, has = core::token_next(tok);
        if !has { break; }
        guard seg.len > 0 else { return null; }
        let node = cur;
        guard node else { return null; }
        cur .= json::member(node, seg);
    }
    return cur;
}

// Returns the string slice of `n`, or `fallback` if `n` is absent or not a string.
fn json_str_or(n: json::Node?, fallback: const u8[:] = "") -> const u8[:] {
    let s, ok = json::as_string(n);
    return if ok { s } else { fallback };
}

// Copies a JSON string (or integer formatted as decimal) from `n` into growable `dst`.
// Clears `dst` and returns `true` when `n` is missing or `null`.
fn json_str_into(n: json::Node?, dst: u8[>..]&) -> bool {
    dst.clear();
    guard n else { return true; }
    return match n.val {
        Null => true,
        Str sv => block { dst.append(sv.s); true },
        Int iv => block { format(dst, iv.v); true },
        _ => false,
    };
}

// Copies a JSON string (or integer formatted as decimal) from `n` into bounded `dst`,
// truncating safely on UTF-8 codepoint boundaries if longer than `dst.cap`.
//
// Example:
//   n = Str("abcdef"), dst: u8[..4] -> dst = "abcd", returns true
fn json_str_into<B>(n: json::Node?, dst: B&) -> bool {
    dst.clear();
    guard n else { return true; }
    return match n.val {
        Null => true,
        Str sv => dst.try_set(truncate_utf8_safe(sv.s, dst.cap)),
        Int iv => block {
            var tmp: u8[..32] = [];
            iv.v.format_i64_dec(tmp);
            dst.try_set(truncate_utf8_safe(tmp[..], dst.cap))
        },
        _ => false,
    };
}

// Extracts an `i64` from an integer or number node, returning `fallback` otherwise.
fn json_i64_or(n: json::Node?, fallback: i64 = 0) -> i64 {
    let iv, ok_i = json::as_i64(n);
    if ok_i { return iv; }
    let fv, ok_f = json::as_f64(n);
    if ok_f && fv >= -9223372036854774784.0 && fv <= 9223372036854774784.0 {
        return fv as! i64;
    }
    return fallback;
}

// Extracts a `bool` from a boolean or integer (`!= 0`) node, returning `fallback` otherwise.
fn json_bool_or(n: json::Node?, fallback: bool = false) -> bool {
    let bv, ok_b = json::as_bool(n);
    if ok_b { return bv; }
    let iv, ok_i = json::as_i64(n);
    if ok_i { return iv != 0; }
    return fallback;
}

// ---- Lenient reflective JSON decoder ---------------------------------------

// Compares a JSON wire key against a Goose struct field name ignoring ASCII case and `'_'`.
//
// Example:
//   wire_key = "TypeWork", field_name = "type_work" -> true
fn eq_json_key_loose(wire_key: const u8[:], field_name: const u8[:]) -> bool {
    var wi: i64 = 0;
    var fi: i64 = 0;
    loop {
        while wi < wire_key.len && wire_key[wi] == '_' { wi = core::add_sat_i64(wi, 1); }
        while fi < field_name.len && field_name[fi] == '_' { fi = core::add_sat_i64(fi, 1); }
        if wi >= wire_key.len || fi >= field_name.len {
            return wi >= wire_key.len && fi >= field_name.len;
        }
        let wb = core::to_lower_ascii_byte(wire_key[wi]);
        let fb = core::to_lower_ascii_byte(field_name[fi]);
        guard wb == fb else { return false; }
        wi = core::add_sat_i64(wi, 1);
        fi = core::add_sat_i64(fi, 1);
    }
    return false;
}

inline fn is_json_num_start(c: u8) -> bool {
    return c == '-' || (c >= '0' && c <= '9');
}

fn read_lenient_i64(r: json::Reader&) -> i64, bool {
    let at = json::skip_space(r.text, r.pos);
    r.pos = at;
    guard at < r.text.len && is_json_num_start(r.text[at]) else {
        skip_json_value_strict(r);
        return 0, false;
    }
    guard check_json_number_token_len(r) else { return 0, false; }
    var scan = if r.text[at] == '-' { core::add_sat_i64(at, 1) } else { at };
    while scan < r.text.len && core::is_ascii_digit(r.text[scan]) {
        scan = core::add_sat_i64(scan, 1);
    }
    let is_flt = scan < r.text.len &&
        (r.text[scan] == '.' || r.text[scan] == 'e' || r.text[scan] == 'E');
    if !is_flt {
        let iv = json::read_int(r);
        return iv, r.error.len == 0;
    }
    let fv = json::read_number(r);
    guard r.error.len == 0 else { return 0, false; }
    guard fv - fv == 0.0 && fv >= -9223372036854774784.0 && fv <= 9223372036854774784.0 else {
        json::fail(r, "non-finite or out-of-range float");
        return 0, false;
    }
    return fv as! i64, true;
}

fn json_decode_lenient(dst: bool&, r: json::Reader&) {
    let c = json::peek(r);
    if c == 't' || c == 'f' {
        dst = json::read_bool(r);
        return;
    }
    if is_json_num_start(c) {
        let v, ok = read_lenient_i64(r);
        if ok { dst = v != 0; }
        return;
    }
    json::skip(r);
}

fn json_decode_lenient(dst: i64&, r: json::Reader&) {
    let v, ok = read_lenient_i64(r);
    if ok { dst = v; }
}

fn json_decode_lenient(dst: u64&, r: json::Reader&) {
    let c = json::peek(r);
    if core::is_ascii_digit(c) {
        json_decode(dst, r);
        return;
    }
    json::skip(r);
}

fn json_decode_lenient(dst: i32&, r: json::Reader&) {
    let v, ok = read_lenient_i64(r);
    if ok { dst = core::clamp_i64(v, -2147483648, 2147483647) as i32; }
}

fn json_decode_lenient(dst: u32&, r: json::Reader&) {
    let v, ok = read_lenient_i64(r);
    if ok { dst = core::clamp_i64(v, 0, 4294967295) as u32; }
}

fn json_decode_lenient(dst: i16&, r: json::Reader&) {
    let v, ok = read_lenient_i64(r);
    if ok { dst = core::clamp_i64(v, -32768, 32767) as i16; }
}

fn json_decode_lenient(dst: u16&, r: json::Reader&) {
    let v, ok = read_lenient_i64(r);
    if ok { dst = core::clamp_i64(v, 0, 65535) as u16; }
}

fn json_decode_lenient(dst: i8&, r: json::Reader&) {
    let v, ok = read_lenient_i64(r);
    if ok { dst = core::clamp_i64(v, -128, 127) as i8; }
}

fn json_decode_lenient(dst: u8&, r: json::Reader&) {
    let v, ok = read_lenient_i64(r);
    if ok { dst = core::clamp_i64(v, 0, 255) as u8; }
}

fn json_decode_lenient(dst: f64&, r: json::Reader&) {
    if is_json_num_start(json::peek(r)) {
        guard check_json_number_token_len(r) else { return; }
        let v = json::read_number(r);
        guard r.error.len == 0 else { return; }
        guard v - v == 0.0 else {
            json::fail(r, "non-finite float");
            return;
        }
        dst = v;
        return;
    }
    skip_json_value_strict(r);
}

// Dispatches lenient JSON decoding via UFCS for any struct field type `T`.
//
// Example:
//   r at `42`, dst: i64 -> dst = 42
fn decode_lenient_field_val<T>(dst: T&, r: json::Reader&) {
    dst.json_decode_lenient(r);
}

fn core::json_decode_lenient<T>(dst: core::Opt<T>&, r: json::Reader&) {
    if json::peek(r) == 'n' {
        json::skip(r);
        dst.present = false;
        dst.value = default<T>();
        return;
    }
    var parsed = default<T>();
    http::decode_lenient_field_val(parsed, r);
    if r.error.len == 0 {
        dst.value = copy(parsed);
        dst.present = true;
    }
}

// Decodes a JSON string or integer scalar leniently into dynamic byte buffer `dst`.
//
// Example:
//   r at `1234` -> dst = "1234"
fn decode_lenient_tagged(_t: ByteBufTag, dst: u8[>..]&, r: json::Reader&) {
    dst.clear();
    let c = json::peek(r);
    if c == '"' {
        let _ = core::read_json_string_growable(r, dst);
        return;
    }
    if is_json_num_start(c) {
        let v, ok = read_lenient_i64(r);
        if ok { format(dst, v); }
        return;
    }
    skip_json_value_strict(r);
}

// Decodes a JSON string or integer into bounded `u8[..N]` `dst`, truncating cleanly on UTF-8 boundaries.
//
// Example:
//   r at `"Привет"`, dst: u8[..4] -> dst = "Пр"
fn decode_lenient_tagged<B>(_t: ByteBufTag, dst: B&, r: json::Reader&) {
    dst.clear();
    let c = json::peek(r);
    if c == '"' {
        var scratch: u8[>..] = [];
        if core::read_json_string_growable(r, scratch) {
            let _ = dst.try_set(truncate_utf8_safe(scratch[..], dst.cap));
        }
        return;
    }
    if is_json_num_start(c) {
        let v, ok = read_lenient_i64(r);
        if ok {
            var tmp: u8[..32] = [];
            v.format_i64_dec(tmp);
            let _ = dst.try_set(truncate_utf8_safe(tmp[..], dst.cap));
        }
        return;
    }
    skip_json_value_strict(r);
}

// Decodes a JSON array leniently into resizable `E[>..]` `dst`.
//
// Example:
//   r at `["a","b"]`, dst: u8[..16][>..] -> dst.len = 2
fn decode_lenient_tagged<E>(_t: ElemArrTag<E>, dst: E[>..]&, r: json::Reader&) {
    dst.clear();
    guard json::peek(r) == '[' else {
        json::skip(r);
        return;
    }
    json::each_element(r) {
        var el = default<E>();
        el.json_decode_lenient(r);
        if r.error.len == 0 {
            dst.push(el);
        }
    };
}

// Decodes a JSON array leniently into bounded `dst`, skipping excess elements past `dst.cap`.
//
// Example:
//   r at `[{"v":"1"},{"v":"2"}]`, dst: Item[..1] -> dst.len = 1
fn decode_bounded_array_lenient<B, E>(dst: B&, r: json::Reader&) {
    dst.clear();
    guard json::peek(r) == '[' else {
        json::skip(r);
        return;
    }
    json::each_element(r) {
        if dst.len < dst.cap {
            var el = default<E>();
            el.json_decode_lenient(r);
            if r.error.len == 0 {
                dst.push(el);
            }
        } else {
            json::skip(r);
        }
    };
}

fn json_decode_lenient<B>(arr: B&, r: json::Reader&) {
    decode_lenient_tagged(arr_tag(arr[..]), arr, r);
}

struct SeenLenientSpan {
    field_idx: i64 = -1,
    key_off:   i64 = 0,
    key_len:   i64 = 0,
    val_start: i64 = 0,
    val_end:   i64 = 0,
}

fn check_lenient_member_conflict(
    text:      const u8[:],
    seen:      SeenLenientSpan[>..]&,
    key_blob:  u8[>..]&,
    field_idx: i64,
    key:       const u8[:],
    val_start: i64,
    val_end:   i64,
) -> bool {
    let cur_val = core::trim_ascii_space(text[val_start..val_end]);
    for &s in seen {
        let same_target = if field_idx >= 0 {
            s.field_idx == field_idx
        } else {
            s.field_idx < 0 && s.key_len == key.len &&
                key_blob[s.key_off..s.key_off + s.key_len] == key
        };
        if same_target {
            let prev_val = core::trim_ascii_space(text[s.val_start..s.val_end]);
            guard prev_val == cur_val else { return false; }
        }
    }
    let k_off = key_blob.len;
    key_blob.append(key);
    seen.push(SeenLenientSpan {
        field_idx: field_idx,
        key_off:   k_off,
        key_len:   key.len,
        val_start: val_start,
        val_end:   val_end,
    });
    return true;
}

// Decodes a JSON object leniently into `out` via `const for` reflection.
// Matches keys case- and underscore-insensitively, unescapes keys, and rejects conflicting duplicates.
//
// Example:
//   r at `{"Discipline":"Math","Items":null}` -> out.discipline = "Math", out.items = []
fn decode_json_struct_lenient<T>(out: T&, r: json::Reader&) {
    guard json::peek(r) == '{' else {
        skip_json_value_strict(r);
        return;
    }
    var has_more, ok_b = json_obj_begin(r);
    guard ok_b && has_more else { return; }
    var key_buf:  u8[>..]              = [];
    var key_blob: u8[>..]              = [];
    var seen:     SeenLenientSpan[>..] = [];
    loop {
        key_buf.clear();
        guard json_obj_read_key(r, key_buf) else { return; }
        let val_start = json::skip_space(r.text, r.pos);
        var matched_idx:  i64 = -1;
        var field_cursor: i64 = 0;
        const for <Name, Acc> in fields<T> {
            if matched_idx < 0 && eq_json_key_loose(key_buf[..], Name) {
                out.Acc.json_decode_lenient(r);
                matched_idx = field_cursor;
            }
            field_cursor += 1;
        }
        if matched_idx < 0 {
            skip_json_value_strict(r);
        }
        guard r.error.len == 0 else { return; }
        let val_end = r.pos;
        guard check_lenient_member_conflict(
            r.text, seen, key_blob, matched_idx, key_buf[..], val_start, val_end,
        ) else {
            json::fail(r, "conflicting duplicate key");
            return;
        }
        let more, ok_n = json_obj_next_or_end(r);
        guard ok_n && more else { return; }
    }
}

// Leniently decodes a JSON document `raw` into `out`, rolling back `out` on syntax error.
//
// Example:
//   raw = "[{\"TypeWork\":null,\"Semester\":5}]" -> out.len = 1, returns true
fn from_json_lenient<T>(raw: const u8[:], out: T&) -> bool {
    guard raw.len > 0 && prevalidate_json_document(raw) else { return false; }
    let saved = copy(out);
    var committed = false;
    defer if !committed { out = copy(saved); };
    var r = json::reader(raw);
    out.json_decode_lenient(r);
    guard json::finish(r) else { return false; }
    committed = true;
    return true;
}

// ---- Auto-comma streaming JsonWriter ---------------------------------------

struct JsonWriter {
    out:        u8[>..]&,
    depth:      i64      = 0,
    need_comma: bool[16] = [false; 16],
}

fn json_writer(out: u8[>..]&) -> JsonWriter {
    out.clear();
    return JsonWriter { out: out, .. };
}

inline fn jw_comma(w: JsonWriter&) {
    guard w.depth > 0 && w.depth <= 16 else { return; }
    let idx = core::sub_sat_i64(w.depth, 1);
    if w.need_comma[idx] {
        w.out.push(',');
    } else {
        w.need_comma[idx] = true;
    }
}

inline fn jw_push_depth(w: JsonWriter&) {
    if w.depth >= 0 && w.depth < 16 {
        w.need_comma[w.depth] = false;
    }
    w.depth = core::add_sat_i64(w.depth, 1);
}

fn begin_obj(w: JsonWriter&) {
    jw_comma(w);
    w.out.push('{');
    jw_push_depth(w);
}

fn end_obj(w: JsonWriter&) {
    if w.depth > 0 { w.depth = core::sub_sat_i64(w.depth, 1); }
    w.out.push('}');
}

fn begin_arr(w: JsonWriter&) {
    jw_comma(w);
    w.out.push('[');
    jw_push_depth(w);
}

fn end_arr(w: JsonWriter&) {
    if w.depth > 0 { w.depth = core::sub_sat_i64(w.depth, 1); }
    w.out.push(']');
}

fn key_obj(w: JsonWriter&, key: const u8[:]) {
    jw_comma(w);
    json::format_key(w.out, key);
    w.out.push('{');
    jw_push_depth(w);
}

fn key_arr(w: JsonWriter&, key: const u8[:]) {
    jw_comma(w);
    json::format_key(w.out, key);
    w.out.push('[');
    jw_push_depth(w);
}

fn field_str(w: JsonWriter&, key: const u8[:], val: const u8[:]) {
    jw_comma(w);
    json::format_key(w.out, key);
    json::format_string(w.out, val);
}

fn field_str_ne(w: JsonWriter&, key: const u8[:], val: const u8[:]) {
    if val.len > 0 { field_str(w, key, val); }
}

fn field_i64(w: JsonWriter&, key: const u8[:], val: i64) {
    jw_comma(w);
    json::format_key(w.out, key);
    json::format_int(w.out, val);
}

fn field_i64_pos(w: JsonWriter&, key: const u8[:], val: i64) {
    if val > 0 { field_i64(w, key, val); }
}

fn field_bool(w: JsonWriter&, key: const u8[:], val: bool) {
    jw_comma(w);
    json::format_key(w.out, key);
    json::format_bool(w.out, val);
}

fn field_bool_true(w: JsonWriter&, key: const u8[:], val: bool) {
    if val { field_bool(w, key, true); }
}

fn raw_value(w: JsonWriter&, raw_json: const u8[:]) {
    jw_comma(w);
    w.out.append(raw_json);
}
