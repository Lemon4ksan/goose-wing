// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Internal helpers for JA4/JA4H, Akamai HTTP/2, and p0f v3 fingerprint codecs.
namespace fingerprint_internal;

import std;
import core from "..";
import http2.framing;
import .types;

// ---- JA4 & JA4H Internal Helpers -------------------------------------------

// Filters out RFC 8701 GREASE values from a slice of 16-bit values into out.
fn filter_grease_u16(vals: const u16[:], out: u16[>..]&) {
    for v in vals {
        if !rfc::is_grease_u16(v) {
            out.push(v);
        }
    }
}

// In-place insertion sort for 16-bit values (deterministic, zero-heap).
fn sort_u16(arr: u16[>..]&) {
    if arr.len <= 1 { return; }
    for i in 1..arr.len {
        let key = arr[i];
        var j = core::sub_sat_i64(i, 1);
        while j >= 0 && arr[j] > key {
            arr[core::add_sat_i64(j, 1)] = arr[j];
            j = core::sub_sat_i64(j, 1);
        }
        arr[core::add_sat_i64(j, 1)] = key;
    }
}

fn append_hex4<B>(val: u16, out: B&) {
    let hi = (val >> 8) as u8;
    let lo = (val & 0xFF) as u8;
    hi.format_u8_hex(out, false);
    lo.format_u8_hex(out, false);
}

fn append_hex4_csv<B>(vals: const u16[:], out: B&) {
    for i in vals.len {
        if i > 0 { out.push(','); }
        append_hex4(vals[i], out);
    }
}

fn append_two_digits<B>(n: i64, out: B&) {
    let d = min(max(n, 0), 99);
    let idx = core::add_sat_i64(d, d);
    let next_idx = core::add_sat_i64(idx, 1);
    guard idx >= 0 && next_idx < 200 else { return; }
    out.push(core::DIGITS_LUT[idx]);
    out.push(core::DIGITS_LUT[next_idx]);
}

// Produces first 12 hex characters of SHA-256 (FoxIO 12-char hash truncation).
fn hash_12_hex<B>(data: const u8[:], out: B&) {
    if data.len == 0 {
        out.append("000000000000");
        return;
    }
    let sum = core::sha256(data);
    for i in 6 {
        sum[i].format_u8_hex(out, false);
    }
}

inline fn ja4_version_rank(v: u16) -> i32 {
    if v == 0x0304 || v == 0xFEFC { return 6; }
    if v == 0x0303 || v == 0xFEFD { return 5; }
    if v == 0x0302 { return 4; }
    if v == 0x0301 || v == 0xFEFF { return 3; }
    if v == 0x0300 { return 2; }
    if v == 0x0002 { return 1; }
    return 0;
}

// Maps highest supported TLS/DTLS version to 2-character JA4 code.
fn ja4_version_string(supported_versions: const u16[:]) -> const u8[:] {
    var best_ver:  u16 = 0;
    var best_rank: i32 = 0;
    for v in supported_versions {
        if !rfc::is_grease_u16(v) {
            let r = ja4_version_rank(v);
            if r > best_rank {
                best_rank = r;
                best_ver = v;
            }
        }
    }
    if best_ver == 0x0304 { return "13"; } // TLS 1.3
    if best_ver == 0x0303 { return "12"; } // TLS 1.2
    if best_ver == 0x0302 { return "11"; } // TLS 1.1
    if best_ver == 0x0301 { return "10"; } // TLS 1.0
    if best_ver == 0x0300 { return "s3"; } // SSL 3.0
    if best_ver == 0x0002 { return "s2"; } // SSL 2.0
    if best_ver == 0xFEFC { return "d3"; } // DTLS 1.3
    if best_ver == 0xFEFD { return "d2"; } // DTLS 1.2
    if best_ver == 0xFEFF { return "d1"; } // DTLS 1.0
    return "00";
}

// Extracts 2-character ALPN code, falling back to nibble hex when non-alphanumeric.
fn ja4_alpn_string<B>(alpn_protocol: const u8[:], out: B&) {
    let head, _, has_comma = alpn_protocol.split_once_byte(',');
    let first_proto = if has_comma { head } else { alpn_protocol };
    guard first_proto.len > 0 else {
        out.append("00");
        return;
    }
    let b_first = first_proto[0];
    let b_last = first_proto[core::sub_sat_i64(first_proto.len, 1)];

    if core::is_ascii_alphanumeric(b_first) && core::is_ascii_alphanumeric(b_last) {
        out.push(b_first);
        out.push(b_last);
    } else {
        let combined = (b_first & 0xF0) | (b_last & 0x0F);
        combined.format_u8_hex(out, false);
    }
}

fn append_ja4_ciphers_hash<B>(filtered_ciphers: u16[>..]&, out: B&) {
    if filtered_ciphers.len == 0 {
        out.append("000000000000");
        return;
    }
    sort_u16(filtered_ciphers);
    var cipher_buf: u8[>..] = [];
    append_hex4_csv(filtered_ciphers[..], cipher_buf);
    hash_12_hex(cipher_buf[..], out);
}

fn append_ja4_extensions_hash<B>(
    filtered_exts:  const u16[:],
    sig_algorithms: const u16[:],
    out:            B&,
) {
    var hash_exts: u16[>..] = [];
    for e in filtered_exts {
        if e != 0x0000 && e != 0x0010 { // Exclude SNI and ALPN per JA4 standard
            hash_exts.push(e);
        }
    }

    var filtered_sigs: u16[>..] = [];
    filter_grease_u16(sig_algorithms, filtered_sigs);

    if hash_exts.len == 0 && filtered_sigs.len == 0 {
        out.append("000000000000");
        return;
    }
    sort_u16(hash_exts);
    var ext_buf: u8[>..] = [];
    append_hex4_csv(hash_exts[..], ext_buf);
    if filtered_sigs.len > 0 {
        if hash_exts.len > 0 {
            ext_buf.push('_');
        }
        append_hex4_csv(filtered_sigs[..], ext_buf);
    }
    hash_12_hex(ext_buf[..], out);
}

fn is_bytes_less(a: const u8[:], b: const u8[:]) -> bool {
    let min_len = min(a.len, b.len);
    for i in min_len {
        if a[i] != b[i] {
            return a[i] < b[i];
        }
    }
    return a.len < b.len;
}

fn is_cookie_pair_less(
    names:  const u8[:][:],
    values: const u8[:][:],
    a_idx:  i64,
    b_idx:  i64,
) -> bool {
    if names[a_idx] != names[b_idx] {
        return is_bytes_less(names[a_idx], names[b_idx]);
    }
    let val_a = if a_idx < values.len { values[a_idx] } else { "" };
    let val_b = if b_idx < values.len { values[b_idx] } else { "" };
    return is_bytes_less(val_a, val_b);
}

fn sort_cookie_indices(
    names:  const u8[:][:],
    values: const u8[:][:],
    order:  i64[>..]&,
) {
    if order.len <= 1 { return; }
    for i in 1..order.len {
        let key_idx = order[i];
        var j = core::sub_sat_i64(i, 1);
        while j >= 0 && is_cookie_pair_less(names, values, key_idx, order[j]) {
            order[core::add_sat_i64(j, 1)] = order[j];
            j = core::sub_sat_i64(j, 1);
        }
        order[core::add_sat_i64(j, 1)] = key_idx;
    }
}

fn append_ja4h_language<B>(accept_lang: const u8[:], out: B&) {
    guard accept_lang.len > 0 else {
        out.append("0000");
        return;
    }
    var count: u64 = 0;
    for b in accept_lang {
        if count == 4 || b == ',' || b == ';' { break; }
        if core::is_ascii_alphanumeric(b) {
            out.push(core::to_lower_ascii_byte(b));
            count = core::add_sat_u64(count, 1);
        }
    }
    while count < 4 {
        out.push('0');
        count = core::add_sat_u64(count, 1);
    }
}

fn append_ja4h_headers_hash<B>(filtered_headers: const u8[:][:], out: B&) {
    if filtered_headers.len == 0 {
        out.append("000000000000");
        return;
    }
    var hbuf: u8[>..] = [];
    for i in filtered_headers.len {
        if i > 0 { hbuf.push(','); }
        filtered_headers[i].to_lower_ascii(hbuf);
    }
    hash_12_hex(hbuf[..], out);
}

fn append_ja4h_cookies_hash<B>(
    cookie_names:  const u8[:][:],
    cookie_values: const u8[:][:],
    out:           B&,
) {
    if cookie_names.len == 0 {
        out.append("000000000000_000000000000");
        return;
    }
    var order: i64[>..] = [];
    for i in cookie_names.len { order.push(i); }
    sort_cookie_indices(cookie_names, cookie_values, order);

    var cbuf: u8[>..] = [];
    for i in order.len {
        if i > 0 { cbuf.push(','); }
        cbuf.append(cookie_names[order[i]]);
    }
    hash_12_hex(cbuf[..], out);

    out.push('_');

    var vbuf: u8[>..] = [];
    for i in order.len {
        if i > 0 { vbuf.push(','); }
        let idx = order[i];
        vbuf.append(cookie_names[idx]);
        vbuf.push('=');
        if idx < cookie_values.len {
            vbuf.append(cookie_values[idx]);
        }
    }
    hash_12_hex(vbuf[..], out);
}

inline fn ja4h_proto_string(proto: const u8[:]) -> const u8[:] {
    if proto.eq_ascii_fold("HTTP/1.0") || proto == "1.0" { return "10"; }
    if proto.eq_ascii_fold("HTTP/1.1") || proto == "1.1" { return "11"; }
    let is_h2 = proto.eq_ascii_fold("HTTP/2") || proto.eq_ascii_fold("HTTP/2.0") || proto.eq_ascii_fold("h2");
    if is_h2 || proto == "2" || proto == "2.0" {
        return "20";
    }
    let is_h3 = proto.eq_ascii_fold("HTTP/3") || proto.eq_ascii_fold("HTTP/3.0") || proto.eq_ascii_fold("h3");
    if is_h3 || proto == "3" || proto == "3.0" {
        return "30";
    }
    return "00";
}

fn filter_ja4h_headers(
    header_names: const u8[:][:],
    flags:        fingerprint::Ja4hFlags,
    has_cookies:  bool,
) -> const u8[:][>..], fingerprint::Ja4hFlags {
    var out_headers: const u8[:][>..] = [];
    var res = fingerprint::Ja4hFlags {
        has_cookie:  flags.has_cookie || has_cookies,
        has_referer: flags.has_referer,
    };
    for h in header_names {
        if h.len == 0 || h[0] == ':' {
            continue;
        }
        if h.eq_ascii_fold("cookie") {
            res.has_cookie = true;
            continue;
        }
        if h.eq_ascii_fold("referer") {
            res.has_referer = true;
            continue;
        }
        out_headers.push(h);
    }
    return out_headers, res;
}

// ---- Akamai HTTP/2 Internal Helpers ----------------------------------------

const H2_MAX_STREAM_ID: u32 = 0x7FFFFFFF; // RFC 9113 Section 4.1 (31-bit stream identifier)

fn format_akamai_settings<B>(settings: const fingerprint::AkamaiSetting[:], out: B&) {
    for i in settings.len {
        if i > 0 {
            out.push(';');
        }
        settings[i].id.format_u32_dec(out);
        out.push(':');
        settings[i].val.format_u32_dec(out);
    }
}

fn format_akamai_priority<B>(priority: const fingerprint::AkamaiPriorityFrame[:], out: B&) {
    guard priority.len > 0 else {
        out.push('0');
        return;
    }
    for i in priority.len {
        if i > 0 {
            out.push(',');
        }
        priority[i].stream_id.format_u32_dec(out);
        out.push(':');
        priority[i].exclusive.format_u32_dec(out);
        out.push(':');
        priority[i].dep_stream_id.format_u32_dec(out);
        out.push(':');
        priority[i].weight.format_u32_dec(out);
    }
}

fn format_akamai_pseudo_headers<B>(pseudos: const u8[:], out: B&) {
    for i in pseudos.len {
        if i > 0 {
            out.push(',');
        }
        out.push(pseudos[i]);
    }
}

inline fn pseudo_header_bit(b: u8) -> u8 {
    if b == 'm' { return 1; }
    if b == 'a' { return 2; }
    if b == 's' { return 4; }
    if b == 'p' { return 8; }
    return 0;
}

// Parses a single Akamai priority token `stream_id:exclusive:dep_stream_id:weight` (RFC 7540 §6.3).
//
// Example:
//   token = "3:0:0:201"
//   returns: AkamaiPriorityFrame { stream_id: 3, exclusive: 0, dep_stream_id: 0, weight: 201 }, ok = true
fn parse_priority_token(token: const u8[:]) -> fingerprint::AkamaiPriorityFrame, bool {
    var dummy = fingerprint::AkamaiPriorityFrame { .. };
    let s_str, rem1, ok_c1 = token.split_once_byte(':');
    guard ok_c1 else { return dummy, false; }
    let excl_str, rem2, ok_c2 = rem1.split_once_byte(':');
    guard ok_c2 else { return dummy, false; }
    let dep_str, w_str, ok_c3 = rem2.split_once_byte(':');
    guard ok_c3 else { return dummy, false; }

    let s_id, ok1 = s_str.parse_u32_dec();
    let excl, ok2 = excl_str.parse_u32_dec();
    let dep, ok3 = dep_str.parse_u32_dec();
    let w, ok4 = w_str.parse_u32_dec();
    guard ok1 && ok2 && ok3 && ok4 && excl <= 1 && w >= 1 && w <= 256 else { return dummy, false; }
    guard s_id > 0 && s_id <= H2_MAX_STREAM_ID && dep <= H2_MAX_STREAM_ID && s_id != dep else { return dummy, false; }

    return fingerprint::AkamaiPriorityFrame {
        stream_id:     s_id,
        exclusive:     excl as u8,
        dep_stream_id: dep,
        weight:        w as u16,
    }, true;
}

// Parses a single key-value setting pair (e.g. 1:65536) in an Akamai fingerprint.
//
// Example:
//   token = "1:65536"
//   returns: AkamaiSetting { id: 1, val: 65536 }, ok = true
fn parse_akamai_setting_token(token: const u8[:]) -> fingerprint::AkamaiSetting, bool {
    var dummy = fingerprint::AkamaiSetting { id: 0, val: 0 };
    let id_str, val_str, has_colon = token.split_once_byte(':');
    guard has_colon else { return dummy, false; }
    let id_val, ok_id = id_str.parse_u32_dec();
    let val_val, ok_val = val_str.parse_u32_dec();
    guard ok_id && ok_val && id_val <= 0xFFFF else { return dummy, false; }
    return fingerprint::AkamaiSetting { id: id_val as u16, val: val_val }, true;
}

// Parses semicolon-separated HTTP/2 settings in an Akamai fingerprint section.
//
// Example:
//   settings_part = "1:65536;2:0"
//   appends: parsed settings to fp.settings, returns: true
fn parse_akamai_settings(settings_part: const u8[:], fp: fingerprint::AkamaiFingerprint&) -> bool {
    guard settings_part.len > 0 else { return true; }
    let saved_len = fp.settings.len;
    var committed = false;
    defer if !committed { fp.settings.resize(saved_len); };

    var tok = core::make_byte_tokenizer(settings_part, ';');
    while true {
        let item, has_more = core::token_next(tok);
        guard has_more else { break; }
        let setting, ok = parse_akamai_setting_token(item);
        guard ok && fp.settings.try_push(setting) else { return false; }
    }
    committed = true;
    return true;
}

// Parses comma-separated priority stream frames in an Akamai fingerprint section.
//
// Example:
//   prio_part = "3:0:0:201,5:0:0:101"
//   appends: parsed frames to fp.priority_frames, returns: true
fn parse_akamai_priorities(prio_part: const u8[:], fp: fingerprint::AkamaiFingerprint&) -> bool {
    guard prio_part.len > 0 && prio_part != "0" else { return true; }
    let saved_len = fp.priority_frames.len;
    var committed = false;
    defer if !committed { fp.priority_frames.resize(saved_len); };

    var tok = core::make_byte_tokenizer(prio_part, ',');
    while true {
        let item, has_more = core::token_next(tok);
        guard has_more else { break; }
        let frame, ok = parse_priority_token(item);
        guard ok && fp.priority_frames.try_push(frame) else { return false; }
    }
    committed = true;
    return true;
}

// Parses comma-separated pseudo-header letters into `out_pseudos`.
//
// Example:
//   pseudo_part = "m,a,s,p"
//   appends: ['m', 'a', 's', 'p'] to out_pseudos, returns: true
fn parse_akamai_pseudo_headers(pseudo_part: const u8[:], out_pseudos: u8[..8]&) -> bool {
    guard pseudo_part.len > 0 else { return false; }
    let saved_len = out_pseudos.len;
    var committed = false;
    defer if !committed { out_pseudos.resize(saved_len); };

    var expect_char = true;
    var seen_mask: u8 = 0;
    for b in pseudo_part {
        if b == ' ' {
            continue;
        }
        if b == ',' {
            guard !expect_char else { return false; }
            expect_char = true;
            continue;
        }
        let bit = pseudo_header_bit(b);
        guard expect_char && bit != 0 && (seen_mask & bit) == 0 else { return false; }
        guard out_pseudos.try_push(b) else { return false; }
        seen_mask = seen_mask | bit;
        expect_char = false;
    }
    guard !expect_char && (seen_mask & 1) != 0 else { return false; }
    committed = true;
    return true;
}

inline fn has_setting_value(settings: const fingerprint::AkamaiSetting[:], id: u16, val: u32) -> bool {
    for &s in settings {
        if s.id == id && s.val == val {
            return true;
        }
    }
    return false;
}

inline fn has_all_four_pseudo_headers(pseudos: const u8[:]) -> bool {
    guard pseudos.len == 4 else { return false; }
    var mask: u8 = 0;
    for b in pseudos {
        mask = mask | pseudo_header_bit(b);
    }
    return mask == 0x0F;
}

fn process_akamai_settings_frame(
    hdr:     const h2_internal::FrameHeader&,
    payload: const u8[:],
    fp:      fingerprint::AkamaiFingerprint&,
) -> bool {
    let is_settings_frame = hdr.stream_id == 0 && (hdr.flags & rfc::H2_FLAG_ACK) == 0;
    guard is_settings_frame && payload.len == hdr.length else {
        return false;
    }
    let saved_len = fp.settings.len;
    var committed = false;
    defer if !committed { fp.settings.resize(saved_len); };

    var cur = core::cursor_from(payload);
    while cur.cursor_len() >= 6 {
        let s_id, ok_id = cur.read_u16();
        let s_val, ok_val = cur.read_u32();
        guard ok_id && ok_val && fp.settings.try_push(fingerprint::AkamaiSetting { id: s_id, val: s_val }) else {
            return false;
        }
    }
    guard cur.cursor_len() == 0 else {
        return false;
    }
    committed = true;
    return true;
}

fn process_akamai_priority_frame(
    hdr:     const h2_internal::FrameHeader&,
    payload: const u8[:],
    fp:      fingerprint::AkamaiFingerprint&,
) -> bool {
    guard hdr.stream_id > 0 && hdr.length == 5 && payload.len == 5 else {
        return false;
    }
    var cur = core::cursor_from(payload);
    let raw_dep, ok_dep = cur.read_u32();
    let raw_weight, ok_w = cur.read_u8();
    guard ok_dep && ok_w else { return false; }
    let exclusive = ((raw_dep >> 31) & 1) as u8;
    let dep_id = raw_dep & H2_MAX_STREAM_ID;
    let weight = core::add_sat_u64(raw_weight, 1) as u16;
    guard hdr.stream_id != dep_id else {
        return false;
    }
    return fp.priority_frames.try_push(fingerprint::AkamaiPriorityFrame {
        stream_id:     hdr.stream_id,
        exclusive:     exclusive,
        dep_stream_id: dep_id,
        weight:        weight,
    });
}

fn process_akamai_wire_frame(
    hdr:            const h2_internal::FrameHeader&,
    payload:        const u8[:],
    fp:             fingerprint::AkamaiFingerprint&,
    found_settings: bool&,
) -> bool {
    if hdr.frame_type == rfc::H2_FRAME_SETTINGS && hdr.stream_id == 0 && (hdr.flags & rfc::H2_FLAG_ACK) == 0 {
        found_settings = true;
        return process_akamai_settings_frame(hdr, payload, fp);
    }
    if hdr.frame_type == rfc::H2_FRAME_WINDOW_UPDATE && hdr.stream_id == 0 && hdr.length == 4 {
        var wu_cur = core::cursor_from(payload);
        let raw_inc, ok_inc = wu_cur.read_u32();
        let inc = raw_inc & H2_MAX_STREAM_ID;
        guard ok_inc && inc > 0 else { return false; }
        fp.window_update = inc;
        return true;
    }
    if hdr.frame_type == rfc::H2_FRAME_PRIORITY && hdr.length == 5 {
        return process_akamai_priority_frame(hdr, payload, fp);
    }
    return true;
}

enum AkamaiWireStep {
    Continue,
    StopAtRequest,
    Invalid,
}

// Advances `cur` past one HTTP/2 handshake frame, stopping before request HEADERS or DATA.
fn step_akamai_wire_frame(
    cur:            core::ByteCursor&,
    fp:             fingerprint::AkamaiFingerprint&,
    found_settings: bool&,
) -> AkamaiWireStep {
    let hdr, err = h2_internal::parse_frame_header(cur.buf);
    if err != rfc::H2_ERR_NO_ERROR || h2_internal::validate_frame_header_rules(hdr) != rfc::H2_ERR_NO_ERROR {
        return AkamaiWireStep.Invalid;
    }
    if hdr.frame_type == rfc::H2_FRAME_HEADERS || hdr.frame_type == rfc::H2_FRAME_DATA {
        return AkamaiWireStep.StopAtRequest;
    }
    let frame_total_len = core::add_sat_i64(rfc::H2_FRAME_HEADER_LEN, hdr.length);
    guard cur.cursor_len() >= frame_total_len else { return AkamaiWireStep.Invalid; }

    let _, _ = cur.read_bytes(rfc::H2_FRAME_HEADER_LEN);
    let payload, ok_pay = cur.read_bytes(hdr.length);
    guard ok_pay && process_akamai_wire_frame(hdr, payload, fp, found_settings) else {
        return AkamaiWireStep.Invalid;
    }
    return AkamaiWireStep.Continue;
}

inline fn is_valid_akamai_wire_setting(s: const fingerprint::AkamaiSetting&) -> bool {
    return h2_internal::validate_settings_parameter(s.id, s.val, false) == rfc::H2_ERR_NO_ERROR;
}

inline fn try_append_frame_header<B>(hdr: const h2_internal::FrameHeader&, out: B&) -> bool {
    var raw: u8[9] = [0; 9];
    h2_internal::encode_frame_header(hdr, raw);
    return out.try_append(raw[..]);
}

inline fn try_append_u16_be_buf<B>(val: u16, out: B&) -> bool {
    var raw: u8[2] = [((val >> 8) & 0xFF) as u8, (val & 0xFF) as u8];
    return out.try_append(raw[..]);
}

inline fn try_append_u32_be_buf<B>(val: u32, out: B&) -> bool {
    var raw: u8[4] = [0; 4];
    core::write_be_u32_at(raw[..], 0, val);
    return out.try_append(raw[..]);
}

fn try_encode_akamai_settings_frame<B>(settings: const fingerprint::AkamaiSetting[:], out: B&) -> bool {
    var valid_settings: u64 = 0;
    for &s in settings {
        if is_valid_akamai_wire_setting(s) {
            valid_settings = core::add_sat_u64(valid_settings, 1);
        }
    }
    let settings_hdr = h2_internal::FrameHeader {
        length:     core::mul_sat_u64(valid_settings, 6) as u32,
        frame_type: rfc::H2_FRAME_SETTINGS,
        flags:      0,
        stream_id:  0,
    };
    guard try_append_frame_header(settings_hdr, out) else { return false; }
    for &s in settings {
        if is_valid_akamai_wire_setting(s) {
            guard try_append_u16_be_buf(s.id, out) && try_append_u32_be_buf(s.val, out) else { return false; }
        }
    }
    return true;
}

fn try_append_priority_frame<B>(p: const fingerprint::AkamaiPriorityFrame&, out: B&) -> bool {
    let sid = p.stream_id & H2_MAX_STREAM_ID;
    let dep_id = p.dep_stream_id & H2_MAX_STREAM_ID;
    if sid == 0 || sid == dep_id {
        return true;
    }
    let p_hdr = h2_internal::FrameHeader {
        length:     5,
        frame_type: rfc::H2_FRAME_PRIORITY,
        flags:      0,
        stream_id:  sid,
    };
    let excl_bit: u32 = if (p.exclusive & 1) != 0 { 0x80000000 } else { 0 };
    let dep = dep_id | excl_bit;
    let w_clamped = min(max(p.weight as u64, 1), 256);
    let w_val = core::sub_sat_u64(w_clamped, 1);
    guard w_val <= 255 else { return false; }
    let w_byte = w_val as u8;
    return try_append_frame_header(p_hdr, out)
        && try_append_u32_be_buf(dep, out)
        && out.try_push(w_byte);
}

// ---- p0f v3 Internal Helpers -----------------------------------------------

const P0F_QUIRK_NAMES: const u8[:][17] = [
    "df", "id+", "id-", "ecn", "0+", "flow", "seq-", "ack+",
    "ack-", "uptr+", "urgf+", "pushf+", "ts1-", "ts2+", "opt+", "expt", "bad",
];

fn quirk_index(name: const u8[:]) -> i64, bool {
    for i in 17 {
        if name == P0F_QUIRK_NAMES[i] {
            return i, true;
        }
    }
    return 0, false;
}

fn quirks_flags(q: const fingerprint::P0fQuirks&) -> bool[17] {
    return [
        q.df, q.id_plus, q.id_minus, q.ecn, q.zero_plus, q.flow,
        q.seq_minus, q.ack_plus, q.ack_minus, q.uptr_plus, q.urgf_plus,
        q.pushf_plus, q.ts1_minus, q.ts2_plus, q.opt_plus, q.expt, q.bad,
    ];
}

fn append_p0f_options<B>(options: const fingerprint::P0fTcpOption[:], out: B&) {
    for idx in options.len {
        if idx > 0 { out.push(','); }
        match options[idx] {
            Eol => out.append("eol"),
            Nop => out.append("nop"),
            Mss => out.append("mss"),
            Ws => out.append("ws"),
            Sok => out.append("sok"),
            Sack => out.append("sack"),
            Ts => out.append("ts"),
            Unknown => out.append("dat"),
        }
    }
}

fn append_p0f_window<B>(sig: const fingerprint::P0fSignature&, out: B&) {
    match sig.window_type {
        Any => {
            out.append("*,");
            sig.window_scale.format_i64_dec(out);
        },
        Mss => {
            out.append("mss*");
            sig.window_size.format_i64_dec(out);
            out.push(',');
            sig.window_scale.format_i64_dec(out);
        },
        Mtu => {
            out.append("mtu*");
            sig.window_size.format_i64_dec(out);
            out.push(',');
            sig.window_scale.format_i64_dec(out);
        },
        Mod => {
            out.append("mod*");
            sig.window_size.format_i64_dec(out);
            out.push(',');
            sig.window_scale.format_i64_dec(out);
        },
        Normal => {
            sig.window_size.format_i64_dec(out);
            out.push(',');
            sig.window_scale.format_i64_dec(out);
        },
    }
}

fn append_p0f_quirks<B>(q: const fingerprint::P0fQuirks&, out: B&) {
    let flags = quirks_flags(q);
    var first = true;
    for i in 17 {
        if flags[i] {
            if !first { out.push(','); }
            out.append(P0F_QUIRK_NAMES[i]);
            first = false;
        }
    }
}

// Extracts colon delimiter offsets across an 8-field p0f signature.
//
// Example:
//   raw = "4:64:0:1460:mss*10,0:mss,sok:df:0"
//   returns: ok = true, colons = [1, 4, 6, 11, 20, 28, 31]
fn parse_p0f_colons(raw: const u8[:], colons: i64[..8]&) -> bool {
    let saved_len = colons.len;
    var committed = false;
    defer if !committed { colons.resize(saved_len); };

    for i in raw.len {
        if raw[i] == ':' {
            guard colons.try_push(i) else { return false; }
        }
    }
    guard colons.len == 7 else { return false; }
    committed = true;
    return true;
}

// Parses the TCP window size token (before ',') of a p0f v3 signature.
//
// Example:
//   ws_str = "mss*10"
//   returns: P0fWindowType.Mss, 10, true
fn parse_p0f_window_size(ws_str: const u8[:]) -> fingerprint::P0fWindowType, i32, bool {
    if ws_str == "*" {
        return fingerprint::P0fWindowType.Any, -1, true;
    }
    var wtype = fingerprint::P0fWindowType.Normal;
    var num_str = ws_str;
    var min_val: i64 = 0;

    let r_mss, is_mss = ws_str.strip_prefix("mss*");
    let r_mtu, is_mtu = ws_str.strip_prefix("mtu*");
    let r_mod, is_mod = ws_str.strip_prefix("mod*");
    let r_pct, is_pct = ws_str.strip_prefix("%");

    if is_mss {
        wtype = fingerprint::P0fWindowType.Mss;
        num_str = r_mss;
    } else if is_mtu {
        wtype = fingerprint::P0fWindowType.Mtu;
        num_str = r_mtu;
    } else if is_mod {
        wtype = fingerprint::P0fWindowType.Mod;
        num_str = r_mod;
        min_val = 1;
    } else if is_pct {
        wtype = fingerprint::P0fWindowType.Mod;
        num_str = r_pct;
        min_val = 1;
    }

    let val, ok = num_str.parse_i64_dec();
    guard ok && val >= min_val && val <= 65535 else {
        return fingerprint::P0fWindowType.Normal, 0, false;
    }
    return wtype, val as i32, true;
}

// Parses TCP window size and scale specifications (f4).
//
// Example:
//   f4 = "mss*10,0"
//   returns: ok = true, sig.window_type = Mss, sig.window_scale = 0
fn parse_p0f_window(f4: const u8[:], sig: fingerprint::P0fSignature&) -> bool {
    if f4 == "*,-1" || f4 == "*,*" {
        sig.window_type = fingerprint::P0fWindowType.Any;
        sig.window_size = -1;
        sig.window_scale = -1;
        return true;
    }
    let ws_str, scale_str, has_comma = f4.split_once_byte(',');
    guard has_comma else { return false; }

    if scale_str == "*" || scale_str == "-1" {
        sig.window_scale = -1;
    } else {
        let sc_val, sc_ok = scale_str.parse_i64_dec();
        guard sc_ok && sc_val >= -1 && sc_val <= 14 else { return false; }
        sig.window_scale = sc_val as i16;
    }

    let wtype, wsize, ok_ws = parse_p0f_window_size(ws_str);
    guard ok_ws else { return false; }
    sig.window_type = wtype;
    sig.window_size = wsize;
    return true;
}

fn push_parsed_option(sig: fingerprint::P0fSignature&, token: const u8[:]) -> bool {
    guard token.len > 0 else { return false; }
    var opt = fingerprint::P0fTcpOption.Unknown;
    let eol_pad, is_eol_pad = token.strip_prefix("eol+");
    if token == "eol" {
        opt = fingerprint::P0fTcpOption.Eol;
    } else if is_eol_pad {
        let pad_val, pad_ok = eol_pad.parse_i64_dec();
        guard pad_ok && pad_val >= 0 && pad_val <= 255 else { return false; }
        opt = fingerprint::P0fTcpOption.Eol;
    } else if token == "nop" {
        opt = fingerprint::P0fTcpOption.Nop;
    } else if token == "mss" {
        opt = fingerprint::P0fTcpOption.Mss;
    } else if token == "ws" {
        opt = fingerprint::P0fTcpOption.Ws;
    } else if token == "sok" {
        opt = fingerprint::P0fTcpOption.Sok;
    } else if token == "sack" {
        opt = fingerprint::P0fTcpOption.Sack;
    } else if token == "ts" {
        opt = fingerprint::P0fTcpOption.Ts;
    }
    return sig.options.try_push(opt);
}

// Parses comma-separated TCP options into signature option array (f5).
//
// Example:
//   f5 = "mss,sok,ts,nop,ws"
//   populates sig.options with corresponding P0fTcpOption entries
fn parse_p0f_options_field(f5: const u8[:], sig: fingerprint::P0fSignature&) -> bool {
    guard f5.len > 0 else { return true; }
    let saved_len = sig.options.len;
    var committed = false;
    defer if !committed { sig.options.resize(saved_len); };

    var tok = core::make_byte_tokenizer(f5, ',');
    while true {
        let token, has_more = core::token_next(tok);
        guard has_more else { break; }
        guard push_parsed_option(sig, token) else { return false; }
    }
    committed = true;
    return true;
}

// Parses comma-separated TCP quirks into signature quirk bitflags (f6).
//
// Example:
//   f6 = "df,id+"
//   populates sig.quirks with bitflags for df and id+
fn parse_p0f_quirks_field(f6: const u8[:], sig: fingerprint::P0fSignature&) -> bool {
    guard f6.len > 0 else { return true; }
    let saved_quirks = sig.quirks;
    var committed = false;
    defer if !committed { sig.quirks = saved_quirks; };

    var tok = core::make_byte_tokenizer(f6, ',');
    while true {
        let token, has_more = core::token_next(tok);
        guard has_more else { break; }
        guard apply_quirk(sig.quirks, token, true) else { return false; }
    }
    committed = true;
    return true;
}

fn apply_quirk(q: fingerprint::P0fQuirks&, name: const u8[:], enabled: bool) -> bool {
    let idx, ok = quirk_index(name);
    guard ok else { return false; }
    match idx {
        0 => { q.df = enabled; },
        1 => { q.id_plus = enabled; },
        2 => { q.id_minus = enabled; },
        3 => { q.ecn = enabled; },
        4 => { q.zero_plus = enabled; },
        5 => { q.flow = enabled; },
        6 => { q.seq_minus = enabled; },
        7 => { q.ack_plus = enabled; },
        8 => { q.ack_minus = enabled; },
        9 => { q.uptr_plus = enabled; },
        10 => { q.urgf_plus = enabled; },
        11 => { q.pushf_plus = enabled; },
        12 => { q.ts1_minus = enabled; },
        13 => { q.ts2_plus = enabled; },
        14 => { q.opt_plus = enabled; },
        15 => { q.expt = enabled; },
        16 => { q.bad = enabled; },
        _ => { return false; },
    }
    return true;
}

// Parses leading p0f v3 header fields (ip_version, ttl, ip_opt_len, mss).
//
// Example:
//   f0 = "4", f1 = "64-", f2 = "0", f3 = "1460"
//   populates sig.ip_version = 4, sig.ttl = 64, sig.has_ttl_minus = true, sig.mss = 1460
fn parse_p0f_header_fields(
    f0:  const u8[:],
    f1:  const u8[:],
    f2:  const u8[:],
    f3:  const u8[:],
    sig: fingerprint::P0fSignature&,
) -> bool {
    if f0 == "4" {
        sig.ip_version = 4;
    } else if f0 == "6" {
        sig.ip_version = 6;
    } else if f0 == "*" {
        sig.ip_version = 0;
    } else {
        return false;
    }

    let ttl_base, has_minus = f1.strip_suffix("-");
    sig.has_ttl_minus = has_minus;
    let ttl_slice = if has_minus { ttl_base } else { f1 };
    let ttl_val, ttl_ok = ttl_slice.parse_u32_dec();
    guard ttl_ok && ttl_val >= 1 && ttl_val <= 255 else { return false; }
    sig.ttl = ttl_val as u8;

    let olen_val, olen_ok = f2.parse_u32_dec();
    guard olen_ok && olen_val <= 255 else { return false; }
    sig.ip_opt_len = olen_val as u8;

    if f3 == "*" {
        sig.mss = -1;
        return true;
    }
    let mss_val, mss_ok = f3.parse_u32_dec();
    guard mss_ok && mss_val <= 65535 else { return false; }
    sig.mss = mss_val as i32;
    return true;
}

fn match_p0f_ttl(actual: const fingerprint::P0fSignature&, target: const fingerprint::P0fSignature&) -> bool {
    guard target.has_ttl_minus else { return actual.ttl == target.ttl; }
    let min_ttl = max(core::sub_sat_u64(target.ttl, 35), 1) as u8;
    return actual.ttl <= target.ttl && actual.ttl >= min_ttl;
}

fn match_p0f_scaled_window(
    actual: const fingerprint::P0fSignature&,
    target: const fingerprint::P0fSignature&,
) -> bool {
    if actual.window_type == target.window_type && actual.window_size == target.window_size {
        return true;
    }
    guard actual.window_type == fingerprint::P0fWindowType.Normal
        && actual.mss > 0
        && actual.window_size >= 0 else {
        return false;
    }
    let is_mtu = target.window_type == fingerprint::P0fWindowType.Mtu;
    let hdr_len: u64 = if !is_mtu { 0 } else if actual.ip_version == 6 { 60 } else { 40 };
    let unit = core::add_sat_u64(actual.mss as u64, hdr_len);
    let prod = core::mul_sat_u64(unit, max(target.window_size, 0) as u64);
    return (actual.window_size as u64) == prod;
}

fn match_p0f_window(actual: const fingerprint::P0fSignature&, target: const fingerprint::P0fSignature&) -> bool {
    match target.window_type {
        Any => { return true; },
        Mss => { return match_p0f_scaled_window(actual, target); },
        Mtu => { return match_p0f_scaled_window(actual, target); },
        Mod => {
            guard actual.window_size >= 0 && target.window_size > 0 else { return false; }
            let _, rem = core::div_rem_u64(actual.window_size as u64, target.window_size as u64);
            return rem == 0;
        },
        Normal => {
            return actual.window_type == fingerprint::P0fWindowType.Normal
                && actual.window_size == target.window_size;
        },
    }
}
