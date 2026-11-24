// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Internal helpers for Akamai HTTP/2 fingerprint codecs and wire framing.
namespace fingerprint_internal;

import std;
import core;
import rfc.h2;
import http2.framing;
import .types;

// ---- Akamai HTTP/2 Internal Helpers ----------------------------------------

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
    guard s_id > 0 && s_id <= rfc::H2_MAX_STREAM_ID &&
        dep <= rfc::H2_MAX_STREAM_ID && s_id != dep else {
        return dummy, false;
    }

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
    hdr:     const http2::FrameHeader&,
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
    hdr:     const http2::FrameHeader&,
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
    let dep_id = raw_dep & rfc::H2_MAX_STREAM_ID;
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
    hdr:            const http2::FrameHeader&,
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
        let inc = raw_inc & rfc::H2_MAX_STREAM_ID;
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
    let hdr, err = http2::parse_frame_header(cur.buf);
    if err != rfc::H2_ERR_NO_ERROR || http2::validate_frame_header_rules(hdr) != rfc::H2_ERR_NO_ERROR {
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
    return http2::validate_settings_parameter(s.id, s.val, false) == rfc::H2_ERR_NO_ERROR;
}

inline fn try_append_frame_header<B>(hdr: const http2::FrameHeader&, out: B&) -> bool {
    var raw: u8[9] = [0; 9];
    http2::encode_frame_header(hdr, raw);
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
    let settings_hdr = http2::FrameHeader {
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
    let sid = p.stream_id & rfc::H2_MAX_STREAM_ID;
    let dep_id = p.dep_stream_id & rfc::H2_MAX_STREAM_ID;
    if sid == 0 || sid == dep_id {
        return true;
    }
    let p_hdr = http2::FrameHeader {
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
