// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Internal helpers for gRPC framing, status codecs, Connect-RPC, health checks, and client parsing.
namespace grpc_internal;

import std;
import json;
import core from "..";
import rfc.grpc;
import http.headers;
import http.request;
import http.response;
import .constants;
import .framing;
import .status;
import .connect;
import .health;
import .client;

// ---- Media Type & Framing Internal Helpers ------------------------------

inline fn matches_media_type(ct: const u8[:], prefix: const u8[:]) -> bool {
    guard ct.starts_with_fold(prefix) else { return false; }
    if ct.len == prefix.len { return true; }
    let next_byte = ct[prefix.len];
    let suffix_idx = core::add_sat_i64(prefix.len, 1);
    if next_byte == '+' {
        return ct.len > suffix_idx && core::is_tchar(ct[suffix_idx]);
    }
    return next_byte == ';' || next_byte == ' ' || next_byte == '\t';
}

inline fn is_web(ct: const u8[:]) -> bool {
    let trimmed = ct.trim_lws();
    return matches_media_type(trimmed, rfc::GRPC_WEB_CONTENT_TYPE)
        || matches_media_type(trimmed, rfc::GRPC_WEB_TEXT_CONTENT_TYPE);
}

inline fn is_web_text(ct: const u8[:]) -> bool {
    let trimmed = ct.trim_lws();
    return matches_media_type(trimmed, rfc::GRPC_WEB_TEXT_CONTENT_TYPE);
}

inline fn merge_varint_septet(acc: u64, b: u8, shift: u64) -> u64 {
    return acc | (((b & 0x7F) as u64) << (shift & 63));
}

inline fn is_metadata_key_char(b: u8) -> bool {
    return (b >= 'a' && b <= 'z') || core::is_ascii_digit(b) || b == '-' || b == '_' || b == '.';
}

fn is_valid_custom_metadata(key: const u8[:], val: const u8[:]) -> bool {
    guard key.len > 0 && key[0] != ':' else { return false; }
    guard !key.eq_ascii_fold(rfc::HEADER_GRPC_STATUS) else { return false; }
    guard !key.eq_ascii_fold(rfc::HEADER_GRPC_MESSAGE) else { return false; }
    guard !key.eq_ascii_fold(rfc::HEADER_GRPC_STATUS_DETAILS_BIN) else { return false; }
    guard !key.eq_ascii_fold("content-type") else { return false; }
    guard !key.eq_ascii_fold("te") else { return false; }
    for b in key {
        guard is_metadata_key_char(b) else { return false; }
    }
    for v in val {
        guard v == '\t' || (v >= 0x20 && v <= 0x7E) || v >= 0x80 else { return false; }
    }
    return true;
}

// Parses a single gRPC-Web trailer header line ("name: value").
//
// Example:
//   line = "grpc-status: 0"
//   returns: true, out_status = grpc::StatusCode.Ok, found_valid_status = true
fn parse_web_trailer_line<B>(
    line:               const u8[:],
    saw_status_key:     bool&,
    found_valid_status: bool&,
    out_status:         grpc::StatusCode&,
    out_message:        B&,
) -> bool {
    let name, raw_val, ok_split = line.split_once_byte(':');
    guard ok_split && name.len > 0 else { return true; }
    let val = raw_val.trim_lws();
    if name.eq_ascii_fold("grpc-status") {
        if saw_status_key {
            out_status = grpc::StatusCode.Unknown;
            return false;
        }
        saw_status_key = true;
        if val.len == 0 {
            return true;
        }
        let status_int, ok_code = val.parse_u32_dec();
        if !ok_code {
            out_status = grpc::StatusCode.Unknown;
            return false;
        }
        out_status = grpc::status_from_code(status_int);
        found_valid_status = true;
        return true;
    }
    if name.eq_ascii_fold("grpc-message") {
        out_message.clear();
        grpc::decode_message(val, out_message);
    }
    return true;
}

// ---- Status & Protowire Internal Helpers --------------------------------

inline fn is_message_unencoded(b: u8) -> bool {
    return b >= 0x20 && b <= 0x7E && b != '%';
}

fn div_u64(n: u64, d: u64) -> u64 {
    guard d > 0 else { return 0; }
    guard n >= d else { return 0; }

    var cur_d = d;
    var cur_q: u64 = 1;
    let half_n = n >> 1;

    while cur_d <= half_n {
        cur_d = core::add_sat_u64(cur_d, cur_d);
        cur_q = core::add_sat_u64(cur_q, cur_q);
    }

    var rem_n = n;
    var quotient: u64 = 0;

    while cur_q > 0 {
        if rem_n >= cur_d {
            rem_n = core::sub_sat_u64(rem_n, cur_d);
            quotient = quotient | cur_q;
        }
        cur_d = cur_d >> 1;
        cur_q = cur_q >> 1;
    }

    return quotient;
}

inline fn convert_timeout_unit(num: u64, unit: u8) -> u64, bool {
    if unit == 'H' { return core::mul_sat_u64(num, 3600000), true; }
    if unit == 'M' { return core::mul_sat_u64(num, 60000), true; }
    if unit == 'S' { return core::mul_sat_u64(num, 1000), true; }
    if unit == 'm' { return num, true; }
    if unit == 'u' {
        let ms = if num > 0 && num < 1000 { 1 } else { div_u64(num, 1000) };
        return ms, true;
    }
    if unit == 'n' {
        let ms = if num > 0 && num < 1000000 { 1 } else { div_u64(num, 1000000) };
        return ms, true;
    }
    return 0, false;
}

inline fn resolve_effective_http_status(headers: const http::HeaderMap&) -> i32 {
    if headers.status_code != 200 {
        return headers.status_code as u16;
    }
    let pseudo_st = headers.get_header(":status").trim_lws();
    if pseudo_st.len > 0 {
        let code_u32, ok_st = pseudo_st.parse_u32_dec();
        if ok_st && code_u32 >= 100 && code_u32 <= 599 {
            return code_u32 as i32;
        }
        return 500;
    }
    return 200;
}

inline fn protowire_varint_len(val: u64) -> u64 {
    var v = val;
    var n: u64 = 1;
    while v >= 0x80 {
        v = v >> 7;
        n = core::add_sat_u64(n, 1);
    }
    return n;
}

inline fn write_protowire_varint(val: u64, dst: u8[:], pos: u64&) {
    var v = val;
    while v >= 0x80 {
        dst[pos as i64] = ((v & 0x7F) as u8) | 0x80;
        pos = core::add_sat_u64(pos, 1);
        v = v >> 7;
    }
    dst[pos as i64] = (v & 0x7F) as u8;
    pos = core::add_sat_u64(pos, 1);
}

inline fn clamp_utf8_prefix_len(s: const u8[:], max_bytes: i64) -> i64 {
    if s.len <= max_bytes { return s.len; }
    var cut = max(max_bytes, 0);
    while cut > 0 && (s[cut] & 0xC0) == 0x80 {
        cut = core::sub_sat_i64(cut, 1);
    }
    return cut;
}

// Decodes padded or unpadded standard/URL-safe Base64 `trimmed` into bounded buffer `out`.
//
// Example:
//   trimmed = "CAMSA2JhZA", out = []
//   returns: true, out = "\x08\x03\x12\x03bad"
inline fn decode_base64_into<B>(trimmed: const u8[:], out: B&) -> bool {
    if (trimmed.len & 3) == 0 {
        return core::base64_decode(trimmed, out) || core::base64url_decode(trimmed, out);
    }
    guard (trimmed.len & 3) != 1 else { return false; }
    var padded: u8[..1400] = [];
    guard padded.try_set(trimmed) else { return false; }
    while (padded.len & 3) != 0 {
        guard padded.try_push('=') else { return false; }
    }
    return core::base64_decode(padded[..], out) || core::base64url_decode(trimmed, out);
}

// Decodes a single `google.protobuf.Any` submessage (`field 1 = type_url`, `field 2 = value`).
//
// Example:
//   wire = [0x0A, 0x04, 't', 'y', 'p', 'e', 0x12, 0x02, 0x01, 0x02]
//   returns: true, out_detail.type_url = "type", out_detail.value = [0x01, 0x02]
fn decode_any_detail(wire: const u8[:], out_detail: grpc::ErrorDetail&) -> bool {
    var tmp_type:  u8[..128] = [];
    var tmp_val:   u8[..256] = [];
    var pos:       i64       = 0;
    var has_field: bool      = false;
    while pos < wire.len {
        let tag, ok_tag = grpc::pb_read_varint(wire, pos);
        let raw_fnum = tag >> 3;
        guard ok_tag && raw_fnum >= 1 && raw_fnum <= grpc::PB_MAX_FIELD_NUM else { return false; }
        let fnum = raw_fnum as u32;
        let wtype = (tag & 0x07) as u32;
        if fnum == 1 || fnum == 2 {
            guard wtype == grpc::PB_WIRE_LEN else { return false; }
            let len_u64, ok_len = grpc::pb_read_varint(wire, pos);
            let rem = core::sub_sat_i64(wire.len, pos);
            guard ok_len && len_u64 <= (rem as u64) else { return false; }
            let end_pos = core::add_sat_i64(pos, len_u64 as i64);
            let slice = wire[pos..end_pos];
            pos = end_pos;
            if fnum == 1 {
                guard slice.validate_utf8() && tmp_type.try_set(slice) else { return false; }
            } else {
                guard tmp_val.try_set(slice) else { return false; }
            }
            has_field = true;
        } else {
            guard grpc::pb_skip_field(wire, pos, wtype) else { return false; }
        }
    }
    guard has_field else { return false; }
    let _ = out_detail.type_url.try_set(tmp_type[..]);
    let _ = out_detail.value.try_set(tmp_val[..]);
    return true;
}

// Parses a single wire field from a `google.rpc.Status` protobuf payload.
//
// Example:
//   wire = [0x08, 0x03], idx = 0
//   returns: true, idx = 2, out_code = 3
fn parse_status_proto_field<B>(
    wire:        const u8[:],
    idx:         i64&,
    out_code:    u32&,
    out_msg:     B&,
    out_details: grpc::ErrorDetail[..4]&,
) -> bool {
    let saved_idx = idx;
    var committed = false;
    defer if !committed { idx = saved_idx; };
    let tag, ok_tag = grpc::pb_read_varint(wire, idx);
    let raw_fnum = tag >> 3;
    guard ok_tag && raw_fnum >= 1 && raw_fnum <= grpc::PB_MAX_FIELD_NUM else { return false; }
    let fnum = raw_fnum as u32;
    let wtype = (tag & 0x07) as u32;
    if fnum == 1 {
        guard wtype == grpc::PB_WIRE_VARINT else { return false; }
        let v, ok_v = grpc::pb_read_varint(wire, idx);
        guard ok_v && v <= 16 else { return false; }
        out_code = v as u32;
        committed = true;
        return true;
    }
    if fnum != 2 && fnum != 3 {
        guard grpc::pb_skip_field(wire, idx, wtype) else { return false; }
        committed = true;
        return true;
    }
    guard wtype == grpc::PB_WIRE_LEN else { return false; }
    let len_u64, ok_l = grpc::pb_read_varint(wire, idx);
    let rem = core::sub_sat_i64(wire.len, idx);
    guard ok_l && len_u64 <= (rem as u64) else { return false; }
    let end_pos = core::add_sat_i64(idx, len_u64 as i64);
    let slice = wire[idx..end_pos];
    if fnum == 2 {
        guard slice.validate_utf8() else { return false; }
        let take_len = clamp_utf8_prefix_len(slice, out_msg.cap);
        let _ = out_msg.try_set(slice[..take_len]);
        idx = end_pos;
        committed = true;
        return true;
    }
    var detail = grpc::ErrorDetail { .. };
    guard decode_any_detail(slice, detail) && out_details.try_push(detail) else { return false; }
    idx = end_pos;
    committed = true;
    return true;
}

// ---- Connect Protocol Internal Helpers ----------------------------------

fn connect_status_name(code: grpc::StatusCode) -> const u8[:] {
    return match code {
        Ok => "ok",
        Cancelled => "canceled",
        Unknown => "unknown",
        InvalidArgument => "invalid_argument",
        DeadlineExceeded => "deadline_exceeded",
        NotFound => "not_found",
        AlreadyExists => "already_exists",
        PermissionDenied => "permission_denied",
        ResourceExhausted => "resource_exhausted",
        FailedPrecondition => "failed_precondition",
        Aborted => "aborted",
        OutOfRange => "out_of_range",
        Unimplemented => "unimplemented",
        Internal => "internal",
        Unavailable => "unavailable",
        DataLoss => "data_loss",
        Unauthenticated => "unauthenticated",
        _ => "unknown",
    };
}

// Parses a Connect Protocol snake_case error code string into a grpc::StatusCode.
//
// Example:
//   name = "resource_exhausted"
//   returns: grpc::StatusCode.ResourceExhausted, true
fn parse_connect_status_code(name: const u8[:]) -> grpc::StatusCode, bool {
    if name == "canceled" || name == "cancelled" {
        return grpc::StatusCode.Cancelled, true;
    }
    var i: u32 = 1;
    while i <= 16 {
        let candidate = grpc::status_from_code(i);
        if name == connect_status_name(candidate) {
            return candidate, true;
        }
        i = core::add_sat_u32(i, 1);
    }
    return grpc::StatusCode.Unknown, false;
}

// Percent-decodes a Connect query component (`%XX` only; `+` remains literal `+`).
//
// Example:
//   src = "hello%20world%2B1", max_out = 64
//   returns: grpc::StatusCode.Ok, out = "hello world+1"
fn percent_decode_connect_component<B>(src: const u8[:], out: B&, max_out: u64) -> grpc::StatusCode {
    if src.len == 0 {
        out.clear();
        return grpc::StatusCode.Ok;
    }
    var idx: i64 = 0;
    out.clear();
    while idx < src.len {
        if (out.len as u64) >= max_out {
            out.clear();
            return grpc::StatusCode.ResourceExhausted;
        }
        let b = src[idx];
        if b == '%' {
            let i1 = core::add_sat_i64(idx, 1);
            let i2 = core::add_sat_i64(idx, 2);
            if i2 >= src.len {
                out.clear();
                return grpc::StatusCode.InvalidArgument;
            }
            let hi = core::hex_digit_to_val(src[i1]);
            let lo = core::hex_digit_to_val(src[i2]);
            if hi < 0 || lo < 0 {
                out.clear();
                return grpc::StatusCode.InvalidArgument;
            }
            let decoded = (core::shl_sat_u64(hi as u64, 4) | (lo as u64)) as u8;
            if !out.try_push(decoded) {
                out.clear();
                return grpc::StatusCode.ResourceExhausted;
            }
            idx = core::add_sat_i64(idx, 3);
        } else {
            if !out.try_push(b) {
                out.clear();
                return grpc::StatusCode.ResourceExhausted;
            }
            idx = core::add_sat_i64(idx, 1);
        }
    }
    return grpc::StatusCode.Ok;
}

inline fn is_valid_percent_encoded_component(src: const u8[:]) -> bool {
    var idx: i64 = 0;
    while idx < src.len {
        if src[idx] == '%' {
            let i2 = core::add_sat_i64(idx, 2);
            guard i2 < src.len else { return false; }
            let hi = core::hex_digit_to_val(src[core::add_sat_i64(idx, 1)]);
            let lo = core::hex_digit_to_val(src[i2]);
            guard hi >= 0 && lo >= 0 else { return false; }
            idx = core::add_sat_i64(idx, 3);
        } else {
            idx = core::add_sat_i64(idx, 1);
        }
    }
    return true;
}

fn apply_connect_query_param(
    raw_k:      const u8[:],
    raw_v:      const u8[:],
    val_start:  i64,
    val_end:    i64,
    out_params: grpc::ConnectUnaryGetParams&,
    msg_start:  i64&,
    msg_end:    i64&,
) -> grpc::StatusCode {
    var key_buf: u8[..64] = [];
    let key_st = percent_decode_connect_component(raw_k, key_buf, 64);
    guard key_st == grpc::StatusCode.Ok else { return grpc::StatusCode.InvalidArgument; }
    let k = key_buf[..];
    if k == "connect" {
        var ver_buf: u8[..16] = [];
        let ver_st = percent_decode_connect_component(raw_v, ver_buf, 16);
        guard ver_st == grpc::StatusCode.Ok && ver_buf[..] == "v1" else {
            return grpc::StatusCode.InvalidArgument;
        }
        out_params.has_version = true;
        return grpc::StatusCode.Ok;
    }
    if k == "encoding" {
        let enc_st = percent_decode_connect_component(raw_v, out_params.encoding, 16);
        if enc_st == grpc::StatusCode.ResourceExhausted {
            return grpc::StatusCode.Unimplemented;
        }
        return enc_st;
    }
    if k == "compression" {
        let comp_st = percent_decode_connect_component(raw_v, out_params.compression, 16);
        if comp_st == grpc::StatusCode.ResourceExhausted {
            return grpc::StatusCode.Unimplemented;
        }
        return comp_st;
    }
    if k == "base64" {
        var b64_buf: u8[..8] = [];
        let b64_st = percent_decode_connect_component(raw_v, b64_buf, 8);
        guard b64_st == grpc::StatusCode.Ok && (b64_buf[..] == "1" || b64_buf[..] == "0") else {
            return grpc::StatusCode.InvalidArgument;
        }
        out_params.base64 = b64_buf[..] == "1";
        return grpc::StatusCode.Ok;
    }
    if k == "message" {
        let max_msg_u64: u64 = rfc::GRPC_DEFAULT_MAX_MESSAGE_SIZE;
        let max_raw = core::mul_sat_u64(max_msg_u64, 3);
        guard (raw_v.len as u64) <= max_raw else {
            return grpc::StatusCode.ResourceExhausted;
        }
        msg_start = val_start;
        msg_end = val_end;
        return grpc::StatusCode.Ok;
    }
    guard is_valid_percent_encoded_component(raw_v) else {
        return grpc::StatusCode.InvalidArgument;
    }
    return grpc::StatusCode.Ok;
}

// Decodes a percent-decoded Base64 or Base64url Connect GET payload into `out_payload`.
//
// Example:
//   pct_decoded = "cGluZw", out_payload = []
//   returns: true, out_payload = "ping"
inline fn decode_connect_base64_payload(pct_decoded: u8[>..]&, out_payload: u8[>..]&) -> bool {
    if core::base64url_decode(pct_decoded[..], out_payload) {
        return true;
    }
    guard (pct_decoded.len & 3) != 1 else { return false; }
    while (pct_decoded.len & 3) != 0 {
        pct_decoded.push('=');
    }
    return core::base64_decode(pct_decoded[..], out_payload);
}

// Decodes and optionally decompresses a Connect Protocol unary GET message payload.
//
// Example:
//   raw_msg = "cGluZw", params.base64 = true, params.compression = ""
//   returns: grpc::StatusCode.Ok, out_payload = "ping"
fn decode_connect_get_payload(
    raw_msg:     const u8[:],
    params:      const grpc::ConnectUnaryGetParams&,
    out_payload: u8[>..]&,
) -> grpc::StatusCode {
    var tmp_payload: u8[>..] = [];
    let max_msg_u64: u64 = rfc::GRPC_DEFAULT_MAX_MESSAGE_SIZE;
    if raw_msg.len > 0 {
        var pct_decoded: u8[>..] = [];
        let max_encoded = core::mul_sat_u64(max_msg_u64, 2);
        let pct_st = percent_decode_connect_component(raw_msg, pct_decoded, max_encoded);
        guard pct_st == grpc::StatusCode.Ok else { return pct_st; }
        if params.base64 {
            guard decode_connect_base64_payload(pct_decoded, tmp_payload) else {
                return grpc::StatusCode.InvalidArgument;
            }
            guard (tmp_payload.len as u64) <= max_msg_u64 else {
                return grpc::StatusCode.ResourceExhausted;
            }
        } else {
            guard (pct_decoded.len as u64) <= max_msg_u64 else {
                return grpc::StatusCode.ResourceExhausted;
            }
            tmp_payload.append(pct_decoded[..]);
        }
    }

    let comp = params.compression[..];
    if comp.len > 0 && !comp.eq_ascii_fold("identity") {
        guard comp.eq_ascii_fold("gzip") else { return grpc::StatusCode.Unimplemented; }
        var decomp_buf: u8[>..] = [];
        let ok_gz, gz_err = core::gzip_decompress_with_limit(
            tmp_payload[..], decomp_buf, rfc::GRPC_DEFAULT_MAX_MESSAGE_SIZE,
        );
        guard ok_gz else {
            return if gz_err == core::CompressError.OutputBufferOverflow {
                grpc::StatusCode.ResourceExhausted
            } else {
                grpc::StatusCode.InvalidArgument
            };
        }
        tmp_payload.clear();
        tmp_payload.append(decomp_buf[..]);
    }
    if params.encoding[..] == "json" {
        guard tmp_payload[..].validate_utf8() else { return grpc::StatusCode.InvalidArgument; }
    }
    out_payload.clear();
    out_payload.append(tmp_payload[..]);
    return grpc::StatusCode.Ok;
}

// Consumes `&`-delimited query parameters from `rem_in` into `out_params` and `msg_start..msg_end`.
//
// Example:
//   rem_in = "connect=v1&encoding=proto"
//   returns: grpc::StatusCode.Ok, out_params.has_version = true, out_params.encoding = "proto"
fn scan_connect_query_pairs(
    rem_in:     const u8[:],
    out_params: grpc::ConnectUnaryGetParams&,
    msg_start:  i64&,
    msg_end:    i64&,
) -> grpc::StatusCode {
    var pos: i64 = 0;
    while pos < rem_in.len {
        let sub = rem_in[pos..];
        let amp_rel = sub.index_of_byte('&');
        let pair_end = if amp_rel >= 0 { core::add_sat_i64(pos, amp_rel) } else { rem_in.len };
        let item = rem_in[pos..pair_end];
        let eq_rel = item.index_of_byte('=');
        if eq_rel >= 0 {
            let val_start = core::add_sat_i64(pos, core::add_sat_i64(eq_rel, 1));
            let st = apply_connect_query_param(
                item[..eq_rel],
                rem_in[val_start..pair_end],
                val_start,
                pair_end,
                out_params,
                msg_start,
                msg_end,
            );
            guard st == grpc::StatusCode.Ok else { return st; }
        }
        pos = if amp_rel >= 0 { core::add_sat_i64(pair_end, 1) } else { rem_in.len };
    }
    guard out_params.has_version && out_params.encoding.len > 0 else {
        return grpc::StatusCode.InvalidArgument;
    }
    guard out_params.encoding[..] == "proto" || out_params.encoding[..] == "json" else {
        return grpc::StatusCode.Unimplemented;
    }
    return grpc::StatusCode.Ok;
}

fn append_connect_json_quoted<B>(raw: const u8[:], out: B&) -> bool {
    let body_bound = if core::is_json_plain_string(raw) {
        raw.len
    } else {
        core::mul_sat_i64(raw.len, 6)
    };
    let max_needed = core::add_sat_i64(out.len, core::add_sat_i64(body_bound, 2));
    guard max_needed <= out.cap else { return false; }
    core::format_json_string(out, raw);
    return true;
}

inline fn has_prior_trailer_key_fold(trailers: const http::HeaderMap&, limit_idx: i64, key: const u8[:]) -> bool {
    for j in limit_idx {
        let e .= trailers.entries[j];
        if http::entry_name(trailers, e).eq_ascii_fold(key) {
            return true;
        }
    }
    return false;
}

fn append_connect_trailer_value_array<B>(
    trailers:  const http::HeaderMap&,
    start_idx: i64,
    key:       const u8[:],
    json_buf:  B&,
) -> bool {
    guard json_buf.try_push('[') else { return false; }
    var first_val = true;
    var j = start_idx;
    while j < trailers.entries.len {
        let e .= trailers.entries[j];
        if http::entry_name(trailers, e).eq_ascii_fold(key) {
            if !first_val {
                guard json_buf.try_push(',') else { return false; }
            }
            guard append_connect_json_quoted(http::entry_value(trailers, e), json_buf) else { return false; }
            first_val = false;
        }
        j = core::add_sat_i64(j, 1);
    }
    return json_buf.try_push(']');
}

fn append_connect_end_stream_metadata<B>(trailers: const http::HeaderMap&, json_buf: B&) -> bool {
    guard json_buf.try_append("\"metadata\":{") else { return false; }
    var first_meta = true;
    var lower_key: u8[..128] = [];
    for &e, i in trailers.entries {
        let k = http::entry_name(trailers, e);
        if k.len == 0 || has_prior_trailer_key_fold(trailers, i, k) {
            continue;
        }
        guard k.len <= lower_key.cap else { return false; }
        lower_key.clear();
        k.to_lower_ascii(lower_key);
        if !first_meta {
            guard json_buf.try_push(',') else { return false; }
        }
        guard append_connect_json_quoted(lower_key[..], json_buf)
            && json_buf.try_push(':')
            && append_connect_trailer_value_array(trailers, i, k, json_buf) else {
            return false;
        }
        first_meta = false;
    }
    return json_buf.try_push('}');
}

fn append_connect_end_stream_error<B>(
    code:     grpc::StatusCode,
    message:  const u8[:],
    json_buf: B&,
) -> bool {
    guard json_buf.try_append("\"error\":{\"code\":")
        && append_connect_json_quoted(connect_status_name(code), json_buf) else {
        return false;
    }
    if message.len > 0 {
        guard json_buf.try_append(",\"message\":")
            && append_connect_json_quoted(message, json_buf) else {
            return false;
        }
    }
    return json_buf.try_push('}');
}

// Decodes a JSON object member key `raw_key` (including `\uXXXX` escapes) into `out_key`.
//
// Example:
//   raw_key = "x-custom", out_key = []
//   returns: true, out_key = "x-custom"
inline fn decode_connect_member_key<B>(raw_key: const u8[:], out_key: B&) -> bool {
    if !raw_key.contains_byte('\\') {
        return raw_key.validate_utf8() && out_key.try_set(raw_key);
    }
    guard json::valid_escapes(raw_key, 0, raw_key.len) else { return false; }
    return core::decode_json_string_into(raw_key, 0, raw_key.len, out_key);
}

inline fn is_valid_connect_metadata_entry(key: const u8[:], val: const u8[:]) -> bool {
    guard key.len > 0 && key[0] != ':' else { return false; }
    for b in key {
        guard core::is_tchar(b) else { return false; }
    }
    for v in val {
        guard v == '\t' || (v >= 0x20 && v <= 0x7E) || v >= 0x80 else { return false; }
    }
    return true;
}

// Parses a single `"key":["val1",...]` array value in a Connect metadata object.
//
// Example:
//   reader at "[\"val1\"]", lower_key = "x-custom"
//   appends: out_trailers["x-custom"] = "val1"
fn parse_connect_metadata_array(
    reader:       json::Reader&,
    lower_key:    const u8[:],
    out_trailers: http::HeaderMap&,
    had_error:    bool&,
) {
    if json::peek(reader) != '[' {
        had_error = true;
        json::skip(reader);
        return;
    }
    var val_buf: u8[..1024] = [];
    json::each_element(reader) {
        if !core::read_json_string_into(reader, val_buf)
            || !is_valid_connect_metadata_entry(lower_key, val_buf[..])
            || !out_trailers.append_header(lower_key, val_buf[..]) {
            had_error = true;
        }
    };
}

// Parses Connect `"metadata":{...}` object entries from `reader` into `out_trailers`.
//
// Example:
//   reader at "{\"x-custom\":[\"val1\"]}"
//   populates: out_trailers["x-custom"] = "val1"
fn parse_connect_metadata_member(
    reader:       json::Reader&,
    seen_meta:    bool&,
    out_trailers: http::HeaderMap&,
    had_error:    bool&,
) {
    if seen_meta || json::peek(reader) != '{' {
        had_error = true;
        json::skip(reader);
        return;
    }
    seen_meta = true;
    var key_buf:   u8[..128] = [];
    var lower_key: u8[..128] = [];
    json::each_member(reader) { raw_key =>
        if !decode_connect_member_key(raw_key, key_buf) || key_buf.len == 0 {
            had_error = true;
            json::skip(reader);
        } else {
            lower_key.clear();
            key_buf[..].to_lower_ascii(lower_key);
            parse_connect_metadata_array(reader, lower_key[..], out_trailers, had_error);
        }
    };
}

// Validates and skips a Connect `"details":[{...},...]` JSON array of error detail objects.
//
// Example:
//   reader at "[{\"type\":\"pkg.Detail\"}]"
//   advances `reader` past the array, had_error = false
inline fn parse_connect_error_details_array(reader: json::Reader&, had_error: bool&) {
    if json::peek(reader) != '[' {
        had_error = true;
        json::skip(reader);
        return;
    }
    json::each_element(reader) {
        if json::peek(reader) != '{' {
            had_error = true;
        }
        json::skip(reader);
    };
}

fn dispatch_connect_error_field<B>(
    reader:     json::Reader&,
    field_key:  const u8[:],
    saw_code:   bool&,
    out_status: grpc::StatusCode&,
    out_msg:    B&,
    had_error:  bool&,
) {
    if field_key == "code" {
        var code_buf: u8[..64] = [];
        if saw_code || !core::read_json_string_into(reader, code_buf) || code_buf.len == 0 || code_buf[..] == "ok" {
            had_error = true;
            return;
        }
        saw_code = true;
        let parsed_code, ok_c = parse_connect_status_code(code_buf[..]);
        out_status = if ok_c { parsed_code } else { grpc::StatusCode.Unknown };
        return;
    }
    if field_key == "message" {
        var full_msg: u8[..4096] = [];
        if !core::read_json_string_into(reader, full_msg) {
            had_error = true;
            return;
        }
        let take_len = clamp_utf8_prefix_len(full_msg[..], out_msg.cap);
        let _ = out_msg.try_set(full_msg[..take_len]);
        return;
    }
    if field_key == "details" {
        parse_connect_error_details_array(reader, had_error);
        return;
    }
    json::skip(reader);
}

// Parses Connect `"error":{"code":"...","message":"...","details":[...]}` object fields.
//
// Example:
//   reader at "{\"code\":\"unauthenticated\",\"message\":\"bad token\"}"
//   sets: out_status = grpc::StatusCode.Unauthenticated, out_msg = "bad token"
fn parse_connect_error_member<B>(
    reader:     json::Reader&,
    seen_error: bool&,
    out_status: grpc::StatusCode&,
    out_msg:    B&,
    had_error:  bool&,
) {
    if seen_error || json::peek(reader) != '{' {
        had_error = true;
        json::skip(reader);
        return;
    }
    seen_error = true;
    out_status = grpc::StatusCode.Unknown;
    var saw_code = false;
    var key_buf: u8[..64] = [];
    json::each_member(reader) { raw_key =>
        if !decode_connect_member_key(raw_key, key_buf) {
            had_error = true;
            json::skip(reader);
        } else {
            dispatch_connect_error_field(reader, key_buf[..], saw_code, out_status, out_msg, had_error);
        }
    };
    if !saw_code {
        had_error = true;
    }
}

fn is_connect_get_request(req: const http::Request&) -> bool {
    guard req.method[..].eq_ascii_fold("GET") else { return false; }
    let q_idx = req.url[..].index_of_byte('?');
    guard q_idx >= 0 else { return false; }
    var rem = req.url[core::add_sat_i64(q_idx, 1)..];
    var key_buf: u8[..16] = [];
    while rem.len > 0 {
        let pair, rest, has_amp = rem.split_once_byte('&');
        let item = if has_amp { pair } else { rem };
        rem = if has_amp { rest } else { "" };
        let k, _, ok_eq = item.split_once_byte('=');
        if ok_eq {
            if k == "connect" { return true; }
            if percent_decode_connect_component(k, key_buf, 16) == grpc::StatusCode.Ok && key_buf[..] == "connect" {
                return true;
            }
        }
    }
    return false;
}

inline fn connect_error_http_status(code: grpc::StatusCode) -> i32 {
    return match code {
        InvalidArgument => 400,
        Unauthenticated => 401,
        PermissionDenied => 403,
        NotFound => 404,
        Unimplemented => 404,
        AlreadyExists => 409,
        Aborted => 409,
        ResourceExhausted => 429,
        Cancelled => 499,
        DeadlineExceeded => 504,
        Unavailable => 503,
        _ => 500,
    };
}

fn encode_connect_unary_error_json<B>(st: const grpc::Status&, out_body: B&) {
    var json_buf: u8[..2048] = [];
    let _ = json_buf.try_append("{\"code\":");
    let _ = append_connect_json_quoted(connect_status_name(st.code), json_buf);
    if st.message.len > 0 {
        let _ = json_buf.try_append(",\"message\":");
        let _ = append_connect_json_quoted(st.message[..], json_buf);
    }
    let _ = json_buf.try_push('}');
    let _ = out_body.try_append(json_buf[..]);
}

// ---- Health Check Internal Helpers --------------------------------------

// Decodes and validates a protobuf `HealthCheckRequest` payload (field 1 = `service` UTF-8 string).
//
// Example:
//   req_payload = "\x0A\x0Amy.Service"
//   returns: "my.Service", true
fn try_decode_health_check_request(req_payload: const u8[:]) -> const u8[:], bool {
    var pos:       i64 = 0;
    var svc_start: i64 = 0;
    var svc_end:   i64 = 0;
    while pos < req_payload.len {
        let tag, ok_tag = grpc::pb_read_varint(req_payload, pos);
        let raw_fnum = tag >> 3;
        guard ok_tag && raw_fnum >= 1 && raw_fnum <= grpc::PB_MAX_FIELD_NUM else { return "", false; }
        let fnum = raw_fnum as u32;
        let wtype = (tag & 0x07) as u32;
        if fnum == 1 {
            guard wtype == grpc::PB_WIRE_LEN else { return "", false; }
            let len_u64, ok_len = grpc::pb_read_varint(req_payload, pos);
            let rem = core::sub_sat_i64(req_payload.len, pos);
            guard ok_len && len_u64 <= (rem as u64) else { return "", false; }
            let end_pos = core::add_sat_i64(pos, len_u64 as i64);
            guard req_payload[pos..end_pos].validate_utf8() else { return "", false; }
            svc_start = pos;
            svc_end = end_pos;
            pos = end_pos;
        } else {
            guard grpc::pb_skip_field(req_payload, pos, wtype) else { return "", false; }
        }
    }
    return req_payload[svc_start..svc_end], true;
}

fn encode_health_check_lpm<B>(serving_st: grpc::ServingStatus, out_lpm: B&) {
    var res_payload: u8[..16] = [];
    if serving_st != grpc::ServingStatus.Unknown {
        let code_u64: u64 = match serving_st {
            Unknown => 0,
            Serving => 1,
            NotServing => 2,
            ServiceUnknown => 3,
        };
        let _ = grpc::pb_write_varint_field(1, code_u64, res_payload);
    }
    grpc::encode_lpm(res_payload[..], out_lpm, false);
}

// ---- Client Internal Helpers --------------------------------------------

inline fn append_custom_metadata_to_request(req: http::Request&, meta: const grpc::Metadata[:]) {
    for &m in meta {
        if is_valid_custom_metadata(m.key[..], m.value[..]) {
            req.set_header(m.key[..], m.value[..]);
        }
    }
}

inline fn classify_gzip_error(gz_err: core::CompressError) -> grpc::StatusCode {
    if gz_err == core::CompressError.OutputBufferOverflow {
        return grpc::StatusCode.ResourceExhausted;
    }
    return grpc::StatusCode.Internal;
}

inline fn append_web_data_frame(frame_payload: const u8[:], is_comp: bool, out_resp: grpc::Response&) -> bool {
    out_resp.is_compressed = is_comp;
    if !is_comp {
        let next_len = core::add_sat_i64(out_resp.payload.len, frame_payload.len);
        guard next_len <= rfc::GRPC_DEFAULT_MAX_MESSAGE_SIZE else {
            out_resp.status = grpc::StatusCode.ResourceExhausted;
            return false;
        }
        out_resp.payload.append(frame_payload);
        return true;
    }
    let ok_gz, gz_err = core::gzip_decompress_with_limit(
        frame_payload, out_resp.payload, rfc::GRPC_DEFAULT_MAX_MESSAGE_SIZE,
    );
    if !ok_gz {
        out_resp.status = classify_gzip_error(gz_err);
    }
    return ok_gz;
}

// Decodes an uncompressed or Gzip-compressed gRPC-Web trailer frame payload.
//
// Example:
//   frame_payload = "grpc-status: 0\r\n", is_comp = false
//   returns: true, out_resp.status = grpc::StatusCode.Ok
inline fn decode_web_trailer_frame(
    frame_payload: const u8[:],
    is_comp:       bool,
    out_resp:      grpc::Response&,
) -> bool {
    if !is_comp {
        if !grpc::parse_web_trailers(frame_payload, out_resp.status, out_resp.message) {
            out_resp.status = grpc::StatusCode.Unknown;
        }
        return true;
    }
    var tr_decomp: u8[>..] = [];
    let ok_gz, _ = core::gzip_decompress_with_limit(
        frame_payload, tr_decomp, rfc::GRPC_DEFAULT_MAX_MESSAGE_SIZE,
    );
    guard ok_gz else { return false; }
    if !grpc::parse_web_trailers(tr_decomp[..], out_resp.status, out_resp.message) {
        out_resp.status = grpc::StatusCode.Unknown;
    }
    return true;
}

// Scans gRPC-Web data and trailer frames in `wire_bytes` for a unary RPC response.
//
// Example:
//   wire_bytes = "\x00\x00\x00\x00\x05hello\x80\x00\x00\x00\x0Fgrpc-status: 0\r\n"
//   returns: true, found_data = true, found_trailer = true
fn scan_web_unary_frames(
    wire_bytes:    const u8[:],
    out_resp:      grpc::Response&,
    found_data:    bool&,
    found_trailer: bool&,
) -> bool {
    var offset:        u32     = 0;
    var frame_payload: u8[>..] = [];
    while offset < (wire_bytes.len as u32) {
        guard !found_trailer else {
            out_resp.payload.clear();
            return false;
        }
        frame_payload.clear();
        var is_trailers = false;
        var is_comp = false;
        let consumed, ok_frame = grpc::decode_web_frame(
            wire_bytes[..], offset, frame_payload, is_trailers, is_comp,
        );
        guard ok_frame else {
            out_resp.payload.clear();
            return false;
        }

        if is_trailers {
            guard decode_web_trailer_frame(frame_payload[..], is_comp, out_resp) else {
                out_resp.payload.clear();
                return false;
            }
            found_trailer = true;
        } else {
            guard !found_data && append_web_data_frame(frame_payload[..], is_comp, out_resp) else {
                out_resp.payload.clear();
                return false;
            }
            found_data = true;
        }
        offset = core::add_sat_u32(offset, consumed);
    }
    return true;
}

// Parses a gRPC-Web response body into payload and trailers.
//
// Example:
//   body = "\x00\x00\x00\x00\x05hello\x80\x00\x00\x00\x0Fgrpc-status: 0\r\n"
//   returns: true, out_resp.payload = "hello", out_resp.status = Ok
fn parse_web_unary_body(
    res_headers:  const http::HeaderMap&,
    res_trailers: const http::HeaderMap&,
    body:         const u8[:],
    out_resp:     grpc::Response&,
) -> bool {
    var wire_bytes: u8[>..] = [];
    let content_type = res_headers.get_header("content-type");
    if content_type.len > 0 && !is_web(content_type) {
        out_resp.status = grpc::status_from_http(resolve_effective_http_status(res_headers));
        return false;
    }
    if is_web_text(content_type) {
        guard grpc::decode_web_text(body, wire_bytes) else { return false; }
    } else {
        wire_bytes.append(body);
    }

    var found_trailer = false;
    var found_data = false;
    guard scan_web_unary_frames(wire_bytes[..], out_resp, found_data, found_trailer) else {
        return false;
    }

    if !found_trailer {
        let has_hdr_status = grpc::extract_status(res_headers, res_trailers, out_resp.status, out_resp.message);
        guard !found_data && has_hdr_status else {
            out_resp.payload.clear();
            return false;
        }
        out_resp.is_trailers_only = true;
        if out_resp.status == grpc::StatusCode.Ok {
            out_resp.status = grpc::StatusCode.Internal;
            return false;
        }
        return true;
    }
    let http_st = resolve_effective_http_status(res_headers);
    if http_st != 200 && out_resp.status == grpc::StatusCode.Ok {
        out_resp.status = grpc::status_from_http(http_st);
    }
    if !found_data {
        out_resp.is_trailers_only = true;
        if out_resp.status == grpc::StatusCode.Ok {
            out_resp.status = grpc::StatusCode.Internal;
            return false;
        }
    }
    return true;
}

// Extracts `grpc-status`, `grpc-message`, and `grpc-status-details-bin` from `res` trailers or headers.
//
// Example:
//   res.trailers["grpc-status"] = "0", res.status_code = 200
//   returns: true, out_resp.status = grpc::StatusCode.Ok
inline fn extract_client_response_status(res: const http::Response&, out_resp: grpc::Response&) -> bool {
    let in_trailers = res.trailers.has_header(rfc::HEADER_GRPC_STATUS);
    let in_headers = !in_trailers && res.headers.has_header(rfc::HEADER_GRPC_STATUS);
    if !in_trailers && !in_headers {
        out_resp.status = grpc::status_from_http(res.status_code);
        return false;
    }
    let status_val = if in_trailers {
        res.trailer(rfc::HEADER_GRPC_STATUS)
    } else {
        res.header(rfc::HEADER_GRPC_STATUS)
    };
    let msg_val = if in_trailers {
        res.trailer(rfc::HEADER_GRPC_MESSAGE)
    } else {
        res.header(rfc::HEADER_GRPC_MESSAGE)
    };
    out_resp.status = grpc::status_from_code(grpc::parse_status_code(status_val));
    if res.status_code != 200 && out_resp.status == grpc::StatusCode.Ok {
        out_resp.status = grpc::status_from_http(res.status_code);
    }
    if msg_val.len > 0 {
        grpc::decode_message(msg_val, out_resp.message);
    }
    var details_b64 = res.trailer(rfc::HEADER_GRPC_STATUS_DETAILS_BIN);
    if details_b64.len == 0 {
        details_b64 = res.header(rfc::HEADER_GRPC_STATUS_DETAILS_BIN);
    }
    if details_b64.len > 0 {
        let _ = grpc::decode_status_details(
            details_b64, out_resp.status, out_resp.status, out_resp.message, out_resp.details,
        );
    }
    return true;
}

// Decodes and validates a native HTTP/2 or HTTP/3 unary gRPC response LPM body.
//
// Example:
//   body = "\x00\x00\x00\x00\x05hello", has_wire_status = true
//   returns: true, out_resp.payload = "hello"
fn decode_native_unary_body(
    body:            const u8[:],
    enc_hdr:         const u8[:],
    has_wire_status: bool,
    out_resp:        grpc::Response&,
) -> bool {
    if body.len >= 5 {
        guard has_wire_status else {
            out_resp.payload.clear();
            return false;
        }
        var comp = false;
        let consumed, ok_lpm = grpc::decode_lpm(body, 0, out_resp.payload, comp);
        guard ok_lpm && consumed == body.len else {
            if out_resp.status == grpc::StatusCode.Ok {
                out_resp.status = grpc::StatusCode.Internal;
            }
            out_resp.payload.clear();
            return false;
        }
        out_resp.is_compressed = comp;
        let comp_st = grpc::validate_recv_compression(comp, enc_hdr, false);
        if comp_st != grpc::StatusCode.Ok {
            out_resp.status = comp_st;
            out_resp.payload.clear();
            return false;
        }
        if comp {
            var decomp_buf: u8[>..] = [];
            let ok_gz, gz_err = core::gzip_decompress_with_limit(
                out_resp.payload[..], decomp_buf, rfc::GRPC_DEFAULT_MAX_MESSAGE_SIZE,
            );
            guard ok_gz else {
                out_resp.status = classify_gzip_error(gz_err);
                out_resp.payload.clear();
                return false;
            }
            out_resp.payload.clear();
            out_resp.payload.append(decomp_buf[..]);
        } else {
            guard out_resp.payload.len <= rfc::GRPC_DEFAULT_MAX_MESSAGE_SIZE else {
                out_resp.status = grpc::StatusCode.ResourceExhausted;
                out_resp.payload.clear();
                return false;
            }
        }
        return true;
    }

    if body.len == 0 && has_wire_status {
        out_resp.is_trailers_only = true;
        if out_resp.status == grpc::StatusCode.Ok {
            out_resp.status = grpc::StatusCode.Internal;
            return false;
        }
        return true;
    }

    if out_resp.status == grpc::StatusCode.Ok {
        out_resp.status = grpc::StatusCode.Internal;
    }
    return false;
}
