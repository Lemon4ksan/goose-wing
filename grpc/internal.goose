// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Internal helpers for gRPC framing, status codecs, health checks, and client parsing.
namespace grpc_internal;

import std;
import core;
import rfc.grpc;
import http.headers;
import http.request;
import http.response;
import .constants;
import .framing;
import .status;
import .health;
import .client;

// ---- Media Type & Framing Internal Helpers ------------------------------

inline fn matches_media_type(ct: const u8[:], prefix: const u8[:]) -> bool {
    guard ct.starts_with_fold(prefix) else { return false; }
    var pos = prefix.len;
    if pos < ct.len && ct[pos] == '+' {
        pos = core::add_sat_i64(pos, 1);
        let sub_start = pos;
        while pos < ct.len && core::is_tchar(ct[pos]) {
            pos = core::add_sat_i64(pos, 1);
        }
        guard pos > sub_start else { return false; }
    }
    while pos < ct.len && core::is_lws(ct[pos]) {
        pos = core::add_sat_i64(pos, 1);
    }
    if pos == ct.len { return true; }
    return ct[pos] == ';' && !ct[pos..].contains_byte(',');
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
    guard ok_split && name.len > 0 else { return false; }
    for b in name {
        guard core::is_tchar(b) else { return false; }
    }
    for vb in raw_val {
        guard vb == '\t' || (vb >= 0x20 && vb <= 0x7E) || vb >= 0x80 else { return false; }
    }
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

fn convert_timeout_unit(num: u64, unit: u8) -> u64, bool {
    if unit == 'H' { return core::mul_sat_u64(num, 3600000), true; }
    if unit == 'M' { return core::mul_sat_u64(num, 60000), true; }
    if unit == 'S' { return core::mul_sat_u64(num, 1000), true; }
    if unit == 'm' { return num, true; }
    if unit == 'u' {
        let q, _ = core::div_rem_u64(num, 1000);
        return if num > 0 && num < 1000 { 1 } else { q }, true;
    }
    if unit == 'n' {
        let q, _ = core::div_rem_u64(num, 1000000);
        return if num > 0 && num < 1000000 { 1 } else { q }, true;
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

checkfree fn protowire_varint_len(val: u64) -> u64 {
    return ((70 - clz(val | 1)) / 7) as u64;
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
    enc_hdr:       const u8[:] = "",
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
        let comp_st = grpc::validate_recv_compression(is_comp, enc_hdr, false);
        guard comp_st == grpc::StatusCode.Ok else {
            out_resp.status = comp_st;
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
    let enc_hdr = res_headers.get_header(rfc::HEADER_GRPC_ENCODING);
    guard scan_web_unary_frames(wire_bytes[..], out_resp, found_data, found_trailer, enc_hdr) else {
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

inline fn count_header_occurrences(m: const http::HeaderMap&, name: const u8[:]) -> i64 {
    var count: i64 = 0;
    for &e in m.entries {
        if http::entry_name(m, e).eq_ascii_fold(name) {
            count = core::add_sat_i64(count, 1);
        }
    }
    return count;
}

// Extracts `grpc-status`, `grpc-message`, and `grpc-status-details-bin` from `res` trailers or headers.
//
// Example:
//   res.trailers["grpc-status"] = "0", res.status_code = 200
//   returns: true, out_resp.status = grpc::StatusCode.Ok
inline fn extract_client_response_status(res: const http::Response&, out_resp: grpc::Response&) -> bool {
    let tr_cnt = count_header_occurrences(res.trailers, rfc::HEADER_GRPC_STATUS);
    let hd_cnt = count_header_occurrences(res.headers, rfc::HEADER_GRPC_STATUS);
    if tr_cnt > 1 || (tr_cnt == 0 && hd_cnt > 1) {
        out_resp.status = grpc::StatusCode.Unknown;
        return false;
    }
    let in_trailers = tr_cnt == 1;
    let in_headers = !in_trailers && hd_cnt == 1;
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
