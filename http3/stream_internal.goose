// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Internal HTTP/3 outbound header encoding, request/trailer/push validation,
// and bidirectional stream frame dispatch helpers (RFC 9114, RFC 9204).
namespace h3_internal;

import std;
import core;
import rfc.h2;
import rfc.h3_quic;
import http.headers;
import quic.packet;
import .internal;
import .types;
import .framing;
import .qpack_codec;
import .qpack_internal;
import .qpack;

// ---- Outbound Extra Header Encoding ----------------------------------------

fn encode_single_h3_extra_header<B1, B2>(
    tbl:           http3::QpackTable&,
    stream_id:     u64,
    base:          u64,
    extra_headers: const http::HeaderMap&,
    entry:         const http::HeaderEntry&,
    body_fields:   B1&,
    enc_stream:    B2&,
    max_dyn_abs:   u64&,
    used_any_dyn:  bool&,
) -> bool {
    let raw_len = extra_headers.raw_buf.len;
    let nb = entry.name_begin as i64;
    let ne = entry.name_end as i64;
    let vb = entry.values_begin as i64;
    let ve = entry.values_end as i64;
    guard nb >= 0 && ne >= nb && ne <= raw_len && vb >= 0 && ve >= vb && ve <= raw_len else {
        return false;
    }
    let raw_name = extra_headers.raw_buf[nb..ne];
    let val = extra_headers.raw_buf[vb..ve];
    if wire::is_h2_skipped_header_name(raw_name) {
        return true;
    }
    if raw_name.eq_ascii_fold("te") && !val.trim_lws().eq_ascii_fold("trailers") {
        return true;
    }
    var lower_name: u8[..256] = [];
    guard raw_name.len > 0 && raw_name.len <= lower_name.cap else { return false; }
    raw_name.to_lower_ascii(lower_name);
    return http3::encode_qpack_field_dynamic(
        tbl, stream_id, base, lower_name[..], val,
        body_fields, enc_stream, max_dyn_abs, used_any_dyn, false,
    );
}

fn encode_h3_extra_headers<B1, B2>(
    tbl:           http3::QpackTable&,
    stream_id:     u64,
    base:          u64,
    extra_headers: const http::HeaderMap&,
    body_fields:   B1&,
    enc_stream:    B2&,
    max_dyn_abs:   u64&,
    used_any_dyn:  bool&,
) -> bool {
    for &entry in extra_headers.entries {
        let ok = encode_single_h3_extra_header(
            tbl, stream_id, base, extra_headers, entry,
            body_fields, enc_stream, max_dyn_abs, used_any_dyn,
        );
        guard ok else { return false; }
    }
    return true;
}

// ---- Request Header, Trailer, Push Promise, and Data Validation ------------

// RFC 9114 Section 4.3.1: Request Pseudo-Header Fields - All HTTP/3 requests MUST include exactly one value for the :method, :scheme, and :path pseudo-header fields, unless the request is a CONNECT request; see Section 4.4.
// RFC 9114 Section 4.4: The CONNECT Method - The :scheme and :path pseudo-header fields are omitted and :authority is present.
// RFC 9220 Section 3: WebSockets Upgrade over HTTP/3 - Extended CONNECT requests include :protocol, :scheme, :authority, and :path.
fn validate_h3_pseudo_headers(
    role:           http3::ConnRole,
    status_count:   i32,
    method_count:   i32,
    scheme_count:   i32,
    path_count:     i32,
    auth_count:     i32,
    is_connect:     bool = false,
    protocol_count: i32  = 0,
) -> bool {
    if role == http3::ConnRole.Client {
        return status_count == 1 && method_count == 0 && scheme_count == 0
            && path_count == 0 && auth_count == 0 && protocol_count == 0;
    }
    if is_connect && protocol_count > 0 {
        return status_count == 0 && method_count == 1 && scheme_count == 1
            && path_count == 1 && auth_count == 1 && protocol_count == 1;
    }
    if is_connect {
        return status_count == 0 && method_count == 1 && scheme_count == 0
            && path_count == 0 && auth_count == 1 && protocol_count == 0;
    }
    return status_count == 0 && method_count == 1 && scheme_count == 1 && path_count == 1 && protocol_count == 0;
}

fn validate_h3_trailers<F>(conn: http3::Connection&, fields: const F&) -> u64 {
    for &field in fields {
        let fname = field.name[..];
        let fval = field.value[..];
        if fname.len > 0 && fname[0] == ':' {
            conn.state = http3::ConnState.Closed;
            conn.error_code = rfc::H3_ERR_GENERAL_PROTOCOL;
            return rfc::H3_ERR_GENERAL_PROTOCOL;
        }
        if fname.eq_ascii_fold("content-length") ||
           fname.eq_ascii_fold("host") ||
           fname.eq_ascii_fold("trailer") ||
           fname.eq_ascii_fold("te") ||
           rfc::is_connection_specific_header(fname) ||
           rfc::is_disallowed_trailer_field(fname) {
            conn.state = http3::ConnState.Closed;
            conn.error_code = rfc::H3_ERR_GENERAL_PROTOCOL;
            return rfc::H3_ERR_GENERAL_PROTOCOL;
        }
        if has_ctl_chars(fval) || is_forbidden_connection_header(fname, fval) {
            conn.state = http3::ConnState.Closed;
            conn.error_code = rfc::H3_ERR_GENERAL_PROTOCOL;
            return rfc::H3_ERR_GENERAL_PROTOCOL;
        }
    }
    return rfc::H3_ERR_NO_ERROR;
}

inline fn validate_pseudo_status(field: const http3::HeaderField&, counts: H3HeaderCounts&) -> i32, bool {
    counts.pseudo_status++;
    guard counts.pseudo_status == 1 && field.value.len == 3 else { return 0, false; }
    let sc, ok_sc = field.value[..].parse_i32_dec();
    guard ok_sc && sc >= 100 && sc <= 599 && sc != 101 else { return 0, false; }
    return sc, true;
}

fn validate_pseudo_method(field: const http3::HeaderField&, counts: H3HeaderCounts&) -> bool {
    counts.pseudo_method++;
    guard counts.pseudo_method == 1 && is_valid_http_method_token(field.value[..]) else { return false; }
    counts.is_connect = (field.value[..] == "CONNECT");
    return true;
}

fn validate_pseudo_scheme(field: const http3::HeaderField&, counts: H3HeaderCounts&) -> bool {
    counts.pseudo_scheme++;
    return counts.pseudo_scheme == 1 && is_valid_uri_scheme(field.value[..]);
}

fn validate_pseudo_authority(field: const http3::HeaderField&, counts: H3HeaderCounts&, auth_val: u8[..256]&) -> bool {
    counts.pseudo_authority++;
    guard counts.pseudo_authority == 1 && is_valid_authority_or_host(field.value[..]) else { return false; }
    return auth_val.try_set(field.value[..]);
}

fn validate_pseudo_path(field: const http3::HeaderField&, counts: H3HeaderCounts&) -> bool {
    counts.pseudo_path++;
    guard counts.pseudo_path == 1 && is_valid_h3_path_bytes(field.value[..]) else { return false; }
    return true;
}

fn validate_pseudo_protocol(
    field:             const http3::HeaderField&,
    counts:            H3HeaderCounts&,
    enable_conn_proto: bool,
) -> bool {
    guard enable_conn_proto else { return false; }
    counts.pseudo_protocol = core::add_sat_i64(counts.pseudo_protocol, 1) as i32;
    guard counts.pseudo_protocol == 1 && field.value.len > 0 else { return false; }
    for b in field.value {
        guard core::is_tchar(b) else { return false; }
    }
    return true;
}

inline fn apply_h3_pseudo_field(
    conn:     http3::Connection&,
    s_idx:    i32,
    field:    const http3::HeaderField&,
    counts:   H3HeaderCounts&,
    auth_val: u8[..256]&,
) -> bool {
    let fname = field.name[..];
    if fname == ":status" {
        let sc, ok_sc = validate_pseudo_status(field, counts);
        guard ok_sc else { return false; }
        conn.streams[s_idx].status_code = sc;
        return true;
    }
    if fname == ":method" {
        return validate_pseudo_method(field, counts) && conn.streams[s_idx].req_method.try_set(field.value[..]);
    }
    if fname == ":scheme" {
        return validate_pseudo_scheme(field, counts);
    }
    if fname == ":authority" {
        return validate_pseudo_authority(field, counts, auth_val)
            && conn.streams[s_idx].req_authority.try_set(field.value[..]);
    }
    if fname == ":path" {
        return validate_pseudo_path(field, counts) && conn.streams[s_idx].req_path.try_set(field.value[..]);
    }
    if fname == ":protocol" {
        let enable_proto = conn.role == http3::ConnRole.Server && conn.local_settings.enable_connect_protocol > 0;
        return validate_pseudo_protocol(field, counts, enable_proto);
    }
    return false;
}

fn process_h3_pseudo_field(
    conn:     http3::Connection&,
    s_idx:    i32,
    field:    const http3::HeaderField&,
    counts:   H3HeaderCounts&,
    auth_val: u8[..256]&,
) -> u64 {
    guard apply_h3_pseudo_field(conn, s_idx, field, counts, auth_val) else {
        conn.state = http3::ConnState.Closed;
        conn.error_code = rfc::H3_ERR_GENERAL_PROTOCOL;
        return rfc::H3_ERR_GENERAL_PROTOCOL;
    }
    return rfc::H3_ERR_NO_ERROR;
}

inline fn apply_h3_content_length(conn: http3::Connection&, s_idx: i32, fval: const u8[:]) -> bool {
    let cl, ok_cl = fval.parse_i64_dec();
    let _, ok_u = fval.parse_u64_dec();
    guard ok_cl && ok_u else { return false; }
    guard conn.streams[s_idx].content_length < 0 || conn.streams[s_idx].content_length == cl else {
        return false;
    }
    conn.streams[s_idx].content_length = cl;
    return true;
}

fn process_h3_regular_field(
    conn:     http3::Connection&,
    s_idx:    i32,
    field:    const http3::HeaderField&,
    counts:   H3HeaderCounts&,
    host_val: u8[..256]&,
) -> u64 {
    let fname = field.name[..];
    let fval = field.value[..];
    if fname.eq_ascii_fold("host") {
        counts.host = core::add_sat_i64(counts.host, 1) as i32;
        guard counts.host == 1 && is_valid_authority_or_host(fval) && host_val.try_set(fval) else {
            conn.state = http3::ConnState.Closed;
            conn.error_code = rfc::H3_ERR_GENERAL_PROTOCOL;
            return rfc::H3_ERR_GENERAL_PROTOCOL;
        }
        return rfc::H3_ERR_NO_ERROR;
    }
    if fname.eq_ascii_fold("content-length") {
        guard apply_h3_content_length(conn, s_idx, fval) else {
            conn.state = http3::ConnState.Closed;
            conn.error_code = rfc::H3_ERR_GENERAL_PROTOCOL;
            return rfc::H3_ERR_GENERAL_PROTOCOL;
        }
        return rfc::H3_ERR_NO_ERROR;
    }
    if fname.eq_ascii_fold("priority") && !conn.streams[s_idx].priority_updated && fval.trim_ascii_space().len > 0 {
        let parsed_p, ok_p = parse_h3_priority_field_value(fval, false);
        if ok_p {
            conn.streams[s_idx].priority = parsed_p;
        }
    }
    return rfc::H3_ERR_NO_ERROR;
}

fn validate_single_h3_header(
    conn:         http3::Connection&,
    s_idx:        i32,
    field:        const http3::HeaderField&,
    seen_regular: bool&,
    counts:       H3HeaderCounts&,
    auth_val:     u8[..256]&,
    host_val:     u8[..256]&,
) -> u64 {
    if has_ctl_chars(field.value[..]) {
        conn.state = http3::ConnState.Closed;
        conn.error_code = rfc::H3_ERR_GENERAL_PROTOCOL;
        return rfc::H3_ERR_GENERAL_PROTOCOL;
    }

    let is_pseudo = field.name.len > 0 && field.name[0] == ':';
    if is_pseudo {
        guard !seen_regular else {
            conn.state = http3::ConnState.Closed;
            conn.error_code = rfc::H3_ERR_GENERAL_PROTOCOL;
            return rfc::H3_ERR_GENERAL_PROTOCOL;
        }
        return process_h3_pseudo_field(conn, s_idx, field, counts, auth_val);
    }

    seen_regular = true;
    if is_forbidden_connection_header(field.name[..], field.value[..])
        || (conn.role == http3::ConnRole.Client && field.name[..].eq_ascii_fold("te")) {
        conn.state = http3::ConnState.Closed;
        conn.error_code = rfc::H3_ERR_GENERAL_PROTOCOL;
        return rfc::H3_ERR_GENERAL_PROTOCOL;
    }
    return process_h3_regular_field(conn, s_idx, field, counts, host_val);
}

inline fn validate_push_promise_pseudo_field(
    field:      const http3::HeaderField&,
    counts:     H3HeaderCounts&,
    req_method: u8[..16]&,
    req_path:   u8[..1024]&,
    auth_val:   u8[..256]&,
) -> bool {
    let fname = field.name[..];
    let fval = field.value[..];
    if fname == ":method" {
        return validate_pseudo_method(field, counts) && !counts.is_connect && req_method.try_set(fval);
    }
    if fname == ":scheme" {
        return validate_pseudo_scheme(field, counts);
    }
    if fname == ":authority" {
        return validate_pseudo_authority(field, counts, auth_val);
    }
    if fname == ":path" {
        return validate_pseudo_path(field, counts) && req_path.try_set(fval);
    }
    return false;
}

fn validate_single_push_promise_field(
    field:        const http3::HeaderField&,
    seen_regular: bool&,
    counts:       H3HeaderCounts&,
    req_method:   u8[..16]&,
    req_path:     u8[..1024]&,
    auth_val:     u8[..256]&,
    host_val:     u8[..256]&,
) -> bool {
    let fname = field.name[..];
    let fval = field.value[..];
    guard http::is_valid_header_name_h2(fname) && !has_ctl_chars(fval) else { return false; }
    if fname.len > 0 && fname[0] == ':' {
        guard !seen_regular else { return false; }
        return validate_push_promise_pseudo_field(field, counts, req_method, req_path, auth_val);
    }
    seen_regular = true;
    guard !is_forbidden_connection_header(fname, fval) && !fname.eq_ascii_fold("content-length") else {
        return false;
    }
    if fname.eq_ascii_fold("host") {
        guard counts.host == 0 && is_valid_authority_or_host(fval) && host_val.try_set(fval) else {
            return false;
        }
        counts.host = 1;
    }
    return true;
}

// RFC 9114 Section 4.6: Server Push - Promised requests MUST include :method, :scheme, :authority, and :path, and MUST NOT use CONNECT.
fn validate_h3_push_promise_fields<F>(
    conn:           http3::Connection&,
    decoded_fields: const F&,
) -> u64 {
    if decoded_fields.len == 0 {
        return rfc::H3_ERR_NO_ERROR;
    }
    var seen_regular = false;
    var counts = H3HeaderCounts { .. };
    var req_method: u8[..16]   = [];
    var req_path:   u8[..1024] = [];
    var auth_val:   u8[..256]  = [];
    var host_val:   u8[..256]  = [];

    for &f in decoded_fields {
        let ok = validate_single_push_promise_field(
            f, seen_regular, counts, req_method, req_path, auth_val, host_val,
        );
        guard ok else {
            conn.state = http3::ConnState.Closed;
            conn.error_code = rfc::H3_ERR_GENERAL_PROTOCOL;
            return rfc::H3_ERR_GENERAL_PROTOCOL;
        }
    }

    let ok_host = counts.host == 0 || auth_val[..].eq_ascii_fold(host_val[..]);
    let ok_req = counts.pseudo_method == 1 && counts.pseudo_scheme == 1 &&
        counts.pseudo_authority == 1 && counts.pseudo_path == 1 &&
        counts.pseudo_status == 0 && counts.pseudo_protocol == 0;
    let bad_asterisk = req_path[..] == "*" && req_method[..] != "OPTIONS";
    guard ok_host && ok_req && !bad_asterisk else {
        conn.state = http3::ConnState.Closed;
        conn.error_code = rfc::H3_ERR_GENERAL_PROTOCOL;
        return rfc::H3_ERR_GENERAL_PROTOCOL;
    }
    return rfc::H3_ERR_NO_ERROR;
}

fn compute_header_fields_hash<F>(fields: const F&) -> u64 {
    var h: u64 = 0xcbf29ce484222325;
    for &f in fields {
        h = core::wyhash64(f.name[..], h ^ 0x9e3779b97f4a7c15);
        h = core::wyhash64(f.value[..], h ^ 0x517cc1b727220a95);
    }
    return h;
}

// RFC 9114 Section 7.2.5: PUSH_PROMISE - Receiving a duplicate push ID with different header fields MUST be treated as H3_GENERAL_PROTOCOL_ERROR.
fn record_or_verify_promised_push<F>(
    conn:           http3::Connection&,
    push_id:        u64,
    decoded_fields: const F&,
) -> u64 {
    let field_hash = compute_header_fields_hash(decoded_fields);
    for &rec in conn.promised_pushes {
        if rec.push_id == push_id {
            guard rec.field_hash == field_hash else {
                conn.state = http3::ConnState.Closed;
                conn.error_code = rfc::H3_ERR_GENERAL_PROTOCOL;
                return rfc::H3_ERR_GENERAL_PROTOCOL;
            }
            return rfc::H3_ERR_NO_ERROR;
        }
    }
    let new_rec = PromisedPushRecord { push_id: push_id, field_hash: field_hash };
    if !conn.promised_pushes.try_push(new_rec) && conn.promised_pushes.len > 0 {
        conn.promised_pushes.remove_at(0);
        let _ = conn.promised_pushes.try_push(new_rec);
    }
    return rfc::H3_ERR_NO_ERROR;
}

fn handle_bidi_push_promise(conn: http3::Connection&, s_idx: i32, payload: const u8[:]) -> u64 {
    // Clients MUST NOT send PUSH_PROMISE frames to servers
    if conn.role == http3::ConnRole.Server {
        conn.state = http3::ConnState.Closed;
        conn.error_code = rfc::H3_ERR_FRAME_UNEXPECTED;
        return rfc::H3_ERR_FRAME_UNEXPECTED;
    }
    guard payload.len > 0 && s_idx >= 0 && s_idx < conn.streams.len else {
        conn.state = http3::ConnState.Closed;
        conn.error_code = rfc::H3_ERR_FRAME_ERROR;
        return rfc::H3_ERR_FRAME_ERROR;
    }
    let push_id, qpack_off, ok_p = quic::decode_varint(payload, 0);
    if !ok_p {
        conn.state = http3::ConnState.Closed;
        conn.error_code = rfc::H3_ERR_FRAME_ERROR;
        return rfc::H3_ERR_FRAME_ERROR;
    }
    // Push ID MUST NOT exceed advertised MAX_PUSH_ID (or any push if never advertised)
    if !conn.max_push_id_sent || push_id > conn.max_push_id_advertised {
        conn.state = http3::ConnState.Closed;
        conn.error_code = rfc::H3_ERR_ID_ERROR;
        return rfc::H3_ERR_ID_ERROR;
    }
    let qpack_data = payload[(qpack_off as i64)..];
    var dec_tbl .= conn.qpack_table;
    if conn.local_qpack_enc_activated {
        dec_tbl .= conn.qpack_dec_table;
    }
    var decoded_fields: http3::HeaderField[..128] = [];
    let q_err = http3::decode_or_block_qpack_section(
        dec_tbl,
        conn.streams[s_idx].stream_id,
        qpack_data,
        decoded_fields,
        conn.local_settings.max_field_section_size,
        true,
        push_id,
    );
    if q_err != http3::QpackError.None && q_err != http3::QpackError.StreamBlocked {
        conn.state = http3::ConnState.Closed;
        conn.error_code = rfc::H3_ERR_QPACK_DECOMPRESSION_FAILED;
        return rfc::H3_ERR_QPACK_DECOMPRESSION_FAILED;
    }
    if q_err == http3::QpackError.None {
        let v_err = validate_h3_push_promise_fields(conn, decoded_fields);
        guard v_err == rfc::H3_ERR_NO_ERROR else { return v_err; }
        let dup_err = record_or_verify_promised_push(conn, push_id, decoded_fields);
        guard dup_err == rfc::H3_ERR_NO_ERROR else { return dup_err; }
    }
    if !conn.has_promised_push_id || push_id > conn.max_promised_push_id {
        conn.max_promised_push_id = push_id;
    }
    conn.has_promised_push_id = true;
    return rfc::H3_ERR_NO_ERROR;
}

fn store_bidi_trailers<F>(conn: http3::Connection&, s_idx: i32, decoded_fields: const F&) -> u64 {
    let t_err = validate_h3_trailers(conn, decoded_fields);
    guard t_err == rfc::H3_ERR_NO_ERROR else { return t_err; }
    conn.streams[s_idx].trailers.clear();
    for &f in decoded_fields {
        guard http::append_header(conn.streams[s_idx].trailers, f.name[..], f.value[..]) else {
            conn.state = http3::ConnState.Closed;
            conn.error_code = rfc::H3_ERR_EXCESSIVE_LOAD;
            return rfc::H3_ERR_EXCESSIVE_LOAD;
        }
    }
    conn.streams[s_idx].trailers_received = true;
    return rfc::H3_ERR_NO_ERROR;
}

fn handle_bidi_headers(
    conn:    http3::Connection&,
    s_idx:   i32,
    payload: const u8[:],
) -> u64 {
    // RFC 9114 §4.1: Extra HEADERS frame after trailers is forbidden
    if conn.streams[s_idx].trailers_received {
        conn.state = http3::ConnState.Closed;
        conn.error_code = rfc::H3_ERR_FRAME_UNEXPECTED;
        return rfc::H3_ERR_FRAME_UNEXPECTED;
    }

    var dec_tbl .= conn.qpack_table;
    if conn.local_qpack_enc_activated {
        dec_tbl .= conn.qpack_dec_table;
    }
    var decoded_fields: http3::HeaderField[..128] = [];
    let q_err = http3::decode_or_block_qpack_section(
        dec_tbl,
        conn.streams[s_idx].stream_id,
        payload,
        decoded_fields,
        conn.local_settings.max_field_section_size,
    );
    if q_err == http3::QpackError.StreamBlocked {
        return rfc::H3_ERR_NO_ERROR;
    }
    if q_err != http3::QpackError.None {
        conn.state = http3::ConnState.Closed;
        conn.error_code = rfc::H3_ERR_QPACK_DECOMPRESSION_FAILED;
        return rfc::H3_ERR_QPACK_DECOMPRESSION_FAILED;
    }

    let is_trailer = conn.streams[s_idx].headers_received &&
        (conn.role == http3::ConnRole.Server || conn.streams[s_idx].status_code >= 200);
    if is_trailer {
        return store_bidi_trailers(conn, s_idx, decoded_fields);
    }

    let v_err = http3::validate_h3_headers(conn, s_idx, decoded_fields);
    guard v_err == rfc::H3_ERR_NO_ERROR else { return v_err; }
    conn.streams[s_idx].headers.clear();
    for &f in decoded_fields {
        if f.name.len > 0 && f.name[0] != ':' {
            guard http::append_header(conn.streams[s_idx].headers, f.name[..], f.value[..]) else {
                conn.state = http3::ConnState.Closed;
                conn.error_code = rfc::H3_ERR_EXCESSIVE_LOAD;
                return rfc::H3_ERR_EXCESSIVE_LOAD;
            }
        }
    }
    return rfc::H3_ERR_NO_ERROR;
}

fn check_h3_empty_streak(conn: http3::Connection&, payload_len: u64) -> bool {
    if payload_len == 0 {
        conn.empty_frame_streak = core::add_sat_u32(conn.empty_frame_streak, 1);
        return conn.empty_frame_streak <= MAX_H3_EMPTY_FRAME_STREAK;
    }
    conn.empty_frame_streak = 0;
    return true;
}

fn is_h3_data_allowed(stream: const http3::StreamEntry&) -> bool {
    if !stream.headers_received || stream.trailers_received {
        return false;
    }
    let sc = stream.status_code;
    if sc == 204 || sc == 304 || (sc >= 100 && sc < 200) {
        return false;
    }
    if sc > 0 && stream.req_method[..] == "HEAD" {
        return false;
    }
    return true;
}

fn append_stream_body(stream: http3::StreamEntry&, payload: const u8[:]) -> u64 {
    guard stream.received_body.try_append(payload) else {
        return rfc::H3_ERR_EXCESSIVE_LOAD;
    }
    stream.body_received_len = core::add_sat_u64(stream.body_received_len, payload.len as u64);

    if stream.content_length >= 0 && stream.body_received_len > (stream.content_length as u64) {
        return rfc::H3_ERR_GENERAL_PROTOCOL;
    }
    return rfc::H3_ERR_NO_ERROR;
}

fn handle_bidi_data(
    conn:        http3::Connection&,
    s_idx:       i32,
    payload_len: u64,
    payload:     const u8[:],
) -> u64 {
    guard check_h3_empty_streak(conn, payload_len) else {
        conn.state = http3::ConnState.Closed;
        conn.error_code = rfc::H3_ERR_EXCESSIVE_LOAD;
        return rfc::H3_ERR_EXCESSIVE_LOAD;
    }

    guard s_idx >= 0 && s_idx < conn.streams.len else {
        conn.state = http3::ConnState.Closed;
        conn.error_code = rfc::H3_ERR_GENERAL_PROTOCOL;
        return rfc::H3_ERR_GENERAL_PROTOCOL;
    }

    guard is_h3_data_allowed(conn.streams[s_idx]) else {
        conn.state = http3::ConnState.Closed;
        conn.error_code = rfc::H3_ERR_FRAME_UNEXPECTED;
        return rfc::H3_ERR_FRAME_UNEXPECTED;
    }

    let b_err = append_stream_body(conn.streams[s_idx], payload);
    guard b_err == rfc::H3_ERR_NO_ERROR else {
        conn.state = http3::ConnState.Closed;
        conn.error_code = b_err;
        return b_err;
    }
    return rfc::H3_ERR_NO_ERROR;
}

fn dispatch_bidi_stream_frame(
    conn:    http3::Connection&,
    s_idx:   i32,
    hdr:     const http3::FrameHeader&,
    payload: const u8[:],
) -> u64 {
    if !rfc::is_allowed_on_request_stream(hdr.frame_type) {
        conn.state = http3::ConnState.Closed;
        conn.error_code = rfc::H3_ERR_FRAME_UNEXPECTED;
        return rfc::H3_ERR_FRAME_UNEXPECTED;
    }
    if hdr.frame_type == rfc::H3_FRAME_PUSH_PROMISE {
        return handle_bidi_push_promise(conn, s_idx, payload);
    }
    if hdr.frame_type == rfc::H3_FRAME_HEADERS {
        return handle_bidi_headers(conn, s_idx, payload);
    }
    if hdr.frame_type == rfc::H3_FRAME_DATA {
        return handle_bidi_data(conn, s_idx, hdr.payload_len, payload);
    }
    return rfc::H3_ERR_NO_ERROR;
}

inline fn buffer_partial_bidi_frame(conn: http3::Connection&, s_idx: i32, rem: const u8[:], fin: bool) -> u64 {
    guard !fin && conn.streams[s_idx].rx_partial_buf.try_set(rem) else {
        conn.state = http3::ConnState.Closed;
        conn.error_code = rfc::H3_ERR_FRAME_ERROR;
        return rfc::H3_ERR_FRAME_ERROR;
    }
    return rfc::H3_ERR_NO_ERROR;
}

inline fn prepend_partial_bidi_rx(
    conn:     http3::Connection&,
    s_idx:    i32,
    data:     const u8[:],
    work_buf: u8[..8192]&,
) -> bool {
    guard conn.streams[s_idx].rx_partial_buf.len > 0 else { return true; }
    guard work_buf.try_append(conn.streams[s_idx].rx_partial_buf[..]) && work_buf.try_append(data) else {
        conn.state = http3::ConnState.Closed;
        conn.error_code = rfc::H3_ERR_FRAME_ERROR;
        return false;
    }
    conn.streams[s_idx].rx_partial_buf.clear();
    return true;
}

// Parses and dispatches a single bidirectional HTTP/3 frame at `offset`, advancing `offset` past the frame.
// Leaves `offset` at `frame_start` when buffering a partial frame; returns `(err_code, stop_loop)`.
//
// Example:
//   buf = [0x00, 0x02, 'o', 'k'], offset = 0, fin = true
//   returns: (H3_ERR_NO_ERROR, false), offset = 4
inline fn step_bidi_stream_frame(
    conn:   http3::Connection&,
    s_idx:  i32,
    buf:    const u8[:],
    offset: u64&,
    fin:    bool,
) -> u64, bool {
    let frame_start = offset;
    let hdr, ok_hdr = http3::parse_frame_header(buf, offset);
    if !ok_hdr {
        let rem = buf[(frame_start as i64)..];
        guard rem.len < 16 else {
            conn.state = http3::ConnState.Closed;
            conn.error_code = rfc::H3_ERR_FRAME_ERROR;
            return rfc::H3_ERR_FRAME_ERROR, true;
        }
        return buffer_partial_bidi_frame(conn, s_idx, rem, fin), true;
    }
    if !rfc::is_allowed_on_request_stream(hdr.frame_type) {
        conn.state = http3::ConnState.Closed;
        conn.error_code = rfc::H3_ERR_FRAME_UNEXPECTED;
        return rfc::H3_ERR_FRAME_UNEXPECTED, true;
    }
    offset = core::add_sat_u64(offset, hdr.header_len);
    let end_off = core::add_sat_u64(offset, hdr.payload_len);
    if end_off > (buf.len as u64) {
        guard core::add_sat_u64(hdr.header_len, hdr.payload_len) <= 4096 else {
            conn.state = http3::ConnState.Closed;
            conn.error_code = rfc::H3_ERR_FRAME_ERROR;
            return rfc::H3_ERR_FRAME_ERROR, true;
        }
        return buffer_partial_bidi_frame(conn, s_idx, buf[(frame_start as i64)..], fin), true;
    }
    let payload = buf[(offset as i64)..(end_off as i64)];
    offset = end_off;
    let f_err = dispatch_bidi_stream_frame(conn, s_idx, hdr, payload);
    return f_err, f_err != rfc::H3_ERR_NO_ERROR;
}

// RFC 9204 Section 2.2.1: Blocked Decoding - Wait for Required Insert Count entries before processing remaining frames on the blocked stream.
fn handle_bidi_stream_frames(
    conn:  http3::Connection&,
    s_idx: i32,
    data:  const u8[:],
    fin:   bool = true,
) -> u64 {
    var work_buf: u8[..8192] = [];
    guard prepend_partial_bidi_rx(conn, s_idx, data, work_buf) else {
        return rfc::H3_ERR_FRAME_ERROR;
    }
    let buf = if work_buf.len > 0 { work_buf[..] } else { data };
    var offset: u64 = 0;
    while offset < (buf.len as u64) {
        var dec_tbl .= conn.qpack_table;
        if conn.local_qpack_enc_activated {
            dec_tbl .= conn.qpack_dec_table;
        }
        if http3::qpack_is_stream_blocked(dec_tbl, conn.streams[s_idx].stream_id) {
            guard conn.streams[s_idx].blocked_wire.try_append(buf[(offset as i64)..]) else {
                conn.state = http3::ConnState.Closed;
                conn.error_code = rfc::H3_ERR_EXCESSIVE_LOAD;
                return rfc::H3_ERR_EXCESSIVE_LOAD;
            }
            return rfc::H3_ERR_NO_ERROR;
        }
        let step_err, done = step_bidi_stream_frame(conn, s_idx, buf, offset, fin);
        if done {
            return step_err;
        }
    }
    return rfc::H3_ERR_NO_ERROR;
}

inline fn is_better_h3_tx_candidate(
    cand: const http3::StreamEntry&,
    best: const http3::StreamEntry&,
) -> bool {
    if cand.priority.urgency != best.priority.urgency {
        return cand.priority.urgency < best.priority.urgency;
    }
    if cand.priority.incremental {
        if cand.last_scheduled_cycle != best.last_scheduled_cycle {
            return cand.last_scheduled_cycle < best.last_scheduled_cycle;
        }
    }
    return cand.stream_id < best.stream_id;
}
