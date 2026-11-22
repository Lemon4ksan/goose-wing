// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Internal HTTP/1.1 response status, header, date-cache, and chunked serializers.
namespace server_internal;

import std;
import core;
import rfc.http;
import http.headers;
import http.request;
import http.response;
import client.internal;
import .profiler;
import .h1_codec;

// Serializes an HTTP/1.1 response status line (RFC 9112 Section 4).
fn serialize_status_line<B>(status_code: i32, out: B&) {
    let pre = rfc::status_line_h1(status_code);
    if pre.len > 0 {
        out.append(pre);
        return;
    }
    out.append("HTTP/1.1 ");
    var code_buf: u8[16] = [0; 16];
    let n = core::fast_u64toa(status_code as u64, code_buf[..]);
    if n > 0 {
        out.append(code_buf[..n]);
    } else {
        status_code.format_i64_dec(out);
    }
    out.push(' ');
    out.append(rfc::status_phrase(status_code));
    out.append("\r\n");
}

fn serialize_server_header<B>(server_name: const u8[:], out: B&) {
    guard server_name.len > 0 else { return; }
    if server_name == "goose-wing" {
        out.append(server::DEFAULT_SERVER_HEADER);
        return;
    }
    out.append("Server: ");
    out.append(server_name);
    out.append("\r\n");
}

inline fn serialize_trailer_names_header<B>(trailers: const http::HeaderMap&, out_wire: B&) {
    guard trailers.entries.len > 0 else { return; }
    out_wire.append("Trailer: ");
    for i in trailers.entries.len {
        if i > 0 { out_wire.append(", "); }
        out_wire.append(http::entry_name(trailers, trailers.entries[i]));
    }
    out_wire.append("\r\n");
}

fn serialize_http1_chunked_response<Res, B>(
    res:         const Res&,
    server_name: const u8[:],
    chunk_size:  i64,
    out_wire:    B&,
) {
    serialize_status_line(res.status_code, out_wire);
    serialize_server_header(server_name, out_wire);
    if !res.has_header("date") {
        out_wire.append(server::get_cached_http_date_header(0));
    }
    out_wire.append("Transfer-Encoding: chunked\r\n");
    serialize_trailer_names_header(res.trailers, out_wire);
    serialize_chunked_header_fields(res.headers, res.trailers.entries.len > 0, out_wire);
    if !res.has_header("connection") {
        out_wire.append("Connection: keep-alive\r\n");
    }
    out_wire.append("\r\n");
    client::encode_chunked_payload(res.body[..], res.trailers, chunk_size, out_wire);
}

const HTTP1_200_SERVER_GOOSE: const u8[:] = "HTTP/1.1 200 OK\r\nServer: goose-wing\r\n";

const HTTP1_200_SERVER_GOOSE_V1: const u8[:] = "HTTP/1.1 200 OK\r\nServer: goose-wing/1.0\r\n";

fn update_server_cached_date(
    date:        server::CachedHttpDate&,
    now_sec:     i64,
    server_name: const u8[:] = "goose-wing",
) {
    let tick_sec = if now_sec > 0 { now_sec } else { core::now().wall_sec };
    if date.header_str.len == 0 || date.last_sec != tick_sec {
        date.last_sec = tick_sec;
        date.last_tsc = server::prof_rdtsc();
        let wall_sec = if now_sec >= 1577836800 { now_sec } else { core::now().wall_sec };
        date.header_str.clear();
        date.header_str.append("Date: ");
        core::format_http(date.header_str, core::unix(wall_sec, 0));
        date.header_str.append("\r\n");

        date.fast_prefix.clear();
        date.fast_prefix.append("HTTP/1.1 200 OK\r\n");
        serialize_server_header(server_name, date.fast_prefix);
        date.fast_prefix.append(date.header_str[..]);

        date.fast_prefix_v1.clear();
        date.fast_prefix_v1.append(HTTP1_200_SERVER_GOOSE_V1);
        date.fast_prefix_v1.append(date.header_str[..]);
    }
}

var g_compat_date: server::CachedHttpDate = server::CachedHttpDate { .. };

// Formats Content-Length decimal header fast without divisions for common lengths.
const CL_HEADER_PREFIX: const u8[:] = "Content-Length: ";

fn serialize_content_length_header<B>(body_len: i64, out: B&) {
    if body_len <= 0 {
        out.append("Content-Length: 0\r\n");
        return;
    }
    var buf: u8[48] = [0; 48];
    for i in 16 {
        buf[i] = CL_HEADER_PREFIX[i];
    }
    let n = core::fast_u64toa(body_len as u64, buf[16..]);
    let pos = core::add_sat_i64(16, n);
    guard pos <= 46 else { return; }
    buf[pos] = '\r';
    buf[core::add_sat_i64(pos, 1)] = '\n';
    out.append(buf[..core::add_sat_i64(pos, 2)]);
}

inline fn response_header_presence_bit(hname: const u8[:]) -> u16 {
    if hname.eq_ascii_fold("date") { return http::RES_PRESENCE_DATE; }
    if hname.eq_ascii_fold("server") { return http::RES_PRESENCE_SERVER; }
    if hname.eq_ascii_fold("connection") { return http::RES_PRESENCE_CONNECTION; }
    if hname.eq_ascii_fold("content-type") { return http::RES_PRESENCE_CONTENT_TYPE; }
    if hname.eq_ascii_fold("content-length") { return http::RES_PRESENCE_CONTENT_LENGTH; }
    if hname.eq_ascii_fold("transfer-encoding") { return http::RES_PRESENCE_TRANSFER_ENCODING; }
    return 0;
}

fn detect_response_presence_mask(headers: const http::HeaderMap&) -> u16 {
    var mask: u16 = 0;
    for &e in headers.entries {
        mask = mask | response_header_presence_bit(http::entry_name(headers, e));
    }
    return mask;
}

struct ResponseHeaderFilter {
    skip_cl:         bool = false,
    is_no_te_status: bool = false,
}

inline fn emit_response_header_entry<B>(
    hname:  const u8[:],
    hval:   const u8[:],
    filter: ResponseHeaderFilter,
    out:    B&,
) {
    let nlen = hname.len;
    if filter.skip_cl && nlen == 14 && hname.eq_ascii_fold("content-length") { return; }
    if filter.is_no_te_status && nlen == 17 && hname.eq_ascii_fold("transfer-encoding") { return; }
    if nlen == 12 && hname.eq_ascii_fold(rfc::HEADER_CONTENT_TYPE) {
        if hval == rfc::MIME_TEXT_PLAIN {
            out.append(rfc::HTTP1_CT_TEXT_PLAIN);
            return;
        }
        if hval == rfc::MIME_APPLICATION_JSON {
            out.append(rfc::HTTP1_CT_APP_JSON);
            return;
        }
    }
    out.append(hname);
    out.append(": ");
    out.append(hval);
    out.append("\r\n");
}

fn serialize_response_headers_list<B>(headers: const http::HeaderMap&, status_code: i32, has_te: bool, out: B&) {
    // RFC 9110 Section 8.6: Content-Length - Forbid on 1xx and 204 responses; allow on 304 Not Modified.
    let forbid_wire_cl = (status_code >= 100 && status_code < 200) || status_code == 204;
    let filter = ResponseHeaderFilter {
        skip_cl:         forbid_wire_cl || has_te,
        is_no_te_status: forbid_wire_cl || status_code == 304,
    };
    for &e in headers.entries {
        emit_response_header_entry(
            http::entry_name(headers, e),
            http::entry_value(headers, e),
            filter,
            out,
        );
    }
}

fn serialize_payload_too_large_error<B>(server_name: const u8[:], wire_out: B&) {
    var err_resp = http::Response { status_code: rfc::STATUS_CONTENT_TOO_LARGE, .. };
    http::set_header(err_resp, "Connection", "close");
    server::serialize_http1_response(err_resp, server_name, wire_out);
}

fn format_local_http_date(out: u8[..64]&, now_sec: i64) {
    let _ = out.try_set(server::get_cached_http_date_header(now_sec));
}

inline fn serialize_http1_fast_single_ct<Res, B>(
    res:          const Res&,
    server_name:  const u8[:],
    eff_body_len: i64,
    mask:         u16,
    out_wire:     B&,
) -> bool {
    guard res.status_code == 200 && (server_name == "goose-wing" || server_name == "goose-wing/1.0") else {
        return false;
    }
    guard mask == http::RES_PRESENCE_CONTENT_TYPE
        && res.headers.entries.len == 1
        && res.trailers.entries.len == 0 else {
        return false;
    }
    let h0_name = http::entry_name(res.headers, res.headers.entries[0]);
    guard h0_name.eq_ascii_fold("content-type") else { return false; }
    if server_name == "goose-wing" {
        out_wire.append(g_compat_date.fast_prefix[..]);
    } else {
        out_wire.append(g_compat_date.fast_prefix_v1[..]);
    }
    serialize_content_length_header(eff_body_len, out_wire);
    let h0_val = http::entry_value(res.headers, res.headers.entries[0]);
    if h0_val == rfc::MIME_TEXT_PLAIN {
        out_wire.append(rfc::HTTP1_CT_TEXT_PLAIN);
    } else if h0_val == rfc::MIME_APPLICATION_JSON {
        out_wire.append(rfc::HTTP1_CT_APP_JSON);
    } else {
        out_wire.append(h0_name);
        out_wire.append(": ");
        out_wire.append(h0_val);
        out_wire.append("\r\n");
    }
    out_wire.append(rfc::HTTP1_CONN_KEEP_ALIVE);
    return true;
}

inline fn policy_omits_server_header(policy: server::ServerHeaderPolicy) -> bool {
    return policy == server::ServerHeaderPolicy.OmitServer || policy == server::ServerHeaderPolicy.OmitBoth;
}

inline fn policy_omits_date_header(policy: server::ServerHeaderPolicy) -> bool {
    return policy == server::ServerHeaderPolicy.OmitDate || policy == server::ServerHeaderPolicy.OmitBoth;
}

inline fn serialize_http1_status_and_meta<B>(
    status_code:   i32,
    server_name:   const u8[:],
    date_hdr:      const u8[:],
    mask:          u16,
    header_policy: server::ServerHeaderPolicy,
    out_wire:      B&,
) {
    let omit_server = policy_omits_server_header(header_policy);
    let omit_date = policy_omits_date_header(header_policy);
    if header_policy == server::ServerHeaderPolicy.Standard && status_code == 200
        && (mask & (http::RES_PRESENCE_SERVER | http::RES_PRESENCE_DATE)) == 0 {
        if server_name == "goose-wing" {
            out_wire.append(g_compat_date.fast_prefix[..]);
            return;
        }
        if server_name == "goose-wing/1.0" {
            out_wire.append(g_compat_date.fast_prefix_v1[..]);
            return;
        }
    }
    serialize_status_line(status_code, out_wire);
    if !omit_server && (mask & http::RES_PRESENCE_SERVER) == 0 {
        serialize_server_header(server_name, out_wire);
    }
    if !omit_date && (mask & http::RES_PRESENCE_DATE) == 0 {
        out_wire.append(date_hdr);
    }
}

inline fn serialize_chunked_header_fields<B>(
    headers:      const http::HeaderMap&,
    has_trailers: bool,
    out_wire:     B&,
) {
    for &e in headers.entries {
        let hname = http::entry_name(headers, e);
        let skip = hname.eq_ascii_fold("content-length")
            || hname.eq_ascii_fold("transfer-encoding")
            || (has_trailers && hname.eq_ascii_fold("trailer"));
        guard !skip else { continue; }
        out_wire.append(hname);
        out_wire.append(": ");
        out_wire.append(http::entry_value(headers, e));
        out_wire.append("\r\n");
    }
}

fn serialize_http1_chunked_with_policy<Res, B>(
    res:           const Res&,
    server_name:   const u8[:],
    chunk_size:    i64,
    out_wire:      B&,
    header_policy: server::ServerHeaderPolicy,
) {
    if header_policy == server::ServerHeaderPolicy.Standard {
        serialize_http1_chunked_response(res, server_name, chunk_size, out_wire);
        return;
    }
    serialize_status_line(res.status_code, out_wire);
    if !policy_omits_server_header(header_policy) {
        serialize_server_header(server_name, out_wire);
    }
    if !policy_omits_date_header(header_policy) && !res.has_header("date") {
        out_wire.append(server::get_cached_http_date_header(0));
    }
    out_wire.append("Transfer-Encoding: chunked\r\n");
    if res.trailers.entries.len > 0 {
        out_wire.append("Trailer: ");
        for i in res.trailers.entries.len {
            if i > 0 { out_wire.append(", "); }
            out_wire.append(http::entry_name(res.trailers, res.trailers.entries[i]));
        }
        out_wire.append("\r\n");
    }
    serialize_chunked_header_fields(res.headers, res.trailers.entries.len > 0, out_wire);
    if !res.has_header("connection") {
        out_wire.append("Connection: keep-alive\r\n");
    }
    out_wire.append("\r\n");
    client::encode_chunked_payload(res.body[..], res.trailers, chunk_size, out_wire);
}
