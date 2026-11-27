// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Internal pooled HTTP/1.1 and HTTP/2 hop dispatch, H2 request encoding, and H2 response frame loops.
namespace client_internal;

import std;
import core;
import rfc.http;
import rfc.h2;
import http.request;
import http.response;
import http.headers;
import net.pool;
import net.transport;
import http2.framing;
import http2.hpack;
import wire.types;
import wire.h1_exchange;
import wire.hpack;
import wire.h2;
import client.client;
import .dns_dial_internal;
import .hop_context_internal;
import .stage_bricks_internal;

fn dispatch_pooled_h1_hop(
    session:     client::Session&,
    conn_id:     i32,
    curr_method: const u8[:],
    ctx:         RequestExecutionContext&,
    current_url: const core::Url&,
    is_https:    bool,
    origin_buf:  const u8[:],
    curr_path:   const u8[:],
    now_sec:     i64,
    now_ns:      i64,
    resp:        http::Response&,
) -> bool {
    let c_idx = session.pool.find_connection_index(conn_id);
    guard c_idx >= 0 else { return false; }

    var released = false;
    defer if !released { session.pool.close_pooled_connection(conn_id); };

    var hop_req = http::Request { .. };
    let _ = hop_req.method.try_set(curr_method);
    http::copy_headers(ctx.headers, hop_req.headers);
    hop_req.body.append(ctx.body[..]);

    let eff_timeout = calc_effective_timeout_ms(session.timeout_ms, ctx.timeout_ms);
    let ok_ex, keep_alive = wing::execute_h1_exchange(
        session.pool.conns[c_idx],
        hop_req,
        current_url,
        resp,
        eff_timeout,
    );
    guard ok_ex else { return false; }

    resp.effective_url = copy(current_url.href);
    http::copy_headers(ctx.headers, resp.sent_headers);
    ingest_transport_response_headers(
        session, current_url, is_https, origin_buf, curr_path, now_sec, resp,
    );
    if keep_alive && resp.is_http1() && resp.status_code != rfc::STATUS_SWITCHING_PROTOCOLS {
        session.pool.release_connection(conn_id, now_ns);
        released = true;
    }
    return true;
}

enum H2RecvStatus {
    Continue,
    Complete,
    Error,
}

struct H2RecvState {
    got_hdrs:   bool               = false,
    saw_goaway: bool               = false,
    await_cont: bool               = false,
    cont_hdr:   http2::FrameHeader = http2::FrameHeader { .. },
    cont_buf:   u8[..16384]        = [],
}

fn build_h2_request_pseudo_headers(
    curr_method: const u8[:],
    current_url: const core::Url&,
    is_https:    bool,
    headers:     const http::HeaderMap&,
) -> http2::PseudoHeaders, bool {
    var pseudo = http2::PseudoHeaders { .. };
    var auth_buf: u8[..300] = [];
    core::format_outgoing_host(current_url, auth_buf);
    let auth_str = auth_buf[..];
    let proto_hdr = http::find_header(headers, ":protocol");
    if curr_method.eq_ascii_fold("CONNECT") && proto_hdr.len == 0 {
        pseudo.has_method = true;
        pseudo.has_authority = true;
        let ok_c = pseudo.method.try_set("CONNECT") && pseudo.authority.try_set(auth_str);
        return pseudo, ok_c;
    }
    let scheme_str: const u8[:] = if is_https { "https" } else { "http" };
    var path_buf: u8[..2048] = [];
    guard format_h2_request_target_path(current_url, path_buf) else { return pseudo, false; }

    pseudo.has_method = true;
    pseudo.has_scheme = true;
    pseudo.has_authority = true;
    pseudo.has_path = true;
    guard pseudo.method.try_set(curr_method) &&
        pseudo.scheme.try_set(scheme_str) &&
        pseudo.authority.try_set(auth_str) &&
        pseudo.path.try_set(path_buf[..]) else {
        return pseudo, false;
    }
    if proto_hdr.len > 0 {
        pseudo.has_protocol = true;
        guard pseudo.protocol.try_set(proto_hdr) else { return pseudo, false; }
    }
    return pseudo, true;
}

fn encode_h2_request<B>(
    curr_method:  const u8[:],
    current_url:  const core::Url&,
    is_https:     bool,
    ctx:          const RequestExecutionContext&,
    enc_dt:       http2::DynamicTable&,
    stream_id:    u32,
    send_preface: bool,
    out:          B&,
) -> bool {
    guard ctx.body.len <= (rfc::H2_DEFAULT_WINDOW_SIZE as i64) else { return false; }
    let pseudo, ok_pseudo = build_h2_request_pseudo_headers(
        curr_method, current_url, is_https, ctx.headers,
    );
    guard ok_pseudo else { return false; }

    let saved_dt = copy(enc_dt);
    var committed = false;
    defer if !committed { out.clear(); enc_dt = copy(saved_dt); };
    out.clear();

    if send_preface {
        guard out.try_append(rfc::H2_CLIENT_PREFACE) else { return false; }
        let empty_settings: wire::WireSetting[..1] = [];
        guard wire::encode_settings_frame(empty_settings[..], out) else { return false; }
    }
    guard wire::encode_h2_headers_frame_from_map(
        enc_dt, stream_id, pseudo, ctx.headers, ctx.body.len == 0, out, 16384,
    ) else { return false; }
    var rem = ctx.body[..];
    while rem.len > 0 {
        let chunk_len = min(rem.len, rfc::H2_DEFAULT_MAX_FRAME_SIZE as i64);
        guard wire::encode_data_frame(stream_id, rem[..chunk_len], chunk_len >= rem.len, out) else {
            return false;
        }
        rem = rem[chunk_len..];
    }
    committed = true;
    return true;
}

fn process_h2_control_frame<B>(
    hdr:     const http2::FrameHeader&,
    payload: const u8[:],
    out:     B&,
) {
    if hdr.frame_type == rfc::H2_FRAME_SETTINGS && (hdr.flags & rfc::H2_FLAG_ACK) == 0 {
        let ack_hdr = wire::WireFrameHeader {
            length: 0, frame_type: rfc::H2_FRAME_SETTINGS, flags: rfc::H2_FLAG_ACK, stream_id: 0,
        };
        let _ = wire::encode_frame_header(ack_hdr, out);
    } else if hdr.frame_type == rfc::H2_FRAME_PING && (hdr.flags & rfc::H2_FLAG_ACK) == 0 && payload.len == 8 {
        var ping_data: u8[8] = [0; 8];
        for i in 8 { ping_data[i] = payload[i]; }
        let _ = wire::encode_ping_frame(ping_data, true, out);
    }
}

inline fn record_h2_rst_stream_error(payload: const u8[:], resp: http::Response&) {
    guard payload.len >= 4 else { return; }
    let rst_code = core::read_be_u32(payload, 0);
    var rst_buf: u8[..16] = [];
    rst_code.format_u64_dec(rst_buf);
    let _ = http::append_header(resp.trailers, "x-wing-h2-rst-code", rst_buf[..]);
}

inline fn verify_h2_response_content_length(resp: const http::Response&, is_head: bool) -> bool {
    if is_head || rfc::is_empty_body_status(resp.status_code) {
        return true;
    }
    let cl_hdr = http::header(resp, "Content-Length").trim_lws();
    if cl_hdr.len == 0 {
        return true;
    }
    let cl_val, ok_cl = cl_hdr.parse_u64_dec();
    return ok_cl && (resp.body.len as u64) == cl_val;
}

inline fn apply_initial_h2_response_headers(
    hdr:      const http2::FrameHeader&,
    frag:     const u8[:],
    dec_dt:   http2::DynamicTable&,
    resp:     http::Response&,
    got_hdrs: bool&,
) -> bool {
    var pseudo = http2::PseudoHeaders { .. };
    let d_err = wire::decode_hpack_to_map(dec_dt, frag, pseudo, resp.headers, 8192, true);
    guard d_err == rfc::H2_ERR_NO_ERROR && pseudo.has_status &&
        pseudo.status != rfc::STATUS_SWITCHING_PROTOCOLS else {
        return false;
    }
    resp.status_code = pseudo.status;
    for &e in resp.headers.entries { http::update_response_presence(resp, http::entry_name(resp.headers, e)); }
    if pseudo.status >= 100 && pseudo.status < 200 {
        guard (hdr.flags & rfc::H2_FLAG_END_STREAM) == 0 else { return false; }
        resp.headers.clear();
        resp.presence_mask = 0;
    } else {
        got_hdrs = true;
    }
    return true;
}

fn finish_h2_response_header_block(
    hdr:      const http2::FrameHeader&,
    frag:     const u8[:],
    is_head:  bool,
    dec_dt:   http2::DynamicTable&,
    resp:     http::Response&,
    got_hdrs: bool&,
) -> H2RecvStatus {
    if !got_hdrs {
        guard apply_initial_h2_response_headers(hdr, frag, dec_dt, resp, got_hdrs) else {
            return H2RecvStatus.Error;
        }
    } else {
        guard (hdr.flags & rfc::H2_FLAG_END_STREAM) != 0 else { return H2RecvStatus.Error; }
        var pseudo = http2::PseudoHeaders { is_trailer: true, .. };
        let d_err = wire::decode_hpack_to_map(dec_dt, frag, pseudo, resp.trailers, 8192, true);
        guard d_err == rfc::H2_ERR_NO_ERROR && !pseudo.has_status else { return H2RecvStatus.Error; }
    }
    let end_s = (hdr.flags & rfc::H2_FLAG_END_STREAM) != 0 ||
        (got_hdrs && (is_head || rfc::is_empty_body_status(resp.status_code)));
    if end_s {
        guard verify_h2_response_content_length(resp, is_head) else { return H2RecvStatus.Error; }
        return H2RecvStatus.Complete;
    }
    return H2RecvStatus.Continue;
}

fn process_h2_response_headers_frame(
    hdr:     const http2::FrameHeader&,
    payload: const u8[:],
    is_head: bool,
    dec_dt:  http2::DynamicTable&,
    resp:    http::Response&,
    state:   H2RecvState&,
) -> H2RecvStatus {
    let frag, f_err = http2::extract_headers_frame_payload(hdr, payload);
    guard f_err == rfc::H2_ERR_NO_ERROR else { return H2RecvStatus.Error; }
    if (hdr.flags & rfc::H2_FLAG_END_HEADERS) == 0 {
        state.cont_buf.clear();
        guard state.cont_buf.try_append(frag) else { return H2RecvStatus.Error; }
        state.cont_hdr = hdr;
        state.await_cont = true;
        return H2RecvStatus.Continue;
    }
    return finish_h2_response_header_block(hdr, frag, is_head, dec_dt, resp, state.got_hdrs);
}

fn process_h2_continuation_frame(
    hdr:       const http2::FrameHeader&,
    payload:   const u8[:],
    stream_id: u32,
    is_head:   bool,
    dec_dt:    http2::DynamicTable&,
    resp:      http::Response&,
    state:     H2RecvState&,
) -> H2RecvStatus {
    guard state.await_cont && hdr.frame_type == rfc::H2_FRAME_CONTINUATION && hdr.stream_id == stream_id else {
        return H2RecvStatus.Error;
    }
    guard state.cont_buf.try_append(payload) else { return H2RecvStatus.Error; }
    if (hdr.flags & rfc::H2_FLAG_END_HEADERS) == 0 {
        return H2RecvStatus.Continue;
    }
    state.await_cont = false;
    return finish_h2_response_header_block(
        state.cont_hdr, state.cont_buf[..], is_head, dec_dt, resp, state.got_hdrs,
    );
}

fn process_h2_data_frame<B>(
    hdr:       const http2::FrameHeader&,
    payload:   const u8[:],
    stream_id: u32,
    is_head:   bool,
    resp:      http::Response&,
    state:     const H2RecvState&,
    out_ctrl:  B&,
) -> H2RecvStatus {
    guard state.got_hdrs else { return H2RecvStatus.Error; }
    let d_slice, d_err = http2::extract_padded_frame_payload(hdr, payload);
    guard d_err == rfc::H2_ERR_NO_ERROR else { return H2RecvStatus.Error; }
    resp.body.append(d_slice);
    if hdr.length > 0 {
        let _ = wire::encode_window_update_frame(0, hdr.length, out_ctrl);
        let _ = wire::encode_window_update_frame(stream_id, hdr.length, out_ctrl);
    }
    let end_d = (hdr.flags & rfc::H2_FLAG_END_STREAM) != 0;
    if end_d {
        guard verify_h2_response_content_length(resp, is_head) else { return H2RecvStatus.Error; }
    }
    return if end_d { H2RecvStatus.Complete } else { H2RecvStatus.Continue };
}

fn process_h2_non_stream_frame<B>(
    hdr:       const http2::FrameHeader&,
    payload:   const u8[:],
    stream_id: u32,
    resp:      http::Response&,
    state:     H2RecvState&,
    out_ctrl:  B&,
) -> H2RecvStatus, bool {
    if hdr.stream_id == 0 && (hdr.frame_type == rfc::H2_FRAME_SETTINGS || hdr.frame_type == rfc::H2_FRAME_PING) {
        process_h2_control_frame(hdr, payload, out_ctrl);
        return H2RecvStatus.Continue, true;
    }
    if hdr.frame_type == rfc::H2_FRAME_RST_STREAM && hdr.stream_id == stream_id {
        record_h2_rst_stream_error(payload, resp);
        return H2RecvStatus.Error, true;
    }
    if hdr.frame_type == rfc::H2_FRAME_GOAWAY {
        guard hdr.stream_id == 0 && payload.len >= 8 && (core::read_be_u32(payload, 0) & 0x7FFFFFFF) >= stream_id else {
            return H2RecvStatus.Error, true;
        }
        state.saw_goaway = true;
        return H2RecvStatus.Continue, true;
    }
    if hdr.frame_type == rfc::H2_FRAME_WINDOW_UPDATE || hdr.stream_id != stream_id {
        return H2RecvStatus.Continue, true;
    }
    return H2RecvStatus.Continue, false;
}

fn process_h2_response_frame<B>(
    hdr:       const http2::FrameHeader&,
    payload:   const u8[:],
    stream_id: u32,
    is_head:   bool,
    dec_dt:    http2::DynamicTable&,
    resp:      http::Response&,
    state:     H2RecvState&,
    out_ctrl:  B&,
) -> H2RecvStatus {
    if state.await_cont {
        return process_h2_continuation_frame(hdr, payload, stream_id, is_head, dec_dt, resp, state);
    }
    guard hdr.frame_type != rfc::H2_FRAME_CONTINUATION else { return H2RecvStatus.Error; }
    let ctrl_st, handled = process_h2_non_stream_frame(hdr, payload, stream_id, resp, state, out_ctrl);
    if handled {
        return ctrl_st;
    }
    let saved_resp = copy(resp);
    let saved_state = state;
    let saved_dt = copy(dec_dt);
    var committed = false;
    defer if !committed { resp = copy(saved_resp); state = saved_state; dec_dt = copy(saved_dt); };
    let st = if hdr.frame_type == rfc::H2_FRAME_HEADERS {
        process_h2_response_headers_frame(hdr, payload, is_head, dec_dt, resp, state)
    } else if hdr.frame_type == rfc::H2_FRAME_DATA {
        process_h2_data_frame(hdr, payload, stream_id, is_head, resp, state, out_ctrl)
    } else {
        H2RecvStatus.Continue
    };
    guard st != H2RecvStatus.Error else { return H2RecvStatus.Error; }
    committed = true;
    return st;
}

fn drain_h2_response_frames<B1, B2>(
    rx_accum:  B1&,
    stream_id: u32,
    is_head:   bool,
    dec_dt:    http2::DynamicTable&,
    resp:      http::Response&,
    state:     H2RecvState&,
    out_ctrl:  B2&,
) -> H2RecvStatus {
    var consumed: i64 = 0;
    defer rx_accum.compact_wire_buffer(consumed);
    while core::sub_sat_i64(rx_accum.len, consumed) >= 9 {
        let hdr, h_err = http2::parse_frame_header(rx_accum[consumed..], 16384);
        guard h_err == rfc::H2_ERR_NO_ERROR else { return H2RecvStatus.Error; }
        let frame_total = core::add_sat_i64(9, hdr.length as i64);
        guard core::sub_sat_i64(rx_accum.len, consumed) >= frame_total else { break; }
        let pay_start = core::add_sat_i64(consumed, 9);
        let pay_end = core::add_sat_i64(consumed, frame_total);
        guard pay_start <= pay_end && pay_end <= rx_accum.len else { return H2RecvStatus.Error; }
        let payload = rx_accum[pay_start..pay_end];
        consumed = pay_end;
        let st = process_h2_response_frame(
            hdr, payload, stream_id, is_head, dec_dt, resp, state, out_ctrl,
        );
        guard st != H2RecvStatus.Error else { return H2RecvStatus.Error; }
        if st == H2RecvStatus.Complete {
            return H2RecvStatus.Complete;
        }
    }
    return H2RecvStatus.Continue;
}

inline fn rollback_h2_response_preserving_rst(resp: http::Response&, saved_resp: const http::Response&) {
    let rst_val = http::trailer(resp, "x-wing-h2-rst-code");
    var rst_copy: u8[..16] = [];
    let has_rst = rst_val.len > 0 && rst_copy.try_set(rst_val);
    resp = copy(saved_resp);
    if has_rst {
        let _ = http::append_header(resp.trailers, "x-wing-h2-rst-code", rst_copy[..]);
    }
}

fn pump_h2_response_frames(
    conn:      net::PooledConnection&,
    rx_accum:  u8[..65536]&,
    stream_id: u32,
    is_head:   bool,
    hpack_dec: http2::DynamicTable&,
    resp:      http::Response&,
    state:     H2RecvState&,
    ctrl_out:  u8[..4096]&,
) -> H2RecvStatus {
    ctrl_out.clear();
    let st = drain_h2_response_frames(rx_accum, stream_id, is_head, hpack_dec, resp, state, ctrl_out);
    guard st != H2RecvStatus.Error else { return H2RecvStatus.Error; }
    if ctrl_out.len > 0 {
        let _ = wing::send_all(conn.transport, ctrl_out[..]);
    }
    return st;
}

fn run_h2_recv_frame_loop(
    conn:        net::PooledConnection&,
    rx_accum:    u8[..65536]&,
    stream_id:   u32,
    is_head:     bool,
    eff_timeout: u32,
    hpack_dec:   http2::DynamicTable&,
    resp:        http::Response&,
    state:       H2RecvState&,
) -> bool {
    var chunk:    u8[4096]   = [0; 4096];
    var ctrl_out: u8[..4096] = [];
    for _ in 4096 {
        if rx_accum.len >= 9 {
            let st_pre = pump_h2_response_frames(
                conn, rx_accum, stream_id, is_head, hpack_dec, resp, state, ctrl_out,
            );
            guard st_pre != H2RecvStatus.Error else { return false; }
            if st_pre == H2RecvStatus.Complete { return true; }
        }
        let n = conn.transport.recv_slice(chunk[..], eff_timeout);
        if n > 0 {
            guard rx_accum.try_append(chunk[..n]) else { return false; }
        }
        let st = pump_h2_response_frames(
            conn, rx_accum, stream_id, is_head, hpack_dec, resp, state, ctrl_out,
        );
        guard st != H2RecvStatus.Error else { return false; }
        if st == H2RecvStatus.Complete { return true; }
        if n <= 0 { return false; }
    }
    return false;
}

fn recv_h2_response_loop(
    conn:        net::PooledConnection&,
    stream_id:   u32,
    is_head:     bool,
    eff_timeout: u32,
    resp:        http::Response&,
) -> bool {
    let hpack_idx = net::ensure_hpack_slot(conn);
    guard hpack_idx >= 0 else { return false; }
    let hpack_dec .= net::hpack_dec_slot(hpack_idx);
    let saved_resp = copy(resp);
    let saved_dt = copy(hpack_dec);
    var committed = false;
    defer if !committed {
        rollback_h2_response_preserving_rst(resp, saved_resp);
        hpack_dec = copy(saved_dt);
    };
    var rx_accum: u8[..65536] = [];
    if conn.rx_buf.len > 0 {
        guard rx_accum.try_append(conn.rx_buf[..]) else { return false; }
        conn.rx_buf.clear();
    }
    var state = H2RecvState { .. };
    let is_done = run_h2_recv_frame_loop(conn, rx_accum, stream_id, is_head, eff_timeout, hpack_dec, resp, state);
    guard state.got_hdrs && is_done && !state.await_cont else { return false; }
    guard conn.rx_buf.try_set(rx_accum[..]) else { return false; }
    if state.saw_goaway {
        conn.no_new_exchanges = true;
    }
    committed = true;
    return true;
}

fn dispatch_pooled_h2_hop(
    session:     client::Session&,
    conn_id:     i32,
    curr_method: const u8[:],
    ctx:         RequestExecutionContext&,
    current_url: const core::Url&,
    is_https:    bool,
    origin_buf:  const u8[:],
    curr_path:   const u8[:],
    now_sec:     i64,
    now_ns:      i64,
    resp:        http::Response&,
) -> bool {
    let c_idx = session.pool.find_connection_index(conn_id);
    guard c_idx >= 0 && c_idx < session.pool.conns.len else { return false; }
    var released = false;
    defer if !released { session.pool.close_pooled_connection(conn_id); };

    let conn .= session.pool.conns[c_idx];
    let hpack_idx = net::ensure_hpack_slot(conn);
    guard hpack_idx >= 0 else { return false; }
    let hpack_enc .= net::hpack_enc_slot(hpack_idx);
    let stream_id = conn.next_h2_stream_id;
    let send_preface = !conn.h2_preface_sent;
    var wire_out: u8[..65536] = [];
    guard encode_h2_request(
        curr_method, current_url, is_https, ctx, hpack_enc, stream_id, send_preface, wire_out,
    ) else {
        return false;
    }
    guard wing::send_all(conn.transport, wire_out[..]) else {
        return false;
    }
    conn.h2_preface_sent = true;
    conn.next_h2_stream_id = min(core::add_sat_u64(conn.next_h2_stream_id, 2), 0xFFFFFFFF) as u32;
    http::reset_response(resp);
    let _ = resp.protocol.try_set("HTTP/2");
    let eff_timeout = calc_phase_timeout_ms(session.read_timeout_ms, session.timeout_ms, ctx.timeout_ms);
    let is_head = curr_method == "HEAD";
    guard recv_h2_response_loop(conn, stream_id, is_head, eff_timeout, resp) else {
        return false;
    }
    resp.effective_url = copy(current_url.href);
    http::copy_headers(ctx.headers, resp.sent_headers);
    ingest_transport_response_headers(session, current_url, is_https, origin_buf, curr_path, now_sec, resp);
    session.pool.release_connection(conn_id, now_ns);
    released = true;
    return true;
}
