// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Internal protocol-specific streaming emitters, H1 chunked wire writers,
// cork error classification, and request flow-control window helpers.
namespace server_internal;

import std;
import core;
import rfc.http;
import rfc.h2;
import rfc.h3_quic;
import http.headers;
import http.response;
import http2.framing;
import http2.hpack;
import quic.packet;
import quic.stream;
import quic.flow_control;
import http3.framing;
import http3.qpack;
import .h1_codec;
import .cork;
import .stream;
import .stream_consumer;

inline fn cork_flush_error_code(flushed: i32, is_empty: bool) -> i32 {
    if flushed == server::CORK_WOULD_BLOCK || (flushed >= 0 && !is_empty) {
        return server::CORK_WOULD_BLOCK;
    }
    return -1;
}

// ---- Shared Wire Egress & Flush Primitives ---------------------------------

inline fn stream_is_hop_by_hop_header(name: const u8[:]) -> bool {
    return rfc::is_connection_specific_header(name) || name.eq_ascii_fold("te");
}

fn stream_flush_pending_ctrl(stream: server::ResponseStream&) -> server::StreamWriteStatus {
    let rem = core::sub_sat_i64(stream.h1_pending_ctrl.len, stream.h1_pending_ctrl_pos);
    guard rem > 0 else { return server::StreamWriteStatus.Ok; }
    let tail = stream.h1_pending_ctrl[stream.h1_pending_ctrl_pos..];
    if stream.cork.sock_fd <= 0 {
        guard tail.len <= stream.cork.buffer.cork_available() else { return server::StreamWriteStatus.WouldBlock; }
        let _ = stream.cork.buffer.cork_write(tail);
        stream.h1_pending_ctrl.clear();
        stream.h1_pending_ctrl_pos = 0;
        return server::StreamWriteStatus.Ok;
    }
    let sent = server::cork_send_raw(stream.cork.sock_fd, tail);
    if sent == server::CORK_WOULD_BLOCK || sent == 0 { return server::StreamWriteStatus.WouldBlock; }
    if sent < 0 {
        stream.closed = true;
        return server::StreamWriteStatus.Error;
    }
    stream.h1_pending_ctrl_pos = core::add_sat_i64(stream.h1_pending_ctrl_pos, sent);
    if stream.h1_pending_ctrl_pos >= stream.h1_pending_ctrl.len {
        stream.h1_pending_ctrl.clear();
        stream.h1_pending_ctrl_pos = 0;
        return server::StreamWriteStatus.Ok;
    }
    return server::StreamWriteStatus.WouldBlock;
}

// Writes an atomic wire block (header + optional payload) to cork or socket.
fn stream_emit_wire_parts(
    stream:  server::ResponseStream&,
    head:    const u8[:],
    payload: const u8[:],
) -> server::StreamWriteStatus {
    let total = core::add_sat_i64(head.len, payload.len);
    guard total > 0 else { return server::StreamWriteStatus.Ok; }
    if stream.cork.sock_fd <= 0 {
        guard total <= stream.cork.buffer.cork_available() else { return server::StreamWriteStatus.WouldBlock; }
        if head.len > 0 { let _ = stream.cork.buffer.cork_write(head); }
        if payload.len > 0 { let _ = stream.cork.buffer.cork_write(payload); }
        return server::StreamWriteStatus.Ok;
    }
    let w = server::server_cork_write2(stream.cork, head, payload);
    if w == server::CORK_WOULD_BLOCK { return server::StreamWriteStatus.WouldBlock; }
    if w < 0 {
        stream.closed = true;
        return server::StreamWriteStatus.Error;
    }
    if w < total { return server::StreamWriteStatus.WouldBlock; }
    return server::StreamWriteStatus.Ok;
}

// ---- Protocol-Specific Header Emitters (stream_begin) ----------------------

fn stream_begin_http1(stream: server::ResponseStream&, res: http::Response&) -> server::StreamWriteStatus {
    if res.status_code == 0 { res.status_code = rfc::STATUS_OK; }
    let is_empty = rfc::is_empty_body_status(res.status_code);
    var hdr_buf: u8[..8192] = [];
    if is_empty {
        stream.h1_chunked = false;
        stream.h1_content_length = 0;
        server::serialize_http1_headers(res, stream.server_name[..], hdr_buf, 0, 0);
    } else {
        let te = http::header(res, rfc::HEADER_TRANSFER_ENCODING);
        let cl_raw = http::header(res, rfc::HEADER_CONTENT_LENGTH);
        if !te.eq_ascii_fold("chunked") && cl_raw.len > 0 {
            let cl_val, ok_cl = cl_raw.trim_lws().parse_i64_dec();
            guard ok_cl && cl_val >= 0 else { return server::StreamWriteStatus.Error; }
            stream.h1_chunked = false;
            stream.h1_content_length = cl_val;
            server::serialize_http1_headers(res, stream.server_name[..], hdr_buf, 0, cl_val);
        } else {
            // RFC 9112 Section 6.1: Transfer-Encoding - forbidden in HTTP/1.0 responses.
            guard res.protocol[..] != "HTTP/1.0" else { return server::StreamWriteStatus.Error; }
            http::set_header(res, rfc::HEADER_TRANSFER_ENCODING, "chunked");
            let _ = http::remove_header(res, rfc::HEADER_CONTENT_LENGTH);
            stream.h1_chunked = true;
            stream.h1_content_length = -1;
            server::serialize_http1_headers(res, stream.server_name[..], hdr_buf, 0, 0);
        }
    }
    let st = stream_emit_wire_parts(stream, hdr_buf[..], "");
    guard st == server::StreamWriteStatus.Ok else { return st; }
    stream.headers_sent = true;
    if is_empty { stream.ended = true; }
    return server::StreamWriteStatus.Ok;
}

fn stream_begin_http2(stream: server::ResponseStream&, res: http::Response&) -> server::StreamWriteStatus {
    if res.status_code == 0 { res.status_code = rfc::STATUS_OK; }
    let is_empty = rfc::is_empty_body_status(res.status_code);
    var dt = http2::new_dynamic_table(0);
    var hpack_block: u8[..8192] = [];
    var status_str:  u8[..16]   = [];
    res.status_code.format_i64_dec(status_str);
    guard http2::encode_hpack_field(dt, hpack_block, ":status", status_str[..], http2::HpackIndexing.None, true) else {
        return server::StreamWriteStatus.Error;
    }
    if stream.server_name.len > 0 && !http::has_header(res, "server") {
        let _ = http2::encode_hpack_field(
            dt, hpack_block, "server", stream.server_name[..], http2::HpackIndexing.None, true,
        );
    }
    for &e in res.headers.entries {
        let name = http::entry_name(res.headers, e);
        let val = http::entry_value(res.headers, e);
        guard !stream_is_hop_by_hop_header(name) else { continue; }
        var lower: u8[..256] = [];
        guard name.len > 0 && name.len <= lower.cap else { return server::StreamWriteStatus.Error; }
        name.to_lower_ascii(lower);
        guard http2::encode_hpack_field(dt, hpack_block, lower[..], val, http2::HpackIndexing.None, true) else {
            return server::StreamWriteStatus.Error;
        }
    }
    var flags: u8 = rfc::H2_FLAG_END_HEADERS;
    if is_empty { flags |= rfc::H2_FLAG_END_STREAM; }
    let fhdr = http2::FrameHeader {
        length:     hpack_block.len as u32,
        frame_type: rfc::H2_FRAME_HEADERS,
        flags:      flags,
        stream_id:  stream.h2_stream_id,
    };
    var raw_hdr: u8[9] = [0; 9];
    http2::encode_frame_header(fhdr, raw_hdr);
    let st = stream_emit_wire_parts(stream, raw_hdr[..], hpack_block[..]);
    guard st == server::StreamWriteStatus.Ok else { return st; }
    stream.headers_sent = true;
    stream.frames_emitted = core::add_sat_u64(stream.frames_emitted, 1);
    if is_empty { stream.ended = true; }
    return server::StreamWriteStatus.Ok;
}

fn stream_begin_http3(stream: server::ResponseStream&, res: http::Response&) -> server::StreamWriteStatus {
    if res.status_code == 0 { res.status_code = rfc::STATUS_OK; }
    let is_empty = rfc::is_empty_body_status(res.status_code);
    var qpack_block: u8[..8192] = [];
    // RFC 9204 Section 4.5.1: Static-only QPACK prefix (RIC = 0, DeltaBase = 0).
    guard qpack_block.try_push(0x00) && qpack_block.try_push(0x00) else { return server::StreamWriteStatus.Error; }
    var status_str: u8[..16] = [];
    res.status_code.format_i64_dec(status_str);
    guard http3::encode_qpack_field(qpack_block, ":status", status_str[..], true) else {
        return server::StreamWriteStatus.Error;
    }
    if stream.server_name.len > 0 && !http::has_header(res, "server") {
        let _ = http3::encode_qpack_field(qpack_block, "server", stream.server_name[..], true);
    }
    for &e in res.headers.entries {
        let name = http::entry_name(res.headers, e);
        let val = http::entry_value(res.headers, e);
        guard !stream_is_hop_by_hop_header(name) else { continue; }
        var lower: u8[..256] = [];
        guard name.len > 0 && name.len <= lower.cap else { return server::StreamWriteStatus.Error; }
        name.to_lower_ascii(lower);
        guard http3::encode_qpack_field(qpack_block, lower[..], val, true) else {
            return server::StreamWriteStatus.Error;
        }
    }
    var h3_hdr: u8[..16] = [];
    guard http3::encode_frame_header(h3_hdr, rfc::H3_FRAME_HEADERS, qpack_block.len as u64) else {
        return server::StreamWriteStatus.Error;
    }
    let st = stream_emit_wire_parts(stream, h3_hdr[..], qpack_block[..]);
    guard st == server::StreamWriteStatus.Ok else { return st; }
    stream.headers_sent = true;
    stream.frames_emitted = core::add_sat_u64(stream.frames_emitted, 1);
    if is_empty {
        let _, _ = quic::on_send_data(stream.quic_stream, stream.quic_stream.bytes_sent, 0, true);
        stream.h3_fin_emitted = true;
        stream.ended = true;
    }
    return server::StreamWriteStatus.Ok;
}

// ---- HTTP/1.1 Streaming Body Writer (Zero 16 KB Ceiling + Partial Offset) --

fn stream_h1_queue_crlf(stream: server::ResponseStream&) -> server::StreamWriteStatus {
    stream.h1_need_chunk_crlf = false;
    let w = server::cork_send_raw(stream.cork.sock_fd, "\r\n");
    if w == 2 { return server::StreamWriteStatus.Ok; }
    if w == 1 {
        let _ = stream.h1_pending_ctrl.try_set("\n");
        stream.h1_pending_ctrl_pos = 0;
        return server::StreamWriteStatus.WouldBlock;
    }
    if w == server::CORK_WOULD_BLOCK || w == 0 {
        let _ = stream.h1_pending_ctrl.try_set("\r\n");
        stream.h1_pending_ctrl_pos = 0;
        return server::StreamWriteStatus.WouldBlock;
    }
    stream.closed = true;
    return server::StreamWriteStatus.Error;
}

fn stream_h1_continue_partial_chunk(
    stream: server::ResponseStream&,
    chunk:  const u8[:],
) -> i64, server::StreamWriteStatus {
    let to_send = min(chunk.len, stream.h1_in_chunk_rem);
    let sent = server::cork_send_raw(stream.cork.sock_fd, chunk[..to_send]);
    if sent == server::CORK_WOULD_BLOCK || sent == 0 { return 0, server::StreamWriteStatus.WouldBlock; }
    if sent < 0 {
        stream.closed = true;
        return 0, server::StreamWriteStatus.Error;
    }
    let sent_i64 = sent as i64;
    stream.h1_in_chunk_rem = core::sub_sat_i64(stream.h1_in_chunk_rem, sent_i64);
    stream.body_bytes_sent = core::add_sat_u64(stream.body_bytes_sent, sent_i64 as u64);
    if stream.h1_in_chunk_rem > 0 {
        return sent_i64, server::StreamWriteStatus.WouldBlock;
    }
    if stream.h1_need_chunk_crlf {
        let crlf_st = stream_h1_queue_crlf(stream);
        if crlf_st != server::StreamWriteStatus.Ok { return sent_i64, crlf_st; }
    }
    return sent_i64, server::StreamWriteStatus.Ok;
}

fn stream_h1_write_fixed(stream: server::ResponseStream&, chunk: const u8[:]) -> i64, server::StreamWriteStatus {
    var rem_allowed = chunk.len;
    if stream.h1_content_length >= 0 {
        let already = stream.body_bytes_sent as i64;
        guard already <= stream.h1_content_length else { return 0, server::StreamWriteStatus.Error; }
        let cl_rem = core::sub_sat_i64(stream.h1_content_length, already);
        guard chunk.len <= cl_rem else { return 0, server::StreamWriteStatus.Error; }
        rem_allowed = min(chunk.len, cl_rem);
    }
    if stream.cork.sock_fd <= 0 {
        let avail = stream.cork.buffer.cork_available();
        guard avail > 0 else { return 0, server::StreamWriteStatus.WouldBlock; }
        let take = min(rem_allowed, avail);
        let _ = stream.cork.buffer.cork_write(chunk[..take]);
        stream.body_bytes_sent = core::add_sat_u64(stream.body_bytes_sent, take as u64);
        return take, if take < rem_allowed {
            server::StreamWriteStatus.WouldBlock
        } else {
            server::StreamWriteStatus.Ok
        };
    }
    let w = server::server_cork_write(stream.cork, chunk[..rem_allowed]);
    if w == server::CORK_WOULD_BLOCK || w == 0 { return 0, server::StreamWriteStatus.WouldBlock; }
    if w < 0 {
        stream.closed = true;
        return 0, server::StreamWriteStatus.Error;
    }
    let w_i64 = w as i64;
    stream.body_bytes_sent = core::add_sat_u64(stream.body_bytes_sent, w_i64 as u64);
    return w_i64, if w_i64 < rem_allowed { server::StreamWriteStatus.WouldBlock } else { server::StreamWriteStatus.Ok };
}

fn stream_h1_write_chunked_sans_io(
    stream: server::ResponseStream&,
    chunk:  const u8[:],
) -> i64, server::StreamWriteStatus {
    var offset: i64 = 0;
    while offset < chunk.len {
        let avail = stream.cork.buffer.cork_available();
        // Reserve up to 12 bytes for `<hex>\r\n` + `\r\n` framing overhead.
        guard avail > 12 else { return offset, server::StreamWriteStatus.WouldBlock; }
        let max_pay = core::sub_sat_i64(avail, 12);
        let take = min(core::sub_sat_i64(chunk.len, offset), max_pay);
        var chdr: u8[..24] = [];
        (take as u64).format_u64_hex(chdr, false);
        chdr.append("\r\n");
        let _ = stream.cork.buffer.cork_write(chdr[..]);
        let _ = stream.cork.buffer.cork_write(chunk[offset..core::add_sat_i64(offset, take)]);
        let _ = stream.cork.buffer.cork_write("\r\n");
        offset = core::add_sat_i64(offset, take);
        stream.body_bytes_sent = core::add_sat_u64(stream.body_bytes_sent, take as u64);
        stream.frames_emitted = core::add_sat_u64(stream.frames_emitted, 1);
    }
    return offset, server::StreamWriteStatus.Ok;
}

fn stream_h1_write_chunked_direct(
    stream: server::ResponseStream&,
    chdr:   const u8[:],
    sub:    const u8[:],
) -> i64, server::StreamWriteStatus {
    let w1 = server::cork_send_raw2(stream.cork.sock_fd, chdr, sub);
    if w1 == server::CORK_WOULD_BLOCK || w1 == 0 { return 0, server::StreamWriteStatus.WouldBlock; }
    if w1 < 0 {
        stream.closed = true;
        return 0, server::StreamWriteStatus.Error;
    }
    let sent = w1 as i64;
    if sent < chdr.len {
        let _ = stream.h1_pending_ctrl.try_set(chdr[sent..]);
        stream.h1_pending_ctrl_pos = 0;
        stream.h1_in_chunk_rem = sub.len;
        stream.h1_need_chunk_crlf = true;
        stream.frames_emitted = core::add_sat_u64(stream.frames_emitted, 1);
        return 0, server::StreamWriteStatus.WouldBlock;
    }
    let body_sent = core::sub_sat_i64(sent, chdr.len);
    stream.body_bytes_sent = core::add_sat_u64(stream.body_bytes_sent, body_sent as u64);
    stream.frames_emitted = core::add_sat_u64(stream.frames_emitted, 1);
    if body_sent < sub.len {
        stream.h1_in_chunk_rem = core::sub_sat_i64(sub.len, body_sent);
        stream.h1_need_chunk_crlf = true;
        return body_sent, server::StreamWriteStatus.WouldBlock;
    }
    let crlf_st = stream_h1_queue_crlf(stream);
    if crlf_st == server::StreamWriteStatus.Error { return body_sent, server::StreamWriteStatus.Error; }
    return body_sent, server::StreamWriteStatus.Ok;
}

fn stream_write_http1(stream: server::ResponseStream&, chunk: const u8[:]) -> i64, server::StreamWriteStatus {
    let ctrl_st = stream_flush_pending_ctrl(stream);
    guard ctrl_st == server::StreamWriteStatus.Ok else { return 0, ctrl_st; }
    if !stream.h1_chunked { return stream_h1_write_fixed(stream, chunk); }
    if stream.cork.sock_fd <= 0 { return stream_h1_write_chunked_sans_io(stream, chunk); }

    var offset: i64 = 0;
    if stream.h1_in_chunk_rem > 0 {
        let n_cont, st_cont = stream_h1_continue_partial_chunk(stream, chunk);
        offset = core::add_sat_i64(offset, n_cont);
        if st_cont != server::StreamWriteStatus.Ok || offset >= chunk.len { return offset, st_cont; }
    }
    if stream.h1_need_chunk_crlf {
        let st_cr = stream_h1_queue_crlf(stream);
        guard st_cr == server::StreamWriteStatus.Ok else { return offset, st_cr; }
    }

    let sub = chunk[offset..];
    var chdr: u8[..24] = [];
    (sub.len as u64).format_u64_hex(chdr, false);
    chdr.append("\r\n");
    let frame_len = core::add_sat_i64(core::add_sat_i64(chdr.len, sub.len), 2);
    if frame_len <= stream.cork.buffer.cork_available() {
        let _ = stream.cork.buffer.cork_write(chdr[..]);
        let _ = stream.cork.buffer.cork_write(sub);
        let _ = stream.cork.buffer.cork_write("\r\n");
        stream.body_bytes_sent = core::add_sat_u64(stream.body_bytes_sent, sub.len as u64);
        stream.frames_emitted = core::add_sat_u64(stream.frames_emitted, 1);
        return chunk.len, server::StreamWriteStatus.Ok;
    }
    let fl_st = server::stream_flush(stream);
    guard fl_st == server::StreamWriteStatus.Ok else { return offset, fl_st; }
    if frame_len < core::CORK_BUFFER_CAP {
        let _ = stream.cork.buffer.cork_write(chdr[..]);
        let _ = stream.cork.buffer.cork_write(sub);
        let _ = stream.cork.buffer.cork_write("\r\n");
        stream.body_bytes_sent = core::add_sat_u64(stream.body_bytes_sent, sub.len as u64);
        stream.frames_emitted = core::add_sat_u64(stream.frames_emitted, 1);
        return chunk.len, server::StreamWriteStatus.Ok;
    }
    let n_dir, st_dir = stream_h1_write_chunked_direct(stream, chdr[..], sub);
    return core::add_sat_i64(offset, n_dir), st_dir;
}

// ---- HTTP/2 Streaming Body Writer (Two-Level Flow Control) -----------------

fn stream_write_http2(stream: server::ResponseStream&, chunk: const u8[:]) -> i64, server::StreamWriteStatus {
    var offset: i64 = 0;
    let max_frame = clamp(stream.h2_max_frame_size as i64, 16384, 16777215);
    while offset < chunk.len {
        let quota = min(max(0, stream.h2_conn_send_window), max(0, stream.h2_stream_send_window));
        if quota <= 0 { return offset, server::StreamWriteStatus.WouldBlock; }
        let rem = core::sub_sat_i64(chunk.len, offset);
        var flen = min(min(rem, max_frame), quota);
        if stream.cork.sock_fd <= 0 {
            let avail = stream.cork.buffer.cork_available();
            if avail <= rfc::H2_FRAME_HEADER_LEN { return offset, server::StreamWriteStatus.WouldBlock; }
            flen = min(flen, core::sub_sat_i64(avail, rfc::H2_FRAME_HEADER_LEN));
        }
        let fhdr = http2::FrameHeader {
            length:     flen as u32,
            frame_type: rfc::H2_FRAME_DATA,
            flags:      0,
            stream_id:  stream.h2_stream_id,
        };
        var raw_hdr: u8[9] = [0; 9];
        http2::encode_frame_header(fhdr, raw_hdr);
        let end_off = core::add_sat_i64(offset, flen);
        let st = stream_emit_wire_parts(stream, raw_hdr[..], chunk[offset..end_off]);
        guard st == server::StreamWriteStatus.Ok else { return offset, st; }
        // RFC 9113 Section 6.9.1: Atomically deduct connection and stream send windows.
        stream.h2_conn_send_window = core::sub_sat_i64(stream.h2_conn_send_window, flen);
        stream.h2_stream_send_window = core::sub_sat_i64(stream.h2_stream_send_window, flen);
        offset = end_off;
        stream.body_bytes_sent = core::add_sat_u64(stream.body_bytes_sent, flen as u64);
        stream.frames_emitted = core::add_sat_u64(stream.frames_emitted, 1);
    }
    return offset, server::StreamWriteStatus.Ok;
}

// ---- HTTP/3 Streaming Body Writer (QUIC Flow Control) ----------------------

fn stream_write_http3(stream: server::ResponseStream&, chunk: const u8[:]) -> i64, server::StreamWriteStatus {
    var offset: i64 = 0;
    while offset < chunk.len {
        let conn_cr = quic::remaining_conn_credit(stream.quic_flow);
        let strm_cr = quic::remaining_stream_credit(stream.quic_stream);
        let credit = min(min(conn_cr, strm_cr), 0x7FFFFFFF) as i64;
        if credit <= 0 { return offset, server::StreamWriteStatus.WouldBlock; }
        let rem = core::sub_sat_i64(chunk.len, offset);
        var flen = min(rem, credit);
        if stream.cork.sock_fd <= 0 {
            let avail = stream.cork.buffer.cork_available();
            // Reserve up to 10 bytes for H3_FRAME_DATA type + length VarInts.
            if avail <= 10 { return offset, server::StreamWriteStatus.WouldBlock; }
            flen = min(flen, core::sub_sat_i64(avail, 10));
        }
        var h3_hdr: u8[..16] = [];
        guard http3::encode_frame_header(h3_hdr, rfc::H3_FRAME_DATA, flen as u64) else {
            return offset, server::StreamWriteStatus.Error;
        }
        let end_off = core::add_sat_i64(offset, flen);
        let st = stream_emit_wire_parts(stream, h3_hdr[..], chunk[offset..end_off]);
        guard st == server::StreamWriteStatus.Ok else { return offset, st; }
        guard quic::record_send(
            stream.quic_flow, stream.quic_stream, stream.quic_stream.bytes_sent, flen as u64,
        ) else {
            return offset, server::StreamWriteStatus.Error;
        }
        offset = end_off;
        stream.body_bytes_sent = core::add_sat_u64(stream.body_bytes_sent, flen as u64);
        stream.frames_emitted = core::add_sat_u64(stream.frames_emitted, 1);
    }
    return offset, server::StreamWriteStatus.Ok;
}

inline fn calc_window_threshold(window_size: u64, pct: u32) -> u64 {
    let scaled, _ = core::div_rem_u64(core::mul_sat_u64(window_size, pct), 100);
    return max(scaled, 1);
}

fn replenish_single_window(
    protocol:       server::WindowProtocol,
    window_size:    u64,
    threshold_pct:  u32,
    unacked_bytes:  u64&,
    advertised_max: u64&,
) -> u64, bool {
    let thresh = calc_window_threshold(window_size, threshold_pct);
    guard unacked_bytes >= thresh else { return 0, false; }
    let pending = unacked_bytes;
    let delta = if protocol == server::WindowProtocol.Http2 {
        min(pending, rfc::H2_MAX_WINDOW_SIZE)
    } else {
        pending
    };
    let next_max = min(core::add_sat_u64(advertised_max, delta), rfc::QUIC_VARINT_MAX);
    guard next_max > advertised_max else { return 0, false; }
    advertised_max = next_max;
    unacked_bytes = core::sub_sat_u64(unacked_bytes, delta);
    let reported = if protocol == server::WindowProtocol.Http3 { next_max } else { delta };
    return reported, true;
}
