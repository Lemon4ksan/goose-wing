// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Internal gRPC server method dispatch, stream decompression, and H2/gRPC-Web connection loops.
namespace grpc_internal;

import std;
import core;
import rfc.http;
import rfc.h2;
import rfc.grpc;
import wire.types;
import wire.h2;
import http2.hpack;
import http.headers;
import http.request;
import http.response;
import server.server;
import server.pipeline;
import .constants;
import .framing;
import .status;
import .connect;
import .health;
import .internal;
import .connect_internal;
import .server_internal;
import .server;

fn build_connect_unary_get_response(
    st:          const grpc::Status&,
    res_payload: const u8[:],
    encoding:    const u8[:],
    ctx:         const grpc::ServerContext&,
    res:         http::Response&,
) {
    res.headers.clear();
    res.trailers.clear();
    res.body.clear();
    res.presence_mask = 0;

    append_metadata_headers(res.headers, ctx.response_metadata[..]);
    if st.code == grpc::StatusCode.Ok {
        res.status_code = rfc::STATUS_OK;
        let ct = if encoding == "json" { rfc::CONNECT_MIME_JSON } else { rfc::CONNECT_MIME_PROTO };
        let _ = res.headers.append_header("content-type", ct);
        res.body.append(res_payload);
        return;
    }

    res.status_code = connect_error_http_status(st.code);
    let _ = res.headers.append_header("content-type", rfc::CONNECT_MIME_JSON);
    encode_connect_unary_error_json(st, res.body);
}

fn dispatch_connect_unary_get<HandlerFn: fn(u16, grpc::ServerContext&, const u8[:], u8[>..]&) -> grpc::Status>(
    d:           const grpc::ServerDispatcher&,
    req:         const http::Request&,
    entry:       const grpc::MethodEntry&,
    now_mono_ns: u64,
    ctx:         grpc::ServerContext&,
    res:         http::Response&,
) -> bool {
    if entry.idempotency != grpc::Idempotency.NoSideEffects {
        res.status_code = rfc::STATUS_METHOD_NOT_ALLOWED;
        let _ = res.headers.append_header("allow", "POST");
        return true;
    }
    if ctx.is_deadline_exceeded(now_mono_ns) {
        let dl_st = grpc::error(grpc::StatusCode.DeadlineExceeded, "Deadline exceeded before handler dispatch");
        build_connect_unary_get_response(dl_st, "", "proto", ctx, res);
        return true;
    }
    let q_idx = req.url[..].index_of_byte('?');
    let query_slice = if q_idx >= 0 { req.url[core::add_sat_i64(q_idx, 1)..] } else { "" };
    var params = grpc::ConnectUnaryGetParams { .. };
    var req_payload: u8[>..] = [];
    let q_code = grpc::parse_connect_get_query(query_slice, params, req_payload);
    if q_code != grpc::StatusCode.Ok {
        let q_err = grpc::error(q_code, "Invalid Connect GET query parameters");
        build_connect_unary_get_response(q_err, "", "json", ctx, res);
        return true;
    }
    let max_msg = if d.max_message_size > 0 { d.max_message_size } else { rfc::GRPC_DEFAULT_MAX_MESSAGE_SIZE };
    if (req_payload.len as u32) > max_msg {
        let sz_err = grpc::error(grpc::StatusCode.ResourceExhausted, "Message exceeds max size");
        build_connect_unary_get_response(sz_err, "", params.encoding[..], ctx, res);
        return true;
    }
    var res_payload: u8[>..] = [];
    let st = HandlerFn(entry.handler_id, ctx, req_payload[..], res_payload);
    build_connect_unary_get_response(st, res_payload[..], params.encoding[..], ctx, res);
    return true;
}

fn prepare_method_dispatch(
    d:                 const grpc::ServerDispatcher&,
    req:               const http::Request&,
    expected_type:     grpc::MethodType,
    now_mono_ns:       u64,
    req_start_mono_ns: u64,
    ctx:               grpc::ServerContext&,
    res:               http::Response&,
) -> i64, bool {
    init_context_transport(req, ctx);
    if !req.method[..].eq_ascii_fold("POST") {
        build_trailers_only_response(grpc::StatusCode.Internal, "HTTP method must be POST", ctx, res);
        return 0, false;
    }
    let ct_hdr = req.header("content-type").trim_lws();
    if ct_hdr.len == 0 || !grpc::is_content_type(ct_hdr) {
        build_trailers_only_response(grpc::StatusCode.InvalidArgument, "Invalid Content-Type header", ctx, res);
        return 0, false;
    }
    let ctx_st = extract_server_context_status(req, ctx, now_mono_ns, req_start_mono_ns);
    if ctx_st != grpc::StatusCode.Ok {
        let ctx_msg = if ctx_st == grpc::StatusCode.Unimplemented {
            "Malformed gRPC URI path"
        } else {
            "Malformed gRPC request headers"
        };
        build_trailers_only_response(ctx_st, ctx_msg, ctx, res);
        return 0, false;
    }
    var path_buf: u8[..260] = [];
    path_buf.push('/');
    path_buf.append(ctx.service[..]);
    path_buf.push('/');
    path_buf.append(ctx.method[..]);
    let method_idx, ok_method = d.find_method(path_buf[..]);
    if !ok_method {
        var err_msg: u8[..288] = [];
        if !err_msg.try_append("Method not found: ") || !err_msg.try_append(path_buf[..]) {
            let _ = err_msg.try_set("Method not found");
        }
        build_trailers_only_response(grpc::StatusCode.Unimplemented, err_msg[..], ctx, res);
        return 0, false;
    }
    let entry .= d.methods[method_idx];
    if ctx.is_web && !d.enable_web {
        build_trailers_only_response(grpc::StatusCode.PermissionDenied, "gRPC-Web transport disabled", ctx, res);
        return 0, false;
    }
    if entry.method_type != expected_type {
        build_trailers_only_response(grpc::StatusCode.Unimplemented, "Method type mismatch", ctx, res);
        return 0, false;
    }
    if ctx.is_deadline_exceeded(now_mono_ns) {
        build_trailers_only_response(
            grpc::StatusCode.DeadlineExceeded, "Deadline exceeded before handler dispatch", ctx, res,
        );
        return 0, false;
    }
    return method_idx, true;
}

fn append_decompressed_stream_span(
    raw_msg:   const u8[:],
    span:      grpc::MessageSpan,
    max_size:  u32,
    ctx:       const grpc::ServerContext&,
    res:       http::Response&,
    new_wire:  u8[>..]&,
    new_spans: grpc::MessageSpan[..32]&,
) -> bool {
    let offset_start = new_wire.len as u32;
    if !span.compressed {
        new_wire.append(raw_msg);
        new_spans.push(grpc::MessageSpan { offset: offset_start, len: span.len, compressed: false });
        return true;
    }
    let eff_limit = calc_grpc_gzip_limit(raw_msg.len, max_size);
    let ok_gz, gz_err = core::gzip_decompress_with_limit(raw_msg, new_wire, eff_limit);
    guard ok_gz else {
        let is_overflow = gz_err == core::CompressError.OutputBufferOverflow;
        let code = if is_overflow {
            grpc::StatusCode.ResourceExhausted
        } else {
            grpc::StatusCode.Internal
        };
        build_trailers_only_response(code, "Failed to decompress client stream message", ctx, res);
        return false;
    }
    let decomp_len = core::sub_sat_u64(new_wire.len as u64, offset_start) as u32;
    new_spans.push(grpc::MessageSpan { offset: offset_start, len: decomp_len, compressed: false });
    return true;
}

fn validate_and_decompress_client_stream(
    reader:   grpc::ClientStreamReader&,
    max_size: u32,
    ctx:      const grpc::ServerContext&,
    res:      http::Response&,
) -> bool {
    let eff_max = if max_size > 0 { max_size } else { rfc::GRPC_DEFAULT_MAX_MESSAGE_SIZE };
    let enc = grpc::get_metadata(ctx, rfc::HEADER_GRPC_ENCODING).trim_lws();
    guard is_supported_encoding(enc) else {
        build_trailers_only_response(grpc::StatusCode.Unimplemented, "Unsupported grpc-encoding", ctx, res);
        return false;
    }
    var any_compressed = false;
    for &span in reader.spans {
        if span.compressed {
            any_compressed = true;
        } else if span.len > eff_max {
            build_trailers_only_response(
                grpc::StatusCode.ResourceExhausted, "Received message exceeds max configured message size", ctx, res,
            );
            return false;
        }
    }
    guard any_compressed else { return true; }
    guard enc.eq_ascii_fold("gzip") else {
        build_trailers_only_response(
            grpc::StatusCode.Internal, "Compressed frame without compression encoding", ctx, res,
        );
        return false;
    }

    var new_wire:  u8[>..]                 = [];
    var new_spans: grpc::MessageSpan[..32] = [];
    for i in reader.spans.len {
        let span = reader.spans[i];
        let raw_msg = grpc::get_client_stream_message(reader, i);
        guard append_decompressed_stream_span(raw_msg, span, eff_max, ctx, res, new_wire, new_spans) else {
            return false;
        }
    }
    reader.wire.clear();
    reader.wire.append(new_wire[..]);
    reader.spans = new_spans;
    return true;
}

// ---- HTTP/2 & gRPC-Web Connection Loop Helpers --------------------------

fn slice_h2_headers_fragment(
    payload:   const u8[:],
    flags:     u8,
    stream_id: u32 = 0,
) -> const u8[:], bool {
    var pad_offset: i64 = 0;
    var pay_end:    i64 = payload.len;
    if (flags & rfc::H2_FLAG_PADDED) != 0 {
        guard payload.len > 0 else { return "", false; }
        let pad_len = payload[0] as i64;
        guard pad_len < payload.len else { return "", false; }
        pad_offset = core::add_sat_i64(pad_offset, 1);
        pay_end = core::sub_sat_i64(pay_end, pad_len);
    }
    if (flags & rfc::H2_FLAG_PRIORITY) != 0 {
        let next_off = core::add_sat_i64(pad_offset, 5);
        guard next_off <= pay_end else { return "", false; }
        let dep_id = core::read_be_u32(payload, pad_offset) & 0x7FFFFFFF;
        guard stream_id == 0 || dep_id != stream_id else { return "", false; }
        pad_offset = next_off;
    }
    guard pad_offset <= pay_end else { return "", false; }
    return payload[pad_offset..pay_end], true;
}

fn execute_server_unary<
    HandlerFn: fn(u16, grpc::ServerContext&, const u8[:], u8[>..]&) -> grpc::Status,
>(
    server:    server::HttpServer&,
    d:         const grpc::ServerDispatcher&,
    client_ip: const u8[:],
    req:       const http::Request&,
    res:       http::Response&,
) {
    server.pipeline.trust_proxy_headers = server.trust_proxy_headers;
    let now_ns = core::as_nanos(core::monotonic_now());
    var future = server_internal::new_inline_handler_future(0);
    let outcome = server::execute_pipeline(server.pipeline, server.timer, client_ip, req, now_ns, res, future);
    server.requests_processed = core::add_sat_u64(server.requests_processed, 1);
    let needs_grpc_dispatch = outcome == server::PipelineOutcome.RouteNotFound ||
        (outcome == server::PipelineOutcome.Handled &&
            res.status_code == rfc::STATUS_OK &&
            res.body.len == 0 &&
            is_request(req));
    if needs_grpc_dispatch {
        let _ = grpc::dispatch_unary(d, req, now_ns, res, HandlerFn);
    }
}

inline fn is_valid_h2_settings_frame(hdr: const wire::WireFrameHeader&) -> bool {
    guard hdr.stream_id == 0 else { return false; }
    if (hdr.flags & rfc::H2_FLAG_ACK) != 0 {
        return hdr.length == 0;
    }
    return (hdr.length % 6) == 0;
}

inline fn validate_h2_settings_payload(payload: const u8[:]) -> bool {
    var off: i64 = 0;
    let total = payload.len;
    while core::add_sat_i64(off, 6) <= total {
        let s = wire::WireSetting {
            id:  core::read_be_u16(payload, off),
            val: core::read_be_u32(payload, core::add_sat_i64(off, 2)),
        };
        guard wire::is_valid_wire_setting(s) else { return false; }
        off = core::add_sat_i64(off, 6);
    }
    return off == total;
}

inline fn slice_h2_data_payload(payload: const u8[:], flags: u8) -> const u8[:], bool {
    if (flags & rfc::H2_FLAG_PADDED) == 0 {
        return payload, true;
    }
    guard payload.len > 0 else { return "", false; }
    let pad_len = payload[0] as i64;
    let data_end = core::sub_sat_i64(payload.len, pad_len);
    guard 1 <= data_end && pad_len < payload.len else { return "", false; }
    return payload[1..data_end], true;
}

fn drain_h2_frames<
    HandlerFn: fn(u16, grpc::ServerContext&, const u8[:], u8[>..]&) -> grpc::Status,
>(
    conn_fd:           i64,
    server:            server::HttpServer&,
    d:                 const grpc::ServerDispatcher&,
    peer_ip:           const u8[:],
    hpack_dec:         http2::DynamicTable&,
    hpack_enc:         http2::DynamicTable&,
    pending:           http::Request&,
    pending_stream_id: u32&,
    in_buf:            u8[..65536]&,
    out_wire:          u8[..65536]&,
) -> bool {
    var cursor: i64 = 0;
    var is_running = true;
    while is_running {
        if core::add_sat_i64(cursor, rfc::H2_FRAME_HEADER_LEN) <= in_buf.len {
            let raw_len: u32 = ((in_buf[cursor] as u32) << 16)
                | ((in_buf[cursor + 1] as u32) << 8)
                | (in_buf[cursor + 2] as u32);
            if raw_len > rfc::H2_DEFAULT_MAX_FRAME_SIZE {
                return false;
            }
        }
        let hdr, payload, ok_frame = wire::read_wire_h2_frame(in_buf[..], cursor);
        if !ok_frame {
            break;
        }
        is_running = grpc::handle_h2_wire_frame(
            conn_fd,
            server,
            d,
            peer_ip,
            hpack_dec,
            hpack_enc,
            pending,
            pending_stream_id,
            hdr,
            payload,
            out_wire,
            HandlerFn,
        );
    }
    if cursor > 0 {
        in_buf.compact_wire_buffer(cursor);
    }
    return is_running;
}

fn serve_h2_connection<
    HandlerFn: fn(u16, grpc::ServerContext&, const u8[:], u8[>..]&) -> grpc::Status,
>(
    server:      server::HttpServer&,
    d:           const grpc::ServerDispatcher&,
    conn_fd:     i64,
    initial_buf: const u8[:],
) {
    let empty_settings: wire::WireSetting[0] = [];
    var srv_set_wire: u8[..16] = [];
    let _ = wire::encode_settings_frame(empty_settings[..], srv_set_wire);
    let _ = net::tcp_send(conn_fd, srv_set_wire[..]);

    var peer_ip: u8[..64] = [];
    net::tcp_get_peer_ip(conn_fd, peer_ip);

    var hpack_dec = http2::new_dynamic_table(4096);
    var hpack_enc = http2::new_dynamic_table(4096);
    var pending = http::new_request("POST", "");
    var pending_stream_id: u32 = 0;

    var in_buf:   u8[..65536] = [];
    var out_wire: u8[..65536] = [];
    var chunk:    u8[..4096]  = [];

    if initial_buf.len > 24 {
        guard in_buf.try_append(initial_buf[24..]) else { return; }
    }

    var is_running = true;
    var idle_ticks: u32 = 0;
    while is_running {
        is_running = drain_h2_frames(
            conn_fd,
            server,
            d,
            peer_ip[..],
            hpack_dec,
            hpack_enc,
            pending,
            pending_stream_id,
            in_buf,
            out_wire,
            HandlerFn,
        );
        if !is_running {
            break;
        }

        chunk.clear();
        let recvd = net::tcp_recv(conn_fd, chunk, 4096, 50);
        if recvd == -2 {
            idle_ticks = core::add_sat_u32(idle_ticks, 1);
            if idle_ticks >= 200 {
                break;
            }
            continue;
        }
        idle_ticks = 0;
        let next_in = core::add_sat_i64(in_buf.len, recvd as i64);
        guard next_in <= in_buf.cap && server::try_append_recv_chunk(recvd, chunk, in_buf) else {
            break;
        }
    }
}

fn serve_web_http1<
    HandlerFn: fn(u16, grpc::ServerContext&, const u8[:], u8[>..]&) -> grpc::Status,
>(
    server:  server::HttpServer&,
    d:       const grpc::ServerDispatcher&,
    conn_fd: i64,
    req_raw: const u8[:],
) {
    var out_wire: u8[..65536] = [];
    var req = http::new_request("GET", "");
    let ok_parse, _ = server::parse_http1_wire_request(req_raw, req);
    guard ok_parse else {
        server::serialize_bad_request_error(server.server_name[..], out_wire);
        let _ = net::tcp_send(conn_fd, out_wire[..]);
        return;
    }

    var peer_ip: u8[..64] = [];
    net::tcp_get_peer_ip(conn_fd, peer_ip);

    var res = http::Response { .. };
    execute_server_unary(server, d, peer_ip[..], req, res, HandlerFn);

    server::serialize_http1_response(res, server.server_name[..], out_wire);
    let _ = net::tcp_send(conn_fd, out_wire[..]);
}

fn try_dispatch_connection_turn<
    HandlerFn: fn(u16, grpc::ServerContext&, const u8[:], u8[>..]&) -> grpc::Status,
>(
    server:  server::HttpServer&,
    d:       const grpc::ServerDispatcher&,
    conn_fd: i64,
    in_buf:  const u8[:],
) -> bool {
    guard !server::is_partial_h2_client_preface(in_buf) else {
        return false;
    }
    if server::is_h2_client_preface(in_buf) {
        serve_h2_connection(server, d, conn_fd, in_buf, HandlerFn);
        return true;
    }
    var hdr_scan_cursor: i64 = 0;
    guard server::has_ready_http1_request(in_buf, hdr_scan_cursor) else {
        return false;
    }
    if core::starts_with(in_buf, "GET /shutdown") {
        var out_wire: u8[..4096] = [];
        let _, _ = server::handle_connection_wire(server, "127.0.0.1", in_buf, 0, out_wire);
        let _ = net::tcp_send(conn_fd, out_wire[..]);
        server.is_running = false;
        return true;
    }
    serve_web_http1(server, d, conn_fd, in_buf, HandlerFn);
    return true;
}

fn serve_connection<
    HandlerFn: fn(u16, grpc::ServerContext&, const u8[:], u8[>..]&) -> grpc::Status,
>(
    server:  server::HttpServer&,
    d:       const grpc::ServerDispatcher&,
    conn_fd: i64,
) {
    var in_buf:     u8[..65536] = [];
    var chunk:      u8[..4096]  = [];
    var wait_ticks: u64         = 0;

    while wait_ticks < 20 {
        chunk.clear();
        let recvd = net::tcp_recv(conn_fd, chunk, 4096, 100);
        if recvd == -2 {
            wait_ticks = core::add_sat_u64(wait_ticks, 1);
            continue;
        }
        let next_in = core::add_sat_i64(in_buf.len, recvd as i64);
        guard next_in <= in_buf.cap && server::try_append_recv_chunk(recvd, chunk, in_buf) else {
            break;
        }
        wait_ticks = 0;

        if try_dispatch_connection_turn(server, d, conn_fd, in_buf[..], HandlerFn) {
            return;
        }
    }
}
