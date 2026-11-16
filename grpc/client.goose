// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// High-level ergonomic gRPC client abstractions for Unary and Streaming RPCs.
// Supports native gRPC over HTTP/2 & HTTP/3 and gRPC-Web (binary and text).
namespace wing;

import std;
import core from "..";
import grpc.constants;
import grpc.framing;
import grpc.status;
import grpc.server;
import http.headers;
import fingerprint.profile;
import http.request;
import http.response;
import client.client;

// ---- gRPC Request & Response Models -------------------------------------

struct GrpcCallConfig {
    service:         u8[..128]          = [],
    method:          u8[..128]          = [],
    timeout_ms:      u64                = 0,
    is_web:          bool               = false,
    is_web_text:     bool               = false,
    use_compression: bool               = false,
    metadata:        GrpcMetadata[..16] = [],
}

fn new_grpc_call_config(service: const u8[:], method: const u8[:]) -> GrpcCallConfig {
    var cfg = GrpcCallConfig { .. };
    let _ = cfg.service.try_set(service);
    let _ = cfg.method.try_set(method);
    return cfg;
}

struct GrpcResponse {
    status:           GrpcStatusCode       = GrpcStatusCode.Ok,
    message:          u8[..256]            = [],
    details:          GrpcErrorDetail[..4] = [],
    is_compressed:    bool                 = false,
    is_trailers_only: bool                 = false,
    payload:          u8[>..]              = [],
}

fn is_grpc_success(res: const GrpcResponse&) -> bool {
    return res.status == GrpcStatusCode.Ok;
}

// ---- Header and Request Builders ----------------------------------------

// Builds a low-level HeaderMap for native HTTP/2 or HTTP/3 framing.
fn build_grpc_request_headers(
    cfg:         const GrpcCallConfig&,
    host:        const u8[:],
    scheme:      const u8[:],
    out_headers: HeaderMap&,
) {
    reset_for_keep_alive(out_headers);

    append_header(out_headers, ":method", "POST");
    append_header(out_headers, ":scheme", scheme);

    var path_buf: u8[..288] = [];
    path_buf.push('/');
    path_buf.append(cfg.service[..]);
    path_buf.push('/');
    path_buf.append(cfg.method[..]);
    append_header(out_headers, ":path", path_buf[..]);

    append_header(out_headers, ":authority", host);

    if cfg.is_web_text {
        append_header(out_headers, "content-type", rfc::GRPC_WEB_TEXT_PROTO);
        append_header(out_headers, "accept", rfc::GRPC_WEB_TEXT_PROTO);
    } else if cfg.is_web {
        append_header(out_headers, "content-type", rfc::GRPC_WEB_CONTENT_TYPE_PROTO);
    } else {
        append_header(out_headers, "content-type", rfc::GRPC_CONTENT_TYPE_PROTO);
    }

    append_header(out_headers, "te", "trailers");

    if cfg.timeout_ms > 0 {
        var timeout_buf: u8[..32] = [];
        encode_grpc_timeout(cfg.timeout_ms, timeout_buf);
        append_header(out_headers, rfc::HEADER_GRPC_TIMEOUT, timeout_buf[..]);
    }

    if cfg.use_compression {
        append_header(out_headers, rfc::HEADER_GRPC_ENCODING, "gzip");
    }
    append_header(out_headers, rfc::HEADER_GRPC_ACCEPT_ENCODING, "identity,gzip");

    for i in cfg.metadata.len {
        if is_valid_grpc_custom_metadata(cfg.metadata[i].key[..], cfg.metadata[i].value[..]) {
            append_header(out_headers, cfg.metadata[i].key[..], cfg.metadata[i].value[..]);
        }
    }
}

inline fn append_grpc_custom_metadata_to_request(req: Request&, meta: const GrpcMetadata[:]) {
    for &m in meta {
        if is_valid_grpc_custom_metadata(m.key[..], m.value[..]) {
            set_header(req, m.key[..], m.value[..]);
        }
    }
}

// Builds a high-level Client Request object for dispatch through Session / Client.
fn build_grpc_http_request(
    cfg:            const GrpcCallConfig&,
    base_url:       const u8[:],
    serialized_msg: const u8[:],
    out_req:        Request&,
) {
    let _ = out_req.method.try_set("POST");

    let _ = out_req.url.try_set(base_url);
    let last_idx = core::sub_sat_i64(out_req.url.len, 1);
    if out_req.url.len == 0 || out_req.url[last_idx] != '/' {
        let _ = out_req.url.try_push('/');
    }
    let _ = out_req.url.try_append(cfg.service[..]);
    let _ = out_req.url.try_push('/');
    let _ = out_req.url.try_append(cfg.method[..]);

    // Reset headers and presence mask for reliable O(1) header lookup
    out_req.headers.clear();
    out_req.presence_mask = 0;

    if cfg.is_web_text {
        set_header(out_req, "content-type", rfc::GRPC_WEB_TEXT_PROTO);
        set_header(out_req, "accept", rfc::GRPC_WEB_TEXT_PROTO);
    } else if cfg.is_web {
        set_header(out_req, "content-type", rfc::GRPC_WEB_CONTENT_TYPE_PROTO);
    } else {
        set_header(out_req, "content-type", rfc::GRPC_CONTENT_TYPE_PROTO);
    }

    set_header(out_req, "te", "trailers");

    if cfg.timeout_ms > 0 {
        var timeout_buf: u8[..32] = [];
        encode_grpc_timeout(cfg.timeout_ms, timeout_buf);
        set_header(out_req, rfc::HEADER_GRPC_TIMEOUT, timeout_buf[..]);
    }

    if cfg.use_compression {
        set_header(out_req, rfc::HEADER_GRPC_ENCODING, "gzip");
    }
    set_header(out_req, rfc::HEADER_GRPC_ACCEPT_ENCODING, "identity,gzip");
    append_grpc_custom_metadata_to_request(out_req, cfg.metadata[..]);

    // Body LPM encoding
    out_req.body.clear();
    if cfg.is_web_text {
        var raw_lpm: u8[>..] = [];
        encode_grpc_lpm(serialized_msg, raw_lpm, cfg.use_compression);
        encode_grpc_web_text(raw_lpm[..], out_req.body);
    } else {
        encode_grpc_lpm(serialized_msg, out_req.body, cfg.use_compression);
    }
}

// ---- Unary Response Parser ----------------------------------------------

inline fn classify_grpc_gzip_error(gz_err: core::CompressError) -> GrpcStatusCode {
    if gz_err == core::CompressError.OutputBufferOverflow {
        return GrpcStatusCode.ResourceExhausted;
    }
    return GrpcStatusCode.Internal;
}

inline fn append_grpc_web_data_frame(frame_payload: const u8[:], is_comp: bool, out_resp: GrpcResponse&) -> bool {
    out_resp.is_compressed = is_comp;
    if !is_comp {
        let next_len = core::add_sat_i64(out_resp.payload.len, frame_payload.len);
        guard next_len <= rfc::GRPC_DEFAULT_MAX_MESSAGE_SIZE else {
            out_resp.status = GrpcStatusCode.ResourceExhausted;
            return false;
        }
        out_resp.payload.append(frame_payload);
        return true;
    }
    let ok_gz, gz_err = core::gzip_decompress_with_limit(
        frame_payload, out_resp.payload, rfc::GRPC_DEFAULT_MAX_MESSAGE_SIZE,
    );
    if !ok_gz {
        out_resp.status = classify_grpc_gzip_error(gz_err);
    }
    return ok_gz;
}

// Decodes an uncompressed or Gzip-compressed gRPC-Web trailer frame payload.
//
// Example:
//   frame_payload = "grpc-status: 0\r\n", is_comp = false
//   returns: true, out_resp.status = GrpcStatusCode.Ok
inline fn decode_grpc_web_trailer_frame(
    frame_payload: const u8[:],
    is_comp:       bool,
    out_resp:      GrpcResponse&,
) -> bool {
    if !is_comp {
        if !parse_grpc_web_trailers(frame_payload, out_resp.status, out_resp.message) {
            out_resp.status = GrpcStatusCode.Unknown;
        }
        return true;
    }
    var tr_decomp: u8[>..] = [];
    let ok_gz, _ = core::gzip_decompress_with_limit(
        frame_payload, tr_decomp, rfc::GRPC_DEFAULT_MAX_MESSAGE_SIZE,
    );
    guard ok_gz else { return false; }
    if !parse_grpc_web_trailers(tr_decomp[..], out_resp.status, out_resp.message) {
        out_resp.status = GrpcStatusCode.Unknown;
    }
    return true;
}

// Scans gRPC-Web data and trailer frames in `wire_bytes` for a unary RPC response.
//
// Example:
//   wire_bytes = "\x00\x00\x00\x00\x05hello\x80\x00\x00\x00\x0Fgrpc-status: 0\r\n"
//   returns: true, found_data = true, found_trailer = true
fn scan_grpc_web_unary_frames(
    wire_bytes:    const u8[:],
    out_resp:      GrpcResponse&,
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
        let ok_frame, consumed = decode_grpc_web_frame(wire_bytes[..], offset, frame_payload, is_trailers, is_comp);
        guard ok_frame else {
            out_resp.payload.clear();
            return false;
        }

        if is_trailers {
            guard decode_grpc_web_trailer_frame(frame_payload[..], is_comp, out_resp) else {
                out_resp.payload.clear();
                return false;
            }
            found_trailer = true;
        } else {
            guard !found_data && append_grpc_web_data_frame(frame_payload[..], is_comp, out_resp) else {
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
fn parse_grpc_web_unary_body(
    res_headers:  const HeaderMap&,
    res_trailers: const HeaderMap&,
    body:         const u8[:],
    out_resp:     GrpcResponse&,
) -> bool {
    var wire_bytes: u8[>..] = [];
    let content_type = get_header(res_headers, "content-type");
    if content_type.len > 0 && !is_grpc_web(content_type) {
        out_resp.status = grpc_status_from_http(resolve_effective_http_status(res_headers));
        return false;
    }
    if is_grpc_web_text(content_type) {
        guard decode_grpc_web_text(body, wire_bytes) else { return false; }
    } else {
        wire_bytes.append(body);
    }

    var found_trailer = false;
    var found_data = false;
    guard scan_grpc_web_unary_frames(wire_bytes[..], out_resp, found_data, found_trailer) else {
        return false;
    }

    if !found_trailer {
        let has_hdr_status = extract_grpc_status(res_headers, res_trailers, out_resp.status, out_resp.message);
        guard !found_data && has_hdr_status else {
            out_resp.payload.clear();
            return false;
        }
        out_resp.is_trailers_only = true;
        if out_resp.status == GrpcStatusCode.Ok {
            out_resp.status = GrpcStatusCode.Internal;
            return false;
        }
        return true;
    }
    let http_st = resolve_effective_http_status(res_headers);
    if http_st != 200 && out_resp.status == GrpcStatusCode.Ok {
        out_resp.status = grpc_status_from_http(http_st);
    }
    if !found_data {
        out_resp.is_trailers_only = true;
        if out_resp.status == GrpcStatusCode.Ok {
            out_resp.status = GrpcStatusCode.Internal;
            return false;
        }
    }
    return true;
}

// Parses a unary gRPC or gRPC-Web response from headers, trailers, and body bytes.
//
// Example:
//   body = "\x00\x00\x00\x00\x05hello", is_web = false
//   returns: ok = true, out_resp.payload = "hello", out_resp.status = Ok
fn parse_grpc_unary_response(
    res_headers:  const HeaderMap&,
    res_trailers: const HeaderMap&,
    body:         const u8[:],
    is_web:       bool,
    out_resp:     GrpcResponse&,
) -> bool {
    out_resp.payload.clear();
    out_resp.message.clear();
    out_resp.details.clear();
    out_resp.is_compressed = false;
    out_resp.is_trailers_only = false;

    if is_web {
        return parse_grpc_web_unary_body(res_headers, res_trailers, body, out_resp);
    }

    let ct = get_header(res_headers, "content-type");
    if ct.len > 0 && !matches_grpc_media_type(ct.trim_lws(), rfc::GRPC_CONTENT_TYPE) {
        out_resp.status = grpc_status_from_http(resolve_effective_http_status(res_headers));
        return false;
    }

    // Native HTTP/2 or HTTP/3 gRPC
    let has_wire_status = extract_grpc_status(res_headers, res_trailers, out_resp.status, out_resp.message);
    var details_b64 = get_header(res_trailers, rfc::HEADER_GRPC_STATUS_DETAILS_BIN);
    if details_b64.len == 0 {
        details_b64 = get_header(res_headers, rfc::HEADER_GRPC_STATUS_DETAILS_BIN);
    }
    if details_b64.len > 0 {
        let _ = decode_grpc_status_details(
            details_b64, out_resp.status, out_resp.status, out_resp.message, out_resp.details,
        );
    }
    if body.len >= 5 {
        guard has_wire_status else {
            out_resp.payload.clear();
            return false;
        }
        var comp = false;
        let ok_lpm, consumed = decode_grpc_lpm(body, 0, out_resp.payload, comp);
        guard ok_lpm && consumed == body.len else {
            if out_resp.status == GrpcStatusCode.Ok {
                out_resp.status = GrpcStatusCode.Internal;
            }
            out_resp.payload.clear();
            return false;
        }
        out_resp.is_compressed = comp;
        let enc_hdr = get_header(res_headers, rfc::HEADER_GRPC_ENCODING);
        let comp_st = validate_recv_compression(comp, enc_hdr, false);
        if comp_st != GrpcStatusCode.Ok {
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
                out_resp.status = classify_grpc_gzip_error(gz_err);
                out_resp.payload.clear();
                return false;
            }
            out_resp.payload.clear();
            out_resp.payload.append(decomp_buf[..]);
        } else {
            guard out_resp.payload.len <= rfc::GRPC_DEFAULT_MAX_MESSAGE_SIZE else {
                out_resp.status = GrpcStatusCode.ResourceExhausted;
                out_resp.payload.clear();
                return false;
            }
        }
        return true;
    }

    if body.len == 0 && has_wire_status {
        out_resp.is_trailers_only = true;
        if out_resp.status == GrpcStatusCode.Ok {
            out_resp.status = GrpcStatusCode.Internal;
            return false;
        }
        return true;
    }

    if out_resp.status == GrpcStatusCode.Ok {
        out_resp.status = GrpcStatusCode.Internal;
    }
    return false;
}

// ---- High-Level RPC Invocation via Client -------------------------------

// Parses a numeric gRPC status code from string.
//
// Example:
//   status_val = "0"
//   returns: 0
fn parse_grpc_status_code(status_val: const u8[:]) -> u32 {
    let trimmed = status_val.trim_lws();
    guard trimmed.len > 0 else { return 2; }
    let status_int, ok_code = trimmed.parse_u32_dec();
    if ok_code {
        return status_int;
    }
    return 2;
}

// Processes incoming gRPC-Web response body and trailers.
fn process_grpc_web_response(body: const u8[:], ct: const u8[:], out_resp: GrpcResponse&) -> bool {
    guard is_grpc_web(ct) else {
        out_resp.status = GrpcStatusCode.Unknown;
        return false;
    }
    var wire_bytes: u8[>..] = [];
    if is_grpc_web_text(ct) {
        guard decode_grpc_web_text(body, wire_bytes) else { return false; }
    } else {
        wire_bytes.append(body);
    }

    var found_trailer = false;
    var found_data = false;
    guard scan_grpc_web_unary_frames(wire_bytes[..], out_resp, found_data, found_trailer) else {
        return false;
    }
    guard found_trailer else {
        out_resp.payload.clear();
        out_resp.status = GrpcStatusCode.Internal;
        return false;
    }
    if !found_data {
        out_resp.is_trailers_only = true;
        if out_resp.status == GrpcStatusCode.Ok {
            out_resp.status = GrpcStatusCode.Internal;
            return false;
        }
    }
    return true;
}

// Extracts `grpc-status`, `grpc-message`, and `grpc-status-details-bin` from `res` trailers or headers.
//
// Example:
//   res.trailers["grpc-status"] = "0", res.status_code = 200
//   returns: true, out_resp.status = GrpcStatusCode.Ok
inline fn extract_client_response_status(res: const Response&, out_resp: GrpcResponse&) -> bool {
    let in_trailers = has_header(res.trailers, rfc::HEADER_GRPC_STATUS);
    let in_headers = !in_trailers && has_header(res.headers, rfc::HEADER_GRPC_STATUS);
    if !in_trailers && !in_headers {
        out_resp.status = grpc_status_from_http(res.status_code);
        return false;
    }
    let status_val = if in_trailers {
        trailer(res, rfc::HEADER_GRPC_STATUS)
    } else {
        header(res, rfc::HEADER_GRPC_STATUS)
    };
    let msg_val = if in_trailers {
        trailer(res, rfc::HEADER_GRPC_MESSAGE)
    } else {
        header(res, rfc::HEADER_GRPC_MESSAGE)
    };
    out_resp.status = grpc_status_from_code(parse_grpc_status_code(status_val));
    if res.status_code != 200 && out_resp.status == GrpcStatusCode.Ok {
        out_resp.status = grpc_status_from_http(res.status_code);
    }
    if msg_val.len > 0 {
        decode_grpc_message(msg_val, out_resp.message);
    }
    var details_b64 = trailer(res, rfc::HEADER_GRPC_STATUS_DETAILS_BIN);
    if details_b64.len == 0 {
        details_b64 = header(res, rfc::HEADER_GRPC_STATUS_DETAILS_BIN);
    }
    if details_b64.len > 0 {
        let _ = decode_grpc_status_details(
            details_b64, out_resp.status, out_resp.status, out_resp.message, out_resp.details,
        );
    }
    return true;
}

// Dispatches a Unary RPC through a client session, handling URL construction,
// LPM serialization, and response parsing.
fn grpc_unary_call(
    session:     Session&,
    base_url:    const u8[:],
    cfg:         const GrpcCallConfig&,
    request_msg: const u8[:],
    out_resp:    GrpcResponse&,
) -> bool {
    out_resp.payload.clear();
    out_resp.message.clear();
    out_resp.details.clear();
    out_resp.is_compressed = false;
    out_resp.is_trailers_only = false;

    var req = new_request("POST", "");
    build_grpc_http_request(cfg, base_url, request_msg, req);

    let res, err = do(session, req);
    guard ok(err) else {
        let rst_hdr = trailer(res, "x-wing-h2-rst-code");
        if rst_hdr.len > 0 {
            let rst_code, ok_rst = rst_hdr.parse_u32_dec();
            out_resp.status = if ok_rst { h2_error_to_grpc_status(rst_code) } else { GrpcStatusCode.Unavailable };
        } else {
            out_resp.status = GrpcStatusCode.Unavailable;
        }
        let take_err = min(err.message.len, out_resp.message.cap);
        let _ = out_resp.message.try_set(err.message[..take_err]);
        return false;
    }

    let rst_after = trailer(res, "x-wing-h2-rst-code");
    if rst_after.len > 0 {
        let rst_code, ok_rst = rst_after.parse_u32_dec();
        out_resp.status = if ok_rst { h2_error_to_grpc_status(rst_code) } else { GrpcStatusCode.Internal };
        return false;
    }

    let has_wire_status = extract_client_response_status(res, out_resp);
    let ct = header(res, "content-type");
    if cfg.is_web || cfg.is_web_text {
        guard is_grpc_web(ct) else {
            out_resp.status = grpc_status_from_http(res.status_code);
            return false;
        }
        if res.body.len == 0 && has_wire_status {
            out_resp.is_trailers_only = true;
            if out_resp.status == GrpcStatusCode.Ok {
                out_resp.status = GrpcStatusCode.Internal;
                return false;
            }
            return true;
        }
        let ok_web = process_grpc_web_response(res.body[..], ct, out_resp);
        if res.status_code != 200 && out_resp.status == GrpcStatusCode.Ok {
            out_resp.status = grpc_status_from_http(res.status_code);
        }
        return ok_web;
    }

    guard matches_grpc_media_type(ct.trim_lws(), rfc::GRPC_CONTENT_TYPE) else {
        out_resp.status = grpc_status_from_http(res.status_code);
        return false;
    }
    return decode_client_native_unary_body(res, has_wire_status, out_resp);
}

// Decodes a native HTTP/2 or HTTP/3 unary gRPC response body or Trailers-Only response.
//
// Example:
//   res.body = "\x00\x00\x00\x00\x05hello", has_wire_status = true
//   returns: true, out_resp.payload = "hello"
fn decode_client_native_unary_body(
    res:             const Response&,
    has_wire_status: bool,
    out_resp:        GrpcResponse&,
) -> bool {
    if res.body.len >= 5 {
        guard has_wire_status else {
            out_resp.payload.clear();
            return false;
        }
        var comp = false;
        let ok_lpm, consumed = decode_grpc_lpm(res.body[..], 0, out_resp.payload, comp);
        guard ok_lpm && consumed == res.body.len else {
            if out_resp.status == GrpcStatusCode.Ok {
                out_resp.status = GrpcStatusCode.Internal;
            }
            out_resp.payload.clear();
            return false;
        }
        out_resp.is_compressed = comp;
        let enc_hdr = header(res, rfc::HEADER_GRPC_ENCODING);
        let comp_st = validate_recv_compression(comp, enc_hdr, false);
        if comp_st != GrpcStatusCode.Ok {
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
                out_resp.status = classify_grpc_gzip_error(gz_err);
                out_resp.payload.clear();
                return false;
            }
            out_resp.payload.clear();
            out_resp.payload.append(decomp_buf[..]);
        } else {
            guard out_resp.payload.len <= rfc::GRPC_DEFAULT_MAX_MESSAGE_SIZE else {
                out_resp.status = GrpcStatusCode.ResourceExhausted;
                out_resp.payload.clear();
                return false;
            }
        }
        return true;
    }

    if res.body.len == 0 && has_wire_status {
        out_resp.is_trailers_only = true;
        if out_resp.status == GrpcStatusCode.Ok {
            out_resp.status = GrpcStatusCode.Internal;
            return false;
        }
        return true;
    }

    if out_resp.status == GrpcStatusCode.Ok {
        out_resp.status = GrpcStatusCode.Internal;
    }
    return false;
}

// ---- Streaming RPC Client Session (Bidi & Server Streaming) --------------

struct GrpcClientStreamOptions {
    is_web:          bool = false,
    use_compression: bool = false,
}

struct GrpcClientStream {
    stream_id:       u32              = 0,
    is_active:       bool             = true,
    is_web:          bool             = false,
    use_compression: bool             = false,
    parser:          GrpcStreamParser = GrpcStreamParser { .. },
}

fn new_grpc_client_stream(
    stream_id: u32,
    opts:      GrpcClientStreamOptions = GrpcClientStreamOptions { .. },
) -> GrpcClientStream {
    return GrpcClientStream {
        stream_id:       stream_id,
        is_active:       true,
        is_web:          opts.is_web,
        use_compression: opts.use_compression,
        parser:          new_grpc_stream_parser(),
    };
}

// Serializes an outbound message into wire LPM format for streaming send.
fn write_stream_message<B>(stream: GrpcClientStream&, payload: const u8[:], out: B&) {
    encode_grpc_lpm(payload, out, stream.use_compression);
}

// Feeds an inbound raw network or HTTP/2 DATA frame chunk into the stream parser.
fn feed_stream_chunk(stream: GrpcClientStream&, chunk: const u8[:]) -> bool {
    return feed(stream.parser, chunk);
}

// Reads the next completed inbound message from the stream.
fn read_stream_message<B>(stream: GrpcClientStream&, out_payload: B&, out_compressed: bool&) -> bool {
    guard next_message(stream.parser, out_payload, out_compressed) else { return false; }
    if out_compressed {
        var decomp_buf: u8[>..] = [];
        let ok_gz, _ = core::gzip_decompress_with_limit(out_payload[..], decomp_buf, stream.parser.max_size);
        out_payload.clear();
        guard ok_gz && out_payload.try_append(decomp_buf[..]) else {
            out_payload.clear();
            return false;
        }
    }
    return true;
}
