// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// High-level ergonomic gRPC client abstractions for Unary and Streaming RPCs.
// Supports native gRPC over HTTP/2 & HTTP/3 and gRPC-Web (binary and text).
namespace grpc;

import std;
import core from "..";
import rfc.grpc;
import http.headers;
import http.request;
import http.response;
import client.client;
import .constants;
import .framing;
import .status;
import .server;
import .internal;

// ---- gRPC Request & Response Models -------------------------------------

struct CallConfig {
    service:         u8[..128]      = [],
    method:          u8[..128]      = [],
    timeout_ms:      u64            = 0,
    is_web:          bool           = false,
    is_web_text:     bool           = false,
    use_compression: bool           = false,
    metadata:        Metadata[..16] = [],
}

fn new_call_config(service: const u8[:], method: const u8[:]) -> CallConfig {
    var cfg = CallConfig { .. };
    let _ = cfg.service.try_set(service);
    let _ = cfg.method.try_set(method);
    return cfg;
}

struct Response {
    status:           StatusCode       = StatusCode.Ok,
    message:          u8[..256]        = [],
    details:          ErrorDetail[..4] = [],
    is_compressed:    bool             = false,
    is_trailers_only: bool             = false,
    payload:          u8[>..]          = [],
}

fn is_success(res: const Response&) -> bool {
    return res.status == StatusCode.Ok;
}

// ---- Header and Request Builders ----------------------------------------

// Builds a low-level HeaderMap for native HTTP/2 or HTTP/3 framing.
fn build_request_headers(
    cfg:         const CallConfig&,
    host:        const u8[:],
    scheme:      const u8[:],
    out_headers: wing::HeaderMap&,
) {
    out_headers.reset_for_keep_alive();

    out_headers.append_header(":method", "POST");
    out_headers.append_header(":scheme", scheme);

    var path_buf: u8[..288] = [];
    path_buf.push('/');
    path_buf.append(cfg.service[..]);
    path_buf.push('/');
    path_buf.append(cfg.method[..]);
    out_headers.append_header(":path", path_buf[..]);

    out_headers.append_header(":authority", host);

    if cfg.is_web_text {
        out_headers.append_header("content-type", rfc::GRPC_WEB_TEXT_PROTO);
        out_headers.append_header("accept", rfc::GRPC_WEB_TEXT_PROTO);
    } else if cfg.is_web {
        out_headers.append_header("content-type", rfc::GRPC_WEB_CONTENT_TYPE_PROTO);
    } else {
        out_headers.append_header("content-type", rfc::GRPC_CONTENT_TYPE_PROTO);
    }

    out_headers.append_header("te", "trailers");

    if cfg.timeout_ms > 0 {
        var timeout_buf: u8[..32] = [];
        encode_timeout(cfg.timeout_ms, timeout_buf);
        out_headers.append_header(rfc::HEADER_GRPC_TIMEOUT, timeout_buf[..]);
    }

    if cfg.use_compression {
        out_headers.append_header(rfc::HEADER_GRPC_ENCODING, "gzip");
    }
    out_headers.append_header(rfc::HEADER_GRPC_ACCEPT_ENCODING, "identity,gzip");

    for &m in cfg.metadata {
        if grpc_internal::is_valid_custom_metadata(m.key[..], m.value[..]) {
            out_headers.append_header(m.key[..], m.value[..]);
        }
    }
}

// Builds a high-level Client Request object for dispatch through Session / Client.
fn build_http_request(
    cfg:            const CallConfig&,
    base_url:       const u8[:],
    serialized_msg: const u8[:],
    out_req:        wing::Request&,
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
        out_req.set_header("content-type", rfc::GRPC_WEB_TEXT_PROTO);
        out_req.set_header("accept", rfc::GRPC_WEB_TEXT_PROTO);
    } else if cfg.is_web {
        out_req.set_header("content-type", rfc::GRPC_WEB_CONTENT_TYPE_PROTO);
    } else {
        out_req.set_header("content-type", rfc::GRPC_CONTENT_TYPE_PROTO);
    }

    out_req.set_header("te", "trailers");

    if cfg.timeout_ms > 0 {
        var timeout_buf: u8[..32] = [];
        encode_timeout(cfg.timeout_ms, timeout_buf);
        out_req.set_header(rfc::HEADER_GRPC_TIMEOUT, timeout_buf[..]);
    }

    if cfg.use_compression {
        out_req.set_header(rfc::HEADER_GRPC_ENCODING, "gzip");
    }
    out_req.set_header(rfc::HEADER_GRPC_ACCEPT_ENCODING, "identity,gzip");
    grpc_internal::append_custom_metadata_to_request(out_req, cfg.metadata[..]);

    // Body LPM encoding
    out_req.body.clear();
    if cfg.is_web_text {
        var raw_lpm: u8[>..] = [];
        encode_lpm(serialized_msg, raw_lpm, cfg.use_compression);
        encode_web_text(raw_lpm[..], out_req.body);
    } else {
        encode_lpm(serialized_msg, out_req.body, cfg.use_compression);
    }
}

// ---- Unary Response Parser ----------------------------------------------

// Parses a unary gRPC or gRPC-Web response from headers, trailers, and body bytes.
//
// Example:
//   body = "\x00\x00\x00\x00\x05hello", is_web = false
//   returns: ok = true, out_resp.payload = "hello", out_resp.status = Ok
fn parse_unary_response(
    res_headers:  const wing::HeaderMap&,
    res_trailers: const wing::HeaderMap&,
    body:         const u8[:],
    is_web:       bool,
    out_resp:     Response&,
) -> bool {
    out_resp.payload.clear();
    out_resp.message.clear();
    out_resp.details.clear();
    out_resp.is_compressed = false;
    out_resp.is_trailers_only = false;

    if is_web {
        return grpc_internal::parse_web_unary_body(res_headers, res_trailers, body, out_resp);
    }

    let ct = res_headers.get_header("content-type");
    if ct.len > 0 && !grpc_internal::matches_media_type(ct.trim_lws(), rfc::GRPC_CONTENT_TYPE) {
        out_resp.status = status_from_http(grpc_internal::resolve_effective_http_status(res_headers));
        return false;
    }

    let has_wire_status = extract_status(res_headers, res_trailers, out_resp.status, out_resp.message);
    var details_b64 = res_trailers.get_header(rfc::HEADER_GRPC_STATUS_DETAILS_BIN);
    if details_b64.len == 0 {
        details_b64 = res_headers.get_header(rfc::HEADER_GRPC_STATUS_DETAILS_BIN);
    }
    if details_b64.len > 0 {
        let _ = decode_status_details(
            details_b64, out_resp.status, out_resp.status, out_resp.message, out_resp.details,
        );
    }
    let enc_hdr = res_headers.get_header(rfc::HEADER_GRPC_ENCODING);
    return grpc_internal::decode_native_unary_body(body, enc_hdr, has_wire_status, out_resp);
}

// ---- High-Level RPC Invocation via Client -------------------------------

// Parses a numeric gRPC status code from string.
//
// Example:
//   status_val = "0"
//   returns: 0
fn parse_status_code(status_val: const u8[:]) -> u32 {
    let trimmed = status_val.trim_lws();
    guard trimmed.len > 0 else { return 2; }
    let status_int, ok_code = trimmed.parse_u32_dec();
    if ok_code {
        return status_int;
    }
    return 2;
}

// Processes incoming gRPC-Web response body and trailers.
fn process_web_response(body: const u8[:], ct: const u8[:], out_resp: Response&) -> bool {
    guard grpc_internal::is_web(ct) else {
        out_resp.status = StatusCode.Unknown;
        return false;
    }
    var wire_bytes: u8[>..] = [];
    if grpc_internal::is_web_text(ct) {
        guard decode_web_text(body, wire_bytes) else { return false; }
    } else {
        wire_bytes.append(body);
    }

    var found_trailer = false;
    var found_data = false;
    guard grpc_internal::scan_web_unary_frames(wire_bytes[..], out_resp, found_data, found_trailer) else {
        return false;
    }
    guard found_trailer else {
        out_resp.payload.clear();
        out_resp.status = StatusCode.Internal;
        return false;
    }
    if !found_data {
        out_resp.is_trailers_only = true;
        if out_resp.status == StatusCode.Ok {
            out_resp.status = StatusCode.Internal;
            return false;
        }
    }
    return true;
}

// Dispatches a Unary RPC through a client session, handling URL construction,
// LPM serialization, and response parsing.
fn unary_call(
    session:     wing::Session&,
    base_url:    const u8[:],
    cfg:         const CallConfig&,
    request_msg: const u8[:],
    out_resp:    Response&,
) -> bool {
    out_resp.payload.clear();
    out_resp.message.clear();
    out_resp.details.clear();
    out_resp.is_compressed = false;
    out_resp.is_trailers_only = false;

    var req = wing::new_request("POST", "");
    cfg.build_http_request(base_url, request_msg, req);

    let res, err = wing::do(session, req);
    guard wing::ok(err) else {
        let rst_hdr = res.trailer("x-wing-h2-rst-code");
        if rst_hdr.len > 0 {
            let rst_code, ok_rst = rst_hdr.parse_u32_dec();
            out_resp.status = if ok_rst { h2_error_to_status(rst_code) } else { StatusCode.Unavailable };
        } else {
            out_resp.status = StatusCode.Unavailable;
        }
        let take_err = min(err.message.len, out_resp.message.cap);
        let _ = out_resp.message.try_set(err.message[..take_err]);
        return false;
    }

    let rst_after = res.trailer("x-wing-h2-rst-code");
    if rst_after.len > 0 {
        let rst_code, ok_rst = rst_after.parse_u32_dec();
        out_resp.status = if ok_rst { h2_error_to_status(rst_code) } else { StatusCode.Internal };
        return false;
    }

    let has_wire_status = grpc_internal::extract_client_response_status(res, out_resp);
    let ct = res.header("content-type");
    if cfg.is_web || cfg.is_web_text {
        guard grpc_internal::is_web(ct) else {
            out_resp.status = status_from_http(res.status_code);
            return false;
        }
        if res.body.len == 0 && has_wire_status {
            out_resp.is_trailers_only = true;
            if out_resp.status == StatusCode.Ok {
                out_resp.status = StatusCode.Internal;
                return false;
            }
            return true;
        }
        let ok_web = process_web_response(res.body[..], ct, out_resp);
        if res.status_code != 200 && out_resp.status == StatusCode.Ok {
            out_resp.status = status_from_http(res.status_code);
        }
        return ok_web;
    }

    guard grpc_internal::matches_media_type(ct.trim_lws(), rfc::GRPC_CONTENT_TYPE) else {
        out_resp.status = status_from_http(res.status_code);
        return false;
    }
    let enc_hdr = res.header(rfc::HEADER_GRPC_ENCODING);
    return grpc_internal::decode_native_unary_body(res.body[..], enc_hdr, has_wire_status, out_resp);
}

// ---- Streaming RPC Client Session (Bidi & Server Streaming) --------------

struct ClientStreamOptions {
    is_web:          bool = false,
    use_compression: bool = false,
}

struct ClientStream {
    stream_id:       u32          = 0,
    is_active:       bool         = true,
    is_web:          bool         = false,
    use_compression: bool         = false,
    parser:          StreamParser = StreamParser { .. },
}

fn new_client_stream(
    stream_id: u32,
    opts:      ClientStreamOptions = ClientStreamOptions { .. },
) -> ClientStream {
    return ClientStream {
        stream_id:       stream_id,
        is_active:       true,
        is_web:          opts.is_web,
        use_compression: opts.use_compression,
        parser:          new_stream_parser(),
    };
}

// Serializes an outbound message into wire LPM format for streaming send.
fn write_stream_message<B>(stream: ClientStream&, payload: const u8[:], out: B&) {
    encode_lpm(payload, out, stream.use_compression);
}

// Feeds an inbound raw network or HTTP/2 DATA frame chunk into the stream parser.
fn feed_stream_chunk(stream: ClientStream&, chunk: const u8[:]) -> bool {
    return stream.parser.feed(chunk);
}

// Reads the next completed inbound message from the stream.
fn read_stream_message<B>(stream: ClientStream&, out: B&, out_compressed: bool&) -> bool {
    guard stream.parser.next_message(out, out_compressed) else { return false; }
    if out_compressed {
        var decomp_buf: u8[>..] = [];
        let ok_gz, _ = core::gzip_decompress_with_limit(out[..], decomp_buf, stream.parser.max_size);
        out.clear();
        guard ok_gz && out.try_append(decomp_buf[..]) else {
            out.clear();
            return false;
        }
    }
    return true;
}
