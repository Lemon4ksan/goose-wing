// High-level ergonomic gRPC client abstractions for Unary and Streaming RPCs.
// Supports native gRPC over HTTP/2 & HTTP/3 and gRPC-Web (binary and text).
namespace wing;

import std;
import grpc.constants;
import grpc.framing;
import grpc.status;
import http.headers;
import client.profile;
import client.request;
import client.response;
import client.client;

// ---- 1. gRPC Request & Response Models -------------------------------------

struct GrpcMetadata {
    key: u8[..64] = [],
    value: u8[..256] = [],
}

struct GrpcCallConfig {
    service: u8[..128] = [],
    method: u8[..128] = [],
    timeout_ms: u64 = 0,
    is_web: bool = false,
    is_web_text: bool = false,
    use_compression: bool = false,
    metadata: GrpcMetadata[..16] = [],
}

fn new_grpc_call_config(service: const u8[:], method: const u8[:]) -> GrpcCallConfig {
    var cfg = GrpcCallConfig { .. };
    cfg.service.append(service);
    cfg.method.append(method);
    return cfg;
}

struct GrpcResponse {
    status: GrpcStatusCode = GrpcStatusCode.Ok,
    message: u8[..256] = [],
    is_compressed: bool = false,
    is_trailers_only: bool = false,
    payload: u8[>..] = [],
}

fn new_grpc_response() -> GrpcResponse {
    return GrpcResponse { .. };
}

fn is_grpc_success(res: const GrpcResponse&) -> bool {
    return res.status == GrpcStatusCode.Ok;
}

// ---- 2. Header and Request Builders ----------------------------------------

// Builds a low-level HeaderMap for native HTTP/2 or HTTP/3 framing.
fn build_grpc_request_headers(
    cfg: const GrpcCallConfig&,
    host: const u8[:],
    scheme: const u8[:],
    out_headers: HeaderMap&
) {
    reset_for_keep_alive(out_headers);

    append_header(out_headers, ":method", "POST");
    append_header(out_headers, ":scheme", scheme);

    var path_buf: u8[..256] = [];
    path_buf.push('/');
    path_buf.append(cfg.service[..]);
    path_buf.push('/');
    path_buf.append(cfg.method[..]);
    append_header(out_headers, ":path", path_buf[..]);

    append_header(out_headers, ":authority", host);

    if cfg.is_web_text {
        append_header(out_headers, "content-type", GRPC_WEB_TEXT_PROTO);
    } else if cfg.is_web {
        append_header(out_headers, "content-type", GRPC_WEB_CONTENT_TYPE_PROTO);
    } else {
        append_header(out_headers, "content-type", GRPC_CONTENT_TYPE_PROTO);
    }

    append_header(out_headers, "te", "trailers");

    if cfg.timeout_ms > 0 {
        var timeout_buf: u8[..32] = [];
        encode_grpc_timeout(cfg.timeout_ms, timeout_buf);
        append_header(out_headers, HEADER_GRPC_TIMEOUT, timeout_buf[..]);
    }

    if cfg.use_compression {
        append_header(out_headers, HEADER_GRPC_ENCODING, "gzip");
    }
    append_header(out_headers, HEADER_GRPC_ACCEPT_ENCODING, "identity,gzip");

    for i in cfg.metadata.len {
        append_header(out_headers, cfg.metadata[i].key[..], cfg.metadata[i].value[..]);
    }
}

// Builds a high-level Client Request object for dispatch through Session / Client.
fn build_grpc_http_request(
    cfg: const GrpcCallConfig&,
    base_url: const u8[:],
    serialized_msg: const u8[:],
    out_req: Request&
) {
    out_req.method.clear();
    out_req.method.append("POST");

    out_req.url.clear();
    out_req.url.append(base_url);
    if out_req.url.len > 0 && out_req.url[out_req.url.len - 1] == '/' {
        out_req.url.append(cfg.service[..]);
        out_req.url.push('/');
        out_req.url.append(cfg.method[..]);
    } else {
        out_req.url.push('/');
        out_req.url.append(cfg.service[..]);
        out_req.url.push('/');
        out_req.url.append(cfg.method[..]);
    }

    // Headers
    var ct_hdr = HeaderItem { .. };
    ct_hdr.name.append("content-type");
    if cfg.is_web_text {
        ct_hdr.value.append(GRPC_WEB_TEXT_PROTO);
    } else if cfg.is_web {
        ct_hdr.value.append(GRPC_WEB_CONTENT_TYPE_PROTO);
    } else {
        ct_hdr.value.append(GRPC_CONTENT_TYPE_PROTO);
    }
    out_req.headers.push(ct_hdr);

    var te_hdr = HeaderItem { .. };
    te_hdr.name.append("te");
    te_hdr.value.append("trailers");
    out_req.headers.push(te_hdr);

    if cfg.timeout_ms > 0 {
        var timeout_hdr = HeaderItem { .. };
        timeout_hdr.name.append(HEADER_GRPC_TIMEOUT);
        encode_grpc_timeout(cfg.timeout_ms, timeout_hdr.value);
        out_req.headers.push(timeout_hdr);
    }

    for i in cfg.metadata.len {
        var meta_hdr = HeaderItem { .. };
        meta_hdr.name.append(cfg.metadata[i].key[..]);
        meta_hdr.value.append(cfg.metadata[i].value[..]);
        out_req.headers.push(meta_hdr);
    }

    // Body LPM encoding
    out_req.body.clear();
    if cfg.is_web_text {
        var raw_lpm: u8[..8192] = [];
        encode_grpc_lpm(serialized_msg, raw_lpm, cfg.use_compression);
        encode_grpc_web_text(raw_lpm[..], out_req.body);
    } else {
        encode_grpc_lpm(serialized_msg, out_req.body, cfg.use_compression);
    }
}

// ---- 3. Unary Response Parser ----------------------------------------------

fn parse_grpc_unary_response(
    res_headers: const HeaderMap&,
    res_trailers: const HeaderMap&,
    body: const u8[:],
    is_web: bool,
    out_resp: GrpcResponse&
) -> bool {
    out_resp.payload.clear();
    out_resp.message.clear();
    out_resp.is_compressed = false;
    out_resp.is_trailers_only = false;

    // gRPC-Web handling (trailers encoded in body with flag 0x80)
    if is_web {
        var wire_bytes: u8[..65536] = [];
        let content_type = get_header(res_headers, "content-type");
        if starts_with_ignore_case(content_type, GRPC_WEB_TEXT_CONTENT_TYPE) {
            guard decode_grpc_web_text(body, wire_bytes) else { return false; }
        } else {
            wire_bytes.append(body);
        }

        var offset: u32 = 0;
        var found_trailer = false;
        while offset < (wire_bytes.len as u32) {
            var frame_payload: u8[..16384] = [];
            var is_trailers = false;
            var is_comp = false;
            let ok_frame, consumed = decode_grpc_web_frame(wire_bytes[..], offset, frame_payload, is_trailers, is_comp);
            guard ok_frame else { break; }

            if is_trailers {
                parse_grpc_web_trailers(frame_payload[..], out_resp.status, out_resp.message);
                found_trailer = true;
            } else {
                out_resp.payload.append(frame_payload[..]);
                out_resp.is_compressed = is_comp;
            }
            offset += consumed;
        }

        if !found_trailer {
            extract_grpc_status(res_headers, res_trailers, out_resp.status, out_resp.message);
        }
        return true;
    }

    // Native HTTP/2 or HTTP/3 gRPC
    let has_wire_status = extract_grpc_status(res_headers, res_trailers, out_resp.status, out_resp.message);
    if body.len >= 5 {
        var comp = false;
        let ok_lpm, _ = decode_grpc_lpm(body, 0, out_resp.payload, comp);
        out_resp.is_compressed = comp;
        return ok_lpm;
    }

    if has_wire_status {
        out_resp.is_trailers_only = true;
        return true;
    }

    return false;
}

// ---- 4. High-Level RPC Invocation via Client -------------------------------

// Dispatches a Unary RPC through a client session, handling URL construction,
// LPM serialization, and response parsing.
fn grpc_unary_call(
    session: Session&,
    base_url: const u8[:],
    cfg: const GrpcCallConfig&,
    request_msg: const u8[:],
    out_resp: GrpcResponse&
) -> bool {
    var req = new_request("POST", "");
    build_grpc_http_request(cfg, base_url, request_msg, req);

    let res, err = do(session, req);
    guard ok(err) else {
        out_resp.status = GrpcStatusCode.Unavailable;
        out_resp.message.clear();
        out_resp.message.append(err.message[..]);
        return false;
    }

    // Check for explicit grpc-status in response headers (trailers or headers-only)
    let status_val = header(res, HEADER_GRPC_STATUS);
    if status_val.len > 0 {
        var status_int: u32 = 0;
        for b in trim_lws(status_val) {
            if b >= '0' && b <= '9' {
                status_int = status_int * 10 + (b - '0');
            }
        }
        out_resp.status = grpc_status_from_code(status_int);

        let msg_val = header(res, HEADER_GRPC_MESSAGE);
        if msg_val.len > 0 {
            decode_grpc_message(msg_val, out_resp.message);
        }
    } else {
        out_resp.status = grpc_status_from_http(res.status_code);
    }

    if cfg.is_web {
        var wire_bytes: u8[..65536] = [];
        let ct = header(res, "content-type");
        if starts_with_ignore_case(ct, GRPC_WEB_TEXT_CONTENT_TYPE) {
            decode_grpc_web_text(res.body[..], wire_bytes);
        } else {
            wire_bytes.append(res.body[..]);
        }

        var offset: u32 = 0;
        while offset < (wire_bytes.len as u32) {
            var frame_payload: u8[..16384] = [];
            var is_trailers = false;
            var is_comp = false;
            let ok_frame, consumed = decode_grpc_web_frame(wire_bytes[..], offset, frame_payload, is_trailers, is_comp);
            guard ok_frame else { break; }

            if is_trailers {
                parse_grpc_web_trailers(frame_payload[..], out_resp.status, out_resp.message);
            } else {
                out_resp.payload.clear();
                out_resp.payload.append(frame_payload[..]);
                out_resp.is_compressed = is_comp;
            }
            offset += consumed;
        }
        return true;
    }

    // Native gRPC body
    if res.body.len >= 5 {
        var comp = false;
        let ok_lpm, _ = decode_grpc_lpm(res.body[..], 0, out_resp.payload, comp);
        out_resp.is_compressed = comp;
        return ok_lpm;
    }

    return true;
}

// ---- 5. Streaming RPC Client Session (Bidi & Server Streaming) --------------

struct GrpcClientStream {
    stream_id: u32 = 0,
    is_active: bool = true,
    is_web: bool = false,
    use_compression: bool = false,
    parser: GrpcStreamParser = GrpcStreamParser { .. },
}

fn new_grpc_client_stream(stream_id: u32, is_web: bool = false, use_compression: bool = false) -> GrpcClientStream {
    return GrpcClientStream {
        stream_id: stream_id,
        is_active: true,
        is_web: is_web,
        use_compression: use_compression,
        parser: new_grpc_stream_parser(),
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
    return next_message(stream.parser, out_payload, out_compressed);
}
