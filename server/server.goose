// Standalone zero-allocation HTTP server engine, wire protocol serializer, and connection coordinator.
// Conforms to RFC 9110 (HTTP Semantics), RFC 9112 (HTTP/1.1 Framing), and RFC 9113 (HTTP/2 Preface Detection).
namespace wing;

import std;
import core from "..";
import .router;
import .pool;
import .pipeline;
import .h2_multiplexer;

// ---- 1. Reason Phrases for HTTP/1.1 Status Line -----------------------------

fn http_status_reason_phrase(code: i32) -> const u8[:] {
    return match code {
        200 => "OK",
        201 => "Created",
        202 => "Accepted",
        204 => "No Content",
        206 => "Partial Content",
        301 => "Moved Permanently",
        302 => "Found",
        304 => "Not Modified",
        307 => "Temporary Redirect",
        308 => "Permanent Redirect",
        400 => "Bad Request",
        401 => "Unauthorized",
        403 => "Forbidden",
        404 => "Not Found",
        405 => "Method Not Allowed",
        408 => "Request Timeout",
        417 => "Expectation Failed",
        429 => "Too Many Requests",
        500 => "Internal Server Error",
        501 => "Not Implemented",
        502 => "Bad Gateway",
        503 => "Service Unavailable",
        504 => "Gateway Timeout",
        _ => "Unknown",
    };
}

// ---- 2. HTTP/1.1 Wire Request Parser ---------------------------------------

// Parses an incoming raw HTTP/1.1 request wire stream.
// Supports Content-Length and RFC 9112 Chunked Transfer Coding with Trailers.
// Enforces RFC 9112 Section 6.1 Smuggling Defense (TE/CL conflict detection).
// Returns (ok, total_bytes_consumed).
fn parse_http1_wire_request<Req>(wire: const u8[:], out_req: Req&) -> bool, i64 {
    guard wire.len >= 4 else { return false, 0; }

    // Find end of headers (\r\n\r\n)
    let hdr_end = core::index_of_slice(wire, "\r\n\r\n");
    guard hdr_end >= 0 else { return false, 0; }
    let header_end_idx = hdr_end + 4;
    let header_bytes = wire[..header_end_idx];

    // Find end of request line
    let line_end = core::index_of_slice(header_bytes, "\r\n");
    guard line_end > 0 else { return false, 0; }
    let req_line = header_bytes[..line_end];

    // Parse method (first space)
    let sp1 = core::index_of_byte(req_line, ' ');
    guard sp1 > 0 else { return false, 0; }
    let method_slice = req_line[..sp1];
    guard is_valid_header_name(method_slice) && method_slice.len <= out_req.method.cap else { return false, 0; }
    out_req.method.clear();
    out_req.method.append(method_slice);

    // Parse path (second space)
    let rest = req_line[(sp1 + 1)..];
    let sp2_rel = core::index_of_byte(rest, ' ');
    guard sp2_rel > 0 else { return false, 0; }
    let path_slice = rest[..sp2_rel];
    guard path_slice.len > 0 && path_slice.len <= out_req.url.cap else { return false, 0; }
    out_req.url.clear();
    out_req.url.append(path_slice);

    // Parse protocol version
    let proto_slice = rest[(sp2_rel + 1)..];
    guard proto_slice == "HTTP/1.1" || proto_slice == "HTTP/1.0" else { return false, 0; }

    // Parse headers
    let rest_headers = header_bytes[(line_end + 2)..];
    var cursor: i64 = 0;

    out_req.headers.clear();
    while cursor < rest_headers.len {
        let rel_end = core::index_of_slice(rest_headers[cursor..], "\r\n");
        if rel_end < 0 { break; }
        if rel_end == 0 { break; } // Empty line reached

        let line = rest_headers[cursor .. (cursor + rel_end)];
        let colon = core::index_of_byte(line, ':');
        // RFC 9112 Section 5.1 & Go #34540 / CVE-2019-16276:
        // Reject header field names with leading whitespace, spaces before colon, or non-tchar bytes.
        guard colon > 0 else { return false, 0; }
        let hname = line[..colon];
        guard is_valid_header_name(hname) else { return false, 0; }

        let hval = trim_lws(line[(colon + 1)..]);
        guard is_valid_header_value(hval) else { return false, 0; }

        var item = HeaderItem { .. };
        guard hname.len <= item.name.cap && hval.len <= item.value.cap else { return false, 0; }
        item.name.append(hname);
        item.value.append(hval);
        guard out_req.headers.len < out_req.headers.cap else { return false, 0; }
        out_req.headers.push(item);
        cursor += rel_end + 2;
    }

    out_req.trailers.clear();
    out_req.body.clear();

    // Check for Transfer-Encoding and Content-Length
    var has_te = false;
    var te_buf: u8[..64] = [];
    var has_cl = false;
    var cl_count = 0;
    var cl_len: i64 = 0;

    for &hdr in out_req.headers {
        if eq_ascii_fold(hdr.name[..], "transfer-encoding") {
            if has_te {
                // Multiple Transfer-Encoding headers: combine with comma (RFC 9112 Section 6.3)
                guard te_buf.len + 2 + hdr.value.len <= te_buf.cap else { return false, 0; }
                te_buf.append(", ");
                te_buf.append(hdr.value[..]);
            } else {
                has_te = true;
                te_buf.clear();
                guard hdr.value.len <= te_buf.cap else { return false, 0; }
                te_buf.append(hdr.value[..]);
            }
        } else if eq_ascii_fold(hdr.name[..], "content-length") {
            has_cl = true;
            cl_count++;
            let val_trimmed = trim_lws(hdr.value[..]);
            guard val_trimmed.len > 0 else { return false, 0; }
            let parsed_cl, ok_cl = core::parse_i64_dec(val_trimmed);
            guard ok_cl && parsed_cl >= 0 else { return false, 0; }
            if cl_count == 1 {
                cl_len = parsed_cl;
            } else if cl_len != parsed_cl {
                // Conflicting multiple Content-Length headers -> reject smuggling attempt
                return false, 0;
            }
        }
    }

    // RFC 9112 Section 6.1 Smuggling Protection:
    // If both Transfer-Encoding and Content-Length are present, reject as smuggling attempt.
    if has_te && has_cl {
        return false, 0;
    }

    if has_te {
        // Must validate transfer encoding value per RFC 9112 Section 6.3 & 7.1
        guard validate_transfer_encoding_value(te_buf[..]) else { return false, 0; }

        let dec_err, chunked_consumed = decode_chunked_body_with_trailers(
            wire[header_end_idx..],
            out_req.body,
            out_req.trailers
        );
        guard dec_err == ChunkedDecodeError.None else { return false, 0; }

        let total_consumed = header_end_idx + chunked_consumed;
        return true, total_consumed;
    }

    // Guard against signed integer addition overflow
    guard cl_len >= 0 && cl_len <= 0x7FFFFFFF && wire.len >= header_end_idx + cl_len else { return false, 0; }
    let total_consumed = header_end_idx + cl_len;

    if cl_len > 0 {
        out_req.body.append(wire[header_end_idx..total_consumed]);
    }

    return true, total_consumed;
}

// Parses an incoming raw HTTP/1.1 response wire stream into a Response model.
// Supports Content-Length and RFC 9112 Chunked Transfer Coding with Trailers.
// Returns (ok, total_bytes_consumed).
fn parse_http1_wire_response<Res>(wire: const u8[:], out_res: Res&) -> bool, i64 {
    guard wire.len >= 4 else { return false, 0; }

    let hdr_end = core::index_of_slice(wire, "\r\n\r\n");
    guard hdr_end >= 0 else { return false, 0; }
    let header_end_idx = hdr_end + 4;
    let header_bytes = wire[..header_end_idx];

    // Find end of status line
    let line_end = core::index_of_slice(header_bytes, "\r\n");
    guard line_end > 0 else { return false, 0; }

    let status_line = header_bytes[..line_end];
    guard status_line.len >= 12 && status_line[..7] == "HTTP/1." else { return false, 0; }

    // Parse 3-digit status code
    let c0 = status_line[9] - '0';
    let c1 = status_line[10] - '0';
    let c2 = status_line[11] - '0';
    guard c0 >= 0 && c0 <= 9 && c1 >= 0 && c1 <= 9 && c2 >= 0 && c2 <= 9 else { return false, 0; }
    out_res.status_code = c0 as i32 * 100 + c1 as i32 * 10 + c2;
    out_res.protocol.clear();
    out_res.protocol.append(status_line[..8]);

    // Parse headers
    let rest_headers = header_bytes[(line_end + 2)..];
    var cursor: i64 = 0;
    out_res.headers.clear();
    while cursor < rest_headers.len {
        let rel_end = core::index_of_slice(rest_headers[cursor..], "\r\n");
        if rel_end < 0 { break; }
        if rel_end == 0 { break; }

        let line = rest_headers[cursor .. (cursor + rel_end)];
        let colon = core::index_of_byte(line, ':');
        guard colon > 0 else { return false, 0; }
        let hname = line[..colon];
        guard is_valid_header_name(hname) else { return false, 0; }
        let hval = trim_lws(line[(colon + 1)..]);
        guard is_valid_header_value(hval) else { return false, 0; }

        var item = HeaderItem { .. };
        guard hname.len <= item.name.cap && hval.len <= item.value.cap else { return false, 0; }
        item.name.append(hname);
        item.value.append(hval);
        guard out_res.headers.len < out_res.headers.cap else { return false, 0; }
        out_res.headers.push(item);
        cursor += rel_end + 2;
    }

    out_res.trailers.clear();
    out_res.body.clear();

    // Check Transfer-Encoding
    var has_te = false;
    var te_buf: u8[..64] = [];
    var has_cl = false;
    var cl_count = 0;
    var cl_len: i64 = 0;

    for &hdr in out_res.headers {
        if eq_ascii_fold(hdr.name[..], "transfer-encoding") {
            if has_te {
                guard te_buf.len + 2 + hdr.value.len <= te_buf.cap else { return false, 0; }
                te_buf.append(", ");
                te_buf.append(hdr.value[..]);
            } else {
                has_te = true;
                te_buf.clear();
                guard hdr.value.len <= te_buf.cap else { return false, 0; }
                te_buf.append(hdr.value[..]);
            }
        } else if eq_ascii_fold(hdr.name[..], "content-length") {
            has_cl = true;
            cl_count++;
            let val_trimmed = trim_lws(hdr.value[..]);
            guard val_trimmed.len > 0 else { return false, 0; }
            let parsed_cl, ok_cl = core::parse_i64_dec(val_trimmed);
            guard ok_cl && parsed_cl >= 0 else { return false, 0; }
            if cl_count == 1 {
                cl_len = parsed_cl;
            } else if cl_len != parsed_cl {
                // Conflicting multiple Content-Length headers -> reject
                return false, 0;
            }
        }
    }

    // RFC 9112 Section 6.1: In responses, Transfer-Encoding overrides Content-Length
    if has_te && validate_transfer_encoding_value(te_buf[..]) {
        let dec_err, chunked_consumed = decode_chunked_body_with_trailers(
            wire[header_end_idx..],
            out_res.body,
            out_res.trailers
        );
        guard dec_err == ChunkedDecodeError.None else { return false, 0; }
        return true, header_end_idx + chunked_consumed;
    }

    // Status 204 No Content, 304 Not Modified, or 1xx: MUST NOT include message body
    if out_res.status_code == 204 || out_res.status_code == 304 || (out_res.status_code >= 100 && out_res.status_code < 200) {
        return true, header_end_idx;
    }

    if has_cl {
        guard cl_len >= 0 && cl_len <= 0x7FFFFFFF && wire.len >= header_end_idx + cl_len else { return false, 0; }
        if cl_len > 0 {
            out_res.body.append(wire[header_end_idx..(header_end_idx + cl_len)]);
        }
        return true, header_end_idx + cl_len;
    }

    // Otherwise, consume remainder of stream until connection close
    if wire.len > header_end_idx {
        out_res.body.append(wire[header_end_idx..]);
    }
    return true, wire.len;
}

// ---- 3. HTTP/1.1 Wire Response Serializer -----------------------------------

// Serializes an HTTP/1.1 response using chunked transfer coding and emits trailers (RFC 9112 Section 7.1).
fn serialize_status_line<B>(status_code: i32, out: B&) {
    out.append("HTTP/1.1 ");
    core::format_i64_dec(status_code as i64, out);
    out.push(' ');
    out.append(http_status_reason_phrase(status_code));
    out.append("\r\n");
}

fn serialize_server_header<B>(server_name: const u8[:], out: B&) {
    if server_name.len > 0 {
        out.append("Server: ");
        out.append(server_name);
        out.append("\r\n");
    }
}

fn serialize_http1_chunked_response<Res, B>(
    res: const Res&,
    server_name: const u8[:],
    chunk_size: i64,
    out_wire: B&
) {
    serialize_status_line(res.status_code, out_wire);
    serialize_server_header(server_name, out_wire);
    out_wire.append("Transfer-Encoding: chunked\r\n");

    if res.trailers.len > 0 {
        out_wire.append("Trailer: ");
        for i in res.trailers.len {
            if i > 0 { out_wire.append(", "); }
            out_wire.append(res.trailers[i].name[..]);
        }
        out_wire.append("\r\n");
    }

    let has_conn = res.has_header("connection");
    for &hdr in res.headers {
        if eq_ascii_fold(hdr.name[..], "content-length") { continue; }
        if eq_ascii_fold(hdr.name[..], "transfer-encoding") { continue; }
        if eq_ascii_fold(hdr.name[..], "trailer") && res.trailers.len > 0 { continue; }

        out_wire.append(hdr.name[..]);
        out_wire.append(": ");
        out_wire.append(hdr.value[..]);
        out_wire.append("\r\n");
    }

    if !has_conn {
        out_wire.append("Connection: keep-alive\r\n");
    }
    out_wire.append("\r\n");

    encode_chunked_payload(res.body[..], res.trailers, chunk_size, out_wire);
}

// Serializes a complete HTTP/1.1 response into raw wire bytes.
// Automatically uses chunked transfer encoding if Transfer-Encoding: chunked is requested or if trailers are present.
fn serialize_http1_response<Res, B>(res: const Res&, server_name: const u8[:], out_wire: B&) {
    let te = header(res, "transfer-encoding");
    if eq_ascii_fold(te, "chunked") || res.trailers.len > 0 {
        serialize_http1_chunked_response(res, server_name, 4096, out_wire);
        return;
    }

    serialize_status_line(res.status_code, out_wire);
    serialize_server_header(server_name, out_wire);

    if res.status_code != 204 && res.status_code != 304 {
        out_wire.append("Content-Length: ");
        core::format_i64_dec(res.body.len, out_wire);
        out_wire.append("\r\n");
    }

    let has_conn = res.has_header("connection");
    for &hdr in res.headers {
        out_wire.append(hdr.name[..]);
        out_wire.append(": ");
        out_wire.append(hdr.value[..]);
        out_wire.append("\r\n");
    }

    if !has_conn {
        out_wire.append("Connection: keep-alive\r\n");
    }

    out_wire.append("\r\n");

    if res.body.len > 0 {
        out_wire.append(res.body[..]);
    }
}

// ---- 4. HttpServer Container and Session Coordinator -----------------------

struct HttpServer {
    pipeline: ServerPipelineConfig = ServerPipelineConfig { .. },
    host: u8[..128] = "127.0.0.1",
    port: u16 = 8080,
    server_name: u8[..64] = "goose-wing/1.0",
    timer: internal::ConnectionTimer = internal::ConnectionTimer { .. },
    is_running: bool = false,
    requests_processed: u64 = 0,
    accept_proxy_protocol: bool = false,
}

fn new_http_server(
    host_str: const u8[:] = "127.0.0.1",
    port_num: u16 = 8080,
) -> HttpServer {
    var server = HttpServer {
        pipeline: new_default_server_pipeline_config(host_str),
        port: port_num,
        timer: internal::new_connection_timer(30000000000, 1000000000), // 30s timeout
        is_running: true,
        requests_processed: 0,
        ..
    };
    server.host.clear();
    server.host.append(host_str);
    return server;
}

fn new_http_server_with_quota<Q>(
    host_str: const u8[:],
    port_num: u16,
    quota: Q
) -> HttpServer {
    var server = HttpServer {
        pipeline: new_server_pipeline_config(host_str, quota),
        port: port_num,
        timer: internal::new_connection_timer(30000000000, 1000000000), // 30s timeout
        is_running: true,
        requests_processed: 0,
        ..
    };
    server.host.clear();
    server.host.append(host_str);
    return server;
}

// Registers routing handlers on the server instance
fn add_get_route(server: HttpServer&, path: const u8[:], handler_id: i32) {
    add_route(server.pipeline.router, "GET", path, handler_id);
}

fn add_post_route(server: HttpServer&, path: const u8[:], handler_id: i32) {
    add_route(server.pipeline.router, "POST", path, handler_id);
}

fn add_put_route(server: HttpServer&, path: const u8[:], handler_id: i32) {
    add_route(server.pipeline.router, "PUT", path, handler_id);
}

fn add_delete_route(server: HttpServer&, path: const u8[:], handler_id: i32) {
    add_route(server.pipeline.router, "DELETE", path, handler_id);
}

fn is_h2_client_preface(raw_stream: const u8[:]) -> bool {
    return raw_stream.len >= 24 && raw_stream[..24] == H2_CLIENT_PREFACE[..];
}

fn serialize_bad_request_error<B>(server_name: const u8[:], wire_out: B&) {
    var err_resp = new_response();
    err_resp.status_code = 400; // Bad Request
    serialize_http1_response(err_resp, server_name, wire_out);
}

// Processes an incoming raw connection payload, performing protocol detection (H1 vs H2 preface),
// executing the server pipeline, and serializing the wire response.
fn handle_connection_wire<B>(
    server: HttpServer&,
    client_ip: const u8[:],
    wire_in: const u8[:],
    now_ns: u64,
    wire_out: B&
) -> PipelineOutcome, bool {
    wire_out.clear();

    var effective_ip: u8[..64] = [];
    effective_ip.append(client_ip);
    var raw_stream = wire_in;
    var proxy_hdr = ProxyHeader { .. };

    if server.accept_proxy_protocol {
        let is_proxy = detect_proxy_protocol(wire_in);
        if is_proxy != ProxyProtocolVersion.None {
            let stripped, has_proxy = detect_and_strip_proxy_header(wire_in, proxy_hdr);
            guard has_proxy else {
                serialize_bad_request_error(server.server_name[..], wire_out);
                return PipelineOutcome.Handled, false;
            }
            raw_stream = stripped;
            if proxy_hdr.src_ip_str.len > 0 {
                effective_ip.clear();
                effective_ip.append(proxy_hdr.src_ip_str[..]);
            }
        }
    }

    if is_h2_client_preface(raw_stream) {
        let now_ms = (now_ns / 1000000) as u64;
        var sess = new_h2_server_session(server.server_name[..], now_ms);
        let _, ok_h2 = handle_h2_server_ingress(sess, server.pipeline, server.timer, effective_ip[..], raw_stream, now_ms, wire_out);
        if ok_h2 {
            server.requests_processed++;
            return PipelineOutcome.Handled, true;
        }
        return PipelineOutcome.Handled, false;
    }

    var req = new_request("GET", "");
    let ok_parse, _ = parse_http1_wire_request(raw_stream, req);
    guard ok_parse else {
        serialize_bad_request_error(server.server_name[..], wire_out);
        return PipelineOutcome.Handled, false;
    }

    var res = new_response();
    var future = internal::new_inline_handler_future(0);
    let outcome = execute_pipeline(server.pipeline, server.timer, effective_ip[..], req, now_ns, res, future);

    // RFC 9110 & CVE-2026-94439: HTTP/1 server connection desynchronization defense.
    // If request method is CONNECT, force Connection: close so the server never treats
    // an established tunnel or subsequent bytes as pipelined HTTP requests.
    if req.method[..] == "CONNECT" {
        header(res, "Connection", "close");
    }

    serialize_http1_response(res, server.server_name[..], wire_out);
    server.requests_processed++;

    return outcome, true;
}
