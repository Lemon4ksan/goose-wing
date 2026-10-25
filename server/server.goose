// Standalone zero-allocation HTTP server engine, wire protocol serializer, and connection coordinator.
// Conforms to RFC 9110 (HTTP Semantics), RFC 9112 (HTTP/1.1 Framing), and RFC 9113 (HTTP/2 Preface Detection).
namespace wing;

import std;
import client.request;
import client.response;
import http.headers;
import security.rate_limiter;
import server.router;
import server.pool;
import server.pipeline;
import http2.framing;
import net.proxy_protocol;
import server.h2_multiplexer;
import client.stream;

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
fn parse_http1_wire_request(wire: const u8[:], out_req: Request&) -> bool, i64 {
    guard wire.len >= 4 else { return false, 0; }

    // Find end of headers (\r\n\r\n)
    var header_end_idx: i64 = -1;
    var scan = 0;
    while scan + 3 < wire.len {
        if wire[scan] == '\r' && wire[scan + 1] == '\n' && wire[scan + 2] == '\r' && wire[scan + 3] == '\n' {
            header_end_idx = scan + 4;
            break;
        }
        scan++;
    }
    guard header_end_idx > 0 else { return false, 0; }

    let header_bytes = wire[..header_end_idx];

    // Find end of request line
    var line_end: i64 = 0;
    while line_end + 1 < header_bytes.len && !(header_bytes[line_end] == '\r' && header_bytes[line_end + 1] == '\n') {
        line_end++;
    }
    guard line_end > 0 else { return false, 0; }

    let req_line = header_bytes[..line_end];

    // Parse method (first space)
    var sp1: i64 = -1;
    for i in req_line.len {
        if req_line[i] == ' ' {
            sp1 = i;
            break;
        }
    }
    guard sp1 > 0 else { return false, 0; }

    let method_slice = req_line[..sp1];
    out_req.method.clear();
    out_req.method.append(method_slice);

    // Parse path (second space)
    var sp2: i64 = -1;
    for i in (sp1 + 1)..req_line.len {
        if req_line[i] == ' ' {
            sp2 = i;
            break;
        }
    }
    guard sp2 > sp1 else { return false, 0; }

    let path_slice = req_line[(sp1 + 1)..sp2];
    out_req.url.clear();
    out_req.url.append(path_slice);

    // Parse headers
    let rest_headers = header_bytes[(line_end + 2)..];
    var cursor: i64 = 0;

    out_req.headers.clear();
    while cursor < rest_headers.len {
        var hline_end = cursor;
        while hline_end + 1 < rest_headers.len && !(rest_headers[hline_end] == '\r' && rest_headers[hline_end + 1] == '\n') {
            hline_end++;
        }
        if hline_end == cursor { break; } // Empty line reached

        let line = rest_headers[cursor..hline_end];
        var colon: i64 = -1;
        for i in line.len {
            if line[i] == ':' { colon = i; break; }
        }

        if colon > 0 {
            let hname = line[..colon];
            var vstart = colon + 1;
            while vstart < line.len && (line[vstart] == ' ' || line[vstart] == '\t') {
                vstart++;
            }
            let hval = line[vstart..];

            var item = HeaderItem { .. };
            item.name.append(hname);
            item.value.append(hval);
            if out_req.headers.len < out_req.headers.cap {
                out_req.headers.push(item);
            }
        }
        cursor = hline_end + 2;
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
            has_te = true;
            te_buf.clear();
            te_buf.append(hdr.value[..]);
        } else if eq_ascii_fold(hdr.name[..], "content-length") {
            has_cl = true;
            cl_count++;
            var parsed_cl: i64 = 0;
            let val_trimmed = trim_lws(hdr.value[..]);
            guard val_trimmed.len > 0 else { return false, 0; }
            for b in val_trimmed {
                guard b >= '0' && b <= '9' else { return false, 0; }
                parsed_cl = parsed_cl * 10 + (b - '0');
            }
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

    let total_consumed = header_end_idx + cl_len;
    guard wire.len >= total_consumed else { return false, 0; }

    if cl_len > 0 {
        out_req.body.append(wire[header_end_idx..total_consumed]);
    }

    return true, total_consumed;
}

// Parses an incoming raw HTTP/1.1 response wire stream into a Response model.
// Supports Content-Length and RFC 9112 Chunked Transfer Coding with Trailers.
// Returns (ok, total_bytes_consumed).
fn parse_http1_wire_response(wire: const u8[:], out_res: Response&) -> bool, i64 {
    guard wire.len >= 4 else { return false, 0; }

    var header_end_idx: i64 = -1;
    var scan = 0;
    while scan + 3 < wire.len {
        if wire[scan] == '\r' && wire[scan + 1] == '\n' && wire[scan + 2] == '\r' && wire[scan + 3] == '\n' {
            header_end_idx = scan + 4;
            break;
        }
        scan++;
    }
    guard header_end_idx > 0 else { return false, 0; }

    let header_bytes = wire[..header_end_idx];

    // Find end of status line
    var line_end: i64 = 0;
    while line_end + 1 < header_bytes.len && !(header_bytes[line_end] == '\r' && header_bytes[line_end + 1] == '\n') {
        line_end++;
    }
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
        var hline_end = cursor;
        while hline_end + 1 < rest_headers.len && !(rest_headers[hline_end] == '\r' && rest_headers[hline_end + 1] == '\n') {
            hline_end++;
        }
        if hline_end == cursor { break; }

        let line = rest_headers[cursor..hline_end];
        var colon: i64 = -1;
        for i in line.len {
            if line[i] == ':' { colon = i; break; }
        }

        if colon > 0 {
            let hname = line[..colon];
            var vstart = colon + 1;
            while vstart < line.len && (line[vstart] == ' ' || line[vstart] == '\t') {
                vstart++;
            }
            let hval = line[vstart..];

            var item = HeaderItem { .. };
            item.name.append(hname);
            item.value.append(hval);
            if out_res.headers.len < out_res.headers.cap {
                out_res.headers.push(item);
            }
        }
        cursor = hline_end + 2;
    }

    out_res.trailers.clear();
    out_res.body.clear();

    // Check Transfer-Encoding
    var has_te = false;
    var te_buf: u8[..64] = [];
    var has_cl = false;
    var cl_len: i64 = 0;

    for &hdr in out_res.headers {
        if eq_ascii_fold(hdr.name[..], "transfer-encoding") {
            has_te = true;
            te_buf.clear();
            te_buf.append(hdr.value[..]);
        } else if eq_ascii_fold(hdr.name[..], "content-length") {
            has_cl = true;
            var parsed_cl: i64 = 0;
            let val_trimmed = trim_lws(hdr.value[..]);
            for b in val_trimmed {
                if b >= '0' && b <= '9' {
                    parsed_cl = parsed_cl * 10 + (b - '0');
                }
            }
            cl_len = parsed_cl;
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
        guard wire.len >= header_end_idx + cl_len else { return false, 0; }
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
fn serialize_http1_chunked_response<B>(
    res: const Response&,
    server_name: const u8[:],
    chunk_size: i64,
    out_wire: B&
) {
    // 1. Status line: HTTP/1.1 <status> <reason>\r\n
    out_wire.append("HTTP/1.1 ");
    format(out_wire, res.status_code as i64);
    out_wire.push(' ');
    out_wire.append(http_status_reason_phrase(res.status_code));
    out_wire.append("\r\n");

    // 2. Server header
    if server_name.len > 0 {
        out_wire.append("Server: ");
        out_wire.append(server_name);
        out_wire.append("\r\n");
    }

    // 3. Transfer-Encoding: chunked (RFC 9112 Section 7.1)
    out_wire.append("Transfer-Encoding: chunked\r\n");

    // 4. Trailer announcement header (RFC 9110 Section 6.5.1)
    if res.trailers.len > 0 {
        out_wire.append("Trailer: ");
        for i in res.trailers.len {
            if i > 0 { out_wire.append(", "); }
            out_wire.append(res.trailers[i].name[..]);
        }
        out_wire.append("\r\n");
    }

    // 5. Custom headers (excluding Content-Length & Transfer-Encoding)
    var has_conn = false;
    for &hdr in res.headers {
        if eq_ascii_fold(hdr.name[..], "connection") { has_conn = true; }
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

    // Header terminator
    out_wire.append("\r\n");

    // 6. Body chunked framing and trailers
    encode_chunked_payload(res.body[..], res.trailers, chunk_size, out_wire);
}

// Serializes a complete HTTP/1.1 response into raw wire bytes.
// Automatically uses chunked transfer encoding if Transfer-Encoding: chunked is requested or if trailers are present.
fn serialize_http1_response<B>(res: const Response&, server_name: const u8[:], out_wire: B&) {
    let te = header(res, "transfer-encoding");
    if eq_ascii_fold(te, "chunked") || res.trailers.len > 0 {
        serialize_http1_chunked_response(res, server_name, 4096, out_wire);
        return;
    }

    // 1. Status line: HTTP/1.1 <status> <reason>\r\n
    out_wire.append("HTTP/1.1 ");
    format(out_wire, res.status_code as i64);
    out_wire.push(' ');
    out_wire.append(http_status_reason_phrase(res.status_code));
    out_wire.append("\r\n");

    // 2. Server header
    if server_name.len > 0 {
        out_wire.append("Server: ");
        out_wire.append(server_name);
        out_wire.append("\r\n");
    }

    // 3. Content-Length header (if not 204 or 304)
    if res.status_code != 204 && res.status_code != 304 {
        out_wire.append("Content-Length: ");
        format(out_wire, res.body.len);
        out_wire.append("\r\n");
    }

    // 4. Custom headers
    var has_conn = false;
    for &hdr in res.headers {
        if eq_ascii_fold(hdr.name[..], "connection") { has_conn = true; }
        out_wire.append(hdr.name[..]);
        out_wire.append(": ");
        out_wire.append(hdr.value[..]);
        out_wire.append("\r\n");
    }

    // Default Connection: keep-alive
    if !has_conn {
        out_wire.append("Connection: keep-alive\r\n");
    }

    // 5. Header terminator
    out_wire.append("\r\n");

    // 6. Body payload
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
    timer: ConnectionTimer = ConnectionTimer { .. },
    is_running: bool = false,
    requests_processed: u64 = 0,
    accept_proxy_protocol: bool = false,
}

fn new_http_server(
    host_str: const u8[:] = "127.0.0.1",
    port_num: u16 = 8080,
    quota: GcraQuota = new_gcra_quota(1000, core::secs(1), 100)
) -> HttpServer {
    var server = HttpServer {
        pipeline: new_server_pipeline_config(host_str, quota),
        port: port_num,
        timer: new_connection_timer(30000000000, 1000000000), // 30s timeout
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
        let stripped, has_proxy = detect_and_strip_proxy_header(wire_in, proxy_hdr);
        if has_proxy {
            raw_stream = stripped;
            if proxy_hdr.src_ip_str.len > 0 {
                effective_ip.clear();
                effective_ip.append(proxy_hdr.src_ip_str[..]);
            }
        }
    }

    // 1. Check for HTTP/2 Client Connection Preface (RFC 9113 Section 3.4)
    if raw_stream.len >= 24 && raw_stream[..24] == H2_CLIENT_PREFACE[..] {
        let now_ms = (now_ns / 1000000) as u64;
        var sess = new_h2_server_session(server.server_name[..], now_ms);
        let _, ok_h2 = handle_h2_server_ingress(sess, server.pipeline, server.timer, effective_ip[..], raw_stream, now_ms, wire_out);
        if ok_h2 {
            server.requests_processed++;
            return PipelineOutcome.Handled, true;
        }
        return PipelineOutcome.Handled, false;
    }

    // 2. Parse HTTP/1.1 wire request
    var req = new_request("GET", "");
    let ok_parse, _ = parse_http1_wire_request(raw_stream, req);
    guard ok_parse else {
        var err_resp = new_response();
        err_resp.status_code = 400; // Bad Request
        serialize_http1_response(err_resp, server.server_name[..], wire_out);
        return PipelineOutcome.Handled, false;
    }

    // 3. Execute request through full server pipeline
    var res = new_response();
    var future = new_inline_handler_future(0);
    let outcome = execute_pipeline(server.pipeline, server.timer, effective_ip[..], req, now_ns, res, future);

    // 4. Serialize HTTP/1.1 response wire bytes
    serialize_http1_response(res, server.server_name[..], wire_out);
    server.requests_processed++;

    return outcome, true;
}
