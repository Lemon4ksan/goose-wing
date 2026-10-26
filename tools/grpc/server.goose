// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Dedicated gRPC and gRPC-Web Server for goose-wing E2E Verification.
// Implements RFC gRPC over HTTP/2, RFC 7540/9113, and gRPC-Web (binary and text).
import std;
import core from "../..";
import wing from "../..";

fn grpc_test_unary_handler(
    handler_id: u16,
    ctx: wing::GrpcServerContext&,
    req_payload: const u8[:],
    res_payload: u8[>..]&,
    out_status: wing::GrpcStatusCode&,
    out_message: u8[..256]&
) {
    if handler_id == 1 {
        // helloworld.Greeter/SayHello
        let auth = wing::get_metadata(ctx, "authorization");
        if auth == "Bearer invalid-token" {
            out_status = wing::GrpcStatusCode.Unauthenticated;
            out_message.append("Invalid authorization token");
            return;
        }

        wing::add_response_metadata(ctx, "x-server-version", "wing-grpc-v2");
        wing::add_response_metadata(ctx, "x-grpc-engine", "goose-wing");

        // Parse Protobuf string field or raw bytes
        // Protobuf wire type for string field 1 is 0x0A followed by length varint
        var name_slice = req_payload;
        if req_payload.len >= 2 && req_payload[0] == 0x0A {
            let p_len = req_payload[1] as i64;
            if req_payload.len >= 2 + p_len {
                name_slice = req_payload[2 .. (2 + p_len)];
            }
        }

        // Response: protobuf field 1 (0x0A, len, "Hello, <name>!")
        var greeting: u8[>..] = [];
        greeting.append("Hello, ");
        greeting.append(name_slice);
        greeting.push('!');

        if req_payload.len >= 2 && req_payload[0] == 0x0A {
            res_payload.push(0x0A);
            res_payload.push(greeting.len as u8);
            res_payload.append(greeting[..]);
        } else {
            res_payload.append(greeting[..]);
        }

        out_status = wing::GrpcStatusCode.Ok;
    } else if handler_id == 2 {
        // echo.EchoService/Echo
        for &m in ctx.metadata {
            let k = m.key[..];
            if core::starts_with_fold(k, "x-echo-") {
                wing::add_response_metadata(ctx, k, m.value[..]);
            }
        }
        res_payload.append(req_payload);
        out_status = wing::GrpcStatusCode.Ok;
    } else if handler_id == 3 {
        // echo.EchoService/Fail
        out_status = wing::GrpcStatusCode.PermissionDenied;
        out_message.append("Access denied by goose security policy");
    }
}

fn emit_grpc_h2_headers<B>(
    hpack_enc: wing::DynamicTable&,
    stream_id: u32,
    res: const wing::Response&,
    end_stream: bool,
    out: B&
) {
    var hpack_block: u8[..4096] = [];
    var status_buf: u8[..16] = "200";
    wing::encode_hpack_field(hpack_enc, hpack_block, ":status", status_buf[..], true, false);
    wing::encode_hpack_field(hpack_enc, hpack_block, "content-type", "application/grpc", true, false);

    for &hdr in res.headers {
        let n = hdr.name[..];
        let v = hdr.value[..];
        if !core::eq_ascii_fold(n, "content-type") && !core::starts_with_fold(n, ":") {
            wing::encode_hpack_field(hpack_enc, hpack_block, n, v, true, false);
        }
    }

    var flags: u8 = 4; // FLAG_END_HEADERS
    if end_stream {
        flags = flags | 1; // FLAG_END_STREAM
    }

    let hdr = wing::FrameHeader {
        length: hpack_block.len as u32,
        frame_type: 1, // HEADERS
        flags: flags,
        stream_id: stream_id,
    };
    wing::encode_frame_header_to(hdr, out);
    out.append(hpack_block[..]);
}

fn emit_grpc_h2_data<B>(
    stream_id: u32,
    body: const u8[:],
    end_stream: bool,
    out: B&
) {
    guard body.len > 0 else { return; }
    var flags: u8 = 0;
    if end_stream {
        flags = flags | 1;
    }

    let hdr = wing::FrameHeader {
        length: body.len as u32,
        frame_type: 0, // DATA
        flags: flags,
        stream_id: stream_id,
    };
    wing::encode_frame_header_to(hdr, out);
    out.append(body);
}

fn emit_grpc_h2_trailers<B>(
    hpack_enc: wing::DynamicTable&,
    stream_id: u32,
    trailers: const wing::HeaderItem[..16]&,
    out: B&
) {
    var hpack_block: u8[..4096] = [];
    for &t in trailers {
        wing::encode_hpack_field(hpack_enc, hpack_block, t.name[..], t.value[..], true, false);
    }

    let flags: u8 = 4 | 1; // FLAG_END_HEADERS | FLAG_END_STREAM
    let hdr = wing::FrameHeader {
        length: hpack_block.len as u32,
        frame_type: 1, // HEADERS
        flags: flags,
        stream_id: stream_id,
    };
    wing::encode_frame_header_to(hdr, out);
    out.append(hpack_block[..]);
}

fn handle_grpc_h2_session(conn: i64, initial_buf: const u8[:], dispatcher: wing::GrpcServerDispatcher&) {
    // Send server settings
    var server_settings_wire: u8[9] = [
        0, 0, 0,    // len = 0
        4,          // type = SETTINGS
        0,          // flags = 0
        0, 0, 0, 0  // stream = 0
    ];
    wing::tcp_send(conn, server_settings_wire[..]);

    var hpack_dec = wing::new_dynamic_table(4096);
    var hpack_enc = wing::new_dynamic_table(4096);

    var in_buf: u8[>..] = [];
    if initial_buf.len > 24 {
        in_buf.append(initial_buf[24..]);
    }

    var is_running = true;
    while is_running {
        while in_buf.len >= 9 {
            let length = ((in_buf[0] as u32) << 16) | ((in_buf[1] as u32) << 8) | in_buf[2];
            let frame_type = in_buf[3];
            let flags = in_buf[4];
            let stream_id = (((in_buf[5] as u32) & 0x7F) << 24) | ((in_buf[6] as u32) << 16) | ((in_buf[7] as u32) << 8) | in_buf[8];

            let total_len = 9 + (length as i64);
            if in_buf.len < total_len {
                break;
            }

            let payload = in_buf[9..total_len];

            if frame_type == 4 { // SETTINGS
                if (flags & 1) == 0 { // Send ACK
                    var ack: u8[9] = [0, 0, 0, 4, 1, 0, 0, 0, 0];
                    wing::tcp_send(conn, ack[..]);
                }
            } else if frame_type == 6 { // PING
                if (flags & 1) == 0 && payload.len == 8 {
                    var pong: u8[17] = [0, 0, 8, 6, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
                    for p in 8 { pong[9 + p] = payload[p]; }
                    wing::tcp_send(conn, pong[..]);
                }
            } else if frame_type == 1 { // HEADERS
                var dec_list = wing::DecodedH2HeaderList { .. };
                var pad_offset: i64 = 0;
                var pay_end: i64 = payload.len;
                if (flags & 8) != 0 && payload.len > 0 {
                    let pad_len = payload[0] as i64;
                    pad_offset += 1;
                    pay_end -= pad_len;
                }
                if (flags & 0x20) != 0 {
                    pad_offset += 5;
                }

                if pad_offset <= pay_end {
                    let frag = payload[pad_offset..pay_end];
                    wing::decode_hpack_header_block(hpack_dec, frag, dec_list);
                }

                var req = wing::new_request("POST", "");
                for &f in dec_list.fields {
                    let n = f.name[..];
                    let v = f.value[..];
                    if n == ":path" {
                        req.url.append(v);
                    } else if !core::starts_with_fold(n, ":") {
                        var h = wing::HeaderItem { .. };
                        h.name.append(n);
                        h.value.append(v);
                        req.headers.push(h);
                    }
                }

                if (flags & 1) != 0 { // END_STREAM
                    var res = wing::new_response();
                    wing::dispatch_grpc_unary(dispatcher, req, 1000000, res, grpc_test_unary_handler);

                    var out_bytes: u8[>..] = [];
                    let end_hdr = res.body.len == 0 && res.trailers.len == 0;
                    emit_grpc_h2_headers(hpack_enc, stream_id, res, end_hdr, out_bytes);
                    if res.body.len > 0 {
                        emit_grpc_h2_data(stream_id, res.body[..], res.trailers.len == 0, out_bytes);
                    }
                    if res.trailers.len > 0 {
                        emit_grpc_h2_trailers(hpack_enc, stream_id, res.trailers, out_bytes);
                    }
                    if out_bytes.len > 0 {
                        wing::tcp_send(conn, out_bytes[..]);
                    }
                }
            } else if frame_type == 0 { // DATA
                var req = wing::new_request("POST", "/helloworld.Greeter/SayHello");
                req.body.append(payload);

                var ct = wing::HeaderItem { .. };
                ct.name.append("content-type");
                ct.value.append("application/grpc");
                req.headers.push(ct);

                var res = wing::new_response();
                wing::dispatch_grpc_unary(dispatcher, req, 1000000, res, grpc_test_unary_handler);

                var out_bytes: u8[>..] = [];
                emit_grpc_h2_headers(hpack_enc, stream_id, res, false, out_bytes);
                emit_grpc_h2_data(stream_id, res.body[..], false, out_bytes);
                emit_grpc_h2_trailers(hpack_enc, stream_id, res.trailers, out_bytes);

                if out_bytes.len > 0 {
                    wing::tcp_send(conn, out_bytes[..]);
                }
            } else if frame_type == 7 { // GOAWAY
                is_running = false;
                break;
            }

            var rem: u8[>..] = [];
            rem.append(in_buf[total_len..]);
            in_buf.clear();
            in_buf.append(rem[..]);
        }

        var chunk: u8[..4096] = [];
        let recvd = wing::tcp_recv(conn, chunk, 4096, 50);
        if recvd == -2 {
            continue;
        }
        if recvd <= 0 {
            break;
        }
        in_buf.append(chunk[..recvd]);
    }
}

fn handle_grpc_web_http1(conn: i64, req_raw: const u8[:], dispatcher: wing::GrpcServerDispatcher&) {
    var req = wing::new_request("GET", "");
    let ok_parse, consumed = wing::parse_http1_wire_request(req_raw, req);
    if !ok_parse {
        let err: const u8[:] = "HTTP/1.1 400 Bad Request\r\nConnection: close\r\n\r\n";
        wing::tcp_send(conn, err);
        return;
    }

    var res = wing::new_response();
    wing::dispatch_grpc_unary(dispatcher, req, 1000000, res, grpc_test_unary_handler);

    var out_wire: u8[>..] = [];
    wing::serialize_http1_response(res, "goose-grpc-web/1.0", out_wire);
    wing::tcp_send(conn, out_wire[..]);
}

fn main() {
    var dispatcher = wing::new_grpc_server_dispatcher();
    wing::register_unary(dispatcher, "helloworld.Greeter", "SayHello", 1);
    wing::register_unary(dispatcher, "echo.EchoService", "Echo", 2);
    wing::register_unary(dispatcher, "echo.EchoService", "Fail", 3);

    let port_env = wing::get_env_port(0);
    let listener = wing::tcp_listen("0.0.0.0", port_env, 128);
    if listener <= 0 {
        print("ERROR_FAILED_TO_LISTEN\n");
        return;
    }
    let port = wing::tcp_getsockname_port(listener);
    print("READY_PORT:", port, "\n");

    var is_running = true;
    while is_running {
        let conn = wing::tcp_accept(listener, 200);
        if conn <= 0 {
            continue;
        }

        var in_buf: u8[>..] = [];
        while true {
            var chunk: u8[..4096] = [];
            let recvd = wing::tcp_recv(conn, chunk, 4096, 500);
            if recvd == -2 {
                continue;
            }
            if recvd <= 0 {
                break;
            }
            in_buf.append(chunk[..recvd]);

            // 1. HTTP/2 Client Preface Check
            if wing::is_partial_h2_client_preface(in_buf[..]) {
                continue;
            }
            if wing::is_h2_client_preface(in_buf[..]) {
                handle_grpc_h2_session(conn, in_buf[..], dispatcher);
                break;
            }

            // 2. HTTP/1.1 gRPC-Web Check
            let hdr_end = core::index_of_slice(in_buf[..], "\r\n\r\n");
            if hdr_end >= 0 {
                if core::index_of_slice(in_buf[..], "GET /shutdown") >= 0 {
                    let resp: const u8[:] = "HTTP/1.1 200 OK\r\nContent-Length: 4\r\nConnection: close\r\n\r\nBYE\n";
                    wing::tcp_send(conn, resp);
                    is_running = false;
                    break;
                }

                handle_grpc_web_http1(conn, in_buf[..], dispatcher);
                break;
            }
        }

        wing::tcp_close(conn);
    }

    wing::tcp_close(listener);
}
