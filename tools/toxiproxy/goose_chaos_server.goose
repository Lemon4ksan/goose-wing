// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Standalone Live Goose-Wing Server for Toxiproxy Chaos & Security Attacks Testing.
// Handles HTTP/1.1, WebSocket (RFC 6455), and HTTP/2 (RFC 9113) natively in Goose!
import std;
import core from "../..";
import wing from "../..";

fn extract_header_val(headers_block: const u8[:], target_header: const u8[:]) -> const u8[:], bool {
    var cursor: i64 = 0;
    while cursor < headers_block.len {
        let rel_end = core::index_of_slice(headers_block[cursor..], "\r\n");
        if rel_end < 0 { break; }
        let line = headers_block[cursor .. (cursor + rel_end)];
        let colon = core::index_of_byte(line, ':');
        if colon > 0 {
            let hname = line[..colon];
            if core::eq_ascii_fold(hname, target_header) {
                let hval = core::trim_lws(line[(colon + 1)..]);
                return hval, true;
            }
        }
        cursor += rel_end + 2;
    }
    return "", false;
}

fn extract_content_length(headers_block: const u8[:]) -> i64, bool {
    let val, found = extract_header_val(headers_block, "content-length");
    if found {
        let cl, ok = core::parse_i64_dec(val);
        if ok && cl >= 0 {
            return cl, true;
        }
    }
    return 0, false;
}

fn drain_and_close(conn: i64) {
    var dummy: u8[..4096] = [];
    var loops = 0;
    while loops < 10 {
        let recvd = wing::tcp_recv(conn, dummy, 4096, 20);
        if recvd <= 0 {
            break;
        }
        loops++;
    }
    wing::tcp_close(conn);
}

fn send_close(conn: i64, status_code: u16, reason: const u8[:]) {
    var close_payload: u8[>..] = [];
    wing::encode_close_payload(close_payload, status_code, reason);
    var frame_wire: u8[>..] = [];
    wing::encode_ws_frame(frame_wire, wing::WS_OPCODE_CLOSE, close_payload[..], false);
    wing::tcp_send(conn, frame_wire[..]);
    drain_and_close(conn);
}

fn handle_websocket_session(conn: i64, client_key: const u8[:]) {
    var accept_key: u8[>..] = [];
    wing::compute_websocket_accept(client_key, accept_key);

    var handshake_resp: u8[>..] = [];
    format(
        handshake_resp,
        "HTTP/1.1 101 Switching Protocols\r\n",
        "Upgrade: websocket\r\n",
        "Connection: Upgrade\r\n",
        "Sec-WebSocket-Accept: ",
        accept_key[..],
        "\r\n\r\n"
    );
    wing::tcp_send(conn, handshake_resp[..]);

    var ws_buf: u8[>..] = [];
    var frag_opcode: u8 = 0;
    var frag_buf: u8[>..] = [];
    while true {
        var chunk: u8[..4096] = [];
        let recvd = wing::tcp_recv(conn, chunk, 4096, 500);
        if recvd == -2 {
            continue;
        }
        if recvd <= 0 {
            break;
        }
        ws_buf.append(chunk[..recvd]);

        while ws_buf.len >= 2 {
            let b0 = ws_buf[0];
            let b1 = ws_buf[1];
            let opcode = b0 & 0x0F;
            let fin = (b0 & 0x80) != 0;
            let is_control = opcode >= 8;

            // RFC 6455 Section 5.1: Client to Server MUST be masked
            if (b1 & 0x80) == 0 {
                send_close(conn, wing::WS_STATUS_PROTOCOL_ERROR, "unmasked client frame");
                return;
            }

            // RFC 6455 Section 5.4 & 5.5: Control frame fragmentation
            if is_control && !fin {
                send_close(conn, wing::WS_STATUS_PROTOCOL_ERROR, "fragmented control frame");
                return;
            }

            // RFC 6455 Section 5.5: Control frame payload length <= 125
            if is_control && (b1 & 0x7F) > 125 {
                send_close(conn, wing::WS_STATUS_PROTOCOL_ERROR, "control frame payload > 125");
                return;
            }

            // RFC 6455 Section 5.2: Reserved bits must be 0
            if (b0 & 0x70) != 0 {
                send_close(conn, wing::WS_STATUS_PROTOCOL_ERROR, "rsv bits set");
                return;
            }

            // Wait until the full variable-length header (len ext + mask key) has arrived
            let raw_len = (b1 & 0x7F) as i64;
            var need_hdr: i64 = 2 + 4;
            if raw_len == 126 { need_hdr += 2; }
            if raw_len == 127 { need_hdr += 8; }
            if ws_buf.len < need_hdr {
                break;
            }

            let hdr, ok_hdr = wing::parse_ws_frame_header(ws_buf[..]);
            if !ok_hdr {
                send_close(conn, wing::WS_STATUS_PROTOCOL_ERROR, "malformed frame");
                return;
            }

            // Payload size limit defense (> 64KB)
            if hdr.payload_len > 65536 {
                send_close(conn, wing::WS_STATUS_MESSAGE_TOO_BIG, "payload > 64KB");
                return;
            }

            let total_len = hdr.header_len + (hdr.payload_len as i64);
            if ws_buf.len < total_len {
                // Wait for remainder of payload
                break;
            }

            var payload: u8[>..] = [];
            payload.append(ws_buf[(hdr.header_len as i64) .. total_len]);
            wing::mask_websocket_payload(payload[..], hdr.mask_key);

            if is_control {
                // RFC 6455 Section 5.4: Control frames can be interleaved at any point
                if hdr.opcode == wing::WS_OPCODE_PING {
                    var out_frame: u8[>..] = [];
                    wing::encode_ws_frame(out_frame, wing::WS_OPCODE_PONG, payload[..], false);
                    wing::tcp_send(conn, out_frame[..]);
                } else if hdr.opcode == wing::WS_OPCODE_CLOSE {
                    let code, reason, ok_close = wing::parse_close_payload(payload[..]);
                    if !ok_close {
                        send_close(conn, wing::WS_STATUS_PROTOCOL_ERROR, "invalid close frame");
                        return;
                    }
                    var out_frame: u8[>..] = [];
                    wing::encode_ws_frame(out_frame, wing::WS_OPCODE_CLOSE, payload[..], false);
                    wing::tcp_send(conn, out_frame[..]);
                    drain_and_close(conn);
                    return;
                }
            } else {
                if hdr.opcode == wing::WS_OPCODE_CONTINUATION {
                    if frag_opcode == 0 {
                        // RFC 6455 Section 5.4: Unexpected continuation frame
                        send_close(conn, wing::WS_STATUS_PROTOCOL_ERROR, "unexpected continuation");
                        return;
                    }
                    frag_buf.append(payload[..]);
                    if hdr.fin {
                        if frag_opcode == wing::WS_OPCODE_TEXT {
                            if !core::validate_utf8(frag_buf[..]) {
                                send_close(conn, wing::WS_STATUS_INVALID_PAYLOAD, "invalid utf8");
                                return;
                            }
                            var out_frame: u8[>..] = [];
                            wing::encode_ws_frame(out_frame, wing::WS_OPCODE_TEXT, frag_buf[..], false);
                            wing::tcp_send(conn, out_frame[..]);
                        } else if frag_opcode == wing::WS_OPCODE_BINARY {
                            var out_frame: u8[>..] = [];
                            wing::encode_ws_frame(out_frame, wing::WS_OPCODE_BINARY, frag_buf[..], false);
                            wing::tcp_send(conn, out_frame[..]);
                        }
                        frag_opcode = 0;
                        frag_buf.clear();
                    }
                } else if hdr.opcode == wing::WS_OPCODE_TEXT || hdr.opcode == wing::WS_OPCODE_BINARY {
                    if frag_opcode != 0 {
                        // RFC 6455 Section 5.4: Cannot start new data frame while previous is unfinished
                        send_close(conn, wing::WS_STATUS_PROTOCOL_ERROR, "interleaved data frames");
                        return;
                    }
                    if !hdr.fin {
                        frag_opcode = hdr.opcode;
                        frag_buf.clear();
                        frag_buf.append(payload[..]);
                    } else {
                        if hdr.opcode == wing::WS_OPCODE_TEXT {
                            if !core::validate_utf8(payload[..]) {
                                send_close(conn, wing::WS_STATUS_INVALID_PAYLOAD, "invalid utf8");
                                return;
                            }
                            var out_frame: u8[>..] = [];
                            wing::encode_ws_frame(out_frame, wing::WS_OPCODE_TEXT, payload[..], false);
                            wing::tcp_send(conn, out_frame[..]);
                        } else {
                            var out_frame: u8[>..] = [];
                            wing::encode_ws_frame(out_frame, wing::WS_OPCODE_BINARY, payload[..], false);
                            wing::tcp_send(conn, out_frame[..]);
                        }
                    }
                } else {
                    send_close(conn, wing::WS_STATUS_PROTOCOL_ERROR, "unknown data opcode");
                    return;
                }
            }

            // Remove processed frame from buffer
            var remaining: u8[>..] = [];
            remaining.append(ws_buf[total_len..]);
            ws_buf.clear();
            ws_buf.append(remaining[..]);
        }
    }
}

fn handle_h2_session(conn: i64, initial_buf: const u8[:]) {
    var sess = wing::new_h2_server_session("goose-chaos/1.0", 1000);
    var pipeline = wing::new_default_server_pipeline_config("127.0.0.1");
    var timer = internal::new_connection_timer(30000000000, 1000000000);
    wing::add_route(pipeline.router, "GET", "/ping", 101);
    wing::add_route(pipeline.router, "POST", "/echo", 202);

    var h2_in: u8[..65536] = [];
    h2_in.append(initial_buf);

    var now_ms: u64 = 1000;
    while true {
        var out_wire: u8[..65536] = [];
        let consumed, ok = wing::handle_h2_server_ingress(sess, pipeline, timer, "127.0.0.1", h2_in[..], now_ms, out_wire);

        if out_wire.len > 0 {
            wing::tcp_send(conn, out_wire[..]);
        }

        if !ok {
            // Anti-DoS triggered (EnhanceYourCalm / ProtocolError / Goaway)
            break;
        }

        if consumed > 0 {
            var rem: u8[..65536] = [];
            rem.append(h2_in[consumed..]);
            h2_in.clear();
            h2_in.append(rem[..]);
        }

        var chunk: u8[..4096] = [];
        let recvd = wing::tcp_recv(conn, chunk, 4096, 2000);
        if recvd <= 0 {
            break;
        }
        h2_in.append(chunk[..]);
        now_ms += 10;
    }
}

fn main() {
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
        let conn = wing::tcp_accept(listener, 500);
        if conn <= 0 {
            continue;
        }

        var in_buf: u8[>..] = [];

        var idle_count = 0;
        while in_buf.len < 65000 {
            var chunk: u8[..4096] = [];
            let recvd = wing::tcp_recv(conn, chunk, 4096, 500);
            if recvd == -2 {
                idle_count++;
                if idle_count >= 6 { // 3 seconds Slowloris timeout
                    break;
                }
                continue;
            }
            if recvd <= 0 {
                break;
            }
            idle_count = 0;
            in_buf.append(chunk[..recvd]);

            // 1. Check for HTTP/2 Connection Preface (wait if a sliced prefix arrived)
            if wing::is_partial_h2_client_preface(in_buf[..]) {
                continue;
            }
            if wing::is_h2_client_preface(in_buf[..]) {
                handle_h2_session(conn, in_buf[..]);
                break;
            }

            // Reject invalid HTTP/2 preface immediately
            if in_buf.len >= 4 && in_buf[..4] == "PRI " {
                break;
            }

            // 2. Check for HTTP/1.1 or WebSocket
            let hdr_end = core::index_of_slice(in_buf[..], "\r\n\r\n");
            if hdr_end >= 0 {
                let body_start = hdr_end + 4;

                // Check for WebSocket Upgrade
                let upgrade_val, has_upgrade = extract_header_val(in_buf[..body_start], "upgrade");
                if has_upgrade && core::eq_ascii_fold(upgrade_val, "websocket") {
                    let sec_key, has_key = extract_header_val(in_buf[..body_start], "sec-websocket-key");
                    if has_key {
                        handle_websocket_session(conn, sec_key);
                        break;
                    }
                }

                let has_te_hdr = core::index_of_slice(in_buf[..body_start], "transfer-encoding") >= 0 || core::index_of_slice(in_buf[..body_start], "Transfer-Encoding") >= 0;
                let cl, has_cl = extract_content_length(in_buf[..body_start]);
                if has_te_hdr && has_cl {
                    // RFC 9112 Section 6.1: Reject TE.CL / CL.TE conflict immediately with 400 Bad Request
                    let err_resp: const u8[:] = "HTTP/1.1 400 Bad Request\r\nContent-Length: 11\r\nConnection: close\r\n\r\nBAD_REQUEST";
                    wing::tcp_send(conn, err_resp);
                    break;
                }
                if has_cl && in_buf.len < body_start + cl {
                    continue;
                }

                let is_chunked = core::index_of_slice(in_buf[..body_start], "chunked") >= 0;
                if is_chunked && core::index_of_slice(in_buf[body_start..], "0\r\n\r\n") < 0 {
                    continue;
                }

                var req = wing::Request {};
                let ok_req, consumed = wing::parse_http1_wire_request(in_buf[..], req);
                if ok_req {
                    if req.url[..] == "/shutdown" {
                        let resp: const u8[:] = "HTTP/1.1 200 OK\r\nContent-Length: 4\r\nConnection: close\r\n\r\nBYE\n";
                        wing::tcp_send(conn, resp);
                        is_running = false;
                        break;
                    }

                    var resp_body: u8[..16384] = [];
                    if req.url[..] == "/echo" {
                        resp_body.append("ECHO:");
                        resp_body.append(req.body[..]);
                    } else {
                        resp_body.append("OK");
                    }

                    var resp_wire: u8[..32768] = [];
                    format(
                        resp_wire,
                        "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: ",
                        resp_body.len,
                        "\r\nConnection: close\r\n\r\n",
                        resp_body[..]
                    );
                    wing::tcp_send(conn, resp_wire[..]);
                    break;
                } else {
                    let err_resp: const u8[:] = "HTTP/1.1 400 Bad Request\r\nContent-Length: 11\r\nConnection: close\r\n\r\nBAD_REQUEST";
                    wing::tcp_send(conn, err_resp);
                    break;
                }
            }
        }

        wing::tcp_close(conn);
    }

    wing::tcp_close(listener);
}
