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
        let line = headers_block[cursor..(cursor + rel_end)];
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
        "\r\n\r\n",
    );
    wing::tcp_send(conn, handshake_resp[..]);

    var ws = wing::new_websocket_session(false);
    var ws_buf: u8[>..] = [];
    var frag_buf: u8[>..] = [];
    var reply: u8[>..] = [];
    var echo_wire: u8[>..] = [];
    while !ws.is_closed {
        var chunk: u8[..4096] = [];
        let recvd = wing::tcp_recv(conn, chunk, 4096, 500);
        if recvd == -2 {
            continue;
        }
        if recvd <= 0 {
            break;
        }
        ws_buf.append(chunk[..recvd]);

        var cursor: i64 = 0;
        while cursor + 2 <= ws_buf.len && !ws.is_closed {
            reply.clear();
            let consumed, handled, view = wing::consume_frame_view_into(
                ws,
                ws_buf[cursor..],
                frag_buf,
                16777216,
                reply,
            );
            if !handled {
                break;
            }
            cursor += consumed;

            if reply.len > 0 {
                wing::tcp_send(conn, reply[..]);
            }

            if view.is_valid && (view.opcode == wing::WS_OPCODE_TEXT || view.opcode == wing::WS_OPCODE_BINARY) {
                echo_wire.clear();
                if view.opcode == wing::WS_OPCODE_TEXT {
                    wing::send_text(ws, view.payload, echo_wire);
                } else {
                    wing::send_binary(ws, view.payload, echo_wire);
                }
                if echo_wire.len > 0 {
                    wing::tcp_send(conn, echo_wire[..]);
                }
            }

            if ws.is_closed {
                drain_and_close(conn);
                return;
            }
        }

        // Advance buffer past consumed frames
        if cursor > 0 {
            if cursor >= ws_buf.len {
                ws_buf.clear();
            } else {
                var remaining: u8[>..] = [];
                remaining.append(ws_buf[cursor..]);
                ws_buf.clear();
                ws_buf.append(remaining[..]);
            }
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
                        resp_body[..],
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
