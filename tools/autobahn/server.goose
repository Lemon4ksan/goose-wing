// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Dedicated WebSocket Echo Server for Autobahn Testsuite (RFC 6455 Compliance).
// RFC-conformant WebSocket implementation in pure Goose.
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
    wing::set_max_payload_length(ws, 16777216); // 16 MB for Autobahn Case 9.x large payload tests

    var ws_buf: u8[>..] = [];
    var idle_count = 0;
    while !ws.is_closed {
        var chunk: u8[..16384] = [];
        let recvd = wing::tcp_recv(conn, chunk, 16384, 500);
        if recvd == -2 {
            // Select timeout: connection is still healthy, peer is just waiting
            idle_count++;
            if idle_count > 60 { // 30 seconds idle timeout
                break;
            }
            continue;
        }
        if recvd <= 0 {
            // Peer closed connection (EOF) or error
            break;
        }
        idle_count = 0;
        ws_buf.append(chunk[..recvd]);

        while ws_buf.len >= 2 && !ws.is_closed {
            var view = wing::WsMessageView { .. };
            var reply: u8[>..] = [];
            let consumed, handled = wing::consume_frame_view(ws, ws_buf[..], view, reply);
            if !handled {
                break;
            }

            if reply.len > 0 {
                wing::tcp_send(conn, reply[..]);
            }

            if view.is_valid && (view.opcode == wing::WS_OPCODE_TEXT || view.opcode == wing::WS_OPCODE_BINARY) {
                var echo_wire: u8[>..] = [];
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

            // Advance buffer
            var remaining: u8[>..] = [];
            remaining.append(ws_buf[consumed..]);
            ws_buf.clear();
            ws_buf.append(remaining[..]);
        }
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
        let conn = wing::tcp_accept(listener, 200);
        if conn <= 0 {
            continue;
        }

        var in_buf: u8[>..] = [];
        while true {
            var chunk: u8[..4096] = [];
            let recvd = wing::tcp_recv(conn, chunk, 4096, 500);
            if recvd <= 0 {
                break;
            }
            in_buf.append(chunk[..recvd]);

            let hdr_end = core::index_of_slice(in_buf[..], "\r\n\r\n");
            if hdr_end >= 0 {
                let body_start = hdr_end + 4;
                let upgrade_val, has_upgrade = extract_header_val(in_buf[..body_start], "upgrade");
                if has_upgrade && core::eq_ascii_fold(upgrade_val, "websocket") {
                    let sec_key, has_key = extract_header_val(in_buf[..body_start], "sec-websocket-key");
                    if has_key {
                        handle_websocket_session(conn, sec_key);
                        break;
                    }
                }

                // Check for /shutdown
                if core::index_of_slice(in_buf[..body_start], "GET /shutdown") >= 0 {
                    let resp: const u8[:] = "HTTP/1.1 200 OK\r\nContent-Length: 4\r\nConnection: close\r\n\r\nBYE\n";
                    wing::tcp_send(conn, resp);
                    is_running = false;
                    break;
                }

                // Non-websocket request: 400 Bad Request
                let err_resp: const u8[:] = "HTTP/1.1 400 Bad Request\r\nContent-Length: 11\r\nConnection: close\r\n\r\nBAD_REQUEST";
                wing::tcp_send(conn, err_resp);
                break;
            }
        }

        wing::tcp_close(conn);
    }

    wing::tcp_close(listener);
}
