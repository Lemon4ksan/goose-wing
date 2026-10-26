// Dedicated WebSocket Echo Server for Autobahn Testsuite (RFC 6455 Compliance).
// Zero-allocation, high-performance, strictly RFC-conformant implementation in pure Goose.
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

fn send_ws_close(conn: i64, status_code: u16, reason: const u8[:]) {
    var close_payload: u8[>..] = [];
    wing::encode_ws_close_payload(close_payload, status_code, reason);
    var frame_wire: u8[>..] = [];
    wing::encode_ws_frame(frame_wire, wing::WS_OPCODE_CLOSE, close_payload[..], false);
    wing::tcp_send(conn, frame_wire[..]);
    drain_and_close(conn);
}

fn send_ws_pong(conn: i64, payload: const u8[:]) {
    var frame_wire: u8[>..] = [];
    wing::encode_ws_frame(frame_wire, wing::WS_OPCODE_PONG, payload, false);
    wing::tcp_send(conn, frame_wire[..]);
}

fn send_ws_message(conn: i64, opcode: u8, payload: const u8[:]) {
    var frame_wire: u8[>..] = [];
    wing::encode_ws_frame(frame_wire, opcode, payload, false);
    wing::tcp_send(conn, frame_wire[..]);
}

fn is_valid_close_code(code: u16) -> bool {
    if code == 1000 || code == 1001 || code == 1002 || code == 1003 ||
       code == 1007 || code == 1008 || code == 1009 || code == 1010 || code == 1011 {
        return true;
    }
    if code >= 3000 && code <= 4999 {
        return true;
    }
    return false;
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
    var frag_active = false;
    var frag_opcode: u8 = 0;
    var frag_buf: u8[>..] = [];

    var idle_count = 0;
    while true {
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

        while ws_buf.len >= 2 {
            let b0 = ws_buf[0];
            let b1 = ws_buf[1];
            let opcode = b0 & 0x0F;
            let fin = (b0 & 0x80) != 0;
            let is_control = (opcode & 0x08) != 0;

            // RFC 6455 Section 5.1: Client to Server MUST be masked
            if (b1 & 0x80) == 0 {
                send_ws_close(conn, wing::WS_STATUS_PROTOCOL_ERROR, "unmasked client frame");
                return;
            }

            // RFC 6455 Section 5.2: Reserved bits MUST be 0
            if (b0 & 0x70) != 0 {
                send_ws_close(conn, wing::WS_STATUS_PROTOCOL_ERROR, "rsv bits set");
                return;
            }

            // RFC 6455 Section 5.2: Opcode validation
            if !wing::is_valid_ws_opcode(opcode) {
                send_ws_close(conn, wing::WS_STATUS_PROTOCOL_ERROR, "invalid opcode");
                return;
            }

            // RFC 6455 Section 5.4 & 5.5: Control frame fragmentation forbidden
            if is_control && !fin {
                send_ws_close(conn, wing::WS_STATUS_PROTOCOL_ERROR, "fragmented control frame");
                return;
            }

            // RFC 6455 Section 5.5: Control frame payload length <= 125
            if is_control && (b1 & 0x7F) > 125 {
                send_ws_close(conn, wing::WS_STATUS_PROTOCOL_ERROR, "control frame payload > 125");
                return;
            }

            // Variable length header offset
            let raw_len = (b1 & 0x7F) as i64;
            var need_hdr: i64 = 2 + 4; // 2 bytes base + 4 bytes mask
            if raw_len == 126 { need_hdr += 2; }
            if raw_len == 127 { need_hdr += 8; }
            if ws_buf.len < need_hdr {
                break;
            }

            let hdr, ok_hdr = wing::parse_ws_frame_header(ws_buf[..]);
            if !ok_hdr {
                send_ws_close(conn, wing::WS_STATUS_PROTOCOL_ERROR, "malformed frame header");
                return;
            }

            let total_len = hdr.header_len + (hdr.payload_len as i64);
            if ws_buf.len < total_len {
                // Incomplete frame, wait for more bytes from socket
                break;
            }

            var payload: u8[>..] = [];
            payload.append(ws_buf[(hdr.header_len as i64) .. total_len]);
            wing::mask_websocket_payload(payload[..], hdr.mask_key);

            // Handle Control Frames (can be interleaved)
            if is_control {
                if hdr.opcode == wing::WS_OPCODE_PING {
                    send_ws_pong(conn, payload[..]);
                } else if hdr.opcode == wing::WS_OPCODE_PONG {
                    // Unsolicited or heartbeat pong: ignored
                } else if hdr.opcode == wing::WS_OPCODE_CLOSE {
                    if payload.len == 0 {
                        // Empty close: valid (1005 NO_STATUS)
                        send_ws_close(conn, wing::WS_STATUS_NORMAL, "");
                        return;
                    } else if payload.len == 1 {
                        // Protocol error: status code must be 2 bytes
                        send_ws_close(conn, wing::WS_STATUS_PROTOCOL_ERROR, "close code must be 2 bytes");
                        return;
                    } else {
                        let code = ((payload[0] as u16) << 8) | payload[1];
                        if !is_valid_close_code(code) {
                            send_ws_close(conn, wing::WS_STATUS_PROTOCOL_ERROR, "invalid close code");
                            return;
                        }
                        if payload.len > 2 {
                            let reason = payload[2..];
                            if !core::validate_utf8(reason) {
                                send_ws_close(conn, wing::WS_STATUS_INVALID_PAYLOAD, "invalid utf-8 in close reason");
                                return;
                            }
                        }
                        send_ws_close(conn, code, "");
                        return;
                    }
                }
            } else {
                // Handle Data Frames (TEXT, BINARY, CONTINUATION)
                if hdr.opcode == wing::WS_OPCODE_TEXT || hdr.opcode == wing::WS_OPCODE_BINARY {
                    if frag_active {
                        send_ws_close(conn, wing::WS_STATUS_PROTOCOL_ERROR, "interleaved new data frame in fragment");
                        return;
                    }

                    if hdr.fin {
                        // Unfragmented message
                        if hdr.opcode == wing::WS_OPCODE_TEXT {
                            if !core::validate_utf8(payload[..]) {
                                send_ws_close(conn, wing::WS_STATUS_INVALID_PAYLOAD, "invalid utf-8 text payload");
                                return;
                            }
                        }
                        send_ws_message(conn, hdr.opcode, payload[..]);
                    } else {
                        // Start of fragmented message
                        frag_active = true;
                        frag_opcode = hdr.opcode;
                        frag_buf.clear();
                        frag_buf.append(payload[..]);
                    }
                } else if hdr.opcode == wing::WS_OPCODE_CONTINUATION {
                    if !frag_active {
                        send_ws_close(conn, wing::WS_STATUS_PROTOCOL_ERROR, "continuation without starting fragment");
                        return;
                    }
                    frag_buf.append(payload[..]);

                    if hdr.fin {
                        // End of fragmented message
                        if frag_opcode == wing::WS_OPCODE_TEXT {
                            if !core::validate_utf8(frag_buf[..]) {
                                send_ws_close(conn, wing::WS_STATUS_INVALID_PAYLOAD, "invalid utf-8 assembled payload");
                                return;
                            }
                        }
                        send_ws_message(conn, frag_opcode, frag_buf[..]);
                        frag_active = false;
                        frag_buf.clear();
                    }
                }
            }

            // Advance buffer
            var remaining: u8[>..] = [];
            remaining.append(ws_buf[total_len..]);
            ws_buf.clear();
            ws_buf.append(remaining[..]);
        }
    }
}

fn main() {
    let listener = wing::tcp_listen("127.0.0.1", 0, 128);
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
