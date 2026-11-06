// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Dedicated WebSocket Echo Server for Autobahn Testsuite (RFC 6455 Compliance).
// RFC-conformant WebSocket implementation in pure Goose.
import std;
import core from "../..";
import wing from "../..";

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

fn handle_websocket_session(
    conn:   i64,
    server: const wing::HttpServer&,
    ws_res: wing::Response&,
    ws:     wing::WebSocketSession&,
) {
    var handshake_resp: u8[>..] = [];
    wing::serialize_http1_response(ws_res, server.server_name[..], handshake_resp);
    wing::tcp_send(conn, handshake_resp[..]);

    wing::set_max_payload_length(ws, 16777216); // 16 MB for Autobahn Case 9.x large payload tests

    var ws_buf:    u8[>..] = [];
    var frag_buf:  u8[>..] = [];
    var reply:     u8[>..] = [];
    var echo_wire: u8[>..] = [];
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

            if view.is_valid && (view.opcode == rfc::WS_OPCODE_TEXT || view.opcode == rfc::WS_OPCODE_BINARY) {
                echo_wire.clear();
                if view.opcode == rfc::WS_OPCODE_TEXT {
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

fn serve_autobahn_connection(
    conn:     i64,
    server:   wing::HttpServer&,
    in_buf:   u8[>..]&,
    out_wire: u8[>..]&,
) -> bool {
    in_buf.clear();
    var chunk: u8[..4096] = [];
    loop {
        chunk.clear();
        let recvd = wing::tcp_recv(conn, chunk, 4096, 500);
        if recvd <= 0 {
            break;
        }
        in_buf.append(chunk[..recvd]);

        guard core::fast_find_crlfcrlf(in_buf[..]) >= 0 else { continue; }

        var req = wing::new_request("GET", "");
        let ok_req, _ = wing::parse_http1_wire_request(in_buf[..], req);
        if ok_req {
            if wing::is_websocket_upgrade_request(req) {
                var ws_res = wing::Response { .. };
                var ws, ok_ws = wing::ws_upgrade_request(req, ws_res, "");
                if ok_ws {
                    handle_websocket_session(conn, server, ws_res, ws);
                    return true;
                }
            }
            if req.url[..] == "/shutdown" {
                out_wire.clear();
                let _ = wing::handle_connection_wire(server, "127.0.0.1", in_buf[..], 0, out_wire);
                wing::tcp_send(conn, out_wire[..]);
                return false;
            }
        }

        out_wire.clear();
        wing::serialize_bad_request_error(server.server_name[..], out_wire);
        wing::tcp_send(conn, out_wire[..]);
        break;
    }
    return true;
}

fn main() {
    let port_env = wing::get_env_port(0);
    let listener = wing::tcp_listen("0.0.0.0", port_env, 128);
    if listener <= 0 {
        print("ERROR_FAILED_TO_LISTEN\n");
        return;
    }
    let port = wing::tcp_getsockname_port(listener);

    var server = wing::new_http_server("0.0.0.0", port);
    let _ = server.server_name.try_set("goose-autobahn/1.0");
    let ws_behavior = wing::WsBehavior { .. };
    let _ = wing::add_ws_route(server, "/", ws_behavior);
    wing::add_static_get_route(server, "/shutdown", "text/plain", "BYE\n", 99);

    print("READY_PORT:", port, "\n");

    var in_buf:   u8[>..] = [];
    var out_wire: u8[>..] = [];
    var is_running = true;
    while is_running {
        let conn = wing::tcp_accept(listener, 200);
        if conn <= 0 {
            continue;
        }
        is_running = serve_autobahn_connection(conn, server, in_buf, out_wire);
        wing::tcp_close(conn);
    }

    wing::tcp_close(listener);
}
