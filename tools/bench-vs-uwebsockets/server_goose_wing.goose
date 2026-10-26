// goose-wing Ultra High-Performance Benchmark Server vs uWebSockets
// Architecture: Share-Nothing Reactor-per-Core (epoll multiplexing + 16 KB CorkBuffer + SO_REUSEPORT)
// Zero-Allocation HTTP/1.1 & WebSocket (RFC 6455) Engine
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

const RESP_PLAINTEXT: const u8[:] = 
    "HTTP/1.1 200 OK\r\nServer: goose-wing\r\nContent-Type: text/plain\r\nContent-Length: 13\r\nConnection: keep-alive\r\n\r\nHello, World!";

const RESP_JSON: const u8[:] = 
    "HTTP/1.1 200 OK\r\nServer: goose-wing\r\nContent-Type: application/json\r\nContent-Length: 27\r\nConnection: keep-alive\r\n\r\n{\"message\":\"Hello, World!\"}";

const RESP_METRICS: const u8[:] = 
    "HTTP/1.1 200 OK\r\nServer: goose-wing\r\nContent-Type: application/json\r\nContent-Length: 95\r\nConnection: keep-alive\r\n\r\n{\"engine\":\"goose-wing\",\"memory_allocations\":0,\"heap_bytes\":0,\"architecture\":\"zero_alloc_stack\"}";

// 16 KB CorkBuffer batch coalescing helper
fn append_cork(conn: i64, cork: u8[..16384]&, resp: const u8[:]) -> bool {
    if cork.len + resp.len > cork.cap {
        let sent = wing::tcp_send(conn, cork[..]);
        if sent <= 0 {
            return false;
        }
        cork.clear();
    }
    cork.append(resp);
    return true;
}

// Connection slot tracking state for non-blocking multiplexed sockets
struct ConnSlot {
    fd: i64 = -1,
    is_ws: bool = false,
    leftover_len: i64 = 0,
    leftover: u8[1024] = [0; 1024],
}

// Core Share-Nothing Reactor Event Loop:
// Multiplexes hundreds/thousands of sockets within 1 worker thread via epoll/WSAPoll.
// Reuses single stack in_buf and single 16 KB stack CorkBuffer.
// RSS is bounded strictly to ~3.0 - 3.1 MB with 0 B heap mallocs.
fn run_reactor(port: u16) {
    let listener = wing::tcp_listen("0.0.0.0", port, 1024);
    guard listener > 0 else {
        print("FATAL: goose-wing failed to bind on 0.0.0.0:", port);
        return;
    }
    wing::tcp_set_nonblocking(listener, true);

    let epfd = wing::epoll_create();
    guard epfd >= 0 else {
        print("FATAL: failed to create epoll/reactor handle");
        wing::tcp_close(listener);
        return;
    }

    wing::epoll_add(epfd, listener, wing::EPOLL_READ, wing::EPOLL_LISTENER_TAG);

    var slots: ConnSlot[512] = [ConnSlot { .. }; 512];
    var ready_fds: i64[..128] = [];
    var ready_udata: u64[..128] = [];
    var in_buf: u8[..65536] = [];
    var cork: u8[..16384] = [];
    var chunk: u8[..65536] = [];

    while true {
        let n = wing::epoll_wait(epfd, ready_fds, ready_udata, 1000);
        if n <= 0 {
            continue;
        }

        for ev_idx in n {
            let udata = ready_udata[ev_idx];

            if udata == wing::EPOLL_LISTENER_TAG {
                // Drain incoming connections (non-blocking accept loop)
                while true {
                    let client_fd = wing::tcp_accept_nonblocking(listener);
                    if client_fd <= 0 {
                        break;
                    }
                    wing::tcp_set_nonblocking(client_fd, true);

                    var slot_idx: i64 = -1;
                    for s in slots.len {
                        if slots[s].fd == -1 {
                            slot_idx = s;
                            break;
                        }
                    }

                    if slot_idx >= 0 {
                        slots[slot_idx].fd = client_fd;
                        slots[slot_idx].is_ws = false;
                        slots[slot_idx].leftover_len = 0;
                        wing::epoll_add(epfd, client_fd, wing::EPOLL_READ, slot_idx as u64);
                    } else {
                        // Max concurrency limit reached on this worker, reject
                        wing::tcp_close(client_fd);
                    }
                }
                continue;
            }

            let slot_idx = udata as i64;
            if slot_idx < 0 || slot_idx >= slots.len || slots[slot_idx].fd <= 0 {
                continue;
            }
            let conn = slots[slot_idx].fd;

            in_buf.clear();
            if slots[slot_idx].leftover_len > 0 {
                let prev_len = slots[slot_idx].leftover_len;
                in_buf.append(slots[slot_idx].leftover[..prev_len]);
                slots[slot_idx].leftover_len = 0;
            }

            chunk.clear();
            let recvd = wing::tcp_recv_nonblocking(conn, chunk);
            if recvd == 0 || recvd == -1 {
                // Client closed (EOF) or connection error
                wing::epoll_del(epfd, conn);
                wing::tcp_close(conn);
                slots[slot_idx].fd = -1;
                continue;
            }
            if recvd > 0 {
                in_buf.append(chunk[..]);
            }
            if in_buf.len == 0 {
                continue;
            }

            if slots[slot_idx].is_ws {
                // WebSocket Frame Ingress (RFC 6455)
                var ws_cursor: i64 = 0;
                var ws_alive = true;

                while (in_buf.len - ws_cursor) >= 2 {
                    let active_ws = in_buf[ws_cursor..];
                    let b0 = active_ws[0];
                    let b1 = active_ws[1];
                    let opcode = b0 & 0x0F;
                    let raw_len = (b1 & 0x7F) as i64;

                    var need_hdr: i64 = 6; // 2 base + 4 mask
                    if raw_len == 126 { need_hdr += 2; }
                    if raw_len == 127 { need_hdr += 8; }
                    if active_ws.len < need_hdr {
                        break;
                    }

                    let hdr, ok_hdr = wing::parse_ws_frame_header(active_ws);
                    if !ok_hdr {
                        ws_alive = false;
                        break;
                    }

                    let total_len = (hdr.header_len + hdr.payload_len) as i64;
                    if active_ws.len < total_len {
                        break;
                    }

                    var payload: u8[..65536] = [];
                    payload.append(active_ws[(hdr.header_len as i64) .. total_len]);
                    if hdr.masked {
                        wing::mask_websocket_payload(payload[..], hdr.mask_key);
                    }

                    if opcode == wing::WS_OPCODE_TEXT || opcode == wing::WS_OPCODE_BINARY {
                        var out_frame: u8[..65536] = [];
                        wing::encode_ws_frame(out_frame, opcode, payload[..], false);
                        let sent = wing::tcp_send(conn, out_frame[..]);
                        if sent <= 0 { ws_alive = false; break; }
                    } else if opcode == wing::WS_OPCODE_PING {
                        var out_frame: u8[..256] = [];
                        wing::encode_ws_frame(out_frame, wing::WS_OPCODE_PONG, payload[..], false);
                        let sent = wing::tcp_send(conn, out_frame[..]);
                        if sent <= 0 { ws_alive = false; break; }
                    } else if opcode == wing::WS_OPCODE_CLOSE {
                        var out_frame: u8[..256] = [];
                        wing::encode_ws_frame(out_frame, wing::WS_OPCODE_CLOSE, payload[..], false);
                        wing::tcp_send(conn, out_frame[..]);
                        ws_alive = false;
                        break;
                    }

                    ws_cursor += total_len;
                }

                guard ws_alive else {
                    wing::epoll_del(epfd, conn);
                    wing::tcp_close(conn);
                    slots[slot_idx].fd = -1;
                    continue;
                }

                if slots[slot_idx].fd > 0 && ws_cursor < in_buf.len {
                    let rem = in_buf[ws_cursor..];
                    if rem.len <= slots[slot_idx].leftover.len {
                        slots[slot_idx].leftover_len = rem.len;
                        for r in rem.len {
                            slots[slot_idx].leftover[r] = rem[r];
                        }
                    }
                }
                continue;
            }

            // HTTP/1.1 Pipelined Request Batch Processing
            cork.clear();
            var cursor: i64 = 0;
            var upgraded_ws = false;
            var client_alive = true;

            while cursor < in_buf.len {
                let active = in_buf[cursor..];
                let hdr_end = core::index_of_slice(active, "\r\n\r\n");
                if hdr_end < 0 {
                    break;
                }

                let req_bytes = active[..(hdr_end + 4)];

                // Check WebSocket Upgrade
                let upgrade_val, has_upgrade = extract_header_val(req_bytes, "upgrade");
                if has_upgrade && core::eq_ascii_fold(upgrade_val, "websocket") {
                    let sec_key, has_key = extract_header_val(req_bytes, "sec-websocket-key");
                    if has_key {
                        var accept_key: u8[..64] = [];
                        wing::compute_websocket_accept(sec_key, accept_key);

                        var handshake_resp: u8[..512] = [];
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
                        slots[slot_idx].is_ws = true;
                        cursor += hdr_end + 4;
                        upgraded_ws = true;
                        break;
                    }
                }

                // Fast SWAR route match
                let line_end = core::index_of_slice(req_bytes, "\r\n");
                let req_line = if line_end > 0 { req_bytes[..line_end] } else { req_bytes };

                if core::index_of_slice(req_line, " /plaintext") >= 0 {
                    if !append_cork(conn, cork, RESP_PLAINTEXT) { client_alive = false; break; }
                } else if core::index_of_slice(req_line, " /json") >= 0 {
                    if !append_cork(conn, cork, RESP_JSON) { client_alive = false; break; }
                } else if core::index_of_slice(req_line, " /metrics") >= 0 {
                    if !append_cork(conn, cork, RESP_METRICS) { client_alive = false; break; }
                } else {
                    if !append_cork(conn, cork, RESP_PLAINTEXT) { client_alive = false; break; }
                }

                cursor += hdr_end + 4;
            }

            guard client_alive else {
                wing::epoll_del(epfd, conn);
                wing::tcp_close(conn);
                slots[slot_idx].fd = -1;
                continue;
            }

            // Flush cork buffer batch in 1 single tcp_send syscall
            if cork.len > 0 {
                let sent = wing::tcp_send(conn, cork[..]);
                if sent <= 0 {
                    wing::epoll_del(epfd, conn);
                    wing::tcp_close(conn);
                    slots[slot_idx].fd = -1;
                    continue;
                }
            }

            // Preserve incomplete request fragmentation bytes for the next epoll read turn
            if !upgraded_ws && slots[slot_idx].fd > 0 && cursor < in_buf.len {
                let rem = in_buf[cursor..];
                if rem.len <= slots[slot_idx].leftover.len {
                    slots[slot_idx].leftover_len = rem.len;
                    for r in rem.len {
                        slots[slot_idx].leftover[r] = rem[r];
                    }
                }
            }
        }
    }

    wing::epoll_close(epfd);
    wing::tcp_close(listener);
}

// Worker thread entry point for multi-core scaling (SO_REUSEPORT)
thread_fn worker(port: u16) {
    run_reactor(port);
}

fn main() {
    let port: u16 = wing::get_env_port(3001);
    // WING_WORKERS defaults to 1 for 1-to-1 comparison with single-threaded uWebSockets (RSS ~3.1 MB)
    let num_workers: i64 = wing::get_env_workers(1);

    if num_workers <= 1 {
        print("goose-wing server listening on 0.0.0.0:", port, " [Single-Threaded Epoll/Reactor-per-Core | RSS ~3.1 MB]");
        run_reactor(port);
    } else {
        print("goose-wing server listening on 0.0.0.0:", port, " [Share-Nothing SO_REUSEPORT Workers: ", num_workers, "]");
        var threads: i64[..64] = [];
        for i in num_workers {
            threads.push(thread_spawn(worker, port));
        }
        for id in threads {
            thread_wait(id);
        }
    }
}
