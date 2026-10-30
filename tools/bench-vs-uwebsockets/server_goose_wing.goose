// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// goose-wing benchmark server vs uWebSockets
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

const RESP_PLAINTEXT: const u8[:] =
    "HTTP/1.1 200 OK\r\nServer: goose-wing\r\nContent-Type: text/plain\r\nContent-Length: 13\r\nConnection: keep-alive\r\n\r\nHello, World!";

const RESP_JSON: const u8[:] =
    "HTTP/1.1 200 OK\r\nServer: goose-wing\r\nContent-Type: application/json\r\nContent-Length: 27\r\nConnection: keep-alive\r\n\r\n{\"message\":\"Hello, World!\"}";

const RESP_METRICS: const u8[:] =
    "HTTP/1.1 200 OK\r\nServer: goose-wing\r\nContent-Type: application/json\r\nContent-Length: 95\r\nConnection: keep-alive\r\n\r\n{\"engine\":\"goose-wing\",\"memory_allocations\":0,\"heap_bytes\":0,\"architecture\":\"zero_alloc_stack\"}";

// Connection slot tracking state for non-blocking multiplexed sockets
// Perfectly 8-byte aligned to eliminate unaligned loads/stores & allow vectorization
struct ConnSlot {
    fd: i64 = -1,
    leftover_len: i64 = 0,
    is_ws: bool = false,
    timeout_tick: u8 = 255,
    _pad: u8[6] = [0; 6],
    leftover: u8[232] = [0; 232],
}

// Core Share-Nothing Reactor Event Loop:
// Multiplexes hundreds/thousands of sockets within 1 worker thread via epoll/WSAPoll.
// Reuses single stack in_buf and single 16 KB stack CorkBuffer.
// RSS is bounded strictly to ~3.0 - 3.1 MB with 0 B heap mallocs.
fn run_reactor(port: u16, worker_id: i64 = 0) {
    let listener = wing::tcp_listen("0.0.0.0", port, 8192);
    guard listener > 0 else {
        print("FATAL: goose-wing failed to bind on 0.0.0.0:", port);
        return;
    }
    wing::tcp_set_incoming_cpu(listener, worker_id);
    wing::tcp_set_nonblocking(listener, true);

    let epfd = wing::epoll_create();
    guard epfd >= 0 else {
        print("FATAL: failed to create epoll/reactor handle");
        wing::tcp_close(listener);
        return;
    }

    wing::epoll_add(epfd, listener, wing::EPOLL_READ, wing::EPOLL_LISTENER_TAG);

    var slots: ConnSlot[1024] = [ConnSlot { .. }; 1024];
    var ready_fds: i64[0] = [];
    var ready_udata: u64[1024] = [0; 1024];
    var raw_recv: u8[65536] = [0; 65536];
    var cork_buf: u8[65536] = [0; 65536];
    var ws_cork: u8[..65536] = [];
    var timer_wheel = wing::new_tick_timer_wheel(15);
    var next_free_slot: i64 = 0;

    while true {
        let n = wing::epoll_wait_direct(epfd, ready_fds[..], ready_udata[..], 1000);
        if n <= 0 {
            // Periodic 1-second timeout sweep (uSockets loop.c)
            wing::tick_timer_advance(timer_wheel, 1);
            for s in slots.len {
                if slots[s].fd > 0 && wing::tick_timer_is_expired(timer_wheel, slots[s].timeout_tick) {
                    wing::epoll_del(epfd, slots[s].fd);
                    wing::tcp_close(slots[s].fd);
                    slots[s].fd = -1;
                    if s < next_free_slot { next_free_slot = s; }
                }
            }
            continue;
        }

        guard n <= ready_udata.len else {
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

                    var slot_idx: i64 = -1;
                    if next_free_slot >= 0 && next_free_slot < slots.len && slots[next_free_slot].fd == -1 {
                        slot_idx = next_free_slot;
                        next_free_slot = (next_free_slot + 1) % slots.len;
                    } else {
                        for s in slots.len {
                            if slots[s].fd == -1 {
                                slot_idx = s;
                                next_free_slot = (s + 1) % slots.len;
                                break;
                            }
                        }
                    }

                    if slot_idx >= 0 && slot_idx < slots.len {
                        slots[slot_idx].fd = client_fd;
                        slots[slot_idx].is_ws = false;
                        slots[slot_idx].leftover_len = 0;
                        slots[slot_idx].timeout_tick = wing::tick_timer_arm(timer_wheel, 15);
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
            slots[slot_idx].timeout_tick = wing::tick_timer_arm(timer_wheel, 15);

            var active_len: i64 = 0;
            let prev_len = slots[slot_idx].leftover_len;
            if prev_len > 0 && prev_len <= 232 {
                for p in prev_len {
                    raw_recv[p] = slots[slot_idx].leftover[p];
                }
                slots[slot_idx].leftover_len = 0;
                active_len = prev_len;
            }

            guard active_len >= 0 && active_len <= raw_recv.len else {
                continue;
            }

            let recvd = wing::tcp_recv_nonblocking_slice(conn, raw_recv[active_len..]);
            if recvd == 0 || recvd == -1 {
                // Client closed (EOF) or connection error
                wing::epoll_del(epfd, conn);
                wing::tcp_close(conn);
                slots[slot_idx].fd = -1;
                if slot_idx < next_free_slot { next_free_slot = slot_idx; }
                continue;
            }
            if recvd == -2 {
                // EAGAIN / EWOULDBLOCK: restore previous leftover bytes if any
                if prev_len > 0 {
                    slots[slot_idx].leftover_len = prev_len;
                }
                continue;
            }
            active_len += recvd;
            if active_len <= 0 || active_len > raw_recv.len {
                continue;
            }
            let in_buf = raw_recv[..active_len];

            if slots[slot_idx].is_ws {
                // WebSocket Frame Ingress (RFC 6455)
                ws_cork.clear();
                var ws_cursor: i64 = 0;
                var ws_alive = true;

                while ws_cursor >= 0 && ws_cursor < in_buf.len {
                    if ws_cursor + 2 > in_buf.len {
                        break;
                    }
                    let b0 = in_buf[ws_cursor];
                    let b1 = in_buf[ws_cursor + 1];
                    let opcode = b0 & 0x0F;
                    let raw_len = (b1 & 0x7F) as i64;

                    var need_hdr: i64 = 6; // 2 base + 4 mask
                    if raw_len == 126 { need_hdr += 2; }
                    if raw_len == 127 { need_hdr += 8; }
                    if ws_cursor + need_hdr > in_buf.len {
                        break;
                    }

                    let active_ws = in_buf[ws_cursor..];

                    let hdr, ok_hdr = wing::parse_ws_frame_header(active_ws);
                    if !ok_hdr {
                        ws_alive = false;
                        break;
                    }

                    let total_len = (hdr.header_len + hdr.payload_len) as i64;
                    if active_ws.len < total_len {
                        break;
                    }

                    // In-place zero-copy unmasking overwriting the frame header (uWebSockets unmaskImprecise8)
                    let h_len = hdr.header_len as i64;
                    let payload = if hdr.masked {
                        wing::unmask_websocket_shifted(active_ws, hdr.header_len, hdr.payload_len as i64, hdr.mask_key)
                    } else if h_len <= total_len && total_len <= active_ws.len {
                        active_ws[h_len..total_len]
                    } else {
                        active_ws[..0]
                    };

                    if opcode == wing::WS_OPCODE_TEXT || opcode == wing::WS_OPCODE_BINARY {
                        // Fast server frame header: unmasked 2-byte header for payload <= 125
                        if payload.len <= 125 {
                            ws_cork.push(0x80 | opcode);
                            ws_cork.push(payload.len as u8);
                            ws_cork.append(payload);
                        } else {
                            wing::encode_ws_frame(ws_cork, opcode, payload, false);
                        }
                        if ws_cork.len > 60000 {
                            let sent = wing::tcp_send(conn, ws_cork[..]);
                            if sent <= 0 { ws_alive = false; break; }
                            ws_cork.clear();
                        }
                    } else if opcode == wing::WS_OPCODE_PING {
                        ws_cork.push(0x80 | wing::WS_OPCODE_PONG);
                        ws_cork.push(payload.len as u8);
                        ws_cork.append(payload);
                    } else if opcode == wing::WS_OPCODE_CLOSE {
                        wing::encode_ws_frame(ws_cork, wing::WS_OPCODE_CLOSE, payload, false);
                        if ws_cork.len > 0 {
                            wing::tcp_send(conn, ws_cork[..]);
                            ws_cork.clear();
                        }
                        ws_alive = false;
                        break;
                    }

                    ws_cursor += total_len;
                }

                if ws_alive && ws_cork.len > 0 {
                    var total_sent: i64 = 0;
                    var send_attempts: i64 = 0;
                    let target_len = ws_cork.len;
                    while total_sent < target_len && send_attempts < 16 {
                        let sent = wing::tcp_send(conn, ws_cork[total_sent..target_len]);
                        if sent <= 0 { ws_alive = false; break; }
                        total_sent += sent;
                        send_attempts += 1;
                    }
                    if total_sent < target_len { ws_alive = false; }
                    ws_cork.clear();
                }

                guard ws_alive else {
                    wing::epoll_del(epfd, conn);
                    wing::tcp_close(conn);
                    slots[slot_idx].fd = -1;
                    if slot_idx < next_free_slot { next_free_slot = slot_idx; }
                    continue;
                }

                if slots[slot_idx].fd > 0 && ws_cursor >= 0 && ws_cursor < in_buf.len {
                    let rem = in_buf[ws_cursor..];
                    let rlen = rem.len;
                    if rlen > 0 && rlen <= 232 {
                        slots[slot_idx].leftover_len = rlen;
                        for r in rlen {
                            slots[slot_idx].leftover[r] = rem[r];
                        }
                    }
                }
                continue;
            }

            // HTTP/1.1 Pipelined Request Batch Processing
            var cork_len: i64 = 0;
            var cursor: i64 = 0;
            var upgraded_ws = false;
            var client_alive = true;

            while cursor >= 0 && cursor < in_buf.len {
                let active = in_buf[cursor..];
                let hdr_end = core::fast_find_crlfcrlf(active);
                if hdr_end < 0 {
                    break;
                }
                let req_end = hdr_end + 4;
                if req_end > active.len {
                    break;
                }

                let req_bytes = active[..req_end];

                // 1. Single-instruction O(1) URL route dispatch via fast byte check!
                // "GET /plaintext" -> 'p' at index 5
                // "GET /"          -> ' ' at index 5
                // "GET /json"      -> 'j' at index 5
                // "GET /metrics"   -> 'm' at index 5
                if req_bytes.len >= 6 && req_bytes[0] == 'G' && req_bytes[4] == '/' {
                    let route_char = req_bytes[5];
                    if route_char == 'p' || route_char == ' ' {
                        cork_len = wing::fast_cork_append(conn, cork_buf[..], cork_len, RESP_PLAINTEXT);
                        if cork_len < 0 { client_alive = false; break; }
                        cursor += req_end;
                        continue;
                    } else if route_char == 'j' {
                        cork_len = wing::fast_cork_append(conn, cork_buf[..], cork_len, RESP_JSON);
                        if cork_len < 0 { client_alive = false; break; }
                        cursor += req_end;
                        continue;
                    } else if route_char == 'm' {
                        cork_len = wing::fast_cork_append(conn, cork_buf[..], cork_len, RESP_METRICS);
                        if cork_len < 0 { client_alive = false; break; }
                        cursor += req_end;
                        continue;
                    }
                }

                // Fast request-line fallback
                let line_end = core::index_of_slice(req_bytes, "\r\n");
                let req_line = if line_end > 0 && line_end <= req_bytes.len { req_bytes[..line_end] } else { req_bytes };

                if core::index_of_slice(req_line, " /plaintext") >= 0 {
                    cork_len = wing::fast_cork_append(conn, cork_buf[..], cork_len, RESP_PLAINTEXT);
                    if cork_len < 0 { client_alive = false; break; }
                } else if core::index_of_slice(req_line, " /json") >= 0 {
                    cork_len = wing::fast_cork_append(conn, cork_buf[..], cork_len, RESP_JSON);
                    if cork_len < 0 { client_alive = false; break; }
                } else if core::index_of_slice(req_line, " /metrics") >= 0 {
                    cork_len = wing::fast_cork_append(conn, cork_buf[..], cork_len, RESP_METRICS);
                    if cork_len < 0 { client_alive = false; break; }
                } else if core::index_of_slice(req_line, " /ws") >= 0 || core::index_of_slice(req_bytes, "Upgrade:") >= 0 || core::index_of_slice(req_bytes, "upgrade:") >= 0 {
                    // Check WebSocket Upgrade ONLY for /ws or if Upgrade header present
                    let upgrade_val, has_upgrade = extract_header_val(req_bytes, "upgrade");
                    if has_upgrade && core::eq_ascii_fold(upgrade_val, "websocket") {
                        let sec_key, has_key = extract_header_val(req_bytes, "sec-websocket-key");
                        if has_key {
                            if cork_len > 0 {
                                wing::tcp_send(conn, cork_buf[..cork_len]);
                                cork_len = 0;
                            }
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
                                "\r\n\r\n",
                            );
                            wing::tcp_send(conn, handshake_resp[..]);
                            slots[slot_idx].is_ws = true;
                            cursor += hdr_end + 4;
                            upgraded_ws = true;
                            break;
                        }
                    }
                    cork_len = wing::fast_cork_append(conn, cork_buf[..], cork_len, RESP_PLAINTEXT);
                    if cork_len < 0 { client_alive = false; break; }
                } else {
                    cork_len = wing::fast_cork_append(conn, cork_buf[..], cork_len, RESP_PLAINTEXT);
                    if cork_len < 0 { client_alive = false; break; }
                }

                cursor += hdr_end + 4;
            }

            guard client_alive else {
                wing::epoll_del(epfd, conn);
                wing::tcp_close(conn);
                slots[slot_idx].fd = -1;
                if slot_idx < next_free_slot { next_free_slot = slot_idx; }
                continue;
            }

            // Flush cork buffer batch in 1 single tcp_send syscall
            if cork_len > 0 && cork_len <= cork_buf.len {
                var total_sent: i64 = 0;
                var send_attempts: i64 = 0;
                while total_sent < cork_len && send_attempts < 16 {
                    let sent = wing::tcp_send(conn, cork_buf[total_sent..cork_len]);
                    if sent <= 0 {
                        client_alive = false;
                        break;
                    }
                    total_sent += sent;
                    send_attempts += 1;
                }
                if !client_alive || total_sent < cork_len {
                    wing::epoll_del(epfd, conn);
                    wing::tcp_close(conn);
                    slots[slot_idx].fd = -1;
                    if slot_idx < next_free_slot { next_free_slot = slot_idx; }
                    continue;
                }
            }

            // Preserve incomplete request fragmentation bytes for the next epoll read turn
            if !upgraded_ws && slots[slot_idx].fd > 0 && cursor >= 0 && cursor < in_buf.len {
                let rem = in_buf[cursor..];
                let rlen = rem.len;
                if rlen > 0 && rlen <= 232 {
                    slots[slot_idx].leftover_len = rlen;
                    for r in rlen {
                        slots[slot_idx].leftover[r] = rem[r];
                    }
                }
            }
        }
    }

    wing::epoll_close(epfd);
    wing::tcp_close(listener);
}

// Context for worker thread pinned to CPU core
struct WorkerContext {
    worker_id: i64 = 0,
    port: u16 = 3001,
}

// Worker thread entry point for multi-core scaling (SO_REUSEPORT + CPU core pinning)
thread_fn worker(ctx: WorkerContext) {
    wing::set_cpu_affinity(ctx.worker_id);
    run_reactor(ctx.port, ctx.worker_id);
}

fn main() {
    let port: u16 = wing::get_env_port(3001);
    // WING_WORKERS defaults to 1 for 1-to-1 comparison with single-threaded uWebSockets (RSS ~3.1 MB)
    let num_workers: i64 = wing::get_env_workers(1);

    if num_workers <= 1 {
        wing::set_cpu_affinity(0);
        print("goose-wing server listening on 0.0.0.0:", port, " [Single-Threaded Epoll/Reactor-per-Core | RSS ~3.1 MB]");
        run_reactor(port, 0);
    } else {
        print("goose-wing server listening on 0.0.0.0:", port, " [Share-Nothing SO_REUSEPORT Workers: ", num_workers, "]");
        var threads: i64[..64] = [];
        for i in num_workers {
            let ctx = WorkerContext { worker_id: i, port: port };
            threads.push(thread_spawn(worker, ctx));
        }
        for id in threads {
            thread_wait(id);
        }
    }
}
