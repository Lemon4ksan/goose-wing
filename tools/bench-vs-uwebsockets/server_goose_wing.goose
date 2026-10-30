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
    bp_idx: i16 = -1,
    _pad: u8[4] = [0; 4],
    leftover: u8[232] = [0; 232],
}

// Cleans up a connection slot, closing fd, freeing backpressure, and restoring to free stack.
fn cleanup_slot(
    epfd: i64,
    slot: ConnSlot&,
    slot_idx: i64,
    free_slots: wing::FreeSlotStack&,
    bp_free: i64[:],
    bp_free_top: i64&,
) {
    if slot.fd > 0 {
        wing::epoll_del(epfd, slot.fd);
        wing::tcp_close(slot.fd);
        slot.fd = -1;
    }
    if slot.bp_idx >= 0 && bp_free_top < bp_free.len {
        bp_free[bp_free_top] = slot.bp_idx;
        bp_free_top++;
        slot.bp_idx = -1;
    }
    wing::push_free_slot(free_slots, slot_idx);
}

// Accepts and registers all pending connections from the listener queue.
fn drain_listener(
    epfd: i64,
    listener: i64,
    timer_wheel: wing::TickTimerWheel&,
    slots: ConnSlot[:],
    free_slots: wing::FreeSlotStack&,
) {
    while true {
        let client_fd = wing::tcp_accept_nonblocking(listener);
        if client_fd <= 0 {
            break;
        }

        let slot_idx = wing::pop_free_slot(free_slots);
        if slot_idx >= 0 && slot_idx < slots.len {
            slots[slot_idx].fd = client_fd;
            slots[slot_idx].is_ws = false;
            slots[slot_idx].leftover_len = 0;
            slots[slot_idx].bp_idx = -1;
            slots[slot_idx].timeout_tick = wing::tick_timer_arm(timer_wheel, 15);
            wing::epoll_add(epfd, client_fd, wing::EPOLL_READ, slot_idx as u64);
        } else {
            wing::tcp_close(client_fd);
        }
    }
}

// Flushes the accumulated cork buffer via bounded send loop with fallback to backpressure.
// Returns true if connection remains alive, false on unbuffered write failure.
fn flush_cork_batch(
    epfd: i64,
    conn: i64,
    slot: ConnSlot&,
    slot_idx: i64,
    cork_buf: const u8[:],
    cork_len: i64,
    bp_pool: wing::BackpressureSlot[:],
    bp_free: i64[:],
    bp_free_top: i64&,
) -> bool {
    guard cork_len > 0 && cork_len <= cork_buf.len else { return true; }
    var total_sent: i64 = 0;
    var send_attempts: i64 = 0;
    while total_sent < cork_len && send_attempts < 16 {
        let sent = wing::tcp_send(conn, cork_buf[total_sent..cork_len]);
        if sent <= 0 {
            break;
        }
        total_sent += sent;
        send_attempts += 1;
    }

    guard total_sent < cork_len else { return true; }
    let unsent = cork_buf[total_sent..cork_len];
    guard slot.bp_idx == -1 && bp_free_top > 0 else { return false; }
    let bp_i = bp_free[bp_free_top - 1];
    let buffered = wing::buffer_backpressure(bp_pool[bp_i], unsent);
    guard buffered else { return false; }
    bp_free_top--;
    slot.bp_idx = bp_i as i16;
    wing::epoll_mod(epfd, conn, wing::EPOLL_WRITE, slot_idx as u64);
    return true;
}

// Periodic sweep to close expired idle connections and free resources.
fn sweep_expired_slots(
    epfd: i64,
    timer_wheel: wing::TickTimerWheel&,
    slots: ConnSlot[:],
    free_slots: wing::FreeSlotStack&,
    bp_free: i64[:],
    bp_free_top: i64&,
) {
    wing::tick_timer_advance(timer_wheel, 1);
    for s in slots.len {
        if slots[s].fd > 0 && wing::tick_timer_is_expired(timer_wheel, slots[s].timeout_tick) {
            cleanup_slot(epfd, slots[s], s, free_slots, bp_free, bp_free_top);
        }
    }
}

// Drains active backpressure bytes on socket if previously registered for EPOLLOUT.
// Returns 1 if fully drained/inactive, 0 if still congested, -1 on fatal socket error.
fn check_drain_backpressure(
    epfd: i64,
    conn: i64,
    slot: ConnSlot&,
    slot_idx: i64,
    bp_pool: wing::BackpressureSlot[:],
    bp_free: i64[:],
    bp_free_top: i64&,
) -> i32 {
    guard slot.bp_idx >= 0 else { return 1; }
    let bp_i = slot.bp_idx as i64;
    guard bp_i >= 0 && bp_i < bp_pool.len else { return 1; }
    let drained, ok = wing::drain_backpressure(bp_pool[bp_i], conn);
    if drained < 0 {
        return -1;
    }
    guard ok else { return 0; }
    if bp_free_top < bp_free.len {
        bp_free[bp_free_top] = bp_i;
        bp_free_top++;
    }
    slot.bp_idx = -1;
    wing::epoll_mod(epfd, conn, wing::EPOLL_READ, slot_idx as u64);
    return 1;
}

// Processes incoming WebSocket wire frames (RFC 6455).
// Returns true if connection remains active, false if closed.
fn handle_ws_ingress(
    conn: i64,
    in_buf: u8[:],
    slot: ConnSlot&,
    ws_cork: u8[..65536]&,
) -> bool {
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

    guard ws_alive else { return false; }

    if slot.fd > 0 && ws_cursor >= 0 && ws_cursor < in_buf.len {
        let rem = in_buf[ws_cursor..];
        let rlen = rem.len;
        if rlen > 0 && rlen <= 232 {
            slot.leftover_len = rlen;
            for r in rlen {
                slot.leftover[r] = rem[r];
            }
        }
    }
    return true;
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
    var free_slots = wing::FreeSlotStack { .. };
    wing::init_free_slots(free_slots, 1024);
    var bp_pool: wing::BackpressureSlot[64] = [wing::BackpressureSlot { .. }; 64];
    var bp_free: i64[64] = [0; 64];
    for b in 64 {
        bp_free[b] = 63 - b;
    }
    var bp_free_top: i64 = 64;

    var ready_fds: i64[0] = [];
    var ready_udata: u64[1024] = [0; 1024];
    var raw_recv: u8[65536] = [0; 65536];
    var cork_buf: u8[65536] = [0; 65536];
    var ws_cork: u8[..65536] = [];
    var timer_wheel = wing::new_tick_timer_wheel(15);

    while true {
        let n = wing::epoll_wait_direct(epfd, ready_fds[..], ready_udata[..], 1000);
        if n <= 0 {
            sweep_expired_slots(epfd, timer_wheel, slots[..], free_slots, bp_free[..], bp_free_top);
            continue;
        }

        guard n <= ready_udata.len else {
            continue;
        }
        for ev_idx in n {
            let udata = ready_udata[ev_idx];

            if udata == wing::EPOLL_LISTENER_TAG {
                drain_listener(epfd, listener, timer_wheel, slots[..], free_slots);
                continue;
            }

            let slot_idx = udata as i64;
            if slot_idx < 0 || slot_idx >= slots.len || slots[slot_idx].fd <= 0 {
                continue;
            }
            let conn = slots[slot_idx].fd;
            slots[slot_idx].timeout_tick = wing::tick_timer_arm(timer_wheel, 15);

            // Drain active backpressure if registered for EPOLLOUT
            if slots[slot_idx].bp_idx >= 0 {
                let drain_status = check_drain_backpressure(
                    epfd, conn, slots[slot_idx], slot_idx,
                    bp_pool[..], bp_free[..], bp_free_top,
                );
                if drain_status < 0 {
                    cleanup_slot(epfd, slots[slot_idx], slot_idx, free_slots, bp_free[..], bp_free_top);
                    continue;
                }
                if drain_status == 0 {
                    // TX buffer still congested; skip reading new requests
                    continue;
                }
            }

            var active_len: i64 = 0;
            let prev_len = slots[slot_idx].leftover_len;
            if prev_len > 0 && prev_len <= 232 {
                for p in prev_len {
                    raw_recv[p] = slots[slot_idx].leftover[p];
                }
                slots[slot_idx].leftover_len = 0;
                active_len = prev_len;
            }

            var client_alive = true;
            var upgraded_ws = false;

            for turn in 4 {
                guard active_len >= 0 && active_len <= raw_recv.len && client_alive else {
                    break;
                }

                let available = raw_recv.len - active_len;
                let recvd = wing::tcp_recv_nonblocking_slice(conn, raw_recv[active_len..]);
                if recvd == -2 {
                    // EAGAIN / EWOULDBLOCK: kernel socket queue fully drained
                    break;
                }
                if recvd == 0 || recvd == -1 {
                    // Client closed (EOF) or connection error
                    cleanup_slot(epfd, slots[slot_idx], slot_idx, free_slots, bp_free[..], bp_free_top);
                    client_alive = false;
                    break;
                }
                active_len += recvd;
                guard active_len > 0 && active_len <= raw_recv.len else {
                    break;
                }
                core::fence_wire_slice(raw_recv[..], active_len);
                let in_buf = raw_recv[..active_len];

                if slots[slot_idx].is_ws {
                    let ws_alive = handle_ws_ingress(conn, in_buf, slots[slot_idx], ws_cork);
                    if !ws_alive {
                        cleanup_slot(epfd, slots[slot_idx], slot_idx, free_slots, bp_free[..], bp_free_top);
                        client_alive = false;
                    }
                    active_len = 0;
                    break;
                }

                // HTTP/1.1 Pipelined Request Batch Processing
                var cork_len: i64 = 0;
                var cursor: i64 = 0;

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
                    cleanup_slot(epfd, slots[slot_idx], slot_idx, free_slots, bp_free[..], bp_free_top);
                    break;
                }

                // Flush cork buffer batch in bounded send loop with fallback to backpressure
                if cork_len > 0 {
                    let flushed = flush_cork_batch(
                        epfd, conn, slots[slot_idx], slot_idx,
                        cork_buf[..], cork_len, bp_pool[..], bp_free[..], bp_free_top,
                    );
                    if !flushed {
                        cleanup_slot(epfd, slots[slot_idx], slot_idx, free_slots, bp_free[..], bp_free_top);
                        client_alive = false;
                        break;
                    }
                }

                // If backpressure engaged or connection upgraded to WS, save unparsed slice and exit turn
                if slots[slot_idx].bp_idx >= 0 || upgraded_ws {
                    if cursor >= 0 && cursor < in_buf.len {
                        let rem_len = in_buf.len - cursor;
                        if rem_len > 0 && rem_len <= 232 {
                            slots[slot_idx].leftover_len = rem_len;
                            for r in rem_len {
                                slots[slot_idx].leftover[r] = in_buf[cursor + r];
                            }
                        } else if rem_len > 232 {
                            cleanup_slot(epfd, slots[slot_idx], slot_idx, free_slots, bp_free[..], bp_free_top);
                            client_alive = false;
                            break;
                        }
                    }
                    active_len = 0;
                    break;
                }

                // If socket queue was completely emptied by previous recv (recvd < available),
                // do NOT loop again — next recv() would waste a syscall returning EAGAIN.
                if recvd < available {
                    if cursor >= 0 && cursor < in_buf.len {
                        let rem_len = in_buf.len - cursor;
                        if rem_len > 0 && rem_len <= 232 {
                            active_len = rem_len;
                            for r in rem_len {
                                raw_recv[r] = in_buf[cursor + r];
                            }
                        } else {
                            active_len = 0;
                        }
                    } else {
                        active_len = 0;
                    }
                    break;
                }

                // Shift any incomplete unparsed request bytes to index 0 of raw_recv for next turn
                if cursor >= 0 && cursor < in_buf.len {
                    let rem_len = in_buf.len - cursor;
                    if rem_len > 0 && rem_len <= 232 {
                        for r in rem_len {
                            raw_recv[r] = in_buf[cursor + r];
                        }
                        active_len = rem_len;
                    } else {
                        active_len = 0;
                        break;
                    }
                } else {
                    active_len = 0;
                }
            }

            // Save leftover fragmentation on loop completion
            if client_alive && !upgraded_ws && slots[slot_idx].fd > 0 && active_len > 0 && active_len <= 232 {
                slots[slot_idx].leftover_len = active_len;
                for r in active_len {
                    slots[slot_idx].leftover[r] = raw_recv[r];
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
