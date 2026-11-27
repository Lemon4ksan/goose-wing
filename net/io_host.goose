// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Unified zero-allocation TCP/Unix/Virtual async I/O host implementing `core::host_*`.
// Delivers zero-copy `LinkEvent` push notifications across Linux epoll & io_uring
// (pbuf_ring multishot recv + async send), Windows WSAPoll & RIO, macOS kqueue,
// and deterministic in-memory virtual duplex pipes.
namespace net;

import std;
import core;
import net.driver;
import .tcp;
import .transport;
import .internal;
import .io_host_internal;
import .io_host_loop_internal;

struct Host {
    backend:         net_internal::HostBackendKind       = net_internal::HostBackendKind.Standard,
    driver_cfg:      net_internal::TransportDriverConfig = net_internal::TransportDriverConfig { .. },
    epfd_shards:     net_internal::EpfdShard[..64]       = [],
    timers:          net_internal::HostTimer[..256]      = [],
    wake_queue:      core::WakeToken[..512]              = [],
    kq_changes:      net_internal::Kevent[..64]          = [],
    accel_slab:      u8[]                                = [],
    epfd:            i64                                 = -1,
    kq_fd:           i64                                 = -1,
    uring_fd:        i64                                 = -1,
    uring_pbuf:      u64                                 = 0,
    rio_cq:          u64                                 = 0,
    rio_buf_id:      u64                                 = 0,
    active_links:    i64                                 = 0,
    epfd_count:      i64                                 = 0,
    active_timers:   i64                                 = 0,
    free_link_head:  i32                                 = -1,
    virt_head:       i32                                 = -1,
    free_timer_head: i32                                 = -1,
    is_open:         bool                                = false,
    links:           net_internal::IoLinkSlot[>..]       = [],
}

// Creates and initializes a `Host` using `driver_cfg` (with automatic OS fallback).
fn new_host(driver_cfg: const net_internal::TransportDriverConfig&) -> Host {
    var cfg = driver_cfg;
    if !cfg.is_probed {
        let _ = net_internal::init_transport_driver(cfg);
    }
    var host = Host {
        driver_cfg: cfg,
        accel_slab: net_internal::make_host_accel_slab(cfg),
        is_open:    true,
        ..
    };
    net_internal::init_host_backend(host, cfg);
    return host;
}

// Closes all active links and OS handles owned by `host`.
fn close_host(host: Host&) {
    guard host.is_open else { return; }
    for i in host.links.len {
        if host.links[i].in_use {
            net_internal::release_host_slot(host, i);
        }
    }
    if host.rio_cq != 0 {
        var drain_res: net_internal::RioResult[..64] = [];
        for _ in 64 {
            let n = net_internal::rio_drain_completions(host.rio_cq, drain_res);
            if n <= 0 {
                break;
            }
        }
    }
    if host.rio_buf_id != 0 {
        net_internal::native_rio_deregister_buffer(host.rio_buf_id);
        host.rio_buf_id = 0;
    }
    if host.rio_cq != 0 {
        net_internal::native_rio_close_cq(host.rio_cq);
        host.rio_cq = 0;
    }
    if host.uring_pbuf != 0 {
        net_internal::uring_free_pbuf_ring(host.uring_pbuf);
        host.uring_pbuf = 0;
    }
    if host.uring_fd >= 0 {
        net_internal::native_uring_close(host.uring_fd);
        host.uring_fd = -1;
    }
    if host.kq_fd >= 0 {
        net_internal::native_kqueue_close(host.kq_fd);
        host.kq_fd = -1;
    }
    for i in host.epfd_shards.len {
        if host.epfd_shards[i].fd >= 0 {
            epoll_close(host.epfd_shards[i].fd);
        }
    }
    host.epfd_shards.clear();
    host.epfd = -1;
    host.links.clear();
    host.timers.clear();
    host.wake_queue.clear();
    host.kq_changes.clear();
    host.free_link_head = -1;
    host.virt_head = -1;
    host.free_timer_head = -1;
    host.active_links = 0;
    host.epfd_count = 0;
    host.active_timers = 0;
    host.is_open = false;
}

// Opens a listening TCP or Unix socket under `owner` (satisfies `core::host_listen`).
fn link_listen(
    host:    Host&,
    addr:    core::ConnectAddr,
    owner:   u16,
    tag:     u64,
    backlog: i32,
) -> core::IoLink, core::IoError {
    guard host.is_open && core::is_valid_listen_addr(addr) && owner != 0 else {
        return core::IoLink { .. }, core::IoError.InvalidArgument;
    }
    let kind = match addr {
        Tcp _ => net_internal::LinkKind.Tcp,
        Unix _ => net_internal::LinkKind.Unix,
    };
    let slot = net_internal::alloc_host_slot(host, owner, tag, kind);
    guard slot >= 0 else { return core::IoLink { .. }, core::IoError.BufferFull; }

    var fd: i64 = -1;
    var is_rio = false;
    match addr {
        Tcp t => {
            if host.backend == net_internal::HostBackendKind.WindowsRIO && host.rio_cq != 0 {
                fd = net_internal::rio_listen(t.host, t.port, backlog);
                is_rio = fd > 0;
            }
            if fd <= 0 {
                fd = tcp_listen(t.host, t.port, backlog);
            }
        },
        Unix u => {
            fd = tcp_listen_unix(u.path, backlog);
        },
    };
    guard fd > 0 else {
        net_internal::release_host_slot(host, slot);
        return core::IoLink { .. }, core::IoError.Closed;
    }
    if !is_rio {
        let _ = tcp_set_nonblocking(fd, true);
    }
    host.links[slot].fd = fd;
    host.links[slot].state = net_internal::LinkSlotState.Listening;
    host.links[slot].is_rio = is_rio;
    if !is_rio {
        net_internal::sync_slot_interest(host, slot);
    }
    return net_internal::host_slot_link(host, slot), core::IoError.None;
}

// Queries the OS-assigned local TCP port bound to a listening or connected `link`.
fn link_local_port(host: const Host&, link: core::IoLink) -> u16 {
    let slot, ok = net_internal::host_match_link(host, link);
    guard ok && host.links[slot].kind == net_internal::LinkKind.Tcp && host.links[slot].fd > 0 else { return 0; }
    return tcp_getsockname_port(host.links[slot].fd);
}

// Begins a non-blocking TCP or Unix outbound connect (satisfies `core::host_connect`).
fn link_connect(
    host:  Host&,
    addr:  core::ConnectAddr,
    owner: u16,
    tag:   u64,
) -> core::IoLink, core::ConnectStatus {
    guard host.is_open && core::is_valid_connect_addr(addr) && owner != 0 else {
        return core::IoLink { .. }, core::ConnectStatus.InvalidArgument;
    }
    let kind = match addr {
        Tcp _ => net_internal::LinkKind.Tcp,
        Unix _ => net_internal::LinkKind.Unix,
    };
    let slot = net_internal::alloc_host_slot(host, owner, tag, kind);
    guard slot >= 0 else { return core::IoLink { .. }, core::ConnectStatus.Failed; }

    var conn_state: i32 = -1;
    let fd = match addr {
        Tcp t => tcp_connect_begin(t.host, t.port, conn_state),
        Unix u => net_internal::tcp_connect_unix_begin(u.path, conn_state),
    };
    guard fd > 0 && conn_state >= 0 else {
        net_internal::release_host_slot(host, slot);
        return core::IoLink { .. }, core::ConnectStatus.Failed;
    }
    host.links[slot].fd = fd;
    host.links[slot].state = if conn_state == 0 {
        net_internal::LinkSlotState.Open
    } else {
        net_internal::LinkSlotState.Connecting
    };
    net_internal::sync_slot_interest(host, slot);
    let link = net_internal::host_slot_link(host, slot);
    let st = if conn_state == 0 { core::ConnectStatus.Connected } else { core::ConnectStatus.InProgress };
    return link, st;
}

// Opens an in-memory bidirectional virtual link pair hosted on `host` for deterministic tests.
fn open_virtual_pair(
    host:    Host&,
    owner_a: u16,
    owner_b: u16,
    tag_a:   u64 = 0,
    tag_b:   u64 = 0,
) -> core::IoLink, core::IoLink, bool {
    guard host.is_open && owner_a != 0 && owner_b != 0 else {
        return core::IoLink { .. }, core::IoLink { .. }, false;
    }
    let pipe_slot, ok_pipe = alloc_virtual_pipe_slot();
    guard ok_pipe else { return core::IoLink { .. }, core::IoLink { .. }, false; }

    let slot_a = net_internal::alloc_host_slot(host, owner_a, tag_a, net_internal::LinkKind.Virtual);
    if slot_a < 0 {
        free_virtual_pipe_slot(pipe_slot);
        return core::IoLink { .. }, core::IoLink { .. }, false;
    }
    let slot_b = net_internal::alloc_host_slot(host, owner_b, tag_b, net_internal::LinkKind.Virtual);
    if slot_b < 0 {
        free_virtual_pipe_slot(pipe_slot);
        net_internal::release_host_slot(host, slot_a);
        return core::IoLink { .. }, core::IoLink { .. }, false;
    }
    host.links[slot_a].virtual_pair = pipe_slot;
    host.links[slot_a].is_b_end = false;
    host.links[slot_a].state = net_internal::LinkSlotState.Open;
    net_internal::virt_link_insert(host, slot_a);
    host.links[slot_b].virtual_pair = pipe_slot;
    host.links[slot_b].is_b_end = true;
    host.links[slot_b].state = net_internal::LinkSlotState.Open;
    net_internal::virt_link_insert(host, slot_b);
    return net_internal::host_slot_link(host, slot_a), net_internal::host_slot_link(host, slot_b), true;
}

// Writes wire bytes to `link` (satisfies `core::host_send`).
fn link_send(host: Host&, link: core::IoLink, data: const u8[:]) -> i32, core::IoError {
    let slot, ok = net_internal::host_match_link(host, link);
    guard ok && data.len > 0 else { return 0, core::IoError.InvalidArgument; }
    guard host.links[slot].state == net_internal::LinkSlotState.Open && !host.links[slot].write_shut else {
        return 0, core::IoError.Closed;
    }
    if host.links[slot].kind == net_internal::LinkKind.Virtual {
        let rc = virtual_pipe_send(host.links[slot].virtual_pair as u16, host.links[slot].is_b_end, data);
        let n, err = core::translate_send_result(rc, data.len);
        if err == core::IoError.WouldBlock || err == core::IoError.ShortWrite {
            host.links[slot].want_write = true;
        }
        return n, err;
    }
    let can_accel_tx = slot < net_internal::NET_HOST_ACCEL_SLOTS && (host.links[slot].is_rio || host.uring_fd >= 0);
    if can_accel_tx {
        return net_internal::send_accel_slab_tx(host, slot, data);
    }
    let rc = tcp_send(host.links[slot].fd, data);
    let n, err = core::translate_send_result(rc, data.len);
    if err == core::IoError.WouldBlock || err == core::IoError.ShortWrite {
        host.links[slot].want_write = true;
        net_internal::sync_slot_interest(host, slot);
    }
    return n, err;
}

// Pauses or resumes incoming byte delivery for backpressure (satisfies `core::host_set_rx_paused`).
fn link_set_rx_paused(host: Host&, link: core::IoLink, paused: bool) -> bool {
    let slot, ok = net_internal::host_match_link(host, link);
    guard ok else { return false; }
    host.links[slot].rx_paused = paused;
    if host.links[slot].is_rio && !paused && host.links[slot].state == net_internal::LinkSlotState.Open {
        let _ = net_internal::post_rio_slot_recv(host, slot);
    } else {
        net_internal::sync_slot_interest(host, slot);
    }
    return true;
}

// Half-closes the write direction of `link` (satisfies `core::host_shutdown_write`).
fn link_shutdown_write(host: Host&, link: core::IoLink) -> bool {
    let slot, ok = net_internal::host_match_link(host, link);
    guard ok && host.links[slot].state == net_internal::LinkSlotState.Open else { return false; }
    host.links[slot].write_shut = true;
    if host.links[slot].kind == net_internal::LinkKind.Virtual {
        let pidx = host.links[slot].virtual_pair;
        guard pidx >= 0 && pidx < MAX_VIRTUAL_PIPES else { return false; }
        if host.links[slot].is_b_end {
            g_virtual_pipes[pidx].closed_b = true;
        } else {
            g_virtual_pipes[pidx].closed_a = true;
        }
        return true;
    }
    return tcp_shutdown(host.links[slot].fd, SHUT_WR);
}

// Closes `link` and invalidates its handle (satisfies `core::host_close`).
fn link_close(host: Host&, link: core::IoLink) -> bool {
    let slot, ok = net_internal::host_match_link(host, link);
    guard ok else { return false; }
    net_internal::release_host_slot(host, slot);
    return true;
}

// Aborts `link` immediately via SO_LINGER(1, 0) RST on TCP sockets (or virtual RST) and releases its slot.
fn link_abort(host: Host&, link: core::IoLink) -> bool {
    let slot, ok = net_internal::host_match_link(host, link);
    guard ok else { return false; }
    if host.links[slot].kind == net_internal::LinkKind.Tcp && host.links[slot].fd > 0 {
        let _ = tcp_set_linger(host.links[slot].fd, true, 0);
    } else if host.links[slot].kind == net_internal::LinkKind.Virtual && host.links[slot].virtual_pair >= 0 {
        let _ = virtual_pipe_inject_rst(host.links[slot].virtual_pair as u16, host.links[slot].is_b_end);
    }
    net_internal::release_host_slot(host, slot);
    return true;
}

// Schedules a timer routed to `owner` (satisfies `core::host_add_timer`).
fn link_add_timer(
    host:     Host&,
    timer_id: u64,
    delay_ms: u64,
    owner:    u16,
    tag:      u64,
    periodic: bool,
    now_ns:   u64,
) -> bool {
    guard host.is_open && timer_id != 0 && owner != 0 else { return false; }
    let deadline = core::add_sat_u64(now_ns, core::mul_sat_u64(delay_ms, net_internal::NET_HOST_NANOS_MS));
    let interval = if periodic { core::mul_sat_u64(delay_ms, net_internal::NET_HOST_NANOS_MS) } else { 0 };
    if host.active_timers > 0 {
        for i in host.timers.len {
            if host.timers[i].active && host.timers[i].timer_id == timer_id {
                host.timers[i].tag = tag;
                host.timers[i].owner = owner;
                host.timers[i].deadline_ns = deadline;
                host.timers[i].interval_ns = interval;
                return true;
            }
        }
    }
    var idx: i64 = -1;
    if host.free_timer_head >= 0 {
        idx = host.free_timer_head;
        host.free_timer_head = host.timers[idx].next_free;
    } else {
        idx = host.timers.len;
        guard host.timers.try_push(net_internal::HostTimer { .. }) else { return false; }
    }
    host.timers[idx] = net_internal::HostTimer {
        timer_id:    timer_id,
        tag:         tag,
        deadline_ns: deadline,
        interval_ns: interval,
        next_free:   -1,
        owner:       owner,
        active:      true,
    };
    host.active_timers = core::add_sat_i64(host.active_timers, 1);
    return true;
}

// Cancels an active timer by ID (satisfies `core::host_cancel_timer`).
fn link_cancel_timer(host: Host&, timer_id: u64) -> bool {
    guard host.is_open && timer_id != 0 && host.active_timers > 0 else { return false; }
    for i in host.timers.len {
        if host.timers[i].active && host.timers[i].timer_id == timer_id {
            host.timers[i].active = false;
            host.timers[i].timer_id = 0;
            host.timers[i].next_free = host.free_timer_head;
            host.free_timer_head = i as i32;
            if host.active_timers > 0 {
                host.active_timers = core::sub_sat_i64(host.active_timers, 1);
            }
            return true;
        }
    }
    return false;
}

// Returns the earliest active timer deadline on `host` in nanoseconds, or `(0, false)`.
fn host_next_timer_ns(host: const Host&) -> u64, bool {
    guard host.is_open && host.active_timers > 0 else { return 0, false; }
    var earliest: u64  = 0xFFFFFFFFFFFFFFFF;
    var found:    bool = false;
    for i in host.timers.len {
        if host.timers[i].active {
            earliest = min(earliest, host.timers[i].deadline_ns);
            found = true;
        }
    }
    return if found { earliest } else { 0 }, found;
}

// Queues a wakeup token for delivery on the next poll pass (satisfies `core::host_wake`).
fn link_wake(host: Host&, token: core::WakeToken) -> bool {
    guard host.is_open && core::wake_token_is_valid(token) else { return false; }
    return host.wake_queue.try_push(token);
}

fn link_poll_dispatch_ctx<D, CtxA, CtxB>(
    host:       Host&,
    driver:     D&,
    arg_a:      CtxA&,
    arg_b:      CtxB&,
    timeout_ms: i64,
    now_ns:     u64,
) -> i32 {
    guard host.is_open else { return 0; }
    var count:      i32     = 0;
    var rx_scratch: u8[>..] = [];
    let eff_timeout = net_internal::clamp_host_timeout(host, timeout_ms, now_ns);

    if host.uring_fd >= 0 {
        net_internal::poll_uring_backend(host, driver, arg_a, arg_b, rx_scratch, eff_timeout, count);
    } else if host.kq_fd >= 0 {
        net_internal::poll_kqueue_backend(host, driver, arg_a, arg_b, rx_scratch, eff_timeout, count);
    } else {
        if host.rio_cq != 0 {
            let rio_tmo = if host.epfd_count > 0 { 0 } else { eff_timeout };
            net_internal::poll_rio_backend(host, driver, arg_a, arg_b, rio_tmo, count);
        }
        let ep_tmo = if count > 0 || host.wake_queue.len > 0 { 0 } else { eff_timeout };
        net_internal::poll_epoll_backend(host, driver, arg_a, arg_b, rx_scratch, ep_tmo, count);
    }
    net_internal::dispatch_virtual_links(host, driver, arg_a, arg_b, rx_scratch, count);
    net_internal::dispatch_host_timers(host, driver, arg_a, arg_b, now_ns, count);
    net_internal::dispatch_host_wakes(host, driver, arg_a, arg_b, count);
    return count;
}

// Polls all active transports, timers, and wakes and pushes events to `driver.on_link_event`
// (satisfies `core::host_step`).
fn link_poll_dispatch<D>(
    host:       Host&,
    driver:     D&,
    timeout_ms: i64,
    now_ns:     u64,
) -> i32 {
    var unused_a = net_internal::UnusedHostArg {};
    var unused_b = net_internal::UnusedHostArg {};
    return link_poll_dispatch_ctx(host, driver, unused_a, unused_b, timeout_ms, now_ns);
}
