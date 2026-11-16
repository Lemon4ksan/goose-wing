// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Unified zero-allocation TCP/Unix/Virtual async I/O host implementing `core::host_*`.
// Delivers zero-copy `LinkEvent` push notifications across Linux epoll & io_uring
// (pbuf_ring multishot recv + async send), Windows WSAPoll & RIO, macOS kqueue,
// and deterministic in-memory virtual duplex pipes.
namespace wing;

import std;
import core from "..";
import net.driver;
import .tcp;
import .transport;

const NET_HOST_MAX_LINKS:   i64 = 256;
const NET_HOST_ACCEL_SLOTS: i64 = 16;
const NET_HOST_ACCEL_CHUNK: i64 = 4096;
const NET_HOST_SLAB_BYTES:  i64 = 131072; // 16 slots * (4KB RX + 4KB TX)
const NET_HOST_MAX_TIMERS:  i64 = 64;
const NET_HOST_MAX_WAKES:   i64 = 64;
const NET_HOST_RX_CAP:      i64 = 16384;
const NET_HOST_NANOS_MS:    u64 = 1000000;
const NET_HOST_MAX_TMO_NS:  u64 = 2147483647000000;
const NET_HOST_MULHI_RECIP: u64 = 0x10C6F7A0B5EE;

const HOST_URING_OP_ACCEPT:  u64 = 1;
const HOST_URING_OP_CONNECT: u64 = 2;
const HOST_URING_OP_RECV:    u64 = 3;
const HOST_URING_OP_SEND:    u64 = 4;
const HOST_URING_OP_POLL_W:  u64 = 5;
const HOST_URING_OP_SHIFT:   u32 = 48;
const HOST_URING_GEN_SHIFT:  u32 = 32;
const HOST_URING_PBUF_BGID:  u16 = 2;
const HOST_URING_CANCEL_TAG: u64 = 0xFFFFFFFFFFFFFFFF;
const HOST_RIO_REQ_RX:       u64 = 1;
const HOST_RIO_REQ_TX:       u64 = 2;
const HOST_KQ_EV_ERROR:      u16 = 0x4000;

enum HostBackendKind {
    Standard,
    IoUring,
    WindowsRIO,
    Kqueue,
}

enum LinkSlotState {
    Free,
    Connecting,
    Listening,
    Open,
}

enum LinkKind {
    Tcp,
    Unix,
    Virtual,
}

struct IoLinkSlot {
    fd:               i64           = -1,
    tag:              u64           = 0,
    rio_rq:           u64           = 0,
    virtual_pair:     i32           = -1,
    epoll_mask:       u32           = 0,
    gen:              u16           = 1,
    owner:            u16           = 0,
    state:            LinkSlotState = LinkSlotState.Free,
    kind:             LinkKind      = LinkKind.Tcp,
    in_use:           bool          = false,
    in_epfd:          bool          = false,
    is_rio:           bool          = false,
    is_b_end:         bool          = false,
    rx_paused:        bool          = false,
    want_write:       bool          = false,
    tx_inflight:      bool          = false,
    eof_received:     bool          = false,
    write_shut:       bool          = false,
    virtual_eof_sent: bool          = false,
}

struct HostTimer {
    timer_id:    u64  = 0,
    tag:         u64  = 0,
    deadline_ns: u64  = 0,
    interval_ns: u64  = 0,
    owner:       u16  = 0,
    active:      bool = false,
}

struct NetHost {
    backend:       HostBackendKind                     = HostBackendKind.Standard,
    driver_cfg:    net_internal::TransportDriverConfig = net_internal::TransportDriverConfig { .. },
    links:         IoLinkSlot[256]                     = [IoLinkSlot { .. }; 256],
    timers:        HostTimer[64]                       = [HostTimer { .. }; 64],
    wake_queue:    core::WakeToken[..64]               = [],
    kq_changes:    net_internal::Kevent[..64]          = [],
    rx_scratch:    u8[16384]                           = [0; 16384],
    accel_slab:    u8[..131072]                        = [],
    epfd:          i64                                 = -1,
    kq_fd:         i64                                 = -1,
    uring_fd:      i64                                 = -1,
    uring_pbuf:    u64                                 = 0,
    rio_cq:        u64                                 = 0,
    rio_buf_id:    u64                                 = 0,
    active_links:  i64                                 = 0,
    epfd_count:    i64                                 = 0,
    active_timers: i64                                 = 0,
    is_open:       bool                                = false,
}

inline fn next_link_gen(cur: u16) -> u16 {
    return if cur >= 65535 { 1 } else { core::add_sat_u64(cur, 1) as u16 };
}

inline fn host_slot_link(host: const NetHost&, slot: i64) -> core::IoLink {
    return core::make_io_link(host.links[slot].owner, host.links[slot].gen, slot as u32);
}

inline fn host_match_link(host: const NetHost&, link: core::IoLink) -> i64, bool {
    guard host.is_open && core::io_link_is_valid(link) else { return -1, false; }
    let slot = core::io_link_slot(link);
    guard slot >= 0 && slot < NET_HOST_MAX_LINKS else { return -1, false; }
    guard host.links[slot].in_use && host.links[slot].gen == core::io_link_gen(link) else {
        return -1, false;
    }
    return slot, true;
}

inline fn host_uring_tag(op: u64, gen: u16, slot: i64) -> u64 {
    let hi = core::shl_sat_u64(op, HOST_URING_OP_SHIFT);
    let mid = core::shl_sat_u64(gen, HOST_URING_GEN_SHIFT);
    return hi | mid | ((slot as u64) & 0xFFFFFFFF);
}

inline fn host_match_uring_tag(host: const NetHost&, user_data: u64) -> u64, i64, bool {
    guard user_data != HOST_URING_CANCEL_TAG else { return 0, -1, false; }
    let op = (user_data >> HOST_URING_OP_SHIFT) & 0xFFFF;
    let gen = ((user_data >> HOST_URING_GEN_SHIFT) & 0xFFFF) as u16;
    let slot = (user_data & 0xFFFFFFFF) as i64;
    guard slot >= 0 && slot < NET_HOST_MAX_LINKS else { return 0, -1, false; }
    guard host.links[slot].in_use && host.links[slot].gen == gen && gen != 0 else { return 0, -1, false; }
    return op, slot, true;
}

inline fn host_rio_rx_offset(slot: i64) -> u32 {
    return (core::shl_sat_u64(slot as u64, 13)) as u32;
}

inline fn host_rio_tx_offset(slot: i64) -> u32 {
    return ((core::shl_sat_u64(slot as u64, 13)) | 4096) as u32;
}

fn try_init_uring_backend(host: NetHost&, cfg: const net_internal::TransportDriverConfig&) -> bool {
    let plat = net_internal::detect_target_platform();
    guard cfg.active_kind == net_internal::TransportDriverKind.IoUring &&
        plat == net_internal::TargetPlatform.Linux else { return false; }
    let rfd = net_internal::native_uring_create(256, 0);
    guard rfd >= 0 else { return false; }
    let pb, ok_pb = net_internal::uring_alloc_pbuf_ring(rfd, HOST_URING_PBUF_BGID, 256, 4096);
    if ok_pb && pb != 0 {
        host.accel_slab.resize(NET_HOST_SLAB_BYTES, 0);
        host.uring_fd = rfd;
        host.uring_pbuf = pb;
        host.backend = HostBackendKind.IoUring;
        return true;
    }
    net_internal::native_uring_close(rfd);
    return false;
}

fn try_init_rio_backend(host: NetHost&, cfg: const net_internal::TransportDriverConfig&) -> bool {
    let plat = net_internal::detect_target_platform();
    guard cfg.active_kind == net_internal::TransportDriverKind.WindowsRIO &&
        plat == net_internal::TargetPlatform.Windows &&
        net_internal::native_rio_available() == 1 else { return false; }
    let cq = net_internal::native_rio_create_cq(512);
    guard cq != 0 else { return false; }
    host.accel_slab.resize(NET_HOST_SLAB_BYTES, 0);
    let bid = net_internal::native_rio_register_slice(host.accel_slab[..]);
    if bid != 0 {
        host.rio_cq = cq;
        host.rio_buf_id = bid;
        host.backend = HostBackendKind.WindowsRIO;
        return true;
    }
    net_internal::native_rio_close_cq(cq);
    host.accel_slab.clear();
    return false;
}

fn try_init_kqueue_backend(host: NetHost&, cfg: const net_internal::TransportDriverConfig&) -> bool {
    let plat = net_internal::detect_target_platform();
    guard cfg.active_kind == net_internal::TransportDriverKind.Kqueue &&
        plat == net_internal::TargetPlatform.Darwin else { return false; }
    let kq = net_internal::native_kqueue_create();
    guard kq >= 0 else { return false; }
    host.kq_fd = kq;
    host.backend = HostBackendKind.Kqueue;
    return true;
}

fn init_host_backend(host: NetHost&, cfg: const net_internal::TransportDriverConfig&) {
    host.epfd = epoll_create();
    if try_init_uring_backend(host, cfg) { return; }
    if try_init_rio_backend(host, cfg) { return; }
    if try_init_kqueue_backend(host, cfg) { return; }
    host.backend = HostBackendKind.Standard;
}

// Creates and initializes a `NetHost` using `driver_cfg` (with automatic OS fallback).
fn new_net_host(driver_cfg: const net_internal::TransportDriverConfig&) -> NetHost {
    var cfg = driver_cfg;
    if !cfg.is_probed {
        let _ = net_internal::init_transport_driver(cfg);
    }
    var host = NetHost {
        driver_cfg: cfg,
        is_open:    true,
        ..
    };
    init_host_backend(host, cfg);
    return host;
}

fn alloc_host_slot(host: NetHost&, owner: u16, tag: u64, kind: LinkKind) -> i64 {
    for i in NET_HOST_MAX_LINKS {
        if !host.links[i].in_use {
            let gen = host.links[i].gen;
            host.links[i] = IoLinkSlot {
                tag:    tag,
                gen:    if gen == 0 { 1 } else { gen },
                owner:  owner,
                kind:   kind,
                in_use: true,
                ..
            };
            host.active_links = core::add_sat_i64(host.active_links, 1);
            return i;
        }
    }
    return -1;
}

inline fn desired_poll_mask(slot: const IoLinkSlot&) -> u32 {
    if slot.state == LinkSlotState.Connecting {
        return EPOLL_WRITE;
    }
    if slot.state == LinkSlotState.Listening {
        return EPOLL_READ;
    }
    if slot.state == LinkSlotState.Open {
        var mask: u32 = 0;
        if !slot.rx_paused && !slot.eof_received {
            mask |= EPOLL_READ;
        }
        if slot.want_write {
            mask |= EPOLL_WRITE;
        }
        return mask;
    }
    return 0;
}

inline fn queue_kq_diff(
    host:     NetHost&,
    fd:       i64,
    udata:    u64,
    old_mask: u32,
    new_mask: u32,
) {
    let want_r = (new_mask & EPOLL_READ) != 0;
    let had_r = (old_mask & EPOLL_READ) != 0;
    if want_r != had_r {
        var ev_r = net_internal::Kevent { .. };
        if want_r {
            net_internal::kevent_prep_read(ev_r, fd as i32, udata, false);
        } else {
            ev_r = net_internal::Kevent {
                ident: fd as u64, filter: net_internal::EVFILT_READ, flags: net_internal::EV_DELETE, ..
            };
        }
        if !host.kq_changes.try_push(ev_r) {
            var ign: net_internal::Kevent[1] = [net_internal::Kevent { .. }];
            let _ = net_internal::kqueue_poll_slice(host.kq_fd, host.kq_changes[..], ign[..0], 0);
            host.kq_changes.clear();
            let _ = host.kq_changes.try_push(ev_r);
        }
    }
    let want_w = (new_mask & EPOLL_WRITE) != 0;
    let had_w = (old_mask & EPOLL_WRITE) != 0;
    if want_w != had_w {
        var ev_w = net_internal::Kevent { .. };
        if want_w {
            net_internal::kevent_prep_write(ev_w, fd as i32, udata, false);
        } else {
            ev_w = net_internal::Kevent {
                ident: fd as u64, filter: net_internal::EVFILT_WRITE, flags: net_internal::EV_DELETE, ..
            };
        }
        if !host.kq_changes.try_push(ev_w) {
            var ign: net_internal::Kevent[1] = [net_internal::Kevent { .. }];
            let _ = net_internal::kqueue_poll_slice(host.kq_fd, host.kq_changes[..], ign[..0], 0);
            host.kq_changes.clear();
            let _ = host.kq_changes.try_push(ev_w);
        }
    }
}

inline fn sync_uring_slot_interest(host: NetHost&, slot: i64, new_mask: u32) {
    let gen = host.links[slot].gen;
    let fd = host.links[slot].fd as i32;
    let old_mask = host.links[slot].epoll_mask;
    if host.links[slot].state == LinkSlotState.Listening {
        if (old_mask & EPOLL_READ) == 0 {
            var sqe = net_internal::UringSqe { .. };
            net_internal::uring_prep_accept_multishot(sqe, fd, host_uring_tag(HOST_URING_OP_ACCEPT, gen, slot));
            var b: net_internal::UringSqe[1] = [sqe];
            let _ = net_internal::uring_submit_sqes(host.uring_fd, b[..]);
        }
        host.links[slot].epoll_mask = EPOLL_READ;
        return;
    }
    if host.links[slot].state == LinkSlotState.Connecting {
        if (old_mask & EPOLL_WRITE) == 0 {
            var sqe = net_internal::UringSqe { .. };
            net_internal::uring_prep_poll_add(sqe, fd, 4, host_uring_tag(HOST_URING_OP_CONNECT, gen, slot));
            var b: net_internal::UringSqe[1] = [sqe];
            let _ = net_internal::uring_submit_sqes(host.uring_fd, b[..]);
        }
        host.links[slot].epoll_mask = EPOLL_WRITE;
        return;
    }
    let want_r = (new_mask & EPOLL_READ) != 0;
    let had_r = (old_mask & EPOLL_READ) != 0;
    if want_r && !had_r {
        var sqe = net_internal::UringSqe { .. };
        net_internal::uring_prep_sqe_recv_multishot(
            sqe, fd, HOST_URING_PBUF_BGID, host_uring_tag(HOST_URING_OP_RECV, gen, slot),
        );
        var b: net_internal::UringSqe[1] = [sqe];
        let _ = net_internal::uring_submit_sqes(host.uring_fd, b[..]);
    } else if !want_r && had_r {
        var sqe = net_internal::UringSqe { .. };
        net_internal::uring_prep_cancel(sqe, host_uring_tag(HOST_URING_OP_RECV, gen, slot));
        sqe.user_data = HOST_URING_CANCEL_TAG;
        var b: net_internal::UringSqe[1] = [sqe];
        let _ = net_internal::uring_submit_sqes(host.uring_fd, b[..]);
    }
    let want_w = (new_mask & EPOLL_WRITE) != 0;
    let had_w = (old_mask & EPOLL_WRITE) != 0;
    if want_w && !had_w && !host.links[slot].tx_inflight {
        var sqe = net_internal::UringSqe { .. };
        net_internal::uring_prep_poll_add(sqe, fd, 4, host_uring_tag(HOST_URING_OP_POLL_W, gen, slot));
        var b: net_internal::UringSqe[1] = [sqe];
        let _ = net_internal::uring_submit_sqes(host.uring_fd, b[..]);
    }
    host.links[slot].epoll_mask = new_mask;
}

inline fn sync_epoll_slot_interest(
    host:     NetHost&,
    slot:     i64,
    fd:       i64,
    old_mask: u32,
    new_mask: u32,
) {
    guard host.epfd >= 0 else { return; }
    let want_epfd = (new_mask != 0) ||
        (host.links[slot].state == LinkSlotState.Open && !host.links[slot].eof_received);
    if !want_epfd {
        if host.links[slot].in_epfd {
            let _ = epoll_del(host.epfd, fd);
            host.links[slot].in_epfd = false;
            host.epfd_count = core::sub_sat_i64(host.epfd_count, 1);
        }
        host.links[slot].epoll_mask = 0;
        return;
    }
    let udata = host_slot_link(host, slot).raw;
    if !host.links[slot].in_epfd {
        if epoll_add(host.epfd, fd, new_mask, udata) {
            host.links[slot].in_epfd = true;
            host.epfd_count = core::add_sat_i64(host.epfd_count, 1);
            host.links[slot].epoll_mask = new_mask;
        }
        return;
    }
    guard old_mask != new_mask else { return; }
    if !epoll_mod(host.epfd, fd, new_mask, udata) {
        let _ = epoll_add(host.epfd, fd, new_mask, udata);
    }
    host.links[slot].epoll_mask = new_mask;
}

fn sync_slot_interest(host: NetHost&, slot: i64) {
    guard slot >= 0 && slot < NET_HOST_MAX_LINKS && host.links[slot].in_use else { return; }
    guard host.links[slot].kind != LinkKind.Virtual && !host.links[slot].is_rio else { return; }
    let fd = host.links[slot].fd;
    guard fd > 0 else { return; }
    let new_mask = desired_poll_mask(host.links[slot]);
    if host.uring_fd >= 0 {
        sync_uring_slot_interest(host, slot, new_mask);
        return;
    }
    let old_mask = host.links[slot].epoll_mask;
    if host.kq_fd >= 0 {
        queue_kq_diff(host, fd, host_slot_link(host, slot).raw, old_mask, new_mask);
        host.links[slot].epoll_mask = new_mask;
        return;
    }
    sync_epoll_slot_interest(host, slot, fd, old_mask, new_mask);
}

fn release_os_link_resources(host: NetHost&, slot: i64) {
    let fd = host.links[slot].fd;
    let was_epfd = host.links[slot].in_epfd && host.uring_fd < 0 && host.kq_fd < 0;
    if host.uring_fd >= 0 {
        sync_uring_slot_interest(host, slot, 0);
    } else if host.kq_fd >= 0 && fd > 0 {
        queue_kq_diff(host, fd, 0, host.links[slot].epoll_mask, 0);
    } else if host.epfd >= 0 && fd > 0 && !host.links[slot].is_rio {
        let _ = epoll_del(host.epfd, fd);
    }
    if was_epfd && host.epfd_count > 0 {
        host.epfd_count = core::sub_sat_i64(host.epfd_count, 1);
    }
    if host.links[slot].is_rio && host.links[slot].state == LinkSlotState.Listening && fd > 0 {
        let _ = net_internal::native_rio_cancel_accept(fd);
    }
    if fd > 0 {
        tcp_close(fd);
    }
}

fn release_host_slot(host: NetHost&, slot: i64) {
    guard slot >= 0 && slot < NET_HOST_MAX_LINKS && host.links[slot].in_use else { return; }
    if host.links[slot].kind == LinkKind.Virtual {
        if host.links[slot].virtual_pair >= 0 {
            virtual_pipe_close(host.links[slot].virtual_pair as u16, host.links[slot].is_b_end);
        }
    } else {
        release_os_link_resources(host, slot);
    }
    let next_gen = next_link_gen(host.links[slot].gen);
    host.links[slot] = IoLinkSlot { gen: next_gen, .. };
    if host.active_links > 0 {
        host.active_links = core::sub_sat_i64(host.active_links, 1);
    }
}

// Closes all active links and OS handles owned by `host`.
fn close_net_host(host: NetHost&) {
    guard host.is_open else { return; }
    for i in NET_HOST_MAX_LINKS {
        if host.links[i].in_use {
            release_host_slot(host, i);
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
    if host.epfd >= 0 {
        epoll_close(host.epfd);
        host.epfd = -1;
    }
    host.wake_queue.clear();
    host.kq_changes.clear();
    host.accel_slab.clear();
    host.epfd_count = 0;
    host.active_timers = 0;
    host.is_open = false;
}

inline fn post_rio_slot_recv(host: NetHost&, slot: i64) -> bool {
    guard slot >= 0 && slot < NET_HOST_ACCEL_SLOTS && host.links[slot].rio_rq != 0 else { return false; }
    return net_internal::native_rio_post_recv(
        host.links[slot].rio_rq,
        host.rio_buf_id,
        host_rio_rx_offset(slot),
        NET_HOST_ACCEL_CHUNK as u32,
        HOST_RIO_REQ_RX,
    ) == 0;
}

// Opens a listening TCP or Unix socket under `owner` (satisfies `core::host_listen`).
fn link_listen(
    host:    NetHost&,
    addr:    core::ConnectAddr,
    owner:   u16,
    tag:     u64,
    backlog: i32,
) -> core::IoLink, core::IoError {
    guard host.is_open && core::is_valid_listen_addr(addr) && owner != 0 else {
        return core::IoLink { .. }, core::IoError.InvalidArgument;
    }
    let kind = match addr {
        Tcp _ => LinkKind.Tcp,
        Unix _ => LinkKind.Unix,
    };
    let slot = alloc_host_slot(host, owner, tag, kind);
    guard slot >= 0 else { return core::IoLink { .. }, core::IoError.BufferFull; }

    var fd: i64 = -1;
    var is_rio = false;
    match addr {
        Tcp t => {
            if host.backend == HostBackendKind.WindowsRIO && host.rio_cq != 0 {
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
        release_host_slot(host, slot);
        return core::IoLink { .. }, core::IoError.Closed;
    }
    if !is_rio {
        let _ = tcp_set_nonblocking(fd, true);
    }
    host.links[slot].fd = fd;
    host.links[slot].state = LinkSlotState.Listening;
    host.links[slot].is_rio = is_rio;
    if !is_rio {
        sync_slot_interest(host, slot);
    }
    return host_slot_link(host, slot), core::IoError.None;
}

// Queries the OS-assigned local TCP port bound to a listening or connected `link`.
fn link_local_port(host: const NetHost&, link: core::IoLink) -> u16 {
    let slot, ok = host_match_link(host, link);
    guard ok && host.links[slot].kind == LinkKind.Tcp && host.links[slot].fd > 0 else { return 0; }
    return tcp_getsockname_port(host.links[slot].fd);
}

// Begins a non-blocking TCP or Unix outbound connect (satisfies `core::host_connect`).
fn link_connect(
    host:  NetHost&,
    addr:  core::ConnectAddr,
    owner: u16,
    tag:   u64,
) -> core::IoLink, core::ConnectStatus {
    guard host.is_open && core::is_valid_connect_addr(addr) && owner != 0 else {
        return core::IoLink { .. }, core::ConnectStatus.InvalidArgument;
    }
    let kind = match addr {
        Tcp _ => LinkKind.Tcp,
        Unix _ => LinkKind.Unix,
    };
    let slot = alloc_host_slot(host, owner, tag, kind);
    guard slot >= 0 else { return core::IoLink { .. }, core::ConnectStatus.Failed; }

    var conn_state: i32 = -1;
    let fd = match addr {
        Tcp t => tcp_connect_begin(t.host, t.port, conn_state),
        Unix u => tcp_connect_unix_begin(u.path, conn_state),
    };
    guard fd > 0 && conn_state >= 0 else {
        release_host_slot(host, slot);
        return core::IoLink { .. }, core::ConnectStatus.Failed;
    }
    host.links[slot].fd = fd;
    host.links[slot].state = if conn_state == 0 { LinkSlotState.Open } else { LinkSlotState.Connecting };
    sync_slot_interest(host, slot);
    let link = host_slot_link(host, slot);
    let st = if conn_state == 0 { core::ConnectStatus.Connected } else { core::ConnectStatus.InProgress };
    return link, st;
}

// Opens an in-memory bidirectional virtual link pair hosted on `host` for deterministic tests.
fn host_open_virtual_pair(
    host:    NetHost&,
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

    let slot_a = alloc_host_slot(host, owner_a, tag_a, LinkKind.Virtual);
    if slot_a < 0 {
        free_virtual_pipe_slot(pipe_slot);
        return core::IoLink { .. }, core::IoLink { .. }, false;
    }
    let slot_b = alloc_host_slot(host, owner_b, tag_b, LinkKind.Virtual);
    if slot_b < 0 {
        free_virtual_pipe_slot(pipe_slot);
        release_host_slot(host, slot_a);
        return core::IoLink { .. }, core::IoLink { .. }, false;
    }
    host.links[slot_a].virtual_pair = pipe_slot;
    host.links[slot_a].is_b_end = false;
    host.links[slot_a].state = LinkSlotState.Open;
    host.links[slot_b].virtual_pair = pipe_slot;
    host.links[slot_b].is_b_end = true;
    host.links[slot_b].state = LinkSlotState.Open;
    return host_slot_link(host, slot_a), host_slot_link(host, slot_b), true;
}

inline fn send_accel_slab_tx(host: NetHost&, slot: i64, data: const u8[:]) -> i32, core::IoError {
    if host.links[slot].tx_inflight {
        host.links[slot].want_write = true;
        return 0, core::IoError.WouldBlock;
    }
    let chunk_len = min(data.len, NET_HOST_ACCEL_CHUNK);
    let tx_off_u32 = host_rio_tx_offset(slot);
    let tx_off = tx_off_u32 as i64;
    let tx_end = core::add_sat_i64(tx_off, chunk_len);
    guard tx_end <= host.accel_slab.len else { return 0, core::IoError.BufferFull; }
    for i in chunk_len {
        host.accel_slab[core::add_sat_i64(tx_off, i)] = data[i];
    }
    if host.links[slot].is_rio && host.links[slot].rio_rq != 0 {
        let rc = net_internal::native_rio_post_send(
            host.links[slot].rio_rq, host.rio_buf_id, tx_off_u32, chunk_len as u32, HOST_RIO_REQ_TX,
        );
        guard rc == 0 else { return 0, core::IoError.Closed; }
    } else {
        var sqe = net_internal::UringSqe { .. };
        let tx_tag = host_uring_tag(HOST_URING_OP_SEND, host.links[slot].gen, slot);
        net_internal::uring_prep_send_slice(sqe, host.links[slot].fd as i32, host.accel_slab[tx_off..tx_end], tx_tag);
        var b: net_internal::UringSqe[1] = [sqe];
        guard net_internal::uring_submit_sqes(host.uring_fd, b[..]) > 0 else { return 0, core::IoError.Closed; }
    }
    host.links[slot].tx_inflight = true;
    if chunk_len < data.len {
        host.links[slot].want_write = true;
        return chunk_len as i32, core::IoError.ShortWrite;
    }
    return chunk_len as i32, core::IoError.None;
}

// Writes wire bytes to `link` (satisfies `core::host_send`).
fn link_send(host: NetHost&, link: core::IoLink, data: const u8[:]) -> i32, core::IoError {
    let slot, ok = host_match_link(host, link);
    guard ok && data.len > 0 else { return 0, core::IoError.InvalidArgument; }
    guard host.links[slot].state == LinkSlotState.Open && !host.links[slot].write_shut else {
        return 0, core::IoError.Closed;
    }
    if host.links[slot].kind == LinkKind.Virtual {
        let rc = virtual_pipe_send(host.links[slot].virtual_pair as u16, host.links[slot].is_b_end, data);
        let n, err = core::translate_send_result(rc, data.len);
        if err == core::IoError.WouldBlock || err == core::IoError.ShortWrite {
            host.links[slot].want_write = true;
        }
        return n, err;
    }
    let can_accel_tx = slot < NET_HOST_ACCEL_SLOTS && (host.links[slot].is_rio || host.uring_fd >= 0);
    if can_accel_tx {
        return send_accel_slab_tx(host, slot, data);
    }
    let rc = tcp_send(host.links[slot].fd, data);
    let n, err = core::translate_send_result(rc, data.len);
    if err == core::IoError.WouldBlock || err == core::IoError.ShortWrite {
        host.links[slot].want_write = true;
        sync_slot_interest(host, slot);
    }
    return n, err;
}

// Pauses or resumes incoming byte delivery for backpressure (satisfies `core::host_set_rx_paused`).
fn link_set_rx_paused(host: NetHost&, link: core::IoLink, paused: bool) -> bool {
    let slot, ok = host_match_link(host, link);
    guard ok else { return false; }
    host.links[slot].rx_paused = paused;
    if host.links[slot].is_rio && !paused && host.links[slot].state == LinkSlotState.Open {
        let _ = post_rio_slot_recv(host, slot);
    } else {
        sync_slot_interest(host, slot);
    }
    return true;
}

// Half-closes the write direction of `link` (satisfies `core::host_shutdown_write`).
fn link_shutdown_write(host: NetHost&, link: core::IoLink) -> bool {
    let slot, ok = host_match_link(host, link);
    guard ok && host.links[slot].state == LinkSlotState.Open else { return false; }
    host.links[slot].write_shut = true;
    if host.links[slot].kind == LinkKind.Virtual {
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
fn link_close(host: NetHost&, link: core::IoLink) -> bool {
    let slot, ok = host_match_link(host, link);
    guard ok else { return false; }
    release_host_slot(host, slot);
    return true;
}

// Aborts `link` immediately via SO_LINGER(1, 0) RST on TCP sockets and releases its slot.
fn link_abort(host: NetHost&, link: core::IoLink) -> bool {
    let slot, ok = host_match_link(host, link);
    guard ok else { return false; }
    if host.links[slot].kind == LinkKind.Tcp && host.links[slot].fd > 0 {
        let _ = tcp_set_linger(host.links[slot].fd, true, 0);
    }
    release_host_slot(host, slot);
    return true;
}

// Schedules a timer routed to `owner` (satisfies `core::host_add_timer`).
fn link_add_timer(
    host:     NetHost&,
    timer_id: u64,
    delay_ms: u64,
    owner:    u16,
    tag:      u64,
    periodic: bool,
    now_ns:   u64,
) -> bool {
    guard host.is_open && timer_id != 0 && owner != 0 else { return false; }
    let deadline = core::add_sat_u64(now_ns, core::mul_sat_u64(delay_ms, NET_HOST_NANOS_MS));
    let interval = if periodic { core::mul_sat_u64(delay_ms, NET_HOST_NANOS_MS) } else { 0 };
    for i in NET_HOST_MAX_TIMERS {
        if host.timers[i].active && host.timers[i].timer_id == timer_id {
            host.timers[i].tag = tag;
            host.timers[i].owner = owner;
            host.timers[i].deadline_ns = deadline;
            host.timers[i].interval_ns = interval;
            return true;
        }
    }
    for i in NET_HOST_MAX_TIMERS {
        if !host.timers[i].active {
            host.timers[i] = HostTimer {
                timer_id:    timer_id,
                tag:         tag,
                deadline_ns: deadline,
                interval_ns: interval,
                owner:       owner,
                active:      true,
            };
            host.active_timers = core::add_sat_i64(host.active_timers, 1);
            return true;
        }
    }
    return false;
}

// Cancels an active timer by ID (satisfies `core::host_cancel_timer`).
fn link_cancel_timer(host: NetHost&, timer_id: u64) -> bool {
    guard host.is_open && timer_id != 0 else { return false; }
    for i in NET_HOST_MAX_TIMERS {
        if host.timers[i].active && host.timers[i].timer_id == timer_id {
            host.timers[i].active = false;
            host.timers[i].timer_id = 0;
            if host.active_timers > 0 {
                host.active_timers = core::sub_sat_i64(host.active_timers, 1);
            }
            return true;
        }
    }
    return false;
}

// Queues a wakeup token for delivery on the next poll pass (satisfies `core::host_wake`).
fn link_wake(host: NetHost&, token: core::WakeToken) -> bool {
    guard host.is_open && core::wake_token_is_valid(token) else { return false; }
    return host.wake_queue.try_push(token);
}

inline fn is_virtual_slot_ready(host: const NetHost&, slot: i64) -> bool {
    guard host.links[slot].in_use && host.links[slot].kind == LinkKind.Virtual else { return false; }
    let pidx = host.links[slot].virtual_pair;
    guard pidx >= 0 && pidx < MAX_VIRTUAL_PIPES else { return false; }
    var rx_len:   i64 = 0;
    var tx_avail: i64 = 0;
    var peer_shut = false;
    if host.links[slot].is_b_end {
        rx_len = g_virtual_pipes[pidx].a_to_b.count;
        tx_avail = core::available(g_virtual_pipes[pidx].b_to_a);
        peer_shut = g_virtual_pipes[pidx].closed_a;
    } else {
        rx_len = g_virtual_pipes[pidx].b_to_a.count;
        tx_avail = core::available(g_virtual_pipes[pidx].a_to_b);
        peer_shut = g_virtual_pipes[pidx].closed_b;
    }
    if !host.links[slot].rx_paused && (rx_len > 0 || (peer_shut && !host.links[slot].virtual_eof_sent)) {
        return true;
    }
    return host.links[slot].want_write && tx_avail > 0;
}

inline fn has_pending_virtual_work(host: const NetHost&) -> bool {
    for i in NET_HOST_MAX_LINKS {
        if is_virtual_slot_ready(host, i) {
            return true;
        }
    }
    return false;
}

fn clamp_host_timeout(host: const NetHost&, timeout_ms: i64, now_ns: u64) -> i64 {
    if timeout_ms == 0 || host.wake_queue.len > 0 || has_pending_virtual_work(host) {
        return 0;
    }
    guard host.active_timers > 0 else { return timeout_ms; }
    var earliest: u64  = 0xFFFFFFFFFFFFFFFF;
    var found:    bool = false;
    for i in NET_HOST_MAX_TIMERS {
        if host.timers[i].active {
            earliest = min(earliest, host.timers[i].deadline_ns);
            found = true;
        }
    }
    guard found else { return timeout_ms; }
    if now_ns >= earliest {
        return 0;
    }
    let rem_ns = min(core::add_sat_u64(core::sub_sat_u64(earliest, now_ns), 999999), NET_HOST_MAX_TMO_NS);
    let rem_ms = min(core::mulhi_u64(rem_ns, NET_HOST_MULHI_RECIP), 2147483647) as i64;
    return if timeout_ms < 0 { rem_ms } else { min(timeout_ms, rem_ms) };
}

struct UnusedHostArg {}

inline fn dispatch_host_ctx_event<D>(
    driver: D&,
    host:   NetHost&,
    _a:     UnusedHostArg&,
    _b:     UnusedHostArg&,
    ev:     const core::LinkEvent&,
) {
    core::on_link_event(driver, host, ev);
}

inline fn emit_host_event<D, CtxA, CtxB>(
    host:   NetHost&,
    driver: D&,
    arg_a:  CtxA&,
    arg_b:  CtxB&,
    ev:     const core::LinkEvent&,
    count:  i32&,
) {
    driver.dispatch_host_ctx_event(host, arg_a, arg_b, ev);
    count = core::add_sat_i64(count, 1) as i32;
}

fn dispatch_host_wakes<D, CtxA, CtxB>(
    host:   NetHost&,
    driver: D&,
    arg_a:  CtxA&,
    arg_b:  CtxB&,
    count:  i32&,
) {
    let pending = host.wake_queue.len;
    guard pending > 0 else { return; }
    var batch: core::WakeToken[..64] = [];
    for i in pending {
        let _ = batch.try_push(host.wake_queue[i]);
    }
    host.wake_queue.clear();
    for i in batch.len {
        let tok = batch[i];
        let ev = core::LinkEvent {
            kind:  core::LinkEventKind.Wake,
            tag:   tok.slot,
            token: tok,
            ..
        };
        emit_host_event(host, driver, arg_a, arg_b, ev, count);
    }
}

fn dispatch_host_timers<D, CtxA, CtxB>(
    host:   NetHost&,
    driver: D&,
    arg_a:  CtxA&,
    arg_b:  CtxB&,
    now_ns: u64,
    count:  i32&,
) {
    guard host.active_timers > 0 else { return; }
    for i in NET_HOST_MAX_TIMERS {
        guard host.timers[i].active && now_ns >= host.timers[i].deadline_ns else { continue; }
        let tid = host.timers[i].timer_id;
        let tag = host.timers[i].tag;
        let owner = host.timers[i].owner;
        if host.timers[i].interval_ns > 0 {
            host.timers[i].deadline_ns = core::add_sat_u64(now_ns, host.timers[i].interval_ns);
        } else {
            host.timers[i].active = false;
            if host.active_timers > 0 {
                host.active_timers = core::sub_sat_i64(host.active_timers, 1);
            }
        }
        let ev = core::LinkEvent {
            kind:     core::LinkEventKind.Timer,
            link:     core::make_io_link(owner, 1, 0),
            tag:      tag,
            timer_id: tid,
            ..
        };
        emit_host_event(host, driver, arg_a, arg_b, ev, count);
    }
}

fn drain_virtual_slot<D, CtxA, CtxB>(
    host:   NetHost&,
    driver: D&,
    arg_a:  CtxA&,
    arg_b:  CtxB&,
    slot:   i64,
    count:  i32&,
) {
    let gen = host.links[slot].gen;
    let link = host_slot_link(host, slot);
    let pidx = host.links[slot].virtual_pair;
    guard pidx >= 0 && pidx < MAX_VIRTUAL_PIPES else { return; }
    let is_b = host.links[slot].is_b_end;
    if host.links[slot].want_write {
        let tx_avail = if is_b {
            core::available(g_virtual_pipes[pidx].b_to_a)
        } else {
            core::available(g_virtual_pipes[pidx].a_to_b)
        };
        if tx_avail > 0 {
            host.links[slot].want_write = false;
            let ev = core::LinkEvent {
                kind: core::LinkEventKind.Writable, link: link, tag: host.links[slot].tag, ..
            };
            emit_host_event(host, driver, arg_a, arg_b, ev, count);
            guard host.links[slot].in_use && host.links[slot].gen == gen else { return; }
        }
    }
    if !host.links[slot].rx_paused {
        let rc = virtual_pipe_recv(pidx as u16, is_b, host.rx_scratch[..]);
        if rc > 0 {
            let ev = core::LinkEvent {
                kind: core::LinkEventKind.Data,
                link: link,
                tag:  host.links[slot].tag,
                data: host.rx_scratch[..rc],
                ..
            };
            emit_host_event(host, driver, arg_a, arg_b, ev, count);
        } else if rc == 0 && !host.links[slot].virtual_eof_sent {
            host.links[slot].virtual_eof_sent = true;
            let ev = core::LinkEvent {
                kind: core::LinkEventKind.Eof, link: link, tag: host.links[slot].tag, ..
            };
            emit_host_event(host, driver, arg_a, arg_b, ev, count);
        }
    }
}

fn dispatch_virtual_links<D, CtxA, CtxB>(
    host:   NetHost&,
    driver: D&,
    arg_a:  CtxA&,
    arg_b:  CtxB&,
    count:  i32&,
) {
    for i in NET_HOST_MAX_LINKS {
        if host.links[i].in_use && host.links[i].kind == LinkKind.Virtual {
            drain_virtual_slot(host, driver, arg_a, arg_b, i, count);
        }
    }
}

fn handle_accepted_fd<D, CtxA, CtxB>(
    host:   NetHost&,
    driver: D&,
    arg_a:  CtxA&,
    arg_b:  CtxB&,
    l_slot: i64,
    l_gen:  u16,
    cfd:    i64,
    is_rio: bool,
    count:  i32&,
) {
    let owner = host.links[l_slot].owner;
    let tag = host.links[l_slot].tag;
    let kind = host.links[l_slot].kind;
    let c_slot = alloc_host_slot(host, owner, tag, kind);
    guard c_slot >= 0 else {
        tcp_close(cfd);
        return;
    }
    if !is_rio {
        let _ = tcp_set_nonblocking(cfd, true);
    }
    host.links[c_slot].fd = cfd;
    host.links[c_slot].state = LinkSlotState.Open;
    if is_rio && c_slot < NET_HOST_ACCEL_SLOTS && host.rio_cq != 0 {
        let c_link = host_slot_link(host, c_slot);
        let rq = net_internal::native_rio_create_rq_ctx(cfd, 16, 16, host.rio_cq, host.rio_cq, c_link.raw);
        if rq != 0 {
            host.links[c_slot].rio_rq = rq;
            host.links[c_slot].is_rio = true;
            if !post_rio_slot_recv(host, c_slot) {
                release_host_slot(host, c_slot);
                return;
            }
        } else {
            let _ = tcp_set_nonblocking(cfd, true);
            sync_slot_interest(host, c_slot);
        }
    } else {
        sync_slot_interest(host, c_slot);
    }
    let ev = core::LinkEvent {
        kind:     core::LinkEventKind.Accepted,
        link:     host_slot_link(host, c_slot),
        listener: core::make_io_link(owner, l_gen, l_slot as u32),
        tag:      tag,
        ..
    };
    emit_host_event(host, driver, arg_a, arg_b, ev, count);
}

fn accept_ready_listener<D, CtxA, CtxB>(
    host:   NetHost&,
    driver: D&,
    arg_a:  CtxA&,
    arg_b:  CtxB&,
    slot:   i64,
    gen:    u16,
    count:  i32&,
) {
    let lfd = host.links[slot].fd;
    let is_rio = host.links[slot].is_rio;
    for _ in 16 {
        guard host.links[slot].in_use && host.links[slot].gen == gen else { break; }
        let cfd = if is_rio {
            net_internal::native_rio_poll_accept(lfd, 0)
        } else {
            tcp_accept_nonblocking(lfd)
        };
        if cfd <= 0 { break; }
        handle_accepted_fd(host, driver, arg_a, arg_b, slot, gen, cfd, is_rio, count);
    }
}

fn finish_connecting_slot<D, CtxA, CtxB>(
    host:     NetHost&,
    driver:   D&,
    arg_a:    CtxA&,
    arg_b:    CtxB&,
    slot:     i64,
    gen:      u16,
    ev_flags: u32,
    count:    i32&,
) {
    let link = host_slot_link(host, slot);
    let tag = host.links[slot].tag;
    let has_err = (ev_flags & core::POLL_ERROR) != 0;
    if !has_err && tcp_connect_finish(host.links[slot].fd) {
        host.links[slot].state = LinkSlotState.Open;
        sync_slot_interest(host, slot);
        let ev = core::LinkEvent { kind: core::LinkEventKind.Connected, link: link, tag: tag, .. };
        emit_host_event(host, driver, arg_a, arg_b, ev, count);
        return;
    }
    release_host_slot(host, slot);
    let closed_ev = core::LinkEvent {
        kind: core::LinkEventKind.Closed, link: link, tag: tag, err: core::IoError.Closed, ..
    };
    emit_host_event(host, driver, arg_a, arg_b, closed_ev, count);
}

fn step_socket_read<D, CtxA, CtxB>(
    host:   NetHost&,
    driver: D&,
    arg_a:  CtxA&,
    arg_b:  CtxB&,
    slot:   i64,
    gen:    u16,
    count:  i32&,
) -> bool {
    guard host.links[slot].in_use && host.links[slot].gen == gen && !host.links[slot].rx_paused else {
        return false;
    }
    let link = host_slot_link(host, slot);
    let tag = host.links[slot].tag;
    let recvd = tcp_recv_nonblocking_slice(host.links[slot].fd, host.rx_scratch[..]);
    if recvd > 0 {
        let ev = core::LinkEvent {
            kind: core::LinkEventKind.Data,
            link: link,
            tag:  tag,
            data: host.rx_scratch[..recvd],
            ..
        };
        emit_host_event(host, driver, arg_a, arg_b, ev, count);
        return recvd >= NET_HOST_RX_CAP;
    }
    if recvd == 0 {
        host.links[slot].eof_received = true;
        sync_slot_interest(host, slot);
        let ev = core::LinkEvent { kind: core::LinkEventKind.Eof, link: link, tag: tag, .. };
        emit_host_event(host, driver, arg_a, arg_b, ev, count);
        return false;
    }
    if recvd == -2 { return false; }
    release_host_slot(host, slot);
    let closed_ev = core::LinkEvent {
        kind: core::LinkEventKind.Closed, link: link, tag: tag, err: core::IoError.Closed, ..
    };
    emit_host_event(host, driver, arg_a, arg_b, closed_ev, count);
    return false;
}

fn drain_ready_socket_reads<D, CtxA, CtxB>(
    host:   NetHost&,
    driver: D&,
    arg_a:  CtxA&,
    arg_b:  CtxB&,
    slot:   i64,
    gen:    u16,
    count:  i32&,
) {
    for _ in 4 {
        if !step_socket_read(host, driver, arg_a, arg_b, slot, gen, count) {
            break;
        }
    }
}

fn handle_readiness_slot_event<D, CtxA, CtxB>(
    host:     NetHost&,
    driver:   D&,
    arg_a:    CtxA&,
    arg_b:    CtxB&,
    slot:     i64,
    gen:      u16,
    ev_flags: u32,
    count:    i32&,
) {
    if host.links[slot].state == LinkSlotState.Listening {
        accept_ready_listener(host, driver, arg_a, arg_b, slot, gen, count);
        return;
    }
    if host.links[slot].state == LinkSlotState.Connecting {
        finish_connecting_slot(host, driver, arg_a, arg_b, slot, gen, ev_flags, count);
        return;
    }
    guard host.links[slot].state == LinkSlotState.Open else { return; }
    let link = host_slot_link(host, slot);
    let tag = host.links[slot].tag;
    if (ev_flags & core::POLL_WRITE) != 0 && host.links[slot].want_write {
        host.links[slot].want_write = false;
        sync_slot_interest(host, slot);
        let ev = core::LinkEvent { kind: core::LinkEventKind.Writable, link: link, tag: tag, .. };
        emit_host_event(host, driver, arg_a, arg_b, ev, count);
        guard host.links[slot].in_use && host.links[slot].gen == gen else { return; }
    }
    if (ev_flags & core::POLL_ERROR) != 0 && (host.links[slot].rx_paused || host.links[slot].eof_received) {
        release_host_slot(host, slot);
        let closed_ev = core::LinkEvent {
            kind: core::LinkEventKind.Closed, link: link, tag: tag, err: core::IoError.Closed, ..
        };
        emit_host_event(host, driver, arg_a, arg_b, closed_ev, count);
        return;
    }
    if (ev_flags & core::POLL_HANGUP) != 0 && host.links[slot].rx_paused && !host.links[slot].eof_received {
        host.links[slot].eof_received = true;
        sync_slot_interest(host, slot);
        let ev = core::LinkEvent { kind: core::LinkEventKind.Eof, link: link, tag: tag, .. };
        emit_host_event(host, driver, arg_a, arg_b, ev, count);
        return;
    }
    if (ev_flags & (core::POLL_READ | core::POLL_HANGUP | core::POLL_ERROR)) != 0 &&
       !host.links[slot].rx_paused && !host.links[slot].eof_received {
        drain_ready_socket_reads(host, driver, arg_a, arg_b, slot, gen, count);
    }
}

fn poll_epoll_backend<D, CtxA, CtxB>(
    host:       NetHost&,
    driver:     D&,
    arg_a:      CtxA&,
    arg_b:      CtxB&,
    timeout_ms: i64,
    count:      i32&,
) {
    guard host.epfd >= 0 && host.epfd_count > 0 else { return; }
    var raw_fds:    i64[64] = [0; 64];
    var raw_udata:  u64[64] = [0; 64];
    var raw_events: u32[64] = [0; 64];
    let t_clamped = min(max(timeout_ms, -1), 2147483647) as i32;
    let n = epoll_wait_events_direct(host.epfd, raw_fds[..], raw_udata[..], raw_events[..], t_clamped);
    guard n > 0 else { return; }
    let limit = min(n as i64, 64);
    for k in limit {
        let link = core::IoLink { raw: raw_udata[k] };
        let slot, ok = host_match_link(host, link);
        guard ok else { continue; }
        handle_readiness_slot_event(host, driver, arg_a, arg_b, slot, core::io_link_gen(link), raw_events[k], count);
    }
}

fn dispatch_single_kevent<D, CtxA, CtxB>(
    host:   NetHost&,
    driver: D&,
    arg_a:  CtxA&,
    arg_b:  CtxB&,
    kev:    const net_internal::Kevent&,
    count:  i32&,
) {
    guard (kev.flags & HOST_KQ_EV_ERROR) == 0 else { return; }
    let link = core::IoLink { raw: kev.udata };
    let slot, ok = host_match_link(host, link);
    guard ok else { return; }
    var flags: u32 = core::POLL_NONE;
    if kev.filter == net_internal::EVFILT_READ { flags |= core::POLL_READ; }
    if kev.filter == net_internal::EVFILT_WRITE { flags |= core::POLL_WRITE; }
    if (kev.flags & net_internal::EV_EOF) != 0 {
        flags |= core::POLL_HANGUP;
        if kev.fflags != 0 { flags |= core::POLL_ERROR; }
    }
    handle_readiness_slot_event(host, driver, arg_a, arg_b, slot, core::io_link_gen(link), flags, count);
}

fn poll_kqueue_backend<D, CtxA, CtxB>(
    host:       NetHost&,
    driver:     D&,
    arg_a:      CtxA&,
    arg_b:      CtxB&,
    timeout_ms: i64,
    count:      i32&,
) {
    guard host.kq_fd >= 0 else { return; }
    var kev_out: net_internal::Kevent[64] = [net_internal::Kevent { .. }; 64];
    let t_ns = net_internal::timeout_ms_to_ns(timeout_ms);
    let n = net_internal::kqueue_poll_slice(host.kq_fd, host.kq_changes[..], kev_out[..], t_ns);
    host.kq_changes.clear();
    guard n > 0 else { return; }
    let limit = min(n as i64, 64);
    for k in limit {
        dispatch_single_kevent(host, driver, arg_a, arg_b, kev_out[k], count);
    }
}

fn dispatch_single_rio_result<D, CtxA, CtxB>(
    host:   NetHost&,
    driver: D&,
    arg_a:  CtxA&,
    arg_b:  CtxB&,
    res:    const net_internal::RioResult&,
    count:  i32&,
) {
    let link = core::IoLink { raw: res.socket_context };
    let slot, ok = host_match_link(host, link);
    guard ok else { return; }
    let tag = host.links[slot].tag;
    if res.request_context == HOST_RIO_REQ_TX {
        host.links[slot].tx_inflight = false;
        if res.status != 0 {
            release_host_slot(host, slot);
            let ev = core::LinkEvent {
                kind: core::LinkEventKind.Closed, link: link, tag: tag, err: core::IoError.Closed, ..
            };
            emit_host_event(host, driver, arg_a, arg_b, ev, count);
            return;
        }
        if host.links[slot].want_write {
            host.links[slot].want_write = false;
            let ev = core::LinkEvent { kind: core::LinkEventKind.Writable, link: link, tag: tag, .. };
            emit_host_event(host, driver, arg_a, arg_b, ev, count);
        }
        return;
    }
    if res.status != 0 {
        release_host_slot(host, slot);
        let ev = core::LinkEvent {
            kind: core::LinkEventKind.Closed, link: link, tag: tag, err: core::IoError.Closed, ..
        };
        emit_host_event(host, driver, arg_a, arg_b, ev, count);
        return;
    }
    if res.bytes_transferred == 0 {
        host.links[slot].eof_received = true;
        let ev = core::LinkEvent { kind: core::LinkEventKind.Eof, link: link, tag: tag, .. };
        emit_host_event(host, driver, arg_a, arg_b, ev, count);
        return;
    }
    let rx_off = host_rio_rx_offset(slot) as i64;
    let rx_len = min(res.bytes_transferred as i64, NET_HOST_ACCEL_CHUNK);
    let rx_end = core::add_sat_i64(rx_off, rx_len);
    let gen = host.links[slot].gen;
    if rx_end <= host.accel_slab.len {
        let ev = core::LinkEvent {
            kind: core::LinkEventKind.Data, link: link, tag: tag, data: host.accel_slab[rx_off..rx_end], ..
        };
        emit_host_event(host, driver, arg_a, arg_b, ev, count);
    }
    if host.links[slot].in_use && host.links[slot].gen == gen && !host.links[slot].rx_paused {
        let _ = post_rio_slot_recv(host, slot);
    }
}

fn poll_rio_backend<D, CtxA, CtxB>(
    host:       NetHost&,
    driver:     D&,
    arg_a:      CtxA&,
    arg_b:      CtxB&,
    timeout_ms: i64,
    count:      i32&,
) {
    guard host.rio_cq != 0 else { return; }
    for i in NET_HOST_MAX_LINKS {
        if host.links[i].in_use && host.links[i].is_rio && host.links[i].state == LinkSlotState.Listening {
            accept_ready_listener(host, driver, arg_a, arg_b, i, host.links[i].gen, count);
        }
    }
    var rio_results: net_internal::RioResult[..64] = [];
    var n = net_internal::rio_drain_completions(host.rio_cq, rio_results);
    if n == 0 && timeout_ms > 0 && host.epfd_count == 0 {
        let _ = net_internal::rio_wait_cq(host.rio_cq, min(timeout_ms, 5) as i32);
        n = net_internal::rio_drain_completions(host.rio_cq, rio_results);
    }
    for k in rio_results.len {
        dispatch_single_rio_result(host, driver, arg_a, arg_b, rio_results[k], count);
    }
}

fn dispatch_uring_send_cqe<D, CtxA, CtxB>(
    host:   NetHost&,
    driver: D&,
    arg_a:  CtxA&,
    arg_b:  CtxB&,
    slot:   i64,
    cqe:    const net_internal::UringCqe&,
    count:  i32&,
) {
    guard (cqe.flags & net_internal::URING_CQE_F_NOTIF) == 0 else { return; }
    let link = host_slot_link(host, slot);
    let tag = host.links[slot].tag;
    host.links[slot].tx_inflight = false;
    if cqe.res <= 0 {
        release_host_slot(host, slot);
        let closed_ev = core::LinkEvent {
            kind: core::LinkEventKind.Closed, link: link, tag: tag, err: core::IoError.Closed, ..
        };
        emit_host_event(host, driver, arg_a, arg_b, closed_ev, count);
        return;
    }
    if host.links[slot].want_write {
        host.links[slot].want_write = false;
        let ev = core::LinkEvent { kind: core::LinkEventKind.Writable, link: link, tag: tag, .. };
        emit_host_event(host, driver, arg_a, arg_b, ev, count);
    }
}

fn dispatch_uring_recv_cqe<D, CtxA, CtxB>(
    host:    NetHost&,
    driver:  D&,
    arg_a:   CtxA&,
    arg_b:   CtxB&,
    slot:    i64,
    gen:     u16,
    cqe:     const net_internal::UringCqe&,
    has_buf: bool,
    bid:     u16,
    count:   i32&,
) {
    let link = host_slot_link(host, slot);
    let tag = host.links[slot].tag;
    if cqe.res == 0 {
        if has_buf { net_internal::uring_recycle_pbuf(host.uring_pbuf, bid); }
        host.links[slot].eof_received = true;
        host.links[slot].epoll_mask &= ~EPOLL_READ;
        let ev = core::LinkEvent { kind: core::LinkEventKind.Eof, link: link, tag: tag, .. };
        emit_host_event(host, driver, arg_a, arg_b, ev, count);
        return;
    }
    if cqe.res < 0 {
        if has_buf { net_internal::uring_recycle_pbuf(host.uring_pbuf, bid); }
        release_host_slot(host, slot);
        let closed_ev = core::LinkEvent {
            kind: core::LinkEventKind.Closed, link: link, tag: tag, err: core::IoError.Closed, ..
        };
        emit_host_event(host, driver, arg_a, arg_b, closed_ev, count);
        return;
    }
    var copied: i32 = 0;
    if has_buf {
        copied = net_internal::uring_read_pbuf(host.uring_pbuf, bid, cqe.res, host.rx_scratch[..]);
        net_internal::uring_recycle_pbuf(host.uring_pbuf, bid);
    }
    if copied > 0 {
        let ev = core::LinkEvent {
            kind: core::LinkEventKind.Data, link: link, tag: tag, data: host.rx_scratch[..copied], ..
        };
        emit_host_event(host, driver, arg_a, arg_b, ev, count);
    }
    if (cqe.flags & net_internal::URING_CQE_F_MORE) == 0 &&
        host.links[slot].in_use &&
        host.links[slot].gen == gen &&
        !host.links[slot].rx_paused &&
        !host.links[slot].eof_received {
        host.links[slot].epoll_mask &= ~EPOLL_READ;
        sync_slot_interest(host, slot);
    }
}

fn dispatch_uring_accept_cqe<D, CtxA, CtxB>(
    host:   NetHost&,
    driver: D&,
    arg_a:  CtxA&,
    arg_b:  CtxB&,
    slot:   i64,
    gen:    u16,
    cqe:    const net_internal::UringCqe&,
    count:  i32&,
) {
    if cqe.res > 0 {
        handle_accepted_fd(host, driver, arg_a, arg_b, slot, gen, cqe.res as i64, false, count);
    }
    if (cqe.flags & net_internal::URING_CQE_F_MORE) == 0 && host.links[slot].in_use && host.links[slot].gen == gen {
        host.links[slot].epoll_mask = 0;
        sync_slot_interest(host, slot);
    }
}

fn dispatch_uring_cqe<D, CtxA, CtxB>(
    host:   NetHost&,
    driver: D&,
    arg_a:  CtxA&,
    arg_b:  CtxB&,
    cqe:    const net_internal::UringCqe&,
    count:  i32&,
) {
    let has_buf = (cqe.flags & net_internal::URING_CQE_F_BUFFER) != 0;
    let bid = ((cqe.flags >> 16) & 0xFFFF) as u16;
    let op, slot, ok = host_match_uring_tag(host, cqe.user_data);
    guard ok else {
        if has_buf { net_internal::uring_recycle_pbuf(host.uring_pbuf, bid); }
        return;
    }
    if op == HOST_URING_OP_RECV {
        dispatch_uring_recv_cqe(host, driver, arg_a, arg_b, slot, host.links[slot].gen, cqe, has_buf, bid, count);
        return;
    }
    if has_buf { net_internal::uring_recycle_pbuf(host.uring_pbuf, bid); }
    let gen = host.links[slot].gen;
    if op == HOST_URING_OP_ACCEPT {
        dispatch_uring_accept_cqe(host, driver, arg_a, arg_b, slot, gen, cqe, count);
        return;
    }
    if op == HOST_URING_OP_CONNECT {
        let ev_flags: u32 = if cqe.res < 0 { core::POLL_ERROR } else { core::POLL_WRITE };
        finish_connecting_slot(host, driver, arg_a, arg_b, slot, gen, ev_flags, count);
        return;
    }
    if op == HOST_URING_OP_SEND {
        dispatch_uring_send_cqe(host, driver, arg_a, arg_b, slot, cqe, count);
        return;
    }
    if op == HOST_URING_OP_POLL_W && host.links[slot].want_write {
        host.links[slot].want_write = false;
        host.links[slot].epoll_mask &= ~EPOLL_WRITE;
        let ev = core::LinkEvent {
            kind: core::LinkEventKind.Writable, link: host_slot_link(host, slot), tag: host.links[slot].tag, ..
        };
        emit_host_event(host, driver, arg_a, arg_b, ev, count);
    }
}

fn poll_uring_backend<D, CtxA, CtxB>(
    host:       NetHost&,
    driver:     D&,
    arg_a:      CtxA&,
    arg_b:      CtxB&,
    timeout_ms: i64,
    count:      i32&,
) {
    guard host.uring_fd >= 0 else { return; }
    var cqes: net_internal::UringCqe[64] = [net_internal::UringCqe { .. }; 64];
    let min_c: u32 = if timeout_ms == 0 { 0 } else { 1 };
    let t_ns = net_internal::timeout_ms_to_ns(timeout_ms);
    let n = net_internal::uring_wait_cqes(host.uring_fd, cqes[..], min_c, t_ns);
    guard n > 0 else { return; }
    let limit = min(n as i64, 64);
    for k in limit {
        dispatch_uring_cqe(host, driver, arg_a, arg_b, cqes[k], count);
    }
}

fn link_poll_dispatch_ctx<D, CtxA, CtxB>(
    host:       NetHost&,
    driver:     D&,
    arg_a:      CtxA&,
    arg_b:      CtxB&,
    timeout_ms: i64,
    now_ns:     u64,
) -> i32 {
    guard host.is_open else { return 0; }
    var count: i32 = 0;
    let eff_timeout = clamp_host_timeout(host, timeout_ms, now_ns);

    if host.uring_fd >= 0 {
        poll_uring_backend(host, driver, arg_a, arg_b, eff_timeout, count);
    } else if host.kq_fd >= 0 {
        poll_kqueue_backend(host, driver, arg_a, arg_b, eff_timeout, count);
    } else {
        if host.rio_cq != 0 {
            let rio_tmo = if host.epfd_count > 0 { 0 } else { eff_timeout };
            poll_rio_backend(host, driver, arg_a, arg_b, rio_tmo, count);
        }
        let ep_tmo = if count > 0 || host.wake_queue.len > 0 { 0 } else { eff_timeout };
        poll_epoll_backend(host, driver, arg_a, arg_b, ep_tmo, count);
    }
    dispatch_virtual_links(host, driver, arg_a, arg_b, count);
    dispatch_host_timers(host, driver, arg_a, arg_b, now_ns, count);
    dispatch_host_wakes(host, driver, arg_a, arg_b, count);
    return count;
}

// Polls all active transports, timers, and wakes and pushes events to `driver.on_link_event`
// (satisfies `core::host_step`).
fn link_poll_dispatch<D>(
    host:       NetHost&,
    driver:     D&,
    timeout_ms: i64,
    now_ns:     u64,
) -> i32 {
    var unused_a = UnusedHostArg {};
    var unused_b = UnusedHostArg {};
    return link_poll_dispatch_ctx(host, driver, unused_a, unused_b, timeout_ms, now_ns);
}
