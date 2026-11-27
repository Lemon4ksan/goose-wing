// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Internal backend state, slot management, and polling dispatch helpers for `net::Host`.
namespace net_internal;

import std;
import core;
import net.driver;
import .tcp;
import .transport;
import .internal;
import .io_host;

const NET_HOST_MAX_LINKS:   i64 = 1048576;
const NET_HOST_ACCEL_SLOTS: i64 = 16;
const NET_HOST_ACCEL_CHUNK: i64 = 4096;
const NET_HOST_SLAB_BYTES:  i64 = 131072; // 16 slots * (4KB RX + 4KB TX)
const NET_HOST_MAX_TIMERS:  i64 = 256;
const NET_HOST_MAX_WAKES:   i64 = 512;
const NET_HOST_RX_CAP:      i64 = 16384;
const HOST_EPFD_SHARD_CAP:  i64 = 4096; // Matches shim/tcp.c WING_MAX_POLL_FDS for WSAPoll
const HOST_MAX_EPFD_SHARDS: i64 = 64;
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
    Closing,
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
    next_free:        i32           = -1,
    virt_prev:        i32           = -1,
    virt_next:        i32           = -1,
    virtual_pair:     i32           = -1,
    epoll_mask:       u32           = 0,
    gen:              u16           = 1,
    owner:            u16           = 0,
    epfd_shard:       i16           = -1,
    state:            LinkSlotState = LinkSlotState.Free,
    kind:             LinkKind      = LinkKind.Tcp,
    in_use:           bool          = false,
    in_epfd:          bool          = false,
    is_rio:           bool          = false,
    is_b_end:         bool          = false,
    rx_paused:        bool          = false,
    rx_inflight:      bool          = false,
    rx_armed:         bool          = false,
    rx_canceling:     bool          = false,
    want_write:       bool          = false,
    tx_inflight:      bool          = false,
    tx_notif_pending: bool          = false,
    accept_armed:     bool          = false,
    connect_armed:    bool          = false,
    poll_w_armed:     bool          = false,
    eof_received:     bool          = false,
    write_shut:       bool          = false,
    virtual_eof_sent: bool          = false,
}

struct HostTimer {
    timer_id:    u64  = 0,
    tag:         u64  = 0,
    deadline_ns: u64  = 0,
    interval_ns: u64  = 0,
    next_free:   i32  = -1,
    owner:       u16  = 0,
    active:      bool = false,
}

struct EpfdShard {
    fd:    i64 = -1,
    count: i32 = 0,
}

inline fn ensure_rx_scratch(rx_scratch: u8[>..]&) {
    if rx_scratch.len < NET_HOST_RX_CAP {
        push_n(rx_scratch, 0 as u8, core::sub_sat_i64(NET_HOST_RX_CAP, rx_scratch.len));
    }
}

inline fn next_link_gen(cur: u16) -> u16 {
    return if cur >= 65535 { 1 } else { core::add_sat_u64(cur, 1) as u16 };
}

inline fn host_slot_link(host: const net::Host&, slot: i64) -> core::IoLink {
    return core::make_io_link(host.links[slot].owner, host.links[slot].gen, slot as u32);
}

inline fn host_match_link(host: const net::Host&, link: core::IoLink) -> i64, bool {
    guard host.is_open && core::io_link_is_valid(link) else { return -1, false; }
    let slot = core::io_link_slot(link);
    guard slot >= 0 && slot < host.links.len else { return -1, false; }
    guard host.links[slot].in_use && host.links[slot].gen == core::io_link_gen(link) else {
        return -1, false;
    }
    return slot, true;
}

inline fn host_match_any_link(host: const net::Host&, link: core::IoLink) -> i64, bool, bool {
    guard host.is_open && core::io_link_is_valid(link) else { return -1, false, false; }
    let slot = core::io_link_slot(link);
    guard slot >= 0 && slot < host.links.len else { return -1, false, false; }
    let is_active = host.links[slot].in_use;
    let is_closing = host.links[slot].state == LinkSlotState.Closing;
    guard (is_active || is_closing) && host.links[slot].gen == core::io_link_gen(link) else {
        return -1, false, false;
    }
    return slot, is_closing, true;
}

inline fn host_uring_tag(op: u64, gen: u16, slot: i64) -> u64 {
    let hi = core::shl_sat_u64(op, HOST_URING_OP_SHIFT);
    let mid = core::shl_sat_u64(gen, HOST_URING_GEN_SHIFT);
    return hi | mid | ((slot as u64) & 0xFFFFFFFF);
}

inline fn host_match_uring_tag(host: const net::Host&, user_data: u64) -> u64, i64, bool {
    guard user_data != HOST_URING_CANCEL_TAG else { return 0, -1, false; }
    let op = (user_data >> HOST_URING_OP_SHIFT) & 0xFFFF;
    let gen = ((user_data >> HOST_URING_GEN_SHIFT) & 0xFFFF) as u16;
    let slot = (user_data & 0xFFFFFFFF) as i64;
    guard slot >= 0 && slot < host.links.len else { return 0, -1, false; }
    guard host.links[slot].in_use && host.links[slot].gen == gen && gen != 0 else { return 0, -1, false; }
    return op, slot, true;
}

inline fn host_match_any_uring_tag(host: const net::Host&, user_data: u64) -> u64, i64, bool, bool {
    guard user_data != HOST_URING_CANCEL_TAG else { return 0, -1, false, false; }
    let op = (user_data >> HOST_URING_OP_SHIFT) & 0xFFFF;
    let gen = ((user_data >> HOST_URING_GEN_SHIFT) & 0xFFFF) as u16;
    let slot = (user_data & 0xFFFFFFFF) as i64;
    guard slot >= 0 && slot < host.links.len else { return 0, -1, false, false; }
    let is_active = host.links[slot].in_use;
    let is_closing = host.links[slot].state == LinkSlotState.Closing;
    guard (is_active || is_closing) && host.links[slot].gen == gen && gen != 0 else {
        return 0, -1, false, false;
    }
    return op, slot, is_closing, true;
}

inline fn host_rio_rx_offset(slot: i64) -> u32 {
    return (core::shl_sat_u64(slot as u64, 13)) as u32;
}

inline fn host_rio_tx_offset(slot: i64) -> u32 {
    return ((core::shl_sat_u64(slot as u64, 13)) | 4096) as u32;
}

fn try_init_uring_backend(host: net::Host&, cfg: const TransportDriverConfig&) -> bool {
    let plat = detect_target_platform();
    guard cfg.active_kind == TransportDriverKind.IoUring &&
        plat == TargetPlatform.Linux &&
        host.accel_slab.len >= NET_HOST_SLAB_BYTES else { return false; }
    let rfd = native_uring_create(256, 0);
    guard rfd >= 0 else { return false; }
    let pb, ok_pb = uring_alloc_pbuf_ring(rfd, HOST_URING_PBUF_BGID, 256, 4096);
    if ok_pb && pb != 0 {
        host.uring_fd = rfd;
        host.uring_pbuf = pb;
        host.backend = HostBackendKind.IoUring;
        return true;
    }
    native_uring_close(rfd);
    return false;
}

fn try_init_rio_backend(host: net::Host&, cfg: const TransportDriverConfig&) -> bool {
    let plat = detect_target_platform();
    guard cfg.active_kind == TransportDriverKind.WindowsRIO &&
        plat == TargetPlatform.Windows &&
        host.accel_slab.len >= NET_HOST_SLAB_BYTES &&
        native_rio_available() == 1 else { return false; }
    let cq = native_rio_create_cq(512);
    guard cq != 0 else { return false; }
    let bid = native_rio_register_slice(host.accel_slab[..]);
    if bid != 0 {
        host.rio_cq = cq;
        host.rio_buf_id = bid;
        host.backend = HostBackendKind.WindowsRIO;
        return true;
    }
    native_rio_close_cq(cq);
    return false;
}

fn try_init_kqueue_backend(host: net::Host&, cfg: const TransportDriverConfig&) -> bool {
    let plat = detect_target_platform();
    guard cfg.active_kind == TransportDriverKind.Kqueue &&
        plat == TargetPlatform.Darwin else { return false; }
    let kq = native_kqueue_create();
    guard kq >= 0 else { return false; }
    host.kq_fd = kq;
    host.backend = HostBackendKind.Kqueue;
    return true;
}

fn wants_host_accel_slab(cfg: const TransportDriverConfig&) -> bool {
    let plat = detect_target_platform();
    if cfg.active_kind == TransportDriverKind.IoUring &&
       plat == TargetPlatform.Linux {
        return true;
    }
    return cfg.active_kind == TransportDriverKind.WindowsRIO &&
        plat == TargetPlatform.Windows &&
        native_rio_available() == 1;
}

fn init_host_backend(host: net::Host&, cfg: const TransportDriverConfig&) {
    let efd = net::epoll_create();
    host.epfd = efd;
    if efd >= 0 {
        let _ = host.epfd_shards.try_push(EpfdShard { fd: efd, count: 0 });
    }
    if try_init_uring_backend(host, cfg) { return; }
    if try_init_rio_backend(host, cfg) { return; }
    if try_init_kqueue_backend(host, cfg) { return; }
    host.backend = HostBackendKind.Standard;
}

fn make_host_accel_slab(cfg: const TransportDriverConfig&) -> u8[>..] {
    var slab: u8[>..] = [];
    if wants_host_accel_slab(cfg) {
        push_n(slab, 0 as u8, NET_HOST_SLAB_BYTES);
    }
    return slab;
}

fn alloc_host_slot(host: net::Host&, owner: u16, tag: u64, kind: LinkKind) -> i64 {
    var slot: i64 = -1;
    var gen:  u16 = 1;
    if host.free_link_head >= 0 {
        slot = host.free_link_head;
        host.free_link_head = host.links[slot].next_free;
        gen = host.links[slot].gen;
        if gen == 0 {
            gen = 1;
        }
    } else {
        guard host.links.len < NET_HOST_MAX_LINKS else { return -1; }
        slot = host.links.len;
        host.links.push(IoLinkSlot { .. });
    }
    host.links[slot] = IoLinkSlot {
        tag:    tag,
        gen:    gen,
        owner:  owner,
        kind:   kind,
        in_use: true,
        ..
    };
    host.active_links = core::add_sat_i64(host.active_links, 1);
    return slot;
}

inline fn desired_poll_mask(slot: const IoLinkSlot&) -> u32 {
    if slot.state == LinkSlotState.Connecting {
        return net::EPOLL_WRITE;
    }
    if slot.state == LinkSlotState.Listening {
        return net::EPOLL_READ;
    }
    if slot.state == LinkSlotState.Open {
        var mask: u32 = 0;
        if !slot.rx_paused && !slot.eof_received {
            mask |= net::EPOLL_READ;
        }
        if slot.want_write {
            mask |= net::EPOLL_WRITE;
        }
        return mask;
    }
    return 0;
}

inline fn push_or_flush_kq_change(host: net::Host&, ev: const Kevent&) {
    if !host.kq_changes.try_push(ev) {
        var ign: Kevent[1] = [Kevent { .. }];
        let _ = kqueue_poll_slice(host.kq_fd, host.kq_changes[..], ign[..0], 0);
        host.kq_changes.clear();
        let _ = host.kq_changes.try_push(ev);
    }
}

inline fn queue_kq_diff(
    host:     net::Host&,
    fd:       i64,
    udata:    u64,
    old_mask: u32,
    new_mask: u32,
) {
    let want_r = (new_mask & net::EPOLL_READ) != 0;
    let had_r = (old_mask & net::EPOLL_READ) != 0;
    if want_r != had_r {
        var ev_r = Kevent { .. };
        if want_r {
            kevent_prep_read(ev_r, fd as i32, udata, false);
        } else {
            ev_r = Kevent {
                ident: fd as u64, filter: EVFILT_READ, flags: EV_DELETE, ..
            };
        }
        push_or_flush_kq_change(host, ev_r);
    }
    let want_w = (new_mask & net::EPOLL_WRITE) != 0;
    let had_w = (old_mask & net::EPOLL_WRITE) != 0;
    if want_w != had_w {
        var ev_w = Kevent { .. };
        if want_w {
            kevent_prep_write(ev_w, fd as i32, udata, false);
        } else {
            ev_w = Kevent {
                ident: fd as u64, filter: EVFILT_WRITE, flags: EV_DELETE, ..
            };
        }
        push_or_flush_kq_change(host, ev_w);
    }
}

inline fn cancel_uring_op_tag(uring_fd: i64, op: u64, gen: u16, slot: i64) {
    var sqe = UringSqe { .. };
    uring_prep_cancel(sqe, host_uring_tag(op, gen, slot));
    sqe.user_data = HOST_URING_CANCEL_TAG;
    var b: UringSqe[1] = [sqe];
    let _ = uring_submit_sqes(uring_fd, b[..]);
}

fn sync_uring_slot_interest(host: net::Host&, slot: i64, new_mask: u32) {
    let gen = host.links[slot].gen;
    let fd = host.links[slot].fd as i32;
    let old_mask = host.links[slot].epoll_mask;
    if host.links[slot].state == LinkSlotState.Listening {
        if (old_mask & net::EPOLL_READ) == 0 && !host.links[slot].accept_armed {
            var sqe = UringSqe { .. };
            uring_prep_accept_multishot(sqe, fd, host_uring_tag(HOST_URING_OP_ACCEPT, gen, slot));
            var b: UringSqe[1] = [sqe];
            if uring_submit_sqes(host.uring_fd, b[..]) > 0 {
                host.links[slot].accept_armed = true;
            }
        }
        host.links[slot].epoll_mask = net::EPOLL_READ;
        return;
    }
    if host.links[slot].state == LinkSlotState.Connecting {
        if (old_mask & net::EPOLL_WRITE) == 0 && !host.links[slot].connect_armed {
            var sqe = UringSqe { .. };
            uring_prep_poll_add(sqe, fd, 4, host_uring_tag(HOST_URING_OP_CONNECT, gen, slot));
            var b: UringSqe[1] = [sqe];
            if uring_submit_sqes(host.uring_fd, b[..]) > 0 {
                host.links[slot].connect_armed = true;
            }
        }
        host.links[slot].epoll_mask = net::EPOLL_WRITE;
        return;
    }
    let want_r = (new_mask & net::EPOLL_READ) != 0;
    if want_r && !host.links[slot].rx_armed && !host.links[slot].rx_canceling {
        var sqe = UringSqe { .. };
        uring_prep_sqe_recv_multishot(
            sqe, fd, HOST_URING_PBUF_BGID, host_uring_tag(HOST_URING_OP_RECV, gen, slot),
        );
        var b: UringSqe[1] = [sqe];
        if uring_submit_sqes(host.uring_fd, b[..]) > 0 {
            host.links[slot].rx_armed = true;
        }
    } else if !want_r && host.links[slot].rx_armed && !host.links[slot].rx_canceling {
        cancel_uring_op_tag(host.uring_fd, HOST_URING_OP_RECV, gen, slot);
        host.links[slot].rx_canceling = true;
    }
    let want_w = (new_mask & net::EPOLL_WRITE) != 0;
    if want_w && !host.links[slot].poll_w_armed && !host.links[slot].tx_inflight &&
        !host.links[slot].tx_notif_pending {
        var sqe = UringSqe { .. };
        uring_prep_poll_add(sqe, fd, 4, host_uring_tag(HOST_URING_OP_POLL_W, gen, slot));
        var b: UringSqe[1] = [sqe];
        if uring_submit_sqes(host.uring_fd, b[..]) > 0 {
            host.links[slot].poll_w_armed = true;
        }
    } else if !want_w && host.links[slot].poll_w_armed {
        cancel_uring_op_tag(host.uring_fd, HOST_URING_OP_POLL_W, gen, slot);
    }
    host.links[slot].epoll_mask = new_mask;
}

inline fn host_epoll_shard_cap() -> i64 {
    if detect_target_platform() == TargetPlatform.Linux {
        return NET_HOST_MAX_LINKS;
    }
    return HOST_EPFD_SHARD_CAP;
}

fn select_epoll_shard(host: net::Host&) -> i64 {
    let cap = host_epoll_shard_cap();
    for i in host.epfd_shards.len {
        if host.epfd_shards[i].fd >= 0 && host.epfd_shards[i].count < cap {
            return i;
        }
    }
    guard host.epfd_shards.len < HOST_MAX_EPFD_SHARDS else { return -1; }
    let nfd = net::epoll_create();
    guard nfd >= 0 else { return -1; }
    let idx = host.epfd_shards.len;
    guard host.epfd_shards.try_push(EpfdShard { fd: nfd, count: 0 }) else {
        net::epoll_close(nfd);
        return -1;
    }
    return idx;
}

inline fn remove_slot_from_epoll_shard(host: net::Host&, slot: i64, fd: i64) {
    let sh: i64 = host.links[slot].epfd_shard;
    if sh >= 0 && sh < host.epfd_shards.len && host.epfd_shards[sh].fd >= 0 {
        if fd > 0 {
            let _ = net::epoll_del(host.epfd_shards[sh].fd, fd);
        }
        if host.epfd_shards[sh].count > 0 {
            host.epfd_shards[sh].count = core::sub_sat_i64(host.epfd_shards[sh].count, 1) as i32;
        }
    }
    host.links[slot].in_epfd = false;
    host.links[slot].epfd_shard = -1;
    if host.epfd_count > 0 {
        host.epfd_count = core::sub_sat_i64(host.epfd_count, 1);
    }
}

fn sync_epoll_slot_interest(
    host:     net::Host&,
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
            remove_slot_from_epoll_shard(host, slot, fd);
        }
        host.links[slot].epoll_mask = 0;
        return;
    }
    let udata = host_slot_link(host, slot).raw;
    if !host.links[slot].in_epfd {
        let sh = select_epoll_shard(host);
        guard sh >= 0 else { return; }
        if net::epoll_add(host.epfd_shards[sh].fd, fd, new_mask, udata) {
            host.links[slot].in_epfd = true;
            host.links[slot].epfd_shard = sh as i16;
            host.epfd_shards[sh].count = core::add_sat_i64(host.epfd_shards[sh].count, 1) as i32;
            host.epfd_count = core::add_sat_i64(host.epfd_count, 1);
            host.links[slot].epoll_mask = new_mask;
        }
        return;
    }
    guard old_mask != new_mask else { return; }
    let sh: i64 = host.links[slot].epfd_shard;
    guard sh >= 0 && sh < host.epfd_shards.len else { return; }
    let sfd = host.epfd_shards[sh].fd;
    if !net::epoll_mod(sfd, fd, new_mask, udata) {
        let _ = net::epoll_add(sfd, fd, new_mask, udata);
    }
    host.links[slot].epoll_mask = new_mask;
}

fn sync_slot_interest(host: net::Host&, slot: i64) {
    guard slot >= 0 && slot < host.links.len && host.links[slot].in_use else { return; }
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

inline fn host_slot_has_inflight_ops(s: const IoLinkSlot&) -> bool {
    return s.rx_inflight || s.rx_armed || s.tx_inflight || s.tx_notif_pending ||
        s.accept_armed || s.connect_armed || s.poll_w_armed;
}

inline fn cancel_closing_uring_ops(host: net::Host&, slot: i64) {
    let gen = host.links[slot].gen;
    if host.links[slot].tx_inflight || host.links[slot].tx_notif_pending {
        cancel_uring_op_tag(host.uring_fd, HOST_URING_OP_SEND, gen, slot);
    }
    if host.links[slot].accept_armed {
        cancel_uring_op_tag(host.uring_fd, HOST_URING_OP_ACCEPT, gen, slot);
    }
    if host.links[slot].connect_armed {
        cancel_uring_op_tag(host.uring_fd, HOST_URING_OP_CONNECT, gen, slot);
    }
}

fn release_os_link_resources(host: net::Host&, slot: i64) {
    let fd = host.links[slot].fd;
    if host.uring_fd >= 0 {
        sync_uring_slot_interest(host, slot, 0);
        cancel_closing_uring_ops(host, slot);
    } else if host.kq_fd >= 0 && fd > 0 {
        queue_kq_diff(host, fd, 0, host.links[slot].epoll_mask, 0);
    } else if host.links[slot].in_epfd && !host.links[slot].is_rio {
        remove_slot_from_epoll_shard(host, slot, fd);
    }
    if host.links[slot].is_rio && host.links[slot].state == LinkSlotState.Listening && fd > 0 {
        let _ = native_rio_cancel_accept(fd);
    }
    if fd > 0 {
        net::tcp_close(fd);
        host.links[slot].fd = -1;
    }
}

inline fn virt_link_insert(host: net::Host&, slot: i64) {
    let head = host.virt_head;
    host.links[slot].virt_prev = -1;
    host.links[slot].virt_next = head;
    if head >= 0 && head < host.links.len {
        host.links[head].virt_prev = slot as i32;
    }
    host.virt_head = slot as i32;
}

inline fn virt_link_remove(host: net::Host&, slot: i64) {
    let prev = host.links[slot].virt_prev;
    let next = host.links[slot].virt_next;
    if prev >= 0 && prev < host.links.len {
        host.links[prev].virt_next = next;
    } else if host.virt_head == (slot as i32) {
        host.virt_head = next;
    }
    if next >= 0 && next < host.links.len {
        host.links[next].virt_prev = prev;
    }
    host.links[slot].virt_prev = -1;
    host.links[slot].virt_next = -1;
}

inline fn finalize_host_slot(host: net::Host&, slot: i64) {
    let next_gen = next_link_gen(host.links[slot].gen);
    host.links[slot] = IoLinkSlot {
        next_free: host.free_link_head,
        gen:       next_gen,
        ..
    };
    host.free_link_head = slot as i32;
}

fn finalize_closing_host_slot(host: net::Host&, slot: i64) {
    guard slot >= 0 && slot < host.links.len &&
        host.links[slot].state == LinkSlotState.Closing &&
        !host_slot_has_inflight_ops(host.links[slot]) else {
        return;
    }
    finalize_host_slot(host, slot);
}

fn release_host_slot(host: net::Host&, slot: i64) {
    guard slot >= 0 && slot < host.links.len && host.links[slot].in_use else { return; }
    if host.links[slot].kind == LinkKind.Virtual {
        virt_link_remove(host, slot);
        if host.links[slot].virtual_pair >= 0 {
            net::virtual_pipe_close(host.links[slot].virtual_pair as u16, host.links[slot].is_b_end);
        }
        finalize_host_slot(host, slot);
    } else {
        release_os_link_resources(host, slot);
        let needs_quarantine = (host.uring_fd >= 0 || host.links[slot].is_rio) &&
            host_slot_has_inflight_ops(host.links[slot]);
        if needs_quarantine {
            host.links[slot].in_use = false;
            host.links[slot].state = LinkSlotState.Closing;
        } else {
            finalize_host_slot(host, slot);
        }
    }
    if host.active_links > 0 {
        host.active_links = core::sub_sat_i64(host.active_links, 1);
    }
}

inline fn post_rio_slot_recv(host: net::Host&, slot: i64) -> bool {
    guard slot >= 0 && slot < NET_HOST_ACCEL_SLOTS && host.links[slot].rio_rq != 0 &&
        !host.links[slot].rx_inflight && host.links[slot].state == LinkSlotState.Open else {
        return false;
    }
    let rc = native_rio_post_recv(
        host.links[slot].rio_rq,
        host.rio_buf_id,
        host_rio_rx_offset(slot),
        NET_HOST_ACCEL_CHUNK as u32,
        HOST_RIO_REQ_RX,
    );
    guard rc == 0 else { return false; }
    host.links[slot].rx_inflight = true;
    return true;
}

inline fn send_accel_slab_tx(host: net::Host&, slot: i64, data: const u8[:]) -> i32, core::IoError {
    if host.links[slot].tx_inflight || host.links[slot].tx_notif_pending {
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
        let rc = native_rio_post_send(
            host.links[slot].rio_rq, host.rio_buf_id, tx_off_u32, chunk_len as u32, HOST_RIO_REQ_TX,
        );
        guard rc == 0 else { return 0, core::IoError.Closed; }
    } else {
        var sqe = UringSqe { .. };
        let tx_tag = host_uring_tag(HOST_URING_OP_SEND, host.links[slot].gen, slot);
        uring_prep_send_slice(sqe, host.links[slot].fd as i32, host.accel_slab[tx_off..tx_end], tx_tag);
        var b: UringSqe[1] = [sqe];
        guard uring_submit_sqes(host.uring_fd, b[..]) > 0 else { return 0, core::IoError.Closed; }
    }
    host.links[slot].tx_inflight = true;
    if chunk_len < data.len {
        host.links[slot].want_write = true;
        return chunk_len as i32, core::IoError.ShortWrite;
    }
    return chunk_len as i32, core::IoError.None;
}

inline fn is_virtual_slot_ready(host: const net::Host&, slot: i64) -> bool {
    guard host.links[slot].in_use && host.links[slot].kind == LinkKind.Virtual else { return false; }
    let pidx = host.links[slot].virtual_pair;
    guard pidx >= 0 && pidx < net::MAX_VIRTUAL_PIPES else { return false; }
    var rx_len:   i64 = 0;
    var tx_avail: i64 = 0;
    var peer_shut = false;
    var peer_rst = false;
    if host.links[slot].is_b_end {
        rx_len = net::g_virtual_pipes[pidx].a_to_b.count;
        tx_avail = core::available(net::g_virtual_pipes[pidx].b_to_a);
        peer_shut = net::g_virtual_pipes[pidx].closed_a;
        peer_rst = net::g_virtual_pipes[pidx].rst_a;
    } else {
        rx_len = net::g_virtual_pipes[pidx].b_to_a.count;
        tx_avail = core::available(net::g_virtual_pipes[pidx].a_to_b);
        peer_shut = net::g_virtual_pipes[pidx].closed_b;
        peer_rst = net::g_virtual_pipes[pidx].rst_b;
    }
    if !host.links[slot].rx_paused && (rx_len > 0 || peer_rst || (peer_shut && !host.links[slot].virtual_eof_sent)) {
        return true;
    }
    return host.links[slot].want_write && tx_avail > 0;
}

inline fn has_pending_virtual_work(host: const net::Host&) -> bool {
    var cur: i64 = host.virt_head;
    while cur >= 0 && cur < host.links.len {
        if is_virtual_slot_ready(host, cur) {
            return true;
        }
        cur = host.links[cur].virt_next;
    }
    return false;
}

fn clamp_host_timeout(host: const net::Host&, timeout_ms: i64, now_ns: u64) -> i64 {
    if timeout_ms == 0 || host.wake_queue.len > 0 || has_pending_virtual_work(host) {
        return 0;
    }
    guard host.active_timers > 0 else { return timeout_ms; }
    var earliest: u64  = 0xFFFFFFFFFFFFFFFF;
    var found:    bool = false;
    for i in host.timers.len {
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
