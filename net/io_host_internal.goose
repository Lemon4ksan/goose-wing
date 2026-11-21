// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Internal backend state, slot management, and polling dispatch helpers for `net::Host`.
namespace net_internal;

import std;
import core from "..";
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

inline fn sync_uring_slot_interest(host: net::Host&, slot: i64, new_mask: u32) {
    let gen = host.links[slot].gen;
    let fd = host.links[slot].fd as i32;
    let old_mask = host.links[slot].epoll_mask;
    if host.links[slot].state == LinkSlotState.Listening {
        if (old_mask & net::EPOLL_READ) == 0 {
            var sqe = UringSqe { .. };
            uring_prep_accept_multishot(sqe, fd, host_uring_tag(HOST_URING_OP_ACCEPT, gen, slot));
            var b: UringSqe[1] = [sqe];
            let _ = uring_submit_sqes(host.uring_fd, b[..]);
        }
        host.links[slot].epoll_mask = net::EPOLL_READ;
        return;
    }
    if host.links[slot].state == LinkSlotState.Connecting {
        if (old_mask & net::EPOLL_WRITE) == 0 {
            var sqe = UringSqe { .. };
            uring_prep_poll_add(sqe, fd, 4, host_uring_tag(HOST_URING_OP_CONNECT, gen, slot));
            var b: UringSqe[1] = [sqe];
            let _ = uring_submit_sqes(host.uring_fd, b[..]);
        }
        host.links[slot].epoll_mask = net::EPOLL_WRITE;
        return;
    }
    let want_r = (new_mask & net::EPOLL_READ) != 0;
    let had_r = (old_mask & net::EPOLL_READ) != 0;
    if want_r && !had_r {
        var sqe = UringSqe { .. };
        uring_prep_sqe_recv_multishot(
            sqe, fd, HOST_URING_PBUF_BGID, host_uring_tag(HOST_URING_OP_RECV, gen, slot),
        );
        var b: UringSqe[1] = [sqe];
        let _ = uring_submit_sqes(host.uring_fd, b[..]);
    } else if !want_r && had_r {
        var sqe = UringSqe { .. };
        uring_prep_cancel(sqe, host_uring_tag(HOST_URING_OP_RECV, gen, slot));
        sqe.user_data = HOST_URING_CANCEL_TAG;
        var b: UringSqe[1] = [sqe];
        let _ = uring_submit_sqes(host.uring_fd, b[..]);
    }
    let want_w = (new_mask & net::EPOLL_WRITE) != 0;
    let had_w = (old_mask & net::EPOLL_WRITE) != 0;
    if want_w && !had_w && !host.links[slot].tx_inflight {
        var sqe = UringSqe { .. };
        uring_prep_poll_add(sqe, fd, 4, host_uring_tag(HOST_URING_OP_POLL_W, gen, slot));
        var b: UringSqe[1] = [sqe];
        let _ = uring_submit_sqes(host.uring_fd, b[..]);
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

inline fn sync_epoll_slot_interest(
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

fn release_os_link_resources(host: net::Host&, slot: i64) {
    let fd = host.links[slot].fd;
    if host.uring_fd >= 0 {
        sync_uring_slot_interest(host, slot, 0);
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

fn release_host_slot(host: net::Host&, slot: i64) {
    guard slot >= 0 && slot < host.links.len && host.links[slot].in_use else { return; }
    if host.links[slot].kind == LinkKind.Virtual {
        virt_link_remove(host, slot);
        if host.links[slot].virtual_pair >= 0 {
            net::virtual_pipe_close(host.links[slot].virtual_pair as u16, host.links[slot].is_b_end);
        }
    } else {
        release_os_link_resources(host, slot);
    }
    let next_gen = next_link_gen(host.links[slot].gen);
    host.links[slot] = IoLinkSlot {
        next_free: host.free_link_head,
        gen:       next_gen,
        ..
    };
    host.free_link_head = slot as i32;
    if host.active_links > 0 {
        host.active_links = core::sub_sat_i64(host.active_links, 1);
    }
}

inline fn post_rio_slot_recv(host: net::Host&, slot: i64) -> bool {
    guard slot >= 0 && slot < NET_HOST_ACCEL_SLOTS && host.links[slot].rio_rq != 0 else { return false; }
    return native_rio_post_recv(
        host.links[slot].rio_rq,
        host.rio_buf_id,
        host_rio_rx_offset(slot),
        NET_HOST_ACCEL_CHUNK as u32,
        HOST_RIO_REQ_RX,
    ) == 0;
}

inline fn send_accel_slab_tx(host: net::Host&, slot: i64, data: const u8[:]) -> i32, core::IoError {
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
    if host.links[slot].is_b_end {
        rx_len = net::g_virtual_pipes[pidx].a_to_b.count;
        tx_avail = core::available(net::g_virtual_pipes[pidx].b_to_a);
        peer_shut = net::g_virtual_pipes[pidx].closed_a;
    } else {
        rx_len = net::g_virtual_pipes[pidx].b_to_a.count;
        tx_avail = core::available(net::g_virtual_pipes[pidx].a_to_b);
        peer_shut = net::g_virtual_pipes[pidx].closed_b;
    }
    if !host.links[slot].rx_paused && (rx_len > 0 || (peer_shut && !host.links[slot].virtual_eof_sent)) {
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

struct UnusedHostArg {}

inline fn dispatch_host_ctx_event<D>(
    driver: D&,
    host:   net::Host&,
    _a:     UnusedHostArg&,
    _b:     UnusedHostArg&,
    ev:     const core::LinkEvent&,
) {
    core::on_link_event(driver, host, ev);
}

inline fn emit_host_event<D, CtxA, CtxB>(
    host:   net::Host&,
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
    host:   net::Host&,
    driver: D&,
    arg_a:  CtxA&,
    arg_b:  CtxB&,
    count:  i32&,
) {
    let pending = host.wake_queue.len;
    guard pending > 0 else { return; }
    for i in pending {
        guard host.is_open && i < host.wake_queue.len else { break; }
        let tok = host.wake_queue[i];
        let ev = core::LinkEvent {
            kind:  core::LinkEventKind.Wake,
            tag:   tok.slot,
            token: tok,
            ..
        };
        emit_host_event(host, driver, arg_a, arg_b, ev, count);
    }
    guard host.is_open else { return; }
    if host.wake_queue.len <= pending {
        host.wake_queue.clear();
        return;
    }
    let rem = core::sub_sat_i64(host.wake_queue.len, pending);
    for j in rem {
        host.wake_queue[j] = host.wake_queue[core::add_sat_i64(pending, j)];
    }
    host.wake_queue.resize(rem);
}

fn dispatch_host_timers<D, CtxA, CtxB>(
    host:   net::Host&,
    driver: D&,
    arg_a:  CtxA&,
    arg_b:  CtxB&,
    now_ns: u64,
    count:  i32&,
) {
    guard host.active_timers > 0 else { return; }
    let n_timers = host.timers.len;
    for i in n_timers {
        guard host.is_open && i < host.timers.len else { break; }
        guard host.timers[i].active && now_ns >= host.timers[i].deadline_ns else { continue; }
        let tid = host.timers[i].timer_id;
        let tag = host.timers[i].tag;
        let owner = host.timers[i].owner;
        if host.timers[i].interval_ns > 0 {
            host.timers[i].deadline_ns = core::add_sat_u64(now_ns, host.timers[i].interval_ns);
        } else {
            host.timers[i].active = false;
            host.timers[i].timer_id = 0;
            host.timers[i].next_free = host.free_timer_head;
            host.free_timer_head = i as i32;
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
    host:       net::Host&,
    driver:     D&,
    arg_a:      CtxA&,
    arg_b:      CtxB&,
    rx_scratch: u8[>..]&,
    slot:       i64,
    count:      i32&,
) {
    let gen = host.links[slot].gen;
    let link = host_slot_link(host, slot);
    let pidx = host.links[slot].virtual_pair;
    guard pidx >= 0 && pidx < net::MAX_VIRTUAL_PIPES else { return; }
    let is_b = host.links[slot].is_b_end;
    if host.links[slot].want_write {
        let tx_avail = if is_b {
            core::available(net::g_virtual_pipes[pidx].b_to_a)
        } else {
            core::available(net::g_virtual_pipes[pidx].a_to_b)
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
        ensure_rx_scratch(rx_scratch);
        let rc = net::virtual_pipe_recv(pidx as u16, is_b, rx_scratch[..]);
        if rc > 0 {
            let ev = core::LinkEvent {
                kind: core::LinkEventKind.Data,
                link: link,
                tag:  host.links[slot].tag,
                data: rx_scratch[..rc],
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
    host:       net::Host&,
    driver:     D&,
    arg_a:      CtxA&,
    arg_b:      CtxB&,
    rx_scratch: u8[>..]&,
    count:      i32&,
) {
    guard host.virt_head >= 0 else { return; }
    var batch: i32[>..] = [];
    var cur:   i64      = host.virt_head;
    while cur >= 0 && cur < host.links.len {
        batch.push(cur as i32);
        cur = host.links[cur].virt_next;
    }
    for i in batch.len {
        let slot: i64 = batch[i];
        guard host.is_open else { break; }
        if slot >= 0 && slot < host.links.len &&
           host.links[slot].in_use && host.links[slot].kind == LinkKind.Virtual {
            drain_virtual_slot(host, driver, arg_a, arg_b, rx_scratch, slot, count);
        }
    }
}

fn handle_accepted_fd<D, CtxA, CtxB>(
    host:   net::Host&,
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
        net::tcp_close(cfd);
        return;
    }
    if !is_rio {
        let _ = net::tcp_set_nonblocking(cfd, true);
    }
    host.links[c_slot].fd = cfd;
    host.links[c_slot].state = LinkSlotState.Open;
    if is_rio && c_slot < NET_HOST_ACCEL_SLOTS && host.rio_cq != 0 {
        let c_link = host_slot_link(host, c_slot);
        let rq = native_rio_create_rq_ctx(cfd, 16, 16, host.rio_cq, host.rio_cq, c_link.raw);
        if rq != 0 {
            host.links[c_slot].rio_rq = rq;
            host.links[c_slot].is_rio = true;
            if !post_rio_slot_recv(host, c_slot) {
                release_host_slot(host, c_slot);
                return;
            }
        } else {
            let _ = net::tcp_set_nonblocking(cfd, true);
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
    host:   net::Host&,
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
            native_rio_poll_accept(lfd, 0)
        } else {
            net::tcp_accept_nonblocking(lfd)
        };
        if cfd <= 0 { break; }
        handle_accepted_fd(host, driver, arg_a, arg_b, slot, gen, cfd, is_rio, count);
    }
}

fn finish_connecting_slot<D, CtxA, CtxB>(
    host:     net::Host&,
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
    host:       net::Host&,
    driver:     D&,
    arg_a:      CtxA&,
    arg_b:      CtxB&,
    rx_scratch: u8[>..]&,
    slot:       i64,
    gen:        u16,
    count:      i32&,
) -> bool {
    guard host.links[slot].in_use && host.links[slot].gen == gen && !host.links[slot].rx_paused else {
        return false;
    }
    let link = host_slot_link(host, slot);
    let tag = host.links[slot].tag;
    ensure_rx_scratch(rx_scratch);
    let recvd = net::tcp_recv_nonblocking_slice(host.links[slot].fd, rx_scratch[..]);
    if recvd > 0 {
        let ev = core::LinkEvent {
            kind: core::LinkEventKind.Data,
            link: link,
            tag:  tag,
            data: rx_scratch[..recvd],
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
    host:       net::Host&,
    driver:     D&,
    arg_a:      CtxA&,
    arg_b:      CtxB&,
    rx_scratch: u8[>..]&,
    slot:       i64,
    gen:        u16,
    count:      i32&,
) {
    for _ in 4 {
        if !step_socket_read(host, driver, arg_a, arg_b, rx_scratch, slot, gen, count) {
            break;
        }
    }
}

fn handle_readiness_slot_event<D, CtxA, CtxB>(
    host:       net::Host&,
    driver:     D&,
    arg_a:      CtxA&,
    arg_b:      CtxB&,
    rx_scratch: u8[>..]&,
    slot:       i64,
    gen:        u16,
    ev_flags:   u32,
    count:      i32&,
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
        drain_ready_socket_reads(host, driver, arg_a, arg_b, rx_scratch, slot, gen, count);
    }
}

fn poll_single_epoll_shard<D, CtxA, CtxB>(
    host:       net::Host&,
    driver:     D&,
    arg_a:      CtxA&,
    arg_b:      CtxB&,
    rx_scratch: u8[>..]&,
    shard_fd:   i64,
    timeout_ms: i64,
    count:      i32&,
) -> i32 {
    var raw_fds:    i64[64] = [0; 64];
    var raw_udata:  u64[64] = [0; 64];
    var raw_events: u32[64] = [0; 64];
    let t_clamped = min(max(timeout_ms, -1), 2147483647) as i32;
    let n = epoll_wait_events_direct(shard_fd, raw_fds[..], raw_udata[..], raw_events[..], t_clamped);
    guard n > 0 else { return 0; }
    let limit = min(n as i64, 64);
    for k in limit {
        let link = core::IoLink { raw: raw_udata[k] };
        let slot, ok = host_match_link(host, link);
        guard ok else { continue; }
        handle_readiness_slot_event(
            host, driver, arg_a, arg_b, rx_scratch, slot, core::io_link_gen(link), raw_events[k], count,
        );
    }
    return n;
}

fn poll_epoll_backend<D, CtxA, CtxB>(
    host:       net::Host&,
    driver:     D&,
    arg_a:      CtxA&,
    arg_b:      CtxB&,
    rx_scratch: u8[>..]&,
    timeout_ms: i64,
    count:      i32&,
) {
    guard host.epfd_count > 0 && host.epfd_shards.len > 0 else { return; }
    if host.epfd_shards.len == 1 {
        let _ = poll_single_epoll_shard(
            host, driver, arg_a, arg_b, rx_scratch, host.epfd_shards[0].fd, timeout_ms, count,
        );
        return;
    }
    var total_ready: i64 = 0;
    let n_shards = host.epfd_shards.len;
    for i in n_shards {
        guard i < host.epfd_shards.len else { return; }
        if host.epfd_shards[i].count > 0 {
            let n = poll_single_epoll_shard(
                host, driver, arg_a, arg_b, rx_scratch, host.epfd_shards[i].fd, 0, count,
            );
            total_ready = core::add_sat_i64(total_ready, n);
        }
    }
    if total_ready == 0 && timeout_ms != 0 && host.epfd_shards.len > 0 {
        let _ = poll_single_epoll_shard(
            host, driver, arg_a, arg_b, rx_scratch, host.epfd_shards[0].fd, max(min(timeout_ms, 2), 1), count,
        );
    }
}

fn dispatch_single_kevent<D, CtxA, CtxB>(
    host:       net::Host&,
    driver:     D&,
    arg_a:      CtxA&,
    arg_b:      CtxB&,
    rx_scratch: u8[>..]&,
    kev:        const Kevent&,
    count:      i32&,
) {
    guard (kev.flags & HOST_KQ_EV_ERROR) == 0 else { return; }
    let link = core::IoLink { raw: kev.udata };
    let slot, ok = host_match_link(host, link);
    guard ok else { return; }
    var flags: u32 = core::POLL_NONE;
    if kev.filter == EVFILT_READ { flags |= core::POLL_READ; }
    if kev.filter == EVFILT_WRITE { flags |= core::POLL_WRITE; }
    if (kev.flags & EV_EOF) != 0 {
        flags |= core::POLL_HANGUP;
        if kev.fflags != 0 { flags |= core::POLL_ERROR; }
    }
    handle_readiness_slot_event(host, driver, arg_a, arg_b, rx_scratch, slot, core::io_link_gen(link), flags, count);
}

fn poll_kqueue_backend<D, CtxA, CtxB>(
    host:       net::Host&,
    driver:     D&,
    arg_a:      CtxA&,
    arg_b:      CtxB&,
    rx_scratch: u8[>..]&,
    timeout_ms: i64,
    count:      i32&,
) {
    guard host.kq_fd >= 0 else { return; }
    var kev_out: Kevent[64] = [Kevent { .. }; 64];
    let t_ns = timeout_ms_to_ns(timeout_ms);
    let n = kqueue_poll_slice(host.kq_fd, host.kq_changes[..], kev_out[..], t_ns);
    host.kq_changes.clear();
    guard n > 0 else { return; }
    let limit = min(n as i64, 64);
    for k in limit {
        dispatch_single_kevent(host, driver, arg_a, arg_b, rx_scratch, kev_out[k], count);
    }
}

fn dispatch_single_rio_result<D, CtxA, CtxB>(
    host:   net::Host&,
    driver: D&,
    arg_a:  CtxA&,
    arg_b:  CtxB&,
    res:    const RioResult&,
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
    host:       net::Host&,
    driver:     D&,
    arg_a:      CtxA&,
    arg_b:      CtxB&,
    timeout_ms: i64,
    count:      i32&,
) {
    guard host.rio_cq != 0 else { return; }
    let n_links = host.links.len;
    for i in n_links {
        guard host.is_open && i < host.links.len else { break; }
        if host.links[i].in_use && host.links[i].is_rio && host.links[i].state == LinkSlotState.Listening {
            accept_ready_listener(host, driver, arg_a, arg_b, i, host.links[i].gen, count);
        }
    }
    var rio_results: RioResult[..64] = [];
    var n = rio_drain_completions(host.rio_cq, rio_results);
    if n == 0 && timeout_ms > 0 && host.epfd_count == 0 {
        let _ = rio_wait_cq(host.rio_cq, min(timeout_ms, 5) as i32);
        n = rio_drain_completions(host.rio_cq, rio_results);
    }
    for k in rio_results.len {
        dispatch_single_rio_result(host, driver, arg_a, arg_b, rio_results[k], count);
    }
}

fn dispatch_uring_send_cqe<D, CtxA, CtxB>(
    host:   net::Host&,
    driver: D&,
    arg_a:  CtxA&,
    arg_b:  CtxB&,
    slot:   i64,
    cqe:    const UringCqe&,
    count:  i32&,
) {
    guard (cqe.flags & URING_CQE_F_NOTIF) == 0 else { return; }
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
    host:       net::Host&,
    driver:     D&,
    arg_a:      CtxA&,
    arg_b:      CtxB&,
    rx_scratch: u8[>..]&,
    slot:       i64,
    gen:        u16,
    cqe:        const UringCqe&,
    has_buf:    bool,
    bid:        u16,
    count:      i32&,
) {
    let link = host_slot_link(host, slot);
    let tag = host.links[slot].tag;
    if cqe.res == 0 {
        if has_buf { uring_recycle_pbuf(host.uring_pbuf, bid); }
        host.links[slot].eof_received = true;
        host.links[slot].epoll_mask &= ~net::EPOLL_READ;
        let ev = core::LinkEvent { kind: core::LinkEventKind.Eof, link: link, tag: tag, .. };
        emit_host_event(host, driver, arg_a, arg_b, ev, count);
        return;
    }
    if cqe.res < 0 {
        if has_buf { uring_recycle_pbuf(host.uring_pbuf, bid); }
        release_host_slot(host, slot);
        let closed_ev = core::LinkEvent {
            kind: core::LinkEventKind.Closed, link: link, tag: tag, err: core::IoError.Closed, ..
        };
        emit_host_event(host, driver, arg_a, arg_b, closed_ev, count);
        return;
    }
    var copied: i32 = 0;
    if has_buf {
        ensure_rx_scratch(rx_scratch);
        copied = uring_read_pbuf(host.uring_pbuf, bid, cqe.res, rx_scratch[..]);
        uring_recycle_pbuf(host.uring_pbuf, bid);
    }
    if copied > 0 {
        let ev = core::LinkEvent {
            kind: core::LinkEventKind.Data, link: link, tag: tag, data: rx_scratch[..copied], ..
        };
        emit_host_event(host, driver, arg_a, arg_b, ev, count);
    }
    if (cqe.flags & URING_CQE_F_MORE) == 0 &&
        host.links[slot].in_use &&
        host.links[slot].gen == gen &&
        !host.links[slot].rx_paused &&
        !host.links[slot].eof_received {
        host.links[slot].epoll_mask &= ~net::EPOLL_READ;
        sync_slot_interest(host, slot);
    }
}

fn dispatch_uring_accept_cqe<D, CtxA, CtxB>(
    host:   net::Host&,
    driver: D&,
    arg_a:  CtxA&,
    arg_b:  CtxB&,
    slot:   i64,
    gen:    u16,
    cqe:    const UringCqe&,
    count:  i32&,
) {
    if cqe.res > 0 {
        handle_accepted_fd(host, driver, arg_a, arg_b, slot, gen, cqe.res as i64, false, count);
    }
    if (cqe.flags & URING_CQE_F_MORE) == 0 && host.links[slot].in_use && host.links[slot].gen == gen {
        host.links[slot].epoll_mask = 0;
        sync_slot_interest(host, slot);
    }
}

fn dispatch_uring_cqe<D, CtxA, CtxB>(
    host:       net::Host&,
    driver:     D&,
    arg_a:      CtxA&,
    arg_b:      CtxB&,
    rx_scratch: u8[>..]&,
    cqe:        const UringCqe&,
    count:      i32&,
) {
    let has_buf = (cqe.flags & URING_CQE_F_BUFFER) != 0;
    let bid = ((cqe.flags >> 16) & 0xFFFF) as u16;
    let op, slot, ok = host_match_uring_tag(host, cqe.user_data);
    guard ok else {
        if has_buf { uring_recycle_pbuf(host.uring_pbuf, bid); }
        return;
    }
    if op == HOST_URING_OP_RECV {
        dispatch_uring_recv_cqe(
            host, driver, arg_a, arg_b, rx_scratch, slot, host.links[slot].gen, cqe, has_buf, bid, count,
        );
        return;
    }
    if has_buf { uring_recycle_pbuf(host.uring_pbuf, bid); }
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
        host.links[slot].epoll_mask &= ~net::EPOLL_WRITE;
        let ev = core::LinkEvent {
            kind: core::LinkEventKind.Writable, link: host_slot_link(host, slot), tag: host.links[slot].tag, ..
        };
        emit_host_event(host, driver, arg_a, arg_b, ev, count);
    }
}

fn poll_uring_backend<D, CtxA, CtxB>(
    host:       net::Host&,
    driver:     D&,
    arg_a:      CtxA&,
    arg_b:      CtxB&,
    rx_scratch: u8[>..]&,
    timeout_ms: i64,
    count:      i32&,
) {
    guard host.uring_fd >= 0 else { return; }
    var cqes: UringCqe[64] = [UringCqe { .. }; 64];
    let min_c: u32 = if timeout_ms == 0 { 0 } else { 1 };
    let t_ns = timeout_ms_to_ns(timeout_ms);
    let n = uring_wait_cqes(host.uring_fd, cqes[..], min_c, t_ns);
    guard n > 0 else { return; }
    let limit = min(n as i64, 64);
    for k in limit {
        dispatch_uring_cqe(host, driver, arg_a, arg_b, rx_scratch, cqes[k], count);
    }
}
