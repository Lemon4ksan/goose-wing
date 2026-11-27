// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Layer 4 Linux AF_XDP (XSK) Zero-Copy Kernel-Bypass Driver.
// Routes Ethernet frames directly between NIC hardware queues and userspace UMEM rings.
namespace net_internal;

import std;
import core;
import net.driver.types;

// Native C bindings from shim/af_xdp.c
extern fn native_af_xdp_probe() -> i32 = "wing_af_xdp_probe";
extern fn native_af_xdp_create_socket() -> i64 = "wing_af_xdp_create_socket";
extern fn native_af_xdp_register_umem(
    xsk_fd:     i64,
    addr:       u64,
    len:        u64,
    chunk_size: u32,
    headroom:   u32,
) -> i32 = "wing_af_xdp_register_umem";
extern fn native_af_xdp_set_ring_size(xsk_fd: i64, ring_opt: i32, entries: u32) -> i32 = "wing_af_xdp_set_ring_size";
extern fn native_af_xdp_bind(xsk_fd: i64, ifindex: u32, queue_id: u32, flags: u32) -> i32 = "wing_af_xdp_bind";
extern fn native_af_xdp_mmap_rings(xsk_fd: i64, entries: u32) -> i32 = "wing_af_xdp_mmap_rings";
extern fn native_af_xdp_fill_push(xsk_fd: i64, umem_offset: u64) -> i32 = "wing_af_xdp_fill_push";
extern fn native_af_xdp_tx_submit(xsk_fd: i64, addr: u64, len: u32, options: u32) -> i32 = "wing_af_xdp_tx_submit";
extern fn native_af_xdp_rx_poll(
    xsk_fd:      i64,
    addr_out:    u64&,
    len_out:     u32&,
    options_out: u32&,
) -> i32 = "wing_af_xdp_rx_poll";
extern fn native_af_xdp_complete_pop(xsk_fd: i64, addr_out: u64&) -> i32 = "wing_af_xdp_complete_pop";
extern fn native_af_xdp_umem_write(xsk_fd: i64, addr: u64, src: const u8[:]) -> i32 = "wing_af_xdp_umem_write";
extern fn native_af_xdp_umem_read(
    xsk_fd:    i64,
    addr:      u64,
    frame_len: u32,
    dst:       u8[:],
) -> i32 = "wing_af_xdp_umem_read";
extern fn native_af_xdp_close(xsk_fd: i64) = "wing_af_xdp_close";

const XSK_LOOPBACK_MAX_SOCKETS: i64 = 16;
const XSK_LOOPBACK_RING_CAP:    u64 = 64;
const XSK_LOOPBACK_FD_BASE:     i64 = 0x40000000;

struct XskLoopbackSlot {
    active:     bool        = false,
    umem_off:   u64         = 0,
    umem_len:   u64         = 0,
    chunk_size: u32         = 0,
    fill_ring:  u64[64]     = [0; 64],
    fill_head:  u64         = 0,
    fill_tail:  u64         = 0,
    comp_ring:  u64[64]     = [0; 64],
    comp_head:  u64         = 0,
    comp_tail:  u64         = 0,
    rx_ring:    XdpDesc[64] = [XdpDesc { .. }; 64],
    rx_head:    u64         = 0,
    rx_tail:    u64         = 0,
    tx_ring:    XdpDesc[64] = [XdpDesc { .. }; 64],
    tx_head:    u64         = 0,
    tx_tail:    u64         = 0,
}

root struct XskLoopbackTable {
    slots: XskLoopbackSlot[16] = [XskLoopbackSlot { .. }; 16],
    umem:  u8[>..]             = [],
}

var g_xsk_lb: XskLoopbackTable = XskLoopbackTable { .. };

fn xsk_lb_find_idx(xsk_fd: i64) -> i64 {
    guard xsk_fd >= XSK_LOOPBACK_FD_BASE else { return -1; }
    let idx = xsk_fd - XSK_LOOPBACK_FD_BASE;
    guard idx >= 0 && idx < XSK_LOOPBACK_MAX_SOCKETS && g_xsk_lb.slots[idx].active else {
        return -1;
    }
    return idx;
}

fn xsk_validate_umem_span(umem_len: u64, chunk_size: u32, addr: u64, span_len: u64) -> bool {
    guard umem_len > 0 else { return false; }
    let csz = chunk_size as u64;
    let max_frame = if csz > 0 && csz < 2048 { csz } else { 2048 };
    guard span_len <= max_frame && addr <= umem_len && span_len <= (umem_len - addr) else {
        return false;
    }
    if csz > 0 {
        let off_in_chunk = addr % csz;
        guard span_len <= (csz - off_in_chunk) else { return false; }
    }
    return true;
}

fn xsk_validate_fill_offset(umem_len: u64, chunk_size: u32, offset: u64) -> bool {
    guard xsk_validate_umem_span(umem_len, chunk_size, offset, 0) else { return false; }
    let csz = chunk_size as u64;
    if csz > 0 {
        guard (offset % csz) == 0 && csz <= umem_len && offset <= (umem_len - csz) else {
            return false;
        }
    }
    return true;
}

// AF_XDP packet descriptor (matches Linux struct xdp_desc)
struct XdpDesc {
    addr:    u64 = 0,
    len:     u32 = 0,
    options: u32 = 0,
}

// Userspace Memory (UMEM) registration configuration
struct AfXdpUmem {
    addr:          u64  = 0,
    len:           u64  = 0,
    chunk_size:    u32  = 2048,
    headroom:      u32  = 0,
    is_registered: bool = false,
}

// AF_XDP Zero-Copy Socket
struct AfXdpSocket {
    fd:             i64       = -1,
    ifindex:        u32       = 0,
    queue_id:       u32       = 0,
    umem:           AfXdpUmem = AfXdpUmem { .. },
    is_bound:       bool      = false,
    rings_mapped:   bool      = false,
    zero_copy_mode: bool      = true,
}

const XSK_RING_RX:         i32 = 2;
const XSK_RING_TX:         i32 = 3;
const XSK_RING_FILL:       i32 = 5;
const XSK_RING_COMPLETION: i32 = 6;

const XDP_FLAGS_ZEROCOPY:        u32 = 1 << 2;
const XDP_FLAGS_COPY:            u32 = 1 << 1;
const XDP_FLAGS_USE_NEED_WAKEUP: u32 = 1 << 3;
const XDP_ERR_EINVAL:            i32 = -22;

fn new_af_xdp_socket() -> AfXdpSocket {
    return AfXdpSocket {
        fd:             -1,
        ifindex:        0,
        queue_id:       0,
        umem:           AfXdpUmem { .. },
        is_bound:       false,
        rings_mapped:   false,
        zero_copy_mode: true,
    };
}

// Creates and registers an AF_XDP kernel-bypass socket with UMEM memory pool and mmap rings.
fn af_xdp_open_socket(
    ifindex:    u32,
    queue_id:   u32,
    umem_addr:  u64,
    umem_len:   u64,
    chunk_size: u32  = 2048,
    zero_copy:  bool = true,
) -> AfXdpSocket, i32 {
    let fd = native_af_xdp_create_socket();
    if fd < 0 {
        return new_af_xdp_socket(), fd as i32;
    }
    var committed = false;
    defer if !committed { native_af_xdp_close(fd); };

    var umem = AfXdpUmem {
        addr:          umem_addr,
        len:           umem_len,
        chunk_size:    chunk_size,
        headroom:      0,
        is_registered: false,
    };

    let reg_err = native_af_xdp_register_umem(fd, umem_addr, umem_len, chunk_size, 0);
    if reg_err != 0 {
        return new_af_xdp_socket(), reg_err;
    }
    umem.is_registered = true;

    // Configure standard ring depths (2048 descriptors) and map Fill/Completion/RX/TX rings
    let fill_err = native_af_xdp_set_ring_size(fd, XSK_RING_FILL, 2048);
    guard fill_err == 0 else { return new_af_xdp_socket(), fill_err; }
    let comp_err = native_af_xdp_set_ring_size(fd, XSK_RING_COMPLETION, 2048);
    guard comp_err == 0 else { return new_af_xdp_socket(), comp_err; }
    let rx_err = native_af_xdp_set_ring_size(fd, XSK_RING_RX, 2048);
    guard rx_err == 0 else { return new_af_xdp_socket(), rx_err; }
    let tx_err = native_af_xdp_set_ring_size(fd, XSK_RING_TX, 2048);
    guard tx_err == 0 else { return new_af_xdp_socket(), tx_err; }

    let mmap_err = native_af_xdp_mmap_rings(fd, 2048);
    guard mmap_err == 0 else { return new_af_xdp_socket(), mmap_err; }

    let base_flags = if zero_copy { XDP_FLAGS_ZEROCOPY } else { XDP_FLAGS_COPY };
    var bind_err = native_af_xdp_bind(fd, ifindex, queue_id, base_flags | XDP_FLAGS_USE_NEED_WAKEUP);
    if bind_err == XDP_ERR_EINVAL {
        bind_err = native_af_xdp_bind(fd, ifindex, queue_id, base_flags);
    }
    if bind_err != 0 {
        return new_af_xdp_socket(), bind_err;
    }

    committed = true;
    return AfXdpSocket {
        fd:             fd,
        ifindex:        ifindex,
        queue_id:       queue_id,
        umem:           umem,
        is_bound:       true,
        rings_mapped:   true,
        zero_copy_mode: zero_copy,
    }, 0;
}

// Publishes a UMEM frame offset into the AF_XDP Fill Ring for kernel RX reception.
fn af_xdp_fill_push(sock: const AfXdpSocket&, umem_offset: u64) -> bool {
    guard sock.fd >= 0 && sock.is_bound && sock.rings_mapped else { return false; }
    let lb_idx = xsk_lb_find_idx(sock.fd);
    if lb_idx >= 0 {
        let s .= g_xsk_lb.slots[lb_idx];
        guard xsk_validate_fill_offset(s.umem_len, s.chunk_size, umem_offset) else { return false; }
        guard (s.fill_tail - s.fill_head) < XSK_LOOPBACK_RING_CAP else { return false; }
        s.fill_ring[(s.fill_tail % XSK_LOOPBACK_RING_CAP) as i64] = umem_offset;
        s.fill_tail += 1;
        return true;
    }
    return native_af_xdp_fill_push(sock.fd, umem_offset) == 0;
}

// Submits a packet descriptor to the AF_XDP TX Ring and kicks the kernel.
fn af_xdp_tx_submit(sock: const AfXdpSocket&, desc: const XdpDesc&) -> bool {
    guard sock.fd >= 0 && sock.is_bound && sock.rings_mapped && desc.len > 0 else { return false; }
    let lb_idx = xsk_lb_find_idx(sock.fd);
    if lb_idx >= 0 {
        let s .= g_xsk_lb.slots[lb_idx];
        guard xsk_validate_umem_span(s.umem_len, s.chunk_size, desc.addr, desc.len) else {
            return false;
        }
        guard (s.tx_tail - s.tx_head) < XSK_LOOPBACK_RING_CAP &&
              (s.comp_tail - s.comp_head) < XSK_LOOPBACK_RING_CAP else {
            return false;
        }
        let idx = (s.tx_tail % XSK_LOOPBACK_RING_CAP) as i64;
        s.tx_ring[idx] = desc;
        s.tx_tail += 1;
        s.tx_head += 1;
        s.comp_ring[(s.comp_tail % XSK_LOOPBACK_RING_CAP) as i64] = desc.addr;
        s.comp_tail += 1;
        return true;
    }
    return native_af_xdp_tx_submit(sock.fd, desc.addr, desc.len, desc.options) == 0;
}

// Polls a received packet descriptor from the AF_XDP RX Ring.
fn af_xdp_rx_poll(sock: const AfXdpSocket&) -> XdpDesc, bool {
    guard sock.fd >= 0 && sock.is_bound && sock.rings_mapped else {
        return XdpDesc { .. }, false;
    }
    let lb_idx = xsk_lb_find_idx(sock.fd);
    if lb_idx >= 0 {
        let s .= g_xsk_lb.slots[lb_idx];
        guard s.rx_head != s.rx_tail else { return XdpDesc { .. }, false; }
        let idx = (s.rx_head % XSK_LOOPBACK_RING_CAP) as i64;
        let d = s.rx_ring[idx];
        s.rx_head += 1;
        return d, true;
    }
    var addr: u64 = 0;
    var len:  u32 = 0;
    var opts: u32 = 0;
    let got = native_af_xdp_rx_poll(sock.fd, addr, len, opts);
    guard got != 0 else {
        return XdpDesc { .. }, false;
    }
    return XdpDesc { addr: addr, len: len, options: opts }, true;
}

// Pops a completed TX frame offset from the AF_XDP Completion Ring.
fn af_xdp_complete_pop(sock: const AfXdpSocket&) -> u64, bool {
    guard sock.fd >= 0 && sock.is_bound && sock.rings_mapped else { return 0, false; }
    let lb_idx = xsk_lb_find_idx(sock.fd);
    if lb_idx >= 0 {
        let s .= g_xsk_lb.slots[lb_idx];
        guard s.comp_head != s.comp_tail else { return 0, false; }
        let addr = s.comp_ring[(s.comp_head % XSK_LOOPBACK_RING_CAP) as i64];
        s.comp_head += 1;
        return addr, true;
    }
    var addr: u64 = 0;
    let got = native_af_xdp_complete_pop(sock.fd, addr);
    return addr, got != 0;
}

// Closes AF_XDP socket, unmaps rings, and unbinds from NIC queue.
fn af_xdp_close(sock: AfXdpSocket&) {
    guard sock.fd >= 0 else { return; }
    let lb_idx = xsk_lb_find_idx(sock.fd);
    if lb_idx >= 0 {
        g_xsk_lb.slots[lb_idx] = XskLoopbackSlot { .. };
        var any_active = false;
        for i in XSK_LOOPBACK_MAX_SOCKETS {
            if g_xsk_lb.slots[i].active {
                any_active = true;
                break;
            }
        }
        if !any_active {
            g_xsk_lb.umem.clear();
        }
    } else {
        native_af_xdp_close(sock.fd);
    }
    sock.fd = -1;
    sock.is_bound = false;
    sock.rings_mapped = false;
    sock.umem.is_registered = false;
}

// Opens an in-memory UMEM loopback AF_XDP socket usable without CAP_NET_RAW on all platforms.
fn af_xdp_open_loopback(num_frames: u32 = 64, frame_size: u32 = 2048) -> AfXdpSocket, bool {
    guard num_frames > 0 && num_frames <= 4096 && frame_size > 0 && frame_size <= 4096 else {
        return new_af_xdp_socket(), false;
    }
    var slot_idx: i64 = -1;
    for i in XSK_LOOPBACK_MAX_SOCKETS {
        if !g_xsk_lb.slots[i].active {
            slot_idx = i;
            break;
        }
    }
    guard slot_idx >= 0 else { return new_af_xdp_socket(), false; }
    let total_bytes = (num_frames as i64) * frame_size;
    let base_off = g_xsk_lb.umem.len;
    g_xsk_lb.umem.resize(core::add_sat_i64(base_off, total_bytes), 0);
    g_xsk_lb.slots[slot_idx] = XskLoopbackSlot {
        active:     true,
        umem_off:   base_off as u64,
        umem_len:   total_bytes as u64,
        chunk_size: frame_size,
        ..
    };
    return AfXdpSocket {
        fd:       XSK_LOOPBACK_FD_BASE + slot_idx,
        ifindex:  0,
        queue_id: 0,
        umem: AfXdpUmem {
            addr:          0,
            len:           total_bytes as u64,
            chunk_size:    frame_size,
            headroom:      0,
            is_registered: true,
        },
        is_bound:       true,
        rings_mapped:   true,
        zero_copy_mode: true,
    }, true;
}

// Copies `data` into the registered UMEM region at `addr` after bounds and chunk-size validation.
fn af_xdp_umem_write(sock: const AfXdpSocket&, addr: u64, data: const u8[:]) -> bool {
    guard sock.fd >= 0 && sock.umem.is_registered && data.len <= 2048 else {
        return false;
    }
    let lb_idx = xsk_lb_find_idx(sock.fd);
    if lb_idx >= 0 {
        let s .= g_xsk_lb.slots[lb_idx];
        guard xsk_validate_umem_span(s.umem_len, s.chunk_size, addr, data.len as u64) else {
            return false;
        }
        let start = core::add_sat_u64(s.umem_off, addr) as i64;
        for i in data.len {
            g_xsk_lb.umem[start + i] = data[i];
        }
        return true;
    }
    return native_af_xdp_umem_write(sock.fd, addr, data) == 0;
}

// Reads `frame_len` bytes from the registered UMEM region at `addr` into `out_frame`.
fn af_xdp_umem_read(
    sock:      const AfXdpSocket&,
    addr:      u64,
    frame_len: u32,
    out_frame: u8[..2048]&,
) -> bool {
    out_frame.clear();
    guard sock.fd >= 0 && sock.umem.is_registered && frame_len <= 2048 else {
        return false;
    }
    let lb_idx = xsk_lb_find_idx(sock.fd);
    if lb_idx >= 0 {
        let s .= g_xsk_lb.slots[lb_idx];
        guard xsk_validate_umem_span(s.umem_len, s.chunk_size, addr, frame_len) else {
            return false;
        }
        let start = core::add_sat_u64(s.umem_off, addr) as i64;
        let end = core::add_sat_i64(start, frame_len);
        return out_frame.try_append(g_xsk_lb.umem[start..end]);
    }
    out_frame.resize(frame_len as i64, 0);
    let n = native_af_xdp_umem_read(sock.fd, addr, frame_len, out_frame[..]);
    guard n >= 0 && n == (frame_len as i32) else {
        out_frame.clear();
        return false;
    }
    return true;
}

// Enqueues a synthetic RX descriptor into a loopback AF_XDP socket's RX ring.
fn af_xdp_inject_loopback_rx(sock: AfXdpSocket&, addr: u64, frame_len: u32) -> bool {
    guard sock.fd >= 0 && sock.is_bound && sock.rings_mapped && frame_len > 0 && frame_len <= 2048 else {
        return false;
    }
    let lb_idx = xsk_lb_find_idx(sock.fd);
    guard lb_idx >= 0 else { return false; }
    let s .= g_xsk_lb.slots[lb_idx];
    guard xsk_validate_umem_span(s.umem_len, s.chunk_size, addr, frame_len) else {
        return false;
    }
    guard (s.rx_tail - s.rx_head) < XSK_LOOPBACK_RING_CAP else { return false; }
    let idx = (s.rx_tail % XSK_LOOPBACK_RING_CAP) as i64;
    s.rx_ring[idx] = XdpDesc { addr: addr, len: frame_len, options: 0 };
    s.rx_tail += 1;
    return true;
}

// AF_XDP Fill/Completion ring state with wrap-split burst enqueueing (`rte_ring_elem_pvt.h` pattern).
struct XskRingState {
    entries:   u64[64] = [0; 64],
    prod_head: u32     = 0,
    cons_head: u32     = 0,
    mask:      u32     = 63,
    capacity:  u32     = 64,
    _pad:      u64[4]  = [0; 4],
}

// Enqueues a burst of UMEM frame addresses into `ring` with 32-bit wrapping cursor delta.
fn xsk_fill_ring_enqueue_burst(ring: XskRingState&, addrs: const u64[:]) -> u32 {
    guard addrs.len > 0 else { return 0; }
    let cap = min((ring.mask + 1) as u64, 64);
    var used = (ring.prod_head - ring.cons_head) as u64;
    var prod = ring.prod_head;
    var staged: u64 = 0;
    for addr in addrs {
        guard used < cap else { break; }
        let slot_idx = (prod & ring.mask) as i64;
        ring.entries[slot_idx] = addr;
        prod = prod + 1;
        used = core::add_sat_u64(used, 1);
        staged = core::add_sat_u64(staged, 1);
    }
    ring.prod_head = prod;
    return staged as u32;
}
