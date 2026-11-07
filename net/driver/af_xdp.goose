// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Layer 4 Linux AF_XDP (XSK) Zero-Copy Kernel-Bypass Driver.
// Routes Ethernet frames directly between NIC hardware queues and userspace UMEM rings.
namespace internal;

import std;
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
extern fn native_af_xdp_close(xsk_fd: i64) = "wing_af_xdp_close";

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

const XDP_FLAGS_ZEROCOPY: u32 = 1 << 2;
const XDP_FLAGS_COPY:     u32 = 1 << 1;

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

    var umem = AfXdpUmem {
        addr:          umem_addr,
        len:           umem_len,
        chunk_size:    chunk_size,
        headroom:      0,
        is_registered: false,
    };

    let reg_err = native_af_xdp_register_umem(fd, umem_addr, umem_len, chunk_size, 0);
    if reg_err != 0 {
        native_af_xdp_close(fd);
        return new_af_xdp_socket(), reg_err;
    }
    umem.is_registered = true;

    // Configure standard ring depths (2048 descriptors) and map Fill/Completion/RX/TX rings
    native_af_xdp_set_ring_size(fd, XSK_RING_FILL, 2048);
    native_af_xdp_set_ring_size(fd, XSK_RING_COMPLETION, 2048);
    native_af_xdp_set_ring_size(fd, XSK_RING_RX, 2048);
    native_af_xdp_set_ring_size(fd, XSK_RING_TX, 2048);

    let mmap_err = native_af_xdp_mmap_rings(fd, 2048);
    let mapped = mmap_err == 0;

    let bind_flags = if zero_copy { XDP_FLAGS_ZEROCOPY } else { XDP_FLAGS_COPY };
    let bind_err = native_af_xdp_bind(fd, ifindex, queue_id, bind_flags);
    if bind_err != 0 {
        native_af_xdp_close(fd);
        return new_af_xdp_socket(), bind_err;
    }

    return AfXdpSocket {
        fd:             fd,
        ifindex:        ifindex,
        queue_id:       queue_id,
        umem:           umem,
        is_bound:       true,
        rings_mapped:   mapped,
        zero_copy_mode: zero_copy,
    }, 0;
}

// Publishes a UMEM frame offset into the AF_XDP Fill Ring for kernel RX reception.
fn af_xdp_fill_push(sock: const AfXdpSocket&, umem_offset: u64) -> bool {
    guard sock.fd >= 0 && sock.is_bound && sock.rings_mapped else { return false; }
    return native_af_xdp_fill_push(sock.fd, umem_offset) == 0;
}

// Submits a packet descriptor to the AF_XDP TX Ring and kicks the kernel.
fn af_xdp_tx_submit(sock: const AfXdpSocket&, desc: const XdpDesc&) -> bool {
    guard sock.fd >= 0 && sock.is_bound && sock.rings_mapped && desc.len > 0 else { return false; }
    return native_af_xdp_tx_submit(sock.fd, desc.addr, desc.len, desc.options) == 0;
}

// Polls a received packet descriptor from the AF_XDP RX Ring.
fn af_xdp_rx_poll(sock: const AfXdpSocket&) -> XdpDesc, bool {
    guard sock.fd >= 0 && sock.is_bound && sock.rings_mapped else {
        return XdpDesc { .. }, false;
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
    var addr: u64 = 0;
    let got = native_af_xdp_complete_pop(sock.fd, addr);
    return addr, got != 0;
}

// Closes AF_XDP socket, unmaps rings, and unbinds from NIC queue.
fn af_xdp_close(sock: AfXdpSocket&) {
    if sock.fd >= 0 {
        native_af_xdp_close(sock.fd);
        sock.fd = -1;
        sock.is_bound = false;
        sock.rings_mapped = false;
        sock.umem.is_registered = false;
    }
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

// Enqueues a burst of UMEM frame addresses into `ring` using bounded ring slot staging.
fn xsk_fill_ring_enqueue_burst(ring: XskRingState&, addrs: const u64[:]) -> u32 {
    guard addrs.len > 0 else { return 0; }
    var prod = ring.prod_head as u64;
    let cons = ring.cons_head as u64;
    var used = core::sub_sat_u64(prod, cons);
    var staged: u64 = 0;
    for addr in addrs {
        guard used < 64 else { break; }
        ring.entries[prod & 63] = addr;
        prod = core::add_sat_u64(prod, 1);
        used = core::add_sat_u64(used, 1);
        staged = core::add_sat_u64(staged, 1);
    }
    ring.prod_head = prod as u32;
    return staged as u32;
}
