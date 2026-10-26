// Layer 4 Linux AF_XDP (XSK) Zero-Copy Kernel-Bypass Driver.
// Routes Ethernet frames directly between NIC hardware queues and userspace UMEM rings.
namespace internal;

import std;
import net.driver.types;

// Native C bindings from shim/af_xdp.c
extern fn wing_af_xdp_probe() -> i32;
extern fn wing_af_xdp_create_socket() -> i64;
extern fn wing_af_xdp_register_umem(xsk_fd: i64, addr: u64, len: u64, chunk_size: u32, headroom: u32) -> i32;
extern fn wing_af_xdp_set_ring_size(xsk_fd: i64, ring_opt: i32, entries: u32) -> i32;
extern fn wing_af_xdp_bind(xsk_fd: i64, ifindex: u32, queue_id: u32, flags: u32) -> i32;
extern fn wing_af_xdp_close(xsk_fd: i64);

fn native_af_xdp_probe() -> i32 { return wing_af_xdp_probe(); }
fn native_af_xdp_create_socket() -> i64 { return wing_af_xdp_create_socket(); }
fn native_af_xdp_register_umem(fd: i64, addr: u64, len: u64, chunk: u32, headroom: u32) -> i32 {
    return wing_af_xdp_register_umem(fd, addr, len, chunk, headroom);
}
fn native_af_xdp_set_ring_size(fd: i64, opt: i32, entries: u32) -> i32 {
    return wing_af_xdp_set_ring_size(fd, opt, entries);
}
fn native_af_xdp_bind(fd: i64, ifindex: u32, qid: u32, flags: u32) -> i32 {
    return wing_af_xdp_bind(fd, ifindex, qid, flags);
}
fn native_af_xdp_close(fd: i64) { wing_af_xdp_close(fd); }

// AF_XDP packet descriptor (matches Linux struct xdp_desc)
struct XdpDesc {
    addr: u64 = 0,
    len: u32 = 0,
    options: u32 = 0,
}

// Userspace Memory (UMEM) registration configuration
struct AfXdpUmem {
    addr: u64 = 0,
    len: u64 = 0,
    chunk_size: u32 = 2048,
    headroom: u32 = 0,
    is_registered: bool = false,
}

// AF_XDP Zero-Copy Socket
struct AfXdpSocket {
    fd: i64 = -1,
    ifindex: u32 = 0,
    queue_id: u32 = 0,
    umem: AfXdpUmem = AfXdpUmem { .. },
    is_bound: bool = false,
    zero_copy_mode: bool = true,
}

const XSK_RING_RX: i32 = 2;
const XSK_RING_TX: i32 = 3;
const XSK_RING_FILL: i32 = 5;
const XSK_RING_COMPLETION: i32 = 6;

const XDP_FLAGS_ZEROCOPY: u32 = 1 << 2;
const XDP_FLAGS_COPY: u32     = 1 << 1;

fn new_af_xdp_socket() -> AfXdpSocket {
    return AfXdpSocket {
        fd: -1,
        ifindex: 0,
        queue_id: 0,
        umem: AfXdpUmem { .. },
        is_bound: false,
        zero_copy_mode: true,
    };
}

// Creates and registers an AF_XDP kernel-bypass socket with UMEM memory pool.
fn af_xdp_open_socket(
    ifindex: u32,
    queue_id: u32,
    umem_addr: u64,
    umem_len: u64,
    chunk_size: u32 = 2048,
    zero_copy: bool = true
) -> AfXdpSocket, i32 {
    let fd = native_af_xdp_create_socket();
    if fd < 0 {
        return new_af_xdp_socket(), fd as i32;
    }

    var umem = AfXdpUmem {
        addr: umem_addr,
        len: umem_len,
        chunk_size: chunk_size,
        headroom: 0,
        is_registered: false,
    };

    let reg_err = native_af_xdp_register_umem(fd, umem_addr, umem_len, chunk_size, 0);
    if reg_err != 0 {
        native_af_xdp_close(fd);
        return new_af_xdp_socket(), reg_err;
    }
    umem.is_registered = true;

    // Configure standard ring depths (2048 descriptors)
    native_af_xdp_set_ring_size(fd, XSK_RING_FILL, 2048);
    native_af_xdp_set_ring_size(fd, XSK_RING_COMPLETION, 2048);
    native_af_xdp_set_ring_size(fd, XSK_RING_RX, 2048);
    native_af_xdp_set_ring_size(fd, XSK_RING_TX, 2048);

    let bind_flags = if zero_copy { XDP_FLAGS_ZEROCOPY } else { XDP_FLAGS_COPY };
    let bind_err = native_af_xdp_bind(fd, ifindex, queue_id, bind_flags);
    if bind_err != 0 {
        native_af_xdp_close(fd);
        return new_af_xdp_socket(), bind_err;
    }

    return AfXdpSocket {
        fd: fd,
        ifindex: ifindex,
        queue_id: queue_id,
        umem: umem,
        is_bound: true,
        zero_copy_mode: zero_copy,
    }, 0;
}

// Closes AF_XDP socket and unbinds from NIC queue.
fn af_xdp_close(sock: AfXdpSocket&) {
    if sock.fd >= 0 {
        native_af_xdp_close(sock.fd);
        sock.fd = -1;
        sock.is_bound = false;
        sock.umem.is_registered = false;
    }
}
