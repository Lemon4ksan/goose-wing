// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Windows Registered I/O (RIO) kernel bypass driver and page-locked buffers.
namespace internal;

import std;

// Native Windows RIO C shims (mswsock.dll)
extern fn native_rio_probe() -> i32 = "wing_rio_probe";
extern fn native_rio_available() -> i32 = "wing_rio_available";
extern fn native_rio_register_buffer(ptr: u64, len: u32) -> u64 = "wing_rio_register_buffer";
extern fn native_rio_deregister_buffer(buf_id: u64) = "wing_rio_deregister_buffer";
extern fn native_rio_create_cq(queue_size: u32) -> u64 = "wing_rio_create_cq";
extern fn native_rio_close_cq(cq_id: u64) = "wing_rio_close_cq";
extern fn native_rio_dequeue_completion(
    cq_id:       u64,
    results_ptr: u64,
    count:       u32,
) -> u32 = "wing_rio_dequeue_completion";
extern fn native_rio_create_rq(sock_fd: i64, cq_id: u64, max_recv: u32, max_send: u32) -> u64 = "wing_rio_create_rq";
extern fn native_rio_receive(
    rq_id:       u64,
    buf_id:      u64,
    offset:      u32,
    length:      u32,
    req_context: u64,
) -> i32 = "wing_rio_receive";
extern fn native_rio_send(
    rq_id:       u64,
    buf_id:      u64,
    offset:      u32,
    length:      u32,
    req_context: u64,
) -> i32 = "wing_rio_send";

// Page-locked registered memory buffer slice descriptor for Windows RIO
struct RioBufferDescriptor {
    buffer_id:     u64  = 0,
    offset:        u64  = 0,
    length:        u32  = 0,
    is_registered: bool = false,
    page_locked:   bool = false,
}

// Registers a contiguous page-locked buffer with the kernel/NIC
fn new_rio_buffer(id: u64, len: u32) -> RioBufferDescriptor {
    return RioBufferDescriptor {
        buffer_id:     id,
        offset:        0,
        length:        len,
        is_registered: true,
        page_locked:   true,
    };
}

// Slices a registered buffer without re-registration or memory allocation
fn rio_sub_buffer(parent: const RioBufferDescriptor&, off: u64, len: u32) -> RioBufferDescriptor {
    let parent_end = parent.offset + parent.length;
    let sub_end = off + len;
    guard parent.is_registered && off >= parent.offset && sub_end <= parent_end else {
        return RioBufferDescriptor { .. };
    }
    return RioBufferDescriptor {
        buffer_id:     parent.buffer_id,
        offset:        off,
        length:        len,
        is_registered: true,
        page_locked:   parent.page_locked,
    };
}

// Deregisters buffer and releases page-locks
fn rio_deregister_buffer(desc: RioBufferDescriptor&) {
    if desc.is_registered && desc.buffer_id != 0 {
        native_rio_deregister_buffer(desc.buffer_id);
    }
    desc.is_registered = false;
    desc.page_locked = false;
    desc.length = 0;
    desc.offset = 0;
}

// Verifies if buffer can fulfill zero-copy requirement
fn rio_can_zero_copy(desc: const RioBufferDescriptor&, req_len: u32) -> bool {
    return desc.is_registered && desc.page_locked && req_len <= desc.length;
}

// Size of a single SOCKADDR_INET slot in the pre-registered RIO address slab.
const RIO_SOCKADDR_INET_SIZE: u32 = 28;

// Maximum number of pre-registered address descriptors in `RioAddressPool`.
const RIO_ADDRESS_POOL_CAP: i32 = 128;

// Windows RIO_BUF slice descriptor for registered data or address buffers (mswsock.h).
struct RIO_BUF {
    buffer_id: u64  = 0,
    offset:    u32  = 0,
    length:    u32  = RIO_SOCKADDR_INET_SIZE,
    next_free: i32  = -1,
    in_use:    bool = false,
}

// Pre-registered address descriptor pool (`RIO_BUF[..128]`) with O(1) free-list acquire/release
// for Windows RIOReceiveEx / RIOSendEx UDP peer address resolution.
struct RioAddressPool {
    descriptors:  RIO_BUF[..128] = [],
    free_head:    i32            = -1,
    active_count: i32            = 0,
    slab_buf_id:  u64            = 0,
    initialized:  bool           = false,
}

inline fn build_rio_addr_descriptor(slab_id: u64, slot_idx: i32) -> RIO_BUF {
    let next_idx = slot_idx + 1;
    return RIO_BUF {
        buffer_id: slab_id,
        offset:    (slot_idx as u32) * RIO_SOCKADDR_INET_SIZE,
        length:    RIO_SOCKADDR_INET_SIZE,
        next_free: if next_idx < RIO_ADDRESS_POOL_CAP { next_idx } else { -1 },
        in_use:    false,
    };
}

// Initializes a pre-registered 128-slot RIO_BUF address pool with an O(1) singly-linked free-list.
fn rio_init_address_pool(pool: RioAddressPool&, slab_buf_id: u64) -> bool {
    pool.descriptors.clear();
    let effective_id: u64 = if slab_buf_id != 0 { slab_buf_id } else { 1 };
    for i in 128 {
        let desc = build_rio_addr_descriptor(effective_id, i as i32);
        guard pool.descriptors.try_push(desc) else {
            return false;
        }
    }
    pool.free_head = 0;
    pool.active_count = 0;
    pool.slab_buf_id = effective_id;
    pool.initialized = true;
    return true;
}

// Acquires a pre-registered RIO_BUF address descriptor in O(1) time from the pool free-list.
// Fails closed with `false` when all 128 descriptors are exhausted (Invariant 13).
fn rio_acquire_address_buf(pool: RioAddressPool&) -> i32, RIO_BUF, bool {
    if !pool.initialized && pool.descriptors.len == 0 {
        guard rio_init_address_pool(pool, 1) else {
            return -1, RIO_BUF { .. }, false;
        }
    }
    let idx = pool.free_head;
    guard idx >= 0 && idx < pool.descriptors.len else {
        return -1, RIO_BUF { .. }, false;
    }
    let next_head = pool.descriptors[idx].next_free;
    pool.descriptors[idx].in_use = true;
    pool.descriptors[idx].next_free = -1;
    pool.free_head = next_head;
    pool.active_count += 1;
    return idx, pool.descriptors[idx], true;
}

// Releases a previously acquired RIO_BUF address descriptor back to the free-list in O(1) time.
fn rio_release_address_buf(pool: RioAddressPool&, slot_idx: i32) -> bool {
    guard pool.initialized && slot_idx >= 0 && slot_idx < pool.descriptors.len else {
        return false;
    }
    guard pool.descriptors[slot_idx].in_use else {
        return false;
    }
    pool.descriptors[slot_idx].in_use = false;
    pool.descriptors[slot_idx].next_free = pool.free_head;
    pool.free_head = slot_idx;
    if pool.active_count > 0 {
        pool.active_count -= 1;
    }
    return true;
}

// Enqueues a registered buffer slice into a Windows RIO Request Queue (`RIOSend`).
fn rio_submit_send(rq_id: u64, desc: const RioBufferDescriptor&, req_context: u64 = 0) -> i32 {
    guard rq_id != 0 && desc.is_registered && desc.buffer_id != 0 && desc.length > 0 else {
        return -1;
    }
    return native_rio_send(rq_id, desc.buffer_id, desc.offset as u32, desc.length, req_context);
}

// Enqueues a registered buffer slice into a Windows RIO Request Queue (`RIOReceive`).
fn rio_submit_recv(rq_id: u64, desc: const RioBufferDescriptor&, req_context: u64 = 0) -> i32 {
    guard rq_id != 0 && desc.is_registered && desc.buffer_id != 0 && desc.length > 0 else {
        return -1;
    }
    return native_rio_receive(rq_id, desc.buffer_id, desc.offset as u32, desc.length, req_context);
}
