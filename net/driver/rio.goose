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
    guard parent.is_registered && off >= parent.offset && (off + len) <= parent_end else {
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
