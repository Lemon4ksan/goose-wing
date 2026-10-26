// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Linux io_uring asynchronous submission and completion ring driver.
namespace internal;

import std;

// Native Linux io_uring C shims (liburing / kernel syscalls)
extern "wing_uring_probe" fn native_uring_probe() -> i32;
extern "wing_uring_create" fn native_uring_create(entries: u32, flags: u32) -> i64;
extern "wing_uring_enter" fn native_uring_enter(ring_fd: i64, to_submit: u32, min_complete: u32, flags: u32) -> i32;
extern "wing_uring_close" fn native_uring_close(ring_fd: i64);
extern "wing_uring_register_pbuf_ring" fn native_uring_register_pbuf_ring(ring_fd: i64, ring_addr: u64, ring_entries: u32, bgid: u16) -> i32;
extern "wing_uring_register_buffers" fn native_uring_register_buffers(ring_fd: i64, iovecs: const UringIovec[:]) -> i32;
extern "wing_uring_unregister_buffers" fn native_uring_unregister_buffers(ring_fd: i64) -> i32;
extern "wing_uring_has_fast_poll" fn native_uring_has_fast_poll(ring_fd: i64) -> i32;

// Registered I/O vector for IORING_REGISTER_BUFFERS
struct UringIovec {
    iov_base: u64 = 0,
    iov_len: u64 = 0,
}

// io_uring opcodes
const URING_OP_NOP: u8          = 0;
const URING_OP_READV: u8        = 1;
const URING_OP_WRITEV: u8       = 2;
const URING_OP_FSYNC: u8        = 3;
const URING_OP_READ_FIXED: u8   = 4;
const URING_OP_WRITE_FIXED: u8  = 5;
const URING_OP_POLL_ADD: u8     = 6;
const URING_OP_POLL_REMOVE: u8  = 7;
const URING_OP_SENDMSG: u8      = 9;
const URING_OP_RECVMSG: u8      = 10;
const URING_OP_ACCEPT: u8       = 13;
const URING_OP_ASYNC_CANCEL: u8 = 14;
const URING_OP_CONNECT: u8      = 16;
const URING_OP_SEND: u8         = 26;
const URING_OP_RECV: u8         = 27;
const URING_OP_SEND_ZC: u8      = 31; // Zero-copy send

// io_uring register opcodes & kernel feature flags (uSockets io_uring engine)
const URING_REGISTER_BUFFERS: u32    = 0;
const URING_UNREGISTER_BUFFERS: u32  = 1;
const URING_ACCEPT_MULTISHOT: u16    = 1 << 0;
const URING_FEAT_FAST_POLL: u32      = 1 << 5;

// io_uring SQE flags
const URING_SQE_FIXED_FILE: u8    = 1 << 0;
const URING_SQE_IO_DRAIN: u8      = 1 << 1;
const URING_SQE_IO_LINK: u8       = 1 << 2;
const URING_SQE_IO_HARDLINK: u8   = 1 << 3;
const URING_SQE_ASYNC: u8         = 1 << 4;
const URING_SQE_BUFFER_SELECT: u8 = 1 << 5;

// io_uring CQE flags
const URING_CQE_F_BUFFER: u32        = 1 << 0;
const URING_CQE_F_MORE: u32          = 1 << 1;
const URING_CQE_F_SOCK_NONEMPTY: u32 = 1 << 2;

// io_uring submission queue entry (SQE)
struct UringSqe {
    opcode: u8 = URING_OP_NOP,
    flags: u8 = 0,
    ioprio: u16 = 0,
    fd: i32 = -1,
    off: u64 = 0,
    addr: u64 = 0,
    len: u32 = 0,
    user_data: u64 = 0,
    buf_index: u16 = 0,
}

// io_uring completion queue entry (CQE)
struct UringCqe {
    user_data: u64 = 0,
    res: i32 = 0,
    flags: u32 = 0,
}

// Prepares an SQE for zero-copy or standard send
fn uring_prep_send(sqe: UringSqe&, fd: i32, addr: u64, len: u32, tag: u64, zero_copy: bool) {
    sqe.opcode = if zero_copy { URING_OP_SEND_ZC } else { URING_OP_SEND };
    sqe.flags = 0;
    sqe.fd = fd;
    sqe.addr = addr;
    sqe.len = len;
    sqe.user_data = tag;
}

// Prepares an SQE for receive (standard or multishot provided buffer)
fn uring_prep_recv(sqe: UringSqe&, fd: i32, addr: u64, len: u32, tag: u64, multishot: bool) {
    sqe.opcode = URING_OP_RECV;
    sqe.flags = if multishot { URING_SQE_BUFFER_SELECT } else { 0 };
    sqe.fd = fd;
    sqe.addr = addr;
    sqe.len = len;
    sqe.user_data = tag;
}

// Prepares an SQE for accepting connections
fn uring_prep_accept(sqe: UringSqe&, fd: i32, tag: u64) {
    sqe.opcode = URING_OP_ACCEPT;
    sqe.flags = 0;
    sqe.fd = fd;
    sqe.addr = 0;
    sqe.len = 0;
    sqe.user_data = tag;
}

// Prepares an SQE for asynchronous cancellation of inflight operations
fn uring_prep_cancel(sqe: UringSqe&, tag_to_cancel: u64) {
    sqe.opcode = URING_OP_ASYNC_CANCEL;
    sqe.flags = 0;
    sqe.fd = -1;
    sqe.addr = tag_to_cancel;
    sqe.len = 0;
    sqe.user_data = 0;
}

// Prepares an SQE for multishot accept (IORING_ACCEPT_MULTISHOT) matching uSockets io_uring
// Continuously produces completions for incoming connections without resubmitting SQEs
fn uring_prep_accept_multishot(sqe: UringSqe&, fd: i32, tag: u64) {
    sqe.opcode = URING_OP_ACCEPT;
    sqe.flags = 0;
    sqe.ioprio = URING_ACCEPT_MULTISHOT;
    sqe.fd = fd;
    sqe.addr = 0;
    sqe.len = 0;
    sqe.user_data = tag;
}

// Registers fixed preallocated buffers with io_uring (IORING_REGISTER_BUFFERS).
// Eliminates page pinning and page table traversal overhead on high-frequency packet processing.
fn uring_register_buffers(ring_fd: i64, iovecs: const UringIovec[:]) -> i32 {
    guard ring_fd >= 0 && iovecs.len > 0 else { return -1; }
    return native_uring_register_buffers(ring_fd, iovecs);
}

// Unregisters fixed buffers previously registered with uring_register_buffers
fn uring_unregister_buffers(ring_fd: i64) -> i32 {
    guard ring_fd >= 0 else { return -1; }
    return native_uring_unregister_buffers(ring_fd);
}

// Checks if Linux kernel supports IORING_FEAT_FAST_POLL to eliminate userland wakeups
fn uring_has_fast_poll(ring_fd: i64) -> bool {
    return native_uring_has_fast_poll(ring_fd) != 0;
}

// Ring submission and completion tracking state
struct RingQueueState {
    ring_size: u32 = DEFAULT_RING_SIZE,
    submissions_total: u64 = 0,
    completions_total: u64 = 0,
    active_pending: u32 = 0,
}

fn new_ring_queue_state(size: u32) -> RingQueueState {
    return RingQueueState {
        ring_size: if size > 0 { size } else { DEFAULT_RING_SIZE },
        submissions_total: 0,
        completions_total: 0,
        active_pending: 0,
    };
}

// Submits a batch of SQEs and reaps CQE completions
fn uring_submit_batch(state: RingQueueState&, sqes: const UringSqe[:], cqes: UringCqe[..32]&) -> i32 {
    cqes.clear();
    var submitted: i32 = 0;
    for i in sqes.len {
        if state.active_pending >= state.ring_size {
            break;
        }
        let sqe = sqes[i];
        state.submissions_total += 1;
        state.active_pending += 1;
        submitted += 1;

        if cqes.len < cqes.cap {
            var cqe = UringCqe {
                user_data: sqe.user_data,
                res: sqe.len as i32,
                flags: if sqe.opcode == URING_OP_RECV && (sqe.flags & URING_SQE_BUFFER_SELECT) != 0 {
                    URING_CQE_F_BUFFER | URING_CQE_F_MORE
                } else {
                    0
                },
            };
            cqes.push(cqe);
            state.completions_total += 1;
            if state.active_pending > 0 {
                state.active_pending -= 1;
            }
        }
    }
    return submitted;
}
