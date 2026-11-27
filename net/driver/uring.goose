// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Linux io_uring asynchronous submission and completion ring driver.
namespace net_internal;

import std;

// Native Linux io_uring C shims (liburing / kernel syscalls)
extern fn native_uring_probe() -> i32 = "wing_uring_probe";
extern fn native_uring_create(entries: u32, flags: u32) -> i64 = "wing_uring_create";
extern fn native_uring_enter(ring_fd: i64, to_submit: u32, min_complete: u32, flags: u32) -> i32 = "wing_uring_enter";
extern fn native_uring_close(ring_fd: i64) = "wing_uring_close";
extern fn native_uring_register_pbuf_ring(
    ring_fd:      i64,
    ring_addr:    u64,
    ring_entries: u32,
    bgid:         u16,
) -> i32 = "wing_uring_register_pbuf_ring";
extern fn native_uring_register_buffers(
    ring_fd: i64,
    iovecs:  const UringIovec[:],
) -> i32 = "wing_uring_register_buffers";
extern fn native_uring_unregister_buffers(ring_fd: i64) -> i32 = "wing_uring_unregister_buffers";
extern fn native_uring_has_fast_poll(ring_fd: i64) -> i32 = "wing_uring_has_fast_poll";
extern fn native_uring_stage_sqes(ring_fd: i64, sqes: const UringSqe[:]) -> i32 = "wing_uring_stage_sqes";
extern fn native_uring_submit_sqes(ring_fd: i64, sqes: const UringSqe[:]) -> i32 = "wing_uring_submit_sqes";
extern fn native_uring_wait_cqes(
    ring_fd:      i64,
    out_cqes:     UringCqe[:],
    min_complete: u32,
    timeout_ns:   i64,
) -> i32 = "wing_uring_wait_cqes";
extern fn native_uring_alloc_pbuf_ring(
    ring_fd:    i64,
    bgid:       u16,
    entries:    u32,
    buf_size:   u32,
    out_handle: u64&,
) -> i32 = "wing_uring_alloc_pbuf_ring";
extern fn native_uring_free_pbuf_ring(handle: u64) = "wing_uring_free_pbuf_ring";
extern fn native_uring_read_pbuf(handle: u64, bid: u16, len: i32, dst: u8[:]) -> i32 = "wing_uring_read_pbuf";
extern fn native_uring_recycle_pbuf(handle: u64, bid: u16) = "wing_uring_recycle_pbuf";
extern fn native_uring_slice_addr(buf: const u8[:]) -> u64 = "wing_uring_slice_addr";

// Registered I/O vector for IORING_REGISTER_BUFFERS
struct UringIovec {
    iov_base: u64 = 0,
    iov_len:  u64 = 0,
}

// io_uring opcodes
const URING_OP_NOP:          u8 = 0;
const URING_OP_READV:        u8 = 1;
const URING_OP_WRITEV:       u8 = 2;
const URING_OP_FSYNC:        u8 = 3;
const URING_OP_READ_FIXED:   u8 = 4;
const URING_OP_WRITE_FIXED:  u8 = 5;
const URING_OP_POLL_ADD:     u8 = 6;
const URING_OP_POLL_REMOVE:  u8 = 7;
const URING_OP_SENDMSG:      u8 = 9;
const URING_OP_RECVMSG:      u8 = 10;
const URING_OP_ACCEPT:       u8 = 13;
const URING_OP_ASYNC_CANCEL: u8 = 14;
const URING_OP_CONNECT:      u8 = 16;
const URING_OP_SEND:         u8 = 26;
const URING_OP_RECV:         u8 = 27;
const URING_OP_SEND_ZC:      u8 = 47; // Zero-copy send (Linux IORING_OP_SEND_ZC)

// io_uring register opcodes & kernel feature flags (uSockets io_uring engine)
const URING_REGISTER_BUFFERS:   u32 = 0;
const URING_UNREGISTER_BUFFERS: u32 = 1;
const URING_ACCEPT_MULTISHOT:   u16 = 1 << 0;
const URING_RECV_MULTISHOT:     u16 = 1 << 1; // IORING_RECV_MULTISHOT
const URING_FEAT_FAST_POLL:     u32 = 1 << 5;

// io_uring SQE flags
const URING_SQE_FIXED_FILE:    u8 = 1 << 0;
const URING_SQE_IO_DRAIN:      u8 = 1 << 1;
const URING_SQE_IO_LINK:       u8 = 1 << 2;
const URING_SQE_IO_HARDLINK:   u8 = 1 << 3;
const URING_SQE_ASYNC:         u8 = 1 << 4;
const URING_SQE_BUFFER_SELECT: u8 = 1 << 5;

// io_uring CQE flags
const URING_CQE_F_BUFFER:        u32 = 1 << 0;
const URING_CQE_F_MORE:          u32 = 1 << 1;
const URING_CQE_F_SOCK_NONEMPTY: u32 = 1 << 2;
const URING_CQE_F_NOTIF:         u32 = 1 << 3; // IORING_CQE_F_NOTIF (zero-copy DMA unpin notification)

const URING_ASYNC_CANCEL_ALL: u32 = 1 << 0;
const URING_ASYNC_CANCEL_FD:  u32 = 1 << 1;
const URING_ERR_ENOBUFS:      i32 = -105;
const URING_ERR_ECANCELED:    i32 = -125;

// io_uring submission queue entry (SQE)
struct UringSqe {
    opcode:    u8  = URING_OP_NOP,
    flags:     u8  = 0,
    ioprio:    u16 = 0,
    fd:        i32 = -1,
    off:       u64 = 0,
    addr:      u64 = 0,
    len:       u32 = 0,
    op_flags:  u32 = 0,
    user_data: u64 = 0,
    buf_index: u16 = 0,
}

// io_uring completion queue entry (CQE)
struct UringCqe {
    user_data: u64 = 0,
    res:       i32 = 0,
    flags:     u32 = 0,
}

// Prepares an SQE for zero-copy or standard send
fn uring_prep_send(sqe: UringSqe&, fd: i32, addr: u64, len: u32, tag: u64, zero_copy: bool) {
    sqe.opcode = if zero_copy { URING_OP_SEND_ZC } else { URING_OP_SEND };
    sqe.flags = 0;
    sqe.ioprio = 0;
    sqe.fd = fd;
    sqe.off = 0;
    sqe.addr = addr;
    sqe.len = len;
    sqe.op_flags = 0;
    sqe.user_data = tag;
    sqe.buf_index = 0;
}

// Prepares an SQE for receive (standard or multishot provided buffer)
fn uring_prep_recv(
    sqe:       UringSqe&,
    fd:        i32,
    addr:      u64,
    len:       u32,
    tag:       u64,
    multishot: bool,
) {
    sqe.opcode = URING_OP_RECV;
    sqe.flags = if multishot { URING_SQE_BUFFER_SELECT } else { 0 };
    sqe.ioprio = if multishot { URING_RECV_MULTISHOT } else { 0 };
    sqe.fd = fd;
    sqe.off = 0;
    sqe.addr = addr;
    sqe.len = len;
    sqe.op_flags = 0;
    sqe.user_data = tag;
    sqe.buf_index = 0;
}

// Prepares an SQE for accepting connections
fn uring_prep_accept(sqe: UringSqe&, fd: i32, tag: u64) {
    sqe.opcode = URING_OP_ACCEPT;
    sqe.flags = 0;
    sqe.ioprio = 0;
    sqe.fd = fd;
    sqe.off = 0;
    sqe.addr = 0;
    sqe.len = 0;
    sqe.op_flags = 0;
    sqe.user_data = tag;
    sqe.buf_index = 0;
}

// Prepares an SQE for asynchronous cancellation of inflight operations
fn uring_prep_cancel(sqe: UringSqe&, tag_to_cancel: u64) {
    sqe.opcode = URING_OP_ASYNC_CANCEL;
    sqe.flags = 0;
    sqe.ioprio = 0;
    sqe.fd = -1;
    sqe.off = 0;
    sqe.addr = tag_to_cancel;
    sqe.len = 0;
    sqe.op_flags = 0;
    sqe.user_data = 0;
    sqe.buf_index = 0;
}

// Prepares an SQE for multishot accept (IORING_ACCEPT_MULTISHOT) matching uSockets io_uring
// Continuously produces completions for incoming connections without resubmitting SQEs
fn uring_prep_accept_multishot(sqe: UringSqe&, fd: i32, tag: u64) {
    sqe.opcode = URING_OP_ACCEPT;
    sqe.flags = 0;
    sqe.ioprio = URING_ACCEPT_MULTISHOT;
    sqe.fd = fd;
    sqe.off = 0;
    sqe.addr = 0;
    sqe.len = 0;
    sqe.op_flags = 0;
    sqe.user_data = tag;
    sqe.buf_index = 0;
}

// Prepares a standalone SQE for multishot provided-buffer receive (`IORING_RECV_MULTISHOT`).
fn uring_prep_sqe_recv_multishot(sqe: UringSqe&, fd: i32, bgid: u16, user_data: u64) {
    sqe.opcode = URING_OP_RECV;
    sqe.flags = URING_SQE_BUFFER_SELECT;
    sqe.ioprio = URING_RECV_MULTISHOT;
    sqe.fd = fd;
    sqe.off = 0;
    sqe.addr = 0;
    sqe.len = 0;
    sqe.op_flags = 0;
    sqe.user_data = user_data;
    sqe.buf_index = bgid;
}

// Prepares an SQE for `recvmsg` (`IORING_OP_RECVMSG`).
fn uring_prep_recvmsg(sqe: UringSqe&, fd: i32, msg_ptr: u64, msg_flags: u32, user_data: u64) {
    sqe.opcode = URING_OP_RECVMSG;
    sqe.flags = 0;
    sqe.ioprio = 0;
    sqe.fd = fd;
    sqe.off = 0;
    sqe.addr = msg_ptr;
    sqe.len = 1;
    sqe.op_flags = msg_flags;
    sqe.user_data = user_data;
    sqe.buf_index = 0;
}

// Prepares an SQE for socket readiness polling (`IORING_OP_POLL_ADD`).
fn uring_prep_poll_add(sqe: UringSqe&, fd: i32, poll_mask: u32, user_data: u64) {
    sqe.opcode = URING_OP_POLL_ADD;
    sqe.flags = 0;
    sqe.ioprio = 0;
    sqe.fd = fd;
    sqe.off = 0;
    sqe.addr = 0;
    sqe.len = 0;
    sqe.op_flags = poll_mask;
    sqe.user_data = user_data;
    sqe.buf_index = 0;
}

// Prepares an SQE removing an active `POLL_ADD` registration by `target_user_data`.
fn uring_prep_poll_remove(sqe: UringSqe&, target_user_data: u64, user_data: u64) {
    sqe.opcode = URING_OP_POLL_REMOVE;
    sqe.flags = 0;
    sqe.ioprio = 0;
    sqe.fd = -1;
    sqe.off = 0;
    sqe.addr = target_user_data;
    sqe.len = 0;
    sqe.op_flags = 0;
    sqe.user_data = user_data;
    sqe.buf_index = 0;
}

// Prepares a `URING_OP_SEND` SQE referencing `buf` (which must remain pinned until CQE completion).
fn uring_prep_send_slice(sqe: UringSqe&, fd: i32, buf: const u8[:], user_data: u64) {
    uring_prep_send(sqe, fd, native_uring_slice_addr(buf), buf.len as u32, user_data, false);
}

// Submits a slice of SQEs into `ring_fd` via mmap SQ ring and `io_uring_enter`.
fn uring_submit_sqes(ring_fd: i64, sqes: const UringSqe[:]) -> i32 {
    guard ring_fd >= 0 && sqes.len > 0 else { return -1; }
    return native_uring_submit_sqes(ring_fd, sqes);
}

// Waits up to `timeout_ns` (`0` = non-blocking) for `min_complete` CQEs in `ring_fd`.
fn uring_wait_cqes(ring_fd: i64, out_cqes: UringCqe[:], min_complete: u32, timeout_ns: i64) -> i32 {
    guard ring_fd >= 0 && out_cqes.len > 0 else { return -1; }
    return native_uring_wait_cqes(ring_fd, out_cqes, min_complete, timeout_ns);
}

// Allocates and registers a kernel-managed `IORING_REGISTER_PBUF_RING` slab.
fn uring_alloc_pbuf_ring(ring_fd: i64, bgid: u16, entries: u32, buf_size: u32) -> u64, bool {
    guard ring_fd >= 0 && entries >= 1 && entries <= 32768 && (entries & (entries - 1)) == 0 && buf_size > 0 else {
        return 0, false;
    }
    var handle: u64 = 0;
    let rc = native_uring_alloc_pbuf_ring(ring_fd, bgid, entries, buf_size, handle);
    return handle, rc == 0 && handle != 0;
}

// Unregisters and unmaps a kernel-managed `pbuf_ring` slab handle.
fn uring_free_pbuf_ring(handle: u64) {
    if handle != 0 {
        native_uring_free_pbuf_ring(handle);
    }
}

// Copies up to `len` bytes from provided buffer `bid` into `dst`.
fn uring_read_pbuf(handle: u64, bid: u16, len: i32, dst: u8[:]) -> i32 {
    guard handle != 0 && len >= 0 && dst.len > 0 else { return -1; }
    return native_uring_read_pbuf(handle, bid, len, dst);
}

// Returns provided buffer `bid` to the kernel ring tail.
fn uring_recycle_pbuf(handle: u64, bid: u16) {
    if handle != 0 {
        native_uring_recycle_pbuf(handle, bid);
    }
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

// Maximum number of entries in an io_uring provided buffer ring (IORING_REGISTER_PBUF_RING).
const URING_MAX_PBUF_RING_ENTRIES: u16 = 32768;

inline fn is_valid_pbuf_ring_entries(entries: u16) -> bool {
    let entries_u32: u32 = entries;
    let mask = entries_u32 - 1;
    return entries >= 1 && entries <= URING_MAX_PBUF_RING_ENTRIES && (entries_u32 & mask) == 0;
}

// Registers a shared user-kernel provided buffer ring (IORING_REGISTER_PBUF_RING) for multishot recv.
// Validates that `entries` is a power of 2 in 1..32768 and `ring_fd >= 0`.
fn uring_register_buf_ring(ring_fd: i32, entries: u16, bgid: u16, ring_addr: u64 = 0) -> bool {
    let valid_entries = is_valid_pbuf_ring_entries(entries);
    guard ring_fd >= 0 && valid_entries else {
        return false;
    }
    return native_uring_register_pbuf_ring(ring_fd, ring_addr, entries, bgid) == 0;
}

// Provided buffer ring entry (struct io_uring_buf).
struct UringBufEntry {
    addr: u64 = 0,
    len:  u32 = 0,
    bid:  u16 = 0,
    resv: u16 = 0,
}

// Provided buffer ring state (struct io_uring_buf_ring) for zero-syscall multishot recv recycling.
struct UringBufRing {
    entries: UringBufEntry[..64] = [],
    tail:    u16                 = 0,
    mask:    u16                 = 63,
    bgid:    u16                 = 0,
}

// Republishes a consumed buffer descriptor back to the provided buffer ring tail (`io_uring_buf_ring_add` + advance).
fn uring_buf_ring_recycle(br: UringBufRing&, bid: u16, addr: u64, len: u32) {
    if br.entries.len < 64 {
        br.entries.resize(64, UringBufEntry { .. });
    }
    let idx = (br.tail & br.mask & 63) as i64;
    br.entries[idx] = UringBufEntry {
        addr: addr,
        len:  len,
        bid:  bid,
        resv: 0,
    };
    br.tail = br.tail + 1;
}

// Extracts the 16-bit provided buffer ID selected by the kernel when `URING_CQE_F_BUFFER` is set.
//
// Example:
//   cqe = UringCqe { flags: (42 << 16) | URING_CQE_F_BUFFER, .. }
//   returns: 42, true
fn extract_uring_cqe_buffer_id(cqe: const UringCqe&) -> u32, bool {
    let bid = cqe.flags >> 16;
    let has_buf = (cqe.flags & URING_CQE_F_BUFFER) != 0;
    return if has_buf { bid } else { 0 }, has_buf;
}

// Ring submission and completion tracking state
struct RingQueueState {
    ring_size:         u32            = DEFAULT_RING_SIZE,
    submissions_total: u64            = 0,
    completions_total: u64            = 0,
    active_pending:    u32            = 0,
    ring_fd:           i64            = -1,
    staged_sqes:       UringSqe[..32] = [],
}

// Prepares and stages a multishot receive SQE with provided buffer selection (`IORING_RECV_MULTISHOT`).
fn uring_prep_recv_multishot(ring: RingQueueState&, fd: i32, bgid: u16, user_data: u64) -> bool {
    guard fd >= 0 else { return false; }
    let sqe = UringSqe {
        opcode:    URING_OP_RECV,
        flags:     URING_SQE_BUFFER_SELECT,
        ioprio:    URING_RECV_MULTISHOT,
        fd:        fd,
        off:       0,
        addr:      0,
        len:       0,
        user_data: user_data,
        buf_index: bgid,
    };
    return ring.staged_sqes.try_push(sqe);
}

fn new_ring_queue_state(size: u32, ring_fd: i64 = -1) -> RingQueueState {
    return RingQueueState {
        ring_size:         if size > 0 { size } else { DEFAULT_RING_SIZE },
        submissions_total: 0,
        completions_total: 0,
        active_pending:    0,
        ring_fd:           ring_fd,
    };
}

inline fn record_sqe_submission(state: RingQueueState&, sqe: const UringSqe&, cqes: UringCqe[..32]&) {
    state.submissions_total += 1;
    state.active_pending += 1;

    let is_buf_select = sqe.opcode == URING_OP_RECV && (sqe.flags & URING_SQE_BUFFER_SELECT) != 0;
    let cqe_flags: u32 = if is_buf_select { URING_CQE_F_BUFFER | URING_CQE_F_MORE } else { 0 };
    var cqe = UringCqe {
        user_data: sqe.user_data,
        res:       sqe.len as i32,
        flags:     cqe_flags,
    };
    cqes.push(cqe);
    state.completions_total += 1;
    if state.active_pending > 0 {
        state.active_pending -= 1;
    }
}

inline fn uring_enter_if_active(ring_fd: i64, submitted: i32) {
    if ring_fd >= 0 && submitted > 0 {
        native_uring_enter(ring_fd, submitted as u32, 0, 0);
    }
}

inline fn uring_try_submit_mmap_sqe(state: RingQueueState&, sqe: const UringSqe&) -> bool {
    guard state.ring_fd >= 0 else { return false; }
    var batch: UringSqe[1] = [sqe];
    let rc = native_uring_stage_sqes(state.ring_fd, batch[..]);
    guard rc == 1 else { return false; }
    state.submissions_total += 1;
    state.active_pending += 1;
    return true;
}

inline fn uring_reap_kernel_cqes(state: RingQueueState&, cqes: UringCqe[..32]&, used_mmap: bool) {
    guard used_mmap && state.ring_fd >= 0 else { return; }
    let avail = cqes.cap - cqes.len;
    guard avail > 0 else { return; }
    var tmp: UringCqe[32] = [UringCqe { .. }; 32];
    let n = native_uring_wait_cqes(state.ring_fd, tmp[..avail], 0, 0);
    guard n > 0 else { return; }
    let count = min(n as i64, avail);
    for i in count {
        cqes.push(tmp[i]);
        state.completions_total += 1;
        if state.active_pending > 0 {
            state.active_pending -= 1;
        }
    }
}

// Submits a batch of SQEs and reaps CQE completions
fn uring_submit_batch(state: RingQueueState&, sqes: const UringSqe[:], cqes: UringCqe[..32]&) -> i32 {
    cqes.clear();
    var submitted: i32 = 0;
    var used_mmap = false;
    for i in sqes.len {
        if state.active_pending >= state.ring_size || cqes.len >= cqes.cap {
            break;
        }
        if state.ring_fd >= 0 {
            if !uring_try_submit_mmap_sqe(state, sqes[i]) {
                break;
            }
            used_mmap = true;
        } else {
            record_sqe_submission(state, sqes[i], cqes);
        }
        submitted += 1;
    }
    uring_enter_if_active(state.ring_fd, submitted);
    uring_reap_kernel_cqes(state, cqes, used_mmap);
    return submitted;
}
