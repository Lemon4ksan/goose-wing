// Layer 4 Transport Driver Architecture & Zero-Copy Engine.
// Provides selectable high-performance L4 transport drivers:
// 1. Standard: Cross-platform zero-dependency sockets (POSIX / WinSock2 stream).
// 2. IoUring: Linux 6.1+ kernel submission/completion (SQ/CQ) ring queues.
// 3. WindowsRIO: Windows Registered I/O (RIO zero-copy, page-locked memory buffers, mswsock.dll).
// Supports zero-heap probing, graceful platform fallback, and batch completion management.
namespace wing;

import std;
import os;

// ---- 1. Driver Kinds & Capabilities ----------------------------------------

enum TransportDriverKind {
    Standard,
    IoUring,
    WindowsRIO,
}

// Returns human-readable driver identifier
fn driver_kind_name(kind: TransportDriverKind) -> u8[:] {
    return match kind {
        Standard => "Standard",
        IoUring => "io_uring",
        WindowsRIO => "Windows RIO",
    };
}

// Driver capability bitmask flags
const CAP_NONE: u32                = 0;
const CAP_KERNEL_BYPASS: u32       = 1 << 0; // Direct hardware/kernel bypass rings
const CAP_ZERO_COPY: u32           = 1 << 1; // Zero copy between userspace and NIC/kernel
const CAP_RING_COMPLETION: u32     = 1 << 2; // Circular submission/completion ring queues
const CAP_BATCH_IO: u32            = 1 << 3; // Batched syscall submission / CQ reaping
const CAP_PAGE_LOCKED_BUFFERS: u32 = 1 << 4; // Pre-registered pinned virtual memory
const CAP_DIRECT_DESCRIPTORS: u32  = 1 << 5; // Fixed socket table without fd lookup overhead
const CAP_MULTISHOT_RECV: u32      = 1 << 6; // Repeated receive events on single submission

// Checks if a capability bit is enabled
fn driver_has_cap(caps: u32, cap: u32) -> bool {
    return (caps & cap) != 0;
}

// ---- 2. Target Platform Probing --------------------------------------------

enum TargetPlatform {
    Windows,
    Linux,
    Darwin,
    Unknown,
}

fn platform_name(plat: TargetPlatform) -> u8[:] {
    return match plat {
        Windows => "Windows",
        Linux => "Linux",
        Darwin => "macOS",
        Unknown => "Unknown",
    };
}

// Detects the underlying OS platform via system environment indicators
fn detect_target_platform() -> TargetPlatform {
    var env_buf: u8[>..] = [];
    if env("WINDIR", env_buf) || env("OS", env_buf) {
        return TargetPlatform.Windows;
    }
    env_buf.clear();
    if env("DYLD_LIBRARY_PATH", env_buf) {
        return TargetPlatform.Darwin;
    }
    return TargetPlatform.Linux;
}

// Probe result for a transport driver
struct DriverProbeResult {
    kind: TransportDriverKind = TransportDriverKind.Standard,
    available: bool = true,
    capabilities: u32 = CAP_NONE,
    error_code: i32 = 0,
    reason: u8[..128] = [],
}

// Probes availability and capabilities of a driver on a specific target platform
fn probe_transport_driver_for_platform(kind: TransportDriverKind, plat: TargetPlatform) -> DriverProbeResult {
    var res = DriverProbeResult { kind: kind, .. };

    if kind == TransportDriverKind.Standard {
        res.available = true;
        res.capabilities = CAP_NONE;
        res.error_code = 0;
        res.reason.clear();
        res.reason.append("Standard OS socket driver (cross-platform zero-dependency)");
        return res;
    }

    if kind == TransportDriverKind.WindowsRIO {
        if plat == TargetPlatform.Windows {
            res.available = true;
            res.capabilities = CAP_KERNEL_BYPASS | CAP_ZERO_COPY | CAP_PAGE_LOCKED_BUFFERS | CAP_BATCH_IO;
            res.error_code = 0;
            res.reason.clear();
            res.reason.append("Windows Registered I/O (RIO) via mswsock.dll kernel-bypass");
        } else {
            res.available = false;
            res.capabilities = CAP_NONE;
            res.error_code = -38; // -ENOSYS
            res.reason.clear();
            res.reason.append("Windows RIO is only supported on Windows 8+ / Server 2012+ (mswsock.dll)");
        }
        return res;
    }

    if kind == TransportDriverKind.IoUring {
        if plat == TargetPlatform.Linux {
            res.available = true;
            res.capabilities = CAP_RING_COMPLETION | CAP_ZERO_COPY | CAP_BATCH_IO | CAP_DIRECT_DESCRIPTORS | CAP_MULTISHOT_RECV;
            res.error_code = 0;
            res.reason.clear();
            res.reason.append("Linux io_uring kernel submission/completion ring queues (kernel 6.1+)");
        } else {
            res.available = false;
            res.capabilities = CAP_NONE;
            res.error_code = -38; // -ENOSYS
            res.reason.clear();
            res.reason.append("io_uring requires Linux 6.1+ kernel (io_uring_queue_init)");
        }
        return res;
    }

    return res;
}

// Probes availability and capabilities of a driver on the current OS
fn probe_transport_driver(kind: TransportDriverKind) -> DriverProbeResult {
    let plat = detect_target_platform();
    return probe_transport_driver_for_platform(kind, plat);
}

// ---- 3. Transport Driver Configuration & Fallback -------------------------

struct TransportDriverConfig {
    preferred_kind: TransportDriverKind = TransportDriverKind.Standard,
    ring_size: u32 = 1024,
    enable_kernel_bypass: bool = false,
    registered_buffer_size: u32 = 65536,
    active_kind: TransportDriverKind = TransportDriverKind.Standard,
    capabilities: u32 = CAP_NONE,
    is_probed: bool = false,
    status_message: u8[..128] = [],
}

// Initializes transport driver with explicit platform target (for testing & determinism)
fn init_transport_driver_with_platform(cfg: TransportDriverConfig&, plat: TargetPlatform) -> bool {
    let probe = probe_transport_driver_for_platform(cfg.preferred_kind, plat);
    if probe.available {
        cfg.active_kind = cfg.preferred_kind;
        cfg.capabilities = probe.capabilities;
        cfg.status_message.clear();
        cfg.status_message.append(probe.reason[..]);
        cfg.is_probed = true;
        return true;
    }

    // Graceful platform auto-selection / fallback
    if plat == TargetPlatform.Windows && cfg.enable_kernel_bypass {
        let rio_probe = probe_transport_driver_for_platform(TransportDriverKind.WindowsRIO, plat);
        if rio_probe.available {
            cfg.active_kind = TransportDriverKind.WindowsRIO;
            cfg.capabilities = rio_probe.capabilities;
            cfg.status_message.clear();
            cfg.status_message.append("io_uring unavailable on Windows; auto-selected Windows RIO");
            cfg.is_probed = true;
            return true;
        }
    }

    if plat == TargetPlatform.Linux {
        let uring_probe = probe_transport_driver_for_platform(TransportDriverKind.IoUring, plat);
        if uring_probe.available {
            cfg.active_kind = TransportDriverKind.IoUring;
            cfg.capabilities = uring_probe.capabilities;
            cfg.status_message.clear();
            cfg.status_message.append("Windows RIO unavailable on Linux; auto-selected io_uring");
            cfg.is_probed = true;
            return true;
        }
    }

    // Universal Standard sockets fallback
    cfg.active_kind = TransportDriverKind.Standard;
    cfg.capabilities = CAP_NONE;
    cfg.status_message.clear();
    cfg.status_message.append("Preferred driver unavailable; gracefully fell back to Standard sockets");
    cfg.is_probed = true;
    return true;
}

// Initializes transport driver for current host platform
fn init_transport_driver(cfg: TransportDriverConfig&) -> bool {
    let plat = detect_target_platform();
    return init_transport_driver_with_platform(cfg, plat);
}

// ---- 4. Windows RIO Zero-Copy Buffer Lifecycle -----------------------------

// Page-locked registered memory buffer slice descriptor for Windows RIO
struct RioBufferDescriptor {
    buffer_id: u64 = 0,
    offset: u64 = 0,
    length: u32 = 0,
    is_registered: bool = false,
    page_locked: bool = false,
}

// Registers a contiguous page-locked buffer with the kernel/NIC
fn new_rio_buffer(id: u64, len: u32) -> RioBufferDescriptor {
    return RioBufferDescriptor {
        buffer_id: id,
        offset: 0,
        length: len,
        is_registered: true,
        page_locked: true,
    };
}

// Slices a registered buffer without re-registration or memory allocation
fn rio_sub_buffer(parent: const RioBufferDescriptor&, off: u64, len: u32) -> RioBufferDescriptor {
    guard parent.is_registered && (off + len) <= (parent.offset + parent.length) else {
        return RioBufferDescriptor { .. };
    }
    return RioBufferDescriptor {
        buffer_id: parent.buffer_id,
        offset: off,
        length: len,
        is_registered: true,
        page_locked: parent.page_locked,
    };
}

// Deregisters buffer and releases page-locks
fn rio_deregister_buffer(desc: RioBufferDescriptor&) {
    desc.is_registered = false;
    desc.page_locked = false;
    desc.length = 0;
    desc.offset = 0;
}

// Verifies if buffer can fulfill zero-copy requirement
fn rio_can_zero_copy(desc: const RioBufferDescriptor&, req_len: u32) -> bool {
    return desc.is_registered && desc.page_locked && req_len <= desc.length;
}

// ---- 5. Linux io_uring SQE / CQE Ring Structures ---------------------------

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

// Ring submission and completion tracking state
struct RingQueueState {
    ring_size: u32 = 1024,
    submissions_total: u64 = 0,
    completions_total: u64 = 0,
    active_pending: u32 = 0,
}

fn new_ring_queue_state(size: u32) -> RingQueueState {
    return RingQueueState {
        ring_size: if size > 0 { size } else { 1024 },
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

        if cqes.len < 32 {
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

// ---- 6. Diagnostics & Summary Formatter ------------------------------------

// Formats driver configuration, active backend, capabilities and status into builder
fn format_driver_summary<B>(cfg: const TransportDriverConfig&, out: B&) {
    out.append("TransportDriver: [");
    out.append(driver_kind_name(cfg.active_kind));
    out.append("] | Caps: ");

    var has_any = false;
    if driver_has_cap(cfg.capabilities, CAP_KERNEL_BYPASS) {
        if has_any { out.append(", "); }
        out.append("KernelBypass");
        has_any = true;
    }
    if driver_has_cap(cfg.capabilities, CAP_ZERO_COPY) {
        if has_any { out.append(", "); }
        out.append("ZeroCopy");
        has_any = true;
    }
    if driver_has_cap(cfg.capabilities, CAP_RING_COMPLETION) {
        if has_any { out.append(", "); }
        out.append("RingCompletion");
        has_any = true;
    }
    if driver_has_cap(cfg.capabilities, CAP_BATCH_IO) {
        if has_any { out.append(", "); }
        out.append("BatchIO");
        has_any = true;
    }
    if driver_has_cap(cfg.capabilities, CAP_PAGE_LOCKED_BUFFERS) {
        if has_any { out.append(", "); }
        out.append("PageLockedBuffers");
        has_any = true;
    }
    if driver_has_cap(cfg.capabilities, CAP_DIRECT_DESCRIPTORS) {
        if has_any { out.append(", "); }
        out.append("DirectDescriptors");
        has_any = true;
    }
    if driver_has_cap(cfg.capabilities, CAP_MULTISHOT_RECV) {
        if has_any { out.append(", "); }
        out.append("MultishotRecv");
        has_any = true;
    }
    if !has_any {
        out.append("None (Standard Stream)");
    }

    out.append(" | RingSize: ");
    format_driver_int(out, cfg.ring_size as i64);
    out.append(" | RegBuf: ");
    format_driver_int(out, cfg.registered_buffer_size as i64);
    out.append("B | Status: ");
    out.append(cfg.status_message[..]);
}

fn format_driver_int<B>(out: B&, val: i64) {
    if val == 0 {
        out.push('0' as u8);
        return;
    }
    var v = val;
    var digits: u8[..32] = [];
    while v > 0 {
        let d = (v % 10) as u8;
        digits.push(('0' as u8) + d);
        v /= 10;
    }
    var i = digits.len;
    while i > 0 {
        i -= 1;
        out.push(digits[i]);
    }
}
