// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Layer 4 Hardware Virtual Memory Management:
// 1. Guarded Arena: Hardware guard pages (PAGE_NOACCESS / PROT_NONE) trapping bounds overflow.
// 2. Instant Memory Reset: Zero-CPU-cycle page decommit (MEM_RESET / MADV_DONTNEED).
// 3. Pinned Memory: Page-locked physical RAM (VirtualLock / mlock) for kernel-bypass DMA.
// 4. Memory-Mapped Files: Direct virtual memory file serving and reading (MapViewOfFile / mmap).
// 5. Large / Huge Pages: D-TLB miss reduction for high-throughput memory arenas.
namespace core;

import std;
import core.io.types;

// Feature configuration flags for page allocation
const PAGE_MEM_GUARD_PAGE: u32 = 0x01;
const PAGE_MEM_HUGE_PAGES: u32 = 0x02;

// Native C shims (shim/page_mem.c)
extern fn native_guarded_arena_create(
    requested_capacity: u64,
    flags:              u32,
    out_handle:         u64&,
    out_capacity:       u64&,
) -> i32 = "wing_guarded_arena_create";

extern fn native_guarded_arena_destroy(handle: u64) = "wing_guarded_arena_destroy";

extern fn native_guarded_arena_write(
    handle: u64,
    offset: u64,
    src:    const u8[:],
) -> i64 = "wing_guarded_arena_write";

extern fn native_guarded_arena_read(
    handle: u64,
    offset: u64,
    dst:    u8[:],
) -> i64 = "wing_guarded_arena_read";

extern fn native_guarded_arena_reset(handle: u64) -> i32 = "wing_guarded_arena_reset";

extern fn native_guarded_arena_clear_zero(
    handle: u64,
    len:    u64,
) -> i32 = "wing_guarded_arena_clear_zero";

extern fn native_page_lock(
    handle: u64,
    offset: u64,
    len:    u64,
) -> i32 = "wing_page_lock";

extern fn native_page_unlock(
    handle: u64,
    offset: u64,
    len:    u64,
) -> i32 = "wing_page_unlock";

extern fn native_mmap_file_open(
    path:       const u8[:],
    out_handle: u64&,
    out_size:   u64&,
) -> i32 = "wing_mmap_file_open";

extern fn native_mmap_file_read(
    handle: u64,
    offset: u64,
    dst:    u8[:],
) -> i64 = "wing_mmap_file_read";

extern fn native_mmap_file_send(
    handle:  u64,
    offset:  u64,
    len:     u32,
    sock_fd: i64,
) -> i32 = "wing_mmap_file_send";

extern fn native_mmap_file_close(handle: u64) = "wing_mmap_file_close";

// Hardware-guarded memory arena with instant recycling support.
struct GuardedArena {
    handle:   u64 = 0,
    capacity: u64 = 0,
    used:     u64 = 0,
    flags:    u32 = 0,
}

// Memory-mapped read-only file view for zero-copy file serving.
struct MmapFile {
    handle: u64 = 0,
    size:   u64 = 0,
}

// Physical-page locked buffer for kernel-bypass DMA.
struct PinnedBuffer {
    handle:    u64  = 0,
    capacity:  u64  = 0,
    is_locked: bool = false,
}

// Allocates a page-aligned virtual memory arena with optional guard page and huge pages.
fn guarded_arena_init(capacity: u64, flags: u32) -> GuardedArena, bool {
    guard capacity > 0 else {
        return GuardedArena {}, false;
    }

    var handle:     u64 = 0;
    var actual_cap: u64 = 0;
    let rc = native_guarded_arena_create(capacity, flags, handle, actual_cap);
    guard rc == 0 && handle != 0 else {
        return GuardedArena {}, false;
    }

    return GuardedArena {
        handle:   handle,
        capacity: actual_cap,
        used:     0,
        flags:    flags,
    }, true;
}

// Releases virtual memory allocation and tears down guard pages.
fn guarded_arena_close(arena: GuardedArena&) {
    if arena.handle != 0 {
        native_guarded_arena_destroy(arena.handle);
        arena.handle = 0;
        arena.capacity = 0;
        arena.used = 0;
        arena.flags = 0;
    }
}

// Appends bytes from `src` to `arena` starting at current `arena.used`.
fn guarded_arena_write(arena: GuardedArena&, src: const u8[:]) -> i64, bool {
    guard arena.handle != 0 && src.len > 0 else {
        return 0, false;
    }

    let src_len = src.len as u64;
    guard src_len <= arena.capacity && arena.used <= arena.capacity - src_len else {
        return 0, false;
    }

    let written = native_guarded_arena_write(arena.handle, arena.used, src);
    guard written > 0 else {
        return 0, false;
    }

    arena.used = arena.used + (written as u64);
    return written, true;
}

// Reads bytes from `arena` at `offset` into `dst`.
fn guarded_arena_read(arena: const GuardedArena&, offset: u64, dst: u8[:]) -> i64, bool {
    guard arena.handle != 0 && dst.len > 0 else {
        return 0, false;
    }

    let dst_len = dst.len as u64;
    guard dst_len <= arena.used && offset <= arena.used - dst_len else {
        return 0, false;
    }

    let n = native_guarded_arena_read(arena.handle, offset, dst);
    guard n >= 0 else {
        return 0, false;
    }

    return n, true;
}

// Instantly resets arena memory pages via kernel decommit (MEM_RESET / MADV_DONTNEED).
// Physical frames are recycled in sub-microsecond time without CPU memset.
fn guarded_arena_reset(arena: GuardedArena&) -> bool {
    guard arena.handle != 0 else {
        return false;
    }

    let rc = native_guarded_arena_reset(arena.handle);
    guard rc == 0 else {
        return false;
    }

    arena.used = 0;
    return true;
}

// Returns the remaining unallocated capacity in bytes.
inline fn guarded_arena_available(arena: const GuardedArena&) -> u64 {
    guard arena.capacity > arena.used else {
        return 0;
    }
    return arena.capacity - arena.used;
}

// Maps a file into virtual address space for zero-copy read access.
fn mmap_file_open(path: const u8[:]) -> MmapFile, bool {
    guard path.len > 0 else {
        return MmapFile {}, false;
    }

    var handle: u64 = 0;
    var size:   u64 = 0;
    let rc = native_mmap_file_open(path, handle, size);
    guard rc == 0 && handle != 0 else {
        return MmapFile {}, false;
    }

    return MmapFile {
        handle: handle,
        size:   size,
    }, true;
}

// Unmaps and closes the memory-mapped file handle.
fn mmap_file_close(mf: MmapFile&) {
    if mf.handle != 0 {
        native_mmap_file_close(mf.handle);
        mf.handle = 0;
        mf.size = 0;
    }
}

// Reads bytes from the memory-mapped file at `offset` into `dst`.
fn mmap_file_read(mf: const MmapFile&, offset: u64, dst: u8[:]) -> i64, bool {
    guard mf.handle != 0 && dst.len > 0 else {
        return 0, false;
    }

    let dst_len = dst.len as u64;
    guard dst_len <= mf.size && offset <= mf.size - dst_len else {
        return 0, false;
    }

    let n = native_mmap_file_read(mf.handle, offset, dst);
    guard n >= 0 else {
        return 0, false;
    }

    return n, true;
}

// Sends bytes directly from memory-mapped file pages to a network socket.
fn mmap_file_send(mf: const MmapFile&, offset: u64, len: u32, sock_fd: i64) -> i32, bool {
    guard mf.handle != 0 && len > 0 && sock_fd >= 0 else {
        return 0, false;
    }

    let send_len = len as u64;
    guard send_len <= mf.size && offset <= mf.size - send_len else {
        return 0, false;
    }

    let sent = native_mmap_file_send(mf.handle, offset, len, sock_fd);
    guard sent >= 0 else {
        return sent, false;
    }

    return sent, true;
}

// Allocates and pins physical memory pages into RAM for kernel-bypass DMA.
fn pinned_buffer_init(capacity: u64) -> PinnedBuffer, bool {
    guard capacity > 0 else {
        return PinnedBuffer {}, false;
    }

    var handle:     u64 = 0;
    var actual_cap: u64 = 0;
    let rc = native_guarded_arena_create(capacity, 0, handle, actual_cap);
    guard rc == 0 && handle != 0 else {
        return PinnedBuffer {}, false;
    }

    let lock_rc = native_page_lock(handle, 0, actual_cap);
    guard lock_rc == 0 else {
        native_guarded_arena_destroy(handle);
        return PinnedBuffer {}, false;
    }

    return PinnedBuffer {
        handle:    handle,
        capacity:  actual_cap,
        is_locked: true,
    }, true;
}

// Unpins and frees physical memory pages.
fn pinned_buffer_close(pb: PinnedBuffer&) {
    if pb.handle != 0 {
        if pb.is_locked {
            native_page_unlock(pb.handle, 0, pb.capacity);
            pb.is_locked = false;
        }
        native_guarded_arena_destroy(pb.handle);
        pb.handle = 0;
        pb.capacity = 0;
    }
}

// Writes data to pinned buffer at `offset`.
fn pinned_buffer_write(pb: PinnedBuffer&, offset: u64, src: const u8[:]) -> i64, bool {
    guard pb.handle != 0 && src.len > 0 else {
        return 0, false;
    }

    let src_len = src.len as u64;
    guard src_len <= pb.capacity && offset <= pb.capacity - src_len else {
        return 0, false;
    }

    let written = native_guarded_arena_write(pb.handle, offset, src);
    guard written > 0 else {
        return 0, false;
    }

    return written, true;
}

// Reads data from pinned buffer at `offset`.
fn pinned_buffer_read(pb: const PinnedBuffer&, offset: u64, dst: u8[:]) -> i64, bool {
    guard pb.handle != 0 && dst.len > 0 else {
        return 0, false;
    }

    let dst_len = dst.len as u64;
    guard dst_len <= pb.capacity && offset <= pb.capacity - dst_len else {
        return 0, false;
    }

    let n = native_guarded_arena_read(pb.handle, offset, dst);
    guard n >= 0 else {
        return 0, false;
    }

    return n, true;
}
