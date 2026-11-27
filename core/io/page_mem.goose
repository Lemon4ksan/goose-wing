// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Layer 4 Hardware Virtual Memory Management:
// Memory-Mapped Files: Direct virtual memory file serving and reading (MapViewOfFile / mmap).
namespace core;

import std;
import core.io.types;
import core.bytes.search;

// Native C shims (shim/page_mem.c)
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

// Memory-mapped read-only file view for zero-copy file serving.
struct MmapFile {
    handle: u64 = 0,
    size:   u64 = 0,
}

// Maps a file into virtual address space for zero-copy read access.
fn mmap_file_open(path: const u8[:]) -> MmapFile, bool {
    guard path.len > 0 && path.len < 1024 && !contains_byte(path, 0) else {
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
