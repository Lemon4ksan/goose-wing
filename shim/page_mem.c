// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Layer 4 Virtual Memory Operations C Shim:
// 1. Hardware Guard Pages (PAGE_NOACCESS / PROT_NONE) for zero-overhead boundary trap.
// 2. Instant Memory Reset (MEM_RESET / MADV_DONTNEED) for sub-microsecond arena recycling.
// 3. Pinned Physical Pages (VirtualLock / mlock) for kernel-bypass DMA.
// 4. Memory-Mapped Static Files (MapViewOfFile / mmap) for zero-copy file transmission.
// 5. Large / Huge Pages (2 MB) for D-TLB miss reduction.

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <string.h>
#include <stdlib.h>

typedef struct {
    uint8_t *data;
    int64_t len;
} wing_bytes_rw;

typedef struct {
    const uint8_t *data;
    int64_t len;
} wing_bytes_ro;

#if defined(__wasm__)
// WebAssembly portability environment
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int32_t wing_tcp_send(int64_t sock_fd, wing_bytes_ro data);

#elif defined(_WIN32)
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winsock2.h>

#elif defined(__APPLE__)
#include <mach/mach.h>
#include <mach/vm_map.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>

#else
// Linux / POSIX
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#endif

// Flags for guarded arena allocation
#define WING_PAGE_GUARD_PAGE 0x01
#define WING_PAGE_HUGE_PAGES 0x02

typedef struct {
    uint8_t *base;
    uint64_t capacity;
    uint64_t total_mapped;
    uint32_t flags;
    bool has_guard;
    bool is_locked;
} wing_guarded_arena_t;

static uint64_t get_system_page_size(void) {
#if defined(__wasm__)
    return 65536; // 64 KB WebAssembly page
#elif defined(_WIN32)
    SYSTEM_INFO si;
    GetSystemInfo(&si);
    return (uint64_t)(si.dwPageSize ? si.dwPageSize : 4096);
#elif defined(__APPLE__)
    vm_size_t ps = 0;
    host_page_size(mach_host_self(), &ps);
    return (uint64_t)(ps ? ps : 16384);
#else
    long ps = sysconf(_SC_PAGESIZE);
    return (uint64_t)(ps > 0 ? ps : 4096);
#endif
}

static uint64_t align_page_up(uint64_t size, uint64_t page_size) {
    if (page_size == 0) page_size = 4096;
    return (size + page_size - 1) & ~(page_size - 1);
}

int32_t wing_guarded_arena_create(uint64_t requested_capacity, uint32_t flags, uint64_t *out_handle,
                                  uint64_t *out_capacity) {
    if (!out_handle || !out_capacity || requested_capacity == 0) {
        return -1;
    }

    uint64_t page_size = get_system_page_size();
    uint64_t aligned_cap = align_page_up(requested_capacity, page_size);
    bool use_guard = (flags & WING_PAGE_GUARD_PAGE) != 0;
    uint64_t total_alloc = use_guard ? (aligned_cap + page_size) : aligned_cap;

    wing_guarded_arena_t *arena = (wing_guarded_arena_t *)calloc(1, sizeof(wing_guarded_arena_t));
    if (!arena) return -2;

    arena->capacity = aligned_cap;
    arena->total_mapped = total_alloc;
    arena->flags = flags;
    arena->has_guard = use_guard;
    arena->is_locked = false;

#if defined(__wasm__)
    arena->base = (uint8_t *)calloc(1, total_alloc);
    if (!arena->base) {
        free(arena);
        return -3;
    }
#elif defined(_WIN32)
    if (use_guard) {
        // Reserve total range with NOACCESS
        uint8_t *res = (uint8_t *)VirtualAlloc(NULL, total_alloc, MEM_RESERVE, PAGE_NOACCESS);
        if (!res) {
            free(arena);
            return -3;
        }
        // Commit only the usable capacity with READWRITE; leaving the trailing page NOACCESS
        uint8_t *com = (uint8_t *)VirtualAlloc(res, aligned_cap, MEM_COMMIT, PAGE_READWRITE);
        if (!com) {
            VirtualFree(res, 0, MEM_RELEASE);
            free(arena);
            return -4;
        }
        arena->base = res;
    } else {
        DWORD alloc_flags = MEM_RESERVE | MEM_COMMIT;
        arena->base = (uint8_t *)VirtualAlloc(NULL, aligned_cap, alloc_flags, PAGE_READWRITE);
        if (!arena->base) {
            free(arena);
            return -3;
        }
    }
#else
    // Linux / macOS
    int mmap_flags = MAP_PRIVATE | MAP_ANONYMOUS;
    arena->base = (uint8_t *)mmap(NULL, total_alloc, PROT_READ | PROT_WRITE, mmap_flags, -1, 0);
    if (arena->base == MAP_FAILED) {
        arena->base = NULL;
        free(arena);
        return -3;
    }

    if (use_guard) {
        // Protect trailing guard page against any read/write access
        int rc = mprotect(arena->base + aligned_cap, page_size, PROT_NONE);
        if (rc != 0) {
            munmap(arena->base, total_alloc);
            free(arena);
            return -4;
        }
    }

#if defined(MADV_HUGEPAGE)
    if (flags & WING_PAGE_HUGE_PAGES) {
        madvise(arena->base, aligned_cap, MADV_HUGEPAGE);
    }
#endif
#endif

    *out_handle = (uint64_t)(uintptr_t)arena;
    *out_capacity = aligned_cap;
    return 0;
}

void wing_guarded_arena_destroy(uint64_t handle) {
    if (handle == 0) return;
    wing_guarded_arena_t *arena = (wing_guarded_arena_t *)(uintptr_t)handle;
    if (!arena || !arena->base) {
        if (arena) free(arena);
        return;
    }

    if (arena->is_locked) {
#if defined(__wasm__)
        // No physical page lock in WebAssembly
#elif defined(_WIN32)
        VirtualUnlock(arena->base, arena->capacity);
#else
        munlock(arena->base, arena->capacity);
#endif
        arena->is_locked = false;
    }

#if defined(__wasm__)
    free(arena->base);
#elif defined(_WIN32)
    VirtualFree(arena->base, 0, MEM_RELEASE);
#else
    munmap(arena->base, arena->total_mapped);
#endif

    arena->base = NULL;
    free(arena);
}

int64_t wing_guarded_arena_write(uint64_t handle, uint64_t offset, wing_bytes_ro src) {
    if (handle == 0 || !src.data || src.len <= 0) return 0;
    wing_guarded_arena_t *arena = (wing_guarded_arena_t *)(uintptr_t)handle;
    if (!arena || !arena->base) return -1;

    if (offset >= arena->capacity) return -2;

    uint64_t available = arena->capacity - offset;
    uint64_t to_write = ((uint64_t)src.len < available) ? (uint64_t)src.len : available;

    memcpy(arena->base + offset, src.data, (size_t)to_write);
    return (int64_t)to_write;
}

int64_t wing_guarded_arena_read(uint64_t handle, uint64_t offset, wing_bytes_rw dst) {
    if (handle == 0 || !dst.data || dst.len <= 0) return 0;
    wing_guarded_arena_t *arena = (wing_guarded_arena_t *)(uintptr_t)handle;
    if (!arena || !arena->base) return -1;

    if (offset >= arena->capacity) return -2;

    uint64_t available = arena->capacity - offset;
    uint64_t to_read = ((uint64_t)dst.len < available) ? (uint64_t)dst.len : available;

    memcpy(dst.data, arena->base + offset, (size_t)to_read);
    return (int64_t)to_read;
}

int32_t wing_guarded_arena_reset(uint64_t handle) {
    if (handle == 0) return -1;
    wing_guarded_arena_t *arena = (wing_guarded_arena_t *)(uintptr_t)handle;
    if (!arena || !arena->base) return -2;

#if defined(__wasm__)
    // WebAssembly has no kernel MMU page decommit, fallback to memset
    memset(arena->base, 0, (size_t)arena->capacity);
    return 0;
#elif defined(_WIN32)
    // Instant OS sub-microsecond page recycle without CPU-intensive memset:
    // Decommit releases physical RAM frames instantly back to OS pool.
    // Recommit provides fresh demand-zero pages on next CPU access.
    BOOL ok1 = VirtualFree(arena->base, arena->capacity, MEM_DECOMMIT);
    LPVOID p = VirtualAlloc(arena->base, arena->capacity, MEM_COMMIT, PAGE_READWRITE);
    return (ok1 && p) ? 0 : -3;
#else
    // POSIX MADV_DONTNEED: kernel drops pages from process working set;
    // subsequent accesses transparently receive clean zero-filled physical pages.
    int rc = madvise(arena->base, arena->capacity, MADV_DONTNEED);
    return (rc == 0) ? 0 : -3;
#endif
}

int32_t wing_guarded_arena_clear_zero(uint64_t handle, uint64_t len) {
    if (handle == 0) return -1;
    wing_guarded_arena_t *arena = (wing_guarded_arena_t *)(uintptr_t)handle;
    if (!arena || !arena->base) return -2;

    uint64_t to_clear = (len > arena->capacity || len == 0) ? arena->capacity : len;
    memset(arena->base, 0, (size_t)to_clear);
    return 0;
}

int32_t wing_page_lock(uint64_t handle, uint64_t offset, uint64_t len) {
    if (handle == 0) return -1;
    wing_guarded_arena_t *arena = (wing_guarded_arena_t *)(uintptr_t)handle;
    if (!arena || !arena->base) return -2;

    if (offset > arena->capacity || len > arena->capacity - offset) return -3;
    uint64_t lock_len = (len == 0) ? (arena->capacity - offset) : len;
    if (lock_len == 0) return -3;

#if defined(__wasm__)
    arena->is_locked = true;
    return 0;
#elif defined(_WIN32)
    BOOL ok = VirtualLock(arena->base + offset, lock_len);
    if (ok) {
        arena->is_locked = true;
        return 0;
    }
    return -4;
#else
    int rc = mlock(arena->base + offset, lock_len);
    if (rc == 0) {
        arena->is_locked = true;
        return 0;
    }
    return -4;
#endif
}

int32_t wing_page_unlock(uint64_t handle, uint64_t offset, uint64_t len) {
    if (handle == 0) return -1;
    wing_guarded_arena_t *arena = (wing_guarded_arena_t *)(uintptr_t)handle;
    if (!arena || !arena->base) return -2;

    if (offset > arena->capacity || len > arena->capacity - offset) return -3;
    uint64_t unlock_len = (len == 0) ? (arena->capacity - offset) : len;
    if (unlock_len == 0) return -3;

#if defined(__wasm__)
    arena->is_locked = false;
    return 0;
#elif defined(_WIN32)
    BOOL ok = VirtualUnlock(arena->base + offset, unlock_len);
    if (ok) {
        arena->is_locked = false;
        return 0;
    }
    return -4;
#else
    int rc = munlock(arena->base + offset, unlock_len);
    if (rc == 0) {
        arena->is_locked = false;
        return 0;
    }
    return -4;
#endif
}

// ---------------------------------------------------------------------------
// Technique 4: Memory-Mapped Files for Zero-Copy Serving & Inspection
// ---------------------------------------------------------------------------

typedef struct {
    uint8_t *base;
    uint64_t file_size;
#if defined(__wasm__)
    int is_malloc;
#elif defined(_WIN32)
    HANDLE file_handle;
    HANDLE mapping_handle;
#else
    int file_fd;
#endif
} wing_mmap_file_t;

int32_t wing_mmap_file_open(wing_bytes_ro path, uint64_t *out_handle, uint64_t *out_size) {
    if (!out_handle || !out_size || !path.data || path.len <= 0 || path.len >= 1024 ||
        memchr(path.data, 0, (size_t)path.len) != NULL) {
        return -1;
    }

    char path_buf[1024];
    memcpy(path_buf, path.data, (size_t)path.len);
    path_buf[path.len] = '\0';

    wing_mmap_file_t *mf = (wing_mmap_file_t *)calloc(1, sizeof(wing_mmap_file_t));
    if (!mf) return -2;

#if defined(__wasm__)
    FILE *f = fopen(path_buf, "rb");
    if (!f) {
        free(mf);
        return -3;
    }
    fseek(f, 0, SEEK_END);
    long sz = ftell(f);
    fseek(f, 0, SEEK_SET);
    if (sz < 0) {
        fclose(f);
        free(mf);
        return -4;
    }
    mf->file_size = (uint64_t)sz;
    mf->base = (uint8_t *)malloc(mf->file_size ? mf->file_size : 1);
    if (!mf->base) {
        fclose(f);
        free(mf);
        return -5;
    }
    if (sz > 0) {
        size_t read_bytes = fread(mf->base, 1, (size_t)sz, f);
        (void)read_bytes;
    }
    fclose(f);
    mf->is_malloc = 1;
#elif defined(_WIN32)
    HANDLE hFile =
        CreateFileA(path_buf, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        free(mf);
        return -3;
    }

    LARGE_INTEGER liSize;
    if (!GetFileSizeEx(hFile, &liSize)) {
        CloseHandle(hFile);
        free(mf);
        return -4;
    }

    mf->file_size = (uint64_t)liSize.QuadPart;
    if (mf->file_size == 0) {
        // Zero-length file cannot be mapped via CreateFileMapping
        mf->file_handle = hFile;
        mf->mapping_handle = NULL;
        mf->base = NULL;
        *out_handle = (uint64_t)(uintptr_t)mf;
        *out_size = 0;
        return 0;
    }

    HANDLE hMap = CreateFileMappingA(hFile, NULL, PAGE_READONLY, 0, 0, NULL);
    if (!hMap) {
        CloseHandle(hFile);
        free(mf);
        return -5;
    }

    LPVOID base = MapViewOfFile(hMap, FILE_MAP_READ, 0, 0, 0);
    if (!base) {
        CloseHandle(hMap);
        CloseHandle(hFile);
        free(mf);
        return -6;
    }

    mf->file_handle = hFile;
    mf->mapping_handle = hMap;
    mf->base = (uint8_t *)base;
#else
    // Linux / macOS
    int fd = open(path_buf, O_RDONLY);
    if (fd < 0) {
        free(mf);
        return -3;
    }

    struct stat st;
    if (fstat(fd, &st) < 0) {
        close(fd);
        free(mf);
        return -4;
    }

    mf->file_size = (uint64_t)st.st_size;
    if (mf->file_size == 0) {
        mf->file_fd = fd;
        mf->base = NULL;
        *out_handle = (uint64_t)(uintptr_t)mf;
        *out_size = 0;
        return 0;
    }

    void *base = mmap(NULL, (size_t)mf->file_size, PROT_READ, MAP_SHARED, fd, 0);
    if (base == MAP_FAILED) {
        close(fd);
        free(mf);
        return -5;
    }

    mf->file_fd = fd;
    mf->base = (uint8_t *)base;
#endif

    *out_handle = (uint64_t)(uintptr_t)mf;
    *out_size = mf->file_size;
    return 0;
}

int64_t wing_mmap_file_read(uint64_t handle, uint64_t offset, wing_bytes_rw dst) {
    if (handle == 0 || !dst.data || dst.len <= 0) return 0;
    wing_mmap_file_t *mf = (wing_mmap_file_t *)(uintptr_t)handle;
    if (!mf || (!mf->base && mf->file_size > 0)) return -1;

    if (offset >= mf->file_size) return 0;

    uint64_t available = mf->file_size - offset;
    uint64_t to_read = ((uint64_t)dst.len < available) ? (uint64_t)dst.len : available;

    if (to_read > 0 && mf->base) {
        memcpy(dst.data, mf->base + offset, (size_t)to_read);
    }
    return (int64_t)to_read;
}

int32_t wing_mmap_file_send(uint64_t handle, uint64_t offset, uint32_t len, int64_t sock_fd) {
    if (handle == 0 || len == 0 || sock_fd < 0) return 0;
    wing_mmap_file_t *mf = (wing_mmap_file_t *)(uintptr_t)handle;
    if (!mf || (!mf->base && mf->file_size > 0)) return -1;

    if (offset >= mf->file_size) return -2;

    uint64_t available = mf->file_size - offset;
    uint32_t to_send = (len < (uint32_t)available) ? len : (uint32_t)available;
    if (to_send == 0 || !mf->base) return 0;

#if defined(__wasm__)
    wing_bytes_ro slice = {mf->base + offset, (int64_t)to_send};
    return wing_tcp_send(sock_fd, slice);
#elif defined(_WIN32)
    int sent = send((SOCKET)sock_fd, (const char *)(mf->base + offset), (int)to_send, 0);
    return (sent >= 0) ? sent : -1;
#else
    ssize_t sent = send((int)sock_fd, mf->base + offset, (size_t)to_send, 0);
    return (sent >= 0) ? (int32_t)sent : -1;
#endif
}

void wing_mmap_file_close(uint64_t handle) {
    if (handle == 0) return;
    wing_mmap_file_t *mf = (wing_mmap_file_t *)(uintptr_t)handle;
    if (!mf) return;

#if defined(__wasm__)
    if (mf->base) free(mf->base);
#elif defined(_WIN32)
    if (mf->base) {
        UnmapViewOfFile(mf->base);
    }
    if (mf->mapping_handle) {
        CloseHandle(mf->mapping_handle);
    }
    if (mf->file_handle && mf->file_handle != INVALID_HANDLE_VALUE) {
        CloseHandle(mf->file_handle);
    }
#else
    if (mf->base && mf->file_size > 0) {
        munmap(mf->base, (size_t)mf->file_size);
    }
    if (mf->file_fd >= 0) {
        close(mf->file_fd);
    }
#endif

    mf->base = NULL;
    free(mf);
}
