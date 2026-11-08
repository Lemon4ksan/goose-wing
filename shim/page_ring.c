// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Layer 4 Virtual Memory Page-Mirrored Ring Buffer C Shim.
// Cross-platform support for hardware virtual page aliasing:
// - Windows: VirtualAlloc2 placeholder split + MapViewOfFile3 (with MapViewOfFileEx fallback).
// - Linux: memfd_create / shm_open + mmap(MAP_SHARED | MAP_FIXED).
// - macOS / Darwin: vm_allocate + vm_remap (Mach VM page aliasing).
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
#include <stdlib.h>
#include <string.h>

// Forward declarations from shim/tcp.c for WebAssembly virtual socket networking
int32_t wing_tcp_send(int64_t sock_fd, wing_bytes_ro data);
int32_t wing_tcp_recv(int64_t sock_fd, wing_bytes_rw buf, uint32_t timeout_ms);

#elif defined(_WIN32)
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winsock2.h>

#ifndef MEM_RESERVE_PLACEHOLDER
#define MEM_RESERVE_PLACEHOLDER 0x00040000
#endif
#ifndef MEM_PRESERVE_PLACEHOLDER
#define MEM_PRESERVE_PLACEHOLDER 0x00000002
#endif
#ifndef MEM_REPLACE_PLACEHOLDER
#define MEM_REPLACE_PLACEHOLDER 0x00004000
#endif

typedef PVOID(WINAPI *pfnVirtualAlloc2)(HANDLE, PVOID, SIZE_T, ULONG, ULONG, void *, ULONG);
typedef BOOL(WINAPI *pfnVirtualFreeEx)(HANDLE, PVOID, SIZE_T, ULONG);
typedef PVOID(WINAPI *pfnMapViewOfFile3)(HANDLE, HANDLE, PVOID, ULONG64, SIZE_T, ULONG, ULONG, void *, ULONG);

#elif defined(__APPLE__)
#include <stdio.h>
#include <mach/mach.h>
#include <mach/vm_map.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <unistd.h>
#else
// Linux / POSIX
#include <stdio.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <sys/socket.h>
#include <unistd.h>
#include <fcntl.h>
#endif

// Forward declaration from shim/simd.c
int64_t wing_fast_find_crlfcrlf(wing_bytes_ro slice);
int64_t wing_simd_find_crlf(wing_bytes_ro slice);

typedef struct {
    uint8_t *base;
    uint32_t capacity;
#if defined(__wasm__)
    int dummy;
#elif defined(_WIN32)
    HANDLE mapping_handle;
    int is_placeholder;
#elif defined(__APPLE__)
    int is_mach_vm;
#else
    int shm_fd;
#endif
} wing_page_ring_t;

static uint32_t align_ring_capacity(uint32_t req) {
#if defined(__wasm__)
    const uint32_t gran = 65536; // WebAssembly 64 KB linear memory page size
#elif defined(_WIN32)
    const uint32_t gran = 65536; // Windows 64 KB allocation granularity
#elif defined(__APPLE__)
    const uint32_t gran = 16384; // Apple Silicon 16 KB page size safe ceiling
#else
    const uint32_t gran = 65536; // 64 KB for Linux huge page / standard page harmony
#endif
    if (req < gran) return gran;
    return ((req + gran - 1) / gran) * gran;
}

int32_t wing_page_ring_create(uint32_t min_capacity, uint64_t *out_handle, uint32_t *out_capacity) {
    if (!out_handle || !out_capacity) return -1;
    uint32_t cap = align_ring_capacity(min_capacity);

    wing_page_ring_t *ring = (wing_page_ring_t *)calloc(1, sizeof(wing_page_ring_t));
    if (!ring) return -1;
    ring->capacity = cap;

#if defined(__wasm__)
    // In WebAssembly, hardware MMU remapping is unavailable.
    // Allocate 2 * cap in linear memory and maintain mirrored writes.
    ring->base = (uint8_t *)calloc(2 * (size_t)cap, 1);
    if (!ring->base) {
        free(ring);
        return -1;
    }
    *out_handle = (uint64_t)(uintptr_t)ring;
    *out_capacity = cap;
    return 0;

#elif defined(_WIN32)
    HMODULE hKb = GetModuleHandleW(L"kernelbase.dll");
    pfnVirtualAlloc2 pVirtualAlloc2 = (pfnVirtualAlloc2)(void *)GetProcAddress(hKb, "VirtualAlloc2");
    pfnVirtualFreeEx pVirtualFreeEx = (pfnVirtualFreeEx)(void *)GetProcAddress(hKb, "VirtualFreeEx");
    pfnMapViewOfFile3 pMapViewOfFile3 = (pfnMapViewOfFile3)(void *)GetProcAddress(hKb, "MapViewOfFile3");

    HANDLE hMap = CreateFileMappingW(INVALID_HANDLE_VALUE, NULL, PAGE_READWRITE, 0, cap, NULL);
    if (!hMap) {
        free(ring);
        return -1;
    }
    ring->mapping_handle = hMap;

    if (pVirtualAlloc2 && pVirtualFreeEx && pMapViewOfFile3) {
        PVOID ph = pVirtualAlloc2(GetCurrentProcess(), NULL, 2 * (SIZE_T)cap, MEM_RESERVE | MEM_RESERVE_PLACEHOLDER,
                                  PAGE_NOACCESS, NULL, 0);
        if (ph) {
            pVirtualFreeEx(GetCurrentProcess(), ph, cap, MEM_RELEASE | MEM_PRESERVE_PLACEHOLDER);
            PVOID v1 = pMapViewOfFile3(hMap, GetCurrentProcess(), ph, 0, cap, MEM_REPLACE_PLACEHOLDER, PAGE_READWRITE,
                                       NULL, 0);
            PVOID v2 = pMapViewOfFile3(hMap, GetCurrentProcess(), (char *)ph + cap, 0, cap, MEM_REPLACE_PLACEHOLDER,
                                       PAGE_READWRITE, NULL, 0);
            if (v1 && v2 && v2 == (char *)v1 + cap) {
                ring->base = (uint8_t *)ph;
                ring->is_placeholder = 1;
                *out_handle = (uint64_t)(uintptr_t)ring;
                *out_capacity = cap;
                return 0;
            }
            if (v1) UnmapViewOfFile(v1);
            if (v2) UnmapViewOfFile(v2);
        }
    }

    // Fallback: VirtualAlloc reserve/release + MapViewOfFileEx
    for (int i = 0; i < 16; i++) {
        PVOID p = VirtualAlloc(NULL, 2 * (SIZE_T)cap, MEM_RESERVE, PAGE_NOACCESS);
        if (!p) continue;
        VirtualFree(p, 0, MEM_RELEASE);
        PVOID v1 = MapViewOfFileEx(hMap, FILE_MAP_ALL_ACCESS, 0, 0, cap, p);
        PVOID v2 = MapViewOfFileEx(hMap, FILE_MAP_ALL_ACCESS, 0, 0, cap, (char *)p + cap);
        if (v1 == p && v2 == (char *)p + cap) {
            ring->base = (uint8_t *)p;
            ring->is_placeholder = 0;
            *out_handle = (uint64_t)(uintptr_t)ring;
            *out_capacity = cap;
            return 0;
        }
        if (v1) UnmapViewOfFile(v1);
        if (v2) UnmapViewOfFile(v2);
    }

    CloseHandle(hMap);
    free(ring);
    return -1;

#elif defined(__APPLE__)
    mach_port_t self = mach_task_self();
    vm_address_t addr = 0;
    kern_return_t kr = vm_allocate(self, &addr, 2 * (vm_size_t)cap, VM_FLAGS_ANYWHERE);
    if (kr == KERN_SUCCESS) {
        kr = vm_deallocate(self, addr + cap, cap);
        if (kr == KERN_SUCCESS) {
            vm_address_t target = addr + cap;
            vm_prot_t cur_prot, max_prot;
            kr = vm_remap(self, &target, cap, 0, VM_FLAGS_FIXED | VM_FLAGS_OVERWRITE, self, addr, FALSE, &cur_prot,
                          &max_prot, VM_INHERIT_SHARE);
            if (kr == KERN_SUCCESS && target == addr + cap) {
                ring->base = (uint8_t *)addr;
                ring->is_mach_vm = 1;
                *out_handle = (uint64_t)(uintptr_t)ring;
                *out_capacity = cap;
                return 0;
            }
        }
        vm_deallocate(self, addr, 2 * (vm_size_t)cap);
    }
    free(ring);
    return -1;

#else
    // Linux: memfd_create + mmap
    int fd = -1;
#if defined(__NR_memfd_create)
    fd = (int)syscall(__NR_memfd_create, "goose_vring", 0);
#endif
    if (fd < 0) {
        char shm_name[64];
        snprintf(shm_name, sizeof(shm_name), "/goose_vring_%d_%ld", getpid(), (long)rand());
        fd = shm_open(shm_name, O_RDWR | O_CREAT | O_EXCL, 0600);
        if (fd >= 0) {
            shm_unlink(shm_name);
        }
    }
    if (fd < 0) {
        free(ring);
        return -1;
    }

    if (ftruncate(fd, cap) != 0) {
        close(fd);
        free(ring);
        return -1;
    }

    void *addr = mmap(NULL, 2 * (size_t)cap, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (addr == MAP_FAILED) {
        close(fd);
        free(ring);
        return -1;
    }

    void *v1 = mmap(addr, cap, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_FIXED, fd, 0);
    void *v2 = mmap((char *)addr + cap, cap, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_FIXED, fd, 0);
    close(fd);

    if (v1 != addr || v2 != (char *)addr + cap) {
        munmap(addr, 2 * (size_t)cap);
        free(ring);
        return -1;
    }

    ring->base = (uint8_t *)addr;
    ring->shm_fd = -1;
    *out_handle = (uint64_t)(uintptr_t)ring;
    *out_capacity = cap;
    return 0;
#endif
}

void wing_page_ring_destroy(uint64_t handle) {
    if (!handle) return;
    wing_page_ring_t *ring = (wing_page_ring_t *)(uintptr_t)handle;
    if (ring->base) {
#if defined(__wasm__)
        free(ring->base);
#elif defined(_WIN32)
        UnmapViewOfFile(ring->base);
        UnmapViewOfFile(ring->base + ring->capacity);
        if (ring->mapping_handle) {
            CloseHandle(ring->mapping_handle);
        }
#elif defined(__APPLE__)
        if (ring->is_mach_vm) {
            vm_deallocate(mach_task_self(), (vm_address_t)ring->base, 2 * (vm_size_t)ring->capacity);
        } else {
            munmap(ring->base, 2 * (size_t)ring->capacity);
        }
#else
        munmap(ring->base, 2 * (size_t)ring->capacity);
#endif
    }
    free(ring);
}

int64_t wing_page_ring_write(uint64_t handle, uint64_t tail_offset, wing_bytes_ro src) {
    if (!handle || !src.data || src.len <= 0) return 0;
    wing_page_ring_t *ring = (wing_page_ring_t *)(uintptr_t)handle;
    if (!ring->base) return -1;

    size_t to_write = (size_t)src.len;
    if (to_write > ring->capacity) {
        to_write = ring->capacity;
    }

    uint32_t off = (uint32_t)(tail_offset % ring->capacity);
#if defined(__wasm__)
    memcpy(ring->base + off, src.data, to_write);
    if (off + to_write > ring->capacity) {
        size_t wrapped = (off + to_write) - ring->capacity;
        memcpy(ring->base, src.data + (to_write - wrapped), wrapped);
    } else {
        memcpy(ring->base + ring->capacity + off, src.data, to_write);
    }
#else
    // Mirrored mapping guarantees [base + off ... base + off + to_write] is valid contiguous virtual memory!
    memcpy(ring->base + off, src.data, to_write);
#endif
    return (int64_t)to_write;
}

int64_t wing_page_ring_read(uint64_t handle, uint64_t head_offset, wing_bytes_rw dst) {
    if (!handle || !dst.data || dst.len <= 0) return 0;
    wing_page_ring_t *ring = (wing_page_ring_t *)(uintptr_t)handle;
    if (!ring->base) return -1;

    size_t to_read = (size_t)dst.len;
    if (to_read > ring->capacity) {
        to_read = ring->capacity;
    }

    uint32_t off = (uint32_t)(head_offset % ring->capacity);
    // Mirrored mapping guarantees [base + off ... base + off + to_read] is valid contiguous virtual memory!
    memcpy(dst.data, ring->base + off, to_read);
    return (int64_t)to_read;
}

int64_t wing_page_ring_peek(uint64_t handle, uint64_t head_offset, wing_bytes_rw dst) {
    return wing_page_ring_read(handle, head_offset, dst);
}

int32_t wing_page_ring_recv(uint64_t handle, uint64_t tail_offset, uint32_t max_len, int64_t sock_fd,
                            uint32_t timeout_ms) {
    if (!handle || sock_fd < 0 || max_len == 0) return -1;
    wing_page_ring_t *ring = (wing_page_ring_t *)(uintptr_t)handle;
    if (!ring->base) return -1;

    uint32_t to_recv = max_len;
    if (to_recv > ring->capacity) {
        to_recv = ring->capacity;
    }

    uint32_t off = (uint32_t)(tail_offset % ring->capacity);
    uint8_t *dst = ring->base + off;

#if defined(__wasm__)
    wing_bytes_rw buf = {dst, (int64_t)to_recv};
    int32_t res = wing_tcp_recv(sock_fd, buf, timeout_ms);
    if (res > 0) {
        if (off + (size_t)res > ring->capacity) {
            size_t wrapped = (off + (size_t)res) - ring->capacity;
            memcpy(ring->base, ring->base + ring->capacity, wrapped);
        } else {
            memcpy(ring->base + ring->capacity + off, ring->base + off, (size_t)res);
        }
    }
    return res;
#elif defined(_WIN32)
    if (timeout_ms > 0) {
        DWORD tv = timeout_ms;
        setsockopt((SOCKET)sock_fd, SOL_SOCKET, SO_RCVTIMEO, (const char *)&tv, sizeof(tv));
    }
    int res = recv((SOCKET)sock_fd, (char *)dst, (int)to_recv, 0);
    return (int32_t)res;
#else
    if (timeout_ms > 0) {
        struct timeval tv;
        tv.tv_sec = timeout_ms / 1000;
        tv.tv_usec = (timeout_ms % 1000) * 1000;
        setsockopt((int)sock_fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    }
    ssize_t res = recv((int)sock_fd, dst, (size_t)to_recv, 0);
    return (int32_t)res;
#endif
}

int32_t wing_page_ring_send(uint64_t handle, uint64_t head_offset, uint32_t len, int64_t sock_fd) {
    if (!handle || sock_fd < 0 || len == 0) return 0;
    wing_page_ring_t *ring = (wing_page_ring_t *)(uintptr_t)handle;
    if (!ring->base) return -1;

    uint32_t to_send = len;
    if (to_send > ring->capacity) {
        to_send = ring->capacity;
    }

    uint32_t off = (uint32_t)(head_offset % ring->capacity);
    const uint8_t *src = ring->base + off;

#if defined(__wasm__)
    wing_bytes_ro data = {src, (int64_t)to_send};
    return wing_tcp_send(sock_fd, data);
#elif defined(_WIN32)
    int res = send((SOCKET)sock_fd, (const char *)src, (int)to_send, 0);
    return (int32_t)res;
#else
    ssize_t res = send((int)sock_fd, src, (size_t)to_send, 0);
    return (int32_t)res;
#endif
}

int64_t wing_page_ring_find_crlf(uint64_t handle, uint64_t head_offset, uint32_t len) {
    if (!handle || len < 2) return -1;
    wing_page_ring_t *ring = (wing_page_ring_t *)(uintptr_t)handle;
    if (!ring->base) return -1;

    uint32_t search_len = (len > ring->capacity) ? ring->capacity : len;
    uint32_t off = (uint32_t)(head_offset % ring->capacity);
    wing_bytes_ro slice = {ring->base + off, (int64_t)search_len};
    return wing_simd_find_crlf(slice);
}

int64_t wing_page_ring_find_crlfcrlf(uint64_t handle, uint64_t head_offset, uint32_t len) {
    if (!handle || len < 4) return -1;
    wing_page_ring_t *ring = (wing_page_ring_t *)(uintptr_t)handle;
    if (!ring->base) return -1;

    uint32_t search_len = (len > ring->capacity) ? ring->capacity : len;
    uint32_t off = (uint32_t)(head_offset % ring->capacity);
    wing_bytes_ro slice = {ring->base + off, (int64_t)search_len};
    return wing_fast_find_crlfcrlf(slice);
}
