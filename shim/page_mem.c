// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Layer 4 Virtual Memory Operations C Shim:
// Memory-Mapped Static Files (MapViewOfFile / mmap) for zero-copy file transmission.

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <string.h>
#include <stdlib.h>
#include <limits.h>

#pragma pack(push, 1)
typedef struct {
    uint8_t *data;
    int64_t len;
} wing_bytes_rw;

typedef struct {
    const uint8_t *data;
    int64_t len;
} wing_bytes_ro;
#pragma pack(pop)

_Static_assert(sizeof(wing_bytes_rw) == sizeof(uint8_t *) + sizeof(int64_t), "wing_bytes_rw must be packed");
_Static_assert(offsetof(wing_bytes_rw, len) == sizeof(uint8_t *), "wing_bytes_rw.len must follow data");
_Static_assert(sizeof(wing_bytes_ro) == sizeof(const uint8_t *) + sizeof(int64_t), "wing_bytes_ro must be packed");
_Static_assert(offsetof(wing_bytes_ro, len) == sizeof(const uint8_t *), "wing_bytes_ro.len must follow data");

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

// Memory-Mapped Files for Zero-Copy Serving & Inspection
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
    if (GetFileType(hFile) != FILE_TYPE_DISK || !GetFileSizeEx(hFile, &liSize) || liSize.QuadPart < 0) {
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
    if (fstat(fd, &st) < 0 || !S_ISREG(st.st_mode) || st.st_size < 0 || (uint64_t)st.st_size > (uint64_t)SIZE_MAX) {
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
    uint64_t req = (uint64_t)len;
    uint64_t clamped = (req < available) ? req : available;
    if (clamped > 0x7FFFFFFFULL) clamped = 0x7FFFFFFFULL;
    uint32_t to_send = (uint32_t)clamped;
    if (to_send == 0 || !mf->base) return 0;

#if defined(__wasm__)
    wing_bytes_ro slice = {mf->base + offset, (int64_t)to_send};
    return wing_tcp_send(sock_fd, slice);
#elif defined(_WIN32)
    int sent = send((SOCKET)sock_fd, (const char *)(mf->base + offset), (int)to_send, 0);
    return (sent >= 0) ? sent : -1;
#else
#ifdef MSG_NOSIGNAL
    int send_flags = MSG_NOSIGNAL;
#else
    int send_flags = 0;
#endif
    ssize_t sent = send((int)sock_fd, mf->base + offset, (size_t)to_send, send_flags);
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
