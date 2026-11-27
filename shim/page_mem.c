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
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>

#else
// Linux / POSIX
#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/stat.h>
#if defined(__linux__)
#include <sys/prctl.h>
#endif
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
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
    // Linux / macOS: use pread() instead of MAP_SHARED mmap to avoid SIGBUS on external truncation.
    int open_flags = O_RDONLY;
#ifdef O_CLOEXEC
    open_flags |= O_CLOEXEC;
#endif
    int fd = open(path_buf, open_flags);
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
    mf->file_fd = fd;
    mf->base = NULL;
#endif

    *out_handle = (uint64_t)(uintptr_t)mf;
    *out_size = mf->file_size;
    return 0;
}

int64_t wing_mmap_file_read(uint64_t handle, uint64_t offset, wing_bytes_rw dst) {
    if (handle == 0 || !dst.data || dst.len <= 0) return 0;
    wing_mmap_file_t *mf = (wing_mmap_file_t *)(uintptr_t)handle;
    if (!mf) return -1;
#if defined(__wasm__) || defined(_WIN32)
    if (!mf->base && mf->file_size > 0) return -1;
#else
    if (mf->file_fd < 0) return -1;
#endif

    if (offset >= mf->file_size) return 0;

    uint64_t available = mf->file_size - offset;
    uint64_t to_read = ((uint64_t)dst.len < available) ? (uint64_t)dst.len : available;

#if defined(__wasm__) || defined(_WIN32)
    if (to_read > 0 && mf->base) {
        memcpy(dst.data, mf->base + offset, (size_t)to_read);
    }
    return (int64_t)to_read;
#else
    if (to_read > (uint64_t)SSIZE_MAX) to_read = (uint64_t)SSIZE_MAX;
    size_t done = 0;
    while (done < (size_t)to_read) {
        ssize_t n = pread(mf->file_fd, dst.data + done, (size_t)to_read - done, (off_t)(offset + done));
        if (n < 0) {
            if (errno == EINTR) continue;
            return done > 0 ? (int64_t)done : -1;
        }
        if (n == 0) break;
        done += (size_t)n;
    }
    return (int64_t)done;
#endif
}

int32_t wing_mmap_file_send(uint64_t handle, uint64_t offset, uint32_t len, int64_t sock_fd) {
    if (handle == 0 || len == 0 || sock_fd < 0) return 0;
    wing_mmap_file_t *mf = (wing_mmap_file_t *)(uintptr_t)handle;
    if (!mf) return -1;
#if defined(__wasm__) || defined(_WIN32)
    if (!mf->base && mf->file_size > 0) return -1;
#else
    if (mf->file_fd < 0) return -1;
#endif

    if (offset >= mf->file_size) return -2;

    uint64_t available = mf->file_size - offset;
    uint64_t req = (uint64_t)len;
    uint64_t clamped = (req < available) ? req : available;
    if (clamped > 0x7FFFFFFFULL) clamped = 0x7FFFFFFFULL;
    uint32_t to_send = (uint32_t)clamped;
    if (to_send == 0) return 0;

#if defined(__wasm__)
    if (!mf->base) return 0;
    wing_bytes_ro slice = {mf->base + offset, (int64_t)to_send};
    return wing_tcp_send(sock_fd, slice);
#elif defined(_WIN32)
    if (!mf->base) return 0;
    int sent = send((SOCKET)sock_fd, (const char *)(mf->base + offset), (int)to_send, 0);
    return (sent >= 0) ? sent : -1;
#else
#ifdef MSG_NOSIGNAL
    int send_flags = MSG_NOSIGNAL;
#else
    int send_flags = 0;
#endif
    uint8_t chunk_buf[16384];
    uint32_t total_sent = 0;
    while (total_sent < to_send) {
        size_t want = (size_t)(to_send - total_sent);
        if (want > sizeof(chunk_buf)) want = sizeof(chunk_buf);
        ssize_t nread = 0;
        do {
            nread = pread(mf->file_fd, chunk_buf, want, (off_t)(offset + total_sent));
        } while (nread < 0 && errno == EINTR);
        if (nread < 0) {
            return total_sent > 0 ? (int32_t)total_sent : -1;
        }
        if (nread == 0) break;
        size_t off = 0;
        while (off < (size_t)nread) {
            ssize_t sent = send((int)sock_fd, chunk_buf + off, (size_t)nread - off, send_flags);
            if (sent < 0) {
                if (errno == EINTR) continue;
                return total_sent > 0 ? (int32_t)total_sent : -1;
            }
            if (sent == 0) return (int32_t)total_sent;
            off += (size_t)sent;
            total_sent += (uint32_t)sent;
        }
    }
    return (int32_t)total_sent;
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
    if (mf->file_fd >= 0) {
        close(mf->file_fd);
        mf->file_fd = -1;
    }
#endif

    mf->base = NULL;
    free(mf);
}

int32_t wing_disable_core_dumps(void) {
#if defined(__wasm__)
    return 0;
#elif defined(_WIN32)
    (void)SetErrorMode(SEM_NOGPFAULTERRORBOX);
    return 0;
#else
    int rc = 0;
#if defined(__linux__)
    if (prctl(PR_SET_DUMPABLE, 0, 0, 0, 0) != 0) rc = -1;
#endif
    struct rlimit rl;
    rl.rlim_cur = 0;
    rl.rlim_max = 0;
    if (setrlimit(RLIMIT_CORE, &rl) != 0) rc = -1;
    return rc;
#endif
}

int32_t wing_write_file_nofollow(wing_bytes_ro path, wing_bytes_ro data, int32_t append) {
    if (!path.data || path.len <= 0 || path.len >= 4096 || memchr(path.data, 0, (size_t)path.len) != NULL) {
        return -1;
    }
    if (data.len < 0 || (data.len > 0 && !data.data)) {
        return -1;
    }
#if defined(__wasm__)
    (void)append;
    return -1;
#elif defined(_WIN32)
    char path_buf[4096];
    memcpy(path_buf, path.data, (size_t)path.len);
    path_buf[path.len] = '\0';
    wchar_t wpath[4096];
    if (MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, path_buf, -1, wpath, 4096) <= 0) {
        return -1;
    }
    DWORD attrs = GetFileAttributesW(wpath);
    if (attrs != INVALID_FILE_ATTRIBUTES && (attrs & FILE_ATTRIBUTE_REPARSE_POINT) != 0) {
        return -1;
    }
    DWORD access = (append != 0) ? FILE_APPEND_DATA : GENERIC_WRITE;
    DWORD disp = (append != 0) ? OPEN_ALWAYS : CREATE_NEW;
    HANDLE h = CreateFileW(wpath, access, 0, NULL, disp, FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT, NULL);
    if (h == INVALID_HANDLE_VALUE) {
        return -1;
    }
    BY_HANDLE_FILE_INFORMATION info;
    if (GetFileType(h) != FILE_TYPE_DISK || !GetFileInformationByHandle(h, &info) ||
        (info.dwFileAttributes & (FILE_ATTRIBUTE_REPARSE_POINT | FILE_ATTRIBUTE_DIRECTORY)) != 0) {
        CloseHandle(h);
        return -1;
    }
    int64_t off = 0;
    while (off < data.len) {
        int64_t rem = data.len - off;
        DWORD chunk = (rem > 0x7FFFFFFFLL) ? 0x7FFFFFFFUL : (DWORD)rem;
        DWORD written = 0;
        if (!WriteFile(h, data.data + off, chunk, &written, NULL) || written == 0) {
            CloseHandle(h);
            return -1;
        }
        off += (int64_t)written;
    }
    CloseHandle(h);
    return 0;
#else
    char path_buf[4096];
    memcpy(path_buf, path.data, (size_t)path.len);
    path_buf[path.len] = '\0';
    int flags = O_WRONLY | O_CREAT;
#ifdef O_NOFOLLOW
    flags |= O_NOFOLLOW;
#endif
#ifdef O_CLOEXEC
    flags |= O_CLOEXEC;
#endif
    flags |= (append != 0) ? O_APPEND : O_EXCL;
    int fd = open(path_buf, flags, 0600);
    if (fd < 0) {
        return -1;
    }
    struct stat st;
    if (fstat(fd, &st) != 0 || !S_ISREG(st.st_mode)) {
        close(fd);
        return -1;
    }
    (void)fchmod(fd, 0600);
    int64_t off = 0;
    while (off < data.len) {
        ssize_t w = write(fd, data.data + off, (size_t)(data.len - off));
        if (w < 0) {
            if (errno == EINTR) continue;
            close(fd);
            return -1;
        }
        if (w == 0) {
            close(fd);
            return -1;
        }
        off += (int64_t)w;
    }
    close(fd);
    return 0;
#endif
}
