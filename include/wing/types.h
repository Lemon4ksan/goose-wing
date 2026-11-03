// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

#ifndef WING_TYPES_H
#define WING_TYPES_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#if defined(_WIN32) || defined(__CYGWIN__)
  #if defined(WING_BUILD_SHARED)
    #define WING_API __declspec(dllexport)
  #elif defined(WING_USE_SHARED)
    #define WING_API __declspec(dllimport)
  #else
    #define WING_API
  #endif
#elif defined(__GNUC__) && __GNUC__ >= 4
  #define WING_API __attribute__((visibility("default")))
#else
  #define WING_API
#endif

#ifdef __cplusplus
extern "C" {
#endif

#define WING_VERSION_MAJOR 0
#define WING_VERSION_MINOR 1
#define WING_VERSION_PATCH 0

/**
 * @brief Returns the semantic version string of the wing library.
 */
WING_API const char *wing_version_string(void);

/**
 * @brief Zero-copy immutable byte slice matching Goose `const u8[:]`.
 */
typedef struct wing_slice {
    const uint8_t *ptr;
    int64_t        len;
} wing_slice_t;

/**
 * @brief Zero-copy mutable byte slice matching Goose `u8[:]`.
 */
typedef struct wing_mut_slice {
    uint8_t *ptr;
    int64_t  len;
} wing_mut_slice_t;

/**
 * @brief Construct an immutable wing_slice_t from a C string literal (excluding null terminator).
 */
#define WING_STR(s) ((wing_slice_t){ (const uint8_t*)(s), (int64_t)(sizeof(s) - 1) })

/**
 * @brief Construct an immutable wing_slice_t from a pointer and length.
 */
#define WING_SLICE(buf, n) ((wing_slice_t){ (const uint8_t*)(buf), (int64_t)(n) })

/**
 * @brief Construct a mutable wing_mut_slice_t from a pointer and length.
 */
#define WING_MUT_SLICE(buf, n) ((wing_mut_slice_t){ (uint8_t*)(buf), (int64_t)(n) })

#ifdef __cplusplus
}
#endif

#endif // WING_TYPES_H
