// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Internal Cookie storage limits, timing constants, and eviction quotas (RFC 6265bis, CHIPS).
namespace internal;

import std;

// Maximum cookie lifetime (400 days).
let K_MINUTES_IN_400_DAYS: i64 = 576000;
let K_MAX_COOKIE_AGE_SEC:  i64 = 576000 * 60;           // 34,560,000 seconds
let K_MAX_COOKIE_AGE_US:   i64 = 576000 * 60 * 1000000; // 34,560,000,000,000 us

// Payload and attribute length limits (RFC 6265bis Section 5.5).
let K_MAX_COOKIE_NAME_VAL_LEN: i64 = 4096; // Exceeding this rejects the entire cookie.
let K_MAX_COOKIE_ATTR_VAL_LEN: i64 = 1024; // Exceeding this ignores the attribute only.

// Domain garbage collection thresholds.
let K_DOMAIN_MAX_COOKIES:    i64 = 180;    // Threshold to trigger domain GC.
let K_DOMAIN_PURGE_COOKIES:  i64 = 30;     // Number of cookies to evict in domain GC.
let K_DOMAIN_TARGET_COOKIES: i64 = 150;    // Remaining cookies per domain quota (180 - 30).

// Priority quotas for domain eviction.
let K_DOMAIN_COOKIES_QUOTA_LOW:    i64 = 30;
let K_DOMAIN_COOKIES_QUOTA_MEDIUM: i64 = 50;
let K_DOMAIN_COOKIES_QUOTA_HIGH:   i64 = 70; // 150 - 30 - 50 = 70

// Global garbage collection thresholds.
let K_MAX_COOKIES:           i64 = 3300;  // Threshold to trigger global GC.
let K_PURGE_COOKIES:         i64 = 300;   // Number of cookies to evict in global GC.
let K_GLOBAL_TARGET_COOKIES: i64 = 3000;  // Remaining cookies global quota (3300 - 300).

// Active cookies accessed within 30 days are exempt from global purge.
let K_SAFE_FROM_GLOBAL_PURGE_DAYS: i64 = 30;
let K_SAFE_FROM_GLOBAL_PURGE_US:   i64 = 30 * 86400 * 1000000; // 2,592,000,000,000 us

// Window for Lax-allowing-unsafe exception (120 seconds).
let K_LAX_ALLOWING_UNSAFE_WINDOW_US: i64 = 120 * 1000000; // 2 minutes (120,000,000 us)

// Maximum bytes per partition key and domain (CHIPS).
let K_PER_PARTITION_DOMAIN_MAX_COOKIE_BYTES: i64 = 10240; // 10 KB quota

// Persistence commit interval and batch size.
let K_COMMIT_INTERVAL_MS:      i64 = 30000; // 30 seconds
let K_COMMIT_AFTER_BATCH_SIZE: i64 = 256;   // 256 mutations (bounded to WriteBackBatcher ops capacity)

// Access time update threshold (60 seconds, Chromium kDefaultAccessUpdateThresholdSeconds).
let K_ACCESS_UPDATE_THRESHOLD_US: i64 = 60 * 1000000;
