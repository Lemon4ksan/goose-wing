// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Internal Cookie storage limits, timing constants, eviction quotas, and shared
// syntax validators (RFC 6265bis, CHIPS).
namespace cookie_internal;

import std;
import core from "..";

// Maximum cookie lifetime (400 days = 576,000 minutes).
let K_MAX_COOKIE_AGE_SEC: i64 = 576000 * 60;           // 34,560,000 seconds
let K_MAX_COOKIE_AGE_US:  i64 = 576000 * 60 * 1000000; // 34,560,000,000,000 us

// Payload and attribute length limits (RFC 6265bis Section 5.5).
let K_MAX_COOKIE_NAME_VAL_LEN: i64 = 4096; // Exceeding this rejects the entire cookie.
let K_MAX_COOKIE_ATTR_VAL_LEN: i64 = 1024; // Exceeding this ignores the attribute only.

// Domain garbage collection thresholds.
let K_DOMAIN_MAX_COOKIES:    i64 = 180; // Threshold to trigger domain GC.
let K_DOMAIN_TARGET_COOKIES: i64 = 150; // Remaining cookies per domain quota (180 - 30).

// Priority quotas for domain eviction.
let K_DOMAIN_COOKIES_QUOTA_LOW:    i64 = 30;
let K_DOMAIN_COOKIES_QUOTA_MEDIUM: i64 = 50;
let K_DOMAIN_COOKIES_QUOTA_HIGH:   i64 = 70; // 150 - 30 - 50 = 70

// Global garbage collection thresholds.
let K_MAX_COOKIES:           i64 = 3300; // Threshold to trigger global GC.
let K_PURGE_COOKIES:         i64 = 300;  // Number of cookies to evict in global GC.
let K_GLOBAL_TARGET_COOKIES: i64 = 3000; // Remaining cookies global quota (3300 - 300).

// Active cookies accessed within 30 days are exempt from global purge.
let K_SAFE_FROM_GLOBAL_PURGE_US: i64 = 30 * 86400 * 1000000; // 2,592,000,000,000 us

// Window for Lax-allowing-unsafe exception (120 seconds).
let K_LAX_ALLOWING_UNSAFE_WINDOW_US: i64 = 120 * 1000000; // 2 minutes (120,000,000 us)

// Maximum bytes per partition key and domain (CHIPS).
let K_PER_PARTITION_DOMAIN_MAX_COOKIE_BYTES: i64 = 10240; // 10 KB quota

// Persistence commit interval and batch size.
let K_COMMIT_INTERVAL_MS:      i64 = 30000; // 30 seconds
let K_COMMIT_AFTER_BATCH_SIZE: i64 = 256;   // 256 mutations (bounded to WriteBackBatcher ops capacity)

// Access time update threshold (60 seconds, Chromium kDefaultAccessUpdateThresholdSeconds).
let K_ACCESS_UPDATE_THRESHOLD_US: i64 = 60 * 1000000;

// ---- shared rfc 6265bis syntax validators ----------------------------------

// RFC 6265bis Section 5.5: Rejects ASCII control characters %x00-08 / %x0A-1F / %x7F (HTAB %x09 allowed).
inline fn has_prohibited_ctl(s: const u8[:]) -> bool {
    for b in s {
        if (b <= 0x08) || (b >= 0x0A && b <= 0x1F) || b == 0x7F {
            return true;
        }
    }
    return false;
}

// RFC 6265 Section 4.1.1: cookie-name is HTTP token (1*tchar; empty name permitted for nameless cookies).
inline fn is_valid_cookie_name(name: const u8[:]) -> bool {
    for b in name {
        guard core::is_tchar(b) else { return false; }
    }
    return true;
}

// RFC 6265 Section 4.1.1: cookie-octet (%x21 / %x23-2B / %x2D-3A / %x3C-5B / %x5D-7E).
inline fn is_cookie_octet(b: u8) -> bool {
    guard core::is_ascii_vchar(b) else { return false; }
    return b != '"' && b != ',' && b != ';' && b != '\\';
}

// RFC 6265 Section 4.1.1: cookie-value (*cookie-octet / (DQUOTE *cookie-octet DQUOTE)).
inline fn is_valid_cookie_val(val: const u8[:]) -> bool {
    let is_quoted = val.len >= 2 && val[0] == '"' && val[core::sub_sat_i64(val.len, 1)] == '"';
    let body = if is_quoted { val[1..^1] } else { val };
    for b in body {
        guard is_cookie_octet(b) else { return false; }
    }
    return true;
}

inline fn is_valid_domain_attr(dom: const u8[:]) -> bool {
    guard dom.len > 0 && dom[core::sub_sat_i64(dom.len, 1)] != '.' else { return false; }
    if !core::is_ip_address_literal(dom) && (core::contains(dom, "..") || dom.contains_byte(':')) {
        return false;
    }
    for b in dom {
        if b <= 0x20 || b >= 0x7F || b == ';' || b == '/' || b == '?' || b == '#' || b == '\\' {
            return false;
        }
    }
    return true;
}
