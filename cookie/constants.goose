// Chromium CookieMonster & IETF RFC 6265bis Architectural Constants and Enumerations.
// Clean Room Implementation for goose-wing.
//
// Core Types:
//   CookieSameSite      - RFC 6265bis cross-site security mode (Default, Lax, Strict, None).
//   CookiePriority      - Chromium CookieMonster cache retention priority (Low, Medium, High).
//   CookieSourceScheme  - Origin-Bound Cookies (OBC) source scheme (Unset, NonSecure, Secure).
//   CookieDeleteCause   - Deletion taxonomy enum for telemetry and audit logging.
//
// Standards & Specifications:
//   RFC 6265bis Cookies: State Management Mechanism (IETF Draft).
//   Chromium net::CookieMonster architectural hysteresis thresholds & eviction quotas.
//   CHIPS (Cookies Having Independent Partitioned State) memory quotas.
namespace wing;

import std;

// ---- architectural limits --------------------------------------------------

// Maximum cookie lifetime capped at 400 days (kMinutesIn400Days = 576000 minutes).
let K_MINUTES_IN_400_DAYS: i64 = 576000;
let K_MAX_COOKIE_AGE_US: i64 = 576000 * 60 * 1000000; // 34,560,000,000,000 us

// Size limits: payload (name + value) vs attributes.
// RFC 6265bis Issue #1340 / Chromium M95+ unified limits.
let K_MAX_COOKIE_NAME_VAL_LEN: i64 = 4096; // Exceeding this rejects the entire cookie.
let K_MAX_COOKIE_ATTR_VAL_LEN: i64 = 1024; // Exceeding this ignores the attribute only.

// Domain Garbage Collection thresholds (hysteresis model).
let K_DOMAIN_MAX_COOKIES: i64 = 180;       // Threshold to trigger domain GC.
let K_DOMAIN_PURGE_COOKIES: i64 = 30;     // Number of cookies to evict in domain GC.
let K_DOMAIN_TARGET_COOKIES: i64 = 150;    // Remaining cookies per domain quota (180 - 30).

// Domain priority quotas (Chromium CookieMonster 6-round protection).
let K_DOMAIN_COOKIES_QUOTA_LOW: i64 = 30;
let K_DOMAIN_COOKIES_QUOTA_MEDIUM: i64 = 50;
let K_DOMAIN_COOKIES_QUOTA_HIGH: i64 = 70; // 150 - 30 - 50 = 70

// Global Garbage Collection thresholds.
let K_MAX_COOKIES: i64 = 3300;            // Threshold to trigger global GC.
let K_PURGE_COOKIES: i64 = 300;           // Number of cookies to evict in global GC.
let K_GLOBAL_TARGET_COOKIES: i64 = 3000;  // Remaining cookies global quota (3300 - 300).

// Immunity window: active cookies accessed within 30 days are immune from global purge.
let K_SAFE_FROM_GLOBAL_PURGE_DAYS: i64 = 30;
let K_SAFE_FROM_GLOBAL_PURGE_US: i64 = 30 * 86400 * 1000000; // 2,592,000,000,000 us

// Cookie Incrementalism: Lax-allowing-unsafe (Lax+POST) 2-minute exception window.
let K_LAX_ALLOWING_UNSAFE_WINDOW_US: i64 = 120 * 1000000; // 2 minutes (120,000,000 us)

// CHIPS: Maximum memory bytes (name + value) per (PartitionKey, eTLD+1) domain.
let K_PER_PARTITION_DOMAIN_MAX_COOKIE_BYTES: i64 = 10240; // 10 KB quota

// Persistence engine: commit interval and batch size.
let K_COMMIT_INTERVAL_MS: i64 = 30000;    // 30 seconds
let K_COMMIT_AFTER_BATCH_SIZE: i64 = 512; // 512 mutations

// ---- same-site enumeration -------------------------------------------------

// RFC 6265bis SameSite mode.
enum CookieSameSite {
    Default, // Lax with Lax-allowing-unsafe 2-minute window
    Lax,     // Permitted for top-level safe navigations (GET/HEAD)
    Strict,  // Only sent in same-site contexts
    None,    // Permitted cross-site, strictly requires Secure flag
}

fn same_site_to_string(same_site_mode: CookieSameSite) -> const u8[:] {
    return match same_site_mode {
        Default => "Default",
        Lax => "Lax",
        Strict => "Strict",
        None => "None",
    };
}

fn parse_cookie_same_site(raw_val: const u8[:]) -> CookieSameSite {
    if eq_ascii_fold(raw_val, "strict") { return CookieSameSite.Strict; }
    if eq_ascii_fold(raw_val, "lax") { return CookieSameSite.Lax; }
    if eq_ascii_fold(raw_val, "none") { return CookieSameSite.None; }
    return CookieSameSite.Default;
}

// ---- priority enumeration --------------------------------------------------

// Retention priority level during memory GC (cookie_constants.h).
enum CookiePriority {
    Low,
    Medium, // Default priority (COOKIE_PRIORITY_DEFAULT)
    High,
}

fn priority_to_string(priority_level: CookiePriority) -> const u8[:] {
    return match priority_level {
        Low => "Low",
        Medium => "Medium",
        High => "High",
    };
}

fn parse_cookie_priority(raw_val: const u8[:]) -> CookiePriority {
    if eq_ascii_fold(raw_val, "low") { return CookiePriority.Low; }
    if eq_ascii_fold(raw_val, "high") { return CookiePriority.High; }
    return CookiePriority.Medium;
}

// ---- source scheme enumeration ---------------------------------------------

// Origin-Bound Cookies (OBC) source scheme.
enum CookieSourceScheme {
    Unset,
    NonSecure,
    Secure,
}

fn source_scheme_to_string(source_scheme: CookieSourceScheme) -> const u8[:] {
    return match source_scheme {
        Unset => "Unset",
        NonSecure => "NonSecure",
        Secure => "Secure",
    };
}

fn parse_cookie_source_scheme(raw_val: const u8[:]) -> CookieSourceScheme {
    if eq_ascii_fold(raw_val, "secure") { return CookieSourceScheme.Secure; }
    if eq_ascii_fold(raw_val, "nonsecure") { return CookieSourceScheme.NonSecure; }
    return CookieSourceScheme.Unset;
}

// ---- deletion cause enumeration --------------------------------------------

// Deletion cause taxonomy for telemetry and persistence (Chromium CookieMonster).
enum CookieDeleteCause {
    UNKNOWN,
    EXPIRED,
    OVERWRITE,
    EXPLICIT,
    UNKNOWN_DELETION,
    DONT_RECORD,
    EVICTED_DOMAIN,
    EVICTED_GLOBAL,
    EXPIRED_OVERWRITE,
    CONTROL_CHAR,
    NON_SECURE,
}

fn delete_cause_code(delete_cause: CookieDeleteCause) -> i64 {
    return match delete_cause {
        UNKNOWN => 0,
        EXPIRED => 1,
        OVERWRITE => 2,
        EXPLICIT => 3,
        UNKNOWN_DELETION => 4,
        DONT_RECORD => 5,
        EVICTED_DOMAIN => 6,
        EVICTED_GLOBAL => 7,
        EXPIRED_OVERWRITE => 10,
        CONTROL_CHAR => 11,
        NON_SECURE => 12,
    };
}

fn delete_cause_to_string(delete_cause: CookieDeleteCause) -> const u8[:] {
    return match delete_cause {
        UNKNOWN => "UNKNOWN",
        EXPIRED => "EXPIRED",
        OVERWRITE => "OVERWRITE",
        EXPLICIT => "EXPLICIT",
        UNKNOWN_DELETION => "UNKNOWN_DELETION",
        DONT_RECORD => "DONT_RECORD",
        EVICTED_DOMAIN => "EVICTED_DOMAIN",
        EVICTED_GLOBAL => "EVICTED_GLOBAL",
        EXPIRED_OVERWRITE => "EXPIRED_OVERWRITE",
        CONTROL_CHAR => "CONTROL_CHAR",
        NON_SECURE => "NON_SECURE",
    };
}
