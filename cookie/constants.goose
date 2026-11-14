// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Cookie enumerations and attribute parsing (RFC 6265bis, CHIPS).
namespace wing;

import std;
import core from "..";

// ---- same-site enumeration -------------------------------------------------

// RFC 6265bis SameSite mode.
enum CookieSameSite {
    Default, // Lax with Lax-allowing-unsafe 2-minute window
    Lax,     // Permitted for top-level safe navigations (GET/HEAD)
    Strict,  // Only sent in same-site contexts
    None,    // Permitted cross-site, strictly requires Secure flag
    Unknown,
}

// Canonical string representation of same_site_mode.
fn same_site_to_string(same_site_mode: CookieSameSite) -> const u8[:] {
    const for <N, V> in variants<CookieSameSite> {
        let v: CookieSameSite = default<V>();
        if same_site_mode == v { return N; }
    }
    return "Unknown";
}

// Parses a SameSite attribute value case-insensitively (RFC 6265bis Section 5.4.7).
// Returns CookieSameSite.Unknown for unrecognized values.
//
// Example:
//   raw_val = "Strict"
//   returns: CookieSameSite.Strict
fn parse_cookie_same_site(raw_val: const u8[:]) -> CookieSameSite {
    const for <N, V> in variants<CookieSameSite> {
        let v: CookieSameSite = default<V>();
        if v != CookieSameSite.Unknown && v != CookieSameSite.Default && raw_val.eq_ascii_fold(N) {
            return v;
        }
    }
    return CookieSameSite.Unknown;
}

// ---- priority enumeration --------------------------------------------------

// Eviction priority levels during garbage collection.
enum CookiePriority {
    Low,
    Medium, // Default priority (COOKIE_PRIORITY_DEFAULT)
    High,
    Unknown,
}

// Canonical string representation of priority_level.
fn priority_to_string(priority_level: CookiePriority) -> const u8[:] {
    const for <N, V> in variants<CookiePriority> {
        let v: CookiePriority = default<V>();
        if priority_level == v { return N; }
    }
    return "Unknown";
}

// Parses a Priority attribute value case-insensitively.
// Returns CookiePriority.Unknown for unrecognized values.
//
// Example:
//   raw_val = "high"
//   returns: CookiePriority.High
fn parse_cookie_priority(raw_val: const u8[:]) -> CookiePriority {
    const for <N, V> in variants<CookiePriority> {
        let v: CookiePriority = default<V>();
        if v != CookiePriority.Unknown && raw_val.eq_ascii_fold(N) {
            return v;
        }
    }
    return CookiePriority.Unknown;
}

// ---- source scheme enumeration ---------------------------------------------

// Source scheme for origin-bound cookies.
enum CookieSourceScheme {
    Unset,
    NonSecure,
    Secure,
    Unknown,
}

// Canonical string representation of source_scheme.
fn source_scheme_to_string(source_scheme: CookieSourceScheme) -> const u8[:] {
    const for <N, V> in variants<CookieSourceScheme> {
        let v: CookieSourceScheme = default<V>();
        if source_scheme == v { return N; }
    }
    return "Unknown";
}

// Parses a serialized source scheme string case-insensitively.
//
// Example:
//   raw_val = "secure"
//   returns: CookieSourceScheme.Secure
fn parse_cookie_source_scheme(raw_val: const u8[:]) -> CookieSourceScheme {
    const for <N, V> in variants<CookieSourceScheme> {
        let v: CookieSourceScheme = default<V>();
        if v != CookieSourceScheme.Unknown && raw_val.eq_ascii_fold(N) {
            return v;
        }
    }
    return CookieSourceScheme.Unknown;
}

// ---- deletion cause enumeration --------------------------------------------

// Deletion reason for persistence and notifications.
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
