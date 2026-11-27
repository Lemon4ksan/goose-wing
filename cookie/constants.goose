// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Cookie enumerations and attribute parsing (RFC 6265bis, CHIPS).
namespace cookie;

import std;
import core;

// RFC 6265bis SameSite mode.
enum SameSite {
    Default, // Lax with Lax-allowing-unsafe 2-minute window
    Lax,     // Permitted for top-level safe navigations (GET/HEAD)
    Strict,  // Only sent in same-site contexts
    None,    // Permitted cross-site, strictly requires Secure flag
    Unknown,
}

// Canonical string representation of same_site_mode.
fn cookie_internal::same_site_to_string(same_site_mode: cookie::SameSite) -> const u8[:] {
    const for <N, V> in variants<cookie::SameSite> {
        let v: cookie::SameSite = default<V>();
        if same_site_mode == v { return N; }
    }
    return "Unknown";
}

// Parses a SameSite attribute value case-insensitively (RFC 6265bis Section 5.4.7).
// Returns SameSite.Unknown for unrecognized values.
//
// Example:
//   raw_val = "Strict"
//   returns: SameSite.Strict
fn parse_same_site(raw_val: const u8[:]) -> SameSite {
    const for <N, V> in variants<SameSite> {
        let v: SameSite = default<V>();
        if v != SameSite.Unknown && v != SameSite.Default && raw_val.eq_ascii_fold(N) {
            return v;
        }
    }
    return SameSite.Unknown;
}

// Eviction priority levels during garbage collection.
enum Priority {
    Low,
    Medium, // Default priority (COOKIE_PRIORITY_DEFAULT)
    High,
    Unknown,
}

// Canonical string representation of priority_level.
fn cookie_internal::priority_to_string(priority_level: cookie::Priority) -> const u8[:] {
    const for <N, V> in variants<cookie::Priority> {
        let v: cookie::Priority = default<V>();
        if priority_level == v { return N; }
    }
    return "Unknown";
}

// Parses a Priority attribute value case-insensitively.
// Returns Priority.Unknown for unrecognized values.
//
// Example:
//   raw_val = "high"
//   returns: Priority.High
fn parse_priority(raw_val: const u8[:]) -> Priority {
    const for <N, V> in variants<Priority> {
        let v: Priority = default<V>();
        if v != Priority.Unknown && raw_val.eq_ascii_fold(N) {
            return v;
        }
    }
    return Priority.Unknown;
}

// Source scheme for origin-bound cookies.
enum SourceScheme {
    Unset,
    NonSecure,
    Secure,
    Unknown,
}

// Canonical string representation of source_scheme.
fn cookie_internal::source_scheme_to_string(source_scheme: cookie::SourceScheme) -> const u8[:] {
    const for <N, V> in variants<cookie::SourceScheme> {
        let v: cookie::SourceScheme = default<V>();
        if source_scheme == v { return N; }
    }
    return "Unknown";
}

// Parses a serialized source scheme string case-insensitively.
//
// Example:
//   raw_val = "secure"
//   returns: cookie::SourceScheme.Secure
fn cookie_internal::parse_source_scheme(raw_val: const u8[:]) -> cookie::SourceScheme {
    const for <N, V> in variants<cookie::SourceScheme> {
        let v: cookie::SourceScheme = default<V>();
        if v != cookie::SourceScheme.Unknown && raw_val.eq_ascii_fold(N) {
            return v;
        }
    }
    return cookie::SourceScheme.Unknown;
}

// Deletion reason for persistence and notifications.
enum DeleteCause {
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
