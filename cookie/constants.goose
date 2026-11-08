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
    return match same_site_mode {
        Default => "Default",
        Lax => "Lax",
        Strict => "Strict",
        None => "None",
        Unknown => "Unknown",
    };
}

// Parses a SameSite attribute value case-insensitively (RFC 6265bis Section 5.4.7).
// Returns CookieSameSite.Unknown for unrecognized values.
//
// Example:
//   raw_val = "Strict"
//   returns: CookieSameSite.Strict
fn parse_cookie_same_site(raw_val: const u8[:]) -> CookieSameSite {
    if raw_val.eq_ascii_fold("strict") { return CookieSameSite.Strict; }
    if raw_val.eq_ascii_fold("lax") { return CookieSameSite.Lax; }
    if raw_val.eq_ascii_fold("none") { return CookieSameSite.None; }
    if raw_val.eq_ascii_fold("default") { return CookieSameSite.Default; }
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
    return match priority_level {
        Low => "Low",
        Medium => "Medium",
        High => "High",
        Unknown => "Unknown",
    };
}

// Parses a Priority attribute value case-insensitively.
// Returns CookiePriority.Unknown for unrecognized values.
//
// Example:
//   raw_val = "high"
//   returns: CookiePriority.High
fn parse_cookie_priority(raw_val: const u8[:]) -> CookiePriority {
    if raw_val.eq_ascii_fold("low") { return CookiePriority.Low; }
    if raw_val.eq_ascii_fold("medium") { return CookiePriority.Medium; }
    if raw_val.eq_ascii_fold("high") { return CookiePriority.High; }
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
    return match source_scheme {
        Unset => "Unset",
        NonSecure => "NonSecure",
        Secure => "Secure",
        Unknown => "Unknown",
    };
}

// Parses a serialized source scheme string case-insensitively.
//
// Example:
//   raw_val = "secure"
//   returns: CookieSourceScheme.Secure
fn parse_cookie_source_scheme(raw_val: const u8[:]) -> CookieSourceScheme {
    if raw_val.eq_ascii_fold("secure") { return CookieSourceScheme.Secure; }
    if raw_val.eq_ascii_fold("nonsecure") { return CookieSourceScheme.NonSecure; }
    if raw_val.eq_ascii_fold("unset") { return CookieSourceScheme.Unset; }
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
