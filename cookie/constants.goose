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
}

// Canonical string representation of same_site_mode.
fn same_site_to_string(same_site_mode: CookieSameSite) -> const u8[:] {
    return match same_site_mode {
        Default => "Default",
        Lax => "Lax",
        Strict => "Strict",
        None => "None",
    };
}

// Parses a SameSite attribute value case-insensitively, defaulting to CookieSameSite.Default (RFC 6265bis Section 5.4.7).
fn parse_cookie_same_site(raw_val: const u8[:]) -> CookieSameSite {
    if core::eq_ascii_fold(raw_val, "strict") { return CookieSameSite.Strict; }
    if core::eq_ascii_fold(raw_val, "lax") { return CookieSameSite.Lax; }
    if core::eq_ascii_fold(raw_val, "none") { return CookieSameSite.None; }
    return CookieSameSite.Default;
}

// ---- priority enumeration --------------------------------------------------

// Eviction priority levels during garbage collection.
enum CookiePriority {
    Low,
    Medium, // Default priority (COOKIE_PRIORITY_DEFAULT)
    High,
}

// Canonical string representation of priority_level.
fn priority_to_string(priority_level: CookiePriority) -> const u8[:] {
    return match priority_level {
        Low => "Low",
        Medium => "Medium",
        High => "High",
    };
}

// Parses a Priority attribute value case-insensitively, defaulting to CookiePriority.Medium.
fn parse_cookie_priority(raw_val: const u8[:]) -> CookiePriority {
    if core::eq_ascii_fold(raw_val, "low") { return CookiePriority.Low; }
    if core::eq_ascii_fold(raw_val, "high") { return CookiePriority.High; }
    return CookiePriority.Medium;
}

// ---- source scheme enumeration ---------------------------------------------

// Source scheme for origin-bound cookies.
enum CookieSourceScheme {
    Unset,
    NonSecure,
    Secure,
}

// Canonical string representation of source_scheme.
fn source_scheme_to_string(source_scheme: CookieSourceScheme) -> const u8[:] {
    return match source_scheme {
        Unset => "Unset",
        NonSecure => "NonSecure",
        Secure => "Secure",
    };
}

// Parses a serialized source scheme string case-insensitively, defaulting to CookieSourceScheme.Unset.
fn parse_cookie_source_scheme(raw_val: const u8[:]) -> CookieSourceScheme {
    if core::eq_ascii_fold(raw_val, "secure") { return CookieSourceScheme.Secure; }
    if core::eq_ascii_fold(raw_val, "nonsecure") { return CookieSourceScheme.NonSecure; }
    return CookieSourceScheme.Unset;
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

// Numeric telemetry code for delete_cause.
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

// Canonical identifier string for delete_cause.
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
