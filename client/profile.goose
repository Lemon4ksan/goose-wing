// Client profile definitions and header sensitivity classification (RFC 9110).
namespace wing;

import std;

// ---- client profiles & header models ---------------------------------------

enum Profile {
    Wing,      // Authentic Wing Zero-Heap Systems Engine identity (Default)
    Custom,    // User-controlled custom profile
    None,      // Minimal raw client without default headers
}

struct HeaderItem {
    name: u8[..64] = [],
    value: u8[..256] = [],
    is_sensitive: bool = false,
}

// ---- header item & ascii helpers -------------------------------------------

// Whether name is a credential or session header that should be stripped on
// cross-origin redirects or scheme downgrades.
fn is_heuristic_sensitive_header(name: const u8[:]) -> bool {
    return eq_ascii_fold(name, "authorization") ||
           eq_ascii_fold(name, "proxy-authorization") ||
           eq_ascii_fold(name, "cookie") ||
           eq_ascii_fold(name, "x-api-key") ||
           eq_ascii_fold(name, "x-auth-token") ||
           eq_ascii_fold(name, "x-access-token") ||
           eq_ascii_fold(name, "x-signature-256") ||
           eq_ascii_fold(name, "x-csrf-token") ||
           eq_ascii_fold(name, "x-xsrf-token") ||
           eq_ascii_fold(name, "www-authenticate") ||
           eq_ascii_fold(name, "proxy-authenticate") ||
           eq_ascii_fold(name, "x-amz-security-token");
}

// Appends src to out with CR, LF, and NUL bytes omitted (RFC 9110 Section 5.5).
fn sanitize_header_bytes<B>(src: const u8[:], out: B&) {
    for b in src {
        if b != '\r' && b != '\n' && b != 0 {
            out.push(b);
        }
    }
}

// A sanitized HeaderItem, detecting sensitive headers and stripping control bytes.
fn make_header(name: const u8[:], value: const u8[:], is_sensitive: bool = false) -> HeaderItem {
    let sens = is_sensitive || is_heuristic_sensitive_header(name);
    var header_item = HeaderItem { is_sensitive: sens, .. };
    sanitize_header_bytes(name, header_item.name);
    sanitize_header_bytes(value, header_item.value);
    return header_item;
}

fn eq_ascii_fold(str_a: const u8[:], str_b: const u8[:]) -> bool {
    guard str_a.len == str_b.len else { return false; }
    for char_idx in str_a.len {
        let char_a = if str_a[char_idx] >= 'A' && str_a[char_idx] <= 'Z' { str_a[char_idx] + 32 } else { str_a[char_idx] };
        let char_b = if str_b[char_idx] >= 'A' && str_b[char_idx] <= 'Z' { str_b[char_idx] + 32 } else { str_b[char_idx] };
        if char_a != char_b { return false; }
    }
    return true;
}

// ---- profile user-agents ---------------------------------------------------

fn profile_user_agent(profile: Profile) -> const u8[:] {
    return match profile {
        Wing => "Wing/1.0 (Goose Zero-Heap Systems Engine) NetStack/7.0",
        Custom => "Wing/1.0 (Custom Profile)",
        None => "goose-wing/0.1",
        _ => "Wing/1.0",
    };
}

fn profile_name(profile: Profile) -> const u8[:] {
    return match profile {
        Wing => "Wing",
        Custom => "Custom",
        None => "None",
        _ => "Wing",
    };
}
