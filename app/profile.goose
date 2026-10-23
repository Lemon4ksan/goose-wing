// Browser fingerprint profiles and header presets for goose-wing.
//
// Core Types:
//   Profile     - Browser fingerprint presets enum (Chrome131, Firefox133, Safari18, None).
//   HeaderItem  - Single HTTP header key-value pair with sensitive credential tagging.
//
// Standards & Specifications:
//   RFC 9110 HTTP Semantics Header Name Case-Insensitivity (ASCII fold).
//   Heuristic sensitivity classification for credential headers (Authorization, Cookie, API Keys).
namespace wing;

import std;

// ---- browser profiles & header models --------------------------------------

enum Profile {
    None,
    Chrome131,
    Firefox133,
    Safari18,
}

struct HeaderItem {
    name: u8[..64] = [],
    value: u8[..256] = [],
    is_sensitive: bool = false,
}

// ---- header item & ascii helpers -------------------------------------------

fn is_heuristic_sensitive_header(name: const u8[:]) -> bool {
    return eq_ascii_fold(name, "authorization") ||
           eq_ascii_fold(name, "proxy-authorization") ||
           eq_ascii_fold(name, "cookie") ||
           eq_ascii_fold(name, "x-api-key") ||
           eq_ascii_fold(name, "x-auth-token") ||
           eq_ascii_fold(name, "x-access-token");
}

fn make_header(name: const u8[:], value: const u8[:], is_sensitive: bool = false) -> HeaderItem {
    let sens = is_sensitive || is_heuristic_sensitive_header(name);
    var header_item = HeaderItem { is_sensitive: sens, .. };
    header_item.name.append(name);
    header_item.value.append(value);
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
        None => "goose-wing/0.1",
        Chrome131 => "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
        Firefox133 => "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:133.0) Gecko/20100101 Firefox/133.0",
        Safari18 => "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_7_1) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.1 Safari/605.1.15",
    };
}

fn profile_name(profile: Profile) -> const u8[:] {
    return match profile {
        None => "None",
        Chrome131 => "Chrome131",
        Firefox133 => "Firefox133",
        Safari18 => "Safari18",
    };
}
