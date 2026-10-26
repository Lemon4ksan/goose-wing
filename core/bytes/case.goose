// Case-insensitive ASCII folding, character predicates, and ASCII transformations.
namespace core;

import std;

// Checks whether byte is ASCII uppercase letter ('A'..'Z').
fn is_ascii_upper(b: u8) -> bool {
    return b >= 'A' && b <= 'Z';
}

// Checks whether byte is ASCII lowercase letter ('a'..'z').
fn is_ascii_lower(b: u8) -> bool {
    return b >= 'a' && b <= 'z';
}

// Checks whether byte is ASCII alphabetic ('A'..'Z' or 'a'..'z').
fn is_ascii_alpha(b: u8) -> bool {
    return (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z');
}

// Checks whether byte is ASCII decimal digit ('0'..'9').
fn is_ascii_digit(b: u8) -> bool {
    return b >= '0' && b <= '9';
}

// Checks whether byte is ASCII alphanumeric ('0'..'9', 'a'..'z', 'A'..'Z').
fn is_ascii_alphanumeric(b: u8) -> bool {
    return is_ascii_alpha(b) || is_ascii_digit(b);
}

// Converts an ASCII byte to lowercase if it is uppercase; otherwise returns unchanged.
fn to_lower_ascii_byte(b: u8) -> u8 {
    return if b >= 'A' && b <= 'Z' { b + 32 } else { b };
}

// Converts an ASCII byte to uppercase if it is lowercase; otherwise returns unchanged.
fn to_upper_ascii_byte(b: u8) -> u8 {
    return if b >= 'a' && b <= 'z' { b - 32 } else { b };
}

// RFC 9110 Section 5.6.3: Compares two byte slices for case-insensitive ASCII equality.
// Fast path compares slices via vectorized gs_memeq if identical.
fn eq_ascii_fold(str_a: const u8[:], str_b: const u8[:]) -> bool {
    guard str_a.len == str_b.len else { return false; }
    if str_a == str_b { return true; }
    for i in str_a.len {
        let ca = if str_a[i] >= 'A' && str_a[i] <= 'Z' { str_a[i] + 32 } else { str_a[i] };
        let cb = if str_b[i] >= 'A' && str_b[i] <= 'Z' { str_b[i] + 32 } else { str_b[i] };
        if ca != cb { return false; }
    }
    return true;
}

// Checks whether s begins with prefix using case-insensitive ASCII comparison.
fn starts_with_fold(s: const u8[:], prefix: const u8[:]) -> bool {
    guard s.len >= prefix.len else { return false; }
    return eq_ascii_fold(s[..prefix.len], prefix);
}

// Checks whether s ends with suffix using case-insensitive ASCII comparison.
fn ends_with_fold(s: const u8[:], suffix: const u8[:]) -> bool {
    guard s.len >= suffix.len else { return false; }
    return eq_ascii_fold(s[s.len - suffix.len..], suffix);
}

// Searches for needle in haystack using case-insensitive ASCII comparison.
// Returns the 0-based byte index of the first match, or -1 if not found.
fn index_of_fold(haystack: const u8[:], needle: const u8[:]) -> i64 {
    guard needle.len <= haystack.len else { return -1; }
    guard needle.len > 0 else { return 0; }
    let max_pos = haystack.len - needle.len;
    for i in max_pos + 1 {
        if eq_ascii_fold(haystack[i..i + needle.len], needle) {
            return i;
        }
    }
    return -1;
}

// Checks whether haystack contains needle using case-insensitive ASCII comparison.
fn contains_fold(haystack: const u8[:], needle: const u8[:]) -> bool {
    return index_of_fold(haystack, needle) >= 0;
}

// Appends ASCII lowercase transformed bytes from src into out buffer.
fn to_lower_ascii<B>(src: const u8[:], out: B&) {
    for b in src {
        out.push(to_lower_ascii_byte(b));
    }
}

// Appends ASCII uppercase transformed bytes from src into out buffer.
fn to_upper_ascii<B>(src: const u8[:], out: B&) {
    for b in src {
        out.push(to_upper_ascii_byte(b));
    }
}
