// Byte scanning, index lookups, and predicate search primitives.
namespace core;

import std;

// Checks whether s begins with prefix.
fn starts_with(s: const u8[:], prefix: const u8[:]) -> bool {
    guard s.len >= prefix.len else { return false; }
    return s[..prefix.len] == prefix;
}

// Checks whether s ends with suffix.
fn ends_with(s: const u8[:], suffix: const u8[:]) -> bool {
    guard s.len >= suffix.len else { return false; }
    return s[s.len - suffix.len..] == suffix;
}

// Checks whether s begins with prefix (alias for starts_with).
fn has_prefix(s: const u8[:], prefix: const u8[:]) -> bool {
    return starts_with(s, prefix);
}

// Checks whether s ends with suffix (alias for ends_with).
fn has_suffix(s: const u8[:], suffix: const u8[:]) -> bool {
    return ends_with(s, suffix);
}

// Checks whether haystack contains needle as a contiguous subslice.
fn contains(haystack: const u8[:], needle: const u8[:]) -> bool {
    return find(haystack, needle) >= 0;
}

// Checks whether s contains byte b.
fn contains_byte(s: const u8[:], b: u8) -> bool {
    for c in s {
        if c == b { return true; }
    }
    return false;
}

// Returns the 0-based index of the first occurrence of byte b in s, or -1 if not found.
fn index_of_byte(s: const u8[:], b: u8) -> i64 {
    for i in s.len {
        if s[i] == b { return i; }
    }
    return -1;
}

// Returns the 0-based index of the last occurrence of byte b in s, or -1 if not found.
fn last_index_of_byte(s: const u8[:], b: u8) -> i64 {
    var idx: i64 = s.len - 1;
    while idx >= 0 {
        if s[idx] == b { return idx; }
        idx--;
    }
    return -1;
}

// Returns the 0-based index of the first occurrence of needle in haystack, or -1 if not found.
fn index_of_slice(haystack: const u8[:], needle: const u8[:]) -> i64 {
    return find(haystack, needle);
}

// Counts the number of non-overlapping occurrences of byte b in s.
fn count_byte(s: const u8[:], b: u8) -> i64 {
    var count: i64 = 0;
    for c in s {
        if c == b { count++; }
    }
    return count;
}
