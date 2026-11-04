// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Zero-allocation slice partitioning, single-delimiter splitting, and token iteration.
namespace core;

import std;

// Splits s around the first occurrence of delimiter byte delim.
// Returns (prefix_before_delim, suffix_after_delim, true) if delim is present;
// otherwise returns (s, "", false). Delimiter byte is omitted from both returned slices.
//
// Example:
//   s = "key=value", delim = '='
//   returns: "key", "value", ok = true
fn split_once_byte(s: const u8[:], delim: u8) -> const u8[:], const u8[:], bool {
    let idx = index_of_byte(s, delim);
    if idx >= 0 {
        return s[..idx], s[idx + 1..], true;
    }
    return s, "", false;
}

// Splits s around the last occurrence of delimiter byte delim.
// Returns (prefix_before_delim, suffix_after_delim, true) if delim is present;
// otherwise returns (s, "", false). Delimiter byte is omitted from both returned slices.
//
// Example:
//   s = "a/b/c", delim = '/'
//   returns: "a/b", "c", ok = true
fn rsplit_once_byte(s: const u8[:], delim: u8) -> const u8[:], const u8[:], bool {
    let idx = last_index_of_byte(s, delim);
    if idx >= 0 {
        return s[..idx], s[idx + 1..], true;
    }
    return s, "", false;
}

// Splits s around the first occurrence of delimiter subslice delim.
// Returns (prefix_before_delim, suffix_after_delim, true) if delim is present;
// otherwise returns (s, "", false). Delimiter is omitted from both returned slices.
//
// Example:
//   s = "foo::bar", delim = "::"
//   returns: "foo", "bar", ok = true
fn split_once(s: const u8[:], delim: const u8[:]) -> const u8[:], const u8[:], bool {
    guard delim.len > 0 else { return s, "", false; }
    let idx = find(s, delim);
    if idx >= 0 {
        return s[..idx], s[idx + delim.len..], true;
    }
    return s, "", false;
}

// Splits s around the first case-insensitive ASCII occurrence of delimiter subslice delim.
// Returns (prefix_before_delim, suffix_after_delim, true) if delim is present;
// otherwise returns (s, "", false). Delimiter is omitted from both returned slices.
//
// Example:
//   s = "Content-Type: text/plain", delim = ": "
//   returns: "Content-Type", "text/plain", ok = true
fn split_once_fold(s: const u8[:], delim: const u8[:]) -> const u8[:], const u8[:], bool {
    guard delim.len > 0 else { return s, "", false; }
    let idx = index_of_fold(s, delim);
    if idx >= 0 {
        return s[..idx], s[idx + delim.len..], true;
    }
    return s, "", false;
}

// Zero-allocation byte tokenizer for iterating over delimiter-separated tokens.
struct ByteTokenizer {
    src:       const u8[:],
    cursor:    i64  = 0,
    delim:     u8   = 0,
    exhausted: bool = false,
}

// Initializes a ByteTokenizer on src scanning for single byte delimiter delim.
fn make_byte_tokenizer(src: const u8[:], delim: u8) -> ByteTokenizer {
    return ByteTokenizer {
        src:       src,
        cursor:    0,
        delim:     delim,
        exhausted: false,
    };
}

// Advances the tokenizer and yields the next token.
// Returns (token_slice, true) while tokens remain, or ("", false) when exhausted.
fn token_next(tok: ByteTokenizer&) -> const u8[:], bool {
    guard !tok.exhausted else { return "", false; }

    if tok.cursor == tok.src.len {
        tok.exhausted = true;
        if tok.cursor > 0 {
            return "", true;
        }
        return "", false;
    }

    guard tok.cursor < tok.src.len else {
        tok.exhausted = true;
        return "", false;
    }

    let start = tok.cursor;
    let rel_idx = index_of_byte(tok.src[start..], tok.delim);
    if rel_idx >= 0 {
        tok.cursor = start + rel_idx + 1;
        return tok.src[start..start + rel_idx], true;
    }

    tok.cursor = tok.src.len;
    tok.exhausted = true;
    return tok.src[start..], true;
}

// Finds the 0-based index of the first occurrence of `delim` outside double quotes ("..."),
// honoring backslash-escaped characters (`\"` and `\\`). Returns `s.len` if `delim` is not found.
//
// Example:
//   s = "foo=\"a;b\"; bar=1", delim = ';'
//   returns: 9 (index of ';' after closing quote)
fn find_unquoted_byte(s: const u8[:], delim: u8) -> i64 {
    var in_quotes = false;
    var escaped = false;
    for b, i in s {
        if escaped {
            escaped = false;
        } else if in_quotes && b == '\\' {
            escaped = true;
        } else if b == '"' {
            in_quotes = !in_quotes;
        } else if !in_quotes && b == delim {
            return i;
        }
    }
    return s.len;
}

// Splits `s` at the first occurrence of `delim` outside double quotes ("...").
// Returns `(prefix, remainder, true)` when `delim` is found, or `(s, "", false)` when not found.
//
// Example:
//   s = "for=\"192.0.2.1\";proto=https", delim = ';'
//   returns: "for=\"192.0.2.1\"", "proto=https", ok = true
fn split_once_unquoted_byte(s: const u8[:], delim: u8) -> const u8[:], const u8[:], bool {
    let idx = find_unquoted_byte(s, delim);
    let next_idx = add_sat_i64(idx, 1);
    guard idx >= 0 && next_idx <= s.len else {
        return s, "", false;
    }
    return s[..idx], s[next_idx..], true;
}
