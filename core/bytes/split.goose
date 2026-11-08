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

// Removes `prefix` from the start of `s` if present.
// Returns `(s[prefix.len..], true)` when `s` starts with `prefix`, or `(s, false)` otherwise.
//
// Example:
//   s = "https://example.com", prefix = "https://"
//   returns: "example.com", ok = true
fn strip_prefix(s: const u8[:], prefix: const u8[:]) -> const u8[:], bool {
    if starts_with(s, prefix) {
        return s[prefix.len..], true;
    }
    return s, false;
}

// Removes `suffix` from the end of `s` if present.
// Returns `(s[..^suffix.len], true)` when `s` ends with `suffix`, or `(s, false)` otherwise.
//
// Example:
//   s = "example.com.", suffix = "."
//   returns: "example.com", ok = true
fn strip_suffix(s: const u8[:], suffix: const u8[:]) -> const u8[:], bool {
    if ends_with(s, suffix) {
        return s[..^suffix.len], true;
    }
    return s, false;
}

// Removes `prefix` from the start of `s` using ASCII case-insensitive comparison.
// Returns `(s[prefix.len..], true)` when `s` starts with `prefix`, or `(s, false)` otherwise.
//
// Example:
//   s = "Bearer token123", prefix = "bearer "
//   returns: "token123", ok = true
fn strip_prefix_fold(s: const u8[:], prefix: const u8[:]) -> const u8[:], bool {
    if starts_with_fold(s, prefix) {
        return s[prefix.len..], true;
    }
    return s, false;
}

// Removes `suffix` from the end of `s` using ASCII case-insensitive comparison.
// Returns `(s[..^suffix.len], true)` when `s` ends with `suffix`, or `(s, false)` otherwise.
//
// Example:
//   s = "Example.COM", suffix = ".com"
//   returns: "Example", ok = true
fn strip_suffix_fold(s: const u8[:], suffix: const u8[:]) -> const u8[:], bool {
    if ends_with_fold(s, suffix) {
        return s[..^suffix.len], true;
    }
    return s, false;
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

// Returns the unconsumed remainder slice of `tok.src` starting at `tok.cursor`,
// or `""` when `tok.exhausted` is true or `tok.cursor >= tok.src.len`.
//
// Example:
//   tok = make_byte_tokenizer("a,b,c", ',') (with tok.cursor = 2)
//   returns: "b,c"
fn token_rest(tok: const ByteTokenizer&) -> const u8[:] {
    guard !tok.exhausted && tok.cursor >= 0 && tok.cursor < tok.src.len else {
        return "";
    }
    return tok.src[tok.cursor..];
}

// Peeks at the next token without advancing `tok`.
// Returns `(token_slice, true)` while tokens remain, or `("", false)` when exhausted.
//
// Example:
//   tok = make_byte_tokenizer("a,b", ',')
//   returns: "a", ok = true (tok.cursor remains 0)
fn token_peek(tok: const ByteTokenizer&) -> const u8[:], bool {
    guard !tok.exhausted else { return "", false; }
    if tok.cursor == tok.src.len {
        if tok.cursor > 0 {
            return "", true;
        }
        return "", false;
    }
    let rem = token_rest(tok);
    guard rem.len > 0 else { return "", false; }
    let rel_idx = index_of_byte(rem, tok.delim);
    if rel_idx >= 0 {
        return rem[..rel_idx], true;
    }
    return rem, true;
}

// Advances the tokenizer and yields the next token.
// Returns (token_slice, true) while tokens remain, or ("", false) when exhausted.
//
// Example:
//   tok = make_byte_tokenizer("a,b", ',')
//   returns: "a", ok = true, tok.cursor = 2
fn token_next(tok: ByteTokenizer&) -> const u8[:], bool {
    let part, ok = token_peek(tok);
    guard ok else {
        tok.exhausted = true;
        return "", false;
    }
    let next_cursor = add_sat_i64(tok.cursor, add_sat_i64(part.len, 1));
    if next_cursor <= tok.src.len {
        tok.cursor = next_cursor;
    } else {
        tok.cursor = tok.src.len;
        tok.exhausted = true;
    }
    return part, true;
}

// Iterates over `delim`-separated tokens in `src`, invoking `F(part)` on each non-empty token.
fn each_non_empty_token<F>(src: const u8[:], delim: u8) {
    var tok = make_byte_tokenizer(src, delim);
    while true {
        let part, ok = token_next(tok);
        if !ok {
            break;
        }
        if part.len > 0 {
            F(part);
        }
    }
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
