// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Byte scanning, index lookups, and predicate search primitives.
namespace core;

import std;

// Equal check for 1..32 byte slices using branchless unaligned 64/32/16-bit XOR.
fn equal_short(s: const u8[:], needle: const u8[:]) -> bool {
    guard s.len == needle.len else { return false; }
    let n = needle.len;
    guard n >= 1 else { return true; }
    if n > 32 {
        return s == needle;
    }
    if n >= 16 {
        return ((read_le_u64(s, 0) ^ read_le_u64(needle, 0)) |
            (read_le_u64(s, 8) ^ read_le_u64(needle, 8)) |
            (read_le_u64(s, n - 16) ^ read_le_u64(needle, n - 16)) |
            (read_le_u64(s, n - 8) ^ read_le_u64(needle, n - 8))) == 0;
    }
    if n >= 8 {
        return ((read_le_u64(s, 0) ^ read_le_u64(needle, 0)) |
            (read_le_u64(s, n - 8) ^ read_le_u64(needle, n - 8))) == 0;
    }
    if n >= 4 {
        return ((read_le_u32(s, 0) ^ read_le_u32(needle, 0)) |
            (read_le_u32(s, n - 4) ^ read_le_u32(needle, n - 4))) == 0;
    }
    if n >= 2 {
        return ((read_le_u16(s, 0) ^ read_le_u16(needle, 0)) |
            (read_le_u16(s, n - 2) ^ read_le_u16(needle, n - 2))) == 0;
    }
    return s[0] == needle[0];
}

// Checks whether s begins with prefix.
fn starts_with(s: const u8[:], prefix: const u8[:]) -> bool {
    guard s.len >= prefix.len else { return false; }
    if prefix.len <= 32 {
        return equal_short(s[..prefix.len], prefix);
    }
    return s[..prefix.len] == prefix;
}

// Checks whether s ends with suffix.
fn ends_with(s: const u8[:], suffix: const u8[:]) -> bool {
    guard s.len >= suffix.len else { return false; }
    if suffix.len <= 32 {
        return equal_short(s[^suffix.len..], suffix);
    }
    return s[^suffix.len..] == suffix;
}

extern fn native_memchr(s: const u8[:], b: u8) -> i64 = "wing_memchr";
extern fn native_simd_last_index_of_byte(s: const u8[:], b: u8) -> i64 = "wing_simd_last_index_of_byte";
extern fn native_simd_count_byte(s: const u8[:], b: u8) -> i64 = "wing_simd_count_byte";

// Checks whether s contains byte b using vectorized memchr.
fn contains_byte(s: const u8[:], b: u8) -> bool {
    guard s.len > 0 else { return false; }
    return native_memchr(s, b) >= 0;
}

// Returns the 0-based index of the first occurrence of byte b in s, or -1 if not found.
fn index_of_byte(s: const u8[:], b: u8) -> i64 {
    guard s.len > 0 else { return -1; }
    return native_memchr(s, b);
}

// Returns the 0-based index of the last occurrence of byte b in s, or -1 if not found.
fn last_index_of_byte(s: const u8[:], b: u8) -> i64 {
    guard s.len > 0 else { return -1; }
    return native_simd_last_index_of_byte(s, b);
}

// Counts the number of non-overlapping occurrences of byte b in s using SSE2 vector popcount.
fn count_byte(s: const u8[:], b: u8) -> i64 {
    guard s.len > 0 else { return 0; }
    return native_simd_count_byte(s, b);
}

// Zero-initialized 256-byte membership table constant.
const EMPTY_MEMBERS: u8[256] = [0; 256];

// Scans s forward for matching or non-matching bytes from set.
fn byteset_find(s: const u8[:], set: const u8[:], invert: bool) -> i64 {
    guard s.len > 0 else { return -1; }
    guard set.len > 0 else {
        return if invert { 0 } else { -1 };
    }
    if set.len == 1 && !invert {
        return index_of_byte(s, set[0]);
    }
    var members = EMPTY_MEMBERS;
    for b in set { members[b] = 1; }
    let excluded: u8 = if invert { 1 } else { 0 };
    var rest = s;
    while rest.len >= 4 {
        let base = s.len - rest.len;
        if members[rest[0]] != excluded { return base; }
        if members[rest[1]] != excluded { return base + 1; }
        if members[rest[2]] != excluded { return base + 2; }
        if members[rest[3]] != excluded { return base + 3; }
        rest = rest[4..];
    }
    for b, i in rest {
        if members[b] != excluded { return s.len - rest.len + i; }
    }
    return -1;
}

// Scans s backwards for matching or non-matching bytes from set.
fn byteset_rfind(s: const u8[:], set: const u8[:], invert: bool) -> i64 {
    guard s.len > 0 else { return -1; }
    guard set.len > 0 else {
        return if invert { s.len - 1 } else { -1 };
    }
    if set.len == 1 && !invert {
        return last_index_of_byte(s, set[0]);
    }
    var members = EMPTY_MEMBERS;
    for b in set { members[b] = 1; }
    let excluded: u8 = if invert { 1 } else { 0 };
    var end = s.len;
    while end >= 4 {
        if members[s[end - 1]] != excluded { return end - 1; }
        if members[s[end - 2]] != excluded { return end - 2; }
        if members[s[end - 3]] != excluded { return end - 3; }
        if members[s[end - 4]] != excluded { return end - 4; }
        end -= 4;
    }
    while end > 0 {
        end -= 1;
        if members[s[end]] != excluded { return end; }
    }
    return -1;
}

// Returns the 0-based index of the first byte matching any byte in set, or -1.
fn find_byteset(s: const u8[:], set: const u8[:]) -> i64 {
    return byteset_find(s, set, false);
}

// Returns the 0-based index of the first byte NOT matching any byte in set, or -1.
fn find_not_byteset(s: const u8[:], set: const u8[:]) -> i64 {
    return byteset_find(s, set, true);
}

// Returns the 0-based index of the last byte matching any byte in set, or -1.
fn rfind_byteset(s: const u8[:], set: const u8[:]) -> i64 {
    return byteset_rfind(s, set, false);
}

// Returns the 0-based index of the last byte NOT matching any byte in set, or -1.
fn rfind_not_byteset(s: const u8[:], set: const u8[:]) -> i64 {
    return byteset_rfind(s, set, true);
}

extern fn native_simd_find_pair(
    s: const u8[:], b1: u8, off1: i64, b2: u8, off2: i64, needle: const u8[:],
) -> i64 = "wing_simd_find_pair";

extern fn native_simd_rfind_pair(
    s: const u8[:], b1: u8, off1: i64, b2: u8, off2: i64, needle: const u8[:],
) -> i64 = "wing_simd_rfind_pair";

// memchr background-frequency ranks (smaller = rarer).
const BYTE_RANK: u8[256] = [
    55, 52, 51, 50, 49, 48, 47, 46, 45, 103, 242, 66, 67, 229, 44, 43,
    42, 41, 40, 39, 38, 37, 36, 35, 34, 33, 56, 32, 31, 30, 29, 28,
    255, 148, 164, 149, 136, 160, 155, 173, 221, 222, 134, 122, 232, 202, 215, 224,
    208, 220, 204, 187, 183, 179, 177, 168, 178, 200, 226, 195, 154, 184, 174, 126,
    120, 191, 157, 194, 170, 189, 162, 161, 150, 193, 142, 137, 171, 176, 185, 167,
    186, 112, 175, 192, 188, 156, 140, 143, 123, 133, 128, 147, 138, 146, 114, 223,
    151, 249, 216, 238, 236, 253, 227, 218, 230, 247, 135, 180, 241, 233, 246, 244,
    231, 139, 245, 243, 251, 235, 201, 196, 240, 214, 152, 182, 205, 181, 127, 27,
    212, 211, 210, 213, 228, 197, 169, 159, 131, 172, 105, 80, 98, 96, 97, 81,
    207, 145, 116, 115, 144, 130, 153, 121, 107, 132, 109, 110, 124, 111, 82, 108,
    118, 141, 113, 129, 119, 125, 165, 117, 92, 106, 83, 72, 99, 93, 65, 79,
    166, 237, 163, 199, 190, 225, 209, 203, 198, 217, 219, 206, 234, 248, 158, 239,
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
];

// Selects the two rarest bytes in needle based on background byte frequency.
inline fn rare_pair(needle: const u8[:]) -> i64, i64 {
    guard needle.len >= 2 else { return 0, 0; }
    var a: i64 = 0;
    var b: i64 = 1;
    if BYTE_RANK[needle[b]] < BYTE_RANK[needle[a]] { a = 1; b = 0; }
    let limit = min(needle.len, 255);
    var i: i64 = 2;
    while i < limit {
        if BYTE_RANK[needle[i]] < BYTE_RANK[needle[a]] {
            b = a;
            a = i;
        } else if needle[i] != needle[a] && BYTE_RANK[needle[i]] < BYTE_RANK[needle[b]] {
            b = i;
        }
        i++;
    }
    return a, b;
}

// Two-Way substring search state with critical factorization.
struct TwoWay {
    critical: i64,
    period:   i64,
    memory:   i64,
    bytes:    u64,
}

inline fn two_way_suffix(s: const u8[:], maximal: bool) -> i64, i64 {
    var best:      i64 = 0;
    var period:    i64 = 1;
    var candidate: i64 = 1;
    var offset:    i64 = 0;
    while candidate + offset < s.len {
        let x = s[best + offset];
        let y = s[candidate + offset];
        if x == y {
            if offset + 1 == period {
                candidate += period;
                offset = 0;
            } else {
                offset += 1;
            }
        } else if (maximal && y > x) || (!maximal && y < x) {
            best = candidate;
            candidate += 1;
            period = 1;
            offset = 0;
        } else {
            candidate += offset + 1;
            offset = 0;
            period = candidate - best;
        }
    }
    return best, period;
}

inline fn make_two_way(s: const u8[:]) -> TwoWay {
    let a, ap = two_way_suffix(s, false);
    let b, bp = two_way_suffix(s, true);
    let critical = max(a, b);
    var period = if a > b { ap } else { bp };
    var small = critical * 2 < s.len;
    if small {
        small = s[..critical] == s[period..period + critical];
    }
    if !small {
        let diff = s.len - critical;
        period = max(critical, diff);
    }
    var bits: u64 = 0;
    let rest = if small { s[..period] } else { s };
    for byte in rest {
        bits |= (1 as u64) << (byte & 63);
    }
    return TwoWay {
        critical: critical,
        period:   period,
        memory:   if small { s.len - period } else { 0 },
        bytes:    bits,
    };
}

fn find_two_way_scan(haystack: const u8[:], needle: const u8[:], two: const TwoWay&, periodic: bool) -> i64 {
    let last = haystack.len - needle.len;
    var pos:    i64 = 0;
    var memory: i64 = 0;
    while pos <= last {
        if two.bytes & ((1 as u64) << (haystack[pos + needle.len - 1] & 63)) == 0 {
            pos += needle.len;
            memory = 0;
            continue;
        }
        var i = if periodic { max(two.critical, memory) } else { two.critical };
        if i < needle.len && needle[i] != haystack[pos + i] {
            pos += i - two.critical + 1;
            memory = 0;
            continue;
        }
        let window = haystack[pos..pos + needle.len];
        if i < needle.len {
            i += 1;
            while i < needle.len && needle[i] == window[i] { i += 1; }
        }
        if i < needle.len {
            pos += i - two.critical + 1;
            memory = 0;
        } else {
            var j = two.critical;
            let stop = if periodic { memory } else { 0 };
            while j > stop && needle[j - 1] == window[j - 1] { j -= 1; }
            if j <= stop { return pos; }
            pos += two.period;
            memory = two.memory;
        }
    }
    return -1;
}

fn find_two_way(haystack: const u8[:], needle: const u8[:]) -> i64 {
    let two = make_two_way(needle);
    return if two.memory > 0 {
        find_two_way_scan(haystack, needle, two, true)
    } else {
        find_two_way_scan(haystack, needle, two, false)
    };
}

// Advances reverse suffix critical factorization by one comparison step.
//
// Example:
//   s = "abacaba", maximal = false, best = 6, period = 1, candidate = 5, offset = 0
//   returns: ok = true, best = 6, period = 2, candidate = 4, offset = 0
inline fn reverse_suffix_step(
    s:         const u8[:],
    maximal:   bool,
    best:      i64&,
    period:    i64&,
    candidate: i64&,
    offset:    i64&,
) -> bool {
    guard offset <= candidate else { return false; }
    let idx_x = sub_sat_i64(best, offset);
    let idx_y = sub_sat_i64(candidate, offset);
    guard idx_x >= 0 && idx_x < s.len && idx_y >= 0 && idx_y < s.len else { return false; }
    let x = s[idx_x];
    let y = s[idx_y];
    if x == y {
        if add_sat_i64(offset, 1) == period {
            guard candidate >= period else { return false; }
            candidate = sub_sat_i64(candidate, period);
            offset = 0;
        } else {
            offset = add_sat_i64(offset, 1);
        }
        return true;
    }
    if (maximal && y > x) || (!maximal && y < x) {
        best = candidate;
        guard candidate >= 1 else { return false; }
        candidate = sub_sat_i64(candidate, 1);
        period = 1;
        offset = 0;
        return true;
    }
    let adv = add_sat_i64(offset, 1);
    guard candidate >= adv else { return false; }
    candidate = sub_sat_i64(candidate, adv);
    offset = 0;
    period = sub_sat_i64(best, candidate);
    return true;
}

inline fn reverse_suffix(s: const u8[:], maximal: bool) -> i64, i64 {
    let slen = s.len;
    var best = sub_sat_i64(slen, 1);
    var period: i64 = 1;
    var candidate = sub_sat_i64(slen, 2);
    var offset: i64 = 0;
    while candidate >= 0 && candidate < slen {
        let cont = reverse_suffix_step(s, maximal, best, period, candidate, offset);
        if !cont { break; }
    }
    let crit = sub_sat_i64(sub_sat_i64(slen, 1), best);
    return crit, period;
}

inline fn make_reverse_two_way(s: const u8[:]) -> TwoWay {
    let a, ap = reverse_suffix(s, false);
    let b, bp = reverse_suffix(s, true);
    let crit_rev = max(a, b);
    var period = if a > b { ap } else { bp };
    let slen = s.len;
    let rem_crit = sub_sat_i64(slen, crit_rev);
    var small = crit_rev < rem_crit;
    if small {
        let s1 = rem_crit;
        let s2 = sub_sat_i64(rem_crit, period);
        let e2 = sub_sat_i64(slen, period);
        if s1 >= 0 && s2 >= 0 && e2 <= slen && s2 <= e2 {
            small = s[s1..] == s[s2..e2];
        } else {
            small = false;
        }
    }
    if !small {
        period = max(crit_rev, rem_crit);
    }
    var bits: u64 = 0;
    let rest_len = if small { min(period, slen) } else { slen };
    var idx: i64 = 0;
    while idx >= 0 && idx < rest_len && idx < slen {
        let byte = s[idx];
        let shift = (byte & 63) as u32;
        bits |= shl_sat_u64(1, shift);
        idx = add_sat_i64(idx, 1);
    }
    let mem_val = sub_sat_i64(slen, period);
    return TwoWay {
        critical: rem_crit,
        period:   period,
        memory:   if small { mem_val } else { 0 },
        bytes:    bits,
    };
}

inline fn rfind_match_left(haystack: const u8[:], needle: const u8[:], base: i64, start_i: i64) -> i64 {
    var i = start_i;
    while i > 0 {
        let idx = sub_sat_i64(i, 1);
        let h_idx = add_sat_i64(base, idx);
        guard idx >= 0 && idx < needle.len && h_idx >= 0 && h_idx < haystack.len else { break; }
        let nl_b = needle[idx];
        let wn_b = haystack[h_idx];
        if nl_b != wn_b { break; }
        i = idx;
    }
    return i;
}

inline fn rfind_match_right(
    haystack: const u8[:],
    needle:   const u8[:],
    base:     i64,
    start_j:  i64,
    stop:     i64,
) -> i64 {
    var j = start_j;
    while j < stop {
        let h_idx = add_sat_i64(base, j);
        guard j >= 0 && j < needle.len && h_idx >= 0 && h_idx < haystack.len else { break; }
        let nl_b = needle[j];
        let wn_b = haystack[h_idx];
        if nl_b != wn_b { break; }
        j = add_sat_i64(j, 1);
    }
    return j;
}

inline fn rfind_two_way_step(
    haystack: const u8[:],
    needle:   const u8[:],
    two:      const TwoWay&,
    periodic: bool,
    base:     i64&,
    memory:   i64&,
) -> bool {
    let nlen = needle.len;
    let ucrit = two.critical;
    let first_b = haystack[base];
    let shift = (first_b & 63) as u32;
    if (two.bytes & shl_sat_u64(1, shift)) == 0 {
        base = sub_sat_i64(base, nlen);
        memory = nlen;
        return false;
    }
    let start_i = if periodic { min(ucrit, memory) } else { ucrit };
    let i = rfind_match_left(haystack, needle, base, start_i);
    if i > 0 {
        let step = add_sat_i64(sub_sat_i64(ucrit, i), 1);
        base = sub_sat_i64(base, step);
        memory = nlen;
        return false;
    }
    let stop = if periodic { memory } else { nlen };
    let j = rfind_match_right(haystack, needle, base, ucrit, stop);
    if j >= stop { return true; }
    base = sub_sat_i64(base, two.period);
    memory = sub_sat_i64(nlen, two.memory);
    return false;
}

fn rfind_two_way_scan(haystack: const u8[:], needle: const u8[:], two: const TwoWay&, periodic: bool) -> i64 {
    let nlen = needle.len;
    let hlen = haystack.len;
    var memory = nlen;
    var base = sub_sat_i64(hlen, nlen);
    while base >= 0 && base < hlen {
        let matched = rfind_two_way_step(haystack, needle, two, periodic, base, memory);
        if matched { return base; }
    }
    return -1;
}

// Searches for needle in haystack in reverse using Crochemore-Perrin Two-Way factorization.
//
// Example:
//   haystack = "aaabbbccc---long_boundary_needle_33_bytes---xx---long_boundary_needle_33_bytes---zz"
//   needle = "---long_boundary_needle_33_bytes---"
//   returns: 46
fn rfind_two_way(haystack: const u8[:], needle: const u8[:]) -> i64 {
    let two = make_reverse_two_way(needle);
    return if two.memory > 0 {
        rfind_two_way_scan(haystack, needle, two, true)
    } else {
        rfind_two_way_scan(haystack, needle, two, false)
    };
}

// Searches for needle in haystack using SIMD packed-pair (< 32 bytes) or Two-Way (> 32 bytes).
// Returns the 0-based byte index of the first match, or -1 if not found.
fn find(haystack: const u8[:], needle: const u8[:]) -> i64 {
    guard needle.len <= haystack.len else { return -1; }
    guard needle.len > 0 else { return 0; }
    if needle.len == 1 {
        return index_of_byte(haystack, needle[0]);
    }
    if needle.len <= 32 {
        let a, b = rare_pair(needle);
        return native_simd_find_pair(haystack, needle[a], a, needle[b], b, needle);
    }
    return find_two_way(haystack, needle);
}

// Searches for needle in haystack in reverse.
// Returns the 0-based byte index of the last match, or -1 if not found.
fn rfind(haystack: const u8[:], needle: const u8[:]) -> i64 {
    guard needle.len <= haystack.len else { return -1; }
    guard needle.len > 0 else { return haystack.len; }
    if needle.len == 1 {
        return last_index_of_byte(haystack, needle[0]);
    }
    if needle.len <= 32 {
        let a, b = rare_pair(needle);
        return native_simd_rfind_pair(haystack, needle[a], a, needle[b], b, needle);
    }
    return rfind_two_way(haystack, needle);
}

// Checks whether haystack contains needle as a contiguous subslice.
fn contains(haystack: const u8[:], needle: const u8[:]) -> bool {
    return find(haystack, needle) >= 0;
}

extern fn native_swar_find_ctl(s: const u8[:]) -> i64 = "wing_swar_find_ctl";
extern fn native_fast_find_crlfcrlf(s: const u8[:]) -> i64 = "wing_fast_find_crlfcrlf";

// Scans slice 8 bytes at a time in 1 CPU cycle using SWAR hasLess(word, 32) (uWebSockets HttpParser.h).
// Returns the index of the first control character (< 32, e.g. \r, \n, \t, \0), or s.len if none found.
fn swar_find_ctl(s: const u8[:]) -> i64 {
    return native_swar_find_ctl(s);
}

// High-speed CRLFCRLF (\r\n\r\n) HTTP header delimiter scanner.
// Returns the index of the first '\r' in \r\n\r\n, or -1 if not found.
fn fast_find_crlfcrlf(s: const u8[:]) -> i64 {
    return native_fast_find_crlfcrlf(s);
}

// Places sentinel fence bytes '\r' and 'a' at offset length and length+1 in wire buffer (uWebSockets HttpParser.h).
// Allows SWAR and vectorized parsers to scan safely without bounds checks in the inner loop.
fn fence_wire_slice(buf: u8[:], length: i64) -> bool {
    guard length >= 0 && length <= sub_sat_i64(buf.len, 2) else { return false; }
    buf[length] = '\r';
    buf[length + 1] = 'a';
    return true;
}

extern fn native_prefetch_t0(s: const u8[:]) = "wing_prefetch_t0";
extern fn native_prefetch_nta(s: const u8[:]) = "wing_prefetch_nta";

// Prefetches slice memory into L1 Data Cache.
inline fn prefetch_t0(s: const u8[:]) {
    native_prefetch_t0(s);
}

// Prefetches slice memory using non-temporal streaming hint (minimizes cache pollution).
inline fn prefetch_nta(s: const u8[:]) {
    native_prefetch_nta(s);
}
