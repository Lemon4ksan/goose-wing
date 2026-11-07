// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Universal Function Call Syntax (UFCS) method bridges for built-in slice, buffer, and integer types.
// Struct and enum types in `namespace core` (`Url`, `Time`, `Duration`, `RingBuffer`, `PipeBuffer`,
// `CorkBuffer`, `ByteCursor`, `ByteBuilder`, `SingleflightGroup`, `WyRand`, `JacobsonRttEstimator`, etc.)
// resolve UFCS dot-calls directly in `namespace core` via Goose's receiver-namespace lookup (`2e2bedef`).
namespace core;

import std;
import core.math;
import core.time;
import core.url;
import core.sync;
import core.bytes;

// ---- io stream ufcs bridges (generic buffer <B>) ---------------------------

fn ::append_u16_be<B>(out: B&, v: u16) { core::append_u16_be(out, v); }
fn ::append_u24_be<B>(out: B&, v: u32) { core::append_u24_be(out, v); }
fn ::append_u32_be<B>(out: B&, v: u32) { core::append_u32_be(out, v); }
fn ::append_u64_be<B>(out: B&, v: u64) { core::append_u64_be(out, v); }

// ---- bytes & stringview ufcs bridges (const u8[:]) -------------------------

fn ::eq_ascii_fold(a: const u8[:], b: const u8[:]) -> bool { return core::eq_ascii_fold(a, b); }
fn ::starts_with_fold(s: const u8[:], prefix: const u8[:]) -> bool { return core::starts_with_fold(s, prefix); }
fn ::ends_with_fold(s: const u8[:], suffix: const u8[:]) -> bool { return core::ends_with_fold(s, suffix); }
fn ::contains_fold(haystack: const u8[:], needle: const u8[:]) -> bool { return core::contains_fold(haystack, needle); }
fn ::index_of_fold(haystack: const u8[:], needle: const u8[:]) -> i64 { return core::index_of_fold(haystack, needle); }

fn ::trim_lws(s: const u8[:]) -> const u8[:] { return core::trim_lws(s); }
fn ::trim_lws_start(s: const u8[:]) -> const u8[:] { return core::trim_lws_start(s); }
fn ::trim_lws_end(s: const u8[:]) -> const u8[:] { return core::trim_lws_end(s); }
fn ::trim_ascii_space(s: const u8[:]) -> const u8[:] { return core::trim_ascii_space(s); }
fn ::trim_ascii_space_start(s: const u8[:]) -> const u8[:] { return core::trim_ascii_space_start(s); }
fn ::trim_ascii_space_end(s: const u8[:]) -> const u8[:] { return core::trim_ascii_space_end(s); }
fn ::trim_byte(s: const u8[:], b: u8) -> const u8[:] { return core::trim_byte(s, b); }
fn ::trim_start_byte(s: const u8[:], b: u8) -> const u8[:] { return core::trim_start_byte(s, b); }
fn ::trim_end_byte(s: const u8[:], b: u8) -> const u8[:] { return core::trim_end_byte(s, b); }
fn ::trim_bytes(s: const u8[:], set: const u8[:]) -> const u8[:] { return core::trim_bytes(s, set); }
fn ::trim_start_bytes(s: const u8[:], set: const u8[:]) -> const u8[:] { return core::trim_start_bytes(s, set); }
fn ::trim_end_bytes(s: const u8[:], set: const u8[:]) -> const u8[:] { return core::trim_end_bytes(s, set); }

fn ::contains_byte(s: const u8[:], b: u8) -> bool { return core::contains_byte(s, b); }
fn ::index_of_byte(s: const u8[:], b: u8) -> i64 { return core::index_of_byte(s, b); }
fn ::last_index_of_byte(s: const u8[:], b: u8) -> i64 { return core::last_index_of_byte(s, b); }
fn ::count_byte(s: const u8[:], b: u8) -> i64 { return core::count_byte(s, b); }

fn ::split_once_byte(s: const u8[:], delim: u8) -> const u8[:], const u8[:], bool {
    return core::split_once_byte(s, delim);
}
fn ::rsplit_once_byte(s: const u8[:], delim: u8) -> const u8[:], const u8[:], bool {
    return core::rsplit_once_byte(s, delim);
}
fn ::split_once(s: const u8[:], delim: const u8[:]) -> const u8[:], const u8[:], bool {
    return core::split_once(s, delim);
}
fn ::split_once_fold(s: const u8[:], delim: const u8[:]) -> const u8[:], const u8[:], bool {
    return core::split_once_fold(s, delim);
}
fn ::find_unquoted_byte(s: const u8[:], delim: u8) -> i64 {
    return core::find_unquoted_byte(s, delim);
}
fn ::split_once_unquoted_byte(s: const u8[:], delim: u8) -> const u8[:], const u8[:], bool {
    return core::split_once_unquoted_byte(s, delim);
}

fn ::parse_u64_dec(s: const u8[:]) -> u64, bool { return core::parse_u64_dec(s); }
fn ::parse_i64_dec(s: const u8[:]) -> i64, bool { return core::parse_i64_dec(s); }
fn ::parse_u32_dec(s: const u8[:]) -> u32, bool { return core::parse_u32_dec(s); }
fn ::parse_i32_dec(s: const u8[:]) -> i32, bool { return core::parse_i32_dec(s); }
fn ::parse_u64_hex(s: const u8[:]) -> u64, bool { return core::parse_u64_hex(s); }
fn ::parse_u32_hex(s: const u8[:]) -> u32, bool { return core::parse_u32_hex(s); }
fn ::parse_u8_hex(s: const u8[:]) -> u8, bool { return core::parse_u8_hex(s); }

fn ::to_lower_ascii<B>(src: const u8[:], out: B&) { core::to_lower_ascii(src, out); }
fn ::to_upper_ascii<B>(src: const u8[:], out: B&) { core::to_upper_ascii(src, out); }
fn ::format_u64_dec<B>(val: u64, out: B&) { core::format_u64_dec(val, out); }
fn ::format_i64_dec<B>(val: i64, out: B&) { core::format_i64_dec(val, out); }
fn ::format_u32_dec<B>(val: u32, out: B&) { core::format_u32_dec(val, out); }
fn ::format_u64_hex<B>(val: u64, out: B&, uppercase: bool = false) { core::format_u64_hex(val, out, uppercase); }
fn ::format_u32_hex<B>(val: u32, out: B&, uppercase: bool = false) { core::format_u32_hex(val, out, uppercase); }
fn ::format_u8_hex<B>(val: u8, out: B&, uppercase: bool = false) { core::format_u8_hex(val, out, uppercase); }

// ---- utf-8 validation bridge (const u8[:]) ---------------------------------

fn ::is_valid_utf8(data: const u8[:]) -> bool { return core::validate_utf8(data); }
fn ::validate_utf8(data: const u8[:]) -> bool { return core::validate_utf8(data); }

// ---- fast query lookup bridges (const u8[:]) -------------------------------

fn ::get_query_param_fast<B>(raw_query: const u8[:], key: const u8[:], out: B&) -> bool, bool {
    return core::get_query_param_fast(raw_query, key, out);
}

fn ::has_query_param_fast(raw_query: const u8[:], key: const u8[:]) -> bool {
    return core::has_query_param_fast(raw_query, key);
}

// ---- safe fixed-capacity buffer operations ---------------------------------

fn ::try_push<A, T>(arr: A&, item: T) -> bool {
    guard arr.len < arr.cap else { return false; }
    arr.push(item);
    return true;
}

fn ::try_push(arr: u8[>..]&, item: u8) -> bool {
    arr.push(item);
    return true;
}

fn ::try_append<A, S>(arr: A&, slice: S) -> bool {
    guard arr.len + slice.len <= arr.cap else { return false; }
    arr.append(slice);
    return true;
}

fn ::try_append(arr: u8[>..]&, slice: const u8[:]) -> bool {
    arr.append(slice);
    return true;
}

fn ::try_set<A, S>(arr: A&, slice: S) -> bool {
    guard slice.len <= arr.cap else { return false; }
    arr.clear();
    arr.append(slice);
    return true;
}

// Shifts unconsumed wire bytes in `arr[consumed..arr.len]` to index `0..rem_len` in-place.
fn compact_wire_buffer<B>(arr: B&, consumed: i64) {
    guard consumed > 0 else { return; }
    let rem_len = core::sub_sat_i64(arr.len, consumed);
    if rem_len <= 0 {
        arr.clear();
        return;
    }
    var idx: i64 = 0;
    while idx < rem_len {
        let src_idx = core::add_sat_i64(consumed, idx);
        arr[idx] = arr[src_idx];
        idx = core::add_sat_i64(idx, 1);
    }
    arr.resize(rem_len);
}

fn ::compact_wire_buffer<B>(arr: B&, consumed: i64) { core::compact_wire_buffer(arr, consumed); }
