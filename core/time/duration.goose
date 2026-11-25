// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Nanosecond-precision duration arithmetic, string formatting and parsing.
namespace core;

import std;

const NANOSECOND:  i64 = 1;
const MICROSECOND: i64 = 1000 * NANOSECOND;
const MILLISECOND: i64 = 1000 * MICROSECOND;
const SECOND:      i64 = 1000 * MILLISECOND;
const MINUTE:      i64 = 60 * SECOND;
const HOUR:        i64 = 60 * MINUTE;
const DAY:         i64 = 24 * HOUR;
const WEEK:        i64 = 7 * DAY;

// Exact scalar time conversions
const SECS_PER_MINUTE: i64 = 60;
const SECS_PER_HOUR:   i64 = 3600;
const SECS_PER_DAY:    i64 = 86400;

const NANOS_PER_MICRO:  i64 = 1000;
const MICROS_PER_MILLI: i64 = 1000;
const NANOS_PER_MILLI:  i64 = 1000000;
const NANOS_PER_SEC:    i64 = 1000000000;

// Extreme 64-bit integer duration boundaries
const DURATION_MIN_NANOS: i64 = -9223372036854775807 - 1;
const DURATION_MAX_NANOS: i64 = 9223372036854775807;
let DURATION_MIN_FORMATTED: const u8[:] = "-2562047h47m16.854775808s";

// Maximum wall clock seconds representable in i64 nanoseconds (~292 years)
const MAX_WALL_SEC_FOR_NANOS: i64 = 9223372036;

// ---- duration: nanosecond-precision interval -------------------------------

// Represents a signed time interval with nanosecond resolution (~+/-292 years).
// Goose automatically provides memberwise struct arithmetic:
// dur1 + dur2, dur1 - dur2, dur * factor, dur / factor, -dur, +=, -=, *=, /=.
struct Duration {
    nanos: i64 = 0,
}

fn nanos(nanos_count: i64) -> Duration { return Duration { nanos: nanos_count }; }
fn micros(micros_count: i64) -> Duration { return Duration { nanos: micros_count * MICROSECOND }; }
fn millis(millis_count: i64) -> Duration { return Duration { nanos: millis_count * MILLISECOND }; }
fn secs(secs_count: i64) -> Duration { return Duration { nanos: secs_count * SECOND }; }
fn mins(mins_count: i64) -> Duration { return Duration { nanos: mins_count * MINUTE }; }
fn hours(hours_count: i64) -> Duration { return Duration { nanos: hours_count * HOUR }; }
fn days(days_count: i64) -> Duration { return Duration { nanos: days_count * DAY }; }
fn weeks(weeks_count: i64) -> Duration { return Duration { nanos: weeks_count * WEEK }; }

fn nanoseconds(nanos_count: i64) -> Duration { return nanos(nanos_count); }
fn microseconds(micros_count: i64) -> Duration { return micros(micros_count); }
fn milliseconds(millis_count: i64) -> Duration { return millis(millis_count); }
fn seconds(secs_count: i64) -> Duration { return secs(secs_count); }
fn minutes(mins_count: i64) -> Duration { return mins(mins_count); }

fn as_nanos(dur: Duration) -> i64 { return dur.nanos; }
fn as_micros(dur: Duration) -> i64 { return dur.nanos / MICROSECOND; }
fn as_millis(dur: Duration) -> i64 { return dur.nanos / MILLISECOND; }
fn as_secs(dur: Duration) -> i64 { return dur.nanos / SECOND; }
fn as_mins(dur: Duration) -> i64 { return dur.nanos / MINUTE; }
fn as_hours(dur: Duration) -> i64 { return dur.nanos / HOUR; }
fn as_days(dur: Duration) -> i64 { return dur.nanos / DAY; }
fn as_secs_f64(dur: Duration) -> f64 { return dur.nanos / 1000000000.0; }
fn as_mins_f64(dur: Duration) -> f64 { return dur.nanos / (MINUTE as f64); }
fn as_hours_f64(dur: Duration) -> f64 { return dur.nanos / (HOUR as f64); }

fn nanoseconds(dur: Duration) -> i64 { return as_nanos(dur); }
fn microseconds(dur: Duration) -> i64 { return as_micros(dur); }
fn milliseconds(dur: Duration) -> i64 { return as_millis(dur); }
fn seconds(dur: Duration) -> f64 { return as_secs_f64(dur); }
fn minutes(dur: Duration) -> f64 { return as_mins_f64(dur); }
fn hours(dur: Duration) -> f64 { return as_hours_f64(dur); }

fn add(dur1: Duration, dur2: Duration) -> Duration { return dur1 + dur2; }
fn sub(dur1: Duration, dur2: Duration) -> Duration { return dur1 - dur2; }
fn abs(dur: Duration) -> Duration {
    if dur.nanos == DURATION_MIN_NANOS { return Duration { nanos: DURATION_MAX_NANOS }; }
    return Duration { nanos: if dur.nanos < 0 { -dur.nanos } else { dur.nanos } };
}

// Duration predicates

fn is_zero(dur: Duration) -> bool { return dur.nanos == 0; }
fn is_negative(dur: Duration) -> bool { return dur.nanos < 0; }
fn is_positive(dur: Duration) -> bool { return dur.nanos > 0; }

// Three-way comparison hook (-1 for less, 0 for equal, +1 for greater).
// std::sort automatically utilizes this hook.
fn compare(dur1: Duration, dur2: Duration) -> i64 {
    if dur1.nanos < dur2.nanos { return -1; }
    if dur1.nanos > dur2.nanos { return 1; }
    return 0;
}

// Truncates duration to a multiple of step_dur (towards zero). Returns dur unchanged if step_dur <= 0.
fn truncate(dur: Duration, step_dur: Duration) -> Duration {
    if step_dur.nanos <= 0 { return dur; }
    if dur.nanos == DURATION_MIN_NANOS {
        let q = DURATION_MIN_NANOS / step_dur.nanos;
        return Duration { nanos: q * step_dur.nanos };
    }
    let is_neg = dur.nanos < 0;
    let abs_nanos = if is_neg { -dur.nanos } else { dur.nanos };
    let truncated_abs = (abs_nanos / step_dur.nanos) * step_dur.nanos;
    return Duration { nanos: if is_neg { -truncated_abs } else { truncated_abs } };
}

// Rounds duration to the nearest multiple of step_dur (half rounds away from zero).
fn round(dur: Duration, step_dur: Duration) -> Duration {
    if step_dur.nanos <= 0 { return dur; }
    if dur.nanos == DURATION_MIN_NANOS {
        let q = DURATION_MIN_NANOS / step_dur.nanos;
        let base_nanos = q * step_dur.nanos;
        let rem = base_nanos - DURATION_MIN_NANOS;
        if rem >= step_dur.nanos - rem {
            return dur;
        }
        return Duration { nanos: base_nanos };
    }
    let is_neg = dur.nanos < 0;
    let abs_nanos = if is_neg { -dur.nanos } else { dur.nanos };
    let quotient = abs_nanos / step_dur.nanos;
    let remainder = abs_nanos - quotient * step_dur.nanos;
    var base_nanos = quotient * step_dur.nanos;
    if remainder >= step_dur.nanos - remainder {
        if base_nanos > DURATION_MAX_NANOS - step_dur.nanos { base_nanos = DURATION_MAX_NANOS; }
        else { base_nanos += step_dur.nanos; }
    }
    return Duration { nanos: if is_neg { -base_nanos } else { base_nanos } };
}

// Formats duration into human-readable shorthand (e.g. "0s", "250ms", "1.5s", "2h45m").
fn format_subsecond_duration<B>(out: B&, total_nanos: i64) -> bool {
    guard total_nanos < SECOND else { return false; }
    if total_nanos < MICROSECOND {
        format(out, total_nanos);
        out.append("ns");
        return true;
    }
    if total_nanos < MILLISECOND {
        let micros_val = total_nanos / MICROSECOND;
        let fraction_nanos = total_nanos % MICROSECOND;
        format(out, micros_val);
        append_trimmed_fraction(out, fraction_nanos, 3);
        out.append("us");
        return true;
    }
    let millis_val = total_nanos / MILLISECOND;
    let fraction_nanos = total_nanos % MILLISECOND;
    format(out, millis_val);
    append_trimmed_fraction(out, fraction_nanos, 6);
    out.append("ms");
    return true;
}

fn format_composite_duration<B>(out: B&, total_nanos: i64) {
    let total_secs = total_nanos / SECOND;
    let remainder_nanos = total_nanos % SECOND;

    let hours_val = total_secs / SECS_PER_HOUR;
    let mins_val = (total_secs % SECS_PER_HOUR) / SECS_PER_MINUTE;
    let secs_val = total_secs % SECS_PER_MINUTE;

    if hours_val > 0 {
        format(out, hours_val);
        out.push('h');
    }
    if mins_val > 0 {
        format(out, mins_val);
        out.push('m');
    }
    if secs_val > 0 || remainder_nanos > 0 || (hours_val == 0 && mins_val == 0) {
        format(out, secs_val);
        append_trimmed_fraction(out, remainder_nanos, 9);
        out.push('s');
    }
}

// Hook used automatically by print(dur), str(dur), and array printing.
fn format<B>(out: B&, dur: Duration) {
    if dur.nanos == 0 {
        out.append("0s");
        return;
    }
    if dur.nanos == DURATION_MIN_NANOS {
        out.append(DURATION_MIN_FORMATTED);
        return;
    }
    var total_nanos = dur.nanos;
    if total_nanos < 0 {
        out.push('-');
        total_nanos = -total_nanos;
    }

    if format_subsecond_duration(out, total_nanos) {
        return;
    }

    format_composite_duration(out, total_nanos);
}

// parse_duration parses a duration string into a Duration value.
//
// Format: a possibly signed sequence of decimal numbers with optional fractional parts
// and a unit suffix (e.g. "300ms", "-1.5h", "2h45m", ".5s", "100ns").
// Supported units: "ns", "us" / "us", "ms", "s", "m", "h", "d", "w".
//
// Caller Contract & Nuances:
// - Return Mode: Returns (Duration, false) on any syntactic, range, or numeric failure.
// - Leading Dot: Supports shorthand leading decimal points (e.g. ".5s" -> 500ms).
// - Strict Validation: Rejects multi-sign prefixes, embedded whitespace, duplicate units, or trailing characters.
// - Overflow Protection: Every multiplication and unit sum is guarded against 64-bit integer overflow;
//   inputs exceeding i64.max nanoseconds safely fail with false.
// - Zero Heap: Operates without heap allocations or runtime regex engines.
//
// Example:
//   raw_str = "1h30m"
//   returns: Duration { nanos: 5400000000000 }, ok = true
fn parse_duration(raw_str: const u8[:]) -> Duration, bool {
    let text = trim(raw_str);
    guard text.len > 0 else { return Duration { 0 }, false; }
    if text == DURATION_MIN_FORMATTED {
        return Duration { nanos: DURATION_MIN_NANOS }, true;
    }

    var is_neg = false;
    var cursor = 0;
    if text[0] == '-' {
        is_neg = true;
        cursor = 1;
    } else if text[0] == '+' {
        cursor = 1;
    }
    guard cursor < text.len else { return Duration { 0 }, false; }

    let max_mag: u64 = if is_neg { 0x8000000000000000 } else { 0x7FFFFFFFFFFFFFFF };
    var total_mag: u64 = 0;

    while cursor < text.len {
        let num_start = cursor;
        while cursor < text.len && ((text[cursor] >= '0' && text[cursor] <= '9') || text[cursor] == '.') {
            cursor++;
        }
        let num_str = text[num_start..cursor];
        guard num_str.len > 0 else { return Duration { 0 }, false; }

        let unit_start = cursor;
        while cursor < text.len &&
              !((text[cursor] >= '0' && text[cursor] <= '9') || text[cursor] == '+' || text[cursor] == '-') {
            cursor++;
        }
        let unit_str = text[unit_start..cursor];
        guard unit_str.len > 0 else { return Duration { 0 }, false; }

        let unit_mult, ok_unit = duration_unit_multiplier(unit_str);
        guard ok_unit else { return Duration { 0 }, false; }

        let comp_mag, ok_comp = parse_duration_component(num_str, unit_mult, max_mag);
        guard ok_comp && comp_mag <= max_mag - total_mag else { return Duration { 0 }, false; }

        total_mag += comp_mag;
    }

    if is_neg {
        if total_mag == 0x8000000000000000 {
            return Duration { nanos: DURATION_MIN_NANOS }, true;
        }
        return Duration { nanos: -(total_mag as i64) }, true;
    }
    return Duration { nanos: total_mag as i64 }, true;
}
