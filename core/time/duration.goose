// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Nanosecond-precision duration arithmetic and string formatting.
namespace core;

import std;

const NANOSECOND:  i64 = 1;
const MICROSECOND: i64 = 1000 * NANOSECOND;
const MILLISECOND: i64 = 1000 * MICROSECOND;
const SECOND:      i64 = 1000 * MILLISECOND;
const MINUTE:      i64 = 60 * SECOND;
const HOUR:        i64 = 60 * MINUTE;
const DAY:         i64 = 24 * HOUR;

// Exact scalar time conversions
const SECS_PER_MINUTE: i64 = 60;
const SECS_PER_HOUR:   i64 = 3600;
const NANOS_PER_MILLI: i64 = 1000000;
const NANOS_PER_SEC:   i64 = 1000000000;

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

fn as_nanos(dur: Duration) -> i64 { return dur.nanos; }
fn as_micros(dur: Duration) -> i64 { return dur.nanos / MICROSECOND; }
fn as_millis(dur: Duration) -> i64 { return dur.nanos / MILLISECOND; }
fn as_secs(dur: Duration) -> i64 { return dur.nanos / SECOND; }
fn as_secs_f64(dur: Duration) -> f64 { return dur.nanos / 1000000000.0; }

fn abs(dur: Duration) -> Duration {
    if dur.nanos == DURATION_MIN_NANOS { return Duration { nanos: DURATION_MAX_NANOS }; }
    return Duration { nanos: if dur.nanos < 0 { -dur.nanos } else { dur.nanos } };
}

// Duration predicates

fn is_zero(dur: Duration) -> bool { return dur.nanos == 0; }
fn is_negative(dur: Duration) -> bool { return dur.nanos < 0; }

// Three-way comparison hook (-1 for less, 0 for equal, +1 for greater).
// std::sort automatically utilizes this hook.
fn compare(dur1: Duration, dur2: Duration) -> i64 {
    if dur1.nanos < dur2.nanos { return -1; }
    if dur1.nanos > dur2.nanos { return 1; }
    return 0;
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
