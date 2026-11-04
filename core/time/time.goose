// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Absolute wall-clock instant, timezone offsets, Date and Time models.
namespace core;

import std;
import os;

// ---- time: wall-clock instant & civil projection ---------------------------

// Represents an absolute instant in time with an explicit timezone offset.
// Monotonic time is strictly separated into Stopwatch and Deadline.
struct Time {
    wall_sec:  i64 = 0,   // Seconds elapsed since Unix epoch 1970-01-01 00:00:00 UTC.
    nsec:      i32 = 0,   // Subsecond fractional nanoseconds in range [0, 999_999_999].
    tz_offset: i32 = 0,   // Seconds east of UTC (e.g. +10800 for UTC+3, -18000 for UTC-5; 0 = UTC).
}

fn now() -> Time {
    return unix_nano(time_ns());
}

// unix returns the local Time corresponding to the given Unix time,
// secs_count seconds and nano_count nanoseconds since January 1, 1970 UTC.
//
// It is valid to pass nano_count outside the range [0, 999_999_999].
// Negative nanoseconds are normalized properly without two's complement sign
// inversion: passing INT64_MIN (-9223372036854775808) correctly normalizes
// seconds into the past without wrapping into future timestamps.
//
// Zero allocations. O(1) arithmetic complexity.
fn unix(secs_count: i64, nano_count: i64 = 0) -> Time {
    var sec_val = secs_count;
    var nsec_val = nano_count;
    if nsec_val < 0 || nsec_val >= 1000000000 {
        let n = nsec_val / 1000000000;
        sec_val += n;
        nsec_val -= n * 1000000000;
        if nsec_val < 0 {
            nsec_val += 1000000000;
            sec_val -= 1;
        }
    }
    return Time {
        wall_sec:  sec_val,
        nsec:      nsec_val as i32,
        tz_offset: 0,
    };
}

fn unix_milli(millis_count: i64) -> Time {
    var sec = millis_count / 1000;
    let rem = millis_count % 1000;
    if millis_count < 0 && rem != 0 {
        sec -= 1;
    }
    return Time {
        wall_sec:  sec,
        nsec:      (rem * 1000000) as i32,
        tz_offset: 0,
    };
}

fn unix_micro(micros_count: i64) -> Time {
    var sec = micros_count / 1000000;
    let rem = micros_count % 1000000;
    if micros_count < 0 && rem != 0 {
        sec -= 1;
    }
    return Time {
        wall_sec:  sec,
        nsec:      (rem * 1000) as i32,
        tz_offset: 0,
    };
}

fn unix_nano(nanos_count: i64) -> Time {
    var sec = nanos_count / 1000000000;
    let rem = nanos_count % 1000000000;
    if nanos_count < 0 && rem != 0 {
        sec -= 1;
    }
    return Time {
        wall_sec:  sec,
        nsec:      rem as i32,
        tz_offset: 0,
    };
}

fn date(
    year_val:  i64,
    month_val: Month,
    day_val:   i64,
    hour_val:  i64 = 0,
    min_val:   i64 = 0,
    sec_val:   i64 = 0,
    nsec_val:  i64 = 0,
    tz_offset: i32 = 0,
) -> Time {
    let days_count = civil_to_days(year_val, month_number(month_val), day_val);
    let total_secs = days_count * 86400 + hour_val * 3600 + min_val * 60 + sec_val - tz_offset;
    var result_time = unix(total_secs, nsec_val);
    result_time.tz_offset = tz_offset;
    return result_time;
}

fn date(
    year_val:  i64,
    month_num: i64,
    day_val:   i64,
    hour_val:  i64 = 0,
    min_val:   i64 = 0,
    sec_val:   i64 = 0,
    nsec_val:  i64 = 0,
    tz_offset: i32 = 0,
) -> Time {
    return date(year_val, month_from_number(month_num), day_val, hour_val, min_val, sec_val, nsec_val, tz_offset);
}

// Decomposes local instant into civil components: year, month, day, hour, minute, second.
fn civil_parts(time_val: Time) -> i64, i64, i64, i64, i64, i64 {
    let local_secs = time_val.wall_sec + time_val.tz_offset;
    var days_count = local_secs / 86400;
    let remainder_secs = local_secs % 86400;
    if local_secs < 0 && remainder_secs != 0 {
        days_count -= 1;
    }

    let year_val, month_val, day_val = days_to_civil(days_count);
    let hour_val = remainder_secs / 3600;
    let min_val = (remainder_secs % 3600) / 60;
    let sec_val = remainder_secs % 60;
    return year_val, month_val, day_val, hour_val, min_val, sec_val;
}

fn year(time_val: Time) -> i64 { let year_val, _, _, _, _, _ = civil_parts(time_val); return year_val; }
fn month(time_val: Time) -> Month {
    let _, month_val, _, _, _, _ = civil_parts(time_val);
    return month_from_number(month_val);
}
fn month_number(time_val: Time) -> i64 { let _, month_val, _, _, _, _ = civil_parts(time_val); return month_val; }
fn day(time_val: Time) -> i64 { let _, _, day_val, _, _, _ = civil_parts(time_val); return day_val; }
fn weekday(time_val: Time) -> Weekday {
    let local_secs = time_val.wall_sec + time_val.tz_offset;
    var days_count = local_secs / 86400;
    if local_secs < 0 && (local_secs % 86400 != 0) {
        days_count -= 1;
    }
    var weekday_num = (days_count + 4) % 7;
    if weekday_num < 0 { weekday_num += 7; }
    return weekday_from_number(weekday_num);
}

fn clock(time_val: Time) -> i64, i64, i64 {
    let _, _, _, hour_val, min_val, sec_val = civil_parts(time_val);
    return hour_val, min_val, sec_val;
}

fn hour(time_val: Time) -> i64 { let _, _, _, hour_val, _, _ = civil_parts(time_val); return hour_val; }
fn minute(time_val: Time) -> i64 { let _, _, _, _, min_val, _ = civil_parts(time_val); return min_val; }
fn second(time_val: Time) -> i64 { let _, _, _, _, _, sec_val = civil_parts(time_val); return sec_val; }
fn nanosecond(time_val: Time) -> i64 { return time_val.nsec; }

fn unix(time_val: Time) -> i64 { return time_val.wall_sec; }
fn unix_milli(time_val: Time) -> i64 { return time_val.wall_sec * 1000 + time_val.nsec / 1000000; }
fn unix_micro(time_val: Time) -> i64 { return time_val.wall_sec * 1000000 + time_val.nsec / 1000; }
fn unix_nano(time_val: Time) -> i64 { return time_val.wall_sec * 1000000000 + time_val.nsec; }
fn is_zero(time_val: Time) -> bool { return time_val.wall_sec == 0 && time_val.nsec == 0; }

// --- Time Arithmetic ---

fn add(time_val: Time, dur: Duration) -> Time {
    var dur_sec = dur.nanos / 1000000000;
    let dur_nsec = dur.nanos % 1000000000;
    if dur.nanos < 0 && dur_nsec != 0 {
        dur_sec -= 1;
    }
    var sec_val = time_val.wall_sec + dur_sec;
    var nsec_val = time_val.nsec + dur_nsec;
    if nsec_val >= 1000000000 {
        sec_val += 1;
        nsec_val -= 1000000000;
    }
    return Time {
        wall_sec:  sec_val,
        nsec:      nsec_val as i32,
        tz_offset: time_val.tz_offset,
    };
}

// The duration elapsed between two Time points (time_val - other_time).
// Clamps to Duration.max or Duration.min if the difference exceeds the representable range.
fn sub(time_val: Time, other_time: Time) -> Duration {
    let sec_diff = time_val.wall_sec - other_time.wall_sec;
    let nsec_diff: i64 = time_val.nsec - other_time.nsec;

    // Saturated arithmetic preventing integer overflow across large time deltas
    if sec_diff > MAX_WALL_SEC_FOR_NANOS || (sec_diff == MAX_WALL_SEC_FOR_NANOS && nsec_diff > 854775807) {
        return Duration { nanos: DURATION_MAX_NANOS };
    }
    if sec_diff < -MAX_WALL_SEC_FOR_NANOS || (sec_diff == -MAX_WALL_SEC_FOR_NANOS && nsec_diff < -854775808) {
        return Duration { nanos: DURATION_MIN_NANOS };
    }
    return Duration { nanos: sec_diff * NANOS_PER_SEC + nsec_diff };
}

fn sub(time_val: Time, dur: Duration) -> Time {
    var dur_sec = dur.nanos / 1000000000;
    let dur_nsec = dur.nanos % 1000000000;
    if dur.nanos < 0 && dur_nsec != 0 {
        dur_sec -= 1;
    }
    var sec_val = time_val.wall_sec - dur_sec;
    var nsec_val = time_val.nsec - dur_nsec;
    if nsec_val < 0 {
        sec_val -= 1;
        nsec_val += 1000000000;
    }
    return Time {
        wall_sec:  sec_val,
        nsec:      nsec_val as i32,
        tz_offset: time_val.tz_offset,
    };
}

// add_months_clamped adds months_count calendar months to time_val with end-of-month clamping.
//
// Caller Contract & Nuances:
// - End-of-Month Clamping: Adding 1 month to January 31 produces February 28 (or Feb 29 in leap years),
//   NEVER rolling over to March 3. Safe for monthly recurring subscriptions, billing, and deadlines.
// - Offset Invariance: Preserves the original wall-clock hours, minutes, seconds, nanoseconds, and tz_offset.
// - Algorithmic Bound: Operates in O(1) constant time without loops or memory allocations.
fn add_months_clamped(time_val: Time, months_count: i64) -> Time {
    let current_year, current_month, current_day, hour_val, min_val, sec_val = civil_parts(time_val);
    let zero_based = (current_month - 1) + months_count;
    var year_delta = zero_based / 12;
    let month_idx = zero_based % 12;
    if zero_based < 0 && month_idx != 0 {
        year_delta -= 1;
    }
    let new_year = current_year + year_delta;
    let new_month = month_idx + 1;

    let max_day_in_month = days_in_month(new_year, new_month);
    let clamped_day = if current_day > max_day_in_month { max_day_in_month } else { current_day };
    let base_days = civil_to_days(new_year, new_month, clamped_day);
    let total_secs = base_days * 86400 + hour_val * 3600 + min_val * 60 + sec_val - time_val.tz_offset;
    return Time {
        wall_sec:  total_secs,
        nsec:      time_val.nsec,
        tz_offset: time_val.tz_offset,
    };
}

// Adds years with leap-day clamping (e.g. Feb 29, 2024 + 1 year -> Feb 28, 2025).
fn add_years_clamped(time_val: Time, years_count: i64) -> Time {
    return add_months_clamped(time_val, years_count * 12);
}

fn days_in_month(time_val: Time) -> i64 {
    let year_val, month_val, _, _, _, _ = civil_parts(time_val);
    return days_in_month(year_val, month_val);
}

fn days_in_year(time_val: Time) -> i64 {
    return if is_leap_year(time_val.year()) { 366 } else { 365 };
}

fn is_leap_year(time_val: Time) -> bool {
    return is_leap_year(time_val.year());
}

fn since(time_val: Time) -> Duration {
    return now().sub(time_val);
}

fn until(time_val: Time) -> Duration {
    return time_val.sub(now());
}

// Three-way comparison hook (-1 for earlier, 0 for equal, +1 for later).
// std::sort automatically utilizes this hook.
fn compare(time_val: Time, other_time: Time) -> i64 {
    if time_val.wall_sec != other_time.wall_sec {
        return if time_val.wall_sec < other_time.wall_sec { -1 } else { 1 };
    }
    if time_val.nsec != other_time.nsec {
        return if time_val.nsec < other_time.nsec { -1 } else { 1 };
    }
    return 0;
}

fn equal(time_val: Time, other_time: Time) -> bool {
    return time_val.wall_sec == other_time.wall_sec && time_val.nsec == other_time.nsec;
}

fn before(time_val: Time, other_time: Time) -> bool {
    return compare(time_val, other_time) < 0;
}

fn after(time_val: Time, other_time: Time) -> bool {
    return compare(time_val, other_time) > 0;
}

// Rounds time_val down to a multiple of dur since the Unix epoch.
// If dur <= 0, returns time_val unchanged.
fn truncate(time_val: Time, dur: Duration) -> Time {
    if dur.nanos <= 0 { return time_val; }

    // Multiple of whole seconds (e.g. 1s, 1m, 1h, 1d)
    if dur.nanos >= 1000000000 && (dur.nanos % 1000000000 == 0) {
        let step_secs = dur.nanos / 1000000000;
        let rem = time_val.wall_sec % step_secs;
        let trunc_sec = time_val.wall_sec - rem;
        return Time {
            wall_sec:  trunc_sec,
            nsec:      0,
            tz_offset: time_val.tz_offset,
        };
    }

    // Sub-second step that divides 1 second evenly (e.g. 1ms, 10ms, 100ms, 500ms, 1us)
    if dur.nanos < 1000000000 && (1000000000 % dur.nanos == 0) {
        let trunc_nsec = (time_val.nsec / dur.nanos) * dur.nanos;
        return Time {
            wall_sec:  time_val.wall_sec,
            nsec:      trunc_nsec as i32,
            tz_offset: time_val.tz_offset,
        };
    }

    // General case: bounded within ~292 years
    let max_sec: i64 = 9223372036;
    if time_val.wall_sec >= -max_sec && time_val.wall_sec <= max_sec {
        let total_nanos = time_val.wall_sec * 1000000000 + time_val.nsec;
        let rem = total_nanos % dur.nanos;
        let base_nanos = total_nanos - rem;
        var truncated_time = unix(0, base_nanos);
        truncated_time.tz_offset = time_val.tz_offset;
        return truncated_time;
    }

    return time_val;
}

fn round_seconds_multiple(time_val: Time, dur_nanos: i64) -> Time {
    let step_secs = dur_nanos / NANOS_PER_SEC;
    guard step_secs > 0 else { return time_val; }
    let is_neg = time_val.wall_sec < 0;
    let abs_sec = if is_neg { -time_val.wall_sec } else { time_val.wall_sec };
    let rem = abs_sec % step_secs;
    var base_sec = abs_sec - rem;
    let rem_nanos = rem * NANOS_PER_SEC + (if is_neg { -(time_val.nsec as i64) } else { time_val.nsec as i64 });
    if rem_nanos >= (dur_nanos + 1) / 2 {
        base_sec += step_secs;
    }
    return Time {
        wall_sec:  if is_neg { -base_sec } else { base_sec },
        nsec:      0,
        tz_offset: time_val.tz_offset,
    };
}

fn round_subsecond_divisor(time_val: Time, dur_nanos: i64) -> Time {
    let nsec_64: i64 = time_val.nsec;
    let quotient = nsec_64 / dur_nanos;
    let rem = nsec_64 % dur_nanos;
    var base_nsec = quotient * dur_nanos;
    var sec_add: i64 = 0;
    if rem >= (dur_nanos + 1) / 2 {
        base_nsec += dur_nanos;
        if base_nsec >= NANOS_PER_SEC {
            base_nsec -= NANOS_PER_SEC;
            sec_add = 1;
        }
    }
    return Time {
        wall_sec:  time_val.wall_sec + sec_add,
        nsec:      base_nsec as i32,
        tz_offset: time_val.tz_offset,
    };
}

fn round_general_nanos(time_val: Time, dur_nanos: i64) -> Time {
    if time_val.wall_sec >= -MAX_WALL_SEC_FOR_NANOS && time_val.wall_sec <= MAX_WALL_SEC_FOR_NANOS {
        let total_nanos = time_val.wall_sec * NANOS_PER_SEC + time_val.nsec;
        let is_neg = total_nanos < 0;
        let abs_nanos = if is_neg { -total_nanos } else { total_nanos };
        let quotient = abs_nanos / dur_nanos;
        let remainder = abs_nanos - quotient * dur_nanos;
        var base_nanos = quotient * dur_nanos;
        if remainder >= dur_nanos - remainder {
            base_nanos += dur_nanos;
        }
        let rounded_nanos = if is_neg { -base_nanos } else { base_nanos };
        var rounded_time = unix(0, rounded_nanos);
        rounded_time.tz_offset = time_val.tz_offset;
        return rounded_time;
    }
    return time_val;
}

// round returns the result of rounding time_val to the nearest multiple of dur since the Unix epoch (half rounds up).
// If dur <= 0, round returns time_val unchanged.
fn round(time_val: Time, dur: Duration) -> Time {
    if dur.nanos <= 0 { return time_val; }

    if dur.nanos >= NANOS_PER_SEC && (dur.nanos % NANOS_PER_SEC == 0) {
        return round_seconds_multiple(time_val, dur.nanos);
    }
    if dur.nanos < NANOS_PER_SEC && (NANOS_PER_SEC % dur.nanos == 0) {
        return round_subsecond_divisor(time_val, dur.nanos);
    }
    return round_general_nanos(time_val, dur.nanos);
}

// Timezone adjustments

fn in_offset(time_val: Time, tz_offset_seconds: i32) -> Time {
    var shifted_time = time_val;
    shifted_time.tz_offset = tz_offset_seconds;
    return shifted_time;
}

fn in_tz(time_val: Time, hours_offset: i64, minutes_offset: i64 = 0) -> Time {
    let sign = if hours_offset < 0 || minutes_offset < 0 { -1 } else { 1 };
    let abs_hours = if hours_offset < 0 { -hours_offset } else { hours_offset };
    let abs_mins = if minutes_offset < 0 { -minutes_offset } else { minutes_offset };
    let total_secs = sign * (abs_hours * 3600 + abs_mins * 60);
    return in_offset(time_val, total_secs as i32);
}

fn utc(time_val: Time) -> Time {
    var utc_time = time_val;
    utc_time.tz_offset = 0;
    return utc_time;
}

fn tz_offset(time_val: Time) -> i32 {
    return time_val.tz_offset;
}

// Civil Calendar Boundaries

fn start_of_day(time_val: Time) -> Time {
    let year_val, month_val, day_val, _, _, _ = civil_parts(time_val);
    return date(year_val, month_from_number(month_val), day_val, 0, 0, 0, 0, time_val.tz_offset);
}

fn end_of_day(time_val: Time) -> Time {
    let year_val, month_val, day_val, _, _, _ = civil_parts(time_val);
    return date(year_val, month_from_number(month_val), day_val, 23, 59, 59, 999999999, time_val.tz_offset);
}

fn start_of_month(time_val: Time) -> Time {
    let year_val, month_val, _, _, _, _ = civil_parts(time_val);
    return date(year_val, month_from_number(month_val), 1, 0, 0, 0, 0, time_val.tz_offset);
}

fn end_of_month(time_val: Time) -> Time {
    let year_val, month_val, day_val, _, _, _ = civil_parts(time_val);
    let last_day = days_in_month(year_val, month_val);
    return date(year_val, month_from_number(month_val), last_day, 23, 59, 59, 999999999, time_val.tz_offset);
}

fn start_of_year(time_val: Time) -> Time {
    let year_val, _, _, _, _, _ = civil_parts(time_val);
    return date(year_val, Month.January, 1, 0, 0, 0, 0, time_val.tz_offset);
}

fn end_of_year(time_val: Time) -> Time {
    let year_val, _, _, _, _, _ = civil_parts(time_val);
    return date(year_val, Month.December, 31, 23, 59, 59, 999999999, time_val.tz_offset);
}
