// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Absolute wall-clock instant, timezone offsets, Date and Time models.
namespace core;

import std;
import os;
import core.math.ct;
import core.math.arithmetic;
import core.time.sim;

// ---- time: wall-clock instant & civil projection ---------------------------

// Represents an absolute instant in time with an explicit timezone offset.
// Monotonic time is strictly separated into Stopwatch and Deadline.
struct Time {
    wall_sec:  i64 = 0,   // Seconds elapsed since Unix epoch 1970-01-01 00:00:00 UTC.
    nsec:      i32 = 0,   // Subsecond fractional nanoseconds in range [0, 999_999_999].
    tz_offset: i32 = 0,   // Seconds east of UTC (e.g. +10800 for UTC+3, -18000 for UTC-5; 0 = UTC).
}

fn now() -> Time {
    if sim_clock_is_active() {
        return unix_nano(sim_now_ns());
    }
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
    let sec_delta = div_euclid_i64(nano_count, 1000000000);
    let nsec_rem = rem_euclid_i64(nano_count, 1000000000);
    return Time {
        wall_sec:  add_sat_i64(secs_count, sec_delta),
        nsec:      nsec_rem as i32,
        tz_offset: 0,
    };
}

fn unix_milli(millis_count: i64) -> Time {
    let sec = div_euclid_i64(millis_count, 1000);
    let rem = mul_sat_i64(rem_euclid_i64(millis_count, 1000), 1000000);
    return Time {
        wall_sec:  sec,
        nsec:      rem as i32,
        tz_offset: 0,
    };
}

fn unix_micro(micros_count: i64) -> Time {
    let sec = div_euclid_i64(micros_count, 1000000);
    let rem = mul_sat_i64(rem_euclid_i64(micros_count, 1000000), 1000);
    return Time {
        wall_sec:  sec,
        nsec:      rem as i32,
        tz_offset: 0,
    };
}

fn unix_nano(nanos_count: i64) -> Time {
    let sec = div_euclid_i64(nanos_count, 1000000000);
    let rem = rem_euclid_i64(nanos_count, 1000000000);
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
    return date(year_val, month_number(month_val), day_val, hour_val, min_val, sec_val, nsec_val, tz_offset);
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
    let days_count = civil_to_days(year_val, month_num, day_val);
    let day_secs = mul_sat_i64(days_count, 86400);
    let hms_secs = add_sat_i64(
        add_sat_i64(mul_sat_i64(hour_val, 3600), mul_sat_i64(min_val, 60)),
        sec_val,
    );
    let total_secs = sub_sat_i64(add_sat_i64(day_secs, hms_secs), tz_offset);
    var result_time = unix(total_secs, nsec_val);
    result_time.tz_offset = tz_offset;
    return result_time;
}

// Decomposes local instant into civil components: year, month, day, hour, minute, second.
fn civil_parts(time_val: Time) -> i64, i64, i64, i64, i64, i64 {
    let local_secs = add_sat_i64(time_val.wall_sec, time_val.tz_offset);
    let days_count = div_euclid_i64(local_secs, 86400);
    let remainder_secs = rem_euclid_i64(local_secs, 86400);

    let year_val, month_val, day_val = days_to_civil(days_count);
    let hour_val = div_euclid_i64(remainder_secs, 3600);
    let min_val = div_euclid_i64(rem_euclid_i64(remainder_secs, 3600), 60);
    let sec_val = rem_euclid_i64(remainder_secs, 60);
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
    let local_secs = add_sat_i64(time_val.wall_sec, time_val.tz_offset);
    let days_count = div_euclid_i64(local_secs, 86400);
    let weekday_num = rem_euclid_i64(add_sat_i64(rem_euclid_i64(days_count, 7), 4), 7);
    return weekday_from_number(weekday_num);
}

fn clock(time_val: Time) -> i64, i64, i64 {
    let _, _, _, hour_val, min_val, sec_val = civil_parts(time_val);
    return hour_val, min_val, sec_val;
}

fn hour(time_val: Time) -> i64 { let _, _, _, hour_val, _, _ = civil_parts(time_val); return hour_val; }
fn minute(time_val: Time) -> i64 { let _, _, _, _, min_val, _ = civil_parts(time_val); return min_val; }
fn second(time_val: Time) -> i64 { let _, _, _, _, _, sec_val = civil_parts(time_val); return sec_val; }

inline fn scale_wall_time_sat(wall_sec: i64, sub_units: i64, scale: i64) -> i64 {
    if wall_sec < 0 && sub_units > 0 {
        return sub_sat_i64(mul_sat_i64(add_sat_i64(wall_sec, 1), scale), sub_sat_i64(scale, sub_units));
    }
    return add_sat_i64(mul_sat_i64(wall_sec, scale), sub_units);
}

fn unix(time_val: Time) -> i64 { return time_val.wall_sec; }
fn unix_milli(time_val: Time) -> i64 {
    return scale_wall_time_sat(time_val.wall_sec, div_euclid_i64(time_val.nsec, 1000000), 1000);
}
fn unix_micro(time_val: Time) -> i64 {
    return scale_wall_time_sat(time_val.wall_sec, div_euclid_i64(time_val.nsec, 1000), 1000000);
}
fn unix_nano(time_val: Time) -> i64 {
    return scale_wall_time_sat(time_val.wall_sec, time_val.nsec, 1000000000);
}
fn is_zero(time_val: Time) -> bool { return time_val.wall_sec == 0 && time_val.nsec == 0; }

// --- Time Arithmetic ---

fn add(time_val: Time, dur: Duration) -> Time {
    let dur_sec = div_euclid_i64(dur.nanos, 1000000000);
    let dur_nsec = rem_euclid_i64(dur.nanos, 1000000000);
    var sec_val = add_sat_i64(time_val.wall_sec, dur_sec);
    var nsec_val = add_sat_i64(time_val.nsec, dur_nsec);
    if nsec_val >= 1000000000 {
        sec_val = add_sat_i64(sec_val, 1);
        nsec_val = sub_sat_i64(nsec_val, 1000000000);
    } else if nsec_val < 0 {
        sec_val = sub_sat_i64(sec_val, 1);
        nsec_val = add_sat_i64(nsec_val, 1000000000);
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
    let nsec_diff = sub_sat_i64(time_val.nsec, other_time.nsec);
    if time_val.wall_sec >= 0 && other_time.wall_sec < 0 {
        let neg_other = sub_sat_i64(0, other_time.wall_sec);
        if add_sat_u64(time_val.wall_sec as u64, neg_other as u64) > (MAX_WALL_SEC_FOR_NANOS as u64) {
            return Duration { nanos: DURATION_MAX_NANOS };
        }
    } else if time_val.wall_sec < 0 && other_time.wall_sec >= 0 {
        let neg_self = sub_sat_i64(0, time_val.wall_sec);
        if add_sat_u64(other_time.wall_sec as u64, neg_self as u64) > (MAX_WALL_SEC_FOR_NANOS as u64) {
            return Duration { nanos: DURATION_MIN_NANOS };
        }
    }
    let sec_diff = sub_sat_i64(time_val.wall_sec, other_time.wall_sec);
    if sec_diff > MAX_WALL_SEC_FOR_NANOS || (sec_diff == MAX_WALL_SEC_FOR_NANOS && nsec_diff > 854775807) {
        return Duration { nanos: DURATION_MAX_NANOS };
    }
    let min_wall = sub_sat_i64(0, MAX_WALL_SEC_FOR_NANOS);
    let min_nsec = sub_sat_i64(0, 854775808);
    if sec_diff < min_wall || (sec_diff == min_wall && nsec_diff < min_nsec) {
        return Duration { nanos: DURATION_MIN_NANOS };
    }
    return Duration { nanos: add_sat_i64(mul_sat_i64(sec_diff, NANOS_PER_SEC), nsec_diff) };
}

fn sub(time_val: Time, dur: Duration) -> Time {
    let dur_sec = div_euclid_i64(dur.nanos, 1000000000);
    let dur_nsec = rem_euclid_i64(dur.nanos, 1000000000);
    var sec_val = sub_sat_i64(time_val.wall_sec, dur_sec);
    var nsec_val = sub_sat_i64(time_val.nsec, dur_nsec);
    if nsec_val < 0 {
        sec_val = sub_sat_i64(sec_val, 1);
        nsec_val = add_sat_i64(nsec_val, 1000000000);
    } else if nsec_val >= 1000000000 {
        sec_val = add_sat_i64(sec_val, 1);
        nsec_val = sub_sat_i64(nsec_val, 1000000000);
    }
    return Time {
        wall_sec:  sec_val,
        nsec:      nsec_val as i32,
        tz_offset: time_val.tz_offset,
    };
}

fn days_in_month(time_val: Time) -> i64 {
    let year_val, month_val, _, _, _, _ = civil_parts(time_val);
    return days_in_month(year_val, month_val);
}

fn is_leap_year(time_val: Time) -> bool {
    return is_leap_year(time_val.year());
}

fn since(time_val: Time) -> Duration {
    return now().sub(time_val);
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

fn before(time_val: Time, other_time: Time) -> bool {
    return compare(time_val, other_time) < 0;
}

fn after(time_val: Time, other_time: Time) -> bool {
    return compare(time_val, other_time) > 0;
}

fn utc(time_val: Time) -> Time {
    var utc_time = time_val;
    utc_time.tz_offset = 0;
    return utc_time;
}

fn tz_offset(time_val: Time) -> i32 {
    return time_val.tz_offset;
}
