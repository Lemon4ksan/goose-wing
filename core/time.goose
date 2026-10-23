// The Goose standard date & time library: candidate for `std::time`.
//
// Core Types:
//   Duration   - signed nanosecond span (~+/-292 years) with memberwise arithmetic (+, -, *, /, -dur).
//   Time       - wall-clock instant (wall_sec since Unix epoch 1970-01-01, subsecond nsec, tz_offset).
//   Stopwatch  - high-resolution monotonic timer for latency measurements.
//   Deadline   - monotonic timeout and cancellation tracker.
//   Month      - calendar month enum (January .. December).
//   Weekday    - civil weekday enum (Sunday .. Saturday).
//
// Standards & Specifications:
//   RFC 3339 / ISO 8601 formatting and zero-allocation parsing.
//   RFC 9110 Section 5.6.7 HTTP-Date formatting (IMF-fixdate) and parsing (IMF, RFC 850, asctime).
//   Howard Hinnant's O(1) proleptic Gregorian civil calendar math.
namespace wing;

import std;
import os;

// ---- duration constants & calendar enums -----------------------------------

let NANOSECOND:  i64 = 1;
let MICROSECOND: i64 = 1000 * NANOSECOND;
let MILLISECOND: i64 = 1000 * MICROSECOND;
let SECOND:      i64 = 1000 * MILLISECOND;
let MINUTE:      i64 = 60 * SECOND;
let HOUR:        i64 = 60 * MINUTE;
let DAY:         i64 = 24 * HOUR;
let WEEK:        i64 = 7 * DAY;

enum Month {
    January,
    February,
    March,
    April,
    May,
    June,
    July,
    August,
    September,
    October,
    November,
    December,
}

enum Weekday {
    Sunday,
    Monday,
    Tuesday,
    Wednesday,
    Thursday,
    Friday,
    Saturday,
}

let MONTH_NAMES: const u8[:][12] = [
    "January", "February", "March", "April", "May", "June",
    "July", "August", "September", "October", "November", "December",
];

let MONTH_SHORT_NAMES: const u8[:][12] = [
    "Jan", "Feb", "Mar", "Apr", "May", "Jun",
    "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
];

let WEEKDAY_NAMES: const u8[:][7] = [
    "Sunday", "Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday",
];

let WEEKDAY_SHORT_NAMES: const u8[:][7] = [
    "Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat",
];

fn month_number(month_val: Month) -> i64 {
    return match month_val {
        January => 1,
        February => 2,
        March => 3,
        April => 4,
        May => 5,
        June => 6,
        July => 7,
        August => 8,
        September => 9,
        October => 10,
        November => 11,
        December => 12,
    };
}

fn month_from_number(month_num: i64) -> Month {
    return match month_num {
        1 => Month.January,
        2 => Month.February,
        3 => Month.March,
        4 => Month.April,
        5 => Month.May,
        6 => Month.June,
        7 => Month.July,
        8 => Month.August,
        9 => Month.September,
        10 => Month.October,
        11 => Month.November,
        12 => Month.December,
        _ => Month.January,
    };
}

fn month_name(month_val: Month) -> const u8[:] {
    return MONTH_NAMES[month_number(month_val) - 1];
}

fn month_short_name(month_val: Month) -> const u8[:] {
    return MONTH_SHORT_NAMES[month_number(month_val) - 1];
}

fn weekday_number(weekday_val: Weekday) -> i64 {
    return match weekday_val {
        Sunday => 0,
        Monday => 1,
        Tuesday => 2,
        Wednesday => 3,
        Thursday => 4,
        Friday => 5,
        Saturday => 6,
    };
}

fn weekday_from_number(weekday_num: i64) -> Weekday {
    return match weekday_num {
        0 => Weekday.Sunday,
        1 => Weekday.Monday,
        2 => Weekday.Tuesday,
        3 => Weekday.Wednesday,
        4 => Weekday.Thursday,
        5 => Weekday.Friday,
        6 => Weekday.Saturday,
        _ => Weekday.Sunday,
    };
}

fn weekday_name(weekday_val: Weekday) -> const u8[:] {
    return WEEKDAY_NAMES[weekday_number(weekday_val)];
}

fn weekday_short_name(weekday_val: Weekday) -> const u8[:] {
    return WEEKDAY_SHORT_NAMES[weekday_number(weekday_val)];
}

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
fn mul(dur: Duration, factor: i64) -> Duration { return dur * factor; }
fn div(dur: Duration, factor: i64) -> Duration { return dur / factor; }
fn abs(dur: Duration) -> Duration {
    let min_i64 = -9223372036854775807 - 1;
    if dur.nanos == min_i64 { return Duration { nanos: 9223372036854775807 }; }
    return Duration { nanos: if dur.nanos < 0 { -dur.nanos } else { dur.nanos } };
}

// Duration predicates (Goose stdlib naming convention without is_ prefix).

fn zero(dur: Duration) -> bool { return dur.nanos == 0; }
fn negative(dur: Duration) -> bool { return dur.nanos < 0; }
fn positive(dur: Duration) -> bool { return dur.nanos > 0; }

fn is_zero(dur: Duration) -> bool { return zero(dur); }
fn is_negative(dur: Duration) -> bool { return negative(dur); }
fn is_positive(dur: Duration) -> bool { return positive(dur); }

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
    let is_neg = dur.nanos < 0;
    let abs_nanos = if is_neg { -dur.nanos } else { dur.nanos };
    let truncated_abs = (abs_nanos / step_dur.nanos) * step_dur.nanos;
    return Duration { nanos: if is_neg { -truncated_abs } else { truncated_abs } };
}

// Rounds duration to the nearest multiple of step_dur (half rounds away from zero).
fn round(dur: Duration, step_dur: Duration) -> Duration {
    if step_dur.nanos <= 0 { return dur; }
    let min_i64 = -9223372036854775807 - 1;
    let max_i64 = 9223372036854775807;
    if dur.nanos == min_i64 { return dur; }
    let is_neg = dur.nanos < 0;
    let abs_nanos = if is_neg { -dur.nanos } else { dur.nanos };
    let quotient = abs_nanos / step_dur.nanos;
    let remainder = abs_nanos - quotient * step_dur.nanos;
    var base_nanos = quotient * step_dur.nanos;
    if remainder >= step_dur.nanos - remainder {
        if base_nanos > max_i64 - step_dur.nanos { base_nanos = max_i64; }
        else { base_nanos += step_dur.nanos; }
    }
    return Duration { nanos: if is_neg { -base_nanos } else { base_nanos } };
}

// Formats duration into human-readable shorthand (e.g. "0s", "250ms", "1.5s", "2h45m").
// Hook used automatically by print(dur), str(dur), and array printing.
fn format<B>(out: B&, dur: Duration) {
    if dur.nanos == 0 {
        out.append("0s");
        return;
    }
    let min_i64 = -9223372036854775807 - 1;
    if dur.nanos == min_i64 {
        out.append("-2562047h47m16.854775808s");
        return;
    }
    var total_nanos = dur.nanos;
    if total_nanos < 0 {
        out.push('-');
        total_nanos = -total_nanos;
    }

    if total_nanos < MICROSECOND {
        format(out, total_nanos);
        out.append("ns");
        return;
    }

    if total_nanos < MILLISECOND {
        let micros_val = total_nanos / MICROSECOND;
        let fraction_nanos = total_nanos % MICROSECOND;
        format(out, micros_val);
        append_trimmed_fraction(out, fraction_nanos, 3);
        out.append("us");
        return;
    }

    if total_nanos < SECOND {
        let millis_val = total_nanos / MILLISECOND;
        let fraction_micros = (total_nanos % MILLISECOND) / 1000;
        format(out, millis_val);
        append_trimmed_fraction(out, fraction_micros, 3);
        out.append("ms");
        return;
    }

    let total_secs = total_nanos / SECOND;
    let remainder_nanos = total_nanos % SECOND;

    let hours_val = total_secs / 3600;
    let mins_val = (total_secs % 3600) / 60;
    let secs_val = total_secs % 60;

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

// Parses duration string (e.g. "300ms", "-1.5h", "2h45m", "10s", "100ns"). Zero-alloc.
// Supported units: ns, us/us, ms, s, m, h, d, w.
fn parse_duration(raw_str: const u8[:]) -> Duration, bool {
    let text = trim(raw_str);
    guard text.len > 0 else { return Duration { 0 }, false; }

    var is_neg = false;
    var cursor = 0;
    if text[0] == '-' {
        is_neg = true;
        cursor = 1;
    } else if text[0] == '+' {
        cursor = 1;
    }
    guard cursor < text.len else { return Duration { 0 }, false; }

    let max_i64 = 9223372036854775807;
    var total_nanos: i64 = 0;

    while cursor < text.len {
        let num_start = cursor;
        while cursor < text.len && ((text[cursor] >= '0' && text[cursor] <= '9') || text[cursor] == '.') {
            cursor++;
        }
        let num_str = text[num_start..cursor];
        guard num_str.len > 0 else { return Duration { 0 }, false; }

        let unit_start = cursor;
        while cursor < text.len && !((text[cursor] >= '0' && text[cursor] <= '9') || text[cursor] == '+' || text[cursor] == '-') {
            cursor++;
        }
        let unit_str = text[unit_start..cursor];
        guard unit_str.len > 0 else { return Duration { 0 }, false; }

        let unit_mult, ok_unit = duration_unit_multiplier(unit_str);
        guard ok_unit else { return Duration { 0 }, false; }

        let component_nanos, ok_comp = parse_duration_component(num_str, unit_mult);
        guard ok_comp else { return Duration { 0 }, false; }
        guard total_nanos <= max_i64 - component_nanos else { return Duration { 0 }, false; }

        total_nanos += component_nanos;
    }

    if is_neg { total_nanos = -total_nanos; }
    return Duration { nanos: total_nanos }, true;
}

// ---- monotonic primitives: stopwatch & deadline ---------------------------

// High-resolution monotonic instant (CLOCK_MONOTONIC / performance counter in nanoseconds).
struct MonotonicInstant {
    nanos: u64 = 0,
}

fn monotonic_now() -> MonotonicInstant {
    let raw_ns = clock_ns();
    return MonotonicInstant { nanos: if raw_ns > 0 { raw_ns as u64 } else { 0 } };
}

fn new_monotonic_instant(nanos_val: u64) -> MonotonicInstant {
    return MonotonicInstant { nanos: nanos_val };
}

fn as_nanos(inst: MonotonicInstant) -> u64 {
    return inst.nanos;
}

fn duration_since(now_inst: MonotonicInstant, anchor: MonotonicInstant) -> Duration {
    if now_inst.nanos <= anchor.nanos {
        return Duration { nanos: 0 };
    }
    let diff = now_inst.nanos - anchor.nanos;
    let max_i64 = 9223372036854775807 as u64;
    let clamped = if diff > max_i64 { max_i64 } else { diff };
    return Duration { nanos: clamped as i64 };
}

// High-resolution monotonic stopwatch backed by the system performance counter.
// Immune to wall-clock adjustments, NTP slew, and leap seconds.
struct Stopwatch {
    start_ns: i64 = 0,
}

fn stopwatch() -> Stopwatch {
    return Stopwatch { start_ns: clock_ns() };
}

fn elapsed(watch: const Stopwatch&) -> Duration {
    return Duration { nanos: clock_ns() - watch.start_ns };
}

fn restart(watch: Stopwatch&) -> Duration {
    let now_ns = clock_ns();
    let elapsed_dur = Duration { nanos: now_ns - watch.start_ns };
    watch.start_ns = now_ns;
    return elapsed_dur;
}

// Monotonic timeout tracker for network deadlines and cancellation tokens.
struct Deadline {
    target_mono_ns: i64 = 0,
    has_deadline: bool = false,
}

fn deadline_after(dur: Duration) -> Deadline {
    let now_ns = clock_ns();
    if dur.nanos <= 0 {
        return Deadline { target_mono_ns: now_ns, has_deadline: true };
    }
    let max_i64 = 9223372036854775807;
    let target = if dur.nanos > max_i64 - now_ns { max_i64 } else { now_ns + dur.nanos };
    return Deadline { target_mono_ns: target, has_deadline: true };
}

fn expired(deadline_val: const Deadline&) -> bool {
    if !deadline_val.has_deadline { return false; }
    return clock_ns() >= deadline_val.target_mono_ns;
}

fn is_expired(deadline_val: const Deadline&) -> bool {
    return expired(deadline_val);
}

fn remaining(deadline_val: const Deadline&) -> Duration {
    if !deadline_val.has_deadline { return Duration { nanos: 9223372036854775807 }; }
    let diff_ns = deadline_val.target_mono_ns - clock_ns();
    return Duration { nanos: if diff_ns > 0 { diff_ns } else { 0 } };
}

fn sleep(dur: Duration) {
    if dur.nanos <= 0 { return; }
    let millis_val = dur.nanos / MILLISECOND;
    if millis_val > 0 {
        sleep_ms(millis_val);
    }
}

// ---- civil calendar math (Howard Hinnant) ----------------------------------

// Converts between proleptic Gregorian calendar (year, month, day) and days since
// Unix epoch (1970-01-01) in O(1) time without loops, lookup tables, or heap allocations.
// Reference: Howard Hinnant, "chrono-Compatible Low-Level Date Algorithms" (2013).
fn days_to_civil(days_since_epoch: i64) -> i64, i64, i64 {
    var shifted_days = days_since_epoch + 719468;
    let era = (if shifted_days >= 0 { shifted_days } else { shifted_days - 146096 }) / 146097;
    let day_of_era = shifted_days - era * 146097;
    let year_of_era = (day_of_era - day_of_era / 1460 + day_of_era / 36524 - day_of_era / 146096) / 365;
    var year_val = year_of_era + era * 400;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month_prime = (5 * day_of_year + 2) / 153;
    let day_val = day_of_year - (153 * month_prime + 2) / 5 + 1;
    let month_val = if month_prime < 10 { month_prime + 3 } else { month_prime - 9 };
    if month_val <= 2 { year_val += 1; }
    return year_val, month_val, day_val;
}

fn civil_to_days(year_val: i64, month_val: i64, day_val: i64) -> i64 {
    var adjusted_year = year_val;
    let adjusted_month = month_val;
    let adjusted_day = day_val;
    if adjusted_month <= 2 { adjusted_year -= 1; }
    let era = (if adjusted_year >= 0 { adjusted_year } else { adjusted_year - 399 }) / 400;
    let year_of_era = adjusted_year - era * 400;
    let day_of_year = (153 * (if adjusted_month > 2 { adjusted_month - 3 } else { adjusted_month + 9 }) + 2) / 5 + adjusted_day - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    return era * 146097 + day_of_era - 719468;
}

fn leap_year(year_val: i64) -> bool {
    return (year_val % 4 == 0 && year_val % 100 != 0) || (year_val % 400 == 0);
}

fn is_leap_year(year_val: i64) -> bool {
    return leap_year(year_val);
}

fn days_in_month(year_val: i64, month_val: i64) -> i64 {
    match month_val {
        1, 3, 5, 7, 8, 10, 12 => 31,
        4, 6, 9, 11 => 30,
        2 => if leap_year(year_val) { 29 } else { 28 },
        _ => 0,
    }
}

// ---- time: wall-clock instant & civil projection ---------------------------

// Represents an absolute instant in time with an explicit timezone offset.
// Monotonic time is strictly separated into Stopwatch and Deadline.
struct Time {
    wall_sec: i64 = 0,    // Seconds elapsed since Unix epoch 1970-01-01 00:00:00 UTC.
    nsec: i32 = 0,        // Subsecond fractional nanoseconds in range [0, 999_999_999].
    tz_offset: i32 = 0,   // Seconds east of UTC (e.g. +10800 for UTC+3, -18000 for UTC-5; 0 = UTC).
}

fn now() -> Time {
    let wall_ns = time_ns();
    let sec = wall_ns / 1000000000;
    let nsec = (wall_ns % 1000000000) as i32;
    return Time {
        wall_sec: sec,
        nsec: nsec,
        tz_offset: 0,
    };
}

fn unix(secs_count: i64, nano_count: i64 = 0) -> Time {
    var sec_val = secs_count;
    var nsec_val: i64 = 0;
    if nano_count >= 0 {
        sec_val += nano_count / 1000000000;
        nsec_val = nano_count % 1000000000;
    } else {
        let pos_nanos = -nano_count;
        let s = pos_nanos / 1000000000;
        let rem_ns = pos_nanos % 1000000000;
        sec_val -= s;
        if rem_ns > 0 {
            sec_val -= 1;
            nsec_val = 1000000000 - rem_ns;
        }
    }
    return Time {
        wall_sec: sec_val,
        nsec: nsec_val as i32,
        tz_offset: 0,
    };
}

fn unix_milli(millis_count: i64) -> Time {
    return unix(millis_count / 1000, (millis_count % 1000) * 1000000);
}

fn unix_micro(micros_count: i64) -> Time {
    return unix(micros_count / 1000000, (micros_count % 1000000) * 1000);
}

fn unix_nano(nanos_count: i64) -> Time {
    return unix(nanos_count / 1000000000, nanos_count % 1000000000);
}

fn date(year_val: i64, month_val: Month, day_val: i64, hour_val: i64 = 0, min_val: i64 = 0, sec_val: i64 = 0, nsec_val: i64 = 0, tz_offset: i32 = 0) -> Time {
    let days_count = civil_to_days(year_val, month_number(month_val), day_val);
    let total_secs = days_count * 86400 + hour_val * 3600 + min_val * 60 + sec_val - tz_offset;
    var result_time = unix(total_secs, nsec_val);
    result_time.tz_offset = tz_offset;
    return result_time;
}

fn date(year_val: i64, month_num: i64, day_val: i64, hour_val: i64 = 0, min_val: i64 = 0, sec_val: i64 = 0, nsec_val: i64 = 0, tz_offset: i32 = 0) -> Time {
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
fn month(time_val: Time) -> Month { let _, month_val, _, _, _, _ = civil_parts(time_val); return month_from_number(month_val); }
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
fn zero(time_val: Time) -> bool { return time_val.wall_sec == 0 && time_val.nsec == 0; }
fn is_zero(time_val: Time) -> bool { return zero(time_val); }

// --- Time Arithmetic ---

fn add(time_val: Time, dur: Duration) -> Time {
    var sec_val = time_val.wall_sec + dur.nanos / 1000000000;
    var nsec_val = time_val.nsec + (dur.nanos % 1000000000);
    if nsec_val >= 1000000000 {
        sec_val += 1;
        nsec_val -= 1000000000;
    } else if nsec_val < 0 {
        sec_val -= 1;
        nsec_val += 1000000000;
    }
    return Time {
        wall_sec: sec_val,
        nsec: nsec_val as i32,
        tz_offset: time_val.tz_offset,
    };
}

fn sub(time_val: Time, other_time: Time) -> Duration {
    let sec_diff = time_val.wall_sec - other_time.wall_sec;
    let nsec_diff = time_val.nsec - other_time.nsec;
    return Duration { nanos: sec_diff * 1000000000 + nsec_diff };
}

fn sub(time_val: Time, dur: Duration) -> Time {
    var sec_val = time_val.wall_sec - dur.nanos / 1000000000;
    var nsec_val = time_val.nsec - (dur.nanos % 1000000000);
    if nsec_val >= 1000000000 {
        sec_val += 1;
        nsec_val -= 1000000000;
    } else if nsec_val < 0 {
        sec_val -= 1;
        nsec_val += 1000000000;
    }
    return Time {
        wall_sec: sec_val,
        nsec: nsec_val as i32,
        tz_offset: time_val.tz_offset,
    };
}

fn sub_duration(time_val: Time, dur: Duration) -> Time {
    return sub(time_val, dur);
}

// Adds months with end-of-month clamping (e.g. Jan 31 + 1 month -> Feb 28/29) in O(1) time.
// This never accidentally overflows into a subsequent month.
fn add_months_clamped(time_val: Time, months_count: i64) -> Time {
    let current_year, current_month, current_day, hour_val, min_val, sec_val = civil_parts(time_val);
    let zero_based = (current_month - 1) + months_count;
    var new_year = current_year + (zero_based / 12);
    var new_month = (zero_based % 12) + 1;
    if new_month < 1 {
        new_month += 12;
        new_year -= 1;
    }

    let max_day_in_month = days_in_month(new_year, new_month);
    let clamped_day = if current_day > max_day_in_month { max_day_in_month } else { current_day };
    let base_days = civil_to_days(new_year, new_month, clamped_day);
    let total_secs = base_days * 86400 + hour_val * 3600 + min_val * 60 + sec_val - time_val.tz_offset;
    return Time {
        wall_sec: total_secs,
        nsec: time_val.nsec,
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
    return if leap_year(time_val.year()) { 366 } else { 365 };
}

fn leap_year(time_val: Time) -> bool {
    return leap_year(time_val.year());
}

fn is_leap_year(time_val: Time) -> bool {
    return leap_year(time_val);
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

// Truncates time to a multiple of dur since Unix epoch. Returns time_val unchanged if dur <= 0.
fn truncate(time_val: Time, dur: Duration) -> Time {
    if dur.nanos <= 0 { return time_val; }
    let total_nanos = time_val.wall_sec * 1000000000 + time_val.nsec;
    let is_neg = total_nanos < 0;
    let abs_nanos = if is_neg { -total_nanos } else { total_nanos };
    let truncated_abs = (abs_nanos / dur.nanos) * dur.nanos;
    let base_nanos = if is_neg { -truncated_abs } else { truncated_abs };
    var truncated_time = unix(0, base_nanos);
    truncated_time.tz_offset = time_val.tz_offset;
    return truncated_time;
}

// Rounds time to the nearest multiple of dur since Unix epoch (half rounds up).
fn round(time_val: Time, dur: Duration) -> Time {
    if dur.nanos <= 0 { return time_val; }
    let total_nanos = time_val.wall_sec * 1000000000 + time_val.nsec;
    let is_neg = total_nanos < 0;
    let abs_nanos = if is_neg { -total_nanos } else { total_nanos };
    let quotient = abs_nanos / dur.nanos;
    let remainder = abs_nanos - quotient * dur.nanos;
    var base_nanos = quotient * dur.nanos;
    if remainder >= dur.nanos - remainder {
        base_nanos += dur.nanos;
    }
    let rounded_nanos = if is_neg { -base_nanos } else { base_nanos };
    var rounded_time = unix(0, rounded_nanos);
    rounded_time.tz_offset = time_val.tz_offset;
    return rounded_time;
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

// ---- codecs: RFC 3339 & RFC 9110 HTTP-Date (public API) --------------------

// Formats Time into RFC 3339 / ISO 8601 string (e.g. "2026-10-22T23:18:18Z" or "2026-10-22T23:18:18+03:00").
// Streaming zero-allocation formatter directly appending to out.
fn format_rfc3339<B>(out: B&, time_val: Time) {
    let year_val, month_val, day_val, hour_val, min_val, sec_val = civil_parts(time_val);
    append_4d(out, year_val);
    out.push('-');
    append_2d(out, month_val);
    out.push('-');
    append_2d(out, day_val);
    out.push('T');
    append_2d(out, hour_val);
    out.push(':');
    append_2d(out, min_val);
    out.push(':');
    append_2d(out, sec_val);

    if time_val.tz_offset == 0 {
        out.push('Z');
    } else {
        var offset_val: i64 = time_val.tz_offset as i64;
        if offset_val < 0 {
            out.push('-');
            offset_val = -offset_val;
        } else {
            out.push('+');
        }
        let offset_hours = offset_val / 3600;
        let offset_mins = (offset_val % 3600) / 60;
        append_2d(out, offset_hours);
        out.push(':');
        append_2d(out, offset_mins);
    }
}

// Formats Time into RFC 3339 with nanosecond fractional precision (e.g. "2026-10-22T23:18:18.5Z").
fn format_rfc3339_nano<B>(out: B&, time_val: Time) {
    let year_val, month_val, day_val, hour_val, min_val, sec_val = civil_parts(time_val);
    append_4d(out, year_val);
    out.push('-');
    append_2d(out, month_val);
    out.push('-');
    append_2d(out, day_val);
    out.push('T');
    append_2d(out, hour_val);
    out.push(':');
    append_2d(out, min_val);
    out.push(':');
    append_2d(out, sec_val);
    append_trimmed_fraction(out, time_val.nsec, 9);

    if time_val.tz_offset == 0 {
        out.push('Z');
    } else {
        var offset_val: i64 = time_val.tz_offset as i64;
        if offset_val < 0 {
            out.push('-');
            offset_val = -offset_val;
        } else {
            out.push('+');
        }
        let offset_hours = offset_val / 3600;
        let offset_mins = (offset_val % 3600) / 60;
        append_2d(out, offset_hours);
        out.push(':');
        append_2d(out, offset_mins);
    }
}

// Universal format hook for Time: used automatically by print(time_val) and str(time_val).
fn format<B>(out: B&, time_val: Time) {
    format_rfc3339(out, time_val);
}

fn format<B>(out: B&, month_val: Month) {
    out.append(month_name(month_val));
}

fn format<B>(out: B&, weekday_val: Weekday) {
    out.append(weekday_name(weekday_val));
}

// Parses RFC 3339 / ISO 8601 strings into Time (e.g. "2026-10-22T23:18:18Z", "2026-10-22T23:18:18+03:00").
// Validates calendar bounds and timezone offset. Zero-allocation.
fn parse_rfc3339(raw_str: const u8[:]) -> Time, bool {
    let text = trim(raw_str);
    guard text.len >= 19 else { return Time { .. }, false; }

    guard text[4] == '-' && text[7] == '-' && (text[10] == 'T' || text[10] == 't' || text[10] == ' ') && text[13] == ':' && text[16] == ':' else {
        return Time { .. }, false;
    }

    let year_val, ok_year = parse_digits(text[..4]);
    let month_val, ok_month = parse_digits(text[5..7]);
    let day_val, ok_day = parse_digits(text[8..10]);
    let hour_val, ok_hour = parse_digits(text[11..13]);
    let min_val, ok_min = parse_digits(text[14..16]);
    let sec_val, ok_sec = parse_digits(text[17..19]);

    guard ok_year && ok_month && ok_day && ok_hour && ok_min && ok_sec else { return Time { .. }, false; }
    guard year_val >= 1 && month_val >= 1 && month_val <= 12 && day_val >= 1 && day_val <= days_in_month(year_val, month_val) else { return Time { .. }, false; }
    guard hour_val >= 0 && hour_val <= 23 && min_val >= 0 && min_val <= 59 && sec_val >= 0 && sec_val <= 60 else { return Time { .. }, false; }

    let nsec_val, cursor, ok_frac = parse_fractional_nanos(text, 19);
    guard ok_frac else { return Time { .. }, false; }

    guard cursor < text.len else { return Time { .. }, false; }
    let parsed_offset, ok_offset = parse_timezone_offset(text[cursor..]);
    guard ok_offset else { return Time { .. }, false; }
    let offset_val = parsed_offset;

    let days_count = civil_to_days(year_val, month_val, day_val);
    let total_secs = days_count * 86400 + hour_val * 3600 + min_val * 60 + sec_val - offset_val;

    return Time {
        wall_sec: total_secs,
        nsec: nsec_val as i32,
        tz_offset: offset_val,
    }, true;
}

// Formats Time into RFC 9110 Section 5.6.7 / RFC 1123 IMF-fixdate (e.g. "Thu, 22 Oct 2026 23:18:18 GMT").
// Always formats in UTC/GMT regardless of local timezone offset.
fn format_http<B>(out: B&, time_val: Time) {
    let utc_time = time_val.utc();
    let year_val, month_val, day_val, hour_val, min_val, sec_val = civil_parts(utc_time);
    let weekday_val = utc_time.weekday();

    out.append(weekday_short_name(weekday_val));
    out.append(", ");
    append_2d(out, day_val);
    out.push(' ');
    out.append(month_short_name(month_from_number(month_val)));
    out.push(' ');
    append_4d(out, year_val);
    out.push(' ');
    append_2d(out, hour_val);
    out.push(':');
    append_2d(out, min_val);
    out.push(':');
    append_2d(out, sec_val);
    out.append(" GMT");
}

// Parses RFC 9110 Section 5.6.7 HTTP-Date formats (IMF-fixdate, RFC 850, asctime).
// Returns (Time, false) if the string is malformed or represents an invalid calendar date.
fn parse_http_date(raw_str: const u8[:]) -> Time, bool {
    let text = trim(raw_str);
    guard text.len >= 24 else { return Time { .. }, false; }

    var comma_idx = -1;
    for scan_idx in text.len {
        if text[scan_idx] == ',' { comma_idx = scan_idx; break; }
    }

    if comma_idx > 0 {
        let day_prefix = text[..comma_idx];
        let rest = trim(text[comma_idx + 1..]);
        var has_dash = false;
        for scan_idx in rest.len {
            if rest[scan_idx] == '-' { has_dash = true; break; }
        }
        if has_dash {
            guard is_valid_weekday_name(day_prefix) else { return Time { .. }, false; }
            return parse_rfc850_date(rest);
        }
        guard is_valid_weekday_short(day_prefix) else { return Time { .. }, false; }
        return parse_imf_fixdate(rest);
    }

    return parse_asctime_date(text);
}

// ---- internal implementation helpers ---------------------------------------
// Formatting helpers, unit multipliers, and sub-parsers.

inline fn append_2d<B>(out: B&, value: i64) {
    let clamped_val = if value < 0 { 0 } else if value > 99 { 99 } else { value };
    out.push(('0' as i64 + clamped_val / 10) as u8);
    out.push(('0' as i64 + clamped_val % 10) as u8);
}

inline fn append_4d<B>(out: B&, value: i64) {
    let clamped_val = if value < 0 { 0 } else if value > 9999 { 9999 } else { value };
    out.push(('0' as i64 + (clamped_val / 1000) % 10) as u8);
    out.push(('0' as i64 + (clamped_val / 100) % 10) as u8);
    out.push(('0' as i64 + (clamped_val / 10) % 10) as u8);
    out.push(('0' as i64 + clamped_val % 10) as u8);
}

fn append_trimmed_fraction<B>(out: B&, fraction_val: i64, num_digits: i64) {
    if fraction_val <= 0 { return; }
    var digits: u8[9] = [0; 9];
    var current_val = fraction_val;
    for digit_idx in num_digits {
        let array_idx = num_digits - 1 - digit_idx;
        digits[array_idx] = ('0' as i64 + (current_val % 10)) as u8;
        current_val /= 10;
    }
    var last_non_zero = num_digits - 1;
    while last_non_zero >= 0 && digits[last_non_zero] == '0' {
        last_non_zero--;
    }
    if last_non_zero >= 0 {
        out.push('.');
        for copy_idx in (last_non_zero + 1) {
            out.push(digits[copy_idx]);
        }
    }
}

fn parse_digits(str_val: const u8[:]) -> i64, bool {
    guard str_val.len > 0 else { return 0, false; }
    let max_i64 = 9223372036854775807;
    var val: i64 = 0;
    for idx in str_val.len {
        let ch = str_val[idx];
        guard ch >= '0' && ch <= '9' else { return 0, false; }
        let digit_val = (ch - '0') as i64;
        guard val <= (max_i64 - digit_val) / 10 else { return 0, false; }
        val = val * 10 + digit_val;
    }
    return val, true;
}

fn is_valid_weekday_short(token: const u8[:]) -> bool {
    guard token.len == 3 else { return false; }
    var clean_buf: u8[3] = [0; 3];
    for char_idx in 3 {
        let char_byte = token[char_idx];
        clean_buf[char_idx] = if char_byte >= 'A' && char_byte <= 'Z' { char_byte + 32 } else { char_byte };
    }
    let s = clean_buf[..];
    return s == "sun" || s == "mon" || s == "tue" || s == "wed" || s == "thu" || s == "fri" || s == "sat";
}

fn is_valid_weekday_name(token: const u8[:]) -> bool {
    if is_valid_weekday_short(token) { return true; }
    guard token.len >= 6 && token.len <= 9 else { return false; }
    var clean_buf: u8[9] = [0; 9];
    for char_idx in token.len {
        let char_byte = token[char_idx];
        clean_buf[char_idx] = if char_byte >= 'A' && char_byte <= 'Z' { char_byte + 32 } else { char_byte };
    }
    let s = clean_buf[..token.len];
    return s == "sunday" || s == "monday" || s == "tuesday" || s == "wednesday" || s == "thursday" || s == "friday" || s == "saturday";
}

fn duration_unit_multiplier(unit_str: const u8[:]) -> i64, bool {
    if unit_str == "ns" { return NANOSECOND, true; }
    if unit_str == "us" || unit_str == "us" || unit_str == "\xc2\xb5s" { return MICROSECOND, true; }
    if unit_str == "ms" { return MILLISECOND, true; }
    if unit_str == "s" { return SECOND, true; }
    if unit_str == "m" { return MINUTE, true; }
    if unit_str == "h" { return HOUR, true; }
    if unit_str == "d" { return DAY, true; }
    if unit_str == "w" { return WEEK, true; }
    return 0, false;
}

fn parse_scaled_fraction(fraction_str: const u8[:], unit_mult: i64) -> i64, bool {
    guard fraction_str.len > 0 else { return 0, true; }
    var fraction_nanos_9d: i64 = 0;
    var scale: i64 = 100000000;
    for frac_idx in fraction_str.len {
        let char_byte = fraction_str[frac_idx];
        guard char_byte >= '0' && char_byte <= '9' else { return 0, false; }
        if scale > 0 {
            fraction_nanos_9d += (char_byte - '0') * scale;
            scale /= 10;
        }
    }
    if unit_mult >= SECOND {
        return fraction_nanos_9d * (unit_mult / SECOND), true;
    }
    return (fraction_nanos_9d * unit_mult) / SECOND, true;
}

fn parse_duration_component(num_str: const u8[:], unit_mult: i64) -> i64, bool {
    var dot_pos = -1;
    for scan_idx in num_str.len {
        if num_str[scan_idx] == '.' {
            if dot_pos >= 0 { return 0, false; }
            dot_pos = scan_idx;
        }
    }

    let max_i64 = 9223372036854775807;

    if dot_pos < 0 {
        let int_val, int_ok = parse_digits(num_str);
        guard int_ok else { return 0, false; }
        guard int_val <= max_i64 / unit_mult else { return 0, false; }
        return int_val * unit_mult, true;
    }

    let whole_str = num_str[..dot_pos];
    let fraction_str = num_str[dot_pos + 1..];
    guard whole_str.len > 0 && fraction_str.len > 0 else { return 0, false; }

    let whole_val, ok_whole = parse_digits(whole_str);
    guard ok_whole else { return 0, false; }
    guard whole_val <= max_i64 / unit_mult else { return 0, false; }
    let whole_nanos = whole_val * unit_mult;

    let fraction_nanos, ok_frac = parse_scaled_fraction(fraction_str, unit_mult);
    guard ok_frac else { return 0, false; }
    guard whole_nanos <= max_i64 - fraction_nanos else { return 0, false; }
    return whole_nanos + fraction_nanos, true;
}

fn parse_fractional_nanos(text: const u8[:], start_pos: i64) -> i64, i64, bool {
    var cursor = start_pos;
    if cursor >= text.len || (text[cursor] != '.' && text[cursor] != ',') {
        return 0, cursor, true;
    }
    cursor++;
    let digit_start = cursor;
    var nsec_val: i64 = 0;
    var scale: i64 = 100000000;
    while cursor < text.len && (text[cursor] >= '0' && text[cursor] <= '9') {
        if scale > 0 {
            nsec_val += (text[cursor] - '0') * scale;
            scale /= 10;
        }
        cursor++;
    }
    guard cursor > digit_start else { return 0, cursor, false; }
    return nsec_val, cursor, true;
}

fn parse_timezone_offset(tz_text: const u8[:]) -> i32, bool {
    guard tz_text.len > 0 else { return 0, false; }
    let tz_char = tz_text[0];
    if tz_char == 'Z' || tz_char == 'z' {
        guard tz_text.len == 1 else { return 0, false; }
        return 0, true;
    }
    guard tz_char == '+' || tz_char == '-' else { return 0, false; }

    let sign = if tz_char == '-' { -1 } else { 1 };
    guard tz_text.len >= 3 else { return 0, false; }
    let off_hours, ok_tz_h = parse_digits(tz_text[1..3]);
    guard ok_tz_h && off_hours <= 23 else { return 0, false; }

    var off_mins: i64 = 0;
    if tz_text.len == 3 {
        off_mins = 0;
    } else if tz_text.len == 5 {
        let parsed_mins, ok_tz_m = parse_digits(tz_text[3..5]);
        guard ok_tz_m && parsed_mins <= 59 else { return 0, false; }
        off_mins = parsed_mins;
    } else if tz_text.len == 6 && tz_text[3] == ':' {
        let parsed_mins, ok_tz_m = parse_digits(tz_text[4..6]);
        guard ok_tz_m && parsed_mins <= 59 else { return 0, false; }
        off_mins = parsed_mins;
    } else {
        return 0, false;
    }

    let offset_seconds = sign * (off_hours * 3600 + off_mins * 60);
    return offset_seconds as i32, true;
}

fn parse_month_name(token: const u8[:]) -> i64 {
    guard token.len == 3 else { return 0; }
    var clean_buf: u8[3] = [0; 3];
    for char_idx in 3 {
        let char_byte = token[char_idx];
        clean_buf[char_idx] = if char_byte >= 'A' && char_byte <= 'Z' { char_byte + 32 } else { char_byte };
    }
    let short_str = clean_buf[..];
    if short_str == "jan" { return 1; }
    if short_str == "feb" { return 2; }
    if short_str == "mar" { return 3; }
    if short_str == "apr" { return 4; }
    if short_str == "may" { return 5; }
    if short_str == "jun" { return 6; }
    if short_str == "jul" { return 7; }
    if short_str == "aug" { return 8; }
    if short_str == "sep" { return 9; }
    if short_str == "oct" { return 10; }
    if short_str == "nov" { return 11; }
    if short_str == "dec" { return 12; }
    return 0;
}

fn make_validated_civil_time(year_val: i64, month_val: i64, day_val: i64, hour_val: i64, min_val: i64, sec_val: i64) -> Time, bool {
    guard year_val >= 1 else { return Time { .. }, false; }
    guard month_val >= 1 && month_val <= 12 else { return Time { .. }, false; }
    guard day_val >= 1 && day_val <= days_in_month(year_val, month_val) else { return Time { .. }, false; }
    guard hour_val >= 0 && hour_val <= 23 && min_val >= 0 && min_val <= 59 && sec_val >= 0 && sec_val <= 60 else { return Time { .. }, false; }

    let days_count = civil_to_days(year_val, month_val, day_val);
    let total_secs = days_count * 86400 + hour_val * 3600 + min_val * 60 + sec_val;
    return unix(total_secs, 0), true;
}

fn parse_imf_fixdate(rest: const u8[:]) -> Time, bool {
    guard rest.len == 24 && rest[2] == ' ' && rest[6] == ' ' && rest[11] == ' ' && rest[14] == ':' && rest[17] == ':' && rest[20..24] == " GMT" else {
        return Time { .. }, false;
    }
    let day_val, ok_day = parse_digits(rest[..2]);
    let month_val = parse_month_name(rest[3..6]);
    let year_val, ok_year = parse_digits(rest[7..11]);
    let hour_val, ok_hour = parse_digits(rest[12..14]);
    let min_val, ok_min = parse_digits(rest[15..17]);
    let sec_val, ok_sec = parse_digits(rest[18..20]);

    guard ok_day && month_val > 0 && ok_year && ok_hour && ok_min && ok_sec else {
        return Time { .. }, false;
    }
    return make_validated_civil_time(year_val, month_val, day_val, hour_val, min_val, sec_val);
}

fn parse_rfc850_date(rest: const u8[:]) -> Time, bool {
    var first_dash = -1;
    for scan_idx in rest.len {
        if rest[scan_idx] == '-' { first_dash = scan_idx; break; }
    }
    guard first_dash >= 1 && first_dash <= 2 else { return Time { .. }, false; }

    let day_val, ok_day = parse_digits(rest[..first_dash]);
    guard ok_day else { return Time { .. }, false; }

    let after_day = rest[first_dash + 1..];
    var second_dash = -1;
    for scan_idx in after_day.len {
        if after_day[scan_idx] == '-' { second_dash = scan_idx; break; }
    }
    guard second_dash == 3 else { return Time { .. }, false; }

    let month_val = parse_month_name(after_day[..second_dash]);
    guard month_val > 0 else { return Time { .. }, false; }

    let after_month = after_day[second_dash + 1..];
    guard after_month.len == 15 && after_month[2] == ' ' && after_month[5] == ':' && after_month[8] == ':' && after_month[11..15] == " GMT" else {
        return Time { .. }, false;
    }

    let parsed_year, ok_year = parse_digits(after_month[..2]);
    guard ok_year else { return Time { .. }, false; }
    let year_val = if parsed_year >= 70 { 1900 + parsed_year } else { 2000 + parsed_year };

    let hour_val, ok_hour = parse_digits(after_month[3..5]);
    let min_val, ok_min = parse_digits(after_month[6..8]);
    let sec_val, ok_sec = parse_digits(after_month[9..11]);
    guard ok_hour && ok_min && ok_sec else { return Time { .. }, false; }

    return make_validated_civil_time(year_val, month_val, day_val, hour_val, min_val, sec_val);
}

fn parse_asctime_date(text: const u8[:]) -> Time, bool {
    guard text.len == 24 && text[3] == ' ' && text[7] == ' ' && text[10] == ' ' && text[13] == ':' && text[16] == ':' && text[19] == ' ' else {
        return Time { .. }, false;
    }
    guard is_valid_weekday_short(text[..3]) else { return Time { .. }, false; }
    let month_val = parse_month_name(text[4..7]);
    guard month_val > 0 else { return Time { .. }, false; }

    let day_part = trim(text[8..10]);
    guard text[8] == ' ' || (text[8] >= '0' && text[8] <= '9') else { return Time { .. }, false; }
    let day_val, ok_day = parse_digits(day_part);
    guard ok_day else { return Time { .. }, false; }

    let hour_val, ok_hour = parse_digits(text[11..13]);
    let min_val, ok_min = parse_digits(text[14..16]);
    let sec_val, ok_sec = parse_digits(text[17..19]);
    let year_val, ok_year = parse_digits(text[20..24]);
    guard ok_hour && ok_min && ok_sec && ok_year else { return Time { .. }, false; }

    return make_validated_civil_time(year_val, month_val, day_val, hour_val, min_val, sec_val);
}
