// Standard Date & Time library for Goose (candidate for std::time).
// Provides nanosecond Duration arithmetic, monotonic Stopwatch & Deadline,
// Howard Hinnant's O(1) civil calendar math, RFC 3339 / ISO 8601 and RFC 9110 HTTP-Date codecs.
namespace wing;

import std;
import os;

// --- Nanosecond Duration Constants ---

let NANOSECOND:  i64 = 1;
let MICROSECOND: i64 = 1000 * NANOSECOND;
let MILLISECOND: i64 = 1000 * MICROSECOND;
let SECOND:      i64 = 1000 * MILLISECOND;
let MINUTE:      i64 = 60 * SECOND;
let HOUR:        i64 = 60 * MINUTE;
let DAY:         i64 = 24 * HOUR;
let WEEK:        i64 = 7 * DAY;

// --- Month and Weekday Enums & Tables ---

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

// --- Duration: Nanosecond-precision Interval ---

// Represents a signed time interval with nanosecond resolution (~±292 years).
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
fn abs(dur: Duration) -> Duration { return Duration { nanos: if dur.nanos < 0 { -dur.nanos } else { dur.nanos } }; }

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
    return Duration { nanos: dur.nanos - (dur.nanos % step_dur.nanos) };
}

// Rounds duration to the nearest multiple of step_dur (half rounds away from zero).
fn round(dur: Duration, step_dur: Duration) -> Duration {
    if step_dur.nanos <= 0 { return dur; }
    let is_neg = dur.nanos < 0;
    let abs_nanos = if is_neg { -dur.nanos } else { dur.nanos };
    let remainder = abs_nanos % step_dur.nanos;
    var base_nanos = abs_nanos - remainder;
    if (remainder * 2) >= step_dur.nanos {
        base_nanos += step_dur.nanos;
    }
    return Duration { nanos: if is_neg { -base_nanos } else { base_nanos } };
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

// Formats duration into human-readable shorthand (e.g. "0s", "250ms", "1.5s", "2h45m").
// Hook used automatically by print(dur), str(dur), and array printing.
fn format<B>(out: B&, dur: Duration) {
    if dur.nanos == 0 {
        out.append("0s");
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
        out.append("µs");
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
// Supported units: ns, us/µs, ms, s, m, h, d, w.
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

    var total_nanos: i64 = 0;

    while cursor < text.len {
        var num_start = cursor;
        while cursor < text.len && ((text[cursor] >= '0' && text[cursor] <= '9') || text[cursor] == '.') {
            cursor++;
        }
        let num_str = text[num_start..cursor];
        guard num_str.len > 0 else { return Duration { 0 }, false; }

        var unit_start = cursor;
        while cursor < text.len && !((text[cursor] >= '0' && text[cursor] <= '9') || text[cursor] == '+' || text[cursor] == '-') {
            cursor++;
        }
        let unit_str = text[unit_start..cursor];
        guard unit_str.len > 0 else { return Duration { 0 }, false; }

        var unit_mult: i64 = 0;
        if unit_str == "ns" {
            unit_mult = NANOSECOND;
        } else if unit_str == "us" || unit_str == "µs" || unit_str == "\xc2\xb5s" {
            unit_mult = MICROSECOND;
        } else if unit_str == "ms" {
            unit_mult = MILLISECOND;
        } else if unit_str == "s" {
            unit_mult = SECOND;
        } else if unit_str == "m" {
            unit_mult = MINUTE;
        } else if unit_str == "h" {
            unit_mult = HOUR;
        } else if unit_str == "d" {
            unit_mult = DAY;
        } else if unit_str == "w" {
            unit_mult = WEEK;
        } else {
            return Duration { 0 }, false;
        }

        var dot_pos = -1;
        for scan_idx in num_str.len {
            if num_str[scan_idx] == '.' { dot_pos = scan_idx; break; }
        }

        if dot_pos < 0 {
            let int_val, int_ok = parse_int(num_str);
            guard int_ok else { return Duration { 0 }, false; }
            total_nanos += int_val * unit_mult;
        } else {
            let whole_str = num_str[..dot_pos];
            let fraction_str = num_str[dot_pos + 1..];

            var whole_val: i64 = 0;
            if whole_str.len > 0 {
                let parsed_val, ok_whole = parse_int(whole_str);
                guard ok_whole else { return Duration { 0 }, false; }
                whole_val = parsed_val;
            }

            total_nanos += whole_val * unit_mult;

            if fraction_str.len > 0 {
                var fraction_val: i64 = 0;
                var div_scale: i64 = 1;
                for frac_idx in fraction_str.len {
                    if frac_idx >= 9 { break; }
                    let char_byte = fraction_str[frac_idx];
                    if char_byte >= '0' && char_byte <= '9' {
                        fraction_val = fraction_val * 10 + (char_byte - '0');
                        div_scale *= 10;
                    }
                }
                total_nanos += (fraction_val * unit_mult) / div_scale;
            }
        }
    }

    if is_neg { total_nanos = -total_nanos; }
    return Duration { nanos: total_nanos }, true;
}

// --- Monotonic Benchmarking & Concurrency Primitives ---

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
    if dur.nanos <= 0 {
        return Deadline { target_mono_ns: clock_ns(), has_deadline: true };
    }
    return Deadline { target_mono_ns: clock_ns() + dur.nanos, has_deadline: true };
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

// --- Howard Hinnant Civil Calendar Algorithm ---
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

// --- Time: Point in Time (Wall-Clock Instant + Civil Projection) ---

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
    var sec_val = secs_count + nano_count / 1000000000;
    var nsec_val = (nano_count % 1000000000) as i32;
    if nsec_val < 0 {
        sec_val -= 1;
        nsec_val += 1000000000;
    }
    return Time {
        wall_sec: sec_val,
        nsec: nsec_val,
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
    var remainder_secs = local_secs % 86400;
    if remainder_secs < 0 {
        remainder_secs += 86400;
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
    let nsec_diff = (time_val.nsec as i64) - other_time.nsec;
    return Duration { nanos: sec_diff * 1000000000 + nsec_diff };
}

fn sub(time_val: Time, dur: Duration) -> Time {
    return add(time_val, Duration { nanos: -dur.nanos });
}

fn sub_duration(time_val: Time, dur: Duration) -> Time {
    return sub(time_val, dur);
}

// Adds months with end-of-month clamping (e.g. Jan 31 + 1 month -> Feb 28/29).
// Unlike Go's AddDate, this never accidentally overflows into a subsequent month.
fn add_months_clamped(time_val: Time, months_count: i64) -> Time {
    let current_year, current_month, current_day, hour_val, min_val, sec_val = civil_parts(time_val);
    var new_year = current_year;
    var new_month = current_month + months_count;
    while new_month > 12 { new_month -= 12; new_year += 1; }
    while new_month < 1 { new_month += 12; new_year -= 1; }

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
    let remainder = total_nanos % dur.nanos;
    let base_nanos = total_nanos - remainder;
    var truncated_time = unix(base_nanos / 1000000000, base_nanos % 1000000000);
    truncated_time.tz_offset = time_val.tz_offset;
    return truncated_time;
}

// Rounds time to the nearest multiple of dur since Unix epoch (half rounds up).
fn round(time_val: Time, dur: Duration) -> Time {
    if dur.nanos <= 0 { return time_val; }
    let total_nanos = time_val.wall_sec * 1000000000 + time_val.nsec;
    let remainder = total_nanos % dur.nanos;
    var base_nanos = total_nanos - remainder;
    if (remainder * 2) >= dur.nanos {
        base_nanos += dur.nanos;
    }
    var rounded_time = unix(base_nanos / 1000000000, base_nanos % 1000000000);
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
    let sign = if hours_offset < 0 { -1 } else { 1 };
    let abs_hours = if hours_offset < 0 { -hours_offset } else { hours_offset };
    let total_secs = sign * (abs_hours * 3600 + minutes_offset * 60);
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
    let year_val, month_val, _, _, _, _ = civil_parts(time_val);
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
        var offset_val = time_val.tz_offset;
        if offset_val < 0 {
            out.push('-');
            offset_val = -offset_val;
        } else {
            out.push('+');
        }
        let offset_hours = (offset_val / 3600) as i64;
        let offset_mins = ((offset_val % 3600) / 60) as i64;
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
        var offset_val = time_val.tz_offset;
        if offset_val < 0 {
            out.push('-');
            offset_val = -offset_val;
        } else {
            out.push('+');
        }
        let offset_hours = (offset_val / 3600) as i64;
        let offset_mins = ((offset_val % 3600) / 60) as i64;
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

    let year_val, ok_year = parse_int(text[..4]);
    let month_val, ok_month = parse_int(text[5..7]);
    let day_val, ok_day = parse_int(text[8..10]);
    let hour_val, ok_hour = parse_int(text[11..13]);
    let min_val, ok_min = parse_int(text[14..16]);
    let sec_val, ok_sec = parse_int(text[17..19]);

    guard ok_year && ok_month && ok_day && ok_hour && ok_min && ok_sec else { return Time { .. }, false; }
    guard month_val >= 1 && month_val <= 12 && day_val >= 1 && day_val <= 31 else { return Time { .. }, false; }
    guard hour_val >= 0 && hour_val <= 23 && min_val >= 0 && min_val <= 59 && sec_val >= 0 && sec_val <= 60 else { return Time { .. }, false; }

    var cursor = 19;
    var nsec_val: i64 = 0;

    if cursor < text.len && (text[cursor] == '.' || text[cursor] == ',') {
        cursor++;
        var scale: i64 = 100000000;
        while cursor < text.len && (text[cursor] >= '0' && text[cursor] <= '9') {
            if scale > 0 {
                nsec_val += (text[cursor] - '0') * scale;
                scale /= 10;
            }
            cursor++;
        }
    }

    var offset_val: i32 = 0;
    if cursor < text.len {
        let tz_char = text[cursor];
        if tz_char == 'Z' || tz_char == 'z' {
            offset_val = 0;
        } else if tz_char == '+' || tz_char == '-' {
            let sign = if tz_char == '-' { -1 } else { 1 };
            cursor++;
            if cursor + 2 <= text.len {
                let off_hours, ok_tz_h = parse_int(text[cursor..cursor + 2]);
                cursor += 2;
                if cursor < text.len && text[cursor] == ':' { cursor++; }
                var off_mins: i64 = 0;
                if cursor + 2 <= text.len {
                    let parsed_mins, ok_tz_m = parse_int(text[cursor..cursor + 2]);
                    if ok_tz_m { off_mins = parsed_mins; }
                }
                if ok_tz_h {
                    offset_val = ((sign * (off_hours * 3600 + off_mins * 60)) as i32);
                }
            }
        }
    }

    let days_count = civil_to_days(year_val, month_val, day_val);
    let total_secs = days_count * 86400 + hour_val * 3600 + min_val * 60 + sec_val - offset_val;

    return Time {
        wall_sec: total_secs,
        nsec: nsec_val as i32,
        tz_offset: offset_val,
    }, true;
}

// Formats Time into RFC 9110 §5.6.7 / RFC 1123 IMF-fixdate (e.g. "Thu, 22 Oct 2026 23:18:18 GMT").
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

fn parse_month_name(token: const u8[:]) -> i64 {
    guard token.len >= 3 else { return 0; }
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

// Parses RFC 9110 §5.6.7 HTTP-Date formats:
// 1. IMF-fixdate: "Sun, 06 Nov 1994 08:49:37 GMT" (preferred RFC 1123 format)
// 2. RFC 850:     "Sunday, 06-Nov-94 08:49:37 GMT" (obsolete 2-digit year format)
// 3. ANSI asctime: "Sun Nov  6 08:49:37 1994" (obsolete fixed-width format)
// Returns (Time, false) if the string is malformed or represents an invalid calendar date.
fn parse_http_date(raw_str: const u8[:]) -> Time, bool {
    let text = trim(raw_str);
    guard text.len >= 24 else { return Time { .. }, false; }

    var day_val: i64 = 0;
    var month_val: i64 = 0;
    var year_val: i64 = 0;
    var hour_val: i64 = 0;
    var min_val: i64 = 0;
    var sec_val: i64 = 0;

    var comma_idx = -1;
    for scan_idx in text.len {
        if text[scan_idx] == ',' { comma_idx = scan_idx; break; }
    }

    if comma_idx > 0 {
        var rest = trim(text[comma_idx + 1..]);
        var first_dash = -1;
        for scan_idx in rest.len {
            if rest[scan_idx] == '-' { first_dash = scan_idx; break; }
        }

        if first_dash > 0 {
            // RFC 850: "06-Nov-94 08:49:37 GMT"
            let parsed_day, ok_day = parse_int(rest[..first_dash]);
            guard ok_day else { return Time { .. }, false; }
            day_val = parsed_day;

            rest = rest[first_dash + 1..];
            var second_dash = -1;
            for scan_idx in rest.len {
                if rest[scan_idx] == '-' { second_dash = scan_idx; break; }
            }
            guard second_dash > 0 else { return Time { .. }, false; }
            let parsed_month = parse_month_name(rest[..second_dash]);
            guard parsed_month > 0 else { return Time { .. }, false; }
            month_val = parsed_month;

            rest = rest[second_dash + 1..];
            guard rest.len >= 11 && rest[2] == ' ' && rest[5] == ':' && rest[8] == ':' else {
                return Time { .. }, false;
            }
            let parsed_year, ok_year = parse_int(rest[..2]);
            guard ok_year else { return Time { .. }, false; }
            year_val = if parsed_year >= 70 { 1900 + parsed_year } else { 2000 + parsed_year };

            let parsed_hour, ok_hour = parse_int(rest[3..5]);
            let parsed_min, ok_min = parse_int(rest[6..8]);
            let parsed_sec, ok_sec = parse_int(rest[9..11]);
            guard ok_hour && ok_min && ok_sec else { return Time { .. }, false; }
            hour_val = parsed_hour; min_val = parsed_min; sec_val = parsed_sec;
        } else {
            // IMF-fixdate: "06 Nov 1994 08:49:37 GMT"
            guard rest.len >= 20 && rest[2] == ' ' && rest[6] == ' ' && rest[11] == ' ' && rest[14] == ':' && rest[17] == ':' else {
                return Time { .. }, false;
            }
            let parsed_day, ok_day = parse_int(rest[..2]);
            guard ok_day else { return Time { .. }, false; }
            day_val = parsed_day;

            let parsed_month = parse_month_name(rest[3..6]);
            guard parsed_month > 0 else { return Time { .. }, false; }
            month_val = parsed_month;

            let parsed_year, ok_year = parse_int(rest[7..11]);
            guard ok_year else { return Time { .. }, false; }
            year_val = parsed_year;

            let parsed_hour, ok_hour = parse_int(rest[12..14]);
            let parsed_min, ok_min = parse_int(rest[15..17]);
            let parsed_sec, ok_sec = parse_int(rest[18..20]);
            guard ok_hour && ok_min && ok_sec else { return Time { .. }, false; }
            hour_val = parsed_hour; min_val = parsed_min; sec_val = parsed_sec;
        }
    } else {
        // ANSI C asctime: "Sun Nov  6 08:49:37 1994"
        guard text.len >= 24 && text[3] == ' ' && text[7] == ' ' && text[10] == ' ' && text[13] == ':' && text[16] == ':' && text[19] == ' ' else {
            return Time { .. }, false;
        }
        let parsed_month = parse_month_name(text[4..7]);
        guard parsed_month > 0 else { return Time { .. }, false; }
        month_val = parsed_month;

        let day_part = trim(text[8..10]);
        let parsed_day, ok_day = parse_int(day_part);
        guard ok_day else { return Time { .. }, false; }
        day_val = parsed_day;

        let parsed_hour, ok_hour = parse_int(text[11..13]);
        let parsed_min, ok_min = parse_int(text[14..16]);
        let parsed_sec, ok_sec = parse_int(text[17..19]);
        let parsed_year, ok_year = parse_int(text[20..24]);
        guard ok_hour && ok_min && ok_sec && ok_year else { return Time { .. }, false; }
        hour_val = parsed_hour; min_val = parsed_min; sec_val = parsed_sec; year_val = parsed_year;
    }

    guard day_val >= 1 && day_val <= days_in_month(year_val, month_val) else { return Time { .. }, false; }
    guard hour_val <= 23 && min_val <= 59 && sec_val <= 59 else { return Time { .. }, false; }

    let days_count = civil_to_days(year_val, month_val, day_val);
    let total_secs = days_count * 86400 + hour_val * 3600 + min_val * 60 + sec_val;
    return unix(total_secs, 0), true;
}
