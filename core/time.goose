// Standard Date & Time library for Goose (candidate for std::time).
// Provides Duration arithmetic, monotonic Stopwatch & Deadline, Howard Hinnant's
// civil calendar math, RFC 3339 / ISO 8601 and RFC 9110 HTTP-Date codecs.
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

fn month_number(m: Month) -> i64 {
    return match m {
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

fn month_from_number(num: i64) -> Month {
    return match num {
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

fn month_name(m: Month) -> const u8[:] {
    return MONTH_NAMES[month_number(m) - 1];
}

fn month_short_name(m: Month) -> const u8[:] {
    return MONTH_SHORT_NAMES[month_number(m) - 1];
}

fn weekday_number(w: Weekday) -> i64 {
    return match w {
        Sunday => 0,
        Monday => 1,
        Tuesday => 2,
        Wednesday => 3,
        Thursday => 4,
        Friday => 5,
        Saturday => 6,
    };
}

fn weekday_from_number(num: i64) -> Weekday {
    return match num {
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

fn weekday_name(w: Weekday) -> const u8[:] {
    return WEEKDAY_NAMES[weekday_number(w)];
}

fn weekday_short_name(w: Weekday) -> const u8[:] {
    return WEEKDAY_SHORT_NAMES[weekday_number(w)];
}

// --- Duration: Nanosecond-precision Interval ---

struct Duration {
    nanos: i64 = 0,
}

// Constructors
fn nanos(n: i64) -> Duration { return Duration { nanos: n }; }
fn micros(us: i64) -> Duration { return Duration { nanos: us * MICROSECOND }; }
fn millis(ms: i64) -> Duration { return Duration { nanos: ms * MILLISECOND }; }
fn secs(s: i64) -> Duration { return Duration { nanos: s * SECOND }; }
fn mins(m: i64) -> Duration { return Duration { nanos: m * MINUTE }; }
fn hours(h: i64) -> Duration { return Duration { nanos: h * HOUR }; }
fn days(d: i64) -> Duration { return Duration { nanos: d * DAY }; }
fn weeks(w: i64) -> Duration { return Duration { nanos: w * WEEK }; }

// Long-name constructor aliases
fn nanoseconds(n: i64) -> Duration { return nanos(n); }
fn microseconds(us: i64) -> Duration { return micros(us); }
fn milliseconds(ms: i64) -> Duration { return millis(ms); }
fn seconds(s: i64) -> Duration { return secs(s); }
fn minutes(m: i64) -> Duration { return mins(m); }

// Accessors
fn as_nanos(d: Duration) -> i64 { return d.nanos; }
fn as_micros(d: Duration) -> i64 { return d.nanos / MICROSECOND; }
fn as_millis(d: Duration) -> i64 { return d.nanos / MILLISECOND; }
fn as_secs(d: Duration) -> i64 { return d.nanos / SECOND; }
fn as_mins(d: Duration) -> i64 { return d.nanos / MINUTE; }
fn as_hours(d: Duration) -> i64 { return d.nanos / HOUR; }
fn as_days(d: Duration) -> i64 { return d.nanos / DAY; }
fn as_secs_f64(d: Duration) -> f64 { return d.nanos / 1000000000.0; }
fn as_mins_f64(d: Duration) -> f64 { return d.nanos / (MINUTE as f64); }
fn as_hours_f64(d: Duration) -> f64 { return d.nanos / (HOUR as f64); }

// Method-syntax aliases
fn nanoseconds(d: Duration) -> i64 { return as_nanos(d); }
fn microseconds(d: Duration) -> i64 { return as_micros(d); }
fn milliseconds(d: Duration) -> i64 { return as_millis(d); }
fn seconds(d: Duration) -> f64 { return as_secs_f64(d); }
fn minutes(d: Duration) -> f64 { return as_mins_f64(d); }
fn hours(d: Duration) -> f64 { return as_hours_f64(d); }

// Arithmetic
fn add(d1: Duration, d2: Duration) -> Duration { return Duration { nanos: d1.nanos + d2.nanos }; }
fn sub(d1: Duration, d2: Duration) -> Duration { return Duration { nanos: d1.nanos - d2.nanos }; }
fn mul(d: Duration, factor: i64) -> Duration { return Duration { nanos: d.nanos * factor }; }
fn div(d: Duration, factor: i64) -> Duration { return Duration { nanos: d.nanos / factor }; }
fn abs(d: Duration) -> Duration { return Duration { nanos: if d.nanos < 0 { -d.nanos } else { d.nanos } }; }

fn is_zero(d: Duration) -> bool { return d.nanos == 0; }
fn is_negative(d: Duration) -> bool { return d.nanos < 0; }
fn is_positive(d: Duration) -> bool { return d.nanos > 0; }

fn truncate(d: Duration, m: Duration) -> Duration {
    if m.nanos <= 0 { return d; }
    return Duration { nanos: d.nanos - (d.nanos % m.nanos) };
}

fn round(d: Duration, m: Duration) -> Duration {
    if m.nanos <= 0 { return d; }
    let is_neg = d.nanos < 0;
    let abs_ns = if is_neg { -d.nanos } else { d.nanos };
    let r = abs_ns % m.nanos;
    var base = abs_ns - r;
    if (r * 2) >= m.nanos {
        base += m.nanos;
    }
    return Duration { nanos: if is_neg { -base } else { base } };
}

fn append_trimmed_fraction<B>(out: B&, frac_in: i64, num_digits: i64) {
    if frac_in <= 0 { return; }
    var digits: u8[9] = [0; 9];
    var val = frac_in;
    for i in num_digits {
        let idx = num_digits - 1 - i;
        digits[idx] = ('0' as i64 + (val % 10)) as u8;
        val /= 10;
    }
    var last = num_digits - 1;
    while last >= 0 && digits[last] == '0' {
        last--;
    }
    if last >= 0 {
        out.push('.');
        for i in (last + 1) {
            out.push(digits[i]);
        }
    }
}

// Formats duration in standard compact style ("250ms", "1.5s", "2h45m")
fn format<B>(out: B&, d: Duration) {
    if d.nanos == 0 {
        out.append("0s");
        return;
    }
    var total_ns = d.nanos;
    if total_ns < 0 {
        out.push('-');
        total_ns = -total_ns;
    }

    if total_ns < MICROSECOND {
        format(out, total_ns);
        out.append("ns");
        return;
    }

    if total_ns < MILLISECOND {
        let us = total_ns / MICROSECOND;
        let frac = total_ns % MICROSECOND;
        format(out, us);
        append_trimmed_fraction(out, frac, 3);
        out.append("µs");
        return;
    }

    if total_ns < SECOND {
        let ms = total_ns / MILLISECOND;
        let frac = (total_ns % MILLISECOND) / 1000;
        format(out, ms);
        append_trimmed_fraction(out, frac, 3);
        out.append("ms");
        return;
    }

    let total_sec = total_ns / SECOND;
    let rem_ns = total_ns % SECOND;

    let h = total_sec / 3600;
    let m = (total_sec % 3600) / 60;
    let s = total_sec % 60;

    if h > 0 {
        format(out, h);
        out.push('h');
    }
    if m > 0 {
        format(out, m);
        out.push('m');
    }
    if s > 0 || rem_ns > 0 || (h == 0 && m == 0) {
        format(out, s);
        append_trimmed_fraction(out, rem_ns, 9);
        out.push('s');
    }
}

// Parses duration string like "300ms", "-1.5h", "2h45m", "10s", "100ns"
fn parse_duration(raw: const u8[:]) -> Duration, bool {
    let s = trim(raw);
    guard s.len > 0 else { return Duration { 0 }, false; }

    var is_neg = false;
    var at = 0;
    if s[0] == '-' {
        is_neg = true;
        at = 1;
    } else if s[0] == '+' {
        at = 1;
    }

    var total_nanos: i64 = 0;

    while at < s.len {
        var num_start = at;
        while at < s.len && ((s[at] >= '0' && s[at] <= '9') || s[at] == '.') {
            at++;
        }
        let num_str = s[num_start..at];
        guard num_str.len > 0 else { return Duration { 0 }, false; }

        var unit_start = at;
        while at < s.len && !((s[at] >= '0' && s[at] <= '9') || s[at] == '+' || s[at] == '-') {
            at++;
        }
        let unit_str = s[unit_start..at];
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

        var dot_idx = -1;
        for i in num_str.len {
            if num_str[i] == '.' { dot_idx = i; break; }
        }

        if dot_idx < 0 {
            let int_val, int_ok = parse_int(num_str);
            guard int_ok else { return Duration { 0 }, false; }
            total_nanos += int_val * unit_mult;
        } else {
            let whole_str = num_str[..dot_idx];
            let frac_str = num_str[dot_idx + 1..];

            var whole_val: i64 = 0;
            if whole_str.len > 0 {
                let v, ok = parse_int(whole_str);
                guard ok else { return Duration { 0 }, false; }
                whole_val = v;
            }

            total_nanos += whole_val * unit_mult;

            if frac_str.len > 0 {
                var frac_val: i64 = 0;
                var div_scale: i64 = 1;
                for i in frac_str.len {
                    if i >= 9 { break; }
                    let c = frac_str[i];
                    if c >= '0' && c <= '9' {
                        frac_val = frac_val * 10 + (c - '0');
                        div_scale *= 10;
                    }
                }
                total_nanos += (frac_val * unit_mult) / div_scale;
            }
        }
    }

    if is_neg { total_nanos = -total_nanos; }
    return Duration { nanos: total_nanos }, true;
}

// --- Monotonic Benchmarking & Concurrency Primitives ---

struct Stopwatch {
    start_ns: i64 = 0,
}

fn stopwatch() -> Stopwatch {
    return Stopwatch { start_ns: clock_ns() };
}

fn elapsed(sw: const Stopwatch&) -> Duration {
    return Duration { nanos: clock_ns() - sw.start_ns };
}

fn restart(sw: Stopwatch&) -> Duration {
    let now_ns = clock_ns();
    let d = Duration { nanos: now_ns - sw.start_ns };
    sw.start_ns = now_ns;
    return d;
}

struct Deadline {
    target_mono_ns: i64 = 0,
    has_deadline: bool = false,
}

fn deadline_after(d: Duration) -> Deadline {
    if d.nanos <= 0 {
        return Deadline { target_mono_ns: clock_ns(), has_deadline: true };
    }
    return Deadline { target_mono_ns: clock_ns() + d.nanos, has_deadline: true };
}

fn is_expired(dl: const Deadline&) -> bool {
    if !dl.has_deadline { return false; }
    return clock_ns() >= dl.target_mono_ns;
}

fn remaining(dl: const Deadline&) -> Duration {
    if !dl.has_deadline { return Duration { nanos: 9223372036854775807 }; }
    let diff = dl.target_mono_ns - clock_ns();
    return Duration { nanos: if diff > 0 { diff } else { 0 } };
}

fn sleep(d: Duration) {
    if d.nanos <= 0 { return; }
    let ms = d.nanos / MILLISECOND;
    if ms > 0 {
        sleep_ms(ms);
    }
}

// --- Howard Hinnant Civil Calendar Algorithm (O(1), zero-alloc) ---

fn days_to_civil(z_in: i64) -> i64, i64, i64 {
    var z = z_in + 719468;
    let era = (if z >= 0 { z } else { z - 146096 }) / 146097;
    let doe = z - era * 146097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    var y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    if m <= 2 { y += 1; }
    return y, m, d;
}

fn civil_to_days(year_in: i64, month_in: i64, day_in: i64) -> i64 {
    var y = year_in;
    let m = month_in;
    let d = day_in;
    if m <= 2 { y -= 1; }
    let era = (if y >= 0 { y } else { y - 399 }) / 400;
    let yoe = y - era * 400;
    let doy = (153 * (if m > 2 { m - 3 } else { m + 9 }) + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    return era * 146097 + doe - 719468;
}

fn is_leap_year(y: i64) -> bool {
    return (y % 4 == 0 && y % 100 != 0) || (y % 400 == 0);
}

fn days_in_month(y: i64, m: i64) -> i64 {
    match m {
        1, 3, 5, 7, 8, 10, 12 => 31,
        4, 6, 9, 11 => 30,
        2 => if is_leap_year(y) { 29 } else { 28 },
        _ => 0,
    }
}

// --- Time: Point in Time (Wall-Clock Instant + Civil Projection) ---

struct Time {
    wall_sec: i64 = 0,    // seconds since Unix epoch 1970-01-01 00:00:00 UTC
    nsec: i32 = 0,        // nanoseconds [0, 999999999]
    tz_offset: i32 = 0,   // seconds east of UTC (0 = UTC)
}

fn now() -> Time {
    let w_ns = time_ns();
    let sec = w_ns / 1000000000;
    let nsec = (w_ns % 1000000000) as i32;
    return Time {
        wall_sec: sec,
        nsec: nsec,
        tz_offset: 0,
    };
}

fn unix(sec: i64, nano: i64 = 0) -> Time {
    var s = sec + nano / 1000000000;
    var n = (nano % 1000000000) as i32;
    if n < 0 {
        s -= 1;
        n += 1000000000;
    }
    return Time {
        wall_sec: s,
        nsec: n,
        tz_offset: 0,
    };
}

fn unix_milli(ms: i64) -> Time {
    return unix(ms / 1000, (ms % 1000) * 1000000);
}

fn unix_micro(us: i64) -> Time {
    return unix(us / 1000000, (us % 1000000) * 1000);
}

fn unix_nano(ns: i64) -> Time {
    return unix(ns / 1000000000, ns % 1000000000);
}

fn date(year: i64, month: Month, day: i64, hour: i64 = 0, min_val: i64 = 0, sec: i64 = 0, nsec: i64 = 0, tz_offset: i32 = 0) -> Time {
    let days = civil_to_days(year, month_number(month), day);
    let total_sec = days * 86400 + hour * 3600 + min_val * 60 + sec - tz_offset;
    var t = unix(total_sec, nsec);
    t.tz_offset = tz_offset;
    return t;
}

fn date(year: i64, month: i64, day: i64, hour: i64 = 0, min_val: i64 = 0, sec: i64 = 0, nsec: i64 = 0, tz_offset: i32 = 0) -> Time {
    return date(year, month_from_number(month), day, hour, min_val, sec, nsec, tz_offset);
}

// Civil decomposition
fn civil_parts(t: Time) -> i64, i64, i64, i64, i64, i64 {
    let local_sec = t.wall_sec + t.tz_offset;
    var days = local_sec / 86400;
    var rem_sec = local_sec % 86400;
    if rem_sec < 0 {
        rem_sec += 86400;
        days -= 1;
    }

    let y, m, d = days_to_civil(days);
    let h = rem_sec / 3600;
    let min_val = (rem_sec % 3600) / 60;
    let s = rem_sec % 60;
    return y, m, d, h, min_val, s;
}

fn year(t: Time) -> i64 { let y, _, _, _, _, _ = civil_parts(t); return y; }
fn month(t: Time) -> Month { let _, m, _, _, _, _ = civil_parts(t); return month_from_number(m); }
fn month_number(t: Time) -> i64 { let _, m, _, _, _, _ = civil_parts(t); return m; }
fn day(t: Time) -> i64 { let _, _, d, _, _, _ = civil_parts(t); return d; }
fn weekday(t: Time) -> Weekday {
    let local_sec = t.wall_sec + t.tz_offset;
    var days = local_sec / 86400;
    if local_sec < 0 && (local_sec % 86400 != 0) {
        days -= 1;
    }
    var wd = (days + 4) % 7;
    if wd < 0 { wd += 7; }
    return weekday_from_number(wd);
}

fn clock(t: Time) -> i64, i64, i64 {
    let _, _, _, h, min_val, s = civil_parts(t);
    return h, min_val, s;
}

fn hour(t: Time) -> i64 { let _, _, _, h, _, _ = civil_parts(t); return h; }
fn minute(t: Time) -> i64 { let _, _, _, _, min_val, _ = civil_parts(t); return min_val; }
fn second(t: Time) -> i64 { let _, _, _, _, _, s = civil_parts(t); return s; }
fn nanosecond(t: Time) -> i64 { return t.nsec; }

fn unix(t: Time) -> i64 { return t.wall_sec; }
fn unix_milli(t: Time) -> i64 { return t.wall_sec * 1000 + t.nsec / 1000000; }
fn unix_micro(t: Time) -> i64 { return t.wall_sec * 1000000 + t.nsec / 1000; }
fn unix_nano(t: Time) -> i64 { return t.wall_sec * 1000000000 + t.nsec; }
fn is_zero(t: Time) -> bool { return t.wall_sec == 0 && t.nsec == 0; }

// --- Time Arithmetic ---

fn add(t: Time, d: Duration) -> Time {
    var s = t.wall_sec + d.nanos / 1000000000;
    var n = t.nsec + (d.nanos % 1000000000);
    if n >= 1000000000 {
        s += 1;
        n -= 1000000000;
    } else if n < 0 {
        s -= 1;
        n += 1000000000;
    }
    return Time {
        wall_sec: s,
        nsec: n as i32,
        tz_offset: t.tz_offset,
    };
}

fn sub(t: Time, u: Time) -> Duration {
    let sec_diff = t.wall_sec - u.wall_sec;
    let nsec_diff = (t.nsec as i64) - u.nsec;
    return Duration { nanos: sec_diff * 1000000000 + nsec_diff };
}

fn sub(t: Time, d: Duration) -> Time {
    return add(t, Duration { nanos: -d.nanos });
}

fn sub_duration(t: Time, d: Duration) -> Time {
    return sub(t, d);
}

// Correct month & year calendar arithmetic with end-of-month clamping (e.g. Jan 31 + 1 month = Feb 28/29)
fn add_months_clamped(t: Time, months: i64) -> Time {
    let y, m, d, h, min_val, s = civil_parts(t);
    var new_y = y;
    var new_m = m + months;
    while new_m > 12 { new_m -= 12; new_y += 1; }
    while new_m < 1 { new_m += 12; new_y -= 1; }

    let max_day = days_in_month(new_y, new_m);
    let clamped_day = if d > max_day { max_day } else { d };
    let base_days = civil_to_days(new_y, new_m, clamped_day);
    let total_sec = base_days * 86400 + h * 3600 + min_val * 60 + s - t.tz_offset;
    return Time {
        wall_sec: total_sec,
        nsec: t.nsec,
        tz_offset: t.tz_offset,
    };
}

fn add_years_clamped(t: Time, years: i64) -> Time {
    return add_months_clamped(t, years * 12);
}

fn days_in_month(t: Time) -> i64 {
    let y, m, _, _, _, _ = civil_parts(t);
    return days_in_month(y, m);
}

fn days_in_year(t: Time) -> i64 {
    return if is_leap_year(t.year()) { 366 } else { 365 };
}

fn is_leap_year(t: Time) -> bool {
    return is_leap_year(t.year());
}

fn since(t: Time) -> Duration {
    return now().sub(t);
}

fn until(t: Time) -> Duration {
    return t.sub(now());
}

// Comparisons
fn compare(t: Time, u: Time) -> i64 {
    if t.wall_sec != u.wall_sec {
        return if t.wall_sec < u.wall_sec { -1 } else { 1 };
    }
    if t.nsec != u.nsec {
        return if t.nsec < u.nsec { -1 } else { 1 };
    }
    return 0;
}

fn equal(t: Time, u: Time) -> bool {
    return t.wall_sec == u.wall_sec && t.nsec == u.nsec;
}

fn before(t: Time, u: Time) -> bool {
    return compare(t, u) < 0;
}

fn after(t: Time, u: Time) -> bool {
    return compare(t, u) > 0;
}

fn truncate(t: Time, d: Duration) -> Time {
    if d.nanos <= 0 { return t; }
    let total_ns = t.wall_sec * 1000000000 + t.nsec;
    let rem = total_ns % d.nanos;
    let base_ns = total_ns - rem;
    var res = unix(base_ns / 1000000000, base_ns % 1000000000);
    res.tz_offset = t.tz_offset;
    return res;
}

fn round(t: Time, d: Duration) -> Time {
    if d.nanos <= 0 { return t; }
    let total_ns = t.wall_sec * 1000000000 + t.nsec;
    let r = total_ns % d.nanos;
    var base_ns = total_ns - r;
    if (r * 2) >= d.nanos {
        base_ns += d.nanos;
    }
    var res = unix(base_ns / 1000000000, base_ns % 1000000000);
    res.tz_offset = t.tz_offset;
    return res;
}

// Timezone adjustments
fn in_offset(t: Time, tz_offset_seconds: i32) -> Time {
    var res = t;
    res.tz_offset = tz_offset_seconds;
    return res;
}

fn in_tz(t: Time, hours: i64, minutes: i64 = 0) -> Time {
    let sign = if hours < 0 { -1 } else { 1 };
    let abs_h = if hours < 0 { -hours } else { hours };
    let total_sec = sign * (abs_h * 3600 + minutes * 60);
    return in_offset(t, total_sec as i32);
}

fn utc(t: Time) -> Time {
    var res = t;
    res.tz_offset = 0;
    return res;
}

fn tz_offset(t: Time) -> i32 {
    return t.tz_offset;
}

// Calendar Boundaries
fn start_of_day(t: Time) -> Time {
    let y, m, d, _, _, _ = civil_parts(t);
    return date(y, month_from_number(m), d, 0, 0, 0, 0, t.tz_offset);
}

fn end_of_day(t: Time) -> Time {
    let y, m, d, _, _, _ = civil_parts(t);
    return date(y, month_from_number(m), d, 23, 59, 59, 999999999, t.tz_offset);
}

fn start_of_month(t: Time) -> Time {
    let y, m, _, _, _, _ = civil_parts(t);
    return date(y, month_from_number(m), 1, 0, 0, 0, 0, t.tz_offset);
}

fn end_of_month(t: Time) -> Time {
    let y, m, _, _, _, _ = civil_parts(t);
    let last_day = days_in_month(y, m);
    return date(y, month_from_number(m), last_day, 23, 59, 59, 999999999, t.tz_offset);
}

fn start_of_year(t: Time) -> Time {
    let y, _, _, _, _, _ = civil_parts(t);
    return date(y, Month.January, 1, 0, 0, 0, 0, t.tz_offset);
}

fn end_of_year(t: Time) -> Time {
    let y, _, _, _, _, _ = civil_parts(t);
    return date(y, Month.December, 31, 23, 59, 59, 999999999, t.tz_offset);
}

// --- High-Speed Formatter Helpers ---

inline fn append_2d<B>(out: B&, v: i64) {
    let val = if v < 0 { 0 } else if v > 99 { 99 } else { v };
    out.push(('0' as i64 + val / 10) as u8);
    out.push(('0' as i64 + val % 10) as u8);
}

inline fn append_4d<B>(out: B&, v: i64) {
    let val = if v < 0 { 0 } else if v > 9999 { 9999 } else { v };
    out.push(('0' as i64 + (val / 1000) % 10) as u8);
    out.push(('0' as i64 + (val / 100) % 10) as u8);
    out.push(('0' as i64 + (val / 10) % 10) as u8);
    out.push(('0' as i64 + val % 10) as u8);
}

// RFC 3339 / ISO 8601 Formatter ("2006-01-02T15:04:05Z" or "2006-01-02T15:04:05+03:00")
fn format_rfc3339<B>(out: B&, t: Time) {
    let y, m, d, h, min_val, s = civil_parts(t);
    append_4d(out, y);
    out.push('-');
    append_2d(out, m);
    out.push('-');
    append_2d(out, d);
    out.push('T');
    append_2d(out, h);
    out.push(':');
    append_2d(out, min_val);
    out.push(':');
    append_2d(out, s);

    if t.tz_offset == 0 {
        out.push('Z');
    } else {
        var off = t.tz_offset;
        if off < 0 {
            out.push('-');
            off = -off;
        } else {
            out.push('+');
        }
        let off_h = (off / 3600) as i64;
        let off_m = ((off % 3600) / 60) as i64;
        append_2d(out, off_h);
        out.push(':');
        append_2d(out, off_m);
    }
}

fn format_rfc3339_nano<B>(out: B&, t: Time) {
    let y, m, d, h, min_val, s = civil_parts(t);
    append_4d(out, y);
    out.push('-');
    append_2d(out, m);
    out.push('-');
    append_2d(out, d);
    out.push('T');
    append_2d(out, h);
    out.push(':');
    append_2d(out, min_val);
    out.push(':');
    append_2d(out, s);
    append_trimmed_fraction(out, t.nsec as i64, 9);

    if t.tz_offset == 0 {
        out.push('Z');
    } else {
        var off = t.tz_offset;
        if off < 0 {
            out.push('-');
            off = -off;
        } else {
            out.push('+');
        }
        let off_h = (off / 3600) as i64;
        let off_m = ((off % 3600) / 60) as i64;
        append_2d(out, off_h);
        out.push(':');
        append_2d(out, off_m);
    }
}

// Default Time format is RFC 3339
fn format<B>(out: B&, t: Time) {
    format_rfc3339(out, t);
}

fn format<B>(out: B&, m: Month) {
    out.append(month_name(m));
}

fn format<B>(out: B&, w: Weekday) {
    out.append(weekday_name(w));
}

// Parses RFC 3339 / ISO 8601 strings into Time
fn parse_rfc3339(raw: const u8[:]) -> Time, bool {
    let s = trim(raw);
    guard s.len >= 19 else { return Time { .. }, false; }

    guard s[4] == '-' && s[7] == '-' && (s[10] == 'T' || s[10] == 't' || s[10] == ' ') && s[13] == ':' && s[16] == ':' else {
        return Time { .. }, false;
    }

    let y_val, y_ok = parse_int(s[..4]);
    let m_val, m_ok = parse_int(s[5..7]);
    let d_val, d_ok = parse_int(s[8..10]);
    let h_val, h_ok = parse_int(s[11..13]);
    let min_val, min_ok = parse_int(s[14..16]);
    let s_val, s_ok = parse_int(s[17..19]);

    guard y_ok && m_ok && d_ok && h_ok && min_ok && s_ok else { return Time { .. }, false; }
    guard m_val >= 1 && m_val <= 12 && d_val >= 1 && d_val <= 31 else { return Time { .. }, false; }
    guard h_val >= 0 && h_val <= 23 && min_val >= 0 && min_val <= 59 && s_val >= 0 && s_val <= 60 else { return Time { .. }, false; }

    var at = 19;
    var nsec: i64 = 0;

    if at < s.len && (s[at] == '.' || s[at] == ',') {
        at++;
        var scale: i64 = 100000000;
        while at < s.len && (s[at] >= '0' && s[at] <= '9') {
            if scale > 0 {
                nsec += (s[at] - '0') * scale;
                scale /= 10;
            }
            at++;
        }
    }

    var tz_offset_val: i32 = 0;
    if at < s.len {
        let tz_char = s[at];
        if tz_char == 'Z' || tz_char == 'z' {
            tz_offset_val = 0;
        } else if tz_char == '+' || tz_char == '-' {
            let sign = if tz_char == '-' { -1 } else { 1 };
            at++;
            if at + 2 <= s.len {
                let off_h, h_tz_ok = parse_int(s[at..at + 2]);
                at += 2;
                if at < s.len && s[at] == ':' { at++; }
                var off_m: i64 = 0;
                if at + 2 <= s.len {
                    let m_tz, m_tz_ok = parse_int(s[at..at + 2]);
                    if m_tz_ok { off_m = m_tz; }
                }
                if h_tz_ok {
                    tz_offset_val = ((sign * (off_h * 3600 + off_m * 60)) as i32);
                }
            }
        }
    }

    let days = civil_to_days(y_val, m_val, d_val);
    let total_sec = days * 86400 + h_val * 3600 + min_val * 60 + s_val - tz_offset_val;

    return Time {
        wall_sec: total_sec,
        nsec: nsec as i32,
        tz_offset: tz_offset_val,
    }, true;
}

// RFC 1123 / HTTP-Date Formatter ("Mon, 02 Jan 2006 15:04:05 GMT")
fn format_http<B>(out: B&, t: Time) {
    let utc_t = t.utc();
    let y, m, d, h, min_val, s = civil_parts(utc_t);
    let wd = utc_t.weekday();

    out.append(weekday_short_name(wd));
    out.append(", ");
    append_2d(out, d);
    out.push(' ');
    out.append(month_short_name(month_from_number(m)));
    out.push(' ');
    append_4d(out, y);
    out.push(' ');
    append_2d(out, h);
    out.push(':');
    append_2d(out, min_val);
    out.push(':');
    append_2d(out, s);
    out.append(" GMT");
}

fn parse_month_name(tok: const u8[:]) -> i64 {
    guard tok.len >= 3 else { return 0; }
    var buf: u8[3] = [0; 3];
    for i in 3 {
        let c = tok[i];
        buf[i] = if c >= 'A' && c <= 'Z' { c + 32 } else { c };
    }
    let m = buf[..];
    if m == "jan" { return 1; }
    if m == "feb" { return 2; }
    if m == "mar" { return 3; }
    if m == "apr" { return 4; }
    if m == "may" { return 5; }
    if m == "jun" { return 6; }
    if m == "jul" { return 7; }
    if m == "aug" { return 8; }
    if m == "sep" { return 9; }
    if m == "oct" { return 10; }
    if m == "nov" { return 11; }
    if m == "dec" { return 12; }
    return 0;
}

// Parses RFC 9110 §5.6.7 HTTP-Date (IMF-fixdate, RFC 850, asctime) into Time
fn parse_http_date(raw: const u8[:]) -> Time, bool {
    let s = trim(raw);
    guard s.len >= 24 else { return Time { .. }, false; }

    var day: i64 = 0;
    var month: i64 = 0;
    var year: i64 = 0;
    var hour: i64 = 0;
    var minute: i64 = 0;
    var second: i64 = 0;

    var comma_idx = -1;
    for i in s.len {
        if s[i] == ',' { comma_idx = i; break; }
    }

    if comma_idx > 0 {
        var rest = trim(s[comma_idx + 1..]);
        var dash1 = -1;
        for i in rest.len {
            if rest[i] == '-' { dash1 = i; break; }
        }

        if dash1 > 0 {
            // RFC 850: "06-Nov-94 08:49:37 GMT"
            let d_val, d_ok = parse_int(rest[..dash1]);
            guard d_ok else { return Time { .. }, false; }
            day = d_val;

            rest = rest[dash1 + 1..];
            var dash2 = -1;
            for i in rest.len {
                if rest[i] == '-' { dash2 = i; break; }
            }
            guard dash2 > 0 else { return Time { .. }, false; }
            let m_val = parse_month_name(rest[..dash2]);
            guard m_val > 0 else { return Time { .. }, false; }
            month = m_val;

            rest = rest[dash2 + 1..];
            guard rest.len >= 11 && rest[2] == ' ' && rest[5] == ':' && rest[8] == ':' else {
                return Time { .. }, false;
            }
            let y_val, y_ok = parse_int(rest[..2]);
            guard y_ok else { return Time { .. }, false; }
            year = if y_val >= 70 { 1900 + y_val } else { 2000 + y_val };

            let h_val, h_ok = parse_int(rest[3..5]);
            let min_val, min_ok = parse_int(rest[6..8]);
            let s_val, s_ok = parse_int(rest[9..11]);
            guard h_ok && min_ok && s_ok else { return Time { .. }, false; }
            hour = h_val; minute = min_val; second = s_val;
        } else {
            // IMF-fixdate: "06 Nov 1994 08:49:37 GMT"
            guard rest.len >= 20 && rest[2] == ' ' && rest[6] == ' ' && rest[11] == ' ' && rest[14] == ':' && rest[17] == ':' else {
                return Time { .. }, false;
            }
            let d_val, d_ok = parse_int(rest[..2]);
            guard d_ok else { return Time { .. }, false; }
            day = d_val;

            let m_val = parse_month_name(rest[3..6]);
            guard m_val > 0 else { return Time { .. }, false; }
            month = m_val;

            let y_val, y_ok = parse_int(rest[7..11]);
            guard y_ok else { return Time { .. }, false; }
            year = y_val;

            let h_val, h_ok = parse_int(rest[12..14]);
            let min_val, min_ok = parse_int(rest[15..17]);
            let s_val, s_ok = parse_int(rest[18..20]);
            guard h_ok && min_ok && s_ok else { return Time { .. }, false; }
            hour = h_val; minute = min_val; second = s_val;
        }
    } else {
        // ANSI C asctime: "Sun Nov  6 08:49:37 1994"
        guard s.len >= 24 && s[3] == ' ' && s[7] == ' ' && s[10] == ' ' && s[13] == ':' && s[16] == ':' && s[19] == ' ' else {
            return Time { .. }, false;
        }
        let m_val = parse_month_name(s[4..7]);
        guard m_val > 0 else { return Time { .. }, false; }
        month = m_val;

        let dom_part = trim(s[8..10]);
        let d_val, d_ok = parse_int(dom_part);
        guard d_ok else { return Time { .. }, false; }
        day = d_val;

        let h_val, h_ok = parse_int(s[11..13]);
        let min_val, min_ok = parse_int(s[14..16]);
        let s_val, s_ok = parse_int(s[17..19]);
        let y_val, y_ok = parse_int(s[20..24]);
        guard h_ok && min_ok && s_ok && y_ok else { return Time { .. }, false; }
        hour = h_val; minute = min_val; second = s_val; year = y_val;
    }

    guard day >= 1 && day <= days_in_month(year, month) else { return Time { .. }, false; }
    guard hour <= 23 && minute <= 59 && second <= 59 else { return Time { .. }, false; }

    let days = civil_to_days(year, month, day);
    let total_sec = days * 86400 + hour * 3600 + minute * 60 + second;
    return unix(total_sec, 0), true;
}
