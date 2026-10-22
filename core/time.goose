// Comprehensive Go-inspired Time & Duration library for goose-wing.
// Provides Duration arithmetic, monotonic and wall-clock Time, Howard Hinnant's
// civil calendar math, RFC 3339 / RFC 1123 / ISO 8601 formatting, and Go layout engine.
namespace wing;

import std;
import os;

// --- Nanosecond Duration Constants (Go parity) ---

let NANOSECOND:  i64 = 1;
let MICROSECOND: i64 = 1000 * NANOSECOND;
let MILLISECOND: i64 = 1000 * MICROSECOND;
let SECOND:      i64 = 1000 * MILLISECOND;
let MINUTE:      i64 = 60 * SECOND;
let HOUR:        i64 = 60 * MINUTE;
let DAY:         i64 = 24 * HOUR;
let WEEK:        i64 = 7 * DAY;

// --- Standard Date & Time Layout Constants (Go layout reference) ---

let LAYOUT_RFC3339:      const u8[:] = "2006-01-02T15:04:05Z07:00";
let LAYOUT_RFC3339_NANO: const u8[:] = "2006-01-02T15:04:05.999999999Z07:00";
let LAYOUT_RFC1123:      const u8[:] = "Mon, 02 Jan 2006 15:04:05 MST";
let LAYOUT_RFC1123Z:     const u8[:] = "Mon, 02 Jan 2006 15:04:05 -0700";
let LAYOUT_RFC850:       const u8[:] = "Monday, 02-Jan-06 15:04:05 MST";
let LAYOUT_ANSIC:        const u8[:] = "Mon Jan _2 15:04:05 2006";
let LAYOUT_DATE_TIME:    const u8[:] = "2006-01-02 15:04:05";
let LAYOUT_DATE_ONLY:    const u8[:] = "2006-01-02";
let LAYOUT_TIME_ONLY:    const u8[:] = "15:04:05";
let LAYOUT_ISO8601:      const u8[:] = "2006-01-02T15:04:05Z";

// --- Month and Weekday Enums ---

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

fn month_name(m: Month) -> const u8[:] {
    return match m {
        January => "January",
        February => "February",
        March => "March",
        April => "April",
        May => "May",
        June => "June",
        July => "July",
        August => "August",
        September => "September",
        October => "October",
        November => "November",
        December => "December",
    };
}

fn month_short_name(m: Month) -> const u8[:] {
    return match m {
        January => "Jan",
        February => "Feb",
        March => "Mar",
        April => "Apr",
        May => "May",
        June => "Jun",
        July => "Jul",
        August => "Aug",
        September => "Sep",
        October => "Oct",
        November => "Nov",
        December => "Dec",
    };
}

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

enum Weekday {
    Sunday,
    Monday,
    Tuesday,
    Wednesday,
    Thursday,
    Friday,
    Saturday,
}

fn weekday_name(w: Weekday) -> const u8[:] {
    return match w {
        Sunday => "Sunday",
        Monday => "Monday",
        Tuesday => "Tuesday",
        Wednesday => "Wednesday",
        Thursday => "Thursday",
        Friday => "Friday",
        Saturday => "Saturday",
    };
}

fn weekday_short_name(w: Weekday) -> const u8[:] {
    return match w {
        Sunday => "Sun",
        Monday => "Mon",
        Tuesday => "Tue",
        Wednesday => "Wed",
        Thursday => "Thu",
        Friday => "Fri",
        Saturday => "Sat",
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

// --- Duration: Nanosecond-precision Interval ---

struct Duration {
    nanos: i64 = 0,
}

// Factory constructors
fn duration_nanos(n: i64) -> Duration { return Duration { nanos: n }; }
fn duration_micros(us: i64) -> Duration { return Duration { nanos: us * MICROSECOND }; }
fn duration_millis(ms: i64) -> Duration { return Duration { nanos: ms * MILLISECOND }; }
fn duration_seconds(s: i64) -> Duration { return Duration { nanos: s * SECOND }; }
fn duration_minutes(m: i64) -> Duration { return Duration { nanos: m * MINUTE }; }
fn duration_hours(h: i64) -> Duration { return Duration { nanos: h * HOUR }; }
fn duration_days(d: i64) -> Duration { return Duration { nanos: d * DAY }; }
fn duration_weeks(w: i64) -> Duration { return Duration { nanos: w * WEEK }; }

fn nanoseconds(n: i64) -> Duration { return Duration { nanos: n }; }
fn microseconds(us: i64) -> Duration { return Duration { nanos: us * MICROSECOND }; }
fn milliseconds(ms: i64) -> Duration { return Duration { nanos: ms * MILLISECOND }; }
fn seconds(s: i64) -> Duration { return Duration { nanos: s * SECOND }; }
fn minutes(m: i64) -> Duration { return Duration { nanos: m * MINUTE }; }
fn hours(h: i64) -> Duration { return Duration { nanos: h * HOUR }; }
fn days(d: i64) -> Duration { return Duration { nanos: d * DAY }; }
fn weeks(w: i64) -> Duration { return Duration { nanos: w * WEEK }; }

// Accessors
fn as_nanos(d: Duration) -> i64 { return d.nanos; }
fn as_micros(d: Duration) -> i64 { return d.nanos / MICROSECOND; }
fn as_millis(d: Duration) -> i64 { return d.nanos / MILLISECOND; }
fn as_seconds(d: Duration) -> f64 { return d.nanos / 1000000000.0; }
fn as_minutes(d: Duration) -> f64 { return d.nanos / (MINUTE as f64); }
fn as_hours(d: Duration) -> f64 { return d.nanos / (HOUR as f64); }

fn nanoseconds(d: Duration) -> i64 { return d.nanos; }
fn microseconds(d: Duration) -> i64 { return d.nanos / MICROSECOND; }
fn milliseconds(d: Duration) -> i64 { return d.nanos / MILLISECOND; }
fn seconds(d: Duration) -> f64 { return d.nanos / 1000000000.0; }
fn minutes(d: Duration) -> f64 { return d.nanos / (MINUTE as f64); }
fn hours(d: Duration) -> f64 { return d.nanos / (HOUR as f64); }

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
    let r = d.nanos % m.nanos;
    let base = d.nanos - r;
    if (r * 2) >= m.nanos {
        return Duration { nanos: base + m.nanos };
    }
    return Duration { nanos: base };
}

// Formats duration in Go style ("250ms", "1.5s", "2h45m")
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
        let frac = (total_ns % MICROSECOND) / 100;
        format(out, us);
        if frac > 0 {
            out.push('.');
            out.push(('0' as i64 + frac) as u8);
        }
        out.append("µs");
        return;
    }

    if total_ns < SECOND {
        let ms = total_ns / MILLISECOND;
        let frac = (total_ns % MILLISECOND) / 100000;
        format(out, ms);
        if frac > 0 {
            out.push('.');
            out.push(('0' as i64 + frac) as u8);
        }
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
        let frac = rem_ns / 100000000; // tenths of a second
        if frac > 0 {
            out.push('.');
            out.push(('0' as i64 + frac) as u8);
        }
        out.push('s');
    }
}

// Parses duration string like Go time.ParseDuration ("300ms", "-1.5h", "2h45m", "10s", "100ns")
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
        // Read numeric part (integer + optional fraction)
        var num_start = at;
        while at < s.len && ((s[at] >= '0' && s[at] <= '9') || s[at] == '.') {
            at++;
        }
        let num_str = s[num_start..at];
        guard num_str.len > 0 else { return Duration { 0 }, false; }

        // Read unit part (letters)
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

        // Parse number
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
                    if i >= 9 { break; } // nanosecond limit
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

// --- Howard Hinnant Civil Calendar Algorithm (O(1), zero-alloc) ---

// Converts days since Unix epoch (1970-01-01) to civil date (year, month [1..12], day [1..31])
fn days_to_civil(z_in: i64) -> i64, i64, i64 {
    var z = z_in + 719468;
    let era = (if z >= 0 { z } else { z - 146096 }) / 146097;
    let doe = z - era * 146097; // [0, 146096]
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365; // [0, 399]
    var y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100); // [0, 365]
    let mp = (5 * doy + 2) / 153; // [0, 11]
    let d = doy - (153 * mp + 2) / 5 + 1; // [1, 31]
    let m = if mp < 10 { mp + 3 } else { mp - 9 }; // [1, 12]
    if m <= 2 { y += 1; }
    return y, m, d;
}

// Converts civil date (year, month [1..12], day [1..31]) to days since Unix epoch (1970-01-01)
fn civil_to_days(year_in: i64, month_in: i64, day_in: i64) -> i64 {
    var y = year_in;
    let m = month_in;
    let d = day_in;
    if m <= 2 { y -= 1; }
    let era = (if y >= 0 { y } else { y - 399 }) / 400;
    let yoe = y - era * 400; // [0, 399]
    let doy = (153 * (if m > 2 { m - 3 } else { m + 9 }) + 2) / 5 + d - 1; // [0, 365]
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy; // [0, 146096]
    return era * 146097 + doe - 719468;
}

// --- Time: Point in Time (Wall + Monotonic Clock) ---

struct Time {
    wall_sec: i64 = 0,    // seconds since Unix epoch 1970-01-01 00:00:00 UTC
    nsec: i32 = 0,        // nanoseconds [0, 999999999]
    mono_ns: i64 = 0,     // monotonic clock reading (clock_ns()) or 0 if wall-only
    tz_offset: i32 = 0,   // seconds east of UTC (0 = UTC)
}

// Constructors
fn now() -> Time {
    let w_ns = time_ns();
    let m_ns = clock_ns();
    let sec = w_ns / 1000000000;
    let nsec = (w_ns % 1000000000) as i32;
    return Time {
        wall_sec: sec,
        nsec: nsec,
        mono_ns: m_ns,
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
        mono_ns: 0,
        tz_offset: 0,
    };
}

fn unix_milli(ms: i64) -> Time {
    return unix(ms / 1000, (ms % 1000) * 1000000);
}

fn unix_micro(us: i64) -> Time {
    return unix(us / 1000000, (us % 1000000) * 1000);
}

fn date(year: i64, month: Month, day: i64, hour: i64 = 0, min_val: i64 = 0, sec: i64 = 0, nsec: i64 = 0, tz_offset: i32 = 0) -> Time {
    let days = civil_to_days(year, month_number(month), day);
    let total_sec = days * 86400 + hour * 3600 + min_val * 60 + sec - tz_offset;
    var t = unix(total_sec, nsec);
    t.tz_offset = tz_offset;
    return t;
}

fn utc(year: i64, month: Month, day: i64, hour: i64 = 0, min_val: i64 = 0, sec: i64 = 0, nsec: i64 = 0) -> Time {
    return date(year, month, day, hour, min_val, sec, nsec, 0);
}

// Calendar decomposition (civil date & time in active timezone)
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

// Calendar inspectors
fn year(t: Time) -> i64 {
    let y, _, _, _, _, _ = civil_parts(t);
    return y;
}

fn month(t: Time) -> Month {
    let _, m, _, _, _, _ = civil_parts(t);
    return month_from_number(m);
}

fn month_number(t: Time) -> i64 {
    let _, m, _, _, _, _ = civil_parts(t);
    return m;
}

fn day(t: Time) -> i64 {
    let _, _, d, _, _, _ = civil_parts(t);
    return d;
}

fn weekday(t: Time) -> Weekday {
    let local_sec = t.wall_sec + t.tz_offset;
    var days = local_sec / 86400;
    if local_sec < 0 && (local_sec % 86400 != 0) {
        days -= 1;
    }
    var wd = (days + 4) % 7; // 1970-01-01 was Thursday (4)
    if wd < 0 { wd += 7; }
    return weekday_from_number(wd);
}

fn year_day(t: Time) -> i64 {
    let y, m, d, _, _, _ = civil_parts(t);
    let start_of_year_days = civil_to_days(y, 1, 1);
    let current_days = civil_to_days(y, m, d);
    return current_days - start_of_year_days + 1;
}

fn clock(t: Time) -> i64, i64, i64 {
    let _, _, _, h, min_val, s = civil_parts(t);
    return h, min_val, s;
}

fn hour(t: Time) -> i64 {
    let _, _, _, h, _, _ = civil_parts(t);
    return h;
}

fn minute(t: Time) -> i64 {
    let _, _, _, _, min_val, _ = civil_parts(t);
    return min_val;
}

fn second(t: Time) -> i64 {
    let _, _, _, _, _, s = civil_parts(t);
    return s;
}

fn nanosecond(t: Time) -> i64 {
    return t.nsec;
}

// Epoch accessors
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
    let new_mono = if t.mono_ns != 0 { t.mono_ns + d.nanos } else { 0 };
    return Time {
        wall_sec: s,
        nsec: n as i32,
        mono_ns: new_mono,
        tz_offset: t.tz_offset,
    };
}

// Go-style t.Sub(u): uses monotonic clock reading if available on both!
fn sub(t: Time, u: Time) -> Duration {
    if t.mono_ns != 0 && u.mono_ns != 0 {
        return Duration { nanos: t.mono_ns - u.mono_ns };
    }
    let sec_diff = t.wall_sec - u.wall_sec;
    let nsec_diff = (t.nsec as i64) - u.nsec;
    return Duration { nanos: sec_diff * 1000000000 + nsec_diff };
}

fn add_date(t: Time, years: i64, months: i64, days: i64) -> Time {
    let y, m, d, h, min_val, s = civil_parts(t);
    var new_y = y + years;
    var new_m = m + months;
    while new_m > 12 { new_m -= 12; new_y += 1; }
    while new_m < 1 { new_m += 12; new_y -= 1; }

    let base_days = civil_to_days(new_y, new_m, d) + days;
    let total_sec = base_days * 86400 + h * 3600 + min_val * 60 + s - t.tz_offset;
    return Time {
        wall_sec: total_sec,
        nsec: t.nsec,
        mono_ns: 0,
        tz_offset: t.tz_offset,
    };
}

fn since(t: Time) -> Duration {
    return now().sub(t);
}

fn until(t: Time) -> Duration {
    return t.sub(now());
}

// Comparisons
fn equal(t: Time, u: Time) -> bool {
    return t.wall_sec == u.wall_sec && t.nsec == u.nsec;
}

fn before(t: Time, u: Time) -> bool {
    if t.wall_sec != u.wall_sec { return t.wall_sec < u.wall_sec; }
    return t.nsec < u.nsec;
}

fn after(t: Time, u: Time) -> bool {
    if t.wall_sec != u.wall_sec { return t.wall_sec > u.wall_sec; }
    return t.nsec > u.nsec;
}

// Timezone location adjustments
fn utc(t: Time) -> Time {
    var res = t;
    res.tz_offset = 0;
    return res;
}

fn in_location(t: Time, tz_offset_seconds: i32) -> Time {
    var res = t;
    res.tz_offset = tz_offset_seconds;
    return res;
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

fn format_date_time<B>(out: B&, t: Time) {
    let y, m, d, h, min_val, s = civil_parts(t);
    append_4d(out, y);
    out.push('-');
    append_2d(out, m);
    out.push('-');
    append_2d(out, d);
    out.push(' ');
    append_2d(out, h);
    out.push(':');
    append_2d(out, min_val);
    out.push(':');
    append_2d(out, s);
}

// --- Go-Style Layout Formatter ---
// Supports "2006-01-02 15:04:05", "Mon Jan _2 15:04:05 MST 2006", RFC3339, etc.
fn format_time<B>(out: B&, t: Time, layout: const u8[:]) {
    let y, m, d, h, min_val, s = civil_parts(t);
    let wd = t.weekday();
    let nsec = t.nsec as i64;

    var at = 0;
    while at < layout.len {
        let rest = layout[at..];

        // 1. Year (2006, 06)
        if starts_with(rest, "2006") {
            append_4d(out, y);
            at += 4;
            continue;
        }
        if starts_with(rest, "06") {
            append_2d(out, y % 100);
            at += 2;
            continue;
        }

        // 2. Month (January, Jan, 01)
        if starts_with(rest, "January") {
            out.append(month_name(month_from_number(m)));
            at += 7;
            continue;
        }
        if starts_with(rest, "Jan") {
            out.append(month_short_name(month_from_number(m)));
            at += 3;
            continue;
        }
        if starts_with(rest, "01") {
            append_2d(out, m);
            at += 2;
            continue;
        }

        // 3. Weekday (Monday, Mon)
        if starts_with(rest, "Monday") {
            out.append(weekday_name(wd));
            at += 6;
            continue;
        }
        if starts_with(rest, "Mon") {
            out.append(weekday_short_name(wd));
            at += 3;
            continue;
        }

        // 4. Day of Month (02, _2)
        if starts_with(rest, "02") {
            append_2d(out, d);
            at += 2;
            continue;
        }
        if starts_with(rest, "_2") {
            if d < 10 { out.push(' '); out.push(('0' + d) as u8); }
            else { append_2d(out, d); }
            at += 2;
            continue;
        }

        // 5. Hour (15, 03)
        if starts_with(rest, "15") {
            append_2d(out, h);
            at += 2;
            continue;
        }
        if starts_with(rest, "03") {
            let h12 = if h == 0 { 12 } else if h > 12 { h - 12 } else { h };
            append_2d(out, h12);
            at += 2;
            continue;
        }

        // 6. Minute (04)
        if starts_with(rest, "04") {
            append_2d(out, min_val);
            at += 2;
            continue;
        }

        // 7. Second (05)
        if starts_with(rest, "05") {
            append_2d(out, s);
            at += 2;
            continue;
        }

        // 8. AM/PM
        if starts_with(rest, "PM") {
            out.append(if h >= 12 { "PM" } else { "AM" });
            at += 2;
            continue;
        }
        if starts_with(rest, "pm") {
            out.append(if h >= 12 { "pm" } else { "am" });
            at += 2;
            continue;
        }

        // 9. Single-digit unpadded components (1=month, 2=day, 3=hour12, 4=minute, 5=second)
        if rest[0] == '1' && (rest.len == 1 || rest[1] < '0' || rest[1] > '9') {
            format(out, m);
            at += 1;
            continue;
        }
        if rest[0] == '2' && (rest.len == 1 || rest[1] < '0' || rest[1] > '9') {
            format(out, d);
            at += 1;
            continue;
        }
        if rest[0] == '3' && (rest.len == 1 || rest[1] < '0' || rest[1] > '9') {
            let h12 = if h == 0 { 12 } else if h > 12 { h - 12 } else { h };
            format(out, h12);
            at += 1;
            continue;
        }
        if rest[0] == '4' && (rest.len == 1 || rest[1] < '0' || rest[1] > '9') {
            format(out, min_val);
            at += 1;
            continue;
        }
        if rest[0] == '5' && (rest.len == 1 || rest[1] < '0' || rest[1] > '9') {
            format(out, s);
            at += 1;
            continue;
        }
        if starts_with(rest, "pm") {
            out.append(if h >= 12 { "pm" } else { "am" });
            at += 2;
            continue;
        }

        // 9. Subsecond (.000, .999, .000000, .000000000)
        if starts_with(rest, ".000000000") || starts_with(rest, ".999999999") {
            out.push('.');
            var frac = nsec;
            var scale: i64 = 100000000;
            for i in 9 {
                out.push(('0' as i64 + (frac / scale) % 10) as u8);
                scale /= 10;
            }
            at += 11;
            continue;
        }
        if starts_with(rest, ".000000") || starts_with(rest, ".999999") {
            out.push('.');
            let micros = nsec / 1000;
            var scale: i64 = 100000;
            for i in 6 {
                out.push(('0' as i64 + (micros / scale) % 10) as u8);
                scale /= 10;
            }
            at += 8;
            continue;
        }
        if starts_with(rest, ".000") || starts_with(rest, ".999") {
            out.push('.');
            let millis = nsec / 1000000;
            var scale: i64 = 100;
            for i in 3 {
                out.push(('0' as i64 + (millis / scale) % 10) as u8);
                scale /= 10;
            }
            at += 4;
            continue;
        }

        // 10. Timezone (Z07:00, -07:00, -0700, MST)
        if starts_with(rest, "Z07:00") {
            if t.tz_offset == 0 {
                out.push('Z');
            } else {
                var off = t.tz_offset;
                out.push(if off < 0 { '-' } else { '+' });
                if off < 0 { off = -off; }
                append_2d(out, (off / 3600) as i64);
                out.push(':');
                append_2d(out, ((off % 3600) / 60) as i64);
            }
            at += 6;
            continue;
        }
        if starts_with(rest, "-07:00") {
            var off = t.tz_offset;
            out.push(if off < 0 { '-' } else { '+' });
            if off < 0 { off = -off; }
            append_2d(out, (off / 3600) as i64);
            out.push(':');
            append_2d(out, ((off % 3600) / 60) as i64);
            at += 6;
            continue;
        }
        if starts_with(rest, "-0700") {
            var off = t.tz_offset;
            out.push(if off < 0 { '-' } else { '+' });
            if off < 0 { off = -off; }
            append_2d(out, (off / 3600) as i64);
            append_2d(out, ((off % 3600) / 60) as i64);
            at += 5;
            continue;
        }
        if starts_with(rest, "MST") {
            out.append(if t.tz_offset == 0 { "UTC" } else { "LCL" });
            at += 3;
            continue;
        }

        // Literal character
        out.push(layout[at]);
        at++;
    }
}

// Parses RFC 3339 / ISO 8601 strings into Time
fn parse_rfc3339(raw: const u8[:]) -> Time, bool {
    let s = trim(raw);
    guard s.len >= 19 else { return Time { .. }, false; }

    // Expect: YYYY-MM-DDTHH:MM:SS
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

    // Fractional seconds
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

    // Timezone
    var tz_offset: i32 = 0;
    if at < s.len {
        let tz_char = s[at];
        if tz_char == 'Z' || tz_char == 'z' {
            tz_offset = 0;
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
                    tz_offset = ((sign * (off_h * 3600 + off_m * 60)) as i32);
                }
            }
        }
    }

    let days = civil_to_days(y_val, m_val, d_val);
    let total_sec = days * 86400 + h_val * 3600 + min_val * 60 + s_val - tz_offset;

    return Time {
        wall_sec: total_sec,
        nsec: nsec as i32,
        mono_ns: 0,
        tz_offset: tz_offset,
    }, true;
}

// --- RFC 9110 §5.6.7 & RFC 6265 §5.1.1 HTTP-Date Parsing ---

fn is_date_delim(b: u8) -> bool {
    return b == 0x09 || (b >= 0x20 && b <= 0x2F) || (b >= 0x3B && b <= 0x40) ||
           (b >= 0x5B && b <= 0x60) || (b >= 0x7B && b <= 0x7E);
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

// Parses a cookie-date / HTTP-date string into UTC unix epoch seconds
fn parse_cookie_date(raw: const u8[:]) -> i64, bool {
    guard raw.len > 0 else { return 0, false; }

    var found_time = false;
    var found_dom = false;
    var found_month = false;
    var found_year = false;

    var hour: i64 = 0;
    var minute: i64 = 0;
    var second: i64 = 0;
    var day: i64 = 0;
    var month: i64 = 0;
    var year: i64 = 0;

    var at = 0;
    while at < raw.len {
        while at < raw.len && is_date_delim(raw[at]) { at++; }
        if at >= raw.len { break; }
        let tok_start = at;
        while at < raw.len && !is_date_delim(raw[at]) { at++; }
        let tok = raw[tok_start..at];

        // 1. Time (HH:MM:SS)
        if !found_time && tok.len >= 5 {
            var c1 = -1;
            var c2 = -1;
            for i in tok.len {
                if tok[i] == ':' {
                    if c1 < 0 { c1 = i; } else if c2 < 0 { c2 = i; break; }
                }
            }
            if c1 > 0 && c2 > c1 {
                let h_val, h_ok = parse_int(tok[..c1]);
                let m_val, m_ok = parse_int(tok[c1 + 1..c2]);
                let s_val, s_ok = parse_int(tok[c2 + 1..]);
                if h_ok && m_ok && s_ok {
                    hour = h_val;
                    minute = m_val;
                    second = s_val;
                    found_time = true;
                    continue;
                }
            }
        }

        // 2. Day of month (1-2 digits)
        if !found_dom {
            var all_digits = true;
            for b in tok {
                if b < '0' || b > '9' { all_digits = false; break; }
            }
            if all_digits && (tok.len == 1 || tok.len == 2) {
                let d_val, d_ok = parse_int(tok);
                if d_ok && d_val >= 1 && d_val <= 31 {
                    day = d_val;
                    found_dom = true;
                    continue;
                }
            }
        }

        // 3. Month (jan..dec)
        if !found_month {
            let m_val = parse_month_name(tok);
            if m_val > 0 {
                month = m_val;
                found_month = true;
                continue;
            }
        }

        // 4. Year (2-4 digits)
        if !found_year {
            var all_digits = true;
            for b in tok {
                if b < '0' || b > '9' { all_digits = false; break; }
            }
            if all_digits && (tok.len == 2 || tok.len == 4) {
                let y_val, y_ok = parse_int(tok);
                if y_ok {
                    year = y_val;
                    found_year = true;
                    continue;
                }
            }
        }
    }

    // 2-digit year normalization
    if year >= 70 && year <= 99 {
        year += 1900;
    } else if year >= 0 && year <= 69 {
        year += 2000;
    }

    // Validation
    guard found_time && found_dom && found_month && found_year else { return 0, false; }
    guard day >= 1 && day <= days_in_month(year, month) else { return 0, false; }
    guard year >= 1601 else { return 0, false; }
    guard hour <= 23 && minute <= 59 && second <= 59 else { return 0, false; }

    let days = civil_to_days(year, month, day);
    return days * 86400 + hour * 3600 + minute * 60 + second, true;
}

// Parses HTTP-Date (RFC 1123, RFC 850, asctime) into Time
fn parse_http_date(raw: const u8[:]) -> Time, bool {
    let unix_sec, ok = parse_cookie_date(raw);
    guard ok else { return Time { .. }, false; }
    return unix(unix_sec, 0), true;
}

// --- Stopwatch for High-Resolution Performance Benchmarking ---

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

// Delays execution for d duration
fn sleep(d: Duration) {
    if d.nanos <= 0 { return; }
    let ms = d.nanos / MILLISECOND;
    if ms > 0 {
        sleep_ms(ms);
    }
}
