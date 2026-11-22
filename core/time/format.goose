// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// RFC 3339 / ISO 8601 and RFC 9110 HTTP-Date codecs and formatters.
namespace core;

import std;
import core.math.arithmetic;
import core.bytes.case;
import core.bytes.trim;
import core.bytes.search;

// ---- codecs: RFC 3339 & RFC 9110 HTTP-Date (public API) --------------------

// Formats Time into an RFC 3339 / ISO 8601 string (e.g. "2026-10-22T23:18:18Z").
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

inline fn is_valid_rfc3339_clock(hour_val: i64, min_val: i64, sec_val: i64, offset_val: i32) -> bool {
    guard hour_val >= 0 && hour_val <= 23 && min_val >= 0 && min_val <= 59 else { return false; }
    if sec_val >= 0 && sec_val < 60 { return true; }
    guard sec_val == 60 else { return false; }
    let hm_secs = add_sat_i64(mul_sat_i64(hour_val, 3600), mul_sat_i64(min_val, 60));
    let utc_hm = sub_sat_i64(hm_secs, offset_val);
    return rem_euclid_i64(utc_hm, 86400) == 86340;
}

// Parses an RFC 3339 / ISO 8601 string into a Time.
//
// Example:
//   raw_str = "2026-10-30T16:00:00Z"
//   returns: Time { ... }, ok = true
fn parse_rfc3339(raw_str: const u8[:]) -> Time, bool {
    let text = raw_str;
    guard text.len >= 19 else { return Time { .. }, false; }

    let is_delim = text[4] == '-' && text[7] == '-' &&
                   (text[10] == 'T' || text[10] == 't' || text[10] == ' ') &&
                   text[13] == ':' && text[16] == ':';
    guard is_delim else { return Time { .. }, false; }

    let year_val, ok_year = parse_digits(text[..4]);
    let month_val, ok_month = parse_digits(text[5..7]);
    let day_val, ok_day = parse_digits(text[8..10]);
    let hour_val, ok_hour = parse_digits(text[11..13]);
    let min_val, ok_min = parse_digits(text[14..16]);
    let sec_val, ok_sec = parse_digits(text[17..19]);

    guard ok_year && ok_month && ok_day && ok_hour && ok_min && ok_sec else { return Time { .. }, false; }
    let valid_date = year_val >= 1 && month_val >= 1 && month_val <= 12 &&
        day_val >= 1 && day_val <= days_in_month(year_val, month_val);
    guard valid_date else { return Time { .. }, false; }

    let nsec_val, cursor, ok_frac = parse_fractional_nanos(text, 19);
    guard ok_frac && cursor < text.len else { return Time { .. }, false; }

    let offset_val, ok_offset = parse_timezone_offset(text[cursor..]);
    guard ok_offset && is_valid_rfc3339_clock(hour_val, min_val, sec_val, offset_val) else {
        return Time { .. }, false;
    }

    let days_count = civil_to_days(year_val, month_val, day_val);
    let hm_secs = add_sat_i64(mul_sat_i64(hour_val, 3600), mul_sat_i64(min_val, 60));
    let clock_secs = sub_sat_i64(add_sat_i64(hm_secs, sec_val), offset_val);
    let total_secs = add_sat_i64(mul_sat_i64(days_count, 86400), clock_secs);

    return Time {
        wall_sec:  total_secs,
        nsec:      nsec_val as i32,
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
//
// Example:
//   raw_str = "Sun, 06 Nov 1994 08:49:37 GMT"
//   returns: Time { ... }, ok = true
fn parse_http_date(raw_str: const u8[:]) -> Time, bool {
    let text = trim_lws(raw_str);
    guard text.len >= 24 else { return Time { .. }, false; }

    var comma_idx = -1;
    for scan_idx in text.len {
        if text[scan_idx] == ',' { comma_idx = scan_idx; break; }
    }

    if comma_idx > 0 {
        guard comma_idx + 1 < text.len && text[comma_idx + 1] == ' ' else { return Time { .. }, false; }
        let day_prefix = text[..comma_idx];
        let rest = text[comma_idx + 2..];
        var has_dash = false;
        for scan_idx in rest.len {
            if rest[scan_idx] == '-' { has_dash = true; break; }
        }
        if has_dash {
            let expected_wday = parse_weekday_name(day_prefix);
            guard expected_wday >= 0 else { return Time { .. }, false; }
            return parse_rfc850_date(rest, expected_wday);
        }
        let expected_wday = parse_weekday_short(day_prefix);
        guard expected_wday >= 0 else { return Time { .. }, false; }
        return parse_imf_fixdate(rest, expected_wday);
    }

    return parse_asctime_date(text);
}

// ---- internal implementation helpers ---------------------------------------
// Formatting helpers, unit multipliers, and sub-parsers.

inline fn append_2d<B>(out: B&, value: i64) {
    let clamped_val = min(max(0, value), 99);
    out.push(('0' as i64 + clamped_val / 10) as u8);
    out.push(('0' as i64 + clamped_val % 10) as u8);
}

inline fn append_4d<B>(out: B&, value: i64) {
    let clamped_val = min(max(0, value), 9999);
    out.push(('0' as i64 + (clamped_val / 1000) % 10) as u8);
    out.push(('0' as i64 + (clamped_val / 100) % 10) as u8);
    out.push(('0' as i64 + (clamped_val / 10) % 10) as u8);
    out.push(('0' as i64 + clamped_val % 10) as u8);
}

fn append_trimmed_fraction<B>(out: B&, fraction_val: i64, num_digits: i64) {
    guard fraction_val > 0 && num_digits >= 1 && num_digits <= 9 else { return; }
    var digits: u8[9] = [0; 9];
    var current_val = fraction_val as u64;
    let last_slot = sub_sat_i64(num_digits, 1);
    for digit_idx in num_digits {
        let array_idx = sub_sat_i64(last_slot, digit_idx);
        digits[array_idx] = ((current_val % 10) + ('0' as u64)) as u8;
        current_val /= 10;
    }
    var last_non_zero = last_slot;
    while last_non_zero >= 0 && digits[last_non_zero] == '0' {
        last_non_zero = sub_sat_i64(last_non_zero, 1);
    }
    if last_non_zero >= 0 {
        let emit_len = add_sat_i64(last_non_zero, 1);
        out.push('.');
        out.append(digits[..emit_len]);
    }
}

// Example:
//   str_val = "1234"
//   returns: 1234, ok = true
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

// Example:
//   str_val = "9223372036854775808", limit = 0x8000000000000000
//   returns: 9223372036854775808, ok = true
fn parse_digits_bounded_u64(str_val: const u8[:], limit: u64) -> u64, bool {
    guard str_val.len > 0 else { return 0, false; }
    var val: u64 = 0;
    for ch in str_val {
        guard ch >= '0' && ch <= '9' else { return 0, false; }
        let digit_val = sub_sat_u64(ch, 48);
        let max_val, _ = div_rem_u64(sub_sat_u64(limit, digit_val), 10);
        guard digit_val <= limit && val <= max_val else { return 0, false; }
        val = add_sat_u64(mul_sat_u64(val, 10), digit_val);
    }
    return val, true;
}

// Example:
//   token = "Sun"
//   returns: 0
fn parse_weekday_short(token: const u8[:]) -> i64 {
    guard token.len == 3 else { return -1; }
    if eq_ascii_fold(token, "sun") { return 0; }
    if eq_ascii_fold(token, "mon") { return 1; }
    if eq_ascii_fold(token, "tue") { return 2; }
    if eq_ascii_fold(token, "wed") { return 3; }
    if eq_ascii_fold(token, "thu") { return 4; }
    if eq_ascii_fold(token, "fri") { return 5; }
    if eq_ascii_fold(token, "sat") { return 6; }
    return -1;
}

// Example:
//   token = "Sunday"
//   returns: 0
fn parse_weekday_name(token: const u8[:]) -> i64 {
    guard token.len >= 6 && token.len <= 9 else { return -1; }
    if eq_ascii_fold(token, "sunday") { return 0; }
    if eq_ascii_fold(token, "monday") { return 1; }
    if eq_ascii_fold(token, "tuesday") { return 2; }
    if eq_ascii_fold(token, "wednesday") { return 3; }
    if eq_ascii_fold(token, "thursday") { return 4; }
    if eq_ascii_fold(token, "friday") { return 5; }
    if eq_ascii_fold(token, "saturday") { return 6; }
    return -1;
}

fn duration_unit_multiplier(unit_str: const u8[:]) -> i64, bool {
    if unit_str == "ns" { return NANOSECOND, true; }
    if unit_str == "us" || unit_str == "\xc2\xb5s" || unit_str == "\xce\xbcs" { return MICROSECOND, true; }
    if unit_str == "ms" { return MILLISECOND, true; }
    if unit_str == "s" { return SECOND, true; }
    if unit_str == "m" { return MINUTE, true; }
    if unit_str == "h" { return HOUR, true; }
    if unit_str == "d" { return DAY, true; }
    if unit_str == "w" { return WEEK, true; }
    return 0, false;
}

// Example:
//   fraction_str = "5", unit_mult = SECOND
//   returns: 500000000, ok = true
fn parse_scaled_fraction(fraction_str: const u8[:], unit_mult: i64) -> i64, bool {
    guard fraction_str.len > 0 else { return 0, true; }
    var fraction_nanos_9d: i64 = 0;
    var scale:             i64 = 100000000;
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

// Example:
//   num_str = "1.5", unit_mult = SECOND, max_mag = 0x7FFFFFFFFFFFFFFF
//   returns: 1500000000, ok = true
fn parse_duration_component(num_str: const u8[:], unit_mult: i64, max_mag: u64) -> u64, bool {
    guard unit_mult > 0 else { return 0, false; }
    let mult_u64 = unit_mult as u64;
    var dot_pos = -1;
    for scan_idx in num_str.len {
        if num_str[scan_idx] == '.' {
            if dot_pos >= 0 { return 0, false; }
            dot_pos = scan_idx;
        }
    }

    if dot_pos < 0 {
        let int_val, int_ok = parse_digits_bounded_u64(num_str, max_mag / mult_u64);
        guard int_ok else { return 0, false; }
        return int_val * mult_u64, true;
    }

    let whole_str = num_str[..dot_pos];
    let fraction_str = num_str[dot_pos + 1..];
    guard fraction_str.len > 0 else { return 0, false; }

    var whole_nanos: u64 = 0;
    if whole_str.len > 0 {
        let whole_val, ok_whole = parse_digits_bounded_u64(whole_str, max_mag / mult_u64);
        guard ok_whole else { return 0, false; }
        whole_nanos = whole_val * mult_u64;
    }

    let fraction_nanos_i64, ok_frac = parse_scaled_fraction(fraction_str, unit_mult);
    guard ok_frac else { return 0, false; }
    let fraction_nanos = fraction_nanos_i64 as u64;
    guard whole_nanos <= max_mag - fraction_nanos else { return 0, false; }
    return whole_nanos + fraction_nanos, true;
}

// Example:
//   text = ".500", start_pos = 0
//   returns: 500000000, cursor = 4, ok = true
fn parse_fractional_nanos(text: const u8[:], start_pos: i64) -> i64, i64, bool {
    var cursor = start_pos;
    if cursor >= text.len || (text[cursor] != '.' && text[cursor] != ',') {
        return 0, cursor, true;
    }
    cursor++;
    let digit_start = cursor;
    var nsec_val: i64 = 0;
    var scale:    i64 = 100000000;
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

// Example:
//   tz_text = "+02:00"
//   returns: 7200, ok = true
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

// Example:
//   token = "Jan"
//   returns: 1
fn parse_month_name(token: const u8[:]) -> i64 {
    guard token.len == 3 else { return 0; }
    if eq_ascii_fold(token, "jan") { return 1; }
    if eq_ascii_fold(token, "feb") { return 2; }
    if eq_ascii_fold(token, "mar") { return 3; }
    if eq_ascii_fold(token, "apr") { return 4; }
    if eq_ascii_fold(token, "may") { return 5; }
    if eq_ascii_fold(token, "jun") { return 6; }
    if eq_ascii_fold(token, "jul") { return 7; }
    if eq_ascii_fold(token, "aug") { return 8; }
    if eq_ascii_fold(token, "sep") { return 9; }
    if eq_ascii_fold(token, "oct") { return 10; }
    if eq_ascii_fold(token, "nov") { return 11; }
    if eq_ascii_fold(token, "dec") { return 12; }
    return 0;
}

fn make_validated_civil_time(
    year_val:      i64,
    month_val:     i64,
    day_val:       i64,
    hour_val:      i64,
    min_val:       i64,
    sec_val:       i64,
    expected_wday: i64,
) -> Time, bool {
    guard year_val >= 1 else { return Time { .. }, false; }
    guard month_val >= 1 && month_val <= 12 else { return Time { .. }, false; }
    guard day_val >= 1 && day_val <= days_in_month(year_val, month_val) else { return Time { .. }, false; }
    let valid_clock = hour_val >= 0 && hour_val <= 23 &&
        min_val >= 0 && min_val <= 59 && sec_val >= 0 && sec_val <= 60;
    guard valid_clock else { return Time { .. }, false; }
    guard sec_val < 60 || (hour_val == 23 && min_val == 59) else { return Time { .. }, false; }

    let days_count = civil_to_days(year_val, month_val, day_val);
    let wday = rem_euclid_i64(add_sat_i64(rem_euclid_i64(days_count, 7), 4), 7);
    guard wday == expected_wday else { return Time { .. }, false; }

    let hm_secs = add_sat_i64(mul_sat_i64(hour_val, 3600), mul_sat_i64(min_val, 60));
    let total_secs = add_sat_i64(mul_sat_i64(days_count, 86400), add_sat_i64(hm_secs, sec_val));
    return unix(total_secs, 0), true;
}

// Example:
//   rest = "06 Nov 1994 08:49:37 GMT", expected_wday = 0
//   returns: Time { ... }, ok = true
fn parse_imf_fixdate(rest: const u8[:], expected_wday: i64) -> Time, bool {
    let is_imf = rest.len == 24 && rest[2] == ' ' && rest[6] == ' ' &&
                 rest[11] == ' ' && rest[14] == ':' && rest[17] == ':' &&
                 eq_ascii_fold(rest[20..24], " GMT");
    guard is_imf else { return Time { .. }, false; }
    let day_val, ok_day = parse_digits(rest[..2]);
    let month_val = parse_month_name(rest[3..6]);
    let year_val, ok_year = parse_digits(rest[7..11]);
    let hour_val, ok_hour = parse_digits(rest[12..14]);
    let min_val, ok_min = parse_digits(rest[15..17]);
    let sec_val, ok_sec = parse_digits(rest[18..20]);

    guard ok_day && month_val > 0 && ok_year && ok_hour && ok_min && ok_sec else {
        return Time { .. }, false;
    }
    return make_validated_civil_time(year_val, month_val, day_val, hour_val, min_val, sec_val, expected_wday);
}

inline fn resolve_rfc850_two_digit_year(parsed_year: i64, ref_year: i64) -> i64 {
    let century = mul_sat_i64(div_euclid_i64(ref_year, 100), 100);
    let candidate = add_sat_i64(century, parsed_year);
    if candidate > add_sat_i64(ref_year, 50) {
        return sub_sat_i64(candidate, 100);
    }
    if candidate < sub_sat_i64(ref_year, 49) {
        return add_sat_i64(candidate, 100);
    }
    return candidate;
}

// Example:
//   rest = "06-Nov-94 08:49:37 GMT", expected_wday = 0
//   returns: Time { ... }, ok = true
fn parse_rfc850_date(rest: const u8[:], expected_wday: i64) -> Time, bool {
    let first_dash = index_of_byte(rest, '-');
    guard first_dash == 2 else { return Time { .. }, false; }

    let day_val, ok_day = parse_digits(rest[..first_dash]);
    guard ok_day else { return Time { .. }, false; }

    let after_day = rest[add_sat_i64(first_dash, 1)..];
    let second_dash = index_of_byte(after_day, '-');
    guard second_dash == 3 else { return Time { .. }, false; }

    let month_val = parse_month_name(after_day[..second_dash]);
    guard month_val > 0 else { return Time { .. }, false; }

    let after_month = after_day[add_sat_i64(second_dash, 1)..];
    let is_rfc850 = after_month.len == 15 && after_month[2] == ' ' && after_month[5] == ':' &&
        after_month[8] == ':' && eq_ascii_fold(after_month[11..15], " GMT");
    guard is_rfc850 else { return Time { .. }, false; }

    let parsed_year, ok_year = parse_digits(after_month[..2]);
    guard ok_year else { return Time { .. }, false; }
    let year_val = resolve_rfc850_two_digit_year(parsed_year, now().utc().year());

    let hour_val, ok_hour = parse_digits(after_month[3..5]);
    let min_val, ok_min = parse_digits(after_month[6..8]);
    let sec_val, ok_sec = parse_digits(after_month[9..11]);
    guard ok_hour && ok_min && ok_sec else { return Time { .. }, false; }

    return make_validated_civil_time(year_val, month_val, day_val, hour_val, min_val, sec_val, expected_wday);
}

// Example:
//   text = "Sun Nov  6 08:49:37 1994"
//   returns: Time { ... }, ok = true
fn parse_asctime_date(text: const u8[:]) -> Time, bool {
    let is_asctime = text.len == 24 && text[3] == ' ' && text[7] == ' ' &&
        text[10] == ' ' && text[13] == ':' && text[16] == ':' && text[19] == ' ';
    guard is_asctime else { return Time { .. }, false; }
    let expected_wday = parse_weekday_short(text[..3]);
    guard expected_wday >= 0 else { return Time { .. }, false; }
    let month_val = parse_month_name(text[4..7]);
    guard month_val > 0 else { return Time { .. }, false; }

    let day_part = if text[8] == ' ' { text[9..10] } else { text[8..10] };
    let valid_d0 = text[8] == ' ' || (text[8] >= '0' && text[8] <= '9');
    guard valid_d0 && text[9] >= '0' && text[9] <= '9' else { return Time { .. }, false; }
    let day_val, ok_day = parse_digits(day_part);
    guard ok_day else { return Time { .. }, false; }

    let hour_val, ok_hour = parse_digits(text[11..13]);
    let min_val, ok_min = parse_digits(text[14..16]);
    let sec_val, ok_sec = parse_digits(text[17..19]);
    let year_val, ok_year = parse_digits(text[20..24]);
    guard ok_hour && ok_min && ok_sec && ok_year else { return Time { .. }, false; }

    return make_validated_civil_time(year_val, month_val, day_val, hour_val, min_val, sec_val, expected_wday);
}
