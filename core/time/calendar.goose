// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Gregorian calendar enums, month/weekday names, and civil calendar math (Howard Hinnant).
namespace core;

import std;
import core.math.arithmetic;

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

fn month_number(month_val: Month) -> i64 {
    var idx: i64 = 1;
    const for <N, V> in variants<Month> {
        let v: Month = default<V>();
        if month_val == v { return idx; }
        idx += 1;
    }
    return 1;
}

fn month_from_number(month_num: i64) -> Month {
    let target = (rem_euclid_i64(month_num, 12) + 11) % 12;
    var idx: i64 = 0;
    const for <N, V> in variants<Month> {
        if target == idx { return default<V>(); }
        idx += 1;
    }
    return Month.January;
}

fn month_name(month_val: Month) -> const u8[:] {
    return match month_val {
        const for <N, V> in variants<Month> {
            V => N,
        },
    };
}

fn month_short_name(month_val: Month) -> const u8[:] {
    return month_name(month_val)[..3];
}

fn weekday_from_number(weekday_num: i64) -> Weekday {
    let norm = rem_euclid_i64(weekday_num, 7);
    var idx: i64 = 0;
    const for <N, V> in variants<Weekday> {
        if norm == idx { return default<V>(); }
        idx += 1;
    }
    return Weekday.Sunday;
}

fn weekday_name(weekday_val: Weekday) -> const u8[:] {
    return match weekday_val {
        const for <N, V> in variants<Weekday> {
            V => N,
        },
    };
}

fn weekday_short_name(weekday_val: Weekday) -> const u8[:] {
    return weekday_name(weekday_val)[..3];
}

// ---- civil calendar math (Howard Hinnant) ----------------------------------

// Converts between proleptic Gregorian calendar (year, month, day) and days since
// Unix epoch (1970-01-01) in O(1) time without loops, lookup tables, or heap allocations.
// Reference: Howard Hinnant, "chrono-Compatible Low-Level Date Algorithms" (2013).
fn days_to_civil(days_since_epoch: i64) -> i64, i64, i64 {
    let shifted_days = add_sat_i64(days_since_epoch, 719468);
    let era = div_euclid_i64(shifted_days, 146097);
    let day_of_era = shifted_days % 146097;
    let year_of_era = (day_of_era - day_of_era / 1460 + day_of_era / 36524 - day_of_era / 146096) / 365;
    var year_val = add_sat_i64(year_of_era, mul_sat_i64(era, 400));
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month_prime = (5 * day_of_year + 2) / 153;
    let day_val = day_of_year - (153 * month_prime + 2) / 5 + 1;
    let month_val = if month_prime < 10 { month_prime + 3 } else { month_prime - 9 };
    if month_val <= 2 { year_val = add_sat_i64(year_val, 1); }
    return year_val, month_val, day_val;
}

fn civil_to_days(year_val: i64, month_val: i64, day_val: i64) -> i64 {
    let m0 = sub_sat_i64(month_val, 1);
    let year_carry = div_euclid_i64(m0, 12);
    let adjusted_month = (m0 % 12) + 1;
    var adjusted_year = add_sat_i64(year_val, year_carry);
    if adjusted_month <= 2 { adjusted_year = sub_sat_i64(adjusted_year, 1); }
    let era = div_euclid_i64(adjusted_year, 400);
    let year_of_era = adjusted_year % 400;
    let m_shift = if adjusted_month > 2 { adjusted_month - 3 } else { adjusted_month + 9 };
    let day_of_year = add_sat_i64((153 * m_shift + 2) / 5, sub_sat_i64(day_val, 1));
    let day_of_era = add_sat_i64(365 * year_of_era + year_of_era / 4 - year_of_era / 100, day_of_year);
    return sub_sat_i64(add_sat_i64(mul_sat_i64(era, 146097), day_of_era), 719468);
}

fn is_leap_year(year_val: i64) -> bool {
    return (year_val % 4 == 0 && year_val % 100 != 0) || (year_val % 400 == 0);
}

fn days_in_month(year_val: i64, month_val: i64) -> i64 {
    match month_val {
        1, 3, 5, 7, 8, 10, 12 => 31,
        4, 6, 9, 11 => 30,
        2 => if is_leap_year(year_val) { 29 } else { 28 },
        _ => 0,
    }
}
