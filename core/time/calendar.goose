// Gregorian calendar enums, month/weekday names, and civil calendar math (Howard Hinnant).
namespace core;

import std;

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

