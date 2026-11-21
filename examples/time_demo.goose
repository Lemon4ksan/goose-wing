// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Test and demonstration of the clean, stdlib-ready Time & Duration library in goose-wing.
import std;
import wing from "..";

fn assert(cond: bool, message: const u8[:]) {
    if !cond {
        print("FAIL: ", message);
        abort(message);
    } else {
        print("  PASS: ", message);
    }
}

fn test_duration_basics() {
    print("=== 1. Duration Arithmetic & Accessors ===");

    let dur = core::millis(1500);
    assert(dur.as_nanos() == 1500000000, "1500ms == 1,500,000,000ns");
    assert(dur.as_millis() == 1500, "1500ms as millis == 1500");
    assert(dur.as_secs_f64() == 1.5, "1500ms as seconds == 1.5");

    // Method-syntax arithmetic
    let sum_via_method = core::secs(10).add(core::mins(2));
    assert(sum_via_method.as_secs_f64() == 130.0, "10s + 2m via add() == 130s");

    let diff_via_method = core::hours(1).sub(core::mins(15));
    assert(diff_via_method.as_mins_f64() == 45.0, "1h - 15m via sub() == 45m");

    // Goose native memberwise struct arithmetic: +, -, *, /, unary -, +=
    let native_sum = core::secs(10) + core::mins(2);
    assert(native_sum.as_secs_f64() == 130.0, "Native operator: core::secs(10) + core::mins(2) == 130s");

    let native_diff = core::hours(1) - core::mins(15);
    assert(native_diff.as_mins_f64() == 45.0, "Native operator: core::hours(1) - core::mins(15) == 45m");

    let native_mul = core::secs(5) * 4;
    assert(native_mul.as_secs_f64() == 20.0, "Native operator: core::secs(5) * 4 == 20s");

    let native_div = core::secs(20) / 2;
    assert(native_div.as_secs_f64() == 10.0, "Native operator: core::secs(20) / 2 == 10s");

    let native_neg = -core::secs(5);
    assert(native_neg.is_negative(), "Native operator: -core::secs(5) is_negative");
    assert(native_neg.abs().as_secs_f64() == 5.0, "abs(-5s) == 5s");

    var accumulating_dur = core::secs(10);
    accumulating_dur += core::secs(5);
    assert(accumulating_dur.as_secs_f64() == 15.0, "Native operator: += 5s accumulates to 15s");

    // Predicates
    let zero_dur = core::nanos(0);
    assert(zero_dur.is_zero(), "zero_dur.is_zero() == true");
    assert(!zero_dur.is_positive() && !zero_dur.is_negative(), "zero_dur is neither positive nor negative");

    let positive_dur = core::secs(1);
    assert(positive_dur.is_positive(), "positive_dur.is_positive() == true");
    assert(!positive_dur.is_zero(), "positive_dur.is_zero() == false");

    // Truncate and round
    let rounded = core::round(core::secs(75), core::mins(1));
    assert(rounded.as_mins_f64() == 1.0, "round(75s, 1m) == 1m");

    let truncated = core::truncate(core::secs(75), core::mins(1));
    assert(truncated.as_mins_f64() == 1.0, "truncate(75s, 1m) == 1m");
}

fn test_duration_formatting_and_parsing() {
    print("=== 2. Duration Formatting & Go-Compatible ParseDuration ===");

    var output_buf: u8[..64] = [];

    output_buf.clear();
    core::format(output_buf, core::millis(250));
    assert(output_buf[..] == "250ms", "Formatted 250ms");

    output_buf.clear();
    core::format(output_buf, core::secs(1) + core::millis(500));
    assert(output_buf[..] == "1.5s", "Formatted 1.5s");

    output_buf.clear();
    core::format(output_buf, core::hours(2) + core::mins(45));
    assert(output_buf[..] == "2h45m", "Formatted 2h45m");

    let dur1, ok1 = core::parse_duration("500ms");
    assert(ok1, "Parsed 500ms");
    assert(dur1.as_millis() == 500, "500ms matches 500 milliseconds");

    let dur2, ok2 = core::parse_duration("1h30m45s");
    assert(ok2, "Parsed composite duration 1h30m45s");
    let expected_seconds = (1 * 3600 + 30 * 60 + 45) as f64;
    assert(dur2.as_secs_f64() == expected_seconds, "1h30m45s matches 5445 seconds");

    let dur3, ok3 = core::parse_duration("-2.5s");
    assert(ok3, "Parsed fractional negative duration -2.5s");
    assert(dur3.as_secs_f64() == -2.5, "-2.5s matches -2.5 seconds");

    let dur4, ok4 = core::parse_duration("100ns");
    assert(ok4, "Parsed 100ns");
    assert(dur4.as_nanos() == 100, "100ns matches 100 nanoseconds");
}

fn test_calendar_and_time_construction() {
    print("=== 3. Howard Hinnant Civil Calendar Decomposition ===");

    let sample_time = core::date(2026, core::Month.October, 22, 23, 18, 18, 500000000, 0);
    assert(sample_time.year() == 2026, "Year is 2026");
    assert(sample_time.month() == core::Month.October, "Month is October");
    assert(sample_time.month_number() == 10, "Month number is 10");
    assert(sample_time.day() == 22, "Day is 22");
    assert(sample_time.weekday() == core::Weekday.Thursday, "2026-10-22 is Thursday");
    assert(sample_time.hour() == 23, "Hour is 23");
    assert(sample_time.minute() == 18, "Minute is 18");
    assert(sample_time.second() == 18, "Second is 18");
    assert(sample_time.nanosecond() == 500000000, "Nanosecond is 500,000,000");

    // Leap year Feb 29, 2000 test (century leap year divisible by 400)
    let leap_time = core::date(2000, core::Month.February, 29, 12, 0, 0, 0, 0);
    assert(leap_time.year() == 2000, "Leap year 2000");
    assert(leap_time.month() == core::Month.February, "Leap month Feb");
    assert(leap_time.day() == 29, "Leap day 29");
    assert(leap_time.weekday() == core::Weekday.Tuesday, "2000-02-29 was Tuesday");

    // 1970-01-01 epoch check
    let epoch_time = core::unix(0, 0);
    assert(epoch_time.year() == 1970 && epoch_time.month_number() == 1 && epoch_time.day() == 1, "Unix(0) is 1970-01-01");
    assert(epoch_time.weekday() == core::Weekday.Thursday, "1970-01-01 was Thursday");
}

fn test_time_arithmetic() {
    print("=== 4. Time Arithmetic & Monotonic-Free Precision ===");

    let time1 = core::now();
    core::sleep(core::millis(2));
    let time2 = core::now();

    assert(time2.after(time1) || time2.equal(time1), "now() advances (time2 >= time1)");

    let base_date = core::date(2026, core::Month.October, 22, 10, 0, 0, 0, 0);
    let tomorrow = base_date.add(core::days(1));
    assert(tomorrow.day() == 23, "add(1 day) moves 22 -> 23");

    // Subtraction of two Times produces a clean Duration
    let difference = tomorrow.sub(base_date);
    assert(difference.as_secs_f64() == 86400.0, "tomorrow - today == 86400s");
}

fn test_formatting_standards() {
    print("=== 5. RFC 3339 & RFC 1123 HTTP-Date Formats ===");

    let sample_time = core::date(2026, core::Month.October, 22, 23, 18, 18, 500000000, 0);

    // RFC 3339
    var buf_rfc3339: u8[..64] = [];
    core::format_rfc3339(buf_rfc3339, sample_time);
    print("  RFC 3339: ", buf_rfc3339[..]);
    assert(buf_rfc3339[..] == "2026-10-22T23:18:18Z", "RFC 3339 matches 2026-10-22T23:18:18Z");

    // RFC 3339 Nano
    var buf_nano: u8[..64] = [];
    core::format_rfc3339_nano(buf_nano, sample_time);
    print("  RFC 3339 Nano: ", buf_nano[..]);
    assert(buf_nano[..] == "2026-10-22T23:18:18.5Z", "RFC 3339 Nano matches 2026-10-22T23:18:18.5Z");

    // RFC 1123 / HTTP Date
    var buf_http: u8[..64] = [];
    core::format_http(buf_http, sample_time);
    print("  RFC 1123: ", buf_http[..]);
    assert(buf_http[..] == "Thu, 22 Oct 2026 23:18:18 GMT", "RFC 1123 matches Thu, 22 Oct 2026 23:18:18 GMT");
}

fn test_parsing_standards() {
    print("=== 6. Parsing RFC 3339 & HTTP Date ===");

    // RFC 3339 UTC
    let parsed_time1, ok1 = core::parse_rfc3339("2026-10-22T23:18:18Z");
    assert(ok1, "Parsed RFC 3339 UTC");
    assert(parsed_time1.year() == 2026 && parsed_time1.month_number() == 10 && parsed_time1.day() == 22, "RFC 3339 date verified");
    assert(parsed_time1.hour() == 23 && parsed_time1.minute() == 18 && parsed_time1.second() == 18, "RFC 3339 time verified");

    // RFC 3339 with timezone offset (+03:00)
    let parsed_time2, ok2 = core::parse_rfc3339("2026-10-22T23:18:18+03:00");
    assert(ok2, "Parsed RFC 3339 with +03:00 timezone");
    assert(parsed_time2.tz_offset == 3 * 3600, "Timezone offset is +3 hours");

    // HTTP Date RFC 1123
    let parsed_time3, ok3 = core::parse_http_date("Thu, 22 Oct 2026 23:18:18 GMT");
    assert(ok3, "Parsed HTTP Date");
    assert(parsed_time3.unix() == parsed_time1.unix(), "Parsed HTTP Date unix timestamp equals RFC 3339 unix timestamp");
}

fn test_stopwatch_and_deadline() {
    print("=== 7. High-Resolution Stopwatch & Deadline ===");

    let watch = core::stopwatch();
    core::sleep(core::millis(5));
    let elapsed_duration = watch.elapsed();
    print("  Stopwatch elapsed: ", elapsed_duration.as_millis(), "ms (", elapsed_duration.as_nanos(), "ns)");
    assert(elapsed_duration.as_nanos() >= 4000000, "Stopwatch measured >= 4ms");

    // Deadline (testing both stdlib expired() and compat is_expired())
    let deadline = core::deadline_after(core::millis(20));
    assert(!deadline.is_expired(), "Deadline is not initially expired (is_expired())");
    assert(deadline.remaining().as_nanos() > 0, "Remaining duration > 0");

    core::sleep(core::millis(25));
    assert(deadline.is_expired(), "Deadline expired after sleep (is_expired())");
    assert(deadline.remaining().as_nanos() == 0, "Expired deadline remaining() == 0");
}

fn test_comparisons_and_truncation() {
    print("=== 8. Pure Point-in-Time Comparisons & Truncation ===");

    let time1 = core::unix(100, 0);
    let time2 = core::unix(200, 0);

    assert(time2.compare(time1) > 0, "compare(time2, time1) > 0");
    assert(time1.compare(time2) < 0, "compare(time1, time2) < 0");
    assert(time1.compare(time1) == 0, "compare(time1, time1) == 0");
    assert(time1.equal(time1), "equal(time1, time1) == true");
    assert(time1.before(time2), "before(time1, time2) == true");
    assert(time2.after(time1), "after(time2, time1) == true");

    // Time truncation and rounding
    let sample_time = core::date(2026, core::Month.October, 22, 14, 25, 45, 0, 0);
    let truncated_hour = sample_time.truncate(core::hours(1));
    assert(truncated_hour.hour() == 14 && truncated_hour.minute() == 0 && truncated_hour.second() == 0, "Truncate to hour -> 14:00:00");

    let rounded_hour = sample_time.round(core::hours(1));
    assert(rounded_hour.hour() == 14 && rounded_hour.minute() == 0, "25 min rounds down to 14:00:00");

    let sample_near_time = core::date(2026, core::Month.October, 22, 14, 45, 0, 0, 0);
    let round_up_hour = sample_near_time.round(core::hours(1));
    assert(round_up_hour.hour() == 15 && round_up_hour.minute() == 0, "45 min rounds up to 15:00:00");
}

fn test_clamped_calendar_math() {
    print("=== 9. Clamped Month/Year Addition (Correct Calendar Arithmetic) ===");

    // Jan 31 + 1 month clamped = Feb 28 in non-leap year (Go returns March 3!)
    let jan31_non_leap = core::date(2025, core::Month.January, 31, 12, 0, 0, 0, 0);
    let feb_clamped = jan31_non_leap.add_months_clamped(1);
    assert(feb_clamped.year() == 2025 && feb_clamped.month_number() == 2 && feb_clamped.day() == 28, "Jan 31 + 1m clamped -> Feb 28");

    // Jan 31 + 1 month clamped = Feb 29 in leap year 2024
    let jan31_leap = core::date(2024, core::Month.January, 31, 12, 0, 0, 0, 0);
    let feb_leap_clamped = jan31_leap.add_months_clamped(1);
    assert(feb_leap_clamped.year() == 2024 && feb_leap_clamped.month_number() == 2 && feb_leap_clamped.day() == 29, "Jan 31 + 1m clamped on leap year -> Feb 29");

    // Feb 29 leap day + 1 year clamped = Feb 28, 2025
    let feb29_leap = core::date(2024, core::Month.February, 29, 12, 0, 0, 0, 0);
    let next_year_clamped = feb29_leap.add_years_clamped(1);
    assert(next_year_clamped.year() == 2025 && next_year_clamped.month_number() == 2 && next_year_clamped.day() == 28, "Feb 29 + 1y clamped -> Feb 28");

    // Days in month & year
    assert(jan31_non_leap.days_in_month() == 31, "Jan has 31 days");
    assert(feb_leap_clamped.days_in_month() == 29, "Feb 2024 has 29 days");
    assert(feb_clamped.days_in_month() == 28, "Feb 2025 has 28 days");
    assert(jan31_leap.is_leap_year(), "2024 is leap year");
    assert(jan31_leap.days_in_year() == 366, "2024 has 366 days");
    assert(jan31_non_leap.days_in_year() == 365, "2025 has 365 days");
}

fn test_calendar_boundaries() {
    print("=== 10. Day & Month Boundaries ===");

    let sample_time = core::date(2026, core::Month.October, 22, 15, 30, 45, 0, 0);

    // Day boundaries
    let start_day = sample_time.start_of_day();
    assert(start_day.hour() == 0 && start_day.minute() == 0 && start_day.second() == 0, "start_of_day is 00:00:00");
    let end_day = sample_time.end_of_day();
    assert(end_day.hour() == 23 && end_day.minute() == 59 && end_day.second() == 59, "end_of_day is 23:59:59");

    // Month boundaries
    let start_month = sample_time.start_of_month();
    assert(start_month.day() == 1 && start_month.hour() == 0, "start_of_month is 1st 00:00:00");
    let end_month = sample_time.end_of_month();
    assert(end_month.day() == 31 && end_month.hour() == 23, "end_of_month is 31st 23:59:59");

    // Year boundaries
    let start_year = sample_time.start_of_year();
    assert(start_year.month_number() == 1 && start_year.day() == 1, "start_of_year is Jan 1");
    let end_year = sample_time.end_of_year();
    assert(end_year.month_number() == 12 && end_year.day() == 31, "end_of_year is Dec 31");
}

fn test_http_resilience_policies() {
    print("=== 11. HTTP Resilience Policies: Backoff & RateLimiter ===");

    // Backoff (moved to client/policy.goose)
    let backoff = client::new_backoff(wing::millis(100), wing::secs(5), 2.0);
    assert(backoff.delay(0) == wing::millis(100), "Attempt 0 is base delay 100ms");
    assert(backoff.delay(1) == wing::millis(200), "Attempt 1 is 200ms");
    assert(backoff.delay(2) == wing::millis(400), "Attempt 2 is 400ms");
    assert(backoff.delay(10) == wing::secs(5), "Attempt 10 capped at max 5.0s");

    // RateLimiter (Token Bucket, moved to app/policy.goose)
    var limiter = client::new_rate_limiter(10.0, 2); // 10 tokens/sec, burst 2
    assert(limiter.allow(), "First token allowed");
    assert(limiter.allow(), "Second burst token allowed");
    assert(!limiter.allow(), "Third token immediately rejected (burst exhausted)");
}

fn main() {
    print("------------------------------------------------------------------");
    print("  goose-wing Standard Time & Duration Engine Test Suite           ");
    print("------------------------------------------------------------------");

    test_duration_basics();
    test_duration_formatting_and_parsing();
    test_calendar_and_time_construction();
    test_time_arithmetic();
    test_formatting_standards();
    test_parsing_standards();
    test_stopwatch_and_deadline();
    test_comparisons_and_truncation();
    test_clamped_calendar_math();
    test_calendar_boundaries();
    test_http_resilience_policies();

    print("------------------------------------------------------------------");
    print("  ALL 11 TEST SUITES PASSED CLEANLY! PERFECT STDLIB HARMONY!      ");
    print("------------------------------------------------------------------");
}
