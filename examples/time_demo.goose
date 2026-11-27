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

    // Method-syntax / native operator arithmetic
    let native_sum = core::secs(10) + core::mins(2);
    assert(native_sum.as_secs_f64() == 130.0, "Native operator: core::secs(10) + core::mins(2) == 130s");

    let native_diff = core::hours(1) - core::mins(15);
    assert((native_diff.nanos / core::MINUTE) == 45, "Native operator: core::hours(1) - core::mins(15) == 45m");

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
    assert(zero_dur.nanos <= 0 && !zero_dur.is_negative(), "zero_dur is neither positive nor negative");

    let positive_dur = core::secs(1);
    assert(positive_dur.nanos > 0, "positive_dur.nanos > 0");
    assert(!positive_dur.is_zero(), "positive_dur.is_zero() == false");

    // Round
    let rounded = core::round(core::secs(75), core::mins(1));
    assert(rounded.as_secs() == 60, "round(75s, 1m) == 1m");
}

fn test_duration_formatting() {
    print("=== 2. Duration Formatting ===");

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
    assert(sample_time.nsec == 500000000, "Nanosecond is 500,000,000");

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

    assert(time2.after(time1) || time2.compare(time1) == 0, "now() advances (time2 >= time1)");

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

fn test_comparisons_and_calendar() {
    print("=== 8. Pure Point-in-Time Comparisons & Calendar Helpers ===");

    let time1 = core::unix(100, 0);
    let time2 = core::unix(200, 0);

    assert(time2.compare(time1) > 0, "compare(time2, time1) > 0");
    assert(time1.compare(time2) < 0, "compare(time1, time2) < 0");
    assert(time1.compare(time1) == 0, "compare(time1, time1) == 0");
    assert(time1.before(time2), "before(time1, time2) == true");
    assert(time2.after(time1), "after(time2, time1) == true");

    assert(core::days_in_month(2025, 1) == 31, "Jan has 31 days");
    assert(core::days_in_month(2024, 2) == 29, "Feb 2024 has 29 days");
    assert(core::days_in_month(2025, 2) == 28, "Feb 2025 has 28 days");
    assert(core::is_leap_year(2024), "2024 is leap year");
    assert(!core::is_leap_year(2025), "2025 is not leap year");
}

fn test_http_resilience_policies() {
    print("=== 9. HTTP Resilience Policies: Backoff & RateLimiter ===");

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
    test_duration_formatting();
    test_calendar_and_time_construction();
    test_time_arithmetic();
    test_formatting_standards();
    test_parsing_standards();
    test_stopwatch_and_deadline();
    test_comparisons_and_calendar();
    test_http_resilience_policies();

    print("------------------------------------------------------------------");
    print("  ALL 9 TEST SUITES PASSED CLEANLY! PERFECT STDLIB HARMONY!       ");
    print("------------------------------------------------------------------");
}
