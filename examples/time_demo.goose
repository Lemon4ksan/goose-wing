// Test and demonstration of the clean, stdlib-ready Time & Duration library in goose-wing.
import std;
import wing from "..";

fn assert(cond: bool, msg: const u8[:]) {
    if !cond {
        print("FAIL: ", msg);
        abort(msg);
    } else {
        print("  PASS: ", msg);
    }
}

fn test_duration_basics() {
    print("=== 1. Duration Arithmetic & Accessors ===");

    let d = wing::millis(1500);
    assert(d.as_nanos() == 1500000000, "1500ms == 1,500,000,000ns");
    assert(d.as_millis() == 1500, "1500ms as millis == 1500");
    assert(d.as_secs_f64() == 1.5, "1500ms as seconds == 1.5");

    let sum = wing::secs(10).add(wing::mins(2));
    assert(sum.as_secs_f64() == 130.0, "10s + 2m == 130s");

    let diff = wing::hours(1).sub(wing::mins(15));
    assert(diff.as_mins_f64() == 45.0, "1h - 15m == 45m");

    let scaled = wing::secs(5).mul(4);
    assert(scaled.as_secs_f64() == 20.0, "5s * 4 == 20s");

    let halved = wing::secs(20).div(2);
    assert(halved.as_secs_f64() == 10.0, "20s / 2 == 10s");

    let neg = wing::secs(-5);
    assert(neg.is_negative(), "-5s is negative");
    assert(neg.abs().as_secs_f64() == 5.0, "abs(-5s) == 5s");

    let rounded = wing::round(wing::secs(75), wing::mins(1));
    assert(rounded.as_mins_f64() == 1.0, "round(75s, 1m) == 1m");

    let truncated = wing::truncate(wing::secs(75), wing::mins(1));
    assert(truncated.as_mins_f64() == 1.0, "truncate(75s, 1m) == 1m");
}

fn test_duration_formatting_and_parsing() {
    print("=== 2. Duration Formatting & Go-Compatible ParseDuration ===");

    var buf: u8[..64] = [];

    buf.clear();
    wing::format(buf, wing::millis(250));
    assert(buf[..] == "250ms", "Formatted 250ms");

    buf.clear();
    wing::format(buf, wing::secs(1).add(wing::millis(500)));
    assert(buf[..] == "1.5s", "Formatted 1.5s");

    buf.clear();
    wing::format(buf, wing::hours(2).add(wing::mins(45)));
    assert(buf[..] == "2h45m", "Formatted 2h45m");

    let d1, ok1 = wing::parse_duration("500ms");
    assert(ok1, "Parsed 500ms");
    assert(d1.as_millis() == 500, "500ms matches 500 milliseconds");

    let d2, ok2 = wing::parse_duration("1h30m45s");
    assert(ok2, "Parsed composite duration 1h30m45s");
    let expected_s = (1 * 3600 + 30 * 60 + 45) as f64;
    assert(d2.as_secs_f64() == expected_s, "1h30m45s matches 5445 seconds");

    let d3, ok3 = wing::parse_duration("-2.5s");
    assert(ok3, "Parsed fractional negative duration -2.5s");
    assert(d3.as_secs_f64() == -2.5, "-2.5s matches -2.5 seconds");

    let d4, ok4 = wing::parse_duration("100ns");
    assert(ok4, "Parsed 100ns");
    assert(d4.as_nanos() == 100, "100ns matches 100 nanoseconds");
}

fn test_calendar_and_time_construction() {
    print("=== 3. Howard Hinnant Civil Calendar Decomposition ===");

    let t = wing::date(2026, wing::Month.October, 22, 23, 18, 18, 500000000, 0);
    assert(t.year() == 2026, "Year is 2026");
    assert(t.month() == wing::Month.October, "Month is October");
    assert(t.month_number() == 10, "Month number is 10");
    assert(t.day() == 22, "Day is 22");
    assert(t.weekday() == wing::Weekday.Thursday, "2026-10-22 is Thursday");
    assert(t.hour() == 23, "Hour is 23");
    assert(t.minute() == 18, "Minute is 18");
    assert(t.second() == 18, "Second is 18");
    assert(t.nanosecond() == 500000000, "Nanosecond is 500,000,000");

    // Leap year Feb 29, 2000 test (century leap year divisible by 400)
    let leap_t = wing::date(2000, wing::Month.February, 29, 12, 0, 0, 0, 0);
    assert(leap_t.year() == 2000, "Leap year 2000");
    assert(leap_t.month() == wing::Month.February, "Leap month Feb");
    assert(leap_t.day() == 29, "Leap day 29");
    assert(leap_t.weekday() == wing::Weekday.Tuesday, "2000-02-29 was Tuesday");

    // 1970-01-01 epoch check
    let epoch = wing::unix(0, 0);
    assert(epoch.year() == 1970 && epoch.month_number() == 1 && epoch.day() == 1, "Unix(0) is 1970-01-01");
    assert(epoch.weekday() == wing::Weekday.Thursday, "1970-01-01 was Thursday");
}

fn test_time_arithmetic() {
    print("=== 4. Time Arithmetic & Monotonic-Free Precision ===");

    let t1 = wing::now();
    wing::sleep(wing::millis(2));
    let t2 = wing::now();

    assert(t2.after(t1) || t2.equal(t1), "now() advances (t2 >= t1)");

    let t = wing::date(2026, wing::Month.October, 22, 10, 0, 0, 0, 0);
    let tomorrow = t.add(wing::days(1));
    assert(tomorrow.day() == 23, "add(1 day) moves 22 -> 23");

    // Subtraction of two Times produces a clean Duration
    let diff = tomorrow.sub(t);
    assert(diff.as_secs_f64() == 86400.0, "tomorrow - today == 86400s");
}

fn test_formatting_standards() {
    print("=== 5. RFC 3339 & RFC 1123 HTTP-Date Formats ===");

    let t = wing::date(2026, wing::Month.October, 22, 23, 18, 18, 500000000, 0);

    // RFC 3339
    var buf3339: u8[..64] = [];
    wing::format_rfc3339(buf3339, t);
    print("  RFC 3339: ", buf3339[..]);
    assert(buf3339[..] == "2026-10-22T23:18:18Z", "RFC 3339 matches 2026-10-22T23:18:18Z");

    // RFC 3339 Nano
    var buf_nano: u8[..64] = [];
    wing::format_rfc3339_nano(buf_nano, t);
    print("  RFC 3339 Nano: ", buf_nano[..]);
    assert(buf_nano[..] == "2026-10-22T23:18:18.5Z", "RFC 3339 Nano matches 2026-10-22T23:18:18.5Z");

    // RFC 1123 / HTTP Date
    var buf_http: u8[..64] = [];
    wing::format_http(buf_http, t);
    print("  RFC 1123: ", buf_http[..]);
    assert(buf_http[..] == "Thu, 22 Oct 2026 23:18:18 GMT", "RFC 1123 matches Thu, 22 Oct 2026 23:18:18 GMT");
}

fn test_parsing_standards() {
    print("=== 6. Parsing RFC 3339 & HTTP Date ===");

    // RFC 3339 UTC
    let t1, ok1 = wing::parse_rfc3339("2026-10-22T23:18:18Z");
    assert(ok1, "Parsed RFC 3339 UTC");
    assert(t1.year() == 2026 && t1.month_number() == 10 && t1.day() == 22, "RFC 3339 date verified");
    assert(t1.hour() == 23 && t1.minute() == 18 && t1.second() == 18, "RFC 3339 time verified");

    // RFC 3339 with timezone offset (+03:00)
    let t2, ok2 = wing::parse_rfc3339("2026-10-22T23:18:18+03:00");
    assert(ok2, "Parsed RFC 3339 with +03:00 timezone");
    assert(t2.tz_offset == 3 * 3600, "Timezone offset is +3 hours");

    // HTTP Date RFC 1123
    let t3, ok3 = wing::parse_http_date("Thu, 22 Oct 2026 23:18:18 GMT");
    assert(ok3, "Parsed HTTP Date");
    assert(t3.unix() == t1.unix(), "Parsed HTTP Date unix timestamp equals RFC 3339 unix timestamp");
}

fn test_stopwatch_and_deadline() {
    print("=== 7. High-Resolution Stopwatch & Deadline ===");

    let sw = wing::stopwatch();
    wing::sleep(wing::millis(5));
    let elapsed = sw.elapsed();
    print("  Stopwatch elapsed: ", elapsed.as_millis(), "ms (", elapsed.as_nanos(), "ns)");
    assert(elapsed.as_nanos() >= 4000000, "Stopwatch measured >= 4ms");

    // Deadline
    let dl = wing::deadline_after(wing::millis(20));
    assert(!dl.is_expired(), "Deadline is not initially expired");
    assert(dl.remaining().as_nanos() > 0, "Remaining duration > 0");

    wing::sleep(wing::millis(25));
    assert(dl.is_expired(), "Deadline expired after sleep");
    assert(dl.remaining().as_nanos() == 0, "Expired deadline remaining() == 0");
}

fn test_comparisons_and_truncation() {
    print("=== 8. Pure Point-in-Time Comparisons & Truncation ===");

    let t1 = wing::unix(100, 0);
    let t2 = wing::unix(200, 0);

    assert(t2.compare(t1) > 0, "compare(t2, t1) > 0");
    assert(t1.compare(t2) < 0, "compare(t1, t2) < 0");
    assert(t1.compare(t1) == 0, "compare(t1, t1) == 0");
    assert(t1.equal(t1), "equal(t1, t1) == true");
    assert(t1.before(t2), "before(t1, t2) == true");
    assert(t2.after(t1), "after(t2, t1) == true");

    // Time truncation and rounding
    let t = wing::date(2026, wing::Month.October, 22, 14, 25, 45, 0, 0);
    let trunc_h = t.truncate(wing::hours(1));
    assert(trunc_h.hour() == 14 && trunc_h.minute() == 0 && trunc_h.second() == 0, "Truncate to hour -> 14:00:00");

    let round_h = t.round(wing::hours(1));
    assert(round_h.hour() == 14 && round_h.minute() == 0, "25 min rounds down to 14:00:00");

    let t_near = wing::date(2026, wing::Month.October, 22, 14, 45, 0, 0, 0);
    let round_up = t_near.round(wing::hours(1));
    assert(round_up.hour() == 15 && round_up.minute() == 0, "45 min rounds up to 15:00:00");
}

fn test_clamped_calendar_math() {
    print("=== 9. Clamped Month/Year Addition (Correct Calendar Arithmetic) ===");

    // Jan 31 + 1 month clamped = Feb 28 in non-leap year (Go returns March 3!)
    let jan31 = wing::date(2025, wing::Month.January, 31, 12, 0, 0, 0, 0);
    let feb_clamped = jan31.add_months_clamped(1);
    assert(feb_clamped.year() == 2025 && feb_clamped.month_number() == 2 && feb_clamped.day() == 28, "Jan 31 + 1m clamped -> Feb 28");

    // Jan 31 + 1 month clamped = Feb 29 in leap year 2024
    let jan31_leap = wing::date(2024, wing::Month.January, 31, 12, 0, 0, 0, 0);
    let feb_leap_clamped = jan31_leap.add_months_clamped(1);
    assert(feb_leap_clamped.year() == 2024 && feb_leap_clamped.month_number() == 2 && feb_leap_clamped.day() == 29, "Jan 31 + 1m clamped on leap year -> Feb 29");

    // Feb 29 leap day + 1 year clamped = Feb 28, 2025
    let feb29_leap = wing::date(2024, wing::Month.February, 29, 12, 0, 0, 0, 0);
    let next_year_clamped = feb29_leap.add_years_clamped(1);
    assert(next_year_clamped.year() == 2025 && next_year_clamped.month_number() == 2 && next_year_clamped.day() == 28, "Feb 29 + 1y clamped -> Feb 28");

    // Days in month & year
    assert(jan31.days_in_month() == 31, "Jan has 31 days");
    assert(feb_leap_clamped.days_in_month() == 29, "Feb 2024 has 29 days");
    assert(feb_clamped.days_in_month() == 28, "Feb 2025 has 28 days");
    assert(jan31_leap.is_leap_year(), "2024 is leap year");
    assert(!jan31.is_leap_year(), "2025 is not leap year");
    assert(jan31_leap.days_in_year() == 366, "2024 has 366 days");
    assert(jan31.days_in_year() == 365, "2025 has 365 days");
}

fn test_calendar_boundaries() {
    print("=== 10. Day & Month Boundaries ===");

    let t = wing::date(2026, wing::Month.October, 22, 15, 30, 45, 0, 0);

    // Day boundaries
    let sod = t.start_of_day();
    assert(sod.hour() == 0 && sod.minute() == 0 && sod.second() == 0, "start_of_day is 00:00:00");
    let eod = t.end_of_day();
    assert(eod.hour() == 23 && eod.minute() == 59 && eod.second() == 59, "end_of_day is 23:59:59");

    // Month boundaries
    let som = t.start_of_month();
    assert(som.day() == 1 && som.hour() == 0, "start_of_month is 1st 00:00:00");
    let eom = t.end_of_month();
    assert(eom.day() == 31 && eom.hour() == 23, "end_of_month is 31st 23:59:59");

    // Year boundaries
    let soy = t.start_of_year();
    assert(soy.month_number() == 1 && soy.day() == 1, "start_of_year is Jan 1");
    let eoy = t.end_of_year();
    assert(eoy.month_number() == 12 && eoy.day() == 31, "end_of_year is Dec 31");
}

fn test_http_resilience_policies() {
    print("=== 11. HTTP Resilience Policies: Backoff & RateLimiter ===");

    // Backoff (moved to app/policy.goose)
    let b = wing::new_backoff(wing::millis(100), wing::secs(5), 2.0);
    assert(b.delay(0).as_millis() == 100, "Attempt 0 is base delay 100ms");
    assert(b.delay(1).as_millis() == 200, "Attempt 1 is 200ms");
    assert(b.delay(2).as_millis() == 400, "Attempt 2 is 400ms");
    assert(b.delay(10).as_secs_f64() == 5.0, "Attempt 10 capped at max 5.0s");

    // RateLimiter (Token Bucket, moved to app/policy.goose)
    var rl = wing::new_rate_limiter(10.0, 2); // 10 tokens/sec, burst 2
    assert(rl.allow(), "First token allowed");
    assert(rl.allow(), "Second burst token allowed");
    assert(!rl.allow(), "Third token immediately rejected (burst exhausted)");
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
