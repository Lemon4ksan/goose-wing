// Exhaustive test and demonstration of the Go-parity Time and Duration system in goose-wing.
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

    let d = wing::milliseconds(1500);
    assert(d.nanoseconds() == 1500000000, "1500ms == 1,500,000,000ns");
    assert(d.milliseconds() == 1500, "1500ms as millis == 1500");
    assert(d.seconds() == 1.5, "1500ms as seconds == 1.5");

    let sum = wing::seconds(10).add(wing::minutes(2));
    assert(sum.seconds() == 130.0, "10s + 2m == 130s");

    let diff = wing::hours(1).sub(wing::minutes(15));
    assert(diff.minutes() == 45.0, "1h - 15m == 45m");

    let scaled = wing::seconds(5).mul(4);
    assert(scaled.seconds() == 20.0, "5s * 4 == 20s");

    let halved = wing::seconds(20).div(2);
    assert(halved.seconds() == 10.0, "20s / 2 == 10s");

    let neg = wing::seconds(-5);
    assert(neg.is_negative(), "-5s is negative");
    assert(neg.abs().seconds() == 5.0, "abs(-5s) == 5s");

    let rounded = wing::round(wing::seconds(75), wing::minutes(1));
    assert(rounded.minutes() == 1.0, "round(75s, 1m) == 1m");

    let truncated = wing::truncate(wing::seconds(75), wing::minutes(1));
    assert(truncated.minutes() == 1.0, "truncate(75s, 1m) == 1m");
}

fn test_duration_formatting_and_parsing() {
    print("=== 2. Duration Formatting & Go ParseDuration ===");

    // Formatting
    var buf: u8[..64] = [];

    buf.clear();
    wing::format(buf, wing::milliseconds(250));
    assert(buf[..] == "250ms", "Formatted 250ms");

    buf.clear();
    wing::format(buf, wing::seconds(1).add(wing::milliseconds(500)));
    assert(buf[..] == "1.5s", "Formatted 1.5s");

    buf.clear();
    wing::format(buf, wing::hours(2).add(wing::minutes(45)));
    assert(buf[..] == "2h45m", "Formatted 2h45m");

    // Parsing
    let d1, ok1 = wing::parse_duration("500ms");
    assert(ok1, "Parsed 500ms");
    assert(d1.milliseconds() == 500, "500ms matches 500 milliseconds");

    let d2, ok2 = wing::parse_duration("1h30m45s");
    assert(ok2, "Parsed composite duration 1h30m45s");
    let expected_s = (1 * 3600 + 30 * 60 + 45) as f64;
    assert(d2.seconds() == expected_s, "1h30m45s matches 5445 seconds");

    let d3, ok3 = wing::parse_duration("-2.5s");
    assert(ok3, "Parsed fractional negative duration -2.5s");
    assert(d3.seconds() == -2.5, "-2.5s matches -2.5 seconds");

    let d4, ok4 = wing::parse_duration("100ns");
    assert(ok4, "Parsed 100ns");
    assert(d4.nanoseconds() == 100, "100ns matches 100 nanoseconds");
}

fn test_calendar_and_time_construction() {
    print("=== 3. Howard Hinnant Calendar Decomposition & Leap Years ===");

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

fn test_time_arithmetic_and_monotonic() {
    print("=== 4. Time Arithmetic, Monotonic Precision & AddDate ===");

    let t1 = wing::now();
    wing::sleep(wing::milliseconds(2));
    let t2 = wing::now();

    assert(t2.after(t1), "now() advances monotonically (t2 after t1)");
    assert(t1.before(t2), "t1 before t2");

    let elapsed = t2.sub(t1);
    assert(elapsed.nanoseconds() > 0, "Elapsed monotonic time is strictly positive");

    let t = wing::date(2026, wing::Month.October, 22, 10, 0, 0, 0, 0);
    let tomorrow = t.add(wing::days(1));
    assert(tomorrow.day() == 23, "add(1 day) moves 22 -> 23");

    let next_year = t.add_date(1, 2, 5);
    assert(next_year.year() == 2027, "add_date(+1 year) == 2027");
    assert(next_year.month_number() == 12, "add_date(+2 months) == 12 (December)");
    assert(next_year.day() == 27, "add_date(+5 days) == 27");
}

fn test_formatting_and_layout_engine() {
    print("=== 5. RFC 3339, RFC 1123 & Go Layout Engine ===");

    let t = wing::date(2026, wing::Month.October, 22, 23, 18, 18, 0, 0);

    // RFC 3339
    var buf3339: u8[..64] = [];
    wing::format_rfc3339(buf3339, t);
    print("  RFC 3339: ", buf3339[..]);
    assert(buf3339[..] == "2026-10-22T23:18:18Z", "RFC 3339 matches 2026-10-22T23:18:18Z");

    // RFC 1123 / HTTP Date
    var buf_http: u8[..64] = [];
    wing::format_http(buf_http, t);
    print("  RFC 1123: ", buf_http[..]);
    assert(buf_http[..] == "Thu, 22 Oct 2026 23:18:18 GMT", "RFC 1123 matches Thu, 22 Oct 2026 23:18:18 GMT");

    // Go reference layout: "2006/01/02 15:04:05"
    var buf_custom: u8[..64] = [];
    wing::format_time(buf_custom, t, "2006/01/02 15:04:05");
    print("  buf_custom: ", buf_custom[..]);
    assert(buf_custom[..] == "2026/10/22 23:18:18", "Go layout 2006/01/02 15:04:05 formatted correctly");

    // 12-hour format with AM/PM: "03:04:05 PM"
    var buf_12h: u8[..64] = [];
    wing::format_time(buf_12h, t, "03:04:05 PM");
    assert(buf_12h[..] == "11:18:18 PM", "12-hour layout 03:04:05 PM formatted correctly");

    // Long names: "Monday, January 02, 2006"
    var buf_long: u8[..64] = [];
    wing::format_time(buf_long, t, "Monday, January 02, 2006");
    print("  Long date: ", buf_long[..]);
    assert(buf_long[..] == "Thursday, October 22, 2026", "Long date layout formatted correctly");
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

fn test_stopwatch() {
    print("=== 7. High-Resolution Stopwatch ===");

    let sw = wing::stopwatch();
    wing::sleep(wing::milliseconds(5));
    let elapsed = sw.elapsed();
    print("  Stopwatch elapsed: ", elapsed.milliseconds(), "ms (", elapsed.nanoseconds(), "ns)");
    assert(elapsed.nanoseconds() >= 4000000, "Stopwatch measured >= 4ms");
}

fn main() {
    print("------------------------------------------------------------------");
    print("  goose-wing Go-Parity Time & Duration Engine Test Suite          ");
    print("------------------------------------------------------------------");

    test_duration_basics();
    test_duration_formatting_and_parsing();
    test_calendar_and_time_construction();
    test_time_arithmetic_and_monotonic();
    test_formatting_and_layout_engine();
    test_parsing_standards();
    test_stopwatch();

    print("------------------------------------------------------------------");
    print("  ALL 7 TIME SUITES PASSED CLEANLY! FLAWLESS GO PARITY!          ");
    print("------------------------------------------------------------------");
}
