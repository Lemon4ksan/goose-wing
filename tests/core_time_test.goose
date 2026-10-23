// Tests for core/time: duration arithmetic, calendar math, and RFC 3339 codecs.
import std;
import wing from "..";

struct StringVector {
    input: const u8[:],
    expect_ok: bool,
    desc: const u8[:],
}

// ----------------------------------------------------------------------------
// 1. Duration Arithmetic, i64.min/max, Signs & Accessors
// ----------------------------------------------------------------------------
fn test_duration_arithmetic_and_bounds(t: wing::T&) {
    t.run("Unit Scales & Conversion Accessors") { sub =>
        let d_ns = wing::nanos(50);
        let d_us = wing::micros(50);
        let d_ms = wing::millis(50);
        let d_s = wing::secs(50);
        let d_m = wing::mins(50);
        let d_h = wing::hours(2);
        let d_d = wing::days(3);
        let d_w = wing::weeks(1);

        sub.assert_eq(d_ns.as_nanos(), 50);
        sub.assert_eq(d_us.as_nanos(), 50000);
        sub.assert_eq(d_us.as_micros(), 50);
        sub.assert_eq(d_ms.as_micros(), 50000);
        sub.assert_eq(d_ms.as_millis(), 50);
        sub.assert_eq(d_s.as_millis(), 50000);
        sub.assert_eq(d_s.as_secs(), 50);
        sub.assert_eq(d_m.as_secs(), 3000);
        sub.assert_eq(d_m.as_mins(), 50);
        sub.assert_eq(d_h.as_mins(), 120);
        sub.assert_eq(d_h.as_hours(), 2);
        sub.assert_eq(d_d.as_hours(), 72);
        sub.assert_eq(d_d.as_days(), 3);
        sub.assert_eq(d_w.as_days(), 7);

        sub.assert_in_delta(wing::millis(1500).as_secs_f64(), 1.5, 0.000001);
        sub.assert_in_delta(wing::secs(90).as_mins_f64(), 1.5, 0.000001);
        sub.assert_in_delta(wing::mins(90).as_hours_f64(), 1.5, 0.000001);
    };

    t.run("Operator Arithmetic & Mutating Assignments") { sub =>
        let a = wing::secs(10);
        let b = wing::secs(3);

        sub.assert_eq((a + b).as_secs(), 13);
        sub.assert_eq((a - b).as_secs(), 7);
        sub.assert_eq((a * 4).as_secs(), 40);
        sub.assert_eq((a / 2).as_secs(), 5);
        sub.assert_eq((-a).as_secs(), -10);

        var acc = wing::secs(10);
        acc += wing::secs(5);
        sub.assert_eq(acc.as_secs(), 15);
        acc -= wing::secs(3);
        sub.assert_eq(acc.as_secs(), 12);
        acc *= 2;
        sub.assert_eq(acc.as_secs(), 24);
        acc /= 4;
        sub.assert_eq(acc.as_secs(), 6);
    };

    t.run("Abs, Zero, Positive, Negative & i64.min Boundary") { sub =>
        let pos = wing::secs(5);
        let zero_dur = wing::nanos(0);
        let neg = wing::secs(-5);
        let min_i64_dur = wing::Duration { nanos: -9223372036854775807 - 1 };

        sub.assert_true(pos.is_positive());
        sub.assert_false(pos.is_negative() || pos.is_zero());

        sub.assert_true(zero_dur.is_zero());
        sub.assert_false(zero_dur.is_positive() || zero_dur.is_negative());

        sub.assert_true(neg.is_negative());
        sub.assert_false(neg.is_positive() || neg.is_zero());

        sub.assert_eq(pos.abs().as_secs(), 5);
        sub.assert_eq(zero_dur.abs().as_nanos(), 0);
        sub.assert_eq(neg.abs().as_secs(), 5);

        // i64.min (-9223372036854775808) must be clamped to i64.max to prevent negative wrap-around
        let abs_min = min_i64_dur.abs();
        sub.assert_eq(abs_min.as_nanos(), 9223372036854775807, "abs(i64.min) must clamp to i64.max without overflow");
    };

    t.run("Three-way Comparison") { sub =>
        let d1 = wing::secs(5);
        let d2 = wing::secs(10);
        let d3 = wing::secs(5);

        sub.assert_eq(wing::compare(d1, d2), -1);
        sub.assert_eq(wing::compare(d2, d1), 1);
        sub.assert_eq(wing::compare(d1, d3), 0);
    };
}

// ----------------------------------------------------------------------------
// 2. Duration Truncation and Rounding
// ----------------------------------------------------------------------------
fn test_duration_truncation_and_rounding(t: wing::T&) {
    t.run("Truncation Towards Zero") { sub =>
        // Step <= 0 returns dur unchanged
        sub.assert_eq(wing::truncate(wing::secs(75), wing::secs(0)).as_secs(), 75);
        sub.assert_eq(wing::truncate(wing::secs(75), wing::secs(-1)).as_secs(), 75);

        // Positive truncation
        sub.assert_eq(wing::truncate(wing::secs(75), wing::mins(1)).as_secs(), 60);
        sub.assert_eq(wing::truncate(wing::secs(59), wing::mins(1)).as_secs(), 0);
        sub.assert_eq(wing::truncate(wing::secs(120), wing::mins(1)).as_secs(), 120);

        // Negative truncation (towards zero)
        sub.assert_eq(wing::truncate(wing::secs(-75), wing::mins(1)).as_secs(), -60);
        sub.assert_eq(wing::truncate(wing::secs(-59), wing::mins(1)).as_secs(), 0);

        // i64.min truncation must stay negative (towards zero), never wrap to positive
        let min_dur = wing::Duration { nanos: -9223372036854775807 - 1 };
        let trunc_min = wing::truncate(min_dur, wing::secs(1));
        sub.assert_true(trunc_min.is_negative(), "truncate(min_i64) must remain negative");
        sub.assert_eq(trunc_min.as_nanos(), -9223372036000000000, "truncate(min_i64) rounds toward zero");
    };

    t.run("Rounding Half-Away-From-Zero") { sub =>
        // Step <= 0 returns dur unchanged
        sub.assert_eq(wing::round(wing::secs(75), wing::secs(0)).as_secs(), 75);

        // Positive rounding: 29s -> 0, 30s -> 60s (half rounds away), 31s -> 60s
        sub.assert_eq(wing::round(wing::secs(29), wing::mins(1)).as_secs(), 0);
        sub.assert_eq(wing::round(wing::secs(30), wing::mins(1)).as_secs(), 60);
        sub.assert_eq(wing::round(wing::secs(31), wing::mins(1)).as_secs(), 60);
        sub.assert_eq(wing::round(wing::secs(89), wing::mins(1)).as_secs(), 60);
        sub.assert_eq(wing::round(wing::secs(90), wing::mins(1)).as_secs(), 120);

        // Negative rounding: -29s -> 0, -30s -> -60s (away from zero), -31s -> -60s
        sub.assert_eq(wing::round(wing::secs(-29), wing::mins(1)).as_secs(), 0);
        sub.assert_eq(wing::round(wing::secs(-30), wing::mins(1)).as_secs(), -60);
        sub.assert_eq(wing::round(wing::secs(-31), wing::mins(1)).as_secs(), -60);
        sub.assert_eq(wing::round(wing::secs(-89), wing::mins(1)).as_secs(), -60);
        sub.assert_eq(wing::round(wing::secs(-90), wing::mins(1)).as_secs(), -120);
    };

    t.run("Large Step Duration Overflow Immunity") { sub =>
        // remainder * 2 would overflow if remainder > i64.max / 2
        let half_max = 4611686018427387900;
        let step = wing::Duration { nanos: half_max + 100 };
        let dur = wing::Duration { nanos: half_max + 50 };
        let rounded = wing::round(dur, step);
        sub.assert_eq(rounded.as_nanos(), step.as_nanos(), "rounding with large step must not overflow i64");
    };
}

// ----------------------------------------------------------------------------
// 3. Duration Formatting & Go-Compatible ParseDuration Security
// ----------------------------------------------------------------------------
fn test_duration_format_and_parse_security(t: wing::T&) {
    t.run("Format Duration Zero-Alloc") { sub =>
        var buf: u8[..64] = [];

        buf.clear(); wing::format(buf, wing::nanos(0));
        sub.assert_bytes_eq(buf[..], "0s");

        buf.clear(); wing::format(buf, wing::nanos(500));
        sub.assert_bytes_eq(buf[..], "500ns");

        buf.clear(); wing::format(buf, wing::micros(750));
        sub.assert_bytes_eq(buf[..], "750us");

        buf.clear(); wing::format(buf, wing::millis(250));
        sub.assert_bytes_eq(buf[..], "250ms");

        buf.clear(); wing::format(buf, wing::secs(1) + wing::millis(500));
        sub.assert_bytes_eq(buf[..], "1.5s");

        buf.clear(); wing::format(buf, wing::hours(2) + wing::mins(45));
        sub.assert_bytes_eq(buf[..], "2h45m");

        buf.clear(); wing::format(buf, wing::millis(-250));
        sub.assert_bytes_eq(buf[..], "-250ms");

        // i64.min must format cleanly without double minus "--"
        buf.clear(); wing::format(buf, wing::Duration { nanos: -9223372036854775807 - 1 });
        sub.assert_contains(buf[..], "-2562047h47m16.854775808s");
    };

    t.run("Valid ParseDuration Matrix (Basic, Composite, High-Precision Fraction)") { sub =>
        let d1, ok1 = wing::parse_duration("500ms");
        sub.require_true(ok1);
        sub.assert_eq(d1.as_millis(), 500);

        let d2, ok2 = wing::parse_duration("1h30m45s");
        sub.require_true(ok2);
        sub.assert_eq(d2.as_secs(), 5445);

        let d3, ok3 = wing::parse_duration("-2.5s");
        sub.require_true(ok3);
        sub.assert_in_delta(d3.as_secs_f64(), -2.5, 0.000001);

        let d4, ok4 = wing::parse_duration("100ns");
        sub.require_true(ok4);
        sub.assert_eq(d4.as_nanos(), 100);

        let d5, ok5 = wing::parse_duration("2w3d4h");
        sub.require_true(ok5);
        sub.assert_eq(d5.as_hours(), 2 * 168 + 3 * 24 + 4);

        // 9-digit fractional nanoseconds in large units (MUST NOT OVERFLOW i64)
        let d6, ok6 = wing::parse_duration("0.500000000h");
        sub.require_true(ok6, "0.500000000h must parse without fraction multiplication overflow");
        sub.assert_eq(d6.as_mins(), 30);

        let d7, ok7 = wing::parse_duration("0.500000000d");
        sub.require_true(ok7, "0.500000000d must parse without fraction multiplication overflow");
        sub.assert_eq(d7.as_hours(), 12);

        let d8, ok8 = wing::parse_duration("0.500000000w");
        sub.require_true(ok8, "0.500000000w must parse without fraction multiplication overflow");
        sub.assert_eq(d8.as_hours(), 84);

        let d9, ok9 = wing::parse_duration("+10s");
        sub.require_true(ok9);
        sub.assert_eq(d9.as_secs(), 10);

        // Leading dot shorthand (Go compatibility, e.g. .5s)
        let d_lead, ok_lead = wing::parse_duration(".5s");
        sub.require_true(ok_lead, ".5s leading dot must parse cleanly");
        sub.assert_eq(d_lead.as_millis(), 500);
    };

    t.run("ParseDuration Malicious & Malformed Vectors (Injection & Overflow Rejection)") { sub =>
        let bad_vectors = [
            StringVector { input: "", expect_ok: false, desc: "empty string" },
            StringVector { input: "   ", expect_ok: false, desc: "whitespace only" },
            StringVector { input: "+", expect_ok: false, desc: "lone plus sign" },
            StringVector { input: "-", expect_ok: false, desc: "lone minus sign" },
            StringVector { input: "+   ", expect_ok: false, desc: "plus sign with spaces" },
            StringVector { input: "-   ", expect_ok: false, desc: "minus sign with spaces" },
            StringVector { input: "s", expect_ok: false, desc: "unit with no number" },
            StringVector { input: "ms", expect_ok: false, desc: "unit with no number" },
            StringVector { input: "-s", expect_ok: false, desc: "sign and unit with no number" },
            StringVector { input: "500", expect_ok: false, desc: "number with no unit" },
            StringVector { input: "-100", expect_ok: false, desc: "negative number with no unit" },
            StringVector { input: "500xyz", expect_ok: false, desc: "unknown unit xyz" },
            StringVector { input: "100sec", expect_ok: false, desc: "invalid unit sec (must be s)" },
            StringVector { input: ".s", expect_ok: false, desc: "dot only with unit" },
            StringVector { input: "..s", expect_ok: false, desc: "double dot with unit" },
            StringVector { input: "1.2.3s", expect_ok: false, desc: "multiple dots in number" },
            StringVector { input: "1..5s", expect_ok: false, desc: "consecutive dots in number" },
            StringVector { input: "1.s", expect_ok: false, desc: "trailing dot with no fraction digits" },
            StringVector { input: "10s+20s", expect_ok: false, desc: "embedded plus sign" },
            StringVector { input: "10s-5s", expect_ok: false, desc: "embedded minus sign" },
            StringVector { input: "9223372036854775808ns", expect_ok: false, desc: "nanos exceeding i64.max" },
            StringVector { input: "999999999999999999h", expect_ok: false, desc: "hours multiplication overflow" },
            StringVector { input: "3000000h3000000h", expect_ok: false, desc: "accumulation sum overflow" },
            StringVector { input: "9223372036854775807s", expect_ok: false, desc: "seconds multiplication overflow" },
        ];

        wing::run_table(sub, "BadDurationMatrix", bad_vectors[..]) { sub2, row, idx =>
            let _, ok = wing::parse_duration(row.input);
            sub2.assert_eq(ok, row.expect_ok, row.desc);
        };
    };
}

// ----------------------------------------------------------------------------
// 4. Monotonic Primitives: Stopwatch & Deadline (Anti-Overflow & Expiration)
// ----------------------------------------------------------------------------
fn test_stopwatch_and_deadline_overflow(t: wing::T&) {
    t.run("Stopwatch Monotonic Progress & Restart") { sub =>
        var sw = wing::stopwatch();
        wing::sleep(wing::millis(3));
        let el1 = sw.elapsed();
        sub.assert_ge(el1.as_millis(), 2, "stopwatch elapsed >= 2ms");

        let restarted_el = sw.restart();
        sub.assert_ge(restarted_el.as_millis(), 2, "restart returns previous elapsed");
        let el2 = sw.elapsed();
        sub.assert_lt(el2.as_millis(), restarted_el.as_millis(), "elapsed resets after restart");
    };

    t.run("Deadline Standard Lifecycle") { sub =>
        let dl = wing::deadline_after(wing::millis(15));
        sub.assert_false(dl.is_expired());
        sub.assert_gt(dl.remaining().as_nanos(), 0);

        wing::sleep(wing::millis(20));
        sub.assert_true(dl.is_expired());
        sub.assert_eq(dl.remaining().as_nanos(), 0);

        // Non-positive deadline expires immediately
        let dl_zero = wing::deadline_after(wing::nanos(0));
        sub.assert_true(dl_zero.is_expired());
        let dl_neg = wing::deadline_after(wing::millis(-5));
        sub.assert_true(dl_neg.is_expired());

        // Unset deadline never expires
        let dl_none = wing::Deadline { target_mono_ns: 0, has_deadline: false };
        sub.assert_false(dl_none.is_expired());
        sub.assert_eq(dl_none.remaining().as_nanos(), 9223372036854775807);
    };

    t.run("CRITICAL: Deadline Maximum Duration Anti-Overflow Vulnerability Test") { sub =>
        // If clock_ns() + i64.max overflows to negative, deadline would immediately expire!
        let dl_max = wing::deadline_after(wing::Duration { nanos: 9223372036854775807 });
        sub.assert_false(dl_max.is_expired(), "deadline with i64.max timeout MUST NOT overflow and expire immediately");
        sub.assert_gt(dl_max.remaining().as_nanos(), 1000000000000);
    };
}

// ----------------------------------------------------------------------------
// 5. Civil Calendar Math & Proleptic Gregorian Leap Years
// ----------------------------------------------------------------------------
fn test_hinnant_civil_calendar_and_leap_years(t: wing::T&) {
    t.run("400-Year Gregorian Leap Year Rules") { sub =>
        // Standard leap years (divisible by 4, not 100)
        sub.assert_true(wing::is_leap_year(2024));
        sub.assert_true(wing::is_leap_year(2028));
        sub.assert_true(wing::is_leap_year(1996));
        sub.assert_true(wing::is_leap_year(1984));

        // Standard non-leap years
        sub.assert_false(wing::is_leap_year(2025));
        sub.assert_false(wing::is_leap_year(2023));
        sub.assert_false(wing::is_leap_year(2021));

        // Century non-leap years (divisible by 100, not 400)
        sub.assert_false(wing::is_leap_year(1900));
        sub.assert_false(wing::is_leap_year(2100));
        sub.assert_false(wing::is_leap_year(1800));
        sub.assert_false(wing::is_leap_year(1700));

        // Century leap years (divisible by 400)
        sub.assert_true(wing::is_leap_year(2000));
        sub.assert_true(wing::is_leap_year(2400));
        sub.assert_true(wing::is_leap_year(1600));
    };

    t.run("Days in Month Calendar Matrix") { sub =>
        // 31-day months
        sub.assert_eq(wing::days_in_month(2026, 1), 31);
        sub.assert_eq(wing::days_in_month(2026, 3), 31);
        sub.assert_eq(wing::days_in_month(2026, 5), 31);
        sub.assert_eq(wing::days_in_month(2026, 7), 31);
        sub.assert_eq(wing::days_in_month(2026, 8), 31);
        sub.assert_eq(wing::days_in_month(2026, 10), 31);
        sub.assert_eq(wing::days_in_month(2026, 12), 31);

        // 30-day months
        sub.assert_eq(wing::days_in_month(2026, 4), 30);
        sub.assert_eq(wing::days_in_month(2026, 6), 30);
        sub.assert_eq(wing::days_in_month(2026, 9), 30);
        sub.assert_eq(wing::days_in_month(2026, 11), 30);

        // February leap vs non-leap
        sub.assert_eq(wing::days_in_month(2025, 2), 28);
        sub.assert_eq(wing::days_in_month(2024, 2), 29);
        sub.assert_eq(wing::days_in_month(2000, 2), 29);
        sub.assert_eq(wing::days_in_month(1900, 2), 28);
        sub.assert_eq(wing::days_in_month(2100, 2), 28);

        // Out of range month
        sub.assert_eq(wing::days_in_month(2026, 0), 0);
        sub.assert_eq(wing::days_in_month(2026, 13), 0);
    };

    t.run("Howard Hinnant Days<->Civil Bijection Round-Trip") { sub =>
        // 1970-01-01 is day 0 of Unix epoch
        let y0, m0, d0 = wing::days_to_civil(0);
        sub.assert_eq(y0, 1970);
        sub.assert_eq(m0, 1);
        sub.assert_eq(d0, 1);
        sub.assert_eq(wing::civil_to_days(1970, 1, 1), 0);

        // 1969-12-31 is day -1
        let ym1, mm1, dm1 = wing::days_to_civil(-1);
        sub.assert_eq(ym1, 1969);
        sub.assert_eq(mm1, 12);
        sub.assert_eq(dm1, 31);
        sub.assert_eq(wing::civil_to_days(1969, 12, 31), -1);

        // 2000-02-29 (leap day in century leap year)
        let days_2000 = wing::civil_to_days(2000, 2, 29);
        let y_l, m_l, d_l = wing::days_to_civil(days_2000);
        sub.assert_eq(y_l, 2000);
        sub.assert_eq(m_l, 2);
        sub.assert_eq(d_l, 29);

        // 2026-10-23
        let days_2026 = wing::civil_to_days(2026, 10, 23);
        let y_26, m_26, d_26 = wing::days_to_civil(days_2026);
        sub.assert_eq(y_26, 2026);
        sub.assert_eq(m_26, 10);
        sub.assert_eq(d_26, 23);
    };
}

// ----------------------------------------------------------------------------
// 6. Time Construction, Accessors, Projections & Pre-1970 Dates
// ----------------------------------------------------------------------------
fn test_time_construction_and_pre1970(t: wing::T&) {
    t.run("Instant Creation & Field Decomposition") { sub =>
        let tm = wing::date(2026, wing::Month.October, 23, 14, 30, 45, 123456789, 0);
        sub.assert_eq(tm.year(), 2026);
        sub.assert_eq(tm.month_number(), 10);
        sub.assert_eq(tm.day(), 23);
        sub.assert_eq(tm.weekday(), wing::Weekday.Friday);
        sub.assert_eq(tm.hour(), 14);
        sub.assert_eq(tm.minute(), 30);
        sub.assert_eq(tm.second(), 45);
        sub.assert_eq(tm.nanosecond(), 123456789);
    };

    t.run("Pre-1970 Negative Unix Timestamps") { sub =>
        // 1969-12-31 23:59:59 UTC is Unix(-1)
        let tm_pre = wing::unix(-1, 0);
        sub.assert_eq(tm_pre.year(), 1969);
        sub.assert_eq(tm_pre.month_number(), 12);
        sub.assert_eq(tm_pre.day(), 31);
        sub.assert_eq(tm_pre.hour(), 23);
        sub.assert_eq(tm_pre.minute(), 59);
        sub.assert_eq(tm_pre.second(), 59);
        sub.assert_eq(tm_pre.weekday(), wing::Weekday.Wednesday);

        // Normalization of negative fractional nanoseconds
        let tm_norm = wing::unix(100, -250000000);
        sub.assert_eq(tm_norm.unix(), 99, "negative nanos must decrement sec");
        sub.assert_eq(tm_norm.nanosecond(), 750000000, "nanos must be normalized in [0, 999_999_999]");

        // min_i64 nanoseconds normalization (must stay in the past, never wrap to future)
        let min_i64_nanos = -9223372036854775807 - 1;
        let tm_min_ns = wing::unix(0, min_i64_nanos);
        sub.assert_lt(tm_min_ns.unix(), 0, "unix(0, min_i64) must be in the past");
        sub.assert_eq(tm_min_ns.unix(), -9223372037);
        sub.assert_eq(tm_min_ns.nanosecond(), 145224192);
    };

    t.run("Calendar Boundary Projections") { sub =>
        let tm = wing::date(2026, wing::Month.October, 23, 15, 45, 30, 500, 0);

        let sod = tm.start_of_day();
        sub.assert_eq(sod.hour(), 0);
        sub.assert_eq(sod.minute(), 0);
        sub.assert_eq(sod.second(), 0);
        sub.assert_eq(sod.nanosecond(), 0);

        let eod = tm.end_of_day();
        sub.assert_eq(eod.hour(), 23);
        sub.assert_eq(eod.minute(), 59);
        sub.assert_eq(eod.second(), 59);
        sub.assert_eq(eod.nanosecond(), 999999999);

        let som = tm.start_of_month();
        sub.assert_eq(som.day(), 1);
        sub.assert_eq(som.hour(), 0);

        let eom = tm.end_of_month();
        sub.assert_eq(eom.day(), 31);
        sub.assert_eq(eom.hour(), 23);

        let soy = tm.start_of_year();
        sub.assert_eq(soy.month_number(), 1);
        sub.assert_eq(soy.day(), 1);

        let eoy = tm.end_of_year();
        sub.assert_eq(eoy.month_number(), 12);
        sub.assert_eq(eoy.day(), 31);
    };
}

// ----------------------------------------------------------------------------
// 7. Time Arithmetic, Comparisons & ReDoS / DoS Immunity
// ----------------------------------------------------------------------------
fn test_time_arithmetic_and_redos_immunity(t: wing::T&) {
    t.run("Point-in-Time Subtraction & Comparisons") { sub =>
        let t1 = wing::unix(1000, 500);
        let t2 = wing::unix(1005, 500);
        let t3 = wing::unix(1000, 800);

        let diff = t2.sub(t1);
        sub.assert_eq(diff.as_secs(), 5);

        sub.assert_true(t1.before(t2));
        sub.assert_true(t2.after(t1));
        sub.assert_false(t1.equal(t2));
        sub.assert_true(t1.equal(t1));

        // Sub-second comparison
        sub.assert_true(t1.before(t3));
        sub.assert_true(t3.after(t1));
        sub.assert_eq(t1.compare(t3), -1);
        sub.assert_eq(t3.compare(t1), 1);

        // Subtraction with i64.min Duration must not crash or negate
        let t_min_sub = t1.sub(wing::Duration { nanos: -9223372036854775807 - 1 });
        sub.assert_gt(t_min_sub.unix(), t1.unix(), "subtracting negative i64.min duration must advance time forward");

        // Saturated subtraction across > 292 years (industry benchmark)
        let t_future = wing::date(2500, wing::Month.January, 1, 0, 0, 0, 0, 0);
        let t_epoch = wing::unix(0, 0);
        let diff_huge = t_future.sub(t_epoch);
        sub.assert_eq(diff_huge.as_nanos(), 9223372036854775807, "difference > 292 years must saturate to max_i64");

        let diff_neg_huge = t_epoch.sub(t_future);
        let min_i64_val = -9223372036854775807 - 1;
        sub.assert_eq(diff_neg_huge.as_nanos(), min_i64_val, "negative difference > 292 years must saturate to min_i64");
    };

    t.run("Clamped Month & Year Arithmetic") { sub =>
        // Non-leap year: Jan 31 + 1 month -> Feb 28
        let jan31_25 = wing::date(2025, wing::Month.January, 31, 12, 0, 0, 0, 0);
        let feb28_25 = jan31_25.add_months_clamped(1);
        sub.assert_eq(feb28_25.year(), 2025);
        sub.assert_eq(feb28_25.month_number(), 2);
        sub.assert_eq(feb28_25.day(), 28);

        // Leap year: Jan 31 + 1 month -> Feb 29
        let jan31_24 = wing::date(2024, wing::Month.January, 31, 12, 0, 0, 0, 0);
        let feb29_24 = jan31_24.add_months_clamped(1);
        sub.assert_eq(feb29_24.year(), 2024);
        sub.assert_eq(feb29_24.month_number(), 2);
        sub.assert_eq(feb29_24.day(), 29);

        // Leap day + 1 year -> Feb 28
        let feb29_leap = wing::date(2024, wing::Month.February, 29, 12, 0, 0, 0, 0);
        let next_yr = feb29_leap.add_years_clamped(1);
        sub.assert_eq(next_yr.year(), 2025);
        sub.assert_eq(next_yr.month_number(), 2);
        sub.assert_eq(next_yr.day(), 28);

        // Backward subtraction: March 31 - 1 month -> Feb 28
        let mar31_25 = wing::date(2025, wing::Month.March, 31, 12, 0, 0, 0, 0);
        let prev_feb = mar31_25.add_months_clamped(-1);
        sub.assert_eq(prev_feb.year(), 2025);
        sub.assert_eq(prev_feb.month_number(), 2);
        sub.assert_eq(prev_feb.day(), 28);
    };

    t.run("CRITICAL: ReDoS & CPU-Hang Immunity in add_months_clamped") { sub =>
        let base = wing::date(2026, wing::Month.January, 15, 12, 0, 0, 0, 0);

        // Massive positive addition: previously a while loop would execute 100 billion iterations!
        let sw = wing::stopwatch();
        let huge_future = base.add_months_clamped(1200000000); // 100 million years
        let dur_elapsed = sw.elapsed();
        sub.assert_lt(dur_elapsed.as_millis(), 10, "add_months_clamped with 1.2 billion months must complete in O(1) time");
        sub.assert_eq(huge_future.year(), 2026 + 100000000);
        sub.assert_eq(huge_future.month_number(), 1);

        // Massive negative subtraction: must also complete in O(1) time
        let sw_neg = wing::stopwatch();
        let huge_past = base.add_months_clamped(-1200000000);
        let dur_neg_elapsed = sw_neg.elapsed();
        sub.assert_lt(dur_neg_elapsed.as_millis(), 10, "add_months_clamped with -1.2 billion months must complete in O(1) time");
        sub.assert_eq(huge_past.year(), 2026 - 100000000);
        sub.assert_eq(huge_past.month_number(), 1);
    };
}

// ----------------------------------------------------------------------------
// 8. Time Truncation, Rounding & Timezones
// ----------------------------------------------------------------------------
fn test_time_truncation_rounding_and_timezones(t: wing::T&) {
    t.run("Time Truncate & Round Half-Up") { sub =>
        let tm = wing::date(2026, wing::Month.October, 23, 14, 25, 45, 0, 0);

        let trunc_h = tm.truncate(wing::hours(1));
        sub.assert_eq(trunc_h.hour(), 14);
        sub.assert_eq(trunc_h.minute(), 0);

        let round_down = tm.round(wing::hours(1));
        sub.assert_eq(round_down.hour(), 14);
        sub.assert_eq(round_down.minute(), 0);

        let tm_half = wing::date(2026, wing::Month.October, 23, 14, 30, 0, 0, 0);
        let round_half = tm_half.round(wing::hours(1));
        sub.assert_eq(round_half.hour(), 15, "half-hour rounds up to next hour");

        // Negative timestamp rounding (pre-1970) must not crash
        let tm_pre = wing::unix(-3600, 0);
        let round_pre = tm_pre.round(wing::mins(15));
        sub.assert_eq(round_pre.unix(), -3600);

        // Post-2262 date truncation without nanosecond overflow
        let t_2500 = wing::date(2500, wing::Month.January, 1, 14, 25, 45, 0, 0);
        let t_2500_trunc = t_2500.truncate(wing::hours(1));
        sub.assert_eq(t_2500_trunc.year(), 2500, "year must remain 2500");
        sub.assert_eq(t_2500_trunc.hour(), 14);
        sub.assert_eq(t_2500_trunc.minute(), 0);
    };

    t.run("Timezone Offsets & in_tz Minute Handling") { sub =>
        let utc_instant = wing::date(2026, wing::Month.October, 23, 12, 0, 0, 0, 0);

        // Moscow UTC+3
        let msk = utc_instant.in_tz(3, 0);
        sub.assert_eq(msk.tz_offset, 10800);
        sub.assert_eq(msk.hour(), 15, "12:00 UTC -> 15:00 UTC+3");

        // New York UTC-5
        let nyc = utc_instant.in_tz(-5, 0);
        sub.assert_eq(nyc.tz_offset, -18000);
        sub.assert_eq(nyc.hour(), 7, "12:00 UTC -> 07:00 UTC-5");

        // St. John's UTC-3:30 (handles both positive and negative minute argument)
        let nfl1 = utc_instant.in_tz(-3, 30);
        sub.assert_eq(nfl1.tz_offset, -12600);
        let nfl2 = utc_instant.in_tz(-3, -30);
        sub.assert_eq(nfl2.tz_offset, -12600);

        // Lord Howe Island UTC+10:30
        let lhi = utc_instant.in_tz(10, 30);
        sub.assert_eq(lhi.tz_offset, 37800);

        // Negative minutes with 0 hours (e.g. UTC-0:30)
        let half_neg = utc_instant.in_tz(0, -30);
        sub.assert_eq(half_neg.tz_offset, -1800);
    };
}

// ----------------------------------------------------------------------------
// 9. RFC 3339 / ISO 8601 Codec & Attack Vectors
// ----------------------------------------------------------------------------
fn test_rfc3339_codec_and_attack_vectors(t: wing::T&) {
    t.run("RFC 3339 Formatting (UTC, Offset, Nano, Extreme Offset)") { sub =>
        var buf: u8[..64] = [];
        let tm = wing::date(2026, wing::Month.October, 23, 14, 30, 45, 500000000, 0);

        buf.clear(); wing::format_rfc3339(buf, tm);
        sub.assert_bytes_eq(buf[..], "2026-10-23T14:30:45Z");

        buf.clear(); wing::format_rfc3339_nano(buf, tm);
        sub.assert_bytes_eq(buf[..], "2026-10-23T14:30:45.5Z");

        let tm_offset = tm.in_offset(10800);
        buf.clear(); wing::format_rfc3339(buf, tm_offset);
        sub.assert_bytes_eq(buf[..], "2026-10-23T17:30:45+03:00");

        let tm_neg_offset = tm.in_offset(-18000);
        buf.clear(); wing::format_rfc3339(buf, tm_neg_offset);
        sub.assert_bytes_eq(buf[..], "2026-10-23T09:30:45-05:00");

        // i32.min offset (-2147483648) widening must not crash
        let tm_min_tz = tm.in_offset(-2147483648);
        buf.clear(); wing::format_rfc3339(buf, tm_min_tz);
        sub.assert_contains(buf[..], "-");
    };

    t.run("Valid RFC 3339 Parsing Matrix") { sub =>
        let valid_cases = [
            "2026-10-23T14:30:45Z",
            "2026-10-23t14:30:45z",
            "2026-10-23 14:30:45Z",
            "2026-10-23T14:30:45+03:00",
            "2026-10-23T14:30:45-05:00",
            "2026-10-23T14:30:45+0300",
            "2026-10-23T14:30:45+03",
            "2026-10-23T14:30:45.5Z",
            "2026-10-23T14:30:45.123456789Z",
            "2016-12-31T23:59:60Z", // Leap second 60 is permitted in RFC 3339
            "2024-02-29T12:00:00Z", // Leap day 2024
            "2000-02-29T12:00:00Z", // Century leap day 2000
        ];

        for i in valid_cases.len {
            let parsed, ok = wing::parse_rfc3339(valid_cases[i]);
            sub.assert_true(ok, valid_cases[i]);
            sub.assert_gt(parsed.year(), 1999);
        }
    };

    t.run("RFC 3339 Security & Attack Vectors (All Must Be Rejected)") { sub =>
        let attack_vectors = [
            // Calendar Bound Bypasses (Must NOT overflow into next month)
            StringVector { input: "2025-02-29T12:00:00Z", expect_ok: false, desc: "Feb 29 on non-leap year 2025" },
            StringVector { input: "2024-02-30T12:00:00Z", expect_ok: false, desc: "Feb 30 on leap year" },
            StringVector { input: "2026-04-31T12:00:00Z", expect_ok: false, desc: "April 31 (Apr has 30 days)" },
            StringVector { input: "2026-06-31T12:00:00Z", expect_ok: false, desc: "June 31 (Jun has 30 days)" },
            StringVector { input: "2026-09-31T12:00:00Z", expect_ok: false, desc: "September 31 (Sep has 30 days)" },
            StringVector { input: "2026-11-31T12:00:00Z", expect_ok: false, desc: "November 31 (Nov has 30 days)" },
            StringVector { input: "2026-00-10T12:00:00Z", expect_ok: false, desc: "Month 0" },
            StringVector { input: "2026-13-10T12:00:00Z", expect_ok: false, desc: "Month 13" },
            StringVector { input: "2026-10-00T12:00:00Z", expect_ok: false, desc: "Day 0" },
            StringVector { input: "2026-10-32T12:00:00Z", expect_ok: false, desc: "Day 32" },

            // Time Range Out of Bounds
            StringVector { input: "2026-10-22T24:00:00Z", expect_ok: false, desc: "Hour 24" },
            StringVector { input: "2026-10-22T23:60:00Z", expect_ok: false, desc: "Minute 60" },
            StringVector { input: "2026-10-22T23:59:61Z", expect_ok: false, desc: "Second 61" },

            // Sign Injections (Exploiting parse_int with leading + or -)
            StringVector { input: "+202-10-22T23:18:18Z", expect_ok: false, desc: "Sign in year" },
            StringVector { input: "-202-10-22T23:18:18Z", expect_ok: false, desc: "Negative year" },
            StringVector { input: "2026-+1-22T23:18:18Z", expect_ok: false, desc: "Plus sign in month" },
            StringVector { input: "2026-10-+5T23:18:18Z", expect_ok: false, desc: "Plus sign in day" },
            StringVector { input: "2026-10-22T+1:00:00Z", expect_ok: false, desc: "Plus sign in hour" },
            StringVector { input: "2026-10-22T-0:00:00Z", expect_ok: false, desc: "Minus sign in hour" },
            StringVector { input: "2026-10-22T12:-5:00Z", expect_ok: false, desc: "Minus sign in minute" },

            // Timezone Injections & Malformed Offsets
            StringVector { input: "2026-10-22T23:18:18", expect_ok: false, desc: "Missing timezone offset" },
            StringVector { input: "2026-10-22T23:18:18Z_INJECTION", expect_ok: false, desc: "Trailing garbage after Z" },
            StringVector { input: "2026-10-22T23:18:18+03:00_EXTRA", expect_ok: false, desc: "Trailing garbage after offset" },
            StringVector { input: "2026-10-22T23:18:18+24:00", expect_ok: false, desc: "Offset hour 24" },
            StringVector { input: "2026-10-22T23:18:18+03:60", expect_ok: false, desc: "Offset minute 60" },
            StringVector { input: "2026-10-22T23:18:18+03:", expect_ok: false, desc: "Truncated offset colon" },
            StringVector { input: "2026-10-22T23:18:18+03:5", expect_ok: false, desc: "Single digit offset minute" },
            StringVector { input: "2026-10-22T23:18:18+03:XX", expect_ok: false, desc: "Alpha characters in offset" },
            StringVector { input: "2026-10-22T23:18:18+-3:00", expect_ok: false, desc: "Sign in offset hour" },

            // Malformed Fractional Seconds
            StringVector { input: "2026-10-22T23:18:18.Z", expect_ok: false, desc: "Empty fraction dot before Z" },
            StringVector { input: "2026-10-22T23:18:18.", expect_ok: false, desc: "Trailing dot without digits" },
            StringVector { input: "2026-10-22T23:18:18.+03:00", expect_ok: false, desc: "Empty fraction dot before offset" },
        ];

        wing::run_table(sub, "RFC3339AttackMatrix", attack_vectors[..]) { sub2, row, idx =>
            let _, ok = wing::parse_rfc3339(row.input);
            sub2.assert_eq(ok, row.expect_ok, row.desc);
        };
    };
}

// ----------------------------------------------------------------------------
// 10. RFC 9110 Section 5.6.7 HTTP-Date Formatting & 3-Format Parser Security
// ----------------------------------------------------------------------------
fn test_http_date_rfc9110_and_attack_vectors(t: wing::T&) {
    t.run("HTTP-Date Format Always in GMT") { sub =>
        let local_tm = wing::date(2026, wing::Month.October, 22, 23, 18, 18, 0, 10800); // 23:18:18 MSK = 20:18:18 GMT
        var buf: u8[..64] = [];
        wing::format_http(buf, local_tm);
        sub.assert_bytes_eq(buf[..], "Thu, 22 Oct 2026 20:18:18 GMT", "format_http must convert local time to GMT");
    };

    t.run("Valid 3-Format HTTP-Date Parsing (IMF-fixdate, RFC 850, asctime)") { sub =>
        let imf_str = "Thu, 22 Oct 2026 23:18:18 GMT";
        let r850_str = "Thursday, 22-Oct-26 23:18:18 GMT";
        let asctime_str = "Thu Oct 22 23:18:18 2026";

        let t_imf, ok1 = wing::parse_http_date(imf_str);
        sub.require_true(ok1);
        let t_850, ok2 = wing::parse_http_date(r850_str);
        sub.require_true(ok2);
        let t_asc, ok3 = wing::parse_http_date(asctime_str);
        sub.require_true(ok3);

        sub.assert_eq(t_imf.unix(), t_850.unix());
        sub.assert_eq(t_imf.unix(), t_asc.unix());

        // asctime with space-padded day
        let t_pad, ok_pad = wing::parse_http_date("Sun Nov  6 08:49:37 1994");
        sub.require_true(ok_pad);
        sub.assert_eq(t_pad.day(), 6);
        sub.assert_eq(t_pad.year(), 1994);
    };

    t.run("HTTP-Date Attack Vectors & Syntax Bypass Rejection") { sub =>
        let bad_http_vectors = [
            // Non-GMT Timezone Trailers (RFC 9110 Section 5.6.7 mandates GMT only)
            StringVector { input: "Thu, 22 Oct 2026 23:18:18 UTC", expect_ok: false, desc: "UTC trailer rejected" },
            StringVector { input: "Thu, 22 Oct 2026 23:18:18 PST", expect_ok: false, desc: "PST trailer rejected" },
            StringVector { input: "Thu, 22 Oct 2026 23:18:18 +0000", expect_ok: false, desc: "Numeric offset rejected" },
            StringVector { input: "Thu, 22 Oct 2026 23:18:18", expect_ok: false, desc: "Missing timezone trailer" },
            StringVector { input: "Thursday, 22-Oct-26 23:18:18", expect_ok: false, desc: "Missing GMT in RFC 850" },

            // Trailing Garbage Injections
            StringVector { input: "Thu, 22 Oct 2026 23:18:18 GMT_EVIL", expect_ok: false, desc: "Trailing garbage after GMT" },
            StringVector { input: "Thu Oct 22 23:18:18 2026 EXTRA", expect_ok: false, desc: "Trailing garbage after asctime year" },

            // Invalid Weekday Tokens
            StringVector { input: "XXX, 22 Oct 2026 23:18:18 GMT", expect_ok: false, desc: "Bogus weekday abbreviation" },
            StringVector { input: "Evil, 22-Oct-26 23:18:18 GMT", expect_ok: false, desc: "Bogus weekday name in RFC 850" },
            StringVector { input: "Bad Oct 22 23:18:18 2026", expect_ok: false, desc: "Bogus weekday in asctime" },

            // Invalid Month Tokens
            StringVector { input: "Thu, 22 Foo 2026 23:18:18 GMT", expect_ok: false, desc: "Bogus month name" },
            StringVector { input: "Thursday, 22-Bar-26 23:18:18 GMT", expect_ok: false, desc: "Bogus month in RFC 850" },
            StringVector { input: "Thu Baz 22 23:18:18 2026", expect_ok: false, desc: "Bogus month in asctime" },

            // Negative Numbers & Sign Injection
            StringVector { input: "Thu, 22 Oct 2026 -5:00:00 GMT", expect_ok: false, desc: "Negative hour in IMF-fixdate" },
            StringVector { input: "Thu, 22 Oct 2026 12:-9:00 GMT", expect_ok: false, desc: "Negative minute in IMF-fixdate" },
            StringVector { input: "Thu, 22 Oct 2026 12:00:-1 GMT", expect_ok: false, desc: "Negative second in IMF-fixdate" },
            StringVector { input: "Thu, +2 Oct 2026 12:00:00 GMT", expect_ok: false, desc: "Plus sign in day" },
            StringVector { input: "Thu Oct +2 23:18:18 2026", expect_ok: false, desc: "Plus sign in asctime day" },

            // Calendar Bounds Bypasses
            StringVector { input: "Thu, 29 Feb 2025 12:00:00 GMT", expect_ok: false, desc: "Feb 29 on non-leap year in HTTP date" },
            StringVector { input: "Thu, 31 Apr 2026 12:00:00 GMT", expect_ok: false, desc: "April 31 in HTTP date" },
        ];

        wing::run_table(sub, "BadHttpDateMatrix", bad_http_vectors[..]) { sub2, row, idx =>
            let _, ok = wing::parse_http_date(row.input);
            sub2.assert_eq(ok, row.expect_ok, row.desc);
        };
    };
}

// ----------------------------------------------------------------------------
// Suite Runner
// ----------------------------------------------------------------------------
fn main() {
    var runner = wing::new_runner("Time & Duration Suite", wing::Verbosity.Verbose);

    wing::run_case(runner, "1. Duration Arithmetic, i64.min/max, Signs & Accessors", test_duration_arithmetic_and_bounds);
    wing::run_case(runner, "2. Duration Truncation and Rounding (Boundary & Half-Way)", test_duration_truncation_and_rounding);
    wing::run_case(runner, "3. Duration Format & Go-Compatible ParseDuration Security", test_duration_format_and_parse_security);
    wing::run_case(runner, "4. Monotonic Primitives: Stopwatch & Deadline (Anti-Overflow)", test_stopwatch_and_deadline_overflow);
    wing::run_case(runner, "5. Civil Calendar Math & Proleptic Gregorian Leap Years", test_hinnant_civil_calendar_and_leap_years);
    wing::run_case(runner, "6. Time Construction, Accessors, Projections & Pre-1970", test_time_construction_and_pre1970);
    wing::run_case(runner, "7. Time Arithmetic, Comparisons & ReDoS / DoS Immunity", test_time_arithmetic_and_redos_immunity);
    wing::run_case(runner, "8. Time Truncation, Rounding & Timezones", test_time_truncation_rounding_and_timezones);
    wing::run_case(runner, "9. RFC 3339 / ISO 8601 Codec & Attack Vectors", test_rfc3339_codec_and_attack_vectors);
    wing::run_case(runner, "10. RFC 9110 Section 5.6.7 HTTP-Date Formatting & 3-Format Parser Security", test_http_date_rfc9110_and_attack_vectors);

    let ok = wing::finish(runner);
    assert(ok);
}
