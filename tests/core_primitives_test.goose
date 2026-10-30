// RUN: goose build -o %t.exe %s
// RUN: %t.exe
// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Consolidated Verification Suite: Core Primitives (Time, Math, Sync, Bytes, IO Streams) Suite
import std;
import core from "..";
import lit from "github.com/Lemon4ksan/goose-lit@v0.1.0";
import os;

// --- Component: core_time ---
// Tests for core/time: duration arithmetic, calendar math, and RFC 3339 codecs.

struct StringVector {
    input:     const u8[:],
    expect_ok: bool,
    desc:      const u8[:],
}

// ----------------------------------------------------------------------------
// 1. Duration Arithmetic, i64.min/max, Signs & Accessors
// ----------------------------------------------------------------------------
fn test_duration_arithmetic_and_bounds(t: lit::T&) {
    t.run("Unit Scales & Conversion Accessors") { sub =>
        let d_ns = core::nanos(50);
        let d_us = core::micros(50);
        let d_ms = core::millis(50);
        let d_s = core::secs(50);
        let d_m = core::mins(50);
        let d_h = core::hours(2);
        let d_d = core::days(3);
        let d_w = core::weeks(1);

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

        sub.assert_in_delta(core::millis(1500).as_secs_f64(), 1.5, 0.000001);
        sub.assert_in_delta(core::secs(90).as_mins_f64(), 1.5, 0.000001);
        sub.assert_in_delta(core::mins(90).as_hours_f64(), 1.5, 0.000001);
    };

    t.run("Operator Arithmetic & Mutating Assignments") { sub =>
        let a = core::secs(10);
        let b = core::secs(3);

        sub.assert_eq((a + b).as_secs(), 13);
        sub.assert_eq((a - b).as_secs(), 7);
        sub.assert_eq((a * 4).as_secs(), 40);
        sub.assert_eq((a / 2).as_secs(), 5);
        sub.assert_eq((-a).as_secs(), -10);

        var acc = core::secs(10);
        acc += core::secs(5);
        sub.assert_eq(acc.as_secs(), 15);
        acc -= core::secs(3);
        sub.assert_eq(acc.as_secs(), 12);
        acc *= 2;
        sub.assert_eq(acc.as_secs(), 24);
        acc /= 4;
        sub.assert_eq(acc.as_secs(), 6);
    };

    t.run("Abs, Zero, Positive, Negative & i64.min Boundary") { sub =>
        let pos = core::secs(5);
        let zero_dur = core::nanos(0);
        let neg = core::secs(-5);
        let min_i64_dur = core::Duration { nanos: -9223372036854775807 - 1 };

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
        let d1 = core::secs(5);
        let d2 = core::secs(10);
        let d3 = core::secs(5);

        sub.assert_eq(core::compare(d1, d2), -1);
        sub.assert_eq(core::compare(d2, d1), 1);
        sub.assert_eq(core::compare(d1, d3), 0);
    };
}

// ----------------------------------------------------------------------------
// 2. Duration Truncation and Rounding
// ----------------------------------------------------------------------------
fn test_duration_truncation_and_rounding(t: lit::T&) {
    t.run("Truncation Towards Zero") { sub =>
        // Step <= 0 returns dur unchanged
        sub.assert_eq(core::truncate(core::secs(75), core::secs(0)).as_secs(), 75);
        sub.assert_eq(core::truncate(core::secs(75), core::secs(-1)).as_secs(), 75);

        // Positive truncation
        sub.assert_eq(core::truncate(core::secs(75), core::mins(1)).as_secs(), 60);
        sub.assert_eq(core::truncate(core::secs(59), core::mins(1)).as_secs(), 0);
        sub.assert_eq(core::truncate(core::secs(120), core::mins(1)).as_secs(), 120);

        // Negative truncation (towards zero)
        sub.assert_eq(core::truncate(core::secs(-75), core::mins(1)).as_secs(), -60);
        sub.assert_eq(core::truncate(core::secs(-59), core::mins(1)).as_secs(), 0);

        // i64.min truncation must stay negative (towards zero), never wrap to positive
        let min_dur = core::Duration { nanos: -9223372036854775807 - 1 };
        let trunc_min = core::truncate(min_dur, core::secs(1));
        sub.assert_true(trunc_min.is_negative(), "truncate(min_i64) must remain negative");
        sub.assert_eq(trunc_min.as_nanos(), -9223372036000000000, "truncate(min_i64) rounds toward zero");
    };

    t.run("Rounding Half-Away-From-Zero") { sub =>
        // Step <= 0 returns dur unchanged
        sub.assert_eq(core::round(core::secs(75), core::secs(0)).as_secs(), 75);

        // Positive rounding: 29s -> 0, 30s -> 60s (half rounds away), 31s -> 60s
        sub.assert_eq(core::round(core::secs(29), core::mins(1)).as_secs(), 0);
        sub.assert_eq(core::round(core::secs(30), core::mins(1)).as_secs(), 60);
        sub.assert_eq(core::round(core::secs(31), core::mins(1)).as_secs(), 60);
        sub.assert_eq(core::round(core::secs(89), core::mins(1)).as_secs(), 60);
        sub.assert_eq(core::round(core::secs(90), core::mins(1)).as_secs(), 120);

        // Negative rounding: -29s -> 0, -30s -> -60s (away from zero), -31s -> -60s
        sub.assert_eq(core::round(core::secs(-29), core::mins(1)).as_secs(), 0);
        sub.assert_eq(core::round(core::secs(-30), core::mins(1)).as_secs(), -60);
        sub.assert_eq(core::round(core::secs(-31), core::mins(1)).as_secs(), -60);
        sub.assert_eq(core::round(core::secs(-89), core::mins(1)).as_secs(), -60);
        sub.assert_eq(core::round(core::secs(-90), core::mins(1)).as_secs(), -120);
    };

    t.run("Large Step Duration Overflow Immunity") { sub =>
        // remainder * 2 would overflow if remainder > i64.max / 2
        let half_max = 4611686018427387900;
        let step = core::Duration { nanos: half_max + 100 };
        let dur = core::Duration { nanos: half_max + 50 };
        let rounded = core::round(dur, step);
        sub.assert_eq(rounded.as_nanos(), step.as_nanos(), "rounding with large step must not overflow i64");
    };
}

// ----------------------------------------------------------------------------
// 3. Duration Formatting & Go-Compatible ParseDuration Security
// ----------------------------------------------------------------------------
fn test_duration_format_and_parse_security(t: lit::T&) {
    t.run("Format Duration Zero-Alloc") { sub =>
        var buf: u8[..64] = [];

        buf.clear(); core::format(buf, core::nanos(0));
        sub.assert_bytes_eq(buf[..], "0s");

        buf.clear(); core::format(buf, core::nanos(500));
        sub.assert_bytes_eq(buf[..], "500ns");

        buf.clear(); core::format(buf, core::micros(750));
        sub.assert_bytes_eq(buf[..], "750us");

        buf.clear(); core::format(buf, core::millis(250));
        sub.assert_bytes_eq(buf[..], "250ms");

        buf.clear(); core::format(buf, core::secs(1) + core::millis(500));
        sub.assert_bytes_eq(buf[..], "1.5s");

        buf.clear(); core::format(buf, core::hours(2) + core::mins(45));
        sub.assert_bytes_eq(buf[..], "2h45m");

        buf.clear(); core::format(buf, core::millis(-250));
        sub.assert_bytes_eq(buf[..], "-250ms");

        // i64.min must format cleanly without double minus "--"
        buf.clear(); core::format(buf, core::Duration { nanos: -9223372036854775807 - 1 });
        sub.assert_contains(buf[..], "-2562047h47m16.854775808s");
    };

    t.run("Valid ParseDuration Matrix (Basic, Composite, High-Precision Fraction)") { sub =>
        let d1, ok1 = core::parse_duration("500ms");
        sub.require_true(ok1);
        sub.assert_eq(d1.as_millis(), 500);

        let d2, ok2 = core::parse_duration("1h30m45s");
        sub.require_true(ok2);
        sub.assert_eq(d2.as_secs(), 5445);

        let d3, ok3 = core::parse_duration("-2.5s");
        sub.require_true(ok3);
        sub.assert_in_delta(d3.as_secs_f64(), -2.5, 0.000001);

        let d4, ok4 = core::parse_duration("100ns");
        sub.require_true(ok4);
        sub.assert_eq(d4.as_nanos(), 100);

        let d5, ok5 = core::parse_duration("2w3d4h");
        sub.require_true(ok5);
        sub.assert_eq(d5.as_hours(), 2 * 168 + 3 * 24 + 4);

        // 9-digit fractional nanoseconds in large units (MUST NOT OVERFLOW i64)
        let d6, ok6 = core::parse_duration("0.500000000h");
        sub.require_true(ok6, "0.500000000h must parse without fraction multiplication overflow");
        sub.assert_eq(d6.as_mins(), 30);

        let d7, ok7 = core::parse_duration("0.500000000d");
        sub.require_true(ok7, "0.500000000d must parse without fraction multiplication overflow");
        sub.assert_eq(d7.as_hours(), 12);

        let d8, ok8 = core::parse_duration("0.500000000w");
        sub.require_true(ok8, "0.500000000w must parse without fraction multiplication overflow");
        sub.assert_eq(d8.as_hours(), 84);

        let d9, ok9 = core::parse_duration("+10s");
        sub.require_true(ok9);
        sub.assert_eq(d9.as_secs(), 10);

        // Leading dot shorthand (Go compatibility, e.g. .5s)
        let d_lead, ok_lead = core::parse_duration(".5s");
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

        lit::run_table(sub, "BadDurationMatrix", bad_vectors[..]) { sub2, row, idx =>
            let _, ok = core::parse_duration(row.input);
            sub2.assert_eq(ok, row.expect_ok, row.desc);
        };
    };
}

// ----------------------------------------------------------------------------
// 4. Monotonic Primitives: Stopwatch & Deadline (Anti-Overflow & Expiration)
// ----------------------------------------------------------------------------
fn test_stopwatch_and_deadline_overflow(t: lit::T&) {
    t.run("Stopwatch Monotonic Progress & Restart") { sub =>
        var sw = core::stopwatch();
        core::sleep(core::millis(3));
        let el1 = sw.elapsed();
        sub.assert_ge(el1.as_millis(), 2, "stopwatch elapsed >= 2ms");

        let restarted_el = sw.restart();
        sub.assert_ge(restarted_el.as_millis(), 2, "restart returns previous elapsed");
        let el2 = sw.elapsed();
        sub.assert_lt(el2.as_millis(), restarted_el.as_millis(), "elapsed resets after restart");
    };

    t.run("Deadline Standard Lifecycle") { sub =>
        let dl = core::deadline_after(core::millis(15));
        sub.assert_false(dl.is_expired());
        sub.assert_gt(dl.remaining().as_nanos(), 0);

        core::sleep(core::millis(20));
        sub.assert_true(dl.is_expired());
        sub.assert_eq(dl.remaining().as_nanos(), 0);

        // Non-positive deadline expires immediately
        let dl_zero = core::deadline_after(core::nanos(0));
        sub.assert_true(dl_zero.is_expired());
        let dl_neg = core::deadline_after(core::millis(-5));
        sub.assert_true(dl_neg.is_expired());

        // Unset deadline never expires
        let dl_none = core::Deadline { target_mono_ns: 0, has_deadline: false };
        sub.assert_false(dl_none.is_expired());
        sub.assert_eq(dl_none.remaining().as_nanos(), 9223372036854775807);
    };

    t.run("CRITICAL: Deadline Maximum Duration Anti-Overflow Vulnerability Test") { sub =>
        // If clock_ns() + i64.max overflows to negative, deadline would immediately expire!
        let dl_max = core::deadline_after(core::Duration { nanos: 9223372036854775807 });
        sub.assert_false(dl_max.is_expired(), "deadline with i64.max timeout MUST NOT overflow and expire immediately");
        sub.assert_gt(dl_max.remaining().as_nanos(), 1000000000000);
    };
}

// ----------------------------------------------------------------------------
// 5. Civil Calendar Math & Proleptic Gregorian Leap Years
// ----------------------------------------------------------------------------
fn test_hinnant_civil_calendar_and_leap_years(t: lit::T&) {
    t.run("400-Year Gregorian Leap Year Rules") { sub =>
        // Standard leap years (divisible by 4, not 100)
        sub.assert_true(core::is_leap_year(2024));
        sub.assert_true(core::is_leap_year(2028));
        sub.assert_true(core::is_leap_year(1996));
        sub.assert_true(core::is_leap_year(1984));

        // Standard non-leap years
        sub.assert_false(core::is_leap_year(2025));
        sub.assert_false(core::is_leap_year(2023));
        sub.assert_false(core::is_leap_year(2021));

        // Century non-leap years (divisible by 100, not 400)
        sub.assert_false(core::is_leap_year(1900));
        sub.assert_false(core::is_leap_year(2100));
        sub.assert_false(core::is_leap_year(1800));
        sub.assert_false(core::is_leap_year(1700));

        // Century leap years (divisible by 400)
        sub.assert_true(core::is_leap_year(2000));
        sub.assert_true(core::is_leap_year(2400));
        sub.assert_true(core::is_leap_year(1600));
    };

    t.run("Days in Month Calendar Matrix") { sub =>
        // 31-day months
        sub.assert_eq(core::days_in_month(2026, 1), 31);
        sub.assert_eq(core::days_in_month(2026, 3), 31);
        sub.assert_eq(core::days_in_month(2026, 5), 31);
        sub.assert_eq(core::days_in_month(2026, 7), 31);
        sub.assert_eq(core::days_in_month(2026, 8), 31);
        sub.assert_eq(core::days_in_month(2026, 10), 31);
        sub.assert_eq(core::days_in_month(2026, 12), 31);

        // 30-day months
        sub.assert_eq(core::days_in_month(2026, 4), 30);
        sub.assert_eq(core::days_in_month(2026, 6), 30);
        sub.assert_eq(core::days_in_month(2026, 9), 30);
        sub.assert_eq(core::days_in_month(2026, 11), 30);

        // February leap vs non-leap
        sub.assert_eq(core::days_in_month(2025, 2), 28);
        sub.assert_eq(core::days_in_month(2024, 2), 29);
        sub.assert_eq(core::days_in_month(2000, 2), 29);
        sub.assert_eq(core::days_in_month(1900, 2), 28);
        sub.assert_eq(core::days_in_month(2100, 2), 28);

        // Out of range month
        sub.assert_eq(core::days_in_month(2026, 0), 0);
        sub.assert_eq(core::days_in_month(2026, 13), 0);
    };

    t.run("Howard Hinnant Days<->Civil Bijection Round-Trip") { sub =>
        // 1970-01-01 is day 0 of Unix epoch
        let y0, m0, d0 = core::days_to_civil(0);
        sub.assert_eq(y0, 1970);
        sub.assert_eq(m0, 1);
        sub.assert_eq(d0, 1);
        sub.assert_eq(core::civil_to_days(1970, 1, 1), 0);

        // 1969-12-31 is day -1
        let ym1, mm1, dm1 = core::days_to_civil(-1);
        sub.assert_eq(ym1, 1969);
        sub.assert_eq(mm1, 12);
        sub.assert_eq(dm1, 31);
        sub.assert_eq(core::civil_to_days(1969, 12, 31), -1);

        // 2000-02-29 (leap day in century leap year)
        let days_2000 = core::civil_to_days(2000, 2, 29);
        let y_l, m_l, d_l = core::days_to_civil(days_2000);
        sub.assert_eq(y_l, 2000);
        sub.assert_eq(m_l, 2);
        sub.assert_eq(d_l, 29);

        // 2026-10-23
        let days_2026 = core::civil_to_days(2026, 10, 23);
        let y_26, m_26, d_26 = core::days_to_civil(days_2026);
        sub.assert_eq(y_26, 2026);
        sub.assert_eq(m_26, 10);
        sub.assert_eq(d_26, 23);
    };
}

// ----------------------------------------------------------------------------
// 6. Time Construction, Accessors, Projections & Pre-1970 Dates
// ----------------------------------------------------------------------------
fn test_time_construction_and_pre1970(t: lit::T&) {
    t.run("Instant Creation & Field Decomposition") { sub =>
        let tm = core::date(2026, core::Month.October, 23, 14, 30, 45, 123456789, 0);
        sub.assert_eq(tm.year(), 2026);
        sub.assert_eq(tm.month_number(), 10);
        sub.assert_eq(tm.day(), 23);
        sub.assert_eq(tm.weekday(), core::Weekday.Friday);
        sub.assert_eq(tm.hour(), 14);
        sub.assert_eq(tm.minute(), 30);
        sub.assert_eq(tm.second(), 45);
        sub.assert_eq(tm.nanosecond(), 123456789);
    };

    t.run("Pre-1970 Negative Unix Timestamps") { sub =>
        // 1969-12-31 23:59:59 UTC is Unix(-1)
        let tm_pre = core::unix(-1, 0);
        sub.assert_eq(tm_pre.year(), 1969);
        sub.assert_eq(tm_pre.month_number(), 12);
        sub.assert_eq(tm_pre.day(), 31);
        sub.assert_eq(tm_pre.hour(), 23);
        sub.assert_eq(tm_pre.minute(), 59);
        sub.assert_eq(tm_pre.second(), 59);
        sub.assert_eq(tm_pre.weekday(), core::Weekday.Wednesday);

        // Normalization of negative fractional nanoseconds
        let tm_norm = core::unix(100, -250000000);
        sub.assert_eq(tm_norm.unix(), 99, "negative nanos must decrement sec");
        sub.assert_eq(tm_norm.nanosecond(), 750000000, "nanos must be normalized in [0, 999_999_999]");

        // min_i64 nanoseconds normalization (must stay in the past, never wrap to future)
        let min_i64_nanos = -9223372036854775807 - 1;
        let tm_min_ns = core::unix(0, min_i64_nanos);
        sub.assert_lt(tm_min_ns.unix(), 0, "unix(0, min_i64) must be in the past");
        sub.assert_eq(tm_min_ns.unix(), -9223372037);
        sub.assert_eq(tm_min_ns.nanosecond(), 145224192);
    };

    t.run("Calendar Boundary Projections") { sub =>
        let tm = core::date(2026, core::Month.October, 23, 15, 45, 30, 500, 0);

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
fn test_time_arithmetic_and_redos_immunity(t: lit::T&) {
    t.run("Point-in-Time Subtraction & Comparisons") { sub =>
        let t1 = core::unix(1000, 500);
        let t2 = core::unix(1005, 500);
        let t3 = core::unix(1000, 800);

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
        let t_min_sub = t1.sub(core::Duration { nanos: -9223372036854775807 - 1 });
        sub.assert_gt(t_min_sub.unix(), t1.unix(), "subtracting negative i64.min duration must advance time forward");

        // Saturated subtraction across > 292 years (industry benchmark)
        let t_future = core::date(2500, core::Month.January, 1, 0, 0, 0, 0, 0);
        let t_epoch = core::unix(0, 0);
        let diff_huge = t_future.sub(t_epoch);
        sub.assert_eq(diff_huge.as_nanos(), 9223372036854775807, "difference > 292 years must saturate to max_i64");

        let diff_neg_huge = t_epoch.sub(t_future);
        let min_i64_val = -9223372036854775807 - 1;
        sub.assert_eq(diff_neg_huge.as_nanos(), min_i64_val, "negative difference > 292 years must saturate to min_i64");
    };

    t.run("Clamped Month & Year Arithmetic") { sub =>
        // Non-leap year: Jan 31 + 1 month -> Feb 28
        let jan31_25 = core::date(2025, core::Month.January, 31, 12, 0, 0, 0, 0);
        let feb28_25 = jan31_25.add_months_clamped(1);
        sub.assert_eq(feb28_25.year(), 2025);
        sub.assert_eq(feb28_25.month_number(), 2);
        sub.assert_eq(feb28_25.day(), 28);

        // Leap year: Jan 31 + 1 month -> Feb 29
        let jan31_24 = core::date(2024, core::Month.January, 31, 12, 0, 0, 0, 0);
        let feb29_24 = jan31_24.add_months_clamped(1);
        sub.assert_eq(feb29_24.year(), 2024);
        sub.assert_eq(feb29_24.month_number(), 2);
        sub.assert_eq(feb29_24.day(), 29);

        // Leap day + 1 year -> Feb 28
        let feb29_leap = core::date(2024, core::Month.February, 29, 12, 0, 0, 0, 0);
        let next_yr = feb29_leap.add_years_clamped(1);
        sub.assert_eq(next_yr.year(), 2025);
        sub.assert_eq(next_yr.month_number(), 2);
        sub.assert_eq(next_yr.day(), 28);

        // Backward subtraction: March 31 - 1 month -> Feb 28
        let mar31_25 = core::date(2025, core::Month.March, 31, 12, 0, 0, 0, 0);
        let prev_feb = mar31_25.add_months_clamped(-1);
        sub.assert_eq(prev_feb.year(), 2025);
        sub.assert_eq(prev_feb.month_number(), 2);
        sub.assert_eq(prev_feb.day(), 28);
    };

    t.run("CRITICAL: ReDoS & CPU-Hang Immunity in add_months_clamped") { sub =>
        let base = core::date(2026, core::Month.January, 15, 12, 0, 0, 0, 0);

        // Massive positive addition: previously a while loop would execute 100 billion iterations!
        let sw = core::stopwatch();
        let huge_future = base.add_months_clamped(1200000000); // 100 million years
        let dur_elapsed = sw.elapsed();
        sub.assert_lt(dur_elapsed.as_millis(), 10, "add_months_clamped with 1.2 billion months must complete in O(1) time");
        sub.assert_eq(huge_future.year(), 2026 + 100000000);
        sub.assert_eq(huge_future.month_number(), 1);

        // Massive negative subtraction: must also complete in O(1) time
        let sw_neg = core::stopwatch();
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
fn test_time_truncation_rounding_and_timezones(t: lit::T&) {
    t.run("Time Truncate & Round Half-Up") { sub =>
        let tm = core::date(2026, core::Month.October, 23, 14, 25, 45, 0, 0);

        let trunc_h = tm.truncate(core::hours(1));
        sub.assert_eq(trunc_h.hour(), 14);
        sub.assert_eq(trunc_h.minute(), 0);

        let round_down = tm.round(core::hours(1));
        sub.assert_eq(round_down.hour(), 14);
        sub.assert_eq(round_down.minute(), 0);

        let tm_half = core::date(2026, core::Month.October, 23, 14, 30, 0, 0, 0);
        let round_half = tm_half.round(core::hours(1));
        sub.assert_eq(round_half.hour(), 15, "half-hour rounds up to next hour");

        // Negative timestamp rounding (pre-1970) must not crash
        let tm_pre = core::unix(-3600, 0);
        let round_pre = tm_pre.round(core::mins(15));
        sub.assert_eq(round_pre.unix(), -3600);

        // Post-2262 date truncation without nanosecond overflow
        let t_2500 = core::date(2500, core::Month.January, 1, 14, 25, 45, 0, 0);
        let t_2500_trunc = t_2500.truncate(core::hours(1));
        sub.assert_eq(t_2500_trunc.year(), 2500, "year must remain 2500");
        sub.assert_eq(t_2500_trunc.hour(), 14);
        sub.assert_eq(t_2500_trunc.minute(), 0);
    };

    t.run("Timezone Offsets & in_tz Minute Handling") { sub =>
        let utc_instant = core::date(2026, core::Month.October, 23, 12, 0, 0, 0, 0);

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
fn test_rfc3339_codec_and_attack_vectors(t: lit::T&) {
    t.run("RFC 3339 Formatting (UTC, Offset, Nano, Extreme Offset)") { sub =>
        var buf: u8[..64] = [];
        let tm = core::date(2026, core::Month.October, 23, 14, 30, 45, 500000000, 0);

        buf.clear(); core::format_rfc3339(buf, tm);
        sub.assert_bytes_eq(buf[..], "2026-10-23T14:30:45Z");

        buf.clear(); core::format_rfc3339_nano(buf, tm);
        sub.assert_bytes_eq(buf[..], "2026-10-23T14:30:45.5Z");

        let tm_offset = tm.in_offset(10800);
        buf.clear(); core::format_rfc3339(buf, tm_offset);
        sub.assert_bytes_eq(buf[..], "2026-10-23T17:30:45+03:00");

        let tm_neg_offset = tm.in_offset(-18000);
        buf.clear(); core::format_rfc3339(buf, tm_neg_offset);
        sub.assert_bytes_eq(buf[..], "2026-10-23T09:30:45-05:00");

        // i32.min offset (-2147483648) widening must not crash
        let tm_min_tz = tm.in_offset(-2147483648);
        buf.clear(); core::format_rfc3339(buf, tm_min_tz);
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
            let parsed, ok = core::parse_rfc3339(valid_cases[i]);
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

        lit::run_table(sub, "RFC3339AttackMatrix", attack_vectors[..]) { sub2, row, idx =>
            let _, ok = core::parse_rfc3339(row.input);
            sub2.assert_eq(ok, row.expect_ok, row.desc);
        };
    };
}

// ----------------------------------------------------------------------------
// 10. RFC 9110 Section 5.6.7 HTTP-Date Formatting & 3-Format Parser Security
// ----------------------------------------------------------------------------
fn test_http_date_rfc9110_and_attack_vectors(t: lit::T&) {
    t.run("HTTP-Date Format Always in GMT") { sub =>
        let local_tm = core::date(2026, core::Month.October, 22, 23, 18, 18, 0, 10800); // 23:18:18 MSK = 20:18:18 GMT
        var buf: u8[..64] = [];
        core::format_http(buf, local_tm);
        sub.assert_bytes_eq(buf[..], "Thu, 22 Oct 2026 20:18:18 GMT", "format_http must convert local time to GMT");
    };

    t.run("Valid 3-Format HTTP-Date Parsing (IMF-fixdate, RFC 850, asctime)") { sub =>
        let imf_str = "Thu, 22 Oct 2026 23:18:18 GMT";
        let r850_str = "Thursday, 22-Oct-26 23:18:18 GMT";
        let asctime_str = "Thu Oct 22 23:18:18 2026";

        let t_imf, ok1 = core::parse_http_date(imf_str);
        sub.require_true(ok1);
        let t_850, ok2 = core::parse_http_date(r850_str);
        sub.require_true(ok2);
        let t_asc, ok3 = core::parse_http_date(asctime_str);
        sub.require_true(ok3);

        sub.assert_eq(t_imf.unix(), t_850.unix());
        sub.assert_eq(t_imf.unix(), t_asc.unix());

        // asctime with space-padded day
        let t_pad, ok_pad = core::parse_http_date("Sun Nov  6 08:49:37 1994");
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

        lit::run_table(sub, "BadHttpDateMatrix", bad_http_vectors[..]) { sub2, row, idx =>
            let _, ok = core::parse_http_date(row.input);
            sub2.assert_eq(ok, row.expect_ok, row.desc);
        };
    };
}

// ----------------------------------------------------------------------------
// Suite Runner
// ----------------------------------------------------------------------------

// --- Component: core_math ---
// Verification and conformance test suite for core/math.goose (std.math).
// Tests branchless constant-time arithmetic, saturation logic, Euclidean division,
// 128-bit multiplication without u128, WyRand v4.2, Lemire fast-range,
// Jacobson EWMA RTT (RFC 6298 / RFC 9002 Errata ID 7539),
// non-cryptographic hashes (FNV-1a, xxHash32, wyhash64), and SOCKS5 CT frame validation.

// ----------------------------------------------------------------------------
// 1. Branchless Constant-Time Arithmetic & Selection
// ----------------------------------------------------------------------------
fn test_branchless_constant_time(t: lit::T&) {
    t.run("ct_is_zero_u32 and ct_is_zero_u64") { sub =>
        sub.assert_eq(core::ct_is_zero_u32(0), 1, "0 is zero (u32)");
        sub.assert_eq(core::ct_is_zero_u32(1), 0, "1 is not zero (u32)");
        sub.assert_eq(core::ct_is_zero_u32(0x80000000), 0, "MSB set is not zero (u32)");
        sub.assert_eq(core::ct_is_zero_u32(0xFFFFFFFF), 0, "all ones is not zero (u32)");

        sub.assert_eq(core::ct_is_zero_u64(0), 1, "0 is zero (u64)");
        sub.assert_eq(core::ct_is_zero_u64(1), 0, "1 is not zero (u64)");
        sub.assert_eq(core::ct_is_zero_u64(0x8000000000000000), 0, "MSB set is not zero (u64)");
        sub.assert_eq(core::ct_is_zero_u64(0xFFFFFFFFFFFFFFFF), 0, "all ones is not zero (u64)");
    };

    t.run("ct_eq, ct_lt, ct_gt") { sub =>
        sub.assert_eq(core::ct_eq_u32(42, 42), 1, "42 == 42");
        sub.assert_eq(core::ct_eq_u32(42, 43), 0, "42 != 43");
        sub.assert_eq(core::ct_eq_u64(10000000000, 10000000000), 1, "10B == 10B");
        sub.assert_eq(core::ct_eq_u64(10000000000, 10000000001), 0, "10B != 10B+1");

        sub.assert_eq(core::ct_lt_u32(10, 20), 1, "10 < 20 (u32)");
        sub.assert_eq(core::ct_lt_u32(20, 20), 0, "20 !< 20 (u32)");
        sub.assert_eq(core::ct_lt_u32(30, 20), 0, "30 !< 20 (u32)");

        sub.assert_eq(core::ct_lt_u64(100, 200), 1, "100 < 200 (u64)");
        sub.assert_eq(core::ct_lt_u64(200, 200), 0, "200 !< 200 (u64)");
        sub.assert_eq(core::ct_lt_u64(300, 200), 0, "300 !< 200 (u64)");

        sub.assert_eq(core::ct_gt_u32(20, 10), 1, "20 > 10 (u32)");
        sub.assert_eq(core::ct_gt_u32(10, 20), 0, "10 !> 20 (u32)");
        sub.assert_eq(core::ct_gt_u64(200, 100), 1, "200 > 100 (u64)");
        sub.assert_eq(core::ct_gt_u64(100, 200), 0, "100 !> 200 (u64)");
    };

    t.run("ct_mask, ct_select, ct_min, ct_max") { sub =>
        sub.assert_eq(core::ct_mask_u32(1), 0xFFFFFFFF, "mask(1) u32");
        sub.assert_eq(core::ct_mask_u32(0), 0, "mask(0) u32");
        sub.assert_eq(core::ct_mask_u64(1), 0xFFFFFFFFFFFFFFFF, "mask(1) u64");
        sub.assert_eq(core::ct_mask_u64(0), 0, "mask(0) u64");

        let mask_t = core::ct_mask_u32(1);
        let mask_f = core::ct_mask_u32(0);
        sub.assert_eq(core::ct_select_u32(mask_t, 555, 999), 555, "ct_select true (u32)");
        sub.assert_eq(core::ct_select_u32(mask_f, 555, 999), 999, "ct_select false (u32)");

        let mask64_t = core::ct_mask_u64(1);
        let mask64_f = core::ct_mask_u64(0);
        sub.assert_eq(core::ct_select_u64(mask64_t, 123456789012, 987654321098), 123456789012, "ct_select true (u64)");
        sub.assert_eq(core::ct_select_u64(mask64_f, 123456789012, 987654321098), 987654321098, "ct_select false (u64)");

        sub.assert_eq(core::ct_min_u32(15, 25), 15, "min_u32 15 vs 25");
        sub.assert_eq(core::ct_min_u32(40, 30), 30, "min_u32 40 vs 30");
        sub.assert_eq(core::ct_max_u32(15, 25), 25, "max_u32 15 vs 25");
        sub.assert_eq(core::ct_max_u32(40, 30), 40, "max_u32 40 vs 30");

        sub.assert_eq(core::ct_min_u64(500, 1000), 500, "min_u64");
        sub.assert_eq(core::ct_max_u64(500, 1000), 1000, "max_u64");
    };

    t.run("ct_abs_i64 and clamp functions") { sub =>
        sub.assert_eq(core::ct_abs_i64(500), 500, "abs(500)");
        sub.assert_eq(core::ct_abs_i64(-500), 500, "abs(-500)");
        sub.assert_eq(core::ct_abs_i64(0), 0, "abs(0)");

        sub.assert_eq(core::clamp_u32(5, 10, 20), 10, "clamp_u32 below");
        sub.assert_eq(core::clamp_u32(15, 10, 20), 15, "clamp_u32 within");
        sub.assert_eq(core::clamp_u32(25, 10, 20), 20, "clamp_u32 above");

        sub.assert_eq(core::clamp_u64(5, 10, 20), 10, "clamp_u64 below");
        sub.assert_eq(core::clamp_u64(15, 10, 20), 15, "clamp_u64 within");
        sub.assert_eq(core::clamp_u64(25, 10, 20), 20, "clamp_u64 above");

        sub.assert_eq(core::clamp_i64(-5, 10, 20), 10, "clamp_i64 below");
        sub.assert_eq(core::clamp_i64(15, 10, 20), 15, "clamp_i64 within");
        sub.assert_eq(core::clamp_i64(25, 10, 20), 20, "clamp_i64 above");
    };
}

// ----------------------------------------------------------------------------
// 2. Saturation & Checked Arithmetic
// ----------------------------------------------------------------------------
fn test_saturation_and_checked_arithmetic(t: lit::T&) {
    t.run("Unsigned Saturation (add_sat, sub_sat, mul_sat)") { sub =>
        sub.assert_eq(core::add_sat_u32(0xFFFFFFFF, 1), 0xFFFFFFFF, "add_sat_u32 overflow");
        sub.assert_eq(core::add_sat_u32(100, 200), 300, "add_sat_u32 normal");

        sub.assert_eq(core::sub_sat_u32(10, 20), 0, "sub_sat_u32 underflow");
        sub.assert_eq(core::sub_sat_u32(30, 10), 20, "sub_sat_u32 normal");

        sub.assert_eq(core::add_sat_u64(core::U64_MAX, 1), core::U64_MAX, "add_sat_u64 overflow");
        sub.assert_eq(core::add_sat_u64(500, 500), 1000, "add_sat_u64 normal");

        sub.assert_eq(core::sub_sat_u64(10, 20), 0, "sub_sat_u64 underflow");
        sub.assert_eq(core::sub_sat_u64(50, 20), 30, "sub_sat_u64 normal");

        sub.assert_eq(core::mul_sat_u32(0x80000000, 2), 0xFFFFFFFF, "mul_sat_u32 overflow");
        sub.assert_eq(core::mul_sat_u32(20, 30), 600, "mul_sat_u32 normal");

        sub.assert_eq(core::mul_sat_u64(0x8000000000000000, 2), core::U64_MAX, "mul_sat_u64 overflow");
        sub.assert_eq(core::mul_sat_u64(1000, 2000), 2000000, "mul_sat_u64 normal");
    };

    t.run("shl_sat_u64 and Signed Saturation") { sub =>
        sub.assert_eq(core::shl_sat_u64(1, 64), core::U64_MAX, "shl_sat shift == 64");
        sub.assert_eq(core::shl_sat_u64(1, 100), core::U64_MAX, "shl_sat shift > 64");
        sub.assert_eq(core::shl_sat_u64(0x8000000000000000, 1), core::U64_MAX, "shl_sat bit loss");
        sub.assert_eq(core::shl_sat_u64(10, 3), 80, "shl_sat normal 10 << 3");
        sub.assert_eq(core::shl_sat_u64(0, 100), 0, "shl_sat 0 shifted is 0");

        sub.assert_eq(core::add_sat_i64(core::I64_MAX - 5, 10), core::I64_MAX, "add_sat_i64 positive ovf");
        sub.assert_eq(core::add_sat_i64(core::I64_MIN + 5, -10), core::I64_MIN, "add_sat_i64 negative ovf");
        sub.assert_eq(core::add_sat_i64(100, -30), 70, "add_sat_i64 normal");

        sub.assert_eq(core::sub_sat_i64(core::I64_MIN + 5, 10), core::I64_MIN, "sub_sat_i64 negative ovf");
        sub.assert_eq(core::sub_sat_i64(core::I64_MAX - 5, -10), core::I64_MAX, "sub_sat_i64 positive ovf");
        sub.assert_eq(core::sub_sat_i64(100, 30), 70, "sub_sat_i64 normal");
    };

    t.run("Checked Arithmetic and Retry-After Conversion") { sub =>
        let c_u32_ovf = core::add_checked_u32(0xFFFFFFFF, 1);
        sub.assert_eq(c_u32_ovf.overflow, true, "add_checked_u32 ovf flag");
        sub.assert_eq(c_u32_ovf.value, 0, "add_checked_u32 wrapped val");

        let c_u32_ok = core::add_checked_u32(100, 200);
        sub.assert_eq(c_u32_ok.overflow, false, "add_checked_u32 ok flag");
        sub.assert_eq(c_u32_ok.value, 300, "add_checked_u32 ok val");

        let c_u64_ovf = core::add_checked_u64(core::U64_MAX, 1);
        sub.assert_eq(c_u64_ovf.overflow, true, "add_checked_u64 ovf flag");

        let c_i64_ovf = core::mul_checked_i64(core::I64_MAX, 2);
        sub.assert_eq(c_i64_ovf.overflow, true, "mul_checked_i64 ovf flag");

        let c_i64_ok = core::mul_checked_i64(10, -5);
        sub.assert_eq(c_i64_ok.overflow, false, "mul_checked_i64 ok flag");
        sub.assert_eq(c_i64_ok.value, -50, "mul_checked_i64 ok val");

        sub.assert_eq(core::retry_after_sec_to_ms_sat(10), 10000, "retry-after 10s -> 10000ms");
        sub.assert_eq(core::retry_after_sec_to_ms_sat(-5), 0, "retry-after negative -> 0ms");
        sub.assert_eq(core::retry_after_sec_to_ms_sat(core::I64_MAX), core::I64_MAX, "retry-after huge -> I64_MAX");
    };
}

// ----------------------------------------------------------------------------
// 3. 128-Bit Multiplication & Wymum Without u128
// ----------------------------------------------------------------------------
fn test_wide_multiplication_and_wymum(t: lit::T&) {
    t.run("mul_wide_u64 Standard Vectors") { sub =>
        let lo0, hi0 = core::mul_wide_u64(0, 123456789);
        sub.assert_eq(lo0, 0, "mul_wide 0 * X lo");
        sub.assert_eq(hi0, 0, "mul_wide 0 * X hi");

        let lo1, hi1 = core::mul_wide_u64(1, 123456789);
        sub.assert_eq(lo1, 123456789, "mul_wide 1 * X lo");
        sub.assert_eq(hi1, 0, "mul_wide 1 * X hi");

        // 2^32 * 2^32 = 2^64 (lo = 0, hi = 1)
        let lo2, hi2 = core::mul_wide_u64(0x100000000, 0x100000000);
        sub.assert_eq(lo2, 0, "2^32 * 2^32 lo");
        sub.assert_eq(hi2, 1, "2^32 * 2^32 hi");

        // (2^64 - 1) * (2^64 - 1) = 2^128 - 2^65 + 1 -> lo = 1, hi = 0xFFFFFFFFFFFFFFFE
        let lo_max, hi_max = core::mul_wide_u64(core::U64_MAX, core::U64_MAX);
        sub.assert_eq(lo_max, 1, "MAX * MAX lo");
        sub.assert_eq(hi_max, 0xFFFFFFFFFFFFFFFE, "MAX * MAX hi");
    };

    t.run("wymum Invariant and Folding") { sub =>
        let w0 = core::wymum(0, 0);
        sub.assert_eq(w0, 0, "wymum(0, 0) == 0");

        let w1 = core::wymum(1, 1);
        sub.assert_eq(w1, 1, "wymum(1, 1) == 1");

        // wymum must mix lo ^ hi
        let lo_m, hi_m = core::mul_wide_u64(0x100000000, 0x100000000);
        let expected = lo_m ^ hi_m;
        let w_cross = core::wymum(0x100000000, 0x100000000);
        sub.assert_eq(w_cross, expected, "wymum mixes lo ^ hi correctly");
    };
}

// ----------------------------------------------------------------------------
// 4. Bit Manipulation & Endianness Codecs
// ----------------------------------------------------------------------------
fn test_bit_manipulation_and_endianness(t: lit::T&) {
    t.run("rotl32, rotr32, rotl64, rotr64") { sub =>
        let val32: u32 = 0x12345678;
        let rot8 = core::rotl32(val32, 8);
        sub.assert_eq(rot8, 0x34567812, "rotl32 by 8");
        sub.assert_eq(core::rotr32(rot8, 8), val32, "rotr32 invert rotl32");

        sub.assert_eq(core::rotl32(val32, 0), val32, "rotl32 by 0");
        sub.assert_eq(core::rotl32(val32, 32), val32, "rotl32 by 32");

        let val64: u64 = 0x0123456789ABCDEF;
        let rot16 = core::rotl64(val64, 16);
        sub.assert_eq(rot16, 0x456789ABCDEF0123, "rotl64 by 16");
        sub.assert_eq(core::rotr64(rot16, 16), val64, "rotr64 invert rotl64");
    };

    t.run("is_pow2 and next_pow2") { sub =>
        sub.assert_eq(core::is_pow2_u32(0), false, "0 is not pow2 (u32)");
        sub.assert_eq(core::is_pow2_u32(1), true, "1 is pow2 (u32)");
        sub.assert_eq(core::is_pow2_u32(1024), true, "1024 is pow2 (u32)");
        sub.assert_eq(core::is_pow2_u32(1023), false, "1023 is not pow2 (u32)");

        sub.assert_eq(core::next_pow2_u32(0), 1, "next_pow2(0)");
        sub.assert_eq(core::next_pow2_u32(1), 1, "next_pow2(1)");
        sub.assert_eq(core::next_pow2_u32(5), 8, "next_pow2(5)");
        sub.assert_eq(core::next_pow2_u32(16), 16, "next_pow2(16)");
        sub.assert_eq(core::next_pow2_u32(17), 32, "next_pow2(17)");

        sub.assert_eq(core::is_pow2_u64(0x8000000000000000), true, "2^63 is pow2 (u64)");
        sub.assert_eq(core::next_pow2_u64(0x8000000000000001), 0x8000000000000000, "next_pow2 overflow clamp");
    };

    t.run("bswap16, bswap32, bswap64") { sub =>
        sub.assert_eq(core::bswap16(0x1234), 0x3412, "bswap16");
        sub.assert_eq(core::bswap32(0x12345678), 0x78563412, "bswap32");
        sub.assert_eq(core::bswap64(0x0102030405060708), 0x0807060504030201, "bswap64");
    };

    t.run("Little-Endian and Big-Endian codecs") { sub =>
        let test_buf: u8[8] = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];
        sub.assert_eq(core::read_le_u32(test_buf[..], 0), 0x04030201, "read_le_u32");
        sub.assert_eq(core::read_le_u64(test_buf[..], 0), 0x0807060504030201, "read_le_u64");

        sub.assert_eq(core::read_be_u16(test_buf[..], 0), 0x0102, "read_be_u16");
        sub.assert_eq(core::read_be_u24(test_buf[..], 0), 0x010203, "read_be_u24");
        sub.assert_eq(core::read_be_u32(test_buf[..], 0), 0x01020304, "read_be_u32");
        sub.assert_eq(core::read_be_u64(test_buf[..], 0), 0x0102030405060708, "read_be_u64");

        var out: u8[..16] = [];
        core::write_be_u16(out, 0x1234);
        sub.assert_eq(out[0], 0x12, "write_be_u16 byte 0");
        sub.assert_eq(out[1], 0x34, "write_be_u16 byte 1");

        out.clear();
        core::write_be_u32(out, 0x12345678);
        sub.assert_eq(out[0], 0x12, "write_be_u32 byte 0");
        sub.assert_eq(out[1], 0x34, "write_be_u32 byte 1");
        sub.assert_eq(out[2], 0x56, "write_be_u32 byte 2");
        sub.assert_eq(out[3], 0x78, "write_be_u32 byte 3");

        var at_buf: u8[8] = [0; 8];
        core::write_be_u16_at(at_buf[..], 0, 0xA1B2);
        sub.assert_eq(at_buf[0], 0xA1, "write_be_u16_at byte 0");
        sub.assert_eq(at_buf[1], 0xB2, "write_be_u16_at byte 1");

        core::write_be_u32_at(at_buf[..], 2, 0x01020304);
        sub.assert_eq(at_buf[2], 0x01, "write_be_u32_at byte 0");
        sub.assert_eq(at_buf[5], 0x04, "write_be_u32_at byte 3");

        core::write_be_u64_at(at_buf[..], 0, 0x1122334455667788);
        sub.assert_eq(at_buf[0], 0x11, "write_be_u64_at byte 0");
        sub.assert_eq(at_buf[7], 0x88, "write_be_u64_at byte 7");
        sub.assert_eq(core::read_be_u64(at_buf[..], 0), 0x1122334455667788, "read/write be_u64 roundtrip");
    };
}

// ----------------------------------------------------------------------------
// 5. Euclidean Division & Remainder
// ----------------------------------------------------------------------------
fn test_euclidean_division_and_remainder(t: lit::T&) {
    t.run("rem_euclid_i64 strictly in [0, |b|)") { sub =>
        sub.assert_eq(core::rem_euclid_i64(7, 3), 1, "7 % 3 == 1");
        sub.assert_eq(core::rem_euclid_i64(-7, 3), 2, "-7 % 3 == 2 (Euclidean non-negative!)");
        sub.assert_eq(core::rem_euclid_i64(7, -3), 1, "7 % -3 == 1");
        sub.assert_eq(core::rem_euclid_i64(-7, -3), 2, "-7 % -3 == 2");
        sub.assert_eq(core::rem_euclid_i64(0, 5), 0, "0 % 5 == 0");
    };

    t.run("div_euclid_i64 Quotient Identity a = q * b + r") { sub =>
        // 7 = 2 * 3 + 1
        sub.assert_eq(core::div_euclid_i64(7, 3), 2, "7 / 3 == 2");
        // -7 = -3 * 3 + 2
        sub.assert_eq(core::div_euclid_i64(-7, 3), -3, "-7 / 3 == -3");
        // 7 = -2 * -3 + 1
        sub.assert_eq(core::div_euclid_i64(7, -3), -2, "7 / -3 == -2");
        // -7 = 3 * -3 + 2
        sub.assert_eq(core::div_euclid_i64(-7, -3), 3, "-7 / -3 == 3");
    };

    t.run("fast_mod_reduce_i32 Ring Buffer Indexing") { sub =>
        sub.assert_eq(core::fast_mod_reduce_i32(0, 16), 0, "idx 0 in buf 16");
        sub.assert_eq(core::fast_mod_reduce_i32(15, 16), 15, "idx 15 in buf 16");
        sub.assert_eq(core::fast_mod_reduce_i32(16, 16), 0, "idx 16 wraps to 0");
        sub.assert_eq(core::fast_mod_reduce_i32(-1, 16), 15, "idx -1 wraps to 15");
        sub.assert_eq(core::fast_mod_reduce_i32(-17, 16), 15, "idx -17 wraps to 15");
    };
}

// ----------------------------------------------------------------------------
// 6. PRNGs & Lemire Fast-Range Mapping
// ----------------------------------------------------------------------------
fn test_prng_and_lemire_range(t: lit::T&) {
    t.run("WyRand Determinism and State Progression") { sub =>
        var rng1 = core::new_wyrand(42);
        var rng2 = core::new_wyrand(42);

        let v1 = core::next_u64(rng1);
        let v2 = core::next_u64(rng2);
        sub.assert_eq(v1, v2, "WyRand deterministic from same seed");
        sub.assert_ne(v1, 0, "WyRand output non-zero");

        let v3 = core::next_u64(rng1);
        sub.assert_ne(v1, v3, "WyRand steps sequentially");

        let u1 = core::next_u32(rng2);
        sub.assert_ne(u1, 0, "WyRand next_u32 non-zero");
    };

    t.run("Xoroshiro64StarStar Generation") { sub =>
        var rng = core::new_xoroshiro64_star_star(123456);
        let a = core::next_u32(rng);
        let b = core::next_u32(rng);
        sub.assert_ne(a, b, "Xoroshiro64 steps state");
    };

    t.run("Lemire Fast-Range Bounds (Biased and Unbiased)") { sub =>
        // Boundary check: output must strictly be in [0, range)
        for i in 100 {
            let r_biased = core::fast_range_biased_u32((i * 123456789) as u32, 50);
            sub.assert_lt(r_biased, 50, "fast_range_biased_u32 < 50");
        }

        let r64_biased = core::fast_range_biased_u64(core::U64_MAX, 100);
        sub.assert_lt(r64_biased, 100, "fast_range_biased_u64 < 100");

        var rng = core::new_wyrand(999);
        for i in 100 {
            let r_unbiased = core::fast_range_unbiased_u32(rng, 37);
            sub.assert_lt(r_unbiased, 37, "fast_range_unbiased_u32 < 37");
        }
    };
}

// ----------------------------------------------------------------------------
// 7. Backoff & Jitter Strategies (Happy Eyeballs / AWS)
// ----------------------------------------------------------------------------
fn test_backoff_and_jitter_strategies(t: lit::T&) {
    t.run("AWS Full and Equal Jitter Bounds") { sub =>
        var rng = core::new_wyrand(1234);
        let base_ms: u64 = 100;
        let cap_ms:  u64 = 10000;

        for attempt in 10 {
            let sleep_full = core::backoff_full_jitter_ms(rng, base_ms, cap_ms, attempt as u32);
            sub.assert_le(sleep_full, cap_ms, "Full Jitter <= cap");

            let sleep_equal = core::backoff_equal_jitter_ms(rng, base_ms, cap_ms, attempt as u32);
            sub.assert_le(sleep_equal, cap_ms, "Equal Jitter <= cap");
        }
    };

    t.run("AWS Decorrelated Jitter (Clamping Flaw Immunity)") { sub =>
        var rng = core::new_wyrand(5678);
        let base_ms: u64 = 50;
        let cap_ms:  u64 = 5000;
        var sleep_ms = base_ms;

        // In naive implementations, if sleep_ms >= cap_ms, clamping to [base_ms, cap_ms]
        // causes the range [base_ms, sleep * 3] to collapse or become degenerate.
        // Goose-wing math guarantees sleep >= base_ms and <= cap_ms always!
        for i in 50 {
            sleep_ms = core::backoff_decorrelated_jitter_ms(rng, base_ms, cap_ms, sleep_ms);
            sub.assert_ge(sleep_ms, base_ms, "Decorrelated sleep >= base");
            sub.assert_le(sleep_ms, cap_ms, "Decorrelated sleep <= cap");
        }
    };

    t.run("Happy Eyeballs Delay Clamping (RFC 8305)") { sub =>
        // Candidate delay below absolute minimum 10ms -> clamped to 10ms
        let d_low = core::clamp_happy_eyeballs_delay_ms(5, false);
        sub.assert_eq(d_low, 10, "RFC 8305 floor >= 10ms");

        // First family recommended min 100ms
        let d_first = core::clamp_happy_eyeballs_delay_ms(50, true);
        sub.assert_eq(d_first, 100, "RFC 8305 first family >= 100ms");

        // Normal CAD within window [100ms, 2000ms]
        let d_normal = core::clamp_happy_eyeballs_delay_ms(250, false);
        sub.assert_eq(d_normal, 250, "Normal CAD preserved");

        // Max CAD ceiling 2000ms
        let d_high = core::clamp_happy_eyeballs_delay_ms(5000, false);
        sub.assert_eq(d_high, 2000, "Max CAD clamped to 2000ms");
    };
}

// ----------------------------------------------------------------------------
// 8. Jacobson EWMA RTT Estimator (RFC 6298 / RFC 9002 Errata ID 7539)
// ----------------------------------------------------------------------------
fn test_jacobson_rtt_estimator_errata7539(t: lit::T&) {
    t.run("Initial State and First Sample") { sub =>
        var est = core::new_jacobson_rtt_estimator(333000);
        sub.assert_eq(est.has_sample, false, "init has no sample");
        sub.assert_eq(core::smoothed_rtt_us(est), 333000, "init srtt 333ms");
        sub.assert_eq(core::rttvar_us(est), 166500, "init rttvar 166.5ms");

        // First RTT sample: 100 ms (100,000 us)
        core::on_rtt_sample(est, 100000, 0, 25000, false);
        sub.assert_eq(est.has_sample, true, "has sample after first update");
        sub.assert_eq(est.min_rtt_us, 100000, "min_rtt initialized to first sample");
        sub.assert_eq(core::smoothed_rtt_us(est), 100000, "first sample srtt == sample");
        sub.assert_eq(core::rttvar_us(est), 50000, "first sample rttvar == sample / 2");
    };

    t.run("RFC 9002 Errata ID 7539 Variance Order Invariant") { sub =>
        var est = core::new_jacobson_rtt_estimator(100000);
        core::on_rtt_sample(est, 100000, 0, 25000, false);

        // Second sample: 120 ms (120,000 us)
        // With Errata ID 7539:
        // prior_srtt = 100,000 us
        // abs_diff = |120,000 - 100,000| = 20,000 us
        // rttvar_scaled was 200,000 (4 * 50,000).
        // rttvar_scaled = 200,000 - 50,000 + 20,000 = 170,000.
        // rttvar = 170,000 / 4 = 42,500 us.
        // srtt_scaled was 800,000 (8 * 100,000).
        // srtt_scaled = 800,000 - 100,000 + 120,000 = 820,000.
        // srtt = 820,000 / 8 = 102,500 us.
        core::on_rtt_sample(est, 120000, 0, 25000, false);

        sub.assert_eq(core::smoothed_rtt_us(est), 102500, "Errata 7539 srtt");
        sub.assert_eq(core::rttvar_us(est), 42500, "Errata 7539 rttvar calculated before srtt update");
    };

    t.run("Defensive Ack Delay Subtraction & Handshake Bounding") { sub =>
        var est = core::new_jacobson_rtt_estimator(50000);
        core::on_rtt_sample(est, 50000, 0, 25000, false);

        // Before handshake confirmation: ack_delay is ignored
        core::on_rtt_sample(est, 60000, 10000, 25000, false);
        // sample with unconfirmed handshake treats adjusted_rtt = latest_rtt (60,000)
        sub.assert_eq(est.min_rtt_us, 50000, "min_rtt remains 50ms");

        // After handshake confirmation:
        // Peer reports malicious ack_delay 50,000 us on latest_rtt 60,000 us
        // min_rtt is 50,000 us. latest_rtt (60,000) < min_rtt (50,000) + ack_delay (25,000 clamped).
        // Goose-wing math DEFENSIVELY rejects subtracting ack_delay so adjusted_rtt does not shrink below min_rtt!
        core::on_rtt_sample(est, 60000, 50000, 25000, true);
        sub.assert_ge(core::smoothed_rtt_us(est), 50000, "Defensive barrier protects srtt");
    };

    t.run("Probe Timeout (PTO) and Loss Time Threshold") { sub =>
        var est = core::new_jacobson_rtt_estimator(80000);
        core::on_rtt_sample(est, 80000, 0, 25000, false);

        // PTO = smoothed_rtt + 4 * rttvar + max_ack_delay
        // = 80,000 + 4 * 40,000 + 25,000 = 80,000 + 160,000 + 25,000 = 265,000 us
        let pto = core::probe_timeout_us(est, 25000);
        sub.assert_eq(pto, 265000, "RFC 9002 PTO formula");

        // Loss time threshold = max(9/8 * max(latest_rtt, srtt), timer_granularity)
        let loss_thresh = core::loss_time_threshold_us(est);
        // 9/8 * 80,000 = 90,000 us
        sub.assert_eq(loss_thresh, 90000, "QUIC loss time threshold 9/8 ratio");
    };
}

// ----------------------------------------------------------------------------
// 9. Fast Non-Cryptographic Hashing & Combinators
// ----------------------------------------------------------------------------
fn test_fast_non_cryptographic_hashes(t: lit::T&) {
    t.run("FNV-1a 32-bit and 64-bit Test Vectors") { sub =>
        let empty_buf: u8[0] = [];
        sub.assert_eq(core::fnv1a_32(empty_buf[..]), 0x811C9DC5, "FNV-1a 32-bit empty offset");
        sub.assert_eq(core::fnv1a_64(empty_buf[..]), 0xCBF29CE484222325, "FNV-1a 64-bit empty offset");

        let hello = "hello";
        sub.assert_eq(core::fnv1a_32(hello[..]), 0x4F9F2CAB, "FNV-1a 32-bit 'hello'");
        sub.assert_eq(core::fnv1a_64(hello[..]), 0xA430D84680AABD0B, "FNV-1a 64-bit 'hello'");
    };

    t.run("xxHash32 Reference Vectors") { sub =>
        let empty_buf: u8[0] = [];
        sub.assert_eq(core::xxhash32(empty_buf[..], 0), 0x02CC5D05, "xxHash32 empty seed 0");

        let hello = "hello";
        sub.assert_eq(core::xxhash32(hello[..], 0), 0xFB0077F9, "xxHash32 'hello' seed 0");
    };

    t.run("wyhash64 Consistency and Block Processing") { sub =>
        let empty_buf: u8[0] = [];
        let h_empty = core::wyhash64(empty_buf[..], 0);
        sub.assert_ne(h_empty, 0, "wyhash64 empty seed 0 produces well-distributed hash");

        let msg = "The quick brown fox jumps over the lazy dog";
        let h_msg1 = core::wyhash64(msg[..], 0);
        let h_msg2 = core::wyhash64(msg[..], 0);
        sub.assert_eq(h_msg1, h_msg2, "wyhash64 deterministic");
        sub.assert_ne(h_msg1, h_empty, "wyhash64 distinguishes message");

        // Long string (> 48 bytes) exercising 48-byte loop and remainder handling
        let long_msg = "goose-wing high-performance deterministic network stack zero-heap constant-time core math primitives";
        let h_long = core::wyhash64(long_msg[..], 42);
        sub.assert_ne(h_long, 0, "wyhash64 48-byte chunk processing");
    };

    t.run("Non-Commutative Hash Combinators") { sub =>
        let h1: u64 = 0x1234567890ABCDEF;
        let h2: u64 = 0xFEDCBA0987654321;
        let comb12 = core::hash_combine_u64(h1, h2);
        let comb21 = core::hash_combine_u64(h2, h1);
        sub.assert_ne(comb12, comb21, "hash_combine_u64 must be non-commutative");

        let h32_1: u32 = 0x12345678;
        let h32_2: u32 = 0x87654321;
        let comb32_12 = core::hash_combine_u32(h32_1, h32_2);
        let comb32_21 = core::hash_combine_u32(h32_2, h32_1);
        sub.assert_ne(comb32_12, comb32_21, "hash_combine_u32 must be non-commutative");
    };
}

// ----------------------------------------------------------------------------
// 10. Constant-Time SOCKS5 Frame Length Validation
// ----------------------------------------------------------------------------
fn test_socks5_frame_validation_ct(t: lit::T&) {
    t.run("SOCKS5 Address Types and Bounds") { sub =>
        // IPv4 (ATYP 0x01): [VER=5, CMD=1, RSV=0, ATYP=1, IPv4 (4B), Port (2B)] -> 10 bytes
        let buf_ipv4: u8[10] = [0x05, 0x01, 0x00, 0x01, 127, 0, 0, 1, 0x1F, 0x90];
        let len_ipv4 = core::socks5_expected_frame_len_ct(buf_ipv4[..]);
        sub.assert_eq(len_ipv4, 10, "SOCKS5 IPv4 expected length");

        // Too short (< 5 bytes)
        let buf_short: u8[4] = [0x05, 0x01, 0x00, 0x01];
        let len_short = core::socks5_expected_frame_len_ct(buf_short[..]);
        sub.assert_eq(len_short, 0, "SOCKS5 frame < 5 bytes returns 0");

        // IPv6 (ATYP 0x04): 4 header + 16 addr + 2 port = 22 bytes
        let buf_ipv6: u8[6] = [0x05, 0x01, 0x00, 0x04, 0x00, 0x00];
        let len_ipv6 = core::socks5_expected_frame_len_ct(buf_ipv6[..]);
        sub.assert_eq(len_ipv6, 22, "SOCKS5 IPv6 expected length");

        // FQDN (ATYP 0x03): 4 header + 1 len + N bytes + 2 port = 7 + N
        // domain_len = 14 -> 7 + 14 = 21 bytes
        let buf_fqdn: u8[6] = [0x05, 0x01, 0x00, 0x03, 14, 0x00];
        let len_fqdn = core::socks5_expected_frame_len_ct(buf_fqdn[..]);
        sub.assert_eq(len_fqdn, 21, "SOCKS5 FQDN expected length (7 + 14 = 21)");

        // FQDN with 0 length domain is invalid
        let buf_fqdn_zero: u8[6] = [0x05, 0x01, 0x00, 0x03, 0, 0x00];
        let len_fqdn_zero = core::socks5_expected_frame_len_ct(buf_fqdn_zero[..]);
        sub.assert_eq(len_fqdn_zero, 0, "SOCKS5 FQDN with zero length invalid");

        // Non-SOCKS5 version (e.g. SOCKS4 = 4)
        let buf_v4: u8[6] = [0x04, 0x01, 0x00, 0x01, 127, 0];
        let len_v4 = core::socks5_expected_frame_len_ct(buf_v4[..]);
        sub.assert_eq(len_v4, 0, "SOCKS4 version rejected");

        // Unknown ATYP returns 0
        let buf_bad_atyp: u8[6] = [0x05, 0x01, 0x00, 0x02, 10, 0];
        let len_bad_atyp = core::socks5_expected_frame_len_ct(buf_bad_atyp[..]);
        sub.assert_eq(len_bad_atyp, 0, "SOCKS5 unknown ATYP returns 0");
    };
}

// ----------------------------------------------------------------------------
// Suite Runner
// ----------------------------------------------------------------------------

// --- Component: core_sync ---
// Tests for concurrency primitives, actors, channels, and singleflight.

// ---- suite 1: multithreading, actors & crash containment ------------------

struct ComputeTask {
    task_id:     i64  = 0,
    operand:     i64  = 0,
    is_terminal: bool = false,
}

struct ComputeResult {
    task_id:      i64 = 0,
    computed_val: i64 = 0,
}

thread_fn compute_worker() {
    loop {
        let task = core::recv_msg<ComputeTask>();
        guard !task.is_terminal else { break; }
        core::send_msg(ComputeResult {
            task_id:      task.task_id,
            computed_val: task.operand * task.operand,
        });
    }
}

// Actor pattern: State manager thread that owns mutable counter without mutexes
struct CounterCommand {
    delta: i64  = 0,
    query: bool = false,
    quit:  bool = false,
}

struct CounterResponse {
    current_value: i64 = 0,
}

thread_fn counter_actor() {
    var state: i64 = 0;
    loop {
        let cmd = core::recv_msg<CounterCommand>();
        if cmd.quit { break; }
        if cmd.query {
            core::send_msg(CounterResponse { current_value: state });
        } else {
            state += cmd.delta;
        }
    }
}

thread_fn contained_crashing_worker() {
    let task = core::recv_msg<ComputeTask>();
    if task.operand == 999 {
        abort("intentional contained worker failure for test");
    }
}

fn test_multithreading_and_actors(t: lit::T&) {
    t.run("Case 1: WaitGroup & Parallel Worker Pool Dispatch") { sub =>
        let num_tasks:   i64 = 8;
        let num_workers: i64 = 2;

        var wg = core::WaitGroup { .. };
        for worker_idx in num_workers {
            let tid = thread_spawn(compute_worker);
            wg.add_worker(tid);
        }

        for task_idx in num_tasks {
            core::send_msg(ComputeTask {
                task_id:     task_idx,
                operand:     task_idx + 1,
                is_terminal: false,
            });
        }

        for worker_idx in num_workers {
            core::send_msg(ComputeTask { is_terminal: true, .. });
        }

        var total_sum: i64 = 0;
        for task_idx in num_tasks {
            let res = core::recv_msg<ComputeResult>();
            total_sum += res.computed_val;
        }

        let wg_ok = wg.wait_all();
        sub.assert_true(wg_ok, "All workers finished successfully");
        sub.assert_eq(total_sum, 204, "Parallel computation matched 1^2 + ... + 8^2");
    };

    t.run("Case 2: Actor-Based State Management (Zero Mutexes)") { sub =>
        let actor_tid = thread_spawn(counter_actor);

        core::send_msg(CounterCommand { delta: 10, .. });
        core::send_msg(CounterCommand { delta: 25, .. });
        core::send_msg(CounterCommand { delta: -5, .. });

        core::send_msg(CounterCommand { query: true, .. });
        let resp = core::recv_msg<CounterResponse>();
        sub.assert_eq(resp.current_value, 30, "Actor returned accurate state (10 + 25 - 5 = 30)");

        core::send_msg(CounterCommand { quit: true, .. });
        let actor_ok = thread_wait(actor_tid);
        sub.assert_true(actor_ok, "Actor terminated cleanly");
    };

    t.run("Case 3: Crash Containment via thread_spawn_contained") { sub =>
        let crash_tid = thread_spawn_contained(contained_crashing_worker);
        core::send_msg(ComputeTask { operand: 999, .. });

        var abort_msg: u8[>..] = [];
        let ok = thread_wait(crash_tid, abort_msg);
        sub.assert_false(ok, "Contained thread reported abort status");
        sub.assert_true(abort_msg.len > 0, "Contained thread captured abort diagnostic message");
    };
}

// ---- suite 2: classical concurrency (baton mutex, semaphore, latch) -------

thread_fn baton_worker() {
    for i in 10 {
        var count = core::baton_lock<i64>();
        count++;
        core::baton_unlock(count);
    }
}

fn test_classical_primitives(t: lit::T&) {
    t.run("Case 1: BatonMutex Share-Nothing Mutual Exclusion") { sub =>
        core::new_baton_mutex(0 as i64);

        let w1 = thread_spawn(baton_worker);
        let w2 = thread_spawn(baton_worker);
        let w3 = thread_spawn(baton_worker);

        let ok1 = thread_wait(w1);
        let ok2 = thread_wait(w2);
        let ok3 = thread_wait(w3);
        sub.assert_true(ok1, "Worker 1 terminated cleanly");
        sub.assert_true(ok2, "Worker 2 terminated cleanly");
        sub.assert_true(ok3, "Worker 3 terminated cleanly");

        let final_count = core::baton_lock<i64>();
        sub.assert_eq(final_count, 30, "Atomic baton increments summed correctly (3 * 10 = 30)");
    };

    t.run("Case 2: Counting Semaphore & Bulkhead Capacity Limiting") { sub =>
        var sem = core::new_semaphore(2);

        let p1 = sem.acquire();
        let p2 = sem.acquire();
        sub.assert_eq(p1.epoch, 1, "First permit has epoch 1");
        sub.assert_eq(p2.epoch, 1, "Second permit has epoch 1");

        // Quota saturated: try_acquire must return false
        let p3, ok3 = sem.try_acquire();
        sub.assert_false(ok3, "try_acquire fails when bulkhead quota is exhausted");

        // Release one permit
        sem.release(p1);

        // Slot freed: try_acquire must now succeed
        let p4, ok4 = sem.try_acquire();
        sub.assert_true(ok4, "try_acquire succeeds after permit return");

        // Clean up
        sem.release(p2);
        sem.release(p4);
    };

    t.run("Case 3: CountDownLatch One-Shot Coordination") { sub =>
        var latch = core::new_count_down_latch(3);

        latch.count_down();
        latch.count_down();
        latch.count_down();

        // Drain the 3 ticks
        var ticks_collected: i64 = 0;
        for i in 3 {
            let item, ok = core::try_recv_msg<core::LatchTick>();
            if ok { ticks_collected++; }
        }
        sub.assert_eq(ticks_collected, 3, "All 3 countdown ticks were captured");
    };

    t.run("Case 4: Scoped Permit Release via defer") { sub =>
        // Drain any leftover permits from global queue
        while true {
            let _, ok = core::sem_try_acquire();
            if !ok { break; }
        }
        var sem = core::new_semaphore(1);
        {
            let permit = sem.acquire();
            defer sem.release(permit);
            let p_blocked, ok_blocked = sem.try_acquire();
            sub.assert_false(ok_blocked, "Semaphore quota exhausted while scoped permit held");
        }
        // At block exit, defer automatically releases the permit!
        let p_free, ok_free = sem.try_acquire();
        sub.assert_true(ok_free, "Permit automatically returned to pool via defer upon block exit");
        sem.release(p_free);
    };
}

// ---- suite 3: cyclic barrier two-phase turnstile synchronization ----------

thread_fn barrier_test_worker(worker_id: i32) {
    var epoch: u64 = 0;
    for step in 5 {
        epoch = core::barrier_sync(worker_id, epoch);
    }
}

fn test_cyclic_barrier(t: lit::T&) {
    t.run("Case 1: Two-Phase Turnstile Multi-Worker Synchronization") { sub =>
        let barrier_tid = core::barrier_start(3);
        let w1 = thread_spawn(barrier_test_worker, 1 as i32);
        let w2 = thread_spawn(barrier_test_worker, 2 as i32);
        let w3 = thread_spawn(barrier_test_worker, 3 as i32);

        let ok1 = thread_wait(w1);
        let ok2 = thread_wait(w2);
        let ok3 = thread_wait(w3);
        sub.assert_true(ok1, "Barrier participant 1 succeeded");
        sub.assert_true(ok2, "Barrier participant 2 succeeded");
        sub.assert_true(ok3, "Barrier participant 3 succeeded");

        core::barrier_stop();
        let coord_ok = thread_wait(barrier_tid);
        sub.assert_true(coord_ok, "Barrier coordinator shutdown cleanly");
    };
}

// ---- suite 4: csp patterns & in-order stream reassembly -------------------

struct ChannelTagA {}
struct ChannelTagB {}

struct RendezvousReq {
    command_id: i32 = 0,
}

thread_fn rendezvous_server() {
    let req = core::chan_recv<ChannelTagA, RendezvousReq>();
    core::chan_rendezvous_reply<ChannelTagA>(req.command_id == 100);
}

fn test_csp_patterns(t: lit::T&) {
    t.run("Case 1: Reassembler In-Order Stream Reconstruction") { sub =>
        var r = core::new_reassembler(0);

        // Push packets in out-of-order sequence: 3, 0, 2, 1
        var item3 = core::ReassemblerItem { seq_id: 3, .. }; item3.data.append("three");
        var item0 = core::ReassemblerItem { seq_id: 0, .. }; item0.data.append("zero");
        var item2 = core::ReassemblerItem { seq_id: 2, .. }; item2.data.append("two");
        var item1 = core::ReassemblerItem { seq_id: 1, .. }; item1.data.append("one");

        r.push_unordered(item3);
        r.push_unordered(item0);
        r.push_unordered(item2);
        r.push_unordered(item1);

        sub.assert_eq(r.pending_count(), 4, "Reassembler holds 4 unordered items");

        let p0, ok0 = r.pop_next_in_order();
        sub.assert_true(ok0, "Pop item 0 ok");
        sub.assert_eq(p0.seq_id, 0, "Item 0 sequence verified");

        let p1, ok1 = r.pop_next_in_order();
        sub.assert_true(ok1, "Pop item 1 ok");
        sub.assert_eq(p1.seq_id, 1, "Item 1 sequence verified");

        let p2, ok2 = r.pop_next_in_order();
        sub.assert_true(ok2, "Pop item 2 ok");
        sub.assert_eq(p2.seq_id, 2, "Item 2 sequence verified");

        let p3, ok3 = r.pop_next_in_order();
        sub.assert_true(ok3, "Pop item 3 ok");
        sub.assert_eq(p3.seq_id, 3, "Item 3 sequence verified");

        let p4, ok4 = r.pop_next_in_order();
        sub.assert_false(ok4, "Pop item 4 returns false (empty)");
        sub.assert_eq(r.pending_count(), 0, "All items drained");
    };

    t.run("Case 2: StaticChan Envelope Tagging & Rendezvous") { sub =>
        let srv = thread_spawn(rendezvous_server);
        let ok = core::chan_rendezvous<ChannelTagA, RendezvousReq>(RendezvousReq { command_id: 100 });
        sub.assert_true(ok, "Rendezvous server confirmed command 100 with Ack");
        thread_wait(srv);
    };
}

// ---- suite 5: actor mailbox, stash buffer & 16-byte actor ref -------------

fn test_actor_subsystem(t: lit::T&) {
    t.run("Case 1: PriorityMailbox Stable Binary Min-Heap Ordering") { sub =>
        var mb = core::PriorityMailbox { .. };

        // Push entries with different priorities:
        // Priority 10 (Low), Priority 1 (High), Priority 5 (Medium), Priority 1 (High FIFO second)
        mb.push(10, 1, 1000);
        mb.push(1, 2, 2001);
        mb.push(5, 3, 5000);
        mb.push(1, 4, 2002);

        sub.assert_eq(mb.count(), 4, "Mailbox has 4 pending messages");

        let e1, ok1 = mb.pop();
        sub.assert_true(ok1, "Pop 1 ok");
        sub.assert_eq(e1.payload_val, 2001, "First high-priority message popped first");

        let e2, ok2 = mb.pop();
        sub.assert_true(ok2, "Pop 2 ok");
        sub.assert_eq(e2.payload_val, 2002, "Second high-priority message preserved FIFO order");

        let e3, ok3 = mb.pop();
        sub.assert_true(ok3, "Pop 3 ok");
        sub.assert_eq(e3.payload_val, 5000, "Medium priority message popped next");

        let e4, ok4 = mb.pop();
        sub.assert_true(ok4, "Pop 4 ok");
        sub.assert_eq(e4.payload_val, 1000, "Low priority message popped last");

        let e5, ok5 = mb.pop();
        sub.assert_false(ok5, "Mailbox empty");
    };

    t.run("Case 2: StashBuffer Message Deferral and Replay") { sub =>
        var stash = core::StashBuffer { .. };
        sub.assert_true(stash.is_empty(), "StashBuffer starts empty");

        stash.stash(core::StashedEnvelope { priority: 1, seq: 1, payload_type: 10, .. });
        stash.stash(core::StashedEnvelope { priority: 1, seq: 2, payload_type: 20, .. });
        stash.stash(core::StashedEnvelope { priority: 1, seq: 3, payload_type: 30, .. });

        sub.assert_eq(stash.stash_count(), 3, "Stashed 3 messages");
        sub.assert_false(stash.is_empty(), "StashBuffer not empty");

        var pending: core::StashedEnvelope[>..] = [];
        let unstashed = stash.unstash_all(pending);
        sub.assert_eq(unstashed, 3, "Unstashed exactly 3 messages");
        sub.assert_eq(pending.len, 3, "Pending array received all 3 messages");
        sub.assert_true(stash.is_empty(), "StashBuffer cleared after unstash_all");
    };

    t.run("Case 3: ActorRef 16-Byte Flat Handle Value Semantics") { sub =>
        let ref_a = core::new_actor_ref(101, 1, 0, 42);
        let ref_b = core::new_actor_ref(101, 1, 0, 42);
        let ref_c = core::new_actor_ref(102, 1, 0, 42);

        sub.assert_true(core::eq_actor_ref(ref_a, ref_b), "ref_a and ref_b are equal");
        sub.assert_false(core::eq_actor_ref(ref_a, ref_c), "ref_a and ref_c differ in actor_id");
    };
}

// ---- suite 6: otp supervision trees & fault tolerance ---------------------

fn test_supervision_trees(t: lit::T&) {
    t.run("Case 1: RestartType Specification & Restart Evaluation") { sub =>
        var sup = core::Supervisor { .. };

        let ok_perm = sup.add_child(core::ChildSpec { id: 1, restart_type: core::RestartType.Permanent, .. }, 101);
        let ok_trans = sup.add_child(core::ChildSpec { id: 2, restart_type: core::RestartType.Transient, .. }, 102);
        let ok_temp = sup.add_child(core::ChildSpec { id: 3, restart_type: core::RestartType.Temporary, .. }, 103);
        sub.assert_true(ok_perm, "Permanent child added");
        sub.assert_true(ok_trans, "Transient child added");
        sub.assert_true(ok_temp, "Temporary child added");
        sub.assert_eq(sup.child_count(), 3, "Supervisor has 3 children");

        var normal_reason:   core::ExitReason = core::ExitReason.Normal;
        var abnormal_reason: core::ExitReason = core::ExitReason.Abnormal { error_code: 1, details: [] };

        // Permanent: always restarts
        sub.assert_true(sup.should_restart_child(0, normal_reason), "Permanent child restarts on Normal");
        sub.assert_true(sup.should_restart_child(0, abnormal_reason), "Permanent child restarts on Abnormal");

        // Transient: restarts ONLY on Abnormal
        sub.assert_false(sup.should_restart_child(1, normal_reason), "Transient child does NOT restart on Normal");
        sub.assert_true(sup.should_restart_child(1, abnormal_reason), "Transient child restarts on Abnormal");

        // Temporary: never restarts
        sub.assert_false(sup.should_restart_child(2, normal_reason), "Temporary child never restarts (Normal)");
        sub.assert_false(sup.should_restart_child(2, abnormal_reason), "Temporary child never restarts (Abnormal)");
    };

    t.run("Case 2: Restart Intensity Throttling (max_restarts / max_seconds)") { sub =>
        var spec = core::SupervisorSpec {
            strategy:      core::Strategy.OneForOne,
            max_restarts:  3,
            max_seconds:   5,
            auto_shutdown: core::AutoShutdown.Never,
        };
        var sup = core::new_supervisor(spec);
        sup.add_child(core::ChildSpec { id: 1, .. }, 201);

        // Record 3 failures within 5-second window
        let r1 = sup.record_failure(0, 1000);
        let r2 = sup.record_failure(0, 1001);
        let r3 = sup.record_failure(0, 1002);
        sub.assert_true(r1, "Failure 1 accepted");
        sub.assert_true(r2, "Failure 2 accepted");
        sub.assert_true(r3, "Failure 3 accepted");

        // 4th failure within window must be rejected (intensity limit exceeded!)
        let r4 = sup.record_failure(0, 1003);
        sub.assert_false(r4, "Failure 4 rejected: intensity limit exceeded");

        // Failure after window has rolled forward past 5 seconds must succeed
        let r5 = sup.record_failure(0, 1010);
        sub.assert_true(r5, "Failure after window expiry accepted");
    };

    t.run("Case 3: AutoShutdown & Specification Validation") { sub =>
        // Invalid config: significant child when auto_shutdown is Never must be rejected
        var sup_never = core::new_supervisor(core::SupervisorSpec { auto_shutdown: core::AutoShutdown.Never, .. });
        let rejected_sig = sup_never.add_child(core::ChildSpec {
            id:           1,
            restart_type: core::RestartType.Transient,
            significant:  true,
            ..
        }, 301);
        sub.assert_false(rejected_sig, "Child with significant=true rejected when auto_shutdown is Never");

        // Invalid config: permanent child marked significant must be rejected
        var sup_auto = core::new_supervisor(core::SupervisorSpec { auto_shutdown: core::AutoShutdown.AnySignificant, .. });
        let rejected_perm_sig = sup_auto.add_child(core::ChildSpec {
            id:           2,
            restart_type: core::RestartType.Permanent,
            significant:  true,
            ..
        }, 302);
        sub.assert_false(rejected_perm_sig, "Permanent child cannot be marked significant");

        // Valid config: transient child marked significant
        let accepted = sup_auto.add_child(core::ChildSpec {
            id:           3,
            restart_type: core::RestartType.Transient,
            significant:  true,
            ..
        }, 303);
        sub.assert_true(accepted, "Transient significant child accepted");
        sub.assert_false(sup_auto.is_auto_shutdown(), "AutoShutdown initially false");
    };
}

// ---- consolidated suite entry point ---------------------------------------

// --- Component: core_bytes ---
// Verification suite for Goose Core Byte String & Zero-Heap Slice Operations (core/bytes):
// - ASCII character classification & transformations (case.goose)
// - Case-insensitive folding, prefix/suffix, and substring search (case.goose)
// - Linear whitespace & ASCII whitespace trimming (trim.goose)
// - Byte set trimming and exact byte trimming (trim.goose)
// - Search predicates, byte indexing, slice indexing, and counting (search.goose)
// - Single-delimiter splitting, reverse splitting, and ByteTokenizer (split.goose)
// - Strict bounds-checked decimal and hex parsing with overflow protection (parse.goose)
// - Zero-allocation decimal and hex formatting (format.goose)
// - Universal Function Call Syntax (UFCS) method bridges (ufcs.goose)

fn test_case_folding(t: lit::T&) {
    t.run("ASCII Predicates & Character Conversions") { sub =>
        sub.assert_true(core::is_ascii_upper('A' as u8), "A is upper");
        sub.assert_true(core::is_ascii_upper('Z' as u8), "Z is upper");
        sub.assert_false(core::is_ascii_upper('a' as u8), "a is not upper");
        sub.assert_false(core::is_ascii_upper('9' as u8), "9 is not upper");

        sub.assert_true(core::is_ascii_lower('a' as u8), "a is lower");
        sub.assert_true(core::is_ascii_lower('z' as u8), "z is lower");
        sub.assert_false(core::is_ascii_lower('A' as u8), "A is not lower");

        sub.assert_true(core::is_ascii_alpha('g' as u8), "g is alpha");
        sub.assert_true(core::is_ascii_alpha('G' as u8), "G is alpha");
        sub.assert_false(core::is_ascii_alpha('5' as u8), "5 is not alpha");

        sub.assert_true(core::is_ascii_digit('0' as u8), "0 is digit");
        sub.assert_true(core::is_ascii_digit('9' as u8), "9 is digit");
        sub.assert_false(core::is_ascii_digit('x' as u8), "x is not digit");

        sub.assert_true(core::is_ascii_alphanumeric('k' as u8), "k is alnum");
        sub.assert_true(core::is_ascii_alphanumeric('7' as u8), "7 is alnum");
        sub.assert_false(core::is_ascii_alphanumeric('-' as u8), "- is not alnum");

        sub.assert_eq(core::to_lower_ascii_byte('M' as u8), 'm' as u8, "M -> m");
        sub.assert_eq(core::to_lower_ascii_byte('m' as u8), 'm' as u8, "m -> m");
        sub.assert_eq(core::to_upper_ascii_byte('w' as u8), 'W' as u8, "w -> W");
        sub.assert_eq(core::to_upper_ascii_byte('W' as u8), 'W' as u8, "W -> W");

        var lower_buf: u8[..64] = [];
        core::to_lower_ascii("GoOsE-WiNg v1.0!", lower_buf);
        sub.assert_eq(lower_buf[..], "goose-wing v1.0!", "to_lower_ascii string conversion");

        var upper_buf: u8[..64] = [];
        core::to_upper_ascii("goose-wing v1.0!", upper_buf);
        sub.assert_eq(upper_buf[..], "GOOSE-WING V1.0!", "to_upper_ascii string conversion");
    };

    t.run("Case-Insensitive Equality & Affixes") { sub =>
        let h1 = "Content-Type";
        let h2 = "content-type";
        let h3 = "CONTENT-TYPE";
        let h4 = "Content-Length";

        sub.assert_true(core::eq_ascii_fold(h1, h2), "h1 eq_fold h2");
        sub.assert_true(h1.eq_ascii_fold(h3), "h1.eq_ascii_fold(h3) via UFCS");
        sub.assert_false(core::eq_ascii_fold(h1, h4), "h1 not eq_fold h4");
        sub.assert_false(core::eq_ascii_fold(h1, "Content"), "Length mismatch false");

        sub.assert_true(core::starts_with_fold("Bearer token_xyz", "bearer"), "starts_with_fold prefix");
        sub.assert_true("BEARER token_xyz".starts_with_fold("bearer "), "starts_with_fold via UFCS");
        sub.assert_false(core::starts_with_fold("Basic user:pass", "bearer"), "starts_with_fold false prefix");

        sub.assert_true(core::ends_with_fold("image.JPEG", ".jpeg"), "ends_with_fold suffix");
        sub.assert_true("archive.tar.GZ".ends_with_fold(".gz"), "ends_with_fold via UFCS");
        sub.assert_false(core::ends_with_fold("document.pdf", ".png"), "ends_with_fold false suffix");

        let text = "The Quick Brown Fox Jumps Over The Lazy Dog";
        sub.assert_true(core::contains_fold(text, "brown fox"), "contains_fold match");
        sub.assert_true(text.contains_fold("LAZY"), "contains_fold via UFCS");
        sub.assert_false(core::contains_fold(text, "Cat"), "contains_fold no match");

        sub.assert_eq(core::index_of_fold(text, "brown"), 10, "index_of_fold matches index 10");
        sub.assert_eq(text.index_of_fold("FOX"), 16, "index_of_fold matches index 16");
        sub.assert_eq(core::index_of_fold(text, "tiger"), -1, "index_of_fold not found is -1");
    };
}

fn test_trimming(t: lit::T&) {
    t.run("Linear White Space (RFC 9110 LWS)") { sub =>
        let raw = " \t  \tAuthorization: Bearer secret \t  ";
        sub.assert_eq(core::trim_lws_start(raw), "Authorization: Bearer secret \t  ", "trim_lws_start");
        sub.assert_eq(core::trim_lws_end(raw), " \t  \tAuthorization: Bearer secret", "trim_lws_end");
        sub.assert_eq(core::trim_lws(raw), "Authorization: Bearer secret", "trim_lws both ends");
        sub.assert_eq(raw.trim_lws(), "Authorization: Bearer secret", "trim_lws via UFCS");

        // Edge cases
        sub.assert_eq(core::trim_lws(""), "", "trim_lws on empty");
        sub.assert_eq(core::trim_lws("     \t\t "), "", "trim_lws all whitespace");
        sub.assert_eq(core::trim_lws("no_spaces"), "no_spaces", "trim_lws without whitespace");
    };

    t.run("ASCII Space Trimming (CR, LF, TAB, SP)") { sub =>
        let multiline = "\r\n  \t{\"status\": \"healthy\"}\n\r\t  ";
        sub.assert_eq(core::trim_ascii_space_start(multiline), "{\"status\": \"healthy\"}\n\r\t  ", "trim_ascii_space_start");
        sub.assert_eq(core::trim_ascii_space_end(multiline), "\r\n  \t{\"status\": \"healthy\"}", "trim_ascii_space_end");
        sub.assert_eq(core::trim_ascii_space(multiline), "{\"status\": \"healthy\"}", "trim_ascii_space both ends");
        sub.assert_eq(multiline.trim_ascii_space(), "{\"status\": \"healthy\"}", "trim_ascii_space via UFCS");
    };

    t.run("Byte and Cutset Trimming") { sub =>
        let slashed = "///api/v2/users///";
        sub.assert_eq(core::trim_start_byte(slashed, '/' as u8), "api/v2/users///", "trim_start_byte");
        sub.assert_eq(core::trim_end_byte(slashed, '/' as u8), "///api/v2/users", "trim_end_byte");
        sub.assert_eq(core::trim_byte(slashed, '/' as u8), "api/v2/users", "trim_byte both ends");
        sub.assert_eq(slashed.trim_byte('/' as u8), "api/v2/users", "trim_byte via UFCS");

        let enclosed = "[{\"key\":\"val\"}]";
        sub.assert_eq(core::trim_bytes(enclosed, "[]"), "{\"key\":\"val\"}", "trim_bytes cutset");
        sub.assert_eq(enclosed.trim_bytes("[]"), "{\"key\":\"val\"}", "trim_bytes via UFCS");

        let quotes = "\"\"quoted string\"\"";
        sub.assert_eq(quotes.trim_bytes("\""), "quoted string", "trim_bytes quotes");
    };
}

fn test_search_and_split(t: lit::T&) {
    t.run("Byte Scanning and Predicates") { sub =>
        let path = "/api/v1/metrics/prometheus";
        sub.assert_true(core::starts_with(path, "/api"), "starts_with prefix");
        sub.assert_true(path.starts_with("/api/v1"), "starts_with via UFCS");
        sub.assert_false(path.starts_with("/auth"), "starts_with non-prefix");

        sub.assert_true(core::ends_with(path, "prometheus"), "ends_with suffix");
        sub.assert_true(path.ends_with("/prometheus"), "ends_with via UFCS");
        sub.assert_false(path.ends_with(".json"), "ends_with non-suffix");

        sub.assert_true(core::contains_byte(path, '@' as u8) == false, "does not contain @");
        sub.assert_true(path.contains_byte('/' as u8), "contains_byte via UFCS");
        sub.assert_eq(core::count_byte(path, '/' as u8), 4, "count_byte finds 4 slashes");
        sub.assert_eq(path.count_byte('/' as u8), 4, "count_byte via UFCS");

        sub.assert_eq(core::index_of_byte(path, 'v' as u8), 5, "index_of_byte 'v' at 5");
        sub.assert_eq(path.index_of_byte('v' as u8), 5, "index_of_byte via UFCS");
        sub.assert_eq(core::last_index_of_byte(path, '/' as u8), 15, "last_index_of_byte '/' at 15");
        sub.assert_eq(path.last_index_of_byte('/' as u8), 15, "last_index_of_byte via UFCS");

        sub.assert_eq(find(path, "metrics"), 8, "index_of_slice finds 'metrics' at 8");
        sub.assert_eq(path.find("metrics"), 8, "index_of_slice via UFCS");
        sub.assert_eq(find(path, "missing"), -1, "index_of_slice missing is -1");
    };

    t.run("Split Once & Reverse Split Once") { sub =>
        let header = "Authorization: Bearer my_jwt_token";
        let left, right, found = core::split_once_byte(header, ':' as u8);
        sub.assert_true(found, "split_once_byte found colon");
        sub.assert_eq(left, "Authorization", "split_once_byte left");
        sub.assert_eq(right, " Bearer my_jwt_token", "split_once_byte right");

        let no_delim = "BareTokenWithoutDelim";
        let nd_left, nd_right, nd_found = no_delim.split_once_byte(':' as u8);
        sub.assert_false(nd_found, "split_once_byte not found");
        sub.assert_eq(nd_left, no_delim, "split_once_byte left is whole string");
        sub.assert_eq(nd_right, "", "split_once_byte right is empty");

        let file_path = "src/core/bytes/case.goose";
        let dir, file_name, r_found = file_path.rsplit_once_byte('/' as u8);
        sub.assert_true(r_found, "rsplit_once_byte found slash");
        sub.assert_eq(dir, "src/core/bytes", "rsplit_once_byte dir");
        sub.assert_eq(file_name, "case.goose", "rsplit_once_byte file_name");

        let wire_msg = "Content-Length: 42\r\n\r\n{\"ok\":true}";
        let headers_part, body_part, sep_found = wire_msg.split_once("\r\n\r\n");
        sub.assert_true(sep_found, "split_once found CRLFCRLF");
        sub.assert_eq(headers_part, "Content-Length: 42", "split_once headers");
        sub.assert_eq(body_part, "{\"ok\":true}", "split_once body");

        let fold_str = "Key=ValUE; charset=utf-8";
        let f_left, f_right, f_found = fold_str.split_once_fold("CHARSET=");
        sub.assert_true(f_found, "split_once_fold found CHARSET=");
        sub.assert_eq(f_left, "Key=ValUE; ", "split_once_fold left");
        sub.assert_eq(f_right, "utf-8", "split_once_fold right");
    };

    t.run("Zero-Allocation ByteTokenizer") { sub =>
        let csv = "alice,bob,carol,david";
        var tok = core::make_byte_tokenizer(csv, ',' as u8);

        let t1, ok1 = core::token_next(tok);
        sub.assert_true(ok1, "tok 1 ok");
        sub.assert_eq(t1, "alice", "tok 1 alice");

        let t2, ok2 = tok.token_next();
        sub.assert_true(ok2, "tok 2 ok");
        sub.assert_eq(t2, "bob", "tok 2 bob");

        let t3, ok3 = tok.token_next();
        sub.assert_true(ok3, "tok 3 ok");
        sub.assert_eq(t3, "carol", "tok 3 carol");

        let t4, ok4 = tok.token_next();
        sub.assert_true(ok4, "tok 4 ok");
        sub.assert_eq(t4, "david", "tok 4 david");

        let t5, ok5 = tok.token_next();
        sub.assert_false(ok5, "tok 5 exhausted");
        sub.assert_eq(t5, "", "tok 5 empty");

        // Edge case: single token
        var single_tok = core::make_byte_tokenizer("alone", ';');
        let st1, s_ok1 = single_tok.token_next();
        sub.assert_true(s_ok1, "single token ok");
        sub.assert_eq(st1, "alone", "single token matches");
        let _, s_ok2 = single_tok.token_next();
        sub.assert_false(s_ok2, "single token then exhausted");

        // Edge case: empty source
        var empty_tok = core::make_byte_tokenizer("", ',');
        let _, e_ok = empty_tok.token_next();
        sub.assert_false(e_ok, "empty source immediately exhausted");
    };
}

fn test_parsing_and_formatting(t: lit::T&) {
    t.run("Decimal Integer Parsing") { sub =>
        let u_val, u_ok = core::parse_u64_dec("18446744073709551615");
        sub.assert_true(u_ok, "parse u64::MAX ok");
        sub.assert_eq(u_val, 18446744073709551615, "u64::MAX parsed accurately");

        let zero, z_ok = "0".parse_u64_dec();
        sub.assert_true(z_ok, "parse 0 ok via UFCS");
        sub.assert_eq(zero, 0, "0 matches");

        // Overflow check (u64::MAX + 1 -> 18446744073709551616)
        let _, of_ok = "18446744073709551616".parse_u64_dec();
        sub.assert_false(of_ok, "u64 overflow rejected");

        // Non-digit check
        let _, nd_ok = "123a45".parse_u64_dec();
        sub.assert_false(nd_ok, "non-digit rejected");

        // Signed i64 tests
        let pos_i, pos_ok = "+9223372036854775807".parse_i64_dec();
        sub.assert_true(pos_ok, "parse positive i64::MAX ok");
        sub.assert_eq(pos_i, 9223372036854775807, "i64::MAX matches");

        let neg_i, neg_ok = "-9223372036854775808".parse_i64_dec();
        sub.assert_true(neg_ok, "parse negative i64::MIN ok");
        sub.assert_eq(neg_i, -9223372036854775807 - 1, "i64::MIN matches");

        let _, i_of_ok = "9223372036854775808".parse_i64_dec();
        sub.assert_false(i_of_ok, "i64 positive overflow rejected");

        let _, i_uf_ok = "-9223372036854775809".parse_i64_dec();
        sub.assert_false(i_uf_ok, "i64 negative underflow rejected");

        // 32-bit integer parsing
        let u32_val, u32_ok = "4294967295".parse_u32_dec();
        sub.assert_true(u32_ok, "u32::MAX parsed");
        sub.assert_eq(u32_val, 4294967295, "u32::MAX matches");

        let _, u32_of = "4294967296".parse_u32_dec();
        sub.assert_false(u32_of, "u32 overflow rejected");

        let i32_val, i32_ok = "-2147483648".parse_i32_dec();
        sub.assert_true(i32_ok, "i32::MIN parsed");
        sub.assert_eq(i32_val, -2147483648, "i32::MIN matches");
    };

    t.run("Hexadecimal Integer Parsing") { sub =>
        let h1, ok1 = core::parse_u64_hex("deadbeef");
        sub.assert_true(ok1, "parse deadbeef hex ok");
        sub.assert_eq(h1, 0xdeadbeef, "deadbeef value matches");

        let h2, ok2 = "0xDEADBEEF".parse_u64_hex();
        sub.assert_true(ok2, "parse 0xDEADBEEF ok via UFCS");
        sub.assert_eq(h2, 0xdeadbeef, "0xDEADBEEF matches");

        let h_max, ok_max = "0xFFFFFFFFFFFFFFFF".parse_u64_hex();
        sub.assert_true(ok_max, "parse max u64 hex ok");
        sub.assert_eq(h_max, 18446744073709551615, "u64 hex max matches");

        let _, bad_hex = "0x123Z".parse_u64_hex();
        sub.assert_false(bad_hex, "invalid hex char Z rejected");

        let u8_val, u8_ok = "2A".parse_u8_hex();
        sub.assert_true(u8_ok, "u8 hex 2A ok");
        sub.assert_eq(u8_val, 42 as u8, "2A is 42");
    };

    t.run("Decimal & Hexadecimal Formatting") { sub =>
        var dec_buf: u8[..64] = [];
        core::format_u64_dec(18446744073709551615, dec_buf);
        sub.assert_eq(dec_buf[..], "18446744073709551615", "format_u64_dec max matches");

        var zero_buf: u8[..16] = [];
        core::format_u64_dec(0, zero_buf);
        sub.assert_eq(zero_buf[..], "0", "format_u64_dec 0 matches");

        var neg_buf: u8[..64] = [];
        core::format_i64_dec(-9223372036854775807 - 1, neg_buf);
        sub.assert_eq(neg_buf[..], "-9223372036854775808", "format_i64_dec i64::MIN matches");

        var hex_lower: u8[..32] = [];
        core::format_u64_hex(0xfeedface, hex_lower, false);
        sub.assert_eq(hex_lower[..], "feedface", "format_u64_hex lowercase");

        var hex_upper: u8[..32] = [];
        core::format_u64_hex(0xfeedface, hex_upper, true);
        sub.assert_eq(hex_upper[..], "FEEDFACE", "format_u64_hex uppercase");

        var byte_buf: u8[..8] = [];
        core::format_u8_hex(0x0a as u8, byte_buf, false);
        sub.assert_eq(byte_buf[..], "0a", "format_u8_hex leading zero padded");

        var fixed_buf: u8[..32] = [];
        core::format_u64_hex_fixed(0x42, 6, fixed_buf, true);
        sub.assert_eq(fixed_buf[..], "000042", "format_u64_hex_fixed 6-digit zero padding");
    };
}

// --- Component: core_io_stream ---
// Verification suite for Goose Core I/O Stream Module (core/io):
// - SliceReader cursor semantics, bounds checking, and integer deserialization (BE/LE)
// - SliceWriter and CountingWriter with capacity guards and integer serialization
// - LimitReader bounded reading and DoS threshold enforcement
// - TeeReader stream tapping and transcript mirroring
// - RingBuffer circular FIFO storage, wraparound behavior, and zero-copy peeking
// - Stream piping helpers (copy_reader_to_writer, copy_reader_all, copy_reader_n)

fn test_slice_reader(t: lit::T&) {
    t.run("Sequential Reading and Exact Slices") { sub =>
        let data = "Hello, World! Systems Zero-Heap IO";
        var r = core::new_slice_reader(data);

        sub.assert_eq(r.remaining(), data.len, "Initial remaining matches data len");
        sub.assert_false(r.is_eof(), "Not EOF initially");

        var buf: u8[16] = [0; 16];
        let n, err = r.read(buf[..5]);
        sub.assert_eq(n, 5, "Read 5 bytes");
        sub.assert_eq(err, core::IoError.None, "No error on partial read");
        sub.assert_eq(buf[..5], "Hello", "Read bytes match expected slice");
        sub.assert_eq(r.remaining(), data.len - 5, "Remaining decreased by 5");

        let p_byte, p_ok = r.peek();
        sub.assert_true(p_ok, "Peek successful");
        sub.assert_eq(p_byte, ',' as u8, "Peek returns next comma byte");
        sub.assert_eq(r.remaining(), data.len - 5, "Peek does not advance cursor");

        let slice, s_err = r.read_slice(2);
        sub.assert_eq(s_err, core::IoError.None, "read_slice ok");
        sub.assert_eq(slice, ", ", "Yielded exact 2-byte slice");

        let skip_err = r.skip(7);
        sub.assert_eq(skip_err, core::IoError.None, "Skip 7 bytes ok");
        sub.assert_eq(r.remaining(), data.len - 14, "Remaining after skip");

        let tail, tail_err = r.read_slice(r.remaining());
        sub.assert_eq(tail_err, core::IoError.None, "Read remaining slice ok");
        sub.assert_eq(tail, "Systems Zero-Heap IO", "Tail slice matches");
        sub.assert_true(r.is_eof(), "Reader reached EOF");
        sub.assert_eq(r.remaining(), 0, "0 remaining at EOF");

        let eof_n, eof_err = r.read(buf[..]);
        sub.assert_eq(eof_n, 0, "Read at EOF returns 0 bytes");
        sub.assert_eq(eof_err, core::IoError.Eof, "Read at EOF returns IoError.Eof");
    };

    t.run("Binary Integer Deserialization (BE & LE)") { sub =>
        // Wire packet:
        // [0] = 0xFE (u8)
        // [1..2] = 0x12, 0x34 (u16 BE = 0x1234, LE = 0x3412)
        // [3..5] = 0x01, 0x02, 0x03 (u24 BE = 0x010203)
        // [6..9] = 0x01, 0x02, 0x03, 0x04 (u32 BE = 0x01020304)
        // [10..17] = 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08 (u64 BE)
        let wire_bytes: u8[18] = [
            0xFE,
            0x12, 0x34,
            0x01, 0x02, 0x03,
            0x01, 0x02, 0x03, 0x04,
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        ];
        var r = core::new_slice_reader(wire_bytes[..]);

        let u8_val, err8 = r.read_u8();
        sub.assert_eq(err8, core::IoError.None, "read_u8 ok");
        sub.assert_eq(u8_val, 0xFE, "u8 matches 0xFE");

        let u16_val, err16 = r.read_u16_be();
        sub.assert_eq(err16, core::IoError.None, "read_u16_be ok");
        sub.assert_eq(u16_val, 0x1234 as u16, "u16 BE matches 0x1234");

        let u24_val, err24 = r.read_u24_be();
        sub.assert_eq(err24, core::IoError.None, "read_u24_be ok");
        sub.assert_eq(u24_val, 0x010203 as u32, "u24 BE matches 0x010203");

        let u32_val, err32 = r.read_u32_be();
        sub.assert_eq(err32, core::IoError.None, "read_u32_be ok");
        sub.assert_eq(u32_val, 0x01020304 as u32, "u32 BE matches 0x01020304");

        let u64_val, err64 = r.read_u64_be();
        sub.assert_eq(err64, core::IoError.None, "read_u64_be ok");
        sub.assert_eq(u64_val, 0x0102030405060708 as u64, "u64 BE matches expected value");

        sub.assert_true(r.is_eof(), "Reader at EOF after decoding packet");

        let _, err_trunc = r.read_u32_be();
        sub.assert_eq(err_trunc, core::IoError.UnexpectedEof, "Reading past EOF returns UnexpectedEof");
    };
}

fn test_slice_writer(t: lit::T&) {
    t.run("Serialization & Integer Encoding") { sub =>
        var storage: u8[32] = [0; 32];
        var w = core::new_slice_writer(storage[..]);

        sub.assert_eq(w.available(), 32, "Initial capacity 32");
        sub.assert_eq(w.written(), 0, "Written 0");

        let err1 = w.write_u8(0xAA);
        sub.assert_eq(err1, core::IoError.None, "write_u8 ok");

        let err2 = w.write_u16_be(0xBEEF as u16);
        sub.assert_eq(err2, core::IoError.None, "write_u16_be ok");

        let err2b = w.write_u24_be(0xABCDEF as u32);
        sub.assert_eq(err2b, core::IoError.None, "write_u24_be ok");

        let err3 = w.write_u32_be(0xCAFEBABE as u32);
        sub.assert_eq(err3, core::IoError.None, "write_u32_be ok");

        let err4 = w.write_exact("WING");
        sub.assert_eq(err4, core::IoError.None, "write_exact string ok");

        sub.assert_eq(w.written(), 1 + 2 + 3 + 4 + 4, "Total written 14 bytes");
        let written_bytes = w.as_written_slice();
        sub.assert_eq(written_bytes.len, 14, "Written slice len 14");

        // Verify with SliceReader
        var r = core::new_slice_reader(written_bytes);
        let b, _ = r.read_u8();
        sub.assert_eq(b, 0xAA, "Decoded u8 matches");
        let v16, _ = r.read_u16_be();
        sub.assert_eq(v16, 0xBEEF as u16, "Decoded u16 matches");
        let v24, _ = r.read_u24_be();
        sub.assert_eq(v24, 0xABCDEF as u32, "Decoded u24 matches");
        let v32, _ = r.read_u32_be();
        sub.assert_eq(v32, 0xCAFEBABE as u32, "Decoded u32 matches");
        let str_tag, _ = r.read_slice(4);
        sub.assert_eq(str_tag, "WING", "Decoded string tag matches");
    };

    t.run("Buffer Overflow Guards") { sub =>
        var small: u8[4] = [0; 4];
        var w = core::new_slice_writer(small[..]);

        let n, err = w.write("12345678");
        sub.assert_eq(n, 4, "Wrote only 4 bytes to 4-byte buffer");
        sub.assert_eq(err, core::IoError.ShortWrite, "ShortWrite reported on partial fit");
        sub.assert_eq(w.available(), 0, "No capacity remaining");

        let err_ovf = w.write_exact("X");
        sub.assert_eq(err_ovf, core::IoError.BufferFull, "write_exact on full writer returns BufferFull");

        var cw = core::new_counting_writer();
        let cw_n, cw_err = core::write(cw, "1234567890");
        sub.assert_eq(cw_n, 10, "CountingWriter consumed 10 bytes");
        sub.assert_eq(cw_err, core::IoError.None, "CountingWriter ok");
        sub.assert_eq(cw.total_written, 10, "Total count is 10");
    };
}

fn test_limit_reader(t: lit::T&) {
    t.run("Strict DoS Boundary & Exceed Enforcement") { sub =>
        let payload = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ";
        // Limit reading to at most 10 bytes
        var lr = core::new_limit_reader(payload, 10);

        sub.assert_eq(lr.remaining(), 10, "Limit remaining is 10");
        sub.assert_false(lr.is_exhausted(), "Not exhausted initially");

        var chunk: u8[8] = [0; 8];
        let n1, err1 = lr.read(chunk[..8]);
        sub.assert_eq(n1, 8, "Read 8 bytes under limit");
        sub.assert_eq(err1, core::IoError.None, "No error on read 8");
        sub.assert_eq(chunk[..8], "01234567", "Read bytes match payload");
        sub.assert_eq(lr.remaining(), 2, "2 bytes remaining under limit");

        // Attempting to read 5 bytes when only 2 remain should clamp to 2
        var small: u8[5] = [0; 5];
        let n2, err2 = lr.read(small[..5]);
        sub.assert_eq(n2, 2, "Read clamped to 2 bytes");
        sub.assert_eq(err2, core::IoError.None, "Read completed");
        sub.assert_eq(small[..2], "89", "Clamped bytes match");
        sub.assert_true(lr.is_exhausted(), "Limiter is now exhausted");
        sub.assert_eq(lr.remaining(), 0, "0 bytes remaining");

        // Next read must fail with LimitExceeded
        var extra: u8[1] = [0; 1];
        let n3, err3 = lr.read(extra[..]);
        sub.assert_eq(n3, 0, "0 bytes read on exhausted limiter");
        sub.assert_eq(err3, core::IoError.LimitExceeded, "Error is LimitExceeded");
        sub.assert_true(lr.exceeded, "Exceeded flag set");
    };
}

fn test_tee_reader(t: lit::T&) {
    t.run("Stream Interception and Mirroring") { sub =>
        let data = "TLS 1.3 ClientHello Transcript Wire Message";
        var tr = core::new_tee_reader(data);
        var transcript_tap: u8[>..] = [];

        var client_buf: u8[16] = [0; 16];
        let n1, err1 = core::read_and_tap(tr, client_buf[..7], transcript_tap);
        sub.assert_eq(n1, 7, "Read 7 bytes");
        sub.assert_eq(err1, core::IoError.None, "Read ok");
        sub.assert_eq(client_buf[..7], "TLS 1.3", "Read slice matches");
        sub.assert_eq(transcript_tap[..], "TLS 1.3", "Tapped transcript matches");

        let slice, err2 = core::read_slice_and_tap(tr, 12, transcript_tap);
        sub.assert_eq(err2, core::IoError.None, "read_slice ok");
        sub.assert_eq(slice, " ClientHello", "Slice matches");
        sub.assert_eq(transcript_tap[..], "TLS 1.3 ClientHello", "Accumulated transcript matches");
        sub.assert_eq(tr.intercepted_total, 19, "Total intercepted bytes matches");
    };
}

fn test_ring_buffer(t: lit::T&) {
    t.run("Circular Storage, Wraparound & Discard") { sub =>
        var rb = core::new_ring_buffer();
        sub.assert_eq(rb.len(), 0, "Initial len 0");
        sub.assert_true(rb.is_empty(), "Initially empty");
        sub.assert_false(rb.is_full(), "Not full");
        sub.assert_eq(rb.available(), 4096, "Available is 4096");

        // Write 10 bytes
        let w1, err1 = rb.write("0123456789");
        sub.assert_eq(w1, 10, "Wrote 10 bytes");
        sub.assert_eq(err1, core::IoError.None, "write ok");
        sub.assert_eq(rb.len(), 10, "Len is 10");

        // Peek 5 bytes
        var peek_buf: u8[5] = [0; 5];
        let p_n = rb.peek(peek_buf[..]);
        sub.assert_eq(p_n, 5, "Peeked 5 bytes");
        sub.assert_eq(peek_buf[..], "01234", "Peeked contents match");
        sub.assert_eq(rb.len(), 10, "Peek does not consume bytes");

        // Read 5 bytes
        var read_buf: u8[5] = [0; 5];
        let r_n, r_err = rb.read(read_buf[..]);
        sub.assert_eq(r_n, 5, "Read 5 bytes");
        sub.assert_eq(r_err, core::IoError.None, "read ok");
        sub.assert_eq(read_buf[..], "01234", "Read contents match");
        sub.assert_eq(rb.len(), 5, "Len reduced to 5");

        // Discard 3 bytes
        let d_n = rb.discard(3);
        sub.assert_eq(d_n, 3, "Discarded 3 bytes");
        sub.assert_eq(rb.len(), 2, "Remaining len 2");

        // Read final 2 bytes
        var tail_buf: u8[4] = [0; 4];
        let t_n, _ = rb.read(tail_buf[..]);
        sub.assert_eq(t_n, 2, "Read 2 bytes");
        sub.assert_eq(tail_buf[..2], "89", "Tail bytes match");
        sub.assert_true(rb.is_empty(), "Ring buffer now empty");

        // Test Wraparound: write near end of buffer
        rb.clear();
        rb.head = 4090;
        rb.tail = 4090;
        rb.count = 0;

        let w_wrap, w_wrap_err = rb.write("ABCDEFGH");
        sub.assert_eq(w_wrap, 8, "Wrote 8 bytes wrapping across edge");
        sub.assert_eq(w_wrap_err, core::IoError.None, "Wrap write ok");
        sub.assert_eq(rb.len(), 8, "Len is 8");

        var wrap_out: u8[8] = [0; 8];
        let r_wrap, r_wrap_err = rb.read(wrap_out[..]);
        sub.assert_eq(r_wrap, 8, "Read 8 bytes across edge");
        sub.assert_eq(r_wrap_err, core::IoError.None, "Wrap read ok");
        sub.assert_eq(wrap_out[..], "ABCDEFGH", "Wrapped bytes read in exact order");
    };
}

fn test_pipeline_helpers(t: lit::T&) {
    t.run("Copy Reader to Writer and Buffer") { sub =>
        var r = core::new_slice_reader("Zero-Allocation Piping Engine");
        var out_storage: u8[64] = [0; 64];
        var w = core::new_slice_writer(out_storage[..]);

        let copied, err = core::copy_reader_to_writer(r, w);
        sub.assert_eq(copied, 29, "Copied 29 bytes");
        sub.assert_eq(err, core::IoError.None, "Copy ok");
        sub.assert_eq(w.as_written_slice(), "Zero-Allocation Piping Engine", "Writer received entire stream");
        sub.assert_true(r.is_eof(), "Reader is EOF");

        var r2 = core::new_slice_reader("Payload Data Segment");
        var target_buf: u8[>..] = [];
        let n_all, err_all = core::copy_reader_all(r2, target_buf);
        sub.assert_eq(n_all, 20, "Copied all 20 bytes into dynamic buffer");
        sub.assert_eq(err_all, core::IoError.None, "copy_all ok");
        sub.assert_eq(target_buf[..], "Payload Data Segment", "Dynamic buffer content matches");
    };
}

fn test_pipe_buffer(t: lit::T&) {
    t.run("Two-Cursor advance_to and Monotonic Examined Invariant") { sub =>
        var pipe = core::new_pipe_buffer();
        sub.assert_eq(pipe.readable_len(), 0, "Initial readable len 0");
        sub.assert_eq(pipe.write_space(), core::PIPE_BUFFER_CAP, "Initial write space 64KB");

        // Write first chunk from transport: "GET /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n"
        let msg = "GET /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n";
        let w_n, w_err = core::write(pipe, msg);
        sub.assert_eq(w_n, msg.len, "Wrote full request to pipe");
        sub.assert_eq(w_err, core::IoError.None, "Write ok");
        sub.assert_eq(pipe.readable_len(), msg.len, "Readable matches msg len");

        // Parser inspects line 1 (consumed 0, examined 26 = "GET /index.html HTTP/1.1\r\n")
        let err_adv1 = core::advance_to(pipe, 0, 26);
        sub.assert_eq(err_adv1, core::IoError.None, "First advance_to ok");
        sub.assert_eq(pipe.consumed, 0, "Consumed is 0");
        sub.assert_eq(pipe.examined, 26, "Examined is 26");

        // Mitigation of .NET issue #107213: adapter reads only 4 bytes ("GET ") and specifies examined = 4
        // The pipe must enforce monotonicity: examined cannot drop from 26 to 4!
        let err_adv2 = core::advance_to(pipe, 4, 4);
        sub.assert_eq(err_adv2, core::IoError.None, "Second advance_to ok");
        sub.assert_eq(pipe.consumed, 4, "Consumed advanced to 4");
        sub.assert_eq(pipe.examined, 26, "Examined held at 26 (monotonic)");

        // Parser now finishes consuming remainder of request
        let rem_to_consume = pipe.readable_len();
        let err_adv3 = core::advance_to(pipe, rem_to_consume, rem_to_consume);
        sub.assert_eq(err_adv3, core::IoError.None, "Final advance_to ok");
        sub.assert_eq(pipe.readable_len(), 0, "Pipe drained to 0 unconsumed bytes");

        // Auto-compaction & recycle test
        core::reset(pipe);
        sub.assert_eq(pipe.consumed, 0, "Reset consumed to 0");
        sub.assert_eq(pipe.examined, 0, "Reset examined to 0");
        sub.assert_eq(pipe.written, 0, "Reset written to 0");
    };

    t.run("Writable Span and Buffer Compaction") { sub =>
        var pipe = core::new_pipe_buffer();

        // Fill 40000 bytes
        var chunk: u8[1000] = ['A' as u8; 1000];
        for i in 40 {
            core::write(pipe, chunk[..]);
        }
        sub.assert_eq(pipe.readable_len(), 40000, "Readable is 40000");

        // Consume 35000 bytes
        core::advance_to(pipe, 35000, 35000);
        sub.assert_eq(pipe.readable_len(), 5000, "Remaining readable is 5000");

        // Requesting 30000 bytes write span should trigger auto-compaction
        let span, err_span = core::get_write_span(pipe, 30000);
        sub.assert_eq(err_span, core::IoError.None, "get_write_span ok after compaction");
        sub.assert_eq(pipe.consumed, 0, "Compacted: consumed back to 0");
        sub.assert_eq(pipe.written, 5000, "Compacted: written adjusted to 5000");
        sub.assert_true(span.len >= 30000, "Available span >= 30000");
    };
}

fn test_cork_buffer(t: lit::T&) {
    t.run("Aggregation, Binary Encoding and Partial Flush") { sub =>
        var cb = core::new_cork_buffer();
        sub.assert_true(cb.cork_is_empty(), "Cork initially empty");
        sub.assert_eq(cb.cork_available(), 16384, "Initial capacity 16KB");

        // Append 9-byte HTTP/2 Frame Header
        cb.cork_write_u24_be(5);             // Length = 5
        cb.cork_write_u8(0x00);              // Type = DATA
        cb.cork_write_u8(0x01);              // Flags = END_STREAM
        cb.cork_write_u32_be(1);             // Stream ID = 1
        cb.cork_write("HELLO");              // Payload

        sub.assert_eq(cb.cork_pending(), 9 + 5, "Pending is 14 bytes");
        sub.assert_eq(cb.cork_as_slice().len, 14, "As slice len is 14");

        // Verify content
        var r = core::new_slice_reader(cb.cork_as_slice());
        let l, _ = r.read_u24_be();
        sub.assert_eq(l, 5 as u32, "Decoded length matches 5");
        let ty, _ = r.read_u8();
        sub.assert_eq(ty, 0x00, "Decoded type matches DATA");
        let fl, _ = r.read_u8();
        sub.assert_eq(fl, 0x01, "Decoded flags matches END_STREAM");
        let sid, _ = r.read_u32_be();
        sub.assert_eq(sid, 1 as u32, "Decoded stream ID matches 1");
        let pay, _ = r.read_slice(5);
        sub.assert_eq(pay, "HELLO", "Decoded payload matches HELLO");

        // Partial consume (e.g. simulated socket sent 9 header bytes)
        cb.cork_consume(9);
        sub.assert_eq(cb.cork_pending(), 5, "Pending reduced to 5 payload bytes");
        sub.assert_eq(cb.cork_as_slice(), "HELLO", "Remaining slice is payload HELLO");

        // Reset
        cb.cork_reset();
        sub.assert_true(cb.cork_is_empty(), "Empty after reset");
    };
}

fn test_simd_accelerators(t: lit::T&) {
    t.run("SIMD Fast ASCII & CRLF Scan") { sub =>
        let ascii_str = "GET /v1/models HTTP/1.1\r\nHost: api.example.com\r\n\r\n";
        sub.assert_true(core::is_pure_ascii(ascii_str), "Pure ASCII string detected by SIMD");
        sub.assert_true(core::validate_utf8(ascii_str), "ASCII string is valid UTF-8");

        let crlf_pos = core::find_crlf(ascii_str);
        sub.assert_eq(crlf_pos, 23, "CRLF position found at index 23");

        let non_ascii = "Hello, 世界!\r\n";
        sub.assert_false(core::is_pure_ascii(non_ascii), "Non-ASCII detected");
        sub.assert_true(core::validate_utf8(non_ascii), "Valid multi-byte UTF-8 recognized");

        let bad_bytes: u8[3] = [0xFF, 0xFE, 0xFD];
        sub.assert_false(core::is_pure_ascii(bad_bytes[..]), "Bad bytes not ASCII");
        sub.assert_false(core::validate_utf8(bad_bytes[..]), "Bad bytes not UTF-8");
    };
}

fn main() {
    var runner = lit::new_runner("Core Primitives (Time, Math, Sync, Bytes, IO Streams) Suite", lit::Verbosity.Verbose);

    lit::run_case(runner, "1. Duration Arithmetic, i64.min/max, Signs & Accessors", test_duration_arithmetic_and_bounds);
    lit::run_case(runner, "2. Duration Truncation and Rounding (Boundary & Half-Way)", test_duration_truncation_and_rounding);
    lit::run_case(runner, "3. Duration Format & Go-Compatible ParseDuration Security", test_duration_format_and_parse_security);
    lit::run_case(runner, "4. Monotonic Primitives: Stopwatch & Deadline (Anti-Overflow)", test_stopwatch_and_deadline_overflow);
    lit::run_case(runner, "5. Civil Calendar Math & Proleptic Gregorian Leap Years", test_hinnant_civil_calendar_and_leap_years);
    lit::run_case(runner, "6. Time Construction, Accessors, Projections & Pre-1970", test_time_construction_and_pre1970);
    lit::run_case(runner, "7. Time Arithmetic, Comparisons & ReDoS / DoS Immunity", test_time_arithmetic_and_redos_immunity);
    lit::run_case(runner, "8. Time Truncation, Rounding & Timezones", test_time_truncation_rounding_and_timezones);
    lit::run_case(runner, "9. RFC 3339 / ISO 8601 Codec & Attack Vectors", test_rfc3339_codec_and_attack_vectors);
    lit::run_case(runner, "10. RFC 9110 Section 5.6.7 HTTP-Date Formatting & 3-Format Parser Security", test_http_date_rfc9110_and_attack_vectors);
    lit::run_case(runner, "11. Branchless Constant-Time Arithmetic & Selection", test_branchless_constant_time);
    lit::run_case(runner, "12. Saturation & Checked Arithmetic", test_saturation_and_checked_arithmetic);
    lit::run_case(runner, "13. 128-Bit Multiplication & Wymum Without u128", test_wide_multiplication_and_wymum);
    lit::run_case(runner, "14. Bit Manipulation & Endianness Codecs", test_bit_manipulation_and_endianness);
    lit::run_case(runner, "15. Euclidean Division & Remainder", test_euclidean_division_and_remainder);
    lit::run_case(runner, "16. PRNGs & Lemire Fast-Range Mapping", test_prng_and_lemire_range);
    lit::run_case(runner, "17. Backoff & Jitter Strategies (Happy Eyeballs / AWS)", test_backoff_and_jitter_strategies);
    lit::run_case(runner, "18. Jacobson EWMA RTT Estimator (RFC 6298 / RFC 9002 Errata ID 7539)", test_jacobson_rtt_estimator_errata7539);
    lit::run_case(runner, "19. Fast Non-Cryptographic Hashing & Combinators", test_fast_non_cryptographic_hashes);
    lit::run_case(runner, "20. Constant-Time SOCKS5 Frame Length Validation", test_socks5_frame_validation_ct);
    lit::run_case(runner, "21. Multithreading, Actors & Crash Containment", test_multithreading_and_actors);
    lit::run_case(runner, "22. Classical Concurrency Primitives", test_classical_primitives);
    lit::run_case(runner, "23. Two-Phase CyclicBarrier Synchronization", test_cyclic_barrier);
    lit::run_case(runner, "24. CSP Patterns & In-Order Reassembly", test_csp_patterns);
    lit::run_case(runner, "25. Actor Subsystem & Priority Mailboxes", test_actor_subsystem);
    lit::run_case(runner, "26. OTP Supervision Trees & Fault Tolerance", test_supervision_trees);
    lit::run_case(runner, "27. ASCII Predicates, Case Conversions & Folding", test_case_folding);
    lit::run_case(runner, "28. Linear Whitespace, ASCII Whitespace & Byte Trimming", test_trimming);
    lit::run_case(runner, "29. Byte Search, Slice Splitting & ByteTokenizer", test_search_and_split);
    lit::run_case(runner, "30. Bounds-Checked Decimal & Hex Parsing and Formatting", test_parsing_and_formatting);
    lit::run_case(runner, "31. SliceReader Stream Cursor & Integer Decoding", test_slice_reader);
    lit::run_case(runner, "32. SliceWriter & CountingWriter Serialization", test_slice_writer);
    lit::run_case(runner, "33. LimitReader DoS Boundary Enforcement", test_limit_reader);
    lit::run_case(runner, "34. TeeReader Stream Interception & Tapping", test_tee_reader);
    lit::run_case(runner, "35. RingBuffer Circular FIFO & Wraparound", test_ring_buffer);
    lit::run_case(runner, "36. Stream Pipeline Copy Helpers", test_pipeline_helpers);
    lit::run_case(runner, "37. PipeBuffer Two-Cursor Pipelines & Monotonicity", test_pipe_buffer);
    lit::run_case(runner, "38. CorkBuffer 16KB Outbound Aggregation", test_cork_buffer);
    lit::run_case(runner, "39. SIMD Fast ASCII, UTF-8 & CRLF Scan", test_simd_accelerators);

    let ok = lit::finish(runner);
    assert(ok);
}
